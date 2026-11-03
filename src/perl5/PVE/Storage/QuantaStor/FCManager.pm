package PVE::Storage::QuantaStor::FCManager;

use strict;
use warnings;
use Carp qw(croak);

our $VERSION = '1.1.0';

=head1 NAME

PVE::Storage::QuantaStor::FCManager - Fibre Channel initiator lifecycle for QuantaStor volumes

=head1 SYNOPSIS

    my $fc = PVE::Storage::QuantaStor::FCManager->new();

    my @wwpns = $fc->initiator_ids();          # local HBA port WWPNs
    $fc->attach($vol);                          # rescan HBAs so the masked LUN appears
    $fc->wait_for_attached($vol);
    my $dev = $fc->volume_device_path($vol);    # /dev/disk/by-id/... (multipath-aware)
    $fc->detach($vol);                          # drop the SCSI devices for this LUN
    $fc->wait_for_detached($vol);

=head1 DESCRIPTION

Peer of L<PVE::Storage::QuantaStor::ISCSIManager> for hosts that reach the
appliance over Fibre Channel. It implements the same transport contract the
plugin consumes (C<initiator_ids>, C<attach>, C<detach>, C<is_attached>,
C<wait_for_attached>, C<wait_for_detached>, C<volume_device_path>,
C<rescan_volume>, C<is_exported>), so C<Custom/QuantaStor.pm> never branches on
the transport itself.

Fibre Channel has no login step. Once QuantaStor masks a volume to this host's
WWPNs, the LUN becomes visible after a SCSI bus rescan on each HBA; detaching
means deleting the resulting SCSI devices (and flushing the multipath map when
one exists). The fabric zoning that lets the HBAs see the appliance's target
ports is an out-of-band prerequisite this module cannot manage.

=head2 Device identity

QuantaStor programs the SCST device with an NAA identifier derived from the
volume's C<deviceDescriptor> (24 hex characters): C<62000000> followed by the
descriptor. Linux exposes that as WWID C<3> + lowercase NAA, so the LUN is
resolved through C</dev/disk/by-id/>:

    dm-uuid-mpath-3<naa>   when multipathd has claimed the paths
    scsi-3<naa>            single path

Both are stable across reboots and independent of the LUN number or the
C</dev/sdX> assignment.

What has been validated on FC hardware is listed in docs/limitations.md.

=cut

# ---------------------------------------------------------------------------
# Constructor
# ---------------------------------------------------------------------------

=head2 new(%args)

All arguments are optional.

=over

=item logger

Coderef C<($level, $message)>. Defaults to no-op.

=item _run_cmd

Coderef for running system commands (multipath tools). Receives a flat list of
args, returns combined output, dies on failure. Defaults to
C<PVE::Tools::run_command> with an C<IPC::Open3> fallback.

=item _sysfs_root, _dev_root

Roots for C</sys> and C</dev>. Tests point these at temp directories holding
fixture trees instead of the live kernel view.

=item _path_exists, _sleep, _read_file, _write_file

Filesystem and timing primitives, injectable for tests.

=back

=cut

sub new {
    my ($class, %args) = @_;

    my $self = {
        logger       => $args{logger}       // sub {},
        _run_cmd     => $args{_run_cmd},
        _sysfs_root  => $args{_sysfs_root}  // '/sys',
        _dev_root    => $args{_dev_root}    // '/dev',
        _path_exists => $args{_path_exists} // sub { -e $_[0] },
        _sleep       => $args{_sleep}       // sub { sleep $_[0] },
        _read_file   => $args{_read_file}   // \&_default_read_file,
        _write_file  => $args{_write_file}  // \&_default_write_file,
    };

    return bless $self, $class;
}

# ---------------------------------------------------------------------------
# Primitives
# ---------------------------------------------------------------------------

sub _run {
    my ($self, @cmd) = @_;
    return $self->{_run_cmd}->(@cmd) if $self->{_run_cmd};
    return _default_run(@cmd);
}

sub _default_run {
    my (@cmd) = @_;

    if (eval { require PVE::Tools; 1 }) {
        my $output = '';
        PVE::Tools::run_command(
            \@cmd,
            outfunc => sub { $output .= "$_[0]\n" },
            errfunc => sub { $output .= "$_[0]\n" },
        );
        return $output;
    }

    require IPC::Open3;
    require Symbol;
    my $err_fh = Symbol::gensym();
    my ($out, $in);
    my $pid = IPC::Open3::open3($in, $out, $err_fh, @cmd)
        or croak "Cannot exec '@cmd': $!";
    my $output = do { local $/; <$out> };
    my $errors = do { local $/; <$err_fh> };
    waitpid $pid, 0;
    my $rc = $? >> 8;
    croak sprintf("Command failed (rc=%d): %s\nOutput: %s",
        $rc, join(' ', @cmd), ($output // '') . ($errors // ''))
        if $rc != 0;
    return ($output // '') . ($errors // '');
}

sub _default_read_file {
    my ($path) = @_;
    open my $fh, '<', $path or croak "Cannot open '$path': $!";
    my $content = do { local $/; <$fh> };
    close $fh;
    $content //= '';
    $content =~ s/\s+\z//;
    return $content;
}

sub _default_write_file {
    my ($path, $content) = @_;
    open my $fh, '>', $path or croak "Cannot write '$path': $!";
    print $fh $content;
    close $fh or croak "Cannot write '$path': $!";
    return 1;
}

sub _read  { my ($self, $p) = @_;      return $self->{_read_file}->($p) }
sub _write { my ($self, $p, $c) = @_;  return $self->{_write_file}->($p, $c) }

# ---------------------------------------------------------------------------
# Initiator identity
# ---------------------------------------------------------------------------

=head2 normalize_wwpn($raw)

Class method. Reduces any WWPN spelling (C<0x21000024ff0a0b0c>,
C<21:00:00:24:ff:0a:0b:0c>, upper case) to the 16 lowercase hex characters
QuantaStor stores for a host initiator. Dies if the result is not a WWPN.

=cut

sub normalize_wwpn {
    my ($class, $raw) = @_;
    croak "normalize_wwpn: value is required" unless defined $raw && length $raw;

    (my $w = lc $raw) =~ s/^\s+|\s+$//g;
    $w =~ s/^0x//;
    $w =~ s/[^0-9a-f]//g;
    croak "normalize_wwpn: '$raw' is not a 16-digit WWPN" unless $w =~ /^[0-9a-f]{16}$/;
    return $w;
}

=head2 initiator_ids()

Returns the WWPNs of every online-capable FC HBA port on this host, read from
C</sys/class/fc_host/hostN/port_name>. Dies if the host has no FC HBA — an
FC storage on a node without one cannot work, and a silent empty list would
register a host with no initiators.

=cut

sub initiator_ids {
    my ($self) = @_;

    my @wwpns;
    for my $host ($self->_fc_hosts()) {
        my $raw = eval { $self->_read("$host/port_name") };
        next unless defined $raw && length $raw;
        my $w = eval { __PACKAGE__->normalize_wwpn($raw) };
        push @wwpns, $w if defined $w;
    }

    croak "FCManager: no Fibre Channel HBA found under $self->{_sysfs_root}/class/fc_host "
        . "— this node cannot use an FC QuantaStor storage" unless @wwpns;

    return sort @wwpns;
}

=head2 initiator_id()

The first WWPN — the identity the plugin registers the host under and uses for
ACL calls. Every other local WWPN is added to the same host object.

=cut

sub initiator_id {
    my ($self) = @_;
    my @ids = $self->initiator_ids();
    return $ids[0];
}

# Directories under /sys/class/fc_host, sorted for deterministic behaviour.
sub _fc_hosts {
    my ($self) = @_;
    my @dirs = sort glob("$self->{_sysfs_root}/class/fc_host/host*");
    return @dirs;
}

# ---------------------------------------------------------------------------
# Volume identity
# ---------------------------------------------------------------------------

=head2 is_exported($vol)

True when the volume object carries the identity needed to find it on the
SCSI bus (a 24-character C<deviceDescriptor>).

=cut

sub is_exported {
    my ($self, $vol) = @_;
    my $d = $vol->{deviceDescriptor};
    return (defined $d && $d =~ /^[0-9a-fA-F]{24}$/) ? 1 : 0;
}

=head2 wwid($vol)

Linux WWID of the volume's LUN: C<3> + lowercase NAA. Dies when the volume has
no usable device descriptor.

=cut

sub wwid {
    my ($self, $vol) = @_;
    croak "FCManager: volume '" . ($vol->{name} // '?') . "' has no 24-character "
        . "deviceDescriptor — cannot derive its SCSI identifier"
        unless $self->is_exported($vol);
    return '3' . lc('62000000' . $vol->{deviceDescriptor});
}

# Candidate by-id paths, multipath first.
sub _candidate_paths {
    my ($self, $vol) = @_;
    my $wwid = $self->wwid($vol);
    my $byid = "$self->{_dev_root}/disk/by-id";
    return ("$byid/dm-uuid-mpath-$wwid", "$byid/scsi-$wwid");
}

=head2 volume_device_path($vol)

Returns the stable C</dev/disk/by-id/> path for the volume: the multipath map
when it exists, else the single-path SCSI link. When neither exists yet (LUN
not attached) the single-path link is returned so callers have a concrete
name to report.

=cut

sub volume_device_path {
    my ($self, $vol) = @_;
    my @paths = $self->_candidate_paths($vol);
    for my $p (@paths) {
        return $p if $self->{_path_exists}->($p);
    }
    return $paths[-1];
}

=head2 is_attached($vol)

True when a by-id link for the volume's WWID exists.

=cut

sub is_attached {
    my ($self, $vol) = @_;
    for my $p ($self->_candidate_paths($vol)) {
        return 1 if $self->{_path_exists}->($p);
    }
    return 0;
}

# ---------------------------------------------------------------------------
# Attach / detach
# ---------------------------------------------------------------------------

=head2 attach($vol)

Makes the LUN visible: issues a wildcard SCSI scan on every FC HBA. Safe to
repeat — a rescan of an already-present LUN is a no-op for the kernel.

=cut

sub attach {
    my ($self, $vol) = @_;
    my $wwid = $self->wwid($vol);

    return 1 if $self->is_attached($vol);

    $self->{logger}->(info => "FCManager: rescanning FC HBAs for LUN $wwid");
    croak "FCManager: no FC HBA could be rescanned" unless $self->_scan_hosts();
    return 1;
}

# Wildcard SCSI scan on every FC HBA; returns how many were scanned.
sub _scan_hosts {
    my ($self) = @_;
    my $scanned = 0;
    for my $host ($self->_fc_hosts()) {
        my ($n) = $host =~ m{/host(\d+)$};
        next unless defined $n;
        my $scan = "$self->{_sysfs_root}/class/scsi_host/host$n/scan";
        eval { $self->_write($scan, "- - -"); $scanned++ };
        $self->{logger}->(warning => "FCManager: scan of host$n failed: $@") if $@;
    }
    return $scanned;
}

# Online FC target ports this host is logged in to; each presents every LUN.
sub _target_ports {
    my ($self) = @_;
    my $n = 0;
    for my $rp (glob("$self->{_sysfs_root}/class/fc_remote_ports/rport-*")) {
        my $roles = eval { $self->_read("$rp/roles") } // '';
        my $state = eval { $self->_read("$rp/port_state") } // '';
        $n++ if $roles =~ /FCP Target/ && $state =~ /Online/;
    }
    return $n;
}

=head2 add_map($wwid, $max_wait)

Whitelists C<$wwid> and builds its multipath map, then waits (default 30 s)
until the map exists and the LUN has a path through every online target port.
An HA pair's standby node maps the LUN a moment after the owner, so the HBAs
are rescanned while waiting. Returns 1 when the map exists (a warning is
logged if paths are still missing at the limit), 0 when it never appeared.

=cut

sub add_map {
    my ($self, $wwid, $max_wait) = @_;
    $max_wait //= 30;

    eval { $self->_run('multipath', '-a', $wwid) };   # "already in wwids" is fine
    my $path = "$self->{_dev_root}/disk/by-id/dm-uuid-mpath-$wwid";
    my $want = $self->_target_ports();
    for (my $t = 0; $t < $max_wait; $t++) {
        # Re-issue every few seconds: paths may still be appearing.
        if ($t % 5 == 0) {
            $self->_scan_hosts() if $t;
            eval { $self->_run('multipath', $wwid) };
        }
        return 1 if $self->{_path_exists}->($path) && $self->_paths_for($wwid) >= $want;
        $self->{_sleep}->(1);
    }
    my $have = () = $self->_paths_for($wwid);
    unless ($self->{_path_exists}->($path)) {
        $self->{logger}->(warning => "FCManager: timeout waiting for multipath map '$path'");
        return 0;
    }
    $self->{logger}->(warning => "FCManager: LUN $wwid has $have of $want paths after ${max_wait}s; "
        . "check zoning and that every target port has the LUN mapped");
    return 1;
}

=head2 wait_for_attached($vol, $max_wait)

Polls for the by-id link (default 30 s, 1 s interval). Returns 1 when it
appears, 0 on timeout.

=cut

sub wait_for_attached {
    my ($self, $vol, $max_wait) = @_;
    $max_wait //= 30;
    my $elapsed = 0;
    while ($elapsed < $max_wait) {
        return 1 if $self->is_attached($vol);
        $self->{_sleep}->(1);
        $elapsed += 1;
    }
    $self->{logger}->(warning =>
        "FCManager: timeout waiting for device of LUN " . $self->wwid($vol));
    return 0;
}

# /sys/block/sd* entries whose SCSI device reports this WWID.
sub _paths_for {
    my ($self, $wwid) = @_;
    my $naa = substr($wwid, 1);   # strip the leading designator type digit
    my @sd;
    for my $blk (sort glob("$self->{_sysfs_root}/block/sd*")) {
        my $w = eval { $self->_read("$blk/device/wwid") };
        next unless defined $w;
        $w = lc $w;
        # sysfs reports "naa.62000000..." ; match on the hex body. The capture
        # untaints the glob result: vzdump runs under perl -T, which refuses
        # to write device/delete through a tainted path.
        push @sd, $1 if $w =~ /\Q$naa\E$/ && $blk =~ m{^(.*/sd[a-z]+)$};
    }
    return @sd;
}

=head2 detach($vol)

Releases the LUN on this host: flushes the multipath map (if any) and deletes
every SCSI device that reports the volume's WWID. Errors are logged, not
raised — the caller is on its way to revoking the ACL, which is the operation
that actually matters. Returns 1 if anything was removed, 0 otherwise.

=cut

sub detach {
    my ($self, $vol) = @_;
    my $wwid = $self->wwid($vol);

    my @sd = $self->_paths_for($wwid);
    my $had_map = $self->{_path_exists}->("$self->{_dev_root}/disk/by-id/dm-uuid-mpath-$wwid");
    return 0 unless @sd || $had_map;

    $self->{logger}->(info => "FCManager: detaching LUN $wwid (" . scalar(@sd) . " path(s))");

    if ($had_map) {
        eval { $self->_run('multipath', '-f', $wwid) };
        $self->{logger}->(warning => "FCManager: multipath flush of $wwid failed: $@") if $@;
    }
    for my $blk (@sd) {
        eval { $self->_write("$blk/device/delete", "1") };
        $self->{logger}->(warning => "FCManager: delete of $blk failed: $@") if $@;
    }
    return 1;
}

=head2 wait_for_detached($vol, $max_wait)

Polls until no SCSI device or by-id link for the WWID remains (default 60 s,
2 s interval). Returns 1 when gone, 0 on timeout.

=cut

sub wait_for_detached {
    my ($self, $vol, $max_wait) = @_;
    $max_wait //= 60;
    my $wwid = $self->wwid($vol);
    my $elapsed = 0;
    while ($elapsed < $max_wait) {
        return 1 if !$self->is_attached($vol) && !$self->_paths_for($wwid);
        $self->{_sleep}->(2);
        $elapsed += 2;
    }
    $self->{logger}->(warning => "FCManager: timeout waiting for LUN $wwid to detach");
    return 0;
}

=head2 rescan_volume($vol)

Refreshes the kernel's view of the LUN size after an appliance-side resize:
rescans each SCSI path and asks multipathd to resize the map when one exists.
Returns 1 on success, 0 when the LUN is not attached (no-op).

=cut

sub rescan_volume {
    my ($self, $vol) = @_;
    my $wwid = $self->wwid($vol);

    my @sd = $self->_paths_for($wwid);
    return 0 unless @sd;

    $self->{logger}->(info => "FCManager: rescanning LUN $wwid geometry");
    my $ok = 1;
    for my $blk (@sd) {
        eval { $self->_write("$blk/device/rescan", "1") };
        if ($@) { $self->{logger}->(warning => "FCManager: rescan of $blk failed: $@"); $ok = 0 }
    }
    if ($self->{_path_exists}->("$self->{_dev_root}/disk/by-id/dm-uuid-mpath-$wwid")) {
        eval { $self->_run('multipathd', 'resize', 'map', $wwid) };
        if ($@) { $self->{logger}->(warning => "FCManager: multipathd resize of $wwid failed: $@"); $ok = 0 }
    }
    return $ok;
}

=head2 transport_name()

Returns C<fc>.

=cut

sub transport_name { return 'fc' }

=head2 missing_device_hint()

Text appended to the plugin's "device did not appear" error.

=cut

sub missing_device_hint {
    return "check fabric zoning between this host's HBAs and the appliance's FC "
         . "target ports, and that the target ports are enabled on the appliance";
}

1;
