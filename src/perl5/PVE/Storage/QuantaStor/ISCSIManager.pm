package PVE::Storage::QuantaStor::ISCSIManager;

use strict;
use warnings;
use Carp qw(croak);

our $VERSION = '1.0.0';

=head1 NAME

PVE::Storage::QuantaStor::ISCSIManager - iSCSI initiator lifecycle for QuantaStor volumes

=head1 SYNOPSIS

    my $iscsi = PVE::Storage::QuantaStor::ISCSIManager->new(
        portal => '10.0.0.1',
    );

    my $iqn = $iscsi->get_initiator_iqn();
    $iscsi->login('iqn.2009-10.com.osnexus:pool-uuid:vm-100-disk-0');
    my $dev = $iscsi->device_path('iqn.2009-10.com.osnexus:pool-uuid:vm-100-disk-0');
    $iscsi->wait_for_logout('iqn.2009-10.com.osnexus:pool-uuid:vm-100-disk-0');
    $iscsi->logout('iqn.2009-10.com.osnexus:pool-uuid:vm-100-disk-0');

=head1 DESCRIPTION

Manages iscsiadm login/logout/discovery for QuantaStor-exported iSCSI targets.

Device paths are resolved through C</dev/disk/by-path/> (stable across reboots)
rather than ephemeral C</dev/sdX> assignments.

All iscsiadm invocations are routed through an injectable C<_run_cmd> coderef,
allowing the full command path to be mocked in unit tests without touching the
filesystem or spawning real processes.

=cut

# ---------------------------------------------------------------------------
# Constructor
# ---------------------------------------------------------------------------

=head2 new(%args)

Required: C<portal> — IP address (or IP:port) of the iSCSI portal.

Optional:

=over

=item logger

Coderef C<($level, $message)>. Defaults to no-op.

=item _run_cmd

Coderef for running system commands. Receives a flat list of args (no shell).
Must return the combined stdout/stderr string on success and die on failure.
Defaults to an implementation that tries C<PVE::Tools::run_command> and falls
back to C<IPC::Open3>.

=item _initiator_file

Path to the initiatorname.iscsi file. Defaults to C</etc/iscsi/initiatorname.iscsi>.
Override in tests to avoid needing the real file.

=back

=cut

sub new {
    my ($class, %args) = @_;

    croak "ISCSIManager: 'portal' is required" unless $args{portal};

    my $self = {
        portal          => $args{portal},
        logger          => $args{logger}         // sub {},
        _run_cmd        => $args{_run_cmd},
        _initiator_file => $args{_initiator_file} // '/etc/iscsi/initiatorname.iscsi',

        # Coderef receiving a single path string, returning truthy if the path
        # currently exists. Default uses -e on the filesystem; tests inject a
        # stub so they don't touch /dev/disk/by-path.
        _path_exists    => $args{_path_exists}   // sub { -e $_[0] },

        # Coderef receiving a number of seconds to sleep. Default is the
        # built-in sleep; tests inject a no-op so wait_for_* loops are instant.
        _sleep          => $args{_sleep}         // sub { sleep $_[0] },
    };

    return bless $self, $class;
}

# ---------------------------------------------------------------------------
# Internal command runner
# ---------------------------------------------------------------------------

# Runs a command given as a list, returns combined output string.
# Dies on non-zero exit.
sub _run {
    my ($self, @cmd) = @_;

    if ($self->{_run_cmd}) {
        return $self->{_run_cmd}->(@cmd);
    }

    return _default_run(@cmd);
}

sub _default_run {
    my (@cmd) = @_;

    # Prefer PVE::Tools::run_command when available — it handles logging and
    # provides safe exec without a shell.
    if (eval { require PVE::Tools; 1 }) {
        my $output = '';
        PVE::Tools::run_command(
            \@cmd,
            outfunc => sub { $output .= "$_[0]\n" },
            errfunc => sub { $output .= "$_[0]\n" },
        );
        return $output;
    }

    # Fallback: IPC::Open3 for safe exec without shell interpolation.
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

# ---------------------------------------------------------------------------
# Initiator identity
# ---------------------------------------------------------------------------

=head2 get_initiator_iqn()

Reads and returns the local iSCSI initiator IQN from C<initiatorname.iscsi>.
Dies if the file cannot be read or contains no C<InitiatorName> entry.

=cut

sub get_initiator_iqn {
    my ($self) = @_;

    open my $fh, '<', $self->{_initiator_file}
        or croak "Cannot open '$self->{_initiator_file}': $!";

    while (my $line = <$fh>) {
        if ($line =~ /^\s*InitiatorName\s*=\s*([\.\-:\w]+)/) {
            close $fh;
            return $1;
        }
    }
    close $fh;
    croak "No InitiatorName found in '$self->{_initiator_file}'";
}

# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

=head2 discover()

Runs C<iscsiadm -m discovery -t sendtargets -p $portal>.
Returns 1 on success, 0 on failure (non-fatal — the target node record may
already exist from a previous discovery).

=cut

sub discover {
    my ($self) = @_;

    $self->{logger}->(debug => "ISCSIManager: discovery at $self->{portal}");

    eval {
        $self->_run('iscsiadm', '-m', 'discovery',
            '-t', 'sendtargets',
            '-p', $self->{portal});
    };
    if ($@) {
        $self->{logger}->(warning => "ISCSIManager: discovery warning: $@");
        return 0;
    }
    return 1;
}

# ---------------------------------------------------------------------------
# Login / logout
# ---------------------------------------------------------------------------

=head2 login($target_iqn)

Discovers (if needed) and logs in to C<$target_iqn> via the configured portal.
Dies on failure.

=cut

sub login {
    my ($self, $target_iqn) = @_;
    croak "login: target_iqn is required" unless defined $target_iqn && length $target_iqn;

    # Idempotent: already logged in means the goal is already achieved.
    return 1 if $self->is_logged_in($target_iqn);

    # Run discovery first so the node record exists.
    $self->discover();

    $self->{logger}->(info => "ISCSIManager: login $target_iqn via $self->{portal}");

    eval {
        $self->_run('iscsiadm', '-m', 'node',
            '--targetname', $target_iqn,
            '--portal',     $self->{portal},
            '--login');
    };
    croak "iSCSI login failed for '$target_iqn': $@" if $@;

    return 1;
}

=head2 logout($target_iqn)

Logs out of C<$target_iqn>. Returns 1 on success, 0 if the session was not
active (treated as a warning, not an error).

=cut

sub logout {
    my ($self, $target_iqn) = @_;
    croak "logout: target_iqn is required" unless defined $target_iqn && length $target_iqn;

    $self->{logger}->(info => "ISCSIManager: logout $target_iqn via $self->{portal}");

    eval {
        $self->_run('iscsiadm', '-m', 'node',
            '--targetname', $target_iqn,
            '--portal',     $self->{portal},
            '--logout');
    };
    if ($@) {
        $self->{logger}->(warning =>
            "ISCSIManager: logout warning (may already be logged out): $@");
        return 0;
    }
    return 1;
}

# ---------------------------------------------------------------------------
# Session inspection
# ---------------------------------------------------------------------------

=head2 is_logged_in($target_iqn)

Returns 1 if there is an active iSCSI session for C<$target_iqn>, 0 otherwise.

=cut

sub is_logged_in {
    my ($self, $target_iqn) = @_;
    croak "is_logged_in: target_iqn is required" unless defined $target_iqn && length $target_iqn;

    my $output = eval {
        $self->_run('iscsiadm', '-m', 'session');
    };
    # A non-zero exit from 'iscsiadm -m session' means no sessions at all.
    return 0 if $@;
    return 0 unless defined $output;

    return ($output =~ /\Q$target_iqn\E/) ? 1 : 0;
}

# ---------------------------------------------------------------------------
# Device path resolution
# ---------------------------------------------------------------------------

=head2 device_path($target_iqn, $lun)

Returns the stable C</dev/disk/by-path/> symlink path for the given target IQN
and LUN number (default 0).

The path is predictable and survives reboots, unlike C</dev/sdX> assignments.

=cut

sub device_path {
    my ($self, $target_iqn, $lun) = @_;
    croak "device_path: target_iqn is required" unless defined $target_iqn && length $target_iqn;
    $lun //= 0;

    # Split portal into host and port. The by-path symlink udev creates always
    # embeds the actual portal port iscsiadm connected on — so if the user
    # configured a non-3260 portal we must use that port here, not a default.
    my ($host, $port) = $self->{portal} =~ /^(.+?)(?::(\d+))?$/;
    $port //= 3260;

    return "/dev/disk/by-path/ip-${host}:${port}-iscsi-${target_iqn}-lun-${lun}";
}

# ---------------------------------------------------------------------------
# Multipath discovery
# ---------------------------------------------------------------------------

=head2 discover_portals($target_iqn)

Sendtargets discovery against the configured portal, returns every
ip:port QuantaStor advertises for $target_iqn (one entry per NIC/path).

=cut

sub discover_portals {
    my ($self, $target_iqn, %opt) = @_;
    croak "discover_portals: target_iqn is required"
        unless defined $target_iqn && length $target_iqn;

    my $tries = $opt{tries} // 5;
    my $delay = $opt{delay} // 1;

    for my $attempt (1 .. $tries) {
        my @out = eval { $self->_run('iscsiadm', '-m', 'discovery',
            '-t', 'sendtargets', '-p', $self->{portal}) };

        my %portals;
        # defensive: _run may hand back one multi-line blob instead of
        # pre-split lines, so re-split everything on newlines ourselves.
        for my $chunk (@out) {
            for my $line (split /\r?\n/, $chunk) {
                $line =~ s/^\s+|\s+$//g;
                next unless $line =~ /^([\d.]+:\d+),\d+\s+(\S+)$/;
                $portals{$1} = 1 if $2 eq $target_iqn;
            }
        }

        my @portals = sort keys %portals;
        if (@portals) {
            $self->{logger}->(info => "ISCSIManager: discovered "
                . scalar(@portals) . " portal(s) for $target_iqn"
                . ($attempt > 1 ? " (attempt $attempt)" : ""));
            return @portals;
        }

        $self->{logger}->(info => "ISCSIManager: discovery attempt "
            . "$attempt/$tries found no portals for $target_iqn yet"
            . " (ACL may still be propagating), retrying...")
            if $attempt < $tries;
        sleep $delay if $attempt < $tries;
    }

    croak "discover_portals: no portals found for '$target_iqn' via "
        . "$self->{portal} after $tries attempts";
}

=head2 login_all($target_iqn)

Logs in to every portal returned by discover_portals(), one iSCSI
session/path per portal. Dies only if ALL logins fail.

=cut

sub login_all {
    my ($self, $target_iqn) = @_;

    my @portals = eval { $self->discover_portals($target_iqn) };
    if ($@ || !@portals) {
        $self->{logger}->(info => "ISCSIManager: falling back to single "
            . "portal login for $target_iqn ($self->{portal})");
        $self->login($target_iqn);
        return 1;
    }

    my ($ok, @errs) = (0);
    for my $portal (@portals) {
        eval {
            $self->_run('iscsiadm', '-m', 'node',
                '--targetname', $target_iqn,
                '--portal', $portal, '--login');
            $ok++;
        };
        push @errs, "$portal: $@" if $@;
    }
    croak "login_all: all logins failed for '$target_iqn': " . join('; ', @errs)
        unless $ok;

    $self->{logger}->(info => "ISCSIManager: $ok/" . scalar(@portals)
        . " path(s) logged in for $target_iqn");
    return $ok;
}

=head2 logout_all($target_iqn)

Logs out every path for $target_iqn. Non-fatal.

=cut

sub logout_all {
    my ($self, $target_iqn) = @_;
    my @portals = eval { $self->discover_portals($target_iqn) };

    my $any = 0;
    for my $portal (@portals) {
        eval {
            $self->_run('iscsiadm', '-m', 'node',
                '--targetname', $target_iqn,
                '--portal', $portal, '--logout');
            $any = 1;
        };
    }
    $self->logout($target_iqn) unless $any; # fallback: old single-path logout
    return 1;
}

=head2 wwid_for($target_iqn, $lun)

Resolves the LUN's SCSI WWID via udev using whichever by-path device
is currently up (WWID is a LUN property, not path-specific).

=cut

sub wwid_for {
    my ($self, $target_iqn, $lun) = @_;
    $lun //= 0;

    croak "wwid_for: no path up for '$target_iqn' lun $lun"
        unless $self->wait_for_device($target_iqn, $lun, 30);

    my $dev = $self->device_path($target_iqn, $lun);
    my @out = $self->_run('/lib/udev/scsi_id', '--whitelisted', "--device=$dev");
    my $wwid = $out[0] // '';
    $wwid =~ s/\s+$//;
    croak "wwid_for: scsi_id returned no WWID for $dev" unless length $wwid;
    return $wwid;
}

=head2 mapper_path($target_iqn, $lun) / wait_for_mapper(...)

Ensures multipathd owns the WWID and returns/waits for /dev/mapper/<wwid>.
Call AFTER login_all() so all sessions exist before the map is built.

=cut

sub mapper_path {
    my ($self, $target_iqn, $lun) = @_;
    my $wwid = $self->wwid_for($target_iqn, $lun // 0);
    eval { $self->_run('multipath', '-a', $wwid) };  # ignore "already in wwids"
    $self->_run('multipath', '-r');                  # (re)build the map
    return "/dev/mapper/$wwid";
}

sub wait_for_mapper {
    my ($self, $target_iqn, $lun, $max_wait) = @_;
    $max_wait //= 30;
    my $mapper = $self->mapper_path($target_iqn, $lun // 0);
    for (my $t = 0; $t <= $max_wait; $t++) {
        return $mapper if -e $mapper;
        sleep 1;
        eval { $self->_run('multipath', '-r') };
    }
    return undef;
}

# ---------------------------------------------------------------------------
# Wait for session teardown
# ---------------------------------------------------------------------------

=head2 wait_for_logout($target_iqn, $max_wait)

Polls C<is_logged_in> until the session disappears or C<$max_wait> seconds
(default 60) have elapsed. Returns 1 if the session is gone, 0 on timeout.

Caller must invoke C<logout()> first — this method only waits; it does not
initiate the logout itself.

Used before volume rollback or deletion to ensure the OS has released the
block device before QuantaStor attempts to modify the volume.

=cut

sub wait_for_logout {
    my ($self, $target_iqn, $max_wait) = @_;
    croak "wait_for_logout: target_iqn is required"
        unless defined $target_iqn && length $target_iqn;

    $max_wait //= 60;
    my $interval = 2;
    my $elapsed  = 0;

    $self->{logger}->(
        info => "ISCSIManager: waiting for logout of '$target_iqn' (max ${max_wait}s)");

    while ($elapsed < $max_wait) {
        return 1 unless $self->is_logged_in($target_iqn);
        $self->{_sleep}->($interval);
        $elapsed += $interval;
    }

    $self->{logger}->(
        warning => "ISCSIManager: timeout waiting for logout of '$target_iqn'");
    return 0;
}

# ---------------------------------------------------------------------------
# Wait for block device to appear after login
# ---------------------------------------------------------------------------

=head2 wait_for_device($target_iqn, $lun, $max_wait)

Polls C</dev/disk/by-path/> for the iSCSI device symlink to appear after a
login. udev creates this symlink asynchronously once the kernel SCSI layer
enumerates the new LUN, so we must wait before returning a path that QEMU
will try to open.

Returns 1 once the symlink exists, 0 on timeout. Default C<$max_wait> is 30
seconds; polling interval is 1 second.

=cut

sub wait_for_device {
    my ($self, $target_iqn, $lun, $max_wait) = @_;
    croak "wait_for_device: target_iqn is required"
        unless defined $target_iqn && length $target_iqn;
    $lun      //= 0;
    $max_wait //= 30;

    my $path     = $self->device_path($target_iqn, $lun);
    my $interval = 1;
    my $elapsed  = 0;

    while ($elapsed < $max_wait) {
        return 1 if $self->{_path_exists}->($path);
        $self->{_sleep}->($interval);
        $elapsed += $interval;
    }

    $self->{logger}->(
        warning => "ISCSIManager: timeout waiting for device '$path'");
    return 0;
}

# ---------------------------------------------------------------------------
# Session rescan
# ---------------------------------------------------------------------------

=head2 rescan($target_iqn)

Rescans the iSCSI session for C<$target_iqn> to refresh LUN geometry in the
kernel.  Must be called after the storage side has resized a LUN while the
session is active (e.g. after a C<volume_resize> on a running VM), so that
the kernel block device reports the updated capacity before callers query it.

Returns 1 on success, 0 if the session is not active (no-op, not an error).

=cut

sub rescan {
    my ($self, $target_iqn) = @_;
    croak "rescan: target_iqn is required"
        unless defined $target_iqn && length $target_iqn;

    return 0 unless $self->is_logged_in($target_iqn);

    $self->{logger}->(info => "ISCSIManager: rescan session for $target_iqn");

    eval {
        $self->_run('iscsiadm', '-m', 'node',
            '--targetname', $target_iqn,
            '--portal',     $self->{portal},
            '--rescan');
    };
    if ($@) {
        $self->{logger}->(warning =>
            "ISCSIManager: rescan warning for '$target_iqn': $@");
        return 0;
    }
    return 1;
}

1;
