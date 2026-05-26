package PVE::Storage::Custom::QuantaStor;

use strict;
use warnings;
use Carp qw(croak);
use Sys::Hostname qw(hostname);

use base qw(PVE::Storage::Plugin);

use PVE::Storage::QuantaStor::APIClient;
use PVE::Storage::QuantaStor::ISCSIManager;

# Bind syslog once at load. PVE::SafeSyslog is present on every PVE host,
# but absent in the unit-test environment; falling back to a no-op keeps
# the module loadable for `prove` without stubbing the module.
my $_syslog_fn = sub { };
if (eval { require PVE::SafeSyslog; 1 }) {
    $_syslog_fn = \&PVE::SafeSyslog::syslog;
}

our $VERSION = '0.2.0';

=head1 NAME

PVE::Storage::Custom::QuantaStor - Proxmox VE storage plugin for QuantaStor appliances

=head1 DESCRIPTION

Registers the storage type C<quantastor> with Proxmox VE via the custom plugin
interface.  All volume management is performed via the QuantaStor REST API;
iSCSI login/logout is handled via L<PVE::Storage::QuantaStor::ISCSIManager>.

No PVE core files are modified by this plugin.  Install via the Debian package
or copy this file to C</usr/share/perl5/PVE/Storage/Custom/> and restart
pvedaemon.

=cut

# ---------------------------------------------------------------------------
# PVE Custom Plugin API version
# ---------------------------------------------------------------------------

=head2 api

Returns the PVE storage API version this plugin implements.

Declared at 13 deliberately. PVE 9.1 has APIVER=13 (hard-blocks anything
higher); PVE 9.2 has APIVER=14 with APIAGE=5, so 13 still loads — it just
warns "implementing an older storage API" once at plugin load. None of
the hooks we override changed between 13 and 14, so claiming 14 would
silence the warning at the cost of breaking every 9.1.x host outright.
Only bump if a new PVE version drops APIAGE such that 13 falls below
APIVER-APIAGE, or if we adopt a 14+ only hook.

=cut

sub api { return 13 }

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

my $MAX_LUNS_PER_VM = 1024;
my $DEFAULT_API_PORT = 8153;
my $SNAP_SEP = '_';   # separator between volume name and snapshot name

# ---------------------------------------------------------------------------
# Password file helpers
# Password is stored in /etc/pve/priv/storage/<storeid>.pw (mode 0600),
# consistent with the CIFS and PBS plugin conventions.
# ---------------------------------------------------------------------------

sub _password_file { return "/etc/pve/priv/storage/$_[0].pw" }

sub _set_password {
    my ($storeid, $password) = @_;
    mkdir '/etc/pve/priv/storage';
    PVE::Tools::file_set_contents(_password_file($storeid), "$password\n", 0600);
}

sub _get_password {
    my ($storeid) = @_;
    my $f = _password_file($storeid);
    return undef unless -f $f;
    my $pw = PVE::Tools::file_read_firstline($f);
    return $pw;
}

sub _delete_password {
    my ($storeid) = @_;
    my $f = _password_file($storeid);
    unlink $f if -f $f;
}

# ---------------------------------------------------------------------------
# Sensitive property lifecycle hooks
# ---------------------------------------------------------------------------

sub on_add_hook {
    my ($class, $storeid, $scfg, %sensitive) = @_;
    _set_password($storeid, $sensitive{password}) if defined $sensitive{password};
}

sub on_update_hook {
    my ($class, $storeid, $scfg, %sensitive) = @_;
    _set_password($storeid, $sensitive{password}) if defined $sensitive{password};
}

sub on_delete_hook {
    my ($class, $storeid, $scfg) = @_;
    _delete_password($storeid);
}

# ---------------------------------------------------------------------------
# Plugin registration
# ---------------------------------------------------------------------------

=head2 type

Returns C<'quantastor'> — the storage type identifier shown in the PVE UI.

=cut

sub type { return 'quantastor' }

=head2 plugindata

Declares supported content types (VM images only) and marks C<password> as
a sensitive property so PVE stores it encrypted.

=cut

sub plugindata {
    return {
        content              => [{ images => 1 }, { images => 1 }],  # [supported, default]
        'sensitive-properties' => { password => 1 },
    };
}

=head2 properties

Defines the QuantaStor-specific configuration fields that appear in the
storage editor UI and are stored in C</etc/pve/storage.cfg>.

=cut

sub properties {
    # Only declare properties that are NOT already registered by built-in PVE
    # plugins.  portal/blocksize/sparse are owned by ISCSIPlugin/ZFSPoolPlugin
    # and must not be re-declared.
    return {
        api_host => {
            description => 'QuantaStor appliance IP address or hostname',
            type        => 'string',
        },
        api_port => {
            description => 'QuantaStor REST API port (default 8153)',
            type        => 'integer',
            minimum     => 1,
            maximum     => 65535,
        },
        pool_id => {
            description => 'QuantaStor storage pool name or UUID',
            type        => 'string',
        },
        ssl_verify => {
            description => 'Verify QuantaStor SSL certificate (disable for self-signed certs)',
            type        => 'boolean',
        },
    };
}

=head2 options

Declares which fields are required vs optional and which are fixed after creation.

=cut

sub options {
    return {
        api_host   => { fixed => 1 },
        username   => { fixed => 1 },
        password   => { optional => 1 },
        pool_id    => { fixed => 1 },
        portal     => { optional => 1 },
        api_port   => { optional => 1 },
        blocksize  => { optional => 1 },
        sparse     => { optional => 1 },
        ssl_verify => { optional => 1 },
        nodes      => { optional => 1 },
        disable    => { optional => 1 },
        content    => { optional => 1 },
        bwlimit    => { optional => 1 },
    };
}

# ---------------------------------------------------------------------------
# Volume naming
# ---------------------------------------------------------------------------

=head2 parse_volname($volname)

Parses a QuantaStor volume name into its PVE components.

Supports the standard ZFS naming convention shared with ZFSPlugin:

    vm-<vmid>-disk-<N>
    base-<vmid>-disk-<N>
    base-<vmid>-disk-<N>/vm-<vmid>-disk-<N>   (cloned from template)

Returns C<($vtype, $name, $vmid, $basename, $basevmid, $isBase, $format)>.

=cut

sub parse_volname {
    my ($class, $volname) = @_;

    if ($volname =~ m/^(((base|basevol)-(\d+)-\S+)\/)?((base|basevol|vm|subvol)-(\d+)-\S+)$/) {
        my $format  = ($6 eq 'subvol' || $6 eq 'basevol') ? 'subvol' : 'raw';
        my $is_base = ($6 eq 'base'   || $6 eq 'basevol') ? 1        : 0;
        return ('images', $5, $7, $2, $4, $is_base, $format);
    }

    die "unable to parse quantastor volume name '$volname'\n";
}

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

# Build a logger coderef matching APIClient/ISCSIManager's ($level, $msg)
# contract. Routes through PVE::SafeSyslog and prefixes each line with the
# plugin tag plus the storeid for easy journalctl filtering.
sub _logger {
    my ($storeid) = @_;
    return sub {
        my ($level, $msg) = @_;
        $_syslog_fn->($level, "QuantaStor[$storeid]: $msg");
    };
}

# Build an APIClient from the storage config hash.
# Password is read from the private password file, not from scfg.
sub _client {
    my ($scfg, $storeid) = @_;

    my $password = _get_password($storeid) // $scfg->{password};
    if (!defined $password || $password eq '') {
        # /etc/pve/priv/storage/ is pmxcfs (cluster-replicated), but if a
        # node ends up without the password file — pmxcfs sync hiccup,
        # manual cleanup, or storage was added before this node joined the
        # cluster — every API call would hit a misleading QuantaStor
        # "err=26 authentication check failed". Fail loudly with the actual
        # cause instead.
        my $node = hostname();
        my $pwfile = _password_file($storeid);
        die "QuantaStor: no password configured for storage '$storeid' on "
          . "node '$node'.\n"
          . "  Expected $pwfile to exist and be non-empty.\n"
          . "  Re-set the password via 'pvesm set $storeid -password <pw>' "
          . "or in the UI under storage edit.\n";
    }

    return PVE::Storage::QuantaStor::APIClient->new(
        host       => $scfg->{api_host},
        port       => $scfg->{api_port} // $DEFAULT_API_PORT,
        username   => $scfg->{username},
        password   => $password,
        ssl_verify => $scfg->{ssl_verify} // 0,
        pool_id    => $scfg->{pool_id},
        logger     => _logger($storeid),
    );
}

# Build an ISCSIManager from the storage config hash.
sub _iscsi {
    my ($scfg, $storeid) = @_;
    my $portal = $scfg->{portal} // $scfg->{api_host};
    return PVE::Storage::QuantaStor::ISCSIManager->new(
        portal => $portal,
        logger => _logger($storeid),
    );
}

# Strip the 'qs-' prefix QuantaStor prepends to pool UUIDs in some contexts.
sub _raw_pool_id {
    my ($pool_id) = @_;
    (my $raw = $pool_id) =~ s/^qs-//;
    return $raw;
}

# Build the QuantaStor snapshot volume name from a PVE volname + snap label.
sub _snap_vol_name {
    my ($vol_name, $snap) = @_;
    return "${vol_name}${SNAP_SEP}${snap}";
}

# Extract the bare volume name from a PVE volname (strips any base prefix).
sub _bare_name {
    my ($class, $volname) = @_;
    return ($class->parse_volname($volname))[1];
}

# ---------------------------------------------------------------------------
# Storage status
# ---------------------------------------------------------------------------

=head2 status($storeid, $scfg, $cache)

Returns C<($total_bytes, $free_bytes, $used_bytes, $active)> for the pool.

=cut

sub status {
    my ($class, $storeid, $scfg, $cache) = @_;

    my ($total, $free, $used, $active) = (0, 0, 0, 0);

    eval {
        my $pool = _client($scfg, $storeid)->pool_get(_raw_pool_id($scfg->{pool_id}));
        $total  = $pool->{size}      // 0;
        $free   = $pool->{freeSpace} // 0;
        $used   = $total - $free;
        $active = 1;
    };
    warn "QuantaStor status error for '$storeid': $@" if $@;

    return ($total, $free, $used, $active);
}

# ---------------------------------------------------------------------------
# Volume listing
# ---------------------------------------------------------------------------

=head2 list_images($storeid, $scfg, $vmid, $vollist, $cache)

Returns an arrayref of volume info hashrefs for volumes in the configured pool,
optionally filtered by C<$vmid> or an explicit C<$vollist>.

=cut

sub list_images {
    my ($class, $storeid, $scfg, $vmid, $vollist, $cache) = @_;

    my $client = _client($scfg, $storeid);

    # pool_id in storage.cfg may be a name or a UUID. storagePoolId on volumes
    # is always a UUID, so resolve once via pool_get before filtering.
    my $pool_uuid = eval {
        $client->pool_get(_raw_pool_id($scfg->{pool_id}))->{id}
    } // _raw_pool_id($scfg->{pool_id});
    warn "QuantaStor list_images pool lookup error: $@" if $@;

    my $all_vols = eval { $client->volume_enum() } // [];
    warn "QuantaStor list_images error: $@" if $@;

    my $res = [];

    for my $vol (@$all_vols) {
        # Only include volumes belonging to our pool.
        next unless defined $vol->{storagePoolId}
            && $vol->{storagePoolId} eq $pool_uuid;

        my $name = $vol->{name};

        # Skip snapshots — they appear as separate volumes in QuantaStor but
        # PVE manages them through the snapshot hooks, not list_images.
        next if $vol->{isSnapshot} && $vol->{isSnapshot} eq '1';

        # Only handle names that follow the PVE naming convention.
        next unless $name =~ m/^(base|basevol|vm|subvol)-(\d+)-/;
        my $owner = $2;

        # Always emit the flat volid form. PVE's parse_volname accepts both
        # 'vm-X-disk-N' and 'base-Y-disk-N/vm-X-disk-N'; reconstructing the
        # latter for clones would require an extra volume_get per item to
        # resolve snapshotParent → base name, and PVE tracks the parent
        # relationship from VM config anyway.
        my $volid = "$storeid:$name";

        if ($vollist) {
            next unless grep { $_ eq $volid } @$vollist;
        } else {
            next if defined $vmid && $owner ne $vmid;
        }

        push @$res, {
            volid  => $volid,
            format => 'raw',
            size   => $vol->{size} // 0,
            vmid   => $owner,
            used   => 0,
        };
    }

    return $res;
}

# ---------------------------------------------------------------------------
# Volume path (called by PVE to get the block device for QEMU)
# ---------------------------------------------------------------------------

=head2 path($scfg, $volname, $storeid, $snapname)

Returns C<($device_path, $vmid, $vtype)>.

The device path is the stable C</dev/disk/by-path/> symlink for the iSCSI LUN.

=cut

sub path {
    my ($class, $scfg, $volname, $storeid, $snapname) = @_;

    die "direct snapshot access not supported on quantastor storage\n"
        if defined $snapname;

    my ($vtype, $name, $vmid) = $class->parse_volname($volname);

    # PVE's delete API handler calls path() BEFORE vdisk_free to look up
    # vtype/ownervm for permission checks. If the volume is already gone we
    # must not die here, or free_image's idempotent fast-path is unreachable.
    # Returning undef path is safe: PVE only uses $path here for backup-vtype
    # auxiliary cleanup, and our vtype is always 'images'.
    my $vol = _client($scfg, $storeid)->volume_get_or_undef($name);
    return (undef, $vmid, $vtype) unless $vol;

    my $iscsi = _iscsi($scfg, $storeid);

    # QuantaStor presents each volume as a dedicated iSCSI target at LUN 0
    # on the wire. The 'lun' field in volume_get is an internal QuantaStor
    # concept (position within a host group) and does not match the actual
    # iSCSI LUN number seen by the initiator.
    my $path = $iscsi->device_path($vol->{iqn}, 0);

    return ($path, $vmid, $vtype);
}

=head2 volume_size_info($scfg, $storeid, $volname, $timeout)

Returns the volume size in bytes (scalar context) or
C<($size, $format, $used, $parent)> in list context.

=cut

sub volume_size_info {
    my ($class, $scfg, $storeid, $volname, $timeout) = @_;

    my $name = _bare_name($class, $volname);
    my $vol  = _client($scfg, $storeid)->volume_get($name);

    my $size = $vol->{size} // 0;
    return wantarray ? ($size, 'raw', 0, undef) : $size;
}

# ---------------------------------------------------------------------------
# Storage activation
# ---------------------------------------------------------------------------

=head2 activate_storage($storeid, $scfg, $cache)

Verifies API connectivity and ensures this PVE node is registered as an
initiator host in QuantaStor.  Called once per storage mount.

=cut

sub activate_storage {
    my ($class, $storeid, $scfg, $cache) = @_;

    my $client = _client($scfg, $storeid);
    my $iscsi  = _iscsi($scfg, $storeid);

    # Verify connectivity — will die on network/auth failure.
    $client->pool_get(_raw_pool_id($scfg->{pool_id}));

    # Register this node as a QuantaStor host if it isn't already.
    my $iqn      = $iscsi->get_initiator_iqn();
    my $hostname = hostname() . '-pve';
    $client->ensure_host_registered($hostname, $iqn,
        description => 'Registered by Proxmox VE QuantaStor plugin');

    return 1;
}

=head2 deactivate_storage($storeid, $scfg, $cache)

No-op — iSCSI sessions are torn down per-volume in C<deactivate_volume>.

=cut

sub deactivate_storage {
    my ($class, $storeid, $scfg, $cache) = @_;
    return 1;
}

# ---------------------------------------------------------------------------
# Volume activation (iSCSI login/logout)
# ---------------------------------------------------------------------------

=head2 activate_volume($storeid, $scfg, $volname, $snapname, $cache)

Grants this node access to the volume via ACL and logs in to the iSCSI target.

=cut

sub activate_volume {
    my ($class, $storeid, $scfg, $volname, $snapname, $cache) = @_;

    die "snapshot activation not supported on quantastor storage\n"
        if defined $snapname;

    my $name   = _bare_name($class, $volname);
    my $client = _client($scfg, $storeid);
    my $iscsi  = _iscsi($scfg, $storeid);

    my $vol = $client->volume_get($name);
    my $iqn = $iscsi->get_initiator_iqn();

    # Grant access then login — order matters.
    $client->volume_acl_add($vol->{id}, $iqn);
    $iscsi->login($vol->{iqn});

    # Wait for the by-path symlink before returning. PVE expects activate_volume
    # to leave the device usable; if we return before udev creates the symlink,
    # QEMU fails to open the disk with a confusing low-level error.
    unless ($iscsi->wait_for_device($vol->{iqn}, 0)) {
        my $dev = $iscsi->device_path($vol->{iqn}, 0);
        die "QuantaStor activate_volume: iSCSI device '$dev' did not appear "
          . "after 30s — check that iscsid is running and the LUN is exported\n";
    }

    return 1;
}

=head2 deactivate_volume($storeid, $scfg, $volname, $snapname, $cache)

Logs out of the iSCSI target and revokes ACL access for this node.

=cut

sub deactivate_volume {
    my ($class, $storeid, $scfg, $volname, $snapname, $cache) = @_;

    die "snapshot deactivation not supported on quantastor storage\n"
        if defined $snapname;

    my $name   = _bare_name($class, $volname);
    my $client = _client($scfg, $storeid);
    my $iscsi  = _iscsi($scfg, $storeid);

    my $vol  = $client->volume_get($name);
    my $iqn  = $iscsi->get_initiator_iqn();
    my $host = $client->host_get($iqn);

    # Logout first, then remove ACL — reverse of activate_volume.
    $iscsi->logout($vol->{iqn});
    $iscsi->wait_for_logout($vol->{iqn});

    $client->volume_acl_remove($vol->{id}, $host->{id}) if $host;

    return 1;
}

# ---------------------------------------------------------------------------
# Volume allocation / deallocation
# ---------------------------------------------------------------------------

=head2 alloc_image($storeid, $scfg, $vmid, $fmt, $name, $size)

Creates a new volume in QuantaStor.  C<$size> is in kilobytes (PVE convention).
Returns the volname (not the full volid).

=cut

sub alloc_image {
    my ($class, $storeid, $scfg, $vmid, $fmt, $name, $size) = @_;

    die "unsupported format '$fmt' — quantastor storage only supports 'raw'\n"
        if $fmt ne 'raw';

    die "illegal name '$name' — should be 'vm-$vmid-*'\n"
        if $name && $name !~ m/^vm-$vmid-/;

    $name //= $class->find_free_diskname($storeid, $scfg, $vmid, $fmt);

    my $client   = _client($scfg, $storeid);
    my $pool_raw = _raw_pool_id($scfg->{pool_id});

    $client->volume_create($name, $size, $pool_raw);

    return $name;
}

=head2 free_image($storeid, $scfg, $volname, $isBase)

Deactivates and permanently deletes a volume (and all its snapshots).

=cut

sub free_image {
    my ($class, $storeid, $scfg, $volname, $isBase) = @_;

    my $name   = _bare_name($class, $volname);
    my $client = _client($scfg, $storeid);
    my $iscsi  = _iscsi($scfg, $storeid);

    # Idempotent: if the volume is already gone on QuantaStor, treat as success.
    # PVE retries deletes on some failure paths; raising "not found" would
    # create a stuck state.
    my $vol = $client->volume_get_or_undef($name);
    return undef unless $vol;

    # Best-effort detach. A volume that's already offline, whose host has been
    # removed, or whose iSCSI session is stale should still be deletable —
    # don't let teardown errors mask the real goal.
    eval {
        my $iqn  = $iscsi->get_initiator_iqn();
        my $host = $client->host_get($iqn);

        $iscsi->logout($vol->{iqn});
        $iscsi->wait_for_logout($vol->{iqn});
        $client->volume_acl_remove($vol->{id}, $host->{id}) if $host;
    };
    warn "free_image teardown warning for '$volname': $@" if $@;

    # Force-delete + cascade so snapshots of this volume go too. PVE expects
    # free_image to leave nothing behind for this volname.
    $client->volume_delete($vol->{id}, delete_options => 4, flags => 2);
    return undef;
}

=head2 volume_resize($scfg, $storeid, $volname, $size, $running)

Grows a volume to C<$size> bytes.  Shrinking is not supported by QuantaStor.

=cut

sub volume_resize {
    my ($class, $scfg, $storeid, $volname, $size, $running) = @_;

    my $name   = _bare_name($class, $volname);
    my $client = _client($scfg, $storeid);

    my $vol      = $client->volume_get($name);
    my $pool_raw = _raw_pool_id($scfg->{pool_id});

    # flags=2 forces the resize through QuantaStor's "active session" check
    # ([err=76]). This is essential for running VMs: logging out the iSCSI
    # session would destroy the kernel block device QEMU has bound to its
    # open fd, breaking the disk for the live guest. With force, the resize
    # happens online and QEMU's fd stays valid against the same /dev/sdX.
    $client->volume_resize($vol->{id}, $pool_raw, $size, flags => 2);

    # Always rescan — the iSCSI session is typically still alive even for
    # stopped VMs (PVE doesn't call deactivate_volume on stop for shared
    # iSCSI). Without a rescan, the kernel keeps its cached pre-resize LUN
    # geometry; QEMU's next block_resize QMP (running) or fresh VM start
    # (stopped) would then see the stale size. rescan is a no-op when no
    # session is active.
    my $iscsi = _iscsi($scfg, $storeid);
    $iscsi->rescan($vol->{iqn});

    return $size;
}

# ---------------------------------------------------------------------------
# Snapshot management
# ---------------------------------------------------------------------------

=head2 volume_snapshot($scfg, $storeid, $volname, $snap)

Takes a snapshot of C<$volname> with label C<$snap>.
The QuantaStor snapshot volume is named C<${volname}_${snap}>.

=cut

sub volume_snapshot {
    my ($class, $scfg, $storeid, $volname, $snap) = @_;

    my $name      = _bare_name($class, $volname);
    my $snap_name = _snap_vol_name($name, $snap);

    _client($scfg, $storeid)->volume_snapshot($name, $snap_name);

    return undef;
}

=head2 volume_snapshot_delete($scfg, $storeid, $volname, $snap, $running)

Deletes the QuantaStor snapshot volume for C<$snap>.

=cut

sub volume_snapshot_delete {
    my ($class, $scfg, $storeid, $volname, $snap, $running) = @_;

    my $name      = _bare_name($class, $volname);
    my $snap_name = _snap_vol_name($name, $snap);

    my $client = _client($scfg, $storeid);
    # Idempotent: if the snapshot is already gone, treat as success.
    my $snap_vol = $client->volume_get_or_undef($snap_name);
    return undef unless $snap_vol;

    # Force-delete: PVE expects volume_snapshot_delete to remove the snapshot
    # even if QuantaStor considers it busy.
    $client->volume_delete($snap_vol->{id}, flags => 2);

    return undef;
}

=head2 volume_rollback_is_possible($scfg, $storeid, $volname, $snap, $blockers)

Asserts that C<$snap> is the most recent snapshot of C<$volname>.
Dies if the rollback is blocked; pushes blocker names onto C<$blockers> if provided.

=cut

sub volume_rollback_is_possible {
    my ($class, $scfg, $storeid, $volname, $snap, $blockers) = @_;

    my $name       = _bare_name($class, $volname);
    my $snap_name  = _snap_vol_name($name, $snap);
    my $client     = _client($scfg, $storeid);

    my $target = $client->volume_get($snap_name);
    die "can't rollback — snapshot '$snap' does not exist on '$volname'\n"
        unless defined $target->{id};

    my $target_ts = $target->{createdTimeStamp}
        or die "can't rollback — snapshot '$snap' has no timestamp\n";

    # Enumerate all volumes and find any snapshots of the same parent that
    # are newer than our target snapshot.
    my $all = $client->volume_enum();
    my $blocked = 0;

    for my $item (@$all) {
        next unless ($item->{isSnapshot} // '') eq '1';
        next unless (defined $item->{snapshotParent})
            && $item->{snapshotParent} eq ($target->{snapshotParent} // '');
        next unless ($item->{createdTimeStamp} // '') gt $target_ts;

        $blocked = 1;
        push @$blockers, $item->{name} if defined $blockers;
    }

    die "can't rollback — '$snap' is not the most recent snapshot on '$volname'\n"
        if $blocked;

    return 1;
}

=head2 volume_snapshot_rollback($scfg, $storeid, $volname, $snap)

Rolls C<$volname> back to C<$snap>: logout → rollback → login.

=cut

sub volume_snapshot_rollback {
    my ($class, $scfg, $storeid, $volname, $snap) = @_;

    my $name      = _bare_name($class, $volname);
    my $snap_name = _snap_vol_name($name, $snap);
    my $client    = _client($scfg, $storeid);
    my $iscsi     = _iscsi($scfg, $storeid);

    my $vol = $client->volume_get($name);

    # PVE guarantees QEMU is stopped before calling this hook, but the iSCSI
    # session may still be lingering (kernel session outlives the QEMU process).
    # Log out so QuantaStor will accept the rollback on an otherwise-idle target.
    # Do NOT re-login here — PVE calls activate_volume when the VM next starts.
    if ($iscsi->is_logged_in($vol->{iqn})) {
        $iscsi->logout($vol->{iqn});
        $iscsi->wait_for_logout($vol->{iqn});
    }

    # PVE-side logout returns before QuantaStor's server-side session tracker
    # GCs the connection. Volume rollback rejects on an active QS session, so
    # poll QS until it agrees the target is idle.
    $client->wait_for_session_gone($name);

    $client->volume_rollback($vol->{id}, $snap_name);

    return undef;
}

# ---------------------------------------------------------------------------
# Template and clone
# ---------------------------------------------------------------------------

=head2 create_base($storeid, $scfg, $volname)

Converts a VM disk into a reusable base image:

  1. Log out / remove ACL
  2. Rename  vm-<vmid>-disk-N  →  base-<vmid>-disk-N
  3. Take a template snapshot  (template-base-<vmid>-disk-N)
  4. Re-grant ACL / log back in

Returns the new base volname.

=cut

sub create_base {
    my ($class, $storeid, $scfg, $volname) = @_;

    my ($vtype, $name, $vmid, $basename, $basevmid, $isBase) =
        $class->parse_volname($volname);

    die "create_base not possible with an existing base image\n" if $isBase;

    my $newname = $name;
    $newname =~ s/^vm-/base-/;

    my $client = _client($scfg, $storeid);
    my $iscsi  = _iscsi($scfg, $storeid);
    my $iqn    = $iscsi->get_initiator_iqn();

    my $vol  = $client->volume_get($name);
    my $host = $client->host_get($iqn);

    # Take offline.
    $iscsi->logout($vol->{iqn});
    $iscsi->wait_for_logout($vol->{iqn});
    $client->volume_acl_remove($vol->{id}, $host->{id}) if $host;

    # Wait for QuantaStor to GC its server-side view of the session before
    # mutating the volume — rename rejects on an active session.
    $client->wait_for_session_gone($name);

    # Rename to base- convention.
    my $renamed = $client->volume_modify($vol->{id}, $newname);
    my $new_iqn = ref $renamed eq 'HASH' && $renamed->{iqn}
        ? $renamed->{iqn}
        : $client->volume_get($newname)->{iqn};

    # Re-grant access and bring online.
    $client->volume_acl_add($vol->{id}, $iqn);
    $iscsi->login($new_iqn);

    # Create the template snapshot that clone_image will clone from.
    my $template_snap = "template-$newname";
    $client->volume_snapshot($newname, $template_snap,
        description => 'Template snapshot created by Proxmox VE');

    my $newvolname = $basename ? "$basename/$newname" : $newname;
    return $newvolname;
}

=head2 clone_image($scfg, $storeid, $volname, $vmid, $snap)

Clones a base image's template snapshot into a new VM disk volume.

=cut

sub clone_image {
    my ($class, $scfg, $storeid, $volname, $vmid, $snap) = @_;

    my ($vtype, $name, undef, undef, undef, $isBase) =
        $class->parse_volname($volname);

    die "clone_image only works on base images\n" unless $isBase;

    my $client      = _client($scfg, $storeid);
    my $iscsi       = _iscsi($scfg, $storeid);
    my $iqn         = $iscsi->get_initiator_iqn();
    my $template_snap = "template-$name";
    my $newname     = $class->find_free_diskname($storeid, $scfg, $vmid, 'raw');

    my $result = $client->volume_clone($template_snap, $newname,
        description => "Cloned from $name by Proxmox VE (vmid $vmid)");

    # The clone API returns { obj => { id => ..., iqn => ... } } on success.
    my $new_vol = (ref $result eq 'HASH' && $result->{obj}) ? $result->{obj} : $result;

    # Grant access and login to the new clone.
    $client->volume_acl_add($new_vol->{id}, $iqn);
    $iscsi->login($new_vol->{iqn});

    return $newname;
}

# ---------------------------------------------------------------------------
# Feature advertisement
# ---------------------------------------------------------------------------

=head2 volume_has_feature($scfg, $feature, $storeid, $volname, $snapname, $running)

Declares which PVE features this plugin supports.

=cut

sub volume_has_feature {
    my ($class, $scfg, $feature, $storeid, $volname, $snapname, $running) = @_;

    my $features = {
        snapshot  => { current => 1, snap => 1 },
        clone     => { base    => 1 },
        template  => { current => 1 },
        copy      => { base    => 1, current => 1 },
        sparseinit => { base   => 1, current => 1 },
    };

    my ($vtype, $name, $vmid, $basename, $basevmid, $isBase) =
        $class->parse_volname($volname);

    my $key = $snapname ? 'snap' : ($isBase ? 'base' : 'current');

    return 1 if $features->{$feature}{$key};
    return undef;
}

=head2 storage_can_replicate

Returns 0 — replication is not supported in this release.

=cut

sub storage_can_replicate {
    my ($class, $scfg, $storeid, $format) = @_;
    return 0;
}

1;
