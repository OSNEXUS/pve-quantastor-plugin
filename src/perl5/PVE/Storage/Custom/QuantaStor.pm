package PVE::Storage::Custom::QuantaStor;

use strict;
use warnings;
use Carp qw(croak);
use Sys::Hostname qw(hostname);

use base qw(PVE::Storage::Plugin);

use PVE::Storage::QuantaStor::APIClient;
use PVE::Storage::QuantaStor::ISCSIManager;
use PVE::Storage::QuantaStor::FCManager;

# Bind syslog once at load. PVE::SafeSyslog is present on every PVE host,
# but absent in the unit-test environment; falling back to a no-op keeps
# the module loadable for `prove` without stubbing the module.
my $_syslog_fn = sub { };
if (eval { require PVE::SafeSyslog; 1 }) {
    $_syslog_fn = \&PVE::SafeSyslog::syslog;
}

our $VERSION = '1.2.0';

=head1 NAME

PVE::Storage::Custom::QuantaStor - Proxmox VE storage plugin for QuantaStor appliances

=head1 DESCRIPTION

Registers the storage type C<quantastor> with Proxmox VE via the custom plugin
interface.  All volume management is performed via the QuantaStor REST API;
iSCSI login/logout is handled via L<PVE::Storage::QuantaStor::ISCSIManager>,
Fibre Channel attach/detach via L<PVE::Storage::QuantaStor::FCManager>.

No PVE core files are modified by this plugin.  Install via the Debian package
or copy this file to C</usr/share/perl5/PVE/Storage/Custom/> and restart
pvedaemon.

=cut

# ---------------------------------------------------------------------------
# PVE Custom Plugin API version
# ---------------------------------------------------------------------------

=head2 api

Returns the PVE storage API version this plugin implements.

Reports the node's own storage API version (C<PVE::Storage::APIVER>, which
PVE defines before it calls C<api()>), clamped to 13..C<$MAX_API>. A PVE 9.1
node (13) and a PVE 9.2 node (16) both load the plugin without the "older
storage API" warning, and one package serves both. A node newer than
C<$MAX_API> still loads it, with that warning, until the newer API versions
are reviewed and C<$MAX_API> is raised.

=cut

my $MAX_API = 16;   # highest storage API reviewed and tested against

sub api {
    my $node = eval { PVE::Storage::APIVER() } // 13;
    return $node < 13 ? 13 : $node > $MAX_API ? $MAX_API : $node;
}

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

my $MAX_LUNS_PER_VM = 1024;
my $DEFAULT_API_PORT = 8153;
my $SNAP_SEP = '_';   # separator between volume name and snapshot name

# Retry budget for the clone/activate ACL race (see activate_volume).
# Package vars so tests can localize them to keep the suite fast.
our $ACL_ADD_ATTEMPTS   = 5;
our $ACL_ADD_RETRY_SECS = 3;

# Retry budget for a busy snapshot delete (err=493, see volume_snapshot_delete).
# 10 x 20s covers the ~3 minute window observed on appliances without the
# server-side fix. Package vars so tests can localize them.
our $SNAP_DELETE_ATTEMPTS   = 10;
our $SNAP_DELETE_RETRY_SECS = 20;

# Disk numbers alloc_image tries when an auto-picked name already exists
# (err=9, see alloc_image). Package var so tests can localize it.
our $ALLOC_NAME_ATTEMPTS = 5;

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

    # Default shared=1. QuantaStor exports each volume as an iSCSI LUN that
    # every node with ACL access sees identically — the storage is shared by
    # nature, not local. Without this, PVE's QemuMigrate.pm scanner classifies
    # the volume as a "local disk" and bails with "storage type 'quantastor'
    # not supported" because 'quantastor' isn't in its hardcoded migratable
    # types regex (dir|btrfs|zfspool|lvmthin|lvm). Users can still override
    # by passing -shared 0 explicitly if they have a reason to.
    $scfg->{shared} = 1 unless exists $scfg->{shared};

    # Must return undef (or a hashref of auto-generated props). PVE wraps the
    # return value into the API response and validates it as an object —
    # returning the scalar 1 from the assignment above trips a schema check
    # with "config: type check ('object') failed".
    return undef;
}

sub on_update_hook {
    my ($class, $storeid, $scfg, %sensitive) = @_;
    # Note: on PVE 9.2 with api>=13 this is called by the base
    # on_update_hook_full with $scfg = $update (the changes only, not the
    # full config). Do NOT default shared here — we'd override an explicit
    # `pvesm set <id> -shared 0` made earlier. The on_add_hook default + the
    # `shared` field in options() are enough; existing storage entries
    # without `shared 1` should backfill via a one-time `pvesm set <id>
    # -shared 1` per the README.
    _set_password($storeid, $sensitive{password}) if defined $sensitive{password};
    return undef;
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

Declares supported content types and marks C<password> as a sensitive
property so PVE stores it encrypted.

Supports C<images> (VM disks) and C<rootdir> (LXC container root filesystems).
Both live on the same QuantaStor iSCSI LUN as a raw block volume
(C<vm-E<lt>vmidE<gt>-disk-N>); for a container PVE lays an ext4 filesystem on
that block device and mounts it (the C<mkfs>/mount/C<resize2fs> live in
C<PVE::LXC>, not here). The default stays C<images>. This mirrors C<RBDPlugin>
(network block + rootdir). C<vztmpl> is intentionally unsupported: template
tarballs need a POSIX filesystem a raw LUN can't provide, so CT templates come
from C<local> (same as RBD).

=cut

sub plugindata {
    return {
        content              => [{ images => 1, rootdir => 1 }, { images => 1 }],  # [supported, default]
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
    # and must not be re-declared.  Note: sparse IS honored by this plugin
    # (see alloc_image), but unlike ZFSPoolPlugin it defaults to ON.
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
        multipath => {
            description => 'Log in on every portal QuantaStor advertises for a '
                . 'volume and use the DM-MPIO device (needs multipath-tools).',
            type        => 'boolean',
            default     => 0,
        },
        volume_prefix => {
            description => 'Prefix for this storage\'s QuantaStor volume names, so '
                . 'several Proxmox clusters can share one pool (e.g. clusterA-).',
            type        => 'string',
            # QuantaStor names: alphanumeric first, then [A-Za-z0-9_.-], 128 max
            # (32 leaves room for the volume and snapshot suffix). Refused, so no
            # storage on the pool can list or collide with another's volumes: a
            # prefix starting like a PVE volume name, or containing 'vm-<n>-' etc.
            # (a shorter prefix would list it), or ending in 'template-' (its
            # names would match another storage's template snapshots).
            pattern     => '(?!(?:base|basevol|vm|subvol)-\d)(?!.*(?:base|basevol|vm|subvol)-\d+-)'
                . '(?!.*template-$)[A-Za-z0-9][A-Za-z0-9_.\-]*',
            maxLength   => 32,
        },
        transport => {
            description => "Host attach transport: 'iscsi' (default) or 'fc' "
                         . "(Fibre Channel)",
            type        => 'string',
            enum        => ['iscsi', 'fc'],
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
        shared     => { optional => 1 },   # see on_add_hook for default behavior
        multipath  => { optional => 1 },
        # Changing it would orphan every existing volume.
        volume_prefix => { optional => 1, fixed => 1 },
        transport  => { optional => 1, fixed => 1 },
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

# Build an FCManager from the storage config hash.
sub _fc {
    my ($scfg, $storeid) = @_;
    return PVE::Storage::QuantaStor::FCManager->new(
        logger => _logger($storeid),
    );
}

sub _is_fc { my ($scfg) = @_; return ($scfg->{transport} // 'iscsi') eq 'fc' }

# The transport that attaches volumes to this host. Both managers implement
# the same volume-keyed contract (see ISCSIManager "TRANSPORT CONTRACT"); the
# iSCSI multipath option stays in _login/_logout/path/volume_resize.
sub _transport {
    my ($scfg, $storeid) = @_;
    return _is_fc($scfg) ? _fc($scfg, $storeid) : _iscsi($scfg, $storeid);
}

# SCSI WWID of a volume: QuantaStor exposes NAA 6 "62000000" + deviceDescriptor
# on every path, so the multipath device can be named without a session.
sub _wwid {
    my ($vol) = @_;
    my $d = $vol->{deviceDescriptor};
    my $what = $vol->{name} // $vol->{id} // '?';
    die "QuantaStor: volume '$what' has no deviceDescriptor — cannot derive "
      . "its multipath WWID\n" unless defined $d && $d =~ /^[0-9a-fA-F]{24}$/;
    return '3' . lc("62000000$d");
}

# Log in to a volume's target: every portal plus its dm map when multipath
# is on, else the single configured portal (caller waits for the device).
sub _login {
    my ($scfg, $t, $vol) = @_;
    # FC has no login: the LUN shows up on a SCSI rescan once the ACL is in.
    # Always multipathed: an HA pair's standby (ALUA) paths fail I/O, so the
    # single-path by-id link can land on a path that cannot be used.
    if (_is_fc($scfg)) {
        $t->attach($vol);
        my $wwid = $t->wwid($vol);
        die "QuantaStor: FC multipath map for '$vol->{name}' ($wwid) did not appear "
          . "after 30s — " . $t->missing_device_hint() . "\n"
            unless $t->add_map($wwid);
        return 1;
    }
    return $t->login($vol->{iqn}) unless $scfg->{multipath};

    $t->login_all($vol->{iqn});
    my $wwid = _wwid($vol);
    die "QuantaStor: multipath map for '$vol->{name}' ($wwid) did not appear "
      . "after 30s — check multipathd and /etc/multipath.conf\n"
        unless $t->add_map($wwid);
    return 1;
}

# Log out of a volume's target and wait for the sessions to go. The dm map is
# flushed first: a map left without paths queues I/O and can hang.
sub _logout {
    my ($scfg, $t, $vol) = @_;
    if (_is_fc($scfg)) {
        $t->detach($vol);
        return $t->wait_for_detached($vol);
    }
    if ($scfg->{multipath}) {
        $t->flush_map(_wwid($vol)) if defined $vol->{deviceDescriptor};
        $t->logout_all($vol->{iqn});
    } else {
        $t->logout($vol->{iqn});
    }
    return $t->wait_for_logout($vol->{iqn});
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

# The storage's volume_prefix ('' when unset); prepended to every QuantaStor name.
sub _prefix {
    my ($scfg) = @_;
    return $scfg->{volume_prefix} // '';
}

# QuantaStor volume name of a PVE volname (strips any base prefix, adds volume_prefix).
sub _qs_name {
    my ($class, $scfg, $volname) = @_;
    return _prefix($scfg) . ($class->parse_volname($volname))[1];
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
    # Lookup and enum errors propagate: an unreadable listing returned as empty
    # makes find_free_diskname hand out names that are already taken.
    my $pool_uuid = $client->pool_get(_raw_pool_id($scfg->{pool_id}))->{id};
    my $all_vols  = $client->volume_enum();

    my $res    = [];
    my $prefix = _prefix($scfg);

    for my $vol (@$all_vols) {
        # Only include volumes belonging to our pool.
        next unless defined $vol->{storagePoolId}
            && $vol->{storagePoolId} eq $pool_uuid;

        my $name = $vol->{name};

        # Skip snapshots — they appear as separate volumes in QuantaStor but
        # PVE manages them through the snapshot hooks, not list_images.
        next if $vol->{isSnapshot} && $vol->{isSnapshot} eq '1';

        # Another cluster's volumes on a shared pool carry a different prefix.
        next unless substr($name, 0, length $prefix) eq $prefix;
        $name = substr($name, length $prefix);

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
With C<$snapname>, it is the path of that snapshot's own LUN.

=cut

sub path {
    my ($class, $scfg, $volname, $storeid, $snapname) = @_;

    my ($vtype, undef, $vmid) = $class->parse_volname($volname);
    my $name = _qs_name($class, $scfg, $volname);
    $name = _snap_vol_name($name, $snapname) if defined $snapname;

    # PVE's delete API handler calls path() BEFORE vdisk_free to look up
    # vtype/ownervm for permission checks. If the volume is already gone we
    # must not die here, or free_image's idempotent fast-path is unreachable.
    # Returning undef path is safe: PVE only uses $path here for backup-vtype
    # auxiliary cleanup, and our vtype is always 'images'.
    my $vol = _client($scfg, $storeid)->volume_get_or_undef($name);
    return (undef, $vmid, $vtype) unless $vol;

    # A volume can exist without a target identity yet (e.g. export not yet
    # provisioned). Return undef path rather than letting the transport croak
    # with a cryptic error — same contract as a missing vol.
    my $t = _transport($scfg, $storeid);
    return (undef, $vmid, $vtype) unless $t->is_exported($vol);

    # FC resolves the LUN by its WWID (the dm map when multipathd has one).
    return ($t->volume_device_path($vol), $vmid, $vtype) if _is_fc($scfg);

    # Same contract for multipath: no descriptor means no derivable device.
    return (undef, $vmid, $vtype)
        if $scfg->{multipath} && !defined $vol->{deviceDescriptor};

    # QuantaStor presents each volume as a dedicated iSCSI target at LUN 0
    # on the wire. The 'lun' field in volume_get is an internal QuantaStor
    # concept (position within a host group) and does not match the actual
    # iSCSI LUN number seen by the initiator. With multipath, the dm device.
    my $path = $scfg->{multipath}
        ? $t->map_path(_wwid($vol))
        : $t->device_path($vol->{iqn}, 0);

    return ($path, $vmid, $vtype);
}

=head2 volume_size_info($scfg, $storeid, $volname, $timeout)

Returns the volume size in bytes (scalar context) or
C<($size, $format, $used, $parent)> in list context.

=cut

sub volume_size_info {
    my ($class, $scfg, $storeid, $volname, $timeout) = @_;

    my $name = _qs_name($class, $scfg, $volname);
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

Dies if this node's initiator name is already registered under another
node's C<-pve> host name; the message gives the C<qs> command that fixes it.

=cut

sub activate_storage {
    my ($class, $storeid, $scfg, $cache) = @_;

    my $client = _client($scfg, $storeid);
    my $t      = _transport($scfg, $storeid);

    # Verify connectivity — will die on network/auth failure.
    $client->pool_get(_raw_pool_id($scfg->{pool_id}));

    die "QuantaStor storage '$storeid': multipath (or FC) is enabled but multipath-tools "
      . "is not installed on this node (apt install multipath-tools)\n"
        if ($scfg->{multipath} || _is_fc($scfg)) && !grep { -x "$_/multipathd" } qw(/usr/sbin /sbin);

    # Register this node as a QuantaStor host if it isn't already. An FC host
    # contributes every HBA port WWPN so a single ACL covers all paths.
    my ($iqn, @extra) = $t->initiator_ids();
    my $what     = _is_fc($scfg) ? 'FC port name (WWPN)' : 'iSCSI initiator name';
    my $hostname = hostname() . '-pve';
    my $host     = $client->host_get($iqn);

    # Another node's plugin registered this IQN: sharing one host entry breaks
    # both nodes' sessions. Admin-named hosts (no '-pve' suffix) are left alone.
    if ($host && ($host->{name} // '') =~ /-pve$/ && $host->{name} ne $hostname) {
        my $msg = "QuantaStor storage '$storeid': this node's $what $iqn is "
          . "already registered on QuantaStor as host '$host->{name}', not '$hostname'. "
          . "Nodes that share an initiator name disrupt each other's storage access; see "
          . "'Storage only works on one cluster at a time' in the troubleshooting guide. ";
        # Several initiators: a node with the same hostname shares it; renaming would take it from that node.
        $msg .= @{ $host->{initiatorPortList} // [] } > 1
          ? "That host also has other initiators, so another node with this node's old "
            . "hostname uses it. Remove this node's initiator name from it: "
            . "qs host-initiator-remove --host=$host->{name} --iqn=$iqn\n"
          : "If this node was renamed, rename the host on QuantaStor: "
            . "qs host-modify --host=$host->{name} --hostname=$hostname\n";
        die $msg;
    }

    $client->ensure_host_registered($hostname, $iqn,
        description      => 'Registered by Proxmox VE QuantaStor plugin',
        extra_initiators => \@extra)
        unless $host && !@extra;

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

# This node's identity for QuantaStor ACL calls. They resolve a host by IQN,
# name or ID but not by WWPN, so FC passes the ID of the host holding the WWPN.
sub _acl_initiator {
    my ($client, $scfg, $t) = @_;
    my $id = $t->initiator_id();
    return $id unless _is_fc($scfg);
    my $host = $client->host_get($id);
    die "QuantaStor: this node's FC port $id is not registered on QuantaStor "
      . "(activate the storage first)\n" unless $host;
    return $host->{id};
}

# Grant $iqn access to a volume.
#
# QuantaStor can return a freshly cloned volume before SCST has created its
# iSCSI target (clone is served by an async ZFS "instant replica"), and the
# ACL add then fails with a transient 5xx — observed as
# "HTTP 500 interrupted by signal" — killing an otherwise-healthy clone.
# Retrying is safe because an ACL add for a host that already has access is
# a no-op. Anything that is not a 5xx (auth, not-found) is a real error and
# must still fail immediately rather than stalling for the whole budget.
sub _acl_add {
    my ($client, $storeid, $vol_id, $iqn, $what) = @_;
    my $acl_err;
    for my $attempt (1 .. $ACL_ADD_ATTEMPTS) {
        eval { $client->volume_acl_add($vol_id, $iqn) };
        return 1 unless $@;
        $acl_err = $@;
        die $acl_err unless $acl_err =~ /HTTP 5\d\d/;
        _logger($storeid)->(warning =>
            "$what failed (attempt $attempt/$ACL_ADD_ATTEMPTS), retrying: $acl_err");
        sleep $ACL_ADD_RETRY_SECS if $attempt < $ACL_ADD_ATTEMPTS;
    }
    die $acl_err;
}

=head2 activate_volume($storeid, $scfg, $volname, $snapname, $cache)

Grants this node access to the volume via ACL and logs in to the iSCSI target.
With C<$snapname>, activates that snapshot's volume instead (vzdump snapshot
mode mounts a container's snapshot read-only to back it up).

=cut

sub activate_volume {
    my ($class, $storeid, $scfg, $volname, $snapname, $cache) = @_;

    # A QuantaStor snapshot is a volume with its own iSCSI target.
    my $name   = _qs_name($class, $scfg, $volname);
    $name      = _snap_vol_name($name, $snapname) if defined $snapname;
    my $client = _client($scfg, $storeid);
    my $t      = _transport($scfg, $storeid);

    my $vol = $client->volume_get($name);

    die "QuantaStor activate_volume: volume '$name' has no "
      . (_is_fc($scfg) ? 'SCSI device identifier' : 'iSCSI target (iqn)')
      . " — the LUN may not be exported yet on the appliance\n"
        unless $t->is_exported($vol);

    my $iqn = _acl_initiator($client, $scfg, $t);

    # Grant access then login — order matters.
    _acl_add($client, $storeid, $vol->{id}, $iqn, "activate_volume: ACL add for '$name'");

    # With multipath, _login already waited for the dm map.
    _login($scfg, $t, $vol);
    return 1 if $scfg->{multipath} && !_is_fc($scfg);

    # Wait for the device link before returning. PVE expects activate_volume
    # to leave the device usable; if we return before udev creates the symlink,
    # QEMU fails to open the disk with a confusing low-level error.
    unless ($t->wait_for_attached($vol)) {
        my $dev   = $t->volume_device_path($vol);
        my $label = _is_fc($scfg) ? 'FC' : 'iSCSI';
        die "QuantaStor activate_volume: $label device '$dev' did not appear "
          . "after 30s — " . $t->missing_device_hint() . "\n";
    }

    return 1;
}

=head2 deactivate_volume($storeid, $scfg, $volname, $snapname, $cache)

Logs out of the iSCSI target and revokes ACL access for this node.

=cut

sub deactivate_volume {
    my ($class, $storeid, $scfg, $volname, $snapname, $cache) = @_;

    my $name   = _qs_name($class, $scfg, $volname);
    $name      = _snap_vol_name($name, $snapname) if defined $snapname;
    my $client = _client($scfg, $storeid);
    my $t      = _transport($scfg, $storeid);

    # Use get_or_undef: a concurrent free_image on another cluster node may have
    # already deleted the volume by the time deactivate runs on this node.
    my $vol = $client->volume_get_or_undef($name);
    return 1 unless $vol;

    my $iqn  = $t->initiator_id();
    my $host = $client->host_get($iqn);

    # Logout first, then remove ACL — reverse of activate_volume.
    _logout($scfg, $t, $vol);

    $client->volume_acl_remove($vol->{id}, $host->{id}) if $host;

    return 1;
}

# ---------------------------------------------------------------------------
# Volume allocation / deallocation
# ---------------------------------------------------------------------------

=head2 alloc_image($storeid, $scfg, $vmid, $fmt, $name, $size)

Creates a new volume in QuantaStor.  C<$size> is in kilobytes (PVE convention).
Returns the volname (not the full volid).

Volumes are thin provisioned unless C<sparse 0> is set in the storage
configuration (the C<sparse> option defaults to on for this plugin).

=cut

sub alloc_image {
    my ($class, $storeid, $scfg, $vmid, $fmt, $name, $size) = @_;

    die "unsupported format '$fmt' — quantastor storage only supports 'raw'\n"
        if $fmt ne 'raw';

    die "illegal name '$name' — should be 'vm-$vmid-*'\n"
        if $name && $name !~ m/^vm-$vmid-/;

    my $auto = !defined $name;
    $name //= $class->find_free_diskname($storeid, $scfg, $vmid, $fmt);

    my $client   = _client($scfg, $storeid);
    my $pool_raw = _raw_pool_id($scfg->{pool_id});

    # A volume created moments ago can be missing from the enum that
    # find_free_diskname reads, so an auto-picked name may already exist.
    # QuantaStor refuses it with err=9; move on to the next disk number.
    for my $attempt (1 .. $ALLOC_NAME_ATTEMPTS) {
        # Default to thin; 'sparse 0' in storage.cfg opts into thick (100% reserved).
        eval { $client->volume_create(_prefix($scfg) . $name, $size, $pool_raw,
            thin => $scfg->{sparse} // 1) };
        return $name unless $@;
        die $@ unless $auto && $@ =~ /err=9\b/ && $attempt < $ALLOC_NAME_ATTEMPTS;
        _logger($storeid)->(warning =>
            "alloc_image: '$name' already exists on QuantaStor, trying the next disk number");
        $name =~ s/(\d+)$/$1 + 1/e;
    }
}

=head2 free_image($storeid, $scfg, $volname, $isBase)

Deactivates and permanently deletes a volume (and all its snapshots).

=cut

sub free_image {
    my ($class, $storeid, $scfg, $volname, $isBase) = @_;

    my $name   = _qs_name($class, $scfg, $volname);
    my $client = _client($scfg, $storeid);
    my $t      = _transport($scfg, $storeid);

    # Idempotent: if the volume is already gone on QuantaStor, treat as success.
    # PVE retries deletes on some failure paths; raising "not found" would
    # create a stuck state.
    my $vol = $client->volume_get_or_undef($name);
    return undef unless $vol;

    # Best-effort detach. A volume that's already offline, whose host has been
    # removed, or whose iSCSI session is stale should still be deletable —
    # don't let teardown errors mask the real goal.
    eval {
        my $iqn  = $t->initiator_id();
        my $host = $client->host_get($iqn);

        _logout($scfg, $t, $vol);
        $client->volume_acl_remove($vol->{id}, $host->{id}) if $host;
    };
    warn "free_image teardown warning for '$volname': $@" if $@;

    # Force-delete + cascade so snapshots of this volume go too. PVE expects
    # free_image to leave nothing behind for this volname.
    eval { $client->volume_delete($vol->{id}, delete_options => 4, flags => 2) };
    if (my $err = $@) {
        # QuantaStor can refuse zvol deletes (err=493 DELETE_ZVOL_FAILED) for a
        # window after target teardown — brief on current builds, minutes-long
        # for fresh snapshot/clone zvols on older ones (observed on 7.0.0.156).
        # The failed cascade may also have PARTIALLY completed (snapshots gone,
        # parent refused), so the per-snapshot cleanup must tolerate objects
        # that no longer exist before retrying the parent.
        my $snaps = $vol->{snapshotIdList};
        die $err unless ref $snaps eq 'ARRAY' && @$snaps;
        warn "free_image: cascade delete of '$volname' failed, retrying with "
           . scalar(@$snaps) . " individual snapshot delete(s): $err";
        for my $snap_id (@$snaps) {
            eval { $client->volume_delete($snap_id, flags => 2) };
            die $@ if $@ && $@ !~ /could not be found/i;
        }
        my $deleted = 0;
        for my $attempt (1 .. 3) {
            eval { $client->volume_delete($vol->{id}, delete_options => 4, flags => 2) };
            if (!$@) { $deleted = 1; last }
            sleep 10 if $attempt < 3;   # ride out the post-teardown busy window
        }
        die $@ unless $deleted;
    }
    return undef;
}

=head2 volume_resize($scfg, $storeid, $volname, $size, $running, $snapname)

Grows a volume to C<$size> bytes.  Shrinking is not supported by QuantaStor.
Dies if C<$snapname> is set: resizing a snapshot is not supported.

=cut

sub volume_resize {
    my ($class, $scfg, $storeid, $volname, $size, $running, $snapname) = @_;

    # Storage API 15: only snapshot-as-volume-chain storages resize a snapshot.
    die "resizing a snapshot is not supported on QuantaStor storage\n" if defined $snapname;

    my $name   = _qs_name($class, $scfg, $volname);
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
    my $t = _transport($scfg, $storeid);
    if (_is_fc($scfg)) {
        warn "volume_resize: rescan failed for '$name' — kernel LUN geometry may be stale\n"
            unless $t->rescan_volume($vol);
        return $size;
    }
    if ($scfg->{multipath}) {
        # Every path must see the new size before the map can grow.
        $t->resize_map(_wwid($vol)) if $t->rescan_all($vol->{iqn});
        return $size;
    }
    unless ($t->rescan($vol->{iqn})) {
        warn "volume_resize: rescan failed for '$name' — "
           . "kernel LUN geometry may be stale; QEMU block_resize may fail\n";
    }

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

    my $name      = _qs_name($class, $scfg, $volname);
    my $snap_name = _snap_vol_name($name, $snap);

    _client($scfg, $storeid)->volume_snapshot($name, $snap_name);

    return undef;
}

=head2 volume_snapshot_delete($scfg, $storeid, $volname, $snap, $running)

Deletes the QuantaStor snapshot volume for C<$snap>.

=cut

sub volume_snapshot_delete {
    my ($class, $scfg, $storeid, $volname, $snap, $running) = @_;

    my $name      = _qs_name($class, $scfg, $volname);
    my $snap_name = _snap_vol_name($name, $snap);

    my $client = _client($scfg, $storeid);
    # Idempotent: if the snapshot is already gone, treat as success.
    my $snap_vol = $client->volume_get_or_undef($snap_name);
    return undef unless $snap_vol;

    # vzdump never deactivates the snapshot it mounted; drop our session first.
    $class->deactivate_volume($storeid, $scfg, $volname, $snap)
        if _transport($scfg, $storeid)->is_exported($snap_vol)
        && _transport($scfg, $storeid)->is_attached($snap_vol);

    # Force-delete: PVE expects volume_snapshot_delete to remove the snapshot
    # even if QuantaStor considers it busy.
    #
    # Appliances without the server-side fix refuse to destroy a freshly
    # created snapshot zvol (err=493 DELETE_ZVOL_FAILED, "Dataset is busy") for
    # a few minutes after creation. A single failure here leaves the guest in a
    # snapshot-delete lock, so ride out that window; the same delete succeeds
    # once it closes. Any other fault is real and must still fail immediately.
    my $deleted = 0;
    my $del_err;
    for my $attempt (1 .. $SNAP_DELETE_ATTEMPTS) {
        eval { $client->volume_delete($snap_vol->{id}, flags => 2) };
        if (!$@) { $deleted = 1; last }
        $del_err = $@;
        # The appliance's own deferred retry may have finished the job meanwhile.
        if ($del_err =~ /could not be found|err=5\b/i) { $deleted = 1; last }
        die $del_err unless $del_err =~ /err=493\b/;
        _logger($storeid)->(warning =>
            "volume_snapshot_delete: snapshot '$snap_name' busy on QuantaStor "
          . "(attempt $attempt/$SNAP_DELETE_ATTEMPTS), retrying: $del_err");
        sleep $SNAP_DELETE_RETRY_SECS if $attempt < $SNAP_DELETE_ATTEMPTS;
    }
    die $del_err unless $deleted;

    return undef;
}

=head2 volume_rollback_is_possible($scfg, $storeid, $volname, $snap, $blockers)

Asserts that C<$snap> is the most recent snapshot of C<$volname>.
Dies if the rollback is blocked; pushes blocker names onto C<$blockers> if provided.

=cut

sub volume_rollback_is_possible {
    my ($class, $scfg, $storeid, $volname, $snap, $blockers) = @_;

    my $name       = _qs_name($class, $scfg, $volname);
    my $snap_name  = _snap_vol_name($name, $snap);
    my $client     = _client($scfg, $storeid);

    my $target = $client->volume_get($snap_name);
    die "can't rollback — snapshot '$snap' does not exist on '$volname'\n"
        unless defined $target->{id};

    my $target_ts = $target->{createdTimeStamp}
        or die "can't rollback — snapshot '$snap' has no timestamp\n";

    # Enumerate all volumes and find any snapshots of the same parent that
    # are newer than our target snapshot. Wrap in eval — a transient API error
    # here must not propagate as an uncaught exception to the PVE UI caller.
    my $all = eval { $client->volume_enum() } // [];
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

Rolls C<$volname> back to C<$snap>: logout → grant this node access → rollback
→ remove that access (no login; PVE activates the volume on the next start).

=cut

sub volume_snapshot_rollback {
    my ($class, $scfg, $storeid, $volname, $snap) = @_;

    my $name      = _qs_name($class, $scfg, $volname);
    my $snap_name = _snap_vol_name($name, $snap);
    my $client    = _client($scfg, $storeid);
    my $t         = _transport($scfg, $storeid);

    my $vol = $client->volume_get($name);

    # PVE guarantees QEMU is stopped before calling this hook, but the iSCSI
    # session may still be lingering (kernel session outlives the QEMU process).
    # Log out so QuantaStor will accept the rollback on an otherwise-idle target.
    # Do NOT re-login here — PVE calls activate_volume when the VM next starts.
    _logout($scfg, $t, $vol) if $t->is_attached($vol);

    # PVE-side logout returns before QuantaStor's server-side session tracker
    # GCs the connection. Volume rollback rejects on an active QS session, so
    # poll QS until it agrees the target is idle. If it never clears (e.g.
    # another cluster node still holds a session on this shared volume), fail
    # with an actionable message instead of letting QS reject with [err=76].
    unless ($client->wait_for_session_gone($name)) {
        die "QuantaStor rollback: volume '$name' still has an active session "
          . "after waiting — another node may have it open. Ensure the VM is "
          . "stopped on all nodes and retry.\n";
    }

    # QuantaStor rebuilds the target (and so its LUN size) on rollback only
    # while a host is assigned; PVE's deactivate on stop removed ours. Without
    # it, a rollback past a resize leaves the LUN at the larger size. Assign
    # this node for the rollback only (no login); activate_volume re-adds it.
    my $iqn = _acl_initiator($client, $scfg, $t);
    _acl_add($client, $storeid, $vol->{id}, $iqn,
        "volume_snapshot_rollback: ACL add for '$name'");
    eval { $client->volume_rollback($vol->{id}, $snap_name) };
    my $err = $@;

    eval {
        my $host = $client->host_get($iqn);
        $client->volume_acl_remove($vol->{id}, $host->{id}) if $host;
    };
    warn "volume_snapshot_rollback: could not remove the ACL added for '$name': $@" if $@;
    die $err if $err;

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

    my ($vtype, $pve_name, $vmid, $basename, $basevmid, $isBase) =
        $class->parse_volname($volname);

    die "create_base not possible with an existing base image\n" if $isBase;

    (my $pve_newname = $pve_name) =~ s/^vm-/base-/;

    # QuantaStor names; the volname returned to PVE stays unprefixed.
    my $name    = _prefix($scfg) . $pve_name;
    my $newname = _prefix($scfg) . $pve_newname;

    my $client = _client($scfg, $storeid);
    my $t      = _transport($scfg, $storeid);
    my $iqn    = _acl_initiator($client, $scfg, $t);

    my $vol  = $client->volume_get($name);
    my $host = $client->host_get($iqn);

    # Take offline.
    _logout($scfg, $t, $vol);
    $client->volume_acl_remove($vol->{id}, $host->{id}) if $host;

    # Wait for QuantaStor to GC its server-side view of the session before
    # mutating the volume — rename rejects on an active session. If it never
    # clears (another node may still hold the volume), fail with an actionable
    # message rather than proceeding into a rename that QS rejects with [err=76]
    # and leaving the volume half-converted. Use the client default (200s): it
    # already exceeds QS's 180s session-manager cycle, which the previous
    # explicit 120s here did not — template conversion failed whenever the
    # cycle had not ticked. Template conversion is rare and interactive-retry
    # is worse than waiting.
    unless ($client->wait_for_session_gone($name)) {
        die "QuantaStor create_base: volume '$name' still has an active session "
          . "after waiting — another node may have it open. Ensure the VM is "
          . "stopped on all nodes and retry.\n";
    }

    # Rename to base- convention. Re-fetch after rename to get the canonical IQN
    # rather than relying on volume_modify's return shape, which varies across
    # QS versions (bare object vs task-wrapper vs iqn absent).
    $client->volume_modify($vol->{id}, $newname);
    my $new_vol = $client->volume_get($newname);

    # Re-grant access and bring online.
    $client->volume_acl_add($vol->{id}, $iqn);
    _login($scfg, $t, $new_vol);

    # Create the template snapshot that clone_image will clone from.
    my $template_snap = _prefix($scfg) . "template-$pve_newname";
    $client->volume_snapshot($newname, $template_snap,
        description => 'Template snapshot created by Proxmox VE');

    my $newvolname = $basename ? "$basename/$pve_newname" : $pve_newname;
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
    my $t           = _transport($scfg, $storeid);
    my $iqn         = _acl_initiator($client, $scfg, $t);
    my $template_snap = _prefix($scfg) . "template-$name";
    my $newname     = $class->find_free_diskname($storeid, $scfg, $vmid, 'raw');

    # Same race as alloc_image: the auto-picked name may already exist (err=9).
    my $result;
    for my $attempt (1 .. $ALLOC_NAME_ATTEMPTS) {
        $result = eval { $client->volume_clone($template_snap, _prefix($scfg) . $newname,
            description => "Cloned from $name by Proxmox VE (vmid $vmid)") };
        last unless $@;
        die $@ unless $@ =~ /err=9\b/ && $attempt < $ALLOC_NAME_ATTEMPTS;
        _logger($storeid)->(warning =>
            "clone_image: '$newname' already exists on QuantaStor, trying the next disk number");
        $newname =~ s/(\d+)$/$1 + 1/e;
    }

    # The clone API returns { obj => { id => ..., iqn => ... } } on success.
    my $new_vol = (ref $result eq 'HASH' && $result->{obj}) ? $result->{obj} : $result;

    # Grant access and login to the new clone. Multipath and FC need the
    # clone's deviceDescriptor, which the clone response may not carry.
    $client->volume_acl_add($new_vol->{id}, $iqn);
    $new_vol = $client->volume_get(_prefix($scfg) . $newname) if $scfg->{multipath} || _is_fc($scfg);
    _login($scfg, $t, $new_vol);

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

    # Keyed on volume role (current/snap/base) derived from the name, not on
    # content type: container rootfs volumes are the same raw vm-/base- shape
    # as VM disks, so they inherit the same snapshot/clone/template/copy support.
    my $features = {
        snapshot  => { current => 1, snap => 1 },
        clone     => { base    => 1 },
        template  => { current => 1 },
        copy      => { base    => 1, current => 1, snap => 1 },
        sparseinit => { base   => 1, current => 1 },
    };

    my ($vtype, $name, $vmid, $basename, $basevmid, $isBase) =
        $class->parse_volname($volname);

    my $key = $snapname ? 'snap' : ($isBase ? 'base' : 'current');

    return 1 if $features->{$feature}{$key};
    return undef;
}

=head2 get_identity($scfg, $storeid)

Returns the QuantaStor storage pool UUID, so every storage entry on the same
pool (from any Proxmox cluster) reports the same identity. It survives HA
pool failover. Dies if the appliance cannot be reached.

=cut

sub get_identity {
    my ($class, $scfg, $storeid) = @_;
    return _client($scfg, $storeid)->pool_get(_raw_pool_id($scfg->{pool_id}))->{id};
}

=head2 storage_can_replicate

Returns 0 — replication is not supported in this release.

=cut

sub storage_can_replicate {
    my ($class, $scfg, $storeid, $format) = @_;
    return 0;
}

=head2 volume_snapshot_needs_fsfreeze

Returns 1 so PVE freezes a container's root filesystem before snapshotting.

An LXC container's rootfs is a live ext4 mounted on the iSCSI LUN, so a
QuantaStor volume snapshot taken while it is mounted would otherwise capture a
crash-consistent (dirty) filesystem. Freezing first makes the snapshot
filesystem-consistent. Same rationale as C<RBDPlugin::volume_snapshot_needs_fsfreeze>.
(The base plugin returns 0, which is correct only for raw VM disks that the
guest OS quiesces itself.)

=cut

sub volume_snapshot_needs_fsfreeze {
    return 1;
}

1;
