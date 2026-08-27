#!/usr/bin/perl
use strict;
use warnings;

use FindBin qw($Bin);
use lib "$Bin/../src/perl5";
use lib "$Bin/lib";

use Test::More;
use File::Temp qw(tempfile);
use Test::QuantaStor::MockUA;
use Test::QuantaStor::MockCmdRunner;

# ---------------------------------------------------------------------------
# PVE::Storage::Plugin is not available outside a PVE host.
# Provide a minimal stub so QuantaStorPlugin can load and 'use base' works.
# ---------------------------------------------------------------------------
{
    package PVE::Storage::Plugin;
    sub new  { my ($class, %a) = @_; return bless \%a, $class }
    sub find_free_diskname {
        my ($class, $storeid, $scfg, $vmid, $fmt) = @_;
        return "vm-${vmid}-disk-0";
    }
    sub parse_volname { die "base parse_volname should not be called in these tests" }
    1;
}

require PVE::Storage::Custom::QuantaStor;

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

my $POOL_UUID   = 'aaaa-1111-bbbb-2222';
my $POOL_ID     = "qs-$POOL_UUID";
my $API_HOST    = '10.0.0.1';
my $PORTAL      = '10.0.0.1';
my $LOCAL_IQN   = 'iqn.1993-08.org.debian:01:testnode';
my $VOL_IQN     = 'iqn.2009-10.com.osnexus:aaaa1111:vm-100-disk-0';
my $VOL_UUID    = 'vol-uuid-0001';
my $HOST_UUID   = 'host-uuid-0001';

# Minimal storage config hash (mirrors /etc/pve/storage.cfg fields).
sub make_scfg {
    return {
        api_host   => $API_HOST,
        username   => 'admin',
        password   => 'secret',
        pool_id    => $POOL_ID,
        portal     => $PORTAL,
        ssl_verify => 0,
    };
}

# Build a pre-wired APIClient+ISCSIManager pair and inject them into the
# plugin via monkey-patching _client / _iscsi for the duration of a subtest.
sub with_mocks {
    my ($ua_responses, $cmd_responses, $test_sub) = @_;

    my $ua     = Test::QuantaStor::MockUA->new(responses => $ua_responses);
    my $runner = Test::QuantaStor::MockCmdRunner->new(responses => $cmd_responses // {});

    # Override the internal factory helpers for the duration of this call.
    no warnings 'redefine';
    local *PVE::Storage::Custom::QuantaStor::_client = sub {
        return PVE::Storage::QuantaStor::APIClient->new(
            host => $API_HOST, username => 'admin', password => 'x',
            _ua => $ua,
            # Stub sleep so wait_for_session_gone polls don't pay real cost.
            _sleep => sub { },
        );
    };
    local *PVE::Storage::Custom::QuantaStor::_iscsi = sub {
        return PVE::Storage::QuantaStor::ISCSIManager->new(
            portal          => $PORTAL,
            _run_cmd        => $runner->as_coderef,
            _initiator_file => _temp_initiator_file(),
            # Pretend the by-path symlink is always present so activate_volume's
            # wait_for_device call doesn't pay real-sleep cost. Individual tests
            # override this when they want to exercise the missing-device path.
            _path_exists    => sub { 1 },
        );
    };

    $test_sub->($ua, $runner);
}

# Write a temp initiatorname.iscsi and return its path.
my $_initiator_path;
sub _temp_initiator_file {
    unless ($_initiator_path) {
        my ($fh, $path) = tempfile(UNLINK => 1);
        print $fh "InitiatorName=$LOCAL_IQN\n";
        close $fh;
        $_initiator_path = $path;
    }
    return $_initiator_path;
}

my $CLASS = 'PVE::Storage::Custom::QuantaStor';

# ---------------------------------------------------------------------------
# 1. Plugin registration
# ---------------------------------------------------------------------------

subtest 'type returns quantastor' => sub {
    is $CLASS->type(), 'quantastor', 'type is quantastor';
};

subtest 'plugindata declares images and rootdir content' => sub {
    my $pd = $CLASS->plugindata();
    ok $pd->{content}[0]{images},  'images content type supported (VM disks)';
    ok $pd->{content}[0]{rootdir}, 'rootdir content type supported (LXC containers)';
    ok $pd->{content}[1]{images},  'images is the default content type';
    ok !$pd->{content}[1]{rootdir}, 'rootdir is not a default content type';
    ok $pd->{'sensitive-properties'}{password}, 'password marked sensitive';
};

subtest 'properties defines required fields' => sub {
    my $props = $CLASS->properties();
    for my $field (qw(api_host pool_id)) {
        ok exists $props->{$field}, "property '$field' defined";
    }
};

subtest 'options marks api_host and pool_id as fixed' => sub {
    my $opts = $CLASS->options();
    ok $opts->{api_host}{fixed}, 'api_host is fixed';
    ok $opts->{pool_id}{fixed},  'pool_id is fixed';
    ok $opts->{nodes}{optional}, 'nodes is optional';
};

subtest 'options accepts shared field (required for live/offline migration)' => sub {
    # QemuMigrate.pm classifies every non-shared volume as "local" and then
    # rejects unrecognized storage types with "storage type 'quantastor' not
    # supported". The plugin must accept `shared` so storage.cfg can carry
    # shared=1, which is what makes PVE's migration scanner skip our volumes.
    my $opts = $CLASS->options();
    ok exists $opts->{shared}, 'shared field declared in options';
    ok $opts->{shared}{optional}, 'shared is optional';
};

subtest 'on_add_hook defaults shared=1 (enables migration)' => sub {
    # On a fresh storage create, $scfg comes in without `shared`. We default
    # it to 1 so the user doesn't have to know about the migration scanner
    # requirement. Pmxcfs writes this back to storage.cfg via PVE's write
    # path (on_add_hook is called with $scfg by reference).
    my $scfg = {
        api_host => '10.0.0.1', username => 'admin', pool_id => 'p',
    };
    $CLASS->on_add_hook('qs-test', $scfg);   # no password kwarg — skips _set_password
    is $scfg->{shared}, 1, 'shared defaulted to 1';
};

subtest 'on_add_hook respects explicit shared=0' => sub {
    # If user passes -shared 0 they get exactly what they asked for, even
    # though migration won't work. Trust the user; never silently override.
    my $scfg = {
        api_host => '10.0.0.1', username => 'admin', pool_id => 'p',
        shared => 0,
    };
    $CLASS->on_add_hook('qs-test', $scfg);   # no password kwarg — skips _set_password
    is $scfg->{shared}, 0, 'explicit shared=0 preserved';
};

subtest 'on_update_hook does NOT touch shared (only the changes are passed in)' => sub {
    # On PVE 9.2 with api>=13, the base on_update_hook_full passes $update
    # (the changes only, not the full config) as the second arg to
    # on_update_hook. Overriding shared here would clobber an explicit
    # `pvesm set <id> -shared 0` the user made earlier. Legacy entries
    # without shared need a one-time `pvesm set <id> -shared 1`.
    my $update = {
        content => 'images,backup',   # an unrelated update
    };
    $CLASS->on_update_hook('qs-test', $update);
    ok !exists $update->{shared}, 'on_update_hook leaves shared alone';
};

subtest 'hooks return undef (PVE validates response.config as object)' => sub {
    # PVE's API endpoint runs:
    #   $res->{config} = $returned_config if $returned_config;
    # and validates $res->{config} as an object. A truthy scalar return
    # trips "config: type check ('object') failed". Both hooks must return
    # undef unless they have actual auto-generated props (we don't).
    my $rv1 = $CLASS->on_add_hook('qs-test',
        { api_host => '10.0.0.1', username => 'admin', pool_id => 'p' });
    is $rv1, undef, 'on_add_hook returns undef';

    my $rv2 = $CLASS->on_update_hook('qs-test', { content => 'images' });
    is $rv2, undef, 'on_update_hook returns undef';
};

subtest '_client dies with actionable error when password is missing on local node' => sub {
    # In a PVE cluster, /etc/pve/priv/storage/ is pmxcfs-replicated but a node
    # can end up without the file (sync hiccup, manual cleanup, storage added
    # before the node joined). Without this check, every API call returns a
    # misleading QuantaStor err=26 "authentication check failed" — a common
    # support pitfall. The plugin must surface the actual cause.

    no warnings 'redefine';
    local *PVE::Storage::Custom::QuantaStor::_get_password = sub { undef };

    eval {
        PVE::Storage::Custom::QuantaStor::_client(
            {
                api_host => '10.0.0.1',
                username => 'admin',
                pool_id  => 'tank',
            },
            'qs-missing-pw',
        );
    };
    my $err = $@;

    like $err, qr/no password configured for storage 'qs-missing-pw'/,
        'mentions storage id';
    like $err, qr/on node '[^']+'/,
        'mentions the local hostname';
    like $err, qr|/etc/pve/priv/storage/qs-missing-pw\.pw|,
        'mentions the expected file path';
    like $err, qr/pvesm set qs-missing-pw -password/,
        'mentions the remediation command';
};

# ---------------------------------------------------------------------------
# 2. parse_volname
# ---------------------------------------------------------------------------

subtest 'parse_volname handles vm disk' => sub {
    my @r = $CLASS->parse_volname('vm-100-disk-0');
    is $r[0], 'images',       'vtype = images';
    is $r[1], 'vm-100-disk-0','name';
    is $r[2], '100',           'vmid';
    ok !$r[5],                 'not a base image';
    is $r[6], 'raw',           'format = raw';
};

subtest 'parse_volname handles base disk' => sub {
    my @r = $CLASS->parse_volname('base-100-disk-0');
    is $r[1], 'base-100-disk-0', 'name';
    ok $r[5],                    'isBase = true';
};

subtest 'parse_volname handles base/vm clone path' => sub {
    my @r = $CLASS->parse_volname('base-100-disk-0/vm-101-disk-0');
    is $r[1], 'vm-101-disk-0',   'child name';
    is $r[3], 'base-100-disk-0', 'basename';
    is $r[4], '100',             'basevmid';
};

subtest 'parse_volname dies on invalid name' => sub {
    eval { $CLASS->parse_volname('not-a-valid-name') };
    like $@, qr/unable to parse/, 'dies on invalid volname';
};

# ---------------------------------------------------------------------------
# 3. status
# ---------------------------------------------------------------------------

subtest 'status returns pool size data' => sub {
    with_mocks(
        { storagePoolGet => { id => $POOL_UUID, size => 2048, freeSpace => 1024 } },
        {},
        sub {
            my ($ua) = @_;
            my ($total, $free, $used, $active) = $CLASS->status('qs1', make_scfg(), {});
            is $total,  2048, 'total';
            is $free,   1024, 'free';
            is $used,   1024, 'used';
            is $active, 1,    'active';
        }
    );
};

subtest 'status returns zeros and inactive on API error' => sub {
    with_mocks(
        { storagePoolGet => { _http_error => '500 Server Error' } },
        {},
        sub {
            my ($total, $free, $used, $active) = $CLASS->status('qs1', make_scfg(), {});
            is $active, 0, 'inactive on error';
            is $total,  0, 'total is 0 on error';
        }
    );
};

# ---------------------------------------------------------------------------
# 4. list_images
# ---------------------------------------------------------------------------

subtest 'list_images returns volumes for the configured pool' => sub {
    with_mocks(
        {
            storageVolumeEnum => [
                { id => 'v1', name => 'vm-100-disk-0', size => 10240,
                  storagePoolId => $POOL_UUID, isSnapshot => '0' },
                { id => 'v2', name => 'vm-101-disk-0', size => 20480,
                  storagePoolId => $POOL_UUID, isSnapshot => '0' },
                { id => 'v3', name => 'vm-200-disk-0', size => 5120,
                  storagePoolId => 'other-pool',  isSnapshot => '0' },
            ],
        },
        {},
        sub {
            my $res = $CLASS->list_images('qs1', make_scfg(), undef, undef, {});
            is scalar @$res, 2, 'only 2 volumes from our pool';
            my @names = sort map { $_->{volid} } @$res;
            is $names[0], 'qs1:vm-100-disk-0', 'first volid';
            is $names[1], 'qs1:vm-101-disk-0', 'second volid';
        }
    );
};

subtest 'list_images filters by vmid' => sub {
    with_mocks(
        {
            storageVolumeEnum => [
                { id => 'v1', name => 'vm-100-disk-0', size => 10240,
                  storagePoolId => $POOL_UUID, isSnapshot => '0' },
                { id => 'v2', name => 'vm-101-disk-0', size => 20480,
                  storagePoolId => $POOL_UUID, isSnapshot => '0' },
            ],
        },
        {},
        sub {
            my $res = $CLASS->list_images('qs1', make_scfg(), 100, undef, {});
            is scalar @$res, 1,                'filtered to 1 volume';
            is $res->[0]{vmid}, 100,            'vmid matches';
        }
    );
};

subtest 'list_images excludes snapshots' => sub {
    with_mocks(
        {
            storageVolumeEnum => [
                { id => 'v1', name => 'vm-100-disk-0', size => 10240,
                  storagePoolId => $POOL_UUID, isSnapshot => '0' },
                { id => 's1', name => 'vm-100-disk-0_snap1', size => 10240,
                  storagePoolId => $POOL_UUID, isSnapshot => '1' },
            ],
        },
        {},
        sub {
            my $res = $CLASS->list_images('qs1', make_scfg(), undef, undef, {});
            is scalar @$res, 1, 'snapshot excluded';
            is $res->[0]{volid}, 'qs1:vm-100-disk-0', 'only the base volume';
        }
    );
};

subtest 'list_images resolves plain pool name to UUID via pool_get' => sub {
    with_mocks(
        {
            storagePoolGet    => { id => $POOL_UUID, size => 1024, freeSpace => 512 },
            storageVolumeEnum => [
                { id => 'v1', name => 'vm-100-disk-0', size => 10240,
                  storagePoolId => $POOL_UUID, isSnapshot => '0' },
                { id => 'v2', name => 'vm-200-disk-0', size => 5120,
                  storagePoolId => 'other-uuid', isSnapshot => '0' },
            ],
        },
        {},
        sub {
            my ($ua) = @_;
            my $scfg = { %{make_scfg()}, pool_id => 'pve-test-pool' };
            my $res  = $CLASS->list_images('qs1', $scfg, undef, undef, {});
            is scalar @$res, 1,                    'only volume from matching pool returned';
            is $res->[0]{volid}, 'qs1:vm-100-disk-0', 'correct volume';
            ok $ua->was_called('storagePoolGet'),   'pool_get called to resolve pool name';
        }
    );
};

# ---------------------------------------------------------------------------
# 5. path
# ---------------------------------------------------------------------------

subtest 'path returns by-path device string' => sub {
    with_mocks(
        { storageVolumeGet => { id => $VOL_UUID, iqn => $VOL_IQN, lun => 0 } },
        {},
        sub {
            my ($path, $vmid, $vtype) = $CLASS->path(make_scfg(), 'vm-100-disk-0', 'qs1');
            like $path, qr{/dev/disk/by-path/ip-.*-iscsi-.*-lun-0}, 'by-path format';
            is $vmid,  100,      'vmid extracted';
            is $vtype, 'images', 'vtype = images';
        }
    );
};

subtest 'path always uses lun-0 regardless of API lun field' => sub {
    with_mocks(
        { storageVolumeGet => { id => $VOL_UUID, iqn => $VOL_IQN, lun => 1 } },
        {},
        sub {
            my ($path) = $CLASS->path(make_scfg(), 'vm-100-disk-0', 'qs1');
            like $path, qr{-lun-0$}, 'lun-0 even when API returns lun=1';
        }
    );
};

subtest 'path dies on snapshot access' => sub {
    eval { $CLASS->path(make_scfg(), 'vm-100-disk-0', 'qs1', 'snap1') };
    like $@, qr/snapshot access not supported/, 'dies for snapshot path';
};

subtest 'path returns undef device for missing volume (delete preflight)' => sub {
    # PVE's delete API calls path() BEFORE vdisk_free for vtype/ownervm checks.
    # If the volume is already gone (idempotent free path), path() must not
    # die — it must return undef device + parsed metadata so the call chain
    # continues to free_image's fast-return.
    with_mocks(
        {
            storageVolumeGet => { RestError =>
                'Specified StorageVolume object vm-100-disk-0 could not be found. [err=5]' },
        },
        {},
        sub {
            my ($path, $vmid, $vtype) = $CLASS->path(make_scfg(), 'vm-100-disk-0', 'qs1');
            is $path,  undef,    'no device path for missing volume';
            is $vmid,  100,      'vmid still derived from volname';
            is $vtype, 'images', 'vtype still images';
        }
    );
};

# ---------------------------------------------------------------------------
# 6. volume_size_info
# ---------------------------------------------------------------------------

subtest 'volume_size_info returns size in bytes' => sub {
    with_mocks(
        { storageVolumeGet => { id => $VOL_UUID, name => 'vm-100-disk-0', size => 10737418240 } },
        {},
        sub {
            my $size = $CLASS->volume_size_info(make_scfg(), 'qs1', 'vm-100-disk-0');
            is $size, 10737418240, 'size in bytes';

            my ($sz, $fmt, $used, $parent) =
                $CLASS->volume_size_info(make_scfg(), 'qs1', 'vm-100-disk-0');
            is $sz,  10737418240, 'size in list context';
            is $fmt, 'raw',       'format is raw';
        }
    );
};

# ---------------------------------------------------------------------------
# 7. activate_storage
# ---------------------------------------------------------------------------

subtest 'activate_storage verifies connectivity and registers host' => sub {
    with_mocks(
        {
            storagePoolGet => { id => $POOL_UUID, size => 1024, freeSpace => 512 },
            hostGet        => { RestError => 'Failed to locate host with IQN' },
            hostAdd        => { obj => { id => $HOST_UUID } },
        },
        {},
        sub {
            my ($ua) = @_;
            my $rc = $CLASS->activate_storage('qs1', make_scfg(), {});
            is $rc, 1, 'returns 1';
            ok $ua->was_called('storagePoolGet'), 'pool connectivity checked';
            ok $ua->was_called('hostAdd'),        'new host registered';
        }
    );
};

subtest 'activate_storage is idempotent when host exists' => sub {
    with_mocks(
        {
            storagePoolGet => { id => $POOL_UUID, size => 1024, freeSpace => 512 },
            hostGet        => { id => $HOST_UUID, name => 'pve-node' },
        },
        {},
        sub {
            my ($ua) = @_;
            $CLASS->activate_storage('qs1', make_scfg(), {});
            ok !$ua->was_called('hostAdd'), 'hostAdd not called for existing host';
        }
    );
};

# ---------------------------------------------------------------------------
# 8. alloc_image / free_image
# ---------------------------------------------------------------------------

subtest 'alloc_image creates volume and returns volname' => sub {
    with_mocks(
        { storageVolumeCreate => { id => $VOL_UUID, name => 'vm-100-disk-0' } },
        {},
        sub {
            my ($ua) = @_;
            my $name = $CLASS->alloc_image('qs1', make_scfg(), 100, 'raw', undef, 10240);
            ok defined $name, 'returns a name';
            like $name, qr/^vm-100-disk-/, 'name has correct prefix';
            ok $ua->was_called('storageVolumeCreate'), 'create API called';

            my $params = $ua->params_for('storageVolumeCreate');
            is $params->{provisionableId}, $POOL_UUID, 'pool UUID passed (qs- stripped)';
            is $params->{thinProvisioned}, 'true', 'thin provisioned by default (sparse unset)';
        }
    );
};

subtest 'alloc_image honors sparse 0 (thick provisioning opt-out)' => sub {
    with_mocks(
        { storageVolumeCreate => { id => $VOL_UUID, name => 'vm-100-disk-0' } },
        {},
        sub {
            my ($ua) = @_;
            my $scfg = { %{ make_scfg() }, sparse => 0 };
            $CLASS->alloc_image('qs1', $scfg, 100, 'raw', undef, 10240);
            my $params = $ua->params_for('storageVolumeCreate');
            is $params->{thinProvisioned}, 'false', 'thick provisioning requested';
        }
    );
};

subtest 'alloc_image rejects non-raw format' => sub {
    eval { $CLASS->alloc_image('qs1', make_scfg(), 100, 'qcow2', undef, 1024) };
    like $@, qr/unsupported format/, 'dies on qcow2';
};

subtest 'alloc_image rejects wrong vmid in name' => sub {
    eval { $CLASS->alloc_image('qs1', make_scfg(), 100, 'raw', 'vm-999-disk-0', 1024) };
    like $@, qr/illegal name/, 'dies on mismatched vmid';
};

subtest 'free_image logs out and deletes volume with cascade+force' => sub {
    with_mocks(
        {
            storageVolumeGet        => { id => $VOL_UUID, iqn => $VOL_IQN },
            hostGet                 => { id => $HOST_UUID },
            storageVolumeAclAddRemoveEx => { status => 'ok' },
            storageVolumeDelete     => { status => 'ok' },
        },
        { 'node --logout' => '', 'session' => { _error => 'no sessions' } },
        sub {
            my ($ua, $runner) = @_;
            $CLASS->free_image('qs1', make_scfg(), 'vm-100-disk-0', 0);
            ok $ua->was_called('storageVolumeDelete'), 'volume deleted';
            ok $runner->was_called('node --logout'),   'iSCSI logout called';

            # free_image must request destructive semantics now that APIClient
            # defaults to safe — otherwise child snapshots would block the
            # delete and PVE would think it succeeded with the volume still live.
            my $p = $ua->params_for('storageVolumeDelete');
            is $p->{deleteOptions}, 4, 'cascade requested by free_image';
            is $p->{flags},         2, 'force requested by free_image';
        }
    );
};

subtest 'free_image falls back to per-snapshot delete when cascade fails' => sub {
    # Older QuantaStor builds (observed on 7.0.0.156) fail the cascade delete
    # on a child snapshot (err=493 DELETE_ZVOL_FAILED) after the volume has
    # been exported over iSCSI, yet deleting the same snapshots individually
    # succeeds — so free_image must not give up on the first cascade failure.
    my $delete_calls = 0;
    with_mocks(
        {
            storageVolumeGet => {
                id  => $VOL_UUID,
                iqn => $VOL_IQN,
                snapshotIdList => ['snap-uuid-1', 'snap-uuid-2'],
            },
            hostGet                     => { id => $HOST_UUID },
            storageVolumeAclAddRemoveEx => { status => 'ok' },
            storageVolumeDelete         => sub {
                return { RestError => 'WebFault: Failed to delete storage volume [err=493]' }
                    if ++$delete_calls == 1;
                return { status => 'ok' };
            },
        },
        { 'node --logout' => '', 'session' => { _error => 'no sessions' } },
        sub {
            my ($ua, $runner) = @_;
            $CLASS->free_image('qs1', make_scfg(), 'vm-100-disk-0', 0);
            is $delete_calls, 4, 'cascade attempt + 2 snapshots + volume retry';

            my @del = grep { m{/qstorapi/storageVolumeDelete\?} } @{ $ua->requests_made };
            like $del[1], qr/storageVolumeList=snap-uuid-1/,   'first snapshot deleted individually';
            like $del[2], qr/storageVolumeList=snap-uuid-2/,   'second snapshot deleted individually';
            like $del[3], qr/storageVolumeList=\Q$VOL_UUID\E/, 'volume delete retried after snapshots';
            like $del[3], qr/deleteOptions=4/,                 'retry still requests cascade';
        }
    );
};

subtest 'free_image fallback tolerates snapshots the cascade already deleted' => sub {
    # A failed cascade may have partially completed: children removed, parent
    # refused (seen on 7.0.0.527 — parent zvol briefly busy after target
    # teardown). The per-snapshot pass must skip not-found and still retry
    # the parent instead of dying on the already-deleted snapshot.
    my $delete_calls = 0;
    with_mocks(
        {
            storageVolumeGet => {
                id  => $VOL_UUID,
                iqn => $VOL_IQN,
                snapshotIdList => ['snap-uuid-1'],
            },
            hostGet                     => { id => $HOST_UUID },
            storageVolumeAclAddRemoveEx => { status => 'ok' },
            storageVolumeDelete         => sub {
                my ($params) = @_;
                $delete_calls++;
                return { RestError => 'WebFault: Failed to delete storage volume [err=493]' }
                    if $delete_calls == 1;
                return { RestError => 'WebFault: Specified StorageVolume object snap-uuid-1 could not be found. [err=5]' }
                    if $params->{storageVolumeList} eq 'snap-uuid-1';
                return { status => 'ok' };
            },
        },
        { 'node --logout' => '', 'session' => { _error => 'no sessions' } },
        sub {
            my ($ua) = @_;
            my $ret = eval { $CLASS->free_image('qs1', make_scfg(), 'vm-100-disk-0', 0); 1 };
            ok $ret, 'free_image succeeds despite already-gone snapshot' or diag $@;
            is $delete_calls, 3, 'cascade + not-found snapshot + parent retry';
        }
    );
};

subtest 'free_image rethrows cascade failure when volume has no snapshots' => sub {
    # A cascade failure on a snapshotless volume is a different problem —
    # falling back would just repeat the same doomed delete, so propagate it.
    with_mocks(
        {
            storageVolumeGet            => { id => $VOL_UUID, iqn => $VOL_IQN },
            hostGet                     => { id => $HOST_UUID },
            storageVolumeAclAddRemoveEx => { status => 'ok' },
            storageVolumeDelete         => { RestError => 'WebFault: pool offline [err=42]' },
        },
        { 'node --logout' => '', 'session' => { _error => 'no sessions' } },
        sub {
            my ($ua) = @_;
            eval { $CLASS->free_image('qs1', make_scfg(), 'vm-100-disk-0', 0) };
            like $@, qr/pool offline/, 'original delete error propagated';
            is scalar(grep { m{/qstorapi/storageVolumeDelete\?} } @{ $ua->requests_made }), 1,
                'no retry attempted without snapshots';
        }
    );
};

subtest 'free_image is a no-op when volume already gone (idempotent)' => sub {
    # PVE retries deletes on some paths; raising "not found" creates a stuck
    # state. Treat already-gone as success.
    with_mocks(
        {
            storageVolumeGet    => { RestError =>
                'Specified StorageVolume object vm-100-disk-0 could not be found. [err=5]' },
        },
        {},
        sub {
            my ($ua, $runner) = @_;
            my $rv = eval { $CLASS->free_image('qs1', make_scfg(), 'vm-100-disk-0', 0) };
            is $@, '',     'no error raised';
            is $rv, undef, 'returns undef';
            ok !$ua->was_called('storageVolumeDelete'), 'no delete call attempted';
        }
    );
};

subtest 'volume_snapshot_delete is a no-op when snapshot already gone' => sub {
    with_mocks(
        {
            storageVolumeGet => { RestError =>
                'Specified StorageVolume object vm-100-disk-0_snap1 could not be found. [err=5]' },
        },
        {},
        sub {
            my ($ua) = @_;
            my $rv = eval { $CLASS->volume_snapshot_delete(make_scfg(), 'qs1', 'vm-100-disk-0', 'snap1') };
            is $@, '',     'no error raised';
            is $rv, undef, 'returns undef';
            ok !$ua->was_called('storageVolumeDelete'), 'no delete call attempted';
        }
    );
};

subtest 'free_image still deletes volume when ACL remove fails' => sub {
    # Simulates an already-detached volume: host lookup succeeds but
    # ACL remove returns a RestError. Delete must still happen.
    with_mocks(
        {
            storageVolumeGet        => { id => $VOL_UUID, iqn => $VOL_IQN },
            hostGet                 => { id => $HOST_UUID },
            storageVolumeAclAddRemoveEx => { RestError => 'ACL entry not found' },
            storageVolumeDelete     => { status => 'ok' },
        },
        { 'node --logout' => '', 'session' => { _error => 'no sessions' } },
        sub {
            my ($ua, $runner) = @_;
            # Suppress the expected warning so test output stays clean.
            my $warn; local $SIG{__WARN__} = sub { $warn = $_[0] };

            eval { $CLASS->free_image('qs1', make_scfg(), 'vm-100-disk-0', 0) };
            is $@, '', 'free_image did not die';
            ok $ua->was_called('storageVolumeDelete'), 'volume deleted despite ACL failure';
            like $warn, qr/teardown warning/, 'warned about teardown failure';
        }
    );
};

subtest 'free_image dies when volume_delete itself fails' => sub {
    with_mocks(
        {
            storageVolumeGet        => { id => $VOL_UUID, iqn => $VOL_IQN },
            hostGet                 => { id => $HOST_UUID },
            storageVolumeAclAddRemoveEx => { status => 'ok' },
            storageVolumeDelete     => { RestError => 'Volume is busy' },
        },
        { 'node --logout' => '', 'session' => { _error => 'no sessions' } },
        sub {
            my ($ua, $runner) = @_;
            eval { $CLASS->free_image('qs1', make_scfg(), 'vm-100-disk-0', 0) };
            like $@, qr/Volume is busy/, 'delete failure surfaces to caller';
        }
    );
};

# ---------------------------------------------------------------------------
# 9. activate_volume / deactivate_volume
# ---------------------------------------------------------------------------

subtest 'activate_volume grants ACL and logs in' => sub {
    with_mocks(
        {
            storageVolumeGet            => { id => $VOL_UUID, iqn => $VOL_IQN },
            storageVolumeAclAddRemoveEx => { status => 'ok' },
        },
        { 'discovery' => '', 'node --login' => '' },
        sub {
            my ($ua, $runner) = @_;
            $CLASS->activate_volume('qs1', make_scfg(), 'vm-100-disk-0', undef, {});
            ok $ua->was_called('storageVolumeAclAddRemoveEx'), 'ACL granted';
            my $p = $ua->params_for('storageVolumeAclAddRemoveEx');
            is $p->{modType}, 0, 'modType=0 (add)';
            ok $runner->was_called('node --login'), 'iSCSI login called';
        }
    );
};

# A freshly cloned volume can exist before SCST has created its iSCSI target, so
# the ACL add comes back 5xx ("interrupted by signal") and the clone dies. The
# add is idempotent, so it is retried; non-5xx must still fail fast.
subtest 'activate_volume retries ACL add through a transient 5xx' => sub {
    my $calls = 0;
    with_mocks(
        {
            storageVolumeGet            => { id => $VOL_UUID, iqn => $VOL_IQN },
            storageVolumeAclAddRemoveEx => sub {
                return { _http_error => '500 Internal Server Error' } if ++$calls == 1;
                return { status => 'ok' };
            },
        },
        { 'discovery' => '', 'node --login' => '' },
        sub {
            my ($ua, $runner) = @_;
            local $PVE::Storage::Custom::QuantaStor::ACL_ADD_RETRY_SECS = 0;
            $CLASS->activate_volume('qs1', make_scfg(), 'vm-100-disk-0', undef, {});
            is $calls, 2, 'retried once after the transient 5xx';
            ok $runner->was_called('node --login'), 'login proceeded after the retry';
        }
    );
};

subtest 'activate_volume does not retry a non-5xx ACL failure' => sub {
    my $calls = 0;
    with_mocks(
        {
            storageVolumeGet            => { id => $VOL_UUID, iqn => $VOL_IQN },
            storageVolumeAclAddRemoveEx => sub {
                $calls++;
                return { RestError => 'Authentication check failed [err=26]' };
            },
        },
        { 'discovery' => '', 'node --login' => '' },
        sub {
            my ($ua, $runner) = @_;
            local $PVE::Storage::Custom::QuantaStor::ACL_ADD_RETRY_SECS = 0;
            eval { $CLASS->activate_volume('qs1', make_scfg(), 'vm-100-disk-0', undef, {}) };
            like $@, qr/Authentication check failed/, 'auth error surfaces as-is';
            is $calls, 1, 'failed fast — no retry burned on a non-transient error';
            ok !$runner->was_called('node --login'), 'did not attempt login';
        }
    );
};

subtest 'activate_volume gives up after the retry budget' => sub {
    my $calls = 0;
    with_mocks(
        {
            storageVolumeGet            => { id => $VOL_UUID, iqn => $VOL_IQN },
            storageVolumeAclAddRemoveEx => sub {
                $calls++;
                return { _http_error => '500 Internal Server Error' };
            },
        },
        { 'discovery' => '', 'node --login' => '' },
        sub {
            no warnings 'once';   # fully-qualified knob referenced once here
            local $PVE::Storage::Custom::QuantaStor::ACL_ADD_RETRY_SECS = 0;
            local $PVE::Storage::Custom::QuantaStor::ACL_ADD_ATTEMPTS   = 3;
            eval { $CLASS->activate_volume('qs1', make_scfg(), 'vm-100-disk-0', undef, {}) };
            like $@, qr/HTTP 500/, 'surfaces the final error';
            is $calls, 3, 'stopped at the configured attempt budget';
        }
    );
};

subtest 'activate_volume dies on snapshot' => sub {
    eval { $CLASS->activate_volume('qs1', make_scfg(), 'vm-100-disk-0', 'snap1', {}) };
    like $@, qr/snapshot activation not supported/, 'dies for snapshot';
};

subtest 'activate_volume dies when device symlink never appears' => sub {
    my $ua     = Test::QuantaStor::MockUA->new(responses => {
        storageVolumeGet            => { id => $VOL_UUID, iqn => $VOL_IQN },
        storageVolumeAclAddRemoveEx => { status => 'ok' },
    });
    my $runner = Test::QuantaStor::MockCmdRunner->new(responses => {
        'discovery' => '', 'node --login' => '',
    });

    no warnings 'redefine';
    local *PVE::Storage::Custom::QuantaStor::_client = sub {
        return PVE::Storage::QuantaStor::APIClient->new(
            host => $API_HOST, username => 'admin', password => 'x',
            _ua => $ua,
            # Stub sleep so wait_for_session_gone polls don't pay real cost.
            _sleep => sub { },
        );
    };
    local *PVE::Storage::Custom::QuantaStor::_iscsi = sub {
        return PVE::Storage::QuantaStor::ISCSIManager->new(
            portal          => $PORTAL,
            _run_cmd        => $runner->as_coderef,
            _initiator_file => _temp_initiator_file(),
            _path_exists    => sub { 0 },   # symlink never appears
            _sleep          => sub { },     # don't actually sleep in test
        );
    };

    eval { $CLASS->activate_volume('qs1', make_scfg(), 'vm-100-disk-0', undef, {}) };
    like $@, qr/iSCSI device .* did not appear/, 'dies with clear message on timeout';
};

subtest 'deactivate_volume logs out and removes ACL' => sub {
    with_mocks(
        {
            storageVolumeGet            => { id => $VOL_UUID, iqn => $VOL_IQN },
            hostGet                     => { id => $HOST_UUID },
            storageVolumeAclAddRemoveEx => { status => 'ok' },
        },
        { 'node --logout' => '', 'session' => { _error => 'no sessions' } },
        sub {
            my ($ua, $runner) = @_;
            $CLASS->deactivate_volume('qs1', make_scfg(), 'vm-100-disk-0', undef, {});
            ok $runner->was_called('node --logout'), 'iSCSI logout called';
            ok $ua->was_called('storageVolumeAclAddRemoveEx'), 'ACL removed';
            my $p = $ua->params_for('storageVolumeAclAddRemoveEx');
            is $p->{modType}, 1, 'modType=1 (remove)';
        }
    );
};

# ---------------------------------------------------------------------------
# 9b. volume_resize
# ---------------------------------------------------------------------------

subtest 'volume_resize online (running VM): force flag + rescan, no logout' => sub {
    # Online resize: keep QEMU's fd valid by NOT logging out. Pass flags=2 to
    # bypass QS's active-session rejection (err=76). Rescan so the kernel
    # picks up the new LUN geometry before PVE's QMP block_resize fires.
    with_mocks(
        {
            storageVolumeGet    => { id => $VOL_UUID, iqn => $VOL_IQN },
            storageVolumeResize => { task => { id => 'task-1' } },
        },
        {
            # session lookup for rescan's is_logged_in check
            'session'       => "tcp: [1] $PORTAL:3260,1 $VOL_IQN (non-flash)\n",
            'node --rescan' => '',
        },
        sub {
            my ($ua, $runner) = @_;

            my $new_size = 6 * 1024 * 1024 * 1024;   # 6 GiB
            my $rv = $CLASS->volume_resize(make_scfg(), 'qs1', 'vm-100-disk-0',
                                           $new_size, 1);
            is $rv, $new_size, 'returns the new size';

            ok  $ua->was_called('storageVolumeResize'),    'storageVolumeResize called';
            my $p = $ua->params_for('storageVolumeResize');
            is $p->{flags}, 2, 'flags=2 (force) passed to QS — bypasses err=76';
            is $p->{newSizeInBytes}, $new_size, 'new size passed through';

            ok  $runner->was_called('node --rescan'), 'iscsiadm --rescan called';
            ok !$runner->was_called('node --logout'), 'NO iscsi logout (would destroy QEMU fd)';
            ok !$runner->was_called('node --login'),  'NO iscsi login (already connected)';
        }
    );
};

subtest 'volume_resize stopped VM with lingering session: rescan still issued' => sub {
    # PVE doesn't always call deactivate_volume on stop for shared iSCSI, so
    # the session is typically still alive when volume_resize fires for a
    # stopped VM. Rescan must still run so the kernel's cached LUN geometry
    # gets refreshed — otherwise the next VM start sees stale size.
    with_mocks(
        {
            storageVolumeGet    => { id => $VOL_UUID, iqn => $VOL_IQN },
            storageVolumeResize => { task => { id => 'task-2' } },
        },
        {
            # Session is alive even though VM is "stopped"
            'session'       => "tcp: [1] $PORTAL:3260,1 $VOL_IQN (non-flash)\n",
            'node --rescan' => '',
        },
        sub {
            my ($ua, $runner) = @_;

            my $new_size = 6 * 1024 * 1024 * 1024;
            my $rv = $CLASS->volume_resize(make_scfg(), 'qs1', 'vm-100-disk-0',
                                           $new_size, 0);
            is $rv, $new_size, 'returns the new size';

            my $p = $ua->params_for('storageVolumeResize');
            is $p->{flags}, 2, 'flags=2 (force) — uniform with running path';

            ok  $runner->was_called('node --rescan'), 'rescan issued unconditionally';
            ok !$runner->was_called('node --logout'), 'no logout';
        }
    );
};

subtest 'volume_resize without active session: rescan is a no-op' => sub {
    # Edge case: VM stopped AND iSCSI session already torn down. rescan should
    # not try to issue iscsiadm --rescan in that state (ISCSIManager::rescan
    # short-circuits when is_logged_in returns false).
    with_mocks(
        {
            storageVolumeGet    => { id => $VOL_UUID, iqn => $VOL_IQN },
            storageVolumeResize => { task => { id => 'task-3' } },
        },
        {
            'session' => { _error => 'iscsiadm: No active sessions.' },
        },
        sub {
            my ($ua, $runner) = @_;
            my $new_size = 6 * 1024 * 1024 * 1024;
            $CLASS->volume_resize(make_scfg(), 'qs1', 'vm-100-disk-0', $new_size, 0);

            ok  $ua->was_called('storageVolumeResize'),  'resize still happens';
            ok !$runner->was_called('node --rescan'),    'rescan command suppressed (no session)';
        }
    );
};

# ---------------------------------------------------------------------------
# 10. Snapshot hooks
# ---------------------------------------------------------------------------

subtest 'volume_snapshot creates snap with correct name' => sub {
    with_mocks(
        { storageVolumeSnapshot => { id => 'snap-uuid' } },
        {},
        sub {
            my ($ua) = @_;
            $CLASS->volume_snapshot(make_scfg(), 'qs1', 'vm-100-disk-0', 'snap1');
            my $p = $ua->params_for('storageVolumeSnapshot');
            is $p->{storageVolume}, 'vm-100-disk-0',        'source volume';
            is $p->{snapshotName},  'vm-100-disk-0_snap1',  'snap name uses _ separator';
        }
    );
};

subtest 'volume_snapshot_delete removes snap volume' => sub {
    with_mocks(
        {
            storageVolumeGet    => { id => 'snap-vol-uuid' },
            storageVolumeDelete => { status => 'ok' },
        },
        {},
        sub {
            my ($ua) = @_;
            $CLASS->volume_snapshot_delete(make_scfg(), 'qs1', 'vm-100-disk-0', 'snap1', 0);
            my $get_p = $ua->params_for('storageVolumeGet');
            is $get_p->{storageVolume}, 'vm-100-disk-0_snap1', 'fetched correct snap volume';
            ok $ua->was_called('storageVolumeDelete'), 'delete called';
        }
    );
};

subtest 'volume_snapshot_rollback: logout then rollback when session active, no re-login' => sub {
    with_mocks(
        {
            storageVolumeGet      => { id => $VOL_UUID, iqn => $VOL_IQN },
            storageVolumeRollback => { id => $VOL_UUID },
            sessionEnum           => [],   # QS confirms no sessions
        },
        {
            # First call (is_logged_in check): session active.
            # Second call (wait_for_logout poll): gone.
            'session'       => [
                "tcp: [1] $PORTAL:3260,1 $VOL_IQN (non-flash)\n",
                { _error => 'no sessions' },
            ],
            'node --logout' => '',
        },
        sub {
            my ($ua, $runner) = @_;
            $CLASS->volume_snapshot_rollback(make_scfg(), 'qs1', 'vm-100-disk-0', 'snap1');
            ok $runner->was_called('node --logout'),      'logged out before rollback';
            ok $ua->was_called('storageVolumeRollback'),  'rollback API called';
            ok !$runner->was_called('node --login'),      'no re-login (PVE calls activate_volume on next start)';

            my $rb_p = $ua->params_for('storageVolumeRollback');
            is $rb_p->{snapshotVolume}, 'vm-100-disk-0_snap1', 'correct snap name';
        }
    );
};

subtest 'volume_snapshot_rollback: skips iSCSI ops when volume not active' => sub {
    with_mocks(
        {
            storageVolumeGet      => { id => $VOL_UUID, iqn => $VOL_IQN },
            storageVolumeRollback => { id => $VOL_UUID },
            sessionEnum           => [],
        },
        {
            'session' => { _error => 'no sessions' },
        },
        sub {
            my ($ua, $runner) = @_;
            $CLASS->volume_snapshot_rollback(make_scfg(), 'qs1', 'vm-100-disk-0', 'snap1');
            ok  $ua->was_called('storageVolumeRollback'),  'rollback API called';
            ok !$runner->was_called('node --logout'),      'no logout for inactive volume';
            ok !$runner->was_called('node --login'),       'no login for inactive volume';
        }
    );
};

subtest 'volume_snapshot_rollback waits for QS-side session GC before calling rollback' => sub {
    # Bug seen in live testing: PVE-side iscsiadm logout returns instantly but
    # QS's session tracker takes seconds to GC. volume_rollback rejects on an
    # active session. The hook must poll sessionEnum until empty BEFORE rollback.
    with_mocks(
        {
            storageVolumeGet      => { id => $VOL_UUID, iqn => $VOL_IQN },
            storageVolumeRollback => { id => $VOL_UUID },
            sessionEnum           => [],   # QS-side already idle
        },
        { 'session' => { _error => 'no sessions' } },
        sub {
            my ($ua) = @_;
            $CLASS->volume_snapshot_rollback(make_scfg(), 'qs1', 'vm-100-disk-0', 'snap1');

            ok $ua->was_called('sessionEnum'),        'sessionEnum was polled';
            ok $ua->was_called('storageVolumeRollback'), 'rollback API called';

            # Order check: sessionEnum must precede storageVolumeRollback.
            my @reqs = @{ $ua->requests_made };
            my ($i_sess) = grep { $reqs[$_] =~ /sessionEnum/ } 0..$#reqs;
            my ($i_rb)   = grep { $reqs[$_] =~ /storageVolumeRollback/ } 0..$#reqs;
            ok defined $i_sess && defined $i_rb && $i_sess < $i_rb,
                'sessionEnum happens before storageVolumeRollback';
        }
    );
};

subtest 'volume_rollback_is_possible returns 1 for most-recent snap' => sub {
    my $ts = '2025-01-01T00:00:00Z';
    with_mocks(
        {
            storageVolumeGet  => {
                id => 'snap-uuid', name => 'vm-100-disk-0_snap1',
                createdTimeStamp => $ts, snapshotParent => $VOL_UUID, isSnapshot => '1',
            },
            storageVolumeEnum => [
                { id => 'snap-uuid', name => 'vm-100-disk-0_snap1',
                  isSnapshot => '1', snapshotParent => $VOL_UUID,
                  createdTimeStamp => $ts },
            ],
        },
        {},
        sub {
            my $r = $CLASS->volume_rollback_is_possible(
                make_scfg(), 'qs1', 'vm-100-disk-0', 'snap1', []);
            is $r, 1, 'returns 1 for most-recent snapshot';
        }
    );
};

subtest 'volume_rollback_is_possible dies when newer snap exists' => sub {
    with_mocks(
        {
            storageVolumeGet  => {
                id => 'snap1-uuid', name => 'vm-100-disk-0_snap1',
                createdTimeStamp => '2025-01-01T00:00:00Z',
                snapshotParent   => $VOL_UUID, isSnapshot => '1',
            },
            storageVolumeEnum => [
                { id => 'snap1-uuid', name => 'vm-100-disk-0_snap1',
                  isSnapshot => '1', snapshotParent => $VOL_UUID,
                  createdTimeStamp => '2025-01-01T00:00:00Z' },
                { id => 'snap2-uuid', name => 'vm-100-disk-0_snap2',
                  isSnapshot => '1', snapshotParent => $VOL_UUID,
                  createdTimeStamp => '2025-06-01T00:00:00Z' },
            ],
        },
        {},
        sub {
            my @blockers;
            eval {
                $CLASS->volume_rollback_is_possible(
                    make_scfg(), 'qs1', 'vm-100-disk-0', 'snap1', \@blockers);
            };
            like $@, qr/not the most recent snapshot/, 'dies when blocked';
            is $blockers[0], 'vm-100-disk-0_snap2', 'blocker name populated';
        }
    );
};

# ---------------------------------------------------------------------------
# 11. create_base / clone_image
# ---------------------------------------------------------------------------

subtest 'create_base renames volume and takes template snapshot' => sub {
    my $new_iqn = 'iqn.2009-10.com.osnexus:pool:base-100-disk-0';
    with_mocks(
        {
            storageVolumeGet            => { id => $VOL_UUID, iqn => $VOL_IQN },
            hostGet                     => { id => $HOST_UUID },
            storageVolumeAclAddRemoveEx => { status => 'ok' },
            storageVolumeModify         => { id => $VOL_UUID, iqn => $new_iqn },
            storageVolumeSnapshot       => { id => 'tmpl-snap-uuid' },
            sessionEnum                 => [],   # QS confirms no sessions
        },
        {
            'node --logout' => '',
            'session'       => { _error => 'no sessions' },
            'discovery'     => '',
            'node --login'  => '',
        },
        sub {
            my ($ua, $runner) = @_;
            my $result = $CLASS->create_base('qs1', make_scfg(), 'vm-100-disk-0');
            is $result, 'base-100-disk-0', 'returns new base volname';

            my $mod_p = $ua->params_for('storageVolumeModify');
            is $mod_p->{newName}, 'base-100-disk-0', 'renamed to base-';

            my $snap_p = $ua->params_for('storageVolumeSnapshot');
            is $snap_p->{snapshotName}, 'template-base-100-disk-0', 'template snap created';
        }
    );
};

subtest 'create_base outlasts slow QuantaStor session GC (waits past 30s)' => sub {
    # The server-side session tracker has been measured taking 20s-2min to GC
    # a logged-out session; with the old 30s default wait, `pct template` right
    # after `pct stop` failed flakily. create_base now waits up to 120s.
    my $enum_calls = 0;
    with_mocks(
        {
            storageVolumeGet            => { id => $VOL_UUID, iqn => $VOL_IQN },
            hostGet                     => { id => $HOST_UUID },
            storageVolumeAclAddRemoveEx => { status => 'ok' },
            storageVolumeModify         => { id => $VOL_UUID, iqn => 'iqn.2009-10.com.osnexus:pool:base-100-disk-0' },
            storageVolumeSnapshot       => { id => 'tmpl-snap-uuid' },
            sessionEnum                 => sub {
                return ++$enum_calls <= 50 ? [ { id => 'lingering-session' } ] : [];
            },
        },
        {
            'node --logout' => '',
            'session'       => { _error => 'no sessions' },
            'discovery'     => '',
            'node --login'  => '',
        },
        sub {
            my $result = $CLASS->create_base('qs1', make_scfg(), 'vm-100-disk-0');
            is $result, 'base-100-disk-0', 'conversion succeeded despite ~50s of lingering session';
            ok $enum_calls > 30, "kept polling past the old 30s default ($enum_calls polls)";
        }
    );
};

subtest 'clone_image clones template snapshot and logs in' => sub {
    my $clone_iqn = 'iqn.2009-10.com.osnexus:pool:vm-101-disk-0';
    with_mocks(
        {
            storageVolumeClone          => { obj => { id => 'clone-uuid', iqn => $clone_iqn } },
            storageVolumeAclAddRemoveEx => { status => 'ok' },
            storageVolumeEnum           => [],
        },
        { 'discovery' => '', 'node --login' => '' },
        sub {
            my ($ua, $runner) = @_;
            my $name = $CLASS->clone_image(make_scfg(), 'qs1', 'base-100-disk-0', 101);
            ok defined $name, 'returns new volume name';
            like $name, qr/^vm-101-disk-/, 'new name has correct vmid';

            my $p = $ua->params_for('storageVolumeClone');
            is $p->{storageVolume}, 'template-base-100-disk-0', 'cloned from template snap';
            ok $runner->was_called('node --login'), 'logged in to clone';
        }
    );
};

subtest 'clone_image dies on non-base volume' => sub {
    eval { $CLASS->clone_image(make_scfg(), 'qs1', 'vm-100-disk-0', 101) };
    like $@, qr/only works on base images/, 'dies on non-base';
};

# ---------------------------------------------------------------------------
# 12. volume_has_feature
# ---------------------------------------------------------------------------

subtest 'volume_has_feature snapshot on current volume' => sub {
    my $r = $CLASS->volume_has_feature(make_scfg(), 'snapshot', 'qs1', 'vm-100-disk-0');
    ok $r, 'snapshot supported on current';
};

subtest 'volume_has_feature clone only on base' => sub {
    ok  $CLASS->volume_has_feature(make_scfg(), 'clone', 'qs1', 'base-100-disk-0'),
        'clone supported on base';
    ok !$CLASS->volume_has_feature(make_scfg(), 'clone', 'qs1', 'vm-100-disk-0'),
        'clone not supported on current';
};

subtest 'storage_can_replicate returns 0' => sub {
    is $CLASS->storage_can_replicate(make_scfg(), 'qs1', 'raw'), 0, 'no replication';
};

# ---------------------------------------------------------------------------
# 13. Container (LXC) rootdir support
# ---------------------------------------------------------------------------

subtest 'volume_snapshot_needs_fsfreeze returns 1' => sub {
    # CT rootfs is a live ext4 on the LUN; PVE must freeze it before we snapshot
    # the QuantaStor volume so the snapshot is filesystem-consistent (as RBD does).
    is $CLASS->volume_snapshot_needs_fsfreeze(), 1, 'fsfreeze required before snapshot';
};

subtest 'container rootfs volume is handled like a raw VM disk' => sub {
    # A container's root filesystem lives on the same raw vm-<vmid>-disk-N LUN
    # shape as a VM disk (no subvol-* / format subvol for block storage), so it
    # flows through the identical parse/alloc/feature paths.
    my @r = $CLASS->parse_volname('vm-200-disk-0');
    is $r[0], 'images', 'CT rootfs parses with the images vtype (raw block volume)';
    is $r[6], 'raw',    'CT rootfs format is raw';

    ok $CLASS->volume_has_feature(make_scfg(), 'snapshot', 'qs1', 'vm-200-disk-0'),
        'snapshot supported on a CT rootfs volume';

    with_mocks(
        { storageVolumeCreate => { id => $VOL_UUID, name => 'vm-200-disk-0' } },
        {},
        sub {
            my ($ua) = @_;
            my $name = $CLASS->alloc_image('qs1', make_scfg(), 200, 'raw', undef, 8192);
            like $name, qr/^vm-200-disk-/, 'alloc_image creates a raw CT rootfs LUN';
            ok $ua->was_called('storageVolumeCreate'), 'create API called for CT rootfs';
        }
    );
};

# ---------------------------------------------------------------------------
done_testing();
