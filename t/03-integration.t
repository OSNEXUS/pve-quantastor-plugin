#!/usr/bin/perl
#
# Integration tests for APIClient and ISCSIManager against a real QuantaStor
# appliance.  All tests are SKIPPED unless the following environment variables
# are set:
#
#   QS_HOST      - QuantaStor appliance IP or hostname
#   QS_USER      - API username (default: admin)
#   QS_PASSWORD  - API password
#   QS_POOL      - Storage pool name or UUID to operate in
#
# Optionally:
#   QS_PORTAL    - iSCSI portal address (defaults to QS_HOST)
#   QS_SSL       - Set to 1 to enable SSL verification (default: 0)
#   QS_CA_CERT   - Path to CA certificate for SSL verification
#
# These tests CREATE and DELETE real volumes on the appliance.  Use a
# dedicated test pool — do not point at a production pool.
#
# Run with:
#   QS_HOST=10.0.0.1 QS_PASSWORD=secret QS_POOL=test-pool prove t/03-integration.t
#

use strict;
use warnings;

use FindBin qw($Bin);
use lib "$Bin/../src/perl5";
use lib "$Bin/lib";

use Test::More;
use POSIX qw(strftime);

# ---------------------------------------------------------------------------
# Guard: skip entire file unless credentials are present
# ---------------------------------------------------------------------------

my $qs_host   = $ENV{QS_HOST}     or plan skip_all => 'QS_HOST not set';
my $qs_user   = $ENV{QS_USER}     // 'admin';
my $qs_pass   = $ENV{QS_PASSWORD} or plan skip_all => 'QS_PASSWORD not set';
my $qs_pool   = $ENV{QS_POOL}     or plan skip_all => 'QS_POOL not set';
my $qs_portal = $ENV{QS_PORTAL}   // $qs_host;
my $qs_ssl    = $ENV{QS_SSL}      // 0;
my $qs_ca     = $ENV{QS_CA_CERT};

# Load modules under test
require PVE::Storage::QuantaStor::APIClient;
require PVE::Storage::QuantaStor::ISCSIManager;

# Shared timestamp suffix for unique test volume names
my $ts = strftime('%Y%m%d%H%M%S', localtime);
my $test_vol    = "integration-test-$ts";
my $test_snap   = "${test_vol}_snap1";
my $test_clone  = "${test_vol}-clone";

# ---------------------------------------------------------------------------
# Shared client instance
# ---------------------------------------------------------------------------

my $client = PVE::Storage::QuantaStor::APIClient->new(
    host       => $qs_host,
    username   => $qs_user,
    password   => $qs_pass,
    ssl_verify => $qs_ssl,
    ca_cert    => $qs_ca,
    logger     => sub { diag "[$_[0]] $_[1]" },
);

# ---------------------------------------------------------------------------
# Cleanup helper — called in END block to remove test volumes even on failure
# ---------------------------------------------------------------------------

my @volumes_to_cleanup;

END {
    for my $vol (reverse @volumes_to_cleanup) {
        eval {
            diag "Cleanup: deleting '$vol'";
            my $v = $client->volume_get($vol);
            $client->volume_delete($v->{id}) if $v;
        };
        diag "Cleanup warning: $@" if $@;
    }
}

# ---------------------------------------------------------------------------
# 1. Connectivity: pool_get
# ---------------------------------------------------------------------------

subtest 'pool_get connects and returns pool metadata' => sub {
    my $pool = eval { $client->pool_get($qs_pool) };
    if ($@) {
        fail "pool_get failed: $@";
        return;
    }
    ok defined $pool->{id},        'pool has id';
    ok defined $pool->{size},      'pool has size';
    ok defined $pool->{freeSpace}, 'pool has freeSpace';
    diag sprintf "Pool '%s': total=%d bytes, free=%d bytes",
        $pool->{name} // $qs_pool, $pool->{size}, $pool->{freeSpace};
};

# ---------------------------------------------------------------------------
# 2. volume_enum
# ---------------------------------------------------------------------------

subtest 'volume_enum returns a list' => sub {
    my $vols = eval { $client->volume_enum() };
    if ($@) { fail "volume_enum failed: $@"; return }

    ok ref $vols eq 'ARRAY', 'returns arrayref';
    diag sprintf "volume_enum returned %d volumes", scalar @$vols;
};

# ---------------------------------------------------------------------------
# 3. volume_create
# ---------------------------------------------------------------------------

subtest 'volume_create creates a new volume' => sub {
    # Strip 'qs-' prefix from pool name if present (API expects raw UUID)
    (my $pool_id = $qs_pool) =~ s/^qs-//;

    my $result = eval { $client->volume_create($test_vol, 1024, $pool_id) };
    if ($@) { fail "volume_create failed: $@"; return }

    push @volumes_to_cleanup, $test_vol;

    ok defined $result, 'got a result';
    diag "Created volume: " . ($result->{name} // $result->{obj}{name} // '?');
};

# ---------------------------------------------------------------------------
# 4. volume_get
# ---------------------------------------------------------------------------

subtest 'volume_get returns the created volume' => sub {
    my $vol = eval { $client->volume_get($test_vol) };
    if ($@) { fail "volume_get failed: $@"; return }

    ok defined $vol->{id},   'volume has id';
    ok defined $vol->{iqn},  'volume has iqn';
    is $vol->{name}, $test_vol, 'volume name matches';
    diag "Volume IQN: $vol->{iqn}";
};

# ---------------------------------------------------------------------------
# 5. volume_snapshot
# ---------------------------------------------------------------------------

subtest 'volume_snapshot creates a snapshot' => sub {
    my $result = eval { $client->volume_snapshot($test_vol, $test_snap) };
    if ($@) { fail "volume_snapshot failed: $@"; return }

    push @volumes_to_cleanup, $test_snap;
    ok defined $result, 'snapshot created';
    diag "Snapshot: $test_snap";
};

# ---------------------------------------------------------------------------
# 6. volume_clone
# ---------------------------------------------------------------------------

subtest 'volume_clone clones a snapshot' => sub {
    my $result = eval { $client->volume_clone($test_snap, $test_clone) };
    if ($@) { fail "volume_clone failed: $@"; return }

    push @volumes_to_cleanup, $test_clone;
    ok defined $result, 'clone created';
    diag "Clone: $test_clone";
};

# ---------------------------------------------------------------------------
# 7. volume_modify (rename)
# ---------------------------------------------------------------------------

subtest 'volume_modify renames a volume' => sub {
    my $renamed = "${test_clone}-renamed";
    my $vol = eval { $client->volume_get($test_clone) };
    if ($@) { fail "volume_get for clone failed: $@"; return }

    my $result = eval { $client->volume_modify($vol->{id}, $renamed) };
    if ($@) { fail "volume_modify failed: $@"; return }

    # Update cleanup list
    @volumes_to_cleanup = map { $_ eq $test_clone ? $renamed : $_ } @volumes_to_cleanup;
    ok defined $result, 'modify returned result';

    # Verify new name
    my $check = eval { $client->volume_get($renamed) };
    is $check->{name}, $renamed, 'volume has new name' if $check;
};

# ---------------------------------------------------------------------------
# 8. host_get / host_add / ensure_host_registered
# ---------------------------------------------------------------------------

subtest 'host_get returns undef for unknown IQN' => sub {
    my $result = $client->host_get('iqn.1970-01.test.nonexistent:node');
    is $result, undef, 'undef for unknown host';
};

subtest 'ensure_host_registered is idempotent' => sub {
    # We use a fake IQN so we don't pollute real host registrations.
    # Skip this sub-test if we cannot safely add/remove hosts.
    my $fake_iqn  = "iqn.2000-01.test.integration:$ts";
    my $fake_host = "integration-test-$ts";

    my $id1 = eval { $client->ensure_host_registered($fake_host, $fake_iqn) };
    if ($@) { fail "first ensure_host_registered failed: $@"; return }

    ok defined $id1, 'first call returns an id';

    my $id2 = eval { $client->ensure_host_registered($fake_host, $fake_iqn) };
    if ($@) { fail "second ensure_host_registered failed: $@"; return }

    is $id1, $id2, 'second call returns same id (idempotent)';

    # Cleanup: remove the test host
    eval { $client->host_remove($id1) };
    diag "host_remove: $@" if $@;
};

# ---------------------------------------------------------------------------
# 9. volume_rollback (requires snapshot, only if snapshot test passed)
# ---------------------------------------------------------------------------

subtest 'volume_rollback rolls back to snapshot' => sub {
    # Only attempt rollback if we successfully created the snapshot
    my $snap_vol = eval { $client->volume_get($test_snap) };
    if (!$snap_vol) {
        skip "snapshot '$test_snap' not available (earlier test may have failed)", 1;
        return;
    }

    my $vol = eval { $client->volume_get($test_vol) };
    if (!$vol) {
        skip "base volume '$test_vol' not available", 1;
        return;
    }

    my $result = eval {
        $client->volume_rollback($vol->{id}, $test_snap)
    };
    if ($@) { fail "volume_rollback failed: $@"; return }

    ok defined $result, 'rollback completed';
};

# ---------------------------------------------------------------------------
# 10. ACL operations (smoke test — does not require a live iSCSI initiator)
# ---------------------------------------------------------------------------

subtest 'volume_acl_add and volume_acl_remove (smoke)' => sub {
    my $fake_iqn  = "iqn.2000-01.test.acl:$ts";
    my $fake_host = "acl-test-$ts";

    # Register a test host
    my $host_id = eval { $client->ensure_host_registered($fake_host, $fake_iqn) };
    if ($@) { fail "host registration failed: $@"; return }

    my $vol = eval { $client->volume_get($test_vol) };
    if (!$vol) { skip "base volume not available", 1; return }

    # Add ACL
    eval { $client->volume_acl_add($vol->{id}, $fake_iqn) };
    ok !$@, 'volume_acl_add did not die' or diag "Error: $@";

    # Remove ACL
    eval { $client->volume_acl_remove($vol->{id}, $host_id) };
    ok !$@, 'volume_acl_remove did not die' or diag "Error: $@";

    # Cleanup test host
    eval { $client->host_remove($host_id) };
};

# ---------------------------------------------------------------------------
# 11. ISCSIManager — device_path smoke (no real iSCSI required)
# ---------------------------------------------------------------------------

subtest 'ISCSIManager device_path produces expected pattern' => sub {
    my $vol = eval { $client->volume_get($test_vol) };
    if (!$vol || !$vol->{iqn}) {
        skip "volume or IQN not available", 1;
        return;
    }

    my $iscsi = PVE::Storage::QuantaStor::ISCSIManager->new(portal => $qs_portal);
    my $path  = $iscsi->device_path($vol->{iqn});

    like $path, qr{^/dev/disk/by-path/ip-\S+-iscsi-\S+-lun-0$},
        'device_path returns a well-formed by-path string';
    diag "Device path: $path";
};

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------

done_testing();
