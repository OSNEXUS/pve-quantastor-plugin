#!/usr/bin/perl
use strict;
use warnings;

# ---------------------------------------------------------------------------
# Ensure our source tree and test lib are on @INC before anything else loads.
# ---------------------------------------------------------------------------
use FindBin qw($Bin);
use lib "$Bin/../src/perl5";
use lib "$Bin/lib";

use Test::More;
use JSON::PP ();
my $true = JSON::PP::true();
use Test::QuantaStor::MockUA;
use PVE::Storage::QuantaStor::APIClient;

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

sub make_client {
    my (%ua_responses) = @_;
    my $ua = Test::QuantaStor::MockUA->new(responses => \%ua_responses);
    return (
        PVE::Storage::QuantaStor::APIClient->new(
            host     => '10.0.0.1',
            username => 'admin',
            password => 'secret',
            _ua      => $ua,
        ),
        $ua,
    );
}

# ---------------------------------------------------------------------------
# 1. Constructor validation
# ---------------------------------------------------------------------------

subtest 'constructor requires host' => sub {
    eval {
        PVE::Storage::QuantaStor::APIClient->new(username => 'a', password => 'b');
    };
    like $@, qr/host.*required/i, 'dies without host';
};

subtest 'constructor requires username' => sub {
    eval {
        PVE::Storage::QuantaStor::APIClient->new(host => 'x', password => 'b');
    };
    like $@, qr/username.*required/i, 'dies without username';
};

subtest 'constructor requires password' => sub {
    eval {
        PVE::Storage::QuantaStor::APIClient->new(host => 'x', username => 'a');
    };
    like $@, qr/password.*required/i, 'dies without password';
};

subtest 'constructor uses default port 8153' => sub {
    my ($client) = make_client();
    is $client->{port}, 8153, 'default port is 8153';
};

subtest 'constructor accepts custom port' => sub {
    my $ua = Test::QuantaStor::MockUA->new(responses => {});
    my $client = PVE::Storage::QuantaStor::APIClient->new(
        host => 'x', username => 'a', password => 'b',
        port => 9000, _ua => $ua,
    );
    is $client->{port}, 9000, 'custom port stored';
};

# ---------------------------------------------------------------------------
# 1b. SSL verification wiring
# ---------------------------------------------------------------------------
# These tests don't inject _ua so the real LWP::UserAgent is built; we then
# inspect ssl_opts via its getter form to assert the right options were set.

subtest 'ssl_verify=0 disables verification (default)' => sub {
    my $client = PVE::Storage::QuantaStor::APIClient->new(
        host => 'x', username => 'a', password => 'b',
    );
    my $ua = $client->_ua;
    is $ua->ssl_opts('SSL_verify_mode'), 0, 'SSL_verify_mode=0';
    is $ua->ssl_opts('verify_hostname'), 0, 'verify_hostname=0';
};

subtest 'ssl_verify=1 enables verification against system CA bundle' => sub {
    my $client = PVE::Storage::QuantaStor::APIClient->new(
        host => 'x', username => 'a', password => 'b',
        ssl_verify => 1,
    );
    my $ua = $client->_ua;
    is $ua->ssl_opts('SSL_verify_mode'), 1, 'SSL_verify_mode=1';
    is $ua->ssl_opts('verify_hostname'), 1, 'verify_hostname=1';
};

subtest 'ca_cert path enables verification with custom CA' => sub {
    my $client = PVE::Storage::QuantaStor::APIClient->new(
        host => 'x', username => 'a', password => 'b',
        ca_cert => '/etc/ssl/certs/my-ca.pem',
    );
    my $ua = $client->_ua;
    is $ua->ssl_opts('SSL_ca_file'),    '/etc/ssl/certs/my-ca.pem', 'SSL_ca_file set';
    is $ua->ssl_opts('verify_hostname'), 1, 'verify_hostname=1';
};

# ---------------------------------------------------------------------------
# 1c. Preemptive HTTP Basic auth
#
# Regression guard: the client MUST attach an Authorization: Basic header to
# every request up front rather than relying on $ua->credentials()
# challenge-response, which silently sends nothing when QuantaStor issues no
# 401 challenge (or one whose realm doesn't match) — surfacing as a misleading
# "[err=26] Authentication check failed" despite correct credentials.
# ---------------------------------------------------------------------------

subtest 'preemptive Authorization: Basic header is set on the real UA' => sub {
    use MIME::Base64 qw(decode_base64);

    my $client = PVE::Storage::QuantaStor::APIClient->new(
        host => 'x', username => 'admin', password => 's3cr3t',
    );
    my $ua = $client->_ua;

    my $hdr = $ua->default_header('Authorization');
    ok defined $hdr && length $hdr, 'Authorization header is present';
    like $hdr, qr/^Basic \S+$/, 'header is Basic <token>';

    (my $token = $hdr) =~ s/^Basic //;
    is decode_base64($token), 'admin:s3cr3t', 'token decodes to user:pass';

    # The token must be a single unbroken line — encode_base64 inserts a
    # newline every 76 chars by default, which would corrupt the header for
    # long credentials. The second arg to encode_base64 ('') suppresses it.
    unlike $token, qr/\s/, 'token contains no embedded whitespace/newlines';
};

subtest 'long credentials produce a single-line token' => sub {
    my $long = 'p' x 200;   # long enough to trip encode_base64's 76-char wrap
    my $client = PVE::Storage::QuantaStor::APIClient->new(
        host => 'x', username => 'admin', password => $long,
    );
    my $hdr = $client->_ua->default_header('Authorization');
    unlike $hdr, qr/\n/, 'no newline in header even for long passwords';
};

# ---------------------------------------------------------------------------
# 2. pool_get
# ---------------------------------------------------------------------------

subtest 'pool_get returns pool data' => sub {
    my ($client, $ua) = make_client(
        storagePoolGet => { id => 'pool-uuid', name => 'tank', size => 2048, freeSpace => 1024 },
    );

    my $pool = $client->pool_get('pool-uuid');
    is $pool->{id},        'pool-uuid', 'pool id';
    is $pool->{name},      'tank',      'pool name';
    is $pool->{size},      2048,        'pool size';
    is $pool->{freeSpace}, 1024,        'pool freeSpace';

    ok $ua->was_called('storagePoolGet'), 'called storagePoolGet';
    my $params = $ua->params_for('storagePoolGet');
    is $params->{storagePool}, 'pool-uuid', 'passed storagePool param';
};

subtest 'pool_get requires pool_id' => sub {
    my ($client) = make_client();
    eval { $client->pool_get('') };
    like $@, qr/pool_id.*required/i, 'dies with empty pool_id';
};

subtest 'pool_get dies on HTTP error' => sub {
    my ($client) = make_client(
        storagePoolGet => { _http_error => '500 Internal Server Error' },
    );
    eval { $client->pool_get('pool-uuid') };
    like $@, qr/failed.*500/i, 'dies with HTTP error message';
};

subtest 'pool_enum returns array' => sub {
    my ($client) = make_client(storagePoolEnum => [
        { name => 'pool-1', id => 'uuid-1', status => 'ONLINE', isActive => $true},
        { name => 'pool-2', id => 'uuid-2', status => 'ONLINE', isActive => $true},
    ]);
    my $result = $client->pool_enum();
    is ref($result), 'ARRAY', 'returns arrayref';
    is scalar @$result, 2, 'two pools returned';
    is $result->[0]{name}, 'pool-1', 'first pool name';
};

# ---------------------------------------------------------------------------
# 3. volume_enum
# ---------------------------------------------------------------------------

subtest 'volume_enum returns list' => sub {
    my @vols = (
        { id => 'v1', name => 'vm-100-disk-0', size => 10240, storagePoolId => 'pool-uuid' },
        { id => 'v2', name => 'vm-101-disk-0', size => 20480, storagePoolId => 'pool-uuid' },
    );
    my ($client, $ua) = make_client(storageVolumeEnum => \@vols);

    my $result = $client->volume_enum();
    is scalar @$result, 2, 'returns 2 volumes';
    is $result->[0]{name}, 'vm-100-disk-0', 'first volume name';
    is $result->[1]{name}, 'vm-101-disk-0', 'second volume name';

    ok $ua->was_called('storageVolumeEnum'), 'called storageVolumeEnum';
};

# ---------------------------------------------------------------------------
# 4. volume_get
# ---------------------------------------------------------------------------

subtest 'volume_get returns volume object' => sub {
    my $vol = { id => 'v1', name => 'vm-100-disk-0', iqn => 'iqn.2009-10.com.osnexus:p:vm-100-disk-0' };
    my ($client, $ua) = make_client(storageVolumeGet => $vol);

    my $result = $client->volume_get('vm-100-disk-0');
    is $result->{id},   'v1',          'volume id';
    is $result->{name}, 'vm-100-disk-0', 'volume name';
    is $result->{iqn},  'iqn.2009-10.com.osnexus:p:vm-100-disk-0', 'volume iqn';

    my $params = $ua->params_for('storageVolumeGet');
    is $params->{storageVolume}, 'vm-100-disk-0', 'passed storageVolume param';
};

subtest 'volume_get requires vol' => sub {
    my ($client) = make_client();
    eval { $client->volume_get('') };
    like $@, qr/vol.*required/i, 'dies with empty vol';
};

subtest 'volume_get surfaces API RestError' => sub {
    my ($client) = make_client(
        storageVolumeGet => { RestError => 'Volume not found' },
    );
    eval { $client->volume_get('no-such-vol') };
    like $@, qr/Volume not found/, 'API error propagated';
};

subtest 'volume_get_or_undef returns undef on QS not-found error' => sub {
    my ($client) = make_client(
        storageVolumeGet => { RestError =>
            'WebFault(Server raised fault: _fault_Specified StorageVolume object vm-99-disk-0 could not be found. [err=5]_/fault_)' },
    );
    my $vol = $client->volume_get_or_undef('vm-99-disk-0');
    is $vol, undef, 'returns undef when QS reports volume missing';
};

subtest 'volume_get_or_undef returns volume when present' => sub {
    my ($client) = make_client(
        storageVolumeGet => { id => 'vol-uuid', name => 'vm-100-disk-0' },
    );
    my $vol = $client->volume_get_or_undef('vm-100-disk-0');
    is $vol->{id}, 'vol-uuid', 'returns the volume hash';
};

subtest 'volume_get_or_undef propagates non-not-found errors' => sub {
    my ($client) = make_client(
        storageVolumeGet => { RestError => 'Authentication failed' },
    );
    eval { $client->volume_get_or_undef('vm-100-disk-0') };
    like $@, qr/Authentication failed/, 'non-not-found errors still die';
};

subtest 'volume_get falls back to pool-scoped enum on multiple matches' => sub {
    my $ua = Test::QuantaStor::MockUA->new(responses => {
        storageVolumeGet  => { RestError => 'multiple matches found for specified query' },
        storagePoolGet    => { id => 'pool-uuid-1' },
        storageVolumeEnum => [
            { id => 'vol-in-pool-1', name => 'vm-100-disk-0', storagePoolId => 'pool-uuid-1' },
            { id => 'vol-in-pool-2', name => 'vm-100-disk-0', storagePoolId => 'pool-uuid-2' },
        ],
    });
    my $client = PVE::Storage::QuantaStor::APIClient->new(
        host => '10.0.0.1', username => 'admin', password => 'secret',
        pool_id => 'pool-uuid-1',
        _ua => $ua,
    );
    my $vol = $client->volume_get('vm-100-disk-0');
    is $vol->{id}, 'vol-in-pool-1', 'returns volume from correct pool';
};

subtest 'volume_get_or_undef returns undef when name collides across pools but is absent from ours' => sub {
    # storageVolumeGet says "multiple matches" (name exists elsewhere), but the
    # pool-scoped enum finds no match in OUR pool. The idempotent delete path
    # must treat this as not-found, not hard-die.
    my $ua = Test::QuantaStor::MockUA->new(responses => {
        storageVolumeGet  => { RestError => 'multiple matches found for specified query' },
        storagePoolGet    => { id => 'pool-uuid-1' },
        storageVolumeEnum => [
            { id => 'vol-in-pool-2', name => 'vm-100-disk-0', storagePoolId => 'pool-uuid-2' },
        ],
    });
    my $client = PVE::Storage::QuantaStor::APIClient->new(
        host => '10.0.0.1', username => 'admin', password => 'secret',
        pool_id => 'pool-uuid-1',
        _ua => $ua,
    );
    my $vol = $client->volume_get_or_undef('vm-100-disk-0');
    is $vol, undef, 'returns undef (not a die) for cross-pool absent volume';
};

# ---------------------------------------------------------------------------
# 5. volume_create
# ---------------------------------------------------------------------------

subtest 'volume_create sends correct params' => sub {
    my $new_vol = { id => 'new-uuid', name => 'vm-100-disk-0' };
    my ($client, $ua) = make_client(storageVolumeCreate => $new_vol);

    my $result = $client->volume_create('vm-100-disk-0', 10240, 'pool-uuid');
    is $result->{id},   'new-uuid',     'returned new volume id';
    is $result->{name}, 'vm-100-disk-0', 'returned new volume name';

    my $params = $ua->params_for('storageVolumeCreate');
    is $params->{name},            'vm-100-disk-0',        'name param';
    is $params->{size},            10240 * 1024,           'size converted KB->bytes';
    is $params->{provisionableId}, 'pool-uuid',            'pool param';
    like $params->{description},   qr/Proxmox/,            'description set';
};

subtest 'volume_create requires name' => sub {
    my ($client) = make_client();
    eval { $client->volume_create('', 1024, 'pool') };
    like $@, qr/name.*required/i, 'dies without name';
};

subtest 'volume_create requires positive size' => sub {
    my ($client) = make_client();
    eval { $client->volume_create('vol', 0, 'pool') };
    like $@, qr/size_kb.*required/i, 'dies with zero size';
};

subtest 'volume_create accepts custom description' => sub {
    my ($client, $ua) = make_client(
        storageVolumeCreate => { id => 'x', name => 'vol' },
    );
    $client->volume_create('vol', 1024, 'pool', description => 'My Volume');
    my $params = $ua->params_for('storageVolumeCreate');
    is $params->{description}, 'My Volume', 'custom description used';
};

# ---------------------------------------------------------------------------
# 6. volume_delete
# ---------------------------------------------------------------------------

subtest 'volume_delete defaults to safe (non-force, non-cascade)' => sub {
    my ($client, $ua) = make_client(storageVolumeDelete => { status => 'ok' });

    $client->volume_delete('vol-uuid');

    my $params = $ua->params_for('storageVolumeDelete');
    is $params->{storageVolumeList}, 'vol-uuid', 'vol_id passed';
    is $params->{deleteOptions},     0,          'deleteOptions=0 (no cascade) by default';
    is $params->{flags},             0,          'flags=0 (no force) by default';
};

subtest 'volume_delete accepts destructive override' => sub {
    my ($client, $ua) = make_client(storageVolumeDelete => { status => 'ok' });
    $client->volume_delete('vol-uuid', delete_options => 4, flags => 2);
    my $params = $ua->params_for('storageVolumeDelete');
    is $params->{deleteOptions}, 4, 'cascade requested';
    is $params->{flags},         2, 'force requested';
};

# ---------------------------------------------------------------------------
# 7. volume_modify
# ---------------------------------------------------------------------------

subtest 'volume_modify sends correct params' => sub {
    my ($client, $ua) = make_client(
        storageVolumeModify => { id => 'v1', name => 'base-100-disk-0' },
    );

    $client->volume_modify('v1', 'base-100-disk-0');

    my $params = $ua->params_for('storageVolumeModify');
    is $params->{storageVolume}, 'v1',             'vol_id passed';
    is $params->{newName},       'base-100-disk-0', 'new name passed';
};

# ---------------------------------------------------------------------------
# 8. volume_snapshot
# ---------------------------------------------------------------------------

subtest 'volume_snapshot sends correct params' => sub {
    my ($client, $ua) = make_client(
        storageVolumeSnapshot => { id => 'snap-uuid' },
    );

    $client->volume_snapshot('vm-100-disk-0', 'vm-100-disk-0_snap1');

    my $params = $ua->params_for('storageVolumeSnapshot');
    is $params->{storageVolume}, 'vm-100-disk-0',       'vol_name passed';
    is $params->{snapshotName},  'vm-100-disk-0_snap1', 'snap_name passed';
};

# ---------------------------------------------------------------------------
# 9. volume_rollback
# ---------------------------------------------------------------------------

subtest 'volume_rollback sends correct params' => sub {
    my ($client, $ua) = make_client(
        storageVolumeRollback => { id => 'v1' },
    );

    $client->volume_rollback('v1-uuid', 'vm-100-disk-0_snap1');

    my $params = $ua->params_for('storageVolumeRollback');
    is $params->{storageVolume},  'v1-uuid',             'vol_id passed';
    is $params->{snapshotVolume}, 'vm-100-disk-0_snap1', 'snap_name passed';
};

# ---------------------------------------------------------------------------
# 10. volume_clone
# ---------------------------------------------------------------------------

subtest 'volume_clone sends correct params' => sub {
    my ($client, $ua) = make_client(
        storageVolumeClone => { obj => { id => 'clone-uuid', iqn => 'iqn.clone' } },
    );

    $client->volume_clone('template-base-100-disk-0', 'vm-102-disk-0');

    my $params = $ua->params_for('storageVolumeClone');
    is $params->{storageVolume}, 'template-base-100-disk-0', 'source vol passed';
    is $params->{cloneName},     'vm-102-disk-0',            'clone name passed';
};

# ---------------------------------------------------------------------------
# 11. volume_acl_add / volume_acl_remove
# ---------------------------------------------------------------------------

subtest 'volume_acl_add sends modType=0' => sub {
    my ($client, $ua) = make_client(
        storageVolumeAclAddRemoveEx => { status => 'ok' },
    );

    $client->volume_acl_add('vol-uuid', 'iqn.initiator');

    my $params = $ua->params_for('storageVolumeAclAddRemoveEx');
    is $params->{storageVolumeList}, 'vol-uuid',      'vol_id passed';
    is $params->{host},              'iqn.initiator', 'host_iqn passed';
    is $params->{modType},           0,               'modType=0 (add)';
};

subtest 'volume_acl_remove sends modType=1' => sub {
    my ($client, $ua) = make_client(
        storageVolumeAclAddRemoveEx => { status => 'ok' },
    );

    $client->volume_acl_remove('vol-uuid', 'host-uuid');

    my $params = $ua->params_for('storageVolumeAclAddRemoveEx');
    is $params->{modType}, 1, 'modType=1 (remove)';
};

# ---------------------------------------------------------------------------
# 12. session_enum
# ---------------------------------------------------------------------------

subtest 'session_enum returns session list' => sub {
    my @sessions = (
        { id => 's1', initiatorIQN => 'iqn.host1' },
    );
    my ($client, $ua) = make_client(sessionEnum => \@sessions);

    my $result = $client->session_enum('vm-100-disk-0');
    is scalar @$result, 1, 'one session returned';
    is $result->[0]{id}, 's1', 'session id';
};

subtest 'wait_for_session_gone returns 1 when sessions list is empty' => sub {
    my $ua = Test::QuantaStor::MockUA->new(responses => {
        sessionEnum => [],   # already empty
    });
    my $client = PVE::Storage::QuantaStor::APIClient->new(
        host => '10.0.0.1', username => 'admin', password => 'x',
        _ua  => $ua, _sleep => sub { },
    );
    is $client->wait_for_session_gone('vm-100-disk-0', 5), 1, 'returns 1 immediately';
};

subtest 'wait_for_session_gone returns 0 on timeout' => sub {
    my $ua = Test::QuantaStor::MockUA->new(responses => {
        sessionEnum => [ { id => 'session-uuid', initiatorIqn => 'iqn.foo' } ],
    });
    my $client = PVE::Storage::QuantaStor::APIClient->new(
        host => '10.0.0.1', username => 'admin', password => 'x',
        _ua  => $ua, _sleep => sub { },
    );
    is $client->wait_for_session_gone('vm-100-disk-0', 2), 0, 'returns 0 after timeout';
};

subtest 'wait_for_session_gone treats sessionEnum errors as still-active' => sub {
    # Simulate a sessionEnum error that doesn't match the "no sessions" pattern.
    # Should not propagate; just keep polling until timeout.
    my $ua = Test::QuantaStor::MockUA->new(responses => {
        sessionEnum => { RestError => 'Transient backend error' },
    });
    my $client = PVE::Storage::QuantaStor::APIClient->new(
        host => '10.0.0.1', username => 'admin', password => 'x',
        _ua  => $ua, _sleep => sub { },
    );
    is $client->wait_for_session_gone('vm-100-disk-0', 2), 0,
        'transient errors do not crash the wait';
};

subtest 'wait_for_session_gone requires vol_name' => sub {
    my ($client) = make_client();
    eval { $client->wait_for_session_gone('') };
    like $@, qr/vol_name.*required/i, 'dies with empty vol_name';
};

subtest 'session_enum returns empty arrayref when no sessions' => sub {
    my ($client) = make_client(sessionEnum => []);
    my $result = $client->session_enum('vm-100-disk-0');
    is ref $result, 'ARRAY', 'returns arrayref';
    is scalar @$result, 0,   'empty arrayref';
};

# ---------------------------------------------------------------------------
# 13. host_get
# ---------------------------------------------------------------------------

subtest 'host_get returns host when found' => sub {
    my $host = { id => 'host-uuid', name => 'pve-node1', iqn => 'iqn.pve' };
    my ($client, $ua) = make_client(hostGet => $host);

    my $result = $client->host_get('iqn.pve');
    is $result->{id},   'host-uuid', 'host id';
    is $result->{name}, 'pve-node1', 'host name';
};

subtest 'host_get returns undef when host not found' => sub {
    my ($client) = make_client(
        hostGet => { RestError => 'Failed to locate host with IQN iqn.x' },
    );
    my $result = $client->host_get('iqn.x');
    is $result, undef, 'returns undef for missing host';
};

subtest 'host_get propagates non-NotFound errors' => sub {
    my ($client) = make_client(
        hostGet => { RestError => 'Authentication failure' },
    );
    eval { $client->host_get('iqn.x') };
    like $@, qr/Authentication failure/, 'non-404 error propagated';
};

# ---------------------------------------------------------------------------
# 14. host_add
# ---------------------------------------------------------------------------

subtest 'host_add sends correct params' => sub {
    my ($client, $ua) = make_client(
        hostAdd => { obj => { id => 'new-host-uuid' } },
    );

    $client->host_add('pve-node1', 'iqn.pve.node1');

    my $params = $ua->params_for('hostAdd');
    is $params->{hostname}, 'pve-node1',    'hostname passed';
    is $params->{iqn},      'iqn.pve.node1', 'iqn passed';
    like $params->{description}, qr/Proxmox/, 'description set';
};

# ---------------------------------------------------------------------------
# 15. ensure_host_registered
# ---------------------------------------------------------------------------

subtest 'ensure_host_registered returns existing host id' => sub {
    my ($client) = make_client(
        hostGet => { id => 'existing-uuid', name => 'pve-node1' },
    );

    my $id = $client->ensure_host_registered('pve-node1', 'iqn.pve');
    is $id, 'existing-uuid', 'returns existing host id without calling hostAdd';
};

subtest 'ensure_host_registered creates new host when not found' => sub {
    my $ua = Test::QuantaStor::MockUA->new(responses => {
        hostGet => { RestError => 'Failed to locate host with IQN iqn.new' },
        hostAdd => { obj => { id => 'created-uuid' } },
    });
    my $client = PVE::Storage::QuantaStor::APIClient->new(
        host => '10.0.0.1', username => 'admin', password => 'x', _ua => $ua,
    );

    my $id = $client->ensure_host_registered('pve-node1', 'iqn.new');
    is $id, 'created-uuid', 'returns newly created host id';
    ok $ua->was_called('hostAdd'), 'hostAdd was called';
};

# ---------------------------------------------------------------------------
# 16. Logger injection
# ---------------------------------------------------------------------------

subtest 'logger is called with level and message' => sub {
    my @log_entries;
    my $ua = Test::QuantaStor::MockUA->new(responses => {
        storagePoolGet => { id => 'p', size => 100, freeSpace => 50 },
    });
    my $client = PVE::Storage::QuantaStor::APIClient->new(
        host     => '10.0.0.1',
        username => 'admin',
        password => 'x',
        _ua      => $ua,
        logger   => sub { push @log_entries, [@_] },
    );

    $client->pool_get('p');
    ok scalar @log_entries > 0, 'logger was called';
    is $log_entries[0][0], 'debug', 'first arg is level';
    like $log_entries[0][1], qr/storagePoolGet/, 'second arg contains method name';
};

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------

done_testing();
