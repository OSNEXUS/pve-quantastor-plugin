#!/usr/bin/perl
use strict;
use warnings;

use FindBin qw($Bin);
use lib "$Bin/../src/perl5";
use lib "$Bin/lib";

use Test::More;
use File::Temp qw(tempfile);
use Test::QuantaStor::MockCmdRunner;
use PVE::Storage::QuantaStor::ISCSIManager;

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Returns (ISCSIManager, MockCmdRunner) wired together.
# Pass %runner_responses to configure command outcomes.
sub make_manager {
    my (%runner_responses) = @_;

    my $runner = Test::QuantaStor::MockCmdRunner->new(
        responses => \%runner_responses,
    );

    my $mgr = PVE::Storage::QuantaStor::ISCSIManager->new(
        portal   => '10.0.0.1',
        _run_cmd => $runner->as_coderef,
    );

    return ($mgr, $runner);
}

# Write a temporary initiatorname.iscsi file and return its path.
sub temp_initiator_file {
    my ($iqn) = @_;
    my ($fh, $path) = tempfile(UNLINK => 1);
    print $fh "## iSCSI Initiator Name\n";
    print $fh "InitiatorName=$iqn\n";
    close $fh;
    return $path;
}

# ---------------------------------------------------------------------------
# 1. Constructor validation
# ---------------------------------------------------------------------------

subtest 'constructor requires portal' => sub {
    eval { PVE::Storage::QuantaStor::ISCSIManager->new() };
    like $@, qr/portal.*required/i, 'dies without portal';
};

subtest 'constructor stores portal' => sub {
    my ($mgr) = make_manager();
    is $mgr->{portal}, '10.0.0.1', 'portal stored';
};

subtest 'constructor uses default initiator file path' => sub {
    my ($mgr) = make_manager();
    is $mgr->{_initiator_file}, '/etc/iscsi/initiatorname.iscsi', 'default path';
};

subtest 'constructor accepts custom initiator file path' => sub {
    my $path = temp_initiator_file('iqn.test');
    my $mgr = PVE::Storage::QuantaStor::ISCSIManager->new(
        portal          => '10.0.0.1',
        _initiator_file => $path,
    );
    is $mgr->{_initiator_file}, $path, 'custom path stored';
};

# ---------------------------------------------------------------------------
# 2. get_initiator_iqn
# ---------------------------------------------------------------------------

subtest 'get_initiator_iqn reads IQN from file' => sub {
    my $expected = 'iqn.1993-08.org.debian:01:aabbccddeeff';
    my $path = temp_initiator_file($expected);

    my $mgr = PVE::Storage::QuantaStor::ISCSIManager->new(
        portal          => '10.0.0.1',
        _initiator_file => $path,
    );

    is $mgr->get_initiator_iqn(), $expected, 'IQN read correctly';
};

subtest 'get_initiator_iqn ignores comment lines' => sub {
    my ($fh, $path) = tempfile(UNLINK => 1);
    print $fh "# This is a comment\n";
    print $fh "## Another comment\n";
    print $fh "InitiatorName=iqn.2009-10.com.osnexus:node1\n";
    close $fh;

    my $mgr = PVE::Storage::QuantaStor::ISCSIManager->new(
        portal          => '10.0.0.1',
        _initiator_file => $path,
    );

    is $mgr->get_initiator_iqn(), 'iqn.2009-10.com.osnexus:node1', 'IQN found after comments';
};

subtest 'get_initiator_iqn dies when file missing' => sub {
    my $mgr = PVE::Storage::QuantaStor::ISCSIManager->new(
        portal          => '10.0.0.1',
        _initiator_file => '/nonexistent/path/initiatorname.iscsi',
    );
    eval { $mgr->get_initiator_iqn() };
    like $@, qr/Cannot open/, 'dies on missing file';
};

subtest 'get_initiator_iqn dies when no InitiatorName entry' => sub {
    my ($fh, $path) = tempfile(UNLINK => 1);
    print $fh "# Just comments, no InitiatorName\n";
    close $fh;

    my $mgr = PVE::Storage::QuantaStor::ISCSIManager->new(
        portal          => '10.0.0.1',
        _initiator_file => $path,
    );
    eval { $mgr->get_initiator_iqn() };
    like $@, qr/No InitiatorName found/, 'dies on empty file';
};

# ---------------------------------------------------------------------------
# 3. discover
# ---------------------------------------------------------------------------

subtest 'discover invokes iscsiadm discovery' => sub {
    my ($mgr, $runner) = make_manager(
        'discovery' => "10.0.0.1:3260,1 iqn.2009-10.com.osnexus:p:vol\n",
    );

    my $rc = $mgr->discover();
    is $rc, 1, 'returns 1 on success';
    ok $runner->was_called('discovery'), 'discovery command issued';
};

subtest 'discover returns 0 on failure (non-fatal)' => sub {
    my ($mgr, $runner) = make_manager(
        'discovery' => { _error => 'iscsiadm: No route to host' },
    );

    my $rc = $mgr->discover();
    is $rc, 0, 'returns 0 on failure without dying';
};

# ---------------------------------------------------------------------------
# 4. login
# ---------------------------------------------------------------------------

subtest 'login calls discovery then login' => sub {
    my ($mgr, $runner) = make_manager(
        'discovery'    => "10.0.0.1:3260,1 iqn.test\n",
        'node --login' => '',
    );

    my $rc = $mgr->login('iqn.2009-10.com.osnexus:pool:vm-100-disk-0');
    is $rc, 1, 'returns 1 on success';
    ok $runner->was_called('discovery'),    'discovery called';
    ok $runner->was_called('node --login'), 'login called';
};

subtest 'login verifies correct iscsiadm arguments' => sub {
    my ($mgr, $runner) = make_manager(
        'discovery'    => '',
        'node --login' => '',
    );

    $mgr->login('iqn.test:vm-100-disk-0');

    # Find the login call in the call log
    my ($login_call) = grep { $_->{sig} eq 'node --login' } @{ $runner->calls_made };
    ok $login_call, 'login call found in log';

    my @cmd = @{ $login_call->{cmd} };
    my %arg_map;
    for my $i (0..$#cmd) {
        if ($cmd[$i] =~ /^--/) {
            $arg_map{$cmd[$i]} = $cmd[$i+1] if $i+1 <= $#cmd;
        }
    }

    is $arg_map{'--targetname'}, 'iqn.test:vm-100-disk-0', '--targetname arg';
    is $arg_map{'--portal'},     '10.0.0.1',               '--portal arg';
};

subtest 'login dies on iscsiadm failure' => sub {
    my ($mgr, $runner) = make_manager(
        'discovery'    => '',
        'node --login' => { _error => 'iscsiadm: Could not login' },
    );

    eval { $mgr->login('iqn.test') };
    like $@, qr/iSCSI login failed/, 'dies on login failure';
};

subtest 'login is idempotent: skips iscsiadm --login when already logged in' => sub {
    my $target = 'iqn.2009-10.com.osnexus:pool:vm-100-disk-0';
    my ($mgr, $runner) = make_manager(
        'session' => "tcp: [1] 10.0.0.1:3260,1 $target (non-flash)\n",
    );

    my $rc = $mgr->login($target);
    is $rc, 1,                               'returns 1';
    ok !$runner->was_called('node --login'), 'iscsiadm --login not called when already logged in';
};

subtest 'login requires target_iqn' => sub {
    my ($mgr) = make_manager();
    eval { $mgr->login('') };
    like $@, qr/target_iqn.*required/i, 'dies with empty target_iqn';
};

# ---------------------------------------------------------------------------
# 5. logout
# ---------------------------------------------------------------------------

subtest 'logout invokes iscsiadm logout' => sub {
    my ($mgr, $runner) = make_manager('node --logout' => '');

    my $rc = $mgr->logout('iqn.test:vol');
    is $rc, 1, 'returns 1 on success';
    ok $runner->was_called('node --logout'), 'logout command issued';
};

subtest 'logout returns 0 on failure (non-fatal)' => sub {
    my ($mgr, $runner) = make_manager(
        'node --logout' => { _error => 'iscsiadm: No matching sessions' },
    );

    my $rc = $mgr->logout('iqn.test:vol');
    is $rc, 0, 'returns 0 without dying';
};

subtest 'logout requires target_iqn' => sub {
    my ($mgr) = make_manager();
    eval { $mgr->logout('') };
    like $@, qr/target_iqn.*required/i, 'dies with empty target_iqn';
};

# ---------------------------------------------------------------------------
# 6. is_logged_in
# ---------------------------------------------------------------------------

subtest 'is_logged_in returns 1 when IQN present in session list' => sub {
    my $target = 'iqn.2009-10.com.osnexus:pool:vm-100-disk-0';
    my ($mgr, $runner) = make_manager(
        'session' => "tcp: [1] 10.0.0.1:3260,1 $target (non-flash)\n",
    );

    is $mgr->is_logged_in($target), 1, 'returns 1 for active session';
};

subtest 'is_logged_in returns 0 when IQN absent from session list' => sub {
    my ($mgr, $runner) = make_manager(
        'session' => "tcp: [1] 10.0.0.1:3260,1 iqn.2009-10.com.osnexus:pool:vm-999-disk-0\n",
    );

    is $mgr->is_logged_in('iqn.2009-10.com.osnexus:pool:vm-100-disk-0'), 0,
        'returns 0 when not in session list';
};

subtest 'is_logged_in returns 0 when no sessions at all' => sub {
    my ($mgr, $runner) = make_manager(
        'session' => { _error => 'iscsiadm: No active sessions' },
    );

    is $mgr->is_logged_in('iqn.test'), 0, 'returns 0 when sessions command fails';
};

subtest 'is_logged_in requires target_iqn' => sub {
    my ($mgr) = make_manager();
    eval { $mgr->is_logged_in('') };
    like $@, qr/target_iqn.*required/i, 'dies with empty target_iqn';
};

# ---------------------------------------------------------------------------
# 7. device_path
# ---------------------------------------------------------------------------

subtest 'device_path returns stable by-path string' => sub {
    my ($mgr) = make_manager();

    my $path = $mgr->device_path('iqn.2009-10.com.osnexus:pool:vm-100-disk-0');
    is $path,
       '/dev/disk/by-path/ip-10.0.0.1:3260-iscsi-iqn.2009-10.com.osnexus:pool:vm-100-disk-0-lun-0',
       'correct by-path string for LUN 0';
};

subtest 'device_path accepts explicit lun number' => sub {
    my ($mgr) = make_manager();
    my $path = $mgr->device_path('iqn.test', 1);
    like $path, qr/-lun-1$/, 'lun number appended';
};

subtest 'device_path uses default 3260 when portal omits port' => sub {
    my $mgr = PVE::Storage::QuantaStor::ISCSIManager->new(
        portal => '10.0.0.1',
    );
    my $path = $mgr->device_path('iqn.test');
    like $path, qr{/ip-10\.0\.0\.1:3260-iscsi-}, 'default port 3260 used';
};

subtest 'device_path honors explicit portal port' => sub {
    my $mgr = PVE::Storage::QuantaStor::ISCSIManager->new(
        portal => '10.0.0.1:3261',
    );
    my $path = $mgr->device_path('iqn.test');
    like $path, qr{/ip-10\.0\.0\.1:3261-iscsi-}, 'configured port embedded';
};

subtest 'device_path uses standard port when portal includes :3260' => sub {
    my $mgr = PVE::Storage::QuantaStor::ISCSIManager->new(
        portal => '10.0.0.1:3260',
    );
    my $path = $mgr->device_path('iqn.test');
    like $path, qr{/ip-10\.0\.0\.1:3260-iscsi-}, 'host:3260 round-trips correctly';
};

subtest 'device_path requires target_iqn' => sub {
    my ($mgr) = make_manager();
    eval { $mgr->device_path('') };
    like $@, qr/target_iqn.*required/i, 'dies with empty target_iqn';
};

# ---------------------------------------------------------------------------
# 8. wait_for_logout
# ---------------------------------------------------------------------------

subtest 'wait_for_logout returns 1 immediately when not logged in' => sub {
    my ($mgr, $runner) = make_manager(
        # session command fails = no sessions
        'session' => { _error => 'iscsiadm: No active sessions' },
    );

    my $rc = $mgr->wait_for_logout('iqn.test', 10);
    is $rc, 1, 'returns 1 when already logged out';
    is $runner->call_count_for('session'), 1, 'session checked once';
};

subtest 'wait_for_logout returns 1 after session disappears' => sub {
    # Simulate: first check shows session active, second check shows it gone.
    my $call_count = 0;
    my $target = 'iqn.test:vm-100-disk-0';

    my $mgr = PVE::Storage::QuantaStor::ISCSIManager->new(
        portal   => '10.0.0.1',
        _run_cmd => sub {
            $call_count++;
            if ($call_count == 1) {
                # First call to 'session' — session still active
                return "tcp: [1] 10.0.0.1:3260,1 $target\n";
            } else {
                # Second call — session gone
                die "iscsiadm: No active sessions\n";
            }
        },
    );

    my $rc = $mgr->wait_for_logout($target, 10);
    is $rc, 1, 'returns 1 once session disappears';
    is $call_count, 2, 'polled twice';
};

subtest 'wait_for_logout returns 0 on timeout' => sub {
    my $target = 'iqn.test:persistent-vol';
    my $runner = Test::QuantaStor::MockCmdRunner->new(responses => {
        'session' => "tcp: [1] 10.0.0.1:3260,1 $target\n",
    });
    my $mgr = PVE::Storage::QuantaStor::ISCSIManager->new(
        portal   => '10.0.0.1',
        _run_cmd => $runner->as_coderef,
        _sleep   => sub { },
    );

    my $rc = $mgr->wait_for_logout($target, 2);
    is $rc, 0, 'returns 0 on timeout';
};

subtest 'wait_for_logout requires target_iqn' => sub {
    my ($mgr) = make_manager();
    eval { $mgr->wait_for_logout('') };
    like $@, qr/target_iqn.*required/i, 'dies with empty target_iqn';
};

# ---------------------------------------------------------------------------
# 8b. wait_for_device
# ---------------------------------------------------------------------------

subtest 'wait_for_device returns 1 when path exists immediately' => sub {
    my $mgr = PVE::Storage::QuantaStor::ISCSIManager->new(
        portal       => '10.0.0.1',
        _path_exists => sub { 1 },
    );
    is $mgr->wait_for_device('iqn.test', 0, 10), 1, 'returns 1 on first check';
};

subtest 'wait_for_device returns 1 once path appears mid-poll' => sub {
    my $checks = 0;
    my $mgr = PVE::Storage::QuantaStor::ISCSIManager->new(
        portal       => '10.0.0.1',
        _path_exists => sub { $checks++; $checks >= 3 ? 1 : 0 },
        _sleep       => sub { },
    );

    is $mgr->wait_for_device('iqn.test', 0, 10), 1, 'returns 1 once path appears';
    is $checks, 3, 'polled three times before success';
};

subtest 'wait_for_device returns 0 on timeout' => sub {
    my $mgr = PVE::Storage::QuantaStor::ISCSIManager->new(
        portal       => '10.0.0.1',
        _path_exists => sub { 0 },
        _sleep       => sub { },
    );

    is $mgr->wait_for_device('iqn.test', 0, 3), 0, 'returns 0 after timeout';
};

subtest 'wait_for_device requires target_iqn' => sub {
    my $mgr = PVE::Storage::QuantaStor::ISCSIManager->new(portal => '10.0.0.1');
    eval { $mgr->wait_for_device('') };
    like $@, qr/target_iqn.*required/i, 'dies with empty target_iqn';
};

# ---------------------------------------------------------------------------
# 9. Logger injection
# ---------------------------------------------------------------------------

subtest 'logger receives messages during login' => sub {
    my @entries;
    my $runner = Test::QuantaStor::MockCmdRunner->new(responses => {
        'discovery'    => '',
        'node --login' => '',
    });
    my $mgr = PVE::Storage::QuantaStor::ISCSIManager->new(
        portal   => '10.0.0.1',
        _run_cmd => $runner->as_coderef,
        logger   => sub { push @entries, [@_] },
    );

    $mgr->login('iqn.test');

    ok scalar @entries > 0, 'logger was called';
    my @levels = map { $_->[0] } @entries;
    ok grep { $_ eq 'info' || $_ eq 'debug' } @levels, 'log level is info or debug';
};

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------

done_testing();
