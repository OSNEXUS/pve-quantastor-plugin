#!/usr/bin/perl
use strict;
use warnings;

use FindBin qw($Bin);
use lib "$Bin/../src/perl5";
use lib "$Bin/lib";

use Test::More;
use File::Temp qw(tempdir);
use File::Path qw(make_path);
use Test::QuantaStor::MockCmdRunner;
use PVE::Storage::QuantaStor::FCManager;

my $CLASS = 'PVE::Storage::QuantaStor::FCManager';

# ---------------------------------------------------------------------------
# Fixture: a fake /sys and /dev tree in a temp directory.
#   fc_hosts   => { host3 => '0x21000024ff0a0b0c', ... }
#   sd         => { sda => 'naa.6200000011112222333344445555aaaa', ... }
#   byid       => [ 'scsi-3620...', 'dm-uuid-mpath-3620...' ]
# ---------------------------------------------------------------------------

sub write_file {
    my ($path, $content) = @_;
    open my $fh, '>', $path or die "write $path: $!";
    print $fh $content;
    close $fh;
}

sub make_tree {
    my (%f) = @_;
    my $root  = tempdir(CLEANUP => 1);
    my $sysfs = "$root/sys";
    my $dev   = "$root/dev";
    make_path("$sysfs/class/fc_host", "$sysfs/class/scsi_host", "$sysfs/block", "$dev/disk/by-id");

    for my $h (sort keys %{ $f{fc_hosts} // {} }) {
        make_path("$sysfs/class/fc_host/$h", "$sysfs/class/scsi_host/$h");
        write_file("$sysfs/class/fc_host/$h/port_name", $f{fc_hosts}{$h} . "\n");
        write_file("$sysfs/class/scsi_host/$h/scan", '');
    }
    for my $sd (sort keys %{ $f{sd} // {} }) {
        make_path("$sysfs/block/$sd/device");
        write_file("$sysfs/block/$sd/device/wwid",   $f{sd}{$sd} . "\n");
        write_file("$sysfs/block/$sd/device/delete", '');
        write_file("$sysfs/block/$sd/device/rescan", '');
    }
    for my $link (@{ $f{byid} // [] }) {
        write_file("$dev/disk/by-id/$link", '');
    }
    return ($root, $sysfs, $dev);
}

sub make_manager {
    my ($sysfs, $dev, %runner_responses) = @_;
    my $runner = Test::QuantaStor::MockCmdRunner->new(responses => \%runner_responses);
    my $mgr = $CLASS->new(
        _sysfs_root => $sysfs,
        _dev_root   => $dev,
        _run_cmd    => $runner->as_coderef,
        _sleep      => sub { },
    );
    return ($mgr, $runner);
}

my $DESC = '0123456789abcdef01234567';                  # 24 hex, as QuantaStor emits
my $WWID = '3' . '62000000' . $DESC;                    # Linux WWID of the NAA
my $VOL  = { id => 'vol-1', name => 'vm-100-disk-0', deviceDescriptor => $DESC };

# ---------------------------------------------------------------------------
# 1. WWPN normalisation
# ---------------------------------------------------------------------------

subtest 'normalize_wwpn accepts every common spelling' => sub {
    is $CLASS->normalize_wwpn('0x21000024FF0A0B0C'),        '21000024ff0a0b0c', 'sysfs 0x form';
    is $CLASS->normalize_wwpn('21:00:00:24:ff:0a:0b:0c'),   '21000024ff0a0b0c', 'colon form';
    is $CLASS->normalize_wwpn(" 21000024ff0a0b0c\n"),       '21000024ff0a0b0c', 'whitespace trimmed';
    eval { $CLASS->normalize_wwpn('21000024ff') };
    like $@, qr/not a 16-digit WWPN/, 'short value rejected';
    eval { $CLASS->normalize_wwpn('') };
    like $@, qr/required/, 'empty rejected';
};

# ---------------------------------------------------------------------------
# 2. Initiator identity
# ---------------------------------------------------------------------------

subtest 'initiator_ids returns every HBA port WWPN, sorted and normalised' => sub {
    my ($root, $sysfs, $dev) = make_tree(
        fc_hosts => { host5 => '0x21000024ff0a0b0d', host3 => '0x21000024ff0a0b0c' });
    my ($mgr) = make_manager($sysfs, $dev);
    is_deeply [ $mgr->initiator_ids() ], [ '21000024ff0a0b0c', '21000024ff0a0b0d' ], 'two WWPNs';
    is $mgr->initiator_id(), '21000024ff0a0b0c', 'primary is the first';
};

subtest 'initiator_ids dies when the node has no FC HBA' => sub {
    my ($root, $sysfs, $dev) = make_tree();
    my ($mgr) = make_manager($sysfs, $dev);
    eval { $mgr->initiator_ids() };
    like $@, qr/no Fibre Channel HBA found/, 'actionable error';
};

# ---------------------------------------------------------------------------
# 3. Volume identity
# ---------------------------------------------------------------------------

subtest 'wwid derives the NAA-based Linux WWID from deviceDescriptor' => sub {
    my ($root, $sysfs, $dev) = make_tree();
    my ($mgr) = make_manager($sysfs, $dev);
    is $mgr->wwid($VOL), $WWID, 'wwid = 3 + 62000000 + descriptor';
    is $mgr->wwid({ deviceDescriptor => uc $DESC }), $WWID, 'descriptor case folded';
    ok $mgr->is_exported($VOL), 'is_exported true with descriptor';
    ok !$mgr->is_exported({ iqn => 'iqn.x' }), 'is_exported false without descriptor';
    eval { $mgr->wwid({ name => 'v', deviceDescriptor => 'abc' }) };
    like $@, qr/no 24-character deviceDescriptor/, 'bad descriptor rejected';
};

subtest 'volume_device_path prefers the multipath map, falls back to single path' => sub {
    my ($root, $sysfs, $dev) = make_tree(byid => [ "scsi-$WWID", "dm-uuid-mpath-$WWID" ]);
    my ($mgr) = make_manager($sysfs, $dev);
    is $mgr->volume_device_path($VOL), "$dev/disk/by-id/dm-uuid-mpath-$WWID", 'multipath map wins';
    ok $mgr->is_attached($VOL), 'attached';

    unlink "$dev/disk/by-id/dm-uuid-mpath-$WWID";
    is $mgr->volume_device_path($VOL), "$dev/disk/by-id/scsi-$WWID", 'single path when no map';

    unlink "$dev/disk/by-id/scsi-$WWID";
    is $mgr->volume_device_path($VOL), "$dev/disk/by-id/scsi-$WWID", 'expected path reported when absent';
    ok !$mgr->is_attached($VOL), 'not attached';
};

# ---------------------------------------------------------------------------
# 4. attach / wait_for_attached
# ---------------------------------------------------------------------------

subtest 'attach rescans every FC HBA' => sub {
    my ($root, $sysfs, $dev) = make_tree(
        fc_hosts => { host3 => '0x21000024ff0a0b0c', host5 => '0x21000024ff0a0b0d' });
    my ($mgr) = make_manager($sysfs, $dev);
    ok $mgr->attach($VOL), 'attach returns true';
    for my $h (qw(host3 host5)) {
        open my $fh, '<', "$sysfs/class/scsi_host/$h/scan" or die $!;
        my $c = do { local $/; <$fh> };
        is $c, '- - -', "$h scanned with wildcard";
    }
};

subtest 'attach is a no-op when the LUN is already visible' => sub {
    my ($root, $sysfs, $dev) = make_tree(
        fc_hosts => { host3 => '0x21000024ff0a0b0c' }, byid => [ "scsi-$WWID" ]);
    my ($mgr) = make_manager($sysfs, $dev);
    ok $mgr->attach($VOL), 'returns true';
    open my $fh, '<', "$sysfs/class/scsi_host/host3/scan" or die $!;
    my $c = do { local $/; <$fh> };
    is $c, '', 'no scan issued';
};

subtest 'wait_for_attached polls until the by-id link appears' => sub {
    my ($root, $sysfs, $dev) = make_tree(fc_hosts => { host3 => '0x21000024ff0a0b0c' });
    my $polls = 0;
    my $mgr = $CLASS->new(
        _sysfs_root => $sysfs, _dev_root => $dev,
        _path_exists => sub { ++$polls >= 3 ? 1 : 0 },
        _sleep => sub { },
    );
    ok $mgr->wait_for_attached($VOL, 10), 'device appeared';
    ok $polls >= 3, 'polled more than once';

    my $never = $CLASS->new(_sysfs_root => $sysfs, _dev_root => $dev,
        _path_exists => sub { 0 }, _sleep => sub { });
    ok !$never->wait_for_attached($VOL, 3), 'timeout returns false';
};

# ---------------------------------------------------------------------------
# 5. detach / wait_for_detached
# ---------------------------------------------------------------------------

subtest 'detach flushes the multipath map and deletes each SCSI path' => sub {
    my ($root, $sysfs, $dev) = make_tree(
        fc_hosts => { host3 => '0x21000024ff0a0b0c' },
        sd   => { sdb => "naa.62000000$DESC", sdc => "naa.62000000$DESC", sda => 'naa.6200000000000000000000000000ffff' },
        byid => [ "dm-uuid-mpath-$WWID" ]);
    my ($mgr, $runner) = make_manager($sysfs, $dev);
    ok $mgr->detach($VOL), 'something was detached';
    ok $runner->was_called("-f $WWID"), 'multipath -f <wwid> issued';
    for my $sd (qw(sdb sdc)) {
        open my $fh, '<', "$sysfs/block/$sd/device/delete" or die $!;
        is scalar(do { local $/; <$fh> }), '1', "$sd deleted";
    }
    open my $fh, '<', "$sysfs/block/sda/device/delete" or die $!;
    is scalar(do { local $/; <$fh> }), '', 'unrelated LUN untouched';
};

subtest 'detach without a multipath map skips the flush' => sub {
    my ($root, $sysfs, $dev) = make_tree(sd => { sdb => "naa.62000000$DESC" });
    my ($mgr, $runner) = make_manager($sysfs, $dev);
    ok $mgr->detach($VOL), 'detached';
    is $runner->call_count, 0, 'no multipath command';
};

subtest 'detach is a no-op when nothing is attached' => sub {
    my ($root, $sysfs, $dev) = make_tree();
    my ($mgr, $runner) = make_manager($sysfs, $dev);
    is $mgr->detach($VOL), 0, 'returns 0';
    is $runner->call_count, 0, 'no commands';
};

subtest 'wait_for_detached returns once paths and links are gone' => sub {
    my ($root, $sysfs, $dev) = make_tree(sd => { sdb => "naa.62000000$DESC" }, byid => [ "scsi-$WWID" ]);
    my ($mgr) = make_manager($sysfs, $dev);
    ok !$mgr->wait_for_detached($VOL, 4), 'times out while the path remains';
    unlink "$dev/disk/by-id/scsi-$WWID";
    ok !$mgr->wait_for_detached($VOL, 4), 'still attached while /sys/block entry remains';
    unlink "$sysfs/block/sdb/device/wwid";
    ok $mgr->wait_for_detached($VOL, 4), 'gone';
};

# ---------------------------------------------------------------------------
# 6. rescan_volume
# ---------------------------------------------------------------------------

subtest 'rescan_volume rescans each path and resizes the multipath map' => sub {
    my ($root, $sysfs, $dev) = make_tree(
        sd => { sdb => "naa.62000000$DESC", sdc => "naa.62000000$DESC" },
        byid => [ "dm-uuid-mpath-$WWID" ]);
    my ($mgr, $runner) = make_manager($sysfs, $dev);
    ok $mgr->rescan_volume($VOL), 'rescan ok';
    for my $sd (qw(sdb sdc)) {
        open my $fh, '<', "$sysfs/block/$sd/device/rescan" or die $!;
        is scalar(do { local $/; <$fh> }), '1', "$sd rescanned";
    }
    ok $runner->was_called("resize map $WWID"), 'multipathd resize map issued';
};

subtest 'rescan_volume is a no-op when the LUN is not attached' => sub {
    my ($root, $sysfs, $dev) = make_tree();
    my ($mgr, $runner) = make_manager($sysfs, $dev);
    is $mgr->rescan_volume($VOL), 0, 'returns 0';
    is $runner->call_count, 0, 'no commands';
};

subtest 'contract helpers' => sub {
    my ($root, $sysfs, $dev) = make_tree();
    my ($mgr) = make_manager($sysfs, $dev);
    is $mgr->transport_name, 'fc', 'transport_name';
    like $mgr->missing_device_hint, qr/zoning/, 'hint mentions zoning';
};

# ---------------------------------------------------------------------------
# add_map: an HA standby node maps the LUN a moment after the owner
# ---------------------------------------------------------------------------

subtest 'add_map rescans until every target port has a path' => sub {
    my ($root, $sysfs, $dev) = make_tree(
        fc_hosts => { host1 => '0x21000024ff0a0b0c' },
        sd       => { sdg => "naa.62000000$DESC" },          # owner's path only
        byid     => [ "dm-uuid-mpath-$WWID" ],
    );
    for my $rp (qw(rport-1:0-0 rport-1:0-1)) {
        make_path("$sysfs/class/fc_remote_ports/$rp");
        write_file("$sysfs/class/fc_remote_ports/$rp/roles",      "FCP Target\n");
        write_file("$sysfs/class/fc_remote_ports/$rp/port_state", "Online\n");
    }
    my ($mgr, $runner) = make_manager($sysfs, $dev);
    my $sleeps = 0;
    $mgr->{_sleep} = sub {
        # The standby path shows up a few seconds in.
        if (++$sleeps == 3) {
            make_path("$sysfs/block/sdi/device");
            write_file("$sysfs/block/sdi/device/wwid", "naa.62000000$DESC\n");
        }
    };
    ok $mgr->add_map($WWID), 'map ready';
    cmp_ok $sleeps, '>=', 3, 'waited for the standby path instead of returning at the first';
    is((() = $mgr->_paths_for($WWID)), 2, 'both paths present');
};

subtest 'add_map returns with a warning when a path never appears' => sub {
    my ($root, $sysfs, $dev) = make_tree(
        fc_hosts => { host1 => '0x21000024ff0a0b0c' },
        sd       => { sdg => "naa.62000000$DESC" },
        byid     => [ "dm-uuid-mpath-$WWID" ],
    );
    for my $rp (qw(rport-1:0-0 rport-1:0-1)) {
        make_path("$sysfs/class/fc_remote_ports/$rp");
        write_file("$sysfs/class/fc_remote_ports/$rp/roles",      "FCP Target\n");
        write_file("$sysfs/class/fc_remote_ports/$rp/port_state", "Online\n");
    }
    my ($mgr) = make_manager($sysfs, $dev);
    my @log;
    $mgr->{logger} = sub { push @log, [@_] };
    ok $mgr->add_map($WWID, 6), 'usable map still returned';
    ok scalar(grep { $_->[1] =~ /has 1 of 2 paths/ } @log), 'missing path reported';
};

subtest 'detach deletes the SCSI devices under perl -T (vzdump runs tainted)' => sub {
    my ($root, $sysfs, $dev) = make_tree(sd => { sdk => "naa.62000000$DESC" });
    my $lib = "$Bin/../src/perl5";
    my $code = q{
        use PVE::Storage::QuantaStor::FCManager;
        my ($sysfs, $dev, $desc) = @ARGV;
        my $m = PVE::Storage::QuantaStor::FCManager->new(
            _sysfs_root => $sysfs, _dev_root => $dev,
            _run_cmd => sub { }, _sleep => sub { },
            logger => sub { print STDERR "$_[1]\n" if $_[0] eq 'warning' });
        $m->detach({ name => 'v', deviceDescriptor => $desc });
    };
    my $out = `$^X -T -I$lib -e '$code' '$sysfs' '$dev' '$DESC' 2>&1`;
    unlike $out, qr/failed|Insecure/, 'no taint failure' or diag $out;
    open my $fh, '<', "$sysfs/block/sdk/device/delete" or die $!;
    is scalar(<$fh>), '1', 'device/delete written';
};

done_testing();
