package PVE::Storage::QuantaStorPlugin;

use strict;
use warnings;

use IO::File;
use JSON qw(decode_json);
use HTTP::Request;
use LWP::UserAgent;
use URI::Escape;

use PVE::Tools qw(run_command file_read_firstline trim dir_glob_regex dir_glob_foreach);
use PVE::Storage::Plugin;
use PVE::JSONSchema qw(get_standard_option);
use POSIX qw(mkfifo strftime ENOENT);

use base qw(PVE::Storage::Plugin);

# Example usage
# eval {
#     my $server_ip    = '10.0.26.200';                      # Replace with your server IP
#     my $username     = 'admin';                           # Replace with your username
#     my $password     = 'password';                        # Replace with your password
#     my $api_name     = 'storageVolumeEnum';                # Replace with your API endpoint
#     my $query_params = {  };  # Updated argument value
#     my $cert_path    = '';      # Provide the path to a certificate or undef for no SSL verify
#     my $timeout      = 15;                                # Custom timeout value in seconds
# 
#     # Call the function
#     my $response_data = qs_api_call($server_ip, $username, $password, $api_name, $query_params, $cert_path, $timeout);
# 
#     # Prettify the response for output
#     my $pretty_result = to_json($response_data, { utf8 => 1, pretty => 1 });
#     print "Response:\n$pretty_result\n";
# };
# if ($@) {
#     warn "Error: $@\n";
# }

sub qs_api_call {
    PVE::Storage::QuantaStorPlugin::qs_write_to_log("QuantaStorPlugin - get_request");
    my ($server_ip, $username, $password, $api_name, $query_params, $cert_path, $timeout) = @_;

    # Set a default timeout if not provided
    $timeout //= 10;

    my $url = "https://$server_ip:8153/qstorapi/$api_name";

    # Add query parameters to the URL if provided
    if ($query_params && %$query_params) {
        my $query_string = join '&', map { uri_escape($_) . '=' . uri_escape($query_params->{$_}) } keys %$query_params;
        $url .= "?$query_string";
    }

    my $ua = LWP::UserAgent->new;

    # Set the timeout
    $ua->timeout($timeout);

    # Configure SSL options
    if ($cert_path) {
        # Use the provided certificate for SSL verification
        $ua->ssl_opts(
            SSL_ca_file     => $cert_path, # Path to the CA certificate
            verify_hostname => 1          # Enable hostname verification
        );
    } else {
        # Disable SSL verification
        $ua->ssl_opts(
            SSL_verify_mode => 0,         # Disable certificate verification
            verify_hostname => 0         # Disable hostname verification
        );
    }

    # Add headers
    $ua->default_header('Accept' => 'application/json');
    $ua->credentials("$server_ip:8153", "Proxmox API", $username, $password);

    # Prepare HTTP GET request
    print "URL: $url\n";
    my $response = $ua->get($url);
    return $response;
}

# Check response status
# if ($response->is_success) {
#     return decode_json($response->decoded_content); # Return raw Perl data structure
# } else {
#     print "Response content: " . $response->decoded_content . "\n";
#     die "HTTP GET Request failed: " . $response->status_line;
# }

sub qs_write_to_log {
    my ($msg) = @_;

    my $logfile = '/var/log/pve-quantastor-plugin.log';

    # Open the file in append mode
    if (open(my $fh, '>>', $logfile)) {
        print $fh "$msg\n";
        close($fh);
    } else {
        warn "Could not open log file '$logfile': $!";
    }
}

sub qs_ls {
    PVE::Storage::QuantaStorPlugin::qs_write_to_log("QuantaStorPlugin - qs_ls");
    my ($scfg, $storeid) = @_;

    my $portal = $scfg->{portal};
    my $list = {};
    my %unittobytes = (
       "k"  => 1024,
       "M" => 1024*1024,
       "G" => 1024*1024*1024,
       "T"   => 1024*1024*1024*1024
    );
    eval {


	    # $list->{$storeid}->{$image} = {
	    #     name => $image,
	    #     size => $size * $unittobytes{$unit},
		#     format => 'raw',
	    # };
    };

    #my $err = $@;
    #die $err if $err && $err !~ m/TESTUNITREADY failed with SENSE KEY/ ;

    return $list;

}

# Configuration

sub type {
    qs_write_to_log("QuantaStorPlugin - type");
    return 'quantastor';
}

sub plugindata {
    qs_write_to_log("QuantaStorPlugin - plugindata");
    return {
	content => [ {images => 1, none => 1}, { images => 1 }],
	select_existing => 1,
    };
}

sub properties {
    qs_write_to_log("QuantaStorPlugin - options");
    return {
	qStoragePoolId => {
	    description => "UUID to identify a QuantaStor Storage Pool.",
	    type => 'string',
	    maxLength => 256,
	},
    };
}

sub options {
    qs_write_to_log("QuantaStorPlugin - options");
    return {
	qStoragePoolId => { fixed => 1 },
	server => { fixed => 1 },
    username => { fixed => 1 },
	nodes => { optional => 1 },
	disable => { optional => 1 },
	bwlimit => { optional => 1 },
    path => { optional => 1},
	options => { optional => 1 },
    };
}

sub check_config {
    qs_write_to_log("QuantaStorPlugin - check_config");
    my ($class, $sectionId, $config, $create, $skipSchemaCheck) = @_;

    $config->{path} = "/mnt/pve/$sectionId" if $create && !$config->{path};

    return $class->SUPER::check_config($sectionId, $config, $create, $skipSchemaCheck);
}

# Storage implementation

sub qs_discovery {
    qs_write_to_log("QuantaStorPlugin - qs_discovery");
    my ($server, $username, $password) = @_;
    qs_write_to_log("QuantaStorPlugin - scanning... $server , $username , $password");

    my $res = {};

    return $res;
}

sub qs_set_credentials {
    qs_write_to_log("QuantaStorPlugin - qs_set_credentials");
    my ($password, $storeid) = @_;

    my $cred_file = qs_cred_file_name($storeid);
    mkdir "/etc/pve/priv/storage";

    PVE::Tools::file_set_contents($cred_file, "password=$password\n");

    return $cred_file;
}

sub qs_cred_file_name {
    qs_write_to_log("QuantaStorPlugin - qs_cred_file_name");
    my ($storeid) = @_;
    return "/etc/pve/priv/storage/${storeid}.pw";
}

sub qs_delete_credentials {
    qs_write_to_log("QuantaStorPlugin - qs_delete_credentials");
    my ($storeid) = @_;

    if (my $cred_file = get_cred_file($storeid)) {
	unlink($cred_file) or warn "removing cifs credientials '$cred_file' failed: $!\n";
    }
}

sub get_cred_file {
    my ($storeid) = @_;

    my $cred_file = qs_cred_file_name($storeid);

    if (-e $cred_file) {
	return $cred_file;
    }
    return undef;
}

sub on_update_hook {
    qs_write_to_log("QuantaStorPlugin - on_update_hook");
    my ($class, $storeid, $scfg, %sensitive) = @_;

    return if !exists($sensitive{password});

    if (defined($sensitive{password})) {
	qs_set_credentials($sensitive{password}, $storeid);
	if (!exists($scfg->{username})) {
	    warn "storage $storeid: ignoring password parameter, no user set\n";
	}
    } else {
	qs_delete_credentials($storeid);
    }

    return;
}

sub qs_password_file_name {
    qs_write_to_log("QuantaStorPlugin - qs_password_file_name");
    my ($scfg, $storeid) = @_;

    return "/etc/pve/priv/storage/${storeid}.pw";
}

sub qs_set_password {
    qs_write_to_log("QuantaStorPlugin - qs_set_password");
    my ($scfg, $storeid, $password) = @_;

    my $pwfile = qs_password_file_name($scfg, $storeid);
    mkdir "/etc/pve/priv/storage";

    PVE::Tools::file_set_contents($pwfile, "$password\n");
}

sub qs_delete_password {
    qs_write_to_log("QuantaStorPlugin - qs_delete_password");
    my ($scfg, $storeid) = @_;

    my $pwfile = qs_password_file_name($scfg, $storeid);

    unlink $pwfile;
}

sub qs_set_encryption_key {
    qs_write_to_log("QuantaStorPlugin - qs_set_encryption_key");
    my ($scfg, $storeid, $key) = @_;

    my $pwfile = qs_encryption_key_file_name($scfg, $storeid);
    mkdir "/etc/pve/priv/storage";

    PVE::Tools::file_set_contents($pwfile, "$key\n");
}

sub qs_delete_encryption_key {
    qs_write_to_log("QuantaStorPlugin - qs_delete_encryption_key");
    my ($scfg, $storeid) = @_;

    my $pwfile = qs_encryption_key_file_name($scfg, $storeid);

    if (!unlink $pwfile) {
	return if $! == ENOENT;
	die "failed to delete encryption key! $!\n";
    }
    delete $scfg->{'encryption-key'};
}

sub qs_master_pubkey_file_name {
    qs_write_to_log("QuantaStorPlugin - qs_master_pubkey_file_name");
    my ($scfg, $storeid) = @_;

    return "/etc/pve/priv/storage/${storeid}.master.pem";
}

sub qs_set_master_pubkey {
    qs_write_to_log("QuantaStorPlugin - qs_set_master_pubkey");
    my ($scfg, $storeid, $key) = @_;

    my $pwfile = qs_master_pubkey_file_name($scfg, $storeid);
    mkdir "/etc/pve/priv/storage";

    PVE::Tools::file_set_contents($pwfile, "$key\n");
}

sub qs_delete_master_pubkey {
    qs_write_to_log("QuantaStorPlugin - qs_delete_master_pubkey");
    my ($scfg, $storeid) = @_;

    my $pwfile = qs_master_pubkey_file_name($scfg, $storeid);

    if (!unlink $pwfile) {
	return if $! == ENOENT;
	die "failed to delete master public key! $!\n";
    }
    delete $scfg->{'master-pubkey'};
}

sub qs_encryption_key_file_name {
    qs_write_to_log("QuantaStorPlugin - qs_encryption_key_file_name");
    my ($scfg, $storeid) = @_;

    return "/etc/pve/priv/storage/${storeid}.enc";
}

my $autogen_encryption_key = sub {
    qs_write_to_log("QuantaStorPlugin - autogen_encryption_key");
    my ($scfg, $storeid) = @_;
    my $encfile = qs_encryption_key_file_name($scfg, $storeid);
    if (-f $encfile) {
	rename $encfile, "$encfile.old";
    }
    my $cmd = ['proxmox-backup-client', 'key', 'create', '--kdf', 'none', $encfile];
    run_command($cmd, errmsg => 'failed to create encryption key');
    return PVE::Tools::file_get_contents($encfile);
};

sub on_add_hook {
    qs_write_to_log("QuantaStorPlugin - on_add_hook");
    my ($class, $storeid, $scfg, %param) = @_;

    my $res = {};

    if (defined(my $password = $param{password})) {
	qs_set_password($scfg, $storeid, $password);
    } else {
	qs_delete_password($scfg, $storeid);
    }

    if (defined(my $encryption_key = $param{'encryption-key'})) {
	my $decoded_key;
	if ($encryption_key eq 'autogen') {
	    $res->{'encryption-key'} = $autogen_encryption_key->($scfg, $storeid);
	    $decoded_key = decode_json($res->{'encryption-key'});
	} else {
	    $decoded_key = eval { decode_json($encryption_key) };
	    if ($@ || !exists($decoded_key->{data})) {
		die "Value does not seems like a valid, JSON formatted encryption key!\n";
	    }
	    qs_set_encryption_key($scfg, $storeid, $encryption_key);
	    $res->{'encryption-key'} = $encryption_key;
	}
	$scfg->{'encryption-key'} = $decoded_key->{fingerprint} || 1;
    } else {
	qs_delete_encryption_key($scfg, $storeid);
    }

    if (defined(my $master_key = delete $param{'master-pubkey'})) {
	die "'master-pubkey' can only be used together with 'encryption-key'\n"
	    if !defined($scfg->{'encryption-key'});

	my $decoded = decode_base64($master_key);
	qs_set_master_pubkey($scfg, $storeid, $decoded);
	$scfg->{'master-pubkey'} = 1;
    } else {
	qs_delete_master_pubkey($scfg, $storeid);
    }

    return $res;
}

sub qs_test_portal {
    qs_write_to_log("QuantaStorPlugin - qs_test_portal");
    my ($portal) = @_;

    my ($server, $port) = PVE::Tools::parse_host_and_port($portal);
    return 0 if !$server;
    return PVE::Network::tcp_ping($server, $port || 3260, 2);
}

sub qs_portals {
    qs_write_to_log("QuantaStorPlugin - qs_portals");
    my ($target, $portal_in) = @_;

    my $res = [];

    return $res;
}

sub check_connection {
    qs_write_to_log("QuantaStorPlugin - check_connection");
    my ($class, $storeid, $scfg) = @_;

    # my $portals = qs_portals($scfg->{target}, $scfg->{portal});

    # for my $portal (@$portals) {
	# my $result = qs_test_portal($portal);
	# return $result if $result;
    # }

    # ($server_ip, $username, $password, $api_name, $query_params, $cert_path, $timeout);

    # TODO: need to get password first from cred file and pass it in
    my $api_name = 'storageSystemGet';
    my $response = qs_api_call($scfg->{server},$scfg->{username},'password',$api_name,{},'',15);

    if ($response->is_success) {
        # DEBUG
        qs_write_to_log("QuantaStorPlugin - Response content: " . $response->decoded_content . "\n");
        return 1;
    } else {
        qs_write_to_log("QuantaStorPlugin - Response content: " . $response->decoded_content . "\n");
        return 0;
    }
    return 1;
}

sub on_delete_hook {
    qs_write_to_log("QuantaStorPlugin - on_delete_hook");
    my ($class, $storeid, $scfg) = @_;

    qs_delete_credentials($storeid);

    return;
}

sub parse_volname {
    my ($class, $volname) = @_;
    $class->qs_write_to_log("parse_volname : volname " + $volname);

    if ($volname =~ m/^lun(\d+)$/) {
	return ('images', $1, undef, undef, undef, undef, 'raw');
    }

    die "unable to parse iscsi volume name '$volname'\n";

}

sub path {
    my ($class, $scfg, $volname, $storeid, $snapname) = @_;
    $class->qs_write_to_log("path : volname " + $volname + " storeid " + $storeid + " snapname " + $snapname);

    die "volume snapshot is not possible on iscsi device"
	if defined($snapname);

    my ($vtype, $lun, $vmid) = $class->parse_volname($volname);

    my $target = $scfg->{target};
    my $portal = $scfg->{portal};

    my $path = "iscsi://$portal/$target/$lun";

    return ($path, $vmid, $vtype);
}

sub create_base {
    my ($class, $storeid, $scfg, $volname) = @_;
    $class->qs_write_to_log("create_base : volname " + $volname + " storeid " + $storeid);

    die "can't create base images in iscsi storage\n";
}

sub clone_image {
    my ($class, $scfg, $storeid, $volname, $vmid, $snap) = @_;
    $class->qs_write_to_log("create_base : volname " + $volname + " storeid " + $storeid + " vmid " + $vmid + " snap " + $snap);

    die "can't clone images in iscsi storage\n";
}

sub alloc_image {
    my ($class, $storeid, $scfg, $vmid, $fmt, $name, $size) = @_;

    die "can't allocate space in iscsi storage\n";
}

sub free_image {
    my ($class, $storeid, $scfg, $volname, $isBase) = @_;

    die "can't free space in iscsi storage\n";
}


sub list_images {
    PVE::Storage::QuantaStorPlugin::qs_write_to_log("QuantaStorPlugin - list_images");
    my ($class, $storeid, $scfg, $vmid, $vollist, $cache) = @_;

    my $res = [];

    $cache->{quantastor} = qs_ls($scfg,$storeid) if !$cache->{quantastor};

    # we have no owner for iscsi devices

    my $target = $scfg->{target};

    if (my $dat = $cache->{quantastor}->{$storeid}) {

        foreach my $volname (keys %$dat) {

            my $volid = "$storeid:$volname";

            if ($vollist) {
                my $found = grep { $_ eq $volid } @$vollist;
                next if !$found;
            } else {
                # we have no owner for iscsi devices
                next if defined($vmid);
            }

            my $info = $dat->{$volname};
            $info->{volid} = $volid;

            push @$res, $info;
        }
    }

    return $res;
}


sub status {
    my ($class, $storeid, $scfg, $cache) = @_;

    my $total = 0;
    my $free = 0;
    my $used = 0;
    my $active = 1;
    return ($total,$free,$used,$active);

    return undef;
}

sub activate_storage {
    my ($class, $storeid, $scfg, $cache) = @_;
    PVE::Storage::QuantaStorPlugin::qs_write_to_log("QuantaStorPlugin - activate_storage");
    return 1;
}

sub deactivate_storage {
    my ($class, $storeid, $scfg, $cache) = @_;
    return 1;
}

sub activate_volume {
    my ($class, $storeid, $scfg, $volname, $snapname, $cache) = @_;

    die "volume snapshot is not possible on iscsi device" if $snapname;

    return 1;
}

sub deactivate_volume {
    my ($class, $storeid, $scfg, $volname, $snapname, $cache) = @_;

    die "volume snapshot is not possible on iscsi device" if $snapname;

    return 1;
}

sub volume_size_info {
    my ($class, $scfg, $storeid, $volname, $timeout) = @_;

    my $vollist = iscsi_ls($scfg,$storeid);
    my $info = $vollist->{$storeid}->{$volname};

    return wantarray ? ($info->{size}, 'raw', 0, undef) : $info->{size};
}

sub volume_resize {
    my ($class, $scfg, $storeid, $volname, $size, $running) = @_;
    die "volume resize is not possible on iscsi device";
}

sub volume_snapshot {
    my ($class, $scfg, $storeid, $volname, $snap) = @_;
    die "volume snapshot is not possible on iscsi device";
}

sub volume_snapshot_rollback {
    my ($class, $scfg, $storeid, $volname, $snap) = @_;
    die "volume snapshot rollback is not possible on iscsi device";
}

sub volume_snapshot_delete {
    my ($class, $scfg, $storeid, $volname, $snap) = @_;
    die "volume snapshot delete is not possible on iscsi device";
}

sub volume_has_feature {
    my ($class, $scfg, $feature, $storeid, $volname, $snapname, $running) = @_;
    
    my $features = {
	copy => { current => 1},
    };

    my ($vtype, $name, $vmid, $basename, $basevmid, $isBase) =
	$class->parse_volname($volname);

    my $key = undef;
    if($snapname){
	$key = 'snap';
    }else{
	$key =  $isBase ? 'base' : 'current';
    }
    return 1 if $features->{$feature}->{$key};

    return undef;
}

sub volume_export_formats {
    my ($class, $scfg, $storeid, $volname, $snapshot, $base_snapshot, $with_snapshots) = @_;

    return () if defined($snapshot); # not supported
    return () if defined($base_snapshot); # not supported
    return () if $with_snapshots; # not supported
    return ('raw+size');
}

sub volume_export {
    my (
	$class,
	$scfg,
	$storeid,
	$fh,
	$volname,
	$format,
	$snapshot,
	$base_snapshot,
	$with_snapshots,
    ) = @_;

    die "volume export format $format not available for $class\n" if $format ne 'raw+size';
    die "cannot export volumes together with their snapshots in $class\n" if $with_snapshots;
    die "cannot export an incremental stream in $class\n" if defined($base_snapshot);
    die "cannot export a snapshot in $class\n" if defined($snapshot);

    my ($file) = $class->path($scfg, $volname, $storeid, $snapshot);

    my $json = '';
    run_command(
	['/usr/bin/qemu-img', 'info', '-f', 'raw', '--output=json', $file],
	outfunc => sub { $json .= shift },
    );
    die "failed to query size information for '$file' with qemu-img\n" if !$json;
    my $info = eval { decode_json($json) };
    die "could not parse qemu-img info command output for '$file' - $@\n" if $@;

    my ($size) = ($info->{'virtual-size'} =~ /^(\d+)$/); # untaint
    die "size '$size' not an integer\n" if !defined($size);
    $size = int($size); # coerce back from string

    PVE::Storage::Plugin::write_common_header($fh, $size);
    run_command(
	['qemu-img', 'dd', 'bs=64k', "if=$file", '-f', 'raw', '-O', 'raw'],
	output => '>&'.fileno($fh),
    );
    return;
}

sub volume_import_formats {
    my ($class, $scfg, $storeid, $volname, $snapshot, $base_snapshot, $with_snapshots) = @_;

    return ();
}

sub volume_import {
    die "volume import is not possible on iscsi storage\n";
}

1;
