package PVE::Storage::QuantaStorPlugin;

use strict;
use warnings;

use Sys::Hostname;
use IO::File;
use JSON;
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
#     my $server_ip    = '10.0.26.200';             # Replace with your server IP
#     my $username     = 'admin';                   # Replace with your username
#     my $password     = 'password';                # Replace with your password
#     my $api_name     = 'storageVolumeEnum';       # Replace with your API endpoint
#     my $query_params = {  };                      # Updated argument value - $query_params = { storageSystem => "testSystem", anotherParam => "value", thirdParam => "123" };
#     my $cert_path    = '';                        # Provide the path to a certificate or undef for no SSL verify
#     my $timeout      = 15;                        # Custom timeout value in seconds
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
    qs_write_to_log("QuantaStorPlugin - qs_api_call");
    my ($server_ip, $username, $password, $api_name, $query_params, $cert_path, $timeout) = @_;

    # Set a default timeout if not provided
    $timeout //= 300;

    my $url = "https://$server_ip:8153/qstorapi/$api_name";

    # Add query parameters to the URL if provided
    if ($query_params && %$query_params) {
        my $query_string = join '&',
            map { uri_escape($_) . '=' . uri_escape($query_params->{$_}) }
            grep { defined $query_params->{$_} && $query_params->{$_} ne '' }
            keys %$query_params;

        $url .= "?$query_string" if $query_string;
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
    # print "URL: $url\n";
    my $response = $ua->get($url);

    # Check response status
    if ($response->is_success) {
        return decode_json($response->decoded_content); # Return raw Perl data structure
    } else {
        print "Response content: " . $response->decoded_content . "\n";
        print "HTTP GET Request failed: " . $response->status_line;
        return '';
    }

    return '';
}

sub qs_storage_volume_enum {
    qs_write_to_log("QuantaStorPlugin - qs_storage_volume_enum");
    my ($server_ip, $username, $password, $cert_path, $timeout, $storageVolumeList) = @_;
    # return qs_api_call($server_ip, $username, $password, 'storagePoolEnum', { }, $cert_path, $timeout);

    my $api_name = 'storageVolumeEnum';
    my $query_params = { storageVolumeList => $storageVolumeList };

    my $response = qs_api_call($server_ip, $username, $password, $api_name, $query_params, $cert_path, $timeout);

    # Prettify the response for output
    my $pretty_result = to_json($response, { utf8 => 1, pretty => 1 });
    # print "Response:\n$pretty_result\n";
    qs_write_to_log("QuantaStorPlugin - qs_storage_volume_enum - Response:\n$pretty_result\n");

    return $response;
}

sub qs_storage_volume_acl_add {
    qs_write_to_log("QuantaStorPlugin - qs_storage_volume_acl_add");
    my ($server_ip, $username, $password, $cert_path, $timeout, $storageVolume, $host) = @_;
    # return qs_api_call($server_ip, $username, $password, 'storagePoolEnum', { }, $cert_path, $timeout);

    my $api_name = 'storageVolumeAclAddRemoveEx';
    my $query_params = { storageVolumeList => $storageVolume, host => $host, modType => 0 };

    my $response = qs_api_call($server_ip, $username, $password, $api_name, $query_params, $cert_path, $timeout);

    # Prettify the response for output
    my $pretty_result = to_json($response, { utf8 => 1, pretty => 1 });
    # print "Response:\n$pretty_result\n";
    qs_write_to_log("QuantaStorPlugin - qs_storage_volume_acl_add - Response:\n$pretty_result\n");

    return $response;
}

sub qs_storage_volume_acl_remove {
    qs_write_to_log("QuantaStorPlugin - qs_storage_volume_acl_remove");
    my ($server_ip, $username, $password, $cert_path, $timeout,  $storageVolume, $host) = @_;
    # return qs_api_call($server_ip, $username, $password, 'storagePoolEnum', { }, $cert_path, $timeout);

    my $api_name = 'storageVolumeAclAddRemoveEx';
    my $query_params = { storageVolumeList => $storageVolume, host => $host, modType => 1 };

    my $response = qs_api_call($server_ip, $username, $password, $api_name, $query_params, $cert_path, $timeout);

    # Prettify the response for output
    my $pretty_result = to_json($response, { utf8 => 1, pretty => 1 });
    # print "Response:\n$pretty_result\n";
    qs_write_to_log("QuantaStorPlugin - qs_storage_volume_acl_remove - Response:\n$pretty_result\n");

    return $response;
}

sub qs_storage_volume_utilization_enum {
    qs_write_to_log("QuantaStorPlugin - qs_storage_volume_utilization_enum");
    my ($server_ip, $username, $password, $cert_path, $timeout, $storageVolume, $offsetDays, $numberOfDays) = @_;
    # return qs_api_call($server_ip, $username, $password, 'storagePoolEnum', { }, $cert_path, $timeout);

    my $api_name = 'storageVolumeUtilizationEnum';
    my $query_params = { storageVolume => $storageVolume, offsetDays => $offsetDays, numberOfDays => $numberOfDays };

    my $response = qs_api_call($server_ip, $username, $password, $api_name, $query_params, $cert_path, $timeout);

    # Prettify the response for output
    # my $pretty_result = to_json($response, { utf8 => 1, pretty => 1 });
    # print "Response:\n$pretty_result\n";
    # qs_write_to_log("QuantaStorPlugin - qs_storage_volume_utilization_enum - Response:\n$pretty_result\n");

    return $response;
}

sub qs_host_add {
    qs_write_to_log("QuantaStorPlugin - qs_host_add");
    my ($server_ip, $username, $password, $cert_path, $timeout, $hostname, $ipAddress, $param_username, $param_password, 
        $hostType, $description, $iqn) = @_;
    # return qs_api_call($server_ip, $username, $password, 'storagePoolEnum', { }, $cert_path, $timeout);

    my $api_name = 'hostAdd';
    my $query_params = { hostname => $hostname, ipAddress => $ipAddress, username => $param_username, password => $param_username, 
                         hostType => $hostType, description => $description, iqn => $iqn };

    my $response = qs_api_call($server_ip, $username, $password, $api_name, $query_params, $cert_path, $timeout);

    # Prettify the response for output
    my $pretty_result = to_json($response, { utf8 => 1, pretty => 1 });
    # print "Response:\n$pretty_result\n";
    qs_write_to_log("QuantaStorPlugin - qs_host_add - Response:\n$pretty_result\n");

    return $response;
}

sub qs_host_get {
    qs_write_to_log("QuantaStorPlugin - qs_host_get");
    my ($server_ip, $username, $password, $cert_path, $timeout, $host) = @_;
    # return qs_api_call($server_ip, $username, $password, 'storagePoolEnum', { }, $cert_path, $timeout);

    my $api_name = 'hostGet';
    my $query_params = { host => $host };

    my $response = qs_api_call($server_ip, $username, $password, $api_name, $query_params, $cert_path, $timeout);

    # Prettify the response for output
    my $pretty_result = to_json($response, { utf8 => 1, pretty => 1 });
    # print "Response:\n$pretty_result\n";
    qs_write_to_log("QuantaStorPlugin - qs_host_get - Response:\n$pretty_result\n");

    return $response;
}

sub qs_host_remove {
    qs_write_to_log("QuantaStorPlugin - qs_host_remove");
    my ($server_ip, $username, $password, $cert_path, $timeout, $host) = @_;
    # return qs_api_call($server_ip, $username, $password, 'storagePoolEnum', { }, $cert_path, $timeout);

    my $api_name = 'hostRemove';
    my $query_params = { host => $host };

    my $response = qs_api_call($server_ip, $username, $password, $api_name, $query_params, $cert_path, $timeout);

    # Prettify the response for output
    # my $pretty_result = to_json($response, { utf8 => 1, pretty => 1 });
    # print "Response:\n$pretty_result\n";
    # qs_write_to_log("QuantaStorPlugin - qs_host_remove - Response:\n$pretty_result\n");

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
    qs_write_to_log("QuantaStorPlugin - qs_ls");
    my ($scfg, $storeid) = @_;

    my $server = $scfg->{server};
    my $list = {};

    eval {
        # here we can run code to ask quantastor what volumes are available.
        my $pool_id = $scfg->{qspoolid} // '';
        qs_write_to_log("QuantaStorPlugin - qs_ls - qspoolid = $pool_id");
        my $res = qs_storage_volume_enum($scfg->{server}, $scfg->{username}, $scfg->{password}, '', 300, '');

        # Filter volumes by storagePoolId
        my @filtered_volumes = grep { $_->{storagePoolId} eq $pool_id } @$res;
        # print encode_json(\@filtered_volumes), "\n";

        # Print the name (iqn) and size of each filtered volume
        foreach my $volume (@filtered_volumes) {
            my $id = $volume->{id} // "No ID";
            my $name = $volume->{name} // "No Name";
            my $size = $volume->{size} // "0";
            my $iqn = $volume->{iqn} // "No SCSI ID";
            my $lun = $volume->{lun} // "0";

            # get the utilization info
            my $util_res = qs_storage_volume_utilization_enum($scfg->{server}, $scfg->{username}, $scfg->{password}, '', 300, $id);
            # parse the response to get the sizeUtilized
            my $used = 0;
            if ($util_res && ref($util_res) eq 'HASH' && defined $util_res->{sizeUtilized}) {
                $used = $util_res->{sizeUtilized} // 0;
            }

            # print "Name: $name, ID $id, Size: $size bytes, iqn: $iqn, used: $used\n";
            $list->{$id} = {
	            name => $name,
	            size => $size,
		        format => 'raw',
                content => 'images',
                iqn => $iqn,
                vmid => $lun, # this has to be and int value.
                used => $used
	        };
        }
    };

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
	format => [ { raw => 1 } , 'raw' ],
    };
}

sub properties {
    qs_write_to_log("QuantaStorPlugin - options");
    return {
	iqn => {
	    description => "IQN to identify a QuantaStor ISCSI volume.",
	    type => 'string',
	    maxLength => 256,
	},
    hostId => {
	    description => "IQN to identify a QuantaStor ISCSI volume.",
	    type => 'string',
	    maxLength => 256,
	},
    };
}

sub options {
    qs_write_to_log("QuantaStorPlugin - options");
    return {
	iqn => { fixed => 1 },
	server => { fixed => 1 },
    username => { fixed => 1 },
	nodes => { optional => 1 },
    disable => {optional => 1},
    shared => { optional => 1 },
    content => { optional => 1 },
    };
}

sub check_config {
    qs_write_to_log("QuantaStorPlugin - check_config");
    my ($class, $sectionId, $config, $create, $skipSchemaCheck) = @_;

    # here we can add more stuff to our config if needed.

    return $class->SUPER::check_config($sectionId, $config, $create, $skipSchemaCheck);
}

# Storage implementation

sub qs_discovery {
    qs_write_to_log("QuantaStorPlugin - qs_discovery");
    my ($server, $username, $password) = @_;
    qs_write_to_log("QuantaStorPlugin - scanning... $server , $username , $password");

    my $res = qs_storage_volume_enum($server, $username, $password, '', 300, '');

    # here we need to return a respose array that contains the info about the available iscsi volumes
    # Collect all iscsi volume names - only collect volume names and ID that are local to the provided server IP address
    my @iscsiVolumeNames = map { { name => $_->{name}, id => $_->{id}, iqn => $_->{iqn} } }
                   grep { exists $_->{name} && exists $_->{id} && exists $_->{iqn} && exists $_->{isRemote} && $_->{isRemote} == 0 }
                   @$res;

    # Print collected volume names
    if (@iscsiVolumeNames) {
        qs_write_to_log("iscsi Volume Names and UUIDs: " . join(", ", map { "$_->{name} (ID: $_->{id}) (IQN: $_->{iqn})" } @iscsiVolumeNames));
    } else {
        qs_write_to_log("No iscsi volumes found.");
    }

    return @iscsiVolumeNames;
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

sub get_initiator_name {
    my $initiator;

    my $fh = IO::File->new('/etc/iscsi/initiatorname.iscsi') || return;
    while (defined(my $line = <$fh>)) {
	next if $line !~ m/^\s*InitiatorName\s*=\s*([\.\-:\w]+)/;
	$initiator = $1;
	last;
    }
    $fh->close();

    return $initiator;
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

    ## use quantastor API to add this host iqn entry to the quantastor grid.
    #my $iqn = get_initiator_name();
    #my $hostname = hostname() + "proxmox-host";
    #my $description = "Host added by Proxmox PVE QuantaStor plug-in.";
    #print "Hostname $hostname Initiator name $iqn\n";
    #my $res_host_get = qs_host_get($scfg->{server}, $scfg->{username}, $scfg->{password}, '', 300, $hostname);
    ## check this response to see if the host already exists.
    #my $res_host_add = qs_host_add($scfg->{server}, $scfg->{username}, $scfg->{password}, '', 300, $hostname, '', '', '', '', $description, $iqn);
    ## get the id of the host we just added.
    #my $decoded = decode_json($res_host_add);
    #my $hostId = $decoded->{id};
    #$scfg->{hostId} = $hostId;
    ## here we need to assign the volume to the host
    #my $res_host_acl_add = qs_storage_volume_acl_add($scfg->{server}, $scfg->{username}, $scfg->{password}, '', 300, $scfg->{iqn}, $hostId);
    # get initiator IQN and hostname
    my $iqn = get_initiator_name();
    my $hostname = hostname() . "-proxmox-host";   # fix: use concatenation, not '+'
    my $description = "Host added by Proxmox PVE QuantaStor plug-in.";
    print "Hostname: $hostname, Initiator: $iqn\n";

    # Step 1: try to fetch the host
    my $res_host_get = qs_host_get($scfg->{server}, $scfg->{username}, $scfg->{password}, '', 300, $iqn);

    my $hostId;

    eval {
        # Make sure it’s a hashref, not empty string
        if (!defined $res_host_get || ref($res_host_get) ne 'HASH') {
            die "qs_host_get returned invalid data type: $res_host_get\n";
        }

        if (exists $res_host_get->{RestError}) {
            # Host not found
            if ($res_host_get->{RestError} =~ /Failed to locate host/i) {
                print "Host not found, creating new host entry...\n";

                my $res_host_add = qs_host_add(
                    $scfg->{server},
                    $scfg->{username},
                    $scfg->{password},
                    '',
                    300,
                    $hostname,
                    '', '', '', '',
                    $description,
                    $iqn
                );

                my $decoded;

                eval {
                    # Verify it’s valid JSON before decoding
                    if (!defined($res_host_add) || $res_host_add !~ /^\s*[{[]/) {
                        die "qs_host_add returned non-JSON or empty response:\n$res_host_add\n";
                    }

                    $decoded = decode_json($res_host_add);

                    # Defensive: ensure it has an 'obj' key and 'id' inside
                    if (!exists $decoded->{obj} || !exists $decoded->{obj}->{id}) {
                        die "qs_host_add response missing expected fields:\n$res_host_add\n";
                    }

                    $hostId = $decoded->{obj}->{id};
                } or do {
                    my $err = $@ || 'Unknown error';
                    die "Fatal error while processing host add: $err\n";
                };

            } else {
                die "Error from qs_host_get: $res_host_get->{RestError}\n";
            }

        } elsif (exists $res_host_get->{id}) {
            # Host already exists
            $hostId = $res_host_get->{id};
            print "Host already exists. ID: $hostId\n";

        } else {
            die "Unexpected response format from qs_host_get.\n";
        }
    };

    if ($@) {
        die "Fatal error while processing host lookup/add: $@\n";
    }

    # store host ID in config
    $scfg->{hostId} = $hostId;

    # Step 2: assign the volume to the host
    my $res_host_acl_add = qs_storage_volume_acl_add(
        $scfg->{server},
        $scfg->{username},
        $scfg->{password},
        '',
        300,
        $scfg->{iqn},
        $hostId
    );
    # we also want to get the mountpoint here see ZFSPoolPlugin

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
    my $response = qs_api_call($scfg->{server},$scfg->{username},$scfg->{password},$api_name,{},'',15);
    # my $pretty_result = to_json($response, { utf8 => 1, pretty => 1 });
    if ($response ne '') {
        # DEBUG
        # qs_write_to_log("QuantaStorPlugin - Response content: " . $pretty_result . "\n");
        qs_write_to_log("QuantaStorPlugin - Success - check_connection");
        return 1;
    } else {
        # qs_write_to_log("QuantaStorPlugin - Response content: " . $pretty_result . "\n");
        qs_write_to_log("QuantaStorPlugin - Failed - check_connection");
        return 0;
    }
    return 1;
}

sub on_delete_hook {
    qs_write_to_log("QuantaStorPlugin - on_delete_hook");
    my ($class, $storeid, $scfg) = @_;

    qs_delete_credentials($storeid);

    my $hostname = hostname();
    # remove host entry from QuantaStor
    my $res = qs_host_remove($scfg->{server}, $scfg->{username}, $scfg->{password}, '', 300, $hostname);

    return;
}

sub parse_volname {
    my ($class, $volname) = @_;
    qs_write_to_log("Plugin.pm - parse_volname $volname");

    return ('images', undef, undef);
}

sub path {
    my ($class, $scfg, $volname, $storeid, $snapname) = @_;
    $class->qs_write_to_log("path : volname " + $volname + " storeid " + $storeid + " snapname " + $snapname);

    die "volume snapshot is not possible on iscsi device"
	if defined($snapname);

    my ($vtype, $lun, $vmid) = $class->parse_volname($volname);

    my $pool = $scfg->{pool};
    my $server = $scfg->{server};

    my $path = "";

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


sub list_volumes {
    qs_write_to_log("QuantaStorPlugin - list_volumes");
    my ($class, $storeid, $scfg, $vmid, $cts) = @_;

    my $res = [];

    my $vols = qs_ls($scfg,$storeid);

    # we have no owner for iscsi devices

    my $target = $scfg->{target};

    foreach my $id (keys %$vols) {
        my $volume = $vols->{$id};
        my $volid = "$storeid:$id";
        qs_write_to_log("QuantaStorPlugin - volid = $volid");

        my $info = $volume;
        $info->{volid} = $volid;
        qs_write_to_log("QuantaStorPlugin - Pushing in volume info $info->{volid}");
        push @$res, $info;
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
