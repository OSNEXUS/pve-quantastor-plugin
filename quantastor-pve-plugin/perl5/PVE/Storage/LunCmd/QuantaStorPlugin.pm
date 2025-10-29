package PVE::Storage::LunCmd::QuantaStorPlugin;

use strict;
use warnings;
use Data::Dumper;
use PVE::SafeSyslog;
use IO::Socket::SSL;
use Sys::Hostname;
use URI::Escape;

use PVE::Storage::QuantaStorPlugin;

use LWP::UserAgent;
use HTTP::Request;
use MIME::Base64;
use JSON;

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


#
#
#
sub get_base {
    return '/dev/zvol';
}

sub qs_path {
    my ($scfg, $volname, $storeid, $snapname) = @_;
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_path called for volname: $volname");

    my ($vtype, $name, $vmid) = qs_parse_volname($volname);
    PVE::Storage::LunCmd::QuantaStorPlugin::qs_write_to_log("LunCmd/QuantaStor.pm - qs_path - parsed volname: vtype=$vtype, name=$name, vmid=$vmid");
    #e.g. iscsi://10.0.26.215/iqn.2009-10.com.osnexus:7b6f4eb4-2f14af41e215fa3a:vm-100-disk-0/1
    my $path = "iscsi://$scfg->{portal}/";
    my $res_vol_get = qs_storage_volume_get($scfg->{qs_apiv4_host},
                                            $scfg->{qs_username},
                                            $scfg->{qs_password},
                                            '',
                                            300,
                                            $name);
    $path .= "$res_vol_get->{iqn}/0";

    # get the iqn for the given volume
    return ($path, $vmid, $vtype);
}

sub qs_parse_volname {
    my ($volname) = @_;
    PVE::Storage::LunCmd::QuantaStorPlugin::qs_write_to_log("LunCmd/QuantaStor.pm - qs_parse_volname $volname");

    if ($volname =~ m/^(((base|basevol)-(\d+)-\S+)\/)?((base|basevol|vm|subvol)-(\d+)-\S+)$/) {
	my $format = ($6 eq 'subvol' || $6 eq 'basevol') ? 'subvol' : 'raw';
	my $isBase = ($6 eq 'base' || $6 eq 'basevol');
	return ('images', $5, $7, $2, $4, $isBase, $format);
    }

    die "unable to parse zfs volume name '$volname'\n";
}

sub qs_api_call {
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_api_call");
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
        qs_write_to_log("LunCmd/QuantaStor.pm - qs_api_call - HTTP GET Request failed: " . $response->status_line);
        print "Response content: " . $response->decoded_content . "\n";
        print "HTTP GET Request failed: " . $response->status_line;
        return '';
    }

    return '';
}

sub qs_storage_volume_enum {
    my ($server_ip, $username, $password, $cert_path, $timeout, $storageVolumeList) = @_;
    # return qs_api_call($server_ip, $username, $password, 'storagePoolEnum', { }, $cert_path, $timeout);
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_storage_volume_enum, storageVolumeList: $storageVolumeList");

    my $api_name = 'storageVolumeEnum';
    my $query_params = { };
    if ($storageVolumeList ne '') {
        $query_params->{storageVolumeList} = $storageVolumeList;
    }

    my $response = qs_api_call($server_ip, $username, $password, $api_name, $query_params, $cert_path, $timeout);

    # Prettify the response for output
    #my $pretty_result = to_json($response, { utf8 => 1, pretty => 1 });
    # print "Response:\n$pretty_result\n";
    #qs_write_to_log("LunCmd/QuantaStor.pm - qs_storage_volume_enum - Response:\n$pretty_result\n");

    return $response;
}

sub qs_storage_volume_get {
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_storage_volume_get");
    my ($server_ip, $username, $password, $cert_path, $timeout, $storageVolume) = @_;
    # return qs_api_call($server_ip, $username, $password, 'storagePoolEnum', { }, $cert_path, $timeout);

    my $api_name = 'storageVolumeGet';
    my $query_params = { storageVolume => $storageVolume };

    my $response = qs_api_call($server_ip, $username, $password, $api_name, $query_params, $cert_path, $timeout);

    # Prettify the response for output
    #my $pretty_result = to_json($response, { utf8 => 1, pretty => 1 });
    # print "Response:\n$pretty_result\n";
    #qs_write_to_log("LunCmd/QuantaStor.pm - qs_storage_volume_get - Response:\n$pretty_result\n");

    return $response;
}

sub qs_storage_volume_create {
    my ($server_ip, $username, $password, $cert_path, $timeout, $name, $size, $pool) = @_;
    # return qs_api_call($server_ip, $username, $password, 'storagePoolEnum', { }, $cert_path, $timeout);
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_storage_volume_create $name $size $pool");

    my $api_name = 'storageVolumeCreate';
    my $trim_pool_name = $pool;
    $trim_pool_name =~ s/^qs-//;
    my $query_params = {
        name => $name,
        size => $size * 1024,
        provisionableId => $trim_pool_name
    };

    my $response = qs_api_call($server_ip, $username, $password, $api_name, $query_params, $cert_path, $timeout);

    # Prettify the response for output
    #my $pretty_result = to_json($response, { utf8 => 1, pretty => 1 });
    # print "Response:\n$pretty_result\n";
    #qs_write_to_log("LunCmd/QuantaStor.pm - qs_storage_volume_create - Response:\n$pretty_result\n");

    return $response;
}

sub qs_storage_volume_delete {
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_storage_volume_delete");
    my ($server_ip, $username, $password, $cert_path, $timeout, $storageVolume) = @_;
    # return qs_api_call($server_ip, $username, $password, 'storagePoolEnum', { }, $cert_path, $timeout);

    my $api_name = 'storageVolumeDeleteEx';
    my $query_params = {
        storageVolume => $storageVolume,
        flags => 2 # Force delete
    };

    my $response = qs_api_call($server_ip, $username, $password, $api_name, $query_params, $cert_path, $timeout);

    # Prettify the response for output
    my $pretty_result = to_json($response, { utf8 => 1, pretty => 1 });
    # print "Response:\n$pretty_result\n";
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_storage_volume_delete - Response:\n$pretty_result\n");

    return $response;
}

sub qs_storage_volume_acl_add {
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_storage_volume_acl_add");
    my ($server_ip, $username, $password, $cert_path, $timeout, $storageVolume, $host) = @_;
    # return qs_api_call($server_ip, $username, $password, 'storagePoolEnum', { }, $cert_path, $timeout);

    my $api_name = 'storageVolumeAclAddRemoveEx';
    my $query_params = { storageVolumeList => $storageVolume, host => $host, modType => 0 };

    my $response = qs_api_call($server_ip, $username, $password, $api_name, $query_params, $cert_path, $timeout);

    # Prettify the response for output
    my $pretty_result = to_json($response, { utf8 => 1, pretty => 1 });
    # print "Response:\n$pretty_result\n";
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_storage_volume_acl_add - Response:\n$pretty_result\n");

    return $response;
}

sub qs_storage_volume_acl_remove {
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_storage_volume_acl_remove");
    my ($server_ip, $username, $password, $cert_path, $timeout,  $storageVolume, $host) = @_;
    # return qs_api_call($server_ip, $username, $password, 'storagePoolEnum', { }, $cert_path, $timeout);

    my $api_name = 'storageVolumeAclAddRemoveEx';
    my $query_params = { storageVolumeList => $storageVolume, host => $host, modType => 1 };

    my $response = qs_api_call($server_ip, $username, $password, $api_name, $query_params, $cert_path, $timeout);

    # Prettify the response for output
    my $pretty_result = to_json($response, { utf8 => 1, pretty => 1 });
    # print "Response:\n$pretty_result\n";
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_storage_volume_acl_remove - Response:\n$pretty_result\n");

    return $response;
}

sub qs_storage_volume_utilization_enum {
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_storage_volume_utilization_enum");
    my ($server_ip, $username, $password, $cert_path, $timeout, $storageVolume, $offsetDays, $numberOfDays) = @_;
    # return qs_api_call($server_ip, $username, $password, 'storagePoolEnum', { }, $cert_path, $timeout);

    my $api_name = 'storageVolumeUtilizationEnum';
    my $query_params = { storageVolume => $storageVolume, offsetDays => $offsetDays, numberOfDays => $numberOfDays };

    my $response = qs_api_call($server_ip, $username, $password, $api_name, $query_params, $cert_path, $timeout);

    # Prettify the response for output
    # my $pretty_result = to_json($response, { utf8 => 1, pretty => 1 });
    # print "Response:\n$pretty_result\n";
    # qs_write_to_log("LunCmd/QuantaStor.pm - qs_storage_volume_utilization_enum - Response:\n$pretty_result\n");

    return $response;
}

sub qs_host_add {
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_host_add");
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
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_host_add - Response:\n$pretty_result\n");

    return $response;
}

sub qs_host_get {
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_host_get");
    my ($server_ip, $username, $password, $cert_path, $timeout, $host) = @_;
    # return qs_api_call($server_ip, $username, $password, 'storagePoolEnum', { }, $cert_path, $timeout);

    my $api_name = 'hostGet';
    my $query_params = { host => $host };

    my $response = qs_api_call($server_ip, $username, $password, $api_name, $query_params, $cert_path, $timeout);

    # Prettify the response for output
    # my $pretty_result = to_json($response, { utf8 => 1, pretty => 1 });
    # print "Response:\n$pretty_result\n";
    # qs_write_to_log("LunCmd/QuantaStor.pm - qs_host_get - Response:\n$pretty_result\n");

    return $response;
}

sub qs_host_remove {
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_host_remove");
    my ($server_ip, $username, $password, $cert_path, $timeout, $host) = @_;
    # return qs_api_call($server_ip, $username, $password, 'storagePoolEnum', { }, $cert_path, $timeout);

    my $api_name = 'hostRemove';
    my $query_params = { host => $host };

    my $response = qs_api_call($server_ip, $username, $password, $api_name, $query_params, $cert_path, $timeout);

    # Prettify the response for output
    # my $pretty_result = to_json($response, { utf8 => 1, pretty => 1 });
    # print "Response:\n$pretty_result\n";
    # qs_write_to_log("LunCmd/QuantaStor.pm - qs_host_remove - Response:\n$pretty_result\n");

    return $response;
}


#
# Subroutine called from ZFSPlugin.pm
#
sub run_lun_command {
    my ($scfg, $timeout, $method, @params) = @_;
    qs_write_to_log("LunCmd/QuantaStor.pm - run_lun_command '$method'");

    if (!defined($scfg->{'qs_user'}) || !defined($scfg->{'qs_password'})) {
        die "Undefined `qs_user` and/or `qs_password` variables.";
    }

    if($method eq "create_lu") {
        return run_create_lu($scfg, $timeout, $method, @params);
    }
    if($method eq "delete_lu") {
        return run_delete_lu($scfg, $timeout, $method, @params);
    }
    if($method eq "import_lu") {
        return run_create_lu($scfg, $timeout, $method, @params);
    }
    if($method eq "modify_lu") {
        return run_modify_lu($scfg, $timeout, $method, @params);
    }
    if($method eq "add_view") {
        return run_add_view($scfg, $timeout, $method, @params);
    }
    if($method eq "list_lu") {
        return run_list_lu($scfg, $timeout, $method, "name", @params);
    }

    return undef;
}

#
#
#
sub run_add_view {
    return '';
}

#
# a modify_lu occur by example on a zvol resize. we just need to destroy and recreate the lun with the same zvol.
# Be careful, the first param is the new size of the zvol, we must shift params
#
sub run_modify_lu {
    qs_write_to_log("LunCmd/QuantaStor.pm - run_modify_lu");
    my ($scfg, $timeout, $method, @params) = @_;

    shift(@params);
    run_delete_lu($scfg, $timeout, $method, @params);
    return run_create_lu($scfg, $timeout, $method, @params);
}

#
#
# Optimized
sub run_list_lu {
    qs_write_to_log("LunCmd/QuantaStor.pm - run_list_lu");
    my ($scfg, $timeout, $method, $result_value_type, @params) = @_;
    qs_write_to_log("LunCmd/QuantaStor.pm - run_list_lu - called with (method: '$method'; result_value_type: '$result_value_type'; param[0]: '$params[0]')");
    my $object = $params[0];
    my $result = $object;

    # Get the zvol name from the full path
    $object =~ s{^/dev/zvol/}{};
    # Remove the qs-uuid/ part, leaving only the zvol name
    $object =~ s{^qs-[^/]+/}{};
    my $zvol_name = $object;
    qs_write_to_log("LunCmd/QuantaStor.pm - run_list_lu - requested object: '$object', zvol_name: '$zvol_name'");
    my $res_vol_get = qs_storage_volume_get($scfg->{qs_apiv4_host},
                                            $scfg->{qs_username},
                                            $scfg->{qs_password},
                                            '',
                                            300,
                                            $zvol_name);

    # happy path
    if (defined($res_vol_get->{lun}) && defined($res_vol_get->{id})) {
        if ($result_value_type eq "lun-id") {
            $result = $res_vol_get->{lun};
        } else {
            $result = "/dev/zvol/qs-" . $res_vol_get->{storagePoolId} . "/" . $res_vol_get->{name};
        }
        qs_write_to_log("LunCmd/QuantaStor.pm - run_list_lu - found object: '$object' with result_value_type: '$result_value_type', result: '$result'");
    } else {
        qs_write_to_log("LunCmd/QuantaStor.pm - run_list_lu - object: '$object' not found");
        $result = undef;
    }

    return $result;
}

#
#
#
sub run_create_lu {
    qs_write_to_log("LunCmd/QuantaStor.pm - run_create_lu");
    my ($scfg, $timeout, $method, @params) = @_;
    qs_write_to_log("LunCmd/QuantaStor.pm - creating LU with Params: @params");
    # e.g. params /dev/zvol/qs-7b6f4eb4-0d07-6966-6442-3b3730925e55/vm-100-disk-0
    my $lun_path  = $params[0];

    # Get the zvol name from the full path
    $lun_path =~ s{^/dev/zvol/}{};
    # Remove the qs-uuid/ part, leaving only the zvol name
    $lun_path =~ s{^qs-[^/]+/}{};
    my $zvol_name = $lun_path;
    qs_write_to_log("LunCmd/QuantaStor.pm - ZVOL Name: $zvol_name");
    # make storageVolumeGet call to get the quantastor UUID and iqn of the zvol
    my $res_vol_get = qs_storage_volume_get($scfg->{qs_apiv4_host},
                                            $scfg->{qs_username},
                                            $scfg->{qs_password},
                                            '',
                                            300,
                                            $zvol_name);
    # my $zvol_iqn = $res_vol_get->{iqn};
    my $zvol_uuid = $res_vol_get->{id};

    # get local host iqn
    my $local_host_iqn = get_initiator_name();

    # make hostGet call to get the UUID of the quantastor host entry for the local host iqn
    my $res_host_get = qs_host_get($scfg->{qs_apiv4_host}, $scfg->{qs_username}, $scfg->{qs_password}, '', 300, $local_host_iqn);

    # make storageVolumeAclAddRemoveEx call to add the zvol access for the local host
    my $res_host_acl_add = qs_storage_volume_acl_add($scfg->{qs_apiv4_host}, $scfg->{qs_username}, $scfg->{qs_password}, '', 300, $zvol_uuid, $local_host_iqn);

    # we need to iscsi target login here.
    # iscsiadm -m node --targetname iqn.2009-10.com.osnexus:7b6f4eb4-2f14af41e215fa3a:vm-100-disk-0 --portal 10.0.26.215 --login
    my $res_login = qs_iscsi_target_login($scfg, $res_vol_get->{iqn});

    # return iqn of the target
    return "";
}

#
#
# Optimzied
sub run_delete_lu {
    qs_write_to_log("LunCmd/QuantaStor.pm - run_delete_lu");
    my ($scfg, $timeout, $method, @params) = @_;
    my $lun_path  = $params[0];
    qs_write_to_log("LunCmd/QuantaStor.pm - run_delete_lu - called with (method: '$method'; param[0]: '$lun_path')");

    # Get the zvol name from the full path
    $lun_path =~ s{^/dev/zvol/}{};
    # Remove the qs-uuid/ part, leaving only the zvol name
    $lun_path =~ s{^qs-[^/]+/}{};
    my $zvol_name = $lun_path;

    # verify the zvol exists.
    my $res_vol_get = qs_storage_volume_get($scfg->{qs_apiv4_host},
                                            $scfg->{qs_username},
                                            $scfg->{qs_password},
                                            '',
                                            300,
                                            $zvol_name);
    if (!defined($res_vol_get->{id})) {
        die "LUN $zvol_name does not exist.";
    }

    # remove acl entry for local host
    my $local_host_iqn = get_initiator_name();
    my $res_host_get = qs_host_get($scfg->{qs_apiv4_host},
                                        $scfg->{qs_username},
                                        $scfg->{qs_password},
                                        '',
                                        300,
                                        $local_host_iqn);

    my $res_host_acl_remove = qs_storage_volume_acl_remove($scfg->{qs_apiv4_host},
                                                            $scfg->{qs_username},
                                                            $scfg->{qs_password},
                                                            '',
                                                            300,
                                                            $res_vol_get->{id},
                                                            $res_host_get->{id});

    # logout from iscsi target
    my $res_logout = qs_iscsi_target_logout($scfg, $res_vol_get->{iqn});

    return "";
}

sub qs_iscsi_target_discover {
    my ($scfg) = @_;
    # iscsiadm -m discovery -t sendtargets -p $scfg->{portal}
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_iscsi_target_discover");
    my $portal = $scfg->{portal};;
    unless ($portal) {
        qs_write_to_log("ERROR: Missing portal in qs_iscsi_target_discover");
        return 0;
    }

    my $cmd = sprintf(
        "iscsiadm -m discovery -t sendtargets -p %s",
        $portal
    );

    qs_write_to_log("Running command: $cmd");

    my $output = `$cmd 2>&1`;
    my $rc = $? >> 8;

    qs_write_to_log("Command output:\n$output");
    qs_write_to_log("Command exit code: $rc");

    if ($rc == 0) {
        qs_write_to_log("Discovery successful for portal $portal");
        return 1;
    } else {
        qs_write_to_log("Discovery failed for portal $portal");
        return 0;
    }
}

sub qs_iscsi_target_login {
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_iscsi_target_login");
    my ($scfg, $target_iqn) = @_;

    # Example: $scfg->{qs_apiv4_host} = "10.0.26.215"
    #          $target_iqn = "iqn.2009-10.com.osnexus:7b6f4eb4-2f14af41e215fa3a:vm-100-disk-0"

    my $portal = $scfg->{portal};
    unless ($portal && $target_iqn) {
        qs_write_to_log("ERROR: Missing portal or target_iqn in qs_iscsi_target_login");
        return 0;
    }

    # First perform discovery
    qs_iscsi_target_discover($scfg);

    my $cmd = sprintf(
        "iscsiadm -m node --targetname %s --portal %s --login",
        $target_iqn,
        $portal
    );

    qs_write_to_log("Running command: $cmd");

    my $output = `$cmd 2>&1`;
    my $rc = $? >> 8;

    qs_write_to_log("Command output:\n$output");
    qs_write_to_log("Command exit code: $rc");

    if ($rc == 0) {
        qs_write_to_log("Login successful for target $target_iqn");
        return 1;
    } else {
        qs_write_to_log("Login failed for target $target_iqn");
        return 0;
    }
}

sub qs_iscsi_target_logout {
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_iscsi_target_logout");
    my ($scfg, $target_iqn) = @_;

    # Example: $scfg->{qs_apiv4_host} = "10.0.26.215"
    #          $target_iqn = "iqn.2009-10.com.osnexus:7b6f4eb4-2f14af41e215fa3a:vm-100-disk-0"

    my $portal = $scfg->{portal};
    unless ($portal && $target_iqn) {
        qs_write_to_log("ERROR: Missing portal or target_iqn in qs_iscsi_target_login");
        return 0;
    }

    my $cmd = sprintf(
        "iscsiadm -m node --targetname %s --portal %s --logout",
        $target_iqn,
        $portal
    );

    qs_write_to_log("Running command: $cmd");

    my $output = `$cmd 2>&1`;
    my $rc = $? >> 8;

    qs_write_to_log("Command output:\n$output");
    qs_write_to_log("Command exit code: $rc");

    if ($rc == 0) {
        qs_write_to_log("Logout successful for target $target_iqn");
        return 1;
    } else {
        qs_write_to_log("Logout failed for target $target_iqn");
        return 0;
    }
}


sub qs_zfs_create_zvol {
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_create_zvol");
    my ($scfg, $zvol, $size) = @_;

    # run qs storageVolumeCreate API
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_create_zvol - creating zvol: $zvol with size: $size, pool: $scfg->{pool}");
    my $create_response = qs_storage_volume_create($scfg->{qs_apiv4_host}, $scfg->{qs_username}, $scfg->{qs_password}, '', 300, $zvol, $size, $scfg->{pool});
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

sub activate_storage {
    qs_write_to_log("LunCmd/QuantaStorPlugin.pm - activate_storage");
    my ($class, $storeid, $scfg, $cache) = @_;
    my $iqn = get_initiator_name();
    my $hostname = hostname() . "-proxmox-host";   # fix: use concatenation, not '+'
    my $description = "Host added by Proxmox PVE QuantaStor plug-in.";
    print "Hostname: $hostname, Initiator: $iqn\n";

    # Step 1: try to fetch the host
    my $res_host_get = qs_host_get($scfg->{qs_apiv4_host}, $scfg->{qs_username}, $scfg->{qs_password}, '', 300, $iqn);

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
                    $scfg->{qs_apiv4_host},
                    $scfg->{qs_username},
                    $scfg->{qs_password},
                    '',
                    300,
                    $hostname,
                    '', '', '', '',
                    $description,
                    $iqn
                );

                eval {
                    if (!defined $res_host_add || ref($res_host_add) ne 'HASH') {
                        die "qs_host_add returned invalid data type: $res_host_add\n";
                    }
                    # Defensive: ensure it has an 'obj' key and 'id' inside
                    if (!exists $res_host_add->{obj} || !exists $res_host_add->{obj}->{id}) {
                        die "qs_host_add response missing expected fields:\n$res_host_add\n";
                    }

                    $hostId = $res_host_add->{obj}->{id};
                    print "QuantaStor host created. ID: $hostId\n";
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
            print "QuantaStor host already exists. ID: $hostId\n";

        } else {
            die "Unexpected response format from qs_host_get.\n";
        }
    };

    if ($@) {
        die "Fatal error while processing QuantaStor host lookup/add: $@\n";
    }

    return 1;
}

sub qs_list_images {
    my ($class, $storeid, $scfg, $vmid, $vollist, $cache) = @_;
    PVE::Storage::LunCmd::QuantaStorPlugin::qs_write_to_log("LunCmd/QuantaStorPlugin.pm - qs_list_images - vmid: $vmid, storeid: $storeid host: $scfg->{qs_apiv4_host}");
    my $res = [];

    my $zfs_list = qs_zfs_list_zvol($scfg);

    for my $info (values $zfs_list->%*) {
	my $volname = $info->{name};
	my $parent = $info->{parent};
	my $owner = $info->{vmid};

	if ($parent && $parent =~ m/^(\S+)\@__base__$/) {
	    my ($basename) = ($1);
	    $info->{volid} = "$storeid:$basename/$volname";
	} else {
	    $info->{volid} = "$storeid:$volname";
	}

	if ($vollist) {
	    my $found = grep { $_ eq $info->{volid} } @$vollist;
	    next if !$found;
	} else {
	    next if defined ($vmid) && ($owner ne $vmid);
	}

	push @$res, $info;
    }

    return $res;
}

sub qs_zfs_list_zvol {
    my ($scfg) = @_;
    qs_write_to_log("LunCmd/QuantaStorPlugin.pm  - qs_zfs_list_zvol host: $scfg->{qs_apiv4_host}, pool: $scfg->{pool}");

    # json response list of storage volumes
    qs_write_to_log("LunCmd/QuantaStorPlugin.pm  - making storage volume enum call using storage config host : $scfg->{qs_apiv4_host}");
    my $res_volume_enum = qs_storage_volume_enum($scfg->{qs_apiv4_host}, $scfg->{qs_username}, $scfg->{qs_password}, '', 300, '');
    my $zvols = qs_zfs_parse_zvol_list($res_volume_enum, $scfg->{pool});

    my $list = {};


    foreach my $zvol (@$zvols) {
    qs_write_to_log("LunCmd/QuantaStorPlugin.pm - qs_zfs_list_zvol - processing zvol: $zvol->{name}");
	my $name = $zvol->{name};
	my $parent = $zvol->{origin};
	if($zvol->{origin} && $zvol->{origin} =~ m/^$scfg->{pool}\/(\S+)$/){
	    $parent = $1;
	}

	$list->{$name} = {
	        name => $name,
	        size => $zvol->{size},
	        parent => $parent,
	        format => $zvol->{format},
            vmid => $zvol->{owner},
        };
    }

    return $list;
}

sub qs_zfs_parse_zvol_list {
    my ($json_data, $pool) = @_;
    qs_write_to_log("LunCmd/QuantaStorPlugin.pm - qs_zfs_parse_zvol_list - called with ( pool: '$pool')");

    my $list = ();

    # trim qs- from pool name
    $pool =~ s/^qs-//;
    return $list if !$json_data;

    foreach my $item (@$json_data) {
        next unless defined $item->{storagePoolId} && $item->{storagePoolId} eq $pool;
        my $zvol = {};
        $zvol->{name} = $item->{name};
        $zvol->{size} = $item->{size} + 0;
        $zvol->{format} = 'raw';
        # extract owner from name if possible
        if ($item->{name} =~ m!^(vm|base|subvol|basevol)-(\d+)-(\S+)$!) {
            $zvol->{owner} = $2;
        } else {
            $zvol->{owner} = '';
        }
        $zvol->{origin} = "";
        qs_write_to_log("LunCmd/QuantaStorPlugin.pm - qs_zfs_parse_zvol_list - processing dataset: '$item->{name}' (pool: '$pool', name: '$zvol->{name}', owner: '$zvol->{owner}')");
        push @$list, $zvol;
    }

    return $list;
}

sub qs_zfs_delete_zvol {
    my ($scfg, $zvol) = @_;
    PVE::Storage::LunCmd::QuantaStorPlugin::qs_write_to_log("ZFSPoolPlugin.pm - zfs_delete_zvol - called with (zvol: '$zvol')");

    my $err;
    # Get the zvol name from the full path
    $zvol =~ s{^/dev/zvol/}{};
    # Remove the qs-uuid/ part, leaving only the zvol name
    $zvol =~ s{^qs-[^/]+/}{};
    my $zvol_name = $zvol;

    # verify the zvol exists.
    my $res_vol_get = qs_storage_volume_get($scfg->{qs_apiv4_host},
                                            $scfg->{qs_username},
                                            $scfg->{qs_password},
                                            '',
                                            300,
                                            $zvol_name);
    # we need to do error checking here. aginst the json response.

    # remove the zvol
    my $res_storage_volume_delete = qs_storage_volume_delete($scfg->{qs_apiv4_host},
                                                            $scfg->{qs_username},
                                                            $scfg->{qs_password},
                                                            '',
                                                            300,
                                                            $res_vol_get->{id});


    die $err if $err;
}

1;