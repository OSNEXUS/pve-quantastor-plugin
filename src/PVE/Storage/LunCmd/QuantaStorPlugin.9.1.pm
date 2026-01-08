package PVE::Storage::LunCmd::QuantaStorPlugin;

use strict;
use warnings;
use Data::Dumper;
use PVE::SafeSyslog;
use IO::Socket::SSL;
use Sys::Hostname;
use URI::Escape;

use LWP::UserAgent;
use HTTP::Request;
use MIME::Base64;
use JSON;

use PVE::Storage::Plugin;
our $MAX_VOLUMES_PER_GUEST = 1024;
# Set to 1 to enable debug logging
our $QS_DEBUG = 0;
our $QS_VERBOSE = 0;

our $QS_CA_BUNDLE = "/etc/ssl/certs/qs-ca-certificates.crt";

# TODO: need to add log rotation
sub qs_write_to_log {
    my ($msg) = @_;
    return if !$QS_DEBUG;

    my $timestamp = scalar(localtime);
    my $logfile = '/var/log/pve-quantastor-plugin.log';

    if (open(my $fh, '>>', $logfile)) {
        print $fh "[$timestamp] $msg\n";
        close($fh);
    }
}

sub qs_log_pretty_response {
    my ($response, $function_name) = @_;
    if (!$QS_VERBOSE) {
        return;
    }
    my $pretty_result = to_json($response, { utf8 => 1, pretty => 1 });
    qs_write_to_log("LunCmd/QuantaStor.pm - $function_name - Response:\n$pretty_result\n");
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
    #e.g. iscsi://10.0.26.215/iqn.2009-10.com.osnexus:7b6f4eb4-2f14af41e215fa3a:vm-100-disk-0/1
    my $path = "iscsi://$scfg->{portal}/";

    my ($vtype, $name, $vmid) = qs_parse_volname($volname);
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_path - parsed volname: vtype=$vtype, name=$name, vmid=$vmid");
    my $res_vol_obj = qs_get_vol_obj_by_name($scfg,$volname);
    $path .= "$res_vol_obj->{iqn}/0";

    # get the iqn for the given volume
    return ($path, $vmid, $vtype);
}

sub qs_qemu_blockdev_options {
    my ($scfg, $storeid, $volname, $machine_version, $options) = @_;

    die "direct access to snapshots not implemented\n"
        if $options->{'snapshot-name'};

    my $res_vol_obj = qs_get_vol_obj_by_name($scfg,$volname);

    return {
        driver => 'iscsi',
        transport => 'tcp',
        portal => "$scfg->{portal}",
        target => "$res_vol_obj->{iqn}",
        lun => 0,
    };
}

sub qs_parse_volname {
    my ($volname) = @_;
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_parse_volname $volname");

    # template-base-100-disk-0 is also a valid name
    if ($volname =~ m/^(((template-base|base|basevol)-(\d+)-\S+)\/)?((template-base|base|basevol|vm|subvol)-(\d+)-\S+)$/) {
	my $format = ($6 eq 'subvol' || $6 eq 'basevol') ? 'subvol' : 'raw';
	my $isBase = ($6 eq 'base' || $6 eq 'basevol');
	return ('images', $5, $7, $2, $4, $isBase, $format);
    }

    die "unable to parse zfs volume name '$volname'\n";
}

sub qs_get_vol_obj_by_name {
    my ($scfg,$volname) = @_;
    my ($vtype, $name, $vmid) = qs_parse_volname($volname);
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_get_vol_obj_by_name - parsed volname: vtype=$vtype, name=$name, vmid=$vmid");
    #trim qs- from pool name
    my $storeid = $scfg->{pool};
    $storeid =~ s/^qs-//;
    my $searchParams = "=name:$name,=storagePoolId:$storeid";
    my $res_vol_search = qs_storage_volume_search($scfg->{qs_apiv4_host},
                                            $scfg->{qs_user},
                                            $scfg->{qs_password},
                                            300,
                                            $searchParams);
    return qs_get_object_from_search_response($res_vol_search);
}

sub qs_api_call {
    #qs_write_to_log("LunCmd/QuantaStor.pm - qs_api_call");
    my ($server_ip, $username, $password, $api_name, $query_params, $timeout) = @_;

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
    # Enable SSL verification if a CA bundle is provided at the expected file path
    if ($QS_CA_BUNDLE && -f $QS_CA_BUNDLE) {
        # Use the provided certificate for SSL verification
        $ua->ssl_opts(
            SSL_ca_file     => $QS_CA_BUNDLE, # Path to the CA certificate
            verify_hostname => 1          # Enable hostname verification
        );
    } else {
        # Disable SSL verification
        qs_write_to_log("LunCmd/QuantaStor.pm - qs_api_call - SSL verification is disabled.");
        $ua->ssl_opts(
            SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE,         # Disable certificate verification
            verify_hostname => 0         # Disable hostname verification
        );
    }

    # Add headers
    my $auth = encode_base64("$username:$password", '');
    $ua->default_header(
        'Accept'        => 'application/json',
        'Authorization' => "Basic $auth",
    );
    my $response = $ua->get($url);

    # Check response status
    if ($response->is_success) {
        return decode_json($response->decoded_content); # Return raw Perl data structure
    } else {
        my $error_msg = "HTTP GET Request failed: " . $response->status_line;
        qs_write_to_log("LunCmd/QuantaStor.pm - qs_api_call - $error_msg");
        qs_write_to_log("Response content: " . $response->decoded_content);

        # Return a hash with error info instead of empty string
        return {
            RestError => $error_msg,
            status_line => $response->status_line,
            content => $response->decoded_content
        };
    }

    return '';
}

sub check_rest_error {
    my ($response, $function_name) = @_;
    qs_write_to_log("LunCmd/QuantaStor.pm - check_rest_error for $function_name");

    # Check if response is defined
    if (!defined($response)) {
        qs_write_to_log("LunCmd/QuantaStor.pm - $function_name - Undefined response");
        die "Error: No response from QuantaStor API ($function_name)";
    }

    my $ref_type = ref($response);

    # Arrays are valid responses (e.g., from enum calls)
    if ($ref_type eq 'ARRAY') {
        qs_write_to_log("LunCmd/QuantaStor.pm - $function_name - Received array response with " . scalar(@$response) . " items");
        return 1; # Arrays don't have RestError, so they're valid
    }

    # Check if it's a hash reference
    if ($ref_type ne 'HASH') {
        qs_write_to_log("LunCmd/QuantaStor.pm - $function_name - Invalid response type: $ref_type");
        die "Error: Invalid response from QuantaStor API ($function_name) - expected HASH or ARRAY, got " . ($ref_type || 'scalar');
    }

    # Now safe to check RestError (only exists in hash responses)
    if (defined($response->{RestError}) && $response->{RestError} ne '') {
        qs_write_to_log("LunCmd/QuantaStor.pm - $function_name - Error in response: " . $response->{RestError});
        die "Error in response from QuantaStor API ($function_name): " . $response->{RestError};
    }

    return 1; # Success
}

sub qs_storage_system_get {
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_storage_system_get");
    my ($server_ip, $username, $password, $timeout, $storageSystem) = @_;

    my $api_name = 'storageSystemGet';
    my $query_params = { };

    my $response = qs_api_call($server_ip, $username, $password, $api_name, $query_params, $timeout);
    check_rest_error($response, 'qs_storage_system_get');
    #qs_log_pretty_response($response, 'qs_storage_system_get');

    return $response;
}

sub qs_storage_pool_get {
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_storage_pool_get");
    my ($server_ip, $username, $password, $timeout, $storagePool) = @_;

    my $api_name = 'storagePoolGet';
    my $query_params = { storagePool => $storagePool };

    my $response = qs_api_call($server_ip, $username, $password, $api_name, $query_params, $timeout);
    check_rest_error($response, 'qs_storage_pool_get');
    #qs_log_pretty_response($response, 'qs_storage_pool_get');

    return $response;
}

sub qs_storage_pool_rescan {
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_storage_pool_rescan");
    my ($server_ip, $username, $password, $timeout, $storageSystem) = @_;

    my $api_name = 'storagePoolRescan';
    my $query_params = { storageSystem => $storageSystem };

    my $response = qs_api_call($server_ip, $username, $password, $api_name, $query_params, $timeout);
    check_rest_error($response, 'qs_storage_pool_rescan');
    #qs_log_pretty_response($response, 'qs_storage_pool_rescan');

    return $response;
}

sub qs_storage_volume_search {
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_storage_volume_search");
    my ($server_ip, $username, $password, $timeout, $searchParams) = @_;
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_storage_volume_search - searchParams: $searchParams");

    # curl -k "https://10.0.26.230:8153/qstorapi/storageVolumeSearch?searchParams=%3Dname%3Avm-100-disk-0,%3DstoragePoolId%3A1e931b00-d85b-bb83-071a-80795e5a2409"
    # $ searchParams = "=name:vm-100-disk-0,=storagePoolId:1e931b00-d85b-bb83-071a-80795e5a2409"
    # $ formatted_searchParams = "%3Dname%3Avm-100-disk-0,%3DstoragePoolId%3A1e931b00-d85b-bb83-071a-80795e5a2409"
    my $api_name = 'storageVolumeSearch';
    my $query_params = { searchParams => $searchParams };

    my $response = qs_api_call($server_ip, $username, $password, $api_name, $query_params, $timeout);
    check_rest_error($response, 'qs_storage_volume_search');
    #qs_log_pretty_response($response, 'qs_storage_volume_search');

    return $response;
}

sub qs_get_object_from_search_response {
    my ($response) = @_;
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_get_object_from_search_response");

    if (defined($response->{list}) && $response->{objCount} == 1) {
        foreach my $obj (@{$response->{list}}) {
            if (defined($obj->{id})) {
                return $obj;
            }
            else {
                qs_write_to_log("LunCmd/QuantaStor.pm - qs_get_object_from_search_response - object id not defined in search response");
            }
        }
    }

    return undef;
}

sub qs_storage_volume_enum {
    my ($server_ip, $username, $password, $timeout, $storageVolumeList) = @_;
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_storage_volume_enum, storageVolumeList: $storageVolumeList");

    my $api_name = 'storageVolumeEnum';
    my $query_params = { };
    if ($storageVolumeList ne '') {
        $query_params->{storageVolumeList} = $storageVolumeList;
    }

    my $response = qs_api_call($server_ip, $username, $password, $api_name, $query_params, $timeout);
    check_rest_error($response, 'qs_storage_volume_enum');
    qs_log_pretty_response($response, 'qs_storage_volume_enum');

    return $response;
}

sub qs_storage_volume_create {
    my ($server_ip, $username, $password, $timeout, $name, $size, $pool, $blocksize, $sparse) = @_;
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_storage_volume_create name: $name size: $size pool: $pool blocksize: $blocksize");
    #strip any non number characters from size and blocksize
    $size =~ s/[^0-9]//g;
    $blocksize =~ s/[^0-9]//g;
    my $api_name = 'storageVolumeCreateEx';
    my $percentReserved = 0;
    # if sparse is 0, we set reservedPercent to 100 to create a thick provisioned volume
    if (defined($sparse) && $sparse == 0) {
        $percentReserved = 100;
    }
    my $query_params = {
        name => $name,
        size => $size * 1024,
        provisionableId => $pool,
        blockSizeKb => $blocksize,
        percentReserved => $percentReserved,
        description => 'Created by Proxmox VE Plugin'
    };

    my $response = qs_api_call($server_ip, $username, $password, $api_name, $query_params, $timeout);
    check_rest_error($response, 'qs_storage_volume_create');
    #qs_log_pretty_response($response, 'qs_storage_volume_create');

    return $response;
}

sub qs_storage_volume_delete {
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_storage_volume_delete");
    my ($server_ip, $username, $password, $timeout, $storageVolume) = @_;

    my $api_name = 'storageVolumeDelete';
    my $query_params = {
        storageVolumeList => $storageVolume,
        deleteOptions => 4, # delete parent and snaps
        flags => 2 # Force delete
    };

    my $response = qs_api_call($server_ip, $username, $password, $api_name, $query_params, $timeout);
    check_rest_error($response, 'qs_storage_volume_delete');
    #qs_log_pretty_response($response, 'qs_storage_volume_delete');

    return $response;
}

sub qs_storage_volume_modify {
    my ($server_ip, $username, $password, $timeout, $storageVolume, $newName) = @_;
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_storage_volume_modify $newName");

    my $api_name = 'storageVolumeModify';
    my $query_params = {
        storageVolume => $storageVolume,
        newName => $newName,
        newDescription => 'Modified by Proxmox VE Plugin'
    };

    my $response = qs_api_call($server_ip, $username, $password, $api_name, $query_params, $timeout);
    check_rest_error($response, 'qs_storage_volume_modify');
    #qs_log_pretty_response($response, 'qs_storage_volume_modify');

    return $response;
}

sub qs_storage_volume_snapshot {
    my ($server_ip, $username, $password, $timeout, $storageVolume, $snapshotName) = @_;
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_storage_volume_snapshot $storageVolume snapshot name: $snapshotName");

    my $api_name = 'storageVolumeSnapshot';
    my $query_params = {
        storageVolume => $storageVolume,
        snapshotName => $snapshotName,
        description => 'Snapshot created by Proxmox VE Plugin'
    };

    my $response = qs_api_call($server_ip, $username, $password, $api_name, $query_params, $timeout);
    check_rest_error($response, 'qs_storage_volume_snapshot');
    #qs_log_pretty_response($response, 'qs_storage_volume_snapshot');

    return $response;
}

sub qs_storage_volume_rollback {
    my ($server_ip, $username, $password, $timeout, $storageVolume, $snapshotVolume) = @_;
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_storage_volume_rollback $storageVolume snapshot name: $snapshotVolume");

    my $api_name = 'storageVolumeRollback';
    my $query_params = {
        storageVolume => $storageVolume,
        snapshotVolume => $snapshotVolume,
    };

    my $response = qs_api_call($server_ip, $username, $password, $api_name, $query_params, $timeout);
    check_rest_error($response, 'qs_storage_volume_rollback');
    #qs_log_pretty_response($response, 'qs_storage_volume_rollback');

    return $response;
}

sub qs_storage_volume_clone {
    my ($server_ip, $username, $password, $timeout, $storageVolume, $cloneName) = @_;
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_storage_volume_clone $storageVolume clone name: $cloneName");

    my $api_name = 'storageVolumeClone';
    my $query_params = {
        storageVolume => $storageVolume,
        cloneName => $cloneName,
        description => 'Clone created by Proxmox VE Plugin'
    };

    my $response = qs_api_call($server_ip, $username, $password, $api_name, $query_params, $timeout);
    check_rest_error($response, 'qs_storage_volume_clone');
    #qs_log_pretty_response($response, 'qs_storage_volume_clone');

    return $response;
}

sub qs_storage_volume_acl_add {
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_storage_volume_acl_add");
    my ($server_ip, $username, $password, $timeout, $storageVolume, $host) = @_;

    my $api_name = 'storageVolumeAclAddRemoveEx';
    my $query_params = { storageVolumeList => $storageVolume, host => $host, modType => 0 };

    my $response = qs_api_call($server_ip, $username, $password, $api_name, $query_params, $timeout);
    check_rest_error($response, 'qs_storage_volume_acl_add');
    #qs_log_pretty_response($response, 'qs_storage_volume_acl_add');

    return $response;
}

sub qs_storage_volume_acl_remove {
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_storage_volume_acl_remove");
    my ($server_ip, $username, $password, $timeout,  $storageVolume, $host) = @_;

    my $api_name = 'storageVolumeAclAddRemoveEx';
    my $query_params = { storageVolumeList => $storageVolume, host => $host, modType => 1 };

    my $response = qs_api_call($server_ip, $username, $password, $api_name, $query_params, $timeout);
    check_rest_error($response, 'qs_storage_volume_acl_remove');
    #qs_log_pretty_response($response, 'qs_storage_volume_acl_remove');

    return $response;
}

sub qs_storage_volume_utilization_enum {
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_storage_volume_utilization_enum");
    my ($server_ip, $username, $password, $timeout, $storageVolume, $offsetDays, $numberOfDays) = @_;

    my $api_name = 'storageVolumeUtilizationEnum';
    my $query_params = { storageVolume => $storageVolume, offsetDays => $offsetDays, numberOfDays => $numberOfDays };

    my $response = qs_api_call($server_ip, $username, $password, $api_name, $query_params, $timeout);
    check_rest_error($response, 'qs_storage_volume_utilization_enum');
    #qs_log_pretty_response($response, 'qs_storage_volume_utilization_enum');

    return $response;
}

sub qs_storage_volume_session_enum {
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_storage_volume_session_enum");
    my ($server_ip, $username, $password, $timeout, $storageVolume) = @_;

    my $api_name = 'sessionEnum';
    my $query_params = { storageVolume => $storageVolume };

    my $response = qs_api_call($server_ip, $username, $password, $api_name, $query_params, $timeout);
    check_rest_error($response, 'qs_storage_volume_session_enum');
    #qs_log_pretty_response($response, 'qs_storage_volume_session_enum');

    return $response;
}

sub qs_host_add {
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_host_add");
    my ($server_ip, $username, $password, $timeout, $hostname, $ipAddress, $param_username, $param_password,
        $hostType, $description, $iqn) = @_;

    my $api_name = 'hostAdd';
    my $query_params = { hostname => $hostname, ipAddress => $ipAddress, username => $param_username, password => $param_username,
                         hostType => $hostType, description => $description, iqn => $iqn };

    my $response = qs_api_call($server_ip, $username, $password, $api_name, $query_params, $timeout);
    check_rest_error($response, 'qs_host_add');
    #qs_log_pretty_response($response, 'qs_host_add');

    return $response;
}

sub qs_host_get {
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_host_get");
    my ($server_ip, $username, $password, $timeout, $host) = @_;

    my $api_name = 'hostGet';
    my $query_params = { host => $host };

    my $response = qs_api_call($server_ip, $username, $password, $api_name, $query_params, $timeout);
    check_rest_error($response, 'qs_host_get');
    #qs_log_pretty_response($response, 'qs_host_get');

    return $response;
}

sub qs_host_remove {
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_host_remove");
    my ($server_ip, $username, $password, $timeout, $host) = @_;

    my $api_name = 'hostRemove';
    my $query_params = { host => $host };

    my $response = qs_api_call($server_ip, $username, $password, $api_name, $query_params, $timeout);
    check_rest_error($response, 'qs_host_remove');
    #qs_log_pretty_response($response, 'qs_host_remove');

    return $response;
}


#
# Subroutine called from ZFSPlugin.pm
#
sub run_lun_command {
    my ($scfg, $timeout, $method, @params) = @_;
    qs_write_to_log("LunCmd/QuantaStorPlugin.pm - run_lun_command '$method'");

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
    if($method eq "list_view") {
        qs_write_to_log("LunCmd/QuantaStorPlugin.pm - executing '$method'");
        return run_list_lu($scfg, $timeout, $method, "lun-id", @params);
    }
    if($method eq "list_lu") {
        return run_list_lu($scfg, $timeout, $method, "name", @params);
    }

    qs_write_to_log("LunCmd/QuantaStorPlugin.pm - run_lun_command method was undefined: '$method'");
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

    my ($qs_pool_id, $zvol_name) = qs_parse_lun_path($object);
    qs_write_to_log("LunCmd/QuantaStor.pm - run_list_lu - requested object: '$object', zvol_name: '$zvol_name'");
    my $res_vol_obj = qs_get_vol_obj_by_name($scfg,$zvol_name);
    # happy path
    if (defined($res_vol_obj->{lun}) && defined($res_vol_obj->{id})) {
        if ($result_value_type eq "lun-id") {
            $result = $res_vol_obj->{lun};
        } else {
            $result = "/dev/zvol/qs-" . $res_vol_obj->{storagePoolId} . "/" . $res_vol_obj->{name};
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

    my ($qs_pool_id, $zvol_name) = qs_parse_lun_path($lun_path);

    qs_write_to_log("LunCmd/QuantaStor.pm - ZVOL Name: $zvol_name");
    # make storageVolumeSearch call to get the quantastor UUID and iqn of the zvol
    my $res_vol_obj = qs_get_vol_obj_by_name($scfg,$zvol_name);
    # check to make sure the zvol exists
    if (!defined($res_vol_obj) || !defined($res_vol_obj->{id})) {
        die "LUN $zvol_name does not exist.";
    }

    # my $zvol_iqn = $res_vol_obj->{iqn};
    my $zvol_uuid = $res_vol_obj->{id};

    # get local host iqn
    my $local_host_iqn = get_initiator_name();

    # make hostGet call to get the UUID of the quantastor host entry for the local host iqn
    my $res_host_get = qs_host_get($scfg->{qs_apiv4_host}, $scfg->{qs_user}, $scfg->{qs_password}, 300, $local_host_iqn);

    # make storageVolumeAclAddRemoveEx call to add the zvol access for the local host
    my $res_host_acl_add = qs_storage_volume_acl_add($scfg->{qs_apiv4_host}, $scfg->{qs_user}, $scfg->{qs_password}, 300, $zvol_uuid, $local_host_iqn);

    # we need to iscsi target login here.
    # iscsiadm -m node --targetname iqn.2009-10.com.osnexus:7b6f4eb4-2f14af41e215fa3a:vm-100-disk-0 --portal 10.0.26.215 --login
    my $res_login = qs_iscsi_target_login($scfg, $res_vol_obj->{iqn});
    # wait_for_volume_available
    my $available = wait_for_volume_available($scfg, $res_vol_obj, 300);
    if (!$available) {
        die "CREATE LU: Timeout waiting for volume to become available after iSCSI login (IQN: $res_vol_obj->{iqn})";
    }

    # return iqn of the target
    return $res_vol_obj->{iqn};
}

#
#
# Optimzied
sub run_delete_lu {
    qs_write_to_log("LunCmd/QuantaStor.pm - run_delete_lu");
    my ($scfg, $timeout, $method, @params) = @_;
    my $lun_path  = $params[0];
    qs_write_to_log("LunCmd/QuantaStor.pm - run_delete_lu - called with (method: '$method'; param[0]: '$lun_path')");

    my ($qs_pool_id, $zvol_name) = qs_parse_lun_path($lun_path);

    my $res_vol_obj = qs_get_vol_obj_by_name($scfg,$zvol_name);
    if (!defined($res_vol_obj) || !defined($res_vol_obj->{id})) {
        die "LUN $zvol_name does not exist.";
    }

    # remove acl entry for local host
    my $local_host_iqn = get_initiator_name();
    my $res_host_get = qs_host_get($scfg->{qs_apiv4_host},
                                        $scfg->{qs_user},
                                        $scfg->{qs_password},
                                        300,
                                        $local_host_iqn);

    my $res_host_acl_remove = qs_storage_volume_acl_remove($scfg->{qs_apiv4_host},
                                                            $scfg->{qs_user},
                                                            $scfg->{qs_password},
                                                            300,
                                                            $res_vol_obj->{id},
                                                            $res_host_get->{id});

    # logout from iscsi target
    my $res_logout = qs_iscsi_target_logout($scfg, $res_vol_obj->{iqn});
    return "";
}

# Helper function to extract qs_uuid and zvol_name from lun_path
sub qs_parse_lun_path {
    my ($lun_path) = @_;
    # Remove /dev/zvol/ prefix if present
    $lun_path =~ s{^/dev/zvol/}{};
    # Extract the uuid part
    my ($qs_pool_id) = ($lun_path =~ m{^qs-([0-9a-fA-F\-]+)/});
    # Remove the qs-uuid/ part, leaving only the zvol name
    $lun_path =~ s{^qs-[^/]+/}{};
    my $zvol_name = $lun_path;
    return ($qs_pool_id, $zvol_name);
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
        qs_write_to_log("ERROR: Missing portal or target_iqn in qs_iscsi_target_logout");
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
    my $trim_pool_name = $scfg->{pool};
    $trim_pool_name =~ s/^qs-//;
    my $create_response = qs_storage_volume_create($scfg->{qs_apiv4_host}, $scfg->{qs_user}, $scfg->{qs_password}, 300, $zvol, $size, $trim_pool_name, $scfg->{blocksize}, $scfg->{sparse});
    # rescan zfs pools for the given system
    my $res_sys_get = qs_storage_system_get($scfg->{qs_apiv4_host}, $scfg->{qs_user}, $scfg->{qs_password}, 300, '');
    my $res_pool_rescan = qs_storage_pool_rescan($scfg->{qs_apiv4_host}, $scfg->{qs_user}, $scfg->{qs_password}, 300, $res_sys_get->{storageSystemId});

}

sub qs_zfs_get_command {
    my ($scfg, $timeout, $method, @params) = @_;
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_zfs_get_command - called with (method: '$method'; params '@params')");
    my $param_str = join(' ', @params);
    # If param_str contains 'available,used', return free and used space of the pool
    if ($param_str =~ /available,used/) {
        my ($uuid) = $param_str =~ /qs-([0-9a-fA-F-]{36})/;

        my $res_pool_get = qs_storage_pool_get($scfg->{qs_apiv4_host},
                                               $scfg->{qs_user},
                                               $scfg->{qs_password},
                                               300,
                                               $uuid);

        # Extract values
        my $size  = $res_pool_get->{size};
        my $free  = $res_pool_get->{freeSpace};
        my $used  = $size - $free;

        my $msg = "$free\n$used";
        qs_write_to_log("LunCmd/QuantaStor.pm - qs_zfs_get_command - available,used - msg: $msg");
        return $msg;
    }
    # Another param volsize,usedbydataset
    elsif ($param_str =~ /volsize,usedbydataset/) {
        # Extract the volume ID (UUID) after the last slash
        my ($volid) = $param_str =~ m{/([0-9a-fA-F-]{36})$};
        my $searchParams = "=id:$volid";
        my $res_vol_search = qs_storage_volume_search($scfg->{qs_apiv4_host},
                                                $scfg->{qs_user},
                                                $scfg->{qs_password},
                                                300,
                                                $searchParams);
        my $res_vol_obj = qs_get_object_from_search_response($res_vol_search);

        # Extract values
        my $size  = $res_vol_obj->{size};
        my $usedByDataset  = $res_vol_obj->{spaceUtilized};

        my $msg = "$size\n$usedByDataset";
        qs_write_to_log("LunCmd/QuantaStor.pm - qs_zfs_get_command - volsize,usedbydataset - msg: $msg");
        return $msg;
    }
    else {
        qs_write_to_log("LunCmd/QuantaStor.pm - qs_zfs_get_command - unhandled param_str: '$param_str'");
    }

    # Default: not handled
    return undef;
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

sub verify_storage_config {
    my ($scfg) = @_;
    qs_write_to_log("LunCmd/QuantaStorPlugin.pm - verify_storage_config");
    # validate storage config
    if (!defined($scfg->{qs_apiv4_host}) || $scfg->{qs_apiv4_host} eq '') {
        die "QuantaStor APIv4 host is not defined in storage configuration.";
    }

    my $host = $scfg->{qs_apiv4_host};
    my $ping_rc = system("ping -c 1 -W 2 '$host' > /dev/null 2>&1");
    if ($ping_rc != 0) {
        die "QuantaStor APIv4 host '$host' is not reachable (ping failed).";
    }
    if (!defined($scfg->{qs_user}) || $scfg->{qs_user} eq '') {
        die "QuantaStor username is not defined in storage configuration.";
    }
    if (!defined($scfg->{qs_password}) || $scfg->{qs_password} eq '') {
        die "QuantaStor password is not defined in storage configuration.";
    }
    # pool - expected format qs-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx (UUID with qs- prefix)
    if (!defined($scfg->{pool}) || $scfg->{pool} eq '') {
        die "QuantaStor storage pool is not defined in storage configuration.";
    }
    if ($scfg->{pool} !~ /^qs-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/) {
        die "QuantaStor storage pool format is invalid. Expected format: qs-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx";
    }
}

sub activate_storage {
    qs_write_to_log("LunCmd/QuantaStorPlugin.pm - activate_storage");
    my ($class, $storeid, $scfg, $cache) = @_;
    my $iqn = get_initiator_name();
    my $hostname = hostname() . "-proxmox-host";   # fix: use concatenation, not '+'
    my $description = "Host added by Proxmox PVE QuantaStor plug-in.";

    # validate storage config
    verify_storage_config($scfg);
    # Step 1: try to fetch the host
    my $res_host_get = qs_host_get($scfg->{qs_apiv4_host}, $scfg->{qs_user}, $scfg->{qs_password}, 300, $iqn);

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
                    $scfg->{qs_user},
                    $scfg->{qs_password},
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
    my ($storeid, $scfg, $vmid, $vollist, $cache) = @_;
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
    my $res_volume_enum = qs_storage_volume_enum($scfg->{qs_apiv4_host}, $scfg->{qs_user}, $scfg->{qs_password}, 300, '');
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
    PVE::Storage::LunCmd::QuantaStorPlugin::qs_write_to_log("LunCmd/QuantaStorPlugin.pm - qs_zfs_delete_zvol - called with (zvol: '$zvol')");

    my $err;
    my ($qs_pool_id, $zvol_name) = qs_parse_lun_path($zvol);
    $qs_pool_id = $scfg->{pool};
    $qs_pool_id =~ s/^qs-//;

    my $res_vol_obj = qs_get_vol_obj_by_name($scfg,$zvol_name);
    # we need to do error checking here. aginst the json response.
    if (!defined($res_vol_obj) || !defined($res_vol_obj->{id})) {
        qs_write_to_log("LunCmd/QuantaStorPlugin.pm - qs_zfs_delete_zvol - zvol: '$zvol_name' does not exist.");
        return;
    }

    # remove the zvol
    my $res_storage_volume_delete = qs_storage_volume_delete($scfg->{qs_apiv4_host},
                                                            $scfg->{qs_user},
                                                            $scfg->{qs_password},
                                                            300,
                                                            $res_vol_obj->{id});


    die $err if $err;

    # rescan storage pools for the given system
    my $res_sys_get = qs_storage_system_get($scfg->{qs_apiv4_host},
                                            $scfg->{qs_user},
                                            $scfg->{qs_password},
                                            300);
    my $res_pool_rescan = qs_storage_pool_rescan($scfg->{qs_apiv4_host},
                                                $scfg->{qs_user},
                                                $scfg->{qs_password},
                                                300,
                                                $res_sys_get->{storageSystemId});
}

sub qs_get_zvol_id_by_name {
    my ($scfg, $zvol_name) = @_;
    PVE::Storage::LunCmd::QuantaStorPlugin::qs_write_to_log("LunCmd/QuantaStorPlugin.pm - qs_get_zvol_id_by_name - called with (zvol_name: '$zvol_name')");

    my $res_vol_obj = qs_get_vol_obj_by_name($scfg,$zvol_name);
    # verify we have a valid response
    if (!defined($res_vol_obj) || !defined($res_vol_obj->{id})) {
        die "ZVOL $zvol_name does not exist.";
    }

    return $res_vol_obj->{id};
}

sub qs_create_base {
    PVE::Storage::LunCmd::QuantaStorPlugin::qs_write_to_log("LunCmd/QuantaStorPlugin.pm - create_base");
    my ($storeid, $scfg, $basename, $volname) = @_;

    my $newname = $volname;
    $newname =~ s/^vm-/base-/;

    # get the storage volume info from quantastor
    # verify the zvol exists.
    my $res_vol_obj = qs_get_vol_obj_by_name($scfg,$volname);

    # logout of iscsi targets before renaming
    PVE::Storage::LunCmd::QuantaStorPlugin::qs_write_to_log("LunCmd/QuantaStorPlugin.pm - create_base - logging out of $volname iqn $res_vol_obj->{iqn}");
    my $res_logout = qs_iscsi_target_logout($scfg, $res_vol_obj->{iqn});
    wait_for_volume_logout($scfg, $res_vol_obj->{id});

    # remove storage volume acl entry for local host
    my $local_host_iqn = get_initiator_name();
    my $res_host_get = qs_host_get($scfg->{qs_apiv4_host},
                                   $scfg->{qs_user},
                                   $scfg->{qs_password},
                                   300,
                                   $local_host_iqn);

    my $res_host_acl_remove = qs_storage_volume_acl_remove($scfg->{qs_apiv4_host},
                                                            $scfg->{qs_user},
                                                            $scfg->{qs_password},
                                                            300,
                                                            $res_vol_obj->{id},
                                                            $res_host_get->{id});

    # modify the volname of the volume via qs API
    PVE::Storage::LunCmd::QuantaStorPlugin::qs_write_to_log("LunCmd/QuantaStorPlugin.pm - create_base - modifying volume name from $volname to $newname");
    my $res_volume_modify = qs_storage_volume_modify($scfg->{qs_apiv4_host},
                                            $scfg->{qs_user},
                                            $scfg->{qs_password},
                                            300,
                                            $res_vol_obj->{id},
                                            $newname);

    # add storage volume acl entry for local host
    # res_volume_modify is the new json zvol object
    my $res_host_acl_add = qs_storage_volume_acl_add($scfg->{qs_apiv4_host},
                                                     $scfg->{qs_user},
                                                     $scfg->{qs_password},
                                                     300,
                                                     $res_volume_modify->{obj}{id},
                                                     $local_host_iqn);

    # login to modified iscsi target
    PVE::Storage::LunCmd::QuantaStorPlugin::qs_write_to_log("LunCmd/QuantaStorPlugin.pm - create_base - logging in to $newname iqn $res_volume_modify->{obj}{iqn}");
    my $res_login = qs_iscsi_target_login($scfg, $res_volume_modify->{obj}{iqn});
    my $available = wait_for_volume_available($scfg, $res_volume_modify->{obj}, 300);
    if (!$available) {
        die "CREATE BASE: Timeout waiting for volume to become available after iSCSI login (IQN: $res_volume_modify->{obj}{iqn})";
    }

    PVE::Storage::LunCmd::QuantaStorPlugin::qs_write_to_log("LunCmd/QuantaStorPlugin.pm - create_base - taking snapshot of new base volume $newname");
    my $res_volume_snapshot = qs_storage_volume_snapshot($scfg->{qs_apiv4_host},
                                            $scfg->{qs_user},
                                            $scfg->{qs_password},
                                            300,
                                            $newname,
                                            "template-$newname");

    my $newvolname = $basename ? "$basename/$newname" : "$newname";
    PVE::Storage::LunCmd::QuantaStorPlugin::qs_write_to_log("LunCmd/QuantaStorPlugin.pm - create_base - returning new volume name: $newvolname");

    return $newvolname;
}

sub qs_clone_image {
    my ($scfg, $storeid, $volname, $vmid, $snap) = @_;
    PVE::Storage::LunCmd::QuantaStorPlugin::qs_write_to_log("LunCmd/QuantaStorPlugin.pm - qs_clone_image - called with (volname: '$volname', vmid: '$vmid')");

    my ($vtype, $basename, $basevmid, undef, undef, $isBase, $format) =
        qs_parse_volname($volname);
    die "clone_image only works on base images\n" if !$isBase;
    PVE::Storage::LunCmd::QuantaStorPlugin::qs_write_to_log("LunCmd/QuantaStorPlugin.pm - qs_clone_image - basename: $basename basevmid: $basevmid");

    my $srcvolname = "template-$basename";

    my $name = qs_find_free_diskname($storeid, $scfg, $vmid, $format);
    PVE::Storage::LunCmd::QuantaStorPlugin::qs_write_to_log("LunCmd/QuantaStorPlugin.pm - qs_clone_image - $name is the new disk name");
    # get the storage volume info from quantastor
    # verify the zvol exists.
    my $res_vol_obj = qs_get_vol_obj_by_name($scfg,$srcvolname);

    #if the volume target does not exist, we cannot clone it.
    if (!defined($res_vol_obj) || !defined($res_vol_obj->{id})) {
        die "LUN $srcvolname does not exist.";
    }

    PVE::Storage::LunCmd::QuantaStorPlugin::qs_write_to_log("LunCmd/QuantaStorPlugin.pm - qs_clone_image - cloning snapshot $srcvolname to new volume $name");
    my $res_volume_clone = qs_storage_volume_clone($scfg->{qs_apiv4_host},
                                                   $scfg->{qs_user},
                                                   $scfg->{qs_password},
                                                   300,
                                                   $res_vol_obj->{id},
                                                   $name);

    # add storage volume acl entry for local host
    my $local_host_iqn = get_initiator_name();
    my $res_host_get = qs_host_get($scfg->{qs_apiv4_host},
                                   $scfg->{qs_user},
                                   $scfg->{qs_password},
                                   300,
                                   $local_host_iqn);

    my $res_host_acl_add = qs_storage_volume_acl_add($scfg->{qs_apiv4_host},
                                                     $scfg->{qs_user},
                                                     $scfg->{qs_password},
                                                     300,
                                                     $res_volume_clone->{obj}{id},
                                                     $local_host_iqn);

    # need to perform iscsi target login here
    PVE::Storage::LunCmd::QuantaStorPlugin::qs_write_to_log("LunCmd/QuantaStorPlugin.pm - qs_clone_image - logging in to $name iqn $res_volume_clone->{obj}{iqn}");
    my $res_login = qs_iscsi_target_login($scfg, $res_volume_clone->{obj}{iqn});
    my $available = wait_for_volume_available($scfg, $res_volume_clone->{obj}, 300);
    if (!$available) {
        die "CLONE: Timeout waiting for volume to become available after iSCSI login (IQN: $res_volume_clone->{obj}{iqn})";
    }

    return "$name";
}

sub qs_get_next_vm_diskname {
    my ($disk_list, $storeid, $vmid, $fmt, $scfg, $add_fmt_suffix) = @_;

    $fmt //= '';
    my $prefix = ($fmt eq 'subvol') ? 'subvol' : 'vm';
    my $suffix = $add_fmt_suffix ? ".$fmt" : '';

    my $disk_ids = {};
    foreach my $disk (@$disk_list) {
    PVE::Storage::LunCmd::QuantaStorPlugin::qs_write_to_log("LunCmd/QuantaStorPlugin.pm - qs_get_next_vm_diskname - processing existing disk: $disk for vmid: $vmid");
	my $disknum = qs_get_vm_disk_number($disk, $vmid);
	$disk_ids->{$disknum} = 1 if defined($disknum);
    }

    for (my $i = 0; $i < $MAX_VOLUMES_PER_GUEST; $i++) {
    PVE::Storage::LunCmd::QuantaStorPlugin::qs_write_to_log("LunCmd/QuantaStorPlugin.pm - qs_get_next_vm_diskname - checking disk number: $i for vmid: $vmid");
	if (!$disk_ids->{$i}) {
	    return "$prefix-$vmid-disk-$i$suffix";
	}
    }

    die "unable to allocate an image name for VM $vmid in storage '$storeid'\n"
}

sub qs_get_vm_disk_number {
    my ($disk_name, $vmid) = @_;

    # Strip common prefixes like "storeid:" or "dataset/"
    # Examples:
    #   qs-storage:vm-102-disk-0   -> vm-102-disk-0
    #   qs-uuid/vm-102-disk-0      -> vm-102-disk-0
    $disk_name =~ s/^[^:\/]+[:\/]//;

    # Match standard Proxmox volume naming patterns
    if ($disk_name =~ m/^(vm|base|subvol|basevol)-$vmid-disk-(\d+)/) {
        return $2;
    }

    return undef;
}

sub qs_find_free_diskname {
    my ($storeid, $scfg, $vmid, $fmt, $add_fmt_suffix) = @_;

    my $disks = qs_list_images($storeid, $scfg, $vmid);

    my $disk_list = [ map { $_->{volid} } @$disks ];

    return qs_get_next_vm_diskname($disk_list, $storeid, $vmid, $fmt, $scfg, $add_fmt_suffix);
}

sub qs_volume_snapshot {
    my ($scfg, $storeid, $volname, $snap) = @_;
    qs_write_to_log("LunCmd/QuantaStorPlugin.pm - qs_volume_snapshot - called with (volname: '$volname')");

    my $vname = (qs_parse_volname($volname))[1];
    my $snap_name = $vname . "_$snap";

    my $res_volume_snapshot = qs_storage_volume_snapshot($scfg->{qs_apiv4_host},
                                            $scfg->{qs_user},
                                            $scfg->{qs_password},
                                            300,
                                            $vname,
                                            $snap_name);
}

sub qs_volume_snapshot_delete {
    my ($scfg, $storeid, $volname, $snap, $running) = @_;

    my $vname = (qs_parse_volname($volname))[1];
    my $snap_name = $vname . "_$snap";
    qs_write_to_log("LunCmd/QuantaStorPlugin.pm - qs_volume_snapshot_delete - called with (snap_name: '$snap_name')");

    my $res_volume_snapshot_delete = qs_storage_volume_delete($scfg->{qs_apiv4_host},
                                            $scfg->{qs_user},
                                            $scfg->{qs_password},
                                            300,
                                            $snap_name);
}

sub qs_volume_snapshot_rollback {
    my ($scfg, $storeid, $volname, $snap) = @_;
    qs_write_to_log("LunCmd/QuantaStorPlugin.pm - qs_volume_snapshot_rollback - called with (volname: '$volname')");
    my $vname = (qs_parse_volname($volname))[1];
    my $snap_name = $vname . "_$snap";

    # logout of iscsi target
    my $res_vol_obj = qs_get_vol_obj_by_name($scfg, $vname);

    my $res_logout = qs_iscsi_target_logout($scfg, $res_vol_obj->{iqn});
    wait_for_volume_logout($scfg, $res_vol_obj->{id});

    # run rollback
    my $res_volume_rollback = qs_storage_volume_rollback($scfg->{qs_apiv4_host},
                                            $scfg->{qs_user},
                                            $scfg->{qs_password},
                                            300,
                                            $res_vol_obj->{id},
                                            $snap_name);


    # login to iscsi target
    my $res_login = qs_iscsi_target_login($scfg, $res_vol_obj->{iqn});
    my $available = wait_for_volume_available($scfg, $res_vol_obj, 300);
    if (!$available) {
        die "ROLLBACK: Timeout waiting for volume to become available after iSCSI login (IQN: $res_vol_obj->{iqn})";
    }
}

sub wait_for_volume_logout {
    my ($scfg, $storageVolume, $max_wait) = @_;
    $max_wait //= 60;  # default 60 seconds
    my $interval = 2;
    my $elapsed = 0;

    qs_write_to_log("Waiting for all sessions to log out for storage volume '$storageVolume'...");

    while ($elapsed < $max_wait) {
        my $response = qs_storage_volume_session_enum(
            $scfg->{qs_apiv4_host},
            $scfg->{qs_user},
            $scfg->{qs_password},
            30,
            $storageVolume
        );

        # Handle undefined response
        unless (defined $response) {
            qs_write_to_log("Invalid response or API call failed during sessionEnum.");
            sleep($interval);
            $elapsed += $interval;
            next;
        }

        # Determine the session list
        my $sessions;
        if (ref $response eq 'ARRAY') {
            $sessions = $response;
        } elsif (ref $response eq 'HASH') {
            $sessions = $response->{result} // $response->{sessions} // [];
        } else {
            $sessions = [];
        }

        my $session_count = ref $sessions eq 'ARRAY' ? scalar(@$sessions) : 0;

        if ($session_count == 0) {
            qs_write_to_log("All iSCSI sessions for volume '$storageVolume' are logged out.");
            return 1;
        }

        qs_write_to_log("Still waiting... $session_count active session(s) remain.");
        sleep($interval);
        $elapsed += $interval;
    }

    qs_write_to_log("Timeout waiting for volume '$storageVolume' sessions to log out after $max_wait seconds.");
    return 0;
}

sub wait_for_volume_available {
    my ($scfg, $vol_obj_json, $max_wait) = @_;
    qs_write_to_log("Waiting for volume to become available: IQN '$vol_obj_json->{iqn}'...");
    $max_wait //= 30;
    # /dev/disk/by-path/ip-10.0.26.31:3260-iscsi-iqn.2009-10.com.osnexus:939349c6-5886c122cc20e2b0:vm-100-disk-0-lun-0
    my $path = "/dev/disk/by-path/ip-" . $scfg->{portal} . ":3260-iscsi-" . $vol_obj_json->{iqn} . "-lun-0";
    for (my $i = 0; $i < $max_wait; $i++) {
        qs_write_to_log("Checking for volume path: $path");
        if (-e $path) {
            qs_write_to_log("Volume $path is now available");
            return 1;
        }
        sleep(1);
        qs_write_to_log("Volume $path not yet available, retrying...");
    }
    return 0;
}

sub qs_volume_rollback_is_possible {
    my ($scfg, $storeid, $volname, $snap, $blockers) = @_;
    qs_write_to_log("LunCmd/QuantaStorPlugin.pm - qs_volume_rollback_is_possible - called with (volname: '$volname', snap: '$snap')");
    my $vname = (qs_parse_volname($volname))[1];
    my $snap_name = $vname . "_$snap";

    # check to see if this snapshot exists on the qs host
    my $res_vol_obj = qs_get_vol_obj_by_name($scfg, $snap_name);

    if (!defined($res_vol_obj) || !defined($res_vol_obj->{id})) {
        die "can't rollback, snapshot '$snap' does not exist on '$volname'\n";
    }

    # we need to see if this snapshot is the most recent snapshot
    # taken on this volume.
    my $res_storage_volume_enum = qs_storage_volume_enum($scfg->{qs_apiv4_host},
                                            $scfg->{qs_user},
                                            $scfg->{qs_password},
                                            300,
                                            '');

    # Parse the list of objects and verify that $res_vol_obj->{createdTimeStamp} is the most recent
    # e.g. "createdTimeStamp": "2025-11-12T21:43:28Z"
    # Determine if $res_vol_obj is the most recent snapshot for volume $vname
    my $target_snapshot_time = $res_vol_obj->{createdTimeStamp};
    qs_write_to_log("Checking if snapshot '$res_vol_obj->{name}' (created: $target_snapshot_time) is the most recent for volume '$vname'");
    my $is_most_recent = 1;

    foreach my $item (@$res_storage_volume_enum) {
        # Only consider snapshots
        qs_write_to_log("Examining item: " . ($item->{name} // 'undef') . " (isSnapshot: " . ($item->{isSnapshot} // 'undef') . ", createdTimeStamp: " . ($item->{createdTimeStamp} // 'undef') . ")");
        unless (defined $item->{isSnapshot} && $item->{isSnapshot} eq '1') {
            qs_write_to_log("Skipping non-snapshot item: " . ($item->{name} // 'undef'));
            next;
        }

        # snapshotParent should be eq to $res_vol_obj->{snapshotParent}
        unless (defined $item->{snapshotParent} && $item->{snapshotParent} eq $res_vol_obj->{snapshotParent}) {
            qs_write_to_log("Skipping snapshot '$item->{name}' (snapshotParent: " . ($item->{snapshotParent} // 'undef') . ") not matching target snapshotParent '" . ($res_vol_obj->{snapshotParent} // 'undef') . "'");
            next;
        }

        qs_write_to_log("Found snapshot '$item->{name}' for volume '$vname' with createdTimeStamp: $item->{createdTimeStamp}");

        # Compare timestamps
        if ($item->{createdTimeStamp} gt $target_snapshot_time) {
            qs_write_to_log("Snapshot '$item->{name}' is newer (created: $item->{createdTimeStamp}) than target snapshot '$res_vol_obj->{name}' (created: $target_snapshot_time)");
            $is_most_recent = 0;
            push @$blockers, $item->{name} if defined $blockers;
        }
    }
    qs_write_to_log("Finished checking snapshots for volume '$vname'. is_most_recent = $is_most_recent");

    qs_write_to_log("Snapshot '$res_vol_obj->{name}' is ". ($is_most_recent ? "the most recent snapshot." : "not the most recent snapshot."));
    if (!$is_most_recent) {
        die "can't rollback, '$snap' is not most recent snapshot on '$volname'\n";
    }

    return 1;
}





1;
