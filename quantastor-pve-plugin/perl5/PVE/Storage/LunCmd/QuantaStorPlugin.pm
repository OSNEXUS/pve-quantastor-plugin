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

# Global variable definitions
# my $MAX_LUNS = 255;                        # Max LUNS per target on the iSCSI server
# my $qs_server_list = undef;           # API connection HashRef using the IP address of the server
# my $qs_rest_connection = undef;       # Pointer to entry in $qs_server_list
# my $qs_global_config_list = undef;    # IQN HashRef using the IP address of the server
# my $qs_global_config = undef;         # Pointer to entry in $qs_global_config_list
# my $dev_prefix = "";
# my $product_name = undef;
# my $apiping = '/api/v1.0/system/version/'; # Initial API method for setup
# my $runawayprevent = 0;                    # Recursion prevention variable
# 
# # QuantaStor API definitions
# my $qs_api_version = "v1.0";          # Default to v1.0 of the API's
# my $qs_api_methods = undef;           # API Methods Nested HASH Ref
# my $qs_api_variables = undef;         # API Variable Nested HASH Ref
# my $truenas_version = undef;
# my $truenas_release_type = "Production";

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
    my $pretty_result = to_json($response, { utf8 => 1, pretty => 1 });
    # print "Response:\n$pretty_result\n";
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_storage_volume_enum - Response:\n$pretty_result\n");

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
    my $pretty_result = to_json($response, { utf8 => 1, pretty => 1 });
    # print "Response:\n$pretty_result\n";
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_storage_volume_get - Response:\n$pretty_result\n");

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
    my $pretty_result = to_json($response, { utf8 => 1, pretty => 1 });
    # print "Response:\n$pretty_result\n";
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_storage_volume_create - Response:\n$pretty_result\n");

    return $response;
}

sub qs_storage_volume_delete {
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_storage_volume_delete");
    my ($server_ip, $username, $password, $cert_path, $timeout, $storageVolume) = @_;
    # return qs_api_call($server_ip, $username, $password, 'storagePoolEnum', { }, $cert_path, $timeout);

    my $api_name = 'storageVolumeDeleteEx';
    my $query_params = {
        storageVolume => $storageVolume
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
    # Might be good to add a check like this
    #if (!defined $qs_server_list->{defined($scfg->{qs_apiv4_host}) ? $scfg->{qs_apiv4_host} : $scfg->{portal}}) {
    #    qs_api_check($scfg);
    #}

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
        return run_list_view($scfg, $timeout, $method, @params);
    }
    if($method eq "list_extent") {
        return run_list_extent($scfg, $timeout, $method, @params);
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
#
sub run_list_view {
    qs_write_to_log("LunCmd/QuantaStor.pm - run_list_view");
    my ($scfg, $timeout, $method, @params) = @_;

    return run_list_lu($scfg, $timeout, $method, "lun-id", @params);
}

#
#
# Optimized
#{
#    "id": "30c82b82-e9c3-06ef-cd5e-d5e15a4a1f4f",
#    "name": "test-target",
#    "customId": "",
#    "state": "0",
#    "stateDetail": "",
#    "type": "3",
#    "createdTimeStamp": "2025-10-17T16:21:44Z",
#    "createdByUserId": "437bb0da-549e-6619-ea0e-a91e05e6befb",
#    "modifiedTimeStamp": "2025-10-17T16:21:46Z",
#    "modifiedByUserId": "437bb0da-549e-6619-ea0e-a91e05e6befb",
#    "isRemote": "false",
#    "storageSystemId": "e0583283-350e-5173-06b3-816ee0f374cf",
#    "ownershipRevision": "0",
#    "internalUse": "0",
#    "storagePoolId": "7b6f4eb4-0d07-6966-6442-3b3730925e55",
#    "size": "10737418240",
#    "isSnapshot": "false",
#    "lazyCloneSnapshotPath": "",
#    "snapshotParent": "",
#    "mountPath": "/dev/zvol/qs-7b6f4eb4-0d07-6966-6442-3b3730925e55/30c82b82-e9c3-06ef-cd5e-d5e15a4a1f4f",
#    "isActiveCheckpoint": "false",
#    "createdBySchedule": "",
#    "compressionRatio": "1.00",
#    "compressionType": "on",
#    "retentionTags": "0",
#    "syncPolicy": "0",
#    "copies": "1",
#    "spaceUtilized": "57344",
#    "logicalSpaceUtilized": "28672",
#    "spaceUtilizedBySnapshots": "0",
#    "spaceReserved": "0",
#    "usedByRefReservation": "0",
#    "vvolType": "0",
#    "vvolParentId": "",
#    "snapshotReferenceId": "",
#    "numHolds": "0",
#    "cachePolicyPrimary": "0",
#    "cachePolicySecondary": "0",
#    "resumeToken": "",
#    "snapshotCount": "0",
#    "createdByScheduleType": "0",
#    "clones": "",
#    "accessMode": "0",
#    "description": "",
#    "devicePath": "",
#    "iqn": "iqn.2009-10.com.osnexus:7b6f4eb4-30c82b82e9c306ef:test-target",
#    "isCloudBackup": "false",
#    "useGuidIqn": "false",
#    "lun": "0",
#    "cloudContainerId": "",
#    "target": "0",
#    "relativeTargetId": "0",
#    "volumeType": "5",
#    "chapPolicy": "6",
#    "blockSizeKb": "64",
#    "chapUsername": "",
#    "chapPassword": "",
#    "storageLinkId": "OSNEXUS__QUANTASTOR__e0583283__30c82b82",
#    "deviceDescriptor": "30c82b82e9c306efe0583283",
#    "enableWriteCache": "false",
#    "accessTimeStamp": "1970-01-01T00:00:00Z",
#    "qosReadIops": "0",
#    "qosWriteIops": "0",
#    "qosReadBandwidth": "0",
#    "qosWriteBandwidth": "0",
#    "qosPolicyId": "",
#    "eui": "eui.3330633832623832",
#    "lunAssignmentPolicy": "0",
#    "cephClusterId": "",
#    "profileId": "1625cdb7-5d25-d9f6-99fd-2779f44095b6",
#    "stripeSizeKb": "0",
#    "stripeCount": "0",
#    "mappingDisabled": "false",
#    "portalGroupId": ""
#}

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



    #my $luns = qs_list_lu($scfg);
    #syslog("info", (caller(0))[3] . " : called with (method: '$method'; result_value_type: '$result_value_type'; param[0]: '$object')");

    #$object =~ s/^\Q$dev_prefix//;
    #syslog("info", (caller(0))[3] . " : TrueNAS object to find: '$object'");
    #if (defined($luns->{$object})) {
    #    my $lu_object = $luns->{$object};
    #    $result = $result_value_type eq "lun-id" ? $lu_object->{$qs_api_variables->{'lunid'}} : $dev_prefix . $lu_object->{$qs_api_variables->{'extentpath'}};
    #    syslog("info",(caller(0))[3] . " '$object' with key '$result_value_type' found with value: '$result'");
    #} else {
    #    syslog("info", (caller(0))[3] . " '$object' with key '$result_value_type' was not found");
    #}
    return $result;
}

#
#
# Optimzed
sub run_list_extent {
    qs_write_to_log("LunCmd/QuantaStor.pm - run_list_extent");
    my ($scfg, $timeout, $method, @params) = @_;
    #my $object = $params[0];
    #syslog("info", (caller(0))[3] . " : called with (method: '$method'; params[0]: '$object')");
    my $result = undef;
    #my $luns = qs_list_lu($scfg);

    #$object =~ s/^\Q$dev_prefix//;
    #syslog("info", (caller(0))[3] . " TrueNAS object to find: '$object'");
    #if (defined($luns->{$object})) {
    #    my $lu_object = $luns->{$object};
    #    $result = $lu_object->{$qs_api_variables->{'extentnaa'}};
    #    syslog("info",(caller(0))[3] . " '$object' wtih key '$qs_api_variables->{'extentnaa'}' found with value: '$result'");
    #} else {
    #    syslog("info",(caller(0))[3] . " '$object' with key '$qs_api_variables->{'extentnaa'}' was not found");
    #}
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

    #my $lun_path  = $params[0];

    #syslog("info", (caller(0))[3] . " : called with (method=$method; param[0]=$lun_path)");

    #my $lun_id    = qs_get_first_available_lunid($scfg);

    #die "Maximum number of LUNs per target is $MAX_LUNS" if scalar $lun_id >= $MAX_LUNS;
    #die "$params[0]: LUN $lun_path exists" if defined(run_list_lu($scfg, $timeout, $method, "name", @params));

    #my $target_id = qs_get_targetid($scfg);
    #die "Unable to find the target id for $scfg->{target}" if !defined($target_id);

    ## Create the extent
    #my $extent = qs_iscsi_create_extent($scfg, $lun_path);

    ## Associate the new extent to the target
    #my $link = qs_iscsi_create_target_to_extent($scfg, $target_id, $extent->{'id'}, $lun_id);

    #if (defined($link)) {
    #   syslog("info","QuantaStor::create_lu(lun_path=$lun_path, lun_id=$lun_id) : successful");
    #} else {
    #   die "Unable to create lun $lun_path";
    #}

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

    # remove the zvol
    my $res_storage_volume_delete = qs_storage_volume_delete($scfg->{qs_apiv4_host},
                                                            $scfg->{qs_username},
                                                            $scfg->{qs_password},
                                                            '',
                                                            300,
                                                            $res_vol_get->{id});

    #syslog("info", (caller(0))[3] . " : called with (method: '$method'; param[0]: '$lun_path')");

    #my $luns      = qs_list_lu($scfg);
    #my $lun       = undef;
    #my $link      = undef;
    #$lun_path =~ s/^\Q$dev_prefix//;

    #if (defined($luns->{$lun_path})) {
    #    $lun = $luns->{$lun_path};
    #    syslog("info",(caller(0))[3] . " lun: '$lun_path' found");
    #} else {
    #    die "Unable to find the lun $lun_path for $scfg->{target}";
    #}

    #my $target_id = qs_get_targetid($scfg);
    #die "Unable to find the target id for $scfg->{target}" if !defined($target_id);

    ## find the target to extent
    #my $target2extents = qs_iscsi_get_target_to_extent($scfg);

    #syslog("info", (caller(0))[3] . " : searching for 'targetextent' with (target_id=$target_id; lun_id=$lun->{$qs_api_variables->{'lunid'}}; extent_id=$lun->{id})");
    #foreach my $item (@$target2extents) {
    #    if($item->{$qs_api_variables->{'targetid'}} == $target_id &&
    #       $item->{$qs_api_variables->{'lunid'}} == $lun->{$qs_api_variables->{'lunid'}} &&
    #       $item->{$qs_api_variables->{'extentid'}} == $lun->{'id'}) {
    #        $link = $item;
    #        syslog("info", (caller(0))[3] . " : found 'targetextent'(target_id=$item->{$qs_api_variables->{'targetid'}}; lun_id=$item->{$qs_api_variables->{'lunid'}}; extent_id=$item->{$qs_api_variables->{'extentid'}})");
    #        last;
    #    }
    #}
    #die "Unable to find the link for the lun $lun_path for $scfg->{target}" if !defined($link);

    ## Remove the extent
    #my $remove_extent = qs_iscsi_remove_extent($scfg, $lun->{'id'});

    ## Remove the link
    #my $remove_link = qs_iscsi_remove_target_to_extent($scfg, $link->{'id'});

    #if($remove_link == 1 && $remove_extent == 1) {
    #    syslog("info", (caller(0))[3] . "(lun_path=$lun_path) : successful");
    #} else {
    #    die "Unable to delete lun $lun_path";
    #}

    return "";
}


sub qs_api_connect {
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_api_connect");
    my ($scfg) = @_;

    #syslog("info", (caller(0))[3] . " : called");

    #my $scheme = $scfg->{qs_use_ssl} ? "https" : "http";
    #my $apihost = defined($scfg->{qs_apiv4_host}) ? $scfg->{qs_apiv4_host} : $scfg->{portal};

    #if (! defined $qs_server_list->{$apihost}) {
    #    $qs_server_list->{$apihost} = REST::Client->new();
    #}
    #$qs_server_list->{$apihost}->setHost($scheme . '://' . $apihost);
    #$qs_server_list->{$apihost}->addHeader('Content-Type', 'application/json');
    #if (defined($scfg->{'truenas_token_auth'})) {
    #    syslog("info", (caller(0))[3] . " : Authentication using Bearer Token Auth");
    #    $qs_server_list->{$apihost}->addHeader('Authorization', 'Bearer ' . $scfg->{truenas_secret});
    #} else {
    #    syslog("info", (caller(0))[3] . " : Authentication using Basic Auth");
    #    $qs_server_list->{$apihost}->addHeader('Authorization', 'Basic ' . encode_base64($scfg->{qs_user} . ':' . $scfg->{qs_password}));
    #}
    ## If using SSL, don't verify SSL certs
    #if ($scfg->{qs_use_ssl}) {
    #    $qs_server_list->{$apihost}->getUseragent()->ssl_opts(verify_hostname => 0);
    #    $qs_server_list->{$apihost}->getUseragent()->ssl_opts(SSL_verify_mode => SSL_VERIFY_NONE);
    #}
    ## Check if the APIs are accessable via the selected host and scheme
    #my $api_response = $qs_server_list->{$apihost}->request('GET', $apiping);
    #my $code = $api_response->responseCode();
    #my $type = $api_response->responseHeader('Content-Type');
    #syslog("info", (caller(0))[3] . " : REST connection header Content-Type:'" . $type . "'");

    ## Make sure we are not recursion calling.
    #if ($runawayprevent > 2) {
    #    qs_api_log_error($qs_server_list->{$apihost});
    #    die "Loop recursion prevention";
    ## Successful connection
    #} elsif ($code == 200 && ($type =~ /^text\/plain/ || $type =~ /^application\/json/)) {
    #    syslog("info", (caller(0))[3] . " : REST connection successful to '" . $apihost . "' using the '" . $scheme . "' protocol");
    #    $runawayprevent = 0;
    ## A 302 or 200 (We already check for the correct 'type' above with a 200 so why add additional conditionals).
    ## So change to v2.0 APIs.
    #} elsif ($code == 302 || $code == 200) {
    #    syslog("info", (caller(0))[3] . " : Changing to v2.0 API's");
    #    $runawayprevent++;
    #    $apiping =~ s/v1\.0/v2\.0/;
    #    qs_api_connect($scfg);
    ## A 307 from QuantaStor means rediect http to https.
    #} elsif ($code == 307) {
    #    syslog("info", (caller(0))[3] . " : Redirecting to HTTPS protocol");
    #    $runawayprevent++;
    #    $scfg->{qs_use_ssl} = 1;
    #    qs_api_connect($scfg);
    ## For now, any other code we fail.
    #} else {
    #    qs_api_log_error($qs_server_list->{$apihost});
    #    die "Unable to connect to the QuantaStor API service at '" . $apihost . "' using the '" . $scheme . "' protocol";
    #}
    #$qs_rest_connection = $qs_server_list->{$apihost};
    return;
}

#
# Check to see what QuantaStor version we are running and set
# the QuantaStor.pm to use the correct API version of QuantaStor
#
sub qs_api_check {
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_api_check");
    my ($scfg, $timeout) = @_;
    #my $result = {};
    #my $apihost = defined($scfg->{qs_apiv4_host}) ? $scfg->{qs_apiv4_host} : $scfg->{portal};
#
    #syslog("info", (caller(0))[3] . " : called");
#
    #if (! defined $qs_rest_connection->{$apihost}) {
    #    qs_api_connect($scfg);
    #    eval {
    #        $result = decode_json($qs_rest_connection->responseContent());
    #    };
    #    if ($@) {
    #        $result = $qs_rest_connection->responseContent();
    #    } else {
    #        $result = $qs_rest_connection->responseContent();
    #    }
    #    $result =~ s/"//g;
    #    syslog("info", (caller(0))[3] . " : successful : Server version: " . $result);
    #    if ($result =~ /^(TrueNAS|FreeNAS)-(\d+)\.(\d+)\-U(\d+)(?(?=\.)\.(\d+))$/) {
    #        $product_name = $1;
    #        $truenas_version = sprintf("%02d%02d%02d%02d", $2, $3 || 0, $4 || 0, $5 || 0);
    #    } elsif ($result =~ /^(TrueNAS)-(\d+)\.(\d+)(?(?=\-U\d+)-U(\d+)|-\w+)(?(?=\.).(\d+))$/) {
    #        $product_name = $1;
    #        $truenas_version = sprintf("%02d%02d%02d%02d", $2, $3 || 0, $4 || 0, $6 || 0);
    #        $truenas_release_type = $5 || "Production";
    #    } elsif ($result =~ /^(TrueNAS-SCALE)-(\d+)\.(\d+)(?(?=\-)-(\w+))\.(\d+)(?(?=\.)\.(\d+))(?(?=\-)-(\d+))$/) {
    #        $product_name = $1;
    #        $truenas_version = sprintf("%02d%02d%02d%02d", $2, $3 || 0, $5 || 0, $7 || 0);
    #        $truenas_release_type = $4 || "Production";
    #    } else {
    #        $product_name = "Unknown";
    #        $truenas_release_type = "Unknown";
    #        syslog("error", (caller(0))[3] . " : Could not parse the version of TrueNAS.");
    #    }
    #    syslog("info", (caller(0))[3] . " : ". $product_name . " Unformatted Version: " . $truenas_version);
    #    if ($truenas_version >= 11030100) {
    #        $freenas_api_version = "v2.0";
    #        $dev_prefix = "/dev/";
    #    }
    #    if ($truenas_release_type ne "Production") {
    #        syslog("warn", (caller(0))[3] . " : The '" . $product_name . "' release type of '" . $truenas_release_type . "' may not worked due to unsupported changes.");
    #    }
    #} else {
    #    syslog("info", (caller(0))[3] . " : REST Client already initialized");
    #}
    #syslog("info", (caller(0))[3] . " : Using " . $product_name . " API version " . $freenas_api_version);
    #$freenas_api_methods   = $freenas_api_version_matrix->{$freenas_api_version}->{'methods'};
    #$freenas_api_variables = $freenas_api_version_matrix->{$freenas_api_version}->{'variables'};
    #$freenas_global_config = $freenas_global_config_list->{$apihost} = (!defined($freenas_global_config_list->{$apihost})) ? freenas_iscsi_get_globalconfiguration($scfg) : $freenas_global_config_list->{$apihost};

    return;
}


#
### FREENAS API CALLING ROUTINE ###
#
#sub qs_api_call {
#    my ($scfg, $method, $path, $data) = @_;
    #my $apihost = defined($scfg->{freenas_apiv4_host}) ? $scfg->{freenas_apiv4_host} : $scfg->{portal};
#
    #syslog("info", (caller(0))[3] . " : called for host '" . $apihost . "'");
#
    #$method = uc($method);
    #if (! $method =~ /^(?>GET|DELETE|POST)$/) {
    #    syslog("info", (caller(0))[3] . " : Invalid HTTP RESTful service method '$method'");
    #    die "Invalid HTTP RESTful service method '$method' used.";
    #}
#
    #if (! defined $freenas_server_list->{$apihost}) {
    #    freenas_api_check($scfg);
    #}
    #$freenas_rest_connection = $freenas_server_list->{$apihost};
    #$freenas_global_config = $freenas_global_config_list->{$apihost};
    #my $json_data = (defined $data) ? encode_json($data) : undef;
    #$freenas_rest_connection->request($method, $path, $json_data);
    #syslog("info", (caller(0))[3] . " : successful");

#    return;
#}

#
# Writes the Response and Content to SysLog
#
sub qs_api_log_error {
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_api_log_error");
    my ($rest_connection) = @_;
    #my $connection = ((defined $rest_connection) ? $rest_connection : $qs_rest_connection);
    #syslog("info","[ERROR]FreeNAS::API::" . (caller(1))[3] . " : Response code: " . $connection->responseCode());
    #syslog("info","[ERROR]FreeNAS::API::" . (caller(1))[3] . " : Response content: " . $connection->responseContent());
    return 1;
}

#
#
#
sub qs_iscsi_get_globalconfiguration {
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_iscsi_get_globalconfiguration");
    my ($scfg) = @_;

    #qs_api_call($scfg, 'GET', $qs_api_methods->{'config'}->{'resource'}, $qs_api_methods->{'config'}->{'get'});
    #my $code = $qs_rest_connection->responseCode();
    #if ($code == 200) {
    #    my $result = decode_json($qs_rest_connection->responseContent());
    #    syslog("info", (caller(0))[3] . " : target_basename=" . $result->{$qs_api_variables->{'basename'}});
    #    return $result;
    #} else {
    #    qs_api_log_error();
    #    return undef;
    #}
}

#
# Returns a list of all extents.
#
sub qs_iscsi_get_extent {
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_iscsi_get_extent");
    my ($scfg) = @_;

    #qs_api_call($scfg, 'GET', $qs_api_methods->{'extent'}->{'resource'} . "?limit=0", $qs_api_methods->{'extent'}->{'get'});
    #my $code = $qs_rest_connection->responseCode();
    #if ($code == 200) {
    #    my $result = decode_json($qs_rest_connection->responseContent());
    #    syslog("info", (caller(0))[3] . " : successful");
    #    return $result;
    #} else {
    #    qs_api_log_error();
    #    return undef;
    #}
}

#
# Create an extent on FreeNas
# http://api.freenas.org/resources/iscsi/index.html#create-resource
# Parameters:
#   - target config (scfg)
#   - lun_path
#
sub qs_iscsi_create_extent {
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_iscsi_create_extent");
    my ($scfg, $lun_path) = @_;

    #my $name = $lun_path;
    #$name  =~ s/^.*\///; # all from last /

    #my $pool = $scfg->{'pool'};
    ## If TrueNAS-SCALE the slashes (/) need to be converted to dashes (-)
    #if ($product_name eq "TrueNAS-SCALE") {
    #    $pool =~ s/\//-/g;
    #    syslog("info", (caller(0))[3] . " : TrueNAS-SCALE slash to dash conversion '" . $pool ."'");
    #}
    #$name  = $pool . ($product_name eq "TrueNAS-SCALE" ? '-' : '/') . $name;
    #syslog("info", (caller(0))[3] . " : " . $product_name . " extent '". $name . "'");

    #my $device = $lun_path;
    #$device =~ s/^\/dev\///; # strip /dev/

    #my $post_body = {};
    #while ((my $key, my $value) = each %{$qs_api_methods->{'extent'}->{'post_body'}}) {
    #    $post_body->{$key} = ($value =~ /^\$.+$/) ? eval $value : $value;
    #}

    #qs_api_call($scfg, 'POST', $qs_api_methods->{'extent'}->{'resource'}, $post_body);
    #my $code = $qs_rest_connection->responseCode();
    #if ($code == 200 || $code == 201) {
    #    my $result = decode_json($qs_rest_connection->responseContent());
    #    syslog("info", "FreeNAS::API::create_extent(lun_path=" . $result->{$qs_api_variables->{'extentpath'}} . ") : successful");
    #    return $result;
    #} else {
    #    qs_api_log_error();
    #    return undef;
    #}
}

#
# Remove an extent by it's id
# http://api.freenas.org/resources/iscsi/index.html#delete-resource
# Parameters:
#    - scfg
#    - extent_id
#
sub qs_iscsi_remove_extent {
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_iscsi_remove_extent");
    my ($scfg, $extent_id) = @_;

    #qs_api_call($scfg, 'DELETE', $qs_api_methods->{'extent'}->{'resource'} . (($qs_api_version eq "v2.0") ? "id/" : "") . "$extent_id/", $qs_api_methods->{'extent'}->{'delete_body'});
    #my $code = $qs_rest_connection->responseCode();
    #if ($code == 200 || $code == 204) {
    #    syslog("info", (caller(0))[3] . "(extent_id=$extent_id) : successful");
    #    return 1;
    #} else {
    #    qs_api_log_error();
    #    return 0;
    #}
}

#
# Returns a list of all targets
# http://api.freenas.org/resources/iscsi/index.html#get--api-v1.0-services-iscsi-target-
#
sub qs_iscsi_get_target {
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_iscsi_get_target");
    my ($scfg) = @_;

    #qs_api_call($scfg, 'GET', $qs_api_methods->{'target'}->{'resource'} . "?limit=0", $qs_api_methods->{'target'}->{'get'});
    #my $code = $qs_rest_connection->responseCode();
    #if ($code == 200) {
    #    my $result = decode_json($qs_rest_connection->responseContent());
    #    syslog("info", (caller(0))[3] . " : successful");
    #    return $result;
    #} else {
    #    qs_api_log_error();
    #    return undef;
    #}
}

#
# Returns a list of associated extents to targets
# http://api.freenas.org/resources/iscsi/index.html#get--api-v1.0-services-iscsi-targettoextent-
#
sub qs_iscsi_get_target_to_extent {
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_iscsi_get_target_to_extent");
    my ($scfg) = @_;

    #qs_api_call($scfg, 'GET', $qs_api_methods->{'targetextent'}->{'resource'} . "?limit=0", $qs_api_methods->{'targetextent'}->{'get'});
    #my $code = $qs_rest_connection->responseCode();
    #if ($code == 200) {
    #    my $result = decode_json($qs_rest_connection->responseContent());
    #    syslog("info", (caller(0))[3] . " : successful");
    #    # If 'iscsi_lunid' is undef then it is set to 'Auto' in FreeNAS
    #    # which should be '0' in our eyes.
    #    # This gave Proxmox 5.x and FreeNAS 11.1 a few issues.
    #    foreach my $item (@$result) {
    #        if (!defined($item->{$qs_api_variables->{'lunid'}})) {
    #            $item->{$qs_api_variables->{'lunid'}} = 0;
    #            syslog("info", (caller(0))[3] . " : change undef iscsi_lunid to 0");
    #        }
    #    }
    #    return $result;
    #} else {
    #    qs_api_log_error();
    #    return undef;
    #}
}

#
# Associate a FreeNas extent to a FreeNas Target
# http://api.freenas.org/resources/iscsi/index.html#post--api-v1.0-services-iscsi-targettoextent-
# Parameters:
#   - target config (scfg)
#   - FreeNas Target ID
#   - FreeNas Extent ID
#   - Lun ID
#
sub qs_iscsi_create_target_to_extent {
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_iscsi_create_target_to_extent");
    my ($scfg, $target_id, $extent_id, $lun_id) = @_;

    #my $post_body = {};
    #while ((my $key, my $value) = each %{$qs_api_methods->{'targetextent'}->{'post_body'}}) {
    #    $post_body->{$key} = ($value =~ /^\$.+$/) ? eval $value : $value;
    #}

    #qs_api_call($scfg, 'POST', $qs_api_methods->{'targetextent'}->{'resource'}, $post_body);
    #my $code = $qs_rest_connection->responseCode();
    #if ($code == 200 || $code == 201) {
    #    my $result = decode_json($qs_rest_connection->responseContent());
    #    syslog("info", (caller(0))[3] . "(target_id=$target_id, extent_id=$extent_id, lun_id=$lun_id) : successful");
    #    return $result;
    #} else {
    #    qs_api_log_error();
    #    return undef;
    #}
}

#
# Remove a Target to extent by it's id
# http://api.freenas.org/resources/iscsi/index.html#delete--api-v1.0-services-iscsi-targettoextent-(int-id)-
# Parameters:
#    - scfg
#    - link_id
#
sub qs_iscsi_remove_target_to_extent {
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_iscsi_remove_target_to_extent");
    my ($scfg, $link_id) = @_;

    #if ($qs_api_version eq "v2.0") {
    #    syslog("info", (caller(0))[3] . "(link_id=$link_id) : V2.0 API's so NOT Needed...successful");
    #    return 1;
    #}

    #qs_api_call($scfg, 'DELETE', $qs_api_methods->{'targetextent'}->{'resource'} . (($qs_api_version eq "v2.0") ? "id/" : "") . "$link_id/", $qs_api_methods->{'targetextent'}->{'delete_body'});
    #my $code = $qs_rest_connection->responseCode();
    #if ($code == 200 || $code == 204) {
    #    syslog("info", (caller(0))[3] . "(link_id=$link_id) : successful");
    #    return 1;
    #} else {
    #    qs_api_log_error();
    #    return 0;
    #}
}

#
# Returns all luns associated to the current target defined by $scfg->{target}
# This method returns an array reference like "freenas_iscsi_get_extent" do
# but with an additionnal hash entry "iscsi_lunid" retrieved from "freenas_iscsi_get_target_to_extent"
#
sub qs_list_lu {
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_list_lu");
    my ($scfg) = @_;

    my $targets   = qs_iscsi_get_target($scfg);
    my $target_id = qs_get_targetid($scfg);

    my %lun_hash;
    #my $iscsi_lunid = undef;

    #if(defined($target_id)) {
    #    my $target2extents = qs_iscsi_get_target_to_extent($scfg);
    #    my $extents        = qs_iscsi_get_extent($scfg);

    #    foreach my $item (@$target2extents) {
    #        if($item->{$qs_api_variables->{'targetid'}} == $target_id) {
    #            foreach my $node (@$extents) {
    #                if($node->{'id'} == $item->{$qs_api_variables->{'extentid'}}) {
    #                    if ($item->{$qs_api_variables->{'lunid'}} =~ /(\d+)/) {
    #                        if (defined($node)) {
    #                            $node->{$qs_api_variables->{'lunid'}} .= "$1";
    #                            $lun_hash{$node->{$qs_api_variables->{'extentpath'}}} = $node;
    #                        }
    #                        last;
    #                    } else {
    #                        syslog("warn", (caller(0))[3] . " : iscsi_lunid did not pass tainted testing");
    #                    }
    #                }
    #            }
    #        }
    #    }
    #}
    #syslog("info", (caller(0))[3] . " : successful");
    return \%lun_hash;
}

sub qs_zfs_create_zvol {
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_create_zvol");
    my ($scfg, $zvol, $size) = @_;

    # run qs storageVolumeCreate API
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_create_zvol - creating zvol: $zvol with size: $size, pool: $scfg->{pool}");
    my $create_response = qs_storage_volume_create($scfg->{qs_apiv4_host}, $scfg->{qs_username}, $scfg->{qs_password}, '', 300, $zvol, $size, $scfg->{pool});
}

#
# Returns the first available "lunid" (in all targets namespaces)
#
sub qs_get_first_available_lunid {
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_get_first_available_lunid");
    my ($scfg) = @_;

    #my $target_id      = qs_get_targetid($scfg);
    #my $target2extents = qs_iscsi_get_target_to_extent($scfg);
    #my @luns           = ();

    #foreach my $item (@$target2extents) {
    #    push(@luns, $item->{$qs_api_variables->{'lunid'}}) if ($item->{$qs_api_variables->{'targetid'}} == $target_id);
    #}

    #my @sorted_luns =  sort {$a <=> $b} @luns;
    my $lun_id      = 0;

    ## find the first hole, if not, give the +1 of the last lun
    #foreach my $lun (@sorted_luns) {
    #    last if $lun != $lun_id;
    #    $lun_id = $lun_id + 1;
    #}

    #syslog("info", (caller(0))[3] . " : $lun_id");
    return $lun_id;
}

#
# Returns the target id on FreeNas of the currently configured target of this PVE storage
#
sub qs_get_targetid {
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_get_targetid");
    my ($scfg) = @_;

    #my $targets   = qs_iscsi_get_target($scfg);
    my $target_id = undef;

    #foreach my $target (@$targets) {
    #    my $iqn = $qs_global_config->{$qs_api_variables->{'basename'}} . ':' . $target->{$qs_api_variables->{'targetname'}};
    #    if($iqn eq $scfg->{target}) {
    #        $target_id = $target->{'id'};
    #        last;
    #    }
    #}
    #syslog("info", (caller(0))[3] . " : successful : $target_id");
    return $target_id;
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

    #my $text = $class->zfs_request(
	#$scfg,
	#10,
	#'list',
	#'-o',
	#'name,volsize,origin,type,refquota',
	#'-t',
	#'volume,filesystem',
	#'-d1',
	#'-Hp',
	#$scfg->{pool},
    #);
    ## It's still required to have qs_zfs_parse_zvol_list filter by pool, because -d1 lists
    ## $scfg->{pool} too and while unlikely, it could be named to be mistaken for a volume.
    #my $zvols = qs_zfs_parse_zvol_list($text, $scfg->{pool});
    #return {} if !$zvols;

    #instead of this, use qs_storage_volume_list API
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
    # example: only return zvols from specified pool
    #[
    #   {
    #      "cachePolicyPrimary" : 0,
    #      "mappingDisabled" : false,
    #      "spaceUtilized" : 57344,
    #      "createdByScheduleType" : 0,
    #      "enableWriteCache" : false,
    #      "modifiedByUserId" : "437bb0da-549e-6619-ea0e-a91e05e6befb",
    #      "name" : "test-target",
    #      "spaceUtilizedBySnapshots" : 0,
    #      "cachePolicySecondary" : 0,
    #      "vvolType" : 0,
    #      "size" : 10737418240,
    #      "type" : 3,
    #      "compressionType" : "on",
    #      "compressionRatio" : "1.00",
    #      "vvolParentId" : null,
    #      "ownershipRevision" : 0,
    #      "qosReadIops" : 0,
    #      "createdTimeStamp" : "2025-10-17 16:21:44+00:00",
    #      "volumeType" : 5,
    #      "qosWriteBandwidth" : 0,
    #      "logicalSpaceUtilized" : 28672,
    #      "snapshotCount" : 0,
    #      "lun" : 0,
    #      "qosReadBandwidth" : 0,
    #      "accessMode" : 0,
    #      "modifiedTimeStamp" : "2025-10-17 16:21:46+00:00",
    #      "usedByRefReservation" : 0,
    #      "chapUsername" : null,
    #      "relativeTargetId" : 0,
    #      "chapPassword" : null,
    #      "eui" : "eui.3330633832623832",
    #      "storageLinkId" : "OSNEXUS__QUANTASTOR__e0583283__30c82b82",
    #      "isActiveCheckpoint" : false,
    #      "target" : 0,
    #      "lazyCloneSnapshotPath" : null,
    #      "syncPolicy" : 0,
    #      "description" : "None",
    #      "deviceDescriptor" : "30c82b82e9c306efe0583283",
    #      "chapPolicy" : 6,
    #      "qosWriteIops" : 0,
    #      "stripeSizeKb" : 0,
    #      "mountPath" : "/dev/zvol/qs-7b6f4eb4-0d07-6966-6442-3b3730925e55/30c82b82-e9c3-06ef-cd5e-d5e15a4a1f4f",
    #      "devicePath" : null,
    #      "resumeToken" : null,
    #      "cloudContainerId" : null,
    #      "snapshotParent" : null,
    #      "createdBySchedule" : null,
    #      "storageSystemId" : "e0583283-350e-5173-06b3-816ee0f374cf",
    #      "portalGroupId" : null,
    #      "clones" : null,
    #      "state" : 0,
    #      "storagePoolId" : "7b6f4eb4-0d07-6966-6442-3b3730925e55",
    #      "accessTimeStamp" : "1970-01-01 00:00:00+00:00",
    #      "useGuidIqn" : false,
    #      "stateDetail" : null,
    #      "blockSizeKb" : 64,
    #      "spaceReserved" : 0,
    #      "isRemote" : false,
    #      "createdByUserId" : "437bb0da-549e-6619-ea0e-a91e05e6befb",
    #      "profileId" : "1625cdb7-5d25-d9f6-99fd-2779f44095b6",
    #      "isSnapshot" : false,
    #      "stripeCount" : 0,
    #      "lunAssignmentPolicy" : 0,
    #      "qosPolicyId" : null,
    #      "internalUse" : 0,
    #      "snapshotReferenceId" : null,
    #      "numHolds" : 0,
    #      "copies" : 1,
    #      "iqn" : "iqn.2009-10.com.osnexus:7b6f4eb4-30c82b82e9c306ef:test-target",
    #      "cephClusterId" : null,
    #      "id" : "30c82b82-e9c3-06ef-cd5e-d5e15a4a1f4f",
    #      "isCloudBackup" : false,
    #      "retentionTags" : 0,
    #      "customId" : null
    #   },
    #   {
    #      "cachePolicySecondary" : 0,
    #      "size" : 10737418240,
    #      "vvolType" : 0,
    #      "spaceUtilizedBySnapshots" : 0,
    #      "compressionRatio" : "1.00",
    #      "vvolParentId" : null,
    #      "type" : 3,
    #      "compressionType" : "on",
    #      "spaceUtilized" : 57344,
    #      "createdByScheduleType" : 0,
    #      "cachePolicyPrimary" : 0,
    #      "mappingDisabled" : false,
    #      "name" : "vm-100-disk-0",
    #      "enableWriteCache" : false,
    #      "modifiedByUserId" : "437bb0da-549e-6619-ea0e-a91e05e6befb",
    #      "relativeTargetId" : 47,
    #      "chapPassword" : null,
    #      "eui" : "eui.6635653462663565",
    #      "chapUsername" : null,
    #      "target" : 9,
    #      "storageLinkId" : "OSNEXUS__QUANTASTOR__e0583283__f5e4bf5e",
    #      "isActiveCheckpoint" : false,
    #      "volumeType" : 5,
    #      "qosWriteBandwidth" : 0,
    #      "lun" : 1,
    #      "snapshotCount" : 0,
    #      "logicalSpaceUtilized" : 28672,
    #      "qosReadIops" : 0,
    #      "ownershipRevision" : 0,
    #      "createdTimeStamp" : "2025-10-21 21:12:47+00:00",
    #      "modifiedTimeStamp" : "2025-10-21 21:12:49+00:00",
    #      "usedByRefReservation" : 10737360896,
    #      "accessMode" : 0,
    #      "qosReadBandwidth" : 0,
    #      "snapshotParent" : null,
    #      "portalGroupId" : null,
    #      "clones" : null,
    #      "storageSystemId" : "e0583283-350e-5173-06b3-816ee0f374cf",
    #      "createdBySchedule" : null,
    #      "resumeToken" : null,
    #      "cloudContainerId" : null,
    #      "storagePoolId" : "7b6f4eb4-0d07-6966-6442-3b3730925e55",
    #      "accessTimeStamp" : "1970-01-01 00:00:00+00:00",
    #      "state" : 0,
    #      "syncPolicy" : 0,
    #      "lazyCloneSnapshotPath" : null,
    #      "stripeSizeKb" : 0,
    #      "devicePath" : null,
    #      "mountPath" : "/dev/zvol/qs-7b6f4eb4-0d07-6966-6442-3b3730925e55/f5e4bf5e-37a6-ac01-ca14-f52266ebddbf",
    #      "deviceDescriptor" : "f5e4bf5e37a6ac01e0583283",
    #      "description" : "None",
    #      "qosWriteIops" : 0,
    #      "chapPolicy" : 0,
    #      "iqn" : "iqn.2009-10.com.osnexus:7b6f4eb4-f5e4bf5e37a6ac01:vm-100-disk-0",
    #      "copies" : 1,
    #      "cephClusterId" : null,
    #      "numHolds" : 0,
    #      "snapshotReferenceId" : null,
    #      "customId" : null,
    #      "isCloudBackup" : false,
    #      "id" : "f5e4bf5e-37a6-ac01-ca14-f52266ebddbf",
    #      "retentionTags" : 0,
    #      "isRemote" : false,
    #      "spaceReserved" : 10737418240,
    #      "blockSizeKb" : 64,
    #      "createdByUserId" : "437bb0da-549e-6619-ea0e-a91e05e6befb",
    #      "stateDetail" : null,
    #      "useGuidIqn" : false,
    #      "qosPolicyId" : null,
    #      "stripeCount" : 0,
    #      "lunAssignmentPolicy" : 1,
    #      "internalUse" : 0,
    #      "profileId" : null,
    #      "isSnapshot" : false
    #   }
    #]
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

    #my @lines = split /\n/, $text;
    #foreach my $line (@lines) {
	#my ($dataset, $size, $origin, $type, $refquota) = split(/\s+/, $line);
    #qs_write_to_log("LunCmd/QuantaStorPlugin.pm - qs_zfs_parse_zvol_list - processing line: '$line'");
	#next if !($type eq 'volume' || $type eq 'filesystem');
#
	#my $zvol = {};
	#my @parts = split /\//, $dataset;
	#next if scalar(@parts) < 2; # we need pool/name
	#my $name = pop @parts;
	#my $parsed_pool = join('/', @parts);
    #qs_write_to_log("LunCmd/QuantaStorPlugin.pm - qs_zfs_parse_zvol_list - processing dataset: '$dataset' (parsed_pool: '$parsed_pool', name: '$name')");
	#next if $parsed_pool ne $pool;
#
	#next unless $name =~ m!^(vm|base|subvol|basevol)-(\d+)-(\S+)$!;
	#$zvol->{owner} = $2;
#
	#$zvol->{name} = $name;
	#if ($type eq 'filesystem') {
	#    if ($refquota eq 'none') {
	#	$zvol->{size} = 0;
	#    } else {
	#	$zvol->{size} = $refquota + 0;
	#    }
	#    $zvol->{format} = 'subvol';
	#} else {
	#    $zvol->{size} = $size + 0;
	#    $zvol->{format} = 'raw';
	#}
	#if ($origin !~ /^-$/) {
	#    $zvol->{origin} = $origin;
	#}
	#push @$list, $zvol;
    #}

    return $list;
}




1;