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

use PVE::Storage::Plugin;
our $MAX_VOLUMES_PER_GUEST = 1024;

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
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_path - parsed volname: vtype=$vtype, name=$name, vmid=$vmid");
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
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_parse_volname $volname");

    if ($volname =~ m/^(((base|basevol)-(\d+)-\S+)\/)?((base|basevol|vm|subvol)-(\d+)-\S+)$/) {
	my $format = ($6 eq 'subvol' || $6 eq 'basevol') ? 'subvol' : 'raw';
	my $isBase = ($6 eq 'base' || $6 eq 'basevol');
	return ('images', $5, $7, $2, $4, $isBase, $format);
    }

    die "unable to parse zfs volume name '$volname'\n";
}

sub qs_api_call {
    #qs_write_to_log("LunCmd/QuantaStor.pm - qs_api_call");
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
    my $response = $ua->get($url);

    # Check response status
    if ($response->is_success) {
        return decode_json($response->decoded_content); # Return raw Perl data structure
    } else {
        qs_write_to_log("LunCmd/QuantaStor.pm - qs_api_call - HTTP GET Request failed: " . $response->status_line);
        qs_write_to_log("Response content: " . $response->decoded_content . "\n");
        qs_write_to_log("HTTP GET Request failed: " . $response->status_line);
        return '';
    }

    return '';
}

sub qs_storage_pool_get {
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_storage_pool_get");
    my ($server_ip, $username, $password, $cert_path, $timeout, $storagePool) = @_;
    # return qs_api_call($server_ip, $username, $password, 'storagePoolEnum', { }, $cert_path, $timeout);

    my $api_name = 'storagePoolGet';
    my $query_params = { storagePool => $storagePool };

    my $response = qs_api_call($server_ip, $username, $password, $api_name, $query_params, $cert_path, $timeout);

    # Prettify the response for output
    #my $pretty_result = to_json($response, { utf8 => 1, pretty => 1 });
    # print "Response:\n$pretty_result\n";
    #qs_write_to_log("LunCmd/QuantaStor.pm - qs_storage_pool_get - Response:\n$pretty_result\n");

    return $response;
}

sub qs_storage_volume_enum {
    my ($server_ip, $username, $password, $cert_path, $timeout, $storageVolumeList) = @_;
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
    my $query_params = {
        name => $name,
        size => $size * 1024,
        provisionableId => $pool,
        description => 'Created by Proxmox VE Plugin'
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

    my $api_name = 'storageVolumeDelete';
    my $query_params = {
        storageVolumeList => $storageVolume,
        deleteOptions => 4, # delete parent and snaps
        flags => 2 # Force delete
    };

    my $response = qs_api_call($server_ip, $username, $password, $api_name, $query_params, $cert_path, $timeout);

    # Prettify the response for output
    # my $pretty_result = to_json($response, { utf8 => 1, pretty => 1 });
    # print "Response:\n$pretty_result\n";
    # qs_write_to_log("LunCmd/QuantaStor.pm - qs_storage_volume_delete - Response:\n$pretty_result\n");

    return $response;
}

sub qs_storage_volume_modify {
    my ($server_ip, $username, $password, $cert_path, $timeout, $storageVolume, $newName) = @_;
    # return qs_api_call($server_ip, $username, $password, 'storagePoolEnum', { }, $cert_path, $timeout);
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_storage_volume_modify $newName");

    my $api_name = 'storageVolumeModify';
    my $query_params = {
        storageVolume => $storageVolume,
        newName => $newName,
        newDescription => 'Modified by Proxmox VE Plugin'
    };

    my $response = qs_api_call($server_ip, $username, $password, $api_name, $query_params, $cert_path, $timeout);

    # Prettify the response for output
    my $pretty_result = to_json($response, { utf8 => 1, pretty => 1 });
    # print "Response:\n$pretty_result\n";
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_storage_volume_modify - Response:\n$pretty_result\n");

    return $response;
}

sub qs_storage_volume_snapshot {
    my ($server_ip, $username, $password, $cert_path, $timeout, $storageVolume, $snapshotName) = @_;
    # return qs_api_call($server_ip, $username, $password, 'storagePoolEnum', { }, $cert_path, $timeout);
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_storage_volume_snapshot $storageVolume snapshot name: $snapshotName");

    my $api_name = 'storageVolumeSnapshot';
    my $query_params = {
        storageVolume => $storageVolume,
        snapshotName => $snapshotName,
        description => 'Snapshot created by Proxmox VE Plugin'
    };

    my $response = qs_api_call($server_ip, $username, $password, $api_name, $query_params, $cert_path, $timeout);

    # Prettify the response for output
    # my $pretty_result = to_json($response, { utf8 => 1, pretty => 1 });
    # print "Response:\n$pretty_result\n";
    # qs_write_to_log("LunCmd/QuantaStor.pm - qs_storage_volume_snapshot - Response:\n$pretty_result\n");

    return $response;
}

#// @doc Roll Storage Volume back from the most recent snapshot.
#int osn__storageVolumeRollback(
#    /*in*/ xsd__string storageVolume,  //@doc Name or UUID of the Storage Volume
#    /*in*/ xsd__string snapshotVolume, //@doc Snapshot Name or UUID to roll back the Storage Volume from. Needs to be the most recent snapshot
#    /*in*/ xsd__unsignedInt flags,
#    /*out*/ struct osn__storageVolumeRollbackResponse {
#        osn__task task;
#        osn__storageVolume obj;
#    } & r);

sub qs_storage_volume_rollback {
    my ($server_ip, $username, $password, $cert_path, $timeout, $storageVolume, $snapshotVolume) = @_;
    # return qs_api_call($server_ip, $username, $password, 'storagePoolEnum', { }, $cert_path, $timeout);
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_storage_volume_rollback $storageVolume snapshot name: $snapshotVolume");

    my $api_name = 'storageVolumeRollback';
    my $query_params = {
        storageVolume => $storageVolume,
        snapshotVolume => $snapshotVolume,
    };

    my $response = qs_api_call($server_ip, $username, $password, $api_name, $query_params, $cert_path, $timeout);

    # Prettify the response for output
    my $pretty_result = to_json($response, { utf8 => 1, pretty => 1 });
    # print "Response:\n$pretty_result\n";
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_storage_volume_rollback - Response:\n$pretty_result\n");

    return $response;
}

sub qs_storage_volume_clone {
    my ($server_ip, $username, $password, $cert_path, $timeout, $storageVolume, $cloneName) = @_;
    # return qs_api_call($server_ip, $username, $password, 'storagePoolEnum', { }, $cert_path, $timeout);
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_storage_volume_clone $storageVolume clone name: $cloneName");

    my $api_name = 'storageVolumeClone';
    my $query_params = {
        storageVolume => $storageVolume,
        cloneName => $cloneName,
        description => 'Clone created by Proxmox VE Plugin'
    };

    my $response = qs_api_call($server_ip, $username, $password, $api_name, $query_params, $cert_path, $timeout);

    # Prettify the response for output
    # my $pretty_result = to_json($response, { utf8 => 1, pretty => 1 });
    # print "Response:\n$pretty_result\n";
    # qs_write_to_log("LunCmd/QuantaStor.pm - qs_storage_volume_clone - Response:\n$pretty_result\n");

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
    # my $pretty_result = to_json($response, { utf8 => 1, pretty => 1 });
    # print "Response:\n$pretty_result\n";
    # qs_write_to_log("LunCmd/QuantaStor.pm - qs_storage_volume_acl_add - Response:\n$pretty_result\n");

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
    # my $pretty_result = to_json($response, { utf8 => 1, pretty => 1 });
    # print "Response:\n$pretty_result\n";
    # qs_write_to_log("LunCmd/QuantaStor.pm - qs_storage_volume_acl_remove - Response:\n$pretty_result\n");

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

sub qs_storage_volume_session_enum {
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_storage_volume_session_enum");
    my ($server_ip, $username, $password, $cert_path, $timeout, $storageVolume) = @_;
    # return qs_api_call($server_ip, $username, $password, 'storagePoolEnum', { }, $cert_path, $timeout);

    my $api_name = 'sessionEnum';
    my $query_params = { storageVolume => $storageVolume };

    my $response = qs_api_call($server_ip, $username, $password, $api_name, $query_params, $cert_path, $timeout);

    # Prettify the response for output
    my $pretty_result = to_json($response, { utf8 => 1, pretty => 1 });
    # print "Response:\n$pretty_result\n";
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_storage_volume_session_enum - Response:\n$pretty_result\n");

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
    # my $pretty_result = to_json($response, { utf8 => 1, pretty => 1 });
    # print "Response:\n$pretty_result\n";
    # qs_write_to_log("LunCmd/QuantaStor.pm - qs_host_add - Response:\n$pretty_result\n");

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
    # check to make sure the zvol exists
    if (!defined($res_vol_get->{id})) {
        die "LUN $zvol_name does not exist.";
    }

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
    my $create_response = qs_storage_volume_create($scfg->{qs_apiv4_host}, $scfg->{qs_username}, $scfg->{qs_password}, '', 300, $zvol, $size, $trim_pool_name);
}

sub qs_zfs_get_command {
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_zfs_get_command");
    my ($scfg, $timeout, $method, @params) = @_;
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_zfs_get_command - called with (method: '$method'; params '@params')");
    my $param_str = join(' ', @params);
    my ($uuid) = $param_str =~ /qs-([0-9a-fA-F-]{36})/;
    qs_write_to_log("LunCmd/QuantaStor.pm - qs_zfs_get_command - getting qs pool with UUID '$uuid'");

    my $res_pool_get = qs_storage_pool_get($scfg->{qs_apiv4_host},
                                            $scfg->{qs_username},
                                            $scfg->{qs_password},
                                            '',
                                            300,
                                            $uuid);

    # Extract values
    my $size  = $res_pool_get->{size};
    my $free  = $res_pool_get->{freeSpace};
    my $used  = $size - $free;

    my $msg = "$free\n$used";

    qs_write_to_log("LunCmd/QuantaStor.pm - qs_zfs_get_command - returning:\n$msg");

    return $msg;
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
    PVE::Storage::LunCmd::QuantaStorPlugin::qs_write_to_log("LunCmd/QuantaStorPlugin.pm - zfs_delete_zvol - called with (zvol: '$zvol')");

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

sub qs_get_zvol_id_by_name {
    my ($scfg, $zvol_name) = @_;
    PVE::Storage::LunCmd::QuantaStorPlugin::qs_write_to_log("LunCmd/QuantaStorPlugin.pm - qs_get_zvol_id_by_name - called with (zvol_name: '$zvol_name')");

    my $res_vol_get = qs_storage_volume_get($scfg->{qs_apiv4_host},
                                            $scfg->{qs_username},
                                            $scfg->{qs_password},
                                            '',
                                            300,
                                            $zvol_name);

    return $res_vol_get->{id};
}

sub qs_create_base {
    PVE::Storage::LunCmd::QuantaStorPlugin::qs_write_to_log("LunCmd/QuantaStorPlugin.pm - create_base");
    my ($storeid, $scfg, $basename, $volname) = @_;

    my $newname = $volname;
    $newname =~ s/^vm-/base-/;

    # get the storage volume info from quantastor
    # verify the zvol exists.
    my $res_vol_get = qs_storage_volume_get($scfg->{qs_apiv4_host},
                                            $scfg->{qs_username},
                                            $scfg->{qs_password},
                                            '',
                                            300,
                                            $volname);

    # logout of iscsi targets before renaming
    PVE::Storage::LunCmd::QuantaStorPlugin::qs_write_to_log("LunCmd/QuantaStorPlugin.pm - create_base - logging out of $volname iqn $res_vol_get->{iqn}");
    my $res_logout = qs_iscsi_target_logout($scfg, $res_vol_get->{iqn});
    wait_for_volume_logout($scfg, $res_vol_get->{id});

    # remove storage volume acl entry for local host
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

    # modify the volname of the volume via qs API
    PVE::Storage::LunCmd::QuantaStorPlugin::qs_write_to_log("LunCmd/QuantaStorPlugin.pm - create_base - modifying volume name from $volname to $newname");
    my $res_volume_modify = qs_storage_volume_modify($scfg->{qs_apiv4_host},
                                            $scfg->{qs_username},
                                            $scfg->{qs_password},
                                            '',
                                            300,
                                            $res_vol_get->{id},
                                            $newname);

    # add storage volume acl entry for local host
    my $res_host_acl_add = qs_storage_volume_acl_add($scfg->{qs_apiv4_host},
                                                     $scfg->{qs_username},
                                                     $scfg->{qs_password},
                                                     '',
                                                     300,
                                                     $res_vol_get->{id},
                                                     $local_host_iqn);

    # login to modified iscsi target
    PVE::Storage::LunCmd::QuantaStorPlugin::qs_write_to_log("LunCmd/QuantaStorPlugin.pm - create_base - logging in to $newname iqn $res_volume_modify->{iqn}");
    my $res_login = qs_iscsi_target_login($scfg, $res_volume_modify->{obj}{iqn});

    PVE::Storage::LunCmd::QuantaStorPlugin::qs_write_to_log("LunCmd/QuantaStorPlugin.pm - create_base - taking snapshot of new base volume $newname");
    my $res_volume_snapshot = qs_storage_volume_snapshot($scfg->{qs_apiv4_host},
                                            $scfg->{qs_username},
                                            $scfg->{qs_password},
                                            '',
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
    my $res_vol_get = qs_storage_volume_get($scfg->{qs_apiv4_host},
                                            $scfg->{qs_username},
                                            $scfg->{qs_password},
                                            '',
                                            300,
                                            $srcvolname);

    PVE::Storage::LunCmd::QuantaStorPlugin::qs_write_to_log("LunCmd/QuantaStorPlugin.pm - qs_clone_image - cloning snapshot $srcvolname to new volume $name");
    my $res_volume_clone = qs_storage_volume_clone($scfg->{qs_apiv4_host},
                                                   $scfg->{qs_username},
                                                   $scfg->{qs_password},
                                                   '',
                                                   300,
                                                   $srcvolname,
                                                   $name);

    # add storage volume acl entry for local host
    my $local_host_iqn = get_initiator_name();
    my $res_host_get = qs_host_get($scfg->{qs_apiv4_host},
                                   $scfg->{qs_username},
                                   $scfg->{qs_password},
                                   '',
                                   300,
                                   $local_host_iqn);

    my $res_host_acl_add = qs_storage_volume_acl_add($scfg->{qs_apiv4_host},
                                                     $scfg->{qs_username},
                                                     $scfg->{qs_password},
                                                     '',
                                                     300,
                                                     $res_volume_clone->{obj}{id},
                                                     $local_host_iqn);

    # need to perform iscsi target login here
    PVE::Storage::LunCmd::QuantaStorPlugin::qs_write_to_log("LunCmd/QuantaStorPlugin.pm - qs_clone_image - logging in to $name iqn $res_volume_clone->{obj}{iqn}");
    my $res_login = qs_iscsi_target_login($scfg, $res_volume_clone->{obj}{iqn});

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
                                            $scfg->{qs_username},
                                            $scfg->{qs_password},
                                            '',
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
                                            $scfg->{qs_username},
                                            $scfg->{qs_password},
                                            '',
                                            300,
                                            $snap_name);
}

sub qs_volume_snapshot_rollback {
    my ($scfg, $storeid, $volname, $snap) = @_;
    qs_write_to_log("LunCmd/QuantaStorPlugin.pm - qs_volume_snapshot_rollback - called with (volname: '$volname')");
    my $vname = (qs_parse_volname($volname))[1];
    my $snap_name = $vname . "_$snap";

    # logout of iscsi target
    my $res_vol_get = qs_storage_volume_get($scfg->{qs_apiv4_host},
                                            $scfg->{qs_username},
                                            $scfg->{qs_password},
                                            '',
                                            300,
                                            $vname);

    my $res_logout = qs_iscsi_target_logout($scfg, $res_vol_get->{iqn});
    wait_for_volume_logout($scfg, $res_vol_get->{id});

    # run rollback
    my $res_volume_rollback = qs_storage_volume_rollback($scfg->{qs_apiv4_host},
                                            $scfg->{qs_username},
                                            $scfg->{qs_password},
                                            '',
                                            300,
                                            $res_vol_get->{id},
                                            $snap_name);


    # login to iscsi target
    my $res_login = qs_iscsi_target_login($scfg, $res_vol_get->{iqn});



    #$volname = ($class->parse_volname($volname))[1];

    #$class->zfs_delete_lu($scfg, $volname);

    #$class->zfs_request($scfg, undef, 'rollback', "$scfg->{pool}/$volname\@$snap");

    #$class->zfs_import_lu($scfg, $volname);

    #$class->zfs_add_lun_mapping_entry($scfg, $volname);
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
            $scfg->{qs_username},
            $scfg->{qs_password},
            '',
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

sub qs_volume_rollback_is_possible {
    my ($scfg, $storeid, $volname, $snap, $blockers) = @_;
    qs_write_to_log("LunCmd/QuantaStorPlugin.pm - qs_volume_rollback_is_possible - called with (volname: '$volname', snap: '$snap')");
    my $vname = (qs_parse_volname($volname))[1];
    my $snap_name = $vname . "_$snap";

    # check to see if this snapshot exists on the qs host
    my $res_volume_get = qs_storage_volume_get($scfg->{qs_apiv4_host},
                                            $scfg->{qs_username},
                                            $scfg->{qs_password},
                                            '',
                                            300,
                                            $snap_name);

    if (!defined($res_volume_get->{id})) {
        die "can't rollback, snapshot '$snap' does not exist on '$volname'\n";
    }

    # we need to see if this snapshot is the most recent snapshot
    # taken on this volume.
    my $res_storage_volume_enum = qs_storage_volume_enum($scfg->{qs_apiv4_host},
                                            $scfg->{qs_username},
                                            $scfg->{qs_password},
                                            '',
                                            300,
                                            '');

    # Parse the list of objects and verify that $res_volume_get->{createdTimeStamp} is the most recent
    # e.g. "createdTimeStamp": "2025-11-12T21:43:28Z"
    # Determine if $res_volume_get is the most recent snapshot for volume $vname
    my $target_snapshot_time = $res_volume_get->{createdTimeStamp};
    qs_write_to_log("Checking if snapshot '$res_volume_get->{name}' (created: $target_snapshot_time) is the most recent for volume '$vname'");
    my $is_most_recent = 1;

    foreach my $item (@$res_storage_volume_enum) {
        # Only consider snapshots
        qs_write_to_log("Examining item: " . ($item->{name} // 'undef') . " (isSnapshot: " . ($item->{isSnapshot} // 'undef') . ", createdTimeStamp: " . ($item->{createdTimeStamp} // 'undef') . ")");
        unless (defined $item->{isSnapshot} && $item->{isSnapshot} eq '1') {
            qs_write_to_log("Skipping non-snapshot item: " . ($item->{name} // 'undef'));
            next;
        }

        # snapshotParent should be eq to $res_volume_get->{snapshotParent}
        unless (defined $item->{snapshotParent} && $item->{snapshotParent} eq $res_volume_get->{snapshotParent}) {
            qs_write_to_log("Skipping snapshot '$item->{name}' (snapshotParent: " . ($item->{snapshotParent} // 'undef') . ") not matching target snapshotParent '" . ($res_volume_get->{snapshotParent} // 'undef') . "'");
            next;
        }

        ## Check if this snapshot belongs to the target volume
        #unless (defined $item->{origin} && $item->{origin} eq $vname) {
        #    qs_write_to_log("Skipping snapshot '$item->{name}' (origin: " . ($item->{origin} // 'undef') . ") not matching target volume '$vname'");
        #    next;
        #}

        qs_write_to_log("Found snapshot '$item->{name}' for volume '$vname' with createdTimeStamp: $item->{createdTimeStamp}");

        # Compare timestamps
        if ($item->{createdTimeStamp} gt $target_snapshot_time) {
            qs_write_to_log("Snapshot '$item->{name}' is newer (created: $item->{createdTimeStamp}) than target snapshot '$res_volume_get->{name}' (created: $target_snapshot_time)");
            $is_most_recent = 0;
            push @$blockers, $item->{name} if defined $blockers;
        }
    }
    qs_write_to_log("Finished checking snapshots for volume '$vname'. is_most_recent = $is_most_recent");

    qs_write_to_log("Snapshot '$res_volume_get->{name}' is ". ($is_most_recent ? "the most recent snapshot." : "not the most recent snapshot."));
    if (!$is_most_recent) {
        die "can't rollback, '$snap' is not most recent snapshot on '$volname'\n";
    }
    # can't use '-S creation', because zfs list won't reverse the order when the
    # creation time is the same second, breaking at least our tests.
    #my $snapshots = $class->zfs_get_sorted_snapshot_list($scfg, $volname, ['-s', 'creation']);

    #my $found;
    #$blockers //= []; # not guaranteed to be set by caller
    #for my $snapshot ($snapshots->@*) {
	#if ($snapshot eq $snap) {
	#    $found = 1;
	#} elsif ($found) {
	#    push $blockers->@*, $snapshot;
	#}
    #}

    #my $volid = "${storeid}:${volname}";

    #die "can't rollback, snapshot '$snap' does not exist on '$volid'\n"
	#if !$found;

    #die "can't rollback, '$snap' is not most recent snapshot on '$vname'\n"
	#if scalar($blockers->@*) > 0;

    #return 1;

    return 1;
}





1;
