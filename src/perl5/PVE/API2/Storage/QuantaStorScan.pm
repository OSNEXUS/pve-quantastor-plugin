package PVE::API2::Storage::Scan;

use strict;
use warnings;

use PVE::JSONSchema qw(get_standard_option);
use PVE::Storage::QuantaStor::APIClient;

# Register a pool-scan method into the existing Scan routing tree.
# This file is loaded via a 'require' appended to Scan.pm by our postinst.

__PACKAGE__->register_method({
    name        => 'quantastorscan',
    path        => 'quantastor',
    method      => 'GET',
    description => 'Scan a QuantaStor appliance and return the list of storage pools.',
    protected   => 1,
    proxyto     => 'node',
    permissions => {
        check => ['perm', '/storage', ['Datastore.Audit']],
    },
    parameters => {
        additionalProperties => 0,
        properties => {
            node => get_standard_option('pve-node'),
            api_host => {
                description => 'QuantaStor appliance hostname or IP.',
                type        => 'string',
            },
            username => {
                description => 'API username.',
                type        => 'string',
                optional    => 1,
                default     => 'admin',
            },
            password => {
                description => 'API password.',
                type        => 'string',
            },
            ssl_verify => {
                description => 'Verify SSL certificate.',
                type        => 'boolean',
                optional    => 1,
                default     => 0,
            },
        },
    },
    returns => {
        type  => 'array',
        items => {
            type       => 'object',
            properties => {
                name   => { type => 'string', description => 'Pool name.' },
                id     => { type => 'string', description => 'Pool UUID.' },
                status => { type => 'string', description => 'Pool status.' },
            },
        },
    },
    code => sub {
        my ($param) = @_;

        my $client = PVE::Storage::QuantaStor::APIClient->new(
            host       => $param->{api_host},
            username   => $param->{username} // 'admin',
            password   => $param->{password},
            ssl_verify => $param->{ssl_verify} // 0,
        );

        my $pools = $client->pool_enum();

        my @result;
        for my $pool (@$pools) {
            next unless $pool->{isActive};
            push @result, {
                name   => $pool->{name},
                id     => $pool->{id},
                status => $pool->{status} // 'ONLINE',
            };
        }

        return \@result;
    },
});

1;
