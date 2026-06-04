package Test::QuantaStor::MockUA;

use strict;
use warnings;
use JSON::PP qw(encode_json);
use Carp qw(croak);

=head1 NAME

Test::QuantaStor::MockUA - Mock LWP::UserAgent for testing APIClient

=head1 SYNOPSIS

    my $ua = Test::QuantaStor::MockUA->new(
        responses => {
            storagePoolGet => { id => 'abc', size => 1024, freeSpace => 512 },
            storageVolumeEnum => [
                { id => 'vol-1', name => 'vm-100-disk-0', size => 10240 },
            ],
            # Simulate an HTTP-level failure:
            storageVolumeDelete => { _http_error => '500 Internal Server Error' },
            # Simulate an API-level error:
            hostGet => { RestError => 'Failed to locate host with IQN' },
        },
    );

    my $client = PVE::Storage::QuantaStor::APIClient->new(
        host => '10.0.0.1', username => 'admin', password => 'x',
        _ua  => $ua,
    );

=head1 DESCRIPTION

Minimal drop-in replacement for LWP::UserAgent. Intercepts C<get()> calls,
matches the QuantaStor method name from the URL, and returns pre-configured
responses without making any real network connections.

Each response value may be:

=over

=item A plain hashref or arrayref

Encoded to JSON and returned as a successful HTTP response.

=item C<{ _http_error => "NNN Reason" }>

Simulates an HTTP-level failure (non-2xx status).

=back

All C<get()> calls are recorded in C<requests_made> for assertion in tests.

=cut

sub new {
    my ($class, %args) = @_;
    return bless {
        responses     => $args{responses} // {},
        requests_made => [],
    }, $class;
}

# Stub out LWP::UserAgent interface methods that APIClient calls on construction.
sub timeout        { }
sub ssl_opts       { }
sub default_header { }
sub credentials    { }

sub get {
    my ($self, $url) = @_;

    push @{ $self->{requests_made} }, $url;

    # Extract the API method name from the URL path component.
    my ($method) = $url =~ m{/qstorapi/([^?]+)};
    croak "MockUA: could not extract method from URL: $url" unless $method;

    my $configured = $self->{responses}{$method};

    # No configured response -> 404.
    unless (defined $configured) {
        return Test::QuantaStor::MockResponse->new(
            success     => 0,
            status_line => '404 Not Found',
            content     => '',
        );
    }

    # Explicit HTTP error sentinel.
    if (ref $configured eq 'HASH' && defined $configured->{_http_error}) {
        return Test::QuantaStor::MockResponse->new(
            success     => 0,
            status_line => $configured->{_http_error},
            content     => '',
        );
    }

    # Normal response — encode to JSON.
    my $json = encode_json($configured);
    return Test::QuantaStor::MockResponse->new(
        success     => 1,
        status_line => '200 OK',
        content     => $json,
    );
}

=head2 requests_made()

Returns an arrayref of URLs that C<get()> was called with, in order.

=cut

sub requests_made { return $_[0]->{requests_made} }

=head2 last_request()

Returns the most recent URL string, or undef.

=cut

sub last_request {
    my ($self) = @_;
    return $self->{requests_made}[-1];
}

=head2 request_count()

Returns the total number of requests made.

=cut

sub request_count { return scalar @{ $_[0]->{requests_made} } }

=head2 was_called($method_name)

Returns true if at least one request was made for the given QuantaStor API
method name (e.g. C<'storageVolumeCreate'>).

=cut

sub was_called {
    my ($self, $method) = @_;
    return grep { m{/qstorapi/\Q$method\E(?:\?|$)} } @{ $self->{requests_made} };
}

=head2 params_for($method_name)

Returns a hashref of query parameters from the first request to $method_name,
or undef if that method was never called. Useful for asserting what parameters
were sent.

=cut

sub params_for {
    my ($self, $method) = @_;

    for my $url (@{ $self->{requests_made} }) {
        next unless $url =~ m{/qstorapi/\Q$method\E\?(.+)$};
        my $qs = $1;
        my %params;
        for my $pair (split /&/, $qs) {
            my ($k, $v) = map { _urldecode($_) } split /=/, $pair, 2;
            $params{$k} = $v;
        }
        return \%params;
    }
    return undef;
}

sub _urldecode {
    my ($s) = @_;
    $s =~ s/\+/ /g;
    $s =~ s/%([0-9A-Fa-f]{2})/chr(hex($1))/ge;
    return $s;
}

# ---------------------------------------------------------------------------

package Test::QuantaStor::MockResponse;

use strict;
use warnings;

sub new {
    my ($class, %args) = @_;
    return bless \%args, $class;
}

sub is_success      { return $_[0]->{success} }
sub status_line     { return $_[0]->{status_line} }
sub decoded_content { return $_[0]->{content} }

1;
