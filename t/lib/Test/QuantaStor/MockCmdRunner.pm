package Test::QuantaStor::MockCmdRunner;

use strict;
use warnings;
use Carp qw(croak);

=head1 NAME

Test::QuantaStor::MockCmdRunner - Mock command runner for testing ISCSIManager

=head1 SYNOPSIS

    my $runner = Test::QuantaStor::MockCmdRunner->new(
        responses => {
            # Key is the first meaningful argument after 'iscsiadm'
            # (typically the subcommand + mode combination).
            # Value is either a string (stdout) or a die message.
            'discovery' => "10.0.0.1:3260,1 iqn.2009-10.com.osnexus:pool:vol\n",
            'node --login' => '',
            'node --logout' => '',
            'session' => "tcp: [1] 10.0.0.1:3260,1 iqn.2009-10.com.osnexus:pool:vm-100-disk-0\n",
        },
    );

    my $iscsi = PVE::Storage::QuantaStor::ISCSIManager->new(
        portal   => '10.0.0.1',
        _run_cmd => $runner->as_coderef,
    );

=head1 DESCRIPTION

Intercepts C<_run_cmd> calls from ISCSIManager without spawning real processes.
Responses are keyed on a compact signature derived from the command arguments.

The signature is built by joining all arguments after 'iscsiadm' with a space,
stripping specific values (target IQNs, portal addresses, etc.) to produce a
stable key regardless of the volume name being operated on:

    iscsiadm -m node --targetname iqn.foo --portal 10.0.0.1 --login
    => 'node --login'

    iscsiadm -m session
    => 'session'

    iscsiadm -m discovery -t sendtargets -p 10.0.0.1
    => 'discovery'

You can also register a per-call die string to simulate command failures:

    responses => {
        'node --login' => { _error => 'iscsiadm: No route to host' },
    }

All calls are recorded for assertion in tests.

=cut

sub new {
    my ($class, %args) = @_;
    return bless {
        responses  => $args{responses} // {},
        calls_made => [],
    }, $class;
}

=head2 as_coderef()

Returns a coderef suitable for passing as the C<_run_cmd> argument to
C<ISCSIManager->new()>.

=cut

sub as_coderef {
    my ($self) = @_;
    return sub { $self->_handle_call(@_) };
}

sub _handle_call {
    my ($self, @cmd) = @_;

    my $sig = _signature(@cmd);
    push @{ $self->{calls_made} }, { cmd => [@cmd], sig => $sig };

    my $configured = $self->{responses}{$sig};

    # Fall through to a default empty-success response if nothing configured,
    # so tests only need to configure responses they actually care about.
    unless (defined $configured) {
        return '';
    }

    # Support response sequences: an arrayref of responses consumed in order.
    # The last element repeats once the sequence is exhausted.  Useful for
    # commands like 'session' that return different results across multiple calls.
    if (ref $configured eq 'ARRAY') {
        $self->{_seq_index}{$sig} //= 0;
        my $idx = $self->{_seq_index}{$sig};
        $configured = $configured->[$idx];
        $self->{_seq_index}{$sig}++ if $idx < $#{ $self->{responses}{$sig} };
    }

    if (ref $configured eq 'HASH' && defined $configured->{_error}) {
        croak $configured->{_error};
    }

    return $configured;
}

# Build a stable key from the command arguments:
# - Drop the program name (iscsiadm)
# - Drop -m (mode flag)
# - Keep the mode value (discovery, node, session)
# - Drop --targetname and the value after it
# - Drop --portal and the value after it
# - Drop -t and the value after it (sendtargets)
# - Drop -p and the value after it (portal)
# - Keep action flags: --login, --logout
sub _signature {
    my (@args) = @_;

    # Remove program name
    shift @args if @args && $args[0] !~ /^-/;

    my @sig_parts;
    my $skip_next = 0;

    for my $arg (@args) {
        if ($skip_next) {
            $skip_next = 0;
            next;
        }

        # Flags whose values we drop to keep the key stable
        if ($arg =~ /^(-m|-t|-p|--targetname|--portal)$/) {
            # Keep only -m's value (the mode), drop the rest including values
            if ($arg eq '-m') {
                $skip_next = 0;  # we want the next token
                # handled below via look-ahead: just don't push -m itself
                next;
            }
            $skip_next = 1;
            next;
        }

        push @sig_parts, $arg;
    }

    # Clean up: the mode value ends up as the first token in sig_parts
    # (since we skipped '-m' but kept its value)
    return join(' ', @sig_parts);
}

=head2 calls_made()

Returns an arrayref of call records. Each record is a hashref:

    { cmd => [\@original_args], sig => 'signature_string' }

=cut

sub calls_made { return $_[0]->{calls_made} }

=head2 call_count()

Returns the total number of command invocations.

=cut

sub call_count { return scalar @{ $_[0]->{calls_made} } }

=head2 was_called($sig)

Returns true if a command with the given signature was invoked at least once.

    $runner->was_called('node --login');   # true if any login happened
    $runner->was_called('session');        # true if session check happened

=cut

sub was_called {
    my ($self, $sig) = @_;
    return grep { $_->{sig} eq $sig } @{ $self->{calls_made} };
}

=head2 call_count_for($sig)

Returns the number of times a command with the given signature was invoked.

=cut

sub call_count_for {
    my ($self, $sig) = @_;
    return scalar grep { $_->{sig} eq $sig } @{ $self->{calls_made} };
}

=head2 reset()

Clears the call log. Useful between sub-tests.

=cut

sub reset {
    my ($self) = @_;
    $self->{calls_made} = [];
}

1;
