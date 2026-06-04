package PVE::Storage::QuantaStor::APIClient;

use strict;
use warnings;
use Carp qw(croak confess);
use URI::Escape qw(uri_escape);
use LWP::UserAgent;
use JSON::PP qw(decode_json encode_json);

our $VERSION = '1.0.0';

=head1 NAME

PVE::Storage::QuantaStor::APIClient - REST API client for QuantaStor storage appliances

=head1 SYNOPSIS

    my $client = PVE::Storage::QuantaStor::APIClient->new(
        host     => '10.0.0.1',
        username => 'admin',
        password => 'secret',
    );

    my $pool = $client->pool_get('my-pool-uuid');
    my $vol  = $client->volume_create('vm-100-disk-0', 10240, 'pool-uuid');

=head1 DESCRIPTION

Encapsulates all HTTP communication with the QuantaStor REST API (port 8153).
Each instance holds a single LWP::UserAgent (lazy-initialised) so connection
overhead is paid once per plugin activation rather than once per API call.

All methods die on error — callers should wrap in eval{} where partial failure
is acceptable.

=cut

# ---------------------------------------------------------------------------
# Constructor
# ---------------------------------------------------------------------------

sub new {
    my ($class, %args) = @_;

    croak "APIClient: 'host' is required"     unless $args{host};
    croak "APIClient: 'username' is required" unless $args{username};
    croak "APIClient: 'password' is required" unless $args{password};

    my $self = {
        host       => $args{host},
        port       => $args{port}       // 8153,
        username   => $args{username},
        password   => $args{password},
        ssl_verify => $args{ssl_verify} // 0,
        ca_cert    => $args{ca_cert},
        timeout    => $args{timeout}    // 30,

        # Optional logger: a coderef that accepts ($level, $message).
        # Defaults to a no-op so the module works without PVE's syslog.
        logger => $args{logger} // sub {},

        # Inject a pre-built UA for testing; otherwise built lazily.
        _ua => $args{_ua},

        # Pool scope for volume lookups. When set, volume_get falls back to
        # an enum+filter if storageVolumeGet returns "multiple matches" (which
        # happens when two pools on the same appliance share a volume name).
        pool_id => $args{pool_id},

        # Coderef receiving seconds-to-sleep. Default is the built-in sleep;
        # tests inject sub {} so polling loops are instant.
        _sleep => $args{_sleep} // sub { sleep $_[0] },
    };

    return bless $self, $class;
}

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

# Returns (and caches) the LWP::UserAgent instance.
sub _ua {
    my ($self) = @_;
    return $self->{_ua} if $self->{_ua};

    my $ua = LWP::UserAgent->new(timeout => $self->{timeout});

    if ($self->{ca_cert}) {
        $ua->ssl_opts(
            SSL_ca_file     => $self->{ca_cert},
            verify_hostname => 1,
        );
    } elsif ($self->{ssl_verify}) {
        # Verify against the system CA bundle.
        $ua->ssl_opts(
            SSL_verify_mode => 1,
            verify_hostname => 1,
        );
    } else {
        $ua->ssl_opts(
            SSL_verify_mode => 0,
            verify_hostname => 0,
        );
    }

    $ua->default_header('Accept' => 'application/json');
    $ua->credentials(
        "$self->{host}:$self->{port}",
        'Proxmox API',
        $self->{username},
        $self->{password},
    );

    $self->{_ua} = $ua;
    return $ua;
}

# Execute a single QuantaStor API call.
# Returns the decoded Perl data structure on success.
# Dies with a descriptive message on HTTP or API-level failure.
sub _get {
    my ($self, $method, %params) = @_;

    my $url = sprintf('https://%s:%d/qstorapi/%s',
        $self->{host}, $self->{port}, $method);

    # Build query string — skip undef and empty-string values.
    my @pairs;
    for my $key (sort keys %params) {
        next unless defined $params{$key} && $params{$key} ne '';
        push @pairs, uri_escape($key) . '=' . uri_escape("$params{$key}");
    }
    $url .= '?' . join('&', @pairs) if @pairs;

    $self->{logger}->(debug => "APIClient: GET $url");

    my $response = $self->_ua->get($url);

    unless ($response->is_success) {
        croak sprintf(
            "QuantaStor API call '%s' failed (HTTP %s)",
            $method, $response->status_line
        );
    }

    my $content = $response->decoded_content;
    unless (defined $content && length $content) {
        croak "QuantaStor API call '$method' returned an empty response";
    }

    my $data = eval { decode_json($content) };
    if ($@) {
        croak "QuantaStor API call '$method' returned invalid JSON: $@\nBody: $content";
    }

    # Surface API-level errors returned as { RestError => "..." }
    if (ref $data eq 'HASH' && defined $data->{RestError}) {
        croak "QuantaStor API error in '$method': $data->{RestError}";
    }

    return $data;
}

# ---------------------------------------------------------------------------
# Storage pool operations
# ---------------------------------------------------------------------------

=head2 pool_get($pool_id)

Returns pool metadata including C<size> and C<freeSpace> (bytes).

=cut

sub pool_get {
    my ($self, $pool_id) = @_;
    croak "pool_get: pool_id is required" unless defined $pool_id && length $pool_id;
    return $self->_get('storagePoolGet', storagePool => $pool_id);
}

=head2 pool_enum()

Returns an arrayref of all storage pool objects visible on this appliance.

=cut

sub pool_enum {
    my ($self) = @_;
    my $result = $self->_get('storagePoolEnum');
    # Normalize: single-pool appliances may return a bare hash instead of a
    # one-element array. Callers always iterate the result.
    $result = [$result] if ref $result eq 'HASH';
    return $result // [];
}

# ---------------------------------------------------------------------------
# Volume operations
# ---------------------------------------------------------------------------

=head2 volume_enum()

Returns an arrayref of all volume objects visible on this appliance.

=cut

sub volume_enum {
    my ($self) = @_;
    my $result = $self->_get('storageVolumeEnum');
    $result = [$result] if ref $result eq 'HASH';
    return $result // [];
}

=head2 volume_get($name_or_uuid)

Returns a single volume object. Dies if the volume does not exist.

=cut

sub volume_get {
    my ($self, $vol) = @_;
    croak "volume_get: vol is required" unless defined $vol && length $vol;

    my $result = eval { $self->_get('storageVolumeGet', storageVolume => $vol) };
    return $result unless $@;

    # storageVolumeGet fails with "multiple matches" when two pools on the same
    # appliance share a volume name. If we have a pool scope, resolve via enum.
    if ($@ =~ /multiple matches/i && $self->{pool_id}) {
        return $self->_volume_get_by_pool_name($vol);
    }
    die $@;
}

=head2 volume_get_or_undef($name_or_uuid)

Like L</volume_get>, but returns C<undef> when the volume does not exist
instead of dying. Useful for idempotent delete paths where "already gone"
is success, not a failure.

QuantaStor's not-found error reads
C<Specified StorageVolume object ... could not be found. [err=5]>; any other
error propagates. Mirrors L</host_get>'s undef-on-not-found contract.

=cut

sub volume_get_or_undef {
    my ($self, $vol) = @_;
    croak "volume_get_or_undef: vol is required" unless defined $vol && length $vol;

    my $result = eval { $self->volume_get($vol) };
    if ($@) {
        return undef if $@ =~ /could not be found|err=5/i;
        die $@;
    }
    return $result;
}

# Enumerate all volumes and return the one matching $name in $self->{pool_id}.
sub _volume_get_by_pool_name {
    my ($self, $name) = @_;

    my $pool = eval { $self->pool_get($self->{pool_id}) };
    my $pool_uuid = $pool ? $pool->{id} : $self->{pool_id};
    $pool_uuid =~ s/^qs-//;

    my $vols = $self->_get('storageVolumeEnum');
    $vols = [$vols] unless ref $vols eq 'ARRAY';

    my @matches = grep {
        ($_->{name} // '') eq $name &&
        ($_->{storagePoolId} // '') eq $pool_uuid
    } @$vols;

    croak "volume_get: no volume '$name' found in pool $pool_uuid"
        unless @matches;

    return $matches[0];
}

=head2 volume_create($name, $size_kb, $pool_id, %opts)

Creates a new volume. C<$size_kb> is in kilobytes (the API expects bytes;
this method performs the conversion). Returns the new volume object.

Optional: C<description>.

=cut

sub volume_create {
    my ($self, $name, $size_kb, $pool_id, %opts) = @_;
    croak "volume_create: name is required"    unless defined $name    && length $name;
    croak "volume_create: size_kb is required" unless defined $size_kb && $size_kb > 0;
    croak "volume_create: pool_id is required" unless defined $pool_id && length $pool_id;

    return $self->_get('storageVolumeCreate',
        name            => $name,
        size            => $size_kb * 1024,   # KB -> bytes
        provisionableId => $pool_id,
        description     => $opts{description} // 'Created by Proxmox VE Plugin',
    );
}

=head2 volume_delete($vol_id, %opts)

Deletes a volume by UUID. Defaults are safe: C<deleteOptions=0> (no cascade)
and C<flags=0> (no force) — QuantaStor rejects if children exist or the
volume is busy. Callers that explicitly want destructive semantics pass
C<delete_options =E<gt> 4> (cascade children) and/or C<flags =E<gt> 2> (force).

=cut

sub volume_delete {
    my ($self, $vol_id, %opts) = @_;
    croak "volume_delete: vol_id is required" unless defined $vol_id && length $vol_id;

    return $self->_get('storageVolumeDelete',
        storageVolumeList => $vol_id,
        deleteOptions     => $opts{delete_options} // 0,
        flags             => $opts{flags}          // 0,
    );
}

=head2 volume_resize($vol_id, $pool_id, $new_size_bytes, %opts)

Grows a volume to C<$new_size_bytes>.  Shrinking is not supported by
QuantaStor.  C<$pool_id> is the pool name or UUID that owns the volume.
Optional C<flags> (default 0).

=cut

sub volume_resize {
    my ($self, $vol_id, $pool_id, $new_size_bytes, %opts) = @_;
    croak "volume_resize: vol_id is required"        unless defined $vol_id        && length $vol_id;
    croak "volume_resize: pool_id is required"       unless defined $pool_id       && length $pool_id;
    croak "volume_resize: new_size_bytes is required" unless defined $new_size_bytes && $new_size_bytes > 0;

    return $self->_get('storageVolumeResize',
        storageVolume   => $vol_id,
        provisionableId => $pool_id,
        newSizeInBytes  => int($new_size_bytes),
        flags           => $opts{flags} // 0,
    );
}

=head2 volume_modify($vol_id, $new_name, %opts)

Renames a volume. Optional: C<description>.

=cut

sub volume_modify {
    my ($self, $vol_id, $new_name, %opts) = @_;
    croak "volume_modify: vol_id is required"   unless defined $vol_id   && length $vol_id;
    croak "volume_modify: new_name is required" unless defined $new_name && length $new_name;

    return $self->_get('storageVolumeModify',
        storageVolume  => $vol_id,
        newName        => $new_name,
        newDescription => $opts{description} // 'Modified by Proxmox VE Plugin',
    );
}

=head2 volume_snapshot($vol_name, $snap_name, %opts)

Takes a snapshot of C<$vol_name> named C<$snap_name>.

=cut

sub volume_snapshot {
    my ($self, $vol_name, $snap_name, %opts) = @_;
    croak "volume_snapshot: vol_name is required"  unless defined $vol_name  && length $vol_name;
    croak "volume_snapshot: snap_name is required" unless defined $snap_name && length $snap_name;

    return $self->_get('storageVolumeSnapshot',
        storageVolume => $vol_name,
        snapshotName  => $snap_name,
        description   => $opts{description} // 'Snapshot created by Proxmox VE Plugin',
    );
}

=head2 volume_rollback($vol_id, $snap_name)

Rolls a volume back to C<$snap_name>. The snapshot must be the most recent.

=cut

sub volume_rollback {
    my ($self, $vol_id, $snap_name) = @_;
    croak "volume_rollback: vol_id is required"    unless defined $vol_id    && length $vol_id;
    croak "volume_rollback: snap_name is required" unless defined $snap_name && length $snap_name;

    return $self->_get('storageVolumeRollback',
        storageVolume  => $vol_id,
        snapshotVolume => $snap_name,
    );
}

=head2 volume_clone($vol_name, $clone_name, %opts)

Clones C<$vol_name> (typically a snapshot) into a new independent volume.

=cut

sub volume_clone {
    my ($self, $vol_name, $clone_name, %opts) = @_;
    croak "volume_clone: vol_name is required"   unless defined $vol_name   && length $vol_name;
    croak "volume_clone: clone_name is required" unless defined $clone_name && length $clone_name;

    return $self->_get('storageVolumeClone',
        storageVolume => $vol_name,
        cloneName     => $clone_name,
        description   => $opts{description} // 'Clone created by Proxmox VE Plugin',
    );
}

# ---------------------------------------------------------------------------
# ACL operations
# ---------------------------------------------------------------------------

=head2 volume_acl_add($vol_id, $host_iqn)

Grants the host identified by C<$host_iqn> access to volume C<$vol_id>.

=cut

sub volume_acl_add {
    my ($self, $vol_id, $host_iqn) = @_;
    croak "volume_acl_add: vol_id is required"   unless defined $vol_id   && length $vol_id;
    croak "volume_acl_add: host_iqn is required" unless defined $host_iqn && length $host_iqn;

    return $self->_get('storageVolumeAclAddRemoveEx',
        storageVolumeList => $vol_id,
        host              => $host_iqn,
        modType           => 0,   # 0 = add
    );
}

=head2 volume_acl_remove($vol_id, $host_id)

Revokes access for host C<$host_id> from volume C<$vol_id>.
C<$host_id> may be the host's UUID or its IQN.

=cut

sub volume_acl_remove {
    my ($self, $vol_id, $host_id) = @_;
    croak "volume_acl_remove: vol_id is required"  unless defined $vol_id  && length $vol_id;
    croak "volume_acl_remove: host_id is required" unless defined $host_id && length $host_id;

    return $self->_get('storageVolumeAclAddRemoveEx',
        storageVolumeList => $vol_id,
        host              => $host_id,
        modType           => 1,   # 1 = remove
    );
}

# ---------------------------------------------------------------------------
# Session operations
# ---------------------------------------------------------------------------

=head2 session_enum($vol_name)

Returns an arrayref of active iSCSI sessions for C<$vol_name>.
An empty arrayref means the volume is not currently attached to any host.

=cut

sub session_enum {
    my ($self, $vol_name) = @_;
    croak "session_enum: vol_name is required" unless defined $vol_name && length $vol_name;

    # session_enum may return an empty list (not a RestError) when no sessions
    # exist — treat that as a valid empty arrayref.
    my $result = eval { $self->_get('sessionEnum', storageVolume => $vol_name) };
    if ($@) {
        return [] if $@ =~ /no sessions/i;
        die $@;
    }
    return $result // [];
}

=head2 wait_for_session_gone($vol_name, $max_wait)

Polls C<session_enum> until QuantaStor reports no active iSCSI sessions on
C<$vol_name>, or C<$max_wait> seconds elapse. Returns 1 once empty, 0 on
timeout. Default C<$max_wait> is 30 seconds; polling interval is 1 second.

This complements ISCSIManager's C<wait_for_logout>: after the PVE-side
iscsiadm session record is gone, QuantaStor may still consider the session
active for several seconds while its own GC catches up. Operations like
volume_rollback and volume_modify reject on an "active session" — call this
method between the local logout and the server-side mutation to bridge the
gap.

=cut

sub wait_for_session_gone {
    my ($self, $vol_name, $max_wait) = @_;
    croak "wait_for_session_gone: vol_name is required"
        unless defined $vol_name && length $vol_name;
    $max_wait //= 30;

    my $interval = 1;
    my $elapsed  = 0;

    while ($elapsed < $max_wait) {
        my $sessions = eval { $self->session_enum($vol_name) };
        # Only treat a successful empty response as "gone". Transient API
        # errors or non-arrayref responses keep us polling — a false positive
        # here would let the caller mutate the volume mid-session.
        if (!$@ && ref $sessions eq 'ARRAY' && @$sessions == 0) {
            return 1;
        }
        $self->{_sleep}->($interval);
        $elapsed += $interval;
    }

    $self->{logger}->(warning =>
        "APIClient: timeout waiting for QuantaStor sessions to clear on '$vol_name'");
    return 0;
}

# ---------------------------------------------------------------------------
# Host operations
# ---------------------------------------------------------------------------

=head2 host_get($iqn_or_name)

Returns the host object, or C<undef> if not found (RestError "Failed to locate
host" is silently converted to undef; other errors propagate).

=cut

sub host_get {
    my ($self, $host) = @_;
    croak "host_get: host is required" unless defined $host && length $host;

    my $result = eval { $self->_get('hostGet', host => $host) };
    if ($@) {
        # "Failed to locate host" is expected when the host has not been
        # registered yet — return undef so callers can treat it as "not found".
        return undef if $@ =~ /Failed to locate host/i;
        die $@;
    }
    return $result;
}

=head2 host_add($hostname, $iqn, %opts)

Registers a new initiator host. Returns the created host object.
Optional: C<ip_address>, C<host_type>, C<description>.

=cut

sub host_add {
    my ($self, $hostname, $iqn, %opts) = @_;
    croak "host_add: hostname is required" unless defined $hostname && length $hostname;
    croak "host_add: iqn is required"      unless defined $iqn      && length $iqn;

    return $self->_get('hostAdd',
        hostname    => $hostname,
        iqn         => $iqn,
        ipAddress   => $opts{ip_address} // '',
        hostType    => $opts{host_type}  // '',
        description => $opts{description} // 'Added by Proxmox VE Plugin',
    );
}

=head2 host_remove($host_id)

Removes a registered host by UUID or IQN.

=cut

sub host_remove {
    my ($self, $host_id) = @_;
    croak "host_remove: host_id is required" unless defined $host_id && length $host_id;
    return $self->_get('hostRemove', host => $host_id);
}

# ---------------------------------------------------------------------------
# Utility: ensure this node is registered as a host
# ---------------------------------------------------------------------------

=head2 ensure_host_registered($hostname, $iqn, %opts)

Idempotent helper: looks up the host by IQN and registers it if not found.
Returns the host UUID either way.

=cut

sub ensure_host_registered {
    my ($self, $hostname, $iqn, %opts) = @_;
    croak "ensure_host_registered: hostname is required" unless defined $hostname && length $hostname;
    croak "ensure_host_registered: iqn is required"      unless defined $iqn      && length $iqn;

    my $host = $self->host_get($iqn);
    if (defined $host) {
        $self->{logger}->(debug => "APIClient: host '$iqn' already registered (id=$host->{id})");
        return $host->{id};
    }

    $self->{logger}->(info => "APIClient: registering new host '$hostname' ($iqn)");
    my $result = $self->host_add($hostname, $iqn, %opts);

    # hostAdd returns { obj => { id => ..., ... }, task => ... }
    my $new_host = (ref $result eq 'HASH' && $result->{obj}) ? $result->{obj} : $result;
    croak "host_add response missing 'id'" unless defined $new_host->{id};
    return $new_host->{id};
}

1;
