# Source layout and module reference

What each file in the repository does, and the public interface of each Perl module.

## Repository layout

```
.
├── src/
│   └── perl5/PVE/
│       ├── API2/Storage/
│       │   └── QuantaStorScan.pm     Pool-scan PVE API endpoint (injected into Scan.pm)
│       └── Storage/
│           ├── Custom/
│           │   └── QuantaStor.pm     PVE custom plugin — registers type 'quantastor'
│           └── QuantaStor/
│               ├── APIClient.pm      REST client for QuantaStor API
│               └── ISCSIManager.pm   iSCSI initiator lifecycle management
├── t/
│   ├── 01-api-client.t               Unit tests — APIClient (50 tests)
│   ├── 02-iscsi-manager.t            Unit tests — ISCSIManager (42 tests)
│   ├── 03-integration.t              Integration tests (requires live appliance)
│   ├── 04-plugin.t                   Unit tests — QuantaStorPlugin (65 tests)
│   ├── run_tests.sh                  Test runner script
│   └── lib/Test/QuantaStor/
│       ├── MockUA.pm                 Mock LWP::UserAgent for APIClient tests
│       └── MockCmdRunner.pm          Mock command runner for ISCSIManager tests
├── debian/                           Debian packaging
├── multipath/
│   └── quantastor.conf               multipathd device section (installed to /etc/multipath/conf.d/)
├── www/
│   └── quantastor-storage.js         PVE web UI panel (injected by postinst)
├── docs/                             User documentation (installation, configuration, multipath,
│                                     containers, troubleshooting, limitations, architecture)
├── build-deb.sh                      Build the .deb package
├── CONTRIBUTING.md                   Development workflow and roadmap
└── README.md                         Overview and quick start
```

`src/README.md` (this file) and `t/README.md` (running the tests) sit next to the code they describe.

## Module reference

### `PVE::Storage::QuantaStor::APIClient`

OO REST client. A single `LWP::UserAgent` is created per client instance.

```perl
my $client = PVE::Storage::QuantaStor::APIClient->new(
    host       => '10.0.0.1',
    username   => 'admin',
    password   => 'secret',
    port       => 8153,       # default
    ssl_verify => 0,          # default off; set 1 to verify against the
                              # system CA bundle, or pass ca_cert => '/path.pem'
                              # to verify against a custom CA
    timeout    => 30,         # default
    logger     => sub { my ($level, $msg) = @_; ... },
);
```

| Method | Description |
|---|---|
| `pool_enum()` | All storage pool objects on the appliance |
| `pool_get($pool_id)` | Pool metadata (size, freeSpace) |
| `volume_enum()` | All volumes on the appliance |
| `volume_get($name_or_uuid)` | Single volume object; dies if not found |
| `volume_get_or_undef($name_or_uuid)` | Like `volume_get` but returns `undef` if not found (safe for idempotent delete) |
| `volume_create($name, $size_kb, $pool_id)` | Create a new volume |
| `volume_delete($vol_uuid)` | Delete volume (safe defaults; callers pass explicit flags for cascade/force) |
| `volume_resize($vol_id, $pool_id, $new_size_bytes)` | Grow a volume to `$new_size_bytes` (flags=2 allows resize while iSCSI session is active — no logout required; caller should rescan after to update kernel LUN geometry) |
| `volume_modify($vol_uuid, $new_name)` | Rename a volume |
| `volume_snapshot($vol_name, $snap_name)` | Take a snapshot |
| `volume_rollback($vol_uuid, $snap_name)` | Roll back to snapshot |
| `volume_clone($vol_name, $clone_name)` | Clone a volume or snapshot |
| `volume_acl_add($vol_uuid, $host_iqn)` | Grant host access to volume |
| `volume_acl_remove($vol_uuid, $host_id)` | Revoke host access |
| `session_enum($vol_name)` | Active iSCSI sessions for a volume |
| `wait_for_session_gone($vol_name, $max_wait)` | Poll `sessionEnum` until QS reports the volume idle (bridges the PVE/QS session GC gap before rollback/rename) |
| `host_get($iqn)` | Look up host (returns `undef` if not found) |
| `host_add($hostname, $iqn)` | Register an initiator host |
| `host_remove($host_id)` | Deregister a host |
| `ensure_host_registered($hostname, $iqn)` | Idempotent register — returns host UUID |

All methods die on error. Wrap in `eval {}` where partial failure is acceptable.

---

### `PVE::Storage::QuantaStor::ISCSIManager`

Manages `iscsiadm` login/logout for QuantaStor-exported iSCSI targets.

```perl
my $iscsi = PVE::Storage::QuantaStor::ISCSIManager->new(
    portal => '10.0.0.1',
    logger => sub { my ($level, $msg) = @_; ... },
);
```

| Method | Description |
|---|---|
| `get_initiator_iqn()` | Read local IQN from `/etc/iscsi/initiatorname.iscsi` |
| `discover()` | `iscsiadm -m discovery` — non-fatal on failure |
| `login($target_iqn)` | Discover + login; dies on failure |
| `logout($target_iqn)` | Logout; returns 0 if not logged in (non-fatal) |
| `is_logged_in($target_iqn)` | Check active session via `iscsiadm -m session` |
| `device_path($target_iqn, $lun)` | Returns `/dev/disk/by-path/ip-...-iscsi-...-lun-N` (honors configured portal port) |
| `wait_for_logout($target_iqn, $max_wait)` | Poll until session gone or timeout; caller must invoke `logout()` first |
| `wait_for_device($target_iqn, $lun, $max_wait)` | Poll the by-path symlink until present, default 30s timeout |
| `rescan($target_iqn)` | Re-read LUN capacity from target after an online resize so the kernel block device reports the new size before QEMU's `block_resize` QMP fires. No-op when not logged in. |
| `sessions($target_iqn)` | Active sessions for the target as `{ sid, portal }` (IPv4 and IPv6 portals) |
| `discover_portals($target_iqn)` | Every `ip:port` QuantaStor advertises for the target (sendtargets, brief retry); dies if none |
| `login_all($target_iqn)` | Log in on every advertised portal that has no session yet (repeat-safe), skipping portals that do not accept a TCP connection within 3 s; dies only if no path is up; falls back to `login()` if discovery fails |
| `logout_all($target_iqn)` | Log out every active session for the target |
| `rescan_all($target_iqn)` | Rescan each session by id; returns how many were rescanned |
| `map_path($wwid)` | `/dev/disk/by-id/dm-uuid-mpath-<wwid>` (independent of `user_friendly_names`) |
| `add_map($wwid, $max_wait)` | `multipath -a` + build the map for this WWID only, then wait for `map_path` |
| `flush_map($wwid)` | `multipath -f` if the map exists; dies if it is still in use |
| `resize_map($wwid)` | `multipathd resize map` after `rescan_all` |

Device paths use `/dev/disk/by-path/` for stability across reboots, unlike ephemeral
`/dev/sdX` assignments. The multipath methods are used only for storages with
`multipath 1` (see [Multipath](../docs/multipath.md)).

---

### `PVE::API2::Storage::QuantaStorScan`

Thin server-side proxy that exposes a QuantaStor pool list as a PVE scan
endpoint. Installed by the package and appended to the `PVE::API2::Storage::Scan`
routing tree via `postinst`. Registered at:

```
GET /api2/json/nodes/<node>/scan/quantastor
```

Parameters: `api_host` (required), `username` (default: `admin`), `password`
(required), `ssl_verify` (optional, default: 0).

Returns an array of `{ name, id, status }` objects for all active pools on the
appliance. Used by the pool scan button in the Add Storage dialog.

Test from the command line:
```bash
pvesh get /nodes/<node>/scan/quantastor \
  --api_host <qs-ip> --username admin --password <pass>
```

### `PVE::Storage::Custom::QuantaStor`

The top-level PVE storage plugin. Inherits from `PVE::Storage::Plugin` and wires
`APIClient` and `ISCSIManager` together to implement all required PVE storage hooks.

| PVE Hook | What it does |
|---|---|
| `type` | Returns `'quantastor'` |
| `activate_storage` | Verify API connectivity; auto-register PVE node as iSCSI initiator host; with `multipath 1`, fail if `multipathd` is not installed |
| `status` | `pool_get` → `(total, free, used, active)` |
| `list_images` | `volume_enum` filtered by pool + PVE naming convention; a failed pool lookup or enum dies rather than returning an empty list |
| `path` | `volume_get` → IQN → `/dev/disk/by-path/` stable device path; with `multipath 1`, the dm map `/dev/disk/by-id/dm-uuid-mpath-<wwid>` (WWID derived from the volume's `deviceDescriptor`, no session needed); with a snapshot name, the path of the snapshot's own volume (`<volname>_<snap>`) |
| `volume_size_info` | `volume_get` → size in bytes |
| `alloc_image` | `volume_create` → returns volname; when the name was auto-picked and QuantaStor refuses it as existing (`err=9`), moves on to the next disk number (up to 5 attempts) |
| `free_image` | logout (multipath: flush map, then every path) → ACL remove → `volume_delete` (best-effort teardown; only delete fails loud) |
| `activate_volume` | `volume_acl_add` → iSCSI login → `wait_for_device` (dies with a clear message if the by-path symlink hasn't appeared within 30s); with `multipath 1`, `login_all` → `add_map` (dies if the map hasn't appeared within 30s); with a snapshot name, activates the snapshot's own volume (vzdump snapshot mode, full clone from a snapshot) |
| `deactivate_volume` | iSCSI logout (multipath: `flush_map` first, then `logout_all`) → `wait_for_logout` → `volume_acl_remove`; with a snapshot name, deactivates the snapshot's own volume |
| `volume_resize` | `storageVolumeResize` with `newSizeInBytes` (flags=2 resizes through an active session — no logout), then an iSCSI rescan so the kernel sees the new LUN size (multipath: `rescan_all` → `resize_map`) — shrinking not supported |
| `volume_snapshot` | `volume_snapshot` (snap stored as `<volname>_<snap>`) |
| `volume_snapshot_delete` | `volume_get(snap)` → logout of the snapshot if this node is logged in to it (vzdump never deactivates the snapshot it mounted) → `volume_delete`; retries a busy (`err=493`) delete for ~3 minutes, other faults fail fast |
| `volume_snapshot_rollback` | logout (if session active) → `wait_for_session_gone` (QS-side GC) → `volume_rollback`; no re-login (PVE calls `activate_volume` on next start) |
| `volume_rollback_is_possible` | Timestamp comparison across sibling snapshots |
| `create_base` | offline → rename `vm-`→`base-` → template snapshot → online (multipath: every path) |
| `clone_image` | `volume_clone` from template snapshot → ACL → login (multipath: every path) |
| `volume_has_feature` | snapshot, clone, template, copy (including from a snapshot), sparseinit |
| `storage_can_replicate` | Returns 0 (not supported in this release) |
| `volume_snapshot_needs_fsfreeze` | Returns 1, so PVE freezes a container's filesystem before a snapshot and the snapshot is filesystem-consistent |
