# QuantaStor PVE Plugin

A [Proxmox VE](https://www.proxmox.com/en/proxmox-virtual-environment) storage plugin that integrates
[QuantaStor](https://www.osnexus.com/products/software-defined-storage) as a first-class iSCSI block
storage backend for virtual machines and containers.

---

## Status

| Component | State |
|---|---|
| `LunCmd/QuantaStorPlugin.pm` (legacy) | Functional alpha — ships as PVE source patches |
| `QuantaStor/APIClient.pm` | Complete — clean REST client, 44 unit tests |
| `QuantaStor/ISCSIManager.pm` | Complete — clean iSCSI lifecycle, 37 unit tests |
| `Custom/QuantaStor.pm` (first-class type) | Complete — all PVE hooks implemented, 46 unit tests |
| Debian packaging | Complete — `pve-storage-quantastor_0.2.0-1_all.deb` |

---

## Architecture

### How it works

QuantaStor manages storage volumes internally and exports them over iSCSI. The plugin sits between
Proxmox VE's storage layer and the QuantaStor REST API:

```
Proxmox VE Storage Layer
        │
        ▼
 Custom/QuantaStor.pm          ← PVE storage plugin (registers type 'quantastor')
        │
        ├── APIClient.pm       ← HTTPS REST calls to QuantaStor (port 8153)
        │
        └── ISCSIManager.pm   ← iscsiadm login/logout/discovery on PVE host
                │
                ▼
        /dev/disk/by-path/...  ← stable block device for QEMU
```

### QuantaStor API

All communication uses QuantaStor's REST API over HTTPS on port 8153 with HTTP Basic Auth.
Requests are plain GET calls with URL-encoded query parameters; responses are JSON.

```
GET https://<host>:8153/qstorapi/<method>?param1=value1&param2=value2
Authorization: Basic <base64(user:pass)>
Accept: application/json
```

### Volume naming convention

PVE volume names follow the standard Proxmox convention:

| Type | Name pattern | Example |
|---|---|---|
| VM disk | `vm-<vmid>-disk-<N>` | `vm-100-disk-0` |
| Template | `base-<vmid>-disk-<N>` | `base-100-disk-0` |
| Template snapshot | `template-base-<vmid>-disk-<N>` | `template-base-100-disk-0` |
| Snapshot | `<volname>_<snapname>` | `vm-100-disk-0_snap1` |

---

## Repository Layout

```
qs-pve-plugin/
├── src/
│   └── perl5/PVE/Storage/
│       ├── Custom/
│       │   └── QuantaStor.pm         PVE custom plugin — registers type 'quantastor'
│       └── QuantaStor/
│           ├── APIClient.pm          REST client for QuantaStor API
│           └── ISCSIManager.pm       iSCSI initiator lifecycle management
├── t/
│   ├── 01-api-client.t               Unit tests — APIClient (44 tests)
│   ├── 02-iscsi-manager.t            Unit tests — ISCSIManager (37 tests)
│   ├── 03-integration.t              Integration tests (requires live appliance)
│   ├── 04-plugin.t                   Unit tests — QuantaStorPlugin (46 tests)
│   ├── run_tests.sh                  Test runner script
│   └── lib/Test/QuantaStor/
│       ├── MockUA.pm                 Mock LWP::UserAgent for APIClient tests
│       └── MockCmdRunner.pm          Mock command runner for ISCSIManager tests
├── debian/                           Debian packaging
├── legacy/                           v0.1-alpha patch-based integration (archived)
│   ├── src/                          Patched PVE source files (per version)
│   ├── patches/                      .patch files for PVE core files
│   ├── install-qs-pve.sh             Legacy patch installer script
│   └── patching-docs.md              Legacy patching documentation
├── pve-upstream/                     Upstream PVE source reference (git-ignored)
├── build-deb.sh                      Build the .deb package
└── README.md
```

---

## Installation

### Package install (recommended)

Download the latest `.deb` from the releases page and install it on each PVE node:

```bash
dpkg -i pve-storage-quantastor_0.2.0-1_all.deb
# PVE services are restarted automatically by postinst
```

The `quantastor` storage type will appear in the PVE UI immediately. The package survives
`pve-storage` and `pve-manager` upgrades intact — no core files are modified.

### Manual install (no package)

```bash
# Ensure iSCSI initiator is enabled (the package postinst does this automatically)
systemctl enable --now iscsid

# Install plugin modules
mkdir -p /usr/share/perl5/PVE/Storage/Custom
cp src/perl5/PVE/Storage/Custom/QuantaStor.pm  /usr/share/perl5/PVE/Storage/Custom/
cp -r src/perl5/PVE/Storage/QuantaStor/        /usr/share/perl5/PVE/Storage/

# Restart PVE services
systemctl restart pvedaemon pveproxy pvestatd pve-cluster
```

### Legacy (patch-based) method

The v0.1-alpha release required patching PVE's own storage modules. Version-specific
patch files are archived in `legacy/` for PVE 8.4.0 and 9.1.1.

```bash
bash legacy/install-qs-pve.sh --install
systemctl restart pvedaemon pveproxy
```

> **Warning:** This overwrites core PVE files and is reverted by PVE package upgrades.
> Use the package install method instead.

### Building the package from source

```bash
# Requires debhelper >= 13
apt install debhelper

bash build-deb.sh
# Produces ../pve-storage-quantastor_0.2.0-1_all.deb
```

---

## Configuration

### Legacy (zfs + quantastor provider)

```
# /etc/pve/storage.cfg
zfs: my-quantastor
    content images
    iscsiprovider quantastor
    portal 10.0.0.1
    pool qs-<pool-uuid>
    qs_apiv4_host 10.0.0.1
    qs_username admin
    qs_password <password>
    blocksize 4k
    sparse 1
```

### New (quantastor type) — Web UI

Go to **Datacenter → Storage → Add → QuantaStor**.

| Field | Tab | Description |
|---|---|---|
| ID | General | Unique storage name within the PVE cluster |
| API Host | General | QuantaStor appliance IP or hostname |
| Username | General | QuantaStor API user (typically `admin`) |
| Password | General | API password — stored securely, never written to `storage.cfg` |
| Pool | General | Storage pool name or UUID on the QuantaStor appliance |
| Content | General | Storage content type — select `Disk image` for VM disks |
| Nodes | General | Restrict to specific PVE nodes (leave empty for all nodes) |
| iSCSI Portal | Advanced | Portal address for iSCSI login — defaults to API Host if left blank |
| SSL Verify | Advanced | Enable SSL certificate verification — leave off for self-signed certs |

`API Host`, `Username`, and `Pool` are fixed after creation. All other fields can be edited later.

### New (quantastor type) — CLI

Add storage via `pvesm` — the password is stored securely and never written to `storage.cfg`:

```bash
pvesm add quantastor my-quantastor \
  --api_host 10.0.0.1 \
  --username admin \
  --password <password> \
  --pool_id <pool-name-or-uuid> \
  --content images \
  --portal 10.0.0.1   \
  --ssl_verify 0
```

`--portal` and `--ssl_verify` are optional. `--portal` defaults to `--api_host` if omitted;
`--ssl_verify` defaults to `0` (off, suitable for self-signed certificates).

The resulting `storage.cfg` entry contains no plaintext password:

```
# /etc/pve/storage.cfg
quantastor: my-quantastor
    api_host 10.0.0.1
    username admin
    pool_id <pool-name-or-uuid>
    content images
    portal 10.0.0.1
    ssl_verify 0
```

`api_host`, `username`, and `pool_id` are fixed after creation. All other
fields are optional and can be updated without removing the storage.

---

## Running Tests

### Unit tests (no appliance required)

```bash
cd qs-pve-plugin
./t/run_tests.sh
```

Requires: `perl`, `libjson-perl` (or `libjson-pp-perl`), `libwww-perl`, `liburi-perl`

```bash
# Install on Debian/Ubuntu/PVE host
apt install libwww-perl liburi-perl
```

### Integration tests (live QuantaStor appliance)

```bash
export QS_HOST=10.0.0.1
export QS_PASSWORD=mysecret
export QS_POOL=test-pool      # Use a dedicated test pool — not production

./t/run_tests.sh --all
```

> Integration tests **create and delete real volumes** on the appliance. Always target a
> dedicated test pool.

| Variable | Required | Default | Description |
|---|---|---|---|
| `QS_HOST` | yes | — | QuantaStor appliance IP or hostname |
| `QS_PASSWORD` | yes | — | API password |
| `QS_POOL` | yes | — | Storage pool name or UUID |
| `QS_USER` | no | `admin` | API username |
| `QS_PORTAL` | no | `QS_HOST` | iSCSI portal address if different from API host |
| `QS_SSL` | no | `0` | Set to `1` to enable SSL certificate verification |
| `QS_CA_CERT` | no | — | Path to CA cert file for SSL verification |

### Verbose output

```bash
./t/run_tests.sh --verbose
```

---

## Module Reference

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
| `pool_get($pool_id)` | Pool metadata (size, freeSpace) |
| `volume_enum()` | All volumes on the appliance |
| `volume_get($name_or_uuid)` | Single volume object; dies if not found |
| `volume_get_or_undef($name_or_uuid)` | Like `volume_get` but returns `undef` if not found (safe for idempotent delete) |
| `volume_create($name, $size_kb, $pool_id)` | Create a new volume |
| `volume_delete($vol_uuid)` | Delete volume (cascades children by default) |
| `volume_modify($vol_uuid, $new_name)` | Rename a volume |
| `volume_snapshot($vol_name, $snap_name)` | Take a snapshot |
| `volume_rollback($vol_uuid, $snap_name)` | Roll back to snapshot |
| `volume_clone($vol_name, $clone_name)` | Clone a volume or snapshot |
| `volume_acl_add($vol_uuid, $host_iqn)` | Grant host access to volume |
| `volume_acl_remove($vol_uuid, $host_id)` | Revoke host access |
| `session_enum($vol_name)` | Active iSCSI sessions for a volume |
| `wait_for_session_gone($vol_name, $max_wait)` | Poll `sessionEnum` until QS reports the volume idle (bridges the PVE/QS GC gap before rollback/rename) |
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
| `device_path($target_iqn, $lun)` | Returns `/dev/disk/by-path/ip-...-iscsi-...-lun-N` (honors any non-3260 port on the configured portal) |
| `wait_for_logout($target_iqn, $max_wait)` | Poll until session gone or timeout |
| `wait_for_device($target_iqn, $lun, $max_wait)` | Poll the by-path symlink until present, default 30s timeout |

Device paths use `/dev/disk/by-path/` for stability across reboots, unlike ephemeral
`/dev/sdX` assignments.

---

## Roadmap

### ~~Phase 3 — `QuantaStorPlugin.pm`~~ ✅ Complete

All PVE storage hooks implemented and unit tested (46 tests). Full VM lifecycle validated
on live PVE 9.1.1 + QuantaStor: create → snapshot → rollback → template → clone.

### ~~Phase 4 — Packaging~~ ✅ Complete

Debian package `pve-storage-quantastor_0.2.0-1_all.deb` builds cleanly with `dpkg-buildpackage`
and installs successfully on PVE 9.1.1. Plugin lives in `/usr/share/perl5/PVE/Storage/Custom/`
(PVE's auto-discovery path for third-party plugins). `postinst` restarts PVE services; `prerm`
warns if active `quantastor` storage entries exist. Build via `bash build-deb.sh`.

### ~~Phase 5 — UI enhancements~~ ✅ Complete

The `quantastor` type is now fully integrated into the PVE web UI. `QuantaStor` appears
in the **Datacenter → Storage → Add** dropdown with a dedicated two-column input panel
(General + Advanced tabs). Fixed fields render as read-only when editing an existing entry.

Implementation ships a standalone JS file (`/usr/share/pve-manager/js/quantastor-storage.js`)
injected into `index.html.tpl` by `postinst` — no `pve-manager` source patches required.
Removed cleanly by `prerm` on uninstall.

### Phase 6 — Migration tooling

For deployments currently running the legacy patched plugin:

- Script to enumerate volumes under the old `zfs`/`quantastor` storage entry
- Move VM disk associations to the new `quantastor` storage type non-destructively
- Restore pristine PVE files: `apt reinstall pve-storage pve-manager`

---

## Contributing

### Prerequisites

- Perl 5.30+
- `libwww-perl`, `liburi-perl` (LWP + URI::Escape)
- `open-iscsi` (for iSCSI tests on a real host)
- A QuantaStor appliance or VM for integration testing

### Running the test suite before submitting

```bash
./t/run_tests.sh
```

All 127 unit tests must pass with no warnings. New functionality should include corresponding
tests in the relevant test file (`t/01-api-client.t`, `t/02-iscsi-manager.t`, or `t/04-plugin.t`).

### Adding a new QuantaStor API method

1. Add the method to `src/perl5/PVE/Storage/QuantaStor/APIClient.pm` following the existing pattern
2. Add unit tests covering the happy path, parameter validation, and at least one error path
3. Update the method table in this README

---

### `PVE::Storage::Custom::QuantaStor`

The top-level PVE storage plugin. Inherits from `PVE::Storage::Plugin` and wires
`APIClient` and `ISCSIManager` together to implement all required PVE storage hooks.

| PVE Hook | What it does |
|---|---|
| `type` | Returns `'quantastor'` |
| `activate_storage` | Verify API connectivity; auto-register PVE node as iSCSI initiator host |
| `status` | `pool_get` → `(total, free, used, active)` |
| `list_images` | `volume_enum` filtered by pool + PVE naming convention |
| `path` | `volume_get` → IQN → `/dev/disk/by-path/` stable device path |
| `volume_size_info` | `volume_get` → size in bytes |
| `alloc_image` | `volume_create` → returns volname |
| `free_image` | logout → ACL remove → `volume_delete` |
| `activate_volume` | `volume_acl_add` → iSCSI login → `wait_for_device` (dies with a clear message if the by-path symlink hasn't appeared within 30s) |
| `deactivate_volume` | iSCSI logout → `wait_for_logout` → `volume_acl_remove` |
| `volume_resize` | `volume_modify` with new size |
| `volume_snapshot` | `volume_snapshot` (snap stored as `<volname>_<snap>`) |
| `volume_snapshot_delete` | `volume_get(snap)` → `volume_delete` |
| `volume_snapshot_rollback` | logout (if session active) → `wait_for_session_gone` (QS-side) → `volume_rollback`; no re-login (PVE calls `activate_volume` on next start) |
| `volume_rollback_is_possible` | Timestamp comparison across sibling snapshots |
| `create_base` | offline → rename `vm-`→`base-` → template snapshot → online |
| `clone_image` | `volume_clone` from template snapshot → ACL → login |
| `volume_has_feature` | snapshot, clone, template, copy, sparseinit |
| `storage_can_replicate` | Returns 0 (not supported in this release) |

---

## Known Limitations

### PVE web UI after `pve-manager` upgrade

The `postinst` script injects a `<script>` tag into `/usr/share/pve-manager/index.html.tpl`
to register the QuantaStor UI panel. If `pve-manager` is upgraded it overwrites this file,
removing the tag. The storage backend continues to work (CLI/API unaffected), but the
**Datacenter → Storage → Add → QuantaStor** option disappears from the UI.

**Fix:** reinstall the plugin after a `pve-manager` upgrade:
```bash
dpkg -i pve-storage-quantastor_0.2.0-1_all.deb
```

A dpkg trigger to automate this is planned for a future release.

### iSCSI LUN field

The QuantaStor REST API returns a `lun` field on volume objects. This is an internal
pool-level concept and does not reflect the wire LUN. All volumes are presented at
iSCSI LUN 0 regardless of what the API reports. The plugin ignores the API field and
always constructs device paths with `-lun-0`.

### Snapshot rollback requires VM to be stopped

PVE enforces this: it calls `vm_stop` (5-second graceful timeout) before invoking the
rollback hook, then aborts with `"unable to rollback vm: vm is running"` if QEMU is
still alive. Rolling back a running VM is not supported.

If a rollback is interrupted and the VM ends up with a `lock: rollback` config entry,
unlock it with:
```bash
qm unlock <vmid>
# or: Datacenter → VM → More → Unlock
```

---

## Supported PVE Versions

| PVE Version | Status |
|---|---|
| 8.4.0 | Legacy patch files in `legacy/patches/`; new plugin requires no version-specific changes |
| 9.1.1 | Validated — dpkg install tested, all PVE services start cleanly |
| Future | New plugin tracks `PVE::Storage::Plugin` interface — no patches needed |

## License

See repository root for license information.
