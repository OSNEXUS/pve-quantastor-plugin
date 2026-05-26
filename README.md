# QuantaStor PVE Plugin

A [Proxmox VE](https://www.proxmox.com/en/proxmox-virtual-environment) storage plugin that integrates
[QuantaStor](https://www.osnexus.com/products/software-defined-storage) as a first-class iSCSI block
storage backend for virtual machines and containers.

---

## Status

| Component | State |
|---|---|
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
pve-quantastor-plugin/
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
├── www/
│   └── quantastor-storage.js         PVE web UI panel (injected by postinst)
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

The `quantastor` storage type will appear in the PVE UI immediately after the browser
is refreshed. The package includes a dpkg trigger that automatically re-injects the
UI script tag if `pve-manager` is upgraded — no manual reinstall required.

### Manual install (no package)

```bash
# Ensure iSCSI initiator is enabled (the package postinst does this automatically)
systemctl enable --now iscsid

# Install plugin modules
mkdir -p /usr/share/perl5/PVE/Storage/Custom
cp src/perl5/PVE/Storage/Custom/QuantaStor.pm  /usr/share/perl5/PVE/Storage/Custom/
cp -r src/perl5/PVE/Storage/QuantaStor/        /usr/share/perl5/PVE/Storage/

# Inject the web UI panel
cp www/quantastor-storage.js /usr/share/pve-manager/js/
sed -i '/pvemanagerlib\.js/a\    <script type="text/javascript" src="/pve2/js/quantastor-storage.js"></script>' \
    /usr/share/pve-manager/index.html.tpl

# Restart PVE services
systemctl restart pvedaemon pveproxy pvestatd
```

> **Note:** Manual installs do not include the dpkg trigger. If `pve-manager` is
> upgraded later, re-run the `sed` command above to restore the UI panel.

### Building the package from source

```bash
# Requires debhelper >= 13
apt install debhelper

bash build-deb.sh
# Produces ../pve-storage-quantastor_0.2.0-1_all.deb
```

---

## Configuration

### How the plugin stores credentials

The QuantaStor API password is **never** written to `/etc/pve/storage.cfg`. On
storage create/update, the plugin's `on_add_hook` / `on_update_hook` writes it
to `/etc/pve/priv/storage/<storeid>.pw` (mode `0600`, owner `root:www-data`),
the same convention upstream PVE uses for CIFS and PBS passwords. `/etc/pve/`
is the pmxcfs cluster filesystem, so the password file is automatically
replicated to every node in the cluster.

If `<storeid>.pw` is missing or empty on a node, every plugin operation on
that node fails. Recent plugin builds (≥ 0.2.0 post-2026-05-26) surface this
as an explicit error naming the file and remediation; older builds silently
shipped an empty password and surfaced a misleading `[err=26] Authentication
check failed` from QuantaStor.

### Web UI

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

`API Host`, `Username`, and `Pool` are fixed after creation. All other
fields can be edited later via the UI.

### CLI

The same configuration via `pvesm`:

```bash
pvesm add quantastor my-quantastor \
  --api_host 10.0.0.1 \
  --username admin \
  --password '<password>' \
  --pool_id <pool-name-or-uuid> \
  --content images \
  --portal 10.0.0.1 \
  --ssl_verify 0
```

Single-quote the password so the shell does not interpret special characters
(`$`, `!`, backticks, etc.).

`--portal` and `--ssl_verify` are optional. `--portal` defaults to `--api_host`
if omitted; `--ssl_verify` defaults to `0` (off, suitable for self-signed
certificates).

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
fields can be updated later via `pvesm set` (or the UI) without removing
the storage. **Avoid `pvesm remove` + `pvesm add` to apply changes** — the
remove path runs `on_delete_hook` which deletes the password file across the
cluster; if the subsequent re-add doesn't capture the password cleanly, you
end up with the missing-`.pw`-file failure mode described above.

### Verifying your setup

After the create, the password file should exist on **every** cluster node:

```bash
# Run on each PVE node:
ls -la /etc/pve/priv/storage/
# Expected: <storeid>.pw present, ~ N bytes (your password length + 1)

# Confirm activation works:
pvesm status --storage <storeid>
# Expected: Status = active, sizes populated
```

If the `.pw` file is present on the creating node but missing on others,
wait 5 seconds for pmxcfs to converge, then re-check. If it's still missing
after that, pmxcfs replication is broken — investigate corosync/pmxcfs
health before working around with manual copies.

If the `.pw` file is missing on every node, the password was not captured at
create time (see [Troubleshooting](#troubleshooting) below).

---

## Troubleshooting

### `Authentication check failed ... [err=26]` from QuantaStor

The plugin sent credentials to the appliance and the appliance rejected
them. Three possibilities, in decreasing order of frequency:

1. **The `.pw` file is missing on the local node** — pre-2026-05-26 plugin
   builds silently ship an empty password in this case. Check:
   ```bash
   ls -la /etc/pve/priv/storage/<storeid>.pw
   ```
   If absent or 0 bytes, write it manually:
   ```bash
   umask 077
   echo '<password>' > /etc/pve/priv/storage/<storeid>.pw
   chmod 0600 /etc/pve/priv/storage/<storeid>.pw
   ```
   pmxcfs will replicate it to the rest of the cluster within seconds.

2. **The credentials really are wrong** — verify with `curl` directly,
   which bypasses the plugin entirely:
   ```bash
   curl -k -u admin:'<password>' \
     "https://<api_host>:8153/qstorapi/storagePoolGet?storagePool=<pool>"
   ```
   If `curl` also returns err=26, fix the password in QuantaStor's UI then
   re-write `<storeid>.pw` on the PVE node.

3. **Special characters in the password got mangled** — if the password
   contains shell metacharacters (`$`, `!`, backticks) and you used
   `pvesm add` without single-quoting it, the shell may have expanded or
   eaten parts of it. Re-set with `pvesm set <storeid> -password '<pw>'`
   (single-quoted) and try again.

### `QuantaStor: no password configured for storage 'X' on node 'Y'`

Surfaced by plugin builds ≥ 0.2.0 post-2026-05-26 in exactly the situation
that used to produce err=26 above. The message names the storeid, the node,
the expected file path, and the `pvesm set` remediation command — follow it
verbatim.

### `Plugin "..." is implementing an older storage API, an upgrade is recommended`

Cosmetic warning that fires from every PVE daemon's plugin scan on PVE 9.2+
because the plugin declares `api()=13` for 9.1 compatibility. See
[Known Limitations](#older-storage-api-warning-on-pve-92).

### `Error loading storage plugin: implements an API version newer than current (N > M)`

Hard-block — the plugin's declared API version is higher than your PVE
version supports, so PVE refuses to load it. The storage type `quantastor`
will not appear in `pvesm` or the UI. Resolution: ensure you are on plugin
0.2.0 from 2026-05-26 or later (where `api()` was reverted from 14 back to
13 for 9.1 compat).

### Storage shows `active` on some nodes, `inactive` on others

If the inactive node prints the "no password configured" error, follow that
message. If it prints `[err=26]`, manually backfill the `.pw` file as in
**err=26** above. If it prints a network/SSL error, the inactive node
cannot reach `api_host:8153` — check firewall/routing, not the plugin.

### A `qm move-disk` or VM migration to another cluster node fails

Most often: the destination node cannot load the plugin (wrong PVE/plugin
version combination) or is missing the `.pw` file. Check on the destination:

```bash
pvesm status --storage <storeid>
ls -la /etc/pve/priv/storage/<storeid>.pw
journalctl -u pvedaemon --since '5 min ago' | grep QuantaStor
```

If migration fails with `storage type 'quantastor' not supported`, the
storage entry is missing `shared 1`. Plugin builds ≥ 0.2.0 post-2026-05-26
default this on new storage adds; for storage created on an earlier build,
backfill once:
```bash
pvesm set <storeid> -shared 1
```

---

## Running Tests

### Unit tests (no appliance required)

```bash
cd pve-quantastor-plugin
./t/run_tests.sh
```

Requires: `perl`, `libwww-perl`, `liburi-perl` (`JSON::PP` and `File::Temp` are included in Perl core)

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
| `volume_delete($vol_uuid)` | Delete volume (safe defaults; callers pass explicit flags for cascade/force) |
| `volume_resize($vol_id, $pool_id, $new_size_bytes)` | Grow a volume to `$new_size_bytes` (`storageVolumeResize`) — shrinking is not supported by QuantaStor |
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

Device paths use `/dev/disk/by-path/` for stability across reboots, unlike ephemeral
`/dev/sdX` assignments.

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
| `free_image` | logout → ACL remove → `volume_delete` (best-effort teardown; only delete fails loud) |
| `activate_volume` | `volume_acl_add` → iSCSI login → `wait_for_device` (dies with a clear message if the by-path symlink hasn't appeared within 30s) |
| `deactivate_volume` | iSCSI logout → `wait_for_logout` → `volume_acl_remove` |
| `volume_resize` | `storageVolumeResize` with `newSizeInBytes`; waits for QS session GC first (same guard as rollback) — shrinking not supported |
| `volume_snapshot` | `volume_snapshot` (snap stored as `<volname>_<snap>`) |
| `volume_snapshot_delete` | `volume_get(snap)` → `volume_delete` |
| `volume_snapshot_rollback` | logout (if session active) → `wait_for_session_gone` (QS-side GC) → `volume_rollback`; no re-login (PVE calls `activate_volume` on next start) |
| `volume_rollback_is_possible` | Timestamp comparison across sibling snapshots |
| `create_base` | offline → rename `vm-`→`base-` → template snapshot → online |
| `clone_image` | `volume_clone` from template snapshot → ACL → login |
| `volume_has_feature` | snapshot, clone, template, copy, sparseinit |
| `storage_can_replicate` | Returns 0 (not supported in this release) |

---

## Known Limitations

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

### Rollback time varies

QuantaStor's server-side session tracker takes a variable amount of time (typically
5–30 seconds) to release after an iSCSI logout. The plugin polls `sessionEnum` and
waits up to 30 seconds before calling the rollback API. This is normal behaviour — if
rollback consistently takes close to 30s, contact OSNEXUS support to investigate the
appliance's session GC configuration.

### "Older storage API" warning on PVE 9.2+

The plugin declares `api() = 13` so it loads on both PVE 9.1.x and 9.2.x. PVE 9.2
raised its `APIVER` to 14 and prints the following at every plugin scan:

```
Plugin "PVE::Storage::Custom::QuantaStor" is implementing an older storage API, an upgrade is recommended
```

This is **cosmetic**. The plugin functions identically on 9.1 and 9.2 — none of the
hooks we override changed between API versions 13 and 14. The warning appears in
`/var/log/syslog` and `journalctl` from every PVE daemon (`pvestatd`, `pvedaemon`,
`pveproxy`, `pvescheduler`) — roughly 10–20 lines per minute per node on 9.2.

We chose 9.1+9.2 compatibility over silencing the warning. If the noise is
problematic in your environment, filter it out:

```bash
# View journal excluding the warning
journalctl | grep -v 'implementing an older storage API'
```

Or add a rsyslog filter at `/etc/rsyslog.d/99-quantastor-quiet.conf`:

```
:msg, contains, "implementing an older storage API" stop
```

A future plugin release will revisit this once PVE 9.1.x support is no longer needed.

---

## Supported PVE Versions

PVE's storage subsystem hard-blocks a plugin whose declared `api()` lies
outside the range `[APIVER - APIAGE, APIVER]`. The plugin currently declares
`api()=13`. Empirically verified against live nodes (2026-05-26):

| PVE Version | `APIVER` | Plugin loads? | Notes |
|---|---|---|---|
| **9.2.x** | 14 | ✓ loads, cosmetic "older storage API" warning | Full lifecycle validated (create → snapshot → rollback → resize → destroy). Warning is informational; see [Known Limitations](#older-storage-api-warning-on-pve-92). |
| **9.1.x** | 13 | ✓ loads silently (exact match) | Validated against 9.1.1 in a 2-node cluster with 9.2. Full lifecycle. |
| **8.4.0** | 11 | ✗ hard-blocked: `implements newer than current (13 > 11)` | Not supported by this plugin. |
| **Future PVE (APIVER ≥ 18)** | ≥18 | ✗ hard-blocked: `API version too old` | Plugin will need to bump `api()` once `APIVER - APIAGE > 13`. Currently APIAGE=5, so this isn't an issue until APIVER reaches 18 (likely PVE 10.x+). |

### Mixed-version cluster guidance

Proxmox does not officially support cluster nodes on different *major*
versions (e.g., 8.x + 9.x in the same cluster). For this plugin specifically:

- **All 9.x nodes can be mixed** — 9.1 and 9.2 in the same cluster work
  fine. The 9.2 nodes will print the cosmetic warning; the 9.1 nodes will
  load silently. Storage operations work transparently across both.
- **Do not include 8.x nodes** — the plugin won't load there at all, and
  any storage operation routed to an 8.x node (e.g., a VM migration target)
  will fail because the `quantastor` type isn't registered.

### Plugin upgrade guidance

Before pushing a new plugin .deb to a cluster:

1. Check the new plugin's `api()` value (`grep 'sub api ' /usr/share/perl5/PVE/Storage/Custom/QuantaStor.pm`).
2. Confirm `api()` is `≤ APIVER` on every cluster node (`grep APIVER /usr/share/perl5/PVE/Storage.pm`).
3. Upgrade one node first and verify the plugin loads (`pvesm status` does not print "Error loading"). Only then upgrade the rest.

A plugin whose `api()` exceeds the cluster's lowest `APIVER` will hard-block
on those nodes. **Existing storage entries in `storage.cfg` are not removed**
when this happens, but any plugin operation on those nodes (status,
activate, free_image) errors out. Recovery is either to upgrade PVE on the
affected nodes or downgrade the plugin.

---

## Roadmap

### ~~Phase 3 — `QuantaStorPlugin.pm`~~ ✅ Complete

All PVE storage hooks implemented and unit tested (46 tests). Full VM lifecycle validated
on live PVE 9.1.1 + QuantaStor: create → snapshot → rollback → template → clone.

### ~~Phase 4 — Packaging~~ ✅ Complete

Debian package `pve-storage-quantastor_0.2.0-1_all.deb` builds cleanly with `dpkg-buildpackage`
and installs successfully on PVE 9.1.1. Plugin lives in `/usr/share/perl5/PVE/Storage/Custom/`
(PVE's auto-discovery path for third-party plugins). `postinst` restarts PVE services and
registers a dpkg trigger so the UI panel survives future `pve-manager` upgrades automatically.

### ~~Phase 5 — UI enhancements~~ ✅ Complete

The `quantastor` type is now fully integrated into the PVE web UI. `QuantaStor` appears
in the **Datacenter → Storage → Add** dropdown with a dedicated two-column input panel
(General + Advanced tabs). Fixed fields render as read-only when editing an existing entry.

Implementation ships a standalone JS file (`/usr/share/pve-manager/js/quantastor-storage.js`)
injected into `index.html.tpl` by `postinst` — no `pve-manager` source patches required.
Removed cleanly by `prerm` on uninstall.

### Phase 6 — Migration tooling

For any deployments still running a legacy patch-based QuantaStor integration:

- Script to enumerate volumes under the old `zfs`/`quantastor` storage entry
- Move VM disk associations to the new `quantastor` storage type non-destructively
- Restore pristine PVE files: `apt reinstall pve-storage pve-manager`

### Phase 7 — Container storage support (`rootdir`)

Extend the plugin to support LXC container root filesystems in addition to VM disks.

- Add `rootdir` to `plugindata` content types alongside `images`
- Each LXC container would receive a dedicated thin-provisioned iSCSI LUN (same
  provisioning model as VM disks)
- Requires formatting the LUN with an appropriate filesystem and mounting it for
  the container — more involved than VM disk support where QEMU handles the block
  device directly
- Update UI panel to allow `Container` content type selection
- Validate with LXC container create / start / stop / destroy lifecycle on PVE

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

## License

See `LICENSE` in the repository root for license information.
