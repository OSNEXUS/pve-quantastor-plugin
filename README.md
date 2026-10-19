# QuantaStor PVE Plugin

A [Proxmox VE](https://www.proxmox.com/en/proxmox-virtual-environment) storage plugin that integrates
[QuantaStor](https://www.osnexus.com/products/software-defined-storage) as a first-class iSCSI block
storage backend for virtual machines and containers.

---

## Status

| Component | State |
|---|---|
| `QuantaStor/APIClient.pm` | Complete — clean REST client, 50 unit tests |
| `QuantaStor/ISCSIManager.pm` | Complete — clean iSCSI lifecycle, 42 unit tests |
| `Custom/QuantaStor.pm` (first-class type) | Complete — all PVE hooks implemented, 65 unit tests |
| Debian packaging | Complete — `pve-storage-quantastor_1.0.1-1_all.deb` |

---

## Architecture

### How it works

QuantaStor manages storage volumes internally and exports them over iSCSI. The plugin sits between
Proxmox VE's storage layer and the QuantaStor REST API:

```
Proxmox VE storage layer (pvedaemon / pvestatd / qm / pct)
        │
        ▼
 Custom/QuantaStor.pm            ← PVE storage plugin (registers type 'quantastor')
        │
        ├── APIClient.pm ─────── control plane ──────► QuantaStor REST API (HTTPS :8153)
        │                        provision / snapshot / clone / resize / ACL
        │
        └── ISCSIManager.pm      ← iscsiadm discover/login/logout/rescan
                │
                ▼
        open-iscsi initiator ═══ data plane (guest I/O) ═══► iSCSI target (TCP :3260)
                │                                            one target per volume, LUN 0
                ▼
        /dev/disk/by-path/...    ← stable block device
                │
                ▼
        QEMU raw VM disk (images) / ext4 container rootfs (rootdir)
```

The same diagram as an image: [`docs/architecture.svg`](docs/architecture.svg).

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
dpkg -i pve-storage-quantastor_1.0.1-1_all.deb
# PVE services are restarted automatically by postinst
```

The `quantastor` storage type will appear in the PVE UI immediately after the browser
is refreshed. The package includes two dpkg file triggers: one on `index.html.tpl`
(re-injects the UI script tag when `pve-manager` is upgraded) and one on
`PVE/API2/Storage/Scan.pm` (re-injects the pool-scan API route when `pve-storage` is
upgraded). No manual reinstall is required after either upgrade.

### Upgrading from the patch-based alpha

The archived v0.1 alpha (GitHub tag `v0.1-alpha`) worked by patching Proxmox's own
storage modules and registered its storage as a `zfs` entry with
`iscsiprovider quantastor`. Version 1.0.0 replaced that integration entirely and
1.0.1 is the same first-class plugin, so on any node running 1.0.0 or later:

- **A leftover alpha storage entry is inert.** The Proxmox core patches it relied
  on do not survive a `pve-storage` upgrade, so the entry has no working provider
  behind it. Nothing warns about this: the entry still shows in `pvesm status`,
  but every operation against it fails.
- **Do not point a `quantastor` storage and a leftover alpha entry at the same
  pool.** Both name volumes `vm-<id>-disk-<n>`, so two storage entries would be
  managing the same QuantaStor volumes and access lists.
- **Moving disks between the two entries is not a supported path.** Do not
  `qm move-disk` / `pct move-volume` onto the alpha entry.

Recommended sequence: stop the guests that use the alpha entry, note their
volumes, remove the alpha entry with `pvesm remove <storeid>`, add the
`quantastor` storage for the same pool, then re-attach each guest's disks under
the new storage (the volumes on the appliance are untouched by this). Finally
restore pristine Proxmox files with `apt reinstall pve-storage pve-manager`.
See Roadmap for the migration tooling that would automate this.

### Manual install (no package)

```bash
# Ensure iSCSI initiator is enabled (the package postinst does this automatically)
systemctl enable --now iscsid

# Install plugin modules
mkdir -p /usr/share/perl5/PVE/Storage/Custom
cp src/perl5/PVE/Storage/Custom/QuantaStor.pm  /usr/share/perl5/PVE/Storage/Custom/
cp -r src/perl5/PVE/Storage/QuantaStor/        /usr/share/perl5/PVE/Storage/

# Install pool-scan API endpoint
mkdir -p /usr/share/perl5/PVE/API2/Storage
cp src/perl5/PVE/API2/Storage/QuantaStorScan.pm /usr/share/perl5/PVE/API2/Storage/
echo 'require PVE::API2::Storage::QuantaStorScan;' >> /usr/share/perl5/PVE/API2/Storage/Scan.pm

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
# Produces ../pve-storage-quantastor_1.0.1-1_all.deb
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
that node fails. 0.2.0 and later surface this
as an explicit error naming the file and remediation; older builds silently
shipped an empty password and surfaced a misleading `[err=26] Authentication
check failed` from QuantaStor.

### Authenticating with an API token instead of a password

The plugin can authenticate to the appliance with a QuantaStor **user
application token** rather than a user's password, so the PVE cluster never
holds a login that also works in the web UI. No plugin option is involved: the
token is entered in the same two fields.

1. On the appliance, create a token for the account the plugin will use
   (ideally a dedicated least-privilege user, see below):

   ```bash
   qs user-app-token-add --user=pve-plugin --name=pve-cluster
   ```

   The result shows an **app key** (a UUID, acts as the username) and a
   64-character **access token** (acts as the password). Copy the access token
   now; it is not shown again. The web UI offers the same under the user's
   security settings.
2. Add or edit the PVE storage with
   **Username** = the app key and **Password** = `QSAPPTKN:` followed by the
   access token, for example `QSAPPTKN:3f9a…c21e`. The token name also works in
   place of the app key.
3. Everything else is unchanged: the pool scan button, `pvesm add`, volume
   create/attach/delete all run under the token, and the credential is stored in
   `/etc/pve/priv/storage/<storeid>.pw` exactly like a password.

Notes:

- A token inherits the role of the user it belongs to, so pair it with a
  least-privilege user rather than `admin`. Do **not** mark the token read-only;
  the plugin creates and deletes volumes.
- Tokens can carry an expiry. Set none (the default) for a storage credential,
  or plan to rotate it: `qs user-app-token-delete` then create a new one and
  `pvesm set <storeid> -password 'QSAPPTKN:<new token>'`.
- Revoking access is one command on the appliance (`qs user-app-token-delete`);
  the PVE side needs no change until a new token is issued.
- Verified with this plugin against a QuantaStor 7 lab appliance: pool scan,
  storage add, volume alloc and free, storage remove. Both a non-expiring and an
  expiring token authenticated; a wrong token is rejected with the usual
  `[err=26]` authentication failure.

### Web UI

Go to **Datacenter → Storage → Add → QuantaStor**.

| Field | Tab | Description |
|---|---|---|
| ID | General | Auto-fills with the first available `qs-storage-N`; edit as needed |
| API Host | General | QuantaStor appliance IP or hostname |
| Username | General | QuantaStor API user, or the app key of an API token (see "Authenticating with an API token") |
| Password | General | API password, or `QSAPPTKN:<access token>` — stored securely, never written to `storage.cfg` |
| Pool | General | Storage pool name on the QuantaStor appliance. Click the scan button (🔍) to connect to the appliance and populate a dropdown of available pools. |
| Content | General | `Disk image` (VM disks), `Container` (LXC root filesystems), or both — both are preselected |
| Nodes | General | Restrict to specific PVE nodes (leave empty for all nodes) |
| iSCSI Portal | Advanced | Portal address for iSCSI login — defaults to API Host if left blank |
| SSL Verify | Advanced | Enable SSL certificate verification — leave off for self-signed certs |

`API Host`, `Username`, and `Pool` are fixed after creation. All other fields can
be edited later via the UI.

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
(`$`, `!`, backticks, etc.). For token authentication pass the app key as
`--username` and `'QSAPPTKN:<access token>'` as `--password`.

`--portal` and `--ssl_verify` are optional. `--portal` defaults to `--api_host`
if omitted; `--ssl_verify` defaults to `0` (off, suitable for self-signed
certificates).

Volumes are **thin provisioned by default**: they consume pool space as data
is written, not their full size at creation. Set `sparse 0` on the storage to
opt into thick provisioning (each volume reserves 100% of its size in the
pool at creation time). Note this default is the opposite of PVE's built-in
ZFS plugins, where `sparse` defaults to off.

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

### QuantaStor HA storage pools

If the pool is a QuantaStor **HA storage pool** — one that fails over between two
controllers — configure the storage against the **failover group's virtual
interface**, not against either controller's own address:

```
# /etc/pve/storage.cfg
quantastor: qs-ha
        api_host 10.0.0.20        # the failover group's floating VIF
        portal 10.0.0.20          # the same VIF
        pool_id my-ha-pool
        username admin
        content images,rootdir
        shared 1
```

Both `api_host` and `portal` must be that virtual interface. It moves with the
pool when the pool fails over, so the REST API endpoint and the iSCSI portal
follow the active controller on their own. Point either one at a controller's own
address instead and the storage stops working the moment the pool moves to the
other controller.

Nothing else about the configuration changes — the plugin does not need to be
told that the pool is an HA pool, and no extra options are required.

Guests keep running across a failover, pausing for roughly 30–45 seconds while
the pool is exported and re-imported. See
[QuantaStor HA pool failover pauses guest I/O](#quantastor-ha-pool-failover-pauses-guest-io)
under Known Limitations for the measured behaviour, and for the one initiator
setting you should not change.

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

## Container (LXC) support

LXC containers can place their root filesystem (and additional mount points) on
QuantaStor storage. Enable the `Container` content type on the storage — tick
it in the web UI dialog, or:

```bash
pvesm set <storeid> --content images,rootdir
```

### How it works

A container volume is the same raw iSCSI LUN as a VM disk (`vm-<vmid>-disk-N`,
thin provisioned by default). The difference is what sits on top: PVE's
container stack (`PVE::LXC`) formats the LUN with ext4, mounts it, and runs
`resize2fs` on grow — the plugin's job is only to hand PVE a local block
device, exactly as it does for VMs. This is the same block-based rootdir model
used by PVE's built-in RBD and LVM-thin plugins.

Validated container lifecycle (PVE 9.1/9.2, two-node cluster):

| Operation | Notes |
|---|---|
| Create / start / stop / destroy | Privileged and unprivileged CTs |
| Snapshot of a running CT | Root fs (and mount points) are fsfreeze'd first, so snapshots are filesystem-consistent |
| Snapshot delete / rollback | Rollback requires the CT stopped (PVE enforces this) |
| Resize (`pct resize`) | Online and offline; LUN grows, then PVE runs `resize2fs` |
| Template + clones | `pct template`, then linked or full clones; destroy clones before their template |
| Migration between nodes | Restart mode only — containers on block storage cannot live-migrate (PVE-wide constraint, same as RBD/LVM-thin) |
| `pct move-volume` | Both directions, to/from other storages; CT moves are file-level (rsync), not block copies |
| Extra mount points | `pct set <ctid> -mp0 <storeid>:<size>,mp=/path` allocates a dedicated LUN per mount point |
| Discard / TRIM | `pct fstrim <ctid>` returns freed space to the thin volume (verified end-to-end: ext4 → iSCSI UNMAP → pool) |

### Container limitations

- **Container templates (`vztmpl`) are not supported** — template tarballs need
  a POSIX filesystem to live on, which a raw block LUN can't provide. Keep CT
  templates on `local` (or another file-based storage) and create containers
  from there onto QuantaStor. This mirrors RBD, where vztmpl is likewise not
  storable.
- **HA fencing with mounted CT filesystems** is safe under Proxmox's default
  watchdog fencing, validated on a two-node cluster with a corosync QDevice and
  corosync isolated from the storage network. With a container's rootfs on
  QuantaStor storage under a continuous write load, the node running it was
  partitioned from the cluster while its storage path stayed reachable — the
  hazardous case. The partitioned node lost quorum in about fifteen seconds and
  kept the LUN writable for roughly a minute more, then its watchdog reset it;
  only after its iSCSI session was gone did the surviving node attach and mount
  the LUN. There was no window in which both nodes wrote to the volume, and the
  filesystem replayed its journal and mounted cleanly. Note two things: the
  plugin provides no storage-level exclusion (both nodes may hold an ACL at
  once), so this safety rests entirely on Proxmox's watchdog timing — do not
  shorten the watchdog or fence-delay defaults; and ext4's multi-mount
  protection acted as a second line of defense, making the surviving node wait
  and confirm the filesystem was free before mounting.
- **QuantaStor version**: use a current QuantaStor 7 build that includes the
  server-side fix for the template-conversion volume wedge and the
  fresh-snapshot delete window. Older 7.0 builds wedge volumes on template
  conversion (stale NVMeoF export after rename) and refuse fresh-snapshot
  deletes for several minutes (see Troubleshooting, `err=493`).

---

## Troubleshooting

### `Authentication check failed ... [err=26]` from QuantaStor

QuantaStor reports err=26 whenever it processes a request whose HTTP Basic
credentials are missing, empty, or wrong. In the field this has three distinct
causes — the first was the subtle one, fixed in the build noted below:

0. **The plugin never sent the credentials at all (fixed in 0.2.1)** —
   builds before this fix authenticated via LWP's challenge-response
   (`$ua->credentials`), which only attaches the `Authorization` header if the
   appliance first issues a `401 WWW-Authenticate: Basic` challenge whose realm
   string matches exactly. Several QuantaStor versions answer an
   unauthenticated API request with an err=26 body under HTTP 200 instead of a
   401 challenge, or use a different realm string — so LWP sent no credentials
   and the appliance returned err=26 that looked exactly like a wrong password.

   The tell-tale sign: **`curl -u admin:'<pw>'` succeeds against the same
   appliance but the plugin still fails.** `curl` sends Basic auth
   preemptively; the old plugin waited for a challenge that never came. This
   build now sends Basic preemptively too, matching curl. If you can reproduce
   this, upgrade the plugin — no config change is needed. To confirm it's this
   case rather than a genuinely bad password, compare preemptive vs.
   challenge-response with curl:
   ```bash
   # Preemptive (what curl and the fixed plugin do) — expect success:
   curl -k -u admin:'<pw>' \
     "https://<api_host>:8153/qstorapi/storagePoolGet?storagePool=<pool>"

   # Challenge-response (what the OLD plugin did) — if this err=26's while the
   # line above succeeds, you hit exactly this bug:
   curl -k --anyauth -u admin:'<pw>' \
     "https://<api_host>:8153/qstorapi/storagePoolGet?storagePool=<pool>"

   # Inspect what (if any) auth challenge the appliance issues:
   curl -k -sD - -o /dev/null \
     "https://<api_host>:8153/qstorapi/storagePoolGet?storagePool=<pool>" \
     | grep -i www-authenticate    # empty output = no challenge issued
   ```

1. **The `.pw` file is missing on the local node** — builds before 0.2.0
   silently ship an empty password in this case. Check:
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

### `Failed to delete storage volume ... [err=493]` on destroy or snapshot delete

QuantaStor raised `OSN_ERR_DELETE_ZVOL_FAILED`: the backing ZFS volume was
busy when the appliance tried to destroy it.

**Appliance builds carrying the server-side fix eliminate all known causes** —
the stale NVMeoF export left by volume renames (the template-conversion
wedge), the ~5-minute undeletable-fresh-snapshot
window (a udev watch race, plus snapshots no longer auto-export at creation),
and the boot-time nvmet serial error. On such builds a persistent err=493 is
unexpected — capture `/var/log/qs/qs_service.log` around the failure and file
a ticket.

On **older appliance builds**:

1. **Brief post-teardown window:** the zvol can stay busy for a few seconds
   after iSCSI target teardown. The plugin already rides this out
   (`free_image` retries, and falls back to per-snapshot deletion if a cascade
   delete partially completed). If a destroy still fails, simply retry it.
2. **Fresh-snapshot window (~5 minutes):** deleting a snapshot within a few
   minutes of creating it is refused while the zvol is busy. The plugin
   retries `pct delsnapshot` / `qm delsnapshot` through this for about three
   minutes (the task log shows each attempt) before giving up. If it still
   fails, the guest is left locked — unlock with `pct unlock <ctid>` (or
   `qm unlock <vmid>`) and retry after a few minutes.
3. **Persistent — stale NVMeoF export after a rename** (`qm template` /
   `pct template` renames `vm-* -> base-*`): the nvmet subsystem keeps the OLD
   name, teardown never finds it, and its namespace holds the zvol open
   indefinitely. Confirm and clear on the appliance (the subsystem is named
   after the volume's *original* name):

   ```bash
   grep -H <volume-guid> /sys/kernel/config/nvmet/subsystems/*/namespaces/*/device_path
   SUBNAME=<matching subsystem nqn>
   rm -f /sys/kernel/config/nvmet/ports/*/subsystems/$SUBNAME
   SUB=/sys/kernel/config/nvmet/subsystems/$SUBNAME
   echo 0 > $SUB/namespaces/1/enable; rmdir $SUB/namespaces/1 $SUB
   ```

   then retry the delete. No reboot required. Upgrading the appliance is the
   real fix.

### Container fails to start: `run_buffer: ... Script exited with status 255` / `Failed to run lxc.hook.pre-start`

If a container on QuantaStor storage fails to start with only this opaque lxc
error, check that the storage still advertises the `Container` content type —
PVE's pre-start hook refuses to start a CT whose rootfs storage lacks
`rootdir`, and lxc swallows the real error message. This happens when someone
edits the storage's Content setting after containers were created on it:

```bash
pvesm set <storeid> --content images,rootdir
```

The iSCSI login and filesystem underneath are typically fine; re-adding the
content type and starting again is sufficient.

### `QuantaStor: no password configured for storage 'X' on node 'Y'`

Surfaced by 0.2.0 and later in exactly the situation
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
will not appear in `pvesm` or the UI. Resolution:

- **For 9.1.x customers**: ensure you are on plugin 0.2.0 or
  later (where `api()` was reverted from 14 back to 13).
- **For 8.4.0 customers**: not supported by this plugin (the archived
  patch-based alpha, GitHub tag `v0.1-alpha`, was the last to target 8.4).

### Storage shows `active` on some nodes, `inactive` on others

If the inactive node prints the "no password configured" error, follow that
message. If it prints `[err=26]`, manually backfill the `.pw` file as in
**err=26** above. If it prints a network/SSL error, the inactive node
cannot reach `api_host:8153` — check firewall/routing, not the plugin.

### A `qm move-disk` or VM migration to another cluster node fails

**First, verify the plugin is loaded on the destination:**

```bash
# On the destination node
pvesm status
ls -la /etc/pve/priv/storage/<storeid>.pw
journalctl -u pvedaemon --since '5 min ago' | grep -i quantastor
```

Common causes:

- **Plugin not installed on destination** — install the `.deb` on every cluster
  node and restart `pvedaemon pveproxy pvestatd`.
- **Missing `.pw` file** — the file lives in `/etc/pve/priv/` (pmxcfs), which
  replicates automatically. If a node is offline when the storage is added it
  may miss the file; backfill with `pvesm set <storeid> --password <pass>` from
  any node.
- **QEMU version skew** — if the source node runs a newer QEMU the default
  machine type (e.g. `pc-q35-11.0`) may be too new for the destination. Pin
  the VM's machine type: `qm set <vmid> --machine pc-q35-10.1` (or whichever
  version matches the older node). Check with `qemu-system-x86_64 --version`
  on both nodes.
- **Storage `shared` flag not set** — PVE's migration scanner classifies the
  storage as local if `shared=0` and blocks migration. Run
  `pvesm set <storeid> --shared 1` or re-add the storage via the UI.

---

## Running Tests

### Unit tests (no appliance required)

```bash
cd qs-pve-plugin
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

Device paths use `/dev/disk/by-path/` for stability across reboots, unlike ephemeral
`/dev/sdX` assignments.

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

---

## Roadmap

### Migration tooling

For deployments still running the archived patch-based alpha:

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

All 157 unit tests must pass with no warnings. New functionality should include corresponding
tests in the relevant test file (`t/01-api-client.t`, `t/02-iscsi-manager.t`, or `t/04-plugin.t`).
`t/05-no-ticket-refs.t` guards the documentation rule below.

- Do not reference internal ticket IDs, issue-tracker links, or working dates in tracked
  files — describe the behavior and the release version instead
  (`t/05-no-ticket-refs.t` enforces this).

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
| `free_image` | logout → ACL remove → `volume_delete` (best-effort teardown; only delete fails loud) |
| `activate_volume` | `volume_acl_add` → iSCSI login → `wait_for_device` (dies with a clear message if the by-path symlink hasn't appeared within 30s) |
| `deactivate_volume` | iSCSI logout → `wait_for_logout` → `volume_acl_remove` |
| `volume_resize` | `storageVolumeResize` with `newSizeInBytes` (flags=2 resizes through an active session — no logout), then an iSCSI rescan so the kernel sees the new LUN size — shrinking not supported |
| `volume_snapshot` | `volume_snapshot` (snap stored as `<volname>_<snap>`) |
| `volume_snapshot_delete` | `volume_get(snap)` → `volume_delete`; retries a busy (`err=493`) delete for ~3 minutes, other faults fail fast |
| `volume_snapshot_rollback` | logout (if session active) → `wait_for_session_gone` (QS-side GC) → `volume_rollback`; no re-login (PVE calls `activate_volume` on next start) |
| `volume_rollback_is_possible` | Timestamp comparison across sibling snapshots |
| `create_base` | offline → rename `vm-`→`base-` → template snapshot → online |
| `clone_image` | `volume_clone` from template snapshot → ACL → login |
| `volume_has_feature` | snapshot, clone, template, copy, sparseinit |
| `storage_can_replicate` | Returns 0 (not supported in this release) |

---

## Known Limitations

### Cluster compatibility

Live migration, offline migration, resize on running VMs, snapshot/rollback,
template/clone, and VM destroy have all been validated on a two-node PVE 9.2
cluster sharing a common QuantaStor portal.

One minor quirk: `qm template` (`create_base`) re-logins to the renamed
`base-*` volume after the operation, leaving an active iSCSI session on the
coordinator node. PVE cleans this up automatically before any subsequent volume
operation. It has no practical impact on cluster operations.

### QuantaStor HA pool failover pauses guest I/O

If the storage is backed by a QuantaStor **HA storage pool** — a failover group
whose pool moves between two controllers — then a controller failover pauses I/O
for every guest on that storage while the pool is exported from one controller
and imported on the other.

**Expect roughly 30–45 seconds of paused I/O.** Guests block for the duration
rather than failing. Measured on a two-node HA pair with running VMs and
containers on the pool, guest-visible pauses were **26–34 seconds**, after which
I/O resumed with no data loss. Guests stayed running, filesystems were clean
afterwards, and the iSCSI sessions recovered on their own — the initiator
re-established the connections without the plugin having to log in again.

**The pause does not grow with the number of volumes.** It was measured at 26
seconds with one volume on the pool, 33 seconds with two, and 34 seconds with
eleven volumes while a guest wrote continuously. The cost is dominated by
exporting and importing the pool itself and moving the virtual interface, which
happens once per failover regardless of how many volumes the pool serves. The
failover operation as a whole does take longer with more volumes (45 to 50
seconds in those runs), but the extra time is not spent blocking guest I/O.

This assumes the storage is configured against the failover group's virtual
interface rather than a single controller — see
[QuantaStor HA storage pools](#quantastor-ha-storage-pools) under Configuration.

Two things to be aware of before relying on this:

- **Do not lower `node.session.timeo.replacement_timeout`** in
  `/etc/iscsi/iscsid.conf`. At its default of 120 seconds it is the budget the
  initiator gives a session to come back before it fails the queued I/O up the
  stack, and it is what makes the pause survivable. Tuning advice that shortens it
  for fast multipath failover does not apply here — there is no alternate path to
  switch to, so shortening it turns a survivable pause into I/O errors. Note that
  the per-command SCSI timeout (`/sys/block/sd*/device/timeout`, 30 seconds) does
  *not* govern this window: while the session is in recovery the transport blocks
  the device queue and holds the I/O rather than timing commands out. On a
  validated failover the host kernel log shows only the connection error and, on
  reconnect, a `Power-on or device reset occurred` notice — no command aborts.
- Roughly 5–10 seconds of the pause is only *detection*. The initiator notices the
  connection is gone through its NOP-out ping (`noop_out_interval` and
  `noop_out_timeout`, 5 seconds each by default), so the total pause is the
  appliance's pool export/import time plus that detection delay.

**VMs running their own operating system survive this too.** A Debian 12 VM with
its root ext4 filesystem — mounted `errors=remount-ro`, so it would drop to
read-only on a write error — was failed over twice while writing continuously.
Each time the guest saw a 26-second I/O pause and then carried on: the root
filesystem stayed read-write, data written before the failover was intact, and the
guest kernel logged nothing at all. No aborts, no timeouts, no filesystem errors.

The guest's own disk timeout is not the deciding factor. Repeating the test with
the guest's SCSI command timeout lowered to 5 seconds, far shorter than the pause,
changed nothing — still no guest-side errors and no read-only remount. QEMU holds
the outstanding request while the host waits for the session to come back, so the
guest never receives an I/O error to react to. There is no need to tune guest disk
timeouts for this.

Those measurements used virtio-scsi with ext4. Other guest operating systems and
disk controller types have not been characterised.

This is separate from Proxmox's own HA — see the container limitations section
regarding HA fencing.

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

QuantaStor's server-side session tracker does not release as soon as the initiator
logs out. Its session manager refreshes on a cycle with a hardcoded 180-second
floor, so a session can remain visible to the appliance for roughly that long
after the guest stops. The plugin polls `sessionEnum` and waits up to 200 seconds
before calling the rollback API, so that the wait outlasts that cycle.

This means a rollback issued immediately after stopping a guest can legitimately
take a couple of minutes to complete. That is normal behaviour, not a hang. If a
rollback instead *fails* with an active-session error, contact OSNEXUS support to
investigate the appliance's session configuration.

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
`api()=13`. Empirically verified against live nodes:

| PVE Version | `APIVER` | Plugin loads? | Notes |
|---|---|---|---|
| **9.2.x** | 14 | ✓ loads, cosmetic "older storage API" warning | Full lifecycle validated (create → snapshot → rollback → resize → destroy). Warning is informational; see [Known Limitations](#older-storage-api-warning-on-pve-92). |
| **9.1.x** | 13 | ✓ loads silently (exact match) | Validated against 9.1.1 in a 2-node cluster with 9.2. Full lifecycle. |
| **8.4.0** | 11 | ✗ hard-blocked: `implements newer than current (13 > 11)` | Not supported by this plugin (the archived patch-based alpha, GitHub tag `v0.1-alpha`, was the last to target 8.4). |
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

## License

See `LICENSE` in the repository root for license information.
