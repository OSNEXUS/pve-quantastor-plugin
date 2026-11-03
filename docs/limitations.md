# Known limitations and supported versions

## Cluster compatibility

Live migration, offline migration, resize on running VMs, snapshot/rollback,
template/clone, and VM destroy have all been validated on a two-node PVE 9.2
cluster sharing a common QuantaStor portal.

One minor quirk: `qm template` (`create_base`) re-logins to the renamed
`base-*` volume after the operation, leaving an active iSCSI session on the
coordinator node. PVE cleans this up automatically before any subsequent volume
operation. It has no practical impact on cluster operations.

## Sharing a storage pool between Proxmox clusters

Without a volume prefix, a QuantaStor storage pool must be used by only one
Proxmox cluster. To let several clusters share a pool, give each cluster's
storage a different `volume_prefix` when you add it (see
[Sharing one pool with a volume prefix](configuration.md#sharing-one-pool-with-a-volume-prefix)).
Otherwise give each cluster its own pool (see
[Multiple Proxmox clusters on one appliance](configuration.md#multiple-proxmox-clusters-on-one-appliance)).

Without a prefix the plugin gives a volume the same name on QuantaStor as it has
in Proxmox, for example `vm-100-disk-0`. When it lists a pool's volumes, it
reports every such volume in that pool as belonging to the cluster that asked.
VM IDs are only unique within one cluster. If two clusters share a pool without
prefixes, both can have a VM 100, and each cluster sees the other's `vm-100-*`
disks as its own:

- `qm disk rescan` attaches the other cluster's disks to the local VM with the
  same ID, as unused disks.
- Destroying a VM and removing its unreferenced disks deletes the other cluster's
  disks for that VM ID. **This loses data.**

The prefix cannot be added to an existing storage, because its volumes would no
longer be found. A cluster that already uses the pool without a prefix can keep
doing so; only the clusters that join later need one.

## One storage entry per pool within a cluster

Within one Proxmox cluster, add only one `quantastor` storage entry per
QuantaStor pool, unless each entry has its own `volume_prefix`. To use
multipath on a pool, switch it on for the existing entry
(`pvesm set <storeid> --multipath 1`) rather than adding a second one. The
same goes for the transport: do not add a Fibre Channel entry next to an iSCSI
entry for the same pool. `transport` is fixed when the entry is added, so choose
it then.

Two entries without prefixes list the same volumes under two names, for example
`qs-a:vm-100-disk-0` and `qs-b:vm-100-disk-0`, and Proxmox treats the second
name as a separate disk:

- Restoring a VM through one entry ends with a rescan that finds the new
  cloud-init volume under the other entry, reports
  `found unused cloudinit disk '<other entry>:vm-<id>-cloudinit', removing it`,
  and deletes the volume the restore just created. The restored VM's first start
  then fails (see
  [A VM whose cloud-init volume is missing fails its next start](#a-vm-whose-cloud-init-volume-is-missing-fails-its-next-start)).
- The same rescan adds the VM's own disks again as `unused` disks under the
  other entry. They are the same QuantaStor volumes as the disks in use, so
  removing one of these unused disks deletes the disk the VM is using.
  **This loses data.**

## QuantaStor HA pool failover pauses guest I/O

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
[QuantaStor HA storage pools](configuration.md#quantastor-ha-storage-pools) in Configuration.

Two things to be aware of before relying on this:

- **Do not lower `node.session.timeo.replacement_timeout`** in
  `/etc/iscsi/iscsid.conf`. At its default of 120 seconds it is the budget the
  initiator gives a session to come back before it fails the queued I/O up the
  stack, and it is what makes the pause survivable. Tuning advice that shortens it
  for fast multipath failover does not apply here — there is no alternate path to
  switch to, so shortening it turns a survivable pause into I/O errors. (With the
  plugin's `multipath 1`, multipathd does shorten it, and the `no_path_retry`
  queueing in [Multipath](multipath.md) is what carries the pause instead.) Note that
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

## iSCSI LUN field

The QuantaStor REST API returns a `lun` field on volume objects. This is an internal
pool-level concept and does not reflect the wire LUN. All volumes are presented at
iSCSI LUN 0 regardless of what the API reports. The plugin ignores the API field and
always constructs device paths with `-lun-0`.

## Snapshot rollback requires VM to be stopped

PVE enforces this: it calls `vm_stop` (5-second graceful timeout) before invoking the
rollback hook, then aborts with `"unable to rollback vm: vm is running"` if QEMU is
still alive. Rolling back a running VM is not supported.

If a rollback is interrupted and the VM ends up with a `lock: rollback` config entry,
unlock it with:
```bash
qm unlock <vmid>
# or: Datacenter → VM → More → Unlock
```

## Rollback time varies

QuantaStor's server-side session tracker does not release as soon as the initiator
logs out. Its session manager refreshes on a cycle with a hardcoded 180-second
floor, so a session can remain visible to the appliance for roughly that long
after the guest stops. The plugin polls `sessionEnum` and waits up to 200 seconds
before calling the rollback API, so that the wait outlasts that cycle. On
Fibre Channel the plugin cannot see these sessions and does not wait (see
[Fibre Channel validation](#fibre-channel-validation)).

This means a rollback issued immediately after stopping a guest can legitimately
take a couple of minutes to complete. That is normal behaviour, not a hang. If a
rollback instead *fails* with an active-session error, contact OSNEXUS support to
investigate the appliance's session configuration.

## "Older storage API" warning on newer PVE releases

The plugin reports each node's own storage API version (`APIVER`), up to the
highest version it has been reviewed and tested against (currently 16), so it
loads silently on PVE 9.1 and 9.2. On a PVE release whose `APIVER` is higher
than that, it still loads and works, but every plugin scan prints:

```
Plugin "PVE::Storage::Custom::QuantaStor" is implementing an older storage API, an upgrade is recommended
```

The warning is informational. It appears in `/var/log/syslog` and `journalctl`
from every PVE daemon (`pvestatd`, `pvedaemon`, `pveproxy`, `pvescheduler`), and
goes away with a plugin release tested against that PVE version. Until then, you
can filter it out:

```bash
# View journal excluding the warning
journalctl | grep -v 'implementing an older storage API'
```

Or add a rsyslog filter at `/etc/rsyslog.d/99-quantastor-quiet.conf`:

```
:msg, contains, "implementing an older storage API" stop
```

## Container backups in snapshot mode can occasionally fail

On current QuantaStor releases, a container backup in snapshot mode can
occasionally fail with `iSCSI login failed ... exit code 21`. This happens when
QuantaStor is still setting up the temporary snapshot as the backup logs in to
it. The next backup run succeeds, and no data is affected. A QuantaStor fix is
in progress. VM backups, and container backups in suspend or stop mode, do not
take this path.

## A VM whose cloud-init volume is missing fails its next start

If a VM's cloud-init volume is missing when the VM starts (deleted by hand, or
removed through a second storage entry on the same pool, see
[One storage entry per pool within a cluster](#one-storage-entry-per-pool-within-a-cluster)),
the start fails with `qemu-img: Could not open ''`. Proxmox asks for the
volume's device path before creating it, and the plugin can only name the
device once the volume exists on QuantaStor. The failed
start creates the volume, so starting the VM again works. Restoring a VM from
backup creates its cloud-init volume, so a restored VM starts normally.

## Linked clones are full copies

A linked clone of a template (`qm clone` or `pct clone` without `--full`, or
"Linked Clone" in the web UI's clone dialog, its default for templates) is not
copy-on-write on this storage. QuantaStor makes the clone by copying all of
the template's written data to a new volume with a ZFS send/receive, which it
caps at 200 MB/s. The clone uses as much space as the template and shares no
blocks with it.

Proxmox runs a linked clone while holding the storage's cluster lock, and aborts
any operation that holds that lock for more than 60 seconds. A linked clone
therefore fails whenever the copy takes longer than that:

```
clone failed: ... 'storage-<storeid>'-locked command timed out - aborting
```

Even at the full 200 MB/s, a template with more than roughly 10 GB of written
data cannot be linked-cloned. On slower pools the limit is much lower: in the
lab, cloning a container template with 289 MB written took 36 seconds in one
run and more than 60 seconds in another.

QuantaStor finishes the copy after Proxmox has given up, so an aborted clone
leaves a volume that no guest uses. Find it and remove it with:

```bash
pvesm list <storeid> --vmid <new-vmid>
pvesm free <storeid>:vm-<new-vmid>-disk-<N>
```

**Use full clones instead** (`qm clone <template> <new-vmid> --full`,
`pct clone <template> <new-vmid> --full`, or "Full Clone" in the web UI).
Proxmox holds the lock only to create the empty volume and copies the data
outside it, so a full clone is not limited by the 60-second lock. It uses the
same space a linked clone does on this storage.

## Disks cannot be reassigned to another guest

Reassigning a disk ("Reassign Owner" in the web UI, `qm disk move --target-vmid`,
`pct move-volume --target-vmid`) is not supported; Proxmox refuses the operation
on this storage.

## Fibre Channel validation

The [Fibre Channel transport](fibre-channel.md) has been validated on one
Proxmox VE 9.2 node with a QLogic QLE2692 HBA, through one FC switch, against a
QuantaStor 7.0 HA pair: VM and container lifecycle (create, start, hot-add,
online resize, snapshot, rollback including after a resize, template, linked and
full clone, destroy), container backup and restore, a plugin upgrade with a
guest running, and HA pool failover and failback with guest I/O.

QuantaStor 6.9 has not been tested as the FC target, but it has been checked by
comparison with 7.0: the appliance code the plugin relies on for FC (registering
the node's port names, granting and revoking access, mapping FC LUNs and
reporting each volume's device identifier) is the same in both releases.

Not yet validated on FC hardware:

- anything that needs a second Proxmox node: migration, cloning across nodes,
  two nodes with access to one volume, Proxmox HA recovery of a guest;
- losing one path (an HBA port, cable or switch port) without a pool failover,
  and losing a whole fabric;
- Emulex HBAs on the Proxmox side.

With more than one Proxmox node on an FC storage, the plugin cannot tell whether
another node still has a volume open. A rollback is still refused by QuantaStor
in that case. Converting a guest to a template is not, so make sure the guest's
disks are not active on another node first.

## Supported PVE versions

PVE's storage subsystem hard-blocks a plugin whose `api()` lies outside the
range `[APIVER - APIAGE, APIVER]`. The plugin's `api()` returns the node's own
`APIVER`, limited to the range 13 to 16:

| PVE Version | `APIVER` | Plugin loads? | Notes |
|---|---|---|---|
| **9.2.x** | 14–16 | ✓ loads silently (reports the node's version) | Validated on PVE 9.2.24 (`APIVER` 16, libpve-storage-perl 9.1.13) against QuantaStor 6.9.1. Earlier 9.2 releases report 14 or 15 and are covered by unit tests. |
| **9.1.x** | 13 | ✓ loads silently (reports 13) | Validated against 9.1.1 in a 2-node cluster with 9.2. Full lifecycle. |
| **8.4.0** | 11 | ✗ hard-blocked: `implements an API version newer than current (13 > 11)` | Not supported by this plugin (the archived patch-based alpha, GitHub tag `v0.1-alpha`, was the last to target 8.4). |
| **Future PVE (APIVER > 16)** | >16 | ✓ loads with the ["older storage API" warning](#older-storage-api-warning-on-newer-pve-releases) | Hard-blocked only once `APIVER - APIAGE` exceeds 16. A later plugin release raises the limit after testing on that PVE. |

### Mixed-version cluster guidance

Proxmox does not officially support cluster nodes on different *major*
versions (e.g., 8.x + 9.x in the same cluster). For this plugin specifically:

- **All 9.x nodes can be mixed** — 9.1 and 9.2 in the same cluster work
  fine. Each node reports its own storage API version, so all of them load
  the plugin silently. Storage operations work transparently across both.
- **Do not include 8.x nodes** — the plugin won't load there at all, and
  any storage operation routed to an 8.x node (e.g., a VM migration target)
  will fail because the `quantastor` type isn't registered.

### Plugin upgrade guidance

Before pushing a new plugin .deb to a cluster, upgrade one node first and
verify the plugin loads (`pvesm status` does not print "Error loading"). Only
then upgrade the rest. The plugin adapts its `api()` to each node, so a mixed
9.1 / 9.2 cluster needs no further checks.

A plugin whose `api()` exceeds the cluster's lowest `APIVER` will hard-block
on those nodes. **Existing storage entries in `storage.cfg` are not removed**
when this happens, but any plugin operation on those nodes (status,
activate, free_image) errors out. Recovery is either to upgrade PVE on the
affected nodes or downgrade the plugin (see
[Upgrading and downgrading](installation.md#upgrading-and-downgrading); not
below 1.2.0 while any storage uses `volume_prefix` or `transport fc`).
