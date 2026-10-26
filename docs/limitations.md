# Known limitations and supported versions

## Cluster compatibility

Live migration, offline migration, resize on running VMs, snapshot/rollback,
template/clone, and VM destroy have all been validated on a two-node PVE 9.2
cluster sharing a common QuantaStor portal.

One minor quirk: `qm template` (`create_base`) re-logins to the renamed
`base-*` volume after the operation, leaving an active iSCSI session on the
coordinator node. PVE cleans this up automatically before any subsequent volume
operation. It has no practical impact on cluster operations.

## One storage pool per Proxmox cluster

A QuantaStor storage pool must be used by only one Proxmox cluster. Separate
clusters can share an appliance, but each one needs its own pool (see
[Multiple Proxmox clusters on one appliance](configuration.md#multiple-proxmox-clusters-on-one-appliance)).

The plugin gives a volume the same name on QuantaStor as it has in Proxmox, for
example `vm-100-disk-0`. When it lists a pool's volumes, it reports every volume
in that pool as belonging to the cluster that asked. VM IDs are only unique within
one cluster. If two clusters share a pool, both can have a VM 100, and each
cluster sees the other's `vm-100-*` disks as its own:

- `qm disk rescan` attaches the other cluster's disks to the local VM with the
  same ID, as unused disks.
- Destroying a VM and removing its unreferenced disks deletes the other cluster's
  disks for that VM ID. **This loses data.**

Sharing one pool between clusters is not supported.

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
before calling the rollback API, so that the wait outlasts that cycle.

This means a rollback issued immediately after stopping a guest can legitimately
take a couple of minutes to complete. That is normal behaviour, not a hang. If a
rollback instead *fails* with an active-session error, contact OSNEXUS support to
investigate the appliance's session configuration.

## "Older storage API" warning on PVE 9.2+

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

## Container backups in snapshot mode can occasionally fail

On current QuantaStor releases, a container backup in snapshot mode can
occasionally fail with `iSCSI login failed ... exit code 21`. This happens when
QuantaStor is still setting up the temporary snapshot as the backup logs in to
it. The next backup run succeeds, and no data is affected. A QuantaStor fix is
in progress. VM backups, and container backups in suspend or stop mode, do not
take this path.

## First start of a restored VM with a cloud-init drive fails

A VM restored from backup has no cloud-init volume yet, and its first start
fails with `qemu-img: Could not open ''`. Proxmox asks for the volume's device
path before creating it, and the plugin can only name the device once QuantaStor
has assigned the volume its iSCSI target. The failed start creates the volume,
so starting the VM again works.

## Disks cannot be reassigned to another guest

Reassigning a disk ("Reassign Owner" in the web UI, `qm disk move --target-vmid`,
`pct move-volume --target-vmid`) is not supported; Proxmox refuses the operation
on this storage.

## Supported PVE versions

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
