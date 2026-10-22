# Container (LXC) support

LXC containers can place their root filesystem (and additional mount points) on
QuantaStor storage. Enable the `Container` content type on the storage — tick
it in the web UI dialog, or:

```bash
pvesm set <storeid> --content images,rootdir
```

## How it works

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
| Backup (`vzdump`) | Snapshot, suspend and stop modes; snapshot mode logs in to a temporary QuantaStor snapshot and mounts it read-only |

## Container limitations

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
- **QuantaStor version**: QuantaStor 6.9 is the recommended release. It
  includes the server-side fixes for the template-conversion volume wedge and
  the fresh-snapshot delete window. Builds without them wedge volumes on
  template conversion (stale NVMeoF export after rename) and refuse
  fresh-snapshot deletes for several minutes (see Troubleshooting, `err=493`).
