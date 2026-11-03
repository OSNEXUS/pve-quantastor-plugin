# Fibre Channel

The plugin can attach QuantaStor volumes over Fibre Channel instead of iSCSI.
Volumes are still created, snapshotted, cloned and resized through the
QuantaStor REST API; only the step that connects a volume to the Proxmox node
changes. Choose the transport when you add the storage. It cannot be changed
afterwards, and a pool should not get a second entry with the other transport
(see [One storage entry per pool within a cluster](limitations.md#one-storage-entry-per-pool-within-a-cluster)).

## Requirements

- **QuantaStor:** FC target ports enabled on the appliance (QuantaStor's FC
  target driver supports QLogic HBAs). For an HA storage pool, both controllers
  need target ports, because the pool's standby controller also presents each
  LUN.
- **Every Proxmox node** that uses the storage needs an FC HBA. A node without
  one fails to activate the storage with `FCManager: no Fibre Channel HBA found`.
- **Zoning:** zone every HBA port of every Proxmox node to every QuantaStor
  target port that serves the pool, on both controllers of an HA pair. The plugin
  cannot see or change zoning.
- **multipath-tools:** installed with the package. FC volumes always use a
  device-mapper multipath map, whatever the storage's `multipath` setting.

Nothing needs to be created on QuantaStor beforehand. When the storage is first
activated on a node, the plugin registers the node as a QuantaStor host with all
of its HBA port names (WWPNs), so one access grant covers every path. If a host
that already holds one of the node's WWPNs exists, the plugin uses it.

## Adding the storage

Use the same options as for iSCSI, plus `--transport fc`:

```bash
pvesm add quantastor qs-fc \
  --api_host <failover group VIF or appliance IP> \
  --username admin \
  --password '<password>' \
  --pool_id <pool-name-or-uuid> \
  --content images,rootdir \
  --transport fc
```

In the web UI, choose **Fibre Channel** in the *Transport* field under the
advanced options of the Add dialog. `--portal` and `--multipath` are not used
with FC. For an HA storage pool, point `--api_host` at the failover group's
virtual interface (see [QuantaStor HA storage pools](configuration.md#quantastor-ha-storage-pools)).

## How a volume is attached

When a guest starts, the plugin:

1. grants this node's QuantaStor host access to the volume;
2. rescans the node's HBAs;
3. waits up to 30 seconds until the LUN has a path through every online target
   port the HBAs can see (on an HA pair the standby controller presents the LUN
   a moment after the owner, and the plugin rescans again while it waits);
4. builds the multipath map and gives the guest
   `/dev/disk/by-id/dm-uuid-mpath-<wwid>`.

The LUN is found by its WWID, which the plugin derives from the volume's
QuantaStor device identifier, so LUN numbers do not matter. Stopping the guest
flushes the map, removes the SCSI devices and revokes access. An online resize
rescans every path and grows the map.

On an HA pair the owner controller's paths are active and the standby
controller's paths are on standby. multipath-tools detects this (ALUA) and
groups the paths itself; the device section the package installs needs no
change for FC. A healthy map looks like this:

```
# multipath -ll
36200000093c105f26eec36319c9307ff dm-6 OSNEXUS,QUANTASTOR
size=1.0G features='1 queue_if_no_path' hwhandler='1 alua' wp=rw
|-+- policy='service-time 0' prio=50 status=active
| |- 1:0:2:64 sdg 8:96  active ready running
| `- 1:0:3:64 sdh 8:112 active ready running
`-+- policy='service-time 0' prio=1 status=enabled
  |- 1:0:0:64 sdi 8:128 active ghost running
  `- 1:0:1:64 sdj 8:144 active ghost running
```

`ghost` marks the standby paths. During a QuantaStor HA pool failover the
groups swap and guest I/O pauses; about 15 seconds was measured in each
direction, with guests continuing afterwards.

## Troubleshooting

### `FC multipath map for '<volume>' (<wwid>) did not appear after 30s`

The LUN never became visible on this node. Check the zoning between this
node's HBAs and the appliance's target ports, and that the target ports are
enabled on the appliance. `lsscsi` should list `OSNEXUS QUANTASTOR` devices
once the volume is granted to this node.

### `FCManager: LUN <wwid> has N of M paths after 30s` (warning in the journal)

The guest started, but some target ports did not present the LUN. Usually one
controller of an HA pair is not zoned to this node, or its target ports are
down. The guest runs on the paths it has; a failover to the controller without
paths would stop its I/O.

### `this node's FC port <wwpn> is not registered on QuantaStor`

The storage has not been activated on this node since its HBA ports changed.
Run `pvesm status` on the node, which registers it.

For what has and has not been validated on FC hardware, see
[Known limitations](limitations.md#fibre-channel-validation).
