# Multipath (DM-MPIO)

When QuantaStor serves iSCSI on more than one network port, the storage can use
every portal at once and keep guest I/O running when one path fails. Turn it on
with `multipath 1`; it is off by default.

With multipath on, the plugin logs each volume in on every portal QuantaStor
advertises for it, builds a device-mapper multipath map for that one LUN, and
gives guests the map (`/dev/disk/by-id/dm-uuid-mpath-<wwid>`) instead of a
single-path device. Deactivating, deleting, rolling back, templating or cloning
a volume tears down or brings up every path, and an online resize rescans every
path and grows the map.

**Nothing to set up on the nodes.** The package depends on `multipath-tools` and
installs a device section for QuantaStor LUNs as
`/etc/multipath/conf.d/quantastor.conf`:

   ```
   devices {
       device {
           vendor               "OSNEXUS"
           product              "QUANTASTOR"
           path_grouping_policy "multibus"
           path_checker         "tur"
           failback             "immediate"
           no_path_retry        24
       }
   }
   ```

   Keep `no_path_retry`: multipathd shortens each iSCSI session's
   recovery timeout to 5 seconds so that a dead path is dropped quickly; without
   queueing, a moment when *every* path is down (a QuantaStor HA pool failover,
   a switch reboot) would fail guest I/O instead of pausing it. With this setting
   the map holds I/O for up to about two minutes (24 x the 5 s polling interval)
   until a path returns.

   Nothing else needs configuring. Debian's defaults (`find_multipaths strict`,
   `user_friendly_names no`) mean multipathd only claims the LUNs the plugin
   registers for `multipath 1` storages, never local disks or other storage, and
   the plugin addresses maps by WWID, so `user_friendly_names` or aliases do not
   affect it. Storages without `multipath 1` are not touched.

   The file is a conffile: local edits are kept across upgrades. If you added the
   same section to `/etc/multipath.conf` for 1.1.0, it is now redundant and can be
   removed (the `conf.d` entry takes precedence).

**Enable it** on a new storage with `--multipath 1` on `pvesm add`, the
*Multipath* checkbox under the Add dialog's advanced options, or on an existing
storage with `pvesm set <storeid> --multipath 1`. Change the setting only while
no guest on that storage is running: a volume that is already logged in keeps the
sessions it was activated with until it is deactivated.

**Verify:** start a guest and check that it has one map with a path per portal,
and that QEMU opened the map:

```bash
multipath -ll                       # OSNEXUS,QUANTASTOR map, one "active ready" line per portal
qm showcmd <vmid> | grep -o 'dm-uuid-mpath-[0-9a-f]*'
```

Losing one path pauses I/O for about 15 seconds (the initiator's NOP-out timeout
plus the 5 s recovery timeout) while the path is failed, then I/O continues on
the remaining paths; the path is reinstated automatically when it comes back.

**Give each path its own network.** Put the iSCSI ports on separate subnets,
ideally separate switches or VLANs, so one failure takes out one path. If a
node's iSCSI NICs share one layer-2 segment, Linux can answer ARP for one NIC's
address on the other ("ARP flux"), and losing one NIC can then interrupt both
paths: the queueing keeps guests running, but I/O pauses until the path
recovers. On such nodes add this to a file in `/etc/sysctl.d/` and run
`sysctl --system`:

```
net.ipv4.conf.all.arp_ignore = 1
net.ipv4.conf.all.arp_announce = 2
```

Measured with two NICs on one segment: losing one NIC paused I/O for 43 s with
the defaults (both paths dropped) and 15 s with these settings (one path kept).

**Advertised portals the node cannot reach are skipped.** QuantaStor advertises
every port that has iSCSI enabled, including ports on networks the Proxmox nodes
are not on. The plugin checks each portal with a 3-second TCP connection first
and skips the ones that do not answer, logging a "not reachable on TCP,
skipped" warning, instead of stalling activation on the initiator's login
retries (about two minutes per unreachable portal). To keep the warning out of
the log, enable iSCSI only on the QuantaStor ports the Proxmox nodes use:

```bash
qs np-modify --port=<port> --iscsi-enable=false    # on the appliance
```

A path that is down when a volume is activated is skipped the same way; it
joins the map the next time the volume is activated (guest start or
migration).
