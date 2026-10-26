# Troubleshooting

Common errors and how to resolve them.

## `Authentication check failed ... [err=26]` from QuantaStor

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

## `Failed to delete storage volume ... [err=493]` on destroy or snapshot delete

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

## Container fails to start: `run_buffer: ... Script exited with status 255` / `Failed to run lxc.hook.pre-start`

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

## `QuantaStor: no password configured for storage 'X' on node 'Y'`

Surfaced by 0.2.0 and later in exactly the situation
that used to produce err=26 above. The message names the storeid, the node,
the expected file path, and the `pvesm set` remediation command — follow it
verbatim.

## `Plugin "..." is implementing an older storage API, an upgrade is recommended`

Cosmetic warning that fires from every PVE daemon's plugin scan on PVE 9.2+
because the plugin declares `api()=13` for 9.1 compatibility. See
[Known limitations](limitations.md#older-storage-api-warning-on-pve-92).

## `Error loading storage plugin: implements an API version newer than current (N > M)`

Hard-block — the plugin's declared API version is higher than your PVE
version supports, so PVE refuses to load it. The storage type `quantastor`
will not appear in `pvesm` or the UI. Resolution:

- **For 9.1.x customers**: ensure you are on plugin 0.2.0 or
  later (where `api()` was reverted from 14 back to 13).
- **For 8.4.0 customers**: not supported by this plugin (the archived
  patch-based alpha, GitHub tag `v0.1-alpha`, was the last to target 8.4).

## Storage shows `active` on some nodes, `inactive` on others

If the inactive node prints the "no password configured" error, follow that
message. If it prints `[err=26]`, manually backfill the `.pw` file as in
**err=26** above. If it prints a network/SSL error, the inactive node
cannot reach `api_host:8153` — check firewall/routing, not the plugin.

## Storage only works on one cluster at a time

Symptom: two Proxmox clusters, or two nodes, use the same QuantaStor appliance.
Only one of them can reach the storage at a time, and shutting one down makes
the other work. Guests may also see I/O errors or stalls whenever the other
side starts a VM or stops one.

Cause: the nodes share an iSCSI initiator name. That usually happens when they
were cloned from the same template. The plugin registers each node with
QuantaStor by its initiator name, so QuantaStor sees both nodes as one host.
Their iSCSI sessions to the same volume can knock each other off, and when
one side detaches a volume, the access it removes is access the other side is
still using.

Check every node of every cluster:

```bash
cat /etc/iscsi/initiatorname.iscsi
```

On QuantaStor, `qs host-list` shows one host per initiator name. If a node is
missing from that list, it is sharing another node's initiator name.

Fix: give every node except one a new, unique name. Do it one node at a time,
on a node that has no running guests using this storage (migrate them off
first), because restarting `iscsid` drops the node's iSCSI sessions:

```bash
echo "InitiatorName=$(iscsi-iname)" > /etc/iscsi/initiatorname.iscsi
systemctl restart iscsid
pvesm status    # re-registers the node with QuantaStor under its new name
```

Run `qs host-list` again on QuantaStor and confirm each node now has its own
host entry.

## A `qm move-disk` or VM migration to another cluster node fails

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
