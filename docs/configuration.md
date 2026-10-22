# Configuration

Adding a QuantaStor storage to Proxmox VE and the options that control it.

## How the plugin stores credentials

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

## Authenticating with an API token instead of a password

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

## Web UI

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

## CLI

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

## QuantaStor HA storage pools

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
[QuantaStor HA pool failover pauses guest I/O](limitations.md#quantastor-ha-pool-failover-pauses-guest-io)
under Known Limitations for the measured behaviour, and for the one initiator
setting you should not change.

## Multipath

To use every iSCSI portal QuantaStor advertises, set `multipath 1` on the storage. Setup, path behavior and network layout are in [Multipath (DM-MPIO)](multipath.md).

## Verifying your setup

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
create time (see [Troubleshooting](troubleshooting.md)).
