# Architecture

How the plugin sits between Proxmox VE and the QuantaStor REST API.

## How it works

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
        /dev/disk/by-path/...    ← stable block device (multipath: the dm map,
                                   /dev/disk/by-id/dm-uuid-mpath-<wwid>)
                │
                ▼
        QEMU raw VM disk (images) / ext4 container rootfs (rootdir)
```

The same diagram as an image: [`architecture.svg`](architecture.svg).

## QuantaStor API

All communication uses QuantaStor's REST API over HTTPS on port 8153 with HTTP Basic Auth.
Requests are plain GET calls with URL-encoded query parameters; responses are JSON.

```
GET https://<host>:8153/qstorapi/<method>?param1=value1&param2=value2
Authorization: Basic <base64(user:pass)>
Accept: application/json
```

## Volume naming convention

PVE volume names follow the standard Proxmox convention:

| Type | Name pattern | Example |
|---|---|---|
| VM disk | `vm-<vmid>-disk-<N>` | `vm-100-disk-0` |
| Template | `base-<vmid>-disk-<N>` | `base-100-disk-0` |
| Template snapshot | `template-base-<vmid>-disk-<N>` | `template-base-100-disk-0` |
| Snapshot | `<volname>_<snapname>` | `vm-100-disk-0_snap1` |
