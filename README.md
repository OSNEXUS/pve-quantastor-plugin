# QuantaStor PVE Plugin

A [Proxmox VE](https://www.proxmox.com/en/proxmox-virtual-environment) storage plugin that integrates
[QuantaStor](https://www.osnexus.com/products/software-defined-storage) as a first-class iSCSI block
storage backend for virtual machines and containers.

---

## Status

| Component | State |
|---|---|
| `QuantaStor/APIClient.pm` | Complete — clean REST client, 50 unit tests |
| `QuantaStor/ISCSIManager.pm` | Complete — clean iSCSI lifecycle, 61 unit tests |
| `Custom/QuantaStor.pm` (first-class type) | Complete — all PVE hooks implemented, 80 unit tests |
| Debian packaging | Complete — `pve-storage-quantastor_1.1.2-1_all.deb` |

---

## Quick start

Install the package on **every node** in the cluster. Use `apt` so the dependencies
(`open-iscsi`, `multipath-tools`) are installed too:

```bash
apt install ./pve-storage-quantastor_1.1.2-1_all.deb
```

Then add the storage from any node:

```bash
pvesm add quantastor qs-storage-1 \
  --api_host 10.0.0.10 \
  --username admin \
  --password '<password>' \
  --pool_id <pool-name-or-uuid> \
  --content images,rootdir
```

`--pool_id` is the QuantaStor storage pool to create volumes in, by name or UUID.
The web UI works too: refresh the browser after installing, then Datacenter → Storage →
Add → **QuantaStor**.

---

## Documentation

| Topic | Covers |
|---|---|
| [Installation](docs/installation.md) | Package install, upgrading and downgrading, upgrading from the patch-based alpha, manual install, building the package |
| [Configuration](docs/configuration.md) | Credentials, API tokens, the web UI and CLI options, QuantaStor HA storage pools, verifying the setup |
| [Multipath (DM-MPIO)](docs/multipath.md) | Using every iSCSI portal the appliance advertises, path loss behavior, network layout |
| [Container (LXC) support](docs/containers.md) | How container volumes work and their limitations |
| [Troubleshooting](docs/troubleshooting.md) | Common errors and how to resolve them |
| [Known limitations and supported versions](docs/limitations.md) | Behavior to know about, supported Proxmox VE versions, mixed-version clusters |
| [Architecture](docs/architecture.md) | How the plugin sits between Proxmox VE and the QuantaStor REST API |
| [Source layout and module reference](src/README.md) | What each file does, the Perl module interfaces, the PVE hooks |
| [Running the tests](t/README.md) | Unit and integration tests |
| [Contributing](CONTRIBUTING.md) | Development workflow and roadmap |

The user guide is also published on the QuantaStor wiki:
[Proxmox Storage Plugin](https://wiki.osnexus.com/index.php?title=Proxmox_Storage_Plugin).

---

## Troubleshooting

See [docs/troubleshooting.md](docs/troubleshooting.md).

## Multipath (DM-MPIO)

See [docs/multipath.md](docs/multipath.md).

## Upgrading from the patch-based alpha

See [Upgrading from the patch-based alpha](docs/installation.md#upgrading-from-the-patch-based-alpha)
in the installation guide.

---

## License

See `LICENSE` in the repository root for license information.
