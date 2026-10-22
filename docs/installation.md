# Installation

Installing, upgrading and building the plugin package.

## Package install (recommended)

Download the latest `.deb` from the releases page and install it on each PVE node
with `apt`, which also installs the packages it depends on (`open-iscsi`,
`multipath-tools`):

```bash
apt install ./pve-storage-quantastor_1.1.2-1_all.deb
# PVE services are restarted automatically by postinst
```

`dpkg -i` does not install dependencies: on a node that lacks one, it stops with
"dependency problems - leaving unconfigured". Run `apt -f install` to finish.

The `quantastor` storage type will appear in the PVE UI immediately after the browser
is refreshed. The package includes two dpkg file triggers: one on `index.html.tpl`
(re-injects the UI script tag when `pve-manager` is upgraded) and one on
`PVE/API2/Storage/Scan.pm` (re-injects the pool-scan API route when `pve-storage` is
upgraded). No manual reinstall is required after either upgrade.

## Upgrading and downgrading

From 1.0.0 or later, install the current package directly on every node — there
are no intermediate versions to step through, no migration steps, and existing
storage entries keep working unchanged. Guests on the storage can keep running
during the upgrade. Use `apt install ./<package>.deb` as above: from 1.1.1 the
package depends on `multipath-tools`, which `apt` installs on nodes that lack it.

**Downgrading needs one step first if multipath is on.** Older releases do not
know the `multipath` option. Before installing a 1.0.x package over 1.1.0 or
later, turn it off on every storage that uses it, with that storage's guests
stopped:

```bash
pvesm set <storeid> --delete multipath
```

## Upgrading from the patch-based alpha

The archived v0.1 alpha (GitHub tag `v0.1-alpha`) worked by patching Proxmox's own
storage modules and registered its storage as a `zfs` entry with
`iscsiprovider quantastor`. Version 1.0.0 replaced that integration entirely and
1.1.1 is the same first-class plugin, so on any node running 1.0.0 or later:

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
See the [Roadmap](../CONTRIBUTING.md#roadmap) for the migration tooling that would automate this.

## Manual install (no package)

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

## Building the package from source

```bash
# Requires debhelper >= 13
apt install debhelper

bash build-deb.sh
# Produces ../pve-storage-quantastor_1.1.2-1_all.deb
```
