
# QuantaStor Proxmox Plugin

This repository provides a Proxmox (PVE) storage plugin for QuantaStor, enabling integration of QuantaStor-managed ZFS over ISCSI storage into your Proxmox environment.

## Features
- Integrates QuantaStor storage pools with Proxmox VE
- Simple installation and rollback
- Safe backup/restore of original Proxmox files

## Requirements
- Proxmox VE 8.x or later
- Bash shell
- Root privileges for installation

## Installation

1. **Clone this repository** (or download the plugin source):
	 ```bash
	 git clone <repo-url>
	 cd pve-quantastor-plugin
	 ```

2. **Run the installer script:**

	 The installer will:
	 - Copy plugin files to the correct Proxmox directories
	 - On first run, back up original files (except the new QuantaStor plugin file)
	 - Optionally print checksums before/after install

	 ```bash
	 sudo ./install-qs-pve.sh
	 ```

	 - To verify file integrity before/after install:
		 ```bash
		 sudo ./install-qs-pve.sh --checksum
		 ```

	 - To restore original files (rollback):
		 ```bash
		 sudo ./install-qs-pve.sh --rollback
		 ```

     - Reload services to use new source scripts:
         ```bash
		 sudo service pve-cluster restart && service pvedaemon restart && service pvestatd restart && service pveproxy restart
		 ```

## How it works
- On first run, the script creates backups of all target files (except the new plugin file) in `/var/tmp/pve-quantastor-backup`.
- The `--rollback` option restores these files, undoing any changes made by the plugin.
- The plugin file `Storage/LunCmd/QuantaStorPlugin.pm` is only added, never backed up or rolled back.

## File Locations
- Perl plugin files: `/usr/share/perl5/PVE/Storage/`
- JavaScript files: `/usr/share/pve-manager/js/`
- API doc files: `/usr/share/pve-docs/api-viewer/`

## Updating the Plugin
To update the plugin, simply re-run the installer script with the new version of the source files.

## Uninstallation
To remove the plugin and restore the original Proxmox files, run:
```bash
sudo ./install-qs-pve.sh --rollback
```

## Troubleshooting
- Ensure you have root privileges (`sudo`) when running the script.
- If you encounter issues, check the backup directory at `/var/tmp/pve-quantastor-backup`.

## License
See LICENSE file for details.
