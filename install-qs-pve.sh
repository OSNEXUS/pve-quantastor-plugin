#!/bin/bash

# Parse optional arguments

DO_CHECKSUM=0
DO_ROLLBACK=0
# backup dir
BACKUP_DIR="/var/tmp/pve-quantastor-backup"

usage() {
    echo "QuantaStor Proxmox Plugin Installer Tool"
    echo ""
    echo "This script copies plugin files from the build directory to the appropriate Proxmox directories."
    echo "On the first run, it creates a backup of the original files in $BACKUP_DIR."
    echo "You can restore the original files at any time using the --rollback option."
    echo "This script must be run from the directory containing the 'quantastor-pve-plugin' folder in the root"
    echo "of the plugin source tree."
    echo ""
    echo "Usage: $0 [--checksum] [--rollback] [--help]"
    echo ""
    echo "  --checksum   Print sha256 hashes of source and target files before and after copy"
    echo "  --rollback   Restore files from backup (undo changes made by this script)"
    echo "  --help       Show this help message"
    echo ""
    echo "Backup/rollback system:"
    echo "  - On first run, all target files (except QuantaStorPlugin.pm) are backed up to $BACKUP_DIR."
    echo "  - The --rollback option restores these files from backup, undoing any changes."
    exit 0
}

for arg in "$@"; do
    case $arg in
        --checksum)
            DO_CHECKSUM=1
            ;;
        --rollback)
            DO_ROLLBACK=1
            ;;
        --help|-h)
            usage
            ;;
    esac
done


# Use the full current working directory as the base source directory
BASE_SOURCE_DIR="$(pwd)/quantastor-pve-plugin"
SOURCE_DIR_PERL5="$BASE_SOURCE_DIR/perl5/PVE"
SOURCE_DIR_JS="$BASE_SOURCE_DIR/js/pve-manager"
SOURCE_DIR_APIDOC="$BASE_SOURCE_DIR/js/pve-docs/api-viewer"

# Target directory
TARGET_DIR_PERL5="/usr/share/perl5/PVE"
TARGET_DIR_JS="/usr/share/pve-manager/js"
TARGET_DIR_APIDOC="/usr/share/pve-docs/api-viewer"

# create an array of the source files and an array of the target files
FILE_NAMES_PERL5=(
    "Storage/ZFSPlugin.pm"
    "Storage/ZFSPoolPlugin.pm"
    "Storage/LunCmd/QuantaStorPlugin.pm"
    "Storage.pm"
)

FILE_NAMES_JS=(
    "pvemanagerlib.js"
)

FILE_NAME_APIDOC=(
    "apidoc.js"
)

# Backup function
backup_files() {
    local file_names=("${!1}")
    local dest_dir="$2"
    for file in "${file_names[@]}"; do
        # Skip backup for QuantaStorPlugin.pm
        if [[ "$file" == "Storage/LunCmd/QuantaStorPlugin.pm" ]]; then
            continue
        fi
        local dest="$dest_dir/$file"
        if [[ -f "$dest" ]]; then
            local backup_path="$BACKUP_DIR/$file.backup"
            mkdir -p "$(dirname "$backup_path")"
            cp "$dest" "$backup_path"
            echo "Backed up: $dest to $backup_path"
        fi
    done
}

# Rollback function
rollback_files() {
    local file_names=("${!1}")
    local dest_dir="$2"
    for file in "${file_names[@]}"; do
        # Skip rollback for QuantaStorPlugin.pm
        if [[ "$file" == "Storage/LunCmd/QuantaStorPlugin.pm" ]]; then
            continue
        fi
        local backup_path="$BACKUP_DIR/$file.backup"
        local dest="$dest_dir/$file"
        if [[ -f "$backup_path" ]]; then
            mkdir -p "$(dirname "$dest")"
            cp "$backup_path" "$dest"
            echo "Rolled back: $backup_path to $dest"
        else
            echo "Backup not found for: $backup_path"
        fi
    done
}

copy_files() {
    local file_names=("${!1}")
    local src_dir="$2"
    local dest_dir="$3"
    for file in "${file_names[@]}"; do
        local src="$src_dir/$file"
        local dest="$dest_dir/$file"
        if [[ -f "$src" ]]; then
            mkdir -p "$(dirname "$dest")"
            cp "$src" "$dest"
            echo "Copied: $src to $dest"
        else
            echo "Source file not found: $src"
        fi
    done
}

print_hashes() {
    local file_names=("${!1}")
    local dir="$2"
    for file in "${file_names[@]}"; do
        local path="$dir/$file"
        if [[ -f "$path" ]]; then
            sha256sum "$path"
        else
            echo "Missing: $path"
        fi
    done
}

# main
# Handle rollback before any other operation
if [[ $DO_ROLLBACK -eq 1 ]]; then
    echo "Rolling back files from $BACKUP_DIR..."
    rollback_files FILE_NAMES_PERL5[@] "$TARGET_DIR_PERL5"
    rollback_files FILE_NAMES_JS[@] "$TARGET_DIR_JS"
    rollback_files FILE_NAME_APIDOC[@] "$TARGET_DIR_APIDOC"
    echo "Rollback complete."
    exit 0
fi


# Only perform backup if BACKUP_DIR does not exist and no backup files exist
should_backup=0
if [[ ! -d "$BACKUP_DIR" ]]; then
    should_backup=1
else
    # Check if any backup file exists for any file
    for file in "${FILE_NAMES_PERL5[@]}"; do
        # Skip backup check for QuantaStorPlugin.pm
        if [[ "$file" == "Storage/LunCmd/QuantaStorPlugin.pm" ]]; then
            continue
        fi
        if [[ ! -f "$BACKUP_DIR/$file.backup" ]]; then
            should_backup=1
            break
        fi
    done
    if [[ $should_backup -eq 0 ]]; then
        for file in "${FILE_NAMES_JS[@]}"; do
            if [[ ! -f "$BACKUP_DIR/$file.backup" ]]; then
                should_backup=1
                break
            fi
        done
    fi
    if [[ $should_backup -eq 0 ]]; then
        for file in "${FILE_NAME_APIDOC[@]}"; do
            if [[ ! -f "$BACKUP_DIR/$file.backup" ]]; then
                should_backup=1
                break
            fi
        done
    fi
fi

if [[ $should_backup -eq 1 ]]; then
    echo "First run detected: backing up target files to $BACKUP_DIR..."
    backup_files FILE_NAMES_PERL5[@] "$TARGET_DIR_PERL5"
    backup_files FILE_NAMES_JS[@] "$TARGET_DIR_JS"
    backup_files FILE_NAME_APIDOC[@] "$TARGET_DIR_APIDOC"
    echo "Backup complete."
    exit 0
fi

if [[ $DO_CHECKSUM -eq 1 ]]; then
    # perl5 files
    echo "Hashes for Source and Target files pre install [perl5]:"
    print_hashes FILE_NAMES_PERL5[@] "$SOURCE_DIR_PERL5"
    echo "---------------------------------"
    print_hashes FILE_NAMES_PERL5[@] "$TARGET_DIR_PERL5"
    echo "---------------------------------"

    # js files
    echo "Hashes for Source and Target files pre install [js]:"
    print_hashes FILE_NAMES_JS[@] "$SOURCE_DIR_JS"
    echo "---------------------------------"
    print_hashes FILE_NAMES_JS[@] "$TARGET_DIR_JS"
    echo "---------------------------------"

    # apidoc files
    echo "Hashes for Source and Target files pre install [apidoc]:"
    print_hashes FILE_NAME_APIDOC[@] "$SOURCE_DIR_APIDOC"
    echo "---------------------------------"
    print_hashes FILE_NAME_APIDOC[@] "$TARGET_DIR_APIDOC"
    echo "---------------------------------"

fi

# copy files from Source to Target - perl5
copy_files FILE_NAMES_PERL5[@] "$SOURCE_DIR_PERL5" "$TARGET_DIR_PERL5"

# copy files from Source to Target - js
copy_files FILE_NAMES_JS[@] "$SOURCE_DIR_JS" "$TARGET_DIR_JS"

# copy files from Source to Target - apidoc
copy_files FILE_NAME_APIDOC[@] "$SOURCE_DIR_APIDOC" "$TARGET_DIR_APIDOC"

if [[ $DO_CHECKSUM -eq 1 ]]; then
    # final hashes should match if the copy was successful
    echo "Hashes for Source and Target files post install [perl5]:"
    print_hashes FILE_NAMES_PERL5[@] "$SOURCE_DIR_PERL5"
    echo "---------------------------------"
    print_hashes FILE_NAMES_PERL5[@] "$TARGET_DIR_PERL5"
    echo "---------------------------------"

    echo "Hashes for Source and Target files post install [js]:"
    print_hashes FILE_NAMES_JS[@] "$SOURCE_DIR_JS"
    echo "---------------------------------"
    print_hashes FILE_NAMES_JS[@] "$TARGET_DIR_JS"
    echo "---------------------------------"

    # apidoc files
    echo "Hashes for Source and Target files post install [apidoc]:"
    print_hashes FILE_NAME_APIDOC[@] "$SOURCE_DIR_APIDOC"
    echo "---------------------------------"
    print_hashes FILE_NAME_APIDOC[@] "$TARGET_DIR_APIDOC"
    echo "---------------------------------"
fi
