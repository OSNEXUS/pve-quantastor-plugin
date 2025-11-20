#!/bin/bash

# Parse optional arguments

DO_CHECKSUM=0
DO_ROLLBACK=0
DO_REVERSE_PATCH=0
# default behavior is patch install
FULL_COPY=0

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
    echo "  --fullcopy     Perform a full copy install (overwrite all files)"
    echo "  --checksum     Print sha256 hashes of source and target files before and after copy"
    echo "  --rollback     Restore files from backup (undo changes made by this script)"
    echo "  --reversepatch Restore original files by reversing applied patches"
    echo "  --help         Show this help message"
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
        --reversepatch)
            DO_REVERSE_PATCH=1
            ;;
        --fullcopy)
            FULL_COPY=1
            ;;
        --help|-h)
            usage
            ;;
    esac
done


# Use the full current working directory as the base source directory
BASE_SOURCE_DIR="$(pwd)/src"
PATCHES_SOURCE_DIR="$(pwd)/patches"
SOURCE_DIR_PERL5="$BASE_SOURCE_DIR/PVE"
SOURCE_DIR_JS="$BASE_SOURCE_DIR/pve-manager/js"
SOURCE_DIR_APIDOC="$BASE_SOURCE_DIR/pve-docs/api-viewer"

SOURCE_DIR_PATCHES_PERL5="$PATCHES_SOURCE_DIR/PVE"
SOURCE_DIR_PATCHES_JS="$PATCHES_SOURCE_DIR/pve-manager/js"
SOURCE_DIR_PATCHES_APIDOC="$PATCHES_SOURCE_DIR/pve-docs/api-viewer"

# Target directory
TARGET_DIR_PERL5="/usr/share/perl5/PVE"
TARGET_DIR_JS="/usr/share/pve-manager/js"
TARGET_DIR_APIDOC="/usr/share/pve-docs/api-viewer"

# create an array of the source files and an array of the target files
FILE_QSTOR_PLUGIN=(
    "Storage/LunCmd/QuantaStorPlugin"
)

FILE_NAMES_PERL5=(
    "Storage/ZFSPlugin"
    "Storage/LunCmd/QuantaStorPlugin"
)

FILE_PATCHES_PERL5=(
    "Storage/ZFSPlugin"
)

FILE_NAMES_JS=(
    "pvemanagerlib"
)

FILE_NAME_APIDOC=(
    "apidoc"
)

# Detect the current pve version
# pveversion
# pve-manager/9.1.1/42db4a6cf33dac83 (running kernel: 6.17.2-1-pve)
# Get the raw version string
PVE_VERSION=$(pveversion | awk -F'/' '{print $2}' | cut -d'-' -f1)

echo "PVE version detected: $PVE_VERSION"

# Backup function
backup_files() {
    local file_names=("${!1}")
    local dest_dir="$2"
    local suffix="$3"
    for file in "${file_names[@]}"; do
        # Skip backup for QuantaStorPlugin.pm
        if [[ "$file" == "Storage/LunCmd/QuantaStorPlugin.pm" ]]; then
            continue
        fi
        local dest="$dest_dir/$file$suffix"
        if [[ -f "$dest" ]]; then
            local backup_path="$BACKUP_DIR/$file$suffix.backup"
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
    local suffix="$3"
    for file in "${file_names[@]}"; do
        # Skip rollback for QuantaStorPlugin.pm
        if [[ "$file" == "Storage/LunCmd/QuantaStorPlugin.pm" ]]; then
            continue
        fi
        local backup_path="$BACKUP_DIR/$file$suffix.backup"
        local dest="$dest_dir/$file$suffix"
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
    local suffix="$4"
    for file in "${file_names[@]}"; do
        local src="$src_dir/$file"
        local dest="$dest_dir/$file.$PVE_VERSION$suffix"
        if [[ -f "$src" ]]; then
            mkdir -p "$(dirname "$dest")"
            cp "$src" "$dest"
            echo "Copied: $src to $dest"
        else
            echo "Source file not found: $src"
        fi
    done
}

apply_patches() {
    local file_names=("${!1}")
    local src_dir="$2"
    local dest_dir="$3"
    local suffix="$4"
    local src="$src_dir/$file.$PVE_VERSION$suffix"
    local dest="$dest_dir/$file"
    if [[ -f "$src" && -f "$dest" ]]; then
        patch "$dest" < "$src"
        echo "Patched: $dest with $src"
    else
        echo "Patch source or destination file not found: $src or $dest"
    fi
}

reverse_patches() {
    local file_names=("${!1}")
    local src_dir="$2"
    local dest_dir="$3"
    local suffix="$4"
    local src="$src_dir/$file.$PVE_VERSION$suffix"
    local dest="$dest_dir/$file"
    if [[ -f "$src" && -f "$dest" ]]; then
        patch -R "$dest" < "$src"
        echo "Reversed patch: $dest with $src"
    else
        echo "Patch source or destination file not found: $src or $dest"
    fi
}

print_hashes() {
    local file_names=("${!1}")
    local dir="$2"
    local suffix="$3"
    local version="$4"
    for file in "${file_names[@]}"; do
        local path="$dir/$file.$version$suffix"
        if [[ -f "$path" ]]; then
            sha256sum "$path"
        else
            echo "Missing: $path"
        fi
    done
}

doPatchInstall() {
    # install the copy of QSTOR plugin only
    copy_files FILE_QSTOR_PLUGIN[@] "$SOURCE_DIR_PERL5" "$TARGET_DIR_PERL5" ".pm"

    # apply patches to other files as needed
    apply_patches FILE_PATCHES_PERL5[@] "$SOURCE_DIR_PATCHES_PERL5" "$TARGET_DIR_PERL5" ".pm"
}

doReversePatchInstall() {
    # reverse patches to other files as needed
    reverse_patches FILE_PATCHES_PERL5[@] "$SOURCE_DIR_PATCHES_PERL5" "$TARGET_DIR_PERL5" ".pm"
}

doFullCopyInstall() {
    # copy files from Source to Target - perl5
    copy_files FILE_NAMES_PERL5[@] "$SOURCE_DIR_PERL5" "$TARGET_DIR_PERL5" ".pm"
    # copy files from Source to Target - js
    copy_files FILE_NAMES_JS[@] "$SOURCE_DIR_JS" "$TARGET_DIR_JS" ".js"
    # copy files from Source to Target - apidoc
    copy_files FILE_NAME_APIDOC[@] "$SOURCE_DIR_APIDOC" "$TARGET_DIR_APIDOC" ".js"
}

doChecksum() {
    # perl5 files
    print_hashes FILE_NAMES_PERL5[@] "$SOURCE_DIR_PERL5" ".pm" "$PVE_VERSION"
    print_hashes FILE_NAMES_PERL5[@] "$TARGET_DIR_PERL5" ".pm" ""
    echo "---------------------------------"
    # js files
    print_hashes FILE_NAMES_JS[@] "$SOURCE_DIR_JS" ".js" "$PVE_VERSION"
    print_hashes FILE_NAMES_JS[@] "$TARGET_DIR_JS" ".js" ""
    echo "---------------------------------"
    # apidoc files
    print_hashes FILE_NAME_APIDOC[@] "$SOURCE_DIR_APIDOC" ".js" "$PVE_VERSION"
    print_hashes FILE_NAME_APIDOC[@] "$TARGET_DIR_APIDOC" ".js" ""
    echo "---------------------------------"
}

# main
# Handle rollback before any other operation
if [[ $DO_ROLLBACK -eq 1 ]]; then
    echo "Rolling back files from $BACKUP_DIR..."
    rollback_files FILE_NAMES_PERL5[@] "$TARGET_DIR_PERL5" ".pm"
    rollback_files FILE_NAMES_JS[@] "$TARGET_DIR_JS" ".js"
    rollback_files FILE_NAME_APIDOC[@] "$TARGET_DIR_APIDOC" ".js"
    echo "Rollback complete."
    exit 0
elif [[ $DO_REVERSE_PATCH -eq 1 ]]; then
    echo "Reversing patches on target files..."
    doReversePatchInstall
    echo "Reverse patch complete."
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
    backup_files FILE_NAMES_PERL5[@] "$TARGET_DIR_PERL5" ".pm"
    backup_files FILE_NAMES_JS[@] "$TARGET_DIR_JS" ".js"
    backup_files FILE_NAME_APIDOC[@] "$TARGET_DIR_APIDOC" ".js"
    echo "Backup complete."
fi

# might only need to do this on full copy installs
if [[ $DO_CHECKSUM -eq 1 ]]; then
    # perl5 files
    echo "Hashes for Source and Target files pre install:"
    doChecksum
fi

# installation
if [[ $FULL_COPY -eq 1 ]]; then
    doFullCopyInstall
else
    # Patch install mode - default
    doPatchInstall
fi

# might only need to do this on full copy installs
if [[ $DO_CHECKSUM -eq 1 ]]; then
    echo "Hashes for Source and Target files post install:"
    doChecksum
fi



