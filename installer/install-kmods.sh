#!/bin/bash
####################################################################################################
# @file install-kmods.sh
#
# Perform installation or removal of kernel modules.
#
# @author ayegorov@
# @author owner is alexg@
#
# Copyright (c) 1999-2016 Parallels International GmbH.
# All rights reserved.
# http://www.parallels.com
####################################################################################################

BASE_DIR="$(dirname "$0")"
PMANAGER="$BASE_DIR/pm.sh"

KMOD_DIR="$2"

BACKUP_DIR="$3"
BACKUP="$BACKUP_DIR/.kmods.list"

LOG_FILE="$4"

ARCH=$(uname -m)
KVER=$(uname -r)
KDIR="/lib/modules/$KVER/extra"

if [ -f "/lib/modules/$KVER/build/include/linux/version.h" ]; then
	KVERH="/lib/modules/$KVER/build/include/linux/version.h"
else
	KVERH="/lib/modules/$KVER/build/include/generated/uapi/linux/version.h"
fi

PRL_MOD="prl_mod"
tools_modules_name="parallels-tools"
FULL_PRODUCT_VERSION=$(cat "$KMOD_DIR/../version")
INSTALL_FULL_PRODUCT_VERSION=$(cat "$BASE_DIR/../version")

# extentions of kernel modules depend on version
if [ $KVER = "$(echo -e $KVER'\n2.5' | sort -t'.' -g | tail -n 1)" ]; then
	KEXT=ko
	BUILD_PRL_FREEZE="yes"
else
	KEXT=o
fi
TGZEXT=tar.gz

####################################################################################################
# Definition of kernel modules to be installed
####################################################################################################

KMODS_PATHS="prl_eth/pvmnet                            \
             prl_tg/Toolgate/Guest/Linux/prl_tg        \
             prl_fs/SharedFolders/Guest/Linux/prl_fs   "

[ "x$BUILD_PRL_FREEZE" = "xyes" ] && KMODS_PATHS="$KMODS_PATHS prl_fs_freeze/Snapshot/Guest/Linux/prl_freeze"

####################################################################################################
# Definition of error codes
####################################################################################################

E_NOERROR=0
E_PMLOCKED=123 # defined in pm.sh
E_NOPM=124   # defined in pm.sh
E_NOACT=141
E_NODIR=142
E_BFAIL=143
E_CFAIL=144
E_BUILD=145
E_KHEAD=146
E_MANAG=147
E_CHKFAIL=150

####################################################################################################
# Show error
####################################################################################################

perror() {
	echo $1 1>&2
}

####################################################################################################
# Check requirements to install kernel modules
####################################################################################################

check_requirements() {
	# Check... are there required package manager and packages?
	packages=$("$PMANAGER" --check gtools)
	retcode=$?
	packages=$(echo "$packages" | grep '^[mo] ')
	[[ -z "$packages" && $retcode -eq 0 ]] && return $E_NOERROR

	do_logging=
	[ -n "$LOG_FILE" ] && do_logging="--logfile"
	for i in {1..10}; do
		"$PMANAGER" $do_logging "$LOG_FILE" --install gtools
		result_pm=$?
		# pm.sh retcode E_PMLOCKED (123) means package manager is locked at the
		# moment. It is highly probale if PTfL are updated after VM resume. So
		# let's retry installation attempt after 10 seconds pause.
		[ $result_pm -ne $E_PMLOCKED ] && break
		[ $i -ne 10 ] &&
			echo 'Package manager is locked. Trying once again.' && sleep 10
	done

	[ $result_pm -eq 0 ] && return $E_NOERROR
	[ $result_pm -eq $E_NOPM ] &&
		perror "Error: none of supported package managers found in system." ||
		perror "Error: failed to install mandatory packages."
	return $E_CHKFAIL
}

####################################################################################################
# Remove kernel modules
####################################################################################################

remove_weak_updates() {
	# On CentOS and RHEL there's mechanism called weak-updates,
	# which creates symlinks for all modules in
	# /lib/modules/$(uname -r)/weak-updates/ directory
	# It's nice to clean that symlinks from that dir also.
	local mod="${1##*/}"
	for kver in $(ls -1 /lib/modules/); do
		rm -f "/lib/modules/${kver}/weak-updates/${mod}"
	done
}


remove_kernel_modules() {
	# Removing dkms modules. Should be done first cause dkms is too smart: it
	# may restore removed modules by original path.
	if type dkms > /dev/null 2>&1; then
		# Previously we registered our kmods under different name.
		# So need to support removing them as well.
		for mod_name in 'parallels-tools-kernel-modules' $tools_modules_name; do
			# Unfortunately we cannot relay on dkms status retcode. So need to
			# grep it's output. If there's nothing - there was no such modules
			# registered.
			dkms status -m $mod_name -v $FULL_PRODUCT_VERSION | \
				grep -q $mod_name || continue
			dkms remove -m $mod_name -v $FULL_PRODUCT_VERSION --all && \
				echo "DKMS modules were removed successfully"
		done
	fi

	for kmod_path in $KMODS_PATHS; do
		kmod=$(echo "$kmod_path" | sed -e "s#/.*##")
		kmod_dir="$KMOD_DIR/$kmod"
		fmod="$KDIR/$kmod.$KEXT"

		echo "Start removal of $kmod kernel module"

		# Unload kernel module
		rmmod "$kmod" > /dev/null 2>&1
		if [ $? -eq 0 ]; then
			echo "Kernel module $kmod was unloaded"
		else
			perror "Error: could not unload $kmod kernel module"
		fi

		# Remove kernel module from directory
		ls "$fmod" > /dev/null 2>&1 && rm -f "$fmod"

		# Remove directory if it exists
		[ -d "$kmod_dir" ] && rm -rf "$kmod_dir"
	done

	if ([ -n "$FLAG_REMOVE_ALL" ] && [ -e "$BACKUP" ]); then
		echo "Remove kernel modules according to $BACKUP file"
		cat "$BACKUP" | while read line; do
			rm -f "$line"
			remove_weak_updates "$line"
		done
		rm -f "$BACKUP"
	fi
}

####################################################################################################
# Install kernel modules
####################################################################################################

install_kernel_modules() {
	# Unpack kernel modules sources
	tar -xzf "$KMOD_DIR/$PRL_MOD.$TGZEXT" -C "$KMOD_DIR"

	# Build kernel modules
	make -C "$KMOD_DIR" -f Makefile.kmods
	result=$?
	if [ $result -ne 0 ]; then
		perror "Error: could not build kernel modules"
		return $E_BFAIL
	fi

	for kmod_path in $KMODS_PATHS; do
		kernel_module_name=$(echo "$kmod_path" | sed -e "s#/.*##")
		kernel_dir="$KMOD_DIR/$kmod_path"
		echo "Start installation of $kernel_module_name kernel module"
		found_module="$kernel_dir/$kernel_module_name.$KEXT"
		if [ ! -e "$found_module" ]; then
			perror "Error: could not find $kernel_module_name kernel module"
			return $E_BFAIL
		fi
		cp -f "$found_module" "$KDIR"
		echo "$KDIR/$kernel_module_name.$KEXT" >> "$BACKUP"
	done

	if type dkms > /dev/null 2>&1; then
		# Starting from version 2.2 dkms broke options compatibility:
		# option "ldtarball" will refuse to get our kmods archive. But at the
		# same time "add" option will eat our kmods sources.
		if dkms --version | sed 's/dkms: \([0-9]\+\.[0-9]\+\)\..*/\1/' | \
			awk '{if ($1 < 2.2) exit 1}'
		then
			dkms add "$KMOD_DIR"
		else
			dkms ldtarball --archive="$KMOD_DIR/$PRL_MOD.$TGZEXT"
		fi
		if [ $? -eq 0 ]; then
			echo "DKMS modules were added successfully"
		else
			echo "DKMS modules were not added"
		fi
		for _kver in `ls /lib/modules`; do
			dkms build -m $tools_modules_name -v $INSTALL_FULL_PRODUCT_VERSION -k $_kver > /dev/null 2>&1
			if [ $? -eq 0 ]; then
				echo "DKMS modules for kernel $_kver were built successfully"
			else
				echo "DKMS modules for kernel $_kver building failed"
			fi
			dkms install -m $tools_modules_name -v $INSTALL_FULL_PRODUCT_VERSION -k $_kver --force > /dev/null 2>&1
			if [ $? -eq 0 ]; then
				echo "DKMS modules for kernel $_kver were installed successfully"
			else
				echo "DKMS modules for kernel $_kver installation failed"
			fi
		done
	fi

	depmod -a
}

####################################################################################################
# Start installation or removal of kernel modules
####################################################################################################

case "$1" in
	-i | --install | -r | --remove)

		# Check directory with kernel modules
		if [ -z "$KMOD_DIR" ]; then
			perror "Error: directory with kernel modules was not specified"
			exit $E_NODIR
		fi

		# Check backup directory
		if [ -z "$BACKUP_DIR" ]; then
			perror "Error: backup directory was not specified"
			exit $E_NODIR
		fi

		# Make directory for extra kernel modules
		mkdir -p "$KDIR"

		if ([ "$1" = "-i" ] || [ "$1" = "--install" ]); then
			act="install"
			fact="Installation"
		else
			act="remove"
			fact="Removal"
		fi

		${act}_kernel_modules
		result=$?

		if [ $result -eq $E_NOERROR ]; then
			echo "${fact} of kernel modules was finished successfully"
		else
			perror "Error: failed to ${act} kernel modules"
		fi

		exit $result
		;;

	-c | --check)
		check_requirements
		exit $?
		;;
esac

exit $E_NOACT
