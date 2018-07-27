#!/bin/bash
####################################################################################################
# @file install.sh
#
# Perform installation, deinstallation or upgrade of Parallels Guest Tools for Linux.
#
# @author ayegorov@
# @author owner is alexg@
#
# Copyright (c) 1999-2016 Parallels International GmbH.
# All rights reserved.
# http://www.parallels.com
####################################################################################################

PATH=/sbin:/bin:/usr/sbin:/usr/bin${PATH:+:$PATH}

TOOLS_NAME='Parallels Guest Tools'
BASE_DIR=$(readlink -f "$(dirname "$(readlink -f "$0")")/..")
INSTALLER="installer"
KMODS="kmods"
TOOLS="tools"
BLACKLIST="blacklist-parallels.conf"
BLACKLIST_OLD="blacklist-parallels"

# Definition of installation package files
INSTALLER_DIR="$BASE_DIR/$INSTALLER"
KMODS_DIR="$BASE_DIR/$KMODS"
TOOLS_DIR="$BASE_DIR/$TOOLS"
INSTALL="$BASE_DIR/install"
INSTALL_GUI="$BASE_DIR/install-gui"
VERSION="$BASE_DIR/version"

# Definition of extra installers
INSTALL_KMODS="$INSTALLER_DIR/install-kmods.sh"
INSTALL_TOOLS="$INSTALLER_DIR/install-tools.sh"

# Dracut kmods blacklist file
DRACUT_CONF_DIR="/etc/dracut.conf.d"
DRACUT_KMODS_FILE="/etc/dracut.conf.d/parallels-tools.conf"

# Definition of target installation files
# The IBACKUP folder is the backupfolder in /var/lib
# the BACKUP folder is the old one in /usr/lib we save it
# in order not to broke the upgrade procedure of the old
# version of parallels-tools

IBACKUP_DIR="/var/lib/parallels-tools"
INSTALL_DIR="/usr/lib/parallels-tools"
INSTALL_DIRS="	$INSTALL_DIR						\
		/usr/lib/parallels-server-tools	\
		/usr/lib/parallels"
MODPROBED_DIR="/etc/modprobe.d"
MODPROBE_CONF="/etc/modprobe.conf"
ALIAS_NE2K_OFF="install ne2k-pci /bin/true # replaced by prl_eth"
ALIAS_NE2K_OVERRIDE="install ne2k-pci modprobe -q prl_eth || modprobe -i ne2k-pci"
MODPROBE_PRL_ETH_CONF="$MODPROBED_DIR/prl_eth.conf"

INSTALL_DIR_KMODS="$INSTALL_DIR/$KMODS"
INSTALL_DIR_TOOLS="$INSTALL_DIR/$TOOLS"

# Definition of LOG file
LOG="/var/log/parallels-tools-install.log"

# Definition of flags
if [ -z "$FLAG_CHECK_GUI" ]; then
	FLAG_CHECK_GUI=""
fi

UPDATE_MODE=0
RESTORE_ON_FAIL=0
REBOOT_REQUIRED=0

####################################################################################################
# Definition of error codes
####################################################################################################

E_NOERROR=0
E_NOLINUX=101
E_NOPERM=102
E_NOARGS=103
E_WARG=104
E_NOVER=105
E_NOTOOLS=106
E_NOANS=148
E_NOPKG=149

####################################################################################################
# Enable/disable logging to file
####################################################################################################

log_enable() {
	exec 3>&- 4>&-
	if [ -n "$VERBOSE" ]; then
		# Save stdout and stderr to free descriptors, then replace
		# stderr and stdout with pipe to subshell which writes
		# everything to it's own stdout and to $LOG file
		# Normally fds 2 and 1 point to the same device, but
		# QProcess uses pipes for IPC, and each standard channel
		# corresponds to distinct pipe
		exec 3>&1 4>&2 &> >(tee -a "$LOG")
	else
		# Just save stdout/err to fd 3/4 and replace them both
		# with opened $LOG file
		exec 3>&1 4>&2 >>"$LOG" 2>&1
	fi
}

log_disable() {
	# Restore saved stdout and stderr, and close additional descriptors
	exec 1>&3 2>&4 3>&- 4>&-
}

####################################################################################################
# Show error
####################################################################################################

perror() {
	echo "$1" >&2
}

####################################################################################################
# Help message
####################################################################################################

usage() {
	echo "Perform installation, deinstallation or upgrade of Parallels Guest Tools for Linux"
	echo "Usage: $0 [option] [--skip-rclocal-restore] [--progress] [--restore-on-fail]"
	echo "		 -i, --install				install or upgrade Parallels tools in Guest OS"
	echo "		 --install-unattended	 		perform unattended installation or upgrade of Parallels tools"
	echo "		 --install-unattended-with-deps"
	echo "							perform unattended installation or upgrade of Parallels tools"
	echo "							with downloading required packages"
	echo "		 --install-ptiagent			install Parallels Tools Installation Agent only"
	echo "		 -r, --remove			 	remove Parallels tools from Guest OS"
	echo "		 -v, --version			 	output version information"
	echo "		 -h, --help				display this help message"
	echo "		 --skip-rclocal-restore  		flag to disable restoring /etc/rc.local broken by unsuccessful"
	echo "							express installation (for Ubuntu systems)"
	echo "		 --progress				show installation progress in terminal"
	echo "		 --verbose				report installation process also to stdout"
	echo "		 --restore-on-fail			try to restore previous Parallels Guest Tools installation"
	echo "							(if it exists) in case of this one is failed"
}

####################################################################################################
# Check requirements to run this script
####################################################################################################

check_requirements() {
	if [ "x$(uname -s)" != "xLinux" ]; then
		perror "Error: these $TOOLS_NAME can be installed on Linux guest OS only."
		exit $E_NOLINUX
	fi

	if [ "x$(id -u)" != "x0" ]; then
		perror "Error: you do not have permissions to run this script."
		exit $E_NOPERM
	fi
}

check_restrictions() {
	# Do not check restrictions if and only if
	# we are installing tools from GUI application
	if [ -z "$FLAG_CHECK_GUI" ]; then
		# Perform basic checks
		check_requirements
		"$INSTALL_KMODS" --check "$KMODS_DIR" "$BACKUP_DIR" "$LOG"
		result=$?
		[ $result -ne $E_NOERROR ] && return $result
	fi

	return $E_NOERROR
}

####################################################################################################
# Remove Guest Tools
####################################################################################################

remove_gt3() {
	daemon=""
	sremove=""

	if [ "$1" = "/usr/lib/parallels" ]; then
		echo "Remove Guest Tools 3.x version"
		daemon="prluserd"
		sremove="remove"
	elif [ "$1" = "/usr/lib/parallels-server-tools" ]; then
		echo "Remove Guest Tools 4.0 RC"
		daemon="prltoolsd"
		sremove="unregister"
	else
		perror "Error: invalid installation directory: $1"
		return $E_NOTOOLS
	fi

	uninstall="$1/uninstall.sh"
	if [ -x "$uninstall" ]; then
		"$uninstall"
	else
		fdaemon="$1/$daemon"
		if [ -x "$fdaemon" ]; then
			echo "Stop Guest Tools service"
			"$fdaemon" stop
		fi

		service="$1/iscripts"
		if [ -x "$service" ]; then
			echo "Unregister Guest Tools service"
			iservice="/etc/init.d/$daemon"
			"$service" $sremove
			[ -e "$iservice" ] && rm -f "$iservice"
		fi

		xconf="$1/.xcfg.info"
		if [ -f "$xconf" ]; then
			echo "Restore X server configuration"
			. "$xconf"

			xfile=""
			if [ -f "$CFGDIR/$LASTCFG" ]; then
				xfile="$CFGDIR/$CURRCFG"
				mv "$CFGDIR/$LASTCFG" "$xfile"
			elif [ -f "$BKPCFG" ]; then
				xfile="$CURCFG"
				mv "$BKPCFG" "$xfile"
			fi

			# Remove X server "fail safe" files
			rm -f "$xfile."*
		fi

		evdev="$1/.evdev.info"
		if [ -f "$evdev" ]; then
			echo "Restore evdev driver"
			. "$evdev"
			fevdev="$1/$EVDEV"
			[ -f "$fevdev" ] && mv "$fevdev" "$XIDIR/$EVDEV"
		fi

		itab="$1/.inittab.fc6"
		if [ -f "$itab" ]; then
			echo "Restore inittab file"
			mv -f "$itab" "/etc/inittab"
		fi

		ilist="$1/.install.lst"
		if [ -f "$ilist" ]; then
			echo "Remove Guest Tools modules"
			cat "$ilist" | while read line; do
				echo "$line" | tr -d \' | xargs rm -f
			done
		fi
	fi

	echo "Remove $1 directory"
	rm -rf "$1"
}

remove_gt4() {

	# Remove user space modules
	remove_mode='--remove'
	test $UPDATE_MODE -eq 1 -a "x$1" != "x-f" && remove_mode='--remove-skip-xconf'

	"$INSTALL_TOOLS" "$remove_mode" "$INSTALL_DIR_TOOLS" "$BACKUP_DIR"

	# Get absolute path of base directory
	pwdir=$(pwd)
	bdir=$(cd "$BASE_DIR"; pwd)
	cd "$pwdir"

	# Check... should we completely remove Guest Tools?
	if ([ "$1" = "-f" ] || [ "$bdir" != "$INSTALL_DIR" ]); then
		# Remove kernel modules
		FLAG_REMOVE_ALL="Yes" "$INSTALL_KMODS" --remove "$INSTALL_DIR_KMODS" "$BACKUP_DIR"

		# Backups will be removed only if we are in non-update or force-remove mode
		if [ "$1" = "-f" -o $UPDATE_MODE -ne 1 ]; then
			# Remove backup directory
			rm -rf "$BACKUP_DIR"
		fi
		# Finally remove installation directory
		echo "Remove $INSTALL_DIR directory"
		rm -rf "$INSTALL_DIR"
	else
		# Remove kernel modules
		FLAG_REMOVE_ALL="" "$INSTALL_KMODS" --remove "$INSTALL_DIR_KMODS" "$BACKUP_DIR"

		echo "Skip removal of $INSTALL_DIR directory"
	fi
}

remove_gt() {
	result=$E_NOTOOLS
	n=0
	if [ -d "$INSTALL_DIR/.backup" ]; then
		echo "old version of parallels tools"
		BACKUP_DIR="$INSTALL_DIR/.backup"
	else
		echo "new version of parallels tools"
		BACKUP_DIR="$IBACKUP_DIR/.backup"
	fi

	[ -f "$MODPROBED_DIR/$BLACKLIST" ] && rm -f "$MODPROBED_DIR/$BLACKLIST"
	[ -f "$MODPROBED_DIR/$BLACKLIST_OLD" ] && rm -f "$MODPROBED_DIR/$BLACKLIST_OLD"
	[ -f "$MODPROBE_PRL_ETH_CONF" ] && rm -f "$MODPROBE_PRL_ETH_CONF"
	[ -f "$DRACUT_KMODS_FILE" ] && rm -f "$DRACUT_KMODS_FILE"
	if [ -f "$MODPROBE_CONF" ]; then
		cmds="$ALIAS_NE2K_OFF:$ALIAS_NE2K_OVERRIDE"
		IFS=':'
		for cmd in $cmds; do
			esc_cmd=$(echo $cmd | sed 's/\//\\\//g')
			grep -q "^\W*$cmd" "$MODPROBE_CONF" && sed -i "/^\W*$esc_cmd/d" "$MODPROBE_CONF"
		done
		unset IFS
	fi

	# Find directory with installed Guest Tools
	for idir in $INSTALL_DIRS; do
		if [ -d "$idir" ]; then
			echo "Found Guest Tools directory: $idir"
			case "$n" in
				0) remove_gt4 "$1" ;;
				# Remove old versions of Guest Tools
				1 | 2) remove_gt3 "$idir" ;;
			esac
			result=$E_NOERROR
		fi
		n=$(($n + 1))
	done

	if [ $result -ne $E_NOERROR ]; then
		echo "Installed Guest Tools were not found"
		UPDATE_MODE=0
	fi

	return $result
}

istatus() {
	local argument=$1
	local version=$2
	local error_msg=$3

	local istatus_dir=$INSTALLER_DIR
	[ -n "$ISTATUS_DIR" ] && istatus_dir=$ISTATUS_DIR
	local arch_suffix=32
	[ "$(uname -m)" = 'x86_64' ] && arch_suffix=64
	local istatus_cmd=$istatus_dir/prl_istatus$arch_suffix

	"$istatus_cmd" "$argument" "$version" ||
		perror "Error during report about ${error_msg}."
}

remove_guest_tools() {
	echo ""
	echo "$(date)"
	echo "Start removal of Guest Tools"
	if [ -d "$INSTALL_DIR/.backup" ]; then
		echo "old version of parallels tools"
		BACKUP_DIR="$INSTALL_DIR/.backup"
	else
		echo "new version of parallels tools"
		BACKUP_DIR="$IBACKUP_DIR/.backup"
	fi

	[ -e "$INSTALL_DIR/version" ] && ver=$(< "$INSTALL_DIR/version")
	# Special kludge to store prl_istatus binary temporarily if we are calling
	# uninstaller "in place".
	local tmp_istatus=$(mktemp -d -t prlistatus-XXXXXX)
	cp "$INSTALLER_DIR"/prl_istatus{32,64} "$tmp_istatus"

	remove_gt -f
	result=$?
	if [ $result -ne $E_NOERROR ]; then
		rm -rf "$tmp_istatus"
		return $result
	fi

	ISTATUS_DIR=$tmp_istatus istatus uninstalled "$ver" \
		"uninstalled tools version"
	rm -rf "$tmp_istatus"

	echo "$TOOLS_NAME were removed successfully!"
	return $E_NOERROR
}

restore_rclocal() {
	rclocal=/etc/rc.local
	rclocal_backup=/etc/rc.local.backup

	test -f "$rclocal" || test -f "$rclocal_backup" || return

	# Try criterias of damaged express installation
	grep -q 'HOME_DIR' "$rclocal" || return
	grep -q '^mv /etc/rc.local.backup /etc/rc.local$' "$rclocal" || return
	grep -q '^reboot$' "$rclocal" || return

	echo "Failed express installation is detected!"
	echo "Trying to restore /etc/rc.local and other stuff"

	# Here are the commands which were not executed during the end
	# of express installation. See Ubuntu's part of UnattendedCd lib.
	mv -f "$rclocal_backup" "$rclocal"
	mv -f /opt/prl-tools-installer/S*gdm /etc/rc2.d/
	mv -f /opt/prl-tools-installer/S*kdm /etc/rc2.d/
	rm -rf /opt/prl-tools-installer
	mv -f /etc/issue.backup /etc/issue
}


PROGR_TOTAL=10
PROGR_CURR=0
echo_progress() {
	[ -z $SHOW_PROGRESS ] && return
	p=`awk -v a=$PROGR_TOTAL -v b=$PROGR_CURR  \
		'BEGIN {printf("%f", (100 / a * b))}'`
	echo "installer:%$p" 1>&3
	let PROGR_CURR+=1
}

####################################################################################################
# Install Guest Tools
####################################################################################################

install_guest_tools() {

	echo_progress
	istatus install_started "$TOOLS_VERSION" \
		"start installation of parallels tools"

	echo ""
	echo "$(date)"
	echo "Start installation or upgrade of Guest Tools"

	echo_progress
	if [ -z "$SKIP_RCLOCAL_RESTORE" ]; then
		restore_rclocal
	else
		echo "Restoring rc.local is skipped"
	fi

	# Switching to update mode
	# If guest tools are not installed really remove_gt() will set UPDATE_MODE=0
	echo_progress
	UPDATE_MODE=1
	remove_gt

	result=$?
	if [ $result -eq $E_NOERROR ]; then
		echo "Register service to install new Guest Tools"
		# TODO register service
	fi

	echo_progress
	echo "Perform installation into the $INSTALL_DIR directory"
	# Create installation directory and copy files
	mkdir -p "$INSTALL_DIR"
	# Set up new style backup_dir
	BACKUP_DIR="$IBACKUP_DIR/.backup"
	# Create directory for backup files
	mkdir -p "$BACKUP_DIR"

	echo_progress
	# Install kernel modules
	cp -Rf "$KMODS_DIR" "$INSTALL_DIR"
	"$INSTALL_KMODS" --install "$INSTALL_DIR_KMODS" "$BACKUP_DIR"
	result=$?
	if [ $result -ne $E_NOERROR ]; then
		# Compilation of kernel modules is failed so do clean up
		rm -rf "$INSTALL_DIR"
		istatus install_failed "$TOOLS_VERSION" \
			"failed installation of parallels tools"
		return $result
	fi

	# Ensure that after kernel update on CentOS
	# or RHEL our drivers won't end up in freshly
	# generated initramfs
	if [ -d "$DRACUT_CONF_DIR" ]; then
		echo 'omit_drivers+="prl_.*"' > "$DRACUT_KMODS_FILE"
	fi

	echo_progress
	# Special procedure to update installer stuff
	# because PTIAgent may be running there.
	local TMP_INSTALLER_DIR="$(mktemp -d -t prlinstallerXXXXXX)"
	cp -Rf "$INSTALLER_DIR" "$TMP_INSTALLER_DIR"
	mv -f "$TMP_INSTALLER_DIR/$INSTALLER" "$INSTALL_DIR"
	chmod 755 "$INSTALL_DIR/$INSTALLER"
	rm -rf "$TMP_INSTALLER_DIR"

	echo_progress
	cp -Rf "$TOOLS_DIR" "$INSTALL_DIR"
	cp -Rf "$INSTALL" "$INSTALL_DIR"
	cp -Rf "$INSTALL_GUI" "$INSTALL_DIR"
	cp -Rf "$VERSION" "$INSTALL_DIR"
	test $UPDATE_MODE -eq 1 && \
	if [ -d "$INSTALL_DIR/.backup" ]; then
		cp -Rf "$INSTALL_DIR/.backup" "$IBACKUP_DIR" && \
		rm -rf "$INSTALL_DIR/.backup"
	fi

	# Install blacklist and override ne2k-pci by our prl_eth
	if [ -d "$MODPROBED_DIR" ]; then
		cp -f "$INSTALLER_DIR/$BLACKLIST" "$MODPROBED_DIR"
		echo "$ALIAS_NE2K_OVERRIDE" > "$MODPROBE_PRL_ETH_CONF"
	elif [ -f "$MODPROBE_CONF" ]; then
		echo "$ALIAS_NE2K_OVERRIDE" >> "$MODPROBE_CONF"
	else
		echo "$MODPROBE_CONF is missing"
	fi

	echo_progress
	# Install user space applications and drivers
	install_mode='--install'
	test $UPDATE_MODE -eq 1 && \
		"$INSTALL_TOOLS" --check-xconf-patched "$INSTALL_DIR_TOOLS" "$BACKUP_DIR" && \
			install_mode='--install-skip-xconf'
	"$INSTALL_TOOLS" "$install_mode" "$INSTALL_DIR_TOOLS" "$BACKUP_DIR"
	result=$?
	if [ $result -ne $E_NOERROR ]; then
		istatus install_failed "$TOOLS_VERSION" \
			"failed installation of parallels tools"
		return $result
	fi

	echo_progress
	echo "Send installed Parallels Tools version to dispatcher."
	istatus installed "$TOOLS_VERSION" "installed tools version"

	echo "$TOOLS_NAME were installed successfully!"
	echo_progress

	return $E_NOERROR
}

install_ptiagent() {
	BACKUP_DIR="$IBACKUP_DIR/.backup"
	mkdir -p "$BACKUP_DIR"

	local tgt_installer_dir="${INSTALL_DIR}/installer"
	local tgt_tools_dir="${INSTALL_DIR}/tools"

	mkdir -p "$tgt_installer_dir"
	mkdir -p "$tgt_tools_dir"

	cp -fR "${INSTALLER_DIR}/ptiagent32" "$tgt_installer_dir"
	cp -fR "${INSTALLER_DIR}/ptiagent64" "$tgt_installer_dir"
	cp -fR "${INSTALLER_DIR}/iagent32" "$tgt_installer_dir"
	cp -fR "${INSTALLER_DIR}/iagent64" "$tgt_installer_dir"

	cp -f "${TOOLS_DIR}/ptiagent.desktop" "$tgt_tools_dir"

	cp -f "$INSTALL_GUI" "$INSTALL_DIR"
	cp -f "$VERSION" "$INSTALL_DIR"
}

is_reboot_required() {
	"$INSTALLER_DIR/detect-xserver.sh" -v >/dev/null 2>&1
	[ $? -eq $E_NOERROR ]
}

post_install() {
	echo ">>> Postinstall"
	echo "Enabling PRL_GL"
	/etc/init.d/prl-x11 start
	echo "Writing OS version and Xorg version"
	"$INSTALLER_DIR/pm.sh" --os-ver > "$IBACKUP_DIR/os.version"
	"$INSTALLER_DIR/detect-xserver.sh" --xver > "$IBACKUP_DIR/xorg.version"
	echo "Starting prltoolsd service:"
	PRL_SKIP_PTIAGENT_START=1 /etc/init.d/prltoolsd start
	echo_progress
}

RESTORE_BACKUP=
backup_old_version() {
	if [ ! -d "$INSTALL_DIR" ]; then
		echo "Previous version was not found. Nothing to backup."
		return 1
	fi

	prev_version_file="$INSTALL_DIR/version"
	[ -r "$prev_version_file" ] && TOOLS_VERSION_PREV=$(< "$prev_version_file")
	echo "Installation of $TOOLS_NAME version '$TOOLS_VERSION_PREV' was found."

	RESTORE_BACKUP=$(mktemp -t prltools-backup-XXXXXX.tar.gz)
	tar cz -C "$INSTALL_DIR" . >"$RESTORE_BACKUP" && \
		echo "Created previous version backup in '$RESTORE_BACKUP'" || \
		echo "Failed to create backup of previous version."
}

restore_old_version() {
	[ -r "$RESTORE_BACKUP" ] || return 1
	echo
	echo "Reinstalling previous version '$TOOLS_VERSION_PREV'" \
		"from backup '$RESTORE_BACKUP'"
	echo '--------------------------------------------------------'
	tmp_installer=$(mktemp -d -t prl-tools-lin-XXXXXX)
	tar xzf "$RESTORE_BACKUP" -C "$tmp_installer" || return 1
	rm -f "$RESTORE_BACKUP"
	"$tmp_installer/install" --install-unattended-with-deps
	rc=$?
	echo '--------------------------------------------------------'
	[ $rc -eq 0 ] &&
		echo "Previous version '$TOOLS_VERSION_PREV' was" \
			"reinstalled successfully" ||
		echo "Failed to restore previous version '$TOOLS_VERSION_PREV'" \
			"(retcode $rc)"
	rm -rf "$tmp_installer"
	return $rc
}

show_installer_error() {
	if [ $result -ne $E_NOPKG -a -z "$FLAG_CHECK_GUI" ]; then
		# Log is not created if installer failed with error $E_NOPKG
		perror "Error: failed to $2 $TOOLS_NAME!"
		[ -f "$LOG" ] && [ -z $VERBOSE ] &&
			perror "Please, look at $LOG file for more information."
	fi
}

show_installer_ok() {
	if [ "$1" = 'install' ]; then
		msg0='installed'
		msg1='installation'
	elif [ "$1" = 'upgrade' ]; then
		msg0='upgraded'
		msg1='upgrade'
	elif [ "$1" = 'remove' ]; then
		msg0='removed'
		msg1='removal'
	elif [ "$1" = 'restore' ]; then
		msg0='restored'
		msg1='recovery'
	fi

	echo "$TOOLS_NAME were $msg0 successfully!"
	[ $REBOOT_REQUIRED -eq 1 ] &&
		echo "Please, reboot your OS to finish $msg1 of $TOOLS_NAME."
}

install_proc() {
	log_enable
	echo "Started installation of $TOOLS_NAME version '$TOOLS_VERSION'"
	check_restrictions
	result=$?
	[ $result -ne $E_NOERROR ] &&
		{ show_installer_error $result "install or upgrade"; return $result; }

	[ $RESTORE_ON_FAIL -eq 1 ] && backup_old_version
	install_guest_tools
	result=$?
	# UPDATE_MODE is set only in install_guest_tools
	[ $UPDATE_MODE -eq 1 ] && type_msg='upgrade' || type_msg='install'
	if [ $result -ne $E_NOERROR ]; then
		show_installer_error $result "$type_msg"
		if [ $RESTORE_ON_FAIL -eq 1 ]; then
			echo "Trying to restore previous $TOOLS_NAME installation..."
			type_msg='restore'
			restore_old_version || return $?
		else
			return $result
		fi
	fi
	post_install
	result=$?
	log_disable
	show_installer_ok "$type_msg"
	return $result
}

remove_proc() {
	check_requirements
	log_enable
	remove_guest_tools
	result=$?
	log_disable
	msg='remove'
	if [ $result -eq $E_NOERROR ]; then
		show_installer_ok "$msg"
	else
		show_installer_error $result "$msg"
	fi
	if ( type lsb_release && type dpkg-reconfigure ) > /dev/null 2>&1; then
		distro=$(lsb_release -i | awk -F " " '{print $3}')
		if [ "$distro" = "Ubuntu" ]; then
			dpkg-reconfigure xserver-xorg
		fi
	fi
	return $result
}

####################################################################################################
# Install, upgrade or remove Guest Tools
####################################################################################################

[ -r "$VERSION" ] && TOOLS_VERSION=$(< "$VERSION")
is_reboot_required && REBOOT_REQUIRED=1

if [ $# -eq 0 ]; then
	perror "Error: wrong number of input parameters [$#]"
	echo ""
	usage
	exit $E_NOARGS
fi

case "$1" in
	--install-x-modules)
		date >> "$LOG"
		echo "Starting installation of Parallels Tools for Linux X modules" \
				>> "$LOG"
		"$INSTALL_TOOLS" --install-x-modules \
				"$INSTALL_DIR_TOOLS" \
				"$IBACKUP_DIR" &> >(tee -a "$LOG")
		result=$?
		if [ $result -eq 0 ]; then
			echo "PTfL X modules installation finished successfully"
		else
			echo "PTfL X modules installation failed"
		fi
		;;

	--install-ptiagent)
		date >> "$LOG"
		echo "Starting installation of Parallels Tools Installation Agent" \
				>> "$LOG"
		install_ptiagent
		"$INSTALL_TOOLS" --install-ptiagent \
				"$INSTALL_DIR_TOOLS" \
				"$BACKUP_DIR" &> >(tee -a "$LOG")
		result=$?
		if [ $result -eq 0 ]; then
			echo "PTIAgent installation finished successfully"
		else
			echo "PTIAgent installation failed"
		fi
		;;

	-i | --install | --install-unattended | --force-install | --install-unattended-with-deps)
		[ "x$2" = "x--skip-rclocal-restore" ] && SKIP_RCLOCAL_RESTORE=1 && \
			shift
		[ "x$2" = "x--progress" ] && SHOW_PROGRESS=1 && shift
		[ "x$2" = "x--verbose" ] && VERBOSE=1 && shift
		[ "x$2" = "x--restore-on-fail" ] && RESTORE_ON_FAIL=1

		install_proc
		result=$?
		;;

	-r | --remove)
		remove_proc
		result=$?
		;;

	-v | --version)
		[ -n "$TOOLS_VERSION" ] || exit $E_NOVER
		echo "$TOOLS_VERSION"
		exit $E_NOERROR
		;;

	-h | --help)
		usage
		exit $E_NOERROR
		;;

	*)
		perror "Error: wrong input parameter [$1]"
		echo ""
		usage
		exit $E_WARG
		;;
esac

exit $result
