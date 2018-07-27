#!/bin/bash
####################################################################################################
# @file install-tools.sh
#
# Perform installation or removal of user space applications and drivers.
#
# @author ayegorov@
# @author owner is alexg@
#
# Copyright (c) 1999-2016 Parallels International GmbH.
# All rights reserved.
# http://www.parallels.com
####################################################################################################

export LANG=C
PATH=${PATH:+$PATH:}/sbin:/bin:/usr/sbin:/usr/bin:/usr/X11R6/bin

BASE_DIR="$(dirname "$0")"
PMANAGER="$BASE_DIR/pm.sh"
DETECT_X_SERVER="$BASE_DIR/detect-xserver.sh"
CONFIGURE_X_SERVER="$BASE_DIR/xserver-config.py"
REGISTER_SERVICE="$BASE_DIR/install-service.sh"
PRLFS_SELINUX="$BASE_DIR/prlfs.te"
PRLVTG_SELINUX="$BASE_DIR/prlvtg.te"
PRLTOOLSD_SELINUX="$BASE_DIR/prltoolsd.te"
PRLTIMESYNC_SELINUX="$BASE_DIR/prltimesync.te"
PRL_TOOLS_INITRAMFS_HOOK="$BASE_DIR/parallels_tools.initramfs-hook"

TOOL_DIR="$2"
PT_LIB_DIR="$TOOL_DIR/../lib"
TOOLS_DIR=""
COMMON_TOOLS_DIR=""

BACKUP_DIR="$3"
XCONF_BACKUP="$BACKUP_DIR/.xconf.info"
TOOLS_BACKUP="$BACKUP_DIR/.tools.list"
PSF_BACKUP="$BACKUP_DIR/.psf"
SLP_BACKUP="$BACKUP_DIR/.${SLP_NAME}.selinux"
TOOLS_ICON="parallels-tools.png"
PRLFS_MANPAGE='mount.prl_fs.8'

ARCH=$(uname -m)

TGZEXT=tar.gz

# Definition of system directories
BIN_DIR="/usr/bin"
SBIN_DIR="/usr/sbin"
INITD_DIR="/etc/init.d"
INIT_DIR="/etc/init"
ICONS_DIR="/usr/share/icons/hicolor"
KERNEL_CONFIG=/boot/config-$(uname -r)
MAN_DIR='/usr/share/man/man8'


# Definition X server configuration variables
XTYPE=""
XVERSION=""
XMODULES_SRC_DIR=""
XMODULES_DIR=""

####################################################################################################
# Definition of X.Org server configuration directories
####################################################################################################

XORG_CONF_DIRS="/etc				 \
		/etc/X11			 \
		/usr/etc			 \
		/usr/etc/X11		 \
		/usr/lib/X11		 \
		/usr/X11R6/etc		 \
		/usr/X11R6/etc/X11	 \
		/usr/X11R6/lib/X11"

XORG_CONF_FILES="xorg.conf xorg.conf-4"

XORG_CONF_DEFAULT="/etc/X11/xorg.conf"

####################################################################################################
# Definition of user space modules
####################################################################################################

TOOLS_X32="prltools"
TOOLS_X64="prltools.x64"

TOOLSD="prltoolsd"
TOOLSD_SERVICE="$BASE_DIR/$TOOLSD.sh"
TOOLSD_ISERVICE="$INITD_DIR/$TOOLSD"
TOOLSD_SD_SERVICE="$TOOLSD.service"        # systemd service file
TOOLSD_JOB="$BASE_DIR/$TOOLSD.conf"        # upstart job config
TOOLSD_INSTALL_JOB="$INIT_DIR/$TOOLSD.conf"

FSMOUNTD='prlfsmountd'

XTOOLS="prl-x11"
XTOOLS_SERVICE="$BASE_DIR/$XTOOLS.sh"
XTOOLS_ISERVICE="$INITD_DIR/$XTOOLS"
XTOOLS_JOB="$BASE_DIR/$XTOOLS.conf"
XTOOLS_INSTALL_JOB="$INIT_DIR/$XTOOLS.conf"
XTOOLS_SD_SERVICE="$XTOOLS.service"
X_EVENT='filesystem'

UTOOLS="prltools_updater"
UTOOLS_SERVICE_INIT="$BASE_DIR/${UTOOLS}_sysv.sh"
UTOOLS_ISERVICE="$INITD_DIR/$UTOOLS"
UTOOLS_JOB="$BASE_DIR/$UTOOLS.conf"
UTOOLS_INSTALL_JOB="$INIT_DIR/$UTOOLS.conf"
UTOOLS_SD_SERVICE="$UTOOLS.service"

CTLCENTER="prlcc"
DNDTOOL="prldnd"
CPTOOL="prlcp"
SGATOOL="prlsga"
TIMESYNCTOOL="prltimesync"

HOSTTIME="prlhosttime"
SHOW_VM_CFG="prl_showvmcfg"
NETTOOL="prl_nettool"
SNAPSHOT_TOOL="prl_snapshot"
SHPROF="prlshprof"
SHPRINT="prlshprint"

XORGFIXER="prl-xorgconf-fixer"
OPENGL_SWITCHER="prl-opengl-switcher.sh"
PRLTOOLS_UPDATER="prltools_updater.sh"
TOOLSD_HBR_FILENAME="99prltoolsd-hibernate"

get_lib_dir() {
	libdirs=
	if [ "$ARCH" = "x86_64" ]; then
		# For 64-bit Debian-based systems 64-bit stuff is placed in /lib and
		# /usr/lib. So need to go through _DIRS32 as well.
		# It should be noted that if the system was updated from 32-bit one
		# this code may not work correctly. But it's not clear how it should
		# work in this case.
		libdirs="/usr/lib64 /usr/lib"
	else
		libdirs="/usr/lib"
	fi
	for libdir in $libdirs; do
		if [ -d "$libdir" ]; then
			echo "$libdir"
			exit $E_NOERR
		fi
	done
	perror "Error: could not find system lib directory"
	exit $E_NOXMODIR
}

LIB_DIR=$(get_lib_dir)
LIB_DIR_X32=

####################################################################################################
# Definition of error codes
####################################################################################################

E_NOERROR=0
E_NOACT=161
E_NODIR=162
E_NOXSERV=163
E_NOXMODIR=164
E_NOXMOD=165
E_NOXCONF=166
E_BFAIL=167
E_IFAIL=168

####################################################################################################
# Show error
####################################################################################################

perror() {
	echo $1 1>&2
}


update_icon_cache()
{
	# mech is taken from host Linux installers
	if type gtk-update-icon-cache > /dev/null 2>&1; then
		ignore_th_index=
		[ -f "$ICONS_DIR/index.theme" ] || ignore_th_index=--ignore-theme-index
		gtk-update-icon-cache $ignore_th_index -fq "$ICONS_DIR" > /dev/null 2>&1
	fi
}

###############################################################################
# Init system related helper functions
###############################################################################

# Check for systemd being main init system.
# Official systemd man suggests this as a reliable check.
# See `sd_booted` documentation on freedesktop.org.
systemd_enabled() {
	[ -d "/run/systemd/system" ]
}

# Check underlying operaion system.for being RHEL/Centos 6.x.
# 6.x have old upstart as init manager, and actually this
# function is an indirect check for this case.
not_rhel6() {
	local major=$(cat /etc/redhat-release 2>/dev/null \
			| rev | cut -d" " -f2 | cut -d. -f2)
	[ "$major" != "6" ]
}

# Check if system has upstart of correct version and all
# necessary directories to install our job files into.
# Old versions and certain OSes are known to have issues,
# and it's safer to fallback on sysv init scripts on such
# systems.
upstart_enabled() {
	/sbin/init --version 2>/dev/null | grep -q upstart \
	    && not_rhel6                                   \
	    && [ -d "/etc/init/" ]
}

####################################################################################################
# Remove user space tools' modules
####################################################################################################

remove_orphaned_files() {
	# In previous versions these files may not be put into TOOLS_BACK
	# log-file correctly. So need to remove them explicitely.
	if [ -e "$UTOOLS_INSTALL_JOB" -o -e "$XTOOLS_INSTALL_JOB" ]; then
		rm -f "$UTOOLS_INSTALL_JOB"
		rm -f "$XTOOLS_INSTALL_JOB"
		type initctl >/dev/null 2>&1 && initctl reload-configuration
	fi
	rm -f "$BIN_DIR/$FSMOUNTD"

	# Some systemd units also might have missed the TOOLS_BACK file,
	# so we need to check for them too.
	rm -f "/usr/lib/systemd/user/${UTOOLS_SD_SERVICE}"

	# On PDFM 11 K20prltoolsd remained in
	# /etc/rc.d/* dirs on systems with systemd,
	# since prtloosd used init compatibility mode,
	# and used to be started by corresponding service
	for rc_level in $(ls -d1 /etc/rc.d/*); do
		rm -f "${rc_level}/K20prltoolsd"
	done
}

remove_tools_modules() {

	skip_xconf_removal=$1

	if [ -e "$TOOLSD_ISERVICE" ]; then
		"$TOOLSD_ISERVICE" stop
		pidfile="/var/run/$TOOLSD.pid"
		if [ -r "$pidfile" ]; then
			# in some versions of tools service there was bug
			# which preveted correct stopping
			# so here is kludge for this situation
			svc_pid=$(< "$pidfile")
			kill $svc_pid
		fi
		if systemd_enabled; then
			systemctl stop "$TOOLSD_SD_SERVICE"
			systemctl disable "$TOOLSD_SD_SERVICE"
		else
			"$REGISTER_SERVICE" --remove "$TOOLSD"
		fi
		rm -f "$TOOLSD_ISERVICE"
	fi

	if [ -e "$XTOOLS_ISERVICE" ]; then
		"$REGISTER_SERVICE" --remove "$XTOOLS"
		rm -f "$XTOOLS_ISERVICE"
	fi

	if [ -e "$UTOOLS_ISERVICE" ]; then
		"$REGISTER_SERVICE" --remove "$UTOOLS"
		rm -f "$UTOOLS_ISERVICE"
	fi

	if systemd_enabled; then
		systemctl stop "$UTOOLS_SD_SERVICE"
		systemctl stop "$XTOOLS_SD_SERVICE"
		systemctl disable "$UTOOLS_SD_SERVICE"
		systemctl disable "$XTOOLS_SD_SERVICE"
	fi

	# kill control all center processes
	for prlcc_pid in $(ps -A -opid,command | grep -v grep | grep "$CTLCENTER\>" | awk '{print $1}'); do
		kill "$prlcc_pid"
	done

	# unload selinux policy
	if [ -e $SLP_BACKUP ]; then
		IFS=$'\n'
		cat "$SLP_BACKUP" | while read mod; do semodule -r $mod; done
		unset IFS
	fi

	#remove shared folder
	mpoint=$(head -n1 $PSF_BACKUP)
	IFS=$'\n'
	cat /proc/mounts | awk '{if ($3 == "prl_fs") print $2}' | \
		while read -r f; do
			mnt_pt=`printf "$f\n"`
			umount "$mnt_pt"
			rmdir "$mnt_pt"
		done
	unset IFS
	umount -at prl_fs
	rmdir "$mpoint"
	# remove fstab entries after tools of version < 9
	sed -i -e 'N;/\n#Parallels.*/d;P;D;' /etc/fstab
	sed -i -e '/prl_fs/d' /etc/fstab

	# delete created links on psf on users desktop
	grep 'Desktop' $PSF_BACKUP | sed 's/\ /\\\ /g' | xargs rm -f

	# Unset parallels OpenGL libraries
	if [ -x "$SBIN_DIR/$OPENGL_SWITCHER" ]; then
		"$SBIN_DIR/$OPENGL_SWITCHER" --off
	else
		echo "Can not find executable OpenGL switching tool by path $opengl_switcher"
	fi

	if [ -e "$TOOLS_BACKUP" ]; then
		echo "Remove tools according to $TOOLS_BACKUP file"
		cat "$TOOLS_BACKUP" | while read line; do
			# Kludge to fix previous buggy backup files on Fedora 19.
			test -f "$line" || line=`echo $line | sed 's/^‘\(.*\)’$/\1/'`
			# Kludge to support case when 64-bit Ubuntu 11.04
			# was updated to 11.10: symlink /usr/lib64 was removed.
			test -f "$line" || line=${line/usr\/lib64/usr\/lib}
			echo " rm $line"
			rm -f "$line"
		done
		rm -f "$TOOLS_BACKUP"
	fi

	# Files from previous versions, which have been forgotten
	# to be added to backup files, and thus remained after
	# tools removal. They are all special cases, and are
	# needed to be removed
	remove_orphaned_files

	# Parallels Tools icon was removed
	# So need to update icon cache
	update_icon_cache

	# Remove directory with extracted prltools.$arch.tar.gz
	# with old modules built for all version of Xorg
	rm -rf "$TOOLS_DIR"

	rmdir '/etc/prltools'

	if [ -n "$skip_xconf_removal" ]; then
		echo "Removing of X server configuration is skipped."
		# we also should not delete directory with tools case backups are stored there
		return 0
	fi

	if [ -e "$XCONF_BACKUP" ]; then
		echo "Restore X server configuration file according to $XCONF_BACKUP"
		. "$XCONF_BACKUP"
		if [ -z "$BACKUP_XBCONF" ]; then
			[ -e "$BACKUP_XCONF" ] && rm -f "$BACKUP_XCONF"
		else
			[ -e "$BACKUP_XBCONF" ] && mv -f "$BACKUP_XBCONF" "$BACKUP_XCONF"
		fi
		# Now we do not remove "evdev_drv.so" driver, but previously we could do this.
		# Thus, leave this string for compatibility with previous versions of Guest Tools.
		[ -e "$BACKUP_XBEVDEV" ] && mv -f "$BACKUP_XBEVDEV" "$BACKUP_XEVDEV"
		rm -f "$XCONF_BACKUP"
	fi

	# Attempt to remove INITD_DIR, as it may have been
	# created by our installer (in case of Arch/Manjaro)
	rmdir "$INITD_DIR" --ignore-fail-on-non-empty

	# Per-user cleanup actions:
	for d in $(awk -F: '{print $6}' /etc/passwd); do
		# Restore configuration of users directories after
		# Shared Profile changes.
		for f in user-dirs.dirs gtk-bookmarks; do
			cfg=${d}/.parallels/${f}
			bkp=${cfg}.orig
			if [ -r "$bkp" -a -L "$cfg" ]; then
				cp -f "$bkp" "$cfg"
				rm -f "$cfg" "$bkp"
			fi
		done

		# Cleanup custom monitors configs of dynamic resolution tool.
		rm -f "${d}/.config/monitors.xml"
	done
}


####################################################################################################
# Install user space tools' modules
####################################################################################################

check_x_server_version() {
	XVERSION=$("$DETECT_X_SERVER" -v)
	if [ $? -ne $E_NOERROR ]; then
		XVERSION="6.7"
		return $E_NOXSERV
	fi
	echo $XVERSION
	return $E_NOERROR
}

get_x_server_version() {
	XTYPE="xorg"
	XVERSION=$(check_x_server_version)
	[ $? -ne $E_NOERROR ] && return $E_NOXSERV
	echo "X server: $XTYPE, Version: $XVERSION"
	XMODULES_SRC_DIR=$("$DETECT_X_SERVER" -dsrc "$TOOLS_DIR")
	if [ $? -eq $E_NOERROR ]; then
		echo "System X modules are installing from $XMODULES_SRC_DIR"
	else
		return $E_NOXMODIR
	fi

	XMODULES_DIR=$("$DETECT_X_SERVER" -d)
	if [ $? -eq $E_NOERROR ]; then
		echo "System X modules are placed in $XMODULES_DIR"
	else
		return $E_NOXMODIR
	fi
	return $E_NOERROR
}


get_x_server_version_num() {
	vmajor=$(echo $XVERSION | awk -F . '{ printf "%s", $1 }')
	vminor=$(echo $XVERSION | awk -F . '{ printf "%s", $2 }')
	vpatch=$(echo $XVERSION | awk -F . '{ printf "%s", $3 }')

	if [ "$vmajor" -ge "6" ]; then
	# Must discount major version,
	# because XOrg changes versioning logic since 7.3 (7.3 -> 1.3)
		vmajor=$(($vmajor - 6))
	fi

	v=$(($vmajor*1000000 + $vminor*1000))
	if [ -n "$vpatch" ]; then
		v=$(($v + $vpatch))
	fi
	echo $v
}


# Prints path to X11 configuration file
find_xorgconf() {
	# Starting from Xorg 1.15 all config files should be stored
	# in another place:
	local v=$(get_x_server_version_num)
	if [ $v -ge 1005000 ]; then
		local d='/usr/share/X11/xorg.conf.d'
		if [ -d "$d" ]; then
			echo "$d/40-prltools.conf"
			return
		fi
	fi

	xdir=""
	xcfg=""

	# Search through all possible directories and X server configuration file
	for dir in $XORG_CONF_DIRS; do
		for file in $XORG_CONF_FILES; do
			if [ -e "$dir/$file" ]; then
				xdir="$dir"
				xcfg="$file"
				break 2
			fi
		done
	done

	if ([ -n "$xdir" ] && [ -n "$xcfg" ]); then
		echo "$xdir/$xcfg"
	else
		echo "$XORG_CONF_DEFAULT"
	fi
}

configure_x_server() {

	xconf=`find_xorgconf`
	xbconf=''
	if [ -f "$xconf" ]; then
		xbconf="$BACKUP_DIR/.${xconf##*/}"
		cp -f "$xconf" "$xbconf"

		echo "X server config: $xconf"
	else
		# X server config doesn't exist
		# So value of xbconf will be empty
		echo "X server config: $xconf (doesn't exist)"
	fi

	# ... and save information about X server configuration files
	echo "BACKUP_XCONF=$xconf"	>>	"$XCONF_BACKUP"
	echo "BACKUP_XBCONF=$xbconf"	>>	"$XCONF_BACKUP"

	# Fedora since 25 doesn't ship python2 at all
	# python command is also absent, python3 is the only option
	if type python3 2>/dev/null; then
		python3 "$CONFIGURE_X_SERVER" "$XTYPE" "$XVERSION" "$xbconf" "$xconf"
	else
		python "$CONFIGURE_X_SERVER" "$XTYPE" "$XVERSION" "$xbconf" "$xconf"
	fi
	if [ "x$?" != "x0" ]; then
		cp -f "$xbconf" "$xconf"
		return 1
	fi
}

install_file() {
	local src=$1
	local dst=$2
	[ -d "$dst" ] && dst="${dst}/${src##*/}"
	cp -vf "$src" "$dst" && echo "$dst" >>"$TOOLS_BACKUP"
}

install_symlink() {
	local src=$1
	local lnk=$2
	[ -d "$link" ] && lnk="${lnk}/${src##*/}"
	ln -svf "$src" "$lnk" && echo "$lnk" >>"$TOOLS_BACKUP"
}

install_x_modules() {
	xmod="$1/x-server/modules"

	# Link X modules for 6.7 and 6.8 versions of X.Org server
	if ([ "x$XVERSION" = "x6.7" ] || [ "x$XVERSION" = "x6.8" ]); then
		if [ "$ARCH" != "x86_64" ]; then
			xlib="$TOOLS_DIR/lib"
			vdrv="prlvideo_drv"
			xvideo="$xmod/drivers/$vdrv"
			mdrv="prlmouse_drv"
			xmouse="$xmod/input/$mdrv"

			gcc -shared "$xvideo.o" "$xlib/libTISGuest.a" "$xlib/libOTGGuest.a" "$xlib/libBitbox.a" \
				-L"$XMODULES_DIR" -lvbe -lddc -lint10 -lramdac -lfb \
				-Wl,-z -Wl,now -Wl,-soname -Wl,"$vdrv.so" -o "$xvideo.so"

			result=$?
			[ $result -ne $E_NOERROR ] && return $result

			install_file "$xvideo.so" "$XMODULES_DIR/drivers" && rm -f "$xvideo.so"

			gcc -shared "$xmouse.o" "$xlib/libTISGuest.a" "$xlib/libOTGGuest.a" "$xlib/libBitbox.a" \
				-Wl,-z -Wl,now -Wl,-soname -Wl,"$mdrv.so" -o "$xmouse.so"

			result=$?
			[ $result -ne $E_NOERROR ] && return $result

			install_file "$xmouse.so" "$XMODULES_DIR/input" && rm -f "$xmouse.so"
		else
			xlib="$TOOLS_DIR/lib"
			vdrv="prlvideo_drv"
			xvideo="$xmod/drivers/$vdrv"
			mdrv="prlmouse_drv"
			xmouse="$xmod/input/$mdrv"

			gcc -r "$xvideo.o" -nostdlib -o "$xvideo-out.o"

			result=$?
			[ $result -ne $E_NOERROR ] && return $result

			install_file "$xvideo-out.o" "$XMODULES_DIR/drivers/$vdrv.o" &&
				rm -f "$xvideo-out.o"

			gcc -r "$xmouse.o" "$xlib/libTISGuest_nopic.a" "$xlib/libOTGGuest_nopic.a" "$xlib/libBitbox_nopic.a" \
				-nostdlib -o "$xmouse-out.o"

			result=$?
			[ $result -ne $E_NOERROR ] && return $result

			install_file "$xmouse-out.o" "$XMODULES_DIR/input/$mdrv.o" &&
				rm -f "$xmouse-out.o"
		fi
	else
		for f in 'input/prlmouse_drv.so' 'drivers/prlvideo_drv.so'; do
			install_file "${xmod}/${f}" "${XMODULES_DIR}/${f}"
		done
	fi
}

apply_x_modules_fixes() {
	v=$(get_x_server_version_num)
	# Starting from XServer 1.4 we are must configure udev,
	# in this purposes we will setup hall/udev rules

	if [ "$v" -ge "1004000" ]; then
	# Configuring udev via hal scripts

		hal_other="/usr/share/hal/fdi/policy/20thirdparty"
		x11prl="x11-parallels.fdi"

		# Let's set this level, why not!
		level=20
		install_file "$TOOL_DIR/$x11prl" "$hal_other/$level-$x11prl"
	fi

	if [ "$v" -ge "1007000" ]; then
	# Configuring udev via rules

		udev_dir="/lib/udev/rules.d"
		xorgprlmouse="xorg-prlmouse.rules"
		level=69
		install_file "$TOOL_DIR/$xorgprlmouse" "$udev_dir/$level-$xorgprlmouse"

		xorgprlmouse="prlmouse.conf"
		level=90
		udev_dir="/usr/lib/X11/xorg.conf.d"
		if test -d "$udev_dir"; then
			install_file "$TOOL_DIR/$xorgprlmouse" "$udev_dir/$level-$xorgprlmouse"
		fi
		udev_dir="/usr/lib64/X11/xorg.conf.d"
		if test -d "$udev_dir"; then
			install_file "$TOOL_DIR/$xorgprlmouse" "$udev_dir/$level-$xorgprlmouse"
		fi
		udev_dir="/usr/share/X11/xorg.conf.d"
		if test -d "$udev_dir"; then
			install_file "$TOOL_DIR/$xorgprlmouse" "$udev_dir/$level-$xorgprlmouse"
		fi
		udev_dir="/etc/X11/xorg.conf.d"
		if test -d "$udev_dir"; then
			install_file "$TOOL_DIR/$xorgprlmouse" "$udev_dir/$level-$xorgprlmouse"
		fi
	fi
}

# Set driver for our device 1ab8:4005 to "prl_tg" if it is "unknown"
# This is to make kudzu happy and not repatch xorg.conf
fix_hwconf() {

	hwconf_file='/etc/sysconfig/hwconf'

	test -r "$hwconf_file" || return

	hwconf_file_content=`< "$hwconf_file"`
	test -z "$hwconf_file_content" && return

	echo "$hwconf_file_content" | awk '
	{
		if ($0 == "-")
		{
			if (NR > 1)
			{
				# One section is already read. Dump it.
				for (i = 0;  i < idx; ++i)
					print items[i]
			}

			# Start reading section
			idx = 0
			class = ""
			device_id = ""
			vendor_id = ""
			driver = ""
			driver_idx = 0
		}
		else
		if ($1 == "class:")
			class = $2
		else
		if ($1 == "vendorId:")
			vendor_id = $2
		else
		if ($1 == "deviceId:")
			device_id = $2
		else
		if ($1 == "driver:")
		{
			driver = $2
			driver_idx = idx
		}

		if (class == "VIDEO" && vendor_id == "1ab8" && device_id == "4005" && driver == "unknown")
		{
			# Section for our video device! Replace driver to prl_tg
			items[driver_idx] = "driver: prl_tg"
			class = ""
		}

		# Appeding item to currect section
		items[idx] = $0
		++idx
	}

	END {

		# Dumping the very last section
		for (i = 0;  i < idx; ++i)
			print items[i]

	}' > "$hwconf_file"
}

# Setup launcher into users's session in all available DEs
# $1 - path to launcher .desktop-file
setup_session_launcher() {

	autostart_paths="/etc/xdg/autostart
/usr/share/autostart
/usr/share/gnome/autostart
/usr/local/share/autostart
/usr/local/share/gnome/autostart
/opt/gnome/share/autostart
/opt/kde/share/autostart
/opt/kde3/share/autostart
/opt/kde4/share/autostart"

	# Try to use kde-config for KDE if available
	if type kde-config >/dev/null 2>&1; then
		kde_autostart_path="`kde-config --prefix`/share/autostart"
		if ! echo $autostart_paths | grep -q "\<$kde_autostart_paths\>"; then
			autostart_paths="$autostart_paths
$kde_autostart_paths"
		fi
	fi

	symlink_name="${1##*/}"
	for autostart_path in $autostart_paths; do
		if [ -d "$autostart_path" ]; then
			install_symlink "$1" "${autostart_path}/${symlink_name}"
		fi
	done
}

install_cpuhotplug_rules()
{
	. "$PMANAGER" >/dev/null 2>&1
	os_name=$(detect_os_name)
	os_version=$(detect_os_version $os_name)
	dst_cpuhotplug_rules="/etc/udev/rules.d/99-parallels-cpu-hotplug.rules"
	os_version=`echo $os_version |	sed 's+.*\.++g'`
	if [ "$os_name" = "redhat" ] && [ "$os_version" -le "5" ]; then
		if [ -r "$KERNEL_CONFIG" ]; then
			cat "$KERNEL_CONFIG" | grep -q "^CONFIG_HOTPLUG_CPU=y"
			[ $? -eq 0 ] && cp -vf "$TOOL_DIR/parallels-cpu-hotplug.rules" "$dst_cpuhotplug_rules"
		fi
	fi
}


install_memory_hotplug_rules()
{
	mem_rule="parallels-memory-hotplug.rules"
	dst_mem_rule="/etc/udev/rules.d/99-$mem_rule"
	grep -qs '^CONFIG_MEMORY_HOTPLUG=y' "$KERNEL_CONFIG" &&
		install_file "$TOOL_DIR/$mem_rule" "$dst_mem_rule"
}


# Updates boot loader configuration
# Current implementation provides only one simple thing:
#  it finds all kernels that don't have 'divider' option
#  and adds 'divider=10' to them.
# Implementation is targeted only for RHEL/CentOS 5.x family.
update_grubconf()
{
	echo "Going to update boot loader cofiguration..."
	grubby_util=/sbin/grubby
	if [ ! -x "$grubby_util" ]; then
		perror "grubby not found"
		return 1
	fi

	grub_conf=/boot/grub/grub.conf
	if [ ! -r "$grub_conf" ]; then
		perror "Cannot find loader conf at path '$grub_conf'"
		return 1
	fi

	grep '^\s*kernel' "$grub_conf" | grep -v divider= | \
		awk '{print $2}' | \
		while read kern; do
			kern="/boot${kern##/boot}"
			[ -f "$kern" ] || continue
			echo " * $kern"
			"$grubby_util" --update-kernel="$kern" --args=divider=10
		done
}

install_selinux_module_make() {
	local makefile="/usr/share/selinux/devel/Makefile"
	local policy=$1
	local bin_path="$2"
	local mod_name=${policy##*/}; mod_name=${mod_name%.*}

	[ ! -f $makefile ] && return 1

	local tempdir=`mktemp -d /tmp/XXXXXX-parallels-tools-selinux`
	[ -z "$tempdir" -o ! -d "$tempdir" ] && return 1

	cp "$policy" "$tempdir"
	cp "${policy%.*}.fc" "$tempdir"
	pushd "$tempdir"
	make -f $makefile ${mod_name}.pp
	popd
	local mod_pkg="$tempdir/${mod_name}.pp"
	[ -e "$mod_pkg" ]                           \
		&& semodule -i "$mod_pkg"           \
		&& restorecon "$bin_path"           \
		&& echo "$mod_name" >>"$SLP_BACKUP"
	local ret_code=$?
	rm -rf "$tempdir"
	return $ret_code
}

install_selinux_module() {
	local policy=$1
	local mod_name=${policy##*/}; mod_name=${mod_name%.*}
	local bin_policy="$TOOLS_DIR/${mod_name}.mod"
	local mod_pkg="$TOOLS_DIR/${mod_name}.pp"

	# Check if SELinux stuff is available
	type checkmodule >/dev/null 2>&1 || return 1

	# Build and install module package
	checkmodule -m -M "$policy" -o "$bin_policy"
	[ -e "$bin_policy" ] && semodule_package -m "$bin_policy" -o "$mod_pkg"
	[ -e "$mod_pkg" ] && semodule -i "$mod_pkg" && \
		echo "$mod_name" >>"$SLP_BACKUP" && return 0
	return 1
}

install_compiz_plugin() {
	local compizdir_target="$LIB_DIR/compiz"
	if ! [ -d "$compizdir_target" ]; then
		echo "Can't find compiz lib dir, skipping compiz pluing install"
		return
	fi
	# Copy from main directory
	local compizdir="$TOOLS_DIR/lib/compiz"
	for lib in "$compizdir"/* ; do
		[ -d "$lib" ] && continue # it's a dir, not a file
		local libname=${lib##*/}
		install_file "$lib" "$compizdir_target/$libname"
	done

	if ! [ -e /etc/os-release ]; then
		# this is not Ubuntu 15.10, 16.04 or 16.10,
		# thus we skip this step, since we have
		# special plugin versions only for them
		return
	fi
	local release=$(awk -F= '/PRETTY_NAME/ { print $2 }' \
			/etc/os-release | tr -d '"')
	# Copy from tagged sub directories
	for dir in "$compizdir/"*; do
		[ -d "$dir" ] || continue
		# check if dir name is prefix of release, e.g.
		# "Ubuntu 16.04" is prefix of "Ubuntu 16.04.1 LTS",
		# with the latter being PRETTY_NAME of the release
		# and the former our directory with needed compiz
		# plugin libraries
		[[ "$release" = "${dir##*/}"* ]] || continue
		for lib in "$dir"/* ; do
			install_file "$lib" "$compizdir_target/${lib##*/}"
 		done
		break
	done
}

install_gnome_coherence_extension() {
	local ext_dir="/usr/share/gnome-shell/extensions"
	if ! [[ -d "$ext_dir" ]]; then
		echo "Cant't find Gnome Shell extensions dir, skipping plugin install"
		return $E_NOERROR
	fi

	local ext_name="coherence-gnome-shell@parallels.com"
	local dest_path="$ext_dir/$ext_name"
	mkdir -p "$dest_path"

	local src_path="$TOOL_DIR/gnome-coherence"
	local src_files="extension.js metadata.json stylesheet.css"
	for f in $src_files; do
		if ! install_file "$src_path"/"$f" "$dest_path"; then
			perror "Failed to install file $src_path/$f"
			return $E_IFAIL
		fi
	done
}

install_and_configure_x() {
	local skip_xconf=$1

	get_x_server_version
	local result=$?
	if [ $result -ne $E_NOERROR ]; then
		perror "Failed to detect X server version"
		return $result
	fi

	if [ -z $skip_xconf ]; then
		configure_x_server
		result=$?
		if [ $result -ne $E_NOERROR ]; then
			perror "Error: could not configure X server"
			return $result
		fi
	else
		echo "X server configuration was skipped"
	fi

	install_x_modules $XMODULES_SRC_DIR
	result=$?
	if [ $result -ne $E_NOERROR ]; then
		perror "Error: could not install X modules"
		return $result
	fi

	apply_x_modules_fixes
	fix_hwconf

	install_compiz_plugin

	# Here we install and enable gnome coherence
	# extension. We enable it system-wide, for every
	# user who launches gnome shell session.
	install_gnome_coherence_extension
	result=$?
	if [ $result -ne $E_NOERROR ]; then
		perror "Fatal error during Gnome Coherence extension installation"
		return $result
	fi

	setup_session_launcher "${TOOL_DIR}/prlcc.desktop"

	# we need to force reloading of the udev rules and
	# reinitialization of devices in order to make X server
	# able to use correct driver for our mouse
	if type udevadm >/dev/null 2>&1; then
		udevadm control --reload-rules && udevadm trigger
		echo "udevadm exited with status $?"
	fi

	if [ -d "$ICONS_DIR" ]; then
		icon="$TOOL_DIR/$TOOLS_ICON"
		icon_target="$ICONS_DIR/48x48/apps/$TOOLS_ICON"
		if [ -e "$icon" ]; then
			install_file "$icon" "$icon_target"
		fi
		update_icon_cache
	fi

	return 0
}

install_tools_modules() {

	skip_xconf=$1

	mkdir -p "$TOOLS_DIR"

	# Unpack user space modules
	tar -xzf "$TOOLS_DIR.$TGZEXT" -C "$TOOLS_DIR"


	# Check XServer version, and is there requires version of X modules?
	get_x_server_version
	result=$?

	if [ $result -eq $E_NOERROR ]; then
		install_and_configure_x $skip_xconf
		result=$?
		if [ $result -ne $E_NOERROR ]; then
			return $result
		fi
	else
		echo "Skip X server configuration and installation of X modules"
	fi

	#prepare for shared folders features using
	if [ -d /media ]; then
		mpoint="/media/psf"
	else
		mpoint="/mnt/psf"
	fi

	echo "$mpoint" > "$PSF_BACKUP"

	mkdir -p "$mpoint"
	if [ -d "$mpoint" ]; then
		chmod 0555 "$mpoint"
		install_selinux_module "$PRLFS_SELINUX"

		# add shared mount point to fstab
		for i in $(awk -F: '{print $6}' /etc/passwd); do
			if [ -d "$i"/Desktop ]; then
				link_name="$i/Desktop/Parallels Shared Folders"
				install_symlink "$mpoint" "$link_name"
			fi
		done
	fi

	install_selinux_module "$PRLVTG_SELINUX"

	# Install time sync tool
	timesync="$COMMON_TOOLS_DIR/usr/bin/$TIMESYNCTOOL"
	install_file "$timesync" "$BIN_DIR/$TIMESYNCTOOL"
	# prltoolsd's SELinux module will need types defined for prltimesync, so
	# we must install timesync SELinux module before prltoolsd's one
	install_selinux_module_make "$PRLTIMESYNC_SELINUX" "$BIN_DIR/$TIMESYNCTOOL"

	# Install tools' service
	mkdir -p "$PT_LIB_DIR" "$INITD_DIR"
	install_file "$TOOLS_DIR/bin/$TOOLSD" "$BIN_DIR/$TOOLSD"
	cp -f "$TOOLSD_SERVICE" "$TOOLSD_ISERVICE"

	if systemd_enabled; then
		install_file "$BASE_DIR/$TOOLSD_SD_SERVICE" '/etc/systemd/system/' &&
			systemctl enable "$TOOLSD_SD_SERVICE"
	elif upstart_enabled; then
		install_file "$TOOLSD_JOB" "$TOOLSD_INSTALL_JOB"
		initctl reload-configuration
	else
		"$REGISTER_SERVICE" --install "$TOOLSD"
	fi

	result=$?
	[ $result -ne $E_NOERROR ] && return $result

	# Exclude ne2k-pci module from initramfs image on Debian-based systems
	if type update-initramfs > /dev/null 2>&1; then
		initramfs_hooks_dir=/usr/share/initramfs-tools/hooks
		prl_tools_initramfs_hook_target="$initramfs_hooks_dir/parallels_tools"
		[ -d "$initramfs_hooks_dir" ] &&
			install_file "$PRL_TOOLS_INITRAMFS_HOOK" "$prl_tools_initramfs_hook_target"
		update-initramfs -u
	fi

	# Install Parallels Shared Folders automount daemon
	fsmountd_src="$TOOL_DIR/$FSMOUNTD.sh"
	fsmountd_dst="$BIN_DIR/$FSMOUNTD"
	install_file "$fsmountd_src" "$fsmountd_dst"

	install_selinux_module_make "$PRLTOOLSD_SELINUX" "$BIN_DIR/$TOOLSD"
	# prltoolsd accesses this directory during startup
	# and this should be permitted by SELinux
	local installer_dir="${TOOL_DIR}/../installer"
	if type semanage; then
		semanage fcontext -a -t lib_t "${installer_dir}(/.*)?"
		restorecon -RFv "$installer_dir"
	else
		echo "Warning: no semanage found in system"
		echo "Not changing type for ${installer_dir}."
	fi

	# Install prl-x11 service
	cp -f "$XTOOLS_SERVICE" "$XTOOLS_ISERVICE"
	# Install prl_updater service for sysV or systemd or upstart
	if systemd_enabled; then
		install_file "$BASE_DIR/$UTOOLS_SD_SERVICE" '/etc/systemd/system/' &&
			systemctl enable "$UTOOLS_SD_SERVICE"
		install_file "$BASE_DIR/$XTOOLS_SD_SERVICE" '/etc/systemd/system/' &&
			systemctl enable "$XTOOLS_SD_SERVICE"
	elif upstart_enabled; then
		install_file "$UTOOLS_JOB" "$UTOOLS_INSTALL_JOB" &&
			initctl reload-configuration
	else
		cp -f "$UTOOLS_SERVICE_INIT" "$UTOOLS_ISERVICE" && "$REGISTER_SERVICE" --install "$UTOOLS"
	fi
	# Check if any upstart services emits 'starting-dm' event
	# and use parallels upstart service to start prl-x11 before X service
	# In other cases use chkconfig service that starts in the beginning
	# of startup. Upstart service was implemented only for Ubuntu yet
	[ -d "$INIT_DIR" ] && grep -q -r "$X_EVENT" "$INIT_DIR" &&
		install_file "$XTOOLS_JOB" "$XTOOLS_INSTALL_JOB" ||
				"$REGISTER_SERVICE" --install "$XTOOLS"

	# Install Parallels Control Center
	# It is built with xorg-7.1 only
	ctlcenter="$COMMON_TOOLS_DIR/usr/bin/$CTLCENTER"
	install_file "$ctlcenter" "$BIN_DIR/$CTLCENTER"

	# and just the same for DnD tool
	dndtool="$COMMON_TOOLS_DIR/usr/bin/$DNDTOOL"
	install_file "$dndtool" "$BIN_DIR/$DNDTOOL"

	# and CP tool as well
	cptool="$COMMON_TOOLS_DIR/usr/bin/$CPTOOL"
	install_file "$cptool" "$BIN_DIR/$CPTOOL"

	# and don't forget brand new SGA
	sgatool="$COMMON_TOOLS_DIR/usr/bin/$SGATOOL"
	install_file "$sgatool" "$BIN_DIR/$SGATOOL"

	# Install host time utility
	hostime="$TOOLS_DIR/bin/$HOSTTIME"
	install_file "$hostime" "$BIN_DIR/$HOSTTIME"

	# Install istatus utility
	show_vm_cfg="$TOOLS_DIR/bin/$SHOW_VM_CFG"
	install_file "$show_vm_cfg" "$BIN_DIR/$SHOW_VM_CFG"

	# Install network tool utility
	nettool="$TOOLS_DIR/sbin/$NETTOOL"
	install_file "$nettool" "$SBIN_DIR/$NETTOOL"

	# Install utility for smoof filesystems backup
	snap_tool="$TOOLS_DIR/sbin/$SNAPSHOT_TOOL"
	install_file "$snap_tool" "$SBIN_DIR/$SNAPSHOT_TOOL"

	# Install shared profile tool
	shprof="$TOOLS_DIR/bin/$SHPROF"
	install_file "$shprof" "$BIN_DIR/$SHPROF"

	# Install shared printers tool
	shprint="$TOOLS_DIR/bin/$SHPRINT"
	install_file "$shprint" "$BIN_DIR/$SHPRINT"

	# Install xorg.conf fixer
	xorgfix="$TOOLS_DIR/sbin/$XORGFIXER"
	install_file "$xorgfix" "$SBIN_DIR/$XORGFIXER"

	# Install OpenGL switcher
	openglsw="$TOOLS_DIR/sbin/$OPENGL_SWITCHER"
	install_file "$openglsw" "$SBIN_DIR/$OPENGL_SWITCHER"

	# Install Parallels Tools updater
	prltoolsup="$TOOLS_DIR/sbin/$PRLTOOLS_UPDATER"
	install_file "$prltoolsup" "$SBIN_DIR/$PRLTOOLS_UPDATER"

	# Man-page for prl_fs
	manpage="$TOOL_DIR/$PRLFS_MANPAGE"
	if [ -d "$MAN_DIR" ]; then
		install_file "$manpage" "$MAN_DIR/$PRLFS_MANPAGE"
	fi

	# For RHEL/CentOS 5.x we need to add special kernel option
	release_file=/etc/redhat-release
	if [ -r "$release_file" ] && \
	   [ `rpm -qf "$release_file" | sed -e "s/.*release-\([0-9]*\).*/\1/g"` -eq 5 ]
	then
		update_grubconf
		rc=$?
		[ $rc -ne 0 ] && perror "Error: failed to update grub.conf"
	fi

	toolsd_hibernate="$TOOL_DIR/$TOOLSD_HBR_FILENAME"
	install_file "$toolsd_hibernate" "/etc/pm/sleep.d/$TOOLSD_HBR_FILENAME"

	install_cpuhotplug_rules
	install_memory_hotplug_rules

	[ "$ARCH" = 'x86_64' ] && arch_suffix=64 || arch_suffix=32
	ptiagent_cmd_symlink="$BIN_DIR/ptiagent-cmd"
	install_symlink \
			"$TOOL_DIR/../installer/iagent$arch_suffix/parallels-wrapper" \
			"$ptiagent_cmd_symlink"
	install_ptiagent

	return $E_NOERROR
}

install_ptiagent()
{
	local ptiagent_starter="$TOOL_DIR/../install-gui"
	local ptiagent_symlink="$BIN_DIR/ptiagent"
	install_symlink "$ptiagent_starter" "$ptiagent_symlink"

	setup_session_launcher "${TOOL_DIR}/ptiagent.desktop"
}

####################################################################################################
# Start installation or removal of user space applications and drivers
####################################################################################################

set_tools_dirs()
{
	# Check directory with tool's modules
	if [ -n "$TOOL_DIR" ]; then
		if [ "$ARCH" = "x86_64" ]; then
			TOOLS_DIR="$TOOL_DIR/$TOOLS_X64"
		else
			TOOLS_DIR="$TOOL_DIR/$TOOLS_X32"
		fi
		COMMON_TOOLS_DIR="$TOOLS_DIR/xorg.7.1"
	else
		perror "Error: directory with tools modules was not specified"
		exit $E_NODIR
	fi
}

case "$1" in
	--install-x-modules)
		set_tools_dirs
		install_and_configure_x
		exit $?
		;;

	--install-ptiagent)
		set_tools_dirs
		install_ptiagent
		exit $?
		;;

	-i | --install | --install-skip-xconf | -r | --remove | --remove-skip-xconf)
		set_tools_dirs

		# Check backup directory
		if [ -z "$BACKUP_DIR" ]; then
			perror "Error: backup directory was not specified"
			exit $E_NODIR
		fi

		skip_xconf=
		if ([ "$1" = "-i" ] || [ "$1" = "--install" ] || [ "$1" = "--install-skip-xconf" ]); then
			act="install"
			sact="installation"
			fact="Installation"
			test "$1" = "--install-skip-xconf" && skip_xconf=1
		else
			act="remove"
			sact="removal"
			fact="Removal"
			test "$1" = "--remove-skip-xconf" && skip_xconf=1
		fi

		echo "Start $sact of user space modules"

		${act}_tools_modules $skip_xconf
		result=$?

		if [ $result -eq $E_NOERROR ]; then
			echo "$fact of user space applications and drivers was finished successfully"
		else
			perror "Error: failed to $act user space applications and drivers"
		fi

		exit $result
		;;

	--check-xconf-patched)
		# Check weather xorg.conf is already patched by PT installer or not yet
		check_x_server_version >/dev/null
		rc=$?
		if [ $rc -ne $E_NOERROR ]; then
			echo "Xorg was not found"
			exit $rc
		fi
		xconf=`find_xorgconf`

		# Will return false if there's no info about xorg.conf backup _and_ there's no prlmouse entry
		[ -f "$XCONF_BACKUP" ] || grep -qs '^\W*Driver\W+"prlmouse"' "$xconf" || exit $E_BFAIL

		# Bug in case of presense of smth metioned above - consider xorg.conf is patched
		exit $E_NOERROR
		;;
esac

exit $E_NOACT
