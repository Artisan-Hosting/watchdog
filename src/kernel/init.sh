# /usr/share/initramfs-tools/scripts/init-top/awdog-manager

#!/bin/sh
PREREQ=""
prereqs() { echo "$PREREQ"; }
case $1 in
  prereqs) prereqs; exit 0 ;;
esac

# Start the manager early (statically linked preferred)
# Ensure awdog.ko is built-in or insmod here, then start the userspace
[ -x /usr/sbin/awdog_client ] && /usr/sbin/awdog_client &
