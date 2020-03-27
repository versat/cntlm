#!/bin/bash
#
# defrtaddr.sh: NetworkManager dispatcher script
#
# Assigns the current IP address used as default route to the
# machine's hostname in the hosts file. This is needed for
# proxy-auto-config's myIpAddress() function to work correctly.
#
# This script needs to be executed whenever an interface has been put up
# or down or a connectivity change has occurred.

ACTION="$2"

# Just exit, if this script was not called on the events of interest.
[ "$ACTION" != "connectivity-change" -a "$ACTION" != "up" -a "$ACTION" != "down" ] && exit 0

COMMENT="# Added by $(realpath $0) on"
HOSTS_FILE="/etc/hosts"

# For debugging
test -n "$3" && HOSTS_FILE="$(realpath $3)"

hostname=$(hostname)

# Get interface name of first entry in routing table.
defroute_if=$(cat /proc/net/route | head -n 2 | tail -n 1 | cut -f 1)

if [ -n "$defroute_if" ]; then
    defroute_addr=$(ifconfig "$defroute_if" | grep -o "inet [0-9.]*" | cut -d ' ' -f 2)
fi

# Remove old host line.
sed -i "\%^$COMMENT% d" "$HOSTS_FILE"
sed -i "/$hostname$/ d" "$HOSTS_FILE"

# Add new host line if default route has an address.
if [ -n "$defroute_addr" ]; then
    echo -e "$COMMENT $(date)\n$defroute_addr $hostname" >> "$HOSTS_FILE"
fi

exit 0
