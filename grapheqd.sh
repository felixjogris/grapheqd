#!/bin/sh

# PROVIDE: grapheqd
# REQUIRE: DAEMON
# KEYWORD: shutdown

# Add the following line to /etc/rc.conf to enable grapheqd:
#
# grapheqd_enable="YES"

. /etc/rc.subr

name="grapheqd"
rcvar="${name}_enable"

load_rc_config "$name"
: ${grapheqd_enable:="NO"}
: ${grapheqd_pidfile:="/var/run/${name}.pid"}
: ${grapheqd_user:="nobody"}

command="/usr/local/sbin/grapheqd"
pidfile="$grapheqd_pidfile"

[ "$pidfile" != "/var/run/grapheqd.pid" ] && command_args="$command_args -p '$pidfile'"

[ -n "$grapheqd_address" ]   && command_args="$command_args -a '$grapheqd_address'"
[ -n "$grapheqd_port" ]      && command_args="$command_args -p '$grapheqd_port'"
[ -n "$grapheqd_raddress" ]  && command_args="$command_args -c '$grapheqd_raddress'"
[ -n "$grapheqd_rport" ]     && command_args="$command_args -r '$grapheqd_rport'"
[ -n "$grapheqd_soundcard" ] && command_args="$command_args -s '$grapheqd_soundcard'"
[ -n "$grapheqd_user" ]      && command_args="$command_args -u '$grapheqd_user'"

$command_args="${command_args# }"

run_rc_command "$1"
