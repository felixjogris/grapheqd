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
: ${grapheqd_username:="nobody"}

command="/usr/local/sbin/grapheqd"
pidfile="$grapheqd_pidfile"
command_args="-p '$pidfile' -u '$grapheqd_username'"
start_precmd="remove_stale_pidfile"

if [ -n "$grapheqd_address" ]; then
  command_args="$command_args -a '$grapheqd_address'"
fi
if [ -n "$grapheqd_port" ]; then
  command_args="$command_args -l '$grapheqd_port'"
fi
if [ -n "$grapheqd_raddress" ]; then
  command_args="$command_args -c '$grapheqd_raddress'"
fi
if [ -n "$grapheqd_rport" ]; then
  command_args="$command_args -r '$grapheqd_rport'"
fi
if [ -n "$grapheqd_soundcard" ]; then
  command_args="$command_args -s '$grapheqd_soundcard'"
fi

remove_stale_pidfile() {
  if [ -e "$pidfile" -a -z "$(check_pidfile "$pidfile" "$command")" ]; then
    rm "$pidfile"
  fi
}

run_rc_command "$1"
