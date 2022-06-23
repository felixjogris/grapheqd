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
start_precmd="remove_stale_pidfile"

if [ -n "$2" ]; then
  profile="$2"
  if [ -n "$grapheqd_profiles" ]; then
    eval grapheqd_enable="\${grapheqd_${profile}_enable:-${grapheqd_enable}}"
    eval grapheqd_pidfile="\${grapheqd_${profile}_pidfile:-/var/run/${name}.${profile}.pid}"
    eval grapheqd_username="\${grapheqd_${profile}_username:-${grapheqd_username}}"
    eval grapheqd_address="\${grapheqd_${profile}_address:-${grapheqd_address}}"
    eval grapheqd_port="\${grapheqd_${profile}_port:-${grapheqd_port}}"
    eval grapheqd_raddress="\${grapheqd_${profile}_raddress:-${grapheqd_raddress}}"
    eval grapheqd_rport="\${grapheqd_${profile}_rport:-${grapheqd_rport}}"
    eval grapheqd_soundcard="\${grapheqd_${profile}_soundcard:-${grapheqd_soundcard}}"
    eval grapheqd_program="\${grapheqd_${profile}_program:-${grapheqd_program}}"
  else
    echo "$0: extra argument ignored"
  fi
elif [ -n "${grapheqd_profiles}" ]; then
  for profile in ${grapheqd_profiles}; do
    eval _enable="\${grapheqd_${profile}_enable:-${grapheqd_enable}}"
    case "x${_enable}" in
      x[Yy][Ee][Ss])
        ;;
      *)
        continue
    esac
    echo "===> grapheqd profile: ${profile}"
    /usr/local/etc/rc.d/grapheqd "$1" "${profile}"
    retcode="$?"
    if [ "0${retcode}" -ne 0 ]; then
      failed="${profile} (${retcode}) ${failed:-}"
    else
      success="${profile} ${success:-}"
    fi
  done
fi

pidfile="$grapheqd_pidfile"
command_args="-p '$pidfile' -u '$grapheqd_username'"

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
