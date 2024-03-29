#!/bin/sh

in="$1"
out="$2"

grep '^[0-9]' "$in" | sort -n | (
    while read nr abi name entry compat; do
	abi=`echo "$abi" | tr '[a-z]' '[A-Z]'`
	if [ "$compat" = "RK" ]; then
	    echo "#ifdef CONFIG_RK"
	    echo "__SYSCALL_${abi}($nr, $entry, $entry)"
	    echo "#endif"
	    continue
	fi

	if [ -n "$compat" ]; then
	    echo "__SYSCALL_${abi}($nr, $entry, $compat)"
	elif [ -n "$entry" ]; then
	    echo "__SYSCALL_${abi}($nr, $entry, $entry)"
	fi
    done
) > "$out"
