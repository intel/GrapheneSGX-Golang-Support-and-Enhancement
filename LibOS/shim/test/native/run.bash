#! /usr/bin/env bash

set -e
echo "1"
ulimit -c 0
echo "2"
[ "$(ulimit -H -n)" = "unlimited" ] || ulimit -S -n $(ulimit -H -n)
echo "3"
[ "$(ulimit -H -d)" = "unlimited" ] || ulimit -S -d $(ulimit -H -d)
echo "4"
if ulimit -T &> /dev/null; then
    echo "5"
    [ "$(ulimit -H -T)" = "unlimited" ] || ulimit -S -T $(ulimit -H -T)
    echo "6"
fi
echo "7"
