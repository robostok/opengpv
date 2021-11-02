#!/bin/bash

function version_gt() { test "$(echo "$@" | tr " " "\n" | sort -V | head -n 1)" != "$1"; }
function version_le() { test "$(echo "$@" | tr " " "\n" | sort -V | head -n 1)" == "$1"; }
function version_lt() { test "$(echo "$@" | tr " " "\n" | sort -rV | head -n 1)" != "$1"; }
function version_ge() { test "$(echo "$@" | tr " " "\n" | sort -rV | head -n 1)" == "$1"; }

cd $(dirname "${BASH_SOURCE[0]}")

EXP_VER=$(curl -s 'https://raw.githubusercontent.com/robostok/opengpv/main/update.json' | jq -r '.version')

CUR_VER=$(cat ./update.json| jq -r '.version')

echo $EXP_VER
echo $CUR_VER

if version_gt "$EXP_VER" "$CUR_VER"; then
    git reset --hard
    git pull
    pip3 install -r requirements.txt
    sudo service opengpv restart
else
    echo 'No Update Required'
fi
