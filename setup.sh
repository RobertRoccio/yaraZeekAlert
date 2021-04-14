#!/bin/bash

mkdir extracted-files
mkdir alerted-files
mkdir logs

INSTALL_DIR=$(pwd)
sed -i 's+INSTALL-DIR+$INSTALL_DIR+'
cp extract-some-files.zeek /usr/local/zeek/share/zeek/policy/frameworks/files/
echo @load frameworks/files/extract-some-files.zeek > /usr/local/zeek/share/zeek/zeekctl/main.zeek