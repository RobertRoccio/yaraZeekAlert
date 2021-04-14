#!/bin/bash

mkdir extracted-files
mkdir alerted-files
mkdir logs

cp extract-some-files.zeek temp.zeek
INSTALL_DIR=$(pwd)
sed -i 's+INSTALL-DIR+'$INSTALL_DIR'+' temp.zeek
\cp temp.zeek /usr/local/zeek/share/zeek/policy/frameworks/files/extract-some-files.zeek
echo @load frameworks/files/extract-some-files.zeek > /usr/local/zeek/share/zeek/zeekctl/main.zeek
rm temp.zeek