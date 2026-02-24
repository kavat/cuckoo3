#!/bin/bash

PATH_PYTHON3=$(find / -name "python3" 2>/dev/null | grep venv | xargs dirname)

adduser cuckoo kvm
chown cuckoo:cuckoo /home/cuckoo -R
chmod 666 /dev/kvm
chmod u+s /usr/lib/qemu/qemu-bridge-helper
$PATH_PYTHON3/vmcloak-qemubridge br0 192.168.30.1/24

tail -f /dev/null
