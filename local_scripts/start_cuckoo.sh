#!/bin/bash
chmod 666 /dev/kvm
adduser cuckoo kvm
/opt/venv/bin/vmcloak-qemubridge br0 192.168.30.1/24
chmod u+s /usr/lib/qemu/qemu-bridge-helper
su - cuckoo -c "/opt/venv/bin/cuckoo --debug --cancel-abandoned"
