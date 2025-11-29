#!/bin/bash
chmod 666 /dev/kvm
adduser cuckoo kvm
/opt/cuckoo3/venv/bin/vmcloak-qemubridge br0 192.168.30.1/24
chmod u+s /usr/lib/qemu/qemu-bridge-helper
su - cuckoo -c "/opt/cuckoo3/venv/bin/cuckoo --debug --cancel-abandoned"
