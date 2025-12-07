#!/bin/bash

adduser cuckoo kvm
chown cuckoo:cuckoo /home/cuckoo -R
chmod 666 /dev/kvm
chmod u+s /usr/lib/qemu/qemu-bridge-helper

tail -f /dev/null
