#!/bin/bash

adduser cuckoo kvm
chown cuckoo:cuckoo /home/cuckoo -R
chmod 666 /dev/kvm
chmod u+s /usr/lib/qemu/qemu-bridge-helper

while true; do
  uwsgi --ini /etc/uwsgi/apps-enabled/cuckoo.ini
  sleep 3
done

tail -f /dev/null
