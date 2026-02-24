#!/bin/bash

chown cuckoo:cuckoo /home/cuckoo -R

ip route add 192.168.30.0/24 via 10.5.7.30

while true; do
  uwsgi --ini /etc/uwsgi/apps-enabled/cuckoo.ini
  sleep 3
done

tail -f /dev/null
