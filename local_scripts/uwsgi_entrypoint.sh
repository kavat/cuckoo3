#!/bin/bash

chown cuckoo:cuckoo /home/cuckoo -R

while true; do
  uwsgi --ini /etc/uwsgi/apps-enabled/cuckoo.ini
  sleep 3
done

tail -f /dev/null
