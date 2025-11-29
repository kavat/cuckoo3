#!/bin/sh

sleep 10
ip route add 192.168.30.0/24 via 10.5.5.3 || true

exec "$@"
