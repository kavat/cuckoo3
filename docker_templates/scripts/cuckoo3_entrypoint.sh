#!/bin/sh

echo "Check for first configuration"
if [ -f /home/cuckoo/.cuckoo/FIRST_DONE ]; then
  echo "Already done"
else

fi

chmod 666 /dev/kvm
vmcloak-qemubridge br0 192.168.30.1/24

# Abilita forwarding
sysctl -w net.ipv4.ip_forward=1

# Forwarding tra interfacce
iptables -A FORWARD -i eth0 -o br0 -j ACCEPT
iptables -A FORWARD -i br0 -o eth0 -j ACCEPT

# NAT per rete interna
iptables -t nat -A POSTROUTING -s 192.168.30.0/24 -o eth0 -j MASQUERADE

# Avvia il container principale
exec "$@"
