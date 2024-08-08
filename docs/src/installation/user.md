# User cuckoo

This page lists commands to install and configure cuckoo user used by application.

### User creation

```bash
useradd cuckoo
chsh -s /bin/bash cuckoo
mkdir /home/cuckoo
chown cuckoo:cuckoo /home/cuckoo
```

### Add user to required groups

```bash
adduser cuckoo kvm
adduser www-data cuckoo
chmod 666 /dev/kvm
groupadd pcap
adduser cuckoo pcap
chgrp pcap /usr/bin/tcpdump
```

### Configure apparmor

Guacamole is used to access VM during detonation in order to increase analysis deph.

```bash
setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump
ln -s /etc/apparmor.d/usr.bin.tcpdump /etc/apparmor.d/disable/
apparmor_parser -R /etc/apparmor.d/disable/usr.bin.tcpdump
apparmor_parser -r /etc/apparmor.d/usr.bin.tcpdump
```
