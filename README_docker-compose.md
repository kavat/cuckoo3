Cuckoo3
=======

Dockerization for Cuckoo3 Sandbox

Dependencies
------------

* Docker
* Docker compose
* At least GB required for HD (minimum 20)
* Access to host /dev/kvm device

Starting services
-----------------

Simple docker compose start command creates architecture

```
docker-compose up -d --remove-orphans
```

First configuration
-------------------

* Vmcloak

```
docker exec -it cuckoo3-core /bin/bash
mkdir /mnt/win10x64
/opt/venv/bin/vmcloak isodownload --win10x64 --download-to /home/cuckoo/win10x64.iso
chown cuckoo /home/cuckoo -R
mount -o loop,ro /home/cuckoo/win10x64.iso /mnt/win10x64
/opt/venv/bin/vmcloak-qemubridge br0 192.168.30.1/24
mkdir -p /etc/qemu
echo 'allow br0' | tee /etc/qemu/bridge.conf
chmod u+s /usr/lib/qemu/qemu-bridge-helper
su - cuckoo
/opt/venv/bin/vmcloak --debug init --win10x64 --hddsize 128 --cpus 2 --ramsize 4096 --network 192.168.30.0/24 --vm qemu --ip 192.168.30.2 --iso-mount /mnt/win10x64 win10base br0
/opt/venv/bin/vmcloak --debug install win10base dotnet:4.7.2 java:8u151 vcredist:2013 vcredist:2019 carootcert firefox tightvnc wallpaper uninstallsw
/opt/venv/bin/vmcloak --debug modify win10base
/opt/venv/bin/vmcloak --debug install win10base disableservices
/opt/venv/bin/vmcloak --debug snapshot --count 1 win10base win10vm_192.168.30.2
```

* Database

```
docker exec -it cuckoo3-guac-db /bin/bash
cat /tmp/templates/* | mysql -u root -p guacamole_db
```

* Sandbox
```
docker exec -it cuckoo3-core /bin/bash
su - cuckoo
cd /opt/cuckoo3
./local_scripts/init_cuckoo.sh
# da cambiare
# in cuckoo.yaml guacamole.db_ip in cuckoo3-guac-db
# in web.yaml elasticsearch.hosts in http://cuckoo3-elasticsearch:9200
```

* Restart services to provide modifications

```
docker compose down
docker compose up -d --remove-orphans
```
