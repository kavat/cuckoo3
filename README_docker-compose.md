Cuckoo3
=======

Dockerization for Cuckoo3 Sandbox

Introduction
------------

VMCloak is a tool to fully create and prepare Virtual Machines that can be
used by Cuckoo Sandbox. In order to create a new Virtual Machine one should
prepare a few configuration values that will be used later on by the tool.

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

* Database

```
docker exec -it cuckoo3_guac-db /bin/bash
cat /tmp/templates/* | mysql -u root -puser_root_password guacamole_db
```

* Sandbox
```
docker exec -it cuckoo3_core /bin/bash
su - cuckoo
cd /opt/cuckoo3
# exec ./local_scripts/init_cuckoo.sh
```
