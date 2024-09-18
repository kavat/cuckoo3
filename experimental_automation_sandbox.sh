# Importing ELK repository
curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elastic.gpg
echo "deb [signed-by=/usr/share/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-8.x.list

# Installing mandatory packages
apt-get update && apt-get upgrade -y
apt-get install git build-essential python3-dev python3.10-venv libhyperscan5 libhyperscan-dev libjpeg8-dev zlib1g-dev unzip p7zip-full rar unace-nonfree cabextract yara tcpdump genisoimage qemu-system-x86 qemu-utils qemu-system-common uwsgi uwsgi-plugin-python3 nginx elasticsearch libcairo2-dev libjpeg-turbo8-dev libpng-dev libtool-bin libossp-uuid-dev libvncserver-dev freerdp2-dev libssh2-1-dev libtelnet-dev libwebsockets-dev libpulse-dev libvorbis-dev libwebp-dev libssl-dev libpango1.0-dev libswscale-dev libavcodec-dev libavutil-dev libavformat-dev tomcat9 tomcat9-admin tomcat9-common tomcat9-user mariadb-server nmap python3-enchant -y

# Adding cuckoo user and providing necessary permissions
useradd cuckoo
chsh -s /bin/bash cuckoo
mkdir /home/cuckoo
chown cuckoo:cuckoo /home/cuckoo
adduser cuckoo kvm
adduser www-data cuckoo
chmod 666 /dev/kvm
groupadd pcap
adduser cuckoo pcap

# Configure apparmor for tcpdump profile
chgrp pcap /usr/bin/tcpdump
setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump
ln -s /etc/apparmor.d/usr.bin.tcpdump /etc/apparmor.d/disable/
apparmor_parser -R /etc/apparmor.d/disable/usr.bin.tcpdump
apparmor_parser -r /etc/apparmor.d/usr.bin.tcpdump

# Configuring ELK with no authentication and local binding
echo "path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
xpack.security.enabled: false
xpack.security.enrollment.enabled: false
xpack.security.http.ssl.enabled: false
xpack.security.transport.ssl.enabled: false
cluster.initial_master_nodes: [\"$(hostname)\"]
http.host: 127.0.0.1" > /etc/elasticsearch/elasticsearch.yml

# Enabling and restarting ELK service
systemctl enable --now elasticsearch
systemctl restart elasticsearch

# Installing Guacamole server to access VM during detonation
cd /tmp
wget https://downloads.apache.org/guacamole/1.5.5/source/guacamole-server-1.5.5.tar.gz
tar -xvf guacamole-server-1.5.5.tar.gz
cd guacamole-server-1.5.5
./configure --with-init-dir=/etc/init.d --enable-allow-freerdp-snapshots
make
make install
ldconfig
systemctl daemon-reload
systemctl enable --now guacd

# Installing Guacamole client to access VM during detonation
cd /tmp
wget https://downloads.apache.org/guacamole/1.5.5/binary/guacamole-1.5.5.war
mv /tmp/guacamole-1.5.5.war /var/lib/tomcat9/webapps/guacamole.war
mkdir -p /etc/guacamole/{extensions,lib}


# Installing connector among Guacamole and MariaDB
cd /tmp
wget https://dev.mysql.com/get/Downloads/Connector-J/mysql-connector-java-8.0.26.tar.gz
tar -xf mysql-connector-java-8.0.26.tar.gz
cp mysql-connector-java-8.0.26/mysql-connector-java-8.0.26.jar /etc/guacamole/lib/
wget https://downloads.apache.org/guacamole/1.5.5/binary/guacamole-auth-jdbc-1.5.5.tar.gz
tar -xf guacamole-auth-jdbc-1.5.5.tar.gz
mv guacamole-auth-jdbc-1.5.5/mysql/guacamole-auth-jdbc-mysql-1.5.5.jar /etc/guacamole/extensions/

# Configuring MariaDB and setting this engine as authentication for Guacamole
mysql_secure_installation
echo "ALTER USER 'root'@'localhost' IDENTIFIED BY 'password';
CREATE DATABASE guacamole_db;
CREATE USER 'guacamole_user'@'localhost' IDENTIFIED BY 'password';
GRANT SELECT,INSERT,UPDATE,DELETE ON guacamole_db.* TO 'guacamole_user'@'localhost';
FLUSH PRIVILEGES;" | mysql -u root -p
cat /tmp/guacamole-auth-jdbc-1.5.5/mysql/schema/*.sql | mysql -u root -p guacamole_db

echo "mysql-hostname: 127.0.0.1
mysql-port: 3306
mysql-database: guacamole_db
mysql-username: guacamole_user
mysql-password: password" > /etc/guacamole/guacamole.properties

# Enabling and restarting Tomcat, Guacamole and MariaDB service
systemctl enable --now tomcat9 guacd mysql
systemctl restart tomcat9 guacd mysql

# Starting install Cuckoo3
chown cuckoo /opt && cd /opt

# Cloning necessary projects
sudo -u cuckoo git clone https://github.com/kavat/cuckoo3
sudo -u cuckoo git clone https://github.com/kavat/vmcloak
sudo -u cuckoo git clone https://github.com/kavat/anubi

# Creating Python virtual environment
sudo -u cuckoo python3 -m venv /opt/cuckoo3/venv

# Installing projects
su - cuckoo
source /opt/cuckoo3/venv/bin/activate
>> cd /opt/cuckoo3
>> pip install wheel
>> ./install.sh
>> cuckoo createcwd
>> cuckoo getmonitor monitor.zip
>> unzip signatures.zip -d ~/.cuckoocwd/signatures/cuckoo/
>> cd ../vmcloak
>> pip install .
>> cd ../anubi
>> pip install -r pip_requirements.txt
>> exit

# Creating executable to run cuckoo3 backend
echo '#!/bin/bash
chmod 666 /dev/kvm
/opt/cuckoo3/venv/bin/vmcloak-qemubridge br0 192.168.30.1/24
chmod u+s /usr/lib/qemu/qemu-bridge-helper
su - cuckoo -c "/opt/cuckoo3/venv/bin/cuckoo --debug --cancel-abandoned"' >> /usr/local/bin/start_cuckoo
chmod +x /usr/local/bin/start_cuckoo

# Creating bridge first time
/opt/cuckoo3/venv/bin/vmcloak-qemubridge br0 192.168.30.1/24
mkdir -p /etc/qemu
echo 'allow br0' | sudo tee /etc/qemu/bridge.conf
chmod u+s /usr/lib/qemu/qemu-bridge-helper

# Building VM using vmcloak project
mkdir /mnt/win10x64
sudo -u cuckoo /opt/cuckoo3/venv/bin/vmcloak isodownload --win10x64 --download-to /home/cuckoo/win10x64.iso
mount -o loop,ro /home/cuckoo/win10x64.iso /mnt/win10x64
sudo -u cuckoo /opt/cuckoo3/venv/bin/vmcloak --debug init --win10x64 --hddsize 128 --cpus 2 --ramsize 4096 --network 192.168.30.0/24 --vm qemu --ip 192.168.30.2 --iso-mount /mnt/win10x64 win10base br0
sudo -u cuckoo /opt/cuckoo3/venv/bin/vmcloak --debug install win10base dotnet:4.7.2 java:8u151 vcredist:2013 vcredist:2019 carootcert firefox tightvnc wallpaper uninstallsw disableservices
sudo -u cuckoo /opt/cuckoo3/venv/bin/vmcloak --debug snapshot --count 1 win10base win10vm_192.168.30.2

# Importing created VM into cuckoo3
sudo -u cuckoo /opt/cuckoo3/venv/bin/cuckoo machine import qemu /home/cuckoo/.vmcloak/vms/qemu
sudo -u cuckoo /opt/cuckoo3/venv/bin/cuckoo machine delete qemu example1

# Building static docs
su - cuckoo
cd /opt/cuckoo3
source /opt/cuckoo3/venv/bin/activate
>> cuckoomigrate database all
>> cd /opt/cuckoo3/docs
>> pip install -r requirements.txt
>> mkdocs build
>> cp -R site ../web/cuckoo/web/static/docs

# Creating configurations for web facing
su - cuckoo
cd /opt/cuckoo3
source /opt/cuckoo3/venv/bin/activate
>> pip install uwsgi
>> cuckoo web generateconfig --uwsgi > /tmp/cuckoo-web.ini
>> exit

mv /tmp/cuckoo-web.ini /etc/uwsgi/apps-available/
ln -s /etc/uwsgi/apps-available/cuckoo-web.ini /etc/uwsgi/apps-enabled/cuckoo-web.ini

echo '[Unit]
After=remote-fs.target network-online.target elasticsearch.target' > /etc/systemd/system/uwsgi.service.d/override.conf

sudo -u cuckoo echo 'STATIC_ROOT = "/opt/cuckoo3/web/cuckoo/web/static"' >> /home/cuckoo/.cuckoocwd/web/web_local_settings.py
sudo -u cuckoo /opt/cuckoo3/venv/bin/cuckoo web generateconfig --nginx > /tmp/cuckoo-web.conf

echo "upstream _uwsgi_cuckoo_web {
    server 127.0.0.1:9090;
}
server {
    listen 80;
    location /static {
        alias /opt/cuckoo3/web/cuckoo/web/static;
    }
    location /manually {
        proxy_pass http://127.0.0.1:8080;
        proxy_buffering off;
        proxy_http_version 1.1;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$http_connection;
        access_log off;
    } 
    location / {
        client_max_body_size 1G;
        proxy_redirect off;
        proxy_set_header X-Forwarded-Proto \$scheme;
        include uwsgi_params;
        uwsgi_pass _uwsgi_cuckoo_web;
    }
}" > /tmp/cuckoo-web.conf

mv /tmp/cuckoo-web.conf /etc/nginx/sites-available/cuckoo-web.conf
ln -s /etc/nginx/sites-available/cuckoo-web.conf /etc/nginx/sites-enabled/cuckoo-web.conf
rm /etc/nginx/sites-enabled/default

systemctl daemon-reload
systemctl enable --now nginx uwsgi
systemctl restart nginx uwsgi

# Check if /home/cuckoo/.cuckoocwd/conf/cuckoo.yaml is ok
# Check if /home/cuckoo/.cuckoocwd/conf/web/web.yaml is ok

echo '#!/bin/bash
su - cuckoo -c "cd /opt/cuckoo3 && git pull" && systemctl restart uwsgi' > /usr/local/bin/pull_cuckoo3
chmod +x /usr/local/bin/pull_cuckoo3

echo '#!/bin/bash
su - cuckoo -c "cd /opt/vmcloak && git pull && /opt/cuckoo3/venv/bin/pip install ."' > /usr/local/bin/pull_vmcloak
chmod +x /usr/local/bin/pull_vmcloak

echo '#!/bin/bash
su - cuckoo -c "cd /opt/anubi && git pull" && systemctl restart uwsgi' > /usr/local/bin/pull_anubi
chmod +x /usr/local/bin/pull_anubi

start_cuckoo
