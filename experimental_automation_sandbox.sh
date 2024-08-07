curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elastic.gpg
echo "deb [signed-by=/usr/share/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-8.x.list

apt update && sudo apt upgrade -y
apt install git build-essential python3-dev python3.10-venv libhyperscan5 libhyperscan-dev libjpeg8-dev zlib1g-dev unzip p7zip-full rar unace-nonfree cabextract yara tcpdump genisoimage qemu-system-x86 qemu-utils qemu-system-common uwsgi uwsgi-plugin-python3 nginx elasticsearch libcairo2-dev libjpeg-turbo8-dev libpng-dev libtool-bin libossp-uuid-dev libvncserver-dev freerdp2-dev libssh2-1-dev libtelnet-dev libwebsockets-dev libpulse-dev libvorbis-dev libwebp-dev libssl-dev libpango1.0-dev libswscale-dev libavcodec-dev libavutil-dev libavformat-dev tomcat9 tomcat9-admin tomcat9-common tomcat9-user mariadb-server nmap -y

useradd cuckoo
chsh -s /bin/bash cuckoo
mkdir /home/cuckoo
chown cuckoo:cuckoo /home/cuckoo

adduser cuckoo kvm
adduser www-data cuckoo
chmod 666 /dev/kvm

groupadd pcap
adduser cuckoo pcap
chgrp pcap /usr/bin/tcpdump
setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump
ln -s /etc/apparmor.d/usr.bin.tcpdump /etc/apparmor.d/disable/
apparmor_parser -R /etc/apparmor.d/disable/usr.bin.tcpdump
apparmor_parser -r /etc/apparmor.d/usr.bin.tcpdump

echo "path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
xpack.security.enabled: false
xpack.security.enrollment.enabled: false
xpack.security.http.ssl.enabled: false
xpack.security.transport.ssl.enabled: false
cluster.initial_master_nodes: ["cuckoo01"]
http.host: 127.0.0.1" > /etc/elasticsearch/elasticsearch.yml

systemctl enable --now elasticsearch
systemctl restart elasticsearch

cd /tmp
wget https://downloads.apache.org/guacamole/1.5.5/source/guacamole-server-1.5.5.tar.gz
wget https://downloads.apache.org/guacamole/1.5.5/binary/guacamole-1.5.5.war
tar -xvf guacamole-server-1.5.5.tar.gz
cd guacamole-server-1.5.5
./configure --with-init-dir=/etc/init.d --enable-allow-freerdp-snapshots
make
make install
ldconfig
systemctl daemon-reload
systemctl enable --now guacd
mv /tmp/guacamole-1.5.5.war /var/lib/tomcat9/webapps/guacamole.war

mkdir -p /etc/guacamole/{extensions,lib}

mysql_secure_installation
cd /tmp
wget https://dev.mysql.com/get/Downloads/Connector-J/mysql-connector-java-8.0.26.tar.gz
tar -xf mysql-connector-java-8.0.26.tar.gz
cp mysql-connector-java-8.0.26/mysql-connector-java-8.0.26.jar /etc/guacamole/lib/
wget https://downloads.apache.org/guacamole/1.5.5/binary/guacamole-auth-jdbc-1.5.5.tar.gz
tar -xf guacamole-auth-jdbc-1.5.5.tar.gz
mv guacamole-auth-jdbc-1.5.5/mysql/guacamole-auth-jdbc-mysql-1.5.5.jar /etc/guacamole/extensions/

mysql -u root -p
ALTER USER 'root'@'localhost' IDENTIFIED BY 'password';
CREATE DATABASE guacamole_db;
CREATE USER 'guacamole_user'@'localhost' IDENTIFIED BY 'password';
GRANT SELECT,INSERT,UPDATE,DELETE ON guacamole_db.* TO 'guacamole_user'@'localhost';
FLUSH PRIVILEGES;
QUIT;

cat /tmp/guacamole-auth-jdbc-1.5.5/mysql/schema/*.sql | mysql -u root -p guacamole_db

echo "mysql-hostname: 127.0.0.1
mysql-port: 3306
mysql-database: guacamole_db
mysql-username: guacamole_user
mysql-password: password" > /etc/guacamole/guacamole.properties

systemctl enable --now tomcat9 guacd mysql
systemctl restart tomcat9 guacd mysql

chown cuckoo /opt && cd /opt

sudo -u cuckoo git clone https://github.com/kavat/cuckoo3
sudo -u cuckoo git clone https://github.com/kavat/vmcloak

sudo -u cuckoo python3 -m venv /opt/cuckoo3/venv

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
>> exit

echo '#!/bin/bash
/opt/cuckoo3/venv/bin/vmcloak-qemubridge br0 192.168.30.1/24
su - cuckoo -c "/opt/cuckoo3/venv/bin/cuckoo --debug --cancel-abandoned"' >> /usr/local/bin/start_cuckoo
chmod +x /usr/local/bin/start_cuckoo

/opt/cuckoo3/venv/bin/vmcloak-qemubridge br0 192.168.30.1/24
mkdir -p /etc/qemu
echo 'allow br0' | sudo tee /etc/qemu/bridge.conf
chmod u+s /usr/lib/qemu/qemu-bridge-helper
mkdir /mnt/win10x64

sudo -u cuckoo /opt/cuckoo3/venv/bin/vmcloak isodownload --win10x64 --download-to /home/cuckoo/win10x64.iso
mount -o loop,ro /home/cuckoo/win10x64.iso /mnt/win10x64
sudo -u cuckoo /opt/cuckoo3/venv/bin/vmcloak --debug init --win10x64 --hddsize 128 --cpus 2 --ramsize 4096 --network 192.168.30.0/24 --vm qemu --ip 192.168.30.2 --iso-mount /mnt/win10x64 win10base br0
sudo -u cuckoo /opt/cuckoo3/venv/bin/vmcloak --debug install win10base dotnet:4.7.2 java:7u80 vcredist:2013 vcredist:2019 edge carootcert wallpaper disableservices
sudo -u cuckoo /opt/cuckoo3/venv/bin/vmcloak --debug snapshot --count 1 win10base win10vm_192.168.30.2
su - cuckoo -c "/opt/cuckoo3/venv/bin/cuckoo machine import qemu ~/.vmcloak/vms/qemu"
su - cuckoo -c "/opt/cuckoo3/venv/bin/cuckoo machine delete qemu example1"

su - cuckoo
cd /opt/cuckoo3
source /opt/cuckoo3/venv/bin/activate
>> cuckoomigrate database all
>> exit

sudo -u cuckoo vi /home/cuckoo/.cuckoocwd/conf/cuckoo.yaml
# route/forward traffic between the analysis machines and the resultserver.
resultserver:
  listen_ip: 192.168.30.1
  listen_port: 2042

# Settings used by Cuckoo to find the tcpdump binary to use for network capture of machine traffic.
tcpdump:
  enabled: True
  path: /usr/bin/tcpdump

sudo -u cuckoo vi /home/cuckoo/.cuckoocwd/conf/web/web.yaml
Edit the subnets in ``allowed_subnets’’. In my case (192.168.68.0/24)
set statistics a True

cd /opt/cuckoo3/docs
sudo -u cuckoo /opt/cuckoo3/venv/bin/pip install -r requirements.txt
sudo -u cuckoo /opt/cuckoo3/venv/bin/mkdocs build
sudo -u cuckoo cp -R site ../web/cuckoo/web/static/docs
sudo -u cuckoo /opt/cuckoo3/venv/bin/pip install uwsgi
sudo -u cuckoo /opt/cuckoo3/venv/bin/cuckoo --debug

su - cuckoo
source /opt/cuckoo3/venv/bin/activate
>> cuckoo web generateconfig --uwsgi > /tmp/cuckoo-web.ini
>> exit
mv /tmp/cuckoo-web.ini /etc/uwsgi/apps-available/
ln -s /etc/uwsgi/apps-available/cuckoo-web.ini /etc/uwsgi/apps-enabled/cuckoo-web.ini

sudo -u cuckoo echo 'STATIC_ROOT = "/opt/cuckoo3/web/cuckoo/web/static"' >> /home/cuckoo/.cuckoocwd/web/web_local_settings.py
sudo -u cuckoo /opt/cuckoo3/venv/bin/cuckoo web generateconfig --nginx > /tmp/cuckoo-web.conf
vi /tmp/cuckoo-web.conf

upstream _uwsgi_cuckoo_web {
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
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $http_connection;
        proxy_set_header Authorization "Basic Z3VhY2FkbWluOmd1YWNhZG1pbgo=";
        access_log off;
    } 

    location / {
        client_max_body_size 1G;
        proxy_redirect off;
        proxy_set_header X-Forwarded-Proto $scheme;
        include uwsgi_params;
        uwsgi_pass _uwsgi_cuckoo_web;
    }
}

mv /tmp/cuckoo-web.conf /etc/nginx/sites-available/cuckoo-web.conf
ln -s /etc/nginx/sites-available/cuckoo-web.conf /etc/nginx/sites-enabled/cuckoo-web.conf
rm /etc/nginx/sites-enabled/default
systemctl enable --now nginx uwsgi
systemctl restart nginx uwsgi

start_cuckoo
