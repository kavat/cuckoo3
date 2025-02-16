# System dependencies

This page lists commands to install system dependencies that must be installed. The required machinery module dependencies depend on the machinery module you are using. See the [machineries](machineries.md) section for more information.

### Generic libraries and tools

These are the generic packages mandatory to start operations

```bash
apt-get update
apt-get upgrade -y
apt-get install -y git build-essential python3-dev python3.10-venv libhyperscan5 libhyperscan-dev libjpeg8-dev zlib1g-dev unzip p7zip-full rar unace-nonfree cabextract yara tcpdump genisoimage qemu-system-x86 qemu-utils qemu-system-common uwsgi uwsgi-plugin-python3 nginx libcairo2-dev libjpeg-turbo8-dev libpng-dev libtool-bin libossp-uuid-dev libvncserver-dev freerdp2-dev libssh2-1-dev libtelnet-dev libwebsockets-dev libpulse-dev libvorbis-dev libwebp-dev libssl-dev libpango1.0-dev libswscale-dev libavcodec-dev libavutil-dev libavformat-dev nmap python3-enchant -y
```

### Elasticsearch

Elasticsearch is used to store statistics data

```bash
curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elastic.gpg

echo "deb [signed-by=/usr/share/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-8.x.list

apt-get install -y elasticsearch

# Configuring ELK with no authentication and local binding
echo "path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
xpack.security.enabled: false
xpack.security.enrollment.enabled: false
xpack.security.http.ssl.enabled: false
xpack.security.transport.ssl.enabled: false
cluster.initial_master_nodes: [\"$(hostname)\"]
http.host: 127.0.0.1" > /etc/elasticsearch/elasticsearch.yml

systemctl enable --now elasticsearch
systemctl restart elasticsearch
```

### Guacamole

Guacamole is used to access VM during detonation in order to increase analysis deph.

```bash
apt-get install -y apt-get install -y tomcat9 tomcat9-admin tomcat9-common tomcat9-user mariadb-server
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

# Configuring MariaDB and setting this engine as authentication for Guacamole
mysql_secure_installation
cd /tmp
wget https://dev.mysql.com/get/Downloads/Connector-J/mysql-connector-java-8.0.26.tar.gz
tar -xf mysql-connector-java-8.0.26.tar.gz
cp mysql-connector-java-8.0.26/mysql-connector-java-8.0.26.jar /etc/guacamole/lib/
wget https://downloads.apache.org/guacamole/1.5.5/binary/guacamole-auth-jdbc-1.5.5.tar.gz
tar -xf guacamole-auth-jdbc-1.5.5.tar.gz
mv guacamole-auth-jdbc-1.5.5/mysql/guacamole-auth-jdbc-mysql-1.5.5.jar /etc/guacamole/extensions/

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
```
