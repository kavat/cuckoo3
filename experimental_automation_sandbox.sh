hostname=$(hostname)

curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elastic.gpg
echo "deb [signed-by=/usr/share/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-7.x.list

sudo apt update && sudo apt upgrade -y
sudo apt install git build-essential python3-dev python3.10-venv libhyperscan5 libhyperscan-dev libjpeg8-dev zlib1g-dev unzip p7zip-full rar unace-nonfree cabextract yara tcpdump genisoimage qemu-system-x86 qemu-utils qemu-system-common uwsgi uwsgi-plugin-python3 nginx elasticsearch -y

sudo useradd cuckoo
sudo mkdir /home/cuckoo
sudo chown cuckoo:cuckoo /home/cuckoo

sudo adduser cuckoo kvm
sudo adduser www-data cuckoo
sudo chmod 666 /dev/kvm

sudo groupadd pcap
sudo adduser cuckoo pcap
sudo chgrp pcap /usr/bin/tcpdump
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump
sudo ln -s /etc/apparmor.d/usr.bin.tcpdump /etc/apparmor.d/disable/
sudo apparmor_parser -R /etc/apparmor.d/disable/usr.bin.tcpdump
sudo apparmor_parser -r /etc/apparmor.d/usr.bin.tcpdump

sudo echo "node.name: ${hostname}
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch

xpack.security.enabled: false

xpack.security.enrollment.enabled: false

xpack.security.http.ssl:
  enabled: false
  keystore.path: certs/http.p12

xpack.security.transport.ssl:
  enabled: false
  verification_mode: certificate
  keystore.path: certs/transport.p12
  truststore.path: certs/transport.p12

cluster.initial_master_nodes: ["${hostname}"]
http.host: localhost" > /etc/elasticsearch/elasticsearch.yml"

sudo chown cuckoo /opt && cd /opt


sudo -u cuckoo git clone https://github.com/kavat/cuckoo3
sudo -u cuckoo git clone https://github.com/kavat/vmcloak.git

sudo -u cuckoo python3 -m venv /opt/cuckoo3/venv

su - cuckoo
source /opt/venv/bin/activate
>> pip install wheel
>> ./install.sh
>> quit

sudo -u cuckoo /opt/cuckoo3/venv/bin/cuckoo createcwd
sudo -u cuckoo /opt/cuckoo3/venv/bin/cuckoo getmonitor monitor.zip
sudo -u cuckoo unzip signatures.zip -d ~/.cuckoocwd/signatures/cuckoo/

cd ../vmcloak
sudo -u cuckoo /opt/cuckoo3/venv/bin/pip install .

sudo /opt/cuckoo3/venv/bin/vmcloak-qemubridge br0 192.168.30.1/24
sudo mkdir -p /etc/qemu
echo 'allow br0' | sudo tee /etc/qemu/bridge.conf
sudo chmod u+s /usr/lib/qemu/qemu-bridge-helper
sudo mkdir /mnt/win10x64


sudo -u cuckoo /opt/cuckoo3/venv/bin/vmcloak isodownload --win10x64 --download-to ~/win10x64.iso
sudo mount -o loop,ro /home/cuckoo/win10x64.iso /mnt/win10x64
sudo -u cuckoo /opt/cuckoo3/venv/bin/vmcloak --debug init --win10x64 --hddsize 128 --cpus 2 --ramsize 4096 --network 192.168.30.0/24 --vm qemu --ip 192.168.30.2 --iso-mount /mnt/win10x64 win10base br0
sudo -u cuckoo /opt/cuckoo3/venv/bin/vmcloak --debug install win10base dotnet:4.7.2 java:7u80 vcredist:2013 vcredist:2019 edge carootcert wallpaper disableservices
sudo -u cuckoo /opt/cuckoo3/venv/bin/vmcloak --debug modify win10base

curl "http://192.168.30.2:8000/execute" -F "command=powershell.exe -command \"Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name \"fDenyTSConnections\" -value 0\""
curl "http://192.168.30.2:8000/execute" -F "command=powershell.exe -command \"Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name \"SecurityLayer\" -value 0\""
curl "http://192.168.30.2:8000/execute" -F "command=powershell.exe -command \"Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name \"UserAuthentication\" -value 0\""

sudo -u cuckoo /opt/cuckoo3/venv/bin/vmcloak --debug snapshot --count 1 win10base win10vm_192.168.30.2
sudo -u cuckoo /opt/cuckoo3/venv/bin/cuckoo machine import qemu ~/.vmcloak/vms/qemu
sudo -u cuckoo /opt/cuckoo3/venv/bin/cuckoo machine delete qemu example1
sudo -u cuckoo /opt/cuckoo3/venv/bin/cuckoomigrate database all

sudo -u cuckoo vi ~/.cuckoocwd/conf/cuckoo.yaml
# route/forward traffic between the analysis machines and the resultserver.
resultserver:
  listen_ip: 192.168.30.1
  listen_port: 2042

# Settings used by Cuckoo to find the tcpdump binary to use for network capture of machine traffic.
tcpdump:
  enabled: True
  path: /usr/bin/tcpdump

sudo -u cuckoo vi ~/.cuckoocwd/conf/web/web.yaml
Edit the subnets in ``allowed_subnets’’. In my case (192.168.68.0/24)
set statistics a True

cd /opt/cuckoo3/docs
sudo -u cuckoo /opt/cuckoo3/venv/bin/pip install -r requirements.txt
sudo -u cuckoo /opt/cuckoo3/venv/bin/mkdocs build
sudo -u cuckoo /opt/cuckoo3/venv/bin/cp -R site ../web/cuckoo/web/static/docs
sudo -u cuckoo /opt/cuckoo3/venv/bin/pip install uwsgi
sudo -u cuckoo /opt/cuckoo3/venv/bin/cuckoo --debug

sudo -u cuckoo /opt/cuckoo3/venv/bin/cuckoo web generateconfig --uwsgi > /tmp/cuckoo-web.ini
sudo mv /tmp/cuckoo-web.ini /etc/uwsgi/apps-available/
sudo ln -s /etc/uwsgi/apps-available/cuckoo-web.ini /etc/uwsgi/apps-enabled/cuckoo-web.ini

sudo -u cuckoo echo 'STATIC_ROOT = "/opt/cuckoo3/web/cuckoo/web/static"' >> ~/.cuckoocwd/web/web_local_settings.py
sudo -u cuckoo /opt/cuckoo3/venv/bin/cuckoo web generateconfig --nginx > /tmp/cuckoo-web.conf
sudo -u cuckoo vi /tmp/cuckoo-web.conf

server {
    listen 80;

    # Directly serve the static files for Cuckoo web. Copy
    # (and update these after Cuckoo updates) these by running:
    # 'cuckoo web djangocommand collectstatic'. The path after alias should
    # be the same path as STATIC_ROOT. These files can be cached. Be sure
    # to clear the cache after any updates.
    location /static {
        alias /opt/cuckoo3/web/cuckoo/web/static;
    }

sudo mv /tmp/cuckoo-web.conf /etc/nginx/sites-available/cuckoo-web.conf
sudo ln -s /etc/nginx/sites-available/cuckoo-web.conf /etc/nginx/sites-enabled/cuckoo-web.conf
sudo rm /etc/nginx/sites-enabled/default
sudo systemctl restart nginx uwsgi

sudo -u cuckoo /opt/cuckoo3/venv/bin/cuckoo
