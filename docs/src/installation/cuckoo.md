## Cuckoo installation

This page describes the steps required to install Cuckoo. Cuckoo can be set up in two ways:

* Default/single node.
    * The main and task running Cuckoo components run on the same machine. They are automatically started
    when starting Cuckoo. This is the type of setup that fits the most scenarios.

* Distributed, one main node and one or more task running nodes.
    * The main Cuckoo node runs on one machine. One or more task running Cuckoo nodes run on other servers/locations.
    Each task running node much be reachable over a network.


### Installing Cuckoo

The following steps are for a normal/generic Cuckoo setup. This is the type of setup fits the most scenarios.

**1. Install all [system dependencies](deps.md)**

**2. Create [dedicated user](user.md) and set system correctly**

**3. Installing Cuckoo 3, Vmcloak and Anubi from a delivery archive.**

3.1 Clone the archives

as cuckoo user
```bash
su - cuckoo
cd /opt
git clone https://github.com/kavat/cuckoo3
git clone https://github.com/kavat/vmcloak
git clone https://github.com/kavat/anubi
```

3.1 Create and activate a new Python >=3.10 virtualenv

as cuckoo user
```bash
su - cuckoo
python3 -m venv /opt/cuckoo3/venv
```

3.2 Install Cuckoo 3

as cuckoo user
```bash
su - cuckoo
source /opt/cuckoo3/venv/bin/activate
>> cd /opt/cuckoo3
>> pip install wheel
>> ./install.sh
```

3.2.1 Creating the Cuckoo CWD.**

By default this will be in `$HOME/.cuckoocwd`. The CWD is where
Cuckoo stores all its results, configurations, and other files. The CWD will be referred to as $CWD.

as cuckoo user
```bash
su - cuckoo
source /opt/cuckoo3/venv/bin/activate
>> cd /opt/cuckoo3
>> cuckoo createcwd
```

3.2.2 Installing the stager and monitor binaries**

The next step is to install the stager and monitor binaries. These are components that
are uploaded to the analysis vm and perform the actual behavioral collection.

as cuckoo user
```bash
su - cuckoo
source /opt/cuckoo3/venv/bin/activate
>> cd /opt/cuckoo3
>> cuckoo getmonitor monitor.zip
```

3.2.3 Installing the Cuckoo signatures

as cuckoo user
```bash
su - cuckoo
cd /opt/cuckoo3
unzip signatures.zip -d /home/cuckoo/.cuckoocwd/signatures/cuckoo/
```

3.3 Install Vmcloak

VMCloak is a utility for automatically creating Virtual Machines with Windows as guest Operating System.

as cuckoo user
```bash
su - cuckoo
source /opt/cuckoo3/venv/bin/activate
>> cd /opt/vmcloak
>> pip install -U .
```

3.4 Install Anubi

as cuckoo user
```bash
su - cuckoo
source /opt/cuckoo3/venv/bin/activate
>> cd /opt/anubi
>> pip install -U -r pip_requirements.txt
>> ln -s /opt/anubi /opt/cuckoo3/anubi
```

**4. Configure VM system for detonation scope.**

4.1 Download Windows 10 ISO provided by Vmcloak and mount it

as privileged user
```bash
sudo -u cuckoo /opt/cuckoo3/venv/bin/vmcloak isodownload --win10x64 --download-to /home/cuckoo/win10x64.iso
mkdir /mnt/win10x64
mount -o loop,ro /home/cuckoo/win10x64.iso /mnt/win10x64
```

4.2 Create the bridge for networking

as privileged user
```bash
/opt/cuckoo3/venv/bin/vmcloak-qemubridge br0 192.168.30.1/24
mkdir -p /etc/qemu
echo 'allow br0' | sudo tee /etc/qemu/bridge.conf
chmod u+s /usr/lib/qemu/qemu-bridge-helper
```

Note: at server boot if you don't create a service that run `/opt/cuckoo3/venv/bin/vmcloak-qemubridge br0 192.168.30.1/24` bridge shall be recrated newly.

4.3 Init VM, install requirements and snapshot it

as cuckoo user
```bash
su - cuckoo
/opt/cuckoo3/venv/bin/vmcloak --debug init --win10x64 --hddsize 128 --cpus 2 --ramsize 4096 --network 192.168.30.0/24 --vm qemu --ip 192.168.30.2 --iso-mount /mnt/win10x64 win10base br0
/opt/cuckoo3/venv/bin/vmcloak --debug install win10base dotnet:4.7.2 java:7u80 vcredist:2013 vcredist:2019 edge carootcert wallpaper disableservices
/opt/cuckoo3/venv/bin/vmcloak --debug snapshot --count 1 win10base win10vm_192.168.30.2
```

4.4 Import VM in Cuckoo 3

as cuckoo user
```bash
su - cuckoo
/opt/cuckoo3/venv/bin/cuckoo machine import qemu /home/cuckoo/.vmcloak/vms/qemu
/opt/cuckoo3/venv/bin/cuckoo machine delete qemu example1
```

Additional information and details for Section 6 can be found at:
* virtualization/machinery software in [machineries modules page](machineries.md)
* VM through Vmcloak in [vm module page](vmcreation.md).

**5. Migrate Cuckoo Database**

as cuckoo user
```bash
su - cuckoo
cd /opt/cuckoo3
source /opt/cuckoo3/venv/bin/activate
>> cuckoomigrate database all
```

Don't consider error raised up

**6. Install Cuckoo 3 documentation**

as cuckoo user
```bash
su - cuckoo
cd /opt/cuckoo3/docs
source /opt/cuckoo3/venv/bin/activate
>> cd /opt/cuckoo3/docs
>> pip install -r requirements.txt
>> mkdocs build
>> cp -R site ../web/cuckoo/web/static/docs
```

**7. Generate web configurations**

as cuckoo user
```bash
su - cuckoo
cd /opt/cuckoo3
source /opt/cuckoo3/venv/bin/activate
>> pip install uwsgi
>> cuckoo web generateconfig --uwsgi > /tmp/cuckoo-web.ini
>> echo 'STATIC_ROOT = "/opt/cuckoo3/web/cuckoo/web/static"' >> /home/cuckoo/.cuckoocwd/web/web_local_settings.py
>> cuckoo web generateconfig --nginx > /tmp/cuckoo-web.conf
```

as privileged user
```bash
mv /tmp/cuckoo-web.ini /etc/uwsgi/apps-available/
ln -s /etc/uwsgi/apps-available/cuckoo-web.ini /etc/uwsgi/apps-enabled/cuckoo-web.ini
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
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $http_connection;
        access_log off;
    } 
    location / {
        client_max_body_size 1G;
        proxy_redirect off;
        proxy_set_header X-Forwarded-Proto $scheme;
        include uwsgi_params;
        uwsgi_pass _uwsgi_cuckoo_web;
    }
}" > /tmp/cuckoo-web.conf

mv /tmp/cuckoo-web.conf /etc/nginx/sites-available/cuckoo-web.conf
ln -s /etc/nginx/sites-available/cuckoo-web.conf /etc/nginx/sites-enabled/cuckoo-web.conf
rm /etc/nginx/sites-enabled/default

systemctl enable --now nginx uwsgi
systemctl restart nginx uwsgi
```

**8. Start Cuckoo 3

Cuckoo can now be started using the following command:

```bash
su - cuckoo -c "/opt/cuckoo3/venv/bin/cuckoo --cwd <cwd path> --debug --cancel-abandoned
```

Or with the default cwd:

```bash
su - cuckoo -c "/opt/cuckoo3/venv/bin/cuckoo --debug --cancel-abandoned
```

Flag --debug can be omitted after first launches, --cancel-abandoned is mandatory if you want to don't consider abandoned tasks


### Installing Cuckoo distributed

The following steps are for a distributed Cuckoo setup. A distributed Cuckoo setup consists
of:

* One main node
    * This is the node to which submissions occur, it performs all result processing, and runs services such as the web interface and API.
    It keeps track of all created analyses. The analyses are scheduled to a task running node that fit the requirements of an analysis. It knows all
    task running nodes.

* One or more task running nodes
    * This node accepts, runs tasks, and stores the collected behavioral logs. It has an API that the main node uses to tell it to run a task or to download a result for a task. This node type is "dumb" it does not know about other nodes or even the main node. This node is also where Cuckoo rooter should be running if automatic network routing is desired.

#### Task running node(s)

We start with setting up one or more task running nodes:

**1. Perform the following for each task running node.**

Follow steps 1 to 8 of the [Installing Cuckoo](#installing-cuckoo) steps.

**2. Start the node(s) by running the following command**
    
    cuckoonode --host <listen ip> --port <listen port>

**3. Copy and store the node API key somewhere.**

Open `$CWD/conf/distributed.yaml` and find the `node_settings` section. It will have a generated key after the `api_key` field.
Write this key down, together with the IP and port of the node.

**3. Ensure the node API is reachable on the specified port.**

Communicate with the API by trying to reach the following API endpoint:

    curl "http://<node ip>:<node port>/machines" -H "Authorization: token <api key>"

It should return a list of available analysis machines.

#### The main node

**1. Perform the following steps.**

Follow steps 1 to 3 and 6 and 7 of the [Installing Cuckoo](#installing-cuckoo) steps.

**2. Adding the task running nodes.**

Open `$CWD/conf/distributed.yaml` and find the `remote_nodes` section. This is a dictionary of remote task running nodes.
For each created/installed task running node, add an entry.

```yaml
<A node name>:
  api_url: http://<node ip>:<node port>
  api_key: <node api key>
```

**3. Start Cuckoo in distributed mode**

Starting Cuckoo in distributed mode will cause Cuckoo to request information from each node on startup. Any connection error with one of
the nodes will result in the stopping of startup.

If the startup is successful, the setup is ready for submission.

    cuckoo --distributed
