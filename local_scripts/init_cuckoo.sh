touch /home/cuckoo/.cuckoocwd/.cuckoocwd
/opt/venv/bin/cuckoo createcwd --update-directories
/opt/venv/bin/cuckoo createcwd --regen-configs
/opt/venv/bin/cuckoo getmonitor monitor.zip
unzip signatures.zip -d ~/.cuckoocwd/signatures/cuckoo/
/opt/venv/bin/cuckoo machine import qemu /home/cuckoo/.vmcloak/vms/qemu
/opt/venv/bin/cuckoo machine delete qemu example1
/opt/venv/bin/cuckoomigrate database all

/opt/venv/bin/vmcloak-qemubridge br0 192.168.30.1/24
