PATH_PYTHON3=$(find / -name "python3" 2>/dev/null | grep venv | xargs dirname)
touch /home/cuckoo/.cuckoocwd/.cuckoocwd
$PATH_PYTHON3/cuckoo createcwd --update-directories
$PATH_PYTHON3/cuckoo createcwd --regen-configs
$PATH_PYTHON3/cuckoo getmonitor monitor.zip
unzip signatures.zip -d ~/.cuckoocwd/signatures/cuckoo/
$PATH_PYTHON3/vmcloak-qemubridge br0 192.168.30.1/24
$PATH_PYTHON3/cuckoo machine import qemu /home/cuckoo/.vmcloak/vms/qemu
$PATH_PYTHON3/cuckoo machine delete qemu example1
$PATH_PYTHON3/cuckoomigrate database all
