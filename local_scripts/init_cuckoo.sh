export PATH=$PATH:/home/cuckoo/.local/bin
cuckoo createcwd
cuckoo getmonitor monitor.zip
unzip signatures.zip -d ~/.cuckoocwd/signatures/cuckoo/
cuckoo machine import qemu /home/cuckoo/.vmcloak/vms/qemu
cuckoo machine delete qemu example1
cuckoomigrate database all
