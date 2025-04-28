#!/bin/bash

time (
	make O=out -j$(nproc) deb-pkg
	ssh qemu "rm -rf /root/debs/*.deb"
	scp *.deb qemu:/root/debs/
	ssh qemu "cd /root/debs; dpkg -i *.deb"
	rm *.deb
	rm *.dsc
	rm *.buildinfo
	rm *.changes
	rm linux-upstream*.tar.gz
)