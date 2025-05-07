#!/bin/bash
set -e
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
	scp qemu:/boot/initrd.img-6.6.66+ /root/learn_linux_lts/kernel_debug/
)
