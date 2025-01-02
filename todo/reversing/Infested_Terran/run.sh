#!/bin/sh

qemu-system-x86_64 \
    -M pc \
    -kernel ./bzImage \
    -drive file=./rootfs.ext2,if=virtio,format=raw \
    -append "root=/dev/vda console=ttyS0" \
    -net nic,model=virtio -net user \
    -nographic
