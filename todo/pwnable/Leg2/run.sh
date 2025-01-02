#!/bin/sh
PORT=8000
FLAG="DH{this_is_a_flag}"
qemu-system-aarch64 -M virt -cpu cortex-a57 -m 128 -kernel kernel -initrd rootfs -nographic -serial mon:stdio -append "console=ttyAMA0 FLAG=\"$FLAG\"" -netdev user,id=n1,hostfwd=tcp::$PORT-:8000 -device virtio-net-pci,netdev=n1
