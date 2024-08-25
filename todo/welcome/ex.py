from pwn import *

p = remote('host3.dreamhack.games', 10734)
p.interactive()
