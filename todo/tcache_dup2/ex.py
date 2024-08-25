from pwn import *

p = remote('host3.dreamhack.games', )
e = ELF('./tcache_dup2')
