from pwn import *

p = remote('host3.dreamhack.games', 16172)


def read():
    num1 = int(p.recvuntil(b'+')[:-1].decode())
    print('num1 : ', num1)

    num2 = int(p.recvuntil(b'=')[:-1].decode())
    print('num2 : ', num2)

    p.recvn(2)  # ?\n 제거

    inpt = num1 + num2
    print('inpt : ', inpt)

    p.sendline(str(inpt).encode())


for i in range(50):
    print(f'{i}')
    read()
    print()

p.recvline()  # Nice\n 제거
print('flag :', p.recvline().decode())
