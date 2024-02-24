# orw Shellcode

orw 쉘코드는 **open, read, write** 쉘 코드의 약자로 orw 셸코드는 파일을 열고, 읽은 뒤 화면에 출력해주는 셸코드이다.
구현하려는 쉘코드의 동작을 C언어 형식의 의사코드로 표현하면 다음과 같다.
```
char buf[0x30];

int fd = open("/tmp/flag", RD_ONLY, NULL);
read(fd, buf, 0x30); 
write(1, buf, 0x30);
```
orw 셸코드를 작성하기 위해 알아야 하는 syscall은 아래와 같다.
|syscall|rax|arg0 (rdi)|arg1 (rsi)|arg2 (rdx)|
|-|-|-|-|-|
|read|0x00|unsigned int fd|char* buf|size_t count|
|write|0x01|unsigned int fd|const char* buf|size_t count|
|open|0x02|const char* filename|int flags|umode_t mode|

- 여기서 **fd**란, 유닉스 계열의 운영체제에서 파일에 접근하는 소프트웨어에 제공하는 가상의 접근 제어자(File Descripotr)이다.
프로세스마다 고유의 서술자 테이블을 갖고 있으며, 그 안에 여러 파일 서술자를 저장한다.
서술자 각각은 번호로 구별되는데,
  - 0번 : 일반 입력(Standard Input, **STDIN**)
  - 1번 : 일반 출력(Standard Output, **STDOUT**)
  - 2번 : 일반 오류(Standard Error, **STDER**)

에 할당되어 있으며, 이들은 프로세스를 터미널과 연결해준다.  
그래서 우리는 키보드 입력을 통해 프로세스에 입력을 전달하고, 출력을 터미널로 받아볼 수 있다.  
프로세스가 생성된 이후, 위의 open같은 함수를 통해 어떤 파일과 프로세스를 연결하려고 하면, 기본으로 할당된 **2번 이후의 번호를 새로운 fd에 차례로 할당**해준다. 그러면 프로세스는 그 fd를 이용하여 파일에 접근할 수 있다.


다음은 의사코드의 각 줄을 어셈블리어로 구현한 코드이다.

## 1. int fd = open(“/tmp/flag”, O_RDONLY, NULL);
|syscall|rax|arg0 (rdi)|arg1 (rsi)|arg2 (rdx)|
|-|-|-|-|-|
|open|0x02|const char* filename|int flags|umode_t mode|
```
push 0x67
mov rax, 0x616c662f706d742f 
push rax
mov rdi, rsp    ; rdi = "/tmp/flag"
xor rsi, rsi    ; rsi = 0 ; RD_ONLY
xor rdx, rdx    ; rdx = 0
mov rax, 2      ; rax = 2 ; syscall_open
syscall         ; open("/tmp/flag", RD_ONLY, NULL)
```
참고로,
```
// https://code.woboq.org/userspace/glibc/bits/fcntl.h.html#24
/* File access modes for `open' and `fcntl'.  */
#define        O_RDONLY        0        /* Open read-only.  */
#define        O_WRONLY        1        /* Open write-only.  */
#define        O_RDWR          2        /* Open read/write.  */
```
위의 어셈블리어 코드를 순서대로 설명하면,
1. **/tmp/flag** 문자열(**0x2f 0x74 0x6d 0x70 ... 0x67**)을 메모리에 위치시키기 위해 스택에 `0x616c662f706d742f67(/tmp/flag)`을 push해야한다.
하지만 스택에는 8 바이트 단위로만 값을 push할 수 있으므로 `0x67`를 우선 push한 후, `0x616c662f706d742f`를 push한다. 그리고 rdi가 이를 가리키도록 rsp를 rdi로 옮긴다.  
메모리에는 아래의 사진처럼 리틀엔디언 방식으로 저장되고, string은 낮은 주소부터(0x2f) 순서대로 읽어서 0x00(NULL, \0)이 나올 때 까지 읽기 때문에 **tmp/flag** 문자열을 출력하게 된다.
- 참고로 long int는 8바이트 단위로 string처럼 낮은 주소부터가 아닌 저장하는 해당 hex값을 통째로 읽고, 4바이트 int의 경우 낮은 주소부터 4바이트 짤라서 통째로 읽는다.
![image](https://github.com/juhyeongkim527/Dreamhack-Study/assets/138116436/27840413-bd6c-4a99-9db5-d8cdd281c780)
![image](https://github.com/juhyeongkim527/Dreamhack-Study/assets/138116436/d4137cc7-9f6f-44f3-9371-3f32390046fc)
## 2.read(fd, buf, 0x30)
|syscall|rax|arg0 (rdi)|arg1 (rsi)|arg2 (rdx)|
|-|-|-|-|-|
|read|0x00|unsigned int fd|char* buf|size_t count|
```
mov rdi, rax      ; rdi = fd
mov rsi, rsp
sub rsi, 0x30     ; rsi = rsp-0x30 ; buf
mov rdx, 0x30     ; rdx = 0x30     ; len
mov rax, 0x0      ; rax = 0        ; syscall_read
syscall           ; read(fd, buf, 0x30)
```

1. system call의 반환 값은 rax에 저장된다. 1번에서 open의 반환값은 `int fd`인데 이는 rax에 저장되고 fd는 2번 뒤부터 순서대로 저장되기 때문에 rax에는 `0x03`이 저장될 것이다. 따라서 해당 rax값(fd)를 rdi에 넘겨준다.
2. rsi는 파일에서 읽은 데이터를 저장할 주소를 가리킨다. 0x30만큼 읽을 것이므로, rsi에 `rsp-0x30`을 대입한다.
3. rdx는 파일로부터 읽어낼 데이터의 길이인 `0x30`으로 설정한다.
4. read 시스템콜을 호출하기 위해서 rax를 `0x0`으로 설정한다.

## 3. write(1, buf, 0x30)
|syscall|rax|arg0 (rdi)|arg1 (rsi)|arg2 (rdx)|
|-|-|-|-|-|
|write|0x01|unsigned int fd|const char* buf|size_t count|

```
move rdi, 1        ; rdi = 1 ; fd = stdout
move rax, 1        ; rax = 1 ; syscall_write
syscall            ; write(1, buf, 0x30)
```
1. 출력은 stdout으로 할 것이므로, rdi를 0x1로 설정한다.
2. rsi와 rdx는 read에서 사용한 값을 그대로 사용한다.
3. write 시스템콜을 호출하기 위해서 rax를 1로 설정한다.

이를 모두 종합하면 아래와 같다.
```
;Name: orw.S

push 0x67
mov rax, 0x616c662f706d742f
push rax
mov rdi, rsp
xor rsi, rsi
xor rdx, rdx
mov rax, 0x2
syscall
mov rdi, rax
mov rsi, rsp
sub rsi, 0x30
mov rdx, 0x30
mov rax, 0x0
syscall
mov rdi, 0x1
mov rax, 0x1
syscall
```
```
// File name: orw.c
// Compile: gcc -o orw orw.c -masm=intel

__asm__(
    ".global run_sh\n"
    "run_sh:\n"

    "push 0x67\n"
    "mov rax, 0x616c662f706d742f \n"
    "push rax\n"
    "mov rdi, rsp    # rdi = '/tmp/flag'\n"
    "xor rsi, rsi    # rsi = 0 ; RD_ONLY\n"
    "xor rdx, rdx    # rdx = 0\n"
    "mov rax, 2      # rax = 2 ; syscall_open\n"
    "syscall         # open('/tmp/flag', RD_ONLY, NULL)\n"
    "\n"
    "mov rdi, rax      # rdi = fd\n"
    "mov rsi, rsp\n"
    "sub rsi, 0x30     # rsi = rsp-0x30 ; buf\n"
    "mov rdx, 0x30     # rdx = 0x30     ; len\n"
    "mov rax, 0x0      # rax = 0        ; syscall_read\n"
    "syscall           # read(fd, buf, 0x30)\n"
    "\n"
    "mov rdi, 1        # rdi = 1 ; fd = stdout\n"
    "mov rax, 0x1      # rax = 1 ; syscall_write\n"
    "syscall           # write(fd, buf, 0x30)\n"
    "\n"
    "xor rdi, rdi      # rdi = 0\n"
    "mov rax, 0x3c	   # rax = sys_exit\n"
    "syscall		   # exit(0)");

void run_sh();

int main() { run_sh(); }
```
