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

다음은 의사코드의 각 줄을 어셈블리어로 구현한 코드이다.

### 1. int fd = open(“/tmp/flag”, O_RDONLY, NULL);
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
