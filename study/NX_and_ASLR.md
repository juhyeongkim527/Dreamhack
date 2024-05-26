시스템 보안의 특성상 보호 기법이 생기면 해당 보호 기법을 우회하는 공격 기법이 계속 등장하며 서로 발전해나가기 때문에 언제 어떤 공격이 새롭게 등장할지 예상하기 힘들다.  

따라서 시스템 개발자들은 시스템이 공격당할 수 있는 표면(**Attack Surface**)를 줄이려고 노력하고 있다.  

r2s 워게임에서는 첫째로 **return_address를 조작할 수 있었고**, **변수(버퍼)의 주소를 알 수 있었으며**, **그 변수(버퍼)의 주소에 쉘코드를 실행시킬 수 있었기 때문**에 익스플로잇이 가능했다.  

만약 해당 워게임에 취약점을 제거하려면 위의 3가지를 전부 제거하면 되는데, 첫번째 return_address는 canary를 통해 막을 수 있었지만, 나머지 두 취약점은 해결되지 않았기 때문에 만약 canary를 우회한다면 익스플로잇이 가능했다.  

위 두가지 취약점을 막기 위해서,
- 버퍼의 주소는 **ASLR(Address Space Layout Randomization)**을 통해 막고,
- 버퍼에 쉘코드를 실행하는 것을 막기 위해서는 **NX( No-eXecute()**를 사용한다.

이번 글에서는 위 두가지 보호기법인 **ASLR**과 **NX**에 대해서 알아보자.

## NX (No-eXecute)

NX는 **실행**(x)에 사용되는 메모리 영역과 **쓰기**(r)에 사용되는 메모리 영역을 분리하는 보호 기법이다. 어떤 메모리에 실행과 쓰기 권한이 함께 있으면 해킹에 취약해지기 쉽다.

왜냐하면 공격자가 만약 코드 영역에 실행 권한이 있다면 자신이 원하는 쉘코드를 수정(write)하고, execute 권한이 프로그램에 존재하기 때문에 쉽게 쉘코드 실행할 수 있고,  
스택이나 데이터 영역에 실행 권한이 있다면 return_address를 조작하여 stack에 쉘코드 삽입하여 익스플로잇을 수행할 수 있기 때문이다. 

CPU가 NX를 지원하면 컴파일러 옵션을 통해 바이너리에 NX를 적용할 수 있으며, NX가 적용된 바이너리는 실행될 때 각 메모리 영역에 필요한 권한만을 부여받는다. 

gdb의 vmmap으로 NX 적용 전후의 메모리 맵을 비교하면, 다음과 같이 NX가 적용된 바이너리에는 코드 영역 외에 실행 권한이 없는 것을 확인할 수 있다. 

반면, NX가 적용되지 않은 바이너리에는 스택 영역([stack])에 실행 권한이 존재하여 rwx 권한을 가지고 있음을 확인할 수 있다.

**NX Enable**
```
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
             Start                End Perm     Size Offset File
          0x400000           0x401000 r--p     1000      0 /home/dreamhack/nx
          0x401000           0x402000 r-xp     1000   1000 /home/dreamhack/nx
          0x402000           0x403000 r--p     1000   2000 /home/dreamhack/nx
          0x403000           0x404000 r--p     1000   2000 /home/dreamhack/nx
          0x404000           0x405000 rw-p     1000   3000 /home/dreamhack/nx
    0x7ffff7d7f000     0x7ffff7d82000 rw-p     3000      0 [anon_7ffff7d7f]
    0x7ffff7d82000     0x7ffff7daa000 r--p    28000      0 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7daa000     0x7ffff7f3f000 r-xp   195000  28000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7f3f000     0x7ffff7f97000 r--p    58000 1bd000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7f97000     0x7ffff7f9b000 r--p     4000 214000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7f9b000     0x7ffff7f9d000 rw-p     2000 218000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7f9d000     0x7ffff7faa000 rw-p     d000      0 [anon_7ffff7f9d]
    0x7ffff7fbb000     0x7ffff7fbd000 rw-p     2000      0 [anon_7ffff7fbb]
    0x7ffff7fbd000     0x7ffff7fc1000 r--p     4000      0 [vvar]
    0x7ffff7fc1000     0x7ffff7fc3000 r-xp     2000      0 [vdso]
    0x7ffff7fc3000     0x7ffff7fc5000 r--p     2000      0 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7fc5000     0x7ffff7fef000 r-xp    2a000   2000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7fef000     0x7ffff7ffa000 r--p     b000  2c000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7ffb000     0x7ffff7ffd000 r--p     2000  37000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7ffd000     0x7ffff7fff000 rw-p     2000  39000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffffffde000     0x7ffffffff000 rw-p    21000      0 [stack]
0xffffffffff600000 0xffffffffff601000 --xp     1000      0 [vsyscall]
```
**NX Disable**
```
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
             Start                End Perm     Size Offset File
          0x400000           0x401000 r--p     1000      0 /home/dreamhack/nx_disabled
          0x401000           0x402000 r-xp     1000   1000 /home/dreamhack/nx_disabled
          0x402000           0x403000 r--p     1000   2000 /home/dreamhack/nx_disabled
          0x403000           0x404000 r--p     1000   2000 /home/dreamhack/nx_disabled
          0x404000           0x405000 rw-p     1000   3000 /home/dreamhack/nx_disabled
    0x7ffff7d7f000     0x7ffff7d82000 rw-p     3000      0 [anon_7ffff7d7f]
    0x7ffff7d82000     0x7ffff7daa000 r--p    28000      0 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7daa000     0x7ffff7f3f000 r-xp   195000  28000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7f3f000     0x7ffff7f97000 r--p    58000 1bd000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7f97000     0x7ffff7f9b000 r--p     4000 214000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7f9b000     0x7ffff7f9d000 rw-p     2000 218000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7f9d000     0x7ffff7faa000 rw-p     d000      0 [anon_7ffff7f9d]
    0x7ffff7fbb000     0x7ffff7fbd000 rw-p     2000      0 [anon_7ffff7fbb]
    0x7ffff7fbd000     0x7ffff7fc1000 r--p     4000      0 [vvar]
    0x7ffff7fc1000     0x7ffff7fc3000 r-xp     2000      0 [vdso]
    0x7ffff7fc3000     0x7ffff7fc5000 r--p     2000      0 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7fc5000     0x7ffff7fef000 r-xp    2a000   2000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7fef000     0x7ffff7ffa000 r--p     b000  2c000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7ffb000     0x7ffff7ffd000 r--p     2000  37000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7ffd000     0x7ffff7fff000 rw-p     2000  39000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffffffde000     0x7ffffffff000 rwxp    21000      0 [stack]  --> 실행 권한이 함께 존재함
0xffffffffff600000 0xffffffffff601000 --xp     1000      0 [vsyscall]
```

### 참고 : 5.4.0 미만 버전 리눅스 커널에서의 NX
5.4.0 이전 버전에서는 NX 미적용시 커널이 `READ_IMPLIES_EXEC`플래그를 설정하여, read 권한이 있는 모든 페이지에 execute 권한을 발생시킴.

5.4.0 이상 버전의 커널은 해당 플래그를 설정하지 않고 NX 미적용시 stack 영역에만 write와 excute 권한이 함께 부여됨.

## ASLR (Address Space Layout Randomization)

ASLR은 바이너리가 실행될 때마다 **스택, 힙, 공유 라이브러리 등을 임의의 주소에 할당**하는 보호 기법이다.

r2c에서도 ASLR이 적용되어 바이너리를 실행할 때 마다 출력해주는 buf의 주소가 다른 것을 확인할 수 있다.

이렇게 실행할 때 마다 해당 영역들의 주소가 바뀌기 때문에 바이너리를 실행하기 전에 미리 주소를 파악하는 것은 힘들고, 익스플로잇시 바이너리를 실행할 때 마다 주소를 파악하는 과정이 필요하다.

ASLR은 **커널에서** 지원하는 보호 기법으로 다음의 명령어를 통해 확인 할 수 있다.

```
>>> $ cat /proc/sys/kernel/randomize_va_space
>>> 2
```
여기서는 2가 출력되었는데 리눅스에서 해당 출력값은 0, 1, 2를 가질 수 있고 각 출력값의 설명은 아래와 같다.

- 0 : No ASLR                             -> ASLR 적용 안함
- 1 : Conservative Randomization(1)       -> 스택, 힙, 라이브러리, vsdo 등
- 2 : Conservative Randomization + brk(2) -> (1)의 영역과 `brk`로 할당한 영역  

### 참고

- `brk` : C library 메모리 관리자는 brk() 시스템 콜을 사용하여 heap 영역을 미리 할당 받은 후 이를 직접 관리하는데, 만약 malloc()이나 다른 프로시저를 통해 heap을 사용하다가 heap 공간이 더 필요한 경우 brk()를 호출하여 heap 영역을 늘이게 된다.  
즉 지금은 쉽게 brk는 heap 영역을 동적으로 늘이는데 사용하는 함수라고 생각하면 된다.   
[참고 링크1](https://velog.io/@whwogur/%EB%A6%AC%EB%88%85%EC%8A%A4-System-call-brk-mmap)  
[참고 링크2](https://campkim.tistory.com/23)

- 'vdso' : [참고 링크](https://junsoolee.gitbook.io/linux-insides-ko/summary/syscall/linux-syscall-3) 

## ASLR 특징
```
// Name: addr.c
// Compile: gcc addr.c -o addr -ldl -no-pie -fno-PIE

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
  char buf_stack[0x10];                   // 스택 버퍼
  char *buf_heap = (char *)malloc(0x10);  // 힙 버퍼

  printf("buf_stack addr: %p\n", buf_stack);
  printf("buf_heap addr: %p\n", buf_heap);
  printf("libc_base addr: %p\n", *(void **)dlopen("libc.so.6", RTLD_LAZY));  // 라이브러리 주소

  printf("printf addr: %p\n", dlsym(dlopen("libc.so.6", RTLD_LAZY), "printf"));  // 라이브러리 함수의 주소
  printf("main addr: %p\n", main);  // 코드 영역의 함수 주소
}
```
위 코드는 ASLR을 확인하기 위해 각 영역의 메모리 주소를 출력하는 코드이다. 이 코드를 통해 ASLR의 특징을 알아보자.   
위 코드를 컴파일하여 3번 실행한 결과는 아래와 같다.

### 참고
- `char *buf_heap`은 포인터 변수이기 때문에, 해당 변수를 %p로 출력하면 해당 변수에 저장된(가리키는) 주소 값이 출력된다. -> malloc()으로 할당된 힙 버퍼의 주소

- `char *buf_heap`에서 buf_heap 변수의 주소를 알고 싶다면 `&buf_heap`으로 출력해야함 (포인터 말고 배열이나 다른 변수는 &를 붙여도 출력이 같음)

```
$ ./addr
buf_stack addr: 0x7ffcd3fcffc0
buf_heap addr: 0xb97260
libc_base addr: 0x7fd7504cd000
printf addr: 0x7fd750531f00
main addr: 0x400667

$ ./addr
buf_stack addr: 0x7ffe4c661f90
buf_heap addr: 0x176d260
libc_base addr: 0x7ffad9e1b000
printf addr: 0x7ffad9e7ff00
main addr: 0x400667

$ ./addr
buf_stack addr: 0x7ffcf2386d80
buf_heap addr: 0x840260
libc_base addr: 0x7fed2664b000
printf addr: 0x7fed266aff00
main addr: 0x400667 
```

위 실행파일의 결과 값을 보면, 스택 영역의` buf_stack`, 힙 영역의 `buf_heap`, 라이브러리 함수 `printf`, 라이브러리 매핑 주소 `libc_base`, 코드 영역의 함수 `main`가 출력되었다. 결과를 살펴보면 다음과 같은 특징이 있다.

1. 코드 영역인 `main` 함수의 주소를 제외하면 다른 영역의 주소는 바이너리 실행때마다 계속 바뀐다.
2. `buf_heap`의 하위 3바이트(12비트)는 힙 버퍼의 오프셋인데, 이는 힙 할당기에서 효율적인 작업을 위해 배치하는 것으로 같은 코드에서는 offset이 일치하기 때문에 바뀌지 않는 것 같음.
3. 바이너리를 반복해서 실행해도 **라이브러리 매핑 주소**`lib_base addr`와 **라이브러리 함수** `printf`의 하위 3바이트(12비트) 값은 변경되지 않았다.
  - 리눅스는 ASLR이 적용되었을 때, 파일을 **페이지(page)** 단위로 임의 주소에 매핑한다. 근데 여기서 하위 3바이트(12비트)는 페이지의 크기를 나타내기 때문에, ASLR이 적용되어도 페이지 크기는 바꾸지 않기 때문에 해당 비트는 변하지 않는다.
3. `libc_base addr`과 `printf`의 주소 차이는 항상 같다.
  - ASLR이 적용되면 라이브러리는 임의 주소에 매핑되지만, 라이브러리 파일 내용 자체는 그대로 해당 주소에 매핑되기 때문에 매핑된 주소로부터 라이브러리의 다른 `심볼(예를 들어 printf()함수)`들까지의 거리(Offset)는 항상 같기 때문이다.

```
>>> hex(0x7fd7504cd000 - 0x7fd750531f00) # libc_base addr - printf addr
'-0x64f00'
>>> hex(0x7ffad9e1b000 - 0x7ffad9e7ff00)
'-0x64f00'
```
```
$ objdump -D /lib/x86_64-linux-gnu/libc.so.6 | grep 064f00 -A3
0000000000064f00 <_IO_printf@@GLIBC_2.2.5>:
   64f00: 48 81 ec d8 00 00 00  sub    $0xd8,%rsp
   64f07: 84 c0                 test   %al,%al
   64f09: 48 89 74 24 28        mov    %rsi,0x28(%rsp)
 ```
ASLR으로 매핑된 라이브러리 주소와 printf() 함수까지의 거리는 `0x64f00`으로 항상 같은 이유는 objdump -d로 라이브러리 `/lib/x86_64-linux-gnu/libc.so.6` 파일을 디스어셈블하여 확인해보았듯이 `0x64f00` 떨어진 위치에 `print()` 함수가 존재하기 때문이다.

## 정리

NX와 ASLR이 적용되면, 스택, 힙, 데이터 영역에 실행 권한이 제거되며 해당 영역이 할당되는 주소가 계속 바뀐다.

그렇다고 하더라도 바이너리의 **코드 영역**은 ***여전히 실행 권한이 존재하며, 주소도 고정되어있다.***

코드 영역에는 유용한 코드 가젯(조각)들과 함수가 포함되어 있기 때문에 return_address를 우리가 작성한 쉘 코드를 payload로 보내서 직접 덮는 대신, 코드 영역의 source들을 활용하면 NX와 ASLR을 우회하여 공격할 수 있다.

대표적인 공격 기법으로는 `Return to Lib(RTL)`과 `Return Oriented Programming(ROP)`가 있다. 다음 정리에서 해당 공격 기법들을 더 공부해보고 정리하자.
