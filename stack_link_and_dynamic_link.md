C의 표준 라이브러리인 `libc`는 우분트에 기본으로 탑재된 라이브러리이며, `/lib/x86_64-linux-gnu/libc.so.6`에 있음. 그래서 arm 맥북 터미널에서는 `#include<stdio.h>`를 하지 않으면 기본 라이브러리 함수를 수행할 수 없음.

## Link

![](https://bpsecblog.files.wordpress.com/2016/02/gote1848be185aaplt-1-e18480e185b3e18485e185b5e186b72.png)

리눅스에서 C 소스 코드 컴파일 단계는 **전처리, 컴파일, 어셈블, 링크** 단계로 이루어진다. 

해당 과정을 거쳐 소스 코드는 기계어 코드인 Object 파일(.o 확장자)로 번역되지만, 해당 Object 파일은 ELF 형식이지만 `executable`이 아닌 `relocatable` 형식으로 실제로 실행할 수 없다. 

그 이유는 오브젝트 파일은 대표적으로 라이브러리 함수와 같이 어셈블 단계에서 찾은 **심볼**들이 기록은 되어 있지만 심볼에 대한 자세한 내용이 하나도 기록되어 있지 않기 때문이다. 즉 오브젝트 파일에서는 심볼이 존재만 할 뿐 라이브러리 함수들의 정의와 내용이 어디 있는지 알 수 없다.

오브젝트 파일에 존재하는 **심볼들의 정보를 찾아서 실행 파일에 기록**하는 것이 바로 Link 과정 중에 일어나는 일이다.

아래의 코드를 예시로 링크 전, 후를 비교해보자.
```
// Name: hello-world.c
// Compile: gcc -o hello-world hello-world.c

#include <stdio.h>

int main() {
  puts("Hello, world!");
  return 0;
}
```
링크 전의 오브젝트 파일을 아래의 명령어로 파악해보면, 심볼의 정보가 기록되어있지 않기 때문에 라이브러리 함수들의 정의가 어디 있는지 알지 못하므로 실행이 불가능하다. 아래와 같이 `puts`의 선언이 <stdio.h>에 있어서 **심볼**은 존재하지만 정보는 아예 없다. 해당 심볼의 정보를 찾아서 기록하는 것이 링크 과정에서 일어나는 일이다.

```
$ readelf -s hello-world.o | grep puts
    11: 0000000000000000     0 NOTYPE  GLOBAL DEFAULT  UND puts
```

아래와 같이 링크 후에는 `libc`에서 `puts`의 정의를 찾아서 연결한다. 
```
$ gcc -o hello-world hello-world.c
$ readelf -s hello-world | grep puts
     2: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND puts@GLIBC_2.2.5 (2)
    46: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND puts@@GLIBC_2.2.5
$ ldd hello-world  --> ldd는 라이브러리 의존성을 확인하는 명령어이다. 
        linux-vdso.so.1 (0x00007ffec3995000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fee37831000)
        /lib64/ld-linux-x86-64.so.2 (0x00007fee37e24000)
```
여기서 `libc` 라이브러리를 같이 컴파일하지 않아도 `libc`에서 오브젝트 파일에 존재하는 심볼을 탐색한 것은 `libc`가 있는 `/lib/x86_64-linux-gnu/`가 표준 라이브러리 경로에 포함되어 있기 때문이다. 

gcc는 소스 코드를 컴파일할 때 표준 라이브러리의 라이브러리 파일들을 모두 탐색하기 때문이다. 아래의 정리된 명령어로 표준 라이브러리의 경로를 확인할 수 있다.
```
$ ld --verbose | grep SEARCH_DIR | tr -s ' ;' '\n'
SEARCH_DIR("=/usr/local/lib/x86_64-linux-gnu")
SEARCH_DIR("=/lib/x86_64-linux-gnu")
SEARCH_DIR("=/usr/lib/x86_64-linux-gnu")
SEARCH_DIR("=/usr/lib/x86_64-linux-gnu64")
SEARCH_DIR("=/usr/local/lib64")
SEARCH_DIR("=/lib64")
SEARCH_DIR("=/usr/lib64")
SEARCH_DIR("=/usr/local/lib")
SEARCH_DIR("=/lib")
SEARCH_DIR("=/usr/lib")
SEARCH_DIR("=/usr/x86_64-linux-gnu/lib64")
SEARCH_DIR("=/usr/x86_64-linux-gnu/lib")
```
링크를 거치고 나면 프로그램에서 puts를 호출할 때, puts의 정의가 있는 libc에서 puts의 코드를 찾고, 해당 코드를 실행하게 된다.

## Static Link vs Dynamic Link
동적 라이브러리를 링크 하는 것을 동적 링크, 정적 라이브러리를 링크하는 것을 정적 링크라고 부른다. 이를 더 자세히 비유와 함께 알아보면,

### 동적 링크

동적 링크된 바이너리를 실행하면 **동적 라이브러리가 프로세스의 메모리에** 매핑된다. 그리고 실행중에 라이브러리의 함수를 호출하면 매핑된 라이브러리에서 호출할 함수의 주소를 찾고, 그 함수를 실행한다.

![](https://img1.daumcdn.net/thumb/R1280x0/?scode=mtistory2&fname=https%3A%2F%2Fblog.kakaocdn.net%2Fdn%2Fc1BYgt%2FbtrR9el15uI%2FrCsKnC4mp606Ex7edukL1k%2Fimg.png)

### 정적 링크

정적 링크를 하면 **바이너리에 정적 라이브러리의 필요한 모든 함수가** 포함된다. 따라서, 해당 함수를 호출할 때 라이브러리를 참조하는 것이 아니라, 자신이 정의한 함수를 호출하는 것처럼 호출할 수 있다. 

동적 링크와 달리 라이브러리에서 원하는 함수를 찾지 않아도 되서 탐색의 비용이 절감될 수 있지만, 여러 바이너리에서 같은 라이브러리를 사용하면 동일한 라이브러리 복제가 여러 번 이루어지기 때문에 용량을 낭비하게 된다.

***정적 링크 시 컴파일 옵션에 따라 include 한 헤더의 함수가 모두 포함 될 수도 있고 그렇지 않을 수도 있다.***

![](https://img1.daumcdn.net/thumb/R1280x0/?scode=mtistory2&fname=https%3A%2F%2Fblog.kakaocdn.net%2Fdn%2FPaufb%2FbtrR8zdbufz%2FlrdVMoqdq5SqBSzMTkjXWk%2Fimg.png)

## 실제 바이너리 비교

```
$ gcc -o static hello-world.c -static   --> 정적 링크
$ gcc -o dynamic hello-world.c -no-pie  --> 동적 링크
```

`dynaic [source] -static` 으로 정적 링크를, `dynamic [source]` 으로 동적 링크를 할 수 있다. (-no-pie는 PIE 없애서 ASLR 없애는거)

```
$ ls -lh ./static ./dynamic
-rwxrwxr-x 1 dreamhack dreamhack  16K May 22 02:01 ./dynamic
-rwxrwxr-x 1 dreamhack dreamhack 880K May 22 02:01 ./static
```

위와 같이 서로의 바이너리 크기를 비교해보면 정적 링크된 바이너리가 동적 링크된 바이너리보다 약 50배 가까운 용량을 더 많이 차지한다.

### 호출 방법

`static` 에서는 `puts` 함수의 정의가 존재하는 실제 메모리 주소를 호출하는 반면, `dynamic` 에서는 `put`의 `plt주소`를 호출한다.

이러한 차이가 발생하는 이유는 정적 링크에서는 정적 라이브러리의 함수 자체를 바이너리에 포함시키지만, 동적 링크에서는 동적 라이브러리를 메모리에 매핑시킨 후 바이너리 실행 시 해당 매핑 메모리에서 함수의 주소를 **찾아야** 하기 때문이다.

***동적 링크 시에 미리 메모리에 매핑된 동적 라이브러리에서 함수의 주소를 찾아서 기록해두지 않는 이유는 바이너리 실행마다 ASLR에 의해 동적 라이브러리의 메모리가 변할 수 있기 때문이다.***

**static**
```
main:
  push   rbp
  mov    rbp,rsp
  lea    rax,[rip+0x96880] # 0x498004
  mov    rdi,rax
  call   0x40c140 <puts>
  mov    eax,0x0
  pop    rbp
  ret
```

**dynamic**
```
main: 
 push   rbp
 mov    rbp,rsp
 lea    rdi,[rip+0xebf] # 0x402004
 mov    rdi,rax
 call   0x401040 <puts@plt>
 mov    eax,0x0
 pop    rbp
 ret
 ```

## PLT & GOT

**PLT(Procedure Linkage Table)** 와 **GOT(Global Offset Table)** 는 라이브러리에서 동적 링크된 **심볼의 주소를 찾을 때** 사용하는 테이블이다.

바이너리가 실행될 때마다 ASLR에 따라 동적 라이브러리가 임의의 주소에 매핑되기 때문에(바뀌기 때문에) 링크 단계에서 미리 라이브러리의 주소를 하나로 확정지을 수 없다. 따라서, 심볼의 주소를 찾기 위해서는 심볼의 이름을 바탕으로 라이브러리에서 심볼들을 탐색하고, 해당 심볼의 정의를 발견하면 그 주소로 실행 흐름을 옮기게 된다. 이 전 과정을 통틀어 **runtime resolve**라고 하는데, 이에 대해서는 나중에 다시 알아보자.

하지만, 여기서 라이브러리의 함수(심볼)가 바이너리에서 여러번 쓰인 경우 함수를 호출할 때 마다 라이브러리에서 계속 함수의 정의를 탐색해야 한다면 매우 비효율적일 것이다.   
**그래서 ELF는 `GOT`라는 테이블을 두고 resolve된 심볼의 주소를 해당 테이블에 저장한다.** 그러면 같은 함수를 다시 호출할 때, GOT에 저장된 함수의 주소를 호출하여 다시 라이브러리를 탐색하는 비효율적인 작업을 없앨 수 있다.

아래는 GOT를 확인하기 위한 예제 코드이다.
```
// Name: got.c
// Compile: gcc -o got got.c -no-pie
#include <stdio.h>

int main() {
  puts("Resolving address of 'puts'.");
  puts("Get address from GOT");
}
```

*** 참고로 나는 PLT없이도 GOT만으로 동적 링킹이 가능하다고 생각했는데, 함수 주소 찾는 것만으로는 기술적으로 GOT만 이용하여 가능하지만 함수 바인딩이나 최적화에서 PLT가 필요하다고 한다.***

### resolve 되기 전

먼저 got.c를 컴파일하고 실행한 직후에, **GOT의 상태를 보여주는 명령어인** `got`를 사용해보면, `puts` 함수의 GOT 엔트리인 `0x404018`에는 아직 `puts`의 주소를 찾기 전이므로 함수 주소 대신 .plt 섹션 어딘가의 주소인 `0x401030`이 적혀있다.

```
$ gdb ./got
pwndbg> entry
pwndbg> got
GOT protection: Partial RELRO | GOT functions: 1
[0x404018] puts@GLIBC_2.2.5 -> 0x401030 ◂— endbr64

pwndbg> plt
Section .plt 0x401020-0x401040:
No symbols found in section .plt
pwndbg>
```

`main()`에서 `puts@plt`를 호출하는 부분에 break를 걸고 run 후 si로 `puts@plt` 내부로 들어가면, resolve 전에는 위에서 확인했듯이 puts의 **GOT** 엔트리에 쓰인 값인 `0x401030`으로 실행 흐름을 옮긴다. `0x401030`은 뒤에서 resolve를 위한 주소이다. 

이후 계속 실행 흐름을 따라가면 `0x401020`으로 점프 후 `<_dl_runtime_resolve_fxsave>`함수의 주소로 점프하는 것을 알 수 있다.  
해당 함수의 이름에서 알 수 있듯이 동적 링크 과정에서 resolve를 하는 함수라는 것을 유추할 수 있다.

```
pwndbg> b *main+18
pwndbg> c
...
──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────
   0x40113e <main+8>     lea    rax, [rip + 0xebf]
   0x401145 <main+15>    mov    rdi, rax
 ► 0x401148 <main+18>    call   puts@plt                      <puts@plt>
        s: 0x402004 ◂— "Resolving address of 'puts'."
...
pwndbg> si
...
──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────
 ► 0x401040       <puts@plt>                        endbr64
   0x401044       <puts@plt+4>                      bnd jmp qword ptr [rip + 0x2fcd]     <0x401030>
    ↓
   0x401030                                         endbr64
   0x401034                                         push   0
   0x401039                                         bnd jmp 0x401020                     <0x401020>
    ↓
   0x401020                                         push   qword ptr [rip + 0x2fe2]      <_GLOBAL_OFFSET_TABLE_+8>
   0x401026                                         bnd jmp qword ptr [rip + 0x2fe3]     <_dl_runtime_resolve_fxsave>
    ↓
   0x7ffff7fd8be0 <_dl_runtime_resolve_fxsave>      endbr64
   0x7ffff7fd8be4 <_dl_runtime_resolve_fxsave+4>    push   rbx
   0x7ffff7fd8be5 <_dl_runtime_resolve_fxsave+5>    mov    rbx, rsp
   0x7ffff7fd8be8 <_dl_runtime_resolve_fxsave+8>    and    rsp, 0xfffffffffffffff0
...
```

이후 `<_dl_runtime_resolve_fxsave+8>` 함수에 진입 후 `finish`를 통해 함수를 전부 수행 후 빠져나오면 `Resolving address of 'puts'.`라는 출력과 함께 `puts` 함수가 resolve 되었음을 확인할 수 있다.

`got` 명령어로 확인해보면 **GOT 엔트리**인 `0x404018`에 이전과 달리 .plt 섹션이 아닌 실제 puts 함수의 주소인 `0x7ffff7e02ed0`이 기록되어 있는 것을 알 수 있다.

그리고 `vmmap`으로 GOT 엔트리에 저장된 주소를 살펴보면 `/usr/lib/x86_64-linux-gnu/libc.so.6 +0x58ed0`로 `libc` 랑비ㅡ러리의 `0x58ed0` offset만큼 떨어진 `puts` 함수가 저장되어 있다는 것을 알 수 있다.

```
pwndbg> ni
...
pwndbg> ni
_dl_runtime_resolve_fxsave () at ../sysdeps/x86_64/dl-trampoline.h:67
67  ../sysdeps/x86_64/dl-trampoline.h: No such file or directory.
...
──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────
   0x401030                                          endbr64
   0x401034                                          push   0
   0x401039                                          bnd jmp 0x401020                     <0x401020>
    ↓
   0x401020                                          push   qword ptr [rip + 0x2fe2]      <_GLOBAL_OFFSET_TABLE_+8>
   0x401026                                          bnd jmp qword ptr [rip + 0x2fe3]     <_dl_runtime_resolve_fxsave>
    ↓
 ► 0x7ffff7fd8be0 <_dl_runtime_resolve_fxsave>       endbr64
   0x7ffff7fd8be4 <_dl_runtime_resolve_fxsave+4>     push   rbx
   0x7ffff7fd8be5 <_dl_runtime_resolve_fxsave+5>     mov    rbx, rsp
   0x7ffff7fd8be8 <_dl_runtime_resolve_fxsave+8>     and    rsp, 0xfffffffffffffff0
   0x7ffff7fd8bec <_dl_runtime_resolve_fxsave+12>    sub    rsp, 0x240
   0x7ffff7fd8bf3 <_dl_runtime_resolve_fxsave+19>    mov    qword ptr [rsp], rax
...
pwndbg> finish
Run till exit from #0  _dl_runtime_resolve_fxsave () at ../sysdeps/x86_64/dl-trampoline.h:67
Resolving address of 'puts'.
...
──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────
   0x401148 <main+18>    call   puts@plt                      <puts@plt>

 ► 0x40114d <main+23>    lea    rax, [rip + 0xecd]
   0x401154 <main+30>    mov    rdi, rax
   0x401157 <main+33>    call   puts@plt                      <puts@plt>

   0x40115c <main+38>    mov    eax, 0
   0x401161 <main+43>    pop    rbp
   0x401162 <main+44>    ret

   0x401163              add    bl, dh
...
pwndbg> got
GOT protection: Partial RELRO | GOT functions: 1
[0x404018] puts@GLIBC_2.2.5 -> 0x7ffff7e02ed0 (puts) ◂— endbr64
pwndbg> vmmap 0x7ffff7e02ed0
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
             Start                End Perm     Size Offset File
    0x7ffff7daa000     0x7ffff7f3f000 r-xp   195000  28000 /usr/lib/x86_64-linux-gnu/libc.so.6 +0x58ed0
```
![](https://img1.daumcdn.net/thumb/R1280x0/?scode=mtistory2&fname=https%3A%2F%2Ft1.daumcdn.net%2Fcfile%2Ftistory%2F183D6C384FA75CE924)

![](https://blog.kakaocdn.net/dn/7JQnw/btq2Mz1JBcE/KIxbMlvMwcuWiY31ikausK/img.png)

### resolve 된 후

소스 코드에서 `puts@plt`를 두 번째로 호출할 때는 `puts`의 GOT 엔트리에 실제 `puts`의 주소인 `0x7ffff7e02ed0`가 쓰여있기 때문에 바로 `puts` 함수가 호출된다.

```
pwndbg> b *main+33
pwndbg> c
...
──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────
   0x401148 <main+18>    call   puts@plt                      <puts@plt>

   0x40114d <main+23>    lea    rax, [rip + 0xecd]
   0x401154 <main+30>    mov    rdi, rax
 ► 0x401157 <main+33>    call   puts@plt                      <puts@plt>
        s: 0x402021 ◂— 'Get address from GOT'
...
pwndbg> si
...
──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────
 ► 0x401040       <puts@plt>      endbr64
   0x401044       <puts@plt+4>    bnd jmp qword ptr [rip + 0x2fcd]     <puts>
    ↓
   0x7ffff7e02ed0 <puts>          endbr64
   0x7ffff7e02ed4 <puts+4>        push   r14
   0x7ffff7e02ed6 <puts+6>        push   r13
   0x7ffff7e02ed8 <puts+8>        push   r12
   0x7ffff7e02eda <puts+10>       mov    r12, rdi
   0x7ffff7e02edd <puts+13>       push   rbp
   0x7ffff7e02ede <puts+14>       push   rbx
   0x7ffff7e02edf <puts+15>       sub    rsp, 0x10
   0x7ffff7e02ee3 <puts+19>       call   *ABS*+0xa8720@plt                <*ABS*+0xa8720@plt>
...
```
![](https://img1.daumcdn.net/thumb/R1280x0/?scode=mtistory2&fname=https%3A%2F%2Ft1.daumcdn.net%2Fcfile%2Ftistory%2F114FE5384FA75CEA0A)

![](https://blog.kakaocdn.net/dn/bQ0Qlg/btq2NEVyK9u/w6JdSGA8hi8CFDTbcy8GS0/img.png)

## PLT와 GOT 취약점을 이용한 공격 기법

PLT와 GOT는 동적 라이브러리에서 함수의 주소를 찾고 기록할 때 사용되는 중요한 테이블이다. 그런데, 여기서 PLT가 GOT 앤트리에 저장된 함수의 주소를 참조하여 실행 흐름을 옮길 때, GOT의 값을 검증하지 않는다는 취약점이 존재한다.

따라서, 만약 공격자가 GOT 앤트리 주소에 저장된 값을 임의로 변경할 수 있다면 PLT로 의도했던 함수의 주소를 호출할 때 그 함수가 아닌 우리가 공격하려고 하는 쉘코드가 담긴 주소로 이동시킬 수 있다.

아래와 같이 GOT 앤트리에 저장된 값을 임의로 변조하여 `got` 바이너리에서 두 번째 `puts()`호출 직전에 `puts`의 GOT 앤트리를 "AAAAAAAA"로 변경하면 실제로 "AAAAAAAA"로 실행 흐름이 옮겨지게 된다.
```
$ gdb -q ./got
pwndbg> b *main+33
pwndbg> r
...
──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────
 ► 0x401157 <main+33>    call   puts@plt                      <puts@plt>
        s: 0x402021 ◂— 'Get address from GOT'

   0x40115c <main+38>    mov    eax, 0
pwndbg> got
GOT protection: Partial RELRO | GOT functions: 1
[0x404018] puts@GLIBC_2.2.5 -> 0x7ffff7e02ed0 (puts) ◂— endbr64

pwndbg> set *(unsigned long long *)0x404018 = 0x4141414141414141

pwndbg> got
GOT protection: Partial RELRO | GOT functions: 1
[0x404018] puts@GLIBC_2.2.5 -> 0x4141414141414141 ('AAAAAAAA')
pwndbg> c
Continuing.

Program received signal SIGSEGV, Segmentation fault.
0x0000000000401044 in puts@plt ()
...
──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────
 ► 0x401044 <puts@plt+4>    bnd jmp qword ptr [rip + 0x2fcd]     <0x4141414141414141>
 ```

위와 같이 **GOT 엔트리에 임의의 값을 Overwrite 하여 실행 흐름을 변조하는 공격 기법을 `GOT Overwrite`**라고 부른다.  
일반적으로 임의 주소에 임의의 값을 오버라이트하는 수단을 가지고 있을 때 수행하는 공격 기법이다.
