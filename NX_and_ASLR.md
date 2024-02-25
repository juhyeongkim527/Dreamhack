시스템 보안의 특성상 보호 기법이 생기면 해당 보호 기법을 우회하는 공격 기법이 계속 등장하며 서로 발전해나가기 때문에 언제 어떤 공격이 새롭게 등장할지 예상하기 힘들다.  

따라서 시스템 개발자들은 시스템이 공격당할 수 있는 표면(**Attack Surface**)를 줄이려고 노력하고 있다.  

r2s 워게임에서는 첫째로 **return_address를 조작할 수 있었고**, **변수(버퍼)의 주소를 알 수 있었으며**, **그 변수(버퍼)의 주소에 쉘코드를 실행시킬 수 있었기 때문**에 익스플로잇이 가능했다.  

만약 해당 워게임에 취약점을 제거하려면 위의 3가지를 전부 제거하면 되는데, 첫번째 return_address는 canary를 통해 막을 수 있었지만, 나머지 두 취약점은 해결되지 않았기 때문에 만약 canary를 우회한다면 익스플로잇이 가능했다.  

위 두가지 취약점을 막기 위해서,
- 버퍼의 주소는 **ASLR(Address Space Layout Randomization)**을 통해 막고,
- 버퍼에 쉘코드를 실행하는 것을 막기 위해서는 **NX( No-eXecute()**를 사용한다.

이번 글에서는 위 두가지 보호기법인 **ASLR**과 **NX**에 대해서 알아보자.

## NX (No-eXecute)

NX는 **실행(x)**에 사용되는 메모리 영역과 **쓰기(r)**에 사용되는 메모리 영역을 분리하는 보호 기법이다. 어떤 메모리에 실행과 쓰기 권한이 함께 있으면 해킹에 취약해지기 쉽다.

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

