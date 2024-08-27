## 서론

**Background:Library** 강의에서 ELF는 PLT와 GOT를 활용하여 라이브러리의 함수를 모두 바이너리에 넣는 정적 링킹이 아닌 필요한 함수만 호출할 때마다 바이너리에 넣는 동적 링킹을 사용한다고 하였다. 

여기에서 함수를 호출할 때 GOT에 라이브러리의 함수가 매핑된 주소를 적는 **Lazy Binding**을 사용하는데, 이는 바이너리의 크기와 컴파일 시간을 줄여주기 때문에 효율적인 방법이다.

그러나, 레이지 바인딩을 하게 되면 바이너리 실행 중에 GOT 테이블을 업데이트해야하기 때문에, GOT 영역에 `write` 권한이 부여된다.

이는 `NX`에서 `stack`에 실행 권한을 제거한 것처럼 `GOT Overwrite`를 발생시켜 공격자가 원하는 함수를 라이브러리에서 찾아 수행하게 하는 취약점을 발생시킨다.

또한, ELF의 데이터 세그먼트에는 프로세스의 초기화 및 종료와 관련된 `.init_array`, `.fini_array`가 있는데 이 영역들은 **프로세스의 시작과 종료에 실행할 함수들의 주소**를 저장하고 있기 때문에, 여기에 공격자가 임의로 값을 쓸 수 있다면 프로세스의 실행 흐름이 조작될 수 있다.

리눅스 개발자들은 이러한 취약점을 해결하고자 프로세스의 데이터 세그먼트를 보호하는 `RELocatin Read-Only(RELRO)` 기법을 개발하게 되었다.

RELRO는 쓰기 권한이 불필요한 데이터 세그먼트에 쓰기 권한을 제거하여 바이너리의 취약점을 보완하는 기법이다.

RELRO는 적용 범위에 따라 RELRO를 부분적으로 적용하는 `Partial RELRO`, RELRO를 가장 넓은 영역에 적용하는 `Full RELRO`가 존재한다.

이번 강의에서는 각각의 특징고 우회 방법에 대해 배워보겠다.

## Partial RELRO

```
// Name: relro.c
// Compile: gcc -o prelro relro.c -no-pie -fno-PIE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main() {
  FILE *fp;
  char ch;
  fp = fopen("/proc/self/maps", "r");
  while (1) {
    ch = fgetc(fp);
    if (ch == EOF) break;
    putchar(ch);
  }
  return 0;
}
```

위 코드는 자신의 메모리 맵을 출력하는 바이너리의 소스 코드 예시이다.

실습 환경의 gcc는 Full RELRO를 기본 적용하며, **PIE를 해제하면 Partial RELRO를 적용한다.**

### Partial RELRO 권한

`gcc -o prelro relro.c -no-pie -fno-PIE`를 통해 PIE가 적용되지 않은 `prelro`를 실행해보면 `0x404000`부터 `0x405000`까지의 주소에 아래와 같이 실행 권한이 존재함을 확인할 수 있다.

```
$ ./prelro
00400000-00401000 r--p 00000000 08:02 2886150                            /home/dreamhack/prelro
00401000-00402000 r-xp 00001000 08:02 2886150                            /home/dreamhack/prelro
00402000-00403000 r--p 00002000 08:02 2886150                            /home/dreamhack/prelro
00403000-00404000 r--p 00002000 08:02 2886150                            /home/dreamhack/prelro
00404000-00405000 rw-p 00003000 08:02 2886150                            /home/dreamhack/prelro
0130d000-0132e000 rw-p 00000000 00:00 0                                  [heap]
7f108632c000-7f108632f000 rw-p 00000000 00:00 0
7f108632f000-7f1086357000 r--p 00000000 08:02 132492                     /usr/lib/x86_64-linux-gnu/libc.so.6
7f1086357000-7f10864ec000 r-xp 00028000 08:02 132492                     /usr/lib/x86_64-linux-gnu/libc.so.6
7f10864ec000-7f1086544000 r--p 001bd000 08:02 132492                     /usr/lib/x86_64-linux-gnu/libc.so.6
7f1086544000-7f1086548000 r--p 00214000 08:02 132492                     /usr/lib/x86_64-linux-gnu/libc.so.6
7f1086548000-7f108654a000 rw-p 00218000 08:02 132492                     /usr/lib/x86_64-linux-gnu/libc.so.6
7f108654a000-7f1086557000 rw-p 00000000 00:00 0
7f1086568000-7f108656a000 rw-p 00000000 00:00 0
7f108656a000-7f108656c000 r--p 00000000 08:02 132486                     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f108656c000-7f1086596000 r-xp 00002000 08:02 132486                     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f1086596000-7f10865a1000 r--p 0002c000 08:02 132486                     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f10865a2000-7f10865a4000 r--p 00037000 08:02 132486                     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f10865a4000-7f10865a6000 rw-p 00039000 08:02 132486                     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7ffe55580000-7ffe555a1000 rw-p 00000000 00:00 0                          [stack]
7ffe555de000-7ffe555e2000 r--p 00000000 00:00 0                          [vvar]
7ffe555e2000-7ffe555e4000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0
```

`objdump -h ./prelro`에서 `-h` 옵션을 통해 섹션 헤더를 참조해보면, 해당 영역에는 아래와 같이 `.got.plt`, `.data`, `.bss`가 할당되어 있다. 

따라서, 위 영역에 대해서는 `write` 권한이 존재하기 때문에 데이터를 변조할 수 있다. 반면, `.init_array`와 `.fini_array`는 각각 `0x403e10` 과 `0x403e18` 에 할당되어 있는데 모두 쓰기 권한이 없는 `00403000-00404000` 사이에 존재하므로 쓰기가 불가능하다.

바이너리의 시작과 종료 함수의 메모리 주소를 조작할 수는 없지만, `.got.plt`와 `.data`, `.bss` 영역은 조작이 가능하므로 `GOT Overwrite` 기법이 여전히 가능함을 알 수 있다.

### 참고 : `.got`와 `.got.plt`의 차이

Partial RELRO가 적용된 바이너리에는 got와 관련된 섹션이 `.got`와 `.got.plt`로 두개가 존재한다.

전역 변수 중에서 바이너리가 실행되는 시점에 바인딩(**Now Binidng**) 되는 변수는 `.got`에 위치하게 되고, 바이너리가 실행될 때 이미 바인딩이 완료되어있기 때문에 이 영역에 쓰기 권한을 부여할 필요가 없다.

반면, 실행중에 바인딩(**Lazy Binding**)이 적용되는 변수는 `.got.plt`에 위치하게 된다. 이 영역은 해당 함수가 호출될 때 매핑된 메모리 주소 값이 써지므로 쓰기 권한이 부여된다.

`Partial RELRO`가 적용된 바이너리에서 대부분의 함수의 GOT 엔트리는 우리가 계속 봤듯이 `.got.plt`에 저장되게 되고, 해당 영역을 우리가 `GOT Overwrite`하게 된다.

## Full RELRO

`gcc -o frelro relro.c`처럼 위의 소스 코드를 PIE를 적용하여 기본 gcc로 컴파일하면 Full RELRO가 적용된 바이너리가 생성된다. 

`frelro`를 실행하여 메모리 맵을 확인하고 이를 섹션 헤더 정보와 종합해보면, **`.got`에는 쓰기 권한이 제거되어 있으며 `.data`와 `.bss` 영역에만 쓰기 권한이 부여된다.**

```
$ ./frelro
563782c64000-563782c65000 r--p 00000000 08:02 2886178                    /home/dreamhack/frelro
563782c65000-563782c66000 r-xp 00001000 08:02 2886178                    /home/dreamhack/frelro
563782c66000-563782c67000 r--p 00002000 08:02 2886178                    /home/dreamhack/frelro
563782c67000-563782c68000 r--p 00002000 08:02 2886178                    /home/dreamhack/frelro
563782c68000-563782c69000 rw-p 00003000 08:02 2886178                    /home/dreamhack/frelro
563784631000-563784652000 rw-p 00000000 00:00 0                          [heap]
7f966f91f000-7f966f922000 rw-p 00000000 00:00 0
7f966f922000-7f966f94a000 r--p 00000000 08:02 132492                     /usr/lib/x86_64-linux-gnu/libc.so.6
7f966f94a000-7f966fadf000 r-xp 00028000 08:02 132492                     /usr/lib/x86_64-linux-gnu/libc.so.6
7f966fadf000-7f966fb37000 r--p 001bd000 08:02 132492                     /usr/lib/x86_64-linux-gnu/libc.so.6
7f966fb37000-7f966fb3b000 r--p 00214000 08:02 132492                     /usr/lib/x86_64-linux-gnu/libc.so.6
7f966fb3b000-7f966fb3d000 rw-p 00218000 08:02 132492                     /usr/lib/x86_64-linux-gnu/libc.so.6
7f966fb3d000-7f966fb4a000 rw-p 00000000 00:00 0
7f966fb5b000-7f966fb5d000 rw-p 00000000 00:00 0
7f966fb5d000-7f966fb5f000 r--p 00000000 08:02 132486                     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f966fb5f000-7f966fb89000 r-xp 00002000 08:02 132486                     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f966fb89000-7f966fb94000 r--p 0002c000 08:02 132486                     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f966fb95000-7f966fb97000 r--p 00037000 08:02 132486                     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f966fb97000-7f966fb99000 rw-p 00039000 08:02 132486                     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7ffc1bace000-7ffc1baef000 rw-p 00000000 00:00 0                          [stack]
7ffc1bb22000-7ffc1bb26000 r--p 00000000 00:00 0                          [vvar]
7ffc1bb26000-7ffc1bb28000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]
```

아래에서 볼 수 있듯이 `.data` 섹션의 오프셋은 `0x4000`인데, 이를 `/home/dreamhack/frelro`가 매핑된 `0x563782c64000`에 더하면, `0x563782c68000`이 되며, 이는 쓰기 권한이 있는 영역에 속하게 된다. 

`.bss` 섹션 역시 동일한 방법으로 매핑된 주소를 계산해보면 `0x563782c68010`가 나오며 마찬가지로 쓰기 권한이 존재하는 영역에 속한다.

하지만, `.got`와 `.init_array`, `.fini_array`의 오프셋을 계산해보면 쓰기 권한이 없는 영역에 속한다.

여기서 `.got.plt`가 존재하지 않는 이유는 Full RELRO가 적용되면 사용되는 모든 라이브러리 함수들의 주소가 `Lazy Binding`이 아닌 `Now Binding`으로 바이너리 로딩(실행) 시점에 모두 바인딩 되기 때문에 GOT에는 쓰기 권한이 부여되지 않아도 되기 때문이다.

그래서 Full RELRO가 적용되면 **GOT Overwrite 기법을 통한 GOT 조작이 불가능하다.**

## RELRO 우회

**Partial RELRO의 경우** `.init_array`와 `.fini_array`를 조작는 것은 불가능하지만, `GOT Overwrite`는 여전히 사용할 수 있다.

그러나, **Full RELRO의 경우** Partial RELRO에 더해 `GOT Overwrite`도 불가능하기 때문에 공격이 매우 제한된다.

**이를 해결하기 위해 공격자들이 덮어쓸 수 있는 다른 함수 포인터를 찾다가 라이브러리에 위치한 `hook`을 찾아내게 되었다.**

라이브러리 함수의 대표적인 `hook`이 `malloc hook`과 `free hook`인데, 원래 이 함수 포인터는 동적 메모리 할당과 해제 과정에서 발생하는 버그를 디버깅하기 쉽도록 만들어진 용도의 함수 포인터이다.

아래와 같이 `mallo`c 함수의 코드를 살펴보면, 함수의 시작 부분에서 `__malloc_hook`이 존재하는지 검사하고, 존재하면 이를 호출한다.

`__malloc_hook`은 `libc.so`에서 쓰기 가능한 영역에 위치한다. 따라서 공격자는 `libc`가 매핑된 주소를 알 때, 이 변수를 조작하고 `malloc`을 호출하여 실행 흐름을 조작할 수 있다. 

이와 같은 공격 기법을 통틀어 `Hook Overwrite`라고 부른다. 이에 대해서는 다음 강의에서 예제와 함께 자세히 살펴보자.

```
void *
__libc_malloc (size_t bytes)
{
  mstate ar_ptr;
  void *victim;
  void *(*hook) (size_t, const void *)
    = atomic_forced_read (__malloc_hook); // read hook
  if (__builtin_expect (hook != NULL, 0))
    return (*hook)(bytes, RETURN_ADDRESS (0)); // call hook
#if USE_TCACHE
  /* int_free also calls request2size, be careful to not pad twice.  */
  size_t tbytes;
  checked_request2size (bytes, tbytes);
  size_t tc_idx = csize2tidx (tbytes);
  // ...
```


## 정리

- **RELocation Read-Only(RELRO)**: 불필요한 데이터 영역에 쓰기 권한을 제거함.

- **Partial RELRO**: `.init_array`, `.fini_array` 등 여러 섹션에 쓰기 권한을 제거함. **Lazy binding을 사용**하므로 라이브러리 함수들의 GOT 엔트리는 쓰기가 가능함. **GOT Overwrite등의 공격으로 우회가 가능함.**

- **Full RELRO**: `.init_array`, `.fini_array` 뿐만 아니라 **GOT에도 쓰기 권한을 제거**함. **Lazy binding을 사용하지 않으며** 라이브러리 함수들의 주소는 바이너리가 로드되는 시점에 바인딩됨.   
libc의 malloc hook, free hook과 같은 함수 포인터를 조작하는 공격으로 우회할 수 있음. => **Hook Overwrite**
