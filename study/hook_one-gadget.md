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

## 익스플로잇 코드

```

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
