# Tcache_Poisoning

`Tcache Poisoning`은 `tcache`를 조작하여 **임의 주소에 청크를 할당**시키는 공격 기법을 말한다.

## 원리

동일한 청크가 `Double Free`로 중복으로 연결된 청크를 재할당하면, 그 청크는 할당된 청크이면서 동시에 해제된 청크가 된다. 

따라서, `duplicated free list`가 만들어지고, 청크의 구조를 떠올려 보면 이러한 중첩 상태가 어떻게 문제로 이어지는지 이해할 수 있다.

![청크의 중첩 상태](https://dreamhack-lecture.s3.amazonaws.com/media/2aa990d00c2ac06e318958f5f2a68a7218602c8a2b9ae50169305c9b8364eec7.gif)

위 이미지에서 왼쪽은 `할당된 청크`의 레이아웃이고, 오른쪽은 `해제된 청크`의 레이아웃인데, 이 둘을 겹쳐보면 **할당된 청크에서 데이터를 저장하는 부분**이 **해제된 청크에서는 `fd` 와 `bk` 값을 저장하는 데 사용(`tcache`에서는 `next`와 `key` 저장)** 된다는 것을 알 수 있다.

따라서 공격자가 중첩 상태인 청크에 임의의 값을 쓸 수 있다면, 그 청크의 `fd` 와 `bk` 를 조작할 수 있으며, **이는 다시 말해 `ptmalloc2` 의 `free list`에 임의 주소를 추가할 수 있음을 의미한다.**

왜냐하면, `ptmalloc2`는 `free list`에 존재하는 청크들의 `fd`와 `bk`를 보고 어떤 청크가 존재하는지 파악하기 때문에, 사용자가 원하는 주소를 `fd`나 `bk`로 추가하면 그 주소의 청크가 `free list`에 추가되는 것과 같기 때문이다.

## 효과

이렇게 되면 `free list`에 추가된 임의의 주소들에 대한 청크들을 `malloc`으로 할당해서, 해당 **청크에 저장되있는 값을 출력**하거나,

해당 청크의 데이터를 조작할 수 있다면, **임의 주소 읽기(Arbitrary Address Read, AAR)** 와 **임의 주소 쓰기(Arbitrary Address Write, AAW)** 가 가능하다.

그럼 이제 이 내용을 통해 `Tcache_Poisoning` 워게임을 풀이해보자.

# 바이너리 분석

```
// Name: tcache_poison.c
// Compile: gcc -o tcache_poison tcache_poison.c -no-pie -Wl,-z,relro,-z,now

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main()
{
  void *chunk = NULL;
  unsigned int size;
  int idx;

  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);

  while (1)
  {
    printf("1. Allocate\n");
    printf("2. Free\n");
    printf("3. Print\n");
    printf("4. Edit\n");
    scanf("%d", &idx);

    switch (idx)
    {
    case 1:
      printf("Size: ");
      scanf("%d", &size);
      chunk = malloc(size);
      printf("Content: ");
      read(0, chunk, size - 1);
      break;
    case 2:
      free(chunk);
      break;
    case 3:
      printf("Content: %s", chunk);
      break;
    case 4:
      printf("Edit chunk: ");
      read(0, chunk, size - 1);
      break;
    default:
      break;
    }
  }

  return 0;
}
```

<img width="677" alt="image" src="https://github.com/user-attachments/assets/7d2f49f5-f517-4b58-8c99-0c5938885a2f">

먼저, `checksec`으로 보호 기법을 살펴보면, `Full RELRO`가 적용되어 있기 때문에 `GOT Overwrite`는 불가능하고 대신 `libc-2.27.so` 버전을 쓰기 때문에 `hook Overwrite`가 가능하다는 것을 생각해볼 수 있다.

그리고 `PIE`가 적용되지 않았기 때문에 `stack, heap, 공유 library`의 주소를 제외하고는 가상 주소가 고정되어 있다는 것도 알 수 있다.

## Double Free Bug

해당 바이너리를 보면, `Double Free Bug`가 발생가능한 조건을 가지고 있다.

`allocate(1)` -> `free(2)` 이후, 해제한 `chunk`의 포인터를 초기화해주지 않았기 때문에 해당 청크에 다시 접근하여 `edit(4)`를 통해 데이터를 수정할 수 있게 된다.

해제되어 `tcache`에 들어온 `chunk`들의 `chunk + 0x8` 주소에는 `key` 값을 저장하고 있다고 했는데, 해당 값은 할당된 상태에서는 데이터를 저장하고 있다가, `tcache`에 들어오면, `tcache_perthread_struct * tcache`의 값을 저장하게 된다고 하였다.

그리고 `free`를 할 때, `e->key == tcache`이면 `Double Free` 에러를 발생시키며 종료하기 때문에 `chunk + 0x8` 주소의 1비트 값만 바꿔줘도 `Double Free` 에러에 걸리지 않고 `Double Free Bug` 취약점을 발생시킬 수 있다.\
(참고로, `tcache`의 `free list`에 저장된 청크들의 주소가 `N`이라면, 소스 코드 상에 존재하는 `chunk`의 주소는 `N + 0x8`이기 때문에 `key` 값도 `header` 이후부터 시작하게 되어서 `chunk + 0x8`에 위치하게 된다. `tcache` 내부의 청크 기준에서는 당연히 `N + 0x18`이다.)

그럼 `edit`을 통해 `chunk`에 랜덤한 `8바이트 + 1바이트(key 조작)` 값을 대입해주면 동일한 청크에 대해 한번 더 `free`를 할 수 있게 된다.

그럼 여기서 이제, 한 `tcache` 엔트리의 Linked List에 동일한 2개의 청크가 연결된 상태가 되어 버린 `Tcache Poison(Duplicated)` 상태가 되기 때문에 임의 주소 읽기, 임의 주소 쓰기가 가능하게 된다.

과정에 대해서는 뒤의 **Exploit**에서 더 자세히 설명해보겠다.

## Leak libc base

`libc_base`를 어떻게 Leak 할지가 중요 포인트인데, `setvbuf(stdout, 0, 2, 0);`를 통해 `stdout`을 등록해주면 `bss 세그먼트`에 해당 `stdout`이 위치하게 되고, 해당 전역 변수는 라이브러리의 `_IO_2_1_stdout_`을 가리키게 된다.

따라서, `stdout`이 가리키는 값인 `_IO_2_1_stdout_`을 Leak한 후에 `libc.symbols['stdout']`을 해당 값에서 빼주면 `libc_base`를 구할 수 있다.

**예전에 gdb에서 찾은 `stdout`은 바이너리의 `bss 세그먼트`에 존재하는 전역 변수(포인터)이고, 실제 입출력은 `libc`에 존재하는`_IO_2_1_stdout_`가 담당하고 해당 값을 `stdout`이 저장하고(가리키고)있다는 것을 잘 기억하자.**

바이너리를 보면 `chunk`의 값을 `print(3)` 해줄 수 있다. 그럼 이를 통해 `chunk`에 `stdout`을 대입해줄 수 있다면, `chunk`를 `print`하는 것이 `stdout`을 `print`하는 것이므로 `stdout`이 가리키는 `_IO_2_1_stdout_`을 출력할 수 있을 것이다.

## Hook Overwrite

`libc_base`를 구했다면, 해당 바이너리에서 `free`를 할 수 있기 때문에 `__free_hook`에 원가젯을 대입해서 쉘을 획득할 수 있을 것이다.

`Tcache Poisoning`을 사용하면 임의 주소 쓰기를 할 수 있다고 하였다.

`tcache`에 존재하는 청크의 `next(fd)`를 조작하여 `__free_hook`을 `tcache`에 추가할 수 있다면, 해당 청크를 `allocate`로 할당하면서 해당 청크에 `og`를 대입해주어서 `__free_hook`이 `og`를 가리키게 될 것이다.

# Exploit

