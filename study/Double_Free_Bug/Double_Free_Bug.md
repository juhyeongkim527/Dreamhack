# 서론

`free` 함수로 할당되어 있던 청크를 해제하면, `ptmalloc`는 크기와 상황에 따라 `tcache`나 `bins`에 해당 청크를 추가하여 관리한다.

이후 `malloc`으로 이전에 해제한 청크와 비슷한 사이즈의 청크를 할당하려고 하면, 이 연결리스트들을 탐색하여 사용했던 청크를 재할당해준다.

`tcache`와 `bins`를 `free list`라고 통칭해보자. 그럼 `free list`의 입장에서 `free`는 청크를 추가하는 함수, `malloc`은 청크를 꺼내는 함수이다.

**여기서, 임의의 청크에 대해 `free`를 두 번 이상 적용할 수 있게 되면, 동일한 청크를 `free list`에 여러 번 추가할 수 있음을 의미한다. 공격자들은 이점에 주목하여 공격 기법을 발명하기 시작했다.**

**청크가 `free list`에 중복해서 존재하면, 해당 청크가 `duplicated` 됐다고 표현하는데, 공격자들은 이 `duplicated free list`를 이용해서 임의 주소에 청크를 할당할 수 있음을 밝혀냈다.**

자세한 방법과 원리는 앞으로 계속 설명할 것이고, 이와 같이 동일한 청크를 중복해서 해제할 수 있는 코드는 취약점으로 분류되어 `Double Free Bug`라고 칭한다.

`ptmalloc2`에서 설명했듯이 `Glibc` 버전에 따라 보호 기법들이 계속 추가되고 기능이 추가되며, 공격 기법이 매우 다양해지고 버전이 높아질수록 공격의 복잡도도 올라간다. 여기선 `Ubuntu 18.04 64-bit (Glibc 2.27)`를 기준으로 설명하겠다.

# `Double Free Bug`

`DFB`는 **동일한 청크를 두 번 이상 `free`할 수 있는 버그**를 말한다. `ptmalloc2`에서 발생하는 버그 중 하나이며, 공격자에게 **임의 주소 읽기, 임의 주소 쓰기,  임의 코드 실행, 서비스 거부 등**의 수단으로 활용될 수 있다.

`UAF`에서 다룬 **`Dangling Pointer`는 `Double Free Bug`를 유발하는 대표적인 원인**이다. 코드 상에서 `Dangling Pointer`가 생성되는지, 그리고 이를 대상으로 `free`를 호출하는 것이 가능한지 살피면 `Double Free Bug`가 존재하는지 가늠할 수 있다.

Double Free Bug를 이용하면 `duplicated free list`를 만드는 것이 가능한데, 이는 청크와 연결리스트의 구조 때문이다. 

ptmalloc2에서 `free list`의 각 청크들은 `fd`와 `bk`로 연결되고, `fd`는 자신보다 **이후**에 해제된 청크를, `bk`는 **이전**에 해제된 청크를 가리킨다. (`tcache`는 `LIFO`이기 때문에 `fd`만 존재)

그런데, 해제된 청크에서 `fd`와 `bk` 값을 저장하는 공간은 다시 재할당되면 청크에서 `데이터`를 저장하는 데 사용된다. 

그러므로 만약 어떤 청크가 `free list`에 중복되어서 `duplicated`되어있는 상황에서, 중복된 청크 중 하나의 청크를 재할당한 후 의도적으로 데이터를 대입해서 `fd`와 `bk` 위치를 조작했을 때, `free list`에 존재하는 청크의 `fd`와 `bk`도 변조되게 된다.

왜냐하면, `malloc`으로 할당된 포인터에는 청크의 주소가 저장되어 있기 때문에 할당된 청크의 데이터를 조작하면, `free list`에 있는 동일한 청크도 조작되기 때문이다.

아래의 모듈은, 인덱스 `0` 청크를 할당 -> 인덱스 `0`번 청크를 2번 `free` -> 다시 인덱스 `0` 청크를 할당 -> 해당 청크에 `data write`를 했을 때의 상황이다.

<img width="562" alt="image" src="https://github.com/user-attachments/assets/4e2fa60f-5db4-42b0-bfe3-8cc74e8d39a8">

이렇게 되면, `allocated chunk list`와 `freed chunk list`에 동일한 청크가 존재하고, `allocated chunk list`의 `chunk 0`의 데이터를 임의 주소로 조작하면, `freed chunk list`의 청크의 `fd`와 `bk` 값도 변조된다.

따라서, 이를 통해 `free list`에 임의 주소를 포함시킬 수 있게 된다.

초기에는 `Double Free`에 대한 검사가 미흡하여 `Double Free Bug`가 있으면 손쉽게 트리거할 수 있었고, 특히 `glibc 2.26` 버전부터 도입된 `tcache`는 도입 당시에 보호 기법이 전무하여 `Double Free`의 쉬운 먹잇감이 되었다.

하지만 시간이 흐르면서 관련한 보호 기법이 `glibc`에 구현되었고 이를 우회하지 않으면 같은 평소에 확인할 수 있듯이 청크를 두 번 해제하는 즉시 프로세스가 `Double Free` 에러를 발생시키며 종료된다.

# 정적 패치 분석

`tcache`에 도입된 보호 기법을 분석하기 위해, 패치된 코드의 [diff](https://sourceware.org/git/?p=glibc.git;a=blobdiff;f=malloc/malloc.c;h=80c600390197df51a355c2130bb2fbe4b80ade13;hp=f8e7250f70f6f26b0acb5901bcc4f6e39a8a52b2;hb=4b246928bd7ffabad7303dffa84ee542450e56d9;hpb=9f433fc791ca4f9d678903ff45b504b524c886fb)를 살펴보자.

## `tcache_entry`

```
typedef struct tcache_entry {
  struct tcache_entry *next;
+ /* This field exists to detect double frees.  */
+ struct tcache_perthread_struct *key;
} tcache_entry;
```

`tcache_entry` 구조체는 **해제된 `tcache` 청크들이 갖는 구조**이다. `diff`에서 추가된 부분을 보면,`Double Free`를 탐지하기 위해 `key` 포인터 추가된 것을 볼 수 있다. 

참고로 앞에서도 얘기했지만, `tcache`에는 `LIFO`로 인해 `fd`만 존재하기 때문에 `fd`와 같은 의미로 사용되는 `next` 포인터만 존재하는 것을 살펴볼 수 있다.

## `tcache_put`

```
tcache_put(mchunkptr chunk, size_t tc_idx) {
  tcache_entry *e = (tcache_entry *)chunk2mem(chunk);
  assert(tc_idx < TCACHE_MAX_BINS);
  
+ /* Mark this chunk as "in the tcache" so the test in _int_free will detect a
       double free.  */
+ e->key = tcache;
  e->next = tcache->entries[tc_idx];
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}
```

`tcache_put`은 **해제한 청크를 `tcache`에 추가**하는 함수이다. 해제된 청크를 나타내는 `tcache_entry *e`를 만들어준 후, 해제된 청크의 `e->key`에 `tcache`라는 값을 대입하는 것이 추가되었다.

여기서 `tcache`는 `tcache_perthread`라는 구조체 변수를 가리킨다.

## `tcache_get`

```
tcache_get (size_t tc_idx)
   assert (tcache->entries[tc_idx] > 0);
   tcache->entries[tc_idx] = e->next;
   --(tcache->counts[tc_idx]);
+  e->key = NULL;
   return (void *) e;
 }
```

`tcache_get`은 **`tcache`에 연결된 청크를 재사용할 때 사용**하는 함수이다.

잘보면, `e->key = NULL;`으로 재사용하는 청크의 `key` 값을 `NULL`으로 바꿔주는 코드가 추가되었다.

## `_int_free`

```
_int_free (mstate av, mchunkptr p, int have_lock)
 #if USE_TCACHE
   {
     size_t tc_idx = csize2tidx (size);
-
-    if (tcache
-       && tc_idx < mp_.tcache_bins
-       && tcache->counts[tc_idx] < mp_.tcache_count)
+    if (tcache != NULL && tc_idx < mp_.tcache_bins)
       {
-       tcache_put (p, tc_idx);
-       return;
+       /* Check to see if it's already in the tcache.  */
+       tcache_entry *e = (tcache_entry *) chunk2mem (p);
+
+       /* This test succeeds on double free.  However, we don't 100%
+          trust it (it also matches random payload data at a 1 in
+          2^<size_t> chance), so verify it's not an unlikely
+          coincidence before aborting.  */
+       if (__glibc_unlikely (e->key == tcache))
+         {
+           tcache_entry *tmp;
+           LIBC_PROBE (memory_tcache_double_free, 2, e, tc_idx);
+           for (tmp = tcache->entries[tc_idx];
+                tmp;
+                tmp = tmp->next)
+             if (tmp == e)
+               malloc_printerr ("free(): double free detected in tcache 2");
+           /* If we get here, it was a coincidence.  We've wasted a
+              few cycles, but don't abort.  */
+         }
+
+       if (tcache->counts[tc_idx] < mp_.tcache_count)
+         {
+           tcache_put (p, tc_idx);
+           return;
+         }
       }
   }
 #endif
```

`_int_free`는 **청크를 해제할 때 호출**되는 함수이다.

2번째 주석이 존재하는 20번째 줄 아래의 코드를 보면, `if (__glibc_unlikely (e->key == tcache))`를 통해 **`e->key == tcache`인데, 해당 청크를 재할당하려고 하면 `Double Free`가 발생했다고 보고 프로그램을 `abort` 시킨다.**

왜냐하면, 해제하려는 청크의 `e->key == tcache`이면 이미 이전에 동일한 청크가 해제가 되어 `tcache` 내에 존재한다는 뜻이기 때문이다.

잘 살펴보면 다른 보호 기법은 없기 때문에, 만약 해당 조건문만 우회하여 통과하면 `Double Free`를 일으킬 수 있다는 것을 알 수 있다.

참고로, `tcache`에 청크를 넣는 `tcache_put`함수는 코드의 마지막쯤을 보면, 위의 조건을 통과할 때 호출하게 된다.

# 동적 분석

이번에는 `gdb`를 이용해서 보호 기법의 적용 과정을 동적으로 분석해보자.

이를 위해 같은 디렉토리에 존재하는 `DockerFile`을 빌드한 후 해당 컨테이너 내에서 `Double Free Bug`가 발생하는 `dfb.c` 소스 코드를 컴파일 후 실행해보면 된다.

```
// Name: dfb.c
// Compile: gcc -o dfb dfb.c
#include <stdio.h>
#include <stdlib.h>
int main() {
  char *chunk;
  chunk = malloc(0x50);
  printf("Address of chunk: %p\n", chunk);
  free(chunk);
  free(chunk); // Free again
}
```

그럼 `malloc`으로 청크를 할당한 직후에 중단점을 설정하고 실행한 후 `heap` 명령어로 청크들의 정보를 조회해보면 아래와 같다.

<img width="606" alt="image" src="https://github.com/user-attachments/assets/0684c24b-46ac-4fdf-b4c2-2bc1a903ec2e">

<img width="269" alt="image" src="https://github.com/user-attachments/assets/ec999815-c7b1-47a6-a392-b857c5940609">

여기서, `malloc(0x50)`을 통해 생성한 `chunk`의 주소는 `0x563812631250`이다. 아직 아무 값도 입력해주지 않았기 떄문에 `size`외에 아래와 같이 해당 메모리 값에는 아무 데이터가 없음을 알 수 있다.

<img width="512" alt="image" src="https://github.com/user-attachments/assets/a0c108a2-d939-4b0d-bb62-ae857fa5e7a2">

그럼 이후에 참조하기 위해 청크를 `gdb` 주소로 정의하기 위해 `set $chunk = (tcache_entry *)0x563812631260`을 입력해주고 넘어가자. 

`0x10`을 더해주는 `key`는 청크의 데이터 영역 + `0x8`에 존재하기 때문에, `0x10`을 더해주지 않으면 헤더에서 `0x8`을 더한 `size` 값이 `key`로 출력되버린다.

그럼 이제, 첫 번째 `free`를 수행한 직후에 다시 중단점을 설정하고, 실행한 후 변수로 설정한 `chunk`의 메모리를 출력해보면 아래와 같다.

<img width="215" alt="image" src="https://github.com/user-attachments/assets/300e2a92-160e-4b8a-bd07-9466be4d10e9">

앞에서 `key`에 넣는 값은 `tcache_perthread`라고 했기 때문에, 아래와 같이 `tcache_perthread_struct *`로 변환해준 후 해당 값이 가리키는 정보를 출력해보면 아래와 같다.

<img width="637" alt="image" src="https://github.com/user-attachments/assets/a5aa7e89-a2b5-4718-bcdf-1b1b8ead85b7">

여기서 `entry`에 청크의 데이터 시작 주소인 `0x563812631260`이 저장되어 있기 때문에 `tcache_perthread`에 해당 청크가 존재하는 것을 확인할 수 있고, 이 때문에 `if (__glibc_unlikely (e->key == tcache))` 조건에 걸려서 `Double Free`가 막히게 된다.

**그럼 즉, 해제된 청크의 `key` 값을 딱 1비트만이라도 바꿀 수 있으면, `e->key`가 `tcache`를 가리키지 않게 되므로 이 보호 기법을 우회할 수 있게 된다.**

# `Tcache Duplication`

```
// Name: tcache_dup.c
// Compile: gcc -o tcache_dup tcache_dup.c

#include <stdio.h>
#include <stdlib.h>

int main() {
  void *chunk = malloc(0x20);
  printf("Chunk to be double-freed: %p\n", chunk);

  free(chunk);
  *(char *)(chunk + 8) = 0xff;  // manipulate chunk->key

  free(chunk);                  // free chunk in twice

  printf("First allocation: %p\n", malloc(0x20));
  printf("Second allocation: %p\n", malloc(0x20));
  return 0;
}
```

해당 소스 코드는 앞에서 `if`로 검사하는 `Double Free` 보호 기법을 우회하여 `DFB`를 트리거하는 코드이다. 

1. 먼저 청크를 할당해준 후 `free`를 통해 해당 청크를 처음 해제해준다.

2. `*(char *)(chunk + 8) = 0xff;`를 통해 해당 청크의 `key`값의 하위 1바이트 값을 `0xff`로 조작해서 `e->key == tcache`의 조건에 걸리지 않도록 해준다. (gdb로 확인해보면 확인해볼 수 있다.)

3. 다시 동일한 청크를 한번 더 `free`해도 위의 변조를 통해 해당 청크가 Double Free되어 `free list`에 동일한 청크가 중복되어 존재하게 된다.

4. 이후 똑같은 사이즈의 청크를 2번 `malloc` 해서 할당해주면, 같은 청크가 2번 연속으로 중복되어 재할당되게 된다.

코드를 컴파일 후 실행해보면 예상과 같이 `Double Free` 보호 기법을 우회하여 아래와 같은 결과를 얻을 수 있다.

<img width="365" alt="image" src="https://github.com/user-attachments/assets/f4b8b1bf-3e01-4d59-acf0-97491a0d2c69">

**이는 나중에 공부할 `tcache poisoning`으로 응용될 수 있다.**
