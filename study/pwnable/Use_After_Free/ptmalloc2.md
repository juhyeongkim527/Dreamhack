# Memory Allocator

운영체제의 핵심 역할 중 하나는 한정된 메모리 자원을 각 프로세스에 효율적으로 배분하는 일이다. 모든 프로세스는 실행 중에 메모리를 동적으로 할당하고 해제하며, 이 과정이 매우 빈번하게 일어난다.

따라서, OS의 `Memory Allocator`는 이러한 메모리의 할당과 해제를 매우 빠르고 효율적으로 이루어 지도록 하는 것이 중요하다.

이를 위해 OS의 Memory Allocator는 특수한 알고리즘으로 구현되며, 몇몇 소프트웨어는 자체적으로 직접 구현한 더욱 최적화된 Memory Allocator를 가지기도 한다.

Memory Allocator의 종류는 알고리즘에 따라 다양한데, 리눅스는 `ptmalloc2`, 구글은 `tcmalloc`, 페이스북이나 파이어폭스는 `jemalloc`를 사용한다. 지금 공부할 종류는 리눅스의 `ptmalloc2`이다.

ptmalloc는 어떤 메모리가 해제되면, 해제된 메모리의 특징을 기억하고 있다가, 비슷한 메모리 할당 요청이 발생하면 빠르게 가지고 있던 메모리들의 특징을 통해 적절한 메모리를 반환해준다. 

이를 통해, 메모리 할당 **속도**를 높일 수 있고, 한정된 메모리 공간을 효율적으로 사용할 수 있게 된다.

`ptmalloc2`는 동적 메모리를 관리하는 리눅스의 핵심 알고리즘이기 때문에 과거부터 다양한 공격 기법이 연구되었고, 이에 따라 새로운 보호 기법도 계속 탄생하였다.

따라서 `ptmalloc2`가 구현된 `GLibc` 버전에 따라 보호 기법이 다르기 때문에, 이에 따른 유효 공격 기법에 큰 차이가 존재한다.

이번 글에서는 `Ubuntu 18.04 64-bit(Glibc 2.27버전)`을 기준으로 취약점과 이에 따른 공격 기법을 설명할 것이다. 특히 `tcache`와 관련된 공격 기법을 간단히 살펴볼 것이며, `ptmalloc2`와 관련된 공격 기법은 매우 다양하고 버전에 따라서도 다르기 때문에 나중에 더 공부해볼 것이다.

## ptmalloc2(pthread malloc 2)

`ptmalloc2`는 `dlmalloc`을 개선한 `ptmalloc`의 두 번째 버전이다. 편하게 `ptmalloc2`를 `ptmalloc`이라고 부를 것이다. 앞에서 말했듯이 리눅스의 Memory Allocator이며 `Glibc`에 구현되어 있다.

ptmalloc의 구현 목표는 **메모리의 효율적인 관리**이다. 따라서 이 큰 목표를 달성하기 위해 아래의 핵심 3가지 세부 목표를 가진다.

### 1. 메모리 낭비 방지

메모리의 동적 할당과 해제는 매우 빈번하게 발생한다. 그런데 컴퓨터의 전체 메모리 공간은 한정되있기 때문에 새로운 공간을 무한히 할당할 수는 없다.

따라서, ptmalloc은 메모리 할당 요청이 발생하면, 먼저 해제된 메모리 공간 중에 재사용할 수 있는 공간이 있는지 탐색한다.

그 후 해제된 메모리 공간 중에서 요청된 크기와 같은 크기의 메모리 공간이 있다면 이를 그대로 재사용하게 한다. 또한, 작은 크기의 할당 요청이 발생했을 때, 해제된 메모리 공간 중 매우 큰 메모리 공간이 있으면 그 영역을 나누어 주기도 한다.

### 2. 빠른 메모리 재사용

운영체제가 프로세스에게 할당하는 **가상 메모리 공간**은 매우 크기 때문에, 사용 가능한(해제된) 메모리 공간을 탐색하기 위해 처음부터 끝까지 탐색하면 매우 시간이 오래걸린다.

따라서, 특정 메모리 공간을 해제한 이후에 이를 빠르게 재사용하려면 해제된 메모리 공간의 주소를 기억하고 있어야 한다.

이를 위해 ptmalloc은 메모리 공간을 해제할 때, `tcache` 또는 `bin`이라는 Linked-List에 해제된 메모리 공간의 정보를 저장해둔다.

**`tcache`와 `bin`은 여러 개가 정의되어 있으며, 각각은 서로 다른 크기의 메모리 공간들을 저장한다. 이러한 특징 때문에 특정 크기의 메모리 할당 요청이 발생했을 때, 그 크기와 관련된 저장소만 탐색하면 되므로 더욱 효율적으로 공간을 재사용할 수 있다.**

### 3. 메모리 단편화 방지

컴퓨터 과학의 메모리 관리 이론에서 `Internal Fragmentation`과 `External Fragmentation`를 관리하고 줄이는 것은 매우 중요한 과제이다.

`Internal Fragmentation`은 프로세스에게 일정 크기의 메모리가 할당되어 있는데, 실제 프로세스의 데이터가 점유하는 공간이 할당된 메모리의 크기에 비해 적어서, 사용하지 않는 빈 공간이 발생하는 경우를 말하며,

`External Fragmentation`은 여러 프로세스에게 할당된 메모리 공간들 사이에 한 프로세스에게 할당하기는 힘든 애매하게 작은 공간이 발생하는 경우이다.

이 두 단편화 때문에 메모리 공간 전체에서 사용되지 않는 공간이 많아보이지만, 실제로 프로세스에게 할당할 메모리 공간이 부족하게 되는 상황이 생길 수 있다.

따라서, ptmalloc은 단편화를 줄이기 위해 **정렬(Alignment)**, **병합(Coalescence)**, **분할(Split)** 방법을 사용한다. 

### 정렬(Alignment)

64비트 아키텍처에서 ptmalloc은 메모리 공간을 `16바이트` 단위로 할당해준다. 사용자가 어떤 크기의 메모리 공간을 요청하면, 그보다 조금 크거나 같은 16바이트 단위의 메모리 공간을 제공한다.

예를 들어, 사용자가 4바이트를 요청하면 16바이트 메모리 공간을 할당해주고, 17바이트를 요청하면 32바이트 메모리 공간을 할당해준다.

이렇게 되면 `Internal Fragmentation`은 발생하지만, 최대 발생할 수 있는 `Internal Fragmentation`은 한번 요청당 `15바이트`로 `External Fragmentation`에 비해 훨씬 작기 때문에 해당 방법으로 메모리 공간을 할당한다.

공간을 정렬하지 않고, 프로세스가 요청하는 만큼 할당할 수 있다면 모든 데이터가 연속적으로 할당되어 외부 단편화를 최소화할 수 있을 것 같아 보인다. 

***그러나 공간을 해제하고 재사용할 때, 정확히 같은 크기의 할당 요청이 발생할 확률보다 비슷한 크기의 요청이 발생할 확률이 높다.*** 

따라서 비슷한 크기의 요청에 대해서는 모두 같은 크기의 공간을 반환해야 해제된 청크들의 재사용률을 높이고, 외부 단편화도 줄일 수 있다.

### 병합(Coalescence), 분할(Split)

또한, ptmalloc은 특정 조건을 만족하는 상황에서 해제된 공간들을 병합하기도 한다. 병합으로 생성된 큰 공간은 그 공간과 같은 크기의 요청에 의해, 또는 그보다 작은 요청에 의해 분할되어 재사용된다.

잘게 나뉜 영역을 병합하고, 필요할 때 구역을 다시 설정함으로써 해제된 공간의 재사용률을 높이고, 외부 단편화를 줄일 수 있다.

## ptmalloc의 객체

ptmalloc2는 `Chunk(청크)`, `bin`, `tcache`, `arena`를 주요 객체로 사용한다.

## 1. Chunk

청크는 덩어리라는 뜻으로, 여기서는 **ptmalloc이 할당한 메모리 공간**을 의미한다. 청크는 `Header`와 `Data`로 구성된다.

헤더에는 청크 관리에 필요한 정보가 들어있고, 데이터에는 이름대로 사용자가 입력한 데이터 그 자체가 저장된다.

![image](https://github.com/user-attachments/assets/d1220eae-f59e-4fb9-93cf-c631c7d5249d)

헤더는 청크의 상태를 나타내기 때문에, **사용 중인 청크인 In-use**의 헤더와, **해제된 청크인 Freed**의 헤더 구조가 서로 다르다. 헤제된 청크에만 `fd`와 `bk`가 존재하고, 아래에 각 헤더의 의미가 있다.

| 이름       | 크기     | 의미                                                                                              |
|------------|------------|---------------------------------------------------------------------------------------------------|
| `prev_size`  | 8바이트  | 인접한 직전 청크의 크기. 청크를 병합할 때 직전 청크를 찾는 데 사용됩니다.                          |
| `size`       | 8바이트  | 현재 청크의 크기. 헤더의 크기도 포함한 값입니다.  <br> <br>64비트 환경에서, 사용 중인 청크 헤더의 크기는 16바이트이므로 사용자가 요청한 크기를 정렬하고, 그 값에 16바이트를 더한 값이 됩니다. |
| `flags`      | 3비트    | 64비트 환경에서 청크는 16바이트 단위로 할당되므로, size의 하위 4비트는 의미를 갖지 않습니다. 그래서 ptmalloc은 size의 하위 3비트를 청크 관리에 필요한 플래그 값으로 사용합니다. <br> <br>각 플래그는 순서대로 `allocated arena(A)`, `mmap’d(M)`, `prev-in-use(P)`를 나타냅니다. `prev-in-use` 플래그는 직전 청크가 사용 중인지를 나타내므로, ptmalloc은 이 플래그를 참조하여 병합이 필요한지 판단할 수 있습니다. 나머지 플래그에 대해서는 여기서 설명하지 않겠습니다. |
| `fd`         | 8바이트  | 연결 리스트에서 `다음 청크`를 가리킴. 해제된 청크에만 있습니다.                                    |
| `bk`         | 8바이트  | 연결 리스트에서 `이전 청크`를 가리킴. 해제된 청크에만 있습니다.                                    |

## 2. bin 🗑️

bin은 문자 그대로, **사용이 끝난 청크들이 저장되는 객체**이다. 메모리의 낭비를 막고, 해제된 청크를 빠르게 재사용할 수 있게 한다.

ptmalloc에는 총 128개의 bin이 정의되어있다. 이 중 62개는 `smallbin`, 63개는 `largebin`, 1개는 `unsortedbin`으로 사용되고, 나머지 2개는 사용되지 않는다.

![image](https://github.com/user-attachments/assets/724ea1e3-705f-4d79-acf8-2680628a7640)

### `smallbin`

smallbin에는 `32bytes` 이상 `1024bytes` 미만의 크기를 갖는 청크들이 각 인덱스에 따라 구분되어서 보관된다. 

같은 인덱스를 가지는 하나의 smallbin에는 같은 크기의 청크들만 보관되며, 인덱스가 1 증가할수록 저장되는 청크들의 크기는 `16bytes`씩 증가한다. 

따라서, `smallbin[0]`에는 `32bytes`의 청크들이 보관되고, 마지막 인덱스인 `smallbin[61]`에는 `32 + 61 * 16`인 `1008bytes`의 청크들이 보관된다.

`smallbin`은 `Circular Doubly Linked List(원형 이중 연결 리스트)`로 구현되며, 먼저 해제된 청크가 먼저 재할당되는 `FIFO` 알고리즘에 의해 관리된다.

참고로, `LIFO`를 사용하면 속도가 가장 빠르지만 `Fragmentation`의 개수가 많아지고, `Address-Ordered`는 정렬을 해줘야 하기 때문에 속도가 느리지만 `Fragmentation`의 개수는 가장 적다. `FIFO`는 그 중간이다.

이중 연결 리스트의 특성상, `smallbin`에 청크를 추가하거나 삭제할 때, 앞 뒤의 `link`를 끊는 과정이 필요하다. ptmalloc에서 이 과정을 `unlink`라고 한다.

또한, `smallbin`의 청크들은 ptmalloc의 병합 대상이기 때문에, 메모리상에서 인접한 두 청크가 해제되어 있고, 같은 인덱스를 가진(같은 크기의) `smallbin`에 속해있다면 이 둘은 병합된다. 이를 `consolidation`이라고 한다.

![smallbin in action](https://dreamhack-lecture.s3.amazonaws.com/media/c065e7f4759319dfc276a90fd5366eb6f57a96654e32f71ee8bd0371dd785e82.gif)

### `fastbin`

일반적으로 크기가 작은 청크들이 크기가 큰 청크들보다 더 빈번하게 할당되고 해제될 가능성이 크다. 따라서 크기가 작은 청크들이 할당과 해제를 효율적으로 하면 전체 시스템의 효율성이 크게 향상될 것이다.

**이런 이유 때문에 ptmalloc은 어떤 크기를 정해두고, 이보다 작은 청크들은 `smallbin`이 아니라 `fastbin`에 저장한다.** 그리고 이들을 관리할 때는 `Fragmentation`의 가능성보다 **속도**에 더 우선순위를 둔다.

`fastbin`에는 `32bytes` 이상 `176bytes` 이하 크기의 청크들이 보관되며, 똑같이 인덱스가 1 증가함에 따라 `16bytes` 만큼 증가하기 때문에 총 10개의 `fastbin`이 존재하게 된다.

***리눅스는 이 중에서도 크기가 작은 순서대로 `7`개인 `32bytes` 이상 `128bytes` 이하의 청크들만 `fastbin`에 저장하여 사용한다.***

`fastbin`은 `smallbin`과 달리 `단일 연결 리스트`이기 때문에 메모리를 할당하거나 해제할 때, 앞 뒤를 끊는 `unlink` 과정이 필요하지 않고, `LIFO` 알고리즘에 의해 메모리를 할당해준다. (파편화는 심하지만 속도가 빠르기 때문이다.)

이에 따라 마지막에 해제된 청크가 가장 먼저 재할당되고, **`fastbin`에 저장되는 청크들은 서로 병합되지 않아서, 청크 간 병합에 사용되는 연산도 아낄 수 있다.**

![fastbin in action](https://dreamhack-lecture.s3.amazonaws.com/media/d5c3e66cda3b4cf335c5e1dd702d8231e8abb7fc43dd1664e5cb824561507c91.gif)

### `largebin`

`largebin`은 `1024bytes` 이상의 크기를 갖는 청크들이 보관된다. 총 `63`개의 `largebin`이 있는데, 완전히 같은 크기의 청크를 보관하는 `smallbin`, `fastbin`과 달리 한 `largebin`에서 **일정 범위 안의 크기**를 갖는 청크들을 모두 보관한다. 

이 범위는 `largebin`의 인덱스가 증가하면 ***로그적***으로 증가한다. 예를 들어, `largebin[0]`는 `1024bytea` 이상, `1088bytes` 미만의 청크를 보관하며, `largebin[32]`는 `3072bytes` 이상, `3584bytes` 미만의 청크를 보관한다. 

이런 방법을 사용하면 적은 수의 `largebin`으로 다양한 크기를 갖는 청크들을 관리할 수 있다. **`largebin`은 범위에 해당하는 모든 청크를 보관하기 때문에, 재할당 요청이 발생했을 때 ptmalloc은 그 안에서 크기가 가장 비슷한 청크(`best-fit`)를 꺼내 재할당한다.**

이 과정을 빠르게 하려고 ptmalloc은 `largebin`안의 청크를 크기 **내림차순으로 `정렬`**합니다. `largebin`은 `이중 연결 리스트`이므로 재할당 과정에서 `unlink` 도 동반된다. 또한, 연속된 `largebin` 청크들은 **병합**의 대상이 된다.

### `unsortedbin`

`unsortedbin`은 문자 그대로, **분류되지 않은 청크들**을 보관하는 bin이다. `unsortedbin`은 하나만 존재하며, **`fastbin`에 들어가지 않는 모든 청크들은 해제되었을 때 크기를 구분하지 않고 `unsortedbin`에 보관된다.** 

`unsortedbin`은 `원형 이중 연결 리스트`이며 내부적으로 정렬되지는 않는다. `smallbin` 크기에 해당하는 청크를 할당 요청하면, ptmalloc은 `fastbin` 또는 `smallbin`을 탐색한 뒤 `unsortedbin`을 탐색한다. 

`largebin`의 크기에 해당하는 청크는 `unsortedbin`을 먼저 탐색한다. `unsortedbin`에서 적절한 청크가 발견되면 해당 청크를 꺼내어 사용한다. 이 과정에서, 탐색된 청크들은 크기에 따라 적절한 bin으로 분류된다.

**ptmalloc은 `unsortedbin`을 활용하여 불필요한 연산을 줄이고, 성능을 최적화한다.** 연구에 따르면, 어떤 청크를 해제한 다음에 비슷한 크기의 청크를 바로 할당하거나, 또는 한번에 여러 청크들을 연속적으로 해제하는 경우가 빈번하게 발생한다고 한다.

전자의 상황에서 `unsortedbin`을 사용하면, 청크 분류에 낭비되는 비용을 없앨 수 있다다. 또한, 청크의 크기가 `largebin`의 범위에 속하면 `largebin` 중 어떤 범위에 속하는지 계산하여 청크를 연결할 적절한 위치를 탐색해야 하는데 이 과정도 생략할 수 있다. 

한편, 후자의 상황에서는 연속적으로 청크를 해제하면서, 병합하고 재분류하는 과정이 반복적으로 발생한다. `unsortedbin`을 사용하면 이러한 비용도 줄일 수 있습니다.

## 3. arena

`arena`는 `fastbin`, `smallbin`, `largebin` 등의 정보를 모두 담고 있는 객체이다. 

`멀티 쓰레드 환경`에서 ptmalloc은 **Race Condition**을 막기 위해 arena에 접근할 때 arena에 `Lock(락)`을 적용한다. 그런데 이 방식을 사용하면 레이스 컨디션은 막을 수 있지만, 반대로 `병목 현상`을 일으킬 수 있다.

ptmalloc은 이를 최대한 피하기 위해 최대 `64`개의 arena를 생성할 수 있도록 허용한다. 서로 다른 공유 자원을 사용하는데도 arena에 락이 걸려서 대기해야 하는 경우나 데드락이 발생한 경우, 새로운 arena를 생성해서 이를 피할 수 있다. 

그런데, 생성할 수 있는 갯수가 64개로 제한되어 있으므로 과도한 멀티 쓰레드 환경에서는 결국 병목 현상이 발생한다. 그래서 `glibc 2.26`에서는 `tcache`를 추가적으로 도입하였다.

### 참고 1. 💡레이스 컨디션(Race Condition)

레이스 컨디션은 어떤 `Shared Resource`을 여러 쓰레드나 프로세스에서 접근할 때 발생하는 오동작을 의미한다. 예를 들어, 한 쓰레드가 어떤 사용자의 계정 정보를 참조하고 있는데, 다른 쓰레드가 그 계정 정보를 삭제하면, 참조하고 있던 쓰레드에서는 삭제된 계정 정보를 참조하게 된다.

이는 경우에 따라 심각한 보안 문제로 이어질 수 있다. 이런 문제를 막기 위해 멀티 쓰레딩을 지원하는 프로그래밍 언어들은 `락(Lock)` 기능을 제공한다. 

한 쓰레드에서 어떤 공유 자원에 락을 걸면, 그 공유 자원을 이용하려는 다른 쓰레드는 락이 해제될 때까지 기다려야 한다. 공유 자원을 사용하는 동안 락을 걸어 놓음으로써 다른 쓰레드에 의한 조작을 차단할 수 있고, 레이스 컨디션을 방지할 수 있다.

그런데 락은 쓰레드를 무제한으로 대기시키기 때문에, 구현을 잘못하거나 쓰레드의 수가 과다하게 많아지면 `병목 현상`을 일으킬 수 있다. 락으로 발생하는 대표적인 문제 중 하나가 여러 쓰레드가 서로 물리고 물려서 어떤 쓰레드도 락을 해제하지 못하는 상황인 `데드락(Deadlock)`이다.

레이스 컨디션을 이용한 공격 기법도 존재하며 이는 나중에 다뤄보도록 하겠다.

### 참고 2. arena의 구현

```
struct malloc_state
{
  /* Serialize access.  */
  __libc_lock_define (, mutex);

  /* Flags (formerly in max_fast).  */
  int flags;

  /* Set if the fastbin chunks contain recently inserted free blocks.  */
  /* Note this is a bool but not all targets support atomics on booleans.  */
  int have_fastchunks;

  /* Fastbins */
  mfastbinptr fastbinsY[NFASTBINS];

  /* Base of the topmost chunk -- not otherwise kept in a bin */
  mchunkptr top;

  /* The remainder from the most recent split of a small request */
  mchunkptr last_remainder;

  /* Normal bins packed as described above */
  mchunkptr bins[NBINS * 2 - 2];

  /* Bitmap of bins */
  unsigned int binmap[BINMAPSIZE];

  /* Linked list */
  struct malloc_state *next;

  /* Linked list for free arenas.  Access to this field is serialized
     by free_list_lock in arena.c.  */
  struct malloc_state *next_free;

  /* Number of threads attached to this arena.  0 if the arena is on
     the free list.  Access to this field is serialized by
     free_list_lock in arena.c.  */
  INTERNAL_SIZE_T attached_threads;

  /* Memory allocated from the system in this arena.  */
  INTERNAL_SIZE_T system_mem;
  INTERNAL_SIZE_T max_system_mem;
};
```

`arena`는 위와 같은 구조를 가지고 있다.

코드를 살펴보면, `arena`는 고유의 `bins`를 가지는 것을 알 수 있다. 그렇기 때문에 각 `thread`가 고유의 `arena`를 가질 수 있도록 ptmalloc이 64개의 arena를 생성할 수 있다면,

각 스레드는 다른 스레드의 할당자(또는 `bins`)와 완전히 분리되어 있기 때문에 병목현상을 피할 수 있다.

만약 모든 스레드가 오직 하나의 `arena`에만 동시에 접근해야 한다면, 각 스레드마다 `bins`를 가질 수도 없을 것이다. 따라서 서로 겹치지 않는 청크에 접근할 때도 `arean`에 락을 걸어야 해서 병목현상이 크게 발생하는 것이다.

`arena`가 여러개 존재하더라도 한 스레드의 `free()`와 다른 스레드의 `malloc()`으로 등의 이유로, 한 스레드가 가지고 있던 `bins`의 청크를 다른 스레드가 사용하게 되는 상황이 발생하게 되면,

다른 스레드의 `arena`에도 접근해야 하기 때문에 병목 현상이 발생할 수 있지만, 이런 상황은 그렇게 일반적으로 많이 발생하지 않기 때문에 전체적인 병목현상은 매우 줄어들 수 있다.

따라서 모든 스레드가 하나의 `arena`만 사용하여 레이스 컨디션을 발생시키지 않는 상황에서도 락때문에 병목현상이 존재하는 것보다, 각 스레드가 고유한 `arena`를 가지는 것이 병목현상을 줄이는데 매우 효과적이다.

## 4. tcache

`tcache`는 `thread local cache`의 약자이다. 이름에서 알 수 있듯, **각 쓰레드에 독립적으로 할당되는 캐시 저장소**를 지칭한다. `tcache`는 `glibc 버전 2.26`에서 도입되었으며, 멀티 쓰레드 환경에 더욱 최적화된 메모리 관리 메커니즘을 제공한다.

각 쓰레드는 `64`개의 `tcache`를 가지고 있다.(`tcache[0x40]`) **`tcache`는 `fastbin`과 마찬가지로 `LIFO` 방식으로 사용되는 `단일 연결리스트`이며, 하나의 tcache는 같은 크기의 청크들만 보관한다.**

**`리눅스`는 각 `tcache`에 보관할 수 있는 청크의 갯수를 `7개`로 제한하고 있는데, 이는 쓰레드마다 정의되는 `tcache`의 특성상, 무제한으로 청크를 연결할 수 있으면 메모리가 낭비될 수 있기 때문이다. `tcache`에 들어간 청크들은 `병합`되지 않는다.**

`tcache`에는 `32bytes` 이상, `1040bytes` 이하의 크기를 갖는 청크들이 보관된다. **이 범위에 속하는 청크들은 할당 및 해제될 때 `tcache`를 가장 먼저 조회한다.** **청크가 보관될 `tcache`가 가득찼을 경우에는 적절한 `bin`으로 분류된다.**

`tcache`는 각 쓰레드가 고유하게 갖는 캐시이기 때문에, ptmalloc은 `Race Condition`을 고려하지 않고 이 캐시에 접근할 수 있다. `arena`의 `bin`에 접근하기 전에 `tcache`를 먼저 사용하므로 `arena`에서 발생할 수 있는 `병목 현상`을 완화하는 효과가 있다.

***`tcache`는 보안 검사가 많이 생략되어 있어서 공격자들에게 힙 익스플로잇의 좋은 도구로 활용될 수 있다.*** 아래에서 `tcache`를 활용한 메모리 할당과 해제 과정을 살펴볼 수 있다.

![tcache in action](https://dreamhack-lecture.s3.amazonaws.com/media/d0f1bf96eb73beafa3fc6161067baac3fce665c582068d89141e502011f452c0.gif)

`tcache`는 `fd`, `bk`가 존재하지 않고 `next`와 `key`가 존재하는데, `LIFO`를 사용하기 때문에 가장 마지막에 `tcache`에 들어온 청크가 연결 리스트의 헤드에 존재하고, `next`에는 그 뒤에 가장 최근에 들어온 청크가 차례대로 연결된다.

정확히 같지는 않지만, 연결 리스트에서 다음 청크를 가리킨다는 의미에서 `fd`와 비슷하다. 그리고 `key`는 `Double Free`를 체크하기 위한 값으로, 이후에 `Double Free` 파트에서 소개할 것이다.

## 정리

1. `smallbin`의 크기에 속하는 메모리를 할당할 때 청크를 조회하는 순서 : `tcache` -> `fastbin` -> `smallbin` -> `unsortedbin`

2. `largebin`의 크기에 속하는 메모리를 할당할 때 청크를 조회하는 순서 : `tcache` -> `unsortedbin` -> `largebin`

3. `fastbin`의 크기에 속하는 메모리가 해제될 때 들어가는 순서 (`32bytes` <= size <=  `128bytes`) : `tcache` -> `fastbin`

4. `fastbin`의 크기에 속하지 않은 메모리가 해제될 때 들어가는 순서 (`128bytes` < size <= `1040bytes`) : `tcache` -> `unsortedbin` -> `smallbin` OR `largebin` (아래에서 과정 설명)

5. `tcache`의 크기에 속하지 않은 메모리가 해제될 때 들어가는 순서 (`1040bytes` < size ) : ``unsortedbin` -> `largebin` (아래에서 과정 설명)

**처음에 해제되면 전부 `unsortedbin`에 존재하다가, 메모리 할당 요청에 의해 `unsortedbin`이 탐색되는 경우, 이 과정에서 탐색된 청크들이 `smallbin`이나 `largebin`으로 분류됨 : 불필요한 연산을 줄이고, 성능을 최적화하기 위해**

### 키워드

**Memory Allocator** : 프로세스의 요청에 따라 동적으로 메모리를 할당 및 해제해주는 주체, 또는 관련된 알고리즘들의 집합. dlmalloc, ptmalloc, jemalloc, tcmalloc 등이 있으며, 리눅스는 그 중에서 ptmalloc2를 사용한다. 구현되는 방식은 다소 차이가 있지만, 핵심 목표는 메모리 단편화의 최소화, 공간 복잡도 및 시간 복잡도의 최적화이다.

**ptmalloc(pthread memory-allocation)** : dlmalloc을 모태로하는 메모리 할당자. malloc , free , realloc 등을 기반으로 사용자의 동적 메모리 요청을 처리함. 사용하는 주요 객체로는 청크, bins, arena, tcache가 있음.

**청크(Chunk)** : ptmalloc2가 메모리를 할당하는 단위.

**bins** : 해제된 청크들을 보관함. ptmalloc은 bin을 이용하여 청크를 빠르게 재할당하고, 단편화를 최소화함. bins에는 fastbin, smallbin, largebin, unsortedbin이 있음.

**arena** : ptmalloc이 관리하는 메모리들의 정보가 담겨있음. 모든 쓰레드가 공유하는 자원으로, 한 쓰레드가 이를 점유하면 race condition을 막기 위해 lock이 걸림. 병목 현상을 막기 위해 64개까지 생성 가능하지만, 이를 초과할 정도로 많은 연산이 발생하면 병목 현상이 일어남.

**tcache** : 쓰레드마다 해제된 청크들을 보관하는 저장소. 멀티 쓰레드 환경에서 arena가 가지고 있는 병목 현상의 문제를 일부 해결해줄 수 있음. 쓰레드마다 할당되므로 용량을 고려하여 각 tcache당 7개의 청크만 보관할 수 있음.
