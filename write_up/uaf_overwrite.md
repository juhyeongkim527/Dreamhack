# 바이너리 분석

```
// Name: uaf_overwrite.c
// Compile: gcc -o uaf_overwrite uaf_overwrite.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct Human
{
  char name[16];
  int weight;
  long age;
};

struct Robot
{
  char name[16];
  int weight;
  void (*fptr)();
};

struct Human *human;
struct Robot *robot;
char *custom[10];
int c_idx;

void print_name() { printf("Name: %s\n", robot->name); }

void menu()
{
  printf("1. Human\n");
  printf("2. Robot\n");
  printf("3. Custom\n");
  printf("> ");
}

void human_func()
{
  int sel;
  human = (struct Human *)malloc(sizeof(struct Human));

  strcpy(human->name, "Human");
  printf("Human Weight: ");
  scanf("%d", &human->weight);

  printf("Human Age: ");
  scanf("%ld", &human->age);

  free(human);
}

void robot_func()
{
  int sel;
  robot = (struct Robot *)malloc(sizeof(struct Robot));

  strcpy(robot->name, "Robot");
  printf("Robot Weight: ");
  scanf("%d", &robot->weight);

  if (robot->fptr)
    robot->fptr();
  else
    robot->fptr = print_name;

  robot->fptr(robot);

  free(robot);
}

int custom_func()
{
  unsigned int size;
  unsigned int idx;
  if (c_idx > 9)
  {
    printf("Custom FULL!!\n");
    return 0;
  }

  printf("Size: ");
  scanf("%d", &size);

  if (size >= 0x100)
  {
    custom[c_idx] = malloc(size);
    printf("Data: ");
    read(0, custom[c_idx], size - 1);

    printf("Data: %s\n", custom[c_idx]);

    printf("Free idx: ");
    scanf("%d", &idx);

    if (idx < 10 && custom[idx])
    {
      free(custom[idx]);
      custom[idx] = NULL;
    }
  }

  c_idx++;
}

int main()
{
  int idx;
  char *ptr;

  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);

  while (1)
  {
    menu();
    scanf("%d", &idx);
    switch (idx)
    {
    case 1:
      human_func();
      break;
    case 2:
      robot_func();
      break;
    case 3:
      custom_func();
      break;
    }
  }
}
```

<img width="674" alt="image" src="https://github.com/user-attachments/assets/74833d55-bd6a-41fc-a908-9206b760fd51">

---
먼저, 해당 바이너리에서 `Human`과 `Robot` 구조체의 크기 뿐만 아니라 멤버 변수들의 크기와 순서 또한 같도록 정의되어 있다.  

그리고 `human_func`와 `robot_func` 함수에서 구조체를 할당할 때 할당된 메모리 영역을 초기화하지 않기 때문에, `Human` 구조체와 `Robot` 구조체 중 이전에 사용하고 해제한 구조체의 멤버 변수의 값을 사용할 수 있게 되는 `UAF` 취약점이 존재한다.

---
그리고 `robot_func`를 보면, `Robot`의 멤버인 `void (*fptr)();` 함수 포인터 값이 존재한다면 해당 함수를 호출하고, 존재하지 않는다면 `print_name` 함수를 대입해준 후 `print_name(robot);`을 호출하도록 한다.

**여기서, 만약 `robot->fptr`에 `UAF` 취약점을 통해 원하는 값을 남겨놓을 수 있다면, 실행 흐름을 조작할 수 있을 것이다. 예를 들어 `system("/bin/sh");`이나 `one_gadget`이 예가 될 것이다.**

---
그리고, `custom_func` 함수를 보면, ` scanf("%d", &size);`를 통해 `0x100` 이상의 `size`를 사용자에게 입력받으면, 사용자가 원하는 크기의 청크를 임의로 `custom[c_idx]`에 할당할 수 있다.

이 함수에서도 `custom[c_idx]`에 메모리를 할당할 때, 할당된 메모리 영역을 초기화하지 않기 때문에 `UAF` 취약점이 존재하고, `read(0, custom[c_idx], size - 1);`를 통해 해당 메모리 영역에 임의의 값을 쓸 수도 있다.

또한 아래의 코드를 통해 원하는 `custom`의 인덱스에 메모리를 해제할 수도 있다.

```
printf("Free idx: ");
scanf("%d", &idx);

if (idx < 10 && custom[idx]) {
  free(custom[idx]);
  custom[idx] = NULL;
}
```

# Exploit 설계

위에서 봤듯이 `robot_func` 함수를 처음 호출할 때는, `robot->fptr`에 값을 대입해주지 않았음에도 해당 값이 존재하면 `robot->ftpr();`을 수행하게 된다.

**따라서, 청크의 크기가 완전히 같은 `human_func` 함수를 먼저 호출하여 `human->age`에 `system("/bin/sh");` 이나 `one_gadget`의 주소를 대입해준 후, 바로 `robot_func`함수를 호출하면 `robot->fptr`이 해당 함수를 가리키게 되어 쉘을 획득할 수 있을 것이다.**

근데, 해당 바이너리에는 따로 `system("/bin/sh");`이 존재하지 않기 때문에 문제에서 주어진 `libc-2.27.so` 라이브러리에 존재하는 `one_gadget`을 찾아서 `human->age`에 대입해주는 방법을 사용하면 될 것이다.

**이를 위해서는 `libc`의 베이스 주소를 먼저 구해야한다.** 이를 어떻게 구할 수 있을까 ? 단서는 `custom_func`에 있다.

## 1. Leak libc base

해당 바이너리에는 `UAF` 취약점이 존재하기 때문에 해당 취약점을 이용하여 `libc base`를 구해야 한다. 이를 위해서 `ptmalloc2`의 `unsorted bin`의 특징을 이용할 수 있다.

**`free`를 통해 `unsortedbin`가 비어 있던 상태에서 처음 연결되는 청크는 `libc` 영역의 특정 주소와 이중 원형 연결 리스트를 형성한다. 따라서, `unsortedbin`에 처음 연결되는 청크는 `fd`와 `bk` 값으로 `libc`영역의 특정 주소를 가리키게 된다.**

**이 특징을 통해, `unsortedbin`에 처음 연결된 청크를 다시 재할당하여 해당 청크에 저장된 `fd`와 `bk` 값을 읽는다면, `libc`의 특정 영역의 주소를 구할 수 있고, 이 특정 영역과 `libc base` 간의 오프셋을 빼주면 `libc base`를 구할 수 있게 된다.**

여기서 아래와 같이 **주의할 점**이 있다.

---
청크가 해제될 때 `32bytes` 이상, `1040bytes` 크기 이하의 청크는 전부 `tcache`에 공간이 존재하는 경우, `tcache`에 먼저 들어가게 된다. 

따라서, 아래의 예시처럼 `1000bytes` 크기로 2개의 청크를 할당해준 후 첫번째 청크를 `free`를 하게 되면, `tcache`에 청크가 들어가기 때문에 `fd`와 `bk`가 `libc`의 특정 영역을 가리키지 않게 된다.\
(`tcache`에서 `fd`는 `tcache` 리스트의 첫번째 블록을 가리킨다고 한다.)

![image](https://github.com/user-attachments/assets/dad350f8-932e-4b0b-b77c-2b778468bf1c)

![image](https://github.com/user-attachments/assets/7b6a5cbb-7cb7-4dd6-b630-b0aea3d106da)

---
위에서 `unsortedbin`에 넣기 위해서는 `1040bytes` 크기 이상의 청크여야 한다고 했기 때문에, `1050bytes` 크기의 청크를 1개 할당 후 `free`를 하게 되면 예상과 달리 아래와 같이 `bin`이 존재하지 않게 되버린다.

<img width="700" alt="image" src="https://github.com/user-attachments/assets/d8211e05-8277-45a9-b32f-b96bba2b498e">

<img width="388" alt="image" src="https://github.com/user-attachments/assets/ecbc9530-a82c-4948-9dc8-be19b6c527aa">

여기서 주의할 점은, 만약 `free`한 후 `unsortedbin`에 들어간 청크가 `Top chunk`에 맞닿아 있다면 두 청크가 병합되어 버리고 `fd`, `bk`가 초기화되버리기 때문에 해당 값을 읽을 수 없다.

<img width="512" alt="image" src="https://github.com/user-attachments/assets/aef2dffc-dc6b-4055-9258-feb1dab0a24d">

따라서, `fd`와 `bk` 값을 읽기 위해서는 2개의 청크를 할당 후, 두번째 청크는 할당된 채로 첫번째 청크가 `Top Chunk`와 맞닿지 못하게 하여, 첫번째 청크만 `free`한 후 `fd`와 `bk` 값을 읽어야 한다.

첫 번째 청크가 아닌 두 번째 청크를 `free` 한다면, `free`한 청크가 `Top Chunk`와 붙어서 당연히 `fd`와 `bk`를 읽을 수 없을 것이다.

**그리고, `malloc`을 통해 청크가 할당되면, 낮은 주소부터 증가하며 `Top Chunk`에 새롭게 할당할 청크가 추가되어 위치하고, `Top Chunk`는 할당된 사이즈에서 추가로 헤더가 추가된 만큼 다시 증가하게 된다.**

아래의 예시를 보면, `1050bytes` 사이즈의 청크를 1개 할당해준 상태에서 `heap`의 상태를 보면 `Top Chunk`의 주소가 `0x5555556036c0` 이고, 다시 `1050bytes` 사이즈의 청크를 1개 더 할당해주면 `Top Chunk`의 주소인 `0x5555556036c0`에 새로운 청크가 붙게 된다.

<img width="724" alt="image" src="https://github.com/user-attachments/assets/a7aac90d-8f85-4788-b99a-0550efec2c38">

<img width="404" alt="image" src="https://github.com/user-attachments/assets/a8e19a05-98fc-4151-8ea8-02a5c0b02797">

<img width="405" alt="image" src="https://github.com/user-attachments/assets/23a98726-d4f8-43be-b5a2-707ea2df4dd4">

---

참고로, 청크가 할당되는 아래의 시나리오를 한번 생각해보자.

<img width="719" alt="image" src="https://github.com/user-attachments/assets/4473df26-a044-491d-917c-bab874f1f89a">

<img width="349" alt="image" src="https://github.com/user-attachments/assets/e74150c5-7133-4516-8cc6-002c2f867681">

순서는 아래와 같다.

1. `custom[0]`에 청크 할당 : `custom[0]` 존재
2. `custom[1]`에 청크 할당 : `custom[0], custom[1]` 존재
3. `custom[2]`에 청크 할당 후, `custom[0]`을 `free` : `custom[1], custom[2]` 존재, `custom[0] = NULL`이자, 해당 청크는 `unsortedbin`에 저장
4. `custom[3]`에 청크 할당 후, `custom[1]`을 `free` : `custom[2], custom[3]` 존재, `custom[0]`이 쓰던 청크가 `unsortedbin`에서 `custom[3]`에게 할당, `custom[1] = NULL`이자 `unsortedbin`에 저장

이 상태에서 `heap`으로 파악해보면, `custom[1]`이 사용하던 청크가 `unsortedbin`에 두번째로 들어갔음에도 불구하고 `fd`, `bk`가 `libc`의 특정 영역을 가리킨다.

**그 이유는, `unsortedbin`에서 프로그램 실행 후 제일 처음 들어간 청크만 `fd`와 `bk`가 `libc`의 특정 영역을 가리키는게 아니라 `unsortedbin`이 비어있던 상태에서 들어간 청크는 전부 `fd`와 `bk`가 `libc`의 특정 영역을 가리키니 이를 알고 넘어가자.**

### 다시 돌아와서...

<img width="358" alt="image" src="https://github.com/user-attachments/assets/de907f80-7c39-47a7-963b-4d4cdc34e795">

그럼 2개의 청크를 할당하고, 첫번째 청크를 해제한 상태에서 `fd`와 `bk`가 가리키는 `0x7ffff7fa3ce0`가 `libc`에 속하는지, 속한다면 오프셋은 얼마인지 `vmmap`을 통해 계산해보자.

### 수정할 부분

이번 문제에서 `libc-2.27.so` 라이브러리를 이용해야 하는데, 나는 `vmmap`으로 출력해보면 아래와 같이 `libc.so.6` 버전이 링킹되어 있기 때문에 `libc base`의 가상 주소와 `fd`와 `bk`로 얻은 특정 영역의 주소도 달라지게 된다.

이 부분을 `LD_PRELOAD`와 `LD_LIBRARY_PATH`로 설정해야 한다고 했는데, 이 부분이 힘들어서 일단은 강의자료의 오프셋과 `size`의 입력 값인 `1280`을 써서 할 예정이다. 나중에 수정하자.

```
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
             Start                End Perm     Size Offset File
    0x555555400000     0x555555402000 r-xp     2000      0 /home/dreamhack/uaf_overwrite
    0x555555601000     0x555555602000 r--p     1000   1000 /home/dreamhack/uaf_overwrite
    0x555555602000     0x555555603000 rw-p     1000   2000 /home/dreamhack/uaf_overwrite
    0x555555603000     0x555555624000 rw-p    21000      0 [heap]
    0x7ffff79e2000     0x7ffff7bc9000 r-xp   1e7000      0 /home/dreamhack/libc-2.27.so
    0x7ffff7bc9000     0x7ffff7dc9000 ---p   200000 1e7000 /home/dreamhack/libc-2.27.so
    0x7ffff7dc9000     0x7ffff7dcd000 r--p     4000 1e7000 /home/dreamhack/libc-2.27.so
    0x7ffff7dcd000     0x7ffff7dcf000 rw-p     2000 1eb000 /home/dreamhack/libc-2.27.so
    0x7ffff7dcf000     0x7ffff7dd3000 rw-p     4000      0 [anon_7ffff7dcf]
    0x7ffff7dd3000     0x7ffff7dfc000 r-xp    29000      0 /lib/x86_64-linux-gnu/ld-2.27.so
    0x7ffff7ff4000     0x7ffff7ff6000 rw-p     2000      0 [anon_7ffff7ff4]
    0x7ffff7ff6000     0x7ffff7ffa000 r--p     4000      0 [vvar]
    0x7ffff7ffa000     0x7ffff7ffc000 r-xp     2000      0 [vdso]
    0x7ffff7ffc000     0x7ffff7ffd000 r--p     1000  29000 /lib/x86_64-linux-gnu/ld-2.27.so
    0x7ffff7ffd000     0x7ffff7ffe000 rw-p     1000  2a000 /lib/x86_64-linux-gnu/ld-2.27.so
    0x7ffff7ffe000     0x7ffff7fff000 rw-p     1000      0 [anon_7ffff7ffe]
    0x7ffffffde000     0x7ffffffff000 rw-p    21000      0 [stack]
0xffffffffff600000 0xffffffffff601000 --xp     1000      0 [vsyscall]
```

`size`에 `1280`을 입력했을 때, `fd`와 `bk`의 값은 `0x7ffff7dcdca0`이다. 그리고, `libc`의 가상 주소의 범위는 `0x7ffff79e2000 ~ 0x7ffff7dcf000` 이므로 `fd` 값이 `libc`에 속하는 것도 알 수 있다.

따라서, `libc base`인 `0x7ffff79e2000`와 `0x7ffff7dcdca0`의 차이를 통해 오프셋을 구해보면, `0x3ebca0`이 나온다.

```
pwndbg> p/x 0x7ffff7dcdca0 - 0x7ffff79e2000
$1 = 0x3ebca0
```

그럼 이제 익스플로잇을 통해, `fd`나 `bk` 값을 구한 후 오프셋인 `0x3ebca0`을 빼주면, `libc base`를 Leak 할 수 있을 것이다.

## 2. `fptr` Overwrite

`Human` 구조체와 `Robot` 구조체는 크기가 같고, 멤버 변수의 위치도 같기 때문에 `human_func`에서 `Human` 구조체를 먼저 할당하여, `robot->fptr`의 위치인 `human->age`에 `libc base + one_gadget`을 대입해준 후, `free`해주면 해당 메모리 영역에 데이터가 남아있을 것이다.

그 후 바로 `robot_func`를 호출하여 `Robot` 구조체를 선언하고 `robot->fptr`에 접근하면 해당 위치가 `NULL`이 아니라 원가젯의 주소가 위치할 것이므로, 해당 원가젯이 바로 수행될 수 있을 것이다.

이는 모두 **`free`하기 전에 사용한 영역의 데이터를 초기화해주지 않아서 `UAF` 취약점이 존재**하기 때문에 가능한 방법이다.

# Exploit 

