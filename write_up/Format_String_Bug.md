# 바이너리 분석

```
// Name: fsb_overwrite.c
// Compile: gcc -o fsb_overwrite fsb_overwrite.c

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void get_string(char *buf, size_t size)
{
  ssize_t i = read(0, buf, size); // 읽은 바이트 수를 리턴 (-1 : 오류, 0 : EOF 만난 경우)
  if (i == -1)
  {
    perror("read");
    exit(1);
  }

  if (i < size) // 0x20보다 읽은 바이트 수가 적은 경우
  {
    if (i > 0 && buf[i - 1] == '\n') // buf의 마지막이 개행문자로 끝나는 경우
      i--;
    buf[i] = 0; // 개행문자('\n') 을 지우고 `0`으로 설정
  }
}

int changeme;

int main()
{
  char buf[0x20];

  setbuf(stdout, NULL);

  while (1)
  {
    get_string(buf, 0x20);
    printf(buf);
    puts("");
    if (changeme == 1337)
    {
      system("/bin/sh");
    }
  }
}
```

<img width="631" alt="image" src="https://github.com/user-attachments/assets/37fb6f58-71ed-4d7e-9571-f4326c6c1867">

먼저, 해당 바이너리는 `get_string()` 함수를 통해 포맷 스트링으로 사용되는 `buf`에 `0x20` 크기의 입력을 받아주고, `0x20` 보다 입력된 바이트의 수가 적고, 마지막 바이트가 개행문자(`'\n'`)로 끝나는 경우 개행문자를 `0` 으로 바꿔준다.

이후, `changeme`의 값이 `1337` 이라면 쉘을 획득할 수 있는 바이너리이다. 따라서, 목표는 포맷 스트링 버그를 통해 `changeme` 변수에 `1337`을 입력하는 것이다.

## `changeme`의 주소 찾기

`changeme` 변수는 스택에 존재하지 않고, 해당 바이너리에는 `PIE`가 적용되어 있기 때문에 `gdb`를 통한 가상주소를 바로 넣어줄 수 없고, **`changeme`가 존재하는 세그먼트의 베이스 주소를 Leak한 후에 `changeme`의 `offset`을 더해줘야 한다.**

## `buf`의 위치 찾기

바이너리에 아래와 같이 `AAAAAAA%7$p`와 `AAAAAAA%6$p` 를 차례대로 입력해보면, `6`번째 인자인 `rsp`에 `buf`가 위치함을 알 수 있다.

<img width="642" alt="image" src="https://github.com/user-attachments/assets/05e6a3ec-925f-4cc5-9906-f08cbb9f9a5e">
