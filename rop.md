바로 이전 문제인 **rtl(return to library)** 문제에서는 `system@plt`를 사용자가 임의로 등록해주었고, `/bin/sh` 문자열도 사용자가 임의로 등록해주었기 때문에, NX에도 불구하고 익스플로잇이 상당히 수월했다.  

하지만, 일반적으로 `system` 함수를 실제 바이너리에 포함시키는 것은 보안상으로 대부분의 상황에서는 제한되기 때문에 실제로 바이너리에 사용자가 등록한 `system@plt`를 이용하는 공격은 현실에서 거의 불가능하다.  

***따라서 현실적으로, ASLR이 적용된 상황에서 `system` 함수를 사용하기 위해서는 프로세스에서 `libc` 라이브러리가 무작위로 매핑된 주소를 찾고, `system`함수와 같은 사용하고자 하는 심볼의 오프셋을 이용하여 함수의 주소를 계산해야 한다.***

여러 리턴 가젯을 이용하는 **ROP**와 **GOT Overwrite** 기법을 통해 어떻게 이런 공격을 이룰 수 있는지 알아보고 실제로 이용해보자.

# ROP : Return Oriented Programming

`ROP`는 리턴 가젯을 사용하여 복잡ㅈ한 실행 흐름을 구현하는 기법이다. 공격자는 이를 이용하여 문제 상황에 따라, `return to library`, `return to dl-resolve`, `GOT overwrite` 등 여러 기법으로 페이로드를 구성할 수 있다.

지난 rtl 문제에서는 `system@plt`를 통해 return to library 기법을 사용하여 문제를 해결하였었다.

이번 `rop.c` 문제에서는 여러 `ret` 단위로 구성된 ROP를 이용한 `GOT Overwrite`를 활용하여 문제를 해결하여 보겠다. 아래는 소스 코드이다.
```
// Name: rop.c
// Compile: gcc -o rop rop.c -fno-PIE -no-pie

#include <stdio.h>
#include <unistd.h>

int main() {
  char buf[0x30];

  setvbuf(stdin, 0, _IONBF, 0);
  setvbuf(stdout, 0, _IONBF, 0);

  // Leak canary
  puts("[1] Leak Canary");
  write(1, "Buf: ", 5);
  read(0, buf, 0x100);
  printf("Buf: %s\n", buf);

  // Do ROP
  puts("[2] Input ROP payload");
  write(1, "Buf: ", 5);
  read(0, buf, 0x100);

  return 0;
}
```
