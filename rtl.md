# 문제 풀이 방법

해당 문제의 소스 코드는 아래와 같다.
```
// Name: rtl.c
// Compile: gcc -o rtl rtl.c -fno-PIE -no-pie

#include <stdio.h>
#include <unistd.h>

const char* binsh = "/bin/sh";

int main() {
  char buf[0x30];

  setvbuf(stdin, 0, _IONBF, 0);
  setvbuf(stdout, 0, _IONBF, 0);

  // Add system function to plt's entry
  system("echo 'system@plt");

  // Leak canary
  printf("[1] Leak Canary\n");
  printf("Buf: ");
  read(0, buf, 0x100);
  printf("Buf: %s\n", buf);

  // Overwrite return address
  printf("[2] Overwrite return address\n");
  printf("Buf: ");
  read(0, buf, 0x100);

  return 0;
}
```
`checksec`으로 바이너리를 검사해보면, **카나리**와 **NX**가 적용되어있기 때문에 **스택에 쉘코드를 주입 후 return_address를 해당 주소로 조작하는 것은 불가능하다.** (스택이 아닌 코드 영역으로 return_address를 조작해야함) 

쉘코드를 주입할 수 없다고 하더라도, C의 표준 라이브러리인 `libc`에는 익스플로잇에 사용할 수 있는 유용한 코드 가젯이 존재한다. 코드 영역은 ASLR이 적용되지 않아 바이너리 생성 시 주소가 고정되어 있기 때문에 해당 코드 영역에서 익스플로잇에 필요한 가젯을 추출하여 사용할 수 있다.

하지만, 소스 코드에서 사용하는 함수(심볼)만 PLT를 통해 라이브러리에서 호출 해올 수 있기 때문에 이를 잘 파악해야한다. 위 소스 코드를 살펴보면, 

- `const char* binsh = "/bin/sh";`와 `system("echo 'system@plt");`를 통해 `system()` 함수를 PLT 테이블에 등록하여 `system('/bin/sh')` 함수를 통해 쉘을 실행할 수 있고,
- ```
  printf("[1] Leak Canary\n");
  printf("Buf: ");
  read(0, buf, 0x100);
  printf("Buf: %s\n", buf);
  ```
  를 통해, canary 값을 알 수 있다.

따라서, 카나리를 우회하고 return_address를 `system('/bin/sh')` 함수를 수행하는 코드 영역으로 return_address 를 조작하여 해당 문제를 풀이 할 수 있을 것이다.

