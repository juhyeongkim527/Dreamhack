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

NX로 인해 쉘코드를 스택에 주입할 수 없다고 하더라도, `바이너리의 코드 영역`과 `라이브러리의 코드 영역`에는 실행 권한이 존재하기 때문에, 해당 영역으로 return_address를 조작하면 익스플로잇이 여전히 가능하다.
그리고 C의 표준 라이브러리인 `libc`에는 익스플로잇에 사용할 수 있는 유용한 코드 가젯이 존재한다. 바이너리의 코드 영역은 ASLR이 적용되지 않아 바이너리 생성 시 주소가 고정되어 있기 때문에 해당 코드 영역에서 익스플로잇에 필요한 가젯을 추출하여 사용할 수 있다. 

하지만, **PLT**를 이용하기 위해서는 소스 코드에서 사용된 함수(심볼)만 PLT를 통해 라이브러리에서 호출해올 수 있기 때문에 이를 잘 파악해야한다. 위 소스 코드를 살펴보면, 

- `const char* binsh = "/bin/sh";`와 `system("echo 'system@plt");`를 통해 `system()` 함수를 PLT 테이블에 등록하여 `system('/bin/sh')` 함수를 통해 쉘을 실행할 수 있고,  
***참고로, ASLR이 걸려있어도 PIE가 적용되어 있지 않다면 PLT의 주소는 고정되어 있음. 따라서, ASLR에 의해 랜덤화되는 라이브러리의 베이스 주소를 몰라도 PLT주소는 고정되어 있기 때문에 라이브러리 함수를 실행할 수 있음. 해당 공격 기법을 Return to PLT라고 함.***
- ```
  printf("[1] Leak Canary\n");
  printf("Buf: ");
  read(0, buf, 0x100);
  printf("Buf: %s\n", buf);
  ```
  를 통해, canary 값을 알 수 있다.

따라서, 카나리를 우회하고 return_address를 `system('/bin/sh')` 함수를 수행하는 코드 영역으로 return_address 를 조작하여 해당 문제를 풀이 할 수 있을 것이다.

## 리턴 가젯
가젯(gadget)은 코드 조각을 의미하는데, 여기서 **리턴 가젯**이란 다음과 같이 `ret`으로 끝나는 어셈블리 코드 조각을 의미한다.  
pwntools 설치 시 함께 설치되는 `ROPgadget`명령어를 통해 원하는 가젯을 구할 수 있다. (아래는 `rtl`의 코드 가젯 목록)
```
$ ROPgadget --binary rtl
Gadgets information
============================================================
...
0x0000000000400285 : ret
...

Unique gadgets found: 83
$
```
리턴 가젯은 여러번의 `ret`을 통해 반환 주소를 덮는 공격의 유연성을 높여서 익스플로잇에 **필요한 조건**을 만족할 수 있도록 돕는다.  
예를 들어 해당 문제에서는 `system('/bin/sh')`을 실행하기 위해 먼저 `rdi`를 `/bin/sh`로 설정하고 `system` 함수를 호출해야 하는데, 이를 위해서는 한번의 과정이 아닌 여러번의 과정이 필요하다.  
이럴 때 리턴 가젯을 여러번 사용하여 반환 주소와 이후의 버퍼를 연속적으로 덮어서, `pop rdi`로 `rdi`를 `/bin/sh`의 주소로 설정해주고, 이어지는 `ret`으로 `system`함수를 호출할 수 있다.
```
addr of ("pop rdi; ret")   <= return address
addr of string "/bin/sh"   <= ret + 0x8
addr of "system" plt       <= ret + 0x10
```
대부분의 함수는 `ret`으로 종료되므로, 함수들도 리턴 가젯으로 사용될 수 있는데 이러한 공격을 **Return_Oriented Programming(ROP)** 라고 한다.

## 익스플로잇 코드

