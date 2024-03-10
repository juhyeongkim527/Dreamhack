바로 이전 문제인 **rtl(return to library)** 문제에서는 `system@plt`를 사용자가 임의로 등록해주었고, `/bin/sh` 문자열도 사용자가 임의로 등록해주었기 때문에, NX에도 불구하고 익스플로잇이 상당히 수월했다.  

하지만, 일반적으로 `system` 함수를 실제 바이너리에 포함시키는 것은 보안상으로 대부분의 상황에서는 제한되기 때문에 실제로 바이너리에 사용자가 등록한 `system@plt`를 이용하는 공격은 현실에서 거의 불가능하다.  

따라서 현실적으로, ASLR이 적용된 상황에서 `system` 함수를 사용하기 위해서는,    
1. 프로세스에서 `libc` 라이브러리가 무작위로 매핑된 주소를 찾고, 
2. `system`함수와 같은 ***사용하고자 하는 심볼의 `오프셋`*** 을 이용하여 함수의 주소를 계산해야 한다.

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

## 문제 풀이 방법

먼저, 해당 문제는 카나리가 적용되어 있기 때문에, 카나리를 우회하고, `system('/bin/sh')`을 실행하기 위해 `libc` 라이브러리의 `system`함수를 이용할 것이다. 

여기서 `system`함수의 plt는 바이너리에서 사용한 적이 없기 때문에 등록되어 있지 않다. 따라서, 바이너리에서 사용한 `read`, `puts`, `write` 함수의 GOT를 `system` 함수의 GOT 주소로 조작해서 해당 plt를 호출하여 `system`함수를 실행할 수 있다. ASLR에 의해 `libc` 라이브러리의 주소가 무작위로 매핑되기 때문에 각 함수의 **오프셋**을 통해 GOT를 Overwrite할 것이다. 

또한 `/bin/sh` 문자열을 `libc`에서 찾는 경우의 수도 존재하지만, 여기서는 `buf`에 직접 `/bin/sh` 문자열을 입력할 수 있기 때문에, 해당 문자열을 직접 입력함으로써 해결할 수 있다. 

<img width="735" alt="image" src="https://github.com/juhyeongkim527/Dreamhack-Study/assets/138116436/2ae1e208-565e-4fb1-904d-d925cb5d036a">

`libc`에서 `bin/sh`의 주소를 찾으려면 오프셋을 또 계산해야하기 때문에 복잡하기 때문이다.

## 1. 카나리 우회

<img width="965" alt="image" src="https://github.com/juhyeongkim527/Dreamhack-Study/assets/138116436/31831586-e83b-4a05-82b3-d90d544da675">

해당 스크린샷에서 buf의 위치는 `rbp-0x40`, 카나리의 위치는 `rbp-0x8`이라는 것을 알 수 있다. 따라서, 카나리를 우회하기 위해 `b'a'*0x39`를 첫번째 페이로드에 담아 전달하여 카나리를 구할 수 있다.

## 2. `system` 함수의 주소 계산

`system` 함수는 `libc.so.6`에 정의되어 있으며, 해당 라이브러리에는 이 바이너리가 호출하는 `read`, `puts`, `printf`도 정의되어 있다. 라이브러리 파일은 메모리에 매핑될 때 전체가 매핑되므로, 다른 함수들과 함께 `system` 함수도 프로세스 메모리에 같이 매핑된다.

바이너리에 `system` 함수가 포함되어 있지 않기 때문에, `system` 함수가 `GOT`에 등록되지는 않지만, 대표적으로 `read` 함수는 GOT에 등록된다. 따라서, `main` 함수에서 `read`를 호출한 이후 해당 함수의 GOT를 읽을 수 있다면, `libc.so.6`이 매핑된 영역의 주소를 알 수 있다.

`read`를 호출한 이후에는 해당 GOT에 메모리에 무작위로 매핑된 `libc` 라이브러리에서 `read`의 고정된 offset만큼 떨어진 거리를 알 수 있기 때문에 `libc`의 베이스 주소를 알 수 있게 되기 때문이다. 참고로, libc 버전은 여러개지만 같은 버전 내에서는 오프셋이 고정되어있다.

예를 들어, Ubuntu GLIBC 2.35-0ubuntu3.1에서 `read` 함수와 `system` 함수 사이의 거리는 항상 `0xc3c20`이다.   
따라서 `read` 함수의 주소를 알 때, `system = read - 0xc3c20`으로 `system` 함수의 주소를 구할 수 있다.  
`libc` 파일이 있으면 다음과 같이 `readelf` 명령어로 함수의 오프셋을 구할 수 있다.

```
$ readelf -s libc.so.6 | grep " read@"
   289: 0000000000114980   157 FUNC    GLOBAL DEFAULT   15 read@@GLIBC_2.2.5
$ readelf -s libc.so.6 | grep " system@"
  1481: 0000000000050d60    45 FUNC    WEAK   DEFAULT   15 system@@GLIBC_2.2.5
```

`read` 함수의 오프셋은 `0x114980` 이고, `system` 함수의 오프셋은 `0x50d60`이므로 둘을 빼면, `0xc3c20`이 나오게 된다.  
따라서, `read` 함수가 resolve된 이후 GOT 주소를 알 때, 해당 함수의 주소에서 `0xc3c20`을 뺴면, `system`함수의 주소도 알 수 있다.

## 3. "/bin/sh"

해당 바이너리의 데이터 영역에는 `/bin/sh` 문자열을 사용한 적이 없으므로 존재하지 않는다. 따라서, 이 문자열을 임의의 버퍼에 직접 주입해서 사용하거나 다른 파일에 포함된 것을 사용해야 한다.

후자의 경우를 택할 때 가장 많이 사용되는 파일이 `libc.so.6`에 포함된 `/bin/sh` 문자열이다. 이 문자열의 주소 또한 `system` 함수를 구할 때 처럼 `offset`을 이용하여 구할 수 있다.

<img width="735" alt="image" src="https://github.com/juhyeongkim527/Dreamhack-Study/assets/138116436/2ae1e208-565e-4fb1-904d-d925cb5d036a">

우리는 해당 문제에서 `buf`에 직접 `/bin/sh` 문자열을 주입할 수 있기 때문에 전자의 방법을 사용하겠다.

## 4. GOT Overwrite





