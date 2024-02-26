C의 표준 라이브러리인 `libc`는 우분트에 기본으로 탑재된 라이브러리이며, `/lib/x86_64-linux-gnu/libc.so.6`에 있음. 그래서 arm 맥북 터미널에서는 `#include<stdio.h>`를 하지 않으면 기본 라이브러리 함수를 수행할 수 없음.

## Link

리눅스에서 C 소스 코드 컴파일 단계는 **전처리, 컴파일, 어셈블, 링크** 단계로 이루어진다. 

해당 과정을 거쳐 소스 코드는 기계어 코드인 Object 파일(.o 확장자)로 번역되지만, 해당 Object 파일은 ELF 형식이지만 `executable`이 아닌 `relocatable` 형식으로 실제로 실행할 수 없다. 

그 이유는 오브젝트 파일은 대표적으로 라이브러리 함수와 같이 어셈블 단계에서 찾은 **심볼**들이 기록은 되어 있지만 심볼에 대한 자세한 내용이 하나도 기록되어 있지 않기 때문이다. 즉 오브젝트 파일에서는 심볼이 존재만 할 뿐 라이브러리 함수들의 정의와 내용이 어디 있는지 알 수 없다.

오브젝트 파일에 존재하는 **심볼들의 정보를 찾아서 실행 파일에 기록**하는 것이 바로 Link 과정 중에 일어나는 일이다.

아래의 코드를 예시로 링크 전, 후를 비교해보자.
```
// Name: hello-world.c
// Compile: gcc -o hello-world hello-world.c

#include <stdio.h>

int main() {
  puts("Hello, world!");
  return 0;
}
```
링크 전의 오브젝트 파일을 아래의 명령어로 파악해보면, 심볼의 정보가 기록되어있지 않기 때문에 라이브러리 함수들의 정의가 어디 있는지 알지 못하므로 실행이 불가능하다. 아래와 같이 `puts`의 선언이 <stdio.h>에 있어서 **심볼**은 존재하지만 정보는 아예 없다. 해당 심볼의 정보를 찾아서 기록하는 것이 링크 과정에서 일어나는 일이다.

```
$ readelf -s hello-world.o | grep puts
    11: 0000000000000000     0 NOTYPE  GLOBAL DEFAULT  UND puts
```

아래와 같이 링크 후에는 `libc`에서 `puts`의 정의를 찾아서 연결한다. 
```
$ gcc -o hello-world hello-world.c
$ readelf -s hello-world | grep puts
     2: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND puts@GLIBC_2.2.5 (2)
    46: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND puts@@GLIBC_2.2.5
$ ldd hello-world  --> ldd는 라이브러리 의존성을 확인하는 명령어이다. 
        linux-vdso.so.1 (0x00007ffec3995000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fee37831000)
        /lib64/ld-linux-x86-64.so.2 (0x00007fee37e24000)
```
여기서 `libc` 라이브러리를 같이 컴파일하지 않아도 `libc`에서 오브젝트 파일에 존재하는 심볼을 탐색한 것은 `libc`가 있는 `/lib/x86_64-linux-gnu/`가 표준 라이브러리 경로에 포함되어 있기 때문이다. 

gcc는 소스 코드를 컴파일할 때 표준 라이브러리의 라이브러리 파일들을 모두 탐색하기 때문이다. 아래의 정리된 명령어로 표준 라이브러리의 경로를 확인할 수 있다.
```
$ ld --verbose | grep SEARCH_DIR | tr -s ' ;' '\n'
SEARCH_DIR("=/usr/local/lib/x86_64-linux-gnu")
SEARCH_DIR("=/lib/x86_64-linux-gnu")
SEARCH_DIR("=/usr/lib/x86_64-linux-gnu")
SEARCH_DIR("=/usr/lib/x86_64-linux-gnu64")
SEARCH_DIR("=/usr/local/lib64")
SEARCH_DIR("=/lib64")
SEARCH_DIR("=/usr/lib64")
SEARCH_DIR("=/usr/local/lib")
SEARCH_DIR("=/lib")
SEARCH_DIR("=/usr/lib")
SEARCH_DIR("=/usr/x86_64-linux-gnu/lib64")
SEARCH_DIR("=/usr/x86_64-linux-gnu/lib")
```
링크를 거치고 나면 프로그램에서 puts를 호출할 때, puts의 정의가 있는 libc에서 puts의 코드를 찾고, 해당 코드를 실행하게 된다.

## Static Link vs Dynamic Link
동적 라이브러리를 링크 하는 것을 동적 링크, 정적 라이브러리를 링크하는 것을 정적 링크라고 부른다. 이를 더 자세히 비유와 함께 알아보면,

### 동적 링크

동적 링크된 바이너리를 실행하면 **동적 라이브러리가 프로세스의 메모리에** 매핑된다. 그리고 실행중에 라이브러리의 함수를 호출하면 매핑된 라이브러리에서 호출할 함수의 주소를 찾고, 그 함수를 실행한다.

### 정적 링크

정적 링크를 하면 **바이너리에 정적 라이브러리의 필요한 모든 함수가** 포함된다. 따라서, 해당 함수를 호출할 때 라이브러리를 참조하는 것이 아니라, 자신이 정의한 함수를 호출하는 것처럼 호출할 수 있다. 

동적 링크와 달리 라이브러리에서 원하는 함수를 찾지 않아도 되서 탐색의 비용이 절감될 수 있지만, 여러 바이너리에서 같은 라이브러리를 사용하면 동일한 라이브러리 복제가 여러 번 이루어지기 때문에 용량을 낭비하게 된다.

***정적 링크 시 컴파일 옵션에 따라 include 한 헤더의 함수가 모두 포함 될 수도 있고 그렇지 않을 수도 있다.***

## 실제 바이너리 비교

```
$ gcc -o static hello-world.c -static   --> 정적 링크
$ gcc -o dynamic hello-world.c -no-pie  --> 동적 링크
```

`dynaic [source] -static` 으로 정적 링크를, `dynamic [source]` 으로 동적 링크를 할 수 있다. (-no-pie는 PIE 없애서 ASLR 없애는거)

```
$ ls -lh ./static ./dynamic
-rwxrwxr-x 1 dreamhack dreamhack  16K May 22 02:01 ./dynamic
-rwxrwxr-x 1 dreamhack dreamhack 880K May 22 02:01 ./static
```

위와 같이 서로의 바이너리 크기를 비교해보면 정적 링크된 바이너리가 동적 링크된 바이너리보다 약 50배 가까운 용량을 더 많이 차지한다.

### 호출 방법

`static` 에서는 `puts` 함수의 정의가 존재하는 실제 메모리 주소를 호출하는 반면, `dynamic` 에서는 `put`의 `plt주소`를 호출한다.

이러한 차이가 발생하는 이유는 정적 링크에서는 정적 라이브러리의 함수 자체를 바이너리에 포함시키지만, 동적 링크에서는 동적 라이브러리를 메모리에 매핑시킨 후 바이너리 실행 시 해당 매핑 메모리에서 함수의 주소를 **찾아야** 하기 때문이다.

**static**
```
main:
  push   rbp
  mov    rbp,rsp
  lea    rax,[rip+0x96880] # 0x498004
  mov    rdi,rax
  call   0x40c140 <puts>
  mov    eax,0x0
  pop    rbp
  ret
```

**dynamic**
```
main: 
 push   rbp
 mov    rbp,rsp
 lea    rdi,[rip+0xebf] # 0x402004
 mov    rdi,rax
 call   0x401040 <puts@plt>
 mov    eax,0x0
 pop    rbp
 ret
 ```

## PLT & GOT

