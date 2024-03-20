## 서론

ASLR이 적용되면 바이너리가 실행될 때마다 스택, 힙, 공유 라이브러리 등이 임의의 무작위 주소에 매핑되므로 공격자가 이 영역들을 알아내기 힘들어져 익스플로잇의 난이도가 어려워졌다.

ASLR 강의의 실습 바이너리 중 `addr`을 떠올려 보면 `stack, heap, library` 등의 주소는 바이너리 실행마다 계속 바뀌었지만, `main` 함수의 주소는 아래와 같이 항상 같았다.

```
$ gcc addr.c -o addr -ldl -no-pie -fno-PIE
$ ./addr
buf_stack addr: 0x7ffffd430560
buf_heap addr: 0x7d0010
printf addr: 0x7f6a241ee810
main addr: 0x400736
$ ./addr
buf_stack addr: 0x7fff22f2c2a0
buf_heap addr: 0x2126010
printf addr: 0x7f1efab79810
main addr: 0x400736
```

그 이유는 `main` 함수는 **바이너리의 코드 영역**이므로 ASLR이 적용되어도 바뀌지 않았기 때문이다. 

하지만, 이번 강의에서 배울 **Position-Independent Executable(PIE)** 가 적용된다면 ASLR이 코드 영역에도 적용되게 되어 `main`함수와 같은 코드 영역의 주소도 알아내기 힘들어진다. 

PIE는 원래 보안을 위해 등장한 기법은 아니지만, 실제로 ASLR 처럼 공격자의 익스플로잇을 어렵게 만들어 보호 기법으로 소개되기도 한다.

ASLR이 적용되었을 때, 라이브러리의 베이스 주소를 구하고 오프셋을 통해 라이브러리에서 필요한 함수를 구했듯이, PIE가 적용되었을 때도 코드 영역의 베이스 주소를 구하고 원하는 코드의 오프셋을 통해 실제 주소를 구하는 방법으로 공격을 할 수 있다.

이번 글에서는 PIE에 대해 자세히 알아볼 것이다.

## PIC

리눅스에서 **ELF**는 실행 파일(Executable)과 공유 오브젝트(Shared Object, SO)로 두 가지가 존재한다.

```
$ file addr
addr: ELF 64-bit LSB executable
$ file /lib/x86_64-linux-gnu/libc.so.6
/lib/x86_64-linux-gnu/libc.so.6: ELF 64-bit LSB shared object
```

실행 파일은 `addr` 처럼 일반적인 바이너리 실행 파일이 해당되고, 공유 오브젝트는 `libc.so.6`과 같은 라이브러리 파일이 해당된다.

공유 오브젝트는 ASLR에서도 알 수 있듯이, 기본적으로 재배치(Relocation)가 가능하도록 설계되어 있었다. 재배치가 가능하다는 것은 메모리의 어느 주소에 무작위로 적재되어도 코드의 의미나 수행 결과가 훼손되지 않음을 뜻한다.  

컴퓨터 과학에서는 이런 성질을 만족하는 코드를 **Position-Independent Code(PIC)** 라고 부른다.

gcc는 PIC 컴파일을 지원하므로, 아무런 옵션이 없으면 PIC 컴파일이 적용된다. PIC가 적용된 바이너리와 그렇지 않은 바이너리를 비교해보자.

```
// Name: pic.c
// Compile: gcc -o pic pic.c
// 	      : gcc -o no_pic pic.c -fno-pic -no-pie
#include <stdio.h>
char *data = "Hello World!";
int main() {
  printf("%s", data);
  return 0;
}
```

위 코드는 PIC에 대해 비교해보기 위한 코드이며, `gcc -o pic pic.c` 로 컴파일하면 PIC가 적용되고 `gcc -o no_pic pic.c -fno-pic -no-pie`로 컴파일하면 PIC가 적용되지 않게 된다.

### 바이너리 분석

```
$ gdb ./no_pic
pwndbg> x/s 0x4005a1
0x4005a1:       "%p"
```

```
$ gdb ./pic
pwndbg> x/s 0x711
0x711:  "%p"
```

```
 push   rbp
 mov    rbp,rsp
-mov    rax,QWORD PTR [rip+0x200b3e]        # 0x601030 <data> : no-pic
+mov    rax,QWORD PTR [rip+0x2009ab]        # 0x201010 <data> : pic
 mov    rsi,rax
-mov    edi,0x4005a1                                          : no-pic
+lea    rdi,[rip+0xa2]        # 0x711                         : pic
 mov    eax,0x0
-call   0x4003f0 <printf@plt>                                 : no-pic
+call   0x530 <printf@plt>                                    : pic
 mov    eax,0x0
 pop    rbp
 ret
```
`no_pic`와 `pic`의 `main` 함수를 비교해보면, `main+14`에서 `%p` 문자를 `printf` 함수에 전달하는 방식이 다르게 나타난다.

PIC가 적용되지 않는 `no_pic` 에서는 문자열을 `0x4005a1`이라는 절대 주소를 통해 참조하는 반면,

PIC가 적용된 `pic`에서는 `0x711`을 `rip+0xa2`인 `rip`에 상대주소(오프셋)을 더하는 방식으로 참조한다.

ASLR처럼 영역이 메모리에 매핑되는 주소가 달라지면, `no-pic`에서는 `0x4005a1`에 있던 데이터도 함게 이동하고 해당 메모리에는 다른 값으로 대체될 수 있기 때문에 절대주소로 참조하면 바이너리의 실행이 제대로 이루어지지 못하는 반면,

`pic`에서는 `rip`를 기준으로 상대주소(오프셋)을 통해 **상대참조(Relative Addressing)** 하기 때문에 바이너리가 메모리에 무작위 주소로 매핑되어도 제대로 실행될 수 있다.

<img width="685" alt="image" src="https://github.com/juhyeongkim527/Dreamhack-Study/assets/138116436/fa694c8a-7ad3-42e6-b382-c9ceea69bba5">
