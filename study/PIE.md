# 정리

1. `PIE`가 적용되지 않고 `ASLR`만 적용된 바이너리에서는 `Compile-Time-Binding`이 적용되어 바이너리가 매핑되는 `가상 베이스 주소`는 고정되어 있다. 그리고 `스택, 힙, 라이브러리의 베이스 주소`는 랜덤화되기 때문에 항상 구해줘야 한다.

2. `PIE`가 적용된 바이너리에서는 바이너리가 매핑되는 `가상 베이스 주소`가 바뀌고, 코드 섹션, 데이터 섹션의 오프셋은 바뀌지 않는다. 코드 섹션, 데이터 섹션이 랜덤화되어 보이는 이유는 `가상 베이스 주소`가 바뀌므로 여기에 더해지는 섹션의 시작 주소 또한 달라보이는 것이다.

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

## PIE

**Position-Independent Executable(PIE)** 는 무작위 주소에 매핑돼도 실행 가능한 실행 파일(바이너리)를 뜻한다.

ASLR이 도입되기 전에는 실행 파일을 무작위 주소에 매핑할 필요가 없었기 때문에 리눅스는 실행 파일의 재배치를 고려하지 않고 설계되었다.

이후에 ASLR이 도입되었을 때 실행 파일도 메모리에 무작위로 매핑되게 하고 싶었지만, 이미 널리 사용되고 있던 실행 파일의 형식을 바꾸어 메모리에 무작위 재배치가 가능하도록 하면 호환성 문제가 발생하여 장점보다 단점이 더 크게 될 수 밖에 없었다.

그래서 개발자들은 실행 파일과 달리 원래 재배치가 가능하도록 설계된 공유 오브젝트(Shared Object)를 실행 파일로 사용하기로 했다.

리눅스의 기본 실행 파일 중 하나인 `/bin/ls`의 파일 헤더 정보를 살펴보면 `Type`이 공유 오브젝트를 나타내는 `DYN(ET_DYN)`임을 알 수 있다.

```
$ readelf -h /bin/ls
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              DYN (Position-Independent Executable file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x6ab0
  Start of program headers:          64 (bytes into file)
  Start of section headers:          136224 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         13
  Size of section headers:           64 (bytes)
  Number of section headers:         31
  Section header string table index: 30
```

## PIE on ASLR

PIE는 재배치가 가능하므로, ASLR이 적용된 시스템에서 실행 파일도 무작위 주소에 적재되게 된다. 참고로 ASLR이 적용되지 않은 시스템에서는 PIE가 적용되어도 실행 파일이 무작위 주소에 적재되지 않는다.

`addr` 실행 파일을 `-no-pie` 옵션을 제거하여 PIE가 적용되도록 컴파일하면 아래와 같이 코드 영역인 `main` 함수의 주소가 바뀌는 것을 알 수 있다.

```
$ gcc -o pie addr.c -ldl
$ ./pie
buf_stack addr: 0x7ffc85ef37e0
buf_heap addr: 0x55617ffcb260
libc_base addr: 0x7f0989d06000
printf addr: 0x7f0989d6af00
main addr: 0x55617f1297ba
$ ./pie
buf_stack addr: 0x7ffe9088b1c0
buf_heap addr: 0x55e0a6116260
libc_base addr: 0x7f9172a7e000
printf addr: 0x7f9172ae2f00
main addr: 0x55e0a564a7ba
$ ./pie
buf_stack addr: 0x7ffec6da1fa0
buf_heap addr: 0x5590e4175260
libc_base addr: 0x7fdea61f2000
printf addr: 0x7fdea6256f00
main addr: 0x5590e1faf7ba
```

## PIE 우회

### 코드의 base주소 구하기

ASLR 환경에서 PIE가 적용되면 바이너리가 실행될 때 마다 다른 주소에 적재된다.   

이렇게 되면, 이전과 달리 **바이너리 코드 영역의 가젯을 바로 사용하거나, 데이터 영역에 접근하려면** 바이너리가 실행될 때 마다 바뀌는 메모리에 적재된 주소를 알아야한다. 

이 주소를 PIE 베이스, 또는 코드 베이스라고 부른다. 코드 베이스를 구하려면 라이브러리의 베이스 주소를 구하듯이 코드 영역의 임의 주소를 읽고, 알고 있는 오프셋을 통해 읽은 영역의 오프셋을 빼줌으로써 베이스 주소를 구할 수 있다.

이는 ROP에서 공유 라이브러리의 베이스 주소를 구하는 방식과 크게 다르지 않다.

### Partial Overwrite

코드 베이스를 구하기 어렵다면 반환 주소의 일부 바이트만 덮는 공격을 고려해볼 수 있다. 이러한 공격을 Partial Overwrite라고 한다.

일반적으로 함수의 반환 주소는 그 함수를 호출한 함수(Caller)의 내부를 가리킬 것이다. 특정 함수의 호출 관계는 정적 분석 또는 동적 분석으로 쉽게 확인할 수 있으므로, 공격자는 반환 주소를 예측할 수 있다.

ASLR 특성상, 페이징으로 인해 스택, 힙, 라이브러리가 매핑된 주소와 같이 **코드 영역의 주소도 하위 12비트 값이 항상 같다.**

따라서, 사용하려는 코드 가젯의 주소가 반환 주소와 하위 한 바이트만 다르다면, 이 갚을 덮어서 원하는 코드를 실행시킬 수 있다.

하지만, 만약 두 바이트 이상이 다른 주소로 실행 흐름을 옮기려고 한다면, ASLR로 랜덤화되는 주소를 맞춰야 하므로 브루트 포싱이 필요하며, 익스플로잇이 확률에 따라 성공하게 된다.

## 정리

- **상대 참조(Relative Addressing)**: 어떤 값을 기준으로 다른 주소를 지정하는 방식

- **Position Independent Code (PIC)**: 어떤 주소에 매핑되어도 실행 가능한 코드. `절대 주소`를 사용하지 않으며 일반적으로 `rip`를 기준으로 한 상대 주소를 사용함.

- **Position Independent Executable (PIE)**: 어떤 주소에 매핑되어도 실행 가능한 실행 파일. PIE의 코드는 모두 PIC이다. 자체적으로 보호 기법은 아니지만 ASLR이 적용된 환경에서는 시스템을 더욱 안전하게 만드는 효과가 있음. 최신 gcc는 기본적으로 PIE 컴파일을 함.

- **Partial Overwrite**: 어떤 값을 일부분만 덮는 공격 방법. PIE를 우회하기 위해 사용될 수 있음.

### 참고 : 페이징(Paging)

<img width="685" alt="image" src="https://github.com/juhyeongkim527/Dreamhack-Study/assets/138116436/fa694c8a-7ad3-42e6-b382-c9ceea69bba5">
