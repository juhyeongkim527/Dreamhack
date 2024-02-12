# pwntools
익스플로잇을 위한 함수들을 구현해둔 파이썬 모듈
- [공식 문서](https://docs.pwntools.com/en/latest/)

### 용어 정리
- Exploit(익스플로잇) = 공격, 침투
- Payload(페이로드) = 순수한 데이터, 즉 익스플로잇시 전달하는 데이터나 행위 ex) 랜섬웨어, 백도어, 셸코드

## process & remote

|익스플로잇 대상|로컬 바이너리|원격 서버|
|-|-|-|
||process|remote|

- process는 보통 익스플로잇을 **테스트**하고 **디버깅**하기 위해 사용
- remote는 대상 서버를 **실제로 공격**하기 위해 사용

```
from pwn import *
p = process('./test')  # 로컬 바이너리 'test'를 대상으로 익스플로잇 수행
p = remote('example.com', 31337)  # 'example.com'의 31337 포트에서 실행 중인 프로세스를 대상으로 익스플로잇 수행
```

## send

- send는 데이터를 프로세스에 전송하기 위해 사용하며 pwntools에는 관련된 다양한 함수가 정의되어 있음
```
from pwn import *
p = process('./test')

p.send(b'A') # ./test에 b'A'를 입력
p.sendline(b'A') # ./test에 b'A' + b'\n'을 입력
p.sendafter(b'hello', b'A') # ./test가 b'hello'를 출력하면, b'A'를 입력
p.sendafterline(b'hello', b'A') # ./test가 hello를 출력하면 b'A' + b'\n'을 입력
```

## recv

- recv는 프로세스에서 데이터를 받기 위해 사용하며 pwntools에는 관련된 다양한 함수가 정의되어 있음
- **recv(n)은 최대 n 바이트**를 받는 것이므로, 그만큼을 받지 못해도 에러를 발생시키지 않지만,  
  **recvn(n)의 경우 정확히 n 바이트**의 데이터를 받지 못하면 계속 기다림

```
from pwn import *
p = process('./test')

data = p.recv(1024) # p가 출력하는 데이터를 최대 1024바이트까지 받아서 data에 저장
data = p.recvline() # p가 출력하는 데이터를 개행문자를 만날 때 까지 받아서 data에 저장
data = p.recvn(5) # p가 출력하는 데이터를 정확히 5바이트만 받아서 data에 저장
data = p.recvuntill(b'hello') # p가 b'hello'가 출력할 때까지 데이터를 data에 저장 
data = p.recvall() # 프로세스가 종료될 때 까지 p가 출력하는 모든 데이터를 data에 저장
```
## packing & unpacking

- packing : 어떤 값을 **리틀 엔디언의 바이트 배열로** 변경
- unpacking : 리틀 엔디언의 바이트 배열을 **어떤 값(hex, ASCII 등)으로** 변경

```
#!/usr/bin/env python3
# Name: pup.py

from pwn import *

# hex 정수
s32 = 0x41424344
s64 = 0x4142434445464748

print(p32(s32)) # 32비트 정수를 리틀 엔디언 바이트 배열로 packing
print(p64(s64)) # 64비트 정수를 리틀 엔디언 바이트 배열로 packing

# 바이트 배열
s32 = b"ABCD" 
s64 = b"ABCDEFGH"

print(hex(u32(s32))) # 32비트 바이트 배열을 32비트 정수로 unpacking후 hex값으로 print
print(hex(u64(s64))) # 64비트 바이트 배열을 64비트 정수로 unpacking후 hex값으로 print
```
```
$ python3 pup.py
b'DCBA' >> packing
b'HGFEDCBA' >> packing
0x44434241 >> unpacking
0x4847464544434241 >> unpacking
```

## interactive

- 셸을 획득했거나, 익스플로잇의 특정 상황에서 **직접 입력을 주면서** 출력을 확인하고 싶을 때 사용하는 함수

```
from pwn import *
p = process('./test')
p.interactive()
```
## ELF

- ELF 헤더에는 익스플로잇에 사용될 수 있는 각종 정보가 기록 pwntools를 사용하면 이 정보들을 쉽게 참조할 수 있음

```
from pwn import *
e = ELF('./test')
puts_plt = e.plt['puts'] # ./test에서 puts()의 PLT 주소를 찾아서 puts_plt에 저장
read_got = e.got['read'] # ./test에서 read()의 GOT 주소를 찾아서 read_got에 저장
```

## context.log

- 익스플로잇에 버그 발생시 익스플로잇을 디버깅하는 로깅 기능

```
from pwn import *
context.log_level = 'error' # 에러만 출력
context.log_level = 'debug' # 대상 프로세스와 익스플로잇간에 오가는 모든 데이터를 화면에 출력
context.log_level = 'info'  # 비교적 중요한 정보들만 출력
```

## context.arch

- 공격 대상의 아키텍쳐에 영향을 받는 셸코드 생성, 코드 어셈블, 코드 디스어셈블 기능을 위해 아키텍처 정보를 지정할 수 있음
- context.arch에 따라 몇몇 함수들의 동작이 달라짐

```
from pwn import *
context.arch  = "amd64" # x86-64
context.arch = "i386" # x86
context.arch = "arm" # arm
```

## shellcraft

- 자주 사용되는 셸 코드들이 저장되어 있어서, 공격에 필요한 셸 코드를 쉽게 꺼내 쓸 수 있게 해줌
- 매우 편리한 기능이지만 정적으로 생성된 셸 코드는 셸 코드가 실행될 때의 메모리 상태를 반영하지 못함  
  또한, 프로그램에 따라 입력할 수 있는 셸 코드의 길이나, 구성 가능한 문자의 종류에 제한이 있을 수 있는데, 이런 조건들도 반영하기 어려움
  따라서 제약 조건이 존재하는 상황에서는 직접 셸 코드를 작성하는 것이 좋음
- [x86-64 대상 셸 코드](https://docs.pwntools.com/en/stable/shellcraft/amd64.html)

```
#!/usr/bin/env python3
# Name: shellcraft.py

from pwn import *
context.arch = 'amd64' # 대상 아키텍처 x86-64

code = shellcraft.sh() # 셸을 실행하는 셸 코드 
print(code)
```
```
$ python3 shellcraft.py
    /* execve(path='/bin///sh', argv=['sh'], envp=0) */
    /* push b'/bin///sh\x00' */
    push 0x68
    mov rax, 0x732f2f2f6e69622f
    ...
    syscall
```

## asm

- pwntools의 어셈블 기능
- 대상 아키텍처가 중요하기 때문에 `context.arch`를 지정해줘야함

```
#!/usr/bin/env python3
# Name: asm.py

from pwn import *
context.arch = 'amd64' # 익스플로잇 대상 아키텍처 'x86-64'

code = shellcraft.sh() # 셸을 실행하는 셸 코드
code = asm(code)       # 셸 코드를 기계어로 어셈블
print(code)
```

```
$ python3 asm.py
b'jhH\xb8/bin///sPH\x89\xe7hri\x01\x01\x814$\x01\x01\x01\x011\xf6Vj\x08^H\x01\xe6VH\x89\xe61\xd2j;X\x0f\x05'
```
