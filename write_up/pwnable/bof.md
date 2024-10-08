먼저 해당 워게임은 이름에서도 힌트가 있듯이 `Buffer Overflow` 취약점이 존재하는 바이너리이다.

소스 코드는 존재하지 않지만, 바이너리가 존재해서 gdb로 동적 분석이 가능하고 꽤 단순한 문제이므로 쉽게 풀 수 있다.

일단 원격 서버에 `flag` 파일의 위치는 `/home/bof/flag`이며, `cat flag를 통해 획득할 수 있을 것이다. 일단 크게 쓰이지는 않지만 보호 기법은 아래와 같다.

<img width="555" alt="image" src="https://github.com/user-attachments/assets/2eeb70ed-6645-48cc-82d4-02503e83429e">

그럼 먼저 바이너리를 한번 실행해보자.

<img width="472" alt="image" src="https://github.com/user-attachments/assets/d3d8811e-2613-413e-9861-6530b6252f4a">

바이너리를 실행하면 처음으로 `meow? `라는 문자열과 함께 입력을 받는다. 임의의 값인 `"a"`를 한번 입력해보자.

<img width="474" alt="image" src="https://github.com/user-attachments/assets/df3ae011-e4ff-482a-aa01-0c4ca0e10dfc">

그럼 아래에서 고양이를 그림을 출력하고 입력 값을 출력해준다. 잘 보면 예시 환경으로 주어진 `deploy` 디렉토리 내에 실행 바이너리인 `bof`와 고양이 그림이 저장된 `cat` 파일이 같이 위치해있다.

<img width="260" alt="image" src="https://github.com/user-attachments/assets/5ddee23c-33ff-4de4-821a-b9844dfb554d">

<img width="256" alt="image" src="https://github.com/user-attachments/assets/4439436f-ac79-4a79-9804-73a70be13638">

뭔가, `cat` 파일의 내용을 읽어서 출력해주는 함수가 바이너리 내에 존재하는 것 같은데, 이 함수의 파일 인자를 `cat`이 아닌, 같은 디렉토리에 존재하는 `flag`로 변경해주면 `cat flag`를 실행해서 `flag` 내용을 읽어올 수 있을 것 같다.

그럼 한번 `gdb`로 바이너리를 동적으로 분석해보자.

# 동적 분석

<img width="667" alt="image" src="https://github.com/user-attachments/assets/c9d9f7a7-b21c-41d2-a830-95a65f980305">

먼저 `disass main`으로 출력해보면 `printf`, `scanf`, `read_cat`, `printf`가 눈에 띈다.

첫 번째 `printf`는 입력을 받기 전 `meow? `를 출력해주는 함수로 보이며, `scanf`는 입력 값을 받아주는 함수, `read_cat`은 `cat` 파일의 내용을 읽는 함수, 두 번째`printf`는 `cat` 파일의 내용을 출력해주는 함수로 예상되니 한번 단계적으로 실행해보자.

## `printf`

<img width="653" alt="image" src="https://github.com/user-attachments/assets/528c11fd-3c14-4ddd-abc0-cea3e0b11a25">

첫 번째 `printf`는 예상과 같이 입력을 받기 전, `meow? `를 출력해주는 함수였다. 그럼 이제 다음 `scanf`까지 중단점을 통해 이동해보자.

## `scanf`

<img width="552" alt="image" src="https://github.com/user-attachments/assets/9f0b0357-6b5b-45e1-9709-73bfa6255424">

`144%s` 의 포맷 스트링을 통해 최대 `144` 길이의 문자열을 입력 받게 된다. 그리고 `0x7fffffffde50`에 해당 입력 값을 저장한다.

그럼 여기서 예상과 같다면, `0x7fffffffde50`를 따라서 `buffer overflow`를 통해 `read_cat`의 인자를 `cat`이 아닌 `flag`로 전달해주면 될 것 같다는 생각이 든다.

참고로 `0x7fffffffde50`는 `rsp`의 주소이고, `rbp`와 `144`만큼 차이가 난다.

<img width="210" alt="image" src="https://github.com/user-attachments/assets/27b281b7-8bc4-4bde-a352-8b07abf7ec00">

이제 중단점을 다시 `read_cat`으로 설정 후 이동해보자.

## `read_cat`

<img width="658" alt="image" src="https://github.com/user-attachments/assets/d35d7637-b7fc-4789-b733-953a39ab5517">

잘보면, `rdi`인 `0x7fffffffded0`에 `0x7461632f2e` 라는 값이 저장되어 있고, 이를 문자열로 해석하면 `./cat`임을 알 수 있다. 따라서 이 주소에 `BOF` 취약점을 통해 `./flag`나 `/home/bof/flag`를 전달해주면 익스플로잇에 성공할 것이다.

<img width="235" alt="image" src="https://github.com/user-attachments/assets/54296b04-a625-4cfb-9357-928884766d02">

그럼 이 주소를 `scanf`에서 입력 받는 주소인 `0x7fffffffde50`와 오프셋이 얼마나 차이나는지 비교해보면, 아래와 같이 `128`만큼 차이가 난다.

<img width="382" alt="image" src="https://github.com/user-attachments/assets/80a1794b-0247-4824-875d-25bd26af3724">

따라서, `b'a'`와 같은 임의의 값을 `128`번 써준 뒤에 `./flag`를 붙여주면 익스플로잇에 성공할 것이다.

참고로 오프셋 차이를 `scanf`에서는 첫번째 인자인 `rdi`에 대입할 `rax`에 `[rbp - 0x90]`을 대입해줬고, `read_cat`에서는 `rax`에 `[rbp - 0x10]`을 대입해줬기 때문에 `0x80 = 128`만큼 차이가 난다고 바로 생각해줘도 된다.

그리고 아래와 같이 `read_cat`에서 `ni`로 넘어가면 바로 파일을 읽어서 내용을 출력해준다.

<img width="272" alt="image" src="https://github.com/user-attachments/assets/5ebc197c-5be3-4a0c-a8d3-6e2c730bdf90">

## `printf`

<img width="432" alt="image" src="https://github.com/user-attachments/assets/988caa24-2f11-4c48-89b4-6cd1dd74e8cd">

마지막 `printf`에서는 그냥 입력 값을 출력해준다.

# Exploit

```
from pwn import *

p = remote('host3.dreamhack.games', 14559)

payload = b'a' * 128
payload += b'./flag'
# payload += b'/home/bof/flag' # 이것도 가능

p.sendlineafter(b'meow? ', payload)
p.interactive()
```
