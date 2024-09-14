# 문제 설명 및 바이너리 분석

---
취약한 인증 프로그램을 익스플로잇해 flag를 획득하세요!

Hint: 서버 환경에 설치된 5.4.0 이전 버전의 커널에서는, NX Bit가 비활성화되어 있는 경우 읽기 권한이 있는 메모리에 실행 권한이 존재합니다. 5.4.0 이후 버전에서는 스택 영역에만 실행 권한이 존재합니다.

---

<img width="1115" alt="image" src="https://github.com/user-attachments/assets/f8c6c451-6021-4999-92fb-8526fa28f0c3">

<img width="709" alt="image" src="https://github.com/user-attachments/assets/1b717225-5e69-42ba-ac96-8e122e998b7c">

먼저, 해당 문제에 적용된 보호 기법이 거의 존재하지 않기 때문에 다양한 공격 패턴이 가능할 것을 예측할 수 있다.

그리고 이번 문제는 다른 문제들과 달리, 바이너리만 존재하고 소스 코드는 존재하지 않는다.

따라서, `validator_dist`와 `validator_server` 바이너리를 분석하여 문제를 풀어야 한다.

---

참고로, 아래에서도 설명하겠지만 `validator_server`는 **IDA**로 분석이 힘들고 `validator_dist`만 바로 분석이 가능하다.

`dist`는 **Distribution**의 약자로 배포판을 의미하기 때문에, 이번 문제에서는 `dist`로 분석한 후 `server`에 해당 취약점으로 공격을 하면 같은 기법으로 공격이 가능하다.

---

그럼 이제 두 바이너리를 한번 실행해보면 아래와 같이 둘다 이용자에게 입력을 받은 후, 입력이 끝나면 바로 바이너리가 종료된다.

<img width="653" alt="image" src="https://github.com/user-attachments/assets/de44fe89-2821-4131-a1dc-1ce37b22264f">

**gdb**를 통해 한번 두 바이너리를 분석해보자.

<img width="556" alt="image" src="https://github.com/user-attachments/assets/976211c5-3cf3-42a3-8506-37c691fcc19e">

먼저, 위 이미지는 `validator_dist` 바이너리의 `main` 함수를 디스어셈블한 결과이다.

<img width="491" alt="image" src="https://github.com/user-attachments/assets/6d74f02b-2cf3-4313-9c3a-90ef36c8e052">

이 부분을 살펴보면, `read()` 함수를 통해 `[rbp-0x80]`이 가리키는 주소에 `0x400` 크기의 데이터를 입력받기 때문에 **BOF** 취약점이 존재하는 것을 알 수 있고,

입력이 끝난 이후에는 `validate` 함수를 호출한다.

`diass validate` 명령어를 통해 해당 함수의 내용도 디스어셈블 해보며 관찰해봤는데, 위에서 `[rbp-0x80]`에 입력된 값과 특정값을 1바이트씩 계속 비교하며 반복해나가는 코드가 보였다.

만약 입력값과 특정값이 다르다면, `jmp`를 통해 `exit` 함수를 호출하며 종료하게 되었다.

디스어셈블된 결과를 보고, 한 바이트씩 차분히 특정값의 패턴을 찾으며 어떤 입력값을 전달해야 하는지 찾을 수 있지만, 이보다 **IDA**를 통해 `validate` 함수를 **디컴파일**하여 파악하는 것이 훨씬 쉽다.

이번에는 디컴파일 방법으로 문제를 풀이하고, 다음에 [링크](https://velog.io/@yyj0110/Dreamhack-Validator)에 잘 정리된 내용을 참고해서 디스어셈블된 결과를 리버싱하여 문제를 풀어보는 방법도 한번 해봐야겠다.

그럼 **IDA**로 `validate` 함수를 디컴파일 해보기 전에 `validator_server` 바이너리도 한번 **gdb**를 통해 분석해보자.

`validator_server` 바이너리를 **gdb**를 통해 분석해봤는데, `disass main` 명령어로 찾아봐도 `main` 함수가 존재하지 않고, `info func` 명령어로는 아래의 세 함수만 존재했다.

<img width="453" alt="image" src="https://github.com/user-attachments/assets/813132e8-0c25-4aaf-8bbc-a7b0b82638a4">

그 이유는 `validator_server` 바이너리가 **stripped** 되어있기 때문이다.

바이너리가 **stripped** 되어있다는 것은, 바이너리를 디버깅하기 위해 필요한 심볼 정보들이 제거되있다는 의미이다.

`file` 명령어를 통해 `validator_dist`와 `validator_server`를 비교해보면 아래와 같이 마지막에 **stripped** 되어있는지 여부가 나온다.

<img width="1355" alt="image" src="https://github.com/user-attachments/assets/63e7e3d2-6787-4007-93f9-fa01c37df91d">

따라서, `validator_server`는 gdb를 통해 일반 바이너리들과 똑같은 방법으로 분석을 하기 힘들다.

어쩌피 이번 문제에서는 `validator_dist` 배포판으로 분석한 후, 서버에 공격할 때는 똑같은 바이너리인 `validator_server`로 공격하면 되서 `validator_server` 자체를 로컬에서 분석할 필요는 없지만,

만약 **stripped** 된 파일을 분석하기 위해서는 아래와 같은 명령어를 통해 **Entry point address**를 찾아서, 해당 주소에 breakpoint를 설정한 후,

```
readelf -a ./binary | more
```

`-a`는 바이너리의 모든 정보를 출력하는 옵션이며, `| more`은 출력 값이 너무 길어지는 것을 방지하기 위해 `more`으로 한 페이지 단위만 짤라서 먼저 보여주는 것이다. 

<img width="812" alt="image" src="https://github.com/user-attachments/assets/4729be66-6813-4715-8b37-4cacca78d59b">

<img width="233" alt="image" src="https://github.com/user-attachments/assets/9b8764ad-af28-4ca4-9218-23ece33cfcf7">

이제 breakpoint 까지 실행을 해서 중단해보면, 아래와 같이 `main` 함수를 호출하기 위한 `__libc_start_main` 함수가 나온다.

<img width="622" alt="image" src="https://github.com/user-attachments/assets/123a3dd6-2315-4368-a7ef-077a3089e897">

`__libc_start_main`을 호출하기 전에 설정해주는 `rdi` 레지스터의 값이 `main` 함수의 주소를 가리키기 때문에,

설정해준 `rdi` 값에 breakpoint를 걸고 `continue`를 해보면, `validator_dist`에서 본 `main`과 같은 함수가 실행되는 것을 알 수 있다.

<img width="991" alt="image" src="https://github.com/user-attachments/assets/5ed357d9-66a1-4577-960e-f93ccb4073b2">

따라서, 로컬에서 `validator_dist`만 분석한 후 서버에 공격할 때는 `validator_server` 바이너리를 공격하면 되겠다는 확신을 할 수 있다.

참고로, **IDA**를 통해 **stripped**된 바이너리를 분석하는 것은 gdb와 달리 쉽지 않기 때문에, 다음에 한번 [링크](https://kimtruth.github.io/2021/06/27/stripped-PIE-tip/)를 참고해서 분석해보자.

그럼 이제, **IDA**를 통해 `validator_dist`를 정적 분석해보며 취약점을 분석해보고 Exploit을 설계해보자.

# `validtor_dist` 바이너리 분석

이제 IDA를 켜서 `validator_dist` 바이너리를 분석해보자.

<img width="550" alt="image" src="https://github.com/user-attachments/assets/b01092fd-7dff-40f7-8bb2-51e84dd14ec5">

먼저 위와 같이, 가장 먼저 나오는 `main` 함수의 디스어셈블 결과에 **F5** 단축키를 입력해서 **디컴파일**한 결과를 살펴보자.

```
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char s[128]; // [rsp+0h] [rbp-80h] BYREF

  memset(s, 0, 0x10uLL);
  read(0, s, 0x400uLL);
  validate(s, 128LL);
  return 0;
}
```

그럼 위와 같이 `main` 함수가 디컴파일된 결과를 살펴볼 수 있고, gdb에서 살펴본 것과 같이 `s` 라는 배열에 `0x400` 크기의 값을 입력 받는다.

`s`는 `[rbp-0x80]`에 저장되어 있었던 것을 기억하고, `validate` 함수를 호출할 때는, `s`와 해당 배열의 크기인 `128(0x80)`을 넘겨준다.

그럼 이제 `validate` 함수를 더블클릭해서, 해당 함수의 내용을 분석해보자.

```
__int64 __fastcall validate(__int64 a1, unsigned __int64 a2)
{
  unsigned int i; // [rsp+1Ch] [rbp-4h]
  int j; // [rsp+1Ch] [rbp-4h]

  for ( i = 0; i <= 9; ++i )
  {
    if ( *(_BYTE *)((int)i + a1) != correct[i] )
      exit(0);
  }
  for ( j = 11; a2 > j; ++j )
  {
    if ( *(unsigned __int8 *)(j + a1) != *(char *)(j + 1LL + a1) + 1 )
      exit(0);
  }
  return 0LL;
}
```

먼저, 첫 번째 반복문을 살펴보자. 

함수의 첫 번째 인자로 받은 `a1`은 `main`에서 `char s[128]`인데, 여기서 `__int64`로 받기 때문에 배열이 아닌 정수로 해석된다.

따라서, *(_BYTE *)`로 타입 변환을 통해 `char` 타입을 저장하는 배열로 해석한 후, 배열의 원소를 가리키도록 한다.

이제 `i`가 0부터 9까지 반복문을 순회하며, 함수의 첫 번째 인자인 `a1` 배열에 인덱스 역할을 하는 `i`를 더한 후, `correct[i]` 값과 `a1`의 원소인 `a1[i]`가 다른 경우 `exit(0);`으로 종료한다.

`correct` 배열의 값은, 배열 이름을 더블클릭해보면 아래와 같이 `"DREAMHACK!"` 문자열이 10바이트 저장된 것을 확인할 수 있다.

여기서 `exit` 함수를 통해 종료되지 않고 검증을 넘어가기 위해서는, `main` 함수에서 호출되는 `read` 함수를 통한 입력에서, `s`의 인덱스 0부터 9까지 저장되어야 하는 문자열은 `"DREAMHACK"`이다.

---

그럼 다음으로 넘어가서 두 번째 반복문을 살펴보자.

같은 방식으로 함수의 첫 번째 인자를 `*(unsigned __int8 *)`를 통해 `char` 타입을 저장하는 배열로 해석한 후, 배열의 원소를 가리키도록 한다.

그리고 배열의 인덱스를 나타내는 `j`는, 11부터 함수의 두 번째 인자인 `a2` 보다 작을 때 까지 증가시키며 비교를 하는데,

`a1[j] != a1[j + 1] + 1`을 만족하는 경우 `exit(0);`를 호출하며 함수가 종료하게 된다.

따라서 이 검증을 넘어가기 위해서는 인덱스 `11`부터 인자로 전달해준 `128`까지 서로 이웃한 인덱스의 원소는, 아스키 코드 값을 기준으로 `1`만큼 차이가 나도록 내림차순으로 저장되어야 한다.

따라서, `main` 함수에서 호출되는 `read` 함수를 통한 입력해서 인덱스 11부터 128까지 저장되어야 하는 문자열은, Exploit 코드에서 반복문을 통해 118부터 0까지 아스키 값을 저장해주면 될 것이다.

참고로, `read` 함수는 널 문자 또는 개행 문자를 만나도 입력을 계속 받기 때문에 아스키 코드 입력 값의 범위는 신경쓰지 않아도 된다. (내가 갑자기 헷갈렸어서)

그럼 이제, `validator_dist` 바이너리에서 `validate` 함수를 통한 검증은 통과할 방법을 설계하였으니, 바이너리의 취약점을 분석해보며 Exploit 계획을 세워보자.

# 취약점 분석


















