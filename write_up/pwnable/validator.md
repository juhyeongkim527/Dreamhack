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

두 바이너리를 한번 실행해보면, 아래와 같이 입력을 받게 되고, 입력이 끝나면 바로 바이너리가 종료된다.

<img width="653" alt="image" src="https://github.com/user-attachments/assets/de44fe89-2821-4131-a1dc-1ce37b22264f">

**gdb**를 통해 한번 두 바이너리를 분석해보자.

<img width="556" alt="image" src="https://github.com/user-attachments/assets/976211c5-3cf3-42a3-8506-37c691fcc19e">

먼저, 위는 `validator_dist` 바이너리의 `main` 함수를 디스어셈블한 결과이다.

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

그럼 이제, **IDA**를 통해 `validator_dist`와 `validator_server`를 정적 분석해보며 취약점을 분석해보고 Exploit을 설계해보자.

# `validtor_dist` 바이너리 분석












