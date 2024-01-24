# 스택

## push val : val을 스택 최상단에 쌓음

### 연산
```
rsp -= 8  
[rsp] = val
```
### 예제
```
[Register]
rsp = 0x7fffffffc400
[Stack]
0x7fffffffc400 | 0x0  <= rsp
0x7fffffffc408 | 0x0
[Code]
push 0x31337
```
### 결과
```
[Register]
rsp = 0x7fffffffc3f8
[Stack]
0x7fffffffc3f8 | 0x31337 <= rsp 
0x7fffffffc400 | 0x0
0x7fffffffc408 | 0x0
```
## pop reg : 스택 최상단의 값을 꺼내서 reg에 대입

### 연산
```
reg = [rsp]  
rsp += 8
```
### 예제
```
[Register]
rax = 0
rsp = 0x7fffffffc3f8
[Stack]
0x7fffffffc3f8 | 0x31337 <= rsp 
0x7fffffffc400 | 0x0
0x7fffffffc408 | 0x0
[Code]
pop rax
```
### 결과
```
[Register]
rax = 0x31337
rsp = 0x7fffffffc400
[Stack]
0x7fffffffc400 | 0x0 <= rsp 
0x7fffffffc408 | 0x0
```

# Procedure
* 특정 기능을 수행하는 코드 조각
* c언어에서 함수에 대응
* 반복되는 연산을 프로시저 호출로 대체할 수 있고, 이름을 붙일 수 있어서 코드 길이를 줄이고 가독성을 높일 수 있음
* 프로시저는 Call, Return의 과정을 거침
* Return 후 다시 실행 흐름으로 돌아와야 하므로 call 후 다음 명령어 주소(return address, 반환 주소)를 stack에 저장하고  
  프로시저로 stack에 저장된 return address에 rip를 이동시킴

## call addr : addr에 위치한 프로시저 호출

### 연산
```
push return_address  
jmp addr
```
### 예제
```
[Register]
rip = 0x400000
rsp = 0x7fffffffc400 
[Stack]
0x7fffffffc3f8 | 0x0
0x7fffffffc400 | 0x0 <= rsp
[Code]
0x400000 | call 0x401000  <= rip
0x400005 | mov esi, eax
...
0x401000 | push rbp
```
### 결과
```
[Register]
rip = 0x401000
rsp = 0x7fffffffc3f8
[Stack]
0x7fffffffc3f8 | 0x400005  <= rsp
0x7fffffffc400 | 0x0
[Code]
0x400000 | call 0x401000
0x400005 | mov esi, eax
...
0x401000 | push rbp  <= rip
```
rip는 `call 0x401000`의 코드가 수행하는 `jmp addr`에 따라 해당 주소를 가리키고,  
rsp는 -=8을 해준 후(push) return address를 저장함 = `push return_address`(return 후 rip를 해당 주소(return address): 0x40005 로 이동시키기 위해)

## leave: __스택프레임__ 정리

### 연산
```
mov rsp, rbp  
pop rbp
```
### 예제
```
[Register]
rsp = 0x7fffffffc400
rbp = 0x7fffffffc480
[Stack]
0x7fffffffc400 | 0x0 <= rsp
...
0x7fffffffc480 | 0x7fffffffc500 <= rbp
0x7fffffffc488 | 0x31337 
[Code]
leave
```
### 결과
```
[Register]
rsp = 0x7fffffffc488
rbp = 0x7fffffffc500
[Stack]
0x7fffffffc400 | 0x0
...
0x7fffffffc480 | 0x7fffffffc500
0x7fffffffc488 | 0x31337 <= rsp
...
0x7fffffffc500 | 0x7fffffffc550 <= rbp
```
`move rsp, rbp`에 따라 rbp가 가리키는 주소를 rsp가 가리키게 하고,  
`pop rbp`에 따라 [rsp](rsp가 현재 가리키는 데이터, 함수 call 이전의 스택 프레임으로 돌아가기 위해 저장해뒀던 rbp주소)를 rbp에 저장한 다음 rsp -= 8을 함

### 스택프레임이란?

스택은 함수별로 자신의 지역변수 또는 연산과정에서 부차적으로 생겨나는 임시 값들을 저장하는 영역입니다. 만약 이 스택 영역을 아무런 구분 없이 사용하게 된다면, 서로 다른 두 함수가 같은 메모리 영역을 사용할 수 있게 됩니다.

예를 들어 A라는 함수가 B라는 함수를 호출하는데, 이 둘이 같은 스택 영역을 사용한다면, B에서 A의 지역변수를 모두 오염시킬 수 있습니다. 이 경우, B에서 반환한 뒤 A는 정상적인 연산을 수행할 수 없습니다.

이런 문제를 막고, 함수별로 서로가 사용하는 스택의 영역을 구분하기 위해 스택프레임이 사용됩니다.

## ret : return address로 반환

### 연산
`pop rip`

### 예제
```
[Register]
rip = 0x401021
rsp = 0x7fffffffc3f8
[Stack]
0x7fffffffc3f8 | 0x400005    <= rsp
0x7fffffffc400 | 0x123456789abcdef
[Code]
0x400000 | call 0x401000
0x400005 | mov esi, eax
...
0x401000 | push rbp
0x401001 | mov rbp, rsp
0x401004 | sub rsp, 0x30
0x401008 | mov BYTE PTR [RSP], 0x3
...
0x401020 | leave
0x401021 | ret <= rip
```
### 결과
```
[Register]
rip = 0x400005
rsp = 0x7fffffffc400
[Stack]
0x7fffffffc3f8 | 0x400005
0x7fffffffc400 | 0x123456789abcdef    <= rsp
[Code]
0x400000 | call 0x401000
0x400005 | mov esi, eax   <= rip
...
0x401000 | push rbp
0x401001 | mov rbp, rsp
0x401004 | sub rsp, 0x30
0x401008 | mov BYTE PTR [RSP], 0x3
...
0x401020 | leave
0x401021 | ret
```

## 스택 프레임의 할당과 해제

![1](https://dreamhack-lecture.s3.ap-northeast-2.amazonaws.com/media/22dad39e510cf772b5909d46b1166519f441ea616127c4c6f818701171493b62.png)
1. func함수를 호출합니다. 이때 다음 명령어의 주소인 0x400005는 스택에 Push됩니다.
![2](https://dreamhack-lecture.s3.ap-northeast-2.amazonaws.com/media/ad39ef0deab50e070164778af0afb4665b0cbea6760cab5ec50f73e0336431e5.png)
2. 기존의 스택 프레임을 저장하기 위해 rbp를 스택에 push합니다.
![3](https://dreamhack-lecture.s3.ap-northeast-2.amazonaws.com/media/03abedd26c449e63d1eef8889db95e614440de172bcc161e22e8800acd862a54.png)
3. 새로운 스택 프레임을 만들기 위해 rbp를 rsp로 옮깁니다.
![4](https://dreamhack-lecture.s3.ap-northeast-2.amazonaws.com/media/824c486f450202ce4ac1af76b0b963aa0d1abdf5d0ca1eabe8d7a16250b994fb.png)
4. 새로 만든 스택 프레임의 공간을 확장하기 위해 rsp를 0x30만큼 뺍니다.
![5](https://dreamhack-lecture.s3.ap-northeast-2.amazonaws.com/media/ef0809c094ab5dc26446d44375364ae9aeca93560be247a9b725c68893753a25.png)
5. 할당한 스택 프레임에 지역변수를 할당합니다.
![6](https://dreamhack-lecture.s3.ap-northeast-2.amazonaws.com/media/cc6837bffd6060c503bd745c81a47eb1c0d69406100e2d58e3b2b55de6cf9356.png)
6. 스택 프레임 위에서 여러 연산을 수행합니다.
![7](https://dreamhack-lecture.s3.ap-northeast-2.amazonaws.com/media/6ee17fe26e627395d991c468e061ca45e58d2d9f26b822451a507220de11f8e7.png)
7. 저장해뒀던 rbp를 꺼내서 원래의 스택 프레임으로 돌아갑니다.
![8](https://dreamhack-lecture.s3.ap-northeast-2.amazonaws.com/media/b8ad527f7a5249d5edc3fb0441bc068c2c0dfe35ac2f39719c4d2b3c427a5464.png)
8. 저장해뒀던 반환 주소를 꺼내어 원래의 실행흐름으로 돌아갑니다.
![9](https://dreamhack-lecture.s3.ap-northeast-2.amazonaws.com/media/3707f9b2a1b59545e1af4bfadabf198978206dffb09aa3638b69c7f39fb74635.png)
9. 기존의 스택프레임과 함께 원래의 실행 흐름을 이어갑니다.
