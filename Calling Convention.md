# Calling Convention
함수 호출 규악이란 **함수의 호출 및 반환**에 대한 약속이다.  
1. 한 함수가 다른 함수를 호출하고 호출된 함수가 반환할 때, 다시 기존의 실행 흐름을 이어나가기 위해 calling convention이 필요하고,  
2. 다른 함수나 기본 실행 흐름에서 사용하고 있던 메모리 값, 레지스터 값을 침범하지 않기 위해서도 필요하다.  

이를 위해 함수 call시에 호출자(Caller)의 Stack frame과 호출 이후에 기존 실행 흐름으로 돌아오기 위한 Return address를 callee가 저장하고 있어야하며, Caller는 Callee가 사용할 parameter(인자)를 전달해줘야한다.

함수 호출 규악을 적용하는 것은 일반적으로 **컴파일러가 수행한다.** 여러 호출 규약이 존재하는데, 프로그래머가 이를 코드에 명시하지 않는다면, 컴파일러가 지원하는 호출 규악 중에서 실행할 CPU 아키텍처에 적합한 것을 선택한다.

하지만, 프로그래머가 컴파일러 없이 어셈블리 코드를 작성하려고 하거나, 어셈블리로 작성된 코드를 읽고자 할 때는 calling convention을 이해하는 것이 필수적이므로, 이에 대해 알고 있는 것이 중요하다.

## 종류

여러 calling convention이 존재하지만, 아키텍처에 따라 나눈다면 x86과 x86-64로 나눌 수 있다.  
- x86에서는 레지스터의 수가 적기 때문에 인자 전달에 **스택을 사용**한다.
- x86-64에서는 레지스터의 수가 x86보다 많아졌기 때문에 6개의 인자는 **rdi, rsi, rdx, rcx, r8, r9**을 순서대로 사용하고 그 이상의 인자에는 x86과 동일하게 스택을 사용한다.

아래와 같이 같은 아키텍처에서도 사용하는 calling convention이 여러개 존재한다. 일단 리눅스 환경에서 중요한 **x86의 cdecl(C decoration call)**과 **x86-64의 SYSV(SYSTEM V AMD64 ABI)**에 대해서 알아보겠다.

### 다양한 함수 호출 규악

**x86** 
- **cdecl**
- stdcall
- fastcall
- thiscall

**x86-64**

- **System V AMD64 ABI의 Calling Convention**
- MS ABI의 Calling Convention

## x86-64 : SYSV
리눅스는 SYSTEM V(SYSV) Application Binary Interface(ABI)를 기반으로 만들어졌다.   
SYSV ABI는 **ELF포맷, 링킹 방법, Calling Convention 등** 여러가지 내용을 담고 있다. file 명렁어로 바이너리의 정보를 살펴보면, 아래와 같이 SYSV 문자열이 포함된 것을 알 수 있다.
```
$ file /bin/ls
/bin/ls: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV) ...

```
SYSV의 calling convention은 아래의 특징을 갖는다.

1. 6개의 인자를 rdi, rsi, rdx, rcs, r8, r9에 순서대로 저장하여 전달하고, 초과한 인자는 스택을 이용하여 저장한다.
2. Caller에서 인자 전달에 사용한 스택을 정리한다.
3. callee의 return 값은 rax를 통해 전달한다.

아래의 코드를 어셈블리 코드로 컴파일하여 분석해보겠다.
```
// Name: sysv.c
// Compile: gcc -fno-asynchronous-unwind-tables  -masm=intel \
//         -fno-omit-frame-pointer -S sysv.c -fno-pic -O0

#define ull unsigned long long

ull callee(ull a1, int a2, int a3, int a4, int a5, int a6, int a7) {
  ull ret = a1 + a2 + a3 + a4 + a5 + a6 + a7;
  return ret;
}

void caller() { callee(123456789123456789, 2, 3, 4, 5, 6, 7); }

int main() { caller(); }
```
## 1. 인자 전달 및 callee 호출
```
$ gdb -q sysv
pwndbg: loaded 139 pwndbg commands and 49 shell commands. Type pwndbg [--shell | --all] [filter] for a list.
pwndbg: created $rebase, $ida GDB functions (can be used with print/break)
Reading symbols from sysv...
...
pwndbg> b *caller
Breakpoint 1 at 0x1185
pwndbg> r
Starting program: /home/dreamhack/sysv

Breakpoint 1, 0x0000555555555185 in caller ()
...
──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────
 ► 0x555555555185 <caller>       endbr64
   0x555555555189 <caller+4>     push   rbp
   0x55555555518a <caller+5>     mov    rbp, rsp
   0x55555555518d <caller+8>     push   7
   0x55555555518f <caller+10>    mov    r9d, 6
   0x555555555195 <caller+16>    mov    r8d, 5
   0x55555555519b <caller+22>    mov    ecx, 4
   0x5555555551a0 <caller+27>    mov    edx, 3
   0x5555555551a5 <caller+32>    mov    esi, 2
   0x5555555551aa <caller+37>    movabs rax, 0x1b69b4bacd05f15
   0x5555555551b4 <caller+47>    mov    rdi, rax
   0x5555555551b7 <caller+50>    call   0x555555555129 <callee>
   0x5555555551bc <caller+55>    add    rsp,0x8
...
```

1. callee에게 전달할 함수 인자는 총 7개인데, `int a7 = 7`은 6개를 초과한 마지막 인자이므로 가장 먼저 스택에 푸쉬하고 차례대로 `ull al = 123456789123456789(0x1b69b4bacd05f15)`가 인자로 전달되도록 레지스터에 값을 저장한다.
2. 이후 `call   0x555555555129 <callee>`를 통해 <callee> 함수 instruction이 저장된 메모리 주소로 rip를 이동시킨다.
3. 그리고 call과 동시에 stack에 <callee>가 **return 후 돌아올 주소(Return address)**를 push하여 저장한다.

## 2. 기존 스택프레임(caller) 저장 및 새로운 스택 프레임(callee) 할당
아래는 <caller+50>번 줄 이후 코드이다.
```
pwndbg> x/9i $rip
=> 0x555555555129 <callee>:	endbr64
   0x55555555512d <callee+4>:	push   rbp
   0x55555555512e <callee+5>:	mov    rbp,rsp
   0x555555555131 <callee+8>:	mov    QWORD PTR [rbp-0x18],rdi
   0x555555555135 <callee+12>:	mov    DWORD PTR [rbp-0x1c],esi
   0x555555555138 <callee+15>:	mov    DWORD PTR [rbp-0x20],edx
   0x55555555513b <callee+18>:	mov    DWORD PTR [rbp-0x24],ecx
   0x55555555513e <callee+21>:	mov    DWORD PTR [rbp-0x28],r8d
   0x555555555142 <callee+25>:	mov    DWORD PTR [rbp-0x2c],r9d
pwndbg> si
pwndbg> si
0x000055555555512e in callee ()
──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────
   0x555555555129 <callee>       endbr64
   0x55555555512d <callee+4>     push   rbp
 ► 0x55555555512e <callee+5>     mov    rbp, rsp
   0x555555555131 <callee+8>     mov    qword ptr [rbp - 0x18], rdi
...
pwndbg> x/4gx $rsp
0x7fffffffe2e8: 0x00007fffffffe300  0x00005555555551bc
0x7fffffffe2f8: 0x0000000000000007  0x00007fffffffe310
pwndbg> print $rbp
$1 = (void *) 0x7fffffffe300
 
```

4. 들어오게 되면 `push rbp`로, return 이후 기존 stack frame으로 돌아오기 위해 **caller의 rbp를 push**하여 저장한다.
5. 그리고 `mov rbp, rsp`를 통해 rbp = rsp를 하여 rbp 위치를 rsp와 동일하게 만든다.
6. 이후 rdi, rsi, ...와 stack에 차례대로 저장된 인자를 전달한다.
   
     - 여기서 지역변수 ret이 코드상으로는 존재하지만 새로운 스택 프레임을 push하여 더 추가하지 않는 이유는,   
callee에서 아래의 코드처럼 ret을 다른데서 사용하지 않고 return 값으로 바로 넘기기 때문에 스택 프레임을 추가하지 않고 rax에 바로 저장하면 되기 때문이다.

     - ```
       ull ret = a1 + a2 + a3 + a4 + a5 + a6 + a7;
       return ret;
       ```
## 반환값 전달 및 기존 실행 흐름 복귀
```
pwndbg> b *callee+79
Breakpoint 3 at 0x555555555178
pwndbg> c
...
──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────
 ► 0x555555555178 <callee+79>    add    rax, rdx
   0x55555555517b <callee+82>    mov    qword ptr [rbp - 8], rax
   0x55555555517f <callee+86>    mov    rax, qword ptr [rbp - 8]
   0x555555555183 <callee+90>    pop    rbp
   0x555555555184 <callee+91>    ret

pwndbg> b *callee+91
Breakpoint 4 at 0x555555555184
pwndbg> c
...
──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────
   0x555555555178 <callee+79>    add    rax, rdx
   0x55555555517b <callee+82>    mov    qword ptr [rbp - 8], rax
   0x55555555517f <callee+86>    mov    rax, qword ptr [rbp - 8]
   0x555555555183 <callee+90>    pop    rbp
 ► 0x555555555184 <callee+91>    ret                                  <0x5555555551bc; caller+55>
    ↓
...
pwndbg> print $rax
$1 = 123456789123456816
```

7. `pop rbp`를 통해 현재 스택프레임의(callee) rsp 값에 저장되어 있는 기존 스택 프레임 (caller의 rbp) 값을 rbp에 저장하여 기존 스택 프레임(caller)으로 돌아간다.
8. `ret`을 통해 pop이후 rsp가 가리키고 있는 return address를 rip에 위치시키고, rsp를 한칸 줄인다. 

    - 이는 `pop rip` 와 같은 동작을 하지만 실제로 해당 instruction을 수행하는 것은 아님

#### [링크](https://github.com/juhyeongkim527/Dreamhack-Study/blob/main/Stack%20and%20Procedure.md)에서 calling convention을 시각적으로 확인하자.
