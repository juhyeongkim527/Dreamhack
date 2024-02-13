# examine🖨
- 프로그램을 분석하다 보면 가상 메모리에 존재하는 임의 주소의 값을 관찰해야할 때가 있습니다.  
이를 위해 gdb에서는 기본적으로 x라는 명령어를 제공합니다. x를 이용하면 특정 주소에서 원하는 길이만큼의 데이터를 원하는 형식으로 인코딩하여 볼수 있습니다.

- o(octal)
- x(hex)
- d(decimal)
- u(unsigned decimal)
- t(binary)
- f(float)
- a(address)
- i(instruction)
- c(char)
- s(string)
- z(hex, zero padded on the left).
- Size letters are b(byte), h(halfword), w(word), g(giant, 8 bytes).

## 예시

1. rsp부터 80바이트를 8바이트씩 hex형식으로 출력

```
pwndbg> x/10gx $rsp
0x7fffffffc228: 0x00007ffff7a05b97      0x0000000000000001
0x7fffffffc238: 0x00007fffffffc308      0x0000000100008000
0x7fffffffc248: 0x00000000004004e7      0x0000000000000000
0x7fffffffc258: 0x71eb993d1f26e436      0x0000000000400400
0x7fffffffc268: 0x00007fffffffc300      0x0000000000000000
```

2. rip부터 5줄의 어셈블리 명령어 출력
```
pwndbg> x/5i $rip
=> 0x4004e7 <main>:     push   rbp
   0x4004e8 <main+1>:   mov    rbp,rsp
   0x4004eb <main+4>:   sub    rsp,0x10
   0x4004ef <main+8>:   mov    DWORD PTR [rbp-0xc],0x0
   0x4004f6 <main+15>:  mov    DWORD PTR [rbp-0x8],0x1
```

3. 특정 주소의 문자열 출력
```
pwndbg> x/s 0x400000
0x400000:       "\177ELF\002\001\001"
```
