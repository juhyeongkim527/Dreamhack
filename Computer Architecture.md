# 컴퓨터 구조

## 컴퓨터의 기능 구조에 대한 설계
컴퓨터가 연산을 효율적으로 하기 위해 어떤 기능이 컴퓨터에 있는지 고민하고 설계하는 분야
1. 폰 노이만 구조
  * 연산, 제어, 저장 기능이 필요
    * CPU
      * ALU - 산술, 논리 연산
      * Control Unit - 제어장치
      * 레지스터, 캐시 - 저장
     
        
          * 범용 레지스터(General Register): 주 용도는 있으나, 그 외의 용도로도 자유롭게 사용할 수 있는 레지스터. x64에는 rax, rbx, rcx, rdx, rsi, rdi, rsp, rbp, r8-r15가 있다.
          * 세그먼트 레지스터(Segment Register): 과거에는 메모리 세그먼테이션이나, 가용 메모리 공간의 확장을 위해 사용했으나, 현재는 주로 메모리 보호를 위해 사용되는 레지스터이다. x64에는 cs, ss, ds, es, fs, gs가 있다.
          * 플래그 레지스터(Flag Register): CPU의 상태를 저장하는 레지스터
          * 명령어 포인터 레지스터(Instruction Pointer Register, IP): CPU가 실행해야할 코드를 가리키는 레지스터. x64에서는 rip가 있다.
     
        
    * memory
      * RAM - 주기억장치
      * HDD, SSD - 보조기억장치
    * bus - 제어 신호, 데이터 이동

2. 하버드 구조
3. 수정된 하버드 구조

## 명렁어 집합 구조(Instruction Set Architecture)
CPU가 처리해야하는 명렁어를 설계하는 분야

* ARM
* x86(32bit)
* x86-64,x64(64bit)
  * 여기서 n bit는 CPU 한번에 처리할 수 있는 비트 개수(WORD)이며 레지스터가 64비트로 이루어졌다는 의미임.
  * 아래는 x86-64 레지스터 이미지![x86-64 레지스터 이미지](https://dreamhack-lecture.s3.amazonaws.com/media/3989967ad96e63dbdcc95e58609a84caa679054b1db92b11fc959ca4b48d18aa.png)
  * 64비트 레지스터는 2^64개의 메모리 주소를 읽을 수 있기 때문에 64비트 레지스터의 메모리 주소 범위는  
    0x0000000000000000~0xffffffffffffffff(16진수는 1자리에 4비트이므로 총 16자리)이며,  
    최대 1TB 크기의 RAM을 가질 수 있으며(32bit 레지스터는 4GB까지), 참고로 메모리 주소는 하나 당 8bit(1byte) 크기를 가짐
  * 아래는 32bit 아키텍처에서의 메모리 시각화 이미지![메모리 시각화](https://tcpschool.com/lectures/img_c_pointer_type.png)

* x86은 32bit ISA를 통칭함 (8086, 80186, 80286 등으로 불렸기 때문에)
* x86-64=AMD64(64bit)는 x86(32bit)와 호환되는 64bit ISA를 통칭함 (intel64, IA-32e도 x86-64로 통칭됨)
 
## 마이크로 아키텍쳐
CPU의 하드웨어적 설계, 즉 CPU가 효율적으로 ISA를 처리할 수 있도록 회로 설계하는 것
