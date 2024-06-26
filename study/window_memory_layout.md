메모리 레이아웃 = 가상 메모리의 구성

# 프로세스 메모리 구조
윈도우 PE 파일 = PE 헤더 + 1개 이상의 섹션
![PE파일 구조](https://goo-gy.github.io/static/885b00e5fe788fcd3207a0308eeaf3c9/6af66/PE_file_memory.png)
## 섹션
유사한 용도로 사용되는 데이터가 모여있는 영역

아래와 같은 섹션의 정보는 PE 헤더에 저장하고, 이 정보를 통해 PE가 각 섹션들을 가상 메모리의 적절한 segment에 매핑됨
* 섹션의 이름
* 섹션의 크기
* 섹션이 로드될 주소의 오프셋(offset = 기준 주소로 얼마나 떨어져있는지)
* 섹션의 속성과 권한 등

  
섹션의 예는,
### .text 섹션 = PE의 __실행 가능한 기계 코드__
read와 execute 권한이 부여됨, write 권한은 공격자의 악의적 코드 삽입의 위험으로  
현대 운영체제에서 write 권한은 제거되어있음
### .data 섹션 = 컴파일 시점에 값이 정해진 전역 변수(PE가 실행중 참조하는 데이터)
CPU가 이 섹션의 데이터를 읽고 쓸 수 있어야 하므로 read, write 권한 부여
### .rdata 섹션 = 컴파일 시점에 값이 정해진 전역 상수와 참조할 DLL(Dynamic Link Library) 및 외부 함수들의 정보
CPU가 이 섹션의 데이터를 읽을수 있어야 하므로, read 권한이 부여되지만, write는 불가능

아래는 .rdata 섹션에 포함되는 여러 데이터의 유형입니다.   
주의 깊게 살펴봐야할 변수는 str_ptr입니다.   
str_ptr은 “readonly”라는 문자열을 가리키고 있는데, str_ptr은 전역 변수로서 .data에 위치하지만, “readonly”는 상수 문자열로 취급되어 .rdata에 위치합니다.

```
const char data_rostr[] = "readonly_data";
char *str_ptr = "readonly";  // str_ptr은 .data, 문자열은 .rdata

int main() { ... }
```

## 섹션이 아닌 메모리
윈도우의 가상 메모리 공간에는 섹션만 로드되는 것이 아닙니다. 프로그램 실행에 있어 필요한 스택과 힙 역시 가상 메모리 공간에 적재됩니다.

### 스택
윈도우즈 프로세스의 각 쓰레드는 자신만의 스택 공간을 가지고 있습니다.  
보통 **지역 변수나 함수의 리턴 주소**가 저장됩니다. 이 영역은 자유롭게 읽고 쓸수 있어야 하기 때문에 읽기/쓰기 권한이 부여됩니다.  
참고로 스택에 대해서 ‘아래로 자란다'라는 표현을 종종 사용하는데, 이는 스택이 확장될 때, 기존 주소보다 낮은 주소로 확장되기 때문입니다.

아래의 코드에서는 지역변수 choice가 스택에 저장되게 됩니다.
```
void func() {
  int choice = 0;
  
  scanf("%d", &choice);
  
  if (choice)
    call_true();
  else
    call_false();
    
  return 0;
}
```

### 힙
힙은 프로그램이 여러 용도로 사용하기 위해 할당받는 공간입니다. 따라서 **모든 종류의 데이터가 저장**될 수 있습니다. 스택과 다른 점은 비교적 스택보다 큰 데이터도 저장할 수 있고 전역적으로 접근이 가능하도록 설계되었단 점입니다. 또한 실행중 동적으로 할당받는 점 역시 다릅니다.

권한은 보통은 데이터를 읽고 쓰기만 하기 때문에 읽기/쓰기 권한만을 가지나, 상황에 따라 실행 권한을 가지는 경우도 존재합니다.

아래 예제 코드는 heap_data_ptr에 malloc()으로 동적 할당한 영역의 주소를 대입하고, 이 영역에 값을 씁니다. heap_data_ptr은 지역변수이므로 스택에 위치하며, malloc으로 할당받은 힙 세그먼트의 주소를 가리킵니다.
```
int main() {
  int *heap_data_ptr =
      malloc(sizeof(*heap_data_ptr));  // 동적 할당한 힙 영역의 주소를 가리킴
  *heap_data_ptr = 31337;              // 힙 영역에 값을 씀
  printf("%d\n", *heap_data_ptr);  // 힙 영역의 값을 사용함
  return 0;
}
```  
