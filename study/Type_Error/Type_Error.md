# Type Error

변수를 선언할 때는 크기와 용도를 나타낼 수 있는 자료형을 함께 지정해주어야 한다.

해당 자료형이 담고 있는 정보는 컴파일러에 전달되고, 컴파일러는 해당 자료형을 참고하여 변수에 관한 코드를 생성한다.

각 자료형에 따라 할당하는 메모리 공간이 달라지고, 각 변수에 대한 연산 또한 그 메모리 공간을 대상으로 이루어진다.

한 번 정의된 변수의 자료형은 바꿀 수 없기 때문에(형변환 제외) 데이터가 자료형의 범위를 넘어서거나, 자료형의 바이트 크기를 넘어서면 `overflow`가 발생할 수 있다.

예를 들어, `int`에 `8bytes`크기의 `0x0123456789abcdef`를 대입하려고 하면, `overflow`가 발생해서 하위 4바이트 크기의 `0x89abcdef`만 저장되고 나머지는 날라간다.\
(정수를 읽을 때는 높은 주소부터 읽기 때문에 대입할 때는 `LSB` 부터 낮은 주소에 차례대로 넣어야 한다.)

## 예제 1. `out_of_range`

아래의 코드를 한번 예시로 보자.

```
// Name: out_of_range.c
// Compile: gcc -o out_of_range out_of_range.c

#include <stdio.h>

unsigned long long factorial(unsigned int n) {
  unsigned long long res = 1;

  for (int i = 1; i <= n; i++) {
    res *= i;
  }

  return res;
}

int main() {
  unsigned int n;
  unsigned int res;

  printf("Input integer n: ");
  scanf("%d", &n);

  if (n >= 50) {
    fprintf(stderr, "Input is too large");
    return -1;
  }

  res = factorial(n);
  printf("Factorial of N: %u\n", res);
}
```
해당 코드는 `unsigned long long` 타입을 리턴하는 `factorial` 함수를 `unsigned int`로 리턴받고 있다.

따라서, `8bytes` 크기의 변수를 `4bytes`에 대입하기 때문에 `overflow`가 발생할 수 있다.

바이너리를 실행하여 `n`을 키워가며 입력하다가 `18`이 되면 아래와 같이 갑자기 값이 작아진다.

```
$ ./out_of_range
Input integer n: 17
Factorial of N: 4006445056

$ ./out_of_range
Input integer n: 18
Factorial of N: 3396534272
```

그 이유는, `18! = 0x16beecca730000`인데, `7btyes` 크기의 정수이기 때문에 `4bytes`에 대입할 때 상위 `3bytes`인 `0x16beec`가 짤리기 때문이다.

자료형의 크기는 아래와 같다. 참고로 `long`은 `32-bit` 시스템에서 `int`와 완전히 동일한 자료형이며 `64-bit` 시스템으로 이식될 때 달라질 수 있다.

| **자료형**            | **크기**           | **범위**                         | **용도**               |
|-----------------------|--------------------|----------------------------------|------------------------|
| `signed char`         | 1 바이트           | -128 to 127                      | 정수, 문자              |
| `unsigned char`       | 1 바이트           | 0 to 255                         | 부호 없는 정수, 문자    |
| `signed short (int)`  | 2 바이트           | -32,768 to 32,767                | 정수                   |
| `unsigned short (int)`| 2 바이트           | 0 to 65,535                      | 부호 없는 정수          |
| `signed int`          | 4 바이트           | -2,147,483,648 to 2,147,483,647  | 정수                   |
| `unsigned int`        | 4 바이트           | 0 to 4,294,967,295              | 부호 없는 정수          |
| `size_t`              | 32bit: 4 바이트    | 0 to 4,294,967,295 (32bit)       | 부호 없는 정수          |
|                       | 64bit: 8 바이트    | 0 to 18,446,744,073,709,551,615 (64bit) | 부호 없는 정수  |
| `signed long`         | 32bit: 4 바이트    | -2,147,483,648 to 2,147,483,647  | 정수                   |
|                       | 64bit: 8 바이트    | -9,223,372,036,854,775,808 to 9,223,372,036,854,775,807 | 정수 |
| `unsigned long`       | 32bit: 4 바이트    | 0 to 4,294,967,295              | 부호 없는 정수          |
|                       | 64bit: 8 바이트    | 0 to 18,446,744,073,709,551,615 | 부호 없는 정수          |
| `signed long long`    | 32bit: 8 바이트    | -9,223,372,036,854,775,808 to 9,223,372,036,854,775,807 | 정수 |
|                       | 64bit: 8 바이트    | -9,223,372,036,854,775,808 to 9,223,372,036,854,775,807 | 정수 |
| `unsigned long long`  | 32bit: 8 바이트    | 0 to 18,446,744,073,709,551,615 | 부호 없는 정수          |
|                       | 64bit: 8 바이트    | 0 to 18,446,744,073,709,551,615 | 부호 없는 정수          |
| `float`               | 4 바이트           | 약 ±1.5 x 10^-45 to ±3.4 x 10^38 | 단정밀도 실수           |
| `double`              | 8 바이트           | 약 ±5.0 x 10^-324 to ±1.7 x 10^308 | 배정밀도 실수           |
| `Type *`              | 32bit: 4 바이트    | 주소                               | 포인터                  |
|                       | 64bit: 8 바이트    | 주소                               | 포인터                  |

## 예제 2. `oor_signflip`

또 다른 예시를 한번 살펴보자.

```
// Name: oor_signflip.c
// Compile: gcc -o oor_signflip oor_signflip.c

#include <stdio.h>

unsigned long long factorial(unsigned int n) {
  unsigned long long res = 1;

  for (int i = 1; i <= n; i++) {
    res *= i;
  }

  return res;
}

int main() {
  int n;
  unsigned int res;

  printf("Input integer n: ");
  scanf("%d", &n);

  if (n >= 50) {
    fprintf(stderr, "Input is too large");
    return -1;
  }

  res = factorial(n);
  printf("Factorial of N: %u\n", res);
}
```

해당 예시는 위의 예시에서 인자로 전달해주는 `n`이 `unsigned int`에서 `int`로 바뀌었다.

```
if (n >= 50) {
    fprintf(stderr, "Input is too large");
    return -1;
  }
```

조건에서 `n`이 너무 커지면 `factorial` 함수를 실행하기 힘들기 때문에 실행하지 않아야 하지만, `int`로 선언해주었기 때문에 음수를 대입해주는 경우 조건문을 통과하게 된다.

그런데 `factorial`에서 인자를 `unsigned int`로 받기 때문에, 만약 `n`에 `-1`을 입력한 경우,

`n`의 메모리에는 `0xffffffff`가 입력되게 되고, 해당 주소를 `unsigned int`로 해석하면 `2^32`가 되서 원래는 조건문에서 걸러져야 할 매우 큰 수가 `factorial`에 전달되어 버린다.

이렇게 되면 `factorial` 계산에 시간이 너무 오래 걸리고, 도중에 값이 `unsigned long long`도 넘어서게 되서 연산도 제대로 이루어지지 않게 되어 오류가 발생한다.

## 예제 3. `oor_bof`

```
// Name: oor_bof.c
// Compile: gcc -o oor_bof oor_bof.c -m32

#include <stdio.h>

#define BUF_SIZE 32

int main() {
  char buf[BUF_SIZE];
  int size;
  
  printf("Input length: ");
  scanf("%d", &size);
  
  if (size > BUF_SIZE) {
    fprintf(stderr, "Buffer Overflow Detected");
    return -1;
  }
  
  read(0, buf, size);
  return 0;
}
```

해당 바이너리는 `size`를 `int`로 선언했기 때문에 앞에서 봤던 부호 반전 때문에 `BOF` 취약점이 발생하는 예제이다.

원래는 `size`가 `BUF_SIZE`를 넘어서면 `BOF` 때매 종료되어야 하지만, `size`가 음수로 입력되면 해당 조건을 뛰어넘게 된다.

근데, `read` 함수의 원형은 `ssize_t read(int fd, void *buf, size_t count);`으로 입력할 크기를 지정하는 인자의 자료형이 `size_t(unsigned long)` 이다.

따라서, `size`를 음수로 입력해서 조건을 넘어서도 `size_t`로 해석하면 `BUF_SIZE`를 넘어서는 큰 양수로 해석될 수 있기 때문에 `BOF` 취약점이 발생하게 된다.

여기서 음수는 무조건 `MSB`가 `1`이어서 입력할 수 있는 `count`의 양수 범위는 `0 <= count <= 32 || count >= 1073741824(2^31)` 이다. (`2^31`은 `TMIN`을 대입할 때)

### 참고 : `64-bit` 시스템에서는 컴파일해도 실행이 되지 않고 오류가 발생하는 이유

`32-bit`에서는 `BOF`로 가능한 최소 양수가 `2^31`이지만, `64-bit`에서는 `2^63`이다. `read` 함수는 `count`로 인자가 이렇게 커지면 아무런 동작도 하지 않고 에러값을 반환한다.

## Type Overflow/Underflow

변수의 값이 연산 중에 자료형의 범위를 벗어나면, 갑자기 크기가 작아지거나 커지는 현상이 발생하는데, 이런 현상을 `Type Overflow/Underflow`라고 부른다. 

정수 자료형을 대상으로 발생하면 Type에 Integer를 넣어 `Integer Overflow/Underflow` 라고 한다.

`Overflow`는 값을 더하다가 범위를 넘어서서 값이 작아지는 것이고, `Underflow`는 값을 빼다가 범위를 넘어서서 값이 커지는 것이다.

더 정확히 말하면, `오버플로우`가 발생했을 때는 자료형이 표현할 수 있는 `최솟값`이 되며, `언더플로우`가 발생하면 `최댓값`이 된다.

![오버플로우/언더플로우 설명 사진](https://dreamhack-lecture.s3.amazonaws.com/media/d33f5f2f7cfb9873741b81c420c52fc20df288c49e5ce4bf317d9194385b98b5.png)

## 예제 4. `integer_example`

```
// Name: integer_example.c
// Compile: gcc -o integer_example integer_example.c

#include <limits.h>
#include <stdio.h>

int main() {
  unsigned int a = UINT_MAX + 1;
  int b = INT_MAX + 1;

  unsigned int c = 0 - 1;
  int d = INT_MIN - 1;

  printf("%u\n", a);
  printf("%d\n", b);

  printf("%u\n", c);
  printf("%d\n", d);
  return 0;
}
```

해당 바이너리를 살펴보면, `a`와 `b`는 `overflow`가 발생하고, `c`와 `d`는 `underflow`가 발생한다.

`a`와 `b`는 값이 작아지고, `c`와 `d`는 값이 커진다.

```
$ ./integer_example
0
-2147483648
4294967295
2147483647
```

## 예제 5. `integer_overflow`

```
// Name: integer_overflow.c
// Compile: gcc -o integer_overflow integer_overflow.c -m32

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int main() {
  unsigned int size;
  scanf("%u", &size);
  
  char *buf = (char *)malloc(size + 1);
  unsigned int read_size = read(0, buf, size);
  
  buf[read_size] = 0;
  return 0;
}
```

해당 바이너리는 `size`를 입력 받아서 `size + 1` 크기의 동적 할당을 해준 후, 최대 `size`만큼 입력을 받아준다.

이후 입력 받은 크기를 `read_size`에 저장해주고 `buf[read_size] = 0;`을 통해 `0(널바이트)`를 대입해준다.

만약 사용자가 `size` 에 `unsigned int` 의 최댓값인 `4294967295(2^32 -1)`을 입력하면, 

`malloc`의 인자도 `32-bit`에서 `size_t` 타입이기 때문에 `integer overflow`로 인해 `size + 1` 은 `0`이 된다. 

`0`이 `malloc` 에 전달되면, `malloc` 은 최소 할당 크기인 `32bytes`만큼 청크를 할당해준다.

**그런데 여기서 `read` 함수는 `size`를 그대로 사용하기 때문에  `32bytes` 크기의 청크에 `4294967295`만큼 값을 대입할 수 있는 `Heap Buffer Overflow`가 발생하게 된다.**

참고로, `size`에 `4294967295 + 1 : 0x0100000000`을 입력해줘서 입력과 함께 `overflow`를 발생시키면, `size = 0`이 되기 때문에 `Heap Buffer Overflow`는 발생하지 않는다.