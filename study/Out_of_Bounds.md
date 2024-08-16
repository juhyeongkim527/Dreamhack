# Out of Bounds

배열의 `index` 처리에서 발생하는 취약점이다. 크기가 미리 정해져 있는 배열의, 기존 크기를 벗어나는 `index` 요소에 참조하는 경우 발생할 수 있다. 

운이 좋으면 `Segmentation Fault`와 같이 프로그램의 비정상 종료로 그치지만, 컴파일러가 경고를 띄워주지 않기 때문에 어떤 경우에는 임의의 다른 메모리 영역에 접근할 수 있기 때문에 치명적인 취약점이 될 수 있다.

정리하면, 배열의 인덱스에 접근할 때 **인덱스 값이 음수이거나 배열의 길이를 벗어나는 경우** 발생한다. 컴파일러나 프로세스는 인덱스와 배열의 자료형에 따라, 어떤 요소(주소)에 접근할지만 계산할 뿐, **계산한 주소가 배열 범위 안에 있는지는 판단하지 않는다.**

따라서, 만약 사용자가 배열 참조에 사용되는 인덱스를 임의 값으로 조정할 수 있다면, 배열의 주소로부터 특정 오프셋에 있는 메모리의 값을 임의로 참조하거나 수정할 수 있게 되는 OOB 취약점이 발생한다.

## Example

```
// Name: oob.c
// Compile: gcc -o oob oob.c

#include <stdio.h>

int main() {
  int arr[10];

  printf("In Bound: \n");
  printf("arr: %p\n", arr);
  printf("arr[0]: %p\n\n", &arr[0]);

  printf("Out of Bounds: \n");
  printf("arr[-1]: %p\n", &arr[-1]);
  printf("arr[100]: %p\n", &arr[100]);

  return 0;
}
```

위의 바이너리를 보면, `int`형 변수 10개를 요소로 하는 배열 `arr`를 선언하고, `arr`, `arr[0]`, `arr[-1]`, `arr[100]` 의 주소를 출력한다.

여기서 중요한 점은 앞에서 말했듯이 `gcc` 컴파일러는 인덱스에 따른 요소의 주소만 계산할 뿐, 해당 주소가 배열의 범위에 속하는지는 판단하지 않기 때문에 프로그램이 정상적으로 실행된다.

해당 바이너리를 실행하면 아래와 같은 결과를 확인할 수 있다.

```
$ gcc -o oob oob.c
$ ./oob
In Bound:
arr: 0x7ffebc778b00
arr[0]: 0x7ffebc778b00

Out of Bounds:
arr[-1]: 0x7ffebc778afc
arr[100]: 0x7ffebc778c90
```

일단 배열 `arr`의 주소와 `arr[0]`의 주소는 같기 때문에 같게 나오고, `Out of Bounds:` 아래를 보면, 배열의 범위를 넘어서는 `arr[-1]`과 `arr[100]`의 주소도 오류없이 출력되는 것을 알 수 있다.

주소를 계산해보면, 먼저 `arr[0] - arr[-1] = 0x4`, `arr[100] - arr[0] = 0x190 = 100 x 4` 로 `int` 형의 오프셋과 일치하는 것을 알 수 있고 컴파일러는 인덱스에 따른 주소 계산만 적절히 수행해주는 것을 알 수 있다.

## 임의 주소 읽기

OOB로 메모리 임의 주소에 저장된 값을 읽으려면, **읽으려는 변수가 배열으로부터 떨어진 오프셋**을 알아야 한다. 배열과 변수가 **같은 세그먼트(예를 들어 스택)에 할당되어 있다면**, 둘 사이의 오프셋은 ASLR이나 PIE가 적용됨과 상관 없이 항상 일정하므로 디버깅을 통해 쉽게 알아낼 수 있다.

만약 다른 세그먼트에 존재한다면, 다른 취약점을 통해 두 변수의 주소를 각각 구한 후 차이를 계산하여 배열으로부터 읽고자 하는 변수의 오프셋을 계산해야 하므로 조금 더 복잡하다.

인덱스의 검사가 존재하지 않는 아래의 에제를 보자.

```
// Name: oob_read.c
// Compile: gcc -o oob_read oob_read.c

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

char secret[256];

int read_secret() {
  FILE *fp;

  if ((fp = fopen("secret.txt", "r")) == NULL) {
    fprintf(stderr, "`secret.txt` does not exist");
    return -1;
  }

  fgets(secret, sizeof(secret), fp);
  fclose(fp);

  return 0;
}

int main() {
  char *docs[] = {"COMPANY INFORMATION", "MEMBER LIST", "MEMBER SALARY",
                  "COMMUNITY"};
  char *secret_code = secret;
  int idx;

  // Read the secret file
  if (read_secret() != 0) {
    exit(-1);
  }

  // Exploit OOB to print the secret
  puts("What do you want to read?");
  for (int i = 0; i < 4; i++) {
    printf("%d. %s\n", i + 1, docs[i]);
  }
  printf("> ");
  scanf("%d", &idx);

  if (idx > 4) {
    printf("Detect out-of-bounds");
    exit(-1);
  }

  puts(docs[idx - 1]);
  return 0;
}
```

먼저 `read_secret()` 함수를 통해 `secret` 배열 크기만큼 `secret.txt`에서 값을 읽어와서 해당 배열에 저장해준다.

그 다음 `docs` 배열에 저장되있는 문자열을 출력하며, `docs`에서 몇번째 정보를 읽을 것인지 사용자에겍 `scanf("%d", &idx);`로 입력을 받는다. 바로 아래에서 `if` 조건을 통해 OOB 검사는 해주지만, **배열 인덱스의 범위를 양수로 넘어가는 것만 검사할 뿐, 음수로 넘어가는 것은 검사하지 않는다.**

```
if (idx > 4) {
  printf("Detect out-of-bounds");
  exit(-1);
}
```

따라서, 만약 읽고자하는 `secret_code`가 `docs`를 기준으로 음수 오프셋에 존재한다면, `puts(docs[idx - 1]);` 코드에서 OOB를 통해 `secret`의 값을 읽을 수 있게 되는 것이다. 

그럼 `docs`와 `secret_code`의 오프셋을 한번 찾아보면자.

일단 스택이라는 같은 세그먼트에 존재하고, `docs` 배열 선언 이후에 `secret_code` 포인터가 선언되며, 둘다 `char *` 자료형이기 때문에 인덱스를 기준으로 오프셋을 한칸만 음수로 이동시키면(스택이므로 낮은 주소로 뻗어나감) 된다.

`gcc - g` 옵션을 통해 디버깅 옵션을 준 후, `print` 로 출력하면 아래와 같이 주소를 더 자세히 알 수 있다.

<img width="1147" alt="image" src="https://github.com/user-attachments/assets/b5eebf49-9e9a-4190-aa9f-2ccc8479d461">
<img width="624" alt="image" src="https://github.com/user-attachments/assets/0cf8c325-0aa9-421b-b8d7-3cc4f559f0c1">

따라서, `idx`에 `0`을 대입하여 `docs[-1]`에 접근하면 `secret_code`를 가리키게 되고, `secret_code`는 `char *`인 문자열 포인터이기 때문에 `puts`로 출력하면 `secret_code`가 가리키는 `secrete` 변수가 출력되게 된다.

## 임의 주소 쓰기

아래의 예제를 한번 살펴보자. 

```
// Name: oob_write.c
// Compile: gcc -o oob_write oob_write.c

#include <stdio.h>
#include <stdlib.h>

struct Student {
  long attending;
  char *name;
  long age;
};

struct Student stu[10];
int isAdmin;

int main() {
  unsigned int idx;

  // Exploit OOB to read the secret
  puts("Who is present?");
  printf("(1-10)> ");
  scanf("%u", &idx);

  stu[idx - 1].attending = 1;

  if (isAdmin) printf("Access granted.\n");
  return 0;
}
```

먼저 `Student` 구조체를 10개 가지고 있는 `stu` 배열이 선언되어 있고, `int isAdmin` 변수가 선언되어 있다.

이후 `scanf("%u", &idx);`를 통해 `idx`에 입력을 받은 후, `stu[idx - 1].attending = 1;`를 통해 해당 인덱스의 `Student` 인스터스가 가지고 있는 `attending`에 1을 대입해준다.

이후, `if (isAdmin) printf("Access granted.\n");`을 통해 `isAdmin`이 `0`이 아니라면 관리자 권한을 획득하는 것으로 보아, OOB 취약점을 통해 `isAdmin` 변수에 `1`을 입력해주면 될 것 같다는 생각을 할 수 있다.

`isAdmin`과 `stu`는 전역 변수로 같은 세그먼트에 존재하기 때문에 두 변수의 오프셋을 출력해보면 아래와 같다.

1. `gcc -g` 옵션을 주지 않고 `i var` 으로 출력 (`i var`은 변수의 위치나 주소를 출력함)

```
pwndbg> i var isAdmin
Non-debugging symbols:
0x0000000000201130  isAdmin
pwndbg> i var stu
Non-debugging symbols:
0x0000000000201040  stu
pwndbg> print 0x201130-0x201040
$1 = 240
```

2. `gcc -g` 옵션을 통해 `print &`로 출력 (`print`는 변수에 저장된 값을 출력 : `pointer` 라면 가리키는 값을 출력, `print &`는 `pointer`라면 해당 변수에 저장된 주소 값을 출력, `pointer`가 아니라면 그 변수가 저장된 주소 자체를 출력)

<img width="455" alt="image" src="https://github.com/user-attachments/assets/09aa6e10-21ed-4ac1-bd09-ecf5c78e7a82">

`gcc - g` 옵션을 주면 `i var`으로 출력했을 때, 해당 변수의 주소가 아닌 소스 코드 상의 위치가 출력되버림

<img width="435" alt="image" src="https://github.com/user-attachments/assets/a77ed67e-3988-445f-a14e-34b0d2ce7f90">

위의 두 방법을 통해 `isAdmin`이 `stu`를 기준으로 `240`만큼 주소가 떨어져있음을 알 수 있고, `Student` 인스턴스의 크기는 `8 + 8 + 8 = 24`임을 알 수 있기 때문에, `stu[10]`이 `stu[0] + 24 * 10`이 되어 `isAdmin`을 가리킴을 알 수 있다.

따라서, `scanf("%u", &idx);`로 입력 받을 때 `11`을 입력해주면 `stu[idx - 1].attending = 1;`에서 `stu[11 - 1].attending = 1;`을 해주게 되어 `isAdmin`에 `1`이 입력되게 된다.

이게 가능한 이유는 `attending`이 `Student` 인스턴스의 첫번째 멤버이기 때문에 `stu[idx - 1].attending == stu[idx - 1]`과 같기 때문이다. 만약, `attending`이 아닌 `age`에 대입을 했다면 OOB가 발생해도 `stu[idx - 1]의 주소 + 16`에 접근하기 때문에 `isAdmin`에 `1`이 대입되지 못한다.
