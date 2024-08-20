# Use After Free

원룸 임대를 예시로 들어보면, 계약이 만료될 경우 ***세입자는 임대인에게 원룸 접근 권한을 반납해야 하며, 임대인은 세입자의 접근 권한을 막고 사용한 원룸은 깨끗이 청소되어야 한다.***

`ptmalloc2`를 통해 메모리를 관리할 때도 비유한 위의 과정이 똑같이 이루어져야 한다.

프로세스에게 할당된 메모리가 해제될 때, **1. 할당된 메모리 참조에 사용한 `포인터`를 메모리 해제 후에 적절히 초기화해주어야 하고**, **2. 해제한 `메모리 공간`을 초기화하여 다음에 할당된 프로세스가 이전에 사용된 메모리 공간에 적혀있는 값을 참조할 수 없게 해야한다.**

위 두 과정이 일어나지 않으면, `Use After Free` 취약점이 발생하게 되고, 이 취약점은 현재까지도 브라우저 및 커널에서 자주 발견되며 익스플로잇 성공률도 다른 취약점에 비해 높아 위험한 취약점이다.

## Dangling Pointer

컴퓨터 과학에서 `Dangling Pointer`는 **유효하지 않은 메모리 영역을 가리키는 포인터**를 말한다. 

메모리 동적 할당에 사용되는 `malloc` 함수는 동적 할당된 메모리 주소를 반환하고, 사용자는 포인터 선언하여 해당 포인터를 통해 `malloc`으로 반환된 메모리 주소를 저장하여 할당된 메모리에 접근한다.

반대로 동적 할당된 메모리를 해제하는데 사용되는 `free` 함수는 해제된 청크를 `ptmalloc`에 반환할 뿐, 앞에서 `malloc`을 통해 **반환된 청크의 주소를 담고 있던 포인터를 초기화하지는 않는다.**

따라서, `free` 호출 이후에 해당 포인터를 초기화하지 않아주면 해당 포인터는 `Dangling Pointer`가 된다.

Dangling Pointer가 생긴다고 해서 프로그램이 보안적으로 취약한 것은 아니지만, 이는 프로그램이 예상치 못한 동작을 할 가능성을 키우며, 경우에 따라서 공격자에게 공격 수단으로 활용될 수 있다. 아래 예제를 살펴보자.

```
// Name: dangling_ptr.c
// Compile: gcc -o dangling_ptr dangling_ptr.c
#include <stdio.h>
#include <stdlib.h>

int main() {
  char *ptr = NULL;
  int idx;

  while (1) {
    printf("> ");
    scanf("%d", &idx);
    switch (idx) {
      case 1:
        if (ptr) {
          printf("Already allocated\n");
          break;
        }
        ptr = malloc(256);
        break;
      case 2:
        if (!ptr) {
          printf("Empty\n");
        }
        free(ptr);
        break;
      default:
        break;
    }
  }
}
```

해당 바이너리는 청크를 해제한 후에 해당 청크를 가리키던 `ptr` 포인터 변수를 초기화해주지 않는다. 따라서, 아래와 같이 청크를 할당하고 해제하면 `ptr`은 여전히 이전에 할당한 청크의 주소를 가리키는 `Dangling Pointer`가 된다.

따라서, `1`을 입력하고 `2`를 입력해서 메모리를 해제해준 후, 다시 `1`으로 메모리를 할당하려고 해도 `ptr`이 초기화되지 않아서 `if(ptr)`에 걸리게 되고 여전히 `ptr`의 주소가 출력되며,

다시 `2`를 입력하면 `if(!ptr)`에 걸리지 않아서 `"Empty"`를 출력하는게 아닌 `Double Free Bug` 발생 시킨다.

<img width="1176" alt="image" src="https://github.com/user-attachments/assets/0fd2b1ad-2649-4479-a03f-a12cb01729b2">

`Double Free Bug`는 프로그램에 심각한 보안 위협이 되는 소프트웨어 취약점으로, 이에 대해서 나중에 더 자세히 설명하도록 하겠다.

# Use After Free

`Use After Free(UAF)`는 문자 그대로, **해제된 이후에도 해제된 메모리에 접근할 수 있을 때 발생하는 취약점**을 말한다.

**앞에서 봤던 `Dangling pointer`에 접근할 수 있게 되어 발생하기도 하지만, 새롭게 할당된 영역을 초기화하지 않고 사용하면서 발생하기도 한다.**

왜냐하면 `malloc`과 `free`를 통해 메모리가 할당되거나 해제될 때 해당 청크의 데이터들은 초기화되지 않기 때문이다. 

따라서, 해제하기 바로 이전에 청크의 데이터를 초기화해주거나 새롭게 할당된 청크를 프로그래머가 명시적으로 초기화해주지 않으면 **이전에 해제한 메모리에 남아있던 데이터가 유출되거나 사용될 수 있다.**

```
// Name: uaf.c
// Compile: gcc -o uaf uaf.c -no-pie
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct NameTag {
  char team_name[16];
  char name[32];
  void (*func)();
};

struct Secret {
  char secret_name[16];
  char secret_info[32];
  long code;
};

int main() {
  int idx;

  struct NameTag *nametag;
  struct Secret *secret;

  secret = malloc(sizeof(struct Secret));

  strcpy(secret->secret_name, "ADMIN PASSWORD");
  strcpy(secret->secret_info, "P@ssw0rd!@#");
  secret->code = 0x1337;

  free(secret);
  secret = NULL;

  nametag = malloc(sizeof(struct NameTag));

  strcpy(nametag->team_name, "security team");
  memcpy(nametag->name, "S", 1);

  printf("Team Name: %s\n", nametag->team_name);
  printf("Name: %s\n", nametag->name);

  if (nametag->func) {
    printf("Nametag function: %p\n", nametag->func);
    nametag->func();
  }
}
```

위 코드는 `UAF` 취약점이 존재하는 예제 코드이다. 구조체 `NameTag`와 `Secret`이 정의되어 있는데, 예제에서 유출되어서는 안되는 `Secret` 구조체를 먼저 할당하여 멤버에 값을 대입 후 이를 해제한다.

이후 `Nametag` 구조체를 할당하여, `nametag->team_name` 멤버 변수에 값을 대입 후, `memcpy(nametag->name, "S", 1);`를 통해 `nametag->name` 멤버 변수에는 `1`개의 크기만큼 `"S"` 문자를 `name`에 저장한다.

그 다음 두 멤버 변수 값을 출력해준 후, `nametag->func`에는 따로 값을 대입해주지 않고 아래와 같이 `if(nametag->func)`을 통해 값이 존재하는지 확인한다.

```
if (nametag->func) {
  printf("Nametag function: %p\n", nametag->func);
  nametag->func();
}
```

만약, `nametag->func`에 값이 존재한다면(`NULL`이 아니라면), `nametag->func`에 저장된 값을 `%p`를 통해 `hex` 값으로 출력해준 후, `nametag->func()`가 가리키는 함수를 실행한다.

실행 결과는 아래와 같다.

<img width="516" alt="image" src="https://github.com/user-attachments/assets/85aefa66-e783-407e-a5f4-9314b33e486f">

결과를 살펴보면, `nametag->name`의 첫번째 문자열만 `"S"`로 바뀐채, `secret->secret_info`에 대입한 값이 출력되고, 

`nametag->func`는 값을 대입해주지 않았음에도 불구하고 `secret->code`의 값인 `0x1337`이 출력되어 `nametag->func();`는 `0x1337`이라는 주소를 따라가서 `Segfault`가 발생한다.

## `uaf` 동적 분석

`ptmalloc2`는 새로운 할당 요청이 들어왔을 때, 요청된 크기와 비슷한 청크가 `tcache`에 있는지 확인 후에 없다면 `bin`에서 확인한다고 하였다.

여기서 찾은 청크를 꺼내어서 재사용하는데, 예제 코드에서 `Nametag`와 `Secret` 구조체는 완전히 같은 크기의 구조체이다. 

**따라서, 먼저 할당한 `secret`을 해제하고 `nametag`를 할당하면, `nametag`는 `secret`이 사용한 청크를 그대로 다시 사용하게 된다.**

이때, `free`는 해제한 청크의 데이터를 초기화해주지 않기 때문에 `nametag`는 `secret`의 데이터 값들이 일부 남아있게 된다.

`gdb`를 통해서 `secret`을 해제한 직후 `secret`이 사용하던 메모리 영역의 데이터를 `free(secret);` 바로 다음 코드에 breakpoint를 걸어서 살펴보자.

해당 중단점에서 `heap` 명령어를 통해 해제된 청크들의 정보를 조회해보면 아래와 같다.

<img width="374" alt="image" src="https://github.com/user-attachments/assets/f8899bda-5515-4f35-a377-c98e7668e694">

총 3개의 청크가 존재하는데, `Free chunk (tcachebins)`인 `0x602250`이 우리가 찾고 있었던 `secret`이 사용했던 청크이다. 해제되었기 때문에 `tcache`의 엔트리에 들어가있는 상태이다.

***참고로, `Allocated chunk`인 `0x405000`은 `tcache`와 관련된 공간으로 `tcache_perthread_struct` 구조체에 해당하며, `libc` 단에서 힙 영역을 초기화할 때 할당하는 청크이다. 이는 다음에 다뤄 볼 예정이다.***

이제 `secret`이 사용 후 해제한 `0x602250`의 메모리 주소에서 저장된 값들을 출력한 부분을 살펴보자.

<img width="511" alt="image" src="https://github.com/user-attachments/assets/f951b295-a869-4f82-9f06-2cd823412688">

`0x4052b0` 주소의 값을 출력해보면 아래와 같이 `secret->secret_info`의 값이 여전히 초기화되지 않고 존재하는 것을 알 수 있다.

<img width="523" alt="image" src="https://github.com/user-attachments/assets/fdcf25f1-efbd-4a30-b590-20eeb99e5cca">

하지만, `secret->secret_name`에 해당하는 부분인 `0x4052a0`는 `fd`와 `bk` 값으로 초기화되어있다.

왜냐하면 `heap` 명령어를 통해 확인한 해당 위치에서 `fd`의 값이 `0x405`인데, `0x4052a0`에도 `0x405`가 저장되어 있기 때문이다.

그리고, `secret_name`의 크기인 `32bytes` 만큼 떨어진 `0x4052d0`에는 `secret->code`에 대입한 값인 `0x1337`이 존재하는 것까지 확인할 수 있다.

다음으로, `nametag`를 할당하고 `printf("Team Name: %s\n", nametag->team_name);`를 호출하기 직전의 시점에 breakpoint를 걸어준 후 `nametag` 멤버 변수들의 값을 확인해보자.

<img width="384" alt="image" src="https://github.com/user-attachments/assets/a3547cf9-5136-4c9e-8ae7-2e417b7eb6aa">

`printf`의 인자인 `nametag->team_name`의 주소가 `0x4052a0` 이므로, 해당 메모리 공간을 살펴보면 아래와 같다.

<img width="530" alt="image" src="https://github.com/user-attachments/assets/8d82e06b-77f7-419c-ad5f-b6cfb36eb49e">

`nametag->team_name`은 입력값대로 입력이 되어 있지만, `nametag->name`에는 초기화되지 않고 앞에서 사용된 `secret->secret_info`의 값이 존재하는 것을 확인할 수 있고, `nametag->func` 또한 앞에서 사용된 `secret->code` 값이 존재하는 것을 알 수 있다.

### 따라서, 예제와 같이 **1. 초기화되지 않은 메모리의 값을 읽어내거나, 2. 새로운 객체가 악의적인 값을 사용하도록 유도하여 프로그램의 정상적인 실행을 방해할 수 있다.**





















