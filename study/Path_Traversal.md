# 서론

리눅스 프로그램은 `파일 시스템`에 접근하여 어떤 파일의 데이터를 읽거나, 파일에 데이터를 쓸 수 있다.

리눅스의 기본 유틸리티인 `cat`으로 파일의 데이터를 출력하게 되면, `cat`은 파일을 열어서 읽은 다음에 `stdout`에 데이터를 출력한다.\
(참고로 `stdout`이 나와서 갑자기 생각이 든 건데, `read`는 사용자에게 입력을 받을 때 사용자가 엔터를 입력하면 `stdin`에 현재까지 저장된 값을 `read`로 가져오게 된다고 한다. 이 때문에 3번째 인자인 `size`보다 작은 값도 입력이 가능하다.)

`로컬 파일 시스템`에 접근하는 서비스를 외부에 공개할 때, 외부 프로세스가 접근할 수 있는 **파일의 경로에 제한을 필수적으로 두어야 한다.**

예를 들어, 사용자에게 각자의 디렉토리를 생성해주고 그 디렉토리만 자유롭게 활용할 수 있게 해주는 서비스가 있다고 하자.

이 경우에 당연히 사용자가 각자의 디렉토리에만 접근할 수 있게 해야, 악의적인 사용자가 다른 사용자의 디렉토리에 접근해서 private한 파일을 훔치거나, 서버의 파일을 조작하여 서버를 장악하는 상황을 막을 수 있다.

`Path Traversal`은 위와 같은 서비스가 있을 때, **사용자가 허용되지 않은 경로에 접근할 수 있는 취약점**을 말한다. 

사용자가 접근하는 경로에 대한 검사가 미흡하여 발생하며, **임의 파일 읽기 및 쓰기**의 수단으로 활용될 수 있다.

# 리눅스 경로

## 절대 경로와 상대 경로

리눅스에는 파일의 경로를 지정하는 두 가지 방법으로 `절대 경로(Absolute Path)`와 `상대 경로(Relative Path)`가 있다.

![image](https://github.com/user-attachments/assets/19c7a81e-a7c4-43c1-adc0-db645d87b252)

### 절대 경로

절대 경로는 **`root director('/')` 부터 파일에 이를 때 까지 거쳐야 하는 디렉토리 명을 모두 연결하여 구성**한다. 각 디렉토리는 `/`로 구분되며, 끝에 대상 파일의 이름을 추가하여 완성한다.\
(참고로 `/`는 `///` 처럼 붙여서 중복하는 경우는 그냥 하나의 `/`와 같다. `/home/tmp == /home///tmp`)

리눅스 파일 시스템에서 한 파일에 대응되는 절대 경로는 유일하며, 파일만의 고유한 값이다. 그래서 현재 사용자가 어떤 디렉토리에 위치하더라도, 루트 디렉토리를 기준으로 찾아가기 때문에 어떤 경로의 파일이라도 가리키고 찾아갈 수 있다.

예시 이미지에서 `target` 파일을 가리키는 절대 경로는 `/a/b/c/target`이다.

### 상대 경로

상대 경로는 **`현재 디렉토리`를 기준으로 다른 파일에 이르는 경로를 상대적으로 표현**한 것이다. 

리눅스에서 `..`은 이전 디렉토리를, `.`은 현재 디렉토리를 의미하고, 이를 통해 상대 경로를 구성할 수 있다.

절대 경로와 달리 어떤 파일을 가리키는 상대 경로의 수는 현재 경로에 따라 다르기 때문에 무한하다. 예시 이미지에서 현재 디렉토리가 `d`일 때, `target`을 가리키는 상대 경로는 아래와 같이 여러개가 존재한다.

- `../c/target`, `./../c/target`, `../../../a/b/c/target`

# Path Traversal

`Path Traversal`은 **`권한 없는 경로`에 프로세스가 접근할 수 있게 되는 취약점**을 말한다. 

여기서 `권한`은 리눅스파일 시스템에서의 `r, w, x`와 같은 권한과 완전히 동일한 개념이 아니라, 서비스 로직 관점에서 어떤 파일이나 디렉토리에 접근할 수 있는가에 대한 권한을 의미한다.

아래의 예제를 보며, `Path Traversal`이 발생할 수 있는 상황에 대해 살펴보자.

```
/ Name: path_traversal.c
// Compile: gcc -o path_traversal path_traversal.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const int kMaxNameLen = 0x100;
const int kMaxPathLen = 0x200;
const int kMaxDataLen = 0x1000;
const char *kBasepath = "/tmp";

int main() {
  char file_name[kMaxNameLen];
  char file_path[kMaxPathLen];
  char data[kMaxDataLen];
  FILE *fp = NULL;

  // Initialize local variables
  memset(file_name, '\0', kMaxNameLen);
  memset(file_path, '\0', kMaxPathLen);
  memset(data, '\0', kMaxDataLen);

  // Receive input from user
  printf("File name: ");
  fgets(file_name, kMaxNameLen, stdin);

  // Trim trailing new line
  file_name[strcspn(file_name, "\n")] = '\0';

  // Construct the `file_path`
  snprintf(file_path, kMaxPathLen, "%s/%s", kBasepath, file_name);

  // Read the file and print its content
  if ((fp = fopen(file_path, "r")) == NULL) {
    fprintf(stderr, "No file named %s", file_name);
    return -1;
  }

  fgets(data, kMaxDataLen, fp);
  printf("%s", data);

  fclose(fp);

  return 0;
}
```

해당 소스 코드를 보면, `fgets(file_name, kMaxNameLen, stdin);`을 통해 `stdin`에서 `kMaxNameLen` 만큼 문자열을 읽어와서 `file_name`에 저장한다.

아래에서 `file_name[strcspn(file_name, "\n")] = '\0';` 이건 줄바꿈 문자를 끝을 나타내는 널문자로 바꿔주는 부분이므로 크게 중요하지 않고,

`sprintf`에서 포맷 스트링을 통해 출력한 문자열을 입력하는 길이를 정해주는 `n`이 추가된 `snprintf` 함수가 사용된 `snprintf(file_path, kMaxPathLen, "%s/%s", kBasepath, file_name);`를 보자.

`kBasepath`와 `file_name`을 인자로 포맷 스트링 `%s/%s`를 변환하여 출력한 후, 출력된 결과를 최대 `kMaxPathLen`까지 `file_path`에 저장한다.

`kBasepath`는 `"/tmp"`이므로, `/tmp/file_name`이 출력될 것인데, 여기서 `/etc/passwd`를 출력하려면 앞에서 `file_name`에 어떤 값을 넣어줘야 할지 생각해보자.

일단 절대 경로로는 이미 `/tmp`부터 시작하기 때문에 `/etc` 부터 시작하지 못해서 불가능하고, 상대 경로로 한번 해볼 수 있다.

`/etc`는 `/tmp`를 기준으로 이전 디렉토리로 이동한 후 다시 `etc`로 이동하면 되기 때문에 `/tmp/../etc/passwd`이 입력되도록 `file_name`에 `"../etc/passwd`를 입력해주면 된다. (참고로 `/tmp`와 `/tmp/`는 같다.)

위와 같이 접근할 파일의 경로를 사용자에게 입력 받으면서, 경로 문자열에 대한 검사가 제대로 이루어지지 않는다면, 사용자가 접근 권한이 없는 영역에 접근할 수 있게 된다.

이렇게 되면 `root`의 비밀번호를 읽어오거나 제거할 수 있고, `ssh`의 설정 등 다른 디렉토리의 설정 정보들을 변경하여 서버에 매우 큰 공격이 발생할 수 있다.
