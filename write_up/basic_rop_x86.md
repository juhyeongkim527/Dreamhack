## 소스 코드
```
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>


void alarm_handler() {
    puts("TIME OUT");
    exit(-1);
}


void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    signal(SIGALRM, alarm_handler);
    alarm(30);
}

int main(int argc, char *argv[]) {
    char buf[0x40] = {};

    initialize();

    read(0, buf, 0x400);
    write(1, buf, sizeof(buf));

    return 0;
}
```
### checksec
<img width="669" alt="image" src="https://github.com/juhyeongkim527/Dreamhack-Study/assets/138116436/215a749b-9759-43d1-a2f3-4db33c079181">

## 익스플로잇 코드
```

```

