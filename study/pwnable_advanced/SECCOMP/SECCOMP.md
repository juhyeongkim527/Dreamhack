[강의 링크](https://learn.dreamhack.io/263#1)

## Sandbox

**샌드박스(Sandbox)** 는 외부의 공격으로부터 시스템을 보호하기 위해 설계된 기법이다.

근본적으로, 개발자가 애플리케이션을 설계할 때 잠재적인 취약점을 모두 찾아서 이에 따른 대응책을 만드는 것은 힘들다.

따라서 아예 **Allow List**와 **Deny List**를 만들어서, 애플리케이션의 기능을 수행하는데에 있어서 꼭 필요한 **시스템 콜 실행** 또는 **파일의 접근**만을 허용한다.

이렇게 되면, 잠재적인 취약점을 발생시킬 수 있는 여러 시스템 콜 또는 파일 접근을 방지할 수 있기 때문에 개발자 입장에서 보안에 신경쓰기 매우 수월하다.

그렇지만, 각 애플리케이션의 실행 목적과 기능이 천차만별이기 때문에 샌드박스는 개발자가 애플리케이션의 요구에 맞춰 직접 명시해야한다.

만약 샌드박스를 적용할 때 애플리케이션에 대한 이해와 보안 관련 지식이 부족하면, 너무 많은 시스템 콜을 Deny하여 서비스의 접근성을 너무 과하게 해치게 될 수 있고, 일부 기능이 정상적으로 실행되지 않을 수 있다. 

예를 들어서 `execve` 시스템 콜 내부에서는 `open` 시스템 콜을 사용하는데, `open` 시스템 콜을 Deny 하면 애플리케이션에서 사용해야 하는 `execve` 시스템 콜을 사용할 수 없게 되는 상황이 발생한다.

반대로 너무 많은 시스템 콜을 Allow 하거나 보안 관련 지식이 부족하면, Deny했다고 생각한 시스템 콜이 다른 방법으로 우회되어 실행될 수 있는 취약점이 발생할 수 있다.

예를 들어, `open` 시스템 콜을 Deny했다고 생각하여 임의 파일에 접근하는 기능을 막았다고 생각했지만, 32-bit 시스템 콜으로 우회하거나, 비슷한 `opneat` 시스템 콜으로 우회할 수 있는 방법이 존재한다.

따라서 결국 샌드박스를 이용하는 것은 애플리케이션의 보안에 큰 도움이 될 수 있지만, 이에 대해 정확히 이해하고 사용하는 것이 중요하다.

<br>

## SECCOMP

**SECCOMP는 SEcure COMPuting mode**를 뜻하는 단어로, 리눅스 커널에서 프로그램의 샌드박싱 매커니즘을 제공하는 보안 기능이다.

샌드박스에서 설명했듯이, SECCOMP를 사용하면 애플리케이션에서 불필요한 시스템 콜의 호출을 방지할 수 있다.

애플리케이션에서 외부의 시스템 명령어를 실행하지 않는다면, `execve`와 같은 시스템 콜은 일반적으로 굳이 시스템에 포함될 필요가 없다.

해당 시스템 콜은 공격자의 익스플로잇에 주로 사용되는 시스템 콜이기 때문에, SECCOMP를 통해 `execve` 시스템 콜이 실행되지 않도록 정책을 설정하면, 해당 시스템 콜이 실행될 때 애플리케이션을 즉시 종료시킬 수 있다.

즉, 애플리케이션에 `execve` 시스템 콜을 통해 공격할 수 있는 취약점이 존재하더라도 `execve` 시스템 콜 자체가 수행되지 않도록 하여 잠재적인 취약점이 실행되지 않도록 하는 효과를 줄 수 있다.

SECCOMP에는 두 가지 모드를 선택해서 적용할 수 있는데, 아래는 코드는 해당 기능의 일부이다.

```c
int __secure_computing(const struct seccomp_data *sd) {
  int mode = current->seccomp.mode;
  int this_syscall;
  ... 
  this_syscall = sd ? sd->nr : syscall_get_nr(current, task_pt_regs(current));
  switch (mode) {
    case SECCOMP_MODE_STRICT:
      __secure_computing_strict(this_syscall); /* may call do_exit */
      return 0;
    case SECCOMP_MODE_FILTER:
      return __seccomp_filter(this_syscall, sd, false);
    ...
  }
}
```

먼저, `sd`는 현재 시스템 콜과 관련된 데이터를 담고 있는 구조체 포인터이다. 시스템 콜 번호인 `nr`, 시스템 콜의 **argument** 등을 포함한다.

`mode`에는 현재 프로세스(`current`)에서 SECCOMP 모드인 `seccomp.mode`를 가져온다.

그리고 `this_syscall`에는 `sd`가 존재하면 `sd->nr`을 통해 `sd`의 시스템 콜 번호를 가져오고, `sd`가 NULL이라면 현재 프로세스에서 호출한 시스템 콜 번호를 가져온다.

이후, `mode`가 `SECCOMP_MODE_STRICT`인지 `SECCOMP_MODE_FILTER`인지에 따라 이에 맞춰 앞에서 설정한 `this_syscall`을 호출해준다.

그럼 이제 SECCOMP의 **STRICT_MODE**와 **FILTER_MODE**가 무엇인지 살펴보자.

<br>

### 1. STRICT_MODE

해당 모드는 `read`, `write`, `exit`, `sigreturn` 시스템 콜의 호출만을 허용한다. 따라서, 이외의 시스템 콜의 호출이 발생하면 `SIGKILL` 시그널을 발생시켜 프로그램을 종료한다.

참고로, `sigreturn`은 리눅스 커널에서 시그널 처리 루틴이 끝난 후 원래의 실행 흐름으로 복귀하는 시스템 콜이다.

STRICT_MODE는 매우 제한된 시스템 콜의 호출만을 허용하기 때문에, 다양한 기능을 수행하는 일반적인 애플리케이션에는 적용할 수 없다.

```c
// Name: strict_mode.c
// Compile: gcc -o strict_mode strict_mode.c

#include <fcntl.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <unistd.h>

void init_filter() { prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT); }

int main() {
  char buf[256];
  int fd = 0;

  init_filter();

  write(1, "OPEN!\n", 6);
  fd = open("/bin/sh", O_RDONLY);  
  write(1, "READ!\n", 6);
  read(fd, buf, sizeof(buf) - 1);
  write(1, buf, sizeof(buf));
  return 0;
}
```

위 코드는 `prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);`를 통해 STRICT_MODE를 적용한 예제 코드이다. `prctl`은 프로세스의 특성이나 규칙을 관리하는 데 사용되는 시스템 콜이다.

따라서 해당 프로그램을 실행했을 때, `open` 시스템 콜의 호출은 허용되지 않기 때문에, 아래와 같이 `write` 시스템 콜의 호출 이후 프로그램이 `SIGKILL`을 발생시키며 종료하게 된다.

```
$ ./strict_mode
OPEN!
Killed
```

<br>

#### STRICT_MODE 동작 원리

STRICT_MODE를 처리하는 코드를 살펴보면, 어떻게 `read`, `write`, `exit`, `sigreturn` 시스템 콜의 호출만을 허용하는지 알 수 있다.

```
static const int mode1_syscalls[] = {
    __NR_seccomp_read,
    __NR_seccomp_write,
    __NR_seccomp_exit,
    __NR_seccomp_sigreturn,
    -1, /* negative terminated */
};
#ifdef CONFIG_COMPAT
static int mode1_syscalls_32[] = {
    __NR_seccomp_read_32,
    __NR_seccomp_write_32,
    __NR_seccomp_exit_32,
    __NR_seccomp_sigreturn_32,
    0, /* null terminated */
};
#endif
static void __secure_computing_strict(int this_syscall) {
  const int *allowed_syscalls = mode1_syscalls;

#ifdef CONFIG_COMPAT
  if (in_compat_syscall()) allowed_syscalls = get_compat_mode1_syscalls();
#endif
  do {
    if (*allowed_syscalls == this_syscall) return;
  } while (*++allowed_syscalls != -1);

#ifdef SECCOMP_DEBUG
  dump_stack();
#endif
  seccomp_log(this_syscall, SIGKILL, SECCOMP_RET_KILL_THREAD, true);
  do_exit(SIGKILL);
}
```

먼저 `mode1_syscalls` 배열에는 허용된 `read`, `write`, `exit`, `sigreturn` 시스템 콜이 저장되고, 마지막에는 `-1`을 통해 배열의 끝을 알린다.

그리고 `#ifdef CONFIG_COMPAT`를 통해 `CONFIG_COMPAT` 모드가 설정되어 있는지 확인하는데, 해당 모드는 64-bit 커널에서 32-bit 애플리케이션을 실행할 수 있도록 하는 호환성 모드이다.

만약 해당 모드가 설정되어있으면, `mode1_syscalls_32` 배열을 정의하여 32-bit `read`, `write`, `exit`, `sigreturn` 시스템 콜을 저장하고, `0`을 통해 배열의 끝을 알린다.

그리고 이제, `__secure_computing_strict(int this_syscall)` 함수를 선언하는데, SECCOMP를 사용하는 애플리케이션에서 시스템 콜이 호출되면 먼저 해당 함수에 진입하게 된다.

해당 함수의 내용을 보면, 먼저 허용된 시스템 콜을 가리키는 `allowed_syscalls` 포인터를 선언하여 `mode1_syscalls`를 가리키도록 한다.

`CONFIG_COMPAT` 모드인 경우 `if` 조건에서 `in_compat_syscall()` 함수를 호출하여 현재 실행 중인 시스템 콜 호출이 32-bit 호환 모드에서 발생했는지를 확인한다.

만약 이 함수가 true를 리턴한다면 현재 프로세스가 32-bit 애플리케이션을 실행 중이라는 뜻이므로, `allowed_syscalls`에 `get_compat_mode1_syscalls();` 함수를 통해 허용된 시스템 콜을 리턴해준다.

앞에서 정의한 `mode1_syscalls_32` 배열을 바로 대입해주지 않고 해당 함수를 호출하는 이유는, 커널은 여러 아키텍처에서 실행될 수 있기 때문에 아키텍처에 따른 올바른 시스템 콜 배열을 리턴하기 위함이라고 하는데, 이 부분은 다음에 더 공부해봐야 겠다.

그리고 `do while` 조건을 통해 `allowed_list`를 순회하며, 인자로 받은 `this_syscall`이 해당 배열에 존재하면 `return`을 통해 함수를 종료시켜 준다.

#### 수정 필요

만약 `*++allowed_syscalls != -1`을 만족하지 않고 빠져나오면 `this_syscall`이 `allowed_syscalls`에 존재하지 않는 시스템 콜이기 때문에 해당 함수에서 다음 루틴으로 넘어간다.

#### 수정 필요

만약 디버그 모드이면 `dump_stack()`을 통해 스택 정보를 출력해주고, 공통적으로 log에 시스템 콜 번호와 시그널을 남기며 `SIGKILL` 시그널과 함께 프로세스를 강제 종료한다.

<br>

### 2-1. FILTER_MODE : seccomp 라이브러리

샌드박스에서 말했던 Allow list와 Deny list를 FILTER_MODE에서 구현할 수 있다.

해당 모드에서는 두 list를 통해 원하는 시스템 콜을 허용하거나, 거부할 수 있다. 해당 모드를 적용한 예제 코드를 이해하기 위해서는 아래의 `seccomp` 라이브러리 관련 함수를 알아야 한다.

| 함수명            | 설명                                                         |
|-------------------|--------------------------------------------------------------|
| `seccomp_init`     | SECCOMP 모드의 기본 값을 설정하는 함수이다. 임의의 시스템 콜이 호출되면 이에 해당하는 이벤트가 발생한다. |
| `seccomp_rule_add` | SECCOMP의 규칙을 추가하는 함수이다. 임의의 시스템 콜을 허용하거나 거부할 수 있다. |
| `seccomp_load`     | 앞서 적용한 규칙을 애플리케이션에 반영하는 함수이다.                |

`seccomp` 설치 명령어는 아래와 같다.

```shell
apt install libseccomp-dev libseccomp2 seccomp
```

<br>

#### ALLOW LIST

```c
// Name: libseccomp_alist.c
// Compile: gcc -o libseccomp_alist libseccomp_alist.c -lseccomp

#include <fcntl.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

void sandbox() {
  scmp_filter_ctx ctx;
  ctx = seccomp_init(SCMP_ACT_KILL);

  if (ctx == NULL) {
    printf("seccomp error\n");
    exit(0);
  }

  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0);
  seccomp_load(ctx);
}

int banned() { fork(); }

int main(int argc, char *argv[]) {
  char buf[256];
  int fd;
  memset(buf, 0, sizeof(buf));

  sandbox();

  if (argc < 2) {
    banned();
  }

  fd = open("/bin/sh", O_RDONLY);
  read(fd, buf, sizeof(buf) - 1);
  write(1, buf, sizeof(buf));
}
```

위 코드는 `seccomp.h` 라이브러리의 함수를 사용하여 지정한 시스템 콜의 호출만을 허용하는 예제 코드이다.

`sandbox()` 함수를 보면 `ctx = seccomp_init(SCMP_ACT_KILL);`를 통해 모든 시스템 콜의 호출을 DENY하는 규칙을 생성한다.

그리고 이렇게 생성된 규칙에 `seccomp_rule_add` 함수를 통해, ALLOW LIST에 넣을(호출을 허용하는) 시스템 콜을 등록해준다.

그리고 `seccomp_load(ctx);`를 통해 지금까지 설정한 규칙을 적용해준다.

`main` 함수를 보면 `sandbox();` 를 통해 위 규칙을 적용해주고, `argc`의 값이 2보다 작은 경우 `banned()` 함수를 호출해준다. 여기서 `banned()`는 `fork` 시스템 콜을 호출해주는 함수이다.

`fork` 시스템 콜은 ALLOW LIST에 등록해주지 않은 시스템 콜이므로 호출이 허용되지 않아서, `argc < 2`인 경우 아래와 같이 프로그램은 종료되게 된다. 아닌 경우 `"/bin/sh"` 파일을 읽고 화면에 출력해준다.

```shell
$ ./libseccomp_alist
Bad system call (core dumped)

$ ./libseccomp_alist 1
ELF> J@X?@8	@@@?888h?h? P?P?!
```

<br>

#### DENY LIST

```c
// Name: libseccomp_dlist.c
// Compile: gcc -o libseccomp_dlist libseccomp_dlist.c -lseccomp

#include <fcntl.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

void sandbox() {
  scmp_filter_ctx ctx;
  ctx = seccomp_init(SCMP_ACT_ALLOW);

  if (ctx == NULL) {
    exit(0);
  }

  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(open), 0);
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(openat), 0);
  seccomp_load(ctx);
}

int main(int argc, char *argv[]) {
  char buf[256];
  int fd;
  memset(buf, 0, sizeof(buf));

  sandbox();

  fd = open("/bin/sh", O_RDONLY);
  read(fd, buf, sizeof(buf) - 1);
  write(1, buf, sizeof(buf));
}
```

위 코드는 `seccomp.h` 라이브러리의 함수를 사용하여 지정한 시스템 콜을 호출하지 못하도록 하는 예제 코드이다.

ALLOW LIST의 방법과 유사하게 `sandbox()` 함수를 보면, 먼저 `ctx = seccomp_init(SCMP_ACT_ALLOW);` 를 통해 모든 시스템 콜의 호출을 허용한다.

이후, `seccomp_rule_add` 함수를 통해 원하는 시스템 콜을 호출하지 못하도록 규칙을 설정해준 후 `seccomp_load(ctx);`를 통해 규칙을 적용시켜준다.

`main` 함수를 보면, `sandbox();` 함수를 호출해주기 때문에 위에서 설정해준 DENY LIST 규칙이 설정될 것이고 이에 따라 `read` 시스템 콜을 호출하면 프로세스가 `SIGKILL` 시그널과 함께 종료될 것이다.

<br>

### 2-2. FILTER_MODE : BPF

앞에서까지 `seccomp` 라이브러리를 사용하여 Allow list와 Deny list를 구현하는 방법을 알아보았다. 라이브러리 대신 **BPF(Berkeley Packet Filter)** 를 사용해서도 이를 구현할 수 있다.

BPF는 커널에서 지원하는 **Virtual Machine(VM)** 으로, 본래에는 네트워크 패킷을 분석하고 필터링하는 목적으로 사용되었다.

이는 **임의 데이터를 비교하고, 결과에 따라 특정 구문으로 분기하는 명령어**를 제공한다. 

라이브러리 함수를 통해 규칙을 정의한 것과 같이 특정 시스템 콜 호출 시에 어떻게 처리할지 명령어를 통해 구현할 수 있다.

BPF는 VM인만큼 다양한 명령어와 타입이 존재하는데, SECCOMP를 적용하는데에 있어 꼭 알아둬야 하는 명령어가 아래에 존재한다.

| 명령어    | 설명                                                                                       |
|-----------|--------------------------------------------------------------------------------------------|
| `BPF_LD`  | 인자로 전달된 값을 Accumulator에 복사한다. 이를 통해 값을 복사한 후 비교 구문에서 해당 값을 비교할 수 있다. |
| `BPF_JMP` | 지정한 위치로 분기한다.                                                                   |
| `BPF_JEQ` | 설정한 비교 구문이 일치할 경우 지정한 위치로 분기한다.                                      
| `BPF_RET` | 인자로 전달된 값을 반환한다.                                                              |

그리고 아래와 같이, BPF 코드를 직접 입력하지 않고 편리하게 원하는 코드를 실행할 수 있게끔 매크로가 존재한다.

##### 1.

```c
BPF_STMT(opcode, operand)
```

`opcode`에는 앞에서 봤듯이 수행하고 싶은 BPF 명령어(`BPF_LD`, `BPF_JMP` 등)를 지정할 수 있고, `operand`에는 `opcode`에서 사용할 값이나 인자를 지정할 수 있다. `opcode`는 인자로 전달된 값에서 몇 번째 인덱스에서 몇 바이트를 가져올 것인지도 지정할 수 있다.

예를 들어, `BPF_STMT(BPF_LD, 0);` 코드는 `BPF_LD` 명령어를 수행하여 Accumulator에 `0` 값을 복사한다.

##### 2.

```c
BPF_JUMP(opcode, operand, true_offset, false_offset)
```

해당 매크로는 `opcode`에 수행할 명령어를 지정하고, 해당 명령어를 `operand`에 존재하는 값과 비교하여 결과에 따라 `true_offset` 또는 `false_offset`으로 분기하는 매크로이다. 

예를 들어, `BPF_JUMP(BPF_JEQ, 0x10, 2, 1);` 는 `BPF_LD`를 통해서 Accumulator에 복사해준 값과 0x10을 비교하여 true인지 false인지 여부에 따라서 `2` 또는 `1` 오프셋으로 분기하는 매크로이다.

대부분 해당 매크로의 `opcode`에는 위와 같이 `BPF_JGT`, `BPF_JGE`와 같은 분기 명령어가 사용된다.

그럼 이제 BPF를 통해 어떻게 Allow list와 Deny list를 구현할 수 있는지 살펴보자.

<br>

#### ALLOW LIST

```c
// Name: secbpf_alist.c
// Compile: gcc -o secbpf_alist secbpf_alist.c
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>

#define ALLOW_SYSCALL(name)                               \
  BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_##name, 0, 1), \
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW)
#define KILL_PROCESS BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL)
#define syscall_nr (offsetof(struct seccomp_data, nr))
#define arch_nr (offsetof(struct seccomp_data, arch))

/* architecture x86_64 */
#define ARCH_NR AUDIT_ARCH_X86_64

int sandbox()
{
  struct sock_filter filter[] = {
      /* Validate architecture. */
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, arch_nr),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ARCH_NR, 1, 0),
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL),
      /* Get system call number. */
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, syscall_nr),
      /* List allowed syscalls. */
      ALLOW_SYSCALL(rt_sigreturn),
      ALLOW_SYSCALL(open),
      ALLOW_SYSCALL(openat),
      ALLOW_SYSCALL(read),
      ALLOW_SYSCALL(write),
      ALLOW_SYSCALL(exit_group),
      KILL_PROCESS,
  };

  struct sock_fprog prog = {
      .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
      .filter = filter,
  };

  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1)
  {
    perror("prctl(PR_SET_NO_NEW_PRIVS)\n");
    return -1;
  }

  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1)
  {
    perror("Seccomp filter error\n");
    return -1;
  }

  return 0;
}

void banned() { fork(); }

int main(int argc, char *argv[])
{
  char buf[256];
  int fd;
  memset(buf, 0, sizeof(buf));
  sandbox();
  if (argc < 2)
  {
    banned();
  }
  fd = open("/bin/sh", O_RDONLY);
  read(fd, buf, sizeof(buf) - 1);
  write(1, buf, sizeof(buf));
  return 0;
}
```

위 코드를 로직에 따라 `main`에서 처음 호출하는 `sandbox` 함수부터 순차적으로 분석해보면 아래와 같다.

```c
int sandbox()
{
  struct sock_filter filter[] = {
      /* Validate architecture. */
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, arch_nr),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ARCH_NR, 1, 0),
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL),
      /* Get system call number. */
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, syscall_nr),
      /* List allowed syscalls. */
      ALLOW_SYSCALL(rt_sigreturn),
      ALLOW_SYSCALL(open),
      ALLOW_SYSCALL(openat),
      ALLOW_SYSCALL(read),
      ALLOW_SYSCALL(write),
      ALLOW_SYSCALL(exit_group),
      KILL_PROCESS,
  };

  struct sock_fprog prog = {
      .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
      .filter = filter,
  };

  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1)
  {
    perror("prctl(PR_SET_NO_NEW_PRIVS)\n");
    return -1;
  }

  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1)
  {
    perror("Seccomp filter error\n");
    return -1;
  }

  return 0;
}
```

먼저, `sandbox` 함수에서는 `filter` 라는 `struct sock_filter` 타입의 배열을 선언한다. `struct sock_filter`는 BPF에서 네트워크 필터링을 위해 사용되는 구조체인데, 여기서는 시스템 콜 필터링을 위해 사용된다고 보면 된다.

```c
struct sock_filter {	/* Filter block */
	__u16	code;   /* Actual filter code */
	__u8	jt;	    /* Jump true */
	__u8	jf;	    /* Jump false */
	__u32	k;      /* Generic multiuse field */
};

struct sock_fprog {	/* Required for SO_ATTACH_FILTER. */
	unsigned short		len;	/* Number of filter blocks */
	struct sock_filter *filter;
};
```

`code`에는 필터링 시 수행할 코드가 들어가고, `jt`, `jf`에는 `code`가 `BPF_JMP`와 같은 점프 명령어인 경우 true, false에 따라 이동할 offset이 저장된다. 그리고 `k`에는 필터 명령어에 사용되는 상수 값이 저장되는데, 예를 들어 시스템 콜 번호나 주소 참조 값들이 들어갈 수 있다.

`filter`에 여러 매크로가 저장되는 방식을 이해하기 위해 위에서 살펴본 BPF 매크로가 `filter`의 배열 원소에 들어가게 되면 어떻게 저장될지, 아래의 매크로 정의를 살펴보자.

```c
/*
 * Macros for filter block array initializers.
 */
#ifndef BPF_STMT
#define BPF_STMT(code, k) { (unsigned short)(code), 0, 0, k }
#endif
#ifndef BPF_JUMP
#define BPF_JUMP(code, k, jt, jf) { (unsigned short)(code), jt, jf, k }
#endif
```

앞에서 봤던 BPF 매크로는, 위와 같이 정의되어 있고, `{}`를 통해 구조체 초기화를 진행한다. 위 코드를 보면 `{}` 내부의 멤버가 차례대로 `struct sock_filter`에 어떻게 저장되는지 이해할 수 있을 것이다.

그럼 이제 `sandbox()` 함수의 `filter` 배열에는 여러 매크로가 들어가는데, 차례대로 살펴보자.

```c
/* Validate architecture. */
BPF_STMT(BPF_LD + BPF_W + BPF_ABS, arch_nr),
```

`BPF_STMT(BPF_LD + BPF_W + BPF_ABS, arch_nr)`는 레지스터(accumulator)에 `arch_nr`에 대한 값을 로드해오는 매크로이다. 참고로 `BPF_LD + BPF_W + BPF_ABS`는 BPF 명령어를 하나로 합쳐서 실행하는 조합을 나타낸다.

`BPF_W`는 데이터를 Word 단위(4bytes)로 가져오겠다는 의미이고, `BPF_ABS`는 특정 주소로부터 절대 오프셋을 적용한 주소에서 데이터를 가져오겠다는 의미이다.

따라서 `BPF_STMT`에 전달된 `operand` 인자 값은 `arch_nr`이므로 `BPF_ABS`에 의해 `arch_nr` 값 자체를 가져오는게 아니라 `arch_nr`에 저장된 절대 오프셋을 통해 구한 주소로부터 데이터를 4바이트 단위로 가져와서 레지스터에 로드한다는 의미이다.

```c
#define arch_nr (offsetof(struct seccomp_data, arch))
```

`arch_nr`은 위와 같은 매크로로 정의되어 있는데, `struct seccomp_data`에서 `arch` 멤버의 오프셋의 주소를 나타낸다. 

참고로 앞에서도 설명했듯이 `struct seccomp_data`는 현재 수행중인 시스템 콜의 정보를 담고 있는 구조체이며, `struct seccomp_data`의 변경에 따라 바뀔 수 있지만, 아래의 구조체에서 이 값은 항상 4일 것이다.

100퍼센트 확신은 못하겠지만, 아마 해당 필터링이 실행될 때 `seccomp_data`로부터 4만큼 떨어진 오프셋에 존재하는 데이터인 `arch`를 레지스터에 로드해온다는 의미로 이해하고 있다.

```c
/**
 * struct seccomp_data - the format the BPF program executes over.
 * @nr: the system call number
 * @arch: indicates system call convention as an AUDIT_ARCH_* value
 *        as defined in <linux/audit.h>.
 * @instruction_pointer: at the time of the system call.
 * @args: up to 6 system call arguments always stored as 64-bit values
 *        regardless of the architecture.
 */
struct seccomp_data {
	int nr;
	__u32 arch;
	__u64 instruction_pointer;
	__u64 args[6];
};
```

그리고 아래의 코드를 통해 만약 해당 accumulate에 저장된 값이 **x86-64** 아키텍처를 나타내는 `ARCH_NR`와 같다면, `SECCOMP_RET_KILL`을 리턴하지 않고 다음 코드로 넘어가며, 아닌 경우 프로그램이 종료된다.

```c
#define arch_nr (offsetof(struct seccomp_data, arch))
...
BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ARCH_NR, 1, 0),
BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL),
```

그리고 아래 코드를 보면 먼저 레지스터에 `syscall_nr`을 로드해준 후, `ALLOW_SYSCALL` 매크로를 호출한 후 마지막에 `KILL_PROCESS`를 호출해준다.

```c
#define syscall_nr (offsetof(struct seccomp_data, nr))
...
BPF_STMT(BPF_LD + BPF_W + BPF_ABS, syscall_nr),
/* List allowed syscalls. */
ALLOW_SYSCALL(rt_sigreturn),
ALLOW_SYSCALL(open),
ALLOW_SYSCALL(openat),
ALLOW_SYSCALL(read),
ALLOW_SYSCALL(write),
ALLOW_SYSCALL(exit_group),
KILL_PROCESS,
```

각 매크로는 아래와 같다.

```c
#define ALLOW_SYSCALL(name)                               \
  BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_##name, 0, 1), \
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW)
#define KILL_PROCESS BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL)
```

`ALLOW_SYSCALL(name)` 매크로는 레지스터에 설정된 값이 `__NR_##name`과 같다면 다음 코드인 `BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW);`로 이동하고, 아니면 한줄을 건너뛰고 다음 코드로 이동한다.

`sandbox()` 코드에서 `ALLOW_SYSCALL(rt_sigreturn)`을 호출하기 전 `BPF_STMT(BPF_LD + BPF_W + BPF_ABS, syscall_nr)`를 호출해줬기 때문에 레지스터에는 현재 시스템 콜 번호를 나타내는 `syscall_nr`이 저장되어 있을 것이다.

따라서 현재 시스템 콜 번호가 `ALLOW_SYSCALL(rt_sigreturn)`에서 받은 `__NR_rt_sigreturn`과 같다면, 바로 `SECCOMP_RET_ALLOW`를 수행하며 `filter`의 다음 원소에 연속적으로 나오는 필터링 코드인 `ALLOW_SYSCALL(open)`을 호출하지 않고 바로 정상적으로 해당 루틴을 벗어나도록 리턴된다.

만약 다른 경우, 계속 연속적인 `ALLOW_SYSCALL(name)`을 호출하고 마지막에 존재하는 `ALLOW_SYSCALL(exit_group)`도 만족하지 않는다면 `KILL_PROCESS` 매크로를 호출하여 프로그램이 `SECCOMP_RET_KILL`을 호출하며 종료된다.

**결국 해당 `filter`에 지정된 필터링 코드는 먼저 현재 아키텍처가 x86-64인지 확인하고, 현재 호출한 시스템 콜 번호가 `ALLOW_SYSCALL(name)`으로 허용해준 시스템 콜에 속하지 않은 경우 프로그램을 종료하는 루틴이다.**

`sandbox()` 함수의 나머지 부분은 전부 앞에서 정의해준 `filter`를 필터링 코드로 규칙을 등록해주고, 시스템 콜이 호출되었을 때 해당 필터링 코드가 수행해주도록 하는 부분이다.

따라서, 아래와 같이 `main`에서 `argc`가 2보다 작은 경우만 `ALLOW_SYSCALL(fork)`가 존재하지 않기 때문에 필터링 코드에서 `KILL_PROCESS` 매크로까지 넘어가서 프로그램이 종료되고, 

2보다 큰 경우 `"/bin/sh"` 파일의 내용을 `read`하고 `write`하는 정상적인 루틴을 가질 수 있을 것이다.

```shell
$ ./secbpf_alistBad system call (core dumped)
$ ./secbpf_alist 1ELF> J@X?@8	@@@?888h?h? P?P?!
```

<br>

#### DENY LIST

```c
// Name: secbpf_dlist.c
// Compile: gcc -o secbpf_dlist secbpf_dlist.c
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>

#define DENY_SYSCALL(name)                                  \
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_##name, 0, 1), \
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL)
#define MAINTAIN_PROCESS BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW)
#define syscall_nr (offsetof(struct seccomp_data, nr))
#define arch_nr (offsetof(struct seccomp_data, arch))
/* architecture x86_64 */
#define ARCH_NR AUDIT_ARCH_X86_64

int sandbox()
{
    struct sock_filter filter[] = {
        /* Validate architecture. */
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, arch_nr),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ARCH_NR, 1, 0),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL),
        /* Get system call number. */
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, syscall_nr),
        /* List allowed syscalls. */
        DENY_SYSCALL(open),
        DENY_SYSCALL(openat),
        MAINTAIN_PROCESS,
    };
    
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };
    
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1)
    {
        perror("prctl(PR_SET_NO_NEW_PRIVS)\n");
        return -1;
    }
    
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1)
    {
        perror("Seccomp filter error\n");
        return -1;
    }
    
    return 0;
}

int main(int argc, char *argv[])
{
    char buf[256];
    int fd;
    memset(buf, 0, sizeof(buf));
    
    sandbox();
    
    fd = open("/bin/sh", O_RDONLY);
    read(fd, buf, sizeof(buf) - 1);
    write(1, buf, sizeof(buf));
    return 0;
}
```

DENY LIST도 앞에서 살펴본 ALLOW LIST와 거의 동일한 논리로 구현된다.

```c
#define DENY_SYSCALL(name)                                \
  BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_##name, 0, 1), \
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL)
#define MAINTAIN_PROCESS BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW)
```

여기서는 해당 매크로 함수만 반대로 구현되어 있는데, `DENY_SYSCALL(name)`의 `__NR_##name`과 `syscall_nr`이 동일할 경우, `BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL)`를 통해 프로세스가 종료된다.

그리고, `filter` 배열의 필터링 코드 루틴에서 `DENY_SYSCALL(name)`를 전부 탈출하면 마지막에 `MAINTAIN_PROCESS`가 호출되어, `SECCOMP_RET_ALLOW`이 리턴되어 루틴이 정상적으로 종료되도록 구현되어 있다.

따라서 `main`에서 `open` 시스템 콜을 호출하면 `DENY_SYSCALL(open)` 루틴에 걸려서 아래와 같이 프로그램이 종료될 것이다.

```shell
$ ./secbpf_dlist
Bad system call (core dumped)
```

## seccomp-tools

SECCOMP 규칙이 위 예제와 달리 매우 복잡할 경우, 소스 코드가 존재한다면 직관적인 BPF 문법 덕분에 이해하는데에 매우 오랜 시간이 걸리지는 않겠지만, 컴파일 된 이후 바이너리를 분석할 때에는 일일히 바이트코드를 변환해야 하기 때문에 매우 어려울 수 있다.

따라서 이러한 경우 **seccomp-tools**를 사용하면 SECCOMP가 적용된 바이너리 분석에 도움을 받을 수 있고, BPF 어셈블리/디스어셈블러도 제공하기 때문에 유용한 도구로 사용할 수 있다.

설치를 위한 명령어는 아래와 같으며, [깃허브 링크](https://github.com/david942j/seccomp-tools)에서 자세한 내용과 설명을 확인할 수 있다.

```shell
$ sudo apt-get update
$ sudo apt install gcc ruby-dev
$ sudo gem install seccomp-tools
```

seccomp-tools의 사용과 이에 대한 설명은 다음 글에서 이어가도록 하겠다.
