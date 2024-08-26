// Name: fsb_overwrite.c
// Compile: gcc -o fsb_overwrite fsb_overwrite.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void get_string(char *buf, size_t size)
{
  ssize_t i = read(0, buf, size); // 읽은 바이트 수를 리턴 (-1 : 오류, 0 : EOF 만난 경우)
  if (i == -1)
  {
    perror("read");
    exit(1);
  }

  if (i < size) // 0x20보다 읽은 바이트 수가 적은 경우
  {
    if (i > 0 && buf[i - 1] == '\n') // buf의 마지막이 개행문자로 끝나는 경우
      i--;
    buf[i] = 0; // 개행문자('\n') 을 지우고 `0`으로 설정
  }
}

int changeme;

int main()
{
  char buf[0x20];

  setbuf(stdout, NULL);

  while (1)
  {
    get_string(buf, 0x20);
    printf(buf);
    puts(""); // 개행문자 추가
    if (changeme == 1337)
    {
      system("/bin/sh");
    }
  }
}
