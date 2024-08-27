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

  stu.[idx - 1].attending = 1;
  //  stu[idx - 1].age = 1; 이렇게 하면 익스플로잇 불가능

  if (isAdmin) printf("Access granted.\n");
  return 0;
}