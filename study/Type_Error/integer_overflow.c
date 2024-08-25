// Name: integer_overflow.c
// Compile: gcc -o integer_overflow integer_overflow.c -m32

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int main()
{
    unsigned int size;
    scanf("%u", &size);

    char *buf = (char *)malloc(size + 1);
    unsigned int read_size = read(0, buf, size);

    buf[read_size] = 0;
    return 0;
}