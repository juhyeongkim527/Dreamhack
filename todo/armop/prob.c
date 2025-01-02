// aarch64-linux-gnu-gcc -O1 -fno-stack-protector -fno-pie -o prob prob.c -static
#include <stdio.h>

void run()
{
    char input[0x10];
    printf("input: ");
    scanf("%s", input);
}

int main()
{
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);
    system("echo 'exploit aarch64!\n'");
    run();
}