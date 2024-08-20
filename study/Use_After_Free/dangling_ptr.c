// Name: dangling_ptr.c
// Compile: gcc -o dangling_ptr dangling_ptr.c
#include <stdio.h>
#include <stdlib.h>

int main()
{
    int *ptr = NULL;
    int idx;

    while (1)
    {
        printf("> ");
        scanf("%d", &idx);
        switch (idx)
        {
        case 1:
            if (ptr)
            {
                printf("ptr : %p\n", ptr);
                printf("value : %d\n", *ptr);
                break;
            }
            ptr = malloc(256);
            break;
        case 2:
            if (!ptr)
            {
                printf("Empty\n");
            }
            free(ptr);
            break;
        default:
            break;
        }
    }
}