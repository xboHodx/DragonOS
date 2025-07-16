#include <stdio.h>

int main()
{
    int res = syscall(2333);
    printf("%d", res);
    return 0;
}