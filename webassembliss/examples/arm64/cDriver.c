#include <stdio.h>
#include <stdlib.h>

extern int _exampleRoutine(int x0, int x1, int x2, int x3);

int main () {
    printf("Hello from C-land!\n");
    printf("Return value: %d\n", _exampleRoutine(1, 20, 300, 4000));
    exit(0);
}
