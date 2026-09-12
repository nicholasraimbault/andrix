// SPDX-License-Identifier: Apache-2.0
#include <stdio.h>
#include <unistd.h>

__attribute__((noinline)) int add(int a, int b) {
    int sum = a + b;
    return sum;
}

int main(void) {
    int result = add(19, 23);
    printf("DEBUG_C uid=%u value=%d\n", (unsigned)getuid(), result);
    return result != 42;
}
