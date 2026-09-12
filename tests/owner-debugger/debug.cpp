// SPDX-License-Identifier: Apache-2.0
#include <iostream>
#include <unistd.h>

struct Counter { int value; };

__attribute__((noinline)) int add(Counter counter, int amount) {
    int sum = counter.value + amount;
    return sum;
}

int main() {
    Counter counter{19};
    int result = add(counter, 23);
    std::cout << "DEBUG_CXX uid=" << getuid() << " value=" << result << '\n';
    return result != 42;
}
