// SPDX-License-Identifier: Apache-2.0
#include "stats.h"
#include <exception>
#include <iostream>

int main(int argc, char** argv) {
    try {
        auto values = parse(argc, argv);
        auto result = summarize(values);
        std::cout << revision << " count=" << values.size()
                  << " mean=" << result.mean << " rms=" << result.rms << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "error: " << error.what() << '\n';
        return 2;
    }
}
