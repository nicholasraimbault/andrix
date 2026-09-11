// SPDX-License-Identifier: Apache-2.0
#include "stats.h"
#include <cmath>
#include <stdexcept>
#include <string>

std::vector<double> parse(int argc, char** argv) {
    if (argc < 2) throw std::invalid_argument("no numbers");
    std::vector<double> values;
    for (int i = 1; i < argc; ++i) {
        std::string text(argv[i]);
        std::size_t used = 0;
        double value = std::stod(text, &used);
        if (used != text.size() || !std::isfinite(value))
            throw std::invalid_argument("not a finite number");
        values.push_back(value);
    }
    return values;
}
