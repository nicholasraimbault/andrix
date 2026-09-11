// SPDX-License-Identifier: Apache-2.0
#include "stats.h"
#include <cmath>
#include <stdexcept>

Summary summarize(const std::vector<double>& values) {
    if (values.empty()) throw std::invalid_argument("empty input");
    double sum = 0, squares = 0;
    for (double value : values) {
        sum += value;
        squares += value * value;
    }
    if (!std::isfinite(sum) || !std::isfinite(squares))
        throw std::overflow_error("input magnitude too large");
    return {sum / values.size(), std::sqrt(squares / values.size())};
}
