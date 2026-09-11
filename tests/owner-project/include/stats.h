// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <vector>

inline constexpr const char* revision = "v1";
struct Summary { double mean; double rms; };
std::vector<double> parse(int argc, char** argv);
Summary summarize(const std::vector<double>& values);
