// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstdio>
#include <string>
#include <string_view>

#include "wire.h"

namespace andrix::work_probe {

// The diagnostic tail contains bytes, not a C string or necessarily UTF-8.
// JSON code points 0..255 preserve those byte values, including embedded NULs.
// The count describes this retained window, not complete stream delivery.
inline bool SnapshotOutputJson(const Snapshot& state, std::string& encoded) {
  encoded.clear();
  if (state.output_size >= sizeof(state.output)) return false;
  encoded = "\"";
  for (unsigned char c : std::string_view(state.output, state.output_size)) {
    if (c == '"' || c == '\\') {
      encoded += '\\';
      encoded += c;
    } else if (c < 32 || c >= 127) {
      char escaped[7];
      snprintf(escaped, sizeof(escaped), "\\u%04x", c);
      encoded += escaped;
    } else {
      encoded += c;
    }
  }
  encoded += '"';
  return true;
}

}  // namespace andrix::work_probe
