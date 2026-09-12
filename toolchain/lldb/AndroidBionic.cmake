# SPDX-License-Identifier: Apache-2.0
# LLDB-specific profile. Keep the qualified compiler profile unchanged.
# Use the explicitly targeted LLVM-style Linux+ANDROID cross toolchain; the
# accompanying LLDB source-selection adaptation includes HostInfoAndroid.cpp.
# No fabricated NDK metadata or undefined-symbol allowance.
include("${CMAKE_CURRENT_LIST_DIR}/../AndroidBionic.cmake")
string(APPEND CMAKE_SHARED_LINKER_FLAGS_INIT " -Wl,--no-undefined")
string(APPEND CMAKE_EXE_LINKER_FLAGS_INIT " -Wl,--no-undefined")
