# SPDX-License-Identifier: Apache-2.0
# Cross-build a native Android/Bionic program from Linux. Like LLVM's upstream
# cmake/platforms/Android.cmake, use the Linux platform plus ANDROID, but explicitly
# select the modern AArch64/API37 ABI and a reviewed complete sysroot. No fake NDK
# release metadata or host headers/libraries are substituted.
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)
set(ANDROID TRUE CACHE BOOL "Android/Bionic target" FORCE)
list(APPEND CMAKE_TRY_COMPILE_PLATFORM_VARIABLES ANDRIX_BOOTSTRAP ANDRIX_SDK)

foreach(required ANDRIX_BOOTSTRAP ANDRIX_SDK)
  if(NOT DEFINED ${required} OR NOT IS_DIRECTORY "${${required}}")
    message(FATAL_ERROR "${required} must name a reviewed input directory")
  endif()
endforeach()
set(CMAKE_C_COMPILER "${ANDRIX_BOOTSTRAP}/bin/clang")
set(CMAKE_CXX_COMPILER "${ANDRIX_BOOTSTRAP}/bin/clang++")
set(CMAKE_C_COMPILER_TARGET aarch64-linux-android37)
set(CMAKE_CXX_COMPILER_TARGET aarch64-linux-android37)
set(CMAKE_ASM_COMPILER_TARGET aarch64-linux-android37)
set(CMAKE_AR "${ANDRIX_BOOTSTRAP}/bin/llvm-ar")
set(CMAKE_RANLIB "${ANDRIX_BOOTSTRAP}/bin/llvm-ranlib")
set(CMAKE_STRIP "${ANDRIX_BOOTSTRAP}/bin/llvm-strip")
set(CMAKE_SYSROOT "${ANDRIX_SDK}/sysroot")
set(CMAKE_FIND_ROOT_PATH "${ANDRIX_SDK}/sysroot")
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

set(ANDROID_HARDENING "-fPIC -fstack-protector-strong -D_FORTIFY_SOURCE=2 -ftrivial-auto-var-init=zero -mbranch-protection=standard -fvisibility=hidden -flto=thin -fsanitize=cfi-icall")
set(CMAKE_C_FLAGS_INIT "${ANDROID_HARDENING}")
set(CMAKE_CXX_FLAGS_INIT "${ANDROID_HARDENING} -nostdinc++ -isystem ${ANDRIX_SDK}/cxx/target -isystem ${ANDRIX_SDK}/cxx/include -nostdlib++")
# Mirror the NDK shared-STL dependency mapping, not host/platform libc++ or an
# assumed libc++.so linker script. The driver already adds the target libunwind.
set(CMAKE_CXX_STANDARD_LIBRARIES "-L${ANDRIX_SDK}/cxx/lib -lc++_shared -lm")
set(ANDROID_LINK_HARDENING "-fuse-ld=lld -Wl,-z,now -Wl,-z,relro -Wl,-z,noexecstack -Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384 -Wl,--exclude-libs,libunwind.a")
set(CMAKE_EXE_LINKER_FLAGS_INIT "${ANDROID_LINK_HARDENING} -pie")
set(CMAKE_SHARED_LINKER_FLAGS_INIT "${ANDROID_LINK_HARDENING}")
set(CMAKE_INSTALL_RPATH "$ORIGIN/../lib64")
set(CMAKE_BUILD_WITH_INSTALL_RPATH ON)
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH OFF)
# Zlib is an NDK API. Other optional dependencies are disabled by the build
# profile rather than accidentally discovered on the GNU/Linux host.
set(ZLIB_INCLUDE_DIR "${ANDRIX_SDK}/sysroot/usr/include" CACHE PATH "Target zlib headers")
set(ZLIB_LIBRARY "${ANDRIX_SDK}/sysroot/usr/lib/aarch64-linux-android/37/libz.so" CACHE FILEPATH "Target zlib stub")
