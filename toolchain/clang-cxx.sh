#!/system/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Ordinary owner command, not an Android app launcher or privilege transition.
exec /usr/bin/clang --driver-mode=g++ --config=/usr/etc/andrix/cxx.cfg "$@"
