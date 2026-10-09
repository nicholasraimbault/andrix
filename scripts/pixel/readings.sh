#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# The fixed readings of stop point 2 in plans/2026-10-09-caiman-workshop-phone.md.
#
#   sh scripts/pixel/readings.sh /absolute/path/to/sealed/platform-tools/fastboot > readings.txt
#
# Run it only on the bootloader screen that shows "Fastboot Mode". Its only argument is the
# sealed platform tools' fastboot, which must be an executable file named by an absolute path.
# It first records that fastboot's version, which contacts no phone. Then it runs exactly these
# fastboot commands, in this order, and no other command reaches the phone:
#
#   fastboot getvar product
#   fastboot getvar is-userspace
#   fastboot getvar version-bootloader
#   fastboot getvar version-baseband
#   fastboot getvar current-slot
#   fastboot getvar unlocked
#   fastboot getvar snapshot-update-status
#   fastboot flashing get_unlock_ability
#
# It prints one record on standard output, stamped with the UTC time, and writes no file. fastboot obeys FASTBOOT_DEVICE
# and ANDROID_SERIAL, so both are unset. fastboot waits for a device without end, so each
# command gets at most 60 seconds. A variable the bootloader does not know fails that one
# reading; the record keeps fastboot's answer and the script goes on, so there is no "set -e".
# scripts/pixel/readings.py reads the record.
#
# The answer formats come from fastboot's source, not from a phone. They stay unconfirmed
# until a session records them, and readings.py refuses any line it does not expect.

if [ "$#" -ne 1 ]; then
    echo 'readings.sh: give the absolute path of the sealed fastboot' >&2
    exit 2
fi
FASTBOOT=$1
case "$FASTBOOT" in
/*) ;;
*)
    echo 'readings.sh: the fastboot path must be absolute' >&2
    exit 2
    ;;
esac
if [ ! -f "$FASTBOOT" ] || [ ! -x "$FASTBOOT" ]; then
    echo 'readings.sh: the fastboot path is not an executable file' >&2
    exit 2
fi
unset FASTBOOT_DEVICE ANDROID_SERIAL

echo 'andrix-readings 3'
echo "taken-at $(date -u +%Y-%m-%dT%H:%M:%SZ)"

echo 'begin version'
timeout 60 "$FASTBOOT" --version 2>&1
echo "end version status $?"

echo 'begin getvar product'
timeout 60 "$FASTBOOT" getvar product 2>&1
echo "end getvar product status $?"

echo 'begin getvar is-userspace'
timeout 60 "$FASTBOOT" getvar is-userspace 2>&1
echo "end getvar is-userspace status $?"

echo 'begin getvar version-bootloader'
timeout 60 "$FASTBOOT" getvar version-bootloader 2>&1
echo "end getvar version-bootloader status $?"

echo 'begin getvar version-baseband'
timeout 60 "$FASTBOOT" getvar version-baseband 2>&1
echo "end getvar version-baseband status $?"

echo 'begin getvar current-slot'
timeout 60 "$FASTBOOT" getvar current-slot 2>&1
echo "end getvar current-slot status $?"

echo 'begin getvar unlocked'
timeout 60 "$FASTBOOT" getvar unlocked 2>&1
echo "end getvar unlocked status $?"

echo 'begin getvar snapshot-update-status'
timeout 60 "$FASTBOOT" getvar snapshot-update-status 2>&1
echo "end getvar snapshot-update-status status $?"

echo 'begin flashing get_unlock_ability'
timeout 60 "$FASTBOOT" flashing get_unlock_ability 2>&1
echo "end flashing get_unlock_ability status $?"

echo 'end-of-readings'
