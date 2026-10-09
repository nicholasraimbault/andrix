# SPDX-License-Identifier: Apache-2.0
"""Official caiman flash scripts, built from GrapheneOS's own sources for the tests.

render_legacy runs device/common/generate-factory-images-common.sh with bash, as
script/generate-release.sh sources it for caiman, with the file operations stubbed out.
capture applies FlashCapturer's conversion from system/core/fastboot/fastboot.cpp at
GrapheneOS 2026100600 to that legacy script, line for line, independently of the
reader's own template. No fastboot binary was built, so capture is a transcription of
the C++ and not its output.
"""
from pathlib import Path
import os
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
DEVICE_COMMON = HERE / 'fixtures' / 'device-common'

# Synthetic, modelled on AOSP's generated fastboot-info.txt for a board like caiman. The
# real file inside a GrapheneOS image zip has not been read.
FASTBOOT_INFO = """\
# fastboot-info for caiman
version 1
flash boot
flash init_boot
flash dtbo
flash vendor_kernel_boot
flash pvmfw
flash vendor_boot
flash --apply-vbmeta vbmeta
reboot fastboot
update-super
flash product
flash system
flash system_dlkm
flash system_ext
flash vendor
flash vendor_dlkm
if-wipe erase userdata
if-wipe erase metadata
"""
# BOARD_GOOGLE_DYNAMIC_PARTITIONS_PARTITION_LIST in adevtool's generated BoardConfig.mk
DYNAMIC = {'system', 'system_dlkm', 'system_ext', 'product', 'vendor', 'vendor_dlkm'}

# generate-release.sh: get_radio_image() and the variables it sets for caiman
HARNESS = r'''
rm() { :; }; unzip() { :; }; zip() { :; }; cp() { :; }
get_radio_image() {
    grep "require version-$1" OTA/android-info.txt | cut -d '=' -f 2 | tr '[:upper:]' '[:lower:]'
}
source "$COMMON/clear-factory-images-variables.sh"
BUILD=$BUILD_NUMBER
VERSION=$BUILD_NUMBER
DEVICE=caiman
PRODUCT=$DEVICE
BOOTLOADER=$(get_radio_image bootloader)
RADIO=$(get_radio_image baseband)
DISABLE_UART=true
DISABLE_FIPS=true
DISABLE_DPM=true
AVB_PKMD="keys/avb_pkmd.bin"
source "$COMMON/generate-factory-images-common.sh"
'''


def android_info(bootloader, baseband):
    return (f'require board=caiman\n\nrequire version-bootloader={bootloader}\n'
            f'require version-baseband={baseband}\nrequire partition-exists=vendor_kernel_boot\n')


def render_legacy(build, bootloader, baseband, common=DEVICE_COMMON):
    with tempfile.TemporaryDirectory() as work:
        work = Path(work)
        (work / 'OTA').mkdir()
        (work / 'OTA/android-info.txt').write_text(android_info(bootloader, baseband))
        environment = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'LC_ALL': 'C',
                       'COMMON': str(common), 'BUILD_NUMBER': build}
        subprocess.run(['bash', '--noprofile', '--norc', '-c', HARNESS], cwd=work,
                       env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=60, check=False)
        return (work / f'tmp/caiman-factory-{build}/flash-all.sh').read_bytes()


def capture(legacy, fastboot_info=FASTBOOT_INFO, splits=4, sparse_limit=0xf900000):
    """FlashCapturer::Run's flash-all.sh for this legacy script (fastboot.cpp 2807-3090)."""
    legacy = legacy.decode('ascii')
    sh = []

    def add_sh_line(text):            # FlashCapturer::AddShLine
        sh.append(text + '\n')

    def add_sh_bat_command(text):     # AddShBatCommand writes the line to the sh script
        sh.append(text + '\n')

    def add_comment(text):            # AddComment -> AddShBatComment -> AddShComment
        sh.append('# ' + text + '\n')

    def check_var(name, value):       # FlashCapturer::AddCheckVarCommand
        short = name.replace('_', '').replace('-', '')
        add_sh_line(short + '=$(fastboot getvar ' + name + ' 2>&1 | grep "' + name +
                    ':" | cut -d \' \' -f 2)\n' 'if ! [ $' + short + ' = "' + value + '" ]; then')
        if name == 'product':
            add_sh_line('  echo Error: this factory image is for ' + value +
                        ', but the name of connected device is $' + short)
        else:
            add_sh_line('  echo Error: unexpected value of ' + name + ' variable: expected ' +
                        value + ', got $' + short)
        add_sh_line('  exit 1\nfi')

    end = legacy.find('\n# PROLOG_END')
    assert end >= 0, 'no PROLOG_END'
    add_sh_line(legacy[:end])
    add_sh_line('echo Available devices:')            # AddShBatLine
    add_sh_bat_command('fastboot devices -l')
    check_var('product', 'caiman')                     # product name from image-caiman-*.zip
    check_var('slot-count', '2')
    # parse_flash_all_sh
    counter, set_a = 0, False
    for line in legacy.split('\n'):
        if not line.startswith('fastboot '):
            continue
        if ' update image-' in line:
            break
        tokens = [token for token in line.split(' ') if token]
        if tokens[1] == 'flash':
            other = tokens[2] == '--slot=other'
            if tokens[3 if other else 2] == 'bootloader':
                assert other
                counter += 1
            assert len(tokens) == (5 if other else 4)
            add_sh_bat_command(line)
        elif tokens[1] == '--set-active=other':
            assert len(tokens) == 2
            add_sh_bat_command(line)
        elif tokens[1] == 'reboot-bootloader':
            assert len(tokens) == 2
            add_sh_bat_command(line)
            add_sh_line('sleep 5')
            if counter == 2 and not set_a:
                add_comment('size of partition splits depends on this value')
                check_var('max-download-size', '0x%x' % sparse_limit)
                add_comment('layout of the super partition depends on the current slot, which '
                            'is hardcoded to slot A')
                add_sh_bat_command('fastboot --set-active=a')
                set_a = True
                check_var('current-slot', 'a')
        elif tokens[1] == 'erase':
            assert len(tokens) == 3
            add_sh_bat_command('fastboot erase ' + tokens[2])
        elif tokens[1] == 'snapshot-update':
            assert tokens[2:] == ['cancel']
            add_sh_bat_command(line)
        elif tokens[1] == 'oem':
            add_sh_bat_command(line)
        else:
            raise AssertionError('unknown flash-all command ' + line)
    assert counter == 2
    # FlashAllTool::Flash: CheckRequirements, CancelSnapshotIfNeeded, then the tasks
    sh.append('# this command only checks android-info.txt requirements, it does not perform '
              'an update\n')
    add_sh_bat_command('fastboot --disable-super-optimization --skip-reboot update android-info.zip')
    add_sh_bat_command('fastboot snapshot-update cancel')
    # ParseFastbootInfo with wants_wipe = true. OptimizedFlashSuperTask::Initialize removes
    # "reboot fastboot", "update-super" and the dynamic flashes, and appends itself last.
    for raw in fastboot_info.split('\n'):
        words = raw.split()
        if not words or words[0].startswith('#') or words[0] == 'version':
            continue
        if words[0] == 'if-wipe':
            words = words[1:]
        if words[0] == 'flash':
            partition = [word for word in words[1:] if not word.startswith('--')][0]
            if partition not in DYNAMIC:
                add_sh_bat_command(f'fastboot flash {partition} {partition}.img')
        elif words[0] == 'erase':
            add_sh_bat_command('fastboot erase ' + words[1])
        else:
            assert words in (['reboot', 'fastboot'], ['update-super']), words
    for number in range(1, splits + 1):           # AddSplitSparsePartition
        sh.append(f'echo Flashing super, {number}/{splits}\n')
        add_sh_bat_command(f'fastboot flash super super_{number}.img')
    return ''.join(sh).encode('ascii')
