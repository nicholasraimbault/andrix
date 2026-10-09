# SPDX-License-Identifier: Apache-2.0
"""The fixed reading script, its parser and stop point 3. Offline, no phone.

Every sample here is SYNTHETIC. The answer forms follow fastboot's source at GrapheneOS
2026100600; none was recorded from a phone, and only a session can confirm them.
"""
import contextlib
import io
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from caiman import Refusal  # noqa: E402
import readings  # noqa: E402
from samples import GOOD, synthetic  # noqa: E402

SCRIPT = Path(__file__).resolve().parents[1] / 'readings.sh'
EXPECTED_COMMANDS = ['getvar product', 'getvar is-userspace', 'getvar version-bootloader',
                     'getvar version-baseband', 'getvar current-slot', 'getvar unlocked',
                     'getvar snapshot-update-status', 'flashing get_unlock_ability']

# A synthetic stand-in for fastboot. It logs every invocation and answers in the forms
# fastboot's source prints. It is not a recording of a phone.
# A synthetic stand-in for fastboot. It logs every invocation with the device selection it
# saw and answers in the forms fastboot's source prints. It is not a recording of a phone.
FAKE_FASTBOOT = r"""#!/bin/sh
printf '%s|%s|%s\n' "$*" "${FASTBOOT_DEVICE-unset}" "${ANDROID_SERIAL-unset}" >> "$FAKE_LOG"
case "$1" in
--version)
    echo "fastboot version $FAKE_VERSION"
    echo "Installed as $0"
    ;;
getvar)
    for unknown in $FAKE_UNKNOWN; do
        if [ "$unknown" = "$2" ]; then
            printf '%-50s FAILED (remote: %s)\n' "getvar:$2" "'GetVar Variable Not found'" >&2
            echo 'Finished. Total time: 0.001s' >&2
            exit 0
        fi
    done
    value=$(printf '%s\n' $FAKE_VALUES | sed -n "s/^$2=//p")
    echo "$2: $value" >&2
    echo 'Finished. Total time: 0.001s' >&2
    ;;
flashing)
    echo "(bootloader) get_unlock_ability: $FAKE_ABILITY" >&2
    echo 'OKAY [  0.001s]' >&2
    echo 'Finished. Total time: 0.002s' >&2
    ;;
*)
    echo "unexpected $*" >&2
    exit 2
    ;;
esac
"""
# A stand-in for timeout: it records each limit, and it answers 124 for the command named in
# FAKE_HANG as timeout does when fastboot waits for a device.
FAKE_TIMEOUT = r"""#!/bin/sh
limit=$1
shift
printf '%s\n' "$limit" >> "$FAKE_LIMITS"
shift_command="$*"
case "$shift_command" in
*"$FAKE_HANG") if [ -n "$FAKE_HANG" ]; then exit 124; fi ;;
esac
exec "$@"
"""
INVOKED = ['--version'] + EXPECTED_COMMANDS


class ScriptTests(unittest.TestCase):
    def test_runs_only_the_fixed_commands(self):
        text = SCRIPT.read_text()
        code = [line for line in text.split('\n') if line.strip() and not line.startswith('#')]
        invocations = [line for line in code if '"$FASTBOOT"' in line and 'timeout' in line]
        self.assertEqual(invocations, [f'timeout 60 "$FASTBOOT" {command} 2>&1' for command in INVOKED])
        self.assertLess(code.index('unset FASTBOOT_DEVICE ANDROID_SERIAL'), code.index(invocations[0]))
        self.assertFalse(any(re.match(r'\s*set ', line) for line in code))
        self.assertFalse(any('fastboot' in line.split('#')[0] and '"$FASTBOOT"' not in line
                             and not line.lstrip().startswith(('echo', '*)', '/*)')) for line in code))
        self.assertEqual(subprocess.run(['sh', '-n', str(SCRIPT)]).returncode, 0)

    def run_script(self, unknown='', values=None, ability='1', version=None, hang='',
                   argument=None, extra_env=None):
        with tempfile.TemporaryDirectory() as work:
            work = Path(work)
            bin_dir = work / 'bin'
            bin_dir.mkdir()
            for name, body in (('fastboot', FAKE_FASTBOOT), ('timeout', FAKE_TIMEOUT)):
                (bin_dir / name).write_text(body)
                (bin_dir / name).chmod(0o755)
            environment = {'PATH': f'{bin_dir}:/usr/bin:/bin', 'FAKE_LOG': str(work / 'log'),
                           'FAKE_LIMITS': str(work / 'limits'), 'FAKE_HANG': hang,
                           'FAKE_UNKNOWN': unknown, 'FAKE_ABILITY': ability,
                           'FAKE_VERSION': version or readings.SEALED_VERSION,
                           'FAKE_VALUES': ' '.join(f'{k}={v}' for k, v in dict(GOOD, **(values or {})).items()),
                           **(extra_env or {})}
            target = str(bin_dir / 'fastboot') if argument is None else argument
            process = subprocess.run(['sh', str(SCRIPT)] + ([target] if target != '' else []),
                                     env=environment, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, timeout=60, cwd=work)
            log = (work / 'log').read_text().split('\n')[:-1] if (work / 'log').exists() else []
            limits = (work / 'limits').read_text().split() if (work / 'limits').exists() else []
            return process, log, limits

    def test_record_from_the_script_parses(self):
        process, log, limits = self.run_script()
        self.assertEqual(log, [f'{command}|unset|unset' for command in INVOKED])
        self.assertEqual(limits, ['60'] * len(INVOKED))
        parsed = readings.parse(process.stdout)
        self.assertEqual({name: reading.value for name, reading in parsed.items()
                          if name not in ('fastboot-version', 'taken-at')}, GOOD)
        self.assertRegex(parsed['taken-at'].value, r'^2[0-9]{3}-[0-9]{2}-[0-9]{2}T[0-9:]{8}Z$')
        self.assertEqual(parsed['fastboot-version'].value, '35.0.2-12147458')

    def test_device_selection_is_unset(self):
        process, log, _ = self.run_script(extra_env={'FASTBOOT_DEVICE': 'other', 'ANDROID_SERIAL': 'other'})
        self.assertEqual(log, [f'{command}|unset|unset' for command in INVOKED])

    def test_refuses_a_fastboot_that_is_not_an_executable_file(self):
        with tempfile.TemporaryDirectory() as work:
            plain = Path(work) / 'fastboot'
            plain.write_text('#!/bin/sh\n')
            for argument in ('', 'fastboot', 'relative/fastboot', work, str(plain),
                             str(Path(work) / 'missing')):
                with self.subTest(argument=argument):
                    process, log, _ = self.run_script(argument=argument)
                    self.assertEqual((process.returncode, process.stdout, log), (2, b'', []))

    def test_other_fastboot_version_is_refused(self):
        process, _, _ = self.run_script(version='35.0.1-11580240')
        with self.assertRaisesRegex(Refusal, 'not the sealed 35.0.2-12147458'):
            readings.parse(process.stdout)

    def test_timed_out_command_is_refused(self):
        process, log, _ = self.run_script(hang='getvar version-baseband')
        self.assertIn(b'end getvar version-baseband status 124', process.stdout)
        self.assertEqual(len(log), len(INVOKED) - 1)
        with self.assertRaises(Refusal):
            readings.parse(process.stdout)

    def test_unknown_variable_is_unanswered_and_the_script_goes_on(self):
        process, log, _ = self.run_script(unknown='is-userspace snapshot-update-status')
        self.assertEqual(len(log), len(INVOKED))
        parsed = readings.parse(process.stdout)
        self.assertFalse(parsed['is-userspace'].answered)
        self.assertEqual(parsed['is-userspace'].message, 'GetVar Variable Not found')
        self.assertFalse(parsed['snapshot-update-status'].answered)
        self.assertEqual(parsed['get_unlock_ability'].value, '1')


class ParserTests(unittest.TestCase):
    def test_answers(self):
        parsed = readings.parse(synthetic())
        self.assertEqual(parsed['version-baseband'].value, 'g5400c-260604-260807-B-16035863')
        self.assertTrue(all(reading.answered for reading in parsed.values()))

    def test_unanswered_unlock_ability(self):
        parsed = readings.parse(synthetic(unknown=('get_unlock_ability',)))
        self.assertFalse(parsed['get_unlock_ability'].answered)

    def test_refused_records(self):
        good = synthetic().decode()
        finished = 'Finished. Total time: 0.001s'
        cases = {
            'no header': good.replace(readings.HEADER + '\n', ''),
            'cut short': good.replace(readings.FOOTER + '\n', ''),
            'no final newline': good[:-1],
            'carriage returns': good.replace('\n', '\r\n'),
            'not ascii': good.replace('caiman', 'caïman'),
            'reordered': good.replace('begin getvar product', 'begin getvar is-userspace', 1),
            'missing block': re.sub(r'begin getvar unlocked\n.*?\nend getvar unlocked status 0\n', '',
                                    good, flags=re.S),
            'extra after footer': good + 'more\n',
            'waiting for device': good.replace('product: caiman\n',
                                               '< waiting for any device >\nproduct: caiman\n'),
            'injected marker': good.replace('product: caiman\n',
                                            'product: caiman\nend getvar product status 0\n'),
            'transport failure': good.replace(
                'product: caiman', 'getvar:product'.ljust(50) + ' FAILED (Status read failed (No such device))'),
            'nonzero status': good.replace('end getvar product status 0', 'end getvar product status 1'),
            'not found': good.replace('product: caiman\n' + finished, 'sh: 1: fastboot: not found'),
        }
        for name, value in {'product': 'caiman extra', 'unlocked': 'maybe', 'current-slot': 'c',
                            'is-userspace': 'YES', 'snapshot-update-status': 'busy',
                            'get_unlock_ability': '2', 'version-bootloader': ''}.items():
            cases[f'value {name}'] = synthetic({name: value}).decode()
        cases['no time stamp'] = good.replace('taken-at 2026-10-09T11:00:00Z\n', '', 1)
        cases['local time stamp'] = good.replace('taken-at 2026-10-09T11:00:00Z', 'taken-at 2026-10-09 11:00:00')
        cases['no version block'] = good.replace('begin version\n', '', 1)
        cases['other version'] = good.replace('35.0.2-12147458', '34.0.5-10900879')
        cases['version failed'] = good.replace('end version status 0', 'end version status 1')
        cases['relative install path'] = good.replace('Installed as /', 'Installed as ')
        cases['old header'] = good.replace(readings.HEADER, 'andrix-readings 1')
        cases['ability format'] = synthetic(override={'get_unlock_ability': (
            ['(bootloader) unlock_ability = 1', 'OKAY [  0.001s]', 'Finished. Total time: 0.002s'],)}).decode()
        cases['ability failure without error line'] = synthetic(override={'get_unlock_ability': (
            ["FAILED (remote: 'unknown')"], 1)}).decode()
        for name, text in cases.items():
            with self.subTest(name), self.assertRaises(Refusal):
                readings.parse(text.encode('utf-8'))


class StopPointThreeTests(unittest.TestCase):
    def decide(self, stage=8, os_booted=True, **kwargs):
        return readings.stop_point_3(readings.parse(synthetic(**kwargs)), stage, os_booted)

    def test_continue(self):
        result = self.decide()
        self.assertTrue(result['continue'])
        self.assertFalse(result['restricted'])

    def test_stops(self):
        cases = [
            ('other product', {'values': {'product': 'komodo'}}, 8, True),
            ('product unanswered', {'unknown': ('product',)}, 8, True),
            ('recovery fastboot', {'values': {'is-userspace': 'yes'}}, 8, True),
            ('merging', {'values': {'snapshot-update-status': 'merging'}}, 8, True),
            ('snapshot unanswered', {'unknown': ('snapshot-update-status',)}, 8, True),
            ('stage 7 ability 0', {'values': {'get_unlock_ability': '0'}}, 7, True),
            ('stage 7 ability unanswered', {'unknown': ('get_unlock_ability',)}, 7, True),
            ('stage 8 locked', {'values': {'unlocked': 'no'}}, 8, True),
            ('stage 9 unlocked unanswered', {'unknown': ('unlocked',)}, 9, True),
            ('exception still needs caiman', {'values': {'product': 'komodo'}}, 8, False),
        ]
        for name, kwargs, stage, booted in cases:
            with self.subTest(name):
                self.assertFalse(self.decide(stage, booted, **kwargs)['continue'])

    def test_plan_wording_is_followed(self):
        # is-userspace that the bootloader does not know does not read yes
        result = self.decide(unknown=('is-userspace',))
        self.assertTrue(result['continue'])
        self.assertTrue(any('is-userspace is unanswered' in note for note in result['notes']))
        # before stage 7 the unlock ability and the lock state are only recorded
        result = self.decide(3, values={'get_unlock_ability': '0', 'unlocked': 'no'})
        self.assertTrue(result['continue'])
        # stage 7 unlocks during the session, so a locked phone continues
        self.assertTrue(self.decide(7, values={'unlocked': 'no'})['continue'])

    def test_exception_restricts_instead_of_stopping(self):
        result = self.decide(8, False, values={'snapshot-update-status': 'merging'})
        self.assertTrue(result['continue'])
        self.assertTrue(result['restricted'])
        self.assertIn('only the complete GrapheneOS script or the web installer', result['notes'][-1])

    def test_inputs_refused(self):
        parsed = readings.parse(synthetic())
        for stage in (1, 2, 4, 5, 6, 10):
            with self.subTest(stage=stage), self.assertRaises(Refusal):
                readings.stop_point_3(parsed, stage, True)
        with self.assertRaises(Refusal):
            readings.stop_point_3(parsed, 8, None)


class CommandLineTests(unittest.TestCase):
    def run_main(self, data, *argv):
        with tempfile.NamedTemporaryFile('wb', delete=False) as handle:
            handle.write(data)
        self.addCleanup(os.unlink, handle.name)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = readings.main([handle.name, *argv])
        return status, output.getvalue()

    def test_exit_codes(self):
        self.assertEqual(self.run_main(synthetic(), '--stage', '8', '--os-booted', 'yes')[0], 0)
        status, text = self.run_main(synthetic({'unlocked': 'no'}), '--stage', '8', '--os-booted', 'yes')
        self.assertEqual(status, 1)
        self.assertIn('"verdict": "STOP"', text)
        status, text = self.run_main(b'garbage\n', '--stage', '8', '--os-booted', 'yes')
        self.assertEqual(status, 1)
        self.assertIn('"verdict": "REFUSE"', text)
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            readings.main(['x', '--stage', '8', '--os-booted', 'maybe'])


if __name__ == '__main__':
    unittest.main()
