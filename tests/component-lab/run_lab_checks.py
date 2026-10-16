#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Host checks of the component transaction lab bridge, with deliberate defects.

Source checks run first: the predictions agree with every suite's cases and the defect lists, every
defect's anchor is in its file exactly once, no build file names this directory, and no public file
here holds a private host path. The Python phase runs each broker suite in its own interpreter.

No compiler or JVM starts unless an actual cgroup bounds this process as the records runner requires
(2 GiB of memory, no swap, 2 CPUs, 256 tasks, no core dumps) and a JDK is on PATH; otherwise those
phases are NOT_RUN. `--allow-unguarded` runs them anyway for development and marks the report
UNGUARDED, never PASS. The Java phase compiles the deployment package with the bridge and its tests,
runs the bridge's suites, and compares the protocol goldens of both codecs byte for byte. The bridge
phase runs the end to end suite: the accepted coordinator through the bridge against the broker on a
simulated guest, one JVM per generation. The driver phase, given the pinned apksigner jar, the public
development platform key and the two built inputs, builds the lab driver against the jar and runs its
unit suite and its end to end suite with the real host signer. The defect phase copies this directory into a scratch tree,
applies one defect at a time, rebuilds when the defect is in Java, and runs the suites predicted to
catch it; each must fail at least its predicted cases. Every JVM has a capped heap, metaspace and
code cache, the serial collector and one client JIT compiler thread.

Host evidence only: a simulated guest, a fake adb server, a scripted host for the bridge suites and,
in the driver phase, the real host signer with the public development key; not Android."""
from pathlib import Path
import argparse
import ast
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
PREDICTIONS = HERE / 'predictions.json'
SUITES = ('test_lab_protocol', 'test_shell_transport', 'test_capture_ledger', 'test_lab_crossings', 'test_lab_broker',
          'test_lab_next')
BRIDGE_SUITE = 'test_lab_bridge'
# The lab driver's end to end suite: the real host signer over apksig, so it needs the pinned
# apksigner jar, the public development platform key and the two built signing inputs.
DRIVER_SUITE = 'test_lab_driver'
DRIVER_JAVA = 'driver/dev/andrix/lab/component/'
DRIVER_TESTS = 'driver-tests/dev/andrix/lab/component/'
DRIVER_JAVA_SUITES = ('DriverTest',)
APKSIG_ENGINE = 'owner/deployment/apksig/dev/andrix/server/deployment/ApksigEngine.java'
APKSIG_SERVICE = 'owner/deployment/apksig/META-INF/services/com.android.apksig.kms.KmsSignerEngineProvider'
PINNED_APKSIGNER_JAR = '6b96559764325d085a6bad6be109cc3053791d63826f84dc0e74032db136a196'
JAVA_SUITES = ('ProtocolTest', 'BridgeTest')
JAVA_PACKAGE = 'dev.andrix.lab.component'
JAVA_MAIN = 'java/dev/andrix/lab/component/'
JAVA_TESTS = 'javatests/dev/andrix/lab/component/'
DEPLOYMENT = 'owner/deployment/java/dev/andrix/server/deployment/'
JVM_LIMITS = ('-XX:+UseSerialGC', '-XX:TieredStopAtLevel=1', '-XX:CICompilerCount=1', '-XX:MaxMetaspaceSize=128m',
              '-XX:ReservedCodeCacheSize=48m')
# Host paths that never belong in public files, assembled so that this file does not hold them.
PRIVATE = re.compile('|'.join(re.escape(part) for part in ('/' + 'home/', '/' + 'srv/', '.local' + '/state',
                                                          'pi-' + 'harness', '/' + 'Users/')))

# Each defect: the file, its exact old and new text, and the suites run against it.
MUTANTS = {
    'eof-read-as-exit': ('shell_transport.py', "        self.problem = 'the stream ended before EXIT'\n"
                                               "        return 'eof-before-exit'\n",
                         "        self.exit_frame = 1\n        self.state = 'exited'\n        return 'exited'\n",
                         ('test_shell_transport',)),
    'second-exit-accepted': ('shell_transport.py',
                             "            if self.state == 'exited':\n                self._final('malformed', "
                             "'a second EXIT packet' if ident == ID_EXIT else 'a packet after EXIT')\n",
                             "            if self.state == 'exited' and ident != ID_EXIT:\n                "
                             "self._final('malformed', 'a packet after EXIT')\n", ('test_shell_transport',)),
    'exit-length-unchecked': ('shell_transport.py', '                if length != 1:\n',
                              '                if length == 0:\n', ('test_shell_transport',)),
    'stream-unbounded': ('shell_transport.py', '                if len(stream) + length > self.limits[ident]:\n',
                         '                if False:\n', ('test_shell_transport',)),
    'transport-failure-read-as-exit-1': ('shell_transport.py',
                                         "            transport, completion = failure, 'not-started'\n",
                                         "            transport, completion = failure, 'exited'\n"
                                         "            decoder.exit_frame = 1\n", ('test_shell_transport',)),
    'ledger-overwrites': ('capture_ledger.py', 'os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW',
                          'os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW', ('test_capture_ledger',)),
    'ledger-gap-accepted': ('capture_ledger.py', '        if number != len(entries) + 1:\n',
                            '        if number < len(entries) + 1:\n', ('test_capture_ledger',)),
    'ledger-incomplete-middle-accepted': ('capture_ledger.py',
                                          "        if not e.complete and e.number not in named and "
                                          "any(x.kind != 'quarantine' for x in entries[i + 1:]):\n",
                                          '        if False:\n', ('test_capture_ledger',)),
    'protocol-trailing-accepted': ('lab_protocol.py', "    if reader.at != reader.end:\n        _fail('trailing bytes "
                                                      "after the body')\n", '', ('test_lab_protocol',)),
    'protocol-session-by-id-alone': ('lab_protocol.py',
                                     "    if name in ('WRITE', 'COMMIT', 'ABANDON') and presence & BOUND_REFERENCE != "
                                     "BOUND_REFERENCE:\n", "    if False:\n", ('test_lab_protocol',)),
    'intent-after-launch': ('lab_broker.py', '        entry = self.ledger.begin_capture(intent)\n'
                                             '        # The final launch gate, once the intent is durable: a launch whose '
                                             'deadline has passed since\n'
                                             "        # the gate's clock reading (an activation grant that may have expired, "
                                             'or a bound) sends nothing.\n'
                                             '        if not_after_ns is not None and self._monotonic() >= not_after_ns:\n'
                                             "            self._not_sent(entry, command, 'the activation grant may have expired "
                                             "before the launch, or its bound passed')\n        try:\n            result = call()\n",
                            '        try:\n            result = call()\n'
                            '            entry = self.ledger.begin_capture(intent)\n', ('test_lab_broker',)),
    'fence-skipped': ('lab_broker.py', '        self._fence()\n        intent = dict(context, operation=operation, command=command, '
                                       'timeout_s=timeout,\n',
                      '        intent = dict(context, operation=operation, command=command, timeout_s=timeout,\n',
                      ('test_lab_broker',)),
    'stop-not-latched': ('lab_broker.py', '        if self.stopped is None:\n            self.stopped = reason\n',
                         '        if self.stopped is None:\n', ('test_lab_broker',)),
    'replay-allowed': ('lab_broker.py', "        if key in self.crossed:\n            return self._reply(m, 'REFUSED', "
                                        "reason='a crossing of one ledger entry is issued once')\n", '',
                       ('test_lab_broker',)),
    'dropped-reply-delivered': ('lab_broker.py', "            return self._reply(m, 'WITHHELD', record=number, "
                                                 "reason='admitted dropped reply')\n",
                                "            return self._reply(m, 'OK', record=number, frame=frame)\n",
                                ('test_lab_broker',)),
    'loss-before-launches': ('lab_broker.py', "            if cell is not None and cell['mode'] == 'loss-before':\n"
                                              "                fault = self.ledger.record('fault', {'cell': cell['cell'], "
                                              "'on': 'cross', 'crossing': number,\n",
                             "            if cell is not None and cell['mode'] == 'never':\n"
                             "                fault = self.ledger.record('fault', {'cell': cell['cell'], "
                             "'on': 'cross', 'crossing': number,\n", ('test_lab_broker',)),
    'cell-acts-again': ('lab_broker.py', "            if cell['on'] == on and cell['cell'] not in self.consumed and all(",
                        "            if cell['on'] == on and all(", ('test_lab_broker',)),
    'preflight-instance-ignored': ('lab_broker.py',
                                   "        if name in proto.FRAMEWORK_CROSSINGS and reading['instance'] != m['entry_instance']:\n",
                                   '        if False:\n', ('test_lab_broker',)),
    'reference-by-id-alone': ('lab_broker.py', '    if (both & proto.CREATED and created != c2 or both & proto.STAGE_DIR '
                                               'and stage != st2\n',
                              '    if False and (both & proto.CREATED and created != c2 or both & proto.STAGE_DIR '
                              'and stage != st2\n', ('test_lab_broker',)),
    'interrupted-read-as-not-launched': ('lab_broker.py',
                                         "            launched = 'unknown' if entry.state == 'interrupted' else False\n",
                                         '            launched = False\n', ('test_lab_broker',)),
    'drain-skipped': ('lab_broker.py', '            self._sleep((drain - self._wall()) / 1e9)\n', '            pass\n',
                      ('test_lab_broker',)),
    'lost-generation-left-running': ('lab_broker.py', "            self.processes.kill(g['pid'])\n",
                                     '            pass\n', ('test_lab_broker',)),
    'lost-read-as-quiet-1': ('lab_broker.py', "                raise readers.Unavailable('capture %d did not complete: "
                                              "%s' % (number, result.completion))\n",
                             "                return 1, '', ''\n", ('test_lab_broker',)),
    'shell2-not-required': ('lab_broker.py', '        if result.status == \'ok\' and shell_transport.FEATURE_SHELL2 in '
                                             'result.features:\n',
                            '        if result.status == \'ok\':\n', ('test_lab_broker',)),
    'second-member-after-halt': ('lab_broker.py', "            if at == 0 and cell is not None and cell['mode'] == "
                                                  "'loss-between-members':\n",
                                 "            if at == 1 and cell is not None and cell['mode'] == "
                                 "'loss-between-members':\n", ('test_lab_broker',)),

    'fence-only-before-the-feature-query': ('lab_broker.py',
        '        self._require_shell2(context, not_after_ns)\n        return self._record_command(operation, command, context, call, '
        'timeout, not_after_ns)\n\n    def _record_command(self, operation, command, context, call, timeout, '
        'not_after_ns=None):\n'
        '        # Every command, the feature query included, is fenced right before its intent: a fence that\n'
        '        # trips while an earlier command runs stops the next one.\n        self._fence()\n',
        '        self._fence()\n        self._require_shell2(context, not_after_ns)\n        return self._record_command(operation, '
        'command, context, call, timeout, not_after_ns)\n\n    def _record_command(self, operation, command, context, '
        'call, timeout, not_after_ns=None):\n',
        ('test_lab_broker',)),
    'drain-forgets-quarantined-captures': ('lab_broker.py', '        for entry in self.ledger.entries:\n'
                                           "            if entry.kind == 'capture' and entry.state == 'interrupted':\n",
                                           '        for entry in self.ledger.unquarantined():\n'
                                           "            if entry.kind == 'capture' and entry.state == 'interrupted':\n",
                                           ('test_lab_broker',)),
    'request-transfer-unbounded': ('lab_broker.py', '        return proto.read_frame(Bounded)\n',
                                   '        return proto.read_frame(rfile)\n', ('test_lab_broker',)),
    'reply-transfer-unbounded': ('lab_broker.py', '        if fileno is None:\n            view = memoryview(data)\n',
                                 '        if True:\n            view = memoryview(data)\n', ('test_lab_broker',)),
    'write-not-revalidated': ('lab_broker.py',
                              "            reading, _, why = self._gate('WRITE', m, context, 'revalidation before %s' % member)\n",
                              "            reading, _, why = {'elapsed': elapsed}, None, None\n", ('test_lab_broker',)),
    'grant-expiry-unchecked': ('lab_broker.py', '    if wall_ms < granted or wall_ms - granted >= window:\n',
                               '    if False:\n', ('test_lab_broker',)),
    'clock-read-before-the-confirmation': ('lab_broker.py',
        "        if name in ('WRITE', 'COMMIT', 'ABANDON'):\n"
        "            confirmed = self._confirm(m, context, ('OPEN',) if name != 'ABANDON' else LIVE)\n"
        "            if confirmed is not None:\n                return None, None, '%s: %s' % (purpose, confirmed)\n"
        '        # The clock is read last: no slow read comes between it and the launch.\n'
        '        started = self._monotonic()\n'
        '        clock = self._clock_group(dict(context, purpose=purpose), emitted=False)\n',
        '        started = self._monotonic()\n'
        '        clock = self._clock_group(dict(context, purpose=purpose), emitted=False)\n'
        "        if name in ('WRITE', 'COMMIT', 'ABANDON'):\n"
        "            confirmed = self._confirm(m, context, ('OPEN',) if name != 'ABANDON' else LIVE)\n"
        "            if confirmed is not None:\n                return None, None, '%s: %s' % (purpose, confirmed)\n",
        ('test_lab_broker', BRIDGE_SUITE)),
    'launch-deadline-unchecked': ('lab_broker.py',
                                  '        if not_after_ns is not None and self._monotonic() >= not_after_ns:\n',
                                  '        if False:\n', ('test_lab_broker',)),
    'deadline-from-the-gate-end': ('lab_broker.py',
                                   "            deadline = activation_deadline(reading['wall'], started, m['granted'], "
                                   "m['window'])\n",
                                   "            deadline = activation_deadline(reading['wall'], self._monotonic(), "
                                   "m['granted'], m['window'])\n", ('test_lab_broker',)),
    'launch-deadline-not-given-to-the-transport': ('lab_broker.py', '        gate = self._may_send(not_after_ns)\n',
                                                   '        gate = None\n', ('test_lab_broker',)),
    'reboot-deadline-not-given-to-the-transport': ('lab_broker.py', '            gate = self._may_send(deadline)\n',
                                                   '            gate = None\n', ('test_lab_broker',)),
    'transport-sends-past-the-launch-deadline': ('shell_transport.py',
                                                 '        if may_send is not None and not may_send():\n'
                                                 "            return sock, 'launch-deadline', 'not-launched', None, "
                                                 "'the launch deadline passed before the service request'\n",
                                                 '        if False:\n'
                                                 "            return sock, 'launch-deadline', 'not-launched', None, "
                                                 "'the launch deadline passed before the service request'\n",
                                                 ('test_shell_transport',)),
    'buffered-stream-accepted': ('lab_broker.py', "        if isinstance(stream, io.BufferedIOBase):\n"
                                                  "            raise BrokerError('a generation stream must be unbuffered')\n",
                                 '', ('test_lab_broker',)),
    'reap-unbounded': ('lab_broker.py', '            killed = True\n            try:\n'
                                        "                code = process.wait(timeout=self.limits['exit_grace_s'])\n",
                       '            killed = True\n            try:\n                code = process.wait()\n',
                       ('test_lab_broker',)),
    'target-read-once': ('lab_broker.py', '        if self._target is None:\n            return self.admission[\'target_scope\']\n',
                         '        if True:\n            return self.admission[\'target_scope\']\n', ('test_lab_broker',)),
    'sources-not-reverified': ('lab_broker.py', '            self._fence()\n            self._verify_sources()\n',
                               '            self._fence()\n', ('test_lab_broker',)),
    'partial-payload-dropped': ('shell_transport.py', '                stream += payload\n', '                pass\n',
                                ('test_shell_transport',)),
    'service-send-failure-read-as-not-launched': ('shell_transport.py',
                                                  "            return sock, failed.transport, 'unknown', None, 'the service "
                                                  "request: %s' % failed\n",
                                                  "            return sock, failed.transport, 'not-launched', None, 'the service "
                                                  "request: %s' % failed\n", ('test_shell_transport',)),
    'target-form-loosened': ('lab_target.py', "    return 'ESTABLISHED_EMPTY' if (code, stdout, stderr) == (0, FRESH_FORM, '') else 'UNKNOWN'\n",
                             "    return 'ESTABLISHED_EMPTY' if code == 0 and stdout.startswith('andrix-native-identities-v1\\n') "
                             "else 'UNKNOWN'\n", ('test_lab_broker',)),
    'target-not-read-at-the-gate': ('lab_broker.py', '            scope = self._target_scope(context)\n',
                                    "            scope = self.admission['target_scope']\n", ('test_lab_broker',)),
    'target-read-widens-the-admission': ('lab_broker.py', "            return read if admitted == 'ESTABLISHED_EMPTY' else admitted\n",
                                         '            return read\n', ('test_lab_broker',)),
    'restart-settle-skipped': ('lab_broker.py',
                               "        settled, settle, why = self._restart_settle(dict(context, purpose='lab-action-settle'), before)\n",
                               "        settled, settle, why = {'clock': 0, 'sessions': 0, 'instance': before[1] + 1}, {'polls': []}, None\n",
                               ('test_lab_broker',)),
    'restart-settle-other-boot-accepted': ('lab_broker.py', "            if clock.ok and clock.reading['boot'] != boot:\n"
                                           "                poll['ended_monotonic_ns'] = self._monotonic()\n"
                                           "                return None, record, 'a poll read another boot'\n", '',
                                           ('test_lab_broker',)),
    'restart-settle-listing-unchecked': ('lab_broker.py', '                if group.ok and _whole_listing(group.facts, later):\n',
                                         '                if group.ok:\n', ('test_lab_broker',)),
    'launch-fence-skipped': ('lab_broker.py', '            if name not in self._launches:\n', '            if False:\n',
                             ('test_lab_broker',)),
    'stored-records-unchecked': ('lab_broker.py', "            if label in ('ticket', 'plan') and digest != m[label + '_digest']:\n",
                                 '            if False:\n', ('test_lab_broker',)),
    'restart-limit-unchecked': ('lab_broker.py',
                                "        if refused is None and launched >= self.admission['lab_actions']['framework-restart']:\n",
                                '        if False:\n', ('test_lab_broker',)),
    'incomplete-listing-accepted': ('lab_broker.py', "    return (len(listings) == 1 and listings[0]['classification'] in COMPLETE_LISTINGS\n",
                                    '    return (len(listings) == 1\n', ('test_lab_broker',)),
    'restart-beside-unknown-commitment': ('lab_broker.py', "RESTART_BLOCKING = ('VERIFYING', 'LIVE_NOT_READY', 'READY')\n",
                                          "RESTART_BLOCKING = ('VERIFYING', 'READY')\n", ('test_lab_broker',)),
    'controller-read-during-generation': ('lab_broker.py', '        if self.open_generation is not None:\n'
                                          "            raise BrokerError('a controller read runs only between generations')\n", '',
                                          ('test_lab_broker',)),
    'diagnostic-of-any-name': ('lab_broker.py', '        if name not in DIAGNOSTICS:\n'
                               "            raise BrokerError('a diagnostic of no known name')\n", '', ('test_lab_broker',)),
    'retention-single-write': ('lab_broker.py', '            view = memoryview(data)\n            while view:\n'
                               '                written = os.write(fd, view)\n                if written <= 0:\n'
                               "                    raise BrokerError('a retained record could not be written whole')\n"
                               '                view = view[written:]\n', '            os.write(fd, data)\n', ('test_lab_broker',)),
    'settle-late-poll-accepted': ('lab_broker.py', "                    if poll['ended_monotonic_ns'] > deadline:\n"
                                  "                        return None, record, 'the settling poll ended after the %d s bound' "
                                  "% RESTART_SETTLE_S\n", '', ('test_lab_broker',)),
    'settle-sessions-after-the-bound': ('lab_broker.py',
                                        "            if clock.ok and clock.reading['instance'] > instance and self._monotonic() < deadline:\n",
                                        "            if clock.ok and clock.reading['instance'] > instance:\n", ('test_lab_broker',)),
    'bound-launch-gate-missing': ('lab_broker.py', "                                             int(self.limits['read_stderr_max']), not_after_ns=deadline_ns,\n",
                                  "                                             int(self.limits['read_stderr_max']),\n", ('test_lab_broker',)),
    'bound-fraction-started': ('lab_broker.py', '                if remaining < BOUND_COMMAND_MIN_S:\n', '                if remaining <= 0:\n',
                               ('test_lab_broker',)),
    'bound-timeout-fixed-at-intent': ('lab_broker.py', '            allowed = timeout if bound_ns is None else min(timeout, max(0.0, (bound_ns - '
                                      'self._monotonic()) / 1_000_000_000))\n'
                                      '            return self.transport.shell(command, allowed, stdout_max, stderr_max, **extra)\n',
                                      '            allowed = timeout\n'
                                      '            return self.transport.shell(command, allowed, stdout_max, stderr_max, **extra)\n',
                                      ('test_lab_broker',)),
    'records-root-unsynced': ('lab_broker.py', '        # earlier call could not finish is never skipped.\n        _sync_directory(self.root)\n',
                              '        # earlier call could not finish is never skipped.\n', ('test_lab_broker',)),
    'existing-record-unsynced': ('lab_broker.py', '            _sync_directory(directory)\n            return\n', '            return\n',
                                 ('test_lab_broker',)),
    'broker-name-unsynced-when-made': ('lab_broker.py', '        _sync_directory(root.parent)\n', '', ('test_lab_broker',)),
    'broker-name-unsynced-at-opening': ('lab_broker.py', '            _sync_directory(self.root.parent)\n', '', ('test_lab_broker',)),
    'feature-query-unbounded': ('lab_broker.py', '        self._require_shell2(context, not_after_ns)\n',
                                '        self._require_shell2(context)\n', ('test_lab_broker',)),
    'feature-query-timeout-uncut': ('lab_broker.py', '            return self.transport.features(allowed, **extra)\n',
                                    '            return self.transport.features(timeout, **extra)\n', ('test_lab_broker',)),
    'feature-gate-not-passed': ('lab_broker.py', '            return self.transport.features(allowed, **extra)\n',
                                '            return self.transport.features(allowed)\n', ('test_lab_broker',)),
    'unreadable-features-unlisted': ('lab_broker.py', "        error = _NotLaunched('the device features could not be read: %s' % result.status)\n"
                                                      '        error.capture, error.command = number, command\n        raise error\n',
                                     "        raise _NotLaunched('the device features could not be read: %s' % result.status)\n",
                                     ('test_lab_broker',)),
    'ledger-entries-unsynced-at-opening': ('capture_ledger.py', '                ledger._sync_file(entry.path / name)\n'
                                                                '            ledger._sync_dir(entry.path)\n',
                                           '                ledger._sync_file(entry.path / name)\n',
                                           ('test_capture_ledger', 'test_lab_broker')),
    'ledger-files-unsynced-at-opening': ('capture_ledger.py', '        ledger._sync_file(ledger.root / MARKER_NAME)\n'
                                                              '        for entry in ledger.entries:\n'
                                                              '            for name in sorted(os.listdir(entry.path)):\n'
                                                              '                ledger._sync_file(entry.path / name)\n',
                                         '        for entry in ledger.entries:\n', ('test_capture_ledger', 'test_lab_broker')),
    'ledger-write-failure-not-latched': ('capture_ledger.py', '        except OSError as error:\n            self._failed = error\n'
                                                              '            raise\n', '        except OSError:\n            raise\n',
                                         ('test_capture_ledger',)),
    'features-send-ungated': ('shell_transport.py', '            if may_send is not None and not may_send():\n'
                                                    "                return FeaturesResult('launch-deadline', (), None, "
                                                    "'the launch deadline passed before the request')\n", '',
                              ('test_shell_transport',)),
    'host-begin-untimed': ('lab_broker.py', "                  'request': m['request'], 'generation': state['generation'], 'wall_ns': self._wall(),\n"
                                            "                  'monotonic_ns': self._monotonic()}\n",
                           "                  'request': m['request'], 'generation': state['generation']}\n", ('test_lab_broker',)),
    'process-ended-untimed': ('lab_broker.py', "                                        'reason': 'the generation ended during the host call',\n"
                                               "                                        'wall_ns': self._wall(), 'monotonic_ns': self._monotonic()})\n",
                              "                                        'reason': 'the generation ended during the host call'})\n",
                              ('test_lab_broker',)),
    'restart-not-admitted': ('lab_broker.py', "        if 'framework-restart' not in self.admission.get('lab_actions', {}):\n",
                             '        if False:\n', ('test_lab_broker',)),
    'restart-during-generation': ('lab_broker.py', '        if self.open_generation is not None:\n'
                                  "            raise BrokerError('a lab action runs only between generations')\n", '',
                                  ('test_lab_broker',)),
    'restart-beside-committed-session': ('lab_broker.py',
                                         "        if any(f['kind'] == 'SESSION' and f['classification'] in RESTART_BLOCKING "
                                         "for f in group.facts):\n", '        if False:\n', ('test_lab_broker',)),
    # The next campaign profile: receipts past the clock guard, health compositions, typed actions.
    'receipt-read-time-substituted': ('lab_broker.py',
        "                    'elapsed': proof['proven_elapsed'], 'wall': proof['wall'], 'classification': 'FULL_SCREEN',\n",
        "                    'elapsed': brackets['end']['elapsed'], 'wall': proof['wall'], 'classification': 'FULL_SCREEN',\n",
        ('test_lab_next',)),
    'receipt-unqualified-visibility': ('lab_broker.py',
        "            if (group['qualified'] and group['issue'] == issue['number'] and group['user'] == row['user']\n",
        "            if (group['issue'] == issue['number'] and group['user'] == row['user']\n",
        ('test_lab_next',)),
    'receipt-later-visibility': ('lab_broker.py',
        "        for group in self.visibility.get((issue['ticket'], issue['index'], row['serial']), ()):\n",
        "        for group in reversed(self.visibility.get((issue['ticket'], issue['index'], row['serial']), ())):\n",
        ('test_lab_next',)),
    'receipt-changed-text-accepted': ('lab_broker.py',
        "            if (row['event'], row['text_sha256']) != (issue['challenge'], issue['text_sha256']):\n",
        "            if row['event'] != issue['challenge']:\n",
        ('test_lab_next',)),
    'receipt-rows-not-pinned': ('lab_broker.py',
        '            if self.rows_seen.get(key, sha) != sha:\n',
        '            if False:\n',
        ('test_lab_next',)),
    'receipt-any-user': ('lab_broker.py',
        "            if (row['user'], row['serial']) not in {(r['user'], r['serial']) for r in issue['required']}:\n",
        '            if False:\n',
        ('test_lab_next',)),
    'notice-under-any-grant': ('lab_broker.py',
        "        if m['actor'] != proto.ACTORS['LAB_OPERATOR']:\n",
        '        if False:\n',
        ('test_lab_next',)),
    'notice-partial-inventory': ('lab_actions.py',
        "    if not reading['whole']:\n        return None, 'the user inventory is not whole'\n    required = []\n",
        '    required = []\n',
        ('test_lab_next',)),
    'compound-manifest-unkept': ('lab_broker.py',
        '            self._keep(digest, data, COMPOUND)\n',
        '            pass\n',
        ('test_lab_next',)),
    'health-witness-assumed': ('lab_broker.py',
        '                if not self.reader.witness_admitted:\n',
        '                if False:\n',
        ('test_lab_next',)),
    'health-late-baseline': ('lab_broker.py',
        "            if group['brackets']['end']['elapsed'] <= window['start']:\n",
        '            if True:\n',
        ('test_lab_next',)),
    'health-baseline-any-framework': ('lab_broker.py',
        "        if found is None or found['brackets']['instance'] != instance:\n",
        '        if found is None:\n',
        ('test_lab_next',)),
    'health-preparation-reused': ('lab_broker.py',
        "            if (operation not in self.used_preparations and (resolved['id'], resolved['serial']) == (user, serial)\n",
        "            if ((resolved['id'], resolved['serial']) == (user, serial)\n",
        ('test_lab_next',)),
    'health-stale-preparation': ('lab_broker.py',
        "                        or brackets['end']['elapsed'] - offer['begin'] > offer['max_probe_ms']):\n",
        '                        or False):\n',
        ('test_lab_next',)),
    'health-postend-emitted': ('lab_broker.py',
        "            if probe_end > window['end']:\n",
        '            if False:\n',
        ('test_lab_next',)),
    'health-outside-a-full-window': ('lab_broker.py',
        "        if ticket['state'] != 'HEALTH_WINDOW' or plan['criteria'] != proto.CRITERIA_ALL:\n",
        '        if False:\n',
        ('test_lab_next',)),
    'observation-cut-to-fit': ('lab_broker.py',
        "        if len(envelopes) > proto.MAX_FRAMES:\n            return self._reply(m, 'REFUSED', reason='the observation holds %d facts, above its bound of %d: none is cut'\n                               % (len(envelopes), proto.MAX_FRAMES))\n",
        '        envelopes = envelopes[:proto.MAX_FRAMES]\n',
        ('test_lab_next',)),
    'action-uses-unbounded': ('lab_broker.py',
        "        if len(uses) >= spec['max_uses']:\n",
        '        if False:\n',
        ('test_lab_next',)),
    'action-repeated-after-uncertainty': ('lab_broker.py',
        "        if uses and not kind['after_uncertain']:\n",
        '        if False:\n',
        ('test_lab_next',)),
    'action-effects-uncapped': ('lab_broker.py',
        "                spent = self._effect_spent(kind['effect'], spec['phase'])\n",
        '                spent = None\n',
        ('test_lab_next',)),
    'action-recipient-guessed': ('lab_actions.py',
        "    if len(found) != 1 or found[0]['id'] != required[0]['user'] or not usable(found[0], required[0]['type']):\n",
        '    if len(found) != 1:\n',
        ('test_lab_next',)),
    'action-lost-left-open': ('lab_broker.py',
        '        for number, begun in sorted(self.open_actions.items()):\n',
        '        for number, begun in []:\n',
        ('test_lab_next',)),
    'action-before-its-predecessor': ('lab_broker.py',
        "            if not settled:\n                raise BrokerError('the predecessor action has no settled use')\n",
        "            if not settled:\n                settled = [{'number': None}]\n",
        ('test_lab_next',)),
    'crossing-effects-uncapped': ('lab_broker.py',
        "            capped = self._crossing_cap(name) if self.admission['version'] == 3 else None\n",
        '            capped = None\n',
        ('test_lab_next',)),
    'admission3-profile-unchecked': ('lab_broker.py',
        "    if value['profile'] != lab_actions.PROFILE:\n",
        '    if False:\n',
        ('test_lab_next',)),
    'admission3-installation-authority': ('lab_actions.py',
        "        if spec['authority'] != kind['authority']:\n",
        "        if spec['authority'] not in ('LAB_CONTROL', 'LAB_USER_ADMIN', 'ACTIVATE'):\n",
        ('test_lab_next',)),
    'protocol2-receipt-time-unbound': ('lab_protocol.py',
        "        if (head['elapsed'], head['subject'], head['sequence']) != (b['proven_elapsed'], b['ticket'], b['notice_index']):\n",
        '        if False:\n',
        ('test_lab_protocol',)),
    'protocol2-classification-unbound': ('lab_protocol.py',
        "    if head['classification'] != health_classification(row[1] for row in b['rows']):\n",
        '    if False:\n',
        ('test_lab_protocol',)),
    'protocol2-simple-carries-compound-kinds': ('lab_protocol.py',
        "        if head['kind'] in (KIND_HEALTH, KIND_RECEIPT):\n",
        '        if False:\n',
        ('test_lab_protocol',)),
    'protocol2-version-unchecked': ('lab_protocol.py',
        "    if struct.unpack('<H', data[4:6])[0] != version:\n",
        '    if False:\n',
        ('test_lab_protocol', 'test_lab_next')),
    'side-noncanonical-accepted': ('lab_evidence.py',
        "    if canonical(value) != data:\n        raise SideError('a side record not in its canonical form')\n",
        '',
        ('test_lab_next',)),
    'record-trailing-accepted': ('lab_records.py',
        "    def finish(self):\n        if self.at != self.end:\n            raise RecordError('trailing bytes in a record')\n",
        '    def finish(self):\n        pass\n',
        ('test_lab_next',)),
    'sim-receipt-read-time': ('sim_android.py',
        "        return [self._fact(dict(value, boot=r['boot'], elapsed=r['elapsed']), 'RECEIPT', r['route'], user=r['user'],\n",
        "        return [self._fact(value, 'RECEIPT', r['route'], user=r['user'],\n",
        ('test_lab_next',)),
    'compound-write-failure-not-latched': ('lab_broker.py',
        '            failed = self._writer_failed(reason)\n',
        '',
        ('test_lab_next',)),
    'spec-write-failure-not-latched': ('lab_broker.py',
        "            raise self._writer_failed('the action spec could not be kept: %s' % error) from error\n",
        '            raise\n',
        ('test_lab_next',)),
    'preparation-uncertainty-dropped': ('lab_broker.py',
        "        uncertain = counts['effects_launched'] + counts['effects_uncertain'] > 0\n",
        '        uncertain = False\n',
        ('test_lab_next',)),
    'preparation-unrecognized-settled': ('lab_broker.py',
        "        if classification == 'UNRECOGNIZED' or brackets is None:\n",
        '        if brackets is None:\n',
        ('test_lab_next',)),
    'health-held-without-current-reads': ('lab_broker.py',
        "            if status != 'UNKNOWN' and not row['commands']:\n",
        '            if False:\n',
        ('test_lab_next',)),
    'health-held-beside-witness-doubt': ('lab_broker.py',
        "                elif status == 'HELD' and witness is not None:\n",
        '                elif False:\n',
        ('test_lab_next',)),
    'compound-manifest-trusted-on-reopening': ('lab_broker.py',
        '                self._check_compound(c)\n',
        '',
        ('test_lab_next',)),
    'receipt-refused-rows-forgotten': ('lab_broker.py',
        "                                      {'rows': judged}, facts, emitted=True, extra={'rows': judged})\n",
        "                                      {'rows': judged}, facts, emitted=True,\n"
        "                                      extra={'rows': judged if status == 'facts' else []})\n",
        ('test_lab_next',)),
    'receipt-rows-pinned-only-from-facts': ('lab_broker.py',
        "            if row['key'] is not None:\n                self.rows_seen.setdefault(row['key'], row['sha256'])\n",
        "            if row['key'] is not None and c['status'] == 'facts':\n"
        "                self.rows_seen.setdefault(row['key'], row['sha256'])\n",
        ('test_lab_next',)),
    'receipt-rows-forgotten-without-manifest': ('lab_broker.py',
        "        elif reader == 'receipts':\n            self._pin_rows(record)\n",
        '',
        ('test_lab_next',)),
    'receipt-rows-forgotten-on-reopening': ('lab_broker.py',
        "            elif kind == 'group' and c.get('reader') == 'receipts' and 'rows' in c:\n"
        '                self._pin_rows(c)\n',
        '',
        ('test_lab_next',)),
    'receipt-unbracketed-rows-forgotten': ('lab_broker.py',
        '            judged, _ = self._judge_rows(m, rows, None)\n',
        '',
        ('test_lab_next',)),
    'health-preparation-kept-by-its-probe': ('lab_broker.py',
        "            extra['preparations'] = [p['operation'] for p in offered]\n",
        "            extra['preparations'] = [p['operation'] for p in used]\n",
        ('test_lab_next',)),
    'health-preparation-any-framework': ('lab_broker.py',
        "                        or offer['instance'] != brackets['instance']\n",
        '',
        ('test_lab_next',)),
    'compound-emission-taken-from-its-summary': ('lab_broker.py',
        "                       observations=observations if emits else [], emitted=emits, **m['extra'])\n",
        "                       observations=c['observations'], emitted=c['emitted'], **m['extra'])\n",
        ('test_lab_next',)),
    'health-preparation-use-not-taken-at-the-bracket': ('lab_broker.py',
        "            self.used_preparations.update(p['operation'] for p in offered)\n",
        '            pass\n',
        ('test_lab_next',)),
    'health-preparation-use-forgotten-on-reopening': ('lab_broker.py',
        "                self.used_preparations.update(c['offered'])\n",
        '                pass\n',
        ('test_lab_next',)),
    'health-row-reason-unbounded': ('lab_broker.py',
        "                    or row['status'] not in proto.ROW_STATUSES or not _side_text(row['reason'])\n",
        "                    or row['status'] not in proto.ROW_STATUSES or not isinstance(row['reason'], str)\n",
        ('test_lab_next',)),
    'receipt-judgment-stops-at-a-contrary-row': ('lab_broker.py',
        '        for row in rows:\n',
        '        for row in rows:\n            if refusal is not None:\n                break\n',
        ('test_lab_next',)),
    'compound-reference-erasure-accepted': ('lab_broker.py',
        "            if kind == 'group' and self.admission['version'] == 3:\n"
        '                self._check_unkept_compound(c)\n',
        '',
        ('test_lab_next',)),
}

# Each Java defect: the file under this directory, its exact old and new text, and the suites run
# against it after a rebuild. A suite is a Java suite or the end to end Python suite.
JAVA_MUTANTS = {
    'config-host-unchecked': (JAVA_MAIN + 'LabConfig.java',
                              '        if (values.length > 6) LabProtocol.checkHex(values[6], 32, "host", false);\n', '',
                              ('BridgeTest',)),
    'activation-window-not-sent': (JAVA_MAIN + 'ShellDevice.java',
                                   '        long window = activated ? plan.activateWindowMillis : 0;\n',
                                   '        long window = activated ? 1 : 0;\n', (BRIDGE_SUITE,)),
    'earlier-framework-fact-taken': (JAVA_MAIN + 'ShellDevice.java',
                                     '        if (o.instance >= 0 && o.instance < clockInstance) return "a fact of an earlier '
                                     'framework than the round\'s clock";\n', '', ('BridgeTest',)),
    'device-route-taken': (JAVA_MAIN + 'ShellDevice.java',
                           '        if (o.route != Route.SHELL) return "the " + o.route + " route on the shell bridge";\n',
                           '', ('BridgeTest',)),
    'fact-boot-unchecked': (JAVA_MAIN + 'ShellDevice.java',
                            '        if (!o.boot.equals(clockBoot)) return "a fact of another boot than the round\'s clock";\n',
                            '', ('BridgeTest',)),
    'stored-ticket-unchecked': (JAVA_MAIN + 'ShellDevice.java',
                                '        if (storedTicket.found != Found.RECORD || !Arrays.equals(DeploymentRecords.encodeTicket'
                                '(storedTicket.value),\n',
                                '        if (storedTicket.found != Found.RECORD || false && !Arrays.equals(DeploymentRecords'
                                '.encodeTicket(storedTicket.value),\n', ('BridgeTest',)),
    'reply-index-unchecked': (JAVA_MAIN + 'ShellDevice.java',
                              '        } else if (o.kind != ObservationKind.REPLY || !o.subject.equals(ticket.ticketId) '
                              '|| o.sequence != index\n',
                              '        } else if (o.kind != ObservationKind.REPLY || !o.subject.equals(ticket.ticketId)\n',
                              ('BridgeTest',)),
    'cross-halt-ignored': (JAVA_MAIN + 'ShellDevice.java',
                           '            case HALT:\n                halter.halt(Halter.STATUS);\n'
                           '                throw new IllegalStateException("the halter returned");\n'
                           '            case STOPPED:\n                throw new GenerationStopped(reply.text("reason"));\n'
                           '            default:\n                throw new BridgeRefusal("the broker refused CROSS: "',
                           '            case HALT:\n                return null;\n'
                           '            case STOPPED:\n                throw new GenerationStopped(reply.text("reason"));\n'
                           '            default:\n                throw new BridgeRefusal("the broker refused CROSS: "',
                           ('BridgeTest', BRIDGE_SUITE)),
    'cross-stop-read-as-lost': (JAVA_MAIN + 'ShellDevice.java',
                                '            case STOPPED:\n                throw new GenerationStopped(reply.text("reason"));\n'
                                '            default:\n                throw new BridgeRefusal("the broker refused CROSS: "',
                                '            case STOPPED:\n                return null;\n'
                                '            default:\n                throw new BridgeRefusal("the broker refused CROSS: "',
                                ('BridgeTest',)),
    'host-withheld-delivered': (JAVA_MAIN + 'FaultHost.java', '                if (end) return false;\n',
                                '                if (end) return true;\n', ('BridgeTest', BRIDGE_SUITE)),
    'host-begin-skipped': (JAVA_MAIN + 'FaultHost.java', '        decide(channel.call(begin), false);\n', '',
                           ('BridgeTest', BRIDGE_SUITE)),
    'host-query-unfenced': (JAVA_MAIN + 'FaultHost.java',
                            '        if (!fenced) throw new BridgeRefusal("no query before the broker confirmed that earlier '
                            'calls ended");\n', '', ('BridgeTest',)),
    'target-unknown-rounds': (JAVA_MAIN + 'LabBridge.java',
                              '        if (target == LabProtocol.TARGET_UNKNOWN) throw new BridgeRefusal("the native target '
                              'scope is not established");\n', '', ('BridgeTest',)),
    'point-halt-ignored': (JAVA_MAIN + 'LabBridge.java',
                           '            case HALT:\n                halter.halt(Halter.STATUS);\n'
                           '                throw new IllegalStateException("the halter returned");\n'
                           '            default:\n                throw new BridgeRefusal("the broker refused POINT: "',
                           '            case HALT:\n                return;\n'
                           '            default:\n                throw new BridgeRefusal("the broker refused POINT: "',
                           ('BridgeTest', BRIDGE_SUITE)),
    'hello-without-config': (JAVA_MAIN + 'LabBridge.java', '.id("config", config.digest)',
                             '.id("config", config.trustPolicy)', ('BridgeTest',)),
    'java-session-by-id-alone': (JAVA_MAIN + 'LabProtocol.java',
                                 '                && (ref.presence & BOUND_REFERENCE) != BOUND_REFERENCE) {\n',
                                 '                && false) {\n', ('ProtocolTest',)),
    # The next campaign profile's bridge end: version 2 envelopes against the round and the store.
    'v2-receipt-before-its-notice': (JAVA_MAIN + 'ShellDevice.java',
        '        if (entry.elapsed > o.elapsed) return "a receipt event before its notice was given";\n',
        '',
        ('BridgeTest',)),
    'v2-old-current-fact': (JAVA_MAIN + 'ShellDevice.java',
        '            if (o.elapsed < clockElapsed) return "a current fact older than the round\'s clock";\n',
        '',
        ('BridgeTest',)),
    'v2-health-outside-window': (JAVA_MAIN + 'ShellDevice.java',
        '        if (e.number("probe_begin") < ticket.windowStart || o.elapsed > ticket.windowStart + plan.healthWindowMillis) {\n',
        '        if (false) {\n',
        ('BridgeTest',)),
    'v2-health-user-not-running': (JAVA_MAIN + 'ShellDevice.java',
        '        if (!running) return "a health probe of a user this observation does not show running";\n',
        '',
        ('BridgeTest',)),
    'v2-compound-read-before-the-clock': (JAVA_MAIN + 'ShellDevice.java',
        '        if (e.number("read_instance") < clockInstance || e.number("read_begin_elapsed") < clockElapsed) {\n',
        '        if (false) {\n',
        ('BridgeTest',)),
    'v2-health-publication-unchecked': (JAVA_MAIN + 'ShellDevice.java',
        '        if (publication == null || !publication.equals(e.id("publication"))) {\n',
        '        if (false) {\n',
        ('BridgeTest',)),
    'v2-observe-halt-ignored': (JAVA_MAIN + 'ShellDevice.java',
        '        if (reply.status() == Status.HALT) {\n            halter.halt(Halter.STATUS);\n            throw new IllegalStateException("the halter returned");\n        }\n        if (reply.status() != Status.OK) throw new BridgeRefusal("the broker refused OBSERVE: " + reply.text("reason"));\n        List<Observation> facts = new ArrayList<>();\n        List<Observation> users = new ArrayList<>();\n',
        '        if (reply.status() != Status.OK) throw new BridgeRefusal("the broker refused OBSERVE: " + reply.text("reason"));\n        List<Observation> facts = new ArrayList<>();\n        List<Observation> users = new ArrayList<>();\n',
        ('BridgeTest',)),
    'java-v2-receipt-time-unbound': (JAVA_MAIN + 'LabProtocol.java',
        '            if (head.elapsed != proven || !head.subject.equals(e.id("ticket")) || head.sequence != e.number("notice_index")) {\n',
        '            if (false) {\n',
        ('ProtocolTest',)),
    'java-v2-classification-unbound': (JAVA_MAIN + 'LabProtocol.java',
        '        if (head.classification != healthClassification(statuses)) {\n',
        '        if (false) {\n',
        ('ProtocolTest',)),
    'java-v2-version-unchecked': (JAVA_MAIN + 'LabProtocol.java',
        '        if (framed != version) throw fail("a frame of protocol version " + framed + " on a version " + version + " channel");\n',
        '',
        ('ProtocolTest',)),
}


def java_case_names(text):
    return re.findall(r'cases\.run\("([^"]+)"', text)


def case_names(tree=HERE):
    """Each suite's case IDs, from its source."""
    names = {}
    for suite in SUITES + (BRIDGE_SUITE, DRIVER_SUITE):
        parsed = ast.parse((tree / (suite + '.py')).read_text())
        found = []
        for node in parsed.body:
            if isinstance(node, ast.ClassDef):
                for item in node.body:
                    if isinstance(item, ast.FunctionDef) and item.name.startswith('test_'):
                        found.append('%s.%s.%s' % (suite, node.name, item.name))
        names[suite] = found
    for suite in JAVA_SUITES:
        names[suite] = java_case_names((tree / JAVA_TESTS / (suite + '.java')).read_text())
    for suite in DRIVER_JAVA_SUITES:
        names[suite] = java_case_names((tree / DRIVER_TESTS / (suite + '.java')).read_text())
    return names


def source_problems(predictions):
    problems = []
    names = case_names()
    counts = {suite: len(found) for suite, found in names.items()}
    if 'PREDICTED' not in predictions.get('status', ''):
        problems.append('the predictions are not marked as predictions')
    if predictions.get('cases') != counts:
        problems.append('predicted cases %s differ from the suites %s' % (predictions.get('cases'), counts))
    for suite, found in names.items():
        if len(set(found)) != len(found):
            problems.append('a case named twice in %s' % suite)
    caught = predictions.get('mutants_caught_at_least', {})
    defects = dict(MUTANTS, **JAVA_MUTANTS, **DRIVER_MUTANTS)
    if set(caught) != set(defects) or len(defects) != len(MUTANTS) + len(JAVA_MUTANTS) + len(DRIVER_MUTANTS):
        problems.append('the defect predictions do not list every defect once')
    for name, (file, old, new, suites) in defects.items():
        if (HERE / file).read_text().count(old) != 1:
            problems.append('the anchor of %s is not in %s once' % (name, file))
        allowed = {(suite + '.' + case) if suite in JAVA_SUITES + DRIVER_JAVA_SUITES else case
                   for suite in suites for case in names[suite]}
        if not caught.get(name) or not set(caught.get(name, ())) <= allowed:
            problems.append('the prediction of %s names no case of its suites' % name)
    for path in HERE.rglob('*'):
        if path.name in ('Android.bp', 'Android.mk') or path.suffix == '.mk':
            problems.append('a build file in the lab directory: %s' % path.name)
        if path.is_file() and path.suffix in ('.py', '.md', '.json', '.java') and PRIVATE.search(path.read_text()):
            problems.append('a private host path in %s' % path.relative_to(REPO))
    return problems


def resource_guard():
    """The records runner's guard, imported read only. None, or why the JVM phases cannot run."""
    sys.path.insert(0, str(REPO))
    try:
        from scripts.proof import component_transaction_records as records
    finally:
        sys.path.pop(0)
    return records.resource_guard()


def tool(name, jdk):
    if jdk:
        path = Path(jdk) / name
        return str(path) if path.is_file() else None
    return shutil.which(name)

# Deliberate defects of the lab driver, each run against the driver suite (a Java one rebuilt with the jar).
DRIVER_MUTANTS = {
    'host-digest-unchecked': (DRIVER_JAVA + 'LabHost.java',
                              '        if (!LabProtocol.sha256Hex(data).equals(sha256)) throw new IOException(what + " differs from '
                              'its admitted digest");\n', '', (DRIVER_SUITE, 'DriverTest')),
    'host-binding-unchecked': (DRIVER_JAVA + 'LabHost.java', '        if (lab.host == null || !lab.host.equals(config.digest)) {\n',
                               '        if (false) {\n', (DRIVER_SUITE, 'DriverTest')),
    'sdk-range-unchecked': (DRIVER_JAVA + 'LabHost.java', '            if (f.minSdk != config.sdkMin || max != config.sdkMax) {\n',
                            '            if (false) {\n', (DRIVER_SUITE,)),
    'approval-any-plan': (DRIVER_JAVA + 'LabHost.java', ' && config.plans.contains(t.plan)\n', '\n', ('DriverTest',)),
    'plan-not-admitted': (DRIVER_JAVA + 'LabDriverMain.java',
                          '        need(hc.plans.contains(planId), "the host configuration does not admit this plan");\n', '',
                          (DRIVER_SUITE,)),
    'admitted-config-unchecked': (DRIVER_JAVA + 'LabDriverMain.java',
                                  '        need(lab.digest.equals(admittedDigest), "the bridge configuration is not the one the '
                                  'admission binds");\n', '', ('DriverTest', DRIVER_SUITE)),
    'other-boots-accepted': (DRIVER_JAVA + 'LabDriverMain.java',
                             '        need(others.isEmpty(), "the store holds facts of another boot, so the baseline\'s boot is not '
                             'established: " + others);\n', '', ('DriverTest', DRIVER_SUITE)),
    'checked-not-t0': (DRIVER_JAVA + 'LabDriverMain.java',
                       '        need(checked.equals(t0), "the selection\'s checked boot is not the boot the driver\'s check '
                       'established");\n', '', ('DriverTest',)),
    'selection-not-current-accepted': (DRIVER_JAVA + 'LabDriverMain.java',
                                       '        return s.choice == ChoiceKind.FACTORY && s.revision == 0 && s.realization == '
                                       'Realization.CURRENT;\n', '        return true;\n', ('DriverTest',)),
    'checkpoint-not-required': (DRIVER_JAVA + 'LabDriverMain.java',
                                '        need(committed, "no committed checkpoint is observed in the baseline boot");\n', '',
                                ('DriverTest',)),
    'pending-checkpoint-accepted': (DRIVER_JAVA + 'LabDriverMain.java',
                                    '                    throw new IllegalStateException("the baseline boot has a pending checkpoint");\n',
                                    '                    break;\n', ('DriverTest',)),
    'data-copy-accepted': (DRIVER_JAVA + 'LabDriverMain.java',
                           '                    if (o.component.equals(component)) throw new IllegalStateException("a data copy is active at '
                           'the baseline");\n', '', ('DriverTest', DRIVER_SUITE)),
    'publication-not-pinned': ('lab_driver.py', '        self.broker.pin_artifacts(plan, members)\n', '', (DRIVER_SUITE,)),
    'settles-before-staging': ('lab_driver.py', "            if plan in self.staged:\n                summary = self.advance('settle', "
                               "ticket, str(rounds))\n            else:\n                summary = self.advance('round', ticket)\n",
                               "            summary = self.advance('settle', ticket, str(rounds))\n", (DRIVER_SUITE,)),
    'staging-failure-swallowed': ('lab_driver.py', '                members = self.stage_publication(plan)\n',
                                  '                try:\n                    members = self.stage_publication(plan)\n'
                                  '                except DriverError:\n                    members = None\n', (DRIVER_SUITE,)),
    'not-published-is-failure': ('lab_driver.py', 'accept=(0, NOT_PUBLISHED)', 'accept=(0,)', (DRIVER_SUITE,)),
    'generation-failure-continued': ('lab_driver.py', "        if summary['status'] not in CONTINUING:\n",
                                     "        if False:\n", (DRIVER_SUITE,)),
    't0-without-own-reads': ('lab_driver.py', "        boot = self.read_boot(summary['generation'])\n",
                             "        boot = self.selection()['checked']\n", (DRIVER_SUITE,)),
    'empty-read-counted': ('lab_driver.py', "            if not any(o['kind'] == kind and o['classification'] in classifications "
                           "for o in facts):\n", "            if False:\n", (DRIVER_SUITE,)),
    't0-kept-across-generations': ('lab_driver.py',
                                   '        self.t0 = None  # A plan binds only the boot of a check that is the last generation.\n',
                                   '', (DRIVER_SUITE,)),
    'host-clock-only': ('lab_driver.py', '        self.clock = clock or (lambda: time.time_ns() // 1_000_000)\n',
                        '        self.clock = lambda: time.time_ns() // 1_000_000\n', (DRIVER_SUITE,)),
    'restart-checkpoint-not-renewed': ('lab_driver.py', "            if not any(g['reader'] == 'checkpoint' and g['status'] == 'facts'\n",
                                       "            if False and not any(g['reader'] == 'checkpoint' and g['status'] == 'facts'\n",
                                       (DRIVER_SUITE,)),
    'restart-beside-a-committed-wait': ('lab_driver.py',
                                        "        return not any(o['kind'] == 'SESSION' and o['classification'] in lab_broker.RESTART_BLOCKING\n",
                                        "        return True or not any(o['kind'] == 'SESSION' and o['classification'] in "
                                        "lab_broker.RESTART_BLOCKING\n", (DRIVER_SUITE,)),
    'restart-beside-a-pending-checkpoint': ('lab_driver.py',
                                            "        if [o['classification'] for o in checkpoint['observations'] if o['kind'] == 'CHECKPOINT'] "
                                            "!= ['COMMITTED']:\n", '        if False:\n', (DRIVER_SUITE,)),
    'faults-acted-not-compared': ('lab_driver.py', "        expected['faults'] = sorted(item['cell'] for item in spec['faults'])\n",
                                  "        expected['faults'] = found['faults']\n", (DRIVER_SUITE,)),
    'restart-effect-unverified': ('lab_driver.py',
                                  "            if not readings or any(r['boot'] != boot or r['instance'] < later or r['instance'] <= before "
                                  "for r in readings):\n",
                                  '            if False:\n', (DRIVER_SUITE,)),
    'attempt-before-terminal': ('lab_driver.py', "              or any(t['state'] not in TERMINAL for t in found)):\n",
                                '              and False):\n', (DRIVER_SUITE,)),
    'attempt-faults-not-admitted': ('lab_driver.py',
                                    "        self.broker.admit_faults([dict(item, plan=plan, attempt=spec['attempt']) "
                                    "for item in spec['faults']])\n", '', (DRIVER_SUITE,)),
    'prediction-not-compared': ('lab_driver.py', '        if found != expected:\n', '        if False:\n', (DRIVER_SUITE,)),
    'cohort-control-not-contradicted': (DRIVER_JAVA + 'LabDriverMain.java',
                                        'contradict ? otherDigest(base.apk) : base.apk', 'base.apk', ('DriverTest', DRIVER_SUITE)),
}


def tool_environment(extra=None):
    env = {k: v for k, v in os.environ.items() if k not in ('CLASSPATH', 'PYTHONPATH', 'ANDRIX_LAB_GOLDENS',
                                                            'ANDRIX_LAB_JAVA', 'ANDRIX_LAB_CLASSES')}
    env.update(extra or {})
    return env


def build(tree, out, javac):
    """Compiles the deployment package, the bridge and its tests from a tree into out/classes."""
    lab = tree / 'tests' / 'component-lab'
    sources = sorted(str(p) for p in (REPO / DEPLOYMENT).glob('*.java'))
    sources += sorted(str(p) for p in (lab / JAVA_MAIN).glob('*.java'))
    sources += sorted(str(p) for p in (lab / JAVA_TESTS).glob('*.java'))
    classes = out / 'classes'
    classes.mkdir(parents=True)
    done = subprocess.run([javac, '-J-Xmx384m', *('-J' + o for o in JVM_LIMITS), '--release', '17', '-Xlint:all', '-Werror',
                           '-implicit:none', '-proc:none', '-d', str(classes), *sources],
                          capture_output=True, text=True, timeout=600, env=tool_environment())
    return classes if done.returncode == 0 else None, (done.stdout + done.stderr)[-4000:]


def run_java(java, classes, suite, args, work, timeout=600):
    state = work / ('jvm-' + suite)
    state.mkdir(parents=True, exist_ok=True)
    try:
        done = subprocess.run([java, '-Xmx256m', *JVM_LIMITS, '-ea', '-Djava.io.tmpdir=' + str(state), '-cp',
                               str(classes), JAVA_PACKAGE + '.' + suite, *args], capture_output=True, text=True,
                              timeout=timeout, env=tool_environment())
    except subprocess.TimeoutExpired:
        return {'returncode': None, 'passed': [], 'failed': [], 'output': 'timeout'}
    return {'returncode': done.returncode, 'passed': re.findall(r'^PASS (.+)$', done.stdout, re.M),
            'failed': sorted(set(re.findall(r'^FAIL (.+?): ', done.stdout, re.M))), 'output': done.stdout[-4000:]}


def run_suite(tree, suite, java=None, classes=None, timeout=900, driver=None):
    """One Python suite of a tree in its own interpreter. The end to end suite gets the JDK and classes;
    the driver suite its classpath, the platform keys and the signing inputs."""
    lab = tree / 'tests' / 'component-lab'
    extra = {'PYTHONPATH': str(lab)}
    if java and classes:
        extra.update(ANDRIX_LAB_JAVA=java, ANDRIX_LAB_CLASSES=str(classes))
    if java and driver:
        extra.update(ANDRIX_LAB_JAVA=java, ANDRIX_LAB_DRIVER_CLASSPATH=driver['classpath'],
                     ANDRIX_LAB_PLATFORM_KEYS=driver['keys'], ANDRIX_LAB_SIGNING_INPUTS=driver['inputs'])
    try:
        done = subprocess.run([sys.executable, '-B', '-m', 'unittest', '-v', suite], cwd=lab,
                              env=tool_environment(extra), capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {'returncode': None, 'passed': [], 'failed': [], 'skipped': [], 'output': 'timeout'}
    output = done.stderr
    passed = re.findall(r'^(test_\w+) \(([\w.]+)\) \.\.\. ok$', output, re.M)
    skipped = re.findall(r'^(test_\w+) \(([\w.]+)\) \.\.\. skipped', output, re.M)
    # A failing subtest prints its label in brackets and its parameters in parentheses after the
    # test's name, either or both, and still fails the test.
    failed = re.findall(r'^(?:FAIL|ERROR): (test_\w+) \(([\w.]+)\)(?: \[.*\])?(?: \(.*\))?$', output, re.M)
    return {'returncode': done.returncode, 'passed': sorted(full for _, full in passed),
            'skipped': sorted(full for _, full in skipped), 'failed': sorted(set(full for _, full in failed)),
            'output': output[-4000:]}


def python_phase(report, names):
    problems, results = [], {}
    for suite in SUITES:
        run = run_suite(REPO, suite)
        results[suite] = {'passed': len(run['passed']), 'failed': run['failed'], 'returncode': run['returncode']}
        if run['returncode'] != 0 or run['failed'] or sorted(run['passed']) != sorted(names[suite]):
            problems.append('%s: %d passed of %d, failed %s' % (suite, len(run['passed']), len(names[suite]),
                                                                 run['failed'] or run['output'][-400:]))
    report['python'] = results
    return problems


def java_phase(report, names, java, javac, work, suites=True):
    """Builds the base tree, runs the Java suites, binds the goldens, then the end to end suite."""
    problems, results = [], {}
    classes, output = build(REPO, work / 'base', javac)
    report['build'] = {'ok': classes is not None, 'output': output}
    if classes is None:
        return ['the base build failed'], None
    if not suites:
        return [], classes
    goldens = work / 'goldens'
    goldens.mkdir()
    env = tool_environment({'PYTHONPATH': str(HERE), 'ANDRIX_LAB_GOLDENS': str(goldens)})
    subprocess.run([sys.executable, '-B', '-m', 'unittest', 'test_lab_protocol.ProtocolTests.test_goldens'], cwd=HERE,
                   env=env, capture_output=True, text=True, timeout=120)
    # Fourteen goldens of version 1 and six of version 2.
    if len(list(goldens.glob('*.bin'))) != 20:
        problems.append('the Python suite wrote %d goldens, not 20' % len(list(goldens.glob('*.bin'))))
    for suite in JAVA_SUITES:
        args = [str(goldens)] if suite == 'ProtocolTest' else [str(work / 'bridge-runs')]
        if suite == 'BridgeTest':
            (work / 'bridge-runs').mkdir()
        run = run_java(java, classes, suite, args, work)
        results[suite] = {'passed': len(run['passed']), 'failed': run['failed'], 'returncode': run['returncode']}
        if run['returncode'] != 0 or run['failed'] or sorted(run['passed']) != sorted(names[suite]):
            problems.append('%s: %d passed of %d, failed %s' % (suite, len(run['passed']), len(names[suite]),
                                                                 run['failed'] or run['output'][-400:]))
    run = run_suite(REPO, BRIDGE_SUITE, java, classes)
    results[BRIDGE_SUITE] = {'passed': len(run['passed']), 'failed': run['failed'], 'skipped': len(run['skipped']),
                             'returncode': run['returncode']}
    if run['returncode'] != 0 or run['failed'] or sorted(run['passed']) != sorted(names[BRIDGE_SUITE]):
        problems.append('%s: %d passed of %d, failed %s' % (BRIDGE_SUITE, len(run['passed']), len(names[BRIDGE_SUITE]),
                                                             run['failed'] or run['output'][-400:]))
    report['java'] = results
    return problems, classes


def build_driver(tree, out, javac, jar):
    """Compiles the deployment package, the bridge, the apksig engine and the driver from a tree against
    the pinned apksigner jar, with the engine's service file. Returns (classpath or None, output)."""
    lab = tree / 'tests' / 'component-lab'
    sources = sorted(str(p) for p in (REPO / DEPLOYMENT).glob('*.java')) + [str(REPO / APKSIG_ENGINE)]
    sources += sorted(str(p) for p in (lab / JAVA_MAIN).glob('*.java'))
    sources += sorted(str(p) for p in (lab / DRIVER_JAVA).glob('*.java'))
    sources += sorted(str(p) for p in (lab / DRIVER_TESTS).glob('*.java'))
    classes = out / 'classes'
    (classes / 'META-INF' / 'services').mkdir(parents=True)
    shutil.copyfile(REPO / APKSIG_SERVICE, classes / 'META-INF' / 'services' / Path(APKSIG_SERVICE).name)
    done = subprocess.run([javac, '-J-Xmx384m', *('-J' + o for o in JVM_LIMITS), '--release', '17', '-Xlint:all', '-Werror',
                           '-implicit:none', '-proc:none', '-cp', str(jar), '-d', str(classes), *sources],
                          capture_output=True, text=True, timeout=600, env=tool_environment())
    return ('%s:%s' % (classes, jar)) if done.returncode == 0 else None, (done.stdout + done.stderr)[-4000:]


def signing_inputs(args):
    """The driver phase's inputs, or the reason it cannot run: the pinned jar by its digest, the key
    directory and the input directory."""
    given = (args.apksig_jar, args.platform_keys, args.signing_inputs)
    if not any(given):
        return None, 'no apksigner jar, platform keys or signing inputs given'
    if not all(given):
        return None, 'some driver inputs given, not all'
    jar = Path(args.apksig_jar).resolve()
    try:
        data = jar.read_bytes()
    except OSError as error:
        return None, 'the apksigner jar cannot be read: %s' % error
    if hashlib.sha256(data).hexdigest() != PINNED_APKSIGNER_JAR:
        return None, 'not the pinned apksigner jar'
    keys, inputs = Path(args.platform_keys).resolve(), Path(args.signing_inputs).resolve()
    if not all((keys / n).is_file() for n in ('platform.pk8', 'platform.x509.pem')) or not all(
            (inputs / n).is_file() for n in ('built-A.apk', 'built-R.apk')):
        return None, 'the key or input directory lacks its files'
    return {'jar': str(jar), 'keys': str(keys), 'inputs': str(inputs)}, None


def driver_phase(report, names, java, javac, work, signing, suites=True):
    """Builds the driver against the pinned jar, then runs its unit suite and its end to end suite."""
    classpath, output = build_driver(REPO, work / 'driver', javac, signing['jar'])
    report['driver_build'] = {'ok': classpath is not None, 'output': output}
    if classpath is None:
        return ['the driver build failed'], None
    if not suites:
        return [], classpath
    problems, results = [], {}
    for suite in DRIVER_JAVA_SUITES:
        runs = work / ('driver-runs-' + suite)
        runs.mkdir()
        run = run_java(java, classpath, suite, [str(runs)], work)
        results[suite] = {'passed': len(run['passed']), 'failed': run['failed'], 'returncode': run['returncode']}
        if run['returncode'] != 0 or run['failed'] or sorted(run['passed']) != sorted(names[suite]):
            problems.append('%s: %d passed of %d, failed %s' % (suite, len(run['passed']), len(names[suite]),
                                                                 run['failed'] or run['output'][-400:]))
    run = run_suite(REPO, DRIVER_SUITE, java, driver=dict(signing, classpath=classpath))
    results[DRIVER_SUITE] = {'passed': len(run['passed']), 'failed': run['failed'], 'skipped': len(run['skipped']),
                             'returncode': run['returncode']}
    if run['returncode'] != 0 or run['failed'] or sorted(run['passed']) != sorted(names[DRIVER_SUITE]):
        problems.append('%s: %d passed of %d, failed %s' % (DRIVER_SUITE, len(run['passed']), len(names[DRIVER_SUITE]),
                                                             run['failed'] or run['output'][-400:]))
    report['driver'] = results
    return problems, classpath


def mutant_phase(report, predictions, chosen, java, javac, base_classes, work, signing=None, driver_classpath=None):
    problems, results = [], {}
    defects = dict(MUTANTS, **JAVA_MUTANTS, **DRIVER_MUTANTS)
    for name, (file, old, new, suites) in defects.items():
        if name not in chosen:
            continue
        tree = work / ('mutant-' + name)
        lab = tree / 'tests' / 'component-lab'
        shutil.copytree(HERE, lab, ignore=shutil.ignore_patterns('__pycache__'))
        (tree / 'scripts').symlink_to(REPO / 'scripts')
        path = lab / file
        path.write_text(path.read_text().replace(old, new, 1))
        failed, note = set(), None
        classes = base_classes
        if name in JAVA_MUTANTS:
            classes, output = build(tree, tree / 'build', javac) if javac else (None, 'no compiler')
            if classes is None:
                note = 'the defect does not compile: ' + output[-300:]
        driver = None
        if name in DRIVER_MUTANTS:
            if signing is None or not javac:
                note = 'no driver phase: not run'
            elif file.startswith(DRIVER_JAVA):
                classpath, output = build_driver(tree, tree / 'driver-build', javac, signing['jar'])
                if classpath is None:
                    note = 'the defect does not compile: ' + output[-300:]
                driver = dict(signing, classpath=classpath)
            else:
                driver = dict(signing, classpath=driver_classpath)
        needs_jvm = any(s in JAVA_SUITES or s == BRIDGE_SUITE for s in suites)
        if needs_jvm and classes is None and note is None:
            note = 'no JVM phase: not run'
        for suite in suites:
            if note is not None:
                break
            if suite in JAVA_SUITES:
                runs = tree / ('runs-' + suite)
                runs.mkdir()
                args = [str(runs)] if suite == 'BridgeTest' else []
                failed |= set(suite + '.' + case for case in run_java(java, classes, suite, args, tree)['failed'])
            elif suite in DRIVER_JAVA_SUITES:
                runs = tree / ('runs-' + suite)
                runs.mkdir()
                failed |= set(suite + '.' + case for case in run_java(java, driver['classpath'], suite, [str(runs)], tree)['failed'])
            elif suite == DRIVER_SUITE:
                failed |= set(run_suite(tree, suite, java, driver=driver)['failed'])
            else:
                failed |= set(run_suite(tree, suite, java, classes)['failed'])
        expected = set(predictions['mutants_caught_at_least'][name])
        results[name] = {'failed': sorted(failed), 'caught': expected <= failed and note is None, 'note': note}
        if not results[name]['caught']:
            problems.append('defect %s was not caught by %s%s' % (name, sorted(expected - failed),
                                                                 ' (%s)' % note if note else ''))
        shutil.rmtree(tree)
    report['mutants'] = results
    return problems


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('--source-checks-only', action='store_true')
    parser.add_argument('--no-mutants', action='store_true')
    parser.add_argument('--no-java', action='store_true', help='skip every JVM phase and every Java defect')
    parser.add_argument('--skip-python', action='store_true', help='skip the Python phase, for a chunked run')
    parser.add_argument('--skip-java-suites', action='store_true', help='build only, for a chunked defect run')
    parser.add_argument('--mutant', action='append', help='only these defects, for a chunked run')
    parser.add_argument('--jdk', help='a JDK bin directory instead of PATH')
    parser.add_argument('--allow-unguarded', action='store_true', help='development only; the report is UNGUARDED')
    parser.add_argument('--apksig-jar', help='the pinned apksigner jar, for the driver phase')
    parser.add_argument('--platform-keys', help='a directory with the public platform.pk8 and platform.x509.pem')
    parser.add_argument('--signing-inputs', help='a directory with the built built-A.apk and built-R.apk')
    parser.add_argument('--report')
    args = parser.parse_args(argv)
    predictions = json.loads(PREDICTIONS.read_text())
    report = {'problems': [], 'status': None, 'guard': None}
    report['problems'] += source_problems(predictions)
    unguarded = False
    if not args.source_checks_only and not report['problems']:
        names = case_names()
        if not args.skip_python:
            report['problems'] += python_phase(report, names)
        java, javac = (None, None) if args.no_java else (tool('java', args.jdk), tool('javac', args.jdk))
        guard = None if args.no_java else resource_guard()
        report['guard'] = guard
        jvm = not args.no_java and java and javac and (guard is None or args.allow_unguarded)
        unguarded = bool(jvm and guard is not None)
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            classes, driver_classpath, signing = None, None, None
            if jvm:
                problems, classes = java_phase(report, names, java, javac, work, not args.skip_java_suites)
                report['problems'] += problems
                signing, reason = signing_inputs(args)
                if signing is None:
                    report['driver'] = 'NOT_RUN: ' + reason
                else:
                    # A chunked defect run still builds the driver, so its defects run against it.
                    problems, driver_classpath = driver_phase(report, names, java, javac, work, signing,
                                                              not args.skip_java_suites)
                    report['problems'] += problems
            elif not args.no_java:
                report['java'] = 'NOT_RUN: ' + (guard or 'no JDK on PATH')
            if not args.no_mutants:
                chosen = set(args.mutant) if args.mutant else set(MUTANTS) | set(JAVA_MUTANTS) | set(DRIVER_MUTANTS)
                unknown = chosen - set(MUTANTS) - set(JAVA_MUTANTS) - set(DRIVER_MUTANTS)
                if unknown:
                    report['problems'].append('unknown defects %s' % sorted(unknown))
                if not jvm:
                    chosen &= set(MUTANTS)
                if signing is None:
                    chosen -= set(DRIVER_MUTANTS)
                report['problems'] += mutant_phase(report, predictions, chosen, java if jvm else None,
                                                   javac if jvm else None, classes, work, signing, driver_classpath)
    ran_java = isinstance(report.get('java'), dict)
    ran_driver = isinstance(report.get('driver'), dict)
    partial = (args.source_checks_only or args.skip_python or args.skip_java_suites or args.no_mutants
               or bool(args.mutant) or not ran_java or not ran_driver)
    if report['problems']:
        report['status'] = 'FAIL'
    elif unguarded:
        report['status'] = 'UNGUARDED'
    else:
        report['status'] = 'PARTIAL' if partial else 'PASS'
    text = json.dumps(report, indent=1, sort_keys=True)
    if args.report:
        Path(args.report).write_text(text + '\n')
    summary = {'status': report['status'], 'guard': report['guard'], 'python': report.get('python'),
               'java': report.get('java'), 'driver': report.get('driver'), 'mutants': len(report.get('mutants', {}))}
    print(text if report['problems'] else json.dumps(summary, sort_keys=True))
    return 0 if not report['problems'] else 1


if __name__ == '__main__':
    sys.exit(main())
