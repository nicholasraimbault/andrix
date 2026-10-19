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
phase runs the end to end suites: the accepted coordinator through the bridge against the broker on
a simulated guest, one JVM per generation, and the next campaign's driver over the host test entry.
The driver phase, given the pinned apksigner jar, the public
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
          'test_lab_next', 'test_lab_loss', 'test_full_users', 'test_health', 'test_witness', 'test_next_campaign')
BRIDGE_SUITE = 'test_lab_bridge'
# The next campaign's driver end to end: the same JDK and compiled classes as the bridge suite, with
# the host test entry and the scripted host in place of the lab driver entry and apksig.
NEXT_DRIVER_SUITE = 'test_next_driver'
JVM_SUITES = (BRIDGE_SUITE, NEXT_DRIVER_SUITE)
# The lab driver's end to end suite: the real host signer over apksig, so it needs the pinned
# apksigner jar, the public development platform key and the two built signing inputs.
DRIVER_SUITE = 'test_lab_driver'
DRIVER_JAVA = 'driver/dev/andrix/lab/component/'
DRIVER_TESTS = 'driver-tests/dev/andrix/lab/component/'
DRIVER_JAVA_SUITES = ('DriverTest',)
APKSIG_ENGINE = 'owner/deployment/apksig/dev/andrix/server/deployment/ApksigEngine.java'
APKSIG_SERVICE = 'owner/deployment/apksig/META-INF/services/com.android.apksig.kms.KmsSignerEngineProvider'
PINNED_APKSIGNER_JAR = '6b96559764325d085a6bad6be109cc3053791d63826f84dc0e74032db136a196'
JAVA_SUITES = ('ProtocolTest', 'BridgeTest', 'RepairTest')
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
    'records-root-unsynced': ('lab_broker.py', '        # earlier call could not finish is never skipped.\n        self._sync_dir(self.root)\n',
                              '        # earlier call could not finish is never skipped.\n', ('test_lab_broker',)),
    'existing-record-unsynced': ('lab_broker.py', '            self._sync_dir(directory)\n            return\n', '            return\n',
                                 ('test_lab_broker',)),
    'broker-name-unsynced-when-made': ('lab_broker.py', '        _sync_directory(root.parent)\n', '', ('test_lab_broker',)),
    'broker-name-unsynced-at-opening': ('lab_broker.py', '            self._sync_dir(self.root.parent)\n', '', ('test_lab_broker',)),
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
    # A baseline is complete only with the witness reader's parts, so this rule shows once a
    # baseline is complete and a witness hook holds while the reader admits no witness reader.
    'health-witness-assumed': ('lab_broker.py',
        '                if not self.reader.witness_admitted:\n',
        '                if False:\n',
        ('test_health',)),
    # The baseline rule moved from the broker into health_baseline.select, and these two with it.
    'health-late-baseline': ('health_baseline.py',
        "        candidates = [b for b in whole if b['brackets']['end']['elapsed'] <= window['start']]\n",
        '        candidates = whole\n',
        ('test_lab_next', 'test_witness')),
    'health-baseline-any-framework': ('health_baseline.py',
        "    if chosen['brackets']['instance'] != instance:\n",
        '    if False:\n',
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
        ('test_lab_loss',)),
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
        "                                           extra=dict({'rows': judged}, **(marker or {})))\n",
        "                                           extra=dict({'rows': judged if status == 'facts' else []},\n"
        "                                                      **(marker or {})))\n",
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

    # The next profile's round boundary, read and round losses, confirmations and commit fence.
    'round-done-ordinal-unchecked': ('lab_broker.py',
        "        if m['checkpoint_ordinal'] != len(found) + 1:\n",
        '        if False:\n',
        ('test_lab_loss',)),
    'round-done-stale-digests-taken': ('lab_broker.py',
        "        if (digests['ticket'], digests['selection']) != (m['ticket_digest'], m['selection_digest']):\n",
        '        if False:\n',
        ('test_lab_loss',)),
    'round-done-of-another-ticket': ('lab_broker.py',
        "        if round_['others'] or round_['ticket'] not in (None, m['ticket']):\n",
        '        if False:\n',
        ('test_lab_loss',)),
    'round-done-milestone-unverified': ('lab_broker.py',
        "        if m['milestone'] != code:\n",
        '        if False:\n',
        ('test_lab_loss',)),
    'round-done-without-its-round': ('lab_broker.py',
        "        if round_ is None:\n            return self._reply(m, 'REFUSED', reason='no round began since the last boundary: one ROUND_DONE ends one '\n",
        "        if round_ is None and False:\n            return self._reply(m, 'REFUSED', reason='no round began since the last boundary: one ROUND_DONE ends one '\n",
        ('test_lab_loss',)),
    'round-loss-at-every-occurrence': ('lab_broker.py',
        "                    and (c['plan'], c['attempt'], c['milestone'], c['occurrence'])\n                    == (m['plan'], m['attempt'], milestone, occurrence)), None) if milestone else None\n",
        "                    and (c['plan'], c['attempt'], c['milestone'])\n                    == (m['plan'], m['attempt'], milestone)), None) if milestone else None\n",
        ('test_lab_loss',)),
    'round-loss-before-its-checkpoint': ('lab_broker.py',
        "        number = self.ledger.record('checkpoint', record)\n        self._next_record('checkpoint', dict(record, number=number, kind='checkpoint'))\n",
        "        if due is not None:\n            fault = self._decide_loss(due, 'halt', 0, m['ticket'], m['request'], state['generation'], [], 'early')\n            return self._reply(m, 'HALT', record=fault, reason='admitted round loss')\n        number = self.ledger.record('checkpoint', record)\n        self._next_record('checkpoint', dict(record, number=number, kind='checkpoint'))\n",
        ('test_lab_loss',)),
    'read-loss-before-its-child': ('lab_broker.py',
        "                group = self._group(name, call, dict(context, **self._marker(m, address, ordinal, due)), m['boot'])\n",
        "                halt = self._read_loss(m, state, due, ordinal, groups[-1] if groups else 0, groups)\n                if halt is not None:\n                    return halt\n                group = self._group(name, call, dict(context, **self._marker(m, address, ordinal, due)), m['boot'])\n",
        ('test_lab_loss',)),
    'read-loss-skipped-unaddressed': ('lab_broker.py',
        "            if address is None and any(c['on'] == 'read' and c['plan'] == m['plan'] and c['cell'] not in self.consumed\n",
        "            if False and any(c['on'] == 'read' and c['plan'] == m['plan'] and c['cell'] not in self.consumed\n",
        ('test_lab_loss',)),
    'loss-stopped-left-due': ('lab_broker.py',
        "            self._settle_unacted('the observation was stopped before its read loss acted')\n",
        '',
        ('test_lab_loss',)),
    'schedule-passed-address-taken': ('lab_broker.py',
        "        if passed >= fault.get('occurrence', 1) and on != 'point':\n",
        '        if False:\n',
        ('test_lab_loss',)),
    'milestone-progress-as-entry': ('lab_protocol.py',
        "        return 'HEALTH_WINDOW_PROGRESS' if before == 'HEALTH_WINDOW' else 'HEALTH_WINDOW_ENTRY'\n",
        "        return 'HEALTH_WINDOW_ENTRY'\n",
        ('test_lab_loss',)),
    'round-reply-record-unchecked': ('lab_protocol.py',
        "        if status in ('STOPPED', 'REFUSED') and m['record'] != 0:\n",
        '        if False:\n',
        ('test_lab_protocol',)),
    'confirmation-beside-a-committed-session': ('lab_actions.py',
        "        if not uncommitted(row, component):\n            return 'session %d: a live session committed, ready or of unknown commitment' % row['id']\n",
        '',
        ('test_lab_loss',)),
    'confirmation-same-boot-taken': ('lab_broker.py',
        "                elif clock.reading['boot'] == old['boot']:\n                    poll['missing'] = 'the same boot: no new boot is observed yet'\n",
        '',
        ('test_lab_loss',)),
    'confirmation-second-boot-taken': ('lab_broker.py',
        '                    if len(new_boots) > TRANSITIONS[kind] or boot != new_boots[-1]:\n',
        '                    if False:\n',
        ('test_lab_loss',)),
    'unsettled-transition-ignored': ('lab_broker.py',
        "            if end is None or end['status'] not in ('OK', 'REFUSED'):\n",
        '            if False:\n',
        ('test_lab_loss',)),
    'managed-commit-unfenced': ('lab_broker.py',
        "        if name == 'COMMIT' and not self._f0_qualified():\n            return 'no managed COMMIT launches before F0 qualifies'\n",
        '',
        ('test_lab_loss',)),
    'managed-commit-fenced-only-by-its-fault': ('lab_broker.py',
        "            fenced = self._commit_fence(name, m) if self.admission['version'] == 3 else None\n",
        "            fenced = self._commit_fence(name, m) if self.admission['version'] == 3 and any(\n                c['on'] == 'cross' and c.get('crossing') == name and c['cell'] not in self.consumed for c in self.cells) else None\n",
        ('test_lab_loss',)),
    'positive-attempt-unfenced': ('lab_broker.py',
        "        if (plan, attempt) != (positive['plan'], positive['attempt']) or self._f0_qualified():\n            return None\n",
        '        return None\n',
        ('test_lab_loss',)),
    'direct-step-without-consent': ('lab_broker.py',
        "        if spec['type'] != 'DIRECT_STAGE' and control not in self.consents:\n            return 'no consent was given before arming'\n",
        '',
        ('test_lab_loss',)),
    'direct-step-after-f0': ('lab_broker.py',
        "        if self.f0 is not None:\n            return 'a direct negative control runs only before F0'\n",
        '',
        ('test_lab_loss',)),
    'checkpoint-bytes-unchecked-at-reopening': ('lab_broker.py',
        "                if self._kept_problem(digest) is not None:\n"
        "                    raise BrokerError('checkpoint %d names bytes the broker did not keep' % c['number'])\n",
        "                pass\n",
        ('test_lab_loss',)),
    # The writer latch at this change's own keeps, and the point's kept ticket and selection.
    'boundary-keep-failure-not-latched': ('lab_broker.py',
        '            stopped = self._writer_failed("the boundary\'s records could not be kept: %s" % error)\n            return self._reply(m, \'STOPPED\', reason=str(stopped))\n',
        "            return self._reply(m, 'REFUSED', reason=str(error))\n",
        ('test_lab_loss',)),
    'round-start-bytes-not-kept': ('lab_broker.py',
        "            kept.append((start['sha256'], round_['start_bytes']))\n",
        '            pass\n',
        ('test_lab_loss',)),
    'issuing-keep-failure-not-latched': ('lab_broker.py',
        "            raise self._writer_failed('the issuing records could not be kept: %s' % error) from error\n",
        '            return facts, str(error)\n',
        ('test_lab_loss',)),
    'f0-keep-failure-not-latched': ('lab_broker.py',
        "            raise self._writer_failed('the F0 capability record could not be kept: %s' % error) from error\n",
        '            raise\n',
        ('test_lab_loss',)),
    'schedule-keep-failure-not-latched': ('lab_broker.py',
        "            raise self._writer_failed('the fault schedule could not be kept: %s' % error) from error\n",
        '            raise\n',
        ('test_lab_loss',)),
    'point-records-not-kept': ('lab_broker.py',
        "                for name in ('ticket', 'selection'):\n                    self._keep(*retained[name])\n",
        '                pass\n',
        ('test_lab_loss',)),
    'point-of-another-ticket-halts': ('lab_broker.py',
        '                m[\'ticket\'], m[\'plan\'], m[\'attempt\'], a[\'installation\'], a[\'component\']):\n            return {}, "the stored ticket is not the point\'s"\n',
        "                m['ticket'], m['plan'], m['attempt'], a['installation'], a['component']):\n            pass\n",
        ('test_lab_loss',)),
    'point-keep-failure-not-latched': ('lab_broker.py',
        '                stopped = self._writer_failed("the point\'s records could not be kept: %s" % error)\n                return self._reply(m, \'REFUSED\', reason=str(stopped))\n',
        "                return self._reply(m, 'REFUSED', reason=str(error))\n",
        ('test_lab_loss',)),
    'point-kept-bytes-unchecked-at-reopening': ('lab_broker.py',
        "                if c.get('on') == 'point' and self.admission['version'] == 3 and any(\n",
        '                if False and any(\n',
        ('test_lab_loss',)),
    # Recovery of F0 and the schedule from kept bytes, whole inventories and the health loss.
    'f0-capability-unchecked-at-reopening': ('lab_broker.py',
        '                why = self._decision_problem(c)\n',
        '                why = None\n',
        ('test_lab_loss',)),
    'f0-decision-relation-unchecked': ('lab_broker.py',
        "        if (c['branch'], c['qualified'], c['predicate_sha256']) != (\n",
        "        if False and (c['branch'], c['qualified'], c['predicate_sha256']) != (\n",
        ('test_lab_loss',)),
    'own-row-takes-a-partial-inventory': ('lab_actions.py',
        "    if not reading.get('whole'):\n        return None, 'the global session inventory is not whole'\n",
        '',
        ('test_lab_loss',)),
    'schedule-summary-unchecked': ('lab_broker.py',
        "        if c['cells'] != faults:\n",
        '        if False:\n',
        ('test_lab_loss',)),
    'health-loss-reads-every-user': ('lab_broker.py',
        '                    # composition is read and no later preparation is used.\n                    break\n',
        '                    pass\n',
        ('test_lab_loss',)),
    # The full user setup package (full_users.py): its forms, gates, actions, records and process
    # join.
    'user-start-stderr-failure-accepted': ('full_users.py',
        "    if (code, stdout, stderr) == (0, '', 'Error: could not start user\\n'):\n"
        "        return 'FAILED'\n",
        "    if (code, stdout, stderr) == (0, '', 'Error: could not start user\\n'):\n"
        "        return 'STARTED'\n",
        ('test_full_users',)),
    'user-dump-started-states-unchecked': ('full_users.py',
        "    if started != {u['id']: u['state'] for u in users if u['state'] != '-1'}:\n",
        '    if False:\n',
        ('test_full_users',)),
    'user-dump-cached-ids-unchecked': ('full_users.py',
        "        _fail('the cached user IDs and the users section disagree')\n",
        '        pass\n',
        ('test_full_users',)),
    'user-dump-trailing-accepted': ('full_users.py',
        '    if lines.peek() is not None:\n'
        "        _fail('the user dump goes on after its last section: %r' % lines.peek()[:120])\n",
        '',
        ('test_full_users',)),
    'user-dump-two-current-users': ('full_users.py',
        "    if dump['current_user'] is not None and dump['current_user'] != dump['mediator_current_user']:\n",
        '    if False:\n',
        ('test_full_users',)),
    'user-dump-serial-twice': ('full_users.py',
        "    if ids != sorted(set(ids)) or len({u['serial'] for u in users}) != len(users):\n",
        '    if ids != sorted(set(ids)):\n',
        ('test_full_users',)),
    'user-effective-restrictions-unchecked': ('full_users.py',
        "        if lists['cached'] is not None and set(lists['cached']) != effective:\n",
        '        if False:\n',
        ('test_full_users',)),
    'user-list-disagreement-accepted': ('full_users.py',
        '    if rows != expected:\n'
        "        return 'the user list and the user dump disagree'\n",
        '',
        ('test_full_users',)),
    'restriction-names-without-digits': ('lab_actions.py',
        "                                                           or not re.fullmatch(r'[a-z][a-z0-9_]{0,63}', r)\n",
        "                                                           or not re.fullmatch(r'[a-z_]{1,64}', r)\n",
        ('test_full_users',)),
    'created-type-unchecked': ('full_users.py',
        "    if u['type'] != SECONDARY_TYPE:\n"
        "        return None, 'the returned user is of another type: %s' % u['type']\n",
        '',
        ('test_full_users',)),
    'created-serial-reuse-accepted': ('full_users.py',
        "    if u['serial'] in created['serials_before']:\n",
        '    if False:\n',
        ('test_full_users',)),
    'created-id-reuse-accepted': ('full_users.py',
        "    if created['user'] in created['before_users']:\n",
        '    if False:\n',
        ('test_full_users',)),
    'removal-from-a-partial-read': ('full_users.py',
        "    if reading is None or not reading['whole']:\n"
        '        return None\n'
        '    shown = ',
        '    if reading is None:\n'
        '        return None\n'
        '    shown = ',
        ('test_full_users',)),
    'created-resolved-from-a-partial-read': ('lab_actions.py',
        "        return None, 'the create action has identified no user'\n"
        "    if not reading['whole']:\n"
        "        return None, 'the user inventory is not whole'\n",
        "        return None, 'the create action has identified no user'\n",
        ('test_full_users',)),
    'creation-unsupported-unchecked': ('full_users.py',
        "    if not user_limits['supports_multiple']:\n"
        "        return 'switchable users are not supported'\n",
        '',
        ('test_full_users',)),
    'creation-restriction-unchecked': ('full_users.py',
        "    if 'no_add_user' in user_limits['creator_restrictions']:\n",
        '    if False:\n',
        ('test_full_users',)),
    'creation-maximum-unchecked': ('full_users.py',
        "    if (user_limits['limit_reached'] or user_limits['type_allowed'] <= user_limits['type_count']\n"
        "            or user_limits['max_switchable'] <= 1):\n",
        '    if False:\n',
        ('test_full_users',)),
    'creation-beside-another-user': ('full_users.py',
        "    if [u['id'] for u in reading['users']] != [0]:\n",
        '    if False:\n',
        ('test_full_users',)),
    'start-running-limit-unchecked': ('full_users.py',
        "    if running + 1 > user_limits['max_running']:\n",
        '    if False:\n',
        ('test_full_users',)),
    'start-stopped-user-unnoticed': ('lab_broker.py',
        "        if outcome['stopped']:\n"
        "            return 'UNEXPECTED', outcome, 'a user that"
        " ran before the start no longer runs', True, postreads\n",
        '',
        ('test_full_users',)),
    'start-reply-trusted': ('lab_broker.py',
        "        if outcome['reply'] == 'STARTED' and runs(after):\n",
        "        if outcome['reply'] == 'STARTED':\n",
        ('test_full_users',)),
    'switch-foreground-unconfirmed': ('lab_broker.py',
        "            return (poll['current'] == user['id'] and s"
        "tate is not None and state['condition'] == 'FOREGROUND'\n"
        "                    and poll['visible'] is True)\n",
        '            return True\n',
        ('test_full_users',)),
    'switch-visibility-unconfirmed': ('lab_broker.py',
        "            return (poll['current'] == user['id'] and s"
        "tate is not None and state['condition'] == 'FOREGROUND'\n"
        "                    and poll['visible'] is True)\n",
        "            return (poll['current'] == user['id'] and st"
        "ate is not None and state['condition'] == 'FOREGROUND')\n",
        ('test_full_users',)),
    'switch-outgoing-background-unchecked': ('lab_broker.py',
        "        elif current != 0 and (len(outgoing) != 1 or '"
        "no_run_in_background' in outgoing[0]['restrictions']):\n",
        '        elif False:\n',
        ('test_full_users',)),
    'setup-without-its-recorded-completion': ('lab_broker.py',
        "        if (polled[0] == '1' and outcome['initialized'] an"
        "d state is not None and state['condition'] == 'FOREGROUND'\n",
        "        if (outcome['initialized'] and state is not None and state['condition'] == 'FOREGROUND'\n",
        ('test_full_users',)),
    'setup-with-ce-locked': ('lab_broker.py',
        "        if current != user['id'] or state is None or state"
        "['condition'] != 'FOREGROUND' or not state['ce_unlocked']:\n",
        "        if current != user['id'] or state is None or state['condition'] != 'FOREGROUND':\n",
        ('test_full_users',)),
    'fixture-replies-trusted': ('lab_broker.py',
        "        if (outcome['uid'] == expected and outcome['use"
        "r_path'] == path and outcome['digest'] == pin['sha256']\n"
        "                and outcome['enabled'] == 'enabled'):\n",
        "        if outcome['enabled'] == 'enabled':\n",
        ('test_full_users',)),
    'fixture-bytes-unchecked': ('lab_broker.py',
        "        if digest is None or digest != pin['sha256']:\n",
        '        if digest is None:\n',
        ('test_full_users',)),
    'created-record-unchecked-at-reopening': ('lab_broker.py',
        "        if full_users.classify_create(*self._capture_reply(capture)) != ('CREATED', c['user']):\n",
        '        if False:\n',
        ('test_full_users',)),
    'identified-record-unchecked-at-reopening': ('lab_broker.py',
        "        if (user['id'], user['serial'], user['type'], user['"
        "flags']) != (c['user'], c['serial'], c['type'], c['flags']):\n",
        '        if False:\n',
        ('test_full_users',)),
    'typed-reading-not-rederived': ('lab_broker.py',
        "        if value is not NotImplemented and ledgers.encode_json(value) != ledgers.encode_json(c.get('reading')):\n",
        '        if False:\n',
        ('test_full_users',)),
    'typed-reading-compared-by-value': ('lab_broker.py',
        "        if value is not NotImplemented and ledgers.encode_json(value) != ledgers.encode_json(c.get('reading')):\n",
        "        if value is not NotImplemented and value != c.get('reading'):\n",
        ('test_full_users',)),
    'serials-forgotten-on-reopening': ('lab_broker.py',
        "                if c.get('reader') == 'inventory' and c.get('status') == 'facts':\n"
        "                    self._serials(c['reading'])\n",
        '',
        ('test_full_users',)),
    'two-main-pids-accepted': ('full_users.py',
        "        if owner['id'] in joined:\n"
        "            _fail('two main SystemUI processes for user %d' % owner['id'])\n",
        '',
        ('test_full_users',)),
    'process-name-unchecked': ('full_users.py',
        "        if c['name'] != SYSTEMUI or c['comm'] != COMM or c['status_name'] != COMM:\n",
        '        if False:\n',
        ('test_full_users',)),
    'process-start-identity-not-rechecked': ('full_users.py',
        "        if recheck.get(pid) != {'comm': c['comm'], 'start_ticks': c['start_ticks']}:\n",
        '        if False:\n',
        ('test_full_users',)),
    'process-denied-read-as-absence': ('full_users.py',
        "    if (code, stdout, stderr) == (1, '', ''):\n"
        '        return []\n',
        '    if code == 1:\n'
        '        return []\n',
        ('test_full_users',)),
    'process-quiet-absence-not-repeated': ('full_users.py',
        '        if not pids and parse_pidof(*self._read(PIDOF)):\n',
        '        if False:\n',
        ('test_full_users',)),
    'process-join-by-listed-order': ('full_users.py',
        "        owner = by_uid.get(c['uids'][0])\n",
        "        owner = sorted(by_uid.values(), key=lambda u: u['id'])[list(candidates).index(pid) % len(by_uid)]\n",
        ('test_full_users',)),
    'created-user-of-any-type': ('lab_actions.py',
        '            if value != SECONDARY_TYPE:\n',
        '            if False:\n',
        ('test_full_users',)),
    'create-used-more-than-once': ('lab_actions.py',
        "    if len(creates) > 1 or any(s['max_uses'] != 1 for s in creates):\n",
        '    if False:\n',
        ('test_full_users',)),
    'created-ephemeral-user-accepted': ('full_users.py',
        "    if u['flags'] & (FLAGS['EPHEMERAL'] | FLAGS['GUEST']):\n",
        '    if False:\n',
        ('test_full_users',)),
    'user-type-enablement-read-as-a-number': ('full_users.py',
        "        types[name] = {'enabled': _bool(values['mEnabled'], 'mEnabled'),\n",
        "        types[name] = {'enabled': _int(values['mEnabled'], -(1 << 31), (1 << 31) - 1, 'mEnabled'),\n",
        ('test_full_users',)),
    'user-type-enablement-number-accepted': ('full_users.py',
        "        types[name] = {'enabled': _bool(values['mEnabled'], 'mEnabled'),\n",
        "        types[name] = {'enabled': _bool({'1': 'true', '0': 'false'}.get(values['mEnabled'], values['mEnabled']),\n"
        "                                        'mEnabled'),\n",
        ('test_full_users',)),
    'user-limit-enablement-form-unchecked': ('full_users.py',
        "    for name in ('supports_multiple', 'dump_supports', 'limit_reached', 'type_enabled'):\n",
        "    for name in ('supports_multiple', 'dump_supports', 'limit_reached'):\n",
        ('test_full_users',)),
    'creation-type-enablement-read-loosely': ('full_users.py',
        "    if user_limits['type_enabled'] is not True:\n",
        "    if not user_limits['type_enabled']:\n",
        ('test_full_users',)),
    'creation-type-disabled-unchecked': ('full_users.py',
        "    if user_limits['type_enabled'] is not True:\n"
        "        return 'the full secondary user type is not enabled'\n",
        '',
        ('test_full_users',)),
    'process-start-identity-after-its-identity-fields': ('full_users.py',
        "            stat = parse_stat(*self._read(proc_command(pid, 'stat')), pid)\n"
        "            name = parse_cmdline(*self._read(proc_command(pid, 'cmdline')))\n"
        "            status = parse_status(*self._read(proc_command(pid, 'status')), pid)\n",
        "            name = parse_cmdline(*self._read(proc_command(pid, 'cmdline')))\n"
        "            status = parse_status(*self._read(proc_command(pid, 'status')), pid)\n"
        "            stat = parse_stat(*self._read(proc_command(pid, 'stat')), pid)\n",
        ('test_full_users',)),
    'user-effects-past-an-unsettled-transition': ('lab_broker.py',
        "        if spec['type'] not in lab_actions.USER_TYPES:\n"
        "            return None\n"
        "        return self._unsettled_transition()\n",
        '        return None\n',
        ('test_full_users',)),
    'user-gate-not-consulted': ('lab_broker.py',
        '        if gate is None:\n'
        '            gate = self._user_gate(spec)\n',
        '',
        ('test_full_users',)),
    # The health package: the UI state form, the readers of bits 0, 2 and 3, the composer, the
    # baselines, the side metadata codec, USER_PIN and CE_SENTINEL.
    'ui-state-unavailable-read-as-false': ('health_compose.py',
        "            values[name], missing[name] = None, value[len('unavailable:'):]\n",
        "            values[name], missing[name] = False, value[len('unavailable:'):]\n",
        ('test_health',)),
    'ui-state-end-marker-unchecked': ('health_compose.py',
        "    if lines[-1] != 'end=' + UI_STATE_HEADER:\n        raise FormError('a UI state reply without its end marker')\n",
        '',
        ('test_health',)),
    'ui-state-user-unchecked': ('health_compose.py',
        "    head = [UI_STATE_HEADER, 'user=%d' % _user(user), 'capabilities=' + ','.join(UI_STATE_CAPABILITIES)]\n",
        "    head = [UI_STATE_HEADER, (lines[1:2] or [''])[0], 'capabilities=' + ','.join(UI_STATE_CAPABILITIES)]\n",
        ('test_health',)),
    'ui-state-helper-bytes-unchecked': ('health_compose.py',
        "        if stderr != '' or readback.file_digest(code, stdout, UI_STATE_HELPER) != UI_STATE_HELPER_SHA256:\n",
        "        if stderr != '':\n",
        ('test_health',)),
    'ui-state-helper-bytes-not-read-again': ('health_compose.py',
        '    reading = parse_ui_state(*run(ui_state_command(user)), user)\n    admitted()\n',
        '    reading = parse_ui_state(*run(ui_state_command(user)), user)\n',
        ('test_health',)),
    'ui-state-invocation-unbounded': ('health_compose.py',
        '    return bool(match) and int(match[1]) <= UI_STATE_MAX_USER\n',
        '    return bool(match)\n',
        ('test_health',)),
    'marker-elsewhere-accepted': ('health_compose.py',
        '    if original and not elsewhere:\n',
        '    if original:\n',
        ('test_health',)),
    'marker-text-alone-accepted': ('health_compose.py',
        '    marked = (text.endswith(MARKER_A) and description.endswith(MARKER_A)\n              and bool(TIME.fullmatch(text[:-len(MARKER_A)]) and TIME.fullmatch(description[:-len(MARKER_A)])))\n',
        '    marked = text.endswith(MARKER_A) and bool(TIME.fullmatch(text[:-len(MARKER_A)]))\n',
        ('test_health',)),
    'clock-first-of-several-taken': ('health_compose.py',
        '    if len(clocks) != 1:\n',
        '    if not clocks:\n',
        ('test_health',)),
    'clock-window-type-unchecked': ('health_compose.py',
        "    if window.get('type') != STATUS_BAR_TYPE or not _visible(node.get('bounds')):\n",
        "    if not _visible(node.get('bounds')):\n",
        ('test_health',)),
    'clock-notice-in-view-accepted': ('health_compose.py',
        "    if notice_package is not None and any(n.get('package') == notice_package for n in display.iter('node')):\n",
        '    if False:\n',
        ('test_health',)),
    'capture-foreground-unchecked': ('health_compose.py',
        "        if condition['current_user'] != user:\n            return 'the user was not in the foreground %s the capture' % name\n",
        '',
        ('test_health',)),
    'capture-unavailable-taken-as-awake': ('health_compose.py',
        "        if values['interactive'] is not True:\n",
        "        if values['interactive'] is False:\n",
        ('test_health',)),
    'capture-insecure-unlock-accepted': ('health_compose.py',
        "        if values['device_secure'] is not True:\n            return 'the user has no secure credential %s the capture: not a legitimate unlock' % name\n",
        '',
        ('test_health',)),
    'unlock-insecure-dismissal-accepted': ('health_compose.py',
        "    if b['device_secure'] is not True or b['keyguard_secure'] is not True:\n",
        '    if False:\n',
        ('test_health',)),
    'unlock-without-a-genuine-lock': ('health_compose.py',
        "    if b['keyguard_locked'] is not True or b['device_locked'] is not True:\n",
        '    if False:\n',
        ('test_health',)),
    'unlock-left-locked-accepted': ('health_compose.py',
        "    if a['keyguard_locked'] or a['device_locked']:\n        return 'BAD', 'the credential unlock left the user locked'\n",
        '',
        ('test_health',)),
    'unlock-nonce-unchecked': ('health_compose.py',
        "    if ce_read.get('status') != 'PRESENT' or ce_read.get('nonce') != origin['nonce']:\n",
        "    if ce_read.get('status') != 'PRESENT':\n",
        ('test_health',)),
    'unlock-current-ce-unchecked': ('health_compose.py',
        "    if values['ce_unlocked'] is not True or listed['state'] != 'RUNNING_UNLOCKED':\n",
        '    if False:\n',
        ('test_health',)),
    'identity-context-unchecked': ('health_compose.py',
        "    if process['context'] != expected['context']:\n",
        '    if False:\n',
        ('test_health',)),
    'identity-app-id-unchecked': ('health_compose.py',
        "    if processes['app_id'] != expected['app_id'] or process['uid'] != expected['uid']:\n",
        '    if False:\n',
        ('test_health',)),
    'identity-plan-base-unchecked': ('health_compose.py',
        "    if plan_base is not None and (plan_base['uid'], plan_base['context']) != (expected['uid'], expected['context']):\n",
        '    if False:\n',
        ('test_health',)),
    'identity-process-loss-as-failure': ('health_compose.py',
        "        return row(UID_AND_CONTEXT, 'UNKNOWN', 'no main SystemUI process of the user now: process loss alone is no '\n",
        "        return row(UID_AND_CONTEXT, 'BAD', 'no main SystemUI process of the user now: process loss alone is no '\n",
        ('test_health',)),
    'composer-hook-assumed-held': ('health_compose.py',
        "                rows[bit] = row(bit, 'UNKNOWN', HOOKS[bit])\n",
        "                rows[bit] = row(bit, 'HELD', '', [0])\n",
        ('test_health',)),
    'composer-unadmitted-command-read-as-unavailable': ('health_compose.py',
        "            raise ComposerError('a command the reader does not admit: %s' % error) from error\n",
        '            raise lab_readers.Unavailable(str(error)) from error\n',
        ('test_health',)),
    'baseline-unavailable-resets': ('health_baseline.py',
        "    whole = [b for b in baselines if b.get('status') == 'facts' and b.get('brackets')]\n",
        "    whole = [b for b in baselines if b.get('brackets')]\n",
        ('test_health',)),
    'baseline-incomplete-relied-on': ('health_baseline.py',
        "    if not facts['complete']:\n",
        '    if False:\n',
        ('test_health',)),
    'baseline-after-the-first-probe': ('health_baseline.py',
        "                      and (first is None or b['brackets']['end']['elapsed'] <= first)]\n",
        ']\n',
        ('test_health',)),
    'baseline-span-start-ignored': ('health_baseline.py',
        "    if unlocked is not None and unlocked > window['start']:\n",
        '    if False:\n',
        ('test_health',)),
    'identity-conflict-unrecorded': ('health_baseline.py',
        "        elif first != identity:\n            conflicts.append(identity['serial'])\n",
        '',
        ('test_health',)),
    'identity-any-active-copy': ('health_baseline.py',
        "    if active['classification'] != 'FACTORY_COPY':\n        return refused('the factory copy is not active')\n",
        '',
        ('test_health',)),
    'identity-system-process-unchecked': ('health_baseline.py',
        "    if len(system) != 1 or (system[0]['uid'], system[0]['context']) != (current['uid'], current['context']):\n",
        '    if len(system) != 1:\n',
        ('test_health',)),
    'preparation-result-path-unchecked': ('health_records.py',
        "        if match is None or match[1] != operation or type(capture['acknowledged']) is not bool:\n",
        "        if match is None or type(capture['acknowledged']) is not bool:\n",
        ('test_health',)),
    'preparation-result-user-unchecked': ('health_records.py',
        "    if (result['user'], result['serial']) != (user, serial):\n        return 'a preparation result of another user or serial'\n",
        '',
        ('test_health',)),
    'baseline-complete-without-witness': ('health_records.py',
        "    if facts['complete'] is not complete:\n",
        '    if False:\n',
        ('test_health',)),
    'preparation-result-unchecked': ('lab_broker.py',
        "            if classification == 'PREPARED' and health_records.preparation_problem(\n",
        '            if False and health_records.preparation_problem(\n',
        ('test_health',)),
    'pin-output-not-withheld': ('lab_broker.py',
        '        if private is not None and (stdout or stderr or residual):\n',
        '        if False:\n',
        ('test_health',)),
    'pin-replaces-a-credential': ('lab_broker.py',
        "        if before['values']['device_secure'] is not False:\n",
        '        if False:\n',
        ('test_health',)),
    'pin-repeated-for-a-serial': ('lab_broker.py',
        "        if self.pins.get(serial):\n            return 'REFUSED', None, 'a PIN was already attempted for this serial: it is never replaced', True, []\n",
        '',
        ('test_health',)),
    'pin-set-without-its-readback': ('lab_broker.py',
        "        if outcome['reply'] == 'SET' and secure:\n",
        "        if outcome['reply'] == 'SET':\n",
        ('test_health',)),
    'pin-not-a-user-action': ('lab_actions.py',
        "USER_TYPES = ('USER_CREATE', 'USER_START', 'USER_SWITCH', 'USER_SETUP', 'USER_FIXTURE', 'USER_PIN', 'CE_SENTINEL')\n",
        "USER_TYPES = ('USER_CREATE', 'USER_START', 'USER_SWITCH', 'USER_SETUP', 'USER_FIXTURE')\n",
        ('test_health',)),
    'sentinel-another-nonce-accepted': ('lab_broker.py',
        "        if outcome['reply'] == 'WRITTEN' and found == {'status': 'PRESENT', 'nonce': nonce}:\n",
        "        if outcome['reply'] == 'WRITTEN' and found.get('status') == 'PRESENT':\n",
        ('test_health',)),
    'sentinel-rewritten': ('lab_broker.py',
        "        if self.sentinels.get(serial):\n            return 'REFUSED', None, 'a CE sentinel was already attempted for this serial: it is never rewritten', True, []\n",
        '',
        ('test_health',)),
    'sentinel-framework-ce-unchecked': ('lab_broker.py',
        "        if before is None or before['values']['ce_unlocked'] is not True:\n",
        '        if before is None:\n',
        ('test_health',)),
    'setup-readback-unchecked': ('lab_broker.py',
        "        if reading['values'][wanted[0]] is not wanted[1]:\n",
        '        if False:\n',
        ('test_health',)),
    'setup-settlement-without-its-intent': ('lab_broker.py',
        "            if intent is None or c['intent'] != intent['number'] or len(kept) != 1 or intent['begin'] != c['begin']:\n",
        '            if intent is None:\n',
        ('test_health',)),
    'identity-conflicts-unchecked-at-reopening': ('lab_broker.py',
        "        if conflicts != c['conflicts']:\n            raise BrokerError('identity baseline %d names other conflicts than its projection makes' % c['number'])\n",
        '',
        ('test_health',)),
    # An identity baseline's projection taken as its group states it, not as its children's own
    # captures give it: a consistent rewrite of the projection and its manifest restores another
    # identity than the factory reads showed.
    'identity-projection-not-rederived': ('lab_broker.py',
        "            raise BrokerError(\"identity baseline %d is not what its children's captures give\" % c['number'])\n",
        '            pass\n',
        ('test_health',)),
    # A private command's undecoded residual left out of the withholding rule: an oversized,
    # malformed or cut reply puts the PIN in the ledger as residual bytes.
    'private-residual-public': ('lab_broker.py',
        "        residual = bytes(getattr(result, 'residual', b'') or b'')\n",
        "        residual = b''\n",
        ('test_health',)),
    # The process history reader of bit 1: its reply parser, its join, and the joins the broker
    # gives it.
    # The helper's reply: an end marker that does not count or digest its lines is taken whole.
    'process-reply-end-unchecked': ('process_health.py',
        "    if int(end[1]) != len(lines) - 1 or hashlib.sha256(body.encode('ascii')).hexdigest() != end[2]:\n",
        '    if False:\n',
        ('test_witness',)),
    # A count above the helper's bound is read as rows, not as an impossible count.
    'process-reply-impossible-count': ('process_health.py',
        '        if int(count) > MAX_ROWS:\n',
        '        if False:\n',
        ('test_witness',)),
    # A number of another form, a sign or a leading zero, read as a number.
    'process-reply-number-loose': ('process_health.py',
        "_INT = r'-?(?:0|[1-9][0-9]{0,18})'\n",
        "_INT = r'[-+]?[0-9]{1,19}'\n",
        ('test_witness',)),
    # A string token in another encoding than the helper's read as its text.
    'process-reply-token-not-canonical': ('process_health.py',
        "    if encode_text(text) != token:\n        raise FormError('a string not in the helper encoding')\n",
        '',
        ('test_witness',)),
    # An empty current list, which the service never returns, read as no current error.
    'process-reply-empty-list-accepted': ('process_health.py',
        "        if name == 'current' and status == 'OK' and returned == 'list' and not items:\n",
        '        if False:\n',
        ('test_witness',)),
    # A part that was not read whole judged as if it had no rows.
    'witness-partial-read-as-empty': ('health_witness.py',
        "        if part['status'] != 'OK':\n",
        '        if False:\n',
        ('test_witness',)),
    # A report a baseline already held taken as a new failure.
    'witness-baseline-report-qualifies': ('health_witness.py',
        '    elif joined and _entry_key(joined[0]) in old_errors:\n',
        '    elif False:\n',
        ('test_witness',)),
    # Two reports of one process taken as one failure.
    'witness-duplicate-reports-qualify': ('health_witness.py',
        '    if len(joined) > 1:\n',
        '    if False:\n',
        ('test_witness',)),
    # A report joined by its PID alone, whatever its UID and process name.
    'witness-report-joined-by-pid-alone': ('health_witness.py',
        '    joined = [e for e in related if live is not None and (e[1], e[2]) == (live[0], live[2])\n'
        '              and _name(e[3]) == process_health.PACKAGE]\n',
        '    joined = [e for e in related if live is not None and e[1] == live[0]]\n',
        ('test_witness',)),
    # An updated reason or time of an earlier exit record taken as a new exit.
    'witness-update-counts-as-new': ('health_witness.py',
        '    updates = [r for r in new_rows if any(_key(s) == _key(r) and s != r for s in seen_rows)]\n',
        '    updates = []\n',
        ('test_witness',)),
    # A held row beside an exit history that changed since the baselines.
    'witness-history-change-holds': ('health_witness.py',
        "        if exclusions:\n            return unknown(exclusions)\n        return 'HELD', '', None\n",
        "        return 'HELD', '', None\n",
        ('test_witness',)),
    # The identity taken as living whatever the discovery around the call shows.
    'witness-identity-assumed-living': ('health_witness.py',
        '    state = _state(before, after, born)\n',
        "    state = 'ALIVE'\n",
        ('test_witness',)),
    # The current list taken as covering another user than the shell's without its qualification.
    'witness-cross-user-assumed': ('health_witness.py',
        '        if user != SHELL_USER_ID and not cross_user:\n',
        '        if False:\n',
        ('test_witness',)),
    # A row placed in time without checking that the wall clock kept its offset.
    'witness-wall-offset-unchecked': ('health_witness.py',
        '    if max(offsets) - min(offsets) > OFFSET_TOLERANCE_MS:\n',
        '    if False:\n',
        ('test_witness',)),
    # A row from before the identity was last seen living taken as its exit.
    'witness-late-row-placed': ('health_witness.py',
        '        elif at <= alive_at + SCALE_TOLERANCE_MS:\n',
        '        elif False:\n',
        ('test_witness',)),
    # A row of another UID taken as the identity's.
    'witness-row-uid-unchecked': ('health_witness.py',
        "    if (row[2], row[3], row[4]) != (birth['uid'],) * 3:\n        return 'another UID'\n",
        '',
        ('test_witness',)),
    # Exits of other reasons, a low memory kill or a user stop included, taken as a crash.
    'witness-any-reason-qualifies': ('health_witness.py',
        'QUALIFIED_REASONS = (4, 5, 6)\n',
        'QUALIFIED_REASONS = tuple(range(17))\n',
        ('test_witness',)),
    # Two exit rows of one identity taken as one exit.
    'witness-duplicate-rows-qualify': ('health_witness.py',
        '    if len(matched) > 1:\n',
        '    if False:\n',
        ('test_witness',)),
    # A new publication taken as independent evidence that a row belongs to this boot.
    'witness-freshness-assumed': ('health_witness.py',
        "        evidence = freshness.fresh(candidates[0], birth, d['loss'], context) if freshness is not None else None\n",
        "        evidence = {'assumed': 'a new publication'}\n",
        ('test_witness',)),
    # A loss pending past its declared bound.
    'witness-pending-unbounded': ('health_witness.py',
        '    if settled or samples[3][0] > pending_until:\n',
        '    if settled:\n',
        ('test_witness',)),
    # One whole baseline taken as repeated baselines.
    'witness-baselines-not-repeated': ('health_witness.py',
        '    if len(repeats) < BASELINE_REPEATS:\n',
        '    if not repeats:\n',
        ('test_witness',)),
    # A boot change since the baselines ignored, so an identity continues across a boot.
    'witness-boot-change-ignored': ('health_witness.py',
        "    if any(b[3]['boot'] != observation['boot'] for b in baselines):\n",
        '    if False:\n',
        ('test_witness',)),
    # The broker passes only the relied baseline, never the repeated ones.
    'repeated-baselines-not-passed': ('lab_broker.py',
        "                              'baselines': self._repeated(m['boot'], user, serial, window),\n",
        "                              'baselines': self._repeated(m['boot'], user, serial, window)[-1:],\n",
        ('test_witness',)),
    # The broker passes no earlier probe, so a loss has no last living read and no first gone one.
    'witness-trail-not-passed': ('lab_broker.py',
        "                              'trail': self._trail(m['boot'], user, serial)}",
        "                              'trail': []}",
        ('test_witness',)),
    # A baseline error forgotten once its report is cleared while the same process lives on.
    'witness-baseline-report-holds': ('health_witness.py',
        '        if any(_relates(e, user, uid) for e in old_entries):\n',
        '        if False:\n',
        ('test_witness',)),
    # Rows first read in the window left out of the earlier observations, so their update is new.
    'witness-window-rows-forgotten': ('health_witness.py',
        '    seen_rows = old_rows + earlier_rows\n',
        '    seen_rows = old_rows\n',
        ('test_witness',)),
    # A row placed after the identity was already gone taken as its exit.
    'witness-loss-upper-bound-ignored': ('health_witness.py',
        '        elif at > upper + SCALE_TOLERANCE_MS:\n',
        '        elif False:\n',
        ('test_witness',)),
    # A held probe's clock left out, so a wall clock step it read is forgotten.
    'witness-held-clock-forgotten': ('health_witness.py',
        '            offsets += [w - e for e, w in replied]\n',
        '            offsets += [] if held else [w - e for e, w in replied]\n',
        ('test_witness',)),
    # An older baseline without its process vetoes the whole ones after it, as in version 1.
    'witness-incomplete-baseline-vetoes': ('health_witness.py',
        "        if _foreign(facts['history']) or _foreign(facts['current_errors']):\n",
        "        if not facts['complete']:\n            return None, 'a baseline before the window is not whole'\n"
        "        if _foreign(facts['history']) or _foreign(facts['current_errors']):\n",
        ('test_witness',)),
    # An update excluded only on its first read, so its new contents read again count as new.
    'witness-update-read-again-new': ('health_witness.py',
        '    updates = [r for r in new_rows if any(_key(s) == _key(r) and s != r for s in seen_rows)]\n',
        '    updates = [r for r in new_rows if _key(r) in {_key(s) for s in seen_rows} and r not in seen_rows]\n',
        ('test_witness',)),
    # An earlier read's clock kept only when it judged this birth identity, so a wall clock step a
    # partial read saw is forgotten.
    'witness-partial-clock-forgotten': ('health_witness.py',
        '            offsets += [w - e for e, w in replied]\n',
        "            offsets += [w - e for e, w in replied] if held or (earlier or {}).get('birth') == birth else []\n",
        ('test_witness',)),
    # A partial read's whole discovery left out, so the loss it bounds, above or below, stays wider.
    'witness-partial-discovery-forgotten': ('health_witness.py',
        "        elif (seen is not None and (earlier['birth'] == birth or (earlier['birth'] is None and begin >= relied_end))\n",
        "        elif (seen is not None and earlier['birth'] == birth\n",
        ('test_witness',)),
    # A partial read before the relied baseline taken as the identity's loss, though no baseline had
    # yet read it living.
    'witness-discovery-before-baseline': ('health_witness.py',
        "        elif (seen is not None and (earlier['birth'] == birth or (earlier['birth'] is None and begin >= relied_end))\n",
        "        elif (seen is not None and (earlier['birth'] == birth or earlier['birth'] is None)\n",
        ('test_witness',)),
    # An earlier decision's observation taken without checking that it names its discovery.
    'witness-observation-form-unchecked': ('health_witness.py',
        "    if observed is not None and (not isinstance(observed, dict) or set(observed) != set(OBSERVED_KEYS)\n"
        "                                 or observed['state'] not in STATES or not _samples(observed['samples'])\n"
        "                                 or not all(_process(observed[k]) for k in ('before', 'after'))):\n",
        "    if observed is not None and (not isinstance(observed, dict) or observed.get('state') not in STATES\n"
        "                                 or not _samples(observed.get('samples'))):\n",
        ('test_witness',)),
    # An earlier read that found the identity only after the call skipped: neither its living
    # observation nor its contradiction counts.
    'witness-unknown-discovery-ignored': ('health_witness.py',
        "        if then == 'GONE':\n",
        "        if then == 'UNKNOWN':\n            continue\n        if then == 'GONE':\n",
        ('test_witness',)),
    # That read's living observation kept but its identity contradiction dropped, so it may join.
    'witness-contradiction-joins': ('health_witness.py',
        "                doubts.append('an earlier read found the identity only after the call: an identity '\n"
        "                              'contradiction, never a qualified join')\n",
        '                pass\n',
        ('test_witness',)),
    # A read that finds the identity living after one that found it gone skipped, not refused.
    'witness-found-after-gone-skipped': ('health_witness.py',
        "        if first_gone is not None:\n            return unknown(['the identity was seen again after it was gone'])\n",
        '        if first_gone is not None:\n            continue\n',
        ('test_witness',)),
    # An earlier read that found the identity before the call only, placed at its bracket, which
    # the composer's other reads widen.
    'witness-went-bracket-anchored': ('health_witness.py',
        '            living.append(replied[0][0])\n            first_gone = replied[3][0]\n',
        "            living.append(begin)\n            first_gone = entry['brackets']['end']['elapsed']\n",
        ('test_witness',)),
    # This read's discovery before the call, which found the identity living, left out.
    'witness-found-before-the-call-ignored': ('health_witness.py',
        "    if state == 'WENT':\n        # This read found the identity before the call: living at its first sample.\n"
        '        living.append(samples[0][0])\n',
        '',
        ('test_witness',)),
    # A baseline, or this read, finding the identity living after a read that found it gone is not
    # checked.
    'witness-living-after-gone-unchecked': ('health_witness.py',
        '    if first_gone is not None and first_gone < alive_at:\n',
        '    if False:\n',
        ('test_witness',)),
    # A baseline that misses the identity between baselines that find it taken as no contradiction.
    'witness-baseline-contradiction-ignored': ('health_witness.py',
        '        elif living:\n',
        '        elif False:\n',
        ('test_witness',)),
    # An exit row placed between the last baseline and the window's start taken as a newly induced
    # failure of the window.
    'witness-prewindow-row-qualifies': ('health_witness.py',
        '        elif at <= opened:\n',
        '        elif False:\n',
        ('test_witness',)),
    # An exit row placed after the window closed taken as a failure of it.
    'witness-postwindow-row-qualifies': ('health_witness.py',
        '        elif at >= closed:\n',
        '        elif False:\n',
        ('test_witness',)),
    # The window's bounds taken without the scale tolerance between the helper's clock and the
    # probes' elapsed scale.
    'witness-window-bounds-exact': ('health_witness.py',
        "    opened, closed = window['start'] + SCALE_TOLERANCE_MS, window['end'] - SCALE_TOLERANCE_MS\n",
        "    opened, closed = window['start'], window['end']\n",
        ('test_witness',)),
    # A window that is missing, of no known form or of another boot used to place rows.
    'witness-window-unchecked': ('health_witness.py',
        '    if why is not None:\n'
        "        return unknown(['%s: no exit row can be placed in it' % why] + doubts + exclusions)\n",
        '',
        ('test_witness',)),
    # A loss already seen before the window opened left pending, as if a row of the window could
    # still come.
    'witness-prewindow-loss-pending': ('health_witness.py',
        "    if upper < window['start'] - SCALE_TOLERANCE_MS:\n",
        '    if False:\n',
        ('test_witness',)),
    # A current report first seen with no earlier read of the window without it taken as new.
    'witness-report-first-seen-qualifies': ('health_witness.py',
        '        elif not _seen_without(context, observation, live, born, _entry_key(joined[0]), window):\n',
        '        elif False:\n',
        ('test_witness',)),
    # A read before the window opened taken as one inside it that found the process without the
    # report.
    'witness-absence-before-window-counts': ('health_witness.py',
        "        if brackets['instance'] != observation['instance'] or brackets['begin']['elapsed'] < window['start']:\n",
        "        if brackets['instance'] != observation['instance']:\n",
        ('test_witness',)),
    # Another user's report taken as absent before where the current list may not cover that user.
    'witness-absence-uncovered-counts': ('health_witness.py',
        '        elif user != SHELL_USER_ID and not cross_user:\n',
        '        elif False:\n',
        ('test_witness',)),
    # A current list that failed taken as one without the report.
    'witness-absence-of-a-failed-list-counts': ('health_witness.py',
        "        if again is None or not again['complete']:\n",
        '        if again is None:\n',
        ('test_witness',)),
    # A whole current list beside a history part that failed taken as covering the process, though
    # without DUMP the list leaves out every UID but the shell's own.
    'witness-absence-of-a-filtered-list-counts': ('health_witness.py',
        "        if again is None or not again['complete']:\n",
        "        if again is None or again['current']['status'] != 'OK':\n",
        ('test_witness',)),
    # A current report joined to the process found before the call, whatever the discovery after it.
    'witness-report-binding-before-only': ('health_witness.py',
        '    live = after if after is not None and before == after else None\n',
        '    live = before\n',
        ('test_witness',)),
    # A framework instance other than the baselines' taken as continuing their identity.
    'witness-framework-change-ignored': ('health_witness.py',
        "    if any(b[3]['instance'] != observation['instance'] for b in baselines):\n",
        '    if False:\n',
        ('test_witness',)),
    # A read that did not find the same process before and after its call taken as one that did.
    'witness-absence-of-another-discovery-counts': ('health_witness.py',
        "            if (seen is None or seen['samples'] != replied or seen['before'] != live or seen['after'] != live\n",
        "            if (seen is None or seen['samples'] != replied\n",
        ('test_witness',)),
    # A read that already listed the report taken as one without it.
    'witness-absence-with-the-report-counts': ('health_witness.py',
        "        if all(_entry_key(e) != key for e in again['current']['entries']):\n",
        '        if True:\n',
        ('test_witness',)),
    # A current report with no window to place an earlier read in left unmarked, so the read may
    # hold.
    'witness-report-window-unmarked': ('health_witness.py',
        "            exclusions.append('a current report, and %s: no earlier read can be placed in it' % why)\n",
        '            pass\n',
        ('test_witness',)),
    # The broker passes no earlier probe's recorded helper reply, so a held probe has no clock.
    'witness-trail-replies-dropped': ('lab_broker.py',
        '                        helper.append(list(self._capture_reply(entry)))\n',
        '                        pass\n',
        ('test_witness',)),
    # A reopening takes a composition's copy of bit 1 without checking it against its projection.
    'witness-copy-unchecked': ('lab_broker.py',
        "            return \"its copy of bit 1's witness is not its projection's\"\n",
        '            pass\n',
        ('test_witness',)),
    # The next campaign: its cells, admission writer, driver rules, helper pushes and readers.
    'next-confirmation-count-unchecked': ('next_cells.py',
        "    if p['confirmations'] != len(cell['confirmations']) or p['boots'] < p['confirmations']:\n",
        '    if False:\n',
        ('test_next_campaign',)),
    'next-notice-faults-kept': ('next_cells.py',
        "    return [f for f in cell.get('faults', []) if world['notice'] or f['needs'] != 'notice']\n",
        "    return list(cell.get('faults', []))\n",
        ('test_next_campaign',)),
    'next-conditional-milestone-required': ('next_cells.py',
        '        if name in CONDITIONAL:\n            if at < len(found) and found[at] == name:\n      '
        '          at += 1\n            continue\n',
        '',
        ('test_next_campaign',)),
    'next-refused-f0-reaches-a': ('next_cells.py',
        "        return world['f0'] != 'REFUSED'\n",
        '        return True\n',
        ('test_next_campaign',)),
    'next-healthy-without-full-probes': ('next_cells.py',
        "    return HEALTHY if world['f0'] == 'FULL' and full_probe else INCONCLUSIVE\n",
        "    return HEALTHY if world['f0'] in ('FULL', 'LIMITED') else INCONCLUSIVE\n",
        ('test_next_campaign',)),
    'driver-confirms-another-wait': ('lab_driver.py',
        "                if not pending or pending[0] != state['state']:\n",
        '                if not pending:\n',
        ('test_next_driver',)),
    'driver-settles-across-applied': ('lab_driver.py',
        "                summary = self.advance('round', ticket)\n            finally:\n",
        "                summary = self.advance('settle', ticket, '40')\n            finally:\n",
        ('test_next_driver',)),
    'driver-unexplained-boot-accepted': ('lab_driver.py',
        "        return 'UNEXPECTED', self.cell, None\n",
        "        return 'MANAGED_ACTIVATION', self.cell, None\n",
        ('test_next_campaign', 'test_next_driver')),
    'driver-halt-count-unchecked': ('lab_driver.py',
        "        if summary['status'] == 'DELIBERATE_HALT' and len(halts) != 1:\n",
        '        if False:\n',
        ('test_next_campaign',)),
    'driver-not-acted-accepted': ('lab_driver.py',
        "            if e.content.get('decision') == 'not-acted':\n                raise DriverError('l"
        "oss %s was left not acted' % cell)\n",
        '',
        ('test_next_campaign',)),
    'driver-unacted-fault-ignored': ('lab_driver.py',
        "        if sorted(set(acted)) != sorted(f['cell'] for f in owed if f['cell'] not in conditiona"
        'l):\n',
        '        if False:\n',
        ('test_next_campaign', 'test_next_driver')),
    'driver-one-baseline-enough': ('lab_driver.py',
        'BASELINES_PER_USER = 2\n',
        'BASELINES_PER_USER = 1\n',
        ('test_next_driver',)),
    'driver-boundary-skipped': ('lab_driver.py',
        "            if state['state'] == 'APPLIED':\n                self.applied_boundary(ticket, pla"
        'n)\n',
        '            if False:\n                self.applied_boundary(ticket, plan)\n',
        ('test_next_driver',)),
    'driver-helpers-unchecked-after-boot': ('lab_driver.py',
        "            if not found['ok']:\n",
        '            if False:\n',
        ('test_next_campaign', 'test_next_driver')),
    'driver-renewal-unchecked': ('lab_driver.py',
        "        if transition['status'] != 'OK' or len(transition['new_boots']) != 1 or not renewed \\"
        "\n                or any(r['status'] != 'facts' for r in renewed.values()):\n",
        '        if False:\n',
        ('test_next_driver',)),
    'driver-publication-digest-optional': ('lab_driver.py',
        '        if set(members) != set(MEMBERS) or publication is None:\n',
        '        if set(members) != set(MEMBERS):\n',
        ('test_next_campaign',)),
    'driver-snapshot-unsynced': ('lab_driver.py',
        '            _write_synced(target / relative, data, self.sync)\n',
        '            _write_synced(target / relative, data, False)\n',
        ('test_next_campaign',)),
    'driver-cache-overwritten': ('lab_driver.py',
        '    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)\n',
        '    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)\n',
        ('test_next_campaign',)),
    'driver-repair-while-a-open': ('lab_driver.py',
        "        if not attempts or attempts[-1]['state'] != 'CLOSED_APPLIED' or self.open_tickets():\n",
        '        if not attempts:\n',
        ('test_next_driver',)),
    'driver-positive-ungated': ('lab_driver.py',
        "            if positive:\n                self.broker.gate_positive(plan, cell['attempt'], 'th"
        "e positive attempt after a qualified F0')\n            self.plan(plan, ticket, boot_limit, com"
        "mand='contradict' if cell['plan'] == 'COHORT' else 'plan')\n",
        "            self.plan(plan, ticket, boot_limit, command='contradict' if cell['plan'] == 'COHOR"
        "T' else 'plan')\n",
        ('test_next_driver',)),
    'driver-boot-count-jump-accepted': ('lab_driver.py',
        "        if after['bootCount'] < before['bootCount'] or after['bootCount'] > before['bootCount'"
        '] + 1:\n',
        '        if False:\n',
        ('test_next_campaign',)),
    'admission-direct-controls-unnamed': ('lab_driver.py',
        '        if role not in payloads or role not in named:\n',
        '        if role not in payloads:\n',
        ('test_next_campaign', 'test_next_driver')),
    'admission-write-members-counted': ('lab_driver.py',
        "            crossings[name] = sum(1 for c in managed if c['prediction']['calls']['WRITE'] > 0)"
        '\n',
        "            crossings[name] = sum(c['prediction']['calls']['WRITE'] for c in managed)\n",
        ('test_next_campaign',)),
    'admission-confirmations-unbounded': ('lab_driver.py',
        "                                 confirmation_services=nominal['confirmations'], observed_boot"
        "s=nominal['identities']),\n",
        "                                 confirmation_services=16, observed_boots=nominal['identities'"
        ']),\n',
        ('test_next_campaign',)),
    'driver-window-pace-unbounded': ('lab_driver.py',
        '        if not 0 < window_pace_s < WINDOW_GAP_S or WINDOW_S / window_pace_s > PROBES:\n',
        '        if window_pace_s <= 0:\n',
        ('test_next_campaign',)),
    'driver-window-paced-like-the-rest': ('lab_driver.py',
        "        pace = self.window_pace_s if state['state'] == 'HEALTH_WINDOW' else self.pace_s\n",
        '        pace = self.pace_s\n',
        ('test_next_campaign',)),
    'driver-positive-identity-skipped': ('lab_driver.py',
        "            self.identity_baseline('before the positive attempt, with the factory copy active')\n",
        '            pass\n',
        ('test_next_driver',)),
    'helper-push-other-bytes': ('lab_broker.py',
        "        if data is None or (hashlib.sha256(data).hexdigest(), len(data)) != (pin['sha256'], pi"
        "n['bytes']) \\\n                or pin['sha256'] != digest:\n",
        '        if data is None:\n',
        ('test_next_campaign',)),
    'helper-push-settles-without-readback': ('lab_broker.py',
        "        if read == digest:\n            return 'OK', outcome, None, True, []\n",
        "        if True:\n            return 'OK', outcome, None, True, []\n",
        ('test_next_campaign',)),
    'helper-pin-unchecked-at-admission': ('lab_broker.py',
        "        if spec['type'] == 'HELPER_PUSH' and spec['inputs'][0]['sha256'] != helper_pin(spec['p"
        "arameters']['helper'])[1]:\n",
        '        if False:\n',
        ('test_next_campaign',)),
    'helper-push-uncapped': ('lab_broker.py',
        "        spent = self._effect_spent('fixture', spec['phase'])\n        if spent is not None:\n "
        "           return 'REFUSED', {'helper': spec['parameters']['helper']}, '%s: nothing launched' "
        '% spent, True, []\n',
        '',
        ('test_next_campaign',)),
    'helper-push-beside-transition': ('lab_broker.py',
        "        if gate is None and spec['type'] == 'HELPER_PUSH':\n            gate = self._unsettled"
        '_transition()\n',
        '',
        ('test_next_campaign',)),
    'helper-check-any-bytes': ('lab_broker.py',
        "        return {'capture': number, 'helper': name, 'sha256': read, 'pinned': digest, 'ok': rea"
        'd == digest}\n',
        "        return {'capture': number, 'helper': name, 'sha256': read, 'pinned': digest, 'ok': rea"
        'd is not None}\n',
        ('test_next_campaign', 'test_next_driver')),
    'helper-push-counted-apart': ('lab_broker.py',
        "            effect = intent and (intent.get('operation') == 'lab-action-effect' or (\n        "
        "        intent.get('operation') == 'lab-action-push' and 'effect_class' in intent))\n",
        "            effect = intent and intent.get('operation') == 'lab-action-effect'\n",
        ('test_next_campaign',)),
    'selection-relation-unchecked': ('lab_records.py',
        "    if s['revision'] < 0 or (s['choice'] == 'PLAN') == (s['plan'] == '00' * 16):\n",
        "    if s['revision'] < 0:\n",
        ('test_next_campaign',)),
    'authorization-relation-unchecked': ('lab_records.py',
        "    if a['inputs'] & ~3 or (a['effect'] == 'SIGN') != (a['inputs'] != 0):\n",
        "    if a['inputs'] & ~3:\n",
        ('test_next_campaign',)),
    # The next driver's version 2: the final reads and their join, the ordinary read wait and its
    # bound, a reached conditional milestone's loss, and F0 as a gate among declared branches.
    'final-owned-session-ignored': ('lab_driver.py',
        "                 'cohort': 'ORIGINAL' if original else 'OTHER', 'live_owned': len(owned)}\n",
        "                 'cohort': 'ORIGINAL' if original else 'OTHER', 'live_owned': 0}\n",
        ('test_next_driver',)),
    'final-active-digest-only': ('lab_driver.py',
        "                 'active': 'R' if identity is not None and variant is not None and identity == exact"
        ' else identity,\n',
        "                 'active': 'R' if identity is not None and identity['apk'] == variant else identi"
        'ty,\n',
        ('test_next_driver',)),
    'final-whole-inventory-unchecked': ('lab_driver.py',
        "        if not read['global-sessions'][0].reading['whole']:\n            return 'the global sessi"
        "on inventory is not whole'\n",
        '',
        ('test_next_driver',)),
    'final-join-controls-ignored': ('lab_driver.py',
        "    referrers |= {lab_actions.control_referrer(control) for control in references['controls']}\n",
        '',
        ('test_next_campaign',)),
    'final-join-unknown-owner-ignored': ('lab_driver.py',
        "            uncertain.append(row['id'])\n",
        '            pass\n',
        ('test_next_campaign', 'test_next_driver')),
    'controller-whole-reads-ungated': ('lab_broker.py',
        "        if any(name in WHOLE_READS for name in names) and self.admission['version'] != 3:\n    "
        "        raise BrokerError('a whole inventory read needs a version 3 admission')\n",
        '',
        ('test_next_campaign',)),
    'driver-ordinary-wait-stops': ('lab_driver.py',
        "                if self.waiting is None:\n                    self.open_wait(state, summary['generation'])\n",
        "                raise DriverError('an unpredicted wait in %s' % state['state'])\n",
        ('test_next_driver',)),
    'driver-ordinary-wait-unbounded': ('lab_driver.py',
        "            if self.waiting is not None and self.monotonic() >= self.waiting['deadline_ns']:\n",
        '            if False:\n',
        ('test_next_driver',)),
    'driver-later-boot-assumed': ('lab_driver.py',
        '        return self.restart_resolves(generation)\n',
        '        return True\n',
        ('test_next_driver',)),
    'driver-later-boot-unread': ('lab_driver.py',
        '        return self.restart_resolves(generation)\n',
        '        return False\n',
        ('test_next_driver',)),
    'driver-reached-conditional-exempt': ('lab_driver.py',
        "                       and next_cells.by_fault(cell, c)['milestone'] not in milestones]\n",
        '                       and True]\n',
        ('test_next_campaign',)),
    'driver-f0-branch-predicted': ('lab_driver.py',
        "        if branch not in self.declaration['branches']:\n",
        "        if branch != self.declaration['branches'][0]:\n",
        ('test_next_campaign', 'test_next_driver')),
    'driver-declaration-unbound': ('lab_driver.py',
        "        if admission.get('cells_sha256') != digest or admitted != self.declaration['branches']:\n",
        '        if False:\n',
        ('test_next_campaign',)),
    'next-record-one-branch': ('next_cells.py',
        '    for world in worlds(declared):\n        entries = []\n',
        '    for world in worlds(declared)[:1]:\n        entries = []\n',
        ('test_next_campaign',)),
    'next-undecided-reaches-a': ('next_cells.py',
        "        if world['f0'] is None:\n            raise ValueError('F0 has not decided whether %s runs'"
        " % cell['name'])\n",
        '',
        ('test_next_campaign',)),
    # The next driver's version 3: the ordinary wait's own admitted budget on the host's clock,
    # and the report of other packages' live sessions at Final.
    'wait-budget-from-the-plan': ('lab_driver.py',
        "        budget = self.broker.admission['wait_policy']['ordinary_wait_ms']\n",
        "        budget = self.plan_record(state['plan'])['verificationWait']\n",
        ('test_next_driver',)),
    'wait-reads-uncut': ('lab_driver.py',
        "            self.read_deadline_ns = None if self.waiting is None else self.waiting['deadline_ns']\n",
        '            self.read_deadline_ns = None\n',
        ('test_next_driver',)),
    'wait-pause-uncut': ('lab_driver.py',
        '        return pace if remaining is None else min(pace, remaining)\n',
        '        return pace\n',
        ('test_next_campaign',)),
    'wait-samples-dropped': ('lab_driver.py',
        "                        samples=waiting['samples'])\n",
        '                        samples=[])\n',
        ('test_next_driver',)),
    'wait-intent-by-ticket-bytes': ('lab_driver.py',
        "        return (state['ticket'], state['state'], len(state['ledger']), state['boot'])\n",
        "        return (state['sha256'],)\n",
        ('test_next_campaign',)),
    'generation-read-deadline-ignored': ('lab_broker.py',
        '        if deadline_ns is None:\n            deadline_ns = self._read_deadline\n',
        '',
        ('test_next_driver',)),
    'generation-read-deadline-unchecked': ('lab_broker.py',
        "        if deadline_ns is not None and (self.admission['version'] != 3 or not isinstance(deadline_ns, "
        'int)\n',
        '        if False and (False\n',
        ('test_next_campaign',)),
    'admission-wait-policy-unchecked': ('lab_broker.py',
        "    lab_actions.check_wait_policy(value['wait_policy'])\n",
        '',
        ('test_next_campaign',)),
    'final-other-sessions-unreported': ('lab_driver.py',
        "        reported = {'other_live': [{'classification': session_classification(row), 'session': row}"
        ' for row in others],\n',
        "        reported = {'other_live': [],\n",
        ('test_next_driver',)),
    'final-other-sessions-uncertain': ('lab_driver.py',
        '        else:\n            others.append(dict(row))\n',
        "        else:\n            uncertain.append(row['id'])\n",
        ('test_next_campaign', 'test_next_driver')),
    'final-other-classification-flattened': ('lab_driver.py',
        "    return 'SEALED' if row['sealed'] else 'OPEN'\n",
        "    return 'OPEN'\n",
        ('test_next_campaign',)),
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

    # The bridge's round boundary and both codecs' milestone rule and reply relation.
    'java-round-ordinal-not-counted': (JAVA_MAIN + 'LabBridge.java',
        '                checkpoints.put(after.ticketId, ordinal);\n',
        '',
        ('BridgeTest',)),
    'java-round-halt-ignored': (JAVA_MAIN + 'LabBridge.java',
        '            case HALT:\n                halter.halt(Halter.STATUS);\n                throw new IllegalStateException("the halter returned");\n            case STOPPED:\n',
        '            case HALT:\n                return;\n            case STOPPED:\n',
        ('BridgeTest',)),
    'java-version-2-runs-untold': (JAVA_MAIN + 'LabBridge.java',
        '            if (config.protocol == LabProtocol.VERSION_2 && counts == null) {\n',
        '            if (false) {\n',
        ('BridgeTest',)),
    'java-milestone-progress-as-entry': (JAVA_MAIN + 'LabProtocol.java',
        '            return "HEALTH_WINDOW".equals(before) ? "HEALTH_WINDOW_PROGRESS" : "HEALTH_WINDOW_ENTRY";\n',
        '            return "HEALTH_WINDOW_ENTRY";\n',
        ('ProtocolTest',)),
    'java-round-reply-record-unchecked': (JAVA_MAIN + 'LabProtocol.java',
        '                if (named ? m.number("record") < 1 : m.number("record") != 0) {\n',
        '                if (named && m.number("record") < 1) {\n',
        ('ProtocolTest',)),
    # The next campaign's repair records.
    'repair-other-boots-mixed': (JAVA_MAIN + 'LabRepair.java',
        "            if (!o.boot.equals(boot)) continue; // Only the established boot's facts: no other"
        ' boot is ordered.\n',
        '',
        ('RepairTest',)),
    'repair-checked-boot-unchecked': (JAVA_MAIN + 'LabRepair.java',
        '        need(s.checkedBoot.equals(boot),\n',
        '        need(true,\n',
        ('RepairTest',)),
    'repair-pending-after-committed': (JAVA_MAIN + 'LabRepair.java',
        '        need(lastPending < firstCommitted, ',
        '        need(true, ',
        ('RepairTest',)),
    'repair-signs': (JAVA_MAIN + 'LabRepair.java',
        '                .signer(repaired.signer).signing(0)\n',
        '                .signer(repaired.signer).signing(1)\n',
        ('RepairTest',)),
    'repair-base-not-current': (JAVA_MAIN + 'LabRepair.java',
        '                .base(current.apk, current.version, current.uid, current.context).selectionRev'
        'ision(current.revision)\n',
        '                .base(repaired.baseApk, repaired.baseVersion, repaired.baseUid, repaired.baseC'
        'ontext)\n                .selectionRevision(current.revision)\n',
        ('RepairTest',)),
    'repair-sign-approved': (JAVA_MAIN + 'LabRepair.java',
        '        need(!approvals.contains("sign"), "a repair signs nothing: no SIGN grant is approved")'
        ';\n',
        '',
        ('RepairTest',)),
    'repair-grants-twice': (JAVA_MAIN + 'LabRepair.java',
        '        need(store.authorizationsOf(repairId).isEmpty(), "the repair plan already has grants")'
        ';\n',
        '',
        ('RepairTest',)),
    'repair-beside-open-ticket': (JAVA_MAIN + 'LabRepair.java',
        '        need(!openTicket(store, lab.component), "a ticket of the component is open");\n       '
        ' List<Authorization> written = new ArrayList<>();\n',
        '        List<Authorization> written = new ArrayList<>();\n',
        ('RepairTest',)),
    'repair-ticket-any-grants': (JAVA_MAIN + 'LabRepair.java',
        '        need(effects.equals(List.of(Effect.STAGE, Effect.ACTIVATE)),\n',
        '        need(true,\n',
        ('RepairTest',)),
}


def java_case_names(text):
    return re.findall(r'cases\.run\("([^"]+)"', text)


def case_names(tree=HERE):
    """Each suite's case IDs, from its source."""
    names = {}
    for suite in SUITES + JVM_SUITES + (DRIVER_SUITE,):
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
    # The next campaign's repair commands and host configuration.
    'repair-pair-unchecked': (DRIVER_JAVA + 'LabHost.java',
        '        if (config.repair == null || !config.repair.equals(repair) || !config.repaired.equals('
        'repaired)) {\n',
        '        if (false) {\n',
        ('DriverTest',)),
    'repair-plan-in-plans': (DRIVER_JAVA + 'LabHost.java',
        '                if (repair.equals(repaired) || !plans.contains(repaired) || plans.contains(rep'
        'air)) {\n',
        '                if (repair.equals(repaired)) {\n',
        ('DriverTest',)),
    'repair-ticket-command': (DRIVER_JAVA + 'LabDriverMain.java',
        '        need(plan.value.repairs.equals(DeploymentRecords.NO_ID), "a repair plan\'s ticket come'
        's from its own phases");\n',
        '',
        ('DriverTest',)),
    'init3-version-1-host': (DRIVER_JAVA + 'LabDriverMain.java',
        '        need(host != null && host.config().repair != null, "the next campaign binds a version '
        '2 lab host configuration");\n',
        '        need(host != null, "the next campaign binds a version 2 lab host configuration");\n',
        ('DriverTest',)),
    'next-commands-any-configuration': (DRIVER_JAVA + 'LabDriverMain.java',
        '        need(lab.profile != null, "the next campaign\'s commands need its version 3 configurat'
        'ion");\n',
        '',
        ('DriverTest',)),
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
    # Fourteen goldens of version 1 and eleven of version 2.
    if len(list(goldens.glob('*.bin'))) != 25:
        problems.append('the Python suite wrote %d goldens, not 25' % len(list(goldens.glob('*.bin'))))
    for suite in JAVA_SUITES:
        args = [str(goldens)] if suite == 'ProtocolTest' else [str(work / ('runs-' + suite))]
        if suite != 'ProtocolTest':
            (work / ('runs-' + suite)).mkdir()
        run = run_java(java, classes, suite, args, work)
        results[suite] = {'passed': len(run['passed']), 'failed': run['failed'], 'returncode': run['returncode']}
        if run['returncode'] != 0 or run['failed'] or sorted(run['passed']) != sorted(names[suite]):
            problems.append('%s: %d passed of %d, failed %s' % (suite, len(run['passed']), len(names[suite]),
                                                                 run['failed'] or run['output'][-400:]))
    for suite in JVM_SUITES:
        run = run_suite(REPO, suite, java, classes)
        results[suite] = {'passed': len(run['passed']), 'failed': run['failed'], 'skipped': len(run['skipped']),
                          'returncode': run['returncode']}
        if run['returncode'] != 0 or run['failed'] or sorted(run['passed']) != sorted(names[suite]):
            problems.append('%s: %d passed of %d, failed %s' % (suite, len(run['passed']), len(names[suite]),
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
        needs_jvm = any(s in JAVA_SUITES or s in JVM_SUITES for s in suites)
        if needs_jvm and classes is None and note is None:
            note = 'no JVM phase: not run'
        for suite in suites:
            if note is not None:
                break
            if suite in JAVA_SUITES:
                runs = tree / ('runs-' + suite)
                runs.mkdir()
                args = [] if suite == 'ProtocolTest' else [str(runs)]
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
