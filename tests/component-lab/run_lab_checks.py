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
simulated guest, one JVM per generation. The defect phase copies this directory into a scratch tree,
applies one defect at a time, rebuilds when the defect is in Java, and runs the suites predicted to
catch it; each must fail at least its predicted cases. Every JVM has a capped heap, metaspace and
code cache, the serial collector and one client JIT compiler thread.

Host evidence only: a simulated guest, a fake adb server and a scripted host, not Android."""
from pathlib import Path
import argparse
import ast
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
SUITES = ('test_lab_protocol', 'test_shell_transport', 'test_capture_ledger', 'test_lab_crossings', 'test_lab_broker')
BRIDGE_SUITE = 'test_lab_bridge'
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
                                             'activation grant may have\n'
                                             '        # expired since the gate\'s clock reading sends nothing.\n'
                                             '        if not_after_ns is not None and self._monotonic() >= not_after_ns:\n'
                                             "            self._not_sent(entry, 'the activation grant may have expired "
                                             "before the launch')\n        try:\n            result = call()\n",
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
        '        self._require_shell2(context)\n        return self._record_command(operation, command, context, call, '
        'timeout, not_after_ns)\n\n    def _record_command(self, operation, command, context, call, timeout, '
        'not_after_ns=None):\n'
        '        # Every command, the feature query included, is fenced right before its intent: a fence that\n'
        '        # trips while an earlier command runs stops the next one.\n        self._fence()\n',
        '        self._fence()\n        self._require_shell2(context)\n        return self._record_command(operation, '
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
                                                 '        if may_send is not None and not may_send():\n',
                                                 '        if False:\n', ('test_shell_transport',)),
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
}

# Each Java defect: the file under this directory, its exact old and new text, and the suites run
# against it after a rebuild. A suite is a Java suite or the end to end Python suite.
JAVA_MUTANTS = {
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
}


def java_case_names(text):
    return re.findall(r'cases\.run\("([^"]+)"', text)


def case_names(tree=HERE):
    """Each suite's case IDs, from its source."""
    names = {}
    for suite in SUITES + (BRIDGE_SUITE,):
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
    defects = dict(MUTANTS, **JAVA_MUTANTS)
    if set(caught) != set(defects) or len(defects) != len(MUTANTS) + len(JAVA_MUTANTS):
        problems.append('the defect predictions do not list every defect once')
    for name, (file, old, new, suites) in defects.items():
        if (HERE / file).read_text().count(old) != 1:
            problems.append('the anchor of %s is not in %s once' % (name, file))
        allowed = {(suite + '.' + case) if suite in JAVA_SUITES else case for suite in suites for case in names[suite]}
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


def run_suite(tree, suite, java=None, classes=None, timeout=900):
    """One Python suite of a tree in its own interpreter. The end to end suite gets the JDK and classes."""
    lab = tree / 'tests' / 'component-lab'
    extra = {'PYTHONPATH': str(lab)}
    if java and classes:
        extra.update(ANDRIX_LAB_JAVA=java, ANDRIX_LAB_CLASSES=str(classes))
    try:
        done = subprocess.run([sys.executable, '-B', '-m', 'unittest', '-v', suite], cwd=lab,
                              env=tool_environment(extra), capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {'returncode': None, 'passed': [], 'failed': [], 'skipped': [], 'output': 'timeout'}
    output = done.stderr
    passed = re.findall(r'^(test_\w+) \(([\w.]+)\) \.\.\. ok$', output, re.M)
    skipped = re.findall(r'^(test_\w+) \(([\w.]+)\) \.\.\. skipped', output, re.M)
    # A failing subtest prints its parameters after the test's name, and still fails the test.
    failed = re.findall(r'^(?:FAIL|ERROR): (test_\w+) \(([\w.]+)\)(?: \(.*\))?$', output, re.M)
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
    if len(list(goldens.glob('*.bin'))) != 14:
        problems.append('the Python suite wrote %d goldens, not 14' % len(list(goldens.glob('*.bin'))))
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


def mutant_phase(report, predictions, chosen, java, javac, base_classes, work):
    problems, results = [], {}
    defects = dict(MUTANTS, **JAVA_MUTANTS)
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
            classes = None
            if jvm:
                problems, classes = java_phase(report, names, java, javac, work, not args.skip_java_suites)
                report['problems'] += problems
            elif not args.no_java:
                report['java'] = 'NOT_RUN: ' + (guard or 'no JDK on PATH')
            if not args.no_mutants:
                chosen = set(args.mutant) if args.mutant else set(MUTANTS) | set(JAVA_MUTANTS)
                unknown = chosen - set(MUTANTS) - set(JAVA_MUTANTS)
                if unknown:
                    report['problems'].append('unknown defects %s' % sorted(unknown))
                if not jvm:
                    chosen &= set(MUTANTS)
                report['problems'] += mutant_phase(report, predictions, chosen, java if jvm else None,
                                                   javac if jvm else None, classes, work)
    ran_java = isinstance(report.get('java'), dict)
    partial = (args.source_checks_only or args.skip_python or args.skip_java_suites or args.no_mutants
               or bool(args.mutant) or not ran_java)
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
               'java': report.get('java'), 'mutants': len(report.get('mutants', {}))}
    print(text if report['problems'] else json.dumps(summary, sort_keys=True))
    return 0 if not report['problems'] else 1


if __name__ == '__main__':
    sys.exit(main())
