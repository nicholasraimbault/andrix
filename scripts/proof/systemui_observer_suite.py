# SPDX-License-Identifier: Apache-2.0
"""The shell observer suite of step D3, as the component transaction runner registers it.

Source checks: the observer's predictions agree with its test sources, and every deliberate
defect anchors exactly once. The guarded run, after the runner's build: both Python suites pass
with their predicted cases, the Java codec decodes every observation the observer gives from the
fixtures, encodes each again to the same bytes and reads the same fields, and each defect fails at
least its predicted cases. Host evidence only. The forms still need guest captures, which the
fixtures README lists."""
from pathlib import Path
import ast
import json
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
PREDICTIONS = ROOT / 'scripts/proof/systemui_observer_predictions.json'
SUITES = {'readbacks': 'scripts.proof.tests.test_systemui_readbacks',
          'observer': 'scripts.proof.tests.test_systemui_observer'}
SESSIONS = 'scripts/proof/systemui_sessions.py'
OBSERVER = 'scripts/proof/systemui_observer.py'
# Each defect: the file, its exact old and new text, and the suites predicted to catch it.
_DESTROYED = "    if session.destroyed:\n        return 'ABANDONED'\n"
_TERMINAL = ("    if session.applied:\n        return 'APPLIED'\n    if session.failed:\n        return 'FAILED'\n"
             "    if session.ready:\n        return 'READY'\n")
MUTANTS = {
    'unknown-form-accepted': (SESSIONS, "        if writer.text() != '\\n'.join(lines) + '\\n':\n"
                                        "            raise ValueError('Record differs from the pinned form')\n",
                              '        pass\n', ('readbacks', 'observer')),
    'unknown-pair-absorbed': (SESSIONS, "        if _FIELD_INSIDE.search(value):\n"
                                        "            raise ValueError('A value holds another field')\n",
                              '        pass\n', ('readbacks', 'observer')),
    'unknown-package-taken-as-foreign': (SESSIONS, '    return package is not None and package != PACKAGE\n',
                                         '    return package != PACKAGE\n', ('readbacks', 'observer')),
    'referrer-mismatch-accepted': (SESSIONS, '                 and s.referrer == expected)',
                                   '                 and s.referrer is not None and s.referrer.startswith(NONCE_SCHEME))',
                                   ('readbacks', 'observer')),
    'write-command-allowed': (OBSERVER, '    BOOT_ID, UPTIME, FRAMEWORK_PID,',
                              "    'vdc checkpoint commitChanges', BOOT_ID, UPTIME, FRAMEWORK_PID,", ('observer',)),
    'shell-reached-around-read': (OBSERVER, 'def boot_hex(uuid):',
                                  'def _around(command):\n    return encoder.subprocess.run(command, shell=True)\n\n\n'
                                  'def boot_hex(uuid):', ('observer',)),
    'boot-id-ignored': (OBSERVER, '            if self._boot(captures) != boot:',
                        '            if self._boot(captures) is None:', ('observer',)),
    'instance-ignored': (OBSERVER, '            if framework and self._instance(captures) != instance:',
                         '            if framework and self._instance(captures) is None:', ('observer',)),
    'listing-disagreement-accepted': (OBSERVER, '        elif row is None or (row.ready, row.applied, row.failed) != '
                                                '(session.ready, session.applied, session.failed):',
                                      '        elif row is None:', ('observer',)),
    'listed-session-missing-accepted': (OBSERVER, '    if set(listed) - seen:', '    if False:', ('observer',)),
    'incomplete-listing-accepted': (OBSERVER, "    if not listing.complete:\n"
                                              "        raise ValueError('The listing is not complete')\n", '',
                                    ('observer',)),
    'destroyed-still-listed-accepted': (OBSERVER, "            if row is not None:\n"
                                                  "                raise ValueError('A destroyed session is still listed')\n",
                                        '            pass\n', ('observer',)),
    'removed-still-listed-accepted': (OBSERVER, "            if session.identity in listed:\n"
                                                "                raise ValueError('A removed session is still listed')\n",
                                      '            pass\n', ('observer',)),
    'committed-refused': (OBSERVER, '        if not session.committed and session.final_status < 0:',
                          '        if session.final_status < 0:', ('observer',)),
    'abandon-without-message': (OBSERVER, '        if session.final_status == INSTALL_FAILED_ABORTED and '
                                          'session.final_message == ABANDONED_MESSAGE:',
                                '        if session.final_status == INSTALL_FAILED_ABORTED:', ('observer',)),
    'destroyed-after-terminal-flags': (OBSERVER, _DESTROYED + _TERMINAL, _TERMINAL + _DESTROYED, ('observer',)),
    'unknown-package-ignored': (OBSERVER, "        if session.package is None and session.staged:\n"
                                          "            raise ValueError('A staged session of no known package')\n",
                                '', ('observer',)),
    # An installer of free text that prints a prefix of its own, and the three ways around the
    # source rule: an import inside a function, a module bound to another name, and an import
    # inside a parser function.
    'installer-prefix-trusted': (SESSIONS, "    for key, count in _PREFIX_COUNTS.items():\n"
                                           "        if sum(token.startswith(key + '=') for token in tokens) != count:\n"
                                           "            return None\n", '', ('readbacks', 'observer')),
    'import-inside-function': (OBSERVER, 'def boot_hex(uuid):',
                               'def _later():\n    import multiprocessing\n    return multiprocessing.cpu_count()\n\n\n'
                               'def boot_hex(uuid):', ('observer',)),
    'module-bound-to-another-name': (OBSERVER, 'def boot_hex(uuid):',
                                     '_tools = encoder\n\n\ndef _around(command):\n'
                                     '    return _tools.shutil.which(command)\n\n\ndef boot_hex(uuid):', ('observer',)),
    'parser-imports-subprocess': (SESSIONS, 'def prefix_package(logical):',
                                  'def _helper(command):\n    import subprocess\n    return subprocess.run(command)\n\n\n'
                                  'def prefix_package(logical):', ('observer',)),
}
DECODE = '''package dev.andrix.server.deployment;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

/** Decodes each observation record of the shell observer, encodes it again and prints its fields. */
public final class ObserverDecode {
    private ObserverDecode() {}

    public static void main(String[] args) throws Exception {
        for (String name : args) {
            byte[] data = Files.readAllBytes(Path.of(name));
            DeploymentRecords.Observation o = DeploymentRecords.decodeObservation(data);
            boolean same = Arrays.equals(DeploymentRecords.encodeObservation(o), data);
            DeploymentRecords.Reference r = o.reference;
            System.out.println(String.join("|", Path.of(name).getFileName().toString(), same ? "SAME" : "DIFFERENT",
                    Integer.toString(o.kind.code), Integer.toString(o.classification.code), o.route.name(),
                    o.installation, o.observationId, o.component, o.boot, Integer.toString(o.user),
                    Long.toString(o.serial), Long.toString(o.instance), Long.toString(o.elapsed), o.raw, o.text,
                    o.digest, Long.toString(o.version), Integer.toString(o.number), Integer.toString(r.presence),
                    Integer.toString(r.sessionId), Long.toString(r.createdMillis), r.stageDir,
                    Integer.toString(r.installerUid), r.nonce));
        }
    }
}
'''
# Writes each fixture fact's record and the line the Java decoder must print for it.
RECORDS = '''
import json, sys
from pathlib import Path
from scripts.proof import component_transaction_records as encoder
from scripts.proof import systemui_observer as observer
from scripts.proof.tests.test_systemui_observer import fixture_facts
out = Path(sys.argv[1])
expected = {}
for name, f in sorted(fixture_facts().items()):
    (out / (name + '.rec')).write_bytes(observer.encode(f))
    facts = f['facts']
    ref = facts.get('reference', (0, 0, 0, '', 0, encoder.ZERO_ID))
    text = facts.get('fingerprint', facts.get('context', ''))
    expected[name + '.rec'] = '|'.join(str(v) for v in (
        name + '.rec', 'SAME', encoder.KINDS[f['kind']], encoder.CLASSIFICATIONS[f['kind']].index(f['classification']) + 1,
        f['route'], f['installation'], f['observation'], f['component'], f['boot'], f['user'], f['serial'],
        f['instance'], f['elapsed'], f['raw'], text, facts.get('apk', encoder.ZERO_DIGEST), facts.get('version', 0),
        facts.get('uid', facts.get('count', 0)), *ref))
print(json.dumps(expected))
'''


def strict(text):
    def pairs(items):
        keys = [k for k, _ in items]
        if len(keys) != len(set(keys)):
            raise ValueError('duplicate key')
        return dict(items)
    return json.loads(text, object_pairs_hook=pairs)


def case_names(suite, root=ROOT):
    """Every test of a suite, as unittest names it, in source order."""
    path = root / (SUITES[suite].replace('.', '/') + '.py')
    names = []
    for node in ast.parse(path.read_text()).body:
        if isinstance(node, ast.ClassDef):
            names += ['%s.%s' % (node.name, item.name) for item in node.body
                      if isinstance(item, ast.FunctionDef) and item.name.startswith('test')]
    return names


def mutant_texts(root=ROOT):
    texts = {}
    for name, (path, old, new, _) in MUTANTS.items():
        source = (root / path).read_text()
        if source.count(old) != 1 or old == new:
            raise ValueError('anchor not exactly once: ' + name)
        texts[name] = (path, source.replace(old, new))
    return texts


def source_problems():
    problems = []
    try:
        mutant_texts()
    except (OSError, ValueError) as error:
        problems.append('observer mutant anchors: %s' % error)
    try:
        predictions = strict(PREDICTIONS.read_text())
        if 'PREDICTED' not in predictions['status']:
            problems.append('observer predictions are not marked as predictions')
        names = {suite: case_names(suite) for suite in SUITES}
        if predictions['cases'] != {suite: len(n) for suite, n in names.items()}:
            problems.append('observer case counts differ from the test sources')
        for suite, listed in names.items():
            if len(set(listed)) != len(listed):
                problems.append('duplicate case names in ' + suite)
        caught = predictions['mutants_caught_at_least']
        if set(caught) != set(MUTANTS):
            problems.append('observer mutant predictions do not list every mutant')
        for name, cases in caught.items():
            allowed = {case for suite in MUTANTS.get(name, ('', '', '', ()))[3] for case in names[suite]}
            if not cases or not set(cases) <= allowed:
                problems.append('observer mutant prediction inconsistent: ' + name)
        if predictions['decoded'] < 1:
            problems.append('observer decode prediction missing')
    except (OSError, ValueError, KeyError) as error:
        problems.append('observer predictions: %s' % error)
    return problems


def run_suite(root, suite, timeout=600):
    """One Python suite in a fresh interpreter: the passed and failed case names."""
    result = subprocess.run([sys.executable, '-B', '-m', 'unittest', '-v', SUITES[suite]], cwd=root,
                            capture_output=True, text=True, timeout=timeout)
    passed = ['%s.%s' % (m[2], m[1]) for m in re.finditer(
        r'^(test\w*) \([\w.]+?\.(\w+)\.\1\)(?:\n.*?)? \.\.\. ok$', result.stderr, re.M)]
    failed = ['%s.%s' % (m[2], m[1]) for m in re.finditer(
        r'^(?:FAIL|ERROR): (test\w*) \([\w.]+?\.(\w+)\.\1\)', result.stderr, re.M)]
    return {'returncode': result.returncode, 'passed': passed, 'failed': sorted(set(failed)),
            'tail': result.stderr[-4000:]}


def qualify(work, classes, report, javac, java, environment):
    """The observer phase of a guarded run. `classes` holds the runner's build of the package."""
    steps, problems = report['steps'], report['problems']
    predictions = strict(PREDICTIONS.read_text())
    step = steps['observer'] = {}
    for suite in SUITES:
        result = run_suite(ROOT, suite)
        step[suite] = {key: result[key] for key in ('returncode', 'failed')}
        step[suite]['passed'] = len(result['passed'])
        if result['returncode'] or result['failed'] or sorted(result['passed']) != sorted(case_names(suite)):
            step[suite]['tail'] = result['tail']
            problems.append('observer %s suite' % suite)
    directory = work / 'observer'
    records = directory / 'records'
    source = directory / 'src/dev/andrix/server/deployment'
    for path in (records, source, directory / 'classes', directory / 'jvm-tmp'):
        path.mkdir(parents=True)
    written = subprocess.run([sys.executable, '-B', '-c', RECORDS, str(records)], cwd=ROOT, capture_output=True,
                             text=True, timeout=300)
    if written.returncode:
        step['records'] = written.stderr[-4000:]
        problems.append('observer records')
        return
    expected = json.loads(written.stdout)
    (source / 'ObserverDecode.java').write_text(DECODE)
    built = subprocess.run([*javac, '-cp', str(classes), '-d', str(directory / 'classes'),
                            str(source / 'ObserverDecode.java')], capture_output=True, text=True, timeout=600,
                           cwd=directory, env=environment)
    if built.returncode:
        step['decode_build'] = (built.stdout + built.stderr)[-4000:]
        problems.append('observer decoder build')
        return
    names = sorted(expected)
    run = subprocess.run([*java, '-Djava.io.tmpdir=' + str(directory / 'jvm-tmp'), '-cp',
                          '%s:%s' % (classes, directory / 'classes'), 'dev.andrix.server.deployment.ObserverDecode',
                          *(str(records / name) for name in names)], capture_output=True, text=True, timeout=600,
                         cwd=directory, env=environment)
    lines = run.stdout.splitlines()
    step['decoded'] = len(lines)
    differing = [n for n, line in zip(names, lines) if expected[n] != line]
    if run.returncode or len(lines) != len(names) or differing or len(names) != predictions['decoded']:
        step['decode'] = {'returncode': run.returncode, 'differing': differing, 'stderr': run.stderr[-4000:]}
        problems.append('observer records decoded by the Java codec')
    step['mutants'] = {}
    for name, (path, text) in mutant_texts().items():
        copy = work / 'observer-mutants' / name
        shutil.copytree(ROOT / 'scripts/proof', copy / 'scripts/proof', ignore=shutil.ignore_patterns('__pycache__'))
        (copy / path).write_text(text)
        failed = set()
        for suite in MUTANTS[name][3]:
            failed |= set(run_suite(copy, suite)['failed'])
        missed = sorted(set(predictions['mutants_caught_at_least'][name]) - failed)
        step['mutants'][name] = {'caught': sorted(failed), 'missed': missed}
        if missed or not failed:
            problems.append('observer mutant %s not caught: %s' % (name, missed))
        shutil.rmtree(copy)
    report['completed_phases'].append('observer')
