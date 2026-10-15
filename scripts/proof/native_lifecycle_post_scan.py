#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The post scan view of the B2 guest boots: an adapter over checkpoint 3a's exact predictions,
bound to the scan wrapper's source.

Checkpoint 3a's predictions read each guest input as its boot seeds it: the store is restored, the
recovery view seeded, and the scan's two native checks are called as predicates. They stay
unchanged, the base. An Android boot then scans the subject's code. The adapted scan wrapper of
InstallPackageHelper defers a mapped package whose scanned code fails the subject check, or passes
it and fails the signer check, at the absolute path of that code, and then throws with the native
deferral code; the scan failure handler defers the same name again. A package that no row maps
fails its scan as not found, and the handler defers it when its name is a native principal name.
The deferral fragment adds the name to the recovery view's deferred set, and marks unidentified
code only for a relative path. The diagnostic renders the deferred set and the unidentified mark
from the view, and nothing else of it.

So the post scan view of a guest boot follows from its base reading and one fact of that boot,
which the boot's plan states: `scanned`, the subject's code scanned at its path under its row;
`parked`, the code absent from the scan with the row kept; or `unmapped`, the code present with no
row mapping the subject. A scanned subject that the checks refuse gains the subject's name, a
scanned subject they admit gains nothing, a parked subject is never scanned, and an unmapped
subject gains its name when it is a native principal name. Nothing else changes. A reading that
already defers the name is unchanged.

The adapter records the SHA-256 of the base and of each source it is bound to: the native
principal patch and its deferral fragment and recovery view, from the working tree for B2's image
and through the floor loader for B1's. Beside it, the extracted wrapper control reads the wrapper
blocks, the failure handler and the deferral out of each image's patch and fragment, statement by
statement, and interprets them, independently of the adapter's rule. A statement of another shape
is refused, never guessed. Prediction only: no guest, store or authority."""
from pathlib import Path
import hashlib
import json
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/proof'))
import native_creation_binding as b1  # noqa: E402

PREDICTIONS = ROOT / 'scripts/proof/native_lifecycle_record_predictions.json'
SUBJECT = 'dev.andrix.proof.principalclosed'
BASE_SECTION = ('b2_checkpoint_3a', 'guest_inputs')
SECTION = ('b2_checkpoint_3b', 'post_scan')
READERS = ('production', 'floor')
# The image each reader models.
IMAGES = {'production': 'B2', 'floor': 'B1'}
SCANS = ('scanned', 'parked', 'unmapped')
# The two checks the post scan view changes. The other four checks keep their base readings.
CHECKS = ('deferred set', 'schema 3 rows')
# The subject check and the signer check, by the scan outcome a reading reports.
OUTCOMES = {'admitted': (True, True), 'refused': (False, False), 'subject refused': (False, True),
            'signer refused': (True, False)}
INSTALL_HELPER = 'services/core/java/com/android/server/pm/InstallPackageHelper.java'
SETTINGS = 'services/core/java/com/android/server/pm/Settings.java'
PATCH = b1.NATIVE_PATCH
PROFILE = b1.NATIVE_PROFILE
DEFERRAL = 'owner/tests/platform/native_recovery_fragments/deferral.java.inc'
DIAGNOSTIC = 'owner/tests/platform/native_recovery_fragments/diagnostic-dump.java.inc'
RECOVERY = 'owner/platform/framework/NativePrincipalRecovery.java'
SOURCES = (PATCH, DEFERRAL, DIAGNOSTIC, RECOVERY)
HUNK = re.compile(r'@@ -[0-9]+(?:,([0-9]+))? \+([0-9]+)(?:,([0-9]+))? @@')
# The path expressions the wrapper and the handler pass to the deferral, and what each is when
# Package Manager scans installed code under /data/app: an absolute path.
PATHS = {'new File(parsedPackage.getPath())': 'absolute', 'result.scanFile': 'absolute', 'null': 'null'}
# The deferred name each deferral passes: the scanned package's own name.
NAMES = {'pkgName': 'scanned package', 'packageName': 'scanned package'}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    """One digest form of a JSON value: sorted keys, no spaces, UTF-8."""
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key: %s' % key)
        result[key] = value
    return result


def load_predictions(path=PREDICTIONS):
    return json.loads(Path(path).read_text(), object_pairs_hook=unique,
                      parse_constant=lambda name: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def base_section(predictions=None):
    """Checkpoint 3a's guest input predictions, the base."""
    predictions = load_predictions() if predictions is None else predictions
    return predictions[BASE_SECTION[0]][BASE_SECTION[1]]


def section(predictions=None):
    """The frozen post scan predictions."""
    predictions = load_predictions() if predictions is None else predictions
    return predictions.get(SECTION[0], {}).get(SECTION[1], {})


def java_order(names):
    """Names in Java String order: by UTF-16 code units."""
    return sorted(names, key=lambda name: name.encode('utf-16-be'))


# ---------------------------------------------------------------- the adapter


def scan_fact(mapping):
    """The scan fact of a host input: a mapped subject's code is scanned, a lost mapping leaves it
    unmapped."""
    if mapping not in ('mapped', 'lost'):
        raise ValueError('host input mapping')
    return 'scanned' if mapping == 'mapped' else 'unmapped'


def adapt(reading, scan, subject=SUBJECT):
    """The post scan view of one base reading at one scan fact: its deferred set and diagnostic
    rows, with the subject's name added exactly when the scan defers it."""
    if type(reading) is not dict or scan not in SCANS or not isinstance(reading.get('scan outcome'), dict):
        raise ValueError('a base reading and a scan fact')
    outcome = reading['scan outcome']
    if scan == 'unmapped':
        if 'subject' in outcome or outcome.get('subject unmapped') not in ('protected', 'unprotected'):
            raise ValueError('an unmapped boot of a reading that maps the subject')
        added = outcome['subject unmapped'] == 'protected'
    else:
        if outcome.get('subject') not in OUTCOMES:
            raise ValueError('a scanned or parked boot of a reading without the mapped subject')
        added = scan == 'scanned' and outcome['subject'] != 'admitted'
    deferred, rows = reading['deferred set'], reading['schema 3 rows']
    if (type(deferred) is not list or type(rows) is not dict or rows.get('deferred') != deferred
            or java_order(set(deferred)) != deferred):
        raise ValueError('a base reading whose deferred set and diagnostic disagree')
    names = java_order(set(deferred) | ({subject} if added else set()))
    return {'deferred set': names, 'schema 3 rows': dict(rows, deferred=names)}


def guest_boot(reading, scan, subject=SUBJECT):
    """A guest boot's whole prediction: the base reading with its post scan checks."""
    return dict(reading, **adapt(reading, scan, subject))


def post_scan_reads(base):
    """The post scan view of every host input and reader."""
    reads = {}
    for name, (mode, mapping) in base['inputs'].items():
        reads[name] = {reader: adapt(base['reads'][name][reader], scan_fact(mapping)) for reader in READERS}
    return reads


def changes(base, reads):
    """Each input and reader whose post scan view differs from its base, with the names added."""
    found = []
    for name in base['inputs']:
        for reader in READERS:
            before, after = base['reads'][name][reader]['deferred set'], reads[name][reader]['deferred set']
            if before != after:
                found.append({'input': name, 'reader': reader, 'image': IMAGES[reader],
                              'seeded': before, 'post_scan': after,
                              'added': java_order(set(after) - set(before))})
    return found


def freeze(base, sources):
    """The frozen post scan predictions: the base digest, the source digests, the changes and every
    post scan reading."""
    reads = post_scan_reads(base)
    return {'base': {'section': '.'.join(BASE_SECTION), 'sha256': sha(canonical(base))},
            'sources': sources, 'checks': list(CHECKS), 'changes': changes(base, reads), 'reads': reads}


# ---------------------------------------------------------------- source binding


def hunks(patch_text, target):
    """The hunks of one file section of a unified diff, each as (first new line number, new side
    lines with an added flag). A malformed hunk refuses."""
    lines = patch_text.split('\n')
    if lines and lines[-1] == '':
        lines.pop()
    found, current, index = [], None, 0
    while index < len(lines):
        line = lines[index]
        if line.startswith('--- ') and index + 1 < len(lines) and lines[index + 1].startswith('+++ '):
            name = lines[index + 1][4:].split('\t')[0]
            current = (name[2:] if name.startswith('b/') else name) == target
            index += 2
            continue
        match = HUNK.match(line)
        index += 1
        if match is None:
            continue
        if current is None:
            raise ValueError('patch hunk before any file header')
        old = 1 if match[1] is None else int(match[1])
        new = 1 if match[3] is None else int(match[3])
        side = []
        while old > 0 or new > 0:
            if index >= len(lines):
                raise ValueError('truncated patch hunk')
            body = lines[index]
            index += 1
            if body.startswith('\\'):
                continue
            if body.startswith('+'):
                side.append((body[1:], True))
                new -= 1
            elif body.startswith('-'):
                old -= 1
            elif body.startswith(' ') or body == '':
                side.append((body[1:], False))
                old -= 1
                new -= 1
            else:
                raise ValueError('malformed patch hunk line')
            if old < 0 or new < 0:
                raise ValueError('patch hunk count mismatch')
        if current:
            found.append((int(match[2]), side))
    if not found:
        raise ValueError('no hunk of ' + target)
    return found


def statements(lines):
    """Physical lines joined into statements, each ending at ';', '{' or '}', with whitespace runs
    collapsed. A line that ends none is continued. Blank lines and whole line comments are no
    statements."""
    out, pending = [], []
    for line in lines:
        if not line.strip() or line.strip().startswith('//'):
            continue
        pending.append(line.strip())
        if line.rstrip().endswith((';', '{', '}')):
            out.append(re.sub(r'\s+', ' ', ' '.join(pending)).replace('( ', '(').replace(' )', ')'))
            pending = []
    if pending:
        raise ValueError('an unterminated statement')
    return out


def block(side, start, span):
    """The statements of the block whose opening statement takes span lines from side[start], to its
    closing brace at the opening line's indentation, and that brace's index."""
    indent = len(side[start][0]) - len(side[start][0].lstrip())
    for end in range(start + span, len(side)):
        text = side[end][0]
        if text.strip() == '}' and len(text) - len(text.lstrip()) == indent:
            return statements([line for line, _ in side[start + span:end]]), end
    raise ValueError('an unclosed block')


def assignment(before, name):
    """The last line before a block that assigns a name, whitespace collapsed, or None."""
    for line, _ in reversed(before):
        text = ' '.join(line.split())
        if re.search(r'\b%s =' % name, text):
            return text
    return None


DEFER = re.compile(r'mPm\.mSettings\.deferNativePackage\(([A-Za-z]+), (.+)\);')
THROW = re.compile(r'throw PackageManagerException\.ofInternalError\("[^"]+", '
                   r'PackageManagerException\.(INTERNAL_ERROR_[A-Z_]+)\);')


def wrapper_steps(body):
    """One wrapper block's statements as steps: each deferral with its name and path, and the throw
    with its internal error code. Any other statement refuses."""
    steps = []
    for text in body:
        defer, throw = DEFER.fullmatch(text), THROW.fullmatch(text)
        if defer and defer[1] in NAMES and defer[2] in PATHS:
            steps.append(('defer', NAMES[defer[1]], PATHS[defer[2]]))
        elif throw:
            steps.append(('throw', throw[1]))
        else:
            raise ValueError('a wrapper statement of another shape: %s' % text[:120])
    return steps


SUBJECT_OPEN = 'if (!mPm.mSettings.nativeScanSubjectAllowedLPr(scanResult.mPkgSetting)) {'
BINDING_OPEN = ('if (!mPm.mSettings.nativeScanBindingAllowedLPr(scanResult.mPkgSetting, '
                'reconcileResult.get(0).mSigningDetails)) {')
NAME_DECLARATION = 'final String pkgName = scanResult.mPkgSetting.getPackageName();'
HANDLER_OPEN = 'if (nativeDeferred || mPm.mSettings.isNativePrincipalPackageLPr(packageName)) {'
HANDLER_NAME = 'String packageName = result.parsedPackage == null ? null : result.parsedPackage.getPackageName();'
DEFERRED_FLAG = ('nativeDeferred = e.internalErrorCode == '
                 'PackageManagerException.INTERNAL_ERROR_NATIVE_IDENTITY_DEFERRED;')


OPENERS = {SUBJECT_OPEN: 'subject', BINDING_OPEN: 'binding', HANDLER_OPEN: 'handler'}


def extract_wrapper(patch_text):
    """The scan wrapper and its failure handler, read out of one image's native principal patch:
    the subject check block, then the signer check block, each as its steps, and the handler's
    steps. Each is one block the patch adds, found once, the subject block first; the name they
    defer is the scanned package's own, and the deferred flag is set in both catch paths. Anything
    else refuses."""
    found, flags = {}, 0
    for first, side in hunks(patch_text, INSTALL_HELPER):
        flags += sum(1 for line, added in side if added and ' '.join(line.split()) == DEFERRED_FLAG)
        for index, (line, _) in enumerate(side):
            text, span = ' '.join(line.split()), 1
            if text.startswith('if (!mPm.mSettings.nativeScanBindingAllowedLPr(') and index + 1 < len(side):
                text, span = text + ' ' + ' '.join(side[index + 1][0].split()), 2
            kind = OPENERS.get(text)
            if kind is None:
                continue
            if kind in found:
                raise ValueError('the %s block occurs twice' % kind)
            body, end = block(side, index, span)
            if not all(added for _, added in side[index:end + 1]):
                raise ValueError('the %s block is not one block the patch adds' % kind)
            found[kind] = {'line': first + index, 'body': body, 'before': side[:index]}
    if set(found) != {'subject', 'binding', 'handler'}:
        raise ValueError('the scan wrapper blocks are not all present once: %s' % sorted(found))
    if not found['subject']['line'] < found['binding']['line']:
        raise ValueError('the signer check precedes the subject check')
    if (assignment(found['subject']['before'], 'pkgName') != NAME_DECLARATION
            or assignment(found['handler']['before'], 'packageName') != HANDLER_NAME):
        raise ValueError('the deferred name is not the scanned package\'s')
    if flags != 2:
        raise ValueError('the deferred flag is not set in both catch paths')
    handler = found['handler']['body']
    if (len(handler) != 3 or not DEFER.fullmatch(handler[0])
            or not re.fullmatch(r'Slog\.w\(TAG, "[^"]+"\);', handler[1]) or handler[2] != 'return;'):
        raise ValueError('the failure handler of another shape')
    return {'subject': wrapper_steps(found['subject']['body']), 'binding': wrapper_steps(found['binding']['body']),
            'handler': wrapper_steps(handler[:1]),
            'lines': {kind: found[kind]['line'] for kind in ('subject', 'binding', 'handler')}}


DEFERRAL_FRAGMENT = ('void deferNativePackage(String packageName, File codePath) {',
                     'synchronized (mLock) {',
                     'if (codePath != null && !codePath.isAbsolute()) {',
                     'mNativeRecoveryView = mNativeRecoveryView.defer(packageName, null).withUnidentifiedCode();',
                     '} else mNativeRecoveryView = mNativeRecoveryView.defer(packageName, codePath);',
                     '}', '}')


def extract_deferral(fragment_text, patch_text):
    """The deferral's effect by path kind, read out of the fragment, which the patch's Settings must
    add exactly once: a relative path marks unidentified code, an absolute or null path does not."""
    body = statements(fragment_text.splitlines())
    if tuple(body) != DEFERRAL_FRAGMENT:
        raise ValueError('the deferral fragment of another shape')
    added = '\n'.join(line for _, side in hunks(patch_text, SETTINGS) for line, flag in side if flag)
    if added.count(fragment_text.rstrip('\n')) != 1:
        raise ValueError('the patch\'s Settings does not add the deferral fragment once')
    return {'absolute': {'defers': True, 'unidentified': False}, 'null': {'defers': True, 'unidentified': False},
            'relative': {'defers': True, 'unidentified': True}}


def extract_recovery(text):
    """The recovery view's defer: a nonempty name joins the protected and deferred names, and the
    view keeps its holds and unidentified mark."""
    match = re.search(r'\n    NativePrincipalRecovery defer\(String packageName, File codePath\) \{\n(.*?)\n    \}\n',
                      text, re.S)
    if match is None or text.count('NativePrincipalRecovery defer(') != 1:
        raise ValueError('the recovery view\'s defer is not one method')
    body = statements(match[1].splitlines())
    expected = ['TreeSet<String> protectedCopy = new TreeSet<>(protectedNames);',
                'TreeSet<String> deferredCopy = new TreeSet<>(deferredNames);', 'if (packageName != null) {',
                'if (packageName.isEmpty()) throw new IllegalArgumentException("Empty name");',
                'protectedCopy.add(packageName);', 'deferredCopy.add(packageName);', '}',
                'TreeSet<Path> paths = new TreeSet<>(keptCodePaths);',
                'if (codePath != null) paths.add(path(codePath));',
                'return new NativePrincipalRecovery(heldAppIds, protectedCopy, deferredCopy, files(paths), '
                'unidentifiedCode);']
    if body != expected:
        raise ValueError('the recovery view\'s defer of another shape')
    return {'adds_name': True, 'keeps_holds': True, 'keeps_unidentified': True}


def extract_diagnostic(text):
    """The diagnostic reads the view's deferred names and unidentified mark, and nothing else of
    it."""
    uses = sorted(set(re.findall(r'\brecovery\.([A-Za-z]+)\(', text)))
    if (uses != ['deferredPackageNames', 'hasUnidentifiedCode'] or text.count('= mNativeRecoveryView;') != 1
            or 'mNativeRecoveryView.' in text):
        raise ValueError('the diagnostic reads the recovery view otherwise: %s' % uses)
    return {'reads': uses}


def image_sources(read):
    """One image's sources by path, through a reader, with their digests and extracted shapes."""
    data = {path: read(path) for path in SOURCES}
    patch = data[PATCH].decode()
    return {'files': [{'path': path, 'sha256': sha(value)} for path, value in data.items()],
            'wrapper': extract_wrapper(patch),
            'deferral': extract_deferral(data[DEFERRAL].decode(), patch),
            'recovery': extract_recovery(data[RECOVERY].decode()),
            'diagnostic': extract_diagnostic(data[DIAGNOSTIC].decode())}


def working_tree(path):
    return (ROOT / path).read_bytes()


def sources(readers=None):
    """The sources of both images: B2's from the working tree, the profile pinning its patch, and
    B1's through the floor loader, which checks each against the floor manifest. Both wrappers and
    deferrals must read alike."""
    readers = {'B2': working_tree, 'B1': b1.floor_bytes} if readers is None else readers
    result = {image: image_sources(read) for image, read in readers.items()}
    profile = json.loads(readers['B2'](PROFILE))
    if [row['sha256'] for row in result['B2']['files'] if row['path'] == PATCH] != [profile['patch_sha256']]:
        raise ValueError('the native principal patch differs from its profile')
    for key in ('wrapper', 'deferral', 'recovery', 'diagnostic'):
        if result['B1'][key] != result['B2'][key]:
            raise ValueError('the two images read the scan wrapper otherwise: ' + key)
    candidate = [row['candidate_sha256'] for row in profile['files'] if row['path'] == INSTALL_HELPER]
    return {'images': {image: {'files': value['files'], 'wrapper_lines': value['wrapper']['lines']}
                       for image, value in result.items()},
            'candidate': {'path': INSTALL_HELPER, 'sha256': candidate[0] if len(candidate) == 1 else None},
            'profile': {'path': PROFILE, 'sha256': sha(readers['B2'](PROFILE))}, 'floor_revision': b1.FLOOR}, result


def candidate_problems(pinned, recorded=None):
    """The adapted InstallPackageHelper itself, rebuilt from the pinned canonical framework copies
    by the current patch: its digest the profile's candidate, and at each recorded wrapper line
    the block's opening line."""
    import native_principal_pins as integration
    recorded = sources()[0] if recorded is None else recorded
    value = integration.profile()
    original = {}
    for row in value['files']:
        path = Path(pinned) / row['path']
        if path.is_symlink() or not path.is_file():
            return ['pinned framework copy missing: ' + row['path']]
        original[row['path']] = path.read_bytes()
    output = integration.targets(original, value)[INSTALL_HELPER]
    problems = [] if sha(output) == recorded['candidate']['sha256'] else ['the candidate differs from the profile']
    lines = output.decode().split('\n')
    openers = {'subject': SUBJECT_OPEN, 'binding': BINDING_OPEN.split(', ')[0] + ',', 'handler': HANDLER_OPEN}
    for kind, number in recorded['images']['B2']['wrapper_lines'].items():
        if ' '.join(lines[number - 1].split()) != openers[kind]:
            problems.append('the candidate\'s line %d is not the %s block' % (number, kind))
    return problems


# ---------------------------------------------------------------- the extracted wrapper control


def control(reading, scan, extracted, subject=SUBJECT):
    """The post scan deferred set by interpreting the extracted statements over one reading's
    reported checks: each wrapper block in order while the code is scanned, the handler after a
    scan failure. A failure whose outcome the statements leave undecided refuses."""
    if scan not in SCANS:
        raise ValueError('scan fact')
    outcome, view = reading['scan outcome'], set(reading['deferred set'])
    deferral = extracted['deferral']

    def defer(path):
        if not deferral[path]['defers'] or deferral[path]['unidentified']:
            raise ValueError('a deferral that marks unidentified code is outside this control')
        view.add(subject)

    if scan == 'parked':
        if outcome.get('subject') not in OUTCOMES:
            raise ValueError('a parked boot of a reading without the mapped subject')
        return java_order(view)
    failed, flagged = False, False
    if scan == 'scanned':
        if outcome.get('subject') not in OUTCOMES:
            raise ValueError('a scanned boot of a reading without the mapped subject')
        allowed = dict(zip(('subject', 'binding'), OUTCOMES[outcome['subject']]))
        for kind in ('subject', 'binding'):
            if allowed[kind]:
                continue
            for step in extracted['wrapper'][kind]:
                if step[0] == 'defer':
                    defer(step[2])
                else:
                    failed, flagged = True, step[1] == 'INTERNAL_ERROR_NATIVE_IDENTITY_DEFERRED'
                    break
            if not failed:
                raise ValueError('a failed %s check that does not throw' % kind)
            break
        if failed and not flagged:
            raise ValueError('a scan failure without the native deferral code is outside this control')
    else:
        if 'subject' in outcome or outcome.get('subject unmapped') not in ('protected', 'unprotected'):
            raise ValueError('an unmapped boot of a reading that maps the subject')
        failed = True
    if failed and (flagged or outcome.get('subject unmapped') == 'protected'):
        for step in extracted['wrapper']['handler']:
            defer(step[2])
    return java_order(view)


def control_problems(base, extracted, adapter=adapt):
    """Every base reading at every scan fact it admits, read by the adapter and by the extracted
    control: each disagreement, by input, reader and scan fact."""
    problems = []
    for name, (_, mapping) in base['inputs'].items():
        for reader in READERS:
            reading = base['reads'][name][reader]
            for scan in (('scanned', 'parked') if mapping == 'mapped' else ('unmapped',)):
                want = control(reading, scan, extracted[IMAGES[reader]])
                got = adapter(reading, scan)['deferred set']
                if got != want:
                    problems.append('%s %s %s: the adapter defers %s, the extracted wrapper %s'
                                    % (name, reader, scan, got, want))
    return problems


def prediction_problems(predictions=None, readers=None):
    """The frozen post scan predictions: the base unchanged and named by its digest, every reading
    the adapter's view of its base, the changes exactly the predicted ones, every source as
    recorded, and the extracted wrapper control agreeing with the adapter on every reading."""
    predictions = load_predictions() if predictions is None else predictions
    problems = []
    try:
        base, frozen = base_section(predictions), section(predictions)
        recorded, extracted = sources(readers)
    except (KeyError, OSError, ValueError) as error:
        return ['post scan sources: %s' % error]
    if not frozen:
        return ['no frozen post scan predictions']
    expected = freeze(base, recorded)
    for key in ('base', 'sources', 'checks', 'changes', 'reads'):
        if frozen.get(key) != expected[key]:
            problems.append('the frozen post scan %s differs from the adapter\'s' % key)
    if set(frozen) != set(expected):
        problems.append('the frozen post scan predictions hold other keys: %s' % sorted(set(frozen) ^ set(expected)))
    if [(item['input'], item['reader'], item['added']) for item in expected['changes']] != [
            ('reservation-wrong-serial', reader, [SUBJECT]) for reader in READERS]:
        problems.append('the post scan view changes other readings than the scanned wrong serial')
    problems += control_problems(base, {image: value for image, value in extracted.items()})
    return problems


def main(argv=None):
    """Print the frozen post scan predictions, from which the predictions file's section is
    written, or check that section with --check. Read only."""
    args = sys.argv[1:] if argv is None else argv
    if args not in ([], ['--check']):
        raise SystemExit('usage: native_lifecycle_post_scan.py [--check]')
    if args == ['--check']:
        problems = prediction_problems()
        print(json.dumps({'status': 'FAIL' if problems else 'PASS', 'problems': problems}, indent=2))
        return 1 if problems else 0
    recorded, _ = sources()
    print(json.dumps(freeze(base_section(), recorded), indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
