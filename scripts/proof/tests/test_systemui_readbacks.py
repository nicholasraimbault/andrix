# SPDX-License-Identifier: Apache-2.0
"""The exact shell readback parsers against captured and source derived forms, with controls."""
import json
from pathlib import Path
import re
import unittest

from scripts.proof import systemui_sessions as s

FIXTURES = Path(__file__).parent / 'fixtures' / 'systemui_readbacks'
FORMS = json.loads((FIXTURES / 'forms.json').read_text())
NONCE = '5e1f0c9a7d3b4e2f8a6c1d0b9e7f3a25'
HELPER_COMMAND = 'CLASSPATH=/data/local/tmp/andrix-d3/andrix-checkpoint-read.jar app_process /system/bin CheckpointRead'
HELPER_SHA256 = 'ae6743f64e3b751906e28d282d720ed2bf2dfd9596baeaea3d4fdb2cf53d6738'
# What a guest showed of each source derived form: the form with other values, or only some cases.
GUEST = {'uptime': 'form', 'installs-active-referrer': 'form', 'installs-unknown-package': 'form',
         'version-uid-list': 'form', 'factory-version-list': 'form', 'listing-plain-children': 'partial',
         'installs-historical-outcomes': 'partial', 'installs-foreign-records': 'partial'}


def form(name):
    entry = FORMS[name]
    return entry['exit'], (FIXTURES / (name + '.out')).read_text(), entry['stderr']


def parse(name):
    """The parser that owns a form, by its command."""
    code, output, error = form(name)
    command = FORMS[name]['command']
    if command.startswith('pm list staged-sessions'):
        return s.staged_listing(code, output, '--only-parent' in command)
    if command == 'dumpsys -t 25 package installs':
        return s.installs_dump(code, output)
    if command.startswith('pm path'):
        return s.package_path(code, output)
    if command.startswith('sha256sum '):
        return s.file_digest(code, output, command.split(' ', 1)[1].strip("'"))
    if command == 'getprop ro.build.fingerprint':
        return s.build_fingerprint(code, output)
    if command == 'cat /proc/sys/kernel/random/boot_id':
        return s.boot_id(code, output)
    if command.startswith('cmd package list packages -U'):
        return s.package_uid(code, output)
    if command.startswith('pm list packages') and '--show-versioncode -U' in command:
        return s.package_version_uid(code, output)
    if command == 'vdc checkpoint needsCheckpoint':
        return s.checkpoint_state(code, output, error)
    if command == 'vdc checkpoint supportsCheckpoint':
        return s.checkpoint_support(code, output, error)
    if command == HELPER_COMMAND:
        return s.checkpoint_read(code, output, error)
    if command == 'id':
        return s.shell_identity(code, output, error)
    if command == 'sm supports-checkpoint':
        return s.sm_supports_checkpoint(code, output, error)
    if command.startswith('pm install-create'):
        return s.created_session(code, output)
    if command.startswith('pm install-commit'):
        return s.commit_observation(code, output)
    if command.startswith('pm list packages') and '--factory-only' in command:
        return s.factory_version(code, output)
    if command == 'cat /proc/uptime':
        return s.uptime_ms(code, output)
    if command == 'pidof com.android.systemui':
        return s.pids(code, output)
    if command.startswith('pidof '):
        return s.single_pid(code, output)
    if command.startswith('cat /proc/') and command.endswith('/status'):
        return s.status_uid(code, output, int(command.split('/')[2]))
    if command == 'dumpsys user':
        return s.users(code, output)
    if command.startswith('cat /proc/') and command.endswith('/stat'):
        return s.start_ticks(code, output, int(command.split('/')[2]), 'system_server')
    if command.startswith('cat /proc/') and command.endswith('/attr/current'):
        return s.process_context(code, output)
    if command == 'getprop sys.boot_completed':
        return s.boot_completed(code, output)
    raise AssertionError('no parser for ' + command)


def with_states(text, states):
    """The user listing with each user's state changed, in its own block and in the started users."""
    for user, state in states.items():
        at = text.index('    State: ', text.index('  UserInfo{%d:' % user))
        text = text[:at] + '    State: ' + state + text[text.index('\n', at):]
    started = ', '.join('%d=%s' % (u, state) for u, state in sorted(states.items()) if state != '-1')
    return re.sub(r'  Started users state: \[[^\]\n]*\]\n', '  Started users state: [%s]\n' % started, text)


def listing_text(rows, children=()):
    """Rows rendered through the pinned writer, as printSession prints them."""
    writer = s.IndentingWriter()
    for row in rows:
        writer.println(row)
        if row in children:
            writer.increase()
            for child in children[row]:
                writer.println(child)
            writer.decrease()
    return writer.text()


def listing_rows(output):
    return [r for r in re.split(r'(?<=;)(?=sessionId = )', output.replace('\n', '')) if r]


def section_records(raw, name):
    """Each session of one section as (identity, values, state keys), read with the parser's helpers."""
    records = []
    lines = raw.split('\n')
    for index, line in enumerate(lines):
        header = re.fullmatch(r'  (?:(?:Active|Finalized) )?Session ([0-9]+):', line)
        if not header:
            continue
        body = []
        for following in lines[index + 1:]:
            if not following.startswith('    '):
                break
            body.append(following)
        session, values, keys = s._session(name, int(header[1]), s._logical('\n'.join(body) + '\n', '    '))
        records.append((int(header[1]), list(values), keys))
    return records


def render_section(name, records):
    writer = s.IndentingWriter()
    writer.println(name + ' install sessions:')
    writer.increase()
    for identity, values, keys in records:
        s._render_session(writer, name, identity, values, keys)
        writer.println()
    writer.println()
    writer.decrease()
    return writer.text()


def split_dump(raw):
    titles = [raw.index(t) for t in ('Active install', 'Finalized install', 'Historical install', 'Legacy install')]
    return [raw[titles[0]:titles[1]], raw[titles[1]:titles[2]], raw[titles[2]:titles[3]], raw[titles[3]:]]


def mutate_session(raw, section, change):
    """The dump with one session's fields changed, wrapped again exactly as the writer would."""
    parts = split_dump(raw)
    index = s.SECTIONS.index(section)
    records = section_records(parts[index], section)
    identity, values, keys = records[0]
    keys = list(s.HEADER_KEYS + s.PARAMS_KEYS + keys)
    change(keys, values)
    header, params = len(s.HEADER_KEYS), len(s.HEADER_KEYS) + len(s.PARAMS_KEYS)
    writer = s.IndentingWriter()
    writer.println(section + ' install sessions:')
    writer.increase()
    if section != 'Historical':
        writer.write(section + ' ')
    writer.println('Session %d:' % identity)
    writer.increase()
    for key, value in zip(keys[:header], values[:header]):
        writer.pair(key, value)
    writer.println()
    if section == 'Historical':
        writer.write(''.join(k + '=' + v + ' ' for k, v in zip(keys[header:params], values[header:params])) + '\n')
    else:
        for key, value in zip(keys[header:params], values[header:params]):
            writer.pair(key, value)
        writer.println()
    for key, value in zip(keys[params:], values[params:]):
        writer.pair(key, value)
    writer.println()
    writer.decrease()
    writer.println()
    rest = render_section(section, records[1:])
    text = writer.text() + rest[rest.index('\n') + 1:]
    parts[index] = text
    return ''.join(parts)


class FormTests(unittest.TestCase):
    def test_every_fixture_is_listed_and_free_of_host_paths(self):
        names = {p.stem for p in FIXTURES.glob('*.out')}
        self.assertEqual(names, set(FORMS))
        for name, entry in FORMS.items():
            self.assertIn(entry['origin'], ('captured', 'source'))
            self.assertLessEqual(set(entry), {'command', 'exit', 'origin', 'stderr', 'guest'}, name)
            text = (FIXTURES / (name + '.out')).read_text() + entry['stderr'] + entry['command']
            # The device's own /data/local/tmp is no host path.
            self.assertIsNone(re.search(r'/home/|/srv/|/opt/|(?<!/data/local)/tmp/|/usr/|127\.0\.0\.1|adb ', text), name)
        self.assertEqual(sum(e['origin'] == 'captured' for e in FORMS.values()), 40)
        self.assertEqual(sum(e['origin'] == 'source' for e in FORMS.values()), 27)
        # Only a source derived form can have been shown by a guest with other values or in part,
        # and showing it never makes its fixture a capture.
        self.assertEqual({name: entry['guest'] for name, entry in FORMS.items() if 'guest' in entry}, GUEST)
        self.assertTrue(all(FORMS[name]['origin'] == 'source' for name in GUEST))

    def test_every_known_form_is_accepted(self):
        refused = ('vdc-needs-checkpoint-failed', 'vdc-needs-checkpoint-inaccessible')
        for name in FORMS:
            if name not in refused:
                parse(name)
        for name in refused:
            with self.assertRaises(ValueError):
                parse(name)

    def test_writer_model_renders_every_captured_dump_again(self):
        for name in FORMS:
            if name.startswith('installs-') and FORMS[name]['origin'] == 'captured':
                raw = form(name)[1]
                parts = split_dump(raw)
                for index, section in enumerate(s.SECTIONS):
                    self.assertEqual(render_section(section, section_records(parts[index], section)), parts[index])


class ListingTests(unittest.TestCase):
    def test_captured_listings(self):
        self.assertEqual(parse('listing-empty').sessions, ())
        ready = parse('listing-ready').for_package()
        self.assertEqual([(r.identity, r.ready, r.applied, r.failed) for r in ready],
                         [(2014338406, True, False, False)])
        failed = parse('listing-failed-signer').sessions[0]
        self.assertTrue(failed.failed)
        self.assertTrue(s.intended_rejection('wrong-signer', failed.error))
        self.assertIn(' sessionId: 2014338406 Error:', failed.error)
        self.assertEqual([r.ready for r in parse('listing-ready-failed').sessions], [True, False])
        applied = parse('listing-applied-history').sessions
        self.assertEqual([(r.applied, r.failed) for r in applied],
                         [(True, False), (True, False), (True, False), (False, True), (False, True), (True, False)])
        self.assertTrue(all(r.package == s.PACKAGE and not r.child for r in applied))
        verity = parse('listing-failed-verity').sessions
        self.assertTrue(any(s.intended_rejection('missing-sidecar', r.error) for r in verity))

    def test_the_only_parent_listing_is_not_complete(self):
        self.assertFalse(parse('listing-ready').complete)
        plain = parse('listing-plain-children')
        self.assertTrue(plain.complete)
        self.assertEqual([(r.identity, r.child, r.found) for r in plain.sessions],
                         [(1234567890, False, True), (1234567891, True, True), (1234567892, True, False),
                          (987654321, False, True)])
        self.assertEqual([r.identity for r in plain.for_package()], [1234567891, 987654321])
        with self.assertRaises(ValueError):
            s.staged_listing(1, form('listing-plain-children')[1], True)

    def test_legacy_parser_agrees_on_captured_listings(self):
        for name in FORMS:
            if name.startswith('listing-') and FORMS[name]['origin'] == 'captured':
                code, output, _ = form(name)
                old = s.parent_sessions(code, output)
                new = s.staged_listing(code, output, True).sessions
                self.assertEqual([(r.identity, r.ready, r.applied, r.failed, r.error) for r in old],
                                 [(r.identity, r.ready, r.applied, r.failed, r.error) for r in new])

    def controls(self, rows):
        """Truncated, reordered, extended and unexpected forms of a listing, each wrapped exactly."""
        text = listing_text(rows)

        def first(pattern, replacement):
            return listing_text([re.sub(pattern, replacement, rows[0], count=1)] + rows[1:])
        yield 'truncated', text[:-1]
        yield 'truncated row', text[:len(text) // 2]
        yield 'cut line', text.rsplit('\n', 2)[0] + '\n'
        yield 'reordered', first(r'(isReady = \w+); (isApplied = \w+)', r'\2; \1')
        yield 'extra field', first('; errorMsg = ', '; isSealed = true; errorMsg = ')
        yield 'unexpected staged', first('isStaged = true', 'isStaged = false')
        yield 'unexpected flag', first(r'isFailed = \w+', 'isFailed = yes')
        yield 'zero identity', first(r'sessionId = [0-9]+', 'sessionId = 0')
        yield 'two states', first(r'isApplied = \w+; isFailed = \w+', 'isApplied = true; isFailed = true')
        yield 'duplicate', listing_text(rows + rows[:1])
        flat = text.replace('\n', '')
        yield 'rewrapped', '\n'.join(flat[n:n + 119] for n in range(0, len(flat), 119)) + '\n'
        child = rows[0].replace('sessionId = ', 'sessionId = 9', 1)
        yield 'child under --only-parent', listing_text(rows, {rows[0]: [child]})
        yield 'crlf', text.replace('\n', '\r\n')

    def test_controls_fail(self):
        for name in ('listing-ready', 'listing-failed-signer', 'listing-ready-failed', 'listing-failed-verity',
                     'listing-applied-history'):
            code, output, _ = form(name)
            rows = listing_rows(output)
            self.assertEqual(listing_text(rows), output)
            for label, text in self.controls(rows):
                with self.subTest(form=name, control=label):
                    self.assertNotEqual(text, output)
                    with self.assertRaises(ValueError):
                        s.staged_listing(code, text, True)
            for bad in (0, 255, -1):
                with self.assertRaises(ValueError):
                    s.staged_listing(bad, output, True)

    def test_an_error_message_cannot_forge_a_row(self):
        forged = ('sessionId = 11; appPackageName = com.android.systemui; isStaged = true; isReady = false; '
                  'isApplied = false; isFailed = true; errorMsg = x;sessionId = 12; appPackageName = '
                  'com.android.systemui; isStaged = true; isReady = true; isApplied = false; isFailed = false; '
                  'errorMsg = ;')
        text = listing_text([forged])
        rows = s.staged_listing(1, text, True).sessions
        self.assertEqual([(r.identity, r.failed) for r in rows], [(11, True)])
        self.assertTrue(rows[0].error.startswith('x;sessionId = 12;'))
        # The lenient parser splits the message into a second, ready session.
        self.assertEqual([r.identity for r in s.parent_sessions(1, text)], [11, 12])


class InstallsTests(unittest.TestCase):
    def test_captured_sections(self):
        active = parse('installs-active-ready').section('Active')
        self.assertEqual(len(active), 1)
        session = active[0]
        self.assertEqual((session.identity, session.user, session.installer_uid, session.created_millis),
                         (1378782103, 0, 2000, 1790056243182))
        self.assertEqual(session.stage_dir, '/data/app-staging/session_1378782103')
        self.assertEqual((session.staged, session.committed, session.sealed, session.ready, session.destroyed),
                         (True, True, True, True, False))
        self.assertIsNone(session.referrer)
        historical = parse('installs-active-ready').section('Historical')[0]
        self.assertEqual((historical.final_status, historical.staged), (-2, False))
        self.assertIn('Persistent apps are not updateable.', historical.final_message)
        finalized = parse('installs-finalized-failed').section('Finalized')[0]
        self.assertEqual((finalized.failed, finalized.error_code), (True, -110))
        self.assertTrue(s.intended_rejection('wrong-signer', finalized.error_message))
        two = parse('installs-finalized-two').section('Finalized')
        self.assertEqual([x.identity for x in two], [2014338406, 1978352588])
        self.assertTrue(s.intended_rejection('missing-sidecar', two[1].error_message))
        mixed = parse('installs-finalized-historical')
        refused = mixed.section('Historical')[0]
        self.assertEqual((refused.identity, refused.final_status, refused.committed), (636061908, -103, False))
        self.assertTrue(s.intended_rejection('mismatched-sidecar', refused.final_message))
        self.assertEqual(len(parse('installs-silent-tail').section('Historical')), 1)

    def test_historical_view_agrees_with_the_legacy_parser(self):
        code, output, _ = form('installs-historical-refused')
        old = s.historical_failure(code, output, 1082186470)
        new = parse('installs-historical-refused').section('Historical')[0]
        self.assertEqual((old.identity, old.installer_uid, old.user, old.package, old.status, old.message),
                         (new.identity, new.installer_uid, new.user, new.package, new.final_status, new.final_message))

    def test_nonce_correlation(self):
        dump = parse('installs-active-referrer')
        found = s.sessions_by_nonce(dump, NONCE)
        self.assertEqual([x.identity for x in found], [1378782103])
        self.assertEqual(s.referrer_nonce(found[0].referrer), NONCE)
        self.assertEqual(s.sessions_by_nonce(dump, '1' * 32), ())
        self.assertEqual(s.sessions_by_nonce(dump, NONCE, 'other.app'), ())
        self.assertEqual(s.sessions_by_nonce(parse('installs-active-ready'), NONCE), ())
        for bad in ('0' * 32, 'A' * 32, '1' * 31, '1' * 33, ''):
            with self.assertRaises(ValueError):
                s.nonce_referrer(bad)
        self.assertIsNone(s.referrer_nonce(None))
        self.assertIsNone(s.referrer_nonce('https://example.org/'))
        for bad in ('andrix-ticket:' + '1' * 31, 'andrix-ticket:' + 'G' * 32, 'andrix-ticket:' + '0' * 32):
            with self.assertRaises(ValueError):
                s.referrer_nonce(bad)

    def test_a_referrer_with_a_mismatched_nonce_is_not_the_ticket_session(self):
        raw = form('installs-active-referrer')[1]
        other = mutate_session(raw, 'Active', lambda keys, values: values.__setitem__(
            keys.index('referrerUri'), s.nonce_referrer('2' * 32)))
        self.assertEqual(s.sessions_by_nonce(s.installs_dump(0, other), NONCE), ())
        self.assertEqual(len(s.sessions_by_nonce(s.installs_dump(0, other), '2' * 32)), 1)

    def controls(self, raw, section):
        yield 'truncated end', raw[:-1]
        yield 'truncated half', raw[:len(raw) // 2]
        yield 'truncated section', raw[:raw.index('Historical install sessions:')]
        yield 'truncated tail', raw[:raw.index('Gentle update')]
        parts = split_dump(raw)
        yield 'reordered sections', parts[0] + parts[2] + parts[1] + parts[3]
        yield 'repeated section', parts[0] + parts[0] + parts[1] + parts[2] + parts[3]

        def swap(keys, values):
            a, b = keys.index('mCommitted'), keys.index('mSealed')
            keys[a], keys[b] = keys[b], keys[a]
            values[a], values[b] = values[b], values[a]
        yield 'reordered fields', mutate_session(raw, section, swap)

        def extra(keys, values):
            keys.insert(keys.index('mSealed'), 'mExtraState')
            values.insert(keys.index('mExtraState'), '1')
        yield 'extra field', mutate_session(raw, section, extra)

        def missing(keys, values):
            index = keys.index('stageDir')
            del keys[index], values[index]
        yield 'missing field', mutate_session(raw, section, missing)

        def value(name, text):
            return lambda keys, values: values.__setitem__(keys.index(name), text)
        for name, text in (('mCommitted', 'maybe'), ('createdMillis', '-1'), ('stageDir', '/tmp/x'),
                           ('installFlags', '500032'), ('userId', 'x'), ('mInstallerUid', '2000.0'),
                           ('appPackageName', 'com..systemui'), ('mChildSessionIds', '[0]'),
                           ('mParentSessionId', '7'), ('mFinalMessage', 'a mSealed=true b'),
                           ('mSessionErrorMessage', 'x mPreapprovalDetails=null'), ('createdMillis', '01')):
            yield 'unexpected ' + name + '=' + text, mutate_session(raw, section, value(name, text))

        def both(keys, values):
            values[keys.index('mSessionReady')] = 'true'
            values[keys.index('mSessionFailed')] = 'true'
        yield 'contradictory state', mutate_session(raw, section, both)
        lines = raw.split('\n')
        joined = next(i for i, line in enumerate(lines) if line.startswith('    mode='))
        yield 'rewrapped', '\n'.join(lines[:joined] + [lines[joined] + lines[joined + 1].lstrip()]
                                      + lines[joined + 2:])
        yield 'orphaned section', raw.replace('Finalized install sessions:',
                                              'Orphaned install sessions:\n  \nFinalized install sessions:', 1)
        yield 'legacy session', raw.replace('Legacy install sessions:\n  {}',
                                            'Legacy install sessions:\n  {5=true}', 1)
        yield 'pending check', raw.replace('Num of PendingChecks=0', 'Num of PendingChecks=1', 1)
        yield 'service timeout', raw + '\n*** SERVICE \'package\' DUMP TIMEOUT (25000ms) EXPIRED ***\n'

    def test_controls_fail(self):
        for name, section in (('installs-active-ready', 'Active'), ('installs-finalized-failed', 'Finalized'),
                              ('installs-finalized-historical', 'Historical'),
                              ('installs-historical-refused', 'Historical')):
            code, raw, _ = form(name)
            self.assertEqual(mutate_session(raw, section, lambda keys, values: None), raw)
            for label, text in self.controls(raw, section):
                with self.subTest(form=name, control=label):
                    self.assertNotEqual(text, raw)
                    with self.assertRaises(ValueError):
                        s.installs_dump(code, text)
            for bad in (1, 255):
                with self.assertRaises(ValueError):
                    s.installs_dump(bad, raw)

    def test_an_unknown_pair_after_free_text_is_refused(self):
        def insert(after, key='mExtraField', value='1'):
            def change(keys, values):
                index = keys.index(after) + 1
                keys.insert(index, key)
                values.insert(index, value)
            return change
        live = form('installs-active-ready')[1]
        removed = form('installs-finalized-historical')[1]
        cases = [(live, 'Active', after) for after in (
            'appLabel', 'stageCid', 'referrerUri', 'extensionParams', 'mFinalMessage', 'mSessionErrorMessage',
            'mPreapprovalDetails', 'mCurrentVerificationPolicy')]
        cases += [(removed, 'Historical', after) for after in (
            'appLabel', 'mFinalMessage', 'mSessionErrorMessage', 'mPreVerifiedDomains', 'mCurrentVerificationPolicy')]
        for raw, section, after in cases:
            with self.subTest(section=section, after=after):
                text = mutate_session(raw, section, insert(after))
                self.assertNotEqual(text, raw)
                with self.assertRaises(ValueError):
                    s.installs_dump(0, text)
        abandoned = mutate_session(live, 'Active', insert('mSessionReady', 'mSessionAbandoned', 'true'))
        with self.assertRaises(ValueError):
            s.installs_dump(0, abandoned)
        # A value of a known form may hold '=' without a space and a field name before it.
        label = mutate_session(live, 'Active', lambda keys, values: values.__setitem__(keys.index('appLabel'), 'a=b'))
        self.assertEqual(s.installs_dump(0, label).section('Active')[0].identity, 1378782103)

    def test_records_of_other_packages_block_nothing(self):
        raw = form('installs-foreign-records')[1]
        dump = s.installs_dump(0, raw)
        self.assertEqual([(x.section, x.identity) for x in dump.sessions], [('Finalized', 2014338406)])
        self.assertEqual([x[:2] for x in dump.skipped], [('Active', 1700000000), ('Active', 1700000001),
                                                        ('Active', 1700000002), ('Active', 1700000003),
                                                        ('Historical', 1700000011), ('Historical', 1700000012)])
        record = raw.index('appPackageName=com.example.other')
        for label, text in (
                ('this package', raw[:record] + raw[record:].replace('com.example.other', 'com.android.systemui', 1)),
                ('no package', raw[:record] + raw[record:].replace('com.example.other', 'null', 1)),
                ('prefix of no known form', raw.replace('installScenario=0 sizeBytes=-1 \n    appPackageName=com.example.other',
                                                        'installScenario=x sizeBytes=-1 \n    appPackageName=com.example.other', 1))):
            with self.subTest(label=label):
                self.assertNotEqual(text, raw, label)
                with self.assertRaises(ValueError):
                    s.installs_dump(0, text)
        self.assertEqual(s.prefix_package('userId=0 '), None)

    def test_an_installer_that_prints_a_prefix_is_refused(self):
        # The shell's -i option sets the installer to free text, which can print a whole prefix naming
        # another package. A SystemUI record that carries it is never skipped as another package's.
        spoof = ('null installInitiatingPackageName=null installOriginatingPackageName=null mInstallerUid=2000 '
                 'createdMillis=1 updatedMillis=1 committedMillis=0 stageDir=null stageCid=null mode=1 '
                 'installFlags=0x0 installLocation=1 installReason=0 installScenario=0 sizeBytes=-1 '
                 'appPackageName=com.example.other')

        def installer(keys, values):
            values[keys.index('installerPackageName')] = spoof
        live = mutate_session(form('installs-active-ready')[1], 'Active', installer)
        removed = mutate_session(form('installs-finalized-historical')[1], 'Historical', installer)
        raw = form('installs-foreign-records')[1]
        start = raw.index('Active Child Session 1700000003:')
        child = raw[:start] + raw[start:].replace('installerPackageName=null ', 'installerPackageName=' + spoof + ' ',
                                                  1).replace('appPackageName=com.example.two',
                                                             'appPackageName=com.android.systemui', 1)
        for label, text in (('a live session alone', live), ('a live session as a child', child),
                            ('a removed record', removed)):
            with self.subTest(label=label):
                self.assertIn('appPackageName=com.example.other', text)
                with self.assertRaises(ValueError):
                    s.installs_dump(0, text)

    def test_multiple_package_families(self):
        raw = form('installs-foreign-records')[1]
        for label, old, new in (
                ('a child of this package', 'appPackageName=com.example.two', 'appPackageName=com.android.systemui'),
                ('a child of no package', 'appPackageName=com.example.two', 'appPackageName=null'),
                ('children the parent does not name', '[1700000002, 1700000003]', '[1700000002, 1700000004]'),
                ('a removed child of no package', 'appPackageName=com.example.one appIcon=false appLabel=null originati',
                 'appPackageName=null appIcon=false appLabel=null originatingUri'),
                ('a removed parent naming an absent child', 'mChildSessionIds=[1700000012]', 'mChildSessionIds=[1700000013]'),
                ('a parent of this package', 'sizeBytes=-1 appPackageName=null \n',
                 'sizeBytes=-1 appPackageName=com.android.systemui \n')):
            with self.subTest(label=label):
                text = raw.replace(old, new, 1)
                self.assertNotEqual(text, raw, label)
                with self.assertRaises(ValueError):
                    s.installs_dump(0, text)

    def test_a_child_session_has_no_known_form(self):
        raw = form('installs-active-ready')[1]
        child = raw.replace('  \n  \nFinalized', '    Active Child Session 5:\n      userId=0 \n  \n  \nFinalized', 1)
        with self.assertRaises(ValueError):
            s.installs_dump(0, child)
        multi = mutate_session(raw, 'Active', lambda keys, values: [
            values.__setitem__(keys.index('isMultiPackage'), 'true'),
            values.__setitem__(keys.index('params.isMultiPackage'), 'true')])
        with self.assertRaises(ValueError):
            s.installs_dump(0, multi)


class ActiveAndBootTests(unittest.TestCase):
    def test_paths(self):
        self.assertEqual(parse('path-factory'), ('factory', s.FACTORY_PATH))
        kind, path = parse('path-data')
        self.assertEqual(kind, 'data')
        self.assertTrue(path.endswith('/base.apk'))
        data = form('path-data')[1]
        for label, text in (('truncated', data[:-1]), ('truncated path', data[:30] + '\n'),
                            ('reordered', data[len('package:'):-1] + ' package:\n'),
                            ('extra line', data + 'package:/data/app/~~x/split.apk\n'),
                            ('extra field', data[:-1] + ' uid:10112\n'),
                            ('unexpected path', 'package:/data/local/tmp/base.apk\n'),
                            ('unexpected package', data.replace('com.android.systemui-', 'com.android.other-'))):
            with self.subTest(control=label), self.assertRaises(ValueError):
                s.package_path(0, text)
        with self.assertRaises(ValueError):
            s.package_path(1, data)

    def test_digests(self):
        factory = parse('digest-factory')
        self.assertEqual(len(factory), 64)
        output = form('digest-factory')[1]
        digest, path = output[:64], s.FACTORY_PATH
        for label, text in (('truncated', output[:63] + output[64:]), ('reordered', path + '  ' + digest + '\n'),
                            ('extra field', digest + '  ' + path + ' x\n'), ('unexpected case', digest.upper() + output[64:]),
                            ('other path', digest + '  /system/priv-app/SystemUI/SystemUI.apk\n'),
                            ('no newline', output[:-1])):
            with self.subTest(control=label), self.assertRaises(ValueError):
                s.file_digest(0, text, path)
        data = form('digest-data')
        with self.assertRaises(ValueError):
            s.file_digest(0, data[1], s.FACTORY_PATH)

    def test_a_guest_form_with_other_values(self):
        """A D3 guest showed both version lists, with SystemUI listed first and the vendor overlay of
        SystemUI at versionCode 1. The illustrative fixtures list the overlay first at 37. The parsers
        read the same SystemUI facts from both, so the form is the guest's, while the illustrative
        values are not."""
        for illustrative, captured in (('version-uid-list', 'version-uid-list-systemui-first'),
                                       ('factory-version-list', 'factory-version-list-systemui-first')):
            with self.subTest(form=illustrative):
                self.assertEqual(parse(illustrative), parse(captured))
                guest, fixture = form(captured)[1].splitlines(), form(illustrative)[1].splitlines()
                self.assertNotEqual(guest, fixture)
                self.assertEqual(guest[0].split(' ')[0], 'package:com.android.systemui')
                self.assertEqual(fixture[0].split(' ')[0], 'package:com.android.systemui.auto_generated_rro_vendor__')
                self.assertIn(' versionCode:1', guest[1])
                self.assertIn(' versionCode:37', fixture[0])
                self.assertEqual(sorted(line.split(' ')[0] for line in guest), sorted(line.split(' ')[0] for line in fixture))

    def test_uid_and_version(self):
        self.assertEqual(parse('uid-list'), 10112)
        self.assertEqual(parse('version-uid-list'), (37, 10112))
        self.assertEqual(parse('version-uid-list-systemui-first'), (37, 10112))
        self.assertEqual(parse('factory-version-list-systemui-first'), 37)
        uid = form('uid-list')[1]
        version = form('version-uid-list')[1]
        for label, parser, text in (
                ('truncated', s.package_uid, uid[:-1]), ('reordered', s.package_uid, uid.replace('package:com.android.systemui uid:10112', 'uid:10112 package:com.android.systemui')),
                ('extra field', s.package_uid, uid.replace(' uid:10112', ' versionCode:37 uid:10112')),
                ('unexpected value', s.package_uid, uid.replace('uid:10112', 'uid:x')),
                ('duplicate', s.package_uid, uid + 'package:com.android.systemui uid:10113\n'),
                ('absent', s.package_uid, 'package:com.android.other uid:10113\n'),
                ('truncated', s.package_version_uid, version[:-1]),
                ('reordered', s.package_version_uid, version.replace('versionCode:37 uid:10112', 'uid:10112 versionCode:37')),
                ('extra field', s.package_version_uid, version.replace(' uid:10112', ' stopped=false uid:10112')),
                ('unexpected value', s.package_version_uid, version.replace('versionCode:37 uid:10112', 'versionCode:-1 uid:10112'))):
            with self.subTest(control=label, parser=parser.__name__), self.assertRaises(ValueError):
                parser(0, text)

    def test_boot_id_and_fingerprint(self):
        boot = parse('boot-id')
        self.assertRegex(boot, r'^[0-9a-f-]{36}$')
        output = form('boot-id')[1]
        for label, text in (('truncated', output[:-2] + '\n'), ('reordered', output[9:-1] + '-' + output[:8] + '\n'),
                            ('extra line', output + output), ('unexpected case', output.upper()),
                            ('unexpected version', output[:14] + '1' + output[15:]), ('empty', '')):
            with self.subTest(control=label), self.assertRaises(ValueError):
                s.boot_id(0, text)
        fingerprint = parse('fingerprint')
        output = form('fingerprint')[1]
        for label, text in (('truncated', output.split(':userdebug')[0] + '\n'),
                            ('reordered', output.replace(':userdebug/test-keys', ':test-keys/userdebug')),
                            ('extra field', output[:-1] + '/extra\n'), ('unexpected type', output.replace(':userdebug/', ':debug/')),
                            ('two lines', output + output), ('no newline', output[:-1])):
            with self.subTest(control=label), self.assertRaises(ValueError):
                s.build_fingerprint(0, text)
        self.assertIn(':userdebug/test-keys', fingerprint)

    def test_cohort(self):
        observed = s.cohort(form('fingerprint')[:2], form('digest-factory')[:2])
        expected = s.Cohort(parse('fingerprint'), parse('digest-factory'))
        self.assertTrue(s.cohort_matches(expected, observed))
        moved = s.Cohort(expected.fingerprint.replace('CP2A.260605.016', 'CP2A.260705.001'), expected.factory_digest)
        self.assertFalse(s.cohort_matches(moved, observed))
        rebuilt = s.Cohort(expected.fingerprint, '0' * 63 + '1')
        self.assertFalse(s.cohort_matches(rebuilt, observed))
        with self.assertRaises(ValueError):
            s.cohort(form('fingerprint')[:2], form('digest-data')[:2])
        with self.assertRaises(ValueError):
            s.cohort_matches(s.Cohort('x', expected.factory_digest), observed)
        with self.assertRaises(ValueError):
            s.cohort_matches((expected.fingerprint, expected.factory_digest), observed)

    def test_checkpoint(self):
        # The withdrawn vdc route: source derived and unqualified. The shell cannot run vdc at all.
        self.assertEqual(parse('vdc-needs-checkpoint-pending'), 'pending')
        self.assertEqual(parse('vdc-needs-checkpoint-none'), 'not_checkpointing')
        self.assertTrue(parse('vdc-supports-checkpoint'))
        inaccessible = form('vdc-needs-checkpoint-inaccessible')
        self.assertEqual(inaccessible, (127, '', '/system/bin/sh: vdc: inaccessible or not found\n'))
        for parser in (s.checkpoint_state, s.checkpoint_support):
            with self.assertRaises(ValueError):
                parser(*inaccessible)
        for code, output, error in ((25, '', ''), (22, '', 'Failed to obtain vold Binder\n'), (2, '', ''),
                                    (1, '1\n', ''), (0, '', 'warning\n'), (-1, '', '')):
            with self.subTest(code=code), self.assertRaises(ValueError):
                s.checkpoint_state(code, output, error)
        with self.assertRaises(ValueError):
            s.checkpoint_support(5, '', '')

    def test_one_guests_identity_reads(self):
        """A D3 guest's boot and framework reads: one boot, and system_server 937 started at tick 10829.
        Two stat reads of one instance differ in their counters, never in the start time. A stat read
        is only ever parsed with the PID it was read for, so the trials' fixture of 957 refuses 937."""
        self.assertEqual(parse('boot-id-3e3ad786'), '3e3ad786-b01f-48a0-afba-cab2701946b8')
        self.assertEqual(parse('uptime-997'), 997260)
        self.assertEqual(parse('framework-pid-937'), 937)
        self.assertEqual((parse('framework-stat-937'), parse('framework-stat-937-later')), (10829, 10829))
        self.assertNotEqual(form('framework-stat-937'), form('framework-stat-937-later'))
        with self.assertRaises(ValueError):
            s.start_ticks(0, form('framework-stat')[1], 937, 'system_server')
        with self.assertRaises(ValueError):
            s.start_ticks(0, form('framework-stat-937')[1], 957, 'system_server')

    def test_process_and_boot_forms(self):
        self.assertEqual(parse('uptime'), 5432170)
        self.assertEqual(parse('framework-pid'), 957)
        self.assertEqual(parse('framework-stat'), 14229)
        self.assertEqual(parse('systemui-pid'), [1839])
        self.assertEqual(parse('systemui-context'), 'u:r:platform_app:s0:c512,c768')
        self.assertTrue(parse('boot-completed'))
        self.assertFalse(parse('boot-not-completed'))
        self.assertEqual(parse('factory-version-list'), 37)
        stat = form('framework-stat')[1]
        context = form('systemui-context')[1]
        versions = form('factory-version-list')[1]
        controls = (
            (s.uptime_ms, ('5432.1\n', '20311.84 5432.17 1\n', '5432.17 20311.84 0.00\n', '-5432.17 20311.84\n')),
            (s.single_pid, ('', '957 958\n', '957\n958\n', '0957\n', 'x\n')),
            (lambda c, x: s.start_ticks(c, x, 957, 'system_server'),
             (stat[:40] + '\n', stat.replace('(system_server) S', 'S (system_server)'), stat.replace('957 (', '958 (', 1),
              stat.replace('(system_server)', '(zygote64)'), stat.replace(' 14229 ', ' x ', 1))),
            (s.process_context, (context[:-1], context[:-1] + '\n', context + 'x', context.replace('u:r:', 'u:object_r:'),
                                 context.replace('c512,c768', 'c512'))),
            (s.boot_completed, ('', '0\n', '1', '1\n1\n', 'true\n')),
            (s.factory_version, (versions[:-1], versions.replace('versionCode:37\npackage:com.android.systemui.a', 'x\n', 1),
                                 versions.replace('package:com.android.systemui versionCode:37',
                                                  'versionCode:37 package:com.android.systemui'),
                                 versions.replace('com.android.systemui versionCode:37', 'com.android.systemui versionCode:37 uid:10112'),
                                 versions.replace('com.android.systemui versionCode:37', 'com.android.systemui versionCode:-1'),
                                 versions + 'package:com.android.systemui versionCode:38\n')))
        for parser, texts in controls:
            for text in texts:
                with self.subTest(parser=getattr(parser, '__name__', 'stat'), text=text[:30]), self.assertRaises(ValueError):
                    parser(0, text)
        with self.assertRaises(ValueError):
            s.single_pid(1, '957\n')

    def test_users_and_processes(self):
        self.assertEqual([(u.user, u.serial, u.state, u.removing, u.partial) for u in parse('users-two')],
                         [(0, 0, 'RUNNING_UNLOCKED', False, False), (10, 12, 'RUNNING_UNLOCKED', False, False)])
        self.assertEqual(parse('systemui-pids-two'), [1839, 4721])
        self.assertEqual(s.single_pid(*form('systemui-pid')[:2]), 1839)
        self.assertEqual((parse('systemui-status-1839'), parse('systemui-status-4721')), (10112, 1010112))
        self.assertEqual(parse('systemui-context-4721'), 'u:r:platform_app:s0:c522,c768')
        listing = form('users-two')[1]
        second = listing.index('  UserInfo{10:')
        for state in s.USER_STATES:
            changed = with_states(listing, {0: state, 10: state})
            self.assertEqual({u.state for u in s.users(0, changed)}, {state})
        removed = listing.replace('\n\n  Started', '\n\n  Recently removed userIds: [11, 13]\n  Started')
        self.assertEqual(len(s.users(0, removed)), 2)
        marked = listing.replace('isPrimary=false', 'isPrimary=false <removing>  <partial>')
        self.assertEqual([(u.removing, u.partial) for u in s.users(0, marked)], [(False, False), (True, True)])
        # A listing cut short, or with any line or block of no known form, gives nothing at all.
        controls = (
            listing[:listing.index('\nDevice properties:')], listing[:second] + '    Type: x\n',
            listing.replace('Current user: 0\n', ''), listing.replace('\nUsers:\n', '\nUsers:\n\n', 1),
            listing.replace('    State: RUNNING_UNLOCKED\n', '    State: RUNNING\n', 1),
            listing.replace('    State: RUNNING_UNLOCKED\n', '', 1),
            listing.replace('    State: RUNNING_UNLOCKED\n', '    State: RUNNING_UNLOCKED\n    State: SHUTDOWN\n', 1),
            listing.replace('    Type: android.os.usertype.full.SECONDARY\n', ''),
            listing.replace('serialNo=12 ', 'serialNo=0 '), listing.replace('UserInfo{10:', 'UserInfo{0:'),
            listing.replace('  UserInfo{10:', ' UserInfo{10:'), listing.replace('serialNo=12 ', 'serialNo=x '),
            listing.replace('isPrimary=false', 'isPrimary=false <unknown>'),
            listing.replace('    Ignore errors preparing storage: false\n', 'Ignore errors preparing storage: false\n',
                            1),
            'Current user: 0\n\nUsers:\n\nDevice properties:\n',
            # The started users come from the same states, so a disagreement or a missing list refuses.
            listing.replace('10=RUNNING_UNLOCKED', '10=RUNNING_LOCKED'), listing.replace(', 10=RUNNING_UNLOCKED', ''),
            listing.replace('10=RUNNING_UNLOCKED]', '10=RUNNING_UNLOCKED, 11=RUNNING_LOCKED]'),
            listing.replace('0=RUNNING_UNLOCKED, 10', '0=RUNNING_UNLOCKED,10'),
            listing.replace('0=RUNNING_UNLOCKED, 10=RUNNING_UNLOCKED', '0=RUNNING_UNLOCKED, 0=RUNNING_UNLOCKED'),
            listing[:listing.index('  Started users state:')],
            listing.replace('  Guest restrictions:\n', ''), listing.replace('    no_sms\n', 'no_sms\n'),
            # A state of no known form, even where both places agree.
            with_states(listing, {0: 'RUNNING', 10: 'RUNNING_UNLOCKED'}))
        for text in controls:
            with self.subTest(text=text[-60:]), self.assertRaises(ValueError):
                s.users(0, text)
        with self.assertRaises(ValueError):
            s.users(1, listing)
        status = form('systemui-status-4721')[1]
        for text in (status[:-1], status.replace('Pid:\t4721', 'Pid:\t4722'),
                     status.replace('Uid:\t1010112\t', 'Uid:\t1010113\t'),
                     status.replace('Uid:\t1010112\t1010112\t1010112\t1010112', 'Uid:\t1010112\t1010112\t1010112'),
                     status + 'Uid:\t0\t0\t0\t0\n', status + 'Pid:\t4721\n', status.replace('Uid:', 'Uid :'),
                     status.replace('Pid:\t4721\n', ''), status.replace('Uid:\t1010112', 'Uid:\t-1')):
            with self.subTest(status=text[-40:]), self.assertRaises(ValueError):
                s.status_uid(0, text, 4721)
        for text in ('', '1839 1839\n', '1839  4721\n', '1839\n4721\n', '0839 4721\n', '1839 4721'):
            with self.subTest(pids=text), self.assertRaises(ValueError):
                s.pids(0, text)
        with self.assertRaises(ValueError):
            s.pids(1, '1839\n')

    def test_a_user_name_may_hold_a_serial_marker(self):
        # A name is free text. The greedy name leaves the line's own suffix, which the dump prints last.
        listing = form('users-two')[1]
        for name in ('x} serialNo=99 isPrimary=true', 'a:b{c}:410} serialNo=1 isPrimary=false', ':', '}'):
            with self.subTest(name=name):
                named = listing.replace('UserInfo{10:D5Second:410}', 'UserInfo{10:%s:410}' % name)
                self.assertEqual([(u.user, u.serial, u.state) for u in s.users(0, named)],
                                 [(0, 0, 'RUNNING_UNLOCKED'), (10, 12, 'RUNNING_UNLOCKED')])

    def test_replies(self):
        self.assertEqual(parse('reply-create-staged'), 2014338406)
        self.assertEqual(parse('reply-commit-ready'), 'ready')


class CheckpointHelperTests(unittest.TestCase):
    """The fixed checkpoint helper's protocol, the shell's identity and the companion support read."""

    def test_the_captured_answer(self):
        self.assertEqual(form('checkpoint-read-committed'),
                         (0, 'andrix-checkpoint-read-v1\nsupports=true\nneeds=false\n', ''))
        self.assertEqual(parse('checkpoint-read-committed'), s.CheckpointReading(True, False, ''))
        self.assertEqual(parse('checkpoint-helper-digest'), HELPER_SHA256)

    def test_every_answer_and_refusal(self):
        expected = {
            'checkpoint-read-pending': (True, True, ''), 'checkpoint-read-unsupported': (False, False, ''),
            'checkpoint-read-call-failed': (True, None, 'supports=true needs=error:java.lang.SecurityException'),
            'checkpoint-read-service-absent': (None, None, 'service-absent'),
            'checkpoint-read-lookup-failed': (None, None, 'lookup:java.lang.ClassNotFoundException'),
            'checkpoint-read-arguments': (None, None, 'arguments')}
        for name, value in expected.items():
            self.assertEqual(parse(name), s.CheckpointReading(*value), name)
        # Every pair of answers the protocol allows, with the status the helper computes from them.
        answers = {'true': True, 'false': False, 'error:unknown': None, 'error:not-boolean': None,
                   'error:android.os.DeadObjectException': None, 'error:a.b.C$D': None}
        for supports, first in answers.items():
            for needs, second in answers.items():
                text = 'andrix-checkpoint-read-v1\nsupports=%s\nneeds=%s\n' % (supports, needs)
                code = 0 if None not in (first, second) else 5
                refusal = '' if code == 0 else 'supports=%s needs=%s' % (supports, needs)
                with self.subTest(supports=supports, needs=needs):
                    self.assertEqual(s.checkpoint_read(code, text, ''), s.CheckpointReading(first, second, refusal))
                    with self.assertRaises(ValueError):
                        s.checkpoint_read(5 - code, text, '')

    def test_unknown_forms_are_refused(self):
        committed = form('checkpoint-read-committed')[1]
        for code, output, error in (
                (0, committed, 'WARNING: linker: unused DT entry\n'), (0, 'noise\n' + committed, ''),
                (0, committed + 'extra\n', ''), (0, committed + '\n', ''), (0, committed[:-1], ''),
                (0, committed.replace('\n', '\r\n'), ''), (0, committed.replace('-v1', '-v2'), ''),
                (0, committed.replace('andrix-checkpoint-read-v1\n', ''), ''),
                (0, committed.replace('supports=true', 'supports=TRUE'), ''),
                (0, committed.replace('needs=false', 'needs=false '), ''),
                (0, committed.replace('supports=true\n', ''), ''),
                (0, 'andrix-checkpoint-read-v1\nneeds=false\nsupports=true\n', ''),
                (0, committed.replace('needs=false', 'needs=error:'), ''),
                (0, form('checkpoint-read-call-failed')[1], ''), (1, committed, ''), (5, committed, ''),
                (-1, committed, ''), (255, '', 'Killed\n'), (0, '', ''), (1, '', ''),
                (3, form('checkpoint-read-arguments')[1], ''), (2, form('checkpoint-read-service-absent')[1], ''),
                (4, 'andrix-checkpoint-read-v1\nerror=lookup:\n', ''),
                (4, 'andrix-checkpoint-read-v1\nerror=lookup:java.lang.Bad Name\n', ''),
                (3, form('checkpoint-read-service-absent')[1] + 'more\n', ''),
                (None, committed, ''), (False, committed, ''), (0, committed.encode(), ''), (0, committed, None),
                (0, committed * 100, '')):
            with self.subTest(code=code, output=output[:60], error=error), self.assertRaises(ValueError):
                s.checkpoint_read(code, output, error)

    def test_the_shell_identity(self):
        self.assertEqual(parse('shell-identity'), (2000, 2000, 'u:r:shell:s0'))
        text = form('shell-identity')[1]
        root = 'uid=0(root) gid=0(root) groups=0(root),1004(input),1007(log) context=u:r:su:s0\n'
        self.assertEqual(s.shell_identity(0, root, ''), (0, 0, 'u:r:su:s0'))
        for code, output, error in (
                (0, text[:-1], ''), (0, text + text, ''), (0, text.replace(' context=', ' label='), ''),
                (0, text.replace('uid=2000(shell)', 'uid=2000'), ''), (0, text.replace('groups=', 'groups=,'), ''),
                (0, text.replace(' context=u:r:shell:s0', ''), ''), (0, text.replace('2000(shell) gid', '02000(shell) gid'), ''),
                (1, text, ''), (0, text, 'warning\n'), (0, text.encode(), '')):
            with self.subTest(output=output[-40:], error=error), self.assertRaises(ValueError):
                s.shell_identity(code, output, error)

    def test_the_companion_support_read(self):
        self.assertTrue(parse('sm-supports-checkpoint-true'))
        self.assertFalse(parse('sm-supports-checkpoint-false'))
        for code, output, error in ((1, '', 'Error: java.lang.SecurityException: x\n'), (0, 'true', ''),
                                    (0, 'true\n', 'warning\n'), (0, '1\n', ''), (0, 'true\ntrue\n', '')):
            with self.subTest(output=output, error=error), self.assertRaises(ValueError):
                s.sm_supports_checkpoint(code, output, error)


if __name__ == '__main__':
    unittest.main()
