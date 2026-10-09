#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Guarded host qualification of step D1 of the first durable component transaction, and of the
artifact store of step D2: the deployment records, their codec, the ticket state machine,
reconciliation and host storage, and the bundle manifest, the publication record and durable
publication, as plans/2026-10-09-component-transaction.md and owner/deployment/README.md define them.

Pure source checks run first. An independent encoder, written here from the README's layout tables
alone, gives every golden. Each must have the length and SHA-256 that the Java codec test pins, and
the README must still state the layout facts this encoder relies on. The case lists, the mutant
anchors and the predictions must agree. No compiler or JVM starts unless an actual cgroup bounds this
process to 2 GiB of memory, no swap, 2 CPUs and 256 tasks, with core dumps disabled, and a JDK is on
PATH. Otherwise the run is NOT_RUN. A guarded run compiles the package and its tests, runs the codec,
machine, store, transaction and artifact suites, compares every golden the codec and artifact suites
write with the independent encoder byte for byte, and runs each deliberate defect against the suites
predicted to catch it. It nests no other runner and imports none of the native account lifecycle runners.

Host JVM evidence only: not Android, device storage, power loss or activation evidence."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import resource
import shutil
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
PREDICTIONS = ROOT / 'scripts/proof/component_transaction_records_predictions.json'
README = ROOT / 'owner/deployment/README.md'
PLAN_TEXT = ROOT / 'plans/2026-10-09-component-transaction.md'
MAIN_DIR = 'owner/deployment/java/dev/andrix/server/deployment/'
TEST_DIR = 'owner/tests/deployment/'
PACKAGE = 'dev.andrix.server.deployment'
MAIN = ('DeploymentRecords', 'TicketMachine', 'Reconciler', 'DeploymentStore', 'Coordinator', 'ArtifactRecords',
        'ArtifactStore', 'ApkEntries', 'HostSigner', 'BundleBuilder')
SUPPORT = ('Cases', 'Fixtures', 'AndroidFacade', 'FakeEngine')
SUITES = {'codec': 'DeploymentRecordsTest', 'machine': 'TicketMachineTest', 'store': 'DeploymentStoreTest',
          'transactions': 'TransactionTest', 'artifacts': 'ArtifactStoreTest', 'signing': 'SigningTest'}
RECORDS = MAIN_DIR + 'DeploymentRecords.java'
MACHINE = MAIN_DIR + 'TicketMachine.java'
RECONCILER = MAIN_DIR + 'Reconciler.java'
STORE = MAIN_DIR + 'DeploymentStore.java'
COORDINATOR = MAIN_DIR + 'Coordinator.java'
ARTIFACT_RECORDS = MAIN_DIR + 'ArtifactRecords.java'
ARTIFACT_STORE = MAIN_DIR + 'ArtifactStore.java'
HOST_SIGNER = MAIN_DIR + 'HostSigner.java'
BUNDLE_BUILDER = MAIN_DIR + 'BundleBuilder.java'
PHASES = ('build', 'codec', 'machine', 'store', 'transactions', 'artifacts', 'signing', 'mutants')
GIB = 1 << 30
# Every JVM stays well inside the 2 GiB guard: a capped heap, metaspace and code cache, the serial
# collector, and one client JIT compiler thread instead of parallel compiles. One JVM runs at a time.
JVM_LIMITS = ('-XX:+UseSerialGC', '-XX:TieredStopAtLevel=1', '-XX:CICompilerCount=1', '-XX:MaxMetaspaceSize=128m',
              '-XX:ReservedCodeCacheSize=48m')
JAVAC_HEAP = '-Xmx384m'
JAVA_HEAP = '-Xmx256m'
# The sealed comparison holds two 43 MB APKs and their signed copies at once.
SEALED_HEAP = '-Xmx768m'
# The apksigner jar that reproduced the sealed SystemUI outputs. The tree's apksig sources compile to
# 257 of its 274 apksig classes byte for byte, so the jar itself is pinned.
PINNED_APKSIGNER_JAR = '6b96559764325d085a6bad6be109cc3053791d63826f84dc0e74032db136a196'
APKSIG_SOURCES = ('owner/deployment/apksig/dev/andrix/server/deployment/ApksigEngine.java',
                  'owner/tests/deployment/apksig/SealedOutputsTest.java')
APKSIG_SERVICE = 'owner/deployment/apksig/META-INF/services/com.android.apksig.kms.KmsSignerEngineProvider'
SEALED_NAMES = (
    "sealed / the pinned apksig with the tool's options reproduces every sealed output byte for byte",
    'sealed / six key operations sign the variant and its restoration in one transaction',
    "sealed / the transaction's outputs equal the tool's reference without v1 byte for byte",
    'sealed / an engine that also signs v1 is refused by the operation count',
    "sealed / the six operation outputs hold the sealed outputs' entries without v1",
    'sealed / both bundles verify against the platform role over every scheme',
    'sealed / both bundles publish together through the store')

# ---------------------------------------------------------------- the independent encoder
# Written from the layout tables of owner/deployment/README.md alone, never from the Java codec:
# field order, widths and codes as the README states them. A test oracle only.

MAGIC = 0x52445841
TYPES = {'plan': 1, 'authorization': 2, 'ticket': 3, 'observation': 4, 'selection': 5, 'manifest': 6,
         'publication': 7, 'transaction': 8}
CLASSES = {'STAGED_SYSTEM_APK': 1, 'STAGED_APEX': 2, 'NONSTAGED_APK': 3}
TARGETS = {'VARIANT': 1, 'FACTORY': 2, 'TEMPORARY_FACTORY': 3}
COMMIT_MODES = {'LATE': 1, 'EARLY': 2}
HEALTH_RESPONSES = {'REPORT_AND_WAIT': 1, 'RESTORE_AUTOMATICALLY': 2}
RECOVERY_ROUTES = {'HOST_SHELL': 1, 'DEVICE_COORDINATOR': 2}
EFFECTS = {'SIGN': 1, 'STAGE': 2, 'ACTIVATE': 3, 'SELECT': 4, 'EMERGENCY_NOTICE': 5}
ACTORS = {'GRANT_HOLDER': 1, 'LAB_OPERATOR': 2}
SCOPES = {'NONE': 0, 'ALL_COMPONENTS': 1, 'ONE_COMPONENT': 2}
COORDINATORS = {'HOST': 1, 'DEVICE': 2}
STATES = ('PLANNED', 'AUTHORIZED', 'SIGNING', 'SIGNED', 'PUBLISHED', 'SESSION_INTENT', 'SESSION_BOUND', 'WRITTEN',
          'COMMIT_INTENT', 'READY', 'READY_AGAIN', 'REBOOT_INTENT', 'ABANDON_INTENT', 'BOOT_OBSERVED',
          'APPLIED_PROVISIONAL', 'APPLIED', 'HEALTH_WINDOW', 'SIGN_FAILED', 'NO_SESSION', 'ABANDONED', 'FAILED_NATIVE',
          'NATIVE_RECORD_LOST', 'CLOSED_APPLIED', 'CLOSED_FAILED', 'CANCELLED', 'VOID', 'DIVERGED', 'SUPERSEDED')
FLAGS = {'UNRESOLVED': 1, 'BOOT_LIMIT': 2, 'REQUEST_LIMIT': 4}
CAUSES = {'NONE': 0, 'CANCELLED': 1, 'VOID_SELECTION': 2, 'VOID_TRUST': 3, 'VOID_TARGET': 4, 'VOID_BASE': 5,
          'OTHER_BYTES': 6}
OUTCOMES = {'OBSERVING': 0, 'HEALTHY': 1, 'DEGRADED': 2, 'UNHEALTHY': 3, 'INCONCLUSIVE': 4, 'REMOVED': 5}
CROSSINGS = {'SIGN': (1, 2), 'PUBLISH': (2, 2), 'CREATE': (3, 1), 'WRITE': (4, 1), 'COMMIT': (5, 1),
             'ABANDON': (6, 16), 'REBOOT': (7, 16), 'NOTICE': (8, 17), 'HANDOVER': (9, 4)}
KINDS = {'BOOT': 1, 'CHECKPOINT': 2, 'FACTORY': 3, 'ACTIVE': 4, 'LISTING': 5, 'SESSION': 6, 'REPLY': 7, 'USER': 8,
         'HEALTH': 9, 'SIGNER': 10, 'BUNDLE': 11}
ROUTES = {'SHELL': 1, 'DEVICE': 2, 'HOST': 3}
CLASSIFICATIONS = {
    'BOOT': ('BOOTING', 'COMPLETED'), 'CHECKPOINT': ('PENDING', 'COMMITTED'), 'FACTORY': ('PRESENT',),
    'ACTIVE': ('FACTORY_COPY', 'DATA_COPY'), 'LISTING': ('NONE_FOR_PACKAGE', 'SESSIONS_FOR_PACKAGE', 'INCOMPLETE'),
    'SESSION': ('OPEN', 'SEALED', 'VERIFYING', 'LIVE_NOT_READY', 'READY', 'APPLIED', 'FAILED', 'ABANDONED', 'REFUSED'),
    'REPLY': ('SUCCESS', 'REFUSED', 'READY', 'ACCEPTED', 'PENDING', 'UNRECOGNIZED'),
    'USER': ('RUNNING_UNLOCKED', 'RUNNING_LOCKED', 'NOT_RUNNING', 'REMOVED'),
    'HEALTH': ('HELD', 'DEGRADED', 'CRASH', 'INCONCLUSIVE'),
    'SIGNER': ('PENDING', 'COMPLETED', 'REFUSED', 'CANNOT_COMPLETE'), 'BUNDLE': ('PUBLISHED', 'ABSENT', 'MISMATCH')}
CHOICES = {'FACTORY': 1, 'PLAN': 2}
RESPONSIBILITIES = {'REBUILD_WINDOW': 1, 'KEEP_STALE': 2}
REALIZATIONS = {'UNCHECKED': 1, 'CURRENT': 2, 'STALE_BASE': 3, 'DISPLACED': 4, 'DIVERGED': 5, 'TEMPORARY_FACTORY': 6}
ROLES = {'VARIANT': 1, 'RESTORATION': 2}
SIGNING_SCHEMES = {'V2': 1, 'V3': 2, 'V4': 3}
MEMBERS = {'APK': 1, 'IDSIG': 2}
TRANSACTION_STATES = {'OPEN': 1, 'COMPLETED': 2, 'REFUSED': 3, 'CANNOT_COMPLETE': 4}
OUTPUT_FACTS = {'APK': 1 | 2 | 4 | 16, 'IDSIG': 8 | 16}  # entries, v2, v3 and the role; v4 and the role
V4_CHECKS = {'VERIFIED': 1}
SCHEMES = 1 | 2 | 4  # v2, v3 and v4
NO_USER, NO_SERIAL = -10000, -1
ZERO_ID, ZERO_DIGEST = '00' * 16, '00' * 32
MAX_LEDGER = sum(bound for _, bound in CROSSINGS.values())


def record(kind, body, version=1):
    """One framed record: magic, type, version, total length, body and the SHA-256 of all of it."""
    raw = bytearray(struct.pack('<IHHI', MAGIC, TYPES[kind], version, 0) + body)
    raw[8:12] = struct.pack('<I', len(raw) + 32)
    return bytes(raw) + hashlib.sha256(bytes(raw)).digest()


def text(value):
    data = value.encode('ascii')
    if len(data) > 255 or any(b < 0x20 or b > 0x7e for b in data):
        raise ValueError('not text')
    return struct.pack('<H', len(data)) + data


def raw(hexdigits, size):
    data = bytes.fromhex(hexdigits)
    if len(data) != size:
        raise ValueError('wrong width')
    return data


def ref(presence=0, session=0, created=0, stage='', installer=0, nonce=ZERO_ID):
    return struct.pack('<Biq', presence, session, created) + text(stage) + struct.pack('<i', installer) + raw(nonce, 16)


def plan(p):
    body = raw(p['installation'], 16) + raw(p['plan'], 16) + text(p['component'])
    body += struct.pack('<BB', CLASSES[p['class']], TARGETS[p['target']]) + raw(p['repairs'], 16)
    body += raw(p['bundleInput'], 32) + struct.pack('<q', p['bundleVersion'])
    body += raw(p['signer'], 32) + raw(p['restorationInput'], 32)
    body += struct.pack('<qB', p['restorationVersion'], p['signing']) + text(p['fingerprint'])
    body += raw(p['factoryApk'], 32) + struct.pack('<q', p['factoryVersion'])
    body += raw(p['baseApk'], 32) + struct.pack('<qi', p['baseVersion'], p['baseUid']) + text(p['baseContext'])
    body += struct.pack('<BBq', 1, 1, p['selectionRevision']) + raw(p['trustPolicy'], 32)
    body += struct.pack('<BHq', COMMIT_MODES[p['commitMode']], p['criteria'], p['healthWindow'])
    body += struct.pack('<B', HEALTH_RESPONSES[p['healthResponse']]) + raw(p['restorationPlan'], 16)
    body += struct.pack('<Bqq', RECOVERY_ROUTES[p['recoveryRoute']], p['noticeDelay'], p['emergencyNoticeDelay'])
    body += struct.pack('<HqHqqq', p['bootLimit'], p['rebootTimeLimit'], p['requestLimit'], p['activateWindow'],
                        p['verificationWait'], p['created'])
    return record('plan', body)


def authorization(a):
    body = raw(a['installation'], 16) + raw(a['authorization'], 16) + text(a['component']) + raw(a['plan'], 16)
    body += struct.pack('<BBBiq', EFFECTS[a['effect']], a['inputs'], ACTORS[a['actor']], a['user'], a['serial'])
    body += raw(a['grant'], 16) + struct.pack('<B', SCOPES[a['scope']]) + raw(a['interaction'], 16)
    body += struct.pack('<q', a['grantedAt'])
    return record('authorization', body)


def ticket(t):
    body = raw(t['installation'], 16) + raw(t['ticket'], 16) + text(t['component']) + raw(t['plan'], 16)
    body += struct.pack('<iB', t['attempt'], COORDINATORS[t['coordinatorClass']]) + raw(t['coordinator'], 16)
    flags = sum(FLAGS[name] for name in t['flags'])
    body += struct.pack('<BBBH', STATES.index(t['state']) + 1, flags, CAUSES[t['cause']], t['bootCount'])
    body += raw(t['boot'], 16) + ref(*t['reference']) + raw(t['windowBoot'], 16) + struct.pack('<q', t['windowStart'])
    body += raw(t['successor'], 16) + struct.pack('<H', len(t['health']))
    for user, serial, outcome in t['health']:
        body += struct.pack('<iqB', user, serial, OUTCOMES[outcome])
    body += struct.pack('<H', len(t['ledger']))
    for crossing, boot, instance, elapsed, grant, reference, issued in t['ledger']:
        body += struct.pack('<B', CROSSINGS[crossing][0]) + raw(boot, 16) + struct.pack('<qq', instance, elapsed)
        body += raw(grant, 16) + raw(reference, 16) + struct.pack('<q', issued)
    return record('ticket', body)


def observation(o):
    kind = o['kind']
    body = raw(o['installation'], 16) + raw(o['observation'], 16) + struct.pack('<H', len(o['component']))
    body += o['component'].encode('ascii') + raw(o['boot'], 16) + struct.pack('<iq', o['user'], o['serial'])
    body += struct.pack('<BBqqq', KINDS[kind], ROUTES[o['route']], o['instance'], o['elapsed'], o['wall'])
    body += raw(o['raw'], 32) + struct.pack('<B', CLASSIFICATIONS[kind].index(o['classification']) + 1)
    facts = o.get('facts', {})
    if kind == 'BOOT':
        body += text(facts['fingerprint'])
    elif kind == 'FACTORY':
        body += raw(facts['apk'], 32) + struct.pack('<q', facts['version'])
    elif kind == 'ACTIVE':
        body += raw(facts['apk'], 32) + struct.pack('<qi', facts['version'], facts['uid']) + text(facts['context'])
    elif kind in ('LISTING', 'HEALTH'):
        body += struct.pack('<H', facts['count'])
    elif kind == 'SESSION':
        body += ref(*facts['reference'])
    elif kind == 'REPLY':
        body += raw(facts['ticket'], 16) + struct.pack('<HB', facts['index'], CROSSINGS[facts['crossing']][0])
        body += ref(*facts['reference'])
    elif kind == 'SIGNER':
        body += raw(facts['request'], 16)
    elif kind == 'BUNDLE':
        body += raw(facts['attempt'], 16) + raw(facts['plan'], 16) + raw(facts['publication'], 32)
        body += raw(facts['bundleApk'], 32) + raw(facts['restorationApk'], 32)
    return record('observation', body)


def selection(s):
    body = raw(s['installation'], 16) + text(s['component']) + struct.pack('<qB', s['revision'], CHOICES[s['choice']])
    body += raw(s['plan'], 16) + struct.pack('<Bq', RESPONSIBILITIES[s['responsibility']], s['rebuildWindow'])
    body += struct.pack('<B', REALIZATIONS[s['realization']]) + raw(s['checkedBoot'], 16) + raw(s['repair'], 16)
    body += raw(s['temporary'], 16) + struct.pack('<q', s['changedAt'])
    return record('selection', body)


def manifest(m):
    """A bundle manifest, type 6, from the README's artifact store table."""
    body = raw(m['installation'], 16) + text(m['component']) + struct.pack('<B', ROLES[m['role']])
    body += raw(m['transaction'], 16) + raw(m['input'], 32) + raw(m['inputEntries'], 32)
    body += struct.pack('<q', m['versionCode']) + raw(m['apk'], 32) + struct.pack('<q', m['apkBytes'])
    body += raw(m['idsig'], 32) + struct.pack('<q', m['idsigBytes']) + raw(m['certificate'], 32) + raw(m['key'], 32)
    body += struct.pack('<BHHB', m['schemes'], m['sdkMin'], m['sdkMax'], V4_CHECKS[m['v4']])
    return record('manifest', body)


def publication(p):
    """A publication, type 7: the bundles in order, the variant first, then its restoration, each
    with its own signing transaction."""
    body = raw(p['installation'], 16) + raw(p['plan'], 16) + text(p['component'])
    body += struct.pack('<B', len(p['bundles']))
    for index, bundle in enumerate(p['bundles']):
        body += raw(bundle, 32) + struct.pack('<B', ROLES['VARIANT' if index == 0 else 'RESTORATION'])
        body += raw(p['transactions'][index], 16)
    return record('publication', body + struct.pack('<q', p['published']))


def transaction(t):
    """The host signer's signing transaction, type 8: the approved context, the operations and the
    expected outputs, from the README's table."""
    body = raw(t['installation'], 16) + raw(t['transaction'], 16) + text(t['component']) + raw(t['plan'], 16)
    body += raw(t['authorization'], 16) + raw(t['certificate'], 32) + raw(t['key'], 32)
    body += struct.pack('<HHBBB', t['sdkMin'], t['sdkMax'], TRANSACTION_STATES[t['state']], t['refused'],
                        len(t['operations']))
    for operation, role, scheme in t['operations']:
        body += raw(operation, 16) + struct.pack('<BB', ROLES[role], SIGNING_SCHEMES[scheme])
    body += struct.pack('<B', len(t['outputs']))
    for role, member, input_digest, entries, version, output, size in t['outputs']:
        body += struct.pack('<BBB', ROLES[role], MEMBERS[member], OUTPUT_FACTS[member])
        body += raw(input_digest, 32) + raw(entries, 32) + struct.pack('<q', version) + raw(output, 32)
        body += struct.pack('<q', size)
    return record('transaction', body)


# ---------------------------------------------------------------- the golden values
# The same values the Java codec test builds, restated here as plain data.

INSTALLATION = '00112233445566778899aabbccddeeff'
COMPONENT = 'com.android.systemui'
FINGERPRINT = 'andrix/caiman/caiman:17/BP4A.260813.001/2026081300:userdebug/test-keys'
NEW_FINGERPRINT = 'andrix/caiman/caiman:17/BP4A.261006.001/2026100600:userdebug/test-keys'
WINDOW = 14 * 24 * 3600 * 1000
CONTEXT = 'u:r:platform_app:s0:c512,c768'
UID = 10057
TIME = 1_791_504_000_000


def ident(n):
    return '%032x' % n


def digest(b):
    return '%02x' % b * 32


def base_plan(n):
    return {'installation': INSTALLATION, 'plan': ident(0x100 + n), 'component': COMPONENT,
            'class': 'STAGED_SYSTEM_APK', 'target': 'VARIANT', 'repairs': ZERO_ID, 'bundleInput': digest(0xb1),
            'bundleVersion': 40, 'signer': digest(0x51), 'restorationInput': digest(0xb2),
            'restorationVersion': 41, 'signing': 1, 'fingerprint': FINGERPRINT,
            'factoryApk': digest(0xf0), 'factoryVersion': 37, 'baseApk': digest(0xf0), 'baseVersion': 37,
            'baseUid': UID, 'baseContext': CONTEXT, 'selectionRevision': 0, 'trustPolicy': digest(0x7a),
            'commitMode': 'LATE', 'criteria': 0x7f, 'healthWindow': 600_000, 'healthResponse': 'REPORT_AND_WAIT',
            'recoveryRoute': 'HOST_SHELL', 'restorationPlan': ZERO_ID, 'noticeDelay': 0, 'emergencyNoticeDelay': 0,
            'bootLimit': 4,
            'rebootTimeLimit': 120_000, 'requestLimit': 3, 'activateWindow': 3_600_000, 'verificationWait': 300_000,
            'created': TIME}


def base_ticket(n, plan_id):
    return {'installation': INSTALLATION, 'ticket': ident(0x400 + n), 'component': COMPONENT, 'plan': plan_id,
            'attempt': 1, 'coordinatorClass': 'HOST', 'coordinator': ident(0xc0), 'state': 'PLANNED', 'flags': (),
            'cause': 'NONE', 'bootCount': 0, 'boot': ZERO_ID, 'reference': (), 'windowBoot': ZERO_ID,
            'windowStart': 0, 'successor': ZERO_ID, 'health': [], 'ledger': []}


def fact(n, boot, kind, classification, elapsed, **changes):
    o = {'installation': INSTALLATION, 'observation': ident(0x500 + n), 'component': '', 'boot': boot,
         'user': NO_USER, 'serial': NO_SERIAL, 'kind': kind, 'route': 'SHELL', 'instance': -1, 'elapsed': elapsed,
         'wall': TIME + elapsed, 'raw': digest(0x99), 'classification': classification}
    if kind in ('FACTORY', 'ACTIVE', 'LISTING', 'SESSION', 'REPLY', 'HEALTH', 'SIGNER', 'BUNDLE'):
        o['component'] = COMPONENT
    if kind in ('LISTING', 'SESSION', 'REPLY'):
        o['instance'] = 1
    if kind in ('USER', 'HEALTH'):
        o['user'], o['serial'] = 0, 0
    if kind in ('SIGNER', 'BUNDLE'):
        o.update(route='HOST', boot=ZERO_ID, instance=-1, elapsed=0, wall=TIME)
    o.update(changes)
    return o


def maximum_ticket():
    boot, nonce, coordinator = 'bb' * 16, 'aa' * 16, 'cc' * 16
    finals = ('HEALTHY', 'DEGRADED', 'UNHEALTHY', 'INCONCLUSIVE', 'REMOVED')
    ledger = []
    order = ['SIGN', 'SIGN', 'PUBLISH', 'PUBLISH', 'CREATE', 'WRITE', 'COMMIT']
    for name in ('REBOOT', 'ABANDON', 'NOTICE', 'HANDOVER'):
        order += [name] * CROSSINGS[name][1]
    for n, name in enumerate(order):
        host = name in ('SIGN', 'PUBLISH')
        grant = {'SIGN': '11' * 16, 'CREATE': '22' * 16, 'COMMIT': '33' * 16, 'REBOOT': '33' * 16,
                 'NOTICE': '33' * 16}.get(name, ZERO_ID)
        reference = {'SIGN': '44' * 15 + '%02x' % n, 'PUBLISH': '55' * 15 + '%02x' % n, 'CREATE': nonce,
                     'HANDOVER': coordinator}.get(name, ZERO_ID)
        ledger.append((name, ZERO_ID if host else boot, -1 if host else n, 0 if host else 1000 * n, grant, reference,
                       -n))
    return {'installation': 'ff' * 16, 'ticket': 'ee' * 16, 'component': 'a.' + 'b' * 253, 'plan': 'dd' * 16,
            'attempt': 2 ** 31 - 1, 'coordinatorClass': 'DEVICE', 'coordinator': coordinator, 'state': 'CLOSED_APPLIED',
            'flags': ('BOOT_LIMIT', 'REQUEST_LIMIT'), 'cause': 'CANCELLED', 'bootCount': 0xffff, 'boot': boot,
            'reference': (31, 2 ** 31 - 1, 2 ** 63 - 1, '/' + 's' * 254, 2 ** 31 - 1, nonce), 'windowBoot': ZERO_ID,
            'windowStart': 0, 'successor': ZERO_ID,
            'health': [(i, 3 * i, finals[i % 5]) for i in range(64)], 'ledger': ledger}


def goldens():
    """Every golden of the Java codec test, by its name there, as bytes from this encoder."""
    late = base_plan(1)
    early = dict(base_plan(2), commitMode='EARLY', signing=2, healthResponse='RESTORE_AUTOMATICALLY',
                 recoveryRoute='DEVICE_COORDINATOR', noticeDelay=300_000, emergencyNoticeDelay=60_000,
                 restorationPlan=ident(0x105),
                 repairs=ident(0x101), baseApk=digest(0xa0), baseVersion=39, criteria=0x3f, bootLimit=8,
                 rebootTimeLimit=60_000, requestLimit=5, activateWindow=7_200_000, verificationWait=600_000,
                 selectionRevision=2, created=TIME + 1)
    factory = dict(base_plan(3), target='FACTORY', bundleInput=ZERO_DIGEST, bundleVersion=0,
                   signer=ZERO_DIGEST, restorationInput=ZERO_DIGEST, restorationVersion=0,
                   signing=0, noticeDelay=120_000, emergencyNoticeDelay=120_000, selectionRevision=5,
                   repairs=ident(0x102))
    temporary = dict(base_plan(4), target='TEMPORARY_FACTORY', repairs=ident(0x101), bundleInput=digest(0xb3),
                     bundleVersion=42, restorationInput=ZERO_DIGEST,
                     restorationVersion=0, fingerprint=NEW_FINGERPRINT, factoryApk=digest(0xf1), factoryVersion=38,
                     baseApk=digest(0xa1), baseVersion=40, selectionRevision=1, created=TIME + 3)
    holder = {'installation': INSTALLATION, 'component': COMPONENT, 'actor': 'GRANT_HOLDER', 'user': 0, 'serial': 0,
              'grant': ident(0x9a), 'scope': 'ALL_COMPONENTS'}
    sign = dict(holder, authorization=ident(0x201), plan=late['plan'], effect='SIGN', inputs=3,
                scope='ONE_COMPONENT', interaction=ident(0x301), grantedAt=TIME + 10)
    activate = dict(holder, authorization=ident(0x202), plan=late['plan'], effect='ACTIVATE', inputs=0,
                    actor='LAB_OPERATOR', user=NO_USER, serial=NO_SERIAL, grant=ZERO_ID, scope='NONE',
                    interaction=ident(0x302), grantedAt=TIME + 20)
    emergency = dict(holder, authorization=ident(0x203), plan=early['plan'], effect='EMERGENCY_NOTICE', inputs=0,
                     grant=ident(0x9b), interaction=ident(0x303), grantedAt=TIME + 30)
    planned = base_ticket(1, late['plan'])
    nonce1 = ident(0x6e01)
    unresolved = dict(base_ticket(2, late['plan']), state='SESSION_INTENT', flags=('UNRESOLVED',), boot=ident(0xb0071),
                      reference=(16, 0, 0, '', 0, nonce1), ledger=[
                          ('SIGN', ZERO_ID, -1, 0, ident(0x201), ident(0x7001), TIME + 40),
                          ('PUBLISH', ZERO_ID, -1, 0, ZERO_ID, ident(0x9b01), TIME + 50),
                          ('CREATE', ident(0xb0071), 7, 5000, ident(0x204), nonce1, TIME + 60)])
    boot2 = ident(0xb0072)
    window = dict(base_ticket(3, late['plan']), state='HEALTH_WINDOW', flags=('BOOT_LIMIT',), bootCount=2,
                  boot=ident(0xb0073),
                  reference=(31, 1234567, TIME + 61, '/data/app-staging/session_1234567', 2000, ident(0x6e03)),
                  windowBoot=ident(0xb0073), windowStart=90_000,
                  health=[(0, 0, 'OBSERVING'), (10, 12, 'UNHEALTHY')], ledger=[
                      ('SIGN', ZERO_ID, -1, 0, ident(0x201), ident(0x7003), TIME + 40),
                      ('PUBLISH', ZERO_ID, -1, 0, ZERO_ID, ident(0x9b03), TIME + 50),
                      ('CREATE', boot2, 7, 5000, ident(0x204), ident(0x6e03), TIME + 60),
                      ('WRITE', boot2, 7, 5100, ZERO_ID, ZERO_ID, TIME + 61),
                      ('COMMIT', boot2, 7, 5200, ident(0x202), ZERO_ID, TIME + 62),
                      ('REBOOT', boot2, 7, 6000, ident(0x202), ZERO_ID, TIME + 63)])
    boot4 = ident(0xb0074)
    superseded = dict(base_ticket(4, late['plan']), coordinatorClass='DEVICE', coordinator=ident(0xd0),
                      state='SUPERSEDED', cause='CANCELLED', successor=ident(0x105), bootCount=1, boot=ident(0xb0075),
                      reference=(27, 99, TIME + 70, '', 1000, ident(0x6e04)),
                      health=[(0, 0, 'HEALTHY'), (10, 12, 'REMOVED'), (11, 14, 'DEGRADED')], ledger=[
                          ('CREATE', boot4, 3, 100, ident(0x204), ident(0x6e04), TIME + 71),
                          ('WRITE', boot4, 3, 110, ZERO_ID, ZERO_ID, TIME + 72),
                          ('COMMIT', boot4, 3, 120, ident(0x202), ZERO_ID, TIME + 73),
                          ('NOTICE', boot4, -1, 150, ident(0x202), ZERO_ID, TIME + 74),
                          ('REBOOT', boot4, -1, 200, ident(0x202), ZERO_ID, TIME + 75),
                          ('HANDOVER', ident(0xb0075), -1, 50, ZERO_ID, ident(0xd0), TIME + 76)])
    boot1, boot3 = ident(0xb0071), ident(0xb0073)
    return {
        'PLAN_LATE_ONE': plan(late),
        'PLAN_EARLY_TWO': plan(early),
        'PLAN_FACTORY': plan(factory),
        'PLAN_TEMPORARY': plan(temporary),
        'AUTH_SIGN': authorization(sign),
        'AUTH_ACTIVATE_LAB': authorization(activate),
        'AUTH_EMERGENCY': authorization(emergency),
        'TICKET_PLANNED': ticket(planned),
        'TICKET_UNRESOLVED': ticket(unresolved),
        'TICKET_WINDOW': ticket(window),
        'TICKET_SUPERSEDED': ticket(superseded),
        'TICKET_MAXIMUM': ticket(maximum_ticket()),
        'OBS_BOOT': observation(fact(1, boot1, 'BOOT', 'COMPLETED', 4000, facts={'fingerprint': FINGERPRINT})),
        'OBS_ACTIVE': observation(fact(6, boot3, 'ACTIVE', 'DATA_COPY', 91_000, facts={
            'apk': digest(0xa1), 'version': 40, 'uid': UID, 'context': CONTEXT})),
        'OBS_LISTING': observation(fact(7, boot1, 'LISTING', 'SESSIONS_FOR_PACKAGE', 5300, facts={'count': 1})),
        'OBS_SESSION_SHELL': observation(fact(2, boot1, 'SESSION', 'VERIFYING', 5300, facts={
            'reference': (15, 1234567, TIME + 61, '/data/app-staging/session_1234567', 2000, ZERO_ID)})),
        'OBS_REPLY_DEVICE': observation(fact(3, boot1, 'REPLY', 'SUCCESS', 5010, route='DEVICE', facts={
            'ticket': ident(0x402), 'index': 2, 'crossing': 'CREATE',
            'reference': (27, 99, TIME + 70, '', 1000, nonce1)})),
        'OBS_HEALTH': observation(fact(4, boot3, 'HEALTH', 'DEGRADED', 95_000, user=10, serial=12,
                                       facts={'count': 0x7b})),
        'OBS_SIGNER': observation(fact(5, ZERO_ID, 'SIGNER', 'COMPLETED', 0, facts={'request': ident(0x7001)})),
        'OBS_BUNDLE': observation(fact(8, ZERO_ID, 'BUNDLE', 'PUBLISHED', 0, facts={
            'attempt': ident(0x9b01), 'plan': ident(0x101), 'publication': digest(0xd7), 'bundleApk': digest(0xa1),
            'restorationApk': digest(0xa2)})),
        'SELECTION_FACTORY': selection({'installation': INSTALLATION, 'component': COMPONENT, 'revision': 0,
                                        'choice': 'FACTORY', 'plan': ZERO_ID, 'responsibility': 'REBUILD_WINDOW',
                                        'rebuildWindow': WINDOW, 'realization': 'UNCHECKED', 'checkedBoot': ZERO_ID,
                                        'repair': ZERO_ID, 'temporary': ZERO_ID, 'changedAt': TIME}),
        'SELECTION_STALE': selection({'installation': INSTALLATION, 'component': COMPONENT, 'revision': 3,
                                      'choice': 'PLAN', 'plan': ident(0x101), 'responsibility': 'KEEP_STALE',
                                      'rebuildWindow': 0, 'realization': 'STALE_BASE', 'checkedBoot': ident(0xb0076),
                                      'repair': ident(0x106), 'temporary': ZERO_ID, 'changedAt': TIME + 100}),
        'SELECTION_TEMPORARY': selection({'installation': INSTALLATION, 'component': COMPONENT, 'revision': 1,
                                          'choice': 'PLAN', 'plan': ident(0x101), 'responsibility': 'REBUILD_WINDOW',
                                          'rebuildWindow': WINDOW, 'realization': 'TEMPORARY_FACTORY',
                                          'checkedBoot': ident(0xb0077), 'repair': ident(0x106),
                                          'temporary': ident(0x104), 'changedAt': TIME + 200}),
    }


def artifact_member(n):
    apk = (('signed apk %d ' % n) * (50 + n)).encode('ascii')
    return apk, ('v4 sidecar %d' % n).encode('ascii')


def artifact_manifest(role, n):
    apk, idsig = artifact_member(n)
    return manifest({'installation': INSTALLATION, 'component': COMPONENT, 'role': role, 'transaction': ident(0x5e),
                     'input': digest(0x30 + n), 'inputEntries': digest(0x40 + n),
                     'versionCode': 40 if role == 'VARIANT' else 41, 'apk': sha(apk), 'apkBytes': len(apk),
                     'idsig': sha(idsig), 'idsigBytes': len(idsig), 'certificate': digest(0xc1), 'key': digest(0xc2),
                     'schemes': SCHEMES, 'sdkMin': 37, 'sdkMax': 37, 'v4': 'VERIFIED'})


def artifact_goldens():
    """The artifact store's goldens, the same values the Java artifact suite builds."""
    variant, restoration = artifact_manifest('VARIANT', 1), artifact_manifest('RESTORATION', 2)
    pair = {'installation': INSTALLATION, 'plan': ident(0x101), 'component': COMPONENT,
            'bundles': [sha(variant), sha(restoration)], 'transactions': [ident(0x5e), ident(0x5e)],
            'published': TIME + 9}
    operations = [(ident(0x6f1 + 3 * r + k), role, scheme) for r, role in enumerate(('VARIANT', 'RESTORATION'))
                  for k, scheme in enumerate(('V2', 'V3', 'V4'))]
    outputs, produced = [], []
    for n, role, version in ((1, 'VARIANT', 40), (2, 'RESTORATION', 41)):
        apk, idsig = artifact_member(n)
        for member, data in (('APK', apk), ('IDSIG', idsig)):
            outputs.append((role, member, digest(0x30 + n), digest(0x40 + n), version, ZERO_DIGEST, 0))
            produced.append((role, member, digest(0x30 + n), digest(0x40 + n), version, sha(data), len(data)))
    signing = {'installation': INSTALLATION, 'transaction': ident(0x5e), 'component': COMPONENT, 'plan': ident(0x101),
               'authorization': ident(0x201), 'certificate': digest(0xc1), 'key': digest(0xc2), 'sdkMin': 37,
               'sdkMax': 0xffff, 'state': 'OPEN', 'refused': 0, 'operations': operations, 'outputs': outputs}
    return {'MANIFEST_VARIANT': variant, 'MANIFEST_RESTORATION': restoration, 'PUBLICATION_PAIR': publication(pair),
            'PUBLICATION_ONE': publication(dict(pair, bundles=[sha(variant)], transactions=[ident(0x5e)])),
            'TRANSACTION_OPEN': transaction(signing),
            'TRANSACTION_COMPLETED': transaction(dict(signing, state='COMPLETED', outputs=produced))}


ARTIFACT_GOLDEN_NAMES = ('MANIFEST_VARIANT', 'MANIFEST_RESTORATION', 'PUBLICATION_PAIR', 'PUBLICATION_ONE',
                         'TRANSACTION_OPEN', 'TRANSACTION_COMPLETED')

GOLDEN_NAMES = ('PLAN_LATE_ONE', 'PLAN_EARLY_TWO', 'PLAN_FACTORY', 'PLAN_TEMPORARY', 'AUTH_SIGN', 'AUTH_ACTIVATE_LAB',
                'AUTH_EMERGENCY',
                'TICKET_PLANNED', 'TICKET_UNRESOLVED', 'TICKET_WINDOW', 'TICKET_SUPERSEDED', 'TICKET_MAXIMUM',
                'OBS_BOOT', 'OBS_ACTIVE', 'OBS_LISTING', 'OBS_SESSION_SHELL', 'OBS_REPLY_DEVICE', 'OBS_HEALTH',
                'OBS_SIGNER', 'OBS_BUNDLE', 'SELECTION_FACTORY', 'SELECTION_STALE', 'SELECTION_TEMPORARY')

# The README's statements this encoder relies on: the frame, the bounds and the crossing bounds.
README_FACTS = (
    'u32  magic      0x52445841, "AXDR" in file order',
    'u16  type       1 plan, 2 authorization, 3 ticket, 4 observation, 5 selection',
    'u16   count, then ledger entries in issue order, at most 60:',
    'The crossings, with the most entries of each in one ledger, are 1 SIGN (2), 2 PUBLISH (2), 3 CREATE (1), '
    '4 WRITE (1), 5 COMMIT (1), 6 ABANDON (16), 7 REBOOT (16), 8 NOTICE (17) and 9 HANDOVER (4).',
    '| 11 BUNDLE | component | id attempt, id plan, d32 publication, d32 bundleApk, d32 restorationApk '
    '| 1 PUBLISHED, 2 ABSENT, 3 MISMATCH |',
    'i32   user                  >= 0, or -10000 (USER_NULL) for no user          prefix',
    'They use the frame above with types 6, 7 and 8, version 1, and at most 4,096 bytes.',
    'u8    schemes               bit 0 v2, 1 v3, 2 v4: exactly 7                         strict',
    'then for each: d32 bundle, nonzero, u8 role, VARIANT first, then RESTORATION, '
    'and id transaction, the bundle\'s own signing transaction, nonzero',
    'The bundle ID is the SHA-256 of the manifest\'s whole frame, checksum included.',
)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def strict(text_value):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate key')
            result[key] = value
        return result
    return json.loads(text_value, object_pairs_hook=unique)


# ---------------------------------------------------------------- predicted case names
# Every case each suite prints, in its run order. Names built in a loop are built the same way
# here, and their templates are checked in the source; every other name appears there once.

KIND_LABELS = ('plan', 'authorization', 'ticket', 'observation', 'selection')
CODEC_NAMES = (
    *('golden / ' + name.lower().replace('_', ' ') for name in GOLDEN_NAMES),
    'golden / authorization layout written by hand',
    'golden / ticket layout written by hand',
    'frame / magic, type, version, length and checksum are verified first',
    'decoder refuses / unknown strict codes in every kind',
    'decoder accepts / informational fields take any value',
    'decoder refuses / zero IDs and digests where a value is required',
    'decoder refuses / text that is empty, too long or not printable',
    'decoder refuses / plan relations',
    'decoder refuses / authorization relations',
    'decoder refuses / ticket relations',
    'decoder refuses / ledger bounds, order and references',
    'decoder refuses / observation scope',
    'decoder refuses / a bundle fact names its attempt and its plan',
    'decoder refuses / bundle fact digests are set exactly when it read the publication',
    'decoder refuses / selection relations',
    'decision 8 / one or two signing transactions fit the layout',
    'decision 2 / both commit modes fit the layout',
    'observation / no user is USER_NULL with serial -1',
    'size / the largest ticket fits MAX_BYTES',
    *('mutation / resealed %s mutations are refused or canonical' % label for label in KIND_LABELS),
    'prefix / later versions give what each record concerns',
    'prefix / version 1 and damaged frames give no prefix',
    'prefix / nothing after the prefix is read',
    'prefix / each frozen rule refuses',
    'surface / values are closed and print no references')

MACHINE_NAMES = (
    'exits / every state has an exit and terminal states have none',
    "exits / the table is the plan's table",
    'loops / every cycle passes a boot or request edge',
    'loops / the four loops are declared bounded or held',
    'check / refuses steps outside the table',
    'check / ABANDON_INTENT to BOOT_OBSERVED and every DIVERGED exit need a COMMIT in the ledger',
    'unresolved / every intent state waits without evidence and never replays',
    'unresolved / an exact native reference clears the flag',
    'unresolved / a reused session ID is not the exact reference',
    'unresolved / proof of absence clears the flag',
    'unresolved / a listing in the same framework instance proves nothing',
    'unresolved / an abandon is repeated only after a later framework instance shows the session live',
    'unresolved / the shell route never sees the nonce',
    'cancel / deferred until the intent resolves',
    'cancel / before any session the ticket closes at once',
    'void / selection and trust changes void before commit',
    'void / after commit a session not yet activated is abandoned and one activating is observed',
    'native accounts / a held target voids the plan before any crossing',
    'late commit / ACTIVATE is required before SESSION_INTENT',
    'early commit / ACTIVATE before COMMIT_INTENT and any reboot applies',
    'ready again / late commit reboots at once under an unexpired unused ACTIVATE',
    'ready again / late commit abandons without one',
    'ready again / an expired ACTIVATE is never used',
    'ready again / the request limit counts lost requests, not reboots that took effect',
    'ready again / notice and its delay come first',
    'ready again / other running users get notice and a declared delay',
    'notice / a restoration shortens notice only under an emergency policy',
    'notice / a rebuilt variant, an unlisted repair or a temporary factory plan never shortens notice',
    'checkpoint / no crossing and no close before the commit',
    'checkpoint / APPLIED only once the checkpoint is observed committed',
    "applied / the bundle's bytes are the APK that its publication bound",
    'publish / a missing publication read holds with the alert, and a cancellation still abandons',
    'applied / a changed UID or context is not applied',
    'boot / a boot during COMMIT_INTENT is BOOT_OBSERVED',
    'boot / outcomes after the activation boot',
    'record lost / the active bytes decide',
    "record lost / before any commit the bundle's bytes are never applied",
    'boot / an applied session with other or prior bytes active is DIVERGED',
    'diverged / other bytes close a live session only after abandoning it',
    'failed native / a changed fingerprint voids',
    'write / a lost or refused write reply abandons the session',
    'commit / a later framework instance with the session live but not ready abandons',
    'loops / the reboot request loop abandons at the request limit',
    'loops / the health window ends UNHEALTHY at the boot limit',
    'restoration / at the boot limit the restoration listed in the approval takes over',
    'loops / the provisional loop holds with the boot limit alert',
    'loops / the abandon loop holds with the request limit alert',
    'loops / the boot limit alert on every path repeating across boots',
    'health / outcomes by serial, crashes, removals and new users',
    'health / a stale base is never healthy',
    'health / an unavailable observation is inconclusive, never unhealthy',
    'restoration / automatic restoration runs only when the approval listed it',
    'health / probes that miss a declared criterion are inconclusive',
    'selection / the choice moves at APPLIED and only then',
    'selection / a move lost between two writes is made at APPLIED or in the health window',
    'selection / an owed move in a step that closes DIVERGED takes the realization from its facts',
    'selection / a void or cancelled plan never moves the choice',
    'cohort / CURRENT, STALE_BASE, DISPLACED and DIVERGED',
    'cohort / an Android deletion keeps the choice',
    'cohort / an open repair plan is linked and the link outlives a status change',
    'cohort / an activation in flight keeps the previous status',
    'cohort / an owner approved temporary factory state keeps the choice',
    'selection / a temporary factory plan never moves the choice',
    'factory / a factory plan changes the choice by authorization alone',
    'signing / one transaction by default and the two that the records still allow',
    'signing / a later attempt skips signing only when the bundles read back published',
    'publish / a lost acknowledgement is resolved by reading, never by publishing again',
    'publish / a second publication follows only a read of absence naming the attempt',
    'publish / a read of other bytes holds with the request limit alert',
    'handover / the coordinator changes only by a recorded handover')

STORE_NAMES = (
    'store / round trip of every kind',
    'store / records are written once and read back as exact bytes',
    'store / a crash at each write step leaves the old record or the new one',
    'store / staging leftovers are never records',
    'store / presence as absent, damaged, newer or unavailable',
    'store / newer, damaged and unknown ticket files block every new ticket',
    'store / one open ticket per component and attempts in order',
    'store / ticket updates must be legal steps from the exact stored bytes',
    "store / a selection's choice changes only with the next revision",
    'store / the realization changes only at the same revision',
    'store / a temporary factory state names its stored stand-in and keeps the choice',
    "store / file names repeat the record's ID",
    'store / authorizations need their stored plan of the same component',
    "store / every write follows the protocol's steps in order")

TRANSACTION_NAMES = (
    *('flow / %s route, %s commit, %s' % (route, mode, signing) for route in ('shell', 'device')
      for mode in ('late', 'early') for signing in ('one signing transaction', 'two signing transactions')),
    'recovery / create reply lost on the shell route stays unresolved until a listing shows none',
    'recovery / create reply lost on the device route is found by nonce',
    'recovery / framework restart before commit loses the record and a new attempt follows',
    'recovery / write fails or its reply is lost',
    'recovery / commit reply lost, ready or failed',
    'recovery / framework restart during commit',
    'recovery / framework restart while READY',
    'recovery / unclean stop after READY, applied, ready again or abandoned',
    'recovery / reboot request lost up to the request limit',
    'recovery / abandon reply lost, gone or still live in a later instance',
    'recovery / install fails at boot',
    'recovery / stop before the checkpoint commits repeats the install',
    'recovery / a session made ready again waits for the checkpoint and activates nothing on a crash',
    'recovery / cancellation at each step',
    'recovery / image change with a pending session, committed and uncommitted',
    'recovery / image change deletes the variant and DISPLACED keeps the choice',
    'recovery / image change keeps the variant as STALE_BASE, never healthy',
    'recovery / session file damaged',
    'recovery / storage freeing while a session waits',
    'recovery / another installer or a downgrade through root',
    'recovery / users added, removed and switched during activation',
    'recovery / coordinator lost at every step resumes by observation',
    'recovery / coordinator lost between the selection and ticket writes keeps the choice',
    'recovery / chosen bytes that return after other bytes are CURRENT again',
    'recovery / crash during the health window',
    'repair / a linked repair plan supersedes the window and restores',
    'decision 3 / automatic restoration takes over only on an observed failure',
    'decision 3 / automatic restoration takes over at the boot limit',
    'decision 6 / a temporary factory copy keeps the choice until the rebuild lands',
    'decision 7 / other running users get notice and a declared delay before the reboot',
    *('faults / sweep at every crossing on the %s route, %s commit' % (route, mode) for route in ('shell', 'device')
      for mode in ('late', 'early')),
    'faults / world events at every round',
    'invariants / every run kept every invariant')

ARTIFACT_NAMES = (
    'records / goldens of both manifests and both publications',
    'records / strict codes, relations and trailing bytes are refused',
    'records / informational times decide nothing and the prefix reads a later version',
    'records / every single byte change is refused or canonical',
    'records / the same bytes keep one bundle ID, and the output may equal its input',
    'store / the pair is staged, published together and read back exactly',
    'store / a stop at every step leaves both bundles visible or neither',
    "store / refusing either bundle's verification publishes nothing",
    'store / every bundle is verified before anything is renamed',
    'store / a bundle is never published alone',
    'store / a lost acknowledgement resolves by reading the exact bytes',
    'store / changed, missing or extra members read as MISMATCH',
    'store / unpublished bundles, staging leftovers and unreadable publications',
    'store / a different bundle under the same ID is never replaced',
    'store / the plan names its inputs and the publication binds the bundles signed from them',
    'store / a second publication completes from the bundles the store already holds',
    'store / a pair from two signing transactions fits the publication',
    "store / a restoration plan publishes the restoration that its pair's publication made visible",
    'store / a plan that signs nothing publishes only the restoration its repaired pair published',
    "store / every bundle carries the plan's signer certificate",
    'records / the signing transaction record keeps its goldens, strict codes, relations and prefix')

SIGNING_NAMES = (
    'signer / the record is written OPEN before the first key operation and names six operations and '
    'four outputs',
    'signer / refusing each signing callback in turn publishes nothing',
    'signer / a lost signing reply resolves by the transaction ID, never by signing again',
    'signer / a request that can no longer complete records SIGN_FAILED',
    'builder / every scheme verifies and every signer has the platform role',
    'builder / both bundles publish together through the store, or neither',
    'builder / a lost acknowledgement resolves by reading the exact bytes',
    'builder / a second publication completes from the held bundles without signing again',
    'builder / a pair from two signing transactions publishes together',
    'builder / a restoration plan publishes the already published restoration')

NAMES = {'codec': CODEC_NAMES, 'machine': MACHINE_NAMES, 'store': STORE_NAMES, 'transactions': TRANSACTION_NAMES,
         'artifacts': ARTIFACT_NAMES, 'signing': SIGNING_NAMES}

# The loop built names: a pattern for the names and the source fragments that build them.
GENERATED = {
    'codec': ((r'golden / [a-z ]+', ('cases.run("golden / " + name.toLowerCase().replace(\'_\', \' \')',)),
              (r'mutation / resealed [a-z]+ mutations are refused or canonical',
               ('"mutation / resealed " + label + " mutations are refused or canonical"',))),
    'transactions': ((r'flow / (shell|device) route, (late|early) commit, (one|two) signing transactions?',
                      ('"flow / " + route.toString().toLowerCase() + " route, "',
                       '(signing == 1 ? "one signing transaction" : "two signing transactions")')),
                     (r'faults / sweep at every crossing on the (shell|device) route, (late|early) commit',
                      ('"faults / sweep at every crossing on the " + route.toString().toLowerCase() + " route, "',))),
}

# ---------------------------------------------------------------- deliberate defects
# Each defect: its edits, as target, exact old text and new text, and the suites that run it. The
# predictions file lists the cases each must fail. A compile failure is a harness failure.

_SIGN_UNRESOLVED = '            return unresolved(c, b, "signing reply missing: resolved only by its request ID");\n'
_WINDOW_IMAGE = ('        if (cohortChanged(c)) {\n'
                 '            b.health(finish(b.health(), Outcome.INCONCLUSIVE));\n'
                 '            return close(c, b, State.CLOSED_APPLIED, "an image change ends the window");\n')
_ACTIVATE_GRANT = '        if (activate == null) return abandon(c, b, "no unexpired ACTIVATE that no reboot has used");\n'
_ACTIVATE_LIMIT = (_ACTIVATE_GRANT + '        if (lostRequests(t, c.now.boot) >= p.requestLimit) '
                   'return abandon(c, b, "reboot request limit");\n')
_REBOOT_LIMIT = ('            if (lostRequests(t, c.now.boot) >= p.requestLimit) '
                 'return abandon(c, b, "reboot request limit");\n'
                 '            return to(c, b, State.READY,')
_APPLIED_OTHER = ('                    b.cause(maxCause(b.cause(), Cause.OTHER_BYTES));\n'
                  '                    return close(c, b, State.DIVERGED, "applied, but other or prior bytes are active");\n')
_COMMIT_CHECK = ('        if (!sameState && after.count(Crossing.COMMIT) == 0 && (after.state == State.DIVERGED\n'
                 '                || (before.state == State.ABANDON_INTENT && after.state == State.BOOT_OBSERVED))) {\n'
                 '            return "no COMMIT in the ledger for " + before.state + " -> " + after.state;\n'
                 '        }\n')
_ABANDON_HOLD = ('            if (t.count(Crossing.ABANDON) >= p.requestLimit) {\n'
                 '                b.set(FLAG_REQUEST_LIMIT);\n'
                 '                return done(c, b, null, null, "abandon request limit: holding and alerting");\n'
                 '            }\n')
_PUBLICATION_WRITE = '            if (!write(index, bytes)) return false; // Visible from here.\n'
_VERIFY_EACH = ('                String reason = verifier.verify(b);\n'
                '                if (reason != null) return false;\n')
_OBSERVATION_END = ('            case BUNDLE:\n                b.subject = in.id();\n                b.plan = in.id();\n'
                    '                b.digest = in.digest();\n                b.bundleApk = in.digest();\n'
                    '                b.restorationApk = in.digest();\n'
                    '                break;\n            default:\n                break;\n        }\n        in.finish();\n')
_PUBLISH_READ = ('        if (c.view.publication(last.reference, c.plan.planId) != Classification.BUNDLE_ABSENT) '
                 'return null;\n')
_PUBLISH_HOLD = ('        b.set(FLAG_REQUEST_LIMIT);\n'
                 '        return done(c, b, null, null, "a second publication had no effect: holding and alerting");\n')
_HELD_OR_STAGED = ('                if (!exact(root.resolve(STAGING + "-" + b.id), b) && !exact(bundle(b.id), b)) '
                   'return false;\n')
_MISMATCH_HOLD = ('        if (mismatch(c)) {\n'
                  '            b.set(FLAG_REQUEST_LIMIT);\n'
                  '            return done(c, b, null, null, "the publication names other bytes: holding and alerting");\n'
                  '        }\n')
_BOUND = ('                    || !m.component.equals(plan.component) || !m.inputEntries.equals(inputs.get(i))\n'
          '                    || m.versionCode != version || !m.transaction.equals(publication.transactions.get(i))) {\n')

MUTANTS = {
    # The plan's named defects.
    'replay-lost-sign-reply': (((RECONCILER, _SIGN_UNRESOLVED,
        '            return issue(c, b, State.SIGNING, entry(c, Crossing.SIGN, last.grant, c.ids.get()), '
        '"sign again");\n'),),
        ('machine',)),
    'replay-abandon-same-instance': (((RECONCILER, '        if (s != null && later(s, abandon)) {\n',
                                       '        if (s != null) {\n'),), ('machine',)),
    'early-applied-before-checkpoint': (((RECONCILER,
        '                if (crossingAllowed(c) && appliedFacts(c)) return applied(c, b);\n',
        '                if (appliedFacts(c)) return applied(c, b);\n'),), ('machine', 'transactions')),
    'early-close-before-checkpoint': (((RECONCILER,
        '        if (created(c.ticket) && !crossingAllowed(c)) {\n'
        '            return done(c, b, null, null, why + "; waiting for the checkpoint");\n        }\n', ''),),
        ('machine',)),
    'second-create-bound': (((RECORDS, 'SIGN(1, 2), PUBLISH(2, 2), CREATE(3, 1), WRITE(4, 1),',
                              'SIGN(1, 2), PUBLISH(2, 2), CREATE(3, 2), WRITE(4, 1),'),), ('codec',)),
    'second-commit-replayed': (((RECORDS, 'WRITE(4, 1), COMMIT(5, 1), ABANDON(6, 16),',
                                 'WRITE(4, 1), COMMIT(5, 2), ABANDON(6, 16),'),
                                (RECONCILER, '        return unresolved(c, b, "commit reply lost or ambiguous");\n',
                                 '        return issue(c, b, State.COMMIT_INTENT, '
                                 'entry(c, Crossing.COMMIT, commit.grant, NO_ID),'
                                 ' "commit again");\n')), ('codec', 'machine')),
    'ready-again-waits-under-late-commit': (((RECONCILER,
        '        if (p.commitMode == CommitMode.LATE) return activate(c, b);\n',
        '        if (p.commitMode == CommitMode.LATE && t.state == State.READY) return activate(c, b);\n'),),
        ('machine', 'transactions')),
    'boot-during-commit-ignored': (((RECONCILER,
        '        if (newBoot) return to(c, b.clear(FLAG_UNRESOLVED), State.BOOT_OBSERVED, '
        '"a kernel boot during commit");\n',
        ''),), ('machine', 'transactions')),
    'android-deletion-resets-choice': (((RECONCILER, '                status = Realization.DISPLACED;\n',
        '                return s.chosen(ChoiceKind.FACTORY, NO_ID, Realization.CURRENT, view.boot, s.changedAt);\n'),),
        ('machine', 'transactions')),
    'stale-base-reported-healthy': (((RECONCILER, _WINDOW_IMAGE,
                                      _WINDOW_IMAGE.replace('Outcome.INCONCLUSIVE', 'Outcome.HEALTHY')),),
                                    ('machine', 'transactions')),
    'expired-activate-used': (((RECONCILER,
        '        return wall < a.grantedAt || wall - a.grantedAt >= c.plan.activateWindowMillis;\n',
        '        return wall < a.grantedAt;\n'),), ('machine', 'transactions')),
    'diverged-close-with-live-session': (((RECONCILER,
        '                return abandon(c, b, "other bytes active while the session lives");\n',
        '                return close(c, b, State.DIVERGED, "other bytes active while the session lives");\n'),),
        ('machine', 'transactions')),
    # The codec's rules.
    'unknown-commit-mode-accepted': (((RECORDS,
        '        b.commitMode = code(CommitMode.values(), in.u8(), c -> c.code, "commit mode");\n',
        '        b.commitMode = in.u8() == 2 ? CommitMode.EARLY : CommitMode.LATE;\n'),), ('codec',)),
    'observation-trailing-bytes': (((RECORDS, _OBSERVATION_END,
                                     _OBSERVATION_END.replace('        in.finish();\n', '')),), ('codec',)),
    'prefix-reads-version-1': (((RECORDS,
                                 '        if (version <= VERSION) throw invalid("no prefix reading of this version");\n',
                                 '        if (version < VERSION) throw invalid("no prefix reading of this version");\n'),),
                               ('codec',)),
    'no-user-any-serial': (((RECORDS,
                             '            if (user != NO_USER || serial != NO_SERIAL) '
                             'throw invalid("NO_USER needs NO_SERIAL");\n',
                             '            if (user != NO_USER) throw invalid("NO_USER needs NO_SERIAL");\n'),), ('codec',)),
    'unresolved-outside-intent': (((RECORDS, '            if ((flags & FLAG_UNRESOLVED) != 0 && !state.intent()) {\n',
                                    '            if ((flags & FLAG_UNRESOLVED) != 0 && state == null) {\n'),), ('codec',)),
    'grant-scope-unchecked': (((RECORDS,
                                '            if ((grantScope == GrantScope.NONE) != grant.equals(NO_ID)) {\n'
                                '                throw invalid("a grant scope exactly with a grant");\n'
                                '            }\n', ''),), ('codec',)),
    'two-signings-without-restoration': (((RECORDS,
        '                if (signing < 0 || signing > 2 || (signing == 2 && !hasRestoration)) {\n',
        '                if (signing < 0 || signing > 2) {\n'),), ('codec',)),
    'ledger-order-unchecked': (((RECORDS,
        '                        if (entry.crossing.code < phase) throw invalid("ledger sequence out of order");\n', ''),),
        ('codec',)),
    'informational-time-refused': (((RECORDS, '        b.createdAt = in.i64();\n',
                                     '        b.createdAt = in.i64();\n'
                                     '        if (b.createdAt < 0) throw invalid("negative time");\n'),),
                                   ('codec',)),
    # The machine, reconciliation and the store.
    'boot-edge-without-boot': (((MACHINE,
        '        if (edge == Edge.BOOT && (!newBoot || before.boot.equals(DeploymentRecords.NO_ID))) {\n',
        '        if (edge == Edge.BOOT && newBoot && before.boot == null) {\n'),), ('machine',)),
    'late-commit-without-activate': (((RECONCILER,
        '            if (activate == null) return null; // Late commit: ACTIVATE before SESSION_INTENT.\n', ''),),
        ('machine',)),
    'cancel-cuts-intent-short': (((RECONCILER,
        '    private static Step sessionIntent(Context c, Ticket.Builder b) {\n        Ticket t = c.ticket;\n',
        '    private static Step sessionIntent(Context c, Ticket.Builder b) {\n        Ticket t = c.ticket;\n'
        '        if (b.cause() != Cause.NONE) return to(c, b.clear(FLAG_UNRESOLVED), State.NO_SESSION, "cut short");\n'),),
        ('machine',)),
    'crossing-in-checkpointed-boot': (((RECONCILER,
        '        return c.now != null && c.view.checkpoint() == Classification.CHECKPOINT_COMMITTED;\n',
        '        return c.now != null;\n'),), ('machine', 'transactions')),
    'boot-limit-not-alerted': (((RECONCILER,
                                 '                    if (t.bootCount + 1 >= p.bootLimit) b.set(FLAG_BOOT_LIMIT);\n',
                                 ''),), ('machine', 'transactions')),
    'reboot-loop-unbounded': (((RECONCILER, _ACTIVATE_LIMIT, _ACTIVATE_GRANT),
                               (RECONCILER, _REBOOT_LIMIT, '            return to(c, b, State.READY,')),
                              ('machine', 'transactions')),
    'abandon-loop-unheld': (((RECONCILER, _ABANDON_HOLD, ''),), ('machine',)),
    'one-open-ticket-unchecked': (((STORE,
        '            if (t.component.equals(ticket.component) && !t.state.terminal()) return false;\n', ''),),
        ('store', 'transactions')),
    'cancelled-plan-moves-choice': (((RECONCILER,
        '        if (cause != Cause.NONE || s.revision != p.selectionRevision || c.now == null) return null;\n',
        '        if (s.revision != p.selectionRevision || c.now == null) return null;\n'),), ('machine',)),
    'reused-session-id-binds': (((RECONCILER,
        '        if (both(ticket, seen, Reference.CREATED) && ticket.createdMillis != seen.createdMillis) return false;\n',
        ''),), ('machine',)),
    'same-instance-absence-proves': (((RECONCILER, '            if (!later(listing, create)) continue;\n', ''),),
                                     ('machine',)),
    # The owner decisions' rules.
    'temporary-factory-moves-choice': (((RECONCILER, '        if (p.target == Target.TEMPORARY_FACTORY) {\n',
                                         '        if (p.target == null) {\n'),), ('machine', 'transactions')),
    'temporary-state-resets-choice': (((RECONCILER,
        '                status = Realization.TEMPORARY_FACTORY;\n                standIn = temporary.planId;\n',
        '                return s.chosen(ChoiceKind.FACTORY, NO_ID, Realization.CURRENT, view.boot, s.changedAt);\n'),),
        ('machine', 'transactions')),
    'automatic-restoration-unlisted': (((RECONCILER,
        '        if (p.healthResponse == HealthResponse.RESTORE_AUTOMATICALLY && failed(outcomes)) {\n',
        '        if (failed(outcomes)) {\n'),), ('machine', 'transactions')),
    'inconclusive-counted-unhealthy': (((RECONCILER,
        '            } else if (o.classification == Classification.HEALTH_CRASH) {\n',
        '            } else if (o.classification == Classification.HEALTH_CRASH\n'
        '                    || o.classification == Classification.HEALTH_INCONCLUSIVE) {\n'),),
        ('machine', 'transactions')),
    'notice-ignores-other-users': (((RECONCILER, '            if (running && !holder) others = true;\n', ''),),
                                   ('machine', 'transactions')),
    'emergency-notice-without-policy': (((RECONCILER,
        '        return policy && approved && !delivered ? p.emergencyNoticeMillis : p.noticeDelayMillis;\n',
        '        return approved && !delivered ? p.emergencyNoticeMillis : p.noticeDelayMillis;\n'),), ('machine',)),
    # The selection write, the owed move and the restoration rules.
    'selection-write-skipped': (((COORDINATOR,
        '            if (!store.putSelection(selection, step.selection)) throw new StoreRefused("selection not written");\n',
        ''),), ('transactions',)),
    'choice-move-not-recomputed': (((RECONCILER, '                return owing(c, window(c, b), b);\n',
                                     '                return window(c, b);\n'),
                                    (RECONCILER, '        Selection owed = move(c, c.ticket.cause);\n        b.window(',
                                     '        Selection owed = null;\n        b.window(')), ('machine',)),
    'own-move-voids-plan': (((RECONCILER,
        '            if (c.selection.revision != p.selectionRevision && !ownMove(c)) {\n',
        '            if (c.selection.revision != p.selectionRevision) {\n'),), ('machine',)),
    'boot-limit-skips-restoration': (((RECONCILER,
        '                if (p.healthResponse == HealthResponse.RESTORE_AUTOMATICALLY) {\n',
        '                if (p.healthResponse == null) {\n'),), ('machine', 'transactions')),
    'emergency-notice-any-repair': (((RECONCILER, '        boolean approved = approvedRestoration(c);\n',
                                      '        boolean approved = !p.repairs.equals(NO_ID);\n'),), ('machine',)),
    # Request counting, applied bytes, lost records and the commit check.
    'request-limit-counts-reboots': (((RECONCILER, _ACTIVATE_LIMIT,
        _ACTIVATE_GRANT + '        if (t.count(Crossing.REBOOT) >= p.requestLimit) '
        'return abandon(c, b, "reboot request limit");\n'),), ('machine',)),
    'applied-session-waits-on-other-bytes': (((RECONCILER, _APPLIED_OTHER, '                    return null;\n'),),
                                             ('machine',)),
    'record-lost-applies-before-commit': (((RECONCILER,
        '                if (committed(t)) return to(c, b, State.APPLIED_PROVISIONAL, "the bundle\'s bytes are active");\n',
        '                if (committed(t) || t.state != null) '
        'return to(c, b, State.APPLIED_PROVISIONAL, "the bundle\'s bytes are active");\n'),), ('machine',)),
    'diverged-without-commit-accepted': (((MACHINE, _COMMIT_CHECK, ''),), ('machine',)),
    # The second CREATE reuses the ticket's nonce and the machine accepts it in place, so the codec
    # and the step check pass it and only the replay checks can catch it.
    'create-replayed': (((RECORDS, 'SIGN(1, 2), PUBLISH(2, 2), CREATE(3, 1), WRITE(4, 1),',
                          'SIGN(1, 2), PUBLISH(2, 2), CREATE(3, 2), WRITE(4, 1),'),
                         (MACHINE, '            case WRITE: return state == State.SESSION_BOUND;\n',
                          '            case CREATE: return state == State.SESSION_INTENT;\n'
                          '            case WRITE: return state == State.SESSION_BOUND;\n'),
                         (RECONCILER, '        return unresolved(c, b, "create reply lost or incomplete");\n',
                          '        return issue(c, b, State.SESSION_INTENT, entry(c, Crossing.CREATE, create.grant, '
                          't.reference.nonce), "create again");\n')), ('machine', 'transactions')),
    'signing-skipped-after-create': (((RECONCILER, '        if (published(c)) return 0;\n',
        '        for (Ticket other : c.planTickets) {\n'
        '            if (!other.ticketId.equals(c.ticket.ticketId) && other.count(Crossing.CREATE) > 0) return 0;\n'
        '        }\n'),), ('machine',)),
    'repeats-any-earlier-fact': (((COORDINATOR,
        '        boolean precedence = o.kind == ObservationKind.SIGNER || o.kind == ObservationKind.BUNDLE;\n',
        '        boolean precedence = true;\n'),), ('transactions',)),
    'repair-link-cleared-on-change': (((RECONCILER, '        String repair = repairable ? s.repair : NO_ID;\n',
                                        '        String repair = status == s.realization ? s.repair : NO_ID;\n'),),
                                       ('machine',)),
    'repair-link-never-set': (((RECONCILER, '            repair = openPlan.planId;\n',
                                '            repair = s.repair;\n'),), ('machine',)),
    'temporary-factory-emergency-delay': (((RECORDS,
        '            if (emergencyNoticeMillis < noticeDelayMillis && target == Target.TEMPORARY_FACTORY) {\n',
        '            if (emergencyNoticeMillis < noticeDelayMillis && target == null) {\n'),), ('codec', 'machine')),
    # An independent review of D1: the latest fact by time, and the owed realization from the facts.
    'repeats-by-list-position': (((COORDINATOR, '            } else if (old.elapsed > latest) {\n',
                                   '            } else if (old.elapsed >= 0) {\n'),), ('transactions',)),
    'owed-move-writes-current': (((RECONCILER, '        return cohortCheck(next, p, null, c.view, null, null);\n',
                                   '        return next;\n'),), ('machine',)),
    'owed-temporary-on-other-bytes': (((RECONCILER,
        '            if (active != null && !active.digest.equals(bundleApk(c))) return null;\n', ''),), ('machine',)),
    'store-update-unchecked': (((STORE,
        '        if (!expected.ticketId.equals(next.ticketId) || TicketMachine.check(expected, next) != null) '
        'return false;\n',
        '        if (!expected.ticketId.equals(next.ticketId)) return false;\n'),), ('store',)),
    # D2's artifact store: visible only when complete, verified first, never alone, read back exactly.
    'artifact-partial-publication': (((ARTIFACT_STORE, '            for (Staged b : staged) place(b);\n',
                                       '            place(staged.get(0));\n'),
                                      (ARTIFACT_STORE, _PUBLICATION_WRITE,
                                       _PUBLICATION_WRITE + '            for (Staged b : staged.subList(1, staged.size())) '
                                       'place(b);\n')), ('artifacts',)),
    'artifact-published-before-verification': (((ARTIFACT_STORE, _VERIFY_EACH, ''),
                                                (ARTIFACT_STORE, _PUBLICATION_WRITE,
                                                 _PUBLICATION_WRITE + '            for (Staged b : staged) '
                                                 'if (verifier.verify(b) != null) return false;\n')), ('artifacts',)),
    'artifact-bundle-published-alone': (((ARTIFACT_STORE,
        '        if (publication.bundles.size() != inputs.size()) return false; // Never one bundle alone.\n',
        '        if (publication.bundles.size() > inputs.size()) return false;\n'),), ('artifacts',)),
    'artifact-unnamed-bundle-visible': (((ARTIFACT_STORE, '        if (!named) return Presence.ABSENT;\n', ''),),
                                        ('artifacts',)),
    'artifact-read-back-trusts-the-name': (((ARTIFACT_STORE,
        '            return exact ? Presence.PUBLISHED : Presence.MISMATCH;\n',
        '            return Presence.PUBLISHED;\n'),), ('artifacts',)),
    'artifact-lost-acknowledgement-republished': (((ARTIFACT_STORE, '        if (current.found != Node.ABSENT) {\n',
                                                    '        if (current.found == null) {\n'),
                                                   (ARTIFACT_STORE,
        '        if (node(parent) != Node.DIRECTORY || node(target) != Node.ABSENT) return false;\n',
        '        if (node(parent) != Node.DIRECTORY) return false;\n')), ('artifacts',)),
    'artifact-staging-read-as-record': (((ARTIFACT_STORE,
        '            if (name.startsWith(".") && name.endsWith(STAGING)) continue; // Never a record.\n', ''),),
        ('artifacts',)),
    'artifact-stage-unchecked': (((ARTIFACT_STORE,
        '        if (apk.length != manifest.apkBytes || idsig.length != manifest.idsigBytes\n'
        '                || !DeploymentRecords.sha256Hex(apk).equals(manifest.apk)\n'
        '                || !DeploymentRecords.sha256Hex(idsig).equals(manifest.idsig)) {\n',
        '        if (apk.length == 0 || idsig.length == 0) {\n'),), ('artifacts',)),
    'artifact-schemes-unchecked': (((ARTIFACT_RECORDS,
        '            if (schemes != SCHEMES) throw DeploymentRecords.invalid("schemes other than v2, v3 and v4");\n',
        ''),), ('artifacts',)),
    'artifact-roles-unordered': (((ARTIFACT_RECORDS,
        '            if (Role.of(in.u8()) != Publication.roleAt(i)) throw DeploymentRecords.invalid("roles out of order");\n',
        '            Role.of(in.u8());\n'),), ('artifacts',)),
    'artifact-trailing-bytes': (((ARTIFACT_RECORDS,
        '        V4Check v4 = V4Check.of(in.u8());\n        in.finish();\n', '        V4Check v4 = V4Check.of(in.u8());\n'),),
        ('artifacts',)),
    # The second publication: a proof of no effect tied to the attempt, a bound of two, a hold
    # with the alert, and completion from the bundles the store holds.
    'publish-again-without-proof': (((RECONCILER, _PUBLISH_READ,
        '        if (c.view.publication(last.reference, c.plan.planId) == Classification.BUNDLE_MISMATCH) '
        'return null;\n'),),
        ('machine', 'transactions')),
    'absence-not-tied-to-attempt': (((RECONCILER,
        '                if (o.kind == ObservationKind.BUNDLE && o.subject.equals(attempt) && o.plan.equals(plan)\n',
        '                if (o.kind == ObservationKind.BUNDLE && o.plan.equals(plan)\n'),), ('machine', 'transactions')),
    'publish-bound-one': (((RECORDS, 'SIGN(1, 2), PUBLISH(2, 2), CREATE(3, 1), WRITE(4, 1),',
                            'SIGN(1, 2), PUBLISH(2, 1), CREATE(3, 1), WRITE(4, 1),'),), ('codec', 'machine')),
    'second-publication-unheld': (((RECONCILER, _PUBLISH_HOLD, '        return null;\n'),), ('machine',)),
    'bundle-fact-without-attempt': (((RECORDS, '            checkId(subject, "subject", !subjectKind);\n',
        '            checkId(subject, "subject", !subjectKind || kind == ObservationKind.BUNDLE);\n'),), ('codec',)),
    'artifact-held-bundles-refused': (((ARTIFACT_STORE, _HELD_OR_STAGED,
        '                if (!exact(root.resolve(STAGING + "-" + b.id), b)) return false;\n'),), ('artifacts',)),
    'artifact-plan-inputs-unbound': (((ARTIFACT_STORE, _BOUND,
        '                    || !m.component.equals(plan.component)\n'
        '                    || m.versionCode != version || !m.transaction.equals(publication.transactions.get(i))) {\n'),),
        ('artifacts',)),
    'artifact-one-transaction': (((ARTIFACT_STORE, _BOUND,
        _BOUND.replace('publication.transactions.get(i)', 'publication.transactions.get(0)')),), ('artifacts',)),
    # Signed output leaves the plan: the bundle's APK digest is what its publication bound, read
    # from the plan's own facts, and a missing read is missing evidence.
    'mismatch-waits-silently': (((RECONCILER, _MISMATCH_HOLD, '        if (mismatch(c)) return null;\n'),),
                                ('machine',)),
    'apk-from-another-plan': (((RECONCILER,
        '                if (o.classification != Classification.BUNDLE_PUBLISHED || !o.plan.equals(plan)) continue;\n',
        '                if (o.classification != Classification.BUNDLE_PUBLISHED) continue;\n'),), ('machine',)),
    'disagreeing-reads-bind': (((RECONCILER,
        '                if (found != null && (!found.digest.equals(o.digest) || !found.bundleApk.equals(o.bundleApk)\n',
        '                if (found == o && (!found.digest.equals(o.digest) || !found.bundleApk.equals(o.bundleApk)\n'),),
        ('machine',)),
    'missing-publication-fact-is-other-bytes': (((RECONCILER,
        '        if (t.state.code >= State.PUBLISHED.code && t.state != State.SIGN_FAILED && bundleApk(c) == null) {\n',
        '        if (t.state.code >= State.PUBLISHED.code && t.state != State.SIGN_FAILED && t.state == null) {\n'),),
        ('machine',)),
    'cohort-without-chosen-publication': (((RECONCILER,
        '            if (chosenApk == null || (standing && temporaryApk == null)) return s;\n',
        '            if (standing && temporaryApk == null) return s;\n'),), ('machine',)),
    # The restoration plan's publication and the signer certificate.
    'artifact-certificate-unchecked': (((ARTIFACT_STORE,
        '            if (!b.id.equals(publication.bundles.get(i)) || !role || !m.certificate.equals(plan.signer)\n',
        '            if (!b.id.equals(publication.bundles.get(i)) || !role\n'),), ('artifacts',)),
    'artifact-restoration-repairs-unbound': (((ARTIFACT_STORE,
        '            if (planPublication(plan.repairs) != Presence.PUBLISHED || repaired == null\n'
        '                    || repaired.bundles.size() != 2 || !repaired.bundles.get(1).equals(staged.get(0).id)) {\n'
        '                return false;\n            }\n', ''),), ('artifacts',)),
    'artifact-restoration-role-unchecked': (((ARTIFACT_STORE,
        '            boolean role = m.role == (plan.signing == 0 ? Role.RESTORATION : Publication.roleAt(i));\n',
        '            boolean role = plan.signing == 0 || m.role == Publication.roleAt(i);\n'),), ('artifacts',)),
    'artifact-restoration-not-single': (((ARTIFACT_STORE,
        '        if (plan.signing == 0 && (plan.repairs.equals(DeploymentRecords.NO_ID) || plan.hasRestoration())) {\n',
        '        if (plan.signing == 0 && plan.repairs.equals(DeploymentRecords.NO_ID)) {\n'),), ('artifacts',)),
    'artifact-signing-plan-any-role': (((ARTIFACT_STORE,
        '            boolean role = m.role == (plan.signing == 0 ? Role.RESTORATION : Publication.roleAt(i));\n',
        '            boolean role = m.role == (plan.signing == 0 ? Role.RESTORATION : m.role);\n'),), ('artifacts',)),
    # A missing or disagreeing publication read holds with the alert, and never blocks an abandon.
    'missing-read-holds-silently': (((RECONCILER, '            b.set(FLAG_REQUEST_LIMIT);\n            if (b.cause()',
                                      '            if (b.cause()'),), ('machine',)),
    'missing-read-blocks-abandon': (((RECONCILER,
        '            if (b.cause() != Cause.NONE && !judgesBytes(t.state)) {\n',
        '            if (b.cause() == null) {\n'),), ('machine',)),
    # The host signer and the bundle builder: no partial output, verification before staging, both
    # bundles together, every signer with the platform role, and never a second signing.
    'signer-partial-output-kept': (((HOST_SIGNER, '            discard(open.transaction);\n', ''),), ('signing',)),
    'builder-published-before-verification': (((BUNDLE_BUILDER,
        '            if (s == null || verify(s.apk, s.idsig, m) != null) return false;\n',
        '            if (s == null) return false;\n'),), ('signing',)),
    'builder-bundle-published-alone': (((BUNDLE_BUILDER,
        '        List<Role> roles = new ArrayList<>(List.of(Role.VARIANT));\n'
        '        if (plan.hasRestoration()) roles.add(Role.RESTORATION);\n        Map<Role, Staged> chosen',
        '        List<Role> roles = new ArrayList<>(List.of(Role.VARIANT));\n        Map<Role, Staged> chosen'),),
        ('signing',)),
    'builder-wrong-role': (((BUNDLE_BUILDER,
        '            if (!s[0].equals(role.certificate) || !s[1].equals(role.key)) return "a signer without the platform '
        'role";\n', ''),), ('signing',)),
    'signer-resigns-after-lost-reply': (((HOST_SIGNER,
        '        if (existing != null || node(record(open.transaction)) != Node.ABSENT) {\n'
        '            return existing == null ? null : new Reply(existing); // Resolved by its ID, never signed again.\n'
        '        }\n', ''),
        (HOST_SIGNER, '            if (!writeNew(record(open.transaction), openBytes)) return null;\n',
         '            if (!put(record(open.transaction), openBytes)) return null;\n')), ('signing',)),
    'artifact-input-equal-output-refused': (((ARTIFACT_RECORDS,
        '            this.installation = installation;\n            this.component = component;\n'
        '            this.transaction = transaction;\n',
        '            if (input.equals(apk)) throw DeploymentRecords.invalid("the input is not signed output");\n'
        '            this.installation = installation;\n            this.component = component;\n'
        '            this.transaction = transaction;\n'),), ('artifacts',)),
}

REQUIRED_DEFECTS = {
    'a replay': ('replay-lost-sign-reply', 'replay-abandon-same-instance'),
    'an early outcome': ('early-applied-before-checkpoint', 'early-close-before-checkpoint'),
    'a second create or commit': ('second-create-bound', 'second-commit-replayed'),
    'a READY_AGAIN that waits under late commit': ('ready-again-waits-under-late-commit',),
    'a boot during COMMIT_INTENT': ('boot-during-commit-ignored',),
    "an Android deletion that resets the owner's choice": ('android-deletion-resets-choice',),
    'a stale base reported as healthy': ('stale-base-reported-healthy',),
    'an expired ACTIVATE used': ('expired-activate-used',),
    'a DIVERGED close with a live session': ('diverged-close-with-live-session',),
    'a partial publication': ('artifact-partial-publication', 'artifact-unnamed-bundle-visible',
                              'signer-partial-output-kept'),
    'publication before verification': ('artifact-published-before-verification',
                                        'builder-published-before-verification'),
    'a bundle published alone': ('artifact-bundle-published-alone', 'builder-bundle-published-alone'),
    'a signer without the platform role': ('builder-wrong-role',),
    'a second signing after a lost reply': ('signer-resigns-after-lost-reply',),
    'a lost acknowledgement not resolved by reading': ('artifact-lost-acknowledgement-republished',
                                                       'artifact-read-back-trusts-the-name'),
    'a second publication without a proof of no effect': ('publish-again-without-proof',
                                                          'absence-not-tied-to-attempt'),
    'a second publication that cannot finish from the held bundles': ('artifact-held-bundles-refused',),
    'a publication not bound to the plan\'s signing inputs': ('artifact-plan-inputs-unbound',),
    'a pair from two signing transactions refused': ('artifact-one-transaction',),
    'a silent wait on a publication that names other bytes': ('mismatch-waits-silently',),
    "an APK digest not bound by the plan's own publication": ('apk-from-another-plan', 'disagreeing-reads-bind',
                                                              'missing-publication-fact-is-other-bytes',
                                                              'cohort-without-chosen-publication'),
    'a restoration published alone by its restoration plan': ('artifact-restoration-repairs-unbound',
                                                              'artifact-restoration-not-single'),
    'a bundle signed as a variant in a RESTORATION role': ('artifact-restoration-role-unchecked',),
    'a ticket frozen by a missing publication read': ('missing-read-holds-silently', 'missing-read-blocks-abandon'),
    'a bundle of another signer published': ('artifact-certificate-unchecked',),
    'a signing plan publishing a bundle signed in another role': ('artifact-signing-plan-any-role',),
}


def replace_once(text_value, old, new):
    if text_value.count(old) != 1:
        raise ValueError('mutant anchor drift: ' + old[:80])
    return text_value.replace(old, new, 1)


def mutant_texts():
    """The source texts each mutant changes, with its edits applied. Each anchor occurs exactly
    once in the text it edits."""
    result = {}
    for name, (edits, suites) in MUTANTS.items():
        texts = {}
        for target, old, new in edits:
            texts[target] = replace_once(texts.get(target, (ROOT / target).read_text()), old, new)
        result[name] = (texts, suites)
    return result


# ---------------------------------------------------------------- pure source checks

def java_goldens(source):
    """The golden lengths and SHA-256 digests the Java codec test pins, by golden name."""
    lengths = dict(re.findall(r'private static final int GOLDEN_([A-Z0-9_]+)_BYTES = ([0-9]+);', source))
    digests = dict(re.findall(r'private static final String GOLDEN_([A-Z0-9_]+)_SHA256 = "([0-9a-f]{64})";', source))
    if set(lengths) != set(digests):
        raise ValueError('golden pins incomplete')
    return {name: (int(lengths[name]), digests[name]) for name in lengths}


def source_text(suite):
    return (ROOT / TEST_DIR / (SUITES[suite] + '.java')).read_text()


def oracle_problems():
    """The Java goldens against the independent encoder, and the README's layout facts."""
    problems = []
    pins = java_goldens(source_text('codec'))
    gold = goldens()
    if set(pins) != set(gold) or tuple(gold) != GOLDEN_NAMES:
        problems.append('golden names differ: %s' % sorted(set(pins) ^ set(gold)))
    for name, data in gold.items():
        if pins.get(name) != (len(data), sha(data)):
            problems.append('Java golden %s differs from the independent encoder' % name)
    readme = README.read_text()
    for fact in README_FACTS:
        if ' '.join(fact.split()) not in ' '.join(readme.split()):
            problems.append('the README no longer states: ' + fact[:60])
    if MAX_LEDGER != 60:
        problems.append('ledger bound %d' % MAX_LEDGER)
    artifact_pins = java_goldens(source_text('artifacts'))
    artifact_gold = artifact_goldens()
    if set(artifact_pins) != set(artifact_gold) or tuple(artifact_gold) != ARTIFACT_GOLDEN_NAMES:
        problems.append('artifact golden names differ: %s' % sorted(set(artifact_pins) ^ set(artifact_gold)))
    for name, data in artifact_gold.items():
        if artifact_pins.get(name) != (len(data), sha(data)):
            problems.append('Java golden %s differs from the independent encoder' % name)
    return problems


def name_problems():
    problems = []
    for suite, names in NAMES.items():
        if len(set(names)) != len(names):
            problems.append('duplicate case names in ' + suite)
        if any(': ' in name for name in names):
            problems.append('a case name of %s holds the failure separator' % suite)
        source = source_text(suite)
        patterns = GENERATED.get(suite, ())
        for name in names:
            generated = [fragments for pattern, fragments in patterns if re.fullmatch(pattern, name)]
            if generated:
                if any(source.count(fragment) != 1 for fragment in generated[0]):
                    problems.append('the template of %s is not in its source once' % name)
            elif source.count('"%s"' % name) != 1:
                problems.append('%s case not named once in its source: %s' % (suite, name))
    return problems


def placement_problems():
    """The package stays outside every Android build: its own directory, no build file names it,
    nothing of it sits where the system_server jar's glob reaches."""
    problems = []
    for name in MAIN:
        text = (ROOT / MAIN_DIR / (name + '.java')).read_text()
        if not text.startswith('// SPDX-License-Identifier: Apache-2.0\npackage %s;\n' % PACKAGE):
            problems.append(name + ' is not in its package')
    if list((ROOT / 'owner/platform/java/dev/andrix/server').glob('deployment*')):
        problems.append('deployment sources under owner/platform/java')
    for path in ROOT.rglob('*'):
        if path.name == 'Android.bp' or path.suffix == '.mk':
            if ROOT / 'upstream' in path.parents or ROOT / 'third_party' in path.parents:
                continue
            if 'deployment' in path.read_text(errors='replace'):
                problems.append('a build file names deployment: %s' % path.relative_to(ROOT))
    store = (ROOT / STORE).read_text()
    if ('    public DeploymentStore(Path root, String installation) {\n'
            '        this(root, installation, step -> { }, true);\n') not in store:
        problems.append('the public store constructor does not sync')
    for path in sorted((ROOT / MAIN_DIR).glob('*.java')):
        if path.name != 'DeploymentStore.java' and 'unsynced(' in path.read_text():
            problems.append('production text uses the unsynced store: ' + path.name)
    return problems


def prediction_problems(predictions):
    problems = []
    if 'PREDICTED' not in predictions['status']:
        problems.append('predictions are not marked as predictions')
    counts = predictions['cases']
    expected = {suite: len(names) for suite, names in NAMES.items()}
    expected.update(goldens=len(GOLDEN_NAMES), artifact_goldens=len(ARTIFACT_GOLDEN_NAMES), mutants=len(MUTANTS))
    if counts != expected:
        problems.append('predicted counts %s differ from the case lists %s' % (counts, expected))
    gold = {name: {'bytes': len(data), 'sha256': sha(data)} for name, data in goldens().items()}
    if predictions['goldens'] != gold:
        problems.append('predicted goldens differ from the independent encoder')
    artifact_gold = {name: {'bytes': len(data), 'sha256': sha(data)} for name, data in artifact_goldens().items()}
    if predictions['artifact_goldens'] != artifact_gold:
        problems.append('predicted artifact goldens differ from the independent encoder')
    caught = predictions['mutants_caught_at_least']
    if set(caught) != set(MUTANTS):
        problems.append('mutant predictions do not list every mutant')
    for name, checks in caught.items():
        suites = MUTANTS.get(name, ((), ()))[1]
        allowed = set()
        for suite in suites:
            allowed |= set(NAMES[suite])
        if not checks or not set(checks) <= allowed:
            problems.append('mutant prediction inconsistent: ' + name)
    for defect, names in REQUIRED_DEFECTS.items():
        if not names or any(name not in MUTANTS for name in names):
            problems.append('no mutant for ' + defect)
    return problems


def source_checks():
    problems = []
    try:
        problems += oracle_problems()
    except (OSError, ValueError) as error:
        problems.append('oracle: %s' % error)
    problems += name_problems()
    problems += placement_problems()
    try:
        mutant_texts()
    except ValueError as error:
        problems.append('mutant anchors: %s' % error)
    try:
        problems += prediction_problems(strict(PREDICTIONS.read_text()))
    except (OSError, ValueError, KeyError) as error:
        problems.append('predictions: %s' % error)
    return problems


# ---------------------------------------------------------------- the guarded run

def _limit(value):
    return None if value == 'max' else int(value)


def resource_guard(cgroup_root=Path('/sys/fs/cgroup'), membership=Path('/proc/self/cgroup')):
    """Require bounded memory, no swap, 2 CPUs, 256 tasks and disabled core dumps, from this
    process's cgroup or an ancestor. Nothing is created or changed. Returns None or a reason."""
    if resource.getrlimit(resource.RLIMIT_CORE) != (0, 0):
        return 'core dumps must be disabled with both limits zero'
    try:
        lines = membership.read_text().splitlines()
    except OSError as error:
        return 'cgroup membership unreadable: %s' % error
    unified = [line[3:] for line in lines if line.startswith('0::')]
    if len(unified) != 1 or not unified[0].startswith('/') or '..' in unified[0].split('/'):
        return 'no single unified cgroup membership'
    leaf = cgroup_root / unified[0].lstrip('/')
    chain = [leaf, *leaf.parents]
    if cgroup_root not in chain:
        return 'cgroup path outside the mounted hierarchy'
    chain = chain[:chain.index(cgroup_root) + 1]
    found = {'memory.max': [], 'memory.swap.max': [], 'pids.max': [], 'cpu.max': []}
    try:
        for directory in chain:
            for name, values in found.items():
                path = directory / name
                if not path.exists():
                    continue
                value = path.read_text().strip()
                if name == 'cpu.max':
                    quota, period = value.split()
                    if quota != 'max':
                        values.append(int(quota) / int(period))
                elif _limit(value) is not None:
                    values.append(_limit(value))
    except (OSError, ValueError) as error:
        return 'cgroup limits unreadable: %s' % error
    effective = {name: min(values) if values else None for name, values in found.items()}
    if (effective['memory.max'] is None or effective['memory.max'] > 2 * GIB
            or effective['memory.swap.max'] != 0
            or effective['cpu.max'] is None or effective['cpu.max'] > 2
            or effective['pids.max'] is None or effective['pids.max'] > 256):
        return 'required bounds absent: %s' % json.dumps(effective, sort_keys=True)
    return None


def tool_environment():
    """The environment of every compiler and JVM: this one, without CLASSPATH."""
    return {name: value for name, value in os.environ.items() if name != 'CLASSPATH'}


def sources(texts=None):
    """Every main and test source, as path to bytes, with mutant texts in place."""
    texts = texts or {}
    files = {}
    for name in MAIN:
        path = MAIN_DIR + name + '.java'
        files[path] = texts[path].encode() if path in texts else (ROOT / path).read_bytes()
    for name in SUPPORT + ('World', 'Bed') + tuple(SUITES.values()):
        path = TEST_DIR + name + '.java'
        files[path] = (ROOT / path).read_bytes()
    return files


def build(work, files):
    source = work / 'src'
    for relative, data in files.items():
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    classes = work / 'classes'
    classes.mkdir(parents=True)
    result = subprocess.run(['javac', '-J' + JAVAC_HEAP, *('-J' + option for option in JVM_LIMITS), '--release', '17',
                             '-Xlint:all', '-Werror', '-implicit:none',
                             '-proc:none', '-d', str(classes), *sorted(str(source / name) for name in files)],
                            capture_output=True, text=True, timeout=600, cwd=work, env=tool_environment())
    return {'returncode': result.returncode, 'output': (result.stdout + result.stderr)[-20000:],
            'inputs': {name: sha(data) for name, data in sorted(files.items())}}


def passed_checks(stdout):
    return re.findall(r'^PASS (.+)$', stdout, re.M)


def failed_checks(stdout):
    return sorted(set(re.findall(r'^FAIL (.+?): ', stdout, re.M)))


def execute(work, main, args, assertions=True, timeout=1800):
    state = work / 'jvm-tmp'
    state.mkdir(exist_ok=True)
    result = subprocess.run(['java', JAVA_HEAP, *JVM_LIMITS, *(['-ea'] if assertions else []),
                             '-Djava.io.tmpdir=' + str(state),
                             '-cp', str(work / 'classes'), PACKAGE + '.' + main, *args],
                            capture_output=True, text=True, timeout=timeout, cwd=work, env=tool_environment())
    return {'returncode': result.returncode, 'stdout': result.stdout[-200000:], 'stderr': result.stderr[-20000:],
            'passed': passed_checks(result.stdout), 'failed': failed_checks(result.stdout)}


def outcome(run, names):
    """Passed and failed names of a finished suite, and whether it is complete."""
    actual = run['passed'] + run['failed']
    return {'passed': run['passed'], 'failed': run['failed'], 'returncode': run['returncode'],
            'unknown': sorted(set(actual) - set(names)),
            'complete': len(actual) == len(names) and set(actual) == set(names)}


def red_names(result, names):
    """The failed names of a complete result, or None when it is not one."""
    if not result['complete'] or result['returncode'] != (1 if result['failed'] else 0):
        return None
    return set(result['failed'])


def run_suite(work, suite):
    """One suite in a built work directory: its arguments are fresh directories."""
    args = []
    if suite != 'machine':
        directory = work / (suite + '-out')
        directory.mkdir()
        args = [str(directory)]
    run = execute(work, SUITES[suite], args)
    return outcome(run, NAMES[suite]), run


def golden_problems(directory, expected=None):
    """Each golden the codec or artifact suite wrote against the independent encoder, byte for byte."""
    expected = goldens() if expected is None else expected
    written = sorted(path.name for path in directory.iterdir()) if directory.is_dir() else []
    problems = []
    if written != sorted(name + '.bin' for name in expected):
        problems.append('written goldens %s' % written)
    for name, data in expected.items():
        path = directory / (name + '.bin')
        if not path.is_file() or path.read_bytes() != data:
            problems.append('golden %s differs from the independent encoder' % name)
    return problems


def qualify(work, report):
    """Every guarded JVM step, in PHASES order, recorded into the report as it finishes. The caller
    has passed every guard."""
    steps, problems = report['steps'], report['problems']
    report['java'] = subprocess.run(['java', '-version'], capture_output=True, text=True,
                                    timeout=60).stderr.strip()
    base = work / 'base'
    base.mkdir(parents=True)
    built = build(base, sources())
    steps['build'] = built
    if built['returncode']:
        problems.append('build')
        return
    report['completed_phases'].append('build')
    for suite in ('codec', 'machine', 'store', 'transactions', 'artifacts', 'signing'):
        result, run = run_suite(base, suite)
        steps[suite] = result
        if red_names(result, NAMES[suite]) != set() or 'unqualified' not in run['stdout']:
            problems.append('%s suite' % suite)
        if suite == 'artifacts' and not problems:
            problems += golden_problems(base / 'artifacts-out' / 'goldens', artifact_goldens())
        if suite == 'codec' and not problems:
            problems += golden_problems(base / 'codec-out')
            refused = execute(base, SUITES['codec'], [str(base / 'no-assertions')], assertions=False, timeout=120)
            if not refused['returncode'] or 'run with -ea' not in refused['stderr']:
                problems.append('codec suite ran without assertions')
        report['completed_phases'].append(suite)
    steps['mutants'] = {}
    mutant_runs(work, steps['mutants'], problems)
    report['completed_phases'].append('mutants')


def mutant_runs(work, records, problems, names=None):
    """Builds each deliberate defect and runs the suites predicted to catch it. Each must fail at
    least its predicted cases. `names` limits the defects, for partial runs that never qualify."""
    expectations = strict(PREDICTIONS.read_text())['mutants_caught_at_least']
    for name, (texts, suites) in mutant_texts().items():
        if names is not None and name not in names:
            continue
        record = {}
        records[name] = record
        directory = work / 'mutants' / name
        directory.mkdir(parents=True)
        built = build(directory, sources(texts))
        if built['returncode']:
            record['build'] = built
            problems.append('mutant %s did not compile; not a red result' % name)
            continue
        failed = set()
        for suite in suites:
            result, _ = run_suite(directory, suite)
            record[suite] = {key: result[key] for key in ('failed', 'returncode', 'complete', 'unknown')}
            red = red_names(result, NAMES[suite])
            if red is None:
                problems.append('mutant %s %s run is not a complete result' % (name, suite))
                continue
            failed |= red
        record['missed'] = sorted(set(expectations[name]) - failed)
        record['caught'] = sorted(failed)
        if record['missed'] or not failed:
            problems.append('mutant %s not caught: %s' % (name, record['missed']))
        # The record keeps the result. Deleting the build frees its page cache inside the guard.
        shutil.rmtree(directory)


def sealed_run(work, args):
    """The optional comparison with the frozen SystemUI outputs: the pinned apksigner jar, the public
    development platform key, and the SystemUI platform role from an independently committed role
    manifest. Returns a result, or the reason it did not run."""
    given = (args.apksig_jar, args.sealed, args.platform_keys, args.role_manifest, args.role_manifest_sha256)
    if not all(given):
        return {'status': 'NOT_RUN', 'reason': 'no sealed inputs given'}
    jar = args.apksig_jar.resolve()
    if sha(jar.read_bytes()) != PINNED_APKSIGNER_JAR:
        return {'status': 'FAIL', 'reason': 'not the pinned apksigner jar'}
    sys.path.insert(0, str(ROOT / 'scripts/proof'))
    import signing_recovery  # noqa: E402 - the trusted role manifest's own validation
    manifest = strict(args.role_manifest.read_text())
    certificate, key = signing_recovery.apk_role(manifest, signing_recovery.SYSTEMUI_COMPONENT,
                                                 args.role_manifest_sha256)
    base = work / 'base' / 'classes'
    classes = work / 'sealed' / 'classes'
    classes.mkdir(parents=True)
    compiled = subprocess.run(['javac', '-J' + JAVAC_HEAP, *('-J' + option for option in JVM_LIMITS), '--release',
                               '17', '-Xlint:all', '-Werror', '-implicit:none', '-proc:none',
                               '-cp', '%s:%s' % (base, jar), '-d', str(classes),
                               *(str(ROOT / name) for name in APKSIG_SOURCES)],
                              capture_output=True, text=True, timeout=600, env=tool_environment())
    if compiled.returncode:
        return {'status': 'FAIL', 'reason': 'build', 'output': (compiled.stdout + compiled.stderr)[-4000:]}
    service = classes / 'META-INF/services' / Path(APKSIG_SERVICE).name
    service.parent.mkdir(parents=True)
    service.write_bytes((ROOT / APKSIG_SERVICE).read_bytes())
    out = work / 'sealed' / 'out'
    out.mkdir()
    # The reference without v1: the pinned jar's own command line with the development key.
    reference = work / 'sealed' / 'reference'
    reference.mkdir()
    digests = {}
    for name in ('A', 'R'):
        signed = subprocess.run(['java', SEALED_HEAP, *JVM_LIMITS, '-jar', str(jar), 'sign',
                                 '--key', str(args.platform_keys.resolve() / 'platform.pk8'),
                                 '--cert', str(args.platform_keys.resolve() / 'platform.x509.pem'),
                                 '--v1-signing-enabled', 'false', '--v4-signing-enabled', 'true',
                                 '--min-sdk-version', '37', '--out', str(reference / (name + '.apk')),
                                 str(args.sealed.resolve() / 'artifacts' / ('built-%s.apk' % name))],
                                capture_output=True, text=True, timeout=600, env=tool_environment())
        if signed.returncode:
            return {'status': 'FAIL', 'reason': 'reference ' + name, 'output': signed.stderr[-4000:]}
        for member in (name + '.apk', name + '.apk.idsig'):
            digests[member] = sha((reference / member).read_bytes())
    state = work / 'sealed' / 'jvm-tmp'
    state.mkdir()
    result = subprocess.run(['java', SEALED_HEAP, *JVM_LIMITS, '-ea', '-Djava.io.tmpdir=' + str(state),
                             '-cp', '%s:%s:%s' % (classes, base, jar), PACKAGE + '.SealedOutputsTest',
                             str(args.sealed.resolve()), str(args.platform_keys.resolve()), certificate, key, str(out),
                             str(reference)],
                            capture_output=True, text=True, timeout=1800, env=tool_environment())
    run = {'returncode': result.returncode, 'stdout': result.stdout[-20000:], 'stderr': result.stderr[-4000:],
           'passed': passed_checks(result.stdout), 'failed': failed_checks(result.stdout)}
    outcome_ = outcome(run, SEALED_NAMES)
    outcome_['status'] = 'PASS' if red_names(outcome_, SEALED_NAMES) == set() else 'FAIL'
    outcome_['role'] = {'certificate': certificate, 'key': key}
    outcome_['reference_without_v1'] = digests
    return outcome_


def fresh_outside(path, what):
    resolved = path.resolve()
    if resolved.exists() or ROOT in resolved.parents or resolved == ROOT:
        raise ValueError('fresh %s outside the repository required' % what)
    return resolved


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, help='fresh JSON path outside the repository')
    parser.add_argument('--work', type=Path, help='fresh scratch directory outside the repository')
    parser.add_argument('--source-checks-only', action='store_true')
    parser.add_argument('--apksig-jar', type=Path, help='the pinned apksigner jar, for the sealed comparison')
    parser.add_argument('--sealed', type=Path, help='the sealed SystemUI build directory holding artifacts/')
    parser.add_argument('--platform-keys', type=Path, help='the directory with the public development platform key')
    parser.add_argument('--role-manifest', type=Path, help='the trusted role manifest, JSON')
    parser.add_argument('--role-manifest-sha256', help="the role manifest's independent commitment")
    args = parser.parse_args(argv)
    report = {'runtime_qualified': False, 'android_qualified': False, 'activation': False}
    problems = source_checks()
    report['source_checks'] = problems or 'PASS'
    if args.source_checks_only:
        report['status'] = 'FAIL' if problems else 'SOURCE_ONLY'
        report['problems'] = problems
        print(json.dumps(report, indent=2))
        return 1 if problems else 0
    if not (args.evidence and args.work):
        parser.error('--evidence and --work are required for a guarded run')
    evidence = fresh_outside(args.evidence, 'evidence path')
    work = fresh_outside(args.work, 'work directory')
    # Pure refusals, in order. Nothing below is created or started until each one passes.
    reason = resource_guard()
    if not reason and not (shutil.which('javac') and shutil.which('java')):
        reason = 'no JDK on PATH'
    if reason:
        report.update(status='NOT_RUN', reason=reason)
        print(json.dumps(report, indent=2))
        return 2
    work.mkdir(parents=True)
    (work / 'tmp').mkdir()
    tempfile.tempdir = str(work / 'tmp')
    report.update(problems=problems, steps={}, completed_phases=[])
    try:
        qualify(work, report)
        if not problems:
            report['sealed'] = sealed_run(work, args)
            if report['sealed']['status'] == 'FAIL':
                problems.append('sealed comparison')
        report['status'] = 'FAIL' if problems else 'PASS'
    except Exception as error:  # noqa: BLE001 - recorded, never swallowed
        report['exception'] = '%s: %s' % (type(error).__name__, error)
        problems.append('qualification did not complete')
        report['status'] = 'NOT_COMPLETE'
    report['not_completed_phases'] = [phase for phase in PHASES if phase not in report['completed_phases']]
    if report['not_completed_phases'] and report['status'] != 'NOT_COMPLETE':
        problems.append('phases did not complete: %s' % report['not_completed_phases'])
        report['status'] = 'NOT_COMPLETE'
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'status': report['status'], 'problems': problems}, indent=2))
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
