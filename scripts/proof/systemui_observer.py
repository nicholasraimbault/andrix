# SPDX-License-Identifier: Apache-2.0
"""The read only shell observer of step D3: exact shell readbacks to Observation records.

The observer reads Android's state through the lab shell route and encodes what it read as
version 1 Observation records, with the runner's independent encoder. It never writes to the
device: every command it can run is one of the fixed read only forms in ALLOWED, and anything else
is refused before it reaches the shell. Each readback is bracketed by two reads of the kernel boot
ID, and each framework readback also by two reads of the framework instance. A readback that
changed boot or instance, or whose output matches no known form, gives no observation at all, so
the ticket waits. Host evidence only: the forms are qualified by guest captures, not by this file.

The framework instance has one scale on the shell route: system_server's start time, in clock
ticks since the kernel boot, from field 22 of /proc/<pid>/stat. Each framework start in a boot has
a larger value, so the reconciler's comparison of an observation's instance with a ledger entry's
holds when the coordinator's Clock reads the instance through `clock()` on the same scale. The
records need no change for this, because they define the instance only as a number that is 0 or
more, or -1 when no framework runs.
"""
from dataclasses import dataclass
import hashlib
import re
import secrets
import time

from scripts.proof import component_transaction_records as encoder
from scripts.proof import systemui_sessions as readback

PACKAGE = readback.PACKAGE
BOOT_ID = 'cat /proc/sys/kernel/random/boot_id'
UPTIME = 'cat /proc/uptime'
FRAMEWORK_PID = 'pidof system_server'
SYSTEMUI_PID = 'pidof com.android.systemui'
LISTING = 'pm list staged-sessions'
INSTALLS = 'dumpsys -t 25 package installs'
FINGERPRINT = 'getprop ro.build.fingerprint'
BOOT_COMPLETED = 'getprop sys.boot_completed'
SUPPORTS_CHECKPOINT = 'vdc checkpoint supportsCheckpoint'
NEEDS_CHECKPOINT = 'vdc checkpoint needsCheckpoint'
ACTIVE_PATH = 'pm path --user 0 ' + PACKAGE
ACTIVE_VERSION = 'pm list packages --user 0 --show-versioncode -U ' + PACKAGE
FACTORY_VERSION = 'pm list packages --user 0 --factory-only --show-versioncode ' + PACKAGE
FACTORY_DIGEST = 'sha256sum ' + readback.FACTORY_PATH
USERS = 'dumpsys user'

# The plan's health criteria that this probe reads, as the records number them. The UI marker (2)
# and keyguard unlock with CE authority (3) need the user in the foreground, which is a lab action
# of D5's vehicle. Native work (5) and the recovery route (6) have no reader here.
UID_AND_CONTEXT, NO_CRASH, ACTIVE_BYTES = 1 << 0, 1 << 1, 1 << 4
# Android's per user UID range: an app's UID is its user times this, plus its app ID.
PER_USER_RANGE = 100000
# How a listed user's state maps to the records' USER classifications. A user Android is removing
# is REMOVED whatever its state.
USER_CLASSES = {'RUNNING_UNLOCKED': 'RUNNING_UNLOCKED', 'RUNNING_LOCKED': 'RUNNING_LOCKED',
                'RUNNING_UNLOCKING': 'RUNNING_LOCKED', 'BOOTING': 'RUNNING_LOCKED', 'STOPPING': 'NOT_RUNNING',
                'SHUTDOWN': 'NOT_RUNNING', '-1': 'NOT_RUNNING'}

# Every command the observer may run. Each is a read: no install, session, setting, property or
# file changes, and no shell syntax. Parameters are filled only from the typed patterns below.
ALLOWED = (
    BOOT_ID, UPTIME, FRAMEWORK_PID, SYSTEMUI_PID, LISTING, INSTALLS, FINGERPRINT, BOOT_COMPLETED,
    SUPPORTS_CHECKPOINT, NEEDS_CHECKPOINT, ACTIVE_PATH, ACTIVE_VERSION, FACTORY_VERSION, FACTORY_DIGEST, USERS,
)
ALLOWED_PATTERNS = (
    re.compile(r'cat /proc/[1-9][0-9]{0,6}/stat'),
    re.compile(r'cat /proc/[1-9][0-9]{0,6}/attr/current'),
    re.compile(r'cat /proc/[1-9][0-9]{0,6}/status'),
    re.compile(r"sha256sum '" + readback.DATA_PATH.pattern + r"'"),
)


class Unclassified(Exception):
    """Output of no known form, a refused command or a readback that crossed a boot or instance."""


def allowed(command):
    return command in ALLOWED or any(p.fullmatch(command) for p in ALLOWED_PATTERNS)


@dataclass(frozen=True)
class Capture:
    command: str
    code: int
    stdout: str
    stderr: str


def raw_digest(captures):
    """SHA-256 of every capture a fact rests on: command, status, output and error, in order."""
    digest = hashlib.sha256()
    for c in captures:
        for part in (c.command, str(c.code), c.stdout, c.stderr):
            data = part.encode('utf-8', 'surrogateescape')
            digest.update(len(data).to_bytes(8, 'little') + data)
    return digest.hexdigest()


def boot_hex(uuid):
    return uuid.replace('-', '')


def quiet_failure(capture):
    """Exit status 1 with no output and no error: how pidof says that nothing matched. A failure
    that prints an error, such as a refused /proc or a lost connection, is an unavailable read."""
    return (capture.code, capture.stdout, capture.stderr) == (1, '', '')


class ShellObserver:
    """Reads one component's facts through `run(command) -> (status, stdout, stderr)`."""

    def __init__(self, run, installation, component=PACKAGE, new_id=None, wall=None):
        if component != PACKAGE:
            raise ValueError('Only SystemUI has known forms')
        self._run = run
        self.installation, self.component = installation, component
        self._new_id = new_id or (lambda: secrets.token_hex(16))
        # The host's wall clock is informational in the record and decides nothing.
        self._wall = wall or (lambda: time.time_ns() // 1_000_000)

    def read(self, command):
        if not allowed(command):
            raise Unclassified('Command outside the read only allowlist')
        code, stdout, stderr = self._run(command)
        return Capture(command, code, stdout, stderr)

    # ------------------------------------------------ bracketing

    def _boot(self, captures):
        capture = self.read(BOOT_ID)
        captures.append(capture)
        return readback.boot_id(capture.code, capture.stdout)

    def _instance(self, captures, absent=False):
        capture = self.read(FRAMEWORK_PID)
        captures.append(capture)
        if absent and (capture.code, capture.stdout) == (1, ''):
            return None, -1
        pid = readback.single_pid(capture.code, capture.stdout)
        capture = self.read('cat /proc/%d/stat' % pid)
        captures.append(capture)
        return pid, readback.start_ticks(capture.code, capture.stdout, pid, 'system_server')

    def _bracket(self, reader, framework=False):
        """Run a reader between two boot ID reads, and two instance reads for framework facts."""
        captures = []
        try:
            boot = self._boot(captures)
            capture = self.read(UPTIME)
            captures.append(capture)
            elapsed = readback.uptime_ms(capture.code, capture.stdout)
            instance = self._instance(captures) if framework else None
            facts = reader(captures)
            if framework and self._instance(captures) != instance:
                raise Unclassified('The framework restarted during the readback')
            if self._boot(captures) != boot:
                raise Unclassified('The device rebooted during the readback')
        except ValueError as error:
            raise Unclassified(str(error)) from error
        # A framework instance is system_server's start time in clock ticks since the boot.
        return boot, instance[1] if framework else -1, elapsed, raw_digest(captures), facts

    def _fact(self, boot, instance, elapsed, raw, kind, classification, component=None, facts=None,
              user=encoder.NO_USER, serial=encoder.NO_SERIAL):
        return {'installation': self.installation, 'observation': self._new_id(),
                'component': self.component if component is None else component, 'boot': boot_hex(boot),
                'user': user, 'serial': serial, 'kind': kind, 'route': 'SHELL',
                'instance': instance, 'elapsed': elapsed, 'wall': self._wall(), 'raw': raw,
                'classification': classification, 'facts': facts or {}}

    def _capture(self, captures, command):
        capture = self.read(command)
        captures.append(capture)
        return capture

    def clock(self):
        """The coordinator's Clock on the observations' scale: (boot, instance, elapsed, wall).

        The boot is the boot ID as 32 hexadecimal digits, the instance system_server's start time
        in clock ticks since the boot, or -1 when no system_server runs, the elapsed time the
        milliseconds since the boot, and the wall time the host's. The same brackets apply."""
        captures = []
        try:
            boot = self._boot(captures)
            capture = self._capture(captures, UPTIME)
            elapsed = readback.uptime_ms(capture.code, capture.stdout)
            instance = self._instance(captures, absent=True)
            if self._instance(captures, absent=True) != instance or self._boot(captures) != boot:
                raise Unclassified('The framework or the device restarted during the read')
        except ValueError as error:
            raise Unclassified(str(error)) from error
        return boot_hex(boot), instance[1], elapsed, self._wall()

    # ------------------------------------------------ device facts

    def boot(self):
        def reader(captures):
            fingerprint = self._capture(captures, FINGERPRINT)
            completed = self._capture(captures, BOOT_COMPLETED)
            return (readback.build_fingerprint(fingerprint.code, fingerprint.stdout),
                    readback.boot_completed(completed.code, completed.stdout))
        boot, instance, elapsed, raw, (fingerprint, completed) = self._bracket(reader)
        return self._fact(boot, instance, elapsed, raw, 'BOOT', 'COMPLETED' if completed else 'BOOTING', '',
                          {'fingerprint': fingerprint})

    def checkpoint(self):
        """PENDING while vold checkpoints this boot. COMMITTED only on a device that supports
        checkpoints and has none pending, which covers a boot whose checkpoint committed."""
        def reader(captures):
            supports = self._capture(captures, SUPPORTS_CHECKPOINT)
            needs = self._capture(captures, NEEDS_CHECKPOINT)
            if not readback.checkpoint_support(supports.code, supports.stdout, supports.stderr):
                raise ValueError('No checkpoint support: no known form of commit')
            return readback.checkpoint_state(needs.code, needs.stdout, needs.stderr)
        boot, instance, elapsed, raw, state = self._bracket(reader)
        return self._fact(boot, instance, elapsed, raw, 'CHECKPOINT',
                          'PENDING' if state == 'pending' else 'COMMITTED', '')

    # ------------------------------------------------ component facts

    def factory(self):
        def reader(captures):
            digest = self._capture(captures, FACTORY_DIGEST)
            version = self._capture(captures, FACTORY_VERSION)
            return (readback.file_digest(digest.code, digest.stdout, readback.FACTORY_PATH),
                    readback.factory_version(version.code, version.stdout))
        boot, instance, elapsed, raw, (digest, version) = self._bracket(reader)
        return self._fact(boot, instance, elapsed, raw, 'FACTORY', 'PRESENT', facts={'apk': digest, 'version': version})

    def active(self):
        def reader(captures):
            path = self._capture(captures, ACTIVE_PATH)
            kind, location = readback.package_path(path.code, path.stdout)
            command = FACTORY_DIGEST if kind == 'factory' else "sha256sum '%s'" % location
            digest = self._capture(captures, command)
            apk = readback.file_digest(digest.code, digest.stdout, location)
            listed = self._capture(captures, ACTIVE_VERSION)
            version, uid = readback.package_version_uid(listed.code, listed.stdout)
            # SystemUI runs once for each running user. The fact carries the system user's process.
            processes = self._processes(captures)
            if 0 not in processes or processes[0][1] != uid:
                raise ValueError("No SystemUI process with the package's UID for the system user")
            label = processes[0][2]
            again = self._capture(captures, ACTIVE_PATH)
            if readback.package_path(again.code, again.stdout) != (kind, location):
                raise ValueError('The active package changed during the readback')
            return kind, apk, version, uid, label
        boot, instance, elapsed, raw, (kind, apk, version, uid, label) = self._bracket(reader)
        return self._fact(boot, instance, elapsed, raw, 'ACTIVE', 'FACTORY_COPY' if kind == 'factory' else 'DATA_COPY',
                          facts={'apk': apk, 'version': version, 'uid': uid, 'context': label})

    def _processes(self, captures, absent=False):
        """Each SystemUI process by its user: {user: (pid, uid, context)}. The user is the UID
        divided by the per user range. Two processes for one user have no known form. With
        `absent`, pidof's quiet failure, exit status 1 with no output and no error, reads as no
        process at all, but only when a second read in the same bracket gives exactly the same.
        Any other failure is an unavailable read, never an observation of no process."""
        listed = self._capture(captures, SYSTEMUI_PID)
        found = {}
        if absent and quiet_failure(listed):
            again = self._capture(captures, SYSTEMUI_PID)
            if not quiet_failure(again):
                raise ValueError('The SystemUI process read did not repeat')
            return found
        for pid in readback.pids(listed.code, listed.stdout):
            status = self._capture(captures, 'cat /proc/%d/status' % pid)
            uid = readback.status_uid(status.code, status.stdout, pid)
            context = self._capture(captures, 'cat /proc/%d/attr/current' % pid)
            label = readback.process_context(context.code, context.stdout)
            user = uid // PER_USER_RANGE
            if user in found:
                raise ValueError('Two SystemUI processes for one user')
            found[user] = (pid, uid, label)
        return found

    # ------------------------------------------------ users and health

    def users(self, previous=()):
        """One USER fact for each user the listing shows, bound by serial, and REMOVED for each
        (user, serial) in `previous` that it no longer shows. The listing comes from one framework
        instance. A listing cut short or of no known form gives no fact at all, because the notice
        rule is only as complete as this listing."""
        def reader(captures):
            listed = self._capture(captures, USERS)
            return readback.users(listed.code, listed.stdout)
        boot, instance, elapsed, raw, listed = self._bracket(reader, framework=True)
        facts, shown = [], set()
        for u in listed:
            shown.add((u.user, u.serial))
            classification = 'REMOVED' if u.removing else USER_CLASSES[u.state]
            facts.append(self._fact(boot, instance, elapsed, raw, 'USER', classification, '', user=u.user,
                                    serial=u.serial))
        for user, serial in previous:
            if (user, serial) not in shown:
                facts.append(self._fact(boot, instance, elapsed, raw, 'USER', 'REMOVED', '', user=user,
                                        serial=serial))
        return facts

    def health(self, domain, apk, baseline=None):
        """One HEALTH fact for each user the listing shows running and unlocked. It covers SystemUI's
        UID and context for that user, which holds when exactly that user's process runs with the
        package's app ID and the expected SELinux domain, and the active bytes, which hold when the
        active APK's digest is `apk`. With a baseline from an earlier probe of the same boot, it also
        covers no crash or ANR: the user's process is still the one the baseline names. Only the
        system user's SystemUI is persistent, so only its process ending is a crash, or an ANR that
        ended it, and gives CRASH. Another user's SystemUI may be ended to free memory, so its
        process ending or missing gives INCONCLUSIVE. Another miss gives DEGRADED. A probe that
        would hold without a baseline gives no fact, because a HELD fact that leaves out the crash
        criterion would read as partial criteria for the whole window. Returns the facts and the
        baseline for the next probe, {(boot, instance, user, serial): pid}. A baseline counts only
        in its own boot and framework instance: a reboot or a framework restart ends every app,
        which is not SystemUI's crash, so the next probe starts a new baseline."""
        def reader(captures):
            listed = self._capture(captures, USERS)
            people = readback.users(listed.code, listed.stdout)
            path = self._capture(captures, ACTIVE_PATH)
            kind, location = readback.package_path(path.code, path.stdout)
            digest = self._capture(captures, FACTORY_DIGEST if kind == 'factory' else "sha256sum '%s'" % location)
            active = readback.file_digest(digest.code, digest.stdout, location)
            versions = self._capture(captures, ACTIVE_VERSION)
            _, uid = readback.package_version_uid(versions.code, versions.stdout)
            return people, active, uid, self._processes(captures, absent=True)
        boot, instance, elapsed, raw, (people, active, uid, processes) = self._bracket(reader, framework=True)
        app = uid % PER_USER_RANGE
        facts, following = [], {}
        for u in people:
            if u.removing or u.state != 'RUNNING_UNLOCKED':
                continue
            process = processes.get(u.user)
            key = (boot_hex(boot), instance, u.user, u.serial)
            if process is not None:
                following[key] = process[0]
            earlier = None if baseline is None else baseline.get(key)
            covered = UID_AND_CONTEXT | ACTIVE_BYTES | (NO_CRASH if earlier is not None else 0)
            identity = (process is not None and process[1] == u.user * PER_USER_RANGE + app
                        and process[2].split(':')[2] == domain)
            ended = process is None or (earlier is not None and process[0] != earlier)
            if ended and u.user != 0:
                # ProcessList marks an app's process persistent only for the system user.
                classification = 'INCONCLUSIVE'
            elif ended and earlier is not None:
                classification = 'CRASH'
            elif identity and active == apk:
                if earlier is None:
                    continue
                classification = 'HELD'
            else:
                classification = 'DEGRADED'
            facts.append(self._fact(boot, instance, elapsed, raw, 'HEALTH', classification, user=u.user,
                                    serial=u.serial, facts={'count': covered}))
        return facts, following

    # ------------------------------------------------ framework facts

    def sessions(self):
        """The complete staged listing and the install dump of one framework instance, joined by
        session ID: one LISTING fact, then one SESSION fact for each of the package's staged
        sessions. Any disagreement between the two readbacks gives no fact at all."""
        def reader(captures):
            listing = self._capture(captures, LISTING)
            dump = self._capture(captures, INSTALLS)
            return (readback.staged_listing(listing.code, listing.stdout, False),
                    readback.installs_dump(dump.code, dump.stdout))
        boot, instance, elapsed, raw, (listing, dump) = self._bracket(reader, framework=True)
        try:
            joined = join(listing, dump, self.component)
        except ValueError as error:
            raise Unclassified(str(error)) from error
        listed = len(listing.for_package(self.component))
        facts = [self._fact(boot, instance, elapsed, raw, 'LISTING',
                            'SESSIONS_FOR_PACKAGE' if listed else 'NONE_FOR_PACKAGE', facts={'count': listed})]
        for classification, reference in joined:
            facts.append(self._fact(boot, instance, elapsed, raw, 'SESSION', classification,
                                    facts={'reference': reference}))
        return facts


# Reference presence bits, as the records define them.
SESSION, CREATED, STAGE_DIR, INSTALLER, NONCE = 1, 2, 4, 8, 16
ABANDONED_MESSAGE = 'Session was abandoned'
INSTALL_FAILED_ABORTED = -115


def reference(session):
    """The native reference a dumped session shows, with the ticket nonce its referrer carries."""
    presence = SESSION | CREATED
    installer = session.installer_uid if session.installer_uid >= 0 else 0
    if session.installer_uid >= 0:
        presence |= INSTALLER
    stage = session.stage_dir or ''
    if stage:
        presence |= STAGE_DIR
    nonce = readback.referrer_nonce(session.referrer)
    if nonce is not None:
        presence |= NONCE
    return (presence, session.identity, session.created_millis, stage, installer,
            nonce if nonce is not None else encoder.ZERO_ID)


def classify(session):
    """The session state that a dumped staged session shows.

    A removed session is abandoned, refused before its commit, or a terminal staged session that
    Android expired, which keeps its applied or failed flag. Any other removed session has no
    known outcome and refuses the readback, because it could be the ticket's."""
    if session.section == 'Historical':
        if session.final_status == INSTALL_FAILED_ABORTED and session.final_message == ABANDONED_MESSAGE:
            return 'ABANDONED'
        if not session.committed and session.final_status < 0:
            return 'REFUSED'
        if session.committed and session.applied:
            return 'APPLIED'
        if session.committed and session.failed:
            return 'FAILED'
        raise ValueError('A removed session of no known outcome')
    if session.destroyed:
        return 'ABANDONED'
    if session.applied:
        return 'APPLIED'
    if session.failed:
        return 'FAILED'
    if session.ready:
        return 'READY'
    if session.committed:
        return 'VERIFYING'
    return 'SEALED' if session.sealed else 'OPEN'


def join(listing, dump, package=PACKAGE):
    """Each staged session of the package as (classification, reference).

    The listing shows every staged session that is not destroyed. Each must appear once in the
    dump's active or finalized section with the same readiness and outcome, and every such
    session in the dump must be listed. Removed sessions come from the historical section. A
    staged session of no known package could be the ticket's, so it refuses the join. Sessions
    and families certainly about other packages give nothing and block nothing."""
    if not listing.complete:
        raise ValueError('The listing is not complete')
    listed = {s.identity: s for s in listing.for_package(package)}
    joined, seen = [], set()
    for session in dump.sessions:
        if session.package is None and session.staged:
            raise ValueError('A staged session of no known package')
        if session.package != package or not session.staged:
            continue
        if session.section == 'Historical':
            if session.identity in listed:
                raise ValueError('A removed session is still listed')
            joined.append((classify(session), reference(session)))
            continue
        if session.identity in seen:
            raise ValueError('A session dumped twice')
        seen.add(session.identity)
        row = listed.get(session.identity)
        if session.destroyed:
            if row is not None:
                raise ValueError('A destroyed session is still listed')
        elif row is None or (row.ready, row.applied, row.failed) != (session.ready, session.applied, session.failed):
            raise ValueError('The listing and the dump disagree')
        joined.append((classify(session), reference(session)))
    if set(listed) - seen:
        raise ValueError('A listed session is missing from the dump')
    return joined


def observed_cohort(boot_fact, factory_fact):
    """The cohort that one boot's BOOT and FACTORY facts show together."""
    if boot_fact['kind'] != 'BOOT' or factory_fact['kind'] != 'FACTORY' or boot_fact['boot'] != factory_fact['boot']:
        raise ValueError('A cohort needs the fingerprint and the factory digest of one boot')
    return readback.Cohort(boot_fact['facts']['fingerprint'], factory_fact['facts']['apk'])


def encode(fact):
    """The record bytes of one observation, through the runner's independent encoder."""
    return encoder.observation(fact)
