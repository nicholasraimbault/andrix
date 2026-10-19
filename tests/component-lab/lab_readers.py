# SPDX-License-Identifier: Apache-2.0
"""The broker's injectable reader adapter: how read only groups of guest reads become observation
facts.

The broker owns every guest command. For each group it binds a `run(command)` function, calls one
reader method, and records the group: the capture numbers it ran, the raw digest, and the facts
it gave. `run` returns `(exit status, stdout text, stderr text)` only for a command whose remote
completion was observed whole: one EXIT packet, a clean end of stream, and no stream above its
bound. Anything else raises Unavailable, so a transport failure never reaches a parser as a fake
exit status 1. Output text keeps undecodable bytes as surrogates, so the raw digest computed from
it equals the digest of the recorded bytes.

A reader method returns observation fact dicts in the form the shell observer and the runner's
independent encoder use, raises Unavailable when a read could not complete, and raises
Unclassified, a ValueError, for output of no known form. Either way the group gives no fact.

`ObserverAdapter` adapts the public shell observer, `scripts/proof/systemui_observer.py`. The
adapter relies only on its documented names: `ShellObserver(run, installation, new_id=, wall=)`,
its `clock`, `boot`, `checkpoint`, `factory`, `active`, `sessions` and `users(previous)` methods,
the module's `allowed(command)`, and its `Unclassified` exception. The checkpoint reader is injected
as a callable that takes the observer. The public one is `ShellObserver.checkpoint`, which reads the
checkpoint through StorageManager with the fixed helper, and whose commands the observer's own
allowlist already holds. Until a reader is injected, no CHECKPOINT fact exists, and the reconciler
issues no crossing. The observer's partial health probe is not exposed, and never will be: it is not
a full probe.

The next campaign profile adds five readers, each admitted by its own flag and called only then:
the whole typed user inventory, the notice fixture's provider rows, a user's health baseline, a
user's full health composition and the whole global session inventory. They return typed
projections, not observation facts: the broker records the raw captures, checks each projection's
form and joins, and builds every fact itself. The full user readers (full_users.py) read the typed
inventory from the whole user forms, and with it the user limits and each user's genuine main
SystemUI process; `ObserverAdapter` admits them when it is given `users=True`. The health package
reads a user's baseline (health_baseline.BaselineReader) and full composition
(health_compose.Composer) through the same run function; `ObserverAdapter` admits them when it
is given both, beside the full user readers. With `global_sessions=True` it admits the whole
global session inventory of global_sessions.py, the observer's own fixed reads parsed whole by its
strict parsers. With `receipts`, a receipt reader factory, it admits the notice fixture's provider
rows: for each read the broker passes the recipients of the ticket's issued notices, from its own
ledger, and the adapter gives exactly those to a reader the factory makes, as the notice fixture's
`NoticeReader(recipients)` takes them."""
import hashlib

import lab_target


class Unavailable(Exception):
    """A read that did not complete whole: no fact."""


class Unclassified(ValueError):
    """Output of no known form: no fact."""


def raw_digest(captures):
    """SHA-256 over every capture of a group in order: for each, the command, the exit status as
    decimal text, the output and the error, each as an eight byte little endian length and its
    bytes. This is the observer's definition. `captures` are (command, exit, stdout bytes, stderr
    bytes) tuples."""
    digest = hashlib.sha256()
    for command, code, stdout, stderr in captures:
        for data in (command.encode('utf-8', 'surrogateescape'), str(code).encode('ascii'), bytes(stdout),
                     bytes(stderr)):
            digest.update(len(data).to_bytes(8, 'little') + data)
    return digest.hexdigest()


class ReaderAdapter:
    """The interface the broker calls. A reader for one component of one installation."""

    installation = None
    component = None
    # Whether a receipt reader is admitted: the full screen notice fixture's provider rows.
    receipts_admitted = False
    # Whether the native target scope is read through this reader (lab_target). The broker then
    # reads it as its own recorded group at HELLO and at every crossing's gate.
    target_admitted = False

    def allowed(self, command):
        """Whether a command is one of the reader's fixed read only forms."""
        raise NotImplementedError

    def bind(self, run):
        """The broker binds its run function for the next group."""
        raise NotImplementedError

    def clock(self):
        """(boot as 32 hexadecimal digits, framework instance or -1, elapsed ms, wall ms)."""
        raise NotImplementedError

    def boot(self):
        raise NotImplementedError

    def checkpoint(self):
        raise NotImplementedError

    def factory(self):
        raise NotImplementedError

    def active(self):
        raise NotImplementedError

    def sessions(self):
        raise NotImplementedError

    def users(self, previous):
        raise NotImplementedError

    def receipts(self, ticket):
        """RECEIPT facts of a ticket's notices. Called only when `receipts_admitted`, under a
        version 1 or 2 admission. Each fact's time is its read time, so a delivery read back
        later is refused by the broker's clock guard: version 1 cannot carry a historical
        receipt."""
        raise NotImplementedError

    # ------------------------------------------------ the next campaign profile

    # Whether the typed whole user inventory is admitted. Typed actions and notices need it.
    inventory_admitted = False
    # Whether the health baseline and composition readers are admitted.
    health_admitted = False
    # Whether a composition's failure witness decision comes from an admitted witness reader.
    # Without one, no criterion row may claim a witnessed crash or ANR.
    witness_admitted = False

    def inventory(self):
        """The typed user inventory from one whole raw dump, as lab_actions.check_inventory defines
        it. Called only when `inventory_admitted`."""
        raise NotImplementedError

    def receipt_rows(self, ticket, recipients):
        """Every row the notice fixture's provider returns in one whole read of the stores of
        `recipients`, each the row's exact bytes and its fields: purpose, installation, component,
        plan, ticket, index or control action, boot token, text digest, event, app UID, user, serial
        and candidate time. `recipients` are the (user, serial) pairs, in order and each once, that
        every notice the broker issued for the ticket required, as its ledger's issue records name
        them: the reader reads those stores and no other user's. Called only when
        `receipts_admitted`, under a version 3 admission."""
        raise NotImplementedError

    def health_baseline(self, context):
        """One user's health baseline: {'user', 'serial', 'facts'}, the facts of the exact form
        health_records.baseline_facts_problem checks. Called only when `health_admitted`."""
        raise NotImplementedError

    def health_composition(self, context):
        """One user's full probe from fresh reads: {'user', 'serial', 'rows', 'witness'}, with seven
        rows in bit order, each its status, reason, the positions of the commands it judged, and the
        preparation or baseline it used. The context names the ticket, plan, user, serial, window,
        the offered preparations and their results, the baseline relied on, the pinned active
        APK, the serial's expected identity and the CE nonce origin. Called only when
        `health_admitted`."""
        raise NotImplementedError

    # Whether the whole global session inventory is admitted. Confirmations and direct controls
    # need it.
    global_admitted = False

    def global_sessions(self):
        """Every installer session of every package from one whole dump, parsed whole before any
        SystemUI projection, as lab_actions.check_global defines it: each session's section, ID,
        package, referrer, family, commitment, readiness and end, and the class of a failure's
        recorded cause. Called only when `global_admitted`."""
        raise NotImplementedError

    def target(self):
        """The native target scope one whole read shows (lab_target.scope). Called only when
        `target_admitted`."""
        raise NotImplementedError

    # Whether the full user readers are admitted: then `inventory` reads the whole user forms, and
    # `user_limits` and `systemui_processes` are admitted with it. The user setup actions need them.
    users_admitted = False

    def user_limits(self):
        """The user limits, full_users.limits' form. Called only when `users_admitted`."""
        raise NotImplementedError

    def systemui_processes(self, inventory):
        """Each listed user's genuine main SystemUI process over a whole typed inventory just read,
        full_users.join_processes' form. Called only when `users_admitted`."""
        raise NotImplementedError

    def rederive(self, name, captures, inventory=None):
        """What a group's recorded captures give when read again, for a reopening's check: a typed
        reading, or for the factory and active reads their facts, whose observation IDs and wall
        times are not the recorded ones. `captures` are (command, exit status or None, stdout,
        stderr) in order. NotImplemented when this reader cannot read them again."""
        return NotImplemented


class ObserverAdapter(ReaderAdapter):
    """The public shell observer behind the reader interface. `observer` is the observer module,
    `checkpoint` a callable that reads the checkpoint through the observer, or None."""

    def __init__(self, observer, installation, component, checkpoint=None, checkpoint_allowed=None,
                 new_id=None, wall=None, target=False, users=False, composer=None, baseline=None,
                 global_sessions=False, receipts=None):
        self._module = observer
        self.installation, self.component = installation, component
        self._run_now = None
        self._seen = []
        # The whole global session inventory, admitted only when asked for: the observer's own
        # fixed reads, which its allowlist already holds, parsed whole by its strict parsers.
        self._global = None
        if global_sessions:
            import global_sessions as global_reader
            self._global = global_reader
            self.global_admitted = True
        # The notice fixture's provider rows: `receipts(recipients)` makes a reader of the given
        # stores, with `allowed(command)`, `bind(run)` and `receipt_rows(ticket)`, as the fixture's
        # NoticeReader is made with the recipients function it reads.
        self._receipts = receipts
        if receipts is not None:
            self._receipt_forms = receipts(lambda ticket: [])
            self.receipts_admitted = True
        # The full user readers, admitted only when asked for, read through the same run function.
        self._users = None
        if users:
            import full_users
            self._users = full_users
            self.users_admitted = self.inventory_admitted = True
        # The health readers, admitted together and only beside the full user readers: the witness
        # reader is admitted exactly when the composer has one.
        self._composer, self._baseline = composer, baseline
        if composer is not None or baseline is not None:
            if not users or composer is None or baseline is None:
                raise ValueError('the health readers need the full user readers, a composer and a baseline reader')
            self.health_admitted = True
            self.witness_admitted = composer.hooks[1] is not None and baseline.witness is not None
        options = {}
        if new_id is not None:
            options['new_id'] = new_id
        if wall is not None:
            options['wall'] = wall
        self._observer = observer.ShellObserver(self._run, installation, component, **options)
        self._checkpoint = checkpoint
        self._checkpoint_allowed = checkpoint_allowed or (lambda command: False)
        self.target_admitted = bool(target)

    def allowed(self, command):
        return bool(self._module.allowed(command) or self._checkpoint_allowed(command)
                    or (self.target_admitted and command == lab_target.COMMAND)
                    or (self._users is not None and self._users.read_allowed(command))
                    or (self._composer is not None and self._composer.allowed(command))
                    or (self._baseline is not None and self._baseline.allowed(command))
                    or (self._global is not None and self._global.allowed(command))
                    or (self._receipts is not None and self._receipt_forms.allowed(command)))

    def bind(self, run):
        self._run_now = run
        self._seen = []

    def _run(self, command):
        if self._run_now is None:
            raise Unavailable('no group is open')
        code, stdout, stderr = self._run_now(command)
        self._seen.append((command, code, stdout, stderr))
        return code, stdout, stderr

    def _call(self, method, *args):
        try:
            return method(*args)
        except self._module.Unclassified as error:
            raise Unclassified(str(error)) from error

    def clock(self):
        boot, instance, elapsed, wall = self._call(self._observer.clock)
        if instance == -1:
            # No framework is read only from pidof's quiet failure, twice in the same bracket. The
            # observer at this package's base does not check standard error, so the adapter does.
            pidof = [c for c in self._seen if c[0] == 'pidof system_server']
            if len(pidof) < 2 or any((code, out, err) != (1, '', '') for _, code, out, err in pidof):
                raise Unclassified('no framework was not read from a confirmed quiet failure')
        return boot, instance, elapsed, wall

    def target(self):
        if not self.target_admitted:
            raise Unavailable('no target reader is admitted')
        return lab_target.scope(*self._run(lab_target.COMMAND))

    def boot(self):
        return [self._call(self._observer.boot)]

    def checkpoint(self):
        if self._checkpoint is None:
            raise Unavailable('no qualified checkpoint reader is integrated')
        return [self._call(self._checkpoint, self._observer)]

    def factory(self):
        return [self._call(self._observer.factory)]

    def active(self):
        return [self._call(self._observer.active)]

    def sessions(self):
        return list(self._call(self._observer.sessions))

    def users(self, previous):
        return list(self._call(self._observer.users, tuple(previous)))

    def _user_reader(self):
        if self._users is None:
            raise Unavailable('no full user reader is admitted')
        return self._users.UserReader(self._run)

    def inventory(self):
        return self._user_reader().inventory()

    def user_limits(self):
        return self._user_reader().limits()

    def systemui_processes(self, inventory):
        return self._user_reader().processes(inventory)

    def global_sessions(self):
        if self._global is None:
            raise Unavailable('no global session inventory is admitted')
        return self._global.read(self._run)

    def receipt_rows(self, ticket, recipients):
        if self._receipts is None:
            raise Unavailable('no receipt reader is admitted')
        given = [(int(user), int(serial)) for user, serial in recipients]
        reader = self._receipts(lambda asked: list(given) if asked == ticket else [])
        reader.bind(self._run)
        try:
            return reader.receipt_rows(ticket)
        finally:
            reader.bind(None)

    def rederive(self, name, captures, inventory=None):
        if name == 'global-sessions':
            return self._global.rederive(captures) if self._global is not None else NotImplemented
        if name in ('factory', 'active'):
            # The public observer reads the recorded replies again, in order: a capture of another
            # command, one that did not complete, or one left over refuses.
            queue = list(captures)

            def run(command):
                if not queue or queue[0][0] != command:
                    raise Unclassified('the captures are not the reads a %s fact makes' % name)
                _, code, stdout, stderr = queue.pop(0)
                if code is None:
                    raise Unavailable('a capture did not complete')
                return code, stdout, stderr
            observer = self._module.ShellObserver(run, self.installation, self.component, new_id=lambda: '00' * 16,
                                                  wall=lambda: 0)
            fact = self._call(getattr(observer, name))
            if queue:
                raise Unclassified('captures beyond the reads a %s fact makes' % name)
            return [fact]
        if self._users is None:
            return NotImplemented
        return self._users.rederive(name, captures, inventory)

    def health_baseline(self, context):
        if self._baseline is None:
            raise Unavailable('no health baseline reader is admitted')
        return self._baseline.read(self._run, context)

    def health_composition(self, context):
        if self._composer is None:
            raise Unavailable('no health composer is admitted')
        return self._composer.compose(self._run, context)
