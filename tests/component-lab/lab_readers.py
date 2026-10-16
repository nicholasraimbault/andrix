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
form and joins, and builds every fact itself. The parsers of the guest's forms are later
packages, so `ObserverAdapter` admits none of them."""
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
    # Whether a receipt reader is admitted. The full screen notice fixture is a later package.
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

    def receipt_rows(self, ticket):
        """Every row the notice fixture's provider returns in one whole read, each the row's
        exact bytes and its fields: purpose, installation, component, plan, ticket, index or
        control action, boot token, text digest, event, app UID, user, serial and candidate time.
        Called only when `receipts_admitted`, under a version 3 admission."""
        raise NotImplementedError

    def health_baseline(self, context):
        """One user's health baseline: {'user', 'serial', 'facts'}. Called only when
        `health_admitted`."""
        raise NotImplementedError

    def health_composition(self, context):
        """One user's full probe from fresh reads: {'user', 'serial', 'rows', 'witness'}, with seven
        rows in bit order, each its status, reason, the positions of the commands it judged, and the
        preparation or baseline it used. Called only when `health_admitted`."""
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


class ObserverAdapter(ReaderAdapter):
    """The public shell observer behind the reader interface. `observer` is the observer module,
    `checkpoint` a callable that reads the checkpoint through the observer, or None."""

    def __init__(self, observer, installation, component, checkpoint=None, checkpoint_allowed=None,
                 new_id=None, wall=None, target=False):
        self._module = observer
        self.installation, self.component = installation, component
        self._run_now = None
        self._seen = []
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
                    or (self.target_admitted and command == lab_target.COMMAND))

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
