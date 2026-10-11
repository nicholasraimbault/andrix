# Component transaction lab bridge

This directory holds the host vehicle that step D5 of the
[first durable component transaction](../../plans/2026-10-09-component-transaction.md) uses to drive
the accepted coordinator against one disposable guest through the shell route. It has two halves:

- **The broker**, in Python. It owns every guest command, the raw captures, the fault schedule and
  the stop fence. It builds each command from typed fields and never runs caller supplied shell
  text.
- **The bridge**, in Java. It runs inside one coordinator process and implements the coordinator's
  `Device` through the broker. Ticket decisions stay in the accepted `Reconciler`.

Everything here is host code with host tests. It runs no emulator, starts no guest, installs nothing
and signs nothing. A passing suite qualifies the protocol, the ledger and the broker's rules on the
host. It does not qualify any Android form, delivery route, health criterion or activation. The lab
driver, the notice and health fixtures, the admission and the closure are later packages.

## Files

| File | Contents |
| --- | --- |
| `lab_protocol.py` | Version 1 of the bridge protocol: framing, message layouts, relations |
| `shell_transport.py` | The adb host client: shell protocol v2, the reboot service, the sync push |
| `capture_ledger.py` | The broker's numbered durable ledger |
| `lab_broker.py` | The broker: admission, lock, fences, generations, groups, crossings, fault cells |
| `lab_crossings.py` | The typed crossing commands and their reply forms |
| `lab_readers.py` | The injectable reader adapter and its adapter for the public shell observer |
| `source_manifest.py` | The exact source manifest a broker is admitted with |
| `sim_android.py`, `labtest.py` | Host test support: a small simulated guest and a client |
| `test_*.py` | The host suites |

## Process model

One broker serves one admitted guest runtime. It is the parent of each coordinator process, a
generation, and talks to it over that process's own standard input and output, which the broker
created as unbuffered pipes. Standard output carries only protocol frames. Diagnostics go to
standard error, which the broker keeps in a file per generation outside the ledger.

- **One writer.** An open broker holds an exclusive lock on its directory. A second broker on the
  same directory refuses to open.
- **One operation in flight.** The broker handles one request at a time to its end. While a capture
  is open the ledger accepts no other entry.
- **Generations.** A generation starts only after every earlier one has ended and its process was
  reaped. The bridge's first request is HELLO, once. A generation exits 0 when its work completed,
  99 only when the broker ordered a halt, and 125 when the broker answered STOPPED. The broker
  records each end as COMPLETE, DELIBERATE_HALT, STOPPED, KILLED or FAILED. An exit 99 that the
  broker did not order is FAILED. A generation that a lost broker left is recorded as LOST.
- **A lost generation.** If the coordinator process dies while the broker runs its command, the
  broker finishes that command within its bound, records it, and only then sees the end of the
  generation. The reply it could not deliver is lost, and reconciliation decides by observation.
- **Bounded transfers.** A generation may be idle for its bound before a request begins. Once a
  request's first byte arrives, the whole frame must arrive within the same bound, and each reply
  must be written whole within it. A stalled peer ends the generation, and its process is killed
  and reaped within its own bound before another generation starts.
- **A lost broker.** The next broker on the directory quarantines the incomplete last entry, waits
  out the bound of a command whose effect is unknown, ends a lost generation's process if it still
  runs, and records all of this before it serves again.

## Protocol, version 1

Every frame, little endian:

```
u32  magic      0x424c5841, "AXLB" in file order
u16  version    1
u16  type       odd for a request; its reply is the request's type plus one
u32  length     of the whole frame, checksum included: 92 to 4,194,304
id   request    16 bytes, nonzero, fresh for each request; a reply repeats it
d32  manifest   32 bytes, the admitted source manifest digest, nonzero
     body       the type's fields in order
d32  checksum   SHA-256 of every preceding byte
```

Integers are fixed width: `u8`, `u16`, `u32` unsigned, `i32`, `i64` signed. `id` is 16 raw bytes,
`d32` 32 raw bytes. `text` is a `u16` length and that many bytes of printable ASCII, 0x20 to 0x7e,
at most 1,024. `blob` is a `u32` length and at most 65,536 bytes. `ref` is the deployment records'
reference block: `u8` presence (bit 0 session, 1 created, 2 stage dir, 3 installer, 4 nonce),
`i32` session, `i64` created, `text` stage dir of at most 255 bytes, `i32` installer, `id` nonce,
each field set exactly when its bit is. Decoding checks the size, magic, version, type, length and
checksum first, then every field's bound, the absence of trailing bytes and every relation below.
It never repairs input, and every valid message has exactly one encoding.

Every reply body begins with `u8 status`: 1 OK, 2 UNAVAILABLE, 3 STOPPED, 4 HALT, 5 WITHHELD,
6 NO_REPLY, 7 REFUSED, and ends with `text reason`, empty exactly with OK. REFUSED answers a
request that breaks the protocol or the admission in any reply type. The bridge treats it as a
fatal error, never as a lost reply.

| Type | Body | Relations |
| --- | --- | --- |
| 1 HELLO | `id installation, id coordinator, d32 config, text component, d32 trust, u8 route` | route 1 SHELL; the component is a package name; every digest nonzero |
| 2 HELLO reply | `u8 status, u32 generation, u8 target, text reason` | OK, STOPPED or REFUSED. Generation at least 1 and target 1 ESTABLISHED_EMPTY, 2 HELD or 3 UNKNOWN exactly with OK |
| 3 CLOCK | empty | |
| 4 CLOCK reply | `u8 status, id boot, i64 instance, i64 elapsed, i64 wall, u32 group, text reason` | OK, UNAVAILABLE, STOPPED. With OK the boot is nonzero, the instance at least -1, the elapsed time at least 0, and the group names the reading's ledger entry. Otherwise the reading is all zero |
| 5 OBSERVE | `u8 scope, text component, id boot, id ticket, id plan, u8 state` | scope 1 COMPONENT with no ticket, plan or state, or 2 TICKET with all three. The boot is the round's clock boot |
| 6 OBSERVE reply | `u8 status, u16 count, count of (u32 group, blob frame), text reason` | OK or STOPPED. At most 256 frames, each an observation record with the ledger entry of its group |
| 7 CROSS | `id ticket, d32 ticketDigest, id plan, d32 planDigest, i32 attempt, text component, u16 index, u8 crossing, u16 occurrence, id entryBoot, i64 entryInstance, i64 entryElapsed, id grant, id reference, ref native, d32 bundleApk, u8 actor, i64 granted, i64 window` | below |
| 8 CROSS reply | `u8 status, u32 record, blob frame, text reason` | OK with the REPLY observation, NO_REPLY, WITHHELD, HALT, STOPPED. The frame exactly with OK. The record names the broker's crossing entry |
| 9 POINT | `text point, id ticket, id plan, i32 attempt` | the point is `selection-written`, the coordinator's BETWEEN_WRITES |
| 10 POINT reply | `u8 status, u32 record, text reason` | OK or HALT, with the fault entry exactly for HALT |
| 11 HOST | `u8 phase, u8 crossing, id ticket, id plan, i32 attempt, u16 index, u16 occurrence, id reference, u8 outcome, d32 reply` | phase 1 BEGIN or 2 END, crossing 1 SIGN or 2 PUBLISH. BEGIN has outcome 0. END has outcome 1 REPLY, 2 NULL or 3 THREW, and the SHA-256 of the reply's record exactly with REPLY |
| 12 HOST reply | `u8 status, u32 record, text reason` | OK, HALT, WITHHELD, with the record |
| 13 REPORT | `id ticket, u8 state, u8 flags, u8 cause, u16 count, count of u8 crossing, text note` | a ticket's state, flags, cause and ledger, informational |
| 14 REPORT reply | `u8 status, u32 record, text reason` | OK with the report's entry |

A CROSS names a device crossing: 3 CREATE, 4 WRITE, 5 COMMIT, 6 ABANDON, 7 REBOOT or 8 NOTICE. The
index is below 140 and the occurrence, the count of that crossing in the ledger up to the entry,
is from 1 to the crossing's bound and the index plus one. CREATE, WRITE, COMMIT and ABANDON need an
entry instance of at least 0. The grant is nonzero exactly for CREATE, COMMIT, REBOOT and NOTICE,
with its actor class, 1 GRANT_HOLDER or 2 LAB_OPERATOR. CREATE carries the ticket's nonce as its
reference and as the only field of `native`. WRITE, COMMIT and ABANDON carry a `native` reference
with the session, createdMillis, installer and nonce, never the session ID alone. WRITE carries the
APK digest that the plan's publication binds, and nothing else does. COMMIT, REBOOT and NOTICE,
under an ACTIVATE grant, carry the grant's time and the plan's activation window in milliseconds,
both at least 1. Every other crossing carries zero for both.

The goldens in `test_lab_protocol.py` pin one frame of every type. The Java codec must produce the
same bytes.

## Transport

`shell_transport.py` talks to the host's adb server through its smart socket protocol. A transport
service first selects the device with `host:tport:serial:<serial>`, and the broker never falls back
to protocol 1 or a PTY.

- **Shell.** The service `shell,v2,raw:<command>`. The daemon frames standard output (1), standard
  error (2) and the exit status (3) as a one byte ID and a four byte length. It sends one EXIT
  packet of length 1 after the process ends and then closes. A remote exit status exists only for
  exactly one well formed EXIT packet followed by a clean end of stream. An end of stream before
  EXIT, a packet cut short, a second EXIT, an EXIT of another length, any other packet ID, a packet
  after EXIT, a stream above its bound or a timeout each leave the status unknown. Each stream has
  its own bound, and a packet that would pass it ends the read before its payload is taken. When
  the stream stops inside a stdout or stderr packet, the payload bytes already received stay in
  that stream and the result names the stream. The bytes of a cut header stay as residual. Neither
  completes anything.
- **Launch and transport status.** A result records whether the command was launched (the
  service's OKAY), not launched, or unknown (the service request's transmission began, and no
  status came back or the transmission failed part way), the
  transport's status (ok, closed, timeout, I/O error, protocol fault, connect, transport or service
  failure with the server's FAIL message), the completion, the EXIT value received and the two
  streams unchanged. A transport error is never a remote exit status, so an adb error never becomes
  a quiet remote 1.
- **Reboot.** The service `reboot:`. It has no shell protocol and no exit status. Its
  acknowledgement is accepted (OKAY), refused (FAIL) or none, then how the stream ended and any
  message. A new boot ID, read later, resolves the request.
- **Push.** The service `sync:`, version 1 SEND: `SEND` with `path,mode`, `DATA` chunks of at most
  64 KiB, `DONE` with the modification time, then OKAY or FAIL with a message, then `QUIT`. The
  broker verifies every pushed file with a separate digest read.

These forms come from the pinned adb client and the daemon's shell service. The service argument
names `v2` and `raw`, and the feature name `shell_v2`, are the client's constants defined outside
the sources this package inspected. A guest check of the shell form must precede any mutation.

## Ledger

```
<broker>/ledger/LEDGER           "andrix-lab-ledger 1", written once
<broker>/ledger/NNNNNN-<kind>/   one entry, numbered from 1 without gaps
```

A record entry holds `record.json`. A capture holds `intent.json`, then `stdout` and `stderr`, then
`result.json` with each stream's digest and size. Every file is created exclusively, written whole
and synced through its own descriptor, and each directory change is synced. The intent is synced
before the command is launched, and the result is written last. Each JSON file repeats its entry's
number and kind. Nothing is ever rewritten or removed.

The kinds are `open`, `generation`, `generation-end`, `capture`, `group`, `crossing`, `outcome`,
`fault`, `escrow`, `host`, `quarantine`, `stop`, `faults`, `artifacts` and `report`.

Reopening checks the marker, each name and kind, the numbering, each entry's files and each complete
capture's stream digests. One writer writes one entry at a time, so only the last entry can be
incomplete after a crash. A reopening broker writes a quarantine record for it before anything else:
`launched: false` when no whole intent exists, because a command starts only after its intent is
synced, and `launched: "unknown"` for an intent without a result. A crash during that reopening can
leave a run of quarantine entries, which the next reopening completes. The wait for a command whose
effect is unknown comes from every capture with an intent and no result, quarantined or not, so a
reopening lost before or during its wait leaves the same wait to the next one. Any other incomplete
entry, a gap, an unknown name, a link, an extra file or other stream bytes refuse the reopening.

## Broker

A broker directory holds `admission.json` and `manifest.json`, both written once, the ledger, and
the generations' diagnostics.

- **Admission.** The installation, component, coordinator, trust policy digest, source manifest
  digest, the digest of the bridge's configuration file, the device serial, the native target
  scope, the guest staging directory, the fences and the limits. A HELLO must repeat the
  installation, coordinator, configuration digest, component and trust policy exactly. Every
  request must carry the admitted manifest digest.
- **Sources.** Opening verifies every file the manifest lists, each a regular file reached without
  a link, with its exact digest and size. Any difference refuses the opening.
- **Shell protocol v2.** Before its first guest command, each broker reads the device's features
  through the server, as a recorded capture. A definite answer without `shell_v2` latches a stop.
  An answer that cannot be read launches nothing, and is asked again before the next command.
- **Fences.** Before every guest command, reads and the feature query included, right before its
  intent: the stop latch, the stop file, the lease file's token and the runtime deadline. A tripped
  fence is latched in the ledger with its reason. From then on every request that needs the guest is
  answered STOPPED, HELLO included, in this broker and every later one on the same ledger. A command
  already running finishes within its own bound.
- **Groups.** Each reader call is one group: its captures, its raw digest and the facts it gave are
  recorded together. A read whose remote completion was not observed whole raises Unavailable, so
  a transport failure never reaches a parser as an exit status. Every fact must be of the reader's
  kinds, of the admitted installation and route, of the right component scope, of the round's
  boot, and carry its group's raw digest. The uptime and the framework instance never go back
  within a boot. A group of another boot ends the observation.
- **Target scope.** The admission states whether the native target scope was positively
  established empty. An injected target reader, when the controller gives one, is read again at
  HELLO and at every crossing's gate; a reader that fails or names no known scope reads UNKNOWN.
  Unless the scope is established empty, no crossing but the abandon of the ticket's own exact
  session is launched. The broker does not establish the scope itself.
- **Sources.** Before every crossing the admitted sources are verified again. A difference latches
  a stop.

### Crossings

Each CROSS is recorded before its first command, and the broker refuses any later CROSS for the
same ticket and ledger index, so a crossing is never repeated, after a reopening too. A gate comes
before the crossing's first mutation. It reads the target scope, then the clock as its own group:
the boot must be the entry's, and for a framework crossing the framework instance too. Under an
ACTIVATE grant the reading's wall time must be at or after the grant's time and before the end of
the plan's activation window, the reconciler's rule, so a grant that expired after the round's
clock launches nothing. WRITE, COMMIT and ABANDON then read the sessions and need exactly one live
session with the ticket's ID, which matches the ticket's reference by the reconciler's rule:
createdMillis or the nonce known to both, and every field both know equal. WRITE and COMMIT need it
open. Otherwise nothing is launched and the reply is NO_REPLY. WRITE passes the gate again after
staging and before each member, so a reboot, a framework change or a replaced session during the
uploads writes nothing more. A change after the first member leaves the second unwritten, then and
after any reopening, with NO_REPLY.

| Crossing | Commands | Reply |
| --- | --- | --- |
| CREATE | `pm install-create --user 0 -r --pkg <component> --staged --referrer andrix-ticket:<nonce>` | SUCCESS for `Success: created install session [N]`, with the reference that one session readback in the same framework instance shows for N with the ticket's nonce, or N alone. Otherwise UNRECOGNIZED |
| WRITE | for each member: a sync push to `<staging dir>/<plan>/<member>` and a digest read, then `pm install-write <session> base.apk <path>` and `pm install-write <session> base.apk.idsig <path>` | SUCCESS only when both report `Success: streamed N bytes` with the member's size. The second member is never written unless the first succeeded |
| COMMIT | `pm install-commit --staged-ready-timeout 60000 <session>` | READY, ACCEPTED, PENDING for the timeout sentence, otherwise UNRECOGNIZED |
| ABANDON | `pm install-abandon <session>` | SUCCESS for `Success`, otherwise UNRECOGNIZED |
| REBOOT | the reboot service | none: a new boot ID resolves it |
| NOTICE | an admitted notice route's fixed commands, each checked against the route's allowlist | the route's own exact forms; without a route, nothing is launched |

A reply exists only for a command that completed whole, with exit status 0, nothing on standard
error and exactly the expected output for SUCCESS and its peers. A command that did not complete
gives NO_REPLY, and its effect is unknown. No form maps to REFUSED, because no refusal form has been
captured and a refusal reads as proof that nothing happened. WRITE pushes only artifacts that the
controller pinned for the plan: each member's host path, digest and size, read and checked again
before the push.

### Fault cells

The controller, never a generation, admits fault cells as ledger records. Each names its ID, where
it acts, its key and its mode.

| On | Key | Modes |
| --- | --- | --- |
| `cross` | plan, attempt, crossing, occurrence | `loss-before`, `loss-after`, `drop-reply`, `loss-between-members` (WRITE only) |
| `host` | plan, attempt, SIGN or PUBLISH, occurrence | `loss-before`, `loss-after`, `drop-reply` |
| `point` | plan, attempt, point | `halt` |

A request takes the first unconsumed cell whose key it matches. The record of the request names the
cell before anything acts, so a cell acts at most once, across reopenings too.

- **loss-before.** Nothing is launched. A fault record says so, and then the broker answers HALT.
- **loss-after.** The crossing runs once and is recorded, a fault record keeps the digest of the
  withheld reply, and the broker answers HALT.
- **drop-reply.** The crossing runs once and is recorded. An escrow record keeps the withheld reply,
  and the broker answers WITHHELD, which the bridge turns into a lost reply. Escrow is evidence for
  the closure. It is never given to any generation and never settles an observation.
- **loss-between-members.** WRITE writes the first member, a fault record follows, and the broker
  answers HALT. The second member is never written, then or after a reopening.
- **halt.** At the coordinator's BETWEEN_WRITES point, a fault record, then HALT.

A HOST BEGIN is recorded before the bridge calls the host signer or publisher, and its END after.
A second BEGIN or END for one ledger entry is refused. A generation that ends during a host call
has its call recorded as ended with its process, so a later generation's query never runs while the
old call could still complete. That a command was not launched is recorded for the closure only. It
never becomes an observation, so it can never serve as proof that the guest has no session.

A notice route has `allowed(command)` and `notice(run, ticket, index, plan)`. It runs its fixed
commands through the broker's `run`, which fences, records and returns each whole shell result, and
classifies its own exact forms as SUCCESS, REFUSED or UNRECOGNIZED. A SUCCESS says that the fixture
accepted the request, never that a user saw the notice: receipts come from later observation.

## Reader adapter

`lab_readers.py` defines what the broker calls. A reader has an allowlist of fixed read only
commands and returns observation facts in the form that the shell observer and the runner's
independent encoder use. `ObserverAdapter` adapts the public shell observer through its documented
names only. Its checkpoint reader is injected: the public one is `ShellObserver.checkpoint`, which
reads the checkpoint through StorageManager with the fixed helper. Until a checkpoint reader is
injected, no CHECKPOINT fact exists, and the reconciler issues no crossing. The adapter
reads no framework only from pidof's quiet failure, read twice. The observer's partial health probe
and any receipt reader are not exposed. Health composition and the notice fixture are later
packages.

## Running the checks

```sh
python3 -B -m unittest discover -s tests/component-lab -p 'test_*.py'
```

These are host checks only. They use a simulated guest and a fake adb server, so they qualify no
guest form, Android behavior, power loss or activation.

## Limits

- The shell v2, reboot and push forms are source derived, and need a guest check before mutation.
- No refusal form of any crossing is qualified, so no reply reads REFUSED.
- No notice route, receipt reader, health composition or crash witness exists here.
- The native target scope is an admitted decision. The broker does not establish it.
- A process crash is not power loss, and directory times are not durability evidence.
