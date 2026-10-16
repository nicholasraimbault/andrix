# Component transaction lab bridge

This directory holds the host vehicle that step D5 of the
[first durable component transaction](../../plans/2026-10-09-component-transaction.md) uses to drive
the accepted coordinator against one disposable guest through the shell route. It has two halves:

- **The broker**, in Python. It owns every guest command, the raw captures, the fault schedule and
  the stop fence. It builds each command from typed fields and never runs caller supplied shell
  text.
- **The bridge**, in Java. It runs inside one coordinator process and implements the coordinator's
  `Device` through the broker. Ticket decisions stay in the accepted `Reconciler`.

Everything here is host code with host tests. It runs no emulator, starts no guest and installs
nothing. Only the lab driver's suite signs, and only when it is given the public development
platform key that Android source trees carry and the two built inputs: it signs them for a simulated
guest, never for a device. A passing suite qualifies the protocol, the ledger, the broker's rules
and the driver's guards on the host. It does not qualify any Android form, delivery route, health
criterion or activation. The lab driver's core is here: the store's setup from the guest's own
baseline and the coordinator processes with the real host, and the design's loss cells as one
sequence of attempts. The guest vehicle, the notice and health fixtures, the admission and the
closure are later packages.

## Files

| File | Contents |
| --- | --- |
| `lab_protocol.py` | Versions 1 and 2 of the bridge protocol: framing, message layouts, relations, envelopes |
| `shell_transport.py` | The adb host client: shell protocol v2, the reboot service, the sync push |
| `capture_ledger.py` | The broker's numbered durable ledger |
| `lab_broker.py` | The broker: admission, lock, fences, generations, groups, crossings, fault cells |
| `lab_crossings.py` | The typed crossing commands and their reply forms |
| `lab_readers.py` | The injectable reader adapter and its adapter for the public shell observer |
| `lab_actions.py` | The next campaign profile's typed lab actions: registry, exact specs, user resolution |
| `lab_evidence.py` | Strict canonical side records: compound manifests and retained action specs |
| `lab_records.py` | Strict readers of a stored plan and ticket, for where a compound fact may be placed |
| `lab_target.py` | The native target scope read: the selected image's exact fresh form of Package Manager's native identity diagnostic |
| `source_manifest.py` | The exact source manifest a broker is admitted with |
| `lab_driver.py` | The lab driver: the store's setup, the baseline check, the plan from it, the generations, the published variant staged for WRITE, and the cell sequence's attempts |
| `cells.py` | The loss cells as one ordered sequence of attempts on one plan, each with its faults and prediction |
| `driver/` | Java: `LabDriverMain`, the driver's coordinator process and store setup, and `LabHost`, the real host signer, artifact store and bundle builder |
| `driver-tests/` | Java: `DriverTest`, unit checks of the driver's baseline, selection, host configuration and approval guards |
| `sim_android.py`, `labtest.py` | Host test support: a small simulated guest and a client |
| `test_*.py` | The host suites; `test_lab_next.py` is the next campaign profile's broker suite |

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

## Protocol, version 2

The next campaign profile's bridge speaks version 2, and only it: a broker under a version 3
admission decodes and encodes version 2 frames, and every other broker version 1 frames. A frame of
the other version is refused, never converted. The frame and every message are version 1's, except
the OBSERVE reply:

| Type | Body | Relations |
| --- | --- | --- |
| 6 OBSERVE reply | `u8 status, u32 control_record, u16 count, count envelopes, text reason` | OK with control record 0 and at most 256 envelopes; HALT with the consumed fault record and none; STOPPED or REFUSED with neither. No observation ID twice. No WITHHELD |

An envelope is `u32 group, u8 mode, d32 evidence, u16 block length, block, blob observation`. The
observation is one whole deployment observation record of version 1, and the evidence digest is
its raw digest. The block has its mode's exact layout and size:

| Mode | Block | Relations |
| --- | --- | --- |
| 1 SIMPLE_CURRENT | empty | A current fact as version 1 carries it, never HEALTH and never RECEIPT |
| 2 RECEIPT_EVENT | the read bracket, then `id plan, id ticket, u16 notice_index, d32 issue_ticket_digest, id event, d32 row, d32 delivery_group, i64 delivery_instance, i64 delivery_begin, i64 proven_elapsed, i64 delivery_end` | A full screen RECEIPT of that ticket and notice index, at the proven event: `delivery_begin <= proven_elapsed <= delivery_end <= read_end_elapsed`, the delivery in a framework instance no later than the read's. Every ID and digest nonzero |
| 3 COMPOSED_HEALTH | the read bracket, then `id plan, id ticket, id window_boot, i64 window_start, d32 publication, d32 active_apk, d32 baseline, d32 preparation_root, i64 probe_begin, i64 probe_end, u8 criteria`, then seven rows of `u8 bit, u8 status, d32 child` | One HEALTH fact of every criterion (127) at its probe's end: `window_start <= probe_begin <= read_begin_elapsed` and `probe_end == read_end_elapsed`, the window of the read's boot, the rows bits 0 to 6 in order with statuses 1 HELD, 2 BAD or 3 UNKNOWN, and the classification the rows give |

The read bracket is `id read_boot, i64 read_instance, i64 read_begin_elapsed, i64 read_end_elapsed`:
the current read's own boot, running framework instance and elapsed times, which the compound fact
also carries. A health classification follows its rows at both ends: a BAD no crash or ANR row,
which only a qualified failure witness gives, is CRASH; any other BAD row is DEGRADED; seven HELD
rows are HELD; anything else is INCONCLUSIVE. The goldens pin a version 2 frame and each form of
the new OBSERVE reply; both codecs produce the same bytes.

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
- **Launch and transport status.** A result records whether the command was launched (the service's
  OKAY), not launched, or unknown (the service request's transmission began, and no status came back
  or the transmission failed part way), the transport's status (ok, closed, timeout, I/O error,
  protocol fault, connect, transport or service failure with the server's FAIL message), the
  completion, the EXIT value received and the two streams unchanged. A transport error is never a
  remote exit status, so an adb error never becomes a quiet remote 1. A launch deadline, when the
  caller gives one, is asked once more right before the service request, and before the feature
  query's request: a deadline passed by then sends nothing, and the command is not launched.
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
`fault`, `escrow`, `host`, `quarantine`, `stop`, `faults`, `artifacts`, `report`, `lab-action` and
`notice-issue`.

Reopening checks the marker, each name and kind, the numbering, each entry's files and each complete
capture's stream digests, then syncs every file it holds, every entry's directory and its own again
before anything relies on the history: an entry that reads whole may still have had a file or
directory sync fail, and a sync that fails refuses the reopening. A loss the kernel already reported
to an earlier sync can go unreported to a later one, and nothing read from user space shows it. So a
writer never writes on after a failed write or sync: the ledger refuses every later write in that
process, and no command can launch without its durable intent. One writer writes one entry at a
time, so only the last entry can be incomplete after a crash. A reopening broker writes a quarantine
record for it before anything else: `launched: false` when no whole intent exists, because a command
starts only after its intent is synced, and `launched: "unknown"` for an intent without a result. A
crash during that reopening can leave a run of quarantine entries, which the next reopening
completes. The wait for a command whose effect is unknown comes from every capture with an intent
and no result, quarantined or not, so a reopening lost before or during its wait leaves the same
wait to the next one. Any other incomplete entry, a gap, an unknown name, a link, an extra file or
other stream bytes refuse the reopening.

## Broker

A broker directory holds `admission.json` and `manifest.json`, both written once, the ledger, and
the generations' diagnostics. Creating it syncs the directory that holds its name, and every opening
syncs that directory and the broker's own again before anything relies on the durable history, so a
barrier an interrupted creation or an earlier failed sync never reached is never skipped.

- **Admission.** The installation, component, coordinator, trust policy digest, source manifest
  digest, the digest of the bridge's configuration file, the device serial, the native target scope,
  the guest staging directory, the fences and the limits. Version 2, for a guest, adds the lab
  actions with their limits, the crossings the broker may launch and the deployment store (see A
  guest's admission below); version 1 admits no lab action and every crossing. Version 3 is the next
  campaign profile's (see The next campaign profile below). A HELLO must repeat the installation,
  coordinator, configuration digest, component and trust policy exactly. Every request must carry
  the admitted manifest digest.
- **Sources.** Opening verifies every file the manifest lists, each a regular file reached without a
  link, with its exact digest and size. Any difference refuses the opening.
- **Shell protocol v2.** Before its first guest command, each broker reads the device's features
  through the server, as a recorded capture. A definite answer without `shell_v2` latches a stop. An
  answer that cannot be read launches nothing, and is asked again before the next command.
- **Fences.** Before every guest command, reads and the feature query included, right before its
  intent: the stop latch, the stop file, the lease file's token and the runtime deadline. A tripped
  fence is latched in the ledger with its reason. From then on every request that needs the guest is
  answered STOPPED, HELLO included, in this broker and every later one on the same ledger. A command
  already running finishes within its own bound.
- **Groups.** Each reader call is one group: its captures, its raw digest and the facts it gave are
  recorded together. A read whose remote completion was not observed whole raises Unavailable, so a
  transport failure never reaches a parser as an exit status. Every fact must be of the reader's
  kinds, of the admitted installation and route, of the right component scope, of the round's boot,
  and carry its group's raw digest. The uptime and the framework instance never go back within a
  boot. A group of another boot ends the observation.
- **Target scope.** The admission states whether the native target scope was positively established
  empty. The scope is read again at HELLO and at every crossing's gate (WRITE's before its staging
  pushes and before each member), except the abandon of the ticket's own exact session, which needs
  no empty scope. On a guest, the reader's admitted target reader reads Package Manager's native
  identity diagnostic as the broker's own recorded group (`lab_target.py`): only the selected
  image's exact fresh form, with the native store missing and no hold, reads ESTABLISHED_EMPTY, and
  anything else, a failed read included, reads UNKNOWN, never HELD. The read only narrows the
  admission: an admitted scope that is not established empty stands. On the host, a test may instead
  inject a callable. Unless the scope is established empty, no crossing but that abandon is
  launched.
- **Sources.** Before every crossing the admitted sources are verified again. A difference latches a
  stop.
- **Lab actions.** The one lab action is the framework restart, `am restart`, which the controller
  asks for between generations with a reason, never a generation. It is refused unless the admission
  names it, while a generation is open, after a stop, without a reason, and once the admitted number
  of restart commands has been asked (each capture intent counts, launched or not). After its BEGIN
  record the broker reads the clock and the session listing as its own groups, never given to a
  coordinator: unless the listing is whole (one LISTING fact of a complete classification) and of
  the clock's running framework instance, and no session of the component is VERIFYING, READY or
  LIVE_NOT_READY, so that no session committed or of unknown commitment could activate, it records
  the refusal and launches nothing. The command's exit proves nothing: Android returns at once and
  brings system_server back later. So after the command's capture the broker polls, every 5 seconds
  within one hard bound of 300, each poll a clock group and, when that clock shows a later instance
  of the same boot, a session listing group, until one poll shows the same boot, a larger framework
  instance than its precondition read and a whole listing of that instance. A poll command is
  admitted only with at least one second of the bound left, then may run on what is left of it; the
  bound is also its launch deadline, refused after its durable intent and again by the transport
  right before the service request; the transport is given only what the bound has left at the call;
  sleeps are cut to the time left; and a poll that ends after the bound settles nothing. The END
  record names the precondition's instance, the polls and the settling poll; a poll of another boot,
  or no such poll within the bound, ends the action refused.
- **Controller reads and diagnostics.** Between generations the controller may also ask reader
  groups (clock, boot, checkpoint, factory, active, sessions and, when admitted, the target),
  recorded as the broker's own groups, and one fixed diagnostic, `logcat -b all -d`, captured like
  any command with its own output bound. Both are fenced, and neither runs during a generation.
- **A guest's admission.** Version 2 names the device crossings the broker may launch at all: any
  other crossing is answered NO_REPLY with nothing launched, whatever the fault schedule holds, and
  a fault cell that needs a launch on such a crossing is refused at admission (a loss before the
  effect needs none). It also names the deployment store: before each crossing the broker reopens
  the ticket and plan records the crossing names, which must hash to the digests it carries, and its
  grant and the component's selection, keeps each under its SHA-256 in the broker's records, and
  names them in the crossing record. A record is written whole to a fresh temporary name, synced,
  read back, renamed into place and read again, with the broker root and the records directory
  synced each time, and again whenever a name is found already there, so a sync an earlier call
  could not finish is never skipped. A crossing whose records cannot be kept or differ launches
  nothing and consumes no fault cell.

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

A HOST BEGIN is recorded before the bridge calls the host signer or publisher, and its END after,
each with the broker's own wall and monotonic times as it handles them: they bracket the host
effect, and say nothing of when the bridge sent its request. A second BEGIN or END for one ledger
entry is refused. A generation that ends during a host call has its call recorded as ended with its
process, so a later generation's query never runs while the old call could still complete. That a
command was not launched is recorded for the closure only. It never becomes an observation, so it
can never serve as proof that the guest has no session.

A notice route has `allowed(command)` and `notice(run, ticket, index, plan)`. It runs its fixed
commands through the broker's `run`, which fences, records and returns each whole shell result, and
classifies its own exact forms as SUCCESS, REFUSED or UNRECOGNIZED. A SUCCESS says that the fixture
accepted the request, never that a user saw the notice: receipts come from later observation.

## The next campaign profile

A version 3 admission names the profile `d5-next-vehicle-1`. It keeps version 2's base, launch set
and store, and replaces version 2's action map with exactly these keys: the SHA-256 of the cells,
fixtures, payloads and fault schedule it binds, the ordered typed action specs, the F0 branches,
the effect limits and the boot policy. Every key is exact and every digest nonzero; an unknown key,
version or profile refuses the admission. Its bridge configuration is version 3, which names the
same profile, and its generations speak protocol version 2. The broker retains the stored records
every crossing names, as under version 2.

- **Effect limits.** Separate caps of each device crossing's effects, of direct, admin, fixture and
  control action effects, and of each phase's action effects. Zero forbids; nothing is unlimited.
  Effects are counted from the ledger's captures that may have launched, an interrupted intent
  included, never from replies or END records, and a reopening never resets them. A crossing past
  its cap, or a REBOOT past the boot policy's activation services, launches nothing.
- **Compound groups.** A receipt read, a notice visibility, a health baseline and a health
  composition are each one compound group. Its children, every capture and clock read, are in the
  ledger first; then its manifest, a canonical side record (`lab_evidence.py`) with its schema,
  profile, a fresh group ID, the sources, its context, its captures by number and stream digests,
  its bracket, its projection, its facts without their raw digest and whether it emits them or only
  keeps them, as a probe that ended after its window does, is written whole, synced and kept under
  `compound/<sha256>`; then the ledger group names the manifest and the digests of the frames it
  emits. An emitted fact's raw digest is the manifest's. A manifest whose group record never
  followed is an honest prefix and emits nothing; a group whose status is not facts keeps its
  children and reason and emits nothing. A manifest, or an action's spec, that cannot be written or
  synced latches the broker's stop before anything else is recorded: then the group is kept
  unavailable with the reason, and no later command or effect starts, after a reopening too. A
  reopening opens every manifest a group names, and refuses one that is missing, changed or not in
  its canonical form, or that its group does not summarize: its scope, context, status, children,
  bracket and joins, its captures as the ledger holds them, and whether and what the group emitted,
  which only the manifest decides. In this profile only the compound writer makes a group of these
  four readers, and it names no manifest only in its own record of one it could not keep:
  unavailable, with that reason, emitting nothing. Any other such group without a manifest, its
  reference null or absent, refuses the reopening.
- **Notices.** A NOTICE crossing under the lab operator's ACTIVATE, and only that, reads a whole
  typed user inventory and records a `notice-issue` before any presentation: the retained ticket
  and grant digests, the boot, the entry's time, a fresh unpredictable challenge, the exact text and
  its SHA-256, and the required recipients, every running full secondary user. A running user of
  another type or with a removing, partial or precreated marker, an inventory that is not whole,
  or no recipient launches nothing. The notice adapter then presents the issue with its fixed
  commands, each within the grant's launch deadline. Its reply proves no delivery.
- **Receipts past the clock guard.** A ticket's observation reads the notice fixture's provider
  whole between two clock reads of one boot and one running framework instance. A row becomes a
  RECEIPT_EVENT only when it names an issued notice of this ticket, plan, installation and
  component, the issue's boot token, event and text, a required recipient, once in the read, with
  the bytes it had when first read, and when that recipient's first qualified visibility group of
  this boot completed before the read ended. Its time is that visibility's completion, the first
  proven delivery: never the row's candidate time, never the read's time, and never moved by a later
  visibility. The notice entry's time must not follow it. Only the read's bracket moves the clock
  scale, so the event never lowers or advances it, and ordinary facts keep their guard. A row of
  another ticket, purpose or boot, or one without a qualified visibility yet, is kept and gives
  nothing. A contrary row refuses the whole read, wherever it stands, and judgment goes on past it.
  So every row of a whole read keeps its first bytes, whether or not the read emits: a refused
  read, or one whose bracket did not complete, still pins them. A reopening rebuilds the issues,
  visibilities, first row bytes and first proofs from the ledger.
- **Health compositions.** In a ticket's observation in HEALTH_WINDOW, for each user that
  observation's whole listing shows running, the broker composes one full probe only when that user
  has a fresh settled preparation. It reads the ticket's window and the plan's window length from
  the store's own records (`lab_records.py`), never from a request, and refuses a ticket outside a
  window of every criterion or of another boot. The admitted composer reads afresh between two clock
  reads and names, for each of the seven criteria, its status, reason, the reads it judged and the
  preparation or baseline it used. The broker only ever lowers a row to UNKNOWN: a HELD or BAD row
  needs the current reads it judged; the no crash or ANR row needs an admitted witness reader, and
  HELD needs the last good baseline that completed by the window's start in the read's framework
  instance and no witness decision, BAD a qualified witness; the UI marker, unlock and native work
  rows need a preparation of that criterion in the read's framework instance that began in the
  window, ended before the read and is within its maximum probe width. A preparation serves one
  probe: the probe's begin bracket names every preparation offered to its composer, and from then on
  they are used up, whatever its reads, rows or manifest give; a reopening restores that use from
  the bracket. A row whose reason no side record can hold is of no known form. The classification
  follows the rows. A probe that ends after the window is kept as evidence outside it and emits
  nothing. A missing, partial or unreadable composition keeps its captures and reason and emits
  nothing; an UNKNOWN row gives INCONCLUSIVE, never HELD.
- **Health baselines.** `health_baseline` reads one user's baseline between generations, for a user
  a whole inventory shows running and unmarked, as a compound group that is never a deployment
  fact. An unavailable read is kept and never replaces the last good baseline.
- **Typed lab actions** (`lab_actions.py`). Each spec has exactly its ID, registered type, phase,
  cell, runtime, installation, authority, user selector, typed parameters, pinned inputs, its type's
  preconditions, predecessor, successors, uses, timeout and output bounds. Authority is the type's
  LAB_USER_ADMIN or LAB_CONTROL; no installation grant or ACTIVATE is one. A selector is the
  observed system user, the user one named create action made, or a required recipient of an
  issued notice; it names no user itself. `run_action` runs one use between generations. It refuses
  before recording anything outside the admission, during a generation, without a reason, with
  another request than its type's, after a fence, past its uses, after an unsettled use unless the
  type is an idempotent capture and read, or before its predecessor settled. It keeps the spec's
  exact bytes by digest, reads a whole typed inventory and resolves the user from it; a user that
  does not resolve is refused with that inventory kept and no use consumed. The BEGIN record pins
  the spec digest, authority, resolved user with its inventory group, inputs, predecessor
  checkpoint, phase, cell and, for a preparation, a fresh challenge, before any precondition or
  effect. Every command is the type's or its admitted adapter's fixed form, fenced, within the
  action's deadline and output bounds, and each effect command first checks the effect limits. The
  END record names only its own captures, its later reads, its outcome, what stayed uncertain and
  whether it settled. After an effect that may have launched, a use settles only with a qualified
  outcome and its whole bracket: an unrecognized form, or a later read that is unavailable, leaves
  it uncertain, so it is observed or halted, never repeated. A reopening records a LOST END for a
  BEGIN without one, and that action is never run again to find out.

Version 1 of the registry has three types. FRAMEWORK_RESTART is version 2's restart as one typed
use; the old action map is never reinterpreted. NOTICE_VISIBILITY captures and reads one required
recipient's display through the notice adapter; it qualifies only in the notice's boot with one
running framework through its bracket, for the recipient as the display's current user, awake and
focused, showing the issue's challenge. HEALTH_PREPARATION runs the health adapter's UI, user and
work steps for its criteria under a fresh challenge. No type creates a user yet, so no spec may
select a created user.

## Lab driver

The driver decides no ticket: the accepted reconciler does, inside each generation, and the broker
owns every guest command. `init` writes the store with the factory choice at revision 0 and the
bridge's version 2 configuration, whose last line names the lab host configuration's SHA-256, before
the broker's admission binds that configuration's digest; the admission so binds the host
configuration as well. The first generation is the cohort check of the guest as it is. A check
generation that ends COMPLETE does not by itself establish T0. T0 is the boot of the clock read of
the driver's last generation, when that generation was a check whose own reads, as the broker's
ledger records them, all returned facts of that boot, including a completed boot, a checkpoint
state, the factory copy and the active copy, and the selection then records that boot as checked.
Any later generation ends T0. `plan` makes the immutable plan from T0's own facts while T0 stands.
It is refused when the store holds facts of any other boot, since nothing in the records orders
boots and wall time is informational; when T0's facts are missing, disagree, or show a pending
checkpoint or a data copy; and when the selection is not the factory choice found current. The
signing inputs' entry digests and version codes come from the input APKs themselves. The plan
carries the design's starting values: late commit, report and wait, all users, a 15 minute health
window, 2 minute notice delays, request limit 3, a 5 minute reboot timeout, a 24 hour ACTIVATE
window and a 10 minute verification wait, with the boot limit the driver gives. Its lab operator
grants are SIGN for both inputs, STAGE and ACTIVATE; each later attempt gets a fresh STAGE.

The driver rounds a ticket one generation at a time until its PUBLISH has run, reads the plan's
publication back through the artifact store, and pins the published variant's two members for the
broker's WRITE before any later round can need them; then it settles. While the plan has no
publication at all, for instance after a PUBLISH lost before its effect, it keeps rounding, and the
coordinator publishes again. A publication that is there but mismatched or unreadable, or any failed
export, stops the driver before another round, so no session is created without pinned members. A
deliberately halted generation is followed by a new one on the same store, which continues by
observation; a generation that failed, was stopped or killed, or was lost stops the driver.

`LabHost` signs with the development platform key that public Android source trees carry, for a
disposable lab guest only, through apksig without v1. Its configuration names every file it uses
with its SHA-256, and a generation is given the configuration and its digest, which the admission
pins. It refuses a host configuration that the bridge configuration does not name, and a configured
SDK range other than the inputs' declared range. Its approval callback allows a key operation only
for a transaction of the store's installation and component, of an admitted plan, for the configured
role and SDK range, within the transaction's declared operations.

The design's loss cells run as one ordered sequence of attempts on one plan (`cells.py`). First the
cohort refusal: right after a complete check, `contradict` makes a second plan as `plan` does, its
cohort's factory copy changed by one digit, and its ticket must close VOID with cause VOID_BASE
before any crossing. Then each attempt: the store must hold exactly the plan's earlier attempts,
each terminal (attempt 1 is the plan's own first ticket, still PLANNED), as `tickets` lists them;
the broker admits the attempt's faults before its first generation; `ticket` makes the attempt's
ticket, with a fresh SIGN grant for both inputs when nothing is published yet and the attempt must
sign again; and the driver advances it until it is terminal. When a generation leaves the ticket's
state, flags, crossings and session unchanged in SESSION_INTENT, COMMIT_INTENT or ABANDON_INTENT,
the driver asks the broker's framework restart only if that generation's own last reads show a wait
a later framework instance resolves: a clock reading, a COMMITTED checkpoint, and one whole listing
of the clock's instance with no session committed or of unknown commitment. A pending checkpoint, an
unavailable read or a committed session is another wait, and the driver waits instead. After a
restart the next generation's own clock reads must show the later instance the broker's settle wait
found, of the same boot, and it must read the checkpoint again, or the driver stops. The attempt's
records are then compared with its prediction: the ticket's end, cause and crossings from the store,
and from the broker's ledger since the attempt began the native commands launched, the host calls
whose END records a reply, the restarts asked and each admitted fault's action. These are launch and
request counts; the closure judges the effects. Any difference stops the driver. After `init`, every
generation, `plan` and `ticket` the driver also keeps a numbered snapshot of the store's records
with their SHA-256, since the store replaces a ticket's record with its successor.

## Reader adapter

`lab_readers.py` defines what the broker calls. A reader has an allowlist of fixed read only
commands and returns observation facts in the form that the shell observer and the runner's
independent encoder use. `ObserverAdapter` adapts the public shell observer through its documented
names only. Its checkpoint reader is injected: the public one is `ShellObserver.checkpoint`, which
reads the checkpoint through StorageManager with the fixed helper. Until a checkpoint reader is
injected, no CHECKPOINT fact exists, and the reconciler issues no crossing. The adapter
reads no framework only from pidof's quiet failure, read twice. The observer's partial health probe
and any receipt reader are not exposed. The next profile's readers, the typed inventory, the notice
fixture's provider rows, the health baseline and the health composer, and its notice and health
adapters, are interfaces here; the simulated guest implements them for host tests, and the guest's
forms are later packages. `ObserverAdapter` admits none of them.

## Running the checks

```sh
python3 -B -m unittest discover -s tests/component-lab -p 'test_*.py'
```

These are host checks only. They use a simulated guest and a fake adb server, so they qualify no
guest form, Android behavior, power loss or activation.

The driver suite needs the pinned apksigner jar, a directory with the public `platform.pk8` and
`platform.x509.pem`, and a directory with the built `built-A.apk` and `built-R.apk`. The lab runner
takes them as `--apksig-jar`, `--platform-keys` and `--signing-inputs`, checks the jar by its
digest, builds the deployment package, the bridge, the apksig engine and the driver against it, and
runs the driver suite and its defects. Without them the driver phase is NOT_RUN and the run is
partial.

## Limits

- The shell v2, reboot and push forms are source derived, and need a guest check before mutation.
- No refusal form of any crossing is qualified, so no reply reads REFUSED.
- No guest notice route, receipt reader, visibility capture, inventory parser, health composer,
  preparation step or crash witness exists here. The next profile's mechanisms join, order and bound
  what such readers return, on the simulated guest only. Whether a notice is visible on a locked or
  unlocked display, an app row survives Android loss, a provider read authenticates the shell, the
  elapsed scales agree, a preparation unlocks and returns CE, a native child runs and a witness
  qualifies a crash needs a guest.
- The read and round loss addresses and the round boundary messages are not part of version 2 yet:
  no broker path answers an OBSERVE with HALT.
- The framework restart is source derived. Whether `am restart` gives a later instance in the same
  boot within the settle bound and keeps uncommitted sessions, as the simulated guest does, needs a
  guest check before any cell relies on it; the 300 second bound is a proposal, not a measurement.
  The cell sequence's predictions come from the design's cell table and hold on the simulated guest;
  no Android form is qualified by them.
- The native target scope's fresh form is the one captured on the selected producer image. It
  establishes nothing on another image, and no guest of this package has read it yet.
- A process crash is not power loss, and directory times are not durability evidence.
