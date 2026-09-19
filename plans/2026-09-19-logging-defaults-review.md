# Logging defaults, privacy and online source review

Status: the owner endorsed the proposed direction and requested online research. This
review supports the separation and privacy principles, with the qualifications below.
Exact retention values, the event catalogue and implementation remain unqualified. No
runtime logging, Android policy or export setting changes follow from this document.

The discussion refined the earlier [work result retention choice](2026-09-19-work-result-retention.md).
Live supervision, security records, optional work history and output capture are distinct.
Durable records describe observed facts; they are not execution or restart permission.
This is a personal owner controlled computer, not an enterprise compliance profile.

## Proposed defaults under review

| Capability | Direction |
| --- | --- |
| Live work state and current results | Required in memory for safe control and rediscovery |
| Security and supervisor failure records | Minimal, protected, local recording enabled |
| Persistent work activity history | Disabled by default, available through an explicit owner choice |
| Persistent terminal/output capture | Disabled unless explicitly saved or redirected |
| Raw command arguments, environments and sensitive contents | No automatic collection |
| Debug verbosity | Disabled by default |
| Remote forwarding or encrypted archive export | Disabled until explicitly configured |

Owner control of persistence must not let arbitrary applications or log producers
change the policy. Disabling history does not disable live ownership or Stop. An owner
who disables security record persistence also accepts reduced investigation coverage;
that mode must not be advertised as a mandatory audit or compliance facility.

## Inspected sources

Public sources were checked on 2026-09-19. They support principles and identify failure
cases, not a qualification of Andrix code or a universal numerical retention policy.
The proposed defaults are our application of those principles to the owner's goals,
not a matrix prescribed by any of these sources.

- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html):
  event selection, excluded sensitive data, configurable logging, collection, verification,
  protection and disposal. This is application security guidance, often in an organizational
  context. It also warns against disabling logging needed for compliance.
- [Android log information disclosure guidance](https://developer.android.com/privacy-and-security/risks/log-info-disclosure):
  avoiding sensitive and unpredictable production log contents, restricting debug logging,
  and avoiding leakage through the shared `logcat` buffer. Its app/R8 examples are not
  implementation instructions for the native Andrix manager.
- [AOSP file based encryption](https://source.android.com/docs/security/features/encryption/file-based)
  and [Android Direct Boot](https://developer.android.com/privacy-and-security/direct-boot):
  the CE/DE distinction, preference for CE where possible, and CE remaining available
  after ordinary screen relock.
- [Linux fscrypt threat model](https://docs.kernel.org/filesystems/fscrypt.html#threat-model):
  access control remains necessary while keys are in use. Storage encryption does not
  generally protect accessible plaintext against full system compromise. Key removal
  and cache eviction have explicit limitations.
- [systemd journal configuration](https://www.freedesktop.org/software/systemd/man/latest/journald.conf.html):
  separate volatile/persistent storage, per service rate limits and suppression messages,
  size/retention controls, synchronization intervals, and a documented blocking hazard
  from synchronous forwarding. These are implementation examples, not adopted defaults.
- [NCSC logging and monitoring](https://www.ncsc.gov.uk/collection/10-steps/logging-and-monitoring):
  proportionate collection, availability for later investigation, tamper protection and
  testing. It recommends at least six months for important organizational logs because
  incidents may be discovered months later. That is not a personal phone mandate.
- [NIST SP 800-92](https://csrc.nist.gov/pubs/sp/800/92/final), especially sections 2.3 and 4.2:
  confidentiality, integrity and availability of logs, choosing retention from objectives
  and resources, and not adopting example values unchanged. This is a 2006 enterprise
  guide. It is used here for those principles, not its historical protocol or algorithm
  recommendations.
- [Android Auto Backup](https://developer.android.com/identity/data/autobackup):
  many app files are included by default, explicit exclusions exist, and cloud backup
  settings do not necessarily govern every device transfer. This describes app data,
  not automatic backup of Andrix's native storage tree.

## Assessment and required refinements

### 1. Minimal collection is well supported, but must still be useful

OWASP calls for proportionate event selection and warns that indiscriminate collection
can hide important events in noise. Android specifically recommends predictable log
contents and avoiding sensitive information, including accidental disclosure in errors.

Use a documented set of event types and approved fields. Prefer event/error codes and
necessary authenticated context over formatting entire requests, exception objects,
arguments, environments or output. Validate field types and lengths, and encode them
correctly. Filtering secrets out after writing them is not equivalent to avoiding their
collection. Hashing a sensitive value is not automatically sufficient anonymization.

Minimal must not mean only failures. Successful security relevant grant, revocation and
policy changes matter too. OWASP explicitly includes authentication successes and higher
risk administration. Map this to Andrix's actual authority operations, not every routine
owner program launch. The event selection should apply consistently to relevant events
from trusted callers as well as untrusted ones.

A minimal default is not comprehensive endpoint monitoring. Malicious behavior using
otherwise authorized ordinary computation may leave no distinguishing Andrix security
record. Richer owner enabled diagnostics can improve investigation at a privacy cost.

### 2. Seven days and 1 MiB are not validated product defaults

The proposed figures were a candidate budget for recent local diagnostics, not a result
of measurements or a standard recommendation. NCSC's longer organizational recommendation
shows why a week of local records must not be described as complete incident history.
NIST explicitly says example configuration values must be adapted to the actual purpose.

A size cap can shorten the time covered dramatically. As illustrative arithmetic only,
1 MiB holds 4,096 records of 256 bytes before other overhead. Ten such records per second
fill that space in under seven minutes. This is not an Andrix workload measurement.

Before selecting product values, measure normal and hostile event rates, encoded record
sizes, storage overhead and phone impact. Separate retention purposes if needed: recent
local diagnostics versus longer owner selected investigation history. Expose the actual
coverage window, overflow/suppression counts and unavailable periods. A nominal age limit
is not a guarantee that all events from that period remain available.

### 3. Flood resistance needs more than rotation

OWASP requires testing that logs cannot exhaust resources. Journald demonstrates per
service limiting and reporting of suppressed messages, rather than silent unlimited
collection.

Bound ingress, record size, queued writes, memory and storage. Apply fair limits so one
noisy producer or repeated denial cannot displace all important records. Preserve a
bounded indication of lost data and logging health. Consider separate capacity for
critical policy changes and repetitive failures, then verify it under an actual flood.
No rate limiter can honestly claim complete capture while dropping records.

### 4. Logging failure must remain outside execution control

OWASP explicitly requires logging failures not to prevent the application from otherwise
running. Journald's documentation gives a concrete counterexample: a hung synchronous
forwarding target can block the logger and then services writing to it.

History I/O must not hold registry, admission or Stop locks. A blocked writer retains its
bounded obligation instead of spawning unlimited replacements. Stop and genuine CE
withdrawal must proceed independently. Report storage failure and uncertainty rather
than claiming a durable result. A request explicitly requiring a durable receipt may
be refused if persistence is unavailable; ordinary or explicitly nonpersistent execution
must not be silently reclassified as durable.

### 5. CE storage is appropriate, with an explicit coverage gap

AOSP recommends CE storage where possible. Direct Boot documentation explicitly says
ordinary screen relock does not remove access to CE storage. Andrix still obtains genuine
user/CE authority from its platform adapter, not from a readable file or an old descriptor.

While CE is genuinely unavailable, keep at most a bounded memory buffer and report the
coverage limit. Do not introduce a less protected persistent fallback silently. A crash
or reboot before that buffer can be saved can lose those events. This is a deliberate
privacy tradeoff, not complete boot or incident logging.

Close or retire the logger's CE resources promptly when authority is revoked, without
making key withdrawal wait for the logger. The fscrypt limitations and the observed busy
file outcomes prohibit a claim of instantaneous plaintext or key erasure.

### 6. Local protection and external archives have different guarantees

Protect log readers, writers and configuration through actual identity and scoped
interfaces. Live kernel control handles and old work IDs do not become authority merely
because they appear in a saved record.

CE encryption is not protection from a fully compromised OS while the data is accessible.
A local checksum or hash chain alone cannot establish completeness against an attacker
who can rewrite the whole local store. Stronger historical confidentiality or integrity
needs a separately protected key, reference or copy and an explicit threat model.

Encrypted owner selected archives remain a reasonable separate capability, not a solved
cryptographic protocol or part of the default. They do not prevent a compromised source
from suppressing or falsifying subsequent events. No automatic export, remote dependency
or additional wake authority is implied by recording local events.

### 7. No export must cover secondary copies too

Android's production logging guidance warns about the broader shared `logcat` audience.
Do not duplicate sensitive Andrix records into that sink as a convenience. Keep diagnostic
content deliberately limited, and audit owned logging call sites.

Also inspect backups, device transfers, crash/support bundles, temporary files and UI
caches. Android's backup documentation makes this particularly relevant if a companion
app stores copies. It does not establish that the native Andrix store is currently backed
up. Verify the actual product paths and configuration instead of assuming either outcome.

Owner requested deletion should cover the copies Andrix controls and clearly describe
what it cannot remove. Expiry, access revocation, logical deletion and physical erasure
are different claims. No proposed runtime retention rule applies to sealed development
evidence or authoritative producer artifacts.

## Next verification gate

The principles are sound for the stated personal computing scope. The exact event
catalogue, retention numbers and durability promises still require design and tests:

- Secret canaries in argv, environment, output and error paths do not appear in default
  records, shared Android logs or unintended secondary copies controlled by Andrix.
- Untrusted producers cannot read, modify, disable or forge protected recording controls.
- Floods, malformed data and encoding boundaries do not exhaust resources or hide gaps.
- Full/read-only storage, missing permissions, writer crash or blocked I/O leave Stop and
  unrelated supervision responsive and retain honest outstanding obligations.
- Genuine CE withdrawal, normal relock, reboot and interrupted writes preserve their
  distinct meanings, without silently writing to a weaker storage class.
- History disabled produces no equivalent durable activity collection elsewhere in
  Andrix. Owner configured exports and retention behave as declared.
- Explicit durable receipts survive the tested failures before the API promises them.

This review is source research. It adds no host concurrency, Android runtime, battery,
power loss or phone qualification.
