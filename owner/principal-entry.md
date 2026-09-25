# Ordinary principal launch integration

Status: initial implementation, not selected by a product and not qualified on Android.
The owner authorized disposable development of the
[native integration direction](../plans/2026-09-24-native-runtime-integration.md), not a
production account representation or a general credential setter.

This is launch code, not a new diagnostic application. It extends the existing work runtime
rather than assigning Unix job lifetime to an Android isolated service. API bindings and the
platform account authority remain separate work.

## Implemented boundary

The first implementation uses one protected manager per principal, already running under that
principal's ordinary UID. The platform must establish its whole credential and resource profile
once, before starting the manager. Individual launches do not change UID, GID or groups and do
not execute an owner chosen program as root. The manager and ordinary programs share Unix
authority, while distinct MAC roles protect the manager's control machinery.

- `principal_profile` validates, encodes and seals immutable principal data separately from the
  ordinary executable, arguments, environment and directory. It carries a principal incarnation,
  Android user and serial, actual package UID/GID, the complete supplementary group list and
  expected worker context. Empty groups mean none, not inherited groups. No grants or UID
  allocation are stored here. The record is bound to one work identity and authority epoch.
- `WorkRuntime` accepts that optional profile and a captured account home only from trusted
  construction code. Its actual real, effective and saved UID/GID must match the principal.
  The profile is fixed for that manager incarnation. The admission authority must explicitly
  affirm that exact profile; the existing CE only authority refuses principal mode by default.
  Existing admission, captured cgroup,
  independent Stop, creator ownership, uncertainty and result retention continue to apply.
- Private launch protocol version 3 carries two additional descriptor roles for the profile and
  home. Legacy mode carries neither and retains its seven original roles before optional stdio
  closure. This is a private coordinated protocol change, not a new public launch request.
- `andrix-principal-launcher` authenticates the actual parent and channel credentials, checks
  the protected manager role, immutable work/profile binding, all credential values, zero
  capabilities, resource membership and home shape. It selects only the native worker role,
  installs the additional syscall restriction and claims the existing irreversible entry gate.
- The fixed `andrix-principal-entry` receives only ordinary launch data, profile data and the
  home descriptor alongside standard I/O. It verifies the resulting ordinary credentials, MAC,
  NNP and seccomp state, changes to the captured home, and closes all three data descriptors.
  Only then does it apply ordinary directory/environment choices and execute the program.
  There is no package app data or plaintext fallback.

The profile reader checks complete seals before observing size. Sealing proves byte integrity,
not origin, current authority or ownership of an Android policy subject. The private peer and
platform authority must establish those facts. Work identities retain the existing full unsigned
64 bit range, including manager incarnations whose high bit is set.

The new ordinary principal filter permits Binder transport while retaining the architecture and
io_uring restrictions. It refuses reserved, root and isolated UID classes. Android services still
check actual caller permissions; the filter grants none. The legacy reserved UID path continues
to block Binder. Installing another filter cannot relax a filter already inherited.

## Account home and resource limits

A captured home is checked for ownership, the native home MAC role and range, and fscrypt v2.
Its mode and group remain owner controlled. A trusted creator may initialize a private 0700
home, but changing its mode or group is not a new prohibition on starting ordinary work.

The format check does **not** distinguish CE from DE, verify the user's CE key identifier or
establish current key availability. The authoritative account home provider must supply the
correct CE directory. Admission must track the genuine user/CE epoch. A retained descriptor is
not authority and may keep storage references alive until the manager retires. Withdrawal,
process termination, descriptor closure and completed storage eviction remain separate facts.

The new entry currently checks the earlier vehicle's bounded resource class. This is not a
production quota. In particular, `RLIMIT_NPROC` counts threads across the shared real UID,
including managed helpers outside a work cgroup. The new principal path must not be activated
without resolving that coupling and qualifying an appropriate resource class. Cgroup task
controls are a candidate where the platform supports them; no unsupported controller is assumed.

## Activation fences

No product installs these new binaries or supplies their new MAC domains. This cut does not
publish a principal service, mutate package state or broaden the existing lifecycle service.
Before activation, the following must be connected and checked:

1. An authoritative native account designation and UID lifetime contract in Android. Package
   removal, replacement or reuse cannot race surviving native work. A package snapshot followed
   by an asynchronous Stop is not a UID reservation.
2. A trusted platform factory that resolves the real subject, user serial and native role,
   explicitly establishes groups even when empty, clears capabilities and constructs the
   protected manager/resource environment. No caller supplied UID or label becomes authority.
3. A principal aware admission source that revokes the exact manager instance when its binding
   or user/CE authority ends. The old primary-user CE publisher alone is not that source.
   The old UID 7500 endpoint check must not be generalized to trust ordinary worker Binder calls
   from a shared principal UID. Use authenticated manager role/instance authority.
4. Policy for the fixed manager to worker exec, including the required `nnp_transition`, home
   metadata ioctls and ordinary Binder use. Ordinary programs must not enter the manager role,
   access private control sockets, ptrace/signal the manager or write delegated cgroup controls.
   An authenticated public work interface is distinct from those private controls.
5. A complete resource class and UID accounting/presentation contract. There is no fake
   foreground state or UI lifetime owner in this launch implementation.

These are missing platform integrations, not facts established by the profile parser or a
successful host build. No supported native account, phone API binding or production launch is
claimed by this checkpoint.

## Verification

Twenty nine focused host tests passed, including profile round trips/refusals, sealed descriptor
ownership, both filter programs, legacy/private protocol roles, work control and admission
regressions. The real Linux cgroup backend also passed its existing descendant lifetime,
independent Stop, held creation/observation, retirement and EOF controls after the private wire
change. That run used the legacy host bootstrap with supplied authority, not the new Android
principal/MAC path.

Review also found a preexisting immutable launch reader ordering issue. `ReadLaunch` observed
size before checking seals, permitting a writer to resize and seal between those operations.
It now checks seals before final size. A deterministic test uses an actual memfd and an
interleaved writer at the size observation, with a positive control for the interception.
This correction does not retroactively change any historical runtime result.

Both new entries and both legacy entries also compiled as AArch64/Bionic executables against
pinned SDK/platform inputs. These are standalone compilation artifacts, not a full Soong/image
build or a runtime launch qualification.
