# Optional lab preparation for V2 header only recovery

This directory prepared the lab qualification of B2 header only recovery. It holds a controlled
input generator and predictor, and a host rehearsal. Nothing here applies Android source, builds
an image or runs a device. Native execution, the native factory and V2 publication stay off in
every image. See the [plan](../../../plans/2026-09-28-native-header-recovery-lab.md) for the
stages and limits. The separately admitted Android stages that used this preparation have since
completed; the plan records their scoped results.

## Retired lab format token

The lab image changed one byte of the exact adapted B2 `Settings.java`: the literal
`NativeIdentityStore.Format.V1` of the boot store construction became `Format.V2`. Its own
profile, patch and tool kept that token apart from every normal image. Since the
[version 2 normal store](../../../plans/2026-10-02-native-store-v2-normal.md) step, the normal
native patch constructs `Format.V2` itself, and its adapted Settings equals that lab output byte
for byte. The token's tool, tests, profile and patch were removed. They stay in Git history and in
the sealed records of the `23cede6` lab build. A later lab image gets a new reviewed vehicle.

## Composition order

Apply in this order, each with its own tool and evidence:

1. The normal companions: owner lifecycle CE, package verity, Package Installer payload sync and
   native principal pins.
2. The existing writer fixture, with `native_identity_writer.py --lab-test-only`.

The shared framework fence admits the writer fixture under lab admission only over the complete
stack: the native principal companion, the owner lifecycle CE companion, and package verity with
its payload sync companion, each exactly adapted. It accepts the fixture exactly upstream or
exactly adapted, so a partial fixture refuses every inspection, check, apply and revert. The writer
tool also requires the fixture exactly upstream before an apply and exactly adapted before a
revert, so a repeated apply or revert refuses. There is no force option; recovery from a partial
state is a reviewed manual repair of the checkout. Reverse the writer fixture first, while every
companion is still complete, then the native and payload companions. The CE and package verity
companions keep their accepted state. Every normal tool refuses while the fixture is present.

The tools do not detect a live build producer. Retiring the producer scope, and capturing it
empty, before any apply or revert is the caller's precondition, as is the admission of any
effects.

## Controlled input and predictions

`LabHistoryStore.java` uses only the actual `NativeIdentityRecords` codec:

```text
LabHistoryStore empty-v1 OUTPUT
LabHistoryStore predict-v2 OUTPUT LINEAGE APP_ID USER_SERIAL 1
```

`empty-v1` writes one empty version 1 header pair and an empty `slots` directory with a fresh
random lineage. Its bytes equal what the store's own initialization writes for that lineage.
`predict-v2` writes three predicted records and a manifest, in files that are not a store layout:
the V2 CREATING header with the complete binding of principal ID 1, the LIVE header after
publication and the generation 1 body. The subject and signer are the fixture's fixed values; the
runner compares them, and the observer's, with values parsed from the pinned writer fixture. The
lineage, app ID and user 0 serial come from the lab's own records and are validated by
`lab_history_observe.prediction_arguments`. Output must be a fresh normalized absolute path whose
existing parent is a real directory. Existing, aliased or partial output, unknown modes and
invalid identifiers refuse with explicit checks, also without Java assertions. There is no
PackageSetting, UID allocation, user data, key file, initializer or publication here, and the
output is lab input or prediction only.

## Host rehearsal

`NativeWriterLabRehearsal.java` drives the unchanged `NativePrincipalWriterFixture`, the real
manager and store and the host PMS facades with `Format.V2`, the production format of the boot
read, which the runner ties to the native patch's boot literal:

- A fresh generated empty V1 store, then `info`, `select-new` and `prepare`, which captures ID 1,
  the facade app ID, user serial and signer.
- The slot root changes from 0700 to 0500. Real unprivileged read and search remain, and the
  process has no DAC override. The first commit returns false with the original handle kept.
  The store holds exactly the complete V2 CREATING header, counter 1, and no body, slot
  directory, seed, backup or extra file.
- No commit retry before the modeled cold restart. The restart restores PENDING from the header,
  and a new fixture instance refuses the old one. The original slot root mode returns while the
  fixture is idle. `select-rebind` and `prepare` keep the same ID, record and handle, and the
  commit writes the generation 1 body and the LIVE header under counter 1. A cold reopening
  restores the body PENDING with the original ID.
- Controls: a lost commit reply with status reconciliation, error, exception and observation
  wrapper faults after the actual writer returned, retained nonces and intents, no select-new
  fallback or initializer after the restart, and a changed APK signer that cannot rebind.

The rehearsal's facade installs the existing fixture tests' synthetic certificate, the bytes 1, 2
and 3, with the digest `039058c6`. It is not the fixture's development signer `874cedf4`, and a
host result says nothing about the Android subject's certificate. `LabHistoryStore.predict` accepts
the rehearsal's signer set for this host check, while the command line always predicts with the
development signer of the pinned writer fixture.

Its transcript carries the actual replies, and an issued ledger line for the deliberately lost
commit, to the observers. Its byte copies of the store are byte oracles only. They carry no modes,
owners or labels, and no hash of them proves durability. Modes are observed separately on the live
store: 0700 after generation, 0500 for the fault, the same mode after the modeled restart, and
0700 again once restored. It is a host facade rehearsal, not the Android proof.

## Observers

`../lab_history_observe.py` adds the header only false commit arm beside the unchanged positive
`writer_observe.assess_commit`. It requires the recorded select-new intent, the original
instance, nonce and selected identity, one acknowledged prepare and exactly one completed commit
attempt that returned false, a fresh PENDING observation and no historical positive commit
acknowledgement. The issued ledger kind decides between the direct reply and explicit status
reconciliation. It never infers that nothing happened or that no reservation exists. An
exception, a missing reply or a stale observation can only be retained as UNKNOWN on purpose, in
an envelope keyed to the issued ledger record. That envelope keeps the issued commit whether no
reply, an unavailable reply, an unparseable reply or a foreign reply arrives. It trusts fields only
from a reply in the issued scope. The envelope fingerprints the supplied reply and stderr text
encoded as strict UTF-8; it retains neither. Before assessment, the caller retains the raw stdout
and stderr with the issued ledger. Fingerprints match only after strict UTF-8 decoding without
newline translation. It never invents an acknowledgement or authorizes a retry. Store snapshots are compared separately and exactly with
the lab input and predictions.

The runner checks the primary arm's empty, CREATING and LIVE headers, body and predicted files
against an independent layout oracle. Other fault and refusal stores also have the Java codec
assertions. It evaluates that oracle at the fixed golden values, at a fresh command line lineage with the development signer, and
at the rehearsal's actual lineage, app ID and serial with the independently computed host test
signer. The oracle is test only; the actual codec alone produces lab input and predictions. The
runner starts every compiler and JVM with its working directory inside its work directory, a
heap of at most 256 MiB, fatal error and replay logs kept there and no core requested, and it refuses any host
facade stub overlap except the reviewed `android/util/Log.java`.

`scripts/proof/native_lab_history.py` is the guarded qualification runner. Its phases are the JDK
check, the generator controls, the rehearsal, the legacy version 1 writer regression and the pure
suites. Its predictions are in `scripts/proof/native_lab_history_predictions.json`. The pinned
rebuild of the native outputs is the B1 runner's `--verify-candidate`.

The complete host run also requires `ANDRIX_SOURCE_ROOT` to name the pinned Android source
checkout. This supplies the existing Package Installer derivation controls. Any skipped required
suite case makes qualification fail; a zero test process exit alone is insufficient. The
checkout is read only input to these tests, not authority to apply a companion.
