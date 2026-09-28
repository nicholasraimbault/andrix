# Optional lab preparation for V2 header only recovery

This directory prepares a later lab qualification of B2 header only recovery. It holds a lab
only framework adaptation, a controlled input generator and predictor, and a host rehearsal.
Nothing here applies Android source, builds an image or runs a device. Production stays
`Format.V1`. Native execution, the native factory and V2 publication stay off in every image.
See the [plan](../../../plans/2026-09-28-native-header-recovery-lab.md) for the stages and limits.

## Lab format adaptation

`native-store-format-v2.patch` changes one byte of the exact adapted B2 `Settings.java`: the
literal `NativeIdentityStore.Format.V1` of the boot store construction in
`readNativeIdentityStoreForBoot` becomes `Format.V2`. It adds no file, path, boolean, property,
setting, `valueOf`, `values`, reflection or other selector. Its profile pins the pinned upstream
Settings, the exact adapted input, the lab output, the patch, the writer profile and helper, and
the fixture's subject, signer, version and user. It records `lab_only`,
`native_execution_enabled` false, `format` V2 and `production_format` V1.

The profile and patch stay here, outside `patches/`. That location is not a bypass. The
unchanged production format guard scans `patches/` and refuses a copy of this patch there, and
the shared framework fence detects the applied lab state in any checkout and refuses it without
explicit lab history admission.

`scripts/proof/native_lab_format.py` validates the current normal native profile with every
source hash it requires, but pins only its Settings rows. A correction that changes only the
store keeps this adaptation admissible. A changed adapted Settings refuses it until the patch is
regenerated and reviewed.

## Composition order

Apply in this order, each with its own tool and evidence:

1. The normal companions: owner lifecycle CE, package verity, Package Installer payload sync and
   native principal pins.
2. The existing writer fixture, with `native_identity_writer.py --lab-test-only`.
3. This format, with `native_lab_format.py --lab-history-format --action apply --require-lab`.

Reverse this format first, while every companion is still complete, then the writer fixture,
then the native and payload companions. The CE and package verity companions keep their accepted
state. Every normal tool refuses while the format is present.

The shared fence reports the Settings file and the native companion as `LAB_FORMAT_V2`, never
`ADAPTED`. One decision admits that state, and only through
`android_lifecycle.inspect_lab_native_format`, over the complete lab stack: every other native
file exactly adapted, the exact adapted writer fixture, the owner lifecycle CE companion adapted,
and package verity with its payload sync companion adapted. The same stack is required for every
inspection, check, apply and revert, not only for a build. Unknown bytes and partial states always
refuse. If a companion becomes partial while the format is present, no tool proceeds and there is
no force option. Recovery is a reviewed manual repair of the checkout. Every action needs
`--lab-history-format` and a fresh unsealed evidence path outside the source tree and the
repository.

The tools do not detect a live build producer. Retiring the producer scope, and capturing it
empty, before any apply or revert is the caller's precondition, as is the admission of any
effects. Known upstream and adapted bytes never load the lab files. When the lab derivation is
unavailable, unknown Settings bytes refuse as before.

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
publication and the generation 1 body. The subject and signer are the fixture's fixed values. The
lineage, app ID and user 0 serial come from the lab's own records and are validated by
`lab_history_observe.prediction_arguments`. Output must be a fresh normalized absolute path whose
existing parent is a real directory. Existing, aliased or partial output, unknown modes and
invalid identifiers refuse with explicit checks, also without Java assertions. There is no
PackageSetting, UID allocation, user data, key file, initializer or publication here, and the
output is lab input or prediction only.

## Host rehearsal

`NativeWriterLabRehearsal.java` drives the unchanged `NativePrincipalWriterFixture`, the real
manager and store and the host PMS facades with `Format.V2`:

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
development signer from the profile.

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

`scripts/proof/native_lab_history.py` is the guarded qualification runner. Its predictions are
in `scripts/proof/native_lab_history_predictions.json`.

The complete host run also requires `ANDRIX_SOURCE_ROOT` to name the pinned Android source
checkout. This supplies the existing Package Installer derivation controls. Any skipped required
suite case makes qualification fail; a zero test process exit alone is insufficient. The
checkout is read only input to these tests, not authority to apply a companion.
