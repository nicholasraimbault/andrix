<!-- SPDX-License-Identifier: Apache-2.0 -->

# Native Accounts host facade tests

These are **test only** inputs. The 20 controlled `facades/` Java files and two
`tests/` Java files adapt the independently reviewed host fixture. The two
production files are **not copied here**. The runner compiles the current
`owner/platform/java/dev/andrix/server/OwnerNativeAccountQuery.java` and
`owner/terminal/src/dev/andrix/terminal/NativeAccountController.java` directly,
with exactly those 22 test inputs. The AIDL sources are recorded as shape
references only, not generated or compiled. `NativePrincipalManager` is an inert
capture facade, not the real manager, PMS projection, store, lock or factory
metadata resolver. Binder caller identity, package and user records, exact
current signer *tokens*, service registration, scheduling and text view are
controlled facts. Tokens do not verify certificates. No test code enters an
Android build.

Run this JVM gate **explicitly**, from the repository root. Use an external
supervisor that starts this Python command as the leader of a dedicated owned
process group, monitors it and retires that **whole group** on any stop.
Running it ungrouped in a shell is refused. Choose a fresh absolute output
directory below scratch storage that you own, outside the checkout, and supply
an explicit read only JDK and measured binary digests. The supervisor's
payload is:

```sh
python3 -B owner/tests/native-accounts-host/run.py \
  --output "$OWN/fresh-native-accounts-run" --jdk "$JDK" \
  --javac-sha256 "$JAVAC_SHA256" --java-sha256 "$JAVA_SHA256"
```

No JDK or PATH fallback exists. A missing or existing output, a noncanonical
path, an unexpected input or a wrong JDK digest refuses the run. The caller
must separately admit and monitor its local storage, resource and runtime
conditions. Those conditions are not Native Accounts test requirements or
arguments to this public runner. Leave failed outputs intact; use a fresh
name for a separately admitted run, not a silent retry. The runner saves
SHA256 values of all 24 explicit Java inputs, the three AIDL shape references,
the runner, both JDK binaries, generated classes, exact commands, child process
IDs and groups, direct waits, stdout, stderr and a finite `RESULT.json`. It
uses explicit empty class and source paths, no jars,
`--release 17 -Xlint:all -Werror -proc:none`, and `-ea`. An owned empty input
file opened read only gives the child stdin EOF, rather than opening a generic
device for read and write. JDK children **inherit the supervised group**;
they never create detached sessions. The runner directly waits for each known
child and can signal that child by PID. The external supervisor retires the
whole group, including any surviving descendants, on success or failure. One
100 second TERM, 101 second KILL and 103 second deadline covers the entire
invocation, not three successive deadlines. HOME, tmp and JVM error output
are confined to the output directory; perf and attach are disabled.

The endpoint asserts at least 46 authentication and response cases. The
controller asserts at least 21 scheduling and rendering cases, including
release and test only shutdown of its blocked worker. This is a bounded
**host facade** test. It does not qualify real PMS, signing provenance,
Android AIDL generation, Binder driver and kernel, SELinux, Android builds,
DEX, a device, native activation or a main branch merge. Header and path
changes alter class hashes. Do not identify new class outputs with old host
packet class hashes or reclassify older source only results.

For a source only guard that **never invokes javac or the JVM**, use
`python3 -B -m unittest scripts.proof.tests.test_native_accounts_host_runner`.
This guard is safe to include in normal pure source test selections. The JVM
entry point is not called by that test or by an import.
