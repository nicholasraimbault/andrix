# Terminal source and portable parser proof

```sh
python3 -B scripts/proof/terminal_libraries.py \
  --android-jar "$GRAPHENEOS_ROOT/prebuilts/sdk/current/public/android.jar" \
  --junit-jar "$GRAPHENEOS_ROOT/prebuilts/devtools/tools/lib/junit-4.12.jar" \
  --jdk-bin "$GRAPHENEOS_ROOT/prebuilts/jdk/jdk25/linux-x86/bin" \
  --evidence-dir "$NEW_EXTERNAL_EVIDENCE"
```

The helper validates the checked-in manifest digest, all 42 selected upstream
Git blobs/SHA-256 hashes and licensing inputs. It rejects source changes, self-
rewritten manifests, symlink substitutions, extra files and an imported Termux
process launcher. Updating the pin or adapting upstream code requires a reviewed
provenance change, not editing hashes merely to get a PASS.

The SDK and JUnit inputs are pinned by digest to the inspected GrapheneOS anchor.
The unmodified parser's tests run on a host JDK with the explicit utility adapters
under `owner/tests/terminal-host` and the real Andrix process-free session adapter.
No Termux JNI/process session or Android authority is supplied. These helpers are
not an Android view, identity, CE, lifecycle or input-permission mock.

Additional tests feed the actual terminal parser through the new output cursor:
fragmented UTF-8/escape sequences, duplicate frames/title callbacks and gaps.
`OperatingSystemControlTest.disabledTestSetClipboard` remains disabled upstream
and is not counted as an exercised test. Android clipboard policy still needs the
real Andrix adapter and runtime check; automatic escape requests must not be
mistaken for explicit user copy/paste.

`PASS_PORTABLE_TERMINAL_ENGINE_AND_REPLAY` means these portable tests passed.
It does **not** mean the Android view/IME/authority boundary is qualified or that
`vi`/a compiler has been exercised in the new terminal. Those are subsequent [owner-tools gates](../../plans/2026-09-10-owner-tools.md).

The regular host suite separately compiles/runs the C++ journal/frame encoder and
Java decoder/cursor, including real Unix-socket replacement and a cross-language
wire fixture. Both g++ and a JDK must be on PATH; absent tools fail rather than
quietly claiming the new cross-language check passed.
