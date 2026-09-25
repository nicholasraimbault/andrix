# Terminal parser diagnostics stay out of shared logging

Status: implementation with host regression coverage. The Android module build and device
logging checks have separate status below. This repairs the existing minimal recording policy;
it does not introduce a new recording default or alter the work lifetime contract.

## Defect and correction

The [decision audit](2026-09-25-deliberate-decision-audit.md#f1-the-terminal-adapter-can-leak-parser-payloads-into-logging)
found that the first party session adapter passed a null `TerminalSessionClient` to the pinned
terminal parser. The parser's `Logger` then fell back to Android Log. Several malformed termcap
and clipboard escape branches include their input in diagnostics even when key logging is off.

The adapter now supplies an explicit client which discards these parser diagnostics. They are
untrusted terminal content, not protected authority events. No payload string, exception or hash
is sent to the shared log through that client. Other callbacks keep the old null client behavior;
`TerminalOutput` and `applyOutput` still own presentation. Cursor style retains its default.
Explicit user clipboard operations remain separate from automatic escape requests.

The 42 pinned upstream source files remain byte identical. This correction belongs at Andrix's
owned integration boundary, not in a silently edited import or a platform logging exemption.

## Verification

The actual adapter and parser run in the JVM tests with the existing Android logging facade.
Each malformed odd termcap, invalid hexadecimal termcap, unknown decoded termcap name and invalid
Base64 OSC52 case has a
matching control which deliberately restores the old null client route and observes a dummy
canary at the logging sink. The normal adapter refuses that logging route, including fragmented
byte delivery. A thousand event diagnostic flood emits no shared log contents. Rendering,
cursor defaults and automatic versus explicit clipboard behavior remain checked.

The regression was run before the production correction: 156 tests ran, with the two new privacy
tests failing. With the correction, all 156 passed. These are real parser/adapter executions,
not an Android logd observation or a complete terminal privacy certification.

An earlier runner attempt failed to compile because its broad protocol glob included newer
AIDL dependent work classes. That failed attempt remains separate. The parser runner now names
its actual portable `InputQueue` and `OutputProtocol` dependencies. Work reference/tracker tests
retain their own scope; this change does not substitute host AIDL mocks for Android behavior.

## Remaining boundary

The correction does not claim that every Android log producer, IME, accessibility service,
clipboard consumer, task snapshot or support bundle is private. Those are distinct authorized
crossings and qualification surfaces. It also does not change the legacy Console lifetime or
its shared control executor. Android artifact/runtime observations must refer to the corrected
producer rather than inheriting an older fixture's result.
