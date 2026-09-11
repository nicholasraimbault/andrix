# Finite lab UI queue

`ui_queue.py` is an operator-side file-protocol client, not a production Android
control interface. Use it only with a ready, owned, private runtime and its matching
finite UI consumer. It submits one action, waits for the matching completed result,
and only then publishes the next action. A failed/mismatched/missing result stops
that batch; an unresolved prior action blocks a new batch. Concurrent clients are
excluded by a nonblocking file lock. The consumer must publish results atomically.

```sh
python3 -B scripts/proof/ui_queue.py --runtime /private/runtime \
    --actions /private/actions.json --timeout 180
```

Keep runtime paths, actions, PINs, captures and results outside public Git. The
caller selects and authorizes the actions; a JSON result is not itself proof that a
shell command or Android workload passed. Inspect actual output and appropriate
positive/negative controls. After an input timeout, the remote Android input process
may still be injecting events: **do not automatically retry, press Enter or submit
another batch**. Inspect/settle or stop the window before an explicit recovery.

`text_actions()` produces printable ASCII chunks of at most 60 characters, without
an implicit Enter. It rejects Android input percent escapes, newlines and untested
non-ASCII input. This is a bounded test route, not an IME/Unicode compatibility claim.

`terminal_input_ready()` examines a real UI hierarchy for the attached status and
an enabled, focused terminal view. Use that observation before sending terminal
input instead of assuming that a fixed delay after Attach was sufficient. It does
not attest keyguard state or native-shell readiness and grants no Android authority.
Native eligibility, controller lifetime, CE checks and the PTY boundary are unchanged.

In the [native project trial](../../plans/2026-09-11-owner-project-input.md), the
predicate accepted actual eligible Android views and blocked both cold first-Attach
failures. No following command/key action was submitted after either failed readiness
step. Explicit retries worked; this did not fix or hide the underlying resize failure.
