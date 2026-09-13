# Multiplexer client-retirement control

`client_hangup.c` creates its own fresh PTY and child, then runs the native
`/usr/bin/tmux -L andrix-proof attach-session -t lab` client. The owner must first
create that live server/session and put the supplied marker on its screen.

After receiving a bounded redraw containing the marker, the probe closes **only its
own PTY master** and waits for that client to exit. It reports the actual wait status,
not an assumed signal/exit code. The result still requires live server/pane identity
and a successful owner-client operation afterward; client exit alone does not prove
the retained workload survived.

Default SIGCHLD and exclusive child reaping are required. On failure, cleanup can
signal only the freshly created client child, never a supplied PID, the independent
server or its panes. Poll/reap loops are bounded; arbitrary uninterruptible kernel
stalls are not a real-time guarantee. A marker/readiness failure or premature child
exit is not a pass.

The host test exercises the actual PTY/hangup/reaping path with an explicit child
exec stub, plus real exec-failure and ignored-SIGCHLD controls. It does **not** execute
native Android tmux or qualify SELinux/keeper behavior. Android qualification must
compile and run the public fixture through the owner terminal and preserve its
observed output and independent live controls.
