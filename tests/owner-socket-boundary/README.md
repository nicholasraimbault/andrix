# Ordinary-app owner-socket boundary probe

This is an optional same-signer **different-identity** APK, not a product package.
It declares no permissions or shared UID. Its native code first creates and connects
to a fresh socket in the APK's own cache directory, including a checked two-way byte
exchange and peer identity. It cleans only that newly created private fixture.

The external control attempts a nonblocking connection to an explicitly supplied
owner tmux socket path. It sends/reads no payload on that connection and closes it
immediately. Unexpected connection success is a failure, not a denial or a claim of
strict non-mutation. ENOENT, ECONNREFUSED and helper errors are not permission passes.
The socket path must come from actual owner-terminal output, with the tmux server
and socket held live and owner-client positives immediately before/after the test.

Run normal instrumentation with `socket_path` pointing to the observed
`/data/misc_ce/0/andrix/.tmp/tmux-7500/<name>`. The result deliberately says
`DENIAL_OBSERVED_REQUIRE_LIVE_OWNER_SOCKET_CONTROLS`; it cannot establish external
liveness by itself. Different-UID DAC and SELinux policy controls remain distinct.
GrapheneOS's implicit PM permission metadata is not a measured runtime-grant claim.

The host test exercises actual fresh named-socket connect/roundtrip and cleanup,
plus a missing-path control. It is not an Android SELinux or coordinator-role test.
