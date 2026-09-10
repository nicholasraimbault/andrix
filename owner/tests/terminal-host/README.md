# Portable terminal-engine test adapters

These files are **host test inputs only**. No Android app/module includes them.
They supply logging, Base64, RGB extraction, annotation types and an inert session
callback type so the unmodified terminal parser tests can run on a host JDK.
Keyboard integer constants are compiled from the pinned Android SDK jar.

They do not implement Binder, identity, permissions, CE state, keyguard, PTYs,
Android Views or an actual terminal session. A host parser PASS is not Android
UI/integration/security proof. The inert `TerminalSession` prevents accidental
linkage of Termux's excluded JNI/process-launching session implementation.
