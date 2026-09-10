# Portable terminal-engine test adapters

These files are **host test inputs only**. No Android app/module includes them.
They supply logging, Base64, RGB extraction and annotation types so the unmodified
terminal parser tests can run on a host JDK. Keyboard integer constants are compiled
from the pinned Android SDK jar.

The real process-free Andrix session adapter is compiled alongside these helpers;
its clipboard separation, input encoding and dimensions are tested here. There is
no replacement/mock session type and no Termux JNI/process launcher.

These adapters do not implement Binder, identity, permissions, CE state, keyguard,
PTYs or Android Views. A host parser/adapter PASS is not Android UI/integration/
security proof; those require the actual platform and emulator checks.
