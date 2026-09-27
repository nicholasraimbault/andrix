# Native recovery boot fragments

These Apache 2.0 fragments are extracted verbatim from the guarded adapted Android framework
sources. The source profile hashes them, and the patch guard requires each fragment to occur
exactly once in its corresponding adapted file.

`NativeRecoveryBootTest.java.in` supplies small host facades around these actual statements. It
checks cleanup ordering, code retention versus identity attribution, install marker ownership,
refused deletion, malformed paths, binding capacity and the counter withheld beside unselected
or incompatible header copies. This is not a full PMS or Android boot fixture.
`admission.java.inc` is the exact cached Settings reservation check. The manager host facade contains that method verbatim, and
`NativePreparationAdmissionTest` exercises it against the actual reservation projection with
filesystem I/O forbidden under the PMS monitor. The facade also runs `restore-capacity.java.inc`
verbatim when it restores a reopened registry.
The original framework files retain their upstream copyright and license notices.
