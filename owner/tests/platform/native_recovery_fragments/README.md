# Native recovery boot fragments

These Apache 2.0 fragments are extracted verbatim from the guarded adapted Android framework
sources. The source profile hashes them, and the patch guard requires each fragment to occur
exactly once in its corresponding adapted file.

`NativeRecoveryBootTest.java.in` supplies small host facades around these actual statements. It
checks cleanup ordering, code retention versus identity attribution, install marker ownership,
refused deletion, malformed paths, binding capacity and the counter withheld beside unselected
or incompatible header copies. This is not a full PMS or Android boot fixture.
`admission.java.inc` is the exact cached Settings reservation check, now over a creation plan. The manager host facade contains that method verbatim, and
`NativePreparationAdmissionTest` exercises it against the actual reservation projection with
filesystem I/O forbidden under the PMS monitor. The facade also runs `restore-capacity.java.inc`
verbatim when it restores a reopened registry.

Four history fragments pin the adapted Settings text that reads the store's shared history view:
`restore-history.java.inc` takes the restore inputs from the shared restoration,
`stored-history.java.inc` remembers and returns histories of exact core pins, `scan.java.inc` is
the scan rule, and `recovery-seeding.java.inc` is boot recovery seeding. Seeding defers a mapped
history that is retiring, retired or suspended, as the scan refuses it.

Three lifecycle fragments pin the boot facts. `boot-facts.java.inc` records them once, after
seeding, from the same boot read, and defers the package each one names.
`retired-boot.java.inc` holds the queries that disposition and release take them from, and
`deferral.java.inc` is the deferral of a package name. `observation.java.inc` takes each later
store read into the cached view and the held set without touching the boot facts, and
`release-finish.java.inc` forgets a released account's remembered history while its app ID stays
held until a new Settings instance.

The facade contains every Settings fragment verbatim, and its restore runs restoration,
observation, seeding and the boot facts in the order of the adapted boot method.
`NativeHistoryHarness.java.in` runs one revision's whole boot restoration method, with the
observation, remembering and hold refresh it calls, its recovery seeding, boot facts, retired boot
queries, release finish and scan rule around small facades. The runner fills it with the text
cut from its own candidate Settings.
The original framework files retain their upstream copyright and license notices.
