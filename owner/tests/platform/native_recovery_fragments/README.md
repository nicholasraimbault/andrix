# Native recovery boot fragments

These Apache 2.0 fragments are extracted verbatim from the guarded adapted Android framework
sources. The source profile hashes them, and the patch guard requires each fragment to occur
exactly once in its corresponding adapted file.

`NativeRecoveryBootTest.java.in` supplies small host facades around these actual statements. It
checks cleanup ordering, code retention versus identity attribution, install marker ownership,
refused deletion, malformed paths and binding capacity. This is not a full PMS or Android boot
fixture. The original framework files retain their upstream copyright and license notices.
