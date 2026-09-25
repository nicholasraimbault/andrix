# Native package updates without stale shells or unsafe collection

Status: proposed refinement of the [integrated platform model](2026-09-25-integrated-platform-model.md)
after reviewing its costs against conventional Unix behavior. No package store or retention mode
is implemented or qualified by this document, and no production default has been adopted.

## Recommended first candidate

**New commands follow the current selection. Managed packages carry exact dependency closures.
Retention is automatic and conservative. Whole environment pinning is an explicit mode.**

This separates three promises:

- **Selection:** which package a new command finds.
- **Consistency:** which interpreter, libraries, helpers and resources belong to that package or
  explicitly pinned environment.
- **Retention:** how long those exact managed objects remain available.

Changing selection does not have to discard the old objects. Keeping old objects does not freeze
names in the mutable current view or prove every ABI combination is compatible.

A managed package's closure contains its declared internal dependencies. Public command discovery
through PATH can still select a newer external tool, as on Unix. Unmanaged owner programs and
files remain first class. A build requiring a fixed whole environment explicitly pins one.

## Conservative retention without an operation on every exec

Use the store authority's publication sequence as a reclamation watermark:

1. Publish a complete selection and its sequence atomically with the store's reference accounting.
2. At current mode work admission, record the sequence before entry. Creation of this reference
   and collection use the same serialized ownership protocol.
3. Keep exact objects from selections which the scope could have reached during its lifetime.
   In practice, a superseded generation remains held while a live current mode scope predates
   its supersession. Other roots still apply: current selection, pins, recovery material, pending
   builds/plans/publications and explicitly leased environments.
4. Release the scope's hold only on actual retirement, including descendants and late creation.
   Manager loss is not release; unknown or blocked instances retain their obligations.
5. Mark an object retiring before refusing new references and deleting it. A process scan is never
   the deciding authority.

This needs no command interception, extra exec, mount service or lease IPC for every child command.
A program may close all its ordinary descriptors without losing its scope's retention.

**The storage cost remains real:** an old current mode shell can hold every changed package object
since that shell's admission. Content sharing avoids duplicate unchanged bytes, but does not remove
this churn. It is a simpler representation of conservative retention, not perfect knowledge of use.

### Keep long lived fixed services out of the watermark

Enabled services are already version pinned in the accepted architecture. Give their own execution
environment exact leases rather than making them retain every future interactive update. Pinned
build environments work the same way.

Interactive work submitted through such a service must have its own declared current or pinned
mode and correct reference transfer; it must not accidentally inherit an old service environment.
An ordinary unmodified long lived tmux scope can still hold back churn. Show that cost rather than
pretending the refinement eliminates it.

## Coverage and limits

- Unmodified fork/exec and inherited references **within the same captured scope** are covered by
  that scope's retention window.
- A new command through current gets the current selection. Its managed internal closure remains
  exact where the package/linker contract supports it.
- A current alias may disappear or point elsewhere after an explicit package change. Retaining
  an old exact object does not preserve that alias forever.
- Whole environment pinning adds stronger cross-command consistency. It does not roll back
  mutable user data.
- A reference passed into a newer scope may predate its retention window. Submission must carry
  the required older bound or exact lease. Later transfers require an explicit owned transfer
  to claim the stronger guarantee. An arbitrary path string or directory FD is not enough.
- Managed closure construction, interpreter behavior, RUNPATH, later dlopen and Android namespace
  behavior need qualification. Updating a library does not magically update a binary whose
  selected closure still names the old library; the resolver must publish a compatible new closure.

Low space refuses or defers new publication before violating live retention. The owner sees which
scopes or pins retain space and can end obsolete work or change policy deliberately. Normal
collection never evicts a live lease merely with a warning.

## More precise retention is an optimization to earn

A narrower managed execution path could acquire a lease for only the selected package closure
before exec. A small dispatcher could preserve argv/environment and leave no resident process.
The lease would last for the captured work scope, not only the initial process.

That can reduce retained storage to closures actually selected by live work, rather than all
intervening updates. It adds an exec and IPC dependency to managed commands, plus scope
 authentication, lost reply handling and compatibility work. An inherited channel can be passed
between scopes, so it is not scope identity by itself. Missing authority or capacity must refuse
or defer a protected launch, not silently execute without the promised lease.

A safely authenticated principal instance lease can be a coarser fallback where the exact work is
unknown. It protects only the closures it holds and may retain them longer; it is not equivalent
to a watermark over every intervening selection. Direct store paths, undeclared dynamic discovery
and cross-scope transfers still need honest contracts. None of these qualifications may restrict
ordinary unmanaged execution by accident.

Test this as an explicit managed path only if the simpler baseline's measured holdback is material.
Do not make the store authority a new fragile dependency of every shell command just to save a
few old copies.

### Why not images or kernel interception first?

Stock read only closure images and nonlazy unmount checks can provide authoritative retention for
actual open/mapped references. They do not retain an arbitrary cached path that will be opened
later. Scripts whose interpreters live elsewhere and delayed dependencies need additional roots.
Images also introduce packaging/deduplication, mount/loop resources, protected mount operations,
namespace behavior and CE backing file retirement obligations.

They may earn their place for coarse authenticated package sets, where integrity and activation
already justify them. They are not the default answer to native package collection. Per exec
ptrace/seccomp/fanotify style interception similarly needs a stronger reason than hypothetical
storage savings, and target kernel availability cannot be assumed.

## Deciding measurements

1. Measure conservative retention under actual update cadence and long lived interactive work,
   with pinned scopes excluded. Report changed retained bytes and their real holders, not a
   guessed compression or sharing ratio.
2. Prove admission/publication/collection ordering and retained uncertainty through manager and
   store restart. Exercise descendants and references crossing scopes.
3. Test exact managed closure behavior with scripts, interpreters, helper execs, plugins and late
   dlopen. Distinguish current name changes from deletion of retained exact objects.
4. If needed, compare dispatcher latency and savings on the same sessions, including many small
   commands, closed inherited descriptors, unavailable authority and capacity exhaustion.
5. Keep the simpler design if the extra precision does not justify its latency, failure and
   maintenance costs.

This is a practical middle path: conventional command selection, stronger declared package
consistency, automatic retention and optional reproducibility. It reduces daily friction and
avoids new machinery on every exec, but does not claim zero storage cost or perfect prediction
of future program behavior.
