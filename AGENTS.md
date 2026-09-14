# Andrix

Andrix aims to make Android a general-purpose mobile computer with an
owner-controlled Unix environment.

## Values

- The phone serves and is controlled by its owner.
- The owner can program, extend and change the system.
- Preserve what makes it a phone; reject restrictions that exist to preserve
  vendor control.
- Build clear, coherent and maintainable systems grounded in observed reality.

## Project context

Start repository work with [current work](plans/current.md). Read its linked
milestone when relevant.

Consult the [accepted architecture](docs/architecture.md) for work that changes
or depends on the system design. Changes to the project values or accepted
architecture require an explicit project decision. Design alternatives remain
proposals until adopted.

If a task needs private local paths or access context, consult
`dev/operator-current.md` when present. That ignored file supplies operating
context; public work state and recorded evidence establish project claims.

## Engineering standard

Build for a coherent, maintainable, long-term owner-controlled OS, not merely a
passing demonstration. Use bounded proofs to discover real requirements and failure
modes. A successful prototype establishes evidence, not a permanent architecture.

After a proof, review the design before building further dependencies on it. Separate
essential contracts from incidental prototype choices; assess ownership, interfaces,
lifecycle, recovery, update compatibility and resource policy. Retain, refactor or
replace the implementation according to that review. A clean replacement is appropriate
when it produces the better design; do not preserve awkward coupling because work was
already spent on it, or rewrite sound code merely for a fresh start. Prefer the simplest
coherent design that meets the requirements, not the easiest workaround or the most
elaborate abstraction.

Carry verified requirements, behavioral tests and negative cases forward. Do not pin
implementation accidents as permanent contracts or transfer an old implementation's
qualification to its replacement. Re-run relevant regression and runtime proofs on
the resulting design, preserve prior evidence, and make changes to accepted requirements
explicit rather than weakening them to obtain a pass.

## Public documentation boundary

Public Git holds product architecture, source provenance, reusable build/test
instructions, and concise milestone outcomes with their limitations.

Keep machine inventory, local access paths, process IDs, live job/lease state,
execution transcripts, raw receipts, and cross-project coordination in ignored
operator records or private evidence. Do not turn public milestones into an
operational diary. Preserve detailed failures privately; publish the reusable
technical lesson when it affects the product or its tooling.
