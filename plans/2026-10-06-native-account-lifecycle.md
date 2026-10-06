# Native account lifecycle authority

Status: accepted by the owner on 2026-10-06. It sets who may create, suspend, retire and delete a
native account and when its UID may be released. Nothing is implemented or enabled by this
decision. Retirement and identity recovery, journey 6 of the
[integrated platform model](2026-09-25-integrated-platform-model.md), are designed next under it.

## Decision

A native account is the Unix identity that native programs run under inside one Android user,
held by Package Manager's native identity store. The owner accepted this policy:

- **Creation.** Each Android user's normal Unix login comes with that user, during trusted setup
  or full user creation. That user creates any further native accounts, confirming with their own
  credential. No app or installation creates one.
- **Administration grant.** Acting on another user's native accounts requires an explicit native
  account administration grant. The phone's owner normally holds it and may delegate it, limited in
  scope. It does not follow from being the first user, from Android user administration, from
  signing or from installation authority.
- **Suspension.** The account's user, or the grant holder for any user, may suspend an account.
  Suspension is one reversible state that stops the account's work and keeps its UID, data and
  keys. Only equal or greater authority lifts it, and the record keeps who suspended it and why.
- **Retirement.** The account's user with their credential, or the grant holder with
  authentication, may retire an account. Retirement deletes nothing and releases nothing.
- **Data deletion.** Deleting a retired account's data is a separate, explicit step by its own
  user. Across users, only the grant holder may do it, with a destructive confirmation. It is never
  automatic and never a side effect of installing or repairing a package. Ordinary file deletion
  inside a live account is unaffected.
- **UID release.** A UID is released only after the account's data is deleted or migrated and
  everything that acted under the account is confirmed retired. Release stays off until it is
  qualified. A later account never inherits an earlier account's identity or grants, even if it
  receives the same number.
- **Android user removal.** Removing an Android user authorizes disposing of its native accounts,
  with unfinished obligations kept on record.
- **Recovery.** An independent route handles lost credentials and damaged records. Restored
  records stay inactive until someone with authority activates them.
- **Other authorities.** Installation authority, signing and Android user administration grant
  none of this on their own.

## Consequences under the accepted architecture

These follow from the decision and the [accepted architecture](../docs/architecture.md). They are
requirements on the design, not further choices.

- Stopping work is irreversible for that work instance, so resuming a suspended account restores
  its eligibility, not the stopped work. Suspension does not undo effects already accepted.
- One account's retirement or deletion must not release anything another account or Android user
  still depends on. A carrier package shared across users has one app ID for all of them.
- Unfinished obligations of a removed Android user stay bound to that user's serial, so they cannot
  reach a later user that receives the same user ID.
- A restored record must match its stored prior owner and signer lineage, as the
  [reservation component](../owner/platform/principal-pins.md) already requires, and is never
  filled in from whatever package is installed now.

## Reasons

- The architecture gives each [full Android user](../docs/architecture.md#accounts) an integrated
  Unix login and keeps ordinary accounts separate from administrative capabilities. Its
  [authorized device administrator](../docs/architecture.md#administrative-elevation) is not
  automatic authority over every account, so power across users is a grant of its own. Android
  likewise lets a secondary user delete itself while the owner can remove any user.
- Linux's `useradd` can give a removed account's number to a new account, which then owns the files
  left behind. Holding the number while anything depends on it prevents that without permanently
  consuming Android's 10,000 shared app IDs. It matches the release conditions the
  [integrated platform model](2026-09-25-integrated-platform-model.md#durable-native-identity)
  proposes and the final phases the reservation component already models.
- As with `userdel`, which keeps the home directory unless asked, removing an account and deleting
  its data stay separate. Linux's password lock leaves running programs and other ways in, so here
  suspension is a single state that stops the account's work.

An independent review shaped this revision. It rejected a first draft that never released UIDs,
asked for the explicit administration grant and setup creation of the normal login, and found the
suspension, user removal, recovery and shared carrier cases recorded above.

## What this leaves open

- Prompts, credential types, and how the grant is held, delegated and revoked belong to the
  [authority design](2026-09-21-owner-authority.md).
- The retirement protocol, its completion evidence, what suspension closes beyond running work,
  and qualified release are the next design work.
- Protection against an actively malicious platform administrator is not promised, and
  administrative access does not supply a locked account's credential encrypted keys.
