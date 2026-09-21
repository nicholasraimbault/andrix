# Android accounts with integrated Unix environments

Status: multiple accounts are part of the accepted
[vision](../docs/vision.md), not a product restriction to one human. Existing Unix
qualification is limited to the primary Android user; this plan is not a multiuser pass.

## Contract and ownership

A person may maintain many accounts, or several people may use separate accounts. Build
on full Android users, with an integrated Unix login identity, home, processes, jobs and
preferences for each. Android remains responsible for actual user lifecycle and credential
storage authority. Do not create a disconnected account database that disagrees with it.

Accounts are not automatically administrators. Device signing, system administration and
permission to elevate are separate grants. The OS and baseline `/usr` may be shared;
private data and account work are not. System component changes can affect every account.
Android also shares installed package code in ways that differ from private application
data, so do not promise arbitrary independent versions of one package for every user.

## Required design

- Map Unix names, UIDs and groups to Android user identity without collisions with app or
  platform identities. A different HOME path under the same credentials is not isolation.
- Establish appropriate MAC contexts, descriptor/socket authorization and user binding
  for services. IDs alone remain metadata, not authentication.
- Associate each home and admission epoch with that user's genuine CE authority. UI state,
  readable files and retained descriptors are not substitutes.
- Define create, login, switch, end session and account removal. Switching accounts is not
  automatically Stop; ending a user session or actual CE withdrawal has different effects.
- Define background account resource and lifecycle policy. Many stored accounts do not
  imply unlimited simultaneously running users or workloads.
- Keep owner software/data separate from shared OS package state and expose administration
  effects clearly. No dedicated agent account architecture is needed for this workstream.

## Proposed controls

Exercise two or more full users with independent Unix processes and homes. Verify actual
credentials, MAC, cgroups, API authorization and descriptor ownership. Attempt cross-account
file access, work control and reference replay, with live positive controls for each user.

Test switching without equating it to CE loss, explicit user stop, credential storage
withdrawal/regrant, background resource handling and account removal with work still owned.
An old account or work reference must not gain authority over a new account/instance. Check
shared OS update behavior separately from private data retention.

Retain user0 proofs with their original scope. Choose account creation and CLI/UI mechanisms
after source review; this plan does not yet select a `useradd` implementation, database or
new public API. The [authority plan](2026-09-21-owner-authority.md) owns elevation and the
[installer plan](2026-09-21-rolling-composition.md) owns initial setup choices.
