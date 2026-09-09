# Connected-service policy: attestation provisioning

**Read-only findings; owner clarified the networking policy on 2026-09-09.**
The [accepted architecture](architecture.md) now prohibits automatic direct
connections from official Andrix components to Google-operated services, while
allowing provider-side Google backends and the owner's explicit use of Google
products. This resolves the earlier policy question about indirect provisioning;
it is not a connected-runtime pass or an implementation change.

## What the pinned client does

Reference: GrapheneOS `2026081300`, frameworks/base
`aab06a8bd44c4c2b58eeec780fde83baa9d43a40`, RemoteKeyProvisioning
`069767f2d1960ae3c6eb4d253cbb8c5b659c01fb`.

- `RemoteKeyProvisioningSettings` defaults to
  `https://remoteprovisioning.grapheneos.org/v1`. In `Settings.getUrl`, this
  override takes precedence over the stored URL and the
  `remote_provisioning.hostname` property. A hostname-property dump alone therefore
  does not establish the effective endpoint, and blanking that property is not a
  reviewed solution.
- `BootReceiver` schedules a daily provisioning-pool job with connected-network,
  charging and battery-not-low constraints. This is not solely an operation
  explicitly initiated by a user app; runtime execution still depends on its
  conditions and key-pool state.
- `ServerInterface.fetchGeek` requires validated network connectivity and the
  network-consent check, then POSTs `CborUtils.buildProvisioningInfo` to
  `:fetchEekChain`. The CBOR includes the OS build fingerprint, RKPD package
  version, a rollout identifier, and the default hostname when set.
- That identifier is a stored random rollout bucket below 1,000,000, **not proof of
  a globally unique hardware identifier**. The request also gets a fresh UUID in
  its URL; do not conflate those two identifiers.
- `SystemInterface.generateCsr` calls the genuine KeyMint remote-provisioning HAL.
  Older and newer HAL paths differ; both add unverified device information with
  the build fingerprint. Newer optional flags can add reset reporting or feedback;
  their actual Pixel behavior has not been qualified here.
- `Provisioner.batchProvision` passes the CSR to
  `ServerInterface.requestSignedCertificates`, which POSTs the supplied bytes to
  `:signCertificates`. The client documentation describes MACed public keys and
  protected device data. Changing the hostname is not removing this payload.
- `NetworkUtils.assumeNetworkConsent` normally returns true outside the special
  China-GMS feature path. The error mentioning GMSCore must not be read as a general
  requirement to install Google Play before provisioning can occur.

The public [GrapheneOS FAQ](https://grapheneos.org/faq#default-connections) explicitly
identifies its endpoint as a private reverse proxy to
`https://remoteprovisioning.googleapis.com/`. It describes privacy improvements,
including per-app attestation keys and the proxy being unable to decrypt provisioned
keys. It also distinguishes a future device with a GrapheneOS attestation root
and its own provisioning service from the existing Google-certified hardware path.

**A privacy-preserving proxy is not the same claim as zero upstream service
dependence or zero device-derived protocol data.** Nor is this a finding that
GrapheneOS secretly embeds Google Play or sends ordinary app contents as telemetry.
The service and protocol purpose need to be described accurately.

## Accepted networking policy

The initial review used the earlier literal requirement: no proprietary Google
service dependence and no direct or forwarded device/user data reaching Google.
The source findings remain valid under that interpretation. The owner subsequently
clarified the intended boundary:

> if the service does it backend its ok. i just dont want andrix to ping google
> unless you literally go to google.com or their other products like youtube.

Accordingly:

- Official Andrix components must not automatically contact Google-operated
  services directly. This includes background checks, telemetry and component
  downloads, not only analytics messages.
- The owner's explicit use of a Google product or service is allowed. This is not
  blanket permission for unrelated background Google connections or incidental
  Google requests from otherwise non-Google activity.
- A non-Google service may process requests using Google on its backend. Such
  forwarding is allowed; it must not be described as zero Google involvement or
  zero data reaching Google.
- Google-dependent app compatibility is not an Andrix release requirement. Local
  owner tools do not need mandatory remote attestation, and there is no adopted
  project to build a replacement certification authority merely for that purpose.

This is an explicit owner decision, not permission inferred from GrapheneOS
adoption. It does not authorize adding telemetry or unrelated data collection.

## Consequences and remaining qualification

| Path | Policy disposition |
| --- | --- |
| Client uses the genuine GrapheneOS provisioning proxy; its backend uses Google | Permitted design candidate. Verify the actual client endpoint and ensure no automatic direct-Google redirect/fallback path. Google remains the provisioning authority. |
| A streaming service uses Google for license processing on its backend | Permitted. The browser/CDM's own direct provisioning, update and license connections remain a separate review. |
| Automatic Silvervine CDM download from `www.google.com` or `edgedl.me.gvt1.com` | Not permitted as an automatic official Andrix path. A non-Google delivery source or offline import would need authenticated inputs and appropriate distribution rights. |
| Owner explicitly visits Google Search or YouTube | Permitted explicit Google-product use. This does not exempt unrelated OS background traffic. |

Genuine Pixel provisioning is a per-device cryptographic protocol, not a static
CT-list mirror. The clarified policy allows retaining an appropriate proxy path;
there is no need to invent replacement keys/certificates simply to remove its
server-side Google relationship. A supported independently provisioned Pixel
replacement and complete proxy/server privacy properties have not been established
and are not prerequisites implied by this clarification.

Before connected qualification:

- Reconcile all relevant client endpoints, redirects and fallbacks with the policy.
  No connected migrated-image qualification is claimed yet.
- Preserve genuine attestation and local hardware security; do not forge success,
  spoof identity/certificates or globally disable services to manufacture a quiet
  capture. Whether a consumer works must be reported honestly.
- Establish real guest connectivity and service behavior with bounded captures and
  loss accounting. A Google-IP denylist or offline silence is not a semantic policy
  proof, nor does a non-Google hostname alone establish the service's operator.
- Do not accept vendor terms, change production keys, deploy a replacement service
  or touch the handset without the relevant explicit authority.

## Evidence limits

These are exact client-source observations plus a separately fetched live official
FAQ. No RKP request was sent for this review. No Pixel HAL CSR, server-side
processing, packet/body capture or flag-dependent feedback behavior was observed.
The earlier offline guest cannot prove any connected privacy property. A cancelled
worker delivered no substantive review; primary inspected the recorded sources.

This is the first focused item in the broader connected-policy review. Updater/app
catalog trust, CT/revocation delivery, DNS/time/connectivity, geolocation and actual
carrier/eSIM paths still need their own scoped checks.
