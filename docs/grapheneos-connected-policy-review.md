# Connected-service policy: attestation provisioning

**Read-only findings; no policy exception or connected run adopted here.** The
accepted architecture still requires official Andrix images/services to operate
independently of proprietary Google services and send them no device/user data.
This review identifies a consequential release gate rather than silently changing
that requirement or disabling a security consumer.

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

## Decision boundary

For Pixel-first Andrix, genuine attestation provisioning cannot simply be treated
like a static CT-list mirror. It is a per-device cryptographic protocol tied to
hardware trust roots and a provisioning authority. We have not established a
supported independently provisioned Pixel replacement or the complete downstream
privacy properties of the proxy/server implementation.

Before a connected test that could invoke this path, the owner needs to decide
whether the literal zero-Google-service/data requirement remains absolute, or
whether a narrowly documented exception for genuine hardware attestation
provisioning is acceptable. This is an architecture/policy decision, **not permission
already inferred from adopting the GrapheneOS source base**.

Until resolved:

- Keep UI/core work offline and continue source review.
- Do not claim the GrapheneOS proxy satisfies Andrix's current strict requirement.
- Do not forge successful provisioning, spoof identity/certificates, strip required
  attestation consumers, or globally disable services to manufacture a quiet capture.
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
