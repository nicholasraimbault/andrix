# APEX signing keys

Generate payload and container keypairs on the build host. Private keys stay
there and outside Git and communication channels. Public keys may be committed.

The script requires OpenSSL and Android's `avbtool` and preserves existing
keys.

```sh
AVBTOOL=/absolute/path/to/avbtool scripts/gen-apex-keys.sh
```

It writes the AVB payload pair (`.pem`, `.avbpubkey`) and APK container pair
(`.x509.pem`, `.pk8`) under `keys/`.
