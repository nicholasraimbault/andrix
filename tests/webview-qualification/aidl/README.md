# Pinned public SafeMode contract

`org/chromium/android_webview/common/services/ISafeModeService.aidl` is copied
unchanged from the pinned Chromium152 provider source. SHA-256:
`881975244f5e77d7f3184484b78cd2f4c5cbe2931e69887c2172e16c68c66abc`.
The original notice and exact upstream BSD license are retained. This is not all
Andrix Apache-2.0 code. The AIDL compiler supplies its descriptor/transactions;
there is no replacement service or hand-written Binder protocol.

The included `SafeModeContract.java` is the typed adapter emitted by the explicit
`prepare_contract.py` maintenance helper. Refresh only against reviewed upstream
source; the helper neither downloads inputs nor silently replaces different
existing files. Its synthetic parser tests are not an Android Binder result.
