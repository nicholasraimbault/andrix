# SPDX-License-Identifier: Apache-2.0
"""The native target scope as the lab broker reads it: Package Manager's native identity diagnostic,
read as the shell user on the selected producer image.

The scope is ESTABLISHED_EMPTY only when one whole read of the diagnostic exits 0 with no error
output and exactly the fresh form below: the form that three captures of a fresh guest of the
selected image show unchanged before installs, after installs and after a reboot, with the native
store missing, its counter unknown and no hold. Any other reply, including a well formed one with
other values or another schema, reads UNKNOWN, which stops every crossing but the abandon of the
ticket's own session. This reader never reports HELD: a hold is not established by a form it does
not know, and HELD would void a ticket.

The form is the selected image's. Another image needs its own captured form, never this one."""

COMMAND = 'dumpsys package --andrix-native-identities'

FRESH_FORM = ('andrix-native-identities-v1\n'
              'live_settings=true\n'
              'authority=not-reported\n'
              'counter_known=false\n'
              'cached_header=MISSING\n'
              'cached_enumeration_complete=false\n'
              'creation_ready=false\n'
              'allocator_search_start=10000\n'
              'unidentified_code=false\n')
FRESH_FORM_SHA256 = '8fa8f35d202d86bc73ce1d61aef481c9eabacf22b121ea1332d3efa9febefabb'


def scope(code, stdout, stderr):
    """The scope one whole read shows: ESTABLISHED_EMPTY for the exact fresh form, else UNKNOWN."""
    return 'ESTABLISHED_EMPTY' if (code, stdout, stderr) == (0, FRESH_FORM, '') else 'UNKNOWN'
