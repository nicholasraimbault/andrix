# SPDX-License-Identifier: Apache-2.0
"""Check supplied Android CE observations. This module supplies no authority."""


def valid_recovery(original, withdrawn, restored):
    """A grant can reuse the new revocation generation, not the original one.

    Callers must obtain these observations from their real trusted platform and
    independently establish the withdrawal and normal credential recovery. This
    comparison is not key availability, key erasure or caller authentication.
    """
    for observation in (original, withdrawn, restored):
        if (not isinstance(observation, dict)
                or type(observation.get('instance')) is not int
                or type(observation.get('generation')) is not int
                or not 0 < observation['instance'] < 2**63
                or not 0 < observation['generation'] < 2**63 - 1
                or type(observation.get('available')) is not bool):
            return False
    return (original['available'] and not withdrawn['available'] and restored['available']
            and original['instance'] == withdrawn['instance'] == restored['instance']
            and original['generation'] < withdrawn['generation'] <= restored['generation'])
