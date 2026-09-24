# SPDX-License-Identifier: Apache-2.0
"""Pure fixture argument construction. Labels are not principal or request authority."""
import re


def location_arguments(action, nonce, duration_ms):
    if action not in ['info', 'watch'] or not isinstance(action, str):
        raise ValueError('unknown location action')
    if not isinstance(nonce, str) or not re.fullmatch(r'[A-Za-z0-9_]{1,64}', nonce):
        raise ValueError('invalid public nonce')
    if type(duration_ms) is not int:
        raise ValueError('duration must be an integer')
    if (action == 'info' and duration_ms != 0) or (action == 'watch' and not 1000 <= duration_ms <= 300000):
        raise ValueError('duration outside fixture bounds')
    return [action, nonce, str(duration_ms)]


def info_nonce(run_tag, command_number):
    if (not isinstance(run_tag, str) or not re.fullmatch(r'[A-Za-z0-9_]{1,24}', run_tag)
            or type(command_number) is not int or not 1 <= command_number <= 999999999):
        raise ValueError('invalid fixture operation label')
    # The readable command label is deliberately not used: labels may contain hyphens.
    nonce = f'{run_tag}_info_{command_number}'
    location_arguments('info', nonce, 0)
    return nonce
