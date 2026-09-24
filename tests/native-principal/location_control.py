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


def close_control(xml, package):
    """One observed ordinary fixture button. Never a credential or generic input helper."""
    import xml.etree.ElementTree as ET
    if (not isinstance(xml, str) or len(xml) > 256 * 1024 or '<!DOCTYPE' in xml
            or package not in ['dev.andrix.proof.principal', 'dev.andrix.proof.principalpeer',
                               'dev.andrix.proof.principalclosed']):
        raise ValueError('invalid fixture UI observation')
    tree = ET.fromstring(xml)
    matches = [node for node in tree.iter('node')
               if node.get('package') == package and node.get('text') == 'Close permission UI'
               and node.get('class') == 'android.widget.Button'
               and node.get('enabled') == 'true' and node.get('clickable') == 'true']
    if len(matches) != 1:
        raise ValueError('missing or ambiguous fixture close button')
    match = re.fullmatch(r'\[([0-9]+),([0-9]+)\]\[([0-9]+),([0-9]+)\]', matches[0].get('bounds', ''))
    if match is None:
        raise ValueError('missing close-button geometry')
    left, top, right, bottom = map(int, match.groups())
    if not (0 <= left < right <= 8192 and 0 <= top < bottom <= 8192):
        raise ValueError('invalid close-button geometry')
    return (left + right) // 2, (top + bottom) // 2
