#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Sequential client for the finite lab UI queue; not an Android authority API."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import time
import xml.etree.ElementTree as ET


def terminal_input_ready(xml):
    """Observe the real unlocked console view, not a guessed startup delay/prompt.

    This is a test-driver readiness predicate. It is not cryptographic keyguard or
    native-shell attestation and must not be used to grant production authority.
    """
    if len(xml) > 1024 * 1024 or '<!DOCTYPE' in xml or '<!ENTITY' in xml:
        raise ValueError('Unbounded/unsupported UI hierarchy')
    nodes = list(ET.fromstring(xml).iter('node'))
    state = any(n.get('package') == 'dev.andrix.terminal'
                and n.get('class') == 'android.widget.TextView'
                and n.get('text') == 'Attached — native owner UID7500' for n in nodes)
    view = any(n.get('package') == 'dev.andrix.terminal'
               and n.get('class') == 'android.view.View'
               and n.get('enabled') == 'true' and n.get('focused') == 'true' for n in nodes)
    return state and view


def text_actions(text, chunk=60):
    """Keep each Android input invocation bounded; do not implicitly press Enter."""
    if (type(chunk) is not int or not 1 <= chunk <= 60 or not isinstance(text, str)
            or not 1 <= len(text) <= 8192 or '%' in text
            or not all(32 <= ord(c) < 127 for c in text)):
        raise ValueError('Expected bounded printable ASCII without input percent escapes')
    return [{'action': 'text', 'text': text[i:i + chunk]} for i in range(0, len(text), chunk)]


def submit(runtime, actions, timeout=180):
    runtime = Path(runtime)
    queue = runtime/'state/ui-requests'
    evidence = runtime/'evidence/ui'
    ended = runtime/'evidence/controller.status'
    if (not queue.is_dir() or not (evidence/'ready').is_file() or ended.exists()
            or queue.is_symlink() or evidence.is_symlink()):
        raise RuntimeError('No active, ready UI controller')
    if (not isinstance(actions, list) or not 1 <= len(actions) <= 1024
            or any(not isinstance(a, dict) or not isinstance(a.get('action'), str) for a in actions)
            or not 0 < timeout <= 7200):
        raise ValueError('Expected a finite action batch and deadline')
    # Also catches non-JSON values before publishing any part of the batch.
    payloads = [json.dumps(a, allow_nan=False).encode() + b'\n' for a in actions]
    if sum(map(len, payloads)) > 1024 * 1024:
        raise ValueError('Action batch too large')
    with (runtime/'state/ui-submit.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        requests = list(evidence.glob('*.request.json'))
        if list(queue.glob('*.json')) or any(
                not p.with_name(p.name.replace('.request.', '.result.')).is_file() for p in requests):
            raise RuntimeError('A prior UI action is still pending; inspect it before continuing')
        ids = []
        for path in requests:
            name = path.name.split('.')[0]
            if not re.fullmatch(r'[0-9]{4}', name):
                raise ValueError('Unexpected UI request ID')
            ids.append(int(name))
        number = max(ids, default=0)
        if number + len(actions) > 9999:
            raise ValueError('UI action IDs exhausted')
        deadline = time.monotonic() + timeout
        results = []
        for data in payloads:
            if ended.exists() or time.monotonic() >= deadline:
                raise RuntimeError('Controller ended or batch deadline reached')
            number += 1
            ident = f'{number:04d}'
            temporary, destination = queue/(ident+'.new'), queue/(ident+'.json')
            result = evidence/(ident+'.result.json')
            if result.exists():
                raise RuntimeError('Result exists without its request; refusing ID reuse')
            with temporary.open('xb') as target:
                target.write(data)
            # Atomic publication without overwriting another writer's request.
            os.link(temporary, destination)
            temporary.unlink()
            while not result.exists():
                if ended.exists() or time.monotonic() >= deadline:
                    raise RuntimeError('UI result missing; outcome uncertain, no following action submitted')
                time.sleep(.05)
            row = json.loads(result.read_bytes())
            if row.get('id') != ident or row.get('status') != 'COMPLETED':
                raise RuntimeError('UI action failed or mismatched; inspect '+str(result))
            results.append(row)
        return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime', type=Path, required=True)
    parser.add_argument('--actions', type=Path, required=True)
    parser.add_argument('--timeout', type=float, default=180)
    args = parser.parse_args()
    rows = submit(args.runtime, json.loads(args.actions.read_bytes()), args.timeout)
    print(json.dumps(rows[-1], indent=2))


if __name__ == '__main__':
    main()
