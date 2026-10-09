# SPDX-License-Identifier: Apache-2.0
"""A SYNTHETIC signed world for the tests: a manifest repository with SSH signed tags, the
base records that pin its tags, and the committed adevtool records bound to them.

The real manifest repository and its tags are not used. Keys are generated per run.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess

FIXTURES = Path(__file__).resolve().parent / 'fixtures'
RECORDS = {tag: json.loads((FIXTURES / f'adevtool/records/{tag}.json').read_text())
           for tag in ('2026081300', '2026100600')}
PATCH = {'2026081300': '2026-08-05', '2026100600': '2026-10-05'}
ENV = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'HOME': '/nonexistent',
       'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull,
       'GIT_AUTHOR_NAME': 'Manifest fixture', 'GIT_AUTHOR_EMAIL': 'fixture@example.invalid',
       'GIT_COMMITTER_NAME': 'Manifest fixture', 'GIT_COMMITTER_EMAIL': 'fixture@example.invalid'}


def run(*args, cwd=None):
    return subprocess.run([str(arg) for arg in args], cwd=cwd, env=ENV, check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.decode().strip()


class World:
    def __init__(self, work, tags=('2026081300', '2026100600'), unsigned=(), foreign=()):
        self.work = Path(work)
        self.work.mkdir(parents=True, exist_ok=True)
        self.key = self.work / 'tag-key'
        run('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', '', '-f', self.key)
        kind, blob = (self.work / 'tag-key.pub').read_text().split()[:2]
        self.signers = self.work / 'allowed_signers'
        self.signers.write_text(f'contact@grapheneos.org {kind} {blob}\n')
        self.foreign = self.work / 'foreign-key'
        run('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', '', '-f', self.foreign)
        self.repo = self.work / 'platform_manifest'
        self.repo.mkdir()
        run('git', '-C', self.repo, 'init', '-q')
        self.bases = self.work / 'bases'
        self.bases.mkdir()
        self.records = {}
        for tag in sorted(tags):
            revision = RECORDS[tag]['adevtool_revision'] if tag in RECORDS else hashlib.sha1(tag.encode()).hexdigest()
            manifest = (f'<manifest><default revision="refs/tags/android-17.0.0_r1"/>'
                        f'<project path="vendor/adevtool" name="adevtool" revision="{revision}"/>'
                        f'<!-- {tag} --></manifest>\n')
            (self.repo / 'default.xml').write_text(manifest)
            run('git', '-C', self.repo, 'add', 'default.xml')
            run('git', '-C', self.repo, 'commit', '-q', '-m', tag)
            if tag in unsigned:
                run('git', '-C', self.repo, 'tag', '-a', '-m', tag, tag)
            else:
                key = self.foreign if tag in foreign else self.key
                run('git', '-C', self.repo, '-c', 'gpg.format=ssh', '-c', f'user.signingkey={key}',
                    'tag', '-s', '-m', tag, tag)
            base = {'schema': 'andrix.upstream.base/1', 'release': tag, 'manifest': {
                'tag_object': run('git', '-C', self.repo, 'rev-parse', f'refs/tags/{tag}'),
                'commit': run('git', '-C', self.repo, 'rev-parse', 'HEAD'),
                'path': 'default.xml',
                'blob': run('git', '-C', self.repo, 'rev-parse', 'HEAD:default.xml'),
                'sha256': hashlib.sha256(manifest.encode()).hexdigest(),
                'allowed_signers_sha256': hashlib.sha256(self.signers.read_bytes()).hexdigest()},
                'security_patch_level': {'value': PATCH.get(tag, '2026-09-05')}}
            (self.bases / f'{tag}.json').write_text(json.dumps(base))
            if tag in RECORDS:
                record = copy.deepcopy(RECORDS[tag])
                record['manifest_sha256'] = base['manifest']['sha256']
                record['tree_head'] = record['adevtool_revision']   # as record --tree adds it
                self.records[tag] = record
