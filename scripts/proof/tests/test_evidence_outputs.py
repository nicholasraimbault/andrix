# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
import os
import tempfile
import unittest

from scripts.proof.evidence_outputs import require_external_outputs


class EvidenceOutputsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base/'input'
        self.root.mkdir()
        self.data = self.root/'artifact'
        self.data.write_bytes(b'original bytes')

    def test_external_existing_and_future_outputs(self):
        external = self.base/'log'
        external.write_bytes(b'not an input')
        require_external_outputs(self.root, [external, self.base/'new-status'])
        self.assertEqual(self.data.read_bytes(), b'original bytes')

    def test_input_root_and_internal_output_refused(self):
        for output in [self.root, self.data, self.root/'new-log']:
            with self.assertRaisesRegex(ValueError, 'inside input tree'):
                require_external_outputs(self.root, [output])

    def test_similar_prefix_is_not_containment(self):
        require_external_outputs(self.root, [self.base/'input-log'])

    def test_symlink_destination_into_input_refused(self):
        alias = self.base/'alias'
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'inside input tree'):
            require_external_outputs(self.root, [alias/'future-log'])

    def test_hardlink_destination_refused(self):
        alias = self.base/'hard-link'
        os.link(self.data, alias)
        with self.assertRaisesRegex(ValueError, 'aliases input inode'):
            require_external_outputs(self.root, [alias])

    def test_open_descriptor_alias_refused_without_writing(self):
        alias = self.base/'hard-link'
        os.link(self.data, alias)
        fd = os.open(alias, os.O_WRONLY | os.O_APPEND)
        try:
            with self.assertRaisesRegex(ValueError, 'descriptor aliases input inode'):
                require_external_outputs(self.root, [], [fd])
        finally:
            os.close(fd)
        self.assertEqual(self.data.read_bytes(), b'original bytes')

    def test_external_descriptor_and_pipe(self):
        fd = os.open(self.base/'log', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        reader, writer = os.pipe()
        try:
            require_external_outputs(self.root, [], [fd, writer])
        finally:
            os.close(fd)
            os.close(reader)
            os.close(writer)

    def test_input_symlink_is_not_followed(self):
        outside = self.base/'outside'
        outside.mkdir()
        other = outside/'log'
        other.write_bytes(b'external')
        (self.root/'external-link').symlink_to(outside, target_is_directory=True)
        require_external_outputs(self.root, [other])


if __name__ == '__main__':
    unittest.main()
