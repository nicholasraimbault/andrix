# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import terminal_update as update


class TerminalUpdateTests(unittest.TestCase):
    def test_only_signature_entries_may_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            def apk(name,signature,resource):
                p=root/name
                with zipfile.ZipFile(p,'w') as z:
                    z.writestr('AndroidManifest.xml',b'manifest')
                    z.writestr('classes.dex',b'code')
                    z.writestr('META-INF/DEV.RSA',signature)
                    z.writestr('META-INF/services/example',resource)
                return p
            a=apk('a.apk',b'old',b'resource');b=apk('b.apk',b'new',b'resource')
            self.assertEqual(update.payload(a),update.payload(b))
            c=apk('c.apk',b'new',b'changed')
            self.assertNotEqual(update.payload(a),update.payload(c))

    def test_signer_record_must_be_unique_and_exact(self):
        digest='a'*64;text='Number of signers: 1\nV3.0 Signer: certificate SHA-256 digest: '+digest+'\n'
        self.assertTrue(update.signer_matches(text,digest))
        self.assertFalse(update.signer_matches(text,'b'*64))
        self.assertFalse(update.signer_matches(text+text,digest))
        self.assertFalse(update.signer_matches(text.replace('signers: 1','signers: 2'),digest))


if __name__=='__main__':unittest.main()
