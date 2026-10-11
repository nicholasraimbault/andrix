# SPDX-License-Identifier: Apache-2.0
"""Version 1 of the lab bridge protocol: one encoding for each message, goldens that bind the
Python and Java codecs, and refusal of every malformed frame. Host evidence only."""
import hashlib
import io
import os
import struct
import unittest

import labtest  # noqa: F401  (path setup)
import lab_protocol as proto

REQUEST = '0f' * 16
MANIFEST = 'ad' * 32
NONCE = '5e1f0c9a7d3b4e2f8a6c1d0b9e7f3a25'
BOUND = (31, 1189842383, 1791504012345, '/data/app-staging/session_1189842383', 2000, NONCE)


def golden_messages():
    """One fixed message of every type. The Java codec test encodes the same values."""
    m = proto.message
    return {
        'HELLO': m('HELLO', REQUEST, MANIFEST, installation='00112233445566778899aabbccddeeff',
                   coordinator='c0' * 16, config='3c' * 32, component='com.android.systemui', trust='7a' * 32,
                   route=1),
        'HELLO_REPLY': m('HELLO_REPLY', REQUEST, MANIFEST, status=1, generation=3, target=1, reason=''),
        'CLOCK': m('CLOCK', REQUEST, MANIFEST),
        'CLOCK_REPLY': m('CLOCK_REPLY', REQUEST, MANIFEST, status=1, boot='1f0d016e80904303a3ff9eb193eb403d',
                         instance=4021, elapsed=812345, wall=1791504812345, group=17, reason=''),
        'OBSERVE': m('OBSERVE', REQUEST, MANIFEST, scope=2, component='com.android.systemui',
                     boot='1f0d016e80904303a3ff9eb193eb403d', ticket='04' * 16, plan='01' * 16, state=7),
        'OBSERVE_REPLY': m('OBSERVE_REPLY', REQUEST, MANIFEST, status=1, frames=[(18, b'\x01\x02'), (19, b'\x03')],
                           reason=''),
        'CROSS': m('CROSS', REQUEST, MANIFEST, ticket='04' * 16, ticket_digest='11' * 32, plan='01' * 16,
                   plan_digest='22' * 32, attempt=2, component='com.android.systemui', index=4, crossing=5,
                   occurrence=1, entry_boot='1f0d016e80904303a3ff9eb193eb403d', entry_instance=4021,
                   entry_elapsed=812000, grant='2a' * 16, reference=proto.ZERO_ID, native=BOUND,
                   bundle_apk=proto.ZERO_DIGEST, actor=2, granted=1791504000000, window=3600000),
        'CROSS_REPLY': m('CROSS_REPLY', REQUEST, MANIFEST, status=1, record=42, frame=b'reply-record', reason=''),
        'POINT': m('POINT', REQUEST, MANIFEST, point='selection-written', ticket='04' * 16, plan='01' * 16, attempt=2),
        'POINT_REPLY': m('POINT_REPLY', REQUEST, MANIFEST, status=4, record=43, reason='admitted fault cell'),
        'HOST': m('HOST', REQUEST, MANIFEST, phase=2, crossing=1, ticket='04' * 16, plan='01' * 16, attempt=2,
                  index=0, occurrence=1, reference='9b' * 16, outcome=1, reply='ab' * 32),
        'HOST_REPLY': m('HOST_REPLY', REQUEST, MANIFEST, status=5, record=44, reason='admitted dropped host reply'),
        'REPORT': m('REPORT', REQUEST, MANIFEST, ticket='04' * 16, state=24, flags=0, cause=0, ledger=[1, 2, 3, 6],
                    note='settle'),
        'REPORT_REPLY': m('REPORT_REPLY', REQUEST, MANIFEST, status=1, record=45, reason=''),
    }


# SHA-256 of each golden frame. A deliberate layout change replaces them with the Java test's.
GOLDENS = {
    'HELLO': 'abc3267476f4f4e2e51a6832ba154484a1307a33f2e60063e90136937f5c6c0c',
    'HELLO_REPLY': '73b98362f536dad8ef61fbe23d8b761158dcae9f9ee916894210e369866b5793',
    'CLOCK': 'ac5895b1ec24658af76bddfc40d1130f858ae948f736b9c33337587ced1cad99',
    'CLOCK_REPLY': '529fbab76241756678696d9cacca78a3b7a52cc323119d82af2e7a842a91e6b0',
    'OBSERVE': 'f97df0c52813b9daca05caa0ea649042a68a4e389a2fd30fc930fa70835f0cd7',
    'OBSERVE_REPLY': '281344f7d8ca5879fe31ea999408229d8efb9290ceab4536e47221e61ce9e5da',
    'CROSS': '0c2d43765e4be9be7652f06b5f979212d7ec1c5a3e70bc4d66e5224b328713eb',
    'CROSS_REPLY': 'b90aa2fa2a1b758d2161235a37d55210ee1c9b95207ba84e5ea7013d3ad0d31a',
    'POINT': '7e3da79951886f9683a7b4b7b1bd7cba13efde47dda642a36c28224d150ecfe0',
    'POINT_REPLY': 'e66de80bc95223d73a327321e4ef215a4be116374b2ba68f13ebfc5fb9ff79f0',
    'HOST': 'bd7707720c837772ad7753b44b125c874044685e17e74c492a8f2abe410aba36',
    'HOST_REPLY': '7daad1982144430f2cbb437f9f8909ff4c8a31e4a2e07fc30753a3dd54a57baf',
    'REPORT': '7156a50db3f8f21d7d33a054ce9f096646051828c9ffd111514350fc80bf6800',
    'REPORT_REPLY': 'e677104dd5b782e941c16d27527ea46a3126c7fbc707ffe6c2719d1597414217',
}


def reframe(data, body_change):
    """A frame with its body changed and its length and checksum made consistent again."""
    body = body_change(bytearray(data[proto.HEADER:-proto.CHECKSUM]))
    head = bytearray(data[:proto.HEADER])
    head[8:12] = struct.pack('<I', proto.HEADER + len(body) + proto.CHECKSUM)
    out = bytes(head) + bytes(body)
    return out + hashlib.sha256(out).digest()


class ProtocolTests(unittest.TestCase):
    def test_every_type_has_one_encoding(self):
        for name, message in golden_messages().items():
            data = proto.encode(message)
            decoded = proto.decode(data)
            self.assertEqual(decoded, message, name)
            self.assertEqual(proto.encode(decoded), data, name)

    def test_goldens(self):
        directory = os.environ.get('ANDRIX_LAB_GOLDENS')
        for name, message in golden_messages().items():
            data = proto.encode(message)
            if directory:
                with open(os.path.join(directory, name + '.bin'), 'wb') as handle:
                    handle.write(data)
            self.assertEqual(hashlib.sha256(data).hexdigest(), GOLDENS[name], name)

    def test_the_frame_is_checked_first(self):
        data = proto.encode(golden_messages()['CROSS'])
        cases = {
            'short': data[:proto.MIN_FRAME - 1],
            'magic': b'AXLC' + data[4:],
            'version': data[:4] + struct.pack('<H', 2) + data[6:],
            'type': data[:6] + struct.pack('<H', 99) + data[8:],
            'length': data[:8] + struct.pack('<I', len(data) + 1) + data[12:],
            'checksum': data[:-1] + bytes([data[-1] ^ 1]),
            'trailing': reframe(data, lambda body: body + b'\x00'),
            'cut': reframe(data, lambda body: body[:-1]),
            'zero request': (lambda raw: raw + hashlib.sha256(raw).digest())(data[:12] + bytes(16) + data[28:-32]),
            'zero manifest': (lambda raw: raw + hashlib.sha256(raw).digest())(data[:28] + bytes(32) + data[60:-32]),
        }
        for name, bad in cases.items():
            with self.assertRaises(proto.ProtocolError, msg=name):
                proto.decode(bad)

    def test_fields_are_bounded(self):
        hello = golden_messages()['HELLO']
        for change in ({'component': 'com.android.systemui\x00'}, {'component': 'caf\xe9.x'}, {'component': 'x'},
                       {'component': 'a.' + 'b' * 300}, {'installation': '00' * 16}, {'installation': 'AB' * 16},
                       {'route': 2}, {'route': 256}):
            with self.assertRaises(proto.ProtocolError, msg=str(change)):
                proto.encode(dict(hello, **change))
        observe = golden_messages()['OBSERVE_REPLY']
        for change in ({'frames': [(1, b'x')] * 257}, {'frames': [(0, b'x')]}, {'frames': [(1, b'')]},
                       {'frames': [(1, b'x' * 65537)]}, {'status': 3}):
            with self.assertRaises(proto.ProtocolError, msg=str(change)[:60]):
                proto.encode(dict(observe, **change))
        with self.assertRaises(proto.ProtocolError):
            proto.encode(dict(hello, extra=1))

    def test_cross_relations(self):
        cross = golden_messages()['CROSS']
        create = dict(cross, crossing=3, grant='2a' * 16, reference=NONCE, native=(16, 0, 0, '', 0, NONCE), granted=0,
                      window=0)
        self.assertEqual(proto.decode(proto.encode(create))['crossing'], 3)
        write = dict(cross, crossing=4, grant=proto.ZERO_ID, actor=0, bundle_apk='a1' * 32, granted=0, window=0)
        self.assertEqual(proto.decode(proto.encode(write))['crossing'], 4)
        bad = {
            'a sign is not a device crossing': dict(cross, crossing=1),
            'a handover is not a device crossing': dict(cross, crossing=9),
            'commit without a grant': dict(cross, grant=proto.ZERO_ID, actor=0),
            'a grant without its actor': dict(cross, actor=0),
            'write with a grant': dict(write, grant='2a' * 16, actor=2),
            'write without the bundle': dict(write, bundle_apk=proto.ZERO_DIGEST),
            'commit with a bundle': dict(cross, bundle_apk='a1' * 32),
            'create without its nonce': dict(create, reference=proto.ZERO_ID),
            'create with another nonce': dict(create, native=(16, 0, 0, '', 0, '77' * 16)),
            'create with a session': dict(create, native=BOUND),
            'commit by ID alone': dict(cross, native=(1, 1189842383, 0, '', 0, proto.ZERO_ID)),
            'commit without the nonce': dict(cross, native=(15, *BOUND[1:5], proto.ZERO_ID)),
            'a framework crossing without its instance': dict(cross, entry_instance=-1),
            'an occurrence beyond the bound': dict(cross, occurrence=2),
            'an occurrence beyond the index': dict(cross, crossing=6, grant=proto.ZERO_ID, actor=0, index=0,
                                                   occurrence=2, granted=0, window=0),
            'commit without its grant time': dict(cross, granted=0),
            'commit without the activation window': dict(cross, window=0),
            'a negative grant time': dict(cross, granted=-1),
            'create with a grant time': dict(create, granted=1791504000000),
            'write with a window': dict(write, window=3600000),
            'an index beyond the ledger': dict(cross, index=140),
            'a reference with unknown bits': dict(cross, native=(63, *BOUND[1:])),
            'a session ID without its bit': dict(cross, native=(30, *BOUND[1:])),
        }
        for name, message in bad.items():
            with self.assertRaises(proto.ProtocolError, msg=name):
                proto.encode(message)

    def test_reply_relations(self):
        g = golden_messages()
        bad = {
            'a clock without its boot': dict(g['CLOCK_REPLY'], boot=proto.ZERO_ID),
            'an unavailable clock with a reading': dict(g['CLOCK_REPLY'], status=2, reason='x'),
            'an ok reply with a reason': dict(g['HELLO_REPLY'], reason='x'),
            'a refusal without a reason': dict(g['HELLO_REPLY'], status=7, generation=0, target=0),
            'a cross reply ok without its frame': dict(g['CROSS_REPLY'], frame=b''),
            'a no reply with a frame': dict(g['CROSS_REPLY'], status=6, reason='x'),
            'a withheld reply without its record': dict(g['CROSS_REPLY'], status=5, frame=b'', record=0, reason='x'),
            'a point halt without its record': dict(g['POINT_REPLY'], record=0),
            'a point withheld': dict(g['POINT_REPLY'], status=5),
            'a hello unavailable': dict(g['HELLO_REPLY'], status=2, generation=0, target=0, reason='x'),
            'a host begin with an outcome': dict(g['HOST'], phase=1),
            'a host reply without its digest': dict(g['HOST'], reply=proto.ZERO_DIGEST),
            'a report of an unknown crossing': dict(g['REPORT'], ledger=[10]),
            'a report with unknown flags': dict(g['REPORT'], flags=8),
            'a point of no known name': dict(g['POINT'], point='other'),
            'an observation of the component naming a ticket': dict(g['OBSERVE'], scope=1),
        }
        for name, message in bad.items():
            with self.assertRaises(proto.ProtocolError, msg=name):
                proto.encode(message)
        refused = dict(g['CLOCK_REPLY'], status=7, boot=proto.ZERO_ID, instance=0, elapsed=0, wall=0, group=0,
                       reason='HELLO first')
        self.assertEqual(proto.decode(proto.encode(refused))['status'], 7)

    def test_streams_carry_whole_frames(self):
        data = proto.encode(golden_messages()['HELLO']) + proto.encode(golden_messages()['CLOCK'])
        stream = io.BytesIO(data)
        self.assertEqual(proto.decode(proto.read_frame(stream))['type'], 'HELLO')
        self.assertEqual(proto.decode(proto.read_frame(stream))['type'], 'CLOCK')
        self.assertIsNone(proto.read_frame(stream))
        with self.assertRaises(proto.ProtocolError):
            proto.read_frame(io.BytesIO(data[:20]))
        huge = data[:8] + struct.pack('<I', proto.MAX_FRAME + 1) + data[12:]
        with self.assertRaises(proto.ProtocolError):
            proto.read_frame(io.BytesIO(huge))

    def test_replies_pair_with_requests(self):
        self.assertEqual([proto.reply_type(t) for t in ('HELLO', 'CLOCK', 'OBSERVE', 'CROSS', 'POINT', 'HOST',
                                                        'REPORT')],
                         ['HELLO_REPLY', 'CLOCK_REPLY', 'OBSERVE_REPLY', 'CROSS_REPLY', 'POINT_REPLY', 'HOST_REPLY',
                          'REPORT_REPLY'])
        with self.assertRaises(proto.ProtocolError):
            proto.reply_type('CROSS_REPLY')


if __name__ == '__main__':
    unittest.main()
