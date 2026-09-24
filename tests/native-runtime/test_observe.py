# SPDX-License-Identifier: Apache-2.0
import copy
import json
import struct
import unittest
import observe


def sample(kind="native"):
    uid = 99001 if kind == "native" else 10146
    pid = 901 if kind == "native" else 902
    status = (f"Pid:\t{pid}\nTgid:\t{pid}\nUid:\t{uid} {uid} {uid} {uid}\n"
              f"Gid:\t{uid} {uid} {uid} {uid}\nGroups:\t3003\n"
              "CapInh:\t0000000000000000\nCapPrm:\t0000000000000000\n"
              "CapEff:\t0000000000000000\nCapAmb:\t0000000000000000\n"
              "CapBnd:\t000001ffffffffff\nNoNewPrivs:\t0\nSeccomp:\t2\n")
    value = dict(version=1, kind=kind, nonce="trial_n", pid=pid, uid=uid, gid=uid,
                 caller_pid=900, caller_uid=10146, created_elapsed_ms=10, elapsed_ms=12,
                 status=status, cgroup="0::/uid_99001/pid_901\n", exe="/system/bin/zygote_next",
                 selinux="u:r:isolated_app:s0:c1,c2", art_present=False)
    if kind == "managed":
        value.update(selinux="u:r:untrusted_app:s0:c1,c2", art_present=True,
                     package=observe.PACKAGE, application_uid=uid, attribution_uid=uid,
                     attribution_package=observe.PACKAGE, keyguard_constructed=True)
    return value


class ObservationTest(unittest.TestCase):
    def test_profiles_and_required_actual_identity(self):
        for kind in ("native", "managed"):
            value = sample(kind)
            observe.profile(value, kind, "trial_n", 10146, 900)
            for key, replacement in (("caller_uid", 1000), ("caller_pid", 1), ("uid", 0),
                                     ("art_present", not value["art_present"]), ("pid", True),
                                     ("nonce", "other"), ("elapsed_ms", 9)):
                changed = copy.deepcopy(value)
                changed[key] = replacement
                with self.assertRaises(ValueError, msg=key):
                    observe.profile(changed, kind, "trial_n", 10146, 900)

    def test_status_is_complete_and_not_silence(self):
        value = sample()
        for status in (value["status"] + "Uid: 0 0 0 0\n",
                       value["status"].replace("Seccomp:\t2\n", ""),
                       value["status"].replace("CapEff:\t0000000000000000", "CapEff:\t0000000000000001"),
                       value["status"].replace("99001 99001 99001 99001", "99001 0 99001 99001")):
            changed = dict(value, status=status)
            with self.assertRaises(ValueError):
                observe.profile(changed, "native", "trial_n", 10146, 900)

    def test_json_duplicate_refused(self):
        with self.assertRaises(ValueError):
            observe.decode('{"pid":1,"pid":2}')
        with self.assertRaises(ValueError):
            observe.decode('{"pid":NaN}')

    def test_events_require_complete_controller_and_window(self):
        phases = ["controller", "managed", "native", "observing"] + ["heartbeat"] * 15 + ["unbind_begin", "unbind_returned"] * 2 + ["awaiting_destroy", "complete"]
        rows = []
        for i, phase in enumerate(phases):
            details = {}
            if phase == "observing": details = {"duration_ms": 30000}
            if phase == "heartbeat": details = {"index": i - 4}
            if phase in {"unbind_begin", "unbind_returned"}: details = {"kind": "native" if i < 21 else "managed", "called": True}
            if phase == "awaiting_destroy": details = {"duration_ms": 10000}
            if phase == "complete": details = {"controller_passed": True}
            rows.append(dict(version=1, seq=i + 1, nonce="trial", phase=phase,
                             elapsed_ms=1 + i * 2000 + (8000 if i == 24 else 0), details=details))
        def encode(data):
            return ("\n".join("INSTRUMENTATION_STATUS: runtime_event=" + json.dumps(r) for r in data)
                    + "\nINSTRUMENTATION_RESULT: runtime_result=controller_complete\nINSTRUMENTATION_CODE: -1\n").encode()
        self.assertEqual(25, len(observe.events(encode(rows), "trial", True)))
        for changed in (rows[:-1], rows + [rows[-1]], [dict(r, seq=2) for r in rows]):
            with self.assertRaises(ValueError): observe.events(encode(changed), "trial", True)
        changed = copy.deepcopy(rows)
        for r in changed: r["elapsed_ms"] = 1
        with self.assertRaises(ValueError): observe.events(encode(changed), "trial", True)

    def test_lifecycle_requires_exact_instance_and_all_callbacks(self):
        rows = [dict(version=1, kind="native", event=e, nonce="" if e == "create" else "trial_n",
                     pid=901, uid=99001, created_elapsed_ms=10, elapsed_ms=10 + i)
                for i, e in enumerate(("create", "bind", "unbind", "destroy"))]
        def encode(data):
            result = b""
            for r in data:
                body = b"\x04AndrixRuntime\0ANDRIX_RUNTIME " + json.dumps(r).encode() + b"\0"
                result += struct.pack("<HHiIIIII", len(body), 28, 901, 901, 1, 0, 0, 99001) + body
            return result
        self.assertEqual(4, len(observe.lifecycle(encode(rows), "native", "trial_n", 901, 99001, 10)))
        for data in (rows[:-1], rows + [rows[-1]], list(reversed(rows))):
            with self.assertRaises(ValueError): observe.lifecycle(encode(data), "native", "trial_n", 901, 99001, 10)
        with self.assertRaises(ValueError): observe.lifecycle(encode(rows)[:-1], "native", "trial_n", 901, 99001, 10)
        wrong = copy.deepcopy(rows)
        wrong[-1]["uid"] = 99002
        with self.assertRaises(ValueError): observe.lifecycle(encode(wrong), "native", "trial_n", 901, 99001, 10)
        with self.assertRaises(ValueError): observe.lifecycle(encode(rows), "native", "trial_n", 901, 99001, 10, unbind_begin=13)
        with self.assertRaises(ValueError): observe.lifecycle(encode(rows), "native", "trial_n", 901, 99001, 10, finish_begin=13)
        changed = copy.deepcopy(rows)
        changed[-1]["created_elapsed_ms"] = 11
        with self.assertRaises(ValueError): observe.lifecycle(encode(changed), "native", "trial_n", 901, 99001, 10)


if __name__ == "__main__":
    unittest.main()
