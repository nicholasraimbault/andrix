# SPDX-License-Identifier: Apache-2.0
"""Strict observations for the finite runtime characterization, not policy qualification."""
import json
import re
import struct

PACKAGE = "dev.andrix.proof.nativeruntime"


def object_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def decode(text):
    return json.loads(text, object_pairs_hook=object_pairs,
                      parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))


def integer(value, minimum=0):
    if type(value) is not int or value < minimum or value > (1 << 63) - 1:
        raise ValueError("invalid integer")
    return value


def credentials(text):
    if not isinstance(text, str) or len(text) > 8192:
        raise ValueError("invalid status")
    required = {"Pid", "Tgid", "Uid", "Gid", "Groups", "CapInh", "CapPrm", "CapEff",
                "CapBnd", "CapAmb", "NoNewPrivs", "Seccomp"}
    result = {}
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if key not in required:
            continue
        if not sep or key in result:
            raise ValueError("duplicate status field")
        tokens = value.split()
        if key.startswith("Cap"):
            if len(tokens) != 1 or not re.fullmatch(r"[0-9a-fA-F]{16}", tokens[0]):
                raise ValueError("invalid capabilities")
            result[key] = int(tokens[0], 16)
        else:
            if any(not re.fullmatch(r"[0-9]+", x) for x in tokens):
                raise ValueError("invalid status number")
            values = [int(x) for x in tokens]
            if key in {"Uid", "Gid"} and len(values) != 4:
                raise ValueError("invalid credential vector")
            if key not in {"Uid", "Gid", "Groups"} and len(values) != 1:
                raise ValueError("invalid status scalar")
            result[key] = values
    if set(result) != required:
        raise ValueError("incomplete credentials")
    return result


def profile(value, kind, nonce, principal_uid, controller_pid=None):
    if not isinstance(value, dict) or type(value.get("version")) is not int or value.get("version") != 1 or value.get("kind") != kind:
        raise ValueError("profile type")
    keys = {"version", "kind", "nonce", "pid", "uid", "gid", "caller_pid", "caller_uid",
            "created_elapsed_ms", "elapsed_ms", "status", "cgroup", "selinux", "exe", "art_present"}
    if kind != "native":
        keys |= {"package", "application_uid", "attribution_uid", "attribution_package"}
    if kind == "managed": keys.add("keyguard_constructed")
    if set(value) != keys: raise ValueError("unexpected profile fields")
    if value.get("nonce") != nonce:
        raise ValueError("profile nonce")
    pid = integer(value["pid"], 1)
    uid = integer(value["uid"], 1)
    gid = integer(value["gid"], 1)
    caller_uid = integer(value["caller_uid"], 1)
    caller_pid = integer(value["caller_pid"], 1)
    created = integer(value["created_elapsed_ms"], 1)
    if integer(value["elapsed_ms"], 1) < created:
        raise ValueError("profile time")
    if not 10000 <= principal_uid < 20000:
        raise ValueError("ordinary principal required")
    if uid != gid or caller_uid != principal_uid:
        raise ValueError("wrong principal or caller")
    if kind == "native":
        if not 99000 <= uid < 100000 or value["art_present"] is not False:
            raise ValueError("not native isolated runtime")
        if not re.fullmatch(r"u:r:isolated_app:s0(?::c[0-9]+(?:,c[0-9]+)*)?", value["selinux"]):
            raise ValueError("not isolated app MAC")
    else:
        if uid != principal_uid or value["art_present"] is not True:
            raise ValueError("not ordinary managed runtime")
        if value.get("package") != PACKAGE or value.get("attribution_package") != PACKAGE:
            raise ValueError("wrong package attribution")
        if value.get("application_uid") != uid or value.get("attribution_uid") != uid:
            raise ValueError("wrong UID attribution")
        if not re.fullmatch(r"u:r:untrusted_app(?:_[0-9]+)?:s0(?::c[0-9]+(?:,c[0-9]+)*)?", value["selinux"]):
            raise ValueError("not ordinary app MAC")
        if kind == "managed" and value.get("keyguard_constructed") is not True:
            raise ValueError("incomplete managed bootstrap control")
    if controller_pid is not None and (caller_pid != controller_pid or pid == controller_pid):
        raise ValueError("not distinct service or expected caller")
    c = credentials(value["status"])
    if c["Uid"] != [uid] * 4 or c["Gid"] != [gid] * 4 or c["Pid"] != [pid] or c["Tgid"] != [pid]:
        raise ValueError("credential inconsistency")
    if any(c[key] for key in ("CapInh", "CapPrm", "CapEff", "CapAmb")) or c["Seccomp"] != [2]:
        raise ValueError("unexpected privilege or missing seccomp")
    if c["NoNewPrivs"] not in ([0], [1]):
        raise ValueError("invalid NNP")
    # Bounding capabilities, supplementary groups and NNP are recorded, not a production allowlist.
    group = value["cgroup"]
    if not isinstance(group, str) or len(group) > 8192 or len(re.findall(r"^0::/[^\n]*$", group, re.M)) != 1:
        raise ValueError("invalid cgroup")
    if not isinstance(value["exe"], str) or not value["exe"].startswith("/") or len(value["exe"]) > 1024:
        raise ValueError("invalid executable observation")
    return c


def events(raw, nonce, complete=False):
    if len(raw) > 262144:
        raise ValueError("instrumentation output bound")
    text = raw.decode("utf-8", errors="strict")
    rows = []
    elapsed = -1
    terminal = False
    for line in text.splitlines():
        if not line.startswith("INSTRUMENTATION_STATUS: runtime_event="):
            continue
        row = decode(line.split("=", 1)[1])
        if terminal or type(row.get("version")) is not int or row.get("version") != 1 or type(row.get("seq")) is not int or row.get("nonce") != nonce or row.get("seq") != len(rows) + 1:
            raise ValueError("event identity/order")
        now = integer(row["elapsed_ms"], 1)
        if now < elapsed or not isinstance(row.get("details"), dict):
            raise ValueError("event time/details")
        elapsed = now
        if row.get("phase") not in {"controller", "managed", "native", "observing", "heartbeat", "unbind_begin", "unbind_returned", "awaiting_destroy", "complete"}:
            raise ValueError("unknown phase")
        terminal = row["phase"] == "complete"
        rows.append(row)
    if complete:
        phases = [r["phase"] for r in rows]
        expected = ["controller", "managed", "native", "observing"] + ["heartbeat"] * 15 + ["unbind_begin", "unbind_returned"] * 2 + ["awaiting_destroy", "complete"]
        if phases != expected or rows[-1]["details"].get("controller_passed") is not True:
            raise ValueError("incomplete finite controller")
        if rows[3]["details"].get("duration_ms") != 30000:
            raise ValueError("wrong observation window")
        if [r["details"].get("index") for r in rows[4:19]] != list(range(15)):
            raise ValueError("heartbeat sequence")
        if rows[18]["elapsed_ms"] - rows[3]["elapsed_ms"] < 30000:
            raise ValueError("short observation")
        if [r["details"].get("kind") for r in rows[19:23]] != ["native", "native", "managed", "managed"]:
            raise ValueError("unbind ownership")
        if not all(rows[i]["details"].get("called") is True for i in [20, 22]):
            raise ValueError("unbind not called")
        if rows[23]["details"].get("duration_ms") != 10000 or rows[24]["elapsed_ms"] - rows[23]["elapsed_ms"] < 10000:
            raise ValueError("missing pre-finish retirement window")
        if text.count("INSTRUMENTATION_RESULT: runtime_result=controller_complete") != 1 or not re.search(r"^INSTRUMENTATION_CODE: -1\s*$", text, re.M):
            raise ValueError("instrumentation terminal missing")
    return rows


def log_records(raw):
    """Pinned logger_entry v4. Writer PID/UID come from logd, not the JSON."""
    if len(raw) > 8 * 1024 * 1024: raise ValueError("log bound")
    offset = 0
    rows = []
    while offset < len(raw):
        if len(raw) - offset < 28: raise ValueError("truncated logger header")
        size, header, pid, tid, sec, ns, lid, uid = struct.unpack_from("<HHiIIIII", raw, offset)
        if header != 28 or size < 3 or size > 5120 or ns >= 1000000000 or lid != 0:
            raise ValueError("unknown logger record")
        end = offset + header + size
        if end > len(raw): raise ValueError("truncated logger payload")
        body = raw[offset + header:end]
        offset = end
        tag, sep, message = body[1:].partition(b"\0")
        if not sep or not message.endswith(b"\0"): raise ValueError("invalid log message")
        if tag != b"AndrixRuntime": continue
        message = message[:-1]
        if body[0] != 4 or not message.startswith(b"ANDRIX_RUNTIME "):
            raise ValueError("unexpected fixture log")
        row = decode(message[len(b"ANDRIX_RUNTIME "):].decode("utf-8", errors="strict"))
        if set(row) != {"version", "kind", "event", "nonce", "pid", "uid", "created_elapsed_ms", "elapsed_ms"}:
            raise ValueError("unexpected lifecycle fields")
        if row.get("pid") != pid or row.get("uid") != uid:
            raise ValueError("log writer mismatch")
        rows.append(row)
    return rows


def lifecycle(raw, kind, nonce, pid, uid, created, unbind_begin=None, finish_begin=None):
    rows = []
    for row in log_records(raw):
        if row.get("kind") != kind or row.get("pid") != pid or row.get("created_elapsed_ms") != created:
            continue
        if type(row.get("version")) is not int or row.get("version") != 1 or row.get("uid") != uid or row.get("nonce") != ("" if row.get("event") == "create" else nonce):
            raise ValueError("lifecycle identity mismatch")
        if integer(row["elapsed_ms"], 1) < created:
            raise ValueError("lifecycle time")
        rows.append(row)
    if [r.get("event") for r in rows] != ["create", "bind", "unbind", "destroy"]:
        raise ValueError("incomplete lifecycle")
    if any(a["elapsed_ms"] > b["elapsed_ms"] for a, b in zip(rows, rows[1:])):
        raise ValueError("lifecycle time order")
    if unbind_begin is not None and rows[2]["elapsed_ms"] < unbind_begin:
        raise ValueError("premature unbind")
    if finish_begin is not None and rows[3]["elapsed_ms"] >= finish_begin:
        raise ValueError("destruction not established before instrumentation finish")
    return rows
