#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Read-only, host-only checks of three isolated Trichrome/Vanadium APKs."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import ssl
import stat
import struct
import subprocess
import sys
import zipfile

from ordinary_app import Failure, require, sha256

ANDROID = "http://schemas.android.com/apk/res/android"
ROLES = ("webview", "library", "config")
WEBVIEW_ABI_MARKER = "lib/arm64-v8a/libplaceholder.so"
# Stable Android public attribute IDs. Names alone are not the compiled identity.
ATTR_IDS = {
    "name": 0x01010003, "value": 0x01010024,
    "minSdkVersion": 0x0101020c, "targetSdkVersion": 0x01010270,
    "maxSdkVersion": 0x01010271, "versionCode": 0x0101021b,
    "versionName": 0x0101021c, "version": 0x01010519,
    "certDigest": 0x01010548, "compileSdkVersion": 0x01010572,
    "compileSdkVersionCodename": 0x01010573,
}
UNVERIFIED = [
    "Compiled ConfigInfo package/certificate trust: inspect the generated ConfigInfo, "
    "build inputs and their relationship to these exact artifact paths. The Config APK "
    "container signature does NOT prove that WebView trusts or consumes it.",
    "Source/build provenance, complete toolchain identity and coordinated updates/rollback.",
    "ELF linking, dependencies, alignment, CFI, MTE, sandbox and other hardening "
    "(only packaged native ELF class/endianness/machine/type headers are checked).",
    "Provider/image integration, installation, rendering, runtime config behavior, TLS/CT "
    "and no-Google/network behavior. No APK strings scan establishes these claims.",
]


def package_name(value):
    require(re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+", value),
            "invalid package/static-library name: " + value)
    return value


def certificate_info(pem):
    """Exactly one public X.509 PEM; no keys, chains, preamble or trailing objects."""
    require(0 < len(pem) <= 65536, "invalid public certificate size")
    match = re.fullmatch(rb"[ \t\r\n]*-----BEGIN CERTIFICATE-----\r?\n"
                         rb"([A-Za-z0-9+/=\r\n]+)-----END CERTIFICATE-----[ \t\r\n]*", pem)
    require(match is not None, "expected exactly one public CERTIFICATE PEM block")
    encoded = match[1].replace(b"\r", b"").replace(b"\n", b"")
    try:
        der = base64.b64decode(encoded, validate=True)
    except ValueError as error:
        raise Failure("invalid certificate base64") from error
    require(base64.b64encode(der) == encoded and len(der) >= 2 and der[0] == 0x30,
            "invalid/canonical certificate DER")
    # OpenSSL's X.509 reader can ignore trailing bytes: bound the outer DER object.
    length, start = der[1], 2
    if length & 0x80:
        count = length & 0x7f
        require(1 <= count <= 4 and len(der) >= 2 + count and der[2] != 0,
                "invalid DER length")
        length, start = int.from_bytes(der[2:2 + count], "big"), 2 + count
        require(length >= 128, "noncanonical DER length")
    require(start + length == len(der), "truncated or multiple certificate DER objects")
    try:
        # No default CA store, TLS connection, certificate validity/signature or private key
        # operation. This uses the stdlib OpenSSL binding solely to parse the X.509 object.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cadata=pem.decode("ascii"))
        require(context.cert_store_stats()["x509"] == 1, "ambiguous X.509 certificate")
    except (ssl.SSLError, UnicodeError) as error:
        raise Failure("invalid X.509 certificate") from error
    return {"pem_sha256": hashlib.sha256(pem).hexdigest(),
            "certificate_sha256": hashlib.sha256(der).hexdigest()}


def signer_digest(output, expected):
    """Accept a single legacy or scheme-labelled signer, never a key/stamp digest."""
    fields = {}
    labels = set()
    counts, verifies, schemes = [], [], {}
    allowed = {"certificate DN", "certificate SHA-256 digest", "certificate SHA-1 digest",
               "certificate MD5 digest", "key algorithm", "key size (bits)",
               "public key SHA-256 digest", "public key SHA-1 digest", "public key MD5 digest"}
    stamp_seen = False
    for line in output.splitlines():
        if not line:
            continue
        if line == "Verifies":
            verifies.append(line)
        elif line.startswith("Number of signers:"):
            counts.append(line)
        elif line.startswith("Verified using "):
            match = re.fullmatch(r"Verified using (v[0-9]+(?:\.[0-9]+)*) scheme \([^\r\n()]+\): (true|false)", line)
            require(match is not None and match[1] not in schemes, "ambiguous signature schemes")
            schemes[match[1]] = match[2] == "true"
        elif line == "Verified for SourceStamp: false" and not stamp_seen:
            stamp_seen = True
        else:
            match = re.fullmatch(r"(Signer #1 |V[0-9]+(?:\.[0-9]+)* Signer: )([^:\r\n]+): ([^\r\n]*)", line)
            require(match is not None and match[2] in allowed and match[2] not in fields,
                    "unrecognized/ambiguous apksigner record: " + line)
            labels.add(match[1])
            fields[match[2]] = match[3]
    require(verifies == ["Verifies"] and counts == ["Number of signers: 1"]
            and len(labels) == 1 and any(schemes.values()), "missing/ambiguous APK verification or signer")
    digest = fields.get("certificate SHA-256 digest", "")
    require(re.fullmatch(r"[0-9a-fA-F]{64}", digest), "missing/malformed signer certificate SHA-256")
    require(digest.lower() == expected, "APK signer differs from expected public certificate")
    return digest.lower()


def rows(output, names):
    pattern = r"\s*(?:" + "|".join(re.escape(name) for name in names) + r")\b"
    return [line for line in output.splitlines() if re.match(pattern, line)]


def decimal(value):
    require(re.fullmatch(r"[0-9]+", value), "nondecimal package/SDK value")
    number = int(value)
    require(0 < number <= 0x7fffffff, "package/SDK value outside supported positive int32 range")
    return number


def parse_badging(output):
    packages = rows(output, ("package",))
    require(len(packages) == 1 and packages[0].startswith("package: "),
            "missing/malformed/ambiguous package info")
    tail, fields = packages[0][len("package: "):], {}
    while tail:
        match = re.match(r"([A-Za-z][A-Za-z0-9_]*)='([^'\r\n]*)'(?: +|$)", tail)
        require(match is not None and match[1] not in fields, "malformed/duplicate package field")
        fields[match[1]] = match[2]
        tail = tail[match.end():]
    require({"name", "versionCode", "versionName"} <= fields.keys(), "missing package fields")
    require(not ({"split", "versionCodeMajor"} & fields.keys()), "split/major package versions unsupported")
    result = {"package": package_name(fields["name"]), "version_code": decimal(fields["versionCode"]),
              "version_name": fields["versionName"], "badging_package_fields": fields}
    for key, names, optional in (("min_sdk", ("sdkVersion", "minSdkVersion"), False),
                                 ("target_sdk", ("targetSdkVersion",), False),
                                 ("max_sdk", ("maxSdkVersion",), True)):
        values = rows(output, names)
        require(len(values) == 1 or (optional and not values), "missing/ambiguous " + key)
        result[key] = None
        if values:
            match = re.fullmatch(r"(?:" + "|".join(names) + r"):'([0-9]+)'", values[0])
            require(match is not None, "malformed " + key)
            result[key] = decimal(match[1])
    native = rows(output, ("native-code",))
    require(len(native) <= 1, "ambiguous native-code badging")
    result["native_abis"] = []
    if native:
        require(re.fullmatch(r"native-code:(?: '[A-Za-z0-9_-]+')+", native[0]), "malformed native-code badging")
        result["native_abis"] = re.findall(r"'([^']+)'", native[0])
        require(result["native_abis"] == ["arm64-v8a"], "APK badging is not ARM64-only")
    return result


class Element:
    def __init__(self, tag, indent):
        self.tag, self.indent = tag, indent
        self.attrs, self.children = {}, []


def parse_xmltree(output):
    """Parse aapt2's indentation tree, not a flat search across unrelated elements."""
    stack, nodes, namespaces = [], [], {}
    for line in output.splitlines():
        match = re.fullmatch(r"( *)([NEA]): (.+)", line)
        require(match is not None, "unrecognized aapt2 XML tree row")
        indent, kind, text = len(match[1]), match[2], match[3]
        if kind == "N":
            declaration = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)=(\S+) \(line=[0-9]+\)", text)
            require(not nodes and declaration is not None and declaration[1] not in namespaces,
                    "unsupported/ambiguous XML namespace declaration")
            namespaces[declaration[1]] = declaration[2]
            continue
        while stack and stack[-1].indent >= indent:
            stack.pop()
        if kind == "E":
            element = re.fullmatch(r"([^\s()]+) \(line=[0-9]+\)", text)
            require(element is not None and (stack or not nodes), "malformed/multiple XML roots")
            node = Element(element[1], indent)
            if stack:
                stack[-1].children.append(node)
            nodes.append(node)
            stack.append(node)
        else:
            attribute = re.fullmatch(r"([^\s=()]+)(?:\(0x([0-9a-fA-F]{8})\))?=(.+)", text)
            require(stack and attribute is not None and not stack[-1].children,
                    "malformed/misplaced XML attribute")
            name = attribute[1]
            if name.startswith(ANDROID + ":"):
                name = "android:" + name[len(ANDROID) + 1:]
            elif name.startswith("android:"):
                require(namespaces.get("android") == ANDROID, "wrong Android namespace")
            resource_id = int(attribute[2], 16) if attribute[2] else None
            attrs = stack[-1].attrs
            require(name not in attrs and (resource_id is None or all(resource_id != value[0] for value in attrs.values())),
                    "duplicate XML attribute name/resource ID")
            attrs[name] = (resource_id, attribute[3])
    require(nodes and nodes[0].tag == "manifest" and sum(node.tag == "manifest" for node in nodes) == 1,
            "missing/ambiguous manifest root")
    return nodes


def attribute(node, name):
    require(name in node.attrs, "missing " + node.tag + " attribute " + name)
    resource_id, value = node.attrs[name]
    expected_id = ATTR_IDS[name[len("android:"):]] if name.startswith("android:") else None
    require(resource_id == expected_id, "wrong compiled attribute ID: " + name)
    return value


def string(node, name):
    value = attribute(node, name)
    match = re.fullmatch(r'"([^"\\\r\n]*)"(?: \(Raw: "([^"\\\r\n]*)"\))?', value)
    require(match is not None and (match[2] is None or match[1] == match[2]),
            "nonliteral/ambiguous string: " + name)
    return match[1]


def integer(node, name):
    value = attribute(node, name)
    match = re.fullmatch(r"(?:\(type 0x1[01]\))?(0x[0-9a-fA-F]+|[0-9]+)", value)
    require(match is not None, "nonliteral integer: " + name)
    number = int(match[1], 16 if match[1].startswith("0x") else 10)
    require(0 < number <= 0x7fffffff, "manifest integer outside supported positive int32 range")
    return number


def one_child(nodes, parent, tag):
    found = [node for node in nodes if node.tag == tag]
    require(len(found) == 1 and found[0] in parent.children, "missing/ambiguous/misplaced " + tag)
    return found[0]


def pin_digest(value):
    require(re.fullmatch(r"[0-9a-fA-F]{64}|(?:[0-9a-fA-F]{2}:){31}[0-9a-fA-F]{2}", value),
            "malformed static-library SHA-256 pin")
    return value.replace(":", "").lower()


def check_metadata(badging, xmltree, expected_package, role):
    info = parse_badging(badging)
    nodes = parse_xmltree(xmltree)
    manifest = nodes[0]
    require(info["package"] == string(manifest, "package") == expected_package, "wrong/inconsistent APK package")
    require(not ({"split", "android:versionCodeMajor"} & manifest.attrs.keys())
            and not any(node.tag == "uses-split" for node in nodes), "split/major package versions unsupported")
    require(info["version_code"] == integer(manifest, "android:versionCode"), "inconsistent package version code")
    version_name = string(manifest, "android:versionName") if "android:versionName" in manifest.attrs else None
    require(info["version_name"] == (version_name if version_name is not None else ""), "inconsistent version name")
    info["version_name"] = version_name
    sdk = one_child(nodes, manifest, "uses-sdk")
    for key, name in (("min_sdk", "minSdkVersion"), ("target_sdk", "targetSdkVersion"), ("max_sdk", "maxSdkVersion")):
        value = integer(sdk, "android:" + name) if "android:" + name in sdk.attrs else None
        require(info[key] == value, "inconsistent manifest/badging " + key)
    require(info["target_sdk"] >= info["min_sdk"]
            and (info["max_sdk"] is None or info["max_sdk"] >= info["min_sdk"]), "invalid SDK range")
    for name, getter in (("compileSdkVersion", integer), ("compileSdkVersionCodename", string)):
        value = getter(manifest, "android:" + name) if "android:" + name in manifest.attrs else None
        badged = info["badging_package_fields"].get(name)
        require(badged == (str(value) if value is not None else None), "inconsistent " + name)
        info[name] = value
    application = one_child(nodes, manifest, "application")
    allowed_tag = {"webview": "uses-static-library", "library": "static-library", "config": None}[role]
    for tag in ("uses-static-library", "static-library"):
        if tag != allowed_tag:
            require(not any(node.tag == tag for node in nodes), "unexpected " + tag + " in " + role)
    if allowed_tag:
        declaration = one_child(nodes, application, allowed_tag)
        keys = {"android:name", "android:version"}
        if role == "webview":
            keys.add("android:certDigest")
        require(set(declaration.attrs) == keys and not declaration.children,
                "unsupported/ambiguous static-library attributes or additional certificates")
        info[allowed_tag] = {"name": package_name(string(declaration, "android:name")),
                             "version": integer(declaration, "android:version")}
        if role == "webview":
            info[allowed_tag]["certificate_sha256"] = pin_digest(string(declaration, "android:certDigest"))
            metadata = [node for node in nodes if node.tag == "meta-data"
                        and string(node, "android:name") == "com.android.webview.WebViewLibrary"]
            require(len(metadata) == 1 and metadata[0] in application.children,
                    "missing/ambiguous/misplaced WebViewLibrary metadata")
            require(set(metadata[0].attrs) == {"android:name", "android:value"} and not metadata[0].children,
                    "WebViewLibrary must have one literal value, not a resource")
            library = string(metadata[0], "android:value")
            require(re.fullmatch(r"lib[A-Za-z0-9_.+-]+\.so", library), "invalid WebViewLibrary filename")
            info["webview_library"] = library
    return info


def check_archive(apk, *, role=None):
    """Stream/CRC-check entries; never extract. Header checks are not ELF qualification.

    Only an explicit webview role permits Chromium's empty ARM64 ABI marker.
    """
    require(role is None or role in ROLES, "unknown APK archive role")
    libraries, abi_markers, manifest, names = [], [], None, set()
    with zipfile.ZipFile(apk) as archive:
        for entry in archive.infolist():
            name = entry.filename
            parts = (name[:-1] if entry.is_dir() else name).split("/")
            require(name == entry.orig_filename and name not in names and "\\" not in name
                    and not any(part in ("", ".", "..") for part in parts), "ambiguous APK ZIP path/duplicate entry")
            names.add(name)
            kind = stat.S_IFMT(entry.external_attr >> 16)
            require(kind in (0, stat.S_IFDIR if entry.is_dir() else stat.S_IFREG), "nonregular APK ZIP entry")
            if parts[0] == "lib":
                require((entry.is_dir() and parts == ["lib"])
                        or (len(parts) >= 2 and parts[1] == "arm64-v8a"), "non-ARM64/mixed native ABI directory")
            if entry.is_dir():
                require(entry.file_size == 0, "nonempty ZIP directory")
                require(parts[-1] != "libplaceholder.so", "ABI marker must be a regular ZIP entry")
                continue
            digest, header = hashlib.sha256(), b""
            with archive.open(entry) as source:
                for block in iter(lambda: source.read(1024 * 1024), b""):
                    header = (header + block[:64])[:64]
                    digest.update(block)
            record = {"path": name, "size_bytes": entry.file_size, "sha256": digest.hexdigest()}
            if name == "AndroidManifest.xml":
                require(len(header) >= 8 and header[:4] == b"\x03\x00\x08\x00"
                        and struct.unpack_from("<I", header, 4)[0] == entry.file_size,
                        "AndroidManifest.xml is not a bounded binary XML container")
                manifest = record
            if parts[-1] == "libplaceholder.so":
                # Chromium apkbuilder.py writes native_lib_placeholders as empty ZIP entries.
                require(role == "webview" and name == WEBVIEW_ABI_MARKER
                        and entry.file_size == 0 and not header,
                        "ABI marker requires WebView role and exact empty " + WEBVIEW_ABI_MARKER)
                abi_markers.append(record)
            elif name.startswith("lib/") or name.lower().endswith(".so") or header.startswith(b"\x7fELF"):
                require(re.fullmatch(r"lib/arm64-v8a/[A-Za-z0-9_.+-]+\.so", name), "native payload outside ARM64 lib directory")
                require(len(header) == 64 and header[:7] == b"\x7fELF\x02\x01\x01"
                        and struct.unpack_from("<HHI", header, 16) == (3, 183, 1),
                        "native library is not ELF64 little-endian AArch64 DYN v1")
                libraries.append(record)
    require(manifest is not None, "missing binary AndroidManifest.xml")
    return {"manifest": manifest, "native_libraries": sorted(libraries, key=lambda item: item["path"]),
            "abi_markers": sorted(abi_markers, key=lambda item: item["path"]),
            "native_abis": ["arm64-v8a"] if libraries or abi_markers else []}


def check_relationships(apks, expected):
    use = apks["webview"]["metadata"]["uses-static-library"]
    library = apks["library"]["metadata"]["static-library"]
    require(use["name"] == library["name"], "static-library namespace mismatch")
    require(use["version"] == library["version"], "static-library version mismatch")
    require(use["certificate_sha256"] == apks["library"]["signer_certificate_sha256"] == expected,
            "static-library certificate pin/signer mismatch")
    # ABI markers are not payloads; only validated native libraries can satisfy this.
    native_path = "lib/arm64-v8a/" + apks["webview"]["metadata"]["webview_library"]
    require(native_path in [entry["path"] for entry in apks["library"]["archive"]["native_libraries"]],
            "WebViewLibrary native payload missing from TrichromeLibrary APK")
    return {"namespace": use["name"], "version": use["version"], "certificate_sha256": expected,
            "webview_library_path_in_library_apk": native_path}


class Runner:
    def __init__(self, args):
        self.args, self.evidence, self.sequence = args, args.evidence.resolve(), 0
        self.summary = {"schema": 1, "verdict": "FAIL", "scope": "Isolated APK static checks only",
                        "config_info_trust": "UNVERIFIED", "runtime_verified": False,
                        "unverified": UNVERIFIED, "apks": {}, "tools": {}}

    def command(self, arguments, timeout=120, version_stderr_pattern=None):
        self.sequence += 1
        stem = self.evidence / f"{self.sequence:03d}"
        record = {"argv": [str(arg) for arg in arguments], "timeout_seconds": timeout,
                  "cwd": str(Path.cwd()), "environment_overrides": {"LC_ALL": "C", "LANG": "C"}}
        with open(str(stem) + ".stdout", "wb") as stdout, open(str(stem) + ".stderr", "wb") as stderr:
            try:
                completed = subprocess.run(record["argv"], stdin=subprocess.DEVNULL, stdout=stdout,
                                           stderr=stderr, timeout=timeout, check=False,
                                           env={**os.environ, **record["environment_overrides"]})
                record["returncode"] = completed.returncode
            except BaseException as error:
                record["exception"] = type(error).__name__ + ": " + str(error)
                raise
            finally:
                Path(str(stem) + ".command.json").write_text(json.dumps(record, indent=2) + "\n")
        require(completed.returncode == 0, f"command {self.sequence:03d} failed; see raw evidence")
        stdout_text = Path(str(stem) + ".stdout").read_text(encoding="utf-8")
        stderr_text = Path(str(stem) + ".stderr").read_text(encoding="utf-8")
        if stderr_text.strip():
            # Pinned AOSP aapt2 writes its version to stderr. Accept only that
            # standalone version row, never diagnostics mixed with metadata.
            require(version_stderr_pattern is not None and not stdout_text.strip()
                    and re.fullmatch(version_stderr_pattern, stderr_text.strip()),
                    f"command {self.sequence:03d} produced unexpected stderr; see raw evidence")
            return stderr_text
        return stdout_text

    def run(self):
        failure = None
        try:
            self.summary["checker_sources"] = {
                name: sha256(Path(__file__).with_name(name))
                for name in ("webview_artifacts.py", "ordinary_app.py")}
            cert_path = self.args.expected_cert.resolve(strict=True)
            with cert_path.open("rb") as source:
                pem = source.read(65537)
            cert = certificate_info(pem)
            self.summary["expected_certificate"] = {"input_path": str(cert_path), **cert}
            (self.evidence / "expected-certificate.pem").write_bytes(pem)
            expected = cert["certificate_sha256"]
            # Snapshot all three first. Only evidence is written; tools never inspect a
            # live build output. Input and snapshot hashes are checked again at the end.
            for role in ROLES:
                source = getattr(self.args, role + "_apk").resolve(strict=True)
                snapshot = self.evidence / (role + ".apk")
                before = sha256(source)
                record = {"input_path": str(source), "snapshot_path": str(snapshot),
                          "sha256": before, "expected_package": getattr(self.args, role + "_package")}
                self.summary["apks"][role] = record
                shutil.copyfile(source, snapshot)
                require(sha256(snapshot) == before, "input changed while snapshotting " + role)
            for name in ("aapt2", "apksigner"):
                tool = getattr(self.args, name)
                version_pattern = (r"Android Asset Packaging Tool \(aapt\) [0-9A-Za-z.+_-]+"
                                   if name == "aapt2" else None)
                self.summary["tools"][name] = {
                    "path": str(tool), "launcher_sha256": sha256(tool),
                    "version_output": self.command([tool, "version"],
                                                   version_stderr_pattern=version_pattern)}
            for role, record in self.summary["apks"].items():
                apk = Path(record["snapshot_path"])
                record["signer_certificate_sha256"] = signer_digest(self.command([
                    self.args.apksigner, "verify", "--verbose", "--print-certs", "--Werr", apk]), expected)
                record["archive"] = check_archive(apk, role=role)
                record["metadata"] = check_metadata(
                    self.command([self.args.aapt2, "dump", "badging", apk]),
                    self.command([self.args.aapt2, "dump", "xmltree", apk, "--file", "AndroidManifest.xml"]),
                    record["expected_package"], role)
                require(record["metadata"]["native_abis"] == record["archive"]["native_abis"],
                        role + " native ABI badging/archive mismatch")
            self.summary["static_library_relationship"] = check_relationships(self.summary["apks"], expected)
            for record in self.summary["apks"].values():
                require(sha256(record["input_path"]) == sha256(record["snapshot_path"]) == record["sha256"],
                        "APK input/snapshot changed during verification")
            require(sha256(cert_path) == sha256(self.evidence / "expected-certificate.pem") == cert["pem_sha256"],
                    "expected certificate changed during verification")
            for tool in self.summary["tools"].values():
                require(sha256(tool["path"]) == tool["launcher_sha256"], "tool launcher changed during verification")
            self.summary["verdict"] = "PASS"
        except (Exception, KeyboardInterrupt) as error:
            failure = type(error).__name__ + ": " + str(error)
        finally:
            self.summary["failure"] = failure
            (self.evidence / "summary.json").write_text(json.dumps(self.summary, indent=2) + "\n")
        if failure:
            raise Failure(failure)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for role in ROLES:
        parser.add_argument("--" + role + "-apk", required=True, type=Path)
        parser.add_argument("--" + role + "-package", required=True, help="explicit expected package name")
    parser.add_argument("--expected-cert", required=True, type=Path, help="one PUBLIC X.509 certificate PEM, never a key")
    for tool in ("aapt2", "apksigner"):
        parser.add_argument("--" + tool, required=True, type=Path, help="explicit pinned executable path")
    parser.add_argument("--evidence", required=True, type=Path, help="NEW directory outside this checkout; never overwritten/deleted")
    args = parser.parse_args(argv)
    try:
        packages, paths = [], []
        for role in ROLES:
            packages.append(package_name(getattr(args, role + "_package")))
            path = getattr(args, role + "_apk").resolve(strict=True)
            require(path.is_file() and path.suffix == ".apk", "exact APK file required")
            paths.append(path)
        require(len(set(packages)) == len(set(paths)) == 3, "three distinct packages and APK paths required")
        require(args.expected_cert.is_file(), "public certificate file required")
        for tool in ("aapt2", "apksigner"):
            path = getattr(args, tool).resolve(strict=True)
            require(path.is_file() and os.access(path, os.X_OK), "executable tool required: " + tool)
            setattr(args, tool, path)
        root = Path(__file__).resolve().parents[2]
        evidence = args.evidence.resolve()
        require(evidence != root and root not in evidence.parents, "evidence must be outside this checkout")
        evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
        Runner(args).run()
        print("PASS: scoped APK signature/manifest/ARM64 packaging checks only; compiled ConfigInfo trust UNVERIFIED.")
        print("Evidence: " + str(evidence))
        return 0
    except (Exception, KeyboardInterrupt) as error:
        print("FAIL: " + str(error) + "; inspect evidence; no integration/runtime proof.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
