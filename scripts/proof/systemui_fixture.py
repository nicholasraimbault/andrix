#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Prepare SystemUI proof patches only. Never apply, build, sign or install them."""
from pathlib import Path
import argparse
import difflib
import hashlib
import json

BP = 'packages/SystemUI/Android.bp'
CLOCK = 'packages/SystemUI/src/com/android/systemui/statusbar/policy/Clock.java'
MODULE = 'android_app {\n    name: "SystemUI",\n'
NORMAL = 'CharSequence smallTime = getSmallTime();'
DEMO = 'setText(getSmallTime());'
DESCRIPTION = 'setContentDescription(mContentDescriptionFormat.format(mCalendar.getTime()));'
METHOD = '    private CharSequence getSmallTime() {'
VARIANTS = [('A', 'marker'), ('R', 'restore'), ('B', 'bad'), ('C', 'restore')]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def change_blueprint(text, version):
    if not 0 < version <= 0x7fffffff:
        raise ValueError('Version must fit this fixture\'s positive APK versionCode')
    if text.count(MODULE) != 1:
        raise ValueError('Expected one SystemUI android_app target')
    begin = text.index(MODULE)
    end = text.find('\n}\n', begin)
    if end < 0:
        raise ValueError('Missing SystemUI module end')
    block = text[begin:end]
    if 'aaptflags:' in block:
        raise ValueError('Refuse an existing SystemUI aaptflags configuration')
    for required in ['platform_apis: true', 'certificate: "platform"',
                     'privileged: true', 'system_ext_specific: true']:
        if required not in block:
            raise ValueError('SystemUI source contract missing: '+required)
    return text.replace(MODULE, MODULE+'    aaptflags: ["--version-code", "'+str(version)+'"],\n', 1)


def change_clock(text, mode):
    if mode not in ['marker', 'restore', 'bad']:
        raise ValueError('Unknown fixture mode')
    if 'andrixWorkshopTime' in text:
        raise ValueError('Already modified Clock source')
    for token, count in [(NORMAL, 1), (DEMO, 1), (DESCRIPTION, 2), (METHOD, 1)]:
        if text.count(token) != count:
            raise ValueError('Clock source contract differs: '+token)
    if mode == 'restore':
        return text
    value = ('android.text.TextUtils.concat(time, " WS-A")'
             if mode == 'marker' else '"WS-B BAD"')
    helper = ('    // Disposable workshop proof, not a shipped clock feature.\n'
              '    private CharSequence andrixWorkshopTime(CharSequence time) {\n'
              '        return '+value+';\n'
              '    }\n\n')
    text = text.replace(NORMAL, 'CharSequence smallTime = andrixWorkshopTime(getSmallTime());')
    text = text.replace(DEMO, 'setText(andrixWorkshopTime(getSmallTime()));')
    text = text.replace(DESCRIPTION,
                        'setContentDescription(andrixWorkshopTime(\n'
                        '                mContentDescriptionFormat.format(mCalendar.getTime())));')
    return text.replace(METHOD, helper+METHOD)


def make_variants(blueprint, clock, baseline_version):
    if not 0 < baseline_version <= 0x7fffffff-len(VARIANTS):
        raise ValueError('Baseline version has no bounded increasing fixture range')
    result = []
    for offset, (label, mode) in enumerate(VARIANTS, 1):
        version = baseline_version+offset
        sources = {BP: change_blueprint(blueprint, version), CLOCK: change_clock(clock, mode)}
        patch = ''.join(''.join(difflib.unified_diff(before.splitlines(keepends=True),
                                                   sources[name].splitlines(keepends=True),
                                                   fromfile='a/'+name, tofile='b/'+name))
                        for name, before in [(BP, blueprint), (CLOCK, clock)])
        result.append({'label': label, 'mode': mode, 'version': version,
                       'sources': sources, 'patch': patch})
    return result


def prepare(source_root, output, bp_sha256, clock_sha256, baseline_version):
    source_root = Path(source_root).resolve(strict=True)
    output = Path(output).resolve()
    repo = Path(__file__).resolve().parents[2]
    if output.is_relative_to(source_root) or output.is_relative_to(repo):
        raise ValueError('Fixture outputs must be outside source and repository')
    if output.exists():
        raise ValueError('Fresh output directory required')
    files = {name: (source_root/'frameworks/base'/name).read_bytes() for name in [BP, CLOCK]}
    if sha(files[BP]) != bp_sha256 or sha(files[CLOCK]) != clock_sha256:
        raise ValueError('Inspected source hash differs')
    variants = make_variants(files[BP].decode(), files[CLOCK].decode(), baseline_version)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    report = {'baseline_version': baseline_version,
              'original_sha256': {name: sha(data) for name, data in files.items()},
              'variants': [], 'source_modified': False, 'component_built': False,
              'signing_or_installation_performed': False,
              'complete_build_dependency_closure_verified': False}
    for variant in variants:
        folder = output/variant['label']
        folder.mkdir(mode=0o700)
        for name, text in variant['sources'].items():
            path = folder/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        patch = folder/'framework.patch'
        patch.write_text(variant['patch'])
        report['variants'].append({
            'label': variant['label'], 'mode': variant['mode'], 'version': variant['version'],
            'sha256': {name: sha(text.encode()) for name, text in variant['sources'].items()},
            'patch_sha256': sha(patch.read_bytes()),
            'clock_is_original': variant['sources'][CLOCK].encode() == files[CLOCK]})
    for name, original in files.items():
        if (source_root/'frameworks/base'/name).read_bytes() != original:
            raise RuntimeError('Source changed during fixture preparation')
    (output/'recipe.json').write_text(json.dumps(report, indent=2)+'\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--bp-sha256', required=True)
    parser.add_argument('--clock-sha256', required=True)
    parser.add_argument('--baseline-version', type=int, required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.source_root, args.output, args.bp_sha256,
                             args.clock_sha256, args.baseline_version), indent=2))


if __name__ == '__main__':
    main()
