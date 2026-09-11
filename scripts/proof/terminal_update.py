#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Prepare a separate verified APK/v4 update pair. Never install it in a factory image."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import subprocess
import zipfile


def sha(path):
    with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()


def payload(apk):
    with zipfile.ZipFile(apk) as z:
        names=z.namelist()
        if len(names)!=len(set(names)):raise ValueError('Duplicate APK ZIP entries')
        # Only JAR signing metadata may change, not arbitrary META-INF resources.
        signature=re.compile(r'META-INF/(?:MANIFEST\.MF|[^/]+\.(?:SF|RSA|DSA|EC))$',re.I)
        return {name:hashlib.sha256(z.read(name)).hexdigest() for name in names if not signature.fullmatch(name)}


def signer_matches(text,digest):
    certs=re.findall(r'^(?:Signer #1 |V[0-9.]+ Signer: )certificate SHA-256 digest: ([0-9a-f]+)$',text,re.M)
    return 'Number of signers: 1' in text and certs==[digest]


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-root',type=Path,required=True)
    p.add_argument('--apk',type=Path,required=True)
    p.add_argument('--apk-sha256',required=True)
    p.add_argument('--key',type=Path,required=True)
    p.add_argument('--cert',type=Path,required=True)
    p.add_argument('--cert-sha256',required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();os.umask(0o077);root=a.source_root.resolve();out=a.output.resolve()
    repo=Path(__file__).resolve().parents[2]
    if out.is_relative_to(root) or out.is_relative_to(repo):raise ValueError('Update outputs must stay outside source/image trees')
    if sha(a.apk)!=a.apk_sha256:raise ValueError('Input APK differs from frozen receipt')
    out.mkdir(parents=True,exist_ok=False)
    env={**os.environ,'PATH':str(root/'prebuilts/jdk/jdk25/linux-x86/bin')+':'+os.environ['PATH']}
    signer=root/'out/host/linux-x86/bin/apksigner'
    def run(label,args):
        q=subprocess.run(list(map(str,args)),env=env,text=True,capture_output=True,timeout=90)
        (out/(label+'.stdout')).write_text(q.stdout);(out/(label+'.stderr')).write_text(q.stderr)
        (out/(label+'.status')).write_text('exit_code='+str(q.returncode)+'\n')
        if q.returncode:raise RuntimeError(label+' failed')
        return q.stdout
    original=run('source-signature',[signer,'verify','--verbose','--print-certs',a.apk])
    if not signer_matches(original,a.cert_sha256):raise ValueError('Input signer differs')
    target=out/'AndrixTerminal.apk'
    run('sign',[signer,'sign','--key',a.key,'--cert',a.cert,'--v4-signing-enabled','true','--min-sdk-version','37','--out',target,a.apk])
    sidecar=out/'AndrixTerminal.apk.idsig'
    verified=run('update-signature',[signer,'verify','--verbose','--print-certs','--v4-signature-file',sidecar,target])
    if not signer_matches(verified,a.cert_sha256) or 'Verified using v4 scheme (APK Signature Scheme v4): true' not in verified:
        raise ValueError('Update pair did not pass the explicit v4/signer checks')
    if payload(a.apk)!=payload(target):raise ValueError('Non-signature APK payload changed')
    run('alignment',[root/'out/host/linux-x86/bin/zipalign','-c','-P','16','4',target])
    result={'source_apk_sha256':a.apk_sha256,'apk_sha256':sha(target),'idsig_sha256':sha(sidecar),
            'signer_sha256':a.cert_sha256,'non_signature_payload_identical':True,'v4_verified':True,
            'factory_image_input':False,'Android_installation_proved':False}
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))


if __name__=='__main__':main()
