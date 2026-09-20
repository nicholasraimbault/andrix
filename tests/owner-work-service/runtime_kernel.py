#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Real runtime controls, only in one explicitly owned systemd delegation."""
from pathlib import Path
import ctypes,json,os,re,resource,select,signal,subprocess,sys,time

def require(value, message):
    if not value: raise RuntimeError(message)

def main():
    rows=Path('/proc/self/cgroup').read_text().splitlines()
    relative=next(line[3:] for line in rows if line.startswith('0::'))
    own=Path('/sys/fs/cgroup')/relative.lstrip('/');root=own.parent
    require(own.name=='control' and re.fullmatch(r'andrix-work-runtime-kernel-[0-9]{8}t[0-9]{6}z\.service',root.name),'owned work runtime proof delegation only')
    require(root.resolve()==root and root.is_relative_to(f'/sys/fs/cgroup/user.slice/user-{os.getuid()}.slice'),'owned runtime hierarchy')
    limits={name:(root/name).read_text().strip() for name in ['memory.max','memory.swap.max','cpu.max','pids.max']}
    require(limits=={'memory.max':str(512<<20),'memory.swap.max':'0','cpu.max':'200000 100000','pids.max':'128'},'actual runtime resource limits')
    evidence=Path(__file__).resolve().parent
    (evidence/'limits.json').write_text(json.dumps({'root':str(root),'limits':limits},indent=2)+'\n')
    require(resource.getrlimit(resource.RLIMIT_CORE)==(0,0),'zero core limit')
    require(len(sys.argv)==2,'explicit frozen native runtime probe')
    require(ctypes.CDLL(None,use_errno=True).prctl(36,1,0,0,0)==0,'fixture subreaper')
    flags=os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW
    manager=root/'manager_control';work=root/'work'
    require(not manager.exists() and not work.exists(),'fresh private namespace')
    manager.mkdir();work.mkdir()
    identities={str(path):path.stat().st_ino for path in [manager,work]}
    kills=[os.open(path/'cgroup.kill',os.O_WRONLY|os.O_CLOEXEC|os.O_NOFOLLOW) for path in [manager,work]]
    aggregate=os.open(root,flags);namespace=os.open(work,flags)
    placement=os.open(manager/'cgroup.procs',os.O_WRONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
    process=None
    try:
        def place():
            os.write(placement,str(os.getpid()).encode())
        process=subprocess.Popen([sys.argv[1],'--manager',str(aggregate),str(namespace)],pass_fds=(aggregate,namespace,placement),preexec_fn=place,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        out,err=process.communicate(timeout=100)
        print(out,end='');print(err,end='',file=sys.stderr)
        require(process.returncode==0,'native runtime controls failed')
        observed=json.loads(out);require(observed['real_cgroup_runtime'] and not observed['Android_authority_profile_or_phone_qualified'],'native observation scope')
        require(not [x for x in work.iterdir() if x.is_dir()],'all work scopes actually removed')
        require('populated 0' in (work/'cgroup.events').read_text(),'actual final empty')
    finally:
        for fd in kills:os.write(fd,b'1')
        if process is not None:
            try:process.wait(timeout=10)
            except subprocess.TimeoutExpired:pass
        until=time.monotonic()+10
        while time.monotonic()<until:
            while True:
                try:
                    pid,_=os.waitpid(-1,os.WNOHANG)
                    if not pid:break
                except ChildProcessError:break
            if all('populated 0' in (path/'cgroup.events').read_text() for path in [manager,work]):break
            time.sleep(.02)
        for path in [manager,work]:require(path.stat().st_ino==identities[str(path)] and 'populated 0' in (path/'cgroup.events').read_text(),'owned cleanup empty')
        # Only this exclusive, freshly created work namespace. No mount/path or
        # process-name ownership inference is used to reclaim outside it.
        for path in sorted([x for x in work.rglob('*') if x.is_dir()],key=lambda x:len(x.parts),reverse=True):path.rmdir()
        work.rmdir();manager.rmdir()
        for fd in [aggregate,namespace,placement,*kills]:os.close(fd)
        (evidence/'final-cgroup.json').write_text(json.dumps({name:(root/name).read_text().strip() for name in ['memory.peak','memory.events','memory.swap.peak','cpu.stat']},indent=2)+'\n')

if __name__=='__main__':main()
