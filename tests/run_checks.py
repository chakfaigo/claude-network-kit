"""Run isolated regressions; --core additionally validates the native core offline."""
from pathlib import Path
import argparse,hashlib,json,os,re,subprocess,sys
BASE=Path(__file__).resolve().parent.parent

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--core',action='store_true');parser.add_argument('--user-agents',action='store_true',help='Create and clean up separate temporary user agents on a logged-in Mac');args=parser.parse_args()
    # Legacy harnesses load adjacent copies. Never silently test stale sources.
    for name in ('guard_health.py','guard_notify.py','guard_pf.py','guard_runtime.py'):
        if (BASE/'tests'/name).read_bytes()!=(BASE/'portable/src'/name).read_bytes():
            raise RuntimeError('Legacy test subject differs from distributed source: '+name)
    rows=[];total=0
    for path in sorted((BASE/'tests').glob('test_*.py')):
        p=subprocess.run([sys.executable,'-B',str(path)],cwd=BASE,capture_output=True,text=True,timeout=90,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'})
        output=p.stdout+'\n'+p.stderr;count=None
        for line in p.stdout.splitlines():
            try:value=json.loads(line)
            except ValueError:continue
            if isinstance(value,dict) and 'tests_run' in value:count=value['tests_run']
        match=re.search(r'Ran (\d+) tests?',output)
        if match:count=int(match[1])
        row={'suite':path.name,'exit':p.returncode,'tests':count};rows.append(row);print(json.dumps(row),flush=True)
        if p.returncode or not isinstance(count,int):
            print(output);raise RuntimeError('Suite failed or test count unavailable: '+path.name)
        total+=count
    if args.core:
        subprocess.run([sys.executable,'-B',str(BASE/'tests/check_core.py')],cwd=BASE,check=True,timeout=90)
    if args.user_agents:
        subprocess.run([sys.executable,'-B',str(BASE/'tests/check_user_agents.py'),'--allow-temporary-agents'],cwd=BASE,check=True,timeout=90)
    report={'passed':True,'tests':total,'suites':rows,'native_core_checked':args.core,'temporary_user_agents_checked':args.user_agents,
            'source_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((BASE/'portable/src').glob('*.py'))},
            'scope':'Isolated logic and optional offline native syntax/domain checks; not target-machine acceptance'}
    (BASE/'release-test-report.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS: '+str(total)+' isolated tests'+(' + offline native core checks' if args.core else ''))
if __name__=='__main__':main()
