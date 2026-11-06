from pathlib import Path
import argparse,importlib.util,json,os,plistlib,re,subprocess,tempfile,time,uuid
parser=argparse.ArgumentParser(description='Opt-in real launchd test using temporary sleep/true agents, never production services.')
parser.add_argument('--allow-temporary-agents',action='store_true')
args=parser.parse_args()
if not args.allow_temporary_agents:parser.error('Pass --allow-temporary-agents to permit creating and removing separate temporary user agents.')
if os.geteuid()==0:parser.error('Run as the logged-in ordinary user, not root.')
base=Path(__file__).resolve().parent
repo=base.parent
spec=importlib.util.spec_from_file_location('subject',repo/'portable/src/controller.py');C=importlib.util.module_from_spec(spec);spec.loader.exec_module(C)
domain='gui/'+str(os.getuid());suffix=uuid.uuid4().hex
labels=['local.claude-network-kit.test.'+suffix+'.menu','local.claude-network-kit.test.'+suffix+'.watch']
report={'scope':'Only separately named temporary user agents, sleep/true executables; no production services, network, proxy or firewall changes','checks':[],'cleanup':[]}
def raw(args):return subprocess.run(list(map(str,args)),capture_output=True,text=True,timeout=6)
def inspect(label):return raw(['/bin/launchctl','print',domain+'/'+label])
def pid(label):
 p=inspect(label);m=re.search(r'^\s*pid = (\d+)',p.stdout,re.M);return int(m[1]) if m else None
with tempfile.TemporaryDirectory(prefix='launchd-check-',dir=base) as folder:
 folder=Path(folder)
 try:
  for label in labels:assert inspect(label).returncode==113,'Unique label unexpectedly exists'
  C.register_user_agent(domain,labels[0],['/bin/sleep','120'],{},folder);first=pid(labels[0]);assert first
  C.register_user_agent(domain,labels[0],['/bin/sleep','120'],{},folder);second=pid(labels[0]);assert second and first!=second
  report['checks'].append({'test':'live_menu_full_reload','passed':True})
  C.register_user_agent(domain,labels[1],['/usr/bin/true'],{'StartInterval':3600},folder)
  path=folder/(labels[1]+'.plist');data=plistlib.loads(path.read_bytes());data['StartInterval']=30;path.write_bytes(plistlib.dumps(data))
  before=inspect(labels[1]);old=re.search(r'run interval = (\d+) seconds',before.stdout);assert old and int(old[1])==3600,'Unable to establish stale loaded interval'
  C.register_user_agent(domain,labels[1],['/usr/bin/true'],{'StartInterval':30},folder)
  after=inspect(labels[1]);new=re.search(r'run interval = (\d+) seconds',after.stdout);assert new and int(new[1])==30,'Loaded interval not updated'
  report['checks'].append({'test':'live_loaded_interval_3600_to_30_despite_matching_file_and_arguments','passed':True})
  report['passed']=True
 except Exception as e:
  report['passed']=False;report['failure_type']=type(e).__name__;report['failure_detail']=str(e)[:400]
 finally:
  for label in labels:
   if inspect(label).returncode==0:raw(['/bin/launchctl','bootout',domain+'/'+label])
   deadline=time.monotonic()+5
   while inspect(label).returncode==0 and time.monotonic()<deadline:time.sleep(.1)
   report['cleanup'].append({'test_agent_removed':inspect(label).returncode==113})
report['passed']=report.get('passed',False) and all(x['test_agent_removed'] for x in report['cleanup'])
(repo/'user-agents-test-report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
print(json.dumps(report,ensure_ascii=False,indent=2))
raise SystemExit(0 if report['passed'] else 1)
