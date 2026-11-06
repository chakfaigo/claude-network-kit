"""Portable installer tests: all OS commands are fake; writes confined to test jail."""
from pathlib import Path
import fcntl,contextlib,copy,importlib.util,io,json,os,plistlib,shutil,socket,subprocess,sys,tempfile,types,unittest
from unittest import mock
BASE=Path(__file__).resolve().parent.parent
SRC=BASE/'portable/src'
JAIL=None;ACTIVE=False
NODE={'server':'gateway.example.test','port':8001,'username':'fixture-user','password':'fixture-secret','expected_ip':'93.184.216.34'}
UPSTREAM={'type':'vmess','server':'us-one.example.test','server_port':8080,'uuid':'11111111-1111-4111-8111-111111111111','security':'auto','alter_id':0,'transport':{'type':'ws','path':'/fixture','headers':{'Host':'us-one.example.test'}}}
WITH_UPSTREAM=dict(NODE,upstream=UPSTREAM)
def audit(event,args):
 if not ACTIVE:return
 if event.startswith(('socket.','subprocess.')) or event in ('os.system','os.posix_spawn','os.kill'):raise AssertionError('External operation forbidden')
 def writable(value, dirfd=None):
  if isinstance(value,int):return
  p=Path(os.fsdecode(value))
  if not p.is_absolute() and isinstance(dirfd,int) and dirfd>=0:
   parent=fcntl.fcntl(dirfd,fcntl.F_GETPATH,b'\0'*1024).split(b'\0',1)[0]
   p=Path(os.fsdecode(parent))/p
  p=p.resolve()
  if p!=JAIL and JAIL not in p.parents:raise AssertionError('Write outside jail: '+str(p))
 if event=='open' and len(args)>2 and args[2]&(os.O_CREAT|os.O_TRUNC|os.O_WRONLY|os.O_RDWR|os.O_APPEND):writable(args[0])
 if event in ('os.remove','os.rmdir'):writable(args[0],args[1] if len(args)>1 else None)
 if event in ('os.mkdir','os.chmod','os.chown','os.utime'):writable(args[0],args[2] if event in ('os.mkdir','os.chmod') and len(args)>2 else None)
 if event in ('os.rename','os.link'):writable(args[0]);writable(args[1])
 if event=='os.symlink':writable(args[1])
def load(n):
 spec=importlib.util.spec_from_file_location(n,SRC/(n+'.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
C=I=U=H=R=None
PF_BASE='scrub-anchor "com.apple/*"\nnat-anchor "com.apple/*"\nrdr-anchor "com.apple/*"\ndummynet-anchor "com.apple/*"\nanchor "com.apple/*"\nload anchor "com.apple" from "/etc/pf.anchors/com.apple"\n'
class ConfigTests(unittest.TestCase):
 def test_origin_has_no_residential_or_auth_material(self):
  v=C.build(NODE,'en0','/fixture','original');self.assertTrue(all(x['type']=='direct' for x in v['outbounds']));self.assertNotIn(NODE['password'],json.dumps(v));self.assertEqual(v['route']['final'],'original')
 def test_origin_rejects_targets_before_domestic_and_ordinary(self):
  v=C.build(NODE,'en0','/fixture','original');rules=v['route']['rules'];i=next(i for i,r in enumerate(rules) if 'anthropic.com' in r.get('domain_suffix',[]));self.assertEqual(rules[i]['action'],'reject');self.assertLess(i,next(i for i,r in enumerate(rules) if 'rule_set' in r));self.assertEqual(v['dns']['rules'][1]['rcode'],'REFUSED')
 def test_home_protected_and_dns_use_residential(self):
  v=C.build(NODE,'en0','/fixture','home');self.assertEqual(v['route']['rules'][4]['outbound'],'residential');self.assertEqual(v['dns']['rules'][1]['server'],'remote-dns');self.assertEqual(v['dns']['servers'][1]['detour'],'residential')
 def test_blocked_keeps_unknown_home_path_but_denies_targets(self):
  v=C.build(NODE,'en0','/fixture','home_blocked');self.assertEqual(v['route']['final'],'residential');self.assertEqual(v['route']['rules'][4]['action'],'reject')
 def test_origin_dns_has_no_residential_dependency(self):
  v=C.build(NODE,'en0','/fixture','original');self.assertEqual(v['dns']['final'],'local-dns');self.assertTrue(all('detour' not in r for r in v['dns']['servers']))
 def test_fresh_home_has_no_missing_old_proxy_for_ordinary_overseas(self):
  v=C.build(NODE,'en0','/fixture','home');self.assertEqual(v['route']['final'],'residential');self.assertFalse(any(x.get('outbound')=='original' for x in v['route']['rules']));self.assertEqual(v['dns']['final'],'remote-dns')
 def test_ipv6_udp_denied_before_any_allow(self):
  for mode in ('home','home_blocked','original'):
   r=C.build(NODE,'en0','/fixture',mode)['route']['rules'];self.assertEqual(r[2],{'network':'udp','action':'reject'});self.assertEqual(r[3],{'ip_cidr':['::/0'],'action':'reject'})
 def test_bundle_tampering_denied(self):
  v=C.build_bundle(NODE,'en0','/fixture');v['configs']['original']['route']['rules'][4]={'outbound':'direct'}
  with self.assertRaises(ValueError):C.validate_bundle(v)
 def test_no_relay_or_foreign_backup(self):
  v=C.build_bundle(NODE,'en0','/fixture');self.assertFalse(v['has_relay']);self.assertEqual(set(v['configs']),{'home_direct','home_direct_blocked','original'});self.assertNotIn('backup_node',v)
 def test_invalid_inputs_rejected(self):
  for key,val in [('server','host;touch x'),('port',True),('port',0),('expected_ip','127.0.0.1'),('expected_ip','::1'),('password','x\nsecret'),('username','中')]:
   with self.subTest(key=key,val=val):
    n=dict(NODE);n[key]=val
    with self.assertRaises(ValueError):C.validate_node(n)
 def test_missing_expected_ip_denied(self):
  n=dict(NODE);del n['expected_ip']
  with self.assertRaises(ValueError):C.validate_node(n)
 def test_no_original_input_mutation(self):
  n=copy.deepcopy(NODE);C.build_bundle(n,'en0','/fixture');self.assertEqual(n,NODE)
 def test_health_uses_new_verified_exit(self):
  h=load('guard_health');b=C.build_bundle(NODE,'en0','/fixture');R.Supervisor(h,None,b);self.assertEqual(h.EXPECTED_IP,NODE['expected_ip'])
  s=h.decide_health(None,'home',[NODE['expected_ip']]);self.assertEqual(h.decide_health(s,'home',[NODE['expected_ip']])['phase'],'healthy');self.assertEqual(h.decide_health(s,'home',['8.8.8.8'])['reason'],'wrong_exit')

class UpstreamConfigTests(unittest.TestCase):
 def test_all_five_modes_have_protected_priority(self):
  bundle=C.build_bundle(WITH_UPSTREAM,'en0','/fixture');C.validate_bundle(bundle)
  self.assertTrue(bundle['has_relay']);self.assertEqual(len(bundle['configs']),5)
  for name,v in bundle['configs'].items():
   rules=v['route']['rules'];target=rules[4]
   if name in ('home_direct','home_relay'):self.assertEqual(target['outbound'],'residential')
   else:self.assertEqual(target['action'],'reject');self.assertEqual(v['dns']['rules'][1]['rcode'],'REFUSED')
   self.assertFalse(any('process_name' in r or 'process_path' in r for r in rules))
   for i,r in enumerate(rules):
    if r.get('outbound')=='original':self.assertGreater(i,5)
 def test_home_only_explicit_ordinary_list_uses_original(self):
  v=C.build(WITH_UPSTREAM,'en0','/fixture','home');self.assertEqual(v['route']['final'],'residential')
  self.assertIn('openai.com',v['route']['rules'][-1]['domain_suffix'])
  self.assertEqual(v['route']['rules'][-1]['outbound'],'original')
  self.assertEqual(v['dns']['rules'][-1]['server'],'ordinary-dns')
  self.assertEqual(next(x for x in v['dns']['servers'] if x['tag']=='ordinary-dns')['detour'],'original')
 def test_home_direct_and_relay_keep_same_residential_exit(self):
  configs=C.build_bundle(WITH_UPSTREAM,'en0','/fixture')['configs']
  for name,kind in [('home_direct','direct'),('home_relay','vmess')]:
   out={x['tag']:x for x in configs[name]['outbounds']}
   self.assertEqual(out['upstream']['type'],kind);self.assertEqual(out['residential']['detour'],'upstream');self.assertEqual(out['residential']['server'],NODE['server']);self.assertNotIn('fallback',out['residential'])
   self.assertEqual(out['original']['server'],UPSTREAM['server'])
 def test_origin_has_only_selected_proxy_and_direct_no_residential(self):
  v=C.build(WITH_UPSTREAM,'en0','/fixture','original');self.assertEqual({x['tag'] for x in v['outbounds']},{'original','direct'});self.assertEqual(v['route']['final'],'original');self.assertEqual(v['dns']['final'],'remote-dns');self.assertEqual(v['dns']['servers'][1]['detour'],'original');self.assertNotIn(NODE['password'],json.dumps(v))
 def test_invalid_upstream_cannot_add_routes_listeners_or_detours(self):
  for key,value in [('detour','direct'),('server','localhost;command'),('uuid','bad'),('server_port',True),('security','bad'),('tls',{'insecure':True}),('transport',{'type':'ws','path':'/x\nheader'})]:
   node=copy.deepcopy(WITH_UPSTREAM);node['upstream'][key]=value
   with self.subTest(key=key):
    with self.assertRaises(ValueError):C.build_bundle(node,'en0','/fixture')
 def test_preflight_is_loopback_only_and_cannot_reconfigure_network(self):
  v=C.build_preflight(WITH_UPSTREAM,'en0',19081,19082)
  self.assertTrue(all(x['type']=='mixed' and x['listen']=='127.0.0.1' for x in v['inbounds']));self.assertNotIn('experimental',v);self.assertNotIn('rule_set',v['route']);self.assertEqual(v['route']['rules'][3]['action'],'reject');self.assertEqual(v['log'],{'disabled':True})
  self.assertEqual({x['tag'] for x in v['outbounds']},{'upstream','residential'})
 def test_preflight_invalid_or_duplicate_ports_rejected(self):
  for ports in [(1080,1080),(1,1080),(True,1080),(65536,1080)]:
   with self.assertRaises(ValueError):C.build_preflight(WITH_UPSTREAM,'en0',*ports)
 def test_claude_app_and_dns_are_protected_in_all_supported_modes(self):
  for node in [NODE,WITH_UPSTREAM]:
   for name,value in C.build_bundle(node,'en0','/fixture')['configs'].items():
    route=value['route']['rules'][4];dns=value['dns']['rules'][1]
    self.assertIn('claude.app',route['domain_suffix']);self.assertIn('claude.app',dns['domain_suffix'])
    if name in ('home_direct','home_relay'):self.assertEqual(route['outbound'],'residential');self.assertEqual(dns['server'],'remote-dns')
    else:self.assertEqual(route['action'],'reject');self.assertEqual(dns['rcode'],'REFUSED')
 def test_preflight_resolves_ipv4_only_after_protection_and_before_forwarding(self):
  rules=C.build_preflight(WITH_UPSTREAM,'en0',19081,19082)['route']['rules']
  resolve=next(i for i,r in enumerate(rules) if r.get('action')=='resolve')
  self.assertEqual(rules[resolve]['strategy'],'ipv4_only')
  self.assertLess(next(i for i,r in enumerate(rules) if 'claude.app' in r.get('domain_suffix',[])),resolve)
  self.assertTrue(all(i>resolve for i,r in enumerate(rules) if 'outbound' in r))
 def test_upstream_source_inputs_not_modified(self):
  n=copy.deepcopy(WITH_UPSTREAM);C.build_bundle(n,'en0','/fixture');self.assertEqual(n,WITH_UPSTREAM)

class InstallerTests(unittest.TestCase):
 def setUp(self):
  self.stack=contextlib.ExitStack();self.addCleanup(self.stack.close);self.base=Path(tempfile.mkdtemp(dir=JAIL));self.root=self.base/'system/ClaudeResidential';self.root.parent.mkdir();self.private=self.root/'private';self.plist=self.base/'daemon.plist';self.conf=self.base/'pf.conf';self.conf.write_text(PF_BASE);self.anchor=self.base/'anchor';self.events=[];self.fail=None
  self.delivery=self.base/'payload';(self.delivery/'assets').mkdir(parents=True);(self.delivery/'src').mkdir();(self.delivery/'menu/build/家宽状态.app').mkdir(parents=True)
  (self.delivery/'menu/build/家宽状态.app/fixture').write_text('menu')
  for n in I.RUNTIME_FILES:(self.delivery/'src'/n).write_text('# fixture')
  for n in ['sing-box','geosite-cn.srs','geoip-cn.srs']:(self.delivery/'assets'/n).write_text('fixture')
  self.node=self.base/'node.json';self.node.write_text(json.dumps(NODE))
  for k,v in {'ROOT':self.root,'PRIVATE':self.private,'PLIST':self.plist,'PF_CONF':self.conf,'PYTHON':self.root/'python/bin/python3.12','PACKAGE':self.delivery/'src','DELIVERY':self.delivery}.items():self.stack.enter_context(mock.patch.object(I,k,v))
  self.stack.enter_context(mock.patch.object(I.pf,'ANCHOR_FILE',str(self.anchor)))
  self.stack.enter_context(mock.patch.object(I.os,'geteuid',return_value=0))
  self.stack.enter_context(mock.patch.object(I,'physical_interface',return_value='en0'))
  self.stack.enter_context(mock.patch.object(I,'snapshot_network',return_value={'services':[{'name':'Wi-Fi','info':'IP address: 192.168.1.2'}]}))
  self.stack.enter_context(mock.patch.object(I,'precheck_pf',return_value=(PF_BASE,PF_BASE+'# fixture guarded')))
  self.stack.enter_context(mock.patch.object(I,'listener_pids',return_value=set()))
  self.stack.enter_context(mock.patch.object(I.runtime,'trusted',return_value=None))
  self.stack.enter_context(mock.patch.object(I.runtime,'guard_ok',return_value=True))
  self.stack.enter_context(mock.patch.object(I.runtime,'ensure_pf',side_effect=lambda *a,**k:self.events.append('PF')))
  self.stack.enter_context(mock.patch.object(I,'run',side_effect=self.runner))
  self.stack.enter_context(mock.patch.object(I,'copy_runtime',side_effect=self.copy_runtime))
  real_temp=tempfile.TemporaryDirectory
  self.stack.enter_context(mock.patch.object(I.tempfile,'TemporaryDirectory',side_effect=lambda *a,**k:real_temp(*a,**dict(k,dir=k.get('dir',self.base)))))
  mask=os.umask(0o077);self.addCleanup(os.umask,mask)
 def runner(self,args,**kw):
  args=list(map(str,args));self.events.append(args)
  if self.fail=='parser' and 'check' in args:raise RuntimeError('fixture parse failure')
  if self.fail=='bootstrap' and 'bootstrap' in args:raise RuntimeError('fixture bootstrap failure')
  if args[0]=='/sbin/ifconfig':return types.SimpleNamespace(returncode=1,stdout='',stderr='')
  if args[:2]==['/bin/launchctl','print']:return types.SimpleNamespace(returncode=1,stdout='',stderr='')
  return types.SimpleNamespace(returncode=0,stdout='',stderr='')
 def copy_runtime(self,dest):
  if self.fail=='copy':raise OSError('fixture disk full')
  (dest/'python/bin').mkdir(parents=True);(dest/'python/bin/python3.12').write_text('fixture')
 def test_success_prepares_full_payload_before_pf(self):
  result=I.install(self.node);self.assertTrue(result['request_id']);self.assertTrue((self.root/'Origin.command').exists());self.assertTrue((self.private/'before-guard/network.json').exists());self.assertEqual(self.root.stat().st_mode&0o777,0o755);self.assertEqual((self.root/'public').stat().st_mode&0o777,0o755)
  idx=self.events.index('PF');self.assertTrue(any(isinstance(e,list) and 'check' in e for e in self.events[:idx]));self.assertTrue(any(isinstance(e,list) and 'bootstrap' in e for e in self.events[idx:]));self.assertEqual(json.loads((self.private/'installed.json').read_text())['flavor'],I.FLAVOR)
 def test_parser_failure_preserves_network_and_root(self):
  self.fail='parser'
  with self.assertRaises(RuntimeError):I.install(self.node)
  self.assertFalse(self.root.exists());self.assertEqual(self.conf.read_text(),PF_BASE);self.assertNotIn('PF',self.events)
 def test_disk_copy_failure_keeps_system_unpublished(self):
  self.fail='copy'
  with self.assertRaises(OSError):I.install(self.node)
  self.assertFalse(self.root.exists());self.assertFalse(self.plist.exists());self.assertEqual(self.conf.read_text(),PF_BASE);self.assertNotIn('PF',self.events)
 def test_existing_install_is_never_overwritten(self):
  self.root.mkdir();(self.root/'owner').write_text('keep')
  with self.assertRaises(RuntimeError):I.install(self.node)
  self.assertEqual((self.root/'owner').read_text(),'keep');self.assertFalse(self.events)
 def test_port_conflict_stops_before_copy(self):
  with mock.patch.object(I,'listener_pids',return_value={123}):
   with self.assertRaises(RuntimeError):I.install(self.node)
  self.assertFalse(self.root.exists());self.assertNotIn('PF',self.events)
 def test_no_admin_stops_before_mutation(self):
  with mock.patch.object(I.os,'geteuid',return_value=501):
   with self.assertRaises(RuntimeError):I.install(self.node)
  self.assertFalse(self.root.exists())
 def test_missing_node_stops_before_mutation(self):
  self.node.unlink()
  with self.assertRaises(RuntimeError):I.install(self.node)
  self.assertFalse(self.root.exists())
 def test_bootstrap_failure_retains_origin_repair_entry(self):
  self.fail='bootstrap'
  with self.assertRaises(RuntimeError):I.install(self.node)
  self.assertIn('PF',self.events);self.assertTrue((self.root/'Origin.command').exists());self.assertTrue((self.private/'configs.json').exists() if False else (self.private/'original.json').exists())
  self.fail=None;r=I.switch('original');self.assertEqual(json.loads((self.private/'intent.json').read_text())['mode'],'original');self.assertEqual(r['mode'],'original')
 def test_switch_rejects_other_install_flavor(self):
  self.private.mkdir(parents=True);(self.private/'installed.json').write_text('{"flavor":"someone-else"}')
  with self.assertRaises(RuntimeError):I.switch('original')
  self.assertFalse((self.private/'intent.json').exists())
 def test_switch_does_not_overwrite_original_backup(self):
  I.install(self.node);p=self.private/'before-guard/network.json';before=p.read_bytes();I.switch('original');self.assertEqual(p.read_bytes(),before)
 def test_diagnostics_whitelists_no_secrets(self):
  I.install(self.node);(self.root/'public/status.json').write_text('{"mode":"home"}')
  (self.private/'health-probes.jsonl').write_text(json.dumps({'started_at':1,'checks':[{'target':'ip_trace','curl_exit':28,'password':'do-not-export','stderr':'do-not-export'}]})+'\n')
  r=I.diagnostics();self.assertNotIn('do-not-export',json.dumps(r));self.assertEqual(r['probe_rounds'][0]['checks'][0]['curl_exit'],28)

 def test_initial_verified_relay_persists_matching_request(self):
  self.node.write_text(json.dumps(WITH_UPSTREAM));result=I.install(self.node,'relay')
  self.assertEqual(json.loads((self.private/'selection.json').read_text()),{'id':result['request_id'],'choice':'relay'})
  self.assertTrue((self.private/'home_relay_blocked.json').exists())
 def test_relay_without_node_stops_before_mutation(self):
  with self.assertRaises(RuntimeError):I.install(self.node,'relay')
  self.assertFalse(self.root.exists());self.assertFalse(self.events)
 def test_unknown_initial_route_stops_before_mutation(self):
  with self.assertRaises(RuntimeError):I.install(self.node,'unprotected')
  self.assertFalse(self.root.exists());self.assertFalse(self.events)
 def test_upstream_all_modes_parse_before_pf_and_backup_has_no_node(self):
  self.node.write_text(json.dumps(WITH_UPSTREAM));I.install(self.node,'direct')
  checks=[e for e in self.events[:self.events.index('PF')] if isinstance(e,list) and 'check' in e]
  self.assertEqual(len(checks),5);self.assertNotIn(UPSTREAM['uuid'],(self.private/'before-guard/network.json').read_text())

class ControllerTests(unittest.TestCase):
 def setUp(self):
  self.base=Path(tempfile.mkdtemp(dir=JAIL));self.stack=contextlib.ExitStack();self.addCleanup(self.stack.close);self.stack.enter_context(mock.patch.object(U,'STATUS',self.base/'status.json'));self.stack.enter_context(mock.patch.object(U,'ROOT',self.base/'absent'))
 def state(self,**kwargs):
  v={'version':1,'mode':'home','phase':'healthy','policy':'home_open','successes':2,'core_running':True,'updated_at':U.time.time(),'request_id':'new'};v.update(kwargs);U.STATUS.write_text(json.dumps(v))
 def test_stale_request_does_not_authorize(self):
  self.state(request_id='old');self.assertIsNone(U.wait_for_result('new','home',timeout=0.001))
 def test_stale_timestamp_does_not_authorize(self):
  self.state(updated_at=0);self.assertIsNone(U.wait_for_result('new','home',timeout=0.001))
 def test_origin_stays_denied_without_home_success(self):
  self.state(mode='original',phase='blocked',policy='original_blocked',successes=0);self.assertEqual(U.wait_for_result('new','original',timeout=.1)['policy'],'original_blocked')
 def test_direct_probe_does_not_put_password_on_command_line(self):
  calls=[]
  def run(args,**kw):calls.append((args,kw));return types.SimpleNamespace(returncode=0,stdout='ip='+NODE['expected_ip']+'\n',stderr='')
  with mock.patch.object(U,'run',side_effect=run):self.assertEqual(len(U.probe_direct(NODE)),2)
  for a,k in calls:self.assertNotIn(NODE['password'],str(a));self.assertIn(NODE['password'],k['input'])
 def test_wrong_exit_stops_preflight(self):
  with mock.patch.object(U,'run',return_value=types.SimpleNamespace(returncode=0,stdout='ip=8.8.8.8\n',stderr='secret')):
   with self.assertRaisesRegex(RuntimeError,'预期出口'):U.probe_direct(NODE)
 def test_probe_failure_does_not_echo_credentials(self):
  with mock.patch.object(U,'run',return_value=types.SimpleNamespace(returncode=97,stdout='',stderr=NODE['password'])):
   try:U.probe_direct(NODE)
   except RuntimeError as e:self.assertNotIn(NODE['password'],str(e))
   else:self.fail('must fail')
 def test_new_file_manifest_rejects_modified_payload(self):
  p=self.base/'payload';p.mkdir();(p/'file').write_text('modified');(p/'manifest.json').write_text('{"files":{"file":"wrong"}}')
  with mock.patch.object(U,'DELIVERY',p):
   with self.assertRaisesRegex(RuntimeError,'不完整'):U.verify_manifest()
 def test_existing_root_blocks_install_before_probe(self):
  U.ROOT.mkdir()
  with mock.patch.object(U.os,'geteuid',return_value=501),mock.patch.object(U.platform,'system',return_value='Darwin'),mock.patch.object(U.platform,'machine',return_value='arm64'),mock.patch.object(U,'run',return_value=types.SimpleNamespace(stdout='13.6')):
   with self.assertRaisesRegex(RuntimeError,'已有保护'):U.preflight()

class PreflightTests(unittest.TestCase):
 def setUp(self):
  self.base=Path(tempfile.mkdtemp(dir=JAIL));self.log=io.StringIO();self.good=[{'curl_exit':0,'check_passed':True}]*2;self.bad=[{'curl_exit':28,'check_passed':False}]*2
 def test_direct_success_avoids_relay(self):
  with mock.patch.object(U,'probe_local',return_value=self.good) as local,mock.patch.object(U,'probe_direct',return_value=[{'curl_exit':0,'exit_matches_expected':True}]*2):
   self.assertEqual(U.choose_preflight_route(WITH_UPSTREAM,19081,19082,self.log),'direct');self.assertEqual(local.call_count,1)
 def test_failed_direct_uses_only_same_residential_via_relay(self):
  with mock.patch.object(U,'probe_local',return_value=self.good) as local,mock.patch.object(U,'probe_direct',side_effect=RuntimeError('timeout')):
   self.assertEqual(U.choose_preflight_route(WITH_UPSTREAM,19081,19082,self.log),'relay');self.assertEqual(local.call_args,mock.call(19082,NODE['expected_ip']))
 def test_failed_us_line_stops_before_household_check(self):
  with mock.patch.object(U,'probe_local',return_value=self.bad),mock.patch.object(U,'probe_direct') as direct:
   with self.assertRaisesRegex(RuntimeError,'普通代理'):U.choose_preflight_route(WITH_UPSTREAM,19081,19082,self.log)
   direct.assert_not_called()
 def test_both_paths_fail_stops(self):
  with mock.patch.object(U,'probe_local',side_effect=[self.good,self.bad]),mock.patch.object(U,'probe_direct',side_effect=RuntimeError('timeout')):
   with self.assertRaisesRegex(RuntimeError,'均未通过'):U.choose_preflight_route(WITH_UPSTREAM,19081,19082,self.log)
 def test_public_us_original_trace_is_accepted(self):
  with mock.patch.object(U,'run',return_value=types.SimpleNamespace(returncode=0,stdout='ip=93.184.216.34\nloc=US\n',stderr='')):
   self.assertTrue(U.checked_rows(U.probe_local(19081)))
 def test_non_us_original_or_private_ip_is_rejected(self):
  for body in ['ip=93.184.216.34\nloc=JP\n','ip=127.0.0.1\nloc=US\n','ip=93.184.216.34\nip=8.8.8.8\nloc=US\n']:
   with mock.patch.object(U,'run',return_value=types.SimpleNamespace(returncode=0,stdout=body,stderr='')):self.assertFalse(U.checked_rows(U.probe_local(19081)))
 def test_wrong_residential_exit_is_rejected_and_raw_errors_not_logged(self):
  with mock.patch.object(U,'run',return_value=types.SimpleNamespace(returncode=0,stdout='ip=8.8.8.8\nloc=US\n',stderr=NODE['password'])):
   result=U.probe_local(19082,NODE['expected_ip']);self.assertFalse(U.checked_rows(result));self.assertNotIn(NODE['password'],json.dumps(result))
 def test_preflight_requires_own_live_listeners(self):
  child=mock.Mock(pid=1001);child.poll.return_value=None
  with mock.patch.object(U,'run',return_value=types.SimpleNamespace(returncode=0,stdout='1001\n')):U.wait_preflight(child,(19081,19082))
  child.poll.return_value=1
  with self.assertRaises(RuntimeError):U.wait_preflight(child,(19081,19082))
 def run_temporary_probe(self,fail=False,parser_fail=False):
  child=mock.Mock(pid=1001);child.poll.return_value=None;events=[];paths=[]
  real_temp=tempfile.TemporaryDirectory
  def runner(args,**kw):
   events.append(list(map(str,args)));path=Path(args[-1]);paths.append(path)
   self.assertEqual(path.stat().st_mode&0o777,0o600);self.assertEqual(path.parent.stat().st_mode&0o777,0o700)
   return types.SimpleNamespace(returncode=1 if parser_fail else 0,stdout='',stderr='private error')
  def launch(*args,**kw):events.append(list(args[0]));return child
  with mock.patch.object(U,'preflight_interface',return_value='en0'),mock.patch.object(U,'reserve_probe_ports',return_value=(19081,19082)),mock.patch.object(U.tempfile,'TemporaryDirectory',side_effect=lambda **kw:real_temp(dir=self.base,**kw)),mock.patch.object(U,'run',side_effect=runner),mock.patch.object(U.subprocess,'Popen',side_effect=launch),mock.patch.object(U,'wait_preflight'),mock.patch.object(U,'choose_preflight_route',side_effect=RuntimeError('probe failed') if fail else None,return_value='relay'):
   if fail or parser_fail:
    with self.assertRaises(RuntimeError):U.probe_paths(WITH_UPSTREAM,self.log)
   else:self.assertEqual(U.probe_paths(WITH_UPSTREAM,self.log),'relay')
  self.assertTrue(all(not p.exists() for p in paths));self.assertTrue(all('networksetup' not in str(e) and 'pfctl' not in str(e) and 'sudo' not in str(e) for e in events))
  return child
 def test_temporary_core_stops_and_secrets_deleted_after_success(self):
  child=self.run_temporary_probe();child.terminate.assert_called_once();child.wait.assert_called_once()
 def test_temporary_core_stops_on_probe_failure(self):
  child=self.run_temporary_probe(fail=True);child.terminate.assert_called_once()
 def test_bad_preflight_config_never_launches_core(self):
  child=self.run_temporary_probe(parser_fail=True);child.terminate.assert_not_called()

def main():
 global JAIL,ACTIVE,C,I,U,H,R
 sys.dont_write_bytecode=True;sys.addaudithook(audit)
 captured=io.StringIO()
 with tempfile.TemporaryDirectory(dir=BASE/'tests',prefix='portable-jail-') as d:
  JAIL=Path(d).resolve();ACTIVE=True
  C,I,U,H,R=[load(n) for n in ['guard_config','guard_install','controller','guard_health','guard_runtime']]
  suite=unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(c) for c in [ConfigTests,UpstreamConfigTests,InstallerTests,ControllerTests,PreflightTests])
  r=unittest.TextTestRunner(stream=captured,verbosity=2).run(suite);ACTIVE=False
 report={'tests_run':r.testsRun,'passed':r.wasSuccessful(),'failures':len(r.failures),'errors':len(r.errors),'real_external_operations':0,'writes':'audit-enforced temporary jail','details':captured.getvalue()}
 (BASE/'portable-test-report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k!='details'}))
 if not r.wasSuccessful():print(captured.getvalue())
 return 0 if r.wasSuccessful() else 1
if __name__=='__main__':raise SystemExit(main())
