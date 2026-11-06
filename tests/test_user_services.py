"""Controller regressions with fake launchd and audit-enforced temporary writes."""
from pathlib import Path
import contextlib, importlib.util, io, json, os, plistlib, subprocess, sys, tempfile, unittest
from unittest import mock
import test_portable as guard
C = None

class FakeLaunchd:
    def __init__(self, path, args):
        self.path=path; self.args=args; self.loaded=False; self.pid=True
        self.commands=[]; self.bootstrap_codes=[]; self.unloading=0; self.ticks=0
        self.active={}; self.fail_bootout=False; self.stuck=False
    def clock(self): self.ticks += .1; return self.ticks
    def text(self):
        return '\npath = '+str(self.path)+'\narguments = {\n'+'\n'.join(self.args)+'\n}\n'+('pid = 12345\n' if self.pid else '')+'run interval = '+str(self.active.get('StartInterval',0))+' seconds\n'
    def run(self, command, **kw):
        command=list(map(str,command)); op=command[1]; self.commands.append((op,kw.get('timeout')))
        code=0;out='';err=''
        if op=='print':
            if self.unloading and not self.stuck:
                self.unloading-=1
                if not self.unloading:self.loaded=False
            code=0 if self.loaded else 113;out=self.text() if self.loaded else ''
        elif op=='bootout':
            if self.fail_bootout:code=5
            else:self.unloading=3
        elif op=='bootstrap':
            code=self.bootstrap_codes.pop(0) if self.bootstrap_codes else 0
            if code==0:self.loaded=True;self.active=plistlib.loads(self.path.read_bytes())
            else:err='fixture bootstrap error'
        r=subprocess.CompletedProcess(command,code,out,err)
        if kw.get('check'):r.check_returncode()
        return r

class RegistrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.agents=Path(self.tmp.name);self.label='fixture.status';self.args=['/fixture/Status']
        self.fake=FakeLaunchd(self.agents/(self.label+'.plist'),self.args)
        for obj,name,value in [(C,'run',self.fake.run),(C.time,'sleep',lambda n:None),(C.time,'monotonic',self.fake.clock)]:
            p=mock.patch.object(obj,name,value);p.start();self.addCleanup(p.stop)
    def register(self, extra=None):return C.register_user_agent('gui/501',self.label,self.args,{} if extra is None else extra,self.agents)
    def operations(self):return [x[0] for x in self.fake.commands]
    def test_new_agent_loads_complete_private_payload(self):
        self.assertTrue(self.register()['registration_verified'])
        self.assertEqual(self.fake.path.stat().st_mode&0o777,0o600)
        self.assertEqual(self.fake.active['KeepAlive'],{'SuccessfulExit':False})
        self.assertTrue(all(0<t<=2 for _,t in self.fake.commands))
    def test_matching_disk_and_arguments_do_not_hide_old_loaded_interval(self):
        self.register({'StartInterval':30});self.fake.active['StartInterval']=3600;self.fake.commands=[]
        self.register({'StartInterval':30})
        self.assertIn('bootout',self.operations());self.assertEqual(self.fake.active['StartInterval'],30)
    def test_retry_after_failed_unload_reloads_even_with_new_plist_on_disk(self):
        self.register({'StartInterval':3600});self.fake.fail_bootout=True
        with self.assertRaises(subprocess.CalledProcessError):self.register({'StartInterval':30})
        self.assertEqual(plistlib.loads(self.fake.path.read_bytes())['StartInterval'],30)
        self.assertEqual(self.fake.active['StartInterval'],3600)
        self.fake.fail_bootout=False;self.register({'StartInterval':30})
        self.assertEqual(self.fake.active['StartInterval'],30)
    def test_unload_is_observed_before_reloading(self):
        self.register();self.fake.commands=[];self.register()
        ops=self.operations();self.assertGreaterEqual(ops[ops.index('bootout')+1:ops.index('bootstrap')].count('print'),3)
    def test_transient_slot_errors_are_retried(self):
        self.fake.bootstrap_codes=[5,37,0];self.register();self.assertEqual(self.operations().count('bootstrap'),3)
    def test_nontransient_error_not_retried(self):
        self.fake.bootstrap_codes=[13,0]
        with self.assertRaises(subprocess.CalledProcessError):self.register()
        self.assertEqual(self.operations().count('bootstrap'),1)
    def test_persistent_bootstrap_errors_are_bounded(self):
        self.fake.bootstrap_codes=[5]*1000
        with self.assertRaises(subprocess.CalledProcessError) as error:self.register()
        self.assertEqual(error.exception.returncode,5)
        self.assertLess(self.operations().count('bootstrap'),100)
    def test_failed_bootstrap_with_matching_job_never_counts_as_success(self):
        real=self.fake.run
        def run(args,**kw):
            if args[1]=='bootstrap':self.fake.loaded=True;self.fake.bootstrap_codes=[5]
            return real(args,**kw)
        with mock.patch.object(C,'run',run),self.assertRaises(subprocess.CalledProcessError):self.register()
    def test_unload_timeout_does_not_bootstrap(self):
        self.register();self.fake.commands=[];self.fake.stuck=True
        with self.assertRaises(RuntimeError):self.register()
        self.assertNotIn('bootstrap',self.operations())
    def test_print_permission_error_is_not_absence(self):
        with mock.patch.object(C,'run',return_value=subprocess.CompletedProcess(['launchctl','print'],13,'','')),self.assertRaises(subprocess.CalledProcessError):self.register()
        self.assertFalse(self.fake.path.exists())
    def test_command_timeout_is_reported(self):
        with mock.patch.object(C,'run',side_effect=subprocess.TimeoutExpired(['launchctl','print'],2)),self.assertRaises(subprocess.TimeoutExpired):self.register()
    def test_idle_periodic_watcher_is_registered_not_delivery_verified(self):
        self.fake.pid=False;r=self.register({'StartInterval':30});self.assertTrue(r['registration_verified']);self.assertNotIn('delivery_verified',r)
    def test_menu_without_pid_fails_readiness(self):
        self.fake.pid=False
        with self.assertRaises(RuntimeError):self.register()
    def test_symbolic_link_is_rejected(self):
        self.fake.path.symlink_to(self.agents/'elsewhere')
        with self.assertRaises(RuntimeError):self.register()
        self.assertFalse(self.fake.commands)
    def test_plist_changed_during_loading_is_rejected(self):
        real=self.fake.run
        def run(args,**kw):
            r=real(args,**kw)
            if args[1]=='bootstrap':self.fake.path.write_bytes(b'changed')
            return r
        with mock.patch.object(C,'run',run),self.assertRaisesRegex(RuntimeError,'发生变化'):self.register()

class ReportingTests(unittest.TestCase):
    def test_menu_failure_does_not_skip_cli_settings(self):
        log=io.StringIO()
        with mock.patch.object(C,'register_user_services',side_effect=C.UserServiceError([{'label':'status','exit_code':5}])),mock.patch.object(C,'install_proxy_preferences',return_value=None) as apply:
            errors=C.finish_user_setup(log);apply.assert_called_once()
        self.assertEqual(len(errors),1);self.assertIn('cli_proxy_settings',log.getvalue())
    def test_failed_agent_does_not_skip_second_agent(self):
        with tempfile.TemporaryDirectory() as folder,mock.patch.object(C.Path,'home',return_value=Path(folder)),mock.patch.object(C,'USER_ROOT',Path(folder)/'logs'),mock.patch.object(C,'register_user_agent',side_effect=[subprocess.CalledProcessError(5,['launchctl','bootstrap'],stderr='fixture'),{'registration_verified':True}]) as action:
            with self.assertRaises(C.UserServiceError) as caught:C.register_user_services()
            self.assertEqual(action.call_count,2);self.assertEqual(caught.exception.issues[0]['operation'],'bootstrap')
    def test_errors_name_the_requested_retry_entry(self):
        for mode,expected in [('original','Origin.command'),('home','Home.command'),('install','Home.command')]:
            state={'mode':'original' if mode=='original' else 'home'}
            self.assertIn(expected,C.setup_failure_message(state,mode,[{'stage':'cli_proxy_settings'}]))
    def test_home_request_does_not_accept_original_result(self):
        with tempfile.TemporaryDirectory() as folder:
            status=Path(folder)/'status.json';status.write_text(json.dumps({'version':1,'request_id':'new','mode':'original','phase':'blocked','policy':'original_blocked','core_running':True,'updated_at':C.time.time(),'successes':0}))
            with mock.patch.object(C,'STATUS',status):self.assertIsNone(C.wait_for_result('new','home',timeout=.001))

class EntryTests(unittest.TestCase):
    def run_entry(self, mode, failure=False):
        with tempfile.TemporaryDirectory() as folder,contextlib.ExitStack() as stack:
            base=Path(folder);user=base/'user';root=base/'installed';root.mkdir();user.mkdir()
            delivery=base/'portable';(delivery/'private').mkdir(parents=True)
            (delivery/'private/node.json').write_text(json.dumps(guard.NODE));(delivery/'manifest.json').write_text('{"files":{}}')
            for name,value in [('USER_ROOT',user/'logs'),('ROOT',root),('DELIVERY',delivery)]:stack.enter_context(mock.patch.object(C,name,value))
            stack.enter_context(mock.patch.object(C.Path,'home',return_value=user));stack.enter_context(mock.patch.object(C.os,'geteuid',return_value=501))
            stack.enter_context(mock.patch.object(C.sys,'argv',['controller.py',mode]))
            stack.enter_context(mock.patch.object(C,'preflight'));stack.enter_context(mock.patch.object(C,'probe_paths',return_value='direct'))
            calls=[]
            state={'mode':'original' if mode=='original' else 'home','request_id':'new','phase':'blocked' if mode=='original' else 'healthy'}
            def privileged(args,log):
                calls.append(list(map(str,args)))
                if str(args[-1])=='--diagnostics':return {'probe_rounds':[{},{}],'log_files':[{'uid':0,'mode':0o600}]}
                return {'request_id':'new','mode':state['mode']}
            stack.enter_context(mock.patch.object(C,'privileged',privileged))
            wait=stack.enter_context(mock.patch.object(C,'wait_for_result',return_value=state))
            stack.enter_context(mock.patch.object(C,'register_user_services',side_effect=C.UserServiceError([{'label':'fixture'}]) if failure else None,return_value=[{'registration_verified':True}]))
            out=io.StringIO()
            with contextlib.redirect_stdout(out):
                if failure:
                    with self.assertRaisesRegex(RuntimeError,'Origin.command'):C.main()
                else:C.main()
            settings=json.loads((user/'.claude/settings.json').read_text())
            self.assertEqual(settings['env']['HTTPS_PROXY'],'http://127.0.0.1:10808')
            wait.assert_called_once_with('new',state['mode'])
            logs=list((user/'logs/logs').glob('*.log'));self.assertEqual(len(logs),1)
            self.assertIn('cli_proxy_settings',logs[0].read_text())
            if not failure:self.assertIn('尚需逐项完成',out.getvalue())
            return calls
    def test_original_entry_includes_settings_and_mode_result(self):self.run_entry('original')
    def test_original_partial_failure_still_applies_cli_and_reports_original(self):self.run_entry('original',True)
    def test_home_entry_includes_diagnostic_gate(self):self.assertEqual(self.run_entry('home')[-1][-1],'--diagnostics')
    def test_install_entry_preserves_preflight_selection_and_user_setup(self):
        calls=self.run_entry('install');self.assertIn('--initial-route',calls[0]);self.assertEqual(calls[0][-1],'direct')


def main():
    global C
    sys.dont_write_bytecode=True;sys.addaudithook(guard.audit)
    with tempfile.TemporaryDirectory(dir=Path(__file__).parent,prefix='services-jail-') as folder:
        guard.JAIL=Path(folder).resolve();guard.ACTIVE=True
        old=tempfile.tempdir;tempfile.tempdir=folder
        try:
            C=guard.load('controller');suite=unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(c) for c in [RegistrationTests,ReportingTests,EntryTests])
            r=unittest.TextTestRunner(verbosity=1).run(suite)
        finally:guard.ACTIVE=False;tempfile.tempdir=old
    return 0 if r.wasSuccessful() else 1
if __name__=='__main__':raise SystemExit(main())
