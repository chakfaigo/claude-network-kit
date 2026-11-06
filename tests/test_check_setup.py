"""Read-only onboarding checks with fake OS responses and synthetic settings."""
from pathlib import Path
import contextlib, hashlib, io, json, os, plistlib, sys, tempfile, unittest
from unittest import mock
import test_portable as guard
D=None

class CheckTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.base=Path(self.tmp.name)
        self.package=self.base/'package';self.package.mkdir();(self.package/'VERSION').write_text('v2026.11.05.5\n')
        (self.package/'manifest.json').write_text(json.dumps({'files':{'VERSION':hashlib.sha256((self.package/'VERSION').read_bytes()).hexdigest()}}))
        self.home=self.base/'user';self.home.mkdir();self.root=self.base/'installed'
        self.responses={('/usr/sbin/scutil','--proxy'):(0,'<dictionary> {\n}'),('/sbin/ifconfig','utun99'):(1,'')}
        for name,value in [('system','Darwin'),('machine','arm64'),('mac_ver',('13.6','',''))]:
            p=mock.patch.object(D.platform,name,return_value=value);p.start();self.addCleanup(p.stop)
    def run_fake(self,args):return self.responses.get(tuple(args),(113,''))
    def collect(self,env=None,policy_paths=None):return D.collect(self.package,self.root,self.home,{} if env is None else env,self.run_fake,now=1000,policy_paths=[] if policy_paths is None else policy_paths)
    def row(self,report,key):return next(x for x in report['checks'] if x['id']==key)
    def settings(self,env):
        (self.home/'.claude').mkdir(exist_ok=True);p=self.home/'.claude/settings.json';p.write_text(json.dumps({'env':env}));p.chmod(0o600);return p
    def valid_env(self):return {**{k:'http://127.0.0.1:10808' for k in ('HTTP_PROXY','HTTPS_PROXY','http_proxy','https_proxy')},'NO_PROXY':'localhost,127.0.0.1,::1','no_proxy':'localhost,127.0.0.1,::1'}
    def test_fresh_machine_is_never_accepted_as_complete(self):
        r=self.collect();self.assertFalse(r['acceptance_complete']);self.assertEqual(r['stage'],'before_installation');self.assertEqual(self.row(r,'cli_global_file')['state'],'pending')
    def test_package_tamper_blocks_installation(self):
        (self.package/'VERSION').write_text('changed');self.assertEqual(self.row(self.collect(),'package_integrity')['state'],'needs_action')
    def test_private_and_escaping_manifest_paths_rejected_before_read(self):
        for name in ['private/node.json','../secret','/tmp/secret']:
            (self.package/'manifest.json').write_text(json.dumps({'files':{name:'fixture'}}))
            self.assertEqual(D.package_check(self.package)[0],'needs_action')
    def test_symlink_manifest_is_not_followed(self):
        p=self.package/'manifest.json';p.unlink();p.symlink_to(self.base/'absent');self.assertEqual(D.package_check(self.package)[0],'needs_action')
    def test_symlink_payload_is_not_followed(self):
        p=self.package/'VERSION';p.unlink();p.symlink_to(self.base/'absent');self.assertEqual(D.package_check(self.package)[0],'needs_action')
    def test_http_credentials_and_arbitrary_values_are_not_exported(self):
        env=self.valid_env();env['HTTPS_PROXY']='http://person:sensitive-fixture@outside.example:9000';env['ANTHROPIC_API_KEY']='sensitive-fixture'
        self.settings(env);r=self.collect(env);self.assertNotIn('sensitive-fixture',json.dumps(r));self.assertNotIn('outside.example',json.dumps(r));self.assertEqual(self.row(r,'cli_global_file')['state'],'needs_action')
    def test_bypass_and_lowercase_mismatch_are_flagged(self):
        for key,value in [('NO_PROXY','*'),('no_proxy','api.anthropic.com'),('https_proxy','http://127.0.0.1:9999'),('ALL_PROXY','socks5://external.example:10808')]:
            env=self.valid_env();env[key]=value;self.settings(env);self.assertEqual(self.row(self.collect(),'cli_global_file')['state'],'needs_action')
    def test_valid_global_settings_are_only_file_evidence(self):
        self.settings(self.valid_env());r=self.collect();self.assertEqual(self.row(r,'cli_global_file')['state'],'baseline_match');self.assertFalse(r['acceptance_complete'])
    def test_open_settings_permissions_are_flagged(self):
        self.settings(self.valid_env()).chmod(0o644);self.assertEqual(self.row(self.collect(),'cli_global_file')['state'],'needs_action')
    def test_invalid_settings_object_is_unknown_not_passed(self):
        p=self.settings({});p.write_text('[]');self.assertEqual(self.row(self.collect(),'cli_global_file')['state'],'pending')
    def test_system_proxy_active_in_any_dictionary_is_flagged(self):
        self.responses[('/usr/sbin/scutil','--proxy')]=(0,'<dictionary> { HTTPEnable : 0\n Scoped : <dictionary> { HTTPSEnable : 1 }}')
        self.assertEqual(self.row(self.collect(),'system_proxy')['state'],'needs_action')
    def test_failed_system_command_never_means_no_proxy(self):
        self.responses[('/usr/sbin/scutil','--proxy')]=(None,'');self.assertEqual(self.row(self.collect(),'system_proxy')['state'],'pending')
    def test_existing_installation_does_not_offer_overwrite(self):
        self.root.mkdir();r=self.collect();self.assertEqual(r['stage'],'existing_installation');self.assertIn('禁止',self.row(r,'installation_stage')['message'])
    def test_broken_install_symlink_is_not_a_fresh_machine(self):
        self.root.symlink_to(self.base/'missing');r=self.collect();self.assertEqual(r['stage'],'existing_installation');self.assertEqual(self.row(r,'installed_path')['state'],'needs_action');self.assertFalse(any(x['id']=='home_status' for x in r['checks']))
    def test_install_regular_file_is_not_followed(self):
        self.root.write_text('sensitive-fixture');r=self.collect();self.assertEqual(self.row(r,'installed_path')['state'],'needs_action');self.assertNotIn('sensitive-fixture',json.dumps(r))
    def test_chrome_file_match_still_requires_live_policy_check(self):
        p=self.base/'policy.plist';p.write_bytes(plistlib.dumps(D.POLICIES));r=self.collect(policy_paths=[p]);row=self.row(r,'chrome_policy');self.assertEqual(row['state'],'pending');self.assertTrue(all(x['matches'] for x in row['details']['local_file_clues'][0].values()))
    def test_custom_config_directory_is_only_reported_as_present(self):
        r=self.collect({'CLAUDE_CONFIG_DIR':'/sensitive-fixture'});self.assertTrue(self.row(r,'checker_environment')['details']['review_keys_present']['CLAUDE_CONFIG_DIR']);self.assertNotIn('sensitive-fixture',json.dumps(r))
    def test_status_requires_freshness_and_consistent_mode(self):
        s={'version':1,'mode':'home','phase':'healthy','policy':'home_open','successes':2,'core_running':True,'updated_at':999}
        self.assertEqual(D.summarize_status(s,1000)[0],'baseline_match')
        for update in [{'updated_at':0},{'updated_at':float('nan')},{'updated_at':1006},{'core_running':False},{'successes':1}]:
            self.assertEqual(D.summarize_status(dict(s,**update),1000)[0],'needs_action')
    def test_origin_is_expected_blocking_not_complete_acceptance(self):
        s={'version':1,'mode':'original','phase':'blocked','policy':'original_blocked','successes':0,'core_running':True,'updated_at':999}
        self.assertEqual(D.summarize_status(s,1000)[0],'pending')
    def test_unknown_status_never_exports_arbitrary_strings(self):
        _,_,result=D.summarize_status({'mode':'sensitive-fixture','reason':'sensitive-fixture'},1000);self.assertNotIn('sensitive-fixture',json.dumps(result))
    def test_optional_output_is_exclusive_and_private(self):
        out=self.base/'report.json'
        with mock.patch.object(D,'collect',return_value={'checks':[]}),mock.patch.object(D.os,'geteuid',return_value=501),mock.patch.object(sys,'argv',['check_setup','--json','--output',str(out)]),contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(D.main(),0);self.assertEqual(out.stat().st_mode&0o777,0o600)
            with self.assertRaises(FileExistsError):D.main()
    def test_profile_has_only_three_network_settings_and_no_identity(self):
        p=Path(__file__).resolve().parent.parent/'portable/examples/Chrome网络基线.mobileconfig';profile=plistlib.loads(p.read_bytes())
        self.assertEqual(profile['PayloadScope'],'User');self.assertFalse(profile['PayloadRemovalDisallowed'])
        payload=profile['PayloadContent'];self.assertEqual(len(payload),1);self.assertEqual(payload[0]['PayloadType'],'com.apple.ManagedClient.preferences')
        prefs=payload[0]['PayloadContent'];self.assertEqual(set(prefs),{'com.google.Chrome'})
        self.assertEqual(prefs['com.google.Chrome']['Forced'][0]['mcx_preference_settings'],D.POLICIES)


def main():
    global D
    sys.dont_write_bytecode=True;sys.addaudithook(guard.audit)
    with tempfile.TemporaryDirectory(dir=Path(__file__).parent,prefix='checks-jail-') as folder:
        guard.JAIL=Path(folder).resolve();guard.ACTIVE=True;old=tempfile.tempdir;tempfile.tempdir=folder
        try:D=guard.load('check_setup');r=unittest.TextTestRunner(verbosity=1).run(unittest.defaultTestLoader.loadTestsFromTestCase(CheckTests))
        finally:guard.ACTIVE=False;tempfile.tempdir=old
    return 0 if r.wasSuccessful() else 1
if __name__=='__main__':raise SystemExit(main())
