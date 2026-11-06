"""Offline checks using the distributed Apple Silicon core. No network or installation."""
from pathlib import Path
import importlib.util,json,platform,subprocess,tempfile
BASE=Path(__file__).resolve().parent.parent

def main():
    if platform.system()!='Darwin' or platform.machine()!='arm64':
        raise RuntimeError('Native core validation requires an Apple Silicon Mac; do not count a skipped check as passed.')
    spec=importlib.util.spec_from_file_location('config',BASE/'portable/src/guard_config.py');C=importlib.util.module_from_spec(spec);spec.loader.exec_module(C)
    node={'server':'gateway.example.test','port':8001,'username':'fixture-user','password':'fixture-only','expected_ip':'93.184.216.34'}
    upstream={'type':'vmess','server':'upstream.example.test','server_port':8080,'uuid':'11111111-1111-4111-8111-111111111111','security':'auto','alter_id':0,'transport':{'type':'ws','path':'/fixture','headers':{'Host':'upstream.example.test'}}}
    core=BASE/'portable/assets/sing-box';report={'network_denied':True,'configurations':[],'domain_samples':[]}
    def run(args):
        result=subprocess.run(['/usr/bin/sandbox-exec','-p','(version 1)(allow default)(deny network*)',str(core),*map(str,args)],capture_output=True,text=True,timeout=20)
        if result.returncode:raise RuntimeError(result.stderr)
        return result
    with tempfile.TemporaryDirectory(prefix='core-offline-') as folder:
        folder=Path(folder)
        for has_upstream in (False,True):
            n=dict(node,**({'upstream':upstream} if has_upstream else {}));bundle=C.build_bundle(n,'en0',str(BASE/'portable/assets'));C.validate_bundle(bundle)
            for name,config in bundle['configs'].items():
                path=folder/f'{has_upstream}-{name}.json';path.write_text(json.dumps(config));run(['check','-c',path]);report['configurations'].append(path.name)
        path=folder/'preflight.json';path.write_text(json.dumps(C.build_preflight(dict(node,upstream=upstream),'en0',19081,19082)));run(['check','-c',path]);report['configurations'].append(path.name)
        path=folder/'protected-rules.json';path.write_text(json.dumps({'version':4,'rules':[C.targets()]}))
        for domain,expected in [('claude.app',True),('x.livepreview.claude.app',True),('notclaude.app',False),('claude.app.evil.example',False),('api.anthropic.com',True),('www.douyin.com',False),('chatgpt.com',False)]:
            matched='match rules.' in run(['rule-set','match',path,domain]).stderr
            if matched!=expected:raise RuntimeError('Protected-domain boundary mismatch: '+domain)
            report['domain_samples'].append({'domain':domain,'matches':matched})
    (BASE/'core-test-report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(report,ensure_ascii=False))
if __name__=='__main__':main()
