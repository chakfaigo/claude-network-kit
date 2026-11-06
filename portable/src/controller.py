"""User-side entry for a fresh Mac. Never elevate the complete controller."""
from pathlib import Path
import datetime, fcntl, hashlib, importlib.util, ipaddress, json, math, os, platform, plistlib, re, shutil, socket, subprocess, sys, tempfile, time
ROOT=Path('/Library/Application Support/ClaudeResidential')
PYTHON=ROOT/'python/bin/python3.12'
STATUS=ROOT/'public/status.json'
SOURCE=Path(__file__).resolve().parent
DELIVERY=SOURCE.parent
USER_ROOT=Path.home()/'Library/Application Support/HomeGuard'

def load(name):
 spec=importlib.util.spec_from_file_location(name,SOURCE/(name+'.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def run(args, **kw):
 kw.setdefault('timeout',30)
 return subprocess.run([str(x) for x in args],capture_output=True,text=True,**kw)

def preflight():
 if os.geteuid()==0:raise RuntimeError('请以普通用户双击安装入口')
 if platform.system()!='Darwin' or platform.machine()!='arm64':raise RuntimeError('此安装包仅用于Apple Silicon Mac')
 version=run(['/usr/bin/sw_vers','-productVersion']).stdout.strip()
 if int(version.split('.')[0])<13:raise RuntimeError('需要macOS 13或以上')
 if ROOT.exists() or ROOT.is_symlink():raise RuntimeError('此电脑已有保护目录；不要用全新安装覆盖')
 if (Path.home()/'Library/LaunchAgents/local.claude.residential.status.plist').exists():raise RuntimeError('此电脑已有状态栏登录项，请先核对')
 for target in ['default','1.1.1.1']:
  r=run(['/sbin/route','-n','get',target]);m=re.search(r'^\s*interface:\s*(\S+)',r.stdout,re.M)
  if r.returncode or not m or m[1].startswith('utun'):raise RuntimeError('当前网络或VPN需先核对；尚未修改网络')
 proxy=run(['/usr/sbin/scutil','--proxy']).stdout
 if re.search(r'\b(?:HTTPEnable|HTTPSEnable|SOCKSEnable|ProxyAutoConfigEnable|ProxyAutoDiscoveryEnable)\s*:\s*1\b',proxy):raise RuntimeError('当前已开启代理；新机安装不会覆盖')
 if run(['/sbin/ifconfig','utun99']).returncode==0:raise RuntimeError('utun99已被使用')

def verify_manifest():
 manifest=json.loads((DELIVERY/'manifest.json').read_text())
 for relative,digest in manifest['files'].items():
  p=DELIVERY/relative
  if p.is_symlink() or not p.is_file() or DELIVERY.resolve() not in p.resolve().parents:raise RuntimeError('安装文件路径异常')
  if hashlib.sha256(p.read_bytes()).hexdigest()!=digest:raise RuntimeError('安装文件不完整：'+p.name)

def probe_direct(node):
 """Explicit SOCKS5h proxy, no inherited proxy or new core; fixed public checks only."""
 rows=[]
 for url in ['https://www.cloudflare.com/cdn-cgi/trace','https://1.1.1.1/cdn-cgi/trace']:
  opts={'proxy':'socks5h://'+node['server']+':'+str(node['port']),'proxy-user':node['username']+':'+node['password'],'noproxy':'','url':url}
  conf='\n'.join(k+' = '+json.dumps(v,ensure_ascii=False) for k,v in opts.items())+'\n'
  r=run(['/usr/bin/curl','-q','--config','-','--silent','--show-error','--fail','-4','--connect-timeout','5','--max-time','12','--max-filesize','8192'],input=conf)
  ips=re.findall(r'^ip=([^\r\n]+)',r.stdout,re.M)
  valid=r.returncode==0 and len(ips)==1
  try: found=str(ipaddress.ip_address(ips[0])) if valid else None
  except ValueError:found=None
  rows.append({'curl_exit':r.returncode,'exit_matches_expected':found==node['expected_ip']})
  if found!=node['expected_ip']:
   raise RuntimeError('家宽直连或预期出口验证未通过，尚未安装或改网。可能需要前置线路；请提供安装日志中的错误码 '+str(r.returncode))
 return rows

def probe_local(port,expected_ip=None):
 rows=[]
 for url in ['https://www.cloudflare.com/cdn-cgi/trace','https://1.1.1.1/cdn-cgi/trace']:
  result=run(['/usr/bin/curl','-q','--silent','--show-error','--fail','-4','--proxy','http://127.0.0.1:'+str(port),'--noproxy','','--connect-timeout','5','--max-time','12','--max-filesize','8192',url])
  ips=re.findall(r'^ip=([^\r\n]+)',result.stdout,re.M)
  locations=re.findall(r'^loc=([^\r\n]+)',result.stdout,re.M)
  try: address=ipaddress.ip_address(ips[0]) if len(ips)==1 else None
  except ValueError:address=None
  valid=result.returncode==0 and address is not None and address.version==4 and address.is_global
  matches=valid and (str(address)==expected_ip if expected_ip else locations==['US'])
  rows.append({'curl_exit':result.returncode,'check_passed':bool(matches)})
 return rows

def checked_rows(rows):
 return len(rows)==2 and all(r.get('check_passed') is True for r in rows)

def choose_preflight_route(node,original_port,relay_port,log):
 ordinary=probe_local(original_port)
 log.write('UPSTREAM_CHECK '+json.dumps(ordinary)+'\n');log.flush()
 if not checked_rows(ordinary):raise RuntimeError('普通代理线路验证未通过，尚未安装或改网；请保留日志')
 try:
  direct=probe_direct(node)
 except RuntimeError as e:
  log.write('DIRECT_CHECK_FAILED '+str(e)+'\n');log.flush()
 else:
  log.write('DIRECT_CHECK '+json.dumps(direct)+'\n');log.flush();return 'direct'
 relayed=probe_local(relay_port,node['expected_ip'])
 log.write('RELAY_CHECK '+json.dumps(relayed)+'\n');log.flush()
 if not checked_rows(relayed):raise RuntimeError('家宽直连及普通代理前置均未通过出口验证，尚未安装或改网')
 return 'relay'

def preflight_interface():
 result=run(['/sbin/route','-n','get','default'])
 match=re.search(r'^\s*interface:\s*([A-Za-z][A-Za-z0-9_-]{0,31})\s*$',result.stdout,re.M)
 if result.returncode or not match or match[1].startswith('utun'):raise RuntimeError('检测前无法确认物理网络，尚未安装或改网')
 return match[1]

def reserve_probe_ports():
 # Hold both reservations together so the OS cannot allocate the same port twice.
 with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as first, socket.socket(socket.AF_INET,socket.SOCK_STREAM) as second:
  first.bind(('127.0.0.1',0));second.bind(('127.0.0.1',0))
  return first.getsockname()[1],second.getsockname()[1]

def wait_preflight(child,ports):
 deadline=time.monotonic()+8
 while time.monotonic()<deadline:
  if child.poll() is not None:raise RuntimeError('临时线路检测未能启动，尚未安装或改网')
  owned=[]
  for port in ports:
   r=run(['/usr/sbin/lsof','-a','-p',str(child.pid),'-iTCP:'+str(port),'-sTCP:LISTEN','-t'])
   owned.append(r.returncode==0 and set(r.stdout.split())=={str(child.pid)})
  if all(owned):return
  time.sleep(.15)
 raise RuntimeError('临时线路检测启动超时，尚未安装或改网')

def probe_paths(node,log):
 if 'upstream' not in node:
  log.write('DIRECT_CHECK '+json.dumps(probe_direct(node))+'\n');log.flush();return 'direct'
 interface=preflight_interface();ports=reserve_probe_ports()
 config=load('guard_config').build_preflight(node,interface,*ports)
 with tempfile.TemporaryDirectory(prefix='home-line-check-') as folder:
  path=Path(folder)/'check.json'
  fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
  with os.fdopen(fd,'w') as stream:json.dump(config,stream)
  core=DELIVERY/'assets/sing-box'
  checked=run([core,'check','-c',path])
  if checked.returncode:raise RuntimeError('临时检测配置无效，尚未安装或改网')
  # Only a short-lived loopback listener; no admin, TUN, route, PF, or proxy writes.
  child=subprocess.Popen([str(core),'run','-c',str(path),'--disable-color'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','LANG':'en_US.UTF-8'})
  try:
   wait_preflight(child,ports)
   return choose_preflight_route(node,*ports,log)
  finally:
   if child.poll() is None:
    child.terminate()
    try:child.wait(timeout=5)
    except subprocess.TimeoutExpired:child.kill();child.wait(timeout=5)

def wait_for_result(request_id,expected_mode,timeout=155):
 deadline=time.monotonic()+timeout
 while time.monotonic()<deadline:
  try:
   v=json.loads(STATUS.read_text());t=v.get('updated_at')
   fresh=type(t) in (int,float) and math.isfinite(t) and -5<=time.time()-t<=120
   if fresh and v.get('version')==1 and v.get('request_id')==request_id and v.get('core_running') is True:
    if v.get('mode')=='home' and v.get('phase')=='healthy' and v.get('policy')=='home_open' and v.get('successes')==2 and expected_mode=='home':return v
    if v.get('mode')=='original' and v.get('phase')=='blocked' and v.get('policy')=='original_blocked' and v.get('successes')==0 and expected_mode=='original':return v
  except (OSError,ValueError,TypeError):pass
  time.sleep(1)
 return None

class UserServiceError(RuntimeError):
 def __init__(self,issues):
  self.issues=issues
  super().__init__('菜单或提醒登记失败；具体服务和退出码已写入日志')

def service_matches(result,path,args):
 if result.returncode:return False
 found=re.search(r'^\s*path = (.+)$',result.stdout,re.M)
 block=re.search(r'^\s*arguments = \{\n(.*?)^\s*\}',result.stdout,re.M|re.S)
 return bool(found and found[1].strip()==str(path) and block and [x.strip() for x in block[1].splitlines() if x.strip()]==args)

def register_user_agent(domain,label,args,extra,agents):
 path=agents/(label+'.plist');target=domain+'/'+label
 if path.is_symlink():raise RuntimeError('登录项为符号链接')
 payload={'Label':label,'ProgramArguments':args,'RunAtLoad':True,'LimitLoadToSessionType':'Aqua','ProcessType':'Background','Umask':0o077,'StandardOutPath':'/dev/null','StandardErrorPath':'/dev/null',**extra}
 if not extra:payload.update(KeepAlive={'SuccessfulExit':False},ThrottleInterval=15,ProcessType='Interactive')
 data=plistlib.dumps(payload)
 def inspect(timeout=2):
  result=run(['/bin/launchctl','print',target],timeout=timeout)
  # 113 means this named service does not exist. Other failures are not absence.
  if result.returncode not in (0,113):result.check_returncode()
  return result
 loaded=inspect()
 fd,temp=tempfile.mkstemp(prefix='.'+label+'.',dir=agents)
 try:
  with os.fdopen(fd,'wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
  os.chmod(temp,0o600);os.replace(temp,path)
 finally:Path(temp).unlink(missing_ok=True)
 # Always load the complete payload. Matching path/argv cannot establish that
 # launchd has loaded the current StartInterval, KeepAlive or other settings.
 if loaded.returncode==0:
  run(['/bin/launchctl','bootout',target],check=True,timeout=2)
  deadline=time.monotonic()+5
  while True:
   remaining=deadline-time.monotonic()
   if remaining<=0:raise RuntimeError('旧登录项未在限时内卸载')
   if inspect(min(2,remaining)).returncode==113:break
   time.sleep(.1)
 run(['/bin/launchctl','enable',target],check=True,timeout=2)
 deadline=time.monotonic()+5;last_boot=None
 while True:
  remaining=deadline-time.monotonic()
  if remaining<=0:
   if last_boot is not None:last_boot.check_returncode()
   raise RuntimeError('登录项未在限时内加载')
  boot=run(['/bin/launchctl','bootstrap',domain,path],timeout=min(2,remaining));last_boot=boot
  if boot.returncode==0:break
  # Slot cleanup may lag behind print reporting absence. A failed bootstrap
  # never becomes success merely because another loaded job has matching argv.
  if boot.returncode not in (5,37):boot.check_returncode()
  time.sleep(.15)
 deadline=time.monotonic()+5
 while True:
  remaining=deadline-time.monotonic()
  if remaining<=0:raise RuntimeError('登录项已请求加载，但未确认就绪')
  loaded=inspect(min(2,remaining))
  if service_matches(loaded,path,args) and (extra or re.search(r'^\s*pid = \d+',loaded.stdout,re.M)):break
  time.sleep(.1)
 if path.is_symlink() or path.read_bytes()!=data:raise RuntimeError('登录项文件在登记期间发生变化')
 return {'label':label,'action':'loaded','registration_verified':True}

def register_user_services():
 if USER_ROOT.is_symlink():raise RuntimeError('用户日志目录为符号链接')
 USER_ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
 agents=Path.home()/'Library/LaunchAgents'
 if agents.is_symlink():raise RuntimeError('登录项目录为符号链接')
 agents.mkdir(parents=True,exist_ok=True)
 domain='gui/'+str(os.getuid())
 tasks=[('local.claude.residential.status',[str(ROOT/'Home状态.app/Contents/MacOS/ResidentialStatus')],{}),
        ('local.claude.residential.watch',[str(PYTHON),'-I','-B',str(ROOT/'guard_notify.py')],{'StartInterval':30})]
 results=[];issues=[]
 for label,args,extra in tasks:
  try:results.append(register_user_agent(domain,label,args,extra,agents))
  except Exception as error:
   issue={'label':label,'type':type(error).__name__}
   if type(error) is RuntimeError:issue['detail']=str(error)
   if isinstance(error,subprocess.TimeoutExpired):issue.update(operation=str(error.cmd[1]),timeout_seconds=error.timeout)
   if isinstance(error,subprocess.CalledProcessError):
    issue.update(operation=str(error.cmd[1]),exit_code=error.returncode,diagnostic=(error.stderr or '')[:500])
   issues.append(issue)
 if issues:raise UserServiceError(issues)
 return results

def finish_user_setup(log):
 errors=[]
 for stage,action in [('menu_and_notifications',register_user_services),('cli_proxy_settings',install_proxy_preferences)]:
  try:log.write('USER_SETUP '+json.dumps({'stage':stage,'ok':True,'result':action()},ensure_ascii=False)+'\n')
  except Exception as error:
   row={'stage':stage,'type':type(error).__name__,'ok':False}
   if isinstance(error,UserServiceError):row['issues']=error.issues
   log.write('USER_SETUP '+json.dumps(row,ensure_ascii=False)+'\n');errors.append(row)
  log.flush()
 return errors

def setup_failure_message(state,requested,errors):
 actual='Home' if state['mode']=='home' else 'Origin'
 retry='Origin.command' if requested=='original' else 'Home.command'
 names={'menu_and_notifications':'菜单/提醒','cli_proxy_settings':'CLI应用设置'}
 failed='、'.join(names[row['stage']] for row in errors)
 return '网络已切换为 '+actual+'；'+failed+'未全部完成。请重试 '+retry+'，具体失败步骤见本次日志'

def install_proxy_preferences():
 # Only the supported app environment is changed; no language/timezone/browser disguise.
 settings=Path.home()/'.claude/settings.json'
 if settings.parent.is_symlink() or settings.is_symlink():raise RuntimeError('应用配置路径为符号链接')
 settings.parent.mkdir(mode=0o700,exist_ok=True)
 if settings.exists():
  data=json.loads(settings.read_text())
  if type(data) is not dict or type(data.get('env',{})) is not dict:raise RuntimeError('已有应用配置格式需人工核对')
 else:data={}
 backup=USER_ROOT/'before-user-settings.json'
 if not backup.exists():
  fd=os.open(backup,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'w') as f:json.dump({'exists':settings.exists(),'content':data},f)
 proxy={'HTTP_PROXY':'http://127.0.0.1:10808','HTTPS_PROXY':'http://127.0.0.1:10808','ALL_PROXY':'socks5h://127.0.0.1:10808','NO_PROXY':'localhost,127.0.0.1,::1'}
 proxy.update({k.lower():v for k,v in list(proxy.items())});data.setdefault('env',{}).update(proxy)
 tmp=settings.with_name('.home-settings-new')
 fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  with os.fdopen(fd,'w') as f:json.dump(data,f,ensure_ascii=False,indent=2)
  os.replace(tmp,settings)
 finally:tmp.unlink(missing_ok=True)

def privileged(arguments,log):
 subprocess.run(['/usr/bin/sudo','-v'],check=True)
 # Password is read by sudo from the user's terminal and is never captured.
 p=subprocess.run(['/usr/bin/sudo','-n',*map(str,arguments)],capture_output=True,text=True,timeout=240)
 log.write(p.stdout);log.write(p.stderr);log.flush()
 if p.returncode:raise RuntimeError('管理员步骤未完成，请查看本次日志；保护若已建立会继续保留')
 lines=[x[7:] for x in p.stdout.splitlines() if x.startswith('RESULT ')]
 if len(lines)!=1:raise RuntimeError('管理员返回的安装结果无法确认')
 return json.loads(lines[0])

def main():
 if os.geteuid()==0:raise RuntimeError('不要用sudo启动整个用户入口')
 mode=sys.argv[1] if len(sys.argv)==2 else ''
 if mode not in ('install','home','original','diagnostics'):raise RuntimeError('入口参数无效')
 if USER_ROOT.is_symlink():raise RuntimeError('日志目录为符号链接')
 USER_ROOT.mkdir(parents=True,mode=0o700,exist_ok=True)
 logdir=USER_ROOT/'logs'
 if logdir.is_symlink():raise RuntimeError('日志目录为符号链接')
 logdir.mkdir(mode=0o700,exist_ok=True)
 lock=os.open(USER_ROOT/'operation.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
 try:
  fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  logpath=logdir/(datetime.datetime.now().strftime('%Y%m%d-%H%M%S')+'-'+mode+'.log')
  fd=os.open(logpath,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
  with os.fdopen(fd,'w') as log:
   print('日志：'+str(logpath),flush=True)
   if mode=='install':
    preflight();verify_manifest();node=load('guard_config').validate_node(json.loads((DELIVERY/'private/node.json').read_text()))
    print('先验证线路与家宽出口；此阶段不修改系统网络。',flush=True)
    selected_route=probe_paths(node,log)
    print('线路和家宽出口检查通过，开始安装保护。现有连接可能短暂中断。',flush=True)
    result=privileged([sys.executable,'-I','-B',SOURCE/'guard_install.py','--install',DELIVERY/'private/node.json','--initial-route',selected_route],log)
    expected='home'
   elif mode=='diagnostics':
    result=privileged([PYTHON,'-I','-B',ROOT/'guard_install.py','--diagnostics'],log)
    out=logdir/('诊断-'+datetime.datetime.now().strftime('%Y%m%d-%H%M%S')+'.json')
    fd=os.open(out,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as f:json.dump(result,f,ensure_ascii=False,indent=2)
    print('诊断已导出：'+str(out));return
   else:result=privileged([PYTHON,'-I','-B',ROOT/'guard_install.py',mode],log);expected=mode
   registration_errors=finish_user_setup(log)
   state=wait_for_result(result['request_id'],expected)
   if state is None:raise RuntimeError('尚未确认服务就绪，请保留日志；已安装后可重试Home或Origin入口')
   log.write('FINAL '+json.dumps(state)+'\n')
   if state['mode']=='home':
    diag=privileged([PYTHON,'-I','-B',ROOT/'guard_install.py','--diagnostics'],log)
    if len(diag.get('probe_rounds',[]))<2 or not diag.get('log_files') or any(f.get('uid')!=0 or f.get('mode')!=0o600 for f in diag['log_files']):
     raise RuntimeError('Home已验证，但详细日志落盘/权限尚未通过检查；保护继续运行，请导出诊断')
   if registration_errors:raise RuntimeError(setup_failure_message(state,mode,registration_errors))
   if state['mode']=='home':print('Home 已通过两轮出口验证。菜单栏和提醒已登记，日志自动记录。')
   else:print('Origin 已启动，受保护目标继续锁定；普通流量按已配置的线路处理。')
   print('客户端配置与实机验收尚需逐项完成。首次接入请按《新机快速接入》继续；提醒登记不代表通知已实际送达。')
 finally:os.close(lock)

if __name__=='__main__':
 try:main()
 except KeyboardInterrupt:print('已取消；已建立的保护不会因此撤销。');raise SystemExit(1)
 except Exception as e:print('操作未完成：'+str(e));raise SystemExit(1)
