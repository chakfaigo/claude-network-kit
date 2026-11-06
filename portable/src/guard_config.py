"""Fresh-Mac SOCKS5 configurations. Pure construction; never touches networking."""
from pathlib import Path
import copy, ipaddress, json, re, uuid
PORT = 10808
TUN_INTERFACE = 'utun99'
FLAVOR = 'fresh-mac-upstream-v2'
ORDINARY_SUFFIXES = ['openai.com','chatgpt.com','oaistatic.com','oaiusercontent.com',
 'notion.so','notion.site','notion-static.com']
ORDINARY_DOMAINS = ['update.code.visualstudio.com','marketplace.visualstudio.com',
 'vscode.download.prss.microsoft.com','vscode.blob.core.windows.net']
SUFFIXES = ['anthropic.com','claude.ai','claude.com','claude.app','clau.de','claudemcpclient.com',
 'claudemcpcontent.com','claudeusercontent.com','sentry.io','statsigapi.net','intercom.io','intercomcdn.com']
DOMAINS = ['servd-anthropic-website.b-cdn.net','anthropic.com.cdn.cloudflare.net','anthropic.auth0.com',
 'anthropic-com.ghost.io','browser-intake-us5-datadoghq.com','cdn.usefathom.com']
KEYWORDS = ['datadog','sentry','sift']
IPS = ['160.79.104.0/21']
class ConfigError(ValueError): pass
def require(ok, message):
 if not ok: raise ConfigError(message)
def validate_node(node):
 require(type(node) is dict and set(node) in ({'server','port','username','password','expected_ip'}, {'server','port','username','password','expected_ip','upstream'}),'节点字段不完整')
 host=node['server']
 require(type(host) is str and len(host)<=253 and bool(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?',host)), '节点地址必须为IPv4或DNS主机名')
 require(type(node['port']) is int and 1<=node['port']<=65535,'节点端口无效')
 for k in ['username','password']:
  s=node[k];require(type(s) is str and s.isascii() and 0<len(s.encode())<=255 and not any(ord(c)<32 or ord(c)==127 for c in s),'节点身份字段无效')
 try: ip=ipaddress.ip_address(node['expected_ip'])
 except (ValueError,TypeError): raise ConfigError('必须填写预期公网IPv4') from None
 require(ip.version==4 and ip.is_global,'必须使用预期公网IPv4')
 if 'upstream' in node: validate_upstream(node['upstream'])
 return copy.deepcopy(node)
def validate_upstream(value):
 require(type(value) is dict and set(value)=={'type','server','server_port','uuid','security','alter_id','transport'},'普通线路字段无效')
 require(value['type']=='vmess','普通线路协议无效')
 require(type(value['server']) is str and len(value['server'])<=253 and bool(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?',value['server'])),'普通线路地址无效')
 require(type(value['server_port']) is int and 1<=value['server_port']<=65535,'普通线路端口无效')
 try: identity=str(uuid.UUID(value['uuid']))
 except (ValueError,TypeError,AttributeError): raise ConfigError('普通线路身份无效') from None
 require(identity==value['uuid'],'普通线路身份格式无效')
 require(value['security'] in ('auto','none','zero','aes-128-gcm','chacha20-poly1305'),'普通线路加密方式无效')
 require(type(value['alter_id']) is int and 0<=value['alter_id']<=65535,'普通线路参数无效')
 ws=value['transport']
 require(type(ws) is dict and {'type','path'}<=set(ws) and not set(ws)-{'type','path','headers','max_early_data','early_data_header_name'},'普通线路传输参数无效')
 require(ws['type']=='ws' and type(ws['path']) is str and ws['path'].startswith('/'),'普通线路传输格式无效')
 if 'headers' in ws: require(type(ws['headers']) is dict and set(ws['headers'])=={'Host'} and type(ws['headers']['Host']) is str,'普通线路Host无效')
 if 'max_early_data' in ws: require(type(ws['max_early_data']) is int and 0<=ws['max_early_data']<=65535,'普通线路early data无效')
 if 'early_data_header_name' in ws: require(type(ws['early_data_header_name']) is str and bool(re.fullmatch(r'[A-Za-z0-9-]+',ws['early_data_header_name'])),'普通线路early data标头无效')
 for text in [ws['path'],ws.get('headers',{}).get('Host','')]: require(len(text)<=4096 and not any(ord(c)<32 or ord(c)==127 for c in text),'普通线路包含无效字符')
 return copy.deepcopy(value)
def upstream_outbound(node,interface,tag):
 return dict(validate_upstream(node['upstream']),tag=tag,bind_interface=interface,domain_resolver={'server':'local-dns','strategy':'ipv4_only'})
def targets():return {'domain_suffix':SUFFIXES[:],'domain':DOMAINS[:],'domain_keyword':KEYWORDS[:]}
def build(node, interface, asset_dir, mode, via_relay=False):
 node=validate_node(node)
 require(mode in ('home','home_blocked','original'),'模式无效')
 require(type(interface) is str and bool(re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,31}',interface)) and not interface.startswith('utun'),'需要有效物理接口')
 require(type(asset_dir) is str and Path(asset_dir).is_absolute(),'规则目录无效')
 require(type(via_relay) is bool and (not via_relay or 'upstream' in node),'缺少前置线路')
 original=mode=='original';opened=mode=='home';has_upstream='upstream' in node
 selected='original' if original else 'residential'
 local_resolver={'server':'local-dns','strategy':'ipv4_only'}
 out=[{'type':'direct','tag':'direct','bind_interface':interface,'domain_resolver':local_resolver}]
 if has_upstream: out.append(upstream_outbound(node,interface,'original'))
 elif original: out.append({'type':'direct','tag':'original','bind_interface':interface,'domain_resolver':local_resolver})
 if not original:
  out += [upstream_outbound(node,interface,'upstream') if via_relay else {'type':'direct','tag':'upstream','bind_interface':interface,'domain_resolver':local_resolver},
   {'type':'socks','tag':'residential','server':node['server'],'server_port':node['port'],'version':'5',
    'username':node['username'],'password':node['password'],'network':'tcp','detour':'upstream','domain_resolver':local_resolver}]
 dns=[{'type':'https','tag':'local-dns','server':'223.5.5.5','server_port':443,'path':'/dns-query','bind_interface':interface}]
 if not original or has_upstream: dns.append({'type':'https','tag':'remote-dns','server':'1.1.1.1','server_port':443,'path':'/dns-query','detour':selected})
 if has_upstream and not original: dns.append({'type':'https','tag':'ordinary-dns','server':'1.1.1.1','server_port':443,'path':'/dns-query','detour':'original'})
 td=dict(targets(),server='remote-dns') if opened else dict(targets(),action='predefined',rcode='REFUSED')
 dr=[{'query_type':'AAAA','action':'predefined','rcode':'NOERROR'},td,{'rule_set':['geosite-cn'],'server':'local-dns'}]
 rt={'outbound':'residential'} if opened else {'action':'reject'}
 rules=[{'action':'sniff'},{'port':53,'action':'hijack-dns'},{'network':'udp','action':'reject'},
  {'ip_cidr':['::/0'],'action':'reject'},dict(targets(),**rt),dict(ip_cidr=IPS[:],**rt),
  {'ip_is_private':True,'outbound':'direct'},{'rule_set':['geosite-cn'],'outbound':'direct'},
  {'action':'resolve','strategy':'ipv4_only'},{'rule_set':['geoip-cn'],'outbound':'direct'}]
 if has_upstream and not original:
  ordinary={'domain_suffix':ORDINARY_SUFFIXES[:],'domain':ORDINARY_DOMAINS[:]}
  rules.append(dict(ordinary,outbound='original'));dr.append(dict(ordinary,server='ordinary-dns'))
 exclusions=[]
 for host in [x.get('server','') for x in out]:
  try:
   server_ip=ipaddress.ip_address(host)
   require(server_ip.version==4,'节点暂不支持IPv6地址');exclusions.append(str(server_ip)+'/32')
  except ValueError: pass
 tun={'type':'tun','tag':'tun-in','interface_name':TUN_INTERFACE,'address':['172.19.0.1/30'],
      'mtu':1500,'auto_route':True,'strict_route':True,'stack':'mixed','route_exclude_address':sorted(set(exclusions))}
 return {'log':{'level':'warn','timestamp':True},
  'dns':{'servers':dns,'rules':dr,'final':'local-dns' if original and not has_upstream else 'remote-dns','strategy':'ipv4_only'},
  'inbounds':[tun,{'type':'mixed','tag':'mixed-in','listen':'127.0.0.1','listen_port':PORT}],
  'outbounds':out,'route':{'rules':rules,'final':selected,'auto_detect_interface':True,
    'default_domain_resolver':local_resolver,'rule_set':[{'type':'local','tag':n,'format':'binary','path':str(Path(asset_dir)/(n+'.srs'))} for n in ['geosite-cn','geoip-cn']]}}
def build_bundle(node,interface,asset_dir):
 node=validate_node(node)
 configs={n:build(node,interface,asset_dir,m) for n,m in
   [('home_direct','home'),('home_direct_blocked','home_blocked'),('original','original')]}
 if 'upstream' in node:
  configs.update({n:build(node,interface,asset_dir,m,True) for n,m in [('home_relay','home'),('home_relay_blocked','home_blocked')]})
 return {'version':1,'flavor':FLAVOR,'node':node,'interface':interface,
  'asset_dir':asset_dir,'has_relay':'upstream' in node,'configs':configs}
def validate_bundle(bundle):
 require(type(bundle) is dict and set(bundle)=={'version','flavor','node','interface','asset_dir','has_relay','configs'},'保护包结构无效')
 expected=build_bundle(bundle['node'],bundle['interface'],bundle['asset_dir'])
 require(json.dumps(bundle,sort_keys=True,allow_nan=False)==json.dumps(expected,sort_keys=True,allow_nan=False),'保护包内容不符合预期，禁止启动')
def build_preflight(node,interface,original_port,relay_port):
 """Temporary loopback checks on the target Mac: no TUN, PF, or system settings."""
 node=validate_node(node)
 # Reuse production construction to validate all node/interface inputs.
 production=build(node,interface,'/preflight-unused-assets','home_blocked',True)
 require(all(type(p) is int and 1024<=p<=65535 for p in (original_port,relay_port)) and original_port!=relay_port,'检测端口无效')
 outputs=[copy.deepcopy(x) for x in production['outbounds'] if x['tag'] in ('upstream','residential')]
 return {'log':{'disabled':True},
  'dns':{'servers':[production['dns']['servers'][0]],'final':'local-dns','strategy':'ipv4_only'},
  'inbounds':[{'type':'mixed','tag':tag,'listen':'127.0.0.1','listen_port':port} for tag,port in [('check-original',original_port),('check-relay',relay_port)]],
  'outbounds':outputs,
  'route':{'default_domain_resolver':{'server':'local-dns','strategy':'ipv4_only'},'rules':[
    {'action':'sniff'},{'network':'udp','action':'reject'},{'ip_cidr':['::/0'],'action':'reject'},
    dict(targets(),action='reject'),{'ip_cidr':IPS[:],'action':'reject'},
    # Match production's IPv4 target resolution before forwarding to VMess.
    {'action':'resolve','strategy':'ipv4_only'},
    {'inbound':['check-original'],'outbound':'upstream'},
    {'inbound':['check-relay'],'outbound':'residential'}],'final':'upstream'}}
