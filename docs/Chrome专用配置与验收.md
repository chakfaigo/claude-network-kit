# Chrome 专用配置与验收

Chrome是必须单独配置、验证的客户端，不能因为CLI、终端或系统代理正常就跳过。执行本页及[Net.Coffee 11项标准](NetCoffee强制配置与验收.md)后才能记录Chrome的验收结论。

**中文系统、Chrome界面、网页和输入语言都允许保留。Chrome网络配置仍须严格核对。** 不要求伪造时区或安装指纹浏览器；时区记录真实配置，不将与出口一致视作账号安全保证。

**当前同事版安装器只负责网络保护和Claude Code代理设置，不会自动写入下列Chrome策略。** 策略值是目标配置，不是本包已经自动完成的证明。必须在目标机以受支持的Chrome管理方式配置并检查实际生效；不能把创建JSON文件或执行defaults命令本身当作成功。

## 1. 官方 Chrome 与目标配置

使用官方稳定版Google Chrome，记录版本和当前资料目录；不要为了配置清空登录态、cookies、历史或密码。企业管理的电脑先核对既有策略来源，不覆盖企业管理要求。

在 `chrome://policy` 中查看、重新加载策略；以下为本项目的Chrome目标值。若不支持、未知、冲突、报错或值不一致，记录待处理，不能勾选完成。

| 策略 | 目标值 | 作用与边界 |
|---|---|---|
| QuicAllowed | false | 关闭Chrome QUIC，配合核心UDP限制避免HTTP/3路径变化。该策略不支持动态刷新，须保存工作并完全退出、重开Chrome后验证 |
| DnsOverHttpsMode | off | 关闭Chrome自行选择的Secure DNS，让本方案接管DNS。**不是关闭代理核心的DoH**：受保护域名仍应由核心remote-dns经家宽加密解析 |
| WebRtcIPHandling | disable_non_proxied_udp | 限制WebRTC的非代理UDP；此值本身并非禁止所有UDP，代理支持时仍可能使用UDP。本包核心另外拒绝UDP，因此仍须实测WebRTC并核对TCP路径 |

这些策略名称、值和作用已经对照Chromium官方定义核对（2026-11-05）；适用版本分别自Chrome 43、78、91起。以目标Chrome的实际支持和策略状态为准，不用过期chrome://flags代替受支持策略。

若还未部署策略，可先在 `chrome://settings/security` 核对Secure DNS开关，但界面状态不能替代其余策略验收。配置策略时应由目标机所有者或管理员通过受支持的macOS受管偏好/配置描述文件/Chrome管理方式操作；这份仓库没有附一份自动安装Chrome策略的描述文件，不得假设安装网络包后策略就存在。

若必须采用浏览器自己的DoH，需要单独验证其解析器、出站和失败行为，并记录为偏离本基线；不能默认automatic模式就符合受保护DNS要求。DNS服务器引导解析和国内DNS的例外见总标准。

## 2. TUN、系统代理基线、扩展与实际请求

1. 本公开同事版依靠受管TUN接入Chrome，macOS系统HTTP/HTTPS/SOCKS/PAC/自动发现基线为关闭。查看系统网络代理确认没有其他配置覆盖，同时验证TUN与实际连接。**不要照旧说明手工开启系统代理并填10808**：本版安装/切换快照会拒绝已有代理。Claude Code的HTTP_PROXY指向10808是独立的应用设置，不能推导Chrome必须开启系统代理。检查没有VPN、代理扩展或启动参数改变路径。
2. 查看 `chrome://extensions` 和 `chrome://policy` 中可能改变代理、DNS、WebRTC的项目，记录来源。不要随意卸载现有扩展；需要停用时先确认它的作用并保留恢复方式。
3. 用**正在使用的这个Chrome资料目录**打开Net.Coffee的IP、DNS、WebRTC检查；同时结合核心/实际连接证据核对。不能以终端curl、其他浏览器或无痕窗口的结果代替日常Chrome。
4. 再访问实际使用的Claude网页并做最小请求，核对相应连接的受保护规则和家宽路径。IP查询站点只能证明自身那次请求，不能单凭它证明Claude的实际出口。
5. 地理定位权限与公网IP是不同信号；查看Claude等相关站点的定位授权，按实际业务需要决定。不要为了显示某国家伪造GPS，也不要把拒绝定位当作防风控保证。

## 3. DNS、WebRTC 与 IPv6 判断标准

- 受保护域名的实际DNS必须遵循核心指定的加密代理路径；Chrome自己绕到未经核对的解析器或其他出口时不通过。
- WebRTC出现未授权的公网出口地址或其他实际公网绕路时不通过；仅出现局域网私有地址或mDNS名称，不能单凭该项断定公网IP泄漏，需结合实际连接判断。
- 浏览器检测页没有显示IPv6，不等于所有IPv6路径都被限制；结合系统/核心策略和实际请求核对。未解释的受保护IPv6绕路不通过。
- 测试失败、无法检测或网页超时记为待验收，不得把“没有结果”写成无泄漏。
- 不要导出cookies、登录令牌或未经脱敏的Chrome NetLog到公共仓库。需要网络日志时保留本地并只分享必要的脱敏结论。

## 4. Chrome TLS 与网页指纹不能混为一谈

官方Chrome本身使用其版本对应的TLS实现；通过普通HTTP CONNECT/SOCKS隧道、不进行TLS中间人解密时，端到端握手由浏览器完成。不要为了“更像Chrome”给真正的Chrome额外加未知指纹伪装或关闭证书校验。

代理外层TLS的fingerprint字段、浏览器到站点的TLS、Canvas/WebGL、语言、时区不是同一项。检测网页显示Canvas/WebGL不能证明目标Claude看到的TLS。指纹也会随版本与平台变化，不能保证与任意其他Chrome一模一样，更不保证账号资格。

CCBaga-B的环境核验只证明那个伴生浏览器测到的项目，不能当成日常Google Chrome或官方Claude桌面端已经完成验收。

## 5. 故障、恢复与重启都要包含 Chrome

在目标机所有者知情的维护窗口验证：家宽失联、出口不符、Origin、核心退出时，Chrome里的受保护请求不能改走其他出口；恢复后要重新验证，不能只看旧页面缓存仍显示内容。

完全退出Chrome后重开、系统重启、开盖和换Wi-Fi后，检查策略、系统代理保持基线关闭、TUN与Home新鲜状态与一条新请求。未完成的项目在[验收模板](验收记录模板.md)保留待验收。严格UDP/IPv6/PF策略可能影响AirDrop等本地功能，不能为修复它们直接关闭保护。

## 官方与参考来源

- [Chrome策略列表](https://chromeenterprise.google/policies/)
- [QuicAllowed官方定义](https://github.com/chromium/chromium/blob/main/components/policy/resources/templates/policy_definitions/Miscellaneous/QuicAllowed.yaml)
- [DnsOverHttpsMode官方定义](https://github.com/chromium/chromium/blob/main/components/policy/resources/templates/policy_definitions/Miscellaneous/DnsOverHttpsMode.yaml)
- [WebRtcIPHandling官方定义](https://github.com/chromium/chromium/blob/main/components/policy/resources/templates/policy_definitions/WebRtc/WebRtcIPHandling.yaml)
- [Net.Coffee指南](https://ip.net.coffee/claude/claudecode.html)
- [IP检查](https://ip.net.coffee/ip/) · [DNS检查](https://ip.net.coffee/dns/) · [WebRTC检查](https://ip.net.coffee/webrtc/)

检测入口可能调整；若链接变化，从Net.Coffee主站导航进入，不把失效页面当检测通过。
