# Claude 客户端与验收

## 先把保护安装与客户端安装分开

本包不安装 Claude，不含 Claude 登录态。安装保护会在保留无关键的前提下，将用户 `~/.claude/settings.json` 的 env 代理设置到 `http://127.0.0.1:10808`；也保留供其他工具使用的 SOCKS 变量。本版不自动写.zprofile/.zshrc，也不启用macOS系统代理；其他终端工具的启动环境不要假设相同，应实际核对。

官方 Claude Code 支持 HTTP/HTTPS 代理，不支持只靠 SOCKS。因此 HTTP/HTTPS 变量必须有效，不能仅留 `ALL_PROXY`。NO_PROXY 仅允许预期的本机回环，不要写成 `*` 或把 Claude 域名排除。

## Chrome

Chrome是独立验收项。必须执行[Chrome专用配置与验收](Chrome专用配置与验收.md)，核对QuicAllowed、DnsOverHttpsMode和WebRtcIPHandling目标值与实际生效。当前安装器没有自动设置这些Chrome策略，本版Chrome经受管TUN，系统代理保持关闭；TUN正常不等于Chrome策略已完成。中文语言可保留。

## 实际启动环境与请求目标（必须检查）

按[强制流程C2–C5](必须执行的部署流程.md)核对真正生效的进程环境、大小写代理变量、NO_PROXY、CLAUDE_CONFIG_DIR、全局/项目/托管设置及启动参数。当前安装器只合并默认全局文件，不检查所有覆盖来源。

NO_PROXY不得排除Claude或使用通配全部；自定义目录不能悄悄跳过代理env。未知ANTHROPIC_BASE_URL、网关、API Key或远端执行位置都须先纳入路由与认证验收。不要输出完整环境泄漏Key，也不要用sudo或关闭证书校验来让连接成功。后台旧进程可能保留旧环境，修改后按客户端方式重开并复验。

## CLI

1. 按[官方安装文档](https://code.claude.com/docs/en/setup)安装独立 CLI；原生安装不要求先装 Node.js。VS Code 扩展自带组件不代表终端已有 `claude`。
2. 检查 `claude --version`、实际命令路径及安装来源，避免不同安装方式冲突。
3. 用自己的官方账号登录；订阅登录与 Console/API 计费不同。没有需求时不要添加第三方 ANTHROPIC_BASE_URL 或 API Key。
4. 先在小测试目录运行，用普通权限确认或 Plan；检查已有全局 permissions.allow、插件、MCP、hooks，避免不知情继承部署或合并授权。不要默认启用 bypassPermissions 或 --dangerously-skip-permissions。
5. `/status` 核对代理与认证状态；完成一条最小请求，结合实际连接/路由日志与保护状态判断。状态页有配置不等于请求已走通。

安装包的 10808 是本机核心入口，不是示例家宽端口；不要把账号密码填到客户端代理变量。链路应由核心统一管理。

## 桌面端

只从[官方桌面端入口](https://code.claude.com/docs/en/desktop-quickstart)下载。桌面端自带 Code 所需组件，不要求先安装 CLI。

- Chat 的页面、登录、更新由桌面应用发起，不能用终端出口代替验收。
- Local Code 可使用全局设置；验证本地文件范围、权限和网络。
- SSH / Cloud 请求可能从远端发出，本机家宽保护不能延伸过去。初次使用选择 Local。
- Cowork 和电脑控制需要单独核对执行环境与权限。普通聊天不用先开放屏幕录制或辅助功能。

## 验收记录

每个客户端记录日期、版本、Home状态、登录方式、实际命中规则、出口证据和请求结果。IP 查询站点只能证明它自己的请求，不能自动证明 Claude 的出口。没有服务器侧/目标请求的出口证据时，明确标记为推断。

先做正常路径验收，再在目标机所有者同意的维护窗口进行故障验收：家宽不可达、出口不匹配、核心退出、Origin、恢复、开盖、Wi-Fi切换和重启。故障时受保护目标应拒绝且无其他出口回落，恢复需重新验证。不能把离线测试当这些故障已经实机通过。

无认证 HTTP 探测出现 API 根路径 404 或网页 403，不能直接推断模型 API 故障或账号被封。证书校验通过只说明该 TLS 握手通过，不说明账号可用或出口分类正确。
