# Claude Network Kit

供同事使用的 macOS 家宽保护包：Home / Origin、Claude 分流、断线阻断、本机提醒、菜单状态与诊断。**不含任何真实线路、账号密码、订阅身份或个人登录数据。每位使用者必须准备自己的线路。**

## 必须先完成：Net.Coffee 配置与验收

**中文系统、浏览器和界面可以保留；出口、DNS、TCP/UDP、IPv6、分流优先级、连接稳定性和并发管理必须严格核对。**

1. 必读 [Net.Coffee 11项强制配置与验收标准](docs/NetCoffee强制配置与验收.md)，逐项填写[本地验收记录](docs/验收记录模板.md)。安装成功、网页能打开或IP高分都不能替代验收。
2. 出口不符、Claude/DNS绕路、保护状态未知或客户端未核对时，不得判为交付完成；不能为试通而关闭保护。
3. 必读[实际排查经验](docs/实际排查经验.md)：包含链式代理与分流、AirDrop兼容、DNS/IP评分、CLI与桌面差异、权限、故障恢复和隐私分发。
4. 网页的TLS指纹示例不能直接套用本包的VMess/WS＋SOCKS5链路；本版不声称把CLI变成Chrome，也不保证账号不会受限制。具体不适用项和未实现项必须如实记录，不能宣称逐字满足网页全部建议。

**Chrome也必须单独配置和验收：** 见[Chrome专用配置与验收](docs/Chrome专用配置与验收.md)。同事版安装器不会自动写Chrome策略；中文可以保留，QUIC、Secure DNS、WebRTC、代理与故障恢复仍须逐项检查。

这些是强制交付标准，**不是声称安装器已经自动检查了所有项目**。目标机的实测与故障演练仍需完成。

## 先确认适用范围

- Apple Silicon Mac，macOS 13 以上；来源版本针对 M1 / Ventura 13.6 做过适配。其他符合版本条件的 Mac 仍需现场验收。
- 仅供首次安装：已有本保护目录、VPN/TUN 或系统代理时，安装器会拒绝覆盖。Windows、Intel Mac、Linux 不适用。
- 家宽：SOCKS5 用户名密码认证、固定公网 IPv4 出口。
- 可选普通代理／家宽前置：当前仅支持美国出口的 VMess + WebSocket，配置不含 TLS。其他协议不能直接填入，需先适配与验证。
- Home 并非“除了 Claude，全部走普通代理”：只有 OpenAI、Notion 和列明的 VS Code 更新域名走普通代理；其余海外流量默认走家宽。国内与局域网按规则处理。

## 最快开始

1. 从本仓库的 [Releases](https://github.com/chakfaigo/claude-network-kit/releases) 下载 `claude-network-kit-macos-arm64.zip`，完整解压；仓库现已公开，无需登录 GitHub 或申请权限。
2. 先阅读上述强制标准及 [安装与回退](docs/安装与回退.md)，准备自己的线路。若已有代理/VPN，先评估冲突，不要强行覆盖。
3. 双击 `portable/配置线路.command`，输入自己的家宽信息；可选普通代理按 `portable/examples/upstream.example.json` 在本地准备。示例是无效占位数据，不能直接联网。
4. 双击 `portable/安装.command`。它先检查线路，再请求本机管理员授权，最后等待 Home 与日志核验成功。
5. 按 [应用验收](docs/Claude客户端与验收.md) 分别测试浏览器、VS Code、CLI 和桌面端。

使用 GitHub “Download ZIP” 时应确认脚本可执行权限和运行时符号链接完整，推荐使用 Release ZIP。源代码、运行时和配套组件也一并保存在仓库中。

## 文档入口

- [Chrome专用配置与验收](docs/Chrome专用配置与验收.md)

- [Net.Coffee 强制配置与验收标准](docs/NetCoffee强制配置与验收.md)
- [实际排查经验](docs/实际排查经验.md)
- [本地验收记录模板](docs/验收记录模板.md)

- [安装、日常使用与回退边界](docs/安装与回退.md)
- [分流、链式代理、性能与保护边界](docs/网络原理与性能.md)
- [CLI、桌面端、认证和验收](docs/Claude客户端与验收.md)
- [CCBaga 与 Net.Coffee 调研、来源和可信边界](docs/参考资料评估.md)
- [排错顺序与故障分类](docs/故障排查.md)
- [隐私与分享要求](docs/隐私与分享.md)
- [验证结果](docs/验证记录.md)

## 仓库结构与来源

`portable/src` 为 Python 保护程序；`portable/menu` 含 Swift 源码和本地签名的菜单程序；`portable/assets` 含 sing-box 和国内规则；`portable/python` 为自带 Python；`tests` 为隔离测试。`portable/来源与构建` 保留核心源码、许可证、构建参数和 Python 来源摘要。

整理版本：2026-11-05。沿用已有保护架构，新增本地填写线路入口与分享文档，没有重新设计网络策略。没有在分享者的电脑上运行安装器或改变网络。历史偶发断线的根因尚未全部确定，不能宣称解决了供应商故障、所有系统兼容问题或账号限制。

此包需要修改系统网络、防火墙和后台服务；安装后的影响范围大于单个 Claude 应用。请先读安装说明。没有 Apple 开发者公证，不要关闭 Gatekeeper、SIP 或全局安全设置。
