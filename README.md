# Claude Network Kit

供同事使用的 macOS 家宽保护包：Home / Origin、Claude 分流、断线阻断、本机提醒、菜单状态与诊断。**不含任何真实线路、账号密码、订阅身份或个人登录数据。每位使用者必须准备自己的线路。**

## 先确认适用范围

- Apple Silicon Mac，macOS 13 以上；来源版本针对 M1 / Ventura 13.6 做过适配。其他符合版本条件的 Mac 仍需现场验收。
- 仅供首次安装：已有本保护目录、VPN/TUN 或系统代理时，安装器会拒绝覆盖。Windows、Intel Mac、Linux 不适用。
- 家宽：SOCKS5 用户名密码认证、固定公网 IPv4 出口。
- 可选普通代理／家宽前置：当前仅支持美国出口的 VMess + WebSocket，配置不含 TLS。其他协议不能直接填入，需先适配与验证。
- Home 并非“除了 Claude，全部走普通代理”：只有 OpenAI、Notion 和列明的 VS Code 更新域名走普通代理；其余海外流量默认走家宽。国内与局域网按规则处理。

## 最快开始

1. 从本仓库的 [Releases](https://github.com/chakfaigo/claude-network-kit/releases) 下载 `claude-network-kit-macos-arm64.zip`，完整解压；仓库现已公开，无需登录 GitHub 或申请权限。
2. 阅读 [安装与回退](docs/安装与回退.md)，准备自己的线路。若已有代理/VPN，先评估冲突，不要强行覆盖。
3. 双击 `portable/配置线路.command`，输入自己的家宽信息；可选普通代理按 `portable/examples/upstream.example.json` 在本地准备。示例是无效占位数据，不能直接联网。
4. 双击 `portable/安装.command`。它先检查线路，再请求本机管理员授权，最后等待 Home 与日志核验成功。
5. 按 [应用验收](docs/Claude客户端与验收.md) 分别测试浏览器、VS Code、CLI 和桌面端。

使用 GitHub “Download ZIP” 时应确认脚本可执行权限和运行时符号链接完整，推荐使用 Release ZIP。源代码、运行时和配套组件也一并保存在仓库中。

## 文档入口

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
