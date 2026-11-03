# 安全加固实施与验收记录

适用范围：`iphone-use` 的本地安全加固工作区，基于 `0161185`，版本号仍为
`0.27.34`。这是本地候选版本，不是上游发布、生产签名或真机上线证明。

## 已实现的安全边界

| 范围 | 实现 | 验证与保留的边界 |
| --- | --- | --- |
| 无人值守更新 | 安装器持久关闭旧自动升级任务；检查脚本和 `upgrade` 只通知，不安装、不自更新、不重签、不构建 Runner、不刷新插件或 skill；删除 main 回退和网络安装器执行旁路 | 强制、重装和旧环境参数不能恢复自动执行；当前 Mac 的 launchd 禁用状态、禁用标记、任务文件和加载状态已分别回读 |
| 手动可信发布 | 独立初始信任根、Ed25519 阈值签名、双向根轮换、撤销、期限、版本/序列/时钟回退防护、完整文件清单、私有快照及确认安装 | 已学到的根撤销和签名版本水位在载荷缺失时也持久保存；拒绝不完整、篡改、额外文件、符号链接及 app 版本伪装；不伪造上游密钥，不宣称完整 TUF 实现 |
| 默认监听与迁移 | 默认回环；远程要求显式授权、不同的人类密码与 agent token、可验证的 HTTPS 入口；默认、命名和嵌入式入口使用统一策略 | 旧配置不兼容时在替换文件/停止服务前拒绝升级；已保存的远程 profile 正常继承，关闭 profile 覆盖遗留中继环境变量 |
| 远程访问 | `remote enable/status/disable` 管理既有 HTTPS 入口；验证真实 TLS 和目标设备身份，失败回滚；可信代理仅本机回环，非本机中继强制安全传输 | TLS 终止服务的域名、签发和续期由操作者选定的服务负责；中继是可信终止方，不是端到端加密保证；未创建公网入口 |
| iOS 配对与迁移 | 不自动降级 HTTP LAN，不跨源转发凭据；身份探测同时绑定 nonce 与完整目的 HTTPS 地址；迁移成功后才切换、复制完成后才删除旧凭据 | 不能用转发的 nonce-only 回答冒充新端点；真实撤销持久要求重新授权，不能因重启或 Keychain 删除失败悄悄使用旧密码；没有身份密钥的旧档案需要重新扫码 |
| 身份与授权 | 登录/配对/agent 失败域隔离，密码验证前有有界来源预算；可信 Host/Origin/转发来源；随机主体、独立 read/control agent、持久设备/会话撤销及管理界面 | 合法 agent 和续期不被陌生配对失败全局锁死；同源的新密码登录仍受来源预算约束，不承诺共享网络永不受限；共享旧 bearer 仍是一个共享主体 |
| 任务与 Flow | 任务归属由验证过的凭据决定，确认绑定实际显示提示的版本；管理员接管需新鲜密码与原因；Flow 本地审批独立于下载目录并绑定精确内容和输入 | 下载内容的风险标签不能给自己免确认；调度的 `confirm_side_effects` 不再是永久授权；未知风险和副作用流程要求逐次确认，不承诺可通过 JSON 或模型判断一切 UI 后果 |
| 日志、密钥与卸载 | 默认 tracing 不保留消息正文、凭据、屏幕文字和输入；计时/运行持久日志仅结构化统计及进程级化名；私有存储拒绝链接/不安全权限；卸载先确认升级任务停止 | 显式请求的任务结果/导出诊断仍可能含私人数据；同一 OS 用户已被攻陷不在文件权限的保护范围；本地打包默认 ad-hoc 签名，不创建或解锁私钥/钥匙串 |

## 自动化验收

本次工作区全量 Rust 测试有 **54 个测试目标、1824 项通过、0 项失败、2 项忽略**。
忽略项为真实公共模型服务测试 `task::tests::zen_public_live_text` 和已有的
`redaction::sample::render_sample` 示例生成项，未将它们计为通过。

其他相互独立的验收：安装/卸载/更新/迁移脚本 **134 项**，发布元数据 CLI **7 项**，
Swift 实际传输源码夹具 **12 项**，中继实际 TypeScript 源码夹具 **5 项**，真实二进制
回环 HTTP/TLS 协议 **11 项**。协议测试同时用于优化构建的 app 内二进制；测试 CA 仅在
该测试客户端信任，不导入系统。测试产生的临时进程、证书及状态目录在退出时清理。

iOS Remote App **63 个 Swift 源文件**通过真实 iPhoneOS SDK 的 Swift 6 严格并发类型检查。
这不是 App 链接签名、设备安装或真机验收。Relay 使用已锁定的依赖安装且禁止依赖安装脚本，
TypeScript 类型检查通过；没有部署 Cloudflare 服务。

生产代码的严格 Clippy 检查使用本机现有工具链：
`cargo clippy --locked --offline --workspace -- -D warnings`。
新增的 13 个 Rust 文件完整通过 rustfmt 检查，所有修改通过 `git diff --check`，shell 与
新增 Python、网页 JavaScript 均完成语法检查。全仓格式检查仍有大量既有格式差异；没有以
“统一格式”为由改动不相关文件。额外的 `--all-targets` Clippy 包含一个基线即存在的
`crates/mcp/src/jev.rs:997` 测试夹具 `cloned_ref_to_slice_refs` 告警，不把该扩展检查伪报为全绿。
本次新增的借用、异步测试锁和中继参数结构告警已经修正。

## 可复验命令

这台机器没有 `~/.local/bin/heavy-cargo`，按仓库约定采用顺序执行和并发上限 2。
有 heavy-cargo 的环境应优先使用它。命令需在项目根目录执行。

```sh
export PATH="$HOME/.cargo/bin:$PATH"
git diff --check
bash -n install.sh uninstall.sh scripts/auto-update.sh scripts/sign.sh
CARGO_BUILD_JOBS=2 nice -n 10 cargo check --locked --offline --workspace --all-targets
CARGO_BUILD_JOBS=2 nice -n 10 cargo clippy --locked --offline --workspace -- -D warnings
CARGO_BUILD_JOBS=2 nice -n 10 cargo test --locked --offline --workspace --all-targets --no-fail-fast
CARGO_BUILD_JOBS=2 nice -n 10 cargo build --locked --offline --release --workspace --bins
for test in scripts/test-install-*.sh scripts/test-uninstall-safety.sh; do bash "$test" || exit; done
python3 -I scripts/test-auto-update.py
python3 -I scripts/test-install-security-policy.py
python3 -I scripts/test-release-bundle.py
bash scripts/test-remote-connection.sh
(cd relay && npm ci --ignore-scripts --no-audit --no-fund && npm run check)
bash scripts/test-relay-security.sh
python3 -I scripts/test-security-protocol.py --daemon target/release/iphone-use
```

PR 工作流已加入真实 TLS/撤销协议、迁移策略、通知型更新、发布元数据和中继边界回归；
这是工作流代码更新，不代表已推送到远端或 GitHub CI 已运行。

## 交付与不能冒充完成的项目

本地优化构建和 ad-hoc 签名 app 位于 `target/security-release-candidate.*`，交付目录内的
`verification-results.json`、源文件摘要和 patch 记录本次候选代码及验收证据。
候选 app 保留版本号 0.27.34；它不是同版本的上游原始二进制，不能仅凭版本号识别内容。
Ad-hoc 签名仅用于本机代码完整性，不是发布者签名或 notarization。

当前用户下没有已安装的 iphone-use 主服务，因此没有借“部署安全修复”新建服务、接管手机、
注册 MCP 客户端或更改现有浏览器/手机连接。旧自动升级禁用状态单独保留并回读验证。

生产签名者的公钥指纹、实际 HTTPS 入口及其证书管理、手机扫码/网络切换验收需要真实部署
材料和设备；没有导入测试信任根、虚构发布者身份或用夹具冒充真机。

代码仍在工作区，未提交/推送/合并。当前 Git 提交身份与上一提交身份不一致，未冒用或修改
作者身份，也未把未执行的提交或上线写成“完成”。提交前应核对身份，并按文件审查和暂存。

详细操作与威胁边界：
[签名离线发布](signed-releases.md)、[远程访问与凭据](remote-access.md)、
[任务 API](../agent-task.md)、[本轮设计](hardening-design.md)。
