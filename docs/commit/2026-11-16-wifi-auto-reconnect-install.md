# 无线重连功能提交与正式安装

用户已授权本次 Git 提交与本机正式安装；远程推送不在范围内。

- 分支：`codex/wifi-auto-reconnect`，功能基线 `cc20df6`。
- 语言与工具：Rust / Cargo / rustfmt / clippy；文档为 Markdown。
- 正式安装原版本：0.27.34。本次从已验收功能分支构建同版本的本地发布构建。
- 主检出由其他会话更新至 0.28.1，保留其改动，本次不合并该独立更新。
- Mac Shadowrocket 全程保持开启；保留配对身份及网络地址缓存。

## 提交流程

- [x] 1. 建立本任务清单。
- [x] 2. 核对工作区与功能分支。
- [x] 3. 加载项目和全局 AGENTS.md。
- [x] 4. 确认没有 CodeGraph 索引，使用文本与源码审查。
- [x] 5. 无冲突、无无关暂存；不在主分支提交。
- [x] 6. 检查全部变更、新文件及敏感信息。
- [x] 7. 确认 Rust 工具链。
- [x] 8. 复核静态检查。
- [x] 9. 复核局部格式与差异检查，保留无关格式基线。
- [x] 10. 复核功能测试。
- [x] 11. 未发现本次可确认的阻断项。
- [x] 12. 独立 CLI 初始化超时无结论；按技能方案 B 完成本地语义审查并归档。
- [x] 13. 用户已明确授权提交本次已验收功能。
- [x] 14. `feat(wifi): reconnect paired iPhones with per-network address memory`。
- [x] 15. 核对作者；实际提交前按文件暂存并重新核对暂存集合。
- [x] 16. 不执行未授权的远程推送。
- [x] 17. 记录提交、安装验收与资源去向。

## 正式安装验收

- [x] 从已提交源码构建 release daemon、MCP 和 legacy launcher。
- [x] 使用项目 make-app.sh / sign.sh 打包签名，原子替换正式 App 并保留回滚备份。
- [x] CLI 链接、daemon、supervisor 和无线 worker 全部使用正式 App 路径。
- [x] 正式 App 签名验证、实际 HTTP GET 与无线就绪状态验证通过。
- [x] 旧调试进程退出，LaunchAgent/helper 不再依赖隔离工作区。
- [x] 记录 USB 断开、Shadowrocket Connected 与主服务 drivable=true。

## 审查资源

- 任务：`iphone-wifi-install-26fdd09e-f714-4234-88e8-121931d6fdc7`。
- 私有目录及 tmux socket：`/private/tmp/iphone-wifi-install-26fdd09e-f714-4234-88e8-121931d6fdc7`。
- 独立只读审查 session：`$0`，名称 `review-r1`，server PID `71564`。
- 审查报告保存在该目录的 `review.txt`，仅提交结论，不提交终端日志。
- 收尾使用 sea-issue-resolver 的 task_tmux.py 按上述实际身份归档并清理。
- 功能分支与工作区保留供用户查看；正式运行不应依赖其产物。
- 审查 session `$0` 已归档释放，task_tmux.py check 返回 complete=true；本任务
  创建的审查进程已退出。保留私有构建/签名日志及验收 JSON 作为安装证据。

## 审查与检查结论

- 逐项复核 USB-only 配对、仅 pair-verify 的网络候选、RSD 设备身份、物理网卡
  绑定、loopback 转发、私有缓存与原子更新、PID 身份及所有权/parked 规则。
- DTX 边界检查及异步回调、停止信号和会话资源释放纳入语义审查。
- 未发现可确认的阻断项；不把 CLI 无返回记录成独立审查通过。
- 复用同一代码状态的 server 测试：1067 通过、1 跳过；加强后的 cache 测试
  11 通过。新模块 rustfmt、全量差异检查和 clippy 已完成；无关历史警告保留。
- 本轮安装相关测试：ad-hoc 签名 4 项、CLI 链接 5 项通过。
- 检查发现已安装 Runner 有独立的 slowBeat 调整。主机 App 以项目脚本生成并
  签名后原子替换，不使用会覆盖该源码的默认完整安装器；手机端源码、配对和
  地址缓存均保留。此操作是明确授权的本地构建安装，不是网络发布或自动升级。

## 最终交付

- 功能提交：`ea776ed`，提交后工作区干净；本记录另行以文档提交归档。
- 安装版本：本地 release 0.27.34 / build 999，代码来自该功能提交；不是上游
  0.28.1 发布，也不改变其他会话的主分支更新。
- 正式位置：`~/Applications/iPhoneUse.app`，CLI 链接保持指向该 App。
- App 使用原项目 sign.sh 的本地 ad-hoc 签名，未访问私钥或变更钥匙串。
  `codesign --verify --deep --strict` 通过，正式二进制 SHA-256 与已签名构建一致。
- 两个 LaunchAgent 的 `IPHONE_USE_SETUP_BIN` 都指向正式可执行文件；通过
  proc_pidpath 检查 daemon、supervisor、worker 的实际映像，均来自正式 App。
  精确匹配旧 debug 程序路径的进程数为 0。链接库仅来自 macOS 系统目录。
- USB 持续断开，签名 Runner `/status` 为 HTTP 200 / ready=true；daemon
  `/agent/status` 为 HTTP 200、runner=true、drivable=true、transport=wifi-tunnel。
- 正式切换前后 Runner 源码和配对身份摘要一致，schema-2 网络记录及旧缓存保留。
  Shadowrocket 验证为 Connected。
- 持久备份：`~/Applications/.iphone-use-wifi-backup-gtjicxds/`，目录权限 0700，
  包含旧 App 和权限 0600 的原配置快照。配置快照只供追溯；回滚时也应将引擎
  指向正式 App，不能把旧调试路径恢复成运行依赖。
- 没有推送、创建 PR、合并主分支或删除未合并工作区/分支。

本轮构建和签名命令（安装证据目录见上面的审查资源记录）：

```sh
CARGO_BUILD_JOBS=2 cargo --config 'source.tuna.registry="sparse+https://rsproxy.cn/index/"' build --locked --release --bin iphone-use --bin iphone-use-mcp --bin iphone-use-legacy-launch
bash scripts/make-app.sh /private/tmp/iphone-wifi-install-26fdd09e-f714-4234-88e8-121931d6fdc7/package
SIGN_IDENTITY=- bash scripts/sign.sh /private/tmp/iphone-wifi-install-26fdd09e-f714-4234-88e8-121931d6fdc7/package/iPhoneUse.app
codesign --verify --deep --strict "$HOME/Applications/iPhoneUse.app"
"$HOME/.local/bin/iphone-use" --version
```

其他格式、clippy、server/cache 测试的精确命令见
[功能验收记录](../wifi-auto-reconnect.md#validation-commands)。
