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
- [ ] 17. 记录提交、安装验收与资源去向。

## 正式安装验收

- [ ] 从已提交源码构建 release daemon、MCP 和 legacy launcher。
- [ ] 使用项目 make-app.sh / sign.sh 打包签名，原子替换正式 App 并保留回滚备份。
- [ ] CLI 链接、daemon、supervisor 和无线 worker 全部使用正式 App 路径。
- [ ] 正式 App 签名验证、实际 HTTP GET 与无线就绪状态验证通过。
- [ ] 旧调试进程退出，LaunchAgent/helper 不再依赖隔离工作区。
- [ ] 记录 USB 断开、Shadowrocket Connected 与主服务 drivable=true。

## 审查资源

- 任务：`iphone-wifi-install-26fdd09e-f714-4234-88e8-121931d6fdc7`。
- 私有目录及 tmux socket：`/private/tmp/iphone-wifi-install-26fdd09e-f714-4234-88e8-121931d6fdc7`。
- 独立只读审查 session：`$0`，名称 `review-r1`，server PID `71564`。
- 审查报告保存在该目录的 `review.txt`，仅提交结论，不提交终端日志。
- 收尾使用 sea-issue-resolver 的 task_tmux.py 按上述实际身份归档并清理。
- 功能分支与工作区保留供用户查看；正式运行不应依赖其产物。

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
