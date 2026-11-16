# 共享正式 App 与主实例迁移验收

## What changed

- `install.sh` 的命名实例和 legacy default 安装路径共用 `~/Applications/iPhoneUse.app`，共享更新覆盖已安装消费者的状态快照、签名验证、身份核验、健康检查及失败恢复。
- 保留每个实例的配置、认证、配对、缓存及已分配端口；不启动原本 disabled/unloaded 的 Runner。更新已停止的 daemon 时保留其状态。
- `uninstall.sh` 能识别命名实例的共享程序，同时保留共享 App，只清理该实例与已知历史私有副本。
- 新增私有 `primary-instance` 标记及公共读取逻辑，CLI、MCP、setup 和后续未指定实例的安装更新选择迁移后的主实例。
- 新增 `scripts/migrate-primary-instance.py`，仅迁移已暂停的 legacy default；支持预览、独立备份、路径调整、中断恢复和启动失败回滚。

## Why

旧安装器每次安装命名实例都会重新复制 App，导致程序版本与数据隔离混在一起。共享 App 负责版本一致，独立状态目录与端口负责手机隔离。主实例改名后必须同步裸 CLI/MCP 及更新入口，否则它们仍会查找已经退役的 legacy default 配置。

## Verification

本机构建并正式安装 0.28.1 / build 1000；执行默认更新、i12 重复安装、default → i16 迁移，以及改名后的无参数重复安装。最后一次安装自动选择 i16，未重建 legacy default 或实例私有 App。实际进程均来自正式 App，不依赖 worktree 的 `target/`。

| 实例 | 独立状态目录 | daemon / Runner / 视频端口 |
|---|---|---|
| i16 | `~/.iphone-use/instances/i16` | 44321 / 8100 / 9100 |
| i12 | `~/.iphone-use/instances/i12` | 45710 / 8410 / 9410 |

- 两个认证 HTTP 状态端点均为 200，实例身份正确。两边 Runner 保持 disabled/unloaded，两台手机保持 released，无屏幕读取或手机业务操作。
- 对迁移前选取的凭据、配对、设备配置、流程及 OCR 缓存做摘要对比：i16 的 36 个文件、i12 的 8 个文件内容未变。原有 daemon 环境配置逐项保持。
- 裸正式 CLI 的 `instance-context` 返回 i16；正式 MCP stdio 的无参数 `phone_status` 返回 i16，显式 `instance=i12` 返回 i12。两次调用均保持暂停状态。
- 两实例目录内均无 `runtime/iPhoneUse.app`，旧 default 两个 plist 和 loaded label 已退役。正式 App 深度签名验证通过。
- Shadowrocket 全程保持 Connected，未修改 VPN、路由或 Tailscale。

执行命令：

```bash
bash -n install.sh uninstall.sh scripts/setup-runner.sh
git diff --check
rustfmt --edition 2021 crates/core/src/primary_instance.rs
python3 scripts/test-shared-app-install.py
python3 scripts/test-migrate-primary-instance.py
bash scripts/test-install-named-swap.sh
bash scripts/test-install-args.sh
bash scripts/test-setup-runner-shim.sh
bash scripts/test-install-runner-sources.sh
bash scripts/test-install-release-transaction.sh
bash scripts/test-uninstall-safety.sh
bash scripts/test-install-client-config.sh
python3 scripts/test-install-security-policy.py
CARGO_BUILD_JOBS=2 cargo --config 'source.tuna.registry="sparse+https://rsproxy.cn/index/"' clippy -p core -p server -p iphone-use-mcp --lib --bins -- -D warnings
CARGO_BUILD_JOBS=2 cargo --config 'source.tuna.registry="sparse+https://rsproxy.cn/index/"' test -p core -p server -p iphone-use-mcp --lib --bins
CARGO_BUILD_JOBS=2 cargo --config 'source.tuna.registry="sparse+https://rsproxy.cn/index/"' build --release --bin iphone-use --bin iphone-use-mcp --bin iphone-use-legacy-launch
python3 scripts/migrate-primary-instance.py --name i16 --confirm
codesign --verify --deep --strict ~/Applications/iPhoneUse.app
```

本机 `heavy-cargo` 不存在，按仓库规则回退单个、两路 rustc 并发的 Cargo；未引入依赖。Rust lib/bin 测试共 1540 passed、3 ignored；共享安装与迁移隔离测试各 9 项通过，涵盖重复安装、peer 失败、禁用状态、原生 Runner exec、替换中断、凭据移动后中断、IPv6、路径冲突及状态目录覆盖。

曾执行 `clippy --all-targets -- -D warnings`，被既有 `crates/mcp/tests/observe_over_stdio.rs:86` 的 `needless_borrow` 阻断；该文件在基线提交中已有此写法，本次未修改。随后相关库和二进制 Clippy 通过，不声称全目标 Clippy 通过。

独立审查发现的回滚与地址兼容问题已修复并补测；最终定向复核无剩余 Critical/Important。恢复备份和含本机凭据的验证材料仅保存在用户私有目录，不进入 Git。

本次没有恢复手机控制或重新执行拔线控制任务，HTTP/MCP 验收证明服务路由、状态隔离与暂停状态，不能替代实机操作验收。
