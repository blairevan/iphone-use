# 多实例共享正式 App

所有实例使用 `~/Applications/iPhoneUse.app`，安装器不再在各实例的 `runtime/` 下复制 App。实例名称决定状态目录、LaunchAgent 标签、手机绑定和端口，与 App 所在目录无关。

## 安装和更新

```bash
./install.sh --instance lab --udid <UDID> /path/to/iPhoneUse.app
./install.sh --instance lab /path/to/iPhoneUse.app --no-setup
```

首次创建需要指定手机；重复安装从该实例的配置中读取绑定和端口。所有实例共用经过签名验证的 App，更新前备份相关 plist 和启停状态，停止已加载的消费者，再切换程序并恢复它们。已禁用或未加载的 Runner 不会被更新操作唤醒。原有实例的认证、配对、无线地址缓存不参与 App 替换。

共享 App 的任一已加载 daemon 未通过进程身份、监听端口和认证 HTTP 状态检查，整个共享更新回滚。共享事务使用用户目录中的安装锁；并行安装会退出，不会抢占另一事务。失败恢复记录留在 `~/Applications/.iphone-use-peer-backup.*`，可能包含凭据，请保持私有。异常断电后不要盲目移除安装锁，应先确认没有安装进程并检查恢复记录。

旧实例仍然指向其私有 App 时，安装器接受已知旧路径并迁到共享程序。旧私有 App 不再被创建或使用；为避免擅自删除数据，原有历史副本不会自动删除。卸载某个命名实例只删除该实例的数据和历史私有副本，保留共享正式 App。

## 将 legacy default 改为 i16

仓库中的迁移工具只接受已暂停的 legacy default，不会把另一实例的数据合并进目标。

```bash
python3 scripts/migrate-primary-instance.py --name i16
python3 scripts/migrate-primary-instance.py --name i16 --confirm
```

默认执行预览。正式迁移时：

1. 验证 default daemon 处于 released，Runner 已禁用且未加载，目标目录和启动项不存在。
2. 备份原配置，将 default 的配置、配对、凭据、缓存、构建产物和日志移至 `~/.iphone-use/instances/i16`。
3. 保留共享 `runner/` 源码、自动更新禁用标记和其他 `instances/`；`bin/` 是实例自己的 OCR 缓存，一并迁入 i16。仅修正已移动文件的绝对路径。
4. 将启动项改为 `.i16` / `.runner.i16`，使用共享 App，保留原手机绑定和原端口；Runner 继续暂停。
5. 写入私有 `~/.iphone-use/primary-instance`。未指定实例的 CLI、MCP 和后续安装更新选择 i16，显式 `IPHONE_USE_INSTANCE=i12` 仍选择 i12。显式 `default` 保留旧语义，不作为 i16 的别名。
6. 验证新 daemon 的实例身份和暂停状态；失败时恢复原路径、配置和运行状态。

历史 `~/Library/Logs/iPhoneUse` 不会删除；新启动项将日志写至 i16 自己的 `logs/`。迁移备份位于 `~/Applications/.iphone-use-primary-backup-*`。迁移工具不修改客户端配置，裸 MCP 命令通过共享程序的主实例解析继续找到 i16；已启动的旧客户端进程需正常重启以加载新版程序。

期望本机布局：

| 实例 | 状态目录 | daemon / Runner / 视频端口 |
|---|---|---|
| i16 | `~/.iphone-use/instances/i16` | 44321 / 8100 / 9100 |
| i12 | `~/.iphone-use/instances/i12` | 45710 / 8410 / 9410 |

## 验证命令

```bash
bash -n install.sh uninstall.sh scripts/setup-runner.sh
python3 scripts/test-shared-app-install.py
python3 scripts/test-migrate-primary-instance.py
bash scripts/test-install-named-swap.sh
bash scripts/test-setup-runner-shim.sh
```

Python 测试在临时 HOME 中运行实际安装函数或迁移事务，使用假的 launchd，不操作真实手机、服务或网络。实机状态验收应另外检查进程路径、两个认证 HTTP 端点、独立持久文件摘要及端口；HTTP 200 只证明服务正常，不表示已恢复手机控制。
