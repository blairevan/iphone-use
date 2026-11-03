# 固定版本的可信离线安装

自动任务只检查版本。`iphone-use upgrade`（包括没有 `--check` 时）不再安装
程序、更新插件、拉取 skill、重签 App 或构建 Runner。旧的 `curl … | sh`
入口、release 解析失败回退 main、下载辅助脚本的安装旁路均已停用。

## 初始信任

使用已经审查、在本地构建的 `iphone-use` 验证器。发布签名管理员提供
`root.json`；其 **SHA-256 指纹必须通过另一个独立可信渠道核对**，不能把下载
页面旁边的 checksum 当作独立信任。普通运行设备不需要、也不应存放发布私钥。

```sh
iphone-use release trust /secure/offline/root.json --fingerprint <独立核对的64位十六进制指纹>
iphone-use release verify /path/to/fixed-release-bundle
iphone-use release install /path/to/fixed-release-bundle --confirm
# 命名实例：同一经验证的发布，可明确选择实例。
iphone-use release install /path/to/fixed-release-bundle --instance phone-two --confirm
```

未配置 root 时安装失败，**不会自动下载或信任发布者密钥**。当前仓库不伪造
上游签名，也没有把测试密钥部署为真实信任根。没有签名的上游 release 不能
通过这条路径安装；可以审查源码后本地构建并显式运行本地安装器。

## 包格式与签名

包是一个普通目录，不自动解压不可信归档。包含 `iPhoneUse.app`、`install.sh`、
`uninstall.sh`、`scripts/setup-runner.sh`、`skills/iphone-use/SKILL.md` 及完整
`runner/` 源码/预构建产物。所有 payload 文件都必须出现在签名清单，目录不能
带符号链接、设备文件或额外未列明的脚本。

`scripts/release-bundle.py` 仅生成元数据与待签名字节，**不生成或读取私钥**。
发布环境的 Ed25519 签名工具/HSM 对以下字节签名：

```text
UTF-8("iphone-use-release-metadata-v1") + 0x00 + 原始 JSON payload 字节
```

公钥为 32 字节原始 Ed25519 公钥；key id 是它的 SHA-256。签名为 64 字节原始
Ed25519 签名。envelope 包含 Base64 编码的 payload 和 key-id→Base64-signature
映射；验证器不重新序列化 JSON，因此不存在不同 canonical JSON 实现的歧义。

先用 `root` 子命令从公钥生成初始根，参数包括 `--root-key`、`--release-key`、
各自的 `--root-threshold`／`--release-threshold`、递增版本及 Unix 到期时间。
两个 key 参数可重复；阈值按不同密钥计票。生产建议离线 root 多签，发布角色
使用独立密钥；不要把 CI 仓库写权限等同于签名管理员权限。

发布清单准备步骤：

```sh
python3 scripts/release-bundle.py manifest /path/to/bundle \
  --version 0.27.34 --sequence <递增序列> --commit <40位固定commit> \
  --expires <Unix到期时间> --platform aarch64-apple-darwin --output /secure/release.payload.json
python3 scripts/release-bundle.py signing-input /secure/release.payload.json \
  --output /secure/release.to-sign
# 在离线签名环境对 release.to-sign 签名，得到 64 字节 release.sig。
python3 scripts/release-bundle.py envelope /secure/release.payload.json \
  --signature /secure/release-public.raw:/secure/release.sig \
  --output /path/to/bundle/manifest.json
```

私钥不能放入 bundle、仓库、应用运行目录、命令行参数或普通日志。应用本地
Apple codesign 身份不是发布清单的信任根，同源 SHA-256 文件也不是签名替代品。

## 轮换、撤销与回滚

`roots/2.json`、`roots/3.json` 等是新 root payload 的签名 envelope，版本必须
逐一递增，**同时满足旧 root 和新 root 各自的签名阈值**。新 root 的 releases
密钥集合不再列出旧密钥即撤销旧发布密钥。最终 root 和 release 都必须未过期。
已过期旧 root 只能认证连续的新 root，不能直接授权安装。超过阈值的 root
密钥同时失陷仍然需要独立渠道恢复；代码无法消除对签名管理员的信任。

验证版本、序列、内容、目标架构、期限及本地时钟回退后，在私有目录逐文件
复制并计算摘要，再执行这一份快照。拒绝重复序列的不同内容、已知旧版本、
额外文件和所有校验失败。每个已认证的新 root 立即持久化，不能通过缺失下一份元数据撤销已知的密钥撤销；root 与防降级记录原子写入同一文件，在暂存载荷前记录
已观察到的序列；安装失败允许重试相同内容，但不能通过故意失败清除防降级。

安装沿用原项目 app／plist／skill／Runner 的事务与健康检查，失败恢复旧安装。
安装事务的回滚不是给任意旧 release 重新授权。确认安装仅针对本次固定快照，
不会开启凌晨自动升级。此封装采用 TUF 的关键安全原则，但**不是完整 TUF 客户端**。

参考：The Update Framework Specification v1.0.37 的 root rotation、rollback
与 freeze 防护章节；本实现的具体约束以 `crates/server/src/release/` 及测试为准。

`release verify` 不修改已安装应用，但会更新已认证的信任根和版本最高水位。即使包缺少载荷，已学到的签名密钥撤销和签名清单序列也不能回退。首次导入前仍须人工核对独立指纹。验证器还要求清单版本与暂存 app 的 `CFBundleShortVersionString` 一致。
