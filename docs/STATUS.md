# 当前工程状态

记录日期：2026-11-04。此文件区分源码、编译和运行证据，不把旧第三方成品或旧 CI 构建当成本轮交付。

| 层级 | 已取得证据 | 未取得证据 |
|---|---|---|
| 版本 | 官方 tags、固定 super/core/gum/releng SHA、16 r25c / 17 r29 要求 | 不自动跟随未来版本 |
| 补丁 | 两版八份 pinned 文件 guard、兼容命名修改、独立 feature、严格重放与完整报告校验 | ART/GC/JDWP 的功能性隐藏替代、所有参考 patch 全面移植 |
| 本地回归 | 46 项通过；真实 C++ 配置/SHA-256 30 检查通过 | 这些测试不是 Android runtime |
| Zygisk wrapper | 本机 r25c 交叉编译；真实 exported entry、NEEDED 检查通过，无 libc++_shared | 17 r29 构建、完整 Gadget 集成、设备 SELinux/namespace/FD 加载 |
| GitHub | 首轮 Linux 回归通过；两版均在 sdkmanager 要求 JDK 17、runner 使用 JDK 11 时失败；已加入显式 JDK 17 配置 | 本轮 server/Gadget 完整构建尚未完成 |
| App | 无新设备操作 | 官方握手、JS/Java/GC/异常/业务可用性及长期稳定性均未验证 |
| KPM | 本地观察基线离线策略/ELF 测试；默认无 hook | 隐藏能力未完成，目标内核 ABI 和加载未经本轮验证 |

## 已知限制

- `apply_patches.py` 对全组源文件做预检查、临时写入和后置检查，但跨多个 `os.replace` 不是文件系统事务；中途 I/O 失败可能留下部分变化。失败必须停止，重用源码前重新核验或使用 fresh checkout。
- 默认兼容 profile 可增量添加 `zygisk-loader`；任意 feature 间自动切换/删除不支持，不能默默接受漂移。
- 来源 JSON 做内容完整性校验，不是恶意篡改防伪签名；CI 必须由 verifier 直接生成。
- FD 加载保持载荷大小/hash，不会隐藏 `/proc/maps`；linker 私有摘链未实施。
- worker 的 wait 不承诺暂停整个 App 主线程。100ms 是可配置试验值，不能声称所有 App 正确时机。
- Zygisk install 使用文本 targets.conf，无图形选 App APK；默认无目标。
- 旧 system_server 崩溃调查目标保持暂停，本轮只推进本地和 GitHub 构建。
