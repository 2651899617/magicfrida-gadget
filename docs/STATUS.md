# 当前工程状态

记录日期：2026-11-05。此文件区分源码、编译、下载完整性、安装格式与运行证据；不把旧第三方成品当成本轮交付。

**当前工作区已增加新的源码补丁，下面的 Actions run 41822602267 和产品 hash 仅对应旧提交 `99150590…`，不包含本次 helper/socket/DEX/Zymbiote/prgname/main-loop、可选 agent 入口、Gadget 构建/监听/JSON 配置、bridge/runtime 或 GLib/SDK-lock 实验。新增源码尚未提交、未触发新编译、未进行设备测试。**

| 层级 | 已取得证据 | 未取得证据 |
|---|---|---|
| 版本 | 官方 tags、固定 super/core/gum/releng SHA；16.7.19 / NDK r25c、17.25.2 / NDK r29 | 不自动跟随未来版本 |
| 补丁 | 两版 43／47 份 core/gum pinned 文件 guard；默认 16／18 份命名修改；Gadget 构建/头文件/Fruity 消费者闭环与可选 JSON 配置；可选 agent 入口联动 24／26 份文件；独立 bridge、GLib 线程、SDK-lock 和16 runtime接入 recipe | 新源码的 CCode/Android 编译、最终 embedded agent lookup；真实 Gadget 配置/SONAME/加载、ART/GC/异常功能、GLib 静态 SDK 重编及最终链接消费 |
| 本地回归 | 最新 116 项全部通过、零 skip；每版 32 种 feature 集及正反顺序零 fuzz/零 offset 重放；Gadget 源码专项 9 项、产物专项 29 项；两版 ART 源码模型各 39 检查、真实 C++ 配置/SHA-256 30 检查通过 | runtime/模块打包的编译器是测试替身，Gadget 文件查找为限制性源码模型，不是 Android runtime；当前工作区改动尚未提交 |
| GitHub 编译 | run 41822602267 的 checks、16/17 两个完整构建任务均 success；两版 server、魔改 Gadget 自动初始化版、魔改 Gadget Zygisk 专用版、wrapper 与模块 zip 已生成并上传 | 编译成功不是官方客户端连接或 App 可用性证据 |
| 来源复核 | 两版实际 CI source 与 post-build patch 报告通过本地完整性校验；完整 GitHub 构建日志已保存 | 来源 JSON 不是防恶意伪造签名 |
| 本地产品核验 | 两版归档大小/SHA-256、CRC、路径、最终二进制及模块载荷/入口/依赖/默认配置/源码 hash/许可证复核全部通过；两版 server 在设备执行 --version 正确 | 完整性检查不代表注入运行成功 |
| server 实机运行 | 16.7.19 对 com.tq.my：首轮非默认参数/remote spawn 失败并出现 arm32 zygote SIGBUS、随后 framework 重启；默认 server/USB 重试 spawn→resume 成功，目标 PID 和系统 PID 持续 30 秒稳定 | 尚未完成目标 App 脚本/Java 功能验收；首轮根因未确定；17 仅验证 --version，未注入 |
| Zygisk wrapper | 两版 CI 交叉编译通过；本地复核真实 exported entry 与 NEEDED，通过且无 libc++_shared；最终专用 Gadget 显式初始化入口存在 | 设备 Zygisk API、SELinux/namespace/FD 加载及宿主业务未验证 |
| 安装格式 | Magisk v29.0 文档与 APatch tag 11282 默认安装源码均确认管理器安装不要求 META-INF；默认提取后 source customize.sh，SKIPUNZIP=0 符合该流程 | 本轮未实际安装；未覆盖 APatch 自定义 metamodule 安装器；当前包不提供 recovery 安装入口 |
| App | 默认 16 server spawn 后 com.tq.my PID 11751 持续 30 秒存活，前台 Activity 为 .MainActivity；boot ID/系统 PID 不变 | 未验证完整业务、长期稳定性及 JS/Java/GC/异常处理；不把 spawn 无脚本测试称为完整功能通过 |
| KPM | 本地观察基线离线策略/ELF 测试；默认无 hook | 隐藏能力未完成，目标内核 ABI 和加载未经本轮验证 |

## 2026-11-04 至 2026-11-05 本地源码迁移

- 仅采用 `fridaneed/最新的frida内容/anti-frida.py` 作该脚本参考，旧副本不重复。三套 patch 与三篇文章的逐点结论统一写入 `docs/patch-decisions.md`，不是整体淘汰实践脚本。
- compatible 已落实 helper 32/64 资源、helper process 与注入 fallback 两条 abstract socket、Gum 现有 prgname、core 主循环线程；17 另有 DEX、Zymbiote host/payload/template 三方同步与 mapper 标签。默认保留官方协议和 `frida_agent_main`。
- 可选 `agent-entrypoint-rename` 通过 Vala CCode 同步定义、JNI/glue、导出、各平台注入调用及 labrat/test 到 `nianchu_agent_main`；默认/当前 CI 不启用。collector/模块命名带 `-entry-renamed-`，不混作默认产物。
- 保留原始 fixture 字节/SHA；入口补丁中 Windows `.def` CRLF 用 Git `-text -eol` 保留。重放使用 GNU patch `--binary --fuzz=0`，拒绝 offset；未宽松重放或改原始 fixture 规避失败。
- 最新完整回归：**116 项全部通过，零 skip**，用时 **144.339 秒**；每版 **32 种 feature 集**的直接/增量/重复与正反顺序零 fuzz/零 offset 重放通过。两版 direct ART 源码模型各 **39 检查通过**，真实 C++ 策略/hash **30 检查通过**。日志：[regression-full-gadget-locked-20261105.log](E:/frida魔改/work/nianchu-source-migration-tools-20261104/regression-full-gadget-locked-20261105.log)。此前 103 项为 Gadget 新迁移前基线，旧日志保留。新 Gadget 源码专项 9 项、产物专项 29 项（含新增 4 项身份/打包模型）通过；首轮专项有 1 项误将 16 排序符号套到 17 的测试断言失败，改为分版本断言后重跑通过，补丁保留两版原有排序符号。首次全套 116 项通过后又补非 Darwin 空实现及最终文件链接/解析身份断言，中间运行主动停止，最终对固定代码重新全套通过；停止日志不作通过证据。
- `fridagadget16.5.7魔改.md` 的有效正文 13–290 已逐点采用：两版监听标签、raw/modulated/生成头与 glue/Darwin 消费者、ELF 最终 `nianchu-gadget.so` 及 compat 路径、Droidy 共享暂存前缀和 portal 文案。完整归档扫描发现 Fruity 的 TCP 标签识别消费者，新增同时接受官方旧标签/nianchu 标签，保留端口解析和复用流程。每版新增 8 份固定源码，清单为 `patches/gadget-files.json`；两版完整 guard 43／47、默认修改 16／18。
- 可选 `gadget-json-config` 仅改 Android Gadget 的文件查找顺序为 `.config` → `.json` → `.config.so`；默认/脚本配置、framework、显式 config_data 优先及错误语义保留。Gadget/zip 带 `-json-config-`，与入口实验组合为 `-entry-renamed-json-config-`；server 不添加 JSON 变体名。collector/builder 校验实际最终文件名及源码/hash 配置约定，标注 `runtime_lookup=not-tested`。模块仍直接传 JSON，不复制文章的 App 私有配置写入或脚本安装。
- Gadget 配置测试为限制性源码翻译模型；两版监听 set_thread_name 的非 Darwin 实现为空，只有 i/macOS 实际设置监听线程名，Android worker 的 g_thread_new 标签为另一既有路径。模块 zip 模型的 compiler/readelf 为替身、synthetic ELF 仅在临时测试目录。没有真实生成头编译、SONAME/dynamic lookup、Android Gadget 或模块运行证据。`git diff --check` 通过，既有 Git 换行 warning 保留，未做全仓换行规范化。
- 官方 Java bridge 6.3.9／7.0.13 源码包已从 registry.npmjs.org 下载并核 SHA-512/SHA-1；原 6.3.9 android.js 缓存与完整包逐字相同。两版独立 `direct-art-gc` 源码 recipe 已完成，联动原方法替换、clone 非虚原调用、GC/GetOat 角色及失败/revert 清理；7.0.13 另适配 ESM 与 Nterp clone 同步。桥接专项 **13 项通过**，两版各 **39 个源码模型检查通过**，零 fuzz/零 offset 重放和语法检查通过。下载未执行包代码；未改变用户 registry 或客户端。默认构建仍未启用实验 bridge，16 QJS/V8 和17外置打包、Frida/Android runtime 均未验证。
- 当前两文件联动的独立准备包：[6.3.9](E:/frida魔改/work/nianchu-bridge-direct-gc-639-current-20261105/package)、[7.0.13](E:/frida魔改/work/nianchu-bridge-direct-gc-7013-current-20261105/package)，各自有 bridge-report.json；这是源码包，不是编译产物。旧 `nianchu-bridge-direct-gc-20261105` 初稿不含后续 class-factory 联动，不作当前输入。
- 两版完整 releng/deps.toml fixture 与 SDK/bootstrap/GLib pins 已登记至 `patches/dependencies.json`。新增 `verify_dependency_sources.py` 的输入门槛：完整固定 checkout、HEAD 与 blob 字节、递归子模块；拒绝忽略的旧构建文件和 `skip-worktree` 掩盖漂移。专项 9 项通过；尚未接入 CI，不接受导出归档，不认证修改后的 SDK 或最终链接消费。
- 两版 GLib 固定归档已下载到隔离目录，仅作位置研究；根目录许可证为 `LICENSES/` 而非 COPYING，首次 anchor 检查因此失败，修正后下载成功。归档导出不含完整 Git 子模块且省略两个 symlink，未执行其中代码，不当作可构建 checkout。
- 16 独立 `gum-runtime` 源码接入已完成：默认空值选项、19 个实验包文件依赖、编译前严格准备、`-direct-art-gc` 缓存隔离、QJS/V8 生成 hash 报告。7 项专项通过，编译器为模型替身；无真实 runtime bundle/最终二进制/运行证据。CI 与 collector 未接入此变体，默认 bridge 不变。
- GLib 独立 `thread-labels` recipe 每版 7 份 guard，只改两处诊断线程标签为 `nianchu-worker/nianchu-dbus`，生命周期保留；日志域/GType 保留。releng 独立 `sdk-lock` 在启用后核 SDK 的 machine/prefix、版本、文件集/hash，失败不走目录删除或 SDK 下载兜底；仅单 SDK 字节锁，不证明构建来源或最终链接。两类 recipe 的 8 项专项通过，未真实重编 SDK。
- `GLib-GIO/GDBusProxy` 的日志/类型兼容方案及 `FridaScriptEngine/GumScript` 注册类型仍未完成。`pool_spawner/pool_spoiler` 固定 core/gum 未命中；`frida-inject` 命中独立工具 target/说明，非当前运行线程。
- 本机 PATH 未发现 valac、Meson、Ninja、Clang 或 Docker；`wsl --list --quiet` 返回 1，解码错误明确为“未安装适用于 Linux 的 Windows 子系统”。未安装工具链或修改系统环境；未执行本轮完整 Frida/SDK 编译，未产出包含新增 patch 的 Android 二进制。最终 agent 动态符号 lookup、官方客户端、JS/Java/GC/异常/业务均未经本轮验证。
- 此次实施 **无手机/ADB/KPM、无系统 Python/frida.exe 修改、无 commit/push/dispatch**；以下实机证据属于此前已结束的窄授权测试，不自动恢复。

## 已验证的旧基线构建

- 仓库分支：`fix/build-integrity`。`main` 未合并，未发布 Release。
- 构建提交：`99150590d5eb22bb492b6b1c1b1571c1635e7a66`。
- [GitHub Actions run 41822602267](https://github.com/2651899617/magicfrida-gadget/actions/runs/41822602267)。
- 16/17 的 compatible 编译、增量 zygisk-loader 编译、最终 target 收集、wrapper 编译、入口检查、模块打包及 artifact 上传步骤均 success。
- 该 run 的 Linux 回归为 47 项；本地加入 5 项 source verifier 测试后为 52 项，不能把新增测试说成已由该 run 执行。
- 17 构建实际日志为 `go version go1.26.10 linux/amd64`；源码要求 Go >= 1.26，CI 显式启用 Compiler backend。

### 产品归档身份

两份本地完整归档的大小/SHA-256 均与 Actions 上传日志记录一致；CRC、路径和解包检查通过：

| 版本 | Artifact | zip 字节数 | 已核验归档 SHA-256 |
|---|---|---:|---|
| 16.7.19 | [13317652864](https://github.com/2651899617/magicfrida-gadget/actions/runs/41822602267/artifacts/13317652864) | 79934448 | `2d10ec4ac8b618a4c89e6fe2f9e8f1eaf2551da60278449091516b06743a2df1` |
| 17.25.2 | [13317548392](https://github.com/2651899617/magicfrida-gadget/actions/runs/41822602267/artifacts/13317548392) | 118974821 | `ea49a4e8a80b10d9c94f5042fc5afdc3cfd6ef8a57ace9a7ad9f279e684f6099` |

每版产品包含：

- `nianchu-server-<version>-android-arm64`
- `nianchu-gadget-<version>-android-arm64.so`：**魔改 Gadget 自动初始化版**。
- `nianchu-gadget-zygisk-<version>-android-arm64.so`：**魔改 Gadget Zygisk 专用版**，由模块显式调用初始化入口。
- `nianchu-zygisk-<version>-android-arm64.zip`：自有 wrapper 与最终专用 Gadget；`targets.conf` 默认无目标。
- 完整 source/patch manifest、模块 build report 和许可证通知。

两种 Gadget 均来自本项目修改后的固定源码，不是官方未修改成品。默认修改为兼容基线；exit-monitor-off / signal-interposition-off 本轮未启用，不宣称全面强化已完成。

## 本地最终产物

### 16.7.19

| 产物 | 本地文件 | 字节数 | SHA-256 |
|---|---|---:|---|
| server | [nianchu-server-16.7.19-android-arm64](E:/frida魔改/work/nianchu-range-16-41822602267/files/out/compatible/nianchu-server-16.7.19-android-arm64) | 53698272 | `3aab08b4a7a741c9784c5752c1acd66ae43a9d40e2e68f5bb3b8a7792c248985` |
| 魔改 Gadget 自动初始化版 | [nianchu-gadget-16.7.19-android-arm64.so](E:/frida魔改/work/nianchu-range-16-41822602267/files/out/compatible/nianchu-gadget-16.7.19-android-arm64.so) | 25818472 | `b40cd5dda14d4aaf7a1803a53d008e46cb3b8e0aef0dbe2f18692dae8f306935` |
| 魔改 Gadget Zygisk 专用版 | [nianchu-gadget-zygisk-16.7.19-android-arm64.so](E:/frida魔改/work/nianchu-range-16-41822602267/files/out/zygisk/nianchu-gadget-zygisk-16.7.19-android-arm64.so) | 25818472 | `cff7ac899e57010291ba786c785b61e56c57b2e3beef2d502ceb59fb7550cd8d` |
| Zygisk 模块 zip | [nianchu-zygisk-16.7.19-android-arm64.zip](E:/frida魔改/work/nianchu-range-16-41822602267/files/out/module/nianchu-zygisk-16.7.19-android-arm64.zip) | 10157329 | `a1a42b5e777260d4413cacde47edb0032d9b94832091ed2daa798443dd7bc7c3` |

wrapper SHA-256：`b926ab4532ee4ea27a4804f684f6bb3adc3b1a8d029cd0168b55d0a7f35d1ed0`。

### 17.25.2

| 产物 | 本地文件 | 字节数 | SHA-256 |
|---|---|---:|---|
| server | [nianchu-server-17.25.2-android-arm64](E:/frida魔改/work/nianchu-range-17-41822602267/files/out/compatible/nianchu-server-17.25.2-android-arm64) | 84852608 | `cc3d96727365ff051e0401084aa3bfffa5c97ed6fd495192914ff4fcc7f046bb` |
| 魔改 Gadget 自动初始化版 | [nianchu-gadget-17.25.2-android-arm64.so](E:/frida魔改/work/nianchu-range-17-41822602267/files/out/compatible/nianchu-gadget-17.25.2-android-arm64.so) | 39409456 | `d153565b4704d0087d05fd1b44504bee9ad4f720c117b728524e277961926d99` |
| 魔改 Gadget Zygisk 专用版 | [nianchu-gadget-zygisk-17.25.2-android-arm64.so](E:/frida魔改/work/nianchu-range-17-41822602267/files/out/zygisk/nianchu-gadget-zygisk-17.25.2-android-arm64.so) | 39409456 | `724fc1bbb58c29383805b664e852a04db2dbf02698e683618cedca20522a0ef9` |
| Zygisk 模块 zip | [nianchu-zygisk-17.25.2-android-arm64.zip](E:/frida魔改/work/nianchu-range-17-41822602267/files/out/module/nianchu-zygisk-17.25.2-android-arm64.zip) | 14734700 | `1625db26f898a75f2263da88c31d7cc180345f1c7522616c8c98c259dc20e232` |

wrapper SHA-256：`c0bef6586ef35d8b8fc2b31ce69bccc81731cff58c1acc753842aaa0356588a1`。

### 两版共同核验结果

- compatible 与 zygisk 目录中的 server 字节/hash 相同；每版两种 Gadget 不同，显式入口存在与否符合初始化 profile。
- 模块内专用 Gadget 与收集器最终文件的大小/hash 一致。
- 真实 wrapper 入口 `zygisk_module_entry`、专用 Gadget 入口 `nianchu_gadget_init` 均为已定义的 GLOBAL DEFAULT 动态导出。
- wrapper 实际 NEEDED 仅为 `liblog.so`、`libdl.so`、`libm.so`、`libc.so`，与报告一致，无 `libc++_shared`。
- source/patch 报告、完整模块源码清单/hash、包内配置/README/许可通知与本地来源逐项核对通过。
- zip 根目录、module.prop 和确切文件清单符合打包规则；无 service.sh/post-fs-data.sh、额外 APK 或默认启用的目标。
- 17 ELF 使用本机 r25c 的 llvm-readelf 只读解析；**17 编译工具链仍是 CI 的 r29**，未用 r25c 重编 17。

只读核验报告：

- [verification-16-41822602267.json](E:/frida魔改/work/nianchu-download-tools-20261104/verification-16-41822602267.json)
- [verification-17-41822602267.json](E:/frida魔改/work/nianchu-download-tools-20261104/verification-17-41822602267.json)

## 下载与日志记录

- 两版产品分别位于 `E:\frida魔改\work\nianchu-range-16-41822602267` 和 `E:\frida魔改\work\nianchu-range-17-41822602267`；完整 `artifact.zip` 已核验，提取文件在 `files\out`。
- 真实来源报告与完整日志：`E:\frida魔改\work\nianchu-logs-41822602267-g8vq3rrt`。
- 本地下载/校验脚本与报告隔离于 `E:\frida魔改\work\nianchu-download-tools-20261104`，使用 Python `-I`；不从下载目录启动解释器或运行载荷。
- 首轮两版分块下载均因个别传输错误退出；续传分别复用 76/77 与 112/114 个完整分块，只补缺块，随后完整大小/SHA-256、CRC 和路径检查通过。
- 续传增加身份、缓存文件名/长度、禁止覆盖已重组归档和最终 hash 门槛；独立的 6 项离线失败测试通过。这 6 项不属于仓库的 52 项回归。
- 此前 6373376 字节的旧下载仍是残缺文件，未提取，不得作为交付。

## 安装格式的已核实事实

[Magisk v29.0 官方 guides.md](https://github.com/topjohnwu/Magisk/blob/v29.0/docs/guides.md#magisk-module-installer) 明确：模块本身打成 zip 即可作为管理器安装包；`META-INF/com/google/android/update-binary` 与 `updater-script` 仅在支持 recovery 刷入时需要。

[官方 util_functions.sh](https://github.com/topjohnwu/Magisk/blob/v29.0/scripts/util_functions.sh) 的 `install_module()` 提取根目录 `module.prop`，在没有 `SKIPUNZIP=1` 时提取其余文件并设置默认权限，再 source `customize.sh`。

APatch 的核查固定到 [tag 11282 / commit e8e4651c16fb5075882a25813c8732285fdb3505](https://github.com/bmax121/APatch/commit/e8e4651c16fb5075882a25813c8732285fdb3505)：[管理器入口](https://github.com/bmax121/APatch/blob/e8e4651c16fb5075882a25813c8732285fdb3505/app/src/main/java/me/bmax/apatch/util/APatchCli.kt#L274-L306) 直接调用 `apd module install`；[module.rs](https://github.com/bmax121/APatch/blob/e8e4651c16fb5075882a25813c8732285fdb3505/apd/src/module.rs#L375-L402) 检查根目录 `module.prop`；[内置 installer](https://github.com/bmax121/APatch/blob/e8e4651c16fb5075882a25813c8732285fdb3505/apd/assets/installer.sh#L371-L386) 排除 META-INF、默认提取并 source `customize.sh`。

本项目无 legacy `install.sh`；`SKIPUNZIP=0`、`ARCH=arm64` 与 API 数值比较符合该默认流程。`bash -n` 静态语法检查通过，未运行安装器。无需为管理器安装添加 recovery bootstrap；自定义 metamodule `metainstall.sh` 不在此次结论范围。

这只是格式与源码证据，不证明当前设备管理器安装或 Zygisk 加载已成功。

## 2026-11-04 server 实机测试与首轮故障

设备为 Pixel 3 / blueline，serial `8B5X13Z86`，Android 10 / API 29 / arm64，内核 4.9.210，SELinux Enforcing。用户已停止既有 hluda。两版 server 推送到独立临时目录，设备端 SHA-256 与上表一致；实际 `--version` 分别返回 16.7.19 / 17.25.2。官方 Python 客户端分别安装在本轮独立 venv，未修改原有 Python/frida.exe。

用户明确允许本次 `com.tq.my` 真正 spawn 所需的 zygote/system_server 内部 agent 路径和当前 server 的官方 SELinux policy 初始化；这不包含 KPM、主动重启、清数据、重装或替换现有模块。

### 首轮：非默认参数/remote，失败

实际启动参数：

```text
server16 --disable-preload --ignore-crashes --verbose --listen=127.0.0.1:31416 --directory=/data/local/tmp/nianchu-runtime-20261104-70ffefc3/agent16
```

匹配官方客户端通过本轮 adb forward 和 `add_remote_device('127.0.0.1:31416')`，调用 `device.spawn(['com.tq.my'])`。约一秒后报 `TransportError: agent connection closed unexpectedly`；spawn 没有返回目标 PID，未执行 attach、测试脚本或 resume。记录“official-client-connected”仅表示创建了远端 device 对象，不是独立协议握手验收。

- 21:11:00.675：32 位 zygote PID 869/TID 4824 和子进程 4825 同时 SIGBUS / BUS_ADRALN，fault addr 0x6e。
- 最初几秒取样仍显示旧 PID，不能据此排除延迟重启。
- 21:11:04.804：新 zygote64 PID 4888 记录 `boot_progress_start: 31920925`；21:11:06.252 新 system_server PID 5017 记录 `boot_progress_system_run`，并出现 BootAnimation。
- system_server 从 1416→5017，zygote64 从 868→4888，zygote32 从 869→4889。这是 Android framework 重启证据；同一时段 boot_progress 已是开机后约 8 小时 52 分，随后 uptime 仍为约 8 小时 58 分，**不是内核/整机冷重启**。未执行 adb reboot。
- 本轮 server PID 4798 已 TERM 停止，本轮 31416 转发已移除；未重试 17。

只读定位显示：SIGBUS PC 位于 ARM32 libc `do_nftw` 中，故障指令为 `ldrd r0,r1,[r7,#0x24]`，r7=0x4a，实际访问 0x6e。父/子 LR 位于 libc `fork()` 内部 atfork 父/子分支附近；父 r0=4825、子 r0=0，支持 clone 已产生父子后的恢复/回调路径异常。不能从损坏回溯证明是哪一个回调或 hook 导致。tombstone 已有 nianchu-agent-32.so 和两个 UUID memfd 库，栈值进入 UUID 库；多份 agent/既有 hook 交叉是疑点，不是已证根因。

默认资源创建/lookup、构建期 blob 与 `frida_agent_main` 约定匹配，未发现确定的资源改名 bug。未逐个验证 embedded arm32 ELF 的边界仍是覆盖限制，不等于发现编译损坏。非默认选项、remote/USB、启动时旧进程内 agent 状态尚未形成单变量对照，不能指认某个选项或编译问题为首轮根因。

证据目录：`E:\frida魔改\work\nianchu-runtime-20261104-70ffefc3\crash-evidence-2dad3d`，保存两份 tombstone 和 crash/all logcat。首轮原始报告 `spawn-16.json` 保留了早期取样，须结合后续日志理解，不将其中早期 after PID 当作完整观察期结论。

### 用户默认方式及一次无脚本复测：成功，无重启

用户手动 `./server16`，官方 CLI `frida -U -f com.tq.my -l poketyu.js` 已输出 Spawned/Resuming；其后 TypeError 和进程退出是独立的脚本/应用问题，不能倒推 spawn 失败。

随后用户明确要求再 spawn 一次观察。实测使用同一 server16 **不传任何选项**、匹配官方 16.7.19 客户端的 USB device，执行一次 `device.spawn(['com.tq.my'])` → `device.resume(pid)`，**未加载任何目标 hook 脚本**：

- 新目标 PID 11751，连续观察超过 30 秒均存活。
- 前台 resumed Activity 为 `com.tq.my/.MainActivity`；不据此宣称完整业务或脚本功能通过。
- system_server=5017、zygote32=4889、zygote64=4888 全程不变。
- boot ID `72ed91c2-fc74-4384-842d-6bfc8744319d` 不变，uptime 从 32440.51→32475.73 秒连续增长。
- 本次未观察到 framework 或整机重启；测试 server PID 11703 已停止，目标 App 保留运行，未新增 adb forward。

[无脚本默认复测报告](E:/frida魔改/work/nianchu-runtime-20261104-70ffefc3/spawn-16-default-retry.json)。该结果确认同一 16 产物可完成此设备/目标的默认 spawn→resume，但不代表完整 JS/Java/hook 功能已通过，也不消除首轮故障。17 尚未进行 spawn/注入。

## 已知限制与执行边界

- `apply_patches.py` 对全组源文件做预检查、临时写入和后置检查，但跨多个 `os.replace` 不是文件系统事务；中途 I/O 失败可能留下部分变化。失败必须停止，重用源码前重新核验或使用 fresh checkout。
- 默认兼容 profile 可增量添加 `zygisk-loader`；任意 feature 间自动切换/删除不支持，不能默默接受漂移。
- FD 加载保持载荷大小/hash，不会隐藏 `/proc/maps`；linker 私有摘链未实施。
- worker 的 wait 不承诺暂停整个 App 主线程。100ms 是可配置试验值，不能声称所有 App 正确时机。
- 模块使用文本 `targets.conf`，无图形选 App APK；默认无目标。不包含开机 APK 安装、属性改写、全局信号过滤或 KPM 自动加载。
- 16 bundled Java bridge 为固定 6.3.9；17 bridge 为客户端/脚本外置依赖，不能将 server/Gadget 编译通过当作 Java bridge 功能验证。
- 旧 system_server 专项崩溃目标未自动恢复；本轮仅按用户的新授权测试 com.tq.my server spawn，17 和 Gadget/Zygisk 未注入。
- 已部署两版 server 到独立临时目录，并执行 16 的上述两次测试；未加载 KPM、主动重启、清数据/重装 App、修改 /data/system 或 /data/app，也未修改系统 Python/frida.exe。测试服务已停；进一步设备实验需要明确测试范围。
- 当前全部源码/fixture/测试/文档改动尚未提交/推送，继承的 `tests/test_source.py` 与旧运行证据保留；未为文档或离线迁移自动触发两版完整编译。
