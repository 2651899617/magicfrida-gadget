# 补丁取舍与来源

仅以 `E:/frida魔改/fridaneed/最新的frida内容/anti-frida.py` 作为该脚本的采用参考；旧副本不重复登记。用户提供的实践脚本、三套 patch 和文章均按固定源码的适用性、冲突及创建/消费者联动判断，不因使用 LIEF、字符串替换或功能裁剪的形式而整体排除。这里区分“参考已验证”“本项目源码已迁移”“本项目编译/运行已验证”。

## 2026-11-07 raw Agent 库名与废弃动态字符串修复

- run 42345534583 的活动 SONAME 已改为 `libnianchu-agent-raw.so`，应用命中的 `frida-agent-raw.so` 是 `.dynstr` 尾部旧名；四个实际 Agent 各有一处。旧 schema 2 虽记录残留，却没有归零门槛，本节补齐这个缺口。
- 两版 `lib/agent/meson.build` 只把 raw `shared_library` 名从 `frida-agent-raw` 改成 `nianchu-agent-raw`，raw_agent/modulated_agent/final target 对象、header 和最终路径消费者不改。完整固定源码无按旧 raw 名查找的功能消费者。
- schema 3 清理最后一次 LIEF 写出后无引用的完整 `.dynstr` 旧名。活动 SONAME 必须为新名；覆盖动态字符串字段、符号后缀、GNU version 名/file 引用，遇仍被引用或未知消费者则拒绝，不作通用子串替换。零填充保持文件大小、字符串表长度及索引。
- 真实内嵌 Agent、外层收集产物和报告验证新增旧18字节子串归零门槛；arm64/arm32 Agent 同时核 SONAME 与实际入口。原始 maps 的手机签名验收随重新部署进行，编译与静态结构不替代运行测试。

## 2026-11-07 功能兼容的内部标识修复

本段取代下文旧 schema 1 的整文件随机字符串规则，基于成功 run 41980419791 的 `764950b…` 修复：

- 两版 `lib/agent/agent.vala` 私有 StopReason 使用 `NianchuAgentStopReason` 注册名；保留数值、常量名、nick 和全部数值消费者。CCode 由 pinned generator/spec 生成，原 fixture 字节不改。
- 改写器 schema 2 使用内部类型/诊断清单和完整 NUL 字符串匹配，固定等长前缀 `Nnchu`／`nnchu`，相同类型在不同 ELF/版本/架构中保持同名；`Friday` 及前后附加字符不误改。StopReason 不走通用类型映射。
- 保留 `GDBusProxy`、`GumScript`、`GLib-GIO`、ART resolver 键、`./lib/android`、枚举 value_name/nick、`FRIDA_V8_EXTRA_FLAGS` 和公开 Frida API/DBus 类型。移除全文件 `gadget` 通配规则，模块初始化导出稳定为 `nianchu_gadget_init`。诊断标签匹配限定 `.rodata`；符号表修改由 LIEF 和独立 hash 查找校验联动。
- 本地已取得两版固定完整 core 归档，仅用于只读消费者核对；原稀疏 fixture 不冒充完整源码。内部实际消费者使用 typeof、数值和显式 JSON/DBus 键；未把外部反射按旧私有类型名查询视为受支持客户端协议。
- collector 强制验证最终 server 内嵌 arm64/arm32 Agent 的实际入口、hash、新 StopReason 和旧选定类型残留。host Vala/GLib 契约测试覆盖0/1、value_name、nick、查询及属性读写；Android JS/Java、GC、异常和模块加载仍按独立运行证据报告。

## 2026-11-05 参考 patch 扩展（历史工作树）

用户要求按参考 patch 与最新版 anti-frida.py 实施，当前工作树已扩展默认 recipe；下文旧构建/实验记录按其注明的提交和 run 理解。

- 两版 guard 已扩展为 50／55 份。server 默认目录与 agent 资源前缀使用 UUID；helper/socket/memfd、core/Gadget 初始化品牌使用 nianchu。Linux 临时目录按参考返回 `/system/lib64`。
- `exit-monitor-off`、`signal-interposition-off`、`agent-entrypoint-rename`、`gadget-json-config` 成为默认 feature；signal 项现在包括 whole POSIX exception backend attach/detach 停用。`zygisk-loader` 仍仅供模块构建追加。
- RPC 三个消费者通过双层 Base64 获取原 `frida:rpc` 值，线上协议值保持；Droidy/ADB 的指定 OPEN/CLSE/WRTE 分支按参考执行 break。
- agent ELF 最终名称与 compat 查找同步；embed-agent/embed-helper 在资源编译前调用 ELF 改写器，覆盖非空兼容架构文件。两版 Gadget 文章修改继续保留。
- `patches/rename.py` 从只读审计扩展为 LIEF 0.17.6 改写器：符号中的 frida/FRIDA、四类 rodata 字符串、参考 PATH_STRINGS 全文件等长替换；作者 libwzdnb-agent 品牌改用 libnianchu-agent。rodata 使用显式 VA 模式；原始文件偏移仅用于报告。最终重建后独立检查 GNU/SysV hash 查找与 NEEDED。
- 全文件 `gadget` 替换会改变 Zygisk 初始化导出；最终入口由重写报告 `initialization_symbol` 记录，wrapper/collector/module 必须使用同一经校验入口。该字符串改写不是只改线程标签，也会触及 ART 解析键与 Java bridge 路径；运行行为需要单独验证。
- 16 bundled bridge 6.3.9 增加编译前 PrettyMethod hook 删除；17 外置 7.0.13 增加独立参考 patch/bundle 脚本。与既有 direct-art-gc profile 分开记录，不能混用报告。

以上为本轮未提交工作树的实现状态。完整离线回归 183 项通过、2 项因 Windows 符号链接权限跳过；ELF 专项 7/7、artifact 30/30、workflow 8/8、补丁组合 32/32、Gadget 9/9。16/17 的普通及 Zygisk Gadget 四种真实 ELF 均完成内存 rewrite/report 校验，原始产物未改。GNU hash 显式重建不重排 dynsym；只报告 PT_DYNAMIC 实际启用的 hash 表，嵌入 ELF 连同 header/program/section table 均受外层替换隔离保护。collector/module 使用报告驱动的初始化入口，CI checks/build 各使用固定 LIEF 0.17.6 独立 venv。旧 Actions run 41951726835 不包含这些新增修改；真实 Android 编译、真实 npm bridge 构建与 Java/GC/异常运行验证尚未执行。

## 先前源码 recipe 与构建记录

| 修改点 | 16.7.19 | 17.25.2 | 联动及证据范围 |
|---|---|---|---|
| server 临时资源目录 | `nianchu.server` | 同左 | 修改既有默认目录，不迁往 `/data/app`，不改 SELinux/权限策略 |
| agent 资源及 memfd 标签 | `nianchu-agent-<arch>.so`、arm/arm64 创建与查找同步 | 同左 | 原 `AgentResource` name 进入 memfd；不强制覆盖通用 memfd wrapper 的 name 参数 |
| helper 资源名 | 32/64 同步为 `nianchu-helper-*` | 同左 | name 同时用于 `MemoryHelperFile` 和文件 fallback，保留 FD/长度/生命周期 |
| helper process abstract socket | `/nianchu-` + UUID | 同左 | listener 与传给 helper 的地址来自同一变量 |
| 注入 fallback abstract socket | `/nianchu-` + UUID | 同左 | 保留 UUID、`fallback_address.data.length + 1`、远端字符串/字节写入及 send_fd |
| helper DEX | 当前对应点不适用 | `nianchu-helper-*.dex` | 同变量写入、chmod、启动及 finally unlink |
| Zymbiote socket | 此实现不存在 | host、memmem 模板与 C payload 同步为 `/nianchu-zymbiote-` | 保留 64 字节字段、abstract 前导 NUL 和 cursor 步长 |
| blob mapper 标签 | 此实现不存在 | `nianchu-agent.so` | 只改 blob mapper 名称，保留依赖 resolver 和 entrypoint resolve |
| Gadget/JS/core 主循环线程 | `nianchu-gadget`、`nianchu-js`、`nianchu-main` | 同左 | 只改现有 `g_thread_new` 的 name，保留 callback、上下文、join 与 teardown |
| Gum 嵌入 prgname | 原 `g_set_prgname("frida")` 改为 `nianchu` | 同左 | 只改已有赋值；不在 core 另加无条件宿主 prgname 调用 |
| Gadget 监听线程及 Fruity 消费者 | `nianchu-t<port>`／`nianchu-unix`；Fruity 同时接受官方旧 TCP 标签 | 同左 | TCP 标签最长 14 字节；保留端口解析、已有 Gadget 复用、连接与 wait/resume 语义，不把源码标签模型当真实线程观察 |
| Gadget 构建/生成头 | raw/modulated 名称和生成头统一 nianchu；glue/Darwin include 同步 | 同左 | ELF 最终输出 `nianchu-gadget.so`，compat 查找同步；保留 `frida-gadget` 最终 target 键及 Windows/Darwin 最终布局、构造/析构排序符号 |
| Gadget Droidy 暂存/portal 文案 | 共享 SO/config 前缀 `nianchu-gadget-`；portal 错误文案同步 | 同左 | UUID、App 内路径、SO/config 传输、清理及 `frida:` socket 保留；没有运行 Droidy 或向设备写文件 |

默认 compatible 的修改文件数为 16 版 **16** 份、17 版 **18** 份；完整 guard 分别为 **43／47** 份。原始 fixture 不写入改后源码，SHA-256 固定在 spec.json。

## 独立可选项

| feature | 来源及实现 | 验证及边界 |
|---|---|---|
| `agent-entrypoint-rename` | 从旧 patch/新版脚本的入口点迁移，统一为自有 `nianchu_agent_main`；Vala `[CCode(cname=...)]`、JNI/glue、各平台导出、注入调用、AgentContainer 和 labrat/test 同步 | 16／17 分别覆盖 24／26 份入口源码；默认保留旧入口；源码组合重放已验证，CCode 编译及最终 embedded agent lookup 未验证 |
| `zygisk-loader` | Android 不自动初始化，增加独立 `nianchu_gadget_init`，由模块显式传入配置 | 普通自动 Gadget 不启用；该入口不是 agent 入口；Actions run 41951726835 已实际编译 compatible 与 Zygisk 两个 profile，设备加载仍未验证 |
| `exit-monitor-off` | 构造函数中的 Windows/POSIX attach 成组移除，其余退出逻辑保留 | 未验证有序退出功能代价；默认/CI 不启用 |
| `signal-interposition-off` | 仅去 signal/sigaction replace 和对应 revert，保留异常 handler 安装与清理 | 不等于 whole exceptor backend 禁用；未验证异常功能代价；默认/CI 不启用 |
| `gadget-json-config` | 采用 Gadget 文章的 JSON 配置思路，但保留 `.config` 优先、增加 `.json` 再回退 `.config.so`；只改 Android Gadget load_config block | 显式 config_data 优先、脚本 `.config`、非 Android/framework 及错误处理保留；产物/zip 带 `-json-config-`，不宣称 server 新配置行为；真实文件查找未测 |

所有项沿用精确 SHA、命中次数、全组预检查、拒绝 partial/drift 和导出 diff 一致性。可从 base 或 compatible 添加整个 feature 集；不支持任意 feature 增删自动切换。跨文件 replace 不是回滚事务。

入口实验版产物/模块文件名带 `-entry-renamed-`。collector 报告 server 的 **embedded-agent 源码约定**，最终动态 lookup 明确为 `not-tested`；Gadget 的 agent 入口为 `not-applicable`。不能把 marker 计数、server 自身的 dynsym 或 Gadget 导出当作 embedded agent 的 lookup 证明。

入口补丁包含上游 Windows `.def` 的 CRLF hunk，Git 对该补丁禁用文本/换行转换。离线重放使用 `patch --binary -p1 --fuzz=0 --batch`，并拒绝 offset；不规范化原始 fixture 来规避 SHA 或 hunk 检查。

## 新版 anti-frida.py 剩余点

| 点 | 本轮结论 |
|---|---|
| 全 ELF symbol／rodata 随机等长替换 | 实践脚本可参考，但本轮不直接执行它改正式产物。适用点优先迁为源码 recipe；并非否定所有二进制方法。LIEF patch_address 的地址语义仍需专门核验 |
| `FridaScriptEngine`、`GumScript` | 固定源码分别存在 Vala ScriptEngine 与 `G_DEFINE_INTERFACE(GumScript,...)`；属于注册类型而非普通线程标签。尚未落实注册名/消费者/API 闭环，不能标完成 |
| `gmain`、`gdbus` | 固定 GLib 源码已登记独立 `thread-labels` recipe，两处线程创建分别改 `nianchu-worker`、`nianchu-dbus`，保留函数/context/生命周期；每版 7 份 guard。源码重放已测，静态 SDK/compat arm32 重编及 final link 未验证 |
| `GLib-GIO`、`GDBusProxy` | 日志域影响路由/过滤/测试；GType 注册名影响反射及下游按名查找，保留不混入线程标签 recipe。未完成独立日志/类型兼容方案 |
| `pool_spawner`／`pool_spoiler` | 固定两版完整 core/gum 文本搜索未命中；不能把脚本 token 当现存源码点 |
| 新版新增 `frida-inject` | 命中独立 inject 工具 target 和说明文本，不是 server/Gadget 运行线程。当前产品不收集该工具，不盲目改 target/构建名 |
| `./lib/android`、`art::JavaVMExt::AddGlobalRef`、`art::ClassLinker::VisitClassLoaders` | bridge 模块/ART 解析键，不是任意可换标签；直接改名会影响模块加载或符号解析。需功能替代，不使用随机字符串破坏 lookup |
| `libfrida-agent` | 本轮同步运行资源名；构建期原始 target、符号与嵌入变量保持各自联动，不全局替换所有前缀 |

## 三套 patch 与三篇文章

本地三套集合：`Patchs`（11 份）、`fridapatch`（独立 core/gum、合集及脚本）、`Patchs-master/strongR-frida/frida-core`（8 份）。按语义去重，独立 patch 与合集差异不忽略：PrettyMethod、exit 的 Windows 分支、signal 的 whole-backend 与局部 replace、入口导出和 memfd 行为均存在不同版本。

| 参考 | 提取及取舍 |
|---|---|
| `Frida15.2.2魔改.md` | 有效正文 13–413，后文为重复抓取；新增默认控制端口 27042→26666 作为部署选择记录，暂不改变默认官方客户端用法。root 临时目录改 `/data/app` 有软重启警告，不迁入默认版 |
| `frida16.5.7魔改-去除libart.so特征.md` | 有效正文 13–305；DoCall/GetOat/GC、原 ArtMethod 承载 impl、clone 原调用、JDWP、PrettyMethod 和 code-readable 点作为 16 实验 bridge 的迁移依据。展示 RegisterNative 监听不等于方法替换/原调用/GC/异常全部通过 |
| `[原创]从零编译魔改 Frida 16.5.2…DexProtector…md` | 有效正文 16–910；成功描述是 server + 样本脚本。匿名地址/RVA、LR、SHA 输入、maps 返回值、线程 RET 均为样本相关，不写入通用产品；正文 16.5.2 与部署命令 16.3.3 的矛盾保留 |
| `fridagadget16.5.7魔改.md` | 有效正文 13–290；291–568、569–846 为重复抓取。两版 Gadget 构建名/生成头/监听线程/compat/Droidy/portal 点均迁移为 nianchu recipe，并补文章遗漏的 Darwin include 与 Fruity 线程名消费者。新增 `.json` 独立项保留旧配置回退；原 Gum prgname 已覆盖，不重复新增无条件赋值 |

官方 `re.frida`／`re/frida`／`frida:rpc` 保留，异常命令不吞掉。没有将 ART hook 裁剪、`gum_ensure_code_readable` 早退或 root 目录搬迁混入兼容基线；功能性方案仍按独立实验处理，不把“删除后能编译”当作完整功能。

## Gadget 文章脚本及 Zygisk 取舍

- 文章 `anan.py` 的入口改名由现有独立 `agent-entrypoint-rename` 覆盖，并闭环真实定义/导出/消费者；不照抄 `main` 或作者品牌。LIEF/sed 全符号/rodata 批量替换只作实践参考，不直接执行；`patch_address` 的 file_offset 地址模式仍未验证。
- 四个注册名/日志域逆序点不冒充纯命名：`FridaScriptEngine/GumScript/GLib-GIO/GDBusProxy` 仍需完整功能兼容方案。文章中的 RegisterNatives 观察脚本不等于 Gadget 功能或 ART/GC 验证。
- 本模块已有 `nianchu_gadget_init(config,result)` 直接传 JSON；不复制文章往 `/data/data/<package>` 写配置、customize.sh 配置复制、script interaction/script.js 安装或旧模块成品。Droidy recipe 只保留并改名上游流程的共享暂存路径，不执行设备写入。
- `embed-agent.py` 调用细节仅见外部截图，截图未访问/未转录的代码不算已读或已采用；没有加入文章未包含的内核隐藏依赖。
- Gadget 清单见 `patches/gadget-files.json`，每版 8 份新增固定源码。collector 的 `gadget_config_lookup` 仅为经过 pinned recipe/hash 核对的源码约定，`runtime_lookup=not-tested`；module builder 核同名最终文件、完整约定和 feature 变体，不能据此宣称最终 SONAME、真实动态 lookup 或 Android 加载通过。

- 两版原有监听 `Environment.set_thread_name()` 在非 Darwin 的 glue 中为空实现，仅 i/macOS 实际调用 `pthread_setname_np`。TCP/Unix 标签已改源码并同步 Fruity，但不宣称 Android 因此产生新 OS 线程名；Android worker 的 `g_thread_new("nianchu-gadget",...)` 是另一既有路径。15 字节上限检查只是标签长度兼容模型，未新增 Android 命名实现。
- Gadget 专项 9 项、产物专项 29 项通过；完整回归 116 项、零 skip，每版 32 种 feature 集及正反顺序零 fuzz/零 offset 重放通过。配置路径为限制性源码翻译模型、模块 zip 单元测试使用临时 synthetic ELF/编译器替身，不是这些模型测试本身进行了 Vala/Android/真实 wrapper 构建。另有 Actions run 41951726835 对两版 compatible 与 zygisk-loader profile 的真实 Android arm64 构建证据；配置路径和设备运行仍未验证。首轮 Gadget 排序符号断言失败已按两版上游差异修正，补丁未改排序符号，修正后完整重跑通过。

## Java bridge 与依赖来源

- 16 bundled bridge 默认固定 **6.3.9**。官方 npm 包已从 `registry.npmjs.org` 取得，19 份文件；SHA-512/SHA-1 与官方 metadata 一致；此前阅读的 android.js 与该包逐字相同。默认构建 **未应用 ART 修改**。独立 `direct-art-gc` 源码 recipe 已落实 android.js 与 class-factory.js：原方法承载替换、clone 非虚原调用、GC map/查询角色、失败 wrapper 清理及 revert；6 项专项和 39 个源码模型检查通过。保留 GC/GetOat/PrettyMethod/JDWP；拒绝编译后入口/Xposed/非 ARM/API<23，尚未 QJS/V8 打包、未 runtime 验证。
- 16 另有独立 `gum-runtime` recipe，默认空值的 `nianchu_java_bridge_source` 选项指向完整准备后的实验包。Meson 跟踪 19 个文件，generate-runtime 在 frida-compile 前核精确 SHA 并准备两份修改文件，私有缓存带 `-direct-art-gc`。7 项专项覆盖默认缓存、QJS/V8 源码调用链、首次依赖安装和失败 partial 拒绝；编译器是测试替身，不称真实 QJS/V8 打包通过。需独立 builddir；当前 CI/collector 未接入该变体，最终二进制消费及 Android runtime 未验证。
- 17 bridge 外置。官方 **7.0.13** 包已取得并校验，20 份文件，ESM；独立 `direct-art-gc` 源码 recipe 已适配，保留 ESM 导出及未修改的 index.js，新增 Nterp 同步对原调用 clone 的 quick_code 操作。7 项专项和 39 个源码模型检查通过；两版专项合计 13 项。未进行外置打包、客户端安装或 Frida/Android 运行验证，不声称是所有官方 17 客户端必用版本。
- 两包声明 `LGPL-2.0 WITH WxWindows-exception-3.1`；此次未执行包脚本、未更改 npm registry 或用户客户端。
- xiaojia bridge 核验 HEAD：`f7141a697294a95760f34d58aebbe93b44459430`。README 底座 6.3.6；main 是 shadow 包装，并非文章 direct 方案。其自定义 prctl 内核依赖、异步批量 hook 和无条件 global.Java 赋值不纳入本轮。branch 中 direct/保留 GetOat 两方案只作研究依据，fork 新增代码许可仍需核对，不整包复制。
- 16 GLib 固定 `frida/glib@8f43c78bc4f6a510c610c7738fdf23ecf99c6be8`，SDK/bootstrap 为 `20250512/20250321`；17 固定 `frida-forks/glib@c366177b9292432a26f6903fa82a71d83e4927eb`，为 `20261030/20250801`。完整 deps.toml fixture 与 SHA 已登记至 `patches/dependencies.json`。
- 新增 `verify_dependency_sources.py`：只校验未修改的固定 releng/GLib checkout、每个 Git blob 字节和递归子模块，拒绝 HEAD 漂移、旧构建杂项及 `skip-worktree` 掩盖的源码变化。它不是构建器，也不接受导出归档冒充完整 checkout；当前未接入 CI。
- 新增独立 releng `sdk-lock` recipe，设置 `NIANCHU_SDK_LOCK` 后先验证绝对 SDK 路径、machine、版本、精确文件集及 SHA-256；失败抛错，不进入 SDK 目录删除/归档/网络兜底。未设置时保留原行为，toolchain 不受该变量约束。当前一次锁定只接受一个 machine/prefix，多 SDK 的配置链尚未集成；锁清单本身不是可信来源签名，也不证明这些库来自修改后的源码。
- 上游 checkout 不符只 WARNING、安装 manifest 可跳过构建、SDK 仅凭 VERSION.txt 接受；17 另有 `FRIDA_DEPS_REBUILD/FRIDA_DEPS_BASE` 的部分包复用。已建立 pristine 输入及可选 SDK 字节锁两层门槛，但未连接完整构建器/最终链接。实际 SDK 重编、隔离缓存、修改后 provenance 和 final link 消费门槛仍未完成，不能拿旧预编译 SDK 当作完成。

## 固定来源及执行边界

官方 super/core/gum/releng SHA 见 versions.json。新增 core/gum fixture 来自固定完整归档，并与既有全部 fixture 逐字交叉核对；归档根名与 anchor 不是密码学发行签名。入口清单路径及 SHA 另见 `patches/entrypoint-files.json`。

Zygisk API 5 header SHA-256：`f8d55e8b4f89d418c5941afe62ce6a09ddec1f4afd9a1b0a01eb40a93310dd28`，保留上游许可证。xiaojia config 样本只读，hash `5eb188865bfcc46b31fcb6e12699ecb8a76b61f3872cac3809c6f20cfb8bfc36`；字段/字符串存在不能证明私有摘链执行路径。

本轮源码已提交并推送至 `fix/build-integrity`（`be895fa4f4e074c92c942c5e73df84129ffc7dc5`），Actions run 41951726835 构建成功；本次构建未操作 ADB/手机/KPM，也未修改系统 Python/frida.exe。默认 solist/r_debug 摘链、resetprop、全局信号过滤和开机 APK 安装不纳入。当前 KPM 仅观察 foundation，不宣称通用隐藏完成或所有 App 免检测。
