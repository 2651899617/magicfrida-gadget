# 当前工程状态

记录日期：2026-11-07。

## 2026-11-07 E 轮完整可读段字符串改造（实施中）

基线提交 `a8c907f212ffa588223de8bb8598302e4612e394`、成功 run 42353264303 的四简名产品已完成手机替换与 native 验收。E 轮新增检测按全部 PF_R/PT_LOAD 的 `p_filesz` 枚举 ASCII、每片最多 256 字节，大小写不敏感匹配 `frida`，21 次匹配回调写共享原因码。四完整内嵌 Agent 基线为 336/336/288/292 次命中；原 ARM64 捕获回放为 2714 回调、21 命中，与前 2 MiB 校准一致。

本轮将运行时功能字符串和 gumjs 嵌入资源存为编码字节，使用时恢复原字节到 heap。Android 编译入口固定为两版 releng/env_android.py 的 Meson C/C++ compiler 数组前缀，兼容架构由同一环境重新生成；真实 target/common_flags/sysroot、wire/API、GType/name/nick 和资源长度保持。新报告 schema 4 拒绝旧 schema 3 复用，Agent/Gadget 全部可读 PT_LOAD 的匹配回调必须少于 21，server 内嵌两架构分别校验。源码转换报告与离线计数不是功能或目标 App 成功证明。

目前完整本地回归 262 项，259 通过、3 跳过（Windows 符号链接权限两项、本机缺 valac 一项）；后续包装器专项增加失败 JSON 保留及三个精确嵌入 ELF 资源源的 passthrough，分别复测。编码器 24 项包含实际 host C/C++ 执行，包装器还核验 NDK r25.2 的 arm64/armv7 对象编译；完整可读段专项 7/7、ELF 专项 20/20、生成与构建约束 10/10 通过。提交 `95232a6058bb3a32fe446df0b429206ed6bd20df` 的 run 42375666984 已完成 Linux 回归 **264 项，263 通过、1 跳过**（CI 没有本地历史 Gadget 归档）；两版独立 host Vala/GLib 枚举契约通过，实际 Agent 生成器仍为 valac 0.58.0-frida。该 run 两个完整 Android 构建均在首批 C 对象的编码器输入解析处失败，报告明确为 `input_does_not_parse`，已保存归档 digest、CRC 和精确失败 JSON；正在补齐真实 NDK/GLib 的 GNU 类型别名、枚举属性及 Clang 声明语法兼容，实际编译源码与功能值保持原语义。两版固定 SDK 的四份真实 Android 预处理输入均经 Clang 语法检查接受，已用于复现并验证解析修复；17 本地复现使用 r25，CI 构建仍固定 r29。新增真实 wrapper→outliner→host C/C++ 编译、链接和执行的原值恢复集成验证已通过，包装器专项最终复测 **22/22**，包含原依赖、forced header、只读源、真实 arm64/arm32 对象和失败报告保留。

C 解析修复后的冻结专项为 **34/34**，四份固定 SDK 的真实 Android C 输入均完成编码和实际对象编译，零 skip；core `patch.c` 每版转换 10 处 literal、5 个 heap buffer、3 个精确静态 pointer slot。后续 C++ 新增真实 `#line` 来源策略，只为完整 libc++、V8、Highway 头建立 opaque AST 视图，自有 Gum/core、GLib 和 NDK C 头继续解析，原头字节与编译语义保留。16 的真实完整 ApiResolver 输入使用 r25/C++17，17 的完整本地对照使用 r26/C++20，均已通过实际 installer→wrapper→编码器→NDK ARM64 对象编译、原依赖闭环和 1,701 份输入的 SHA/mode 保持检查；对象分别为 142,120／265,728 字节。收紧完整声明与作用域边界、外部同名类型／重载／静态消费者的未知判定后，两版真实对象再次通过；新增来源边界专项 **20/20**、零 skip，覆盖精确头字节、八进制路径、整资源跳过、跨声明和错槽拒绝、heap 恢复及生成 helper 污染拒绝。17 的 CI 仍固定 r29；这些对象不是完整产品构建。当前 wrapper `1.1` 的 26 项命令/依赖/来源门槛全部通过、零 skip；真实 C/C++ heap 原值恢复集成也通过。最终编码器 SHA-256 为 `d5641613dee8468a717c08cf038f19e1234b60a48c251e07741d0c9b9127bea1`；同一源码身份的完整回归 **307 项，304 通过、0 失败、0 错误、3 跳过**，用时 294.375 秒。跳过项为 Windows 符号链接权限两项、本机缺 valac 一项；实际 host C/C++ 执行和 r25 arm64/armv7 C/C++ 对象编译均通过。测试期间十份改动文件的大小与 SHA-256 保持，报告为 `work/nianchu-outline-regression-final-20261107-h/verification.json`、日志为同目录 `tests.log`。最后一次来源边界与旧 lexer 合并专项 **21/21**、零 skip；新完整 Android 构建和产品预算验收随后按对应提交身份执行。

设备验收工具已冻结，完整内存 E 模型、maps/ELF 边界及进程清理离线检查通过 1,049 个断言组；该数不是仓库测试项数，也不是设备运行证据。父部署器 10/10 恢复测试通过、零 skip，包含 spawn 晚返回持久化、pending unknown、PID 复用、阻塞 RPC 的独立恢复和退出确认。通过报告必须明确 `cleanup_confirmed=true`、`cleanupstatus=observed_exited`、`pending_spawns={}`，并确认 qjs/v8 两个 disposable sleep 均退出；失败后清理未确认会保留恢复目录，不以文件已还原冒充完整恢复。

KPM `1.1.0` 的全局版本曾完成编译、三组 Unicorn 和独立哈希核验，尚未推送；用户最新要求改为读取者或调用者 `UID > 10000`，`1.1.1` 已完成固定 GCC 编译、三组实际 Unicorn 测试、产物冻结和独立机械核验，并原子替换手机 `/data/local/tmp/nianchu-ptrace.kpm`。正式文件为 19,896 字节、`0644`、`root:root`，设备端 SHA-256 `a045419d933e41ef6227430badcba53fbd88650b85a1baa21ae9cd38543f912a`；旧文件备份逐项核验并保留本地，stage 已清理，交付报告 `work/nianchu-maps-uid-delivery-20261107-a/deployment.json`、`verification.json` 和 `journal.jsonl` 均记录完成。源码 ZIP 为 39,070 字节，SHA-256 `7df6794677ee6a4e53ccbd3aa31733de0e6f38fd5f09320acf07bb3f95fd4ee5`。四个回调均有实际 `BL current_uid`，15 个 imports 均为 SDK 实际导出；gateway 仍为 112 字节、control offset 96、无重定位。测试覆盖五个 UID 边界、reader/caller 与目标身份错配、before/after 身份变化、缺 UID metadata、能力失效回滚及原四个 worker 的 stale callback 生命周期，项目 Python `-I` 只读复用已有模拟器包，未安装依赖。两参考源码已核对：pandahide 全局，xiaojiahide 读取者 `UID > 10000`；nianchu 按最新要求采用后者的范围门槛，仍精确保留记录并改写目标路径。手机只读观察到五个候选符号名称，地址为零；模块未加载，尚无手机内核 ABI 或实际 hook 运行证据。当前新 Frida 完整构建与手机替换尚未完成；system_server 根因调查保持暂停。

## 2026-11-07 raw Agent 名称与动态字符串残留修复

修复基线提交 `90e85c12157314dafbfdaffaf565e0bd61a0e592`，run 42345534583 已成功构建并推送四份简名产物；CI 201 项回归、真实 Vala/GLib 契约及手机两版直接 sleep native Agent/RPC/Interceptor/Memory/resume/unload-detach 通过。该版本的活动 SONAME 已为 `libnianchu-agent-raw.so`，但 LIEF 重建后 `.dynstr` 尾部保留 `libfrida-agent-raw.so`。16 arm64 旧完整串偏移 `0x3C4F`，应用子串命中 `0x3C52`；16 arm32 为 `0x2C61`，17 arm64/arm32 为 `0x38E7`/`0x3009`。旧报告记录残留但未要求归零，因此这些通过记录不证明旧 raw 签名已消除。

本次从两版 Meson 源码直接生成 `libnianchu-agent-raw.so`，保留 raw/modulated/final target 对象和现有消费者。schema 3 在最后一次 ELF builder 写出后检查废弃完整 `.dynstr` 名称：活动 SONAME 必须为新名，动态字段、符号（含后缀引用）和 GNU version 名/file 引用全部避开才可零填充；保持文件大小、表长度、索引及 hash lookup。外层 server 不修改内嵌 ELF。collector 和报告验证强制旧 `frida-agent-raw.so` 子串归零，真实两种架构的 Agent SONAME 必须为新名，旧 schema 2 拒绝复用。

最终ELF专项20/20通过，覆盖未引用字符串清理、live SONAME/NEEDED/后缀引用拒绝、普通及SHT_NULL保留的GNU version文件/aux名称引用、异常链与记录重叠拒绝、嵌入保护、报告和增量重写。两版源码专项34项、产物/模块专项31项通过；最终完整本地回归210项，207通过、3跳过（Windows无法创建符号链接两项，本机缺valac一项）。四份上一构建的真实Agent在内存副本清理后，旧raw签名均为零，程序/节/符号布局、活动字符串引用和hash lookup不变；原产品文件未写回。CI重建和新手机部署正在执行；完成身份及hash记录在独立交付报告。Android Java/ART/目标App/Zygisk安装加载的验收仍独立进行；system_server根因调查保持暂停。

## 2026-11-07 内部标识与功能契约修复

基线 HEAD `764950b6865cbaf94e81177a753250a04d5bd670`，成功构建 run 41980419791。用户实测的 `FridaAgentStopReason` 偏移 `0x185B72` 精确对应 16 版内嵌 arm64 Agent 的只读段；原规则漏掉首字母大写 `Frida`。两版私有枚举在固定源码 recipe 加入 CCode 注册名 `NianchuAgentStopReason`，保留 Vala 枚举名、0/1、常量前缀和 nick。内部实现类型及诊断字符串使用固定清单和完整 NUL 字符串匹配，等长映射 `Frida→Nnchu`／`frida→nnchu`，不改公开 Frida API/DBus 类型。公共 GLib/Gum 类型、日志域、ART 查询、JS import、枚举 value_name 和环境变量从原随机规则移除，重新编译恢复原值。通用 `gadget` 子串规则移除，模块入口稳定为 `nianchu_gadget_init`。

改写报告升级 schema 2，旧报告拒绝复用。收集器检查两版 server 实际嵌入的 arm64/arm32 Agent：ELF 初始化导出、GNU/SysV hash、源码新类型存在、旧 StopReason 和清单内完整旧类型为零。CI checks 实际用 Vala 生成 C 并运行 host GLib 枚举/属性契约；host 测试不是 Android ART、JS/Java、GC/异常或 App 业务证据。本轮本地整套回归190项（2项Windows符号链接权限跳过，其余通过），最终62个内部类型与13个诊断标识的ELF专项12/12通过；Vala验证器专项11项（10通过，1因本机无valac跳过）。生成补丁一致性8/8、产物/模块31/31通过，`git diff --check`通过。CI真实Vala、双版Android构建、下载和四简名手机推送正在执行，完成后记录本轮身份及hash。

以下 2026-11-05 内容为历史阶段记录，不表示当前工作树或当前产物状态。

**当前未提交工作树正在实施参考 full patch，区别于下文已推送提交。** 两版 pinned guard 扩展为 50／55 份；默认启用退出监控停用、POSIX signal backend 停用、agent 入口改名及 Gadget JSON 配置，并补充 UUID 目录/agent、RPC 编码、memfd 标签、Droidy/ADB 分支、Java bridge PrettyMethod 补丁和嵌入前 ELF 改写钩子。collector 只改写发布副本，module builder 读取经校验报告中的初始化入口。当前完整离线回归 **183 项通过、2 项跳过**；跳过项是 Windows 无符号链接创建权限。另有 ELF 专项 7/7、artifact 30/30、workflow 8/8、补丁组合32/32、Gadget 9/9、Java bridge 13/13。四种两版 Gadget/zygisk ELF 均完成内存改写与报告验证；检查 GNU/SysV hash、初始化导出和嵌入 ELF 完整性。`git diff --check` 通过。尚无本工作树的 Android 编译、真实 npm bridge 构建或设备运行证据；旧 Actions 成功不代表此工作树已构建。

以下表格及产物 hash 是已提交版本的历史验证记录；与上段有差异时按各自提交范围理解。

**当前提交 `be895fa4f4e074c92c942c5e73df84129ffc7dc5` 已推送至 `fix/build-integrity`。Actions run [41951726835](https://github.com/2651899617/magicfrida-gadget/actions/runs/41951726835) 的 checks 和 16.7.19／17.25.2 两个完整构建任务均 success，覆盖本次 Gadget 源码的 compatible／Zygisk profile。两版产品 artifact 已独立下载，完整 zip SHA-256、CRC、路径及源码/补丁/ELF/module 内容核验均通过，详见下文本轮产物表和只读报告。设备和 App 运行仍未测试。run 41822602267 与下文标明的旧产品 hash 仅属于旧提交 `99150590…`，不包含本次 Gadget 修改。**

| 层级 | 已取得证据 | 未取得证据 |
|---|---|---|
| 版本 | 官方 tags、固定 super/core/gum/releng SHA；16.7.19 / NDK r25c、17.25.2 / NDK r29 | 不自动跟随未来版本 |
| 补丁 | 两版 43／47 份 core/gum pinned 文件 guard；默认 16／18 份命名修改；Gadget 构建/头文件/Fruity 消费者闭环与可选 JSON 配置；可选 agent 入口联动 24／26 份文件；独立 bridge、GLib 线程、SDK-lock 和16 runtime接入 recipe | 可选 CCode/agent 最终 lookup；JSON sidecar 的 Android runtime lookup；ART/GC/异常功能、GLib 静态 SDK 重编及独立 SDK-lock profile 最终链接消费 |
| 本地回归 | 最新 116 项全部通过、零 skip；每版 32 种 feature 集及正反顺序零 fuzz/零 offset 重放；Gadget 源码专项 9 项、产物专项 29 项；两版 ART 源码模型各 39 检查、真实 C++ 配置/SHA-256 30 检查通过 | runtime/模块打包的模型单测使用测试替身，Gadget 文件查找为限制性源码模型，不是 Android runtime；可选 feature 组合不等同于本次已编译组合 |
| GitHub 编译 | run 41951726835／提交 `be895fa4…` 的 checks 与 16/17 构建均 success；本次 116 项 Linux CI 回归成功；两版 server、自动初始化 Gadget、Zygisk 专用 Gadget、wrapper 与模块 zip 已构建并上传 | 编译成功不是官方客户端连接或 App 可用性证据 |
| 来源复核 | run 41951726835 两版实际 CI source 与 compatible/Zygisk post-build patch 报告均通过当前本地完整性校验；完整构建日志归档已下载并通过归档 hash/CRC/路径检查 | 来源 JSON 不是防恶意伪造签名 |
| 本地产品核验 | run 41951726835 两版产品 zip 大小/SHA-256、CRC、路径、final target/filename/config contract、ELF hash/导出、模块 payload/wrapper 入口与依赖/源码 hash/许可证均通过只读 verifier | runtime 未测试；不由静态核验推出设备加载或 App 可用 |
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
- Gadget 配置测试为限制性源码翻译模型；两版监听 set_thread_name 的非 Darwin 实现为空，只有 i/macOS 实际设置监听线程名，Android worker 的 g_thread_new 标签是另一既有路径。真实 CI 已编译两版 generated header、普通及 Zygisk Gadget、wrapper 与模块；本轮只读 verifier 检查实际 ELF hash、导出及 wrapper 依赖，但没有运行 Gadget、验证 Android sidecar 查找或设备模块加载。模块 zip 单元测试中的 compiler/readelf 替身和 synthetic ELF 仅描述模型测试，不是本轮 CI 产品。`git diff --check` 通过，既有 Git 换行 warning 保留，未做全仓换行规范化。
- 官方 Java bridge 6.3.9／7.0.13 源码包已从 registry.npmjs.org 下载并核 SHA-512/SHA-1；原 6.3.9 android.js 缓存与完整包逐字相同。两版独立 `direct-art-gc` 源码 recipe 已完成，联动原方法替换、clone 非虚原调用、GC/GetOat 角色及失败/revert 清理；7.0.13 另适配 ESM 与 Nterp clone 同步。桥接专项 **13 项通过**，两版各 **39 个源码模型检查通过**，零 fuzz/零 offset 重放和语法检查通过。下载未执行包代码；未改变用户 registry 或客户端。默认构建仍未启用实验 bridge，16 QJS/V8 和17外置打包、Frida/Android runtime 均未验证。
- 当前两文件联动的独立准备包：[6.3.9](E:/frida魔改/work/nianchu-bridge-direct-gc-639-current-20261105/package)、[7.0.13](E:/frida魔改/work/nianchu-bridge-direct-gc-7013-current-20261105/package)，各自有 bridge-report.json；这是源码包，不是编译产物。旧 `nianchu-bridge-direct-gc-20261105` 初稿不含后续 class-factory 联动，不作当前输入。
- 两版完整 releng/deps.toml fixture 与 SDK/bootstrap/GLib pins 已登记至 `patches/dependencies.json`。新增 `verify_dependency_sources.py` 的输入门槛：完整固定 checkout、HEAD 与 blob 字节、递归子模块；拒绝忽略的旧构建文件和 `skip-worktree` 掩盖漂移。专项 9 项通过；尚未接入 CI，不接受导出归档，不认证修改后的 SDK 或最终链接消费。
- 两版 GLib 固定归档已下载到隔离目录，仅作位置研究；根目录许可证为 `LICENSES/` 而非 COPYING，首次 anchor 检查因此失败，修正后下载成功。归档导出不含完整 Git 子模块且省略两个 symlink，未执行其中代码，不当作可构建 checkout。
- 16 独立 `gum-runtime` 源码接入已完成：默认空值选项、19 个实验包文件依赖、编译前严格准备、`-direct-art-gc` 缓存隔离、QJS/V8 生成 hash 报告。7 项专项通过，编译器为模型替身；无真实 runtime bundle/最终二进制/运行证据。CI 与 collector 未接入此变体，默认 bridge 不变。
- GLib 独立 `thread-labels` recipe 每版 7 份 guard，只改两处诊断线程标签为 `nianchu-worker/nianchu-dbus`，生命周期保留；日志域/GType 保留。releng 独立 `sdk-lock` 在启用后核 SDK 的 machine/prefix、版本、文件集/hash，失败不走目录删除或 SDK 下载兜底；仅单 SDK 字节锁，不证明构建来源或最终链接。两类 recipe 的 8 项专项通过，未真实重编 SDK。
- `GLib-GIO/GDBusProxy` 的日志/类型兼容方案及 `FridaScriptEngine/GumScript` 注册类型仍未完成。`pool_spawner/pool_spoiler` 固定 core/gum 未命中；`frida-inject` 命中独立工具 target/说明，非当前运行线程。
- 本轮实际 `make` 的是 Android Frida server/Gadget builddir 与模块 wrapper；不是 GLib/releng SDK 独立重编或 SDK-lock 实验构建。最终 agent 动态符号 lookup、官方客户端连接、JS/Java/GC/异常/业务均未经本次验证。
- 本次提交 `be895fa4f4e074c92c942c5e73df84129ffc7dc5` 已推送至 `fix/build-integrity`，Actions run 41951726835 通过 checks 并完成两版 Android 构建；两份产品归档已完成独立校验，产品 hash 和报告见“本轮构建产物”。实机证据属于此前已结束的窄授权测试，不自动恢复，本次编译未操作手机/ADB/KPM。

## 本轮构建产物（run 41951726835）

构建提交 `be895fa4f4e074c92c942c5e73df84129ffc7dc5`，分支 `fix/build-integrity`。GitHub Actions checks（116 项，零 skip）及 16/17 两个完整构建 job 均 success；两版 build logs artifact 与产品 artifact 均已下载。产品归档 SHA-256 与 GitHub artifact digest 一致，ZIP CRC、成员路径和独立只读 verifier 全部通过。

| 版本 | Artifact ID | ZIP 字节数 | ZIP SHA-256 |
|---|---:|---:|---|
| 16.7.19 | [13381138493](https://github.com/2651899617/magicfrida-gadget/actions/runs/41951726835/artifacts/13381138493) | 79,945,817 | `5cf6f18ad11ab68e0ae66718038085b3872097096732c4a23a5bd6aba4316d4c` |
| 17.25.2 | [13381975309](https://github.com/2651899617/magicfrida-gadget/actions/runs/41951726835/artifacts/13381975309) | 118,985,668 | `cdcc6b8c898fff52c90fb4251e4c549c7aac2bfe3de5802919360fbaa17a0918` |

| 版本 | 产物 | 字节数 | SHA-256 |
|---|---|---:|---|
| 16.7.19 | [server](E:/frida魔改/work/nianchu-build-41951726835-16.7.19/files/out/compatible/nianchu-server-16.7.19-android-arm64) | 53,698,272 | `618d342a8d385bf17671a3072fcc094f2654a07e1162b739490072fd5283db24` |
| 16.7.19 | [自动初始化 Gadget](E:/frida魔改/work/nianchu-build-41951726835-16.7.19/files/out/compatible/nianchu-gadget-16.7.19-android-arm64.so) | 25,818,472 | `ea91862b0716b42196b96a06427bfda2e99ce38ac532e0b34d6ad723f2b0e228` |
| 16.7.19 | [Zygisk 专用 Gadget](E:/frida魔改/work/nianchu-build-41951726835-16.7.19/files/out/zygisk/nianchu-gadget-zygisk-16.7.19-android-arm64.so) | 25,818,472 | `0907a6555bb554f59f1ea73576c454896b3fa7a829537a8312288e255b4c6c91` |
| 16.7.19 | [Zygisk 模块 zip](E:/frida魔改/work/nianchu-build-41951726835-16.7.19/files/out/module/nianchu-zygisk-16.7.19-android-arm64.zip) | 10,161,298 | `79442cded48e331acc0629507903f00382dd54f056da04416088b8803ec53af9` |
| 17.25.2 | [server](E:/frida魔改/work/nianchu-build-41951726835-17.25.2/files/out/compatible/nianchu-server-17.25.2-android-arm64) | 84,852,608 | `87a6fe3ff1997d47129a4f3a4f043732a33d0c0ef6681c75c17a8c91fd9344e3` |
| 17.25.2 | [自动初始化 Gadget](E:/frida魔改/work/nianchu-build-41951726835-17.25.2/files/out/compatible/nianchu-gadget-17.25.2-android-arm64.so) | 39,409,456 | `e00c1ae28c545fd1b070810bb9d61dcd668524718a3182c5a3e35031fa6d5d56` |
| 17.25.2 | [Zygisk 专用 Gadget](E:/frida魔改/work/nianchu-build-41951726835-17.25.2/files/out/zygisk/nianchu-gadget-zygisk-17.25.2-android-arm64.so) | 39,409,456 | `6379c9d64f58b8f1870002fd533bfca605aa7200fa1976d58d6dd67ede0216e0` |
| 17.25.2 | [Zygisk 模块 zip](E:/frida魔改/work/nianchu-build-41951726835-17.25.2/files/out/module/nianchu-zygisk-17.25.2-android-arm64.zip) | 14,738,657 | `55cabb96d08dc077d08235cd9b943cd22a2166eb30181817569e6b6116f98014` |

共同核验结果：Meson 的最终 target 是 installed custom target `frida-gadget`，最终文件名 `nianchu-gadget.so`；普通与 Zygisk 专用 Gadget hash 不同，每版两 profile 的 server hash 相同。Zygisk Gadget 实际导出 `nianchu_gadget_init`，wrapper 实际导出 `zygisk_module_entry`；wrapper NEEDED 为 `liblog.so`、`libdl.so`、`libm.so`、`libc.so`，无 `libc++_shared`。模块 zip 各有 12 个预期文件，内载 Gadget hash 与专用最终产物一致，targets.conf 全部注释，源码清单和 NOTICE 与提交源码一致。

本地验证报告：[16.7.19](E:/frida魔改/work/nianchu-download-tools-20261104/verification-16-41951726835.json)、[17.25.2](E:/frida魔改/work/nianchu-download-tools-20261104/verification-17-41951726835.json)。下载和日志保存在 `E:/frida魔改/work/nianchu-build-41951726835-{16.7.19,17.25.2}` 与对应 `nianchu-logs-41951726835-*` 目录。

这些是编译、来源与静态 ELF/包结构证据；本轮没有手机部署、客户端握手、Gadget sidecar 实际查找、Zygisk/SELinux 加载或 App/ART 功能运行测试。可选 `agent-entrypoint-rename`、`gadget-json-config`、ART bridge、独立 GLib SDK 与 SDK-lock feature 未包含在本次两个 build profile。


## 已验证的旧基线构建（run 41822602267）

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
- 以上两项实机证据来自此前已结束的窄授权测试；本次 CI 构建未部署产物或操作设备。17 和 Gadget/Zygisk 未进行设备注入。
- 已部署两版 server 到独立临时目录，并执行 16 的上述两次测试；未加载 KPM、主动重启、清数据/重装 App、修改 /data/system 或 /data/app，也未修改系统 Python/frida.exe。测试服务已停；进一步设备实验需要明确测试范围。
- 源码与本轮文档变更已包含在提交 `be895fa4f4e074c92c942c5e73df84129ffc7dc5` 并推送至 `fix/build-integrity`；Actions run 41951726835 已完成两版构建。旧运行证据继续保留，未借本次 CI 恢复任何设备操作授权。
