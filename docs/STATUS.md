# 当前工程状态

记录日期：2026-11-08。

## 2026-11-08 新 server16 启动 SIGSEGV：GLib 初始化前字符串恢复

交付 run `42455834261` 的 16.7.19 成功产品后，用户启动的新 `/data/local/tmp/server16` 两次在主线程退出。设备文件为 54,129,336 字节、SHA-256 `ebd750a90c64faeb1452c0ef618e9fdaf4671cfa83115f4b21582bac515eaf93`；23:04:50 的 PID 19085 与 22:58:53 的 PID 18582 都是 UID0、SIGSEGV/SEGV_MAPERR、fault address 0x8。tombstone #00 相对 PC `0x30ed5c4` 对应 ELF VA `0x30ee5c4`（RX 段 VA 比文件 offset 高 0x1000），指令 `08 a4 40 a9` 为 `ldp x8,x9,[x0,#8]`，x0=0。对应 `g_ptr_set_add`；调用链为生成恢复 constructor → `g_once_init_enter` → slice 分配/线程私有状态 → `g_private_get_impl` → `g_thread_state_add(g_thread_privates,key)` → `g_ptr_set_add(NULL,key)`。固定 Frida GLib 的 `g_thread_privates` 由 `glib_init`/`_g_thread_init` 才创建；priority101 恢复 constructor 提前调用 GLib。故障证据在 `work/nianchu-server16-tombstones-20261108-a/` 和 `work/nianchu-server16-disasm-20261108-b/`。

源码修复为 Android 两架构生成独立启动 runtime：每 TU 一个匿名 RW arena，直接 mmap/mmap2，内部32位原子 once；ARM64比较交换用内联LDAXR/STXR，避免外部outline-atomic helper。wrapper根据实际最后一个target或Android clang驱动triple选择策略；host诊断保持GLib模型。原字符串/资源字节与静态表字段保持，映射驻留到进程结束。四组NDK25 ARM64/ARM32 C/C++完整独立链接和Unicorn执行退出码0，每组一个arena，报告 `work/nianchu-server16-bootstrap-tests-20261108-e/`；完整真实gummemory.c的新ARM64对象编译通过，报告 `work/nianchu-server16-authentic-tu-20261108-a/report.json`。这是源码与模拟执行验证，尚未重建/推送完整server产品。此次ADB仅采证，没有signal或切换生产进程，也没有加载/控制KPM；采集时旧PID29778已退出，当前没有server16监听。默认Windows客户端16.7.19，与server版本相同；jailed Gadget错误来自远程server请求失败后返回NULL的客户端回退路径。

最后新增的 Android 独立链接、启动恢复与 target 选择专项 **3/3 通过、零 skip**；NDK25 ARM64/ARM32 C/C++ 四组 `-nostdlib -static` 链接没有 GLib/libc 或外部 atomic helper 依赖，受检 scripts/tests 源码身份前后一致，报告 `work/nianchu-server16-bootstrap-final-20261108-g/report.json`。首轮完整回归为365项、360通过、1错误、4skip，唯一错误是模块zip模型的Windows临时文件 `os.replace` WinError5，单项重跑通过；定向145项测试本体OK（144通过、1skip），退出异常来自报告脚本将TestCase直接JSON序列化，已修为id/reason。第二轮完整回归使用工作区下含中文及`frida`的TEMP，366项出现3failure/3error/4skip：bridge夹具要求ASCII路径、host GCC依赖文件路径不是UTF-8，raw-string夹具路径中的`frida`使编码计数多1。未改源码或断言，改用独立ASCII TEMP `C:/Users/2651899617/AppData/Local/Temp/nso-regression-20261109-c`；最终完整日志与源码身份报告在 `work/nianchu-server16-regression-final-20261109-c/`，旧两轮日志保留。诊断说明为 `work/nianchu-server16-startup-fix-diagnosis-20261109.md`。

最终完整回归 **366项，362通过、0失败、0错误、4环境跳过**，用时267.806秒，命令exit0，全部受检scripts/tests源码SHA/size前后一致；报告 `work/nianchu-server16-regression-final-20261109-c/report.json`。跳过为Windows符号链接权限两项、host GCC不支持GNU99定基enum一项、缺valac一项。ASCII临时目录下此前所有路径相关错误均通过；旧两轮日志保留。最终工作树补丁与manifest保存到 `work/nianchu-server16-startup-fix-release-20261109-a/`，其中包括此前未提交的enum/origin修复；完整Linux重建入口 `work/rebuild-server16-startup-fix.sh` 已通过shell语法检查，未执行整产品构建。

## 2026-11-08 C 定基匿名枚举与 compiler line origins（本地验证通过，产品待后继 CI）

提交 `3cbf8934970ab0a0e273025c0780751b3fd9d506` 的 run [42455834261](https://github.com/2651899617/magicfrida-gadget/actions/runs/42455834261) 已通过 checks；17.25.2/r29 在完整 `lib/payload/libc-shim.c` 的 GNU99 输入解析阶段失败，真实 receipt 的原 source SHA-256 为 `0fd93c7ae1c3363293afe6b2d5348b7dab5069c934e6024f7eb213db152a00e1`，错误上下文是 Bionic 合法 `enum : size_t`。截至 2026-11-08 10:38 UTC，16.7.19/r25 仍在 server／自动初始化 Gadget 编译步骤；没有本轮新 server16 完成或四文件替换结论。

C 定基匿名 enum 由完整原 token 的命名 C++ probe 和删除 `:base` 的等长 C probe 交叉验证，最终 region 绑定核对完整 body 的原视图、绝对偏移和所有子节点签名；compiler 原底层类型、值、无名身份与 CRLF 保持。类型、typedef／alias／slot 使用 `c_fixed_underlying_anonymous_enum` 保持 unknown。安全审查复现了 significant lexer 跳过枚举 gap 中 `#error` 和 `#pragma pack` 的缺陷；完整 enum span 现在只接受词法确认的 exact line markers，其他指令明确拒绝，配对 packing-gap resource／slot repro 在改写前失败。聚合与编译期资源限制保持保守。

C/C++ wrapper 均用 `-E` 保留 compiler line origins；仅解析视图等长空白化经过词法识别的 numeric GNU／`#line` 标记，compiler 保留原 marker。C 不新增 header opacity。NDK API19 完整 C 原源码编译成功、旧 `-E -P` 输入却因系统头 `strtof` 诊断失去抑制而失败，这次保留 flag 3 恢复原系统头分类，直接 `-P` 仅从预处理阶段移除，wrapped `-P` 拒绝。生成 helper 前后以 numeric 非 system marker 重置，真实 source markers 保持。新增真实 host 回归证明系统头原诊断行为保留，同时用户源码中的隐式函数声明仍失败；真实 C/C++ heap 恢复、依赖文件及 arm64／arm32 wrapper 对象均通过。

最终编码器 SHA-256 为 `994f00bcb224fbd1d88b9edd3bc6873553ef429a7b4bc3d2333cf03af38e8620`，wrapper 为 `0f61ee28e882b1d3ee27932c424b84a4fc07494812d02ff8bad4b493bf039e06`。固定 parser／LIEF 下完整本地回归 **363 项，359 通过、0 失败、0 错误、4 环境跳过**，用时 238.502 秒，受检十文件 size／SHA 前后一致；报告 `work/nianchu-c-enum-origin-regression-20261108-b/verification.json`。跳过为 Windows 符号链接权限两项、host GCC 不支持 GNU99 定基 enum 一项及缺 valac 一项；未将跳过计为通过。首轮 a 的两个失败是旧测试仍要求无 roots marker 不进入 shadow、helper 使用 standard `#line`；仅更新断言为 audited 等长 marker 和 numeric non-system origin 后，最终 b 通过，编码器及 wrapper 没有再改动。独立定向审查的 26 检查已确认前述 P1 缺陷修复，未见范围内剩余阻断。

固定 core commit `317363ce8064e3ede421ded3e53e1d3ffcfd782d` 的完整 `libc-shim.c` 与官方固定归档 member 和 CI source SHA 相同；本地 NDK26 的 arm64/API21、arm32/API19 均完成原源码对象、保留行来源的完整预处理及对象、完整编码器输出对象，以及 CI 错误中完整 `enum : size_t` 的原／编码后语义 probe。两架构共 14 条 clang 命令全部 rc0，10 个对象均为正确 ET_REL，完整 TU 各编码 5 处 literal／3 个 heap buffer，枚举 probe 各编码 1 处 literal；依赖闭包 283／280 文件 size／SHA／mode 前后一致。报告 `work/nianchu-authentic-libc-shim-outlined-20261108-e/validation.json`，不声称该 r26 预处理与 CI r29 字节相同，也不代替产品／设备运行验收。

独立 KPM `nianchu-ptrace 1.1.4` 已修复 shared `fargs.local` 覆盖，私有 128×72 字节 snapshot 表、单次 try-CAS 和竞争保守失效；三个正式 ARM64 fixture 全通过，module 536 场景／3121 断言／0 失败，12 份源文件前后不变。正式文件已交付 `/data/local/tmp/nianchu-ptrace.kpm`，25,272 字节、0644、root:root，SHA-256 `03e068f224984c8f05e1811cedf60aea180c8a24be3ce177c97d176c2c58e26d`，source ZIP 为 `cefd7f1df8520673a4a59892eafa42e12d799b9c791b89e618e385c9755b8240`；release 与 deployment 分别在 `nianchu-ptrace-kpm/release-private-snapshot-20261108-a/`、`work/nianchu-kpm-private-snapshot-deployment-20261108-a/deployment.json`。未加载／卸载／控制模块、未做本轮 App spawn、未重启设备或生产 server。App 内 Agent 同 UID 文本 maps 漏项已由源码确认，但 Android soinfo、17 mapper／ioctl 及产品断言禁用分支阻止从静态结论直接推出 App SIGKILL；该故障仍待原版本／操作／PID 时间线的真机验收。

## 2026-11-08 libbpf `size_t :0` 位域解析修复（本地验证通过，固定产品构建待验收）

提交 `068b382cc4c08419bca300f3663ddb2295caed11` 的 run [42448381735](https://github.com/2651899617/magicfrida-gadget/actions/runs/42448381735) 中，17.25.2/r29 的唯一失败仍在 Vala 生成的 `lib/base/linux.c` 输入解析阶段；19 个 parse_error 全部对应 libbpf 的 `size_t :0;`。固定 tree-sitter-c 0.24.2 将 `size_t` 分类为 `primitive_type`，原整数类型白名单未接受它。本次只对完整原类型字节为 `size_t` 的该节点补齐识别，继续使用原字段 named/projected parser-only probes、宽度完整 AST/span 和原始编译字节验证；未扩大其它 primitive 类型的接受范围。

最终编码器 SHA-256 为 `6c76941d20fb18aa28bfb9a985df9d5b9e9fd884cc32f0ccda3b077c8cba255f`。四项专项全部通过，覆盖 CRLF/原类型与宽度保留、畸形字段拒绝、实际 host 原输入与编码后运行及 NDK25 两架构对象。完整回归 **347 项，344 通过、0 失败、0 错误、3 环境跳过**，受检十份源码 SHA/size 前后一致，报告 `work/nianchu-size-t-regression-20261108-b/verification.json`；跳过为 Windows 符号链接权限两项及本机缺 valac 一项，真实 arm64/arm32 C/C++ wrapper 对象验证已实际通过。首轮 a 的新增 fixture 错把合法 qualified 位域列为应拒绝输入，并在 cpp-output 模式中留下未展开的 `__SIZE_TYPE__`；修正 fixture 的输入模式与错误预期后通过，未放宽产品解析检查。

19 个真实完整 libbpf scope 的 LF/CRLF **38/38** 通过，原字段、宽度 AST/span 和完整输出字节一致，聚合与编译期限制仍保守拒绝。完整 SDK17 `#include <bpf/libbpf.h>` 的本地 NDK25 arm64/arm32 baseline→完整预处理→编码器→对象链均成功，每架构 54 次匿名规范化，其中 19 次为 `size_t`；编码器输出与完整原预处理字节相同，6 个正确架构 ET_REL 对象和 16 条 clang/readelf 子命令均通过。报告 `work/nianchu-libbpf19-candidate-evidence-20261108-b/validation-report.json`，SHA-256 `7330b33a38480022312a1939cd42e4d38201a8504e03c9df1c78af63a79c0473`。该范围不当作整份 CI `linux.c` 复现或 r29 产品验收；后续固定 16/r25、17/r29 完整构建、E 预算与手机 native 验收继续按新提交身份执行。

内核模块 `nianchu-ptrace 1.1.2` 已完成实际构建、三组 ARM64 仿真和原子文件交付：`/data/local/tmp/nianchu-ptrace.kpm`，27,776 字节，`0644`、`root:root`，SHA-256 `3a9b9072cc4fb649c7071eb576a314c51b7d98e3557b9a14bd58ec5ab493220d`。module fixture 实际 136 场景、669 断言、0 失败，源码前后身份一致；交付记录 `work/nianchu-kpm-maps-symbols-delivery-20261108-a/deployment.json`。本次只交付文件，未加载/卸载/控制 KPM，手机 helper clone ABI 和 App 崩溃结果仍待动态验证。

## 2026-11-08 NDK C 无名位域解析修复（源码专项通过，完整产品待验收）

提交 `af3035d521d9aca53f6ced46f5bb31a832a431d9` 的 run [42440530273](https://github.com/2651899617/magicfrida-gadget/actions/runs/42440530273) 已通过 checks，17.25.2/r29 完成后结论 failure。独立下载归档身份为 ID `13602961104`，834,419 字节，SHA-256 `bea0bafbcefdc6aaba82364d8ea1c57110a4916aa1675f4ae8e12a3c74726c38`；大小、完整 SHA、CRC、safe paths 与所有解包字节已核。172 份 TU receipts 为 140 C 和 31 C++ compiled/rc0、1 C failed；真实 `gumv8scriptbackend.cpp` 已通过一次 `anonymous-enum-base` normalization。完整 29,142 行日志唯一失败 TU 为 Vala 0.58.0-frida 生成的 `linux.c`，预处理 rc0 后在 outliner 报 `input_does_not_parse`，尚未调用变换后 compiler。报告的 20 个 parse_error 为 `__u32 :32/:24/:31`、`__u64 :64`、`__u16 :16`；20 是窗口上限，不能据此断言完整输入没有其它语法问题。原 generated C、完整 pp 和 depfile 未归档，C 的 `-P` 去掉来源行，窗口不当作完整 TU。独立证据 `work/nianchu-outline-diagnostic-evidence-42440530273-17-20261108-b/diagnostics.json` 与 `linux-parse-errors.json`。本节记录时 16/r25 仍在 Build server/Gadget 步骤；已停止该失败 run 的等待交付程序，`device_delivery_started=false`。

修复仅用于 C：原字段子树唯一错误须为缺失 declarator，missing 坐标允许在 type.end 到 colon.start 的 trivia gap；原始完整字段命名 probe、投影 field probe 和最终 exact field/type/name/colon/clause/完整 width AST/semicolon 绑定均验证。只把原 type span 等长投影为 `T x`，保留全部真实编译字节和 CR/LF；synthetic parser 类型和字段保持未知，位域聚合仍跳过静态槽。宽度的 literal 按编译期保留，resource 在一般 `sizeof` 例外之前整资源跳过，隐藏原类型的资源引用同步审计。短类型、多 declarator、qualified C、未知扩展、畸形宽度与其它 ERROR 继续拒绝。候选编码器 SHA-256 `7eeea9e7551a8936e1f5d5841b44e364e2b8e69141b908459264c300e55b836e`。

新位域源码专项 **7/7** 通过、零 skip，用时 2.296 秒，日志 `work/nianchu-c-bitfield-source-tests-20261108-b.log`。包含原始/编码后真实 host C 执行、位域宽度/零宽边界/内存值检查、静态槽与整资源保留，以及真实 NDK25 `<linux/bpf.h>` 完整 include 的 arm64/arm32 原输入和编码后对象编译。首轮日志 a 保留：测试误假设固定 C++ grammar 接受无名 `sizeof` 位域，且假设 NDK pp 冒号后没有空格；按真实语法范围修正 fixture，改为对每个实际位域声明逐字节比较，未放宽 parser。NDK25/26 四组完整真实 BPF TU 已完成原 source/pp syntax/object 与冻结编码器 CLI、编码后 syntax/object，全部 rc0；r25 两架构各 24 个、r26 各 35 个无名位域，宽度完整 AST/span、原类型及字段声明输出字节保持。该独立 TU 无待编码字符串，输出与完整原 pp 字节相同，验证的是 parser shadow 与原 token 编译；字符串编码后 generated validation 与原值恢复由专项 host/NDK fixture 验证。source/header/pp/depfile 和原对象 SHA/mode 前后保持，对象为正确 ET_REL/ELF64-AArch64 或 ET_REL/ELF32-ARM。最终索引 `work/nianchu-authentic-bpf-uapi-tu-20261108-b/final-catalog.json`，SHA-256 `abe908d8c231317af79ce3285817045469fb475fcd5ad906e64e9d337a790624`；变换报告 SHA-256 `bc646f0082f194d76049604f81a553fa2896c53b1236d9a8bc0f244bcbda1069`。完整 Frida `linux.c` 再生成输入已独立审计：固定 core 866 源文件与 13 个 Vala 输入匹配，Linux/RPC patch 内存结果匹配 CI SHA；真实 valac 0.58.0-frida、标准 VAPI/EFNI、精确生成配置和 NDK29 本机尚缺，因此未重建失败 TU，原 20 窗口不拼接成 TU。

相同候选的最终完整回归 **346 项，343 通过、0 失败、0 错误、3 跳过**，用时 254.768 秒；十份受检文件 SHA/size 前后保持，报告 `work/nianchu-outline-regression-final-20261108-bitfield-b/verification.json`。真实 wrapper 的 arm64/arm32 C/C++ 对象四组通过；skip 为 Windows 符号链接权限两项、本机缺 valac 一项。首次完整回归 a 为 346 项、342 通过、4 skip，其中真实 wrapper 编译器环境未显式选择；final b 补齐 `NIANCHU_TEST_CLANG/CLANGXX` 后同源码通过，没有修改测试或实现以减少 skip。独立候选审查完成静态安全门与 9 个 Transformer AST 观察，范围内未见实证阻断；上游服务中断后的候选动态矩阵／绑定失配注入未完成，不称全面动态审查通过。这些本地诊断不替代固定 r29 产品、新完整 E 预算或手机 native 验收。内核模块 `nianchu-ptrace 1.1.1` 已编译与推送，尚未加载；手机正式 Frida 文件继续保持待替换状态。

## 2026-11-08 完整 C++ 模板析构与 Bionic 无名枚举解析修复（源码验证通过，产品待验收）

提交 `c3bb2b86de2d9ef1b990ea18e7dd7d40a74c9d46` 的 run [42396208965](https://github.com/2651899617/magicfrida-gadget/actions/runs/42396208965) 已完成，checks success，两个 Android build failure。GitHub 查询中断导致旧 progress 留在执行中，重新查询的完整 run/commit/event/path 与三个归档身份已核；失败结论来自实际 CI，查询异常不是编译原因。独立来源门禁实际收集可信提交中的 327 项测试，与日志一致：323 通过、0 失败、0 错误、4 明确跳过，两版 host Vala 编译和运行 rc0。16 共 269 份 TU receipt，266 compiled、3 failed；17 共 130 份，129 compiled、1 failed。全部已记录源 SHA/mode 保持，四份失败都在 AST 输入阶段，尚无变换后 compiler failure。17 `gummemory.c` 已由真实 r29 编码并编译通过，26 个 `neon_vector_type` 与 6 个 `neon_polyvector_type` 保留；16 主 arm64、compat arm 和 17 主 arm64 的 `gumdarwingrafter.c` 都 compiled/rc0，各两组 push(1)/pop、原字节保持、最终 packing alignment 空且栈深度 0。

16 的三处失败属于完整 `gumv8core.cpp` 主 arm64、compat arm 和 `gumv8process.cpp` compat arm：`argv[i].~Local<Value>()` 被固定 cpp grammar 读成比较表达式。修复仅在确认 destructor 成员调用、简单类型参数及完整独立类型与调用 probe 后空白化解析视图中的 `<Value>`；receiver、循环、下标、析构名和最终编译字节保持，模板布局仍未知，隐藏类型标识及 receiver 的 literal／资源引用继续接受保守判定。四项新析构专项通过，包含实际 host C++ 原输入与编码后编译执行、析构次数和顺序、原功能字符串恢复；零 skip，日志 `work/nianchu-destructor-source-tests-20261108-a.log`。

17 的唯一新失败属于 `gumv8scriptbackend.cpp` 的真实 Bionic `bits/bionic_multibyte_result.h`，合法 `enum : size_t { ... }` 产生缺失名称。只在原枚举子树唯一错误为缺失名称、非 scoped、完整整型基类型和枚举体独立 probe 通过后空白化解析视图中的 `:base`。枚举仍无名称，全部枚举项／值与偏移保持，原基类型编译字节保留，类型按 `cpp_fixed_underlying_anonymous_enum` 保持未知。枚举值和 `sizeof(resource)` 引用接受编译期上下文检查，整资源跳过；浮点／void、未知基类型和无关语法错误继续拒绝。枚举相关 9 项专项通过（6 项新增、3 项既有），包含 r25 arm64/arm32 原输入和编码后对象、host 固定宽度／符号／值断言与原值恢复，零 skip，日志 `work/nianchu-anonymous-enum-source-tests-20261108-b.log`。

prepare/config/build validation 增加实际 installer SHA-256 和显式 wrapper 版本，validation 回显三份工具 SHA 并拒绝安装脚本漂移或旧配置缺身份。源码编码专项 **90/90** 通过、零 skip，用时 46.842 秒，日志 `work/nianchu-outline-cpp-enum-destructor-source-tests-20261108-a.log`；包装器完整专项 29/29 通过、零 skip，用时 22.904 秒，日志 `work/nianchu-outline-installer-full-tests-20261108-a.log`。当前独立来源门禁已核真实失败归档的大小、完整 SHA、CRC、路径和解包字节，`delivery_passed=false`；旧 prepare 缺身份、TU failure、17 缺 arm32 和未生成产品全部继续阻断交付。字段一致性不是签名认证，完整 compiler/TU 原字节和设备运行尚需独立证据。完整 16/r25 `gumv8core.cpp` 和 `gumv8process.cpp` 的 arm64/arm32 四组原 source syntax/object、保留 `#line` 的预处理、原预处理 syntax/object 都已实际完成 rc0，原源码逐文件匹配固定 Git blob；生成头来自固定真实 Gum generator 和 GLib mkenums，没有删 include、截函数或替换 typedef。原依赖闭包为 613/615/559/556 份文件，各组 SHA/size/mode 前后保持，报告 `work/nianchu-authentic-destructor-tu-20261108-a/baseline/baseline-r25-a/baseline-summary.json`。这些 Windows NDK r25 诊断对象不当作 Linux CI 整产品或设备运行证据。冻结编码器 SHA-256 `3058f29feff04455a69fd6b1707f32725a82f6761d4330bd2584172b5b2e1a0c`，installer SHA-256 `3e72fa68780ce82c56f9128f6d4b320e8c179be2f06968cdbd47a7c13c9ef7d5`。

相同冻结源码完整本地回归 **339 项，336 通过、0 失败、0 错误、3 跳过**，用时 236.171 秒，受检十份文件 SHA/size 前后保持；报告 `work/nianchu-outline-regression-final-20261108-cpp-b/verification.json`。跳过项为 Windows 符号链接权限两项、本机缺 valac 一项。首次完整回归 a 的 1 个错误来自临时目录 `os.replace` 的 WinError 5，失败日志保留；更换独立 TEMP 后同源码完整重跑通过，没有修改 parser、patcher 或测试断言绕过该错误。独立只读 parser 审查 **727 检查、0 issues**，报告 `work/nianchu-parser-review-tools-20261108-a/review-final-3058f29f.json`；原始语义非法输入由真实 compiler 同样拒绝，未判作新增 shadow 吞错。

同一冻结编码器已完成四组完整 V8 输入的真实 CLI、转换后 syntax 与 object，全部 rc0；core 两架构析构 tokens 各 5→5，process 各 1→1，生成正确 ELF64/AArch64 与 ELF32/ARM 的 ET_REL 对象。原 source/header/pp/依赖闭包 SHA/size/mode 保持。汇总 `work/nianchu-authentic-destructor-tu-20261108-a/encoder/final-freeze-a/encoder-summary.json`，SHA-256 `1ff471940b1361b8e11047f80460b06e17f5f3bdd05b553a08be2b8d0d1b04a9`。core 每组保守跳过 `"/_frida.js"`，原因 `cpp_header_origin_call_parameter`，process 无 skip；各组 failures/errors 为空。逐根原头字节补审计正确解码 Windows `#line` 中文路径中的 octal escapes，libc++ 与 V8 合计字节数为 1,913,656/1,912,302/1,526,960/1,525,606，前后逐字节一致；报告 `opaque-raw-headers-per-root-audit.json`，SHA-256 `06c397ed5dfdbd7fbf55c65c062bcefd7ff1129da7ff6716414cae00a92a66c8`。补审计修正原辅助指纹只覆盖 libc++ 的计数范围，旧报告保留。上述实际 Windows NDK25/C++17 诊断编译不等于 Linux CI 完整配置、r29 产品或 Android runtime；新固定 NDK 产品、完整 E 预算和手机验收继续执行，手机正式 Frida 文件尚未替换。

## 2026-11-08 完整 Android 构建的 NEON 属性修复（实施中）

提交 `a23762c4c88136fd1827f31505ecb72bda905fbc` 的 run [42393330255](https://github.com/2651899617/magicfrida-gadget/actions/runs/42393330255) 已通过 Linux checks：**323 项，320 通过、0 失败、0 错误、3 跳过**，用时 33.726 秒；两版真实 host Vala/GLib 枚举生成、编译与运行均通过。17.25.2/r29 已完成此前失败的 `gumdarwingrafter.c` 编码与编译，随后 `gummemory.c` 的合法 `neon_vector_type` typedef 在 AST 输入阶段报 `input_does_not_parse`，前 20 个上下文为错误报告上限。16.7.19/r25 的完整构建仍在执行。17 失败归档 ID `13582324265`，166,980 字节，SHA-256 `05b0247725fcf4cd357d53799f3a1233cd346209b6229602c31f17e249b2e620`，run/commit、完整归档 SHA、CRC 和路径已核验。

修复仅将 `neon_vector_type/neon_polyvector_type` 加入现有属性解析白名单，原属性括号、参数、向量类型与 typedef 原字节完整交给真实 compiler；类型别名和使用该类型的静态 slot、资源继续按 `type_or_field_attributes` 保持未知。未知属性、非法参数或无关语法错误继续失败，未扩大 passthrough 或增加源代码 fallback。冻结编码器 SHA-256 `1869ba2d9141cd8114d2d15b081561f430d153fdda54e75dfa2bb982c03c3e2a`。新增 4 项 NEON 测试均通过，包含 r25 真实 `arm_neon.h` 的 arm64/arm32、GNU99 C/C++17 原输入和变换后对象编译、向量宽度及 polynomial intrinsic、slot 与整资源 skip，零 skip，用时 14.321 秒，日志 `work/nianchu-outline-neon-source-tests-20261108-a.log`。r26 的 C++ 两架构对照通过；其 GNU99 C 的 `-E -P` 原输入在运行编码器前因重复 `bfloat16_t` typedef 和测试显式 `-Werror` 失败，单独保留于 `work/nianchu-outline-neon-ndk26-reference-tests-20261108-a.log`，不计通过。完整源码专项 **80/80**、零 skip，用时 49.987 秒；完整本地回归 **327 项，324 通过、0 失败、0 错误、3 跳过**，用时 320.058 秒，跳过项仍为 Windows 符号链接权限两项、本机缺 valac 一项。测试期间十份受检文件的大小及 SHA-256 保持，报告 `work/nianchu-outline-regression-final-20261108-neon-a/verification.json`，对应源码专项日志 `work/nianchu-outline-neon-source-tests-20261108-b.log`。三份完整 `gummemory.c`（16/r25、17/r25、17/r26）已完成固定 Git blob 源及原 `dlmalloc.c` include、原源码 baseline、`-E -P` 输入、实际冻结编码器 CLI、`-x cpp-output` syntax 和对象编译；全部 rc0，未增加 `-Werror/Wno` 或修改 GNU99 标准。NEON typedef 原字节保持，每 case 转换四处 literal、两个 heap buffer；280/293/289 个依赖文件 SHA/mode 前后保持。catalog 为 `work/nianchu-authentic-memory-tu-20261108-a/catalog.json`，7,653 字节，SHA-256 `5eea813f1cc49a368e7a57700436e76a0567623ed698d9623db15ef3218ff760`。17 r25/r26 仍为本地对照；r29 产品、最终可读段预算和手机验收待新完整构建。

## 2026-11-08 完整 Android 构建的 packing 指令修复（实施中）

提交 `ef1f35a1cb9b62af0ce6820048459fd3f5d8e193` 的 run [42388162339](https://github.com/2651899617/magicfrida-gadget/actions/runs/42388162339) 已结束。Linux 回归为 **307 项，304 通过、0 失败、0 错误、3 跳过**，用时 32.372 秒；跳过项是 CI 缺少历史 Gadget 归档一项、未显式选择 NDK 的两项编码器测试。包装器的真实 arm64/armv7 对象和 host C/C++ 原值恢复集成通过，两版独立 Vala/GLib 枚举契约也通过。两版完整 Android 构建均在 `gumdarwingrafter.c` 的合法 `#pragma pack (push, 1)` 处被编码器误判 `input_not_fully_preprocessed`；此前失败的 core `patch.c` 和枚举对象已通过该轮实际编译。失败归档已核对 digest、大小、CRC 和路径；交付程序在构建门槛处退出，手机正式 Frida 文件未替换。

packing 修复保留原指令字节，按完整预处理输入的顺序跟踪生效范围，包含外部 C++ 头里的真实词法指令。packing 期间定义的聚合类型在后续静态对象中保持未知，即使对象在 `pop` 后声明也跳过字段改写；布局依赖递归穿透按值成员、数组、union/class 和 C++ 基类，指针与函数成员不传播该依赖。不安全的元数据引用使整个数字资源跳过。注释及 raw string 内的伪 `#pragma/#line` 不改变指令或来源状态；数字 pop 和关键字／保留编译器拼写 label 拒绝，避免 Clang/GCC 语义分歧。新增嵌套恢复、默认布局、递归按值依赖、指针例外、外部头跨来源、整资源跳过和无效指令拒绝测试。冻结编码器 SHA-256 为 `efaad29a46871990a3ed524fa1516acf9ae78c31157a66eadd54729b3e6b15b6`；源码专项 **76/76**、零 skip，用时 39.163 秒，包含实际 host C/C++ 和 NDK 编译，以及未知 `typeof` 语法提前返回前的递归 packing 标记保持；日志 `work/nianchu-outline-packing-source-tests-20261108-f.log`。最终冻结身份的独立 packing 审查完成，约定范围内无剩余阻断；五组完整 `gumdarwingrafter.c` 输入完成编码和实际 GNU99 NDK 对象编译（16 r25 arm64/arm32、17 arm64 r25/r26 和 17 arm32 r25 对照），全部原 pragma 字节／顺序与六个 packed record 布局保持。最终证据为 `work/nianchu-authentic-grafter-tu-20261107-61mgt_6b/evidence/catalog-encoder-efaad29a.json`，SHA-256 `ef9a69a2a936b07f03a231f8f153e4f4f1f7a3408c42198fe86fafdea7997233`。17 arm32/r26 的合成对照原 `-E -P` 输入在 API 19 的 `strtof` 声明处失败，未运行编码器、不计通过；17 r25/r26 均为本地对照，产品仍由固定 r29 CI 验收。完整本地回归 **323 项，320 通过、0 失败、0 错误、3 跳过**，用时 393.662 秒；跳过项为 Windows 符号链接权限两项、本机缺 valac 一项。测试期间十份受检文件大小及 SHA-256 保持，报告 `work/nianchu-outline-regression-final-20261108-packing-a/verification.json`。同一最终编码器的两版真实完整 `gumv8apiresolver.cpp` installer→wrapper→outliner→NDK 对象集成也通过：16 r25/C++17 对象 142,128 字节，SHA-256 `a0880b7f63f8cf4f4b29eb18d4c59e6fef24f42acfbeec268da86e7ac229bbbc`；17 r26/C++20 对照对象 265,736 字节，SHA-256 `811feba29fb366a51f3097b8521aa30c817f780e35a13ee3149d1360810f4963`。每版四处 literal、两个 heap buffer，1,701 份冻结输入的 hash/mode 保持，原依赖闭包及 ELF64/AArch64 ET_REL 节边界通过，临时文件已清理；报告位于 `work/nianchu-authentic-cpp-wrapper-integration-20261107-a/runs/source16-efaad29a-20261108-a/integration.json` 与 `runs/source17-ndk26-reference-efaad29a-20261108-a/integration.json`。下一次固定 NDK 的完整 Android 构建随后按提交身份执行；下文 307 项本地结果属于 `ef1f35a` 提交前的编码器身份。

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
