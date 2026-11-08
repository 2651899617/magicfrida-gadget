# nianchu-frida

Android arm64 自有源码构建工程，面向自有或已明确授权的测试 App。固定 Frida **16.7.19** 和 **17.25.2**；版本、上游 SHA、子模块 SHA 与精确 NDK revision 见 `versions.json`。

## GitHub 编译

公开构建仓库：<https://github.com/2651899617/magicfrida-gadget>。

`main`／`fix/build-integrity` 推送或手动触发 `.github/workflows/build.yml`：

1. Linux 运行补丁、ELF、产物报告及真实 C++ 配置/SHA-256 回归。
2. 16.7.19 使用 NDK r25c (`25.2.9519653`)，17.25.2 使用 r29 (`29.0.14206865`)；Node 22 是 CI 选择。
3. 克隆固定 tag 并验证实际 SHA、所有子模块状态、NDK 安装实值和上游 NDK 要求；不绕过版本检查。
4. 严格应用兼容补丁；全部文件/hash 预检查，禁止 fuzz 或失败继续。
5. 构建并依据 Meson introspection 收集两个 installed final target，拒绝缺 server、raw 或 modulated 中间产物。
6. 保存普通 Gadget 后，增量应用 `zygisk-loader` 并重建模块专用 Gadget，检查导出入口后打包。
7. 全部步骤通过才上传产品 artifact；失败日志和来源报告始终保留。

每版 artifact `nianchu-frida-<version>-android-arm64` 包含：

| 路径 | 产物 |
|---|---|
| `compatible/` | `nianchu-server-<version>-android-arm64`、`nianchu-gadget-<version>-android-arm64.so`、完整 manifest |
| `zygisk/` | `nianchu-gadget-zygisk-<version>-android-arm64.so`（只供显式模块初始化）、对应 manifest |
| `module/` | `nianchu-zygisk-<version>-android-arm64.zip`、wrapper 构建报告 |

**普通 Gadget 和模块专用 Gadget 不可混用。** 模块专用 Android Gadget 不在构造函数中自动启动；必须通过模块调用 `nianchu_gadget_init`。普通 Gadget 保持官方构造函数与相邻配置加载方式。16/17 官方 server 均基于对应源码 target，不是 rusda/Rust 成品。17.25.2 的 Compiler 使用 Go 工具链，CI 安装 Go 1.26 并显式启用，避免 auto 模式缺依赖静默降级。

## 当前修改范围

默认 recipe 按参考 patch 开启 `exit-monitor-off`、`signal-interposition-off`、`agent-entrypoint-rename` 和 `gadget-json-config`。server 默认资源目录与 agent 前缀使用 UUID；helper、socket、memfd 和初始化品牌使用 `nianchu`。RPC 标记通过双层 Base64 解码生成，线上协议值仍为 `frida:rpc`；Droidy/ADB 对参考 patch 指定的 OPEN/CLSE/WRTE 分支执行 break。Linux 临时目录返回值按参考改为 `/system/lib64`，其设备权限与运行影响尚待实机验证。系统 Python 和现有 frida.exe 保持原状。

两版 pinned guard 为 **51／56** 份文件，包含 Android 编译入口 `releng/env_android.py`。基线提交 `a8c907f212ffa588223de8bb8598302e4612e394` 的 run 42353264303 已完成 raw Agent 名称修复、完整构建和四简名手机交付；E 轮编码改造的新构建和验证记录另见 `docs/STATUS.md`。

| feature | 当前默认与作用 |
|---|---|
| `zygisk-loader` | 仅模块版追加；Android 构造函数不启动 Gadget，由 wrapper 显式初始化 |
| `exit-monitor-off` | 默认开启；移除退出准备 interception 的构造逻辑 |
| `signal-interposition-off` | 默认开启；停用 POSIX exception backend attach/detach 及 signal/sigaction interposition |
| `agent-entrypoint-rename` | 默认开启；源码定义、导出与注入消费者统一为 `nianchu_agent_main` |
| `gadget-json-config` | 默认开启；Android Gadget 查找 `.config` → `.json` → `.config.so`，显式 config_data 优先 |

产物名称继续标记 `-entry-renamed-`／`-json-config-` 等有效 feature；server 不添加 JSON 配置变体名。普通 Gadget 与模块专用 Gadget 分别收集；ELF 改写若改变模块初始化符号，最终 wrapper 必须消费经校验报告中的 `initialization_symbol`。

```text
python -I -B scripts/apply_patches.py --source <固定完整Frida源码根目录> --version 16.7.19 --report <树外报告>
```

17.25.2 使用对应 version；模块构建追加 `--feature zygisk-loader`。默认 feature 自动合并，不需要在命令中重复列出。

16 bundled Java bridge 6.3.9 已增加编译前参考 patch hook，移除 PrettyMethod hook；17 外置 7.0.13 使用独立 patch/build 脚本生成 bundle。它们与下节 `direct-art-gc` 实验是两套不同 profile，测试和产物报告分别记录。

`patches/rename.py` 使用固定 LIEF **0.17.6** 和 schema 4 报告，保留已有内部标识和 raw Agent 清理规则。私有 `StopReason` 注册名为 `NianchuAgentStopReason`，枚举数值、value_name/nick 不变；raw Agent 从 Meson 生成 `libnianchu-agent-raw.so`，最后一次 LIEF 写出后只清除确认无动态字段、符号或版本引用的完整旧名。GNU/SysV hash 和 arm64/arm32 内嵌 Agent 的入口、实际 SONAME、新类型正向锚点、旧 raw 子串归零仍强制核验。

新增 `scripts/outline_elf_strings.py` 在编译前处理预处理 C/C++。原功能字符串和指定 gumjs 数字资源存为编码字节，Android 通过每翻译单元一个匿名 RW arena 恢复，直接使用 mmap/mmap2 与内部32位原子 once，避免 priority101 构造阶段提前调用尚未初始化的 GLib；ARM64比较交换使用内联LDAXR/STXR，host诊断保持 GLib heap 模型。wrapper按实际最终 Android target 选择对应 ARM64/ARM32 runtime。AST 指定静态表字段、资源引用和函数名，保留公共查询键、wire/API、enum name/nick、source_tag 以及原资源字节、长度和 `sizeof`。不安全上下文保留并报告具体原因。GNU/Clang 扩展使用等长解析视图定位，原编译输入保留真实 token；被遮罩的属性和未知类型仍参与写入安全判定。NEON 的 `neon_vector_type/neon_polyvector_type` 沿用属性解析视图，实际向量类型及参数原字节完整编译，引用该类型的静态 slot 与资源按属性类型保持未知。C++ 显式模板析构调用仅在 AST 确认成员调用、简单类型参数和空参数列表后遮蔽解析视图中的类型参数，receiver、析构函数名和最终编译字节保持；隐藏的类型标识和 receiver 资源引用继续参与保守安全判定。无名定基枚举仅在原树的唯一错误是缺失名称、完整基类型和枚举体经独立解析通过后遮蔽 `:base`；枚举仍无名称，类型保持未知，枚举值与其中的 `sizeof` 资源引用按编译期上下文整资源跳过。C 无名位域仅在字段子树唯一错误为缺失 declarator、原始完整字段命名 probe 通过后，将原类型 span 在等长解析视图中投影为 `T x`；冒号、完整宽度 AST、分号与换行偏移保持，真实编译字节不改。synthetic 类型和字段保持未知，含位域聚合仍不改静态槽；位域宽度的字面量和 `sizeof(resource)` 保持编译期，任一资源引用使整个资源跳过。字面量 `#pragma pack` 保留原字节并按整个输入跟踪生效范围；按值包含受影响子对象的聚合递归跳过，指针成员不传播该布局依赖，不安全的资源元数据引用使整资源跳过。外部头只恢复词法识别的真实指令，注释和 raw string 内的伪 `#pragma/#line` 不改变状态；未知指令、编译器语义不同的数字 pop 和关键字 label 继续拒绝。C/C++ 均使用 `-E` 保留 compiler line origins；仅具体 libc++／V8／Highway 头根建立 C++ opaque AST 视图；原外部头仍完整编译，自有 core/gum、GLib 和 NDK C 头继续解析，外部头内标记与资源明确报告。来源切换要求完整声明边界和顶层／namespace／extern C 作用域；外部同名类型、重载和静态变量引用按未知处理。wrapper `1.1` 强制来源策略与根重叠检查，旧 prepare 配置拒绝复用。prepare、config 和 build validation 保存 installer／wrapper／outliner 的 SHA-256 与 wrapper 版本；安装脚本在 prepare 后漂移或旧 config 缺该身份时拒绝验证。两版 Android `releng/env_android.py` 的 Meson compiler 数组使用外置 Python `-I` wrapper，兼容 arm32 同样接入；精确 parser pins、工具 SHA、原 source SHA/mode、原依赖及 target/sysroot 都核验。最终输入使用 `cpp-output`／`c++-cpp-output`，避免 forced header 二次展开。

schema 4 重新枚举最终全部可读 PT_LOAD 的 `p_filesz`：ASCII 0x20–0x7e、每片最多 256 字节、大小写不敏感匹配 `frida`、每个 callback 计一次。每份 Agent/Gadget 必须有非零扫描字节和 printable callbacks，匹配回调允许为零且必须少于 21 次，server 内嵌两架构分别检查；旧 schema 3 拒绝复用。普通 `Friday` 与原缓存 SDK 残留列入预算，原功能值不得靠逐串改 QuickJS bytecode 消除。`--rewrite --kind agent|helper|server|gadget --report <报告>` 写回指定构建文件；不加 `--rewrite` 为只读审计。host 契约与磁盘计数不替代 Android JS/Java、GC、异常和宿主业务运行验证。

## Java bridge 源码实验

`patches/java-bridge/<version>/direct-art-gc.patch` 分别基于固定官方 6.3.9（16 bundled 底座）和 7.0.13（17 外置 ESM 候选），独立改写 `ArtMethodMangler` 与 `class-factory` 原调用消费者：原方法承载替换，clone 供非虚原调用，失败清理和 revert 恢复相互联动。7.0.13 另将 Nterp 同步的 quick_code 操作对准原调用 clone，保留 ESM 导出与 index.js。两版专项合计 13 项，各有 39 个源码模型检查通过。不安装到用户客户端，不改变 global.Java，不自动进入 server/Gadget 构建。

该实验保留 GetOat/GC 类引用同步、PrettyMethod 和 JDWP；不安装原方案的 quick dispatch/DoCall 重定向。只支持 Android >= 6.0 的 ARM/ARM64 非编译入口（含显式 Nterp clone 回退），拒绝 Xposed 包装和编译后入口。模型/语法/补丁重放不证明真实 ART、GC、JIT/AOT 或异常安全。

```text
python -I -B scripts/prepare_java_bridge.py --version 6.3.9 --source <完整官方6.3.9源码包目录> --out <新实验目录>
python -I -B scripts/prepare_java_bridge.py --version 7.0.13 --source <完整官方7.0.13源码包目录> --out <另一新实验目录>
```

输入必须逐文件匹配固定包 SHA；输出含 `package/` 和 `bridge-report.json`，明确标注 source-only、未打包 runtime、未实机验证。17 外置打包仍待完成；17 源码适配不等于已被客户端消费。

16 另有独立 `gum-runtime` recipe：新增默认空值选项 `nianchu_java_bridge_source`，跟踪完整实验包文件，在编译前严格验证/准备 bridge，并使用独立 `-direct-art-gc` 私有缓存。7 项集成模型测试覆盖 QJS/V8 调用顺序、默认缓存隔离、缺依赖安装及半修改缓存拒绝；编译器为测试替身，尚无真实 bundle、Android 二进制或运行证据。默认/当前 CI 未启用该实验。

```text
python -I -B scripts/apply_dependency_profile.py --component gum-runtime --version 16.7.19 --source <固定Gum源码根目录> --report <树外新报告>
```

源码 recipe 应用后，另用新的实验 builddir 设置 `-Dfrida-gum:nianchu_java_bridge_source=<prepare_java_bridge输出的package绝对路径>`。不得将实验报告或产物冒充默认兼容版；最终 collector 尚未接入该变体。

## 静态 SDK 输入校验

两版固定 GLib、releng/deps.toml、SDK 和 bootstrap 版本另见 `patches/dependencies.json`。`verify_dependency_sources.py` 只认证**尚未修改的输入 checkout**：核 HEAD、完整 Git blob 字节、递归子模块，拒绝修改、未跟踪/被忽略的旧构建文件和导出归档。输出明确标注未构建 SDK、未验证最终消费；此命令尚未接入 CI，也不是修改后 SDK 的验收器。

```text
python -I -B scripts/verify_dependency_sources.py --version 16.7.19 --releng <完整固定releng checkout> --glib <完整固定GLib checkout> --report <树外新报告>
```

GLib 独立 `thread-labels` recipe 只修改两处线程标签（`nianchu-worker`、`nianchu-dbus`）；每版保留 7 份固定源码 guard，日志域/GType 不变。releng 独立 `sdk-lock` recipe 在设置 `NIANCHU_SDK_LOCK=<绝对锁清单路径>` 后按 machine/prefix、版本、精确文件集和 SHA-256 验证已部署 SDK，失败不删目录、不走 SDK 下载兜底。该锁仅约束单一 SDK machine/prefix，不锁 toolchain，也不证明构建来源；当前未接入多 SDK/CI 配置链。

```text
python -I -B scripts/apply_dependency_profile.py --component glib --version 16.7.19 --source <固定GLib源码根目录> --report <树外新报告>
python -I -B scripts/apply_dependency_profile.py --component releng --version 16.7.19 --source <固定releng源码根目录> --report <另一树外新报告>
```

上述两 component 也支持 17.25.2。上游未锁定 SDK 缓存仅凭 `VERSION.txt` 接受，旧安装 manifest 还能跳过构建。后续必须隔离 `FRIDA_DEPS` 和构建目录，核对修改后源码、库 hash、实际 machine-file/pkg-config 及链接输入；当前未完成 SDK 重编和 final link 消费验证，不能用旧预编译包替代。多文件替换不提供失败回滚；partial 状态会被后续检查拒绝。

## Zygisk

说明和配置见 [`module/README.md`](module/README.md)。借鉴 xiaojia 的选目标、可配置延迟、listen/wait 和远程连接流程；不复制其 Gadget/loader 成品。默认无目标，按完整 UID 和精确进程名匹配；拒绝 system_server 与广域注入。不依赖 companion 或 libc++_shared，不写 App 数据目录、私有 linker 链表或全局属性，不吞退出信号。

## 验证层级

- 本地回归和 wrapper 交叉编译可证明对应源码模型/ELF检查通过。
- Actions 成功才能证明本轮 16/17 server/Gadget 完整构建通过。
- 官方客户端握手、JS/Java/GC/异常/方法替换、Zygisk/SELinux 加载及目标 App 真实业务**仍需独立运行测试**。
- 监听、PID 活着、脚本打印或编译通过不等于 App 正常使用。

当前状态与未覆盖项见 [`docs/STATUS.md`](docs/STATUS.md)，补丁取舍见 [`docs/patch-decisions.md`](docs/patch-decisions.md)。

## KPM 边界

内核工程位于工作目录独立的 `nianchu-ptrace-kpm`。按用户最新要求，`nianchu-ptrace 1.1.1` 已加入当前读取者或调用者 `UID > 10000` 门槛，maps、TracerPid 和 TRACEME 统一适用；UID 10000、root、shell 保留原行为，没有特定 App UID 名单或被读目标 PID/UID 过滤。maps 精确将 `/memfd:nianchu-cache` 显示为 `/nianchu-cache`，保留 deleted 后缀、数字字段与真实 VMA/vm_file；`maps=on/off` 可控。已核对 xiaojiahide、pandahide 的调用局部 count 快照和新增输出处理方式。1.1.1 固定工具链编译和三组 Unicorn ARM64 测试通过，手机文件推送与实际内核 ABI、加载验证分别记录。

手机交付使用四个简名 `server16`、`server17`、`zygisk_gadget16.zip`、`zygisk_gadget17.zip`，以及独立 KPM 文件；Zygisk 安装、KPM 加载、手机重启与 system_server 注入不随文件推送执行。

## 本地检查

```text
python -I -B -m unittest discover -s tests -p "test_*.py" -v
python -I scripts/build_module.py --ndk <NDK r25c 或 r29> --out <新的输出目录>
```

无 manifest 时只构建 wrapper，不生成伪 Gadget 或模块 zip。完整模块打包必须使用收集器生成的 `zygisk/manifest.json`。
