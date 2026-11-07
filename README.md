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

两版 pinned guard 为 **50／55** 份文件。基线提交 `764950b6865cbaf94e81177a753250a04d5bd670` 的 run 41980419791 已完成两版完整构建；2026-11-07 增补内部标识改名与功能查询键保留，新构建和验证记录另见 `docs/STATUS.md`。

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

`patches/rename.py` 使用固定 LIEF **0.17.6** 和 schema 2 报告：私有 `StopReason` 从源码生成 `NianchuAgentStopReason`，枚举数值、value_name 和 nick 保持；经核对的内部类型及函数诊断使用跨版本、跨架构一致的等长映射 `Frida→Nnchu`／`frida→nnchu`。原始字符串处理限于完整 NUL 字符串和明确清单，普通 `Friday`、公开 Frida API/DBus 类型、`GDBusProxy`、`GumScript`、`GLib-GIO`、ART 查询键、`./lib/android` 和 `FRIDA_V8_EXTRA_FLAGS` 保留。取消通用 `gadget` 子串替换，Zygisk 入口稳定为 `nianchu_gadget_init`。符号表仍使用 LIEF 改写并独立核 GNU/SysV hash；嵌入 Agent/helper 在资源编译前改写，外层 server 不改嵌入 ELF。collector 强制核 arm64/arm32 Agent 的入口、类型改名和残留，未通过就不发布。`--rewrite --kind agent|helper|server|gadget --report <报告>` 写回指定构建文件；不加 `--rewrite` 为只读审计。静态/host GLib 契约不等于 Android JS/Java、GC、异常和宿主业务验证。

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

内核工程不在本仓库构建工作流内。最新本地 KPM 安全基线只提供默认无 hook、可选精确 reader UID 的有界观察，**不包含 maps/路径/调试状态隐藏能力**。离线 ELF/策略检查不等于目标内核 ABI 或真实加载验证；不能将该观察基线称为通用隐藏模块已完成。

本次构建不包含 ADB 部署、KPM 加载、手机重启、system_server 注入、改 `/data/system`／`/data/app`、清数据或 App 安装卸载。

## 本地检查

```text
python -I -B -m unittest discover -s tests -p "test_*.py" -v
python -I scripts/build_module.py --ndk <NDK r25c 或 r29> --out <新的输出目录>
```

无 manifest 时只构建 wrapper，不生成伪 Gadget 或模块 zip。完整模块打包必须使用收集器生成的 `zygisk/manifest.json`。
