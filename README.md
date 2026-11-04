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

默认 `nianchu-compatible` 仅包括经过固定源码联动检查的四类命名修改：server 临时目录、自有 agent 临时资源名、Gadget 线程标签、JS scheduler 线程标签。保留 `frida_agent_main` 和官方 `re.frida`／`re/frida`／`frida:rpc`；不改用户系统 Python、frida.exe。

| 可选 feature | 功能代价／状态 |
|---|---|
| `zygisk-loader` | 仅模块版启用；增加显式配置初始化入口，普通自动加载不适用 |
| `exit-monitor-off` | 禁用退出准备 interception，可能影响有序退出；CI 默认不启用 |
| `signal-interposition-off` | 禁用 signal/sigaction replace，保留异常 handler 安装/清理；可能影响异常处理，CI 默认不启用 |

16 bundled Java bridge 固定 6.3.9，当前未修改 ART/GC/JDWP/PrettyMethod 功能。17 的 Java bridge 由客户端/脚本外置提供，不能声称 server/Gadget 补丁会修改它。当前补丁不是全面检测面隐藏，也不承诺所有 App 免检测。

`patches/rename.py` 已改为**只读 ELF 边界审计**，不做任何二进制替换。hash 与 marker 报告不等于动态 lookup／协议握手验证。旧 `patches/frida-core`／`patches/frida-gum` 文件仅为历史参考，CI 不应用它们。

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
