# nianchu Zygisk Gadget loader

独立 arm64 / Android API 26+ / Zygisk API 5 模块。仅供自有或已授权测试 App；编译和 ELF 检查不等于 Zygisk/SELinux/目标 App 运行验证。

## 来源和与 xiaojia 的区别

参考其显式选 App、配置延迟、listen/wait 和远程客户端连接流程。已只读核对的两个样本 config SHA-256 均为 `5eb188865bfcc46b31fcb6e12699ecb8a76b61f3872cac3809c6f20cfb8bfc36`，端口 14725、on_load wait。native 样本可见 config/package_name/inject/delay/dlopen 字符串，但其具体线程、文件复制和摘链行为未经反编译/运行证明；没有复制其二进制或私有实现。

Zygisk 头文件沿用公开 API，ISC 风格许可证完整保留于 `include/zygisk.hpp`。loader/policy/SHA-256 为本项目独立实现。

## 初始化方式

必须加载启用 **zygisk-loader** 源码 feature 的最终 nianchu Gadget。它保留底层 Frida 内存初始化构造函数和官方协议，但 Android `frida_on_load` 不再自动启动 Gadget；导出 `nianchu_gadget_init(config, result)`，在 `android_dlopen_ext` 返回、linker 锁释放后调用官方 `frida_gadget_load`。

preAppSpecialize 只读取 targets.conf、打开最终 Gadget FD 并调用 exemptFd。postAppSpecialize 创建 detached 工作线程；worker 延迟指定毫秒、复核大小/SHA-256、FD 映射、解析显式入口并传入 JSON 配置。不会写 App 数据目录或全局环境变量，不需要 root companion。模块在线程和 Gadget 活跃时保留映射，不 dlclose 活代码。

可选 `gadget-json-config` 仅增加 Android Gadget 的相邻配置查找：`.config` → `.json` → `.config.so`，默认版仍为 `.config` → `.config.so`。本模块始终显式传入 JSON，优先于文件查找，因此不需要附带或写入 App 私有 `.json` 文件，也不安装文章的 script interaction/script.js。JSON 配置版载荷和模块 zip 带 `-json-config-`；与入口实验组合时为 `-entry-renamed-json-config-`。zip 内部载荷仍固定 `gadget/libnianchu-gadget.so`，两种普通/模块初始化方式不可混用。

**wait 仅让 Gadget 初始化线程等待客户端，不承诺停止 App 主线程。** App 启动/SELinux namespace/FD 权限/Gadget 抽象进程枚举均须在隔离测试环境验证；100ms 是可配置值，不是所有 App 通用时机。FD 加载不会隐藏 maps，未实现 linker 摘链。

## 配置

安装包 targets.conf 默认全部为注释。每一行必须为：

```text
10123 com.example.nianchu.test 100 14725 wait
```

字段为完整 UID、精确进程名、delay_ms (0..60000)、port (1024..65535)、wait 或 resume。最多 64 条/16KiB；UID 仅允许常规 App appId 10000..19999（包含明确的 Android user ID）。同 UID 的其他进程、子进程名、isolated/system_server 均不会自动匹配。重复/未知/畸形配置全部拒绝，不做部分加载。

地址固定 127.0.0.1，避免样本 0.0.0.0 对外监听。授权运行时，远程端点应使用官方匹配版本客户端；连接姿势与样本 `-H 127.0.0.1:<forwarded-port> -F` 相同。端口转发和实机启动不由构建脚本执行。

## 构建门槛

```text
python -I scripts/build_module.py --ndk <NDK> --out <新目录>
python -I scripts/build_module.py --ndk <NDK> --out <新目录> --manifest <收集器 manifest.json>
```

第一条仅编译 wrapper，不提供伪 Gadget 或 zip；第二条必须有最终 Gadget 的完整源码/补丁来源、hash、显式导出入口，才打包。NDK 16.7.19 使用 r25c，17.25.2 使用 r29。拒绝 libc++_shared 和未知动态依赖。

当前 collector 只接受 Meson 已安装、已后处理的 `frida-gadget` 最终 target，实际文件名必须为 `nianchu-gadget.so`，拒绝载荷文件 symlink 和解析后 raw/modulated 中间产物名。manifest 记录 `final_filename` 和 `gadget_config_lookup`；builder 必须核对 feature、外部变体名、候选顺序/显式配置优先及完整来源/hash。旧基线 manifest 不含本轮新约定，不能拿来打成本轮新版模块。源码模型或打包格式测试不证明新 Gadget/生成头/最终 ELF 已编译，实际编译和设备加载仍须独立验收。

不包含 service.sh/post-fs-data.sh、全局属性伪装、信号过滤器、私有 linker 写入、自动安装 APK、ADB、KPM 或重启操作。没有 APK 图形选 App 界面，配置目前为显式文本。
