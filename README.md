# magicfrida-gadget

自构建的魔改 frida-gadget（Android arm64），目标：在 DexProtector 加固的 app
里可用且不被检测。

## 背景（检测模型，全部实测）

DexProtector 的 native 检测在 `attachBaseContext` 里同步执行（启动后约
0.4–1.1s），检测维度（详见看雪文章《新版 dexprotector 环境检测分析》）：

1. **inline hook 检测线程**：持续扫描 `libc` / `libart` / `libandroid`
   的代码页，找异常跳转指令。stock frida 的 exit-monitor 在初始化时
   `interceptor.attach` libc 的 `exit` / `abort` —— 必中。
   本仓库用 `frida-disable_exit_monitor.patch` 在源码层移除。
2. **frida-java-bridge 的 ArtMethod.prettyMethod hook**：bundled runtime
   会 hook libart —— `frida-disable_art_prettymethod_hook.patch` 在生成
   runtime 时删除。
3. **信号处理器接管**（gum exceptor backend attach）——
   `frida-disable_signal_attach.patch` 移除。
4. **r_debug 链表枚举**：DP 通过 auxv→AT_PHDR→r_debug 遍历所有加载的 so。
   注入侧（zygisk wrapper）需要在 `r_debug.r_map` 和链接器 `solist`
   两条链上都摘掉 gadget 节点（见 magicfrida 仓库的 wrapper）。
5. **字符串/内存特征**：构建后由 `patches/rename.py` 做同长度替换
   （保留 `re.frida` 协议串，官方客户端直接可用）。

## 使用

1. `push` 或手动 `workflow_dispatch` 触发构建（默认 frida 16.7.19）
2. 在 Actions 页面下载 artifact `magic-gadget-arm64`
3. 推到目标 app 的私有目录，由注入 wrapper `dlopen`（参考 magicfrida
   仓库的 syscore wrapper：预置 → dlopen → 持链接器锁摘双链 → unlink）
4. 官方 frida 客户端（协议 `re.frida`）`frida -H 127.0.0.1:<port> -p <pid>`

## 补丁

| 补丁 | 作用 |
|---|---|
| `frida-core/frida-disable_exit_monitor.patch` | 移除 libc exit/abort 的 inline hook |
| `frida-gum/frida-disable_art_prettymethod_hook.patch` | 移除 bundled java-bridge 的 ArtMethod hook |
| `frida-gum/frida-disable_signal_attach.patch` | 移除 gum exceptor 的信号接管 |
| `patches/rename.py` | 构建后字符串指纹清理（同长度替换） |

## 声明

仅供安全研究与授权测试使用。
