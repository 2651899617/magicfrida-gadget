# 补丁取舍与来源

此表记录本轮实际采用范围。参考文章与样本并不自动等于目标 App 实测；没有取得对应源码/许可或功能测试的项不标为完成。

| 参考面 | 处理 | 16/17 实现或边界 | 验证 |
|---|---|---|---|
| server 资源目录/agent 创建与查找 | 独立重写 | 固定源码中的 nianchu 品牌资源，保留动态入口 | SHA、精确命中、创建/lookup 联动 |
| Gadget/JS 线程标签 | 采用语义级修改 | 修改 g_thread_new 参数，不改宿主 prgname | 两版 recipe/diff 重放 |
| 全文二进制/rodata/symbol 替换 | 淘汰 | 审计原字节；不改 embedded ELF/bytecode | 畸形 ELF 拒绝、copy byte identity |
| re.frida/frida:rpc 编码及异常命令吞掉 | 不采用 | 保持官方协议，不吞解析错误 | 静态保持；runtime handshake 未测 |
| 入口改 main/xiaojia_main | 不采用 | 保留 frida_agent_main，模块新增独立 nianchu_gadget_init | 源码 guard 与模块导出检查 |
| exit-monitor 删除 | 可选实验 | 精确删除构造函数 attach，保留其他逻辑 | 无 dangling Windows call，未测有序退出 |
| signal/sigaction 修改 | 可选实验 | 只去 replace/revert，不禁整个 exceptor backend | handler 安装/cleanup 保留，runtime 未测 |
| ART/GC/JDWP/PrettyMethod | 待功能替代与证据 | 16 bundled bridge 6.3.9 不改；17 外置不假装已改 | 上游注释证明 PrettyMethod 有异常兼容功能 |
| gum_ensure_code_readable 短路 | 淘汰 | 保留代码页保护和原功能 | 不写该 patch |
| xiaojia Gadget 选目标/延迟/listen-wait | 借鉴交互、独立实现 | 精确 UID+进程、worker delay、显式 JSON init | 样本配置只读、真实 C++ policy/hash；Android 未测 |
| xiaojia 成品载荷 | 不复制 | 发布只来自固定 Frida 源码 final target | collector provenance/hash/entry gate |
| 默认 solist/r_debug 摘链 | 不采用 | 不写未核实 linker 私有 ABI | 不宣称 Hyatt -500 唯一根因 |
| resetprop/全局信号过滤/开机 APK 安装 | 不采用 | Zygisk 包不含这些 scripts | 静态契约检查；不触碰设备 |
| hidecore/panda 广域内核过滤 | 不复制 | 当前 KPM 仅观察 foundation，不在此 CI 发布 | 默认 nohook，不宣称隐藏完成 |

## 固定来源

官方 Frida 16.7.19／17.25.2 的 superproject、core、gum、releng SHA 见 versions.json。测试 fixture 是这些固定提交的八份原始源文件，仅用于完整性和重放；具体路径及 SHA-256 在各版本 spec.json。

Zygisk API header 来自已有公开 API 5 副本，SHA-256 `f8d55e8b4f89d418c5941afe62ce6a09ddec1f4afd9a1b0a01eb40a93310dd28`；完整上游许可证保留，不修改 header。

本地 xiaojia 两个 config 样本 hash 均为 `5eb188865bfcc46b31fcb6e12699ecb8a76b61f3872cac3809c6f20cfb8bfc36`，listen、14725、wait。native 样本中 config/package_name/inject/delay/dlopen 字符串只说明含相关字段/符号，不能当作具体执行路径或摘链证据。没有引入样本私有代码，故不在发布包内携带其载荷或 APK。

rusda、xiaojia Java bridge/gothook 参考仓库已取得固定 clone，但全面实际 patch/许可核对尚未结束。当前不复制这些仓库实现，也不声称已完成其精华移植。检测文章中特定 RVA、哈希或设备私有布局不写进通用模块。
