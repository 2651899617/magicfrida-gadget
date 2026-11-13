# 当前工程状态

记录日期：2026-11-13。

## 2026-11-13 定位残留 linker 模式与 DEX 解密密钥状态

精确APK10915 SHA f9ea96b04a146d725a1d2f12ebe51826563ebcdb6d80f527be19997fdcfdb5e6；离线inner ELF SHA fe064a9d1811bdb71d8fe870db2090b72962071c71a18a53fa63169299161a82。已定位 native mCookie 扩展：复制旧槽，每payload output置0，调用0x10380忽略bool并追加包括null的结果，JNI SetObjectField写回；该路径可形成两旧槽加五null的现场数组。运行时是否进入及5次OpenCommon实参尚未捕获。设备Java DexFile.close在native返回false时仍清mCookie，因此不能继续把普通Java close结束后留下非空部分零mCookie作为主要解释。

完整恢复壳0x6b994的3个ASCII扫描模式（83/119/143字节），在正式c3bc内嵌ARM64Agent中全部各1次，Agent偏移0x235b1b/0x1874a0/0x222197；Agent SHA87f64f44fc2601c82dda6c33522b2fbc71c0fb51e5682071c12468ff45cf67b4。壳直接搜索文本，??/?4也是literal字节；现有线程改名不处理此特征。gum-js-loop/gmain/linjector及/subprojects/frida直接count0，现场nianchu-js，剩余gdbus都是路径/标识/日志。

关键更正：sp+0x80+0x420就是sp+0x4a0；0x2291c重读已受sp28状态影响的16字节，0x2292c写入global0x129588所指实际SM4密钥。此前“比较缓冲区与密钥分离”判断错误并撤回。0x6b994匹配后状态0x1d，经密钥影响DEX解密；当前已确定静态连接，未动态捕获配置/状态/返回。API29 OpenCommon size来自DEX头base+0x20的file_size，而非外层descriptor长度；magic/version/过短size可返回null，verify和verify_checksum均false。

本地16源码候选已实施：固定 `gumandroid.c` 只改变三条ARM64模式的首字母 `f`→`F`，实际指令值、通配掩码、位移和解析路径保持。上游SHA `4a48a4b32cd93335440cc5c05e01ee93ea877b15ab5da0e7ee04d783a8f81dcd`，结果SHA `0b1a1d3a2c110d142ca8f687d6018f71c22b0b1a466173a20e3332eabab4f465`。16固定文件55→56，17 recipe保持。61项定向检查通过；使用既有固定依赖venv完成394项完整离线回归：389通过、5跳过、0失败、0错误，源码前后身份一致，耗时235.758秒。跳过项为旧Gadget实物、Windows符号链接权限两项、Host Clang扩展和valac。首轮系统Python缺解析器依赖导致失败的记录仍保留，没有安装依赖或改全局配置。

云端audit和独立下载核验均新增第五项 `gumandroid.c`：两架构真实编译回执→object→Gum archive→同Agent绑定，并检查链接ARM64Agent及server内嵌资源三个旧literal为0、新literal存在。独立核验按1MiB分块，165项流式边界/计数/schema拒绝检查通过，精确c3bc旧产品被正确拒绝。这是核验器逻辑与负对照结果；新GitHub产物的完整消费链尚未运行，不能当作已构建或已部署。

本阶段完成本地源码候选、静态分析及离线验证；没有新增spawn/切服/reboot/设备命令，未更新生产server、commit/push/CI或完成业务/真实q验收。手机c3bc不含候选。正式修复仍待新GitHub构建和com.moutai.mall10915的原父进程、Agent、业务UI、unload/detach、真实CLI q及server退出/framework验收；17未测。完整报告 `work/current-evidence/moutai10915-helper-decoded-20261113-a/state-dex-chain.md`，原始结果在同目录 `linker-pattern-regression-b/report.json`、`linker-pattern-streaming/report.json` 和state-strings-e。下列设备身份只保留此前采集时状态。


## 2026-11-13 新 boot 的原生与单页 RX 对照仍复现空 DexFile

发现设备 boot 已变为 `07e81a42-245b-4095-877d-16ec8e4b8631`；本轮没有执行 reboot。注入前 framework1048/704/705、Agent映射0、linker代码完整RX。普通启动父进程18756持续存活超过75秒，后到LoginActivity；UI提取控件0且未视觉审查，只记录普通启动存活，不称业务通过。

只启动已核验c3bc默认server20810/ticks4309670，argv仅绝对exe、默认27042，ready回执核对owned socket inode512376。默认preload会注入系统Agent，因此server存在对照不等于纯进程存在实验。启动后zygote704的linker offset0x53000页RWX，设备ELF符号确认RVA0x53344为 `rtld_db_dlactivity`；该处原RET字节c0035fd6被改为B，页内只有这4字节不同。

原生heartbeat测试App21289没有调用Java、没有业务hook，ready后resume仍于00:48:11+0800复现 `OatDexFile::FindClassDef+12`、fault0xa8、x0=0。故Java.available初始化不是本次故障的必要条件。第一个native-rx实验21686因字节严格guard失败而没有实施权限修改；不计为RX实验。

有效RX单变量实验App23926/ticks4365185保留活动hook及全部4096字节，仅把App内linker offset0x53000页RWX改为RX；ready及heartbeat收到，权限后字节SHA保持8d6368de71fea7643b25f134b180f78b6a3bdde47ea15213f7862fe7955359fa。5.49秒身份保持，10.62秒原进程消失；00:54:17+0800同0xa8崩溃，cookie长度7、index0/1非零、index2..6零。匹配tombstone_02 SHA ca632313ebff407fbaf0aeb5b26f46eeb21ec5a25472be1965c65a8fe1dcb789确认实验页到崩溃仍RX，另出现offset0x3c000 RWX（该页包含 `do_dlopen` 入口）。因此只排除“恢复0x53000这一页即可解决”，未排除其它hook/权限变化、默认preload副作用或App侧响应。script destroyed是目标SIGSEGV后的清理结果，不当作新根因。

最新只读核验App为空，server20810及framework身份保持、boot保持；没有停服、追加spawn、系统attach、改fake/SELinux或清数据。新App兼容性仍未修复，正式产品未改变。证据：moutai10915-fresh-boot-20261113-a、moutai10915-default16-ready-20261113-a、moutai10915-native16-20261113-b、moutai10915-native16-linker-rx-20261113-b、moutai10915-rx-final-20261113-a。以下“App/server为空”等旧节为当时状态。

静态补充：23926的x1/x3内存实捕类描述符 `Lcom/moutai/mall/MTApp;`，实际失败发生在壳实例化目标Application查找MTApp。Android10参考closeDexFile会保留已注册DexFile并清零其它槽；设备匹配libart符号 `DexFile_closeDexFile` RVA0x413458/size1704，RVA0x413794字节1f7b36f8为写0到cookie当前槽。该路径能形成所见部分清零状态，但未证明本次调用及调用方，不据此patch ART。完整反汇编在moutai10915-art-cookie-close-20261113-a，参考源码在moutai10915-cookie-reference-20261113-a。

源码消费链按HEAD核验Gum pin88e78178f786bf8cea2172ed6aeff335f30dd299；rtld_db_dlactivity/r_brk hook为官方保留路径，未被recipe修改。CI实际应用edits和default_features，已交付默认signal-interposition-off移除整个POSIX Exceptor安装（包括SIGSEGV/SIGBUS等）及signal/sigaction替换，exit-monitor-off移除exit/_exit/abort准备拦截；均为实际兼容性变量，尚未证明本次因果。native无Java仍包含Gum/Exceptor对象/module registry初始化，不能称零内部hook。独立汇总 `work/current-evidence/moutai10915-rx-final-20261113-a/conclusions.md`。git diff --check退出0，未重跑完整构建或把离线验证计作App验收。

## 2026-11-12 新 App com.moutai.mall 1.9.15/10915 尚未通过

用户报告裸CLI `frida -U -f com.moutai.mall` 已spawn/resume，但App19533于2026-11-11 23:09:56+0800在ART类查找时SIGSEGV，fault0xa8。设备版本实核1.9.15/10915、UID10322、ARM64；旧技能案例1.9.12/10912不适用，未复用偏移。保存匹配tombstone_09及设备libart，BuildId ccd73e8ae9b59d5596b3b8aeef234d43、SHA6419d690ecbdc247b348199f27b1f2819829bbb275d4b3bec3f35ec4e284c22c。

ARM64调用处读取Dex cookie第2槽为0，作为x0传入静态 `OatDexFile::FindClassDef(const DexFile&,...)`；RVA0x44e0e8对应 `ldr x8,[x0,#0xa8]`。空的是传入DexFile，不是OatDexFile::this。tombstone确认cookie长度7、index0/1非零、index2..6为0；Android10参考源码遍历index1起的所有槽，没有逐槽判空。已定位直接崩溃机制，但未证明哪个组件创建/清空cookie。可读取的调用处256字节与设备磁盘libart一致；PC页为--x，未实捕该页运行时字节。

原App有nianchu-cache Agent、无完整offset0带路径ART解析副本；采集时server16已不存在，不能凭Agent名称反向确认当次server SHA。普通启动仅做一次明确组件am start，15秒等待超时后出现反复fork子进程、PC0x978/SP0/LR0的另一类崩溃，Splash不能验收。保存最新tombstone_03（App2800，00:55:24，Agent映射0），随后一次am force-stop仅结束本次App崩溃循环；App/server为空，framework1041/694/695和boot fbc92c19保持，没有重启、清数据、改fake UID、安装模块或追加注入。

当前zygote64 linker64文件offset0x53000的一页仍RWX；只读精确比较4096字节已与磁盘完全一致，0不同字节，SHA be161c487d3c0c19b26090c5f21c4dc6b69b8fff298c3c2ce905a17f1f411cff。代码恢复但权限保留；该页亦在此前同boot修复产品验收映射里。Gum原有gum_memory_patch_code在RWX系统不恢复页权限，与残留候选吻合，尚未证明新App检测此页或其引起空cookie。当前读取权限候选只改ensure_code_readable，不解决patch_code/Interceptor写后残留；不得称现有候选已经修复此问题。

诊断 `work/current-evidence/moutai10915-art-crash-20261112-a/diagnosis.md`；普通启动证据在moutai10915-plain-20261112-a。新App可用性未通过，正式源码和产品未改变，未自动执行新的reboot；仍需稳定普通启动基线、实际server身份和官方16/魔改16对照后收敛server补丁。

## 2026-11-11 默认端口手动spawn及按用户要求停服

专用47016测试与用户默认27042启动曾同时存在两份c3bc产品；用户默认CLI超时发生在创建App PID前，system_server记录ProcessStartResult.pid空对象，不能当作旧Provider/NPE或直接认定双server是唯一根因。用户默认PID14915后来退出，未向其发信号；只对助手明确归属PID9316单次TERM，pending spawn/children为空，移除owned18851→47016转发，系统Agent映射随后为0。

随后只启动一份无额外参数的同路径c3bc server，PID17697/ticks158942、默认端口，无手动转发。用户明确反馈“我刚刚手动测试 可以spwan”，并要求停掉server；按fresh完整身份及SHA核验后单次TERM17697，确认已退出、server PID为空、framework与boot保持。此处spawn成功是用户反馈，不扩大为助手已完成真实CLI q/完整业务验收。以下旧节的9316/13136“保持运行”是当时历史状态，已不是当前状态。

## 2026-11-11 修复 server16 在新boot下完成三轮spawn验收

用户明确选择切换并实测。精确复核时旧server18976已经退出，无其他server，不追加信号；正常ADB reboot后新boot `fbc92c19-4608-406e-93e4-7d013e06bbdb`，framework1041/694/695。注入前核对正常ART映射无旧Agent/完整解析副本；恢复仅ROOT fake（UID10323，fake1/nokill0，附加监控关闭），只启动已核验 `/data/local/tmp/nianchu-server16-42803346600/server16`。当前server9316、start_ticks54377，运行SHA `c3bc3731a835f40fe844bd286e6b5f87aa835028616da8ba72c7853ff9c3a96d`，本机转发127.0.0.1:18851→设备127.0.0.1:47016，启动--disable-preload。

对App7.51.0/751002完成三轮：裸spawn/resume App9703（ticks61077）；两次spawn/attach/ready+heartbeat/resume App11355（ticks67644）、App13136（ticks74854）。各自原父进程存活≥25秒，进入SignInActivity，UI树有登录/注册控件；本轮Provider/NPE与主线程FATAL为0，无目标退出信号。两次script unload/detach成功，退出会话后同一App仍活；framework及server完整身份保持，policy测试前后SHA一致。最终点击登录入口获得即时协议提示响应，未输入或提交账户信息；最新mResumedActivity为PhoneOrEmailLoginActivity，App13136、ppid694、State S。

三轮App及最终系统进程均无完整7,696,384字节offset0带路径ART解析副本，说明匿名backing修复在真实Agent生效。此前旧默认文件SHA1c37df…所复现的Provider/NPE，在当前修复映像三轮中未复现。旧 `/data/local/tmp/server16` 文件未覆盖；用户当前应使用上述已运行的独立修复路径，避免再次启动旧文件。

**已通过口径：本设备/版本/ROOT fake条件下裸spawn/resume和连续两次Agent脚本生命周期、登录页UI响应。** 首页业务未登录验收，截图未视觉审查，真实CLI q及server进程退出/ARM32系统Agent卸载未测试；不将SDK detach替代这些项目。17未测。读取权限/maps短读候选尚未进入此运行产品，当前无新commit/push/CI。

报告 `work/current-evidence/repaired16-cleanboot-start751002/acceptance.md` 和 `acceptance-summary.json`；三轮原始报告分别为repaired16-cleanboot-bare751002、repaired16-cleanboot-heartbeat1-751002、repaired16-cleanboot-heartbeat2-751002。修复server9316及App13136保持运行。

## 2026-11-11 用户实测当前魔改 server16 spawn 重现 Provider/NPE

当前主任务是魔改server16的可用性；普通fake启动仅是基线，不将Root谓词/VM研究替代server修复。用户在同一新boot自行使用server16 spawn后报告崩溃。只读采集确认App19106于1794407200.601创建，1794407205.132发生主线程 `Unable to get provider androidx.startup.InitializationProvider`、`AppInitializer.doInitialize(SourceFile:13)` 空List.isEmpty NPE，1794407205.240退出signal9。普通App10093此前在1794407200.008被ActivityManager force-stop，不能将其退出当作检测自毁。

用户当前运行的 `/data/local/tmp/server16` 为PID18976、start_ticks733081、PPID18923、SHA `1c37df2853c03589c67ba83a5bc44f78dd49751be26ff9ff67a17e305955547c`、size54198952，对应4516059/run42499266252，不含后来ART parser匿名backing及Thumb修复。zygote64 697现在存在完整7,696,384字节offset0带路径ART解析副本 `0x713fd7a000–0x71404d1000`，system_server1033也有完整副本；与此前独立backing正反对照所确认的NPE触发条件一致。本次App19106已退出，没有其直接maps，不把当前系统映射冒充该App快照。

含修复的124e/run42803346600产品已在 `/data/local/tmp/nianchu-server16-42803346600/server16`，设备和主机文件SHA `c3bc3731a835f40fe844bd286e6b5f87aa835028616da8ba72c7853ff9c3a96d`、size54198952核验通过；既有双架构源码→对象→归档→Agent→server独立消费链报告存在。但此前该产品在另一个已注入boot中更早SIGKILL，仍不代表当前fake条件下spawn通过。它不包含未提交的读取权限/maps短读候选。

保持用户正在运行的server18976，未发信号、未追加注入或启动第二server。有效新产品验收需先允许停止当前已确认server并重启，使zygote不继承当前旧Agent；不得把双server环境当成干净对照。诊断与可核验原始证据： `work/current-evidence/operator-modified16-spawn751002/diagnosis.md`。本次魔改server可用性未通过，未宣布修复完成。

## 2026-11-11 重启后开启 Root fake，普通启动到达登录页

用户要求重启并开启fake测试。此前仅发出重启说明而未执行的错误已纠正；实际ADB reboot后boot变为 `ab6bc030-7f04-42a9-8de0-d5ce4cb624e7`，framework为system_server1033、zygote64 697、zygote698。系统启动完成后，经APatch临时加载既有 `nianchu-syscall-crash`，设备模块与技能包SHA均为 `30fdfce8979d44c96b84da0fef9b52a448c715dc23f4a77128f9595c89c84ace`。没有读取SuperKey，没有运行setup_device.py，没有启动Frida server、加载maps模块或修改SELinux。

内核回执确认uidadd=10323和 `trace=1 fake=1 nokill=0 dump=0 exitmon=0 memmon=0 pathmon=0 sysmon=0 resolve=1 ROOT=1 FRIDA=0 XPOSED=0 AOSP=0 uidcount=1`。仅Root路径类别启用；本次日志有358条fake:1路径记录，包括/system/bin/su等返回-ENOENT。日志中tgid字段显示697而tid显示10093，不使用该tgid字段证明App父进程；身份以/proc/10093/stat的start_ticks100053、ppid697核对。

一次普通 `am start -W` 创建父进程10093，25秒内身份保持，20秒时进入SignInActivity；UI树显示登录、注册控件。点击登录入口立即产生“请勾选同意协议后再进行操作”响应，未填写或提交账号信息；后续实际Activity为PhoneOrEmailLoginActivity，同一父进程已持续170.94秒。framework身份与policy SHA前后一致，前后无server进程。报告 `work/current-evidence/plain-fake-reboot751002/report.json`、UI摘要及截图已保存；截图尚未进行视觉审查，不把截图保存本身当作视觉验收。

当前结论：重启加Root fake的普通启动已能打开并响应登录页面，完整首页业务与Frida spawn仍未验收。由于没有同一新boot下fake关闭的冷启动对照，本次结果未单独区分重启和fake的因果贡献，不能据此宣布魔改server问题已修复。保持fake开启和App运行，后续先只读采集稳定进程。

## 2026-11-11 当前普通启动失败，纠正 spawn 因果归因

用户指出“不spawn App也进不去”。该观察与本轮证据一致：在没有Frida注入、没有spawn操作的普通 `am start` 中，App10152、10321、11600均被SIGKILL。最新11600（start_ticks3001857，parent700）于1794393227.757创建，1794393227.994退出signal9，约237ms；本轮helper仅读取/proc，未写App内存、未发送设备信号。故“当前退出由新server16/spawn直接造成”的归因不成立；当前按普通启动故障定位，暂停重复spawn和部署候选server。

所有上述实验都在boot `a14ed9f2-e93a-4e52-9da8-915023492618` 中，早于普通启动已注入并卸载过系统Agent。无注入前基线，所以这些结果也不证明魔改无问题，尚需区分环境/策略/App状态与注入残留。此前带路径ART解析副本与AppInitializer/NPE的一次性对照仍是独立已验证问题，不与当前更早SIGKILL合并归因；读取权限/maps短读候选是已复现源码缺陷，其385通过/4跳过不代表App修好。

最新只读采集 `work/current-evidence/plain-bound-frames751002/report.json` 保存同PID两库8个映射的first/last共16个完整快照，helper保留数据4,259,840字节、整体预算8MiB/8秒，退出后独立文件已按SHA删除；framework PID/start_ticks/exe与policy SHA前后一致。libexec本次匿名RVA0x44000、753664字节SHA `55504a2c0860558443d6ef6b20b5de657fa3cc96ec6b474a1c1c3c1b91451da7`，3次采样代码一致；数据段74字节变化。libexecmain匿名RVA0x15000、798720字节SHA `f468a35ca3f0e55bc47e5f6176c3dc954e5b40dd066c8cfb92e97ce62093bafc`。不复用10321本次RVA0x46000或旧750043偏移。

同次原生链接表已恢复mprotect/syscall/kill导入、constructor表及JNI_OnLoad RVA0x7666c。退出helper0x47bfc–0x47d98通过getpid取得自身PID，0x47d7c执行kill(9)，状态flags483/494在采样中均0；指针槽0x116140经壳VM表0x116000调度。另定位代码校验0x4e1ec–0x4e354（尝试RX后比较磁盘4字节）和权限函数0x4e744–0x4e9d0（maps扫描、mprotect、返回状态），以及0x4cc34中比较0x58000051/0xd61f0220的代码签名。仅为静态已存在路径，尚无运行时pc/lr证明哪个退出点触发，未建立execmod拒绝到SIGKILL完整因果；未patch App/VM/JNI。

下载后新核验工具 `work/nianchu-cloud-delivery-tools-20261110-a/verify_cloud_evidence16_repairs_streaming.py` 已覆盖backing/Thumb/读取权限/maps四修正的源码→双架构回执→对象→归档→同Agent→重写资源→server字节链，要求显式完整commit/run与干净可信checkout。语法检查通过，旧124e缺新fixture及短commit在读大归档前拒绝；新云端正向消费链尚未执行，没有新commit/push/CI。原生静态Agent因模型限流终止，无结果，不计为审计通过。

## 2026-11-11 16真机对照及代码读取权限候选

提交 `124e15430ebef43f14ed7c8c74cfea5d618a55c6` 的 run [42803346600](https://github.com/2651899617/magicfrida-gadget/actions/runs/42803346600) 已成功；归档13772628518完整785,947,404字节，SHA `5c902658c9f72ea7df0a97cedfc4bda8527f64c89e4f712a85719eee09f98c8c`。16两profile各49个来源输入独立核验，手机独立文件 `/data/local/tmp/nianchu-server16-42803346600/server16` 的SHA `c3bc3731a835f40fe844bd286e6b5f87aa835028616da8ba72c7853ff9c3a96d`、大小54,198,952、权限755通过。用户“启动 测试”后执行本轮实验；17未部署或测试。

新16心跳App20429、官方16.7.19同脚本App2213、新16无attach/JS裸spawn3521、官方裸spawn4250均SIGKILL。当前boot的普通启动1387也SIGKILL，但发生在系统Agent注入/卸载之后；不能视为注入前基线，不能因此推出魔改无问题。裸spawn的真实maps显示新16只有正常4段ART映射，官方额外有7,696,384字节同路径完整ART解析副本；backing修正在新产品上生效，App先退出，原Provider/NPE及业务尚未验收。

手机此前已重启，原生产7316在本轮交付前已不存在。候选19867/3084、官方1718/3946均按本轮完整身份及运行SHA核对后单次TERM退出；未向生产、zygote或system_server发信号。最新boot `a14ed9f2-e93a-4e52-9da8-915023492618`，framework1121/700/701身份保持，三系统进程Agent映射计数均0，无测试server。卸载后ART/log代码字节与磁盘一致，libc部分字节也一致但仍RWX；这不等于未经注入状态。官方server自身启动会调用SELinux policy初始化，因此getenforce不变不足以证明策略完全不变；本轮未手动修改策略，后续不以重复启动扩展该影响。

源码确认16 `gum_ensure_code_readable()` 在API29以上直接把读取代码页改为RWX。本轮16-only候选改为查询原权限，已可读不改，不可读仅增加READ，保留已有WRITE/EXECUTE，失败不缓存。固定新增fixtureSHA `b04af3b6b0fd39cceb085f4c5934dc116059cc03509de3fd3eb72a047af111f8`；生成器/recipe及云端gummemory两架构对象→归档→同Agent消费链联动。**只修代码读取的误加WRITE，不称Memory.patchCode/Interceptor全部权限残留已修复，也未证明这是当前SIGKILL根因。** ART/log execmod拒绝先于退出，kill调用者尚未定位。

定向57项、0失败/错误/跳过，154.644秒，报告 `work/nianchu-readability16-focused-regression-20261111-d/report.json`；包含实际提取旧/新C函数编译执行（旧11/新0）、跨页及失败重试、消费链绑定拒绝、生成器/feature/patch重放和workflow契约。首轮三次WinError5临时文件替换失败在独立临时目录同源码重跑通过。完整报告 `work/nianchu-readability16-diagnosis-20261111.md`。本候选尚未commit/push/构建新产品或真机验收，手机文件不包含本候选。

完整回归首轮e为386项、3失败、3错误、66跳过，报告保留；临时目录含中文及frida、未显式选择测试编译器导致路径拒绝、raw literal多匹配和大量原生用例跳过。改用独立ASCII目录 `C:/Users/2651899617/AppData/Local/Temp/nso-suite-20261111-f` 及已安装主机GCC/G++、NDK25 Clang，未修改产品源码或放宽断言。六个原问题及两个读取权限测试8/8复测通过。最终完整回归 **386项、382通过、0失败、0错误、4环境跳过**，247.235秒，全部受检scripts/tests/fixtures/recipes SHA/size前后一致，报告 `work/nianchu-readability16-full-regression-20261111-f/report.json`。跳过为Windows符号链接权限两项、host GCC缺GNU99定基enum扩展一项、缺valac一项；不计为通过。这是源码/小型fixture验证，未执行本机完整Android产品构建。

最新只读状态 `work/nianchu-phone-readonly-20261111-f/report.json`：boot及framework1121/700/701保持，无server。两次限时无Frida普通启动采集f/g均未取得完整匿名RX字节，App7749/7933均SIGKILL；各自保存当前日志窗口及报告，host watcher退出，未发送信号或写设备策略。f识别libexec相邻匿名RX745,472字节，整份maps作为printf单参数触发参数长度限制且未读到字节；g限定目标相邻行后仍未抓到完整代码。没有据失败采集定位补丁或扩展设备操作。

真实完整gummemory.c候选使用既有NDK25 ARM64头文件完成源码对象、保留行来源预处理、当前outliner及转换后对象四阶段，均rc0，源码/头文件身份保持；报告 `work/nianchu-readability16-authentic-tu-20261111-g/report.json`。这仅一个完整TU，不是本机完整产品构建，不声明ARM32或Android业务验收。只读审计确认该16 recipe没有maps过滤或FILE/fd替换，但上游maps迭代器补读一次后可能解引用NULL换行指针。实际提取函数完整read退出0、每次20字节短读访问异常0xc0000005，未建立与App SIGKILL的因果。

16新增固定gumprocess-linux.c fixtureSHA `7a9f4120eb724d2611a558ddd91db9dabc69e3c82c2ee937111291ce7ac0e935`，与固定上游归档逐字节一致；读取权限查询依赖该迭代器，因此候选补读至完整换行，EOF/读取错误/超长行返回FALSE，不增加过滤或改fd生命周期。generator/recipe固定文件16增为55、17仍58；云端审计加入两架构maps源码→实际编译回执→对象→Gum归档→同Agent绑定。定向26/26通过，最终 **389项、385通过、0失败、0错误、4环境跳过**，296.604秒，受检源码/fixture/recipe身份一致；报告 `work/nianchu-mapsread16-full-20261111-i/report.json`。首轮新增harness计数器int/size_t严格编译失败已按size_t修正，未放宽-Werror。当前候选仍未commit/push/新CI或手机部署；App SIGKILL及业务修复验收仍未完成。

旧751002 live dump漏采相邻匿名RX解密段（libexec753,664字节、libexecmain798,720字节），已有首段不够定位退出。一次无Frida只读短窗口采集未取到遗漏段，超时后host watcher退出，reconcile确认目标已退出、无遗留采集进程及framework/boot保持；不套用750043偏移。


## 2026-11-10 Thumb 双架构消费链审计修正，仅重建16

提交 `6a0a191744fb232e9ef1e42434f21f79cbcedc75` 的 run [42764739790](https://github.com/2651899617/magicfrida-gadget/actions/runs/42764739790) checks成功；16完整make和compatible成品收集完成，随后审计错误 `exactly one actual ARM32 Thumb relocator compilation required`，未发布产品。失败日志artifact13754225614，1,796,768字节，SHA-256 `1906bac8f37f2785cd072dec7eb71187552dae564ab992dbd22dd4192afc737e`，已独立下载核验。

真实receipt证明同一修正 `gumthumbrelocator.c` SHA `079e6a38e41e2b3cb6ad1f6ba0941ef4b28c905449431bc95f3e21d438737bb6` 被编译两次：primary ARM64和compat ARM32都成功。Gum ARM/Thumb后端也进入ARM64库，原新增gate错误假定只有ARM32记录。本次不删除另一架构证据，改为恰好各一份，分别绑定对应架构ELF backing对象链接的Agent，拒绝缺失、重复、未知架构或任一Agent SHA不匹配。

按用户“只核对 16 版本 17 目前还没有测试”，push默认仅构建16；manual dispatch显式选择17或both才扩大矩阵。完整编译继续只用GitHub。旧27e62e0的16 compatible/Zygisk完整证据已分别独立复核43个输入，报告 `work/nianchu-cloud-evidence16-independent-20261110-c/report.json`；不作为Thumb新产品或Android验收。生产7316保持原映像，新产品尚未部署。

## 2026-11-10 新成品 spawn 实测与 ARM32 清理 SIGILL 修复

完整 GitHub run [42663039421](https://github.com/2651899617/magicfrida-gadget/actions/runs/42663039421) 对提交 `27e62e0244d91c50f5be9446f786c4cb7d0d2826` 的 checks、16.7.19、17.25.2 全部成功；回归379项、372通过、7跳过、0失败。两版成品归档已顺序流式下载并核对发布SHA/大小/ZIP CRC。新16的compatible、Zygisk、两架构内嵌Agent、Gadget和模块独立核验通过，报告 `work/nianchu-cloud-product-audit-42663039421-20261110-a/verified16.json`。17独立成品审计和两版完整证据tar的本机独立消费链复核仍待完成。

新server16已推送 `/data/local/tmp/nianchu-spawn-42663039421-20261110-b/server16`，54,198,952字节，SHA-256 `42fbb0fcff6f64326f50055bf43b43e16207201c6c960b5497743b6f6e69e95a`，未替换生产 `/data/local/tmp/server16`。候选PID10993在loopback47016握手full后，对 `com.danlan.xiaolan` 7.51.0/751002执行一次零JS spawn；25秒取消，未返回PID、未attach/resume。系统报 `ProcessStartResult.pid` 的null读取，App未创建；原AppInitializer/List.isEmpty为0条不能判定修复通过。报告 `work/nianchu-newserver16-app-spawn-42663039421-20261110-b/report.json`。

pending spawn/child均为空后只对已记录候选10993发TERM。退出期间13:16:33的32位zygote11560发生SIGILL，随后framework自行重建；boot_id不变。生产7316的完整PID/start_ticks22213802/exe/device66323/inode24721/argv/大小及运行SHA `1c37df2853c03589c67ba83a5bc44f78dd49751be26ff9ff67a17e305955547c`始终保持，没有向生产、zygote或system_server发信号。候选/helper11226/监听已退出，精确forward37949→47016已移除；新文件和全部证据保留。普通am启动的等待命令25秒超时，但只读后续观察确认17865/17895保持20秒、framework11639/11548/11551稳定，Activity为SignInActivity登录页，近期日志无原NPE；不是新server spawn或业务页验收。

完整tombstone和四组runtime代码窗口绑定新ARM32 Agent：RX文件offset0x4dd000对应ELF VA0x4de000，load bias0xc7e43000；LR0xc8334b01对应ELF VA0x4f1b00，逐字节匹配 `gum_memory_get_protection → gum_proc_maps_iter_destroy → close`。故障PC0xe098571c字节 `2d e9 01 80`为Thumb非法PUSH含PC；来自两版 pinned `gum/arch-arm/gumthumbrelocator.c` 的PC-relative LDR重定位。修复保存 `{r0,r1}`预留两栈槽，第二槽覆盖目标后仍POP `{r0,pc}`，r1保持不变。两版原fixture SHA相同 `52db2f355ddf39e347c79b8b5322cc64e9bc6a94d2564be102b3fefa8ea6da09`，只改该序列。小型实际提取C函数原生回归两项通过，旧编码失败/修复后成功；writer和目标内存为fixture模型，尚未做真实ARM32跳板执行或修复后设备验收。云端消费链gate新增Thumb源码→ARM32对象→archive→同一Agent绑定。此次修复尚未重建成品；前述27e62e0产品不含此修正。

定向回归 `work/nianchu-thumb-focused-regression-20261110-a/report.json`：60项、59通过、0失败/错误、1项缺host C编译器跳过（既有ELF backing host harness）；新增Thumb两项包含四次小型host原生fixture执行，全部通过。生成器重放、GNU patch/feature组合、消费链绑定拒绝和workflow契约均通过；完整Android构建继续由GitHub执行。

证据：`work/nianchu-newserver16-framework-evidence-20261110-a/`，地址绑定 `crash-binding.json`；普通启动只读观察 `work/nianchu-newserver16-ordinary-readonly-20261110-a/`。先前双Agent环境下的spawn结果不作clean comparison，App创建前ProcessStartResult-null阶段仍需独立定位；不重复注入、不控制KPM、不改SELinux、不自动停止/切换生产server。

## 2026-11-10 GitHub Actions 构建及 ELF backing 消费链审计

AppInitializer 修复已提交为 `2da202eed0c2bcbf44a87e0d36e6c17f09104295`，已推送 `fix/build-integrity`，触发 run [42660605039](https://github.com/2651899617/magicfrida-gadget/actions/runs/42660605039)。该 run 的云端回归为371项、364通过、7跳过、0失败；两版完整构建已进入编译。所有本地大型编译已停止，后续完整构建只在 GitHub Actions 执行。

新增独立构建主机审计 `scripts/audit_elf_backing_ci.py`：在 compatible 收集后、Zygisk 源码变化前保存第一份证据；Zygisk 收集后保存第二份。核对实际 canonical Gum SHA、ARM64/ARM32 编译回执与 ET_REL 对象、对象在 Gum ar 归档中的逐字节存在、实际 Ninja 数据依赖及执行记录、Agent 完整 ELF 和两架构嵌入 server 的字节一致性，并保存证据 tar 与逐文件 SHA。产物与失败日志均上传该证据。该步骤不编译代码、不操作设备，构建来源证据不代替 Android runtime 验收；编译器在主机上计算 SHA，完整编译器及临时预处理/转换文件不随证据打包。

消费链审计补充需要后继 CI 实际执行；上面的首轮 run 不含新增审计步骤。完整产品、独立下载审计和隔离原生验证仍待完成。保持正在运行的生产 server，不自动切换进程映像。

## 2026-11-09 AppInitializer 回归：继承的 ART 文件解析副本

当前 Frida16 产品来自提交 `4516059cba184c4b5133d374f5abac7383cd95d4`，完整构建 run `42499266252` 的 checks、16、17 jobs 均成功；新16已完成文件核验和手机交付。用户自行启动后的生产 PID7316，start_ticks22213802，运行映像 SHA-256 `1c37df2853c03589c67ba83a5bc44f78dd49751be26ff9ff67a17e305955547c`。前节“完整产品待构建”是提交前的历史阶段记录。

目标为 `com.danlan.xiaolan` 7.51.0/751002。用户报告 KPM 已卸载；裸 CLI 和零 create_script 的 production spawn/attach/resume 均复现九个 Provider 实例化失败及 `AppInitializer.doInitialize(SourceFile:13)` 的空 `List.isEmpty()`。普通 am 启动、production spawn/resume 不 attach、production spawn 加隔离 server numeric-PID attach 均在观察期存活。隔离 attach 的两版真实 Agent 段布局已核，不把测试结束主动 detach 的 `application-requested` 当作 Frida 被 App 杀死。旧版双 server spawn 对照发生32位zygote SIGILL并引起系统自行重建framework，未作为有效App版本对照；测试server及转发已清理。生产server映像始终保持。

失败路径保留 zygote 继承的 Agent。Gum `ThreadCountCloaker` 的 ART import 枚举触发 `_gum_native_module_get_elf_module()` 缓存；`gum_elf_module_load()` 用 `g_mapped_file_new()` 读取整份 ART，GBytes 长期持有该文件映射。内部 Cloak 不改变原生 `/proc/self/maps`。失败快照中多出 `0x7951539000–0x7951c90000`、offset0、大小 `0x757000` 的同路径 `libart.so` 副本，启动后副本成为 RWX，实际 ART 代码仍 execute-only；新加载 Agent 的通过快照没有副本，实际 ART 代码成为 RWX。此路径上游16/17原本就存在，尚不将其归因为新字符串arena的某个错误。

一次性测试App中，probe只把该只读副本原地址替换为匿名映射，逐字节确认7696384字节一致，恢复只读，随后卸载probe脚本再resume。PID25255和重复实验PID26904均存活27秒，无Provider/NPE；匹配的同脚本只读control保留文件映射，PID26723再次出现相同Provider/NPE。证据为 `work/nianchu-art-backing-probe-20261109-a/`、`work/nianchu-art-backing-probe-control-20261109-a/` 和 `work/nianchu-art-backing-probe-20261109-b/`。该对照确认带路径的解析副本是本次兼容性触发点；壳内部具体maps消费者函数尚未定位，不冒用旧750043偏移。

源码修复已纳入两版默认兼容 recipe：Android ELF磁盘解析改用 `g_file_get_contents()` 和 `g_bytes_new_take()` 持有完整匿名内存副本，覆盖ONLINE/OFFLINE，保留source_blob、vDSO、APK提取、原解析指针生命周期和非Android映射路径；文件读取失败保留OFFLINE错误/ONLINE live-base回退。避免对heap buffer登记page-aligned `file_mapped_range`。此分配发生于已初始化GLib后的lazy解析，不恢复早期constructor101调用GLib。

最终本地完整回归 **371项，367通过、0失败、0错误、4环境跳过**，用时209.466秒，全部受检scripts/tests身份前后保持；报告 `work/nianchu-elf-backing-full-regression-20261109-c/report.json`。跳过为两项Windows符号链接权限、host GCC不支持GNU99定基enum及缺valac。新增ELF专项5项包含两版×两平台四个实际编译执行的源码提取harness，验证普通/空文件、错误、cache/lifetime及blob/vDSO/APK旁路；GLib ownership doubles不代替Android成品。首轮完整b只有旧guard数量断言51/56未更新，现随新增gumelfmodule改为52/57；前期子Python GBK错误输出已通过显式UTF-8修正。旧日志保留，未放宽产品检查。

新server/Gadget完整构建与无probe成品真机验收继续执行；probe成功不当作新server成品已验收。当前HEAD仍为 `4516059`，新源码尚未提交或推送。


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
