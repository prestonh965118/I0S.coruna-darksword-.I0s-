---
title: "iOS 屏幕画面外流链路归属防御分析报告"
description: "iOS 上的一帧画面到底有没有离开这台设备、由哪条通道离开、这一格在哪些面上读得回、能对外说到哪一层：十一层归属分解（L1 会话与画面来源面标识、L2 授权与同意、L3 通道件、L4 执行域与隔离、L5 落点与存储、L6 观测平面、L7 告知、L8 复位与再核对、L9 管理面回查、L10 公告对齐、L11 引用与结论），三件（采集件／落点件／告知件）× 11 类会话 × 20 项核对项的差集口径，J1—J4 与 Q1—Q4 两套判定模型，两个离线只读核验脚本（75 + 64 个码，共 139 个全部实跑触发，33 次实跑逐码覆盖表）"
lang: zh-CN
---

# iOS 屏幕画面外流链路归属防御分析报告

## 摘要

本报告集前十八篇依次回答过这些归属问题：缺陷在哪（第 01、06、07、12 篇的攻击面归属）、谁能进入这道门（第 02 篇的访问控制归属）、这条链路看见了什么（第 03、04 篇）、这台设备归谁（第 08、10、11 篇的主体归属）、这段代码凭什么被允许运行（第 14 篇的授权链归属）、这条通道凭什么存在（第 15 篇的通道归属）、同网段上谁看得见谁（第 16 篇的局域网可达性归属）、一条内容进了检索面之后谁能查回来（第 17 篇的检索面归属）、一份从别处来的内容被判成了什么类型（第 18 篇的类型判定归属）。本文回答系列里的第九类，也是前八篇里每一份台账都会引用、却从未被正面拆解的那一格：**一帧画面到底有没有离开这台设备、由哪条通道离开、这一格在哪些面上读得回、能对外说到哪一层。**

这句话拆开是三个问句，而且三个问句的判定权分属三方：**谁授权了这一帧被取走**（同意对话框由框架呈现、`B/apple-platform-security-guide.txt:4241` 明写它在录制开始前出现且每个 App 进程一次；镜像的两种选择在 `B/apple-platform-security-guide.txt:1438—1439` 由 Mac 侧 Secure Enclave 执行——授权权在用户与硬件手里）；**这一帧走哪条路离开、离开后落到哪儿**（影片写入只有 ReplayKit 子系统可访问的目录 `B/apple-platform-security-guide.txt:4244`、广播经 `com.apple.broadcast-services` 端点交扩展 `B/apple-platform-security-guide.txt:4249`、镜像在 iPhone 保持锁定的前提下被 Mac 远用 `B/apple-platform-security-guide.txt:1428—1429`、投屏与伴生显示走 AirPlay／CarPlay 的 MFi-SAP `B/apple-platform-security-guide.txt:1374`——通道权在框架与系统进程手里）；**这一格谁能对外说**（锁屏持久通知 `B/apple-platform-security-guide.txt:1429`、macOS 权限清单里的 Screen recording 一类 `B/apple-platform-security-guide.txt:2262`、管理面 13 个画面语义键 `C/readings-19.txt:92`、公告组件名四处——观测权分散，且四处互不通气）。

本文的核心结论是这三件**两两都不闭合**，而且不闭合的方向与第 18 篇正好相反：18 篇的声明权在内容生产者手里、判定权在框架手里；本篇最要紧的一格是**登记方对自己那条通道恰恰是最没有读数的**。同一节里存在两条方向相反的公开口径：`B/apple-platform-security-guide.txt:4242` 明写采集在 ReplayKit 守护进程 replayd 的进程之外发生、录下来的内容对 App 进程永不可见，`B/apple-platform-security-guide.txt:4243` 又明写 in-app 通道允许 App 取得 video 与 sample buffers、由权限对话框守护。两条都成立，差别只在走的是哪一条。所以本篇把「指名走的是这两条里的哪一条」做成一条**独立核对项**（脚本一的 C01 正是拦这一格），而不把「谁取走了画面」当作可以顺推的结论。

比这更要紧的是一条**列间错位读数**。画面外流六个组件名在 1,266 行公告里逐字命中 **40 行、13 个去重 CVE、6 个组件**（`C/readings-19.txt:8—10`），其中 `ReplayKit` 只有 1 行（`C/readings-19.txt:13`）；平台分布是 **macOS 31 行、iOS 4 行、其余平台 5 行**（`C/readings-19.txt:27—28`）。impact 列的 14 个画面语义词形里，`record`／`recording`／`captur`／`display`／`mirror`／`screenshot`／`broadcast`／`airplay`／`replaykit`／`iosurface` **十个词形全部命中 0 行**，有命中的只有 `screen` 13 行、`peer` 6 行、`vnc` 6 行、`keystroke` 3 行（`C/readings-19.txt:31—44`）；含 `maliciously crafted` 的 467 行里同时出现画面语义词的 **0 行**（`C/readings-19.txt:56`），crafted 行里组件名含 `screen` 的 **0 个**（`C/readings-19.txt:57`）。唯一一句直接写「看见画面」的影响句是 `CVE-2026-112480`「A user with screen sharing access may be able to view another user's screen」（`C/readings-19.txt:63`）。也就是说：公告的**组件列**写了 screen，**影响句列**几乎从不写画面被带走；按任一列筛选出流缺陷都会漏。这是本文的中心事实，也是第 22 章脚本二里 R 族与 X 族信号码的设计根据。

还有一条必须前置的**时点约束**：本层公开读数里没有任何一句把「画面离开设备」写成不需要用户动作。平台安全指南里免交互措辞只有 2 行且都属别处（`C/readings-19.txt:160—162`）；公告 impact 列含 `without user interaction`／`without user consent` 的 10 行、含 `without user permission` 的 8 行（`C/readings-19.txt:163—164`），按组件是 CoreMedia 5、WindowServer 3、AccessorySetupKit 2（`C/readings-19.txt:165`），落在画面外流子集内的只有 3 行、同一个 `CVE-2026-112575`，三行全是 macOS 平台行（`C/readings-19.txt:166—169`）。因此本文对出流发生时点的表述一律收敛为「**录制／镜像／投屏这三类会话建立之后**」或「**打开／预览／分享这三类动作之后**」，不写任何免交互判定。

全文有十三组可数的公开读数（第 16 章，R01—R36，每组给归档行锚）、两套四档判定模型（第 19 章）、十一层归属分解（第 4—14 章）、一个十一层 × 责任方 × 三件 × 证据的归属矩阵（第 15 章），以及两个完全离线、只读、不联网、不接触任何设备或任何被登记对象的核验脚本：画面外流台账逐字段审查器（490 行，71 个信号码 + 4 档判定）与画面外流三件差集与公告子词表比对器（614 行，64 个码 = 60 个信号码 + 4 级闭合）。**合计 139 个码全部由真实夹具触发**，33 次实跑（脚本一 18 次 2,444 行、脚本二 15 次 4,157 行）的逐码可达性见第 23 章；两支脚本的只读性质由第 23.1 节的二十段实证（P1—P20，临时目录前缀分别是 `scr19.` 与 `sct19.`）逐条给出位置。

---

## 目录

1. [引言](#1-引言)
2. [视角声明与本文边界](#2-视角声明与本文边界)
3. [三套词表：接口面口径、系统口径与管理面公告回查口径，以及八处换算失败](#3-三套词表接口面口径系统口径与管理面公告回查口径以及八处换算失败)
4. [L1 会话与画面来源面标识层](#4-l1-会话与画面来源面标识层)
5. [L2 授权与同意层](#5-l2-授权与同意层)
6. [L3 通道件层：九条出流路径与三种缓冲形态](#6-l3-通道件层九条出流路径与三种缓冲形态)
7. [L4 执行域与隔离层](#7-l4-执行域与隔离层)
8. [L5 落点与存储层](#8-l5-落点与存储层)
9. [L6 观测平面层：这一格由哪个面读回来](#9-l6-观测平面层这一格由哪个面读回来)
10. [L7 告知层：锁屏持久通知、会话结束横幅与来源披露](#10-l7-告知层锁屏持久通知会话结束横幅与来源披露)
11. [L8 复位与再核对层：三个停止口、丢弃与残件声明](#11-l8-复位与再核对层三个停止口丢弃与残件声明)
12. [L9 管理面回查层：210 个纯键名分母与 13 个画面语义键](#12-l9-管理面回查层210-个纯键名分母与-13-个画面语义键)
13. [L10 公告对齐层：40 行子集、列间错位与平台行标注](#13-l10-公告对齐层40-行子集列间错位与平台行标注)
14. [L11 引用与结论层：doc.* 与唯一的拒收空间 sec.*](#14-l11-引用与结论层doc-与唯一的拒收空间-sec)
15. [归属矩阵：十一层 × 责任方 × 三件 × 证据](#15-归属矩阵十一层--责任方--三件--证据)
16. [公开读数：这条通路上能数出来的十三组事实](#16-公开读数这条通路上能数出来的十三组事实)
17. [可见性边界：这一层读者能拿到什么](#17-可见性边界这一层读者能拿到什么)
18. [五个读数面：接口侧、系统口径侧、告知侧、管理侧、公告侧](#18-五个读数面接口侧系统口径侧告知侧管理侧公告侧)
19. [两套判定模型：J1—J4 与 Q1—Q4](#19-两套判定模型j1j4-与-q1q4)
20. [运营指标 O1—O10](#20-运营指标-o1o10)
21. [只读核验脚本一：画面外流台账逐字段审查器](#21-只读核验脚本一画面外流台账逐字段审查器)
22. [只读核验脚本二：画面外流三件差集与公告子词表比对器](#22-只读核验脚本二画面外流三件差集与公告子词表比对器)
23. [三十三次实跑与全量信号覆盖验收](#23-三十三次实跑与全量信号覆盖验收)
24. [十二个误区](#24-十二个误区)
25. [常见问题](#25-常见问题)
26. [未公开文档化边界清单](#26-未公开文档化边界清单)
27. [结论](#27-结论)
28. [参考资料](#28-参考资料)

---

## 1. 引言

### 1.1 三个问句与三段判定权

本文主键：**一次画面外流会话上「谁授权—走哪条通道—哪一面读得回」的三段归属**。它和系列里任何一篇都不重合，因为它要求三格独立判定，而每格分别属于不同篇目：

| 问句 | 谁持有判定权 | 落在本文哪一层 | 系列里的最近邻（但不重合） |
| --- | --- | --- | --- |
| 这一帧凭什么被取走 | 用户与硬件（`consent.*`）+ 框架呈现的同意对话框 | L1 会话与来源面标识、L2 授权与同意 | 08 篇的用途声明与隐私键（画面外流没有对应的申报面，同意对话框由框架直接呈现）、02 篇的访问控制（谁能进这一格与这一格被不被取走是两次判定） |
| 由哪条通道离开、离开后落到哪儿 | 框架与系统进程（`chan.*` + `dom.*` + `land.*`） | L3 通道件、L4 执行域、L5 落点 | 15 篇的通道存在性（本篇只登记画面走的九条出流路径之一，不重建隧道装配）、06 篇的 XPC 端点（`com.apple.broadcast-services` 在 06 是服务面，在本篇只是通道件的一格）、16 篇的局域网可达性 |
| 这一格在哪些面上读得回、能对外说到哪一层 | 锁屏通知／macOS 权限清单／管理面键／公告组件四处，互不通气 | L6 观测、L7 告知、L8 复位、L9 管理、L10 公告、L11 引用 | 07 篇的通知呈现层（提示出现过与画面流出去过是两格）、13 篇的证据链（本篇只登记报告标识，不采集日志）、09 篇的补丁传导（那是版本覆盖，本篇是出流归属） |

三个问句合起来构成第 19 章的两套四档判定模型：脚本一的 J1—J4 回答「这一条能不能进入对外归属表述」，脚本二的 Q1—Q4 回答「三件对完之后，归属还能不能立起来」。

### 1.2 为什么必须单独拆出一篇：三个可数的理由

**第一，三段判定权互不引用，而且分散在十二个字段命名空间里。** `A/replaykit.txt:5` 那句框架句把「录下来」与「发出去」写在同一句里（Record or stream video from the screen, and audio from the app and microphone 是同一份能力的另一句口径，见 `A/replaykit.txt:71` 的 macOS 表述）；`A/replaykit_rpscreenrecorder.txt:13` 又给出「Only one app at a time can use the recorder on the user’s device.」——并发上限、预览面与分享面全在接口文档里，而落点、告知与执行域三条全在平台安全指南里（`B/apple-platform-security-guide.txt:4244`、`:4241`、`:4242`）。公开文档没有任何一句把这三段接起来。本篇因此把十二格必备字段（`id.session_kind`、`id.source_face`、`consent.granted_by`、`chan.egress_path`、`chan.process_owner`、`dom.domain_class`、`land.destination`、`obs.plane`、`notice.prompt_shown`、`undo.reset_method`、`mgmt.mdm_configurable`、`doc.source`）分属十二个命名空间逐格登记，缺任一按脚本一的 S09 记并落 J4。

**第二，同一层里有两条方向相反的公开通道，混用必然得出假结论。** `B/apple-platform-security-guide.txt:4242` 说采集在 replayd 的进程之外发生、录下来的内容对 App 进程永不可见；`B/apple-platform-security-guide.txt:4243` 说 in-app 采集允许 App 拿到 video 与 sample buffers；`B/apple-platform-security-guide.txt:4250` 再说宿主 App 对广播出去的音视频内容没有特权、只有 ReplayKit 与第三方广播扩展有访问权。三句同真，所指却是三条不同通道。这正是必须单拆一篇的理由：第 03 篇的抓包审计与第 15 篇的通道讨论都没有这一格「同层反向口径」，任何一篇都不接管它。脚本一的 C01／C03／C04 与脚本二的 S09 全部围绕这条设计——通道件必须指名走的是哪一条，不能写成「App 录了屏」这种含糊句。

**第三，这一格在公开口径里说不出后果，而看起来管这一格的管理面键有五分之二是同词不同义。** impact 列的 14 个画面词形里 10 个命中 0（`C/readings-19.txt:31—44`），crafted 与画面语义词交集 0（`C/readings-19.txt:56、:57`）；KEV 95 条 Apple 条目里描述含画面语义词的只有 2 条（`C/readings-19.txt:82—85`），没有任何一条把「画面外流」写成在野利用后果。管理面 220 行清单里形态命中 218、纯键名分母 210（`C/readings-19.txt:88—91`），画面语义词命中 13 个键（`C/readings-19.txt:92`，清单 `C/readings-19.txt:95—107`），其中 `allowAutomaticScreenSaver`、`allowCallRecording`、`allowLockScreenControlCenter`、`allowLockScreenNotificationsView`、`allowLockScreenTodayView` 命中的是词形、管的不是画面出流（`C/readings-19.txt:96—100`）。所以本篇的归属表述只能停在「哪一次会话在哪一格被取出、由哪条路径离开、由哪个面读回」，不能停在「这一帧泄露导致了什么」——后者在公开档案里没有对应句式。这正是脚本一的 G01／G02、R01／R04 与 X01 信号码的落点。

### 1.3 本文不做什么

本文是归属与口径分析，不是操作手册。以下内容明确不做，且第 21、22 章两支脚本在设计上不可用于这些目的：

- **只写防御性归属分析**。不含恶意文件构造、不含格式畸形化、不含解析缺陷定位、不含崩溃复现与载荷投递的做法；不给任何缺陷位置、内存布局或利用链时序。
- **不指导关闭或欺骗采集提示**，**不利用 `forceBypassScreenCaptureAlert`**——它只作为管理面读数的一格登记其存在形态（脚本二 K05 的判据正是这一条：绕过采集提示的键不作为采集件或落点件的归属依据）；**不给**任何绕过隔离标记、告知流程或管理面审计的做法。
- **不提供任何免交互触发路径**。依据是 R32—R36：本层公开读数里没有任何一句把「画面离开设备」写成不需要用户动作。全文对出流时点只允许写成「打开／预览／分享这三类动作之后」或「录制／镜像／投屏这三类会话建立之后」。
- **两支脚本一律离线只读**：只处理台账文本与公开词表，**不调用** `file`／`mdls`／`mdimport`／`mdutil`／`mdfind`／`spctl`／`codesign`／`defaults`／`log`／`sysctl`／`xcrun`／`profiles`／`plutil`／`sips`／`qlmanage`／`otool` 等任何命令行工具——这些名字在两支脚本里只出现在头部拒收声明与 K02 拒收正则两处（第 23.1 节 P4／P14 给出位置），不碰设备、不联网、不打开任何被登记的对象；唯一写出目标是 `mktemp -d` 临时目录且实现不向其写入。
- **台账一律拒收**：真实用户检索词、可还原身份的语音描述、真实联系人／健康／位置样本、形似共享密钥或口令的取值（`glpat-`／`ghp_`／`AKIA`／`Bearer `／`-----BEGIN`）、设备绝对路径、整段文件正文、超长度阈值载荷。全部夹具为合成标识与合成取值；这一条由脚本一的 K01—K03 与脚本二的 S01—S10／K 族实现为阻断信号，不是写在正文里的承诺。
- **公告侧读数一律标注平台行**，不得写成 iOS 侧结论（子集 macOS 31 行、iOS 4 行，`C/readings-19.txt:27—28`）。
- **不声称做了设备实测，也不代替厂商口径**。本文能保证的是判定过程可离线复算，不能保证登记内容与某台真实设备一致；凡是只有厂商承诺、没有公开文档支撑的判断，一律落在第 26 章的未公开文档化边界清单里，不进结论。

---

## 2. 视角声明与本文边界

系列里任何一篇在开篇都必须回答「这件事第 X 篇不是已经写过了吗」。本节逐条回答，并把边界写成可检查的句子——每一行的「不重复部分」都能在对应篇目里找到原句位置。三处硬分界各开一节，其余篇目列一张表。

### 2.1 与第 16 篇的分界（局域网可达性 ↔ 画面可见性）

第 16 篇判的是「**谁能在局域网上看见这台设备**」，本篇判的是「**这台设备的画面有没有被别人看见**」。两句话主语相同、宾语不同，判定对象也不同：16 篇的客体是一个可被发现的服务，本篇的客体是一次已经建立的出流会话。

**分界在两处。** 其一是 `allowAirPlayIncomingRequests`：它在 16 篇属于「这台设备愿不愿意被局域网发现」那一格，在本篇属于「入站 AirPlay 请求能否被策略关掉」那一格（`B/mdm-restrictions.txt:29` 的说明句 `the system disables incoming AirPlay requests.`），同一个键在两篇分属两个平面，交接只在本节，本篇不复用 16 篇的权限件模型。其二是 16 篇在第 2641 行的 FAQ 里明确把「能不能评价某个具体投屏协议栈」否定掉并把这一格留给后续——本篇接管这一格，但仍然只做归属、不做协议栈有效性评测。

用词普查支持这条分界：`AirPlay` 在 01—18 全部正文里命中 17 次（09 篇 4、10 篇 1、12 篇 2、15 篇 1、16 篇 6、18 篇 3），**全部作为局域网可达性与发现面的例举出现，没有一篇讨论它带走画面**。同理，`投屏` 只出现 1 次，`镜像` 的 93 处逐处回查为 Mach-O 镜像／仓库镜像／内存镜像三义，无一处指 iPhone Mirroring。因此本篇对这九条出流路径的命名不与任何既有篇目冲突。

### 2.2 与第 07 篇的分界（锁屏录制提示已被 07 篇取走）

锁屏「正在录制」提示可被消除这一格，公开口径落在 `CVE-2025-30438`，组件行是 Share Sheet，**已被第 07 篇取走**（07 篇 §16.5 第 1094 行）：07 篇用它论证「四张页同义不同组件」，并给出该条的修复口径。**本篇不重述这条 CVE 的修复过程、不重述其通知呈现层归属（07 篇第 762、778 行），只在视角声明处回链。**

分界句是一句可以检查的命题：**提示出现过，与画面流出去过，是两格。** 前者是告知面能不能读回的一格（`B/apple-platform-security-guide.txt:4241` 说录制开始前呈现同意对话框，`B/apple-platform-security-guide.txt:1429` 说被 Mac 远用期间 iPhone 锁屏上有一条持续通知）；后者是通道件与落点件的两格。本篇判后者，并把前者仅当作「告知面可读回」的样例登记在 L7。反过来，告知面读不回也不能反推画面没被带走：`B/mdm-restrictions.txt:1018` 明写受管理课程里的学生 `automatically gives permission … without prompting the student`——提示这一格可以被管理面替用户省掉，本篇只陈述这一句的公开口径，不给任何利用方式。

另有一条同词不同义必须划清：`broadcast` 在 01—18 正文里命中 40 次，其中 07 篇 17 次是推送广播语义、16 篇 23 次是局域网广播协议语义，都与 ReplayKit 的 broadcast extension 不是一回事。本篇凡写「广播」都限定为 `live_broadcast` 会话类（会话标识前缀 `BCA_`）。

### 2.3 与第 18 篇的分界（三件的第二件在两篇含义不同）

第 18 篇处理「一份从别处来的字节被判成了什么类型、由哪条通道读回来解析」，与本篇共用三件法这一**方法**，但第二件换了轴：18 篇的通道件问「解析器能否把类型读回来」，本篇的通道件问「画面能否被带走」。这是 16、17、18 之后第四处需要重新定义对象类与核对项的替换——本篇的 11 类会话（`REC_ movie_recording`、`BCA_ live_broadcast`、`MIR_ mirroring`、`CMP_ companion_display`、`AIR_ airplay_video`、`RMO_ remote_observation`、`SCN_ system_screenshot`、`SCK_ scscreen_capture`、`SVC_ system_service`，另加 `NA_ not_recorded`、`UNK_ unknown` 两个兜底类）与 20 项核对项（采集件 7 项／落点件 5 项／告知件 8 项）全部重列于第 22 章，不复用前两篇或 18 篇的任何信号码。

两篇之间还有一条可交叉引用的负读数：同一份公告基线在 18 篇里算出「`maliciously crafted` 与画面语义词交集 = 0」，本篇把它读作 **内容侧口径与出流侧口径互不相通**（`C/readings-19.txt:56`；同一条在 18 篇写作 crafted∩画面词 0）。18 篇 `screenshot` 一词的 10 处全在类型判定语境里，本篇的 `still_capture` 是出流路径的一格，两者不同形。第 03 篇第 2882、3284 行把「防截屏／防录屏」当作抓包审计里的一个待测项列出，不给归属判定——本篇不接这一格的有效性评测。

### 2.4 与其余各篇的分界

| 篇 | 它已经写过 | 本文不重复 | 本文独占 |
| --- | --- | --- | --- |
| 01 入口 | 消息附件自动解析与渲染预览（01 第 50、169 行） | 不论证入口、不重建攻击链时序 | 画面外流与消息内容无关：一帧画面被录走时不需要任何附件 |
| 02 访问控制／04 认证通道加密／09 更新链／10 设备归属／12 供应链 | 无一处讨论画面离开设备（逐词普查见 2.1 节） | 不引用其结论 | 管理面键在本篇只表示「这一格能否被策略关掉」，不表示所有权、供应链或加密强度 |
| 05 生物识别 | Secure Enclave 相关 24 处 | 不判生物特征本体、不展开 SEP 模型 | `B/apple-platform-security-guide.txt:1439` 那句只作为**授权被硬件强制**的读数（`consent.pairing_choice` 一格） |
| 06 XPC／Mach IPC | 服务清单与「公告组件名 ↔ 设备侧表现」落差（06 第 11、13、138 行） | 不重建服务清单 | `com.apple.broadcast-services`（`B/apple-platform-security-guide.txt:4249`）与 out-of-process 预览 UI（`:4245`）在本篇只登记为通道件，其端点语义归 06 |
| 08 隐私授权 | 用途串、隐私清单与 required reason 全模型 | 不新增授权申报面 | 同意对话框由框架呈现（`:4241`）、不经用途声明，因此不能用「申报了」推「能出流」 |
| 11 备份与副本 | 副本在谁手上、可不可解 | 不谈副本与密钥轮换 | 录影产物落在「只有 ReplayKit 子系统可访问、任何 App 都不可访问」的目录（`:4244`）——它既不是副本也不是可导出对象，这一格本篇独占 |
| 13 证据链 | 采集时刻—导出时序（13 第 370 行） | 不采集日志、不定义留存与同意口径 | 会话结束横幅与锁屏通知在本篇只登记为观测件与告知件；崩溃面只允许报告标识（脚本一 K03） |
| 14 签名与分发授权 | 描述文件、公证与运行授权 | 不谈代码运行授权 | 广播扩展要挂端点配置才参与（`:4249`）是**通道准入**，不是运行授权；两格在台账里分列 |
| 15 网络扩展与 VPN | 通道词形在去重组件名里全部命中 0 的词形差集法（15 第 21、201 行） | 不建立「通道类 ↔ 组件名」映射 | 方法同源而尺子不同：本篇换成画面语义词表，实测 14 个词形里 10 个命中 0（`C/readings-19.txt:31—44`） |
| 17 聚焦索引与 Siri 建议 | 检索面可查询性与标识形态双检 | 不讨论索引写入与删除可证性 | 帧内容不进检索面：`Siri` 组件那 1 行含 screen 的公告（`C/readings-19.txt:51`）说的是屏上文本，不是画面流 |

相邻但**排除**的四个平面：XPC 端点实现（归 06）、局域网可达性（归 16）、内容类型判定（归 18）、留存与同意记录（归 13）。本篇只在台账里登记它们的标识格，不引用其结论。

### 2.5 三件法与本文的可证性边界

本文的可证边界由一句文档事实决定：**一帧画面被带走之后，没有任何公开接口能把「这一次带走了什么」读回来。** `B/apple-platform-security-guide.txt:4242` 那句「录下来的内容对 App 进程永不可见」在方法学上是个正面结论：登记方最没有读数的那一格，恰恰是最需要归属的那一格。因此本篇所有关于「这一帧到底有没有离开」的表述，只能写成三种形态之一：

1. **接口口径**——某 API 的公开说明写了它给谁、给到什么形态（`A/replaykit_rpscreenrecorder.txt:12`、`:13`；`A/replaykit_rpbroadcastsamplehandler.txt:12` 说缓冲对象由框架交给扩展；`A/replaykit_rpbroadcastconfiguration.txt:3` 说直播同时另产影片件）。
2. **系统口径**——平台安全指南逐格写了机制归谁（`B/apple-platform-security-guide.txt:4241`—`4257` 的 ReplayKit 全节十三格、`1428`—`1439` 的 iPhone Mirroring 六条要点、`:1374` 的 AirPlay 与 MFi-SAP、`:708` 的相机指示灯硬件级设计、`:4157` 的 HomeKit 帧由独立系统进程渲染且不允许截屏）。
3. **回查口径**——公告、KEV、管理面这三份公开登记里这一格写了什么（`C/readings-19.txt:8—16` 的子集六组件读数、`:82—85` 的 KEV 两条、`:92` 的 13 个画面语义键）。

**没有第四种。** 本文不允许任何「实测发现这一帧被某条通道带走」的表述，因为那需要在设备上开启会话并读取采集面，属于本篇红线。这条边界带来一处必须写清的负面结论：**「这一帧确实被带走」在本篇不能表达为实测，只能表达为「三件对齐 + 平面可得性 + 引用落回归档行号」这一间接三段**——采集件七项有读数、落点件五项有读数、告知件八项有读数，三件差集为空，且每个取值都落在第 4 节那张 11 类 × 20 项的能力表所声明的可得性档位内。第 6、9、19 章与脚本一的 C／E／O／N 族、脚本二的 T 族与 V 族全部围绕这条边界设计。

---

## 3. 三套词表：接口面口径、系统口径与管理面公告回查口径，以及八处换算失败

三套词表各说各话，是这一层最容易产生假结论的原因。本节先把三套词表各自的取值列清楚（取值一律取两支脚本 usage 段逐字列出的枚举，不取正文的自由描述），再逐条给出八处**换算失败**——即「从一套词表的说法推不出另一套词表的结论」的固定位置。第 21、22 章两支脚本的每一个信号码都能归到某一条失败上。

### 3.1 词表 A：接口面口径（采集件的分母）

来源是组 A 的十五条接口文档与脚本一 usage 段的十二个命名空间。可枚举取值：

| 取值集 | 字段（脚本一 usage 行号） | 出处 | 拦下它的信号码 |
| --- | --- | --- | --- |
| 会话标识前缀四类 `REC_`／`BCA_`／`MIR_`／`CMP_`；会话类十格含两个兜底 | `id.session_kind`（行 45—46） | `A/replaykit_rpscreenrecorder.txt:11`（每个 App 有自己的录制器实例）、`A/replaykit_rpsystembroadcastpickerview.txt:11` | 脚本一 S02／B02；脚本二 S10（前缀与会话类不符即无法回指） |
| 九条出流路径 `out_of_process_capture`／`in_app_sample_buffer`／`broadcast_upload`／`mirroring_local`／`airplay_stream`／`carplay_template_stream`／`external_display_stream`／`classroom_observation`／`still_capture` | `chan.egress_path`（行 62—64） | `B/apple-platform-security-guide.txt:4242`、`:4243`、`:4257`、`:1428—1429`、`:1374`、`A/carplay.txt:5`、`A/uikit_uiwindow.txt:18`、`B/mdm-restrictions.txt:726`、`:3261` | 脚本一 C01（通道件必须指名走的是这两条中的哪一条）；脚本二 S09 |
| 缓冲形态五格 `raw_unencoded`／`serialized`／`encoded_clip`／`movie_file`／`frame_set` | `chan.buffer_form`（行 65） | `B/apple-platform-security-guide.txt:4257`（逐字只给 raw unencoded 与 serialized 两格）、`:4244`（影片件） | 脚本一 C05；脚本二 S05（一格要么有读数要么明确没有） |
| 进程归属四格 `app_process`／`replayd`／`system_service`／`extension_process` | `chan.process_owner`（行 66） | `B/apple-platform-security-guide.txt:4242`；进程名逐字只有全小写一种形态 | 脚本一 C02／C03／D06；脚本二 M06 |
| 接口入口两套口径（`current`／`superseded`） | `chan.api_entry` 与 `chan.entry_status`（行 67—71） | `A/replaykit_rpscreenrecorder.txt:4`、`A/replaykit_rppreviewviewcontroller.txt:4`、`A/replaykit_rpsystembroadcastpickerview.txt:4`、`A/replaykit_rpscreenrecorder_isrecording.txt:4` 四处同句 | 脚本一 C06／C07；脚本二 T05 |
| 端点形态 `com.apple.broadcast-services`／`other` | `chan.service_endpoint`（行 74） | `B/apple-platform-security-guide.txt:4249` | 脚本一 C05；脚本二 M02／X07 |
| 并发上限 `one_at_a_time`／`unlimited` | `chan.concurrent_limit`（行 77） | `A/replaykit_rpscreenrecorder.txt:13`（Only one app at a time can use the recorder） | 脚本一 C08；脚本二 D02 |
| 预览面与分享面（`in_process`／`out_of_process`／`system_vended`；`app_vended`／`system_vended`／`none`） | `chan.preview_surface`、`chan.share_surface`（行 75—76） | `B/apple-platform-security-guide.txt:4245`；`A/replaykit_rppreviewviewcontroller.txt:153`（预览面与分享面在一个枚举里二选一） | 脚本一 C09／E03；脚本二 P07 |
| 画面来源面（脚本十九格、脚本二九格） | `id.source_face`（行 50—52） | `A/replaykit_rpsystembroadcastpickerview.txt:11`（触发面是视图层级里的一个按钮）、`:13`（可钉死到单一 provider） | 脚本一 B03；脚本二 T06 |
| 外流时点 `on_start`／`on_session`／`on_share`／`on_stop`／`on_reboot`／`per_stream` | 脚本二第 10 列（usage 行 50） | `B/apple-platform-security-guide.txt:4241`（提示在前、采集在后） | 脚本二 S07；脚本一 A02 |

这套词表的特点：**每一格都是登记方在台账里选的取值，没有一格是系统在采集之后反过来写回的。** `A/uikit_uiscenesession.txt:13` 说明会话生命周期由系统持有、`:123` 给出「A unique identifier that persists for the lifetime of the session」，这是本篇主键能落到「一次会话」的唯一公开依据；`A/uikit_uiscene.txt:217` 的 `no longer onscreen` 是系统通知而不是 App 自述，同样只用于界定来源面。

### 3.2 词表 B：系统口径（执行域、落点与告知的分母）

来源是平台安全指南的四个节（ReplayKit 4237—4257、iPhone Mirroring 1428—1439、AirPlay 与 CarPlay 1374、权限与指示 708／2262／3261／3575／4157）。逐格取值与归属：

| 系统口径 | 出处 | 对应词表 A 的哪一格 | 拦下它的信号码 |
| --- | --- | --- | --- |
| 同意对话框在录制开始前呈现，且每个 App 进程一次 | `B/apple-platform-security-guide.txt:4241` | `consent.alert_shown`／`consent.alert_scope` | 脚本一 A02／A03；脚本二 D02 |
| 采集在 replayd 的进程之外发生，内容对 App 进程永不可见 | `:4242` | `chan.process_owner`／`chan.host_has_access` | 脚本一 C02／C03；脚本二 K03 |
| in-app 采集允许 App 取得 video 与 sample buffers，由权限对话框守护 | `:4243` | 同上两格的另一条取值 | 脚本一 C04／N01；脚本二 S09 |
| 影片写入只有 ReplayKit 子系统可访问的目录 | `:4244` | `land.destination`／`land.write_scope` | 脚本一 E01／E02；脚本二 M05 |
| 预览与分享 UI 由 ReplayKit 提供、out-of-process | `:4245` | `chan.preview_surface`／`share_surface` | 脚本一 C09；脚本二 D01 |
| 第三方服务要建两个扩展、挂 `com.apple.broadcast-services` 端点 | `:4249` | `chan.extension_count`／`service_endpoint` | 脚本一 C05；脚本二 T08 |
| 宿主 App 对广播的音视频没有特权，只有 ReplayKit 与第三方广播扩展有访问权 | `:4250` | `chan.host_has_access`（`never_accessible`） | 脚本一 D01；脚本二 K03／T02 |
| 上传扩展处理 raw unencoded sample buffers，数据被 serialized | `:4257` | `chan.buffer_form` | 脚本一 C05；脚本二 S05 |
| iPhone 保持锁定，锁屏面上有一条持续通知 | `:1428—1429` | `notice.lockscreen_visible`／`banner_kind` | 脚本一 N02／O01 |
| 同一 Apple Account 的设备用本地点对点协议交换密码学身份 | `:1431` | `consent.granted_by`／`dom.transport` | 脚本一 D02；脚本二 T04 |
| 镜像的远程解锁明确不需要安全测距；两种选择在 Mac 侧由 Secure Enclave 执行 | `:1438—1439` | `consent.secure_ranging`／`pairing_choice` | 脚本一 A05／A06／N05 |
| AirPlay 用认证 IC 校验接收端；AirPlay audio 与 CarPlay video 走 MFi-SAP | `:1374` | `dom.isolation_mechanism` | 脚本一 D03；脚本二 K04 |
| AirDrop 与 AirPlay 的点对点 Wi-Fi 采用随机化 MAC 地址 | `:3901` | `dom.mac_randomized` | 脚本一 D05；脚本二 T07 |
| Tap to Pay 与 ID Verifier Display Only 被设计为禁止一切截图与录屏取走屏上信息 | `:3261`、`:3575` | `still_capture`／`external_display_stream` 的公开例外格 | 脚本二 D03 |

这套词表的特点：**每一格只说机制归谁，不说这一次会话的结果。** 平台安全指南逐格列出的是通道与执行域（广播期的采集与影片录制完全一致这一条写在 `:4248`，广播选择器用私有 API 实现写在 `:4256`，两者都只用于说明格数而非结论），没有任何一句写「这次采集带走了哪一帧」；`A/quartzcore_calayer_contents.txt:23—24` 说明画面内容落在一块可被直接给出的对象上、视图会替换它，`A/avkit.txt:37` 给出方向相反的通道（把 nearby iPhone 当摄像头），`A/homekit` 一侧的视频帧由独立系统进程渲染且不允许截屏（`B/apple-platform-security-guide.txt:4157`）——三者都只用来划边界。

### 3.3 词表 C：管理面与公告回查口径（观测件与对外表述的分母）

| 词形 | 出处 | 含义 |
| --- | --- | --- |
| 220 行清单、形态命中 218、纯键名分母 210 | `C/readings-19.txt:88—91`；`B/mdm-restriction-keys.txt:1—4` 四行是分段标题、不是键 | 管理面唯一能表达的东西：允许或不允许；分母口径与第 18 篇一致，两篇可交叉引用而不换算 |
| 画面语义词命中 13 个键（`allow*` 9、`force*` 4） | `C/readings-19.txt:92—93`，逐键清单 `C/readings-19.txt:95—107` | 真正约束出流的只有 `allowScreenShot`、`allowRemoteScreenObservation`、`allowiPhoneMirroring`、`allowAirPlayIncomingRequests`、两条 AirPlay 配对口令键、`forceClassroomUnpromptedScreenObservation` 与 `forceBypassScreenCaptureAlert` |
| 其中 5 键是同词不同义 | `C/readings-19.txt:96—100`（屏保／通话录音／锁屏控件三面） | 命中词形不等于管画面：`mgmt.word_family` 的 `lockscreen_surface`／`screensaver`／`call_recording` 三档由此设出 |
| `forceBypassScreenCaptureAlert` 只登记存在形态 | `C/readings-19.txt:106` | 「策略可以改变同意对话框是否出现」这一格的证据；本篇不指导如何使用或规避它 |
| 说明句流与 `CODE\|` 流分属两个流 | `B/mdm-restrictions.txt:29`、`:726`、`:729`、`:766`、`:965`、`:969`、`:1018`；`CODE\|` 形态 299 行（`C/readings-19.txt:121`）、说明句命中画面语义词 9 行（`C/readings-19.txt:111`，逐行 `:112—120`） | 管理面自身的错位：说明句回溯不到键名。这是脚本二 X 族与 P06 的判据来源 |
| 公告六列、1,266 条组件×CVE 对 | `C/readings-19.txt:2—5`（330 去重 CVE、129 去重组件、12 平台版本行）；`C/advisory-19.tsv` 表头 `file`／`platform`／`component`／`cve`／`impact`／`avail` | 存在性读数的载体，且两列互不校验 |
| 画面外流子集 40 行、13 CVE、6 组件；macOS 31 行、iOS 4 行、其余 5 行 | `C/readings-19.txt:8—10`、逐组件 `:11—16`、平台分布 `:27—28` | 本篇所有公告侧读数一律标注平台行，不写成 iOS 侧结论 |
| impact 含 `screen` 的 13 行分布在 4 个组件 | `C/readings-19.txt:48—52`（`Screen Sharing Server` 6、`Remote Management` 3、`smbx` 3、`Siri` 1） | 组件名含 screen 不等于影响句讲画面 |
| 匹配形态必须随读数写出 | `C/readings-19.txt:45`（原样大写 `VNC` = 6；整列小写化后仍用大写模式 = 0，是一条假读数；小写化＋小写模式 = 6） | 脚本一 R05 专门拦「把假读数抄进台账」 |
| 单 CVE 在子集里最大跨平台行数 8 | `C/readings-19.txt:79` | 同一 CVE 在多平台行重复计数，是 X 族要求按「组件×CVE 对」而非行数计量的理由 |
| KEV Apple 条目 95、描述含画面语义词 2 条 | `C/readings-19.txt:82—85`（`CVE-2026-65400` macOS improper authentication、`CVE-2023-28206` iOS/iPadOS/macOS 的 IOSurfaceAccelerator 越界写） | KEV 没有一条把画面外流写在野利用后果里，这是本篇第二条口径警告 |
| 免交互措辞的全部落点 | `C/readings-19.txt:160—169`（PSG 2 行且属别处；公告 `without user interaction`／`consent` 10 行、`without user permission` 8 行；子集内 3 行同一个 `CVE-2026-112575`，全为 macOS 平台行） | 出流时点的写法约束由此实证；影响句逐字为 `An app may be able to monitor keystrokes without user permission` |

### 3.4 八处换算失败

这八条是本文的负面骨架。每条都写成「A 词表的这一句**推不出** B 词表的那一句」，并在句末标明它由脚本一或脚本二的哪个信号码拦下（码的判据文案取自两支脚本 usage 段与 `DOC["…"]` 赋值，逐字可回查）。

**失败 1：框架句写了「用户可以录屏并分享」→ 该 App 进程拿到了这一帧。** `A/replaykit.txt:5` 把录与发写在同一句，`A/replaykit_rpscreenrecorder.txt:12` 说 App 可以录制应用内的音视频并加麦克风解说；但 `B/apple-platform-security-guide.txt:4242` 明写内容对 App 进程永不可见，`:4250` 明写宿主 App 对广播内容没有特权。登记主体与采集主体不是同一个进程，两句之间没有换算关系。拦下：脚本一 C01／C03／C04，脚本二 S09／K03。

**失败 2：同意提示呈现过 → 提示的粒度就是会话的粒度。** `B/apple-platform-security-guide.txt:4241` 的公开口径只给「每个 App 进程一次」；`consent.alert_scope` 枚举里的 `per_session`／`per_device`／`per_stream` 全是登记方自行加严或放宽。顺序也不可颠倒：提示在前、采集在后。拦下：脚本一 A02／A03，脚本二 D02。

**失败 3：这一帧被录下来了 → 落点已定、复位已完成。** `A/replaykit_rpscreenrecorder.txt:240`、`:251`、`:267` 三个停止口里只有第三个在签名里出现输出 URL；`A/replaykit_rpscreenrecorder.txt:88` 的 `Discards the current recording.` 是第四个独立复位口；`B/apple-platform-security-guide.txt:4244` 又说明影片目录任何 App 都不可访问。停止、丢弃、落点三格彼此独立。拦下：脚本一 E01／E02／V01／V02／V04，脚本二 M05／P04。

**失败 4：广播走通了 → 承载方与特权如登记所述。** `B/apple-platform-security-guide.txt:4249` 要求两个扩展挂在同一端点上，`:4248` 说广播期采集与影片录制完全一致，`:4257` 说扩展拿到的是未编码原始缓冲。扩展数量、端点、缓冲形态是三格，缺一即无法回指；而 `A/replaykit_rpbroadcastconfiguration.txt:3` 说明直播还另产影片件，不能把广播会话的落点抄成 `none`。拦下：脚本一 C05／D01／E05，脚本二 C05／S08／T08。

**失败 5：某个平面读得回这一格 → 这一格与另一个平面同轴。** `B/apple-platform-security-guide.txt:1429` 的锁屏通知读不出执行域；`A/carplay_cpinterfacecontroller.txt:26` 说界面特征取自车机主屏，车机模板读不出 App 内提示；`A/uikit_uiwindow.txt:18` 说额外窗口通常用于在外屏显示内容，外屏面与本机面是两个平面；`B/apple-platform-security-guide.txt:2262` 的 macOS 权限状态给出的是「允许与否」，不给出画面落到哪儿。四类机制的采集入口各有其承载面，跨面读数不能互抄。拦下：脚本一 O01／O02／O03／D06，脚本二 P01／P02／P05／P07。

**失败 6：来源是截屏或厂商说法 → 它可以充当机制依据。** `obs.plane` 与 `dom.domain_source`、`notice.warning_text_source` 三个字段都允许 `vendor_claim`、`screenshot`、`assumed` 作为**存在性**取值，但都不允许它们作为**判定依据**：一次界面读数只能证明那一天这一面显示过什么。`A/replaykit_rpsystembroadcastpickerview.txt:12`（Mac Catalyst 下点击该按钮无效果）就是典型一例——某一形态下读不回，不等于机制不存在。拦下：脚本一 D04／N03／K03，脚本二 V03。

**失败 7：管理面命中画面语义词的键有 13 个 → 13 个键都约束画面出流。** `C/readings-19.txt:92` 的 13 个键里有 5 个是同词不同义（`C/readings-19.txt:96—100`）；`B/mdm-restrictions.txt:766` 那个键一次关掉三类出流；`B/mdm-restrictions.txt:726` 要求把子约束键嵌在指定 payload 下；`B/mdm-restrictions.txt:1018` 说明管理面可以替用户给出「不被提示」的同意。关掉承载通道与给出同意是两格，命中词形与管出流是两格。拦下：脚本一 G01／G02／G03／G05，脚本二 M03／X04／K05／P06。

**失败 8：口径之间可以互相换算 → 结论可以写成一句而不必回指。** 公告组件列写 screen 而 impact 列几乎不写画面（`C/readings-19.txt:48—52`、`:56`、`:57`）；`C/readings-19.txt:27—28` 的平台分布使任何跨平台结论都必须标注平台行；`C/readings-19.txt:45` 使每个命中数都必须标注匹配形态。三套词表之间没有任何一条公开换算句，所以任何跨套结论都必须落回「哪一次会话、哪一格、取自哪份归档的哪一行」，而**不是画面本身**——台账只登记格，不登记帧内容、不登记可还原身份的样本。字段上由 `doc.source` 与 `doc.line_ref` 两格承载：行号只写 `1234` 或 `6-9` 这一种形态，带「第／行」前缀的写法在两份台账之间不可换算。拦下：脚本一 X01／X02／R01／R03／R04／R05／R06，脚本二 X01／X02／V01／V02／K01。

八条失败的分布可以逐码核对：1→C01／C03／C04 与 S09／K03，2→A02／A03 与 D02，3→E 族与 V01／V02／V04 与 M05／P04，4→C05／D01／E05 与 C05／S08／T08，5→O 族与 D06 加 P01／P02／P05／P07，6→D04／N03／K03 与 V03，7→G 族与 M03／X04／K05／P06，8→R 族与 X01／X02 加 X 族与 V01／V02。第 23.6 节的静态反向对齐会把这八组逐条数一遍。

---

## 4. L1 会话与画面来源面标识层

### 4.1 本层管什么

L1 只回答两件事：**这一次画面外流被登记成哪一类会话**，以及**画面在哪一格被取出**。它不判定通道（L3）、不判定执行域（L4）、也不判定落点（L5）；`id.*` 七个字段的全部作用是给后面四层提供可以互相回指的标识。

四类会话前缀与 `id.session_kind` 一一对应，逐字取自脚本一 usage 段第 19 行：`REC_` 本机录制／`BCA_` 直播广播／`MIR_` 跨设备镜像／`CMP_` 伴生与外接显示，对应 `movie_recording`／`live_broadcast`／`mirroring`／`companion_display` 四档。四档在公开口径里各有自己的支撑句：`REC_` 落在 `A/replaykit_rpscreenrecorder.txt:12` 「Your app can record the audio and video inside of the app, along with user commentary through the microphone.」；`BCA_` 落在 `B/apple-platform-security-guide.txt:4246`（`ReplayKit broadcasting` 节名）与 `:4248`；`MIR_` 落在 `B/apple-platform-security-guide.txt:1429` 「iPhone Mirroring allows a user to use their iPhone from their nearby Mac.」；`CMP_` 落在 `A/carplay.txt:5` 与 `A/uikit_uiwindow.txt:18`。

脚本一只收这四类前缀，前缀不在四类内即触发 **B01**（脚本一第 413 行）；脚本二把会话类扩到 11 档，另收 `AIR_`／`RMO_`／`SCN_`／`SCK_`／`SVC_`／`NA_`／`UNK_` 七个前缀（脚本二第 172—174 行），并在第 317 行以 **S03** 拦会话类越界、第 319 行以 **S10** 拦前缀与会话类不符。**S03 与 S10 是同一件事的两半**：前者管「这一类存不存在」，后者管「前缀说的是不是这一类」；S10 的判据文案指向 `C/readings-19.txt` 第 11—16 行（画面外流子集的六个组件名逐条登记）与第 48—51 行（`screen` 词形命中的另四个组件名），也就是说前缀越界之所以阻断，是因为它让这一行再也回指不到任何一份公开清单。本篇把这两支脚本的口径差写成一句话：**一台设备上的四类本机机制，加上七档相邻类与未建模类**。

`id.channel_word` 的 16 个词形按脚本一 usage 第 47—49 行逐字照抄：13 个机制词（`ReplayKit`／`ScreenCaptureKit`／`RPScreenRecorder`／`RPSystemBroadcastPickerView`／`broadcast_extension`／`IOSurface`／`WindowServer`／`iPhoneMirroring`／`AirPlay`／`CarPlay`／`Classroom`／`RemoteScreenObservation`／`screenshot`）加 `none` 与 `not_recorded`／`unknown` 两个未登记档。其中 `IOSurface` 与 `WindowServer` 是**系统口径的词**，它们同时是公告侧六组件子集的成员（`C/readings-19.txt` 第 11—16 行）；`ScreenCaptureKit` 与 `RPScreenRecorder` 同族并存，正是第 6.3 节换代句的来源。

`id.source_face` 是 12 档可判面（10 个实名面加 `not_applicable`／`none` 两个否定档），另加 `not_recorded`／`unknown` 两个不参与判定的未登记档，枚举合计 14 个 token，逐个给锚点：`control_center` ← `:4256`「With the broadcast picker, users initiate system broadcasts directly from their app using the same system-defined user interface that’s accessible using Control Center.」；`in_app_button` ← `A/replaykit_rpsystembroadcastpickerview.txt:11`「Add this view to your view hierarchy to let users broadcast directly from your app.」；`broadcast_picker` ← 同一行后半句「When a user taps the broadcast button, it displays a broadcast picker, allowing the user to select a broadcast provider.」；`preview_share_ui` ← `:4245` 与 `A/replaykit_rppreviewviewcontroller.txt:11`；`mirroring_app` ← `:1438`「Remote unlock for iPhone Mirroring uses the same remote unlock protocol as iPhone unlock using Apple Watch but is initiated by the user launching the iPhone Mirroring app on their paired Mac.」；`airplay_menu` ← 见 4.3 第 5 点；`carplay_template` ← `A/carplay.txt:5`；`settings_ui` ← `:2262`；`mdm_profile` ← `B/mdm-restrictions.txt:766`；`external_accessory` ← `:1373`「Verified MFi accessories can request access to different transport methods and functionality」。

`id.provenance` 与前者的区别要写明：来源面记的是**动作在哪个控件上发生**，来源记的是**这一帧的取用方是谁**。`mac_host` 与 `vehicle_display` 两档正是 `:1429` 与 `A/carplay.txt:6` 的直译；`managed_by_mdm`／`course_managed` 两档由 `B/mdm-restrictions.txt:729` 与 `:1018` 支撑，且这两档与 `control_center`、`in_app_button`、`broadcast_picker`、`preview_share_ui` 四个 App 内面互斥（B03 的判据）。

### 4.2 字段清单

| 字段名 | 取值域 | 公开出处行锚 |
| --- | --- | --- |
| `id.session_kind`（必备格） | 11 档：上述四类 + `external_display`／`remote_observation`／`still_capture`／`not_applicable`／`none`／`not_recorded`／`unknown` | `B/apple-platform-security-guide.txt:4241`、`:4246`、`:1429`；`A/carplay.txt:5` |
| `id.channel_word` | 16 词形（13 个机制词 + 3 个兜底档） | `A/replaykit.txt:5`；`B/apple-platform-security-guide.txt:4249`、`:1374`；`C/readings-19.txt` 第 11—16 行 |
| `id.source_face`（必备格） | 14 档：10 个实名面 + `not_applicable`／`none` 两个否定档 + `not_recorded`／`unknown` 两个未登记档 | `B/apple-platform-security-guide.txt:4256`、`:4245`、`:1438`、`:1373`；`A/replaykit_rpsystembroadcastpickerview.txt:11`；`A/carplay.txt:5`；`B/mdm-restrictions.txt:766` |
| `id.provenance` | 10 档 | `B/apple-platform-security-guide.txt:4256`（`initiated_by_user`）、`:1429`（`mac_host`）、`:1374`（`external_receiver`）；`A/carplay.txt:6`（`vehicle_display`） |
| `id.bundle_id` | 点分段标识，按 **B04** | `A/replaykit_rpsystembroadcastpickerview.txt:13`（把选择器限定到某个 provider 的方式是设置成 broadcast extension 的 bundle identifier） |
| `id.team_id` | 10 位字母数字，按 **B05** | 无逐字公开句；判据只有 usage 第 39 行的形态受检清单 |
| `id.session_ref` | 点分段标识且须指向同一份台账里存在的对象，按 **B06** | `A/uikit_uiscenesession.txt:123`、`:137` |

### 4.3 本层的失败点

1. **前缀越界**：脚本一 **B01**、脚本二 **S03**／**S10**。这三码拦的不是「会话不存在」，而是「这一行无法回指任何一份公开清单」。
2. **会话类与通道词不同族**（**B02**，两处判据）：`id.channel_word = ReplayKit` 而会话类是 `mirroring` 或 `companion_display` 时报；进入面记成 `mdm_profile` 而会话类是本机外流类时也报。判据文案分别指向 `B/apple-platform-security-guide.txt:4241`（影片录制的同意提示）与 `:4246`（广播节名）——**录制与广播是两个会话类，通道词不能互换**。
3. **进入面与来源矛盾**（**B03**）：来源记 `managed_by_mdm`／`course_managed`，进入面却记成 `in_app_button`／`broadcast_picker`／`preview_share_ui`／`control_center`。这一条的公开依据是 `A/replaykit_rpsystembroadcastpickerview.txt:11` 与 `A/uikit_uiscenesession.txt:13`「UIKit maintains the session information for the lifetime of the scene itself, destroying the session in response to the user closing the scene in the app switcher.」——**进入面是 App 内控件时，来源不能记成管理面**。
4. **三格形态登记不成形状**（**B04**／**B05**／**B06**）：与第 18 篇同一判据——形状不对不是「值错了」，而是**这一格不是从公开材料抄来的**。
5. `airplay_menu` 一档在本篇归档里没有逐字句给出菜单形态：能核到的只有 `B/apple-platform-security-guide.txt:1374`（接收端校验）与 `:3901`（点对点 Wi-Fi 随机 MAC）两句间接支撑。因此 L1 只校验词族与来源是否同侧（B02／B03），不校验面名本身，这一处边界在第 26 章的未公开文档化清单里单独列一行。

### 4.4 本层信号码与字段的对应

L1 绑定 **B 族六码**：B01 前缀（`id.session_kind`）、B02 词族与类不同族（`id.channel_word` ↔ `id.session_kind`）、B03 面与来源矛盾（`id.source_face` ↔ `id.provenance`）、B04 包标识（`id.bundle_id`）、B05 团队标识（`id.team_id`）、B06 跨会话引用（`id.session_ref`）。行式三码在本层同样生效：`id.*` 写进未登记命名空间落 **S04**、清单外字段名落 **S05**、同一字段重复登记落 **S03**（后值静默覆盖前值）；`id.session_kind` 与 `id.source_face` 同属 12 个必备格，缺任一按 **S09** 记并落 J4。

---

## 5. L2 授权与同意层

### 5.1 本层管什么

L2 登记的是**同意发生过没有、由谁给出、按什么范围给出**，登记到枚举为止。**本层不讨论、也不提供任何让提示不出现或改变提示时机的做法**：本篇全篇的写法约束是只把公开读到的同意形态登记下来，`forceBypassScreenCaptureAlert` 在本篇里只作为管理面读数的一格存在形态被登记（第 12 章），L2 不把它当作可用选项。

同意这一层在公开口径里只有一句强句：`B/apple-platform-security-guide.txt:4241` 「Before recording starts, ReplayKit presents a user consent alert requesting that the user acknowledge their intent to record the screen, the microphone, and the front camera.」，同一行再把范围与重复条件写在一句里：「This alert is presented once per app process, and it’s presented again if the app is left in the background for longer than eight minutes.」这一句把 L2 的三格一次性钉住：**提示先于采集**（时序）、**同意范围是 App 进程**（`consent.alert_scope = once_per_app_process`）、**同意的对象是三样东西**（屏幕、麦克风、前置摄像头）。

配对型同意另给一档：`B/apple-platform-security-guide.txt:1439` 「When users set up iPhone Mirroring for the first time, they’re prompted to choose to either “Automatically authenticate,” or to “Ask every time.”」，同一行明写这一选择由谁执行——「The Secure Enclave on the Mac enforces this user choice and prompts the user to authenticate using their Mac password (or Touch ID if supported).」。与之相邻的是 `:1438` 的一句减法：「Secure ranging isn’t required for iPhone Mirroring.」。**镜像的远程解锁明确不需要安全测距**，因此 `consent.secure_ranging` 在 `MIR_` 会话上记 `required` 是台账自造条件。

`consent.granted_by` 的五种来源各有自己的公开句，不能合并叙述：`user_alert` ← `:4241`（录制前的同意对话框）；`control_center_toggle` ← `:4256`（选择器与控制中心里是同一套系统定义界面）；`apple_account_pairing` ← `:1431`「Users signed in to devices with the same Apple Account exchange cryptographic identities using a local peer-to-peer protocol, encrypted using keys stored in iCloud using end-to-end encryption.」；`course_enrollment` 与 `mdm_profile` ← 同出 `B/mdm-restrictions.txt:1018` 一句，但**主体不同**：前者是课程注册带来的观察许可，后者是配置描述文件本身给出的许可。`B/mdm-restrictions.txt` 的说明句流与键名流在归档里分属两段（1—1230 行与 1231—1530 行），所以这一句在这一份归档里回溯不到键名——正文引用它时只写行号，不补键名。

`consent.revocable` 是本层唯一没有逐字出处的枚举位：归档里没有任何一句写「用户可以撤回屏幕采集同意」。因此这一格允许取 `not_applicable`，但不允许由 `alert_shown = yes` 反推——撤回能力在第 11 章按三个停止口与一个丢弃口登记，在第 12 章按管理面键登记，本层只承认「同意发生过」。

### 5.2 字段清单

| 字段名 | 取值域 | 公开出处行锚 |
| --- | --- | --- |
| `consent.granted_by`（必备格） | 10 档：`user_alert`／`control_center_toggle`／`apple_account_pairing`／`course_enrollment`／`mdm_profile` + `not_granted`／`not_determinable`／`not_applicable`／`not_recorded`／`unknown` | `B/apple-platform-security-guide.txt:4241`、`:4256`、`:1431`；`B/mdm-restrictions.txt:1018` |
| `consent.alert_shown` | `yes`／`no`／`not_applicable`／`not_recorded`／`unknown` | `B/apple-platform-security-guide.txt:4241` |
| `consent.alert_scope` | `once_per_app_process`／`per_session`／`per_device`／`per_stream`／`not_recorded`／`unknown` | `B/apple-platform-security-guide.txt:4241`（只有 `once_per_app_process` 有出处） |
| `consent.microphone_used`／`camera_used` | 布尔五档 | `B/apple-platform-security-guide.txt:4238`、`:4241` |
| `consent.secure_ranging` | `required`／`not_required`／`not_recorded`／`unknown` | `B/apple-platform-security-guide.txt:1438` |
| `consent.pairing_choice` | `automatically_authenticate`／`ask_every_time`／`not_applicable`／`not_recorded`／`unknown` | `B/apple-platform-security-guide.txt:1439` |
| `consent.revocable` | 布尔五档 | 无逐字公开句；由第 11 章三个停止口与第 12 章管理面键回填 |
| `dom.mac_randomized`（交叉引用，命名空间属 L4） | `yes`／`no`／`not_applicable`／`not_recorded`／`unknown` | `B/apple-platform-security-guide.txt:3901`「Apple generates randomized MAC addresses for the peer-to-peer Wi-Fi connections that are used for AirDrop and AirPlay.」 |

### 5.3 本层的失败点

1. **授权主体串台**（**A01**）：`consent.granted_by = mdm_profile` 却登记 `alert_shown = yes`。判据文案同时引 `B/apple-platform-security-guide.txt:4241` 与 `B/mdm-restrictions.txt:1018`「in the Education payload, a student enrolled in a managed course through the Classroom app automatically gives permission to that course teacher’s requests to observe the student’s screen without prompting the student.」——**两处授权的主体不同**，管理面给出的许可不是设备侧弹出过一次提示的证据。
2. **时序颠倒**（**A02**）：来源记 `user_alert` 而提示位记 `no`。这一条拦的不是取值，而是顺序：提示在前、采集在后，二者不可颠倒登记。
3. **范围自造**（**A03**）：`alert_shown = yes` 而 `alert_scope` 不是 `once_per_app_process`。公开口径只给「每个 App 进程一次」，`per_device`／`per_session`／`per_stream` 三档都是台账自行加严或放宽；本篇允许它们存在，但要求结论档位降级。
4. **采集件参与却不登记提示位**（**A04**）：麦克风或摄像头为 `yes` 而提示位为空。依据 `:4238`（用户可用前置摄像头与麦克风为录制加注解）与 `:2262`（macOS 权限清单里 `Screen recording` 与 `Input monitoring` 并列为一类）。
5. **配对型同意漏登**（**A05**／**A06**）：镜像会话把安全测距记成必要条件（A05），或 `channel_word = iPhoneMirroring` 却不记配对选择（A06）。A06 之所以单列，是因为 `:1439` 的两种选择在 Mac 侧由 Secure Enclave 执行，它是 L2 唯一一档**执行侧可核对**的同意。

### 5.4 本层信号码与字段的对应

L2 绑定 **A 族六码**：A01 主体（`granted_by` ↔ `alert_shown`）、A02 顺序（`granted_by` ↔ `alert_shown`）、A03 范围（`alert_scope`）、A04 采集件（`microphone_used`／`camera_used` ↔ `alert_shown`）、A05 测距（`secure_ranging`）、A06 配对选择（`pairing_choice`）。`consent.granted_by` 是 12 个必备格之一；本层枚举越界一律走 **S07**，`consent.*` 写成清单外字段走 **S05**。告知面（`notice.*`，第 10 章）与本章的分工是：L2 记「同意是否给出」，L7 记「用户看得见哪一句」，两层的判据码不互用（N01 与 A02 是同一次外流的两个面，不是同一条判据的两写法）。

---

## 6. L3 通道件层：九条出流路径与三种缓冲形态

### 6.1 本层管什么

L3 管**画面走哪条路离开**。这一层的九条路径全部有逐字出处，而且第一条与第二条互为反命题——这是本篇的中心事实之一。同一节里 `B/apple-platform-security-guide.txt:4242` 写「Screen and audio capture occurs out of the app’s process in the ReplayKit daemon replayd. This is designed to ensure the recorded content is never accessible to the app process.」，紧接的 `:4243` 写「This allows an app to get video and sample buffers, which is guarded by the permissions dialogue.」。**同一节、两条相反通道**：一条是 App 进程永远读不到，一条是 App 拿得到 sample buffer。因此 `chan.host_has_access` 的 `never_accessible` 与 `yes` 两档都有公开依据，台账只能按通道选一个，不能两个都写。

### 6.2 字段清单

| 字段名 | 取值域 | 公开出处行锚 |
| --- | --- | --- |
| `chan.egress_path`（必备格） | 13 档：9 条出流路径 `out_of_process_capture`／`in_app_sample_buffer`／`broadcast_upload`／`mirroring_local`／`airplay_stream`／`carplay_template_stream`／`external_display_stream`／`classroom_observation`／`still_capture` + `not_applicable`／`none`／`not_recorded`／`unknown` | 逐条：`out_of_process_capture` → `:4242`；`in_app_sample_buffer` → `:4243`；`broadcast_upload` → `:4257`、`:4249`；`mirroring_local` → `:1429`、`:1439`；`airplay_stream` → `:1374`、`:3901`；`carplay_template_stream` → `:1374`，内容侧 `A/carplay.txt:5`；`external_display_stream` → `A/uikit_uiwindow.txt:18`；`classroom_observation` → `B/mdm-restrictions.txt:726`、`:729`；`still_capture` → `:766`、`B/apple-platform-security-guide.txt:2262` |
| `chan.buffer_form` | `raw_unencoded`／`serialized`／`movie_file` 三档有出处；`encoded_clip`／`frame_set` 是登记位；另有 `not_applicable`／`not_recorded`／`unknown` | `raw_unencoded` 「The extension that third-party broadcast services implement to handle video and audio content during broadcasting uses raw unencoded sample buffers.」→ `:4257`；`serialized` 「During this mode of handling, video and audio data is serialized and passed to the third-party upload extension in real time through a direct XPC connection.」→ 同一行 `:4257`；`movie_file` → `:4244` |
| `chan.process_owner`（必备格） | `app_process`／`replayd`／`system_service`／`extension_process`／`not_determinable`／`not_recorded`／`unknown` | `replayd` → `:4242`、`:4248`「The screen and audio capture mechanism during broadcasting is identical to movie recording and occurs in replayd.」；`app_process` → `:4243`；`extension_process` → `:4249`、`:4257`；`system_service` → `:4157` |
| `chan.api_entry` | 13 个逐字公开符号 + `none` + 两个未登记档，另收一种点分段标识形态；两者都不合按 **C06** | `RPScreenRecorder` → `A/replaykit_rpscreenrecorder.txt:3`；`RPPreviewViewController` → `A/replaykit_rppreviewviewcontroller.txt:3`；`RPSystemBroadcastPickerView` → `A/replaykit_rpsystembroadcastpickerview.txt:3`；`RPBroadcastHandler` → 归档类页题名为 `RPBroadcastSampleHandler`（`A/replaykit_rpbroadcastsamplehandler.txt:6`），枚举位写作 `RPBroadcastHandler`，两档词形不同，正文按枚举登记，`:12` 的前半句 `objects as captured by ReplayKit, you subclass` 说明缓冲对象由框架交给扩展；`RPBroadcastConfiguration` → `A/replaykit_rpbroadcastconfiguration.txt:3`；`CPInterfaceController` → `A/carplay_cpinterfacecontroller.txt:22`「A controller that manages the templates for constructing a scene’s user interface.」；`UISceneSession` → `A/uikit_uiscenesession.txt:13`；`UIScreen` 与外屏 → `A/uikit_uiwindow.txt:18` |
| `chan.entry_status` | `current`／`superseded`／`not_recorded`／`unknown` | 四处同族换代句：`A/replaykit_rpscreenrecorder.txt:4`「Use ScreenCaptureKit instead」、`A/replaykit_rppreviewviewcontroller.txt:4`「Use SCRecordingEditor instead」、`A/replaykit_rpsystembroadcastpickerview.txt:4`「Use ScreenCaptureKit SCContentSharingPicker instead」、`A/replaykit_rpscreenrecorder_isrecording.txt:4`「Use SCStream isCapturing instead」 |
| `chan.host_has_access` | `yes`／`no`／`never_accessible`／`not_determinable`／`not_recorded`／`unknown` | `never_accessible` → `:4242`；`yes` → `:4243`；广播侧的第三档「Only ReplayKit and the third-party broadcast extensions have access.」→ `:4250` |
| `chan.extension_count`／`service_endpoint` | `two`／`one`／`zero`… 与 `com.apple.broadcast-services`／`other`／`none`… | `:4249` 的前半句「Broadcast extensions: For third-party services to participate in ReplayKit broadcasting, they’re required to create two new extensions that are configured with the com.apple. broadcast-services endpoint」（归档行里端点被 PDF 文本化断成 `com.apple. broadcast-services`，台账枚举取 `com.apple.broadcast-services` 一种形态；扩展数由此定为 `two`） |
| `chan.preview_surface`／`share_surface` | `in_process`／`out_of_process`／`system_vended` 与 `app_vended`／`system_vended`／`none`… | `:4245`「The user has the ability to preview and share the movie with a user interface vended by ReplayKit.」；`A/replaykit_rppreviewviewcontroller.txt:153`「The modes used to determine whether the preview view controller or the share screen appears when editing a replay.」（预览面与分享面在一个枚举里二选一） |
| `chan.concurrent_limit` | `one_at_a_time`／`unlimited`／`not_applicable`／`not_recorded`／`unknown` | `A/replaykit_rpscreenrecorder.txt:13`「Only one app at a time can use the recorder on the user’s device.」 |

三个必须写出来的缓冲细节：`:4257` 把「不编码」与「被序列化」写在同一句里，所以 `raw_unencoded` 与 `serialized` 不是两条通道而是同一条通道的两个时刻；`movie_file` 才是产物形态（`:4244`）；`A/replaykit_rpbroadcastconfiguration.txt:3`「An object used to configure the movie clips produced during a live broadcast.」说明**直播期同时另产影片件**，这一格归 L5 的 `stored_object = mp4_clip`。

路径与形态的登记纪律有两条。第一条：`chan.buffer_form` 的 `encoded_clip` 与 `frame_set` 是**登记位**，本篇归档里没有逐字句规定这两种形态挂在哪个接口上（`A/replaykit_rpscreenrecorder.txt:98`「Exports a clip recording to a file.」只说片段导出到文件，不说编码形态），取这两值时 `doc.line_ref` 必须落到能支撑它的那一行，否则按 S07 之外的口径漂移处理。第二条：`egress_path` 的 `not_applicable` 与 `none` 语义不同——前者表示这条会话本就没有出流通道（相邻类与 `NA_`／`UNK_` 会话用），后者表示确认无对应条目；写成空值等同未登记（S06），且外流类会话取这两值任一时都触发 **C01**。

### 6.3 本层的失败点

1. **通道件缺失**（**C01**）：会话类是外流类而 `chan.egress_path` 为空或记 `none`。
2. **进程归属与通道形态矛盾**（**C02**）：`process_owner = replayd` 却记 `in_app_sample_buffer`。
3. **两条相反通道写串**（**C03**／**C04**）：出进程采集却称 App 读得到（C03，判据 `:4242` 的 never accessible）；App 内取样却称内容永不被 App 访问（C04，判据 `:4243` 的允许取样）。这两码是本篇判据密度最高的一对。
4. **广播通道件缺件**（**C05**）：`broadcast_upload` 而未登记扩展数量、服务端子点或缓冲形态（判据 `:4249` 与 `:4257`）。
5. **接口标识写成别的形状**（**C06**）：既不是枚举里的符号名也不是点分段形态。
6. **换代口径当现用依据**（**C07**）：`entry_status = superseded` 而提示位不是 `no`——入口已换新、提示位未跟着换，说明这一行是从旧文档抄的。
7. **并发上限漏登**（**C08**）与**预览面与分享面口径混用**（**C09**）：进程内预览配系统提供的分享面（判据 `:4245` 与 `A/replaykit_rppreviewviewcontroller.txt:11`）。
8. 抽取器造成的两处不可拼句：`A/replaykit_rpscreenrecorder.txt:11` 结尾断在 doc-link 处、`A/replaykit_rpbroadcastsamplehandler.txt:12` 的前半句是「objects as captured by ReplayKit, you subclass」，其主语在 `:11`。正文按纪律不跨行拼句，也不把断行句当完整命题引用。

### 6.4 本层信号码与字段的对应

L3 绑定 **C 族九码**，与九条出流路径同数，但对应关系是判据关系而非一一映射：C01/C02/C03/C04 管 `egress_path` 与 `process_owner`、`host_has_access` 的自洽；C05 管 `extension_count`、`service_endpoint`、`buffer_form` 三件齐备；C06 管 `api_entry` 与 `service_endpoint` 形态；C07 管 `entry_status`；C08 管 `concurrent_limit`；C09 管 `preview_surface` 与 `share_surface`。`chan.egress_path` 与 `chan.process_owner` 同属必备格。广播侧另有一句上限必须登记：`:4250`「The architecture helps ensure that hosting apps have no privileges to the broadcasted video and audio contents.」——承载 App 对广播内容没有特权，这一句使 `extension_count = two` 成为广播通道上唯一合法的扩展数量取值。

---

## 7. L4 执行域与隔离层

### 7.1 本层管什么

L4 管**这一格画面当时跑在谁的地址空间里、靠什么机制隔开**。它与 L3 的分工是：L3 说「走哪条路」，L4 说「路在哪一层执行」。判据文案里最直白的一条是 **D06**：画面由 `replayd` 取出而执行域记成 `app_sandboxed`，指向 `:4242`（采集发生在 replayd）与 `A/uikit_uiwindow.txt:18`（额外窗口通常用于在外屏显示内容）——出流进程归属与执行域类别必须一致。

`dom.isolation_mechanism` 七档机制逐个给行锚：

| 取值 | 公开出处行锚 | 逐字要点 |
| --- | --- | --- |
| `sandbox` | `B/apple-platform-security-guide.txt:2263` | 「Data Vault helps protect against unauthorized access to the data, even from processes that aren’t themselves sandboxed.」——沙箱之外的进程另有约束，故本档只表示「在沙箱画像内」，不表示「数据受 Data Vault 保护」 |
| `out_of_process` | `:4242`、`:4245`、`:4248`、`:4256` | 采集在 `replayd`、预览与分享 UI 由 ReplayKit out-ofprocess 呈现、广播选择器 out-of-process |
| `secure_enclave` | `:1431`、`:1439` | `:1431` 的前半句「iPhone Mirroring lets users forward notifications from their iPhone to a Mac using the same Apple Account.」给出账号侧前提；Mac 侧 Secure Enclave 执行用户配对选择的那一句已在 5.1 逐字引过（`:1439`） |
| `authentication_ic` | `:1373`、`:1374` | 「AirPlay also uses the authentication IC to verify that receivers have been approved by Apple.」 |
| `mfi_sap` | `:1374` | 「AirPlay audio and CarPlay video streams use the MFi-SAP (Secure Association Protocol), which encrypts communication between the accessory and device using AES128 in counter (CTR) mode.」 |
| `sts_protocol` | `:1374`、`:1382`、`:1383` | `:1382` 的前半句「All use cases are built upon the same basic foundation: a mutually authenticated Stationto-Station (STS) protocol」（`Stationto-Station` 是 PDF 断词，本篇照抄不改写）；`:1383` 要求用户逐对启用解锁关系 |
| `blastdoor` | `:1440`、`:1441` | **只用于划界**：BlastDoor 隔离、解析、转码与校验的是 Messages 与 IDS 到达的不可信数据，不覆盖屏幕采集；登记它只为说明本层不属于它 |

其余四格：`dom.domain_class` 六档（`app_sandboxed`／`daemon_extension`／`system_service`／`extension`／`isolated_display`／`kernel`）里，`daemon_extension` 有 `:4245`（经 iOS Extension 基础设施 out-ofprocess 呈现）与 `:4249` 支撑，`isolated_display` 有 `A/carplay_cpinterfacecontroller.txt:26`「The trait collection of the vehicle’s primary screen.」（界面特征取自车机主屏，不取本机屏）支撑，`kernel` 只能按 `:1382` 的例外句（无 Secure Enclave 的 Mac 在内核终止 STS 隧道）作**边界登记**；`dom.memory_safety_class` 四档没有任何一句公开话给出「这一条通道属于哪一档」，只能按公告组件名（`IOSurface`／`IOMobileFrameBuffer`）加平台行标注回填，而 `C/readings-19.txt` 第 27—28 行的读数是 macOS 31 行、iOS 4 行，标注必须照此写出；`dom.transport` 六档中 `local_peer_to_peer` 有 `:1431` 与 `:1439`，`wifi_network` 有 `:3901`，`vehicle_bus` 有 `:1373` 的传输方式句；`dom.domain_source` 八档（`platform_doc`／`advisory`／`mdm_status_item`／`vendor_claim`／`screenshot`／`assumed` 六档实名 + `not_recorded`／`unknown` 两档未登记）。

### 7.2 字段清单

| 字段名 | 取值域 | 公开出处行锚 |
| --- | --- | --- |
| `dom.domain_class`（必备格） | 6 档 + 3 兜底 | `B/apple-platform-security-guide.txt:4245`、`:4249`、`:4157`、`:1382`；`A/carplay_cpinterfacecontroller.txt:26` |
| `dom.isolation_mechanism` | 7 档机制 + `none`／`not_determinable`／两档未登记 | 见 7.1 表 |
| `dom.memory_safety_class` | `memory_safe`／`mixed`／`legacy_unsafe`／`not_determinable` + `not_recorded`／`unknown` | `C/readings-19.txt` 第 11—16 行（组件名）＋第 27—28 行（平台行数） |
| `dom.pairing_verified` | 布尔五档 | `B/apple-platform-security-guide.txt:1374`；`B/mdm-restrictions.txt:965`、`:969` 两条配对口令键 |
| `dom.transport` | `local_peer_to_peer`／`wifi_network`／`cellular`／`usb`／`vehicle_bus` + `not_applicable` + `not_recorded`／`unknown` | `:1431`、`:1439`、`:3901`、`:1373` |
| `dom.mac_randomized` | 布尔五档 | `:3901` |
| `dom.domain_source` | 6 档 + 两档未登记 | `platform_doc` → 本层全部 `B/…` 行锚；`advisory` → `C/advisory-19.tsv` 六列；`mdm_status_item` → `B/mdm-restriction-keys.txt` 键表；后三档无出处 |

### 7.3 本层的失败点

1. **执行域类别未登记**（**D01**）：这一格同时是必备格，缺失即 S09 落 J4。
2. **跨设备落点却记无隔离机制**（**D02**）：`land.destination` 为 `remote_mac`／`third_party_service`／`vehicle_display`／`external_receiver`／`home_hub` 五档之一而 `isolation_mechanism = none`。判据是 `:1431`（同一 Apple 账户的设备用本地点对点协议交换密码学身份）。
3. **点对点传输未登记配对核验形态**（**D03**）：判据 `:1374` 与 `:1382`——相互认证的 STS 协议与长期密钥是本层唯一一句把「配对已被核验」写成机制的话。
4. **域结论只来自厂商说法、截屏或假定**（**D04**）：`dom.domain_source` 落在 `vendor_claim`／`screenshot`／`assumed` 三档任一时报。这一码与 X01／X02 同族：截屏与厂商说法不能充当机制依据，是本文第 3.4 节已建立的写法约束。
5. **Wi-Fi 承载却未核对地址随机化**（**D05**）：判据 `:3901`。
6. **进程归属与执行域矛盾**（**D06**）：见 7.1。

`dom.memory_safety_class` 四档的登记只能走「组件名 + 平台行」两条旁证。本层可核的两条例证是：画面外流六组件子集里的 `IOSurface` 与 `IOMobileFrameBuffer`（`C/readings-19.txt` 第 11—16 行），以及 KEV 目录里画面语义词命中的两条之一 `CVE-2023-28206`——`C/readings-19.txt` 第 84—85 行给出的是 IOSurfaceAccelerator 越界写，平台行标注为 `iOS, iPadOS, and macOS`。**这两条都不给「这一条通道是哪一档内存安全类别」的读数**，所以 `memory_safe`／`mixed`／`legacy_unsafe` 三档里任何一档被写成确认结论，都必须同时有 `dom.domain_source = advisory` 与 `adv.platform_row` 两格在场；公告侧读数一律标注平台行，不得写成 iOS 侧结论。

L4 与第 06 篇的分工必须重声明一次：服务清单、端点校验与 Mach 层归第 06 篇，本篇只登记「有／无端点标识」与「跑在哪一层」，不重建服务名单，也不给任何跨域的做法。

### 7.4 本层信号码与字段的对应

L4 绑定 **D 族六码**：D01 管 `domain_class`，D02 管 `isolation_mechanism` ↔ `land.destination`，D03 管 `pairing_verified` ↔ `transport`，D04 管 `domain_source`，D05 管 `mac_randomized` ↔ `transport`，D06 管 `domain_class` ↔ `chan.process_owner`。本层与 L6（观测平面层）之间有一条单向约束：锁屏通知面读不出执行域（**O01**，判据 `:1429`），因此 `obs.plane = lock_screen_notice` 与 `obs.field_read = domain_class` 同时出现时报——L4 的读数只能来自平台文档、状态项或公告，不能来自告知面。

---

## 8. L5 落点与存储层

### 8.1 本层管什么

L5 管**画面离开之后落到哪儿、以什么对象存着、分享之后还在不在**。本层最重要的一格是 `land.write_scope = replaykit_only_directory`，出处 `B/apple-platform-security-guide.txt:4244`「The movie file is written to a directory that’s only accessible to the ReplayKit subsystems and is never accessible to any apps.」。这一句给出的是**可访问性**，不是**存在性**：影片确实写进了一个目录，但 App 读不到它。与第 11 篇的划界正落在这里——第 11 篇管备份与恢复链路里数据副本的归属，本篇不判定这个目录是否被纳入备份；归档里没有任何一句把 ReplayKit 目录与备份链路连起来，所以 `replaykit_only_directory` 既不能写成「没有副本」，也不能写成「副本可导出」，它只能作为 L5 的一格登记存在。

### 8.2 字段清单

| 字段名 | 取值域 | 公开出处行锚 |
| --- | --- | --- |
| `land.destination`（必备格） | `local_movie`／`third_party_service`／`remote_mac`／`vehicle_display`／`external_receiver`／`home_hub` + `none`／`not_applicable`／两档未登记 | `local_movie` → `:4244`；`third_party_service` → `:4249`（上传扩展把音视频数据交给服务的后端服务器）与 `A/replaykit.txt:5`「They can then share their recordings with other users through email, messages, and social media.」；`remote_mac` → `:1429`；`vehicle_display` → `A/carplay.txt:5`；`external_receiver` → `:1374`；`home_hub` → `:4157` |
| `land.write_scope` | `replaykit_only_directory`／`app_container`／`service_side_store`／`kernel_none` + `not_determinable`／`not_applicable`／两档未登记 | `:4244`（第一档的唯一出处）；`:4250`（承载 App 无特权，故服务侧与 App 侧两档不能互换） |
| `land.stored_object` | `movie`／`mp4_clip`／`sample_buffer`／`snapshot`／`frame` + `none`／`not_applicable`／两档未登记 | `movie` → `:4244`；`mp4_clip` → `A/replaykit_rpbroadcastconfiguration.txt:3`；`sample_buffer` → `:4243`、`:4257`；`snapshot` → `:2262`「macOS: Input monitoring (for example, keyboard strokes), Prompt, Screen recording (for example, static screen shots and video)」与 `B/mdm-restrictions.txt:766`；`frame` → `A/quartzcore_calayer_contents.txt:23`「Assigning a value to this property causes the layer to use your image rather than create a separate backing store.」与 `:24`（视图会替换这一格的直接赋值） |
| `land.persist_after_share` | 布尔五档 | `A/replaykit.txt:5`（分享动作与录制动作写在同一句里）；`:4257`（后端服务器） |
| `land.trimmed` | 布尔五档 | `A/replaykit_rpscreenrecorder.txt:13`「You can present a user interface (view controller) where a user can trim and preview recordings, and share them with other users.」；`A/replaykit_rppreviewviewcontroller.txt:3` |

### 8.3 本层的失败点

1. **落点缺失**（**E01**）：会话类是外流类而 `land.destination` 为空、`none` 或 `not_applicable`。
2. **写域与落点矛盾**（**E02**）：落点为本地影片却把写域记成 App 容器可访问——判据正是 8.1 逐字引过的 `:4244` 整句，其落点侧含义就是同一句后半段对任何 App 都不可访问的表述。
3. **有预览面无裁剪位**（**E03**）：登记了 `chan.preview_surface` 却不登记是否裁剪。判据 `A/replaykit_rppreviewviewcontroller.txt:3` 与 `A/replaykit_rpscreenrecorder.txt:13`。
4. **交给第三方却不登记留存**（**E04**）：落点为第三方服务而 `persist_after_share` 空。判据 `A/replaykit.txt:5` 与 `:4257`。
5. **存储对象与会话类错配**（**E05**）：`stored_object = mp4_clip` 而会话不是 `live_broadcast`。
6. **落点交接只有一个口在签名里出现输出 URL**：三个停止口分别是 `A/replaykit_rpscreenrecorder.txt:240`（`stopRecording`，回调给的是 `RPPreviewViewController`）、`:251`（`stopRecordingWithHandler:`）与 `:267`（`stopRecordingWithOutputURL:completionHandler:`），只有第三个签名里出现输出 URL，其说明句在 `:252`「Stops the current recording and writes the movie to the specified output URL.」。另有一个丢弃口 `:88`「Discards the current recording.」（方法名在 `:90` 与 `:97`），一个导出片段的口 `:98`「Exports a clip recording to a file.」。**复位面（第 11 章）的 `undo.output_url_returned` 只能按上述口的签名形态回填**：走了 `stop_recording` 或 `discard_recording` 而这一格留空，触发 **V01**；再证明依据写成 `assumed`，触发 **V02**；`reset_method = not_determinable` 却声称已再证明，触发 **V04**（三条判据分别见同脚本第 451、452、454 行）。

### 8.4 本层信号码与字段的对应

L5 绑定 **E 族五码**：E01 管 `destination`，E02 管 `destination` ↔ `write_scope`，E03 管 `trimmed` ↔ `chan.preview_surface`，E04 管 `persist_after_share` ↔ `destination`，E05 管 `stored_object` ↔ `id.session_kind`。跨层两条：L5 与 L4 的耦合走 **D02**（跨设备落点必须有隔离机制），L5 与 L8 的耦合走 **V01**／**V04**——`:4244` 说明复位针对的是影片目录的可访问性，`:4242` 说明采集面本身在 replayd 内，两者不是同一件事，所以「删了文件」与「断了通道」在第 11 章必须分格登记。本层的对外表述上限到此为止：**「这一格画面在台账里被登记为落到 X，写域是 Y，存储对象是 Z，公开依据是第 N 行的哪一句」**；不写「因此它已被删除」，也不写「因此它仍在某处」——两个方向都没有读数支撑。

---

## 9. L6 观测平面层：这一格由哪个面读回来

### 9.1 这一层给的不是事实，是坐标系

观测平面层不产生新读数，它规定**每一个读数必须自带「从哪儿读回来」**。本篇的客体是「一帧画面到底有没有离开这台设备、由哪条通道离开」，而这件事在设备侧真正能读回的面只有五个：锁屏通知、控制中心开关、相机指示灯、设置面板、MDM status item。其余各档读回的是**口径**（平台文档、公告、App 自述、厂商承诺），不是这一帧画面。这条区分是本章全部纪律的来源，也是本篇不把「看不见」写成「没有发生」的依据。

`obs.plane` 枚举共 14 个 token：10 个实体平面加 4 个哨兵（`not_determinable`／`none`／`not_recorded`／`unknown`）。本节把 10 个实体平面加 `not_determinable` 与 `none` 这 12 档逐个说清它能读回哪一格、读不回哪一格。

| 档 | 能读回哪一格 | 读不回什么 | 归档依据 |
| --- | --- | --- | --- |
| `lock_screen_notice` | 「画面正被另一台设备看着」这件事本身，即 `obs.field_read = egress_state` 与 `notice.banner_kind` | 读不回执行域、进程归属与落点 | `B/apple-platform-security-guide.txt:1428—1429`：`:1429` 前半句 `iPhone Mirroring allows a user to use their iPhone from their nearby Mac.`，同一行随后写明被远端使用期间 iPhone 保持锁定、锁屏面上有一条持续通知 |
| `control_center` | 「这条通道在设备侧由哪个控件打开」，即 `id.source_face = control_center` 的旁证 | 读不回控件背后的实现 | `B/…:4256`：`The user interface is implemented using a private API and is an extension that lives within the ReplayKit framework.`（同一行前半句写明广播选择器用的就是控制中心可达的那套系统界面） |
| `camera_indicator` | 「采集此刻可被用户看见」这一格，`obs.indicator_visible = yes` 的唯一合法平面 | 读不回画面内容本身 | `B/…:708`：`The architecture is designed to prevent any untrusted software—even with root or kernel privileges in macOS—from engaging the camera without also visibly lighting the on-screen camera indicator light.` |
| `settings_ui` | 「这一类能力被系统登记为一个权限类」——集合级读数 | 读不回某一次会话；且本档在归档里的清单句是 macOS 行 | `B/…:2262`：`• macOS: Input monitoring (for example, keyboard strokes), Prompt, Screen recording (for example, static screen shots and video)` |
| `platform_doc` | 平台承诺的形态本身，即 `dom.domain_source`／`notice.warning_text_source`／`mgmt.key_source` 三格的 `platform_doc` 档 | 读不回这一台设备上现在是什么状态 | 组 B 全部（第 2.2 节口径）；引用必须落到行号 |
| `advisory` | 组件×CVE 对、修复版本、平台行 | 读不回某一帧画面，也读不回 iOS 侧结论（第 13 章） | `C/advisory-19.tsv` 六列与 `C/readings-19.txt:2—5` |
| `mdm_status_item` | 「某个限制键在这台受管设备上生效」 | 读不回这一帧是否离开、更读不出告知位是否已被满足 | `B/mdm-restrictions.txt` 每条限制的 `Available:`／`Requires supervision:` 两行（第 12.1 节的三行结构） |
| `crash_report` | 只登记一个可回查的报告标识（9.4） | 不承载本篇任何一格的读数 | 组 A 无崩溃文档件；`DOC["K03"]` 一句：`观测面只登记报告标识，不粘贴堆栈、日志或截屏正文` |
| `app_self_report` | 面板是否呈现、由谁配置——「这个格有没有被 App 侧登记过」 | 不独立构成观测（`O03`） | `A/replaykit_rppreviewviewcontroller.txt:11`：`Upon completion of a successful recording, the preview view controller is passed into the completion handler`（前半句逐字） |
| `vendor_claim` | 厂商自己说了什么 | 不能充当机制依据（第 3.4 节失败点 6） | 劣化档，与 `screenshot`／`assumed` 同族 |
| `not_determinable` | 承认这一格没有任何可读回的面 | —— | 本篇把它当结论登记，不当缺口登记 |
| `none` | 本篇没有从任何面读回这一格 | —— | 与 `not_recorded`（没登记）不同形，不可互换 |

三个必须先说下的结构事实：

1. **锁屏通知面与相机指示灯面是仅有的两个「硬件与系统共同保证可见」的面**，其余八档都可被配置或版本改变。`B/…:1429` 那条持续通知与 `B/…:708` 那条指示灯设计，是本篇能写「用户面确实看得见某格」的全部依据。
2. **`:3261` 与 `:3575` 是观测面的反向读数**——`Tap to Pay on iPhone is designed to prevent all photo, video, screenshot and screenrecording features from capturing PIN information.` 与 `It is also designed to prevent all screenshot and screen-recording features from capturing the displayed information.` 两句各给出一个「任何观测平面上都不该有画面读数」的场景。这两格本篇只登记为 `land.stored_object = none` 且 `obs.plane = not_determinable`，不写成「这一面被关掉了」。
3. **`HomeKit` 那句是同一方向的第三条**：`B/…:4157` 写明视频帧由独立系统进程安全渲染，App 不能存取该流、也不允许从该流截屏——它给的是「画面在设备内被看见但不可外流」的正向口径，本篇只在 L4／L5 引它，观测侧用它说明 `none` 与 `not_determinable` 的差别。

### 9.2 `obs.field_read` 六档：可被读回的格的全集

六档 `egress_state`／`prompt_state`／`host_process`／`domain_class`／`destination`／`indicator_state` 是本篇**能被某个面读回**的格的全集，其余层的格（L2 的同意主体、L3 的缓冲形态、L9 的键生效状态）只能通过它们映射到六档之一才谈得上"被读回"。六个平面与六个字段的对应关系不是多对多，而是被两条判据硬性收束：

| 字段 | 合法平面 | 不合法组合与拦它的码 |
| --- | --- | --- |
| `egress_state` | `lock_screen_notice`、`control_center`、`mdm_status_item` | 无（本篇把「离开与否」写成可被三个面旁证的格） |
| `prompt_state` | `lock_screen_notice`、`control_center`、`settings_ui`、`app_self_report` | `lock_screen_notice` 与 `notice.lockscreen_visible = no` 同时出现 → `N04` |
| `host_process` | `platform_doc`、`advisory` | 由 `A/` 接口件读回时平面只能记 `app_self_report`，不得记 `platform_doc` |
| `domain_class` | `platform_doc`、`advisory`、`mdm_status_item` | `lock_screen_notice` + `domain_class` → `O01`，判据文案逐字：`锁屏通知读不出执行域` |
| `destination` | `platform_doc`、`settings_ui`、`app_self_report` | 平面记 `crash_report` 时缺读数时刻即 `O02`、缺引用格即 `X01`，两条各计一次 |
| `indicator_state` | 仅 `camera_indicator` | `obs.indicator_visible = yes` 而平面不是 `camera_indicator` → `O04` |

`O04` 的判据文案逐字是：`登记了采集指示灯可见但观测平面不是指示灯面`。这条把 `:708` 那条硬件级口径写成了台账形态：**指示灯可见这件事只能在指示灯面上读回，别的面声称看到指示灯即形态不成立**。

### 9.3 时刻、可见位与四个失败点

`obs.read_at` 与 `undo.verified_at` 是脚本一里仅有的两个日期字段，形态按 `C/kev-apple.tsv` 表头两列 `dateAdded`／`dueDate` 的 `YYYY-MM-DD` 同形校验（`S08`，属阻断档）。为什么时刻在本层是硬格，`A/uikit_uiscene.txt:199` 与 `:217` 给了唯一一处公开依据：`A notification that indicates that the scene is running in the background and is no longer onscreen.`——on-screen 与 off-screen 是两条**系统通知**，即「画面在不在某个屏上」本身是时刻性的，不带时刻的读数无法区分「此刻在面上」与「登记时在面上」。

| 码 | 判据（代码里的条件） | 阻断性 | 依据 |
| --- | --- | --- | --- |
| `O01` | `obs.plane = lock_screen_notice` 且 `obs.field_read = domain_class` | 非阻断 | `DOC["O01"]` 逐字给出 `B/…:1429` 那半句作为依据 |
| `O02` | 平面为实体档（非 `none`／`not_recorded`／`not_determinable`）且 `obs.read_at` 为空 | 非阻断 | `DOC["O02"]`：`A/uikit_uiscene.txt` 第 199 与 217 行 + usage 文本的 `obs.read_at` 格 |
| `O03` | `obs.plane` 为 `vendor_claim` 或 `app_self_report` 且 `doc.conclusion = confirmed` | 非阻断 | `DOC["O03"]`：`B/…:2262`——可核对的状态在系统侧，不在 App 自述里 |
| `O04` | `obs.indicator_visible = yes` 且平面不是 `camera_indicator`／`not_recorded` | 非阻断 | `DOC["O04"]`：`B/…:708` 与 `B/…:4245` |

`obs.list_visible`（这一格在列表或面板里是否可见）是布尔位，脚本一没有为它单独设码，它受 `S07`（枚举越界）与 `K02`（形态拒收）两条共同约束。本篇用它承担一个窄职责：`A/replaykit_rpsystembroadcastpickerview.txt:12` 那句 `Clicking the broadcast button has no effect in Mac apps built with Mac Catalyst.` 所描述的「控件在但无效果」，只能登记成 `list_visible = yes` 加通道件的另一格，不能登记成「不可见」。

### 9.4 崩溃面：三句规范在本篇收束成一条

`obs.crash_report_ref` 的形态判据是 `[A-Za-z0-9-]{6,40}`，或 `absent`／`not_applicable`；写成堆栈片段、设备路径或带空格的描述即触发 `K03`（阻断档）。规范一共三句，本篇只用第一句与第三句：**崩溃引用只登记报告标识；崩溃面不承载本篇任何一格的读数；本层不做崩溃复现与缺陷定位。** 组 A 十二份件里没有崩溃文档件，组 B 只给关联句，因此这一档在台账里的正确用法只有一个——把一个归属结论挂到一个可回查的外部对象上。

### 9.5 台账字段与信号口径

**台账字段**：`obs.plane`（必备格，14 个取值，10 个实体平面）、`obs.field_read`（9 个取值，6 个可观测字段）、`obs.read_at`（日期）、`obs.indicator_visible`／`obs.list_visible`（布尔位）、`obs.crash_report_ref`（形态受检）。
**信号口径**：`O01`—`O04` 四码（全部非阻断）＋ `K03`（阻断）＋ `S07`／`S08` 两条形态码；跨层联动为 `N04`（第 10 章）与 `X01`（第 14 章）。

---

## 10. L7 告知层：锁屏持久通知、会话结束横幅与来源披露

### 10.1 本章的范围，先划出来

**本章只登记告知出现过没有、告知文本从哪一格里抄来。** 本篇不写任何让提示不出现、伪装提示或替代提示的做法；`B/mdm-restriction-keys.txt` 里那个与采集提示同族的键（第 12.2 节逐字列出）在本篇只作为「策略面存在一个能改变同意对话框是否出现的格」这一格的**存在形态登记**，不给出任何使用方式，也不给出任何验证它生效的方法。这条范围声明与第 21 章脚本头部注释里的两句一并读：脚本本身也声明「不含告知提示的欺骗或关闭」。

### 10.2 五格的公开口径

- **`notice.prompt_shown`（必备格）**：公开口径只有一句直接支撑提示的存在与位置——`B/…:4241`：`Before recording starts, ReplayKit presents a user consent alert requesting that the user acknowledge their intent to record the screen, the microphone, and the front camera.`。同一行的下一句给出重复条件（`DOC["A03"]` 逐字写作「公开口径只给『每个 App 进程一次』，per_device／per_session／per_stream 都是台账自行加严或放宽」），因此这三档在本篇一律按加严或放宽记，不按平台口径记。**提示在前、采集在后，这个顺序不可颠倒登记**，`DOC["A02"]` 的原文就是这一句。
- **`notice.banner_kind`**：两档实体值直接来自 `B/…:1429` 同一行的两半——`persistent` 对应「被远端使用期间锁屏面上有一条持续通知」，`first_time_banner` 对应同行后半句「会话结束后第一次解锁时显示一条横幅」。`none` 与 `not_applicable` 是两档不同的登记：前者是「这一类会话公开口径里没有横幅」，后者是「本格与这一会话类无关」。配对选择与此联动：`consent.pairing_choice` 的 `automatically_authenticate`／`ask_every_time` 两档来自 `B/…:1439`，`DOC["N05"]` 把它作为「首次设置的两种选择决定后续是否再提示」的依据。
- **`notice.lockscreen_visible`**：五档里 `not_supported` 是本篇必须保留的一档——公开口径里没有任何一句承诺某一类会话会在锁屏上留下读数，因此「平台不支持」与「这次没显示」不能写成同一个值。它与 `obs.plane = lock_screen_notice` 的互斥由 `N04` 拦（判据文案：`称锁屏通知面不可见却从锁屏通知取数`，依据句指向 `C/readings-19.txt:99` 那个键名）。
- **`notice.origin_disclosed`**：只有 `disclosed`／`absent` 两档是结论。唯一能支撑 `disclosed` 的公开句子是 `B/…:1431` 的锁屏通知转发建立在同一 Apple 账户的配对之上（前半句 `iPhone Mirroring lets users forward notifications from their iPhone to a Mac using the same Apple Account.`）——它披露的是「画面被哪一台设备看着」这一层来源，不披露任何第三方接收方，所以广播与 AirPlay 两类的这一格本篇只能记 `absent`。
- **`notice.warning_text_source`**：九档里 `platform_doc`／`advisory`／`support_note` 三档可回指，`vendor_claim`／`screenshot`／`assumed` 三档不可回指。**写下后两档之一即触发 `N03`**（判据文案：`告知文本依据是截屏或假定`，依据是本文第 3.4 节失败点）。这两个取值本身即信号，不需要额外字段。

### 10.3 五个失败点与「无提示必须留下一句」

| 码 | 判据（代码里的条件） | 本层的含义 |
| --- | --- | --- |
| `N01` | 会话类属四类主线之一且 `notice.prompt_shown` 为空或 `not_recorded` | 画面确已离开设备但告知位没登记——**这一条是必备格之外的第二道锁** |
| `N02` | `id.session_kind = mirroring`、`notice.banner_kind = none` 而 `consent.alert_shown = yes` | 镜像类会话登记「无横幅」但同意提示为已出现，两格互斥 |
| `N03` | `warning_text_source ∈ {screenshot, assumed}` | 告知文本依据不可回指 |
| `N04` | `notice.lockscreen_visible = no` 且 `obs.plane = lock_screen_notice` | 锁屏不可见与从锁屏取数不能同时成立 |
| `N05` | `prompt_shown = no`、`origin_disclosed = absent`、会话类属主线且 `notice.notice_note` 为空 | **本篇唯一一条要求"写说明句"的码**：无提示本身可以登记，但必须留下一句说明，否则跨台账复算时不可换算 |

`N05` 依据句（`DOC["N05"]`）逐字指向 `B/…:1439` 与 `B/…:1431` 两行——即「后续是否再提示」与「来源披露到哪一层」这两件事都有公开口径可回指，写下与公开口径不同的结论时必须自己留下依据句。`notice.notice_note` 是自由文本字段，但受 `K02` 的形态拒收约束（长度阈值、设备路径形态、密钥串形态一律拒收），它不是可以放载荷的地方。

### 10.4 谁读得回告知

三处，第一处是硬约束：**崩溃面读不出告知状态**——本篇没有为这条单设码，而是通过 `obs.field_read = prompt_state` 与 `obs.plane = crash_report` 的组合落入 `O02`（缺读数时刻）与 `X01`（缺引用）双记。**管理面读得到键、读不到告知位**：`B/mdm-restrictions.txt:766` 那一条能关掉截图与录制能力本身，但它不产生「用户已被告知」这一格——`mgmt.*` 与 `notice.*` 之间没有任何一条换算句，这是第 3 章八处换算失败在本层的落点。**系统通知面读得到横幅形态**：`B/…:1429` 是唯一的会话结束横幅口径，`first_time_banner` 这一档除了它没有第二个来源。

### 10.5 台账字段与信号口径

**台账字段**：`notice.prompt_shown`（必备格，5 取值）、`notice.banner_kind`（6 取值，2 个实体档）、`notice.lockscreen_visible`（6 取值，含 `not_supported`）、`notice.origin_disclosed`（5 取值，2 个结论档）、`notice.warning_text_source`（9 取值，3 可回指 3 不可回指）、`notice.notice_note`（自由文本，受 `K02` 约束）。
**信号口径**：`N01`—`N05` 五码（全部非阻断）；跨层联动 `A02`／`A03`（第 5 章）、`N04`↔`O01`（第 9 章）、`G04`↔`N01`（第 12 章，管理面替用户给出的那类同意）。

---

## 11. L8 复位与再核对层：三个停止口、丢弃与残件声明

### 11.1 `undo.reset_method`：九档里只有五档有接口面依据

枚举共 12 个 token，本篇当九档讲（8 个实体加 `not_determinable`）。可分三组：

- **有直接签名依据的两组，共三个停止口加一个丢弃口**。`A/replaykit_rpscreenrecorder.txt:238` 给出 `Stops the current recording.`，对应符号在 `:240`（`stopRecording`）与 `:251`（`stopRecordingWithHandler:`）；`A/…:252` 给出 `Stops the current recording and writes the movie to the specified output URL.`，对应符号在 `:267`（`stopRecordingWithOutputURL:completionHandler:`）。**三个停止口里只有第三个在签名里出现输出 URL**——`DOC["V01"]` 逐字就是这样写的。丢弃是第四个、也是独立的一个口：`A/…:88` 给出 `Discards the current recording.`，符号名在 `:90`（`discardRecording`）与 `:97`（`discardRecordingWithHandler:`）。因此 `stop_recording` 与 `discard_recording` 两档不能互换：前者可以带输出 URL，后者按公开口径是丢弃当前录制。
- **落点侧的两档**：`delete_movie` 与 `revoke_consent`。前者指向 `B/…:4244` 那个「只有 ReplayKit 子系统可访问的目录」里的影片件（第 8 章已落），后者指向 `consent.revocable` 一格的复位侧后果——**公开口径里没有一句说明撤销同意后已离开的画面会被追回**，所以这一档只能记动作，不能记效果。
- **借来的四档**：`unpair`（借 `B/…:1431` 那套配对身份，同行说明身份被钉住、变更即不再转发通知）、`mdm_reapplied`（借 `B/mdm-restrictions.txt` 每条限制的 `Available:` 与 `Requires supervision:` 两行；**本章只登记这一事件是否发生，不描述如何下发、也不描述如何核对下发结果**）、`restart` 与 `expiry_only`（**本篇归档里没有对应句子**：`expiry_only` 只能借 `C/kev-apple.tsv:2` 的 `dueDate` 一列，而那是修复期限、不是画面失效）。

### 11.2 六个字段与四条码

| 码 | 判据（代码里的条件） | 含义与依据 |
| --- | --- | --- |
| `V01` | `reset_method ∈ {stop_recording, discard_recording}` 且 `undo.output_url_returned` 为空 | 走了停止口或丢弃口却没登记输出 URL 有没有被交出；依据即上面 `:240／:251／:267` 三行 |
| `V02` | `reproof_done = yes` 且 `reproof_basis = assumed` | 再证明依据为假定——**本层唯一一条把「假定」判死的码** |
| `V03` | `residue_claimed = yes` 且 `undo.verified_at` 为空 | 残留是一个时刻性断言，没有时刻等于没写；日期形态另按 `S08` |
| `V04` | `reset_method = not_determinable` 且 `reproof_done = yes` | 复位方法不可判定却声称已再证明 |

`undo.output_url_returned` 的五档里 `not_applicable` 有实义：`mirroring`、`companion_display` 与 `remote_observation` 三类会话在本篇归档里没有「输出 URL」这一物件，写下 `yes`／`no` 反而是把录制类形态套到镜像类上。`undo.residue_claimed` 与 `undo.reproof_done` 是同族布尔位（`yes`／`no`／`not_recorded`／`unknown`），本篇要求两格分开写——**「有残件」与「已再核对」是两件事**，合并写会同时躲过 `V02` 与 `V03`。

### 11.3 哪些依据算合格再核对

`undo.reproof_basis` 十档里七个实体档，按可核对性分三档：

| 取值 | 可核对性 | 依据 |
| --- | --- | --- |
| `re_opened` | 合格 | 重新打开是一条显式动作；`A/replaykit_rppreviewviewcontroller.txt:11` 的回调交出预览对象是可登记的再进入点 |
| `re_broadcast` | 合格 | `A/replaykit_rpbroadcastsamplehandler.txt:84—98` 给出 `broadcastStarted`／`broadcastAnnotated`／`broadcastFinished` 三段生命周期，重新广播能落到这三段之一 |
| `re_rendered` | 合格 | 呈现结果差异；`B/…:4245` 那句（预览与分享的界面由 ReplayKit 提供、进程外呈现）是本篇唯一的呈现面口径 |
| `user_visible_prompt` | 合格但受第 10 章限制 | 告知文本源必须落在可回指三档，否则 `N03` |
| `platform_doc` | 合格 | 组 B 行号 |
| `advisory_component` | 合格但只给集合级 | 组件×CVE 同行；不得写成 iOS 侧结论（第 13 章） |
| `assumed` | **不合格** | `V02`，且真实台账写下它即不进入对外表述（第 14.1 节的措辞层级） |

`not_applicable`／`not_recorded`／`unknown` 三档是登记缺失档，本篇要求：**`reproof_done = no` 比 `reproof_done = yes` 加 `assumed` 更可用**——前者是一格诚实的空位，后者是一条无法复算的断言。

### 11.4 谁读得回复位，以及本层的表述上限

`obs.field_read` 的六档里没有一个描述复位结果，这是本篇复位层与第 18 篇同一层位最明显的差别：**画面外流的复位不改变"这一格被判成什么"，只改变"这一格还在不在某个面上"**。因此读回复位只能借三个面：锁屏通知面（横幅消失这件事本身，`B/…:1429` 后半句）、指示灯面（采集停止后不再点亮，`:708` 那条设计的反向读法）、管理面（键是否重新下发，只登记事件）。三者都只能证明**复位条件成立**，不能证明「这一帧画面被从某个远端删除了」——后者需要一个落点侧的读数面，而本篇归档里没有。这条上限是第 24 章「把停止口当成追回口」一条误区的落点，也是 `undo.*` 全部对外表述的最高档。

### 11.5 台账字段与信号口径

**台账字段**：`undo.reset_method`（12 取值，8 个实体）、`undo.output_url_returned`（5）、`undo.residue_claimed`／`undo.reproof_done`（各 4）、`undo.reproof_basis`（10 取值，7 个实体、6 个合格）、`undo.verified_at`（日期，`S08`）。
**信号口径**：`V01`—`V04` 四码（全部非阻断，本层无阻断档——复位层不改变归属结论的对错，只改变结论的时效）；跨层联动 `S08`（时刻形态）、`O02`（复位读数同样要带时刻）。

---

## 12. L9 管理面回查层：210 个纯键名分母与 13 个画面语义键

### 12.1 分母纪律：先给四个数，再给命中

读 `B/mdm-restriction-keys.txt` 这一份清单必须先说清 218 这个数**不是键名数**。四个数逐字取自 `C/readings-19.txt:88—91`：表内总行数 220（R19）、按「单个字母数字标识」形态命中的行 218（R20，与第 18 篇同一口径）、其中首字母小写的行 216（R21）、形态命中行里**不是键名的 8 行**——两个分段标题（`Important`、`Note`，物理位于 `:2` 与 `:4`）加六个平台名行——**纯键名分母取 210**（R22）。`:1—4` 四行是分段标题（`Device Management`／`Important`／`Mac Catalyst`／`Note`），`:5—8` 起逐行才是 `allow` 前缀的小驼峰单标识。两支脚本都按「形态命中集合」做包含判断，因此对「不在清单内」的判定实际以 218 为准而不是 210；这条差异必须写在正文而不是脚注里，它是 `G01` 第二条与 `G02` 共同的口径前提：**按行直接取键会虚增分母 8，用虚增的分母做命中判断会漏判。**

### 12.2 13 个画面语义键与两个前缀族

`C/readings-19.txt:92` 给命中数（R23）：**218 个形态命中行里出现画面语义词（`screen`／`airplay`／`record`／`observ`／`mirr`）的键 13 个**；`:93` 给前缀分布（R24）：`allow*` 9 个、`force*` 4 个。13 个键名逐字取自 `:95—107`（R25），按本篇的用法分三组：

- **真正约束画面能否离开设备的**：`allowScreenShot`（静图出流）、`allowiPhoneMirroring`（跨设备镜像）、`allowRemoteScreenObservation`（Classroom 远屏观察）、`allowAirPlayIncomingRequests`（入向 AirPlay 请求）、`forceAirPlayIncomingRequestsPairingPassword` 与 `forceAirPlayOutgoingRequestsPairingPassword`（两个方向的配对口令）、`forceClassroomUnpromptedScreenObservation`（远屏观察的提示形态）。这七个键的共同特征是：**它们约束的是通道的开合与配对形态，不约束已经离开的画面能否被追回**——本篇所有 `mgmt.*` 对外表述都止于这一句。
- **同词不同义的四族五格**：`allowAutomaticScreenSaver`、`allowCallRecording`、`allowLockScreenControlCenter`、`allowLockScreenNotificationsView`、`allowLockScreenTodayView`。它们命中 `screen`／`record`／`lockscreen` 这些**词形**，管的却分别是屏保、通话录音与三个锁屏面开关。脚本一把这五个键写进同一张同词表，`G02` 的判据逐字是：`该键命中词形但不约束画面离开设备`，依据句（`DOC["G02"]`）指向 `C/readings-19.txt:96—100`。**这一组是 L9 最容易出假读数的一格**，也是 `mgmt.word_family` 存在的全部理由。
- **只登记存在形态的一格**：`forceBypassScreenCaptureAlert`。本篇把它登记为「管理面这一族的取值里存在一个与采集提示出现与否相关的键」，**不给出任何使用它的方式、不给出任何让它生效的验证步骤、也不讨论在什么形态下它不起作用**。第 10 章那句范围声明在这里生效：告知层的纪律不因为管理面有一格而改变。

`mgmt.word_family` 五档即上述分组的台账形态：`egress_control`（七格那一组）、`lockscreen_surface`（三个 `allowLockScreen*`）、`screensaver`、`call_recording`，另两档是登记缺失。写下后三档之一却把 `mdm_configurable` 记成能约束画面离开，即落入 `G02`。

### 12.3 Restrictions 说明句的 9 行与 `CODE|` 的 299 行：管理面自身的错位

`B/mdm-restrictions.txt` 共 1,530 行（R26，`C/readings-19.txt:110`）。这一页被派生器拆成两个流：**说明句流 1—1230、`CODE|` 形态流 1231—1530，其中 `CODE|` 形态的键名行 299 条**（R28，`:121`）。后果是说明句里那句「If ⟨键⟩, the system disables …」在这份归档里回溯不到键名——`IDX/sources-19.md` 把这条明写为抽取器限制。本篇把它当作**管理面自身错位的实证**来登记，而不是当缺陷绕开：说明句命中画面语义词的只有 9 行（R27，`:111`），逐行在 `:112—120`，而 `CODE|` 流里形似画面语义的只有 `:1392` 与 `:1393` 两行 `CODE| allowScreenShot`。

九行说明句里本篇必须引的六条（全部只引该行完整前半句）：

| 行 | 逐字前半句 | 登记进哪一格 |
| --- | --- | --- |
| `:29` | `, the system disables incoming AirPlay requests.` | `mgmt.restriction_key = allowAirPlayIncomingRequests` 的语义侧 |
| `:726` | `, the system disables remote screen observation by the Classroom app. Nest this key beneath` | `mgmt.payload` 必填的依据——子约束键要写清挂在哪份 payload 下（`G03`） |
| `:729` | `, the Classroom app doesn’t observe remote screens. Requires a supervised device until iOS 13 and macOS 10.15.` | `mgmt.supervised` 的口径来源（`DOC["G04"]` 的第二条依据） |
| `:766` | `, the system disables saving a screenshot of the display and capturing a screen recording. It also disables the Classroom app from observing remote screens.` | **一个键同时关掉三类出流**：静图、屏幕录制采集、Classroom 远屏观察。本篇只用它说明「一键三禁」的存在，不推论任何绕过 |
| `:965` | `, the system forces all devices sending AirPlay requests to this device to use a pairing password. This key isn’t supported in tvOS 10.2 and later.` | 入向配对口令，同行给出 tvOS 10.2 之后的替代口径（改用 AirPlay 安全 payload） |
| `:969` | `, the system forces all devices receiving AirPlay requests from this device to use a pairing password.` | 出向配对口令；与 `:965` 成对，是三条 AirPlay 句里的两条 |

第三条 AirPlay 相关句即 `:29`。三条合起来给出的公开口径是：**入向可禁、双向可强制配对口令、其中一个方向的键在新平台上有替代口径**——这是本篇关于管理面与 AirPlay 的全部表述，且 `:965` 那半句的替代口径必须与键名同行登记（`mgmt.key_source = official_doc`）。

`:1018` 是本层最敏感的一行，逐字前半句是 `in the Education payload, a student enrolled in a managed course through the Classroom app automatically gives permission to that course teacher’s`（同行随后写明该许可针对教师观察学生屏幕的请求且不提示学生）。**本篇只陈述这一句公开口径，把它登记成 `consent.granted_by = course_enrollment` 与 `mgmt.payload = com.apple.education` 两格，绝不写任何让它生效的配置路径。** `DOC["A01"]` 给的就是这条边界：两处授权的主体不同（`B/…:4241` 的设备侧提示与 `B/mdm-restrictions.txt:1018` 的课程侧自动许可）——把后者登记成设备用户自己的同意即 `G04`（判据逐字：`课程免提示同意被登记成设备用户自己的同意`，依据为 `:1018` 与 `:729` 两行）。

### 12.4 六格字段与触发信号

`mgmt.mdm_configurable` 六档：`channel_only`／`content_only`／`yes`／`no` 加两档缺失。**`content_only` 且键名为空即 `G01`**——依据句（`DOC["G01"]`）指向 `C/readings-19.txt:92` 与 `:95—107` 那份清单，因为那 13 个键里没有一个的内容维度是「画面本身」，所以 `content_only` 这一档在本篇实际无解，只能改记 `channel_only`。`mgmt.key_in_inventory` 五档里 **`not_checked` 必须显式写**——留空会同时躲过 `G01` 与 `G02`，这也是本篇把「没查过」当成一个实体档而非空值的原因。`mgmt.payload` 三档实体（`com.apple.applicationaccess`／`com.apple.education`／`com.apple.airplay`，逐字取自脚本枚举），登记了 payload 却没写 `mgmt.key_source` 即 `G03`。`mgmt.supervised` 两档结论，与 `B/mdm-restrictions.txt` 每条限制的 `Requires supervision:` 行同侧登记。

`mgmt.key_source` 六档里两个取值本身即信号：`vendor_claim` 意味着这一格的键名依据只来自厂商说法——本篇要求同格的 `dom.domain_source` 不能也只是厂商说法或截屏，否则落 `D04`（判据文案逐字：`执行域结论只来自厂商说法、截屏或假定`，依据指向本文第 3.4 节失败点）；`none` 意味着登记了 payload 却没有键出处，即 `G03`。`mgmt.restriction_key` 的形态受检（小驼峰单标识，`G05`）就是照 `:5—8` 那一形态写的，写成带空格或点分段形态即不是这份清单里的键。

### 12.5 台账字段与信号口径

**台账字段**：`mgmt.mdm_configurable`（必备格，6 取值）、`mgmt.word_family`（6 取值，4 个实体档）、`mgmt.key_in_inventory`（5 取值，`not_checked` 为实体档）、`mgmt.restriction_key`（形态受检）、`mgmt.payload`（7 取值，3 具名 payload）、`mgmt.supervised`（4）、`mgmt.key_source`（6）。
**信号口径**：`G01`—`G05` 五码（全部非阻断）；跨层联动 `N04`（锁屏面键与锁屏读数）、`A01`／`G04`（课程侧同意）、`D04`（键来源与执行域来源同档校验）、`S07`（枚举越界）。本层全部对外表述的上限是集合级：「这一族行为可被某个键约束」，不是「这台设备上这一帧被管住了」。

---

## 13. L10 公告对齐层：40 行子集、列间错位与平台行标注

### 13.1 子集极小，所以平台行标注是硬纪律

四个规模数逐字取自 `C/readings-19.txt:2—5`：公告 1,266 行组件×CVE 对（R01）、330 个去重 CVE（R02）、129 个去重组件名（R03）、12 个平台版本行（R04）。画面外流这一层的子集是：

| 读数 | 值 | 出处 |
| --- | --- | --- |
| R05 子集行数 | 40 | `C/readings-19.txt:8` |
| R06 子集去重 CVE | 13 | `:9` |
| R07 子集组件数 | 6（`IOMobileFrameBuffer` 4 行／`IOSurface` 8／`ReplayKit` 1／`Screen Sharing` 3／`Screen Sharing Server` 21／`WindowServer` 3） | `:10—16` |
| R08 子集 macOS 行／iOS 行 | 31／4 | `:27` |
| R09 其余平台行（tvOS 2／watchOS 2／visionOS 1） | 5 | `:24—28` |

**1,266 行里 40 行，约 3%；这 40 行里 macOS 平台行占 31 行，iOS 平台行占 4 行；本篇主线框架 `ReplayKit` 只有 1 行。** 这三条数合起来是一条写作纪律的来源：**本篇所有公告侧读数必须逐条带 `adv.platform_row` 标注，且不得写成 iOS 侧结论**。`adv.platform_row` 六档实体值（`iOS`／`iPadOS`／`macOS`／`tvOS`／`watchOS`／`visionOS`）按 `C/readings-19.txt:19—26` 那一份平台分布逐行对齐；版本号形态另按 `B/apple-platform-security-guide.txt:180` 那句「除特别注明外本指南覆盖的版本」做限定（`R06` 管 `adv.fix_version` 的纯数字点分形态）。

### 13.2 画面语义词在 impact 列几乎不存在

`C/readings-19.txt:31—44` 逐个给出 14 个词形的行级命中：**10 个词形命中 0 行**——`record`、`recording`、`captur`、`display`、`mirror`、`screenshot`、`broadcast`、`airplay`、`replaykit`、`iosurface`；有命中的四个是 `screen` 13 行、`peer` 6 行、`vnc` 6 行、`keystroke` 3 行。`adv.impact_word` 的七个实体档（`screen`／`keystroke`／`peer`／`vnc`／`record`／`display`／`mirror`）**就是照这一段词形表造的**，其中三档在本篇归档里恒为 0——这三档本篇保留的理由是"公开词形存在但公告不用"，登记成 `none` 时引用格写 `none`（确认无对应条目）而不是留空。

大小写会单独造出假读数，`C/readings-19.txt:45`（R10）给了一个三值演示：同一列里原样匹配大写 `VNC` 得 6；把整列小写化之后**仍用大写模式**匹配得 0——这条 0 是假读数；小写化＋小写模式得 6。因此 `adv.case_mismatch_checked` 只有 `yes` 一档可用，写下词形命中而未核对匹配形态即 `R05`（判据逐字：`词形命中未核对大小写匹配形态（假读数风险）`，依据句指向 `:45`）。

### 13.3 列间错位：467 行、0 行、0 个，以及 `screen` 那 13 行的 4 个组件

| 读数 | 值 | 出处 |
| --- | --- | --- |
| R12 含 `maliciously crafted` 的行 | 467 | `C/readings-19.txt:55` |
| R13 其中同时出现画面语义词的行 | **0** | `:56` |
| R14 crafted 行里组件名含 `screen` 的组件数 | **0** | `:57` |
| R11 `screen` 那 13 行的组件分布 | `Screen Sharing Server` 6、`Remote Management` 3、`smbx` 3、`Siri` 1，共 4 个组件 | `:48—52` |

这一组数是 L10 的中心事实：**公告侧的「恶意构造对象」这套词与本层这套词完全不在同一批行里相遇**。它给出三条台账纪律。(1) 按组件名筛选画面外流相关缺陷，会整批漏掉那 467 行；按影响文本筛选，会拿到组件名对不上的行——`adv.component_is_egress_layer` 的 `not_checked` 一档因此必须能显式写出来。(2) 那 4 个组件名（`DOC["R01"]` 逐字列出这四个）是 `adv.impact_word = screen` 唯一合法的组件集合，写下 `screen` 而组件不在这四个之内且未核对，即 `R04`。(3) 组件名属这六个子集之外、又没核对、又没补丁通道，即 `R03` 第二条（判据逐字：`组件名不属本层却用于确认结论：不在六组件子集内且既未核对也无补丁通道`）——六个组件名逐字取自 `C/readings-19.txt:11—16`，脚本一把它们原样建成子集表（含空格的 `Screen Sharing Server` 也在内），这也是 X08 一类词表形态检查在本篇的落点。

### 13.4 唯一一句直接写「看见画面」的影响句，以及「对」与「行」的差别

`C/readings-19.txt:63` 给 `Remote Management` 组件的 `CVE-2026-112480`，影响句逐字是：`A user with screen sharing access may be able to view another user's screen`。**这是全档案 1,266 行里唯一一句把「看见画面」写成后果的影响句**，而它所在的是 `Remote Management` 组件、不是本篇四个主线通道中的任何一个——本篇对它的用法止于此：登记为「公开口径里存在一句直接写画面被看见的影响句」，且必须与同行平台标注一起写。

同一组件的行数是 `C/readings-19.txt:60`（R15）：`Remote Management` 7 行、3 个去重 CVE（`:61—63` 三条影响句逐条给出，其中两条写的是 arbitrary code execution 与 unexpected system termination，与本层客体不同）。子集内的跨平台行数分布见 `:66—78`：`CVE-2026-112477` 8 行（R16，单 CVE 最大跨平台行数）、4 行的 1 个、3 行的 7 个、2 行的 1 个、1 行的 2 个。**这组分布正是本篇把归属单位定为「组件×CVE 对」而不是「行数」的理由**：同一 CVE 在 12 个平台版本行里最多占 8 行，按行数做统计会把一个缺陷数成八个。

### 13.5 KEV：95 条里 2 条，且没有一条把画面外流写在野利用后果里

`C/readings-19.txt:82—83`：Apple 条目 95 条（R17）、描述里出现画面语义词的 2 条（R18）。两条在 `:84—85`：`CVE-2026-65400`（macOS 平台行，improper authentication 一类）与 `CVE-2023-28206`（iOS、iPadOS 与 macOS 平台行，`IOSurfaceAccelerator` 的越界写一类）。**两条的描述都没有把「画面离开设备」写成在野利用的后果**——本篇据此把 `adv.kev_listed = yes` 与画面外流归属之间写成**无换算关系**：在 KEV 名单内只说明该缺陷被列名，不说明这一帧画面曾经离开。`R07` 拦的是一种台账内部矛盾：`adv.kev_listed = yes` 而 `adv.patch_channel = not_release`（判据逐字：`在 KEV 名单内却把补丁通道记为非发布`，依据句指向 `C/kev-apple.tsv:2` 那同行给出的 `dateAdded` 与 `dueDate`，以及 `C/readings-19.txt:83—85`）。

### 13.6 免交互措辞：本篇写作约束的实证

四组读数：`C/readings-19.txt:160`（R32）平台安全指南里出现免交互措辞的行 **2** 行，逐行在 `:161—162`——`:1442` 那行讲的是 BlastDoor 的设计目标、`:4681` 那行讲的是设备管理服务条目；`:163`（R33）公告 impact 列出现 `without user interaction` 或 `without user consent` 的行 10；`:164`（R34）出现 `without user permission` 的行 8；`:165`（R35）按组件为 `CoreMedia` 5、`WindowServer` 3、`AccessorySetupKit` 2；`:166`（R36）落在画面外流六组件子集内的行 **3**、去重 CVE 只有一个 `CVE-2026-112575`，三行逐字在 `:167—169`，影响句是 `An app may be able to monitor keystrokes without user permission`，**三行全部是 macOS 平台行**。

这一段是本篇写作约束的实证，而不是一个附注：`CoreMedia` 那 5 行写的是摄像头访问方向（与本篇客体相反）、`AccessorySetupKit` 那 2 行属配件配对（第 22 篇客体）、`WindowServer` 那 3 行写的是按键监听、且全在 macOS 行；指南里那 2 行一句属消息与身份服务的隔离设计、一句属设备管理服务的定义条目。**本篇公开读数里没有任何一句把「画面离开设备」写成不需要用户动作**，因此正文里发生时点只允许写成「打开／预览／分享这三类动作之后」或「录制／镜像／投屏这三类会话建立之后」。同时，`adv.*` 侧不写任何免交互触发路径，`R33`—`R36` 只作为「免交互措辞在本层只落在别的客体上」这一条边界登记。

### 13.7 台账字段与信号口径

**台账字段**：`adv.component`（自由文本，须落六组件或含 `screen` 的四组件之一才能给本层结论）、`adv.component_is_egress_layer`（5 取值）、`adv.cve`（`CVE-年-序号` 形态，`R02`）、`adv.kev_listed`（6 取值）、`adv.impact_word`（10 取值，7 个实体词形）、`adv.platform_row`（8 取值，6 个平台行）、`adv.case_mismatch_checked`（4 取值）、`adv.patch_channel`（7 取值，4 个具名通道）、`adv.fix_version`（形态，`R06`）。
**信号口径**：`R01`（有词形无组件）、`R02`／`R06`（形态）、`R03`（组件不属本层却用于确认，两条 emit 路径）、`R04`（`screen` 与四组件表不符）、`R05`（大小写未核对）、`R07`（KEV 与补丁通道矛盾），全部非阻断；`X02`（行号形态）与 `X01`（确认结论缺引用）在本层最常同时出现，因为公告行的引用格必须同时落文件与行号。

---

## 14. L11 引用与结论层：doc.* 与唯一的拒收空间 sec.*

### 14.1 三个字段与措辞层级

`doc.*` 是三个字段：`doc.source`（来源文件，必备格）、`doc.line_ref`（行号）、`doc.conclusion`（结论档）。`doc.line_ref` 只允许 `1234` 或 `6-9` 这一种形态——usage 第 42 行逐字写作「行号引用只写 1234 或 6-9 这一种形态，带『第／行』前缀的写法在两份台账之间不可换算」，写成「第 1429 行」这类带中文前后缀的形态即 `X02`（形态码，非阻断，只有与必备格缺失或 `S`／`K` 族同现时才落 `J4`）。为什么这条这么硬：两支脚本的引用格分别要求「公开词形值本身／`A/quicklook.txt:16` 这一形态的归档行号／`none`／`not_recorded`」（引号里那串只是 usage 给的**形态示例**，`quicklook.txt` 不在本归档 `A/` 的 15 件里，见第 23.6 节坑七），带前后缀的写法在两份台账之间不可换算——`X01` 的判据文案逐字就是「确认结论缺来源文件或行号」，依据句指向本文第 3.4 节失败点 8。

`doc.conclusion` 六档（4 个结论档加 2 个登记缺失档）的允许措辞层级，本篇写成一张从上到下的表：

| 档 | 允许与到哪儿为止 | 配套硬条件 |
| --- | --- | --- |
| `confirmed` | 「按公开口径，这一格成立」——**只到格，不到设备** | 必须同时有 `doc.source` 与 `doc.line_ref`（`X01`）；不得只由自述平面支撑（`O03`）；不得由不属本层的组件名（`R03`）或命中词形但不约束出流的键（`G02`）支撑 |
| `absent_in_ledger` | 「本篇归档里没有这一格的读数」 | 只能配 0 命中读数（如 `C/readings-19.txt:32—40` 那十个 0 行词形）或全表检索无命中；引用格落 `none` 表示确认无对应条目 |
| `not_determinable` | 公开口径存在但不足以定这一格 | 典型例：`B/…:4256` 后半句 `The user interface is implemented using a private API and is an extension that lives within the ReplayKit framework.` 只说明实现不在公开符号面上，因此这一格的 `host_process` 读回只能记这一档 |
| `assumed` | 假定，**只允许出现在合成夹具里** | 真实台账写下它即不进入对外表述，且与 `reproof_basis = assumed`（`V02`）、`warning_text_source = assumed`（`N03`）、`domain_source = assumed`（`D04`）三条同源 |
| `not_recorded`／`unknown` | 登记缺失档 | 与 `absent_in_ledger` 不同形：后者是查过且为无，前者是没查 |

判定档与本层的关系只有一条：`J1` 要求十二格齐备且无任何信号，`J4` 由 `S`／`K` 族或必备格缺失直接落——**`doc.*` 三格里唯一在必备清单上的是 `doc.source`**，但缺 `doc.line_ref` 的确认结论会被 `X01` 记账，本篇因此把「引用完整」当作 `J1` 的事实门槛而不是可选加严。

### 14.2 `sec.*`：第十二个空间，唯一用途是「触发了收」

`sec.*` 是脚本一十二个命名空间之外多出来的一个：usage 逐字写明 `sec.* 拒收用命名空间：本空间下任何字段都会触发 K01`，而 `K01` 在阻断表里——**出现即 `J4`、退出码 1**。这个空间不参与任何层的归属，它的存在只为了让一份写坏了的台账能被机器识别而不是被静默读成某个字段。

拒收清单逐条（前七条来自 brief 第 7 节的红线与脚本头部注释，后三条来自 `K02` 的形态正则，逐字为 `取值形似设备路径／长载荷／密钥串，拒收`）：

1. 真实用户检索词；
2. 可还原身份的语音描述；
3. 真实联系人、健康、位置样本；
4. 形似共享密钥或口令的取值——`glpat-`、`ghp_`、`AKIA`、`Bearer `、`-----BEGIN` 五个前缀（脚本内另含 `gho_` 与 `xox` 两个同源前缀）；
5. 设备绝对路径形态（`/Applications`、`/private`、`/var`、`/Users`、`/System` 起始，或含 `/var/mobile/`）；
6. 整段文件正文；
7. 超长度阈值载荷（长度大于 120 字符的取值）；
8. 形似 Base64 的长串（40 字符以上的 base64 字符集形态）；
9. 崩溃堆栈正文、日志正文或截屏正文（`K03` 的形态判据即为此而设）；
10. 真实设备标识、真实账户或真实课程标识。

本篇夹具全部为合成标识与合成取值，这一点在只读实证与覆盖验收里各核一遍（第 23 章 P4／P14 两段）。**拒收不是"删掉重登"的许可**：`K01`—`K03` 三码都要求删除该字段本身，本篇不提供任何把被拒收内容改写后重新登记的通道，因为改写后的取值仍然可能可还原身份。

### 14.3 本章是那条限制的落点

本篇能保证的是**判定过程可离线复算**：同一份台账文本、同一份归档、两支不联网不碰设备的只读脚本，任何人复跑得到同一组信号码与同一组判定档。本篇不能保证的是**登记内容与某台真实设备一致**：台账的输入是登记方写下的行，而不是设备状态——脚本一不读设备、不调用任何命令行工具（`file`／`mdls`／`mdfind`／`profiles`／`log`／`sysctl`／`plutil` 等名字在本篇只出现在头部拒收声明与 `K02` 形态判据两处）、不打开任何被登记的对象。这条限制必须写在引用与结论层，因为它约束的正是「这一句结论能说到哪儿」——它同时是第 17 章可见性边界与第 27 章结论段共同的口径来源。

### 14.4 台账字段与信号口径

**台账字段**：`doc.source`（必备格，只允许 `A/`／`B/`／`C/` 三份归档标识与公开词表值）、`doc.line_ref`（`1234` 或 `6-9`）、`doc.conclusion`（6 取值，4 个实体档）；`sec.*` 无合法字段。
**信号口径**：`X01`（确认结论缺来源文件或行号）、`X02`（行号形态非法）；拒收三码 `K01`／`K02`／`K03` 全部阻断；形态与结构码 `S01`—`S09` 全部阻断（行格式、命名空间、字段名、空值、枚举越界、重复登记、必备格缺失）。跨层联动：`O03`／`N03`／`D04`／`V02`／`G02`／`R03`／`R04` 七条都以 `doc.conclusion = confirmed` 或某一档劣化取值为触发条件——**本层是全部结论措辞的收口处**。

## 15. 归属矩阵：十一层 × 责任方 × 三件 × 证据

### 15.1 这张矩阵怎么读

矩阵是第 4—14 章的收束件，不是新证据。它有四列有信息量：**这一格归谁**（谁有权决定这一格的取值）、**属哪一件**（三件里的哪一件；混合的必须写清哪一半）、**公开证据**（哪一份归档件的哪几行真的承载这一格）、**缺它时落哪个号**（脚本一的大写字母族与档位、脚本二的对应码）。表中 `B/…guide.txt` 是 `B/apple-platform-security-guide.txt` 的缩写，`A/…` 与 `C/…` 锚点全部逐字取自 `IDX/sources-19.md` 与 `C/readings-19.txt` 里已核过的行号。

三条读法规矩：

1. 「这一格归谁」与「公开证据在哪个面」是两件事。本篇的中心事实正是这两列的错位：**授权权在用户与硬件、通道权在四条出流通道、后果观测权在通知面与公告面**，三段各有各的持有人，彼此不引用（15.3 节）。凡「归谁」写用户、「证据」写管理面或公告面的行，就是争议格。
2. 「缺它时落哪个号」只写脚本一里主守这一层的族（第 3 章的命名空间映射），同号不同义的族（C 族、D 族、K 族、V 族、X 族在两支脚本里判据不同）已在第 9.4、12.5 与 13.3 节交代，本表不重复消歧；`S09`（必备格缺失）与 `K01`—`K03`（拒收清单）是全层共用的两条，不在行内重复列。
3. 每一行的「属哪一件」必须能回指本章后面两节或第 4—14 章的某一句原文。混合归属只有 L2、L8、L11 三行，且都写成「哪一半属哪一件」；其余八行是单件表述。

### 15.2 矩阵

| 层 | 这一格归谁 | 属哪一件 | 公开证据（归档行锚） | 缺它时落哪个号 |
| --- | --- | --- | --- | --- |
| L1 会话与来源面标识 | 系统持有会话、登记方只能引（`A/uikit_uiscenesession.txt:13`、`:123`） | 采集件（入口与状态） | `A/uikit_uiscenesession.txt:13、123、137`；`A/replaykit_rpsystembroadcastpickerview.txt:11`；`B/…guide.txt:1429`；`C/readings-19.txt:124—125` | 一：B01—B06、S02；必备格 `id.session_kind`／`id.source_face` 缺任一即 S09 → J4；二：S02、会话类前缀 1:1 不成立即 Q4 |
| L2 授权与同意 | 用户（提示由框架呈现），管理面可代给出「不被提示」的同意 | 混合：存在性属告知件（`prompt_shown`），主体属采集件（入口资格） | `B/…guide.txt:4241`（`Before recording starts, ReplayKit presents a user consent alert…`）；`B/mdm-restrictions.txt:1018`；`B/…guide.txt:1439` | 一：A01—A06（`consent.granted_by` 缺 → S09 → J4）；二：K 族越界、T08（对外表述缺必需格） |
| L3 通道件 | 平台框架与守护进程；App 只在 in-app 那条通道上有份 | 落点件（`egress_path` 是九条出流路径枚举） | `B/…guide.txt:4242、4243、4248、4249、4257`；`A/replaykit_rpscreenrecorder.txt:13`；`A/replaykit_rpbroadcastsamplehandler.txt:12` | 一：C01—C09（`chan.egress_path`／`chan.process_owner` 缺 → S09 → J4）；二：通道件七项、T03、T06 |
| L4 执行域与隔离 | 平台；登记方只有引用权 | 采集件（`process_owner`、`isolation_mechanism`） | `B/…guide.txt:4250、1431、1374、3901、4157`；`A/uikit_uiwindow.txt:18` | 一：D01—D06、C06（`dom.domain_class` 缺 → S09 → J4）；二：K01—K05、P05 |
| L5 落点与存储 | 写域由平台划定（ReplayKit 子系统独占目录），落点由会话类决定 | 落点件（`landing_destination` 是唯一数组型核对项） | `B/…guide.txt:4244、4257`；`A/replaykit.txt:5`；`A/replaykit_rpbroadcastconfiguration.txt:3` | 一：E01—E05（`land.destination` 缺 → S09 → J4）；二：落点件五项、T01、P02 |
| L6 观测平面 | 登记方选择平面；平面本身不承载事实 | 三件共用（本层是坐标系、不是读数源，故不属任一件） | `B/…guide.txt:1429、2262、708`；`A/uikit_uiscene.txt:199、217`；`A/replaykit_rppreviewviewcontroller.txt:153` | 一：O01—O04（`obs.plane` 缺 → S09 → J4）；二：P01—P07 全部发生在本层 |
| L7 告知 | 系统呈现提示与通知；App 不能决定是否弹 | 告知件（八项核对项的全部） | `B/…guide.txt:4241、1429、1439、708、2262`；`C/readings-19.txt:98—100`（`allowLockScreen*` 三键） | 一：N01—N05（`notice.prompt_shown` 缺 → S09 → J4）；二：布尔位七项、P06、P07 |
| L8 复位与再核对 | 登记方执行、系统判定、残留归观测 | 混合：三个停止口的存在性属采集件，`reset_method` 取值属告知件 | `A/replaykit_rpscreenrecorder.txt:240、251、267、88、90、97`；`C/kev-apple.tsv:2` | 一：V01—V04（`undo.reset_method` 缺 → S09 → J4，全为非阻断）；二：T08、P04 |
| L9 管理面回查 | MDM 管理员（下发键）；Apple（写键的口径） | 落点件（键只决定通道开不开，不决定画面被谁取走） | `C/readings-19.txt:88—94、95—107、110—121`；`B/mdm-restrictions.txt:29、726、729、766、965、969、1018` | 一：G01—G05（`mgmt.mdm_configurable` 缺 → S09 → J4）；二：K 族限制键形态、M04 |
| L10 公告对齐 | Apple（发布组件×CVE 行）；本篇只有回查权 | 采集件的外部旁证（进程归属，无落点列、无告知列） | `C/readings-19.txt:2—5、8—10、27—28、55—57、60—63、82—85、163—169`；`C/advisory-19.tsv:1` | 一：R01—R07（`adv.*` 不在必备格里，缺格只落非阻断）；二：X01—X08、V06 |
| L11 引用与结论 | 登记方写引用，校验阶段落回归档行号 | 三件共用（引用格式层，本身不成一件） | `IDX/sources-19.md` 两条抽取器限制；`C/readings-19.txt:45`（大小写三态） | 一：X01—X02、K02—K03（`doc.source` 缺 → S09 → J4）；二：V01—V06 |

### 15.3 三段判定权彼此不引用

本篇的立论基是三段判定权各自独立、且互相不引用（`IDX/overlap-19.md` 主键选择依据一节）：

- **授权权**在用户与硬件：`A/replaykit.txt:5` 那句把「录下来」与「发出去」写进同一句、`B/…guide.txt:4241` 的同意对话框按 App 进程各呈现一次、`:1439` 那句 `The Secure Enclave on the Mac enforces this user choice` 由 Mac 侧执行用户选择。
- **通道权**在四条出流通道：录制落 `:4244` 的独占目录、广播经 `:4249` 的端点配置交扩展、镜像在 `:1429` 的「iPhone 保持锁定」前提下被 Mac 远用、投屏与伴生显示走 `:1374` 的 MFi-SAP。
- **后果观测权**在锁屏持久通知与会话结束横幅（`:1429`）、macOS 权限清单里的 `Screen recording` 一类（`:2262`）、管理面 13 个画面语义键（`C/readings-19.txt:92`）与公告组件名四处。

三段各自能缺，且任何一段都不给另外一段背书：**授权发生过，但任何一面读不回「这一次带走了什么」；通道存在，但画面可能被系统自己截走；公告写了 `screen`，却没有一行写画面数据类型**。这就是矩阵里 L2、L3 与 L6—L7 四行「归谁」与「证据」不同源的原因。

### 15.4 三件两两不闭合的三个方向与矩阵的不读法

三件在本篇不是一对一闭合的，三个方向各有实证，且都是同一份归档里的句子：

1. **采集件与落点件不闭合（同一节里两条相反通道）**。`B/…guide.txt:4242` 明写 `This is designed to ensure the recorded content is never accessible to the app process`，紧邻的 `:4243` 又明写 `This allows an app to get video and sample buffers, which is guarded by the permissions dialogue`。同一节里既写「App 进程永不可见」，又写「App 能拿到缓冲」——采集件因此不是一个值而是两条通道，台账必须指名走的是哪一条（脚本一 C01 的判据）。
2. **采集件与告知件不闭合（预览面对 App 不可读）**。`:4245` 的预览与分享界面 `presented out-ofprocess`（归档行内写作 `out-ofprocess`），由 ReplayKit 而非承载 App 呈现；`A/replaykit_rppreviewviewcontroller.txt:153` 又把预览面与分享面做成一个枚举里的二选一。用户在预览面上看见了画面，这一格从 App 侧读不回来——告知件的读数面与采集件的持有人不是同一个进程（脚本一 C09、脚本二 P06 的落点）。
3. **落点件与告知件不闭合（通道准入不是运行授权）**。`:4249` 的两个扩展要配置 `com.apple.broadcast-services` 端点才参与广播，这是**通道准入**；代码运行授权是第 14 篇的客体，两者在台账里分列两格。反过来说，端点配上了、扩展挂上了，也不产生任何「用户被告知了」的读数（`:4250`：`Only ReplayKit and the third-party broadcast extensions have access`）。

矩阵的不读法必须写清四条：

- **本矩阵不给任何某台设备上的实况结论**。它给的是「这一格的值应当由谁写、在哪个面读回、缺位时落哪个号」；某台具体设备上某一帧画面是否离开，本篇既无口径也无手段（第 2 章视角声明）。
- 矩阵不表示因果。L2 授权发生过不推出 L3 通道生效，L10 公告有行不推出 L5 落点在 iOS 上——子集 macOS 31 行、iOS 4 行（`C/readings-19.txt:27`）这条分布就是反例。
- 矩阵不表示权重。缺格判定按必备 12 格定位、按信号计数定档，不是「按层加权」：12 格分布在 10 层里，只有 L10 公告对齐层一格都没有，所以公告侧缺读数只落非阻断码，而 L1、L3 两层的任一必备格缺位立即 J4。
- 矩阵不替代第 19 章的两套判定档。同一对象可以 J1 而 Q4：台账写满且形态合规，但会话类未建模（`not_recorded`／`unknown`）时，逐值判定不发生，只落 D04 与 Q4。**对外表述必须同时给两档**。

---

## 16. 公开读数：这条通路上能数出来的十三组事实

### 16.1 读数纪律

十三组全部来自 `C/readings-19.txt`（169 行，十三组、36 个 R 号），派生器是 `tools/readings19.pl`；输入是本轮抓下来的公开档案件（公告 TSV、KEV TSV、MDM 键表与 Restrictions 页、平台安全指南、接口文档）。**读的是档案文本，不是设备、不是任何被登记的对象**，也不调用任何命令行工具去判定某个文件。三条计数规矩逐组适用：**行级与去重级分开说**（公告粒度是组件×CVE 对）；**命中口径就是派生器里那一个正则，且必须写匹配形态**（第 4 组给一条显式演示）；**读数只支撑集合级结论**，不支撑个体级结论。`C/readings-19.err` 与 `C/advisory-19.err` 均为空文件（0 行），这一件事本身进第 23 章验收表。

### 16.2 十三组

**第 1 组 语料规模（`:1—5`）**：数出来的是公告基线的四个分母。R01 组件×CVE 对 **1266** 行、R02 去重 CVE **330**、R03 去重组件名 **129**、R04 平台版本行 **12**（`C/readings-19.txt:2—5`）。能支撑：后面十二组的分母，以及「六列里没有来源列、没有画面数据类型列」这一结构性事实。不能支撑：任一具体设备上的暴露面大小——1266 是档案行数，不是风险条目数。

**第 2 组 画面外流组件子集（`:7—16`）**：六个组件名逐字匹配的三量与逐组件行数。R05 **40** 行、R06 **13** 个去重 CVE、R07 **6** 个组件；逐组件 `IOMobileFrameBuffer` 4、`IOSurface` 8、`ReplayKit` 1、`Screen Sharing` 3、`Screen Sharing Server` 21、`WindowServer` 3（`:11—16`）。能支撑：**本层公告侧的子集极小，且唯一与 iOS 接口同名同形的组件 `ReplayKit` 只有 1 行**——这就是第 13 章把公告对齐层写成旁证层而不是结论层的理由。不能支撑：把 21 行的 `Screen Sharing Server` 读成 iOS 侧结论（它是 macOS 侧服务名）。

**第 3 组 子集的平台分布（`:18—28`）**：九个平台版本行的逐行分布（iOS 26.7.2 and iPadOS 26.7.2 1、iOS 27.2 and iPadOS 27.2 3、macOS Golden Gate 27.2 11、macOS Sequoia 15.8.2 10、macOS Tahoe 26.7.2 10、tvOS 27.2 2、visionOS 27.2 1、watchOS 27.2 2，`:19—26`）。R08 **macOS 31 行、iOS 4 行**，R09 其余平台（tvOS／watchOS／visionOS）**5 行**（`:27—28`）。能支撑：本篇「公告侧读数一律标注平台行」这条硬约束的实证。不能支撑：**任何一条 macOS 行都不许写成 iOS 结论**；4 行 iOS 也不足以支撑「iOS 侧的修复覆盖」这类句法。

**第 4 组 impact 列的画面语义词形（`:30—45`）**：14 个词形扫 1,266 行影响句的逐词行数。有命中的只有 `screen` **13**、`peer` **6**、`vnc` **6**、`keystroke` **3**；`record`／`recording`／`captur`／`display`／`mirror`／`screenshot`／`broadcast`／`airplay`／`replaykit`／`iosurface` **全部 0 行**（`:31—44`）。R10 是大小写三态演示：**原样匹配大写 `VNC` 得 6；把整列小写化后仍用大写模式匹配得 0（这是一条假读数）；小写化＋小写模式得 6**（`:45`）。能支撑：本层词表 14 个词形里 10 个命中 0 这一负空间，以及第 23 章「每个命中数都要写清匹配形态」的验收条款。不能支撑：0 命中不等于不存在——公告的措辞由发布方选，`mirror` 为 0 不表示没有镜像类缺陷，只表示公告没有这样写。

**第 5 组 含 screen 的行的组件分布（`:47—52`）**：R11 **4** 个组件，逐组件 `Screen Sharing Server` 6、`Remote Management` 3、`smbx` 3、`Siri` 1（`:48—51`）。能支撑：`screen` 一词在公告里是**屏幕共享与远程管理语义**，不是画面采集语义；`Siri` 那 1 行写的是屏上文本，与画面流无关（`IDX/overlap-19.md` 第 17 篇边界行）。不能支撑：把这四个组件名当成本篇九条出流路径的组件映射——本篇不建立「通道类↔组件名」映射（这是第 15 篇方法的迁移，见重叠审计行）。

**第 6 组 crafted 口径与本层的交集（`:54—57`）**：R12 impact 含 `maliciously crafted` 的行 **467**、R13 其中同时出现画面语义词的行 **0**、R14 crafted 行里组件名含 `screen` 的 **0** 个。能支撑：内容侧口径与出流侧口径互不相通——这是本篇从第 18 篇接过来的那条 0，第 18 篇把它读成「类型判定与解析层词形错位」，本篇把它读成「内容缺陷与画面外流是两套公告语义」。不能支撑：**467 与 0 都不能换算成本层风险**，467 是分母、0 是交集，两者都不是缺陷计数。

**第 7 组 Remote Management 同页跨面读数（`:59—63`）**：R15 组件行 **7** 行、去重 CVE **3**；三条影响句逐字：`A remote attacker may be able to cause arbitrary code execution`（CVE-2026-112427，`:61`）、`An attacker on the local network may be able to cause unexpected system termination or corrupt process memory`（CVE-2026-112457，`:62`）、`A user with screen sharing access may be able to view another user's screen`（CVE-2026-112480，`:63`）。能支撑：本篇唯一一句直接写「看见画面」的公告影响句存在，且它落在 `Remote Management` 这一格。不能支撑：把这个组件读成 ReplayKit 或镜像通道——同组件 7 行里两条与画面无关（18.7 节据此写「五个面互不通气」）。

**第 8 组 单 CVE 跨平台行数分布（`:65—79`）**：R16 子集内单 CVE 最大跨平台行数 **8**（CVE-2026-112477），其后 4 行一例、3 行七例、2 行一例、1 行两例（`:66—78`，其中 CVE-2026-112575 占 3 行）。能支撑：X02／R02 的形态约束——**一个 CVE 在档案里不是一个唯一定位，跨行换算必须带平台版本行**；本篇所有 CVE 引用一律写「编号＋行数」两个量。不能支撑：**行数不得当 CVE 数用**，8 行不等于 8 个缺陷。

**第 9 组 KEV 与本层（`:81—85`）**：R17 KEV Apple 条目 **95** 行、R18 描述含画面语义词的条目 **2** 条：`CVE-2026-65400`（平台列 `macOS`，`Apple macOS contains an improper authentication vulnerability that could allow an attacker on th…`）与 `CVE-2023-28206`（平台列 `iOS, iPadOS, and macOS`，`Apple iOS, iPadOS, and macOS IOSurfaceAccelerator contain an out-of-bounds write vulnerability t…`），逐条在 `:84—85`（两处行尾均为读数器截断，正文不补全）。能支撑：KEV 侧的独立一档读数（`adv.kev_listed`），以及 `C/kev-apple.tsv.meta.txt` 的 `catalogVersion`／`dateReleased`／`count` 三行分母口径提示（**分母是全目录条目数，不是 Apple 条目数**）。不能支撑：**KEV 没有一条把「画面外流」写成在野利用后果**——两条命中分别是认证缺陷与越界写，与本层的出流语义无关；`dateAdded`／`dueDate` 只给日期形态，不给画面离开设备的证明。

**第 10 组 MDM 限制键总表（`:87—107`）**：分母链 R19 表内总行 **220** → R20 形态命中 **218** → R21 首字母小写 **216** → R22 形态命中里不是键名的 **8** 行（六个平台名 + `Important`／`Note`），**纯键名分母 210** → R23 画面语义词（`screen`／`airplay`／`record`／`observ`／`mirr`）命中键 **13** → R24 `allow*` 前缀 **9**、`force*` 前缀 **4**。R25 十三个键逐字清单（`:95—107`）：`allowAirPlayIncomingRequests`、`allowAutomaticScreenSaver`、`allowCallRecording`、`allowLockScreenControlCenter`、`allowLockScreenNotificationsView`、`allowLockScreenTodayView`、`allowRemoteScreenObservation`、`allowScreenShot`、`allowiPhoneMirroring`、`forceAirPlayIncomingRequestsPairingPassword`、`forceAirPlayOutgoingRequestsPairingPassword`、`forceBypassScreenCaptureAlert`、`forceClassroomUnpromptedScreenObservation`。能支撑：**210 个键里真正约束画面出流的只有其中数键**，`allowAutomaticScreenSaver`／`allowCallRecording`／三个 `allowLockScreen*` 是**同词不同义**（屏保、通话录音、锁屏控件，均不管画面离开设备，G02 的判据）。不能支撑：本篇**不说明也不建议使用任何一键的开关效果**，`forceBypassScreenCaptureAlert` 只作为「策略可以改变同意对话框是否出现」这一格的存在形态登记，不给使用方式与规避法；分母 210 与第 18 篇同一口径，两篇可交叉引用而不换算。

**第 11 组 Restrictions payload 页（`:109—121`）**：R26 页内 **1530** 行、R27 说明句含画面语义词 **9** 行（逐行 `:112—120`：29、726、729、766、965、969、1018、1392、1393）、R28 以 `CODE|` 形态出现的键名行 **299**。能支撑：**说明句流与键名流分属两段**（1—1230 行 vs 1231—1530 行），说明句里的「If ⟨键⟩, the system disables …」在这一份归档里回溯不到键名——这是管理面自身错位的实证（18.5 节）。其中 `:766` 那行是关键读数：一个键同时禁用保存截图、屏幕录制采集与 Classroom 远屏观察；`:1018` 那行是第二关键读数：受管理课程里的学生自动给出同意且不提示。不能支撑：把这两句读成任何可操作的配置步骤，本篇**不给规避管理面审计的做法**；299 也不是键的总数，`CODE|` 行有重复。

**第 12 组 平台安全指南的本层段落（`:123—157`）**：R29 归档总行数 **4886**（读数器口径；`IDX/sources-19.md` 记该件为 4,885 行文本，两处口径差一行，正文一律以读数器口径引用并保留 `C/readings-19.txt:124` 这一行锚）、R30 命中本层语义词 **31** 行、R31 其中 iPhone Mirroring 提及 **6** 行、ReplayKit **13** 行、AirPlay **5** 行。31 行的逐行清单在 `:126—156`，含 1374、1381、1428—1431、1438—1439、2262、3261、3575、3901、4157 与 4237—4257 全节。能支撑：本篇三条主线段落的密度差异——**系统口径侧是本篇唯一有正向密度的面**，40 行公告 vs 31 行系统口径 vs 9 行管理面说明句。不能支撑：4886 与 31 都不是覆盖率；`A/` 侧另有 3 件 404 已记 SKIPPED（`broadcastappextension`、`replaykit/rpbroadcastmanager`、`uikit/uiview/drawhierarchy`），正文不引，因此 31 行命中不能算作「指南对本层的完整表述」。

**第 13 组 免交互措辞的分布与子集交集（`:159—169`）**：R32 平台安全指南里出现免交互措辞的行 **2**（`:161—162` 的 1442 BlastDoor 与 4681 词条，两处都属别处语义）、R33 公告 impact 含 `without user interaction`／`without user consent` 的行 **10**、R34 含 `without user permission` 的行 **8**、R35 按组件 `CoreMedia` 5、`WindowServer` 3、`AccessorySetupKit` 2、R36 落在画面外流子集内的行 **3**，且**三行同一个 CVE——`CVE-2026-112575`**（`:167—169`，三行平台列全为 macOS，影响句逐字 `An app may be able to monitor keystrokes without user permission`）。能支撑：本篇写作约束的实证——**本层公开读数里没有任何一句把「画面离开设备」写成不需要用户动作**；`CoreMedia` 那 5 行写的是摄像头访问（与本层方向相反），`AccessorySetupKit` 那 2 行属配件配对（第 22 篇客体）。不能支撑：由 10 行或 8 行推出任何免用户动作的画面外流路径；正文出流时点只允许写成「打开／预览／分享这三类动作之后」或「录制／镜像／投屏这三类会话建立之后」。

### 16.3 三组容易读错的数

- **467／0／0 不是「公告里没有画面缺陷」**。`:55—57` 三个数分别是 crafted 行数、其中含画面语义词的行数、crafted 行里组件名含 `screen` 的组件数。它说的是两套措辞在 impact 列不相遇；`:63` 那句直接写「view another user's screen」的影响句恰好不含 `maliciously crafted`，就是这条错位的正面实例。
- **216 与 210 的差是口径而不是漏写**。R21 的 216 是「形态命中且首字母小写」，R22 的 210 是「形态命中里去掉 8 个非键名行」；`B/mdm-restriction-keys.txt:1—4` 的四个分段标题也在 218 之内。第 10 组的分母链只能整段引用，不可截取其一部分作「键数」。
- **95 与 2 的比不写成比例**。KEV 的 Apple 条目 95 是分母，画面语义词命中 2 条；本篇不写「2/95 = 2.1%」，因为 2 的判据是描述列含画面语义词，而 95 的判据是 `vendorProject == Apple`——两个判据不同层，比值无语义。

### 16.4 十三组与章的映射

| 组 | 主要落点 | 作为分母或判据的码 |
| --- | --- | --- |
| 1 语料规模 | 16 全章、13.1 | R01／R02（一） |
| 2 画面外流子集 | 13.2、15.4 | 一：R03；二：X03 |
| 3 平台分布 | 2 章红线、13.4 | 一：R06 |
| 4 词形与大小写 | 3.2 词表、23 验收 | 一：R05；二：M 族 |
| 5 含 screen 的组件 | 15.4、18.7 | 一：R01 |
| 6 crafted 交集 | 3.4 失败点、18.6 | 一：R04；二：X04 |
| 7 Remote Management | 18.7 | 一：R02 |
| 8 跨平台行数 | 13.3 | 一：R07、X02；二：X02 |
| 9 KEV | 13.2、17.2 | 一：V03、S08 |
| 10 MDM 键表 | 12.1—12.4、18.5 | 一：G01—G05；二：K 族、M04 |
| 11 Restrictions 页 | 12.3、18.5 | 一：G03、G04 |
| 12 PSG 段落 | 4—11 章全部、18.2—18.3 | 一：A／C／D／E／N／O 族 |
| 13 免交互分布 | 2 章红线、24 章误区 | 一：A02、E04 |

---

## 17. 可见性边界：这一层读者能拿到什么

### 17.1 四类读者各自的可见量

本篇把「可见性」定义成**读者档位**，不是责任档位。四类读者在同一格上的可见量差别极大：

| 读者 | 能拿到 | 拿不到 |
| --- | --- | --- |
| 审计方（离线复算者） | 两份归档件的全部行、36 个 R 号读数、两支脚本的输入与输出；任何一格的「有没有公开口径承载它」 | 某台设备上某一帧画面的实际去向（无手段、无口径）；`replayd` 进程内的任何字节 |
| 设备主（用户） | 锁屏持久通知与会话结束横幅（`B/…guide.txt:1429`）、同意对话框（`:4241`）、预览与分享界面（`:4245`）、相机指示灯（`:708`）、控制中心里的镜像与投屏入口 | 「录下来的那一段现在在谁的机器上」；广播侧上行数据的任何读数（`:4250` 之后与 App 无关） |
| 管理方（MDM） | 13 个画面语义键的下发状态（`C/readings-19.txt:95—107`）、Restrictions 说明句 9 行（`:112—120`）、`mdm_declaration`／`configuration_profile` 两个平面 | 告知状态（键下发不等于用户被提示，N04 判据）、采集入口、落点目录里的对象 |
| App（承载方） | 自己走 in-app 通道时的 sample buffer（`:4243`）、录制完成回调与预览对象（`A/replaykit_rppreviewviewcontroller.txt:11`） | 出进程采集的内容（`:4242`）、广播内容（`:4250`）、影片文件（`:4244`）、HomeKit 视频帧与截屏（`:4157`） |

一句话概括这张表：**四行里只有「设备主」与「管理方」拿到的东西互不覆盖，而 App 拿到的最少**——本篇的归属分析因此天然是三段拼合，不是任一段独立完成。

### 17.2 五处承重口径句

边界不是推论，是这五句逐字口径立的：

1. `:4242`：`This is designed to ensure the recorded content is never accessible to the app process.`（采集件在 App 侧不可见）
2. `:4250`：`The architecture helps ensure that hosting apps have no privileges to the broadcasted video and audio contents.` 后半句 `Only ReplayKit and the third-party broadcast extensions have access.`（广播侧只有 ReplayKit 与第三方广播扩展有访问权）
3. `:4244`：`The movie file is written to a directory that's only accessible to the ReplayKit subsystems and is never accessible to any apps.`（影片目录任何 App 都不可访问）
4. `:4245`：`The user has the ability to preview and share the movie with a user interface vended by ReplayKit.`，预览与分享界面 out-of-process 呈现（告知面的持有人不是 App）
5. `:4157`：`As a result, the app is unable to access or store the video stream.` 同句另写 `In addition, apps aren't permitted to capture screenshots from this stream.`（HomeKit 帧由独立系统进程渲染，且不允许截屏——本层唯一一处「既不可存取也不可截」的双重口径）

`:2262` 与 `:708` 各补一条：macOS 权限清单把 `Screen recording` 与 `Input monitoring` 并列为一类可核对状态；`:708` 那句写明不可信软件即使取得 root 或内核权限也无法在不点亮屏上指示灯的前提下启用摄像头——**本层唯一一处「采集必须可见」的硬件级强口径**，且它是 Mac 侧句子，不得换算为 iOS 结论。

### 17.3 「判定正确」只能写成间接三段

因为 17.2 的五句把直接读数全部划给了 App 之外，本篇能给出的「判定正确」只能是三段间接表述，缺一不成立：

1. **三件对齐**（脚本二 Q1）：同一会话的采集件、落点件、告知件核对项彼此不矛盾、能力表要求的格都在。
2. **平面可得性**（能力表第三列的 required／optional／not_applicable／undocumented 四值）：这一格在本会话类下是否可由该平面读回；`undocumented` 是本篇承认边界的位置。
3. **引用落回归档行号**（`doc.source` + `doc.line_ref`，脚本一 X02）：这一格凭哪一句公开口径写。跨面结论必须同时给出两侧的平面名、字段与行号，否则按 X01 处理。

三段齐备只能说到「这一格与公开口径一致且内部不矛盾」，**永远到不了「这一帧画面确实离开了这台设备」**。这就是第 2 章「本文能保证判定过程可离线复算，不能保证登记内容与某台真实设备一致」的由来。

### 17.4 边界清单在第 26 章的位置

本节的负空间逐条进第 26 章未公开文档化边界清单，接口位置固定在三处：**第 26 章每条边界必须给「本篇归档里检索过的词形与命中行数」**（无命中要写 0 行而不是省略）、**给「它为什么不是漏写」**、**给「台账里这一格应当填什么」**（`not_recorded`／`not_applicable`／`undocumented` 三值之一，C 档不成行）。本篇进第 26 章的候选在 17.2 与 16.2 已定位：`record`／`mirror`／`screenshot`／`broadcast`／`airplay` 五个词形在 impact 列 0 行、iOS 侧的采集指示口径（`:708` 是 Mac 句）、广播上行的留存口径（`:4250` 之后无人写）、`A/` 侧 3 件 404 造成的符号空缺。

---

## 18. 五个读数面：接口侧、系统口径侧、告知侧、管理侧、公告侧

### 18.1 把 26 个读数平面切成五面

第 9 章按「平面承载哪一件」分组定 `obs.plane` 的合法值；本章按「读者从哪一侧去看」重切一次定对外表述。**切分对象是脚本二 usage 第 40—44 行的 26 个读数平面，每面只归一侧，五个实面加兜底档计数相加必须等于 26**：

| 面 | 数 | 平面 |
| --- | --- | --- |
| 接口侧 | 6 | `api_reference`、`extension_doc`、`replayd_surface`、`vehicle_display`、`carplay_template`、`external_screen` |
| 系统口径侧 | 2 | `platform_doc`、`daemon_doc` |
| 告知侧 | 7 | `in_app_alert`、`control_center_toggle`、`broadcast_picker`、`pairing_prompt`、`lock_screen_notice`、`camera_indicator`、`notice_sheet` |
| 管理侧 | 3 | `settings_ui`、`configuration_profile`、`mdm_declaration` |
| 公告侧 | 5 | `advisory_entry`、`kev_entry`、`crash_report`、`vendor_claim`、`app_self_report` |
| 兜底档 | 3 | `none`、`not_recorded`、`unknown` |

6 + 2 + 7 + 3 + 5 + 3 = 26 ✓。三个兜底值单列一档，是因为它们**不是读数面而是「这一格没有面」的登记值**；把 `none` 归进任何一侧都会让 P01（已读数无平面）失去判据。

### 18.2 接口侧

**能读回**：L1 的会话与来源面标识（`id.session_kind`／`id.source_face`）、L3 的采集入口与并发上限、L5 的落点接口存在性。**形态**：`A/` 15 件归档件（92,938 字节、3,726 行，`IDX/sources-19.md` 组 A 表），由 `tools/jsondump.pl` 从 Apple 文档 JSON 派生；关键锚 `A/replaykit.txt:5、71`、`A/replaykit_rpscreenrecorder.txt:11、12、13、88、240、251、267`、`A/replaykit_rppreviewviewcontroller.txt:11、153`、`A/replaykit_rpsystembroadcastpickerview.txt:11、12、13`、`A/uikit_uiscenesession.txt:13、123、137`、`A/uikit_uiwindow.txt:18、432—482`、`A/carplay.txt:5`、`A/carplay_cpinterfacecontroller.txt:26`。**限制**：JSON 抽取器在 doc-link 处断行，`A/replaykit.txt:5` 与 `A/replaykit_rpscreenrecorder.txt:13` 都是断句行，**正文只引每行完整前半句，不跨行拼句**；另有 3 件 404 记为 SKIPPED，接口侧因此有已知的符号空缺。**失效形态**：`A/` 侧的句被抄到公告侧平面 → P03；复位口记在采集面 → P04；采集入口记在不符合的面上 → P05（脚本二按会话类的入口—平面映射逐值判）。

### 18.3 系统口径侧

**能读回**：L4 执行域与隔离、L5 写域、L3 通道语义（本篇唯一有正向密度的面）。**形态**：`B/apple-platform-security-guide.txt` 三条主线段落——ReplayKit 全节 `:4237—4257`（含 4241／4242／4243／4244／4245／4248／4249／4250／4256／4257）、iPhone Mirroring 段 `:1428—1439`（含 1431 的点对点身份交换与 1438—1439 的远程解锁）、AirPlay 与伴生显示段 `:1374—1381`（含 1381 把「解锁」与「被看见」写进同一条目）。相邻的四处边界句 `:4157`（HomeKit）、`:3261`（Tap to Pay 禁一切截图录屏）、`:3575`（ID Verifier Display Only 同）、`:708`（Mac 指示灯）只用来划界不作结论。**失效形态**：把 `:2262` 或 `:708` 的 macOS 句换算成 iOS 结论（一：O03／O04 的判据；二：V06 阻断）；把 `:4242` 与 `:4243` 两句合并成一条通道（一：C01 阻断）；`:4249` 的端点写成非点分段形态（一：C06）。

### 18.4 告知侧

**能读回**：L7 八项告知核对项与 L6 的观测平面选择；本篇的「画面离开过」在用户面上只有这一侧的三种形态——**锁屏持久通知**（`:1429`：`While being remotely used on the Mac the iPhone remains locked and users see a persistent notification on the iPhone's Lock Screen.`，同节 `:1429` 另写会话结束后首次解锁时显示横幅）、**会话提示与选择器**（`:4241` 的同意对话框、`A/replaykit_rpsystembroadcastpickerview.txt:11` 的按钮—选择器链）、**指示灯**（`:708`，Mac 侧硬件口径）。**失效形态**：告知件核对项记在接口引用面上 → P06（告知与受管口径的读数在管理面文档，不在接口文档）；画面来源面是 `classroom_app`（受管发起）而告知格从 App 内提示面读回 → P07；`lock_screen_notice` 与 `allowLockScreenNotificationsView`（`C/readings-19.txt:99`）同时成立 → 一：N04 阻断（锁屏通知面可被管理面关掉，「锁屏不可见」与「从锁屏通知读数」不能同时成立）。

### 18.5 管理侧

**能读回**：L9 的 `mgmt.mdm_configurable` 与 13 个画面语义键的下发状态。**形态**：两份 MDM 归档件的**两流错位**——`B/mdm-restriction-keys.txt` 只给键名（220 行、形态命中 218、纯键名分母 210，`:89—91`），`B/mdm-restrictions.txt` 把说明句流（1—1230）与 `CODE|` 键名流（1231—1530，299 条）分在两段，因此说明句里的 `If ⟨键⟩, the system disables …` 在这一份归档里回溯不到键名（`IDX/sources-19.md` 抽取器限制第 2 条）。两处关键句：`:766`（一个键同时禁用保存截图、屏幕录制采集与 Classroom 远屏观察）与 `:1018`（受管理课程的学生自动给出同意且不提示）——后者登记的是「管理面可以替用户给出『不被提示』的同意」这一格的公开口径，本篇只陈述它，不给任何使用方式与规避做法。**失效形态**：落点件核对项记在采集指示灯面上 → P02；限制键形态写成带空格、斜杠或点分段的串 → 一：G05、二：K 族；子约束键没写挂在哪份 payload 下 → 一：G03（`:726` 那句 `Nest this key beneath … as a subrestriction.`）；键名命中词形但语义不属本层 → 一：G02（同词不同义五键）。

### 18.6 公告侧

**能读回**：L10 的组件×CVE 集合、KEV 的在野名单与日期形态；`C/advisory-19.tsv` 六列 `file`／`platform`／`component`／`cve`／`impact`／`avail`（`:1`，1,266 条）与 `C/kev-apple.tsv` 七列 95 条 Apple 条目加 `.meta.txt` 三行目录元数据。**注意六列里没有来源列、没有落点列、没有告知列，也没有画面数据类型列**——这是公告侧的结构性上限，不是本篇的检索缺陷（第 4 组 14 个词形 10 个 0 行）。**失效形态**：把组件名当采集入口 → 一：R03／R04，二：P03（公告六列里没有采集入口列）；把行数当 CVE 数 → 一：R07、X02；平台行未标注就下 iOS 结论 → 一：R06，二：V06；`kev_entry` 承载机制结论 → 一：K03 类拒收（观测面只登记报告标识，不粘贴堆栈、日志或截屏正文）。

### 18.7 五个面互不通气的实证

本篇最干净的一条实证在第 7 组：`Remote Management` 这个组件的 7 条公告行、3 个去重 CVE，三行三句互相不认识——`CVE-2026-112427` 写远程攻击者导致任意代码执行、`CVE-2026-112457` 写本地网络攻击者导致系统意外终止或进程内存损坏、`CVE-2026-112480` 写 `A user with screen sharing access may be able to view another user's screen`（`C/readings-19.txt:61—63`）。**同一个组件名下，两条与画面完全无关、一条直接写「看见别人的画面」**；公告侧给不出这三行之间哪一条走了本篇九条出流路径里的哪一条，接口侧的 `A/` 15 件里也没有名为 `Remote Management` 的对象，管理侧的 13 键里同样没有一个键叫这个名字（`allowRemoteScreenObservation` 管的是 Classroom 远屏观察，`C/readings-19.txt:101`）。

三个方向因此互不闭合，与 15.4 节的三条一一对应：**公告侧的一行无法换算到接口侧的符号、接口侧的一句无法换算到告知侧的一次呈现、告知侧的一次呈现无法换算到管理侧的一键下发**。本篇的处理办法不是建立换算表，而是把跨面结论一律拆成「两侧各引各的行号」（`doc.source` + `doc.line_ref`，脚本一 X01／X02 阻断、脚本二 V06 阻断），并把这个不可换算本身作为第 20 章 O8（跨面引用完整率）的测量对象。

## 19. 两套判定模型：J1—J4 与 Q1—Q4

两套模型都只有四档，都从 1 到 4 **变差**，都是**表述资格**而不是风险等级，也都只由两支脚本的输出决定——**不需要任何设备侧数据**。脚本一的四档写在 usage 第 132—133 行与 `VD[]`（第 255—258 行），判定式在第 468—471 行；脚本二的四档写在 usage 第 89—91 行，判定式在第 557—560 行、发档在第 561—564 行。

### 19.1 J1—J4：一条画面外流台账自己站不站得住（脚本一）

| 档 | 触发条件（代码原义） | 文案（第 255—258 行逐字） |
| --- | --- | --- |
| J4 | 该会话缺任一必备格（第 375 行置 `miss[id]`），或命中任一阻断码（第 240—241 行的 `HB`，12 码） | 存在结构性或拒收信号（S／K 族或必备格缺失）：本行不可用 |
| J1 | 无阻断且 `percnt[id] = 0`（第 469 行） | 十二格齐备且无阻断信号：这一次画面外流可进入对外归属表述 |
| J2 | 无阻断且 `percnt[id]` 为 1—2（第 470 行） | 仅 1—2 条非结构性信号：可作内部台账使用，暂不对外表述 |
| J3 | 无阻断且 `percnt[id] ≥ 3`（第 471 行） | 3 条以上非结构性信号：归属结论尚未收敛 |

三个机制事实：**其一**，阻断集只有 12 个码——`S01—S09` 加 `K01 K02 K03`（第 240 行一行写死），其余 59 个码全为非阻断，所以 J2／J3 的分子天然只含非阻断信号。**其二**，`percnt[id]` 计的是该会话的**信号行数**而不是码数（第 152 行每次 `emit()` 自增一次）。`mid` 夹具的实证即在这一条上：四条会话各带 2—3 条信号，`REC_M1`／`BCA_M1`／`MIR_M1` 落 J2、三条信号齐全的 `CMP_M1` 落 J3（`FX/run-log.txt` 第 579—581 行：`会话数=4 信号行数=9 不同信号码=9 阻断信号条数=0`、`判定分布 J1=0 J2=3 J3=1 J4=0`）。**其三**，每条信号末尾由 `src(code)`（第 173 行）拼上 `DOC[code]`，`DOC` 数组共 71 条（第 259—329 行）与 71 个码一一对应，`C/readings-19.txt` 与 `A/`、`B/` 归档行号逐条可回查。

### 19.2 Q1—Q4：三件对完之后归属还能不能立起来（脚本二）

| 档 | 触发条件（代码原义） | 文案（第 561—564 行逐字，此处给判据侧） |
| --- | --- | --- |
| Q4 | 该会话类不在能力表里（`!(kdOf[id] in capKdSet)`）、能力表零行（`capKdN = 0`）、或该会话在读入期就有形态失败（`subjBad[id]`，第 320 行由 S03／S04 置位） | 连可得性都不能定：该会话类在能力表里没有任何一行，或本会话没有一行能通过形态校验 |
| Q2 | `hardN ≥ 1`（第 556 行数该会话的阻断行数，`HB` 共 42 码，第 232—239 行） | 存在阻断信号：三件差集、平面可得性或公开词表至少一段互相矛盾，不能作为对外归属表述 |
| Q3 | `holesReq > 0` 或 `reqNoRef > 0` 或 `recTot = 0` 或 `soft > 0`（第 559 行） | 只能定「这一类会话应当有哪几格」，不能定「这一格由谁读回」 |
| Q1 | 以上全不触发（第 560 行） | 三件差集、平面可得性与公开词表三段齐备且无阻断：可用于对外表述这一条画面外流链路缺哪一格 |

**Q 档自身不计信号**：第 111 行 `else if (code !~ /^Q[1234]$/) soft[id]++` 把四档排除在 `soft` 之外，否则刚发出的 Q3 行会自证 Q3。同一条件还出现在三处：非 Q 行写 stderr（第 601 行）、Q 行写 stdout（第 602 行）、`信号行数`（第 604 行）与`不同信号码`（第 605 行）都只数非 Q 行，末尾的按码计数（第 610 行）同样跳过 Q 码。**四档因此永远不进「阻断信号条数」**，也永远不会把一次干净运行推出退出码 0。

### 19.3 逐值判定的两条结构事实

这两条是本篇夹具设计的依据，也是读任何一张 Q 档分布表之前必须先拿到的口径。

**（a）逐值判定只在能力表建模过的（会话类, 核对项）对上发生。** K 族、M 族、V02 与 X 族全部写在第 440—547 行那个 `for (kk in capOf)` 循环内部，循环第 442 行先做 `if (c2 != kd) continue`——**没有建模的配对根本不进入判定体**。未建模的会话类（`not_recorded`、`unknown`）只得到两样东西：第 408 行的 `D04`（`会话类未建模：… 这一类的判据未建模，缺哪一格无从判定`）与第 561 行的 Q4。夹具侧写：`FX/capability-19.csv` 180 条数据行 = 9 个建模类 × 20 项核对项，11 个会话类里恰好 2 类无行；`FX/tri-19-bad.txt` 第 62 行的注释逐字写着「值级判据只对着能力表里建模过的（会话类,核对项）跑，所以这些行一律落在 system_service 上，用兜底类只会得到『未建模』」。

**（b）数组型核对项把多个落点并进同一格，逐值判定按空格分词逐个走。** `MULTI` 集只有 `landing_destination` 一项（第 161 行，usage 第 39 行同句），同一会话的第二行不新建登记而是把引用并进原格：第 334—335 行 `refOf[k] = refOf[k] " " rf` 并同时累加进 `destRefOf[id]`。因此判定体第 450 行先 `split(refOf[k], rfa, " ")`，再由第 465—498 行对每个落点值逐一走 K 族、M 族与 X 族——**一个格里挂了三个落点，同一条核对项就能出三条不同码的信号的**。也正因如此，数组型的重复登记判据与非数组型不同：同一状态、同一平面、同一归属且同一引用才算 `S08`（第 333 行），三格全同而引用不同则合并（第 334 行），三格里有一格不同算 `S09` 同项两口径（第 339 行）。

### 19.4 阻断 42 个与非阻断 18 个：档位、退出码与不计入阻断的两类

脚本二的 `HB` 集写在第 232—239 行，usage 第 87—88 行逐族列出，两处的清单必须同读：

- **阻断号 42 个**：`S01—S10`、`C01—C05`、`K01—K05`、`M01—M06`、`T03—T08`、`X01—X08`、`V02`、`V06`。**出现即该会话落 Q2，进程以退出码 1 收束**（第 612 行 `exit (nblk > 0 ? 1 : 0)`）。
- **非阻断号 18 个**：`D01—D05`、`P01—P07`、`T01`、`T02`、`V01`、`V03`、`V04`、`V05`。**只落 Q3，退出码仍为 0**。usage 第 92 行逐字写着「覆盖空洞、平面越界与三件不成对不计入阻断，只落 Q3（此时退出码仍为 0）」。
- 由此得到一条必须写死的读法：**退出码 0 不等于归属成立**。`mid` 夹具的 `MID_B`（`mirroring`，8 个 required 格没有登记行）只有非阻断的 D02 命中，落 Q3；同一次运行里 `MID_A` 带三条阻断（T04／T06／T08）落 Q2，于是退出码 1 是被 `MID_A` 拉起来的，`MID_B` 自己并不贡献退出码（`FX/run-log-tri.txt` 第 1097—1098、1107 行：`信号行数=42 不同信号码=7 阻断信号条数=3`、`闭合等级 Q1=0 Q2=1 Q3=1 Q4=1`、`exit=1`）。
- 脚本一侧同构但清单更短：阻断集 12 码（第 240 行），`exit (blocked > 0 ? 1 : 0)`（第 488 行），A／B／C／D／E／G／N／O／R／V／X 十一族 59 码全为非阻断，命中再多也只把会话推到 J2／J3 而不出 J4——所以脚本一同样存在「J3 而退出码 0」的形态，`mid` 夹具那一次就是 `判定分布 J1=0 J2=3 J3=1 J4=0` 配 `exit=0`。

### 19.5 两套模型不可换算的理由与四种接缝组合

三条不可换算的理由都在输入层：**（1）输入份数不同**——脚本一读一份或多份合并的逐字段台账（第 144—145 行只要求「至少一份且存在」），脚本二要求恰好三份且顺序固定（第 102 行），两者的「对象」在结构上不是同一个东西；**（2）计数对象不同**——J 档数的是信号行数，Q 档的 `hardN` 数阻断行、`holesReq` 数 required 空洞、`recTot` 数已读数格（第 445、453、462 行），Q3 的四个触发条件里没有任何一个能折算成「几条信号」；**（3）档位的覆盖面不同**——J 档没有「未建模」这一档，Q 档没有「必备格缺失」这一档，脚本一的 `S09`（必备格缺失，第 375 行）与脚本二的 `S09`（同一核对项出现两种登记口径，第 339 行）同号不同义，两支脚本的 S 族与 K 族也各有各的判据。

四种组合里两对需要点明：

- **J1 而 Q4 真实可达**：台账十二格齐备、形态全合规，但会话类未建模或能力表退化。实跑侧写有两例——`empty-tables` 得 `能力表行=0 词表词条=0 … 闭合等级 Q1=0 Q2=0 Q3=0 Q4=9`，`same-file`（三份输入指向同一个文件）得 `核对项登记行=543 能力表行=0 词表词条=0 … Q4=9`（`FX/run-log-tri.txt` 第 3674—3679、4150—4156 行），脚本一那一侧的同一批台账却是干净的。
- **J4 而 Q1 需要条件**：由 `S01—S06` 或 `K01—K03` 引起的 J4 在同数据上不会给出 Q1，因为两支脚本的 S 族与 K 族都在各自阻断集里，必落 Q2；只由 `S09`（必备格缺失）引起的 J4，在脚本二侧对应的是 required 空洞 `D02`（非阻断）而落 Q3，除非缺失的那一格对这一会话类在能力表里不是 required。**本篇 33 次实跑里没有「J4 且 Q1」这一组合**，如果读者在自己的数据上遇到它，说明两份输入的形态规则被改过，属工具漂移而不是结论。

推荐口径是把两档并列写出（「逐条审查 J2，三件对账 Q3，缺 `landing_destination` 与 `prompt_shown` 两格」），**绝不合并成单一分数**：合并会掩盖第 15.4 节那条事实——逐条越严谨，越容易让三件缺口看起来像已闭合。

---

## 20. 运营指标 O1—O10

十条指标全部能用第 21、22 章两支脚本的输出与第 16 章的 36 个 R 号算出，不需要设备侧数据，也不需要新的读数源。**它们是台账质量指标，不是风险指标**：任何一条到 1 都不表示这台设备的画面更安全，只表示这一批登记的表述资格更完整。

| 号 | 指标与定义 | 分子／分母来自哪条读数或哪个信号 | 警戒线 | 不能用来做什么 |
| --- | --- | --- | --- | --- |
| O1 | 必备 12 格齐备率：未触发 `S09` 的会话数 ÷ 会话数 | 脚本一第 375 行置 `miss[id]`、第 481 行 J4 计数；12 格清单见 usage 第 35—37 行 | 必须为 1；低于 1 时该批台账整体不可对外 | 不能读成「这台设备的画面没有外流」——12 格全齐只说明登记完整 |
| O2 | 十字段形态通过率：未触发 `B04`／`B05`／`B06`／`C06`／`R02`／`R06`／`G05`／`X02`／`S08`／`K03` 任一码的会话数 ÷ 会话数 | 脚本一 usage 第 38—43 行的受检清单与第 351—360 行的十个判定点 | 必须为 1，其中 `K03` 属阻断码，命中即 J4 | 不能用来证明取值正确：形态合规只是「抄自公开材料」的必要条件（`DOC["B05"]` 第 269 行的措辞就是这条） |
| O3 | 逐条审查收敛率：（J1＋J2）会话数 ÷ 会话数 | 脚本一第 481 行 `判定分布 J1=… J2=… J3=… J4=…`；基线 good 4/4、mid 3/4 | 与 O4 同看；单看无意义 | 不是风险等级；J2 只表示「暂不对外表述」，不表示这一条链路可疑 |
| O4 | 三件闭合率：Q1 会话数 ÷ 三件会话数 | 脚本二第 608 行 `闭合等级`；基线 `tri-19-good.txt` 9 会话全 Q1、信号 0 行、`exit=0`（`FX/run-log-tri.txt` 第 1038—1041 行） | 必须为 1 才能对外表述「这一格由谁读回」 | 不能替代 O3：Q1 只说三段齐备，不说某一格填得对不对 |
| O5 | 能力表建模覆盖率：`kdOf[id]` 命中 `capKdSet` 的会话数 ÷ 会话数 | 脚本二第 408 行 `D04` 与第 557 行 Q4 条件；固定分母：能力表 180 行 = 9 类 × 20 项，11 类里 2 类未建模 | 允许 `not_recorded`／`unknown` 两类的结构性缺口，但这两类一律不计入对外表述 | 不能用来推断真实设备上是否存在某一类会话；未建模只意味着「判据未建模」 |
| O6 | 平面-核对项配对率：未触发 `P01`—`P07` 的已读数格 ÷ 全部已读数格 | 脚本二第 501—517 行七条判定；判据基是第 206—213 行的 31 组平面×件配对与第 178—185 行的八类承载面清单；取值域为 26 平面 × 20 项 | 必须为 1；P 族为非阻断码，所以这条不达标时退出码可能仍是 0 | 不能用来解释退出码；也不能把「平面越界」写成「该平面不存在」 |
| O7 | 公告与管理面回指率：未触发 `X01`—`X07` 的对外表述格 ÷ 挂在公告面或管理面的已读数格 | 脚本二第 527—546 行；公开分母：R01 组件×CVE 对 1266、R02 去重 CVE 330、R03 组件名 129、R05 子集 40 行、R06 子集 CVE 13、R07 六组件；夹具侧写 去重词条 80、组件词条 12、子词表组件 6 | 必须为 1 | 不能把「回指成功」写成 iOS 侧结论：子集 macOS 31 行、iOS 4 行（R08），每条命中都要带平台行标注 |
| O8 | 管理面键存在形态核对率：未触发 `G02`／`G05`／`X04` 的会话数 ÷ 登记了限制键的会话数 | 脚本一第 456、358 行与脚本二第 482、531 行；分母链 R19 表内 220 → R20 形态命中 218 → R22 纯键名分母 210 → R23 画面语义词命中 13 → R24 `allow*` 9／`force*` 4 | 必须为 1；命中 `X04` 即 Q2 | 不能用来表示任何一键的开关效果，也不写配置步骤；`forceBypassScreenCaptureAlert` 只在 K05 那一格里核对存在形态（`DOC["K05"]` 第 259 行引 `C/readings-19.txt:106`） |
| O9 | 告知位齐备率：出流会话中未触发 `N01` 与 `N05` 的会话数 ÷ 出流会话数 | 脚本一第 248 行 `EG[]` 五档出流类、第 446 与 450 行两条判据；出处 `B/apple-platform-security-guide.txt:4241`、`:1429` | 必须为 1（`N05` 那一格是「无提示、无披露且无说明句」三格同缺） | 不能用来推断用户是否真的看见过提示；也不能反推「有提示即有授权」 |
| O10 | 引用-结论一致率：`doc.conclusion = confirmed` 且未触发 `X01`／`X02` 的会话数 ÷ 全部 confirmed 会话数 | 脚本一第 466、359 行；脚本二侧同看 `V02`（第 496 行）与 `V01`（第 553 行）；分母另可对照 R10 的大小写三态（6／0／6） | 必须为 1；这是第 3.4 节失败点 8 的唯一机器化落点 | 不能用来核对画面本身——台账登记的是格，不是帧 |

三条使用说明：

- **O1、O2、O4、O6、O7、O8、O9、O10 是「必须为 1」的一类**，分子分母同源，任何一条命中就说明该批台账有格被写成自由文本、有读数挂错面或有结论没有回指处。**O3 与 O5 是「结构对照」类**：O3 只与 O4 成对读，O5 的缺口在本篇夹具里是设计出来的，不是待办事项。
- **十个指标里没有一条使用「命中率」这种口径**。凡涉及公告与管理面的分母（1266、330、129、40、13、6、220、218、210、13、95、2）一律整段引用第 16 章的 R 号，不得截取其一部分当「键数」或「组件数」；命中数一律标注匹配形态，因为 R10 演示过一条假读数是怎么产生的（小写化之后仍用大写模式匹配得 0）。
- **十条指标都不出设备结论**。`FX/coverage-proof.txt` 的 C1—C22 段能证明的只有：脚本一 71 个码定义与出处各 71、18 次实跑、2444 行留档；脚本二 60 个信号码加 4 个判定位共 64、15 次实跑、4157 行留档；合计 33 次实跑、139 个码全部触发、两支脚本的一号两义均为 0。判据可达与结论正确是两件事。

---

## 21. 只读核验脚本一：画面外流台账逐字段审查器

这支脚本回答一个问题：**一次画面离开设备的会话被写成若干行台账之后，这行台账自己站不站得住**（头部第 5 行逐字）。它不检查文件、不检查设备、不检查任何通道，只检查登记。

### 21.1 输入与边界

输入是一份或多份台账文本，每行三列：`<画面外流会话标识>,<字段名>,<值>`；`#` 开头与空行忽略，行尾 CR 忽略，**值里不能含逗号**（usage 第 18 行逐字）。会话标识四类前缀与 `id.session_kind` 一一对应：`REC_` 本机录制／`BCA_` 直播广播／`MIR_` 跨设备镜像／`CMP_` 伴生与外接显示（usage 第 19 行）；前缀不在四类内即 `B01`（第 413 行），末尾的 `前缀会话数 REC= BCA= MIR_= CMP=` 一行（第 482 行）是这支脚本特有的分组读数。参数校验只有两条：至少一份输入（第 144 行）、每份都存在（第 145 行），不满足一律退出码 2。多份一次传入是合法用法且**合并读入而不是分批读入**：`twice` 实跑把同一份 good 台账传两遍，`S03 同一字段重复登记` 命中 250 行、四个会话整批落 J4、退出码 1（`FX/run-log.txt` 第 1404—1408 行）——同一会话的同一字段不允许有两个取值。边界句在 usage 第 135 行与头部第 8—10 行。

### 21.2 十二个命名空间与必备 12 格

命名空间集合 `NS[]` 写死在第 238—239 行，恰好 12 项：`id`／`consent`／`chan`／`dom`／`land`／`obs`／`notice`／`undo`／`mgmt`／`adv`／`doc`／`sec`。usage 第 20—34 行逐空间列出自己的字段清单，`sec.*` 是唯一用途为「触发了收」的第十二个空间——该空间下任何字段直接 `K01` 并终止该行（第 344 行）。字段名不在 `DOM`／`BOOL`／`DT`／`KNOWN` 四张清单之内按 `S05` 记（第 345 行），`KNOWN` 的 13 个附加字段写在第 242—243 行。

必备格 12 个由第 247 行的 `REQ` 一行写死，与 usage 第 35—37 行逐字相同：`id.session_kind id.source_face consent.granted_by chan.egress_path chan.process_owner dom.domain_class land.destination obs.plane notice.prompt_shown undo.reset_method mgmt.mdm_configurable doc.source`。缺任一格在第 375 行同时做两件事：发 `S09`、置 `miss[id] = 1`，后者直接锁 J4。这 12 格在十一层里的分布就是第 15.2 矩阵最后一列的出处：**L1、L2、L3（两格）、L4、L5、L6、L7、L8、L9、L11 各贡献一格或两格，唯独 L10 公告对齐层一格都没有**——所以公告侧缺读数只落非阻断码，而 L1、L3 任一格缺位立即 J4。枚举取值在第 176—235 行逐格写死（`DOM[]` 60 格），越界按 `S07`（第 347 行）；布尔位两格在第 236 行、日期位两格在第 237 行分别走 `S07` 与 `S08`。

### 21.3 形态受检字段清单

usage 第 38—43 行给出十个形态码，判定点集中在第 351—360 行，逐条列出各拦什么：

- `B04` 拦 `id.bundle_id`：必须是两段以上的点分段标识且不含空格（`isBundle`，第 165 行），另有一条在第 415 行——录制或广播会话给确认结论却不登记承载它的包标识。出处 `A/replaykit_rpsystembroadcastpickerview.txt:13`。
- `B05` 拦 `id.team_id`：必须是 10 位字母数字（`isTeamID`，第 166 行）。出处是 usage 自己的形态清单（第 269 行）：写成别的形状说明这一格不是从公开材料抄来的。
- `B06` 拦 `id.session_ref`：点分段标识（`isDotId`，第 167 行），且第 414 行再核一次「被引对象要在同一份台账里存在」。出处 `A/uikit_uiscenesession.txt:137`。
- `C06` 拦 `chan.api_entry` 与 `chan.service_endpoint` 两格（第 354—355 行两条 emit）：接口标识必须是公开符号名、点分段标识或短横线单标识之一；端子点必须落在 `com.apple.broadcast-services`／`other` 清单或点分段形态内。出处 `B/…guide.txt:4249`。
- `R02` 拦 `adv.cve`：`CVE-年-序号` 四位以上序号（`isCVE`，第 163 行）。出处 `C/advisory-19.tsv` 表头与 `C/readings-19.txt:61—63`。
- `R06` 拦 `adv.fix_version`：纯数字点分、最多四段（`isVer`，第 164 行）。出处 `B/…guide.txt:180`。
- `G05` 拦 `mgmt.restriction_key`：小写开头的单个驼峰标识（第 358 行的行内正则）。出处 `B/mdm-restriction-keys.txt:5—8`——写成路径形态（如 `com.apple.applicationaccess.allowScreenShot`）即不是这一份清单里的键。
- `X02` 拦 `doc.line_ref`：只允许 `1234` 或 `6-9` 两种形态（`isLineRef`，第 168 行）。带「第／行」前后缀的中文写法在两份台账之间不可换算。
- `S08` 拦 `obs.read_at` 与 `undo.verified_at`（第 237、349 行）：ISO 日期形态外加月份与日期范围校验（`isISOdt`／`validCal`，第 161—162 行），口径取自 `C/kev-apple.tsv` 的 `dateAdded`／`dueDate` 两列。
- `K03` 拦 `obs.crash_report_ref`：只允许 6—40 位字母数字与连字符的报告标识，或 `absent`／`not_applicable`（第 360 行）。堆栈片段、设备路径、带空格的描述一律拦停，且 `K03` 是阻断码。

### 21.4 十三族 71 个信号码一览

| 族 | 码数 | 管什么（判据行号在本支脚本内） | 是否阻断 |
| --- | --- | --- | --- |
| A | 6 | 授权主体与提示口径：同意来源记成管理面却登记设备侧弹出提示（`A01`，417 行）、记成用户提示却说提示未出现（`A02`，418 行）、提示范围偏离「每个 App 进程一次」（`A03`，419 行）、麦克风或摄像头参与却未登记提示位（`A04`，420 行）、镜像把安全测距当必要条件（`A05`，421 行）、镜像未登记配对选择（`A06`，422 行） | 非阻断 |
| B | 6 | 会话标识与来源面：前缀不在四类内（`B01`，413 行）、会话类与通道词不同族（`B02`，411 与 416 行两条 emit）、进入面与来源矛盾（`B03`，412 行）、包标识（`B04`）、团队标识（`B05`）、跨会话引用（`B06`） | 非阻断 |
| C | 9 | 通道件：出流类却无通道（`C01`，423 行）、进程归属与通道形态矛盾（`C02`）、出进程采集却称 App 读得到（`C03`）、App 内取样却称内容永不被访问（`C04`）、广播通道件缺扩展数或端点或缓冲（`C05`）、接口标识与端子点形态（`C06`）、被取代口径仍作现用依据（`C07`）、录制类未登记并发上限（`C08`）、预览面与分享面口径混用（`C09`） | 非阻断 |
| D | 6 | 执行域与隔离：类别未登记（`D01`，431 行）、跨设备落点却称无隔离（`D02`，432 行）、本地点对点未登记配对核验（`D03`，433 行）、结论只来自厂商说法／截屏／假定（`D04`，434 行）、Wi-Fi 承载未核对地址随机化口径（`D05`，435 行）、画面由 `replayd` 取出却把执行域记成 App 沙箱（`D06`，436 行） | 非阻断 |
| E | 5 | 落点与写域：出流类却无落点（`E01`，437 行）、本地影片却把写域记成 App 容器可访问（`E02`，438 行）、有预览面未登记裁剪（`E03`，439 行）、交第三方服务未登记留存（`E04`，440 行）、存储对象为直播影片片段但会话不是直播（`E05`，441 行） | 非阻断 |
| G | 5 | 管理面：称可配内容却无键名（`G01`，455 与 459 行两条 emit）、命中词形但不约束画面出流的键（`G02`，456 行，判据是 `SAME[]` 那五个键，第 253—254 行）、登记 payload 却没写键来源（`G03`，457 行）、课程免提示同意被记成设备用户自己的同意（`G04`，458 行）、限制键形态（`G05`） | 非阻断 |
| K | 3 | 内容越界与拒收：`sec.*` 空间出现字段（`K01`，344 行）、取值形似设备路径／长载荷／Base64 形状／密钥串（`K02`，350 行，四个形态函数在第 169—172 行）、崩溃引用非报告标识形态（`K03`，360 行） | 全部阻断 |
| N | 5 | 告知：出流会话告知位未登记（`N01`，446 行）、镜像无横幅却称提示已出现（`N02`，447 行）、告知文本依据截屏或假定（`N03`，448 行）、称锁屏不可见却从锁屏通知取数（`N04`，449 行）、无提示无来源披露且无任何说明句（`N05`，450 行） | 非阻断 |
| O | 4 | 观测平面：锁屏面读不出执行域（`O01`，442 行）、有平面却未登记读数时刻（`O02`，443 行）、只靠自述平面给确认结论（`O03`，444 行）、指示灯可见但观测平面不是指示灯面（`O04`，445 行） | 非阻断 |
| R | 7 | 公告对齐：登记影响句词形却无组件名（`R01`，460 行）、CVE 形态（`R02`）、组件不属本层却用于确认（`R03`，462 与 463 行两条 emit）、`screen` 词形与含 screen 的四组件表不对齐（`R04`，461 行）、命中未核对大小写匹配形态（`R05`，464 行）、修复版本形态（`R06`）、在 KEV 内却把补丁通道记为非发布（`R07`，465 行） | 非阻断 |
| S | 9 | 行式与命名空间：列数不足三（`S01`，334 行）、会话标识为空（`S02`，337 行）、同一字段重复登记（`S03`，340 行）、未登记的命名空间（`S04`，343 行）、清单外字段名（`S05`，345 行）、取值为空（`S06`，346 行）、枚举与布尔位越界（`S07`，347—348 行）、日期形态（`S08`，349 行）、必备格缺失（`S09`，375 行） | 全部阻断 |
| V | 4 | 复位与再核对：走停止或丢弃口但未登记输出 URL 是否交出（`V01`，451 行）、再证明依据为假定（`V02`，452 行）、称有残留但未登记核对时刻（`V03`，453 行）、复位方法不可判定却声称已再证明（`V04`，454 行） | 非阻断 |
| X | 2 | 引用与结论：确认结论缺来源文件或行号（`X01`，466 行）、行号引用形态非法（`X02`，359 行） | 非阻断 |

6＋6＋9＋6＋5＋5＋3＋5＋4＋7＋9＋4＋2 = 71，与 `FX/coverage-proof.txt` 的 C1（`emit` 去重 71）与 C2（`DOC` 赋值去重 71）两处独立计数相等，C3 的差集为空。**判定位 J1—J4 不计入信号码**（C5 明确剔除），所以脚本一侧是 71 个码、脚本二一侧是 60 个码加 4 个判定位共 64 个，两侧合计 139。

### 21.5 四级判定与退出码

逐条信号写 **stderr**（第 483 行），形如 `码<TAB>会话<TAB>说明（出处）`；四档判定写 **stdout**（第 472 行），末尾固定四行汇总（第 479—482 行：`画面外流会话数= 信号行数= 判定行数=`、`不同信号码= 阻断信号条数=`、`判定分布 J1= J2= J3= J4=`、`前缀会话数 REC= BCA= MIR_= CMP=`），随后是按码排序的计数表（第 484—487 行，同样写 stderr）。`-q` 只关掉 stdout 上那几行逐会话判定（第 472 行的 `if (!QUIET)`；开关在第 142 行），信号、汇总与计数表一行不少——`quiet` 实跑与 `codes` 实跑的五个汇总数全等（第 1876—1879 行对第 535—538 行）。退出码三条路：`exit (blocked > 0 ? 1 : 0)`（第 488 行）；输入缺失或不可读给 2（第 144—145 行）；`-h`／`--help` 给 0（第 141 行）。18 次实跑的退出码分布是 0×6、1×10、2×2（C9），`codes` 那一次为 `会话数=68 信号行数=396 不同信号码=67 阻断信号条数=206`、`判定分布 J1=0 J2=3 J3=0 J4=65`（第 535—537 行），`multi` 那一次把 good／mid／bad 三份合并读入后 `不同信号码=71` 全部非零（第 1140—1142 行），这是第 23 章覆盖验收的主证据。

### 21.6 只读与拒收纪律

**唯一写出目标**是 `mktemp -d` 建的临时目录，前缀 `scr19.`（第 147 行），第 148 行在 EXIT／INT／TERM 三个信号上 `rm -rf`；`TMPD` 只出现在赋值与 trap 两处，实现不向其写入任何字节（P3 段与 P8 段的「无残留：临时目录前缀 scr19. 匹配不到任何东西」）。awk 程序体内没有 `system()`、没有 `getline < 文件`、没有 `popen()`（P1）。**本支脚本不调用 `file`／`mdls`／`mdimport`／`mdutil`／`mdfind`／`spctl`／`codesign`／`defaults`／`log`／`sysctl`／`xcrun`／`profiles`／`plutil`／`sips`／`qlmanage`／`otool` 中的任何一个**：这十六个名字在整支脚本里只出现在头部第 8—9 行的拒收声明一处（P4 命中第 9 行、P4b 对 `file`／`log` 整词零命中、P4d 的命令位置探测为空匹配，而 P4c 用两条样例证明该探测规则不是空转）。整词普查（P6）只得 `awk=1 tr=3 cat=1 mktemp=3 rm=1`，`perl`／`python`／`node` 为 0。不联网、不读设备状态、不打开任何被登记的对象、不修改输入文件。

拒收执行点三条：`K01`（第 344 行，`sec.*` 空间）、`K02`（第 350 行，`devPath()`／`longBlob()`／`b64ish()`／`secretish()` 四个形态函数命中，`secretish()`（第 172 行）匹配 `glpat-`／`ghp_`／`gho_`／`xox`／`AKIA`／`Bearer `／`-----BEGIN` 七种前缀）、`K03`（第 360 行，崩溃引用非报告标识形态）。真实用户检索词、可还原身份的语音描述、真实联系人／健康／位置样本、设备绝对路径、整段文件正文、超长度阈值载荷一律拒收；本篇全部夹具为合成标识与合成取值。

**两支脚本在设计上不可用于以下目的**：关闭或欺骗采集提示、规避管理面审计、构造任何免交互触发路径、定位采集面缺陷或复现崩溃。`forceBypassScreenCaptureAlert` 在本篇只作为管理面读数的一格被核对存在形态：脚本一里它只能作为 `mgmt.restriction_key` 的一个取值参与 `G05` 的形态判定（第 358 行），脚本二里它只在 `K05`（第 475—476 行）出现——出现在采集件或落点件即拦停，不进入 `isSecretish` 的拒收判据；两支脚本都不写它的开关效果与配置步骤。

### 21.7 全量源码

```bash
#!/usr/bin/env bash
# screen-egress-ledger-review.sh —— 画面外流台账逐字段审查器（离线 / 只读 / 不联网 / 不碰设备）
# 输入：一份或多份台账文本，每行一条记录：  <画面外流会话标识>,<字段名>,<值>
# 输出：逐条信号码（stderr） + 每个会话的四级判定（stdout） + 汇总
# 本脚本只判定「一次画面离开设备的会话被登记成一条台账之后，这行台账自己站不站得住」：
# 不含录制通道的绕过做法、不含告知提示的欺骗或关闭、不含采集面的缺陷定位、不含任何免交互触发路径的构造。
# 台账里出现文件正文、形似设备绝对路径的取值、形似共享密钥或口令的串、超长 Base64 载荷或真实人名地址时触发 K01—K03 并要求删除该字段。
# 本脚本不联网、不调用 file／mdls／mdimport／mdutil／mdfind／spctl／codesign／defaults／log／sysctl／xcrun／profiles／
#       plutil／sips／qlmanage／otool 等任何命令行工具、不读取设备状态、不打开任何被登记的会话对象；
#       唯一写出目标是 mktemp -d 创建的临时目录，退出时删除，本实现不向其写入任何字节。
set -u
LC_ALL=C; export LC_ALL

usage() {
  cat <<'EOF'
用法: screen-egress-ledger-review.sh [-q] 台账文件 [...]
  -q  不输出逐会话判定行；-h/--help 显示本帮助
台账行格式: <画面外流会话标识>,<字段名>,<值>    # 开头与空行忽略，行尾 CR 忽略，值里不能含逗号
会话标识前缀（四类，与 id.session_kind 一一对应）: REC_ 本机录制／BCA_ 直播广播／MIR_ 跨设备镜像／CMP_ 伴生与外接显示
字段命名空间（十二个 + 一个拒收空间）:
  id.*       会话与对象标识（session_kind / channel_word / source_face / provenance / bundle_id / team_id / session_ref）
  consent.*  授权与同意（granted_by / alert_shown / alert_scope / microphone_used / camera_used / secure_ranging / pairing_choice / revocable）
  chan.*     通道件（egress_path / buffer_form / process_owner / api_entry / entry_status / host_has_access / extension_count /
             service_endpoint / preview_surface / share_surface / concurrent_limit）
  dom.*      执行域与隔离（domain_class / isolation_mechanism / memory_safety_class / pairing_verified / transport / mac_randomized / domain_source）
  land.*     落点与存储（destination / write_scope / persist_after_share / trimmed / stored_object）
  obs.*      观测平面（plane / field_read / read_at / indicator_visible / list_visible / crash_report_ref）
  notice.*   告知面（prompt_shown / banner_kind / lockscreen_visible / origin_disclosed / warning_text_source / notice_note）
  undo.*     复位面（reset_method / output_url_returned / residue_claimed / reproof_done / reproof_basis / verified_at）
  mgmt.*     管理面（mdm_configurable / restriction_key / word_family / key_in_inventory / payload / supervised / key_source）
  adv.*      公告对齐（component / component_is_egress_layer / cve / kev_listed / impact_word / platform_row /
             case_mismatch_checked / patch_channel / fix_version）
  doc.*      引用与结论（source / line_ref / conclusion）
  sec.*      拒收用命名空间：本空间下任何字段都会触发 K01
必备格（缺任一按 S09 记，并落 J4）：id.session_kind id.source_face consent.granted_by chan.egress_path
  chan.process_owner dom.domain_class land.destination obs.plane notice.prompt_shown undo.reset_method
  mgmt.mdm_configurable doc.source
形态受检字段（形状不合法按对应信号码记）：
  id.bundle_id 按 B04；id.team_id（10 位字母数字）按 B05；id.session_ref（点分段标识）按 B06；
  chan.api_entry 与 chan.service_endpoint 按 C06；adv.cve（CVE-年-序号）按 R02；
  adv.fix_version（纯数字点分）按 R06；mgmt.restriction_key（小驼峰单标识）按 G05；
  doc.line_ref 只写 `1234` 或 `6-9` 这一种形态，带「第／行」前缀的写法在两份台账之间不可换算，按 X02；
  obs.read_at 与 undo.verified_at 按 S08；obs.crash_report_ref 按 K03。
枚举取值（逐字匹配，越界按 S07）:
  id.session_kind        movie_recording live_broadcast mirroring companion_display external_display
                         remote_observation still_capture not_applicable none not_recorded unknown
  id.channel_word        ReplayKit ScreenCaptureKit RPScreenRecorder RPSystemBroadcastPickerView
                         broadcast_extension IOSurface WindowServer iPhoneMirroring AirPlay CarPlay
                         Classroom RemoteScreenObservation screenshot none not_recorded unknown
  id.source_face         control_center in_app_button broadcast_picker preview_share_ui mirroring_app
                         airplay_menu carplay_template settings_ui mdm_profile external_accessory
                         not_applicable none not_recorded unknown
  id.provenance          local_user initiated_by_user mac_host vehicle_display external_receiver
                         managed_by_mdm course_managed not_determinable not_recorded unknown
  consent.granted_by     user_alert control_center_toggle apple_account_pairing course_enrollment
                         mdm_profile not_granted not_determinable not_applicable not_recorded unknown
  consent.alert_shown    yes no not_applicable not_recorded unknown
  consent.alert_scope    once_per_app_process per_session per_device per_stream not_recorded unknown
  consent.microphone_used / camera_used / revocable   yes no not_applicable not_recorded unknown
  consent.secure_ranging required not_required not_recorded unknown
  consent.pairing_choice automatically_authenticate ask_every_time not_applicable not_recorded unknown
  chan.egress_path       out_of_process_capture in_app_sample_buffer broadcast_upload
                         mirroring_local airplay_stream carplay_template_stream external_display_stream
                         classroom_observation still_capture not_applicable none not_recorded unknown
  chan.buffer_form       raw_unencoded serialized encoded_clip movie_file frame_set not_applicable not_recorded unknown
  chan.process_owner     app_process replayd system_service extension_process not_determinable not_recorded unknown
  chan.api_entry         RPScreenRecorder RPPreviewViewController RPSystemBroadcastPickerView RPBroadcastHandler
                         RPBroadcastConfiguration SCStream SCContentSharingPicker UIScreen UISceneSession UIScene
                         CPInterfaceController WKWebView AVPlayerViewController none not_recorded unknown
                         另收点分段标识形态（如 com.apple.screencontent）；两者都不合按 C06
  chan.entry_status      current superseded not_recorded unknown
  chan.host_has_access   yes no never_accessible not_determinable not_recorded unknown
  chan.extension_count   two one zero not_applicable not_recorded unknown
  chan.service_endpoint  com.apple.broadcast-services other none not_applicable not_recorded unknown
  chan.preview_surface   in_process out_of_process system_vended not_applicable not_recorded unknown
  chan.share_surface     app_vended system_vended none not_applicable not_recorded unknown
  chan.concurrent_limit  one_at_a_time unlimited not_applicable not_recorded unknown
  dom.domain_class       app_sandboxed daemon_extension system_service extension isolated_display
                         kernel not_determinable not_recorded unknown
  dom.isolation_mechanism sandbox out_of_process secure_enclave authentication_ic mfi_sap sts_protocol
                         blastdoor none not_determinable not_recorded unknown
  dom.memory_safety_class memory_safe mixed legacy_unsafe not_determinable not_recorded unknown
  dom.pairing_verified   yes no not_applicable not_recorded unknown
  dom.transport         local_peer_to_peer wifi_network cellular usb vehicle_bus not_applicable not_recorded unknown
  dom.mac_randomized    yes no not_applicable not_recorded unknown
  dom.domain_source      platform_doc advisory mdm_status_item vendor_claim screenshot assumed not_recorded unknown
  land.destination       local_movie third_party_service remote_mac vehicle_display external_receiver
                         home_hub none not_applicable not_recorded unknown
  land.write_scope       replaykit_only_directory app_container service_side_store kernel_none
                         not_determinable not_applicable not_recorded unknown
  land.persist_after_share / land.trimmed   yes no not_applicable not_recorded unknown
  land.stored_object     movie mp4_clip sample_buffer snapshot frame none not_applicable not_recorded unknown
  obs.plane              lock_screen_notice control_center camera_indicator settings_ui platform_doc
                         advisory mdm_status_item crash_report app_self_report vendor_claim
                         not_determinable none not_recorded unknown
  obs.field_read         egress_state prompt_state host_process domain_class destination indicator_state none
                         not_recorded unknown
  obs.indicator_visible / obs.list_visible   yes no not_applicable not_recorded unknown
  notice.prompt_shown    yes no not_applicable not_recorded unknown
  notice.banner_kind     persistent first_time_banner none not_applicable not_recorded unknown
  notice.lockscreen_visible yes no not_supported not_applicable not_recorded unknown
  notice.origin_disclosed disclosed absent not_applicable not_recorded unknown
  notice.warning_text_source platform_doc advisory support_note vendor_claim screenshot assumed
                         not_applicable not_recorded unknown
  undo.reset_method      stop_recording discard_recording delete_movie revoke_consent unpair
                         mdm_reapplied restart expiry_only not_determinable none not_recorded unknown
  undo.output_url_returned yes no not_applicable not_recorded unknown
  undo.residue_claimed / reproof_done        yes no not_recorded unknown
  undo.reproof_basis     re_opened re_broadcast re_rendered user_visible_prompt platform_doc advisory_component
                         assumed not_applicable not_recorded unknown
  mgmt.mdm_configurable  channel_only content_only yes no not_recorded unknown
  mgmt.word_family       egress_control lockscreen_surface screensaver call_recording not_recorded unknown
  mgmt.key_in_inventory  yes no not_checked not_recorded unknown
  mgmt.payload           com.apple.applicationaccess com.apple.education com.apple.airplay none
                         not_applicable not_recorded unknown
  mgmt.supervised        yes no not_recorded unknown
  mgmt.key_source        restrictions_inventory official_doc vendor_claim none not_recorded unknown
  adv.component_is_egress_layer yes no not_checked not_recorded unknown
  adv.kev_listed         yes no not_checked not_applicable not_recorded unknown
  adv.impact_word        screen keystroke peer vnc record display mirror none not_recorded unknown
  adv.platform_row       iOS iPadOS macOS tvOS watchOS visionOS not_recorded unknown
  adv.case_mismatch_checked yes no not_recorded unknown
  adv.patch_channel      whole_version rapid_security_response background_improvement not_release
                         not_determinable not_recorded unknown
  doc.conclusion         confirmed absent_in_ledger not_determinable assumed not_recorded unknown
公告对齐子词表（公开口径里画面外流这一层的全部命中，R03／R04 据此判定；
  基线 C/readings-19.txt 第 11—16 行与第 48—51 行）:
  组件子集六个（逐字，含空格形态）: IOMobileFrameBuffer / IOSurface / ReplayKit / Screen Sharing /
                                    Screen Sharing Server / WindowServer
  impact 含 screen 的组件四个: Screen Sharing Server / Remote Management / smbx / Siri
引用格: 公开词形值本身 / A/quicklook.txt:16 这一形态的归档行号 / none（确认无对应条目）/ not_recorded（未登记）
判定档：J1 十二格齐备且无任何信号；J2 只有 1—2 条非结构性信号；J3 三条以上非结构性信号；
        J4 存在结构性或拒收信号（S／K 族或必备格缺失）。
退出码：出现阻断信号时为 1，输入不可用时为 2，否则为 0。
本脚本不联网、不访问设备、不修改输入文件；临时件写在 mktemp -d 并在退出时删除。
EOF
}

QUIET=0
case "${1:-}" in
  -h|--help) usage; exit 0 ;;
  -q) QUIET=1; shift ;;
esac
[ $# -ge 1 ] || { usage >&2; exit 2; }
for f in "$@"; do [ -f "$f" ] || { echo "输入不可读: $f" >&2; exit 2; }; done

TMPD=$(mktemp -d "${TMPDIR:-/tmp}/scr19.XXXXXX") || { echo "无法创建临时目录" >&2; exit 2; }
trap 'rm -rf "$TMPD"' EXIT INT TERM

awk -v QUIET="$QUIET" '
function emit(code, id, msg,   k) {
  cnt[code]++; percnt[id]++; lines[++nline] = sprintf("%s\t%s\t%s", code, (id==""?"-":id), msg src(code))
  if (code in HB) hard[id] = 1
}
function GV(i, f,   k) { k = i SUBSEP f; return (k in valof) ? valof[k] : "" }
function hasToken(s, t,   n, arr, i2) { n = split(s, arr, " "); for (i2 = 1; i2 <= n; i2++) if (arr[i2] == t) return 1; return 0 }
function istrue(v)  { return (v=="true"||v=="yes"||v=="1") }
function isfalse(v) { return (v=="false"||v=="no"||v=="0") }
function isbool(v)  { return (istrue(v) || isfalse(v) || v=="unknown" || v=="not_recorded" || v=="not_applicable") }
function isNA(v)    { return (v=="" || v=="not_recorded" || v=="unknown") }
function isISOdt(v) { return (v ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]([ T][0-9][0-9]:[0-9][0-9](:[0-9][0-9])?)?([Zz]|[+-][0-9][0-9]:?[0-9][0-9])?$/ && validCal(v)) }
function validCal(v,  p, mo, dy) { split(substr(v,1,10), p, "-"); mo = p[2]+0; dy = p[3]+0; return (mo>=1 && mo<=12 && dy>=1 && dy<=31) }
function isCVE(v)   { return (v ~ /^CVE-[0-9]{4}-[0-9]{4,}$/) }
function isVer(v)   { return (v ~ /^[0-9]+(\.[0-9]+){0,3}$/) }
function isBundle(v){ return (v ~ /^[A-Za-z0-9][A-Za-z0-9._-]*\.[A-Za-z0-9][A-Za-z0-9._-]*$/ && v !~ /[ ]/) }
function isTeamID(v){ return (v ~ /^[A-Za-z0-9]{10}$/) }
function isDotId(v) { return (v ~ /^[A-Za-z][A-Za-z0-9_-]*(\.[A-Za-z0-9_-]+)+$/) }
function isLineRef(v) { return (v ~ /^[0-9]+(-[0-9]+)?$/) }
function devPath(v) { return (v ~ /^\/(Applications|private|var|Users|System)\// || v ~ /\/var\/mobile\//) }
function longBlob(v){ return (length(v) > 120) }
function b64ish(v)  { return (v ~ /^[A-Za-z0-9+\/]{40,}={0,2}$/) }
function secretish(v){ return (v ~ /^(glpat-|ghp_|gho_|xox|AKIA|Bearer |-----BEGIN)/) }
function src(c)     { return (c in DOC) ? "（" DOC[c] "）" : "" }
BEGIN {
  FS = ","
  DOM["id.session_kind"]="movie_recording live_broadcast mirroring companion_display external_display remote_observation still_capture not_applicable none not_recorded unknown "
  DOM["id.channel_word"]="ReplayKit ScreenCaptureKit RPScreenRecorder RPSystemBroadcastPickerView broadcast_extension IOSurface WindowServer iPhoneMirroring AirPlay CarPlay Classroom RemoteScreenObservation screenshot none not_recorded unknown "
  DOM["id.source_face"]="control_center in_app_button broadcast_picker preview_share_ui mirroring_app airplay_menu carplay_template settings_ui mdm_profile external_accessory not_applicable none not_recorded unknown "
  DOM["id.provenance"]="local_user initiated_by_user mac_host vehicle_display external_receiver managed_by_mdm course_managed not_determinable not_recorded unknown "
  DOM["consent.granted_by"]="user_alert control_center_toggle apple_account_pairing course_enrollment mdm_profile not_granted not_determinable not_applicable not_recorded unknown "
  DOM["consent.alert_shown"]="yes no not_applicable not_recorded unknown "
  DOM["consent.alert_scope"]="once_per_app_process per_session per_device per_stream not_recorded unknown "
  DOM["consent.microphone_used"]="yes no not_applicable not_recorded unknown "
  DOM["consent.camera_used"]="yes no not_applicable not_recorded unknown "
  DOM["consent.revocable"]="yes no not_applicable not_recorded unknown "
  DOM["consent.secure_ranging"]="required not_required not_recorded unknown "
  DOM["consent.pairing_choice"]="automatically_authenticate ask_every_time not_applicable not_recorded unknown "
  DOM["chan.egress_path"]="out_of_process_capture in_app_sample_buffer broadcast_upload mirroring_local airplay_stream carplay_template_stream external_display_stream classroom_observation still_capture not_applicable none not_recorded unknown "
  DOM["chan.buffer_form"]="raw_unencoded serialized encoded_clip movie_file frame_set not_applicable not_recorded unknown "
  DOM["chan.process_owner"]="app_process replayd system_service extension_process not_determinable not_recorded unknown "
  DOM["chan.api_entry"]="RPScreenRecorder RPPreviewViewController RPSystemBroadcastPickerView RPBroadcastHandler RPBroadcastConfiguration SCStream SCContentSharingPicker UIScreen UISceneSession UIScene CPInterfaceController WKWebView AVPlayerViewController none not_recorded unknown "
  DOM["chan.entry_status"]="current superseded not_recorded unknown "
  DOM["chan.host_has_access"]="yes no never_accessible not_determinable not_recorded unknown "
  DOM["chan.extension_count"]="two one zero not_applicable not_recorded unknown "
  DOM["chan.service_endpoint"]="com.apple.broadcast-services other none not_applicable not_recorded unknown "
  DOM["chan.preview_surface"]="in_process out_of_process system_vended not_applicable not_recorded unknown "
  DOM["chan.share_surface"]="app_vended system_vended none not_applicable not_recorded unknown "
  DOM["chan.concurrent_limit"]="one_at_a_time unlimited not_applicable not_recorded unknown "
  DOM["dom.domain_class"]="app_sandboxed daemon_extension system_service extension isolated_display kernel not_determinable not_recorded unknown "
  DOM["dom.isolation_mechanism"]="sandbox out_of_process secure_enclave authentication_ic mfi_sap sts_protocol blastdoor none not_determinable not_recorded unknown "
  DOM["dom.memory_safety_class"]="memory_safe mixed legacy_unsafe not_determinable not_recorded unknown "
  DOM["dom.pairing_verified"]="yes no not_applicable not_recorded unknown "
  DOM["dom.transport"]="local_peer_to_peer wifi_network cellular usb vehicle_bus not_applicable not_recorded unknown "
  DOM["dom.mac_randomized"]="yes no not_applicable not_recorded unknown "
  DOM["dom.domain_source"]="platform_doc advisory mdm_status_item vendor_claim screenshot assumed not_recorded unknown "
  DOM["land.destination"]="local_movie third_party_service remote_mac vehicle_display external_receiver home_hub none not_applicable not_recorded unknown "
  DOM["land.write_scope"]="replaykit_only_directory app_container service_side_store kernel_none not_determinable not_applicable not_recorded unknown "
  DOM["land.stored_object"]="movie mp4_clip sample_buffer snapshot frame none not_applicable not_recorded unknown "
  DOM["obs.plane"]="lock_screen_notice control_center camera_indicator settings_ui platform_doc advisory mdm_status_item crash_report app_self_report vendor_claim not_determinable none not_recorded unknown "
  DOM["obs.field_read"]="egress_state prompt_state host_process domain_class destination indicator_state none not_recorded unknown "
  DOM["obs.indicator_visible"]="yes no not_applicable not_recorded unknown "
  DOM["obs.list_visible"]="yes no not_applicable not_recorded unknown "
  DOM["notice.prompt_shown"]="yes no not_applicable not_recorded unknown "
  DOM["notice.banner_kind"]="persistent first_time_banner none not_applicable not_recorded unknown "
  DOM["notice.lockscreen_visible"]="yes no not_supported not_applicable not_recorded unknown "
  DOM["notice.origin_disclosed"]="disclosed absent not_applicable not_recorded unknown "
  DOM["notice.warning_text_source"]="platform_doc advisory support_note vendor_claim screenshot assumed not_applicable not_recorded unknown "
  DOM["undo.reset_method"]="stop_recording discard_recording delete_movie revoke_consent unpair mdm_reapplied restart expiry_only not_determinable none not_recorded unknown "
  DOM["undo.output_url_returned"]="yes no not_applicable not_recorded unknown "
  DOM["undo.residue_claimed"]="yes no not_recorded unknown "
  DOM["undo.reproof_done"]="yes no not_recorded unknown "
  DOM["undo.reproof_basis"]="re_opened re_broadcast re_rendered user_visible_prompt platform_doc advisory_component assumed not_applicable not_recorded unknown "
  DOM["mgmt.mdm_configurable"]="channel_only content_only yes no not_recorded unknown "
  DOM["mgmt.word_family"]="egress_control lockscreen_surface screensaver call_recording not_recorded unknown "
  DOM["mgmt.key_in_inventory"]="yes no not_checked not_recorded unknown "
  DOM["mgmt.payload"]="com.apple.applicationaccess com.apple.education com.apple.airplay none not_applicable not_recorded unknown "
  DOM["mgmt.supervised"]="yes no not_recorded unknown "
  DOM["mgmt.key_source"]="restrictions_inventory official_doc vendor_claim none not_recorded unknown "
  DOM["adv.component_is_egress_layer"]="yes no not_checked not_recorded unknown "
  DOM["adv.kev_listed"]="yes no not_checked not_applicable not_recorded unknown "
  DOM["adv.impact_word"]="screen keystroke peer vnc record display mirror none not_recorded unknown "
  DOM["adv.platform_row"]="iOS iPadOS macOS tvOS watchOS visionOS not_recorded unknown "
  DOM["adv.case_mismatch_checked"]="yes no not_recorded unknown "
  DOM["adv.patch_channel"]="whole_version rapid_security_response background_improvement not_release not_determinable not_recorded unknown "
  DOM["doc.conclusion"]="confirmed absent_in_ledger not_determinable assumed not_recorded unknown "
  BOOL["land.persist_after_share"]=1; BOOL["land.trimmed"]=1
  DT["obs.read_at"]=1; DT["undo.verified_at"]=1
  NS["id"]=1; NS["consent"]=1; NS["chan"]=1; NS["dom"]=1; NS["land"]=1; NS["obs"]=1
  NS["notice"]=1; NS["undo"]=1; NS["mgmt"]=1; NS["adv"]=1; NS["doc"]=1; NS["sec"]=1
  split("S01 S02 S03 S04 S05 S06 S07 S08 S09 K01 K02 K03", hb, " ")
  for (i in hb) HB[hb[i]] = 1
  split("id.bundle_id id.team_id id.session_ref chan.api_entry chan.service_endpoint adv.component obs.crash_report_ref mgmt.restriction_key doc.source doc.line_ref adv.cve adv.fix_version notice.notice_note", extra, " ")
  for (i in extra) KNOWN[extra[i]] = 1
  for (f in DOM) KNOWN[f] = 1
  for (f in BOOL) KNOWN[f] = 1
  for (f in DT) KNOWN[f] = 1
  split("id.session_kind id.source_face consent.granted_by chan.egress_path chan.process_owner dom.domain_class land.destination obs.plane notice.prompt_shown undo.reset_method mgmt.mdm_configurable doc.source", REQ, " ")
  EG["movie_recording"]=1; EG["live_broadcast"]=1; EG["mirroring"]=1; EG["companion_display"]=1; EG["external_display"]=1
  CROSS["remote_mac"]=1; CROSS["third_party_service"]=1; CROSS["vehicle_display"]=1; CROSS["external_receiver"]=1; CROSS["home_hub"]=1
  WORD4["Screen Sharing Server"]=1; WORD4["Remote Management"]=1; WORD4["smbx"]=1; WORD4["Siri"]=1
  SIX["IOMobileFrameBuffer"]=1; SIX["IOSurface"]=1; SIX["ReplayKit"]=1
  SIX["Screen Sharing"]=1; SIX["Screen Sharing Server"]=1; SIX["WindowServer"]=1
  SAME["allowCallRecording"]=1; SAME["allowAutomaticScreenSaver"]=1; SAME["allowLockScreenControlCenter"]=1
  SAME["allowLockScreenNotificationsView"]=1; SAME["allowLockScreenTodayView"]=1
  VD["J1"]="十二格齐备且无阻断信号：这一次画面外流可进入对外归属表述"
  VD["J2"]="仅 1—2 条非结构性信号：可作内部台账使用，暂不对外表述"
  VD["J3"]="3 条以上非结构性信号：归属结论尚未收敛"
  VD["J4"]="存在结构性或拒收信号（S／K 族或必备格缺失）：本行不可用"
  DOC["A01"]="见 B/apple-platform-security-guide.txt 第 4241 行（录制开始前 ReplayKit 呈现用户同意提示）与 B/mdm-restrictions.txt 第 1018 行（管理面里学生注册课程即自动给出「不被提示」的同意）——两处授权的主体不同"
  DOC["A02"]="见 B/apple-platform-security-guide.txt 第 4241 行（Before recording starts, ReplayKit presents a user consent alert…）：提示在前、采集在后，二者顺序不可颠倒登记"
  DOC["A03"]="见 B/apple-platform-security-guide.txt 第 4241 行（This alert is presented once per app process）：公开口径只给「每个 App 进程一次」，per_device／per_session／per_stream 都是台账自行加严或放宽"
  DOC["A04"]="见 B/apple-platform-security-guide.txt 第 4238 行（users can annotate their content using the device’s front camera and microphone）与第 2262 行（macOS 权限清单里 Screen recording 与 Input monitoring 并列为一类）"
  DOC["A05"]="见 B/apple-platform-security-guide.txt 第 1438 行（Remote unlock for iPhone Mirroring … Secure ranging isn’t required）：镜像的远程解锁明确不需要安全测距"
  DOC["A06"]="见 B/apple-platform-security-guide.txt 第 1439 行（首次设置时用户在「Automatically authenticate」与「Ask every time」之间选择，由 Mac 侧 Secure Enclave 执行这一选择）"
  DOC["B01"]="见 A/uikit_uiscenesession.txt 第 13 行（UIKit 在场景整个生命周期内持有会话信息）与第 123 行（A unique identifier that persists for the lifetime of the session）：会话标识是公开口径里的第一格，不可判定就不能给确认结论"
  DOC["B02"]="见 B/apple-platform-security-guide.txt 第 4241 行（movie recording 的同意提示）与第 4246 行（ReplayKit broadcasting 节名）：录制与广播是两个会话类，通道词不能互换"
  DOC["B03"]="见 A/replaykit_rpsystembroadcastpickerview.txt 第 11 行（用户点按广播按钮后显示选择器）与 A/uikit_uiscenesession.txt 第 13 行（用户在 App 切换器里关闭场景即销毁会话）：进入面是 App 内控件时，来源不能记成管理面"
  DOC["B04"]="见 A/replaykit_rpsystembroadcastpickerview.txt 第 13 行（把选择器限定到某个 provider 的方式是设置成 broadcast extension 的 bundle identifier）——本层公开口径里包标识是点分段标识"
  DOC["B05"]="见 usage 文本形态受检字段清单（团队标识是 10 位字母数字串；写成别的形状说明这一格不是从公开材料抄来的）"
  DOC["B06"]="见 A/uikit_uiscenesession.txt 第 137 行（The scene associated with the current session）：跨会话引用必须指向一份点分段标识，且被引对象要在同一份台账里存在"
  DOC["C01"]="见 B/apple-platform-security-guide.txt 第 4242 行（出进程采集在 replayd）与第 4243 行（in-app 采集拿得到 sample buffers）：通道件必须指名走的是这两条中的哪一条"
  DOC["C02"]="见 B/apple-platform-security-guide.txt 第 4242 行（Screen and audio capture occurs out of the app’s process in the ReplayKit daemon replayd）"
  DOC["C03"]="见 B/apple-platform-security-guide.txt 第 4242 行（This is designed to ensure the recorded content is never accessible to the app process）"
  DOC["C04"]="见 B/apple-platform-security-guide.txt 第 4243 行（This allows an app to get video and sample buffers, which is guarded by the permissions dialogue）"
  DOC["C05"]="见 B/apple-platform-security-guide.txt 第 4249 行（两个扩展、配置 com.apple.broadcast-services 端点）与第 4257 行（上传扩展处理 raw unencoded sample buffers 且数据被 serialized）"
  DOC["C06"]="见 B/apple-platform-security-guide.txt 第 4249 行（端点写作 com.apple.broadcast-services 这一种点分段形态）与 A/replaykit_rpscreenrecorder.txt 第 3 行、A/carplay_cpinterfacecontroller.txt 第 15 行（公开符号名逐字给出）：接口标识写成别的形态即不是这一层里的入口"
  DOC["C07"]="见 A/replaykit_rpscreenrecorder.txt 第 4 行（Use ScreenCaptureKit instead）、A/replaykit_rppreviewviewcontroller.txt 第 4 行、A/replaykit_rpsystembroadcastpickerview.txt 第 4 行与 A/replaykit_rpscreenrecorder_isrecording.txt 第 4 行：四处同句说明本层入口有两套公开口径"
  DOC["C08"]="见 A/replaykit_rpscreenrecorder.txt 第 13 行（Only one app at a time can use the recorder on the user’s device）：并发上限是公开口径里唯一一句"
  DOC["C09"]="见 B/apple-platform-security-guide.txt 第 4245 行（预览与分享的界面由 ReplayKit 提供且 out-ofprocess 呈现）与 A/replaykit_rppreviewviewcontroller.txt 第 11 行（录制完成后预览对象被交给回调）"
  DOC["D01"]="见 B/apple-platform-security-guide.txt 第 4250 行（hosting apps have no privileges to the broadcasted content，只有 ReplayKit 与第三方广播扩展有访问权）"
  DOC["D02"]="见 B/apple-platform-security-guide.txt 第 1431 行（同一 Apple 账户的设备用本地点对点协议交换密码学身份）"
  DOC["D03"]="见 B/apple-platform-security-guide.txt 第 1374 行（AirPlay 用认证 IC 校验接收端；音频与 CarPlay 视频流经 MFi-SAP）与第 1382 行（相互认证的 Station-to-Station 协议与长期密钥）"
  DOC["D04"]="见本文第 3.4 节失败点（截屏与厂商说法不能充当机制依据）"
  DOC["D05"]="见 B/apple-platform-security-guide.txt 第 3901 行（AirDrop 与 AirPlay 用的点对点 Wi-Fi 连接采用随机化 MAC 地址）"
  DOC["D06"]="见 B/apple-platform-security-guide.txt 第 4242 行（采集发生在 replayd）与 A/uikit_uiwindow.txt 第 18 行（额外窗口通常用于在外屏显示内容）：出流进程归属与执行域类别必须一致"
  DOC["E01"]="见 B/apple-platform-security-guide.txt 第 4244 行（影片写入只有 ReplayKit 子系统可访问的目录）"
  DOC["E02"]="见 B/apple-platform-security-guide.txt 第 4244 行（…is never accessible to any apps）：落点在 ReplayKit 目录时写域不能记成 App 容器可读"
  DOC["E03"]="见 A/replaykit_rppreviewviewcontroller.txt 第 3 行（预览并编辑一段录制）与 A/replaykit_rpscreenrecorder.txt 第 13 行（用户界面里可以裁剪与预览）"
  DOC["E04"]="见 A/replaykit.txt 第 5 行（录下的内容随后经邮件、信息或社交媒体分享给其他用户）与 B/apple-platform-security-guide.txt 第 4257 行（广播上传扩展）"
  DOC["E05"]="见 A/replaykit_rpbroadcastconfiguration.txt 第 3 行（配置直播过程中产生的 movie clips）——mp4_clip 只属于直播形态"
  DOC["O01"]="见 B/apple-platform-security-guide.txt 第 1429 行（iPhone 保持锁定，锁屏面上有一条持续通知）：锁屏通知读不出执行域"
  DOC["O02"]="见 A/uikit_uiscene.txt 第 199 与 217 行（on-screen 与 off-screen 是两条系统通知）与 usage 文本的 obs.read_at 格（有观测平面必须登记读数时刻）"
  DOC["O03"]="见 B/apple-platform-security-guide.txt 第 2262 行（macOS 把 Screen recording 列为可与 Input monitoring 并列的一类权限状态）：可核对的状态在系统侧，不在 App 自述里"
  DOC["O04"]="见 B/apple-platform-security-guide.txt 第 708 行（不可信软件即使取得 root 或内核权限也无法在不点亮屏上采集指示灯的情况下启用摄像头）与第 4245 行（预览与分享界面 out-ofprocess）"
  DOC["N01"]="见 B/apple-platform-security-guide.txt 第 4241 行（同意提示先于录制）与第 4243 行（in-app 采集受权限对话框守护）"
  DOC["N02"]="见 B/apple-platform-security-guide.txt 第 1429 行（被远端使用期间锁屏上有持续通知）"
  DOC["N03"]="见本文第 3.4 节失败点（截屏与厂商说法不能充当告知文本依据）"
  DOC["N04"]="见 C/readings-19.txt 第 99 行（allowLockScreenNotificationsView 命中画面语义词清单）：锁屏通知面可被管理面关闭，「锁屏不可见」与「从锁屏通知读数」不能同时成立"
  DOC["N05"]="见 B/apple-platform-security-guide.txt 第 1439 行（首次设置的两种选择决定后续是否再提示）与第 1431 行（通知转发建立在同一 Apple 账户的配对之上）"
  DOC["V01"]="见 A/replaykit_rpscreenrecorder.txt 第 240、251、267 行（三个停止口里只有 stopRecordingWithOutputURL:completionHandler: 在签名里出现输出 URL）"
  DOC["V02"]="见 A/replaykit_rpscreenrecorder.txt 第 88 行（Discards the current recording.）与第 90、97 行（discardRecording、discardRecordingWithHandler: 两个方法名）——丢弃是一个独立复位口"
  DOC["V03"]="见 C/kev-apple.tsv 第 2 行（dateAdded 与 dueDate 都是 YYYY-MM-DD 形态）与 usage 文本的 undo.verified_at 格"
  DOC["V04"]="见 B/apple-platform-security-guide.txt 第 4244 行（复位针对的是影片目录的可访问性）与第 4242 行（采集面本身在 replayd 内）"
  DOC["G01"]="见 C/readings-19.txt 第 92 行（218 个形态命中行里出现画面语义词的键为 13 个）与第 95—107 行的键名清单"
  DOC["G02"]="见 C/readings-19.txt 第 96—100 行（allowAutomaticScreenSaver、allowCallRecording 与三个 allowLockScreen* 命中词形但不约束画面离开设备）"
  DOC["G03"]="见 B/mdm-restrictions.txt 第 726 行（Nest this key beneath … as a subrestriction）：子约束键必须写清它挂在哪一份 payload 下"
  DOC["G04"]="见 B/mdm-restrictions.txt 第 1018 行（课程内的学生自动给出同意且不提示）与第 729 行（Classroom 不观察远端屏幕这一条要求受管设备）"
  DOC["G05"]="见 B/mdm-restriction-keys.txt 第 5—8 行（逐行都是 allow 前缀的小驼峰单标识；写成路径或带空格即不是这一份清单里的键）"
  DOC["R01"]="见 C/readings-19.txt 第 48—52 行（含 screen 的 13 行分布在 Screen Sharing Server 6、Remote Management 3、smbx 3、Siri 1 四个组件）"
  DOC["R02"]="见 C/advisory-19.tsv 表头（file、platform、component、cve、impact、avail 六列）与 C/readings-19.txt 第 61—63 行（三条 CVE 逐条都是 CVE-年-序号形态）"
  DOC["R03"]="见 C/readings-19.txt 第 8—10 行与第 11—16 行（子集 40 行、13 个去重 CVE、六个组件名及其行数）"
  DOC["R04"]="见 C/readings-19.txt 第 56—57 行（含 maliciously crafted 的 467 行里，同时出现画面语义词的 0 行；crafted 行里组件名含 screen 的 0 个）"
  DOC["R05"]="见 C/readings-19.txt 第 45 行（原样匹配大写 VNC 得 6；整列小写化后仍用大写模式匹配得 0——这是一条假读数；小写化＋小写模式得 6）"
  DOC["R06"]="见 B/apple-platform-security-guide.txt 第 180 行（除特别注明外覆盖 iOS 26.5、iPadOS 26.5、macOS 26.5 等版本——版本号是「平台名 + 主.次」形态）"
  DOC["R07"]="见 C/kev-apple.tsv 第 2 行（CVE-2026-86950 同时给出 dateAdded 与 dueDate，说明存在已发布版本）与 C/readings-19.txt 第 83—85 行（KEV 里画面语义词命中 2 条）"
  DOC["X01"]="见本文第 3.4 节失败点 8（口径之间不能直接换算，结论必须回到文件与行号）"
  DOC["X02"]="见 usage 文本（行号引用只写 `1234` 或 `6-9` 这一种形态，带「第／行」前缀的写法在两份台账之间不可换算）"
  DOC["S01"]="见 usage 文本的行格式（一行只登记一个会话的一个字段，列数固定为三）"
  DOC["S02"]="见 usage 文本的行格式（会话标识是行第一列，缺失时无法判断这一格属于哪一次画面外流）"
  DOC["S03"]="见 usage 文本（同一会话的同一字段只能有一个取值，重复登记会让后值静默覆盖前值）"
  DOC["S04"]="见 usage 文本的十二个命名空间清单（命名空间是字段归属判断层的唯一依据）"
  DOC["S05"]="见 usage 文本的字段清单（清单外的字段名不会被任何判定读取）"
  DOC["S06"]="见 usage 文本（值里不能含逗号；留空等同没有登记这一格）"
  DOC["S07"]="见 usage 文本的枚举字段与布尔位（枚举值必须由登记方选定，不接受自由文本）"
  DOC["S08"]="见 C/kev-apple.tsv 表头（dateAdded、dueDate 两列使用 YYYY-MM-DD 形态，本脚本的日期格按同一形态校验）"
  DOC["S09"]="见 usage 文本的必备格清单"
  DOC["K01"]="见本脚本头部注释的拒收声明"
  DOC["K02"]="见本脚本头部注释：文件正文、设备路径、密钥串与超长载荷一律拒收"
  DOC["K03"]="见本文第 12 章（观测面只登记报告标识，不粘贴堆栈、日志或截屏正文）"
}
{
  if ($0 ~ /^[ ]*#/ || $0 ~ /^[ ]*$/) next
  sub(/\r$/, "")
  if (NF < 3) { emit("S01", $1, "列数不足 3：" $0); next }
  id = $1; f = $2; v = $3
  for (i = 4; i <= NF; i++) v = v "," $i
  if (id == "") { emit("S02", "", "会话标识为空：" f); next }
  if (!(id in SEEN)) { SEEN[id] = 1; ORD[++noid] = id }
  k = id SUBSEP f
  if (k in valof) emit("S03", id, "同一字段重复登记：" f)
  valof[k] = v
  ns = f; sub(/\..*$/, "", ns)
  if (!(ns in NS)) { emit("S04", id, "未登记的命名空间：" f); next }
  if (ns == "sec") { emit("K01", id, "sec.* 拒收空间出现字段：" f); next }
  if (!(f in DOM) && !(f in BOOL) && !(f in DT) && !(f in KNOWN)) { emit("S05", id, "未登记字段名：" f); next }
  if (v == "") { emit("S06", id, "取值为空：" f); next }
  if (f in DOM && f != "chan.api_entry" && f != "chan.service_endpoint") { if (!hasToken(DOM[f], v)) emit("S07", id, "枚举越界：" f "=" v) }
  else if (f in BOOL) { if (!isbool(v)) emit("S07", id, "布尔位取值非法：" f "=" v) }
  else if (f in DT)  { if (!isISOdt(v)) emit("S08", id, "日期形态非法：" f "=" v) }
  if (devPath(v) || longBlob(v) || b64ish(v) || secretish(v)) emit("K02", id, "取值形似设备路径／长载荷／密钥串，拒收：" substr(v,1,20) "...")
  if (f == "id.bundle_id" && !isBundle(v) && !isNA(v))    emit("B04", id, "包标识登记不合法：" v)
  if (f == "id.team_id" && !isTeamID(v) && !isNA(v))      emit("B05", id, "团队标识形态非法：" v)
  if (f == "id.session_ref" && !isDotId(v) && v != "none" && !isNA(v)) emit("B06", id, "跨会话引用不合法：" v)
  if (f == "chan.api_entry" && !isDotId(v) && !hasToken(DOM["chan.api_entry"], v) && v !~ /^[A-Za-z0-9_-]+$/ && !isNA(v)) emit("C06", id, "接口标识形态非法：" v)
  if (f == "chan.service_endpoint" && !hasToken(DOM["chan.service_endpoint"], v) && !isDotId(v) && !isNA(v)) emit("C06", id, "服务端子点形态非法：" v)
  if (f == "adv.cve" && !isCVE(v) && v != "none" && !isNA(v)) emit("R02", id, "CVE 形态非法：" v)
  if (f == "adv.fix_version" && !isVer(v) && v != "none" && !isNA(v)) emit("R06", id, "修复版本形态非法：" v)
  if (f == "mgmt.restriction_key" && v !~ /^[a-z][a-zA-Z0-9]+$/ && v != "none" && !isNA(v)) emit("G05", id, "限制键形态非法：" v)
  if (f == "doc.line_ref" && !isLineRef(v) && !isNA(v))   emit("X02", id, "行号引用形态非法：" v)
  if (f == "obs.crash_report_ref" && v !~ /^[A-Za-z0-9-]{6,40}$/ && v != "absent" && v != "not_applicable" && !isNA(v)) emit("K03", id, "观测引用不是报告标识形态")
  if (id ~ /^REC_/) PREF["REC"]++
  if (id ~ /^BCA_/) PREF["BCA"]++
  if (id ~ /^MIR_/) PREF["MIR"]++
  if (id ~ /^CMP_/) PREF["CMP"]++
  if (id ~ /^(REC|BCA|MIR|CMP)_/) PREFOK[id] = 1
  next
}
END {
  for (oi = 1; oi <= noid; oi++) {
    id = ORD[oi]
    p3 = substr(id, 1, 3)
    if (p3 == "REC" || p3 == "BCA" || p3 == "MIR" || p3 == "CMP") SD[p3]++
    for (ri = 1; ri <= 12; ri++) {
      if (!REQ[ri]) break
      if (isNA(GV(id, REQ[ri]))) { emit("S09", id, "必备格缺失：" REQ[ri]); miss[id] = 1 }
    }
    sk  = GV(id, "id.session_kind"); cw = GV(id, "id.channel_word")
    face = GV(id, "id.source_face"); prov = GV(id, "id.provenance")
    ref = GV(id, "id.session_ref"); bs = GV(id, "id.bundle_id")
    gb = GV(id, "consent.granted_by"); as = GV(id, "consent.alert_shown")
    scope = GV(id, "consent.alert_scope"); mic = GV(id, "consent.microphone_used")
    cam = GV(id, "consent.camera_used"); rang = GV(id, "consent.secure_ranging")
    pc = GV(id, "consent.pairing_choice")
    path = GV(id, "chan.egress_path"); buf = GV(id, "chan.buffer_form")
    po = GV(id, "chan.process_owner"); st = GV(id, "chan.entry_status")
    ha = GV(id, "chan.host_has_access"); ec = GV(id, "chan.extension_count")
    ep = GV(id, "chan.service_endpoint"); pv = GV(id, "chan.preview_surface")
    sh = GV(id, "chan.share_surface"); cl = GV(id, "chan.concurrent_limit")
    dcls = GV(id, "dom.domain_class"); iso = GV(id, "dom.isolation_mechanism")
    pvf = GV(id, "dom.pairing_verified"); tr = GV(id, "dom.transport")
    rnd = GV(id, "dom.mac_randomized"); dsrc = GV(id, "dom.domain_source")
    dest = GV(id, "land.destination"); ws = GV(id, "land.write_scope")
    per = GV(id, "land.persist_after_share"); trimm = GV(id, "land.trimmed")
    so = GV(id, "land.stored_object")
    plane = GV(id, "obs.plane"); fld = GV(id, "obs.field_read"); rat = GV(id, "obs.read_at")
    ind = GV(id, "obs.indicator_visible")
    ps = GV(id, "notice.prompt_shown"); bk = GV(id, "notice.banner_kind")
    lsv = GV(id, "notice.lockscreen_visible"); od = GV(id, "notice.origin_disclosed")
    wts = GV(id, "notice.warning_text_source"); note = GV(id, "notice.notice_note")
    rmth = GV(id, "undo.reset_method"); our = GV(id, "undo.output_url_returned")
    rc = GV(id, "undo.residue_claimed"); rp = GV(id, "undo.reproof_done")
    rb = GV(id, "undo.reproof_basis"); vat = GV(id, "undo.verified_at")
    mc = GV(id, "mgmt.mdm_configurable"); rk = GV(id, "mgmt.restriction_key")
    wf = GV(id, "mgmt.word_family"); kii = GV(id, "mgmt.key_in_inventory")
    pay = GV(id, "mgmt.payload"); sup = GV(id, "mgmt.supervised"); ksrc = GV(id, "mgmt.key_source")
    cmpn = GV(id, "adv.component"); cpl = GV(id, "adv.component_is_egress_layer")
    kev = GV(id, "adv.kev_listed"); iw = GV(id, "adv.impact_word")
    cmc = GV(id, "adv.case_mismatch_checked"); pch = GV(id, "adv.patch_channel")
    concl = GV(id, "doc.conclusion"); srcf = GV(id, "doc.source")

    if (sk != "none" && face == "mdm_profile" && !EG[sk] && sk != "remote_observation") emit("B02", id, "会话类与通道词不同族：管理面进入面不承载本机外流")
    if ((prov == "managed_by_mdm" || prov == "course_managed") && (face == "in_app_button" || face == "broadcast_picker" || face == "preview_share_ui" || face == "control_center")) emit("B03", id, "进入面与来源矛盾：" face " vs " prov)
    if (!PREFOK[id]) { emit("B01", id, "会话标识前缀不在 REC_／BCA_／MIR_／CMP_ 四类内：" id) }
    if (ref != "" && !(ref in SEEN)) emit("B06", id, "跨会话引用不合法：指向本台账里不存在的对象：" ref)
    if (isNA(bs) && (sk == "live_broadcast" || sk == "movie_recording") && concl == "confirmed") emit("B04", id, "包标识登记不合法：录制或广播会话给确认结论却未登记承载它的包标识")
    if (cw == "ReplayKit" && (sk == "mirroring" || sk == "companion_display")) emit("B02", id, "会话类与通道词不同族：ReplayKit 不承载镜像或伴生显示")
    if (gb == "mdm_profile" && as == "yes") emit("A01", id, "同意来源记成管理面却又登记设备侧弹出了提示")
    if (gb == "user_alert" && as == "no") emit("A02", id, "同意来源记成用户提示但提示位登记为未出现")
    if (scope != "once_per_app_process" && !isNA(scope) && as == "yes") emit("A03", id, "提示范围偏离公开口径：" scope)
    if ((mic == "yes" || cam == "yes") && isNA(as)) emit("A04", id, "麦克风或摄像头参与采集却未登记提示位")
    if (sk == "mirroring" && rang == "required") emit("A05", id, "镜像会话把安全测距登记为必要条件")
    if (cw == "iPhoneMirroring" && isNA(pc) && sk != "not_applicable") emit("A06", id, "镜像会话未登记配对选择（自动认证／每次询问）")
    if (isNA(path) || path == "not_applicable" || path == "none") { if (EG[sk]) emit("C01", id, "画面外流通道件缺失：" sk) }
    if (po == "replayd" && path == "in_app_sample_buffer") emit("C02", id, "进程归属与通道形态矛盾：出进程 daemon 却登记 App 内取样")
    if (path == "out_of_process_capture" && ha == "yes") emit("C03", id, "出进程采集却称 App 进程读得到画面内容")
    if (path == "in_app_sample_buffer" && ha == "never_accessible") emit("C04", id, "App 内取样通道却称内容永不被 App 访问")
    if (path == "broadcast_upload" && (isNA(ec) || isNA(ep) || isNA(buf))) emit("C05", id, "广播通道件缺失：扩展数量、服务端子点或缓冲形态未登记")
    if (st == "superseded" && as != "no") emit("C07", id, "被取代口径仍用作现用依据：入口已换新但提示位未换")
    if ((sk == "movie_recording" || path == "out_of_process_capture") && isNA(cl)) emit("C08", id, "录制类会话未登记并发上限")
    if (pv == "in_process" && sh == "system_vended") emit("C09", id, "预览面与分享面口径混用：进程内预览配系统提供的分享面")
    if (isNA(dcls)) emit("D01", id, "执行域类别未登记")
    if (iso == "none" && (dest in CROSS)) emit("D02", id, "画面落点跨设备却登记为无隔离机制：" dest)
    if (tr == "local_peer_to_peer" && isNA(pvf)) emit("D03", id, "本地点对点传输未登记配对核验形态")
    if (dsrc == "vendor_claim" || dsrc == "screenshot" || dsrc == "assumed") emit("D04", id, "执行域结论只来自厂商说法、截屏或假定：" dsrc)
    if (tr == "wifi_network" && isNA(rnd)) emit("D05", id, "登记了 Wi-Fi 承载但未核对地址随机化口径")
    if (po == "replayd" && dcls == "app_sandboxed") emit("D06", id, "画面由 replayd 取出但执行域记成 App 沙箱内")
    if (isNA(dest) || dest == "not_applicable" || dest == "none") { if (EG[sk]) emit("E01", id, "画面外流落点缺失：" sk) }
    if (dest == "local_movie" && ws == "app_container") emit("E02", id, "落点为本地影片却把写域记成 App 容器可访问")
    if (pv != "not_applicable" && !isNA(pv) && isNA(trimm)) emit("E03", id, "登记了预览面但未登记是否裁剪")
    if (dest == "third_party_service" && isNA(per)) emit("E04", id, "画面交给第三方服务但未登记分享后是否留存")
    if (so == "mp4_clip" && sk != "live_broadcast") emit("E05", id, "存储对象为直播影片片段但会话不是直播")
    if (plane == "lock_screen_notice" && fld == "domain_class") emit("O01", id, "锁屏通知面读不出执行域")
    if (plane != "none" && plane != "not_recorded" && plane != "not_determinable" && isNA(rat)) emit("O02", id, "有观测平面却未登记读数时刻")
    if ((plane == "vendor_claim" || plane == "app_self_report") && concl == "confirmed") emit("O03", id, "只靠自述平面给出确认结论：" plane)
    if (ind == "yes" && plane != "camera_indicator" && plane != "not_recorded" && !isNA(plane)) emit("O04", id, "登记了采集指示灯可见但观测平面不是指示灯面：" plane)
    if (EG[sk] && isNA(ps)) emit("N01", id, "画面确已离开设备但告知位未登记：" sk)
    if (sk == "mirroring" && bk == "none" && as == "yes") emit("N02", id, "镜像会话登记无提示横幅但同意提示为已出现")
    if (wts == "screenshot" || wts == "assumed") emit("N03", id, "告知文本依据是截屏或假定：" wts)
    if (lsv == "no" && plane == "lock_screen_notice") emit("N04", id, "称锁屏通知面不可见却从锁屏通知取数")
    if (ps == "no" && od == "absent" && EG[sk] && note == "") emit("N05", id, "画面离开设备但无提示、无来源披露且无任何说明句")
    if (rmth ~ /^(stop_recording|discard_recording)$/ && isNA(our)) emit("V01", id, "复位走停止或丢弃口但未登记输出 URL 是否被交出")
    if (istrue(rp) && rb == "assumed") emit("V02", id, "再证明依据为假定")
    if (istrue(rc) && isNA(vat)) emit("V03", id, "声称有残留但未登记核对时刻")
    if (rmth == "not_determinable" && istrue(rp)) emit("V04", id, "复位方法不可判定却声称已再证明")
    if (mc == "content_only" && isNA(rk)) emit("G01", id, "管理面结论缺键名或未核对：称可配内容却没有键名")
    if (!isNA(rk) && (rk in SAME) && wf == "egress_control") emit("G02", id, "该键命中词形但不约束画面离开设备：" rk)
    if (!isNA(pay) && pay != "not_applicable" && pay != "none" && isNA(ksrc)) emit("G03", id, "登记了 payload 却没写键来源")
    if (gb == "course_enrollment" && pay == "com.apple.education" && ksrc == "restrictions_inventory") emit("G04", id, "课程免提示同意被登记成设备用户自己的同意")
    if (istrue(sup) && kii == "not_checked" && !isNA(rk)) emit("G01", id, "管理面结论缺键名或未核对：受管设备但键不在 218 个形态命中行内")
    if (!isNA(iw) && iw != "none" && isNA(cmpn)) emit("R01", id, "登记了影响句词形却没有组件名")
    if (iw == "screen" && !isNA(cmpn) && !(cmpn in WORD4) && cpl != "yes") emit("R04", id, "词形为 screen 但组件不在含 screen 的四个组件内且未核对：" cmpn)
    if (cpl == "no" && concl == "confirmed") emit("R03", id, "组件名不属本层却用于确认结论：" cmpn)
    if (!isNA(cmpn) && !(cmpn in SIX) && cpl == "not_checked" && pch == "not_recorded") emit("R03", id, "组件名不属本层却用于确认结论：不在六组件子集内且既未核对也无补丁通道")
    if (!isNA(iw) && iw != "none" && cmc != "yes") emit("R05", id, "词形命中未核对大小写匹配形态（假读数风险）：" iw)
    if (kev == "yes" && pch == "not_release") emit("R07", id, "在 KEV 名单内却把补丁通道记为非发布")
    if (concl == "confirmed" && (isNA(srcf) || isNA(GV(id, "doc.line_ref")))) emit("X01", id, "确认结论缺来源文件或行号")

    if (miss[id] || (id in hard)) verdict = "J4"
    else if (percnt[id] + 0 == 0) verdict = "J1"
    else if (percnt[id] + 0 <= 2) verdict = "J2"
    else verdict = "J3"
    if (!QUIET) print verdict "\t" id "\t" VD[verdict]
    JDIST[verdict]++
  }
  tot = 0; codes = 0
  for (c in cnt) { tot += cnt[c]; codes++ }
  blocked = 0
  for (c in cnt) if (c in HB) blocked += cnt[c]
  printf "\n画面外流会话数=%d 信号行数=%d 判定行数=%d\n", noid, nline, noid
  printf "不同信号码=%d 阻断信号条数=%d\n", codes, blocked
  printf "判定分布 J1=%d J2=%d J3=%d J4=%d\n", JDIST["J1"]+0, JDIST["J2"]+0, JDIST["J3"]+0, JDIST["J4"]+0
  printf "前缀会话数 REC=%d BCA=%d MIR=%d CMP=%d\n", SD["REC"]+0, SD["BCA"]+0, SD["MIR"]+0, SD["CMP"]+0
  for (i = 1; i <= nline; i++) print lines[i] > "/dev/stderr"
  m = 0
  for (c in cnt) KEYS[++m] = c
  for (a = 1; a <= m; a++) for (b = a + 1; b <= m; b++) if (KEYS[b] < KEYS[a]) { t = KEYS[a]; KEYS[a] = KEYS[b]; KEYS[b] = t }
  for (a = 1; a <= m; a++) printf "%s\t%d\n", KEYS[a], cnt[KEYS[a]] > "/dev/stderr"
  exit (blocked > 0 ? 1 : 0)
}
' "$@"
```

---

## 22. 只读核验脚本二：画面外流三件差集与公告子词表比对器

脚本一逐条查登记内部，这一支查**三份登记之间**：同一条画面外流链路在采集件、落点件、告知件里各被说过一次，说的还是不是同一件事，说的东西在公开词表里存不存在。四类问题在头部第 3—8 行逐条写出：三件不成对、覆盖空洞、平面越界、归属悬空；四者与第 18 章五侧的对应关系见 22.5。

### 22.1 三份输入与边界

三份输入**顺序固定、全部只读**：第 102 行要求恰好三份（`[ $# -eq 3 ]`），少给多给一律退出码 2（`fewargs` 与 `noargs` 两次实跑都是 2）；第 103 行逐份检查可读性，任一份不可读同样是 2。三份的列格式各写在 usage 一处：

1. **三件清单**每行 10 列：`<会话标识>,<会话类>,<核对项>,<三件状态>,<读数平面>,<词表归属>,<引用>,<对外表述>,<画面来源面>,<外流时点>`（usage 第 26—27 行；判定在第 310 行 `n != 10` → `S01`）；
2. **三件能力表**每行 3 列：`<会话类>,<核对项>,<可得性>`（usage 第 74 行；第 358 行 `n != 3` → `C01`）；
3. **公开词表**为制表符分隔三列：`<词表类别>\t<词表值>\t<来源标识>`（usage 第 75—77 行），第 377 行跳过表头行 `kind<TAB>value`，第 379—382、394 行四条 emit 都在校验这张表自己的形态。

夹具规模是判定的分母：`FX/capability-19.csv` 182 行 = 2 行注释 + **180 条数据行**（9 个建模会话类 × 20 项核对项，一行不缺一行不多）；`FX/vocab-19.tsv` 91 行 = 3 行注释 + 1 行表头 + 87 条数据行，按归一化值（`nrm()`，第 115 行：小写化并去掉空格下划线斜杠点冒号）去重后 **80 条**；`FX/tri-19-good.txt` 184 行给九条会话。畸形对照件 `FX/capability-19-bad.csv` 12 行、只被读进 **3 条**有效行（`bad-capability` 实跑：`能力表行=3 信号行数=200 阻断信号条数=55 … 闭合等级 Q1=0 Q2=27 Q3=10 Q4=19`，第 1468—1470 行），`FX/vocab-19-bad.tsv` 6 行、只读出 **1 条**词条（`bad-vocabulary` 实跑：`词表词条=1 信号行数=841 阻断信号条数=108 … 闭合等级 Q1=0 Q2=48 Q3=6 Q4=2`，第 2470—2472 行）。

边界段（头部第 13—18 行）逐句写明：不联网取公告；不调用 `file`／`mdls`／`mdimport`／`mdutil`／`mdfind`／`spctl`／`codesign`／`defaults`／`log`／`sysctl`／`xcrun`／`profiles`／`plutil`／`sips`／`qlmanage`／`otool` 中任何一个（P14 显示这些名字只有两处落点——第 13 行的头部拒收声明与第 469 行 `K02` 的**拒收正则**，P14b 的命令位置探测为空匹配；P16 的整词普查得 `awk=1 cat=1 mktemp=2 rm=1`）；不打开、不截取、不录制任何被登记的画面；不修改输入；给出「三件不成对」或「覆盖空洞」**不等于补登记**；不给出任何关闭或欺骗采集提示的做法，`forceBypassScreenCaptureAlert` 只作为管理面读数的一格被核对存在形态。唯一写出目标是 `mktemp -d` 的临时目录，前缀 `sct19.`（第 105 行，与脚本一的 `scr19.` 分开，两者可并存不冲突），第 106 行 trap 删除，实现不向其写入任何字节。

### 22.2 三件 × 20 核对项 × 11 会话类 × 26 平面 × 12 词表归属的取值域

九个集合在 `BEGIN` 段（第 141—170 行）逐格写死，并在 usage 第 28—77 行全文枚举，取值域如下：

| 维度 | 数量 | 出处 | 备注 |
| --- | --- | --- | --- |
| 三件 | 3 | 第 144—146 行三次 `mkit` | 采集件 captured 7 项、落点件 landed 5 项、告知件 notified 8 项 |
| 核对项 | 20 | 同上 | 采集件 `capture_entry entry_status process_owner concurrent_limit isolation_mechanism preview_surface share_surface`；落点件 `egress_path landing_destination write_scope stored_object mac_randomized`；告知件 `prompt_shown banner_kind lockscreen_visible indicator_visible origin_disclosed pairing_verified persist_after_share reset_method` |
| 数组型核对项 | 1 | 第 161 行 `MULTI` | 只有 `landing_destination`；其余核对项一号一行 |
| 会话类 | 11 | 第 143 行 `KD` | 8 个画面外流类 + `system_service` + `not_recorded`／`unknown` 两个兜底类；与 11 个标识前缀 1:1（第 172—174 行 `PFX`，越界即 `S10`，第 319 行） |
| 读数平面 | 26 | 第 164 行 `PL` | 23 个实体面加 `none`／`not_recorded`／`unknown`；非法即 `S06` |
| 词表归属 | 12 | 第 165 行 `VW` | 9 个实体类别 + `doc_ref`／`mixed` 两个结构类别 + `not_recorded`／`unknown` 一档兜底；非法即 `S07`（第 323 行） |
| 三件状态 | 5 | 第 160 行 `ST` | `recorded absent not_applicable not_recorded unknown`；非法即 `S05` |
| 可得性 | 4 | 第 169 行 `AV` | `required optional not_applicable undocumented`；越界即 `C04` |
| 公开词表类别 | 9 | 第 170 行 `VK` | 类别不在集合内即 `X08` |
| 布尔位 | 7 | 第 162 行 `BOOL`、usage 第 71—73 行 | 取值只收 `BV` 五档（第 163 行），在判定之后的第 570—572 行复核 |

两套「谁能承载谁」的配对就是第 18 章五侧划分的代码出处：**31 组平面 × 件配对**播种在第 206—213 行（采集件 7 面、落点件 7 面、告知件 17 面），**18 组词表归属 × 件配对**播种在第 224—231 行；`T03`（第 520—521 行）查后者，`P05`（第 510—511 行）查前者。另有四张按公开口径逐类写死的承载表：`CEK[]` 八类会话的采集入口承载面（第 178—185 行）、`CEL[]` 八类的合法入口词形（第 187—194 行）、`ISOK[]` 五种隔离机制各自承载的会话类（第 196—200 行）、`APPBAD` 六个「把归属记成 App 进程内即不成立」的出进程采集类（第 176 行）。`P2P` 只有两个值（`mirroring_local`、`airplay_out`，第 202 行），它是 `T04`／`T06`／`T07` 三条点对判据的入口。

### 22.3 形态规则六条

usage 第 78—84 行给六条形态规则，判定体在第 480—485 行逐条落地，出处逐条给在 `DOC` 第 260—265 行：

- **符号形态**（`capture_entry`）：大写开头的驼峰标识，不含空格与斜杠（`isSymForm`，第 120 行），不合即 `M01`。出处 `A/replaykit.txt` 第 60、64、46、42 行与 `A/carplay_cpinterfacecontroller.txt` 第 5 行（公开符号逐字给出，都是大写开头的驼峰标识）。
- **端子点形态**（`endpoint_tag`）：点分段标识（`isIdForm`，第 119 行），不合即 `M02`。出处 `B/apple-platform-security-guide.txt:4249`——`com.apple.broadcast-services` 是公开口径里唯一写法。
- **限制键形态**（`restriction_key`）：小写开头的单个驼峰标识，不含空格、斜杠与点（`isKeyForm`，第 121 行），不合即 `M03`。出处 `B/mdm-restriction-keys.txt:5—8` 与 `C/readings-19.txt:95—107`（13 个画面语义词命中键全是这一种形态）。
- **CVE 形态**（`advisory_cve`）：`CVE-年-序号`（`isCve`，第 118 行），不合即 `M04`。出处 `C/advisory-19.tsv` 表头与 `C/readings-19.txt:61—63`。
- **落点形态**（`landing_destination`）：字母数字与下划线组成的单标识，不含斜杠、冒号与空格（`isDestForm`，第 123 行），不合即 `M05`。出处 `B/…guide.txt:4244`——落点登记为一个类别名，不是设备绝对路径。
- **进程名形态**（`process_name`）：全小写单标识（`isProcForm`，第 122 行），不合即 `M06`。出处 `B/…guide.txt:4242`——本层公开口径逐字给出的进程名只有 `replayd` 这一种全小写形态。

`M05` 还有两条近义词与越表路径（第 488—489 行）：引用值命中 `NEAR` 那 30 个近义单词（`recording broadcast mirroring … serialized`，第 159 行）算「公开词形的近义词」；既不在该格 `TOK[]` 词形表里、归一化后又不在公开词表里，同样算 `M05`。`TOK[]` 十格的逐格词形表写在第 148—157 行，与 usage 第 53—70 行逐字对应。

### 22.4 九族 60 个信号码一览

| 族 | 码数 | 管什么（判据行号在本支脚本内） | 是否阻断 |
| --- | --- | --- | --- |
| S | 10 | 清单自身形态：列数不是十（`S01`，310 行）、会话标识为空或含空白（`S02`，314 行）、会话类越界（`S03`，317 行）、核对项越界（`S04`，318 行）、三件状态非法（`S05`，321 行）、读数平面非法（`S06`，322 行）、词表归属／对外表述／画面来源面／外流时点四列越界（`S07`，323—326 行）与布尔位越界（572 行）、数组型重复登记（`S08`，333 与 338 行两条 emit）、同一核对项出现两种登记口径（`S09`，339 行）、前缀与会话类不符（`S10`，319 行） | 全部阻断 |
| C | 5 | 能力表自身形态：行形态非法（`C01`，358 行）、会话类越界（`C02`，360 行）、核对项越界（`C03`，361 行）、可得性越界（`C04`，362 行）、可得性基准不可用（`C05`，365—366 行两条 emit 加第 400 行「三件能力表一条有效行都没有」） | 全部阻断 |
| K | 5 | 归属与越界：引用格形似密钥、口令、归档文件、设备绝对路径或整段载荷（`K01`，467—468 行，判据 `isSecretish` 第 125—130 行）、引用格登记设备侧命令行入口名（`K02`，469—470 行，那一串工具名是**拒绝**模式不是执行点）、出进程采集类把归属记成 App 进程内（`K03`，471—472 行）、隔离机制与承载会话类不符（`K04`，473—474 行）、提示绕过键进入通道件（`K05`，475—476 行） | 全部阻断 |
| M | 6 | 公开词形六条形态规则（见 22.3，第 480—485 行；`M05` 另有近义词与越表两条 emit） | 全部阻断 |
| D | 5 | 覆盖空洞：required 被明确记为不存在（`D01`，452 行）、required 完全没有登记行或无读数（`D02`，445 与 453 行两条 emit）、不适用与能力表冲突（`D03`，454 与 457—459 行两条 emit）、会话类未建模（`D04`，408 行）、某核对项整张清单零登记（`D05`，402 行） | 全部非阻断 |
| P | 7 | 平面越界：已读数却挂 `none` 面（`P01`，501 行）、落点件记在采集指示灯面（`P02`，502—503 行）、采集件记在公告或 KEV 面（`P03`，504—505 行）、复位口记在采集面（`P04`，506—507 行）、平面与核对项不配对（`P05`，510—511 行）与采集入口不在该类承载面清单（512—513 行，同码两条 emit）、告知件记在接口引用面（`P06`，508—509 行）、来源面与读数平面错配（`P07`，514—517 行两条 emit） | 全部非阻断 |
| T | 8 | 三件差集与矛盾：只登记采集件而无落点与告知（`T01`，411—412 行）、有落点或告知而无采集件（`T02`，413—414 行）、词表归属与件层不配对（`T03`，520—521 行）、点对点缺配对核验（`T04`，419—420 行）、同一会话既 `current` 又 `superseded`（`T05`，415—416 行）、会话类与入口不符（`T06`，423—424 与 426—427 行两条 emit）、地址随机化口径冲突（`T07`，421—422 行）、对外表述为是但该类必需格缺位（`T08`，428—438 行） | `T01`／`T02` 非阻断，`T03`—`T08` 阻断 |
| X | 8 | 公开词表比对：公告组件悬空（`X01`，535 与 538 行两条 emit）、子词表成员不成立（`X02`，534 与 539—540 行两条 emit）、CVE 悬空（`X03`，530 行）、限制键悬空（`X04`，531 行）、机制词悬空（`X05`，532 行）、符号或声明键悬空（`X06`，545—546 行）、端子点与进程名悬空（`X07`，542—543 行两条 emit）、**公开词表自身形态非法（`X08`，第 379、381、382、394 行四条 emit 加第 401 行「整表无可用行，符号、端子点、公告与限制键比对均不可执行」）** | 全部阻断 |
| V | 6 | 引用形态与口径闭合：required 格引用全为无标识（`V01`，553—554 行）、引用既非公开词表值也非文档行号形态（`V02`，494—497 行）、复位只靠自述面（`V03`，523—524 行）、已读数却未登记这一格是否会对外（`V04`，522 行）、同一核对项在会话之间既有已读数又有明确不存在（`V05`，578—580 行）、挂在公告面或管理面却没有词表标识（`V06`，528—529 行） | 仅 `V02`／`V06` 阻断 |

10＋5＋5＋6＋5＋7＋8＋8＋6 = 60，加 `Q1`—`Q4` 四个判定位共 64，与 C11、C12 两处独立计数相等，C13 差集为空，C20 给出「一号一判据 64｜形态族 0｜参数化 0｜一号多义 0」。**X 族与脚本一 R 族的接缝是本支脚本最重要的一处非对称**：同一件「公告组件名与画面外流层对不对」的事，脚本一只降级（`R03`／`R04`／`R05` 全为非阻断），脚本二拦停——因为脚本二读的是整份公开词表，能判定「这个组件名在词表里到底存不存在」；`X01`／`X02` 各两条 emit 路径合起来是四个方向（不在全量、只在子词表不在全量、标为子词表成员却在子词表里找不到、在全量里没有 crafted 行却把画面外流归属对外表述为是），缺一即 Q2。`X08` 的阻断理由是另一类：它不说某条归属错了，而说**比对本这件事不可执行**。

### 22.5 四类差集问题与逐值判定的两条结构事实

四类问题与第 18 章五侧一一对应：**三件不成对**（`T01`／`T02`，第 411—414 行）跨来源侧与通道侧——只说清谁取了画面、没说画面落到哪儿与用户看得见哪一格；**覆盖空洞**（`D01`—`D05`）发生在通道侧与管理侧，判据基是能力表的 `required` 而不是脚本硬编码；**平面越界**（`P01`—`P07`）是管理侧与公告侧最容易越的一界，`P03` 那句判据直接写成「公告六列里没有采集入口列」；**归属悬空**（`X01`—`X07`）整条落在公告侧与管理侧的词表上。四类里只有 `T03`—`T08` 与 `X` 族是阻断码，所以「三件不成对」与「覆盖空洞」这两类**永远不会把退出码推到 1**（usage 第 92 行），必须与 Q 档同读。

第 19.3 节的两条结构事实在本支脚本里的落点已经逐行给出，这里只补它们的读法后果：**（a）** 未建模的会话类不进值级判定体，`not_recorded`／`unknown` 只得到 `D04` 与 Q4，所以看 Q 档分布时必须把「未建模」与「判出问题」分开数——`mid` 夹具的 `UNK_C` 那一行 `采集件=1 落点件=0 告知件=0 required=0 已读数=0 缺:（无）` 就是这条的形态：矩阵给出 `required=0` 而不是「全缺」，随后 `T01`（非阻断）与 Q4 同时发出。**（b）** `landing_destination` 的多个落点并进同一格后按空格分词逐值判定，因此一条核对项可以同时出 `K01`、`M05`、`X01` 三条不同族的信号；也正因如此，`S08` 与 `S09` 对数组型与非数组型给的判据不同（第 331—341 行整个分支），读重复登记类信号时必须先看这一格是不是数组型。

### 22.6 闭合等级与退出码

stdout 三段：**三件差集矩阵**（第 584—596 行，每会话一行，给采集件／落点件／告知件已读数格数、该类 `required` 总数、命中数与缺项清单，`required` 由能力表逐类现算——`movie_recording` 16 项、`live_broadcast` 14、`mirroring` 12、`airplay_video` 11、`scscreen_capture` 10、`system_screenshot` 9、`remote_observation` 8、`companion_display` 7、`system_service` 2）、**公开词表读数**（第 597—598 行一行八个计数：合格夹具下逐字为 `去重词条=80 机制词词条=16 符号词条=19 端点词条=3 CVE 词条=18 组件词条=12 子词表组件=6 限制键词条=13`）、逐会话 Q 档（第 602 行）。`子词表组件=6` 与 `组件词条=12` 这一对就是第 16.2 节第 2 组在词表侧的形态：全量组件词表 12 条里只有 6 条落在画面外流子集内。stderr 给逐条信号（第 601 行），末尾三行汇总（第 606—608 行）与按出现顺序的码计数（第 609—611 行）。`-q` 关掉的是第 583—599 行整个 `if (!QUIET)` 段与第 602 行的逐会话 Q 档，信号、汇总与计数一行不少（`quiet` 与 `codes` 两次的 `三件会话数=57 核对项登记行=62 信号行数=835`、`不同信号码=54 阻断信号条数=102` 逐字相同，第 955—956 行对第 3362—3363 行）。

退出码仍是三条路：`exit (nblk > 0 ? 1 : 0)`（第 612 行）、输入不足三份或不可读给 2（第 102—103 行）、`-h` 给 0。15 次实跑的分布是 0×3、1×9、2×3（C19）。有一处顺序事实必须如实写出：**第 568—581 行的布尔位枚举复核（`S07`）与登记口径未统一（`V05`）发生在逐会话闭合等级确定（第 550—566 行）之后**，它们不参与任何档位的计算，却参与 `cnt[]` 因而参与退出码——所以本支脚本存在「会话已定 Q1／Q3、进程仍以退出码 1 收束」的形态，与第 19.4 节「退出码 0 不等于归属成立」是同一条设计的两侧。合格夹具那一次不留这种空间：九条会话全 Q1、信号 0 行、`exit=0`（第 1038—1041 行）；`empty-tables` 与 `same-file` 两次则是反例——`能力表行=0 词表词条=0` 时九条会话整批落 Q4，且因为 `C05` 与 `X08` 都是阻断码而直接以退出码 1 收束（第 3674—3679、4150—4156 行）。

### 22.7 全量源码

```bash
#!/usr/bin/env bash
# screen-egress-tripartite-diff.sh —— 画面外流三件差集与公告子词表比对器（离线 / 只读 / 不联网 / 不碰设备）
# 作用：把「采集件（画面在哪一格被取出）× 落点件（取出之后落到哪儿）× 告知件（用户面与受管面看得见哪一格）」
#       三份登记放在一起算差集，专查逐条审查（screen-egress-ledger-review.sh）查不出的四类问题——
#       「登记了这一项，另两件却一条已读数也没有」（三件不成对）；
#       「某一类会话按公开口径明确需要的核对项，台账里一条也没有」（覆盖空洞）；
#       「读数挂在某个平面上，但那个平面按公开口径根本不承载这一格」（平面越界）；
#       「台账引用的接口符号、端子点、公告组件、CVE 或限制键，公开词表里不存在」（归属悬空）。
# 输入（顺序固定，三个文件全部只读）：
#   1) 三件清单   每行 10 列：<会话标识>,<会话类>,<核对项>,<三件状态>,<读数平面>,<词表归属>,<引用>,<对外表述>,<画面来源面>,<外流时点>
#   2) 三件能力表 每行 3 列：<会话类>,<核对项>,<可得性>
#   3) 公开词表   制表符分隔三列：<词表类别>	<词表值>	<来源标识>    # 开头与空行忽略
# 边界：本脚本不联网取公告，不调用 file/mdls/mdimport/mdutil/mdfind/spctl/codesign/defaults/log/sysctl/xcrun/profiles
#       等任何命令行工具，不打开、不截取、不录制任何被登记的画面，不修改输入文件；只核对三份登记与公开词表是否自洽。
#       给出「三件不成对」或「覆盖空洞」不等于补登记：补登记需要新的读数来源，本脚本只指出缺哪一格、
#       按公开口径这一格本应由哪个平面给出。本脚本不给出任何关闭或欺骗采集提示的做法，
#       forceBypassScreenCaptureAlert 只作为管理面读数的一格被核对存在形态。
#       唯一写出目标是 mktemp -d 创建的临时目录，退出时删除，本实现不向其写入任何字节。
set -u
LC_ALL=C; export LC_ALL

usage() {
  cat <<'EOF'
用法: screen-egress-tripartite-diff.sh [-q] 三件清单 三件能力表 公开词表
  -h|--help 显示本帮助；-q 只输出汇总，不逐条打印三件差集矩阵与词表读数
三件清单行格式（10 列，逗号分隔；# 与空行忽略，行尾 CR 忽略，值里不能含逗号）:
  <会话标识>,<会话类>,<核对项>,<三件状态>,<读数平面>,<词表归属>,<引用>,<对外表述>,<画面来源面>,<外流时点>
会话类（11：8 个画面外流类 + 1 个服务类 + 2 个兜底类，与会话标识前缀一一对应）:
  REC_ movie_recording      BCA_ live_broadcast      MIR_ mirroring           CMP_ companion_display
  AIR_ airplay_video        RMO_ remote_observation  SCN_ system_screenshot   SCK_ scscreen_capture
  SVC_ system_service       NA_  not_recorded        UNK_ unknown
核对项（20 项，按三件归属）:
  采集件 captured   capture_entry entry_status process_owner concurrent_limit
                    isolation_mechanism preview_surface share_surface
  落点件 landed     egress_path landing_destination write_scope stored_object mac_randomized
  告知件 notified   prompt_shown banner_kind lockscreen_visible indicator_visible
                    origin_disclosed pairing_verified persist_after_share reset_method
三件状态: recorded absent not_applicable not_recorded unknown
数组型核对项（同一会话可多行登记，逐行给一个落点）: landing_destination；其余核对项一号一行，重复行按 S08/S09 报出
读数平面（26）: platform_doc api_reference daemon_doc extension_doc in_app_alert control_center_toggle
  broadcast_picker pairing_prompt lock_screen_notice camera_indicator notice_sheet settings_ui
  configuration_profile mdm_declaration advisory_entry kev_entry crash_report replayd_surface
  vehicle_display carplay_template external_screen vendor_claim app_self_report
  none not_recorded unknown
词表归属: session_kind api_symbol plist_key restriction_key advisory_component
  advisory_component_crafted advisory_cve endpoint_tag process_name doc_ref mixed not_recorded unknown
对外表述: yes no not_recorded unknown
画面来源面: in_app_button control_center broadcast_picker mirroring_app carplay_template
  vehicle_display classroom_app system_menu not_recorded unknown
外流时点: on_start on_session on_share on_stop on_reboot per_stream not_recorded unknown
引用格: 公开词形值 / 词表值本身 / A/replaykit_rpscreenrecorder.txt:13 / C/readings-19.txt:92 /
  none（确认无对应条目）/ not_recorded（未登记）
逐核对项的公开词形值（M 族与 X 族据此判定；符号形态、端子点形态、限制键形态、CVE 形态、
  落点形态、进程名形态各按帮助里的形态规则判定）:
  capture_entry         RPScreenRecorder RPBroadcastController RPBroadcastHandler RPBroadcastSampleHandler
                        RPBroadcastMP4ClipHandler RPBroadcastConfiguration RPSystemBroadcastPickerView
                        RPPreviewViewController SCContentSharingPicker UIScreen UIWindow CALayer
                        CPInterfaceController none
  entry_status          current superseded no_longer_supported not_applicable
  process_owner         app_process replayd extension_process system_service window_server not_applicable
  concurrent_limit      one_at_a_time one_per_scene unlimited not_applicable
  isolation_mechanism   sandbox out_of_process secure_enclave mfi_sap peer_pairing not_applicable none
  landing_destination   local_movie remote_mac vehicle_display third_party_service teacher_device
                        screenshot_file clipboard not_applicable
  write_scope           replaykit_only_directory app_container shared_photo_library service_side_store
                        none not_applicable
  stored_object         movie mp4_clip frame screenshot not_applicable none
  banner_kind           persistent temporary none not_applicable
  reset_method          stop_recording discard_recording stop_broadcast unpair restart
                        control_center_toggle settings_toggle not_applicable
布尔位（7 项，只收 yes／no／not_applicable／not_recorded／unknown）:
  prompt_shown lockscreen_visible indicator_visible origin_disclosed
  pairing_verified persist_after_share mac_randomized
三件能力表行格式（3 列）: <会话类>,<核对项>,<可得性>    可得性: required optional not_applicable undocumented
公开词表行格式（3 列，制表符分隔）: <词表类别>	<词表值>	<来源标识>
  词表类别: session_kind api_symbol plist_key restriction_key advisory_component
  advisory_component_crafted advisory_cve endpoint_tag process_name
形态规则（M 族逐条判据）:
  符号形态 capture_entry：大写开头的驼峰标识，不含空格与斜杠
  端子点形态 endpoint_tag：点分段标识（com.apple.broadcast-services 是公开口径里唯一写法）
  限制键形态 restriction_key：小写开头的单个驼峰标识，不含空格、斜杠与点
  CVE 形态 advisory_cve：CVE-年-序号
  落点形态 landing_destination：字母数字与下划线组成的单标识，不含斜杠、冒号与空格
  进程名形态 process_name：全小写单标识（replayd 是公开口径里唯一逐字给出的进程名）
信号族：S 清单自身形态 / C 能力表自身形态 / K 归属与越界 / M 公开词形 / D 覆盖空洞 /
        P 平面越界 / T 三件差集与矛盾 / X 公开词表比对 / V 引用形态与口径闭合 / Q1—Q4 闭合等级
阻断信号码（出现即为 Q2）：S01—S10 C01—C05 K01—K05 M01—M06 T03—T08 X01—X08 V02 V06
非阻断信号码（只落 Q3，计入口径漂移）：D01—D05 P01—P07 T01 T02 V01 V03 V04 V05
闭合等级：Q1 三件差集、平面可得性、公开词表三段齐备且无任何信号 / Q2 存在阻断信号 /
          Q3 只有非阻断信号（覆盖空洞、平面越界、三件不成对、无引用或整段缺读数）：只能定覆盖面不能定归属 /
          Q4 连可得性都不能定
退出码：出现阻断信号时为 1，输入不可用时为 2，否则为 0。覆盖空洞、平面越界与三件不成对不计入阻断，只落 Q3（此时退出码仍为 0）。
本脚本不联网、不访问设备、不修改输入文件。
EOF
}

QUIET=0
case "${1:-}" in
  -h|--help) usage; exit 0 ;;
  -q) QUIET=1; shift ;;
esac
[ $# -eq 3 ] || { usage >&2; exit 2; }
for f in "$@"; do [ -r "$f" ] || { echo "输入不可读: $f" >&2; exit 2; }; done

TMPD=$(mktemp -d "${TMPDIR:-/tmp}/sct19.XXXXXX") || { echo "无法创建临时目录" >&2; exit 2; }
trap 'rm -rf "$TMPD"' EXIT INT TERM

awk -v QUIET="$QUIET" '
function emit(code, id, msg,  k) {
  cnt[code]++; lines[++nline] = sprintf("%s\t%s\t%s", code, (id==""?"-":id), msg src(code))
  if (code in HB) hard[id] = 1; else if (code !~ /^Q[1234]$/) soft[id]++
}
function isNA(v)  { return (v=="" || v=="not_recorded" || v=="unknown") }
function trim(v)  { gsub(/^[[:space:]]+|[[:space:]]+$/, "", v); return v }
function nrm(v,  t) { t = tolower(v); gsub(/[[:space:]_\/.:-]/, "", t); return t }
function hasToken(s, t,  a, i, n) { n = split(s, a, " "); for (i = 1; i <= n; i++) if (a[i] == t) return 1; return 0 }
function hasTok(it, v,  t, i, n) { n = split(TOK[it], t, " "); for (i = 1; i <= n; i++) if (t[i] == v) return 1; return 0 }
function isCve(v)    { return (v ~ /^CVE-[0-9]{4}-[0-9]{4,}$/) }
function isIdForm(v) { return (v ~ /^[A-Za-z][A-Za-z0-9_-]*(\.[A-Za-z0-9_-]+)+$/) }
function isSymForm(v){ return (v ~ /^[A-Z][A-Za-z0-9]*$/) && v !~ /[ ]/ && v !~ /\// }
function isKeyForm(v){ return (v ~ /^[a-z][A-Za-z0-9]*$/) && v !~ /[ .\/]/ }
function isProcForm(v) { return (v ~ /^[a-z][a-z0-9]*$/) && v !~ /[ .\/]/ }
function isDestForm(v) { return (v ~ /^[A-Za-z0-9_]+$/) && v !~ /[ :\/]/ }
function isDocRef(v) { return (v ~ /^[ABC]\/[A-Za-z0-9._\/-]+:[0-9]+(-[0-9]+)?$/) }
function isSecretish(v) {
  return (v ~ /-----BEGIN/ || v ~ /^(ghp_|glpat-|AKIA|xox[abp]-|Bearer )/ \
      || v ~ /\.(mov|mp4|m4v|m4a|png|jpg|jpeg|heic|key|p12|pfx|mobileprovision|cap|pcap|sqlite|dmg|zip|tar)$/ \
      || v ~ /^\/(Applications|private|var\/mobile|Users|Library|System|Developer)\// || v ~ /^file:\/\// \
      || v ~ /^data:[A-Za-z\/+]*;base64,/ || length(v) > 120)
}
function src(c) { return (c in DOC) ? "（" DOC[c] "）" : "" }
function ck(a, b) { return a SUBSEP b }
function isBody(line) { return (line !~ /^[[:space:]]*#/ && line !~ /^[[:space:]]*$/) }
function mkset(set, str,  t, i, n) { n = split(str, t, " "); for (i = 1; i <= n; i++) set[t[i]] = 1 }
function mkit(set, fam, str,  t, i, n) { n = split(str, t, " "); for (i = 1; i <= n; i++) { set[t[i]] = 1; ITFAM[t[i]] = fam } }
function ppair(p, fam) { PAIR[ck(p, fam)] = 1 }
function vpair(vw, fam) { PAIR[ck("VW:" vw, fam)] = 1 }
function GV(i, f,  k) { k = ck(i, f); return (k in statOf) ? statOf[k] : "" }
function GR(i, f,  k) { k = ck(i, f); return (k in refOf) ? refOf[k] : "" }
function GP(i, f,  k) { k = ck(i, f); return (k in planeOf) ? planeOf[k] : "" }
BEGIN {
  FS = ","
  mkset(KD, "movie_recording live_broadcast mirroring companion_display airplay_video remote_observation system_screenshot scscreen_capture system_service not_recorded unknown")
  mkit(ITM, "captured", "capture_entry entry_status process_owner concurrent_limit isolation_mechanism preview_surface share_surface")
  mkit(ITM, "landed",   "egress_path landing_destination write_scope stored_object mac_randomized")
  mkit(ITM, "notified", "prompt_shown banner_kind lockscreen_visible indicator_visible origin_disclosed pairing_verified persist_after_share reset_method")
  mkset(ITOK, "capture_entry entry_status process_owner concurrent_limit isolation_mechanism landing_destination write_scope stored_object banner_kind reset_method")
  TOK["capture_entry"]        = "RPScreenRecorder RPBroadcastController RPBroadcastHandler RPBroadcastSampleHandler RPBroadcastMP4ClipHandler RPBroadcastConfiguration RPSystemBroadcastPickerView RPPreviewViewController SCContentSharingPicker UIScreen UIWindow CALayer CPInterfaceController none"
  TOK["entry_status"]         = "current superseded no_longer_supported not_applicable"
  TOK["process_owner"]        = "app_process replayd extension_process system_service window_server not_applicable"
  TOK["concurrent_limit"]     = "one_at_a_time one_per_scene unlimited not_applicable"
  TOK["isolation_mechanism"]  = "sandbox out_of_process secure_enclave mfi_sap peer_pairing not_applicable none"
  TOK["landing_destination"]  = "local_movie remote_mac vehicle_display third_party_service teacher_device screenshot_file clipboard not_applicable"
  TOK["write_scope"]          = "replaykit_only_directory app_container shared_photo_library service_side_store none not_applicable"
  TOK["stored_object"]        = "movie mp4_clip frame screenshot not_applicable none"
  TOK["banner_kind"]          = "persistent temporary none not_applicable"
  TOK["reset_method"]         = "stop_recording discard_recording stop_broadcast unpair restart control_center_toggle settings_toggle not_applicable"
  # 近义词：形似公开词形但不在这份公开口径里
  mkset(NEAR, "recording broadcast mirroring airplay carplay screenshot capture recorder sharing observation remote local screen surface buffer stream frameclip replaykit windowserver bypass allowed denied confirmed verified assumed dynamic generic raw encoded serialized")
  mkset(ST, "recorded absent not_applicable not_recorded unknown")
  mkset(MULTI, "landing_destination")
  mkset(BOOL, "prompt_shown lockscreen_visible indicator_visible origin_disclosed pairing_verified persist_after_share mac_randomized")
  mkset(BV, "yes no not_applicable not_recorded unknown")
  mkset(PL, "platform_doc api_reference daemon_doc extension_doc in_app_alert control_center_toggle broadcast_picker pairing_prompt lock_screen_notice camera_indicator notice_sheet settings_ui configuration_profile mdm_declaration advisory_entry kev_entry crash_report replayd_surface vehicle_display carplay_template external_screen vendor_claim app_self_report none not_recorded unknown")
  mkset(VW, "session_kind api_symbol plist_key restriction_key advisory_component advisory_component_crafted advisory_cve endpoint_tag process_name doc_ref mixed not_recorded unknown")
  mkset(OUTW, "yes no not_recorded unknown")
  mkset(SRCF, "in_app_button control_center broadcast_picker mirroring_app carplay_template vehicle_display classroom_app system_menu not_recorded unknown")
  mkset(WHEN, "on_start on_session on_share on_stop on_reboot per_stream not_recorded unknown")
  mkset(AV, "required optional not_applicable undocumented")
  mkset(VK, "session_kind api_symbol plist_key restriction_key advisory_component advisory_component_crafted advisory_cve endpoint_tag process_name")
  # 会话标识前缀与会话类一一对应（S10 判据）
  PFX["REC_"]="movie_recording"; PFX["BCA_"]="live_broadcast"; PFX["MIR_"]="mirroring"; PFX["CMP_"]="companion_display"
  PFX["AIR_"]="airplay_video"; PFX["RMO_"]="remote_observation"; PFX["SCN_"]="system_screenshot"; PFX["SCK_"]="scscreen_capture"
  PFX["SVC_"]="system_service"; PFX["NA_"]="not_recorded"; PFX["UNK_"]="unknown"
  # 出进程采集的会话类：把归属记成 App 进程内即不成立（K03 判据）
  mkset(APPBAD, "live_broadcast mirroring companion_display airplay_video remote_observation system_screenshot")
  # 采集入口按公开口径能承载的会话类（P05 判据）
  CEK["movie_recording"]      = "api_reference platform_doc"
  CEK["live_broadcast"]       = "api_reference extension_doc platform_doc"
  CEK["mirroring"]            = "platform_doc daemon_doc"
  CEK["companion_display"]    = "api_reference platform_doc carplay_template vehicle_display"
  CEK["airplay_video"]        = "platform_doc"
  CEK["remote_observation"]   = "mdm_declaration configuration_profile platform_doc"
  CEK["system_screenshot"]    = "platform_doc settings_ui"
  CEK["scscreen_capture"]     = "api_reference platform_doc"
  # 会话类对应的采集入口词形（T06 判据）
  CEL["movie_recording"]   = "RPScreenRecorder RPPreviewViewController SCContentSharingPicker none"
  CEL["live_broadcast"]    = "RPSystemBroadcastPickerView RPBroadcastSampleHandler RPBroadcastMP4ClipHandler RPBroadcastController RPBroadcastHandler none"
  CEL["mirroring"]         = "UIScreen UIWindow none"
  CEL["companion_display"] = "CPInterfaceController UIScreen UIWindow none"
  CEL["airplay_video"]     = "UIScreen UIWindow none"
  CEL["remote_observation"]= "UIScreen none"
  CEL["system_screenshot"] = "UIScreen UIWindow none"
  CEL["scscreen_capture"]  = "SCContentSharingPicker UIScreen UIWindow CALayer none"
  # 隔离机制按公开口径承载的会话类（K04 判据）
  ISOK["out_of_process"]   = "movie_recording live_broadcast"
  ISOK["secure_enclave"]   = "mirroring"
  ISOK["mfi_sap"]          = "companion_display airplay_video"
  ISOK["peer_pairing"]     = "mirroring airplay_video remote_observation"
  ISOK["sandbox"]          = "live_broadcast scscreen_capture system_service"
  # 点对点承载：随机化 MAC 口径只适用这两类（T04 与 T07 判据）
  mkset(P2P, "mirroring_local airplay_out")
  # 平面承载哪一件：按公开口径逐格对齐（平台安全指南第 4237—4257、1428—1439、1374、2262、3901 行；
  # A/replaykit*.txt 逐页符号清单；A/carplay*.txt 第 5、12—17 行；A/uikit_uiwindow.txt 第 18、26 行；
  # B/mdm-restriction-keys.txt 第 5—8 行；B/mdm-restrictions.txt 第 29、726、729、766、965、969、1018 行）
  ppair("platform_doc","captured");    ppair("api_reference","captured")
  ppair("daemon_doc","captured");      ppair("extension_doc","captured")
  ppair("replayd_surface","captured"); ppair("carplay_template","captured")
  ppair("vehicle_display","captured")
  ppair("platform_doc","landed");      ppair("daemon_doc","landed")
  ppair("extension_doc","landed");     ppair("settings_ui","landed")
  ppair("api_reference","landed");     ppair("vehicle_display","landed")
  ppair("external_screen","landed")
  ppair("api_reference","notified")
  ppair("platform_doc","notified");    ppair("in_app_alert","notified")
  ppair("control_center_toggle","notified"); ppair("broadcast_picker","notified")
  ppair("pairing_prompt","notified");  ppair("lock_screen_notice","notified")
  ppair("camera_indicator","notified");ppair("notice_sheet","notified")
  ppair("settings_ui","notified");     ppair("configuration_profile","notified")
  ppair("mdm_declaration","notified"); ppair("advisory_entry","notified")
  ppair("kev_entry","notified");       ppair("crash_report","notified")
  ppair("vendor_claim","notified");    ppair("app_self_report","notified")
  # 词表归属描述哪一件
  vpair("session_kind","captured");  vpair("session_kind","landed")
  vpair("api_symbol","captured");    vpair("plist_key","captured")
  vpair("plist_key","landed");       vpair("endpoint_tag","captured")
  vpair("endpoint_tag","landed");    vpair("process_name","captured")
  vpair("restriction_key","notified"); vpair("advisory_component","notified")
  vpair("advisory_component_crafted","notified"); vpair("advisory_cve","notified")
  vpair("doc_ref","captured"); vpair("doc_ref","landed"); vpair("doc_ref","notified")
  vpair("mixed","captured"); vpair("mixed","landed"); vpair("mixed","notified")
  HB["S01"]=1; HB["S02"]=1; HB["S03"]=1; HB["S04"]=1; HB["S05"]=1; HB["S06"]=1; HB["S07"]=1
  HB["S08"]=1; HB["S09"]=1; HB["S10"]=1
  HB["C01"]=1; HB["C02"]=1; HB["C03"]=1; HB["C04"]=1; HB["C05"]=1
  HB["K01"]=1; HB["K02"]=1; HB["K03"]=1; HB["K04"]=1; HB["K05"]=1
  HB["M01"]=1; HB["M02"]=1; HB["M03"]=1; HB["M04"]=1; HB["M05"]=1; HB["M06"]=1
  HB["T03"]=1; HB["T04"]=1; HB["T05"]=1; HB["T06"]=1; HB["T07"]=1; HB["T08"]=1
  HB["X01"]=1; HB["X02"]=1; HB["X03"]=1; HB["X04"]=1; HB["X05"]=1; HB["X06"]=1; HB["X07"]=1; HB["X08"]=1
  HB["V02"]=1; HB["V06"]=1
  DOC["S01"]="见 usage 文本的三件清单行格式（一行十列、列序固定、值里不能含逗号）"
  DOC["S02"]="见 A/uikit_uiscenesession.txt 第 123 行（A unique identifier that persists for the lifetime of the session）：会话标识是行的第一列，也是与能力表对齐的唯一依据"
  DOC["S03"]="见 C/readings-19.txt 第 8—16 行（画面外流子集只有六行组件名、40 行、13 个去重 CVE）与 B/apple-platform-security-guide.txt 第 4238 行：会话类按公开口径由录制、广播、镜像、伴生显示几条机制导出，其余为兜底类"
  DOC["S04"]="见 B/apple-platform-security-guide.txt 第 4241—4250 行与第 1429—1439 行（采集件、落点件、告知件 20 项逐项有出处）"
  DOC["S05"]="见 A/replaykit_rpbroadcastsamplehandler.txt 第 24 行（ReplayKit 串行调用扩展方法：一格要么有读数要么明确没有，不存在第三种状态）"
  DOC["S06"]="见 usage 文本的读数平面清单（26 个面逐个有出处，写成别的名词说明这一格不是从公开材料抄来的）"
  DOC["S07"]="见 usage 文本的枚举列（词表归属、对外表述、画面来源面、外流时点四列的取值必须由登记方在词表里选定）"
  DOC["S08"]="见 B/apple-platform-security-guide.txt 第 4249 行（第三方服务要建两个扩展挂在同一端点上：落点可以多个，同一个落点重复列出并不增加覆盖面）"
  DOC["S09"]="见 B/apple-platform-security-guide.txt 第 4242 行与第 4243 行（同一次采集只有一条归属口径：出进程在 replayd，或受权限对话框守护的 in-app 取样）"
  DOC["S10"]="见 C/readings-19.txt 第 11—16 行（画面外流子集逐条登记六个组件名及其行数）与第 48—51 行（含 screen 的组件名另有四个）：前缀把一条会话定位到四类机制中的哪一类，前缀与会话类不符即无法回指"
  DOC["C01"]="见 usage 文本的三件能力表行格式（一行三列：会话类,核对项,可得性）"
  DOC["C02"]="见 C/readings-19.txt 第 8—16 行（本层会话类由画面外流子集的六行组件名导出，能力表不引入清单之外的类）"
  DOC["C03"]="见 B/apple-platform-security-guide.txt 第 4241—4257 行与第 1428—1439 行（逐格列出的核对项都在这里，不在此列的项无处登记）"
  DOC["C04"]="见 B/apple-platform-security-guide.txt 第 4245 行（预览与分享界面由 ReplayKit 提供）：可得性只有必需、可选、不适用、未公开四种"
  DOC["C05"]="见 B/apple-platform-security-guide.txt 第 4248 行（广播期间的采集机制与影片录制完全一致）：同一格的两条可得性没有公开依据可选其一"
  DOC["K01"]="见本文第 3.4 节失败点 8（台账只登记哪一个会话在哪一格被判定成什么，不登记画面本身、不登记可还原身份的样本）"
  DOC["K02"]="见本脚本头部注释的拒收声明：设备侧命令行工具不作为任何一格的读数来源"
  DOC["K03"]="见 B/apple-platform-security-guide.txt 第 4242 行（Screen and audio capture occurs out of the app’s process in the ReplayKit daemon replayd）与第 4250 行（hosting apps have no privileges to the broadcasted video and audio contents）"
  DOC["K04"]="见 B/apple-platform-security-guide.txt 第 1374 行（AirPlay 校验接收端、音频与 CarPlay 视频流经 MFi-SAP）与第 1438 行（镜像的远程解锁由 Secure Enclave 执行）：一种隔离机制只承载它公开口径里的那一类会话"
  DOC["K05"]="见 C/readings-19.txt 第 106 行（forceBypassScreenCaptureAlert 只作为管理面读数的一格登记）：绕过采集提示的键不作为采集件或落点件的归属依据"
  DOC["M01"]="见 A/replaykit.txt 第 60、64、46、42 行与 A/carplay_cpinterfacecontroller.txt 第 5 行（公开符号逐字给出，都是大写开头的驼峰标识）"
  DOC["M02"]="见 B/apple-platform-security-guide.txt 第 4249 行（两个扩展配置在 com.apple.broadcast-services 这一种点分段形态上）"
  DOC["M03"]="见 B/mdm-restriction-keys.txt 第 5—8 行与 C/readings-19.txt 第 95—107 行（13 个画面语义词命中键全是小写开头的单个驼峰标识）"
  DOC["M04"]="见 C/advisory-19.tsv 表头与 C/readings-19.txt 第 61—63 行（三条 CVE 逐条都是 CVE-年-序号形态）"
  DOC["M05"]="见 B/apple-platform-security-guide.txt 第 4244 行（影片写入只有 ReplayKit 子系统可访问的目录）：落点登记为一个类别名，不是设备绝对路径"
  DOC["M06"]="见 B/apple-platform-security-guide.txt 第 4242 行（…in the ReplayKit daemon replayd）：本层公开口径逐字给出的进程名只有全小写这一种形态"
  DOC["D01"]="见 B/apple-platform-security-guide.txt 第 4245 行（预览与分享的界面由 ReplayKit 提供）：公开口径里存在的格被记为不存在即与文档冲突"
  DOC["D02"]="见 B/apple-platform-security-guide.txt 第 4241 行（录制开始前呈现同意提示）与 A/replaykit_rpscreenrecorder.txt 第 13 行（同一时刻只有一个 App 能用录制器）：这两格没有读数时结论落不了地"
  DOC["D03"]="见 usage 文本的三件能力表可得性（not_applicable 表示公开口径不给这一格）与 B/apple-platform-security-guide.txt 第 4246 行（广播一节自成一组格）"
  DOC["D04"]="见 C/readings-19.txt 第 27—28 行（子集里 macOS 行 31、iOS 行 4：同一机制在不同平台的公开口径详略不同，未建模的类无法定缺哪一格）"
  DOC["D05"]="见 B/apple-platform-security-guide.txt 第 4241—4257 行（十三个逐格要点）与第 1429—1439 行（镜像六条要点）：20 项里任何一项零登记都说明覆盖面不完整"
  DOC["P01"]="见 usage 文本的读数平面清单：none 表示这一格根本没有面，不能同时把状态记成已读数"
  DOC["P02"]="见 B/apple-platform-security-guide.txt 第 2262 行（macOS 把 Screen recording 列为一类权限状态）：权限状态面给出的是是否允许，不给出画面落到哪儿"
  DOC["P03"]="见 C/advisory-19.tsv 表头（file、platform、component、cve、impact、avail 六列）：公告六列里没有采集入口列，公告面承载不了采集件"
  DOC["P04"]="见 A/replaykit_rpscreenrecorder.txt 第 240、251、267 行（三个停止口都在接口引用页上）：复位口的读数来自接口文档或用户面，不来自采集面"
  DOC["P05"]="见 B/apple-platform-security-guide.txt 第 4242、4249 行与 A/carplay.txt 第 5 行、A/replaykit_rpscreenrecorder.txt 第 3 行：四类机制的采集入口各有其承载面，跨面读数不能互抄"
  DOC["P06"]="见 C/readings-19.txt 第 110—121 行（Restrictions payload 页里九条画面语义词说明句）：告知与受管口径的读数在管理面文档，不在接口引用页"
  DOC["P07"]="见 B/apple-platform-security-guide.txt 第 1431 行（同一 Apple 账户的设备把通知转发到 Mac）与第 4245 行（预览与分享界面 out-ofprocess）：来源面决定能读回哪一面，车机模板读不出 App 内提示"
  DOC["T01"]="见 B/apple-platform-security-guide.txt 第 4242 行（采集在 replayd 出进程发生）与第 4244 行（影片落在 ReplayKit 专用目录）：只登记采集件而无落点件与告知件，等于只说谁取了画面没说画面去了哪"
  DOC["T02"]="见 B/apple-platform-security-guide.txt 第 4250 行（宿主 App 对广播内容没有特权）：落点与告知有读数而采集件一格没有，说明这一格读回来的画面在会话之外"
  DOC["T03"]="见 C/advisory-19.tsv 第 1 行与 B/mdm-restriction-keys.txt 第 5—8 行：公告组件词表与管理面键词表各自只描述告知件那一层"
  DOC["T04"]="见 B/apple-platform-security-guide.txt 第 1439 行（首次设置时在 Automatically authenticate 与 Ask every time 之间选择）与第 1374 行（AirPlay 用认证 IC 校验接收端）：点对点承载必须回指一条配对核验读数"
  DOC["T05"]="见 A/replaykit_rpscreenrecorder.txt 第 4 行（Use ScreenCaptureKit instead）与 A/replaykit_rpbroadcastsamplehandler.txt 第 4 行（No longer supported）：同一会话不能既按当前口径又按废弃口径给两格已读数"
  DOC["T06"]="见 A/replaykit_rpsystembroadcastpickerview.txt 第 3 行（点按广播按钮显示选择器）与 A/carplay_cpinterfacecontroller.txt 第 3、12 行（模板控制器由 CarPlay 创建并交给场景代理）：入口与会话类是公开口径里成对出现的两格"
  DOC["T07"]="见 B/apple-platform-security-guide.txt 第 3901 行（AirDrop 与 AirPlay 的点对点 Wi-Fi 连接使用随机化 MAC 地址）：登记了点对点承载却说地址未随机化，两处口径互相矛盾"
  DOC["T08"]="见 B/apple-platform-security-guide.txt 第 4249 行（不建扩展就没有承载方，扩展与端点两格缺一即无法回指）与第 4241 行（同意提示先于采集）"
  DOC["X01"]="见 C/readings-19.txt 第 4 行（组件名去重 129 个）：任何画面外流归属都要能回指到这 129 个组件名之一"
  DOC["X02"]="见 C/readings-19.txt 第 8—16 行（子集 40 行、13 个去重 CVE、六个组件名及其行数）与第 52 行（含 screen 的组件名 4 个）"
  DOC["X03"]="见 C/readings-19.txt 第 3 行（公告去重 CVE 330 个）与第 9 行（子集去重 CVE 13 个）、第 82—83 行（KEV Apple 条目 95 行）"
  DOC["X04"]="见 C/readings-19.txt 第 88—94 行（限制键总表 220 行、形态命中 218、纯键名分母 210、画面语义词命中 13）与 B/mdm-restriction-keys.txt 第 5—8 行"
  DOC["X05"]="见 C/readings-19.txt 第 124—157 行（平台安全指南本层 31 行里 iPhone Mirroring 6 行、ReplayKit 13 行、AirPlay 5 行）与第 157 行"
  DOC["X06"]="见 A/replaykit.txt 第 60—98 行（本层符号清单逐字给出）与 A/replaykit_rpbroadcastsamplehandler.txt 第 64 行（RPApplicationInfoBundleIdentifierKey 这一种声明键形态）"
  DOC["X07"]="见 B/apple-platform-security-guide.txt 第 4249 行（com.apple.broadcast-services 端点）与第 4242 行（replayd）：端子点与进程名各有一份公开写法"
  DOC["X08"]="见 C/advisory-19.tsv 第 1 行（六列制表符分隔的档案形态）与本脚本头部注释的公开词表行格式"
  DOC["V01"]="见 usage 文本的引用格（公开词形值 / 词表值本身 / 文档行号 / none）：required 格全为无标识时结论无法回指"
  DOC["V02"]="见 A/replaykit_rpbroadcastsamplehandler.txt 第 11—16 行（扩展的 Info.plist 里逐字给出配置项）：引用格必须是公开词表值或文档行号形态二者之一"
  DOC["V03"]="见本文第 3.4 节失败点（厂商说法与 App 自述不能单独支撑复位结论）"
  DOC["V04"]="见 B/apple-platform-security-guide.txt 第 4245 行（用户可预览并分享影片）：一是否会话被对外表述由谁负责，必须逐格登记"
  DOC["V05"]="见 C/readings-19.txt 第 32—38 行（record／recording／captur／display／mirror／screenshot／broadcast 词形在 impact 列的行数全为 0）：同一格在不同会话之间口径不一即登记未统一"
  DOC["V06"]="见 C/readings-19.txt 第 61—63 行（Remote Management 三条 CVE 逐条给全组件名与影响句）：公告面与管理面的每一格都要有可回指的标识"
  DOC["Q1"]="见 B/apple-platform-security-guide.txt 第 4241—4250 行与第 1429—1439 行"
  DOC["Q2"]="见 B/apple-platform-security-guide.txt 第 4242、4244、4249 行与 C/readings-19.txt 第 92、106 行"
  DOC["Q3"]="见 C/readings-19.txt 第 27—28 行（同一机制在 iOS 与 macOS 段落里的公开口径详略不同）与第 56—57 行"
  DOC["Q4"]="见 C/readings-19.txt 第 3—5 行（去重 CVE 330、组件名 129、平台版本行 12）与第 8—9 行（子集行数 40、子集去重 CVE 13）与第 88—90 行（键表 220 行、形态命中 218）"
}

# ---- 输入 1：三件清单 ----
FILENAME == ARGV[1] && isBody($0) {
  line = $0; sub(/\r$/, "", line)
  n = split(line, fx, ",")
  if (n != 10) { emit("S01", fx[1], "清单行形态非法：" line); subjAll = 1; next }
  id = trim(fx[1]); kd = trim(fx[2]); it = trim(fx[3]); st = trim(fx[4])
  pl = trim(fx[5]); vw = trim(fx[6]); rf = trim(fx[7]); ow = trim(fx[8])
  sf = trim(fx[9]); wh = trim(fx[10])
  if (id == "" || id ~ /[ \t]/) { emit("S02", id, "会话标识为空：" line " 无法与三件能力表对齐"); subjAll = 1; next }
  if (!(id in seen)) { seen[id] = 1; order[++nid] = id }
  subj = 0
  if (!(kd in KD)) { emit("S03", id, "会话类越界：" kd); subj = 1 }
  if (!(it in ITM)) { emit("S04", id, "核对项越界：" it); subj = 1 }
  for (p in PFX) { if (substr(id, 1, length(p)) == p && PFX[p] != kd && kd != "") emit("S10", id, "前缀与会话类不符：" p " 对 " kd) }
  if (subj) subjBad[id] = 1
  if (!(st in ST)) emit("S05", id, "三件状态取值非法：" st)
  if (!(pl in PL)) emit("S06", id, "读数平面取值非法：" pl)
  if (!(vw in VW)) emit("S07", id, "枚举越界：词表归属列 " vw)
  if (!(ow in OUTW)) emit("S07", id, "枚举越界：对外表述列 " ow)
  if (!(sf in SRCF)) emit("S07", id, "枚举越界：画面来源面列 " sf)
  if (!(wh in WHEN)) emit("S07", id, "枚举越界：外流时点列 " wh)
  if (!(it in ITM)) next
  itemRows++
  if (!(id in kdSeen)) { kdSeen[id] = 1; kdOf[id] = kd }
  k = ck(id, it)
  if (k in statOf) {
    if (it in MULTI && statOf[k]==st && planeOf[k]==pl && vwOf[k]==vw) {
      if (refOf[k]==rf) emit("S08", id, "数组型重复登记：" it " 两次列同一个落点（差集会重复计数）")
      else refOf[k] = refOf[k] " " rf
      destRefOf[id] = destRefOf[id] " " rf
      next
    }
    if (statOf[k]==st && planeOf[k]==pl && vwOf[k]==vw) emit("S08", id, "数组型重复登记：" it " 两行的状态、平面与归属三格完全一致（差集会重复计数）")
    else emit("S09", id, "同项两口径：" it " " statOf[k] "/" planeOf[k] "/" vwOf[k] " 与 " st "/" pl "/" vw)
    if (it == "entry_status") statRefOf[id] = statRefOf[id] " " rf
    next
  }
  statOf[k] = st; planeOf[k] = pl; vwOf[k] = vw; refOf[k] = rf; outOf[k] = ow
  srcOf[id] = sf; whenOf[id] = wh
  if (it == "landing_destination") destRefOf[id] = destRefOf[id] " " rf
  if (it == "entry_status") statRefOf[id] = statRefOf[id] " " rf
  if (st == "recorded" && ow == "yes") outYes[id] = 1
  famRec[id,ITFAM[it]] += (st == "recorded" ? 1 : 0)
  famAny[id,ITFAM[it]]++
  itemSeen[it] = 1
  next
}

# ---- 输入 2：三件能力表 ----
FILENAME == ARGV[2] && isBody($0) {
  line = $0; sub(/\r$/, "", line)
  n = split(line, fx, ",")
  if (n != 3) { emit("C01", fx[1], "能力表行形态非法：" line); next }
  kd = trim(fx[1]); it = trim(fx[2]); av = trim(fx[3])
  if (!(kd in KD)) { emit("C02", kd, "能力表会话类越界：" kd); next }
  if (!(it in ITM)) { emit("C03", kd, "能力表核对项越界：" it); next }
  if (!(av in AV)) { emit("C04", kd, "可得性取值越界：" av); next }
  kk = ck(kd, it)
  if (kk in capOf) {
    if (capOf[kk] != av) emit("C05", kd, "可得性基准不可用：核对项 " it " 有两条不同可得性（" capOf[kk] " / " av "）")
    else emit("C05", kd, "可得性基准不可用：核对项 " it " 重复登记同一条可得性")
    next
  }
  capOf[kk] = av; capRows++
  if (!(kd in capKdSet)) { capKdSet[kd] = 1; capKdN++ }
  next
}

# ---- 输入 3：公开词表（制表符分隔三列：类别 / 值 / 来源）----
FILENAME == ARGV[3] && isBody($0) {
  line = $0; sub(/\r$/, "", line)
  if (line ~ /^kind\tvalue/) next
  n = split(line, a, "\t")
  if (n < 2) { emit("X08", trim(a[1]), "公开词表形态非法：记录不足两列（类别<TAB>值）" line); next }
  vk = trim(a[1]); vv = trim(a[2])
  if (!(vk in VK)) { emit("X08", vk, "公开词表形态非法：类别列不在允许集合 " vk); next }
  if (vv == "") { emit("X08", vk, "公开词表形态非法：值格为空 " line); next }
  nk = nrm(vv)
  if (!(nk in vocab)) { vocab[nk] = vk; vrows++ }
  if (vk == "advisory_cve") { if (!(nk in cveSeen)) { cveSeen[nk] = 1; cveN++ } }
  else if (vk == "advisory_component") { if (!(nk in compSeen)) { compSeen[nk] = 1; compN++ } }
  else if (vk == "advisory_component_crafted") { if (!(nk in craftSeen)) { craftSeen[nk] = 1; craftN++ } }
  else if (vk == "restriction_key") { if (!(nk in keySeen)) { keySeen[nk] = 1; keyN++ } }
  else if (vk == "session_kind") { if (!(nk in kindSeen)) { kindSeen[nk] = 1; kindN++ } }
  else if (vk == "api_symbol" || vk == "plist_key") { if (!(nk in symSeen)) { symSeen[nk] = 1; symN++ } }
  else if (vk == "endpoint_tag" || vk == "process_name") { if (!(nk in endSeen)) { endSeen[nk] = 1; endN++ } }
  if (n >= 3 && trim(a[3]) != "" && !isDocRef(trim(a[3]) "0")) {
    srcv = trim(a[3])
    if (!isDocRef(srcv) && srcv != "fixture") { emit("X08", vv, "公开词表形态非法：来源标识既不是文档行号形态也不是 fixture " srcv) }
  }
  next
}

END {
  if (capRows == 0) emit("C05", "-", "可得性基准不可用：三件能力表一条有效行都没有，三件差集无法计算")
  if (vrows == 0) emit("X08", "-", "公开词表形态非法：整表无可用行，符号、端子点、公告与限制键比对均不可执行")
  for (t in ITM) if (!(t in itemSeen)) emit("D05", "-", "核对项 " t " 在整张清单里零登记")

  for (ix = 1; ix <= nid; ix++) {
    id = order[ix]
    if (!(id in kdSeen)) continue
    kd = kdOf[id]
    if (capKdN > 0 && !(kd in capKdSet)) emit("D04", id, "会话类未建模：" kd " 在能力表一行都没有，这一类的判据未建模，缺哪一格无从判定")

    cap = famRec[id,"captured"] + 0; land = famRec[id,"landed"] + 0; noti = famRec[id,"notified"] + 0
    if (cap > 0 && land == 0 && noti == 0)
      emit("T01", id, "三件不成对：" cap " 格采集件已读数但落点件与告知件一条都没有：说清谁取了画面没说画面落到哪儿、用户看得见哪一格")
    if ((land > 0 || noti > 0) && cap == 0)
      emit("T02", id, "三件不成对：落点件与告知件共有 " land+noti " 格已读数但采集件一格都没有：读回来的画面落在会话之外")
    if (statRefOf[id] ~ /current/ && statRefOf[id] ~ /superseded/)
      emit("T05", id, "同一会话把入口既登记为当前口径又登记为已废弃口径")
    ev = GR(id, "egress_path"); cev = GR(id, "capture_entry"); pov = GR(id, "process_owner")
    if (!isNA(ev) && ev != "none" && (ev in P2P)) {
      pv = GR(id, "pairing_verified")
      if (pv != "yes") emit("T04", id, "点对点缺配对核验：" ev " 走点对点承载但配对核验登记为 " (pv==""?"（无）":pv))
      mr = GR(id, "mac_randomized")
      if (mr == "no") emit("T07", id, "地址随机化口径冲突：点对点承载却把地址登记为未随机化")
      if (kd != "" && kd != "mirroring" && kd != "airplay_video")
        emit("T06", id, "会话类与入口不符：" ev " 的承载会话类是点对点，但本会话登记为 " kd)
    }
    if (!isNA(cev) && cev != "none" && hasToken(TOK["capture_entry"], cev) && (kd in CEL) && !hasToken(CEL[kd], cev))
      emit("T06", id, "会话类与入口不符：" kd " 的采集入口登记为 " cev "，公开口径里这一类由这些入口承载（" CEL[kd] "）")
    if (outYes[id] == 1) {
      miss = ""
      for (mi = 1; mi <= 2; mi++) {
        it8 = (mi == 1 ? "capture_entry" : "landing_destination")
        if (!((ck(kd, it8) in capOf) && capOf[ck(kd, it8)] == "required")) continue
        st8 = GV(id, it8)
        if (st8 == "" || st8 == "absent" || isNA(st8)) miss = miss (miss==""?"":"、") it8
      }
      if (miss != "")
        emit("T08", id, "对外表述缺必需格：" miss " 在公开口径里对这一类会话是必需的，缺位时对外表述没有依据")
    }

    for (kk in capOf) {
      split(kk, sp, SUBSEP); c2 = sp[1]; it = sp[2]; av = capOf[kk]
      if (c2 != kd) continue
      k = ck(id, it)
      if (!(k in statOf)) {
        if (av == "required") { holesReq[id]++; emit("D02", id, "会话类 " kd " 的 required 核对项 " it " 在本会话完全没有登记行") }
        continue
      }
      st = statOf[k]; pl = planeOf[k]; vw = vwOf[k]; rf = refOf[k]; ow = outOf[k]
      fam = ITFAM[it]
      nrf = split(refOf[k], rfa, " ")
      if (av == "required") {
        if (st == "absent") emit("D01", id, "会话类 " kd " 需要 " it "，台账却明确记为不存在")
        else if (isNA(st)) { holesReq[id]++; emit("D02", id, "会话类 " kd " 需要 " it "，台账记为 " st "：这一格没有读数") }
        else if (st == "not_applicable") { holesReq[id]++; emit("D03", id, "不适用与能力表冲突：" it " 对 " kd " 是必需的，却被记为不适用") }
        if (st == "recorded") { reqTot[id]++; if (isNA(rf) || rf=="none") reqNoRef[id]++ }
      }
      if (av == "not_applicable" && st == "recorded") {
        holesReq[id]++
        emit("D03", id, "不适用与能力表冲突：" it " 在公开口径里对 " kd " 不适用（预览面只属于录制形态，镜像与车机模板没有预览格），却登记了已读数")
      }
      if (st != "recorded") continue
      recTot[id]++

      # ---- 归属与越界（数组型核对项逐值判定）----
      for (ri = 1; ri <= nrf; ri++) {
        rf = rfa[ri]
        if (isSecretish(rf))
          emit("K01", id, "登记越界：" it " 的引用格形似密钥、口令、归档文件、设备绝对路径或整段画面载荷：只登记引用标识，不登记画面")
        else if (rf ~ /^(file|mdls|mdimport|mdutil|mdfind|spctl|codesign|defaults|sysctl|xcrun|profiles|plutil|sips|qlmanage|otool|log|ls|find|screencapture|import)$/)
          emit("K02", id, "读数来源越界：" it " 的引用格登记了设备侧命令行入口名（" rf "）：本脚本与台账都不以任何命令行工具作为读数来源")
        if (it == "process_owner" && rf == "app_process" && (kd in APPBAD))
          emit("K03", id, "采集归属不成立：" kd " 的画面按公开口径在 App 进程之外取出，不能把归属记成 App 进程内")
        if (it == "isolation_mechanism" && (rf in ISOK) && !hasToken(ISOK[rf], kd) && kd != "" && !isNA(rf))
          emit("K04", id, "隔离机制与承载不符：" rf " 按公开口径只承载这些会话类（" ISOK[rf] "），本会话登记为 " kd)
        if (rf == "forceBypassScreenCaptureAlert" && (fam=="captured" || fam=="landed"))
          emit("K05", id, "提示绕过键进入通道件：forceBypassScreenCaptureAlert 只作为管理面读数登记存在形态，不作为 " it " 的归属依据")

        # ---- 公开词形 ----
        if (!isNA(rf) && rf != "none") {
          if (it == "capture_entry")       { if (!isSymForm(rf) && !isDocRef(rf)) emit("M01", id, "符号形态非法：" rf) }
          else if (vw == "endpoint_tag")   { if (!isIdForm(rf) && !hasToken(TOK["capture_entry"], rf)) emit("M02", id, "端子点形态非法：" rf) }
          else if (vw == "restriction_key"){ if (!isKeyForm(rf)) emit("M03", id, "限制键形态非法：" rf) }
          else if (vw == "advisory_cve" || rf ~ /^CVE-/) { if (!isCve(rf)) emit("M04", id, "CVE 形态非法：" rf) }
          else if (it == "landing_destination") { if (!hasTok(it, rf) && !isDestForm(rf) && !isDocRef(rf)) emit("M05", id, "落点形态非法：" rf) }
          else if (vw == "process_name")   { if (!isProcForm(rf) && !hasToken(TOK["process_owner"], rf)) emit("M06", id, "进程名形态非法：" rf) }
          else if (it in ITOK) {
            if (hasTok(it, rf)) { /* 落在公开词形表内 */ }
            else if (rf in NEAR) emit("M05", id, "落点形态非法：" it " 的引用值 " rf " 是公开词形的近义词")
            else if (!(nrm(rf) in vocab) && !isDocRef(rf)) emit("M05", id, "落点形态非法：" it " 的引用值 " rf " 不在这一格的公开词形表里")
          }
        }

        # ---- 引用形态 ----
        if (!(rf=="none" || isNA(rf))) {
          if (!isCve(rf) && !isDocRef(rf) && !(nrm(rf) in vocab) && !(it in ITOK && hasTok(it, rf)) && !((it in BOOL) && (rf in BV)))
            emit("V02", id, "引用回指悬空：" it " 的引用格既不是公开词表值也不是文档行号形态：" rf)
        }
      }

      # ---- 平面越界 ----
      if (pl == "none") emit("P01", id, "已读数无平面：" it " 记为已读数但读数平面为无平面")
      else if (fam=="landed" && pl=="camera_indicator")
        emit("P02", id, "平面越界：落点件核对项 " it " 记在采集指示灯面上，指示灯面只给出是否允许采集")
      else if (fam=="captured" && (pl=="advisory_entry" || pl=="kev_entry"))
        emit("P03", id, "平面越界：采集件核对项 " it " 记在 " pl " 读回：公告六列里没有采集入口列")
      else if (it == "reset_method" && (pl=="replayd_surface" || pl=="daemon_doc" || pl=="extension_doc"))
        emit("P04", id, "平面越界：复位口记在采集面 " pl "：复位读的是接口文档与用户面")
      else if (fam=="notified" && it != "reset_method" && (pl=="api_reference" || pl=="extension_doc" || pl=="daemon_doc"))
        emit("P06", id, "平面越界：告知件核对项 " it " 记在接口引用面上：告知与受管口径的读数在管理面文档")
      else if (!(ck(pl, fam) in PAIR) && !(ck(pl, it) in PAIR))
        emit("P05", id, "平面越界：读数平面 " pl " 与核对项 " it "（属 " fam "）不匹配，这一格不该由这个面给出")
      if (it == "capture_entry" && (kd in CEK) && !hasToken(CEK[kd], pl))
        emit("P05", id, "平面越界：" kd " 的采集入口记在 " pl "，按公开口径这一类入口由这些面承载（" CEK[kd] "）")
      if (fam=="notified" && srcOf[id]=="classroom_app" && pl!="mdm_declaration" && pl!="configuration_profile" && pl!="notice_sheet" && pl!="platform_doc" && pl!="lock_screen_notice")
        emit("P07", id, "来源面与读数平面错配：画面来源面是 " srcOf[id] "（受管发起），告知件这一格却从 " pl " 读回：受管发起的观察要回指管理面")
      if (fam=="notified" && (srcOf[id]=="vehicle_display" || srcOf[id]=="carplay_template" || srcOf[id]=="mirroring_app") && pl=="in_app_alert")
        emit("P07", id, "来源面与读数平面错配：画面来源面是 " srcOf[id] "，告知件这一格却从 App 内提示面读回：车机模板与镜像面读不出 App 内提示")

      # ---- 词表归属与件层 ----
      if (!isNA(vw) && !(ck("VW:" vw, fam) in PAIR))
        emit("T03", id, "词表归属与件层不匹配：" it "（属 " fam "）把词表归属记成 " vw "：这一层词表描述不了这一件")
      if (isNA(ow)) emit("V04", id, "对外表述未登记：" it " 已读数但未登记这一格是否会对外（不阻断）")
      if (it == "reset_method" && (pl=="vendor_claim" || pl=="app_self_report"))
        emit("V03", id, "复位只靠自述：复位口只由 " pl " 给出，其自述不独立构成观测")

      # ---- 公开词表比对 ----
      if (vw=="advisory_cve" || vw=="advisory_component" || vw=="advisory_component_crafted" || vw=="restriction_key" || vw=="session_kind" || vw=="endpoint_tag" || vw=="process_name" || isCve(rf)) {
        if (isNA(rf) || rf=="none")
          emit("V06", id, "公告面缺标识：" it " 挂在公告面或管理面却没有词表标识：缺这一格就无法回指")
        else if (isCve(rf)) { if (vrows>0 && cveN>0 && !(nrm(rf) in cveSeen)) emit("X03", id, "CVE 回指悬空：" rf " 不在公告与 KEV 的 CVE 词表内") }
        else if (vw=="restriction_key") { if (vrows>0 && keyN>0 && !(nrm(rf) in keySeen)) emit("X04", id, "限制键回指悬空：" rf " 不在公开管理面键清单内") }
        else if (vw=="session_kind") { if (vrows>0 && kindN>0 && !isDocRef(rf) && !(nrm(rf) in kindSeen)) emit("X05", id, "机制词回指悬空：" rf " 不在本层公开机制词清单内") }
        else if (vw=="advisory_component_crafted") {
          if (vrows>0 && craftN>0 && !(nrm(rf) in craftSeen)) emit("X02", id, "子词表成员不成立：引用的组件 " rf " 被标注为画面外流子词表成员，但子词表里没有它")
          if (vrows>0 && compN>0 && craftN>0 && (nrm(rf) in craftSeen) && !(nrm(rf) in compSeen)) emit("X01", id, "公告组件回指悬空：" rf " 只在子词表里而不在全量组件词表里")
        }
        else if (vw=="advisory_component") {
          if (vrows>0 && compN>0 && !(nrm(rf) in compSeen)) emit("X01", id, "公告组件回指悬空：引用的公告组件 " rf " 归一化后不在全量组件词表内")
          else if (vrows>0 && craftN>0 && (nrm(rf) in compSeen) && !(nrm(rf) in craftSeen) && ow=="yes")
            emit("X02", id, "子词表成员不成立：引用的组件 " rf " 在全量词表里但不含画面外流行，却把画面外流归属对外表述为是")
        }
        else if (vw=="endpoint_tag") { if (vrows>0 && endN>0 && !isDocRef(rf) && !(nrm(rf) in endSeen)) emit("X07", id, "端点回指悬空：引用的端子点 " rf " 不在公开端点词表内") }
        else if (vw=="process_name") { if (vrows>0 && endN>0 && !isDocRef(rf) && !(nrm(rf) in endSeen)) emit("X07", id, "端点回指悬空：引用的进程名 " rf " 不在公开端点词表内") }
      }
      if ((vw=="api_symbol" || vw=="plist_key") && symN>0 && !isNA(rf) && rf!="none" && !isDocRef(rf) && !(nrm(rf) in symSeen))
        emit("X06", id, "符号回指悬空：引用的框架符号或声明键 " rf " 不在符号词表内")
    }
  }

  for (ix = 1; ix <= nid; ix++) {
    id = order[ix]
    if (!(id in kdSeen)) continue
    if (reqTot[id] > 0 && reqTot[id] == reqNoRef[id])
      emit("V01", id, "required 全无标识：本会话 " reqTot[id] " 项 required 核对项的引用格全为无标识，结论无法回指任何一格")
    hardN = 0
    for (j = 1; j <= nline; j++) { split(lines[j], sp, "\t"); if (sp[2] == id && (sp[1] in HB)) hardN++ }
    if (!(kdOf[id] in capKdSet) || capKdN == 0 || subjBad[id] == 1) grade = "Q4"
    else if (hardN >= 1) grade = "Q2"
    else if (holesReq[id] > 0 || reqNoRef[id] > 0 || recTot[id] == 0 || soft[id] > 0) grade = "Q3"
    else grade = "Q1"
    if (grade == "Q4") emit("Q4", id, "连可得性都不能定：该会话类在能力表里没有任何一行，或本会话没有一行能通过形态校验")
    if (grade == "Q3") emit("Q3", id, "只能定「这一类会话应当有哪几格」，不能定「这一格由谁读回」：存在覆盖空洞、平面越界、三件不成对、无引用或整段缺读数等非阻断信号")
    if (grade == "Q2") emit("Q2", id, "存在阻断信号：三件差集、平面可得性或公开词表至少一段互相矛盾，不能作为对外归属表述")
    if (grade == "Q1") emit("Q1", id, "三件差集、平面可得性与公开词表三段齐备且无阻断：可用于对外表述这一条画面外流链路缺哪一格")
    qcount[grade]++
  }

  for (kk in statOf) {
    split(kk, sp, SUBSEP); id = sp[1]; it = sp[2]; kd = kdOf[id]; st = statOf[kk]
    if (it in BOOL && st == "recorded") {
      bv = refOf[kk]
      if (!(bv in BV)) emit("S07", id, "枚举越界：布尔位 " it " 的取值 " bv)
    }
    key2 = ck(kd, it)
    if (st == "recorded") recByKind[key2] = 1
    if (st == "absent") absByKind[key2] = 1
  }
  for (key2 in recByKind) if (key2 in absByKind) {
    split(key2, sp, SUBSEP)
    emit("V05", "-", "登记口径未统一：会话类 " sp[1] " 的核对项 " sp[2] " 在会话之间既有已读数又有明确不存在（不阻断）")
  }

  if (!QUIET) {
    print "---- 三件差集矩阵（采集件 / 落点件 / 告知件 已读数格数与必需格覆盖）----"
    for (ix = 1; ix <= nid; ix++) {
      id = order[ix]; kd = kdOf[id]
      reqs = 0; hits = 0; hlist = ""
      for (kk in capOf) {
        split(kk, sp, SUBSEP); if (sp[1] != kd || capOf[kk] != "required") continue
        reqs++
        k = ck(id, sp[2])
        if ((k in statOf) && statOf[k] == "recorded") hits++
        else hlist = hlist " " sp[2]
      }
      printf "%s\t%s\t采集件=%d 落点件=%d 告知件=%d\trequired=%d 已读数=%d 缺:%s\n", id, (kd==""?"-":kd), famRec[id,"captured"]+0, famRec[id,"landed"]+0, famRec[id,"notified"]+0, reqs, hits, (hlist==""?"（无）":hlist)
    }
    printf "---- 公开词表读数 ----\n"
    printf "去重词条=%d 机制词词条=%d 符号词条=%d 端点词条=%d CVE 词条=%d 组件词条=%d 子词表组件=%d 限制键词条=%d\n", vrows, kindN, symN, endN, cveN, compN, craftN, keyN
  }

  for (j = 1; j <= nline; j++) { split(lines[j], sp, "\t"); if (sp[1] !~ /^Q[1234]$/) print lines[j] > "/dev/stderr" }
  if (!QUIET) for (j = 1; j <= nline; j++) { split(lines[j], sp, "\t"); if (sp[1] ~ /^Q[1234]$/) print lines[j] }
  nblk = 0; nc = 0; nsig = 0
  for (j = 1; j <= nline; j++) { split(lines[j], sp, "\t"); if (sp[1] !~ /^Q[1234]$/) nsig++ }
  for (c in cnt) { if (c !~ /^Q[1234]$/) nc++; if (c in HB) nblk += cnt[c] }
  printf "\n三件会话数=%d 核对项登记行=%d 能力表行=%d 词表词条=%d 信号行数=%d\n", nid, itemRows, capRows, vrows, nsig
  printf "不同信号码=%d 阻断信号条数=%d\n", nc, nblk
  printf "闭合等级 Q1=%d Q2=%d Q3=%d Q4=%d\n", qcount["Q1"], qcount["Q2"], qcount["Q3"], qcount["Q4"]
  shown = ""
  for (j = 1; j <= nline; j++) { split(lines[j], sp, "\t"); if (sp[1] ~ /^Q[1234]$/) continue; if (!(sp[1] in shn)) { shn[sp[1]] = 1; shown = shown sprintf("  %s=%d\n", sp[1], cnt[sp[1]]) } }
  printf "%s", shown
  exit (nblk > 0 ? 1 : 0)
}
' "$1" "$2" "$3"
```

---

## 23. 三十三次实跑与全量信号覆盖验收

本章不给出任何新读数：第 16 章那十三组公开读数已经写完，本章只做一件事——把第 21、22 章两支脚本的源码与输出逐条对齐，并证明它们能在读者自己机器上原样复现。四条验收标准贯穿全章。

| 号 | 标准 | 判据 | 落点 |
| --- | --- | --- | --- |
| V1 | **码数覆盖** | 两支脚本定义的每一个码（脚本一是 71 个信号码加 J1—J4 四行判定，脚本二是 60 个信号码加 Q1—Q4 四级闭合）都在留档里至少触发一次，且未触发清单与未定义命中清单都为空 | 23.3 的 C5 与 C15 |
| V2 | **只读与离线** | 二十段 grep 实证：awk 程序体内无系统调用型函数、被禁命令名只出现在头部拒收声明与拒收正则里、临时目录建后即删且从不写入 | 23.1 的 P1—P20 |
| V3 | **可回指** | 每一条信号的出处都要落到归档文件行号或 usage 文本；指向本文自身的自引用逐条列出而不是笼统承认 | 23.6 的反向对齐 |
| V4 | **可复现** | 三十三次实跑的输入组合逐段列出；两张表件的每一格由留档现场重数；两份验收留档本身可重跑比对 | 23.2 的清单与 23.6 末段 |

四条标准里 **V1 与 V4 是可数的，V2 是可 grep 的，V3 是可回查的**——没有一条要求读者拿设备或第三方数据来验证。验收放在最后一章而不是第一章的原因也在这里：它针对的是已经写完全文的脚本与已经生成的留档，不是针对计划。

### 23.1 二十段只读实证（V2）

`FX/readonly-proof.sh`（92 行）是这一节的唯一证据来源。它和被它检查的两支脚本属于同一类东西，自己也只做大哥那四类动作：grep 两支脚本的源码、各跑一遍夹具、查临时目录残留、把两份 harness 留档里的命令行归一化；不联网、不访问设备、不修改任何输入，输出写 stdout 供本文逐字引用。`P1—P10` 针对脚本一，`P11—P20` 针对脚本二，两半结构对称。整个 harness 在 `LC_ALL=C` 下运行（源码第 8 行显式导出），匹配口径是字节级的，读者复算时要带上同一个环境变量；两段语法检查（P7 与 P17）都是 `bash -n` 无输出即通过。

```bash
#!/usr/bin/env bash
# readonly-proof.sh —— 第 19 篇「只读约束」的实证脚本
# 只做四件事：grep 两个脚本的源码、各跑一遍夹具、检查临时目录残留、把两次 harness 的命令行归一化。
# 本脚本不联网、不访问设备、不修改任何输入文件。输出写 stdout，供文档逐字引用。
# 约定：show 的参数是一个用单引号包住的完整命令行，先原样打印再交给 bash -c 执行。
# P1—P10 为脚本一（screen-egress-ledger-review.sh），P11—P20 为脚本二（screen-egress-tripartite-diff.sh）。
set -u
LC_ALL=C; export LC_ALL
cd "$(dirname "$0")/.." || exit 1

show() {
  printf '$ %s\n' "$*"
  bash -c "$*" 2>&1
  printf '$ exit=%s\n\n' "$?"
}

echo "=== P1 awk 程序体内没有任何系统调用型函数 ==="
show 'grep -nE "system[(]|getline *[<]|popen[(]|close[(]|cmd |exec " tools/screen-egress-ledger-review.sh'

echo "=== P2 全文唯一的外部目录创建：一处 mktemp -d，前缀 scr19.；注释与用法文本各提一次 ==="
show 'grep -n "mktemp" tools/screen-egress-ledger-review.sh'

echo "=== P3 TMPD 只在赋值与 trap 里出现，正文从不向它写入，退出即删 ==="
show 'grep -n "TMPD" tools/screen-egress-ledger-review.sh'

echo "=== P4 设备侧命令行工具名在脚本一里的全部出现位置（只应出现在第 8—9 行的拒收声明） ==="
show 'grep -nwE "mdls|mdimport|mdutil|mdfind|spctl|codesign|defaults|sysctl|xcrun|profiles|plutil|sips|qlmanage|otool" tools/screen-egress-ledger-review.sh'

echo "=== P4b 两个与正文用词重叠的名字（file／log）整词匹配到的行：逐行看均为注释与出处说明 ==="
show 'grep -nwE "file|log" tools/screen-egress-ledger-review.sh'

echo "=== P4c 命令位置探测的阳性对照：两条样例应命中 2，证明这条规则不是空转 ==="
show 'printf "%s\n" "log show --last 1h" "mdls -name kMDItemContentType" | grep -cE "(^|[;&|($])[[:space:]]*(file|log|mdls|mdimport|mdutil|mdfind|spctl|codesign|defaults|sysctl|xcrun|profiles|plutil|sips|qlmanage|otool)[[:space:]]"'

echo "=== P4d 用同一条规则扫脚本一全文：被禁工具名出现在命令位置的行——应为空匹配 ==="
show 'grep -nE "(^|[;&|($])[[:space:]]*(file|log|mdls|mdimport|mdutil|mdfind|spctl|codesign|defaults|sysctl|xcrun|profiles|plutil|sips|qlmanage|otool)[[:space:]]" tools/screen-egress-ledger-review.sh'

echo "=== P5 没有任何网络或外部程序调用词 ==="
show 'grep -nwE "curl|wget|nc|netcat|ssh|scp|ping|nslookup|dig|openssl|git|python|node|open|osascript" tools/screen-egress-ledger-review.sh'

echo "=== P6 脚本一实际调用的外部命令普查（计数为 0 的行不显示；perl／python／node 应为 0） ==="
show 'for c in awk sed grep tr cut sort uniq wc cat head tail mktemp rm date perl python node; do n=$(grep -ow -- "$c" tools/screen-egress-ledger-review.sh | wc -l); [ "$n" -gt 0 ] && printf "%s=%s " "$c" "$n"; done; echo'

echo "=== P7 脚本一的语法检查 ==="
show 'bash -n tools/screen-egress-ledger-review.sh && echo "bash -n 无输出，即通过"'

echo "=== P8 合格夹具跑一次后检查临时目录残留（应为「无残留」） ==="
show 'bash tools/screen-egress-ledger-review.sh FX/ledger-19-good.txt >/dev/null 2>&1; echo "脚本一 exit=$?"'
show 'ls -d "${TMPDIR:-/tmp}"/scr19.* 2>/dev/null && echo "有残留" || echo "无残留：临时目录前缀 scr19. 匹配不到任何东西"'

echo "=== P9 harness 里不存在任何 URL 或设备节点路径 ==="
show 'grep -nE "https?://|/dev/[a-z]" FX/run-all.sh'

echo "=== P10 十八次实跑的命令行归一化后只剩「脚本 + 选项 + 夹具」这一种形状 ==="
show 'grep -h "^\$ " FX/run-log.txt | grep -v "^\$ exit=" | sed "s#FX/[A-Za-z0-9._-]*#FX/<夹具>#g; s#tools/screen-egress-[a-z-]*\.sh#tools/<脚本>#g" | sort | uniq -c | sort -rn'

echo "=== P11 脚本二的 awk 程序体内同样没有任何系统调用型函数 ==="
show 'grep -nE "system[(]|getline *[<]|popen[(]|close[(]|cmd |exec " tools/screen-egress-tripartite-diff.sh'

echo "=== P12 脚本二唯一的外部目录创建：一处 mktemp -d，前缀 sct19.；其余一次是头部注释里的自述 ==="
show 'grep -n "mktemp" tools/screen-egress-tripartite-diff.sh'

echo "=== P13 TMPD 在脚本二里只出现在赋值与 trap 两处，正文从不向它写入，退出即删 ==="
show 'grep -n "TMPD" tools/screen-egress-tripartite-diff.sh'

echo "=== P14 设备侧命令行工具名在脚本二里的全部出现位置（第 13 行的头部拒收声明与第 469 行 K02 的拒收正则） ==="
show 'grep -nwE "mdls|mdimport|mdutil|mdfind|spctl|codesign|defaults|sysctl|xcrun|profiles|plutil|sips|qlmanage|otool" tools/screen-egress-tripartite-diff.sh'

echo "=== P14b 用同一条命令位置规则扫脚本二全文：被禁工具名出现在命令位置的行——应为空匹配 ==="
show 'grep -nE "(^|[;&|($])[[:space:]]*(file|log|mdls|mdimport|mdutil|mdfind|spctl|codesign|defaults|sysctl|xcrun|profiles|plutil|sips|qlmanage|otool)[[:space:]]" tools/screen-egress-tripartite-diff.sh'

echo "=== P14c file／log 两个与正文用词重叠的名字在脚本二里的整词命中行：逐行看均为注释、拒收正则与出处说明 ==="
show 'grep -nwE "file|log" tools/screen-egress-tripartite-diff.sh'

echo "=== P15 脚本二没有任何网络或外部程序调用词（与 P5 同一族词，去掉会被变量名 nc 误命中的裸词） ==="
show 'grep -nwE "curl|wget|netcat|ssh|scp|ping|nslookup|dig|openssl|git|python|node|perl|osascript|bash -c|eval" tools/screen-egress-tripartite-diff.sh'

echo "=== P16 脚本二实际调用的外部命令普查（计数为 0 的行不显示；perl／python／node 应为 0） ==="
show 'for c in awk sed grep tr cut sort uniq wc cat head tail mktemp rm date perl python node; do n=$(grep -ow -- "$c" tools/screen-egress-tripartite-diff.sh | wc -l); [ "$n" -gt 0 ] && printf "%s=%s " "$c" "$n"; done; echo'

echo "=== P17 脚本二的语法检查 ==="
show 'bash -n tools/screen-egress-tripartite-diff.sh && echo "bash -n 无输出，即通过"'

echo "=== P18 脚本二的三件夹具各跑一次后检查临时目录残留（应为「无残留」） ==="
show 'for f in FX/tri-19-good.txt FX/tri-19-mid.txt FX/tri-19-bad.txt; do bash tools/screen-egress-tripartite-diff.sh "$f" FX/capability-19.csv FX/vocab-19.tsv >/dev/null 2>&1; printf "%s exit=%s " "$f" "$?"; done; echo'
show 'ls -d "${TMPDIR:-/tmp}"/sct19.* 2>/dev/null && echo "有残留" || echo "无残留：临时目录前缀 sct19. 匹配不到任何东西"'

echo "=== P19 脚本二的 harness 里不存在任何 URL 或设备节点路径 ==="
show 'grep -nE "https?://|/dev/[a-z]" FX/run-all-tri.sh'

echo "=== P20 十五次实跑的命令行归一化后只剩「脚本 + 选项 + 三件夹具」这一种形状 ==="
show 'grep -h "^\$ " FX/run-log-tri.txt | grep -v "^\$ exit=" | sed "s#FX/[A-Za-z0-9._-]*#FX/<夹具>#g; s#tools/screen-egress-[a-z-]*\.sh#tools/<脚本>#g" | sort | uniq -c | sort -rn'
```

下面是它在本文归档上跑出的**全量输出**（`FX/readonly-proof.txt`，141 行、25 段，逐字照抄，未删行；每段自带原命令与 `$ exit=` 行）：

```text
=== P1 awk 程序体内没有任何系统调用型函数 ===
$ grep -nE "system[(]|getline *[<]|popen[(]|close[(]|cmd |exec " tools/screen-egress-ledger-review.sh
$ exit=1

=== P2 全文唯一的外部目录创建：一处 mktemp -d，前缀 scr19.；注释与用法文本各提一次 ===
$ grep -n "mktemp" tools/screen-egress-ledger-review.sh
10:#       唯一写出目标是 mktemp -d 创建的临时目录，退出时删除，本实现不向其写入任何字节。
135:本脚本不联网、不访问设备、不修改输入文件；临时件写在 mktemp -d 并在退出时删除。
147:TMPD=$(mktemp -d "${TMPDIR:-/tmp}/scr19.XXXXXX") || { echo "无法创建临时目录" >&2; exit 2; }
$ exit=0

=== P3 TMPD 只在赋值与 trap 里出现，正文从不向它写入，退出即删 ===
$ grep -n "TMPD" tools/screen-egress-ledger-review.sh
147:TMPD=$(mktemp -d "${TMPDIR:-/tmp}/scr19.XXXXXX") || { echo "无法创建临时目录" >&2; exit 2; }
148:trap 'rm -rf "$TMPD"' EXIT INT TERM
$ exit=0

=== P4 设备侧命令行工具名在脚本一里的全部出现位置（只应出现在第 8—9 行的拒收声明） ===
$ grep -nwE "mdls|mdimport|mdutil|mdfind|spctl|codesign|defaults|sysctl|xcrun|profiles|plutil|sips|qlmanage|otool" tools/screen-egress-ledger-review.sh
9:#       plutil／sips／qlmanage／otool 等任何命令行工具、不读取设备状态、不打开任何被登记的会话对象；
$ exit=0

=== P4b 两个与正文用词重叠的名字（file／log）整词匹配到的行：逐行看均为注释与出处说明 ===
$ grep -nwE "file|log" tools/screen-egress-ledger-review.sh
$ exit=1

=== P4c 命令位置探测的阳性对照：两条样例应命中 2，证明这条规则不是空转 ===
$ printf "%s\n" "log show --last 1h" "mdls -name kMDItemContentType" | grep -cE "(^|[;&|($])[[:space:]]*(file|log|mdls|mdimport|mdutil|mdfind|spctl|codesign|defaults|sysctl|xcrun|profiles|plutil|sips|qlmanage|otool)[[:space:]]"
2
$ exit=0

=== P4d 用同一条规则扫脚本一全文：被禁工具名出现在命令位置的行——应为空匹配 ===
$ grep -nE "(^|[;&|($])[[:space:]]*(file|log|mdls|mdimport|mdutil|mdfind|spctl|codesign|defaults|sysctl|xcrun|profiles|plutil|sips|qlmanage|otool)[[:space:]]" tools/screen-egress-ledger-review.sh
$ exit=1

=== P5 没有任何网络或外部程序调用词 ===
$ grep -nwE "curl|wget|nc|netcat|ssh|scp|ping|nslookup|dig|openssl|git|python|node|open|osascript" tools/screen-egress-ledger-review.sh
$ exit=1

=== P6 脚本一实际调用的外部命令普查（计数为 0 的行不显示；perl／python／node 应为 0） ===
$ for c in awk sed grep tr cut sort uniq wc cat head tail mktemp rm date perl python node; do n=$(grep -ow -- "$c" tools/screen-egress-ledger-review.sh | wc -l); [ "$n" -gt 0 ] && printf "%s=%s " "$c" "$n"; done; echo
awk=1 tr=3 cat=1 mktemp=3 rm=1 
$ exit=0

=== P7 脚本一的语法检查 ===
$ bash -n tools/screen-egress-ledger-review.sh && echo "bash -n 无输出，即通过"
bash -n 无输出，即通过
$ exit=0

=== P8 合格夹具跑一次后检查临时目录残留（应为「无残留」） ===
$ bash tools/screen-egress-ledger-review.sh FX/ledger-19-good.txt >/dev/null 2>&1; echo "脚本一 exit=$?"
脚本一 exit=0
$ exit=0

$ ls -d "${TMPDIR:-/tmp}"/scr19.* 2>/dev/null && echo "有残留" || echo "无残留：临时目录前缀 scr19. 匹配不到任何东西"
无残留：临时目录前缀 scr19. 匹配不到任何东西
$ exit=0

=== P9 harness 里不存在任何 URL 或设备节点路径 ===
$ grep -nE "https?://|/dev/[a-z]" FX/run-all.sh
$ exit=1

=== P10 十八次实跑的命令行归一化后只剩「脚本 + 选项 + 夹具」这一种形状 ===
$ grep -h "^\$ " FX/run-log.txt | grep -v "^\$ exit=" | sed "s#FX/[A-Za-z0-9._-]*#FX/<夹具>#g; s#tools/screen-egress-[a-z-]*\.sh#tools/<脚本>#g" | sort | uniq -c | sort -rn
     13 $ tools/<脚本> FX/<夹具>
      1 $ tools/<脚本> FX/<夹具> FX/<夹具> FX/<夹具>
      1 $ tools/<脚本> FX/<夹具> FX/<夹具>
      1 $ tools/<脚本> -q FX/<夹具>
      1 $ tools/<脚本> -h
      1 $ tools/<脚本> 
$ exit=0

=== P11 脚本二的 awk 程序体内同样没有任何系统调用型函数 ===
$ grep -nE "system[(]|getline *[<]|popen[(]|close[(]|cmd |exec " tools/screen-egress-tripartite-diff.sh
$ exit=1

=== P12 脚本二唯一的外部目录创建：一处 mktemp -d，前缀 sct19.；其余一次是头部注释里的自述 ===
$ grep -n "mktemp" tools/screen-egress-tripartite-diff.sh
18:#       唯一写出目标是 mktemp -d 创建的临时目录，退出时删除，本实现不向其写入任何字节。
105:TMPD=$(mktemp -d "${TMPDIR:-/tmp}/sct19.XXXXXX") || { echo "无法创建临时目录" >&2; exit 2; }
$ exit=0

=== P13 TMPD 在脚本二里只出现在赋值与 trap 两处，正文从不向它写入，退出即删 ===
$ grep -n "TMPD" tools/screen-egress-tripartite-diff.sh
105:TMPD=$(mktemp -d "${TMPDIR:-/tmp}/sct19.XXXXXX") || { echo "无法创建临时目录" >&2; exit 2; }
106:trap 'rm -rf "$TMPD"' EXIT INT TERM
$ exit=0

=== P14 设备侧命令行工具名在脚本二里的全部出现位置（第 13 行的头部拒收声明与第 469 行 K02 的拒收正则） ===
$ grep -nwE "mdls|mdimport|mdutil|mdfind|spctl|codesign|defaults|sysctl|xcrun|profiles|plutil|sips|qlmanage|otool" tools/screen-egress-tripartite-diff.sh
13:# 边界：本脚本不联网取公告，不调用 file/mdls/mdimport/mdutil/mdfind/spctl/codesign/defaults/log/sysctl/xcrun/profiles
469:        else if (rf ~ /^(file|mdls|mdimport|mdutil|mdfind|spctl|codesign|defaults|sysctl|xcrun|profiles|plutil|sips|qlmanage|otool|log|ls|find|screencapture|import)$/)
$ exit=0

=== P14b 用同一条命令位置规则扫脚本二全文：被禁工具名出现在命令位置的行——应为空匹配 ===
$ grep -nE "(^|[;&|($])[[:space:]]*(file|log|mdls|mdimport|mdutil|mdfind|spctl|codesign|defaults|sysctl|xcrun|profiles|plutil|sips|qlmanage|otool)[[:space:]]" tools/screen-egress-tripartite-diff.sh
$ exit=1

=== P14c file／log 两个与正文用词重叠的名字在脚本二里的整词命中行：逐行看均为注释、拒收正则与出处说明 ===
$ grep -nwE "file|log" tools/screen-egress-tripartite-diff.sh
13:# 边界：本脚本不联网取公告，不调用 file/mdls/mdimport/mdutil/mdfind/spctl/codesign/defaults/log/sysctl/xcrun/profiles
128:      || v ~ /^\/(Applications|private|var\/mobile|Users|Library|System|Developer)\// || v ~ /^file:\/\// \
469:        else if (rf ~ /^(file|mdls|mdimport|mdutil|mdfind|spctl|codesign|defaults|sysctl|xcrun|profiles|plutil|sips|qlmanage|otool|log|ls|find|screencapture|import)$/)
$ exit=0

=== P15 脚本二没有任何网络或外部程序调用词（与 P5 同一族词，去掉会被变量名 nc 误命中的裸词） ===
$ grep -nwE "curl|wget|netcat|ssh|scp|ping|nslookup|dig|openssl|git|python|node|perl|osascript|bash -c|eval" tools/screen-egress-tripartite-diff.sh
$ exit=1

=== P16 脚本二实际调用的外部命令普查（计数为 0 的行不显示；perl／python／node 应为 0） ===
$ for c in awk sed grep tr cut sort uniq wc cat head tail mktemp rm date perl python node; do n=$(grep -ow -- "$c" tools/screen-egress-tripartite-diff.sh | wc -l); [ "$n" -gt 0 ] && printf "%s=%s " "$c" "$n"; done; echo
awk=1 cat=1 mktemp=2 rm=1 
$ exit=0

=== P17 脚本二的语法检查 ===
$ bash -n tools/screen-egress-tripartite-diff.sh && echo "bash -n 无输出，即通过"
bash -n 无输出，即通过
$ exit=0

=== P18 脚本二的三件夹具各跑一次后检查临时目录残留（应为「无残留」） ===
$ for f in FX/tri-19-good.txt FX/tri-19-mid.txt FX/tri-19-bad.txt; do bash tools/screen-egress-tripartite-diff.sh "$f" FX/capability-19.csv FX/vocab-19.tsv >/dev/null 2>&1; printf "%s exit=%s " "$f" "$?"; done; echo
FX/tri-19-good.txt exit=0 FX/tri-19-mid.txt exit=1 FX/tri-19-bad.txt exit=1 
$ exit=0

$ ls -d "${TMPDIR:-/tmp}"/sct19.* 2>/dev/null && echo "有残留" || echo "无残留：临时目录前缀 sct19. 匹配不到任何东西"
无残留：临时目录前缀 sct19. 匹配不到任何东西
$ exit=0

=== P19 脚本二的 harness 里不存在任何 URL 或设备节点路径 ===
$ grep -nE "https?://|/dev/[a-z]" FX/run-all-tri.sh
$ exit=1

=== P20 十五次实跑的命令行归一化后只剩「脚本 + 选项 + 三件夹具」这一种形状 ===
$ grep -h "^\$ " FX/run-log-tri.txt | grep -v "^\$ exit=" | sed "s#FX/[A-Za-z0-9._-]*#FX/<夹具>#g; s#tools/screen-egress-[a-z-]*\.sh#tools/<脚本>#g" | sort | uniq -c | sort -rn
     11 $ tools/<脚本> FX/<夹具> FX/<夹具> FX/<夹具>
      1 $ tools/<脚本> FX/<夹具>
      1 $ tools/<脚本> -q FX/<夹具> FX/<夹具> FX/<夹具>
      1 $ tools/<脚本> -h
      1 $ tools/<脚本> 
$ exit=0
```

六段解读，每一段都能在上面那段输出里逐字找到对应行。

**被禁工具名只出现在头部拒收声明与 `K02` 拒收正则里。** P4 在脚本一里只命中第 9 行那一处头部拒收声明（`plutil／sips／qlmanage／otool 等任何命令行工具、不读取设备状态、不打开任何被登记的会话对象`）；P14 在脚本二里命中两行——第 13 行的头部拒收声明与第 469 行的拒收正则，后者正是 `K02` 的执行点，把「把命令行工具名登记成来源标识」当作错误登记拦下。第 469 行如果落在命令位置而不是正则字面量里，这条声明就作废；P4d 与 P14b 就是用来钉住这一点的。与正文用词重叠的两个名字另给两段：P4b 在脚本一里是**空匹配**（`$ exit=1`，说明 `file`／`log` 两个词在脚本一里根本不作为整词出现），P14c 在脚本二里命中三行（第 13 行注释、第 128 行取值形态判断里的 `^file://` 前缀、第 469 行拒收正则），三处都是数据或声明而不是命令。

**空匹配都配了阳性对照。** P4c 把 `log show --last 1h` 与 `mdls -name kMDItemContentType` 两条样例交给与 P4d／P14b 完全同一条「命令位置」正则，命中数 = 2；P4d 扫脚本一全文、P14b 扫脚本二全文都是空匹配（两段 `$ exit=1`）。这一对是刻意的：没有 P4c 那个 2，两条空匹配既可能是脚本干净，也可能是正则写坏了，两者不可区分。

**唯一写出目标只有一处，而且从不向它写。** P2 在脚本一里命中三行（第 10 行头部自述、第 135 行 usage 自述、第 147 行唯一的 `mktemp -d "${TMPDIR:-/tmp}/scr19.XXXXXX"`），P3 显示 `TMPD` 只出现在第 147 行赋值与第 148 行 `trap 'rm -rf "$TMPD"' EXIT INT TERM` 两行；脚本二一侧 P12 命中两行（第 18 行自述、第 105 行 `sct19.XXXXXX`）、P13 命中赋值与 `trap` 两行（第 105、106 行）。两份脚本正文里都没有第三处引用 `TMPD` 的行，也就是没有任何一次写入。

**外部命令普查显示两支脚本都没有第二种解释器。** P6 给出脚本一的 `awk=1 tr=3 cat=1 mktemp=3 rm=1`，P16 给出脚本二的 `awk=1 cat=1 mktemp=2 rm=1`。这一段的口径要读准：它数的是整词**出现次数**而不是调用次数，所以 `mktemp=3` 里只有一次是真正的目录创建，脚本一的 `tr=3` 其实是 `dom.transport` 那个取值变量名（源码第 390、433、435 行）。普查词表固定 17 个名字、计数为 0 的不显示，因此 `perl`／`python`／`node` 三行缺席就是「两支脚本本体一次都没用过它们」——`perl` 只出现在 `FX/` 下的派生器与验收件里。

**三档夹具跑完，临时目录两种前缀都查不到残留。** P8 先把 good 档跑一次（`脚本一 exit=0`），再按 `scr19.` 前缀查 `${TMPDIR:-/tmp}`，输出「无残留：临时目录前缀 scr19. 匹配不到任何东西」；P18 把三件夹具 good／mid／bad 各跑一次（`exit=0`、`exit=1`、`exit=1`），再按 `sct19.` 前缀查，同样「无残留」。这两段顺带把退出码的下界与上界各摸了一次：合格夹具 0、中间态与触发件 1。P9 与 P19 用同一条正则 `https?://|/dev/[a-z]` 扫两份 harness（`FX/run-all.sh` 与 `FX/run-all-tri.sh`），两段都是空匹配——三十三次实跑的输入全部来自仓库内的文本，没有 URL，也没有设备节点路径。

**归一化之后命令行只剩一种形状族。** P10 把十八次的命令行去掉夹具名后给出六种形状：`脚本 + 一份夹具` 13 次、`脚本 + 三份夹具` 1 次、`脚本 + 两份夹具` 1 次、`脚本 -q + 一份夹具` 1 次、`脚本 -h` 1 次、`脚本` 无参数 1 次，合计 18，与 C4 的段数相等；P20 把十五次归一化成五种：`脚本 + 三份夹具` 11 次、`脚本 + 一份夹具` 1 次（参数不足那次）、`脚本 -q + 三份夹具` 1 次、`脚本 -h` 1 次、无参数 1 次，合计 15。两种形状族里没有设备路径、没有 URL、没有重定向目标，说明实跑做过的事与本节写的完全一致；归一化刻意抹掉夹具名，具体哪一次喂了哪份夹具由 23.2 逐段给出，两者互为索引。

下面这张索引把二十段按「同一检查在两支脚本上的读数」并列，方便读者拿上面那段输出逐行核对；读数一栏全部是留档里的原值，空匹配一律写明 `$ exit=1`。

| 检查 | 脚本一段 | 脚本一读数 | 脚本二段 | 脚本二读数 |
| --- | --- | --- | --- | --- |
| awk 体内无系统调用型函数 | P1 | 空匹配（`$ exit=1`）| P11 | 空匹配（`$ exit=1`）|
| 唯一目录创建 | P2 | 三行：第 10、135、147 行 | P12 | 两行：第 18、105 行 |
| `TMPD` 引用面 | P3 | 两行：147 赋值、148 `trap` | P13 | 两行：105 赋值、106 `trap` |
| 被禁工具名出现位置 | P4 | 一行：第 9 行拒收声明 | P14 | 两行：第 13 行声明、第 469 行 `K02` 正则 |
| 命令位置规则阴性 | P4d | 空匹配 | P14b | 空匹配 |
| 与正文用词重叠的两个名字（`file`／`log`）整词匹配 | P4b | 空匹配（`$ exit=1`）| P14c | 三行：第 13、128、469 行 |
| 命令位置规则的阳性对照 | P4c | 命中数 2 | P4c | 同左，这一段样例两支脚本共用 |
| 网络与外部程序调用词 | P5 | 空匹配 | P15 | 空匹配（词表另去裸词 `nc`、加 `perl`／`bash -c`／`eval`）|
| 外部命令普查 | P6 | `awk=1 tr=3 cat=1 mktemp=3 rm=1` | P16 | `awk=1 cat=1 mktemp=2 rm=1` |
| 语法检查 | P7 | `bash -n` 无输出即通过 | P17 | `bash -n` 无输出即通过 |
| 跑完夹具后的残留 | P8 | `脚本一 exit=0` ＋ `scr19.` 无残留 | P18 | `exit=0`／`1`／`1` ＋ `sct19.` 无残留 |
| harness 内 URL 与设备路径 | P9 | 空匹配 | P19 | 空匹配 |
| 命令行归一化形状族 | P10 | 六种形状，合计 18 | P20 | 五种形状，合计 15 |

这张表里没有「通过／不通过」这一列，因为二十段全是读数而不是断言：判定由读者拿本节列出的期望去比对。唯一带结论性的是 P4c 那个 2——它不证明脚本干净，只证明 P4d／P14b 那条规则本身还活着。

### 23.2 三十三次实跑清单与 R 号约定（V4 的一半）

三十三次实跑分两份留档：`FX/run-log.txt`（18 个 `===== RUN:` 段、2,444 行，全部跑脚本一）与 `FX/run-log-tri.txt`（15 段、4,157 行，全部跑脚本二），两个段数与两个行数都由 23.3 的 C4 与 C14 现场重数。每段由 harness 写下标签行、命令行、合并的 stdout+stderr 与 `$ exit=` 行。下表逐段给「输入组合」与「这一段期望看到的族」；族一栏里列出的码取自该段留档本身。

**脚本一（R1—R18，harness 为 `FX/run-all.sh`）**

| 号 | 段标签 | 输入组合 | 期望看到的族 | 退出码 |
| --- | --- | --- | --- | --- |
| R1 | `codes` | `FX/ledger-19-bad.txt`（逐码构造，一个会话只扰动一处，68 个会话） | 十三族全量：这一份打出 67 个信号码，A／B／C／D／E／G／K／N／O／R／S／V／X 都有代表 | 1 |
| R2 | `good` | `FX/ledger-19-good.txt`（四条画面外流通道各一条会话） | 无信号、无族可期望：这是下界，四档里只有 J1 | 0 |
| R3 | `mid` | `FX/ledger-19-mid.txt`（四条会话各带 1—3 条非结构性信号） | 非阻断侧的 A／C／D／N／O／R 六族，并补齐 R1 未打到的 `A05`／`C07`／`D03`／`R04`；J2 与 J3 同现 | 0 |
| R4 | `multi` | good + mid + bad 三份同输入 | 合并读入后 71 个信号码全覆盖，四档判定同框 | 1 |
| R5 | `twice` | good 传两遍 | 只出 S 族一条：`S03` 250 条（同一字段重复登记），整批落 J4 | 1 |
| R6 | `quiet` | `-q FX/ledger-19-bad.txt` | 与 R1 同一输入：族与码一个不少，只关掉判定行 | 1 |
| R7 | `help` | `-h` | 无判定：usage 文本自身，含十二个命名空间与必备格清单 | 0 |
| R8 | `noargs` | 无参数 | 无判定：参数校验走 usage 到 stderr | 2 |
| R9 | `missing` | `FX/does-not-exist.txt` | 无判定：「输入不可读」这条路径与 R8 同为 2 而不是 1 | 2 |
| R10 | `empty` | 空文件 | 无判定：零会话，没有登记就没有可判的东西 | 0 |
| R11 | `comments` | 只有注释与空行 | 无判定：注释与空行忽略是实现出来的，不是约定的例外 | 0 |
| R12 | `malformed` | 行格式畸形（缺列／多列／无命名空间／CRLF／`sec.*`／空标识） | S 族 `S01`／`S02`／`S04`／`S07`／`S09` 加 K 族 `K01`，共 9 个码 | 1 |
| R13 | `unknown-field` | 未知命名空间与未登记字段 | `S04`／`S05` 的边界：命名空间清单与字段清单是两层不同的检查，共 6 个码 | 1 |
| R14 | `shape` | 取值形态越界十三处 | 形态族集中一次喂出：`B04`／`B05`／`B06`／`C06`／`G05`／`K03`／`R02`／`R06`／`S07`／`S08`／`X02` 十一处，加临时夹具固有的 `B01`／`D01`／`S09`，共 14 个码 | 1 |
| R15 | `duplicate` | 重复登记与同字段双值 | `S03` 的两条路径（完全相同与取值不同），加临时夹具固有五条，共 7 个码 | 1 |
| R16 | `reject-shapes` | 拒收形态取值五处 | 拒收侧三条：`K02` 命中三值（设备路径、`-----BEGIN` 密钥头、Base64 长载荷）、`K03` 命中崩溃正文式引用、`B06` 命中把密钥头当跨会话引用；另加 `S07` 的 `chan.buffer_form` 枚举越界与 11 条 `S09`，共 8 个码 | 1 |
| R17 | `required-missing` | 只登记一行 | `S09` 的算术：十二个必备格缺十一格逐格记一条，加临时夹具固有六条，共 7 个码 | 1 |
| R18 | `legal-not-applicable` | good 档改写四格为 `not_determinable`／`absent` | 合法一侧的反面对照：S 族与 K 族都不响，只留一条 `B01`（标识前缀 `NA_OK` 不在四类内）落 J2 | 0 |

R12—R17 这六段每段都带 `B01`／`D01` 两条，除 `shape` 外还各带一条 `O02`，`shape`／`unknown-field`／`duplicate`／`reject-shapes`／`required-missing` 五段还各带一条 `S09`：临时夹具只喂要检的那一两格，会话标识前缀、执行域与读数时刻本来就空着，必备格也必然缺。这不是漏跑，是小夹具的固有形状；因此「共 N 个码」总比正文点名的码数多，多出的就是这几条。

**脚本二（R19—R33，harness 为 `FX/run-all-tri.sh`，每段固定三份输入）**

| 号 | 段标签 | 输入组合 | 期望看到的族 | 退出码 |
| --- | --- | --- | --- | --- |
| R19 | `codes` | `FX/tri-19-bad.txt` + `FX/capability-19.csv` + `FX/vocab-19.tsv` | S／D／K／M／P／T／V／X 八族全量：54 个信号码（60 减 C 族五条、减 `X08`，这两组只在 R23／R24 出） | 1 |
| R20 | `good` | `FX/tri-19-good.txt` + 两份干净表 | 无信号：九会话全 Q1，是这套模型的下界 | 0 |
| R21 | `mid` | `FX/tri-19-mid.txt` + 两份干净表 | D 族与 T 族同框（`D02`／`D04`／`D05`／`T01`／`T04`／`T06`／`T08`），Q2、Q3、Q4 三档同现 | 1 |
| R22 | `crafted-only` | `FX/tri-19-crafted.txt` + 干净能力表 + `FX/vocab-19-subset.tsv` | 反向判据 `X01` 一条（组件名 `GraphicServices` 在输入语表第 92 行而不在 129 个全量组件名里）＋单行清单固有的 `D02`／`D05`／`T02`，共 4 个码 | 1 |
| R23 | `bad-capability` | `FX/tri-19-bad.txt` + **畸形能力表** `FX/capability-19-bad.csv` + 干净词表 | C 族五条全出（`C01`—`C05`，首现都在此）与会话类未建模的 `D04`：C／D／K／M／P／S／T／V 八族共 37 个码 | 1 |
| R24 | `bad-vocabulary` | `FX/tri-19-bad.txt` + 干净能力表 + **畸形词表** `FX/vocab-19-bad.tsv` | 公开词表自身形态：`X08` 首现于此，S／D／K／M／P／T／V／X 八族共 49 个码 | 1 |
| R25 | `quiet` | `-q` + R19 同样三份 | 与 R19 同码同数：`-q` 关掉的是判定行与两块矩阵，不改判定 | 1 |
| R26 | `help` | `-h` | 无判定：usage 含三件清单、二十项核对项与阻断／非阻断两个清单 | 0 |
| R27 | `noargs` | 无参数 | 无判定：「恰好三份」这条硬约束 | 2 |
| R28 | `fewargs` | 只给清单一份 | 无判定：同一硬约束的第二种触发形态 | 2 |
| R29 | `missing` | 清单不存在 + 两份干净表 | 无判定：三份输入任一份缺失都是 2 | 2 |
| R30 | `empty-tables` | good + **空壳能力表** + **空壳词表** | 两条「整表无有效行」同框：`C05` 与 `X08`，九会话整批 Q4 | 1 |
| R31 | `empty-ledger` | **空清单** + 两份干净表 | 零会话：D 族一条 `D05`，二十项核对项在整张清单里零登记，非阻断所以退出码仍 0 | 0 |
| R32 | `one-item` | 单行清单 + 两份干净表 | `D05`＋`D02`＋`T01`＋`T08`：只登记一项时三件只出现声明件 | 1 |
| R33 | `same-file` | 三份输入指向同一份 good 清单 | `C05`＋`X08`＋`S08` 同框（`S08` 358 条数组型重复登记），九会话整批 Q4 | 1 |

**R 号只是本章的编号约定。** 两支脚本与两份 harness 都不认识 R 号：留档里的段头是 `===== RUN: codes`、`===== RUN: good` 这样的标签，R 号是本文按标签出现顺序赋的序号，脚本一从 R1 起、脚本二从 R19 起，接续编号使总数正好是 33。23.4 两张表的首现列由 `FX/tbl-check.pl` 的第四个参数注入——表 1 传 1、表 2 传 19（即 C21／C22 那两条调用），所以「首现 R 号」与「加粗与否」都不是手写的，而是把表件与留档对撞出来的结果；表里凡加粗的格都表示该码的首现晚于起跑那一次。

**退出码算术**：脚本一 6 个 0、10 个 1、2 个 2，共 18；脚本二 3 个 0、9 个 1、3 个 2，共 15；两串分别与 C9／C19 的分布逐数相等，两个总数与 C4／C14 的段数相等。这三种退出码的分布本身就是验收项：只出现 0 与 1 说明输入校验那条路径没被跑到，只出现 1 说明合格一侧的下界没被证明。

### 23.3 覆盖比对（V1）

`FX/coverage-report.sh` 是这一节的唯一证据来源。它做三类事：grep 两支脚本的源码数出定义集合与出处集合、调用 `FX/` 下三个派生器（`code-coverage.pl`、`code-uniqueness.pl`、`tbl-check.pl`）把留档重数一遍、用 `grep -c` 与 `wc -l` 复核两份运行留档的段数与行数；同样不联网、不访问设备、不修改任何输入。`C1—C10` 针对脚本一，`C11—C20` 针对脚本二，`C21—C22` 是 23.4 两张表件的现场重数，编号按「同一检查在两支脚本上各出现一次」左右对齐，便于逐行比对。

```bash
#!/usr/bin/env bash
# coverage-report.sh —— 生成 FX/coverage-proof.txt（信号码覆盖验收留档）
# 只做五件事：数一遍两个脚本里定义的号、各跑一遍覆盖夹具、比对两者、把逐号触发次数列出来、最后用 tbl-check 把第 23 章两张表件现场重算一遍。
# C1—C10 为脚本一（screen-egress-ledger-review.sh 与 FX/run-log.txt），C11—C20 为脚本二（screen-egress-tripartite-diff.sh 与 FX/run-log-tri.txt），C21—C22 为两张表件的重算。
# 本脚本不联网、不访问设备、不修改任何夹具；唯一写出目标是 FX/coverage-proof.txt。
set -u
LC_ALL=C; export LC_ALL
cd "$(dirname "$0")/.." || exit 1

OUT=FX/coverage-proof.txt
: > "$OUT"

show() {
  printf '$ %s\n' "$*"
  bash -c "$*" 2>&1
  printf '$ exit=%s\n\n' "$?"
}

{
echo "=== C1 脚本一定义的信号码数（emit 调用去重） ==="
show 'grep -oE "emit\(\"[A-Z][0-9]+\"" tools/screen-egress-ledger-review.sh | grep -oE "\"[A-Z][0-9]+\"" | tr -d "\"" | sort -u | wc -l'

echo "=== C2 脚本一逐号出处（DOC 赋值去重）：与 C1 同为 71，缺一即脚本自身不一致 ==="
show 'grep -oE "DOC\[\"[A-Z][0-9]+\"\]" tools/screen-egress-ledger-review.sh | grep -oE "\"[A-Z][0-9]+\"" | tr -d "\"" | sort -u | wc -l'

echo "=== C3 定义集合与出处集合的差集（应为空） ==="
show 'comm -3 <(grep -oE "emit\(\"[A-Z][0-9]+\"" tools/screen-egress-ledger-review.sh | grep -oE "\"[A-Z][0-9]+\"" | tr -d "\"" | sort -u) <(grep -oE "DOC\[\"[A-Z][0-9]+\"\]" tools/screen-egress-ledger-review.sh | grep -oE "\"[A-Z][0-9]+\"" | tr -d "\"" | sort -u)'

echo "=== C4 全量运行留档的行数与运行次数 ==="
show 'grep -c "^===== RUN" FX/run-log.txt; wc -l < FX/run-log.txt'

echo "=== C5 信号码覆盖比对（判定位 J1—J4 不计入信号码） ==="
show 'perl FX/code-coverage.pl tools/screen-egress-ledger-review.sh FX/run-log.txt'

echo "=== C6 逐号触发次数（按族排序，全部 >= 1；判定行 J1—J4 与逐码计数行已剔除） ==="
show 'grep -E "^[A-Z][0-9]+[[:space:]]" FX/run-log.txt | grep -vE "^J[1-4][[:space:]]" | grep -vE "^[A-Z][0-9]+[[:space:]]+[0-9]+[[:space:]]*$" | cut -f1 | sort | uniq -c | sort -k2 | awk "{printf \"%s=%s \", \$2, \$1}"'

echo "=== C7 触发次数最少的那些号（应没有 0；判定行 J1—J4 与逐码计数行已剔除） ==="
show 'grep -E "^[A-Z][0-9]+[[:space:]]" FX/run-log.txt | grep -vE "^J[1-4][[:space:]]" | grep -vE "^[A-Z][0-9]+[[:space:]]+[0-9]+[[:space:]]*$" | cut -f1 | sort | uniq -c | sort -n | head -5'

echo "=== C8 四级判定的可达性：good 出 J1、mid 出 J2 与 J3、bad 出 J4 ==="
show 'grep -h "^判定分布" FX/run-log.txt | sort -u'

echo "=== C9 退出码分布：0（无阻断）／1（有阻断）／2（输入不可用）都出现过 ==="
show 'grep "^\\\$ exit=" FX/run-log.txt | sort | uniq -c'

echo "=== C10 一号两义的排查：同一信号码在源码里只允许对应一条判据（字段参数化除外） ==="
show 'perl FX/code-uniqueness.pl tools/screen-egress-ledger-review.sh'

echo "=== C11 脚本二定义的信号码数（emit 调用去重，含判定行 Q1—Q4） ==="
show 'grep -oE "emit\(\"[A-Z][0-9]+\"" tools/screen-egress-tripartite-diff.sh | grep -oE "\"[A-Z][0-9]+\"" | tr -d "\"" | sort -u | wc -l'

echo "=== C12 脚本二逐号出处（DOC 赋值去重）：与 C11 同为 64，缺一即脚本自身不一致 ==="
show 'grep -oE "DOC\[\"[A-Z][0-9]+\"\]" tools/screen-egress-tripartite-diff.sh | grep -oE "\"[A-Z][0-9]+\"" | tr -d "\"" | sort -u | wc -l'

echo "=== C13 脚本二定义集合与出处集合的差集（应为空） ==="
show 'comm -3 <(grep -oE "emit\(\"[A-Z][0-9]+\"" tools/screen-egress-tripartite-diff.sh | grep -oE "\"[A-Z][0-9]+\"" | tr -d "\"" | sort -u) <(grep -oE "DOC\[\"[A-Z][0-9]+\"\]" tools/screen-egress-tripartite-diff.sh | grep -oE "\"[A-Z][0-9]+\"" | tr -d "\"" | sort -u)'

echo "=== C14 脚本二全量运行留档的行数与运行次数 ==="
show 'grep -c "^===== RUN" FX/run-log-tri.txt; wc -l < FX/run-log-tri.txt'

echo "=== C15 脚本二的信号码覆盖比对（判定位由 emit 产生，Q1—Q4 要求各自至少可达一次） ==="
show 'perl FX/code-coverage.pl tools/screen-egress-tripartite-diff.sh FX/run-log-tri.txt'

echo "=== C16 脚本二逐号触发次数（按族排序，全部 >= 1；剔除规则同 C6） ==="
show 'grep -E "^[A-Z][0-9]+[[:space:]]" FX/run-log-tri.txt | grep -vE "^[A-Z][0-9]+[[:space:]]+[0-9]+[[:space:]]*$" | cut -f1 | sort | uniq -c | sort -k2 | awk "{printf \"%s=%s \", \$2, \$1}"'

echo "=== C17 脚本二触发次数最少的那些号（应没有 0；剔除规则同 C16） ==="
show 'grep -E "^[A-Z][0-9]+[[:space:]]" FX/run-log-tri.txt | grep -vE "^[A-Z][0-9]+[[:space:]]+[0-9]+[[:space:]]*$" | cut -f1 | sort | uniq -c | sort -n | head -5'

echo "=== C18 脚本二四级闭合判定的可达性：good 出 Q1、mid 出 Q2/Q3/Q4、bad 出四级同框 ==="
show 'grep -h "^闭合等级 Q" FX/run-log-tri.txt | sort -u'

echo "=== C19 脚本二的退出码分布：0（无阻断）／1（有阻断）／2（输入不可用）都出现过 ==="
show 'grep "^\\\$ exit=" FX/run-log-tri.txt | sort | uniq -c'

echo "=== C20 脚本二一号两义的排查：同一信号码在源码里只允许对应一条判据 ==="
show 'perl FX/code-uniqueness.pl tools/screen-egress-tripartite-diff.sh'

echo "=== C21 表件重算（脚本一）：第 23 章表 1 的每格（首现 R 号与累计）由本留档现场重数并逐项比对 ==="
show 'perl FX/tbl-check.pl PART/tbl1.md tools/screen-egress-ledger-review.sh FX/run-log.txt 1'

echo "=== C22 表件重算（脚本二）：第 23 章表 2 的每格由本留档现场重数并逐项比对 ==="
show 'perl FX/tbl-check.pl PART/tbl2.md tools/screen-egress-tripartite-diff.sh FX/run-log-tri.txt 19'
} >> "$OUT" 2>&1

echo "已写出 $OUT ($(wc -l < "$OUT") 行)"
```

下面是它在本文归档上跑出的**全量输出**（`FX/coverage-proof.txt`，136 行、22 段，逐字照抄，未删行；每段同样自带原命令与 `$ exit=` 行）：

```text
=== C1 脚本一定义的信号码数（emit 调用去重） ===
$ grep -oE "emit\(\"[A-Z][0-9]+\"" tools/screen-egress-ledger-review.sh | grep -oE "\"[A-Z][0-9]+\"" | tr -d "\"" | sort -u | wc -l
71
$ exit=0

=== C2 脚本一逐号出处（DOC 赋值去重）：与 C1 同为 71，缺一即脚本自身不一致 ===
$ grep -oE "DOC\[\"[A-Z][0-9]+\"\]" tools/screen-egress-ledger-review.sh | grep -oE "\"[A-Z][0-9]+\"" | tr -d "\"" | sort -u | wc -l
71
$ exit=0

=== C3 定义集合与出处集合的差集（应为空） ===
$ comm -3 <(grep -oE "emit\(\"[A-Z][0-9]+\"" tools/screen-egress-ledger-review.sh | grep -oE "\"[A-Z][0-9]+\"" | tr -d "\"" | sort -u) <(grep -oE "DOC\[\"[A-Z][0-9]+\"\]" tools/screen-egress-ledger-review.sh | grep -oE "\"[A-Z][0-9]+\"" | tr -d "\"" | sort -u)
$ exit=0

=== C4 全量运行留档的行数与运行次数 ===
$ grep -c "^===== RUN" FX/run-log.txt; wc -l < FX/run-log.txt
18
2444
$ exit=0

=== C5 信号码覆盖比对（判定位 J1—J4 不计入信号码） ===
$ perl FX/code-coverage.pl tools/screen-egress-ledger-review.sh FX/run-log.txt
定义 71 命中 71 未触发清单 [] 未定义命中 []
$ exit=0

=== C6 逐号触发次数（按族排序，全部 >= 1；判定行 J1—J4 与逐码计数行已剔除） ===
$ grep -E "^[A-Z][0-9]+[[:space:]]" FX/run-log.txt | grep -vE "^J[1-4][[:space:]]" | grep -vE "^[A-Z][0-9]+[[:space:]]+[0-9]+[[:space:]]*$" | cut -f1 | sort | uniq -c | sort -k2 | awk "{printf \"%s=%s \", \$2, \$1}"
A01=3 A02=3 A03=5 A04=5 A05=2 A06=3 B01=16 B02=3 B03=3 B04=13 B05=4 B06=13 C01=34 C02=3 C03=3 C04=3 C05=3 C06=8 C07=2 C08=66 C09=3 D01=48 D02=3 D03=2 D04=3 D05=3 D06=3 E01=35 E02=3 E03=3 E04=6 E05=3 G01=6 G02=3 G03=3 G04=3 G05=4 K01=4 K02=18 K03=5 N01=35 N02=5 N03=3 N04=3 N05=3 O01=3 O02=188 O03=3 O04=5 R01=3 R02=4 R03=6 R04=2 R05=5 R06=4 R07=3 S01=4 S02=4 S03=255 S04=7 S05=5 S06=3 S07=13 S08=7 S09=666 V01=3 V02=3 V03=3 V04=3 X01=12 X02=4 $ exit=0

=== C7 触发次数最少的那些号（应没有 0；判定行 J1—J4 与逐码计数行已剔除） ===
$ grep -E "^[A-Z][0-9]+[[:space:]]" FX/run-log.txt | grep -vE "^J[1-4][[:space:]]" | grep -vE "^[A-Z][0-9]+[[:space:]]+[0-9]+[[:space:]]*$" | cut -f1 | sort | uniq -c | sort -n | head -5
      2 A05
      2 C07
      2 D03
      2 R04
      3 A01
$ exit=0

=== C8 四级判定的可达性：good 出 J1、mid 出 J2 与 J3、bad 出 J4 ===
$ grep -h "^判定分布" FX/run-log.txt | sort -u
判定分布 J1=0 J2=0 J3=0 J4=0
判定分布 J1=0 J2=0 J3=0 J4=1
判定分布 J1=0 J2=0 J3=0 J4=4
判定分布 J1=0 J2=1 J3=0 J4=0
判定分布 J1=0 J2=3 J3=0 J4=65
判定分布 J1=0 J2=3 J3=1 J4=0
判定分布 J1=4 J2=0 J3=0 J4=0
判定分布 J1=4 J2=6 J3=1 J4=65
$ exit=0

=== C9 退出码分布：0（无阻断）／1（有阻断）／2（输入不可用）都出现过 ===
$ grep "^\\\$ exit=" FX/run-log.txt | sort | uniq -c
      6 $ exit=0
     10 $ exit=1
      2 $ exit=2
$ exit=0

=== C10 一号两义的排查：同一信号码在源码里只允许对应一条判据（字段参数化除外） ===
$ perl FX/code-uniqueness.pl tools/screen-egress-ledger-review.sh
形态族 C06：接口标识形态非法 / 服务端子点形态非法
参数化 S07：布尔位取值非法 / 枚举越界
信号码总数 71｜一号一判据 69｜形态族 1｜参数化 1｜一号多义 0
$ exit=0

=== C11 脚本二定义的信号码数（emit 调用去重，含判定行 Q1—Q4） ===
$ grep -oE "emit\(\"[A-Z][0-9]+\"" tools/screen-egress-tripartite-diff.sh | grep -oE "\"[A-Z][0-9]+\"" | tr -d "\"" | sort -u | wc -l
64
$ exit=0

=== C12 脚本二逐号出处（DOC 赋值去重）：与 C11 同为 64，缺一即脚本自身不一致 ===
$ grep -oE "DOC\[\"[A-Z][0-9]+\"\]" tools/screen-egress-tripartite-diff.sh | grep -oE "\"[A-Z][0-9]+\"" | tr -d "\"" | sort -u | wc -l
64
$ exit=0

=== C13 脚本二定义集合与出处集合的差集（应为空） ===
$ comm -3 <(grep -oE "emit\(\"[A-Z][0-9]+\"" tools/screen-egress-tripartite-diff.sh | grep -oE "\"[A-Z][0-9]+\"" | tr -d "\"" | sort -u) <(grep -oE "DOC\[\"[A-Z][0-9]+\"\]" tools/screen-egress-tripartite-diff.sh | grep -oE "\"[A-Z][0-9]+\"" | tr -d "\"" | sort -u)
$ exit=0

=== C14 脚本二全量运行留档的行数与运行次数 ===
$ grep -c "^===== RUN" FX/run-log-tri.txt; wc -l < FX/run-log-tri.txt
15
4157
$ exit=0

=== C15 脚本二的信号码覆盖比对（判定位由 emit 产生，Q1—Q4 要求各自至少可达一次） ===
$ perl FX/code-coverage.pl tools/screen-egress-tripartite-diff.sh FX/run-log-tri.txt
定义 64 命中 64 未触发清单 [] 未定义命中 []
$ exit=0

=== C16 脚本二逐号触发次数（按族排序，全部 >= 1；剔除规则同 C6） ===
$ grep -E "^[A-Z][0-9]+[[:space:]]" FX/run-log-tri.txt | grep -vE "^[A-Z][0-9]+[[:space:]]+[0-9]+[[:space:]]*$" | cut -f1 | sort | uniq -c | sort -k2 | awk "{printf \"%s=%s \", \$2, \$1}"
C01=1 C02=1 C03=1 C04=1 C05=5 D01=3 D02=2065 D03=9 D04=26 D05=101 K01=3 K02=4 K03=3 K04=3 K05=3 M01=4 M02=6 M03=9 M04=4 M05=22 M06=6 P01=3 P02=3 P03=4 P04=4 P05=15 P06=3 P07=6 Q1=9 Q2=127 Q3=22 Q4=42 S01=4 S02=4 S03=4 S04=4 S05=4 S06=4 S07=16 S08=366 S09=8 S10=4 T01=78 T02=125 T03=4 T04=13 T05=4 T06=9 T07=4 T08=115 V01=4 V02=56 V03=4 V04=3 V05=4 V06=3 X01=3 X02=4 X03=2 X04=4 X05=2 X06=2 X07=9 X08=6 $ exit=0

=== C17 脚本二触发次数最少的那些号（应没有 0；剔除规则同 C16） ===
$ grep -E "^[A-Z][0-9]+[[:space:]]" FX/run-log-tri.txt | grep -vE "^[A-Z][0-9]+[[:space:]]+[0-9]+[[:space:]]*$" | cut -f1 | sort | uniq -c | sort -n | head -5
      1 C01
      1 C02
      1 C03
      1 C04
      2 X03
$ exit=0

=== C18 脚本二四级闭合判定的可达性：good 出 Q1、mid 出 Q2/Q3/Q4、bad 出四级同框 ===
$ grep -h "^闭合等级 Q" FX/run-log-tri.txt | sort -u
闭合等级 Q1=0 Q2=0 Q3=0 Q4=0
闭合等级 Q1=0 Q2=0 Q3=0 Q4=9
闭合等级 Q1=0 Q2=1 Q3=0 Q4=0
闭合等级 Q1=0 Q2=1 Q3=1 Q4=1
闭合等级 Q1=0 Q2=27 Q3=10 Q4=19
闭合等级 Q1=0 Q2=48 Q3=6 Q4=2
闭合等级 Q1=0 Q2=49 Q3=5 Q4=2
闭合等级 Q1=9 Q2=0 Q3=0 Q4=0
$ exit=0

=== C19 脚本二的退出码分布：0（无阻断）／1（有阻断）／2（输入不可用）都出现过 ===
$ grep "^\\\$ exit=" FX/run-log-tri.txt | sort | uniq -c
      3 $ exit=0
      9 $ exit=1
      3 $ exit=2
$ exit=0

=== C20 脚本二一号两义的排查：同一信号码在源码里只允许对应一条判据 ===
$ perl FX/code-uniqueness.pl tools/screen-egress-tripartite-diff.sh
信号码总数 64｜一号一判据 64｜形态族 0｜参数化 0｜一号多义 0
$ exit=0

=== C21 表件重算（脚本一）：第 23 章表 1 的每格（首现 R 号与累计）由本留档现场重数并逐项比对 ===
$ perl FX/tbl-check.pl PART/tbl1.md tools/screen-egress-ledger-review.sh FX/run-log.txt 1
表内格 75｜脚本一定义码 75｜不一致 0｜表内未出现的码 []
$ exit=0

=== C22 表件重算（脚本二）：第 23 章表 2 的每格由本留档现场重数并逐项比对 ===
$ perl FX/tbl-check.pl PART/tbl2.md tools/screen-egress-tripartite-diff.sh FX/run-log-tri.txt 19
表内格 64｜脚本一定义码 64｜不一致 0｜表内未出现的码 []
$ exit=0
```

七段解读之前，先把二十二段按「同一检查在两支脚本上的读数」并列成索引，读数一栏全是上面 fence 里的原值；读者拿这张表定位，再回留档核行。

| 检查 | 段 | 读数 | 段 | 读数 |
| --- | --- | --- | --- | --- |
| 定义数（`emit` 去重）| C1 | 71 | C11 | 64（含 Q1—Q4）|
| 出处数（`DOC[…]` 去重）| C2 | 71 | C12 | 64 |
| 两集合差集 | C3 | 空 | C13 | 空 |
| 留档段数／行数 | C4 | 18／2444 | C14 | 15／4157 |
| 覆盖比对 | C5 | `定义 71 命中 71 未触发清单 [] 未定义命中 []` | C15 | `定义 64 命中 64 未触发清单 [] 未定义命中 []` |
| 逐号计数串 | C6 | 71 项，最大 `S09=666` | C16 | 64 项，最大 `D02=2065` |
| 最少的五个号 | C7 | `2 A05`／`2 C07`／`2 D03`／`2 R04`／`3 A01` | C17 | `1 C01`／`1 C02`／`1 C03`／`1 C04`／`2 X03` |
| 判定分布去重 | C8 | 八行 | C18 | 八行 |
| 退出码分布 | C9 | `0×6 1×10 2×2` | C19 | `0×3 1×9 2×3` |
| 一号两义 | C10 | 一号多义 0（形态族 1、参数化 1）| C20 | 一号多义 0（两类例外都是 0）|
| 表件现场重数 | C21 | `表内格 75｜不一致 0` | C22 | `表内格 64｜不一致 0` |

七段解读，读数全部出自上面那段留档。

**定义集合与出处集合两侧同数、差集为空。** C1 与 C2 都是 `71`，C3 的 `comm -3` 无输出（`$ exit=0`）：脚本一里每一次 `emit("…")` 都用得到一个 `DOC[…]` 出处，反之每一个出处都被调用到，没有只写不用的注释，也没有无出处的信号。脚本二一侧 C11 与 C12 都是 `64`、C13 同样为空差集。这两个「两侧同数」是脚本自身的内在一致性检查，与实跑无关，所以它排在覆盖比对之前。

**留档规模由现场重数。** C4 给出脚本一留档 `18` 段、`2444` 行，C14 给出脚本二留档 `15` 段、`4157` 行；两个段数与 23.2 的 R1—R18、R19—R33 一一对应，也与 23.1 的 P10／P20 归一化形状合计（13+1+1+1+1+1=18、11+1+1+1+1=15）互证——三份留档说的是同一批实跑。

**未触发清单与未定义命中双向都空。** C5 的整行输出是 `定义 71 命中 71 未触发清单 [] 未定义命中 []`，C15 是 `定义 64 命中 64 未触发清单 [] 未定义命中 []`。左边那个空清单说明 V1 成立：脚本一 71 个信号码、脚本二 64 个（含 Q1—Q4）在 33 次实跑里每个至少出现一次；右边那个空清单说明留档里没有源码中不存在的码——两份留档不是手抄的。

**逐号计数与两张表件的累计列同源。** C6 与 C16 那两串的逐字读数已在 fence 里，这里只点出四个反直觉的大数：脚本一 `S09=666`、`O02=188`、`S03=255`、`C08=66`，脚本二 `D02=2065`、`S08=366`、`Q2=127`、`T01=78`。它们大不是因为某条判据被反复触发，而是因为这两类判据按格与按行计数：`S09` 对每个会话逐格记一次缺失的必备格，R1、R4、R6 这三段各出 188 条（R4 那次三份夹具合并读入 76 个会话），光这三段就占了 666 里的 564；`O02` 是「有观测平面却未登记读数时刻」的逐会话读数，同样三段各出 60 条，加上五段小夹具的零星条目凑成 188；脚本二的 `D02`（本会话缺某个 required 核对项）按会话乘核对项计数，十五段累到 2065，`S08` 的 366 条里 358 条来自 R33 那一次三份输入指向同一份清单的重复登记。因此这几个数只能与 C21／C22 的重算结果比对，不能拿直觉去核；另外留档里每个码还会打一行「码＋条数」的计数行，C6 与 C16 的口径已把那类行剔除，本节所有数都是剔除后的信号行数。23.4 两张表的累计列与这两串是同一次 `grep` 的产物，逐数相等。

**最少的号也没有 0。** C7 五行是 `2 A05`、`2 C07`、`2 D03`、`2 R04`、`3 A01`，C17 五行是 `1 C01`、`1 C02`、`1 C03`、`1 C04`、`2 X03`。脚本一最少的四个号恰好就是表 1 里首现晚于 R1 的那四个（A05／C07／D03／R04，都在 R3 才出现，各只被 mid 档打到一次、再被 R4 打到一次）；脚本二最少的四个号恰好是 `C01—C05` 里的四条，它们只在畸形能力表那一段（R23）出现。换句话说，「最小值」这一段与「首现」那一列指向同一批边缘覆盖，两处互相钉住。

**四级判定的可达性八行。** C8 与 C18 各自 `sort -u` 出八行，逐字如下，每行都能在两份留档里找到对应那一次实跑。

| C8 判定分布（脚本一） | 见证段 | C18 闭合等级（脚本二） | 见证段 |
| --- | --- | --- | --- |
| `判定分布 J1=0 J2=0 J3=0 J4=0` | R10、R11 | `闭合等级 Q1=0 Q2=0 Q3=0 Q4=0` | R31 |
| `判定分布 J1=0 J2=0 J3=0 J4=1` | R13—R17 五段 | `闭合等级 Q1=0 Q2=0 Q3=0 Q4=9` | R30、R33 |
| `判定分布 J1=0 J2=0 J3=0 J4=4` | R5、R12 | `闭合等级 Q1=0 Q2=1 Q3=0 Q4=0` | R22、R32 |
| `判定分布 J1=0 J2=1 J3=0 J4=0` | R18 | `闭合等级 Q1=0 Q2=1 Q3=1 Q4=1` | R21 |
| `判定分布 J1=0 J2=3 J3=0 J4=65` | R1、R6 | `闭合等级 Q1=0 Q2=27 Q3=10 Q4=19` | R23 |
| `判定分布 J1=0 J2=3 J3=1 J4=0` | R3 | `闭合等级 Q1=0 Q2=48 Q3=6 Q4=2` | R24 |
| `判定分布 J1=4 J2=0 J3=0 J4=0` | R2 | `闭合等级 Q1=0 Q2=49 Q3=5 Q4=2` | R19、R25 |
| `判定分布 J1=4 J2=6 J3=1 J4=65` | R4 | `闭合等级 Q1=9 Q2=0 Q3=0 Q4=0` | R20 |

这十六行里最要紧的是左列最后一行与右列第四行：前者证明 J1、J2、J3、J4 能在同一次实跑里同时出现，后者证明 Q 的三档不是互斥标签而是逐会话独立判定。两张分布表都是 `sort -u` 的结果，所以同一形状被多次跑出来时只显示一行——`J4=1` 那一行背后是五段，`Q4=9` 那一行背后是两段。

**退出码三种都出现过。** C9 是 `6 $ exit=0`、`10 $ exit=1`、`2 $ exit=2`（合计 18），C19 是 `3 $ exit=0`、`9 $ exit=1`、`3 $ exit=2`（合计 15），与 23.2 表里两列退出码的竖排计数逐数相等。三个值都非零缺席，说明「无阻断」的下界、「有阻断」的上界与「输入不可用」这条独立路径都被真跑过。

**一号两义排查。** C10 三行输出照抄：`形态族 C06：接口标识形态非法 / 服务端子点形态非法`、`参数化 S07：布尔位取值非法 / 枚举越界`、`信号码总数 71｜一号一判据 69｜形态族 1｜参数化 1｜一号多义 0`；C20 一行：`信号码总数 64｜一号一判据 64｜形态族 0｜参数化 0｜一号多义 0`。两处「一号多义 0」是这一节的收尾判据：脚本一被允许的两条例外都写明了理由——`C06` 属同一形态族的不同字段、`S07` 的判据文本按字段参数化；脚本二一条例外都不需要。

**两张表件的现场重数。** C21 与 C22 调的是同一个派生器，只差第四个参数（起始 R 号）：

| 调用 | 输出（逐字） |
| --- | --- |
| `perl FX/tbl-check.pl PART/tbl1.md tools/screen-egress-ledger-review.sh FX/run-log.txt 1` | `表内格 75｜脚本一定义码 75｜不一致 0｜表内未出现的码 []` |
| `perl FX/tbl-check.pl PART/tbl2.md tools/screen-egress-tripartite-diff.sh FX/run-log-tri.txt 19` | `表内格 64｜脚本一定义码 64｜不一致 0｜表内未出现的码 []` |

两行的第三格都是 `不一致 0`，第四格都是空清单，所以 23.4 那两张表的每一格——每一个首现 R 号与每一个累计数——都不是手抄的。

### 23.4 逐码首现表（两张）

表 1 覆盖脚本一：75 格，即 71 个信号码加 J1—J4 四行判定，按 13 个族排（A／B／C／D／E／G／K／N／O／R／S／V／X，判定行 J 插在 G 与 K 之间以保持字母序）。表 2 覆盖脚本二：64 格，即 60 个信号码加 Q1—Q4，按 9 个族排（C／D／K／M／P／S／T／V／X）。两张表同形：每格三个数——码、首现、累计。「首现」是 23.2 那套 R 号，不是脚本认识的标签；「累计」与 C6／C16 串里同码的那个数逐字相等。凡加粗的格，都表示该码首次出现的位置晚于该表的起跑段（表 1 从 R1 起、表 2 从 R19 起），加粗与否由 `tbl-check.pl` 判定，不由本文手写。

| 码 | 首现 | 累计 | 码 | 首现 | 累计 | 码 | 首现 | 累计 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `A01` | R1 | 3 | `A02` | R1 | 3 | `A03` | R1 | 5 |
| `A04` | R1 | 5 | `A05` | **R3** | 2 | `A06` | R1 | 3 |
| `B01` | R1 | 16 | `B02` | R1 | 3 | `B03` | R1 | 3 |
| `B04` | R1 | 13 | `B05` | R1 | 4 | `B06` | R1 | 13 |
| `C01` | R1 | 34 | `C02` | R1 | 3 | `C03` | R1 | 3 |
| `C04` | R1 | 3 | `C05` | R1 | 3 | `C06` | R1 | 8 |
| `C07` | **R3** | 2 | `C08` | R1 | 66 | `C09` | R1 | 3 |
| `D01` | R1 | 48 | `D02` | R1 | 3 | `D03` | **R3** | 2 |
| `D04` | R1 | 3 | `D05` | R1 | 3 | `D06` | R1 | 3 |
| `E01` | R1 | 35 | `E02` | R1 | 3 | `E03` | R1 | 3 |
| `E04` | R1 | 6 | `E05` | R1 | 3 | `G01` | R1 | 6 |
| `G02` | R1 | 3 | `G03` | R1 | 3 | `G04` | R1 | 3 |
| `G05` | R1 | 4 | `J1` | **R2** | 8 | `J2` | R1 | 13 |
| `J3` | **R3** | 2 | `J4` | R1 | 143 | `K01` | R1 | 4 |
| `K02` | R1 | 18 | `K03` | R1 | 5 | `N01` | R1 | 35 |
| `N02` | R1 | 5 | `N03` | R1 | 3 | `N04` | R1 | 3 |
| `N05` | R1 | 3 | `O01` | R1 | 3 | `O02` | R1 | 188 |
| `O03` | R1 | 3 | `O04` | R1 | 5 | `R01` | R1 | 3 |
| `R02` | R1 | 4 | `R03` | R1 | 6 | `R04` | **R3** | 2 |
| `R05` | R1 | 5 | `R06` | R1 | 4 | `R07` | R1 | 3 |
| `S01` | R1 | 4 | `S02` | R1 | 4 | `S03` | R1 | 255 |
| `S04` | R1 | 7 | `S05` | R1 | 5 | `S06` | R1 | 3 |
| `S07` | R1 | 13 | `S08` | R1 | 7 | `S09` | R1 | 666 |
| `V01` | R1 | 3 | `V02` | R1 | 3 | `V03` | R1 | 3 |
| `V04` | R1 | 3 | `X01` | R1 | 12 | `X02` | R1 | 4 |

表 1 里有六个加粗格，四件事需要说明。第一，`A05`／`C07`／`D03`／`R04` 四个码的首现是 **R3**（mid 档）而不是 R1：R1 那份逐码构造件覆盖了 67 个码，这四个非阻断侧的号要靠 mid 档那四条会话才打到，67 加 4 正好是 C1 的 71，这条等式与 C5 的空清单是同一件事的两种写法。第二，`J1` 的首现是 **R2**（合格档），因为 R1 那份触发件里没有干净会话；`J3` 的首现是 **R3**。第三，`J1` 累计 8、`J4` 累计 143 这两个数与 C16 那种大数同源，也是逐会话计数，不要按「八次实跑」去理解。第四，未加粗的 69 格首现都是 R1，这只说明 R1 那一次喂得最满，不说明其它段是冗余的——R2 到 R18 各自钉住的是下界、参数校验与结构性小样本，见 23.2 的族列。

| 码 | 首现 | 累计 | 码 | 首现 | 累计 | 码 | 首现 | 累计 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `C01` | **R23** | 1 | `C02` | **R23** | 1 | `C03` | **R23** | 1 |
| `C04` | **R23** | 1 | `C05` | **R23** | 5 | `D01` | R19 | 3 |
| `D02` | R19 | 2065 | `D03` | R19 | 9 | `D04` | R19 | 26 |
| `D05` | R19 | 101 | `K01` | R19 | 3 | `K02` | R19 | 4 |
| `K03` | R19 | 3 | `K04` | R19 | 3 | `K05` | R19 | 3 |
| `M01` | R19 | 4 | `M02` | R19 | 6 | `M03` | R19 | 9 |
| `M04` | R19 | 4 | `M05` | R19 | 22 | `M06` | R19 | 6 |
| `P01` | R19 | 3 | `P02` | R19 | 3 | `P03` | R19 | 4 |
| `P04` | R19 | 4 | `P05` | R19 | 15 | `P06` | R19 | 3 |
| `P07` | R19 | 6 | `Q1` | **R20** | 9 | `Q2` | R19 | 127 |
| `Q3` | R19 | 22 | `Q4` | R19 | 42 | `S01` | R19 | 4 |
| `S02` | R19 | 4 | `S03` | R19 | 4 | `S04` | R19 | 4 |
| `S05` | R19 | 4 | `S06` | R19 | 4 | `S07` | R19 | 16 |
| `S08` | R19 | 366 | `S09` | R19 | 8 | `S10` | R19 | 4 |
| `T01` | R19 | 78 | `T02` | R19 | 125 | `T03` | R19 | 4 |
| `T04` | R19 | 13 | `T05` | R19 | 4 | `T06` | R19 | 9 |
| `T07` | R19 | 4 | `T08` | R19 | 115 | `V01` | R19 | 4 |
| `V02` | R19 | 56 | `V03` | R19 | 4 | `V04` | R19 | 3 |
| `V05` | R19 | 4 | `V06` | R19 | 3 | `X01` | R19 | 3 |
| `X02` | R19 | 4 | `X03` | R19 | 2 | `X04` | R19 | 4 |
| `X05` | R19 | 2 | `X06` | R19 | 2 | `X07` | R19 | 9 |
| `X08` | **R24** | 6 |  | |  |  | |  |

表 2 里六个加粗格分三组。`C01`—`C05` 五条首现 **R23**（畸形能力表），累计分别 `1/1/1/1/5`，是整张表最薄的一族：能力表自身的五种畸形各只在畸形件里出现一次，其中 `C05`（整表无有效行）另在 R30 与 R33 各出现一次，所以是 5 而非 1。`Q1` 首现 **R20**（合格档，累计 9 会话），与表 1 的 `J1` 同理。`X08` 首现 **R24**（畸形词表），累计 6。族内最薄的三个号 `X03`／`X05`／`X06` 各累计 2（见 C17 与 C16），它们的构造过程踩过坑，写在 23.6 末段。表 2 最后一行只有 `X08` 一格，其余两格为空，是 64 除以 3 除不尽的排版余数，不是漏码——C22 的「表内格 64」按码数而不是按格位统计。

### 23.5 判定与退出码可达

可达性小结四句。其一，139 个号（脚本一 71 个信号码加 4 个判定、脚本二 60 个信号码加 4 个闭合等级）在 33 次实跑里全部至少触发一次，两个未触发清单与两个未定义命中清单都是空（C5、C15）。其二，J1—J4 与 Q1—Q4 都各自可达，且 J 的四档在 R4 同框、Q 的三档在 R21 同框（C8、C18）。其三，退出码 0、1、2 在两支脚本上都出现过（C9、C19），其中 2 全部来自参数与输入校验路径。其四，两侧下界都跑到了：脚本一 good 档四会话全 J1、零信号行、退出码 0；脚本二 good 档九会话全 Q1、零阻断、退出码 0，mid 档 Q2、Q3、Q4 各 1。

有一个形态要说清楚，免得读者按「判定即退出码」去读日志。脚本一是在逐会话循环里给每个会话定 J1—J4 的，而退出码不是从判定推出来的：会话循环收尾打印完判定行之后，程序才在末尾对阻断位做枚举累加（`for (c in cnt) if (c in HB) blocked += cnt[c]`），再由 `exit (blocked > 0 ? 1 : 0)` 决定退出码。也就是说，判定在前、阻断位统计在后，两者之间没有回环。因此存在这种合法组合：某会话已经定为 J1（它自己一条信号都没有）或 J3（只有非阻断信号），但同一次实跑里另一个会话带着阻断信号，进程仍以退出码 1 收束。R4 那次就是见证——判定分布 `J1=4 J2=6 J3=1 J4=65`，`$ exit=1`。这不矛盾，但读日志时要按「先看每档判定行，再看末尾的阻断计数，最后看退出码」这个顺序，不能拿退出码去反推单个会话的档位。脚本二没有这个错位，它的闭合等级与退出码都由同一套阻断／非阻断清单直接驱动。

另一个要说明的是未建模的会话类。脚本二的能力表只登记十类会话，`FX/tri-19-mid.txt` 与 `FX/tri-19-bad.txt` 里各留了一条不在其中的类名（`UNK_C` 用 `unknown`，`NA_D4` 用 `not_recorded`），用来证明「能力表没有这一行」这条路径本身可达。这两类只从族名之外的两条通用检查里得到读数：`D04`（会话类未建模）与闭合等级 `Q4`（可得性无法判定）；所有依赖能力表的逐值判据（K／M／P／V／X 那几条）都不会在它们身上跑，因为无行可查。`UNK_C` 另外多出一条 `T01`，因为它登记了采集件而没有落点件与告知件，那条检查不看能力表。

### 23.6 静态反向对齐与一号两义排查

反向对齐问的是：源码里每一条信号的出处，有多少真的落得到公开归档。数法是把 `DOC["…"]` 赋值整行取出来，看文本里有没有形如 `A/xxx.txt`、`B/xxx.txt`、`C/xxx.tsv` 的归档引用。

| 脚本 | DOC 行 | 含归档出处 | 自引用 | 归档提及次数 | 不同归档 |
| --- | --- | --- | --- | --- | --- |
| 脚本一（71 个号） | 71 | 55 | 16 | 68 | 16 |
| 脚本二（64 个号） | 64 | 55 | 9 | 68 | 11 |

16 条与 9 条自引用必须逐条列出而不是笼统承认，它们是：脚本一 `B05`、`D04`、`N03`、`X01`、`X02`、`S01`、`S02`、`S03`、`S04`、`S05`、`S06`、`S07`、`S09`、`K01`、`K02`、`K03`；脚本二 `S01`、`S06`、`S07`、`C01`、`K01`、`K02`、`P01`、`V01`、`V03`。这三种自引用都各有理由：S 族与 `B05`、`C01`、`P01` 引的是 usage 文本自己的行格式或清单（格式类判据的出处只能是格式声明本身）；`D04`、`N03`、`X01`、`K03`、`V03`、`C01` 引的是本文第 3.4 节与本层方法论章节的结论；`K01`、`K02` 引的是脚本头部注释的拒收声明。

把同一件事按族摊开，就能看出锚点集中在哪儿。「有锚点」指该码的 `DOC` 文本里至少有一条归档引用，分母是族内码数。

| 脚本一族 | 有锚点／码数 | 脚本二族 | 有锚点／码数 |
| --- | --- | --- | --- |
| `A01`—`A06` | 6／6 | `C01`—`C05` | 4／5 |
| `B01`—`B06` | 5／6 | `D01`—`D05` | 5／5 |
| `C01`—`C09` | 9／9 | `K01`—`K05` | 3／5 |
| `D01`—`D06` | 5／6 | `M01`—`M06` | 6／6 |
| `E01`—`E05` | 5／5 | `P01`—`P07` | 6／7 |
| `G01`—`G05` | 5／5 | `Q1`—`Q4` | 4／4 |
| `K01`—`K03` | 0／3 | `S01`—`S10` | 7／10 |
| `N01`—`N05` | 4／5 | `T01`—`T08` | 8／8 |
| `O01`—`O04` | 4／4 | `V01`—`V06` | 4／6 |
| `R01`—`R07` | 7／7 | `X01`—`X08` | 8／8 |
| `S01`—`S09` | 1／9 | 合计 | 55／64 |
| `V01`—`V04` | 4／4 | | |
| `X01`—`X02` | 0／2 | | |
| 合计 | 55／71 | | |

按族看，脚本一的 13 个族里 K 族与 X 族完全没有归档锚点（`K01`—`K03` 全部指向头部声明，`X01`／`X02` 指向本文与 usage），其余 11 个族都至少有一条归档锚点，最薄的 S 族 9 条里只有 `S08` 一条引到 `C/kev-apple.tsv` 的表头日期形态；脚本二的 9 个信号族加 Q 族十族全部有归档锚点，最薄的是 `K01`—`K05` 的 3／5 与 `V01`—`V06` 的 4／6。这张表也是本章的一处限制：K 与 X 两族的判据本质上不依赖公开归档，靠 grep 数不出问题，只能靠读者判断这三条拒收声明与本文第 3.4 节是否可回指。

夹具侧的锚点落在另一层。三份台账夹具（`ledger-19-good／mid／bad`）的取值列提到归档时只写文件名，一共 63 次提及、覆盖 11 个不同文件，一次都没有带行号；行号在脚本的 `DOC` 文本里补齐。脚本二的公开词表反过来：`FX/vocab-19.tsv` 91 行里除表头与三行注释外的 87 行，第三列一律写成 `文件:行号`，覆盖 13 个不同归档——台账类输入靠脚本给行号，词表类输入靠输入自带行号，两条回落路径不混用。

两份表件的重数调用只差两个参数，写在这里方便直接复制：

```console
perl FX/tbl-check.pl PART/tbl1.md tools/screen-egress-ledger-review.sh FX/run-log.txt 1
perl FX/tbl-check.pl PART/tbl2.md tools/screen-egress-tripartite-diff.sh FX/run-log-tri.txt 19
```

第一个参数是表件、第二个是脚本源码、第三份是留档、第四个是起始 R 号（表 1 传 1、表 2 传 19）。这两条就是 23.3 的 C21 与 C22，各自报 `不一致 0` 与空清单；起始 R 号决定加粗与否，改这个数会改变表里哪些格加粗，但不会改变累计列。

两份留档的可重跑性用同一种比对法。`bash FX/coverage-report.sh > /tmp/cov19.txt 2>&1` 与 `bash FX/readonly-proof.sh > /tmp/ro19.txt 2>&1`，再分别 `diff /tmp/cov19.txt FX/coverage-proof.txt`、`diff /tmp/ro19.txt FX/readonly-proof.txt`，期望都没有输出。这两份 harness 不读时钟、不排序随机数、也不带版本号，所以差异只可能来自脚本或夹具被改过；本文没有重跑它们，第 23 章通篇是留档的转录，比对留给读者。

本轮真正踩到的坑有七处，都写在这里而不是略过。第一，`X03`／`X05`／`X06` 三个号一度不可达：三条构造行原本挂在能力表里没有的会话类上，于是只得到 `D04` 与 `Q4`，逐值判据根本没跑；改成 `system_service` 类后三个号各出 2 次（C16）。第二，数组型核对项 `landing_destination` 让合格档虚报 `M05` 与 `V02`：一行多值时必须把取值切开后逐值判定，整串比对会把合法的多落点当成未知取值；改完虚报消失，`V02` 的 56 次全落在该逐值判定真正该落的地方。第三，反向判据需要专门的子语表：`FX/vocab-19-subset.tsv` 是在 91 行的正式词表后加一行 `advisory_component_crafted → GraphicServices`，`GraphicServices` 不在 129 个真实组件名里，`X01` 才有的可反指；只喂正式词表时这一族是哑的。第四，引用格的形态规则卡过一次：`X02` 只认 `1234` 或 `6-9` 这一种行号写法，带「第／行」前缀或把别名塞进括号里的写法一律判非法，而同一条判据在两份台账之间不能各写各的；把出处写成「裸文件加行号、注记另起一句」之后，23.6 的锚点统计才与留档一致。第五，关键表分母口径：`B/mdm-restriction-keys.txt` 那份归档有四种可数口径——总行 220、行形态命中的 218、首字母小写的 216、以及排除 8 行非键名之后的纯键名分母 210。第 16 章那组公开读数用的是 210，而脚本里按形态筛出来的是 216 与 218，两边对不上时先查分母口径再查逻辑；本章不重做这个数，只提醒一句：行首大写这条粗筛只能拿到 4 行标题（`Device Management`、`Important`、`Mac Catalyst`、`Note`），它与「非键名 8 行」不是同一个口径，余下四行要靠第 16 章那条键名形态规则才筛得出来。第六，`tbl-check.pl` 的输出标签在脚本二那一段仍照打「脚本一定义码」——那是派生器里硬编码的措辞，C22 那行的数字口径是对的（64 对 64、不一致 0），但读者若只看标签会误以为比对跑错了脚本。第七，脚本一 usage 第 131 行举例引用形态时写的是 `A/quicklook.txt:16`，而本归档 `A/` 下的 15 个文件里没有 `quicklook.txt`（那是第 18 篇的归档名）；这一处只是示例性文字，不构成可回指锚点，23.6 上面的 16 个不同归档里也没有它，读者照那个例子去找会落空。

### 复算入口

六个入口，按「单跑一支脚本、重跑一份留档」的顺序排列：

```console
bash tools/screen-egress-ledger-review.sh FX/ledger-19-good.txt
bash tools/screen-egress-tripartite-diff.sh FX/tri-19-good.txt FX/capability-19.csv FX/vocab-19.tsv
bash FX/run-all.sh
bash FX/run-all-tri.sh
bash FX/coverage-report.sh
bash FX/readonly-proof.sh
```

第二行的三份输入必须按「清单、能力表、公开词表」的顺序给全，只给一份或两份都会走 `exit=2` 那条路径，这是参数校验而不是判定失败。这一章不写出任何被登记对象，上面六条命令读的东西也只在 `.srcx19` 目录之内：两支脚本读台账与两张表，两份 harness 读脚本源码与夹具，三个派生器读留档；临时目录建在 `${TMPDIR:-/tmp}` 下、前缀 `scr19.` 或 `sct19.`，退出即删，P8 与 P18 已现场查过无残留。

## 24. 十二个误区

以下十二条是把第 3—23 章的读数压回成一句话时最容易压错的形状。每条给出**误区表述 → 依据读数 → 正确表述**，依据只用本篇归档件里的行锚、第 23.2 节那三十三次实跑的留档与第 23.4 节两张表的累计数，不引入新事实。前八条与第 3.4 节那八处换算失败一一对应——这不是省事，那八处失败本来就是「两格被压成一格」的八个具体形态；后四条压的是失败点之外的四个惯性读法（触发时点、实测冲动、退出码语义、边界清单的用途）。累计数一律逐字取自 23.4 那两张表，判据文案一律逐字取自两支脚本的 `emit()` 与 `DOC["…"]` 赋值，读者拿同一份留档可以逐条复算。

**误区 1：框架句写了「用户可以录屏并分享」，所以这一帧画面被那个 App 进程拿到了。**
依据：`A/replaykit.txt:5` 确实把录与发写进同一句——`Using the ReplayKit framework, users can record video from the screen, and audio from the app and microphone.`，同句后半是 `They can then share their recordings with other users through email, messages, and social media.`；`A/replaykit_rpscreenrecorder.txt:12` 也写了 `Your app can record the audio and video inside of the app, along with user commentary through the microphone.`。但 `B/apple-platform-security-guide.txt:4242` 说的是另一条通道：`Screen and audio capture occurs out of the app’s process in the ReplayKit daemon replayd.`，紧接一句 `This is designed to ensure the recorded content is never accessible to the app process.`；`:4250` 又写 `The architecture helps ensure that hosting apps have no privileges to the broadcasted video and audio contents.`。台账侧：脚本一 `C01`（判据逐字「画面外流通道件缺失：⟨会话类⟩」，累计 34）、`C03`（「出进程采集却称 App 进程读得到画面内容」，3）、`C04`（「App 内取样通道却称内容永不被 App 访问」，3）；脚本二 `S09`（「同项两口径」，8）、`K03`（「采集归属不成立：⟨会话类⟩ 的画面按公开口径在 App 进程之外取出，不能把归属记成 App 进程内」，3）。
正确表述：**框架句的主语是 users，不是 app process；一句公开文档只能确定这一格存在，不能确定归属落在哪个进程。**`chan.egress_path` 的九条出流路径——`out_of_process_capture`、`in_app_sample_buffer`、`broadcast_upload`、`mirroring_local`、`airplay_stream`、`carplay_template_stream`、`external_display_stream`、`classroom_observation`、`still_capture`——必须逐条指名，而 `:4242` 与 `:4243` 是两条互斥通道：九条里只有 `in_app_sample_buffer` 一条允许把内容归属记到 App 进程，其余八条都不允许。

**误区 2：同意提示呈现过，所以提示的粒度就是这一次会话的粒度。**
依据：`B/apple-platform-security-guide.txt:4241` 的公开口径只有一句频次读数——`Before recording starts, ReplayKit presents a user consent alert requesting that the user acknowledge their intent to record the screen, the microphone, and the front camera.` 与 `This alert is presented once per app process,`；`consent.alert_scope` 枚举里的 `per_session`／`per_device`／`per_stream` 全是登记方自行加严或放宽，脚本一 `A03` 的判据逐字就是「提示范围偏离公开口径：⟨取值⟩」（累计 5）。顺序也不可颠倒：`A02`「同意来源记成用户提示但提示位登记为未出现」（3）拦的是把提示与采集的先后写反的登记。脚本二侧同一件事落在 `D02`（「会话类 ⟨…⟩ 的 required 核对项 ⟨…⟩ 在本会话完全没有登记行」，累计 2065，是两张表里最大的一个数）。
正确表述：**「提示按 App 进程各一次」是频次读数，不是会话粒度读数。**把 `consent.alert_shown=yes` 写成这一次会话级授权需要另一句公开口径，而本篇归档里没有那一句；`per_session` 这类值可以登记，但它只能作为登记方的加严声明，不能作为对外表述的依据。

**误区 3：这一帧被录下来了，所以落点已定、复位也已完成。**
依据：三件法把这一句拆成三件——采集件 7 项（`capture_entry entry_status process_owner concurrent_limit isolation_mechanism preview_surface share_surface`）、落点件 5 项（`egress_path landing_destination write_scope stored_object mac_randomized`）、告知件 8 项（`prompt_shown banner_kind lockscreen_visible indicator_visible origin_disclosed pairing_verified persist_after_share reset_method`），合计 20 项核对项。`A/replaykit_rpscreenrecorder.txt` 的 `:240`、`:251`、`:267` 三个停止口里只有第三个在签名里出现输出 URL，`:88` 的 `Discards the current recording.` 是第四个独立复位口；`B/apple-platform-security-guide.txt:4244` 又写 `The movie file is written to a directory that’s only accessible to the ReplayKit subsystems and is never accessible to any apps.`。实测侧：脚本一 `E01`（「画面外流落点缺失：⟨会话类⟩」，累计 35）、`V01`（3）、`V02`（3）、`V04`（3）；脚本二 `M05`（「落点形态非法：…」，22）、`P04`（「平面越界：复位口记在采集面…」，4）。
正确表述：**「录到了」只闭合采集件那七项；落点件五项与告知件八项要各自有读数。**三件不成对在脚本二里是 `T01`（「三件不成对：⟨n⟩ 格采集件已读数但落点件与告知件一条都没有」，累计 78）与 `T02`（125）两条**非阻断**码，只把会话推到 Q3 而不改退出码——差集没对完这件事在退出码上是看不见的，R32 那一次只登记一项时打出的正是 `D05`＋`D02`＋`T01`＋`T08`。

**误区 4：广播走通了，所以承载方、端点与特权都如登记所述。**
依据：`B/apple-platform-security-guide.txt:4249` 要求第三方服务建两个扩展挂在同一端点上，`:4248` 说广播期采集与影片录制完全一致，`:4257` 说扩展拿到的是 `raw unencoded sample buffers`；`A/replaykit_rpbroadcastconfiguration.txt:3` 则写明直播同时另产影片件——`An object used to configure the movie clips produced during a live broadcast.`。扩展数量、端子点、缓冲形态是三格（`chan.extension_count`／`chan.service_endpoint`／`chan.buffer_form`），缺一即无法回指。台账侧：脚本一 `C05`（「广播通道件缺失：扩展数量、服务端子点或缓冲形态未登记」，3）、`D01`（「执行域类别未登记」，48）、`E05`（「存储对象为直播影片片段但会话不是直播」，3）；脚本二 `C05`（5，首现 R23）、`S08`（「数组型重复登记：…」，366，其中 358 条来自 R33 那一次三份输入指向同一份清单）、`T08`（「对外表述缺必需格：…」，115）。
正确表述：**「广播可用」是能力表的一行，不是这一条会话的三格读数。**落点是数组型核对项（`landing_destination`，唯一一项可多行），多个落点并进同一格后逐值判定，所以同一格可以同时出三条不同族的信号；把重复行列成第二落点会被 `S08` 判成重复登记而不是覆盖面。

**误区 5：某个平面读得回这一格，所以这一格与另一个平面同轴。**
依据：`B/apple-platform-security-guide.txt:1429` 的锁屏通知读不出执行域；`A/carplay_cpinterfacecontroller.txt:26` 写 `The trait collection of the vehicle’s primary screen.`——车机模板读不出 App 内提示；`A/uikit_uiwindow.txt:18` 说额外窗口通常用于在外屏显示内容，外屏面与本机面是两个平面；`:2262` 的 macOS 权限清单给出的是允许与否，不给出画面落到哪儿。台账侧：脚本一 `O01`（「锁屏通知面读不出执行域」，3）、`O02`（「有观测平面却未登记读数时刻」，累计 188）、`O03`（「只靠自述平面给出确认结论」，3）、`D06`（「画面由 replayd 取出但执行域记成 App 沙箱内」，3）；脚本二 `P01`（3）、`P02`（3）、`P05`（15）、`P07`（6）。
正确表述：**26 个读数平面与 20 项核对项之间是脚本里按公开口径写死的 31 组配对，配对之外的一律是越界读数。**P 族七个码全为非阻断码，所以第 20 章 O6 这条不达标时退出码仍可能是 0；「这一面读不回」不等于「这一格不存在」，也写不成「该平面不存在」，只能写成这一格在本篇无从判定。

**误区 6：来源是截屏或厂商说法，所以它可以充当机制依据。**
依据：`dom.domain_source` 与 `notice.warning_text_source` 两个枚举都收 `vendor_claim`／`screenshot`／`assumed` 三档，`obs.plane` 那一侧的对应值是 `vendor_claim` 与 `app_self_report`；四处都只把它们当**存在性**取值，没有一处把它们当判定依据。`A/replaykit_rpsystembroadcastpickerview.txt:12` 是最好的反例：`Clicking the broadcast button has no effect in Mac apps built with Mac Catalyst.`——某一个形态下读不回，不等于机制不存在。台账侧：脚本一 `D04`（「执行域结论只来自厂商说法、截屏或假定：⟨取值⟩」，3）、`N03`（「告知文本依据是截屏或假定：⟨取值⟩」，3）、`K03`（「观测引用不是报告标识形态」，5）；脚本二 `V03`（「复位只靠自述：复位口只由 ⟨平面⟩ 给出，其自述不独立构成观测」，4）。
正确表述：**这三档能证明「那一天这一面显示过什么」，不能证明「机制如何运转」。**第 20 章 O9 与 O10 的分子都把这三档排除在可对外表述之外；反过来把平台文档与 App 自述并排引用却不说明冲突处理，同样给不出机制结论。

**误区 7：管理面命中画面语义词的键有 13 个，所以 13 个键都约束画面出流。**
依据：`C/readings-19.txt:92` 的 13 个键里 5 个是同词不同义（`:96—100`：`allowAutomaticScreenSaver`、`allowCallRecording` 与 `allowLockScreenControlCenter`／`allowLockScreenNotificationsView`／`allowLockScreenTodayView`），分母链是读数 R19 表内 220 行 → R20 形态命中 218 → R22 非键名 8 行、纯键名 210 → R23 画面语义词命中 13 → R24 `allow*` 9 个／`force*` 4 个。`B/mdm-restrictions.txt:766` 是一个键同时关掉三类出流的活例（`the system disables saving a screenshot of the display and capturing a screen recording.` 同句还连带 Classroom 远屏观察）；`:726` 要求把子约束键嵌在指定 payload 下；`:1018` 说明受管理课程里的学生「automatically gives permission to that course teacher’s requests to observe the student’s screen without prompting the student」。`forceBypassScreenCaptureAlert` 在 `C/readings-19.txt:106` 里只登记存在形态，本篇不指导如何使用或规避它。台账侧：脚本一 `G01`（6）、`G02`（「该键命中词形但不约束画面离开设备」，3）、`G03`（3）、`G05`（「限制键形态非法」，4）；脚本二 `M03`（9）、`X04`（4）、`K05`（「提示绕过键进入通道件」，3）、`P06`（3）。
正确表述：**关掉承载通道、给出同意、让某一格可被策略配置，是三件事。**`mgmt.word_family` 里 `lockscreen_surface`／`screensaver`／`call_recording` 三档就是为了把那五个键挡在 `egress_control` 之外而设的；管理面对某条出流通道「可配」不等于该通道「已受控」，写后者需要的是键的粒度证据，而这份证据在 210 个纯键名的清单里不存在。

**误区 8：口径之间可以互相换算，所以结论可以写成一句而不必回指。**
依据：`C/readings-19.txt:27—28` 给出子集的平台分布 macOS 31 行、iOS 4 行（读数 R08），`:28` 另给其余平台 5 行（读数 R09）；`:45`（读数 R10）演示一条假读数怎么产生——原样匹配大写 `VNC` 得 6、整列小写化后仍用大写模式得 0、小写化＋小写模式得 6；`:56`、`:57`（读数 R13／R14）给出含 `maliciously crafted` 的 467 行里同时出现画面语义词的 0 行、crafted 行里组件名含 `screen` 的 0 个。台账侧：脚本一 `R01`（3）、`R03`（「组件名不属本层却用于确认结论」，6）、`R04`（「词形为 screen 但组件不在含 screen 的四个组件内且未核对」，2，首现 R3）、`R05`（「词形命中未核对大小写匹配形态（假读数风险）」，5）、`X01`（「确认结论缺来源文件或行号」，12）、`X02`（「行号引用形态非法」，4，R14 集中喂出）；脚本二 `X01`（3）、`X02`（4）、`V01`（4）、`V02`（「引用回指悬空」，56）。
正确表述：**任何跨套结论都要落到「哪一次会话、哪一格、取自哪份归档的哪一行」，且行号只认 `1234` 或 `6-9` 这一种形态。**本篇公告侧读数一律带平台行标注：画面外流子集里 iOS 平台行只有 4 行，所以没有任何一条公告读数可以被写成 iOS 侧结论；命中数一律带匹配形态，因为读数 R10 已经演示过假读数是怎么造出来的。

**误区 9：公告里没写需要用户动作，所以画面是在没有动作的情况下流出去的。**
依据：这是一条**结构性负读数**，也是本篇的硬写作约束。`C/readings-19.txt:160—169`：读数 R32 平台安全指南里出现免交互措辞的只有 2 行，逐行是第 1442 行 BlastDoor 与第 4681 行 device management service 词条，都不在任何画面通道上；R33 公告 impact 列含 `without user interaction` 或 `without user consent` 的 10 行、R34 含 `without user permission` 的 8 行；R35 按组件分布是 CoreMedia 5、WindowServer 3、AccessorySetupKit 2；R36 落在画面外流六组件子集内的只有 3 行、同一个 `CVE-2026-112575`，影响句逐字为 `An app may be able to monitor keystrokes without user permission`（`:167—169`），三行全是 macOS 平台行。台账侧：脚本一 `A02`（3）钉住「提示在前、采集在后」，`N01`（「画面确已离开设备但告知位未登记：⟨会话类⟩」，累计 35）、`N02`（5）、`N05`（「画面离开设备但无提示、无来源披露且无任何说明句」，3）；脚本二 `T08`（115）与 `V04`（3）。
正确表述：**本篇对出流时点的表述只允许两种形态：「打开／预览／分享这三类动作之后」或「录制／镜像／投屏这三类会话建立之后」。**脚本二 `外流时点` 那一列的取值（`on_start`、`on_session`、`on_share`、`on_stop`、`on_reboot`、`per_stream` 加 `not_recorded`／`unknown` 两个控制值）只能由登记侧的动作与会话给出，不能由公告侧的沉默推出——「公告没写」只说明这一列不记载这件事，不说明这件事没有发生，也不说明它不需要动作。

**误区 10：拿设备实测一下最直接——跑一次 `mdls` 或 `file` 就知道这一帧走没走出去。**
依据：这是方法论越界，不是结论分歧。第 23.1 节 P1 与 P11 用系统调用型模式在两支脚本的 awk 程序体里都得到空匹配（以 grep 自己的退出码 1 表达）；P4 在脚本一里只命中第 9 行那一行头部拒收声明，P14 在脚本二里命中第 13 行声明与第 469 行 `K02` 拒收正则两行，两侧合起来这三行都是声明或正则字面量而不是命令；P4c 用同一条「命令位置」规则的阳性对照得命中数 2，P4d 与 P14b 两条阴性都是空匹配；P6 与 P16 的外部命令普查分别是 `awk=1 tr=3 cat=1 mktemp=3 rm=1` 与 `awk=1 cat=1 mktemp=2 rm=1`，`perl`／`python`／`node` 三行缺席。拒收侧的码：脚本一 `K01`（「sec.* 拒收空间出现字段：⟨字段名⟩」，累计 4，四次分散在 R1、R4、R6 与 R12 那段行格式畸形里）、`K02`（「取值形似设备路径／长载荷／密钥串，拒收」，18，其中 R16 那一次拒收形态夹具独占 3 条）、`K03`（5）；脚本二 `K01`（「登记越界：…形似密钥、口令、归档文件、设备绝对路径或整段画面载荷」，3）、`K02`（4，出处文案逐字是「见本脚本头部注释的拒收声明：设备侧命令行工具不作为任何一格的读数来源」）。
正确表述：**本篇全部结论必须是离线可复算的口径结论。**「这一帧确实被带走」在本篇不能表达为实测，只能表达为「采集件七项有读数、落点件五项有读数、告知件八项有读数，三件差集为空，且每个取值都落在能力表所声明的可得性档位内」这一间接三段。这条限制同时是第 26 章 N12 的正文：本文能保证判定过程可复算，不能保证登记内容与某台真实设备一致；把实测写进脚本，脚本就从台账审查器变成采集器，头部那句只读声明立刻作废。

**误区 11：脚本退出码 0，或者某个会话判到 J1／Q1，就说明这条出流链路没问题。**
依据：两支脚本的阻断清单长度不同。脚本一阻断集只有 12 个码（`S01—S09` 加 `K01 K02 K03`，源码第 240—241 行写死），其余 59 码全为非阻断，命中再多也只把会话推到 J2／J3 而不出 J4——R3 那一次 `判定分布 J1=0 J2=3 J3=1 J4=0` 配 `exit=0` 就是这个形状。脚本二阻断号 **42 个**（`S01—S10`、`C01—C05`、`K01—K05`、`M01—M06`、`T03—T08`、`X01—X08`、`V02`、`V06`）出现即落 Q2 且进程以退出码 1 收束；非阻断 **18 个**（`D01—D05`、`P01—P07`、`T01`、`T02`、`V01`、`V03`、`V04`、`V05`）只落 Q3 而退出码仍 0，usage 第 92 行逐字写着「覆盖空洞、平面越界与三件不成对不计入阻断，只落 Q3（此时退出码仍为 0）」。四种给出 0 的合法形状都在留档里：实跑 R10（空文件）与 R11（只有注释与空行）是零会话、退出码 0；R18 把四格写成 `not_determinable`／`absent` 这类合法哨兵值，只留一条 `B01` 落 J2；R31 空清单打 20 条非阻断 `D05`（累计 101）而退出码仍是 0；R20 是九会话全 Q1 的下界而不是达标。还有一个顺序事实必须写出：脚本一在逐会话循环里先把 J1—J4 打完（第 468—472 行），到末尾才对阻断位做累加（第 478 行 `for (c in cnt) if (c in HB) blocked += cnt[c]`）并由第 488 行决定退出码，所以存在「会话已定 J1／J3 而进程仍以退出码 1 收束」的组合，R4 那一次 `判定分布 J1=4 J2=6 J3=1 J4=65` 配 `$ exit=1` 就是见证；脚本二同构——等级在第 561—564 行发出，之后第 568 行起还有一轮对全部已登记布尔位的补检（补出的 `S07` 与非统一口径 `V05`，累计 4）都不回溯已发的档位。
正确表述：**退出码只跟随阻断族，不表达任何正向结论。**使用时固定核对四格：会话数是否为 0、信号行数是否为 0、这个 0 是「下界」还是「无输入」、档位与退出码是否出自同一份输入。`exit 0` 不等于「这台设备的画面没有外流」，也不等于「已获授权」；两支脚本判的都是登记内容的自洽性，不是内容本身的安全性。

**误区 12：把第 26 章的边界清单当成台账的缺口，觉得补一格就闭合了。**
依据：会话类有 11 个且与会话标识前缀一一对应（`REC_` movie_recording、`BCA_` live_broadcast、`MIR_` mirroring、`CMP_` companion_display、`AIR_` airplay_video、`RMO_` remote_observation、`SCN_` system_screenshot、`SCK_` scscreen_capture、`SVC_` system_service，另加 `NA_` not_recorded 与 `UNK_` unknown 两个兜底类），而 `FX/capability-19.csv` 只有 180 条数据行 = 9 个建模类 × 20 项核对项，兜底两类按设计不进能力表。结构事实是：脚本二的逐值判定（K 族、M 族、`V02`、X 族全部写在第 440—547 行那个按能力表配对的循环里，第 442 行先 `if (c2 != kd) continue`）**只在能力表建模过的（会话类, 核对项）对上发生**，未建模类只得到 `D04`（「会话类未建模：…这一类的判据未建模，缺哪一格无从判定」，累计 26）与闭合等级 `Q4`（累计 42）。对照之下，`S09`（脚本一，「必备格缺失：⟨字段名⟩」，累计 666）查的是「该填的没填」、`D05`（脚本二，「核对项 ⟨…⟩ 在整张清单里零登记」，101）查的是「这一格全表没人登记」，两者都预设这一格在公开口径里存在。至于复位与再核对层在脚本二里没有独立核对项这一格，唯一反查落点是 `V05`（4，非阻断）。
正确表述：**边界清单不是待办清单。**未建模只意味着「判据未建模」，不能用来推断真实设备上是否存在某一类会话（第 20 章 O5 的这条限制）；把清单上的条目补成台账里的一行，制造出的是一条回指不到任何公开句子的信号，而 `D04` 与 `Q4` 存在的意义正是把这类缺口标成不可对外表述。

十二张形状对照如下，末列给出该误区在两支脚本里的落点与第 23.2 节实跑的段号；「累计」取自第 23.4 节两张表（脚本一为 71 个信号码加四档判定的 75 格，脚本二为 60 个信号码加四级闭合的 64 格）：

| 误区 | 压错的换算 | 层 | 主要信号码（累计） | 实证段 |
| --- | --- | --- | --- | --- |
| 1 | 框架句 → App 进程拿到画面 | L3／L4 | 一 `C01`(34)、`C03`(3)、`C04`(3)；二 `S09`(8)、`K03`(3) | R1、R4、R19 |
| 2 | 提示频次 → 会话粒度 | L2 | 一 `A02`(3)、`A03`(5)；二 `D02`(2065) | R1、R19 |
| 3 | 录到了 → 落点与复位已闭合 | L5／L8 | 一 `E01`(35)、`V01`(3)；二 `M05`(22)、`T01`(78) | R1、R19、R32 |
| 4 | 广播可用 → 三格齐全 | L3／L5 | 一 `C05`(3)、`D01`(48)、`E05`(3)；二 `C05`(5)、`S08`(366) | R1、R19、R23、R33 |
| 5 | 一面读得回 → 各面同轴 | L6 | 一 `O01`(3)、`O02`(188)、`D06`(3)；二 `P05`(15)、`P07`(6) | R1、R19 |
| 6 | 截屏／厂商说法 → 机制依据 | L6／L7 | 一 `D04`(3)、`N03`(3)、`K03`(5)；二 `V03`(4) | R1、R3、R19 |
| 7 | 命中 13 键 → 13 键管出流 | L9 | 一 `G01`(6)、`G02`(3)、`G05`(4)；二 `M03`(9)、`X04`(4)、`K05`(3) | R1、R19、R23、R24 |
| 8 | 跨套换算 → 一句结论 | L10／L11 | 一 `R03`(6)、`R05`(5)、`X01`(12)；二 `X02`(4)、`V02`(56) | R1、R3、R14、R19、R22 |
| 9 | 公告未写动作 → 无需动作 | L2／L7 | 一 `A02`(3)、`N01`(35)、`N05`(3)；二 `T08`(115)、`V04`(3) | R1、R19、R21、R32 |
| 10 | 实测 → 可证 | 全篇 | 一 `K01`(4)、`K02`(18)；二 `K01`(3)、`K02`(4) | R1、R12、R16、R19 |
| 11 | 退出码 0 → 没问题 | 全篇 | 一 `J1`(8)、`J4`(143)；二 `D05`(101)、`Q2`(127)、`V05`(4) | R2、R3、R4、R18、R20、R31 |
| 12 | 边界清单 → 待办清单 | 全篇 | 一 `S09`(666)；二 `D04`(26)、`Q4`(42) | R21、R23、R30、R33 |

末列之后还有一处值得单独看的覆盖强度差异，它比任何一句「覆盖充分」都更能说明这套验收的边界。**脚本一 71 个码里最薄的四个号累计恰为 2**：`A05`、`C07`、`D03`、`R04` 的首现都是 **R3**（mid 档），只被那四条会话各打到一次、再被 R4 的合并读入打到一次，C7 那五行读数逐字是 `2 A05`／`2 C07`／`2 D03`／`2 R04`／`3 A01`（`FX/coverage-proof.txt` 第 30—37 行）。**脚本二更窄：`C01`—`C04` 四个码累计各为 1，且只在畸形能力表 R23 那一段打印过**——它们校验的是能力表自身的行格式、会话类、核对项与可得性四个取值集合，只有把能力表本身喂畸形才可能命中；C17 五行是 `1 C01`／`1 C02`／`1 C03`／`1 C04`／`2 X03`，词表侧的 `X05`／`X06` 同样各为 2。实跑 R19 那一段（逐码构造件）只打到 54 个信号码，正好是 60 减 C 族五条减 `X08`，这两组只在实跑 R23 与 R24 出。改到这九个码的判据时，只有对应那一段日志会变色，其余各段毫无反应；这是本文当前覆盖强度的真实上限，不是笔误，也是第 23.3 节 C5 与 C15 那两个空清单之外唯一需要读者自己留意的缺口。

## 25. 常见问题

**问：这套台账与两支脚本必须跑在设备上吗？**
不。两支脚本都是纯文本、离线、只读：脚本一（`tools/screen-egress-ledger-review.sh`，490 行）收一份或多份三列会话台账，脚本二（`tools/screen-egress-tripartite-diff.sh`，614 行）固定收三份登记件——十列三件清单、三列能力表、三列公开词表。第 23.1 节那二十段检查是这件事的实证而不是一句声明，`P1—P10` 针对脚本一、`P11—P20` 针对脚本二，两半结构对称：P1 与 P11 在两支脚本的 awk 程序体里对系统调用型函数都是空匹配（`$ exit=1`）；P4 在脚本一里只命中第 9 行那一行头部拒收声明，P14 在脚本二里命中第 13 行声明与第 469 行 `K02` 拒收正则两行；P4d 与 P14b 用同一条「命令位置」规则扫全文都是空匹配，而 P4c 的阳性对照命中数 2——没有这个 2，两条空匹配既可能是脚本干净也可能是正则写坏了；P6 与 P16 的外部命令普查是 `awk=1 tr=3 cat=1 mktemp=3 rm=1` 与 `awk=1 cat=1 mktemp=2 rm=1`，`perl`／`python`／`node` 三行缺席；P2／P3 与 P12／P13 显示唯一写出目标是一处 `mktemp -d`（前缀 `scr19.` 与 `sct19.`），`TMPD` 只出现在赋值行与 `trap` 行；P8 与 P18 跑完夹具后按两种前缀查残留都是「无残留」；P9 与 P19 在两份 harness 里查不到 URL 与设备节点路径；P10 与 P20 把三十三次实跑的命令行归一化后只剩「脚本＋选项＋夹具」六种与五种形状。

要说清一处不对称：这二十段查的是「有没有能读别处的口子」，查不到「读到的内容是不是设备事实」。登记件由人填写，本文能保证判定过程离线可复算，不能保证某一格与某台真实设备一致——这一条写进第 26 章 N12，与第 24 章误区 10 是同一条限制的两面。

**问：两支脚本我该先跑哪一支？为什么不合并成一个分数？**
先脚本一。它逐会话检查十二个命名空间里该填的格填没填、填的形态合不合规，输出 `J1`—`J4`，回答「这一条登记能不能进入对外表述」；脚本二吃的是另一形状，输出 `Q1`—`Q4`，回答「三份登记对完之后归属还能不能立起来」。两者对同一现实的粒度也不同：脚本一只认四类会话前缀（usage 第 19 行 `REC_`／`BCA_`／`MIR_`／`CMP_`），脚本二把会话类扩到 11 个并与 11 个前缀一一对应（usage 第 28—31 行）。**绝不合并成单一分数**：合并会掩盖一件事——逐条登记越严谨，三件缺口越容易被看成已闭合。同一份合格夹具在两支脚本上给出的两个 0 也不是同一个东西：实跑 R2 打 `判定分布 J1=4 J2=0 J3=0 J4=0` 配 `exit=0`，说明四条登记自洽；实跑 R20 是九会话全 `Q1`、零信号，说明三份登记对得完。还有一层必须留在分数之外：脚本二的 18 个非阻断号命中再多也不改退出码，usage 第 92 行逐字写着「覆盖空洞、平面越界与三件不成对不计入阻断，只落 Q3（此时退出码仍为 0）」——一个合并分把「全绿」与「一片非阻断」压成同一个数。

**问：为什么 139 个号必须全部至少触发一次？全触发是不是就说明判据判得对？**
不是，它只说明每一条判据都还活着。139 是两支脚本的全部格子：脚本一 71 个信号码加 `J1`—`J4` 共 75 格，脚本二 60 个信号码加 `Q1`—`Q4` 共 64 格。`FX/coverage-proof.txt` 那 22 段给出的是一组互相钉死的读数：C1 与 C2 现场数出脚本一的 `emit()` 号与 `DOC["…"]` 号各 71，C3 的差集为空；C11 与 C12 在脚本二那侧各 64，C13 同样空；C5 与 C15 是「定义 71 命中 71 未触发清单 [] 未定义命中 []」与「定义 64 命中 64」；C6 与 C16 逐号计数全部大于等于 1，C7 与 C17 给出最薄的五号；C8 与 C18 证明四档判定与四级闭合各自可达（`J` 四档在实跑 R4 同框、`Q` 三档在 R21 同框）；C9 与 C19 证明退出码 0、1、2 都出现过；C10 与 C20 证明一号一判据（脚本一 71 号里一号多义 0，另有形态族 `C06` 与参数化 `S07` 各一条）；C21 与 C22 把两张表件的 75 格与 64 格逐格与留档重数、不一致为 0。判据本身对不对，靠的是第 21、22 章逐号给出的公开出处行号，由读者拿归档自己核对，覆盖验收不代替这一步。

**问：夹具全是合成标识，能不能换成真实台账或真实设备上的会话记录？**
不能，换进来的那一刻这套验收就失效了。台账拒收清单写在两支脚本的头部注释与 usage 里：真实用户检索词、可还原身份的语音描述、真实联系人类／健康类／位置类样本、形似共享密钥或口令的取值（`glpat-`／`ghp_`／`AKIA`／`Bearer `／`-----BEGIN` 这一类前缀）、设备绝对路径、整段文件正文、超长度阈值的载荷。画面字节本身更不进台账：脚本二 `K01` 的出处文案逐字是「见本文第 3.4 节失败点 8（台账只登记哪一个会话在哪一格被判定成什么，不登记画面本身、不登记可还原身份的样本）」，`K02` 的出处文案逐字是「见本脚本头部注释的拒收声明：设备侧命令行工具不作为任何一格的读数来源」。

真实台账进来后第一件要做的事反而是洗数据：实跑 R16 专喂拒收形态，那一段独占 3 条 `K02`；实跑 R12 的行格式畸形里同时打出一条 `K01`。拒收侧的累计数（逐字取自第 23.4 节两张表）是脚本一 `K01`(4)、`K02`(18)、`K03`(5)，脚本二 `K01`(3)、`K02`(4)、`K03`(3)、`K04`(3)、`K05`(3)。洗过一遍之后，判定对象已经从「归属能不能立起来」变成「数据干不干净」，而这份留档也不能再随文发布——`FX/coverage-proof.txt` 与 `FX/readonly-proof.txt` 的价值恰恰在于第三方能在无设备、无私有数据的条件下原样重跑。

**问：出流时点为什么只许写成「打开／预览／分享这三类动作之后」或「录制／镜像／投屏这三类会话建立之后」？**
因为本篇归档里关于触发条件的读数只有 `C/readings-19.txt:160—169` 那一组，而它支撑不了任何第三种写法：读数 R32 显示免交互措辞在平台安全指南里只有 2 行，逐行是第 1442 行 BlastDoor 词条与第 4681 行 device management service 词条，两条都不在任何画面通道上；读数 R33 是公告 impact 列含 `without user interaction` 或 `without user consent` 的 10 行；读数 R34 是含 `without user permission` 的 8 行；读数 R35 的组件分布是 CoreMedia 5、WindowServer 3、AccessorySetupKit 2；读数 R36 落在画面外流六组件子集内的只有 3 行、同一个 `CVE-2026-112575`，影响句逐字为 `An app may be able to monitor keystrokes without user permission`，三行全是 macOS 平台行。

这五条读数说明的是「公告那一列不记载触发条件」，推不出「不需要用户动作」。台账侧拦住这种反推的码：脚本一 `A02`（3，提示与采集的先后写反）、`N01`（35，画面确已离开设备但告知位未登记）、`N05`（3，离开设备而无提示无披露无说明句）；脚本二 `T08`（115，对外表述缺必需格）、`V04`（3）。`外流时点` 那一列的取值（`on_start`、`on_session`、`on_share`、`on_stop`、`on_reboot`、`per_stream`，另加 `not_recorded`／`unknown` 两个控制值）只能由登记侧的动作与会话给出。

**问：退出码 2 是什么？能不能拿它当门禁？**
`2` 只判「输入坏了」：参数个数非法或文件不可读，两支脚本的 usage 各有一行把三值分开写死（脚本一第 134 行、脚本二第 92 行）。实证段是脚本一侧的 R8（无参数）与 R9（文件不存在），脚本二侧的 R27（无参数）、R28（只给清单一份）与 R29（三份里任一份不存在）；两份留档的分布是脚本一 6 个 0、10 个 1、2 个 2（C9），脚本二 3 个 0、9 个 1、3 个 2（C19）。不要把 2 读成「发现问题」：它排在任何判定之前，一批真台账跑出 2 时唯一该做的是先修参数与文件可达性，那 139 个号一个都没被看过。也别把 0 读成「没问题」——本文里给出 0 的合法形状就有四种，实跑 R10（空文件）与 R11（只有注释与空行）是零会话、R18 只留一条 `B01` 落 J2、R20 是九会话全 Q1 的下界、R31 空清单打 20 条非阻断 `D05`（累计 101）而退出码仍是 0。

**问：MDM 下发了画面语义的限制键，能不能据此写成「画面外流已受控」？**
不能。先把分母看清楚：`C/readings-19.txt:88—94` 那条链是读数 R19 键表 220 行 → R20 形态命中 218 → R22 非键名 8 行、纯键名分母 210 → R23 画面语义词命中 13 → R24 `allow*` 9 个／`force*` 4 个；13 个键的清单在 `:95—107`，其中五个是同词不同义（`:96—100`：`allowAutomaticScreenSaver`、`allowCallRecording` 与 `allowLockScreenControlCenter`／`allowLockScreenNotificationsView`／`allowLockScreenTodayView`），它们约束的都不是画面离开设备这件事。

再看键实际管到哪一层：`B/mdm-restrictions.txt:766` 是一个键同时关掉保存截图、录屏采集与 Classroom 远屏观察的活例；`:726` 要求把子约束键嵌在指定 payload 下；`:1018` 说明受管理课程里的学生「automatically gives permission to that course teacher’s requests to observe the student’s screen without prompting the student」——这是管理面替代用户许可的口径，本文不把它写成任何免交互触发路径。`forceBypassScreenCaptureAlert` 在 `C/readings-19.txt:106` 只作为管理面读数的一格登记存在形态，本文不指导如何使用或规避它。台账侧：脚本一 `G01`（6）、`G02`（「该键命中词形但不约束画面离开设备」，3）、`G05`（4）；脚本二 `M03`（9）、`X04`（4）、`K05`（「提示绕过键进入通道件」，3）。键能配置的是通道开不开，给不出某一帧画面在哪条出流路径上、落到哪儿、用户看见哪一格——写「已受控」需要键的粒度证据，而 210 个纯键名的清单里没有这一格。

**问：本文能不能保证某一台设备的情况？**
不能，三处限制叠在一起。其一，登记件人工填写，第 23.1 节那二十段只保证脚本没有读别处的口子（见第一问末尾那句不对称，对应第 26 章 N12）。其二，判定作用域有限：脚本二的逐值判定只在能力表建模过的（会话类, 核对项）配对上发生，兜底两类不进能力表（`FX/capability-19.csv` 只有 9 个建模类 × 20 项 = 180 条数据行），未建模类只得到 `D04`（累计 26）与闭合等级 `Q4`（累计 42）——实跑 R21 里 `UNK_C` 同时打出这两条，R30 把九会话整批推到 `Q4`。其三，平台覆盖不对称：画面外流子集里 macOS 31 行、iOS 只有 4 行（`C/readings-19.txt:27`，读数 R08），所以公告侧任何一条读数都带平台行标注、也都不能写成 iOS 侧结论。

那本文能保证什么？保证同一份输入交给同一支脚本得到同一份输出，且这套输出可以第三方重跑：`FX/run-all.sh` 的 18 段、`FX/run-all-tri.sh` 的 15 段、`bash FX/coverage-report.sh` 的 22 段、`bash FX/readonly-proof.sh` 的 25 段，加上两张表件由 C21／C22 现场重数。

**问：我改了某条判据，怎么知道有没有改坏？看总信号数吗？**
不看总数，看第 23.2 节那张逐次表里哪一段该变色、它确实变色了。三处真实的薄覆盖要提前知道（第 24 章末段给过同一组数）：脚本一的 `A05`、`C07`、`D03`、`R04` 累计恰为 2、首现晚到实跑 R3（mid 档），C7 那五行是 `2 A05`／`2 C07`／`2 D03`／`2 R04`／`3 A01`；脚本二的 `C01`—`C04` 累计各为 1，只在畸形能力表那一段（实跑 R23）打印过，C17 五行末格是 `2 X03`，词表侧的 `X05`／`X06` 同样各为 2；逐码构造件实跑 R19 只打到 54 个信号码，正好是 60 减 C 族五条减 `X08`，这两组只在 R23 与 R24 出。改到这九个码时其余各段毫无反应；反过来把夹具喂宽（比如再畸形化一份清单）只会让累计数变大而不增加覆盖强度，因为薄的从来不是命中次数而是「哪几段能碰到它」。改完之后重跑 `bash FX/coverage-report.sh`，用 C21 与 C22 把两张表件重新对撞一遍，不一致数必须仍为 0。

**问：十一层、三件、二十项核对项、九条出流路径、十一个会话类、二十六个读数平面——这些数字对不对得上？会不会串？**
各自管一件事，不能互换，也不能拿格名跨脚本对齐。十一层（L1—L11）绑的是脚本一的十二个命名空间：`id`／`consent`／`chan`／`dom`／`land`／`obs`／`notice`／`undo`／`mgmt`／`adv`／`doc` 十一个归属空间，加上第 21.2 节写死在 `NS[]` 里的第十二项 `sec`——它的唯一用途是让该空间下任何字段触发 `K01`，不参与任何层的归属；三件是脚本二的主语切分——采集件 7 项、落点件 5 项、告知件 8 项，合计 20 项核对项；九条出流路径是 `chan.egress_path` 那一格的九个取值，不是九个核对项；11 个会话类是清单侧的主语空间，而能力表只建 9 个类；26 个读数平面与三件之间是脚本里按公开口径写死的 31 组配对（源码第 206—222 行的 `ppair(...)` 逐条列出），配对之外一律算越界读数；另有 7 个布尔位与 4 档对外表述取值。

还有一条形状差异必须记住：脚本二同一列「主语」在四个码族下指的不是同一种东西——`D`／`T`／`V`／`X01`—`X07` 用会话标识（如 `MID_A`、`SVC_X4`），`C01`—`C04` 用能力表侧的会话类或列值，`X08` 的逐行支用词表侧的类别值，整表级判定用 `-`（`C05`、`D05`、`V05`）。脚本一没有这个洞，它的信号行只有一个主语空间。**任何把它当单一键去 join 的下游用法都会错**，这条差异本身进了第 26 章的边界清单。

## 26. 未公开文档化边界清单

本章收录的是「公开文档没给，本文就不结论」的那些格子。一条边界要进这张表，必须同时满足三个条件之一：**（a）** 公开文档对这一格既没写成「该类会话必须登记」，也没写成「对该类会话不成立」——即能力表四值里 `undocumented` 那种状态；**（b）** 公开侧有读数，但读数所在的面与本文要的格子不匹配（集合句不能当个体句用，键名形态不能当键语义用，平台行不能跨平台换算，词表取值不能当口径句用）；**（c）** 完全没有公开读点，而第 1.3 节的红线又不允许用设备侧操作补齐。**不属于这三类的不进表**：文档明确写了义务的格子归第 4—14 章的层叙述与第 21、22 章的判据，文档明确写了不适用的格子归能力表的 `not_applicable`（本篇有 50 格属后者，逐列重数见 26.2）。

**编号约定**：本章编号写作 N1—N14，**不补零**，与脚本一第 21 章那五个补零信号码 `N01`—`N05`（告知层）不是同一个东西。这两组编号在本篇撞得比第 18 篇更近，必须逐字说清：`N01` 是脚本一的判据「画面确已离开设备但告知位未登记」（源码第 446 行，出处逐字是 `B/apple-platform-security-guide.txt` 第 4241 行与第 4243 行，累计 35），拦的是**同一行登记内部**缺一格；本章 N1 说的是「画面离开设备的时点这一格在公开侧根本读不回」（说的是**登记之外的公开文档**）。`N04`（第 449 行，累计 3）判的是「锁屏通知面可被管理面关闭，『锁屏不可见』与『从锁屏通知读数』不能同时成立」，本章 N4 说的是广播上行在扩展侧的留存口径无人写过。前者是单行台账的自洽性，后者是登记可能性，`N01` 触发一次并不意味着 N1 这条边界闭合。脚本二没有 N 族（它的十族是 S／C／K／M／D／P／T／X／V／Q），所以本表十四条里凡是引用脚本码的地方，脚本一侧一律带「脚本一」前缀。把 `N01` 当成「第一条边界」去 join 会串。

### 26.1 十四条边界

**N1 · 画面离开设备的时点，公开侧一行都不记载。** 缺的是这一格：某一次会话里那一帧是在哪一个动作之后走的。检索过的词形与命中行数：`without user interaction` 与 `without user consent` 合计 **10 行**（`C/readings-19.txt:163`，读数 R33）、`without user permission` **8 行**（`:164`，R34）、平台安全指南里的免交互措辞 **2 行**（`:160—162`，R32，逐行是第 1442 行 BlastDoor 词条与第 4681 行 device management service 词条，两条都不在任何画面通道上）、按组件切是 `CoreMedia` 5／`WindowServer` 3／`AccessorySetupKit` 2（`:165`，R35）、落在画面外流六组件子集内的只有 **3 行、同一个 CVE**（`:166—169`，R36），影响句逐字为 `An app may be able to monitor keystrokes without user permission`，三行全是 macOS 平台行。为什么不是漏写：这五条读数说明的是「公告那一列不记载触发条件」，推不出「不需要用户动作」，而本篇红线不允许用设备侧动作去补这一格。台账记法：脚本二「外流时点」那一列的取值（usage 第 50 行 `on_start`／`on_session`／`on_share`／`on_stop`／`on_reboot`／`per_stream` 加两个控制值）只能由登记侧的动作与会话导出，回指不到任何公开句；未登记记 `not_recorded`。相关信号：脚本二 `S07`（枚举取值必须由登记方在词表里选定，累计 16）、`T08`（115）；脚本一 `C01`（34，通道件必须指名走的是第 4242 行还是第 4243 行那两条之一）、`N01`（35）、`N05`（3）。**后果：本篇对外表述里，画面离开设备的时点只允许一种形态——「录制／镜像／投屏这三类会话建立之后」；第 24 章误区 9 就是这条边界的落点。**

**N2 · `airplay_menu` 这个来源面取值在归档里没有承载句。** 缺的是这一格：投屏这件事在公开口径里是不是「用户从某个菜单进入的」。检索过的词形与命中行数：`airplay_menu` 在 `A/`＋`B/`＋`C/` 三组归档里逐字 `grep -oF` 命中 **0 次**；相邻读数是脚本一 usage 第 50—52 行把 `id.source_face` 的 14 个取值整列写出（`airplay_menu` 在第 51 行、`DOM["id.source_face"]` 在第 178 行重复同一列），接口侧最远只读到 `A/replaykit_rpsystembroadcastpickerview.txt:11`「`When a user taps the broadcast button, it displays a broadcast picker, allowing the user to select a broadcast provider.`」（按钮，不是菜单）与 `B/…guide.txt:1374`（AirPlay 用认证 IC 校验接收端、音频与 CarPlay 视频流经 MFi-SAP，讲的是承载不是入口）。为什么不是漏写：这是「词表有格、文档无句」，属条件（b）——取值先于句子成形。脚本二把这一列改写成 `system_menu`（usage 第 48—49 行），那是脚本二的自造统称，不是一条新的公开句，不能反过来当依据。台账记法：这一格记 `not_recorded`；为填满枚举而借用 `system_menu` 或 `control_center` 等于自造词表，回指必然落空（`V02`）。相关信号：脚本一 `B02`（3，录制与广播是两个会话类、通道词不能互换）、`B03`（3，进入面是 App 内控件时来源不能记成管理面）；脚本二 `T06`（9，入口与会话类是公开口径里成对出现的两格）。**后果：AirPlay 投屏在本篇只能按「会话建立之后」登记，不能按「用户打开了某个菜单」登记——后半句在归档里没有对应句子。**

**N3 · 同意能否被撤回，四个面上没有一句公开口径。** 缺的是这一格：`consent.revocable`（脚本一 usage 第 59 行与 `consent.microphone_used`／`camera_used` 同行列出，五值 `yes no not_applicable not_recorded unknown`）。检索过的词形与命中行数：`revok` 在 `A/` 组 15 件里命中 **0 行**。公开侧最远读到三处相邻句：`B/…guide.txt:4241`「`This alert is presented once per app process, and it’s presented again if the app is left in the background for longer than eight minutes.`」讲的是再次呈现的触发条件，不是撤回；`A/replaykit_rpscreenrecorder.txt:88`「`Discards the current recording.`」是复位口；`:240`／`:251`／`:267` 三个停止口里只有第三个在签名里出现输出 URL，没有一个接受「撤回同意」这个参数。为什么不是漏写：`undo.reset_method`（usage 第 105 行，含 `revoke_consent` 一值）看起来覆盖了这件事，但那一格的取值来自登记方自选，本篇 14 层分解里 `revoke_consent` 没有任何归档行号可挂。台账记法：`consent.revocable` 记 `not_recorded`，`undo.reset_method` 一侧可以正填 `discard_recording`／`stop_recording`，两格不可互换、不可互相补齐。相关信号：脚本一 `A02`（3，提示在前采集在后，顺序不可颠倒登记）、`A03`（5，公开只给「每 App 进程一次」，`per_session`／`per_device`／`per_stream` 都是台账自行加严或放宽）、`V02`（3，丢弃是一个独立复位口）；脚本二 `P04`（4，复位口的读数来自接口文档或用户面，不来自采集面）。**后果：「用户撤销授权后画面仍在流出」这类句子在本篇既不能肯定也不能否定；第 24 章误区 3（把停止口当追回口）是它的落点。**

**N4 · 广播上行的画面在扩展那一侧留存多久，公开侧无人写过。** 缺的是这一格：`broadcast_upload` 走完之后画面落在哪儿、停留多久、谁能再读回。公开侧读到四句：`B/…guide.txt:4248`（广播期采集与影片录制完全一致、发生在 `replayd`）、`:4257`「`The extension that third-party broadcast services implement to handle video and audio content during broadcasting uses raw unencoded sample buffers.`」、`:4249`（第三方服务要建两个扩展挂在同一端点上）、`A/replaykit_rpbroadcastconfiguration.txt:3`「`An object used to configure the movie clips produced during a live broadcast.`」（直播同时另产影片件）。这四句给的都是「怎么处理」，不给「处理完之后呢」；影片侧的对应句 `:4244` 写得很死（「`The movie file is written to a directory that’s only accessible to the ReplayKit subsystems and is never accessible to any apps.`」），广播侧没有等价句。检索词形与命中行数：`broadcast_upload` 的落点句 **0 行**、能力表里 `stored_object` 对 `live_broadcast` 类没有 `required` 行。为什么不是漏写：条件（b）——存在相邻通道（影片）的强口径句，但把那句搬到广播通道就是跨机制换算。台账记法：`land.destination`（usage 第 87—88 行 10 值，含 `third_party_service`）可以正填，`land.write_scope`（第 89 行，含 `service_side_store`）本篇整格记 `not_determinable`。相关信号：脚本一 `E04`（6，出处是 `A/replaykit.txt:5` 与 `:4257`）、`E05`（3，`mp4_clip` 只属于直播形态）、`C05`（3）；脚本二 `M05`（22，落点登记为类别名而不是设备绝对路径）、`S08`（366，同一个落点重复列出不增加覆盖面）。**后果：广播类的落点结论只能走到「交给第三方上传扩展」这一句为止；第 24 章误区 4 拆的正是「广播走通了所以承载方、端点与特权都如登记所述」。**

**N5 · `:4250` 那句集合口径不能换成「这一帧对宿主 App 不可见」的个体结论。** 缺的是这一格：广播期间某一次会话里宿主 App 究竟读不读得到画面。公开侧读到 `B/…guide.txt:4250` 整句：「`The architecture helps ensure that hosting apps have no privileges to the broadcasted video and audio contents. Only ReplayKit and the third-party broadcast extensions have access.`」，以及同一节里方向相反的两句——`:4242`「`This is designed to ensure the recorded content is never accessible to the app process.`」与 `:4243`「`This allows an app to get video and sample buffers, which is guarded by the permissions dialogue.`」。为什么不是漏写：`:4250` 的主语是 hosting apps（一个集合），谓语是 have no privileges（特权面），它落不进 `chan.host_has_access` 的六个取值（usage 第 72 行 `yes no never_accessible not_determinable not_recorded unknown`）里任何一格的逐次语义；这是条件（b）里最典型的一种——聚合级读数当个体级用。台账记法：这一格要么填 `never_accessible` 并在引用格显式标注「依据是集合口径」，要么填 `not_determinable`；本篇对广播类一律取后者，对录制类才允许 `never_accessible`（依据 `:4242` 的个体句）。相关信号：脚本一 `D01`（48，执行域类别未登记，出处正是 `:4250`）、`C03`（3，出处是 `:4242` 那句 never accessible）；脚本二 `K03`（3，出处同时写 `:4242` 与 `:4250`，拦的是把两种隔离机制混到同一格）、`T02`（125，落点与告知有读数而采集件一格没有）。**后果：把集合句写成个体句，等于在本层重犯第 3.4 节失败点 8；第 24 章误区 1 是它的正面形态。**

**N6 · 外屏与车机模板这两条流的落点可达性没有公开口径。** 缺的是这一格：`external_display_stream`／`carplay_template_stream` 走完之后画面在哪儿、谁能再读回。公开侧读到：`A/uikit_uiwindow.txt:18`「`Most apps need only one window, which displays the app’s content on the device’s main screen.`」（后半句在本行以「as described in」断在 doc-link 上，按 `IDX/sources-19.md` 抽取器限制第 1 条只引前半句）——外屏是文档默认用法之一；`A/carplay.txt:5`「`You control the content of the templates, but the framework controls certain aspects of the template interface elements, such as the touch target size, font size, font color, and highlights.`」是分权句，只讲呈现不讲去向；`A/carplay_cpinterfacecontroller.txt:26`「`The trait collection of the vehicle’s primary screen.`」说明特征取自车机主屏；`A/avkit.txt:37`「`Capture from hardware buttons and AirPods, present an audio input picker, and connect a nearby iPhone as a camera.`」是方向相反的反向通道，本篇只用它划界；`B/…guide.txt:4157`「`As a result, the app is unable to access or store the video stream. In addition, apps aren’t permitted to capture screenshots from this stream.`」说的是 HomeKit 的 IP 摄像机下行流，不是本机画面外流。检索词形与命中行数：`external_receiver` 与 `home_hub` 两个落点取值在 `A/`＋`B/` 归档里各 **0 句**承载。为什么不是漏写：条件（b）——观测平面名有（脚本二 usage 第 43 行的 `vehicle_display`／`carplay_template`／`external_screen` 三面），句子没有。台账记法：`land.destination` 对这两类会话记 `not_determinable`；`obs.plane` 记 `not_recorded` 而不是 `none`（`none` 表示根本没有面，与这三个平面名共存矛盾，脚本二 `P01` 拦的正是这一混用）。相关信号：脚本一 `E01`（35，落点句只有 `:4244` 一条）、`D06`（3，出处同时是 `:4242` 与 `A/uikit_uiwindow.txt:18`：出流进程归属与执行域类别必须一致）；脚本二 `P07`（6，来源面决定能读回哪一面，车机模板读不出 App 内提示）。**后果：这一条是本表十四条里唯一「通道件必填、落点件只能不判定」的配对，把它当缺口去补一格就会造出跨机制换算。**

**N7 · iOS 侧没有采集指示的公开口径，那条强句属于 Mac。** 缺的是这一格：iOS 上一次录制或镜像在硬件层是否必须可见。公开侧读到两处，都带平台名：`B/…guide.txt:708`「`The architecture is designed to prevent any untrusted software—even with root or kernel privileges in macOS—from engaging the camera without also visibly lighting the on-screen camera indicator light.`」主语是 MacBook Neo、约束对象是相机；`:2262`「`macOS: Input monitoring (for example, keyboard strokes), Prompt, Screen recording (for example, static screen shots and video), and System Settings (macOS 13 or later) or System Preferences (macOS 12 or earlier)`」行首就写着 macOS。本层归档里写明「采集必须可见」的强口径句子只有 `:708` 一处（`IDX/sources-19.md` 组 B 的同一标注）。iOS 侧能读回的只有 `:1429`「`While being remotely used on the Mac the iPhone remains locked and users see a persistent notification on the iPhone’s Lock Screen.`」（镜像一条）与 `:4241` 的同意提示（录制一条）。为什么不是漏写：条件（b）与条件（c）叠在一起——句子存在但不在这一平台，且红线不允许用设备侧操作补。台账记法：`notice.prompt_shown` 可正填，`obs.plane` 记 `lock_screen_notice` 或 `in_app_alert`；`camera_indicator` 这个平面名（脚本二 usage 第 41 行）本篇不对 iOS 会话填。相关信号：脚本一 `O04`（5，出处同时是 `:708` 与 `:4245`）、`O03`（3，出处 `:2262`：可核对的状态在系统侧不在 App 自述里）、`O01`（3，锁屏通知读不出执行域）；脚本二 `P02`（3，权限状态面给出的是是否允许，不给出画面落到哪儿）。**后果：硬引 `:708` 造出的跨平台换算是第 3.4 节失败点 8 在本层的一个实例；「指示灯不亮所以没有采集」这句在本篇没有任何依据。**

**N8 · `forceBypassScreenCaptureAlert` 只有形态可读，语义句既不是 iOS 的也不是这一键的。** 缺的是这一格：这个键在 iOS 上到底做了什么。公开侧读到三处，缺一处就能连起来：键名逐行出现在 `B/mdm-restriction-keys.txt:185`（形态位，本篇 13 个画面语义词清单的第 12 格，`C/readings-19.txt:106`）；说明句流里确有一行 `B/mdm-restrictions.txt:997`，逐字形态是 `, then the system bypasses the presentation of a screen capture alert.`——**行首是一个逗号**，因为 `tools/html2txt.pl` 把键名所在的 doc-link 片段送进了另一条流（1—1230 行说明句流、1231—1530 行 299 条 `CODE|` 流，`IDX/sources-19.md` 抽取器限制第 2 条），所以这一行在这一份归档里回溯不到主语；紧跟的可用平台行 `:998` 逐字是 `Available: macOS 15.1+`。检索词形与命中行数：读数 R27 的 9 行画面语义词说明句（`C/readings-19.txt:112—120`，即归档第 29、726、729、766、965、969、1018、1392、1393 行）里**没有第 997 行**——派生器 `tools/readings19.pl` 第 148 行的词形表只有 `screenshot`／`screen recording`／`AirPlay`／`remote screen`／`Classroom app` 五个，`screen capture alert` 不在其中。为什么不是漏写：条件（b）三重不匹配——句子有、平台不对、主语回指不到。台账记法：`mgmt.*` 只登记这一键的存在形态，`notice.*` 一侧不接受它作任何一格的读数来源；本篇不指导如何使用或规避它，也不把它写成任何触发路径（第 1.3 节与第 25 章那一问同一口径）。相关信号：脚本一 `G05`（4，键写成路径或带空格即不属这一份清单）、`G01`（6，出处是 `:92` 的 13 个键与 `:95—107` 的清单）；脚本二 `K05`（3，出处文案逐字是「见 C/readings-19.txt 第 106 行」，拦的是把绕过键进入通道件）、`M03`（9，键必须是小写开头的单个驼峰标识）。**后果：这一格是「公开侧有句、但不是这一平台的句、也不是这一键的句」的最干净一例，任何把它写成 iOS 结论的表述都从这一行退回。**

**N9 · Classroom 远屏观察的告知格只有一种管理面形状。** 缺的是这一格：受管理课程里的学生端有没有出现过提示。公开侧读到 `B/mdm-restrictions.txt:1018` 整行：「`in the Education payload, a student enrolled in a managed course through the Classroom app automatically gives permission to that course teacher’s requests to observe the student’s screen without prompting the student.`」，以及相邻三行：`:726`（`, the system disables remote screen observation by the Classroom app.`，行尾断在 doc-link 上）、`:729`（`, the Classroom app doesn’t observe remote screens.`，且要求受管设备）、`:766`（一个键同时禁用保存截图、屏幕录制采集与 Classroom 远屏观察）。为什么不是漏写：`:1018` 描述的是「受管理课程这一形态里同意如何给出」，是许可的形状，不是「存在一个可被绕过的提示」；把它读成后者就是条件（b）——口径句的面与本文要的格子不匹配，也是本篇红线明令拒绝的方向。台账记法：`notice.prompt_shown` 对来源面 `classroom_app` 记 `not_recorded`；`consent.granted_by` 可正填管理面，且必须与 `mgmt.mdm_configurable` 同行出现，单独填一侧按脚本一 `S09` 记。相关信号：脚本一 `G04`（3，出处逐字是 `:1018` 与 `:729` 两行）、`A01`（3，`B/…guide.txt:4241` 与 `:1018` 两处授权的主体不同）、`N01`（35）、`N05`（3）；脚本二 `P06`（3，出处是 `C/readings-19.txt:110—121`，告知与受管口径的读数在管理面文档而不在接口引用页）。**后果：本篇对学生是否被提示只作陈述不作推断；第 24 章误区 6 与第 25 章管理面那一问说的都是这一格。**

**N10 · 公告的 impact 列不写画面动作，14 个词形里 10 个命中 0 行。** 缺的是这一格：某一帧画面被录走、镜像走、投走这件事，公告六列里没有一列记载。检索过的词形与命中行数（`C/readings-19.txt:31—44`，逐行给出）：`screen` 13 行（`:31`）、`keystroke` 3、`peer` 6、`vnc` 6，而 `record`（`:32`）、`recording`（`:33`）、`captur`（`:34`）、`display`（`:35`）、`mirror`（`:36`）、`screenshot`（`:37`）、`broadcast`（`:38`）、`airplay`（`:39`）、`replaykit`（`:43`）、`iosurface`（`:44`）十个词形各 **0 行**。列结构：`C/advisory-19.tsv` 只有 `file`／`platform`／`component`／`cve`／`impact`／`avail` 六列（表头第 1 行），没有采集入口列也没有画面数据类型列。`screen` 那 13 行分布在 4 个组件（`:48—52`：`Screen Sharing Server` 6、`Remote Management` 3、`smbx` 3、`Siri` 1），唯一一句直接写「看见画面」的是 `:63`「`A user with screen sharing access may be able to view another user's screen`」（`Remote Management`／`CVE-2026-112480`，同组件 7 行 3 个 CVE，`:60—63`）。匹配形态必须一起写：`:45`（R10）演示同一列原样匹配大写 `VNC` 得 6、整列小写化后仍用大写模式得 0（假读数）、小写化加小写模式得 6。为什么不是漏写：条件（a）与（b）之间——公告面承认这些组件、不承认这些动作。台账记法：`adv.*` 三格逐行登记并带平台名；由「0 行」推「没有缺陷」不接受。相关信号：脚本一 `R01`（3）、`R03`（6）、`R04`（2，词形是 screen 但组件不在四个里的薄覆盖）、`R05`（5，匹配形态）；脚本二 `X02`（4，出处含 `:8—16` 与 `:52`）、`X01`（3，任何归属都要回指 129 个组件名之一）。**后果：这就是第 13 章整层的形状——公告面能给的最多是一个组件名加一个 CVE 号。**

**N11 · iOS 侧不能借用 macOS 侧那 31 行。** 缺的是这一格：画面外流子集在 iOS 平台行上的读数密度。公开侧读到：子集 40 行（`C/readings-19.txt:8`，R05）按平台切是 macOS 31 行、iOS 4 行（`:27—28`，R08；逐行 iOS 26.7.2 与 27.2 各 1、3 行，`:19—20`；macOS 三档 11、10、10 行，`:21—23`）、其余 tvOS 2／visionOS 1／watchOS 2 合计 5 行（`:24—26` 与 `:28`，R09）；`ReplayKit` 这个组件名在子集里只有 1 行（`:13`）。同一 CVE 跨平台最多 8 行（`:79`，R16）。KEV 侧：Apple 条目 95 行（`:82`，R17），描述含画面语义词的 2 条（`:83—85`，R18）——`CVE-2026-65400` 是 macOS 的 improper authentication，`CVE-2023-28206` 是 iOS／iPadOS／macOS 的 IOSurfaceAccelerator 越界写；**KEV 里没有一条把「画面外流」写成在野利用后果**。为什么不是漏写：条件（b）——同一条通道在不同平台的公开口径详略不同，行数不能相加、比例不能互推。台账记法：`adv.platform` 逐行必填，跨平台聚合值本篇一律拒收；子集里 iOS 只有 4 行这件事本身按 `D04`／`Q3` 记为覆盖面不完整而不是结论。相关信号：脚本二 `D04`（26，出处文案逐字含「子集里 macOS 行 31、iOS 行 4」）、`Q3`（22，出处是 `:27—28` 与 `:56—57`）；脚本一 `R06`（4，版本号形态依据 `:180` 那句「除特别注明外」的平台版本口径）。**后果：「macOS 有 31 行读数」在本篇不构成 iOS 侧任何结论；第 25 章最后一问把它列为三处限制之一。**

**N12 · 判定本身的可证边界，与「行号属于快照不属于网址」。** 缺的是两格：登记内容与某台真实设备一致这件事；以及「第 N 行」这个引用长期稳定这件事。公开侧读到：无——这两条不是文档缺口，而是本文方法与引用机制的性质。第 23.1 节 P1—P20 二十段能证明两支脚本没有任何读设备、读网络、读索引、读文件属性的口子（P1 与 P11 对系统调用型模式空匹配；P4 与 P14 只在头部拒收声明与 `K02` 拒收正则里命中，P4d／P14b 用同一条命令位置规则扫全文也是空匹配而 P4c 的阳性对照命中 2；P6／P16 的外部命令普查是 `awk=1 tr=3 cat=1 mktemp=3 rm=1` 与 `awk=1 cat=1 mktemp=2 rm=1`；P8／P18 按 `scr19.` 与 `sct19.` 两种前缀查残留都是无残留；P10／P20 把三十三次实跑的命令行归一化后只剩六种与五种形状），**但证明不了某一格填得对**。台账记法：每一条对外表述前加限定语「按台账」，或在同一行给出 `doc.source` 加 `doc.line_ref`。所有 `第 N 行` 指的是第 28 章标注视作日期（2026-11-04）抓取的那份纯文本的行号，同一份文档换一次抓取行号会变。相关信号：脚本一 `X01`（12，确认结论缺来源文件或行号）、`X02`（4，行号引用形态不可换算）、拒收族 `K01`（4）／`K02`（18）／`K03`（5）；脚本二 `X01`（3）／`X02`（4）、`V01`（4，required 格全为无标识时结论无法回指）、`V03`（4，厂商说法与 App 自述不能单独支撑复位结论）。**后果：行号失效时失效的是这份快照而不是这条判据的逻辑；但两份台账之间连形态都不统一时，最后连验收也做不了——这才是这四条码真正的用途。第 24 章误区 10 与误区 11 与本章 26.3 第二条同源。**

**N13 · 三件 404 造成的符号空缺。** 缺的是三格：广播 App 扩展、`RPBroadcastManager`、`UIView` 的 `drawHierarchy` 三个符号面的公开句子。检索过的读数与命中行数：`MANIFEST-A.txt:13`、`:14`、`:18` 三条记录逐字都是 `404|15639|SKIPPED`（slug 依次是 `broadcastappextension`、`replaykit/rpbroadcastmanager`、`uikit/uiview/drawhierarchy`），本篇正文不引用这三件。为什么不是漏写：条件（c）——404 返回的是一个同形的 15,639 字节错误 JSON，只核对文件是否存在不足以判定抓到了正文（`IDX/sources-19.md` 抓取约定第 3 条），而红线不允许改用手机侧取值来补。现存证据侧的边界要写清：广播扩展这一格本篇只读到 `A/replaykit_rpbroadcastsamplehandler.txt:84—98`（`broadcastStarted`／`broadcastAnnotated`／`broadcastFinished` 生命周期三段）与 `:64`（`RPApplicationInfoBundleIdentifierKey` 这一种声明键形态），加上 `B/…guide.txt:4249` 那句「要建两个扩展挂在同一端点上」——**扩展的数量与生命周期有句，扩展的入口类名没有句**。台账记法：`chan.extension_count` 的 `two` 只能填到 `:4249` 为止；`chan.api_entry` 记 `not_recorded`，不记 `none`（`none` 表示这一格在本层根本没有入口，而这三件是空缺不是不存在）。相关信号：脚本一 `C07`（2，薄覆盖，首现实跑 R3；出处是四处同句 `Use … instead`，说明本层入口有两套公开口径）、`C06`（8，形态族：接口标识写成别的形态即不是这一层里的入口）；脚本二 `T05`（4，同一会话不能既按当前口径又按废弃口径给两格已读数）、`X06`（2，符号侧回指 `A/replaykit.txt:60—98`）。**后果：这三格在本篇是「已知缺口」而不是「已核对过的空白」；写成「本层没有这套 API」是错的，写成「本层的这一格本篇没有读到」才是对的。**

**N14 · 兜底两类不进能力表，且本篇 `undocumented` 一格也没有。** 缺的是两格：`not_recorded` 与 `unknown` 这两个会话类的逐值判定；以及「文档既没写义务也没写不成立」这一状态在本篇表格里的表达。读数：`FX/capability-19.csv` 共 182 行 = 2 行口径注释 + **180 条数据行** = 9 个建模类 × 20 项核对项（本轮 `wc -l` 与逐列重数一致：类名逐个是 `airplay_video`、`companion_display`、`live_broadcast`、`mirroring`、`movie_recording`、`remote_observation`、`scscreen_capture`、`system_screenshot`、`system_service`，核对项去重 20 个），11 个会话类里恰好 2 类无行；可得性分布 **required 89、optional 41、not_applicable 50、undocumented 0**，四数相加正好 180。第二个零是本章的结构事实：**第 18 篇有且只有 1 条 `undocumented`，本篇一条都没有**——不是缺口被填平了，而是本篇没有把任何一格判成这一状态。后果一：脚本二的逐值判据（K 族、M 族、`V02`、X 族全写在第 440—547 行那个按能力表配对的循环里，第 442 行先做 `if (c2 != kd) continue`）对兜底两类整批不发生，它们只得到 `D04`（26）与闭合等级 `Q4`（42）。后果二：条件（a）这一状态在本篇没有表格落点，十四条边界全部只能靠正文与信号码留位置——这就是本章比第 18 篇同层位更长、而表格里那一格反而少的原因。相关信号：脚本二 `C05`（5，同一格两条可得性无依据可选其一，首现实跑 R23）、`D05`（101，核对项在整张清单里零登记）、`X08`（6，词表侧，首现实跑 R24）、`V05`（4，同一格在不同会话之间口径不一）；脚本一 `S09`（666，必备格缺失）。**后果：改 `optional`／`not_applicable` 的口径不改变档位；把某一格改成 `undocumented` 会让它同时脱离 `D02`／`D05`／`D03` 三族检查——本篇现在没有这样的格子，也不该为了填满表格去造一个。**

### 26.2 能力表与公开词表怎么承载这些边界

`FX/capability-19.csv` 的 180 条数据行形状是 9 个建模类 × 20 项核对项，取值分布 required 89／optional 41／not_applicable 50／undocumented 0（本轮逐列重数）。注释第 2 行给出四值口径，并要求 `required` 必须能指到具体文件与行号。这组数里承载本表的是两档：**`not_applicable` 的 50 格是正面读数**（公开口径明说这一格对该类不成立），脚本二会去检查有没有人违反它——违反就打 `D03`（累计 9）；**`undocumented` 的 0 格意味着条件（a）在本篇没有表格落点**，所以本表十四条里除了 N14 自己，其余十三条都只能在正文里留位置，不占表格格子。

公开词表侧的分母是 `FX/vocab-19.tsv`：91 行 = 3 行注释 + 1 行表头 + **87 条数据行**，九类分布是 `advisory_cve` 18、`session_kind` 16、`api_symbol` 16、`restriction_key` 13、`advisory_component` 12、`advisory_component_crafted` 6、`plist_key` 3、`process_name` 2、`endpoint_tag` 1（合计 87），good 档实跑的汇总行读 `去重词条=80`。脚本二 X 族八个号的比对分母全部来自这一件：`X01`（3）用 129 个组件名、`X03`（2）用 330 条 CVE 与 95 条 KEV、`X04`（4）用 210 个纯键名、`X05`（2）用平台安全指南本层 31 行、`X06`（2）用符号清单、`X07`（9）用端点与进程名的两种公开写法、`X08`（6）用整表形态。也就是说：**本表 N8、N10、N11 三条边界在词表侧是有分母、无句子的——能判「你说的名字存不存在」，判不了「你说的那件事有没有公开口径」。**

一处常被读错的乘法要留在这里：脚本二在清单为空那一次实跑（R31）打 20 条 `D05` 而退出码仍是 0，那 20 条是**按核对项名聚合**的（每个核对项一条「整张清单里零登记」），与对象数无关；R30 把九会话整批推到 `Q4` 也是同一件事的另一面。把 `D05` 当成「缺了 20 格」去补，会把本表的 N14 读成待办清单——第 24 章误区 12 拦的正是这个读法。

### 26.3 两条固定自查项

**第一条：每次把脚本输出交给下游之前，先核对「会话类数」与「逐值判据发生次数」是不是同一个东西。** 依据是 N14：脚本二的 K／M／V02／X 族逐值判定只在能力表建模过的（会话类, 核对项）对上发生，清单里出现兜底类时那一行照样被计数、照样进矩阵，但一条逐值信号都不会有。good 档九会话全 `Q1`、信号行数 0 是合格下界（实跑 R20）；mid 档 `Q2`、`Q3`、`Q4` 各 1 是三档同框的最小形状（实跑 R21，`UNK_C` 同时打出 `D04` 与 `Q4`）。第二处要一起核对的是两张三列表与留档的一致性：`FX/coverage-proof.txt` 的 C21 打「表内格 75｜脚本一定义码 75｜不一致 0」、C22 打「表内格 64｜…｜不一致 0」，这两个数分别是脚本一 71 个信号码加 `J1`—`J4`、脚本二 60 个信号码加 `Q1`—`Q4`，与本表十四条引用的每一个累计数同源。

**第二条：退出码 0 只表示这一次运行没有阻断信号，不表示输入覆盖了什么，也不表示三件闭合。** 与本表同时相关的极端形状有两种：实跑 R31（空清单）打 20 条 `D05`、四个等级 0、退出码 0；实跑 R10（空文件）与 R11（只有注释与空行）是零会话、退出码 0。脚本二 usage 第 92 行逐字写着「覆盖空洞、平面越界与三件不成对不计入阻断，只落 Q3（此时退出码仍为 0）」，所以 `Q3` 累计 22 那一段在退出码 0 的批里——**看码不看退出码**。两支脚本的退出码分布（脚本一 0×6／1×10／2×2，脚本二 0×3／1×9／2×3）里，2 全部来自参数与输入不可达，排在任何判定之前。这两条自查与第 23.2 节末段同源：**不能触发的信号等于没有写过**；反过来说，没有实跑过的边界不该进这张表——本表十四条每一条都至少带一个 R 号或一个跨全部实跑的累计数。

### 26.4 这张表怎么用、怎么改

三条用法。**（1）这十四条一律不进结论。** 第 1.3 节承诺过「凡是只有厂商承诺、没有公开文档支撑的判断，一律落在第 26 章的未公开文档化边界清单里，不进结论」，本表就是这个存放处；第 27 章的三条结论没有一条落在本表任一行上。**（2）每条边界要求在台账里显式写一个值**——`not_recorded`、`not_applicable`、`not_determinable` 或对应枚举里的一个，**留空不等于承认边界**：留空会被脚本一的 `S01`—`S09` 与 `X01` 这类形态与引用信号计入，反而把会话推到 J4，而 J4 说的是这条登记不成立，不是这条边界成立。**（3）跨篇与跨层引用时带上出处。** 本表十四条的层分组是：N1—N5 属通道与告知侧（第 5、6、10 章），N6—N7 属落点与观测侧（第 8、9 章），N8—N9 属管理面（第 12 章），N10—N11 属公告侧（第 13 章），N12—N14 属证据、夹具与建模（第 17、23 章）。引用第 18 篇的边界必须写成「18 篇 N7」——18 篇有一套 N1—N12、本篇有一套 N1—N14，两篇不复用对方任何信号码（第 2.1 节）。

改这张表的规则只有一条：**新增一条边界，必须同时给出三件东西——一个承担它的脚本码（或一条拒收规则）、一个必填的台账字段、至少一次实跑的 R 号证据。** 本表里有三条给不全：N2 有字段有码但码的主语不对（`B02`／`B03` 拦的是通道词互换与进入面归属，不是「这一取值有没有来源」）；N13 的 `C07` 那 2 条主语是四处 `Use … instead`，不是这三件 404；N14 的 `undocumented` 零格没有任何码可指。这三条因此只能写成「本文对这一格不下判断」，不能写成倾向性表述；N12 连 R 号证据之外的东西都给不出，只能写成方法论限制。给得出三件东西的（N1、N5、N8、N10、N11）才可以被下游当作用途限制来引用。这一规则与第 23 章的覆盖验收同源。

## 27. 结论

本章给三条结论，按证据强度从强到弱排。每条都写两件事：**靠什么成立**（本篇归档里能落到行号的读数，加两支脚本实跑的跨运行累计）与**靠什么不成立**（这一条不能被读成什么）。三条结论都不落在第 26 章的任何一条边界上——第 26 章那十四条说的是「公开文档没给，所以本文不能往哪一步走」，本章说的是「公开文档给了，所以本文能往哪一步走」；两者是同一条通路的两侧，混着写会让读者把边界当成结论、或把结论当成边界。

**结论一 · 来源面、通道、落点三个面两两都不闭合，缺口是「三件之间那一次对照从来没有被公开登记过」。**（证据强度最高：两支脚本的阻断判据同时指向它，且每一段都有归档行号。）

靠什么成立。三段判定权分属三方，逐段有句，但**句与句之间没有一次对照**。**授权权在用户与硬件**——`B/apple-platform-security-guide.txt:4241`「`Before recording starts, ReplayKit presents a user consent alert requesting that the user acknowledge their intent to record the screen, the microphone, and the front camera.`」与「`This alert is presented once per app process…`」；`:1439`「`When users set up iPhone Mirroring for the first time, they’re prompted to choose to either “Automatically authenticate,” or to “Ask every time.” The Secure Enclave on the Mac enforces this user choice…`」。**通道权在出流机制**——`:4242`「`Screen and audio capture occurs out of the app’s process in the ReplayKit daemon replayd.`」与 `:4243`「`This allows an app to get video and sample buffers, which is guarded by the permissions dialogue.`」是同一节里方向相反的两条通道；`:4249` 要求第三方服务建两个扩展挂在同一端点上；`:1429` 写明被远用期间 iPhone 保持锁定；`:1374` 把 AirPlay 音频与 CarPlay 视频流交给 MFi-SAP。**落点在存储侧**——`:4244`「`The movie file is written to a directory that’s only accessible to the ReplayKit subsystems and is never accessible to any apps.`」、`:4245` 的预览与分享界面 out-ofprocess、`:4257` 的上传扩展按 `raw unencoded sample buffers` 处理。全篇唯一一句跨段的公开句是 `A/replaykit.txt:5`「`Using the ReplayKit framework, users can record video from the screen, and audio from the app and microphone.`」与它后半句的「`They can then share their recordings with other users through email, messages, and social media.`」——它跨的是「录制到 App 内分享」这一段，**不覆盖镜像、投屏与广播任何一段**。台账侧累计与这个结构一致：脚本二 `T01`（只登记采集件，**78**）、`T02`（只有落点与告知读数而采集件一格没有，**125**）、`T08`（对外表述为是但该类必需格缺位，**115**）、`D02`（**2065**）、`S08`（同一落点重复列出，**366**）；脚本一 `C01`（34，通道件必须指名走第 4242 行还是第 4243 行那两条之一）、`E01`（35，落点句只有 `:4244` 一条）、`O02`（188，有观测平面却未登记读数时刻）、`S09`（666，必备格缺失）。

不闭合的方向也要写清，而且与第 18 篇相反。第 18 篇的声明权在内容生产者手里、判定权在框架手里，缺口在「读回侧」；本篇的采集权在系统守护进程手里、落点权在框架与扩展手里，**登记方对自己那条通道恰恰是最没有读数的**——App 进程按 `:4242` 被设计成读不到自己发起录制的内容，而公告的 `impact` 列又不写画面动作（第 26 章 N10：14 个词形里 10 个命中 0 行），于是本来最可能补上这一次对照的两个面恰好都不记载这一格。所以 18 篇的补救是「让读回面可核」，本篇的补救只能是「让带走这件事可登记」，而公开档案里没有一格登记「这一次带走的对照」——这也是第 26 章 N1、N4、N6 三条边界同时存在的根因。

靠什么不成立。第一，不成立的是「把三件各自补齐就能闭合」：补齐需要一条公开换算句把通道段接到落点段，而第 3.4 节八处换算失败逐条说明这条句子在归档里不存在，第 18.3 节因此把它写成三条跨侧禁令。第二，不成立的是「本篇可以对某一次真实会话下结论」：本篇所有公告侧读数都是聚合级（1,266 行组件×CVE 对），聚合级不能当个体级用——脚本二 X 族八个阻断码拦的就是引用侧越界，`X01`（3，回指 129 个组件名）、`X02`（4）、`X03`（2）、`X04`（4）、`X05`（2）、`X06`（2）、`X07`（9）、`X08`（6）。第三，不成立的是「三件各有读数就说明三件成对」：采集件按会话类登记、落点件是唯一的数组型核对项（`landing_destination`，usage 第 39 行，同一会话可多行）、告知件按平面登记，三种主语空间在脚本二里不是同一个键——第 25 章末问给的这条形状差异（`D`／`T`／`V`／`X01`—`X07` 用会话标识，`C01`—`C04` 用会话类或列值，`X08` 的逐行支用词表类别值，整表级判定用 `-`）与第 26 章 N12 是同一条限制的两面。

**结论二 · 管理面能在 210 个纯键名分母内约束那 13 个画面语义键的开关，约束不了告知格与观测格。**（证据强度次之：一条完整的分母派生链加三处键作用面的活例句子。）

靠什么成立。先把分母链摊开，逐环都有行号（`C/readings-19.txt:88—93`）：限制键表 **220 行**（R19）→ 形态命中 **218**（R20，与第 18 篇同一口径）→ 首字母小写 **216**（R21）→ 其中 **8 行不是键名**（六个平台名加 `Important`／`Note`），**纯键名分母 210**（R22）→ 画面语义词（`screen`／`airplay`／`record`／`observ`／`mirr`）命中 **13 个键**（R23）→ `allow*` 前缀 **9 个**、`force*` 前缀 **4 个**（R24），清单逐行在 `:95—107`。管理面确实管得到通道这一层，有活例：`B/mdm-restrictions.txt:766` 一行同时关掉三件出流——「`, the system disables saving a screenshot of the display and capturing a screen recording. It also disables the Classroom app from observing remote screens.`」；`:29` 关掉 incoming AirPlay requests；`:726` 要求把子约束键嵌在指定 payload 之下。管理面管不到的是告知格与观测格：`:1018` 那句说明策略改变的是「许可如何给出」，不是「画面走了哪条路、落到哪儿」；`:2262` 那张 macOS 权限清单给出的是「是否允许」，不给落点。再补一刀：这 13 个键里有 **5 个是同词不同义**（`:96—100`：`allowAutomaticScreenSaver`、`allowCallRecording` 与 `allowLockScreenControlCenter`／`allowLockScreenNotificationsView`／`allowLockScreenTodayView`——屏保、通话录音、锁屏控件，都不管画面离开设备这件事），真正与出流有关的是 `allowScreenShot`、`allowRemoteScreenObservation`、`allowiPhoneMirroring`、`allowAirPlayIncomingRequests`、两条 AirPlay 配对口令键、`forceClassroomUnpromptedScreenObservation` 与 `forceBypassScreenCaptureAlert`。台账侧累计：脚本一 `G01`（6）、`G02`（3）、`G03`（3）、`G04`（3）、`G05`（4）、`N04`（3，锁屏通知面可被管理面关闭，「锁屏不可见」与「从锁屏通知读数」不能同时成立）；脚本二 `M03`（9）、`X04`（4）、`K05`（3）、`P06`（3）。

靠什么不成立。第一，不成立的是「已下发画面语义的限制键＝画面外流已受控」：写「已受控」需要键的粒度证据——某一帧画面在哪条出流路径上、落到哪儿、用户看见哪一格——而 210 个纯键名的清单里没有这一格，第 25 章那一问与本条同形。第二，不成立的是「`forceBypassScreenCaptureAlert` 说明采集提示可被绕」：它的说明句在 `B/mdm-restrictions.txt:997` 且行首是一个逗号（主语在另一条流里），可用平台行 `:998` 逐字是 `Available: macOS 15.1+`，而读数 R27 那 9 行画面语义词说明句里没有它——本篇只登记这一键的存在形态（第 26 章 N8），不指导如何使用或规避它，也不把它写成任何触发路径。第三，不成立的是「210 这个分母可以跨篇换算成别的分母」：它与第 18 篇同口径，两篇可交叉引用而不换算；命中数还会随匹配形态变化，`C/readings-19.txt:45`（R10）演示同一列原样大写匹配得 6、小写化后用大写模式得 0、小写化加小写模式得 6。

**结论三 · 「画面外流」与「恶意构造内容」在公告侧是两块互不相交的面，交集为 0。**（证据强度较低——它只有一条负读数——但完全可核对，逐格都是行级读数。）

靠什么成立。把 12 份安全发布的 1,266 条组件×CVE 记录切两刀。第一刀按影响句：含 `maliciously crafted` 的行 **467 行**（`C/readings-19.txt:55`，R12），这 467 行里同时出现画面语义词的 **0 行**（`:56`，R13），crafted 行里组件名含 `screen` 的 **0 个**（`:57`，R14）。第二刀按组件名：画面外流六个组件名逐字命中 **40 行、13 个去重 CVE、6 个组件**（`:8—10`，逐组件行数 `:11—16`，其中 `ReplayKit` 只有 1 行 `:13`），而 impact 列的画面语义词形 14 个里 `record`／`recording`／`captur`／`display`／`mirror`／`screenshot`／`broadcast`／`airplay`／`replaykit`／`iosurface` 十个词形**各 0 行**（`:31—44`）。两刀切出来的是两个不相交的面：`screen` 那 13 行分布在 4 个组件（`:48—52`），唯一一句直接写「看见画面」的是 `Remote Management` 的 `CVE-2026-112480`——「`A user with screen sharing access may be able to view another user's screen`」（`:63`，同组件 7 行 3 个 CVE，`:60—63`）。KEV 侧同样为空：Apple 条目 95 行（`:82`）里描述含画面语义词的只有 2 条（`:83—85`），**没有一条把「画面外流」写成在野利用后果**。这组数出自一支派生器（`tools/readings19.pl`，36 个 R 号只读产出，告警件 `C/readings-19.err` 为 0 字节），公告件由另一支派生器（`tools/adv-parse.pl`，六列 1,267 行）产出，两支不调用彼此。台账侧累计：脚本一 `R01`（3）、`R03`（6）、`R04`（2，词形是 screen 但组件不在四个内，本篇最薄覆盖之一）、`R05`（5）、`R07`（3）；脚本二 `X02`（4）、`X03`（2）、`X04`（4）、`X07`（9）、`M06`（6）。

这条读数直接决定筛选方式的后果：防守方按组件名筛「画面外流相关缺陷」，得到的是那 40 行、而且 31 行在 macOS；按影响句筛「恶意构造内容」，得到的是那 467 行、而且与画面语义词交集为 0。**两个筛法都给不出「谁在这台设备上把画面带走了」这一格**，所以第 13 章把公告对齐层的结论上限写成「组件名与 CVE 号可回指」而不是「缺陷可归属」。

靠什么不成立。第一，不成立的是「交集为 0 说明画面外流路径上没有缺陷」——0 说的是这一列的记载范围，不是缺陷的有无。第二，不成立的是「交集为 0 说明那 467 行与出流无关」——同理，反向读法也不成立，第 24 章误区 7 与误区 8 拆的就是这两种。第三，不成立的是「把两列取交集就能得到可用筛子」：交集会同时丢掉子集 40 行的绝大部分与 crafted 467 行，公开档案里没有第三列可补，且子集里 iOS 只有 4 行（`:27—28`，第 26 章 N11），任何跨平台换算在这条结论上都不被接受。

### 27.1 立场

本篇的立场是一句话：**在公开档案允许的范围内，把「这一帧画面有没有离开这台设备、走哪条通道、离开之后这一格在哪个面上读得回」说成一次可登记、可回指、可复算的归属判定，而不是说成一个关于某台设备的安全结论。** 这句话有三层含义，逐层给边界。

第一层，能说的：某一次被登记的会话，在哪个来源面被取出、走九条出流路径中的哪一条、落到哪个落点类别、用户面与受管面看得见哪一格；这四格齐备时才可以对外表述这一格的归属，判据是脚本一的 `J1`—`J4` 与脚本二的 `Q1`—`Q4` 两套四档（第 19 章）。第二层，不能说的：这一次出流会不会造成什么后果（公开侧没有那一类句式，第 1.3 节与本章结论一）、画面在没有动作的情况下走不走得出去（第 26 章 N1，写法上限是「录制／镜像／投屏这三类会话建立之后」）、这台设备上某一次具体会话属于哪一类（本篇所有读数都是聚合级或口径级）。第三层，最容易说错的：把「公告里有这个组件名」读成「这条通道上有缺陷」，或把「限制键下发了」读成「这一格已受控」。

还有一条关于本篇自身的立场：**本篇的两个核验器不是产品，是口径的显式化。** 它们不接触设备、不联网、不调用任何命令行工具，只读台账文本、三件清单、能力表与公开词表四类夹具；这一点由第 23.1 节二十段只读实证逐条给位置。读者如果把这两支脚本当成检测设备去跑，就已经越过了本篇的立场——它们能告诉你「这条登记说不说得出口」，不能告诉你「这台设备上有没有事」。

### 27.2 方法论：本篇是怎么把这三条结论做出来的

四步，每步都可复算。

**第一步，先把三段判定权拆成三套词表，不给统一表。** 接口面口径（`A/` 组 15 件 / 3,726 行，覆盖 ReplayKit 七件、UIKit 窗口与场景三件、CarPlay 两件、AVKit 与 HomeKit 与 CALayer 各一件）、系统口径（`B/apple-platform-security-guide.txt` 4,885 行，本层命中 31 行，`C/readings-19.txt:124—157`）、管理与公告回查口径（`B/mdm-restriction-keys.txt` 210 个纯键名、`B/mdm-restrictions.txt` 1,530 行两流、`C/advisory-19.tsv` 1,266 行、KEV 95 条）。本篇全程不做跨表替换；第 3 章那八处换算失败，就是把「替换会发生什么」逐处写成句子。**这套做法的价值在负空间**：正因为没有统一表，才能把结论三那个 0 读出来——如果一开始就把 `impact` 列与组件名列并成一列，本章第二条结论根本不存在。

**第二步，把每一个对外能说的字段做成一格，再给每格找一个归档行号或公开词表取值。** 十一层分解（第 4—14 章）落成「十一层 × 责任方 × 三件 × 证据」的矩阵（第 15 章），矩阵里每一格要么给出 `A/`／`B/`／`C/` 的行号，要么写「无」；「无」与「未记录」是两个值，不混用。这一步的成果可机器核对：脚本二 `V02`（引用格既不是公开词表值也不是文档行号形态）累计 **56**，就是「说不清出处」的格子的数量。

**第三步，两套四档判定模型 + 36 个 R 号公开读数 + 33 次实跑。** `J1`—`J4` 管单条登记能否进入对外表述，`Q1`—`Q4` 管一个会话类的三件是否闭合；第 16 章把「能数出来的事实」一次性摊开，任何一条结论被质疑时都能回到某一行；139 个号（脚本一 71 码加 4 档、脚本二 60 码加 4 级）全部由真实夹具触发，脚本一侧 18 次实跑 2,444 行、脚本二侧 15 次实跑 4,157 行，两张三列表的每一个累计数都从这两份留档逐码取来。

**第四步，把不能说的集中登记，并给每条一个「为什么不是漏写」。** 第 26 章十四条边界，每条写清缺的是哪一格、检索过哪些词形与命中行数（0 行要显式写 0）、公开侧最远读到哪、台账里这一格填什么、哪些信号码与之相关、越过这条撞到哪个码。这一章是本篇对自己最严的一章：它给结论一与结论三标出了上限。

四步的次序不能换。跳过第一步会造出一张统一表，那张表会掩盖结论三；跳过第二步，第三步的读数就没有引用格可回指；跳过第三步，第四步就只能写成「本文不做 X」而不是「X 这一格公开档案里没有，且越界有码可拦」。

### 27.3 三条最小可执行建议

三条全部只动台账文本与公开档案，不要求任何设备侧操作、不调用任何命令行工具，也不给出任何绕过采集提示、告知流程或管理面审计的做法。

**建议一 · 逐格指名通道，禁止写「屏幕共享／投屏」一类统称句。** 公开依据是同一节里两条相反通道：`B/apple-platform-security-guide.txt:4242`（出进程采集在 `replayd`，内容对 App 进程不可见）与 `:4243`（in-app 取样拿得到 video 与 sample buffers）；再加 `:4244`（影片落 ReplayKit 专用目录）、`:4249`（广播要有两个扩展挂同一端点）与 `A/replaykit.txt:5`（框架句把录制与分享写进同一句）。对应判据与累计：脚本一 `C01`（34）、`C02`（3）、`C04`（3）、`C09`（3），真正阻断的是 `S09`（666，必备格缺失）与 `C06`（8，接口标识形态）；脚本二 `T01`（78）、`T08`（115）、`K03`（3，把两种隔离机制混到同一格）。写法上限：一次会话的通道只能从 `chan.egress_path` 的九个取值里选一个（脚本一 usage 第 62—63 行），不接受自由文本。

**建议二 · 每一次对外表述前做一次引用格回指检查，并在系统版本更新后重跑。** 引用格只允许两种形态：本篇归档的 `A/`／`B/`／`C/` 文件加行号，或第 16 章公开词表的逐字取值；自由文本、近义词、跨平台换算句一律不接受。量级就是脚本二 `V02` 的 **56** 与 `V01` 的 **4**，脚本一侧是 `X01`（12）与 `X02`（4）。之所以要在版本更新后重跑，是因为这一层的公开口径本身在换代：`Use ScreenCaptureKit instead` 一类替换句在四件引用页的第 4 行各出现一次（`A/replaykit_rpscreenrecorder.txt`、`A/replaykit_rppreviewviewcontroller.txt`、`A/replaykit_rpsystembroadcastpickerview.txt` 与 `A/replaykit_rpscreenrecorder_isrecording.txt`），而 `B/apple-platform-security-guide.txt:4256` 又逐字写着「`The user interface is implemented using a private API and is an extension that lives within the ReplayKit framework.`」——同一能力的新旧两套口径与一条私有实现句并存，读数的稳定性只能靠重跑维持，不能靠记忆。

**建议三 · 公告筛与管理面筛各跑一遍、保存差集，并逐条标注平台行。** 一种按组件名过画面语义词表，一种按 `impact` 句过同一张词表；本篇的实跑差集是 **40 行子集**（macOS 31／iOS 4／其余 5）对 **467 行 crafted 行**，交集 **0 行**（`C/readings-19.txt:8—10`、`:27—28`、`:55—57`），两列都保留、不取交集、不跨平台相加。管理面回查同理：210 个纯键名里命中画面语义词的 13 个键中有 5 个同词不同义（`:92`、`:96—100`），**没有任何一个键给出「某一帧画面在哪条路径上」这一格**，所以「已下发限制键」不能换算成「画面外流已受控」。对应判据与累计：脚本一 `R03`（6）、`R05`（5）、`R01`（3）、`R06`（4）、`G02`（3）；脚本二 `X01`（3）、`X02`（4）、`X03`（2）、`X04`（4）、`D04`（26）。差集要存档，因为它是「公开档案说不清」的证据，不是「缺陷不存在」的证据。

---

**一句话收尾。** 本篇能交出去的，是一张把「这一帧画面被哪只手取出、走哪条路离开、离开之后落在哪一类地方、用户在哪儿能看见这一格」拆到可登记、可回指、可复算的表；交不出去的是任何关于「这一次带走会不会造成后果」的断言，以及任何关于「没有用户动作时画面会不会走」的断言——前一句在公开档案里连对应的句式都没有（14 个画面语义词形里 10 个命中 0 行），后一句连被问法的资格都没有。

## 28. 参考资料

本轮存档目录 `.srcx19/`（取回日期 2026-11-03 至 2026-11-04；复用件按下面「抓取与派生约定」第 8 条逐件 `cmp` 核验）。**七个归档目录共 72 个文件 / 3,674,266 字节**，分组为 `A/` 15 件 / 92,938 字节 / 3,726 行、`B/` 3 件 / 756,290 字节 / 6,635 行、`C/` 6 件 / 312,121 字节 / 1,535 行、`RAW/` 15 件 / 691,523 字节 / 0 行、`tools/` 7 件 / 119,105 字节 / 1,479 行、`FX/` 23 件 / 1,644,513 字节 / 9,302 行、`IDX/` 3 件 / 57,776 字节 / 251 行。上面每一组的件数、字节数与行数都是本轮 `ls` 与 `wc -l`／`wc -c` 的重数结果；与 `IDX/sources-19.md` 的记载有两处不符（`C/` 组字节与平台安全指南行数），逐处写在第 70 条与约定第 9 条里，正文以重数为准。

正文里的每一处 `A/`、`B/`、`C/` 行号都指下面这些**文本化归档件**的行号，不是原始 JSON 的行号，也不是 Apple 文档站页面上的序号。逐件的承重行清单在 `IDX/sources-19.md`（第 70 条）；两支脚本的 `DOC["…"]` 判据文案里已经把这些行号写死，第 23.6 节的静态反向对齐（55／71 与 55／64）会把每一条落回本表的某一件。

### 出流通道接口面文档（A 组 15 件 / 92,938 字节 / 3,726 行）

1. **ReplayKit 框架页**（`A/replaykit.txt`，99 行 / 3,214 字节；原始件 `RAW/replaykit.json` 24,131 字节）：本篇中心事实「录下来与发出去被写在同一句里」的出处。**第 3 行**「Record or stream video from the screen, and audio from the app and microphone.」；**第 5 行**「Using the ReplayKit framework, users can record video from the screen, and audio from the app and microphone.」「They can then share their recordings with other users through email, messages, and social media.」（本行结尾是「ReplayKit is incompatible with」，断在 doc-link 上，按约定第 5 条只引前半句）；第 12／16／20／24／28／32 行 broadcast 家族符号清单；**第 60—98 行** 本层符号清单逐字（脚本二 `X06` 的词表分母）；**第 71 行**「Share screen recordings, or broadcast live audio and video of your app, by adding ReplayKit to your macOS apps and games.」（同一能力的 macOS 口径）。
2. **`RPScreenRecorder` 页**（`A/replaykit_rpscreenrecorder.txt`，326 行 / 6,016 字节；`RAW/…json` 50,541 字节）：录制通道主体件，也是本篇被引最多的一件。**第 3 行**「The shared recorder object that provides the ability to record audio and video of your app.」；**第 4 行**「Use ScreenCaptureKit instead」（同一条录制语义有新旧两套口径，脚本一 `C07` 的四处之一）；**第 11 行**录制器是共享对象、实例按 App 划分；第 12 行 App 内音视频加麦克风旁白；**第 13 行**「Only one app at a time can use the recorder on the user’s device.」（并发上限，本层唯一一句；行尾断在「Your app can’t record video from」）；第 81 行委托；**第 88 行**「Discards the current recording.」加第 90／97 行两个方法名（`discardRecording`、`discardRecordingWithHandler:`，脚本一 `V02` 的出处）；第 120 行可用性布尔；132／137／138 麦克风与在录布尔；154／173 `startCapture` 两式；**第 240／251／267 行**三个停止口（只有第三个签名里出现输出 URL，脚本一 `V01` 与脚本二 `P04` 的出处）。
3. **`RPScreenRecorder.isRecording` 页**（`A/replaykit_rpscreenrecorder_isrecording.txt`，110 行 / 1,828 字节；`RAW/…json` 19,032 字节）：第 3 行「A Boolean value that indicates whether the app is currently recording.」；**第 4 行**「Use SCStream isCapturing instead」（四处 `instead` 之一）；9／11 属性名；第 52 行可用性；76／78 委托协议。
4. **`RPPreviewViewController` 页**（`A/replaykit_rppreviewviewcontroller.txt`，226 行 / 6,312 字节；`RAW/…json` 41,932 字节）：预览面与分享面的分格依据。**第 3 行**类述；**第 4 行**「Use SCRecordingEditor instead」；**第 11 行**「Upon completion of a successful recording, the preview view controller is passed into the completion handler for …」（预览对象由录制完成回调交出，不是用户索取；脚本二 `D01`／`C09` 的出处之一）；第 86 行可分享内容源；136 「The type of screen that appears when the view is presented.」；**第 153 行**「The modes used to determine whether the preview view controller or the share screen appears when editing a replay.」（两面在一个枚举里二选一）；157／159／161 回到录制器。
5. **`RPSystemBroadcastPickerView` 页**（`A/replaykit_rpsystembroadcastpickerview.txt`，226 行 / 6,956 字节；`RAW/…json` 44,299 字节）：广播入口面。**第 3 行**类述（按钮→选择器）；**第 4 行**「Use ScreenCaptureKit SCContentSharingPicker instead」；**第 11 行**「When a user taps the broadcast button, it displays a broadcast picker, allowing the user to select a broadcast provider.」（第 26 章 N2 的相邻读数）；**第 12 行**「Clicking the broadcast button has no effect in Mac apps built with Mac Catalyst.」（同一控件在一个形态下无效果）；**第 13 行**可把选择器钉死到单一 provider 的 bundle identifier（脚本一 `B04` 的出处）；79 可分享内容源；92 参考系转换方法集。
6. **`RPBroadcastSampleHandler` 页**（`A/replaykit_rpbroadcastsamplehandler.txt`，195 行 / 4,398 字节；`RAW/…json` 33,953 字节）：广播扩展侧唯一的接口件。**第 6—9 行**类名；**第 12 行**「objects as captured by ReplayKit, you subclass …」（`IDX/sources-19.md` 把第 11 行的「To handle」并记在这一条里，本篇按行照抄、不拼句）；第 22 行起止方法集；**第 24 行**框架串行调用扩展（脚本二 `S05` 的出处）；74／78 两种处理形态；**第 86／95／98 行** `broadcastAnnotated` 与 `broadcastFinished` 两段生命周期（`broadcastStarted` 在第 114—116 行，索引把三段合记作 84—98）；**第 64 行** `RPApplicationInfoBundleIdentifierKey`（脚本二 `X06` 的键形态出处）。
7. **`RPBroadcastConfiguration` 页**（`A/replaykit_rpbroadcastconfiguration.txt`，120 行 / 3,105 字节；`RAW/…json` 24,337 字节）：**第 3 行**「An object used to configure the movie clips produced during a live broadcast.」（直播同时另产影片件，脚本一 `E05` 的全部依据）；第 90／94 行回到按钮视图与本类。
8. **`UIWindow` 页**（`A/uikit_uiwindow.txt`，613 行 / 15,270 字节；`RAW/…json` 104,111 字节）：外屏通道的接口面。**第 18 行**「Most apps need only one window, which displays the app’s content on the device’s main screen.」（后半句断在 doc-link 上；脚本一 `D06` 的出处之一）；第 26 行「Changing the screen on which the window is displayed.」与第 31 行的指向句「For information about how to display a window on a specific screen, see …」；第 129 行坐标系换算；第 280 行矩形区域内容对象；**第 304 行**显示管理器（分辨率／刷新率／HDR 模式请求）；432／477／479／482 `windowScene` 与「The screen to display the window on.」；596／606／610 场景化绑定。
9. **`UIScene` 页**（`A/uikit_uiscene.txt`，458 行 / 10,579 字节；`RAW/…json` 80,772 字节）：观测面的系统通知依据。**第 199 行**「A notification that indicates that the scene is now onscreen and responding to user events.」；**第 217 行**「A notification that indicates that the scene is running in the background and is no longer onscreen.」（on-screen／off-screen 是系统通知而不是 App 自述，脚本一 `O02` 累计 188 的出处）；第 291 行 macOS 标题栏；411／412 外部 URL 打开选项。
10. **`UISceneSession` 页**（`A/uikit_uiscenesession.txt`，191 行 / 4,576 字节；`RAW/…json` 32,958 字节）：会话标识的公开依据。**第 13 行**「UIKit maintains the session information for the lifetime of the scene itself, destroying the session in response to the user closing the scene in the app switcher.」；第 14 行不直接创建会话对象；第 16 行默认配置来源；**第 123 行**「A unique identifier that persists for the lifetime of the session.」（脚本二 `S02` 逐字取这一行）；**第 137 行**「The scene associated with the current session.」（脚本一 `B06`）。
11. **CarPlay 框架页**（`A/carplay.txt`，547 行 / 16,080 字节；`RAW/…json` 125,872 字节）：伴生显示的分权声明。**第 5 行**「You control the content of the templates, but the framework controls certain aspects of the template interface elements, such as the touch target size, font size, font color, and highlights.」；第 12 行模板展示；24—31 模板与动作件家族；155／163 地图面板；191／204／214 现在播放屏。
12. **`CPInterfaceController` 页**（`A/carplay_cpinterfacecontroller.txt`，346 行 / 6,121 字节；`RAW/…json` 49,050 字节）：第 3／12 行类述与场景代理创建（脚本二 `T06` 的出处）；15／18 导航栈与模态呈现；**第 26 行**「The trait collection of the vehicle’s primary screen.」（界面特征取自车机主屏）；166 模板入栈；298 线程安全说明。
13. **AVKit 框架页**（`A/avkit.txt`，59 行 / 3,156 字节；`RAW/…json` 18,143 字节）：第 5 行采集集成点；**第 37 行**「Capture from hardware buttons and AirPods, present an audio input picker, and connect a nearby iPhone as a camera.」——**方向与本层相反的反向通道**，正文只用它划边界（第 26 章 N6）。
14. **HomeKit 框架页**（`A/homekit.txt`，113 行 / 3,455 字节；`RAW/…json` 27,728 字节）：第 8 行家庭配置数据库；71—72 媒体源显示顺序档；**第 83 行**「Declare your app’s intention to use HomeKit, and get permission from the user to access home automation accessories.」（申报面句子，本篇只用于与 `:4157` 的落点句对照）。
15. **`CALayer.contents` 页**（`A/quartzcore_calayer_contents.txt`，97 行 / 1,872 字节；`RAW/…json` 14,664 字节）：画面内容落在可被直接给出的对象上。第 21—22 行静态图像属性；**第 23 行**「(…) Assigning a value to this property causes the layer to use your image rather than create a separate backing store.」；**第 24 行**视图绑定时不应直接设值的告警；55—70 `contentsRect`／`display`／`draw(_:)` 三个呈现入口；90—97 `contentsCenter`。

### 系统口径与管理面（B 组 3 件 / 756,290 字节 / 6,635 行）

16. **Apple Platform Security 指南文本**（`B/apple-platform-security-guide.txt`，4,885 行 / 697,288 字节，August 2026 版 PDF 文本化；与 `.srcx9`—`.srcx18` 各份为**同一版本副本，本轮 `cmp` 逐字节相同、未重抓，故 `RAW/` 里没有它的原始件**）：第 7 章（执行域层）与第 26 章多条边界的唯一来源。第 180 行版本口径句；**第 708 行** MacBook Neo 的相机指示灯硬件级设计（本层唯一一处「采集必须可见」的强口径，且属 macOS）；第 1373—1374 行 MFi 与 **AirPlay 校验接收端、AirPlay audio 与 CarPlay video 走 MFi-SAP**；**第 1381 行**「An iPhone can be unlocked and viewed on a Mac using iPhone Mirroring.」；1382—1383 STS 协议与逐条解锁关系；**第 1428—1429 行** iPhone Mirroring security 全节（被远用时 iPhone 保持锁定、锁屏持久通知、会话结束后首次解锁横幅）；**第 1431 行**通知转发与点对点身份交换；**第 1438—1439 行**远程解锁与「Automatically authenticate／Ask every time」由 Mac 侧 Secure Enclave 执行；第 1442 行 BlastDoor（本篇只用它划界）；**第 2262 行** macOS 权限清单里的 `Screen recording` 一类；第 2379 行人审与截图；**第 3261 行** Tap to Pay 禁一切截图与录屏；**第 3575 行** ID Verifier Display Only 同类设计；**第 3901 行** AirDrop 与 AirPlay 点对点 Wi-Fi 使用随机化 MAC 地址；**第 4157 行** HomeKit 视频帧由独立系统进程安全渲染、App 不能存取该流、不允许截屏；**第 4237—4257 行 ReplayKit security 全节**：4237 节名、4238 录制与广播能力句、**4241 同意提示（每 App 进程一次、后台超八分钟再呈现）**、**4242 出进程采集在 `replayd`、内容对 App 进程永不可访问**、**4243 in-app 取样拿得到缓冲且受权限对话框守护**、**4244 影片写入只有 ReplayKit 子系统可访问的目录**、**4245 预览与分享界面由 ReplayKit 提供且 out-ofprocess**、4246—4250 广播侧（4248 与影片完全一致、**4249 两个扩展挂同一端点**、**4250 宿主 App 无特权、只有 ReplayKit 与广播扩展有访问权**）、**4256 广播选择器用私有 API 实现**、**4257 上传扩展处理 raw unencoded sample buffers 且数据被 serialized**；4259—4260 SiriKit 关系段（本层不引，仅用于边界）。
17. **设备管理限制键全集**（`B/mdm-restriction-keys.txt`，220 行 / 5,453 字节；与 `.srcx18/B/` 同名件逐字节相同）：第 12 章管理面回查的分母件。**第 1—4 行是页面分段标题**（`Device Management`／`Important`／`Mac Catalyst`／`Note`），**不是键名**；本篇一律写作「220 行 / 形态命中 218 / 其中 8 行非键名 / **纯键名分母 210**」（`C/readings-19.txt:88—91`）；**第 5—8 行**起逐行都是 `allow` 前缀小驼峰单标识（脚本一 `G05` 与脚本二 `M03` 的形态依据）；**第 185 行 `forceBypassScreenCaptureAlert`**——第 26 章 N8 的形态位；画面语义词命中的 13 个键在 `:95—107`，`allow*` 9／`force*` 4。
18. **`Restrictions` 载荷文档全文**（`B/mdm-restrictions.txt`，1,530 行 / 53,549 字节；与 `.srcx18/B/` 同名件逐字节相同）：键说明侧的落点，**两流结构**——1—1230 行说明句流、1231—1530 行 299 条 `CODE|` 片段流（条数由 `C/readings-19.txt:121` 给出，末行 1530 是派生器的段尾标记）。承重行：第 3 行载荷定义句；**第 29 行**「, the system disables incoming AirPlay requests.」；**第 726 行**「, the system disables remote screen observation by the Classroom app. Nest this key beneath …」（行尾断在 doc-link 上）；**第 729 行**「, the Classroom app doesn’t observe remote screens.」；**第 766 行**一个键同时禁用保存截图、屏幕录制采集与 Classroom 远屏观察；第 965／969 行两条 AirPlay 配对口令；**第 997 行**「, then the system bypasses the presentation of a screen capture alert.」与**第 998 行**「Available: macOS 15.1+」（第 26 章 N8：句子在、平台不对、主语回溯不到）；**第 1018 行**受管理课程学生「automatically gives permission … without prompting the student」；1392—1393 两条 `CODE| allowScreenShot`。

### 公告、KEV 与派生读数（C 组 6 件 / 312,121 字节 / 1,535 行）

19. **安全发布聚合词表**（`C/advisory-19.tsv`，1,267 行 = 表头 + **1,266 条记录** / 274,851 字节；列 `file / platform / component / cve / impact / avail`）：由 12 份 Apple 安全内容页（`adv-*.txt`，物理位于 `.srcx16/C/pages/`，本轮复用未重抓）经 `tools/adv-parse.pl` 重新解析。**1,266 条组件×CVE 对、330 个去重 CVE、129 个去重组件名、12 个平台版本行**（`C/readings-19.txt:2—5`）；含 `maliciously crafted` 的 467 行（`:55`）；画面外流六组件名逐字命中 40 行、13 个 CVE、6 个组件（`:8—16`）；平台分布 macOS 31／iOS 4／其余 5（`:27—28`、`:24—26`）；`ReplayKit` 只有 1 行（`:13`）。
20. **CISA KEV 目录的 Apple 切片**（`C/kev-apple.tsv`，96 行 = 表头 + 95 条 / 26,154 字节；列 `cveID / vendorProject / product / dateAdded / dueDate / ransomware / shortDescription`）：按 `vendorProject == Apple` 筛出。第 2 行 `CVE-2026-86950` 同时给出 `dateAdded 2026-09-29` 与 `dueDate 2026-10-13`，是脚本一 `S08`／`V03`／`R07` 日期形态校验的锚点；描述含画面语义词的 2 条在 `C/readings-19.txt:84—85`。
21. **KEV 目录元数据**（`C/kev-apple.tsv.meta.txt`，3 行 / 79 字节）：`catalogVersion`、`dateReleased`、`count`——**分母是 KEV 全目录条目数而不是 Apple 条目数**，本篇凡引用 KEV 比例必须带上这一格。
22. **十三组、36 个 R 号公开读数**（`C/readings-19.txt`，169 行 / 11,037 字节，`tools/readings19.pl` 只读产出）：第 16 章的主体，也是本篇唯一允许的行锚来源之一。读数 1 公告基线（`:2—5`）、读数 2 画面外流子集（`:8—16`）、读数 3 子集平台分布（`:19—28`）、读数 4 impact 画面词形十四项（`:31—45`，含 R10 的匹配形态演示 `:45`）、读数 4b 含 screen 行的组件分布（`:48—52`）、读数 5 crafted 交集（`:55—57`）、读数 6 Remote Management 同页跨面（`:60—63`，`:63` 是唯一一句直接写「看见画面」的影响句）、读数 7 子集内单 CVE 跨平台行数（`:76—79`）、读数 8 KEV（`:82—85`）、读数 9 MDM 键表分母链（`:88—94`）与 13 个键清单（`:95—107`）、读数 10 Restrictions 说明句九行（`:111—120`）与 `CODE|` 299（`:121`）、读数 11 平台安全指南本层段落（`:124—157`，R29 行数 4886、R30 命中 31 行、R31 Mirroring 6／ReplayKit 13／AirPlay 5）、读数 12 免交互措辞分布与子集交集（`:160—169`）。
23. **读数器告警留档**（`C/readings-19.err`，0 字节）：空文件。
24. **公告解析器告警留档**（`C/advisory-19.err`，0 字节）：空文件。**第 23、24 两条本身就是验收项**——第 23.4 节的派生器告警检查要求这两个文件长度为 0，非 0 即说明某组读数的输入形态发生了变化。

### 原始抓取件（RAW 组 15 件 / 691,523 字节）

25—39. 十五份 Apple 文档 JSON，与上面第 1—15 条一一对应（大小取自本轮 `wc -c`，逐件列出以便重放）：`replaykit.json` 24,131、`replaykit_rpscreenrecorder.json` 50,541、`replaykit_rpscreenrecorder_isrecording.json` 19,032、`replaykit_rppreviewviewcontroller.json` 41,932、`replaykit_rpsystembroadcastpickerview.json` 44,299、`replaykit_rpbroadcastsamplehandler.json` 33,953、`replaykit_rpbroadcastconfiguration.json` 24,337、`uikit_uiwindow.json` 104,111、`uikit_uiscene.json` 80,772、`uikit_uiscenesession.json` 32,958、`carplay.json` 125,872、`carplay_cpinterfacecontroller.json` 49,050、`avkit.json` 18,143、`homekit.json` 27,728、`quartzcore_calayer_contents.json` 14,664（合计 691,523 字节；`wc -l` 全部为 0——每份 JSON 是单行、无行尾换行，这正是约定第 2 条「一律先文本化再引用」的机器理由）。**本轮没有把任何一份 JSON 直接当归档引用**，全部经 `tools/jsondump.pl` 文本化成 `A/` 后才进正文。另有 `MANIFEST-A.txt`（18 行，位于存档根目录，不计入上面 72 件）逐条记录 slug／HTTP 码／字节数／行数：**第 13、14、18 行**三条 404 记录（`broadcastappextension`、`replaykit/rpbroadcastmanager`、`uikit/uiview/drawhierarchy`）逐字都是 `404|15639|SKIPPED`，正文不引用这三件——第 26 章 N13。

### 派生器与两支内嵌脚本（tools 组 7 件 / 119,105 字节 / 1,479 行）

40. `tools/jsondump.pl`（46 行 / 1,098 字节）：Apple 文档 JSON → 行式文本，按出现顺序取 `"text"` 片段、每片段一行。
41. `tools/html2txt.pl`（47 行 / 1,089 字节）：HTML → 行式文本，正文片段与代码片段分两流输出（约定第 6 条）。
42. `tools/adv-parse.pl`（34 行 / 1,165 字节）：安全内容页 → 六列 TSV（第 19 条）。
43. `tools/readings19.pl`（189 行 / 8,925 字节）：十三组、36 个 R 号读数器，输出到 stdout（第 22 条）。**第 134 行**是管理面键的词形过滤器（`screen|airplay|record|observ|mirr`），**第 148 行**是 Restrictions 说明句的词形过滤器（`screenshot|screen recording|AirPlay|remote screen|Classroom app`）——两道过滤器决定了 R23 的 13 个键与 R27 的 9 行清单各自包含什么，第 26 章 N8 那处「句子在但不在清单里」直接由第 148 行解释。
44. `tools/gen-tbl19.pl`（59 行 / 2,135 字节）：从两份留档日志逐码取「首现那一次实跑」与「跨全部实跑的累计条数」，渲染成正文第 23.2 节的两张三列表（`PART/tbl1.md` 27 行、`PART/tbl2.md` 24 行）。输入为脚本路径＋日志路径＋起始 R 号＋输出文件，只读日志、不改日志。
45. **正文第 21 章内嵌件：画面外流台账逐字段审查器**（`tools/screen-egress-ledger-review.sh`，490 行 / 50,802 字节）：三列台账、12 个命名空间、71 个信号码加 `J1`—`J4` 共 75 格；必备 12 格写在 usage 第 35—37 行，缺失按 `S09` 记（emit 第 375 行，跨 18 次实跑累计 **666**）；阻断清单在第 240—241 行（`S01`—`S09` 加 `K01`—`K03`，共 12 个）；判档次序第 468—472 行，阻断累加第 478 行，退出第 488 行；临时目录前缀 `scr19.`，外部命令普查 `awk=1 tr=3 cat=1 mktemp=3 rm=1`。
46. **正文第 22 章内嵌件：画面外流三件差集与公告子词表比对器**（`tools/screen-egress-tripartite-diff.sh`，614 行 / 53,891 字节）：十列三件清单、60 个信号码加 `Q1`—`Q4` 共 64 格；三件 20 项（采集件 7／落点件 5／告知件 8）与 11 个会话类前缀写在 usage 第 28—39 行；数组型核对项只有 `landing_destination`（第 39 行）；画面来源面在第 48—49 行、外流时点在第 50 行；阻断清单第 232—239 行（42 个）；第 92 行逐字写着「覆盖空洞、平面越界与三件不成对不计入阻断，只落 Q3（此时退出码仍为 0）」；逐值判定第 440—547 行、第 442 行 `if (c2 != kd) continue`；闭合定级第 561—564 行；临时目录前缀 `sct19.`，外部命令普查 `awk=1 cat=1 mktemp=2 rm=1`。两支脚本的逐条只读实证见第 23.1 节。

### 夹具、校验器与留档（FX 组 23 件 / 1,644,513 字节 / 9,302 行）

47—49. 三档台账夹具（脚本一输入）：`FX/ledger-19-good.txt`（256 行 / 9,477 字节）、`FX/ledger-19-mid.txt`（196 行 / 7,676）、`FX/ledger-19-bad.txt`（806 行 / 31,676）——分别对应 J1／J2—J3／J4 三种形状。
50—53. 四档三件清单夹具（脚本二输入）：`FX/tri-19-good.txt`（184 行 / 20,312）、`FX/tri-19-mid.txt`（9 行 / 937）、`FX/tri-19-bad.txt`（77 行 / 7,987）、`FX/tri-19-crafted.txt`（2 行 / 247，只在子词表里的组件名，用来触发 `X01` 的反向判据）。
54—55. 三件能力表：`FX/capability-19.csv`（182 行 / 7,768 字节 = 2 行口径注释 + 180 条数据行 = **9 个建模类 × 20 项核对项**，取值分布 required 89／optional 41／not_applicable 50／**undocumented 0**，本轮逐列重数）与 `FX/capability-19-bad.csv`（12 行 / 483，逐 C 族信号码各给一行）。
56—58. 公开词表三件：`FX/vocab-19.tsv`（91 行 / 5,576 字节 = 3 行注释 + 1 行表头 + **87 条数据行**，九类分布 `advisory_cve` 18、`session_kind` 16、`api_symbol` 16、`restriction_key` 13、`advisory_component` 12、`advisory_component_crafted` 6、`plist_key` 3、`process_name` 2、`endpoint_tag` 1；good 档实跑读 `去重词条=80`）、`FX/vocab-19-bad.tsv`（6 行 / 221）、`FX/vocab-19-subset.tsv`（92 行 / 5,627，子词表件）。**夹具合计 97,987 字节、全部为合成标识与合成取值**，不含真实文件名、真实画面内容、设备绝对路径或任何形似密钥的串。
59—61. `FX/code-uniqueness.pl`（33 行 / 1,727 字节，校验两支脚本信号码不重号、族内连续）、`FX/code-coverage.pl`（29 行 / 1,110 字节，校验留档日志里每个码至少触发一次）、`FX/tbl-check.pl`（56 行 / 2,269 字节，校验两张三列表的累计数与日志逐码累计一致）。
62—63. `FX/run-all.sh`（136 行 / 4,608 字节，脚本一 18 次实跑驱动）与 `FX/run-all-tri.sh`（78 行 / 2,966 字节，脚本二 15 次实跑驱动）。
64. `FX/coverage-report.sh`（87 行 / 5,896 字节）：逐码可达性汇总，产出第 23.3 节的覆盖表与 `FX/coverage-proof.txt`。
65. `FX/readonly-proof.sh`（92 行 / 7,029 字节）：第 23.1 节二十段只读实证的执行器——P1—P10 针对脚本一、P11—P20 针对脚本二，两半结构对称。
66—67. **`FX/run-log.txt`（脚本一 18 次实跑留档，2,444 行 / 308,164 字节）**与 67. **`FX/run-log-tri.txt`（脚本二 15 次实跑留档，4,157 行 / 1,196,854 字节）**：两件合计 1,505,018 字节，是第 23.2 节两张表与第 27 章全部累计数的唯一来源。
68—69. `FX/coverage-proof.txt`（136 行 / 7,144 字节，22 段：C1—C22，含 C21「表内格 75｜脚本一定义码 75｜不一致 0」与 C22「表内格 64｜…｜不一致 0」）与 `FX/readonly-proof.txt`（141 行 / 8,759 字节，25 段）：两份验收转录，合计 15,903 字节——前者记 139 个号全部触发（75 与 64 两格集），后者记二十段实证与临时目录残留检查。

### 本轮索引（IDX 组 3 件 / 57,776 字节 / 251 行）

70. **`IDX/sources-19.md`（73 行 / 26,484 字节）**：逐件承重行清单＋分组小结＋两条抽取器限制＋工具与夹具清单。它是「行号落在哪一件」的台账。**本轮重数与它有两处不符**：组 C 记「311,547 字节」而 `wc -c` 逐件相加是 **312,121**（差额 574 字节来自 `C/readings-19.txt` 与 `C/advisory-19.tsv` 的本轮再产出）；组 B 记平台安全指南 4,885 行而读数 R29 给 4,886（差一行是末行无行尾换行的计数口径差，正文按引用行号照旧、按 `wc -l` 报件数）。两处都按「重数为准」处理并在此登记。
71. **`IDX/overlap-19.md`（62 行 / 14,399 字节）**：与既有十八篇的逐篇分界表（主键选择依据、用词普查、语料可行性预检、本篇红线与拒收）。第 2 章的分界表与本表末尾那段相邻篇目句都从这一件来；**本篇正文里凡引用其它篇目的行号，一律逐字取自这一件**，取不到行号处只写分界不写行号。
72. **`IDX/brief-19.md`（116 行 / 16,893 字节）**：装配简报——章节与目标行数分配、目录锚点、十一层与脚本一命名空间的映射、脚本二模型、36 个 R 号必读清单、引用纪律六条与红线。**其中一处列数口径要在本表说清**：简报第 4 节记「画面来源面 9、外流时点 7」是按业务取值加 `not_recorded` 计的，而 usage 第 48—50 行实际列出的 token 含 `unknown` 控制值是 10 与 8；本篇正文一律写成「若干取值加两个控制值」，不引用这两个列数，避免读者拿两套口径去对同一列。

### 抓取与派生约定（九条）

1. **Apple 文档 JSON 端点**：统一走 `https://developer.apple.com/tutorials/data/documentation/<slug>.json`。这些是静态可取的，而对应的 HTML 页面由 JS 渲染，直接文本化取不到正文——本轮 15 件里没有任何一件来自 HTML 页。
2. **一律先文本化再引用**：正文与脚本的行号只指 `A/`／`B/`／`C/` 三组文本件，不指 `RAW/`。`RAW/` 里每份 JSON 都是单行无换行件（`wc -l` 为 0），行号概念在其上根本不存在。
3. **404 会返回一个同形的 15,639 字节错误 JSON**，所以每次抓取都要同时核对 HTTP 状态与字节数——只看文件存在与否不足以判定抓到了正文。`MANIFEST-A.txt` 逐件记字节数就是为了这一条可复算，那三条 404 也是这么被认出来的（第 26 章 N13）。
4. **slug 里的 `/` 在 JSON 内转义成 `\/`**，落盘文件名同样把 `/` 换成 `_`；派生器不做还原，符号名比对必须在还原形态上做，脚本二的 X 族判据即按还原形态写。
5. **doc-link 处会断句，只引每行完整的前半句**：`jsondump.pl` 取 `"text"` 片段时会丢弃行内 doc-link 的显示名，所以 `A/replaykit.txt:5` 结尾是「ReplayKit is incompatible with 」、`A/replaykit_rpscreenrecorder.txt:13` 结尾是「Your app can’t record video from 」、`A/uikit_uiwindow.txt:18` 结尾是「as described in 」。本轮曾试过把片段按段落合并，实测会把导航区的抽象描述全并成一行（`END-SEGMENTS=5`），可读性反而更差，已放弃并保持 v1 输出。
6. **`html2txt.pl` 把正文片段与代码片段分成两个流**：`B/mdm-restrictions.txt` 的 1—1230 行是说明句流、1231—1530 行才是 299 条 `CODE|` 片段。后果是说明句里的「If ⟨键⟩, the system disables …」在这一份归档里回溯不到键名（`:29`、`:726`、`:766`、`:997` 四行都以逗号开头），而 `CODE|` 流里形似标识的 token 去重后只有 12 个（其中两个是 `true`／`false` 取值行）、画面语义词只出现 `allowScreenShot` 与 `ScreenObservationPermissionModificationAllowed`。这是第 17 章「管理面自身的两处错位」的实证，也是第 26 章 N8 的全部依据。
7. **键表类页面按行取键必须先剔除分段标题**：见第 17 条——220 行 / 形态命中 218 / 非键名 8 行 / 纯键名 210。直接按行数当键数会让管理面分母虚增 10（第 18 篇同一口径，两篇可交叉引用而不换算）。
8. **复用件必须 `cmp` 而不是只比行数**：本轮 `B/` 组三件与 `.srcx18/B/` 同名件全部逐字节相同才写作「同一版本副本、本轮不重抓」；`C/kev-apple.tsv` 与其 `.meta.txt` 沿用同目录版本；公告页输入（12 份 `adv-*.txt`）物理位于 `.srcx16/C/pages/`，只复用输入、本轮重新解析成 `C/advisory-19.tsv`。
9. **命中数一律带匹配形态，累计数一律带实跑来源**：同一列原样匹配大写 `VNC` 得 6、整列小写化后用大写模式得 0、小写化加小写模式得 6（`C/readings-19.txt:45`）；第 23.2 节两张表的每个累计数都由 `tools/gen-tbl19.pl` 从 `FX/run-log.txt`／`FX/run-log-tri.txt` 逐码取，C21／C22 现场重数不一致为 0。**本轮两处与索引的重数差（组 C 字节、指南行数）已写在第 70 条，一律以重数为准并留痕，不改索引原件。**

### 本篇没有做的事

- **没有做任何设备侧操作**：不采集 Console 或日志、不跑 `file`／`mdls`／`mdimport`／`mdutil`／`mdfind`／`spctl`／`codesign`／`defaults`／`log`／`sysctl`／`xcrun`／`profiles`／`plutil`／`sips`／`qlmanage`／`otool`，不打开任何被登记的会话对象，不构造录制或广播产物。两支脚本的输入只有台账文本、三件清单、能力表与公开词表四类夹具。
- **没有构造恶意文件、没有做格式畸形化、没有定位解析缺陷、没有复现崩溃、没有投递载荷**；`impact` 列里 `maliciously crafted` 那 467 行在本篇只作为聚合级词表分母使用，不引任何单条缺陷。
- **没有指导关闭或欺骗采集提示，没有利用 `forceBypassScreenCaptureAlert`，没有给出任何绕过隔离标记、告知流程或管理面审计的做法，没有提供任何免交互触发路径**；正文不使用任何声称「无需用户动作即可让画面离开设备」的措辞，画面离开设备的时点只写成「录制／镜像／投屏这三类会话建立之后」（依据是 `C/readings-19.txt:160—169` 那五条读数，见第 26 章 N1）。
- **没有把公告侧读数写成 iOS 结论**：子集里 macOS 31 行、iOS 4 行、其余 5 行（`:27—28`、`:24—26`），每条公告读数都带平台行；KEV 95 条里没有一条把画面外流写成在野利用后果（`:82—85`）。
- **没有引用 XNU／Darwin 开源侧实现、没有引用第三方研究博客或 CVE 描述页**：本轮全部来源限于 Apple 文档 JSON、Apple Platform Security 指南文本、Apple 安全发布页与 CISA KEV 官方目录四类。
- **没有重建相邻篇目的客体**：XPC 端点实现与进程宿主归属归第 06 篇、局域网可达性与被看见归第 16 篇、内容类型判定与三件类型轴归第 18 篇、留存与同意记录归第 13 篇、防截屏有效性评测归第 03 篇（逐条分界见 `IDX/overlap-19.md`）。
- **没有给每一格都配上一段文档句**：第 17.4 节与第 26 章十四条边界明确区分「哪一格有文档句、哪一格只有口径、哪一格连句子都没有」，这是本篇承认的方法论限制，不是遗漏；本篇也没有把任何一格判成能力表的 `undocumented`（0 格），这件事本身是第 26 章 N14。

---

**同系列相邻篇目。** 本篇与已发布的十八篇有交接，也有硬分界：**第 01 篇（iMessage 入口与附件）**——消息附件的自动解析与渲染预览归它（01 第 50、169 行）；本篇不论证入口、不重建攻击链时序，因为一帧画面被录走时不需要任何附件。**第 02 篇（访问控制与应用层交互）**、**第 04 篇（认证通道加密）**、**第 09 篇（更新链与补丁传导）**、**第 10 篇（设备归属与转移）**、**第 12 篇（第三方代码供应链）**——这五篇的既有正文里没有任何一处讨论画面离开设备（逐词普查见 `IDX/overlap-19.md` 的用词表），本篇不引用它们的结论；管理面键在本篇只表示「这一格能否被策略关掉」，不表示所有权、供应链或加密强度。**第 03 篇（应用防护与抓包审计）**——「截图/录屏通知 ↔ 是否有防截屏机制」的对照行与防截屏硬件级实现归它（03 第 2882、3284 行）；本篇不做防护有效性评测、不给任何绕过告知的做法，判的是这一帧走哪条通道、哪一面读得回。**第 05 篇（生物识别安全机制）**——Secure Enclave 模型本体归它（该篇 24 处相关论述，无一对应画面出流）；`:1439` 那句「The Secure Enclave on the Mac enforces this user choice」在本篇只作为「授权被硬件强制」的读数。**第 06 篇（XPC 与 Mach IPC）**——服务清单与「公告组件名 ↔ 设备侧表现」的落差表归它（06 第 11、13、138 行）；`com.apple.broadcast-services` 端点（`:4249`）与 out-of-process 预览 UI（`:4245`）在本篇只登记为通道件，其 XPC 端点语义归 06。**第 07 篇（推送链路）**——锁屏录制提示可被消除的那条公告归它（07 §16.5 第 1094 行，组件行 `Share Sheet`），通知呈现层归属也归它（第 762、778 行）；本篇不重述该 CVE 的修复口径，只把提示当告知面可读回的样例——提示**出现过**与画面**流出去过**是两格。**第 08 篇（隐私授权与用途声明）**——用途串、隐私清单与 required reason 全模型归它；画面外流没有对应的隐私键，同意对话框由框架呈现（`:4241`），不经用途声明，所以「申报了」推不出「能出流」。**第 11 篇（备份与恢复数据副本）**——副本在谁手上、可不可解归它；录影产物落在「只有 ReplayKit 子系统可访问、任何 App 都不可访问」的目录（`:4244`），它既不是副本也不是可导出对象。**第 13 篇（日志与诊断证据链）**——采集时刻—导出时序归它（13 第 370 行）；本篇只把会话结束横幅与锁屏通知登记为观测件，不进入留存讨论。**第 14 篇（签名与分发授权链）**——描述文件、公证与运行授权归它；广播扩展要靠端点配置才参与（`:4249`）是**通道准入**而不是运行授权，两者在台账里分列两格。**第 15 篇（网络扩展与代理/VPN 通道归属）**——六个通道词形在去重组件名里全部命中 0 的词形差集法归它（15 第 21、201 行）；方法与本篇同源而方向相反——本篇用画面语义词表，实测 14 个词形里 10 个命中 0（`C/readings-19.txt:31—44`）。**第 16 篇（本地网络访问与局域网发现）**——AirPlay 作为被发现服务的 6 处、`allowAirDrop` 等相邻键差集、以及 FAQ 里明确把「投屏协议栈」留给后续的那一句（16 第 2641 行）归它；16 判「谁能在局域网上看见这台设备」，本篇判「这台设备的画面有没有被别人看见」，`allowAirPlayIncomingRequests`（`B/mdm-restrictions.txt:29`）在两篇里分属两个平面。**第 17 篇（聚焦索引与 Siri 建议链路归属）**——检索面可查询性与 `type_identifier` 形态双检归它；帧内容不进检索面，`Siri` 组件那 1 行含 screen 的公告（`C/readings-19.txt:51`）说的是屏上文本而不是画面流。**第 18 篇（非可信内容解析链路）**——内容被判定成哪个类型、由哪条通道读回归它，`screenshot` 一词的 10 处也在它那里；**三件的第二件在两篇含义不同**：18 的通道件是「解析器能否把类型读回来」，本篇的通道件是「画面能否被带走」；同一份公告列在 18 里 crafted 与画面词的交集是 0（`C/readings-19.txt:56`，与 18 篇同一件同一行），本篇把这条 0 直接当作「内容侧口径与出流侧口径互不相通」的实证（第 27 章结论三）。**第 20 篇（卷、挂载与文件系统形态归属）**——落点所在卷的形态、挂载选项与密钥栈归它；本篇的落点件只判「写到哪块存储、哪些进程能看见」，20 篇判「那块存储是什么卷、由谁挂上、哪一级密钥在保护它」，两篇以「落点」为界，不互相引用结论。各篇分界的逐条实测记于 `IDX/overlap-19.md`。

---

咨询ios系统请咨询 telegram：https://t.me/one00190
