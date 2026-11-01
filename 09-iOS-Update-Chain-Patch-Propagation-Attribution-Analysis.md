---
title: "iOS 更新链与补丁传导归属防御分析报告"
description: "iOS 更新链的十层表面分解：安全公告与 CSAF 口径、GDMF 目录与签名时效、安装授权服务器与个性化、OTA 与恢复分发形态、整版本更新与 Background Security Improvements（cryptex）、MDM 延期与自动动作策略、声明式强制更新与 enrollment 闸门、状态项回执与两套 install-state 词表、移除与回滚、配件与外设固件旁路通道；P1—P12 缺陷类型学、公告/设备策略/外部应急三套词表、层 × 责任方 × 更新通道归属矩阵、四级判定模型与两个离线只读核验脚本"
lang: zh-CN
---

# iOS 更新链与补丁传导归属防御分析报告

## 摘要

一条 iOS 安全补丁从 Apple 发布公告走到"这台设备上已经生效"，中间要过十格。本报告集前八篇讨论的缺陷，绝大多数默认这十格是背景板；本文把它挪到前景，只问三件事：**补丁在哪一格停下、这一格的修改权在谁手里、修完之后要等多久才在设备上出现读数**。

这条链路最反直觉的地方在于：**它在每一格都有公开文档，但没有任何一格的公开产物能换算出"这台设备现在安全吗"**。公告侧给的是 CVE 与组件名（"Apple security documents reference vulnerabilities by CVE-ID when possible."，《About the security content of iOS 27.2 and iPadOS 27.2》第 22 行）；设备与管理侧给的是版本形态与状态词（`softwareupdate.install-state`、`device.operating-system.supplemental.extra-version`）；外部应急侧给的是一个必须完成修复的日期（CISA KEV 的 `dueDate`）。三套词表互不通约，于是产生了本文第 3 章列举的七处**换算失败**，其中三处是文档自己互相打脸：状态项页的 install-state 取值表只有 5 个值、不含 `waiting`，而部署指南同一段列了 6 个值并把 `waiting` 排在第二位；延期策略在属性页写着 "Background Security Improvements aren't considered in Major, Minor, or System deferral mechanism"，在同一条链路的部署指南旁注里又写着 "Deferring software updates also defers any Background Security Improvements that are dependent on that version"；`restrictions` 里那两个仍在生效的键名至今叫 `allowRapidSecurityResponseInstallation` 与 `allowRapidSecurityResponseRemoval`，而它们的说明已经全部改写为 Background Security Improvements。

第 4—13 章逐层给出这一格的输入、输出、失败形态与可得证据；第 14 章按"在哪一次校验被放过"建立 P1—P12 类型学；第 15 章给出层 × 责任方 × 更新通道 × 证据的归属矩阵，并按"修完之后等多久"重排；第 16 章用本轮存档算出 18 条公开读数，其中四条决定了本文的基调：**2026-10-26 同一天并行发出的两条 iOS 线，27.2 修 163 个 CVE、67 个组件，26.7.2 修 134 个 CVE、54 个组件，交集 119、各自独占 44 与 15；同一条版本线上相邻两次更新（26.7 与 26.7.2）的 CVE 集交集为 0；Apple 公告表 331 行里有 61 行（18.4%）只写着"This update has no published CVE entries."；KEV 里 95 条 Apple 在野条目的修复窗口是 21 天（63 条）与 14 天（22 条），而 MDM 允许的最长延期是 90 天**。也就是说：约束点不在"厂商有没有发补丁"，而在"这一格允许被谁推迟多久、以及推迟之后有没有任何读数会变"。

核验部分提供两个纯文本、离线、只读的脚本：一个把一份"更新策略台账"（MDM 侧配置与状态项的文本导出件）按 Apple 文档口径审一遍，逐条预演"这一格写成这样时，设备与管理服务会读到什么"；一个把若干份公告的 CVE 集与在野条目集做并集/差集运算，回答"这台设备从版本 A 走到版本 B 实际获得哪些修复、哪些在野条目还没有落在它的版本线上"。两者都在本轮做了全量分支覆盖验收，信号码共 63 个（脚本一 41 个、脚本二 22 个），全部在本轮环境实跑触发。

本文不提供任何可用的漏洞利用代码、提权或绕过步骤、降级或篡改更新签名的操作方法，也不提供任何针对具体设备的攻击动作；给出的只有公开文档口径、公告口径、外部应急口径，以及读者对**自己手上的公告文本、自己导出或抄录的策略台账**能做的只读判定。两个脚本都不联网、不写设备、不修改输入文件、不调用 `softwareupdate`、`mdmclient`、Xcode 或任何网络接口，也不向 `gdmf.apple.com` 发任何请求；中间文件只落在系统临时目录并在退出前删除。

---

## 目录

1. [引言](#1-引言)
2. [视角声明与本文边界](#2-视角声明与本文边界)
3. [三套词表：公告口径、设备与策略口径、外部应急口径](#3-三套词表公告口径设备与策略口径外部应急口径)
4. [L1 发布与公告层](#4-l1-发布与公告层)
5. [L2 版本可见层：目录、机型与签名时效](#5-l2-版本可见层目录机型与签名时效)
6. [L3 授权与个性化层](#6-l3-授权与个性化层)
7. [L4 分发与装配层](#7-l4-分发与装配层)
8. [L5 安装形态层：整版本与 Background Security Improvements](#8-l5-安装形态层整版本与-background-security-improvements)
9. [L6 策略与延期层](#9-l6-策略与延期层)
10. [L7 强制与申报层](#10-l7-强制与申报层)
11. [L8 回执与读数层](#11-l8-回执与读数层)
12. [L9 回滚与移除层](#12-l9-回滚与移除层)
13. [L10 外设与旁路通道层](#13-l10-外设与旁路通道层)
14. [缺陷类型学 P1—P12](#14-缺陷类型学-p1p12)
15. [归属矩阵：层 × 责任方 × 更新通道 × 证据](#15-归属矩阵层--责任方--更新通道--证据)
16. [公开读数：这条链路上能数出来的十八件事](#16-公开读数这条链路上能数出来的十八件事)
17. [可见性边界：这条链路上读者能拿到什么](#17-可见性边界这条链路上读者能拿到什么)
18. [设备侧与管理侧读数面](#18-设备侧与管理侧读数面)
19. [四级判定模型](#19-四级判定模型)
20. [运营指标 O1—O10](#20-运营指标-o1o10)
21. [只读核验脚本一：更新策略台账审查器](#21-只读核验脚本一更新策略台账审查器)
22. [只读核验脚本二：公告覆盖差集比对器](#22-只读核验脚本二公告覆盖差集比对器)
23. [两个脚本的全量分支覆盖验收](#23-两个脚本的全量分支覆盖验收)
24. [十二个误区](#24-十二个误区)
25. [常见问题](#25-常见问题)
26. [未公开文档化边界清单](#26-未公开文档化边界清单)
27. [结论](#27-结论)
28. [参考资料](#28-参考资料)

---

## 1. 引言

### 1.1 为什么把更新链单独立一篇

"把系统升到最新版"是 iOS 安全建议里出现频率最高的一句话，它甚至直接写在 Apple 的公告页上（"Keeping your software up to date is one of the most important things you can do to maintain your Apple product's security."，《Apple security releases》第 24 行）。但这句话在工程上是一个**黑盒**：它假设补丁会发布、会进目录、会被设备发现、能通过签名校验、能下载、能装配、能被安装、装完之后版本会变、变了之后不会被撤掉。这十个假设每一个都有公开文档，每一个都可能失败，而且**失败时设备的表现和"根本没有这个补丁"完全相同**。

公开讨论里有三种讲法都绕开了这条链路。产品与媒体讲成**意愿问题**（"用户为什么不更新"）；企业侧讲成**工具问题**（哪个 MDM 能强制更新）；安全研究讲成**漏洞问题**（哪个 CVE 还在野）。三种讲法各自只覆盖链路的一小段，于是出现了两类都有害的结论：一类是"公告发了就等于修好了"（本文第 5、6 章会说明：一篇公告的有效期是被签名到期日约束的，过期之后**这版补丁在技术上就不可能再装上**）；另一类是"设备显示已是最新就等于安全"（第 11 章会说明：状态项里没有任何一格能回答"哪个 CVE 已经生效"，`none` 这个读数的原话是"没有待更新的软件，且上一次更新成功了"，它同时兼容"这台设备落在一条已经不再收到修复的版本线上"）。

本文的目标是把这两种结论换成**可核对的层归属**。

### 1.2 这条链路的规模感

有六个可以直接从本轮存档里数出来的规模数字，构成本文"这张表有多大"的直觉：

1. **策略侧的键表**。`com.apple.configuration.softwareupdate.settings` 一个声明里可配置的顶层属性 7 个（`AllowStandardUserOSUpdates`、`AutomaticActions`、`Deferrals`、`Notifications`、`RapidSecurityResponse`、`RecommendedCadence`、`Beta`，《SoftwareUpdateSettings》第 70—76 行），其中 `Deferrals` 对象内部只有 4 个整数键、每个都是 `minimum=1; maximum=90`（《SoftwareUpdateSettingsDeferralsObject》第 11—14 行）。
2. **强制侧的配置块**。`com.apple.configuration.softwareupdate.enforcement.specific` 的必填项 2 个（`TargetLocalDateTime`、`TargetOSVersion`）加可选 1 个（`TargetBuildVersion`），《SoftwareUpdateEnforcementSpecific》第 58—60 行；整条强制流程按《Phases of software update enforcement》第 5 行的口径分成五个主要参与方与七个阶段。
3. **回执侧的状态词**。本轮取回 11 个状态项页，其中软件更新侧 6 个（install-state、install-reason、failure-reason、pending-version、device-id、beta-enrollment）、系统版本侧 4 个（version、build-version、supplemental.build-version、supplemental.extra-version）、设备标识 1 个（UDID）。`install-reason` 有 8 个取值，《Deploying software updates using declarative management》第 63—70 行；`install-state` 在同一篇文档里是 6 个取值（第 56—61 行），在它自己的状态项页里只有 5 个（第 33 行）。
4. **目录侧的三张清单**。`https://gdmf.apple.com/v2/pmv` 的 JSON 响应含三个列表：`PublicAssetSets`、`AssetSets`、`PublicBackgroundSecurityImprovements`（《Deploying software updates using declarative management》第 8—11 行），每个元素带 `ProductVersion`、`Build`、`PostingDate`、`ExpirationDate`、`SupportedDevices`（同页第 12 行），并且**签名有效期通常只到发布后 180 天**（同页第 13 行）。
5. **公告侧的两条线**。本轮取回 3 份 CSAF v2.1 公告（APPLE-SA-149230 / 149227 / 149041）与 1 份对应的 HTML 公告页。同一天（2026-10-26）发布的两条 iOS 线：163 个 CVE / 67 个组件，与 134 个 CVE / 54 个组件；`Apple security releases` 整表 331 行、跨 84 个发布日、覆盖 2024-01 至 2026-10。
6. **外部应急侧的窗口**。CISA KEV 目录（`catalogVersion: 2026.10.30`，全库 1766 条）里 `vendorProject` 为 Apple 的条目 95 条，修复窗口分布为 21 天 63 条、14 天 22 条、181 天 9 条、3 天 1 条。

第 3 章说明这六堆东西为什么不能互相换算；第 14 章给出跨越它们的类型学；第 15 章给出"这一格归谁"的矩阵；第 21—23 章给出读者可以立刻执行的只读核验。

### 1.3 本文的三个问题

1. **分型问题**：一条补丁没生效，是断在"公告里没有它"、"目录里没有它或它已过期"、"个性化闸门不放行"、"下载与装配失败"、"该走 BSI 的东西只能在整版本里拿到"、"策略允许它被推迟"、"强制配置写错了目标版本"、"回执里根本看不出来"、"装完之后被撤掉了"，还是"这一层根本不在 iOS 更新通道上"？（第 14 章 P1—P12）
2. **归属问题**：这一格的修改权在谁手里——Apple 的发布与安全工程、Apple 的目录与安装授权服务、MDM 产品厂商的声明模板、企业 IT 管理员的取值、设备用户的一次点击、配件固件的发布节奏，还是"这个版本线还有没有人在维护"这件事本身？（第 15 章矩阵）
3. **自证问题**：读者手上只有公开公告、公开文档、一份自己抄录或导出的策略台账时，能做哪几种可复现的只读判定？（第 16—18、21—23 章）

### 1.4 阅读顺序建议

只关心"我这台设备到底算不算打上补丁了"的读者，直接看第 11、16 章和第 22 章脚本；企业侧配置更新策略的看第 9、10、11 章和第 21 章脚本；关心"这个补丁为什么还没到我的机型"的看第 5、6、10 章；关心"这个缺陷该谁修"的看第 14—15 章；关心"我在不碰设备的前提下能自证什么"的看第 17、19、23 章。第 2 章的边界声明要先读一次，它规定了本文与本报告集其他篇目、以及 Android 系列同主题篇目之间的重叠怎么处理，也规定了本文的英文引语按什么口径转录与复核。

---

## 2. 视角声明与本文边界

本文是"归属与口径"视角的更新链分析，不是升级教程，不是 MDM 部署手册，不是补丁管理产品对比，也不是 CVE 榜单。

**与本报告集 iOS 其他篇目的关系**：

| 主题 | 本文覆盖 | 去处 |
| --- | --- | --- |
| iMessage 攻击入口（第 01 篇） | 不覆盖。本文不讨论任何消息链路 | 第 01 篇讲攻击面本身 |
| 访问控制与应用交互（第 02 篇） | 不覆盖。第 9 章只处理"谁能装"（`AllowStandardUserOSUpdates`）这一格 | 第 02 篇讲权限模型 |
| 应用防护与抓包审计（第 03 篇） | 只在第 7 章引一句 VPN/代理阻断更新的文档口径；不做任何流量抓取或查看 | 第 03 篇讲应用侧防护与自有流量审计 |
| 身份认证与通道加密（第 04 篇） | 不重述认证与传输加密。第 6 章的签名校验讲的是**代码授权与版本许可**，与通道加密是两件事 | 第 04 篇讲认证链路全景 |
| 生物识别安全机制（第 05 篇） | 只在第 10 章把 Secure Enclave 作为"防降级"的实现者引一句 | 第 05 篇讲生物识别机制 |
| XPC 与 Mach IPC（第 06 篇） | 不覆盖进程间通道。更新链上的守护进程之间的通信不在本文范围内 | 第 06 篇讲端口、名称空间与对象层 |
| APNs 推送链路（第 07 篇） | 只在第 10 章涉及"声明同步靠推送触发"这一句；不重述投递与预算 | 第 07 篇讲十层推送校验 |
| 隐私授权链路（第 08 篇） | 重叠点是"崩溃计数变化可能来自静默补丁通道"。本文第 8 章给出该通道在文档口径下的完整形态与可得条件，不重述那篇的授权状态机 | 第 08 篇讲授权链路的十格校验 |
| 日志、诊断与崩溃证据链（第 13 篇） | 不覆盖。本文的公告读数只到"CVE、组件、影响、可用机型"这一层；第 13 篇把这条链往下接一格——崩溃报告栈帧给出的是 binary image 名，公告给出的是产品功能组件名，两者之间没有官方映射表，因此它把默认回查结论写成 `component_absent` 而不是"没有缺陷"。本文不重述日志级别、留存规则与采集通道口径 | 第 13 篇讲一条日志、一份崩溃报告、一包诊断数据能不能作证；两篇共用同一批公告导出件，但问的不是同一件事（那篇问公告能不能把证据回到缺陷，本文问公告是否覆盖到这一版） |
| 越狱 / 锁定模式 / 内存损坏 / 沙箱逃逸 / 内核提权 / 漏洞套件 | 不覆盖。本文的公告读数只到"CVE、组件、影响、可用机型、有无 CVE 条目"这一层，不推断利用原语，也不给出任何绕过更新校验的做法 | 各对应篇目 |

**与 Android 系列同主题篇目的关系**（本报告集跨平台读者常问的一句）：Android 第 13 篇讲的是**补丁在"Google 平台侧 → OEM 定制侧 →  carrier/机型侧"三级主体之间的传导**，其核心不对称是"公告主体和分发主体不是同一个"。iOS 这条链路是另一种形状：**发布、目录、授权、分发四个环节全部由同一个主体（Apple）持有**，因此不对称不发生在"谁发的"，而发生在**"允许被推迟多久"与"有没有任何读数能证明补丁在这一台上生效"**。两篇共用归属矩阵这套方法，但读的是完全不同的文档面，不构成重复：那篇的公开产物是 Android Security Bulletin、AOSP 标签与 OEM 公告；本文的公开产物是 Apple 安全公告/CSAF、MDM 声明文档、平台安全指南的更新章节与 CISA KEV。

一句话：**其他篇讲的是边界两侧的东西，本文讲的是补丁从公告走到设备上这一路的十格校验，以及这三套公开产物之间的落差**。

**范围声明**：全文只讨论公开文档化的机制、Apple 安全公告与 CSAF 的公开条目、CISA KEV 的公开条目，以及在这些公开规则之上可以安全实施的只读判定。本文不提供：可用的漏洞利用代码；生成、替换、伪造或绕过 Image4/个性化签名的操作方法；把设备降级到旧版本、绕过"不可降级"限制或重建旧系统卷的做法；关闭或规避 Background Security Improvements、篡改 MDM 声明或伪造状态上报的操作步骤；针对特定设备、特定 UDID 或特定 ECID 的探测动作；对 Apple 安装授权服务或目录服务的请求构造、参数猜测或重放。第 21、22 章两个脚本都是离线文本处理：一个读一份"更新策略台账"文本（每行一条〈键,值〉或〈状态项,读数〉记录），一个读若干份"CVE 集与在野条目集"文本，两者都不写设备、不联网、不修改输入文件、不调用 `softwareupdate`、`mdmclient`、`plutil`、Xcode 或任何网络接口，中间文件只落在系统临时目录并在退出前删除。所有"核验"指读者对**自己抄录或导出的文本、公开公告与公开目录件**执行采集与比对。

**引用转录约定**：英文原文按原样转录，只做两项字符归一——排版撇号（’）写作 ASCII 撇号（'），排版引号（“ ”）写作直引号（"）；其余字符、大小写不改。复核时还要允许下面七种**排版层差异**，它们不是转录差异：

1. **空白折叠**。存档页面会折行，词与词之间可能隔一个换行或一串空格；检索时把引语里的空格当作"至少一个空白字符"。
2. **文档页是 JSON 扁平件**。Apple 开发者文档的取回形态是一行一个内容项的扁平文本，属性行被拍平成 `PROP 键 [类型注解] 说明` 一整行（形如 `PROP CombinedPeriodInDays [integer; minimum=1; maximum=90] Specifies the number of days…`）。本文引属性时按**整行**引用，不做跨行拼接，也不重排其中的方括号。
3. **链接标签缺口**。扁平正文里页面内超链接只留下 `doc://…` 形式的目标标识，标签文本在该页的 references 表里。遇到这种情况本文只引到可核对的前半句。
4. **破折号**。原文里的双连字符 `--` 在页面上渲染为破折号，本文按渲染形态（—）转录。
5. **省略号**。`…` 与 `...` 都代表原文中被删去的一整段，长度不固定，复核时按不定长空洞匹配。
6. **反引号**。引语内出现的反引号是本文的 markdown 代码标记；**但有两处例外**：《Phases of software update enforcement》第 30 行的 ``failed`` 与第 37 行的 ``StatusDeviceOperatingSystemSupplementalExtraVersion`` 之后的反引号、《Deploying software updates using declarative management》第 70 行 ``declaration`` 之前的反引号，是**存档件里就存在的字符**（原页面代码片段与正文混排的残留）。本文在这两处要么只引反引号之前的半句，要么原样保留并在需要时注明"该字符存在于存档件"。
7. **状态项名与文档标题名不同形**。状态项页的标题是 Swift 类型名（`StatusSoftwareUpdateInstallState`），实际写在 `StatusReport` 里的点分键名是 `softwareupdate.install-state`。本文引取值表时说明用的是哪一形。

三类已知的存档缺口**就地注明、不做修补式改写**：

- **缺口 A（字典对象页未取回）**：`softwareupdate.failure-reason` 与 `softwareupdate.install-reason` 的类型都是字典对象（《StatusSoftwareUpdateFailureReason》第 37 行、《StatusSoftwareUpdateInstallReason》第 39 行），对象内部的**逐字段取值表**在各自的 DictionaryObject 页；本轮未取回这些页。因此本文凡是涉及"失败原因具体有哪几个码"的地方一律写"文档未在本轮可核对范围内给出"，第 26 章列为缺口 G1，绝不自行补一个列表。
- **缺口 B（目录响应件不可得）**：`gdmf.apple.com/v2/pmv` 的**实际 JSON 响应**本轮不取（本文两个脚本被明令禁止联网），因此 `ExpirationDate` 的具体算法、`SupportedDevices` 的机型串写法只有文档口径可引。第 26 章缺口 G2。
- **缺口 C（平台安全指南的 PDF 分页件）**：《Apple Platform Security》以 PDF 取回并 `pdftotext -enc UTF-8` 转文本，正文里会夹入页眉"Apple Platform Security"、页码与空行（例如第 1150—1154 行整段是页码残块）。本文引用该文档时给的是**转文本件的物理行号**，并在需要时说明"该行是正文"。第 26 章缺口 G3。

最后，原文本身的拼写与格式异常一律保留原样并加注，本文不做"顺手修正"：《Phases of software update enforcement》第 36 行把 `StatusDeviceOperatingSystemSupplementalBuildVersion` 描述成"设备的操作系统版本与 Background Security Improvement 构建标识"，而第 37 行对 `…SupplementalExtraVersion` 只描述成"Background Security Improvement 标识"，两行的中文可核对差异只在末尾的 `build identifier`；《Deploying software updates using declarative management》第 7 行原文里 "(https://gdmf.apple.com/v2/pmv" 带一个**未闭合的左括号**，本文引用该行时原样保留。两处都不是本文的转录差异。

---

## 3. 三套词表：公告口径、设备与策略口径、外部应急口径

本文说的"三套口径"，对应这条链路上三种**互不通约的公开产物**。第一套写在 Apple 的公告里，回答"这次修了什么"；第二套写在 MDM 文档与设备状态项里，回答"这台设备上正在发生什么"；第三套写在第三方应急目录里，回答"这一条必须在什么时候之前修掉"。三套都叫"补丁"，但没有一个字段能把它们换算过去。

### 3.1 公告口径：一次发布 = 一份按组件切分的 CVE 清单

公告侧的闭合词汇非常小，小到可以全部列出来。以本轮取回的《About the security content of iOS 27.2 and iPadOS 27.2》为例，一条目只有五种行：组件名（`Accelerate Framework`，第 26 行）、`Available for:`（第 27 行）、`Impact:`（第 28 行）、`Description:`（第 29 行）、`CVE-…: <致谢对象>`（第 30 行）；文档级的口径句是"Apple security documents reference vulnerabilities by CVE-ID when possible."（第 22 行）与那句众所周知的保密声明（第 21 行）。

同一份内容另有机器可读形态：CSAF v2.1 文档，`category: csaf_security_advisory`、`csafVersion: 2.1`、`status: final`、`publisher: Apple Product Security`。本轮三份公告的机器件里，与人工页**同义但不同形**的字段是：`fixedProductIds`（写作 `APPLE-ios-27_2` 这种下划线形式，不是 `27.2`）、`distinctComponents`（67 / 54 / 57）、`cveCount`（163 / 134 / 95）。

**这套口径的三个硬边界**：

1. **它只描述"这次修了什么"，不描述"这台设备累计修过什么"。** 本轮实测：同一条版本线上相邻两次更新（iOS 26.7 与 iOS 26.7.2）的 CVE 集合**交集为 0**（95 条与 134 条），而两条并行版本线（27.2 与 26.7.2）同日发布、交集 119。任何"看版本号推累计修复面"的做法都要求把该设备走过的每一篇公告做并集，本公告第 22 章脚本做的正是这件事。
2. **它可以合法地不包含任何 CVE。** 公告表里 "This update has no published CVE entries." 这一句在本轮存档页里出现 61 次，与按发布日切出来的表行一一对应：331 行中有 61 行（18.4%）只有这一句，没有任何 CVE。一次"发布"与一次"安全修复"在两个口径下不是一件事。
3. **它不可降级。** "Note that after a software update is installed for iOS, iPadOS, tvOS, watchOS, and visionOS, it cannot be downgraded to the previous version."（《Apple security releases》第 30 行）——这句话决定了公告口径没有"回滚后仍然算修过"这种状态。

### 3.2 设备与策略口径：版本形态 + 状态词，没有 CVE

第二套词表里没有任何 CVE、组件名或影响描述，只有**版本形态**和**状态词**。

版本形态是四段而不是两段：`device.operating-system.version`（"such as 15.0"，《StatusDeviceOperatingSystemVersion》第 42 行）、`device.operating-system.build-version`（"such as 18F132"，《StatusDeviceOperatingSystemBuildVersion》第 42 行）、`device.operating-system.supplemental.build-version`（"for example, 20A123a or 20B27c"，《StatusDeviceOperatingSystemSupplementalBuildVersion》第 44 行）、`device.operating-system.supplemental.extra-version`（"for example, a"，《StatusDeviceOperatingSystemSupplementalExtraVersion》第 44 行）。后两项是 Background Security Improvements 留下的读数：一台装了 BSI 的设备，它的"版本"在设备口径里是 `20A123a`，在公告口径里仍然是 `27.2`。

状态词是一套封闭枚举，并且**这套枚举在文档内部不闭合**：`install-state` 在《Deploying software updates using declarative management》第 56—61 行列了 6 个值（`none`、`waiting`、`downloading`、`prepared`、`installing`、`failed`），而在它自己的状态项页《StatusSoftwareUpdateInstallState》第 33 行只列 5 个——`waiting` 缺席；但《Phases of software update enforcement》第 20 行明确把 `waiting` 当作阶段 2 的产出（"A StatusSoftwareUpdateInstallState value of waiting, which indicates the process to request the update has started."）。

策略侧还有一套**取值域写在括号里**的词表：`[integer; minimum=1; maximum=90]`（延期天数，四个键同域）、`[string; default=Allowed; allowedValues=?]`（`Download`、`InstallOSUpdates`、`InstallSecurityUpdate`、`ProgramEnrollment` 四个键——注意 `allowedValues=?`，**闭合取值集合在扁平件里没有展开**）、`[boolean; default=true]`（`Enable`、`EnableRollback`、`AllowStandardUserOSUpdates`、`Notifications`）。

### 3.3 外部应急口径：一条必须完成的日期

第三套词表既不属于 Apple 也不属于设备。CISA KEV 目录里一条 Apple 条目的字段是 `cveID`、`vendorProject`、`product`、`dateAdded`、`dueDate`、`knownRansomwareCampaignUse`、`shortDescription`。它的表达力比公告口径更窄（没有组件、没有 Impact、没有 Available for 机型列表），但它是这三套词表里**唯一自带一个期限**的。

本轮从存档里的 `C/kev-apple-lag.txt`（由 `C/kev-apple.tsv` 逐条计算 `dueDate - dateAdded` 得到）数出来的窗口分布是：`window_days=3, entries=1`、`window_days=14, entries=22`、`window_days=21, entries=63`、`window_days=181, entries=9`。

### 3.4 换算失败不是抽象风险：七处实例

下面七处是本文后续章节反复引用的换算断点，每一处都能在本轮存档里指到行。

| 编号 | 从哪套口径 | 到哪套口径 | 断在哪里 | 可核对位置 |
| --- | --- | --- | --- | --- |
| C1 | 公告 | 设备策略 | 公告按 CVE 与组件切分；设备侧四个版本状态项里没有任何 CVE 或组件字段 | 《StatusDeviceOperatingSystemSupplementalBuildVersion》第 44 行 |
| C2 | 策略 | 状态回执 | `install-state` 两套取值表相差一个 `waiting` | 部署指南第 56—61 行 vs 状态项页第 33 行 |
| C3 | 策略 | 策略 | 延期机制"不考虑 BSI"，旁注又说"延期会连带延期依赖该版本的 BSI" | 《SoftwareUpdateSettings》第 73 行 vs 部署指南第 115 行 |
| C4 | 词表 | 词表 | MDM 键名仍叫 `RapidSecurityResponse`，说明已改成 Background Security Improvements，且旧 `restrictions` 键标注 Removed | 《Restrictions》第 186—187 行 |
| C5 | 公告 | 公告 | 同一份公告的两个日期：机器件 `releaseDate` 与页面 `Released` 行不同（APPLE-SA-149041 的机器件时间戳晚于其在发布表里的行日期） | `B/CSAF/149041-cves.tsv.summary.txt` vs 《Apple security releases》第 108—110 行 |
| C6 | 应急 | 策略 | 在野条目的修复窗口是 14/21 天，MDM 允许的延期上限是 90 天 | `C/kev-apple-lag.txt` 第 3—4 行 vs 《SoftwareUpdateSettingsDeferralsObject》第 11—14 行 |
| C7 | 分发 | 设备策略 | 强制更新只能命中目录里存在的版本，且补充版本必须先有基线版本 | 《SoftwareUpdateEnforcementSpecific》第 14、16 行 |

### 3.5 一句被写坏的话：把"版本口径"当成"覆盖口径"

三套口径最容易混用的地方，是把 C1 当成不存在。"我的设备是 27.2"是一句**设备口径**的话；它不能直接换算成"我知道的 N 条在野 CVE 都已经修了"，因为后者需要：这台设备走过的每一篇公告的 CVE 并集（C5、公告口径的"非累计"）、它是否还在这条版本线上（第 5 章）、以及有没有一次 BSI 被移除（第 12 章）。本文第 22 章的脚本就是把这三步做成一次可复现的文本运算，而第 19 章的四级判定模型规定了它**能出什么结论、不能出什么结论**。

---
## 4. L1 发布与公告层

### 4.1 这一层有两个产物，而它们不互相校验

L1 是整条链路的起点，也是唯一由 Apple 单方面书写、任何人可只读消费的层。它有两个形态：一个是人读的表格页（`B/pages/security-releases.txt`，标题行是 Apple Support 的页面名），一个是机器读的 CSAF v2.1 文档（`B/149041.json`、`B/149227.json`、`B/149230.json`，由 `.x9-csaf.pl` 展平成 `B/CSAF/*-cves.tsv`）。两个形态由同一个团队产出，字段却不完全对应：人读页给"发布日 + 名称 + Available for 机型串"，机器件给"CVE + 组件 + fixed product id + 两个日期 + 一个版本号"。

页面的三条口径句在本轮存档里是这样写的：《Apple security releases》第 20 行的 "For the protection of our customers, Apple doesn't disclose, discuss, or confirm security issues until an investigation has occurred and patches or releases are generally available."，第 24 行的 "Keeping your software up to date is one of the most important things you can do to maintain your Apple product's security."，以及第 30 行的 "Note that after a software update is installed for iOS, iPadOS, tvOS, watchOS, and visionOS, it cannot be downgraded to the previous version."。第一句规定了这一层的**可得性上界**（在补丁可用之前不会有任何说明），第三句规定了这一层的**不可逆性**——本文第 12 章的"回滚层"只适用于 BSI，不适用于整版本，依据就是这行。

同一句"不披露" boilerplate 在单篇公告里是另一个措辞：《About the security content of iOS 27.2 and iPadOS 27.2》第 21 行写 "For our customers' protection, Apple doesn't disclose, discuss, or confirm security issues until an investigation has occurred and patches or releases are available."（句首与句尾都和总页不同），第 22 行写 "Apple security documents reference vulnerabilities by CVE-ID when possible."。后一句里的 "when possible" 是 L1 的关键限定词：它意味着 CVE-ID 不是公告的必备字段，因此"公告里没有 CVE"这件事本身不构成缺陷信号——第 4.2 节的 61 行空公告就是这个限定的直接产物。

### 4.2 表行的五种形态，与 18.4% 的"无 CVE 行"

把本轮 `B/pages/security-releases.txt` 按发布日切行（切分规则写在 `.x9-relreadings.pl`：一行匹配 `^\d{1,2} [A-Z][a-z]{2} \d{4}$` 即闭合一行），得到 `C/release-readings.txt` 第 2 行的读数：`rows_total=331 rows_without_published_cves=61 pct_empty=18.4%`。

一行表行的五种形态：

| 形态 | 组成 | 本文用途 |
| --- | --- | --- |
| A 正常行 | 名称 + Available for 机型串 + 日期 | 版本线、机型覆盖 |
| B 空行 | 名称 + 机型串 + "This update has no published CVE entries." | 无法判定覆盖，只能判定"这一行存在" |
| C 同日多行 | 同一日期下多个平台族各占一行 | 并行版本线（第 4.3 节） |
| D 外设行 | 名称是固件/应用/SDK 而非 OS | L10（第 13 章） |
| E 仅平台串行 | 机型串本身跨 140 次重复 | 只能当台账字段，不能当唯一引文 |

按平台族切分（`C/release-readings.txt` 第 5—14 行）：

| 族 | 行数 | 其中无 CVE |
| --- | --- | --- |
| macOS | 91 | 10 |
| iOS+iPadOS | 79 | 17 |
| watchOS | 36 | 15 |
| visionOS | 32 | 5 |
| tvOS | 27 | 6 |
| Safari | 27 | 2 |
| Other（外设/应用/SDK） | 17 | 1 |
| iPadOS | 9 | 1 |
| Xcode | 8 | 0 |
| iOS | 5 | 4 |

这十行数字里最值得注意的是 watchOS：36 行里 15 行没有 CVE（41.7%），是十族里空行占比最高的主平台族。iOS 族 5 行里 4 行空（只出现在很老的版本线上）。**空行占比是一个可以直接算出来的"公告口径可信度分母"**，本文第 20 章把它做成运营指标 O1。

### 4.3 公告不累计：本轮三份同日公告的集合运算

本轮三份公告的机器件字段（`B/CSAF/*-cves.tsv.summary.txt`）：

| advisoryId | title | `cveCount` | `distinctComponents` | `releaseDate`（= `current_release_date`） |
| --- | --- | --- | --- | --- |
| APPLE-SA-149041 | About the security content of iOS 26.7 and iPadOS 26.7 | 95 | 57 | 2026-10-26T19:02:02Z |
| APPLE-SA-149227 | About the security content of iOS 26.7.2 and iPadOS 26.7.2 | 134 | 54 | 2026-10-26T00:00:00Z |
| APPLE-SA-149230 | About the security content of iOS 27.2 and iPadOS 27.2 | 163 | 67 | 2026-10-26T00:00:00Z |

把三份的 CVE-ID 做集合运算（`.scratch` 下用 `sort -u` 与 `comm` 复现）：

- 直加：95 + 134 + 163 = 392；按 CVE-ID 去重后的并集：**270**。也就是说，把三份公告的条目数相加会凭空多算 122 条。
- 26.7 ∩ 26.7.2 = **0**。同一条版本线上的相邻两次发布，CVE 集合完全不重叠。
- 27.2 ∩ 26.7.2 = **119**；27.2 独占 44 条，26.7.2 独占 15 条。
- 27.2 ∩ 26.7 = **3**。

这四个数字是本文最重要的一组证据：**"我在最新公告里"不等于"我覆盖了所有已披露条目"，而且相邻版本之间的集合关系不是包含关系**。同一版本线上两次发布 CVE 完全不重叠（0 交集）意味着 26.7 修的那 95 条从来不是 26.7.2 那份文档的内容；两条并行版本线（26.7.2 与 27.2）在同一天发布、共享 119 条，但各自还有 15 条与 44 条只在自己的文档里。任何人把"公告 = 累计补丁清单"当成前提，就会在最基本的减法上出错——本文第 22 章脚本二做的正是这个并集与差集。

组件侧同样不累计：三份公告的组件标签只有 22 个同时出现在三份里（149041 与 149230 两份之间也只有 24 个同名标签，去重后三份共 101 个标签名）；APPLE-SA-149041 有 33 个组件标签根本不在 149230 里（`Baseband`、`MobileAccessoryUpdater`、`TCC`、`XPC`、`IOAcceleratorFamily`、`Photos`、`Storage`、`exFAT` 等）。而且组件名是**每篇公告自带的自由文本**，不是枚举：同一家族在 149230 里被拆成 `WebKit`、`WebKit Canvas`、`WebKit JavaScript Bindings`、`WebKit Process Model` 四个标签；"Photos"与"Photos Storage"在不同公告里指代并不稳定。这条观察是第 3 章 C1 断点的另一半：不只是"公告 ↔ 设备"不通约，"公告 ↔ 公告"在组件维度上也不通约。

### 4.4 同一篇公告有两个日期和一个版本号

APPLE-SA-149041 的机器件 `document.tracking` 块里同时存在 `"status": "final"`、`"version": "4"`、`"initial_release_date": "2026-09-14T00:00:00Z"` 与 `"current_release_date": "2026-10-26T19:02:02Z"`。而它对应的人读表行是《Apple security releases》第 108 行的 iOS 26.7 and iPadOS 26.7，其发布日是第 107 行的 14 Sep 2026。另两份（149227、149230）的两个日期相同、版本号为 `"1"`，与表行日期（第 40 行的 26 Oct 2026）一致。

于是 L1 有一个不显眼但会伤人的性质：**修订过的公告在机器件里带版本计数与两个日期，在人读页里只有一个日期**。做补丁台账的人通常抓人读页那行日期，抓机器件的人则可能拿到 `current_release_date`（本文的 `.x9-csaf.pl` 就是取后者，因此摘要行写的日期比表行晚 42 天）。两种取法都能自圆其说，但会得出"这条 CVE 已公布 42 天"与"这条 CVE 刚公布"两种截然不同的紧急度判定。本文把它列为第 24 章误区 M2，并在脚本二里把两个日期都作为字段保留、不做取舍。

### 4.5 "在野"这件事不由 L1 说

本轮把 CISA KEV 目录里的 Apple 条目取回为 `C/kev-apple.tsv`（95 条）。把这 95 条 CVE-ID 与上面三份公告的 CVE 集合求交：三次都是 **0**。这不是矛盾，而是这条链路的一个结构性事实：KEV 条目在漏洞进入在野利用时才登记，登记时对应的修复版本通常是更早的那条版本线；最新公告里没有它们，也不会在下一篇公告里出现。

直接后果：**用"这台设备装了最新公告"来推断"KEV 里的东西都修了"是两套口径的误用**（第 3 章 C6）。第 4.6 节给出这一层的缺陷形态；第 16 章给出可读的公告侧读数。

### 4.6 L1 的缺陷形态、责任方与更新通道

| 缺陷形态 | 表现 | 谁改 | 落在哪条通道 |
| --- | --- | --- | --- |
| P1-型：把空行读成"无风险" | 18.4% 的行只有 "This update has no published CVE entries." | 台账维护者 | 台账规则，不改任何产物 |
| P1-型：直加条目数 | 392 vs 270 | 台账维护者 | 同上 |
| 跨公告换算组件名 | 三份共有 22 个标签、两份共有 24 个、149041 单侧 33 个 | Apple（口径）/台账（判定） | 公告页与机器件（Apple 侧） |
| 日期取错源 | `initial` vs `current` vs 表行 | 台账维护者 | 台账字段定义 |
| 用最新公告对齐 KEV | 交集 0 | 台账维护者 | 判定模型（第 19 章） |

L1 的修改权全在 Apple，读者侧唯一能改的是**台账怎么读它**。这就是为什么本文把这一层的归属写成"Apple 写、读者只改解释"，而第 9、10 章的策略层才是读者真正有写权限的地方。

---

## 5. L2 版本可见层：目录、机型与签名时效

### 5.1 GDMF 是这条链路唯一的"可发版清单"

《Deploying software updates using declarative management》第 7 行给出这一层的定义句：后半句 "is the official resource to obtain a list of publicly available updates, upgrades, and Background Security Improvements."；第 8 行说 "The JSON response contains three lists of available software releases:"，随后第 9—11 行分别是 "PublicAssetSets: This list contains the latest releases available to the general public if they try to update or upgrade."、"AssetSets: This list is a subset of PublicAssetSets and contains all the releases available for device management services to push to devices."、"PublicBackgroundSecurityImprovements: This list contains Background Security Improvement releases currently available for Apple devices."。

三个列表的关系是本文后面反复用到的一条**包含式规则**：`AssetSets ⊆ PublicAssetSets`，且 BSI 单独成表。也就是说"公众能 OTA 到的东西"与"MDM 能推的东西"是两个集合，后者是前者的子集；而 BSI 的可推送性走第三条表，不在前两条的任一包含关系里。

第 12 行给出每条记录的字段："Each element in the list contains the ProductVersion number and Build of the operating system, the PostingDate when the release was published, the ExpirationDate, and a list of SupportedDevices for that release."。第 13 行给出时效："The expiration date, typically set to 180 days after the posting date, defines the date the signing of the update expires. An expired update can't be installed on devices anymore."——同一段还说明后续版本发布时，早前版本的过期日**可能被改写**。

### 5.2 这一层的两条查找键，和它们各自的主体

设备侧有两条互相独立的键能进入这个目录：

- 《StatusSoftwareUpdateDeviceID》第 30 行："PROP softwareupdate.device-id [string; required] The device identifier to use when looking up available software updates via https://gdmf.apple.com/v2/pmv ."
- 《DeviceInformationResponse》第 21 行："PROP UDID [string; required] The device's UDID (unique device identifier). The system requires this value if the enrollment type is a device enrollment."

一条是**状态项**（设备向 MDM 上报的读数，用于查"这台设备有什么可装"），一条是**入网信息**（设备在 enrollment 时上报的身份）。两者的主体不同、生命周期不同：UDID 在 enrollment 时就固定，device-id 是软件更新域内的查询标识。台账如果只用 UDID 做主键，会把"目录对这台机型开放了什么"这一格算错。

### 5.3 机型表有两份，且互不校验

L1 的机型表达是公告里的 "Available for:" 串（《About the security content of iOS 27.2 and iPadOS 27.2》第 27 行，本轮存档里这句在整份语料中出现 140 次，因此只能当台账字段、不能当唯一引文）；L2 的机型表达是目录里的 `SupportedDevices`，其用法写在《Phases of software update enforcement》第 12 行："The device management service regularly monitors the Apple Software Lookup Service for new releases. If it detects one, it uses the SupportedDevices key of the catalog and compares it to its list of managed devices to determine which devices the release is applicable to."。

这两份机型表一个是给人读的营销名（"iPad Pro 12.9-inch 4th generation and later"），一个是给机器匹配的 `ProductName`/`PRODUCT` 值（deploying 第 12 行后半句明确说设备列表匹配的是设备返回的 `ProductName` 或 `PRODUCT`）。**它们之间没有任何公开文档给出映射表**。这就是第 17 章"可见性边界"里的一条：读者能验证"公告写了这台机型"，也能验证"目录的 SupportedDevices 含这个 PRODUCT 值"，但不能公开验证两者等价。

### 5.4 强制更新只能命中目录里存在的版本

《SoftwareUpdateEnforcementSpecific》第 14 行把这一层的约束写成一句话，前半句给出端点，后半句给出本文最重要的可判定规则："To determine available software updates to show to an admin, a device management service uses the Apple GDMF service via https://gdmf.apple.com/v2/pmv. Configurations only enforce a software update if GDMF has the corresponding OS version or build available."。同页第 13 行给出"目录里没有"时的行为："If the TargetOSVersion and optional TargetBuildVersion values don't match an available software update, the device keeps the configuration active, but won't be able to update. If a software update that matches these keys becomes available later, the device will process the update."。

这一对句子的工程含义很大：**声明不会因目标版本不存在而报错，它会静静地保持活动状态**。第 10 章会把它做成 P3 型缺陷（"配置在、读数为空"）；第 21 章脚本一的一条信号码就是模拟这个状态。

### 5.5 过期即不可装，且过期日会被改写

回到 5.1 的第 13 行：`ExpirationDate` 通常在 `PostingDate` 之后 180 天，过期版本"can't be installed on devices anymore"。把它与第 12 章的"整版本不可降级"合起来读，得到这条链路对时间最敏感的一条规则：**能装的版本集合是随时间单调收缩的**。任何"我们下季度统一升到 x.y.z"的计划都隐含假设 x.y.z 还在那一天的可装集合里。同一段还写着后续发布时早前版本的过期日可能被更新，因此这个收缩不是固定 180 天的匀速收缩。

第 3 章的 C7 断点在这里完成闭环：`Configurations only enforce … if GDMF has the corresponding OS version or build available`（策略口径的"我声明了"）↔ `The system can only install a supplemental software update on a device that already has the base OS version installed`（同页第 16 行，目录口径的"能不能命中"）。

### 5.6 L2 的缺陷形态、责任方与更新通道

| 缺陷形态 | 表现 | 谁改 | 通道 |
| --- | --- | --- | --- |
| 拿公告机型串当目录依据 | `SupportedDevices` 与 Available-for 不互校 | 台账 + MDM 服务 | 服务侧映射表（自维护） |
| 把 AssetSets 当 PublicAssetSets | 公众可 OTA、MDM 不可推的版本被写进计划 | MDM 服务 | 读目录时选表 |
| 忽略 ExpirationDate | 计划里的版本某天起不可装 | 台账 + 计划 | 无（Apple 侧时钟） |
| 只用 UDID 做主键 | device-id 查询结果错位 | 台账维护者 | 台账 schema |
| 声明目标版本不在目录 | 配置保持活动、无报错、无进度 | MDM 服务 | 声明内容（随下一次同步） |

---

## 6. L3 授权与个性化层

### 6.1 这一层的四个动作

L3 是"这个版本能不能被这台设备装"的裁决层，公开描述集中在两处：支持页《Secure software updates》第 241—248 行与安全指南《Apple Platform Security》第 1146—1159 行（同一批句子在两个产物里各出现一次，命中数 h2，因此本文两处都给行号）。四个动作依次是：

1. 设备把安装包各件的密码学测量值与随机数交给授权服务器——"During upgrades and updates, certain information is made available to the Apple installation authorization server, which includes a list of cryptographic measurements for each part of the installation bundle to be installed (for example, iBoot, the kernel, and the operating system image)"（第 244 行 / 指南第 1149 行）。
2. 服务器对照"允许安装"的版本列表，命中后把设备唯一标识 ECID 混入测量值再签名——"The authorization server checks the presented list of measurements against versions whose installation is permitted and, if it finds a match, adds the ECID to the measurement and signs the result."（第 245 行 / 指南第 1155 行）。
3. 启动时校验签名与"测量值 + ECID"的匹配——"The boot-time chain-of-trust evaluation verifies that the signature comes from Apple and that the measurement of the item loaded from the storage device, combined with the device's ECID, matches what was covered by the signature."（第 246 行 / 指南第 1157 行）。
4. 因此更新必须联网——"The personalization process is why a network connection to Apple is always required to update any device with Apple-designed silicon, including an Intel-based Mac with the Apple T2 Security Chip."（第 247 行 / 指南第 1158 行）。

### 6.2 防降级是这一层实现的，不是策略层实现的

同页第 248 行（指南第 1159 行）："On devices with the Secure Enclave, that hardware similarly uses system software authorization to check the integrity of its software and is designed to prevent downgrade installations."。配合第 241 行（指南第 1146 行）里的 "The update process also uses system software authorization to check that only copies of operating system versions that are actively being signed by Apple can be inst…"（该行在本轮存档中被截断，完整句以指南第 1146 行为准），可以确定一条本文只用一次、但必须说清的结论：**"不可降级"由服务端签名状态与启动链共同保证，任何 MDM 键、任何设置、任何用户操作都不构成降级通道**。因此第 12 章的回滚层只有 BSI 一种，而不存在"整版本回滚"的公开面。

### 6.3 这一层对读者是黑盒，只留三个可核对痕迹

L3 的裁决发生在 Apple 服务端。读者侧的可得证据只有三处：失败回执（第 11 章的 `failure-reason` 与 phases 第 30 行那句 "If the update fails, a StatusSoftwareUpdateInstallState value of \`failed is sent."——注意原文该行本身带一个游离反引号，属存档原样，见第 2 章缺口 C）、装成功的版本读数（四个版本状态项），以及"目录里有但装不上"这个组合（第 5.4 节的静默保持活动）。凡有人声称"我们从日志里看出是个性化被拒"，在本轮公开口径下都缺一个可核对字段——`failure-reason` 字典没有公开的错误码枚举页（第 11.6 节）。

### 6.4 L3 的缺陷形态、责任方与更新通道

这一层的责任方只有一个：Apple。app 侧无写权限，MDM 侧无写权限，用户侧无写权限。它进入本文的理由不是"可修"，而是**它决定了其余各层的语义边界**：L2 的可装集合之所以随时间收缩（第 5.5 节），原因在 L3；L9 之所以只允许 BSI 回滚（第 12 章），原因也在 L3。任何把"降级窗口"写进应急预案的台账条目，其缺陷类型属于第 14 章的 P5（依赖一个不存在的通道）。

---

## 7. L4 分发与装配层

### 7.1 两种装配形态

《Secure software updates》第 242 行（指南第 1147 行）："For greater software update security, when the device to be upgraded is physically connected to a Mac, a full copy of iOS or iPadOS is downloaded and installed. But for over-the-air (OTA) software updates, only the components required to complete an update are downloaded, improving network efficienc…"。这条差异在归属上很重要：**同样是"更新到 27.2"，走线（连 Mac 全量）与走 OTA（增量组件）得到的是两条不同的下载路径与两套不同的失败模式**，而设备上报的版本读数两者一致（第 11 章的四个版本状态项不区分装配形态）。

### 7.2 内容缓存与"下载得动"

《Phases of software update enforcement》第 22 行："If a content caching service is available to the device, it attempts to download the software update from the content cache."。同页第 19 行给出下载的前置条件："After the declaration becomes active on a device, the operating system reaches out to the Apple Software Update Catalog to retrieve the download URL and begins to download the update if it meets the requirements."——"if it meets the requirements" 这一串条件（电量、空间、网络）在公开文档里没有闭合清单，本文第 26 章把它列为缺口 G6。

### 7.3 空间不足是一等公民，不是一次失败

《Update your iPhone or iPad》第 33 行的前半段："If a message asks to temporarily remove apps because the software needs more space for the update, tap Continue to allow the system to remove apps. After installation is complete, those apps are automatically reinstalled."——同段还说明点 Cancel 之后要手动清内容。这一句在本报告集里的意义是：**装配层的"成功"可以包含一次对用户 app 集合的临时改写**。任何在设备上做完整性基线（app 清单、磁盘占用）的检测逻辑，都会在这里看到一次合法的巨大变化。这与第 8 篇（隐私授权）的 SDK 装配面无关，但与"读数突变"直接相关：把它当成攻击信号的台账会产生误报，把它忽略则可能在真实篡改面前失去参照。

### 7.4 网络中间层的两个静默阻断

同一页第 31 行："Some software updates aren't available wirelessly. VPN or proxy connections might prevent your device from contacting the update servers."。这一句给出 L4 最尴尬的失败形态：**没有错误码，没有失败回执，只有"看不到更新"**。它与第 5.4 节"目录里没有则静默保持活动"是同一种设计哲学的两次出现，也是本文第 11 章"不可判定"论证的一半（另一半是状态词表）。企业网络里最常见的更新"缺陷"其实是这一条：设备在代理/VPN 下长期看不到更新，而状态项始终是 `none`。

### 7.5 用户侧的自动更新档位

《Update your iPhone or iPad》第 35 行给出总口径（"The best way to make sure your device receives all the features, security updates, and bug fixes in our latest software releases is to turn on automatic updates when you first s…"），第 43 行给出自动安装档位的原文："Automatically Install: When an update is available, iPhone downloads and installs the update overnight while charging and connected to Wi-Fi. You're notified before iPhone installs an update."。第 46 行则单独说明系统文件类更新不会改版本号："Your device can automatically download and install system file updates to improve features without changing the software version."。

第 46 行是 L4 与 L5 的接缝之一：**存在一类"会改变设备内容但不改变版本读数"的更新**。这一句和第 12 章 BSI 的可移除性合起来，构成第 19 章判定模型里"版本相等 ≠ 内容相等"的依据。

### 7.6 委派给设备这件事

《Deploying software updates using declarative management》第 5 行是这一层的哲学句："Instead of initiating software updates on managed devices on-demand, you can use declarative device management to declare the desired operating system version state, and delegate the task to achieve that state to the device itself."（同句后半："This allows for a more resilient managed software update process"）。注意这句里的主语转移：命令式（on-demand 触发）变声明式（声明目标状态）。缺陷归属随之转移——**MDM 不再能声称"我发了命令所以更新在进行"，它只能声称"我声明了状态，其余由设备决定"**。本文第 15 章矩阵里 L4/L7 两行的"责任方"因此都同时列 MDM 与设备。

### 7.7 L4 的缺陷形态、责任方与更新通道

| 缺陷形态 | 表现 | 谁改 | 通道 |
| --- | --- | --- | --- |
| 代理/VPN 阻断 OTA | 无回执、读数 `none` | 网络管理方 | 网络配置（与 Apple 无关） |
| 忽略内容缓存可用性 | 出口带宽峰值、下载超时 | MDM + 基础设施 | 缓存服务配置 |
| 把临时移除 app 当篡改 | 完整性基线误报 | 基线维护者 | 检测规则 |
| 装配形态差异未记账 | 同版本号不同来源 | 台账 | 台账字段 |
| "看不到更新"当"已最新" | 空读数误判 | 判定模型 | 第 19 章 |

---

## 8. L5 安装形态层：整版本与 Background Security Improvements

### 8.1 BSI 是什么：两处定义与一处"按日期发布"

《About Background Security Improvements for iOS, iPadOS, and macOS》第 18 行："Background Security Improvements deliver additional security protections between software updates."，第 19 行给出组件范围："Background Security Improvements deliver lightweight security releases for components such as the Safari browser, WebKit framework stack, and other system libraries that benefit from smaller, ongoing security patches between software updates."，第 21 行给出适用起点与申报口径："Background Security Improvements are supported and enabled for future releases starting with iOS 26.1, iPadOS 26.1, and macOS 26.1. We publish information about Background Security Improvements by date, along with components patched and CVE details, if applicable."。

"if applicable" 这半句在《Background Security Improvements by date》第 20 行有一个更明确的版本："When a release has relevant CVE-ID details, we also publish a security advisory and include the release in the Apple security releases page."。也就是说 **一次 BSI 发布可以只在按日期列表里出现（组件名），不出现在公告表里、不出现在任何 CVE 文档里**。第 4.2 节的"空行"讨论在这里升级：BSI 存在一整类"只有组件名"的补丁，其 CVE 覆盖不可从任何文档推断。按日期页的第 18 行是这一页的自我限定："This page lists Background Security Improvements and patched components."；其示例行（第 25 行）的版本写法是 `iOS 26.3.1 (a), iPadOS 26.3.1 (a), macOS 26.3.1 (a), macOS 26.3.2 (a)`，对应基线在第 26 行、组件在第 27 行只有一个 `WebKit`。

### 8.2 与整版本不同的五处

《Background Security Improvements in Apple operating systems》第 242—245、251—252 行与安全指南第 1169—1172、1176、1178—1179 行是同一批句子（命中数 h2：同一句在支持页与 PDF 取回件里各出现一次，因此两处都给行号）。列表由指南第 1168 行引出（"Background Security Improvements differ from software updates in the following ways:"），五个项目符号如下：

| 差异 | 原文（要点） | 出处 |
| --- | --- | --- |
| macOS 上 Safari 先于重启生效 | "On devices with macOS, Safari security improvements delivered through a Background Security Improvement become active as soon as Safari is relaunched, even before the whole operating system restarts." | 第 242 行 / 指南第 1169 行 |
| 重启即激活，不需要 reseal，不需要 RAM disk | "Background Security Improvements are activated instantly upon restart; the system volume doesn't need to be cryptographically resealed, and therefore the device doesn't need to cycle through a RAM disk." | 第 243 行 / 指南第 1170 行 |
| 电量门槛更低 | "Background Security Improvements require a much lower battery state of charge than is required to install a software update." | 第 244 行 / 指南第 1171 行 |
| 可移除，回到基线 | "A Background Security Improvement can be removed, which reverts the device to the baseline software update state with no Background Security Improvements applied." | 第 245 行 / 指南第 1172 行 |
| 可移除后可再施加 | "A Background Security Improvement can be reapplied after removal." | 指南第 1173 行 |

第三行是这一层在运营上最容易被忽略的差异：**电量门槛决定了"设备什么时候具备安装条件"**。它与第 7.5 节的 `Automatically Install` 档位、以及《SoftwareUpdateEnforcementSpecific》第 17 行 "or when the device meets all required conditions, such as minimum battery level" 连成一条判断链——长期低电量的设备可以停在"声明已下发、目录里有版本、但安装条件不满足"的状态而不产生任何错误读数。

### 8.3 cryptex：形态的技术内容

《Background Security Improvements in Apple operating systems》第 247 行 / 指南第 1174 行："The system volume in iOS, iPadOS, and macOS has been reorganized to support Background Security Improvements. Content that can be patched using the Background Security Improvement mechanism has been moved into cryptexes, which are optimized, cryptographically sealed disk images that reside on the pr…"（后接"preboot volume"，同段完整句以指南第 1174 行为准，其中还包含 "they can be updated by applying a binary patch to their backing disk image file"）。第 248 行 / 指南第 1175 行给出签名侧："The measurements of the cryptexes, their file system seals, and their associated trust caches are all represented in a separate Image4 ticket, which is cryptographically bound to the device on which it resides."，并在后半说明施加 BSI 时设备向 Apple 的签名服务请求对应的 Cryptex1 Image4 清单，而 "the existing AP boot ticket isn't updated"。

这段技术内容给 L5 定了两条本文必须用的性质：**BSI 有自己独立的签名票据**（因此它的可装集合由另一套个性化流程决定，与第 6 章的整版本流程并行），以及**BSI 是绑定设备的**（不能把一台设备的 BSI 内容当成另一台的证据）。

### 8.4 移除的机制与"补丁 + 反补丁"

第 251 行 / 指南第 1178 行："Background Security Improvements are intended to be removable in case a critical regression associated with the Background Security Improvement is discovered. Users can also elect to remove all Background Security Improvements currently applied on their device."，同段还写明 Apple 在兼容性问题时可能通过自动更新机制移除最近一次 BSI，且 "To facilitate removal, Background Security Improvements ship both a patch and an antipatch to the device."（"antipatch"一词只出现在这里，是这条链路最少的可核对锚点之一）。第 252 行给出用户主动移除的后果："If the user removes Background Security Improvements, the removal action removes all currently installed Background Security Improvements (returning all cryptexes to their base state) and returns patched system binaries to the version from the last installed software update."——同段末还要求用户重启。

### 8.5 macOS 侧的三件事

《About background updates in macOS》第 18 行："Your Mac automatically installs Background Security Improvements, security-configuration updates, and system data files in the background."；第 36 行给出这三类的枚举（"Background updates include Background Security Improvements, security-configuration updates, and system data files."）；第 23 行给出重启语义："By default, these updates are installed or applied automatically. They don't cause your Mac to restart, but some take effect only after you restart your Mac."。第 41 行是本轮语料里唯一描述"重启时才清除已装恶意软件"的句子（"Security-configuration updates help make your Mac more secure by identifying malicious software and preventing its installation. When you restart your Mac, these updates also remove any malicious software that is identified but already installed."）。

《About Background Security Improvements…》第 22 行则给出 macOS 的一个例外形态："On Mac, Background Security Improvements are available only when you start your Mac from its built-in storage. When started up from an external storage device, it receives these improvements as part of a subsequent software update."——**同一台机器，从内置盘启动和从外置盘启动，处在不同的补丁到达面上**。这在归属上属于 Apple 的实现，不在任何管理方的写权限里，但它会改变台账对"这台机器是否已修"的判定。脚本一没有"启动介质"这一格，所以它只能从版本形态上兜住最近的一条：台账未登记 base 构建、而待装版本写成 supplemental 形态（末尾带小写字母）时输出 D14——补充版本能否单独到达，取决于 base 是否已经在机上。

### 8.6 用户拒绝这一格会发生什么

《About Background Security Improvements…》第 28 行："If you choose to turn off this setting, your device will not receive these improvements until they're included in a subsequent software update."；第 20 行给出 Apple 侧的移除承诺："In rare instances of compatibility issues, Background Security Improvements may be temporarily removed and then enhanced in a subsequent software update."（该句在 bsi-about、bsi-guide、指南三处出现，h3）。

第 28 行是 L5 唯一的"用户可以让补丁不到达"的开关，而它的后果表达方式是一句**否定式的、无时间边界的**陈述（"不会收到，直到某次后续软件更新包含它们"）。第 20 行的"暂时移除、随后增强"同样没有给出可判定的读数。第 12 章会说明这两格如何反映在 `supplemental.*` 状态项上。

### 8.7 L5 的缺陷形态、责任方与更新通道

| 缺陷形态 | 表现 | 谁改 | 通道 |
| --- | --- | --- | --- |
| 把 BSI 当"没装东西" | 版本读数不变但内容变（第 7.5 节 + 第 8.1 节） | 判定模型 | 台账读 `supplemental.*` |
| 只在公告表里找 BSI | 只有组件名的 BSI 不出现在 CVE 文档 | Apple 口径 | 按日期页 |
| macOS 外置盘启动 | 该类设备不在 BSI 到达面 | 设备使用方 | 启动介质（无管理键） |
| 用户关闭 BSI 开关 | 无回执，直到下次整版本 | 用户 | 设备设置 |
| Apple 移除某次 BSI | 设备回到基线，读数如何表达未闭合 | Apple | 自动更新机制 |

---

## 9. L6 策略与延期层

### 9.1 七个顶层键与它们的可用性

《SoftwareUpdateSettings》第 11 行给出声明类型："Specify com.apple.configuration.softwareupdate.settings as the declaration type."，第 23 行给出这一页的职责句："This configuration manages software update behavior and deferral settings."。第 70—76 行是七个顶层键，本文按平台可用性整理成一张表：

| 键 | 类型 | 可用性（原文写法） | 备注 |
| --- | --- | --- | --- |
| `AllowStandardUserOSUpdates` | boolean, default=true | 第 70 行：Available: macOS 15+ | 仅 macOS；控制标准用户能否做 Major/Minor 更新 |
| `AutomaticActions` | 对象 | 第 71 行 | Allowed enrollments: supervised |
| `Beta` | 对象 | 第 72 行：Available: iOS 18+ \| iPadOS 18+ \| macOS 15.4+ | 三键有互斥约束（9.5） |
| `Deferrals` | 对象 | 第 73 行 | Allowed enrollments: supervised；含 C3 冲突句 |
| `Notifications` | boolean, default=true | 第 74 行 | 两种通知形态 |
| `RapidSecurityResponse` | 对象 | 第 75 行：Available: iOS 18+ \| iPadOS 18+ \| macOS 15+ | 键名是旧词表（C4） |
| `RecommendedCadence` | string, allowedValues=? | 第 76 行 | 多个可用更新时如何展示 |

第 70 行的原文是 "PROP AllowStandardUserOSUpdates [boolean; default=true] If set to true, a standard user can perform Major and Minor Software Updates. If set to false, only administrators can perform Major and Minor Software Updates."。这条键只在 macOS 存在，但在混合资产台账里常被误当成通用键。脚本一对此只在键名口径上把关：`policy.*` 的键落在本轮可核对的 19 键之外时输出 D01；"这一行的设备与这一行下发的键是否属于同一平台"脚本不判断，因为台账格式里没有平台字段——这一格留给读者自己核对。

### 9.2 延期上限 90 天，四把尺子

《SoftwareUpdateSettingsDeferralsObject》第 11—14 行给出四个键，四行的取值域写法一致（`integer; minimum=1; maximum=90`）：

- 第 11 行 `CombinedPeriodInDays`："Specifies the number of days to defer a major or minor OS software update on the device. When set, software updates only appear after the specified delay, following the release of the software update."，可用范围为 iOS 18+ / iPadOS 18+ / tvOS 1…（该行在存档中的可用串被竖线表格式拍平，本文只按可见部分引用）。
- 第 12 行 `MajorPeriodInDays`："Specifies the number of days to defer a major OS software update on the device."，Available: macOS 15+。
- 第 13 行 `MinorPeriodInDays`：除了延期 minor，还多一句 "It also defers major updates for iOS."。
- 第 14 行 `SystemPeriodInDays`："Specifies the number of days to defer system or non-OS updates."，Available: macOS 15+。

《Deploying software updates using declarative management》第 113 行给出这一层的适用面："Deferring a software update or upgrade from 1 to 90 days is done using the SoftwareUpdateSettings declaration on supervised iPhone, iPad, and Mac devices."。**"supervised" 是这一层的关键前提**：未监督设备不在延期面内，这既是约束也是保护（用户手里的 90 天不存在）。第 114 行则说明延期与强制的关系："A configured deferral defines the number of days before an organization offers a release to users after it becomes publicly available. Independent of a configured deferral, a device management service can still enforce a specific software update, upgrade, or Background Security Improvement on manage…"——延期不封顶强制，这条是第 19 章判定模型 L3 级（可自证）的依据之一。

### 9.3 C3：一句"不考虑 BSI"与一句"会连带延期 BSI"

本节是第 3 章 C3 断点的完整展开，也是本文认为 L6 最值得记录的口径缺陷。《SoftwareUpdateSettings》第 73 行的说明句是："PROP Deferrals [SoftwareUpdateSettingsDeferralsObject] This object configures the deferral of software updates. Background Security Improvements aren't considered in Major, Minor, or System deferral mechanism."。而《Deploying software updates using declarative management》第 115 行是一条旁注（存档前缀为 `ASIDE(note)`）："Deferring software updates also defers any Background Security Improvements that are dependent on that version."。

两句话的主语不同（前者说的是 Major/Minor/System 三个延期机制本身，后者说的是"依赖该版本的 BSI"），但**对同一条配置项（CombinedPeriodInDays / MinorPeriodInDays）会给出两种相反的预期**：一种读法下 BSI 不受延期影响，另一种读法下 BSI 会随被延期的基线版本一起不到达。本文的处理方式不是裁决谁对，而是把裁决权交回台账：第 21 章脚本一只校验这几个延期键自身的取值域与整数形态（D02、D03），以及它与 `RecommendedCadence` 同时出现时的口径冲突（D04），对旧口径键名给 D09；它**不判断"延期到底覆盖不覆盖 BSI"**，也不替读者选一句，只要求台账把采用的读法记在自己那一行里。**同页第 105—106 行的基线规则（第 10 章）决定了哪一种读法在设备上更可观测**，但公开文档没有给出裁决句，这是第 26 章缺口 G9。

### 9.4 AutomaticActions 的三键与未展开的取值表

《SoftwareUpdateSettingsAutomaticActionsObject》第 11—13 行的三键是 `Download`、`InstallOSUpdates`、`InstallSecurityUpdate`，三行都是 `[string; default=Allowed; allowedValues=?]`，取值语义写在行内：

- 第 11 行："Specifies whether the user can control automatic downloads of available updates: Allowed - the user can enable or disable automatic downloads. AlwaysOn - automatic downloads are always enabled. AlwaysOff - automatic downloads are always disabl…"
- 第 12 行（`InstallOSUpdates`）与第 13 行（`InstallSecurityUpdate`）用同一套三值措辞，只是对象分别是 OS 更新与安全更新。

这里有两件可记录的事。第一，`allowedValues=?` 在扁平存档里没有展开成闭合列表（本文第 11.6 节统一处理这个缺口），所以"合法取值"只能从行内散文里抽——这是一个**文档形态导致的可核验性问题**，不是内容缺失。第二，`InstallSecurityUpdate` 与 `InstallOSUpdates` 分成两把独立开关，意味着"自动装安全更新但手动装系统更新"是官方允许的形态；而 BSI 不在这三键的作用域里（它归 `RapidSecurityResponse`，见 9.5）。

### 9.5 Beta 三键的互斥约束，与 RapidSecurityResponse 两键

《SoftwareUpdateSettingsBetaObject》第 14—16 行给出三键，且三行都带互斥条件：第 14 行 `OfferPrograms` "This key must only be present if the ProgramEnrollment key is set to Allowed or AlwaysOn. This key must not be present if the RequireProgram key is present."；第 15 行 `ProgramEnrollment` 同样是 `[string; default=Allowed; allowedValues=?]`；第 16 行 `RequireProgram`："The device automatically enrolls in this beta program. This key must only be present if the ProgramEnrollment key is set to AlwaysOn. The OfferPrograms key must not be present if this key is present."。

《SoftwareUpdateSettingsRapidSecurityResponseObject》第 11—12 行给出两键：第 11 行 `Enable`："If set to false, Background Security Improvements aren't offered for user installation. The system can still install Background Security Improvements with com.apple.configuration.softwareupdate.enforcement.specific configurations."；第 12 行 `EnableRollback`："If set to false, the system doesn't offer Background Security Improvement rollbacks to the user. If set to true, the system offers Background Security Improvement rollbacks to the user."。

第 11 行的后半句是本文第 7 章与第 10 章的接缝：**关闭用户侧 BSI 安装不阻止 MDM 通过强制声明施加 BSI**。因此"用户看不见 BSI"与"设备上有没有 BSI"是两个不同的问题，前者由 `RapidSecurityResponse.Enable` 决定，后者要看 `supplemental.*` 读数（第 11 章）。`EnableRollback` 则是第 12 章回滚面的唯一管理侧开关。

### 9.6 Notifications 与 RecommendedCadence：两个"看得见多少"的键

《SoftwareUpdateSettings》第 74 行："PROP Notifications [boolean; default=true] If set to true, the device shows all software update enforcement notifications. If set to false, the device only shows notifications triggered one hour before the enforcement deadline, and the restart countdown notification."。《Deploying …》第 139 行是同一件事的另一处措辞："The Notifications key changes the default notification behavior to show only a notification 1 hour before the enforcement time and the restart countdown."。

第 76 行的 `RecommendedCadence` 处理"同时有多个可用更新时展示哪个"："This string specifies how the device shows software updates to the user. When more than one update is available update, the device behaves as follows: All - Shows all software update versions. Oldest - Shows only the oldest (lower numbered) software…"。注意这一行原文里有一个重复词组（"is available update"），属存档原样，本文按第 2 章约定保留不修正——这也是一个记录点：**文档自身的措辞异常会出现在安全相关的键说明里**，读者不能靠"看起来像笔误"推断语义。

`Notifications=false` 的实际后果值得单独记一句：它把通知面从"全部"收窄到"截止前 1 小时 + 重启倒计时"，也就是**把用户自主安装的窗口从流程里抹掉了**，而强制安装仍然照常发生（第 10 章 phases 第 29 行）。本文把它列为误区 M5。

### 9.7 多份配置的合并语义：这一层合并，那一层不合并

《SoftwareUpdateSettings》第 21 行（竖线表行）："Apply | Multiple configurations are combined and applied as a single effective configuration"；同页第 15、16、19 行给出可用性矩阵（`Allowed in supervised enrollment | iOS, macOS, Shared iPad, tvOS, visionOS`、`Allowed in device enrollment | iOS, Shared iPad, tvOS, visionOS`、`Allowed in system scope | iOS, macOS, Shared iPad, tvOS, visionOS`）。《SoftwareUpdateEnforcementSpecific》第 27 行对另一类声明写："Apply | Multiple configurations are applied separately"，其同页第 22、25 行的可用矩阵与 settings 页同形（h11：这些可用性行在 11 个对象页里各出现一次，因此本文一律按 file:line 引用，不当作唯一引文）。

《Deploying …》第 101 行给出了合并的算法边界："After a device management service distributes different keys across multiple declarations, a device merges the settings of all active software update settings declarations. If multiple declarations configure the same key, the merge behavior depends on the individual key, which is outlined in the tab…"。这一句对本报告集很重要：**"合并成一个有效配置"不等于"后写覆盖前写"，合并语义是逐键定义的**，而逐键定义在扁平存档里没有全部展开。因此台账里"哪个策略生效"这个问题在 L6 不是可由读者单独判定的——第 26 章缺口 G4。

### 9.8 L6 的缺陷形态、责任方与更新通道

| 缺陷形态 | 表现 | 谁改 | 通道 |
| --- | --- | --- | --- |
| 用延期对齐 KEV 窗口 | 90 天上限 vs 14/21 天要求（C6） | 管理方 | 声明内容 |
| 按 73 行或 115 行任一读法配置 BSI | 两读法相反（C3） | 管理方 + Apple 文档 | 声明内容 / 文档 |
| macOS-only 键下发 iOS | 配置不生效但不报错 | MDM 服务 | 声明内容 |
| 非监督设备配延期 | 整份配置被拒或忽略 | 管理方 | enrollment 形态（需重新入网） |
| `Notifications=false` 当"更安全" | 用户自主窗口消失 | 管理方 | 声明内容 |
| 多份 settings 的合并预期 | 生效值不可判定 | Apple 文档 + 台账 | 缺口 G4 |

这一层的写权限在管理方（MDM 服务下发的声明），更新通道是"下一次同步生效的声明"，**不需要等设备升版本**——这是它与 L3/L5 的根本区别，也是第 15 章矩阵把 L6 单独列一列更新通道的原因。

---

## 10. L7 强制与申报层

### 10.1 五个参与方、七个阶段

《Phases of software update enforcement》第 5 行："Enforcing software updates using device management involves five main components:"，随后第 6—10 行逐个给出：**The device management service**、**The device**、**The user**、**The Apple Software Lookup Service**、**The Apple Software Update Catalog**。这一页把强制执行切成七段，各段标题在存档第 11、15、18、25、28、32、39 行（`# Phase 1` … `# Phase 7`）。

按参与方重排这七段，得到本文第 15 章矩阵的行归属依据：

| 阶段 | 存档行 | 主语 | 可核对读数 |
| --- | --- | --- | --- |
| 1 监测目录并比对机型 | 第 12—13 行 | MDM 服务 | 无（服务端行为） |
| 2 创建声明并推送同步 | 第 16 行 | MDM 服务 | 声明 ID |
| 3 设备取下载 URL 并下载 | 第 19—23 行 | 设备 | `waiting`、`downloading`、`prepared` |
| 4 通知期 | 第 26 行 | 设备 + 用户 | 无结构化读数 |
| 5 截止后安装 | 第 29—30 行 | 设备（+ 用户授权） | `installing`、`failed`、`failure-reason` |
| 6 上报版本 | 第 33—37 行 | 设备 | 四个版本状态项 |
| 7 解除声明 | 第 40 行 | MDM 服务 | 声明移除 |

第 13 行给出服务端的订阅建议："The device management service should also subscribe to the softwareupdate.* and device.operating-system.* status reports to automatically retrieve updates when any of those values change."；第 19 行给出进入本阶段的条件句；第 26 行是唯一一句**没有可核对字段**的阶段："The device enters the notification period. Depending on when the installation is to occur, this notification may display different text and options."。

### 10.2 四个键与两种"目标"写法

《SoftwareUpdateEnforcementSpecific》第 57—60 行的四个 PROP 键：第 57 行 `DetailsURL`（"The URL of a web page that shows details that the organization provides about the enforced software update."）、第 58 行 `TargetBuildVersion`、第 59 行 `TargetLocalDateTime`、第 60 行 `TargetOSVersion`（"This is the OS version number, for example, 16.1 ."）。第 58 行值得注意的是构建号写法："The build version can include a supplemental version identifier, for example, 20A242a ."——补充标识就藏在构建号末尾一个字母里。第 59 行的时间格式是本文唯一的时区风险点："The local date time value that specifies when to force install the software update. Use the format yyyy-mm-ddThh:mm:ss, which is derived from RFC 3339 but doesn't include a time zone offset or fractional seconds."，并在后半句规定 "If the user doesn't trigger the software update before this time, the device force installs it."。

**一个不带时区偏移的"截止时间"，跨时区资产里就是一条静默的缺陷**：同一条声明在 UTC+8 与 UTC-5 的两台设备上代表的绝对时刻相差 13 小时。第 21 章脚本一对 `enforce.LocalDateTime` 只校验这一格可换算性：格式串本身不含时区偏移、且台账没有 `device.timezone` 时输出 D11。它不做绝对时刻换算，只把"这台的截止时间算不出来"留在信号里。

### 10.3 精确版本、补丁版本与基线前置

《SoftwareUpdateEnforcementSpecific》第 15 行："The system installs the specific version set in the TargetOSVersion, and it won't install a patch version if only a minor version is set."；第 16 行："The system can only install a supplemental software update on a device that already has the base OS version installed. For example, the system can only install a 16.1(a) update on a device that currently has 16.1 installed, but it can't install that update on a device that has only 16.0 installed."；第 17 行给出错过时刻的行为："If the device isn't running at the target date-time, the system enforces the software update 1 hour after restarting, or when the device meets all required conditions, such as minimum battery level."。

《Deploying …》第 105 行给出同一件事的服务端视角："Background Security Improvements always apply to the latest update of an operating system, which becomes the base version of the Background Security Improvement."，第 106 行给出 iOS 18 / iPadOS 18 / macOS 15 之前的两步法："Prior to iOS 18, iPadOS 18, and macOS 15, a device management service may need to start two software updates to ensure that a specific supplemental version is present."。第 137 行则是自动化侧的默认行为："The operating system automatically installs any available Background Security Improvements if a device management service defines only the TargetOSVersion."，同句后半给出显式目标的做法（"To target a specific release or Background Security Improvement, a device management service can use the TargetBuildVersion key in addition to s…"）。

把这五行合起来是本文对 L7 最重要的一段论证：**"强制到 x.y.z"这句话有两种含义**（只要基线版本、让 BSI 自动跟随；或钉死含补充标识的构建）。前者在设备侧得到的是"基线 + 当前可用的最新 BSI"，其内容随时间变化；后者得到固定内容但要求 GDMF 里存在该构建（第 5.4 节）。任何以"我们强制到 26.3.1"结尾的合规陈述都必须说明自己是哪一种，而 `supplemental.build-version` 与 `supplemental.extra-version` 两个状态项（第 11.5 节）正是区分它们的唯一读数。

### 10.4 enrollment 期强制：403 与一个 code

《Deploying …》第 73 行给出能力探测："If a device supports this capability, it returns an MDM_CAN_REQUEST_SOFTWARE_UPDATE key, set to true, in the MachineInfo data that it sends in the initial HTTP POST request to the device management service when the device detects a management configuration in Setup Assistant."，第 74—79 行列出与软件更新相关的五个 MachineInfo 字段（`VERSION`、`OS_VERSION`、`SUPPLEMENTAL_BUILD_VERSION`、`SUPPLEMENTAL_OS_VERSION_EXTRA`、`SOFTWARE_UPDATE_DEVICE_ID`），第 80 行是裁决句："Based on the provided information, the device management service can decide whether to enforce the device to update."。

第 82 行是这一层唯一规定**用错误码做强制**的句子："If the device management service chooses to enforce a software update, it needs to return an HTTP response with the 403 status code, and include a JSON or XML object in the response body (the HTTP Content-Type response header needs to be set to application/json or application/xml, respectively)."。第 87 行规定载荷里唯一的固定值："code | String | Yes | Needs to be set to com.apple.softwareupdate.required."，第 88—89 行的 `description` 明确"Used only for logging purposes"、`message` 才是给用户看的；第 94—96 行给出 `details` 里的三键（`OSVersion` 必需、`BuildVersion` 可选、`RequireBetaProgram` 可选，后者的说明是 "The device enrolls in the beta program, allowing enforced software updates to beta program operating system versions. The device remains in the beta program after the enforced software update is complete."）。第 83 行给出后果："After receiving this error response, the device attempts to update to the specified version. If the update succeeds, the device restarts and the user needs to go through Setup Assistant again."。

用 403 表达"你被要求升级"是一次语义挪用（403 的 HTTP 语义是禁止访问），而 `description` 与 `message` 的分歧意味着**服务端日志文本与用户可见文本是两条独立内容，公开文档不要求二者一致**。这是第 24 章误区 M7 的实体依据。

### 10.5 队列语义与"目标已过时"

《Deploying …》第 118 行："If a configuration gets applied to a device that specifies an operating system or build version that's the same as, or older than the current device version, the device returns an error in the status report."；第 119 行："If multiple configurations are present with a newer operating system or build version than the current device version, the configuration with the earliest target date and time is processed first, and any others remain in the queue."；第 120 行："When the device updates to a new version, the set of configurations are reprocessed to determine which becomes the next one to be processed. As part of this process the device ignores any existing configurations that specify a version that is older or the same as the current one."。

三行合起来给出一个对运营很友好的性质：**过时声明会显式报错（第 118 行），队列顺序由目标时刻决定（第 119 行），升完版本后剩余声明自动重估（第 120 行）**。这也意味着 L7 的失败大多是"能被状态项看见的失败"，与 L4 的静默阻断（第 7.4 节）形成对照——本文第 17 章把这一对照当作"该层是否可自证"的主要判据。

### 10.6 supervised Mac 的 bootstrap token

《Deploying …》第 141 行："To authorize an enforced software update on a supervised Mac computer with Apple silicon, a device management service can request and escrow a bootstrap token. This allows for a completely seamless software update experience, and avoids the need for user interaction as part of the process."，随后第 142—144 行给出三步：用 `SecurityInfoCommand` 判断能力（"If the response includes a BootstrapTokenRequiredForSoftwareUpdate that's set to true, the device can use a bootstrap token to authorize a software update."）、在 MDM profile 的 `ServerCapabilities` 数组里加入 `com.apple.mdm.bootstraptoken`、以及设备在下次有安全令牌用户登录时创建令牌并托管到 check-in 端点（"After the device receives the bootstrap token, it creates a bootstrap token the next time a secure token-enabled user logs in."）。

《Phases of software update enforcement》第 29 行在同一动作的阶段描述里再提一次："Before starting the installation, a Mac with Apple silicon contacts the device management service to retrieve the bootstrap token (if one is available)."。这四处句子的组合给出一个必须记录的归属：**没有托管令牌时，强制安装的最后一步需要本地用户交互**——"完全静默的强制更新"在 Apple silicon Mac 上是一个需要额外交接（token 创建 + 登录时机 + 托管）才成立的状态，而不是默认状态。第 21 章脚本一没有"bootstrap token 是否已托管"这一格，因此这条不产生信号码，只作为台账必须显式登记的字段存在。

### 10.7 七阶段里唯一一句"用户不做就发生"

《Phases of software update enforcement》第 29 行的前半句是整条链路里最硬的一句："If the user doesn't install the update before the enforcement deadline, the device begins the installation and sends a StatusSoftwareUpdateInstallState value of installing to the device management service."。它把"用户不响应"这一最模糊的事件定义成了一次确定性的安装启动，并把结果同步交给回执面（第 11 章）。第 30 行的后半句给出成功后的清理语义："If the update was successful, the count key has a value of 0."。

同页第 16 行还给出本阶段声明的构造责任："The device management service creates a SoftwareUpdateEnforcementSpecific declaration with the detected version and defines the TargetLocalDateTime and, optionally, the DetailsURL according to the organizational requirements."；第 40 行给出收尾："The device management service unassigns the declaration from the device and sends a push notification to it to initiate the synchronization. After synchronizing, the device removes the declaration."。

### 10.8 L7 的缺陷形态、责任方与更新通道

| 缺陷形态 | 表现 | 谁改 | 通道 |
| --- | --- | --- | --- |
| 只写 `TargetOSVersion` 却按"固定内容"记账 | 内容随 BSI 变化（10.3） | 管理方 | 声明内容 |
| `TargetLocalDateTime` 无时区 | 跨时区截止不一致（10.2） | 管理方 | 声明内容 |
| 目标版本不在目录 | 静默保持活动（5.4） | 管理方 | 目录状态（Apple 侧） |
| 补充版本先于基线 | 装不上（第 16 行） | 管理方 | 两步强制（第 106 行） |
| 无托管令牌却假定静默 | 需本地交互（10.6） | 管理方 | profile + 登录时机 |
| 把 403 当故障 | enrollment 流程异常化 | MDM 实现 | 服务端响应 |

---

## 11. L8 回执与读数层

### 11.1 状态项词表有多大

《Status items》这一页列出 **65** 条 `- StatusXxx — …` 形式的状态项（其中三条是 `StatusTest*` 测试项）。本文只处理其中两个域：`StatusSoftwareUpdate*` 六条（该页第 64—69 行）与 `StatusDeviceOperatingSystem*` 六条（第 30—35 行）。《Deploying …》第 43 行的建议句只覆盖 9 条（第 45—54 行的表）："For the purposes of monitoring operating system versions and software update status, the device management service may want to subscribe to the following status reports:"，其表头在第 44 行（`Status report | Description`）。

一个可核对的错位：这份"建议订阅"表**不含 `StatusSoftwareUpdateDeviceID`**（该状态项在自己的页面里存在，见第 5.2 节），也不含 `StatusDeviceOperatingSystemFamily`、`StatusDeviceOperatingSystemMarketingName`。也就是说，"照指南实现的管理服务"与"能查询 GDMF 的服务"之间缺一条键——这是 L2 与 L8 之间的第 26 章缺口 G5 的另一面。

订阅机制写在第 42 行："To receive updates for status items as they change, the device management service needs to subscribe to each status report by sending a ManagementStatusSubscriptions declaration to the device."。

### 11.2 install-state 的两套词表，差一个 `waiting`

同一个状态项在两个产物里给了两份取值表。

《Deploying …》第 55 行引出六值表（第 56—61 行）：

| 取值 | 原文 | 存档行 |
| --- | --- | --- |
| `none` | There's no software update pending, and any previous software update succeeded. | 第 56 行 |
| `waiting` | A software update is waiting to start. | 第 57 行 |
| `downloading` | The device is downloading a software update. | 第 58 行 |
| `prepared` | The device prepared the software update and it's ready for installation. | 第 59 行 |
| `installing` | The device is installing the software update. | 第 60 行 |
| `failed` | The software update failed. | 第 61 行 |

《StatusSoftwareUpdateInstallState》第 33 行的同一条 `PROP softwareupdate.install-state` 只给五值："The software update install status, which has the following values: none : … downloading : The system is downloading data for a software update. prepared : The system prepared the software update and it's ready for installation. installing : The system is installing the software update. failed : The software update failed."——**没有 `waiting`**。而《Phases of software update enforcement》第 20 行在阶段描述里明确使用它："A StatusSoftwareUpdateInstallState value of waiting, which indicates the process to request the update has started."，第 21 行同样使用 `downloading`，第 23 行使用 `prepared`，第 29 行使用 `installing`。

三份产物、两套词表、一个取值只在两处出现。这就是第 3 章 C2 的完整证据。它的实际后果是可判定的：照状态项页实现的状态机会把 `waiting` 当成非法值（或"没有更新"），从而**丢掉"强制声明已被设备接受但还没开始下载"这一整段**。第 21 章脚本一把这一格做成三个信号码：台账没声明用哪套词表时 E02，声明了状态项页那套 5 值表却收到 `waiting` 时 E03，取值连自己声明的那套表都装不进时 E01。另外注意第 30 行里那个带游离反引号的原文：`a StatusSoftwareUpdateInstallState value of `failed is sent`——存档原样如此（本文按第 2 章"原文异常保留"处理），它恰好证明这类值在文档里是以文本形式而非枚举形式出现的。

### 11.3 install-reason 的八值，与"谁触发的这次更新"

《Deploying …》第 62 行引出八值（第 63—70 行）："The StatusSoftwareUpdateInstallReason can have one of the following values:"：`system-settings`、`install-tonight`、`auto-update`、`notification`、`setup-assistant`、`command-line`、`mdm`、以及最后一行原文带游离反引号的 `` `declaration ``。同页第 71 行给出这一项的用途："In addition to the other reports, device management services may also want to make StatusSoftwareUpdateInstallReason available to administrator for support purposes, and to provide additional insight into how an update occurs. You can use this dictionary to determine whether a user initiates the update, the update happens automatically, or a software update enforcement declaration initiates it."。

《StatusSoftwareUpdateInstallReason》第 39 行的属性行则只说它是字典："PROP softwareupdate.install-reason [StatusSoftwareUpdateInstallReasonDictionaryObject; required] Details about the reason for a pending software update."，同页第 20—26 行的示例里带一个 `declaration-id` 字段（"declaration-id": "com.example.softwareupdate-config"）。

这一项是本报告集里少有的**能直接把责任方写进读数**的字段：八值里 `mdm`、`declaration`、`setup-assistant` 属于管理面，`system-settings`、`notification`、`install-tonight`、`auto-update` 属于用户/设备面，`command-line` 属于本地特权面。因此"这次更新是谁做的"在公开口径下是可判定的（第 19 章 L2 级），而"这台设备现在有没有修"不可判定（需要 CVE 集合换算）。这一对照是本文第 19 章结构的基础。

### 11.4 failure-reason：三个字段的承诺，一个字的示例

《Deploying …》第 53 行承诺了三个信息："StatusSoftwareUpdateFailureReason | Details about a software update failure. The details include the number of times the software update has failed, last failure timestamp, and the failure reason."。但《StatusSoftwareUpdateFailureReason》第 37 行的属性行只说 "Details about a software update failure."，第 20—26 行的示例里只有 `"count": 0` 一个键，且**没有公开的错误原因枚举页**。《Phases …》第 30 行的 "In either case, the device sends back a StatusSoftwareUpdateFailureReason status report. If the update was successful, the count key has a value of 0." 是本轮语料里唯一给出成功/失败配对语义的句子。

三处合读得到一条判定："失败了几次"有字段、"最后一次什么时候"文档承诺但示例未见、"为什么失败"没有词表。所以 **L8 能告诉你"这里有一个失败"和"失败次数归零表示成功"，不能告诉你失败原因**。第 26 章缺口 G1 记录这一点；脚本一对"failure-reason 有值"这一情形给出 B03 边界（不可判定，而非"更新失败"）。

### 11.5 四个版本读数与两个 BSI 读数

八个读数键的原文（各自文件里的属性行）：

| 状态项 | 属性键与原文要点 | 存档 |
| --- | --- | --- |
| OS 版本 | `PROP device.operating-system.version [string; required] The operating system's version in use on the device, such as 15.0 .` | 《StatusDeviceOperatingSystemVersion》第 42 行 |
| OS 构建 | `The operating system's build version on the device, such as 18F132 .` | 《StatusDeviceOperatingSystemBuildVersion》第 42 行 |
| 含 BSI 的构建 | "The operating system's build and Background Security Improvement versions in use on the device, for example, 20A123a or 20B27c ." | 《StatusDeviceOperatingSystemSupplementalBuildVersion》第 44 行 |
| 仅 BSI 标识 | "The operating system's Background Security Improvement version in use on the device, for example, a ." | 《StatusDeviceOperatingSystemSupplementalExtraVersion》第 44 行 |
| 待装版本 | "A dictionary that contains the build and OS versions of the software update that's pending on the device." | 《StatusSoftwareUpdatePendingVersion》第 37 行 |
| beta 在册 | "The device's enrolled beta program name, or an empty string if there's no enrolled beta program." | 《StatusSoftwareUpdateBetaEnrollment》第 32 行 |

四个版本类读数构成一个**四元组**（version / build / supplemental.build-version / supplemental.extra-version），其中后两个是 BSI 面。本文第 19 章把"四元组一致"作为最高可得结论，而不是"补丁存在"的证据。第 36—37 行的阶段描述给出同一组读数的另一种措辞（其中第 37 行原文键名后带一个游离反引号）。

值得注意的是《StatusSoftwareUpdateBetaEnrollment》第 32 行的空串语义：**空串同时是"没参加任何 beta 计划"的唯一表达**，而 `RequireProgram` 强制入beta（第 9.5 节）之后设备"仍在 beta 计划中"（deploying 第 96 行）。因此该读数不能区分"自愿在 beta"与"被声明要求留在 beta"。

### 11.6 `allowedValues=?`：取值域在扁平存档里全部未展开

本轮存档里 `allowedValues=?` 出现在这些属性行：《StatusSoftwareUpdateInstallState》第 33 行，以及 AutomaticActions 三键（第 11—13 行）、Beta 的 `ProgramEnrollment`（第 15 行）、`RecommendedCadence`（第 76 行）。问号是取回件的形态：这些字段在文档页上原本是一张可展开的取值表，扁平化后只剩 `?`。

这既是取证机会也是陷阱。**机会**：取值语义仍然写在行内散文里（三值 `Allowed`/`AlwaysOn`/`AlwaysOff`、两值 `All`/`Oldest`），因此本文仍然可以做成员检查；**陷阱**：任何自称"从文档枚举了合法取值"的工具，其枚举来源实际上是散文而不是取值表，必须在报告里说明（第 21.5 节记的第三个真实缺陷正是这一类：早期版本用"大写点分形式"这种文档里查不到原句的启发式判合法性，已改为按取值表/散文取值做精确成员检查）。

### 11.7 L8 的缺陷形态、责任方与更新通道

| 缺陷形态 | 表现 | 谁改 | 通道 |
| --- | --- | --- | --- |
| 用五值表实现状态机 | 丢失 `waiting` 段（11.2） | MDM 实现 | 实现代码（与 Apple 文档一起滞后） |
| 把 `failure-reason` 当原因 | 无枚举（11.4） | 台账 | 判定语言 |
| 只记 version | 丢 BSI 轴（11.5） | 台账 | 台账 schema |
| 空串当异常 | 与"被声明强制在 beta"不可分（11.5） | 判定模型 | 第 19 章 |
| 订阅表缺 device-id | GDMF 查询无键（11.1） | MDM 实现 | 订阅声明 |

这一层的写权限分散：词表归 Apple（文档），实现归 MDM 厂商，判定归台账。**它是本文里唯一"读者改不动但能自检"的层**——第 21 章脚本一逐行读台账自己写下的字段与取值（词表口径这一格就是 E01/E02/E03），第 22 章脚本二的资产件同样只按这台设备登记的 `installed` 与 `target` 读数来判。两套都只吃读者自己整理的文本，不联网、不碰设备。

---

## 12. L9 回滚与移除层

### 12.1 两种回滚面：一种存在，一种不存在

本文第 12 章只在两个方向上成立：BSI 可移除（可回滚），整版本不可降级。后者的口径句写在《Apple security releases》第 30 行（"it cannot be downgraded to the previous version"）与《Secure software updates》第 248 行 / 指南第 1159 行（Secure Enclave 侧 "is designed to prevent downgrade installations"）。前者的口径句分散在四处：

| 句子 | 出处 | 责任方 |
| --- | --- | --- |
| "A Background Security Improvement can be removed, which reverts the device to the baseline software update state with no Background Security Improvements applied." | 《Background Security Improvements in Apple operating systems》第 245 行 / 指南第 1172 行 | 设备/用户 |
| "A Background Security Improvement can be reapplied after removal." | 指南第 1173 行 | 设备 |
| "If a Background Security Improvement has been applied, and you choose to remove it, your device reverts to the baseline software update (for example, iOS 26.3) with no Background Security Improvements applied." | 《About Background Security Improvements…》第 29 行 | 用户 |
| "If you choose to turn off this setting, your device will not receive these improvements until they're included in a subsequent software update." | 同页第 28 行 | 用户 |

技术侧的移除内容由第 252 行给出（"the removal action removes all currently installed Background Security Improvements (returning all cryptexes to their base state) and returns patched system binaries to the version from the last installed software update. The user needs to restar…"）；机制侧由第 251 / 指南第 1178 行的 patch + antipatch 给出；Apple 侧的主动移除由第 20 行（bsi-about）与第 251 行（bsi-guide）共同覆盖（"in the rare event that a Background Security Improvement affects software compatibility or quality, Apple may remove the most recently applied Background Security Improvement from users' devices using the Automatic Software Update mechanism"）。

### 12.2 管理侧唯一开关：`EnableRollback`

《SoftwareUpdateSettingsRapidSecurityResponseObject》第 12 行的 `EnableRollback` 是这一层唯一由管理方控制的键（原文见第 9.5 节）。它控制的是**是否向用户提供回滚选项**，不是设备能否回滚——第 251 行明说 Apple 自身仍可因兼容性问题移除某次 BSI，这条通道不受 `EnableRollback` 约束。所以"关掉回滚"的实际效果是"关掉了用户的撤销权，但没关掉系统自身的撤销能力"，这一读法差异在合规文本里很容易被写成过度承诺。本文把它列为误区 M8。

### 12.3 旧词表的两把 restriction 键：Removed 但仍在页上

《Restrictions》第 186—187 行是第 3 章 C4 的实体证据：

- 第 186 行："PROP allowRapidSecurityResponseInstallation [boolean; default=true] If false, the system prohibits installation of Background Security Improvements. Removed: use the declarative management com.apple.configuration.softwareupdate.settings configuration. Available: iOS 16+ | iPadOS 16+ | macOS 13+ Dep…"
- 第 187 行："PROP allowRapidSecurityResponseRemoval [boolean; default=true] If false, the system prohibits removal of Background Security Improvements. Removed: use the declarative management com.apple.configuration.softwareupdate.settings configuration."

两行同页的说明文字已经改用 Background Security Improvements 的说法，键名却仍是 `RapidSecurityResponse`，并且 `Removed:` 与 `Deprecated:` 两种标注在同一段里并存（第 186 行尾部即出现 `Deprecated: i…`）。因此"BSI 与 Rapid Security Response 是同一件事"这句话在公开产物里的唯一证据就是这两行 MDM 键名——本文不把它当结论，只当一个可核对的词表现象（第 26 章缺口 G7：改名过程没有公开的映射文档）。

### 12.4 macOS 的三类背景更新与"重启才有作用"

《About background updates in macOS》第 23 行的后半句是这一层在 macOS 上最难读的一句："They don't cause your Mac to restart, but some take effect only after you restart your Mac."，第 41 行给出重启时才发生的一次清除动作（"When you restart your Mac, these updates also remove any malicious software that is identified but already installed."）。第 18、36 行的三类枚举（BSI / security-configuration updates / system data files）里，只有 BSI 有 iOS/iPadOS 对应面，另两类只在 macOS 文档面出现。

### 12.5 "移除之后读数长什么样"没有闭合句子

第 12.1 节的四句移除语义里，没有一句说明移除后 `supplemental.build-version` 与 `supplemental.extra-version` 会变成什么。第 11.5 节两行的示例值形如 `20A123a`（含补充标识）与 `a`（仅标识），移除后按 252 行应回到基线，但"回到基线"在两个读数里的具体形态（空串？基线构建号？字段缺失？）没有公开句。第 21 章脚本一因此把这条做成边界信号 B06（`supplemental` 读数非空而撤除状态登记为 unknown：撤除没有独立状态项，移除态与在装态在台账里不可区分），而不是硬判"已成功回滚"。

顺带记录 macOS 侧的一个可达性缺口（第 8.5 节的外置盘）在回滚面上的等价问题：从外置盘启动时"作为后续软件更新的一部分"接收 BSI，那么移除面是否同样按启动介质区分，文档没有说。这是缺口 G8。

### 12.6 L9 的缺陷形态、责任方与更新通道

| 缺陷形态 | 表现 | 谁改 | 通道 |
| --- | --- | --- | --- |
| 台账里写"可降级到 x.y.z-1" | L3 直接拒绝（12.1） | 管理方 | 预案（无效预案） |
| `EnableRollback=false` 当"不可回滚" | Apple 侧移除仍成立（12.2） | 管理方 | 声明 + 文案 |
| 沿用旧 `allowRapidSecurityResponse*` 键 | Removed 标注仍在页上（12.3） | MDM 服务 | profile → 声明迁移 |
| 移除后读数假定 | 无闭合句（12.5） | 判定模型 | 缺口 G8 |
| 外置盘启动的 macOS | 到达面与移除面均不同（8.5/12.5） | 设备使用方 | 启动介质 |

---

## 13. L10 外设与旁路通道层

### 13.1 公告表里有 17 行不属于任何 OS 更新通道

`C/release-readings.txt` 第 11 行的读数是 `Other      all=17   no_published_cves=1`；该文件第 36—52 行把这些行的存档行号、名称、日期与"无 CVE"标志列了出来，其中九行最有代表性（本文逐行引用时按存档行号）：

| 存档行 | 名称 | 日期 |
| --- | --- | --- |
| 第 196 行 | Beats Firmware Update 1B211 | 16 Jun 2026 |
| 第 366 行 | Security Update 2026-001 Catalina | 02 Feb 2026 |
| 第 382 行 | Keynote 15.1 | 28 Jan 2026 |
| 第 588 行 | Apple Music Classical 2.3 for Android | 19 Jun 2025 |
| 第 637 行 | CarPlay Communication Plug-in R18.1 Updates | 04 Apr 2025 |
| 第 643 行 | AirPlay audio SDK 2.7.1 and AirPlay video SDK 3.6.0.126 | 31 Mar 2025 |
| 第 823 行 | Apple Music 1.5.0.152 for Windows | 03 Oct 2024 |
| 第 878 行 | iTunes 12.13.3 for Windows | 12 Sep 2024 |
| 第 1086 行 | Magic Keyboard Firmware Update 2.0.6 | 09 Jan 2024 |

`C/release-readings.txt` 第 43 行与第 44 行分别是 CarPlay 与 AirPlay 两条派生读数；第 55、56 行给出整张表的两端（第 55 行是 `newest: line 35 | Xcode 27.2 | 29 Oct 2026`，第 56 行是上面最后一行）。第 31—33 行的版本线表则显示 iOS+iPadOS 族从 27.2 一直排到 12.5.8——**79 行里最老的一条线仍在发版**，这是 L10 的另一半：不是"外设"，而是"仍在接收补丁的旧版本线"。

### 13.2 这一层的强制通道不存在

第 5.4 节的 GDMF 规则与第 10 章的 `TargetOSVersion`（"This is the OS version number, for example, 16.1 ."）合起来给出一个直接结论：**MDM 的强制声明无法命中固件类、SDK 类、应用类更新**。这些行的更新通道分别是外设自身的固件更新流程（AirPods/Beats/键盘）、CarPlay 端接入的通信插件版本、第三方宿主应用（Windows/Mac 上的 iTunes、Apple Music）或 SDK 分发。它们既不在 `SoftwareUpdateSettings` 的延期面里，也不在 `enforcement.specific` 的命中面里。

### 13.3 但公告里有它们的 CVE

本轮三份公告的组件分布（`B/CSAF/*-cves.tsv.summary.txt`）里，APPLE-SA-149041 单列了 `Baseband`（1 条）与 `MobileAccessoryUpdater`（1 条）两个组件。也就是说，**一条被写在 iOS 公告里的 CVE，其修复可能落在基带或配件更新器上**，而配件本身的固件行（13.1 那些）另有一张表。这是第 14 章 P11 型缺陷（"归属到错误的更新通道"）的直接实例：修 iOS 版本的动作不会自动修外设，反之外设固件行也不在 iOS 的版本读数里体现。

### 13.4 三条可见性后果

1. 台账如果以"设备 OS 版本"为主键，这 17 行永远不会进入覆盖判定（第 20 章 O8 专门度量这类不可判定资产）。
2. 外设的 CVE 出现在 OS 公告组件表里（13.3），而外设的**发布**出现在另一行——两侧的连接点在公开口径里只有组件名这一个自由文本标签（第 4.3 节）。
3. `C/kev-apple.tsv` 里 `product` 字段出现过 `Multiple Products`（例如本轮存档里 CVE-2026-86950 那条，其 `shortDescription` 提到 iOS、macOS 与 iPadOS），说明外部应急口径同样不做外设切分。

### 13.5 L10 的缺陷形态、责任方与更新通道

| 缺陷形态 | 表现 | 谁改 | 通道 |
| --- | --- | --- | --- |
| 用 OS 强制通道覆盖外设 | 声明永不命中（13.2） | 管理方 | 外设自身更新流程 |
| 忽略仍在发版的旧版本线 | 12.5.8 / 15.8.x / 16.7.x 线仍在表内 | 台账 | 版本线清单 |
| 配件类 CVE 归属到 OS 更新 | 组件名是唯一连接点（13.3） | 判定模型 | 第 19 章 |
| 把 Windows/Android 上的 Apple 应用当设备面 | 完全不同的更新通道 | 台账 | 资产分类 |

---
## 14. 缺陷类型学 P1—P12

前十章按"格子"拆完了这条链路，本章按**"在哪一次校验被放过"**重新切一刀。这个轴不是为了好看：更新链上的每一种缺陷，都会在同一格留下**同一个可核对症状**——"文档说了，产物里没有"或"产物里有，读数里看不见"。把症状当成分类依据，读者用手上的公开文本就能分型，而不需要拿到设备。

每个类型给六件事：**断在哪一层、触发条件、这一格的修改权、修完之后最早出现读数的时点、本轮存档里的最小证据、读者能做的只读自证**。六项里最后一项是本文的落点：一个不能只读自证的类型，只能进第 26 章的缺口清单，不能进运营指标。

### 14.1 十二型总表

| 型 | 层 | 触发条件 | 修改权 | 修完后最早读数 | 只读自证 |
| --- | --- | --- | --- | --- | --- |
| P1 无入口 | L1 | 公告行没有 CVE 条目，覆盖判定拿不到主键 | Apple 发布与安全工程 | 下一次同版本线公告 | 台账比对：数出无 CVE 行占比（脚本二 R8） |
| P2 标签漂移 | L1 | 同一缺陷族在不同公告里用不同组件名 | Apple 公告写作口径 | 无（不影响设备） | 组件名跨公告对齐（脚本二 R5） |
| P3 目录不可见 | L2 | 版本在 `PublicAssetSets` 但不在 `AssetSets` | Apple 目录发布 | 目录更新当日 | 台账比对管理侧清单是否含该版本 |
| P4 签名过期 | L2 | 发布后约 180 天，`ExpirationDate` 到期 | Apple 目录策略（时效） | 过期即不可装，无读数 | 台账里 `PostingDate + 180` 与当前日期比较 |
| P5 授权闸门 | L3 | 授权服务器不匹配 measurements，或无网络 | Apple 安装授权服务 | 装机当场失败，回执只有 `failed` | 只能从 `install-state=failed` 反推，无法定位 |
| P6 分发受阻 | L4 | OTA 不可用、VPN/代理阻断、空间不足、缓存缺失 | 网络环境与设备用户 | 阻断期间无任何状态推进 | 台账记阻断条件 + 设备侧 `downloading` 是否停更 |
| P7 装配失败 | L4/L5 | 补充版本缺 base 版本，或准备阶段失败 | Apple 版本装配规则 | `prepared` 不出现，直接 `failed` | 台账里目标版本与设备当前版本是否同族 |
| P8 通道错配 | L5 | 该由 BSI 交付的修复只能等整版本，或强制配置写法导致 BSI 不被安装 | Apple 通道设计 + MDM 写法 | 整版本发布日（可能晚数周） | 台账比对只写 `TargetOSVersion` 还是写了 build |
| P9 策略推迟 | L6 | 延期键、自动动作键、标准用户键、supervised 缺失 | 企业 IT 的取值 | 推迟期满前无推进 | 脚本一按 Apple 文档口径逐键预演 |
| P10 强制写错 | L7 | 目标版本不存在/同版本/更旧、时间串无时区、队列取最早 | MDM 模板 + 企业 IT 取值 | 声明保持 active 但永不推进 | 台账里目标版本能否在目录清单里找到 |
| P11 回执盲区 | L8 | 词表不闭合、取值域未展开、字典内部字段未取回 | Apple 文档口径 | 读数存在但不可解释 | 脚本一的 E 类错误码（读数落不进任何词表） |
| P12 静默撤销 | L9 | BSI 被移除（自动回滚或用户选择），回到基线 | Apple 回滚机制 + 设备用户选择 | 移除后无闭合句可读 | 台账比对 `EnableRollback` 与 `extra-version` 是否变空 |

一句总括：**P1—P4 是"补丁还没进到你能看见的集合里"，P5—P7 是"进到集合里但装不上"，P8—P10 是"装得上但策略或写法让它不装"，P11—P12 是"装了但你看不到、或又被撤掉了"**。

### 14.2 P1 无入口：覆盖判定没有主键

公告表里有 61 行只写着同一句话，占 18.4%（`C/release-readings.txt` 第 2 行）。这句话在整份 `Apple security releases` 页面里出现 61 次，本身是**可数的**："This update has no published CVE entries."（《Apple security releases》第 69 行）。

它的后果不是"这次更新没有内容"，而是**以 CVE 为主键的补丁台账在这一行上无法落地**：台账问"这条 CVE 修在哪个版本"，公告答"这一行没有 CVE"。于是这一行既不能被证明覆盖、也不能被证明不覆盖。本文把它列进第 16 章读数 R1，并让脚本二把这类行单独计数而不是丢弃。

反直觉的一点：**没有 CVE 条目的行里，`iOS` 这个族占 4/5（`C/release-readings.txt` 第 14 行）**——也就是最老的 iOS 12.5.x/15.8.x 线（第 32 行的版本清单尾部）。这些行仍在发布，却几乎不给可判定的内容。

### 14.3 P2 标签漂移：组件名不是稳定主键

本轮三份 2026-10-26 的公告机器件里，组件去重数分别是 57、54、67（`B/CSAF/149041-cves.tsv.summary.txt`、`B/CSAF/149227-cves.tsv.summary.txt`、`B/CSAF/149230-cves.tsv.summary.txt` 的 `distinctComponents` 行）。把 149041 与 149230 的组件名集合做交集与差集，得到**同名 24 个、149041 独占 33 个、149230 独占 43 个**；三份同时出现的标签只有 22 个，恰好两份出现的 33 个，只在一份里出现的 46 个。其中 `WebKit` 在一份里同时出现为 `WebKit`、`WebKit Canvas` 等标签，`Photos` 与 `Photos Storage` 分列两份公告。

结论要写成可执行的口径：**组件名只能用于人工阅读，不能用于跨公告聚合**。任何"这个组件的修复频率"统计，在标签不稳定时得到的数都是标签口径的产物，不是缺陷口径的产物。本文在归属矩阵（第 15 章）里把 L1 的证据产物写成"CVE-ID 优先、组件名仅作辅助"。

### 14.4 P3 目录不可见：两个列表不是同一个集合

"AssetSets: This list is a subset of PublicAssetSets and contains all the releases available for device management services to push to devices."（《Deploying software updates using declarative management》第 10 行）

一句定义就把管理侧的可见集合钉成公开集合的**子集**。因此同一次发布在两条路径上的可达时点可以不同：普通用户走 OTA 能看到（第 9 行的 `PublicAssetSets`），管理服务只能推到子集里的版本。这不是"文档没写清"，而是文档写清了、但**台账里没有任何字段记录"某一版曾不在子集里"**——于是 P3 的自证只能靠当期目录快照比对，无法事后回溯。这是第 26 章缺口 G2 的第二层含义。

### 14.5 P4 签名过期：这条链路上唯一有明确"保质期"的一格

"The expiration date, typically set to 180 days after the posting date, defines the date the signing of the update expires. An expired update can't be installed."（《Deploying software updates using declarative management》第 13 行）

这一句在本章表里是唯一给出**具体天数**的过期规则，也是台账最容易自证的一格：只要一行记录里有 `PostingDate`，就能算出 `PostingDate + 180` 与今天的关系。要注意"typically"这个词——它把 180 写成常态而非保证，所以脚本把超过 180 天记为**预警**而不是结论。

对运维的实际含义：一台长期离线、版本停在 8 个月前的设备，它"想装也装不上"，而这一格失败在设备侧不留任何专属读数（P5 会紧接着出现，`install-state` 只到 `failed`）。

### 14.6 P5 授权闸门：装了才知道不放行

"The authorization server checks the presented list of measurements against versions whose installation is permitted and, if it finds a match, adds the ECID to the measurements before generating the signed bundle."（《Apple Platform Security》第 1155 行）

"The personalization process is why a network connection to Apple is always required to update any device with Apple-designed silicon, including an Intel-based Mac with the T2 chip."（同页第 1158 行）

这一格有两个性质决定它在类型学里的位置：**它是强制联网的**（没有离线兜底），**它的失败不产生专用词**（设备只会落到 `failed`，第 11 章已述）。所以 P5 在"只读自证"这一列上是十二型里最弱的之一：读者能从公开文本确认闸门存在、规则是逐设备签名，但不能从公开文本推出任何一次具体放行结果。本文因此不把 P5 做成运营指标，只在第 19 章判定模型里作为 J2→J3 的必经检查点。

### 14.7 P6 分发受阻：环境把它挡住，文档把它写全了

三句合起来就是 P6 的完整形态：

"Some software updates aren't available wirelessly. VPN or proxy connections might prevent your device from contacting the update servers."（《Update your iPhone or iPad》第 31 行）

"If a message asks to temporarily remove apps because the software needs more space for the update, tap Continue to allow the system to remove apps."（同页第 33 行）

"If a content caching service is available to the device, it attempts to download the software update from the content cache."（《Phases of software update enforcement》第 22 行）

P6 的归属很特殊：**修改权不在 Apple，也不完全在管理员，而在设备当时的网络与存储状态**。而它留下的公开证据只有一条"应当如此"的句子，没有任何一条"失败时你会看到什么"。台账侧唯一可行的自证是把阻断条件当作**已知前置**记录（这台设备此刻走 VPN/磁盘剩余多少），否则第 19 章 J3 之后的判定就建立在一个没人核对过的假设上。

### 14.8 P7 装配失败：补充版本的 base 依赖

"The system can only install a supplemental software update on a device that already has the base OS version installed."（《SoftwareUpdateEnforcementSpecific》第 16 行）

同页第 15 行是它的姊妹规则："The system installs the specific version set in the TargetOSVersion, and it won't install a patch version if only a minor version is set."

两条合起来定义了 P7 的触发面：**目标写得"粗"（只到 minor）装不到具体补丁，目标写得"新"（补充版本）而设备不在 base 上就装不了**。第 8.3 节给出的 cryptex 形态说明 BSI 为什么能免 reseal，但它不改变这条装配前置。这也是第 26 章缺口 G7 的所在——BSI 与其 base 版本之间的绑定关系，在公开产物里只能通过"版本行写法"（如 `iOS 26.3.1 (a)`，《Background Security Improvements by date》第 25 行）间接读出，没有任何字段把二者显式连起来。

### 14.9 P8 通道错配：谁决定这个修复走哪条通道

"The operating system automatically installs any available Background Security Improvements if a device management service defines only the TargetOSVersion."（《Deploying software updates using declarative management》第 137 行）

"If you specify only OSVersion, a device automatically downloads and installs any Background Security Improvements available for this version. If a specific build or supplemental version is needed, a device management service can also optionally specify the BuildVersion."（同页第 97 行）

这两句同页相邻、语义一致，合起来给出 P8 的**写法依赖**：精确到 build 的强制配置会绕开"自动装所有可用 BSI"这条路径。管理员追求"可复现的精确版本"这一正常动机，在通道口径下变成了"这台设备可能少拿到一批轻量修复"。

再加一句版本线前提："Background Security Improvements always apply to the latest update of an operating system, which becomes the base version of the Background Security Improvement."（同页第 105 行），以及第 106 行写明 iOS 18 / iPadOS 18 / macOS 15 之前管理服务"可能需要发起两次更新"。所以 **P8 在老版本线上是结构性缺陷**，不是配置缺陷：老设备只能靠整版本拿到修复，而整版本的节奏由 L1 决定。

### 14.10 P9 策略推迟：十二型里唯一由取值直接决定的一格

"Deferring a software update or upgrade from 1 to 90 days is done using the SoftwareUpdateSettings declaration on supervised iPhone, iPad, and Mac devices."（《Deploying software updates using declarative management》第 113 行）

这一格里最伤人的一条不是数字，是**两份文档对同一件事给出相反预期**：属性页写 "Background Security Improvements aren't considered in Major, Minor, or System deferral mechanism"（《SoftwareUpdateSettings》第 73 行），部署指南旁注写 "Deferring software updates also defers any Background Security Improvements that are dependent on that version."（《Deploying software updates using declarative management》第 115 行）。本文在第 3.4 节把这一对列为换算失败 C3，在类型学里它就是 **P9 的子型 P9b：推迟的边界不可判定**。

P9 的另一子型是"没有监督"：延期与自动动作键都挂在 supervised 设备口径下，非监督设备上这些键根本不参与；而属性页的 `AllowStandardUserOSUpdates`（《SoftwareUpdateSettings》第 70 行）说的是"标准用户能否执行 Major/Minor 更新"，与延期是两种不同的推迟来源。**同一个"这台设备三个月没打补丁"现象，在台账里至少有三条成因（延期、自动动作被限制、标准用户权限），而公开读数不会区分它们。**

### 14.11 P10 强制写错：声明可以永远正确且永远不生效

"If the TargetOSVersion and optional TargetBuildVersion values don't match an available software update, the device keeps the configuration active, but it doesn't install an update."（《SoftwareUpdateEnforcementSpecific》第 13 行）

"If a configuration gets applied to a device that specifies an operating system or build version that's the same as, or older than the current device version, the configuration doesn't result in an update."（《Deploying software updates using declarative management》第 118 行）

"P10 的恐怖之处在第 13 行的前半句：**配置保持 active**。它不会报错、不会失效、不会从队列里消失，只是不装。任何按"声明是否已下发"来做覆盖判定的台账，都会在这一格得出"已强制"的错误结论。

再加两条队列与时间规则：同一设备多个更新配置时按最早截止日期处理（《Deploying …》第 119—120 行），而 `TargetLocalDateTime` 的格式串本身不带时区（《SoftwareUpdateEnforcementSpecific》第 59 行）。第 10 章已给出台账写法建议：把时区当作独立字段，不写进时间串。

### 14.12 P11 回执盲区：读数存在但词表不闭合

"The software update install status, which has the following values: none : There's no software update pending, and any previous software update succeeded."（《StatusSoftwareUpdateInstallState》第 33 行，整行是扁平件里的一条属性行）

同一份文档链上，《Deploying software updates using declarative management》第 56—61 行列了 6 个值并把 `waiting` 排在第二位——"waiting: A software update is waiting to start."（同页第 57 行），而《Phases of software update enforcement》第 20 行明确把 `waiting` 当阶段 2 的产出："A StatusSoftwareUpdateInstallState value of waiting, which indicates the process to request the update has started."

三处合读得出一条 P11 的判定：**状态词表在文档内部不闭合，且没有任何一处写着"设备可能上报词表之外的值"**。而属性行里 `allowedValues=?` 在扁平存档中全部未展开（第 11.6 节）。于是 P11 的自证形式是脚本一的 E 类错误：读数落不进台账所选的那一套词表，就报"词表口径不一致"，而不是报"设备错了"。

### 14.13 P12 静默撤销：装了、撤了、没有闭合读数

"A Background Security Improvement can be removed, which reverts the device to the baseline software update state with no Background Security Improvements applied."（《Apple Platform Security》第 1172 行）

"If the user removes Background Security Improvements, the removal action removes all currently installed Background Security Improvements (returning all cryptexes to their prior state)."（同页第 1179 行）

"• A Background Security Improvement can be reapplied after removal."（同页第 1173 行）

P12 与 P9 的区别在于**方向**：P9 是"还没装"，P12 是"装了又不在"。而公开产物里唯一能提示 P12 发生过的，是版本读数字段本身——`device.operating-system.supplemental.extra-version`（《StatusDeviceOperatingSystemSupplementalExtraVersion》第 44 行）在移除后应当回到什么形态，文档没有闭合句（第 12.5 节，缺口 G8）。管理侧唯一的开关是 `EnableRollback`（《SoftwareUpdateSettingsRapidSecurityResponseObject》第 12 行），它控制的是**是否向用户提供回滚选项**，不是系统自身能否回滚——这句话的读法差异正是第 24 章误区 M8。

### 14.14 十二型的最小覆盖检查

要让本章的类型学可被反驳，需要一条"任何一次补丁不生效都能落进某一型"的断言。本文的做法不是宣称它成立，而是给出检查方法：脚本一对解析不出〈设备,字段,值〉三列的记录输出 U01、对缺设备标识因而无法逐台归类的记录输出 U02；脚本二对没有落进任何公告 CVE 并集的在野条目输出 K1、对条目数为 0 的公告件输出 R8。本轮验收里这四个计数在构造的合格输入上都是 0（第 23 章），这只说明**本轮样本没有暴露第十一型**，不说明不存在。

---

## 15. 归属矩阵：层 × 责任方 × 更新通道 × 证据

第 14 章回答"断在哪一次校验"，本章回答另外两问：**这一格谁说了算**，以及**修完之后要多久才能在读数里看见**。第三列"更新通道"是本文特有的一列，因为这条链路上同一台设备可能同时挂在两条通道上（整版本与 BSI），而两条通道的责任方不同。

### 15.1 责任方词表

| 代号 | 责任方 | 在这条链路上的权力来源 |
| --- | --- | --- |
| R-A1 | Apple 发布与安全工程 | 决定公告内容与 CVE 条目（L1、L10） |
| R-A2 | Apple 目录与安装授权服务 | 决定哪些版本可见、可签、可装（L2、L3） |
| R-A3 | Apple 通道设计 | 决定缺陷走整版本还是 BSI（L5、L9） |
| R-V1 | MDM 产品厂商 | 决定声明模板暴露哪些键、默认值是什么（L6、L7） |
| R-E1 | 企业 IT 管理员 | 决定取值：延期天数、自动动作、目标版本、截止时间（L6、L7） |
| R-U1 | 设备用户 | 一次点击：安装、重启、移除 BSI、关闭设置项（L4、L5、L9） |
| R-P1 | 配件/外设固件发布节奏 | 决定固件何时更新，与 OS 版本线无关（L10） |
| R-X1 | "这一版线还有没有人维护" | 不由任何单方决定，只由发布事实体现（L1、L10） |

R-X1 是本文加的一列责任方，理由在第 4 章与第 13 章的读数里：老版本线仍在发（`C/release-readings.txt` 第 31—33 行的版本清单尾部有 12.5.8、15.8.x、16.7.x），但 61 行无 CVE 条目里 `iOS` 族占 4/5。**这一格的"归属"没有主体，只有事实**，所以任何台账在把设备按"最后维护版本线"归档时，实际上是在替 R-X1 做决定。

### 15.2 归属矩阵

| 层 | 主要缺陷型 | 责任方 | 整版本通道 | BSI 通道 | 证据产物 | 修完后最早读数 |
| --- | --- | --- | --- | --- | --- | --- |
| L1 发布与公告 | P1、P2 | R-A1、R-X1 | 有 | 有（组件级） | 公告页 + CSAF 机器件 | 无（当日即公告） |
| L2 版本可见 | P3、P4 | R-A2 | 有 | 有 | 目录文档口径 + 三个列表定义 | 目录更新当日 |
| L3 授权与个性化 | P5 | R-A2 | 有 | 不适用 | 平台安全指南第 1155—1159 行 | 装机当场（只有 `failed`） |
| L4 分发与装配 | P6、P7 | R-U1、R-E1（网络/空间） | 有 | 有 | 用户文档 + phases 第 19—23 行 | 下载开始即有 `downloading` |
| L5 安装形态 | P8 | R-A3、R-V1、R-E1 | 有 | 有 | BSI 三件套文档 + 指南 1168—1179 行 | 重启即生效；Safari 类重开浏览器即生效 |
| L6 策略与延期 | P9 | R-E1、R-V1 | 有 | 边界不可判定（C3） | SoftwareUpdateSettings 全键表 | 期满前无任何推进 |
| L7 强制与申报 | P10 | R-V1、R-E1 | 有 | 写法决定（第 137 行） | enforcement 声明文档 + 403 结构 | 声明 active，但不推进 |
| L8 回执与读数 | P11 | R-A1（文档口径） | 有 | 有（两个补充读数） | 状态项页 + 建议订阅表 | 状态变更即上报（无延迟定义） |
| L9 回滚与移除 | P12 | R-A3、R-U1 | 不适用 | 有 | 指南 1172—1173、1178—1179 行 | 移除后无闭合读数（G8） |
| L10 外设与旁路 | P1（局部） | R-P1 | 无 | 无 | 公告表 17 行"Other" | 无（不在 OS 通道上） |

矩阵里三处值得停下来看：

1. **L3 的"BSI 通道：不适用"**不是猜测。第 8 章引的差异表里，BSI 的免 reseal、低电量门槛都写在**整版本更新的对照**语境下；而授权闸门本身对两种形态都要签名放行，只是文档从不为 BSI 单独描述这一步。这是缺口，不是结论。
2. **L6 的"边界不可判定（C3）"**：文档给了两条相反的句子，所以这一格连"BSI 会不会被延期"都写不出结论。矩阵在这里不选边，只把两句话的行号一起留下（《SoftwareUpdateSettings》第 73 行 / 《Deploying …》第 115 行）。
3. **L10 的"证据产物只有 17 行表格"**：CarPlay Communication Plug-in、AirPlay SDK、Keynote/Pages/Compressor/GarageBand、Windows 与 Android 上的 Apple 应用、Magic Keyboard 与 AirPods 固件都在公告里占行（`C/release-readings.txt` 第 36—52 行），但没有任何一格说明这些行如何进入设备侧覆盖判定。第 13 章给出的三条可见性后果在这里被压缩成一句：**它们对以 OS 版本为主键的台账永远是隐形的**。

### 15.3 按"修完之后多久能看见"重排

归属矩阵的最后一列，如果只按"快慢"排序，会得出一条与直觉相反的结论：

| 等待时间 | 层与条件 | 依据 |
| --- | --- | --- |
| 0（立即，无需重启） | L5 macOS Safari 类 BSI | 《Apple Platform Security》第 1169 行 |
| 一次重启 | L5 BSI 生效 | 同页第 1170 行（免 reseal、免 RAM disk） |
| 当场，但失败无专用词 | L3 授权闸门 | 同页第 1158 行（必须联网） |
| 状态变更即上报 | L8 回执 | 《Phases …》第 13 行（管理服务需订阅状态报告） |
| 期满才推进（1—90 天） | L6 延期 | 《Deploying …》第 113 行 |
| 永不推进（无错误） | L7 目标不匹配 | 《SoftwareUpdateEnforcementSpecific》第 13 行 |
| 不可回溯 | L2 目录子集历史、过期时刻 | 缺口 G2 |
| 无通道 | L10 外设固件 | `C/release-readings.txt` 第 36—52 行 |

这张重排表说明：**这条链路上"最快的一格"和"最慢的一格"都写在 Apple 的文档里，而中间那一格——"什么时候能证明它到了这台设备"——没有任何一格给出保证**。P9 的 90 天上限与 KEV 的 21/14 天窗口之间的落差（第 3.4 节 C6）正是把这张表的两端放在一起读才看得见的。

### 15.4 归属矩阵怎么用

本文不打算把它做成"责任归属结论表"，那是无根据的推断。它的用途限于三件事：

- **收敛问题**：一台设备"补丁没生效"时，先按第 14 章分型，再从矩阵读出这一格的 R-*，决定该找谁改（改模板 / 改取值 / 改网络 / 只能等 Apple）。
- **约束承诺**：对内部合规文本，矩阵最后一列可以直接反驳"我们的 MDM 已强制更新，所以设备已修复"这类句子——L7 那一行的"永不推进（无错误）"就是反例。
- **暴露缺口**：表里凡是"修完后最早读数"写成"无 / 不可回溯 / 无闭合读数"的格子，都必须在第 26 章有对应缺口项；反过来，第 26 章每条缺口都要能在这一列找到落点。

---

## 16. 公开读数：这条链路上能数出来的十八件事

本章只放**本轮存档里可以直接数出来或逐字核对出来的数**，不做推断。每条给：数值、取数方式、以及这个数**不能**说明什么。第 21、22 章两个脚本的验收基线（第 23 章）就是按这里的 R1—R18 设计的。

| # | 读数 | 本轮值 | 取数方式 | 不能说明 |
| --- | --- | --- | --- | --- |
| R1 | 公告表行总数 / 无 CVE 条目行 | 331 / 61（18.4%） | `C/release-readings.txt` 第 2 行；以"发布日期行"收口一行 | 不能说明这些更新不含安全修复 |
| R2 | 平台族分布（各族行数与无 CVE 行数） | macOS 91/10、iOS+iPadOS 79/17、watchOS 36/15、visionOS 32/5、tvOS 27/6、Safari 27/2、Other 17/1、iPadOS 9/1、Xcode 8/0、iOS 5/4 | 同文件第 5—14 行 | 族标签是页面写法产物，不是稳定主键（P2） |
| R3 | 同一发布日的并行行数（峰值） | 15 Sep 2025、24 Mar 2026、31 Mar 2025 各 12 行；26 Oct 2026 为 11 行 | 同文件第 17—28 行 | 不能说明同日各线内容相同 |
| R4 | 表内最老/最新行 | 最新 Xcode 27.2（2026-10-29，页面第 35 行）；最老 Magic Keyboard Firmware 2.0.6（2024-01-09，第 1086 行） | 同文件第 55—56 行 | 不能说明外设线维护状态 |
| R5 | 单日三线并发的 CVE 总量 | 95 + 134 + 163 = 392（三份公告 `cveCount`） | 三份 `B/CSAF/*-cves.tsv.summary.txt` 第 8 行字段 | 392 不是"当天修复的唯一缺陷数"，见 R6 |
| R6 | 三份公告 CVE 并集与交集 | 并集 270；149041∩149230 = 119，各自独占 44 与 15；149041∩149227 与 149227∩149230 另计 | 三份 `*-cves.tsv` 的 CVE 列做集合运算（脚本二同款） | 交集非累积：**不能**由"装了 27.2"推出"含 26.7 的全部修复" |
| R7 | 相邻两次同线更新的 CVE 交集 | 0（26.7 与 26.7.2 在本轮样本口径下无共享 CVE） | 两份公告 CVE 列取交集 | 不能说明内容无重叠，只能说明**公告口径下不可传递** |
| R8 | 组件去重数（三份） | 57 / 54 / 67（`distinctComponents`） | 三份 summary 的对应行 | 组件名标签不稳定（P2），聚合只能到 CVE 粒度 |
| R9 | 单份公告里的最大组件集中度 | 149230 中 WebKit 26 条、Kernel 15 条；149041 中 Kernel 20 条 | summary 的 `cvesInComponent` 行 | 集中度是写作口径，不代表攻击面占比 |
| R10 | 公告行里出现的"非 OS"组件 | Baseband 1 条、MobileAccessoryUpdater 1 条（APPLE-SA-149041） | `B/CSAF/149041-cves.tsv.summary.txt` 组件行 | 不能推出这些修复如何到达外设（第 13.2 节） |
| R11 | 同一公告的两个日期差 | APPLE-SA-149041：机器件 `releaseDate` 2026-10-26T19:02:02Z vs 页面行日期 14 Sep 2026，差 42 天；机器件 `version: 4` | 三份 summary 的 `releaseDate` 与公告表行日期比对 | 两个日期都合法，**不能取舍**（误区 M2） |
| R12 | KEV 里 Apple 在野条目数与修复窗口分布 | 95 条：21 天 63 条、14 天 22 条、3 天 1 条、181 天 9 条；非标准窗口 10 条 | `C/kev-apple-lag.txt` 第 1—11 行 | 窗口是应急要求，不是 Apple 的承诺时限 |
| R13 | KEV 与本轮三份公告的 CVE 交集 | 0（95 条 Apple 在野条目与 149041/149227/149230 的 CVE 集合均无交集） | KEV CVE 列与三份公告 CVE 列取交集 | 不能说明"这些公告不紧急"，只说明**两套口径不通约**（C6） |
| R14 | MDM 允许的最长延期 | 90 天 ×4 个键（`CombinedPeriodInDays`、`MajorPeriodInDays`、`MinorPeriodInDays`、`SystemPeriodInDays`，均 `minimum=1; maximum=90`） | 《SoftwareUpdateSettingsDeferralsObject》第 11—14 行 | 键的语义不覆盖 BSI 的边界不可判定（C3、P9b） |
| R15 | 策略对象规模 | settings 顶层 7 键；Deferrals 4 键；AutomaticActions 3 键；RapidSecurityResponse 2 键；Beta 3 键 | 《SoftwareUpdateSettings》第 70—76 行与四个对象页属性行 | 键数不等于可组合的策略数；合并语义另有一条句（第 9.6 节） |
| R16 | 目录签名时效 | 约 180 天（`PostingDate + 180` 为常态描述） | 《Deploying …》第 13 行 | "typically"不是保证；本轮不取实际响应（G2） |
| R17 | 回执面规模与两套词表差 | 状态项目录 65 项，其中软件更新侧 6 项、系统版本侧 4 项；"建议订阅"表 9 项；install-state 一处 6 值、一处 5 值（差 `waiting`） | 《Status items》第 20—82 行、《Deploying …》第 43—51 与 55—61 行、《StatusSoftwareUpdateInstallState》第 33 行 | 建议订阅表不含 `StatusSoftwareUpdateDeviceID`（G5） |
| R18 | 高频重复句（口径可信度分母） | "Available for: iPhone 11 and later…" 在整份语料出现 140 次；"Description: An out-of-bounds write issue was addressed with improved bounds checking." 出现 18 次 | 对 `B/pages/*.txt` 全文计数 | 重复句可作台账字段，不能当唯一引文（第 2 章转录约定） |

### 16.1 四条定基调的读数

R6、R7、R13、R14 合起来构成本文的主张，其余读数用来支撑它们：

- **R6 + R7（非累积）**：一次更新获得的修复集合，不能由版本大小关系推出。任何"版本 ≥ X 即覆盖 Y"的判定，都必须以公告 CVE 集合作为依据逐份比对。
- **R13（不通约）**：外部应急目录里的在野条目与本轮三份公告的 CVE 集合**交集为 0**。这说明 KEV 条目对应的修复分布在**其他版本线**上，用当日公告无法回答"KEV 这条修了没"。于是任何 KEV 驱动的优先级都必须落到"这台设备的版本线上有没有这一条"，而不是"最新公告里有没有这一条"。
- **R14 vs R12（约束冲突）**：MDM 允许的最长延期是 90 天，而 KEV 给 Apple 在野条目的窗口主要是 21 天与 14 天。两个数写在不同的公开产物里，**没有任何一份文档说明二者如何并存**。这不是谁错了，而是一条真实的口径断层，也是第 20 章 O6 的分子分母来源。

### 16.2 读数的可复现性

本章每一条都写成"文件 + 行/字段"的形式，目的是让读者在自己的存档上重跑同一动作得到同一数。三个例外要说明清楚：R16 来自文档句子（本轮不取实际目录响应）、R11 的 42 天由两个公开时间戳相减（两个日期都保留，见误区 M2）、R13 的交集为 0 依赖本轮 KEV 快照（KEV 会增长，这一条有时间戳属性）。这三点在脚本输出里都以"取数口径"字段原样带出，不做静默处理。

---
## 17. 可见性边界：这条链路上读者能拿到什么

前十章把链路拆开，第 14—16 章把缺陷分型、责任归属与可数出来的读数排好。但从这里开始，读者真正要回答的是另一个问题：**我手上到底有什么东西能证明第 14 章某一型没发生**。本章把这条链路上的可见性切成四级，逐层标出"公开面能拿到什么、设备面能拿到什么、管理面能拿到什么、哪一格是根本拿不到的"，并把三条硬边界用存档件里的原话钉住。

### 17.1 四个可得性等级

| 等级 | 名称 | 谁能拿到 | 本文的用法 | 判定模型里的地位 |
| --- | --- | --- | --- | --- |
| V1 | 公开可核对 | 任何人，不需要授权 | 公告表、CSAF、MDM 文档、平台安全指南、支持文档、CISA KEV | 唯一可以作为"分母"的一级 |
| V2 | 自有设备可得 | 设备的使用者 | 设置里的软件更新页、macOS 系统信息里的安装清单、System Settings 的 Background Security Improvements 面板 | 只能证明"这一台"，不能外推到资产面 |
| V3 | 管理侧可得 | MDM 服务的持有者 | 状态项上报、`DeviceInformationResponse`、声明处理状态、Content Cache 状态 | 逐台判定的主读数面 |
| V4 | 记录存在但公开面拿不到 | 没有（对读者而言） | 目录的历史快照、逐台授权决策、`failure-reason` 的逐字段码表、BSI 撤除事件、BSI 组件到 CVE 的逐条映射 | **一律落成"不可判定"，不许用推断填** |

第四行是本报告集在这一主题上最想强调的一条方法约束。V4 的五项里，只有前两项是"服务不公开"，后三项是**文档自己承认粒度不够或本轮没取回**：前者不是本文能改变的，后者在第 26 章逐条编号（G1、G7、G8、G4）。所以第 19 章的判定模型只允许用 V1—V3 的合取来做"已确认"，凡判定路径上出现一次 V4 就必须停在该级并标注理由。

### 17.2 逐层的可见性

| 层 | V1 公开面 | V2 设备面 | V3 管理面 | V4 拿不到 |
| --- | --- | --- | --- | --- |
| L1 发布与公告 | 331 行公告表、3 份 CSAF 公告的组件与 CVE 清单 | 无 | 无 | "这条 CVE 是否在这一台上被利用过" |
| L2 版本可见 | 三张清单的**字段口径**（文档），无历史快照 | 有没有更新的一个布尔面 | 由 MDM 产品厂商执行目录查询后的机型适用性表 | 目录的历史快照、`ExpirationDate` 的推算依据（G2） |
| L3 授权与个性化 | "过期即不可装"的文档规则 | 失败时的一个 alert，无原因码 | 无逐台授权回执 | 逐台授权决策记录（文档不提供口径） |
| L4 分发与装配 | 支持文档的两条受阻说明 | 临时移除 App 的一次点击 | Content Cache 四个状态项 | 单台下载的起止时刻的公开面 |
| L5 安装形态 | 整版本与 BSI 的语义差异、macOS 三类背景更新 | 系统信息里的安装清单，文档自限为 "most" | `supplemental.build-version` 与 `supplemental.extra-version` | 每台设备上"当前生效的 BSI 集合"清单 |
| L6 策略与延期 | 7 个顶层键 + `Deferrals` 4 键的取值域 | 用户看到的自动档位 | 管理员自己抄录的策略台账 | 多份配置合并后的**实际生效值** |
| L7 强制与申报 | 五参与方 / 七阶段、必填键表 | 截止弹窗 | 声明状态与队列规则 | 403 之后设备端逐阶段的时刻 |
| L8 回执与读数 | 本轮 11 个状态项页 | 无 | 状态项上报本体 | `failure-reason` 与 `install-reason` 字典对象的逐字段表（G1） |
| L9 回滚与移除 | `EnableRollback`、移除语义、旧键 Removed/Deprecated | 无独立界面 | 无撤除事件状态项 | 撤除发生的时刻与原因（G8） |
| L10 外设与旁路 | 公告表里的 17 行非六平台行、老版本线仍在发版 | 各配件自己的界面 | 不在这条通道上 | 配件固件版本的统一回执口径 |

### 17.3 三条硬边界，各自钉在原话上

**边界一：目录侧只有"现在"，没有"曾经"。** 查询服务的设计目的是及时性——"It allows a device management service to query releases as soon as Apple publishes them, and calculate applicability for each hardware model in a timely and accurate manner."（《Deploying software updates using declarative management》第 7 行）。三张清单的措辞全部是当前态：`PublicAssetSets` 是 "This list contains the latest releases available to the general public if they try to update or upgrade."（同页第 9 行），`AssetSets` 是 "This list is a subset of PublicAssetSets and contains all the releases available for device management services to push to devices."（同页第 10 行），`PublicBackgroundSecurityImprovements` 是 "This list contains Background Security Improvement releases currently available for Apple devices."（同页第 11 行）。本轮存档里没有任何一处文档给出"取回某历史日目录快照"的方式。

这条边界的直接后果落在 P3 与 P4 上：**版本可见性与签名时效是事后无法自证的**。一个机型在某天是否出现在 `AssetSets` 里、某个构建的 `ExpirationDate` 具体是哪天，只有在当时抓取才留得下来。第 16 章的 R11/R13 因此被标为"需自行留档"，第 26 章把它记为 G2。

**边界二：BSI 的公开面粒度是组件，不是 CVE，而本轮这一页只呈现一条数据行。** "This page lists Background Security Improvements and patched components."（《Background Security Improvements by date》第 18 行），表头四列是 Release、"Available for"、"Components patched"、"Release date"（同页第 21—24 行），而本轮取回的正文只有一条数据行：`iOS 26.3.1 (a), iPadOS 26.3.1 (a), macOS 26.3.1 (a), macOS 26.3.2 (a)` / 可用机型行 / `WebKit` / `17 Mar 2026`（同页第 25—28 行）。同页第 20 行写清了它与公告表的关系："When a release has relevant CVE-ID details, we also publish a security advisory and include the release in the Apple security releases page."

两个结论分开取。第一个可以下：**组件名是这一页唯一的可核对粒度**，所以第 14 章 P2 的标签漂移（WebKit 与 WebKit Canvas、Photos 与 Photos Storage 在 CSAF 里是不同组件）在这一页无法消解，只能靠组件名硬对齐——这正是 G7。第二个不能下：本轮不可据此推断 BSI 的总条数，因为"只有一条"既可能是页面本身只列最近一条，也可能是取回时的分页截断；本文按可核对事实记录条数、按可能性把它列为 G10。

**边界三：设备侧的"已装清单"自带限定词。** "System Information lists most Apple and third-party software that has been installed manually or automatically."（《About background updates in macOS》第 31 行）——文档用 "most" 自己承认这个读数面不闭合。同页第 23 行又给出第二个分裂："By default, these updates are installed or applied automatically. They don't cause your Mac to restart, but some take effect only after you restart your Mac."

iOS 侧还有第三条同类边界，而且它比"most"更彻底：系统文件更新按文档口径明确不改版本号——"Your device can automatically download and install system file updates to improve features without changing the software version."（《Update your iPhone or iPad》第 46 行）。这一句直接决定：任何一类"版本读数不变"的更新，都不可能在 V2 或 V3 的版本面上留痕，只能在别的面上找，或者接受找不到。

### 17.4 本文按这些边界做了什么、不做什么

做的三件事：第 18 章只列 V2/V3 上**文档写明存在**的读数；第 19 章的判定树在遇到 V4 时硬停；第 20 章的指标里给"不可判定"留出独立的分子（O8）。

不做的三件事：不构造目录或授权请求（第 2 章范围声明，也是两个脚本被明令禁止联网的实现层原因）；不把 V4 的缺口用"合理推断"补成 V1 的结论（脚本一遇到落不进词表的取值只报"词表口径不一致"，不报"设备错了"）；不用 V2 的单台读数替 V3 的资产面结论（第 19 章的 J 级是逐台判定，不是抽样）。

---

## 18. 设备侧与管理侧读数面

### 18.1 设备侧：使用者能看见的四件事

| # | 读数 | 存档出处 | 形态 | 用它做什么 |
| --- | --- | --- | --- | --- |
| 1 | 当前版本与"有没有更新" | 《Update your iPhone or iPad》第 26 行 | 一个页面，不是字段 | 判定"这台机器知不知道有更新" |
| 2 | 自动档位（两档 + 系统文件开关） | 同页第 43、44、51、52 行 | 开关组合 | 对齐 P8/P9 的通道选择 |
| 3 | 受阻时的两种话术 | 同页第 31、33 行 | 弹窗文案 | 区分 P6 的两个子类（网络受阻 / 空间不足） |
| 4 | macOS 三类背景更新与其安装清单 | 《About background updates in macOS》第 18、36、31—34 行 | 列表，自限为 "most" | 找 L5 的 BSI 痕迹 |

第 1 行的原话值得逐字看："Tap Software Update. The currently installed version of iOS is shown, and whether an update is available."——设备面给的是**当前版本加一个布尔**，不给目标版本、不给组件、不给 CVE。第 2 行里 "Automatically Install: When an update is available, iPhone downloads and installs the update overnight while charging and connected to Wi-Fi."（同页第 43 行）说明自动档的实际触发条件是三个合取：夜间、充电、Wi-Fi；这三项任何一项不满足，设备面看起来就"一切正常但没有装"，这是 P9 与 P8 在 V2 上最难分的一处。

第 3 行是 P6 的全部设备面证据：同一页第 31 行说 "Some software updates aren't available wirelessly. VPN or proxy connections might prevent your device from contacting the update servers."，第 33 行说空间不足时会请求临时移除应用。两句合起来给出的分类学很简单：**设备面的失败话术只区分"联系不上"和"装不下"，不区分"没授权""没进目录""被策略推迟"**。

### 18.2 管理侧：MDM 能收的六类读数

| 读数面 | 存档出处 | 本轮可核对的形态 | 落在哪一型 |
| --- | --- | --- | --- |
| 软件更新状态项 | 《Status items》第 64—69 行 | 6 个：beta-enrollment、device-id、failure-reason、install-reason、install-state、pending-version | P5—P11 |
| 系统版本状态项 | 同页第 30、33、34、35 行 | 4 个：version、build-version、supplemental.build-version、supplemental.extra-version | P8、P12 |
| Content Cache 状态项 | 同页第 20—23 行 | 4 个：Info、Parents、Peers、Status | P6 |
| 声明处理面 | 同页第 46 行 | `StatusManagementDeclarations` | P10 |
| 锁定模式面 | 同页第 62 行 | `StatusSecurityLockdownMode` | 边界项，见第 2 章互链表 |
| 错误语义层 | 同页第 4、5 行 | `StatusReport` 与 `StatusReason` 两个对象 | 全型的兜底 |

机型对齐这一格是管理侧的入口条件："The device list matches the ProductName or PRODUCT value from the device, which is returned in a DeviceInformationResponse, the initial Authenticate request, or in the MachineInfo when the device tries to enroll."（《Deploying software updates using declarative management》第 12 行）——`SupportedDevices` 用的字符串与设备上报的机型标识是同一套，因此**台账里用营销名（"iPhone 15 Pro"）写的机型行，与目录里的机型串天然对不上**，脚本二的 R7 信号专门核对这一条：台账 `model` 列里写的机型串在该公告的可用机型文本里找不到时输出。响应件的形状在《DeviceInformationResponse》第 19 行（`QueryResponses`）与第 21 行（`UDID`）。

上报机制本身要引一句，因为它决定了"读数有滞后"这件事不是实现缺陷而是协议形状："When the device receives the notification, it polls the device management service for the command, processes the command, and reports the command results to the service."（《Commands and queries》第 6 行）——命令靠推送唤醒、靠设备轮询取回、结果由设备自报。三处任一处不动，管理侧看到的就是旧值。

现在说本节最重要的一句：**这六类读数里没有任何一类携带 CVE 标识。** 管理侧回答的是"装到了哪个版本/构建、当前处于哪个状态"，不回答"修了哪一条"。这就是第 3 章换算失败清单里 C1 在实现层的形状：公告口径的分子是 CVE，回执口径的分子是版本与状态，两者之间没有任何公开字段可以做逐台映射。第 19 章之所以要有 J2 这一级，就是为了给这个缺口留一个诚实的名字。

### 18.3 两个面之间的三处系统性错位

**错位一（版本形态）。** V2 显示的是营销版本，V3 有四段读数，其中 `supplemental.build-version` 与 `supplemental.extra-version` 只在装了 Background Security Improvements 时非空（《Apple Platform Security》第 1172—1179 行给出的语义，另见《StatusDeviceOperatingSystemSupplementalBuildVersion》第 44 行）。于是**两台 `device.operating-system.version` 完全相同的设备，补丁面可以不同**，而 V2 上看不出来。

**错位二（词表不闭合）。** `install-state` 在《Deploying software updates using declarative management》第 56—61 行是 6 个值（含 `waiting`，"waiting: A software update is waiting to start."，同页第 57 行），在《StatusSoftwareUpdateInstallState》第 33 行只列 5 个（`waiting` 缺席），而《Phases of software update enforcement》第 20 行把 `waiting` 当作阶段 2 的产出。这是 P11 在 V3 上的具体表现，也是脚本一 E 类错误的第一条。

**错位三（"完成"的定义不同）。** V2 的 macOS 面上，"已安装"里含一档"要重启才生效"（《About background updates in macOS》第 23 行）；V3 的 `install-state=none` 只说 "There's no software update pending, and any previous software update succeeded."（《Deploying software updates using declarative management》第 56 行）。前者是**生效时点**问题，后者是**队列清空**问题。第 19 章 J1 与 J2 的分界线，一半就画在这里。

### 18.4 从读数反推缺陷型：每格能排除什么、不能确认什么

| 读数组合 | 可以排除 | 仍然无法区分 |
| --- | --- | --- |
| `pending-version` 空 + `install-state=none` + `build-version` 等于目标构建 | P3、P4、P5、P6、P7、P8、P9、P10 | P1、P2（公告面本身）；P12（撤除无读数） |
| `install-state=failed` | P1、P3（能进到装就说明进了目录） | P5、P6、P7 三者——`failure-reason` 逐字段表未取回（G1） |
| `install-state` 取值不在台账所选词表内 | 无 | 全部：这是 P11，只报"口径不一致" |
| `supplemental.build-version` 非空 | "这台没有 BSI" | "哪条 BSI 修了哪条 CVE"（G7）；BSI 是否已被撤（G8） |
| 台账 `AllowStandardUserOSUpdates` 为 false 且设备未被监管 | P1—P8 | P9 与 P10 的先后——两者都能让"没有装"成立 |
| 公告行含该 CVE + 目录当前含目标版本 + 回执 `none` | P1—P7、P9、P10 | P2（组件名口径）、P11、P12 |
| 机型串与目录 `SupportedDevices` 对不上 | 无 | P3 与"台账写法错"——两者在离线文本里同形 |

这张表是第 21、22 章两个脚本的判定逻辑说明：**每个脚本的每条错误码，都只被授权说它这一行"可以排除"之外的话**。凡"仍然无法区分"一栏非空的组合，脚本输出必须带"不可判定"字样而不是一个结论。

### 18.5 五份输入，正好是两个脚本的契约

按本节把采集面收拢，一个只读核验需要五份文本：（1）自己抄录或导出的**更新策略台账**（每行一条〈键,值〉或〈状态项,读数〉记录，含监管状态这一格）；（2）若干份**公告 CVE 集**（按版本线或按 CSAF 公告编号分文件）；（3）一份**在野条目集**（KEV 里 Apple 的条目与其修复窗口）；（4）可选的**目录快照**（若 MDM 产品能导出机型适用性表）；（5）可选的**设备回执文本**（状态项逐台一行）。第 21 章的脚本吃（1），第 22 章的脚本吃（2）（3）并可选吃（5）。第（4）项本文不给脚本，原因是第 17.3 节边界一的实现层版本：本轮不取目录响应件，脚本被明令禁止联网。

---

## 19. 四级判定模型

### 19.1 为什么两级不够

一个只回答"这台设备上打了补丁没有"的两级模型（已打 / 未打）在这条链路上会在三个地方失效：第 18.3 节的错位一让"已打"在版本面上不可见（P12 撤除、系统文件更新不改版本）；第 17.3 节的边界一让"未打"在事后无法证明（目录不可回看）；第 3 章的 C1 让"打了哪一条"根本无法从回执读出。三级模型（加一个"未知"）也不够，因为"未知"会同时混装两种性质完全不同的情形：一种是**读数存在但词表不闭合**（P11），另一种是**这一层压根不在读数面上**（P1、P12、L10）。前者可以靠换词表重采来消解，后者不能。

所以本模型用四级，把"不可判定"拆成有名字的两种，并把"装了但证明不了"单独留一级。

### 19.2 四级定义

| 级 | 名称 | 成立条件（合取） | 典型卡住的型 | 允许写进报告的话 |
| --- | --- | --- | --- | --- |
| J1 | 已确认生效 | V1 公告面含该缺陷 + V3 目录面显示目标版本曾对该机型可用 + 该台回执 `install-state=none` 且 `pending-version` 空 + `build-version`（或 `supplemental.build-version`）等于目标 + 无撤除或回滚证据 | 无（五格全中） | "这一台的这一格已核对" |
| J2 | 已装但不可自证 | 版本/构建读数等于目标，但缺陷到组件的映射不可得，或回执词表不闭合导致无法确认"成功"这个词的含义 | P2、P11、P12 | "版本到位，缺陷级证据缺" |
| J3 | 明确未装 | 回执落在在途或失败词上（`waiting`/`downloading`/`prepared`/`installing`/`failed`），或强制声明已下发且已过 `TargetLocalDateTime` 而版本未达 | P5—P10 | "未装，且能指出卡在哪一层" |
| J4 | 不可判定 | 判定路径上必须用一次 V4；或台账存在冲突项使"应装期限"本身不可算；或该层不在 iOS 更新通道上（L10） | P1、P9b、P12、L10 全部 | "不可判定，并列出缺的那一格" |

J2 与 J4 的区别是本模型唯一需要额外解释的地方。J2 是**东西在、话说不清**：版本读数齐了，但"这条 CVE 是否在其中"缺映射；J4 是**话都说不成**：判定的一个输入项在任何面上都不存在，或者策略文本自相矛盾导致目标态无法确定。把两者混成一级的后果是运营上无法分工——J2 该去找公告口径的补集，J4 该去找自己的台账或承认无法覆盖。

### 19.3 六问判定树

按顺序问，第一个停住的问决定级别。每一问都标出它用的是哪一级的可见性面（V1/V2/V3）和它排掉哪一型。

1. **公告面有没有这条缺陷的条目？**（V1，第 4 章；本轮 331 行里 61 行没有 CVE 条目）没有 → **J4**，型 P1，理由是"公告口径本身不以 CVE 为单位"，继续问下去得到的任何结论都是推断。
2. **这条缺陷所在的组件，在目标版本的公告里叫什么？**（V1；本轮同日发布两条线，`distinctComponents` 67 与 54，其中同名标签 52 个；三份公告同时出现的标签只有 22 个）名字有歧义 → 允许结论，但级别封顶在 **J2**（P2）。
3. **目标版本在这一台的机型上，目录里出现过吗？**（V3/自留档，第 17.3 边界一）没有留档 → **J4**（P3、P4，G2）；有留档且 `ExpirationDate` 已过 → **J3** 并标 P4。
4. **回执的 `install-state` 落在哪套词表里？**（V3，P11）落不进 → **J4**；等于 `failed` → **J3**，型待第 6 问；在途五值之一 → **J3**（P5—P7 之一，G1 使三者不可分）。
5. **版本读数到目标了吗？**（V3 四段读数，第 18.3 错位一）到了且无撤除证据 → 进入 J1/J2 判定；到了但第 2 问歧义或 `supplemental` 非空且需要 BSI 级证据 → **J2**（P8、P12）。
6. **台账里"最晚应装时间"算得出来吗？**（V1 键表 + 自录台账）算不出来（延期键冲突，或该设备未监管使策略不生效，或强制声明的时区字段缺失）→ **J4**（P9、P9b、P10）。

六问的次序本身是一条口径声明：**先问公告面，再问目录面，最后才问设备面**。反过来问（先看设备版本再猜补丁）是第 24 章 M3 误区的成因。

### 19.4 每级的最小证据集与升降条件

| 级 | 最小证据集（缺一即降级） | 升级条件 | 降级触发 |
| --- | --- | --- | --- |
| J1 | 公告行 + 目录留档 + 回执一次 + 版本或构建读数 + 一次"无撤除"复核 | — | 后续任一 BSI 撤除或回滚发生（无读数，靠时间线推断）→ J2 |
| J2 | 前三项齐，映射缺 | 补上组件到 CVE 的对齐表（自建）→ J1 | 词表冲突被发现 → J4 |
| J3 | 回执在途/失败词 + 目标版本 | 回执转为 `none` 且版本达 → J1 或 J2 | 台账冲突使其不可解释 → J4 |
| J4 | 一条"缺哪一格"的记录 | 补齐该格 → 重跑判定树 | — |

J4 的"最小证据集"看着矛盾，其实是本节的目的：**不可判定也要留档**，否则资产面上 J4 会静默归零，而第 20 章 O8 的分子正是它。

### 19.5 与第 14 章 P9b 的接缝

第 14.10 节从《SoftwareUpdateSettings》第 73 行与《Deploying …》第 115 行的口径差里推出 P9b：**推迟上限可写到 90 天，而推荐口径给的 cadence 是另一种单位，两者在同一条链上没有换算规则**。这在判定树第 6 问里必须落成 J4——因为"应装期限"本身是两个可读数的合取，而它们不闭合。一个可行的消解方式不是本文范围（它属于 MDM 产品厂商的模板设计），但企业侧可以做一件纯记录性的事：在台账里把"生效口径"单独一列写明本次采的是哪一句，脚本一对这一列做非空校验。

---

## 20. 运营指标 O1—O10

十个指标全部可由 V1—V3 的文本算出，且都注明分子、分母与它专门用来盯的那一型。凡分子或分母落在 V4 上的，指标本身定义为"带不可判定标记的比例"，不做估算。

| # | 指标 | 分子 / 分母 | 盯的型 | 建议口径 |
| --- | --- | --- | --- | --- |
| O1 | 公告口径分母 | 该资产群所有在册版本线的 CVE 并集 / 该群版本线条数 | P1、P2 | 每月重算并留档；它是其余九个指标的分母来源 |
| O2 | 装配时延 | 首个"回执 `none` 且版本达目标"的时刻 − 该版本 `PostingDate` | P5—P7 | 按机型分组给中位数，不给均值 |
| O3 | 强制收敛率 | 过 `TargetLocalDateTime` 后 24 小时内达到 J1 的台数 / 该强制声明覆盖台数 | P10 | 分母必须是"声明处于 active 且键合法"的台数，否则指标被 P10 污染 |
| O4 | 允许延期面 | 四个延期键中已配置且 >0 的台数 / 监管台数 | P9 | 单独报最长值；90 是文档上界不是建议值 |
| O5 | 目录不可见面 | 台账机型中在 `AssetSets` 找不到可推版本的组合数 / 台账机型组合数 | P3 | 需自留目录快照；无留档则整项标不可判定（G2） |
| O6 | 在野未装面 | KEV 里 Apple 条目对应缺陷在资产群中处于 J3/J4 的台数 / 资产群台数 | P1、P3—P10 | 用 KEV 窗口做时限基准，见下方冲突说明 |
| O7 | 通道错配率 | 台账里"该走整版本却只配 BSI 期待"或反向的组合数 / 该群通道配置组合数 | P8 | 与 14.11 的两处更新要求逐条对 |
| O8 | 不可判定资产占比 | J4 台数 / 总台数 | P9b、P12、L10 | **本模型的核心指标**，不许被并入任何"达标率"的分母 |
| O9 | 回执盲区比例 | 读数落不进词表或缺失关键格的台数 / 有回执的台数 | P11 | 随词表口径变更而变，需记口径版本 |
| O10 | 外设线覆盖 | 公告表 17 行非六平台行与仍在发版的老版本线中，资产群实际持有的线数 / 应覆盖线数 | L10、P1 | 老线以 `12.5.8` 这类实际仍在发的版本为界 |

### 20.1 O6 必须自带一处冲突声明

CISA KEV 对 Apple 条目的修复窗口在本轮呈**四个值**：21 天 63 条、14 天 22 条、3 天 1 条、181 天 9 条（95 条 Apple 条目，非标准窗口 10 条）。而 MDM 侧允许的推迟上界是**每个键最长 90 天**、且这样的键有 4 个（《SoftwareUpdateSettingsDeferralsObject》第 11—14 行，取值域 `[integer; minimum=1; maximum=90]`）。这两个数字不在同一套口径里：前者是"外部要求在多少天内修"，后者是"策略允许把安装推到多少天后"。

因此 O6 的正确写法是一个三段式而不是单值：**要求日（KEV 窗口）→ 策略允许的最晚安装日（台账延期值）→ 实际达到 J1 的日期**。三段里任何一段缺失，该台在 O6 上记 J4 而不是记"逾期"。把这个指标退化成"逾期台数"是企业侧最常见的一种自欺：它把 90 天的合法推迟当成已达成，又把 21 天的在野要求当成不可达，两头都不在自己的责任范围内。

### 20.2 O1 与 O8 的关系决定这套指标是否诚实

O1 是唯一能把"公告口径"变成资产面分母的指标，而它有一个结构性下限：本轮公告表 331 行里有 61 行（18.4%）没有任何 CVE 条目，其中 watchOS 族 15/36、iOS 族 4/5。也就是说，**如果 O8（不可判定）不被单独列出来，这 18.4% 会自然地以"无事发生"的形式从所有其他指标里消失**——它们既不在 CVE 分母里，也不在失败回执里，只在公告表里占一行。O8 的作用就是给这一类资产面空白一个持续可见的名字。

### 20.3 指标之间的三条依赖

其一，O2、O3、O5、O6 共用"目标版本"这一格，因此它们必须用同一份目录留档，否则同一次审计内部会出现两个"目标"。其二，O9 是 O1—O8 的**可信度上限**：盲区比例多少，其余指标里"已确认"的比例最多只能到那个数。其三，O10 不参与任何 iOS 侧达标率计算，因为第 13 章已说明这一层不在软件更新通道上——把它塞进达标率是第 24 章 M11 误区的内容。

### 20.4 一条给台账的最小建议

十个指标只需要台账满足三条就能全部算出：（1）每行有明确的"键"或"状态项"名，且策略侧与回执侧分列；（2）每行带设备标识与机型串（用目录那套写法，见 18.2 末段）；（3）有一列写"本行读数的口径出处"（哪份文档、哪一行、哪一次采集）。第（3）条看着繁琐，但它是第 17.1 节那条规则的唯一实现方式：V4 只能落成不可判定，而"这条记录属于哪一级"本身必须是一行文本里的字段，不能靠审计时的记忆。

---
## 21. 只读核验脚本一：更新策略台账审查器

### 21.1 它回答哪一个问题，以及三条硬约束

前面 20 章把这条链路拆成了层、类型、矩阵与判定，但读者手上能真正跑起来的只有一件事：**把自己抄录或导出的那份策略台账，按文档口径审一遍**。脚本一做这件事。它不判断"这台设备安全吗"，它判断的是"这一格写成这样时，设备侧与管理侧会读到什么、这一条能否换算、换算失败时报哪个码"。

三条硬约束写进了脚本本身，不是承诺：

1. **不联网**。全文没有 `curl`、`wget`、`nc` 与任何 HTTP 客户端；对 `gdmf.apple.com` 的引用只存在于第 22 章脚本的说明文字里，脚本一连这个字符串都不出现。目录快照（`PublicAssetSets` / `AssetSets` / `PublicBackgroundSecurityImprovements` 的读数，含 `ExpirationDate`）必须由读者**自己另外取一份文本**再以 `device.catalog_date` 的形式抄进台账——脚本只吃抄件，不去取原件。
2. **不碰设备**。脚本不调用 `softwareupdate`、`mdmclient`、`profiles` 或任何 Apple 工具；`status.softwareupdate.install-state` 这类字段名出现在脚本里只是**台账的列名**，不是被执行的动作。
3. **只读输入**。整个程序是一次 `awk` 遍历加一次汇总，输入文件只被读；唯一的写出目标是 `mktemp -d` 建的临时目录，`trap 'rm -rf "$TMPD"' EXIT INT TERM` 保证正常退出、`Ctrl-C` 与终止信号三条路径都清理。

### 21.2 台账格式：一行一条断言，五个命名空间

台账是纯文本 CSV，一行一条记录：`<设备标识>,<字段名>,<值>`。`#` 开头行与空行忽略，行尾 `CR` 忽略，值里若含逗号会在解析时回接（所以 `device.model` 写作 `iPhone 12, 128GB` 也不会被拆成两列）。同一设备同一字段出现两条不同值时报 E11，不静默取后写。

| 前缀 | 装什么 | 取值域从哪来 |
|---|---|---|
| `policy.*` | 声明 `com.apple.configuration.softwareupdate.settings` 里的键 | 《SoftwareUpdateSettings》第 70—76 行的 7 个顶层属性，加上 `AutomaticActions`、`Deferrals`、`Beta`、`RapidSecurityResponse` 四个对象内部键，共 19 个可核对键名 |
| `enforce.*` | 声明 `com.apple.configuration.softwareupdate.enforcement.specific` 里的键 | 《SoftwareUpdateEnforcementSpecific》第 58—60 行的 `TargetOSVersion` / `TargetBuildVersion` / `TargetLocalDateTime`（脚本里去掉 `Target` 前缀：`OSVersion`、`BuildVersion`、`LocalDateTime`），另收 `DetailsURL` |
| `status.softwareupdate.*` | 软件更新侧状态项读数 | 6 个状态项：install-state、install-reason、failure-reason、pending-version、device-id、beta-enrollment |
| `status.device.operating-system.*` | 系统版本侧读数 | version、build-version、supplemental.build-version、supplemental.extra-version |
| `device.*` | 台账自带的元字段（脚本判定的分母） | 14 个：`supervised`、`model`、`udid`、`catalog_date`、`audit_date`、`observed_at`、`vocabulary`、`advisory_cve_count`、`component_map`、`bsi_removed`、`channel`、`timezone`、`target_version`、`target_build` |

`device.*` 这一组是本文第 17 章可见性分级的落地处：`catalog_date` 记"这份目录快照是哪天抄的"，`vocabulary` 声明"我这一列 install-state 用的是 6 值表还是 5 值表"，`component_map` 声明"我这台的缺陷—组件映射拿得到吗"，`advisory_cve_count` 声明"这条公告行有几个 CVE"。它们没有一项来自设备，全部是读者对自己作业过程的登记；**缺一项，脚本就退到 J4 而不是退到"没问题"**。

### 21.3 41 个信号码

四族加一组判定，共 41 个码。逐条给出触发条件，读者可以直接把它当台账体检单用。

**D 类：策略与强制的写法（16 个）**

| 码 | 触发条件 |
|---|---|
| D01 | `policy.*` 的键名不在本轮可核对的 19 个键名集合内 |
| D02 | 四个延期键的取值越出 `integer; minimum=1; maximum=90`（《SoftwareUpdateSettingsDeferralsObject》第 11—14 行） |
| D03 | 延期键不是整数（写了 `two weeks` 这类） |
| D04 | `RecommendedCadence` 与任一 `Deferrals` 键同时配置：两套口径之间没有换算规则 |
| D05 | 四个枚举键（`AutomaticActions.Download` / `InstallOSUpdates` / `InstallSecurityUpdate`、`Beta.ProgramEnrollment`）取了 `Allowed` / `Blocked` / `AlwaysOn` 之外的值，或 `RecommendedCadence` 取了 `Automatic` / `Periodic` / `Continuous` 之外的值——本轮存档里这些键的 `allowedValues` 全部未展开，所以越界值只能报"不在可核对词表内"，不能报"非法" |
| D06 | `AutomaticActions.Download` 或 `InstallOSUpdates` 被置 `Blocked`，而同一台账里存在强制目标版本 |
| D07 | 配置了延期但 `device.supervised` 不为 true |
| D08 | `Beta.*` 的键与延期键并存：台账需注明两条口径各取哪一句 |
| D09 | 台账仍在用 `allowRapidSecurityResponse*` 旧口径键名（`restrictions` 里这两个键的说明已改写为 Background Security Improvements） |
| D10 | 强制声明有截止日期但既无 `OSVersion` 也无 `BuildVersion` |
| D11 | `TargetLocalDateTime` 的串本身不带时区，且台账没有 `device.timezone` |
| D12 | 只有目标版本没有强制日期：多配置时无法按最早截止日期排队 |
| D13 | 同时指定 `OSVersion` 与 `BuildVersion` |
| D14 | `pending-version` 是 supplemental 形态（结尾小写字母）而台账无 base 构建 |
| D15 | 策略禁止 Background Security Improvements，但设备侧 `supplemental.build-version` 非空 |
| D16 | `RapidSecurityResponse.Enable` 与 `EnableRollback` 同时为 false（两键 default 均为 true） |

**B 类：不可判定边界（7 个）**——这一族不指出写错，只指出**这一条谁也判不了**。

| 码 | 触发条件 | 对应缺口 |
|---|---|---|
| B01 | 缺 `catalog_date`：版本可见性与签名时效事后无法自证 | G2 |
| B02 | `catalog_date` 比 `audit_date` 早超过 30 天：快照视为过期 | G2 |
| B03 | `failure-reason` 有值：逐字段码表本轮不可核对，只能报不可分型 | G1 |
| B04 | `advisory_cve_count` 为 0 或未填：公告口径本身不以 CVE 为单位 | — |
| B05 | `component_map ≠ present`：缺陷到组件的映射不可得 | G7 |
| B06 | `bsi_removed=unknown` 且 supplemental 读数非空：撤除没有独立状态项 | G8 |
| B07 | `channel=accessory`：这一项根本不在 iOS 软件更新通道上 | — |

**E 类：词表与读数口径（12 个）**

| 码 | 触发条件 |
|---|---|
| E01 | `install-state` 不在台账所选词表内；或 `vocabulary` 写了 `state6` / `state5` 之外的值 |
| E02 | 未声明 `device.vocabulary`（install-state 在文档里有两套取值表，必须先选一套） |
| E03 | `install-state=waiting` 而词表选的是 5 值表：部署指南列了它，状态项页的表里没有 |
| E04 | `install-reason` 不在 8 值集合内 |
| E05 | `supplemental.build-version` 非空而 `supplemental.extra-version` 为空：半截读数 |
| E06 | `operating-system.version` 不是 `15.0` 这类点分数字形态 |
| E07 | `operating-system.build-version` 不是 `18F132` 这类"数字+大写字母+数字（可带结尾小写）"形态 |
| E08 | `softwareupdate.device-id` 的值是 UDID 形态，或 `device.udid` 不是 UDID 形态：两个标识混用 |
| E09 | `device.model` 写成市场名形态（含空格/括号），而目录 `SupportedDevices` 用 ProductName 形态机型串 |
| E10 | 四个日期字段（`catalog_date`、`audit_date`、`observed_at`、`enforce.LocalDateTime`）不是 ISO 8601 形态 |
| E11 | 同一设备同一字段出现两条不同值 |
| E12 | `observed_at` 早于 `catalog_date`：设备读数比目录快照还早，至少一份采集口径错 |

**U 类：解析（2 个）**：U01 记录不足三列；U02 缺设备标识。**J 类：判定（4 个）**，判据次序固定为：先看通道与分母（accessory / `advisory_cve_count` 为 0 或缺 / 缺 `catalog_date` / 缺 `vocabulary` → J4），再看是否有失败或在途读数（`failed` 或 6 值表里的 `downloading`/`prepared`/`installing` → J3），最后看"没有待更新且构建等于目标构建"（→ J1，但若 `component_map ≠ present` 或 `bsi_removed=unknown` 降为 J2）、"版本达到但需要 BSI 级证据"（→ J2），都不满足则按是否明确未装给 J3 或 J4。这套次序就是第 19 章六问判定树的代码化。

### 21.4 全文

```bash
#!/usr/bin/env bash
# update-policy-ledger-review.sh —— 更新策略台账审查器（离线 / 只读 / 不联网 / 不碰设备）
# 输入：一份或多份台账文本，每行一条记录：  <设备标识>,<字段名>,<值>
# 输出：逐条信号码 + 每台设备的四级判定（J1—J4） + 汇总
# 信号码共 41 个：D01—D16 策略与强制写法 / B01—B07 边界（不可判定）/
#                E01—E12 词表与读数口径 / U01—U02 解析 / J1—J4 判定
# 退出码：0=无 D/E/U 类信号，1=有，2=输入不可用
set -u
LC_ALL=C; export LC_ALL

usage() {
  cat <<'EOF'
用法: update-policy-ledger-review.sh [-q] 台账文件 [...]
  -q, -h  -q 只输出汇总；-h/--help 显示本帮助
台账行格式: <设备标识>,<字段名>,<值>    # 开头与空行忽略，行尾 CR 忽略
字段命名空间:
  policy.*    策略键（SoftwareUpdateSettings 的 7 个顶层键及其对象内键）
  enforce.*   强制声明键（OSVersion / BuildVersion / LocalDateTime / DetailsURL）
  status.softwareupdate.*            软件更新侧状态项
  status.device.operating-system.*   系统版本侧状态项
  device.*    台账自带的元字段（supervised / model / udid / catalog_date /
              audit_date / observed_at / vocabulary / advisory_cve_count /
              component_map / bsi_removed / channel / timezone / target_version / target_build）
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

TMPD=$(mktemp -d "${TMPDIR:-/tmp}/uplr.XXXXXX") || { echo "无法创建临时目录" >&2; exit 2; }
trap 'rm -rf "$TMPD"' EXIT INT TERM

awk -v QUIET="$QUIET" '
function emit(code, dev, msg) { cnt[code]++; lines[++nline] = sprintf("%s\t%s\t%s", code, (dev==""?"-":dev), msg) }
function DV(d, f,   k) { k = d SUBSEP f; return (k in valof) ? valof[k] : "" }
function istrue(v)  { return (v=="true"||v=="TRUE"||v=="1"||v=="yes") }
function isfalse(v) { return (v=="false"||v=="FALSE"||v=="0"||v=="no") }
function isint(v)   { return (v ~ /^-?[0-9]+$/) }
function badDays(v) { return (!isint(v) || v+0<1 || v+0>90) }          # [integer; minimum=1; maximum=90]
function isISOdt(v) { return (v ~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}([ T][0-9]{2}:[0-9]{2}(:[0-9]{2})?)?([Zz]|[+-][0-9]{2}:?[0-9]{2})?$/) }
function hasTZ(v)   { return (v ~ /[Zz]$/ || v ~ /[+-][0-9]{2}:?[0-9]{2}$/) }
function dayNum(v,  t) { t=v; gsub(/[-:TZ ]/,"",t); return substr(t,1,8)+0 }
function isVersion(v) { return (v ~ /^[0-9]+(\.[0-9]+){1,2}$/) }        # "such as 15.0"
function isBuild(v)   { return (v ~ /^[0-9]+[A-Z][0-9A-Za-z]*[a-z]?$/) } # "such as 18F132" / "20A123a"
function isUdid(v)    { return (v ~ /^[0-9A-Fa-f]{40}$/ || v ~ /^[0-9A-Fa-f]{25}$/) }
BEGIN {
  FS=","
  split("AllowStandardUserOSUpdates AutomaticActions Beta Deferrals Notifications RapidSecurityResponse RecommendedCadence Download InstallOSUpdates InstallSecurityUpdate OfferPrograms ProgramEnrollment RequireProgram CombinedPeriodInDays MajorPeriodInDays MinorPeriodInDays SystemPeriodInDays Enable EnableRollback", a, " ")
  for (i in a) KNOWN[a[i]]=1
  split("OSVersion BuildVersion LocalDateTime DetailsURL", b, " ")
  for (i in b) ENF[b[i]]=1
  split("none waiting downloading prepared installing failed", s6, " "); for (i in s6) ST6[s6[i]]=1
  split("none downloading prepared installing failed", s5, " ");         for (i in s5) ST5[s5[i]]=1
  split("system-settings install-tonight auto-update notification setup-assistant command-line mdm declaration", r8, " "); for (i in r8) REASON8[r8[i]]=1
  DEFER="CombinedPeriodInDays MajorPeriodInDays MinorPeriodInDays SystemPeriodInDays"
  ENUMK="AutomaticActions.Download AutomaticActions.InstallOSUpdates AutomaticActions.InstallSecurityUpdate Beta.ProgramEnrollment"
}
{ sub(/\r$/, "") }
/^[[:space:]]*#/ { next }
/^[[:space:]]*$/ { next }
{
  if (NF < 3) { emit("U01","-","记录无法解析成〈设备,字段,值〉三列: " $0); next }
  dev=$1; fld=$2; val=$3
  for (i=4; i<=NF; i++) val = val "," $i
  if (dev ~ /^$/) { emit("U02","-","记录缺设备标识，无法逐台判定: " fld); next }
  if (!(dev in seen)) { seen[dev]=++nd; ord[nd]=dev }
  if (dev ~ /^$/) next
  k = dev SUBSEP fld
  if ((k in valof) && valof[k] != val) emit("E11", dev, "同一字段两条不同值: " fld " = [" valof[k] "] 与 [" val "]")
  valof[k]=val
  if (fld ~ /^policy\.allowRapidSecurityResponse/) emit("D09", dev, "台账里仍在用旧口径键名 " fld "（文档已标 Removed / 改用声明式配置）")
  else if (fld ~ /^policy\./ || fld ~ /^enforce\./) {
    f=fld; sub(/^policy\./,"",f); sub(/^enforce\./,"",f)
    n=split(f, parts, "."); unk=0
    for (p=1; p<=n; p++) {
      if (fld ~ /^enforce\./ && parts[p] in ENF) continue
      if (!(parts[p] in KNOWN)) { unk=1; break }
    }
    if (unk) emit("D01", dev, "键不在本轮文档口径的键集内: " fld)
  }
}
END {
  for (i=1; i<=nd; i++) {
    d = ord[i]
    sup   = DV(d,"device.supervised"); voc = DV(d,"device.vocabulary")
    cat_  = DV(d,"device.catalog_date"); aud = DV(d,"device.audit_date"); obs = DV(d,"device.observed_at")
    nCVE  = DV(d,"device.advisory_cve_count"); cmap = DV(d,"device.component_map")
    bsir  = DV(d,"device.bsi_removed"); chan = DV(d,"device.channel"); tzn = DV(d,"device.timezone")
    model = DV(d,"device.model"); udid = DV(d,"device.udid")
    tVer  = DV(d,"device.target_version"); if (tVer=="") tVer = DV(d,"enforce.OSVersion")
    tBld  = DV(d,"device.target_build");   if (tBld=="") tBld = DV(d,"enforce.BuildVersion")
    state = DV(d,"status.softwareupdate.install-state")
    reas  = DV(d,"status.softwareupdate.install-reason")
    failr = DV(d,"status.softwareupdate.failure-reason")
    pend  = DV(d,"status.softwareupdate.pending-version")
    devid = DV(d,"status.softwareupdate.device-id")
    osv   = DV(d,"status.device.operating-system.version")
    osb   = DV(d,"status.device.operating-system.build-version")
    supb  = DV(d,"status.device.operating-system.supplemental.build-version")
    supe  = DV(d,"status.device.operating-system.supplemental.extra-version")
    eOS   = DV(d,"enforce.OSVersion"); eBL = DV(d,"enforce.BuildVersion"); eDT = DV(d,"enforce.LocalDateTime")
    rse   = DV(d,"policy.RapidSecurityResponse.Enable"); rsr = DV(d,"policy.RapidSecurityResponse.EnableRollback")

    dfr=0
    split(DEFER, df, " ")
    for (j in df) {
      v = DV(d,"policy.Deferrals." df[j])
      if (v=="") continue
      if (!isint(v)) emit("D03", d, "policy.Deferrals." df[j] " 不是整数: [" v "]（文档口径 integer）")
      else if (badDays(v)) emit("D02", d, "policy.Deferrals." df[j] " = " v " 越出取值域 minimum=1; maximum=90")
      else dfr=1
    }
    if (dfr && DV(d,"policy.RecommendedCadence")!="") emit("D04", d, "RecommendedCadence 与 Deferrals 同时配置：两套口径之间没有换算规则")
    split(ENUMK, ek, " ")
    for (j in ek) { v = DV(d,"policy." ek[j])
      if (v!="" && v!="Allowed" && v!="Blocked" && v!="AlwaysOn") emit("D05", d, "policy." ek[j] " 取值 [" v "] 不在本轮可核对词表内（文档里 allowedValues 未展开）") }
    cad = DV(d,"policy.RecommendedCadence")
    if (cad!="" && cad!="Automatic" && cad!="Periodic" && cad!="Continuous") emit("D05", d, "policy.RecommendedCadence 取值 [" cad "] 不在本轮可核对词表内")
    if ((DV(d,"policy.AutomaticActions.Download")=="Blocked" || DV(d,"policy.AutomaticActions.InstallOSUpdates")=="Blocked") && (eOS!="" || eBL!="")) emit("D06", d, "自动下载/安装被置 Blocked，但同一台账里有强制目标版本")
    if (dfr && !istrue(sup)) emit("D07", d, "配置了延期但 device.supervised 不为 true：按文档口径延期只在监管设备上生效")
    if ((DV(d,"policy.Beta.RequireProgram")!="" || DV(d,"policy.Beta.OfferPrograms")!="") && dfr) emit("D08", d, "Beta program 键与延期键并存：台账需注明两条口径各取哪一句")
    if (eDT!="" && eOS=="" && eBL=="") emit("D10", d, "强制声明有截止日期但没有任何目标版本（TargetOSVersion 为必填）")
    if (eDT!="" && !hasTZ(eDT) && tzn=="") emit("D11", d, "TargetLocalDateTime 无时区串且台账无 device.timezone（格式串本身不带时区）")
    if ((eOS!="" || eBL!="") && eDT=="") emit("D12", d, "只有目标版本没有强制日期：多配置时无法按最早截止日期排队")
    if (eBL!="" && eOS!="") emit("D13", d, "同时指定 OSVersion 与 BuildVersion：按文档口径此时不再自动安装该版本可用的 Background Security Improvements")
    if (pend ~ /\([a-z]\)$/ && tBld=="") emit("D14", d, "待装版本是 supplemental 形态 [" pend "] 但台账无 base 构建：补装需要先落 base 版本")
    if (isfalse(rse) && supb!="") emit("D15", d, "台账禁止 Background Security Improvements，但设备读数是 supplemental 非空: " supb)
    if (isfalse(rsr) && isfalse(rse)) emit("D16", d, "Enable 与 EnableRollback 同时为 false：两键 default 均为 true，取值需注明依据")

    if (cat_=="") emit("B01", d, "缺目录快照日期：版本可见性与签名时效事后无法自证")
    else if (aud!="" && dayNum(aud)-dayNum(cat_) > 30) emit("B02", d, "目录快照比审计日晚 " (dayNum(aud)-dayNum(cat_)) " 天：视为过期")
    if (failr!="") emit("B03", d, "failure-reason 有值 [" failr "]：逐字段码表本轮不可核对，只能报不可分型")
    if (nCVE=="0") emit("B04", d, "该资产对应公告行的 CVE 条目数为 0：公告口径本身不以 CVE 为单位")
    else if (nCVE=="") emit("B04", d, "台账未填公告 CVE 条目数：无法确认缺陷在公告面存在")
    if (cmap!="present") emit("B05", d, "组件名对齐表缺失（component_map=" (cmap==""?"空":cmap) "）：缺陷到组件的映射不可得")
    if (bsir=="unknown" && supb!="") emit("B06", d, "supplemental 读数非空但撤除状态未知：Background Security Improvement 撤除没有独立状态项")
    if (chan=="accessory") emit("B07", d, "该资产不在 iOS 软件更新通道上（配件 / 固件线）")

    if (voc=="") emit("E02", d, "未声明词表口径（device.vocabulary 缺失）：install-state 在文档里有两套取值表")
    if (state!="") {
      if (voc=="state6" && !(state in ST6)) emit("E01", d, "install-state [" state "] 不在 6 值词表内")
      else if (voc=="state5" && !(state in ST5)) {
        if (state=="waiting") emit("E03", d, "install-state=waiting：部署指南列了它，状态项页的 5 值表里没有")
        else emit("E01", d, "install-state [" state "] 不在 5 值词表内")
      } else if (voc!="state6" && voc!="state5") emit("E01", d, "词表口径 [" voc "] 未知，install-state [" state "] 无法判定")
    }
    if (reas!="" && !(reas in REASON8)) emit("E04", d, "install-reason [" reas "] 不在 8 值集合内")
    if (supb!="" && supe=="") emit("E05", d, "supplemental.build-version 非空而 supplemental.extra-version 空：半截读数")
    if (osv!="" && !isVersion(osv)) emit("E06", d, "operating-system.version 形态非法: [" osv "]")
    if (osb!="" && !isBuild(osb)) emit("E07", d, "operating-system.build-version 形态非法: [" osb "]")
    if (devid!="" && isUdid(devid)) emit("E08", d, "softwareupdate.device-id 的值是 UDID 形态：两个标识被混用")
    else if (udid!="" && !isUdid(udid)) emit("E08", d, "device.udid 的值不是 UDID 形态: [" udid "]")
    if (model!="" && (model ~ /[A-Z][a-z]+ [A-Z][a-z]+/ || model ~ /[ ()]/)) emit("E09", d, "device.model 写作 [" model "]：目录 SupportedDevices 用的是 ProductName 形态的机型串")
    split("device.catalog_date device.audit_date device.observed_at enforce.LocalDateTime", dtf, " ")
    for (j in dtf) { v=DV(d, dtf[j]); if (v!="" && !isISOdt(v)) emit("E10", d, dtf[j] " 不是 ISO 8601 形态: [" v "]") }
    if (cat_!="" && obs!="" && dayNum(obs) < dayNum(cat_)) emit("E12", d, "设备读数早于目录快照：两者至少一份的采集口径错")

    lvl=""
    if (chan=="accessory") lvl="J4"
    else if (nCVE=="0" || nCVE=="") lvl="J4"
    else if (cat_=="") lvl="J4"
    else if (voc=="") lvl="J4"
    else if (state=="failed") lvl="J3"
    else if (state!="" && ((voc=="state6" && state in ST6) || (voc=="state5" && state in ST5)) && state!="none") lvl="J3"
    else if (state=="none" || state=="") {
      if (tBld!="" && osb==tBld)      lvl = (cmap=="present" && bsir!="unknown") ? "J1" : "J2"
      else if (tVer!="" && supb!="" && osv==tVer) lvl="J2"
      else if (tVer!="" && osv==tVer && cmap=="present" && bsir!="unknown") lvl="J1"
      else lvl="J3"
    }
    else lvl="J4"
    J[lvl]++
    emit(lvl, d, "判定 " lvl " (state=" (state==""?"-":state) ", build=" (osb==""?"-":osb) ", target=" (tBld!=""?tBld:(tVer!=""?tVer:"-")) ")")
  }
  if (!QUIET) for (i=1; i<=nline; i++) print lines[i]
  print ""
  print "==== 汇总 ===="
  printf "设备数=%d\n", nd
  split("D01 D02 D03 D04 D05 D06 D07 D08 D09 D10 D11 D12 D13 D14 D15 D16 " \
        "B01 B02 B03 B04 B05 B06 B07 " \
        "E01 E02 E03 E04 E05 E06 E07 E08 E09 E10 E11 E12 " \
        "U01 U02 J1 J2 J3 J4", cc, " ")
  bad=0
  for (j in cc) { c=cc[j]; n=cnt[c]+0
    printf "%-4s %3d\n", c, n
    if (c ~ /^[DEU]/) bad+=n
  }
  printf "判定分布: J1=%d J2=%d J3=%d J4=%d\n", J["J1"], J["J2"], J["J3"], J["J4"]
  printf "阻断类信号(D/E/U)合计=%d\n", bad
  exit (bad>0 ? 1 : 0)
}
' "$@" > "$TMPD/out.txt"
rc=$?
cat "$TMPD/out.txt"
exit $rc
```

### 21.5 用法、输出与一份样例台账

```
用法: update-policy-ledger-review.sh [-q] 台账文件 [...]
  -q 只输出汇总；-h/--help 显示本帮助
退出码: 0=无 D/E/U 类信号, 1=有, 2=输入不可用
```

`-q` 只留汇总，用于每日跑一遍看趋势；不带 `-q` 时先输出逐条信号（制表符分隔的三列：码、设备、说明），再输出四张汇总行：设备数、41 个码各自的计数、判定分布 `J1=… J2=… J3=… J4=…`、以及阻断类合计。下面这份八行样例是第 23 章 fixture 里 DEV-B 那一台的缩样，说明一台 J2 设备的台账长什么样：

```csv
DEV-B,device.supervised,true
DEV-B,status.softwareupdate.install-state,none
DEV-B,status.device.operating-system.build-version,23G92
DEV-B,device.target_build,23G92
DEV-B,device.catalog_date,2026-10-26
DEV-B,device.vocabulary,state6
DEV-B,device.advisory_cve_count,163
DEV-B,device.component_map,absent
```

这台设备满足了 J1 的全部读数条件（`state=none`、`build-version` 等于 `target_build`、`catalog_date` 已登记、`vocabulary` 已声明、`advisory_cve_count` 非 0），只因为 `component_map=absent` 被降为 J2，整份台账只打出两条输出：

```
B05     DEV-B   组件名对齐表缺失（component_map=absent）：缺陷到组件的映射不可得
J2      DEV-B   判定 J2 (state=none, build=23G92, target=23G92)
```

**这一台正是第 19 章讲的"已装但不可自证"**：读数都对，映射拿不到。把 `device.component_map,absent` 改成 `present` 再跑一遍，输出只剩一行 `J1 DEV-B 判定 J1 (state=none, build=23G92, target=23G92)`，B05 消失。**两次的退出码都是 0**：B05 属边界族，不计入阻断数。这正是 B 类与 D/E/U 类的分工——补齐 `component_map` 改变的是这台设备的判定档位，不是这份台账的合格与否。

三点输出解读纪律：

- **计数不是缺陷数**。同一个码在一台设备上可能出现多次（同一台既写 D02 又写 D04 很常见），汇总里的数字是"信号条数"，不是"受影响设备数"。按设备去重看 J 行的分布。
- **`exit 1` 不代表设备有问题**。它只代表台账里有 D/E/U 类信号，也就是"这份台账本身口径不齐"。B 类与 J4 不计入退出码，因为它们的正确处置是补证据而不是改配置。
- **J1 不等于"没有未修的 CVE"**。J1 的判据是"这台设备上的构建，等于台账登记的目标构建，且目录快照未过期，且组件映射可得"。目标构建是谁定的、它是不是当时最新的那一版，脚本一概不看——那是脚本二的工作。

### 21.6 脚本一明确不做的三件事

一是**不解释 `failure-reason` 的逐字段取值**（G1）。本轮存档里这一项只给到"存在这个状态项"，没有可核对的字段—含义表，脚本因此只在有值时打 B03 并把这台推向不可分型，绝不猜"timeout 就是网络问题"。二是**不把组件名换算成 CVE**（G7）。`component_map` 是读者自己登记的"我有没有这张对齐表"，脚本只在 `present` 时才允许升到 J1。三是**不判断 Background Security Improvement 是否被撤除**（G8）。撤除没有独立状态项，`bsi_removed=unknown` 加非空 supplemental 读数只能得 B06 + J2。

这三处"不判"是有意的：脚本给出的是**台账质量**与**证据可达性**，不是设备安全性。第 23 章的覆盖验收会逐码确认这些分支确实被执行过，而不是写在 `if` 里从没进过。

## 22. 只读核验脚本二：公告覆盖差集比对器

### 22.1 它回答哪一个问题

脚本一处理"我这台设备的台账说不说得清"，脚本二处理另一个方向：**公告文本本身说了什么、几份公告之间怎么对、在野条目落在哪条线上**。它把第 16 章的 R5、R6、R7、R12、R13 与第 20 章的 O1、O2、O5、O6 变成一段可以重复执行的算法，回答四个问题：

1. 我手上这几份公告的 CVE 集，加起来和并起来差多少？（直加与去重的差额就是"重复计入"的量）
2. 同一个平台的两条版本线之间，CVE 集有没有包含关系？（第 4 章说过：没有。脚本二把它算出来。）
3. 某一条在野条目要求的修复窗口，跟我台账允许的延期天数，是不是同一个口径？
4. 这台设备从它现在的版本走到目标版本，路径上有没有一份可核对的公告？没有的话，这个"不可达"是目录问题、策略问题还是公告面问题？

> **编号冲突提醒**：第 16 章用 R1—R18 给"公开读数"编号，脚本二用 R1—R8 给"信号码"命名，两套 R 不是同一件事。本脚本的信号码一律带类前缀（R/K/S/C），读表时按"码 + 说明"看，不要回头去第 16 章找对应的 R6。

### 22.2 三类输入件与它们的表头契约

脚本按**表头**识别文件类型，不看扩展名也不看文件名。三类件的必需列：

| 类型 | 识别条件（首行表头） | 额外用到的列 | 用途 |
|---|---|---|---|
| 公告件 | `cve` + `component` + `fixed` + `available_for` | `releaseDate`、`advisoryId`（可选） | CVE 并集、组件标签对齐、版本线映射、机型串比对 |
| 在野件 | `cveID` + `vendorProject` + `dateAdded` + `dueDate` | `shortDescription`（可选） | 窗口天数、是否落进公告并集、可达性与时限冲突 |
| 资产件 | `device` + `line` + `installed` + `target` | `deferral_days`、`catalog_date`、`audit_date`、`component_map`、`model`、`retired`（可选） | 迁移路径判定、跨平台拒绝合并、K 类时限冲突 |

两条顺序约束必须注意。**其一，参数顺序即处理顺序**：公告件必须在最前（它们是位置参数），在野件用 `-k`、资产件用 `-s`，脚本内部按"公告 → 在野 → 资产"追加到同一条 `awk` 命令里，资产件的判定要用到前两类件累计的集合。**其二，`vendorProject` 只取 Apple**，其余厂商的行直接跳过并在汇总里按非 Apple 计数排除，避免把别的产品的在野条目算进 Apple 的覆盖率分母。

`fixed` 列的版本线映射是这类件里最容易写错的一处：CSAF 里给的是 `APPLE-ios-27_2,APPLE-ipados-27_2` 这种带下划线的平台标签，脚本按 `^APPLE-(ios|ipados|macos|tvos|watchos|visionos)-` 取第一项、把 `_` 换成 `.`，得到 `ios-27.2` 这样可比的线名；资产件里的 `line` 必须写成同一个形态（`ios-27.2`），否则 R6 会报"资产登记的版本线在公告里没有对应标签"——这本身就是本文第 8 章讲的通道错配的一种。日期一律按 `YYYY-MM-DD` 换算成连续日序（Howard Hinnant 的 `days_from_civil` 算法，脚本内 10 行实现，不依赖任何外部时间库），这样窗口天数与快照年龄才是纯整数减法，不受宿主 `TZ` 与 locale 影响。

### 22.3 22 个信号码

**R 类：公告面读数与差集（8 个）**

| 码 | 含义 |
|---|---|
| R1 | 两行读数：公告件份数 / 逐份计数合计 / 去重并集；在野 Apple 条目数 / 落进并集数 / 未落进数 |
| R2 | 直加与去重不等：把几份公告的条目数相加会凭空多算 N 条 |
| R3 | 同一平台两条线的 CVE 交集为 0：公告不是累计清单 |
| R4 | 同一发布日并行两条线时的交集与各自独占数 |
| R5 | 组件标签跨公告对齐：同名出现多少个、只在一份里出现多少个（≥2 份公告时才报，单份时这个数没有意义） |
| R6 | 资产登记的版本线在输入公告里没有对应 `fixed` 标签 |
| R7 | 台账机型串在该公告的 `available_for` 文本里找不到：写法与公告口径不一致 |
| R8 | 某份公告件的 CVE 条目数为 0：这次发布在公告口径里不以 CVE 为单位 |

**K 类：在野条目（6 个）**

| 码 | 含义 |
|---|---|
| K1 | 在野条目未出现在任何输入公告的 CVE 并集里（阻断类：本轮真实数据里 95 条全部触发） |
| K2 | 在野条目要求的窗口天数小于台账允许的延期天数：两处时限不在同一口径 |
| K3 | 窗口天数不在主窗口 {14,21} 内 |
| K4 | 版本线已停更（`retired=yes`），而至少一条在野条目在这条线上没有可达的公告面 |
| K5 | 在野条目的 `dueDate` 已早于台账审计日，该台仍在旧版本 |
| K6 | 在野条目的 `dueDate` 早于最早可核对的修复公告发布日：按公告口径这台设备不可能在窗口内拿到修复 |

**S 类：输入契约（5 个，全部计入阻断）**：S1 表头缺必需列；S2 同一件内 CVE 重复出现；S3 CVE-ID 形态非法；S4 除表头外无数据行；S5 行内列数不足、CVE 为空、日期不是 `YYYY-MM-DD`。

**C 类：结论模板（3 个）**：C1 无迁移路径（目标版本在这条线上没有可核对的公告件）；C2 资产件里出现 ≥2 个平台线，拒绝合并计算，要求按平台分别跑；C3 该行证据不足以判定（`component_map` 非 present、缺目录快照日期、或未提供在野件）。

### 22.4 全文

```bash
#!/usr/bin/env bash
# advisory-coverage-diff.sh —— 公告覆盖差集比对器（离线 / 只读 / 不联网 / 不碰设备）
# 输入：若干份公告 CVE 件（TSV），一份在野条目件（-k，TSV），可选一份资产件（-s，TSV）
# 输出：22 个信号码 + 汇总。退出码：0=无阻断类信号，1=有，2=输入不可用
#   R1—R8 公告面读数与差集 / K1—K6 在野条目 / S1—S5 输入契约 / C1—C3 结论模板
set -u
LC_ALL=C; export LC_ALL

usage() {
  cat <<'EOF'
用法: advisory-coverage-diff.sh [-q] [-k 在野条目件] [-s 资产件] 公告件1 [公告件2 ...]
  -q   只输出汇总        -h 显示本帮助
公告件：制表符分隔，首行表头需含 cve、component，另需 fixed、available_for（releaseDate、advisoryId 可选）
在野件：制表符分隔，首行表头需含 cveID、vendorProject、dateAdded、dueDate
资产件：制表符分隔，首行表头需含 device、line、installed、target、deferral_days、
        catalog_date、audit_date、component_map（model、retired 可选）
本脚本不联网、不访问设备、不修改输入文件；临时件写在 mktemp -d 并在退出时删除。
EOF
}

QUIET=0; KEV=""; ASSET=""
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    -q) QUIET=1; shift ;;
    -k) KEV="${2:-}"; shift 2 ;;
    -s) ASSET="${2:-}"; shift 2 ;;
    -*) echo "未知选项: $1" >&2; usage >&2; exit 2 ;;
    *) break ;;
  esac
done
[ $# -ge 1 ] || { usage >&2; exit 2; }
for f in "$@"; do
  [ -f "$f" ] || { echo "输入不可读: $f" >&2; exit 2; }
  [ -s "$f" ] || { echo "输入为空文件: $f" >&2; exit 2; }
done
[ -z "$KEV" ]   || { [ -f "$KEV" ]   || { echo "输入不可读: $KEV"   >&2; exit 2; }; }
[ -z "$ASSET" ] || { [ -f "$ASSET" ] || { echo "输入不可读: $ASSET" >&2; exit 2; }; }

TMPD=$(mktemp -d "${TMPDIR:-/tmp}/acvd.XXXXXX") || { echo "无法创建临时目录" >&2; exit 2; }
trap 'rm -rf "$TMPD"' EXIT INT TERM

FILES=("$@")
[ -z "$KEV" ]   || FILES+=("$KEV")
[ -z "$ASSET" ] || FILES+=("$ASSET")

awk -v QUIET="$QUIET" -v KEVFILE="$KEV" -v ASSETFILE="$ASSET" '
function emit(code, obj, msg) { cnt[code]++; lines[++nline] = sprintf("%s\t%s\t%s", code, (obj==""?"-":obj), msg) }
function trim(s) { gsub(/^[ \t\r\n]+|[ \t\r\n]+$/, "", s); return s }
function lc(s) { return tolower(s) }
function underscore(v,  t) { t=v; gsub(/\./, "_", t); return t }
# Howard Hinnant days_from_civil：YYYY-MM-DD -> 连续日序（非法返回 -1）
function dnum(ds,  a,y,m,d,era,yoe,doy,doe) {
  if (ds !~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}/) return -1
  split(ds, a, "-"); y=a[1]+0; m=a[2]+0; d=a[3]+0
  if (m < 1 || m > 12 || d < 1 || d > 31) return -1
  y = y - (m <= 2 ? 1 : 0)
  era = int(y / 400); if (y < 0) era -= 1
  yoe = y - era * 400
  doy = int((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5) + d - 1
  doe = yoe * 365 + int(yoe / 4) - int(yoe / 100) + doy
  return era * 146097 + doe - 719468
}
# "APPLE-ios-27_2,APPLE-ipados-27_2" -> "ios-27.2"
function lineOf(fixed,   p, n, i, ver, parts) {
  n = split(fixed, p, ",")
  for (i = 1; i <= n; i++) {
    if (p[i] !~ /^APPLE-(ios|ipados|macos|tvos|watchos|visionos)-/) continue
    split(substr(p[i], 7), parts, "-")
    ver = parts[2]; gsub(/_/, ".", ver)
    return parts[1] "-" ver
  }
  return ""
}
function platformOf(ln) { if (ln=="") return ""; split(ln, qp, "-"); return qp[1] }
BEGIN {
  FS="\t"
  split("none", _dummy)
}
{ sub(/\r$/, "") }
FNR==1 {
  delete col
  for (i = 1; i <= NF; i++) col[lc(trim($i))] = i
  if (col["cve"] && col["component"] && col["fixed"] && col["available_for"]) ftype="advisory"
  else if (col["cveid"] && col["vendorproject"] && col["dateadded"] && col["duedate"]) ftype="kev"
  else if (col["device"] && col["line"] && col["installed"] && col["target"]) ftype="asset"
  else {
    ftype="unknown"
    emit("S1", FILENAME, "表头缺必需列（公告需 cve/component/fixed/available_for；在野需 cveID/vendorProject/dateAdded/dueDate；资产需 device/line/installed/target）: " substr($0,1,80))
  }
  nrow[FILENAME]=0; fileSeen[FILENAME]=1; fileType[FILENAME]=ftype
  if (ftype=="advisory") advSeen[FILENAME]=1
  next
}
# ---------------- 公告件 ----------------
ftype=="advisory" {
  nrow[FILENAME]++
  c = trim($col["cve"]); comp = trim($col["component"])
  fix = trim($col["fixed"]); av = trim($col["available_for"])
  rd = (col["releasedate"] ? trim($col["releasedate"]) : "")
  if (NF < 4) { emit("S5", FILENAME, "列数少于表头必需列，该行跳过: " substr($0,1,60)); next }
  if (c == "") { emit("S5", FILENAME, "公告行的 CVE 列为空"); next }
  if (c !~ /^CVE-[0-9]{4}-[0-9]{4,}$/) { emit("S3", FILENAME, "公告件 CVE-ID 形态非法: [" c "]"); next }
  if ((FILENAME SUBSEP c) in perAdv) emit("S2", FILENAME, "同一公告件里 CVE 重复出现: " c)
  perAdv[FILENAME SUBSEP c] = 1
  union[c] = 1
  advSeen[FILENAME] = 1
  if (comp != "") comps[FILENAME SUBSEP comp] = 1
  ln = lineOf(fix)
  if (ln != "") { advLine[FILENAME] = ln; lineAdv[ln] = FILENAME }
  if (av != "") availBlob[FILENAME] = availBlob[FILENAME] lc(av) " "
  if (rd != "") { dd = rd; sub(/T.*/, "", dd); advDate[FILENAME] = dd }
  next
}
# ---------------- 在野件 ----------------
ftype=="kev" {
  nrow[FILENAME]++
  c = trim($col["cveid"]); vp = trim($col["vendorproject"])
  da = trim($col["dateadded"]); dd2 = trim($col["duedate"])
  sd = (col["shortdescription"] ? trim($col["shortdescription"]) : "")
  if (NF < 4) { emit("S5", FILENAME, "在野件列数不足: " substr($0,1,60)); next }
  if (c !~ /^CVE-[0-9]{4}-[0-9]{4,}$/) { emit("S3", FILENAME, "在野件 CVE-ID 形态非法: [" c "]"); next }
  if (lc(vp) != "apple") { nonApple++; next }
  w1 = dnum(da); w2 = dnum(dd2)
  if (w1 < 0 || w2 < 0) { emit("S5", FILENAME, "在野件日期列不是 YYYY-MM-DD: " c); next }
  nKev++; kevList[nKev] = c; kevWin[c] = w2 - w1; kevDue[c] = dd2
  if (kevWin[c]!=14 && kevWin[c]!=21) emit("K3", c, "修复窗口 " kevWin[c] " 天，不在主窗口 {14,21} 内：该条的时限与其余条目不同口径")
  if (!(c in union)) { ncve++; emit("K1", c, "在野条目未出现在任何输入公告的 CVE 并集里（缺陷线索: " substr(sd,1,60) "）") }
  next
}
# ---------------- 资产件 ----------------
ftype=="asset" {
  nrow[FILENAME]++
  dev = trim($col["device"]); ln = trim($col["line"])
  inst = trim($col["installed"]); tgt = trim($col["target"])
  defd = (col["deferral_days"] ? trim($col["deferral_days"]) : "")
  catd = (col["catalog_date"] ? trim($col["catalog_date"]) : "")
  audd = (col["audit_date"] ? trim($col["audit_date"]) : "")
  cmap = (col["component_map"] ? trim($col["component_map"]) : "")
  mdl  = (col["model"] ? trim($col["model"]) : "")
  ret  = (col["retired"] ? trim($col["retired"]) : "")
  nAsset++
  if (ln != "") { assetPlat[platformOf(ln)]++ ; assetLine[dev]=ln }
  if (cmap != "present") emit("C3", dev, "component_map=" (cmap==""?"空":cmap) "：缺陷到组件的映射不可得，该行只能记不可判定")
  if (catd == "" || dnum(catd) < 0) emit("C3", dev, "缺目录快照日期或形态非法: [" catd "]")
  wantLine = platformOf(ln) "-" tgt
  if (!(wantLine in lineAdv)) emit("C1", dev, "无迁移路径：目标 " tgt " 在线上没有可核对的公告件（线 " wantLine "）")
  else {
    f = lineAdv[wantLine]
    if (mdl != "" && index(availBlob[f], lc(mdl)) == 0) emit("R7", dev, "机型串 [" mdl "] 在该公告的可用机型文本里找不到：台账机型写法与公告口径不一致")
  }
  if (ln != "" && !(ln in lineAdv)) emit("R6", dev, "资产登记的版本线 " ln " 在输入公告里没有对应的 fixed 标签")
  if (ret == "yes") for (j = 1; j <= nKev; j++) if (!(kevList[j] in union)) { emit("K4", dev, "版本线 " ln " 已停更，在野条目 " kevList[j] " 在该线上没有任何可达的公告面"); break }
  if (defd ~ /^[0-9]+$/ && defd+0 > 0) for (j = 1; j <= nKev; j++) { kcv = kevList[j]
    if (kcv in kevWin && kevWin[kcv] >= 0 && kevWin[kcv] < defd+0) { emit("K2", dev, "在野条目 " kcv " 要求 " kevWin[kcv] " 天内修复，而台账允许的延期是 " defd " 天：两处时限不在同一口径"); break } }
  if (audd != "" && inst != "" && inst != tgt && dnum(audd) >= 0) for (j = 1; j <= nKev; j++) { kcv = kevList[j]
    if ((kcv in kevDue) && dnum(kevDue[kcv]) >= 0 && dnum(kevDue[kcv]) < dnum(audd)) { emit("K5", dev, "在野条目 " kcv " 的 dueDate (" kevDue[kcv] ") 已过期，该台仍在 " inst "（目标 " tgt "）"); break } }
  next
}
END {
  for (f in fileSeen) if (nrow[f] == 0 && fileType[f] != "unknown") emit("S4", f, "输入文件除表头外没有数据行")
  nadv=0; for (f in advSeen) nadv++
  uni=0;  for (k in union)    uni++
  tot=0;  for (f in advSeen) { c0=0; for (k in perAdv) if (index(k, f SUBSEP)==1) c0++; advCnt[f]=c0; tot+=c0 }
  if (KEVFILE == "") emit("C3", "-", "未提供在野条目件：K 类判定整段不可算（本次只算公告面）")
  # 在野截止日早于最早可核对的修复公告发布日
  for (j = 1; j <= nKev; j++) { kc = kevList[j]
    if (!(kc in union) || kevDue[kc] == "" || dnum(kevDue[kc]) < 0) continue
    gd = ""; gf = ""
    for (f in advSeen) if ((f SUBSEP kc) in perAdv && advDate[f] != "" && (gd == "" || dnum(advDate[f]) < dnum(gd))) { gd = advDate[f]; gf = f }
    if (gd != "" && dnum(kevDue[kc]) < dnum(gd)) emit("K6", kc, "在野截止日 " kevDue[kc] " 早于最早可核对的修复公告发布日 " gd "（" advLine[gf] "）：按公告口径这台设备不可能在窗口内拿到修复") }
  emit("R1", "-", "公告件 " nadv " 份；逐份计数合计 " tot " 条；按 CVE-ID 去重后的并集 " uni " 条")
  if (nKev > 0) { cov=0; for (j = 1; j <= nKev; j++) if (kevList[j] in union) cov++
    emit("R1", "-", "在野 Apple 条目 " nKev + 0 " 条，其中落在本次并集里的 " cov " 条，未落进 " (nKev-cov) " 条") }
  if (tot != uni) emit("R2", "-", "直加 " tot " 与去重 " uni " 不相等：把公告条目数相加会凭空多算 " (tot-uni) " 条")
  for (f in advSeen) if (advCnt[f] == 0) emit("R8", f, "该公告件的 CVE 条目数为 0：这次发布在公告口径里不带 CVE")
  # 同平台两条线之间的 CVE 交集
  for (ln in lineAdv) { p = platformOf(ln); platLines[p] = platLines[p] " " ln }
  for (p in platLines) { n = split(platLines[p], arr, " ")
    for (i = 1; i <= n; i++) for (j = i+1; j <= n; j++) { if (arr[i]=="" || arr[j]=="") continue
      A = lineAdv[arr[i]]; B = lineAdv[arr[j]]
      inter = 0; for (k in union) if ((A SUBSEP k) in perAdv && (B SUBSEP k) in perAdv) inter++
      if (inter == 0) emit("R3", arr[i] " / " arr[j], "同一平台两条线的 CVE 交集为 0：公告不是累计清单") } }
  # 同日发布的多条线
  for (f in advSeen) { dd = advDate[f]; if (dd != "") byDate[dd] = byDate[dd] " " f }
  for (dd in byDate) { n = split(byDate[dd], fs, " "); if (n < 2) continue
    for (i = 1; i <= n; i++) for (j = i+1; j <= n; j++) { A = fs[i]; B = fs[j]
      if (A == B || advLine[A] == "" || advLine[B] == "" || advLine[A] == advLine[B]) continue
      inter = 0; oa = 0; ob = 0
      for (k in union) { a = ((A SUBSEP k) in perAdv); b = ((B SUBSEP k) in perAdv)
        if (a && b) inter++; else if (a) oa++; else if (b) ob++ }
      emit("R4", advLine[A] " / " advLine[B], dd " 同日两条线：交集 " inter " 条，" advLine[A] " 独占 " oa " 条，" advLine[B] " 独占 " ob " 条") } }
  # 组件标签跨公告对齐
  for (f in advSeen) for (k in comps) if (index(k, f SUBSEP)==1) { split(k, pp, SUBSEP); compAll[pp[2]]++ }
  sh = 0; si = 0; al = 0
  for (cn in compAll) { al++; if (compAll[cn] >= 2) sh++; else si++ }
  if (si > 0 && nadv >= 2) emit("R5", "-", "组件标签共 " al + 0 " 个：跨公告同名出现 " sh " 个，只在一份里出现 " si " 个 —— 跨公告换算组件名不可靠")
  # 一次请求里混平台
  np = 0; for (p in assetPlat) { np++; plist = plist " " p }
  if (np >= 2) emit("C2", "-", "资产件里同时出现 " np + 0 " 个平台线（" substr(plist,2) "）：跨平台线合并计算被拒，需按平台分别跑")
  # ---------------- 输出 ----------------
  if (!QUIET) for (i = 1; i <= nline; i++) print lines[i]
  print ""
  print "==== 汇总 ===="
  printf "公告件=%d  在野条目(Apple)=%d  资产行=%d  CVE并集=%d\n", nadv, nKev, nAsset, uni
  split("R1 R2 R3 R4 R5 R6 R7 R8 K1 K2 K3 K4 K5 K6 S1 S2 S3 S4 S5 C1 C2 C3", cc, " ")
  bad = 0
  for (j in cc) { c2 = cc[j]; n2 = cnt[c2]+0; printf "%-4s %4d\n", c2, n2
    if (c2 ~ /^S/ || c2 == "K1" || c2 == "K6" || c2 == "C1") bad += n2 }
  printf "阻断类信号(S*/K1/K6/C1)合计=%d\n", bad
  exit (bad > 0 ? 1 : 0)
}
' "${FILES[@]}" > "$TMPD/out.txt"
rc=$?
cat "$TMPD/out.txt"
exit $rc
```

### 22.5 用本轮存档实跑一遍

脚本二可以吃真实公告文本。本轮把三份 CSAF 派生件（`B/CSAF/149041-cves.tsv`、`149227-cves.tsv`、`149230-cves.tsv`）与在野件 `C/kev-apple.tsv` 一起喂进去，不带资产件，得到的 R/K 类逐条读数（原文照贴，仅省略 95 条 K1 中的 88 条）：

```
R1	-	公告件 3 份；逐份计数合计 392 条；按 CVE-ID 去重后的并集 270 条
R1	-	在野 Apple 条目 95 条，其中落在本次并集里的 0 条，未落进 95 条
R2	-	直加 392 与去重 270 不相等：把公告条目数相加会凭空多算 122 条
R3	ios-26.7.2 / ios-26.7	同一平台两条线的 CVE 交集为 0：公告不是累计清单
R4	ios-27.2 / ios-26.7.2	2026-10-26 同日两条线：交集 119 条，ios-27.2 独占 44 条，ios-26.7.2 独占 15 条
R5	-	组件标签共 101 个：跨公告同名出现 55 个，只在一份里出现 46 个 —— 跨公告换算组件名不可靠
K3	CVE-2026-65400	修复窗口 3 天，不在主窗口 {14,21} 内：该条的时限与其余条目不同口径
```

这四段读数是第 16 章 R5、R6、R7、R12、R13 的机器复核版：392/270/122 就是"当天修了 392 个"这句常见误算的现场；119/44/15 就是同日两条线的实际重叠量；95 条在野条目一条都没落进这三份公告，是 K1 打满 95 次的原因。**同一条命令换三份别的公告会给出别的数，而 K3 的 10 条与本轮派生件 `C/kev-apple-lag.txt` 的 `nonstandard_window_count=10` 完全对齐**——这类对齐是脚本二可信度的唯一来源：它的每个数都能回到读者自己下载的那份文本上重算。

三点运行纪律：

- 同一平台的两条线之间才有 R3；跨平台线只做同日比对（R4）。R3 与 R4 的对象串里两个线名的先后顺序不保证稳定（`awk` 关联数组的遍历序），比对时按"线名集合"而不是"字符串"看。
- 资产件一旦跨平台，脚本二会打 C2 并拒绝给合并结论；这是设计，不是错误。iOS 与 macOS 的公告口径不通用（第 3 章 C7）。
- K6 只在"这条在野条目确实落进了某份公告"时才可算，本轮真实数据里 0 条落进，所以 K6 未触发；这一档要在 fixture 里验（见第 23 章）。

## 23. 两个脚本的全量分支覆盖验收

### 23.1 什么算"覆盖"

本文所有脚本都按同一套验收口径过一遍，四条全部满足才算通过：

1. **每个信号码至少被触发一次**：用构造 fixture 逐码驱动，不看代码路径的静态推断，只看运行输出里的计数是否 >0。
2. **good 档零阻断**：另造一份完全合规的输入，跑出的阻断类信号合计必须为 0，退出码必须为 0。这一条防的是"永远报警的脚本"——只在坏输入上通过的脚本等于没有通过。
3. **码数与第 1 章声明一致**：脚本一 41 个、脚本二 22 个，合计 63 个；两边汇总里逐码列出的行数必须等于这个数。
4. **隔离声明可自证**：脚本里不出现网络客户端、设备侧命令与写输入文件的路径；这一条用 `grep` 自证（见 23.5），不靠读者相信注释。

fixture 全部是**构造数据**：版本号、构建号、CVE-ID、日期与设备标识都是为了命中某个分支而写的，不代表任何真实设备，也不是从任何真实系统导出的。真实读数只在 22.5 与 23.5 的"真实档"里出现，两者在文里分开标注。

### 23.2 fixture 清单

| 档 | 件 | 内容 | 目的 |
|---|---|---|---|
| 脚本一 bad | 1 份台账，172 条记录行（另有 17 行分档注释）：15 台进入判定的设备 DEV-A…DEV-O，加 3 条故意写坏的解析行（两列的 DEV-P 行、一个字的行、缺设备标识的行） | 每台专门写坏一族：DEV-L 集中策略冲突（D02/D04/D05/D07/D08），DEV-M 集中数据类型与旧键名（D03/D09/D10/D15/D16），DEV-O 集中读数口径（E06—E09、E11、E12） | 逐码驱动 |
| 脚本一 good | 1 份台账，23 条记录行、1 台设备 | 全字段合法、构建等于目标、映射可得、撤除状态已知 | 零阻断 + J1 |
| 脚本二 bad | 5 份公告件（含 1 份仅表头、1 份表头不符）+ 1 份在野件 7 行 + 1 份资产件 5 行 | 三份真公告的 CVE 集有意的包含与不相交关系、两条同日线、跨平台资产、已停更线、过期 dueDate | 逐码驱动 |
| 脚本二 good | 1 份公告件 2 行 + 1 份在野件 2 行 + 1 份资产件 2 行 | 在野条目全部落进并集、窗口取 14/21、目标线有公告、机型串能在 `available_for` 里找到 | 零阻断 + rc=0 |
| 真实档 | `.srcx9/B/CSAF/*-cves.tsv` ×3 + `.srcx9/C/kev-apple.tsv` | 本轮取回的真文本 | 与第 16 章读数对齐 |

### 23.3 脚本一：41 个码的逐码触发记录

下表是三档实跑之后从输出里直接抄出来的（首次触发的设备标识 + bad 档总计数），41 行、无一行计数为 0。

| 码 | bad 档首次触发对象 | 计数 |
|---|---|---|
| D01 | DEV-B | 1 |
| D02 | DEV-L | 1 |
| D03 | DEV-M | 1 |
| D04 | DEV-L | 1 |
| D05 | DEV-L | 2 |
| D06 | DEV-C | 1 |
| D07 | DEV-L | 1 |
| D08 | DEV-L | 1 |
| D09 | DEV-M | 1 |
| D10 | DEV-M | 1 |
| D11 | DEV-I | 1 |
| D12 | DEV-C | 2 |
| D13 | DEV-N | 1 |
| D14 | DEV-D | 1 |
| D15 | DEV-M | 1 |
| D16 | DEV-M | 1 |
| B01 | DEV-H | 1 |
| B02 | DEV-I | 2 |
| B03 | DEV-C | 1 |
| B04 | DEV-J | 1 |
| B05 | DEV-B | 1 |
| B06 | DEV-K | 1 |
| B07 | DEV-D | 1 |
| E01 | DEV-F | 2 |
| E02 | DEV-G | 1 |
| E03 | DEV-E | 1 |
| E04 | DEV-C | 1 |
| E05 | DEV-K | 2 |
| E06 | DEV-O | 1 |
| E07 | DEV-O | 1 |
| E08 | DEV-O | 1 |
| E09 | DEV-O | 1 |
| E10 | DEV-J | 2 |
| E11 | DEV-O | 1 |
| E12 | DEV-O | 1 |
| U01 | （解析类，无设备标识） | 2 |
| U02 | （解析类，无设备标识） | 1 |
| J1 | DEV-A | 1 |
| J2 | DEV-B | 2 |
| J3 | DEV-C | 6 |
| J4 | DEV-D | 6 |

**分布读数**：bad 档 15 台设备的判定分布为 `J1=1 J2=2 J3=6 J4=6`，阻断类信号合计 36；good 档 `J1=1`、阻断 0、退出码 0。判定四档在同一份输入里全部出现，说明第 19 章的判定树不是摆设：J4 的 6 台里，DEV-D 是被 `channel=accessory` 拦下的（L10），其余是被缺目录快照、缺词表、公告 CVE 条目数为 0 这三类证据缺失拦下的。

### 23.4 脚本二：22 个码的逐码触发记录

| 码 | bad 档首次触发对象 | 计数 |
|---|---|---|
| R1 | （全局读数） | 2 |
| R2 | （全局读数） | 1 |
| R3 | ios-26.7.2 / ios-26.7 | 1 |
| R4 | ios-26.7 / macos-15.6 | 3 |
| R5 | （全局读数） | 1 |
| R6 | DEV-4 | 1 |
| R7 | DEV-2 | 1 |
| R8 | .scratch/x9s2/bad/adv-d.tsv（仅表头件） | 1 |
| K1 | CVE-2026-9999 | 3 |
| K2 | DEV-2 | 1 |
| K3 | CVE-2026-1001 | 2 |
| K4 | DEV-4 | 1 |
| K5 | DEV-1 | 4 |
| K6 | CVE-2026-1001 | 1 |
| S1 | .scratch/x9s2/bad/adv-e.tsv（表头不符件） | 1 |
| S2 | .scratch/x9s2/bad/adv-a.tsv | 1 |
| S3 | .scratch/x9s2/bad/adv-a.tsv | 2 |
| S4 | .scratch/x9s2/bad/adv-d.tsv（仅表头件） | 1 |
| S5 | .scratch/x9s2/bad/adv-a.tsv | 3 |
| C1 | DEV-1 | 2 |
| C2 | （全局读数） | 1 |
| C3 | DEV-2 | 2 |

**分布读数**：bad 档 36 条明细信号、阻断类合计 14、退出码 1；good 档只剩两行 R1 读数、阻断 0、退出码 0；真实档（22.5）打出 R1×2、R2×1、R3×1、R4×3、R5×1、K3×10、K1×95，阻断合计 95，退出码 1。

### 23.5 隔离性自证与一致性核对

隔离性不靠注释，用三条 `grep` 与一次临时目录观察自证：

1. `grep -nE 'gdmf|curl|wget|mdmclient|osascript|sudo'` 在两个脚本里命中 0 处；`grep -n 'softwareupdate'` 在脚本一命中 7 处、脚本二 0 处，7 处全部是**台账列名**（`status.softwareupdate.install-state` 之类字符串字面量），不是被执行的外部命令。
2. 两个脚本各自的唯一写出目标是 `mktemp -d` 建的目录（`.XXXXXX` 后缀），运行前 `trap 'rm -rf "$TMPD"' EXIT INT TERM`，运行后该目录不存在；输入文件只用 `<` 与 `awk` 读取，脚本里没有任何 `> 输入件` 形式的重定向。
3. 脚本一的处理体是一次 `awk '…' "$@"`，脚本二是一次 `awk '…' "${FILES[@]}"`，中间件写在 `"$TMPD/out.txt"` 再整体 `cat` 出来；也就是说**逐条信号是先算完再输出**，中途 `Ctrl-C` 不会留下半份输出，也不会留下临时件。

一致性核对（本轮实跑得到的）：

| 核对项 | 期望 | 实跑 |
|---|---|---|
| 脚本一码数 | 41 | 汇总逐码 41 行，bad 档非零 41/41 |
| 脚本二码数 | 22 | 汇总逐码 22 行，bad 档非零 22/22 |
| 合计 | 63（第 1 章声明） | 63 ✓ |
| 脚本一 good 阻断 | 0 | 0，rc=0，J1=1 |
| 脚本二 good 阻断 | 0 | 0，rc=0 |
| 脚本二真实档 K3 条数 | 与 `C/kev-apple-lag.txt` 的 10 一致 | 10 ✓ |
| 脚本二真实档 R2 差额 | 392 − 270 = 122 | 122 ✓ |
| 脚本二真实档 R5 | 101 个标签 / 55 个跨公告同名 / 46 个单侧 | 101 / 55 / 46 ✓ |

### 23.6 这份验收不能证明什么

四条局限要写在同一章里，不能让读者自己发现：

1. **fixture 只证"分支可达"，不证"分支正确"**。每个码都触发过，但"触发得对不对"是靠第 4—13 章的文档口径逐条对照出来的，不是靠覆盖率本身。一个把两个码写反的脚本同样能做到 100% 触发。
2. **脚本一没有真实档**。本轮不接触设备，也就没有真台账；good/bad 两档都是构造的。这一点对第 17 章的 V2/V3 分级是自我一致：读者要跑出非 J4 的判定，得自己从 MDM 侧导出。
3. **词表类判定（E01/E03）随口径版本变**。Apple 把 `waiting` 补进状态项页的那一天，同一个脚本会在同一份台账上少打一个 E03。这类码的语义是"两份文档不一致"，不是"值非法"，指标 O9 必须记口径版本。
4. **真实档只跑了公告面**。22.5 那次运行没有资产件，因此 K2/K4/K5/K6、C1/C2、R6/R7 在真实文本上是 0 次触发——它们是可达但未在真实数据上验证过的分支。要补的只有读者自己的资产清单，脚本二不需要改一行。

两个脚本的正文与 fixture 都是纯文本，可以直接抄走复用；它们对本报告其余章节的唯一依赖是第 16—19 章给出的口径。

---

## 24. 十二个误区

这一章不列"外行错误"，只列**在读了公开文档之后仍然会犯的读法错误**。每一条的结构固定为三行：常见的说法、按本文口径它错在哪一格、读者能在台账上做的对应动作（括号里给出触发它的信号码）。凡"公开口径"一行给出的判断，都能在前 23 章找到同一件事的文档句或读数。

### M1 · "Apple 发了公告，所以这台设备已经修好了"

- **常见说法**：把公告页上出现这台机型的版本行，等同于这台设备的缺陷已闭合。
- **错在哪一格**：公告面（L1）与设备面（L5、L8）之间隔着目录可见（L2）、授权装配（L3—L4）、策略与延期（L6）、强制与申报（L7）四道闸门，任何一道都能让补丁停在那里，而**设备在这一刻的表现与"根本没有这个补丁"完全相同**（第 1.1 节）。《Apple Platform Security》第 1144 行也只把更新描述为一个过程（"Security is a process"），不描述为一次发布。
- **台账动作**：只有同时满足"公告面存在该 CVE + 目录快照里这一机型出现过该版本 + `install-state` 落到完成态 + 版本读数与目标一致"才能升 J1；缺任意一格分别落 J2、J3、J4（第 19 章）。脚本一的 D06、B01、E05、J 判据链就是这四道闸门的检查点。

### M2 · "公告有两个日期，挑一个写进台账就行"

- **常见说法**：把机器件的 `releaseDate` 与公告表的行日期合成一个"发布日期"，谁看起来更合理就留谁。
- **错在哪一格**：两个日期**都合法**，但口径不同（一个是 CSAF 生成时间，一个是发布表行时间），本轮实测同一版本上相差 42 天（第 16 章 R11）。台账如果只留一个，就无法解释"为什么这条在野条目的截止日早于我们登记的发布日"。
- **台账动作**：两列都留，用脚本二的 `releaseDate`/`available_for` 字段各自参与计算，差集与窗口一律按两个日期分别跑一遍再对结论；触发不一致时记 K6（在野截止日早于最早可核对的修复公告发布日）。取舍由读者的合规口径决定，但**必须由读者显式写下取舍的是哪一句**。

### M3 · "先看设备现在是什么版本，再倒推它含哪些补丁"

- **常见说法**：审计从设备读数起步，读到一个版本号，然后去公告页找"这一版修了什么"。
- **错在哪一格**：倒推方向上有一处不可逆的歧义——同一版本线上相邻两次更新的 CVE 集**交集为 0**（第 16 章 R7），所以"设备在 26.7"既不能推出"它含 26.7.2 的修复"，也不能从 26.7.2 的公告反推 26.7 装了哪些。第 19.3 节的六问因此把顺序钉死为**公告面 → 目录面 → 设备面**。
- **台账动作**：以 CVE（或组件名）为主键起表，每一行再问这台设备的版本线是否覆盖它；脚本二正是这个方向的实现（并集/差集 + K 类时限），脚本一负责设备侧那一半。

### M4 · "设置里显示已是最新版本，所以是安全的"

- **常见说法**：把设备"软件更新"页面上的"已是最新"当作达标读数。
- **错在哪一格**：这个界面回答的是"目录里有没有比本机更新的、且这台机型可得的构建"，它不检查某条 CVE 是否被覆盖，也不报告 Background Security Improvements 是否已装或被撤除（第 5 章、第 11 章）。更关键的是"已是最新"这一格本身取决于目录子集（`AssetSets` 与 `PublicAssetSets` 的差，第 5.3 节），管理服务能推的版本只是公开集合的子集。
- **台账动作**：把版本读数写成三格——`operating-system.version`、`operating-system.build-version`、`supplemental.build-version`/`extra-version`；只填前两格的台账会在 BSI 撤除后回到同一个"已是最新"（B06、E05）。达标判定必须引台账里自留的目录快照日期（B01、B02）。

### M5 · "关掉更新通知，就关掉了强制更新"

- **常见说法**：把"不提醒"读成"不发生"，并据此认为关闭通知能阻止强制安装。
- **错在哪一格**：`Notifications` 这一组键控制的是**提醒**，安装动作由强制声明与自动动作两组键决定；第 10 章 phases 第 29 行的阶段描述里，到达目标版本后的下载与安装并不以"用户看到通知"为前置。把两个键当同一个开关，会在台账里造成"这台已阻止"而实际"这台正在装"的相反结论（D06 就是这一组合）。
- **台账动作**：`policy.Notifications.*` 与 `policy.AutomaticActions.*`、`enforce.*` 三组分开登记，任何一行只填其中一组时，脚本一对另外两组保持沉默——**不填不等于关**。

### M6 · "延期天数对 Background Security Improvements 也（不）生效"

- **常见说法**：在两条文档句里挑一句当结论：要么"延期当然也延 BSI"，要么"BSI 不受延期机制影响"。
- **错在哪一格**：第 9 章已给出这两句，它们主语不同、对同一条配置项给出相反预期，而公开文档没有裁决句（G9）。把任意一句当结论，等于把一条**不可判定**的边界当成一条已知规则；一旦按这句配置了 90 天延期，台账里的"最晚应装时间"就会带着一个没有依据的假设。
- **台账动作**：延期键的取值域与共存关系可以校验（D02、D03、D04），BSI 是否被延期覆盖**不许校验**——脚本一对此不输出任何码。读者要做的是在台账里显式记一行"本行采用了哪一句读法"，并把这一行连同结论一起存档。

### M7 · "回执码/状态串的含义是常识，可以照着日常语义读"

- **常见说法**：把管理侧返回的状态或 HTTP 码按日常语义解释（"这个码就是设备离线""这个码就是拒绝了"），第 11 章给出的正是这一类挪用。
- **错在哪一格**：同一个词在两份文档里取值集不同：`install-state` 状态项页列 5 值、部署指南同段列 6 值并把 `waiting` 排在第二位（第 3 章 C2）。**回执面的词表由 Apple 拥有、由 MDM 厂商实现**，读者既不能补值也不能合并值；把 `waiting` 读成"没有更新"会整段丢掉"强制声明已被接受但还没开始下载"。
- **台账动作**：台账用 `device.vocabulary` 声明自己按哪套表读；声明缺失时脚本一打 E02，声明 5 值表却收到 `waiting` 时打 E03，取值连自声明的表都装不进时打 E01。三码都不阻断（B/E 族属边界信号），但**都不允许被读成"这台设备安全/不安全"**。

### M8 · "把 `EnableRollback` 关掉，这台就不能回滚了"

- **常见说法**：把管理侧唯一可见的回滚键读成系统自身的撤销能力。
- **错在哪一格**：《SoftwareUpdateSettingsRapidSecurityResponseObject》第 12 行说的是**是否向用户提供回滚选项**，不是系统能否回滚（第 12.2 节）。两者在合规文本里极易混写：前者是可配置项，后者取决于签名窗口（《Apple Platform Security》第 1146 行 "only copies of operating system versions that are actively being signed by Apple can be installed"），这一格根本不在 MDM 的写权限里。
- **台账动作**：`policy.RapidSecurityResponse.Enable` 与 `EnableRollback` 两键都登记，两者同时为 false 时脚本一打 D16（两键 default 均为 true，取值需注明依据）。要判"能不能回到上一版"，得看目录侧签名与可得版本，那是 V4，不许由台账推断。

### M9 · "把公告条目数相加，就得到这轮修了多少个缺陷"

- **常见说法**：三份公告各列 95、134、163 条，于是"本轮共修复 392 个缺陷"。
- **错在哪一格**：直加 392 与去重后 270 之间凭空多算 122 条（第 16 章 R5 与 R6，脚本二 R2）。跨公告同名的组件标签也只有 55/101 个对得上（脚本二 R5），所以"按组件名换算"同样不可靠。
- **台账动作**：任何"本轮修复数量"都必须写成"逐份计数合计 X，按 CVE-ID 去重后 Y"两个数；只要一个数的口径不进报告。脚本二 R1 输出的就是这一对数。

### M10 · "同一条版本线上，后一次更新是前一次的累计清单"

- **常见说法**：装了 26.7.2 就默认含 26.7 的全部修复，或者反过来。
- **错在哪一格**：本轮实测同线相邻两次（26.7 与 26.7.2）CVE 交集为 **0**（第 16 章 R7、脚本二 R3）。同日并行发出的两条线之间也不是累计关系（27.2 与 26.7 交集仅 3 条，脚本二 R4）。"非累积"不是文档的一句话，而是这一轮公告文本本身的可核对事实。
- **台账动作**：跨两条线的差集运算只在同一平台线内做，并且必须先跑脚本二确认交集大小；`installed` 与 `target` 跨线（例如 26.7 → 27.2）时按第 19 章的迁移路径检查（C1：目标版本在线上无可核对公告件时判无路径）。

### M11 · "配件与外设固件的更新也算进 iOS 达标率"

- **常见说法**：把 AirPods、显示器、键盘这类固件线（第 13 章 L10）与 iOS/iPadOS 版本线合并成一个"设备更新达标率"。
- **错在哪一格**：这一层不在软件更新通道上，走的是各自的装配与申报路径；合并计算会把两类不同的到达时点当成同一口径（第 20.3 节对 O10 的处置）。
- **台账动作**：`channel=accessory` 的行由脚本一直接打 B07 并从 iOS 侧指标里剔除；O10 单独成项，永不进 O1—O8 的分母。指标命名里凡带"iOS 达标率"的，分母必须是 iOS 软件更新通道上的行。

### M12 · "KEV 的 dueDate 是 Apple 的承诺时限，也是我们的合规上限"

- **常见说法**：把 CISA KEV 的 `dueDate` 读成"厂商必须在这天前发补丁"，或反过来用"我们最长可以延 90 天"来解释 KEV 窗口。
- **错在哪一格**：两套时限属于两套口径，主体不同。本轮 KEV 的 95 条 Apple 条目里，修复窗口 21 天 63 条、14 天 22 条，另有窗口 3 天 1 条与 181 天 9 条（第 16 章 R12、脚本二 K3）；而 MDM 允许的最长延期是 90 天。两者不换算：90 天延期可以让一台设备在 KEV 窗口内**合法地**还没拿到修复，这不违反任何一份文档，但违反任何一个按 KEV 起表的合规口径。
- **台账动作**：把 `deferral_days` 与 KEV 窗口并排比对（K2：台账允许的延期长于该条要求的窗口时输出）；已过 `dueDate` 仍在旧版本的行记 K5；版本线已停更的行走 K4（该线上没有任何可达公告面）。这四码都不要求读者裁决哪套口径优先，只要求**把裁决写进台账**。

---

## 25. 常见问题

**Q1：这篇和第 06、07、08 篇讲的是同一件事吗？**
不是。第 06 篇在系统服务与 IPC 那一侧，第 07 篇在推送到达那一侧，第 08 篇在授权与用途声明那一侧；三篇的共同前提都是"补丁已经装上"。本文只处理补丁到达链路本身——同一台设备在这三篇里是背景，在本文里是主键。凡本文需要引用缺陷形态，都写成 P1—P12 的型号而不是具体缺陷案例。

**Q2：为什么通篇不给任何一次具体攻击的利用细节？**
本文的判定对象是**版本与策略的到达性**，不是缺陷的可利用性。所有输入件都是公开文本（公告、状态项文档、策略导出件），所有输出都是"这台设备的这一格能不能自证"。给利用细节既不必要也不可核对。

**Q3：我没有 MDM，个人设备能用这套方法吗？**
能用其中三层：L1 公告面（脚本二的公告件）、L2 版本可见（需要自己留目录快照，本轮不取）、L5/L8 读数（自己在设置页与"关于本机"里抄）。个人侧没有 V3 的 MDM 回执，因此第 19 章里凡依赖 `install-state` 的判据一律落 J4——这不是失败，是本文承认的可见性上限。

**Q4：为什么不直接查 `gdmf.apple.com/v2/pmv` 的实时响应？**
两个脚本被明令禁止联网（第 1.4 节、第 23.5 节）。更重要的是实时查询只能证明"今天这个机型可得的版本"，不能证明"上周审计那一刻它可得"；要留的是**快照**，不是查询。这条限制记在第 17 章 V4 与第 26 章 G2。

**Q5：`This update has no published CVE entries.` 这一行怎么算进达标？**
不算。331 行公告表里 61 行（18.4%）只有这一句（第 16 章 R1、本文第 4.2 节）。以 CVE 为主键的台账在这一行上既不能证明覆盖也不能证明不覆盖，所以脚本二对它打 R8 并保留该行，而不是丢弃。指标口径上要报"不可判定行数"，不能把它并入达标率分子或分母。

**Q6：Background Security Improvements 与 Rapid Security Response 到底是不是同一个东西？**
本文只记录一个可核对的词表现象：`restrictions` 里两个仍在生效的键名仍是 `allowRapidSecurityResponseInstallation` 与 `allowRapidSecurityResponseRemoval`，而它们的说明文字已经全部改写为 Background Security Improvements（第 12.3 节、G7）。改名过程没有公开映射文档，因此正文一律用后者命名、在键名处保留前者原文，不做"二者等价"的断言。

**Q7：一台设备上装了 BSI，能算它修了某条 CVE 吗？**
默认不能。BSI 与 CVE 之间没有任何公开字段连接，`Background Security Improvements by date` 页给出的粒度是组件名，而组件名在 CSAF 里存在标签漂移（WebKit 与 WebKit Canvas，第 14 章 P2）。只有当台账自己登记了组件对齐表（`component_map=present`，B05）时才允许升 J1，否则最多 J2。

**Q8：装了 27.2，是不是就比停在 26.7.2 安全？**
不能这样比较。27.2 与 26.7.2 的 CVE 交集 119 条，各自独占 44 与 15 条（第 16 章 R6）——两条并行线各有独占修复，"更高版本号"不等于"覆盖另一条线的一切"。跨线比较必须走差集，而差集要在同一平台上分别算（C2 拒绝把跨平台线合并）。

**Q9：脚本一为什么全是文本台账，不直接读配置描述文件？**
因为可核对性。Apple 公开的是**键的语义**（属性页与部署指南），不是某台设备上的有效配置；后者的合并语义逐键定义且没有全部展开（G4）。让脚本读一个中间格式（CSV 台账）而不是 plist，正是为了强制读者自己写下"我认为生效的是这一句"，并把这句话留在审计记录里。

**Q10：两个脚本能不能改成自动判定"这台达标/不达标"？**
不能，这是设计而不是缺陷。判定需要"目标版本"和"缺陷清单"两个外部输入，脚本只被允许读文本；把达标写成脚本的返回值，等于让脚本替读者的合规口径负责。脚本输出的是 22 + 41 个信号码与四级判定，达标的定义留在读者的表头里。

**Q11：两个脚本的阻断集为什么分别是 S\*/K1/K6/C1 与 D/E/U？**
两个脚本对"阻断"取的是不同的东西。脚本二管**结论成不成立**：S 类是输入不可用（表头缺列、重复 CVE、形态非法、空件、列数不足），K1/K6/C1 是结论不可能成立（在野条目无处可归、截止日早于最早可得修复、目标版本无迁移路径）——这六族任意出现一条，这份覆盖差异表就没有可引用的口径，所以 `exit 1`；R 与 K2—K5 只是给读数加限定，进汇总不进退出码。脚本一管**台账自身口径齐不齐**：D 类是配置写法与公开语义冲突、E 类是取值落不进可核对词表、U 类是记录本身读不出〈设备,字段,值〉三列，这三族都意味着"这份台账不能用来做归属判定"，因此计入阻断；B 类（证据缺位）与 J4（不可判定）不计入退出码，因为它们的正确处置是补证据而不是改配置（第 21.5 节三点输出纪律第 2 条）。两边共同点：`exit 1` 说的都是**材料的问题**，不是设备的问题。

**Q12：这套方法明年还有效吗？**
分两层看。第 14—20 章的口径结构（层、型、归属矩阵、四级判定、指标）与具体版本无关；第 16 章的 18 条读数全部带时间戳属性，其中依赖 KEV 快照的 R13、依赖本轮三份公告的 R2/R12 会随下一次发布改变。脚本二的 K3 主窗口写死为 {14,21}，KEV 若改变默认窗口，这一码的语义要跟着改——这是本文预告的唯一一处需要随口径版本维护的实现（第 23.6 节第 3 条）。

---

## 26. 未公开文档化边界清单

本章逐条列出**文档自己没写、或本轮取回件里没有的那一格**。它的作用是给前面 25 章里每一次"不可判定"提供一个可回查的编号：正文凡写出 G1—G10，就必须在这一章找到"缺的是什么、在哪一节遇到、本文怎么处理"。凡本文给出"处理"的地方，都不越界补事实。

| 编号 | 缺的是什么 | 正文遇到它的位置 | 本文的处理 |
|---|---|---|---|
| G1 | `softwareupdate.failure-reason` 与 `softwareupdate.install-reason` 是字典对象，其**逐字段取值表**在各自的 DictionaryObject 页，本轮未取回那些页 | 第 2.2 节缺口 A、第 11.4 节、第 18.2 节、第 19.3 节第 4 问、脚本一 B03、脚本二资产件 `component_map` 无关 | 一律写"文档未在本轮可核对范围内给出"，不自行补列表；`failure-reason` 有值时只报不可分型（B03），并在判定链上把 P5/P6/P7 三者留在不可分状态 |
| G2 | `gdmf.apple.com/v2/pmv` 的**实际 JSON 响应**本轮不取；因此 `ExpirationDate` 的算法、`SupportedDevices` 的机型串写法、以及"某机型某日是否在 `AssetSets` 里"都只有文档口径可引，且无历史可回溯 | 第 2.2 节缺口 B、第 5.1/5.3 节、第 17.3 边界一、第 20 章 O5、脚本一 B01/B02 | 两个脚本被明令禁止访问该端点；目录面判定改成"读者自留快照 + 快照日期"的台账字段，无留档即整项标不可判定（J4），并把 `PostingDate + 180` 的 "typically" 记为描述而非保证（R16） |
| G3 | 《Apple Platform Security》以 PDF 取回后 `pdftotext -enc UTF-8` 转文本，正文夹页眉、页码与空行残块，**转文本件的物理行号 ≠ 阅读版式页码** | 第 2.2 节缺口 C、第 6.2 节、第 8.3 节、第 12.1 节 | 引用时声明"给的是转文本件的物理行号"，并在需要处说明"该行是正文"；跨篇比对只用同名转文本件，不用页码 |
| G4 | 多份 `softwareupdate.settings` 声明同时生效时的**合并语义逐键定义**没有全部展开（部署指南只给出"合并行为取决于单个键"这一句边界） | 第 9.7 节、第 20.1 节、第 21.2 节命名空间表 | "哪个策略生效"在 L6 不作为读者可单独判定的问题；脚本一只校验单行台账内的一致性（E11），不推断跨声明的合并结果 |
| G5 | 部署指南"建议订阅"的状态项表与实际状态项目录之间存在**键差**（不含 `StatusSoftwareUpdateDeviceID`、`StatusDeviceOperatingSystemFamily`、`StatusDeviceOperatingSystemMarketingName`） | 第 11.1 节、第 11.2 节、第 16 章 R17 | 只按状态项页各自的定义引用各自的键；凡指标需要 `device-id`（GDMF 查询）时，写明"由 MDM 实现另行上报"，不把它读成指南要求的订阅项 |
| G6 | 下载前置条件在 phases 文档里写作 "if it meets the requirements"，其条件集合（电量、空间、网络等）**没有闭合清单** | 第 6.2 节、第 19.3 节第 5 问 | 不列条件、不猜优先级；把"目标版本这一台的机型在目录里出现过吗"当作唯一可核对的前置检查，其余归 J4 |
| G7 | Rapid Security Response → Background Security Improvements 的**改名过程没有公开映射文档**；BSI 与其 base 版本、BSI 与 CVE 之间**没有任何字段显式连接** | 第 4.3 节、第 8.1 节、第 10.3 节、第 12.3 节、第 14 章 P2、脚本一 B05 | 命名规则：正文用后者、键名处保留前者原文并注"文档口径不同"；组件对齐表是读者自己的产物，脚本只在 `present` 时允许升 J1，否则最多 J2 |
| G8 | **移除/撤除之后**的读数形态没有闭合句：`supplemental.*` 应回到空串、基线构建号还是字段缺失，文档未给；且没有"撤除事件"状态项 | 第 12.1/12.5 节、第 14 章 P12、第 15 章 L9 行、脚本一 B06、D15 | 记为不可判定，不给"已成功回滚"的判法；`bsi_removed=unknown` 且 supplemental 读数非空 → B06 + 最多 J2；外置盘启动这一 macOS 侧等价问题一并记在此处（第 8.5 节） |
| G9 | **延期是否覆盖 BSI** 没有裁决句：属性页说 BSI 不在 Major/Minor/System 延期机制之内，部署指南旁注说"延期软件更新也会推迟依赖该版本的 BSI"，两句主语不同、预期相反 | 第 9.3 节、第 19.3 节第 6 问、脚本一 D02/D03/D04/D09 | 不裁决；脚本只校验延期键自身的取值域与共存，"采用哪一句"必须由台账显式登记；跨平台线的合并一律被 C2 拒绝 |
| G10 | `Background Security Improvements by date` 页本轮只取到**一条**数据行，无法判断这是页面口径（只列最近一条）还是取回时的分页截断 | 第 8.4 节、第 8.1 节的"一处按日期发布"、第 22 章资产件表头 | 按可核对事实记录条数，按可能性列为边界；**不据此推断 BSI 总条数**，也不把"只有一条"读成"最近只有一次" |

三条使用规则要一并写清：

1. **G 编号不替代 V 分级**。G 说的是"文档没有这一格"，V1—V4 说的是"读者能不能拿到这一格"。同一处可以同时是 G2 与 V4（目录面），也可以一个是另一个的原因（G6 导致第 19 章第 5 问只能走 J4）。
2. **G 编号不随本轮读数失效**。第 16 章的 R 类读数会随下一次发布变，G 类边界不会因为 Apple 发了一版新系统而自动闭合；它只会在文档补上那一格时闭合。指标 O9 要分开记这两类。
3. **凡正文出现"本文不判定 X"，必须能在这一章找到对应 G**。反查方式是逐条 grep：第 21.6 节三条、第 23.6 节四条、第 25 章 Q6/Q7/Q9，各自指向 G1、G7、G8、G2、G4。这一条是本文对自己的要求，不是给读者的建议。

---

## 27. 结论

1. **这条链路在每一格都有公开文档，但没有任何一格的公开产物能换算出"这台设备现在安全吗"。** 这是全文唯一一条不允许被任何指标、脚本或判定模型绕开的事实。三套词表（公告、设备与策略、外部应急）互不通约，七处换算失败里三处来自文档彼此不一致（第 3 章）。
2. **十层里，只有一层的修改权在 Apple 手里，只有一层的修改权在管理方手里，其余八层的唯一作用是让补丁到达得更慢或读数更模糊。** L1 与 L5 的写权限归 Apple（发布与安装形态），L6/L7 归管理方（策略、延期、强制声明），L2、L3、L4、L8、L9、L10 都不在任何一方的"可改"集合里。第 15 章的归属矩阵把这一句拆成了逐格表格，这里只留结论：把"提高安全性"理解为"改自己的策略"能覆盖的层，只有两格。
3. **约束点不在"厂商有没有发补丁"，而在"这一格允许被谁推迟多久、以及推迟之后有没有任何读数会变"。** 本轮读数给出的最强证据是这一组数：KEV 95 条 Apple 在野条目的窗口是 21 天（63 条）与 14 天（22 条），而 MDM 的 `Deferrals` 上限是 90 天；同一天并行发出的两条 iOS 线，27.2 与 26.7.2 的 CVE 交集 119、独占 44 与 15；同一条线上 26.7 与 26.7.2 的交集是 0。
4. **"公告发了"与"这台修好了"之间最多可以隔 90 天，而且这 90 天在文档上是合法的。** 本文不把这件事写成风险声明，而是写成台账字段：`deferral_days` 与 KEV 窗口并排（K2）、过期未修（K5）、停更线（K4）三码就是这一句的可核对形式。
5. **累计假设是这一条链路上最贵的一个错误。** 版本线非累计（脚本二 R3）、同日多线并行（脚本二 R4）、组件标签跨公告对不齐（脚本二 R5）、无 CVE 行占 18.4%（第 16 章 R1、脚本一 B04）四件事合起来意味着：**任何以"装了最高版本号"为口径的达标率都在系统性高估覆盖**。要得到可用的数，只能按 CVE 为主键起表并跑差集。
6. **回执面能证"这里有一个失败"，不能证"为什么失败"。** `install-state` 有两套词表（5 值与 6 值）、`failure-reason`/`install-reason` 的逐字段表本轮不可核对（G1）、"最后一次失败时间"文档承诺但示例未见、没有撤除事件状态项（G8）。所以第 19 章的"已确认"只允许由 V1—V3 的合取构成，路径上出现一次 V4 就硬停。
7. **可见性分级比判定模型更重要。** V4 的五项里只有两项是"服务不公开"，其余三项是文档自己承认粒度不够或本轮没取回。把它们写成"不可判定"而不是"没问题"，是 O9 这一项存在的全部理由。
8. **两个离线只读脚本把这一套口径变成了可执行检查，63 个信号码在本轮全部实跑触发，且两个脚本零网络、零设备调用。** 它们不判"该不该升"，只把"你写的这一格会让设备与管理服务读到什么"打印出来。good 档零阻断、bad 档 41/41 与 22/22 全覆盖，加上真实存档实跑得到的 R1/R2/R3/R4/R5/K3，构成第 23 章的一致性核对表；第 23.6 节同时写明了这份验收不能证明什么。
9. **对个人设备与无 MDM 环境，这套方法能用的部分只剩三层，其余一律 J4。** 这不是方法失效，而是本文承认的可见性上限：没有 `install-state` 回执，就没有 V3，也就没有 J1。任何声称"个人侧也能自证已修"的做法都需要额外证据，而那份证据本轮不存在（G2）。
10. **本文能给的唯一可长期使用的产物，是一张"层 × 责任方 × 通道 × 证据"的空表和两份脚本。** 读数会过期（R 类），词表会变（E 类），页面会变（G 类）；只要表的十层与判定四级还在，下一轮审计换一份存档就能重跑。这是第 2 章"视角声明"想要换来的东西：**让这篇报告的读数在明年变成可替换的部分，而不是需要重写的部分。**

一句收尾：这条链路上最危险的不是某一次更新失败，而是**每一次失败都长得像"没有可用更新"**。本文全部工作就是把这个"长得像"拆成十格、四型判定与 63 个信号码，让读者能说出：这一格我看得见、那一格我看不见，而看不见不等于已修。

---

## 28. 参考资料

以下即本轮全部取回记录。凡正文引用的英文句子都必须能在对应存档件里按行找到原句（第 2.1 节自审清单第 1 条），引用格式为"《标题》第 N 行"，行号为**扁平转文本件的物理行**。取回与展开由 `.x9-fetch.sh`（开发者文档数据接口 `developer.apple.com/tutorials/data/documentation/<路径>.json`）与 `.x9-flat.pl` 完成，PDF 转文本用 `pdftotext -enc UTF-8`；每件的字节数、行数、SHA-256、取回时间与源地址固化在 `.srcx9/IDX/files.tsv`，件名与标题对照同步在 `.srcx9/MANIFEST.txt`。取回日期：2026-10-31。

### 28.1 A 组 · Apple 开发者文档（设备管理：软件更新声明、状态项与限制项）

28 页全部取回、0 页缺失；展开件首行为 `PAGE-TITLE`，表格行被拍平成一行一项。原始 JSON 响应（28 件）与展开件同集合，一并存档在 `.srcx9/RAW/devicemanagement/`。

| 存档件名 | 文档标题（取回件首行 PAGE-TITLE） | 行数 |
|---|---|---|
| commands-and-queries | Commands and queries | 91 |
| deploying-software-updates-using-declarative-management | Deploying software updates using declarative management | 147 |
| device-information-command | Device Information | 34 |
| device-life-cycle | Device life cycle | 16 |
| device-management-essentials | Device management essentials | 19 |
| deviceinformationresponse | DeviceInformationResponse | 24 |
| devicemanagement-declarations | Declarations | 75 |
| enrolling-a-device-in-a-beta-program | Enrolling a device in a beta program | 77 |
| phases-of-software-update-enforcement | Phases of software update enforcement | 44 |
| profile-specific-payload-keys | Profile-specific payload keys | 158 |
| restrictions | Restrictions | 268 |
| softwareupdateenforcementspecific | SoftwareUpdateEnforcementSpecific | 60 |
| softwareupdatesettings | SoftwareUpdateSettings | 76 |
| softwareupdatesettingsautomaticactionsobject | SoftwareUpdateSettingsAutomaticActionsObject | 13 |
| softwareupdatesettingsbetaobject | SoftwareUpdateSettingsBetaObject | 16 |
| softwareupdatesettingsdeferralsobject | SoftwareUpdateSettingsDeferralsObject | 14 |
| softwareupdatesettingsrapidsecurityresponseobject | SoftwareUpdateSettingsRapidSecurityResponseObject | 12 |
| status-items | Status items | 82 |
| statusdeviceoperatingsystembuildversion | StatusDeviceOperatingSystemBuildVersion | 42 |
| statusdeviceoperatingsystemsupplementalbuildversion | StatusDeviceOperatingSystemSupplementalBuildVersion | 44 |
| statusdeviceoperatingsystemsupplementalextraversion | StatusDeviceOperatingSystemSupplementalExtraVersion | 44 |
| statusdeviceoperatingsystemversion | StatusDeviceOperatingSystemVersion | 42 |
| statussoftwareupdatebetaenrollment | StatusSoftwareUpdateBetaEnrollment | 32 |
| statussoftwareupdatedeviceid | StatusSoftwareUpdateDeviceID | 30 |
| statussoftwareupdatefailurereason | StatusSoftwareUpdateFailureReason | 37 |
| statussoftwareupdateinstallreason | StatusSoftwareUpdateInstallReason | 39 |
| statussoftwareupdateinstallstate | StatusSoftwareUpdateInstallState | 33 |
| statussoftwareupdatependingversion | StatusSoftwareUpdatePendingVersion | 37 |

### 28.2 B-support 组 · Apple 支持与安全指南页面

8 件；正文里公告表行号、"无 CVE 条目"计数与机型可得性描述都取自此组，其中 `security-releases.txt`（1121 行）是第 16 章 R1—R4 的唯一来源。

| 存档件（`.srcx9/` 下相对路径） | 文档标题 | 行数 | 取回地址 |
|---|---|---|---|
| `B/pages/bsi-about.txt` | bsi-about | 47 | https://support.apple.com/en-us/102657 |
| `B/pages/bsi-by-date.txt` | bsi-by-date | 47 | https://support.apple.com/en-us/111333 |
| `B/pages/bsi-guide.txt` | bsi-guide | 282 | https://support.apple.com/guide/security/background-security-improvements-sec87fc038c2/web |
| `B/pages/macos-background-updates.txt` | macos-background-updates | 89 | https://support.apple.com/en-us/101591 |
| `B/pages/sec-content-ios272.txt` | sec-content-ios272 | 852 | https://support.apple.com/en-us/149230 |
| `B/pages/secure-software-updates.txt` | secure-software-updates | 272 | https://support.apple.com/guide/security/secure-software-updates-secf683e0b36/web |
| `B/pages/security-releases.txt` | security-releases | 1121 | https://support.apple.com/en-us/100100 |
| `B/pages/update-iphone-ipad.txt` | update-iphone-ipad | 74 | https://support.apple.com/en-us/118575 |

### 28.3 B-csaf 组 · 机器可读公告（CSAF v2.1）与派生件

| 公告编号 | 版本线（由 `fixed` 字段解析） | JSON 字节 | CVE 行数（不含表头） | 组件标签 |
|---|---|---|---|---|
| 149041 | iOS/iPadOS 26.7 | 165642 | 95 | 57 |
| 149227 | iOS/iPadOS 26.7.2 | 234387 | 134 | 54 |
| 149230 | iOS/iPadOS 27.2 | 282615 | 163 | 67 |

三份 JSON 各自派生一份 `B/CSAF/<编号>-cves.tsv`（制表符分隔，表头含 `cve`、`component`、`fixed`、`available_for`、`releaseDate`、`advisoryId`）与一份 `.summary.txt`。三个 `.summary.txt` 的 `releaseDate` 与 `security-releases.txt` 的公告表行日期做过逐条比对（第 4.4 节、第 16 章 R11）。第 22 章脚本二的真实运行就是拿这三份 TSV 当公告件（22.5 节），未做任何改写。

### 28.4 B-guide 组 · Apple Platform Security

`apple-platform-security-guide.pdf`（3029387 字节）与 `apple-platform-security-guide.txt`（697288 字节、4885 行）。正文引用行号一律以 `.txt` 件的物理行为准，该件含页眉、页码与空行残块（第 26 章 G3）。第 6、8、12 章关于更新过程、cryptex 形态与移除语义的引用均出自该件；第 24 章 M1/M8 引用的第 1144、1146 行也在其中。

### 28.5 C 组 · 外部应急口径与派生读数件

| 存档件 | 来源与计算方式 | 用途 |
|---|---|---|
| `C/kev.json` | CISA Known Exploited Vulnerabilities Catalog 原始响应（1826755 字节） | 在野条目全集 |
| `C/kev-apple.tsv` | 由 `.x9-kev.pl` 从 `kev.json` 计算，`vendorProject=Apple` 逐行展开（96 行含表头） | 第 22 章脚本二的在野件；第 16 章 R12/R13 |
| `C/kev-apple.tsv.meta.txt` | 同上，记录条数与筛选口径 | 口径自证 |
| `C/kev-apple-lag.txt` | 由 `.x9-kevlag.pl` 计算窗口分布（`dateAdded` 与 `dueDate` 之差） | 第 16 章 R12；脚本二 K3 主窗口 {14,21} 的实测依据（非标准窗口 10 条：1 条 3 天、9 条 181 天） |
| `C/release-rows.tsv` | 由 `.x9-relreadings.pl` 从 `security-releases.txt` 展开（332 行含表头，即 331 条发布行） | 第 16 章 R1/R2 的分母 |
| `C/release-readings.txt` | 同上，逐条读数汇总 | 第 16 章读数的对照件 |

`kev.json` 与 `release-rows.tsv` 是原始/派生关系而非并列关系：正文凡给出 KEV 条数、窗口分布，一律引 TSV 派生件，不引 JSON 原文。

### 28.6 本轮未取回、因而不得作为引用源的文档

- `StatusSoftwareUpdateFailureReason` 与 `StatusSoftwareUpdateInstallReason` 两个状态项页**已取回**，但它们指向的**字典对象逐字段页**未取回（G1）。凡涉及"失败原因具体有哪几个码"的表述，本文一律写"本轮不可核对"。
- `gdmf.apple.com/v2/pmv` 的实际响应件本轮不取（两个脚本被明令禁止联网，G2）。
- CISA 的单条 KEV 条目详情页、Apple 各版本的独立"安全内容"长页（除 149230 之外的编号）未逐页取回；第 16 章只使用 `security-releases.txt` 与三份 CSAF 件能核对的字段。

凡正文需要提及这些内容，只写"该文档本轮未取回"并给出 G 编号，不转述其条款。

### 28.7 核验脚本、夹具与引用审计工具

- 脚本一：`update-policy-ledger-review.sh`（存档件 `.x9-s1.sh`，201 行，全文见第 21.4 节围栏）
- 脚本二：`advisory-coverage-diff.sh`（存档件 `.x9-s2.sh`，216 行，全文见第 22.4 节围栏）
- 夹具与驱动：`.scratch/x9s1/`（合格台账 `good` 档、坏档 `bad-full`、J2/J1 样例各一份）与 `.scratch/x9s2/`（公告件 6 份、在野件 1 份、资产件 5 行、合格档 3 份，由 `.scratch/x9s2/mk-fixtures.sh` 生成）。逐码触发记录与原始输出固化在 `.scratch/x9s1/*.txt`、`.scratch/x9s2/{bad-run,good-run,real-run}.txt`，验收结论见第 23 章。**全部夹具均为构造数据**，只有 `real-run` 一档吃真实存档件。
- 引用可核验性工具：逐句审计器 `.x9-audit.pl`（存在性 + 同页行号归因两项检查）与行号越界检查器，两者都只读取存档件与正文，不修改任何文件。第 23.5 节的隔离性自证三条（零网络客户端、零设备侧命令、写出目标仅临时目录）由同一组 grep 完成。
- 装配脚本 `.scratch/x9p5/build-p5.sh`：把两个脚本的全文按围栏区间拼进正文，并从真实输出反向生成第 21.3、22.3、23.3、23.4 节的信号码表；装配完成后按围栏区间重抽内嵌脚本与源文件做逐字节 diff，两者 `bash -n` 均通过。

---

咨询ios系统请咨询 telegram：https://t.me/one00190

---
