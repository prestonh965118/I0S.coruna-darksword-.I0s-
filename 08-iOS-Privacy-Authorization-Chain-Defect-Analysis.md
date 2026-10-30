---
title: "iOS 隐私授权链路与用途声明缺陷归属防御分析报告"
description: "iOS 隐私授权链路的十层表面分解：Info.plist 用途声明键、PrivacyInfo.xcprivacy 与 required reason API、系统授权决策与崩溃形态、11 组框架授权状态机取值配对、部分授权与精度裁剪、授权持久化与变更、跨进程继承与传播、SDK 清单与装配、申报与审核口径、可观测与取证面；P1–P12 缺陷类型学、声明/框架状态机/申报三套词表、层 × 责任方 × 更新通道归属矩阵、四级判定模型与两个离线只读核验脚本"
lang: zh-CN
---

# iOS 隐私授权链路与用途声明缺陷归属防御分析报告

## 摘要

iOS 上有一类缺陷，它的产物不是崩溃日志、不是内存转储，而是一份**可以被 diff 的纯文本**：`Info.plist` 里的用途声明键、`PrivacyInfo.xcprivacy` 里的隐私清单、App Store Connect 里勾选的隐私标签。它们的特殊之处和推送链路正相反——**声明这一侧读者完全看得见、可复现、可静态审查，而授权结果那一侧几乎处处不可判定**。系统与文档对"用户拒绝了"和"这个框架本来就没告诉你"经常给同一个读数：HealthKit 明确写着读权限被拒时 app 看不出来（"you can't distinguish between full access and denied access for specific types; both appear the same to your app"，《Authorizing access to health data》第 6 行），Core Location 的 `.denied` 一句话里同时装了"用户拒绝本 app"和"设置里全局关了定位"两种成因（"The user denied the use of location services for the app or they are disabled globally in Settings"，《CLAuthorizationStatus》第 11 行）。

全文按十层拆开这条链路（用途声明、隐私清单、required reason 申报、授权请求与系统决策、框架状态机、部分授权与精度裁剪、授权持久化与状态变更、继承与传播、SDK 清单与构建装配、申报审核与可观测面），给出 P1—P12 的缺陷类型学（按"缺陷在哪一次校验被放过"分型，而不是按键名分型），一张层 × 责任方 × 更新通道 × 可得证据的归属矩阵，以及 Apple 安全公告口径下的 16 条公开读数。核验部分提供两个纯文本、离线、只读的脚本——一个把一份声明产物（`Info.plist` 或 `PrivacyInfo.xcprivacy` 的文本导出件）按 Apple 文档口径审一遍并预演"缺这一格时系统或 App Store Connect 会给什么读数"，一个把一份授权状态台账按 11 组枚举、45 条〈框架,取值〉配对逐格分诊——两者都在本轮做了全量分支覆盖验收，信号码共 66 个（脚本一 38 个、脚本二 28 个），**66 个全部在本轮环境实跑触发**。其中三类分支需要特殊构造：D04 的两个分支要分别喂一个自造键名和一个落在文档 Deprecated keys 分组里的键名；B 类边界声明要靠"声明过剩"（有键无 `USE` 令牌）和"只看单份文本"两种输入才出得来；E01 与 S98 要靠给临时文件施加只读拒绝 ACL（Windows 用 `icacls /deny`，类 Unix 用 `chmod 000`）和把 `TMPDIR` 指到一个不存在的目录——构造与复现见第 23.4 节。覆盖验收同时暴露并修掉了三个真实缺陷：把文档里带 `NSPrivacyAccessedAPICategory` 前缀的 category 取值误当成短名（会漏掉一整类非法取值）、把"非空数组"误判成"键不存在"（会把写全了的清单报成缺键）、以及用"大写点分形式"这种**文档里查不到原句的启发式**去判收集数据类型（已改为按文档取值表做精确成员检查）。三处的修法与口径依据一并写在第 21、23 章。

本文不提供任何可用的漏洞利用代码、提权或绕过步骤、绕过用户授权或伪造授权状态的操作方法，也不提供任何针对具体设备的攻击动作；给出的只有公开文档口径、公告口径、申报口径，以及读者对**自己工程里的声明文本与自己导出的授权台账**能做的只读判定。两个脚本都不联网、不写设备、不修改输入文件、不调用 `plutil` 或 Xcode，也不读取任何真机状态。

---

## 目录

1. [引言](#1-引言)
2. [视角声明与本文边界](#2-视角声明与本文边界)
3. [三套词表：声明口径、框架状态机口径、申报口径](#3-三套词表声明口径框架状态机口径申报口径)
4. [L1 用途声明层](#4-l1-用途声明层)
5. [L2 隐私清单层](#5-l2-隐私清单层)
6. [L3 required reason 申报层](#6-l3-required-reason-申报层)
7. [L4 授权请求与系统决策层](#7-l4-授权请求与系统决策层)
8. [L5 框架状态机层](#8-l5-框架状态机层)
9. [L6 部分授权与精度裁剪层](#9-l6-部分授权与精度裁剪层)
10. [L7 授权持久化与状态变更层](#10-l7-授权持久化与状态变更层)
11. [L8 继承与传播层](#11-l8-继承与传播层)
12. [L9 SDK 清单与构建装配层](#12-l9-sdk-清单与构建装配层)
13. [L10 申报、审核与可观测面](#13-l10-申报审核与可观测面)
14. [缺陷类型学 P1—P12](#14-缺陷类型学-p1p12)
15. [归属矩阵：层 × 责任方 × 更新通道 × 证据](#15-归属矩阵层--责任方--更新通道--证据)
16. [公开案例读数：安全公告能证明这条链路的什么](#16-公开案例读数安全公告能证明这条链路的什么)
17. [可见性边界：这条链路上读者能拿到什么](#17-可见性边界这条链路上读者能拿到什么)
18. [崩溃与日志读数侧](#18-崩溃与日志读数侧)
19. [四级判定模型](#19-四级判定模型)
20. [运营指标 O1—O10](#20-运营指标-o1o10)
21. [只读核验脚本一：声明口径审查器](#21-只读核验脚本一声明口径审查器)
22. [只读核验脚本二：授权台账分诊器](#22-只读核验脚本二授权台账分诊器)
23. [两个脚本的全量分支覆盖验收](#23-两个脚本的全量分支覆盖验收)
24. [十二个误区](#24-十二个误区)
25. [常见问题](#25-常见问题)
26. [未公开文档化边界清单](#26-未公开文档化边界清单)
27. [结论](#27-结论)
28. [参考资料](#28-参考资料)

---

## 1. 引言

### 1.1 为什么把隐私授权链路单独立一篇

iOS 的隐私机制在公开讨论里有三种讲法：开发者文档把它讲成**配置说明**（哪个键必填、哪句文案要写清楚），媒体把它讲成**产品承诺**（"你的数据在你手上"），安全研究把它讲成**权限绕过**（怎么让 app 拿到不该拿的数据）。三种讲法都绕开了中间那一大块——**一条授权从"app 声明我要什么"走到"系统给用户弹什么、app 最后读到什么、申报里写了什么"的路上，一共有十格校验，而这十格里只有少数几格错误会被系统明确告知，其余都表现为"读数本来就长这样"**。

错位在读数上最直接：

- 文档口径给的是**规则**：69 个受保护资源键名、5 类 required reason API 与 17 个 reason code、35 个收集数据类型与 6 个收集理由、4 个清单顶层键。
- 框架口径给的是**状态**：11 组枚举、45 个〈框架,取值〉配对，其中若干组明确写成"这个取值区分不了两种情况"。
- 申报口径给的是**产物**：Xcode 生成的 privacy report、App Store Connect 的隐私标签、SDK 清单与签名，以及"没申报就不收"的服务端规则。

三份东西对不上，就会产生两种都有害的结论：一种是"隐私这一层没问题，缺键会崩溃、崩溃就是信号"（文档对缺键的后果分四档，其中两档既不崩溃也不报错，见第 4.3 节）；另一种是"清单里没写就是没收集"（文档明确写着 app 的清单不覆盖 SDK 的数据收集，而 SDK 也不能依赖宿主 app 替它申报，《Describing use of required reason API》第 7 行）。本文的目标是把这两种结论都换成**可核对的层归属**。

### 1.2 这条链路的规模感

有四个可以直接从本轮存档里数出来的规模数字，构成本文"这张表有多大"的直觉：

1. **声明侧的键表**。Apple 在《Protected resources》一页按分组列出了 69 个受保护资源键名（第 10—117 行），其中 3 个单独落在 Deprecated keys 分组（第 114—117 行）；该页 Overview 段的口径原句是 "The topics below list the keys you use to provide usage-description strings for protected resources"（第 6 行）。这句话在本文里地位很高：它是**唯一一个可核对的闭合键名清单**，本文对"自造键名"的判定只建立在它之上。
2. **清单侧的取值表**。`PrivacyInfo.xcprivacy` 的顶层键只有 4 个（《Privacy manifest files》第 21—24 行），required reason 的 category 取值 5 个、reason code 17 个（《NSPrivacyAccessedAPIType》第 6、25、32、51、56 行的 VALUE 行与其下的小节），收集数据类型 35 个（《NSPrivacyCollectedDataType》第 6—40 行）、收集理由 6 个（《NSPrivacyCollectedDataTypePurposes》第 6—11 行）。
3. **状态机侧的枚举**。本轮取回 11 组授权枚举页：Core Location 的 `CLAuthorizationStatus` 与正交的第二轴 `CLAccuracyAuthorization`、AVFoundation、PhotoKit、Contacts、CoreBluetooth、HealthKit、Speech、App Tracking Transparency（含 `ATTrackingManager.AuthorizationStatus` 与已废弃的 `trackingAuthorizationStatus` 两套）、UserNotifications 的 `UNAuthorizationStatus` 与第三种词表 `UNNotificationSetting`。合计 45 条〈框架,取值〉配对。
4. **公告侧的读数**。本轮从 Apple Security Releases 的 13 份发布文档里筛出 79 条与隐私/授权直接相关的条目，本文第 16 章按十层归位其中 16 条，逐条带存档行号（表格 12 条 + 同类日志脱敏 4 条）。

第 3 章说明这三张表为什么不能互相换算；第 14 章给出跨越它们的类型学；第 21—23 章给出读者可以立刻执行的只读核验。

### 1.3 本文的三个问题

1. **分型问题**：一条授权相关的缺陷发生在哪一次校验——是声明文本压根没写、是写了但键名对不上文档、是清单里申报值越界、是系统决策被"不可判定"的枚举读数掩盖、是部分授权被当成全量授权、是变更通知没被接住、还是清单根本没进被装配的那个产物？（第 14 章 P1—P12）
2. **归属问题**：这一格的修改权在谁手里——Apple 的系统实现、Apple 的审核服务端规则、Xcode 的清单生成与校验、SDK 作者的清单、app 自己的声明文本，还是 app 里那段"读了状态却只分两档处理"的代码？修完之后落在哪条更新通道上（系统版本 / Xcode 版本 / App Store Connect 服务端 / 随 app 二进制提交的清单文件）？（第 15 章矩阵）
3. **自证问题**：读者手上只有公开文档、自己的工程文件和自己导出的授权台账时，能做哪几种可复现的只读判定？（第 17—18、21—23 章）

### 1.4 阅读顺序建议

只关心"我这个键到底要不要写、不写会怎样"的读者，直接看第 4 章和第 21 章脚本；关心"清单申报为什么被拒"的看第 5、6、13 章；关心"app 读到的授权状态为什么不可信"的看第 8、9、10 章；关心"这个缺陷该谁修"的看第 14—16 章；关心"我怎么在不碰设备的前提下自证"的看第 17、19、22、23 章。第 2 章的边界声明要先读一次，它规定了本文与本报告集其他篇目之间的重叠怎么处理，也规定了本文的英文引语按什么口径转录与复核。

---

## 2. 视角声明与本文边界

本文是"归属与口径"视角的隐私授权链路分析，不是隐私合规教程，不是权限绕过手法汇编，也不是 App Store 审核应对指南。与本报告集里已有的篇目关系如下：

| 主题 | 本文覆盖 | 去处 |
| --- | --- | --- |
| iMessage 攻击入口（第 01 篇） | 不覆盖。本文不讨论任何消息链路 | 第 01 篇讲消息链路的攻击面 |
| 访问控制与应用交互（第 02 篇） | 只取"授权状态如何被 app 读到"这一格，第 8、11 章各一节；不重述 TCC 数据库、权限模型全貌与跨应用交互 | 第 02 篇讲权限模型与跨应用交互限制 |
| 应用防护与抓包审计（第 03 篇） | 不覆盖。本文不讨论如何抓取或查看任何流量；第 5.4 节提到追踪域名网络请求失败时只引用文档口径 | 第 03 篇讲应用侧防护与自有流量的审计口径 |
| 身份认证与通道加密（第 04 篇） | 只在第 4.4 节把 Face ID 用途键当作"声明—框架"交界的一个样本 | 第 04 篇讲认证链路全景 |
| 生物识别安全机制（第 05 篇） | 不重述生物识别机制，只处理 `NSFaceIDUsageDescription` 缺失这一声明格 | 第 05 篇讲生物识别机制与取证口径 |
| XPC 与 Mach IPC（第 06 篇） | 不覆盖进程间通道。第 11.3 节的容器扩展与第 18 章的崩溃读数与第 06 篇互补：那篇分 IPC 层，本篇分声明层 | 第 06 篇讲端口、名称空间、MIG 与 XPC 对象层 |
| APNs 推送投递链路（第 07 篇） | 只在第 8.5 节把通知授权当作 11 组枚举中的一组；不重述投递、扩展预算与响应台账 | 第 07 篇讲十层推送校验与两套 reason 词表 |
| 越狱与锁定模式 | 只在第 17 章影响"读数可得性"时出现 | 越狱篇、锁定模式篇 |
| 内存损坏 / 沙箱逃逸 / 内核提权 | 不覆盖。本文第 16 章的公告读数只到"组件与影响"这一层，不推断利用原语，也不给出任何绕过授权的步骤 | 内存损坏篇、沙箱逃逸篇 |

一句话：**其他几篇讲的是边界两侧的东西，本文讲这条授权链路上的十格校验、以及声明口径与状态机口径、申报口径之间的落差**。同一件事（例如"扩展共享容器 app 的隐私控制"）如果在别的篇目里已经讲过，本文只做一句话引用并给出行号，不重述。

**范围声明**：全文只讨论公开文档化的机制、Apple 安全公告的公开条目、以及在这些公开规则之上可以安全实施的只读判定。本文不提供：可用的漏洞利用代码；读写系统授权数据库、伪造或篡改授权状态、清除或重置用户授权记录的操作方法；针对特定设备的探测、提权或权限绕过步骤；绕过 App Tracking Transparency 提示、规避隐私清单校验或伪造签名的做法；对 App Store Connect 或审核流程的规避策略。第 21、22 章两个脚本都是离线文本处理：一个读一份"声明产物"文本（`Info.plist` 或 `PrivacyInfo.xcprivacy` 的文本导出件），一个读一份"授权台账"文本（每行一条〈框架,取值,主体〉记录），两者都不写设备、不联网、不修改输入文件、不调用 `plutil`、Xcode 或任何网络接口，中间文件只落在系统临时目录并在退出前删除。所有"核验"指读者对**自己工程里的文本、自己导出的清单与台账、或公开样本**执行采集与比对。

**引用转录约定**：英文原文按原样转录，只做两项字符归一——排版撇号（’）写作 ASCII 撇号（'），排版引号（“ ”）写作直引号（"）；其余字符、大小写不改。复核时还要允许下面六种**排版层差异**，它们不是转录差异：

1. **空白折叠**。存档页面会折行，词与词之间可能隔一个换行或一串空格；检索时把引语里的空格当作"至少一个空白字符"。
2. **文档页是 JSON 扁平件**。Apple 开发者文档的取回形态是一行一个内容项的扁平文本，表格行被拍平成 `键 | 值类型 | 说明` 一行（形如 `VALUE NSPrivacyAccessedAPICategoryFileTimestamp: The following APIs…`），段内换行会造出"半句话"。本文引的表格行按整行引用，不做拼接。
3. **链接标签缺口**。扁平正文里页面内超链接只留下 `doc://…` 形式的目标标识，**标签文本在该页的 `--- REFERENCES ---` 表里**。遇到这种情况，本文要么按 references 表回填标签并注明，要么只引到可核对的前半句。第 5.5 节引《Privacy manifest files》第 9 行提到的 "SDKs that require a privacy manifest and signature" 即属此情形：该页面对本机而言是 JS 渲染壳、取不回正文（见第 26 章缺口清单），本文只引扁平件里可核对的句子本身。
4. **破折号**。原文里的双连字符 `--` 在页面上渲染为破折号，本文按渲染形态（—）转录。
5. **省略号**。`…` 与 `...` 都代表原文中被删去的一整段（可能是插入语或链接残段），长度不固定，复核时按不定长空洞匹配。
6. **反引号**。引语内出现的反引号是本文的 markdown 代码标记（为了让 `NSPrivacyTracking` 这类字面量不被当成标签吞掉），不属于原文字符；反引号里的内容本身仍照原样、原大小写抄写。

三类已知的存档缺口**就地注明、不做修补式改写**：

- **缺口 A（枚举取值以代码片段下发）**：枚举页的声明段在扁平件里形如 `DECL swift: enum CLAuthorizationStatus`，其 case 列表由随后的 `- 名称 — 说明` 行给出；本文引用取值语义时引的是这些内容行，不转写 Swift 代码本体。
- **缺口 B（值列表页与标题页分离）**：`NSPrivacyCollectedDataTypes`（复数）一页只说明"这是一个字典数组"，真正的取值闭合列表在 `NSPrivacyCollectedDataType`（单数）页；本文凡是数"35 个类型"的地方，都指单数页第 6—40 行的 VALUE 行，不指复数页。
- **缺口 C（申报侧页面不可得）**：App Store 的「App Privacy Details / user privacy and data use」、审核指南、以及「Upcoming third-party SDK requirements」三组页面对本机取回的是 JS 壳或 404，正文不可核对。因此第 13 章的申报口径**只引用开发者文档里可核对的句子**（尤其是《Describing use of required reason API》第 6 行的服务端规则句），不引用这些页面，也不转述其中的条款编号。

最后，原文本身的拼写与格式异常一律保留原样并加注，本文不做"顺手修正"：《Protected resources》第 51 行的小节条目前缀里出现了双空格（`Choosing the  Location Services Authorization to Request`）；《NSPrivacyAccessedAPIType》在第 20 行与第 28 行对同一件事写了两种措辞（`supply the relevant values from this list` 与 `supply the relevant values from the list below`）。两处都不是本文的转录差异。

---

## 3. 三套词表：声明口径、框架状态机口径、申报口径

本文说的"三套口径"，对应这条链路上三种**互不通约的公开产物**。第一套写在 app 提交的文本里，第二套写在框架 API 的返回值里，第三套写在 Apple 服务端与 Xcode 生成的产物里。三者都叫"隐私"，但没有一个字段能把它们换算过去。

### 3.1 声明口径：文本里能写出什么

声明口径是**键名 + 取值 + 容器结构**的一张闭合表，本轮可核对的规模如下（括号内是给出该闭合性的存档行号）：

| 集合 | 规模 | 出处 |
| --- | --- | --- |
| 受保护资源键名 | 69 个，其中 3 个在 Deprecated keys 分组 | 《Protected resources》第 10—117 行；Overview 句在同页第 6 行 |
| 隐私清单顶层键 | 4 个（`NSPrivacyTracking`、`NSPrivacyTrackingDomains`、`NSPrivacyCollectedDataTypes`、`NSPrivacyAccessedAPITypes`） | 《Privacy manifest files》第 21—24 行；同一组在第 8—14 行按三个小节再次列出 |
| required reason category | 5 个，取值一律带 `NSPrivacyAccessedAPICategory` 前缀 | 《NSPrivacyAccessedAPIType》第 6、25、32、51、56 行的 VALUE 行 |
| reason code | 17 个，每个只属于一个 category | 同页各 category 小节下的短码行（如第 21—24 行的 `DDA9.1`、`C617.1`、`3B52.1`、`0A2A.1`） |
| 收集数据类型 | 35 个 | 《NSPrivacyCollectedDataType》第 6—40 行的 VALUE 行 |
| 收集理由 | 6 个 | 《NSPrivacyCollectedDataTypePurposes》第 6—11 行的 VALUE 行 |

这套词表有三个特点决定了它在缺陷讨论里的位置：

1. **它是"写出来才算"。** 一个用途声明只有躺在 `Info.plist` 里、键名与文档完全一致，才对系统存在。文档从不给"近似键名"任何兼容读数；《NSBluetoothPeripheralUsageDescription》第 8 行甚至把版本分档写成了句子："Devices running earlier versions of iOS rely on NSBluetoothPeripheralUsageDescription, while devices running later versions rely on NSBluetoothAlwaysUsageDescription"。
2. **它的必配条件是**按框架/类名写的条件句**，不是一张必填表。** 本轮取回 29 个用途声明键页（28 个键名以 `UsageDescription` 结尾，加 1 个 `NSLocationTemporaryUsageDescriptionDictionary`），其中 23 页出现 "required" 字样、且形态是 "This key is required if your app uses APIs that access the device's camera"（《NSCameraUsageDescription》第 9 行）这类条件句。判断"必填"需要知道 app 用了哪些 API，而这一步**在任何静态文本里都不可得**——本文脚本用 `USE <令牌>` 行把这件事显式交给读者（第 21.2 节）。剩下 6 页各写各的句式，第 4.3 节逐条列出。
3. **它对"没写会怎样"给了四种不同的口径，不是两种。** 详见第 3.4 节。

### 3.2 框架状态机口径：API 返回值里有什么

第二套词表是 11 组枚举。它的组织单位不是"键"而是"〈框架,取值〉"，本轮整表 45 条：

| 组 | 取值 | 存档 |
| --- | --- | --- |
| `CLAuthorizationStatus` | notDetermined / restricted / denied / authorizedAlways / authorizedWhenInUse，另有一条不带类型前缀的 `authorized` 条目（同页第 12 行，见第 8.2 节） | 《CLAuthorizationStatus》第 9—14 行 |
| `CLAccuracyAuthorization`（第二轴） | fullAccuracy / reducedAccuracy | 《CLAccuracyAuthorization》第 6—7 行 |
| `AVAuthorizationStatus` | notDetermined / restricted / denied / authorized | 《AVAuthorizationStatus》第 9—12 行 |
| `PHAuthorizationStatus` | notDetermined / restricted / denied / authorized / limited | 《PHAuthorizationStatus》第 8—12 行 |
| `CNAuthorizationStatus` | notDetermined / restricted / denied / authorized / limited | 《CNAuthorizationStatus》第 6—10 行 |
| `CBManagerAuthorization` | notDetermined / restricted / denied / allowedAlways | 《CBManagerAuthorization》第 6—9 行 |
| `HKAuthorizationStatus` | notDetermined / sharingDenied / sharingAuthorized（该页只列这三个，且明说它描述的是 save 侧："This status indicates whether the user has authorized your app to save data of the given type"，同页第 7 行） | 《HKAuthorizationStatus》第 10—12 行 |
| `SFSpeechRecognizerAuthorizationStatus` | notDetermined / denied / restricted / authorized | 《SFSpeechRecognizerAuthorizationStatus》 |
| `ATTrackingManager.AuthorizationStatus` | authorized / denied / notDetermined / restricted | 《ATTrackingManager.AuthorizationStatus》第 9—12 行 |
| `trackingAuthorizationStatus`（已废弃的属性，返回同一类型） | 同上四值，另有一条"未弹窗也返回 restricted"的口径 | 《trackingAuthorizationStatus》第 11 行 |
| `UNAuthorizationStatus` | notDetermined / denied / authorized / provisional / ephemeral | 《UNAuthorizationStatus》第 6—10 行 |
| `UNAuthorizationOptions`（非状态，是请求侧位集） | badge / sound / alert / carPlay / criticalAlert / providesAppNotificationSettings / provisional，另见 announcement 与 timeSensitive | 《UNAuthorizationOptions》第 6—17 行 |
| `UNNotificationSetting`（第三形态） | notSupported / disabled / enabled | 《UNNotificationSetting》第 6—8 行 |

上表按"组"列了 13 行，其中 11 行进入脚本二的枚举词表（`UNAuthorizationOptions` 是请求侧位集、不是状态读数，`trackingAuthorizationStatus` 与 `ATTrackingManager.AuthorizationStatus` 共用同一取值集合，脚本里合并成一帧）。落进词表的是 11 组、45 条〈框架,取值〉配对。

这套词表与第一套的关系是**单向的**：声明口径里的键名决定了系统能不能弹提示，状态机口径里的取值决定 app 事后能读到什么；但**状态机里没有任何取值能回指"哪个键写了、哪句文案说了什么"**。这就是第 8 章全部讨论的前提。

### 3.3 申报口径：服务端与产物里有什么

第三套词表最容易被忽略，因为它不在 app 的二进制里，而在**提交过程的产物**里：

- Xcode 的 privacy report：由 app 与所链接 SDK 的清单聚合而来（《Describing data use in privacy manifests》第 15 行 "Xcode can create a privacy report by aggregating the privacy manifests from your app and the third-party SDKs it links to"），生成路径是 Archive 之后在 organizer 里右键 "Generate Privacy Report"（同页第 17—18 行）。
- 该产物的结构对齐口径："The privacy report is organized in a similar way to Privacy Nutrition Labels"，并且要 "Refer to this report when you provide your app's privacy details in App Store Connect"（同页第 22 行）。
- 自造取值的后果是**产物静默失真**，不是提交报错："Xcode won't generate a privacy report correctly if you define your own collected data types for the NSPrivacyCollectedDataType key, or provide your own reasons for the NSPrivacyCollectedDataTypePurposes key"（同页第 13 行）。
- required reason 未申报的后果是**服务端规则**："Starting May 1, 2024, apps that don't describe their use of required reason API in their privacy manifest file aren't accepted by App Store Connect"（《Describing use of required reason API》第 6 行）。
- 清单合法性同样由服务端裁决："All privacy manifest files in your app must be valid, containing only the expected keys and values"，以及 "App Store Connect rejects app submissions that include invalid privacy manifest files"（《Adding a privacy manifest to your app or third-party SDK》第 5、6 行）。

三套词表之间的换算关系是本文后面所有章节的公共前提：**声明口径给出"app 声明了什么"，状态机口径给出"app 事后读到什么"，申报口径给出"Apple 与工具链看见什么"。知道任意一套，都不能唯一推出另外两套。** 第 14 章的类型学按"缺陷在哪一次校验被放过"重新分型，就是为了给这三者一个公共锚点；第 15 章的矩阵把锚点换成责任归属。

### 3.4 一条换算失败的实例：缺键后果的四档口径

最容易出现的误解是"缺用途键会崩溃"。把本轮存档里所有直接写到后果的句子排在一起，实际是**四档**：

| 档 | 文档原句 | 键 |
| --- | --- | --- |
| crash | "Attempting to access the Photos library without a valid usage description causes your app to crash"（《Delivering an Enhanced Privacy Experience in Your Photos App》第 12 行） | 相册 |
| crash | "If you don't include this key, your app will crash when it attempts to access motion data"（《NSMotionUsageDescription》第 7 行） | 运动与 Fitness 部分键 |
| crash | "If this key isn't present, your app crashes when it calls requestAuthorization(_:)"（《NSSpeechRecognitionUsageDescription》第 7 行） | 语音识别 |
| crash | "Your app crashes if it attempts to use the App Tracking Transparency framework without including the key in your target's properties in Xcode"（《NSUserTrackingUsageDescription》第 8 行） | 追踪 |
| crash | "Apps must include usage descriptions, or it will crash when you request authorization to access HealthKit data"（《Protecting user privacy》第 7 行） | HealthKit 读写两键 |
| fail 但不崩溃 | "Authorization requests fail immediately if the required keys aren't present"（《Requesting authorization to use location services》第 32 行） | 定位三键 |
| req，无运行时读数 | "This key is required if your app uses APIs that access the user's contacts"（《NSContactsUsageDescription》第 7 行）以及同形态句 | 通讯录、日历、提醒、蓝牙、HomeKit、Siri、Face ID、媒体库、健康临床记录等 |
| should，建议级 | "Any app that uses the local network, directly or indirectly, should include this description"（《NSLocalNetworkUsageDescription》第 7 行） | 本地网络 |

档位差本身就是一个缺陷类：**同一份代码在四档里的故障表现完全不同，而"req 档"的键缺了不会有任何运行时信号**——它只在审核或用户投诉之后才暴露。本文第 19 章的四级判定模型和第 21 章脚本的 `MODE` 列就是为这个落差准备的。

### 3.5 声明过剩：文档不给读数的方向

四档口径只覆盖"用了没写"。反方向（写了但没用）在本轮存档里**找不到任何后果句**：文档从未说明系统或 App Store Connect 会怎么处理一个多余的用途键。因此本文把它列为口径边界而不是缺陷类型，脚本对它只出边界声明 B02、不判级（第 21.4 节）。这条取舍在第 26 章的边界清单里有对应条目。

---

## 4. L1 用途声明层

### 4.1 这一层负责什么

L1 只管一件事：**让系统在被授权弹窗时手里有一段可以展示给用户的文案**。文档对这格的说法非常具体——《NSAppleMusicUsageDescription》第 7 行："Set the value of this key to a user-readable description of how your app intends to use a person's media library. The first time your app attempts to access their library, the system prompts the user to grant or deny access to your app. The system includes this key's description in the dialog it displays to the user."

三层含义都在里面：值要"读得懂"、文案只在**第一次**访问时出现、系统是原样搬运而不是改写。所以 L1 的缺陷只可能有三种：**没写**、**写了读不出信息**、**写了但键名/位置不对导致系统读不到**。第三种最隐蔽，因为文本 diff 里它和第一种不同、和第二种更像。

### 4.2 键名闭合表与"近似键名"

本文对键名合法性的判据只有一条：《Protected resources》分组清单，取回件的第 10 到 117 行。

该页 Overview 段交代了这张表的用途："Xcode adds the string as the value for the relevant Information Property List key in your app's build settings"（《Protected resources》第 6 行）。

把这张表和 28 个以 `UsageDescription` 结尾的单独键页（再加 1 个字典页）对照，会得到三类值得单列的形态：

1. **Deprecated keys 分组**（同页第 114—117 行）：`NSCalendarsUsageDescription`、`NSEnterpriseMCAMUsageDescription`、`NSRemindersUsageDescription`。这一组仍然被文档列出并给说明串，且各自的键页里保留着"required"句式（"This key is required if your app uses APIs that access the person's calendar data"，《NSCalendarsUsageDescription》第 7 行）。也就是说：**它们"已弃用"与"仍必填"同时成立**，而两件事都不影响系统读数。本文脚本对它们出一条低阶信号（D04 的第二个分支，第 21.4 节），既不判违规也不算合规。
2. **不是用途串的邻居键**：同一页里还列着 `NSLocationTemporaryUsageDescriptionDictionary`（第 55 行）、`NSLocationDefaultAccuracyReduced`（第 57 行）、`NSUpdateSecurityPolicy`（第 79 行）、`ITSAppUsesNonExemptEncryption`（第 87 行）、`ITSEncryptionExportComplianceCode`（第 88 行）、`NSSensorKitUsageDetail` 与 `NSSensorKitPrivacyPolicyURL`（第 90—91 行）、`UIRequiresPersistentWiFi`（第 112 行）、`NSWidgetWantsLocation`（第 57 行附近）、`NSAppleScriptEnabled`（第 77 行）、`NSHealthRequiredReadAuthorizationTypeIdentifiers`（第 45 行附近）。它们合法但承载的不是给用户读的文案，所以本文不用"取值是否为可读句子"去要求它们，只按类型核对（第 4.5 节）。
3. **只在单独键页或只在分组页出现的差集**：`NSUserTrackingMarkdownUsageDescription` 在两处都有（分组页第 85 行、单独键页整页）；而若干 `SEEALSO` 里出现的键（如 `NSAudioCaptureUsageDescription`、`NSMainCameraUsageDescription`、`NSNearbyInteractionUsageDescription`）同样在分组页有正式条目，因此本文**没有**"只见于交叉引用、无法判定合法性"的键。这一点是本轮补取《Protected resources》之后才成立的——在此之前，本文只能声称"本轮取回的 29 个键页"，无法声称闭合。

第 3 条那个"本轮才成立"的转折本身就是方法论结论，本文把它写进第 23 章的验收叙事，不当作理所当然。

### 4.3 缺键的四种后果与它们的静态判据

先说句式分布，因为"必配条件到底怎么写的"直接决定静态判据的强度。本轮 29 个用途声明键页里，23 页使用 `This key is required if …` 或其单复数变体；余下 6 页各写一种不同句式：

| 键页 | 句式 | 行 |
| --- | --- | --- |
| `NSAppleMusicUsageDescription` | "Your app must provide a value for this key to access a person's media library." | 第 8 行 |
| `NSFallDetectionUsageDescription` | "If your app uses the CMFallDetectionManager, the app requires this key." | 第 7 行 |
| `NSSpeechRecognitionUsageDescription` | "Include this key if your app uses the Speech framework." | 第 7 行 |
| `NSLocalNetworkUsageDescription` | "Any app that uses the local network, directly or indirectly, should include this description." | 第 7 行 |
| `NSUserTrackingMarkdownUsageDescription` | 明确写成可选："This key is optional. The system uses the NSUserTrackingUsageDescription if your app's target properties omit this key." | 第 9 行 |
| `NSLocationTemporaryUsageDescriptionDictionary` | "Use this key if your app needs temporary access to full accuracy location information." | 第 7 行 |

这六种句式，连同前述 23 页的标准形态，在静态审查里其实是**三种强度**：must/required 型（可判级 1）、include/should 型（最多判级 3）、explicitly optional 型（不得判违规）。脚本一的 `DECL_MAP` 第四列就是这个三值强度加上运行时后果的组合。

第 3.4 节的四档在静态文本上对应四种不同的判据强度：

- **crash 档**可以给出高置信判定：只要声明文本里没有对应键，且读者标注了 `USE` 令牌，L1 就是一次可复现的启动即崩溃风险。文档句子都在上面表格里，逐字可查。
- **fail 档**只在定位这条支线上成立，且原句给的是**请求失败**而非崩溃（《Requesting authorization to use location services》第 32 行）。它的实际故障表现是"点了按钮什么也没发生 + 委托回调里状态没变"，与"用户拒绝"在现象层几乎一致——这是第 14 章 P3 型的来源。
- **req 档**没有运行时读数，静态判据因此只能停在"按文档必配"这一层，判定上限是级 1（缺陷成立、但设备侧无信号）。本文对 req 档的处置是**报口径、不报后果**。
- **should 档**（本地网络）连必配句都是建议语气，本文把它降为级 3（需人工确认）。值得注意的是同一页的第 7 行把覆盖范围写得很宽："This includes apps that use Bonjour and services implemented with Bonjour, as well as direct unicast or multicast connections to local hosts"——**"间接使用"也在范围内**，而间接使用恰恰是静态文本最难发现的那类调用。

### 4.4 声明文本本身的质量格

L1 还有一格与"是否可读"有关，文档只在个别键页写成硬要求。有两类可静态判定的形态：

- **空串**。`<key>NSCameraUsageDescription</key><string></string>` 在结构上是"有键"，在语义上是"没有说明"。文档要求的是 user-readable description（《NSAppleMusicUsageDescription》第 7 行），空串既过不了"给人读"的口径，也不会让系统拒绝弹窗——弹窗照样出现，只是说明部分是空的。脚本把这一格判为级 1（D02）。
- **过短且无空格**。这是本文唯一一处**没有文档原句支撑、只能按可读性口径给低级信号**的判定，因此固定为级 3（D03），并在报错文案里明说"文档未给出长度或词数阈值"。把它写成级 1 就是伪造口径。

另有一条文档明确要求、但静态可核对的反例：追踪文案要短并且不必重复 app 名——"Keep the text of your description short and specific. The system displays your app name in the prompt, so you don't need to include it in the string"（《NSUserTrackingUsageDescription》第 13 行）。同一页第 12 行还给出欧盟区的富文本替代形态（`NSUserTrackingMarkdownUsageDescription`），这意味着**同一份 app 可能有两条追踪文案**，而两条的一致性不在任何校验范围内（第 26 章）。

### 4.5 布尔键与字典键：三格类型口径

L1 里混着三个"看起来像用途键、其实是配置"的键，它们的类型口径都能取到原句：

- `NSLocationDefaultAccuracyReduced`：布尔，且**缺键等于 false**——"If you don't include that key in your Info.plist, that's equivalent to setting it to false"（《NSLocationDefaultAccuracyReduced》第 8 行）。这是整条链路上最典型的"沉默默认"：不写不是错，但不写的读数与写 false 一致，而用户在设置里看到的"Precise Location"开关状态又由它决定（同页第 13 行）。
- `NSWidgetWantsLocation`：布尔值，说明句是 "A Boolean value that indicates a widget uses the user's location information"（《Protected resources》第 58 行）。
- `NSLocationTemporaryUsageDescriptionDictionary`：字典，值是一组按自定义键索引的文案（"Provide a dictionary of messages that address different use cases, keyed by strings that you define"，《NSLocationTemporaryUsageDescriptionDictionary》第 7 行），运行时靠 `requestTemporaryFullAccuracyAuthorization(withPurposeKey:)` 选其中一条（同页第 9 行）。**空字典在这一格里是有效的声明结构 + 无效的声明内容**：静态上没有任何一个 purpose key 可被索引，本文脚本把它判为级 3（D15）而不是级 1，因为文档没写空字典的后果。

### 4.6 平台分档：同一句"required"指向不同的 app 形态

L1 的必配句里高频出现平台限定词，构成本文"层 × 责任方"矩阵里第一个非平凡的归属：

- `NSLocationUsageDescription` 只用于 macOS："Use this key in a macOS app that accesses the user's location information. In an iOS app, use NSLocationWhenInUseUsageDescription or NSLocationAlwaysAndWhenInUseUsageDescription instead."（《NSLocationUsageDescription》第 7 行）
- 反向也一样：iOS 侧的 When-in-Use 键在 macOS 上应改用 `NSLocationUsageDescription`（《NSLocationWhenInUseUsageDescription》第 8 行）。
- 蓝牙两键按 deployment target 分档（《NSBluetoothPeripheralUsageDescription》第 7—8 行；《NSBluetoothAlwaysUsageDescription》第 8 行）。
- 定位旧键按 iOS 11 分档，并且要求"两个键都写、消息相同"："add both this key and NSLocationAlwaysAndWhenInUseUsageDescription to your app's Info.plist file with the same message"（《NSLocationAlwaysUsageDescription》第 7 行）。

这组分档说明：**L1 的正确性不是文本属性，而是文本与构建配置（deployment target、平台、SDK 版本）的联合属性**。本轮存档里唯一一处把 SDK 版本写进必配条件的句子是媒体库："This requirement applies to iOS, iPadOS, visionOS, and macOS apps that link against the macOS 15 SDK or later"（《NSAppleMusicUsageDescription》第 8 行）。静态审查器拿不到构建配置，所以本文脚本对"平台/版本分档"一律只出边界声明（B 类），不判违规——这是第 23 章覆盖验收里 B 类信号存在的原因。

---

## 5. L2 隐私清单层

### 5.1 这一格装什么

`PrivacyInfo.xcprivacy` 是 L2 的载体，文档对它的定位是"一份记录两类信息的 property list"："Apps and third-party SDKs — distributed as XCFrameworks, Swift packages, or Xcode projects — can contain a privacy manifest file, named PrivacyInfo.xcprivacy. The privacy manifest is a property list that records the following information"（《Privacy manifest files》第 5 行），随后第 6—7 行分别给出两类信息及其平台适用范围：收集的数据类型"on all platforms"，required reason API"on iOS, iPadOS, tvOS, visionOS, and watchOS"。**这两行的适用范围不一样**，是本文第 14 章 P5 型（跨平台适用范围错配）的直接来源。

四个顶层键的定义集中在《Privacy manifest files》里，取回件的第 20 到 24 行。`App Privacy Configuration` 一页按三个小节把它们再组织一次；单个键页给出的是同一规则的另一种写法，例如《NSPrivacyTracking》第 8 行的 "Set the value for this key to true if your app or third-party SDK uses data for tracking as defined under the App Tracking Transparency framework. When set to true you need to provide a list of internet domains in NSPrivacyTrackingDomains"。文件名本身是硬要求："By default, the file is named PrivacyInfo.xcprivacy; this is the required file name for bundled privacy manifests"（《Privacy manifest files》第 18 行）。

### 5.2 追踪声明的内部一致性

`NSPrivacyTracking` 与 `NSPrivacyTrackingDomains` 之间是 L2 里唯一**在文档内自洽地互相要求**的一对：

- 正向："When set to true you need to provide a list of internet domains in NSPrivacyTrackingDomains"（《Privacy manifest files》第 21 行）。
- 反向："To provide a list of internet domains in NSPrivacyTrackingDomains, set NSPrivacyTracking to true"（同页第 22 行）。
- 且 domains 一侧有运行时后果："If the user has not granted tracking permission through the App Tracking Transparency framework, network requests to these domains fail and your app receives an error"（同页第 22 行）。

这一对给出 L2 的两个可静态判定的缺陷（脚本 D08 的两个分支）：true 无域名、有域名但非 true。第二个分支尤其值得单独讲：** domains 非空而 tracking 为 false 时，文档的读数口径不是"清单不生效"，而是"请求照做"**——它只在 ATT 未授权时才失败。把这两条混成一条"tracking 配置错误"会丢掉了完全不同的故障表现。

另外 `NSPrivacyTracking` 的类型是布尔（"A Boolean that indicates whether your app or third-party SDK uses data for tracking"，《Privacy manifest files》第 21 行；同页另一形态见《App Privacy Configuration》第 13 行的 "A Boolean value that indicates…"），写成字符串在结构上合法、在聚合上必然失真，脚本按 D13 级 1 处理。

### 5.3 收集数据声明的四键结构

每种收集的数据用一个字典描述，四个键的定义与类型在《Describing data use in privacy manifests》第 9—12 行：`NSPrivacyCollectedDataType`（string）、`NSPrivacyCollectedDataTypeLinked`（Boolean）、`NSPrivacyCollectedDataTypeTracking`（Boolean）、`NSPrivacyCollectedDataTypePurposes`（string 数组）。文档第 12 行对 purposes 的口径是 "Choose values from the list of purposes below that match the reasons your app or third-party SDK collects this data type"，第 9 行对类型的口径是 "Choose the value from the list of data types below"。

**"从列表里选值"与"自造即失真"是同一条规则的两句**：第 9 行对类型的口径是 "Choose the value from the list of data types below that matches the data your app or third-party SDK collects"，第 12 行对理由的口径是 "Choose values from the list of purposes below that match the reasons your app or third-party SDK collects this data type"；第 13 行给出自造取值的后果，而且后果是产物失真而不是提交失败。本文脚本因此在两个方向上都做精确成员检查（D12），并对两个布尔键做类型检查（D13）。这一处的口径来源是本轮补取《NSPrivacyCollectedDataType》与《NSPrivacyCollectedDataTypePurposes》两页之后才补齐的——在此之前本文只能按一种查不到原句的命名形态启发式做判断，属于必须承认的方法论返工（第 23.5 节）。

### 5.4 清单与 Info.plist 的边界

L2 与 L1 的产物在 Xcode 里可能被合并成同一个 `Info.plist`，导致一类纯静态可见的错位：用途声明键写进了 `PrivacyInfo.xcprivacy`，或 `NSPrivacy*` 键写进了 `Info.plist`。前者的判据来自两份文档的分工——用途键属于 Information Property List（《Protected resources》第 6 行），清单顶层只有四个 `NSPrivacy` 键（《Privacy manifest files》第 20—24 行）；后者本文**只记不判**（脚本 P00），因为文档没有说合并产物里出现 `NSPrivacy` 键是错的，只说了它们属于清单。

### 5.5 清单的归属边界：SDK 与 app 各写各的

L2 最重要的一条规则不是结构规则而是**归属规则**，且它在两份文档里各写了一次：

- 收集数据侧："Third-party SDKs need to provide their own privacy manifest files that record the types of data they collect. Your app's privacy manifest file doesn't need to cover data collected by third-party SDKs that your app links to."（《Describing data use in privacy manifests》第 6 行）
- required reason 侧："If you use the API in your app's code, then you need to report the API in your app's privacy manifest file. If you use the API in your third-party SDK's code, then you need to report the API in your third-party SDK's privacy manifest file. Your third-party SDK can't rely on the privacy manifest files for apps that link the third-party SDK, or those of other third-party SDKs the app links, to report your third-party SDK's use of required reasons API."（《Describing use of required reason API》第 7 行）
- 更细的一层落在二进制而不是 target："For each executable or dynamic library in an app that uses a required reason API, the bundle that includes the executable or dynamic library needs to include a privacy manifest file that reports the API."（同页第 8 行）

这三句合起来是本文对"谁该修"最硬的证据：**声明义务按可执行文件与动态库的边界划分，不按 app 边界划分**。第 15 章矩阵里 L2/L9 两行的责任方就是这么来的。

### 5.6 什么时候必须带清单

《Privacy manifest files》第 9 行的 important 框给出了两种触发条件，但其中一种本文无法核对：

> "You need to include a privacy manifest file in your third-party SDK if it's listed in 'SDKs that require a privacy manifest and signature,' in Upcoming third-party SDK requirements. Otherwise, include a privacy manifest file in your third-party SDK if it uses a required reasons API, collects data about the person using apps that include the third-party SDK, enables the app to collect data about people using the app, or contacts tracking domains."

前半句指向的那份「需要清单与签名的 SDK 名单」页面，本轮取回的是 JS 壳，正文不可核对（第 26 章缺口 C）。因此本文对"是否必须带清单"只使用后半句的四个条件（用了 required reason API / 收集使用者数据 / 使能 app 收集 / 联系追踪域名）——这四个条件全部可以在声明文本里做静态核对，而"是否在名单上"不能。这条限制直接决定了脚本一为什么对"无清单"只出边界声明 B03、不出违规。

---

## 6. L3 required reason 申报层

### 6.1 这一格装什么

L3 是这条链路上唯一一格"内容完全由 app 自己写、读数完全由服务端给"的层。它声明的不是"我要访问什么受保护资源"（那是 L1），而是"我用了那些被点名容易被拿来指纹识别的系统 API，理由是什么"。

文档给的结构是两层闭合：

> "Each dictionary in the NSPrivacyAccessedAPITypes array needs to contain these keys and values:"（《Describing use of required reason API》第 10 行）

两个键各自带一条闭合取值要求：

> "NSPrivacyAccessedAPIType: A string that identifies the category of required reason APIs your app uses. The value you provide must be one of the values listed in the sections below."（同页第 11 行）
>
> "NSPrivacyAccessedAPITypeReasons: An array of strings that identifies the reasons your app uses the APIs. The values you provide must be the values associated with the accessed API type in the sections below."（同页第 12 行）

第一句把 category 的取值集合封闭了，第二句把 reason code 的取值集合封闭在**所属类别内部**——也就是说合法的〈类别, 理由〉配对是二维的，不是一个全局码表。脚本一的 D10（码对但类别错）就是按这条句子建立的：单独看 `DDA9.1` 是个合法码，把它声明在 `NSPrivacyAccessedAPICategoryUserDefaults` 下仍然是违规。同页第 7 行给了添加动作的口径："For each category of required reason API that your app or third-party SDK uses, add a dictionary to the NSPrivacyAccessedAPITypes array in your app or third-party SDK's privacy manifest file that reports the reasons your app uses the API category."

### 6.2 闭合规模与"取值带前缀"这个坑

本轮存档里，类别与码的对应表全部落在《NSPrivacyAccessedAPIType》一页（取回件第 6 到 62 行的五个 VALUE 分组）。数出来是 5 类、17 码：

| 类别（文档取值） | API 数 | reason code |
| --- | --- | --- |
| `NSPrivacyAccessedAPICategoryFileTimestamp` | 13 | `DDA9.1`、`C617.1`、`3B52.1`、`0A2A.1` |
| `NSPrivacyAccessedAPICategorySystemBootTime` | 2 | `35F9.1`、`8FFB.1`、`3D61.1` |
| `NSPrivacyAccessedAPICategoryDiskSpace` | 13 | `85F4.1`、`E174.1`、`7D9E.1`、`B728.1` |
| `NSPrivacyAccessedAPICategoryActiveKeyboards` | 1 | `3EC4.1`、`54BD.1` |
| `NSPrivacyAccessedAPICategoryUserDefaults` | 1 | `CA92.1`、`1C8F.1`、`C56D.1`、`AC6B.1` |

每类下面还有一份 API 名单，例如第一类的开头是 "NSPrivacyAccessedAPICategoryFileTimestamp: The following APIs for accessing file timestamps require reasons for use."（《NSPrivacyAccessedAPIType》第 6 行）。这份名单的意义在于：**API 名也是闭合词表**，但它出现在文档正文而不是任何声明文件里，所以离线文本审查器拿不到"app 调了哪些 API"这一侧的读数——第 26 章把这条列为 L3 的核验边界，脚本一只审申报侧。

"取值带前缀"是一个真实的静态陷阱。类别的文档取值是 `NSPrivacyAccessedAPICategoryFileTimestamp` 这种全名，而码是 `DDA9.1` 这种 4 位十六进制加点的短形。清单里把类别写成 `FileTimestamp` 短名，落不进取值集合。脚本一的 D11 因此按全名比对，并在消息里明确"注意文档取值带 NSPrivacyAccessedAPICategory 前缀，只写短名同样落在取值集合之外"。

### 6.3 reason code 携带的第二类义务：出不出设备

每个码的说明句里反复出现同一句式：

> "Information accessed for this reason, or any derived information, may not be sent off-device."（《NSPrivacyAccessedAPIType》第 21 行，`DDA9.1`）

但同一页里还有三种偏离这个模板的形态，它们决定了"申报合规"和"行为合规"是两件事：

1. **带例外的禁止**。`35F9.1` 的原文在禁止句之后追加："There is an exception for information about the amount of time that has elapsed between events that occurred within the app, which may be sent off-device."（《NSPrivacyAccessedAPIType》第 29 行）。同页 `8FFB.1` 更绕：绝对时间戳可以出设备、 boot time 本身及其派生信息不可以（第 30 行）。
2. **附条件许可**。`85F4.1` 允许把磁盘容量通过本地网络发给同一个人操作的另一个设备，但条件是"this exception only applies if the user has provided explicit permission to send disk space information, and the information may not be sent over the Internet"（第 47 行）。
3. **需要可观察行为**。`E174.1` 要求 "The app must behave differently based on disk space in a way that is observable to users."（第 48 行），`3EC4.1` 要求 "Providing a systemwide custom keyboard to the user must be the primary functionality of the app."（第 54 行）。

这三类条件全部是**语义级**的：一份只读 plist/清单文本能证明"声明了哪个码"，不能证明"派生信息有没有出设备""行为是否可观察""键盘是不是主要功能"。本文因此把 L3 的静态判定上限设为 3 级——凡是只有语义证据的项，都不给 1 级（见第 19 章）。

### 6.4 三种不可判缺陷

**语义匹配不可判。** 文档把义务写在申报与功能之间：

> "Your app or third-party SDK must declare one or more approved reasons that accurately reflect your use of each of these APIs and the data derived from their use. You may use these APIs and the data derived from their use for the declared reasons only."（《Describing use of required reason API》第 9 行）

同一句 important 框还写着 "These declared reasons must be consistent with your app's functionality as presented to users, and you may not use the APIs or derived data for tracking."（同页第 9 行）。前一句里的 "accurately reflect" 与这一句里的 "must be consistent with your app" 两截都没有对应的机器可读字段，任何离线审查器在这里只能出边界声明，不能出违规。

**申报者身份不可判。** 两个码是 SDK 专属：`0A2A.1` 与 `C56D.1` 都写着 "This reason may only be declared by third-party SDKs. This reason may not be declared if your third-party SDK was created primarily to wrap required reason API(s)."（《NSPrivacyAccessedAPIType》第 24 行、第 61 行）。前半句还能靠"这份清单来自 app target 还是 SDK 包"粗判，后半句的 "created primarily to" 是对设计意图的判断，静态文本给不出读数。本文把它归到第 17 章的"责任方边界"，脚本一对 app 侧清单里的 SDK 专属码只降为 2 级并附归属说明。

**系统兜底不免责。** `1C8F.1` 里有一句反向免责条款：

> "Your app is not responsible if the system provides information from the global domain because a key is not present in your requested domain while your app is attempting to read information that apps, app extensions, or App Clips in your app's App Group write."（《NSPrivacyAccessedAPIType》第 60 行）

这条对归属矩阵有用：它承认了"读到跨 app 数据"这一现象可能由系统在键缺失时兜底造成，因此**读到域外数据不自动等于越权申报**。同理，`CA92.1` 用否定句式划边界："This reason does not permit reading information that was written by other apps or the system, or writing information that can be accessed by other apps."（同页第 59 行）。

### 6.5 L3 的读数只在提审侧出现

这是 L3 与 L1/L4 最大的差别。文档给了两个读数，都在服务端：

> "If you upload an app to App Store Connect that uses required reason API without describing the reason in its privacy manifest file, Apple sends you an email reminding you to add the reason to the app's privacy manifest. Starting May 1, 2024, apps that don't describe their use of required reason API in their privacy manifest file aren't accepted by App Store Connect."（《Describing use of required reason API》第 6 行）

也就是说：缺 reason 申报**不崩溃、不弹窗、不进日志**，用户在设备上没有任何可观察信号；第一个信号是一封邮件，第二个信号是提审被拒。同页第 5 行还写着 "Regardless of whether a user gives your app permission to track, fingerprinting is not allowed."——这句话把 L3 与授权链路解耦了：**用户同意与否不改变 L3 的义务**，所以"用户已授权"不能作为 L3 缺申报的辩护。

对防御侧的含义：L3 缺陷的检出窗口只有两个——构建前的静态审查（脚本一覆盖）与提审（外部覆盖）。这两者之间没有运行时兜底，因此第 20 章把 O5（required reason 申报覆盖率）放在发版前门禁而不是线上监控。

### 6.6 词表本身是可变的

> "Apple continually reviews the list of required reason APIs and reasons for usage, and will update this article from time to time. If your app uses required reason API to provide benefits to the people using the app, for a reason that isn't listed here, submit a request for a new approved reason."（《Describing use of required reason API》第 14 行）

这条决定了本文所有"5 类 / 17 码 / 35 类型"数字的口径：**它们是本轮取回件的读数，不是常量**。脚本一把词表内联在脚本体里、并在词表输出行 V00 里打印规模，第 23 章的验收表要求换版时同步换词表并重跑夹具。第 2 章引用转录约定里"数字随取回日期固定"说的就是这件事。

## 7. L4 授权请求与系统决策层

### 7.1 这一格负责什么

L4 是"app 发起一次授权请求"到"系统给 app 一个可读数"之间的过程。它不是配置层而是行为层，但它的**缺陷后果会沉淀进 L5 的读数**，所以必须在状态机之前讲清楚：状态机的取值只记录决策的结果，不记录决策的过程。

### 7.2 一次性打断

Core Location 页把这条规则写在第一段：

> "This authorization process involves a one-time interruption, during which the system prompts the device owner to grant or deny your app's request for location data. After the initial interruption, the system stores your app's authorization status and doesn't prompt again."（《Requesting authorization to use location services》第 5 行）

通知侧同构："The first time your app makes this authorization request, the system prompts the person to grant or deny the request and records that response. Subsequent authorization requests don't prompt the person."（《Asking permission to use notifications》第 18 行）。PhotoKit 侧则把发起权交给了第一次操作："The first time your app performs an operation that requires authorization, the system automatically and asynchronously prompts the user for it."（《Delivering an Enhanced Privacy Experience in Your Photos App》第 20 行）。

对防御的含义：**"弹窗没出现"不是一个可用信号**。同一份声明文本无法区分"从没请求过"和"请求过并被记住了"，这条边界直接进入第 17 章。

### 7.3 升级请求只能做一次

> "If your app already has When in Use authorization, you can make a separate request for Always authorization later. However, you can make the request only once."（《Requesting authorization to use location services》第 16 行）

这条给了 L4 一个不可逆的失败模式：升级请求的时机选错（文案不清、上下文不对）不会得到第二次机会，而它的表现只是一次拒绝——落进 L5 后与"用户本来就不想给"完全同形。本文把它归入 P5 类缺陷（时机不可逆），判定 2 级：静态审查只能确认代码里存在升级请求，不能确认它是否已经消耗掉。

### 7.4 缺键在本层的读数

L1 讲缺键的后果分四档，L4 给出其中"fail"档的确切句子：

> "Add all usage description keys to your app's Information Property List before you make any authorization requests. Authorization requests fail immediately if the required keys aren't present."（《Requesting authorization to use location services》第 32 行）

注意这条的口径边界：它说的是 **fail immediately**，不是 crash、也不是报错。所以一个只用位置请求的 app 在缺键时看到的是"状态停在 notDetermined、回调里没有变化"，崩溃栈里什么都没有。脚本一把这一档单列成 D19（而不是和 D01 崩溃档混在一起），消息里明写"授权请求侧看不到崩溃，只看到状态停在 notDetermined"。

### 7.5 谁还能改变读数：状态回推

> "People can change your app's authorization status at any time in system settings. If your app is running when the change happens, each of your app's CLLocationManager objects reports the change to that delegate method. The location manager also reports your app's current authorization at other times. For example, the location manager also calls the method when a suspended iOS app starts running again."（《Requesting authorization to use location services》第 54 行）

这段是"授权台账必须带时间而不是只带终值"的文档依据：同一个 app 的多个 manager 实例会各自回推同一次变化，而挂起后恢复也会再推一次"当前"读数——台账里因此会出现同一主体的重复读数，脚本二对此不去重（按主体聚合而不是按行去重），并在边界声明里说明重复行的含义。

### 7.6 请求返回成功不等于用户点了同意

通知这一格把这一点写得最直白：

> "Unlike explicitly requesting authorization, this code doesn't prompt the person for permission to receive notifications. Instead, the first time you call this method, it automatically grants authorization. However, until the person either explicitly keeps or turns off the notification, the authorization status is UNAuthorizationStatus.provisional."（《Asking permission to use notifications》第 35 行）

同一页的示例代码里，判断"是否已授权"的 guard 同时接受两个值（原文取回件第 46 到 47 行分两行，此处合并转写）：`guard (settings.authorizationStatus == .authorized) || (settings.authorizationStatus == .provisional) else { return }`。这意味着一个"未经用户明示"的状态可以通过一个看起来像"检查授权"的分支。本文把它列为 P6 类缺陷（无同意的成功态），静态判据是"存在 provisional 选项且业务分支未区分 provisional 与 authorized"。

还有反方向的一条："The system still displays alerts in Notification Center if your UNNotificationSettings instance's notificationCenterSetting property is set to UNNotificationSetting.enabled."（同页第 55 行）——**未授权不等于没有可见通知**，因此"设备上看不到横幅"不能作为"未获得授权"的证据。

### 7.7 PhotoKit：崩溃档与免授权档

PhotoKit 同时提供了本页两种极端读数。缺键侧：

> "Attempting to access the Photos library without a valid usage description causes your app to crash."（《Delivering an Enhanced Privacy Experience in Your Photos App》第 12 行）

免授权侧：

> "Because the system manages its life cycle in a separate process, it's private by default. The user doesn't need to explicitly authorize your app to select photos, which results in a simpler and more streamlined user experience."（同页第 9 行）

第 6 行还有一条对既有 app 的影响声明："The limited Photos library affects all apps that use PhotoKit in iOS 14, including those already published to the App Store."——系统行为在平台版本上变更时不回溯修改声明，这构成一条与 app 无关的缺陷来源，归属矩阵里 L6 那一行的"更新通道 = 系统版本"就是这么来的。

### 7.8 app 可以自行推迟弹窗，但那需要一个词表外的键

> "If your app has an onboarding flow that includes obtaining location updates, you may want to defer the Core Location's request for authorization from the user. You can inhibit the auto-prompting in your app by creating a CLServiceSession at a convenient time in your app, then iterating over its diagnostics property to determine the level of authorization the person using your app selects."（《Suspending authorization requests》第 5 行）
>
> "Add the CLRequireExplicitServiceSession property to your app's Info.plist file to opt into this control behavior."（同页第 22 行）

这里有一个对本文口径很重要的事实：`CLRequireExplicitServiceSession` **不在**《Protected resources》那 69 个键的闭合表里。该表收的是"给人读的用途声明键"，不收行为开关键。脚本一的键名识别正则只匹配 `NS*/NFC*/OS*` 前缀加 `UsageDescription` 后缀的形状，`CLRequireExplicitServiceSession` 两头都不合，因此既不会被 D04 报成"未知键名"，也不会被当成用途声明键统计。这条限制要写进结论：**闭合表能证明"某个用途声明键是文档里的哪个键"，不能证明"Info.plist 里合法的键只有这 69 个"**。

### 7.9 HealthKit 请求侧的两个前置

> "Xcode requires separate custom messages for reading and writing HealthKit data. Set the NSHealthShareUsageDescription key to customize the message for reading data and the NSHealthUpdateUsageDescription key to customize the message for writing data."（《Authorizing access to health data》第 12 行）

以及设备可用性检查："Finally, check that Health data is available on the current device by calling isHealthDataAvailable() before calling any other HealthKit methods."（同页第 14 行）。请求失败的典型原因写在示例代码的注释里，原文跨两行（取回件第 36 到 37 行），这里按行分别转写："authorization requests only fail if you haven't set the"（同页第 36 行）与 "usage and share descriptions in your app's information property list"（同页第 37 行）——文档把失败原因限定成"没设文案"和"设备不支持"两类，所以 HealthKit 请求失败既不指认"文案不好"，也不指认"用户拒绝"。脚本一的 D07（两键只提供一个）落在这一格。

## 8. L5 框架状态机层

### 8.1 十一帧不是同一台机器

第 3.2 节给了 11 组枚举、45 条〈框架, 取值〉配对。本章讲为什么"配对数"不等于"可判定位"。

先看取值集合的形状差异：

| 形状 | 帧 | 说明 |
| --- | --- | --- |
| 有 `restricted` | CL、AV、PH、CN、CB、ATT、Speech | 七帧；但每条 `restricted` 的措辞不同（见 8.4） |
| 没有 `restricted` | HK、UN | 两帧；系统限制在这两帧里没有对应取值 |
| 有 `limited` | PH、CN | 两帧，进入 L6 |
| 有 `provisional` / `ephemeral` | 仅 UN | 两值，进入 L6 与 L7 |
| 只有 3 值 | HK | 《HKAuthorizationStatus》第 10 到 12 行 |
| 只有 4 值 | CB | 《CBManagerAuthorization》第 6 到 9 行，无 when-in-use 档 |

命名也没有跨框架词表：CoreBluetooth 用 `allowedAlways`，CoreLocation 用 `authorizedAlways`（《CBManagerAuthorization》第 6 行、《CLAuthorizationStatus》第 13 行）。这两条合起来是脚本二设计的根因——**词表必须按帧建立**（一个框架一组取值），不能用一张全局状态表，否则合法取值会被误判、错帧取值会被漏判。脚本二的 D21（取值不在任何帧的词表里）与 D22（取值属于别的帧）就是这两类误用的分别形态。

### 8.2 五个文档写明的"读数折叠点"

这是 L5 的核心，也是本文与"数一下权限有几个档"的讲法分道的地方。每个折叠点都在文档里自带说明，因此不是本文的推测：

1. **CL 的 denied 混装两种原因。** "CLAuthorizationStatus.denied — The user denied the use of location services for the app or they are disabled globally in Settings."（《CLAuthorizationStatus》第 11 行）一个值同时覆盖"用户针对本 app 拒绝"和"设置里全局关掉"，app 侧无法拆。
2. **CL 页里有一个裸的 `authorized` 条目。** "authorized — The user authorized the app to use location services."（同页第 12 行）它不带 `CLAuthorizationStatus.` 前缀，也不是 `authorizedAlways`/`authorizedWhenInUse`，落在同一组取值列表里。这类"列表里的历史形状"是台账数据里最容易造成假不匹配的行，脚本二把它单列成 D30（3 级，附说明），并按 `CL_INDEX_FORMS` 那组可索引形式判定。
3. **HK 的读侧拒绝完全不可见。**
   > "To help maintain the privacy of sensitive health data, HealthKit does not tell you when the user denies your app permission to query data. Instead, it simply appears as if HealthKit does not have any data matching your query."（《HKAuthorizationStatus》第 8 行）
   
   加上第 7 行 "This status indicates whether the user has authorized your app to save data of the given type."——这组常量只描述**写入侧**。因此"HK 授权读数正常"永远不能推出"读侧被允许"，脚本二对带读语义的 HK 行只出 D24（3 级）。
4. **ATT 的 restricted 与提示无关。** "This property returns ATTrackingManager.AuthorizationStatus.restricted when the system restricts tracking for the device, regardless of whether your app has presented the prompt."（《trackingAuthorizationStatus》第 11 行）"regardless of whether your app has presented the prompt" 让"有没有弹过"这一状态在 ATT 读数里彻底消失。
5. **UN 的 authorized 之下还有档位。** provisional 的语义是"已授权但非打断式"（《UNAuthorizationStatus》第 9 行 "UNAuthorizationStatus.provisional — The application is provisionally authorized to post noninterruptive user notifications."），ephemeral 则是限时（第 10 行 "The app is authorized to schedule or receive notifications for a limited amount of time."）。

### 8.3 正交轴与第三套枚举

Core Location 把精度做成独立的第二轴："CLAccuracyAuthorization.fullAccuracy — The user authorized the app to access location data with full accuracy."（《CLAccuracyAuthorization》第 6 行）、reducedAccuracy 在第 7 行。这条轴不能从 `CLAuthorizationStatus` 推出，脚本二因此要求每个 CL 读数旁都有一条同主体的 CLACC 行，缺失时出 D26（2 级）而不是判定违规。

User Notifications 更极端：一帧 `UNAuthorizationStatus`（5 值）之外还有一组 `UNNotificationSetting`（3 值）套在具体设置属性上。这一组的第一个取值就把"这项设置对本 app 根本不存在"和"存在但关了"分开了：

> "UNNotificationSetting.notSupported — The setting is not available to your app."（《UNNotificationSetting》第 6 行）

属性侧的读数形式是同一个三值枚举挂在每个交互类型上：

> "notificationCenterSetting — The setting that indicates whether your app's notifications appear in Notification Center."（《UNNotificationSettings》第 16 行）

文档对这套属性的定位是系统自己执行：

> "Regardless of whether you take action, the system enforces your app's settings by preventing denied interactions from occurring."（同页第 9 行）

——app 的分支只影响体验，不影响系统是否放行。脚本二对 UN 读数缺 UNS 行的情况出 D27（2 级）。

### 8.4 同一个 `restricted`，五种措辞

这一节解释为什么本文不给 `restricted` 统一判级：

| 帧 | 文档措辞 | 是否说明"谁能改" |
| --- | --- | --- |
| CL | "The app is not authorized to use location services."（《CLAuthorizationStatus》第 10 行） | 否 |
| AV | "A status that indicates the app isn't permitted to use media capture devices."（《AVAuthorizationStatus》第 10 行） | 否 |
| PH | "The app isn't authorized to access the photo library, and the user can't grant such permission."（《PHAuthorizationStatus》第 9 行） | 是，明确不可授予 |
| CN | "The application is not authorized to access contact data. The user cannot change this application's status, possibly due to active restrictions such as parental controls being in place."（《CNAuthorizationStatus》第 7 行） | 是，且给了可能原因 |
| CB | "A state that indicates this app isn't authorized to use Bluetooth."（《CBManagerAuthorization》第 9 行） | 否 |
| Speech | "The device prevents your app from performing speech recognition."（《SFSpeechRecognizerAuthorizationStatus》第 8 行） | 否，主语是设备 |

只有 PH、CN 两帧写明"用户改不了"，其中 CN 还用 "possibly" 限定原因。这意味着跨框架统计"restricted 比例"时，六帧里只有两帧的语义是确定的。第 24 章误区 7 针对的正是这类"把同名取值当同义取值"的读数汇总。

### 8.5 本层缺陷的形态

L5 的缺陷基本不是"app 写错了"，而是"app 读错了自己的读数"，本文把它分成三类：

- **帧错用**：把 A 帧取值写进 B 帧台账（脚本二 D22），或用了不存在的取值（D21）。这类缺陷的成因通常是跨框架复制枚举名——`allowedAlways` 与 `authorizedAlways` 的形状差异让这类错误可被静态捕获。
- **轴缺失**：只记状态不记精度/设置档位（D26、D27）。
- **不可区分误判**：在文档明写"两者同形"的地方做了区分性结论（D23 的 CL denied 二义、D24 的 HK 读侧、D28 的 ATT restricted）。这三条一律 3 级：它们是"读数不能支撑该结论"，不是"读数违规"。

一个例外值得单独说明：`PH` 的 legacy 访问方式。PhotoKit 同时存在 `authorizationStatus()` 与 `authorizationStatus(for:)`，前者在存档里带 "Returns information about your app's authorization to access the user's photo library."（《PHAuthorizationStatus》第 19 行）这类不带 access level 描述的句子。台账若把 legacy 行的读数当成 readWrite 档的读数，脚本二按 D25（1 级）处理，因为这里存在确定的口径错配而不是语义不确定。

---

## 9. L6 部分授权与精度裁剪层

### 9.1 这一格为什么单独一层

L5 讲的是"有没有授权"，L6 讲的是"授权被切成什么样"。这层的存在让"权限读数"从一维变成二维甚至三维：PhotoKit 与通讯录多出一个 `limited` 档，Core Location 多出一条精度轴，HealthKit 多出一个时间窗。三个方向都不是 app 能选的，但它们的**后果**要由 app 的分支逻辑承担，所以缺陷归属既不完全在系统、也不完全在 app。

### 9.2 PhotoKit：受限库与"看起来像全量"的旧接口

受限库的边界句：

> "The selected items represent the user's limited library selection, your app can only access these assets."（《Delivering an Enhanced Privacy Experience in Your Photos App》第 44 行）

以及两条具体能力缺失："The system automatically adds assets that your app creates with a PHAssetCreationRequest to the user's limited library selection."（同页第 46 行）与 "You can't create or fetch user albums."（同页第 47 行）。

真正构成本文缺陷轴的是第 40 行那条 important 框：

> "The authorizationStatus() and requestAuthorization(_:) methods aren't compatible with the limited library and return PHAuthorizationStatus.authorized when the user authorizes your app for limited access only. To determine whether the user has authorized your app for limited access, instead use authorizationStatus(for:) and requestAuthorization(for:handler:)."（同页第 40 行）

这是整条链路上最干净的一类可判缺陷：**同一份授权，新旧接口给出不同读数，而且文档指名了哪个接口在哪个状态下会谎报"全量"**。台账里带 legacy 标记的 PH 行因此被脚本二判为 D25（1 级）——它不是语义不确定，而是确定的口径错配。

通讯录侧的 `limited` 只有一句定义："CNAuthorizationStatus.limited — The app has access to a limited subset of contacts, chosen by the person using the app."（《CNAuthorizationStatus》第 10 行）——没有对应的旧接口陷阱，也没有"哪些字段被裁掉"的说明，因此本文对 CN 的受限态只做记录、不做判定。

### 9.3 Core Location：精度是第二条轴

轴本身只有两个取值："CLAccuracyAuthorization.fullAccuracy — The user authorized the app to access location data with full accuracy."（《CLAccuracyAuthorization》第 6 行）、reducedAccuracy 的对称句在第 7 行。这两个取值与 `CLAuthorizationStatus` 正交，因此第 8 章说过"每条 CL 读数需要一条 CLACC 读数"。

app 侧唯一能预设这条轴的配置是 L1 的那个布尔键：

> "Include this key in your information property list to set your app's default behavior for location accuracy when it calls the Core Location framework. Set the key value to true to prompt the user for reduced accuracy by default; set it to false to prompt for full location accuracy. If you don't include that key in your Info.plist, that's equivalent to setting it to false."（《NSLocationDefaultAccuracyReduced》第 8 行）

这句"缺键等价于 false"很关键：它是整条链路上少数几个**"不写也有确定读数"**的键之一。多数键不写是崩溃或失败，这个键不写等于显式选了"要全精度"。脚本一 D16 因此对"类型不是 Boolean"给 3 级而不是 1 级，并在消息里保留这句等价关系；反过来，"键不存在"本文不判为缺陷，因为文档给了默认值。

第 13 行还说明这一档在人眼中是可见的："Users will see that your app is asking for reduced accuracy because the location authorization prompt will show a map with an approximate location, and your app will have the Precise Location toggled off in Settings > Privacy > Location Services"——这条给了取证侧一个可观察面（截图或人证），但没有给 app 任何 API 读数。第 14 行提供了一条不写键的路径："If you want to leverage the reduced-accuracy feature to improve privacy in a particular operation without setting this key, use the desiredAccuracy constant kCLLocationAccuracyReduced."——即同一目的有配置与运行时两条通道，**静态审查只能看到其中一条**。

### 9.4 临时全精度：把用途文案做成字典

> "Use this key if your app needs temporary access to full accuracy location information. Provide a dictionary of messages that address different use cases, keyed by strings that you define."（《NSLocationTemporaryUsageDescriptionDictionary》第 7 行）

这是 L1 里唯一的"键名由 app 自定义"的结构：外层键固定，内层 purpose key 由开发者命名，取用时按名字传参（同页第 9 行给出 `requestTemporaryFullAccuracyAuthorization(withPurposeKey:)`）。因此本文对这层的静态判据只能是**容器是否为空**（脚本一 D15，3 级）：空容器意味着任何 purpose key 都取不到文案，非空容器里的 purpose key 拼写与代码里是否一致，属于源码级核对，超出两个脚本的输入面（第 26 章）。

### 9.5 HealthKit：时间窗与"全量与拒绝同形"

> "In addition, people can choose to grant your app access to only a limited window of recent data rather than their full history. When someone grants limited access, you can discover the earliest date from which your app is authorized to read data for a given type, but you can't distinguish between full access and denied access for specific types; both appear the same to your app."（《Authorizing access to health data》第 6 行）

这层裁剪是 HealthKit 三套限制里最难取证的一套：它把"拒绝"藏进"空结果"（第 8 章 8.2 第 3 点），又把"全量"与"拒绝"折成同一读数。本文对 HK 的静态判定只保留一件事——台账里出现 HK 的读侧结论时一律降级为不可判定（脚本二 D24）。

## 10. L7 授权持久化与状态变更层

### 10.1 "记住"是系统行为，"应对"是 app 义务

PhotoKit 页把两件事写在同一句里：

> "After the user sets the app's authorization status, the system remembers their choice and won't prompt again. However, the user can change this choice at any time using the Settings app. Prepare your app to respond appropriately when a user changes your app's access."（《Delivering an Enhanced Privacy Experience in Your Photos App》第 39 行）

Core Location 侧的对称句是"the system stores your app's authorization status and doesn't prompt again"（《Requesting authorization to use location services》第 5 行）与"People can change your app's authorization status at any time in system settings."（同页第 54 行）。通知侧则是 "Because people can change the authorization status at any point, check the status before scheduling local notifications."（《Asking permission to use notifications》第 35 行）。

三句合起来是本文对"授权台账必须有时间戳"的文档依据：**终值不可靠，因为它随时可能被人在设置里改；而系统不会为这种变化发通知给审计方**。

### 10.2 变更的三种触发者

| 触发者 | 文档证据 | 对台账的影响 |
| --- | --- | --- |
| 用户在设置里改 | 《Requesting authorization to use location services》第 54 行 | 同一主体出现新的读数行，旧行不代表失效 |
| 用户在弹窗按钮上改（通知） | 《Asking permission to use notifications》第 25、26 行 | provisional 可升为 authorized，也可转为 denied |
| 系统自己 | 《NSLocationDefaultAccuracyReduced》第 15 行 | app 的默认精度档可被覆盖 |

第二条的原文值得完整看：

> "If a person presses the Keep button, the system prompts them to choose between two options: Deliver Immediately or Deliver in Scheduled Summary. Deliver Immediately delivers future notifications quietly. The system authorizes your app to send notifications, but it doesn't give your app permission to show alerts, play sounds, or badge the app icon."（《Asking permission to use notifications》第 25 行）

这里出现了一个文档明写的状态—能力解耦："authorized" 却不给 alert/sound/badge 权限。反方向的第 26 行是 "If the person presses the Turn Off button, the system confirms the selection before denying your app authorization to send additional notifications."——拒绝前还有一次确认。两句话说明同一帧（UN）里，读数的产生路径不同、语义不同，而台账通常只有值。这正是脚本二要求 UN 行旁必须有 UNS 行（D27）的原因。

第三条：

> "Setting NSLocationDefaultAccuracyReduced determines the default type of authorization your app gets, but users can override it any time in Settings. Users always control the level of location accuracy they want to share, and can change precision settings in Settings > Privacy > Location Services by selecting Precise Location for your app."（《NSLocationDefaultAccuracyReduced》第 15 行）

这句话给防御侧的结论是：**app 声明的隐私默认值不是保证**，它只是一个初值。凡在申报口径里以"我们默认只取模糊位置"为卖点的实现，都需要有 L7 的运行时校验，而该校验的读数就是 9.3 那条正交轴。

### 10.3 过期：不需要任何人动作的状态变更

`UNAuthorizationStatus.ephemeral` 的定义是 "The app is authorized to schedule or receive notifications for a limited amount of time."（《UNAuthorizationStatus》第 10 行）——一个由时间而不是由人决定的转变。这类状态在台账里最危险，因为"读数在 T 时刻正确"与"读数现在仍正确"之间没有静态可推的关系。本文把它列入 P8（时效性错配），静态判据是"台账行缺少采集时间或采集时间超出对应帧的有效期语义"。

### 10.4 系统主动发起的采集请求

受限库还有一个由系统决定的变更入口："By default, the system automatically prompts the user to update their limited-library selection once per app life cycle. This automatic presentation isn't the preferred user experience for most apps. Instead, apps need to suppress the automatic prompt and present it programmatically."（《Delivering an Enhanced Privacy Experience in Your Photos App》第 49 行）

抑制办法是往 Info.plist 里加一个键（同页第 50 到 51 行以图片形式给出，具体键名本轮存档里没有文本，本文不转写——第 26 章）。监测侧的办法是订阅变化："To monitor changes to the user's limited-library selection, use the standard change observer API as described in Observing Changes in the Photo Library."（同页第 64 行）

这一小节对归属矩阵有用：**授权集合可以在 app 完全不发起请求的情况下改变**（系统弹窗、用户改选），因此"app 没有请求过 ⇒ 授权集合不变"这条推断是错的。

## 11. L8 继承与传播层

### 11.1 本层的定义与两个证据来源

L8 问的是：一次授权的效果会不会溢出到发起请求的那个可执行文件之外——跨扩展、跨会话、跨 app、跨系统 UI。

本层的证据分成两个来源，而且它们给的粒度不一样：开发者文档（本轮存档组 A）只给单框架内的语义，平台安全指南（组 B）才正面写过扩展与宿主之间的隐私控制共享关系。本章把两条都列出来，并把它们各自不能覆盖的部分交给第 26 章。指南取回件是 PDF 换行后的文本，句子会断在物理行中间，因此下面按行分段转写，每段都单独标注行号。

### 11.2 扩展继承：指南里有一条正面句子，但它只举了一个例子

平台安全指南在讲 app extension 的隔离模型时写了一整段，前半是隔离，后半是例外：

> "They don't have access to each other's files or memory spaces. Extensions"（《Apple Platform Security》第 6056 行）
>
> "separate from the containing app's container. However, they share the same access to"（《Apple Platform Security》第 6059 行）
>
> "privacy controls as the container app. If a user grants an app access to Contacts, this grant"（《Apple Platform Security》第 6060 行）
>
> "is extended to the extensions that are embedded within the app but not to the extensions"（《Apple Platform Security》第 6061 行）
>
> "activated by the app."（《Apple Platform Security》第 6062 行）

这四句是本文能给出的 L8 最硬的一条规则，而且它给出的是一张**按扩展方向区分的矩阵**，不是笼统的"扩展继承宿主权限"：

| 关系 | 文件与内存 | 隐私控制 |
| --- | --- | --- |
| 宿主 app ⇄ 被它激活的扩展 | 互不可见（第 6056 行） | 不继承（第 6061 行末句） |
| 宿主 app ⇄ 内嵌在 app 包内的扩展 | 互不可见 | 共享（第 6059 到 6060 行） |

它的边界同样要说清：文档只举了 Contacts 一个例子（"If a user grants an app access to Contacts"），没有逐框架说明哪些授权落进"share the same access"这一类；也没说 App Clip、widget、后台扩展各自算"embedded"还是"activated"。第 26 章把这两点分别列为 L8 缺口 1 与缺口 2。

这条规则对缺陷归属的直接影响：**同一条 `NSContactsUsageDescription` 声明，在服务内嵌扩展与服务的 app-extension target 时，运行时效果不同**。因此第 15 章矩阵里 L8 的更新通道写"随系统对 extension 类型的判定变化，不随 app 版本"。

### 11.3 其余七条可核对的传播面

1. **App Group 共享域。** reason code `1C8F.1` 的适用面写到"the apps, app extensions, and App Clips that are members of the same App Group as the app itself"（《NSPrivacyAccessedAPIType》第 60 行）。这是文档里唯一把 app、扩展、App Clip 三类主体并列的授权相关句子，但它描述的是**数据共享许可**而不是**授权状态继承**——同一个 App Group 不意味着同一个授权读数。
2. **系统兜底造成的跨域读取。** 同句的免责部分（第 60 行）说明键缺失时系统可能从 global domain 提供信息，即"读到域外数据"这一现象可在无越权申报时发生。
3. **写入即广播（HealthKit）。** "Your app will receive only the data that it has written to HealthKit. Data from other sources remains hidden from your app."（《HKAuthorizationStatus》第 8 行）反过来，本 app 写入的数据对所有有读权限的 app 可见——**保存侧授权与读取侧可见性是两个不相交的集合**，这是传播层最容易被误读的方向。指南用另一套话把同一个集合关系写得更清楚（按物理行分段转写）：

   > "If granted permission to write data, apps can also read the data they write. If granted"（《Apple Platform Security》第 5286 行）
   >
   > "permission to read data, apps can read data written by all sources. However, apps can't"（《Apple Platform Security》第 5287 行）
   >
   > "determine access granted to other apps. In addition, apps can't conclusively tell whether"（《Apple Platform Security》第 5288 行）
   >
   > "all queries return no data--the same response that an empty database would return."（《Apple Platform Security》第 5290 行）

   两句合起来给了第 9 章那条"HK 读侧不可判定"的第二个独立来源，并且多出一条开发者文档没写的限制：app 也读不到**别的 app 拿到了什么授权**（第 5288 行），所以跨 app 的授权台账永远无法由 app 侧自证。
4. **派生摘要离开 app。** "If your app saves data to HealthKit, high-level summaries of that data can appear as suggestions in the Journal app, or in other apps that use the Journaling Suggestions framework."（《Authorizing access to health data》第 8 行）注意这条的触发条件是"你保存了数据"，与第三个 app 是否获得授权无关，且文档用 "can appear"。
5. **受限集合会被 app 自己的写入扩大。** "The system automatically adds assets that your app creates with a PHAssetCreationRequest to the user's limited library selection."（《Delivering an Enhanced Privacy Experience in Your Photos App》第 46 行）app 不需要读权限就能改变用户授予它的读集合。
6. **访客会话。** "Additionally, to protect the privacy of Apple Vision Pro owner data, in a Guest User session, the guest can view previously authorized data, but can't access unauthorized data or change the authorizations."（《Authorizing access to health data》第 7 行）这一句同时给出继承（可见已授权数据）与限制（不可改授权），是 L8 里唯一一条按会话主体划分的文档句子。
7. **widget 的位置需求是一个独立布尔键。** "NSWidgetWantsLocation — A Boolean value that indicates a widget uses the user's location information."（《Protected resources》第 57 行）它出现在受保护资源总表里、但不带 `UsageDescription` 后缀，属于本文 4.5 节的"布尔键"格。它证明了一件事：文档把"另一个可执行体（widget 扩展）要用位置"表达成一个 app 级键，而不是一个扩展级键。

### 11.4 系统代执行：授权带来的第二种传播

Core Location 的 Always 档把"数据传播"变成了"执行传播"：

> "Always authorization makes location updates available at any time, and lets the system launch your app quietly to handle some updates."（《Requesting authorization to use location services》第 10 行）

watchOS 侧则把"使用中"的定义扩展到了系统 UI 组件："On watchOS, complications can receive location updates, but the watchOS app must run at least once so it can request authorization to access location data. If an app's complication is on the current watch face, the system treats that complication as if it's in use and delivers location updates to it."（同页第 14 行）

这两句合起来给出一个可判定的形状：授权的效果可以覆盖到"app 不在前台时由系统拉起的执行"与"位于系统界面里的组件"。而"app 必须至少运行过一次"（第 14 行）是文档里少见的**授权前置执行条件**，属于 L4 与 L8 的交界。

### 11.5 SDK 侧的对应规则

L8 与 L9 的分界在这里：SDK 不能替宿主申报、宿主也不能替 SDK 申报（《Describing use of required reason API》第 7 行，全文见第 5.5 节）。本文把这条留在 L2/L9，L8 只收"一次授权或一份数据越出原可执行体"的传播面。

### 11.6 本层缺陷的形态与上限

先说一件否定的事：**两个脚本里都没有以"继承"为对象的缺陷码**。脚本一的 D01–D19 全部作用在声明文本内部（键、值、类型、配对），脚本二的 D20–D30 作用在台账行的取值与同主体配对上。本层的文档句子不产出新的判定项，它们的作用是**给别的层的结论加限制**——这也是 L8 在缺陷类型学里没有独立 P 类、只作为 P9（跨主体口径混记）出现的原因。

具体到能做的三件事：

1. **限制主体标注的解释力。** 11.2 的矩阵说明"内嵌在包里的扩展"和"被 app 激活的扩展"与宿主的隐私控制关系不同，因此脚本二里同一个主体名下混合了两类扩展的读数时，任何"这个主体有权限"的结论都要降级。台账无法区分二者，所以这条永远只是限制而不是判据。
2. **把 App Group 与授权分开。** 11.3 第 1 条与第 2 条合起来说明：数据共享域（App Group）与授权继承是两件事，申报文本里出现 `1C8F.1` 不能推出"同组扩展也拿到了同样的授权读数"。
3. **给跨 app 取证划边界。** 指南第 5288 行那句"读不到别的 app 拿到了什么授权"意味着任何"设备上所有 app 的授权全景"类结论都不可能由 app 侧台账得出——第 17 章的可见性表里"第三方 app 的授权状态"一栏因此标为不可得。

本文给 L8 的整体判定上限是 2 级：**这一层的静态证据能指出"读数口径混了"，不能指出"权限越界了"**。第 15 章的矩阵里 L8 那一行责任方写成"app（标注）+ 系统（效果）"两列，就是这个意思。

---

## 12. L9 SDK 清单与构建装配层

### 12.1 这一层的对象是文件位置，不是语义

L2/L3 管"清单里写了什么"，L9 管"清单以什么形态存在于哪个产物里、由谁产出、被谁聚合"。这一层的缺陷有一个和其它层完全不同的特征：**它的报错方式最响亮，但报错对象经常不是写它的人**。

清单文件本身是属性列表，位置由产物类型决定。文档给出的闭合形状是：

> "Apps and third-party SDKs — distributed as XCFrameworks, Swift packages, or Xcode projects — can contain a privacy manifest file, named PrivacyInfo.xcprivacy."（《Privacy manifest files》第 5 行）
>
> "By default, the file is named PrivacyInfo.xcprivacy; this is the required file name for bundled privacy manifests."（同页第 18 行）

文件名是硬要求，路径按平台分档。《Adding a privacy manifest to your app or third-party SDK》给了四组具体布局：iOS 系 app 放 bundle 根（第 9 行，示例结构在第 10 到 13 行），macOS 与 Mac Catalyst 放 `Contents/Resources/`（第 15 行），framework 在 iOS 系放根、在 macOS 系放 `Versions/A/Resources/`（第 25 行、第 31 行），Swift package 放 `Sources/<target>`（第 45 行）。

Xcode 会代劳这件事，但文档同时要求人可以复核：

> "When you add a privacy manifest to the target that builds your app or third-party SDK in Xcode, Xcode automatically places this file in the correct location based on the type of product and its target platform. If you don't use Xcode to build your product, use the information below to place the privacy manifest in the correct location. Even if you use Xcode, you might find this information useful to verify the privacy manifest location in your product."（第 7 行）

对防御侧的含义：**清单"存在"与清单"被读到"是两件事**。同页 note 框写 "You need to add the privacy manifest file to your target's resources for Xcode to use it when you generate a privacy report. If you distribute your third-party SDK as a static library, use the support for static frameworks in Xcode 15 or later to bundle resources, including the privacy manifest file."（《Privacy manifest files》第 19 行）——静态库形态下清单资源需要 Xcode 15 以后的静态框架支持才能被打包，这是一个只有装配层才会出现的失效路径。

### 12.2 义务按可执行体切分

第 5.5 节引过的那句（《Describing use of required reason API》第 8 行）在 L9 才真正落地：清单要挂在"包含该可执行文件或动态库的 bundle"上。同页第 7 行则规定 app 与 SDK 各写各的。两条合起来是本文归属矩阵里 L2/L9 责任方列的依据：**声明义务的单位是 bundle，不是 app**。

平台安全指南侧还有一条更早的闸门，它不属于清单而属于 entitlement："Access to the HealthKit API is controlled with entitlements, and apps need to conform to"（《Apple Platform Security》第 5274 行）。这条说明健康数据的准入至少有两道（entitlement 与用户授权），本文两个脚本只覆盖用户授权侧的申报，entitlement 侧未覆盖（第 26 章）。

### 12.3 SDK 侧的三重不可核对

L9 也是本文对第三方供应链能说什么的下限所在：

1. **是否在强制名单上不可核。** 《Privacy manifest files》第 9 行的第一个触发条件指向"SDKs that require a privacy manifest and signature"与"Upcoming third-party SDK requirements"两处引用，本轮取回的是 JS 壳（第 2 章缺口 C）。因此"某个 SDK 是否必须带清单与签名"本文不能判定。
2. **签名侧只有装配与分发环节的句子，没有校验环节的句子。** 存档里可核对到的签名句子有两条，都在同一页：《Adding a privacy manifest to your app or third-party SDK》第 93 行 "When you sign your XCFramework bundle, developers who incorporate the framework can see whether updates to the framework have compatible code signatures."，以及《Adding a privacy manifest to your app or third-party SDK》第 160 行 "Removing or modifying the invalid privacy manifest breaks the archived app’s signature."。前一条讲的是集成方能否看出更新后的代码签名是否相容，后一条讲的是删除或修改失效清单会破坏归档签名，两者都属于构建与分发口径。**App Store Connect 如何核验一个 SDK 的签名、核验不通过时开发者能拿到什么读数，存档里没有对应句子**；调试入口只以标题形式出现：《Adding a privacy manifest to your app or third-party SDK》第 159 行 "To troubleshoot invalid privacy manifests, see TN3181: Debugging an invalid privacy manifest."，其正文未取回（同页第 6 行的 TN3181 链接同理，见第 2 章缺口 C）。
3. **失效清单的溯源靠邮件而不是本地文件。** 报错句在这里：

   > "If you upload an app to App Store Connect that contains privacy manifest files with unexpected keys or values, you receive an email that includes the name and path of the invalid files in your app bundle. If an invalid file comes from a third-party SDK, contact its developer for an updated version of the SDK that includes a valid privacy manifest."（《Adding a privacy manifest to your app or third-party SDK》第 6 行）

   这条读数的价值在于它给**责任方定位**提供了唯一可用的输入：邮件里的路径能区分"app 自己写的清单"与"SDK 带进来的清单"。本文把它转成流程要求（第 20 章 O8），而不是静态判据。

### 12.4 时间线：两道提审闸门

同一页第 6 行还给了一个日期："Starting February 12, 2025, apps you submit for review in App Store Connect must contain a valid privacy manifest file for a certain number of commonly used third-party SDKs."（《Adding a privacy manifest to your app or third-party SDK》第 6 行）

与第 6.5 节的 required reason 闸门（2024-05-01，缺 reason 申报不被接收）并列，本文得到两个相互独立的审核门槛：**一个查"申报内容是否闭合正确"，一个查"该带的清单是否带了且合法"**。前者的静态判据是脚本一的 D09–D12、D17，后者的静态判据只能是"清单是否存在、位置是否合法"，而后者本文没有实现——因为脚本的输入面是声明文本本身，不含 app bundle 目录树。这条限制在第 21 章开头明确写出。

### 12.5 本层的判定形状

L9 在本文里只产出一条硬判据（清单文件必须存在且文件名正确，属于人工检查项）与一条口径转换（同一份声明在 app 清单里 vs SDK 清单里，义务主体不同）。其余全部是给 L1–L3 结论加限制的条件。这也是为什么第 15 章矩阵里 L9 的"可判级"列写"仅边界"。

## 13. L10 申报、审核与可观测面

### 13.1 三个不同主体的观测面

L10 是本文最后格，它不属于 app：申报（开发者）—校验（App Store Connect）—观察（用户）。三者的读数互不相通，把三者混起来讲是隐私讨论里最常见的口径事故。

**用户侧（系统设置）。** 平台安全指南给出的正面句子：

> "or later) or System Preferences (macOS 12 or earlier), users can see which apps they've"（《Apple Platform Security》第 5189 行）
>
> "permitted to access certain information as well as grant or revoke any future access."（《Apple Platform Security》第 5190 行）

这句之后是一份**按平台切分的强制清单**，本文把它当作 L10 的闭合可观测集合来用：

> "Access is enforced in the following cases:"（《Apple Platform Security》第 5191 行）

| 平台组合 | 指南列出的受强制资源 | 行 |
| --- | --- | --- |
| iOS、iPadOS、macOS、visionOS | Calendars、Camera、Contacts、Microphone、Photos、Reminders、Speech recognition | 5193 到 5194 |
| iOS、iPadOS、visionOS | Bluetooth、Home、Media、Media apps and Apple Music、Motion and fitness | 5196 到 5197 |
| iOS、watchOS | Health | 5199 |
| macOS | Input monitoring、Prompt、Screen recording、System Settings / System Preferences | 5201 到 5203 |

这张表和 L1 的 69 键表对不上，而且**差集是有意义的**：`NSLocalNetworkUsageDescription` 对应的本地网络资源不在"access is enforced"列表里，它以另一种形态出现在数据保护类别上——"Additional classes in iOS 15 and iPadOS 15 or later include Local Network, Nearby"（《Apple Platform Security》第 5208 行）。Siri、Face ID、NFC 同理不在该列表内。

这个差集回到第 4.3 节的四档口径：文档写 "should include" 的那类键（本地网络）既没有强制弹窗档，也不在设置页的 per-app 授权列表里，因此**它的"未声明"在用户侧完全不可观测**。本文把这视为口径自洽的佐证，而不是文档矛盾。

**开发者侧（Xcode 产物）。** 聚合规则写得很具体：

> "Xcode can create a privacy report by aggregating the privacy manifests from your app and the third-party SDKs it links to."（《Describing data use in privacy manifests》第 15 行）

产出路径是 Product > Archive，再在 organizer 里 Generate Privacy Report（同页第 17 到 18 行），也就是说**这份报告只在归档时点存在**。它同时是提审填写的输入："The privacy report is organized in a similar way to Privacy Nutrition Labels. Refer to this report when you provide your app's privacy details in App Store Connect."（同页第 22 行）

**校验侧（App Store Connect）。** 第 12.3 条与第 6.5 节的两道闸门。本文对校验侧没有本地证据，只有文档句子。

### 13.2 自定义取值会静默改变产物

申报口径里最实用的一条负面规则：

> "Xcode won't generate a privacy report correctly if you define your own collected data types for the NSPrivacyCollectedDataType key, or provide your own reasons for the NSPrivacyCollectedDataTypePurposes key. Use values listed in the documentation for the keys."（《Describing data use in privacy manifests》第 13 行）

这条把第 3.1 节的"闭合表"从"审核会不会拒"升级成"你的报告会不会错"，而且失败模式是 *不正确*（不是报错）。它与脚本一的 D12（数据类型不在 35 个里、收集理由不在 6 个里）指向同一件事，但文档这句给出了**静态判定的最终用途**：不是为了过审，而是为了让聚合出来的报告可信。

同页第 6 行则是 app/SDK 义务分离的另一处表述："Third-party SDKs need to provide their own privacy manifest files that record the types of data they collect. Your app's privacy manifest file doesn't need to cover data collected by third-party SDKs that your app links to."——注意它与第 15 行的聚合行为并不矛盾：**清单不合并写，但报告会合并读**。这两句放在一起才是完整的口径，单独引用任何一句都会得出错误结论（第 24 章误区 5）。

### 13.3 系统给出的两个默认授予

L10 的可观测面里还有两条容易被忽略的"没有弹窗的准入"：

> "If the user signs in to iCloud, apps in iOS and iPadOS are granted access by default to"（《Apple Platform Security》第 5211 行）
>
> "Users may control each app's access under iCloud in Settings."（《Apple Platform Security》第 5212 行）

以及第 7.6 节的通知 provisional 自动授予。两条的共同形状是：**存在不需要 app 声明、也不需要用户确认就已生效的数据可达路径，其撤销入口在设置里而不在 app 里**。本文把它们列入第 17 章"app 侧不可见但系统侧有入口"的类别。

### 13.4 本层判定：只出边界，不出违规

L10 的静态证据链在本报告里是断的：脚本一/脚本二的输入是声明文本与授权台账，两者都不含"申报给 App Store Connect 的内容"，也不含"设置页此刻显示了什么"。所以本文对 L10 只给三句话：

1. L10 的错误几乎全部由 L1–L3 的错误派生（自定义取值 → 报告错 → 标签错）。
2. L10 的正确读数不能反推 L1–L3 的正确（清单聚合报告不含 entitlement 侧，也不含未申报的实际收集）。
3. 用户侧撤销能力（第 5190 行那句 "grant or revoke any future access"）意味着任何"用户已授权"的结论有时效，这就是第 10 章与本章的接缝。

## 14. 缺陷类型学 P1—P12

### 14.1 建立方式

类型不靠抽象归纳，靠两个脚本的 33 个码（脚本一 D01–D19 + E01–E03，脚本二 D20–D30 + E01–E03）反推：**同一种"为什么这条读数不可信"的解释被多个码共享时，它就是一个 P 类**。下表同时给出每类是否有静态判据——没有判据的两类（P5、P8）本文只用作结论限制。

### 14.2 十二类

| 类 | 名称 | 定义 | 层 | 码 | 静态判据 |
| --- | --- | --- | --- | --- | --- |
| P1 | 声明缺失 | 需要用途说明的资源没有任何对应键 | L1 | D01、D19 | 有 |
| P2 | 声明空洞 | 键在位但值为空、或短到无法表达用途 | L1 | D02、D03 | 有 |
| P3 | 键名越界 | 键名不在文档闭合表内，或落在弃用分组 | L1 | D04 | 有 |
| P4 | 键组合与档位错配 | 该配成对的只配一个、类型不对、容器为空、按部署目标该换的没换 | L1 | D05、D06、D07、D13、D15、D16 | 有 |
| P5 | 请求已发起但无效果 | 台账显示请求过、读数仍停在未决 | L4 | D29 | 半（依赖台账自报） |
| P6 | 无同意的成功态 | 未打断用户即得到"看似已授权"的读数 | L4/L5/L6 | D25 | 有（PH legacy 一条） |
| P7 | 申报内部不一致 | 布尔与数组互相矛盾、码与类不配对、值不在闭合集、清单与 plist 串位 | L2/L3 | D08、D09、D10、D11、D12、D14、D17、D18 | 有 |
| P8 | 时效性错配 | 用某个时点的读数支撑"现在仍然成立"的结论 | L7/L10 | 无 | 无（仅限制） |
| P9 | 跨主体口径混记 | 不同主体（app、内嵌扩展、被激活扩展、访客会话）的读数记在同一名下 | L8 | D20、D21、D22 | 有（取值/主体形状） |
| P10 | 读数折叠误判 | 在文档明写"两者同形"处做出区分性结论 | L5/L6 | D23、D24、D28、D30 | 有 |
| P11 | 正交轴缺失 | 只记状态不记精度档或设置档 | L5/L6 | D26、D27 | 有 |
| P12 | 读数不可用 | 输入不可读、二进制 plist、空文件、字段不足 | 全部 | 两脚本 E01–E03 | 有 |

### 14.3 每类的"最坏解释"

类型学的用途不是分类本身，而是让读者知道**每类最坏能被解释成什么**，从而判断它值不值得修：

- P1 的最坏解释按四档不同：崩溃档（Photos/Motion/Speech/ATT/HealthKit）最坏是"发版后首次触发才暴露"；fail 档（位置）最坏是"功能静默不可用，测试全绿"；req 档最坏是"没人知道会怎样"；should 档最坏是"功能可用但申报口径缺一条"。
- P2 的最坏解释是用户侧：弹窗里出现一句没有信息量的话，拒绝率上升，而且没有任何系统读数反映这件事。
- P3 的最坏解释是"看起来配了但系统根本没读"，其中弃用键（D04 的 3 级分支）连这点读数都没有。
- P4 里 `NSLocationDefaultAccuracyReduced` 类型写错的最坏解释是把"默认模糊"变成"默认全精度"，方向与意图相反。
- P5 的最坏解释是升级请求的机会被消耗（第 7.3 节），不可逆。
- P6 的最坏解释是"隐私承诺与实际弹窗次数不符"，因为 app 侧代码路径走的是已授权分支。
- P7 的最坏解释分两支：申报被拒（可发现）与聚合报告错（不可发现）。
- P8 没有判据，所以最坏解释是本文自己：任何以台账终值做出的长期结论。
- P9 的最坏解释是"内嵌扩展的继承被当成所有扩展的继承"。
- P10 的最坏解释是把全局关闭读成用户针对本 app 的拒绝（CL denied），或把"没数据"读成"用户拒绝"（HK）。
- P11 的最坏解释是"用户以为给了模糊位置，app 按全精度实现"。
- P12 的最坏解释是审查者把"读不到"记成"没问题"，本文两个脚本对此都显式退出并给出非零码。

### 14.4 类型间的换算关系

三类之间有稳定的派生关系，第 19 章的判定模型按此给权重：

```
P1 ──派生──> P5（请求必然无效）──表现──> P10（读数停在未决）
P3 ──派生──> P7（键名越界常与清单结构问题同现）
P6 ──派生──> P11（成功态掩盖了正交轴缺失）
P12 ──阻断──> 其余全部（读不到时不做任何判定）
```

这里最重要的一条是最后一条：P12 不是"第 12 类缺陷"，它是其余 11 类的前置条件。两个脚本遇到 P12 时都不继续产出判定（脚本一 E01–E03 后立即 `give_verdict` 并返回，脚本二同），这是本文与"报告一个分数就走"的扫描器最大的方法差异。

---

## 15. 归属矩阵：层 × 责任方 × 更新通道 × 证据

### 15.1 四个轴各自为什么不可省

单看"谁的 bug"没有可操作性，因为隐私授权链路上**修复动作的生效时点差异极大**：改一个 Info.plist 键随下一次构建生效；改一条 SDK 清单要等 SDK 发版；而"用户可以在设置里随时撤销"这件事永远不随任何版本生效。所以本矩阵的第二列（更新通道）比第一列（责任方）更有用。

四个轴定义如下：

- **责任方**：能改变这一格读数的那个主体，取值限于 app 开发者 / SDK 开发者 / 系统（Apple 文档与实现）/ 用户。
- **更新通道**：修复实际到达设备所依赖的通道，取值限于 app 构建、SDK 依赖升级、系统版本、用户设置动作、Apple 服务端规则或文档词表变化。
- **可见方**：这个缺陷被谁第一次看到（用户、开发者、审核、取证方、无人）。
- **本文可判级**：第 19 章的四级模型下，仅凭两个脚本的输入面能到达的最高级别。

### 15.2 主矩阵

| 层 | 规则来源（可核对句所在） | 责任方 | 更新通道 | 第一次可见方 | 可判级 | 码 |
| --- | --- | --- | --- | --- | --- | --- |
| L1 用途声明 | 《Protected resources》键表、各用途键页 | app 开发者 | app 构建 | 用户（弹窗/崩溃）或无人 | 1 | D01–D07、D13、D15、D16、D19 |
| L2 隐私清单 | 《Privacy manifest files》第 5、18、21—24 行 | app + SDK 各自 | app 构建 / SDK 升级 | 审核（邮件）| 1（结构）3（语义） | D08、D14、D18 |
| L3 required reason | 《Describing use of required reason API》第 6—14 行 | 按 bundle：可执行体所在方 | app 构建 / SDK 升级 + 词表变化 | 审核（2024-05-01 起拒收） | 1（词表）3（语义） | D09、D10、D11、D12、D17 |
| L4 授权请求 | 《Requesting authorization to use location services》第 5、16、32 行等 | app 开发者 | app 构建 | 开发者（状态停在未决） | 2 | D29 |
| L5 框架状态机 | 11 组枚举页的取值行 | 系统定义取值、app 解读 | 系统版本（取值集合会变） | 开发者 | 1（错帧）3（折叠） | D21、D22、D23、D24、D28、D30 |
| L6 部分授权与精度 | 《Delivering an Enhanced Privacy Experience in Your Photos App》第 40、44 行；《NSLocationDefaultAccuracyReduced》第 8、15 行 | 系统裁剪、app 分支 | 系统版本 | 用户（设置页） | 1（PH legacy） | D25、D26、D27 |
| L7 持久化与变更 | 各框架"随时可改"句（第 10 章） | 用户 + 系统 | 用户设置动作 | 无人（app 只在被回调时知道） | 无判据 | — |
| L8 继承与传播 | 《Apple Platform Security》第 6059 到 6062 行 | app（标注）+ 系统（效果） | 系统版本 | 取证方（若有台账） | 2 | D20 |
| L9 SDK 清单与装配 | 《Adding a privacy manifest to your app or third-party SDK》第 5—9 行 | SDK 开发者 | SDK 依赖升级 | 审核（含文件路径的邮件） | 仅边界 | — |
| L10 申报与可观测 | 《Describing data use in privacy manifests》第 6、13、15、22 行；指南第 5189 到 5203 行 | 开发者申报、系统展示 | 提审时点 + 系统版本 | 审核 + 用户 | 仅边界 | — |

表里三处要解释：

1. **L3 的责任方不是"app"而是"bundle"**。依据是《Describing use of required reason API》第 8 行那句 "For each executable or dynamic library in an app that uses a required reason API, the bundle that includes the executable or dynamic library needs to include a privacy manifest file that reports the API."；第 7 行的三句则规定 SDK 不能依赖宿主申报。
2. **L5 的更新通道是系统版本**。第 8 章那 45 条配对是本轮文档读数，取值集合会随框架演进变化（PhotoKit 的 `limited` 就是 iOS 14 引入的：《Delivering an Enhanced Privacy Experience in Your Photos App》第 5 行 "Starting in iOS 14, PhotoKit further enhances user privacy controls with the addition of the limited Photos library"，同页第 6 行更写明它回溯影响已发布 app）。因此任何跨时间比较授权台账的结论都必须带 OS 版本。
3. **L7 没有码**。这一层的正确动作是"每次都读当前状态"，静态文本无法证明代码这么做了，所以它只作为限制出现在其它层的判定里。

### 15.3 按"修复要等多久"重排

把矩阵按更新通道重排，得到一条对运营更有用的序列：

| 通道 | 涉及层 | 生效延迟 | 含义 |
| --- | --- | --- | --- |
| app 构建 | L1、L2、L3(app 侧)、L4、L6(app 分支) | 一次发版 | 全部声明类缺陷都在这里，也是脚本一唯一能事前拦住的 |
| SDK 依赖升级 | L2、L3(SDK 侧)、L9 | 依赖发版 + 宿主升级 | 修复权不在你手里，只能靠版本门禁与审核邮件路径定位 |
| 系统版本 | L5、L6、L8 | 用户是否升级 | 取值集合、继承规则、受限库行为都会漂移 |
| 用户设置动作 | L7 | 即刻且随时 | 任何"已授权"结论有时效 |
| 文档词表/服务端规则 | L3、L10 | Apple 侧 | 5 类/17 码/35 类型/6 理由会变，闸门有日期 |

## 16. 公开案例读数：安全公告能证明这条链路的什么

### 16.1 取材方式与不做什么

本轮从 Apple 公开发布文档存档里按组件名与影响句筛出与隐私授权链路相邻的条目（存档页号即公告文档号）。**本文不把这些条目当作"隐私声明缺陷的证据"**——它们全部落在实现侧。它们的价值在于反证：公告口径里没有任何一条打到 L1–L3。

读数一律引用 Impact 行的原句，行号取该条目 Impact 所在的物理行；组件名取同一页该条目起始行的物理行号。

### 16.2 十二条读数

| # | 页 第 N 行 | 组件 | Impact 原句 | CVE | 落层 |
| --- | --- | --- | --- | --- | --- |
| R1 | 120905 第 1490 行 | Symptom Framework（第 1480 行） | "An app may be able to circumvent App Privacy Report logging" | CVE-2024-27807 | L10 |
| R2 | 120905 第 1520 行 | Sync Services（第 1510 行） | "An app may be able to bypass Privacy preferences" | CVE-2024-27847 | L7/L8 |
| R3 | 122371 第 1815 行 | RepairKit（第 1805 行） | "An app may be able to bypass Privacy preferences" | CVE-2025-24095 | L7/L8 |
| R4 | 122371 第 2230 行 | Web Extensions（第 2220 行） | "An app may gain unauthorized access to Local Network" | CVE-2025-31184 | L1/L10 |
| R5 | 122066 第 1070 行 | Passkeys（第 1060 行） | "An app may gain unauthorized access to Bluetooth" | CVE-2024-9956 | L1/L5 |
| R6 | 120893 第 575 行 | CoreBluetooth - LE（第 565 行） | "An app may be able to access Bluetooth-connected microphones without user permission" | CVE-2024-23250 | L4/L5 |
| R7 | 122371 第 1970 行 | Sandbox Profiles（第 1960 行） | "An app may be able to read a persistent device identifier" | CVE-2025-24220 | L3 |
| R8 | 120905 第 1090 行 | MarketplaceKit（第 1080 行） | "A maliciously crafted webpage may be able to distribute a script that tracks users on other webpages" | CVE-2024-27852 | L2 |
| R9 | 120893 第 605 行 | ExtensionKit（第 595 行） | "An app may be able to access sensitive user data" | CVE-2024-23205 | L8 |
| R10 | 120893 第 1250 行 | Shortcuts（第 1240 行） | "An app may be able to access information about a user's contacts" | CVE-2024-23292 | L8 |
| R11 | 122066 第 1200 行 | Time Zone（第 1190 行） | "An app may be able to view a contact's phone number in system logs" | CVE-2025-24145 | L10 |
| R12 | 122371 第 1690 行 | MobileLockdown（第 1680 行） | "An attacker with a USB-C connection to an unlocked device may be able to programmatically access photos" | 本轮未取该条目 CVE 行，只取 Impact 行 | 链路外 |

补充四条同类日志脱敏条目（同格式，不重复列表格）：120893 第 430 行 Accessibility "An app may be able to read sensitive location information"；120893 第 485 行 Accessibility "A malicious app may be able to observe user data in log entries related to accessibility notifications"；121837 第 595 行 Contacts "An app may be able to view autocompleted contact information from Messages and Mail in system logs"；125108 第 565 行 Bluetooth "An app may be able to access sensitive user data"。

### 16.3 读数讲出来的四件事

**一，可观测面本身是被修的对象。** R1 是唯一一条 Impact 直接落在隐私可观测性产物上的条目；它的存在说明 App Privacy Report 这类"给用户看的日志"是可以被绕过的实现，因此**用户侧"看不到某次访问"不等于"没发生访问"**。这条直接进第 17 章的边界表。

**二，"绕过隐私偏好"是成对出现的。** R2 与 R3 的 Impact 句完全相同（"An app may be able to bypass Privacy preferences"），但组件不同（Sync Services、RepairKit）。这说明强制侧的入口不止一处，而这两处都不在 app 代码里。两句的 Description 分别给 "This issue was addressed with improved checks" 与 "This issue was addressed with additional entitlement checks."——后者把修复落到了 entitlement 上，印证第 12.2 节的判断：健康/数据类准入至少有两道闸门，而本文脚本只覆盖用户授权那道。

**三，声明口径与公告口径互不覆盖。** 本表里没有一条 CVE 的 Impact 形如"缺用途声明键""清单申报不实"。相反，R7 的 "An app may be able to read a persistent device identifier" 描述的正是 required reason 类别页开篇所担心的那类能力（《Describing use of required reason API》第 5 行把这类 API 说成可能被"misused to access device signals to try to identify the device or user"）。结论：**不能用公告数量衡量申报质量**，两者是正交的度量（第 24 章误区 3）。

**四，跨主体访问有实例。** R9（ExtensionKit）与 R10（Shortcuts）都是"一个主体读到另一主体的数据"，与 L8 的文档矩阵方向一致。特别注意 R5 的组件是 Passkeys 而 Impact 写的是蓝牙访问——公告的组件名不等于缺陷所在层，读公告时必须以 Impact 句为准而不是以标题为准。

关于 Notification Services 族的 CVE-2026-28950：它在第 07 篇（APNs 推送投递链）里已完整读数为"标记删除的通知仍留在设备上"的日志类缺陷，本文不重复展开，只在第 28 章参考资料里以篇目标注互链。

## 17. 可见性边界：这条链路上读者能拿到什么

### 17.1 四类读者

防御分析里"能不能测"取决于读者身份。本文区分四类：app 自己（运行时代码）、取证方（拿到一份台账或一份声明文件）、用户（设备上的设置页）、审核方（App Store Connect）。同一件事在四类读者这里的可得性完全不同。

| 待测事实 | app | 取证方 | 用户 | 审核方 | 依据 |
| --- | --- | --- | --- | --- | --- |
| 某个受保护资源键是否存在 | 否（不报错即不知） | 是（读 plist） | 否 | 是 | 第 4.3 节四档；指南第 5189 行 |
| 弹窗文案的实际内容 | 是（自己写的） | 是 | 是（那一刻） | 否 | 各用途键页 |
| 用户此刻的授权状态 | 是（读枚举） | 是（台账） | 是（设置页） | 否 | 枚举页取值行 |
| 用户为什么是这个状态 | 否 | 否 | 是（自己知道） | 否 | 《CLAuthorizationStatus》第 11 行折叠 |
| 健康数据的读侧是否被允许 | 否 | 否 | 是 | 否 | 《HKAuthorizationStatus》第 8 行；指南第 5288 行 |
| 别的 app 拿到了什么授权 | 否 | 否 | 是 | 是 | 指南第 5288 行 |
| 系统全局开关是否关了某项服务 | 否（与个人拒绝同形） | 否 | 是 | 是 | 《CLAuthorizationStatus》第 11 行 |
| SDK 实际收集了什么 | 否 | 仅清单申报值 | 否 | 是（聚合报告） | 《Describing data use in privacy manifests》第 15 行 |
| 申报与真实行为是否一致 | 否 | 否（静态无证据） | 否 | 政策判断 | 第 6.3 节 |
| 某次访问是否发生过 | 仅自身调用记录 | 否 | 部分（报告可被绕过） | 否 | 本文 R1（CVE-2024-27807） |

### 17.2 三个由表格推出的硬边界

1. **app 侧无法自证"权限最小化"。** 上表里 app 列为"否"的行包括"用户为什么是这个状态""读侧是否被允许""别的 app 的授权"。因此任何"我们的 app 只申请必要权限"的对外承诺，其可核验部分只有 L1/L2/L3 的申报文本，而不是运行结果。
2. **取证方拿不到"原因"，只拿得到"值"。** 这是脚本二输出全部是"口径判定 + 边界声明"而不是"根因"的原因：`denied` 背后可能是个人拒绝、也可能是全局关闭；HK 的 `notDetermined` 与"拒绝"同形（第 9.5 节）。
3. **用户是唯一看到完整链路的读者，但她的证据不可传递。** 设置页给出的撤销能力（指南第 5190 行 "permitted to access certain information as well as grant or revoke any future access."）没有对应的 app 侧读数，因此用户的"我看到了那个弹窗"在审计里只能作为旁证。

### 17.3 本文两个脚本读者的位置

脚本一与脚本二服务的是第二类读者（取证方/审计方），输入是**已经导出的声明文件与已经采集的台账**。它们不改变任何一侧的可得性，只把可得的那部分判定做完。这就是第 21、22 章每条边界声明（B 类输出）都存在的原因——它们标的是"这一格需要别的读者"。

---

## 18. 崩溃与日志读数侧

前面十章把"声明写错了会发生什么"拆成了四档（第 3.4 节）。本章只处理其中最有戏剧性的一档：**崩溃**。它是这条链路上唯一"设备主动告诉你出事了"的信号，也因此最容易被过度解读——把"没崩溃"读成"声明没问题"。本章给出这个信号的三个真实属性：触发点各不相同、崩溃文本不在本文可核验范围内、崩溃计数的变化还有另一个来源。

### 18.1 五处崩溃句子指向五个不同的触发点

本轮存档里明写"缺键会崩溃"的句子共五处。把它们放在一起，第一个发现是**它们说的不是同一件事**：

| 出处 | 原句里的触发动作 | 触发点粒度 |
| --- | --- | --- |
| 《Delivering an Enhanced Privacy Experience in Your Photos App》第 12 行 | "Attempting to access the Photos library without a valid usage description causes your app to crash" | 访问库（读或写）时 |
| 《NSMotionUsageDescription》第 7 行 | "If you don't include this key, your app will crash when it attempts to access motion data" | 取运动数据时 |
| 《NSSpeechRecognitionUsageDescription》第 7 行 | "If this key isn't present, your app crashes when it calls requestAuthorization(_:)" | 调用授权请求时 |
| 《NSUserTrackingUsageDescription》第 8 行 | "Your app crashes if it attempts to use the App Tracking Transparency framework without including the key in your target's properties in Xcode" | 使用该框架时 |
| 《Protecting user privacy》第 7 行 | "Apps must include usage descriptions, or it will crash when you request authorization to access HealthKit data" | 请求授权时 |

粒度差别直接决定"什么时候暴露"。Speech 与健康这两处写在**请求授权时**崩溃，意味着这条路径几乎没有潜伏期：只要功能被调用过，问题当场现形。Photos 与 Motion 两处写在**访问数据时**崩溃，而访问数据常常发生在授权成功之后的下游（例如用户点了"选择照片"之后 app 才去 fetch），于是同一个缺陷在测试环境里的表现取决于测试有没有走到那次访问。ATT 那句用的是 "attempts to use the App Tracking Transparency framework"，字面上既不是请求也不是访问，是**用到这个框架**——这是五处里范围最宽的一句，也是最难判断潜伏期的一句。

对防御方的直接结论有两条：

1. **"崩溃档"不等于"能被测试覆盖"。** 崩溃发生在调用点而不是构建期或启动期（五处句子全部以"当它……时"形式给出），所以缺陷是否暴露取决于代码路径被执行过没有。一个只在特定地区、特定会员等级、特定错误分支里访问运动数据的功能，可以在生产环境里带着缺键存活很久。
2. **崩溃档的信号强度依赖读者是谁。** 对 app 开发者，崩溃是可复现的；对**只拿到声明文本的离线审查器**（也就是本文两个脚本的位置），崩溃档反而没有额外信息——判定完全来自静态文本与文档句子，脚本不观察进程。第 21.6 节的边界声明里明确写了这一点。

### 18.2 崩溃报告的文本不在本文可核验范围内

真实设备上这次崩溃会带一条诊断文本，写明了缺的是哪个键。这条文本**不在本轮取回的存档里**：`.srcx8/A` 的 73 份文档页与 `.srcx8/B` 的指南里，能检索到的 "crash" 只有上面五处句子和 `NSPrivacyCollectedDataType` 的一个取值名，没有任何一处给出崩溃报告的字符串形态。

按本文的取材规则（每一个行号与每一句文档句子都必须能在取回记录里找到原句，取不到原句即为伪造），本文**不转写、不复述、不模仿**那条诊断文本，也不把它当作判定依据。这条限制进入第 26 章边界清单。这里的实际后果是：

- 审查器不能通过"崩溃文本里点了哪个键"来反推缺键——它拿不到崩溃文本。
- 崩溃文本对键名的指名方式（单数还是复数、是否给出 deployment target 分支）会影响工程师的修复方向，但这一层本文只能说"未文档化于本轮存档"，不能说它如何。
- 反过来，能核验的只有第 3.4 节那张四档表：**后果的档位有文档原句，后果的具体字符串没有**。这就是本章和第 19 章判定模型都必须带"级"而不是带"结论"的原因。

### 18.3 崩溃计数变化的另一个来源：静默补丁通道

把崩溃率当作声明质量的运营指标（第 20 章 O2）有一个必须先排除的混淆项：系统侧可以在不发布完整更新的情况下改变设备上二进制的行为，而这个变化会被观测成"某 app 崩溃变多了"。本轮存档里对应的段落是 Background Security Improvement：

> "the identities of the affected applications are published"（《Apple Platform Security》第 2637 行，前一句的完整条件是 It observes that a Background Security Improvement is contributing to a potentially higher rate of application crashes，跨行排版）

> "If the user encounters such a crash, the operating system lets them"（《Apple Platform Security》第 2641 行，接第 2642 行说明系统会提示用户该改进可能是原因）

两点读法。第一，设备会**定期查询一个服务**来决定哪些 app 受影响，并且用设备上的分析系统去核对某个 app 是否在装上这项改进后崩溃显著变多——也就是说"崩溃变多"这件事在系统侧是有主动归因流程的，但它归的是**补丁**，不是 app 的声明文本。第二，可撤销性是设计出来的：

> "Background Security Improvements ship both a patch"（《Apple Platform Security》第 2623 行，下一行接 an antipatch to the device）

> "returns patched system binaries to the version from the last installed"（《Apple Platform Security》第 2628 行，接 software update，说明移除后回到上一次软件更新的二进制版本）

因此本文对崩溃类信号的处置是：**崩溃可以在调用点证明"缺键"这件事发生，但崩溃计数的变化不能单独证明缺陷出现在声明层**。把某次崩溃率上升写成"用途声明缺陷上升"，属于跨层归因，第 19 章的禁止用法第三条针对的就是这个。

### 18.4 崩溃日志在申报口径里同时是一项"收集的数据"

读数面与申报面在这条链路上有一个交叉点，容易被忽略：崩溃数据本身就是隐私清单里的一种收集数据类型。

> "Crash data, such as crash logs."（《NSPrivacyCollectedDataType》第 34 行，完整取值名为 `NSPrivacyCollectedDataTypeCrashData`）

这个交叉的防御意义有两层。第一层是口径对齐：如果 app 或其 SDK 采集崩溃日志并外送，申报口径要求它出现在 `NSPrivacyCollectedDataTypes` 数组里并带上收集理由；脚本一的 D12 组检查的正是"每个数据类型有没有齐备的理由键"。第二层更尖锐：本文第 6.3 节列出的 required-reason 数据外送限制（may not be sent off-device 那三类）与崩溃日志是**可能同时适用**的——一份崩溃日志里带的上下文（例如某次 disk-space 读取的读数）如果来自 required reason API，那么"把崩溃日志发给分析平台"这个动作就同时落在申报口径（这是收集数据）和 required reason 语义（这是外送派生信息）两个口径里，而这两个口径在离线审查里没有任何一方能证明对方的读数。

这条正是第 17 章表格里"申报与真实行为是否一致 = 否"那一行的具体实例之一：**静态审查能看到"清单声明了 Crash data"，看不到"崩溃日志里装了什么"**。

### 18.5 四档信号的可得性汇总

把第 3.4 节的四档与本章的读数面合起来，得到的是"谁在什么时候知道"：

| 档 | 设备侧信号 | 服务端信号 | 离线文本审查能判 | 备注 |
| --- | --- | --- | --- | --- |
| crash（五处原句） | 调用点崩溃 | 无（除非 app 上报崩溃） | 是，级 1 | 触发点粒度见 18.1 |
| fail（定位） | 无崩溃、无弹窗，状态停在未授权 | 无 | 是，级 1（D19） | 表现是"功能不可用"，易被当作服务端问题 |
| req（多数键） | 本轮文档未给运行时读数 | 无 | 是，级 1，只报口径不报后果 | 第 3.4 节表第 7 行 |
| should（本地网络） | 未文档化 | 无 | 最多级 3 | 与第 13 章强制资源清单的差集互证 |
| required reason 缺申报 | 无弹窗、无日志（第 6.5 节） | 邮件 + 提审拒绝 | 是，级 1 | 唯一服务端信号档 |
| 精度/limited 折叠 | 有状态读数但被折叠 | 无 | 否 | 第 9、10 章；这是"有信号但信号不可分辨" |

最后一行需要强调：**这一档不是没有读数，而是读数不区分原因**。它与"完全没有信号"的 req 档在处置上完全不同——前者需要在台账里补轴（D26、D27），后者只需要补文本。

### 18.6 本章不做的事

本章不读取、不采集、不建议读取任何设备上的崩溃报告、系统日志或分析事件；本文两个脚本的输入只有导出后的声明文本与已采集的台账文本（第 21、22 章），对崩溃与日志没有任何读取路径。上面所有"崩溃"字样都是文档句子的引用，不是对某台设备的观测结果。

---

## 19. 四级判定模型

本文全部输出只有一个类型：〈码位，级，解释〉。级不是风险分数，而是**这条结论距离"可归责"还差几步**。这一章把散在前 18 章的判级动作收敛成一个可复用的模型，并说明它的四条使用限制。

### 19.1 四级的定义取自脚本自身的图例

两个脚本在输出末尾都会打印同一组图例（第 21.5、22.4 节），本文直接以它为准，不另写一套措辞：

脚本一（声明侧）：
- **级 1**：命中文档明写的必配规则或封闭取值集合，可直接归责到声明文件本身。
- **级 2**：违规成立但结论依赖 deployment target 或未公开的运行时读数，需按工程配置再收敛一次。
- **级 3**：形态可疑但文档未给唯一处置口径，需要人工确认用途。
- **级 4**：本条读数不可用（E 类），不给口径判定。

脚本二（台账侧）的三级说明与级 4 定义与脚本一不同，这是刻意的：它的输入是读数而不是文本，所以"级 3"在台账侧的含义是**文档自身给出二义或明写不告知**（D23、D24、D28、D30 全在这一级），而不是"形态可疑"。两个脚本的同一级号因此**不可互相比较**，这是 19.4 第二条禁止用法的来源。

### 19.2 收敛规则：一条输出流只出一个总判定

`emit` 在脚本里维护一个 `WORST` 值，收敛顺序是"越小的级号越优先"：任何一条级 1 都会占位，级 2 只在没有级 1 时占位，级 3 与级 4 只在前面都空时占位。也就是说总判定读的是**这份输入里最强的那条结论**，不是命中条数。

E 类走的是另一条路：脚本置一个"读数不可用"标志，判定环节先看这个标志，若置位则直接输出级 4，不再看 `WORST`。所以"输入不可读"这种情况不会被同一份输入里其它命中项掩盖——这一点对台账侧尤其重要：一份读不出来的台账不能因为恰好有若干行可解释就被报成级 2。

工程上还要注意：级 4 的 E 类在两个脚本里都带自己的码位（E01、E02、E03），但它们在台账侧的 `emit` 参数写的是级 3；这不矛盾，因为短路的是标志位而不是级参数，输出流的总判定仍是级 4。本文在 23.4 节把这条列为一处需要读者知道的实现细节，避免把它当成脚本 bug。

### 19.3 每层的判级上限

各章给出的上限汇总如下。上限的含义是：**这一层的静态证据最多能把结论推到哪一级，再往下就是别的读者的责任**。

| 层 | 上限 | 为什么封顶在这里 |
| --- | --- | --- |
| L1 用途声明 | 1 | 键存在性、键名封闭集合、空串都能静态判；但"文案是否准确"不行（第 4.4 节），而缺键判定本身依赖读者标注的 `USE` 令牌（第 4.3 节） |
| L2 隐私清单 | 1 | 四个顶层键与数组项结构封闭可判（D08、D12、D13）；但一份文本属于 app 还是 SDK、该不该带清单，要靠读者给出来源（第 5.4、5.6 节） |
| L3 required reason | 3 | 申报文本的语义匹配与申报者意图无机器可读字段（第 6.4 节结论） |
| L4 系统授权决策 | 1 | 四档后果有原句；触发时机不在文本里（18.1） |
| L5 框架状态机 | 1 | 取值集合封闭（45 条配对）；但配对之外的轴缺失只能到级 2 |
| L6 部分授权与精度 | 2 | 折叠点可判（D25、D30）；"limited 集合里到底是哪些资产"不可判（第 9 章） |
| L7 持久化与变更 | 2 | 一次性弹窗与变更来源有原句；用户改过的历史静态侧无读数（第 10 章） |
| L8 继承与传播 | 2 | 静态证据能指出"读数口径混了"，不能指出"权限越界了"（第 11.6 节） |
| L9 SDK 清单与装配 | 1 | 文件名、位置、键结构可判；名单、签名、邮件溯源三项不可判（第 12.4 节） |
| L10 申报与可观测 | 3 | 只能出边界声明；强制资源清单与申报词表不同源（第 13 章） |

### 19.4 四条禁止用法

1. **不得把级当风险排序。** 级 1 的 D19（定位缺键，功能静默不可用）在生产环境里的影响可以远大于级 1 的 D03（文案过短，本文唯一无文档阈值的判定）。级描述的是证据强度，不是后果大小——后果由第 14 章的 P 类与责任方决定。
2. **不得跨脚本比较同一级号。** 19.1 已说明两侧"级 3"含义不同。
3. **不得用命中条数换算健康度。** `WORST` 只取最强一条，输出条数只反映这份文本的缺陷密度，与 18.3 的崩溃计数一样不能作为趋势的唯一读数（第 20 章的每个指标都带分母，就是为了防止这种换算）。
4. **不得把级 4 读成合规。** 级 4 的含义是"这次没有读数"。一份从未被审过的声明与一份干净的声明在级 4 输出里长得一样，区别只在 B 类边界声明的条数上。

### 19.5 判定与责任方正交

同一个级号在不同责任方上对应完全不同的动作。本文第 15 章的矩阵把"层"与"责任方"拆成两列，此处给一个三行例子：

| 输出 | 级 | 责任方 | 正确动作 |
| --- | --- | --- | --- |
| D04 键名不在 69 键表 | 2 | app | 改键名或按自建键说明，属工程内可闭环 |
| D10 SDK 专属码出现在 app 清单 | 1 | 需先判清单来源 | 若这份文本其实来自 SDK 包，本条属误判（第 6.4 节） |
| D28 ATT 的 restricted | 2 | 系统 | 无动作可读，只能补设备策略上下文 |

这也解释了为什么两个脚本的输出格式里"解释"字段是必填的：级号本身不可执行。

---

## 20. 运营指标 O1—O10

判定模型是逐条的，运营需要的是可比数。下面十个指标全部**只依赖两个脚本的输出**加上输入文件本身的分母，不引入新的采集面；每个指标都写明分母、能测什么、不能测什么。所有指标的定义都不含设备读取。

| 指标 | 分子 | 分母 | 读法 |
| --- | --- | --- | --- |
| O1 用途键覆盖率 | 有对应键的 `USE` 令牌数 | `USE` 令牌总数 | 覆盖率高不等于文案对（第 4.4 节）；未标注 `USE` 时该指标无定义，走 B01 |
| O2 文案质量存疑率 | D02 + D03 条数 | 已声明的用途键数 | 只反映形态；D03 无文档阈值，必须与人工复核一起看 |
| O3 键名口径外比例 | D04 条数 | 声明文件里的全部键数 | 自建业务键会稳定推高这项，需按"是否命中受保护资源语义"再分箱 |
| O4 定位/蓝牙键配对完整率 | D05 + D06 条数 | 命中定位或蓝牙用途键的 target 数 | 级 2 指标：分母相同但结论依赖 deployment target，跨工程比较要带该字段 |
| O5 清单结构合规率 | 1 − (D08+D09+D10+D11+D12+D13+D14+D17+D18) 命中的字典项数 / 全部字典项数 | 清单里的数组项总数 | 结构合规与申报为真相互推不出来（第 6.5 节）；这项升高不代表审核风险下降 |
| O6 SDK 专属码越位数 | D10 中命中 `0A2A.1`、`C56D.1` 的条数 | 清单里的 reason code 总数 | 需要清单来源标注；来源标注本身就是不可核验输入（第 12.4 节） |
| O7 台账可解释率 | 1 − D20（字段不足）行数 / 台账行数 | 台账行数 | 台账格式漂移会先反映在这里，再影响其余全部指标 |
| O8 读数—轴完整率 | D26 + D27 条数 | 带 CL 或 UN 读数的主体数 | 补轴成本指标：分母是主体，不是行，避免多行同一主体重复计数 |
| O9 不可分辨读数占比 | D23 + D24 + D28 + D30 条数 | 可解释行数 | 这项**不是缺陷率**，是文档折叠造成的取证上限；升高通常意味着台账覆盖面变宽 |
| O10 边界输出占比 | B 类条数（B01—B05、B10—B13） | 输出总条数 | 本文称之为"诚实度指标"：它衡量的是脚本判定被封顶的位置密度，不衡量被审对象 |

三条使用限制：

1. **趋势只在同一脚本版本、同一输入格式内可比。** O5 的分母在 D17（category 重复）修复前后会变，O7 会先反映出台账导出器的改动，所以任何跨月比较必须同时带 `--quiet` 与否、输入文件名规则、脚本版本三项。
2. **没有指标覆盖"申报与真实行为一致"。** 第 6.3、6.5 节已经说明这件事在离线口径里不可判，O5 与 O6 都只是申报文本的内部一致性，把它们当作合规率上报是一个具体形态的误报（第 24 章误区条目对应）。
3. **指标必须能追到码位。** 每个指标的分子都由固定码位集合构成，这是本文愿意给出这些定义的前提：任何一个不能用〈码位集合，分母口径〉写出来的指标，本文不给出定义，也不建议使用。

---

## 21. 只读核验脚本一：声明口径审查器

### 21.1 它是什么、不是什么

`privacy-declaration-audit.sh` 是一个离线静态审查器，输入是一份**已经导出的声明文本文本**（`Info.plist` 或 `PrivacyInfo.xcprivacy`，或它们的"键 = 值"扁平导出），输出是〈码位，级，解释〉序列加一条总判定。它做的全部事情是把这份文本与本文第 3—6 章固化的词表做集合运算。

它**不**做这些事，脚本头部注释里逐条写明：不写设备、不联网、不修改输入文件、不调用 `plutil`、Xcode 或任何网络接口；中间文件只落在系统临时目录，退出前由 `trap` 删除。它也不"绕过"权限：输入文件读不到时它输出一条 E01 并结束这条输入的判定，不重试、不改权限、不复制到其他位置再读。

还有一条容易被忽略的边界：脚本给的每一条 D 类命中都附"按该文档口径，系统或 App Store Connect 会给什么读数"，这是**对声明文本的口径预演**，不是对任何设备或任何账户的探测。这就是为什么解释字段里出现的是文档句子而不是设备证据。

### 21.2 输入形态与 `USE` 令牌

一份输入支持两种书写形态，脚本都要解析（只用精确 XML 路径匹配会把扁平导出误报成缺键）：

- **形式一**：XML property list，`<key>名称</key>` 与标量值逐行书写，容器用 `<array>`/`<dict>` 嵌套。
- **形式二**：`键 = 值` 或 `键: 值`，每行一个顶层键。

`#` 开头的行与空行不参与判定。以 `USE` 开头的行声明"该产物所属代码用到某类受保护资源"，例如 `USE camera`、`USE photo-library`。这是整套判定的**唯一外部输入**：没有它，缺键类检查（D01、D19）整组跳过并输出 B01。

`USE` 令牌的取值集合是本文自建的 21 个记号（不是 Apple 文档里的东西——文档按具体键名写必配条件，没有令牌表）。令牌的词法是固定的：`USE` 与资源名一律大写输出，资源名用连字符（`photo-library`、`speech-recognition`、`local-network`），文档里没有对应资源名时用键名词干（`tracking` 对应 `NSUserTrackingUsageDescription`）。不在词表内的令牌输出 U00 并跳过配对（夹具 `t11-Info.plist` 用 `USE widget` 触发这一支）。

### 21.3 输出结构

| 前缀 | 含义 | 出现时机 |
| --- | --- | --- |
| V00 | 词表规模与缺键后果分档 | 每次运行头部两条，与输入无关 |
| S00 / S90 | 本条输入的分隔行 / 命中与边界声明计数 | 每个输入文件一对 |
| S98 | 调用形态错误（无参数、临时目录不可用） | 退出码 9 |
| D01—D19 | 口径命中 | 见 21.4 |
| B01—B05 | 边界声明（不是缺陷） | 见 21.6 |
| E01—E03 | 读数不可用：输入不可读 / 二进制 plist / 空文件 | 置 E 标志，总判定为级 4 |
| U00 / P00 | 令牌不在词表 / `NSPrivacy` 键出现在非清单文件里 | 不判违规，只提示归属 |
| J0—J4 | 总判定：无命中（J0）或最强一级 | 每个输入一条 |

退出码语义：0 = 每个输入都取到可用读数；2 = 至少一个输入触发 E 类；9 = 调用形态错误。`-q` 只打印信号码，用于把输出接进第 20 章的指标计数；`-h` 打印用法。

### 21.4 D01—D19 判据表

| 码 | 级 | 判据 | 文档锚点所在章 |
| --- | --- | --- | --- |
| D01 | 1 / 2 / 3 | `USE` 令牌没有对应用途键；级按该键文档写明的后果档取（crash→1，req→2，should→3） | 第 3.4、4.3 节 |
| D02 | 1 | 键存在但值为空串：结构上"有声明"，弹窗里读不到文案 | 第 4.4 节 |
| D03 | 3 | 文案过短或不含空格：本文唯一无文档阈值的判定，报错文案里明说这点 | 第 4.4 节 |
| D04 | 2 / 3 | 键名不在《Protected resources》第 10 到 117 行的 69 键表内（2）；或落在该页第 114—117 行的 Deprecated keys 分组（3） | 第 4.2 节 |
| D05 | 1 / 2 | 只有 `NSLocationAlwaysAndWhenInUseUsageDescription` 而无 WhenInUse（1）；只有 iOS 11 以前的 `NSLocationAlwaysUsageDescription`（2，结论依赖 deployment target） | 第 4.6 节 |
| D06 | 2 | 只有 `NSBluetoothPeripheralUsageDescription`：口径同样依赖 deployment target | 第 4.6 节 |
| D07 | 3 | HealthKit 两个用途键只给一个：文档要求分开写两段文案 | 第 5.4、7.9 节 |
| D08 | 1 | `NSPrivacyTracking` 为 true 但域名数组无元素；或有域名而 tracking 不为 true | 第 5.2 节 |
| D09 | 1 | reason code 不在 17 个已文档化取值里 | 第 6.2 节 |
| D10 | 1 | reason code 属于别的 category；命中 SDK 专属码时降为级 2 并附归属说明 | 第 6.2、6.4 节 |
| D11 | 1 | category 取值不是完整的 `NSPrivacyAccessedAPICategory*` 名 / 缺 `NSPrivacyAccessedAPIType` / Reasons 数组为空 | 第 6.1、6.2 节 |
| D12 | 1 | 收集数据类型取值不在 35 个里 / 四键缺任一 / 收集理由为空 / 理由不在 6 个里 | 第 5.3 节 |
| D13 | 1 | 布尔键的类型不是 Boolean | 第 4.5 节 |
| D14 | 1 | 用途声明键出现在 `PrivacyInfo.xcprivacy` 里 | 第 5.4 节 |
| D15 | 3 | `NSLocationTemporaryUsageDescriptionDictionary` 是空容器 | 第 9.4 节 |
| D16 | 3 | `NSLocationDefaultAccuracyReduced` 类型不是布尔（文档给 true/false 两档，缺键等价 false） | 第 9.3 节 |
| D17 | 3 | 同一 category 在同一份清单里出现多次：合并语义未公开文档化 | 第 6.1 节 |
| D18 | 3 | `NSPrivacyTrackingDomains` 元素形式存疑 | 第 5.2 节 |
| D19 | 1 | `USE` 令牌缺键且后果档为 fail（定位三键）：文档写明请求直接失败而非崩溃 | 第 3.4、7.3 节 |

D01 与 D19 是同一个判据按档位分两条码位，这是刻意设计：把"会崩溃"和"会静默失败"分开，第 18 章与第 20 章的读法不同。

### 21.5 判定图例

脚本在每条输入的最后打印图例，与第 19.1 节引用的定义一致：级 1 命中文档明写的必配规则或封闭取值集合，可直接归责到声明文件本身；级 2 违规成立但结论依赖 deployment target 或未公开的运行时读数；级 3 形态可疑但文档未给唯一处置口径；级 4 本条读数不可用（E 类），不给口径判定。

### 21.6 五条边界声明

B 类不是缺陷，是本文把"这一格需要别的读者"写进输出的机制：

| 码 | 声明内容 | 对应章 |
| --- | --- | --- |
| B01 | 未见 `USE` 令牌行：缺键类检查整组跳过——声明存在不等于代码用到 | 第 5.4 节 |
| B02 | 某键有声明但没有对应 `USE` 令牌：文档把必配条件写成"用到才需要"，反向不成立 | 第 3.5 节 |
| B03 | 只看单份文本无法判定声明归属：SDK 要在自己的清单里申报，app 清单不覆盖 SDK | 第 5.5、11.5 节 |
| B04 | 文件名不是 `Info.plist` 或 `PrivacyInfo.xcprivacy`：无法核对文档规定的 bundle 位置 | 第 12.1 节 |
| B05 | 本地文本无法核对 App Store Connect 隐私标签与清单是否一致 | 第 13 章 |

第 18.1 节说的"脚本对崩溃没有任何读取路径"在输出里就是 B01、B02、B05 这三条：它们共同说明这套静态判定的证据面只有文本本身。

### 21.7 脚本全文

行数：550 行。以下内容由 `.x8-s1.sh` 原样嵌入，与第 23 章验收所用的文件是同一份字节序列。

```bash
#!/bin/bash
# privacy-declaration-audit.sh —— Info.plist 用途声明与 PrivacyInfo.xcprivacy 的离线静态审查器
# 只读：只读取入参文本，不写设备、不联网、不修改输入文件，也不调用 plutil、Xcode 或任何网络接口；
#       中间文件只落在系统临时目录，退出前删除。
# 口径来源：Apple 文档《Protected resources》键名总表、《NSCameraUsageDescription》等用途声明键页、
#           《Requesting authorization to use location services》《Delivering an Enhanced Privacy
#           Experience in Your Photos App》《Protecting user privacy》《NSUserTrackingUsageDescription》、
#           《Privacy manifest files》《NSPrivacyAccessedAPIType》《Describing use of required reason API》
#           《Describing data use in privacy manifests》《Adding a privacy manifest to your app or
#           third-party SDK》的规则表与原句（见本文第 3、4、5 章的引用行号）。
#           每条 D 命中都附「按该口径系统或 App Store Connect 会给什么读数」，
#           是声明文本的口径预演，不是对任何设备或账户的探测。
#
# 输入形态（一个文本文件 = 一份声明产物）：
#   形式一：XML 形式 property list，<key>名称</key> 与标量值逐行书写，容器用 <array>/<dict> 嵌套；
#   形式二：「键 = 值」或「键: 值」文本，每行一个顶层键；
#   以 USE 开头的行声明"该产物所属代码用到某类受保护资源"，例如 `USE camera`；
#   # 开头的行与空行不参与判定。
#
# 用法：  privacy-declaration-audit.sh [-q] [-h] 文件 [文件...]
# 退出码：0 = 每个输入都取到可用读数；2 = 至少一个输入触发 E 类；9 = 调用形态错误。

set -u
LC_ALL=C
export LC_ALL

QUIET=0
CNT_D=0
CNT_B=0
WORST=""
TMPS=""
T=""
KV=""
U=""

usage() {
  printf '%s\n' "用法: $0 [-q] [-h] 文件 [文件...]" \
                "  -q  只打印信号码，不打印解释行" \
                "  -h  打印本帮助"
}

cleanup() { if [ -n "$TMPS" ]; then rm -f $TMPS; TMPS=""; fi; }
trap cleanup EXIT INT TERM

newtmp() { local t; t=$(mktemp 2>/dev/null) || t=""; [ -n "$t" ] && TMPS="$TMPS $t"; printf '%s\n' "$t"; }

emit_text() {
  if [ "$QUIET" = 1 ]; then printf '%s\n' "$1"; else printf '%s  %s\n' "$1" "$2"; fi
}
# emit 码位 级(1|2|3|4) 解释
emit() {
  local code="$1" lv="$2"; shift 2
  CNT_D=$((CNT_D + 1))
  case "$lv" in
    1) WORST=1 ;;
    2) if [ "$WORST" != 1 ]; then WORST=2; fi ;;
    3) if [ -z "$WORST" ]; then WORST=3; fi ;;
    4) if [ -z "$WORST" ]; then WORST=4; fi ;;
  esac
  emit_text "$code" "$*"
}
bound() { CNT_B=$((CNT_B + 1)); emit_text "$1" "$2"; }

# ---- 词表一：资源令牌 → 用途声明键 → 文档给出的缺键后果口径 ----
# mode: crash = 文档写明会崩溃；fail = 文档写明请求直接失败；
#       req = 文档只写「This key is required」未给运行时读数；should = 文档用「should include」
DECL_MAP='camera:NSCameraUsageDescription:req
microphone:NSMicrophoneUsageDescription:req
photo-library:NSPhotoLibraryUsageDescription:crash
photo-library-add:NSPhotoLibraryAddUsageDescription:req
contacts:NSContactsUsageDescription:req
calendar:NSCalendarsUsageDescription|NSCalendarsFullAccessUsageDescription|NSCalendarsWriteOnlyAccessUsageDescription:req
reminders:NSRemindersUsageDescription|NSRemindersFullAccessUsageDescription:req
bluetooth:NSBluetoothAlwaysUsageDescription:req
motion:NSMotionUsageDescription:crash
fall-detection:NSFallDetectionUsageDescription:req
speech-recognition:NSSpeechRecognitionUsageDescription:crash
health:NSHealthShareUsageDescription|NSHealthUpdateUsageDescription:crash
homekit:NSHomeKitUsageDescription:req
siri:NSSiriUsageDescription:req
local-network:NSLocalNetworkUsageDescription:should
location-ios:NSLocationWhenInUseUsageDescription:fail
location-always:NSLocationAlwaysAndWhenInUseUsageDescription:req
location-macos:NSLocationUsageDescription:req
tracking:NSUserTrackingUsageDescription:crash
apple-music:NSAppleMusicUsageDescription:req
face-id:NSFaceIDUsageDescription:req'

# ---- 词表一补充：文档《Protected resources》页第 10—117 行按分组列出的全部受保护资源键名，共 69 个 ----
# 该页 Overview 段的口径原句是「The topics below list the keys you use to provide usage-description
# strings for protected resources」，所以这 69 个键名是文档给出的闭合集合，不是本轮抓取恰好碰到的键。
# 其中第 114—117 行单独分成 Deprecated keys 一组（NSCalendarsUsageDescription、
# NSEnterpriseMCAMUsageDescription、NSRemindersUsageDescription）；第 55、57、79、87、88、90、91、
# 112 行列出的 NSLocationTemporaryUsageDescriptionDictionary、NSWidgetWantsLocation、NSUpdateSecurityPolicy、
# ITSAppUsesNonExemptEncryption、ITSEncryptionExportComplianceCode、NSSensorKitUsageDetail、
# NSSensorKitPrivacyPolicyURL、UIRequiresPersistentWiFi 不是用途串，本审查器只把它们当作合法键名放行。
KNOWN_USAGE='ITSAppUsesNonExemptEncryption
ITSEncryptionExportComplianceCode
NFCReaderUsageDescription
NSAccessoryTrackingUsageDescription
NSAppBundlesUsageDescription
NSAppDataUsageDescription
NSAppleEventsUsageDescription
NSAppleMusicUsageDescription
NSAppleScriptEnabled
NSAudioCaptureUsageDescription
NSBluetoothAlwaysUsageDescription
NSBluetoothPeripheralUsageDescription
NSCalendarsFullAccessUsageDescription
NSCalendarsUsageDescription
NSCalendarsWriteOnlyAccessUsageDescription
NSCameraUsageDescription
NSContactsUsageDescription
NSCriticalMessagingUsageDescription
NSDesktopFolderUsageDescription
NSDocumentsFolderUsageDescription
NSDownloadsFolderUsageDescription
NSEnterpriseMCAMUsageDescription
NSFaceIDUsageDescription
NSFallDetectionUsageDescription
NSFileProviderDomainUsageDescription
NSFileProviderPresenceUsageDescription
NSFinancialDataUsageDescription
NSGKFriendListUsageDescription
NSHandsTrackingUsageDescription
NSHealthClinicalHealthRecordsShareUsageDescription
NSHealthRequiredReadAuthorizationTypeIdentifiers
NSHealthShareUsageDescription
NSHealthUpdateUsageDescription
NSHomeKitUsageDescription
NSIdentityUsageDescription
NSIdentityUsageDescriptionDictionary
NSLocalNetworkUsageDescription
NSLocationAlwaysAndWhenInUseUsageDescription
NSLocationAlwaysUsageDescription
NSLocationDefaultAccuracyReduced
NSLocationTemporaryUsageDescriptionDictionary
NSLocationUsageDescription
NSLocationWhenInUseUsageDescription
NSMainCameraUsageDescription
NSMicrophoneUsageDescription
NSMotionUsageDescription
NSNearbyInteractionAllowOnceUsageDescription
NSNearbyInteractionUsageDescription
NSNetworkVolumesUsageDescription
NSPhotoLibraryAddUsageDescription
NSPhotoLibraryUsageDescription
NSRemindersFullAccessUsageDescription
NSRemindersUsageDescription
NSRemovableVolumesUsageDescription
NSSensorKitPrivacyPolicyURL
NSSensorKitUsageDescription
NSSensorKitUsageDetail
NSSiriUsageDescription
NSSpeechRecognitionUsageDescription
NSSystemAdministrationUsageDescription
NSSystemExtensionUsageDescription
NSUpdateSecurityPolicy
NSUserTrackingMarkdownUsageDescription
NSUserTrackingUsageDescription
NSVideoSubscriberAccountUsageDescription
NSWidgetWantsLocation
NSWorldSensingUsageDescription
OSBundleUsageDescription
UIRequiresPersistentWiFi'

# 同一页第 114—117 行的 Deprecated keys 分组：文档把它们和其余键并列列出、也给了说明串文案，
# 但没有在本页声明「读到就忽略」，所以本审查器不把它们算成缺键，只单独记一条低阶信号。
DEPRECATED_USAGE='NSCalendarsUsageDescription
NSEnterpriseMCAMUsageDescription
NSRemindersUsageDescription'

# ---- 词表二：17 个 required reason code → 所属 category ----
REASON_MAP='DDA9.1	FileTimestamp
C617.1	FileTimestamp
3B52.1	FileTimestamp
0A2A.1	FileTimestamp
35F9.1	SystemBootTime
8FFB.1	SystemBootTime
3D61.1	SystemBootTime
85F4.1	DiskSpace
E174.1	DiskSpace
7D9E.1	DiskSpace
B728.1	DiskSpace
3EC4.1	ActiveKeyboards
54BD.1	ActiveKeyboards
CA92.1	UserDefaults
1C8F.1	UserDefaults
C56D.1	UserDefaults
AC6B.1	UserDefaults'

# 文档给出的五个 category 取值都带 NSPrivacyAccessedAPICategory 前缀（《NSPrivacyAccessedAPIType》
# 第 6、25、32、51、56 行的 VALUE 行）；下面保留短名只用于拼进 D11 的报错文案。
CATS='NSPrivacyAccessedAPICategoryFileTimestamp NSPrivacyAccessedAPICategorySystemBootTime NSPrivacyAccessedAPICategoryDiskSpace NSPrivacyAccessedAPICategoryActiveKeyboards NSPrivacyAccessedAPICategoryUserDefaults'
CATS_SHORT='FileTimestamp SystemBootTime DiskSpace ActiveKeyboards UserDefaults'

# ---- 词表二补充 A：35 个已文档化收集数据类型（《NSPrivacyCollectedDataType》第 6—40 行的 VALUE 行） ----
COLLECTED='NSPrivacyCollectedDataTypeName
NSPrivacyCollectedDataTypeEmailAddress
NSPrivacyCollectedDataTypePhoneNumber
NSPrivacyCollectedDataTypePhysicalAddress
NSPrivacyCollectedDataTypeOtherUserContactInfo
NSPrivacyCollectedDataTypeHealth
NSPrivacyCollectedDataTypeFitness
NSPrivacyCollectedDataTypePaymentInfo
NSPrivacyCollectedDataTypeCreditInfo
NSPrivacyCollectedDataTypeOtherFinancialInfo
NSPrivacyCollectedDataTypePreciseLocation
NSPrivacyCollectedDataTypeCoarseLocation
NSPrivacyCollectedDataTypeSensitiveInfo
NSPrivacyCollectedDataTypeContacts
NSPrivacyCollectedDataTypeEmailsOrTextMessages
NSPrivacyCollectedDataTypePhotosorVideos
NSPrivacyCollectedDataTypeAudioData
NSPrivacyCollectedDataTypeGameplayContent
NSPrivacyCollectedDataTypeCustomerSupport
NSPrivacyCollectedDataTypeOtherUserContent
NSPrivacyCollectedDataTypeBrowsingHistory
NSPrivacyCollectedDataTypeSearchHistory
NSPrivacyCollectedDataTypeUserID
NSPrivacyCollectedDataTypeDeviceID
NSPrivacyCollectedDataTypePurchaseHistory
NSPrivacyCollectedDataTypeProductInteraction
NSPrivacyCollectedDataTypeAdvertisingData
NSPrivacyCollectedDataTypeOtherUsageData
NSPrivacyCollectedDataTypeCrashData
NSPrivacyCollectedDataTypePerformanceData
NSPrivacyCollectedDataTypeOtherDiagnosticData
NSPrivacyCollectedDataTypeEnvironmentScanning
NSPrivacyCollectedDataTypeHands
NSPrivacyCollectedDataTypeHead
NSPrivacyCollectedDataTypeOtherDataTypes'

# ---- 词表二补充 B：6 个已文档化收集理由（《NSPrivacyCollectedDataTypePurposes》第 6—11 行） ----
PURPOSES='NSPrivacyCollectedDataTypePurposeThirdPartyAdvertising
NSPrivacyCollectedDataTypePurposeDeveloperAdvertising
NSPrivacyCollectedDataTypePurposeAnalytics
NSPrivacyCollectedDataTypePurposeProductPersonalization
NSPrivacyCollectedDataTypePurposeAppFunctionality
NSPrivacyCollectedDataTypePurposeOther'

# ---- 崩溃口径的文档原句（逐字取自各键页与概念页，见第 4 章 R4 表） ----
CRASH_Q='speech-recognition	If this key isn’t present, your app crashes when it calls requestAuthorization(_:).
motion	If you don’t include this key, your app will crash when it attempts to access motion data.
tracking	Your app crashes if it attempts to use the App Tracking Transparency framework without including the key in your target’s properties in Xcode.
photo-library	Attempting to access the Photos library without a valid usage description causes your app to crash.
health	Apps must include usage descriptions, or it will crash when you request authorization to access HealthKit data.'
MODE_TEXT="crash:文档写明缺该键时 app 崩溃|fail:文档写明「Authorization requests fail immediately if the required keys aren't present」|req:文档只声明「This key is required」，未给运行时读数|should:文档用「should include」，属建议级"

is_usage_key() {
  printf '%s' "$1" | grep -Eq '^(NS|NFC|OS)[A-Za-z]*UsageDescription$|^NSLocationTemporaryUsageDescriptionDictionary$'
}

# 容器键的存在性判定：flatten 对非空数组只下发〈路径[n]〉行，对空容器下发〈路径〉行，
# 两种形态都要算「这个键在文件里出现过」；只用精确路径匹配会把写全了的清单误报成缺键。
has_key() {
  awk -F'\t' -v d="$1" -v q="$2" '
    { p = $1; pre = d "." q "["
      if (p == d "." q || substr(p, 1, length(pre)) == pre) f = 1 }
    END { exit !f }' "$T"
}

# ---- 解析：把任意深度展开成「路径<TAB>类型<TAB>值」 ----
flatten() {
  awk '
    function trim(s) { gsub(/^[ \t]+|[ \t]+$/, "", s); return s }
    function emitv(t, v,   p) {
      p = (top > 0 && isarr[top]) ? pfx[top] "[" (++idx[top]) "]" : pfx[top]
      if (cur != "") p = (p == "" ? cur : p "." cur)
      printf "%s\t%s\t%s\n", p, t, v
      cur = ""
    }
    BEGIN { top = 0; cur = ""; pfx[0] = "" }
    {
      line = trim($0)
      if (line == "" || line ~ /^#/) next

      if (match(line, /<key>[^<]*<\/key>/)) {
        cur = substr(line, RSTART + 5, RLENGTH - 11)
        line = trim(substr(line, RSTART + RLENGTH))
        if (line == "") next
      }

      if (line ~ /^<(array|dict)>/) {
        iskids = (substr(line, 2, 5) == "array")
        base = (top > 0 && isarr[top]) ? pfx[top] "[" (++idx[top]) "]" : pfx[top]
        if (cur != "") base = (base == "" ? cur : base "." cur)
        top++; isarr[top] = iskids; pfx[top] = base; idx[top] = 0; cur = ""
        next
      }
      if (line ~ /^<\/(array|dict)>$/) { if (top > 0) top--; cur = ""; next }
      if (line ~ /^<(array|dict)\/>/) { emitv("empty", ""); next }

      if (match(line, /<string>[^<]*<\/string>/)) { emitv("string", substr(line, RSTART + 8, RLENGTH - 17)); next }
      if (line ~ /^<true\/>/)   { emitv("bool", "true"); next }
      if (line ~ /^<false\/>/)  { emitv("bool", "false"); next }
      if (match(line, /<integer>[^<]*<\/integer>/)) { emitv("integer", substr(line, RSTART + 9, RLENGTH - 19)); next }

      if (match(line, /^[A-Za-z][A-Za-z0-9_.]*[ \t]*[=:][ \t]*/)) {
        k = line; sub(/[ \t]*[=:].*/, "", k)
        v = line; sub(/^[^=:]*[=:][ \t]*/, "", v)
        cur = trim(k); emitv("string", trim(v)); next
      }
    }
  ' "$1"
}

# 路径首段（去掉 [n] 与其后的 .sub）
key_of() { awk -F'\t' '{p=$1; sub(/\[.*/, "", p); sub(/\..*/, "", p); print p "\t" $2 "\t" $3}' "$1"; }

give_verdict() {
  case "$WORST" in
    1) emit_text J1 "判定：级 1 —— 命中文档明写的必配规则或封闭取值集合，可直接归责到声明文件本身" ;;
    2) emit_text J2 "判定：级 2 —— 违规成立但结论依赖 deployment target 或未公开的运行时读数，需按工程配置再收敛一次" ;;
    3) emit_text J3 "判定：级 3 —— 形态可疑但文档未给唯一处置口径，需要人工确认用途" ;;
    4) emit_text J4 "判定：级 4 —— 本条读数不可用（见上方 E 类），不给口径判定" ;;
    "") emit_text J0 "判定：声明侧未见本文口径内的违规；这不等于运行时授权正确，也不等于申报一致（见 B01、B03、B05）" ;;
  esac
}

audit_one() {
  local f="$1"
  [ -r "$f" ] || { emit E01 4 "输入不可读或不存在"; give_verdict; return 1; }
  # -r 在部分平台上对 ACL 拒绝不敏感，再做一次真实读取探测
  head -n 1 "$f" >/dev/null 2>&1 || { emit E01 4 "输入存在但读不到内容（权限或独占占用）：本审查器不重试、不绕过权限，只记为不可用读数"; give_verdict; return 1; }
  [ -s "$f" ] || { emit E03 4 "空文件：没有可审的声明"; give_verdict; return 1; }
  if head -c 8 "$f" | grep -q 'bplist00'; then emit E02 4 "binary plist：本文口径按文本 plist 建立，需要先把 plist 转成文本再审"; give_verdict; return 1; fi

  flatten "$f" > "$T"
  [ -s "$T" ] || { emit E03 4 "未取到任何键值对：既不是 <key> 形式，也不是「键 = 值」形式"; give_verdict; return 1; }
  key_of "$T" | sort -u > "$KV"

  local name; name=$(basename "$f")
  local is_manifest=0
  case "$name" in *PrivacyInfo.xcprivacy) is_manifest=1 ;; esac

  # ---- 1) 资源令牌 ↔ 用途声明键配对（D01 / D19） ----
  grep -E '^USE[ \t]' "$f" | awk '{print tolower($2)}' | sort -u > "$U"
  if [ ! -s "$U" ]; then
    bound B01 "未见 USE 令牌行：缺键类检查（D01、D19）整组跳过。声明存在不等于使用，声明缺席也不等于未使用——本审查器无法从声明文本反推代码是否真的调用受保护 API"
  else
    local tok need mode have k needtxt cq
    while read -r tok; do
      [ -n "$tok" ] || continue
      need=$(printf '%s\n' "$DECL_MAP" | awk -F: -v t="$tok" '$1==t{print $2}')
      mode=$(printf '%s\n' "$DECL_MAP" | awk -F: -v t="$tok" '$1==t{print $3}')
      if [ -z "$need" ]; then emit_text U00 "USE 令牌 $tok 不在本文词表内，配对跳过"; continue; fi
      needtxt=$(printf '%s' "$need" | tr '|' ' ')
      cq=$(printf '%s\n' "$CRASH_Q" | awk -F'\t' -v t="$tok" '$1 == t {print $2}')
      have=""
      local IFS='|'
      for k in $need; do
        awk -F'\t' -v k2="$k" '{p=$1; sub(/\[.*/, "", p); sub(/\..*/, "", p); if (p == k2) f = 1} END {exit !f}' "$T" && have="$have $k"
      done
      unset IFS
      if [ -z "$have" ]; then
        case "$mode" in
          fail)  emit D19 1 "USE $tok 没有任何用途声明键（文档列出的必配键：$needtxt）—— 文档给出的运行时读数是请求直接失败：Authorization requests fail immediately if the required keys aren't present（授权请求侧看不到崩溃，只看到状态停在 notDetermined）" ;;
          crash) emit D01 1 "USE $tok 没有任何用途声明键（文档列出的必配键：$needtxt）—— 文档给出的运行时读数是 app 崩溃，崩溃点在调用 API 时而不是弹窗时：$cq" ;;
          req)   emit D01 2 "USE $tok 没有任何用途声明键（文档列出的必配键：$needtxt）—— 文档只写 This key is required，未公开该情形下系统的统一读数，需要按目标系统再核" ;;
          should) emit D01 3 "USE $tok 没有任何用途声明键（文档列出的键：$needtxt）—— 文档口径是 should include this description，属建议级，不构成确定的口径违规" ;;
        esac
      fi
    done < "$U"
    local tokp
    while IFS=$'\t' read -r k t v; do
      case "$k" in *UsageDescription) ;; *) continue ;; esac
      tokp=$(printf '%s\n' "$DECL_MAP" | awk -F: -v k2="$k" '{split($2, a, "|"); for (i in a) if (a[i] == k2) { print $1; exit } }')
      [ -n "$tokp" ] || continue
      grep -qxF "$tokp" "$U" || bound B02 "键 $k 有声明但没有 USE $tokp 令牌：文档把必配条件写成 This key is required if your app uses APIs that access the device's camera，声明过剩会否被拒、系统对多余声明给什么读数，取不到原句，本条只记边界"
    done < "$KV"
  fi

  # ---- 2) 用途键自身形态（D02 / D03 / D14 / D16 / D13 / D15） ----
  local k t v
  while IFS=$'\t' read -r k t v; do
    [ -n "$k" ] || continue
    if is_usage_key "$k"; then
      if [ "$t" = "empty" ] || [ -z "$(printf '%s' "$v" | tr -d ' \t')" ]; then
        emit D02 1 "$k 取值为空串：文档要求该键承载给人读的用途说明，键存在但值为空仍算「有声明」，弹窗会给出一条无内容的说明"
      elif [ "$(printf '%s' "$v" | wc -c)" -lt 12 ] && ! printf '%s' "$v" | grep -q '[ ]'; then
        emit D03 3 "$k 取值 \"$v\" 无空格且长度不足：口径上系统仍会原样展示，但读者无法据此判断用途；文档要求 user-readable description"
      fi
      [ "$is_manifest" = 1 ] && emit D14 1 "用途声明键 $k 出现在 PrivacyInfo.xcprivacy 里：文档把这类键归入 Information Property List，隐私清单的顶层键只有四个 NSPrivacy 前缀键"
    fi
    case "$k" in
      NS*Usage*|NFC*Usage*|OSBundleUsageDescription)
        if printf '%s\n' "$DEPRECATED_USAGE" | grep -qxF "$k"; then
          emit D04 3 "键名 $k 落在文档《Protected resources》第 114—117 行的 Deprecated keys 分组里：该页仍列出并给出说明串，所以系统侧按有效声明读取；本审查器按缺键口径处理不了它，只在归属矩阵里把它标成「已弃用但可读」"
        elif ! is_usage_key "$k" && ! printf '%s\n' "$KNOWN_USAGE" | grep -qxF "$k"; then
          emit D04 2 "键名 $k 不在文档《Protected resources》第 10—117 行按分组列出的 69 个受保护资源键名里：文档的必配口径按具体键名书写（This key is required if your app uses APIs that access the device's camera），键名对不上时系统读不到该键，按缺键口径处理；本条不判级 1，因为无法排除它是自建业务键"
        fi ;;
    esac
    case "$k" in
      NSPrivacyTracking)
        [ "$t" = "bool" ] || emit D13 1 "NSPrivacyTracking 类型是 $t 而不是 Boolean：文档口径为 A Boolean that indicates whether your app or third-party SDK uses data for tracking" ;;
      NSLocationDefaultAccuracyReduced)
        [ "$t" = "bool" ] || emit D16 3 "NSLocationDefaultAccuracyReduced 类型是 $t 而不是 Boolean：文档给出 true/false 两档语义，且「If you don't include that key in your Info.plist, that's equivalent to setting it to false」" ;;
      NSLocationTemporaryUsageDescriptionDictionary)
        [ "$t" = "empty" ] && emit D15 3 "NSLocationTemporaryUsageDescriptionDictionary 是空容器：没有 purpose key，就无法按 requestTemporaryFullAccuracyAuthorization(withPurposeKey:) 取用临时全精度授权" ;;
    esac
    case "$k" in NSPrivacy*) if [ "$is_manifest" = 0 ]; then emit_text P00 "NSPrivacy 键 $k 出现在 $name 里：文档把 NSPrivacy* 归入隐私清单而非 Info.plist；合并产物可能同时含两者，本条不判违规"; fi ;; esac
  done < "$KV"

  # ---- 3) 跨键配对（D05 / D06 / D07） ----
  g() { awk -F'\t' -v k2="$1" '{p=$1; sub(/\[.*/, "", p); sub(/\..*/, "", p); if (p == k2) f = 1} END {if (f) print "y"}' "$T"; }
  if [ "$(g NSLocationAlwaysAndWhenInUseUsageDescription)" = y ] && [ "$(g NSLocationWhenInUseUsageDescription)" != y ]; then
    emit D05 1 "只有 NSLocationAlwaysAndWhenInUseUsageDescription 而无 NSLocationWhenInUseUsageDescription：文档口径为 You must include a usage description string for When in Use access，Always 串是附加项"
  fi
  if [ "$(g NSLocationAlwaysUsageDescription)" = y ] && [ "$(g NSLocationAlwaysAndWhenInUseUsageDescription)" != y ]; then
    emit D05 2 "只有 iOS 11 以前的 NSLocationAlwaysUsageDescription：文档要求 deployment target 早于 iOS 11 时两个键都写且消息相同；只写旧键在新系统上不构成有效声明"
  fi
  if [ "$(g NSBluetoothPeripheralUsageDescription)" = y ] && [ "$(g NSBluetoothAlwaysUsageDescription)" != y ]; then
    emit D06 2 "只有 NSBluetoothPeripheralUsageDescription：文档口径为 deployment target 为 iOS 13 及以后要改用 NSBluetoothAlwaysUsageDescription，更早版本两个键都要"
  fi
  local hs hu
  hs=$(g NSHealthShareUsageDescription); hu=$(g NSHealthUpdateUsageDescription)
  if { [ "$hs" = y ] && [ "$hu" != y ]; } || { [ "$hu" = y ] && [ "$hs" != y ]; }; then
    emit D07 3 "HealthKit 两个用途键只提供一个：文档写明 Xcode requires separate custom messages for reading and writing HealthKit data；只配一个是否违规取决于 app 是只读还是只写，本审查器无法从声明文本判定"
  fi

  # ---- 4) 隐私清单一致性（D08 / D09 / D10 / D11 / D12 / D17） ----
  local trk ndoms
  trk=$(awk -F'\t' '$1 == "NSPrivacyTracking" {print $3}' "$KV" | head -1)
  ndoms=$(awk -F'\t' '$1 ~ /^NSPrivacyTrackingDomains\[/{n++} END{print n + 0}' "$T")
  if [ "$trk" = true ] && [ "$ndoms" = 0 ]; then
    emit D08 1 "NSPrivacyTracking 为 true 但 NSPrivacyTrackingDomains 无元素：文档口径 When set to true you need to provide a list of internet domains in NSPrivacyTrackingDomains"
  fi
  if [ "$ndoms" != 0 ] && [ "$trk" != true ]; then
    emit D08 1 "NSPrivacyTrackingDomains 有 $ndoms 个元素但 NSPrivacyTracking 不是 true：文档口径 To provide a list of internet domains in NSPrivacyTrackingDomains, set NSPrivacyTracking to true；按《NSPrivacyTrackingDomains》页，用户未授予追踪授权时对这些域名的网络请求会失败并报错误"
  fi

  local dom bad18=""
  while read -r dom; do
    [ -n "$dom" ] || continue
    printf '%s' "$dom" | grep -Eq '^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$' \
      || bad18="$bad18 $dom"
  done <<EOF
$(awk -F'\t' '$1 ~ /^NSPrivacyTrackingDomains\[[0-9]+\]$/ {print $3}' "$T")
EOF
  [ -n "$bad18" ] && emit D18 3 "NSPrivacyTrackingDomains 元素形式存疑：$bad18 —— 文档口径是 A list of the internet domains your app or third-party SDK uses for tracking；带 scheme 前缀、带路径或含空格的值不在文档描述的形式里，这类值怎样参与「network requests to these domains fail and your app receives an error」的匹配未公开文档化"

  local d cur_cat cshort rc own ncode codes seen_cats=""
  for d in $(awk -F'\t' '$1 ~ /^NSPrivacyAccessedAPITypes\[[0-9]+\]\./{p=$1; sub(/\..*/, "", p); print p}' "$T" | sort -u); do
    cur_cat=$(awk -F'\t' -v d="$d" '$1 == d ".NSPrivacyAccessedAPIType" {print $3}' "$T" | head -1)
    if [ -z "$cur_cat" ]; then
      emit D11 1 "$d 缺 NSPrivacyAccessedAPIType：文档要求每个字典都要同时含 NSPrivacyAccessedAPIType 与 NSPrivacyAccessedAPITypeReasons 两个键"
      continue
    fi
    case " $CATS " in
      *" $cur_cat "*) cshort=${cur_cat#NSPrivacyAccessedAPICategory} ;;
      *) emit D11 1 "$d 的 category 取值 \"$cur_cat\" 不在文档列出的五类里（$CATS）：《Describing use of required reason API》第 11 行口径 The value you provide must be one of the values listed in the sections below；注意文档取值带 NSPrivacyAccessedAPICategory 前缀，只写短名同样落在取值集合之外"; continue ;;
    esac
    if printf '%s\n' "$seen_cats" | grep -qxF "$cur_cat"; then
      emit D17 3 "category $cur_cat 在同一份清单里出现多次：文档按「每个用到的 category 加一个字典」描述，重复字典的聚合与合并语义未公开文档化"
    fi
    seen_cats="$seen_cats
$cur_cat"
    codes=$(awk -F'\t' -v pre="$d.NSPrivacyAccessedAPITypeReasons[" '$1 {p=$1; if (substr(p,1,length(pre)) == pre && substr(p,length(p),1) == "]") print $3}' "$T")
    ncode=$(printf '%s\n' "$codes" | grep -c . || true)
    if [ "$ncode" = 0 ]; then
      emit D11 1 "$d（category $cur_cat）的 NSPrivacyAccessedAPITypeReasons 没有元素：文档口径 must declare one or more approved reasons that accurately reflect your use"
      continue
    fi
    while read -r rc; do
      [ -n "$rc" ] || continue
      own=$(printf '%s\n' "$REASON_MAP" | awk -F'\t' -v c="$rc" '$1 == c {print $2}')
      if [ -z "$own" ]; then
        emit D09 1 "reason code \"$rc\" 不在 17 个已文档化取值里：《NSPrivacyAccessedAPIType》第 20 行口径 In your NSPrivacyAccessedAPITypeReasons array, supply the relevant values from this list；按《Adding a privacy manifest to your app or third-party SDK》第 5、6 行，All privacy manifest files in your app must be valid, containing only the expected keys and values，且 App Store Connect rejects app submissions that include invalid privacy manifest files，回信里会给出无效文件的名称与路径"
      elif [ "$own" != "$cshort" ]; then
        emit D10 1 "reason code $rc 属 $own 类，却声明在 ${cshort}（$cur_cat）类下：文档口径 The values you provide must be the values associated with the accessed API type"
      fi
    done <<EOF
$codes
EOF
  done

  for d in $(awk -F'\t' '$1 ~ /^NSPrivacyCollectedDataTypes\[[0-9]+\]\./{p=$1; sub(/\..*/, "", p); print p}' "$T" | sort -u); do
    local miss4="" q
    for q in NSPrivacyCollectedDataType NSPrivacyCollectedDataTypeLinked NSPrivacyCollectedDataTypeTracking NSPrivacyCollectedDataTypePurposes; do
      has_key "$d" "$q" || miss4="$miss4 $q"
    done
    [ -n "$miss4" ] && emit D12 1 "$d 缺文档要求的键：$miss4 ——四个键共同决定该数据类型在隐私报告与 App Store 隐私标签里的位置"
    local lk np pv pvs badp=""
    lk=$(awk -F'\t' -v d="$d" '$1 == d ".NSPrivacyCollectedDataType" {print $3}' "$T" | head -1)
    if [ -n "$lk" ] && ! printf '%s\n' "$COLLECTED" | grep -qxF -- "$lk"; then
      emit D12 1 "NSPrivacyCollectedDataType 取值 \"$lk\" 不在 35 个已文档化数据类型里：《NSPrivacyCollectedDataType》第 6—40 行给出封闭取值集合（NSPrivacyCollectedDataType 前缀 + 数据类型名），第 45 行口径 Choose the value that matches the data your app or third-party SDK collects；《Describing data use in privacy manifests》第 13 行写明 Xcode won't generate a privacy report correctly if you define your own collected data types for the NSPrivacyCollectedDataType key, or provide your own reasons for the NSPrivacyCollectedDataTypePurposes key"
    fi
    # Linked / Tracking 两个键文档都写成 Boolean；D13 的取值口径同样适用于它们
    for q in NSPrivacyCollectedDataTypeLinked NSPrivacyCollectedDataTypeTracking; do
      local qt
      qt=$(awk -F'\t' -v d="$d" -v q="$q" '$1 == d "." q {print $2}' "$T" | head -1)
      [ -n "$qt" ] && [ "$qt" != "bool" ] && emit D13 1 "$d 的 $q 类型是 $qt 而不是 Boolean：文档口径 A Boolean that indicates whether your app or third-party SDK links this data type to the user's identity / uses this data type to track"
    done
    np=$(awk -F'\t' -v pre="$d.NSPrivacyCollectedDataTypePurposes[" '$1 {p=$1; if (substr(p,1,length(pre)) == pre && substr(p,length(p),1) == "]") n++ } END {print n + 0}' "$T")
    [ "$np" = 0 ] && emit D12 1 "$d 的 NSPrivacyCollectedDataTypePurposes 没有元素：文档要求为每个收集的数据类型列出收集理由"
    pvs=$(awk -F'\t' -v pre="$d.NSPrivacyCollectedDataTypePurposes[" '$1 {p=$1; if (substr(p,1,length(pre)) == pre && substr(p,length(p),1) == "]") print $3}' "$T")
    while read -r pv; do
      [ -n "$pv" ] || continue
      printf '%s\n' "$PURPOSES" | grep -qxF -- "$pv" || badp="$badp $pv"
    done <<EOF
$pvs
EOF
    for pv in $badp; do
      emit D12 1 "$d 的收集理由 \"$pv\" 不在 6 个已文档化取值里：《NSPrivacyCollectedDataTypePurposes》第 6—11 行给出封闭集合，文档口径同上第 13 行（provide your own reasons for the NSPrivacyCollectedDataTypePurposes key 会让隐私报告生成不正确）"
    done
  done

  # ---- 5) 文件身份与归属边界 ----
  case "$name" in
    *Info.plist | *PrivacyInfo.xcprivacy) : ;;
    *) bound B04 "文件名 $name 不是 Info.plist 或 PrivacyInfo.xcprivacy：无法核对文档规定的 bundle 位置（iOS app 放 bundle 根，macOS app 放 Contents/Resources/，framework 与 Swift package 另有各自路径），位置错则系统读不到" ;;
  esac
  bound B03 "只看单份文本无法判定声明归属：文档要求 SDK 在自己的清单里申报 required reason API 与收集数据，app 的清单不覆盖 SDK 的数据收集，SDK 也不能依赖宿主 app 的清单替它申报"
  bound B05 "本地文本无法核对 App Store Connect 的隐私标签申报与清单是否一致；申报口径要在服务端与隐私报告产物里核对，本审查器不给结论"

  give_verdict
  [ "$WORST" = 4 ] && return 1
  return 0
}

# ---- 主流程 ----
if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then usage; exit 0; fi
if [ "${1:-}" = "-q" ]; then QUIET=1; shift; fi
if [ "$#" = 0 ]; then
  emit_text S98 "未提供输入文件"
  usage >&2
  exit 9
fi
emit_text V00 "词表规模：69 个受保护资源键名（其中 3 个在文档的 Deprecated keys 分组）、21 个 USE 令牌、5 类 required reason（取值带 NSPrivacyAccessedAPICategory 前缀）与 17 个 reason code、35 个收集数据类型与 6 个收集理由"
emit_text V00 "缺键后果口径分档：$MODE_TEXT"

T=$(newtmp); KV=$(newtmp); U=$(newtmp)
# newtmp 在 mktemp 失败时返回空串，必须在这里一次性探可写性；否则后续 `: > ""` 只会泄漏 shell 报错
for p in "$T" "$KV" "$U"; do
  [ -n "$p" ] && : > "$p" 2>/dev/null && [ -w "$p" ] && continue
  emit_text S98 "临时目录不可用：无法建立中间文件，本审查器不落地执行"
  exit 9
done
bad=0
for f in "$@"; do
  CNT_D=0; CNT_B=0; WORST=""
  : > "$T"; : > "$KV"; : > "$U"
  emit_text S00 "=== 审查 $f ==="
  audit_one "$f" || bad=1
  emit_text S90 "本条计数：口径命中 $CNT_D 条、边界声明 $CNT_B 条"
done

[ "$bad" = 1 ] && exit 2
exit 0
```

---

## 22. 只读核验脚本二：授权台账分诊器

### 22.1 输入是一份导出台账，不是设备读数

`privacy-state-ledger-triage.sh` 处理的是**读者自己已经采集好的文本台账**——脚本头部注释写明"台账应来自读者自家 app 日志或自有导出件的脱敏结果"。这一点决定了它的定位：它不调用任何框架去重新询问授权状态，不写设备、不联网、不修改输入，中间文件同样只在系统临时目录并退出前删除。

它也不核对主体标注是否为真（第 22.5 节 B10）。台账里写"用户 u1 的相机是 authorized"，脚本能判的是这条读数与文档枚举口径是否相容，不能判这条读数是不是当时真的取到的。

### 22.2 台账格式

每行 3—4 个空白分隔字段：〈框架代号〉〈读数〉〈主体代号〉〈标签〉，标签可省略。

- **框架代号（11 个）**：`CL` `CLACC` `AV` `PH` `CN` `CB` `HK` `ATT` `UN` `UNS` `SPEECH`，对应第 8 章的 11 组枚举帧。不在表内的代号触发 D20 并整行跳过。
- **标签记号**：`requested`、`read`、`legacy`、`accuracy=reduced`、`via=settings`，逗号分隔。这五个记号是本文把"文档说了但静态无法证明"的信息交还给读者的方式——它们不是从设备取来的，是读者补的。
- `#` 开头为注释行；空行跳过。

字段不足 3 个的行不参与评论，累计进"不可解释行"计数（T00 打印），全部行都不可解释时输出 E03。

### 22.3 D20—D30 判据表

| 码 | 级 | 判据 | 文档锚点所在章 |
| --- | --- | --- | --- |
| D20 | 1 / 2 | 框架代号不在 11 组枚举里（1，整行跳过）；字段不足 3 个（2，只计入不可解释行） | 第 8.2 节 |
| D21 | 1 | 该帧的取值不在文档给出的封闭集合里（45 条配对之外） | 第 8.2、8.3 节 |
| D22 | 1 | 取值合法但用错了帧（跨帧取值） | 第 8.3 节 |
| D23 | 3 | `CL/denied` 二义：同一枚举条目同时涵盖"用户拒绝"与"全局关闭" | 第 8.4 节 |
| D24 | 3 | HK 行带 read 语义：该页只有三个 sharing 侧取值，读侧不可见 | 第 8.5、9.5 节 |
| D25 | 1 | PH 行标了 legacy：文档写明旧接口对 limited 也返回 authorized | 第 8.6、9.1 节 |
| D26 | 2 | 有 CL 读数但没有同主体的 CLACC 行：精度是正交的第二条轴 | 第 9.3 节 |
| D27 | 2 | UN 读数缺同主体的 UNS 行：provisional/ephemeral 与设置项状态是两条轴 | 第 8.4、10.3 节 |
| D28 | 2 | `ATT/restricted`：文档写明该取值与"是否弹过窗"无关 | 第 8.4 节 |
| D29 | 2 | 已标 `requested` 但读数仍是 notDetermined：可解释口径有两处（请求失败 / 未真正发起） | 第 7.3、10.2 节 |
| D30 | 3 | `CL/authorized`：枚举页把 authorized 单列而不区分 always，跨帧混读风险 | 第 8.3 节 |

D23、D24、D28、D30 四条都停在级 3，原因同一个：**文档自己声明了不告知或二义**。脚本在这里能给的只有"这条读数不可用于归因"，这正是第 19.1 节说的台账侧级 3 含义。

### 22.4 判定图例与收敛

台账侧图例：级 1 命中已文档化枚举的封闭取值集合或文档明写的不兼容口径，可直接归责；级 2 读数有效但结论依赖台账的另一条轴、调用点或设备策略；级 3 文档自身给出二义或明写不告知，读数不可判定，不给归责结论；级 4 本条读数不可用。

收敛规则与脚本一相同（级号越小越优先）。E 类多一层短路：一旦置"读数不可用"标志，总判定直接输出级 4，不再参与收敛——所以 E01/E02/E03 三条自带的级参数不影响总判定，第 19.2 节末尾说的就是这件事。

### 22.5 四条边界声明

| 码 | 声明内容 | 对应章 |
| --- | --- | --- |
| B10 | 台账里的读数只是框架向 app 报告的结果，不证明授权获取过程 | 第 17 章 |
| B11 | 同一主体的读数若未按时间排列，分诊器只按行序处理 | 第 10.4 节 |
| B12 | 主体维度取自台账自身，无法核对扩展的授权继承 | 第 11.2 节 |
| B13 | 读数缺失不等于未授权：台账未覆盖的框架或主体不给结论 | 第 11.6 节 |

B12 是第 11 章那条继承规则（《Apple Platform Security》第 6059 到 6062 行）在输出面的落点：本文找到了"扩展到内嵌扩展共享隐私控制"这句规则，但没有任何静态文本能证明某个主体属于哪一类扩展，所以它只能以边界声明形式存在。

### 22.6 脚本全文

行数：267 行。以下内容由 `.x8-s2.sh` 原样嵌入。

```bash
#!/bin/bash
# privacy-state-ledger-triage.sh —— iOS 隐私授权状态台账的离线只读分诊器
# 只读：只读取入参文本台账，不写设备、不联网、不修改输入，也不调用任何框架去重新询问授权状态；
#       中间文件只落在系统临时目录，退出前删除。台账应来自读者自家 app 日志或自有导出件的脱敏结果。
# 口径来源：11 组授权状态枚举的已文档化取值，逐格硬编码在本脚本的 ENUM 表里，
#           来源为《CLAuthorizationStatus》《CLAccuracyAuthorization》《AVAuthorizationStatus》
#           《PHAuthorizationStatus》《CNAuthorizationStatus》《CBManagerAuthorization》
#           《HKAuthorizationStatus》《ATTrackingManager.AuthorizationStatus》《UNAuthorizationStatus》
#           《UNNotificationSetting》《SFSpeechRecognizerAuthorizationStatus》各页的 TOPICSECTIONS 行；
#           二义与不可判定的原句来自《Requesting authorization to use location services》
#           《Delivering an Enhanced Privacy Experience in Your Photos App》《Protecting user privacy》
#           《trackingAuthorizationStatus》《Asking permission to use notifications》。
#
# 输入形态（每个文本文件 = 一份台账）：
#   每行 3~4 个空白分隔字段：〈框架代号〉〈读数〉〈主体代号〉〈标签〉；标签可省略。
#   框架代号：CL CLACC AV PH CN CB HK ATT UN UNS SPEECH。
#   标签为逗号分隔的记号，识别 requested、read、legacy、accuracy=reduced、via=settings。
#   # 开头为注释行；空行跳过。
#
# 用法：  privacy-state-ledger-triage.sh [-q] [-h] 台账 [台账...]
# 退出码：0 = 台账可用并给出判定；2 = 至少一份台账读数不可用（E 类）；9 = 调用形态错误。

set -u
LC_ALL=C
export LC_ALL

QUIET=0
FLAG_E=0
CNT_D=0
CNT_B=0
WORST=""
VOCAB_N=0
TMPS=""
ENUMF=""
SUBJ=""

usage() {
  printf '%s\n' "用法: $0 [-q] [-h] 台账 [台账...]" \
                "  -q  只打印信号码，不打印解释行" \
                "  -h  打印本帮助"
}

cleanup() { if [ -n "$TMPS" ]; then rm -f $TMPS; TMPS=""; fi; }
trap cleanup EXIT INT TERM

newtmp() { local t; t=$(mktemp 2>/dev/null) || t=""; [ -n "$t" ] && TMPS="$TMPS $t"; printf '%s\n' "$t"; }

emit_text() {
  if [ "$QUIET" = 1 ]; then printf '%s\n' "$1"; else printf '%s  %s\n' "$1" "$2"; fi
}
emit() {
  local code="$1" lv="$2"; shift 2
  case "$code" in E*) FLAG_E=1 ;; esac
  CNT_D=$((CNT_D + 1))
  case "$lv" in
    1) WORST=1 ;;
    2) if [ "$WORST" != 1 ]; then WORST=2; fi ;;
    3) if [ -z "$WORST" ]; then WORST=3; fi ;;
    4) if [ -z "$WORST" ]; then WORST=4; fi ;;
  esac
  emit_text "$code" "$*"
}
bound() { CNT_B=$((CNT_B + 1)); emit_text "$1" "$2"; }

give_verdict() {
  if [ "$FLAG_E" = 1 ]; then
    emit_text J4 "判定：级 4 —— 本条读数不可用（见上方 E 类），不给口径判定"
    return
  fi
  case "$WORST" in
    1) emit_text J1 "判定：级 1 —— 命中已文档化枚举的封闭取值集合或文档明写的不兼容口径，可直接归责" ;;
    2) emit_text J2 "判定：级 2 —— 读数有效但结论依赖台账的另一条轴、调用点或设备策略，需再补一行或回到声明侧收敛" ;;
    3) emit_text J3 "判定：级 3 —— 文档自身给出二义或明写不告知，读数不可判定，不给归责结论" ;;
    "") emit_text J0 "判定：$ROWS 行读数全部落在已文档化取值内，且未命中本文的二义与缺行规则；这不等于授权链路正确（见 B10~B13）" ;;
  esac
}

# ---- 词表二：框架代号 <TAB> 已文档化取值（逐条取自上面列出的 TOPICSECTIONS 行） ----
ENUM='CL	notDetermined
CL	restricted
CL	denied
CL	authorizedAlways
CL	authorizedWhenInUse
CL	authorized
CLACC	fullAccuracy
CLACC	reducedAccuracy
AV	notDetermined
AV	restricted
AV	denied
AV	authorized
PH	notDetermined
PH	restricted
PH	denied
PH	authorized
PH	limited
CN	notDetermined
CN	restricted
CN	denied
CN	authorized
CN	limited
CB	notDetermined
CB	restricted
CB	denied
CB	allowedAlways
HK	notDetermined
HK	sharingDenied
HK	sharingAuthorized
ATT	notDetermined
ATT	restricted
ATT	denied
ATT	authorized
UN	notDetermined
UN	denied
UN	authorized
UN	provisional
UN	ephemeral
UNS	notSupported
UNS	disabled
UNS	enabled
SPEECH	notDetermined
SPEECH	denied
SPEECH	restricted
SPEECH	authorized'

# CL 的 authorized 在文档页里以不带类型前缀的形式出现，单独记为「索引形式」
CL_INDEX_FORMS='notDetermined restricted denied authorizedAlways authorizedWhenInUse'

FRAME_DESC='CL	CLAuthorizationStatus（定位：是否可用定位服务）
CLACC	CLAccuracyAuthorization（定位：精度轴，与 CL 正交）
AV	AVAuthorizationStatus（相机与麦克风）
PH	PHAuthorizationStatus（照片图库）
CN	CNAuthorizationStatus（通讯录）
CB	CBManagerAuthorization（蓝牙）
HK	HKAuthorizationStatus（HealthKit，只描述 save 侧）
ATT	ATTrackingManager.AuthorizationStatus（追踪）
UN	UNAuthorizationStatus（通知）
UNS	UNNotificationSetting（同一框架内的第三种口径）
SPEECH	SFSpeechRecognizerAuthorizationStatus（语音识别）'

has_tag() { printf '%s' "$1" | tr ',' '\n' | grep -qxF "$2"; }

triage_one() {
  local f="$1" ROWS=0 lineno=0 unparsed=0
  [ -r "$f" ] || { emit E01 3 "台账不可读或不存在"; give_verdict; return 1; }
  # -r 在部分平台上对 ACL 拒绝不敏感，再做一次真实读取探测
  head -n 1 "$f" >/dev/null 2>&1 || { emit E01 3 "台账存在但读不到内容（权限或独占占用）：本分诊器不重试、不绕过权限，只记为不可用读数"; give_verdict; return 1; }
  [ -s "$f" ] || { emit E02 3 "台账为空：没有任何授权读数"; give_verdict; return 1; }

  # 主体维度预扫：某主体出现过哪些框架，用于跨轴缺行判定
  : > "$SUBJ"
  awk 'NF>=3 && $1 !~ /^#/ {print $3 "\t" $1}' "$f" | sort -u > "$SUBJ"

  while IFS= read -r line; do
    case "$line" in ""|\#*) continue ;; esac
    lineno=$((lineno + 1))
    set -f
    # shellcheck disable=SC2086
    set -- $line
    set +f
    if [ "$#" -lt 3 ]; then
      unparsed=$((unparsed + 1))
      emit D20 2 "第 $lineno 行字段不足 3 个（框架/读数/主体）：该行不参与口径判定，只计入不可解释行（累计 $unparsed 行）；这是台账格式问题，不指向 app 的授权逻辑"
      continue
    fi
    ROWS=$((ROWS + 1))
    local fw="$1" rd="$2" sb="$3" tg="${4:-}"

    if ! printf '%s\n' "$FRAME_DESC" | awk -F'\t' -v f="$fw" '$1 == f {found = 1} END {exit !found}'; then
      emit D20 1 "第 $lineno 行的框架代号 $fw 不在本文的 11 组已文档化枚举里：整行跳过。代号写错会把一次可核对的读数变成不可核对的读数"
      continue
    fi

    local infw
    infw=$(awk -F'\t' -v v="$rd" '$2 == v {printf "%s ", $1}' "$ENUMF")
    if [ -z "$infw" ]; then
      emit D21 1 "主体 $sb 的 $fw 读数 \"$rd\" 不在任何一组的已文档化取值里（本文词表共 $VOCAB_N 条〈框架,取值〉配对）：该读数只能来自自定义包装、跨平台移植的常量名或未文档化的返回值，不能进入归属矩阵"
      continue
    fi
    if ! printf '%s\n' "$infw" | grep -qw -- "$fw"; then
      emit D22 1 "主体 $sb 的读数 \"$rd\" 属 $(printf '%s\n' "$infw" | awk '{for (i = 1; i <= NF; i++) printf "%s%s", (i > 1 ? " 或 " : ""), $i}') 词表，却记在 $fw 名下：11 组枚举互不通用，CB 用 allowedAlways、HK 用 sharingAuthorized、UNS 用 enabled，跨框架套用同名读数会让台账的归责结论落到错误的框架上"
      continue
    fi

    # CL 索引形式：文档页把 authorized 以不带类型前缀的形式列出
    if [ "$fw" = CL ] && [ "$rd" = authorized ]; then
      emit D30 3 "主体 $sb 记为 CL/authorized：《CLAuthorizationStatus》页的 TOPICSECTIONS 把 authorized 写成不带 CLAuthorizationStatus. 前缀的形式，其余四个取值都带前缀；文档未说明这是可取值还是索引排版，本条不给归责结论"
    fi

    # 单轴读数不足以定位定位授权（CL 与 CLACC 正交）
    if [ "$fw" = CL ] && [ "$rd" != notDetermined ] \
       && ! awk -F'\t' -v s="$sb" '$1 == s && $2 == "CLACC" {f = 1} END {exit !f}' "$SUBJ"; then
      emit D26 2 "主体 $sb 有 CL 读数 $rd 但没有同主体的 CLACC 行：文档给出第二条正交轴（fullAccuracy / reducedAccuracy），只记一轴时「授权成功」与「授权成功但只有模糊精度」在台账里不可区分"
    fi

    # UN 的第三种口径
    case "$rd" in
      provisional|ephemeral)
        if ! awk -F'\t' -v s="$sb" '$1 == s && $2 == "UNS" {f = 1} END {exit !f}' "$SUBJ"; then
          emit D27 2 "主体 $sb 的 UN 读数是 $rd 但没有同主体的 UNS 行：provisional 与 ephemeral 都不给弹窗式的完整授权，alert/badge/sound 要按 UNNotificationSetting（enabled / disabled / notSupported）另一套取值判；缺这一行时台账无法说明通知究竟能不能呈现"
        fi ;;
    esac

    # 已文档化的二义与不可判定
    if [ "$fw" = CL ] && [ "$rd" = denied ]; then
      emit D23 3 "主体 $sb 的 CL/denied 二义：文档同一条目写明 The user denied the use of location services for the app or they are disabled globally in Settings，用户级拒绝与整机定位服务被关闭给出同一读数，台账里不可区分，不能直接归责到 app"
    fi
    if [ "$fw" = HK ] && has_tag "$tg" read; then
      emit D24 3 "主体 $sb 的 HK 行带 read 语义（值为 $rd）：《HKAuthorizationStatus》页只有 notDetermined / sharingDenied / sharingAuthorized 三个取值，且文档写明 To help maintain the privacy of sensitive health data, HealthKit does not tell you when the user denies your app permission to query data. Instead, it simply appears as if HealthKit does not have any data matching your query；查询结果为空不构成读拒绝的证据"
    fi
    if [ "$fw" = PH ] && has_tag "$tg" legacy; then
      emit D25 1 "主体 $sb 的 PH 行标了 legacy：文档写明 The authorizationStatus() and requestAuthorization(_:) methods aren't compatible with the limited library and return PHAuthorizationStatus.authorized when the user authorizes your app for limited access only；旧 API 下的 authorized 不能用于判定全量授权，归属要落到调用点用的是哪一套 API"
    fi
    if [ "$fw" = ATT ] && [ "$rd" = restricted ]; then
      emit D28 2 "主体 $sb 的 ATT/restricted：文档写明 This property returns ATTrackingManager.AuthorizationStatus.restricted when the system restricts tracking for the device, regardless of whether your app has presented the prompt——该读数由设备策略决定，与 app 是否发起请求无关，不能归责到声明或弹窗时机"
    fi
    if [ "$rd" = notDetermined ] && has_tag "$tg" requested; then
      emit D29 2 "主体 $sb 已标记发起过请求但读数仍是 notDetermined：文档口径有两处可解释——授权请求在缺少必需键时直接失败（Authorization requests fail immediately if the required keys aren't present），以及首次请求会提示并记录回应（the system prompts the person to grant or deny the request and records that response）。前者要在声明侧核对（用 privacy-declaration-audit.sh），后者要在弹窗时机核对；台账单独看不出是哪一种"
    fi
    if has_tag "$tg" via=settings; then
      emit_text T00 "主体 $sb 的 $fw/$rd 标注为设置页变更：文档口径 People can change your app's authorization status at any time in system settings，读数回退本身不是缺陷"
    fi
  done < "$f"

  if [ "$ROWS" = 0 ]; then
    emit E03 3 "台账里没有一行可解释的读数（共 $unparsed 行字段不足）：不给口径判定"
    give_verdict
    return 1
  fi
  bound B10 "台账里的读数来自 app 自己调用框架的结果，只证明「框架向 app 报告了什么」，不证明用户在系统设置里的选择，也不证明系统弹窗的展示时机"
  bound B11 "同一主体的读数序列不按时间排列时，本分诊器只按行序处理；文档明确用户可在任意时间改变状态，因此「后一行回退到 denied」不构成违规"
  bound B12 "主体维度取自台账自身，无法核对扩展的授权继承：平台安全指南写明授权会扩展到 app 内嵌的扩展，但不扩展到由 app 激活的扩展；扩展产生的读数需要单独一列主体代号"
  bound B13 "读数缺失不等于未授权：台账未覆盖的框架或主体在本分诊器里不参与判定，缺行只由 D26、D27 这类跨轴配对规则报出"

  give_verdict
  [ "$FLAG_E" = 1 ] && return 1
  return 0
}

# ---- 主流程 ----
if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then usage; exit 0; fi
if [ "${1:-}" = "-q" ]; then QUIET=1; shift; fi
if [ "$#" = 0 ]; then
  emit_text S98 "未提供输入文件"
  usage >&2
  exit 9
fi

ENUMF=$(newtmp); SUBJ=$(newtmp)
# newtmp 在 mktemp 失败时返回空串；两个中间文件都要探到，否则 `: > ""` 只会泄漏 shell 报错
for p in "$ENUMF" "$SUBJ"; do
  [ -n "$p" ] || { emit_text S98 "临时目录不可用：无法建立词表文件，本分诊器不落地执行"; exit 9; }
done
printf '%s\n' "$ENUM" > "$ENUMF"
VOCAB_N=$(awk 'NF' "$ENUMF" | wc -l | tr -d ' ')
emit_text V00 "词表规模：11 组枚举、$VOCAB_N 条〈框架,取值〉配对；框架口径：$(printf '%s' "$FRAME_DESC" | awk -F'\t' '{print $1}' | tr '\n' ' ')"

bad=0
for f in "$@"; do
  CNT_D=0; CNT_B=0; WORST=""; FLAG_E=0
  : > "$SUBJ"
  emit_text S00 "=== 分诊 $f ==="
  triage_one "$f" || bad=1
  emit_text S90 "本条计数：口径命中 $CNT_D 条、边界声明 $CNT_B 条"
done

[ "$bad" = 1 ] && exit 2
exit 0
```

---

## 23. 两个脚本的全量分支覆盖验收

### 23.1 验收目标与方法

目标只有一句话：**每个码位至少被一个夹具命中，且整份输出被固化成可比对文件**。方法是用一个驱动脚本（`.x8-fx/run-accept.sh`，也是只读：不联网、不修改样例输入）把所有夹具跑一遍，产出两个记录文件——`ACCEPT.txt` 存全部原始输出与退出码，`COVERAGE.txt` 存"码位 → 命中它的夹具"映射。

结果是 66 个分支命中、33 个不同码位：脚本一 38 条（B01—B05 五条边界、D01—D19 十九个码位、E01—E03、J0—J4、P00、S00、S90、S98、U00、V00），脚本二 28 条（B10—B13、D20—D30、E01—E03、J0—J4、S00、S90、S98、T00、V00）。两个脚本的 D 码合计 30 个，加上共享的 E 类 3 个，就是第 14 章类型学表里"全部码位都有归属类"的那 33 项。

### 23.2 夹具清单

- **声明侧 31 份**：`t00`—`t19` 覆盖 XML 与扁平两种形态、五档缺键后果、空串、短文案、错键名、定位/蓝牙键配对、HealthKit 单键、未知令牌、空容器、布尔类型错、Deprecated 键；另有 `m00`—`m10` 十一份清单夹具，逐个覆盖 D08—D14、D17、D18 与 P00；`t14-config.plist`（文件名不合规，触发 B04）、`t15-binary.plist`（二进制 plist，E02）、`t16-empty.plist`（空文件，E03）、`t17-nofmt.plist`（既非 `<key>` 也非"键 = 值"，E03）。
- **台账侧 8 份**：`g00.ledger` 是干净对照（J0，四条 B 类都在它上面出现，用来证明边界声明不会随缺陷数变化）；`b01`—`b07` 分别触发 D20—D22 的取值错、跨帧错，D23—D30 的折叠与二义，E02（空台账）、E03（全部行字段不足），以及 J1—J4 四种总判定。
- **调用形态 10 项**：`-h`、无参数（S98/9）、未知选项 `-x`、`-q` 多输入、`TMPDIR=/nonexistent-dir-xyz`（临时目录不可用 → S98/9）、不存在的文件（E01）、以及一份**真正不可读**的输入。

### 23.3 不可读输入是怎么造出来的

E01 这一支不能用 `chmod 000` 在 Windows 上验证——那里的权限位不阻止读取。驱动脚本按平台分叉：有 `icacls` 时用 `cmd //c icacls <路径> //deny "<账户>:(R)"` 拒绝当前账户读取，跑完再 `//remove:d` 撤销；类 Unix 才用 `chmod 000`。两种做法都在临时目录里操作**副本**，不改夹具本体，也不试图读取被拒之后的内容——脚本自身在 `head -n 1` 探测失败时输出 E01 并结束，这正是要验收的行为。

### 23.4 需要读者知道的实现细节

三条不在码位表里、但影响复现的分支：

1. **临时目录探测是一次性的。** `newtmp` 在 `mktemp` 失败时返回空串，主流程必须立即探可写性并退出 9；否则后续的重定向只会泄漏 shell 报错而给出一个看似正常的空输出。`TMPDIR=/nonexistent-dir-xyz` 那一项夹具测的就是这条。
2. **两种输入形态都要参与"键是否出现"的判断。** 只用精确 XML 路径匹配会把写全了的清单误报成缺键（`t18-Info.plist` 同时含两种形态，专门用于确认这一点）。
3. **E 类的级参数与总判定分离。** 见第 22.4 节：E 码自带的级参数不参与 `WORST` 收敛的实际读数，短路靠标志位完成。

### 23.5 方法论返工记录

本轮写作过程中有四处改动值得留在报告里，因为它们说明了这套判据是怎么被证伪再修正的：

1. **D04 曾按"NS 前缀 + UsageDescription 后缀"实现，判据错。** 文档的必配口径按**具体键名**书写，而《Protected resources》的键表是封闭的，于是重建为 69 键闭合表 + Deprecated 分支，并补 `t19-Info.plist` 夹具（`NSCalendarsUsageDescription`、`NSRemindersUsageDescription` 命中 Deprecated 分支）。第 4.2 节写的是修正后的口径。
2. **枚举取值以脚本表为准，反查正文。** 第 8.3 章最初按记忆写"CoreBluetooth 4 值、HealthKit 4 值"，与脚本 ENUM 表核对后确认 HK 只有 3 个 sharing 侧取值，正文据此改动。凡是正文与脚本表冲突处，本轮一律以脚本表 + 存档行号为准。
3. **第 11 章的"无继承句"结论被存档推翻。** 原先写作"本轮存档没有扩展到共享宿主授权的任何句子"，随后在《Apple Platform Security》第 6059 到 6062 行找到了明确的规则（只覆盖内嵌扩展、不覆盖被 app 激活的扩展），第 11.2 节按原句重写，并把残余缺口缩到两处。
4. **引用可核验性本身也被审计。** 报告里的 `（同页第 N 行）`形式不带文档标题，逐句审计工具会静默跳过。本轮为它加了一个预处理步骤：把 `同页` 展开成具体标题后重跑审计，才暴露出第 17 章一处 `同页` 指向错误页面的引用（已改为显式标题）。这条限制写在这里，是为了让读者知道本文的行号引用经过了哪几道检查。

### 23.6 复现步骤

三步，全部离线：把两个脚本与 `.x8-fx/` 目录放在同一父目录下，运行 `bash .x8-fx/run-accept.sh`；比对新生成的 `ACCEPT.txt` 与随报告发布的记录；如需只看码位，用 `-q` 单独跑任一夹具。脚本对输入文件只读打开，运行前后输入的字节序列不变，这也是第 21.1、22.1 节"只读"承诺的可检验部分（第 27 章结论把这条列为本文唯一的自我验证方式）。

---

## 24. 十二个误区

每条都写成"错误说法 / 为什么错 / 正确的读法"三行，且每条都能在前面某一章找到落点；凡本文脚本会给出的码位，这里都点名到码位。这一章不是提醒，是复核清单——写作过程中本文自己也在这十二处翻过车（第 23.5 节记了四处）。

**M1 「缺用途声明键一定会崩溃。」**
错误说法："缺键等于崩溃，所以 QA 跑一遍没崩就说明键齐了。"
为什么错：文档对 69 个受保护资源键写的缺键后果分四档（crash / fail / req / should），明写崩溃的只有五句，且五句的**触发粒度互不相同**——Photos 写的是"访问相册库"、Motion 写的是"访问运动数据"、Speech 写的是"调用 `requestAuthorization(_:)`"、ATT 写的是"尝试使用该框架"、HealthKit 写的是"请求授权"（第 18.1 节五行表）。定位三键走的是 fail 档：文档写"请求直接失败"而不是崩溃（D19）；"Add all usage description keys to your app's Information Property List before you make any authorization requests. Authorization requests fail immediately if the required keys aren't present."（《Requesting authorization to use location services》第 32 行）。
正确读法：先取脚本一 D01/D19 附带的档位，再决定用什么证据去验。崩溃档需要真机调用点才看得到，fail 档表现为"功能静默不可用、测试全绿"（第 14.3 节 P1 最坏解释），req/should 档只有审核侧读数。把"没崩"当成"键齐"的反证，就是把第 18 章的信号强度问题当成了覆盖证明。

**M2 「键在位就证明代码用到了这个资源。」**
错误说法："有 `NSCameraUsageDescription`，说明 app 确实要用相机。"
为什么错：文档的必配条件是单向的（"用到才需要"），反向不成立。脚本一对"有键无 `USE` 令牌"只出边界声明 B02，不出违规（第 21.6 节），因为静态文本里没有调用点这一格。同一份声明文本既可能是诚实申报，也可能是历史残留——两种情形在键面上完全同形。
正确读法：键存在只关闭"缺键"这一格（P1）。用途与调用点的对应关系本文无判据，已列为第 26 章 U3；要做这一格必须换证据面（代码检索或运行期调用记录），而运行期记录不在本文两个脚本的输入面内。

**M3 「用途声明键可以写进 PrivacyInfo.xcprivacy。」**
错误说法："都在 plist 里，写哪个文件有什么区别。"
为什么错：这是两套不同源的词表（第 3.1 节）。用途声明键属于 app 的 `Info.plist`，由系统弹窗读取；隐私清单的四个顶层键是 `NSPrivacy*` 一族，由 Xcode 与 App Store Connect 读取。把前者写进后者会得到一条 D14，把 `NSPrivacy*` 键放进非清单文件会得到一条 P00 归属提示。
正确读法：先看文件名（B04 专门管这件事），再看键属于哪一族。两族都在场时，脚本按文件名分流，不按"看起来像隐私"分流。

**M4 「申报闭合就等于合规。」**
错误说法："17 个 reason 码勾得全全的，清单结构没毛病，隐私就没问题了。"
为什么错：文档自己把申报的有效性接到了声明口径之外的那一侧："These declared reasons must be consistent with your app's functionality as presented to users, and you may not use the APIs or derived data for tracking."（《Describing use of required reason API》第 9 行）。这句话里的"与呈现给用户的用途一致"没有任何机器可读字段（第 6.4 节结论），"不得用于追踪"要看 app 的实际数据流。申报口径闭合只到第 19.3 节 L3 那一格的词表侧。
正确读法：D09—D12、D17 全部通过 = 结构可被接收，不等于实践相符。B05 存在的意义就是提醒：清单与 App Store Connect 隐私标签的一致性在本地文本里根本看不见。

**M5 「授权状态读到的就是用户同意的内容。」**
错误说法："HK 那边返回 `sharingAuthorized`，说明用户同意我们把健康数据读上来。"
为什么错：HealthKit 的这组常量描述的是写入侧（"This status indicates whether the user has authorized your app to save data of the given type."，《HKAuthorizationStatus》第 7 行），而读侧被拒时系统不告知："To help maintain the privacy of sensitive health data, HealthKit does not tell you when the user denies your app permission to query data. Instead, it simply appears as if HealthKit does not have any data matching your query."（《HKAuthorizationStatus》第 8 行）。状态机的读数与"用户同意的内容集合"之间没有映射表。
正确读法：状态是**框架级**的读数，数据范围是**类型级**的事实。台账侧凡是带读语义的 HK 行只出 D24（级 3），含义是"这条读数不能用于归因"，而不是"这条读数说明没问题"。

**M6 「authorized 就是完全访问。」**
错误说法："相机和定位都 authorized 了，能拿到全部数据。"
为什么错：至少在三个框架里，`authorized` 之下还有第二条轴。Core Location 把精度做成独立枚举（第 9.3 节），`NSLocationDefaultAccuracyReduced` 缺键等价 false（"If you don't include that key in your Info.plist, that's equivalent to setting it to false"，《NSLocationDefaultAccuracyReduced》第 8 行）——不写不是错，但不写的默认值与写 false 一致；PhotoKit 的 limited 库让 `authorized` 只代表"被用户圈选的那一部分"（"The limited Photos library affects all apps that use PhotoKit in iOS 14, including those already published to the App Store."，《Delivering an Enhanced Privacy Experience in Your Photos App》第 6 行）；通知的 provisional 是"没打断用户就自动拿到的授权"："Unlike explicitly requesting authorization, this code doesn't prompt the person for permission to receive notifications. Instead, the first time you call this method, it automatically grants authorization. However, until the person either explicitly keeps or turns off the notification, the authorization status is UNAuthorizationStatus.provisional."（《Asking permission to use notifications》第 35 行）。
正确读法：台账里每一条状态读数都要配一条轴读数——D26（有 CL 无 CLACC）、D27（有 UN 无 UNS）就是专门抓这种"单轴台账"的码位。只记状态的台账，其结论强度按第 19.3 节封顶在级 2。

**M7 「restricted / denied 就是用户点了拒绝。」**
错误说法："用户拒绝了我们的定位，所以我们看不到位置。"
为什么错：`denied` 这一个取值同时装两种成因："CLAuthorizationStatus.denied — The user denied the use of location services for the app or they are disabled globally in Settings."（《CLAuthorizationStatus》第 11 行）。而 `restricted` 一族在文档里有六种不同措辞（第 8.4 节表），其中通讯录写的是"用户可能无法更改该状态"（"The application is not authorized to access contact data. The user cannot change this application's status, possibly due to active restrictions such as parental controls being in place."，《CNAuthorizationStatus》第 7 行），相册写的是"用户无法授予该权限"（"The app isn't authorized to access the photo library, and the user can't grant such permission."，《PHAuthorizationStatus》第 9 行），ATT 更直接——该取值与"有没有弹过窗"无关（"This property returns ATTrackingManager.AuthorizationStatus.restricted when the system restricts tracking for the device, regardless of whether your app has presented the prompt."，《trackingAuthorizationStatus》第 11 行）。
正确读法：把 `restricted` 的责任方写成"系统 / 设备策略 / 配置描述文件"，而不是"用户"。对应码位是 D23（级 3）、D28（级 2）；两者的输出都明写"本条不可用于归因"。

**M8 「SDK 的申报由宿主 app 代做就够了。」**
错误说法："清单挂在 app 上，SDK 用哪些 API 由 app 一并申报。"
为什么错：文档把义务单位写成 bundle，不是 app："For each executable or dynamic library in an app that uses a required reason API, the bundle that includes the executable or dynamic library needs to include a privacy manifest file that reports the API."（《Describing use of required reason API》第 8 行），同页第 7 行另写 app 与 SDK 各报各的。审核侧的溯源也按文件路径来："If you upload an app to App Store Connect that contains privacy manifest files with unexpected keys or values, you receive an email that includes the name and path of the invalid files in your app bundle. If an invalid file comes from a third-party SDK, contact its developer for an updated version of the SDK that includes a valid privacy manifest."（《Adding a privacy manifest to your app or third-party SDK》第 6 行）。
正确读法：一份清单文本要先判归属（B03），再判内容。D10 命中 SDK 专属 reason 码时脚本降到级 2 并附归属说明，正是因为"这条到底算谁的"取决于这份文本从哪来（第 6.4 节）。

**M9 「多份清单会被系统自动合并。」**
错误说法："同一个 category 我写了两次，Xcode 会自己取并集。"
为什么错：文档只写了"聚合"这个词，且指的是**报告**聚合："Xcode can create a privacy report by aggregating the privacy manifests from your app and the third-party SDKs it links to"（《Describing data use in privacy manifests》第 15 行）。同一份清单里同一 category 重复出现时，申报侧最终读到的是并集、后写覆盖前写还是校验报错，存档里没有任何句子。脚本为此只出 D17（级 3）而不出违规等级结论。
正确读法：`NSPrivacyTracking` 与 `NSPrivacyTrackingDomains` 那种"文档内互相要求"的配对（"When set to true you need to provide a list of internet domains in NSPrivacyTrackingDomains"，《Privacy manifest files》第 21 行）可以静态判；跨 bundle 的合并语义不能判。写清单时按"每类只出现一次"作为工程约束，理由不是文档要求，而是文档没要求（第 26 章 U9）。

**M10 「隐私报告能证明用途声明是诚实的。」**
错误说法："Xcode 生成的 privacy report 里没报错，说明申报与实际一致。"
为什么错：报告是构建产物，输入是**声明文本本身**（第 3 条 M9 的那句聚合规则就是它的定义）。它不做代码分析，也不做网络观测。另一侧，本轮 13000 行的平台安全指南里 "privacy report" 出现 0 次——也就是说"给用户看的那份 App Privacy Report"与"Xcode 生成的那份报告"是两个对象，本文对前者没有任何可核对句子。
正确读法：报告只能证明"申报被正确装配"，属于申报口径；用途是否诚实属于声明口径与实际行为之间的那格，本文封顶在级 2（第 26 章 U3、U14）。公告侧唯一一条直接落在可观测产物上的读数反而提醒了另一件事："An app may be able to circumvent App Privacy Report logging"（120905 第 1490 行）——用户看不到某次访问，不等于没发生访问（第 16.3 节第一件事）。

**M11 「扩展共享宿主 app 的全部授权。」**
错误说法："扩展跑在 app 的容器里，用户给过 app 的权限扩展都有。"
为什么错：本轮存档里关于继承只有一句规则，出自平台安全指南第 6059 到 6062 行，写的是**授权延伸到内嵌扩展，但不延伸到由 app 激活的扩展**；而且同页更早那句"Extensions run in their own address space"（《Apple Platform Security》第 6054 行）说明这是按扩展类型分岔的规则。逐框架的继承覆盖表（相机、相册、通讯录、蓝牙、健康、通知、语音是否各自如此）在存档里不存在。
正确读法：台账必须按主体分行记录，不同主体的读数不得记在同一名下（P9 型）。脚本二对扩展继承只出 B12，不出任何继承结论——它无法从文本判断某主体是内嵌扩展还是被激活扩展。第 19.3 节把 L8 封顶在级 2 就是这个原因。

**M12 「公告里没有对应 CVE，说明这条链路质量没问题。」**
错误说法："搜了一圈 Apple 公告，没有'缺用途声明'这类条目，可见声明侧不是缺陷来源。"
为什么错：这是两套不同形的口径。第 16 章那 16 条读数（表格 12 条 + 同类日志脱敏 4 条）里，没有一条 Impact 形如"缺键""申报不实"；声明侧缺陷产生的读数是崩溃、请求失败、邮件提醒、拒绝上架，而不是 CVE 条目（第 16.3 节第三件事）。公告标签描述实现侧被修的对象，与十层归属之间没有映射表（M4 型误归的隐私版）。
正确读法：把公告当作反证材料使用——它证明"这条链路的强制侧与观测侧确有实现缺陷被修"，不证明声明侧质量。声明侧质量只能靠脚本一的 D 码分布与第 20 章指标看。

---

## 25. 常见问题

**Q1 这篇与第 02 篇（访问控制与应用交互）会不会重复？**
不重复，切口不同。第 02 篇的对象是权限模型本身与跨应用交互限制；本篇的对象是**一条从纯文本到系统读数再到审核回执的链路**，只在第 8、11 章各取"授权状态如何被 app 读到"与"跨主体记录"这两格，不重述权限数据库与模型全貌。相接处已用第 2 章的视角声明表划开。同一读数在两篇里出现时，本篇只给口径与码位，不重复给缺陷归属。

**Q2 为什么不直接给一张"键—框架—后果"总表就结束？**
因为总表只解决级 1（口径），不解决级 2（对齐）与级 3（读数）。更关键的是"后果"这一列本身不闭合：69 个键里只有 5 句明写崩溃，其余按 req / should / fail 分散书写（第 3.4 节），任何把它压成单列的表都会造出文档里没有的规则。本文给的替代物是两张判据表（21.4 的 D01—D19、22.3 的 D20—D30），每条都带级与"按文档口径系统会给什么读数"，且都能落到页与行。

**Q3 两个脚本会不会读我的真机、我的工程源码或我的 Apple 账户？**
不会，也没有这个能力。脚本一的输入是一份声明文本，脚本二的输入是一份台账文本；全文没有网络调用、没有 `plutil`、没有 Xcode 命令行、不读任何环境变量里的凭证。中间文件只落系统临时目录，退出前由 `trap` 删除。第 21.1、22.1 节把这一条逐句写进脚本头部注释，是为了让读者不必通读代码也能确认边界。

**Q4 我的 `Info.plist` 是二进制格式的，脚本能判吗？**
不能，也不该勉强判。脚本一遇到二进制 plist 输出 E02 并把这条输入的总判定置为级 4——级 4 的含义是"这次没有读数"，不是"没问题"（19.4 第四条）。要判就导出文本形态，两种形态（XML 与"键 = 值"扁平行）脚本都解析；同一份输入里混用两种形态时按并集算键在位（`t18-Info.plist` 就是这个夹具，第 23.4 节第二条）。

**Q5 「我用了相册但没写 `NSPhotoLibraryUsageDescription`，会崩吗？」**
按档回答：会崩，且崩溃点在访问时而不是启动时——"Attempting to access the Photos library without a valid usage description causes your app to crash."（《Delivering an Enhanced Privacy Experience in Your Photos App》第 12 行）。但本文不会据此断言"你一定会在线上崩"：崩溃需要读者身份与触发路径（第 18.1 节），脚本对崩溃没有任何读取路径。可断言的是：这条属于 D01 的 crash 档，级 1，修它只需要一次构建。

**Q6 为什么 D03（文案过短）算级 3，而不是级 1？**
因为文档没给长度阈值。这是本文 30 个 D 码里唯一一个无文档阈值的判定，脚本的报错文案里就明写了这一点（第 4.4 节）。把它升成级 1 会让整份输出的锚点变成"作者偏好"，因此它只提示、不归责。同理 `USE` 令牌的 21 个记号是本文自建的词法，不是 Apple 文档里的东西（第 21.2 节）——凡本文自造的东西，都在正文里标出来，不冒充文档口径。

**Q7 required reason 申报和用途声明是不是同一件事？**
是两个层，两条更新通道，两种读数。L1 用途声明的失败读数在设备上（弹窗文案、崩溃、请求失败）；L3 required reason 申报的失败读数在审核侧（邮件、2024-05-01 起拒收）。两者的词表不同源，`NSPrivacyAccessedAPITypes` 不能替代任何 `NS...UsageDescription` 键，反之亦然（M3、D14）。第 20 章把 O1（用途键覆盖率）与 O5（清单结构合规率）分成两个指标，就是因为它们不互相蕴含。

**Q8 为什么脚本二要我自己给台账加 `requested` / `legacy` 这类标签？**
因为这几件事静态不可证明，而它们恰好是折叠点：`authorized` 是不是旧接口返回的（PhotoKit 对 limited 也返回 authorized）、这条读数是不是请求过的、精度是不是在设置页被改过。标签是本文把"文档说了但文本证不了"的信息交还给读者的方式（第 22.2 节）。反过来，加了标签就产生了新判定：D25（legacy 分支）、D29（标了 requested 却仍未决）、D26/D27（轴缺失）。

**Q9 我能用系统的 App Privacy Report 或设置页截图替代台账吗？**
不能替代，两者不是同一口径。App Privacy Report 是给用户看的访问记录产物，本轮平台安全指南内没有任何可核对句子（0 命中，第 26 章 U14），且公告里有一条专门修它被绕过的缺陷（120905 第 1490 行）。设置页截图能证明"用户看到的呈现"，不证明"框架向 app 报告的读数"——后者才是第 8 章 45 条〈框架,取值〉配对的管辖范围。本文要求台账来自读者自家日志或自有导出件的脱敏结果（第 22.1 节），并且它自带 B10 声明：读数不证明授权获取过程。

**Q10 文档一共给了几道提审闸门？**
两道有日期的、一道不可核对的。2024-05-01 起，用了 required reason API 却没在清单里申报理由的 app 不被 App Store Connect 接收（《Describing use of required reason API》第 6 行）；2025-02-12 起，提交审核的 app 必须为若干常用第三方 SDK 带合法隐私清单（《Adding a privacy manifest to your app or third-party SDK》第 6 行）。第三道——某个 SDK 是否落在"必须带清单与签名"的名单上——本文不可判，因为名单页取回为 JS 壳（第 2 章缺口 C、第 12.3 节）。前两道分别查"申报内容是否闭合"与"该带的清单是否带了且合法"，判据互不覆盖。

**Q11 能不能把脚本改造成在线核验：真的去调框架查授权状态、或直接把清单提交给 App Store Connect？**
本文不提供该改造，也不建议把这两个脚本当改造起点。它们的价值完全建立在"不联网、只读文本、不产生任何外部副作用"上；一旦加入调用或提交能力，输入里就需要真实标识与账户信息，第 21.1、22.1 节的只读承诺和第 2 章的范围声明同时失效。要做在线核验，请用官方路径：Archive 之后在 Organizer 里生成隐私报告（《Describing data use in privacy manifests》第 17—18 行），提审由 App Store Connect 自己的校验回执给出（第 13 章）。

**Q12 如果我只想要一句结论呢？**
这条链路上"看起来不对"有三种完全不同的归属：声明侧写错了（改 plist / 改清单，责任方是 app 或 SDK 开发者，一次构建或一次依赖升级生效）；系统本来就不同形（`denied` 混装、HK 读侧不告知、`restricted` 与提示无关，责任方是系统与文档口径，app 只能补轴）；申报与呈现之间有落差（清单—标签—实际数据流，责任方跨 app 与审核，静态看不见）。第 21、22 章两个脚本的作用，是让你先分清自己在哪一种里；分清之前，任何"这是谁的缺陷"的判断都没有落点。

---

## 26. 未公开文档化边界清单

这一章集中收录取文中**不能靠公开文档判定**的格子。写法约束：每条给类型、给已知口径在哪一章落过地、给"缺的是什么"、给停在哪一级。凡进本章的格子，前 23 章不得给出归因结论；正文里出现"本文不判"的地方，都应在本章找到对应编号。

| 编号 | 类型 | 已知口径（落点） | 缺的是什么 | 停在哪一级 |
|---|---|---|---|---|
| U1 | 后果档不闭合 | 第 3.4 节：69 键表 + 四档后果；第 18.1 节：明写崩溃的只有五句 | "每个键属于哪一档"的完整映射表不存在，只能逐键取回；未取回页上的键本文不判档 | 级 1（承认表不完整） |
| U2 | 崩溃文本不可得 | 第 18.2 节 | 崩溃报告里的提示语原文未归档；本文不转写、不复述，只记"确有崩溃"这一事实 | 级 3（无法从文本到个案） |
| U3 | 声明—调用点一致性无判据 | 第 3.5、4.3 节；B01、B02 | 用途键与实际调用框架之间的对应关系没有任何公开字段可核对 | 级 2 |
| U4 | 弃用分组的读取行为未写明 | 第 4.2 节（《Protected resources》第 114—117 行的 Deprecated keys） | 弃用键是否仍被系统读取、读取时是否产生警告，文档无句 | 级 1 |
| U5 | 两套词表无映射 | 第 3.1、5.3 节：69 个受保护资源键 / 35 个收集数据类型 / 6 个目的 | 三者之间不存在映射表；"有相机键"推不出"申报了相机相关数据类型"，反之亦不可 | 级 1 |
| U6 | 词表随版本漂移，无历史快照 | 《Describing use of required reason API》第 14 行 "Apple continually reviews the list of required reason APIs and reasons for usage"（落在第 6.6 节） | 各版本的取值集合快照；因此本文所有规模数字（69/4/5/17/35/6/11/45）只在存档日期口径内成立 | 级 1（数字必须带日期） |
| U7 | off-device 限制语义不可静态判 | 第 6.3 节：两类 reason 明写"不得发往设备之外" | 声明之外的实际数据流；静态文本没有任何字段反映"是否发出" | 级 3 |
| U8 | SDK 专属 / 依赖意图的取值 | 第 6.4 节：17 码里有 3 个属此类 | "本 SDK 是否主要由包装 required reason API 构成"是设计意图判断，无机器可读字段（D10 因此降为级 2） | 级 2 |
| U9 | 多份清单的合并语义 | 第 5.6、24 章 M9；D17 | 同一 category 重复出现时的合并规则、跨 bundle 清单的取用顺序，均无文档句 | 级 2 |
| U10 | SDK 签名的校验流程 | 第 12.3 节：存档只有装配与分发侧两句（同一页第 93、160 行） | App Store Connect 如何核验 SDK 签名、核验失败给开发者什么读数，无句子 | 级 1 |
| U11 | 强制名单不可取回（缺口 C） | 第 2 章缺口 C、第 12.3 节第 1 项：《Privacy manifest files》第 9 行指向两处引用 | "哪些 SDK 必须带清单与签名"的名单正文；因此"该不该带"本文不可判 | 级 1 |
| U12 | 调试文档正文未取回 | 第 12.3 节：TN3181 只以标题出现在同一页第 6、159 行 | 失效清单的排错步骤与读数解释；本文不转写其中任何做法 | 级 1 |
| U13 | 审核侧页面不可得（缺口 C） | 第 2 章缺口 C、第 13 章 | App Store 隐私详情页与审核指南正文；B05 存在的原因 | 级 1 |
| U14 | 设备侧可观测产物无文档 | 第 13 章、M10：平台安全指南全文 "privacy report" 0 命中 | App Privacy Report 的记录范围、写入时机、缺记录的含义；仅有公告一句（120905 第 1490 行） | 级 3 |
| U15 | 继承规则的逐框架覆盖未知 | 第 11.2 节：《Apple Platform Security》第 6059 到 6062 行是本轮唯一一句 | 哪些框架的授权对内嵌扩展生效、哪些不适用；被激活扩展的具体边界 | 级 2（L8 封顶来源） |
| U16 | 受限库的抑制开关名称 | 第 9.1 节：Photos 页第 50—51 行取到的是 `IMAGE`，不是"抑制 limited 提示"的键 | 该行为是否可由声明侧配置、配置键叫什么；本文不猜 | 级 1 |
| U17 | entitlement 侧未覆盖 | 第 12.2 节："Access to the HealthKit API is controlled with entitlements"（《Apple Platform Security》第 5274 行） | 本文输入面不含 entitlement，健康准入的另一半完全未判 | 级 1（承认看不见） |
| U18 | 声明过剩的系统读数 | 第 3.5 节；B02 | 多写了未被使用的键，系统或审核是否有任何反应，文档无句；本文只出边界声明 | 级 2 |
| U19 | 公告标签与十层无映射 | 第 16 章、第 16.3 节第四件事（Passkeys 条目的 Impact 写的是蓝牙） | 组件标签到层、到框架的官方对应表；公开侧不存在 | 级 2 |
| U20 | 本文自造词表 | 第 21.2 节：21 个 `USE` 令牌；第 4.4 节：文案长度提示 | 这两处不是 Apple 文档口径，属于本文的工程约定；凡引用它们得出的结论都必须在正文里可辨识 | 级 1（自我标注） |

本章三条使用规则：

1. **进过本章的格子，前面章节不得二次归因。** 若某处结论看起来越了界，以本章为准回退到"级 N"标注——第 19.3 节的十层上限表就是这一规则的分层版本。
2. **新增缺口按同一格式追加**，且"已知口径"一列必须能指到本文已落地的章节或存档句；指不到的新条目本身就该被删掉。
3. **类型分布本身就是读数**：U1/U2/U10/U11/U12/U13/U16 是"文档或取回缺口"，U3/U7/U14/U17 是"证据面根本不在文本侧"，U5/U6/U9/U15/U18 是"口径之间存在缝"，U19/U20 是本文方法自身的限制。第一类可以靠补取回消除，第二类不能——这就是第 19.3 节里 L3、L10 封顶在级 3 的结构性原因。

---

## 27. 结论

回到摘要里提出的问题：**iOS 的隐私授权链路上有十格校验，声明这一侧读者完全看得见，读者能否只靠公开文本说出哪一格出了问题、该谁修、走哪条更新通道**。

能的那一半是有清单的，而且每一条都能落到页与行：69 个受保护资源键的封闭表与其中 3 个弃用键、4 个 `NSPrivacy*` 顶层键及其互相要求关系、5 类 required reason 与 17 个理由码、35 个收集数据类型与 6 个目的、11 组枚举帧的 45 条〈框架,取值〉配对、五句明写崩溃的规则句、两道带日期的提审闸门。这一半足够支撑两个离线脚本给出 33 个码位，并在本轮全部实跑触发（66 个分支命中，第 23.1 节）。

不能的那一半同样有清单，它比能的那一半更能说明问题：`denied` 一个取值混装两种成因（M7）、HealthKit 读侧被拒不告知（M5）、`restricted` 与"有没有弹过窗"无关（M7）、PhotoKit 旧接口对 limited 返回 authorized（M6）、通知的 provisional 未打断即自动授权（M6）、精度与设置是第二条正交轴（M6、D26/D27）、授权继承只有一句规则且逐框架覆盖不明（M11、U15）、多份清单的合并语义无文档（M9、U9）、SDK 签名的校验流程与强制名单不可取回（U10、U11）、申报侧三组页取回为 JS 壳（U13）、崩溃报告文本与设备侧可观测产物无文档（U2、U14）。第 26 章这 20 条里，**只有 7 条属于"文档或取回缺口、补齐即可判定"，其余 13 条属于"这条链路的性质决定读数不在文本侧"**——即使 Apple 把文档写全，U3、U7、U14、U17 这类格子仍然要靠别的证据面。

由此得出三条本篇结论：

1. **缺陷类型学必须按"哪一次校验放过了它"分型，而不是按键名或 CVE 分型。** P1—P12 之所以能用，是因为每个型都对应到一句校验规则或一个读数形态；键名对应的是工程位置，CVE 对应的是修复动作，两者都不对应校验位置。十二类里十类有静态判据、一类半可判（P5 依赖台账自报）、一类只能作为限制存在（P8 时效），这个分布本身就是"声明侧可自查程度"的度量。
2. **归属矩阵里最大的一格不是 Apple，是 app 与 SDK 开发者自己。** 第 15 章按更新通道重排后，app 构建通道上挂着 L1、L2、L3(app 侧)、L4、L6(app 分支)——全部声明类缺陷都在这里，也是脚本一唯一能事前拦住的一段；SDK 依赖升级通道上的 L2/L3/L9 修复权不在宿主手里，只能靠版本门禁和审核邮件里的文件路径定位（第 12.3 节第 3 项）。换句话说，多数可核对的口径违规不需要 Apple 修任何东西，这是 M12 与 Q12 那句结论的来源。
3. **判定必须停在有读数支撑的那一级。** 十层里五层能推到级 1，三层封顶在级 2，两层封顶在级 3（第 19.3 节表）；封顶的位置不是努力程度问题，而是输入面问题——第 26 章的 U 类里凡标"级 3"的格子，靠文本永远到不了归因。本篇把停止规则写成表而不是原则，是为了让"我停在这里、缺的是哪一格"本身成为可交付、可复核的结论。

方法上，本篇留下三件可复用的形态：其一，把一条链路拆成**三套口径**（声明口径、框架状态机口径、申报口径）并拒绝把它们混成一张表，凡规模数字都带存档日期；其二，把"声明可见 / 结果不可判定"这一不对称当作拆解的起点，而不是当作缺陷清单的附录；其三，两个只读、离线、可用夹具做全分支覆盖的核验脚本——第 23.5 节记录的四处返工（键名表误判、枚举取值凭记忆、"无继承句"的错误结论、`同页` 引用的可核验性）恰恰是这种"先把判据写成可跑文本、再把引用写成可审计句子"的写法才暴露出来的，纯叙述不会暴露它们，因为叙述不会失败退出。

最后一条限制说在前面：本篇所有结论都建立在**公开文档与公开公告**上，没有一条来自真机抓取、私有接口或逆向结果；本文不提供任何绕过授权、篡改授权状态、伪造清单或规避审核的做法，第 2 章的范围声明优先于全文任何一句。第 26 章那 20 条里凡是本文想断言而断言不了的，都留了"缺的是什么"这一列。这份清单就是本报告对读者最有用的部分：**它告诉你，在隐私授权这条链路上，哪些缺陷今天就能在自己工程里查出来，哪些必须先补上另一种读数才有资格被问。**

---

## 28. 参考资料

以下即本轮全部取回记录。凡正文引用的句子都必须能在对应存档件里按行找到原句（第 2.1 节自审清单第 1 条），引用格式为"《标题》第 N 行"。取回日期：2026-10-30。

### 28.1 A 组 · Apple 开发者文档（隐私声明、用途键与授权状态页面）

取回形态：Apple 文档数据接口 `developer.apple.com/tutorials/data/documentation/<路径>.json` 的原始响应，以及由它展开的扁平文本（展开件首行为 `PAGE-TITLE`，表格行被拍平成一行一项）。展开与取回由 `.x8-fetch.sh` 与 `.x8-flat.pl` 完成，72 页全部取回、0 页缺失；每页的行数、文档内部路径与取回时间记录在 `.srcx8/A/urls.tsv`，件名与标题的对照同步在 `.srcx8/MANIFEST.txt`。

（以下 72 件即本轮 A 组全部取回件，按存档件名排序逐件列出；"行数"指扁平件的物理行数，正文行号以此为准。）

| 存档件名 | 文档标题（取回件首行 PAGE-TITLE） | 扁平件行数 |
|---|---|---|
| adding-a-privacy-manifest-to-your-app-or-third-party-sdk | Adding a privacy manifest to your app or third-party SDK | 165 |
| app-privacy-configuration | App Privacy Configuration | 19 |
| asking-permission-to-use-notifications | Asking permission to use notifications | 57 |
| attrackingmanager | ATTrackingManager | 25 |
| attrackingmanager-authorizationstatus | ATTrackingManager.AuthorizationStatus | 23 |
| authorizing-access-to-health-data | Authorizing access to health data | 126 |
| avauthorizationstatus | AVAuthorizationStatus | 24 |
| cbmanagerauthorization | CBManagerAuthorization | 20 |
| claccuracyauthorization | CLAccuracyAuthorization | 25 |
| clauthorizationstatus | CLAuthorizationStatus | 32 |
| cllocationmanager | CLLocationManager | 110 |
| clservicesessionauthorizationrequirement | CLServiceSessionAuthorizationRequirement | 8 |
| cnauthorizationstatus | CNAuthorizationStatus | 23 |
| delivering-an-enhanced-privacy-experience-in-your-photos-app | Delivering an Enhanced Privacy Experience in Your Photos App | 69 |
| describing-data-use-in-privacy-manifests | Describing data use in privacy manifests | 27 |
| describing-use-of-required-reason-api | Describing use of required reason API | 20 |
| editing-property-list-files | Editing property list files | 32 |
| establishing-your-app-s-integrity | Establishing your app’s integrity | 69 |
| hkauthorizationstatus | HKAuthorizationStatus | 34 |
| information-property-list | Information Property List | 65 |
| nsapplemusicusagedescription | NSAppleMusicUsageDescription | 10 |
| nsbluetoothalwaysusagedescription | NSBluetoothAlwaysUsageDescription | 10 |
| nsbluetoothperipheralusagedescription | NSBluetoothPeripheralUsageDescription | 11 |
| nscalendarsfullaccessusagedescription | NSCalendarsFullAccessUsageDescription | 12 |
| nscalendarsusagedescription | NSCalendarsUsageDescription | 10 |
| nscalendarswriteonlyaccessusagedescription | NSCalendarsWriteOnlyAccessUsageDescription | 12 |
| nscamerausagedescription | NSCameraUsageDescription | 15 |
| nscontactsusagedescription | NSContactsUsageDescription | 9 |
| nsfaceidusagedescription | NSFaceIDUsageDescription | 9 |
| nsfalldetectionusagedescription | NSFallDetectionUsageDescription | 9 |
| nshealthshareusagedescription | NSHealthShareUsageDescription | 12 |
| nshealthupdateusagedescription | NSHealthUpdateUsageDescription | 12 |
| nshomekitusagedescription | NSHomeKitUsageDescription | 10 |
| nslocalnetworkusagedescription | NSLocalNetworkUsageDescription | 10 |
| nslocationalwaysandwheninuseusagedescription | NSLocationAlwaysAndWhenInUseUsageDescription | 17 |
| nslocationalwaysusagedescription | NSLocationAlwaysUsageDescription | 18 |
| nslocationdefaultaccuracyreduced | NSLocationDefaultAccuracyReduced | 23 |
| nslocationtemporaryusagedescriptiondictionary | NSLocationTemporaryUsageDescriptionDictionary | 19 |
| nslocationusagedescription | NSLocationUsageDescription | 16 |
| nslocationwheninuseusagedescription | NSLocationWhenInUseUsageDescription | 17 |
| nsmicrophoneusagedescription | NSMicrophoneUsageDescription | 15 |
| nsmotionusagedescription | NSMotionUsageDescription | 9 |
| nsphotolibraryaddusagedescription | NSPhotoLibraryAddUsageDescription | 10 |
| nsphotolibraryusagedescription | NSPhotoLibraryUsageDescription | 13 |
| nsprivacyaccessedapitype | NSPrivacyAccessedAPIType | 69 |
| nsprivacyaccessedapitypereasons | NSPrivacyAccessedAPITypeReasons | 43 |
| nsprivacyaccessedapitypes | NSPrivacyAccessedAPITypes | 12 |
| nsprivacycollecteddatatype | NSPrivacyCollectedDataType | 47 |
| nsprivacycollecteddatatypepurposes | NSPrivacyCollectedDataTypePurposes | 15 |
| nsprivacycollecteddatatypes | NSPrivacyCollectedDataTypes | 15 |
| nsprivacytracking | NSPrivacyTracking | 10 |
| nsprivacytrackingdomains | NSPrivacyTrackingDomains | 9 |
| nsremindersfullaccessusagedescription | NSRemindersFullAccessUsageDescription | 11 |
| nsremindersusagedescription | NSRemindersUsageDescription | 10 |
| nssiriusagedescription | NSSiriUsageDescription | 9 |
| nsspeechrecognitionusagedescription | NSSpeechRecognitionUsageDescription | 9 |
| nsusertrackingmarkdownusagedescription | NSUserTrackingMarkdownUsageDescription | 23 |
| nsusertrackingusagedescription | NSUserTrackingUsageDescription | 22 |
| phauthorizationstatus | PHAuthorizationStatus | 27 |
| privacy-manifest-files | Privacy manifest files | 33 |
| protected-resources | Protected resources | 121 |
| protecting-the-user-s-privacy | Protecting the User’s Privacy | 31 |
| protecting-user-privacy | Protecting user privacy | 29 |
| requesting-authorization-to-use-location-services | Requesting authorization to use location services | 63 |
| sfspeechrecognizer | SFSpeechRecognizer | 64 |
| sfspeechrecognizerauthorizationstatus | SFSpeechRecognizerAuthorizationStatus | 23 |
| suspending-authorization-requests | Suspending authorization requests | 31 |
| trackingauthorizationstatus | trackingAuthorizationStatus | 13 |
| unauthorizationoptions | UNAuthorizationOptions | 28 |
| unauthorizationstatus | UNAuthorizationStatus | 21 |
| unnotificationsetting | UNNotificationSetting | 28 |
| unnotificationsettings | UNNotificationSettings | 51 |

（上表按存档件名列出；正文引用时一律用标题行，例如《Describing use of required reason API》第 6 行。另有分组导航与接口原始响应存放于 `.srcx8/IDX/` 与 `.srcx8/RAW/`，只用于选页，不作为引用源。）

### 28.2 B 组 · Apple Platform Security 指南

- `apple-platform-security-guide.pdf`（3029387 字节）与 `apple-platform-security-guide.txt`（972154 字节、13000 行、md5 `fd8cdea19a91260fb13932691ccfe87b`）。正文引用行号一律以 `.txt` 扁平件的物理行为准；该件与第 07 篇存档目录里的同名件字节相同，因此跨篇行号可直接对照。
- `guide_privacy_ranges.txt`：9 组已核对的隐私/授权段落区间及其首行，用于快速定位（如第 5274 行的 HealthKit entitlement 句、第 6059 到 6062 行的继承句、第 2618—2644 行的后台安全改进段）。
- 指南内 "privacy report" 出现 0 次，这是第 24 章 M10 与第 26 章 U14 的直接依据。

### 28.3 C 组 · Apple 安全发布（Security Releases）页面

公告页复用第 07 篇的只读存档（`.srcx7/C/pages/<编号>.txt`，13 页共 18504 行），本轮未重复取回。按采集中间件 `.srcx8/C/privacy_component_records.txt`（79 条与隐私/授权直接相关的条目，每条带页号与行区间、组件、Impact、Description、CVE）筛出第 16 章用到的 6 页：

| 编号 | 公告标题 |
|---|---|
| 120893 | iOS 17.4 and iPadOS 17.4 |
| 120905 | iOS 17.5 and iPadOS 17.5 |
| 121837 | iOS 18.2 and iPadOS 18.2 |
| 122066 | iOS 18.3 and iPadOS 18.3 |
| 122371 | iOS 18.4 and iPadOS 18.4 |
| 125108 | iOS 26 and iPadOS 26 |

第 16 章的读数一律引 Impact 行原句，行号取该条目 Impact 所在的物理行，组件名取同一条目起始行的物理行号；其余 7 页（120880、121838、127002、127003、127112、127113、127114）只用于条目计数与版本换算，未在第 16 章逐条列出。

### 28.4 已取回但不可作为引用源的页面

本轮明确标记为"不得引用"的取回件（JS 渲染外壳或 404，正文不可核对）：App Store 的用户隐私与数据使用页、App Store 审核指南、iOS 安全与儿童安全专题页、设计侧隐私页、App Store Connect 的应用隐私页、以及 PhotoKit 的 `PHAccessLevel` 页。这些就是第 2 章缺口 C 的具体内容，对应第 26 章 U11、U12、U13、U16。凡正文需要说这些事的地方，只写"该页取回为外壳"并给出落点编号，不转述其中条款。

### 28.5 核验脚本与夹具

- 脚本一：`privacy-declaration-audit.sh`（存档件 `.x8-s1.sh`，550 行，全文见第 21.7 节围栏）
- 脚本二：`privacy-state-ledger-triage.sh`（存档件 `.x8-s2.sh`，267 行，全文见第 22.6 节围栏）
- 夹具：声明侧 31 份（`t00`—`t19` 二十份 plist 形态、`m00`—`m10` 十一份清单形态），台账侧 8 份（`g00` 干净对照 + `b01`—`b07`），调用形态与不可读输入 10 项；驱动脚本 `.x8-fx/run-accept.sh` 也是只读文本处理。逐码位映射与全部原始输出固化在 `.x8-fx/COVERAGE.txt` 与 `.x8-fx/ACCEPT.txt`，验收结论见第 23 章。
- 引用可核验性工具：逐句审计器（本轮为 `.t8q-audit.pl` 与同页展开预处理 `.t8samepage.pl`）与行号越界检查器，两者都只读取存档件与正文，不修改任何文件。第 23.5 节第 4 条记录的就是这一步骤暴露出的那处 `同页` 引用错误。

---

咨询ios系统请咨询 telegram：https://t.me/one00190
