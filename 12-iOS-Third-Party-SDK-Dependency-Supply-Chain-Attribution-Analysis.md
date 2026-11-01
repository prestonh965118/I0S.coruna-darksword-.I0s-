---
title: "iOS 第三方 SDK 与依赖代码供应链归属防御分析报告"
description: "iOS 应用内第三方代码的十层供应链表面分解：声明与锁定、解析与装配、二进制形态与签名身份、强制签名与库校验的平台口径、强制名单与隐私清单申报、版本可观测性、公告与 CVE 归属、移除与可证消失、组织侧可见性、构建可重现性与审核口径；P1—P12 缺陷类型学、装配口径/平台签名口径/公告归属口径三套词表与七处换算失败、层 × 责任方 × 形态 × 证据的归属矩阵、四级判定模型与两个离线只读核验脚本（信号码 64 + 34）"
lang: zh-CN
---

# iOS 第三方 SDK 与依赖代码供应链归属防御分析报告

## 摘要

本报告集前十一篇处理的两类问题是"缺陷在哪"和"这台设备归谁"。本文处理第三类，也是前十一篇都没有正面写过的一类：**一个 iOS 应用里那些不是你自己写的代码，是怎么进到产物里的、谁为它签名、版本被锁在哪一刻、它的漏洞算在谁头上，以及"这个 SDK 已经不在我们的产品里了"这句话要拿什么来证明**。这四件事在开发者界面上看起来是一件事——Xcode 左侧那一段 Swift Package Dependencies——但在 Apple 的公开文档里，它们分别由四类主体、三种形态和四个不同证据面回答，而且第四类问题在公开口径里根本没有答案。

第 3 章给三套词表和七处换算失败，其中四处是公开文档之间可以直接对出来的差：**"同一个开发者"这句话**，《Third-party SDK requirements》写"When you adopt a new version of a third-party SDK in your app, Xcode will validate that it was signed by the same developer"（第 122 行），平台安全指南写 Team ID 是"10-character alphanumeric string"且"any library with the same team identifier in its code signature as the main executable"（第 2362 行）——两者同名不同判：前者比对的是**依赖前后两个版本之间**的签名者，后者比对的是**框架与主可执行文件之间**的团队标识，台账里只写一格"已签名"必然把这两种校验混成一格；**依赖要求形态**，Xcode 给三种 package requirement（Version / Branch / Commit，第 18—21 行），CocoaPods 的 `spec.source` 给 `:tag`、`:branch`、`:commit`、`:http`+`sha256` 四种（Podspec Syntax Reference 第 203—215 行），两套词表在"锁定到哪一刻"上并不等价；**二进制版本的读数来源**，锁定文件读得到的是需求解析结果，XCFramework 内部实际编译版本要靠产物元数据，Swift Package Manager 二进制依赖的 checksum 只在解析或更新时被比对（Identifying binary dependencies 第 16 行）；**公告归属**，三份并行版本线安全公告共 392 条 CVE 行里，带开源上游语句的只有 1 条（`CVE-2019-5598`），CISA KEV 目录 `catalogVersion=2026.10.30` 的 1,766 条里 `vendorProject` 取 Apple 的 95 条，两者都不覆盖"app 里第三方代码的缺陷该记在谁头上"——Apple 公开语料里没有任何一句关于这件事的话（第 26 章 G5）。

第 4—13 章逐层给出输入、输出、失败形态与可得证据。其中三条事实决定了整篇的判定结构：**装配即责任**——《Third-party SDK requirements》第 118 行写"you are responsible for all the code the SDK includes in your app"，《App Review Guidelines》第 127 行写"You are responsible for making sure everything in your app complies with these guidelines, including ad networks, analytics services, and third-party SDKs"，两句分别落在隐私口径与审核口径上，但归属主体是同一个；**签名变化的两种解释在文档里并列存在**——《Verifying the origin of your XCFrameworks》第 14 行给出合法变更理由（提供方把 SDK 所有权转给另一家组织、新版本用新组织的 Team ID 签名），第 16 行紧接着给出非法解释（说明框架被篡改或有人注入自己的代码并伪装成该框架的一个版本），第 21 行的构建错误文本"[XCFramework name] is not signed with the expected identity and may have been compromised"本身不带判据，判据只能来自台账与提供方陈述；**强制名单只到"必须带清单与签名"这一层**——该页第 124 行的名单要求覆盖第 125—210 行共 **86 个 SDK 名**，其中没有任何一条给出提供方身份、版本号或签名主体，这份名单能证明义务，不能证明归属。

核验部分提供两个纯文本、离线、只读的脚本：脚本一把一份"第三方依赖装配与来源台账"按 Apple 文档口径审一遍，逐条回答"这一格写成这样时，这段代码的归属、身份、版本与消失结论还成不成立"，并对 `key.*` 命名空间与形似私钥/描述文件内容的取值直接报警（K01）；脚本二把装配登记件、产物读数件与移除台账件做集合差集、事件时序与口径一致性比对，回答"这个依赖在三件记录之间能不能闭合、它在产物里读到过却没有装配登记意味着什么、移除与复核的先后能不能同时为真"。信号码共 98 个（脚本一 64 个、脚本二 34 个），全部在本轮环境实跑触发，第 23 章给出逐码覆盖表。

本文不提供任何可用的漏洞利用代码、提权或绕过步骤，**不含任何绕过 Xcode 签名校验、伪造或替换 Team ID、降级或重新打包第三方框架、规避构建报错的做法，不含针对具体应用、具体 SDK 或具体提供方的攻击动作，不含任何"如何往别人产物里塞代码"的步骤**；也不提供依赖投毒、镜像替换或锁文件篡改的操作方法。本文给出的只有公开文档口径、代码归属判定、责任方划分、可见性边界与只读核验。**全部只写防御与归属判定。**两个脚本都不联网、不调用任何设备侧或 Apple 命令行工具、不修改输入文件；唯一写出目标是 `mktemp -d` 创建的临时目录，退出时删除。脚本一拒收任何密钥材料这一点不是顺带检查，而是本文的立场：**把签名私钥或描述文件内容抄进依赖台账，等于把"这段代码是谁签的"从一条可公开核对的身份变成一份需要保护的机密**——台账需要的是 Team ID 形态的身份串与证书指纹，永远不是密钥本身。

---

## 目录

1. [引言](#1-引言)
2. [视角声明与本文边界](#2-视角声明与本文边界)
3. [三套词表：装配口径、平台签名口径、公告归属口径](#3-三套词表装配口径平台签名口径公告归属口径)
4. [L1 声明与锁定层](#4-l1-声明与锁定层)
5. [L2 解析与装配层](#5-l2-解析与装配层)
6. [L3 二进制形态与签名身份层](#6-l3-二进制形态与签名身份层)
7. [L4 强制签名与库校验的平台口径层](#7-l4-强制签名与库校验的平台口径层)
8. [L5 强制名单与隐私清单申报层](#8-l5-强制名单与隐私清单申报层)
9. [L6 版本可观测性层](#9-l6-版本可观测性层)
10. [L7 公告与 CVE 归属层](#10-l7-公告与-cve-归属层)
11. [L8 移除与可证消失层](#11-l8-移除与可证消失层)
12. [L9 组织侧可见性层](#12-l9-组织侧可见性层)
13. [L10 构建可重现性与审核口径层](#13-l10-构建可重现性与审核口径层)
14. [缺陷类型学 P1—P12](#14-缺陷类型学-p1p12)
15. [归属矩阵：层 × 责任方 × 形态 × 证据](#15-归属矩阵层--责任方--形态--证据)
16. [公开读数：这条链路上能数出来的十八件事](#16-公开读数这条链路上能数出来的十八件事)
17. [可见性边界：这一层读者能拿到什么](#17-可见性边界这一层读者能拿到什么)
18. [四个读数面：工程侧、构建侧、设备侧、组织侧](#18-四个读数面工程侧构建侧设备侧组织侧)
19. [四级判定模型](#19-四级判定模型)
20. [运营指标 O1—O10](#20-运营指标-o1o10)
21. [只读核验脚本一：第三方依赖装配与来源台账审查器](#21-只读核验脚本一第三方依赖装配与来源台账审查器)
22. [只读核验脚本二：三件差集与消失结论比对器](#22-只读核验脚本二三件差集与消失结论比对器)
23. [两个脚本的全量分支覆盖验收](#23-两个脚本的全量分支覆盖验收)
24. [十二个误区](#24-十二个误区)
25. [常见问题](#25-常见问题)
26. [未公开文档化边界清单](#26-未公开文档化边界清单)
27. [结论](#27-结论)
28. [参考资料](#28-参考资料)

---

## 1. 引言

### 1.1 一个依赖声明与一段产品里的代码不是同一件事

在开发者认知里，"我们用了一个 SDK"是一句话：工程导航器里多了一个包，Podfile 里多了一行。在产品里，"用了一个 SDK"是一次装配动作的结果：某个版本的某段代码在某一天的某一次构建里被拉下来、被解析、被链接进主可执行文件或嵌进 Frameworks 目录。在平台口径里，"用了一个 SDK"是一条签名事实：那个二进制带的 Team ID 与主程序是否一致，它是否会被系统允许加载。在提供方与上游的口径里，"用了一个 SDK"是一个他们看不见的事实——他们能知道自己的某个版本有缺陷，却不知道哪个应用在哪台设备上还带着那个版本。

这四句话各自的主语不同：**第一句的主语是应用团队，第二句是构建系统，第三句是操作系统，第四句是公告作者。**本报告讨论的归属判定，全部落在这四个主语之间的缝隙上——缝隙而不是主语本身，因为四个主语各自在 Apple 的公开文档里都有明确的句子，缝隙是那些句子之间**没有对接点**的位置。

### 1.2 为什么"第三方代码"要单独建一套归属语言

本报告集里已经存在两套相邻语言，但它们都不能直接搬过来用。

第 02 篇建立了**运行时权限语言**：一个 SDK 在设备上能访问什么、以什么身份访问、越界之后归谁。那套语言处理"有权做什么"，它需要一个已经加载起来的进程。第 08 篇建立了**申报语言**：隐私清单里写了什么、required reason 用了哪一档、Aggregate 报告由谁聚合、审核里由谁签字。那套语言处理"说了什么"，它的对象是一份文件的内容。

供应链归属要处理的是这两者之间缺失的一段：**这段代码是怎么进到产物里的，进来之后的身份事实是什么，它出问题时记在谁头上，以及它不在了能不能证明。**这段东西用权限语言写不出来（进程还没起来），用申报语言也写不出来（申报的是数据实践而不是代码来源）。所以本文另建一套词表，并在第 2 章把与第 02、08 篇的分工线画清楚。

另一个必须单独建语言的原因是**归属主体的数量不同**。权限链路上责任方是两方（平台、应用）；申报链路上是三方（应用、审核方、清单作者）；供应链上是**四方**：应用开发者、SDK 提供方、上游开源项目、平台。一份第三方二进制常常同时是三个人的作品——提供方 fork 了上游、自己编译、自己签名，然后在你的工程里以第四种身份出现。四方可归属是本篇判定模型（第 19 章）里 J1 级的必要条件之一，也是第 14 章缺陷类型学里半数条目的来源。

### 1.3 本文要回答的四个问题

1. **进得来的路径能不能登记成可核对的事实？** 一份依赖的"需求形态 + 解析结果 + 锁定文件是否在册 + 自动解析是否关闭"四格，能不能唯一定位到某一次装配？（第 4、5 章）
2. **这段代码的身份归谁？** 二进制的签名主体、预期身份、身份变化的原因，能不能用公开文档口径分开"合法变更"与"必须调查"两种情形？（第 6、7 章）
3. **这一台上跑的到底是哪一版，谁能知道？** 版本读数有四种来源（锁定文件、产物元数据、崩溃日志、分发平台），它们的置信度不同；设备侧与组织侧对"装了哪些 SDK"的可见性需要分别判定。（第 9、12 章）
4. **缺陷与消失怎么定责？** 一个 CVE 属于提供方、上游还是应用自己？"我们已经不用这个 SDK 了"能不能证明？（第 10、11 章）

四个问题里，前三个都有 Apple 文档的明确句子可以依据；第四个的一半（CVE 归属）在 Apple 公开语料里**没有任何对应句子**，本文对这一半的处理是给出一套可执行的登记规则并把"公开口径不存在"写进第 26 章 G5，而不是发明一条 Apple 没说过的规则。

### 1.4 一个具体的例子

某应用的支付模块依赖一个闭源 XCFramework，提供方是一家支付服务商，服务商内部又封装了一个开源加密库。2026 年 6 月，服务商发布 3.4.3 修复上游的一个缺陷。三条记录如下：

- 工程侧：`Package.swift` 里以 `branch: "release/3.x"` 声明该依赖，`Package.resolved` 已提交进仓库，但 CI 脚本没有传 `-disableAutomaticPackageResolution`。
- 构建侧：某次存档构建的产物元数据读到 `PaymentCore.framework` 版本为 3.4.2，Team ID 与提供方在 2025 年登记的签名一致，但工程在 2026 年 5 月更换过一次提供方签名主体（服务商把业务转给了另一家主体）。
- 台账侧：一条 2026-06-10 的记录写着"PaymentCore 已升级至 3.4.3，风险关闭"。

这段记录里同时有四处归属判定不成立，而且**每一处都可以由公开文档直接指出**：以 branch 声明意味着解析结果可以随分支移动，而 `-disableAutomaticPackageResolution` 未传意味着 CI 不必按 `Package.resolved` 构建（CI 文档第 11 行）；产物元数据读到 3.4.2 与台账宣称的 3.4.3 不一致，两者只有一个能代表这一台上跑的版；签名主体变更这件事在《Verifying the origin of your XCFrameworks》第 14 行与第 16 行里是两种不同解释，台账没记原因，就退化成一条无法定责的构建错误；最后，"已升级"与"该缺陷已修复"之间还差一个版本可观测性证明——除非构建侧重新读一次，台账里那句"风险关闭"没有任何可回指的读数。

本文的四个脚本信号（`Z02`、`X04`、`G02b`、`V03`）分别对应上面四处。它们不指出攻击者，也不提供任何绕过手段，只把这段记录里**每一处"看起来像结论但其实是断言"的地方**放回它应有的格子里。

## 2. 视角声明与本文边界

本文与本报告集其它篇目存在四处同源语料重叠（第 02、03、08、09 篇各有一处，第 11 篇有一处方法形似），所以边界必须在第 3 章之前画完，并且要画到章节级别——本篇的读者很可能已经读过第 08 篇的隐私清单章节和第 09 篇的归属矩阵章节。

### 2.1 本文的视角

本文站在**应用集成方对自己产物里那段外部代码做归属核对**这一侧，而不是安全评估者做依赖挖掘这一侧。判据只有一个：某一段第三方代码此刻的来源、身份、版本与"还在不在"，能不能用公开文档 + 工程台账 + 只读核验得出一个可交付的结论。得不出结论的格子，本文写"不可判定"并说明为什么不可判定，不猜一个。

这个视角有三个具体后果，贯穿全文：

- **不写攻击路径。** 依赖投毒、镜像替换、锁文件篡改是供应链话题的另一半，本文只在"台账该记哪一格才能发现它"的意义上提到它们，不给出任何实施步骤。第 6 章引用《Verifying the origin of your XCFrameworks》第 16 行的非法解释时，引用的目的是**说明这条构建错误文本本身不带判据**，不是描述攻击。
- **不假定读者能拿到 SDK 源码。** 闭源 XCFramework 是本文的主要对象之一，因此"版本可观测性"（第 9 章）的全部判定只能建立在**产物侧读数**（锁定文件、框架元数据、崩溃日志、分发平台记录）上，而不是"读一下它的源码"上。
- **归属结论按最弱一环给出。** 一条依赖即使在九个格子上闭合，只要签名身份的来源不可核对，本文给出的等级就退到第 19 章的 J2 或更低，并说明是哪一格把它拉下来的。

### 2.2 与本报告集其它篇目的分工

| 篇目 | 它管什么 | 与本文的重叠点 | 本文如何切分 |
| --- | --- | --- | --- |
| 第 01 篇 iMessage 攻击入口 | 消息链路上的攻击面 | 无 | 本文不涉及消息链路、不涉及任何入口侧行为 |
| 第 02 篇 访问控制与应用交互 | 第 16 章的第三方 SDK 权限审计框架：`Info.plist`、entitlements、运行时实际访问行为 | 同一批 SDK，不同的问题 | 第 02 篇问"这个 SDK 在设备上**有权做什么**"，本文问"这个 SDK 是**怎么进到产物里的**、它的缺陷**记在谁头上**"。权限模型一律指向第 02 篇，本文不重述 entitlement 语义 |
| 第 03 篇 应用防护与抓包审计 | 威胁表里一行"供应链攻击：通过第三方 SDK/库植入后门，缓解手段 SBOM + 依赖审计 + 签名验证" | 一行 | 那一行是本文的题名级概括，本文把它展开成十层判定。且本文第 13 章要指出一个该行没有说的事实：**SBOM 这个词在 Apple 公开语料里不存在**（全库检索只命中开放标准组织自己的页面），所以"SBOM 由谁产出"在 iOS 生态里只能写成组织侧自证，不能写成平台口径（第 26 章 G1） |
| 第 04 篇 身份认证与通道加密 | 认证流程与传输加密 | 名义重叠 | 本文的"签名"一律指**代码签名身份**（Team ID、证书指纹、预期身份），与通道加密无关，不引用第 04 篇的任何结论 |
| 第 05 篇 生物识别安全机制 | Secure Enclave 与生物特征 | 无 | 不涉及 |
| 第 06 篇 XPC 与 Mach IPC | 进程间通道与系统服务 | 无 | SDK 与宿主 app 的**进程内**调用不构成 IPC 话题，本文不重述 |
| 第 07 篇 APNs 推送链路 | 通知投递链路的缺陷归属 | 无 | 推送 SDK 只作为"一个第三方框架"出现在名单讨论里，不涉及 token、证书与投递 |
| 第 08 篇 隐私授权链路与用途声明 | 第 5 章隐私清单层、第 6 章 required reason 层、第 12 章 L9 的 SDK 清单与构建装配层（文件位置、bundle 义务单位、失效清单邮件） | **最大重叠**：同页同行语料（`Third-party SDK requirements`、2025-02-12 闸门、SDK 签名要求） | 第 08 篇的对象是**声明内容与申报闭合**（清单里写了什么、挂在哪个 bundle 上、由谁聚合、审核里谁签字）；本文的对象是**代码本体的来源、身份与版本**。切法有三条硬线：① 本文不复述 `PrivacyInfo.xcprivacy` 的键语义，也不写 required reason API 的取值口径；② 本文只在第 8 章引用"哪些 SDK 必须带清单与签名"这一**名单事实**（存档件第 124—210 行），把名单当归属证据的边界来用；③ 签名一侧两篇取的是同一份文档的**不同环节**——第 08 篇取的是装配与分发环节（其自述），本文取回的是**校验环节**（预期身份、Team ID 变更的两种解释、构建错误文本、过期与吊销证书、审计指令，见第 6 章）。本文对第 08 篇有一项反向贡献：第 08 篇 12.3 节第 1 条缺口"强制名单不可核（页面是 JS 壳）"由本文本轮取回正文而**关闭**，读数是 86 条、无重名、无一条给出提供方身份（第 8 章） |
| 第 09 篇 更新链与补丁传导 | 公告 → 目录 → 授权 → 分发 → 安装 → 回执 → 回滚；第 15 章归属矩阵、第 16 章公告读数、脚本二的 CVE 集差集 | 同源 CSAF / KEV 语料 | 第 09 篇自述"管补丁走到哪"，本文"管**这个缺陷属于哪个主体、集成方能不能知道自己带着它**"。本文只使用 KEV 的 `vendorProject` 归属面与 Apple 行的存在性作为口径证据，**不做**滞后计算、覆盖差集与机型可用版本判定，也不重述个性化签名与安装授权 |
| 第 10 篇 设备生命周期与归属转移 | 设备属于谁、监管权与凭据的移交 | 仅一处读数面 | 第 10 篇第 16 章 R15 把"AirPlay SDK"当成一条公告行读数来读；本文的客体是**代码**，不是设备，不涉及激活锁、绕过码与移交流程 |
| 第 11 篇 备份与恢复链路数据副本 | 数据副本的归属、可见性与可证删除 | **方法形似**：两篇都有一条"可证消失"判定链 | 客体相反：第 11 篇证的是**数据副本不在了**，本文证的是**代码不在产物里了**。第 11 篇全文没有 SDK 字样（本文写作时已对其正文做过检索确认），两篇的台账字段、脚本与判定链无共用件。本文不引用备份面，第 11 篇也不引用装配面 |
| 第 13 篇 日志、诊断与崩溃证据链 | 一条记录被写下、留存、送达之后能不能作证 | **一处正向交接**：本文第 6 章的 build UUID 与 dSYM 归属 | 本文给的是**符号身份从哪条供应链来**（dSYM 由提供方给、由归档找），第 13 篇把它当作符号化档位的前提直接引用（其第 9 章与 L6 层），再往下问"这份报告此刻符号化到了哪一档、能不能作对外表述的依据"。第 13 篇不重述装配、签名与名单读数，本文不重述日志级别、留存与采集通道口径 |

一句话：**别的篇处理"这个 SDK 能做什么""这个 SDK 说了什么""这个补丁走到哪"，本文处理"这段代码是谁的、哪一版、还在不在、出事算谁的"。**

### 2.3 与 Android 系列同主题篇目的关系

Android 系列第 16 篇（Project Mainline 与 APEX 模块归属）读的是**平台把哪些代码切成可独立更新的模块**；本文读的是**应用自己把哪些外部代码装配进自己的产物**。主体方向相反：那边是平台下推，这边是应用上引。公开产物也完全不同：那边是 APEX manifest、模块列表与 `apexd` 行为；这边是 `Package.resolved`、`Podfile.lock`、XCFramework 的签名身份与 Team ID。

两篇共用同一套方法（归属矩阵 + 四级判定 + 只读比对脚本），这在本报告集里是刻意的：同一个读者群体要用同一套判据读两个平台。**不构成重复**——那边没有任何一句话讲应用侧依赖解析，这边没有任何一句话讲 Mainline 模块的可更新边界。

### 2.4 范围声明与排除项

全文只讨论公开文档化的机制、Apple 开发者文档与支持文档的原文口径、App Store 审核指南、Apple 安全公告与 CSAF 的公开条目、CISA KEV 的公开条目，以及在这些公开规则之上可以安全实施的只读判定。

本文**不提供**、也不指向以下内容：

- 可用的漏洞利用代码、提权步骤或任何绕过手段。
- **绕过 Xcode 签名校验、伪造或替换 Team ID、规避"not signed with the expected identity"构建报错、降级或重新打包第三方框架的做法。**第 6 章给出的是这条错误文本为什么不足以定责，以及台账该记哪一格才能定责；不是清除该报错的方法。
- **依赖投毒、镜像替换、锁文件篡改、上游仓库账号接管的操作方法或可行性讨论。**本文只在"哪种登记形态能发现它"的意义上命名这些风险。
- 针对任何具体应用、具体 SDK、具体提供方或具体上游项目的攻击动作、漏洞定位与利用路径。本文的例子（含 1.4 节的 PaymentCore）是**结构示例**，其中的版本号、日期与签名主体变更情形均为构造，不指称任何真实公司的行为。
- 从他人产物、他人工程或他人构建机中提取、反编译、导出第三方代码的步骤。
- 备份口令破解、激活锁绕过、MDM 规避——分别由第 11 篇、第 10 篇与第 02 篇明确排除，本文同样排除，且本文的对象根本不涉及设备凭据。

**凭据边界（本文的一条硬规则）**：台账**永不记录密钥值**。脚本一对任何 `key.*` 命名空间字段直接报警（K01），并对形似私钥块、`.p12`、`.mobileprovision` 内容的取值报警，不接受"记哈希""记前几位"这类折中写法。理由写在摘要里，这里再说一遍它的归属含义：**把签名私钥或描述文件内容抄进依赖台账，等于把"这段代码是谁签的"从一条可公开核对的身份事实变成一份需要保护的机密**——台账需要的是 Team ID 形态的身份串与证书指纹，永远不是密钥本身。

**脚本形态声明**：第 21、22 章两个脚本都是离线纯文本处理。脚本一读一份"第三方依赖装配与来源台账"文本（每行一条〈键,值〉记录，按命名空间分组）；脚本二读三份文本——装配登记件、产物读数件、移除台账件——做集合差集、事件时序与口径一致性比对。两者都不写设备、不联网、不修改输入文件、不调用 `xcodebuild`、`swift package`、`pod`、`codesign`、`plutil`、`security`、`profiles`、Xcode、App Store Connect 或任何网络接口；中间文件只落在 `mktemp -d` 创建的临时目录并在退出前删除。所有"核验"指读者对**自己抄录或导出的文本、工程内已提交的锁文件副本、公开公告与公开目录件**执行采集与比对。

### 2.5 引用与转录约定

英文原文按原样转录，只做两项字符归一——排版撇号（’）写作 ASCII 撇号（'），排版引号（“ ”）写作直引号（"）；其余字符、大小写不改。复核时还要允许下面七种**排版层差异**，它们不是转录差异：

1. **空白折叠**。存档页面会折行，词与词之间可能隔一个换行或一串空格；检索时把引语里的空格当作"至少一个空白字符"。
2. **开发者文档是 JSON 扁平件**。本轮 `A/` 组 36 个文件由 `developer.apple.com` 的 `…/data/documentation/…json` 取回后拍平：一行一个内容块，标题行形如 `PAGE-TITLE …`，章节标记为 `# Overview`、`## 小节名`，旁注保留类型前缀形如 `ASIDE(important) …`、`ASIDE(warning) …`、`ASIDE(note) …`。本文引这些页时按**整行**引用并给该行行号，不做跨行拼接，也不去掉 `ASIDE(...)` 前缀（去掉会让读者检索不到）。
3. **链接标签缺口**。扁平正文里页面内超链接只留下 `doc://…` 形式的目标标识，标签文本在该页的 references 表里。遇到这种情况本文只引到可核对的前半句，并在需要时注明"其后是页面内链接"。
4. **破折号**。原文里的双连字符 `--` 在页面上渲染为破折号（例如 `Tech Note 2449` 上文那句 "xcodebuild honors your SSH configuration — there’s no additional setup required"），本文按渲染形态转录。
5. **省略号与占位方括号**。`…` 与 `...` 代表被删去的一整段，长度不固定；`[XCFramework name]`、`[appName]`、`[platform]` 这类方括号是**原文自带的占位符**，本文原样保留，不替换成具体名字，也不说明为本文改写。
6. **平台安全指南的 PDF 分页残块**。`B/apple-platform-security-guide.txt` 是 4,885 行、697,288 字节的 `pdftotext -enc UTF-8` 转文本件（与第 08、09、10、11 篇同一版本，行号可直接对照），正文里会夹入页眉、页码与空行，并且存在**单词跨行被连字符拆开**的残块——本文第 4 章会引用一处形如 `an Appleissued certificate` 的文本，那不是转录错误，是 PDF 转文本时把跨行的 "Apple-issued" 连字符吞掉后的产物，本文原样引用并在此注明。
7. **术语的大小写与复数形**。`Team ID`、`team identifier string`、`team identifier` 三种写法在同一份语料里并存（前者见指南第 2362 行，中者见第 2360 行，后者见第 2362 行前半），`Package.resolved` 有时写作 `` `Package.resolved` `` 反引号形。本文引哪一处就给哪一处的形，不统一成一种写法。

两类已知的本轮**语料缺口**就地注明、不做修补式改写（完整版见第 26 章）：

- **缺口 A（SBOM 词汇不存在）**：本轮全库检索 `SBOM`、`CycloneDX`、`SPDX`、`SLSA` 只命中开放标准组织自己的页面与 `B/pages/*` 里的非 Apple 文档；Apple 开发者文档树与平台安全指南内**没有**任何 SBOM 生成或消费口径。因此本文凡是涉及"软件物料清单"的地方一律写"Apple 公开语料无对应句子，属组织侧自证"，第 26 章列为 G1。→ 见第 13 章
- **缺口 B（`swift package` 命令级机读输出件未取回）**：SPM 侧本文只持有 Xcode 文档给出的 `Package.resolved` 句子与 CI 标志位句子；`swift package resolve` 之外的 machine-readable 输出件本轮未取回。本文不写任何命令级输出格式，第 26 章 G2。→ 见第 4、5 章
- **缺口 C（App Store Connect 侧的校验读数不可得）**：`Third-party SDK requirements` 第 122 行只说 "Xcode will validate that it was signed by the same developer"，**校验发生在 Xcode**；ASC 服务端是否二次校验、不通过时开发者拿到什么读数，本轮语料没有句子。第 26 章 G3（这条是第 08 篇 12.3 节缺口的延伸：名单部分已由本文关闭，校验读数部分本文同样未关闭）。→ 见第 7 章
- **缺口 D（`Podfile.lock` 语义件未取回）**：本文 CocoaPods 侧只取回 Podspec Syntax Reference（`spec.source` 的 `:tag`/`:branch`/`:commit`/`:http`+`sha256`，第 203—215 行；`vendored_frameworks`，第 528 行）。`Podfile.lock` 各段的**字段语义**本轮未取回，因此第 4 章只写"锁定文件的存在性与提交状态"这一层，不解释锁文件内部字段。第 26 章 G4。→ 见第 4 章
- **缺口 E（本文的主缺口）**：Apple 公开语料对"app 里第三方代码的 CVE 归属"**没有任何一句**。三方安全公告只覆盖 Apple 自己的软件，CISA KEV 只覆盖被在野利用的条目。本文对这一层的处理是给出一套可执行的**登记规则**（第 10 章）并把"公开口径不存在"写进第 26 章 G5，绝不发明一条 Apple 没说过的归属规则。→ 见第 10 章

原文自身的拼写与格式异常一律保留原样并加注，本文不"顺手修正"。除上面第 6 条的 `Appleissued` 之外，另一处是《Creating a multi-platform binary framework bundle》与《Verifying the origin of your XCFrameworks》两页里对同一个检查器分别写作 "Xcode's XCFramework inspector" 与 "the inspector"，本文引用时给页名 + 行号而不试图统一。

### 2.6 证据分层

本文引用的公开材料分五层，各层能证明的东西不同，行文里会标明用的是哪一层：

- **平台安全层**：Apple 平台安全指南（4,885 行逐行版本）。它能证明**强制代码签名、库校验与 Team ID 链接规则**这些"系统会拦什么"的事实（第 2350—2362 行族）。它是本文唯一能证明"平台侧行为"的层。
- **开发者流程层**：Xcode 文档（依赖声明、CI 构建、二进制依赖识别、多平台框架包、构建产物布局、代码签名格式等 36 页）与 Tech Notes。它能证明**工程侧与构建侧有什么读数和没有什么读数**——"没有什么"这类证据在第 9、11 章承担主要作用。
- **申报与审核层**：`Third-party SDK requirements`（86 条强制名单 + 签名校验句）、App Review Guidelines、导出合规与公证文档。它们能证明**义务落在谁头上**，不能证明事实状态。
- **第三方工具文档层**：CocoaPods Podspec Syntax Reference、Swift Package Manager 的 README 与 Package Registry Usage。它们只在本文需要说明"另一套解析器怎么锁定版本"时出现，且**明确标注为非 Apple 文档**，其口径不与 Apple 文档互换。
- **公告与目录层**：Apple 安全公告的三份 CSAF JSON、`100100` 并行版本线页、CISA KEV `known_exploited_vulnerabilities.json`（`catalogVersion=2026.10.30`）。它们能证明**归属语言的边界在哪里**——第 10 章的主要工作正是用这一层证明"这一层覆盖不到 app 里的第三方代码"。

五层之间不能互相换算的地方，就是第 3 章后半部分的 F1—F7。其中 F1（开发者流程层的"锁定"与平台安全层的"签名"在两套文档里各说一件事）和 F6（申报层的"你必须负责"无法换算成公告层的"这个 CVE 归你"）是本报告与其它篇差异最大的两处。

---

## 3. 三套词表：装配口径、平台签名口径、公告归属口径

本文说的"三套口径"，对应这条链路上三种**互不通约的公开产物**。第一套写在工程文件与 CI 里，回答"这段代码是怎么进来的、锁在哪一刻"；第二套写在平台安全指南与 Xcode 文档里，回答"这段代码的签名身份是什么、系统会不会加载它"；第三套写在安全公告与应急目录里，回答"这个缺陷是哪个组件的、谁发的"。三套都叫"第三方代码"，但没有一个字段能把它们换算过去。

### 3.1 装配口径（本文的台账语言）

这是本文自己定义、也是第 21 章脚本一实现的词表。设计目标与第 11 篇一致：**每个字段都能在公开文档里找到对应的机制事实，且没有任何字段需要越界取证才能填。**一条依赖 = 一个标识 + 若干〈键,值〉行；键必须带命名空间。

| 命名空间 | 字段 | 取值 | 对应机制事实 |
| --- | --- | --- | --- |
| `dep.` | `kind` | spm / cocoapods / carthage / xcframework / vendored_framework / static_library / dynamic_library / git_submodule / manual_copy / unknown | 装配路径有五条以上，锁定与校验语义各不相同（《Adding package dependencies…》第 17—21 行；Podspec 第 203—215、527—528 行） |
| | `requirement_kind` | version / range / branch / commit / unpinned / unknown | Xcode 三种 package requirement（Version / Branch / Commit，第 18—21 行）；CocoaPods `:tag`/`:branch`/`:commit`（第 203—205、212 行） |
| | `requirement_value` | 版本范围串 / 分支名 / 提交号 / URL | 需求本身不固定内容，只固定"允许什么" |
| | `resolved_version`、`resolved_commit` | 语义版本串 / 7—40 位十六进制 | 解析结果与需求是两件事；Commit 形态"isn't recommended"（第 21 行） |
| | `lock_present`、`lock_committed` | true / false / unknown | CI 文档要求"be sure to commit your project’s `Package.resolved` file"（第 6 行）并给出路径（第 10 行） |
| | `auto_resolution` | enabled / disabled / unknown | `xcodebuild` 需另传 `-disableAutomaticPackageResolution`（第 11 行） |
| | `binary_form` | source / binary_xcframework / binary_framework / binary_static / binary_dynamic / unknown | 源码依赖与二进制依赖的取证可能性不同（《Identifying binary dependencies》第 5、7 行） |
| | `origin_url`、`origin_trust` | 地址串 / first_party_declared · mirror · vendor_release · unknown | "Only add package dependencies by trustworthy authors"（第 16 行） |
| | `provenance_recorded`、`integration_date` | true/false/unknown、ISO 日期 | 谁在哪一刻把它放进来；二进制形态的 checksum 只在解析或更新时被比对（第 16 行） |
| `sig.` | `state` | signed_expected / signed_other / unsigned / invalid / removed / expired / revoked / not_applicable / unknown | XCFramework 校验的失败形态（《Verifying the origin…》第 6、29 行） |
| | `team_id`、`team_id_expected` | 10 位字母数字串或 unknown | "A team identifier is a 10-character alphanumeric string—for example, 1A2B3C4D5F."（指南第 2362 行） |
| | `identity_changed`、`change_reason` | true/false/unknown；ownership_transfer / certificate_renewal / repackaged / team_rotation / none / unknown | 同一条签名变化的**两种并列解释**（第 14 行合法、第 16 行非法） |
| | `fingerprint_recorded`、`verification_surface`、`error_text_seen`、`disposition_date` | bool；xcode_build / manual / none；bool；ISO 日期 | 自签身份时检查器给出 SHA-256 指纹（第 10 行）；错误文本形如 "[XCFramework name] is not signed with the expected identity and may have been compromised"（第 21 行） |
| `manifest.` | `on_required_list`、`list_name_match` | true/false/unknown | 强制名单 86 条（第 124—210 行）；名单是**按 SDK 名**匹配的，名不实即无从判定 |
| | `privacy_manifest_present`、`signature_required`、`aggregate_report_seen` | true/false/unknown | 清单义务与二进制签名义务（第 122、124 行）；Xcode 在归档前把各清单合成一份报告（第 120 行） |
| `ver.` | `shipped_version_source` | lockfile / binary_metadata / crash_log / app_store_connect / unknown | 四种来源的置信度不同，本文第 9 章据此分级 |
| | `version_confidence` | exact / range / unknown | 分支形态的需求只能给出 range，不能给出 exact |
| | `device_visible`、`org_visible` | true/false/unknown | 设备侧与组织侧能否读到这一格（第 12 章） |
| `cve.` | `cve_id`、`attribution` | `CVE-YYYY-NNNN…`；app_dev / sdk_provider / upstream / platform / shared / unassigned / unknown | **本字段无 Apple 文档依据**（缺口 E / G5），是本文的登记规则而非平台口径 |
| | `advisories_apple`、`advisories_sdk_provider`、`advisories_upstream`、`kev_listed` | bool/unknown | 三个公告面加一个在野条目面，四者覆盖互不重合（第 10 章） |
| | `fix_version_known`、`fix_version_shipped`、`fix_adopted` | bool/unknown | "上游修了" / "我们带着修好的版本" / "集成方已采纳"三件事，缺一个都不能关闭 |
| `remove.` | `requested`、`removed_at`、`recheck_date` | bool/unknown；ISO 日期 | 移除请求与实际复核是两个时刻 |
| | `residual_refs`、`witness_type`、`provable_absence`、`replacement` | none / binary / source / lock / unknown；build_log / lockfile / diff / scan / none / unknown；yes / no / witness_based；字符串 | 第 11 章的"可证消失"四格；`witness_based` 是本文里最弱的一档正面结论 |
| `build.` | `cache_used`、`resolution_pinned`、`reproducible`、`uuid_checked` | bool/unknown | 构建产物布局与 UUID 语义（《Understanding build product layout changes》；Tech Note 3178 第 7、30 行） |
| `org.` | `inventory_surface`、`mdm_visible` | mdm / none / unknown；bool/unknown | 组织侧可见性；Apple 公开语料没有"MDM 能列出 app 内第三方 SDK"的句子（第 12 章） |
| `key.` | **禁止存在** | — | 任何 `key.*` 字段被脚本一直接报警（K01）。见 2.4 节凭据边界 |

命名空间本身有八类合法值（`dep` `sig` `manifest` `ver` `cve` `remove` `build` `org`）加一类禁止值（`key`）；不带点、点在前两位、命名空间未知这三种形态分别报警（S03）。

### 3.2 平台签名口径：一句话能证明什么，不能证明什么

这一套词表不是本文造的，是 Apple 文档给的，但它的**颗粒度**必须说清楚，否则台账会把两种不同的校验混记成一格。

平台安全层给的是**加载期规则**：可执行代码必须由 Apple 签发的证书签名（指南第 2353 行），框架可以由开发者嵌入并由 Apple 签发的证书校验，校验"通过 team identifier string 完成"（第 2360 行），而进程在启动时链接的每个动态库都要做代码签名校验，规则是"可以链接系统自带的库，或者链接与主可执行文件**带相同 team identifier** 的库"（第 2362 行）。这一句给出的是**框架 ↔ 主程序**之间的比较。

开发者流程层给的是**采纳期规则**：当应用"adopt a new version of a third-party SDK"时，Xcode 会校验它是否"signed by the same developer"（SDK requirements 第 122 行），以及"预期身份"不匹配时报错（《Verifying the origin…》第 21 行）。这一句给出的是**版本前后两次之间**的比较。

两套词表用同一个词 "same"，比较对象完全不同。平台层不管这段代码是什么时候被采纳的，只问它现在能不能被加载；流程层不管它能不能被加载，只问它和你上次拿到的那份是不是同一个开发者签的。**台账若只记一格"已签名"，就同时丢掉了这两条判据**——这是 F1，也是本文把 `sig.state` 与 `sig.verification_surface` 拆成两个字段的原因。

平台签名口径还有一处不能证明的东西值得单独说：`library validation` 这个术语在指南全文里**命中为零**（本文对 4,885 行文本做过检索）。指南描述的是同一种行为的实质（第 2362 行整句），而不是那个名字。凡是把"库校验"当作 Apple 公开术语来引用的场合，本文都改写成"第 2362 行所描述的 team identifier 链接规则"，不借用未出现的术语。→ 见第 7 章

### 3.3 公告归属口径：组件名不是 SDK 名

第三套词表来自 CSAF 与 KEV。Apple 的三份并行版本线公告（本轮 149041 / 149227 / 149230）共 **392 条 CVE 行**，每条落在一个 product / component 树上；组件标题的形态是"系统组件名 + 机型范围"，而不是任何第三方 SDK 的名字。本轮从这三份 JSON 里抽出的**带开源上游语句的条目只有 1 条**（`CVE-2019-5598`），它是"Apple 承认某个组件来自上游"的读数，不是"app 里的第三方 SDK 由谁负责"的读数。

CISA KEV（`catalogVersion=2026.10.30`，`vulnerabilities` 共 **1,766 条**，`vendorProject` 去重后 **291 个**，其中取 Apple 的 **95 条**）给的是另一件事：**这条缺陷已被在野利用**。它既不覆盖未在被利用的第三方缺陷，也不区分"Apple 系统里的第三方代码"和"某个 app 里的第三方代码"。

所以公告归属口径能证明的是"某个组件的某个缺陷被谁公告"，不能证明的是"这段代码在哪个应用的产物里"。这条边界是第 10 章全部论证的起点，也是本文唯一一处**公开口径完全缺席**的层次（G5）。

### 3.4 三套词表各自的主语与宾语

| 口径 | 主语（谁能填这一格） | 宾语（这一格说的是谁） | 时间基准 | 缺位时能否补 |
| --- | --- | --- | --- | --- |
| 装配口径 | 应用团队、构建系统 | 一段代码进入产物的动作 | 解析/提交的那一刻 | 能（工程内有事实文件） |
| 平台签名口径 | 平台、Xcode | 一份二进制的签名身份 | 加载/采纳的那一刻 | 部分能（产物内有签名） |
| 公告归属口径 | 公告作者、目录维护者 | 一个组件的一个缺陷 | 发布日 | **不能**（主语不认识你的产物） |

第三行的"不能补"是本文与第 09 篇最大的方法差别：第 09 篇讨论的更新链上，三套口径的主语可以是同一个主体（Apple），因此公告与设备之间存在可核对的传导；本文讨论的供应链上，公告作者**永远不知道你的产物里有什么**，所以传导链在这里断掉，只能靠集成方自己的台账接续。

### 3.5 七处换算失败（F1—F7）

以下七处是"看起来能换算、实际不能"的位置。每一处给出两端的原文句子和为什么接不上，后文各章引用 F 编号时不再重述理由。

- **F1｜"signed by the same developer" ≠ "any library with the same team identifier in its code signature as the main executable"。** 前者比版本之间的签名者（SDK requirements 第 122 行），后者比框架与主程序（指南第 2362 行）。台账写一格"已签名"无法回答"哪个校验过了"。→ 第 6、7 章
- **F2｜需求形态的等价物不存在。** Xcode 给 Version / Branch / Commit 三种（第 18—21 行），CocoaPods 的 `:git` 支持 `:tag`、`:branch`、`:commit`、`:submodules`，`:http` 支持 `:sha256`/`:sha1`（Podspec 第 212—215 行）。**CocoaPods 的 http 形态能带内容哈希，Xcode 的三种 package requirement 里没有一格是内容哈希**；反之 SPM 的二进制依赖 checksum 由作者在 manifest 里给出（第 16 行），CocoaPods 侧对应的是 `:http`+`sha256`。两套"锁定"锁的是不同的东西，不能填进同一格。→ 第 4 章
- **F3｜`Package.resolved` 在册 ≠ CI 按它构建。** 文档同时给出两件事：提交锁文件（第 6 行）与另传 `-disableAutomaticPackageResolution`（第 11 行）。只满足前者时，`xcodebuild` 仍可能重新解析。"我们有锁文件"不能换算成"构建必然用它"。→ 第 5 章
- **F4｜清单在 ≠ 代码可信。** 清单与签名的强制名单只给 SDK 名（86 条，第 125—210 行），**没有一条给出提供方身份、版本号或签名主体**。名单能换算成义务，不能换算成归属。→ 第 8 章
- **F5｜"we are responsible" ≠ 归属规则。** SDK requirements 第 118 行与审核指南第 127 行把责任落到应用开发者身上，两句话都是**义务句**，不含任何"这个 CVE 该记在哪一方"的判定标准。义务与归属之间缺的那一步，Apple 语料没有补。→ 第 10 章
- **F6｜版本读数四种来源不可互换。** 锁文件读到的是解析结果，产物元数据读到的是编译进去的版本串，崩溃日志读到的是符号化时刻的版本，App Store Connect 读到的是**提交件**的版本。四者回答的不是同一时刻的同一个问题，"我们的版本是 X"必须先说明来源。→ 第 9 章
- **F7｜"已移除" ≠ "可证不在"。** 源码引用清了、锁文件里没有它了，产物里仍可能残留 vendored 二进制；反之构建日志没出现它，也可能只是缓存命中。移除的四个格（`residual_refs` / `witness_type` / `provable_absence` / `recheck_date`）与"我们删掉了"这句话之间不能互相换算。→ 第 11 章

七处里有四处（F1、F2、F3、F6）能由公开文档直接判"不成立"，三处（F4、F5、F7）只能判"公开口径不足"。这个 4:3 的分布就是本文第 19 章把 J3 设为常态而不是例外的原因——供应链上多数问题不是"你没做对"，而是"平台没有给你可以核对的口径"。

---

## 4. L1 声明与锁定层

### 4.1 这一层管什么

L1 只回答一个问题：**这段外部代码是被哪句话请进来的，那句话把它钉到了什么程度**。它不管解析结果（L2）、不管二进制身份（L3）、不管清单义务（L5）。

这一层之所以要先立，是因为"锁定"这个词在 iOS 工程语境内**不是一种状态而是一个谱**，而且不同装配通道的锁定终点不一样：有的锁到版本号区间、有的锁到分支指针、有的锁到提交号、有的锁到内容哈希、有的什么都不锁。台账若只用一栏"版本"记录，就丢失了"锁到哪一刻"这个归属判定里最关键的信息——**因为后文所有"这段代码是谁的"结论，都要求先把"是哪一版"钉住**。

### 4.2 五条装配通道与各自的机制口径

| 通道 | 声明写在哪个文件 | 锁定语义（公开口径） | 谁执行解析 | 出处 |
| --- | --- | --- | --- | --- |
| SwiftPM（Xcode 集成） | `Package.swift` / 工程内 package requirement | 三型 requirement：Version / Branch / Commit | Xcode 或 `xcodebuild` | 《Adding package dependencies to your app》第 17—21 行 |
| SwiftPM 二进制目标 | manifest 内 `binaryTarget` | URL 形态带 checksum；本地形态**不生成 checksum**，把 `.xcframework` 直接放进包的 Git 仓库 | Xcode 在校验归档件与 manifest 声明一致时比对 checksum | 《Distributing binary frameworks as Swift packages》第 15—16 行 |
| CocoaPods | `Podfile` / `podspec` 的 `spec.source` | `:git` 支持 `:tag` `:branch` `:commit` `:submodules`；`:svn` 支持 `:folder` `:tag` `:revision`；`:hg` 支持 `:revision`；`:http` 支持 `:sha256` `:sha1` `:headers` | CocoaPods（非 Apple 工具） | Podspec Syntax Reference 第 203—215 行 |
| 手工 XCFramework / vendored 框架 | 无声明文件，直接加入 target | **没有任何锁定**：文件本身即全部内容 | 无 | 《Verifying the origin of your XCFrameworks》第 5 行；Podspec 第 527—528 行（`vendored_frameworks` 写法） |
| Git submodule / 源码内嵌 | `.gitmodules` 或直接把源码放进仓库 | 锁到父仓库记录的提交号，但没有依赖解析器参与 | Git | 本文不展开（归属结论与手工形态同类） |

五行里最特殊的是第四行。**手工放入的 XCFramework 没有声明、没有解析、没有锁文件，因此在 L1 上没有任何可核对的读数**——它的全部归属证据只能来自 L3（签名身份）与台账自记的 `origin_trust`。这正是脚本一对 `dep.lock_present=false` 且 requirement 为 commit 形态时报 M01（"提交号不在锁文件里，是手工拷贝形态"）的原因：那格数据在逻辑上不属于任何解析器产出的锁文件，只可能是人手抄进去的。

### 4.3 三型 requirement 的锁定强度：文档自己给的排序

Xcode 文档对三种 requirement 的说明里带了两处明确的价值判断，本文按它们排序：

- **Version**（第 19 行）：可以选择接受到下一个 major 或下一个 minor 的更新，也可以选具体区间或精确版本；"The version rule requires Swift packages to conform to semantic versioning."（要求上游遵守语义化版本）。
- **Branch**（第 20 行）：使用场景是"developing multiple packages in tandem and don't want to publish versions"，即协同开发时的**临时**形态。
- **Commit**（第 21 行）：原文直接写 "Choosing this option isn't recommended, and you should only use this option in exceptional cases."，理由给得很实在：钉到提交确实保证内容不变、代码稳定，**但"You don't receive any updates"**；紧接着建议"如果你担心远端包的稳定性，应当选 version 形态里更严格的档位"。

这段口径给出一个反直觉但重要的结论：**在本报告集的判据里，Commit 形态不是最强锁定。**它把内容钉死了，同时把补丁通道钉死了——第 10 章的 CVE 归属讨论里，一个以 commit 装配的依赖天然无法满足 `cve.fix_adopted` 的更新路径。归属判定要同时看"钉得多紧"和"能不能动"，因此本文用二维记法：`requirement_kind`（钉法）+ `requirement_value`（钉在哪）+ `resolved_version`（解析到什么）。三格缺一即判定降等（M08、M09、V03）。

CocoaPods 一侧多出一格本文很需要的东西：**`:http` + `:sha256`/`:sha1` 是内容级锁定**（Podspec 第 214—215 行的例子给的是一个 SDK zip 加一个 40 位 sha1）。SwiftPM 侧最接近的是 URL binary target 的 checksum（由作者用 `swift package compute-checksum` 生成，第 15 行）。两者都不出现在 Xcode 的三型 requirement 里——这就是 F2：**"锁到内容"这件事在两条通道上都有，但都不是 Apple package requirement 词表里的一个选项**，所以台账必须显式记 `dep.requirement_kind=unpinned` 之外的形态，不能把哈希塞进 `commit` 那一格。

### 4.4 输入 / 输出 / 台账字段

- 输入：一次"添加依赖"动作（UI 或文本改动）＋ 一句 requirement。
- 输出：一个可归属的声明形态，和一个（可能不存在的）解析基准。
- 字段：`dep.kind`、`dep.requirement_kind`、`dep.requirement_value`、`dep.resolved_version`、`dep.resolved_commit`、`dep.lock_present`、`dep.lock_committed`、`dep.binary_form`、`dep.origin_url`、`dep.origin_trust`、`dep.provenance_recorded`、`dep.integration_date`。

`dep.origin_trust` 的四档取值是本文对文档一句重要话的工程化：《Adding package dependencies to your app》第 16 行的旁注（`ASIDE(important)`）**"Only add package dependencies by trustworthy authors."**（第 16 行）。这句话没有给"可信"的判据，因此本文不发明判据，只要求登记"这条声明是谁给的"：`first_party_declared`（本方工程文档明确指定作者与仓库）、`vendor_release`（提供方自有分发面）、`mirror`（从镜像或内部缓存取回）、`unknown`。

### 4.5 失败形态

| 编号 | 失败形态 | 为什么这是问题而不是笔误 | 脚本信号 |
| --- | --- | --- | --- |
| DL-1 | 装配通道未登记 | 五条通道的锁定语义不同，通道未知则"锁到哪一刻"这个问题无法回答 | M08 |
| DL-2 | requirement 形态未登记 | 不知道有没有被钉住；`unpinned` 与空值含义不同，前者是结论后者是没看过 | M09 |
| DL-3 | 以 commit 形态装配但无锁文件 | 提交号来自人手抄录，解析器没有为它出过场 | M01 |
| DL-4 | 分支型 requirement 且自动解析开启 | 每次构建可以取到不同代码；分支指针本身还会随远端移动，即使锁文件在册 | M02、M02b |
| DL-5 | 锁文件存在但未提交 | 开发机与 CI 可解析出不同版本，"我们用的是 X"这句话没有公共参照 | M03 |
| DL-6 | 解析结果与需求对不上 | 要么需求被改过没记，要么解析器给出的不是那句话允许的内容 | M04 |
| DL-7 | 无 `origin_url` 的二进制形态 | 取回位置不可回溯，L3 的"预期身份"就没有比对基准 | M06 |
| DL-8 | 来源记为镜像且未登记指纹 | 镜像件与官方发布件的一致性无从核对 | M07 |
| DL-9 | `origin_url` 走明文 `http` | 取回件完整性只剩转录口径 | M07b |

DL-4 是这九条里唯一一条**"看起来什么错都没犯"的失败**：工程有锁文件、CI 也提交了，但 requirement 是分支。文档层面它完全合法（第 20 行给出了使用场景），归属层面它是本文最难写的一格——`version_confidence` 只能记 `range`，而第 10 章的 CVE 结论几乎都需要 `exact`。本文对它给的不是"改掉"，而是"记下来它是区间"（V03 只在**未登记置信度**时报，不在记为 `range` 时报）。

### 4.6 可得证据与判据

这一层的证据是**工程内已提交的文件本身**：`Package.swift` 的那一句、`Package.resolved`（其路径由文档给出：`[appName].xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved`，CI 文档第 10 行）、`Podfile.lock`、`.gitmodules`。它们能证明"声明允许什么"和"上一次解析到了什么"，**不能证明"这一台设备上跑的是哪个版本"**——后者要到 L6 才能判。

判据一句话：**L1 只在"这句话能否唯一定位一份内容"的意义上闭合。**如果 requirement 是区间或分支，L1 永远不闭合，本文允许它带着 `range` 进入 L2，但第 19 章的等级上限就降到 J2。

---

## 5. L2 解析与装配层

### 5.1 这一层管什么

L1 管"说了什么"，L2 管"**做了什么**"：把需求变成一份落到磁盘上的代码或二进制的那次动作，以及这次动作发生在哪台机器、哪一刻、按不按锁文件。

这一层要单列，是因为 Apple 的公开口径里存在一个**双重要求**：既要提交锁文件，又要额外传一个标志位。两者是两件事，做完前一件不等于做完后一件。CI 文档原文两处并列：

> "However, be sure to commit your project’s `Package.resolved` file to your Git repository. This ensures a reliable CI workflow that always uses the expected version of a package dependency."（第 6 行）
>
> "If your CI pipeline uses the `xcodebuild` command directly, also pass the `-disableAutomaticPackageResolution` flag. This flag ensures that the CI pipeline always uses the package dependencies as defined in the `Package.resolved` file."（第 11 行）

两句的关键词是 **also**。"提交锁文件"这句的强度是"Most projects … don’t require additional configuration"（第 6 行前半），"传标志位"这句的强度是"If your CI pipeline uses the `xcodebuild` command directly"——**凡是直接用 `xcodebuild` 的流水线都在适用范围内**。因此本文把 L2 的核心判据定为一条：**只有当 `auto_resolution=disabled`（或该流水线不使用 `xcodebuild` 直接调用）时，锁文件才参与构建的正确性论证。**

### 5.2 装配动作的三个可核对时刻

| 时刻 | 发生什么 | 公开口径 | 能证明什么 | 不能证明什么 |
| --- | --- | --- | --- | --- |
| 解析（resolve） | 按 requirement 选定版本，写/更新 `Package.resolved` | CI 文档第 9 行："Xcode stores the exact version of each package dependency in a file called `Package.resolved`. The file automatically updates when package requirements … change." | 上一次解析到了哪一版 | 构建时用的是不是这一版 |
| 取回（fetch / checksum 比对） | 拉源码或下载归档件；URL 二进制目标在此刻比对 checksum | 《Identifying binary dependencies》第 16 行："When Xcode resolves or updates package dependencies, it doesn’t allow binary dependencies to change the checksum without also changing the version." | 取回件与 manifest 声明一致 | **不证明**远端在两个时刻之间没有换内容 |
| 链接/嵌入 | 产物里出现该框架或其符号 | 《Understanding build product layout changes》第 8—11 行给出 bundle 内可执行目录布局；Tech Note 3178 第 7 行给出每份 Mach-O 镜像带 build UUID | 产物里确实有这段代码 | 这段代码的来源与归属 |

第 16 行那句值得再看一遍它的**边界**：checksum 只在"resolves or updates"这一刻参与，且规则是"不许在不改版本的前提下改 checksum"。这条保护是**作者侧**的（作者必须"create a checksum and include it in the package manifest"，同一页第 15 行给出作者生成命令），它把"提供方悄悄换了一份二进制但版本号不动"变成 Xcode 会拒绝的动作。反过来，它**不覆盖**本地路径形态——文档第 16 行（Distributing binary frameworks 一页）明确写本地包"don’t generate a checksum"，把 `.xcframework` 直接放进 Git 仓库。**这条通道上没有内容级校验，只有仓库历史**。

### 5.3 输入 / 输出 / 台账字段

- 输入：一次构建动作（人或 CI）＋ requirement ＋ 锁文件状态 ＋ 解析器开关状态。
- 输出：落盘的依赖内容 ＋ 一个（可能缺失的）解析基准 ＋ 产物内的镜像与 UUID。
- 字段：`dep.auto_resolution`、`dep.lock_present`、`dep.lock_committed`、`dep.resolved_version`、`dep.resolved_commit`、`build.resolution_pinned`、`build.cache_used`、`build.uuid_checked`。

脚本二把这一层的证据落成三份文件里的两件事：**装配登记件**（每个依赖一行：通道、requirement 形态与值、解析结果、锁文件是否提交、集成日与集成人）与**产物读数件**（每个构建一行：构建标识、依赖、读数来源、产物里的版本串、置信度、是否记录 UUID、构建日）。两份的差集就是 L2 的判定对象：**登记了却没读到的依赖，和读到了却没登记的依赖，是两种不同的归属失败**（X01、X02）。前者说明构建里没有它（或者它换了名字出现），后者说明产物里存在一段工程台账不知道来源的代码——后者更严重，因此本文把它列为阻断项而不是提醒项。

### 5.4 失败形态

| 编号 | 失败形态 | 为什么这是问题而不是记录习惯 | 脚本信号 |
| --- | --- | --- | --- |
| RS-1 | 提交锁文件但没传标志位（直接用 `xcodebuild`） | 文档两处并列，只满足前者时 CI 仍会重新解析；"按锁文件构建"这句话不成立 | M02、Z02 |
| RS-2 | 自动解析状态记为 `unknown` | 这一格只有三种取值，`unknown` 是诚实的写法，但它把结论锁在 J3；脚本不猜 | M02 判定链、J3 |
| RS-3 | 产物读到某依赖、装配登记件里没有 | 产物里存在台账不认识来源的代码 | X02 |
| RS-4 | 装配登记件里有、产物读数件里从未读到 | 可能是未链接、可能是改名；两种都不是"已闭合" | X01 |
| RS-5 | 同一依赖两条读数版本不同且都记为 exact | 一个钉不住两个版本；至少要有一条读数的来源填错 | X04、Z08 |
| RS-6 | 读数来源记为 `unknown` | 版本串本身没有假伪，但无法参与任何结论 | Z08 |
| RS-7 | 构建用了缓存却没登记缓存范围 | "重跑一次得到同一产物"这句话的适用范围被夸大 | B03 |

RS-1 是本报告集 1.4 节示例里的第一处（`Z02`）。它的危险性不在"版本会漂"这一常见说法，而在**它会伪装成已闭合**：锁文件确实在仓库里，`git log` 能看到它的每一次变更，评审时看到它便以为构建必然按它——而文档给出的正是相反条件（第 11 行）。本文把它写成一条**可脚本化**的判据：`requirement_kind ∈ {branch, unpinned}` 且（`lock_committed=false` 或 `auto_resolution=enabled`）→ 直接判该格不闭合（Z02、M02）。

### 5.5 可得证据与判据

这一层的证据分两类，强度不同：

- **强证据**：CI 配置文本（有没有传 `-disableAutomaticPackageResolution`）、已提交的锁文件内容、构建日志里解析阶段的行、产物内的版本串与 build UUID。这些都能被读者自己抄录后交给脚本二比对。
- **弱证据**：本地开发机的解析状态、Xcode UI 里显示的版本、"我们内部约定不自动解析"这句话。前者不可回指（每台机器一份），后两条是陈述而非读数。

判据一句话：**L2 闭合 = "需求 → 解析 → 构建"三跳都有读数，且第二跳到第三跳之间没有开关缺口。**任何一跳缺失，版本可观测性（L6）就无法给出 exact，CVE 归属（L7）也无法声明"我们带着修好的那一版"。

---

## 6. L3 二进制形态与签名身份层

### 6.1 这一层管什么

L3 回答两个问题：**这段代码在产物里以什么形态存在**，以及**它带的签名身份说明了谁**。两个问题必须放在一起答，因为形态决定了身份读数可不可得：源码形态没有"签名主体"这回事（它被编进你的二进制，签名是你的）；二进制形态则同时存在两个签名主体（提供方的、你的），而它们的比较恰好是本文最容易被记错的一格（F1）。

### 6.2 形态清单与每种形态的可核对读数

| 形态 | 台账取值 | 产物里长什么样 | 可核对读数 | 出处 |
| --- | --- | --- | --- | --- |
| 源码包 | `source` | 被编译进主可执行文件或目标产物 | 无独立镜像、无独立签名 | 《Identifying binary dependencies》第 5 行（源码可审、可改、可重编） |
| XCFramework | `binary_xcframework` | 多平台构件，内含静态或动态框架/库 | File inspector 的签名状态；Apple 开发者证书身份时**显示签名团队**；自签身份时显示**证书 SHA-256 指纹** | 《Creating a multiplatform binary framework bundle》第 5 行；《Verifying the origin…》第 8、10 行 |
| 单个 framework | `binary_framework` | `.framework` 目录 + 主二进制 | 同上（校验对象仍是那份 Mach-O） | 同上 |
| 静态框架 | `binary_framework`（+ `dep.kind=static_library`） | framework bundle，但主二进制是静态归档；客户端链接并嵌入时 **Xcode 15+ 会把主二进制从嵌入的 bundle 中省略** | 产物里可能"没有那个文件"却有那段代码 | 《Creating a static framework》第 5 行 |
| 可合并动态库 | `binary_dynamic`（+ `mergeable`） | release 构建里 Xcode 生成合并元数据并**把依赖合并进目标二进制** | 同上，且比静态框架更隐蔽：debug 与 release 产物形态不同 | 《Configuring your project to use mergeable libraries》第 6、8、10 行 |
| vendored 框架 / 库 | `vendored_framework` / `static_library` / `dynamic_library` | 由 Pod 直接带进来的现成件 | CocoaPods 侧的 `vendored_frameworks` 写法（可同时列 `.framework` 与 `.xcframework`） | Podspec 第 527—528 行 |
| 手工拷贝 | `manual_copy` | 无声明、无解析 | 只剩签名身份与自记来源 | 《Verifying the origin…》第 5 行；4.2 节 |

**这张表里最重要的两行是"静态框架"和"可合并动态库"。**它们给出一个对本报告全篇有约束力的事实：*产物里没有某个 `.framework` 文件，不等于产物里没有那段代码。* 静态框架的主二进制会被从嵌入 bundle 中省略（第 5 行原文 "Xcode 15 or later omits the main binary from the embedded framework bundle"），可合并动态库在 release 构建里被合并进目标（第 8 行 "merges dependencies into the target"），合并后的产物"slightly larger"（第 10 行）。因此本文第 11 章（可证消失）明确禁止把"Frameworks 目录里没有它"当作消失证据——那是形态误读，不是归属结论。这是 F7 的后半段成因。

顺带一条入口读数：SwiftPM 二进制依赖在工程里有一个可点开的标记——展开依赖后**寻找名为 `Referenced Binaries` 的文件夹**，它存在即说明该依赖分发二进制或依赖一个二进制（第 12 行）；进一步取证则 Control-click 其中的 XCFramework bundle 在 Finder 打开（第 13 行）。这是集成方**不需要任何越界动作**就能拿到的一份形态读数。

### 6.3 内容级校验：checksum 覆盖什么，不覆盖什么

《Identifying binary dependencies》第 16 行的旁注给了一条正面机制：作者必须创建 checksum 并写进 manifest；**"When Xcode resolves or updates package dependencies, it doesn’t allow binary dependencies to change the checksum without also changing the version."**

这句的归属含义要精确拆开：

- 它**覆盖**：提供方发布新版本时偷偷换二进制而不改版本号。校验点在解析/更新时刻。
- 它**不覆盖**：本地路径形态（Distributing binary frameworks 第 16 行明确"don’t generate a checksum"，改为把 `.xcframework` 放进包的 Git 仓库）。
- 它**不覆盖**：checksum 之外的身份问题。内容一致不等于内容可信——一份有缺陷的 SDK，checksum 完全正确。

因此本文在台账里把 `dep.provenance_recorded`（来源凭据有没有登记）与 `sig.state`（签名身份是什么）分开，且**不允许**用 checksum 的存在来填充这两格中的任何一格。

### 6.4 签名身份的四种读数与一种混合

《Verifying the origin of your XCFrameworks》一页给全了身份读数面：

1. **加入工程那一刻**：用 Xcode 检查嵌在 XCFramework 里的代码签名信息（第 6 行前半）。
2. **Apple 开发者证书身份**：File inspector **显示是哪个团队签的**（第 8 行）。这是 `sig.team_id` 的唯一直接读数来源。
3. **自签身份**：inspector 显示证书 SHA-256 指纹，文档指令是"Verify that the certificate fingerprint matches the value you expect"（第 10 行）。这条给出 `sig.fingerprint_recorded` 的必要性——**自签形态下没有 Team ID 可比，只有指纹可比**。
4. **签名被移除**：Xcode 在 inspector 显示该变化，构建系统在不解决时直接失败（第 32、34 行）。

混合的那一种是**过期或吊销**：即使身份自加入以来从未变过，Xcode 也会警告（第 30 行）。文档给的处置是"work with the SDK provider to obtain a new version of the framework that’s signed by a valid code signing identity"。这一条在归属判定上很有用：**它把"身份没变"与"身份仍有效"分成了两件事**，而多数台账只有前者一格。本文对应两个取值（`expired`、`revoked`）并要求 `sig.disposition_date`。

### 6.5 一次签名变化的两种解释——本文最重要的一格

文档在"Diagnose build failures caused by code signature changes"一节里把两种解释**并列**写出，顺序是合法的在前：

> "An XCFramework’s code signature can change for legitimate reasons, like: the provider of a third-party SDK transfers ownership of the SDK to another organization, who release a version that’s signed with the new organization’s Team ID."（第 13—14 行）
> "you switch from a vendor-supplied distribution of an XCFramework to a version that you build and sign yourself."（第 15 行）
>
> "A changed code signature can also indicate that the XCFramework has been tampered with, or another actor has injected their own code into your system, pretending it’s a version of the XCFramework."（第 16 行）

紧接着是那条错误文本：「Select the error that says "[XCFramework name] is not signed with the expected identity and may have been compromised"」（第 21 行；原文此处内层是一对排版双引号，本文按第 2.5 节的引号归一写作直引号，外层改用「」以避免同形引号嵌套）。

**这条错误文本本身不带判据。**它给出的是"身份不是预期的"这一事实加上一个可能性陈述（"may have been compromised"），而不是两种解释中的哪一种成立。文档给出的判据在别处：第 19 行要求"Work with the XCFramework’s provider to determine whether the change is expected"——**判据来自提供方的陈述，不来自 Xcode**。第 24 行给出对偶情形："If your team and the SDK provider can’t account for the change…"，处置是恢复带预期签名的版本或从工程里移除该框架（第 25—28 行：移到废纸篓、新开 Finder 窗口、从可信来源拖入替代件、回 Xcode 在 inspector 复核）。第 29 行的 `ASIDE(warning)` 又把范围放大：意外签名变化可能意味着基础设施里存在被利用的缺陷，因此要审计 XCFramework 的来源**并且**审计开发与部署环境，"even if you revert the XCFramework to a correctly-signed version"。

本文对这一格的处理有三条明确界限：

- **本文只把上述文档口径转成台账字段与判据**（`sig.identity_changed` + `sig.change_reason` + `sig.disposition_date`），不提供任何"让报错不再出现"的做法。文档里"Accept Change"那一步的前提是与提供方确认变更是预期的（第 19 行），确认这一步本文无法代替任何人完成；把它写成一套可照做的点击序列，正是本文排除项要挡的内容。
- **`change_reason` 未登记即不可定责**。脚本一对 `identity_changed=true` 且 `change_reason=unknown` 报 G02（"需向提供方核实，不得默认相容"）；对 `change_reason=ownership_transfer` 报 G02b——后者不是错误，而是本文承认它是**文档明列的合法原因之一**，同时要求登记新团队标识，否则第 9 章的版本读数会同时挂着两个身份。
- **`verification_surface=none` 而结论为可信**，报 G05；`error_text_seen=true` 与"可信状态"同时存在，报 G05b。这两条针对的是同一种记录习惯：把"我们用了这个 SDK 很多年没问题"当成身份核验。

### 6.6 输入 / 输出 / 失败形态 / 判据

- 输入：一份落到产物里的外部代码 ＋ 它的形态 ＋ 它的签名。
- 输出：一个身份读数（Team ID 或 SHA-256 指纹或两者皆无）＋ 一个形态结论（能否独立回指到某个依赖）。
- 字段：`dep.binary_form`、`sig.*`（全部）、`build.uuid_checked`。
- 失败形态：

| 编号 | 失败形态 | 为什么这是问题 | 脚本信号 |
| --- | --- | --- | --- |
| BF-1 | 二进制形态未登记来源凭据 | 身份再干净也回答不了"从哪拿的" | M05 |
| BF-2 | 签名状态为 unsigned / invalid / removed | 平台口径要求全部可执行代码由 Apple 签发证书签名；未签名不是可装配形态 | G01、G01b |
| BF-3 | 身份变更但原因未知 | 两种解释并列存在，不选一个就等于没读 | G02 |
| BF-4 | `team_id` 形态不符 10 位字母数字 | 与指南第 2362 行的定义不吻合，读到的多半不是 Team ID | G03 |
| BF-5 | 实际与预期团队标识不一致 | 需要显式处置记录，不能靠"能构建"结案 | G04 |
| BF-6 | 记为可信但核验面为 none | 结论无观测支撑 | G05 |
| BF-7 | 报错文本与可信状态并存 | 两项只能保留一个 | G05b |
| BF-8 | 二进制形态记为"签名不适用" | 静态链入也要签；要么改形态要么补签名 | G07 |
| BF-9 | 产物身份没有 build UUID 记录 | 指不回本次构建的那份镜像 | Z03 |
| BF-10 | 手工放入的外部框架且集成方未知 | 该形态上没有任何自动校验参与 | Z09 |

判据一句话：**L3 闭合 = 形态读数（有没有独立镜像）与身份读数（Team ID 或指纹）都有，并且两者指向同一个依赖标识。**任何一项缺失，第 15 章归属矩阵里这一行的"证据"列就只能填"陈述"，而陈述在四级判定里最多支撑 J3。

---

## 7. L4 强制签名与库校验的平台口径层

### 7.1 这一层管什么，以及为什么要把"平台侧"单列

L3 读的是**这段代码的身份**，L4 读的是**平台对身份说什么规则**。单列的原因很实际：读者拿到的每一条签名相关信号，都得分清它是**应用侧可核验的事实**（我能读到 Team ID、我能比对指纹）还是**平台侧的行为**（内核拒绝加载、系统在安装时校验）。把两者混成一句"iOS 会校验第三方库签名"，就会得出一个错误结论：以为平台校验失败会在设备上暴露给集成方。实际上集成方能在构建期拿到的读数与运行期平台行为，是两个不同的面。

平台安全指南在"App code signing process in iOS, iPadOS, tvOS, visionOS, and watchOS"一节给的是**规则面**（本节全部引文出处；该节自第 2350 行起）：

- 内核启动后控制哪些用户进程与应用可以运行；为确保所有应用来自"一个已知且经批准的来源"并且未被篡改，这些系统"require that all executable code be signed using an Appleissued certificate"（第 2353 行；该行是 PDF 转文本产物，原文的 "Apple-issued" 在此处丢了连字符，本文按 2.5 节第 6 条规则原样引用）。
- 强制代码签名把信任链从操作系统延伸到应用，并帮助**防止第三方应用加载未签名代码资源或使用自修改代码**（同第 2353 行后半）。
- 开发者可以嵌入框架，让"that code validated with an Apple-issued certificate (through a team identifier string)"（第 2360 行）。
- 进程启动时链接的每个动态库都要做代码签名校验；校验通过 team identifier 完成，它是"10-character alphanumeric string—for example, 1A2B3C4D5F"；程序可以链接系统自带的库，**或者链接与主可执行文件带相同 team identifier 的库**；由于系统自带的可执行文件没有 team identifier，它们只能链接系统自带的库（第 2362 行整句）。

### 7.2 `library validation`：一个术语的缺席

"**library validation**"这个词在平台安全指南全文里**命中为零**（本文对 4,885 行文本按大小写不敏感做过检索）。它出现在开发者文档里，但出现的语境是 macOS：Hardened Runtime 的能力清单里有一条 **"Disable Library Validation Entitlement — A Boolean value that indicates whether the app loads arbitrary plug-ins or frameworks, without requiring code signing."**（《Hardened Runtime》第 16 行），公证文档在讨论第三方设备扩展（PDE）时提到 macOS 10.14.x 与 10.15 之间该 entitlement 的必要性变化（《Notarizing macOS software》第 34 行）。

这条缺席有三层结论，本文把它们分别落到不同章节：

1. **不能把 "library validation" 当作 Apple 对 iOS 的公开术语来引用。**iOS 侧的同一行为在第 2362 行有实质描述但没有这个名字；本文一律写成"第 2362 行所描述的 team identifier 链接规则"。
2. **规则的名字只出现在 macOS 语境**，说明"禁用库校验"是一个 **macOS 侧可声明的豁免**（一条布尔 entitlement），而 iOS 侧的文档没有给出对应的豁免句。本文不推断"iOS 上等价物不可关闭"这一结论，只记录"iOS 侧公开语料没有给出可关闭的口径"（→ 第 26 章）。
3. **entitlement 归属方向值得单独一句**：《Hardened Runtime》第 8 行写"entitlements 只加在执行文件上，shared libraries、frameworks 与 in-process plug-ins **继承宿主执行文件的 entitlements**"。这句话在权限侧属于第 02 篇的对象，本文不重述；但它的**供应链含义**必须在本文说一次：**第三方框架没有自己的授权面，它拿到的权限是你这个宿主的**。装配进一个 SDK，等于把它放进你的权限边界里——这是"装配即责任"（第 8 章 F5、第 15 章归属矩阵）在平台规则上的落点，而不是道德命题。

### 7.3 分发通道决定签名读数落在谁手里

平台侧还有一条对 L4 影响很大的规则，写在《Using the latest code signature format》第 8 行：**经 App Store 或 TestFlight 分发的应用，"App Store Connect first verifies your signature, and then re-signs the app using an Apple identity, before making the app available for download."**（该行原文有拼写异常"DER embeddded entitlements"，三个 d，本文原样转录）

这条句子的归属后果需要写清楚，否则台账会记错主体：

- **校验发生在两处**：Xcode 在你采纳新版本 SDK 时校验签名者是否同一个开发者（SDK requirements 第 122 行）；App Store Connect 在分发前校验你的签名。两句主语不同、时刻不同。
- **到设备上的那份不是你的签名件**（App Store / TestFlight 通道下由 Apple 身份重签）。因此"设备上那个二进制的签名主体是提供方"这种记法是**错的**——设备侧读数（第 18 章）不能倒推装配期身份。装配期身份只能在工程与构建期取证。
- 其他通道（Ad Hoc、企业计划）不适用重签：同一页第 9 行说明这些通道由 Xcode 与 `codesign` 生成签名，macOS 10.14—11 上的签名可能不含 DER entitlements。

第 26 章 G3 就落在这一节：文档说 "Xcode will validate"（采纳期）与"App Store Connect first verifies"（分发期），但**没有给出 App Store Connect 校验不通过时开发者拿到什么读数**。本文不猜这个读数长什么样。

### 7.4 公证与锁定模式：本文用到与不用的边界

公证（Notarization）是 **macOS** 的机制，文档第 5 行明确"Notarization of macOS software is not App Review"。本文不把它当 iOS 供应链证据使用，只在两个地方引它作为对照：（a）说明 Apple 在"检查恶意组件"这件事上的公开口径是**先有签名再有公证**，且两者都不是审核；（b）说明 iOS 上没有等价的公开件可引。

同样地，本文不使用 Hardened Runtime 作为 iOS 侧证据（它连同上一条 entitlement 都是 macOS 目标的能力）。iOS 侧本文只用平台安全指南第 2350—2362 行族与开发者文档的采纳期句子。

### 7.5 输入 / 输出 / 失败形态 / 判据

- 输入：一条签名相关结论（来自 L3）＋ 分发通道。
- 输出：该结论属于**应用侧可核验**还是**平台侧行为**的归类，以及设备侧读数的正确解释。
- 字段：`sig.verification_surface`、`ver.shipped_version_source=app_store_connect`、`dep.binary_form`、`manifest.signature_required`。
- 失败形态：

| 编号 | 失败形态 | 为什么这是问题 | 脚本信号 |
| --- | --- | --- | --- |
| SV-1 | 把 Xcode 采纳期校验记成平台运行期校验 | F1 的另一种写法：两个时刻的判据不同 | G05 |
| SV-2 | 把设备侧读到的签名主体当作提供方身份 | App Store/TestFlight 通道下由 Apple 重签（第 8 行） | V01、Z08 |
| SV-3 | 用"iOS 会拒绝加载未签名库"证明某 SDK 已被校验 | 平台规则不是集成方台账的证据 | G01b |
| SV-4 | 借用 `library validation` 这个词指代 iOS 规则 | 该术语在本轮 Apple 语料里只出现于 macOS 语境 | 本文口径，不落信号 |
| SV-5 | 名单要求签名却没登记签名状态 | 义务已知而事实未知 | P02 |

判据一句话：**L4 不给归属结论，它只给"哪些格子不属于你"。**这一层的用处是让读者在出具"这段代码已由平台校验"这类句子之前，先看清校验的主体、时刻与通道。

---

## 8. L5 强制名单与隐私清单申报层

### 8.1 这一层管什么，以及与第 08 篇的分界

L5 只取申报语料里的**一个事实**：哪些第三方代码被平台点名"必须带隐私清单，且作为二进制依赖使用时还必须带签名"。这个事实对供应链的用处只有一个——**它是 Apple 公开语料里唯一一份"平台承认这些 SDK 存在于 app 中"的名单**。它不是可信名单、不是允许名单、不是版本清单，也不给出任何归属信息。

清单里写了什么、required reason API 用哪一档、Aggregate 报告由谁聚合、审核里谁签字——**这些全部是第 08 篇的对象，本文一律不复述**（见 2.2 节的三条硬线）。本节只处理名单的**读数性质**：它能证明什么义务，不能证明什么归属。

### 8.2 义务句与名单的读数

《Third-party SDK requirements》一页里，与本文有关的三句：

> "when you use a third-party SDK with your app, you are responsible for all the code the SDK includes in your app, and need to be aware of its data collection and use practices."（第 118 行）
> "When you prepare to distribute your app, Xcode will combine the privacy manifests across all the third-party SDKs used by your app into a single, easy-to-use report."（第 120 行）
> "You must include the privacy manifest for any SDK listed below when you submit new apps in App Store Connect that include those SDKs, or when you submit an app update that adds one of the listed SDKs as part of the update. Signatures are also required in these cases where the listed SDKs are used as binary dependencies. **Any version of a listed SDK, as well as any SDKs that repackage those on the list, are included in the requirement.**"（第 124 行）

第 124 行最后一句是本文在本层最重要的读数，它把三件事一次说清：

1. **义务不按版本切**："Any version of a listed SDK" —— 老版本不豁免。因此台账里"我们用的这个版本是名单生效之前发布的"**不能**作为免除理由。
2. **义务穿透重打包**："as well as any SDKs that repackage those on the list" —— 一个把 Alamofire 封装进自家 SDK 的支付框架，**仍在义务范围内**。这一句是本文第 10 章 CVE 归属讨论里唯一能借用的 Apple 口径：**平台在"义务"层面承认了封装关系**，尽管它在"归属"层面仍然无话（F5）。
3. **义务的触发时机是提交**：新增该 SDK 的更新提交、新 app 提交。因此它是**提交期**读数，不是构建期读数。

### 8.3 名单读数：86 条，零条给出归属

本轮已把该页正文的名单落盘为 `C/sdk-required-list.tsv`（名称 + 行号），读数如下：

| 读数项 | 本轮值 | 说明 |
| --- | --- | --- |
| 名单跨度 | 存档件第 **125—210** 行 | 页尾紧接 "Submit your feedback"，边界清楚 |
| 条数 | **86** | 无重名 |
| 含下划线的条目 | 19 | Flutter/Dart 插件命名风格的一部分 |
| 以小写字母开头的条目 | 24 | 同上 |
| 含斜杠的条目 | 1（`BoringSSL / openssl_grpc`） | 一条里并列两个名字 |
| 头词族（读者侧切分） | Firebase 12、Google 4、OneSignal 4、Rx 3，其余 49 族各 1 条 | **页面本身是平表，不标注归属方**；族切分是读者的观察，不是文档口径 |

**这份名单里没有任何一条给出提供方身份、版本号或签名主体。**它给出的是"名字 + 义务"。因此第 15 章归属矩阵里，名单只能出现在"证据 = 义务依据"这一列，绝不能出现在"证据 = 来源身份"这一列。

这条缺席在实操上有两个后果，本文把它们写成台账字段：

- `manifest.list_name_match`：名单是**按 SDK 名**匹配的，而你的产物里的镜像名、Pod 名、包名与名单里的写法未必一致（名单里有 `url_launcher` 与 `url_launcher_ios` 两条相邻项，也有 `BoringSSL / openssl_grpc` 这种一条两项）。名不匹配时**不能推断"不在名单上"**，脚本对 `on_required_list=true` 而 `list_name_match` 未取布尔值报 P05。
- `manifest.on_required_list` 未登记时报 P03，理由写得很直白：**名单事实要对照名单本身判定，本脚本不猜**。

### 8.4 义务闭合与归属不闭合：本层的判据

第 08 篇处理的是**申报闭合**（该写的写了没、该挂的挂了没、聚合报告对不对）。本文处理的是**归属闭合**，两者在同一条依赖上有四种组合，本文只承认第四种：

| 清单在 | 签名在 | 来源与身份登记 | 归属结论 |
| --- | --- | --- | --- |
| ✗ | ✗ | ✗ | 名单内则提交期本不应通过（P01）；无归属证据 |
| ✓ | ✗ | ✗ | 申报闭合，供应链未闭合 |
| ✓ | ✓ | ✗ | **最容易骗人的一格**：义务全尽，但"这段代码是谁的、哪一版"仍然说不出 |
| ✓ | ✓ | ✓ | 归属可出具 |

第三行是本文与第 08 篇最实的分工差别：**第 08 篇的判定走到第三行就成立了，本文的判定要到第四行。**一个把清单和签名都补齐、但工程侧没有任何装配与身份登记的依赖，在申报口径里是合规的，在供应链口径里仍是 J3（"来源或签名身份仍不确定：不能判断这段代码是谁的"）。

失败形态：

| 编号 | 失败形态 | 为什么这是问题 | 脚本信号 |
| --- | --- | --- | --- |
| PL-1 | 在名单上却缺隐私清单 | 名单口径下这一项不应被提交 | P01 |
| PL-2 | 在名单上、要求签名、二进制形态，却没登记签名状态 | 义务已知，事实栏为空 | P02 |
| PL-3 | 名单归属未判定 | 判定要对照名单本身，不猜 | P03 |
| PL-4 | 看过聚合报告却没登记版本来源 | **聚合面是清单的聚合，不是版本的聚合**；这是申报层与供应链层最常被混用的一格 | P04 |
| PL-5 | 名单名匹配与名单判定不闭合 | 两项互相引用 | P05 |
| PL-6 | 用"版本早于名单生效"作免除理由 | 第 124 行明确 "Any version" | 本文口径（不落信号，因为台账没有"免除理由"这一格） |
| PL-7 | 用"我们用的不是名单上那个 SDK，是别人封装的"作免除理由 | 第 124 行明确包含重打包者 | 同上 |

判据一句话：**L5 给义务，不给身份。**本层的读数只在两种判定里参与：提交期合规（第 08 篇）与封装关系承认（本文第 10 章借用）。

---

## 9. L6 版本可观测性层

### 9.1 这一层管什么

L6 回答一个极朴素、却在本报告集里第一次被单列的问题：**谁能知道这一台设备上的这个应用，跑的是这个 SDK 的哪一版？**

注意这句话里有三个可能被跳过的限定：**这一台**（不是"我们的最新版"）、**这个应用**（不是"我们的工程"）、**哪一版**（不是"我们升过级"）。第 1.4 节的示例之所以四处判定不成立，其中两处（`V03` 与"风险关闭"无可回指读数）就落在这一层。

### 9.2 四种版本来源与它们的置信度

| 来源 | 台账取值 | 读到的是什么 | 时刻 | 能证明 | 不能证明 |
| --- | --- | --- | --- | --- | --- |
| 锁定文件 | `lockfile` | 上一次解析选定的版本 | 解析时 | "按这句话解析会得到 X" | 构建是否用了它（F3） |
| 产物元数据 | `binary_metadata` | 镜像自身携带的版本串（framework 的 Info 域、Mach-O 里的版本载荷） | 构建产物 | **这一份产物里带的版本** | 设备上跑的是不是这一份 |
| 崩溃日志 | `crash_log` | 符号化时刻的镜像身份 | 现场 | 出问题时那一份镜像存在过 | 无 build UUID 时连符号化都做不到（TN3178 第 33 行） |
| App Store Connect | `app_store_connect` | **提交件**的版本 | 分发 | 提交的是哪一份 | 它是你的签名件（第 8 章：ASC 校验后用 Apple 身份重签，指南外的口径见《Using the latest code signature format》第 8 行） |

四行的排序就是本文给的置信度排序，但置信度不来自"来源名好听"，而来自**这条链路的两个已知断点**：解析→构建之间有没有开关缺口（L2），构建→设备之间有没有重签与更新换代（第 7 章、第 09 篇）。因此台账要求两格一起看：`ver.shipped_version_source` + `ver.version_confidence`（`exact` / `range` / `unknown`）。

三条本文会反复使用的换算规则：

- **钉到提交号即 exact**。脚本对 commit 形态装配却把置信度记成非 exact 报 V02（"提交号是唯一定位，应为 exact"）；反过来，分支形态只能 `range`，这是记录事实而非缺陷（V03 只在**未登记**置信度时报）。
- **来源记为 `unknown` 时，版本串本身不可用于任何结论**。脚本二对读数来源 `unknown` 报 Z08。这条很硬：一个"我记得是 3.4.2"的记录与一个产物元数据读数，在归属判定里权重相差两级。
- **同一依赖两条 exact 且不同版本 → 必有一条来源填错**（X04、RS-5）。本文不试图判定哪条对，只判定"这两条不能同真"。

### 9.3 设备侧与组织侧：两个"看不见"

L6 的诚实结论是**两个可见性缺口**，本文把它们写成字段而不是写成建议：

- **设备侧（`ver.device_visible`）**：应用自己的产物里带着第三方镜像，但公开语料没有给出"从设备外部列出某 app 内嵌了哪些第三方框架及其版本"的口径。设备侧能读到的东西属于第 02、03 篇的对象（容器、备份、诊断），本文不重述。声称设备侧可见却没有任何版本来源，报 V01。
- **组织侧（`ver.org_visible` / `org.inventory_surface`）**：Apple 公开语料没有"MDM 能列出被管设备上各应用内嵌的第三方 SDK 与版本"这一句。企业能知道装了哪个应用、哪个版本；**应用里装着谁家的哪一版第三方代码，对管理面不可见**。因此"监管方能核实我们移除了某 SDK"这句话不能依赖 MDM 读数，只能依赖自证的构建与产物记录。组织可见性记为否却填了 MDM 读数报 V04；声称组织可见但清单面为 none 报 V05。

这两格的意义不在"做不到"，而在**结论的主语必须换**：凡是依赖设备侧或组织侧读数的归属结论，都必须降级为"由集成方自证"（第 12 章 L9 展开）。

### 9.4 输入 / 输出 / 失败形态 / 判据

- 输入：一个版本陈述（来自任何一处）。
- 输出：该陈述绑定的〈来源, 时刻, 置信度〉三元组，缺失即不可用于结论。
- 字段：`ver.shipped_version_source`、`ver.version_confidence`、`ver.device_visible`、`ver.org_visible`、`ver.reported_by`。
- 失败形态：

| 编号 | 失败形态 | 为什么这是问题 | 脚本信号 |
| --- | --- | --- | --- |
| VO-1 | 版本陈述无来源 | 四种来源的换算规则不同，无来源等于无时刻 | Z08 |
| VO-2 | 置信度未登记 | 读者无法区分"钉住"与"区间" | V03 |
| VO-3 | 锁定文件版本当成产物版本 | 中间隔着 L2 的开关缺口（F3） | Z01 |
| VO-4 | 同一依赖两条 exact 不同值 | 不能同真 | X04 |
| VO-5 | 设备可见性声称与来源不齐 | 无观测支撑 | V01 |
| VO-6 | 组织可见性与 MDM 读数矛盾 | 两格互斥 | V04 |
| VO-7 | 非产物侧来源却记为 exact | 旁证只能支撑范围，精确版本要回到产物元数据或崩溃符号 | Z07 |

判据一句话：**L6 闭合 = 每条版本陈述都能回指到一个〈来源 + 时刻〉，且该来源能代表被讨论的那个对象（工程 / 产物 / 设备 / 提交件）。**这条判据是第 10 章 CVE 归属能不能说"我们带着修好的版本"的前提——**没有 L6，就没有任何一句修复声明是可核对的。**

---

## 10. L7 公告与 CVE 归属层

### 10.1 这一层管什么，以及本文在这一层没有公开口径可依

L7 回答："这段第三方代码的一个缺陷，**记在谁头上**，以及集成方能不能知道自己带着它。"

必须先说清楚一件事：**Apple 公开语料里没有任何一句回答这个问题。**（缺口 E / G5，2.5 节已就地注明）三方安全公告只覆盖 Apple 自己的软件，CISA KEV 只覆盖被在野利用的条目，两者都不谈"app 里第三方代码的缺陷该由哪个主体登记"。因此本章分两段：**前半是公开读数**（能证明公告面覆盖到哪里），**后半是本文给出的登记规则**（明确标注为本文口径，不冒充平台规则）。第 26 章 G5 就是把这条缺席写成一个结论而不是写成一个遗憾。

### 10.2 四个公告面，四种互不重合的覆盖

| 面 | 主体 | 覆盖什么 | 对集成方的用处 | 覆盖不到的地方 |
| --- | --- | --- | --- | --- |
| Apple 安全公告 / CSAF | Apple | Apple 自己软件里的缺陷，按 product/component 树组织 | 证明"Apple 有没有承认某组件来自上游" | 任何 app 内装配的第三方代码 |
| SDK 提供方公告 | 提供方 | 它自己发布的 SDK 的版本与修复 | 唯一能给出"SDK 侧修复版本"的面 | 提供方不公告时无面可读 |
| 上游开源项目公告 | 上游 | 上游代码的缺陷与修复 | 判定"提供方只是搬运者"的依据 | 上游不知道被谁用了它 |
| CISA KEV | 第三方目录维护者 | **已被在野利用**的条目 | 优先级排序 | 未在被利用的条目、app 侧装配事实 |

四行里只有一个交集对集成方有意义：**提供方公告 + 上游公告 → 修复版本；Apple 公告与 KEV → 只是旁证**。这正是脚本一的四格设计（`advisories_apple` / `advisories_sdk_provider` / `advisories_upstream` / `kev_listed`）。

### 10.3 本轮读数：公告面到底覆盖到哪

本轮从三份并行版本线公告 JSON 与 KEV 目录件里得到的读数：

| 读数 | 值 | 含义 |
| --- | --- | --- |
| 三份公告 CVE 行合计 | 95 + 134 + 163 = **392** | 全部 `vendor=Apple` |
| 带开源上游语句的行 | **1**（`CVE-2019-5598`，落在 149227） | 149041 与 149230 均为 0 条 |
| 公告里声明上游归属的行 | **0** | 没有任何一行公告声明"这段代码由某外部主体维护" |
| 去重后的组件标题数 | **101** | 组件名是系统组件名，不是 SDK 名 |
| 其中本文判读为"代码树在 Apple 之外"的组件 | 22 | **这是读者的判断，不是公告口径**，落盘件 `C/advisory-upstream-titles.txt` 自身已写明这一点 |
| KEV `catalogVersion` | 2026.10.30 | 本轮件版本 |
| KEV 条目数 / `vendorProject` 去重数 | **1,766 / 291** | Microsoft 390、Cisco 102、**Apple 95**、Adobe 83、Google 76、Oracle 46 为前六 |
| KEV 里 Apple 的行 | 95 | 全部是 Apple 平台软件，**无一条是"某 app 内嵌的第三方 SDK"** |

392 : 1 这个比例本身就是本章的结论：**在 Apple 的公开公告语言里，"第三方代码"几乎不是一个可归属对象。**而 KEV 的 291 个 `vendorProject` 里也不存在"某个 iOS 应用"这种主体——目录的主语是软件厂商，不是集成方。

本文把这组读数同时用于两个方向：一方面证明"公告面帮不上忙"，另一方面也证明**集成方不能把责任推给公告缺位**——第 8.2 节的第 124 行已经承认封装关系（"any SDKs that repackage those on the list"），义务不因上游不在公告里而消失。

### 10.4 本文给出的归属登记规则（**非 Apple 口径**）

以下七条是本文提出的登记规则，用途是让"归属"这一格在台账里可核对、可回指。**它不声称是 Apple 的规则，也不与任何 Apple 句子冲突。**

1. **记到能指回一份具体二进制为止。**`cve.attribution` 必须与 `dep.identity`（L3 的团队标识或指纹）落在同一依赖标识上；否则报 C05（"归属未登记：四级判定无法给出 J1"）。
2. **封装者承担集成义务，不冒充修复义务。**提供方重打包上游（第 124 行的 repackage 口径）时，`attribution=shared` 或 `sdk_provider`；当提供方公告与上游公告同时存在且提供方只是搬运，本文要求改写 `upstream`（C06b）。这条的目的不是分配道德责任，而是**让"修复版本从哪来"有唯一出处**。
3. **不得用 Apple 公告覆盖外部归属。**归属记为外部主体却声称 Apple 公告覆盖它，报 C02——Apple 公告只覆盖 Apple 自己的软件（10.3 的 392 : 1 是这条的依据）。
4. **归属记为平台方需要依据。**`attribution=platform` 但 Apple 侧与提供方侧公告都没登记，报 C06。
5. **在野条目先定归属再排优先级。**`kev_listed=true` 而归属未知，报 C03。KEV 提供的是紧迫性，不是主体。
6. **三格分离：修复版本已知 / 我们带着它 / 集成方已采纳。**`fix_version_known=false` 却登记了采纳状态报 C04；记为已采纳但没有实际上线的版本读数报 C04b（这一条直接依赖 L6，缺 L6 就无法闭合）。
7. **归属缺失时写 `unassigned`，不写 `unknown`。**两格在本文词表里不同：`unknown` 是"看过但判不出"，`unassigned` 是"这条缺陷还没被登记到任何依赖标识上"。混用会让第 20 章的指标 O1 失真。

七条规则里有六条能在 Apple 文档找到**间接**依据（义务句、repackage 句、身份句、清单聚合句），只有第 7 条纯属本文的登记卫生。把它们整体标注为"非 Apple 口径"是必要的诚实：**这一层的公开缺席不能被报告用一套看似权威的规则填平。**

### 10.5 三句义务句的位置

| 句 | 出处 | 能证明 | 不能证明 |
| --- | --- | --- | --- |
| "you are responsible for all the code the SDK includes in your app, and need to be aware of its data collection and use practices" | SDK requirements 第 118 行 | 责任主体是应用开发者；且这句话落在**隐私口径**语境 | 缺陷归属、修复义务边界 |
| "You are responsible for making sure everything in your app complies with these guidelines, including ad networks, analytics services, and third-party SDKs, so review and choose them carefully." | App Review Guidelines 第 127 行 | 责任主体同样是应用开发者，且明确点名广告网络/分析服务/第三方 SDK；"review and choose them carefully"是**选择时的义务** | 任何缺陷登记规则 |
| "Any version of a listed SDK, as well as any SDKs that repackage those on the list, are included in the requirement." | SDK requirements 第 124 行 | 封装关系被承认、义务不按版本切 | 归属主体排序 |

两句"you are responsible"加一句 repackage，是 Apple 语料里离"归属"最近的三句。**它们合起来仍然不构成一条归属规则**（F5）：它们说的是"结果由你承担"，不是"缺陷由你登记"。本章把这一区分写成一句可操作的话：**义务决定谁去修，归属决定这条记录挂在哪个标识上。**台账里两者都填 `app_dev` 是本文最常见的错误之一（见第 24 章误区）。

### 10.6 输入 / 输出 / 失败形态 / 判据

- 输入：一条缺陷标识 + 一个依赖标识 + 四个公告面读数。
- 输出：一个可回指的归属主体，和一个"能否声明已修复"的结论。
- 字段：`cve.*`（全部）。
- 失败形态：

| 编号 | 失败形态 | 为什么这是问题 | 脚本信号 |
| --- | --- | --- | --- |
| CV-1 | 归属未登记 | 无法出 J1 | C05 |
| CV-2 | 用 Apple 公告覆盖外部归属 | 公告面不覆盖 app 内第三方代码 | C02 |
| CV-3 | 在野条目未定归属就排优先级 | 紧迫性替代了主体 | C03 |
| CV-4 | 修复版本未知却记采纳 | 三格混成一格 | C04 |
| CV-5 | 记已采纳但无版本读数 | 缺 L6 支撑 | C04b |
| CV-6 | 归属记为平台方却两侧公告都空 | 无依据 | C06 |
| CV-7 | 提供方与上游公告并存但提供方只是搬运 | 修复出处不唯一 | C06b |
| CV-8 | 把义务句当归属句用 | F5 | 本文口径（不落信号） |

判据一句话：**L7 闭合 = 缺陷标识能回指到依赖标识，归属主体能回指到一次身份读数，修复状态能回指到一个版本来源。**三句缺一，第 19 章的判定停在 J2，且本文允许它就这样写出来——**"这条缺陷我们暂时说不出归谁"是一个可交付结论，不是失败。**

---

## 11. L8 移除与可证消失层

### 11.1 这一层管什么，客体与第 11 篇相反

L8 回答："**我们已经不用这个 SDK 了**"这句话要拿什么证明。

先划客体：第 11 篇证明的是**数据副本不在了**（客体是数据，证据面是介质、密钥与处置回执），本文证明的是**代码不在产物里了**（客体是代码，证据面是装配登记、构建产物与移除台账）。两篇的字段、脚本与判据互不引用。方法形似（都是"三件差集 + 时序 + 分级"）是刻意的，不是重复。

### 11.2 四类残留与两个形态陷阱

移除动作清掉的往往只是其中一类引用。本文把残留分四格（`remove.residual_refs`）：

| 残留类 | 清掉它的动作 | 常见漏清原因 |
| --- | --- | --- |
| `source` | 删除引用与调用点 | 编译通过即以为清完 |
| `lock` | 更新并提交锁文件 | 锁文件由解析器维护，人手不碰 |
| `binary` | 删除工程里的框架文件、Pod 的 `vendored_frameworks` 项、包内 `.xcframework` | **手工拷贝形态没有声明文件可删**，于是没人知道要删 |
| `none` | — | 只有四类都核实过才能填 |

两个形态陷阱直接来自第 6 章：静态框架的主二进制会被 Xcode 从嵌入 bundle 中省略（《Creating a static framework》第 5 行），可合并动态库在 release 构建里被合并进目标二进制（《Configuring your project to use mergeable libraries》第 8 行）。**这两种形态下，"产物里没有它的镜像"是正常状态，与它是否被移除无关。**因此本文对消失结论的取证顺序里，"看 Frameworks 目录"这一步的证据权重是零。

### 11.3 四种见证与三档结论

`remove.witness_type` 只允许四种正面见证，各自能证明的范围不同：

| 见证 | 能证明 | 不能证明 |
| --- | --- | --- |
| `build_log` | 这一次构建的链接/嵌入阶段没出现它 | 缓存命中时的旧产物、未参与构建的分支 |
| `lockfile` | 下一次解析不会选它 | 工程里手工放进去的副本（`binary` 残留） |
| `diff` | 两次产物之间的差异 | 差异方向对不对（改名会被读成消失） |
| `scan` | 扫描覆盖到的范围内没有 | 扫描口径之外的形态（合并进主二进制的那部分） |

三档结论（`remove.provable_absence`）：

- `yes`：`residual_refs=none` ＋ 有见证类型 ＋ 有 `recheck_date` ＋ 移除后没有反向读数。
- `witness_based`：有见证但仍有其它不确定项。**本文允许这一档作为正面结论交付，但等级封顶在 J1**（脚本一对 J1 的定义里第二档写明"来源、身份、版本、消失四项齐备且无阻断信号"，`witness_based` 只在无阻断时进入）。
- `no`：不可证。**这一档必须写明为什么不可证**，脚本对"记为不可证但没登记是否申请过移除"报 R07，就是要读者把"没打算移除"与"移除过但证不了"分开。

时序规则（脚本二的 Y 族）：`recheck_date` 早于 `removed_at` 报 R04 / Y 族同类；移除之后又读到 `binary_present` 报 Z10（"后续读数推翻了消失结论，产物里仍有这段代码"）；删除与轮换、恢复之间的先后不能同时为真这类判定在第 11 篇有对应形，本文不重复其语义，只保留供应链客体下的三条：`Y01`（移除早于登记）、`Y02`（复核早于移除）、`Y06`（同一依赖两条同类动作）。

### 11.4 输入 / 输出 / 失败形态 / 判据

- 输入：一个移除请求 + 一次或多次产物读数。
- 输出：一个带时刻与见证的消失结论，或一个明确的"不可证"。
- 字段：`remove.*`（全部）＋ 脚本二的移除台账件七列（序号、依赖、动作、事件日、残留、见证、复核日）。
- 失败形态：

| 编号 | 失败形态 | 为什么这是问题 | 脚本信号 |
| --- | --- | --- | --- |
| RM-1 | 申请了移除但没有移除时间 | 无时刻即无可证 | R01 |
| RM-2 | 仍有残留却记为可证消失 | 两件事不能同真 | R02 |
| RM-3 | 记了移除时间但某类仍有残留 | 这是替换未完成，不是消失 | R02b |
| RM-4 | 可证消失只由见证支撑却没有见证类型 | "有见证"是空话 | R03 |
| RM-5 | 声称已消失且证据形态登记为 none | 结论无证据 | R03b |
| RM-6 | 复核日早于移除日 | 时序不成立 | R04 |
| RM-7 | 移除后既无替换项也没写明不再需要 | 归属悬空：这段能力去哪了 | R05 |
| RM-8 | 可证消失但没有复核日期 | 结论无时效（锁文件会再解析） | R06 |
| RM-9 | 回执引用了清单外的依赖标识 | 处置记录落在集合外 | X03 |
| RM-10 | 移除动作没有可回指的见证主体 | 消失结论只能靠声明 | Z05、X07 |
| RM-11 | 移除之后又读到该依赖在产物里 | 结论被后续读数推翻 | Z10 |

判据一句话：**L8 闭合 = 四类残留逐一核实为 `none`，且至少一个见证能回指到一份具体构建产物，并且移除之后有过一次复核。**这一句里的"回指到一份具体构建产物"要求 build UUID 参与（TN3178 第 7 行：UUID 把镜像连到它的 dSYM；第 30 行：签名覆盖该 UUID）——**没有 UUID 的产物读数指不回那一次构建**（Z03）。

---

## 12. L9 组织侧可见性层

### 12.1 这一层管什么

L8 问"能不能证明"，L9 问"**谁能看见**"：在集成方之外，还有谁有可能知道某个第三方代码存在于某个产物里。这一层的价值在于它决定了归属结论能被**谁**用作证据：自证（组织内部）、合同（客户与审计方）、还是平台（Apple）。

四个主体的可见性差别很大，本文把它们分开登记：

| 主体 | 能看到什么（公开口径范围内） | 看不到什么 |
| --- | --- | --- |
| SDK 提供方 | 自家 SDK 的下载次数与集成方数量（**本文不假设任何具体后台读数**：本轮 Apple 语料没有相关句子）；它知道某个版本有缺陷 | 哪个应用、哪台设备、哪个版本还带着它 |
| 上游开源项目 | 同上更弱：完全不知道谁用了它 | 集成方存在性本身 |
| 平台（Apple） | 提交件的清单聚合报告与签名事实（第 8 章 SDK requirements 第 120、124 行）；分发前的签名校验（《Using the latest code signature format》第 8 行） | 构建期的装配选择、内部 CI 的解析结果 |
| 管理方（MDM / 企业 IT） | 装了哪个应用、应用版本、托管配置面 | **应用内嵌了哪些第三方 SDK 与版本**：Apple 公开语料没有给出可读清单的句子 |

第三行是本报告集里第一次出现的不对称：**平台看到的是"提交件 + 申报"，看不到"装配过程"。**这就是为什么第 8 章的名单能证明义务而不能证明归属——申报面与装配面是两个不同的时刻。第四行是本文第 9.3 节那条结论的组织侧版本：**管理面看不到 SDK。**

### 12.2 自证是唯一的补齐路径

既然外部主体都看不见，"某个 SDK 已被移除"这类句子要交付给外部，只有**自证材料**一条路径。本文用 `org.attestation_source` 登记自证材料出自哪里，四种形态强度不同：

| 取值 | 内容 | 适用 | 强度 |
| --- | --- | --- | --- |
| `build_log` | 一次构建的完整日志（含依赖解析段） | 能证明那一次构建 | 中（一次性、不可外推到其它构建） |
| `lockfile` | 已提交的锁文件 + 仓库历史 | 能证明解析基准的存在 | 中（受 F3 限制） |
| `artifact_scan` | 产物内镜像清单与签名身份 | 能证明那一份产物里有什么 | 高（但受 L3 形态陷阱限制） |
| `vendor_statement` | 提供方的书面陈述 | 能证明身份变更的解释（对应 6.5 节第 19 行的 "Work with the XCFramework’s provider"） | 低（无观测支撑，需与前三者合并） |

`vendor_statement` 单独不能提升任何结论。它与第 6 章那条"判据来自提供方陈述"的文档口径是一致的：Apple 文档把签名变化是否预期交给提供方判断，但**判断结果的证据地位由集成方决定**。

### 12.3 输入 / 输出 / 失败形态 / 判据

- 输入：一句对外表述（"我们不再使用 X"）。
- 输出：该表述可被哪个主体核验，以及需要附哪些自证件。
- 字段：`org.inventory_surface`、`org.mdm_visible`、`org.attestation_source`、`ver.org_visible`。
- 失败形态：

| 编号 | 失败形态 | 为什么这是问题 | 脚本信号 |
| --- | --- | --- | --- |
| OV-1 | 声称组织可见但清单面为 none | 无观测支撑 | V05 |
| OV-2 | 组织可见性记为否却填了 MDM 读数 | 两格互斥；MDM 面上没有 SDK 清单 | V04 |
| OV-3 | 把提供方陈述当独立证据 | 陈述无观测支撑 | 本文口径 |
| OV-4 | 消失结论没有对外可交付件 | 结论只能内部使用，写清这一点 | R03 |

判据一句话：**L9 的结论都是关于"这句话能给谁说"，不是关于"这段代码在哪"。**它不参与 J1—J4 的等级计算，只决定该结论在对外场景里能不能引用。

---

## 13. L10 构建可重现性与审核口径层

### 13.1 这一层管什么

L10 是本文最外一层，管两件事：**这段代码进了产物之后，同一个工程再构建一次还会不会得到同一份东西**（可重现性），以及**审核口径里第三方代码的责任是怎么写的**（审核面）。两者放在一起，是因为它们在台账里共用同一格：**"我们说的是这个产物，还是这个工程。"** 可重现性决定前一句话能不能成立，审核口径决定后一句话由谁承担。

### 13.2 可重现性的三个公开抓手与它们的边界

**抓手一：build UUID。**Tech Note 3178 第 25 行给出一条正面事实："By default the Apple linker sets the build UUID based on a hash of the built code. This promotes reproducible builds."（默认情况下 Apple 链接器按已构建代码的哈希设置 build UUID）；第 30 行给出它的签名后果："If a Mach-O image is signed, that signature covers the build UUID."（镜像被签名时，签名覆盖该 UUID）；第 41 行给出反面："If two different Mach-O images had the same build UUID, you wouldn’t be able to match up an image with the correct debug symbol (dSYM) file."

这三句合起来给本文一条很硬的判据：**UUID 是"哪一次构建的那份镜像"的唯一标识，且被签名保护。**因此脚本二要求产物元数据读数必须带 UUID（Z03），第 11 章的消失结论要求它能回指到一次带 UUID 的构建。**注意边界**：UUID 由"已构建代码的哈希"派生，所以它能标识产物，**不能**用来证明外部代码来源——这是"可重现"与"可归属"之间的一道墙，本文不让它被混淆。

**抓手二：解析是否钉住。**第 5 章的 `-disableAutomaticPackageResolution`（CI 文档第 11 行）与 `Package.resolved`（第 6、9 行）是工程侧唯一能钉住解析结果的两个手段。脚本一对"自动解析开启却记为可重现"报 B01，对"解析未钉住却记为可重现"报 B02；对偶面是 B04（解析已钉住却记为不可重现，要求说明其它不确定来源）。

**抓手三：Run Script 构建阶段。**《Running custom scripts during a build》第 8 行："To execute a custom script at build time, add a Run Script build phase to your target. This build phase runs separately from the target’s other build phases, such as the compilation and link build phases."；第 26 行的旁注要求声明脚本访问的输入输出文件集合，以便构建系统"inform the build process … ensures correctness"。这一条对本文的意义是**负面的但重要**：**任何不受依赖系统管辖的代码来源（下载、生成、拷贝）都可以经由 Run Script 进入产物**，而它的正确性依赖于人工声明的输入输出集合。台账若不登记这类阶段，可重现性结论就有一个未声明的入口（B03 针对缓存，本文把脚本阶段归为同一类"未声明来源"，在误区一章给出写法）。

### 13.3 审核口径里的第三方责任句

审核面的两句本文已在 10.5 节列出（第 118 行、第 127 行），这里补第三处位置关系：平台安全指南全文里 **"App Review" 只命中 1 次**，在该命中处（第 2388 行）的语境是"robust App Review to help prevent the installation of malicious apps"，也就是**装机前的把关**，而不是装配期的核对。指南里另有 `notariz` 命中 20 次、`Gatekeeper` 命中 20 次，全部落在 macOS 章节（本轮 `C/guide-supply-map.txt` 的行号表可查）。

这组读数给出一个必须写清的结构事实：**Apple 的平台文档在"应用内部装配了什么第三方代码"这件事上没有校验环节。**它有：装机前的审核（第 2388 行）、提交前的校验（第 122、124 行、ASC 重签句）、运行期的加载限制（第 2362 行）。它没有：**构建期对"这段代码从哪来"的核验**。所以本文的十层判定里，L1、L2、L8 三层的证据**只能由集成方产生**，这不是工程不严，而是平台口径本来就把这三层留给集成方。

### 13.4 补一句 SBOM：词汇缺席与三份非 Apple 件

本文不使用"SBOM 由谁产出"这个句式作为平台口径，理由是第 26 章 G1 那条缺席：**本轮全库检索 `SBOM`、`CycloneDX`、`SPDX`、`SLSA` 在 Apple 开发者文档树与平台安全指南内命中为零**；命中的只有四个开放标准组织自己的页面（`B/pages/cyclonedx-sbom.txt`、`spdx-specs.txt`、`slsa-provenance.txt` 等，均为**非 Apple 文档**）。因此本文对 SBOM 的全部立场是：**它是组织侧可自证的一类材料，不是 Apple 生态里有平台口径的一类事实。**凡是需要向外部主体交付"依赖全集"的场合，本文写成"由集成方按装配登记件出具"，不写"Apple 提供 SBOM"。

### 13.5 输入 / 输出 / 失败形态 / 判据

- 输入：一次可重现性声明 + 一次审核相关表述。
- 输出：该声明绑定的构建标识与钉住状态；该表述的正确主语（集成方而非平台）。
- 字段：`build.reproducible`、`build.resolution_pinned`、`build.cache_used`、`build.uuid_checked`、`manifest.aggregate_report_seen`。
- 失败形态：

| 编号 | 失败形态 | 为什么这是问题 | 脚本信号 |
| --- | --- | --- | --- |
| RB-1 | 自动解析开启却记为可重现 | 区间型解析每次可取不同件 | B01 |
| RB-2 | 解析未钉住却记为可重现 | 同上，且不依赖具体通道 | B02 |
| RB-3 | 使用构建缓存却没登记命中范围 | 结论适用面被夸大 | B03 |
| RB-4 | 已钉住却记为不可重现且无说明 | 另一侧的口径不一致 | B04 |
| RB-5 | 两条登记对同一事实给不同值 | 台账本身不自洽 | X05 |
| RB-6 | 回执序号重复 | 结论无法回指 | X06 |
| RB-7 | 同一依赖两条同类动作同日 | 两条无法区分 | Y04 |

判据一句话：**L10 不给新的归属结论，它给"结论有效期"。**一份可重现性记录的作用是把第 9 章与第 11 章的读数从"那一次构建成立"扩展到"按这套钉住条件重跑仍成立"；扩展不出去时，本文一律要求写成带构建标识的单次结论。

---

## 14. 缺陷类型学 P1—P12

本文说的"缺陷"不是可被利用的代码缺陷，而是**台账与流程里的判定缺陷**：一句归属结论因为某种记录形态而不成立。十二类由第 4—13 章的失败形态归并而来，每类给出触发条件、归属后果、所在层与脚本信号。归并原则是"同一个归属后果只留一类"，因此 P 类与层内失败编号是多对多关系。

| 类 | 名称 | 触发条件 | 归属后果 | 主要层 | 脚本信号 |
| --- | --- | --- | --- | --- | --- |
| P1 | 未钉住的解析 | requirement 为 branch/unpinned，或自动解析未关闭 | "这一版"这句话不成立；版本可观测性封顶 `range` | L1 L2 | M02、M02b、Z02、B01、B02 |
| P2 | 锁文件缺失或未提交 | 有解析器但锁文件不在仓库里 | 开发机与 CI 各持一个解析基准，公共参照消失 | L1 L2 | M01、M03、Z06 |
| P3 | 需求与解析不一致 | `resolved_version` 落在 requirement 允许范围之外 | 要么需求被改过未记，要么解析结果不属于这句话 | L1 | M04 |
| P4 | 无声明的二进制 | 手工放入 / vendored，且集成方或来源未登记 | 只剩签名身份一格可核对；装配时刻不可追 | L1 L3 | M05、M06、M07、M07b、Z09 |
| P5 | 身份变更未定因 | `identity_changed=true` 且 `change_reason` 为 unknown 或未登记 | 文档给出两种并列解释，选不出即无法定责 | L3 | G02、G02b、G04、G05b |
| P6 | 身份读数缺失 | 自签却无指纹、二进制却记"签名不适用"、过期/吊销未记处置 | 身份结论没有观测支撑 | L3 L4 | G01、G01b、G03、G05、G07 |
| P7 | 名单义务未闭合 | 在名单上却缺清单或缺签名状态登记 | 提交期义务与归属结论互相脱节 | L5 | P01、P02、P03、P04、P05 |
| P8 | 版本读数无源或过强 | 来源 unknown / 非产物侧来源却记 exact / 两条 exact 互斥 | 版本陈述不能代表任何被讨论的对象 | L6 | V02、V03、Z07、Z08、X04、Z01 |
| P9 | 归属主体缺席或错挂 | CVE 未挂到依赖标识、用 Apple 公告覆盖外部归属、记平台方却无依据 | 四级判定无法给 J1；修复出处不唯一 | L7 | C02、C03、C05、C06、C06b |
| P10 | 修复三格混同 | 把"上游修了"当成"我们带着修好的版本"或"已采纳" | 风险提前关闭；第 1.4 节示例的第四处 | L7 L6 | C04、C04b |
| P11 | 消失结论不可证或被推翻 | 有残留却记可证消失、无见证类型、移除后又读到 binary_present | "不再使用"这句话不能对外交付 | L8 | R01—R07、R02b、Z04、Z05、Z10 |
| P12 | 可见性越权声称 | 声称设备侧或组织侧能看到 SDK 与版本 | 把自证结论写成第三方已知的结论 | L6 L9 | V01、V04、V05 |

三类值得多看一眼：

- **P1 与 P2 的区分**。P2 是"没有基准"，P1 是"有基准但基准会动"。P2 容易被发现（文件不在），P1 容易被误判为已解决（文件在，于是以为钉住了）。CI 文档把两件事并列说（第 6 行与第 11 行）正是因为它们经常被合并。
- **P5 与 P6 的区分**。P6 是"从来没看过身份"，P5 是"看过了、身份变了、但说不出为什么"。**P5 比 P6 更难交付**：P6 补一次读数即可闭合，P5 需要一次跨主体沟通（文档第 19 行的 "Work with the XCFramework’s provider"）并把结论记进台账，还要求处置日期。
- **P10 是本文与第 09 篇的接缝**。第 09 篇管补丁走到哪（公告 → 目录 → 授权 → 分发 → 安装 → 回执 → 回滚），本文管"这个缺陷记在谁头上、集成方能否知道自己带着它"。P10 落在接缝的本文一侧：它的失败不是"补丁没走到"，而是**集成方在没有任何版本读数的情况下写了"风险关闭"**。

## 15. 归属矩阵：层 × 责任方 × 形态 × 证据

这张表是本文的核心工具。行是十层，列是"这一层的结论能由谁作出、需要什么形态的证据、缺什么就退到哪一级"。

| 层 | 结论 | 可归属主体 | 证据形态 | 证据持有者 | 换算失败点 | 缺失时的等级 |
| --- | --- | --- | --- | --- | --- | --- |
| L1 声明与锁定 | 这段代码被哪句话请进来、钉到什么程度 | 应用团队 | 已提交的声明文件与锁文件 | 应用团队 | F2（两套"锁定"不同物） | J4 |
| L2 解析与装配 | 构建用的是不是那句话允许的那一份 | 应用团队 + 构建系统 | 构建配置（标志位）、解析日志、锁文件 | 应用团队 | F3（锁文件 ≠ 按它构建） | J4 → J3 |
| L3 形态与身份 | 这段代码是谁签的、以什么形态存在 | 提供方（签名主体）/ 应用团队（自签） | File inspector 读数、SHA-256 指纹、build UUID | 应用团队（工程期） | F1（两种校验不同名） | J3 |
| L4 平台口径 | 哪些是平台拦的、哪些是应用侧可核验的 | 平台 | 指南第 2350—2362 行族、签名格式文档 | 公开文档 | 第 7 章 SV-1/SV-2 | 不降等，只纠正主语 |
| L5 名单与申报 | 平台是否点名要求清单与签名 | 平台（义务方为应用团队） | 86 条名单 + 第 124 行 repackage 句 | 公开文档 | **F4**（名单给义务不给归属） | 不升等 |
| L6 版本可观测 | 这一台上跑的是哪一版、谁知道 | 应用团队（产物侧）/ 无人（设备侧） | 四源读数 + 置信度 | 应用团队 | **F6**（四源不可互换） | J2 |
| L7 公告与归属 | 这个缺陷记在谁头上 | 四方（应用/提供方/上游/平台） | 四个公告面 + 本文登记规则 | 应用团队 | **F5**（义务句 ≠ 归属规则） | J2 |
| L8 移除与消失 | 能不能证明不在了 | 应用团队 | 四类残留 + 四种见证 + 复核时刻 | 应用团队 | **F7**（"已移除" ≠ "可证不在"） | J1（不带消失结论） |
| L9 组织侧可见 | 这句话能给谁说 | 管理方 / 审计方 / 客户 | 自证材料四种形态 | 应用团队 | 第 12.1 节第四行（管理面看不到 SDK） | 不影响等级，影响交付对象 |
| L10 可重现与审核 | 结论有效期多长 | 应用团队 / 审核方 | UUID、钉住状态、缓存范围、审核责任句 | 应用团队 | UUID 标识产物不标识来源（13.2） | 不降等，限定适用面 |

### 15.1 按主体重读一遍

| 主体 | 它能独立闭合哪些层 | 它在哪些层上必须依赖别人 | 它的结论能被谁核验 |
| --- | --- | --- | --- |
| 应用开发者（集成方） | L1、L2、L3、L6、L8、L10 | L5（名单由平台给）、L7（缺陷由别人公告） | 内部评审、自证材料 |
| SDK 提供方 | L3（它是签名主体）、L7 的修复版本一侧 | L1、L2、L6、L8（集成方的产物它看不见） | 提供方的公告与陈述；无观测支撑 |
| 上游开源项目 | L7 的缺陷定义一侧 | 其余全部：它不知道谁用了它 | 上游公告；提供方是否采纳不可见 |
| 平台（Apple） | L4、L5 | 全部装配事实 | 公开文档；但**不含构建期核验**（13.3） |

这张表解释了为什么本文的四级判定把 J1 定为"可进入归责表述"而不是"安全"：**四个主体里没有任何一个能同时闭合十层**。集成方能闭合六层，但其中三层（L5、L7 的一半、L4）的输入来自别人；提供方能闭合两层，而这两层恰好是集成方最需要的身份与修复出处。

### 15.2 形态如何改变证据强度

同一个依赖在四种装配形态下的可核对性差异极大，这是本文与"依赖审计"通识最大的分歧点：

| 形态 | 身份证据 | 版本证据 | 消失证据 | 综合可判定性 |
| --- | --- | --- | --- | --- |
| 源码 SPM 包 | 无独立签名（等于你的签名） | 锁文件强 | diff + 构建日志可用 | 高 |
| URL 二进制目标 | checksum + 签名 | 锁文件 + 产物元数据 | 强 | 最高 |
| 本地路径 XCFramework | **无 checksum**（文档明确不生成） | 仅产物元数据 | 需人工清点 | 中，且完全依赖签名登记 |
| 静态框架 / 可合并动态库 | 构建期签名 | 产物元数据 | **"产物里没这个文件"不可用** | 中低（形态陷阱） |
| 手工 vendored 框架 | 仅签名或指纹 | 仅产物元数据 | 仅扫描 | 低 |

第三行与第四行是本文最常被低估的两处：本地路径形态上"内容级校验"这件事在文档里就没有（《Distributing binary frameworks as Swift packages》第 16 行），而可合并形态上"文件级消失"这件事也不成立（《Configuring your project to use mergeable libraries》第 8 行）。**两者都不是记录不当，而是形态本身决定的证据上限。**

## 16. 公开读数：这条链路上能数出来的十八件事

"读数"指本文本轮实际从公开件里数出来、且读者可以自行复核的量。凡不能数的，本文写成口径而不写成数字。

| 编号 | 读数 | 本轮值 | 出处与复核方法 |
| --- | --- | --- | --- |
| R1 | Xcode 给出的 package requirement 种类 | 3（Version / Branch / Commit） | 《Adding package dependencies to your app》第 18—21 行 |
| R2 | 文档明确"不推荐"的种类 | 1（Commit） | 同页第 21 行 |
| R3 | CocoaPods `spec.source` 支持的仓库类型 | 4（`:git` `:svn` `:hg` `:http`） | Podspec Syntax Reference 第 212—215 行 |
| R4 | 其中能带内容哈希的形态 | 1（`:http` + `:sha256`/`:sha1`） | 同页第 214—215 行 |
| R5 | 强制清单与签名的 SDK 名单条数 | **86**（存档件第 125—210 行，无重名） | `C/sdk-required-list.tsv` |
| R6 | 名单中给出提供方身份 / 版本 / 签名主体的条数 | **0 / 0 / 0** | 同页正文逐条读；名单是平表 |
| R7 | 名单里的重打包条款 | 1 句（"Any version … as well as any SDKs that repackage those"） | SDK requirements 第 124 行 |
| R8 | 平台安全指南里 "library validation" 命中 | **0** | `C/guide-supply-map.txt`（对 4,885 行件的大小写不敏感检索） |
| R9 | 同一文档里 "team identifier" / "Team ID" 命中 | 2（第 2360、2362 行） | 同上 |
| R10 | 同一文档里 "mandatory code signing" 命中 | 3（第 2351—2353 行） | 同上 |
| R11 | 同一文档里 "App Review" 命中 | 1（第 2388 行） | 同上 |
| R12 | 签名变更的并列解释条数 | 2（合法 2 例 + 非法 1 例，均在同一节） | 《Verifying the origin…》第 13—16 行 |
| R13 | 构建错误文本的形态 | 1 句，含"may have been"（可能性而非判据） | 同页第 21 行 |
| R14 | 三份并行版本线公告的 CVE 行数 | 95 / 134 / 163，合计 **392** | `C/advisory-supply-readings.txt` |
| R15 | 其中带开源上游语句的行数 | **1**（`CVE-2019-5598`） | 同上 |
| R16 | 公告里声明上游归属的行数 | **0** | 同上（每条公告行的 vendor 均为 Apple） |
| R17 | 去重后的组件标题数 / 本文判读为外树的组件数 | **101 / 22**（后者为读者判断，件内已标注） | `C/advisory-upstream-titles.txt` |
| R18 | CISA KEV：条目数 / `vendorProject` 去重数 / Apple 行数 | **1,766 / 291 / 95**（`catalogVersion=2026.10.30`） | `C/kev-attribution.tsv` 首行与计数表 |

R8—R11 这四条是"平台口径的沉默面"的量化：平台文档反复讲代码签名（R9、R10），几乎不讲库校验这个名字（R8），完全不讲构建期装配核验（R11 的语境是装机前）。**R8 与 R11 不是"资料没找全"，是本轮件里就是这么分布的**，本文按 2.5 节的约定把它写成读数而不是写成推测。

R14—R17 四条构成第 10 章的主证据：**公告语言里第三方代码几乎不是可归属对象**。R17 的第二个数（22）是本文里唯一一处明示为"读者判断"的读数，落盘件自身带着这句说明，正文引用时同样带着它。

另有两条口径级读数本文不编进 R 序列，因为它们不是"数出来的"：**Apple 公开语料中关于 app 内第三方代码 CVE 归属的句子数为 0**（G5），**Apple 公开语料中出现 SBOM / CycloneDX / SPDX / SLSA 词汇的 Apple 文档数为 0**（G1）。缺席句子的计数在方法上是脆弱的（检索式不同结果不同），本文因此把它们写成第 26 章的边界而不是第 16 章的读数。

---

## 17. 可见性边界：这一层读者能拿到什么

### 17.1 三类可拿到的东西

| 类别 | 具体件 | 取得方式（全部只读） | 有效期 |
| --- | --- | --- | --- |
| 工程内文件 | `Package.swift`、`Package.resolved`、`Podfile`、`Podfile.lock`、`.gitmodules`、XCFramework bundle 本体 | 仓库读取；`git log` 取历史 | 随提交变 |
| 产物内读数 | framework 的版本串、Mach-O 的 build UUID、代码签名里的 Team ID 或证书指纹、`Referenced Binaries` 结构 | Xcode File inspector 的显示读数；归档件目录清单 | 那一份产物 |
| 外部公开件 | 平台安全指南、Xcode 文档、SDK requirements 页与名单、App Review Guidelines、CSAF JSON、KEV JSON | 公开 URL 取回并存档 | 抓取日版本 |

三类之外，本文不提供任何取得方式。第三类的行号与本文一致，是因为本文所有引用都落在 `.srcx12/` 存档件上，读者重取时若行号变化应以自己那一版为准（2.5 节）。

### 17.2 五条明确拿不到

1. **设备侧的"某 app 内嵌了哪些第三方 SDK 及其版本"清单**。公开语料没有给出对应读数面（9.3）。本文不推断它是否存在，只写"不可核对"。
2. **提供方后台的集成方列表**。本文不假设任何具体读数（12.1 第一行），因为提供方说不说这句话与集成方的归属判定无关。
3. **上游项目"谁用了它"的可见性**。不存在。这直接决定第 10 章的规则 2 为什么要写成"让修复出处唯一"而不是"找到所有使用方"。
4. **App Store Connect 校验不通过时开发者拿到的读数**（缺口 C / G3）。文档只说 Xcode 会校验、ASC 会先验签再重签，没给失败读数形态。
5. **平台对构建期装配选择的任何核验结果**（13.3）。这不是"没开放"，是公开口径里本来没有这一环。

五条的共同点：它们全都是**别人手里的事实**。第 1—4 条在别人系统的数据库里，第 5 条在平台的流程里。本文对全部五条的处理方式相同：**把结论的主语换成集成方自己**（"我们能证明什么"），而不是"谁能看到什么"。

### 17.3 同一个事实，四种身份看到的范围

| 身份 | 能看到 | 看不到 | 出具结论的性质 |
| --- | --- | --- | --- |
| 集成方工程负责人 | 工程内文件全部、CI 配置 | 线上设备实际带的版本 | 可出 J1—J4 全部 |
| 集成方安全/合规审计 | 上述 + 产物清单与签名读数 | 未归档的历史构建 | 只能对已归档产物出结论 |
| 客户 / 第三方审计 | **只有集成方给的材料** | 全部一手证据 | 只能复核，不能独立判定 |
| MDM / 企业 IT | 装了哪个 app、app 版本、托管配置 | SDK 与其版本（12.1 第四行） | 无 SDK 级结论能力 |

第三行是本文对"能不能向客户证明"的唯一诚实回答：**客户看到的永远是你的自证件**。因此第 12 章的四种自证形态在对外场景里地位高于任何平台口径——它是唯一跨主体可传递的证据形式。

## 18. 四个读数面：工程侧、构建侧、设备侧、组织侧

### 18.1 总表

| 读数面 | 能读到 | 载体 | 时刻 | 与下一面之间的断点 | 台账字段 |
| --- | --- | --- | --- | --- | --- |
| 工程侧 | 需求语句、锁文件、名单义务、形态标记 | 仓库、`Referenced Binaries` 目录结构（第 12 行） | 添加依赖时、提交时 | **→ 构建侧：自动解析开关（第 11 行）** | `dep.*`、`manifest.*` |
| 构建侧 | 解析日志、产物内镜像清单、版本串、build UUID、签名身份 | 构建日志、归档产物、File inspector | 那一次构建 | **→ 设备侧：分发通道与 Apple 重签（签名格式文档第 8 行）** | `sig.*`、`build.*`、`ver.shipped_version_source` |
| 设备侧 | 应用版本、崩溃报告里的镜像与 UUID、诊断数据 | 设备与崩溃聚合系统 | 运行时 | **→ 组织侧：管理面只到应用粒度** | `ver.device_visible` |
| 组织侧 | 装了哪些应用、应用版本、托管配置 | MDM 报表（其 SDK 粒度缺失为公开口径事实） | 采集周期 | 无（这是最后一面） | `org.*`、`ver.org_visible` |

### 18.2 四处跨面换算失败

- **工程 → 构建**：锁文件在册不等于按它构建（F3）。这一处断点是本文唯一**可以用一个命令标志关闭**的断点（CI 文档第 11 行），因此它在指标 O3 里单独计。
- **构建 → 设备**：产物读数不等于设备实际带的版本（分发、更新、多机型）。本文把这条推给第 09 篇的更新链，不在本篇重述；本篇只要求版本陈述绑定来源（F6）。
- **设备 → 组织**：崩溃报告里能看到某个镜像存在，MDM 报表里看不到 SDK。这一处的后果是**同一句"我们带着 X"在两个面上的可核验程度不同**，对外表述必须指明面（12.3）。
- **组织 → 工程**：管理面完全接不上装配面（17.2 第五条）。这是本报告集里唯一一个**双向都断**的接缝。

### 18.3 每面最强的单点读数

如果只能各取一个读数，本文给的优先级是：工程侧取**已提交的 `Package.resolved`**（配合 `auto_resolution` 状态），构建侧取**产物内镜像的 build UUID + 签名身份**（TN3178 第 7、30 行；签名覆盖 UUID），设备侧取**崩溃报告里该镜像的 UUID**（无 UUID 时符号化不成立，第 33 行），组织侧取**应用版本 + 自证材料编号**（因为 SDK 粒度不存在）。

这四个读数之所以强，是因为它们**互相之间能用 UUID 对齐**，而 UUID 是本文里唯一跨"构建—设备"两面的连接符。这也解释了为什么脚本二把 `uuid_recorded` 设成必填之一（Z03）。

## 19. 四级判定模型

### 19.1 四级的定义与实现条件

判定输入是五个门（脚本一实现，变量名一并给出以便读者核对代码）：

| 门 | 变量 | 成立条件（台账字段层面） | 对应层 |
| --- | --- | --- | --- |
| 装配可登记 | `have` | `dep.kind`、`requirement_kind`、`binary_form`、锁文件状态四格都非空 | L1 L2 |
| 来源可回溯 | `srcok` | `origin_url` 与 `origin_trust` 非空，且 `provenance_recorded=true` | L1 L3 |
| 身份可核对 | `sigok` | `sig.state` 非空、`change_reason` 非空，且（`not_applicable` 或实际/预期团队标识至少有一个） | L3 L4 |
| 版本可观测 | `verok` | 版本来源、置信度、设备可见性三格齐 | L6 |
| 消失可证明 | `remov` | `provable_absence` 非空；为 `yes`/`witness_based` 时要求残留格、移除时间与复核日齐，`witness_based` 还要求见证类型 | L8 |

等级按"最弱一环"给：

- **J4｜只知道装了这个依赖。** `have` 不成立，或阻断信号数 ≥ 6。含义：这条记录不能作为任何归属结论的输入。
- **J3｜能登记，说不出是谁的。** `have` 成立但 `srcok` 或 `sigok` 不成立。这是本文里**数量上最常见的可交付等级**，也是第 3.5 节 4:3 分布的直接结果。
- **J2｜能定归属，说不出这一台上是哪一版。** 前三门成立但 `verok` 不成立。含义：任何"我们已经升级到 X"的句子在这一格上不可核对（1.4 示例的第三、四处落在这里）。
- **J1｜能定责，但消失结论未闭合。** 前四门成立而 `remov` 不成立。脚本一此时输出的是"能定责『该谁处置』，不能定责『是否已消失』"。
- **J1（第二档）｜四项齐备且无阻断信号。** 五门全过，输出"可进入归责表述"。

**两档 J1 是本文与第 09—11 篇判定模型的差别。**本篇不把它们编成 J0/J1，理由是消失结论的客体（代码）与归属结论的客体（缺陷）在文档口径上不同源：前者是产物侧事实，后者是公告侧事实加本文的登记规则。合并成一级会让读者误以为"J1 = 全闭合"，而实际上 J1 第一档的对外表述范围是被明确限制的。

### 19.2 等级不能上跳的三种情形

1. **`sig.state` 为 `expired` 或 `revoked` 且有处置日期。**即使其它门全过，本文也要求把它写成 J1 第一档并附处置记录，因为第 30 行的口径是"与提供方取得由有效身份签名的新版本"——**在拿到新版本之前，身份事实是不完整的**。
2. **形态为本地路径 XCFramework 且 `sig.fingerprint_recorded=false`。**该通道没有 checksum（4.2 表第三行、Distributing 第 16 行），身份只剩 inspector 一次读数；若未登记，`sigok` 实质不成立。
3. **`change_reason` 填了 `ownership_transfer` 但未登记新团队标识。**这是 G02b 的场景：文档承认它合法，但合法变更仍需要把变更后的身份写进台账，否则第 9 章的读数会同时挂两个主体。

### 19.3 用第 1.4 节示例走一遍

那条 PaymentCore 记录：`requirement_kind=branch`、`lock_present=true`、`lock_committed=true`、`auto_resolution=enabled`、产物读数 `3.4.2`、台账陈述"已升级至 3.4.3"、身份变更未记原因。

- `have`：四格都非空 → 成立。
- `srcok`：提供方登记了，但 `change_reason` 未登记导致 `sigok` 不成立（J3 门槛）。
- `verok`：版本来源是 `binary_metadata`，但台账里那句"已升级"没有来源格 → 三格不齐。
- 阻断信号：`Z02`（分支 + 自动解析）、`X04`（两条 exact 不同值）、`G02b`/`G02`（变更未定因）、`V03`（置信度未登记）、`C04b`（记采纳无读数）。

**判定：J3，且阻断信号数足以让它在真实台账里跌到 J4。**这个例子说明一件事：四级模型不是给"做得好坏"打分，而是给"这句话能被谁引用"分级——J3 的 PaymentCore 仍然可以正常商用，但它不能出现在"该风险已关闭"的表述里。

### 19.4 与 P 类的映射

| 判定 | 通常由哪些 P 类挡住 |
| --- | --- |
| J4 | P1、P2、P3、P4（登记本身不齐） |
| J3 | P4、P5、P6、P7 |
| J2 | P8、P10、P12 |
| J1 第一档 | P9、P11 |
| J1 第二档 | 无阻断，或仅非阻断提示 |

### 19.5 脚本二的三件闭合等级

脚本二用另一套等级（Q1—Q4），因为它判的不是"这句话能被谁引用"，而是**三份记录之间能不能闭合**：

- **Q4**：三件不齐或本依赖行形态不可解析 → 没有可比对象。
- **Q3**：三件齐但差集非空 → 这份依赖的身份在三件之间对不上（X 族）。
- **Q2**：集合闭合但时序不成立（Y 族），或口径矛盾（Z 族）→ 按最弱一环给结论。
- **Q1**：三件闭合、时序成立、口径一致 → 可对该依赖出具版本与消失结论。

两套等级的关系：**Q1 是 J 判定的输入条件之一，Q3/Q4 直接压到 J4。**脚本一的门看"一格填没填"，脚本二的门看"三件说没说同一件事"——前者防漏记，后者防互斥。这是本文给两个脚本的分工，也是第 23 章把它们的信号码分开列覆盖表的原因。

## 20. 运营指标 O1—O10

指标全部可**用两个脚本的输出直接算出**，不引入新数据源。每个指标给出定义、口径与警戒读法；本文不给阈值数字——阈值随组织规模与依赖数量变化，本文只说哪种读法值得停下来。

| 编号 | 指标 | 定义 | 分母口径 | 警戒读法 |
| --- | --- | --- | --- | --- |
| O1 | 归属登记覆盖率 | 有 `cve.attribution`（非 `unknown`/`unassigned`）的依赖数 ÷ 在册依赖数 | 装配登记件行数 | 低覆盖不代表风险高，代表**下次出 CVE 时无处可挂**（第 10 章规则 7） |
| O2 | 身份可核对率 | `sigok` 成立的依赖 ÷ 二进制形态依赖 | `dep.binary_form` 为二进制的行 | 与 P4/P6 直接对应；手工 vendored 一列通常拉低全局 |
| O3 | 解析钉住率 | `auto_resolution=disabled` 且 `lock_committed=true` ÷ 使用解析器的依赖 | `dep.kind ∈ {spm, cocoapods, carthage}` | 这是唯一能**用一个标志关闭**的断点（18.2），所以单独计 |
| O4 | exact 版本读数占比 | `version_confidence=exact` 且来源为产物侧 ÷ 有版本读数的依赖 | 产物读数件 | 若 exact 占比高但来源多为 `lockfile`，说明读数被 F6 误用（Z01、Z07） |
| O5 | 名单义务闭合率 | 名单内依赖中 `privacy_manifest_present=true` 且签名状态非空 ÷ 名单内依赖 | `manifest.on_required_list=true` 的行 | 与第 08 篇指标区分：那边算申报，这边算"义务与身份同时具备" |
| O6 | 消失可证率 | `provable_absence ∈ {yes, witness_based}` ÷ 已申请移除的依赖 | `remove.requested=true` 的行 | 分母必须排除"从没申请过移除"的依赖，否则指标虚高 |
| O7 | 复核及时率 | `recheck_date ≥ removed_at` 且在同一产物周期内 ÷ 有移除时间的依赖 | 同上 | 只用于发现"移除后从未回头看"（R06、Z06） |
| O8 | 三件闭合率 | Q1 依赖数 ÷ 装配登记件依赖数 | 脚本二汇总 | 本指标是 O1—O7 的**合取**，异常时先看 X 族而非补单格 |
| O9 | 阻断信号密度 | 阻断信号条数 ÷ 依赖数 | 脚本一汇总行 | 用于跨周期比较，不用于单周期评价；第 23 章的坏样本读数是 215/64，只作方法演示 |
| O10 | 自证可用率 | 有可对外交付自证件（四种形态之一）的依赖 ÷ 需要对外表述的依赖 | 由 `org.attestation_source` 是否非空决定 | 唯一在**外部主体**一侧有意义的指标（17.3 第三行） |

三条共同纪律：

1. **分母必须用"有该格的依赖"，不是全部依赖。**O6、O10 尤其容易被写成全局分母而虚高。
2. **指标不许换算。**O3 高不代表 O4 高（钉住解析不等于产物侧版本读数），O5 高不代表 O2 高（清单齐不等于身份清）。这正是第 3 章 F1—F7 在运营层的复现。
3. **指标不用于给单个依赖"打分"。**它们是台账质量的度量；单个依赖的可交付性只看它的 J 级与 Q 级。

---

## 21. 只读核验脚本一：第三方依赖装配与来源台账审查器

### 21.1 用途与边界

`sdk-supply-ledger-review.sh` 审查一份或多份**第三方依赖装配与来源台账**：逐字段校验、逐条给信号码，并对每个依赖输出一条 J1—J4 判定。它的定位与本系列第 09—11 篇的脚本一致，但排除项按本文客体重写过：

- **纯文本、离线、只读**。不联网、不调用任何设备侧或 Apple 命令行工具（不用 `xcodebuild`、`swift package`、`pod`、`codesign`、`plutil`、`security`、`profiles`，不调 Xcode、不调 `curl`），不修改输入文件。
- **唯一写出目标**是 `mktemp -d` 创建的临时目录，退出时随 `trap` 删除。
- **不含任何绕过签名校验、伪造或替换 Team ID、降级或重新打包第三方框架、规避构建报错的做法**；不提供依赖投毒、镜像替换或锁文件篡改的操作方法；不针对任何具体应用、具体 SDK 或具体提供方给出攻击动作。
- 台账里出现 `key.*` 命名空间、或出现形似私钥材料 / `.p12` / `.mobileprovision` 内容的取值，**直接触发 K01 并要求删除该字段**。这不是顺带检查：按第 2.4 节的立场，把签名私钥或描述文件内容抄进依赖台账，等于把"这段代码是谁签的"从一条可公开核对的身份变成一份需要保护的机密。脚本不接受"改存口令前几位"或"存哈希"这类折中，只接受 Team ID 形态的身份串与证书指纹。

它做的是**归属判定与口径核对**：格子有没有写、写的话与公开口径是否冲突、同一依赖内部是否自相矛盾、移除与复核的先后能不能成立。它**不校验"写得对不对"**——那需要读产物、读签名、读锁文件，而本脚本的设计前提就是不访问这些。这一句要和第 17 章连起来读：脚本能判的是"这条记录能否支撑一个归属结论"，不是"这段代码实际来自哪里"。

### 21.2 输入格式

```
用法: sdk-supply-ledger-review.sh [-q] 台账文件 [...]
  -q, -h  -q 只输出汇总；-h/--help 显示本帮助
台账行格式: <依赖标识>,<字段名>,<值>    # 开头与空行忽略，行尾 CR 忽略
退出码：出现阻断信号时为 1，否则为 0。信号明细走 stderr，汇总走 stdout。
```

（以上是 `-h` 输出的摘录；完整帮助列出了九个命名空间的全部字段名。`-q` 与 `-h` 只在**第一个参数**位置被识别，把它写在文件名之后会被当成台账文件。）

一行一条记录，**恰好三列**，逗号分隔。这里与第 11 篇的脚本有一个实际差别：本脚本对列数是硬判定，`NF != 3` 即 S01 并跳过该行，**值里不能再含逗号**。所以带查询串的下载地址、`~> 1.2, < 2.0` 这类版本区间要先改写成不含逗号的形式（用分号或空格），否则会被解析层拒收——拒收本身可见，比静默切错列好。

九个命名空间对应本文十个层章节，缺一格就在对应层上少一项判据：

| 命名空间 | 回答的问题 | 对应层 | 缺格时的直接后果 |
| --- | --- | --- | --- |
| `dep.*` | 走哪条装配通道、要求钉到哪一刻、什么形态、从哪取回、谁在哪天放进工程 | L1、L2 | 判定起点缺失，多数依赖直接落 J4 |
| `sig.*` | 这段代码的签名身份是什么、变过没有、变更有没有原因、在哪个面上核过 | L3、L4 | 归属主语无法确定（J3 的常见成因） |
| `manifest.*` | 是否带隐私清单、是否在强制名单上、名单名怎么对上的 | L5 | 无法区分"义务"与"归属"两件事 |
| `ver.*` | 这一台/这一版是从哪个读数面知道的、置信度多少 | L6 | 版本结论只能到范围，不能到点（J2） |
| `cve.*` | 缺陷号、三侧公告、归属主体、修复版本是否已上线 | L7 | 归责表述没有对象 |
| `remove.*` | 申请过没有、哪天移除、有无残留、靠什么见证、哪天复核 | L8 | 消失结论不可证（J1 分档的唯一依据） |
| `build.*` | 是否可重现、是否钉住解析、是否核过 build UUID | L10 | 台账结论无法回指到某一次构建 |
| `org.*` | 管理面看不看得到、清单面是什么、自证件出自谁 | L9 | 对外表述只能引内部台账 |
| `key.*` | **拒收用命名空间**：本空间下任何字段都触发 K01 | 2.4 | 见上文立场 |

枚举域取值表就是脚本 `DOM[]` 里那十五条，与第 3.1 节的台账字段表同源。取值不在允许集合内即 S04，脚本**不做近义替换**（`signed_ok` 不会被认成 `signed_expected`）：口径混用的成本必须由台账作者承担，而不是由脚本猜。

解析层与凭据层信号：

| 信号 | 触发条件 | 阻断 |
| --- | --- | --- |
| S01 | 行不是三列 | 是 |
| S02 | 依赖标识为空，或标识内含空白字符 | 是 |
| S03 | 字段名不带命名空间，或命名空间未知 | 是 |
| S04 | 枚举字段取值不在允许集合内 | 是 |
| S05 | 布尔字段取值不是 `true/yes/1/false/no/0/unknown` | 是 |
| S06 | 日期字段不是 ISO 8601 形态；或提交号非十六进制；或 CVE 号形态不符；或 `origin_url` 不是可核对地址形态 | 是 |
| S07 | 同一依赖同一字段出现两个不同值 | 是 |
| S08 | 同一依赖同一字段重复登记且值相同 | 否 |
| K01 | 出现 `key.*` 字段；或任意字段的值形似私钥/描述文件内容 | 是 |
| G03 | `sig.team_id` 不是 10 位字母数字（平台安全指南第 2362 行的形态判据） | 是 |

### 21.3 输出形态

逐条信号行是 `信号码<TAB>依赖标识<TAB>说明`，说明里带**文档出处行号**（凡触发口径类信号处）；然后是逐依赖的判定行，最后是汇总段：

```
依赖数=N 信号行数=M
不同信号码=K 阻断信号条数=B
  <码>=<计数>（按首次出现顺序）
```

**阻断信号在这支脚本里是一张显式名单**（脚本第 97—99 行的 `HB` 数组，共 36 个码，含 J4 与 J3 两个判定本身），不是"除结构性提示与判定之外的全部"。名单化的理由是：能够**否掉一条归属表述**的缺陷种类应当可审计——第 19 章讲的五个门是判据，这张名单是判据的反面记录；改名单必须走"先改文档再改脚本"的顺序（第 26.1 节原则 2），否则判定强度会随代码漂移而不留痕迹。

名单里有三个码值得单独说明，因为它们容易被误读成"错误太严重所以阻断"：

- `G01`（签名状态 `invalid` / `removed`）阻断，但它的说明文本只重复文档口径——文档给出的处置是"与提供方确认、从可信来源重新获取"，脚本到此为止，**不给任何让构建通过的做法**。
- `P01`（在强制名单上且缺隐私清单）阻断，依据是名单口径而非归属口径：这一格成立时，问题的第一层是"这个依赖不应被提交"。
- `C03`（CVE 在在野名单上但归属未定）阻断，是本文唯一一处**因为归属为空而阻断**的信号：没有归属主体，修复顺序无从排（第 10.5 节末句）。

### 21.4 实跑结果

两个样本都在本轮环境实际执行过，输出原样摘录。

**好样本**（`fx/good.tsv`，2 个依赖、70 条记录 + 2 行注释）：一个源码型 Pod（签名记 `not_applicable`、明确写了"不申请移除且不可证消失"），一个二进制 XCFramework（Team ID 相符、在强制名单上且带清单，但 `remove.*` 一格未填）。

```
J1	Alamofire	来源、身份、版本、消失四项齐备且无阻断信号：可进入归责表述
J1	PaymentCore	来源、身份、版本三项齐备，但没有可核验的消失结论：能定责「该谁处置」，不能定责「是否已消失」

依赖数=2 信号行数=2
不同信号码=1 阻断信号条数=0
  J1=2
```

退出码 0。这个样本的作用是让 **J1 的两种形态在同一次运行里同时出现**：`Alamofire` 走到"四项齐备"不是因为它的消失可证，而是因为它把"不可证"当作结论**明确登记**（`remove.provable_absence=no`）——第 19.2 节说的"留空与 `unknown` 与 `no` 是三件事"在这条输出上落地；`PaymentCore` 各项都齐全、只因为没有 `remove.*` 记录而停在第二档。同一次运行里没有任何非判定信号，说明全闭合台账的噪声可以真的是零。

**坏样本**（`fx/bad.tsv`，139 行、128 条记录、64 个依赖标识，含 1 行只有两列、1 行标识为空）：

```
依赖数=64 信号行数=376
不同信号码=63 阻断信号条数=215
```

退出码 1。判定分布是 **J4=61、J3=2、J2=1，没有一条到达 J1**。这组数字里有两个要点：

1. **计数最大的五个码全是"缺格"类**（V03=63、P03=62、M09=57、M08=55、J4=61）。这不是脚本啰嗦，而是这个样本刻意让多数依赖只登记一到两格——一个只写了 `dep.kind` 的依赖，在四个命名空间上各缺一次格，四个信号乘上 60 多个依赖就是两百多条。**分母效应要在读数时扣掉**：这也是第 20 章 O1 用"有该格的依赖"作分母的原因。
2. **J3=2 而不是 0**。这个样本里只有两条依赖通过了 `have` 门又卡在来源或签名门上——恰好对应第 3.5 节说的"F1—F7 的换算失败让 J3 成为常态"的另一面：一个真实台账里 J3 多，是好事还是坏事取决于它是**登记缺格**造成还是**来源真的说不清**造成，两者在信号上分得开（缺格看 M08/M09/P03/V03，说不清看 M05/M06/M07/G02/G04）。

各信号族在坏样本里的分布（用于第 23.2 节的逐码覆盖定位）：

| 族 | 本轮出现的码 | 条数 | 其中阻断条数 |
| --- | --- | --- | --- |
| 解析与凭据 S/K | S01 S02 S03 S04 S05 S06 S07 S08 K01 | 14 | 13 |
| 装配与锁定 M | M01 M02 M02b M03 M04 M05 M06 M07 M07b M08 M09 | 126 | 116 |
| 签名与身份 G | G01 G01b G02 G02b G03 G04 G05 G05b G06 G07 | 10 | 8 |
| 清单与名单 P | P01 P02 P03 P04 P05 | 66 | 1 |
| 版本可观测 V | V01 V02 V03 V04 V05 | 67 | 2 |
| 缺陷归属 C | C02 C03 C04 C04b C05 C06 C06b | 10 | 2 |
| 移除与消失 R | R01 R02 R02b R03 R03b R04 R05 R06 R07 | 13 | 9 |
| 构建可重现 B | B01 B02 B03 B04 | 6 | 1 |
| 判定 J | J2 J3 J4 | 64 | 63 |

摘录六条真实输出（逐字来自 stderr，可按第 23 章方法与脚本对照）：

```
K01	KeyField	台账记录了 key.private_key_material：应删除该字段，只登记身份指纹与归属结论
G01	SigInvalid	签名状态 invalid：文档口径是移入废纸篓并从可信来源重装，本脚本不给任何绕过校验的做法
G07	SigNAonBinary	二进制形态却把签名记为不适用：平台口径是全部可执行代码需签名，这一项要么改形态要么补签名
P01	ListedNoManifest	在强制名单上且缺隐私清单：按名单口径这一项不应被提交
C03	KevUnassigned	CVE-2026-1002 在在野名单上但归属未定：先定归属再谈修复顺序
R02	RemBinaryResid	仍有 binary 侧残留却记为可证消失：两件事不能同真
```

`R02` 与 `R02b` 是一对：前者是"有残留却记可证消失"（结论与事实矛盾，阻断），后者是"有移除时间但仍有残留"（替换未完成，非阻断）——同一条 `remove.residual_refs=binary` 配上不同结论走不同码，这是第 11 章"移除有两种失败形状"的直接实现。

### 21.5 使用限制

1. **枚举词表是本轮口径**，不是 Apple 或 CocoaPods 的接口契约。第 3 章的 F1—F7 说的是两套词表之间没有换算式，脚本**不发明换算**：它只报"这一格与那一格不能同时为真"，不报"这一格应该填什么"。
2. **缺格与错格分开报**。缺格走 M08/M09/P03/V03/R07/C05 这一类"未登记"分支，错格走 S04/S05/S06 与各族的冲突分支。合并两类会让改进方向失真——缺格要补流程，错格要改表单。
3. **`unknown` 是合法值，留空不是**。三态字段接受 `unknown`（含义是"承认不可判定"），留空触发缺格。这个区分在第 19 章的门条件里是承重的：`sig.state=unknown` 会让 `sigok` 不成立，而 `sig.state` 留空同样不成立但触发的是另一个码。
4. **形态校验不等于事实校验**。G03 只判 `team_id` 是不是 10 位字母数字；脚本不调 `codesign`，因此**不可能**发现"登记的 Team ID 与实际签名不符"。这一条要在台账说明里写给读者：脚本提高的是记录完整率与口径一致性，不是签名验证覆盖率。
5. **多份台账合并审查时依赖标识必须全局唯一**。脚本一次读入全部文件后按依赖聚合，跨文件重名会表现为 S07（同一字段两个值）而不是"两个工程各有一份"。若确实要分工程登记，给标识加工程前缀。
6. **判定是"这条记录能否支撑表述"，不是"这个依赖是否安全"**。J4 不等于危险，J1 不等于安全：一个未登记任何来源信息的自研代码合并依赖会是 J4，一个已知有高危 CVE 但四格齐全的第三方 SDK 会是 J1。第 25 章 Q11 处理这个混淆。

脚本全文（266 行）：

```bash
#!/usr/bin/env bash
# sdk-supply-ledger-review.sh —— 第三方依赖装配与来源台账审查器（离线 / 只读 / 不联网 / 不碰设备）
# 输入：一份或多份台账文本，每行一条记录：  <依赖标识>,<字段名>,<值>
# 输出：逐条信号码 + 每个依赖的四级判定（J1—J4） + 汇总
# 本脚本只做归属判定与口径核对：不含任何绕过签名校验、伪造团队标识、替换外部二进制
# 或规避 Xcode 报错的做法；不提供任何注入、篡改、降级或重新打包依赖的手段。
# 台账里出现私钥、证书私钥材料或签名口令的写法直接触发 K01 并要求删除该字段。
# 本脚本不联网、不调用任何设备侧或 Apple 命令行工具、不修改输入文件；
# 唯一写出目标是 mktemp -d 创建的临时目录，退出时删除。
set -u
LC_ALL=C; export LC_ALL

usage() {
  cat <<'EOF'
用法: sdk-supply-ledger-review.sh [-q] 台账文件 [...]
  -q, -h  -q 只输出汇总；-h/--help 显示本帮助
台账行格式: <依赖标识>,<字段名>,<值>    # 开头与空行忽略，行尾 CR 忽略
字段命名空间:
  dep.*       依赖本体（kind / requirement_kind / requirement_value / resolved_version /
              resolved_commit / lock_present / lock_committed / auto_resolution /
              binary_form / origin_url / origin_trust / provenance_recorded /
              integrated_by / integration_date）
  sig.*       签名与身份（state / team_id / team_id_expected / identity_changed /
              change_reason / fingerprint_recorded / verification_surface /
              error_text_seen / disposition_date）
  manifest.*  清单与名单（privacy_manifest_present / on_required_list /
              signature_required / list_name_match / aggregate_report_seen）
  ver.*       版本可观测（shipped_version_source / device_visible / org_visible /
              version_confidence / reported_by）
  cve.*       缺陷归属（cve_id / advisories_apple / advisories_sdk_provider /
              advisories_upstream / attribution / kev_listed / fix_version_known /
              fix_adopted / fix_version_shipped）
  remove.*    移除与可证消失（requested / removed_at / replacement / residual_refs /
              provable_absence / witness_type / recheck_date）
  build.*     构建可重现（reproducible / cache_used / resolution_pinned / uuid_checked）
  org.*       组织侧（mdm_visible / inventory_surface / attestation_source）
  key.*       拒收用命名空间：本空间下任何字段都会触发 K01
退出码：出现阻断信号时为 1，否则为 0。信号明细走 stderr，汇总走 stdout。
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

TMPD=$(mktemp -d "${TMPDIR:-/tmp}/sslr.XXXXXX") || { echo "无法创建临时目录" >&2; exit 2; }
trap 'rm -rf "$TMPD"' EXIT INT TERM

awk -v QUIET="$QUIET" '
function emit(code, dep, msg) { cnt[code]++; lines[++nline] = sprintf("%s\t%s\t%s", code, (dep==""?"-":dep), msg) }
function DV(d, f,   k) { k = d SUBSEP f; return (k in valof) ? valof[k] : "" }
function istrue(v)  { return (v=="true"||v=="yes"||v=="1") }
function isfalse(v) { return (v=="false"||v=="no"||v=="0") }
function isbool(v)  { return (istrue(v) || isfalse(v)) }
function isTBD(v)   { return (v=="unknown") }
function isISOdt(v) { return (v ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]([ T][0-9][0-9]:[0-9][0-9](:[0-9][0-9])?)?([Zz]|[+-][0-9][0-9]:?[0-9][0-9])?$/ && validCal(v)) }
function validCal(v,  p, mo, dy) { split(substr(v,1,10), p, "-"); mo = p[2]+0; dy = p[3]+0; return (mo >= 1 && mo <= 12 && dy >= 1 && dy <= 31) }
function dayNum(v,  t) { t=v; gsub(/[^0-9]/,"",t); return substr(t,1,8)+0 }
function isCve(v)   { return (v ~ /^CVE-[0-9]{4}-[0-9]{4,}$/) }
function isCommit(v){ return (v ~ /^[0-9a-f]{7,40}$/) }
function isTeam(v)  { return (v ~ /^[A-Za-z0-9]{10}$/) }
function isUrl(v)   { return (v ~ /^(https?:\/\/|git@|ssh:\/\/)[^ ]+$/) }
BEGIN {
  FS=","
  DOM["dep.kind"]=" spm cocoapods carthage xcframework vendored_framework static_library dynamic_library git_submodule manual_copy unknown "
  DOM["dep.requirement_kind"]=" version range branch commit unpinned unknown "
  DOM["dep.binary_form"]=" source binary_xcframework binary_framework binary_static binary_dynamic unknown "
  DOM["dep.origin_trust"]=" first_party_declared mirror vendor_release unknown "
  DOM["dep.auto_resolution"]=" enabled disabled unknown "
  DOM["sig.state"]=" signed_expected signed_other unsigned invalid removed expired revoked not_applicable unknown "
  DOM["sig.change_reason"]=" ownership_transfer certificate_renewal repackaged team_rotation none unknown "
  DOM["sig.verification_surface"]=" xcode_build manual none unknown "
  DOM["ver.shipped_version_source"]=" lockfile binary_metadata crash_log app_store_connect unknown "
  DOM["ver.version_confidence"]=" exact range unknown "
  DOM["cve.attribution"]=" app_dev sdk_provider upstream platform shared unassigned unknown "
  DOM["remove.residual_refs"]=" none binary source lock unknown "
  DOM["remove.provable_absence"]=" yes no witness_based unknown "
  DOM["remove.witness_type"]=" build_log lockfile diff scan none unknown "
  DOM["org.inventory_surface"]=" mdm none unknown "
  NS["dep"]=1; NS["sig"]=1; NS["manifest"]=1; NS["ver"]=1; NS["cve"]=1
  NS["remove"]=1; NS["build"]=1; NS["org"]=1; NS["key"]=1
  BOOL["dep.lock_present"]=1; BOOL["dep.lock_committed"]=1; BOOL["dep.provenance_recorded"]=1
  BOOL["sig.identity_changed"]=1; BOOL["sig.fingerprint_recorded"]=1; BOOL["sig.error_text_seen"]=1
  BOOL["manifest.privacy_manifest_present"]=1; BOOL["manifest.on_required_list"]=1
  BOOL["manifest.signature_required"]=1; BOOL["manifest.aggregate_report_seen"]=1
  BOOL["ver.device_visible"]=1; BOOL["ver.org_visible"]=1
  BOOL["cve.advisories_apple"]=1; BOOL["cve.advisories_sdk_provider"]=1; BOOL["cve.advisories_upstream"]=1
  BOOL["cve.kev_listed"]=1; BOOL["cve.fix_version_known"]=1; BOOL["build.uuid_checked"]=1
  BOOL["remove.requested"]=1; BOOL["build.cache_used"]=1; BOOL["build.resolution_pinned"]=1
  DATE["dep.integration_date"]=1; DATE["sig.disposition_date"]=1
  DATE["remove.removed_at"]=1; DATE["remove.recheck_date"]=1
  split("S01 S02 S03 S04 S05 S06 S07 K01 M01 M02 M02b M03 M08 M09 " \
        "G01 G01b G02 G03 G04 G05b G06 G07 P01 V01 V05 C02 C03 R01 R02 R03 R03b R04 R06 B01 J4 J3", HB, " ")
  for (i in HB) HARD[HB[i]]=1
}
{ sub(/\r$/, "") }
/^[[:space:]]*#/ { next }
/^[[:space:]]*$/ { next }
{
  if (NF != 3) { emit("S01", "", sprintf("第 %d 行字段数=%d，应为 3（依赖标识,字段名,值）", FNR, NF)); next }
  dep = $1; fld = $2; val = $3
  gsub(/^[[:space:]]+|[[:space:]]+$/, "", dep)
  gsub(/^[[:space:]]+|[[:space:]]+$/, "", fld)
  gsub(/^[[:space:]]+|[[:space:]]+$/, "", val)
  if (dep == "") { emit("S02", "", sprintf("第 %d 行依赖标识为空", FNR)); next }
  if (dep ~ /[[:space:]]/) { emit("S02", dep, "标识含空白字符"); next }
  if (!(dep in seen)) { seen[dep]=1; order[++ndep]=dep }
  dot = index(fld, ".")
  if (dot < 2) { emit("S03", dep, sprintf("字段名 %s 不带命名空间", fld)); next }
  ns = substr(fld, 1, dot-1)
  if (!(ns in NS)) { emit("S03", dep, sprintf("命名空间 %s 未知", ns)); next }
  k = dep SUBSEP fld
  if (k in valof) {
    if (valof[k] == val) emit("S08", dep, sprintf("%s 重复登记同值", fld))
    else emit("S07", dep, sprintf("%s 重复登记且值不同：%s 与 %s", fld, valof[k], val))
  }
  valof[k] = val; nfld[dep]++

  if (ns == "key") { emit("K01", dep, sprintf("台账记录了 %s：应删除该字段，只登记身份指纹与归属结论", fld)); next }
  if (tolower(val) ~ /private key|privkey|-----begin|\.p12|\.mobileprovision/) {
    emit("K01", dep, sprintf("%s 的值像密钥或描述文件内容，应改为身份指纹", fld)); next
  }
  if ((fld in BOOL) && val != "" && !isbool(val) && !isTBD(val)) { emit("S05", dep, sprintf("%s 需要布尔值或 unknown，实为 %s", fld, val)) }
  if ((fld in DOM) && val != "" && index(DOM[fld], " " val " ") == 0) { emit("S04", dep, sprintf("%s 取值 %s 不在允许集合", fld, val)) }
  if (fld in DATE && val != "" && !isTBD(val) && !isISOdt(val)) { emit("S06", dep, sprintf("%s 需要 ISO8601 日期，实为 %s", fld, val)) }
  if (fld == "dep.resolved_commit" && val != "" && !isTBD(val) && !isCommit(val)) { emit("S06", dep, sprintf("resolved_commit %s 不是十六进制提交号", val)) }
  if (fld == "cve.cve_id" && val != "" && !isTBD(val) && !isCve(val)) { emit("S06", dep, sprintf("cve_id %s 不是 CVE-YYYY-NNNN 形态", val)) }
  if (fld == "dep.origin_url" && val != "" && !isTBD(val) && !isUrl(val)) { emit("S06", dep, sprintf("origin_url %s 不是可核对的地址形态", val)) }
  if (fld == "sig.team_id" && val != "" && !isTBD(val) && !isTeam(val)) { emit("G03", dep, sprintf("team_id %s 不是 10 位字母数字", val)) }
}
END {
  for (di = 1; di <= ndep; di++) {
    dep = order[di]
    kind = DV(dep,"dep.kind"); rk = DV(dep,"dep.requirement_kind"); rv = DV(dep,"dep.requirement_value")
    resv = DV(dep,"dep.resolved_version"); resc = DV(dep,"dep.resolved_commit")
    lock = DV(dep,"dep.lock_present"); lockc = DV(dep,"dep.lock_committed"); auto = DV(dep,"dep.auto_resolution")
    bf = DV(dep,"dep.binary_form"); ou = DV(dep,"dep.origin_url"); tr = DV(dep,"dep.origin_trust")
    prov = DV(dep,"dep.provenance_recorded")
    st = DV(dep,"sig.state"); tid = DV(dep,"sig.team_id"); tidx = DV(dep,"sig.team_id_expected")
    idc = DV(dep,"sig.identity_changed"); cr = DV(dep,"sig.change_reason")
    fp = DV(dep,"sig.fingerprint_recorded"); vs = DV(dep,"sig.verification_surface")
    et = DV(dep,"sig.error_text_seen"); disp = DV(dep,"sig.disposition_date")
    pmp = DV(dep,"manifest.privacy_manifest_present"); onl = DV(dep,"manifest.on_required_list")
    sigreq = DV(dep,"manifest.signature_required"); lnm = DV(dep,"manifest.list_name_match")
    ars = DV(dep,"manifest.aggregate_report_seen")
    svs = DV(dep,"ver.shipped_version_source"); devv = DV(dep,"ver.device_visible"); orgv = DV(dep,"ver.org_visible")
    vcf = DV(dep,"ver.version_confidence")
    cid = DV(dep,"cve.cve_id"); aap = DV(dep,"cve.advisories_apple"); asp = DV(dep,"cve.advisories_sdk_provider")
    aup = DV(dep,"cve.advisories_upstream"); att = DV(dep,"cve.attribution"); kev = DV(dep,"cve.kev_listed")
    fvk = DV(dep,"cve.fix_version_known"); fva = DV(dep,"cve.fix_adopted"); fvs = DV(dep,"cve.fix_version_shipped")
    rr = DV(dep,"remove.requested"); rat = DV(dep,"remove.removed_at"); rep = DV(dep,"remove.replacement")
    resid = DV(dep,"remove.residual_refs"); pab = DV(dep,"remove.provable_absence"); wt = DV(dep,"remove.witness_type")
    rcd = DV(dep,"remove.recheck_date")
    repro = DV(dep,"build.reproducible"); cache = DV(dep,"build.cache_used"); pin = DV(dep,"build.resolution_pinned")
    mdmv = DV(dep,"org.mdm_visible"); ois = DV(dep,"org.inventory_surface")

    # ---- 装配与锁定 ----
    if (kind == "") emit("M08", dep, "dep.kind 未登记：走哪条装配通道不可判定")
    if (rk == "")   emit("M09", dep, "dep.requirement_kind 未登记：这一项有没有被钉住不可判定")
    if (isfalse(lock) && (rk == "commit" || isCommit(resc))) { emit("M01", dep, sprintf("lock_present=false 但按 %s 装配：提交号不在锁文件里，是手工拷贝形态", rk==""?resc:rk)) }
    if ((rk == "branch" || rk == "unpinned") && auto == "enabled") emit("M02", dep, sprintf("requirement_kind=%s 且自动解析开启：每次构建可取到不同代码", rk))
    if (rk == "branch" && lockc != "") {
      if (istrue(lockc)) emit("M02b", dep, "分支型要求虽进了锁文件，但锁文件里的分支指针仍随远端移动")
      else emit("M02", dep, "分支型要求且锁文件未提交")
    }
    if (istrue(lock) && isfalse(lockc)) emit("M03", dep, "锁文件存在但未提交：CI 与开发机可解析出不同版本")
    if (rk == "version" && rv != "" && resv != "" && !isTBD(resv) && rv != resv && index(resv, rv) == 0) emit("M04", dep, sprintf("解析出 %s 与要求 %s 对不上", resv, rv))
    if (bf ~ /^binary/ && !istrue(prov)) emit("M05", dep, sprintf("二进制形态 %s 未登记来源凭据", bf))
    if ((kind == "git_submodule" || kind == "manual_copy") && ou == "") emit("M06", dep, sprintf("%s 没有 origin_url：无法回溯取回位置", kind))
    if (tr == "mirror" && isfalse(fp)) emit("M07", dep, "来源是镜像且未登记指纹：与官方发布件的一致性无从核对")
    if (ou ~ /^http:\/\//) emit("M07b", dep, "origin_url 走明文 http：取回件完整性只有转录口径")

    # ---- 签名与身份 ----
    if (st == "invalid" || st == "removed") emit("G01", dep, sprintf("签名状态 %s：文档口径是移入废纸篓并从可信来源重装，本脚本不给任何绕过校验的做法", st))
    if (st == "unsigned" && bf ~ /^binary/) emit("G01b", dep, "平台口径要求全部可执行代码由 Apple 签发证书签名：未签名的外部二进制不是可装配形态")
    if (st == "expired" || st == "revoked") { emit("G06", dep, sprintf("签名身份 %s，处置日期=%s", st, disp==""?"未登记":disp)) }
    if (istrue(idc) && (cr == "unknown" || cr == "")) emit("G02", dep, "签名身份变更且原因未知：需向提供方核实，不得默认相容")
    if (istrue(idc) && cr == "ownership_transfer") emit("G02b", dep, "记为归属转移：文档承认这是合法变更原因之一，需同时登记新团队标识")
    if (tid != "" && tidx != "" && !isTBD(tid) && !isTBD(tidx) && tid != tidx) emit("G04", dep, sprintf("实际团队标识 %s 与预期 %s 不一致", tid, tidx))
    if (st == "signed_expected" && vs == "none") emit("G05", dep, "登记为可信身份但核验面为 none：结论没有观测支撑")
    if (istrue(et) && st == "signed_expected") emit("G05b", dep, "既有报错文本又有可信状态：两项只能保留一个")
    if (st == "not_applicable" && bf ~ /^binary/) emit("G07", dep, "二进制形态却把签名记为不适用：平台口径是全部可执行代码需签名，这一项要么改形态要么补签名")

    # ---- 清单与名单 ----
    if (istrue(onl) && isfalse(pmp)) emit("P01", dep, "在强制名单上且缺隐私清单：按名单口径这一项不应被提交")
    if (istrue(onl) && istrue(sigreq) && bf ~ /^binary/ && st == "") emit("P02", dep, "在名单上、要求签名、二进制形态，但未登记签名状态")
    if (onl == "") emit("P03", dep, "manifest.on_required_list 未登记：名单事实要对照名单本身判定，本脚本不猜")
    if (istrue(ars) && svs == "") emit("P04", dep, "看过聚合报告但版本来源未登记：聚合面不等于逐项版本读数")
    if (lnm != "" && onl != "true" && onl != "false") emit("P05", dep, sprintf("名单名匹配记为 %s 而 on_required_list 未取布尔：两项应闭合", lnm))

    # ---- 版本可观测 ----
    if (istrue(devv) && svs == "") emit("V01", dep, "声称设备侧可见但没有版本来源：不可核对")
    if (rk == "commit" && vcf != "" && vcf != "exact") emit("V02", dep, sprintf("按提交号装配却把置信度记为 %s：提交号是唯一定位，应为 exact", vcf))
    if (vcf == "") emit("V03", dep, "ver.version_confidence 未登记：读者无法区分钉住与区间")
    if (isfalse(orgv) && mdmv != "") emit("V04", dep, "组织可见性记为否却填了 MDM 读数：两项冲突")
    if (istrue(orgv) && ois == "none") emit("V05", dep, "声称组织可见但清单面为 none")

    # ---- 缺陷归属 ----
    if (cid != "" && !isTBD(cid)) {
      if (istrue(aap) && (att == "sdk_provider" || att == "upstream")) emit("C02", dep, "归属记为外部主体却声称 Apple 公告覆盖它：Apple 公告只覆盖 Apple 自己的软件")
      if (istrue(kev) && att == "unassigned") emit("C03", dep, sprintf("%s 在在野名单上但归属未定：先定归属再谈修复顺序", cid))
      if (isfalse(fvk) && fva != "") emit("C04", dep, "修复版本未知却登记了采纳状态")
      if (istrue(fvk) && istrue(fva) && fvs == "") emit("C04b", dep, "记为已采纳但没有实际上线的版本读数")
      if (att == "" || att == "unknown") emit("C05", dep, sprintf("%s 归属未登记：四级判定无法给出 J1", cid))
      if (att == "platform" && !istrue(asp) && !istrue(aap)) emit("C06", dep, "归属记为平台方但两侧公告都没登记：需说明依据")
      if (istrue(aup) && istrue(asp) && att == "sdk_provider") emit("C06b", dep, "上游与提供方两侧公告同时存在：提供方只是搬运者时归属应写 upstream")
    }

    # ---- 移除与可证消失 ----
    if (istrue(rr) && rat == "") emit("R01", dep, "申请了移除但没有移除时间：不可证")
    if (resid == "binary" || resid == "lock" || resid == "source") {
      if (pab == "yes") emit("R02", dep, sprintf("仍有 %s 侧残留却记为可证消失：两件事不能同真", resid))
      if (rat != "") emit("R02b", dep, sprintf("登记了移除时间但 %s 侧仍有残留：这是替换未完成，不是消失", resid))
    }
    if (pab == "witness_based" && (wt == "none" || wt == "" || isTBD(wt))) emit("R03", dep, "可证消失只由见证支撑，却没有见证类型")
    if (istrue(rr) && pab == "yes" && wt == "none") emit("R03b", dep, "声称已消失且证据形态登记为 none")
    if (rat != "" && rcd != "" && isISOdt(rat) && isISOdt(rcd) && dayNum(rcd) < dayNum(rat)) emit("R04", dep, sprintf("复核日 %s 早于移除日 %s", rcd, rat))
    if (istrue(rr) && rep == "" && kind != "manual_copy") emit("R05", dep, "移除后既没有替换项也没有写明不再需要")
    if (pab == "yes" && rcd == "") emit("R06", dep, "可证消失但没有复核日期：结论无时效")
    if (pab == "no" && rr == "") emit("R07", dep, "记为不可证消失但没登记是否申请过移除")

    # ---- 构建可重现 ----
    if (istrue(repro) && auto == "enabled") emit("B01", dep, "自动解析开启却记为可重现：区间型解析每次可取不同件")
    if (istrue(repro) && !istrue(pin)) emit("B02", dep, "解析未钉住却记为可重现")
    if (istrue(repro) && istrue(cache)) emit("B03", dep, "使用构建缓存：可重现结论需注明缓存命中范围")
    if (isfalse(repro) && istrue(pin)) emit("B04", dep, "解析已钉住却记为不可重现：需说明其它不确定来源")

    # ---- J 判定 ----
    blk = 0
    for (q = 1; q <= nline; q++) {
      split(lines[q], parts, "\t")
      if (parts[2] != dep) continue
      if (parts[1] in HARD) blk++
    }
    have  = (kind != "" && rk != "" && bf != "" && lock != "")
    srcok = (ou != "" && tr != "" && istrue(prov))
    verok = (svs != "" && vcf != "" && devv != "")
    sigok = (st != "" && cr != "" && (st == "not_applicable" || tid != "" || tidx != ""))
    remov = (pab != "" && (pab == "no" || (istrue(rr) && rat != "" && resid != "" && (pab == "witness_based" ? (wt != "" && wt != "none") : 1) && rcd != "")))
    if (blk >= 6 || !have)      emit("J4", dep, "只观察到「装了这个依赖」：装配通道、要求类型、形态或锁文件状态未齐，或阻断信号不少于 6 条")
    else if (!srcok || !sigok)  emit("J3", dep, "装配可登记，来源或签名身份仍不确定：不能判断这段代码是谁的")
    else if (!verok)            emit("J2", dep, "可判归属，但版本可观测性不完整：不能判断这一台上跑的是哪一版")
    else if (!remov)            emit("J1", dep, "来源、身份、版本三项齐备，但没有可核验的消失结论：能定责「该谁处置」，不能定责「是否已消失」")
    else                        emit("J1", dep, "来源、身份、版本、消失四项齐备且无阻断信号：可进入归责表述")
  }

  # ---- 汇总 ----
  if (nline > 0) {
    for (q = 1; q <= nline; q++) print lines[q] > "/dev/stderr"
    if (!QUIET) print "" > "/dev/stderr"
  }
  ndist = 0
  for (code in cnt) ndist++
  blk = 0
  for (code in cnt) if (code in HARD) blk += cnt[code]
  printf "依赖数=%d 信号行数=%d\n", ndep, nline
  printf "不同信号码=%d 阻断信号条数=%d\n", ndist, blk
  for (code in cnt) printf "  %s=%d\n", code, cnt[code]
  exit (blk > 0 ? 1 : 0)
}
' "$@"
```

---

## 22. 只读核验脚本二：三件差集与消失结论比对器

### 22.1 它解决的问题与为什么必须分成三件

脚本一只读**一份**台账，因此它只能问"这一格与那一格能不能同真"。本文第四个问题——"这个 SDK 已经不在我们的产品里了，拿什么证明"——恰好需要三种不同主体在不同时刻写下的三份记录：

| 记录件 | 谁在什么时候写 | 承载的事实 | 单独一份能证明什么 |
| --- | --- | --- | --- |
| **装配件** `-A` | 应用开发方，在把依赖放进工程的那一天 | 声明与解析结果：走哪条通道、钉到哪个版本、锁文件在不在册、谁放进来的 | "我们登记要装它" |
| **产物件** `-P` | 构建系统，在每一次构建之后 | 产物侧读数：从哪个面读到版本、置信度、有没有记 build UUID、哪一天构建 | "它确实进了产物，而且是这一版" |
| **移除台账件** `-D` | 处置执行人，在每一次申请、移除、复核之后 | 事件序列：请求、产物在场、移除、复核，各自的日期、残留与见证 | "它在哪一天不再进产物，且被复核过" |

三份分开不是形式洁癖。**每一件事的真相只存在于两个记录面之差里**：声明了却没读到（X01）说明装配未落地或登记多余；读到了却没声明（X02）说明产物里有未登记的第三方代码——这是本文最重的一格，因为它意味着归属链的起点根本不存在；台账引用了登记集合之外的标识（同样是 X02，但说明文本不同）说明处置记录挂错了对象。任何一份单独存在时，这两种情形都看不出来。

脚本二因此是一个**集合差集 + 事件时序 + 口径一致性**比对器，输出 Q1—Q4 四级结论，与脚本一的 J1—J4 平行：J 级看"这条记录能否支撑一句归属表述"，Q 级看"三件记录之间能不能闭合"。两者不互换（第 22.5 节给出四种组合的读法）。

它的边界与脚本一完全相同，且因为要跨三件比对，多一条：**它不推断缺失的记录**。产物件里没有某个依赖时，脚本报"断链"，不报"该依赖不存在"——它无法区分"没装"与"装了但没人记"，这个区分只能由台账流程提供（第 17 章可见性边界的直接后果）。

### 22.2 输入格式

```
用法: sdk-build-crosscheck.sh [-q] [-A 装配件] [-P 产物件] [-D 移除台账件]
三件也可以混写在同一个文件里：此时把 -A / -P / -D 都指向该文件，并用行首 A: / P: / D: 标记归属。
退出码：出现阻断信号时为 1，否则为 0。信号明细走 stderr，汇总走 stdout。
```

三件的列序固定在 `-h` 帮助里，逐件如下（**列数不足即 W01，整行跳过**——脚本二对列数是下限判定，值里含逗号会错位，同脚本一）：

- **装配件**（8 列）：`<依赖标识>,<装配方式>,<需求形态>,<需求值>,<解析版本>,<锁定在册>,<集成日>,<集成方>`。装配方式词表与脚本一的 `dep.kind` **完全同源**（十个取值），需求形态六个取值、锁定在册三态、集成方七个取值也与脚本一的枚举域一致——这是两个脚本能接续的前提。
- **产物件**（7 列）：`<构建标识>,<依赖标识>,<读数来源>,<产物版本>,<置信度>,<uuid记录>,<构建日>`。读数来源四选一或 `unknown`，对应第 9 章的四个版本读数面；置信度取 `exact/range/unknown`。
- **移除台账件**（7 列）：`<序号>,<依赖标识>,<动作>,<事件日>,<残留引用>,<见证类型>,<复核日>`。动作五类把一次处置拆成可定序的事件而不是布尔值：`adoption_recorded`、`binary_present`、`removal_requested`、`removed`、`recheck_completed`。序号唯一是结论可回指的前提（重复即 X06）。

三件的**日期一律要求可定序**（ISO 形态），因为 Y 族四个码全靠日期比较；移除台账件里"复核日"是**末列**且允许留空或 `unknown`，只有既非留空、又非 `unknown`、又不是日期时才触发 W03。这里有一处两列分工值得写清：复核日那一列只用于 Z06 的"复核时点挂在了一个不产生复核的动作上"，真正参与先后比较的是 `recheck_completed` 那一行的**事件日**（Y02 用它比移除日）。留空不会让 Y02 误判，但会让 Z06 失去对象——两列都要填，含义不同。

混写模式（`-A` `-P` `-D` 指向同一个文件）会关掉基于文件名的归属推断，改看每行的 `A:` / `P:` / `D:` 前缀；没有前缀的行触发 W01 并跳过。这个模式存在的原因很实际：小团队的三份记录常常就是同一张表加一列"记录面"。

### 22.3 四族比对

| 族 | 码 | 比的是什么 | 一句话语义 |
| --- | --- | --- | --- |
| **W 行形态** | W01—W04 | 单行列数、标识、取值域、日期、构建标识/序号 | 行不可解析时后面的比对全部失去对象 |
| **X 集合闭合** | X01—X07 | 三件之间的依赖标识差集、同标识重复登记、同构建标识两个版本 | 差集方向决定严重性：产物有而登记无（X02）比登记有而产物无（X01）重 |
| **Y 事件时序** | Y01—Y06 | 集成日 / 构建日 / 请求日 / 移除日 / 复核日之间的先后；同类事件成对 | 时序不成立时"消失"这个词失去含义 |
| **Z 口径一致** | Z01—Z10 | 版本读数来源与形态、置信度、UUID、锁定在册与需求形态、残留与结论 | 本文七处换算失败（F1—F7）里能在机器上判出来的那几处 |

四个族里 Z 族最容易被低估，因为它报的不是矛盾而是**换算不合法**：`Z01` 是一个二进制框架的版本读数取自 lockfile——这句话在任何一份记录内部都不矛盾，它违反的是第 9 章的换算规则（锁文件记的是需求解析结果，不证明框架内部实际编译的版本）。`Z07` 同理：崩溃日志或 App Store Connect 面读到的版本记成 `exact` 置信度，是把旁证当点读数。`Z03` 要求 `binary_metadata` 读数必须配 build UUID，依据是 TN3178 第 7 行（UUID 把镜像连到 dSYM）与第 30 行（签名覆盖该 UUID）——没有 UUID 的产物元数据读数回指不到"这一次构建的那份镜像"。

`Z09` 是唯一一条**只由装配件触发**的口径信号：手工放入（`manual_copy` / `vendored_framework`）且集成方 `unknown`。它引用的文档口径是《Verifying the origin of your XCFrameworks》第 5 行——"这些包的行为会成为产品行为的一部分"。这一格的严重性在于装配即责任：连"谁放进来的"都没有记录时，责任仍然落在应用开发方，只是无法内部分配。

X 族里两个码要区分方向：

- `X01` 装配件登记、产物件没有读数 → 阻断，但说明文本写的是"断链"而不是"未安装"；
- `X02` 产物件或台账件引用了装配件之外的标识 → 阻断，且这类依赖在 Q 分级里**必然落 Q4**（第 22.4 节坏样本的 GhostDep 就是这一条）。

### 22.4 实跑结果

四种运行都在本轮环境执行过（同一支脚本、四组参数），输出原样摘录。

**（1）三件全闭合**（`fx2/a_good.csv` + `p_good.csv` + `d_good.csv`，各 3 个依赖）：

```
装配登记数=3 产物读数依赖数=3 台账引用依赖数=3

不同信号码=1 阻断信号条数=0
  Q1=3
```

退出码 0。三件标识集合完全相同（`Networking` / `PaymentCore` / `LegacyAnalytics`），时序成立（LegacyAnalytics 走满"请求 2026-05-01 → 移除 2026-05-20 → 复核 2026-06-10"，其产物读数日 2026-04-01 早于移除日），口径一致。这里有一处值得注意：三个依赖里只有 `PaymentCore` 是二进制形态（`xcframework`），它的版本读数来自 `binary_metadata` 并记了 build UUID；另外两个源码型依赖的读数同样来自 `lockfile`，但**不触发 Z01**——Z01 只在装配方式是 `xcframework` / `vendored_framework` / `static_library` / `dynamic_library` 四者之一时触发。同一种记法在两种形态上一个报错一个沉默，正是第 9 章"锁文件对源码依赖够用、对二进制框架不够用"那句判据的可执行形式。

**（2）三件全缺陷**（`fx2/a_bad.csv` 49 行 + `p_bad.csv` 33 行 + `d_bad.csv` 44 行）：

```
装配登记数=46 产物读数依赖数=27 台账引用依赖数=19

不同信号码=31 阻断信号条数=117
  Q4=36  Q3=6  Q2=5  Q1=1
```

退出码 1。三个计数本身就是一个结论：**46 : 27 : 19 是三个互不相等的集合基数**，也就是三个记录面各自覆盖的依赖全集不同——这是本文反复描述的那种状态（装配声明、产物事实、处置记录来自三个不同流程，从未对齐）。Q4 的 36 条由两部分组成：46 个装配登记里 34 个因自身行形态不可解析（W/X 族）而落 Q4，另外 2 个标识（`GhostDep` 只在产物件、`GhostDepD` 只在台账件）各贡献一条——所以 Q4 计数**可以大于**装配登记数，读数时不要把两者相除。

摘录八条（覆盖四族）：

```
W03	BadRK	需求形态 [tag] 不在词表内
W04	-	产物行缺构建标识：读数无法回指到某一次构建: ,pb12,NoBidDep,lockfile,1.0.0,exact,true,2026-03-01
X05	DupAdopt	同一依赖在装配件里两行的形态或需求不同: [version,1.0.0/spm] 与 [version,1.1.0/cocoapods]
X04	SameBidTwo	同一构建标识 [pb2] 对该依赖给出两个版本 [1.0.0] 与 [1.0.1]：一次构建只有一个产物
Y02	RecheckEarly	复核完成 [2026-05-01] 早于移除 [2026-06-01]：复核不可能确认一件尚未发生的事
Z01	Q2Tier	二进制框架的版本读数取自 lockfile（构建 pb10）：锁定文件记的是需求解析结果，不证明框架内部实际编译的版本
Z10	BackAgain	台账 d23 在移除 [2026-06-01] 之后又记到 binary_present [2026-07-01]：后续读数推翻了消失结论，产物里仍有这段代码
Q4	GhostDep	该依赖只出现在产物件里：没有装配登记，归属、版本与消失三项判定都缺少起点
```

`W03 需求形态 [tag] 不在词表内` 这一条最有信息量：`tag` 是 CocoaPods 的记法，不是 Xcode 的三种 package requirement 之一。脚本二按 Xcode 词表拒收，**这就是第 3 章 F2 那处换算失败在机器上的样子**——两套词表之间没有映射函数，所以只能拒收，不能"接受并折算"。台账要同时容纳两种来源时，正确做法是把 Pod 的 `:tag` 登记成 `version` + 具体值，并在依赖标识之外另存原始记法，而不是扩词表。

`Z10` 在坏样本里只有一条，来自 `BackAgain` 这个依赖的四行台账（`d22 removed 2026-06-01` / `d23 binary_present 2026-07-01` / `d24 removal_requested 2026-05-01` / `d25 recheck_completed 2026-08-01`）。这一条是本文第 11 章"移除的两种失败形状"的第二种——**消失结论被自己后续的记录推翻**。它与其他信号的区别在于：其他码说的是"记录不一致"，Z10 说的是"结论已经不成立"。在 Q 分级里它算 Z 族（口径矛盾），`BackAgain` 因此落 Q2；但业务侧应把它当作比 Q2 更紧急的一件事处理，因为它意味着一句已经对外说过的话现在是错的。同一条依赖上还有一处**脚本判不出来**的东西值得写进限制：`d23` 的 `binary_present` 带着 `残留引用=binary`，而时间更晚的 `d25` 复核完成却记 `残留引用=none`——脚本的 Z04 只做"动作 removed 与其自身残留列"的内部比较，Z10 只问"移除之后是否又见产物"，都不做"较晚的复核结论与较早的残留读数是否相容"这种跨条推断。这是第 23.4 节登记的口径缺口之一。

**（3）只给一件**（三次运行，各只提供一个参数）：

| 参数 | 汇总行 | 不同信号码 | 阻断 | 退出码 |
| --- | --- | --- | --- | --- |
| 仅 `-A` | 装配登记数=3 产物读数依赖数=0 台账引用依赖数=0 | 5（N02 N03 X01 X03 Q4） | 6 | 1 |
| 仅 `-P` | 装配登记数=0 产物读数依赖数=3 台账引用依赖数=0 | 3（N01 N03 X02） | 3 | 1 |
| 仅 `-D` | 装配登记数=0 产物读数依赖数=0 台账引用依赖数=3 | 3（N01 N02 X02） | 3 | 1 |

三个码 `N01` / `N02` / `N03` 就是"某件未提供"，它们**不计入阻断**（`code !~ /^N/ && code !~ /^Q/` 是阻断定义）：缺件是使用方式问题，不是台账缺陷，把它们算进阻断会让"只跑一件"的正常用法显示成满屏错误。注意仅 `-P` 与仅 `-D` 时 X02 各触发 3 次、而 Q 级一条不出——因为装配登记缺失时"归属、版本、消失三项判定都缺少起点"，脚本拒绝给出任何分级结论。这是脚本二最重要的一处保守设计：**它不会用两份记录替第三份记录补出结论**。

**（4）混写模式**（`-A = -P = -D = fx2/merged.csv`，四行有效记录 + 一行无前缀）：

```
装配登记数=1 产物读数依赖数=1 台账引用依赖数=1

不同信号码=2 阻断信号条数=1
  Q1=1
  W01=1
```

退出码 1。同一组事实（1 个依赖、三件齐全）在两次运行里给出同一个 Q1，说明混写只是换一种输入写法、不改语义；W01 那一行是文件里故意放的无前缀行 `OrphanLine,with,no,marker`，它的作用是**证明 MERGED 模式真的生效**——如果脚本仍按文件名判归属，这个文件被当成装配件读，八列判定会把所有行都拒掉。

### 22.5 与脚本一的接续方式

两支脚本读的是同一套事实的不同切片，接入顺序是**先一后二**：脚本一保证每一格填得对口径，脚本二保证格子与格子之间连得上。反过来跑会看到大量 Q4——它们多数是脚本一早已能定位的填表问题。

J 级与 Q 级的组合有四种典型读法：

| 组合 | 读法 | 能对外说什么 |
| --- | --- | --- |
| J1 + Q1 | 台账完整、三件闭合 | 可以出具"版本 = X、且自 Y 日起不再进产物（有复核）"这类表述 |
| J3 + Q1 | 三件闭合，但来源或签名身份本身不确定 | 能说"它在产物里是哪一版"，不能说"这段代码是谁的"——第 6 章 BF-2 的典型形态 |
| J1 + Q4 | 单条台账自洽，但它在产物件或台账件里没有对应记录 | **什么都不说**：自洽的记录可能描述的是一个不存在的装配（脚本一看不见产物，这是它的能力上限） |
| J4 + Q2 | 两处都缺 | 先补表（脚本一），再对表（脚本二）；此时任何"已移除"表述都不成立 |

第三行是两支脚本相互不可替代性的最好说明：脚本一**看不到跨件缺口**，脚本二**不理解单格语义**（它的装配件没有签名、清单、CVE 三族字段）。一个依赖可以在脚本一里是 J1、在脚本二里是 Q4，两条结论都对，合起来才是可用的判断。

脚本全文（277 行）：

```bash
#!/usr/bin/env bash
# sdk-build-crosscheck.sh —— 装配登记、产物读数与移除台账的三件差集比对器
# （离线 / 只读 / 不联网 / 不碰设备 / 不调用任何 Apple 命令行工具）
# 本脚本只做集合差集、时间序与口径一致性比对，输出「这段代码是谁的、
# 这一台跑的是哪一版、它还在不在」三级归属结论；
# 不含任何绕过 Xcode 签名校验、伪造 Team ID、替换外部二进制或规避构建报错的做法，
# 也不提供任何注入、篡改、降级或重新打包依赖的手段。
# 本脚本不联网、不访问设备、不修改输入文件；临时件写在 mktemp -d 并在退出时删除。
set -u
LC_ALL=C; export LC_ALL

usage() {
  cat <<'EOF'
用法: sdk-build-crosscheck.sh [-q] [-A 装配件] [-P 产物件] [-D 移除台账件]
  -q  只输出汇总与分级结论；-h 显示本帮助
  -A 装配件   每行: <依赖标识>,<装配方式>,<需求形态>,<需求值>,<解析版本>,<锁定在册>,<集成日>,<集成方>
             装配方式: spm cocoapods carthage xcframework vendored_framework
                       static_library dynamic_library git_submodule manual_copy unknown
             需求形态: version range branch commit unpinned unknown
             锁定在册: true false unknown
             集成方:   app_dev sdk_provider upstream platform shared unassigned unknown
  -P 产物件   每行: <构建标识>,<依赖标识>,<读数来源>,<产物版本>,<置信度>,<uuid记录>,<构建日>
             读数来源: lockfile binary_metadata crash_log app_store_connect unknown
             置信度:   exact range unknown
             uuid记录: true false unknown
  -D 移除台账件 每行: <序号>,<依赖标识>,<动作>,<事件日>,<残留引用>,<见证类型>,<复核日>
             动作:     adoption_recorded binary_present removal_requested removed recheck_completed
             残留引用: none binary source lock unknown
             见证类型: build_log lockfile diff scan none unknown
             复核日:   ISO 日期、留空或 unknown
  三件也可以混写在同一个文件里：此时把 -A / -P / -D 都指向该文件，并用行首 A: / P: / D: 标记归属。
  # 开头与空行忽略，行尾 CR 忽略；日期接受 YYYY-MM-DD 或带时刻的 ISO 写法。
退出码：出现阻断信号时为 1，否则为 0。信号明细走 stderr，汇总走 stdout。
本脚本不联网、不访问设备、不修改输入文件；唯一写出目标是 mktemp -d 创建的临时目录，退出时删除。
EOF
}

QUIET=0; AF=""; PF=""; DF=""
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    -q) QUIET=1; shift ;;
    -A) AF=${2:-}; shift 2 ;;
    -P) PF=${2:-}; shift 2 ;;
    -D) DF=${2:-}; shift 2 ;;
    *) echo "未知参数: $1" >&2; usage >&2; exit 2 ;;
  esac
done
if [ -z "$AF" ] && [ -z "$PF" ] && [ -z "$DF" ]; then usage >&2; exit 2; fi
FILES=()
for f in "$AF" "$PF" "$DF"; do
  [ -z "$f" ] && continue
  [ -f "$f" ] || { echo "输入不可读: $f" >&2; exit 2; }
  dup=0
  if [ "${#FILES[@]}" -gt 0 ]; then
    for g in "${FILES[@]}"; do [ "$g" = "$f" ] && dup=1; done
  fi
  [ "$dup" = "1" ] && continue
  FILES+=("$f")
done

TMPD=$(mktemp -d "${TMPDIR:-/tmp}/sbcc.XXXXXX") || { echo "无法创建临时目录" >&2; exit 2; }
trap 'rm -rf "$TMPD"' EXIT INT TERM

awk -v QUIET="$QUIET" -v AF="$AF" -v PF="$PF" -v DF="$DF" -v MERGED="$([ -n "$AF" ] && [ "$AF" = "$PF" ] && [ "$PF" = "$DF" ] && echo 1 || echo 0)" '
function emit(code, dep, msg) { cnt[code]++; lines[++nline] = sprintf("%s\t%s\t%s", code, (dep==""?"-":dep), msg) }
function isISOdt(v) { return (v ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]([ T][0-9][0-9]:[0-9][0-9](:[0-9][0-9])?)?([Zz]|[+-][0-9][0-9]:?[0-9][0-9])?$/ && validCal(v)) }
function validCal(v,  p, mo, dy) { split(substr(v,1,10), p, "-"); mo = p[2]+0; dy = p[3]+0; return (mo >= 1 && mo <= 12 && dy >= 1 && dy <= 31) }
function dayNum(v,  t) { t = v; gsub(/[^0-9]/, "", t); return substr(t,1,8)+0 }
function istrue(v)  { return (v=="true"||v=="yes"||v=="1") }
function isBlank(v) { return (v ~ /^[ \t]*$/) }
function inSet(v, n, S,   i) { for (i=1; i<=n; i++) if (S[i]==v) return 1; return 0 }
function isBinary(k) { return (k=="xcframework"||k=="vendored_framework"||k=="static_library"||k=="dynamic_library") }
function tally(c, pre,   q, p, n) {
  n = 0
  for (q = 1; q <= nline; q++) {
    split(lines[q], p, "\t")
    if (p[2] != c) continue
    if (p[1] ~ "^" pre) n++
  }
  return n
}
BEGIN {
  FS=","
  nKIND=split("spm cocoapods carthage xcframework vendored_framework static_library dynamic_library git_submodule manual_copy unknown", KIND, " ")
  nRK=split("version range branch commit unpinned unknown", RK, " ")
  nTRU=split("true false unknown", TRU, " ")
  nATTR=split("app_dev sdk_provider upstream platform shared unassigned unknown", ATTR, " ")
  nSRC=split("lockfile binary_metadata crash_log app_store_connect unknown", SRC, " ")
  nCONF=split("exact range unknown", CONF, " ")
  nACT=split("adoption_recorded binary_present removal_requested removed recheck_completed", ACT, " ")
  nRES=split("none binary source lock unknown", RES, " ")
  nWIT=split("build_log lockfile diff scan none unknown", WIT, " ")
}
{ sub(/\r$/, "") }
/^[ \t]*#/ { next }
/^[ \t]*$/ { next }
{
  oline = $0
  kind = ""
  if (MERGED != "1") {
    if (FILENAME == AF) kind = "A"
    else if (FILENAME == PF) kind = "P"
    else if (FILENAME == DF) kind = "D"
  }
  if (oline ~ /^[ \t]*A[ \t]*:/) kind = "A"
  else if (oline ~ /^[ \t]*P[ \t]*:/) kind = "P"
  else if (oline ~ /^[ \t]*D[ \t]*:/) kind = "D"
  if (kind == "") { emit("W01","-","该行没有归属标记：三件混写在同一个文件里时需用行首 A: / P: / D: 标明: " oline); next }
  sub(/^[ \t]*[APD][ \t]*:/, "", $0)

  if (kind == "A") {
    if (NF < 8) { emit("W01","-","装配件行不足八列: " oline); next }
    dep=$1; k=$2; rk=$3; rv=$4; resv=$5; lk=$6; id=$7; by=$8
    if (isBlank(dep)) { emit("W02","-","装配行缺依赖标识: " oline); next }
    if ((dep in Aseen)) {
      if (Ark[dep] != rk || Arv[dep] != rv || Ak[dep] != k) emit("X05", dep, "同一依赖在装配件里两行的形态或需求不同: [" Ark[dep] "," Arv[dep] "/" Ak[dep] "] 与 [" rk "," rv "/" k "]")
      else emit("X05", dep, "同一依赖在装配件里重复登记且内容相同: " dep)
    } else {
      Aseen[dep]=1; Ano[++An]=dep
      Ak[dep]=k; Ark[dep]=rk; Arv[dep]=rv; Aresv[dep]=resv; Alk[dep]=lk; Aid[dep]=id; Aby[dep]=by
    }
    if (!inSet(k, nKIND, KIND))   emit("W03", dep, "装配方式 [" k "] 不在词表内")
    if (!inSet(rk, nRK, RK))      emit("W03", dep, "需求形态 [" rk "] 不在词表内")
    if (!inSet(lk, nTRU, TRU))    emit("W03", dep, "锁定在册 [" lk "] 不是 true/false/unknown")
    if (!inSet(by, nATTR, ATTR))  emit("W03", dep, "集成方 [" by "] 不在词表内")
    if (!isISOdt(id))             emit("W03", dep, "集成日 [" id "] 不是可定序的日期")
    if (rk != "unpinned" && rk != "unknown" && isBlank(rv)) emit("W03", dep, "需求形态为 [" rk "] 却没有需求值")
    if (isBlank(resv))            emit("W03", dep, "解析版本为空：锁定文件读到什么版本必须有值，unknown 请显式写 unknown")
    if (by == "unknown" && (k == "manual_copy" || k == "vendored_framework")) emit("Z09", dep, "手工放入的外部框架且集成方为 unknown：无法回指是谁在哪一步把它放进工程（Verifying the origin of your XCFrameworks 第 5 行：这些包的行为会成为产品行为的一部分）")
    next
  }
  if (kind == "P") {
    if (NF < 7) { emit("W01","-","产物件行不足七列: " oline); next }
    bid=$1; dep=$2; src=$3; pv=$4; cf=$5; uu=$6; bd=$7
    if (isBlank(bid)) { emit("W04","-","产物行缺构建标识：读数无法回指到某一次构建: " oline); next }
    if (isBlank(dep)) { emit("W02","-","产物行缺依赖标识: " oline); next }
    if (!inSet(src, nSRC, SRC))   emit("W03", dep, "读数来源 [" src "] 不在词表内")
    if (!inSet(cf, nCONF, CONF))  emit("W03", dep, "置信度 [" cf "] 不在 exact/range/unknown 词表内")
    if (!inSet(uu, nTRU, TRU))    emit("W03", dep, "uuid 记录 [" uu "] 不是 true/false/unknown")
    if (!isISOdt(bd))             emit("W03", dep, "构建日 [" bd "] 不是可定序的日期")
    pn[dep]++
    psrc[dep SUBSEP pn[dep]] = src; pver[dep SUBSEP pn[dep]] = pv
    pcft[dep SUBSEP pn[dep]] = cf;  puid[dep SUBSEP pn[dep]] = uu
    pday[dep SUBSEP pn[dep]] = bd;  pbid[dep SUBSEP pn[dep]] = bid
    if (!(dep in PallSeen)) { PallSeen[dep]=1; Pall[++Pn]=dep }
    kq = bid SUBSEP dep
    if (kq in bq) {
      if (bq[kq] != pv) emit("X04", dep, "同一构建标识 [" bid "] 对该依赖给出两个版本 [" bq[kq] "] 与 [" pv "]：一次构建只有一个产物")
      else { bq2[kq]++; if (bq2[kq]==2) emit("X07", dep, "构建标识 [" bid "] 对同一依赖登记了多条读数来源 [" src "]：需说明它们分别覆盖哪个切片") }
    } else { bq[kq]=pv; bq2[kq]=1 }
    next
  }
  if (kind == "D") {
    if (NF < 7) { emit("W01","-","移除台账行不足七列: " oline); next }
    rid=$1; dep=$2; ac=$3; ev=$4; rs=$5; wt=$6; rc=$7
    if (isBlank(rid)) { emit("W04","-","台账行缺序号：结论无法回指该条: " oline); next }
    if ((rid in Dseen)) emit("X06","-","台账序号重复: " rid "（两条记录引用同一动作，须改用不同序号）")
    Dseen[rid]=1
    if (isBlank(dep)) { emit("W02","-","台账行缺依赖标识: " oline); next }
    if (!inSet(ac, nACT, ACT))    emit("W03", dep, "动作 [" ac "] 不在词表内")
    if (!inSet(rs, nRES, RES))    emit("W03", dep, "残留引用 [" rs "] 不在词表内")
    if (!inSet(wt, nWIT, WIT))    emit("W03", dep, "见证类型 [" wt "] 不在词表内")
    if (!isISOdt(ev))             emit("W03", dep, "事件日 [" ev "] 不是可定序的日期")
    if (rc != "" && rc != "unknown" && !isISOdt(rc)) emit("W03", dep, "复核日 [" rc "] 既不是日期也不是 unknown 或留空")
    dn[dep]++
    dact[dep SUBSEP dn[dep]] = ac; dday[dep SUBSEP dn[dep]] = ev
    dres[dep SUBSEP dn[dep]] = rs; dwit[dep SUBSEP dn[dep]] = wt
    drc[dep SUBSEP dn[dep]]  = rc; drid[dep SUBSEP dn[dep]] = rid
    if (!(dep in DallSeen)) { DallSeen[dep]=1; Dall[++Dl]=dep }
    next
  }
}
END {
  if (AF == "") emit("N01","-","装配件未提供：依赖全集不可知，差集与归属结论都不成立")
  if (PF == "") emit("N02","-","产物件未提供：这段代码是否真进了产物无从核对")
  if (DF == "") emit("N03","-","移除台账未提供：消失结论与复核时序不可核对")

  for (i = 1; i <= An; i++) { c = Ano[i]
    if (!(c in pn))    emit("X01", c, "装配件登记了该依赖、产物件没有它的读数：声明装配与实际产物之间断链")
    if (!(c in dn))    emit("X03", c, "该依赖在移除台账里没有任何条目：既没记录留存也没记录消失")
  }
  for (i = 1; i <= Pn; i++) { c = Pall[i]
    if (!(c in Aseen)) emit("X02", c, "产物件读到该依赖、装配件没有登记：产物里出现未登记的第三方代码，归属起点缺失")
  }
  for (i = 1; i <= Dl; i++) { c = Dall[i]
    if (!(c in Aseen)) emit("X02", c, "移除台账引用了装配件之外的依赖标识 [" c "]：处置记录落在登记集合之外")
  }

  for (i = 1; i <= An; i++) {
    c = Ano[i]; if (!(c in pn)) continue
    k = Ak[c]; rk = Ark[c]; resv = Aresv[c]; lk = Alk[c]; id = Aid[c]
    for (t = 1; t <= pn[c]; t++) {
      src = psrc[c SUBSEP t]; pv = pver[c SUBSEP t]; cf = pcft[c SUBSEP t]
      uu = puid[c SUBSEP t]; bd = pday[c SUBSEP t]; bid = pbid[c SUBSEP t]
      if (resv != "unknown" && pv != "unknown" && pv != resv) emit("X04", c, "装配解析版本 [" resv "] 与产物读数版本 [" pv "] 不一致（构建 " bid "）：两者只有一个能代表这一台上跑的版")
      if (src == "lockfile" && isBinary(k)) emit("Z01", c, "二进制框架的版本读数取自 lockfile（构建 " bid "）：锁定文件记的是需求解析结果，不证明框架内部实际编译的版本")
      if (src == "crash_log" || src == "app_store_connect") {
        if (cf == "exact") emit("Z07", c, "读数来源为 [" src "] 却给出 exact 置信度（构建 " bid "）：旁证只能支撑范围，精确版本要回到产物元数据或崩溃符号")
      }
      if (src == "binary_metadata" && !istrue(uu)) emit("Z03", c, "产物元数据读数但未记录 build UUID（构建 " bid "）：没有 UUID 就指不回本次构建的那份镜像，签名还覆盖该 UUID（TN3178 第 7、30 行）")
      if (src == "unknown") emit("Z08", c, "读数来源 unknown（构建 " bid "）：无法判断这条版本读数出自哪里，也就无法把这段代码回指到某个提供方")
      if (isISOdt(bd) && isISOdt(id) && dayNum(bd) < dayNum(id)) emit("Y06", c, "构建日 [" bd "] 早于集成日 [" id "]：读数指向集成之前的那次构建，不代表当前装配状态")
    }
    if ((rk == "commit" || rk == "unpinned" || rk == "branch") && !istrue(lk)) emit("Z02", c, "需求形态为 [" rk "] 且锁定文件不在册：解析结果可随时间漂移（Building Swift packages or apps that use them in continuous integration workflows 第 9 行：把 Package.resolved 提交进仓库才不会构建到意外版本）")
    if (istrue(lk) && rk == "unpinned") emit("Z06", c, "声明锁定文件在册但需求形态为 unpinned：两处记法互相矛盾，无法判断解析结果是否被固定")
  }

  for (i = 1; i <= An; i++) {
    c = Ano[i]
    if (dn[c] == 0) continue
    id = Aid[c]
    nreq=0; ndel=0; nrc=0
    for (t = 1; t <= dn[c]; t++) {
      a = dact[c SUBSEP t]; ev = dday[c SUBSEP t]; rs = dres[c SUBSEP t]
      wt = dwit[c SUBSEP t]; rc = drc[c SUBSEP t]; qid = drid[c SUBSEP t]
      if (a == "removed")            { ndel++; if (ndel==1) delday=ev }
      else if (a == "removal_requested") { nreq++; if (nreq==1) reqday=ev }
      else if (a == "recheck_completed") { nrc++;  if (nrc==1)  rcdays=ev }
      if (a == "removed" && rs != "none") emit("Z04", c, "台账 " qid " 记为 removed 但残留引用为 [" rs "]：声称已消失的同时记录了仍在的引用")
      if (a == "removed" && (wt == "none" || wt == "unknown" || wt == "")) emit("Z05", c, "台账 " qid " 的移除没有可回指的见证（witness=[" wt "]）：消失结论只能靠声明")
      if (rc != "" && rc != "unknown" && a != "recheck_completed") emit("Z06", c, "台账 " qid " 填了复核日 [" rc "] 但动作不是 recheck_completed：复核时点挂在一个不产生复核的动作上")
      for (u = t+1; u <= dn[c]; u++) {
        if (dact[c SUBSEP u] != a) continue
        if (dday[c SUBSEP u] == ev) emit("Y04", c, "同一依赖两条同为 [" a "] 且事件日相同 [" ev "]（台账 " qid " 与 " drid[c SUBSEP u] "）：两条无法区分")
        else                        emit("Y05", c, "同一依赖两条同为 [" a "] 但事件日不同 [" ev " / " dday[c SUBSEP u] "]：结论要指明是哪一条")
      }
    }
    if (ndel > 0 && nreq == 0) emit("Y03", c, "有 removed 但没有 removal_requested：移除动作缺请求记录，事件序列不完整")
    if (isISOdt(id)) {
      if (ndel > 0 && isISOdt(delday) && dayNum(delday) < dayNum(id)) emit("Y01", c, "移除事件日 [" delday "] 早于集成日 [" id "]：删掉的不是这次装配的那个对象")
    }
    if (nrc > 0 && ndel > 0 && isISOdt(rcdays) && isISOdt(delday) && dayNum(rcdays) < dayNum(delday)) emit("Y02", c, "复核完成 [" rcdays "] 早于移除 [" delday "]：复核不可能确认一件尚未发生的事")
    if (ndel > 0 && nrc == 0) emit("Z06", c, "有 removed 但没有 recheck_completed：移除后未复核，消失结论停留在单次记录")
    if (ndel > 0 && isISOdt(delday)) {
      for (t = 1; t <= dn[c]; t++) {
        if (dact[c SUBSEP t] != "binary_present") continue
        if (isISOdt(dday[c SUBSEP t]) && dayNum(dday[c SUBSEP t]) > dayNum(delday)) emit("Z10", c, "台账 " drid[c SUBSEP t] " 在移除 [" delday "] 之后又记到 binary_present [" dday[c SUBSEP t] "]：后续读数推翻了消失结论，产物里仍有这段代码")
      }
    }
  }

  for (i = 1; i <= Pn; i++) { c = Pall[i]
    if (c in Aseen) continue
    if (AF == "") continue
    emit("Q4", c, "该依赖只出现在产物件里：没有装配登记，归属、版本与消失三项判定都缺少起点")
  }
  for (i = 1; i <= Dl; i++) { c = Dall[i]
    if (c in Aseen) continue
    if (AF == "") continue
    if ((c in PallSeen)) continue
    emit("Q4", c, "该依赖只出现在移除台账里：既无装配登记也无产物读数")
  }
  for (i = 1; i <= An; i++) {
    c = Ano[i]
    fmtbad = tally(c, "W") + tally(c, "X")
    seqbad = tally(c, "Y"); sembad = tally(c, "Z")
    if (AF == "" || PF == "" || DF == "" || fmtbad > 0) emit("Q4", c, "三件不齐或该依赖的行形态不可解析：差集比对没有可比对象")
    else if (seqbad > 0) emit("Q3", c, "集合闭合但时间序不成立：集成、移除与复核的先后不可同时为真")
    else if (sembad > 0) emit("Q2", c, "集合闭合且时序成立，但版本或消失口径存在矛盾：归属结论按最弱一环给出")
    else emit("Q1", c, "三件闭合、时序成立、口径一致：可对该依赖出具版本与消失结论")
  }

  if (nline > 0) {
    for (q = 1; q <= nline; q++) print lines[q] > "/dev/stderr"
    if (!QUIET) print "" > "/dev/stderr"
  }
  ndist = 0
  for (code in cnt) ndist++
  blk = 0
  for (code in cnt) if (code !~ /^N/ && code !~ /^Q/) blk += cnt[code]
  printf "装配登记数=%d 产物读数依赖数=%d 台账引用依赖数=%d\n", An, Pn, Dl
  printf "不同信号码=%d 阻断信号条数=%d\n", ndist, blk
  for (code in cnt) printf "  %s=%d\n", code, cnt[code]
  exit (blk > 0 ? 1 : 0)
}
' "${FILES[@]}"
```

---

## 23. 两个脚本的全量分支覆盖验收

### 23.1 验收方法

覆盖验收要回答的问题很窄：**信号码表里登记的每一个码，本轮是否真的被触发过一次**。一个从未被触发的码等于没写过的码——它会出现在文档里、出现在汇总表里，却永远不会出现在读者面前，而读者无法区分"这条判据不存在"与"这条判据存在但样本没命中"。

方法是集合双向差集，四步：

1. **取声明集**：从脚本源码里把所有 `emit("…"` 的字面码抽出来去重。脚本一得 64 个，脚本二得 34 个（`grep -o 'emit("[A-Za-z0-9]*"' | sed | sort -u`）。这一步不需要执行脚本，因此它抓的是"代码里写出来的分支"，不是"我以为写了的分支"。
2. **取观测集**：按下面列出的全部运行方式逐条实跑，把每行 stderr 的第一列（信号码）抽出、去重。脚本一的空行来自 `print "" > "/dev/stderr"`（非 `-q` 时在信号与汇总之间加一空行），要先用 `awk 'NF'` 滤掉，否则差集里会出现一个空码。
3. **双向 `comm`**：`comm -23 声明 观测` 为空表示每个声明的码都触发过；`comm -13 声明 观测` 为空表示没有输出过表外码。**两个方向都要为空**才算闭合。
4. **多次运行合并**：判定类码（J1、Q1）只在闭合样本出现，缺件类码（N01—N03）只在"少给一件"的运行出现，所以观测集必须并上所有运行方式，不能只看坏样本。

本轮实跑清单（共 8 次，全部在本环境执行）：

| 运行 | 命令 | 退出码 | 观测到的码数 |
| --- | --- | --- | --- |
| 脚本一 好样本 | `bash .x12-s1.sh fx/good.tsv` | 0 | 1（J1） |
| 脚本一 坏样本 | `bash .x12-s1.sh fx/bad.tsv` | 1 | 63 |
| 脚本二 三件闭合 | `-A a_good -P p_good -D d_good` | 0 | 1（Q1） |
| 脚本二 三件缺陷 | `-A a_bad -P p_bad -D d_bad` | 1 | 31 |
| 脚本二 仅装配件 | `-A a_good` | 1 | 5 |
| 脚本二 仅产物件 | `-P p_good` | 1 | 3 |
| 脚本二 仅台账件 | `-D d_good` | 1 | 3 |
| 脚本二 混写模式 | `-A m -P m -D m`（同一个 `merged.csv`） | 1 | 2 |

结果：**脚本一 64/64，脚本二 34/34，两个方向差集均为空，合计 98 个信号码全部有实跑记录。**

三点方法上的说明：

- 脚本二的坏样本单独只能给出 31 个码，缺的 3 个全是 `N01`/`N02`/`N03`——这三个码的触发条件是"某件没给"，与"给了但填错"在设计上互斥，所以必须靠那三次单件运行补齐。**任何把"缺件"类信号写进脚本的判定，都要有一组故意缺件的运行**，否则它们永远不可达。
- 混写模式那一行的价值不只在覆盖率：它是唯一一次能证明 `MERGED=1` 分支（关闭基于文件名的归属推断）真被执行过的运行；同时它给出的 Q1 与三件闭合运行给出的 Q1 是同一结论，构成一处很小的回归检查。
- 覆盖验收**不校验判据写得对不对**，只校验分支可达。判据正确性靠第 23.4 节的缺口清单与第 21.5／22.5 两节的限制声明来限定其含义边界。

### 23.2 脚本一：64 个信号码的覆盖表

"样本"列是触发该码的依赖标识（本轮样本里每个标识都为命中一格而命名，见第 21.4 节）；"阻断"取自脚本第 97—99 行的 `HB` 名单。计数来自上表两次运行的合并观测。

| 码 | 判据 | 样本 | 条数 | 阻断 |
| --- | --- | --- | --- | --- |
| S01 | 行不是恰好三列 | 第 3 行（两列） | 1 | 是 |
| S02 | 依赖标识为空或含空白 | 第 4 行（标识为空） | 1 | 是 |
| S03 | 字段名无命名空间或命名空间未知 | `NoDot` `BadNs` | 2 | 是 |
| S04 | 枚举字段取值不在允许集合 | `BadEnum`（`submodule_copy`） | 1 | 是 |
| S05 | 布尔字段取值非布尔也非 `unknown` | `BadBool`（`maybe`） | 1 | 是 |
| S06 | 日期/提交号/CVE 号/地址形态不符 | `BadDate` `BadCommit` `BadCve` `BadUrl` | 4 | 是 |
| S07 | 同一依赖同一字段两个不同值 | `DupConflict` | 1 | 是 |
| S08 | 同一依赖同一字段重复同值 | `DupSame` | 1 | 否 |
| K01 | 出现 `key.*` 字段，或值形似密钥/描述文件 | `KeyField` `KeyInValue` | 2 | 是 |
| M01 | 无锁文件却按提交号装配（手工拷贝形态） | `CommitNoLock` | 1 | 是 |
| M02 | 分支/未钉住 + 自动解析开启 | `BranchAuto` | 1 | 是 |
| M02b | 分支型要求虽进锁文件但指针仍随远端移动 | `BranchLocked` | 1 | 是 |
| M03 | 锁文件存在但未提交 | `LockUncommitted` | 1 | 是 |
| M04 | 解析版本与要求版本对不上 | `VerMismatch` | 1 | 否 |
| M05 | 二进制形态未登记来源凭据 | `BinaryNoProv` 等 5 项 | 5 | 否 |
| M06 | 子模块/手工拷贝无 `origin_url` | `CommitNoLock` `SubNoOrigin` | 2 | 否 |
| M07 | 来源是镜像且未登记指纹 | `MirrorNoFp` | 1 | 否 |
| M07b | `origin_url` 走明文 `http:` | `PlainHttp` | 1 | 否 |
| M08 | `dep.kind` 未登记 | 55 个依赖 | 55 | 是 |
| M09 | `dep.requirement_kind` 未登记 | 57 个依赖 | 57 | 是 |
| G01 | 签名状态 `invalid`/`removed` | `SigInvalid` | 1 | 是 |
| G01b | 未签名 + 二进制形态 | `SigUnsignedBin` | 1 | 是 |
| G02 | 身份变更且原因未知 | `SigChangeUnknown` | 1 | 是 |
| G02b | 身份变更记为归属转移（需补新团队标识） | `SigOwnershipTransfer` | 1 | 否 |
| G03 | `team_id` 不是 10 位字母数字 | `ShortTeam` | 1 | 是 |
| G04 | 实际团队标识与预期不一致 | `SigTeamMismatch` | 1 | 是 |
| G05 | 记为可信但核验面 `none` | `SigNoSurface` | 1 | 否 |
| G05b | 既有报错文本又有可信状态 | `SigErrorSeen` | 1 | 是 |
| G06 | 签名身份过期或被吊销 | `SigExpired` | 1 | 是 |
| G07 | 二进制形态却记签名不适用 | `SigNAonBinary` | 1 | 是 |
| P01 | 在强制名单上且缺隐私清单 | `ListedNoManifest` | 1 | 是 |
| P02 | 名单+要求签名+二进制但未记签名状态 | `ListedSigNoState` | 1 | 否 |
| P03 | `manifest.on_required_list` 未登记 | 62 个依赖 | 62 | 否 |
| P04 | 看过聚合报告但版本来源未登记 | `AggregateNoSrc` | 1 | 否 |
| P05 | 名单名匹配已填但名单布尔未取布尔 | `NameMatchLoose` | 1 | 否 |
| V01 | 声称设备侧可见但无版本来源 | `DevVisibleNoSrc` | 1 | 是 |
| V02 | 按提交号装配却非 `exact` 置信度 | `CommitLooseConf` | 1 | 否 |
| V03 | `ver.version_confidence` 未登记 | 63 个依赖 | 63 | 否 |
| V04 | 组织可见性记否却填了 MDM 读数 | `OrgFalseMdm` | 1 | 否 |
| V05 | 声称组织可见但清单面 `none` | `OrgVisibleNoSurface` | 1 | 是 |
| C02 | 归属外部主体却声称 Apple 公告覆盖 | `AppleCovsProvider` | 1 | 是 |
| C03 | 在在野名单上但归属未定 | `KevUnassigned` | 1 | 是 |
| C04 | 修复版本未知却登记采纳状态 | `FixUnknownAdopted` | 1 | 否 |
| C04b | 记为已采纳但无实际上线版本读数 | `FixAdoptedNoShip` | 1 | 否 |
| C05 | CVE 有号但归属未登记 | `BadCve` 等 4 项 | 4 | 否 |
| C06 | 归属记为平台方但两侧公告都未登记 | `PlatformNoAdvisory` | 1 | 否 |
| C06b | 上游与提供方公告同在却归给提供方 | `ProviderAlsoUpstream` | 1 | 否 |
| R01 | 申请移除但无移除时间 | `RemNoDate` `RemClaimedNone` | 2 | 是 |
| R02 | 有残留却记可证消失 | `RemBinaryResid` | 1 | 是 |
| R02b | 有移除时间但仍有残留（替换未完成） | `RemLockResidAt` | 1 | 否 |
| R03 | 靠见证支撑却无见证类型 | `RemWitnessNone` | 1 | 是 |
| R03b | 声称已消失且证据形态 `none` | `RemClaimedNone` | 1 | 是 |
| R04 | 复核日早于移除日 | `RemRecheckEarly` | 1 | 是 |
| R05 | 移除后无替换也未写明不再需要 | `RemNoDate` `RemClaimedNone` | 2 | 否 |
| R06 | 可证消失但无复核日期 | `RemBinaryResid` 等 3 项 | 3 | 是 |
| R07 | 记不可证消失但未登记是否申请过 | `RemNeverAsked` | 1 | 否 |
| B01 | 自动解析开启却记可重现 | `ReproAuto` | 1 | 是 |
| B02 | 解析未钉住却记可重现 | `ReproAuto` 等 3 项 | 3 | 否 |
| B03 | 可重现且使用构建缓存 | `ReproCached` | 1 | 否 |
| B04 | 解析已钉住却记不可重现 | `ReproPinnedFalse` | 1 | 否 |
| J1 | 五门全过（两档：有/无消失结论） | `Alamofire` `PaymentCore` | 2 | 否 |
| J2 | 前门过但版本可观测不完整 | `J2Tier` | 1 | 否 |
| J3 | 来源或签名身份仍不确定 | `CommitNoLock` `J3Tier` | 2 | 是 |
| J4 | 起始四格不齐或阻断 ≥ 6 | 61 个依赖 | 61 | 是 |

表里三处值得复核的性质：

1. **`RemClaimedNone` 一个依赖命中 R01/R03b/R05/R06 四码**，说明台账里"声称消失但证据为 none"这一处写法会同时破坏时间、见证、替换、复核四项——第 11 章 RM-4 说的就是这个复合失败，脚本没有把它压成一条，因为四条各自的可修复动作不同。
2. **`M05`（二进制未登记来源凭据）与 `M08`/`M09` 不同层**：M05 非阻断而 M08/M09 阻断。理由是 M05 说的是一种登记习惯缺失（多数真实台账都有它），M08/M09 说的是判定起点不存在。若把 M05 升级为阻断，几乎所有二进制依赖都会落 J4，判定就失去区分力——这就是第 21.3 节把阻断定义成显式名单而不是"其余全部"的实际收益。
3. **判定行本身计入阻断**（J3、J4 在名单内，J1、J2 不在）。因此"阻断信号条数"随依赖数增长，不能当缺陷密度读；要读密度看 M/G/P/V 各族计数。第 21.4 节坏样本的 215 条阻断里有 63 条是 J3/J4 判定行。

### 23.3 脚本二：34 个信号码的覆盖表

"样本"列括号内标明该码在哪一次运行里被触发（坏＝三件缺陷，闭＝三件闭合，单＝单件运行，混＝混写模式）。条数是**脚本二六次运行的合并观测**（含三次单件与一次混写），因此会大于第 22.4 节坏样本单次的计数。

| 码 | 判据 | 样本 | 条数 | 阻断 |
| --- | --- | --- | --- | --- |
| W01 | 行不可解析：列数不足，或混写模式下无前缀 | 坏：`ShortRowA` `ShortRowP` `ShortDel`；混：`OrphanLine` | 4 | 是 |
| W02 | 三件任一行缺依赖标识 | 坏：`,BadRow,…` `,pb13,,…` `d41,,…` | 3 | 是 |
| W03 | 取值域/日期/需求值/解析版本任一不符 | `BadVocab` `BadRK` `BadLock` `BadDate` `BadRV` `BadResv` `BadBy` `BadSrcDep` `BadConfDep` `BadUuidDep` `BadBdDep` `BadAct` `BadRes` `BadWit` `BadEv` `BadRc` | 16 | 是 |
| W04 | 缺构建标识或台账序号 | 坏：`,pb12,NoBidDep,…` `,MissingRid,…` | 3 | 是 |
| X01 | 装配件登记、产物件无读数 | 坏 20 项 + 单（仅 `-A`）3 项 | 23 | 是 |
| X02 | 产物件或台账件引用了未登记标识 | `GhostDep` `GhostDepD` + 单（仅 `-P`、仅 `-D`）各 3 项 | 8 | 是 |
| X03 | 装配件登记、台账件无一条记录 | 坏 28 项 + 单（仅 `-A`）3 项 | 31 | 是 |
| X04 | 装配解析版本与产物读数版本不一致；或同一构建标识两个版本 | `VerMismatch` `SameBidTwo` | 3 | 是 |
| X05 | 同一依赖在装配件里重复登记 | `DupAdopt`（形态与需求都不同） | 1 | 是 |
| X06 | 台账序号重复 | `d4` `d26` | 2 | 是 |
| X07 | 同一构建标识对同一依赖登记多条读数来源 | `MultiSrc` | 1 | 是 |
| Y01 | 移除事件日早于集成日 | `Q3Tier` `DelBeforeAdopt` | 2 | 是 |
| Y02 | 复核完成早于移除 | `RecheckEarly` | 1 | 是 |
| Y03 | 有 `removed` 无 `removal_requested` | `DelBeforeAdopt` 等 7 项 | 7 | 是 |
| Y04 | 同类事件两条且同日（不可区分） | `SameDayTwin` | 1 | 是 |
| Y05 | 同类事件两条但不同日（结论要指明哪一条） | `DiffDayTwin` `DupSeq` | 2 | 是 |
| Y06 | 构建日早于集成日 | `EarlyBuild` `Q3Tier` | 2 | 是 |
| Z01 | 二进制形态的版本读数取自 lockfile | `Q2Tier` | 1 | 是 |
| Z02 | 分支/提交/未钉住且锁文件不在册 | `BranchNoLock` | 1 | 是 |
| Z03 | 产物元数据读数但未记 build UUID | `NoUuidMeta` | 1 | 是 |
| Z04 | `removed` 与自身残留列矛盾 | `ResBinary` `BadRes` | 2 | 是 |
| Z05 | 移除无可回指见证 | `NoWitness` | 1 | 是 |
| Z06 | 矛盾三形：锁定在册 vs unpinned、有移除无复核、复核日挂错动作 | `UnpinnedLocked` `DelBeforeAdopt` `RcOnWrongAct` 等 7 个依赖命中 8 条 | 8 | 是 |
| Z07 | 旁证读数面却给 `exact` | `CrashExact` `AscExact` | 2 | 是 |
| Z08 | 读数来源 `unknown` | `NoSrc` | 1 | 是 |
| Z09 | 手工放入且集成方 `unknown` | `HandCopied` `VendoredUnknown` | 2 | 是 |
| Z10 | 移除之后又见 `binary_present` | `BackAgain` | 1 | 是 |
| N01 | 装配件未提供 | 单（仅 `-P`、仅 `-D`） | 2 | 否 |
| N02 | 产物件未提供 | 单（仅 `-A`、仅 `-D`） | 2 | 否 |
| N03 | 台账件未提供 | 单（仅 `-A`、仅 `-P`） | 2 | 否 |
| Q1 | 三件闭合、时序成立、口径一致 | 闭 3 项；坏：`AdoptOnly`；混：`Networking` | 5 | 否 |
| Q2 | 集合闭合、时序成立，但版本或消失口径矛盾 | `Q2Tier` `ResBinary` `NoWitness` `RcOnWrongAct` `BackAgain` | 5 | 否 |
| Q3 | 集合闭合，但时间序不成立 | `Q3Tier` `RecheckEarly` `NoRequest` `SameDayTwin` `DiffDayTwin` `DupSeq` | 6 | 否 |
| Q4 | 三件不齐或行形态不可解析（含只有产物件/只有台账件的标识） | 坏 34 项 + `GhostDep` `GhostDepD` + 单 3 项 | 39 | 否 |

一处覆盖细节值得记下：`X01`、`X02`、`X03` 三个码在**单件运行**里也触发，且触发对象是好样本的三个依赖。也就是说同一份完全闭合的记录，只喂其中一件时全部变成差集缺口——这不是脚本在报错，而是差集比对的定义本身：**任何一件单独存在时，另外两件的缺失都是全量的**。第 22.1 节"每一件事的真相只存在于两个记录面之差里"在这一行数字上是最直接的证据。

### 23.4 口径覆盖缺口（G8 的展开）

覆盖验收说明"每个码都可达"，本节说明"哪些真实缺陷**没有码**"。两者合起来才是这两支脚本的能力边界；只写前者会让读者把"没报"读成"没问题"。

1. **`dep.integrated_by` 在脚本一里没有取值域校验。**脚本二的装配件第八列（集成方）按七值域校验（`BadBy` 触发 W03），脚本一只登记不校验——同一个事实两处口径强度不同。后果：脚本一的台账可以把集成方写成任意串而不被拒。修法是先统一词表（第 3.1 节），再给 `dep.integrated_by` 加 DOM 项；本轮没有加，是为了保持第 21 章冻结的信号码表与实跑结果一致。
2. **"是否二进制"在两支脚本里推导方式不同。**脚本一有独立字段 `dep.binary_form`（六个取值，含 `binary_static`/`binary_dynamic`），脚本二没有该列，改由装配方式四值推出（`xcframework`、`vendored_framework`、`static_library`、`dynamic_library`）。于是一个通过 git 子模块拉取预编译框架的依赖（`git_submodule` + `binary_framework`）在脚本一触发 M05，在脚本二**不触发 Z01**：同一依赖的"二进制性"两处可取不同值，而 Z01 正是 F3 那处换算失败的判据。
3. **跨事件的残留相容性没有码。**第 22.4 节 `BackAgain` 那处已说明：较晚的复核结论记 `none`、较早的产物在场记 `binary`，脚本不做这条比较。要判它需要"按依赖取时间序最后一条事件"的语义，本轮没有实现，也没有对应信号码，因此文档不能声称脚本能发现"复核结论与残留读数冲突"。
4. **F3 只能由脚本二判，而脚本二需要产物件。**脚本一的 `ver.*` 族只判登记完整性与冲突（V01—V05），没有"二进制 + lockfile 读数"这一条。这意味着**没有构建侧记录件的团队，机器上无法判出本文最重要的一处换算失败**，只能靠人工（第 16 章 R9—R11 三处读数的来源差别）。这是流程缺口而不是脚本缺陷，写在这里是为了不让读者以为补脚本能解决。
5. **签名身份的真实性不在能力范围内。**G03 只判形态，G04 只比两个登记值；脚本不调 `codesign`，因此不可能发现"登记的 Team ID 与实际嵌入签名不符"。第 6 章 BF-3（伪装成某框架的版本）在机器上是**不可判**的，只能由提供方陈述与核验面记录支撑。
6. **强制名单没有内置。**脚本一不抄那 86 个 SDK 名（P03 只判"这一格没填"），因为名单会随文档更新，抄进脚本等于给脚本加版本依赖。名单核对仍是一次人工对照（第 8.2 节的读数表就是为这件事准备的）。**"不在名单上"这句话只能由人工判定产生。**
7. **CVE 归属判据是本文口径，不是 Apple 口径。**C02—C06b 全部按第 10.4 节七条规则判，而那七条规则在 Apple 公开语料里没有对应句子（G5）。脚本能给它们"看起来像平台规则"的形式，读者不能据此反推 Apple 有这套规则。
8. **两套装配词表不换算。**脚本只接受 Xcode 的六种需求形态；CocoaPods 的 `:tag`/`:http`+`sha256` 记法要么被 W03/S04 拒收，要么由台账作者先换算（F2、F6）。脚本不提供换算函数，因为它一旦提供就是在发明一个 Apple 与 CocoaPods 都没有写过的映射。
9. **Q 分级不看 Z 族内部严重性。**`Z10`（结论已被推翻）与 `Z04`（一条记录内部矛盾）在 Q 级里同权，都落 Q2。第 22.4 节建议业务侧对 Z10 另做升级，但脚本本身没有分级权重表——加权重会改变 Q 的定义，属于口径变更，要先改文档。

### 23.5 退出码约定与接入方式

两支脚本共用同一套退出码语义：

| 退出码 | 含义 | 两支脚本的具体触发 |
| --- | --- | --- |
| 0 | 无阻断信号 | 脚本一：`HB` 名单内计数为 0；脚本二：W/X/Y/Z 计数为 0 |
| 1 | 有阻断信号 | 同上取反；**含 J3/J4 或任何 W/X/Y/Z 时必然为 1** |
| 2 | 用法错误或输入不可读 | 无参数、`-A/-P/-D` 之外的未知参数、文件不存在、`mktemp -d` 失败 |

接入方式三条：

1. **信号明细走 stderr、汇总走 stdout**，所以 `2> signals.tsv` 就能得到一张可直接进 diff 的表（三列 TAB 分隔）。周期任务里推荐把 `signals.tsv` 按 `(码, 依赖)` 排序后与上一周期比对，**看新增码种数而不是新增条数**——条数会被 M08/M09/P03/V03 这类分母效应主导（第 21.4 节第 1 点）。
2. **不要把退出码 1 直接当告警升级**。因为 J3/J4 计入阻断，任何一条登记不全的依赖都会让脚本一返回 1。可升级的判据是"某个具体码出现"（K01、G01、R02、Z10、X02 这几条形成本身唯一），或"J4 数量周环比上升"。第 20 章 O2、O8、O9 三个指标就是按这个思路设计的。
3. **顺序固定为先脚本一后脚本二**，且两支脚本读的是同一批事实的两种形制（三元组台账 vs 三件定长表）。若只有一份记录，先跑脚本一补格；若三件齐了但脚本二大量 Q4，先回查装配件与产物件的依赖标识拼写是否同源（大小写、`.git` 后缀、Pod 名与 target 名不一致都会变成假差集，全部表现为 X02/X01）。

关于写出目标：两支脚本都在开头 `mktemp -d` 建目录并 `trap` 删除，本轮实现里没有任何字节写入该目录（比对全部在 awk 内存中完成，输出只走 stdout/stderr）。保留它不是为了"以后要写"，而是为了让"唯一写出目标是临时目录"这条约束在后续扩展时不会被绕过——如果将来要落中间件，路径只能来自 `$TMPD`，而读者可以从脚本第 51—52 行（脚本一）与 62—63 行（脚本二）确认除它之外没有任何重定向目标。

---

## 24. 十二个误区

每条一句结论、一句文档依据、一句"照做会怎样"。**这里的 M 编号指误区，与脚本一里装配信号族 `M01—M09` 不是同一套编号**；正文引用会分别写作"误区 M3"与"信号 M03"。

**误区 M1 · 加了 Swift Package 就等于版本被钉住了。**
依据：《Adding package dependencies to your app》第 19 行的 Version requirement 是一个**区间**；《Building Swift packages or apps that use them in CI workflows》第 6 行与第 9 行才给出钉住的那一步——把 `Package.resolved` 提交进仓库，第 11 行补了 CI 侧的 `-disableAutomaticPackageResolution`。
照做的结果：仓库里只有一句 `from: "3.0.0"`，而团队以为锁住了。每次解析都可能取到新区间内的新版本，且 CI 与开发机可能取到不同的版本。对应信号 M02、M03、B01、B02；第 4.3 节的强度谱与第 13.2 节的三个杠杆是这条误区的正面写法。

**误区 M2 · 按 Commit 装配是最强锁定，所以不用管锁文件。**
依据：第 18—21 行给三种 package requirement，其中 Commit 一句是 "isn't recommended"，理由写在同一行："you don't receive any updates"；而钉住语义在文档里挂在 `Package.resolved` 上（spm-ci 第 6、9 行）。
照做的结果：提交号本身确实唯一，但它**不在锁文件里**（脚本一 M01 的判据就是"lock_present=false 却按提交号装配"），于是这台机器之外的任何人都只能靠工程文件里那行散文字知道装了什么。同时"不更新"意味着修复版本不会自动进来——第 10 章的修复归属因此更难。对应 M01、V02、DL-4。

**误区 M3 · 依赖带了隐私清单，就说明它的来源已经清楚了。**
依据：《Third-party SDK requirements》第 120 行讲清单的合并与上报，第 122 行讲签名校验，是同一页上的**两件**事；清单描述数据实践，签名描述代码身份。
照做的结果：台账里 `manifest.privacy_manifest_present=true` 却 `sig.state` 留空——第 08 篇的申报口径成立，本文的归属口径仍缺两格。第 8.4 节四行组合表的第三行与第四行分别就是这两种状态；对应信号 P02。

**误区 M4 · 在强制名单上的 SDK 等于被 Apple 审过来源的 SDK。**
依据：第 124 行的名单只要求"带隐私清单与签名"，同页第 125—210 行的 86 个名字里**没有任何一条**给出提供方身份、版本号或签名主体（Q3 的计数与形态见第 8.2 节）。
照做的结果：把名单当白名单，从而不登记 `sig.team_id_expected`——这一格空着时，脚本一只能给 G05（结论没有观测支撑）或 J3。名单能证明义务，不能证明归属；第 8.1 节末句就是这条。

**误区 M5 · Xcode 报 "not signed with the expected identity" 一定是被篡改。**
依据：《Verifying the origin of your XCFrameworks》第 13—14 行先给出合法变更理由（提供方把 SDK 所有权转给另一家组织、新版本用新组织的 Team ID 签名），第 16 行才给出非法解释（被篡改，或有人注入自己的代码并伪装成该框架的一个版本），第 21 行是报错原文。
照做的结果：两个方向都会错。直接接受变更等于放弃归属核对；直接判定投毒等于把文档承认的合法路径写成事故，进而做出错误的对外声明。判据只能来自台账与提供方陈述（G02 阻断、G02b 提示"记为归属转移时要同时登记新团队标识"）。**本文不提供任何让这条报错消失的做法。**

**误区 M6 · 签不上就自己签一个 / 改一下 entitlement 让它加载。**
依据：平台安全指南第 2353 行要求全部可执行代码由 Apple 签发证书签名；同页第 2362 行的链接规则按 team identifier 比对；XCFramework 文档第 24—27 行给出的处置是"与提供方确认后从可信来源重新获取"。
照做的结果：自签或借用其它证书会把该框架的签名主体变成**你自己**，于是第 118 行那句 "you are responsible for all the code the SDK includes in your app" 从一句本来就成立的责任声明，变成一份你在技术上亲手签署的承诺。本文不写这类做法的任何步骤；脚本一对 `invalid` / `removed` / `unsigned` 三种状态一律阻断（G01、G01b、G07），并在说明文本里把处置回指到文档口径。

**误区 M7 · 产物包里没有那个 framework 文件，就说明没用那个 SDK。**
依据：《Creating a static framework》第 5 行——Xcode 15 起嵌入式框架 bundle 内省略主二进制；《Configuring your project to use mergeable libraries》第 8、10 行——发布构建把依赖合并进目标，产物里不再有独立文件。
照做的结果：以"目录扫描"为唯一见证的消失结论会给出**假阳性**（其实代码在里面）与假阴性（合并后的产物里找不到文件）两个方向；第 11.2 节的两个形态陷阱与 `remove.witness_type=scan` 的局限（R03、R03b）就是为这条写的。

**误区 M8 · 崩溃日志或上架页面上的版本号，就是产物里编译进去的版本。**
依据：TN3178 第 7 行（UUID 把镜像连到 dSYM）与第 30 行（签名覆盖该 UUID）说明**回指需要 UUID**；《Identifying binary dependencies》第 16 行说明二进制依赖的 checksum 只在解析或更新时被比对。
照做的结果：把旁证当点读数，置信度写成 `exact`——脚本二 Z07；没有 UUID 的产物元数据读数写不成可交付结论（Z03）；来源干脆记 `unknown`（Z08）。第 9.2 节"四个来源各自能证明什么"是给这条误区准备的对照表。

**误区 M9 · SDK 的 CVE 该由 Apple 公告覆盖；Apple 没发公告就说明不影响我们。**
依据：三份并行版本线公告共 392 条 CVE 行，带开源上游语句的只有 1 条（`CVE-2019-5598`，见 `C/advisory-supply-readings.txt`）；CISA KEV 目录 1,766 条里 `vendorProject` 取 Apple 的 95 条；Apple 公告只覆盖 Apple 自己的软件。
照做的结果：正向误写是 C02（归属外部主体却声称 Apple 公告覆盖），反向误写是 C06（归属记为平台方但两侧公告都没登记）。更深一层：Apple 公开语料里没有任何一句讨论"app 内第三方代码的缺陷归属"（G5），所以任何归属写法都是**本方口径**，必须像第 10.4 节那样标明。

**误区 M10 · 提供方一句"我们已经不用那个库了"可以进我们的自证件。**
依据：第 118 行与《App Review Guidelines》第 127 行把义务主语固定为开发方，且都点名 ad networks / analytics services / 第三方 SDK；提供方陈述不改变义务归属。
照做的结果：`org.attestation_source=vendor_statement` 这类自证的判定上限在本文模型里被压到最低档（第 12.3 节）；把它当实证会让 O10（自证可用率）虚高，并在争议时无法回指任何可核对记录。

**误区 M11 · MDM 能看到设备上装的是哪个 SDK、哪个版本。**
依据：第 12.1 节四主体可见性表——管理面能看到的是设备、配置与 app 是否安装，看不到 app 内的依赖；第 17.2 节第一条明确写了"设备侧的某 app 内嵌 SDK 及版本清单"没有公开读数面。
照做的结果：`ver.org_visible=true` 配 `org.inventory_surface=mdm` 而无证据（V05/V04 两条形同自相矛盾的记法）。更糟的是用这种组合对外声称"我们已确认全部设备"，这是第 12 章 OV-2 那一格的失败形状。

**误区 M12 · "已移除"是一个动作，不是一段时间状态。**
依据：移除要证明的是"从某次构建起不再进产物，并且被复核过"——需要请求、产物在场、移除、复核四类事件与见证（第 11.3 节四种见证类型各自的局限）；复核早于移除在逻辑上不成立。
照做的结果：只有一次"移除时间"而没有复核日的结论无时效（R06）；后续又读到 `binary_present` 时结论已被自己的记录推翻（脚本二 Z10）；有 removed 无请求则事件序列不完整（Y03）。**"这个 SDK 已不在我们产品里"这句话的有效期等于最后一次复核日的时效。**

---

## 25. 常见问题

**Q1 · 这一层跟"设备有没有漏洞"有什么关系？**
没有直接关系。本文处理的是装配期与记录期的事实：这段代码怎么进的产品、谁签的、版本锁在哪一刻、漏洞记在谁头上、它还在不在。它的后果不是"多一个 CVE"，而是"一处我们无法说清归属的代码"或"一句无法回指证据的已移除声明"。第 02 篇管运行时权限，第 08 篇管申报，第 09 篇管补丁走到哪，第 11 篇管数据副本落在谁手上，**本篇管这段代码是谁的**。

**Q2 · 为什么不提供任何"验证签名真实性"的做法？**
按定义，验证签名真实性需要调用 `codesign` 或等价工具读产物。本文的两个脚本刻意不这样做，因为一旦引入"读别人产物"的能力，就会滑向第 2.4 节排除项里的两件事：**从他人产物中提取或反编译第三方代码**，以及把台账从"可公开核对的身份记录"变成"需要保护的机密材料"。替代做法是把签名写成**归属问题**：`sig.state`、`sig.team_id_expected`、`sig.verification_surface` 三格足以判定"这条结论有几分支撑"，而不需要任何人去重跑校验。

**Q3 · Team ID 能不能进台账？私钥或描述文件呢？**
Team ID 可以且应该——它是文档定义的身份串形态（指南第 2362 行："a 10-character alphanumeric string"），10 位字母数字，本身就是用于公开核对的标识；形态不符会触发 G03。**私钥、证书私钥材料、`.p12`、`.mobileprovision` 内容一律不可**：出现即 K01 并要求删除该字段（第 2.4 节立场）。脚本也拒绝值里形似这些内容的写法，而不只看字段名。

**Q4 · 一个依赖最少要记哪几格才不算空白？**
判定起点四格：`dep.kind`、`dep.requirement_kind`、`dep.binary_form`、`dep.lock_present`。这四格不齐就是 J4（第 19.1 节的 `have` 门）——J4 的含义是"我们只观察到装了这个依赖"，其余全部不可判。要走到 J1，还需要来源三格、签名三格、版本三格，以及一整组 `remove.*`。

**Q5 · 版本可观测性四条来源，我该用哪一条？**
按"能否回指到这一次构建的那份镜像"排序：产物元数据 + build UUID > 锁文件（仅对源码依赖等价）> 崩溃日志符号 > App Store Connect 显示值。前三条分别对应 Z03、Z01、Z07 三处判据；**第 9.2 节表里的"能证明/不能证明"两列就是选来源时该看的东西**。

**Q6 · Apple 有没有规定第三方 SDK 的 CVE 归属？**
没有。本轮全库检索的结论是零句（G5）。三方公告只覆盖 Apple 自己的软件，KEV 只覆盖在野利用条目。第 10.4 节那七条是本文给出的登记规则，并在正文里明确标注为非 Apple 口径——读者引用时应写"本文口径"，不应写成"Apple 要求"。

**Q7 · 强制名单那 86 个 SDK 名，能不能直接抄进脚本自动判？**
不建议，本文没这样做。名单会随文档更新（同一页第 124 行还写着"Any version of a listed SDK, as well as any SDKs that repackage those on the list, are included in the requirement"，重打包形态也算在名单义务内），把名单抄进脚本等于给脚本加了一个版本依赖，而名单核对的正确产物是一份带抓取日与行号的对照表（本文是 `C/sdk-required-list.tsv`）。P03 因此只判"这一格没填"，不判"该不该填"。

**Q8 · 两个脚本的结论能互换吗？J 级和 Q 级什么关系？**
不能互换。J 级看单条记录能否支撑一句归属表述（自洽性），Q 级看三件记录能否闭合（连通性）。第 22.5 节给了四种组合的读法，其中 **J1 + Q4 是最需要警惕的一格**：台账内部完全自洽，但它在产物件或台账件里没有对应记录——这条记录可能描述的是一个不存在的装配。

**Q9 · 没有 CI、没有归档、只有一台 Mac 的小团队，本文还有什么可用？**
可用的是子集：脚本一（只要一份三元组台账，不需要产物件）+ 脚本二的"仅装配件"用法。此时判定上限是 J2 与 Q4，但**登记动作本身已经改变了局面**：从"没人知道装了什么"变成"知道装了什么、但无法证明产物侧事实"。第 20 章 O1、O2 两个指标在这种条件下仍可周度执行；Z01/Z07/Z03 这些跨件判据要等构建记录建立后才可达（第 23.4 节第 4 条）。

**Q10 · 与 Android 系列第 16 篇（Mainline / APEX 模块归属）是不是重复？**
不是，方向相反。Android 第 16 篇是**平台下推**：谁把模块装进设备、模块缺陷记在 Google 还是 OEM。本文是**应用上引**：谁把代码装进 app、app 内缺陷记在开发方还是 SDK 提供方。共用的只有方法骨架（差集比对、四级判定、归属矩阵），客体、责任主体与公开口径来源完全不同；2.3 节把这条分工线写成了正文。

**Q11 · 本文有没有给出"这个 SDK 安全吗"的答案？**
没有，也不给。全文没有任何针对具体应用、具体 SDK 或具体提供方的评价、攻击动作或风险结论。第 8.2 节列出的 86 个名字是**名单事实**（哪些 SDK 落在义务范围内），不是评级；第 10.6 节列出的 CVE 行是公告面的覆盖读数，不是漏洞分析。任何把本文当选型依据的用法都超出了它的范围。

**Q12 · 我怎么复核本文的引用？**
所有引用落在 `.srcx12/` 存档件上，索引件 `IDX/files.tsv`（102 条）带路径、行数、sha256、抓取时刻与源 URL，`IDX/titlemap.tsv`（48 行）给出《标题》到文件名的映射。第 2.5 节列出七类可容忍的转录差异（PDF 转文本吞掉的连字符、`ASIDE(...)` 扁平写法、原文自带的 `[XCFramework name]` 占位符等）；读者重取时若行号变化，应以自己那一版为准。

---

## 26. 未公开文档化边界清单

八条，按"缺的是哪一句"写。**这一章是本文唯一允许出现"文档未展开"的地方**；正文其它各处（含 2.5 节就地注明的五条）凡遇到未展开，都指回这里的编号。G1—G5 与 2.5 节的缺口 A—E 一一对应，编号换一套是因为本章还要收进三条不属于"语料没取回"的边界：G6、G7 是**公开口径自身的结构缺席**，G8 是**本文没有给字段位、也没给信号码的一组事实**。

**G1 · SBOM 这个词在 Apple 公开语料里不存在。**（缺口 A）
本轮全库检索 `SBOM`、`CycloneDX`、`SPDX`、`SLSA` 四个词，在 A 组 36 件开发者文档与 4,885 行平台安全指南内**命中为零**；命中的只有开放标准组织自己的页面（`B/pages/cyclonedx-sbom.txt`、`spdx-specs.txt`、`slsa-provenance.txt`），全部为非 Apple 文档。
影响：本文凡涉及"软件物料清单"的表述只能写成组织侧自证（第 13 章），不能写成平台口径；指标 O10 的分母因此由 `org.attestation_source` 是否为空决定，而不是由任何平台读数决定。
台账做法：把清单登记为**集成方出具的产物**（自证件编号 + 出具方 + 出具日），不要写"平台已生成依赖清单"——这句话本文无法背书，而且它会把读者的注意力从"谁能核验"移到"谁该提供"上。

**G2 · `swift package` 命令级机读输出件本轮未取回。**（缺口 B）
SPM 侧本文只持有两句文档事实：`Package.resolved` 要提交进仓库（CI 文档第 6、9 行）与 CI 侧 `-disableAutomaticPackageResolution`（同页第 11 行）。`swift package resolve`、`swift package show-dependencies` 一类命令的输出格式本轮没有存档件。
影响：第 4、5 章不写任何命令输出形态，两支脚本也没有任何"命令输出"输入面。凡想用命令返回替代锁文件记录的写法，都不在本文口径内；`dep.lock_present` 与 `dep.lock_committed` 两格的证据出处是**仓库状态**，不是命令退出码。

**G3 · App Store Connect 校验不通过时开发者拿到什么读数。**（缺口 C）
《Third-party SDK requirements》第 122 行只说 "Xcode will validate that it was signed by the same developer"（校验发生在采纳期的 Xcode）；《Using the latest code signature format》第 8 行只说分发期 "App Store Connect first verifies your signature, and then re-signs the app using an Apple identity"。**两处都没有给出"不通过时开发者看到什么"**。
影响：这条是第 08 篇 12.3 节缺口的延伸——名单部分已由本文关闭（86 条名单已存档并计数），校验失败读数部分本文同样未关闭。因此 `manifest.*` 与 `sig.*` 两族能判"该不该做"，不能判"平台拒了什么"；O5 只统计义务闭合率，不统计提交结果，这个差别必须随指标一起交付。

**G4 · `Podfile.lock` 各段字段语义件未取回。**（缺口 D）
CocoaPods 侧本轮只取回 Podspec Syntax Reference（`spec.source` 四种仓库形态在第 212—215 行，`vendored_frameworks` 在第 528 行）；`Podfile.lock` 内部各段的字段语义没有存档件。
影响：第 4 章只写"锁定文件的存在性与提交状态"这一层，不解释锁文件内部字段。对 CocoaPods 通道而言，`dep.resolved_version` 的读数出处是集成方自己的解读，本文不给字段级口径。后果之一：F2 那处换算失败在 CocoaPods 侧**只能用拒收表达**（W03、S04），不能用折算表达——折算需要一份本文没有的语义件。

**G5 · app 内第三方代码的 CVE 归属：Apple 语料零句（本文主缺口）。**（缺口 E）
三条并行版本线公告共 392 条 CVE 行，每条的 vendor 均为 Apple，带开源上游语句的只有 1 条（`CVE-2019-5598`）；CISA KEV `catalogVersion=2026.10.30` 共 1,766 条，`vendorProject` 取 Apple 的 95 条。**两个口径都不讨论"这段代码在谁的产物里"**（R14—R16）。
影响：这是全文唯一一处公开口径完全缺席的层次。第 10.4 节七条登记规则是本文口径，其中六条只有 Apple 文档的**间接**依据（义务句、repackage 句、身份句、清单聚合句），第 7 条纯属登记卫生。脚本一的 C02—C06b 看起来像平台规则，但它们不是（第 23.4 节第 7 条）；引用时必须写"本文口径"，不能写"Apple 要求"。
处置：把这条缺席写成结论而不是遗憾。**"Apple 没有规定 app 内第三方代码的缺陷归属"本身就是一句可对外交付的话**，但它的前半句（因此本文给了一套自标口径的规则）必须紧跟其后，否则读者会把缺席读成许可。

**G6 · "library validation" 这个名字与"可关闭"的口径只存在于 macOS 语境。**
`library validation` 在平台安全指南 4,885 行内大小写不敏感命中为零（R8）；iOS 侧同一行为由第 2362 行以 team identifier 链接规则**实质描述**但没有这个名字。可关闭它的那条 entitlement（《Hardened Runtime》第 16 行 "Disable Library Validation Entitlement — A Boolean value that indicates whether the app loads arbitrary plug-ins or frameworks, without requiring code signing."）连同公证文档第 34 行对第三方设备扩展的讨论，都属 macOS 目标能力。
影响：本文**不推断**"iOS 上等价物不可关闭"，只记录"iOS 侧公开语料没有给出可关闭的口径"（7.2 节第 2 条）。因此这条边界不落任何信号码：脚本不能因为台账写了"已禁用库校验"就判它对或错，那一格在 iOS 语境里没有可比对象。
用法约束：凡引用"库校验"作为 iOS 平台行为的句子，一律改写成"第 2362 行所描述的 team identifier 链接规则"；把 macOS 的 entitlement 当作 iOS 可声明的豁免，是第 7.4 节明确排除的用法。

**G7 · 重打包关系被义务承认，却没有任何判别读数。**
名单条款第 124 行写着 "Any version of a listed SDK, as well as any SDKs that repackage those on the list, are included in the requirement"——平台在**义务**层面承认封装关系。但本轮语料没有任何一句给出"如何从产物判断某个框架是重打包件"的读数：签名口径只给签名主体（Team ID、证书），而重打包者的签名主体就是它自己。
影响：`sig.change_reason=repackaged`、`cve.attribution=shared` 与 C06b 那条"提供方只是搬运者时应改写 upstream"，都只能由**提供方陈述 + 集成方登记**支撑，机器不可判。这也是第 03 篇威胁表那一行"缓解手段 SBOM + 依赖审计 + 签名验证"最容易被误读的地方：**签名核验查不出封装**，能查封装的只有清单与陈述。
台账做法：重打包关系单独成格，并在台账外保存提供方原话的出处（页名 + 抓取日）。本文不把它写成核验结论，也不写成"已排除"。

**G8 · 本文档口径里没有字段位、也没有信号码的一组事实。**
九条逐列在第 23.4 节，按缺席性质归并为三类：

1. **两处词表强度不齐**：`dep.integrated_by` 只有脚本二校验取值域（脚本一只登记）；"是否二进制"脚本一用 `dep.binary_form` 六值、脚本二由装配方式四值推出。同一事实在两种形制里可信度不同，`Z01` 的可达集合因此不等于 `M05` 的可达集合。
2. **需要跨事件、跨记录语义的比较没有实现**：较晚复核记 `none` 与较早 `binary_present` 的相容性（22.4 节 `BackAgain`）、Q 分级对 Z 族内部严重性的加权（`Z10` 与 `Z04` 同权）。这两类都需要"按依赖取时序末条"或"判据带权重"的语义，实现它们等于改 Q 级的定义——属于口径变更，要先改文档再改脚本。
3. **能力边界**：签名身份的真实性（G03 只判形态、G04 只比两个登记值，脚本不调 `codesign`）、强制名单内容（P03 只判"这一格没填"）、CVE 归属判据的依据（G5 的镜像）、F3 只在脚本二可达（需要产物件）。

这一条与 G1—G7 分开写，是因为前者需要 Apple 补文档，后者需要**我们补字段定义或承认不可得**；混在一起会让读者以为脚本"漏检"，实际是那些格子没有读数，或者有读数但没有可比对象。

### 26.1 三条处置原则

1. **G1—G7 只允许以"补采集要求"的形式出现在流程里，不允许以"检查项"的形式出现在脚本里**——它们没有可读的输入。脚本里出现的每一条判断都必须能回指本文某一处已核验文本；不能回指的判据一律删除，而不是降级标注为"建议"。这条纪律也是第 21 章码表与第 23 章覆盖表必须同时存在的原因：表里的每个码都要有实跑记录，不允许"先写着以后再说"的码。
2. **G8 允许扩展，但有顺序**：若下一轮要补字段（例如给脚本一加 `dep.integrated_by` 的取值域、或给两支脚本补一份统一的"二进制性"换算），应先更新第 3.1 节字段表与本条分界，再动脚本，并重跑第 23.1 节那八次实跑。**不给脚本加没有文档依据的字段**，也不给已有字段换口径——判据一换，上一周期的信号计数就不再可比，而第 20 章 O9 的全部用法恰好建立在"只用于跨周期比较"这个前提上。
3. **G5 与 G3 共同决定本文的结论上限**：任何"某 SDK 的缺陷归提供方"的声明，都同时缺公开归属口径（G5）与平台核验读数（G3），所以它只能以"本文口径 + 提供方陈述"双要件出现，永远不能升为实证。第 19 章把 J1 拆成两档、并把消失结论单独占一格，就是为了让这类上限在等级里可见，而不是靠行文谨慎。

---

## 27. 结论

本篇写了三件事：**这段代码是谁的、这一台上跑的是哪一版、以及"它已经不在了"这句话要怎么写才成立**。三件事共用一张台账，但分属四个主语，这是全部困难的来源。

**第一，这一层的缺陷绝大多数是记录缺陷，不是实现缺陷。**十层拆完，能在公开文档里找到"实现与此处口径不符"的点是零个；能找到"公开口径彼此换算失败"的点是七个（F1—F7），其中四处（F1、F2、F3、F6）可由公开文档直接判"不成立"，三处（F4、F5、F7）只能判"公开口径不足"。**这个 4:3 的分布就是本文把 J3 设为常态而不是例外的原因**：供应链上多数问题不是"你没做对"，而是"平台没有给你可以核对的口径"。因此第 14 章的 P1—P12 不是漏洞类型，而是十二种可复现的记错方式；第 24 章的十二条误区也不是态度问题，每一条都对应一处文档里并排存在、却不能互相替换的句子。

**第二，没有任何一个主体能独立闭合全链，而最需要别人的那两格恰好是自己的。**第 15 章的矩阵：集成方能闭合六层（L1、L2、L3、L6、L8、L10），提供方两层（L3 的签名主体、L7 的修复版本一侧），上游一层（缺陷定义），平台两层（L4、L5）；四方里没有一方能给出"这个 app 的依赖全集"。第 15.2 节又压上一层更硬的限制：本地路径 XCFramework 在文档层面就没有 checksum，可合并库让"产物里没这个文件"这件事失去证据价值——**这两处不是记录不当，而是装配形态决定的证据上限**。所以本篇对"这段代码是谁的"的回答必须由三格合起来给（`sig.state`、`sig.team_id_expected`、`sig.verification_surface`），而不是由签名本身给：签名只说明谁签了它，不说明它是谁的、从哪条通道来的、你从哪一刻起该重新核它。

**第三，义务句不是归属句。**两句 "you are responsible"（SDK requirements 第 118 行、审核指南第 127 行）加一句 repackage（第 124 行）是 Apple 语料里离"归属"最近的三句，合起来仍不构成任何归属规则：它们说的是**结果由谁承担**，不是**这条记录挂在谁头上**。本文把这一区分写成一句可执行的话——**义务决定谁去修，归属决定这条记录挂在哪个标识上**——并把它的缺席（G5）作为结论而不是遗憾交付。同一逻辑也适用于消失：第 124 行承认封装，所以"我们用的不是原版"这句推不出"义务不在我们"；台账里把义务与归属同时填成 `app_dev`（第 10 章 CV-8）与把提供方陈述当实证（误区 M10）是同一处失败的两种写法。

**第四，两个脚本的作用是把上面三条变成可周期执行的动作。**98 个信号码（脚本一 64 个、脚本二 34 个），全部由公开文本推导，离线、只读、不碰设备、不调用任何 Apple 命令行工具。第 23 章给出这 98 个码的可达性证据：八次实跑，坏样本逐一触发，好样本退出码 0 且不产出任何阻断信号；**不能触发的信号等于没有写过**。两支脚本的分工也构成本篇的方法结论——脚本一防漏记（一格填没填），脚本二防互斥（三件说没说同一件事），只做前者会得到一份自洽但可能描述着不存在的装配的台账（J1 + Q4），只做后者会得到一份闭合却无人负责补格的记录（Q1 + J4）。

最后留三句限制。其一，本篇所有结论成立于第 16 章 R1 起固定的那份版本快照：平台安全指南 4,885 行 / 697,288 字节 / md5 `d106784191540ae19729ac4aeea7e602`，A 组 36 件开发者文档于 2026-11-01 取回，名单件 `B/pages/sdk-requirements.txt` 312 行，三份 CSAF 与 KEV 目录 `catalogVersion=2026.10.30`。指南换版会移动行号，名单更新会改变 86 这个数——**这两类都是口径变更事件，必须与任何趋势断点记在同一天**，否则下一轮读到 O5 或 O9 跳变时会把它读成质量变化（第 20 章 O9 只用于跨周期比较，前提正是口径未变）。其二，本文没有任何针对具体应用、具体 SDK 或具体提供方的评价与攻击动作：第 8.2 节的 86 个名字是名单事实，第 10.6 节的 CVE 行是公告面覆盖读数，都不是评级，也不能当选型依据。其三，本文不提供任何让签名校验报错消失、伪造或替换身份、绕过名单的做法；遇到这类需求时，第 6 章与第 7 章给出的唯一处置是文档自己的那句——**与提供方确认后从可信来源重新取得**。

---

## 28. 参考资料

本轮存档：`.srcx12/`（取回日期 2026-11-01，六组共 102 个文件）。索引件 `.srcx12/IDX/files.tsv`（102 条：组别、形制、路径、字节、行数、sha256、mtime、源 URL、抓取时刻），`.srcx12/IDX/titlemap.tsv`（48 行：《文档标题》→ 文件名），汇总件 `.srcx12/MANIFEST.txt`。全部为公开文档，离线取回；本轮未访问任何设备、未调用任何设备侧或 Apple 命令行工具、未提交任何构建。

### Apple 开发者文档与 Tech Notes（A 组：转文本件 36 个 / 333,632 字节；对应原始 JSON 35 个 / 941,842 字节）

1. **依赖声明与解析**：*Adding package dependencies to your app*（75 行；第 18—21 行三种 package requirement，Commit 同页标 "isn't recommended"）、*Building Swift packages or apps that use them in continuous integration workflows*（22 行；第 6、9 行提交 `Package.resolved`，第 11 行 `-disableAutomaticPackageResolution`）、*Organizing your code with local packages*（20 行）、*Editing a package dependency as a local package*（16 行）、*Publishing a Swift package with Xcode*（27 行）、*Creating a standalone Swift package with Xcode*（153 行）、`PackageDescription.Package` API 件（77 行）。
2. **二进制形态与来源核验**：*Verifying the origin of your XCFrameworks*（43 行；第 5 行 origin 声明、第 13—16 行合法与非法两种并列解释、第 21 行报错原文含 "may have been"、第 24—27 行处置）、*Creating a multi-platform binary framework bundle*（67 行）、*Creating a static framework*（49 行；第 5 行 Xcode 15 起嵌入式 bundle 内省略主二进制）、*Configuring your project to use mergeable libraries*（53 行；第 8、10 行合并动作与 "slightly larger"）、*Distributing binary frameworks as Swift packages*（61 行；第 16 行本地路径不生成 checksum）、*Identifying binary dependencies*（19 行；第 16 行 checksum 的比对时机）。
3. **构建与产物**：*Understanding build product layout changes*（29 行）、*Embedding nonstandard code structures in a bundle*（157 行；第 12 行 `Referenced Binaries`）、*Identifying and addressing framework module issues*（40 行）、*Running custom scripts during a build*（56 行）、*Adding a build configuration file to your project*（90 行）、*Projects and workspaces*（21 行）、*Command line tools*（19 行）、*Xcode 26 release notes*（486 行）。
4. **签名、分发与技术说明**：*Using the latest code signature format*（43 行；第 8 行 ASC 先验签再以 Apple 身份重签、第 9 行其它通道由 Xcode 与 `codesign` 生成签名；该行原文拼写异常 "DER embeddded entitlements" 已在 2.5 节注明并原样保留）、*Sharing your team's signing certificates*（47 行）、*Preparing your app for distribution*（73 行）、*Distributing your app for beta testing and releases*（81 行）、TN3178 *Checking for and resolving build UUID problems*（58 行；第 7 行 UUID 连接镜像与 dSYM、第 30 行签名覆盖该 UUID、第 33 行无 UUID 时符号化不成立）、TN3181 *Debugging Invalid Privacy Manifests*（68 行）、TN3126 *Inside Code Signing Hashes*（270 行）、TN3127 *Inside Code Signing Requirements*（200 行）、TN3125 *Inside Code Signing Provisioning Profiles*（207 行）、TN3161 *Inside Code Signing Certificates*（277 行）。
5. **macOS 侧对照件（本文只用于说明名字与语境，不作为 iOS 供应链证据，见 7.4 与 G6）**：*Hardened Runtime*（26 行；第 8 行 entitlements 由宿主执行文件继承给 shared libraries / frameworks / in-process plug-ins，第 16 行 Disable Library Validation Entitlement）、*Notarizing macOS software before distribution*（65 行；第 5 行 "Notarization of macOS software is not App Review"、第 34 行 PDE 与 entitlement 的版本关系）、*Complying with encryption export regulations*（17 行）、*DeviceCheck*（24 行）。

### 平台安全指南与申报语料（B 组）

6. Apple, *Platform Security Guide*（`B/apple-platform-security-guide.txt`，4,885 行 / 697,288 字节 / md5 `d106784191540ae19729ac4aeea7e602`；`pdftotext -enc UTF-8` 转文本件，与第 08、09、10、11 篇同一版本，行号可直接互参）。本篇引用的关键段落：强制代码签名（第 2351—2353 行）、可嵌入以 Apple 签发证书验证的代码（第 2360 行）、team identifier 链接规则与 "10-character alphanumeric string"（第 2362 行）、App Review 语境（第 2388 行）。`library validation` 在该件内命中为零（R8）；证据件是派生的 `C/guide-supply-map.txt`（32 行）与 `C/guide-supply-hits.tsv`（367 行，按用词逐行给出命中位置）。
7. Apple, *Third-party SDK requirements*（`B/pages/sdk-requirements.txt`，312 行）。四句引文分别在第 118 行（责任句）、第 120 行（清单合并与上报）、第 122 行（"Xcode will validate that it was signed by the same developer"）、第 124 行（义务范围与 repackage 条款），第 125—210 行是 86 条名单。**这一件同时关闭了第 08 篇缺口 C 的名单部分**：该篇当年只取回 JS 壳页，本轮取回正文。派生件 `C/sdk-required-list.tsv`（87 行 = 表头 + 86 名 + 行号）与 `C/sdk-required-readings.txt`（28 行：条数、跨度、首 token 统计）。
8. Apple, *App Review Guidelines*（593 行；第 127 行的责任与第三方服务句）；*Apple security releases* 索引（1,121 行，与第 10 篇同一取回件，用于定位三份并行版本线公告编号）。

### 非 Apple 文档（B 组 `pages/`，正文引用时一律标注为外部口径）

9. CocoaPods, *Podspec Syntax Reference*（788 行；第 203—215 行 `spec.source` 的 `:git`/`:svn`/`:hg`/`:http` 四形态与 `:sha256`/`:sha1`，第 528 行 `vendored_frameworks`）。Swift Package Manager, *README*（52 行）与 *Package Registry Usage*（500 行）。
10. CycloneDX *SBOM*（90 行）、SPDX *Specifications*（118 行）、SLSA *Provenance* 规范（557 行）三件**只用于证明 G1**：`SBOM`、`CycloneDX`、`SPDX`、`SLSA` 这四个词只存在于开放标准组织自己的页面里，Apple 语料内没有对应文档。

### 公告与在野利用口径（C 组）

11. 三条并行版本线 CSAF：`B/149041.json`（5,649 行 / md5 `ffb3584635686fe880c513e2c2212f32`）、`B/149227.json`（7,887 行 / md5 `7664ad6b8f1a29f1634c3484033a1abb`）、`B/149230.json`（9,587 行 / md5 `ed621092fc484c8dd64edd5958756f88`）；三件均为 `.srcx11` 同名件的逐字节副本，CVE 行数 95 / 134 / 163，合计 392（R14）。派生件：`C/advisory-supply-readings.txt`（18 行，含 R14—R16 的计数出处）、`C/advisory-supply-hits.tsv`（2 行，供应链用词命中矩阵）、`C/advisory-component-titles.tsv`（102 行，组件标题去重表）、`C/advisory-upstream-titles.txt`（49 行，其中 22 项判读为外树组件——**该归属为读者判断，件内自带这句说明**，正文引用时同样带着它）。
12. CISA, *Known Exploited Vulnerabilities Catalog*（`C/kev.json`，28,040 行 / 1,826,755 字节 / sha256 `3aa9cf3c01f116362a29d111702979175453c425e3733bde80fc4f6f8e2294e5`；`catalogVersion=2026.10.30`，count 1,766，与 `.srcx11/C/kev.json` md5 相同）。派生件 `C/kev-attribution.tsv`（124 行：`vendorProject` 去重 291 项与 Apple 的 95 条行）。

### 本轮产物

13. 脚本一 `.x12-s1.sh`（266 行，64 个信号码）：第三方依赖装配与来源台账审查器，输入一份或多份三元组台账，输出逐条信号码与 J1—J4 四级判定。脚本二 `.x12-s2.sh`（277 行，34 个信号码）：装配件 / 产物件 / 移除台账件三件差集与消失结论比对器，输出 W/X/Y/Z/N 族信号与 Q1—Q4 闭合等级。两支脚本全文分别见第 21.5 节末与第 22.5 节末的 `bash` 代码块；两者都不联网、不访问设备、不修改输入文件，唯一写出目标是 `mktemp -d` 创建的临时目录（本轮实现中该目录未被写入任何字节）。
14. 存档生成件（只读处理公开存档文本，均为本轮自写）：`.x12-fetch.sh`、`.x12-fetchweb.sh`、`.x12-flat.pl`、`.x12-html2txt.pl`、`.x12-titles.pl`、`.x12-csafmap.pl`、`.x12-guidemap.pl`、`.x12-sdklist.pl`、`.x12-titlemap.pl`、`.x12-manifest.pl`。
15. 样例输入与实跑输出：`fx/good.tsv`（72 行，2 个依赖，退出码 0，输出仅 `J1=2`）、`fx/bad.tsv`（139 行 = 128 条记录 / 64 个依赖标识，215 条阻断信号，63 个码 + 好样本的 J1 合计 64 个码全部可达）；`fx2/a_good.csv` + `p_good.csv` + `d_good.csv`（各 3 个依赖，全部 Q1，退出码 0）、`a_bad.csv`（49 行）+ `p_bad.csv`（33 行）+ `d_bad.csv`（44 行）（117 条阻断、31 个码）、`merged.csv`（6 行，混写模式验证 `MERGED=1` 分支，输出 W01 与一条 Q1）。八次实跑的命令、退出码与逐码覆盖表见第 21.4、22.4 与第 23 章。

### 同系列相邻篇目

16. 第 02 篇（访问控制与数据保护类）——本篇只在 7.2 节借它一句"entitlement 由宿主继承"的供应链含义，进程权限对象归该篇。第 03 篇（应用防护与抓包审计）——其威胁表里"供应链攻击：通过第三方 SDK/库植入后门"一行是本文的题名级来源，本文把它展开成十层判定，并在 G7 处指出该行三项缓解手段各自查不出什么。第 08 篇（隐私授权链路与用途声明）——清单内容、required reason 档位、Aggregate 报告与审核签字全部归它；本文只取名单的**读数性质**（第 8 章），分工线见 2.2 节三条硬线。第 09 篇（更新链与补丁传导）——管补丁走到哪，本文管这段代码是谁的；接缝在 P10（"上游修了"与"我们带着修好的版本"与"已采纳"三格混同）。第 10 篇（设备生命周期与归属迁移）——管设备属于谁、托管凭据何时作废；该篇第 16 章 R15 把"AirPlay SDK"当成一条公告行读数来读，那个客体在本文口径下是提供方 SDK 而非设备能力，一句话分工见 2.3 节。第 11 篇（备份与恢复链路数据副本归属）——方法形似（三件差集 + 四级判定 + 只读脚本），客体相反：那边是数据副本在谁手上、可不可解，这边是代码在谁的产物里、还在不在。第 13 篇（日志、诊断与崩溃证据链归属）——本文第 6 章给出的 build UUID 与 dSYM 归属口径被它作为符号化前提直接引用（其第 9 章 L6 层），它接着问的是"这份报告此刻符号化到哪一档、能不能作对外表述的依据"；那条链上的日志级别、留存、采集通道与同意口径全部由它负责，本文不重述。第 14 篇（签名与分发授权链归属）——本文第 4—5 章的签发侧前提（证书从哪来、私钥在哪、身份能不能导出同步）直接借用它的签名与构建口径；它反过来管"这段代码凭什么被允许运行、授权什么时候失效"，本篇管"这段代码怎么进到产物里、它的缺陷算在谁头上"。两篇的交接点是签名身份，分界是主体：本篇问代码来源，它问运行授权。

---

咨询ios系统请咨询 telegram：https://t.me/one00190
