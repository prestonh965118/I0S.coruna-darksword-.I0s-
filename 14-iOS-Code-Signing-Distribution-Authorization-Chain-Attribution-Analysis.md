---
title: "iOS 签名与分发授权链归属防御分析报告"
description: "iOS 上一段代码到底凭什么被允许运行、这份授权什么时候失效、失效之后谁能证明：十一条授权链层（身份、签发、形态、范围、权利、时效、失效与校验、观测平面、通道差异、复核处置、公告回查）的逐层分解，九通道 × 22 要素的可得性矩阵、两个到期日与两种时间戳、描述文件三格回读与签名身份不可回读、DER 形态与槽位 -5/-7、J1—J4 与 Q1—Q4 两套判定模型和两个离线只读核验脚本（信号码 64 + 44，共 108 个全部实跑触发，30 次实跑逐码覆盖表）"
lang: zh-CN
---

# iOS 签名与分发授权链归属防御分析报告

## 摘要

本报告集前十三篇回答过三类归属问题：**缺陷在哪**（第 01、06、07、12 篇的攻击面归属）、**这台设备归谁**（第 08、10、11 篇的主体归属）、**这条记录能不能作证**（第 13 篇的证据链归属）。本文回答第四类，也是前十三篇反复引用、却从未正面拆解的那一类：**这段代码凭什么被允许运行、这份授权是谁给的、它什么时候不算了、不算之后谁能证明。**

这件事在工程界看起来是一句话——"我们的包是签过名的"。在 Apple 的公开文档里，它被拆成十一条各自有主语的链：谁签（签名身份与私钥 custody）、谁发（签发路径与证书链）、签的是什么（App ID 形态与 DER 形态）、发到哪（设备清单或全设备声明）、给了什么权利（描述文件白名单与声明的权利）、什么时候到期（两个到期日与两种时间戳）、什么时候失效（校验、吊销、首次启动确认）、这一格是谁读回来的（观测平面）、不同通道到底要不要这一格（可得性）、撤销之后做了什么（处置）、这个缺陷对应哪个公告（回查）。十一条链各有官方口径，而且**没有任何一条官方文档把它们串成一条链**。本文第 3 章给出这三套互不对接的词表和八处直接换算失败，其中四处可以在公开文档之间对出来：

**"签名校验通过了，所以这段代码能跑"**——《TN3161: Inside Code Signing: Certificates》第 218 行对 `codesign --verify -vvv` 的输出给了一句直白的警告："Be careful how you interpret this output. It isn’t saying that the code is fit for some specific purpose, like running on your Mac or installing on your iPhone."，第 219—223 行把"通过"展开成五条**内部一致性**判据（期望文件齐全、没有多余文件、文件未被修改、对叶子证书做一次基础 X.509 信任评估、代码满足它自己的 Designated Requirement）。同一篇第 229—230 行再补两刀："When signing code, codesign doesn’t check that the code-signing identity’s certificate was issued by Apple."、"When verifying code, codesign doesn’t check if the code will be accepted by the target platform."。把"退出码 0"记成"这台设备上的授权成立"，是把**一次离线自洽检查**读成了**一次授权判定**。

**"描述文件到期了，所以已分发的 App 会停"**——三个通道给三种到期语义。App Store 侧：TN3161 第 244 行 "App Store apps are signed with credentials that don’t expire. In contrast, your distribution certificate and provisioning profiles can expire. However, this re-signing means that your credentials only need to be valid at the time that you submit your app."（第 252 行同样写：提交时校验一次，之后由 Apple 重签而与你的证书到期日脱钩）。Developer ID 侧：第 253 行 "People who install your product expect it to continue working, regardless of your certificate’s expiration date. Apple enables this by embedding a secure timestamp within your code signature… When you run the code, macOS checks that its Developer ID certificate was valid at the time that it was signed."——到期日在**运行时装**上被换算成"签名那一刻是否有效"。企业 / Ad Hoc / 开发侧：TN3125 第 89—92 行的 `ExpirationDate` 直接限制描述文件本身的有效窗口，"This validity period varies by profile type, but it’s typically not more than a year. The exception here is Developer ID profiles, which have an expiration date far in the future."。台账里只有一个 `到期日` 字段，等于把三种语义压成一种，跨通道的"何时失效"结论必然错位。

**"管理面能列出描述文件，所以管理面能核对签名身份"**——《ProvisioningProfileListResponse.ProvisioningProfileListItem》第 5—7 行给出的全部字段是 `ExpiryDate`（optional，date）、`Name`（required，string）、`UUID`（required，string）——**三格**。签名者类型、签发路径、证书链、App ID 前缀、设备清单、权利白名单，一都不在这条命令的回读里。而《InstalledApplicationListResponse.InstalledApplicationListItem》第 5 行的 `AdHocCodeSigned` 是一个布尔值，第 21 行的 `IsValidated` 说的是"这个 App 当前是否可运行"。把"读到了 `AdHocCodeSigned=true`"记成"确认了签名身份是 ad hoc 开发者证书"，是把**形态布尔**读成**身份结论**。

**"台账里有 Team ID，所以授权主语确定了"**——Team ID 在公开文档里出现在三个不同的位置，且三者不互证：TN3125 第 71 行它是 App ID 前缀（`SKMME9E2Y8.com.example…`，属于**描述文件里的权利声明**）；TN3127 第 128 行它是叶子证书 `subject.OU`（属于**证书里的身份**）；TN3125 第 100—101 行它是 `com.apple.developer.team-identifier` 授权项（属于**运行时读到的权利格**）。更关键的是 TN3127 第 124 行的限定："The OID checks shown here only make sense in the scope established by `anchor apple generic`, that is, for certificates issued by Apple. There’s nothing to stop a malicious CA from issuing certificates with these OIDs."。三格只登记一格的台账，写不出"这个 Team 授权了这次运行"。

第 4—14 章逐层给出输入、官方规则、失败形态与可得证据，其中三条事实决定了整篇的判定结构：**授权对象本身有两种编码形态且旧形态已经不能启动**（TN3125 第 34 行 "the traditional property list view of a profile is no longer the source of truth… each profile contains a DER-Encoded-Profile property which holds a binary form of the profile that’s the new source of truth"；《Using the latest code signature format》第 6 行 "Apps signed with a previous signature format will not launch"；第 12 行 "For any value of v less than 20400, you need to re-sign your app"）；**执行闸门与授权口径是两套东西**（《Apple Platform Security Guide》第 2353 行把内核描述成"controls which user processes and apps can be run"并要求所有可执行代码有签名，第 2362 行给的是签名校验条目，而"谁被授权"要回到描述文件与证书——第 7、8 章说明这两个平面在同一台设备上同时成立但口径不同）；**管理面建模了证书吊销却没有建模代码签名授权对象**——《Profile-specific payload keys》第 46 行有 `CertificateRevocation`（"The payload that configures certificate revocation checking"），全文却没有任何 provisioning profile 类型的载荷；《Status Items》第 61 行有 `StatusSecurityCertificateList`，同样没有任何描述文件状态项。管理面对"TLS 凭证的撤销"有载荷、有状态项，对"代码签名授权对象"只有第 5—7 行那三格回读——这条不对称是第 11 章 L8 层与第 26 章缺口清单的核心读数。

核验部分提供两个纯文本、离线、只读的脚本。**脚本一**把一份"授权链台账"按 Apple 文档口径审一遍，九个命名空间（`id. who. what. where. how. when. state. obs. doc.`）逐格回答"这一格写成这样时，这个授权对象的身份、签发、形态、范围、权利、时效、失效处置、观测通道与引用结论还成不成立"，给出 J1—J4 四档，并对 `key.*` 命名空间与形似私钥、PKCS#12、CSR、描述文件正文、设备绝对路径的取值直接报警（K01 / K02）。**脚本二**把要素登记册、通道能力表与真实公告词表三份纯文本做集合差集与口径一致性比对，回答"这条通道到底要不要这一格、这个读数挂的平面给不给得出这一格、台账引用的公告标识与组件名在词表里有没有"，给出 Q1—Q4 四档。信号码共 **108 个**（脚本一 64 个、脚本二 44 个），**全部在本轮环境实跑触发**，第 23 章给出三十次实跑的逐码覆盖表与退出码。

本文不提供任何可用的漏洞利用代码、提权或绕过步骤，**不含任何伪造或替换描述文件、绕过签名校验、重签他人代码、提取或导出私钥、规避设备侧执行闸门的做法**；不含针对具体设备、具体团队或具体应用的授权判定结论；也不提供任何规避管理面审计的手段。本文给出的只有公开文档口径、授权链归属判定、可见性边界、可得性矩阵与只读核验。**全部只写防御与归属判定。**

两个脚本都不联网、不调用任何设备侧或 Apple 命令行工具（不执行 `codesign`、`security`、`devicectl`、`xcrun`、`altool`、`syspolicy_check`）、不读取描述文件或证书正文、不修改输入文件；唯一写出目标是 `mktemp -d` 创建的临时目录，退出时由 trap 删除。脚本一拒收密钥材料与描述文件正文不是顺带检查，而是本文的立场：**把私钥、PKCS#12 或描述文件正文抄进授权台账，等于把一份本来只受密钥链与设备规则约束的凭证，变成一份不受任何签发规则约束的副本**——台账需要登记的是"哪个身份、经哪条签发路径、给了哪一格权利、由哪个平面在什么时刻读回"，永远不是凭证本身。

---

## 目录

1. [引言](#1-引言)
2. [视角声明与本文边界](#2-视角声明与本文边界)
3. [三套词表：授权对象口径、执行口径、公告口径，与八处换算失败](#3-三套词表授权对象口径执行口径公告口径与八处换算失败)
4. [L1 身份层：谁签的，签给谁](#4-l1-身份层谁签的签给谁)
5. [L2 签发层：证书从哪来，私钥在哪](#5-l2-签发层证书从哪来私钥在哪)
6. [L3 形态层：授权对象自身的形状](#6-l3-形态层授权对象自身的形状)
7. [L4 范围层：哪些设备、哪些地域](#7-l4-范围层哪些设备哪些地域)
8. [L5 权利层：授权了什么能力](#8-l5-权利层授权了什么能力)
9. [L6 时效层：两个到期日与两种时间戳](#9-l6-时效层两个到期日与两种时间戳)
10. [L7 失效与校验层：授权什么时候不算了](#10-l7-失效与校验层授权什么时候不算了)
11. [L8 观测平面层：这一格是谁读回来的](#11-l8-观测平面层这一格是谁读回来的)
12. [L9 通道差异层：同一要素在不同通道的可得性](#12-l9-通道差异层同一要素在不同通道的可得性)
13. [L10 复核与处置层：撤销之后做了什么](#13-l10-复核与处置层撤销之后做了什么)
14. [L11 公告回查层与缺陷类型学 P1—P14](#14-l11-公告回查层与缺陷类型学-p1p14)
15. [归属矩阵：层 × 责任方 × 形态 × 证据](#15-归属矩阵层--责任方--形态--证据)
16. [公开读数：这条链路上能数出来的十八件事](#16-公开读数这条链路上能数出来的十八件事)
17. [可见性边界：这一层读者能拿到什么](#17-可见性边界这一层读者能拿到什么)
18. [四个读数面：签发侧、构建侧、设备侧、管理面](#18-四个读数面签发侧构建侧设备侧管理面)
19. [两套判定模型：J1—J4 与 Q1—Q4](#19-两套判定模型j1j4-与-q1q4)
20. [运营指标 O1—O10](#20-运营指标-o1o10)
21. [只读核验脚本一：授权链台账审查器](#21-只读核验脚本一授权链台账审查器)
22. [只读核验脚本二：通道要素差集与公告词表比对器](#22-只读核验脚本二通道要素差集与公告词表比对器)
23. [两个脚本的全量分支覆盖验收](#23-两个脚本的全量分支覆盖验收)
24. [十二个误区](#24-十二个误区)
25. [常见问题](#25-常见问题)
26. [未公开文档化边界清单](#26-未公开文档化边界清单)
27. [结论](#27-结论)
28. [参考资料](#28-参考资料)

---
## 1. 引言

### 1.1 "这个包是签过的"是五句不同的话

在工程认知里，"这段代码有签名"是一句话。把这句话拆开，它同时主张五件事，而这五件事各自主语不同、口径不同、失败方式也不同：

**第一件：这份代码被某个数字身份签过。**主语是签名者与私钥。《TN3161: Inside Code Signing: Certificates》第 102 行给的定义是 "To sign code you need a certificate and the private key that matches the public key in that certificate. This combination is called a digital identity or, if it’s for signing code, a code-signing identity."，第 103 行立刻补一句 "As a certificate only contains a public key, you can’t use it to sign code."。这一件事关心的是**谁手里有私钥**，不关心权限范围。

**第二件：这个身份是 Apple 发给他的。**主语是签发路径与证书链。同一篇第 80—83 行给出三级链的口径（叶子由 Apple Developer website 发给开发者、中间证书是"one of a very limited set used for code signing"、根是 Apple Root CA 且 "Apple operating systems trust this implicitly"），第 229 行则说明 `codesign` **在签名时并不检查这个证书是不是 Apple 发的**。签发归属与"签名动作成立"是两件事。

**第三件：有一份授权对象允许这段代码在这个范围里跑。**主语是描述文件。TN3125 第 133 行是整篇里唯一把权利与执行直接连起来的一句："Every entitlement claimed by this app is authorized by its profile, and thus iOS allows the app to run."。而这条句子的主语是**描述文件**，不是签名。

**第四件：这段代码此刻还满足它的授权。**主语是校验与失效。TN3161 第 219—223 行的五条内部一致性判据、TN3125 第 89 行的 `ExpirationDate`、TN3126 第 158 行的槽位 `-5` / `-7` 各自决定"此刻满足"到什么程度。

**第五件：有人能证明第四件。**主语是观测平面与引用。第 11 章说明管理面在这条链上只回读三格（描述文件列表项的 `ExpiryDate` / `Name` / `UUID`），第 14 章说明公告词表里没有任何授权对象词汇。**前四件都可以是团队内部的自述，第五件决定它能不能对外说。**

五件事在开发者界面里塌缩成两个动作（Xcode 的 Signing & Capabilities 面板、`codesign --verify`），本文的任务是把它们重新拆开，并给出**每一格空白意味着哪一句结论不能写**的判定规则。

### 1.2 为什么授权链要单独建一套归属语言

本报告集已有的归属语言不能直接搬用：

- 第 02 篇的**运行时权限语言**处理"这个进程有权访问什么"。签名授权链是它的**前置条件**而不是它本身：`get-task-allow` 之类的授权项确实出现在权限语境里，但 TN3125 第 111—112 行给的口径是"描述文件里的授权项是**白名单**，App 声明的权利是**另一份东西**"，这两份的比对不由权限模型给出。
- 第 08 篇的**申报语言**处理"隐私清单说了什么"。授权链处理的是**权利从哪来**：一份清单可以申报某种能力，它不能让这段代码获得该能力。
- 第 09 篇的**更新链语言**处理"补丁走到哪一步"。本文 L11 层只借它一个结论并且把它量化：**公告词表用的是产品功能组件名，不是授权对象词汇**（第 16 章读数 1—11 给出具体命中数）。
- 第 10 篇的**主体语言**处理"这台设备归谁、托管边界在哪"。授权链与之相邻但不同：一个企业描述文件可以让同一个 Team 的包装在任意设备上（TN3125 第 87 行的 `ProvisionsAllDevices`），此时"设备归谁"与"这段代码凭什么能跑"是两个各自主语的问题。
- 第 11 篇的**副本语言**处理"一份数据落在哪、密钥归谁"。本文 L2 层与之最接近：PKCS#12 导出（《Synchronizing code signing identities with your developer account》第 21—31 行）产生的是一份可复制的凭证副本，但那一篇讨论的是用户数据副本的归属，本文讨论的是**签名能力副本的归属与外泄后果**（第 19 行那句官方警告见第 5 章）。
- 第 12 篇的**供应链语言**处理"这段第三方代码怎么进到产物里"。授权链的形态层与之相接：TN3126 第 246—260 行说明嵌套代码在 macOS 用 cdhash 加 DR 引用、在 iOS / watchOS / tvOS 用资源集合引用，这正是第 12 篇 L3 层那条依赖的一个**签名后果**。
- 第 13 篇的**证据链语言**处理"一条记录能不能作证"。本文与之最像，但对象不同：那一篇的台账格是"记录的产生、留存、送达"，本文的台账格是"授权的归属、范围、时效、失效"。两篇的判定档位都用四档，但档位含义完全不可互换（第 19 章 19.4 给合读规则）。

授权链要处理的缺失一段是：**一段代码从被签出到被引用为"我们有权这么分发"之间，有多少个必须登记的读数，以及每一个读数缺失时哪句话不能写。**所以本文另建一套词表，并在第 2 章把与第 02、08、09、10、11、12、13 篇的分工线画清楚。

### 1.3 一条被普遍接受、但在文档里没有依据的表述

行业里最常见的授权表述是："这个 App 由我们的企业证书签名并分发给我们自己的员工，签名有效。"这句话在本文的框架里有六处需要台账支撑，而任何一处空白都会让它降级：

- "企业证书"是哪一条链发出来的？TN3161 第 229 行说明签名工具**不核对**签发者是不是 Apple；所以这个结论必须来自链与 EKU 的登记，而不是来自签名动作本身。
- "分发给员工"在公开口径里的边界是什么？《Apple Developer Enterprise Program》页第 109 行给的是"allows large organizations to develop and deploy proprietary, internal-use apps to their employees"，第 111 行给的是资格口径："only for the internal use and distribution of proprietary apps in specific use cases that are not adequately addressed with public apps on the App Store, custom apps through Apple Business or Ad Hoc distribution, or beta testing through TestFlight"，第 115 行再把分发收进"to distribute these apps privately and securely to employees within the organization"，本文第 7 章 L4 层把它落到范围格。
- "我们的员工"这一格在设备上怎么读回来？第 11 章：管理面只回读描述文件三格，第 12 章说明这条通道在设备侧需要描述文件被装上（《Apple Platform Security Guide》第 2365 行）。
- "签名有效"是哪一种有效？第 10 章：`codesign --verify` 的有效是五条内部一致性判据；`ValidateApplications` 命令给出的有效是设备侧此刻可运行；这两者不是同一件事。
- 这次分发用的授权对象到期了吗？第 9 章：TN3161 第 270 行 "Certificates aren’t the only code-signing asset that expire. Provisioning profiles also have an expiration date."，两个到期日必须分别登记。
- 如果证书吊销了，你们做了什么？第 13 章：《Synchronizing code signing identities with your developer account》第 39—41 行只给"吊销之后可以删除，且只能删除你或团队成员在你开发者账户里吊销的证书"，本文把它落到处置格。

这六处空白不会让这句话变成假话，它让它变成**一句无法核对的话**。本文全部核验工作就是给出这六处的登记格式与判定档位。

---

## 2. 视角声明与本文边界

### 2.1 本文视角

本文站在**防御侧授权治理**（authorization governance）视角：一个已经在用（或正在考虑用）某种分发通道把代码送进设备的组织，如何判断手里这份授权记录能不能支撑一句对外结论——"这个包是我们有权分发的、到某日为止有效、失效之后我们知道并处置了"。它不是证书管理手册，不是发布流水线 SOP，也不是开发者协议的法律意见。

### 2.2 与前十三篇的分工

| 相邻篇目 | 它处理什么 | 本文处理什么 | 分界句 |
| --- | --- | --- | --- |
| 第 02 篇 访问控制 | 进程有权访问什么、越界归谁 | 这段代码凭什么获得访问资格、授权从哪条链来 | 权限管"运行时能不能碰"，本文管"这份权利是谁给的、什么时候收回" |
| 第 08 篇 隐私授权 | 清单与 required reason 说了什么 | 权利来源与授权对象白名单，不由申报证明 | 本文不审清单内容，只审"这项能力有没有被授权" |
| 第 09 篇 更新链 | 补丁走到哪一步 | 公告词表与授权对象词汇之间没有映射 | 本文只借"公告口径"一个结论并在第 16 章量化 |
| 第 10 篇 生命周期归属 | 设备归谁、托管边界 | 授权归谁、哪条链发的、私钥在谁手里 | 设备易主不自动让授权易主；全设备声明通道尤其如此 |
| 第 11 篇 备份副本 | 用户数据副本落在哪、密钥归谁 | 签名能力副本（PKCS#12 / 导出的身份）归谁、外泄后果 | 本文不讨论用户数据加密，只讨论签名身份的可复制性与托管 |
| 第 12 篇 供应链 | 第三方代码如何进入产物 | 嵌套代码在签名里怎么被引用、重签边界在哪 | 本文 L3 层引用其结论：嵌套形态决定形态格能不能对齐 |
| 第 13 篇 证据链 | 一条记录能不能作证 | 一段授权能不能被证明存在过、当时有效 | 两篇都用四档，但档位对象不同：一个是记录，一个是权利 |

本文与第 02 篇最容易混的一段是"权利"。第 02 篇问的是**运行时某进程能不能访问某资源**，本文问的是**这份权利是不是被一条签发链给出来的、给到哪个范围**。同一个 `keychain-access-groups`，第 02 篇登记它带来的隔离效果，本文登记它在描述文件白名单里的形态（TN3125 第 104—108、114 行的通配写法）与 App 实际声明的取值（第 118—131 行）是否对齐。

### 2.3 明确不做的事

- 不提供伪造或替换描述文件、绕过签名校验、重签他人代码、提取或导出私钥、规避设备侧执行闸门的任何做法；不提供绕过 Developer Mode、首次启动确认或管理面校验的操作细节。
- 不给出任何具体 Team、具体应用、具体设备或具体分发案例的授权判定结论；全部台账样例是合成值，第 21、22 章开头逐条声明。唯一非合成输入是第 22 章的公告词表导出件，它只用于词汇比对，不含任何授权结论。
- 不判定法律意义上的授权有效性。本文的 J1—J4 与 Q1—Q4 是**文档口径下的可核对性档位**，不是对开发者协议、许可或合规的结论。
- 不替代证书与私钥治理咨询。第 5 章讨论 `key_storage` 与 `key_custody` 时，只登记"是否核对过"，不给出"这条私钥该放在哪"的建议。
- 不提供任何规避管理面审计、删除登记痕迹或伪造回查结论的手段。第 13 章只写处置动作的**可得性与口径**，不写绕过方式。
- 不预测 Apple 未来的签名格式、链结构或载荷形态。TN3125 第 33 行与 TN3126 第 13 行都明确写了这些细节"could change at any time"，本文全部结构判定都限定在本轮归档件的口径内。

---
## 3. 三套词表：授权对象口径、执行口径、公告口径，与八处换算失败

本文用到的官方词汇分属三套互不对接的口径。三套都有独立文档来源，都没有给出跨套映射；第 21、22 章两个脚本里全部"取值域"就按这三套分别登记。

本文的行号引用给出**归档件里的行号**：文件名短的直接写件名（`TN3125 38`、`sharing 第 39—41 行`），文件名过长的用下表简称，第 5—7 章的归属表也沿用同一张表。简称与归档路径一一对应，路径相对 `.srcx14/`，行数按 `wc -l` 口径，任何一条都可以用 `sed -n 'Np' <路径>` 逐行复现。

| 简称 | 归档路径 | 行数 |
| --- | --- | --- |
| 指南 | `B/apple-platform-security-guide.txt` | 4,885 |
| 审核指南 | `B/pages/app-review-guidelines.txt` | 593 |
| PKI 页 | `B/pages/apple-certificateauthority.txt` | 92 |
| 最新格式 | `A/using-the-latest-code-signature-format.txt` | 43 |
| 已注册设备 | `A/distributing-your-app-to-registered-devices.txt` | 40 |
| 定位设备标识 | `A/locating-device-identifiers.txt` | 29 |
| 分发前准备 | `A/preparing-your-app-for-distribution.txt` | 73 |
| 描述文件列表项 | `A/provisioningprofilelistitem-fields.txt` | 7 |
| 安装应用列表项 | `A/installedapplicationlistitem-fields.txt` | 26 |
| 校验响应字段 | `A/validateapplicationsresponse-fields.txt` | 14 |
| 安装描述文件命令 | `A/install-provisioning-profile-command.txt` | 31 |
| 声明式清单 | `A/devicemanagement-declarations.txt` | 75 |
| 载荷键 | `A/profile-specific-payload-keys.txt` | 158 |
| 状态项 | `A/status-items.txt` | 82 |
| 117767 页 | `B/pages/support-117767-alt-dist.txt` | 80 |

### 3.1 词表 A：授权对象口径（身份与描述文件的"五问"）

《TN3125: Inside Code Signing: Provisioning Profiles》用五个疑问词组织整篇（第 37、66、77、88、93 行的五个章节标题：`The who` / `The what` / `The where` / `The when` / `The how`），这是公开文档里唯一一份把"一份授权对象"拆成可核对格子的口径。本文的台账命名空间直接照它建，再加身份、状态、观测与引用四格：

| 术语 | 文档里的表述 | 行锚 | 台账字段 |
| --- | --- | --- | --- |
| DeveloperCertificates | "Every profile has a DeveloperCertificates property holding the certificates of each developer who can sign code covered by the profile." | TN3125 38 | `who.cert_type`、`id.cert_fp` |
| DER 里的证书格 | "This doesn’t contain a full copy of each certificate, but rather a SHA-256 checksum of the certificate." | TN3125 195 | `what.der_profile`、`id.cert_fp` |
| App ID | "an App ID, composed of an App ID prefix and a bundle ID" | TN3125 71 | `id.app_id`、`what.appid_form` |
| 通配 App ID | "This profile applies to any app whose App ID starts with SKMME9E2Y8.com.example.apple-samplecode." | TN3125 76 | `what.appid_form=wildcard` |
| 设备清单 | "Most profiles apply to a specific list of devices. This is encoded in the ProvisionedDevices property" | TN3125 78—79 | `where.provisioned_listed` |
| App Store 无设备格 | "App Store distribution profiles have no ProvisionedDevices property because you can’t run an App Store distribution signed app locally." | TN3125 86 | `where.provisioned_listed=not_applicable` |
| 全设备声明 | "Developer ID and In-House (Enterprise) distribution profiles have the ProvisionsAllDevices property, indicating that they apply to all devices." | TN3125 87 | `where.all_devices_claim` |
| 到期日 | "Every profile has an ExpirationDate property which limits how long the profile remains valid." | TN3125 89 | `when.profile_expiry` |
| 时长口径 | "it’s typically not more than a year. The exception here is Developer ID profiles, which have an expiration date far in the future." | TN3125 92 | `when.expiry_basis` |
| 权利白名单 | "The entitlements in the profile act as an allowlist. This isn’t the same as the entitlements claimed by the app." | TN3125 111 | `how.allowlist_covered` |
| 覆盖方向 | "Every entitlement claimed by the app must be in the profile’s allowlist but the reverse isn’t true." | TN3125 112 | `how.allowlist_covered=exceeds` 判据 |
| 权利通配 | "Some entitlements in the allowlist use wildcard syntax… Wildcards don’t make sense in the app’s code signature." | TN3125 114 | `what.claim_form` |
| Team ID 授权项 | `com.apple.developer.team-identifier` 取值 `SKMME9E2Y8` | TN3125 100—101 | `id.team_id` |
| 受限授权项 | "restricted entitlements must be authorized by a provisioning profile… the fact that the keychain-access-groups entitlement must be authorized by a profile means that other developers can’t impersonate your app in order to steal its keychain items." | TN3125 141 | `how.restricted_entitlement` |
| 无受限授权项则不需要描述文件 | "A Mac app that uses no restricted entitlements doesn’t need a provisioning profile… The only exception to this rule is TestFlight, which always requires a profile." | TN3125 142 | `how.profile_required` |
| 内嵌位置 | `MyApp.app/Contents/embedded.provisionprofile`（macOS）与 `MyApp.app/embedded.mobileprovision`（其他平台） | TN3125 146—147 | `what.ent_slot` |
| App Store 包不含描述文件 | "Apps that you download from the App Store don’t contain an embedded provisioning profile because the App Store checks that the app is signed and provisioned correctly as part of its distribution process." | TN3125 149 | `what.der_profile=not_applicable` |
| 独立可执行文件 | "A standalone executable can’t claim a restricted entitlement because there’s no place to embed the provisioning profile that authorizes that claim." | TN3125 150 | `what.ent_slot=none` |
| 格式不保证 | "The exact format of provisioning profiles isn’t documented and could change at any time." | TN3125 33 | 第 26 章 N2 |

签名身份侧的口径补自 TN3161：`digital identity` = 证书 + 私钥（第 102 行）、证书本身不能签名（第 103 行）、CSR 流程"creates a public / private key pair in your login keychain"（第 116 行）、"Your private key never leaves your Mac. As long as you keep that key to yourself, no one can sign code as you."（第 121 行）、云托管时"You don’t have direct access to either of them."（第 125 行）。

### 3.2 词表 B：执行口径（内核、校验、槽位与需求表达式）

| 术语 | 文档口径 | 行锚 | 台账字段 |
| --- | --- | --- | --- |
| 强制签名 | "these operating systems require that all executable code be signed using an Appleissued certificate" | 指南 2353 | `state.validate_state` |
| 内核控制运行 | "After the kernel has started, it controls which user processes and apps can be run." | 指南 2353 | 第 10 章执行闸门 |
| 框架按 Team ID 校验 | "This verification is accomplished through the team identifier (Team ID), which is extracted from an Apple-issued certificate. A team identifier is a 10-character alphanumeric string" | 指南 2362 | `id.team_id` 形态判据 |
| 描述文件装到用户 | "Users need to have the provisioning profile installed to run these apps." | 指南 2365 | `state.first_launch_confirm` |
| 管理面装的隐式信任 | "Apps installed through a device management service are implicitly trusted because the relationship between the organization and the device is already established." | 指南 2365 | `obs.plane=mdm_command` 的语义 |
| 首次启动需 Apple 确认 | "On first launch of any proprietary in-house app, the device needs to receive positive confirmation from Apple that the app is allowed to run." | 指南 2365 | `state.first_launch_confirm` |
| 运行时逐页校验 | "This per-page architecture allows the kernel to check each page as it’s loaded into memory." | TN3126 138 | 第 10 章 |
| 校验通过 ≠ 适配用途 | "It isn’t saying that the code is fit for some specific purpose, like running on your Mac or installing on your iPhone." | TN3161 218 | `state.validate_state` 语义限定 |
| 五条内部一致性判据 | 期望文件齐全 / 无多余文件 / 未被修改 / 叶子证书基础 X.509 信任评估成功 / 满足自身 DR | TN3161 219—223 | 脚本一 V 族依据 |
| cdhash | "Hashing a code directory results in a code directory hash, or cdhash. This value uniquely identifies the code being signed." | TN3126 69 | `id.cdhash` |
| 公证票据 | "A notarized ticket is a set of cdhash values, signed by the notary service to confirm that it has checked that code for malicious components." | TN3126 69 | 第 14 章 X 族依据 |
| 惰性分页校验 | "This allows the system to run a code-signed executable and check its code signature lazily (in the computer science sense of that word)." | TN3126 138 | 第 10 章 |
| 槽位 -5 / -7 | "Slot -5 holds a hash of the entitlements." / "-5 contains a value and -7 contains a zero value, or is not present, you need to re-sign" | TN3126 145、157 | `what.ent_slot` |
| 资源密封 | "Slot -3 in the code directory holds the hash of that file"（该文件即 CodeResources） | TN3126 160 | `what.resource_sealed` |
| 嵌套引用（macOS） | "The cdhash property holds the code directory hash of the nested code" + "The requirement property holds the designated requirement (DR) of that nested code" | TN3126 246、255 | `what.nested_signed` |
| 嵌套模型不同（iOS 等） | "iOS, watchOS, and tvOS have a different model for nested code… the app references that nested code as a collection of resource files rather than using a single nested code reference." | TN3126 260 | 第 6 章 |
| 需求是布尔函数 | "A code signing requirement is a function that, given a code signature, returns a Boolean value." | TN3127 15 | 第 10 章 DR 格 |
| 签名标识 ≠ 签名身份 | "A code signing identifier is a string chosen by the signer to uniquely identify their code… Don’t confuse this with a code signing identity, which is a digital identity used for code signing." | TN3127 19 | `id.bundle_id` 与 `who.*` 分离 |
| DR 与代码身份 | "Most code has a designated requirement (DR) which is how the code identifies itself" | TN3127 49 | 第 10 章 |
| 非 macOS 平台 DR 不为主 | "Other Apple platforms allow for a DR, but it doesn’t represent the primary means of tracking code identity." | TN3127 50 | 第 12 章通道差异 |
| anchor apple generic | "which requires that the code be signed by a code signing identity issued by Apple" | TN3127 71 | `who.chain_root` |
| OID 检查的适用域 | "The OID checks shown here only make sense in the scope established by anchor apple generic… There’s nothing to stop a malicious CA from issuing certificates with these OIDs." | TN3127 124 | 第 5 章 A05/A11 依据 |
| Team ID 在证书里的位置 | "The certificate leaf[subject.OU] = SKMME9E2Y8 term requires that the leaf certificate’s Organization Unit field be SKMME9E2Y8. In a Developer ID certificate, this is where you’ll find the Team ID." | TN3127 128 | `id.team_id` 来源二 |
| 签名格式版本 | "Look in the output for a string such as CodeDirectory v=20500. For any value of v less than 20400, you need to re-sign your app." | 最新格式 12 | `what.sig_version` |
| 旧格式不能启动 | "Apps signed with a previous signature format will not launch." | 最新格式 6 | 第 6 章硬事实 |

### 3.3 词表 C：可得性与公告口径（通道、平面、组件名）

| 术语 | 文档口径 | 行锚 | 台账字段 |
| --- | --- | --- | --- |
| 开发设备上限 | "a limited number of devices per product family per year" | 已注册设备 6 | `where.device_id_form` |
| Xcode 注册并写入描述文件 | "Xcode registers and adds the device to the provisioning profile." | 已注册设备 11 | `obs.plane` |
| Ad Hoc 子集 | "Testers can run your app only on the devices that you add to the provisioning profile." | 已注册设备 33—34 | `where.provisioned_listed` |
| Developer Mode | "To run your iOS… app that you install from an iOS Package Archive, enable Developer Mode on that device" | 已注册设备 29 | `where.dev_mode_required` |
| UDID 两种形态 | Mac 上称为 "Provisioning UDID"；Device Hub / Finder 给出 UDID 字段 | 定位设备标识 9—13、26 | `where.device_id_form=udid40/udid25` |
| bundle ID 上传后不可改 | "After you upload your first build to App Store Connect, you can’t change the bundle ID" | 分发前准备 16 | `id.bundle_id` 时效语义 |
| 项目归属团队 | "assign all of the targets in a project to a team that belongs to the Apple Developer Program" | 分发前准备 24 | `id.team_id` 归属动作 |
| 描述文件回读三格 | `ExpiryDate`（optional date）、`Name`（required string）、`UUID`（required string） | 描述文件列表项 5—7 | `obs.field_read` |
| 安装应用形态布尔 | `AdHocCodeSigned (optional) boolean — If true, the app is ad-hoc code signed.` | 安装应用列表项 5 | `obs.field_read=signature_bool` |
| 校验态字段 | `IsValidated (optional) boolean — If true, the app is valid and can run on the device. If the app is enterprise-distributed and unvalidated, it won’t be able to run until validation has occurred.` | 安装应用列表项 21 | `state.validate_state` |
| 来源字段 | `Source (optional) string — The source of the application. When Declarative Device Management manages the app, this value is Declarative Device Management.` | 安装应用列表项 25 | `obs.plane=ddm` |
| 校验命令回读 | `ValidateApplicationsResponse` 的 Status / NotOnConsole / UDID / EnrollmentID 等格 | 校验响应字段 5—14 | `state.*` 与 `obs.*` |
| 装描述文件的通道与权限 | Device channel 支持 iOS/macOS/Shared iPad/tvOS/visionOS/watchOS，User channel N/A，Required access right `AllowProvisioningInstallationRemoval` | 安装描述文件命令 17—21 | `obs.command_name` |
| 声明式清单类型 | `AppManaged`、`LegacyInteractiveProfile`、`LegacyProfile`（无描述文件类声明） | 声明式清单 13、22—23 | 第 11 章 P02 依据 |
| 证书吊销载荷 | `CertificateRevocation — The payload that configures certificate revocation checking` | 载荷键 46 | 第 11 章 / 第 26 章 N3 |
| 证书列表状态项 | `StatusSecurityCertificateList` — "The status item that lists the device’s managed certificates." | 状态项 61 | 第 11 章 |
| 公证是基线审查 | "Notarization is a baseline review that applies to all apps, regardless of their distribution channel" | 117767 页 22 | `who.issuing_path=notary_service` |
| 地域与账户双重条件 | "Only users based in Brazil, Japan, or the European Union are able to install apps through alternative app distribution. The country or region of your Apple Account must be set to one of those countries or regions, and you must physically be located there." | 117767 页 21 | `where.region` |
| 公告组件词表 | CSAF 导出件的 `component` 列（本轮 392 行、101 个不同组件名） | 第 16 章读数 1—2 | `doc.source` 回查 |

### 3.4 八处换算失败

下面八条不是"容易误解"，而是**两套口径之间没有官方映射**，任何直接换算都会在台账里留下无法核对的格。前四处可以在归档件之间逐字对出，后四处由第 21、22 章的信号编码。

**F1｜"校验退出码 0" → "被授权运行"。** TN3161 第 218—223 行把 `codesign --verify` 的结果限定为五条内部一致性判据，第 230 行明确 "When verifying code, codesign doesn’t check if the code will be accepted by the target platform."；设备侧的"能运行"另有出处（安装应用列表项第 21 行 `IsValidated`）。两个"有效"没有换算关系。→ 脚本一 `V01` / `V02`。

**F2｜"有到期日" → "到那天失效"。** 三条通道三种语义（摘要第 2 段）。同一个 `到期日` 字段无法同时表达 App Store 的"提交时校验一次"、Developer ID 的"运行时装上换算回签名时刻"、企业/Ad Hoc 的"描述文件自身窗口"。→ 脚本一 `T01` / `T02` / `T09`。

**F3｜"管理面能列出" → "管理面能核对签名身份"。** 描述文件列表项只有三格（第 5—7 行）；`AdHocCodeSigned` 是形态布尔（第 5 行）不是身份结论；`security find-identity` 的 SHA-1 指纹在另一侧（TN3161 第 173 行）。三处读数分属三个平面。→ 脚本一 `O01` / `O02`；脚本二 `P01`。

**F4｜"App ID 相同" → "同一次授权"。** TN3125 第 71、76 行说明通配 App ID 覆盖一整片；第 104—108、114 行说明权利白名单里 `SKMME9E2Y8.*` 也覆盖一整片。把"通配命中"登记成"精确授权"，等于把范围格与权利格同时放大。→ 脚本一 `B01` / `B02` / `H02`。

**F5｜"Team ID 出现过" → "Team 已确认"。** 词表 A 里 Team ID 出现在描述文件授权项（TN3125 第 100—101 行），词表 B 里出现在叶子证书 `subject.OU`（TN3127 第 128 行），执行口径里出现在框架加载校验（指南第 2362 行）。三处互相独立，且 TN3127 第 124 行给出"malicious CA 可以签发同样 OID"的限定。→ 脚本一 `A01` / `A11`；脚本二 `V01`。

**F6｜"证书链到 Apple 根" → "这一格可读回"。** TN3161 第 83 行（"The root certificate is Apple Root CA. Apple operating systems trust this implicitly."）与描述文件三格回读（第 11 章）之间没有桥：链可信不代表管理面读得到，管理面读不到也不代表链不可信。→ 脚本二 `P05`。

**F7｜"公告里修了一个签名相关的洞" → "我的授权对象受影响"。** 本轮 101 个不同组件名里，含签名授权词形的**一个都没有**（第 16 章读数 3—11）；唯一一条描述句命中 `signature` 的是 Heimdal 的 "An issue with signature validation was addressed with improved checks."，与代码签名授权无关。→ 脚本二 `X04`。

**F8｜"吊销了" → "已失效且已处置"。** 签发侧口径只到"吊销的证书可以删除，且只能删自己人吊销的"（第 13 章），删除动作与"设备上这段代码不再被允许运行"之间，公开文档没有给出任何设备侧回读通道。把 `revoke_action=revoked` 直接写成"授权已失效"缺整段证据。→ 脚本一 `V03` / `V04` / `V05`。

这八条中的每一条，在台账里的表现都是"某一格被写成了另一格的结论"。第 19 章的两套四档模型判定的是：**当这些换算失败发生时，这个授权对象还剩哪几句能对外说。**

---
## 4. L1 身份层：谁签的，签给谁

### 4.1 输入与规则

台账侧的输入是 `id.*` 与 `who.signer_type` 两族七格：`channel`（分发通道）、`team_id`、`bundle_id`、`app_id`、`profile_uuid`、`cert_fp`、`cdhash`。官方规则有四条直接可核：

1. **App ID 是两段拼接**：TN3125 第 71 行 "This property holds an App ID, composed of an App ID prefix and a bundle ID."。因此 `app_id = team_id . bundle_id` 是一致性判据，不是命名习惯；不一致时脚本一给 `B01`。
2. **Team ID 有固定形态**：《Apple Platform Security Guide》第 2362 行 "A team identifier is a 10-character alphanumeric string—for example, 1A2B3C4D5F."。不是 10 位字母数字的取值不能进入任何身份结论（`A10`）。
3. **证书指纹是回指手段**：TN3161 第 173 行 "The hex string next to each identity is the SHA-1 hash of its certificate, which is a good way to resolve any ambiguities with the name."。第 145 行还说明 `codesign` 可以按这个 SHA-1 消歧。所以 `cert_fp` 必须是 40（SHA-1）或 64（SHA-256）位十六进制（`A09`）。
4. **cdhash 是把授权绑定到具体二进制的唯一手段**：TN3126 第 69 行 "This value uniquely identifies the code being signed."。通道已定而 `cdhash` 未登记时，授权只能落到"这个 Team 的这类包"，落不到"这个包"（`B07`）。

### 4.2 硬事实

- 身份层的**主语是两个不同的东西**：签名身份（谁签）与被签对象（签给哪个 App ID）。TN3127 第 19 行专门警告不要混淆 code signing identifier 与 code signing identity，本文的 `id.bundle_id` 属前者、`who.*` 属后者。
- **Team ID 单独不足以闭合授权**。TN3125 第 100—101 行的 Team ID 是描述文件里的授权项，TN3127 第 128 行的 Team ID 是叶子证书的 `subject.OU`，指南第 2362 行的 Team ID 是库加载校验用的字符串。三者不互证。只登记 Team ID 而无证书指纹时，失效结论不可证（`A12`）。
- **管理面给不出身份层的大部分格**：见第 11 章，描述文件列表项只回读三格。所以身份层的读数只能来自签发侧（开发者账户、证书文件）或构建侧（签名输出），不能来自设备侧回读。

### 4.3 失败形态

| 台账写法 | 后果 | 信号 |
| --- | --- | --- |
| `id.channel` 与 `who.signer_type` 任缺其一 | "这段代码凭什么被允许运行"没有主语 | A01 |
| `id.team_id=TOOSHORT` | 连形态判据都不满足，身份格整体作废 | A10 |
| `id.app_id` 与 `team_id.bundle_id` 不等 | 授权对象与身份对象脱钩，范围格与权利格同时失去参照 | B01 |
| 有 `cert_fp` 无有效期 | `codesign` 选身份要核对当前时刻在有效期内，缺有效期即无法核对 | A05 |
| 只有口头"是我们的包"，无 `cdhash` | 无法绑定到具体二进制 | B07 |
| 把 `.p12` 路径写进 `who.key_storage` | 台账里出现凭证材料形态的取值 | K01 / K02 |

---

## 5. L2 签发层：证书从哪来，私钥在哪

### 5.1 输入与规则

输入是 `who.*` 十二格：`signer_type`、`issuing_path`、`cert_type`、`cert_not_before`、`cert_not_after`、`eku_codesign`、`chain_root`、`chain_depth`、`key_storage`、`key_custody`、`identity_exported`、`export_channel_split`。官方规则：

- **签发链的公开形态**：TN3161 第 80—83 行给出三级链（叶子由 Apple Developer website 发给开发者、中间证书是"one of a very limited set used for code signing, including Apple Worldwide Developer Relations Certification Authority and Developer ID Certification Authority"、根为 "The root certificate is Apple Root CA. Apple operating systems trust this implicitly."），第 84 行补一句 "Don’t rely on the exact details of this chain of trust; it could change in the future."。链根不是 Apple Root CA 时本文不给身份结论（`A08`）。
- **EKU 决定这张证书能不能签代码**：第 150 行 "It checks that the certificate supports code signing. Specifically, it looks for Code Signing within the certificate’s Extended Key Usage extension"，第 151—157 行给出 `X509v3 Extended Key Usage: critical / Code Signing` 的实际输出。不含 Code Signing 的证书不能是签名动作的发出者（`A07`）。
- **证书与私钥合起来才是身份**：第 102—103 行（见 1.1）。因此"有证书无私钥"不是可用身份：《Synchronizing code signing identities with your developer account》第 33 行 "If you have a certificate but not the corresponding private key, you can’t use that certificate for code signing"。
- **私钥落点决定泄露归属**：第 116 行手动 CSR "creates a public / private key pair in your login keychain"；第 121 行 "Your private key never leaves your Mac. As long as you keep that key to yourself, no one can sign code as you."；第 122 行允许智能卡或硬件令牌；第 123 行给出口径里的风险——"It’s easy to miss that your most critical code-signing asset, your private key, is tucked away in your login keychain… you might lose your private key, for example, when you migrate to a new Mac."；第 124 行说明 Xcode 走同一条路并有同一个坑；第 125 行说明云托管时"You don’t have direct access to either of them."。登记了 `key_storage` 而未登记 `key_custody` 时，泄露算谁的无法确定（`A11`）。
- **导出身份是有官方警告的一格**：《Synchronizing code signing identities with your developer account》第 19 行是本文引用频率最高的一句："Anybody who gets access to the exported signing identity and learns (or guesses) the password can distribute signed software that appears to users and the operating system to come from your Apple Developer account"，并且同段给出"用不同渠道分别传递身份与口令"的口径。`identity_exported=yes` 而 `export_channel_split` 不为 `yes` 时给 `A04`。
- **云端托管与手动导出是两条路**：同一页第 18 行说明云托管证书（cloud-managed certificates）由 Xcode 自动创建并在团队内共享，不需要手动导出；把它和"已导出签名身份 + 私钥在 Apple 云端"同时登记是互斥组合（`A02` / `A03`）。

### 5.2 硬事实

Apple PKI 页把中间证书的**到期**公开列出（第 40—41 行 Developer ID G1 "Expiring 02/01/2027 22:12:15 UTC"、G2 "Expiring 09/17/2031 00:00:00 UTC"；第 45—49 行 Worldwide Developer Relations G2—G6 各带到期时间戳），并在第 51 行的 "Certificate Revocation Lists" 标题下、第 52—56 行公开五份证书吊销清单（Apple Inc. Root CRL、Apple Computer, Inc. Root CRL、Software Update CRL、Timestamp CRL、Worldwide Developer Relations CRL）。也就是说：**CA 层的失效时点是公开的，叶子层的失效时点要自己登记。**台账里 `chain_depth` 越出 1—5 的取值直接判为形态错误（`S04`），因为公开口径只给出"三级为标准"这一形态。

### 5.3 失败形态

| 台账写法 | 后果 | 信号 |
| --- | --- | --- |
| `issuing_path=cloud_managed` 而 `key_custody=self` | 云托管时开发者对私钥无直接访问，两者不能同时成立 | A02 |
| `identity_exported=yes` + `key_storage=apple_cloud` | 云端托管没有手动导出这条路，两格必有一格是抄来的 | A03 |
| 导出身份与口令同渠道 | 官方警告的直接命中项 | A04 |
| `cert_fp` 有、`cert_not_after` 无 | 无法核对签名时刻是否在有效期内 | A05 |
| `eku_codesign=false` | 这不是代码签名证书，签名归属不成立 | A07 |
| `chain_root=other_root` | 不满足 `anchor apple generic` 的口径前提 | A08 |
| 签发层齐备但引用格空 | 全部结论无法逐行核对 | D01 |

---

## 6. L3 形态层：授权对象自身的形状

### 6.1 输入与规则

输入是 `what.*` 八格与 `id.cdhash`。这一层的官方规则集中在两种编码形态与一个版本号上：

- **两种形态，旧的已失效**：TN3125 第 34 行 "the traditional property list view of a profile is no longer the source of truth… Rather, each profile contains a DER-Encoded-Profile property which holds a binary form of the profile that’s the new source of truth"；第 198 行给出启用范围 "This DER-encoded profile is required starting with iOS 15, iPadOS 15, tvOS 15, and watchOS 8."；《Using the latest code signature format》第 6 行说得更直接："Starting in iOS 15, iPadOS 15, tvOS 15, and watchOS 8, the system checks for a new, more secure signature format that uses Distinguished Encoding Rules, or DER, to embed entitlements into your app’s signature. Apps signed with a previous signature format will not launch."。`der_profile` 不为 `true` 时给 `B03`。
- **版本号是可以直接读的判据**：最新格式页第 12 行 "Look in the output for a string such as CodeDirectory v=20500. For any value of v less than 20400, you need to re-sign your app."。`sig_version` 低于 20400 给 `B04`，超出公开观察区间（20100—20600）给形态告警（`S04`）。
- **权利槽有两个位置，缺一即不完整**：TN3126 第 145 行 "Slot -5 holds a hash of the entitlements."，第 157—158 行给出诊断口径："If -5 contains a value and -7 contains a zero value, or is not present, you need to re-sign your app to include the new DER entitlements… If you have an iOS app whose signature has an entry in -5 but no entry in -7, then it has entitlements but it’s missing the new-style DER-encoded entitlements and you must re-sign it to be compatible with iOS 15."。只在 `-5` 有值给 `B05`。
- **嵌套要由内向外逐个签**：最新格式页第 36 行 "If your app contains nested code, such as an app extension, a framework, or a bundled watchOS app, sign each item separately, starting with the most deeply nested executable, and working your way out; then sign your main app last. Don’t include entitlements or profiles when signing frameworks. Including them produces an invalid code signature."。`nested_signed` 不为 `true` 给 `B06`。
- **资源也被签名覆盖**：TN3126 第 160 行 "If your code exist in a bundle then the code signature protects not just your code but the resources in your bundle. Central to this is the CodeResources file. Slot -3 in the code directory holds the hash of that file"。
- **嵌套引用模型按平台不同**：TN3126 第 246—260 行说明 macOS 用 cdhash + DR 引用嵌套代码，且第 259 行 "In theory this lets you update the nested code with a new version, as long as it has the same DR. In practice, this facility is not used in standard deployment workflows and is now deprecated."；第 260 行给 iOS / watchOS / tvOS 的另一套："the app references that nested code as a collection of resource files rather than using a single nested code reference. Nested code references are only used on macOS."。

### 6.2 硬事实

形态层的**结论全部可以离线读**：版本号、槽位、嵌套是否逐个签、资源是否密封，都属于构建侧可登记事实，不依赖设备回读，也不依赖管理面。这也是为什么本文把形态层的阻断级别设得比身份层高：这一层出现 `B03`/`B04`/`B05` 时，"这段代码能不能在这台设备上启动"已经有官方否定答案（最新格式页第 6 行）。

同时，**"能启动"和"被授权"仍然是两句话**。TN3125 第 133 行的条件句是"每一项声明的权利都被描述文件授权"，与形态格的满足条件是两回事。

### 6.3 失败形态

| 台账写法 | 后果 | 信号 |
| --- | --- | --- |
| `der_profile=false` 且通道是 iOS 类 | 该包在这几个系统上根本不会启动，"已分发"结论不成立 | B03 |
| `sig_version=20100` | 需要重签，登记成"有效"是时点错位 | B04 / T06 |
| `ent_slot=legacy_only` | 缺 DER 权利槽，签名视为不完整 | B05 |
| 应用声明里出现通配符 | 通配符只属于描述文件允许清单侧（TN3125 第 114 行） | B02 |
| 框架带权利或描述文件 | 官方口径直接判为无效签名 | B06 相关 |
| 未登记 `resource_sealed` | 资源侧改动是否可检出无从说明 | B07 族 |

---

## 7. L4 范围层：哪些设备、哪些地域

### 7.1 输入与规则

输入是 `where.*` 七格：`provisioned_listed`、`all_devices_claim`、`device_id_form`、`dev_mode_required`、`dev_mode_state`、`supervised`、`region`。官方规则：

- **范围有两种互斥写法**：TN3125 第 78 行的 `ProvisionedDevices` 数组与第 87 行的 `ProvisionsAllDevices`。第 86 行给出通道约束："App Store distribution profiles have no ProvisionedDevices property because you can’t run an App Store distribution signed app locally."。在 App Store / TestFlight 通道登记设备清单，是把一个官方不存在的格填上值（`C02`）；在开发 / Ad Hoc 通道不登记设备范围，是把唯一的范围手段空着（`C01`）。
- **设备标识有两种公开形态**：《Locating device identifiers》第 9—13 行给出 Device Hub 里"Copy the device ID that appears in the UDID field"，第 15—21 行给出 Finder 路径，第 26 行给出 Mac 上"Copy the device ID that appears in the Provisioning UDID field"。iOS 类设备的现代 UDID 是 40 位旧形态或 25 位新形态，登记时必须写明是哪一类，否则无法回指到具体设备（`C04`）。
- **注册设备有配额**：《Distributing your app to registered devices》第 6 行 "Consider that your team has a limited number of devices per product family per year for both development and testing."。范围格的口径因此是**年度配额内的集合**，不是"我们想给谁"。
- **Ad Hoc 是一个设备子集**：同篇第 31—34 行，第 32 行 "To create a provisioning profile containing a subset of devices…"，第 34 行 "Testers can run your app only on the devices that you add to the provisioning profile."。
- **Developer Mode 是设备侧前置**：同篇第 29 行 "To run your iOS, iPadOS, visionOS, or watchOS app that you install from an iOS Package Archive, enable Developer Mode on that device."。要求开发者模式的通道而 `dev_mode_state=off` 时，"能跑"是错的（`C05`）。
- **全设备声明只属于特定通道**：第 87 行把 `ProvisionsAllDevices` 限定给 Developer ID 与 In-House。开发或 Ad Hoc 通道声称适用全部设备给 `C03`。
- **替代分发通道有地域与账户双重条件**：《Installing apps through alternative app distribution》第 21 行 "Only users based in Brazil, Japan, or the European Union are able to install apps through alternative app distribution. The country or region of your Apple Account must be set to one of those countries or regions, and you must physically be located there."；第 19 行给出可用范围 "Alternative app distribution is available in Brazil, Japan, and the countries or regions of the European Union. The features of alternative app distribution might vary."。区域格为空的替代分发记录无法定范围（`C06`）。《Learn more about alternative app distribution for developers》页第 191—193 行还记着 iOS/iPadOS 27.2 的安装体验更新与"出境到欧盟以外时可获得 90 天的替代市场与替代分发 App 安装"，说明这一格**随版本与地域变动**，登记必须带核对时刻。

### 7.2 硬事实

范围层是十一条链里唯一一条**主语不完全在开发者手里**的链：`ProvisionedDevices` 由开发者写，但"这台设备算不算在内"由注册配额、设备标识形态与开发者模式状态共同决定；企业通道用 `ProvisionsAllDevices` 放弃了设备清单，代价是范围只能靠组织侧手段约束（第 11 章管理面、第 13 章处置）。

### 7.3 失败形态

| 台账写法 | 后果 | 信号 |
| --- | --- | --- |
| App Store 通道 + `provisioned_listed=yes` | 这一格在该通道的描述文件里根本不存在 | C02 |
| 开发通道 + 设备范围空 | 唯一范围手段未登记，"在哪些机器能跑"无从回答 | C01 |
| `device_id_form=mixed` | 清单里的标识形态混杂，无法逐台回指 | C04 |
| 企业通道 + `all_devices_claim=yes` + 区域格空（替代通道） | 跨地域声明没有官方依据 | C03 / C06 |
| `dev_mode_required=yes` 而 `dev_mode_state=off` | 设备侧前置不满足 | C05 |
| 只写"我们内部所有员工"不写范围实现 | 范围格是空口径，属组织自述 | C01 / D01 |

---

## 8. L5 权利层：授权了什么能力

### 8.1 输入与规则

输入是 `how.*` 四格：`profile_required`、`allowlist_covered`、`restricted_entitlement`、`appstore_resigned`，配合 `what.claim_form`。这一层的规则是整篇最干净的一条，因为它有两个方向明确的官方句：

- **白名单方向**：TN3125 第 111 行 "The entitlements in the profile act as an allowlist. This isn’t the same as the entitlements claimed by the app. To actually claim an entitlement, include the entitlement in the app’s code signature."；第 112 行 "Every entitlement claimed by the app must be in the profile’s allowlist but the reverse isn’t true. It’s fine for the allowlist to include entitlements that the app doesn’t claim."。因此"超出允许清单"是有方向的判定（`H02`），"清单比声明宽"不是问题。
- **通配方向**：第 114 行 "Some entitlements in the allowlist use wildcard syntax. In the above example, `SKMME9E2Y8.*` means that the app can claim any keychain access group with the `SKMME9E2Y8.` prefix. Wildcards don’t make sense in the app’s code signature."；第 133 行给出正向闭合的例子 "Every entitlement claimed by this app is authorized by its profile, and thus iOS allows the app to run."。
- **受限与不受限的边界**：第 141 行 "In contrast, restricted entitlements must be authorized by a provisioning profile. This is an important security feature on macOS. For example, the fact that the keychain-access-groups entitlement must be authorized by a profile means that other developers can’t impersonate your app in order to steal its keychain items."；第 135—139 行给出 macOS 上不需要描述文件授权的那一组（`com.apple.security.get-task-allow`、`com.apple.security.application-groups`、App Sandbox 与 Hardened Runtime 相关项），第 140 行补上其他平台的差异："On other Apple platforms the equivalent to com.apple.security.get-task-allow is get-task-allow and, as with all entitlements on those platforms, must be authorized by a profile."。声明受限权利却记为不需要描述文件授权给 `H01`。
- **不需要描述文件的情形与唯一例外**：第 142 行 "A Mac app that uses no restricted entitlements doesn’t need a provisioning profile. This is true even if the app is distributed on the App Store. The only exception to this rule is TestFlight, which always requires a profile."。
- **App Store 侧权利格由 Apple 重签后的证书决定**：TN3161 第 241 行给出叶子证书名（"The leaf certificate is Apple Mac OS Application Signing. This doesn’t match the certificate from the code-signing identity you used to sign your app prior to submission…"），第 242 行把它推广到全部平台，第 247—248 行给出"你自己不能运行 App Store 分发签名包，macOS 上的例外不受支持且声明受限权利时会失败"。App Store 通道记为重签而时效基准仍写 `profile` 给 `H04`。
- **审核侧对口径的补充**：《App Review Guidelines》第 128 行说明部分权利只给有限用途；第 262 行（2.5.19）把隐藏、休眠、未记录特性与混淆列为可导致下架或终止账户的后果；第 334 行给出冒充口径："Submitting apps which impersonate other apps or services is considered a violation of the Developer Code of Conduct and may result in removal from the Apple Developer Program"。这三条不属于签名机制，但决定了"权利格能不能对外表述"。

### 8.2 硬事实

权利层有一个**不能反推**的性质：允许清单覆盖不等于声明了该权利，声明了该权利也不等于运行时能用（第 02 篇的范围）。所以 `allowlist_covered=full` 只闭合"授权来源"这一格，不闭合"实际能力"。脚本一在这一层只判定**来源是否存在、方向是否越界**，不判定运行时后果。

另外：独立可执行文件不能声明受限权利，因为没地方嵌描述文件（TN3125 第 150 行）。这一条常被写成"我们用命令行工具"然后权利格全空，实为形态决定的必然空缺（第 26 章 N6）。

### 8.3 失败形态

| 台账写法 | 后果 | 信号 |
| --- | --- | --- |
| `restricted_entitlement=yes` + `profile_required=false` | 受限权利必须有授权来源 | H01 |
| 声明项超出允许清单还写 `conclusion=confirmed` | 官方口径下系统不放行 | H02 |
| 允许清单只覆盖部分声明 | 至少一项权利没有来源，但结论写成整体确认 | H03 |
| App Store 通道 + `appstore_resigned=yes` + `expiry_basis=profile` | 最终包不带描述文件，时效基准错位 | H04 |
| 权利格抄自清单申报而非签名输出 | 权利来源与声明内容混用 | H01 / V03（脚本二） |

---
## 9. L6 时效层：两个到期日与两种时间戳

### 9.1 输入与规则

这一层的输入是七格：`when.profile_expiry`、`when.audit_at`、`when.time_source`、`when.expiry_basis`、`when.resign_needed`，加 `who.cert_not_before`、`who.cert_not_after`，再加 `obs.read_at` 一格。规则要分清，因为公开口径给的**不是同一个时钟**：

- **描述文件侧只有到期，没有起始**：TN3125 第 89 行 "Every profile has an ExpirationDate property which limits how long the profile remains valid."；第 91 行给出一个真实读数 `2022-07-23T14:30:34Z`，是从 payload 里 `plutil -extract ExpirationDate raw` 读出来的，也就是说这一格本来就写在描述文件正文里，任何能读描述文件的人都能读到。台账写"有效期一年"而不写具体到期时刻，等于把一格里能填的东西换成了口径。
- **一年是常态，Developer ID 是唯一远端例外**：第 92 行 "This validity period varies by profile type, but it’s typically not more than a year. The exception here is Developer ID profiles, which have an expiration date far in the future."。核对时刻之外四百天以上、通道又不是 Developer ID 或公证直发，脚本一给 `T08`。
- **证书侧是区间而不是单点**：TN3161 第 251 行 "All X.509 certificates have a valid date range. For Apple code-signing certificates that’s typically a year from the date of issue, although the exact duration varies based on the certificate type."。有指纹或 EKU 却没有两个日期格，给 `A05`——因为选身份这一步本身要拿当前时间比对有效期。
- **App Store 通道的时效在提交时刻闭合**：TN3161 第 244 行 "App Store apps are signed with credentials that don’t expire. In contrast, your distribution certificate and provisioning profiles can expire. However, this re-signing means that your credentials only need to be valid at the time that you submit your app."；第 252 行 "When you submit an app to the App Store, it checks that the app’s distribution certificate is currently valid. The App Store then re-signs your app, making it independent of your distribution certificate’s expiry date."。这两句是"两个到期日"里最容易被合并的一对：合并之后，App Store 通道的对象会被持续按描述文件到期判定失效，而公开口径明确说重签后的包与你的到期日无关。
- **Developer ID 直发靠签名内的安全时间戳把判定挪到过去**：第 253 行 "People who install your product expect it to continue working, regardless of your certificate’s expiration date. Apple enables this by embedding a secure timestamp within your code signature. This records when your code was signed. When you run the code, macOS checks that its Developer ID certificate was valid at the time that it was signed."；第 254 行给出三条来源（Xcode 自动加、`codesign --timestamp` 手动加、公证服务保证一定有），第 255—260 行给出读数方式与真实字段 `Timestamp=27 Jan 2024 at 10:52:13`。
- **两种时间戳不能混用**：第 261 行 "Don’t confused the Timestamp and Signed Time fields. The latter is not secured by the Apple timestamp service. Rather, codesign sets this field based on your Mac’s current time. You typically see this field in development-signed code."，第 266 行给出对应读数 `Signed Time=27 Jan 2024 at 10:53:29`。时间基准记成本机签名时刻给 `T03`：这一格只说明那台 Mac 当时认为是几点，不能用来支撑任何"当时还在有效期内"的结论。
- **时间戳服务本身不是可依赖的公开接口**：第 268 行说明 Developer ID 签名必须能联网、走 `timestamp.apple.com` 与 RFC 3161 形态的协议；第 269 行 "ASIDE(important) The Apple timestamp service is reserved for use by code signing. Its name and behaviour are considered implementation details. Don’t ship a product that depends on those details."。因此台账登记时间戳种类是允许的，登记该服务的行为细节作为判据则不被公开口径支持（第 26 章 N7）。
- **形态不合时"是否重签"是一格处置，不是一格结论**：using-the-latest-code-signature-format 第 31 行 "If your app doesn’t have the new signature format, or is missing the DER entitlements in the signature, you’ll need to re-sign the app on a Mac running macOS 11 or later, which includes the DER encoding by default."，第 29 行给出症状式表述 "If your app successfully installs, but doesn’t launch, your app needs to be re-signed with a new provisioning profile."。签名形态不合格（版本低于 20400、只占旧槽、非 DER）却没有 `when.resign_needed`，给 `T06`。

### 9.2 硬事实

- **失效时点分布在三层对象上，只有两层公开**。CA 层的到期时刻是逐张公布的：apple-certificateauthority 第 45—50 行把 Worldwide Developer Relations G2—G6 与 WWDR MP CA 1 的到期 UTC 时刻直接写在证书名里（例如第 49 行 "Worldwide Developer Relations - G6 (Expiring 03/19/2036 00:00:00 UTC)"）。叶子证书层没有这种列表，只能由持有者自己登记 `who.cert_not_after`。第 13 章 L10 会看到 CA 层与叶子层的失效在处置手段上也完全不同。
- **设备侧的链是用签名里内嵌的中间证书建的**。TN3161 第 182 行 "The codesign tool adds the full chain of trust to the CMS structure within the code signature. When you run code on a device, the system uses the intermediate certificates in this CMS structure to build its chain of trust. That means that user devices don’t have to have the code signing intermediate certificates installed."。这意味着中间证书一旦到期，影响面取决于当初签进去的是哪一张，而不是设备上装了什么；`who.chain_root` 与 `who.cert_fp` 两格因此不能省。
- **到期判定必须有第三个时刻**。任何"已过期/未过期"的表述都隐含一个比较基准，脚本一把这个基准显式化为 `when.audit_at`（缺基准给 `T05`）。同一对象若有 `obs.read_at`，读数时刻晚于描述文件到期而结论仍写"已确认"给 `T07`：读回来的只能是历史状态。
- **不写时效基准，失效就无法归因到某一张对象**。`expiry_basis` 三值（profile / certificate / both）分别对应"描述文件到期""证书到期""两侧都算"。证书已过期而基准只记 profile 给 `T04`，两格都缺给 `T09`。这一层的归属问题不是"过没过期"，而是"过期这件事发生在哪张对象上、由谁登记、由谁处置"。

### 9.3 失败形态

| 台账写法 | 后果 | 信号 |
| --- | --- | --- |
| 需要描述文件的通道但 `profile_expiry` 空 | 时效格不存在，失效无从判定 | T01 |
| `profile_expiry` 早于 `audit_at`，结论仍为可运行 | 这条授权已经失效 | T02 |
| `time_source=local_signed_time` 当作有效依据 | 本机时间不受保护 | T03 |
| 证书已过期而 `expiry_basis=profile` | 失效归因写错对象 | T04 |
| 有到期日没有核对时刻 | 任何过期判定都不成立 | T05 |
| 形态不合但未登记是否需要重签 | 分不清"失效"还是"未生效" | T06 |
| `obs.read_at` 晚于到期却写"已确认" | 把历史读数当当前状态 | T07 |
| 非 Developer ID 通道到期日在四百天以外 | 与公开的一年口径冲突 | T08 |
| `expiry_basis` 空 | 两张对象的时效混成一格 | T09 |

---

## 10. L7 失效与校验层：授权什么时候不算了

### 10.1 输入与规则

输入是四格：`state.validate_state`、`state.first_launch_confirm`、`state.still_running`、`when.resign_needed`，配合 `id.channel`。这一层的规则来自"运行闸门"和"授权口径"不是同一个平面这一事实：

- **企业（In-House）通道有首启确认这一道**：apple-platform-security-guide 第 2365 行 "Users need to have the provisioning profile installed to run these apps. This helps ensure that only the organization’s intended users are able to load the apps onto their iPad, iPhone, or Apple Vision Pro. Apps installed through a device management service are implicitly trusted because the relationship between the organization and the device is already established. Otherwise, users have to approve the app’s provisioning profile in Settings. Organizations can also restrict users from approving apps from unknown developers. On first launch of any proprietary in-house app, the device needs to receive positive confirmation from Apple that the app is allowed to run."。四个句子分别给出四个可登记事实：描述文件要装、管理面安装隐式信任、否则要在"设置"里批准、组织可以禁止批准未知开发者应用，而**首启还要一次 Apple 侧肯定确认**。企业通道不登记校验状态给 `V01`；状态为 pending 或 failed 却没有首启确认格给 `V02`。
- **设备侧只有一个布尔，且它只讲"能不能跑"**：installedapplicationlistitem-fields 第 21 行 "IsValidated (optional) boolean — If true , the app is valid and can run on the device. If the app is enterprise-distributed and unvalidated, it won’t be able to run until validation has occurred."。这一格是 L8 的观测输入，也是本层的判定输入，但它不含主体、不含原因、不含时刻，因此不能反过来写成"授权由谁给出"。
- **校验可以由管理面强制重做，但命令面很窄**：validate-applications-command 第 21 行 "ValidateApplicationsCommand — The command to force validation of developer and universal provisioning profiles for enterprise apps."；第 14 行设备通道为 "iOS, Shared iPad, tvOS, visionOS"（不含 macOS 与 watchOS），第 18 行要求访问权 `AllowAppInstallation`。同一页第 25 行还列出 "Install Enterprise Application — Install an enterprise app on a device."，而那个命令的设备通道在第 18 行只写 macOS——这两条放在一起是本层最有用的一个读数：**能让企业应用强制重校验的通道，和能装企业应用的命令通道，不是同一组平台**。
- **运行时校验的粒度是内存页，不是包**：TN3126 第 138 行 "This per-page architecture allows the kernel to check each page as it’s loaded into memory. … the kernel may choose to verify the hash of the page’s contents. This allows the system to run a code-signed executable and check its code signature lazily (in the computer science sense of that word)."，第 8 行同样把这件事称作 "code signing’s lazy per-page signature checking"。校验发生在页被载入或触发页错误的那一刻，已经加载的页不会被逐页重查，所以"授权失效"与"仍在运行"是可以并存的真实状态；这一格就是 `state.still_running`（过期却未登记是否在跑给 `V06`）。
- **本机校验命令不构成设备侧结论**：using-the-latest-code-signature-format 第 35 行 "ASIDE(important) Only re-sign apps from the command-line as a last resort to update your code signature to include the DER entitlements. Re-signing apps from the command-line is not supported for iOS, iPadOS, tvOS, visionOS, and watchOS."；TN3161 第 247—248 行说明 App Store 分发签名的包你自己跑不起来。因此脚本一不查 `codesign --verify`、不查 `security`、不查任何设备命令，本层只做**台账格与公开口径的一致性判定**。

### 10.2 硬事实

- **"失效"在公开口径里至少有四种不同东西**：① 未生效（形态不合，第 03 章 L3，处置是重签）；② 到期（描述文件 `ExpirationDate` 或证书有效期止，第 9.1 节）；③ 吊销（证书身份被撤销，L10）；④ 校验未通过（企业通道首启没有得到肯定确认）。这四种在设备上的可见表现可以完全相同（应用打不开），但在归属上分别落在开发者、Apple 签发侧、账号管理员与设备用户四类责任方。台账只有一格"是否可用"时，这四种会被压成同一个结论。
- **设备侧没有"当前授权状态"这一格**。管理面能给的最接近读数是 `IsValidated` 与 `AdHocCodeSigned` 一类布尔，它们说明形态与可运行性，不说明是谁签的、依据哪张证书、什么时候到期。第 04 章 L1 与本章合起来给出本文的核心不对称：**执行侧判定充分，但归属信息不输出；归属信息齐备的台账又不参与执行判定**。
- **隐式信任不等于身份可读**。guide 第 2365 行说管理面安装的应用是隐式信任的，这只是解释"为什么不需要用户在设置里批准"，不给任何签名身份读数；把它写成"MDM 能核对签名"属于跨层换算，脚本二在 P 族与 V 族都拦。

### 10.3 失败形态

| 台账写法 | 后果 | 信号 |
| --- | --- | --- |
| 企业通道 + `validate_state` 空 | 首启确认与管理面重校验都无读数 | V01 |
| `validate_state=pending` 且首启确认格空 | 不能运行却不知道卡在闸门哪一步 | V02 |
| 到期已判定但 `still_running` 未登记 | 漏掉"过期仍在跑"这一常见真实状态 | V06 |
| 形态不合却未登记是否需要重签 | 把未生效记成失效 | T06 |
| 用本机 `codesign --verify` 通过写成设备侧结论 | 两个平面之间没有公开换算 | V01 / O01 |
| 只写"应用打不开"不分四类 | 失效归因给错责任方 | T04 / V02 |

---

## 11. L8 观测平面层：这一格是谁读回来的

### 11.1 输入与规则

输入是四格：`obs.plane`、`obs.field_read`、`obs.command_name`、`obs.read_at`。脚本二另有一个平面枚举（11 值）与"平面 × 要素类别"配对表，两边对齐的是同一条规则：**一个平面只能读回它被建模的格**。

- **描述文件清单只给三格**：provisioningprofilelistitem-fields 第 5—7 行依次为 "ExpiryDate (optional) date — The expiry date of the provisioning profile."、"Name (required) string — The display name of the provisioning profile."、"UUID (required) string — The unique identifier for the provisioning profile."。没有 Team ID，没有证书，没有设备清单，没有权利清单。把 `team_id` 或"证书列表"记成这一平面的读数给 `O02`（脚本二对应 `P01`）。
- **读这一张清单本身是一项被单独授权的能力**：provisioning-profile-list-command 第 14 行设备通道覆盖六个平台、第 18 行要求访问权 `AllowProvisioningInspection`；installed-application-list-command 第 18/22 行则要求 `AllowQueryApplications`。因此"能不能读回这一格"在管理面上有配置前提，观测通道为空却给出确认结论给 `O01`。
- **安装与移除走命令面，且要求另一个访问权**：install-provisioning-profile-command 第 17 行设备通道为六个平台、第 21 行要求 `AllowProvisioningInstallationRemoval`，第 12 行还写明 "No error occurs if the provisioning profile is already present."——幂等成功意味着响应本身不告诉你装的是哪一份。
- **声明式平面没有描述文件这个对象**（三处一致的负发现）：devicemanagement-declarations 第 13 行列 `AppManaged`、第 22—23 行列 `LegacyInteractiveProfile` 与 `LegacyProfile`，整个清单里没有描述文件声明；profile-specific-payload-keys 第 46 行有 "CertificateRevocation — The payload that configures certificate revocation checking."，但没有描述文件正文键；status-items 第 61 行有 "StatusSecurityCertificateList — The status item that lists the device’s managed certificates."，但没有描述文件状态项。把描述文件对象挂在声明式平面给 `O03`（脚本二对应 `P02`）。
- **管理面对"强制重校验"只回标准响应键**：validateapplicationsresponse-fields 第 5—14 行列出 `CommandUUID`、`Status`、`ErrorChain`、`UDID` 等，没有任何逐应用判定格。记为已读数但平面为空给 `P04`（脚本二）；这也就是 `O01` 的另一面。
- **安装应用清单给的是形态布尔与来源串**：installedapplicationlistitem-fields 第 5 行 "AdHocCodeSigned (optional) boolean — If true , the app is ad-hoc code signed."、第 10 行 "DistributorIdentifier (optional) string — The marketplace hosted application’s distributor ID."、第 25 行 "Source (optional) string — The source of the application. When Declarative Device Management manages the app, this value is Declarative Device Management ."。用形态布尔闭合身份结论给 `O04`。

### 11.2 硬事实

- **观测平面能证明的唯一事情是"这一格被读到过"**。它不证明授权成立，也不证明授权来自谁。本层把这一点变成两格的分工：`obs.plane` 说明从哪儿读，`obs.field_read` 说明读到的是哪一格，缺后者时脚本一不允许用平面来支撑 `doc.conclusion=confirmed`。
- **管理面读数天然带时刻，必须登记**。`obs.read_at` 是本层与 L6 的接缝：读数时刻晚于描述文件到期而结论写"已确认"给 `T07`；这是所有跨层换算里最常发生的一次，因为清单类响应看起来总是"当前状态"。
- **三套口径各自只在自己的平面可读**。授权对象口径的格在描述文件本体里（TN3125 第 38—110 行逐个给出属性名与读取方式），平台执行口径的格在签名结构里（TN3126 第 69 行的代码目录哈希、TN3127 第 48—57 行的 requirement），管理面口径的格在命令与声明的建模里。第 12 章 L9 把这件事按通道摊开，第 3 章词表 C 把取值域列全。

### 11.3 失败形态

| 台账写法 | 后果 | 信号 |
| --- | --- | --- |
| 观测通道为空却写"已确认" | 结论没有可读回它的平面 | O01 |
| 把 Team ID / 证书列表记成管理面读数 | 描述文件清单只有三格 | O02 / P01 |
| 描述文件对象挂在声明式平面 | 声明式侧未建模该对象 | O03 / P02 |
| 用 `AdHocCodeSigned` 一类布尔闭合身份 | 形态不等于主体 | O04 |
| 要素读数记在公告侧 | 公告词表只给组件与 CVE | P03 |
| 记为已读数但平面为无通道 | 响应只回标准 ack 键 | P04 |
| 类别与平面不匹配的其他组合 | 这一格不属于该平面可读集合 | P05 |
| `obs.read_at` 晚于到期仍写"已确认" | 把历史读数当当前状态 | T07 |

---

## 12. L9 通道差异层：同一要素在不同通道的可得性

### 12.1 输入与规则

脚本二读三个只读输入：要素清单（每行恰好八列：`标识,通道,要素,登记状态,读数平面,词表归属,引用,对外`）、通道能力表（`通道,要素,可得性`）、公告词表（CSAF 导出的 `cve<TAB>component`）。通道取 9 个真实值：`app_store`、`testflight`、`ad_hoc`、`development`、`enterprise`、`developer_id`、`alternative_marketplace`、`web_distribution`、`notarized_direct`；要素取五类共 22 项：identity 类 6 项（signing_identity、cert_chain_root、eku_code_signing、cert_validity、cert_revocation、team_id）、profile 类 9 项（app_id、bundle_id_claim、provisioned_devices、provisions_all_devices、profile_expiry、profile_name_uuid、entitlement_allowlist、der_profile、developer_cert_list）、exec 类 4 项（cdhash、designated_requirement、nested_signature、signature_format_version）、device 类 2 项（dev_mode_state、first_launch_confirmation）、mgmt 类 1 项（validate_state）。可得性四档各有明确含义：`required`＝该通道按公开口径必须有这一格；`optional`＝可以有但不是判据；`not_applicable`＝公开口径明确这一格在该通道不存在；`undocumented`＝公开口径既没给存在也没给不存在。第四档是本层存在的理由：**分不清"不该有"和"没说"，差集就会把文档空白算成违规**。

对齐的规则：

- App Store 分发描述文件按公开口径根本没有设备清单格：TN3125 第 86 行 "App Store distribution profiles have no ProvisionedDevices property because you can’t run an App Store distribution signed app locally."。这一格在 App Store / TestFlight 通道是 `not_applicable`，登记了读数即冲突（`D03`）。
- "适用于所有设备"只有两类描述文件有：第 87 行 "Developer ID and In-House (Enterprise) distribution profiles have the ProvisionsAllDevices property, indicating that they apply to all devices."。
- 权利清单方向、通配方向与到期格属于 profile 类，出处分别是第 94—110、111—114、89—92 行；`der_profile` 的口径来自 using-the-latest-code-signature-format 第 29 行与第 12 行；`cdhash` 来自 TN3126 第 69 行；`designated_requirement` 与 `signature_format_version` 来自 TN3127 第 48—57、15—19 行；`dev_mode_state` 来自 enabling-developer-mode-on-a-device 第 5—6 行；`validate_state` 与 `first_launch_confirmation` 来自 guide 第 2365 行与 installedapplicationlistitem-fields 第 21 行。`team_id` 的公开定义在 guide 第 2362 行。
- 能力表本身必须逐通道建模：一条有效行都没有时差集不可计算，给 `C06`；清单里出现的通道在能力表一行都没有，给 `D04`——这不代表该通道有问题，代表**判据未建模**，两者在报告里必须写成不同的结论。

### 12.2 通道 × 要素类矩阵

下表把 22 项按类摊到 9 条通道上（格值是可得性档位；`—` 表示该格在该通道未公开文档化，即 `undocumented`）。它不是合规清单，而是差集计算的基准：脚本二把它编码成能力表输入，台账缺哪一格、多记哪一格都由它决定。

| 通道 | identity 类 | profile 类 | exec 类 | device 类 | mgmt 类 |
| --- | --- | --- | --- | --- | --- |
| `app_store` | required | required，但 `provisioned_devices` 为 not_applicable | required | not_applicable | not_applicable |
| `testflight` | required | required；TN3125 第 142 行使 TestFlight 成为"无受限权利也要描述文件"的唯一例外 | required | not_applicable | not_applicable |
| `ad_hoc` | required | required，含 `provisioned_devices` | required | not_applicable | — |
| `development` | required | required，含 `provisioned_devices` | required | required | — |
| `enterprise` | required | required，含 `provisions_all_devices` | required | — | required |
| `developer_id` | required | required，`profile_expiry` 允许远端 | required | not_applicable | — |
| `alternative_marketplace` | required | required | required | — | — |
| `web_distribution` | required | required | required | — | — |
| `notarized_direct` | required | — | required | not_applicable | — |

矩阵里三处值得单独说明。**其一**，`device` 类在 `development` 之外没有稳定的公开口径：开发者模式只在开发通道被明确要求，而首启确认只在企业通道被明确写出，因此其余通道只能进 `—` 而不是 `not_applicable`。**其二**，`mgmt` 类唯一一项 `validate_state` 只对企业通道 required，因为强制重校验命令的公开定义就是"developer and universal provisioning profiles for enterprise apps"。**其三**，`notarized_direct` 的 profile 类整行进 `—`：公开口径没有把描述文件作为公证直发的判据来描述，把空档写成"不需要"属于越界结论。

### 12.3 硬事实

- **同一要素在多通道口径不同，但主语不换**。`cert_validity` 在 App Store 通道的实际作用止于提交时刻（TN3161 第 244、252 行），在 Developer ID 通道则由签名内的安全时间戳把判定挪到签名时刻（第 253 行）；两种情况下"签发这张证书的账号"仍是同一个责任方。通道差异改变的是**失效由谁承担**，不改变主体。
- **引用格必须能回指**。脚本二要求第八格（引用）三选一成立：CVE 标识、文档行号引用（`TNxxxx:行` 或 `A/文件:行`），或者明确写 `none`。全部 required 要素都没有可回指格给 `T02`；引用形似私钥、描述文件正文或设备绝对路径给 `T01`；形态两者都不是给 `T04`。同一通道同一要素在对象之间既有"已读数"又有"明确不存在"给 `T03`：这是登记口径未统一，不是数据冲突。
- **一次运行只有一条分发通道**。同一对象登记两个通道给 `D06`。这一条看似形式要求，实际是本报告的判定前提：主键是"一次运行授权"，两条通道意味着两个不同的失效时点与两类责任方被合并成一行。

### 12.4 失败形态

| 台账写法 | 后果 | 信号 |
| --- | --- | --- |
| 能力表行数不足、通道整列缺失 | 该通道判据未建模，缺哪一格算不出 | D04 / C06 |
| required 要素明确记为不存在 | 通道判据与公开口径直接冲突 | D01 |
| required 要素记为未登记 / 完全没有登记行 | 两种覆盖空洞 | D02 / D05 |
| not_applicable 要素被记为已读数，或 required 记为不适用 | 把文档空白当许可 | D03 |
| 同一对象两个通道 | 一次运行有两条授权来源 | D06 |
| 清单/能力表取值域不合 | 词表本身失控 | S01—S09 / C01—C05 |
| required 要素全部无标识引用 | 差集结论无法回指 | T02 |
| 同一通道同一要素两种口径 | 口径漂移 | T03 / S09 |

---

## 13. L10 复核与处置层：撤销之后做了什么

### 13.1 输入与规则

输入是四格：`state.revoke_action`、`state.revoke_recorded`、`state.delete_verified`、`state.revocation_basis`。这一层的规则很短，因为公开口径给得很短：

- **吊销是一个需要留痕的动作，不是结论**：`state.revoke_action=revoked` 而 `revoke_recorded` 不为 yes 给 `V03`；`revoke_recorded=yes` 而 `delete_verified` 不为 yes 给 `V04`。两个动作各有一个官方落点：账号侧撤销与本地删除。sharing-your-teams-signing-certificates 第 39—41 行给出后者：小节名是 "Delete a revoked certificate"，正文 "Control-click the certificate that you want to delete in the certificates management panel … Xcode prompts you for confirmation, and removes the certificate and corresponding private key from your keychain."，紧接第 41 行 "You can only delete certificates that you or a team member revoke in your developer account."——**能删的前提是已经在账号里撤销过**，因此这两格存在官方认可的先后关系，不能只记后一格。
- **公开口径只给吊销清单的存在，不给设备侧何时可见**：apple-certificateauthority 第 24 行 "Apple established the Apple PKI in support of the generation, issuance, distribution, revocation, administration, and management of public/private cryptographic keys that are contained in CA-signed X.509 Certificates."；第 51—56 行列出五张 CRL（Apple Inc. Root CRL、Apple Computer, Inc. Root CRL、Software Update CRL、Timestamp CRL、Worldwide Developer Relations CRL）。管理面这边能读回的只有配置项：profile-specific-payload-keys 第 46 行 "CertificateRevocation — The payload that configures certificate revocation checking."，status-items 第 61 行的 `StatusSecurityCertificateList` 只列被管理的证书。因此把依据记成"应当已生效"给 `V05`——这不是保守，是这一格确实没有读数。
- **没有"签名与分发授权链"的吊销口径**（负发现）：TN3161 全文不出现 revoke / revocation / CRL 任何一词（已按关键词逐条检查），它给的是证书有效期、时间戳与链构建；TN3125 通篇不描述描述文件被撤销的机制，只描述到期格。也就是说：**代码签名侧的叶子证书吊销路径没有公开文档化**，第 26 章把它列为主缺口 N1。

### 13.2 硬事实

- **证书有效期止早于核对时刻而没有任何续签或吊销处置记录，本身就是一个信号**（`A06`）。这一条与 L6 的 `T02` 不同：`T02` 问的是描述文件时效，`A06` 问的是签发侧对象的处置是否闭环。归属层需要这两格分开，因为它们的责任方不同——一个是运营描述文件的人，一个是持有签名身份的人。
- **删掉本地副本不等于该身份不再被使用**。导出身份一旦被他人持有，删除动作只发生在你这一侧；sharing 第 33 行 "If you have a certificate but not the corresponding private key, you can’t use that certificate for code signing or generating other digital signatures. You must have the complete digital identity to sign code and other digital objects." 说明"是否还能签"取决于私钥在哪里，而不是钥匙串里还有没有那张证书。因此 `delete_verified` 与 `who.key_custody` 要一起读。
- **设备侧的"还在跑"不能由处置动作推断**。L7 的 `state.still_running` 与 `V06` 在这里重新出现：吊销留痕齐备但运行时状态未登记，归属表述只能写到"该身份已被撤销"，不能写"这段代码已停止运行"。
- **引用格在处置层最容易被省掉**。缺 `doc.source` 或 `doc.line_ref` 给 `D01`（每条判定都附），因为处置结论的争议几乎都发生在"依据哪一条公开口径"上，而不是发生在动作本身。

### 13.3 失败形态

| 台账写法 | 后果 | 信号 |
| --- | --- | --- |
| `revoke_action=revoked` 但无留痕格 | 动作未记录，责任链断在中间 | V03 |
| 有留痕但删除未验证 | 只闭合了本地一侧 | V04 |
| `revocation_basis=assumed` | 依据是推测，设备侧可见时点无读数 | V05 |
| 证书过期且无处置记录 | 签发侧时效未闭环 | A06 |
| 处置结论缺来源与行号 | 无法回到公开文档核对 | D01 |
| 撤销后未登记是否仍在运行 | 把"身份已撤销"写成"代码已停" | V06 |

---
## 14. L11 公告回查层与缺陷类型学 P1—P14

### 14.1 输入与规则

这一层有两个用途：**把公告当作可回查的外部锚点**，以及**把前十一层的失败形态收成一套可命名的缺陷类型学**。

公告侧的输入只有两列（脚本二的第三个只读输入：`cve` 与 `component`），规则因此很短：

- 公告能给的是**组件名与标识**，不是授权要素。归档的三份 CSAF 公告（`B/149041.json`、`B/149227.json`、`B/149230.json`，标题分别是 iOS 26.7 / 26.7.2 / 27.2 的安全内容说明）导出 392 行 CVE、101 个去重组件名；把这 101 个组件名按 15 个签名与分发授权词形（sign、trust、cert、provision、profile、entitle、codesig、notariz、revok、gatekeep、launchd、sandbox、amfi、secureboot、kernel）逐一匹配，只有 `kernel` 命中 1 个（Kernel）。也就是说：**这份词表里没有"签名"这个组件**，任何把授权要素读数挂到公告平面的写法都会撞上 `P03` 与 `X04`。
- 标识必须回指到词表内。引用了一个不在公告词表内的 CVE 给 `X01`；引用的组件名归一化后不在词表内给 `X02`；词表整体不可用（无可用行）给 `X03`；词表可用、签名授权词形命中为 0、却仍有授权要素读数挂在公告平面给 `X04`；挂了公告平面却没有标识给 `X05`。
- 还有一条来自归档内部的定向规则：`X06` 专门拦"引用指向 MDM 的 Identity management 页"这一写法。那一页讲的是通行码与平台单点登录，和签名身份无关，但它的标题最容易被子串匹配误当作身份来源，因此单独立码。

引用锚点在本报告里的正确用法只有一个方向：**用它把一条台账判定钉回公开文档**（`doc.source` + `doc.line_ref`，缺任一格给 `D01`），而不是用它证明"某签名机制有漏洞"。

### 14.2 缺陷类型学 P1—P14

十三篇以后各层的失败形态可以合并成 14 种缺陷类型。类型的价值在于**它规定了归属结论最多能写到哪一步**——左列是台账里看得见的特征，右列是这种特征允许的表述上限。

| 类型 | 特征 | 归属结论能写到 | 信号 |
| --- | --- | --- | --- |
| P1 授权主语缺失 | 通道与签名者类型两格空，或观测平面与结论同时缺 | 只能写"有一条运行记录"，不能写"谁被授权" | A01 / J4 |
| P2 主体与身份错位 | 只有 Team ID 没有证书指纹；App ID 与 `TeamID.bundleID` 不符 | 能写团队级主语，不能写证书级失效 | A12 / B01 / H02 |
| P3 签发路径与私钥矛盾 | 云端托管却记私钥自持；导出身份与口令同渠道；保管有位置没持有人 | 泄露事件的归属可判，签发事件不可判 | A02 / A03 / A04 / A11 |
| P4 链与有效期不合 | 链根非 Apple Root CA；EKU 不含代码签名；有效期止已过且无处置 | 能定"签名动作当时不成立"，不能定"包有问题" | A06 / A07 / A08 / A09 |
| P5 权利方向越界 | 受限项记为无需描述文件；声明超出允许清单；部分覆盖却给确认 | 能定"系统不该放行"，运行时后果另判 | H01 / H02 / H03 |
| P6 权利来源与申报混用 | 权利格抄自清单申报而非签名输出；App Store 重签后仍按描述文件判时效 | 能定来源格错位，不能定能力格 | H01 / H04 |
| P7 形态代际未闭合 | 非 DER、只占旧槽、代码目录版本低于 20400、嵌套未逐个签 | 属"未生效"而非"失效"，处置是重签 | B03 / B04 / B05 / B06 / T06 |
| P8 范围格不存在却被引用 | App Store 通道登记设备清单；全设备声明落在无此格的通道；标识形态混杂 | 范围表述整体作废 | C01 / C02 / C03 / C04 |
| P9 设备侧前置未登记 | 需要开发者模式但状态空；企业通道校验状态或首启确认空 | 能定"闸门未过"，不能定授权主体 | C05 / V01 / V02 |
| P10 时效基准混用 | 两到期日写成一格；缺核对时刻；有到期无基准 | 失效归因给错对象（证书侧/描述文件侧） | T01 / T02 / T04 / T05 / T09 |
| P11 时间戳类型误用 | 以本机 `Signed Time` 作为有效依据；依赖时间戳服务细节 | "当时有效"这类回溯表述不成立 | T03 / T08 |
| P12 处置未闭环 | 记为已吊销无留痕；有留痕未验证删除；依据写"应当已生效"；未登记是否仍在跑 | 只能写"账号侧动作已发生" | V03 / V04 / V05 / V06 |
| P13 观测平面越界 | 管理面读身份；声明式挂描述文件对象；用形态布尔闭合身份；读数时刻晚于到期 | 结论降级为"读到过这一格" | O01 / O02 / O03 / O04 / T07 / P01—P05 |
| P14 公告归属悬空 | 要素挂公告平面；标识不在词表；组件词表零命中仍有读数 | 缺陷不能归到签名组件 | X01 / X02 / X03 / X04 / X05 / X06 |

类型学有两处刻意不做的事。**其一**，不给 14 种类型排严重级：P1 与 P13 在运营上后果完全不同，但都属于"结论不能外发"，脚本一用 J4/O01 表达而不是用等级。**其二**，不把类型映射到责任方以外的处置动作：处置动作是第 20 章指标层的事，映射会把归属结论变成工单口径。

### 14.3 两个可用锚点，都不能当作结论

归档语料里只有两行真正落在授权链上：

- `B/149041.json` 第 4774—4784 行的 CVE-2026-86881，组件 `Security`（第 4775 行），影响句（第 4779 行）"An attacker with a compromised intermediate certificate authority may be able to issue certificates with arbitrary extended key usages"，解决句（第 4784 行）"A certificate validation issue was addressed with improved certificate validation."。这一行对应本文 L1—L2 的中间证书与 EKU 两格（TN3161 第 147—150、159—173 行；guide 第 2360 行），它是公开语料里唯一把"中间 CA"与"扩展密钥用法"一起写出来的读数，因此适合作为 `who.chain_root` / `who.eku_codesign` 两格的回查锚点。
- CISA KEV 里唯一一条 Apple 侧与证书校验相关的记录：CVE-2023-41991，`Multiple Products`，加入日期 2023-09-25，名称 "Apple Multiple Products Improper Certificate Validation Vulnerability"。

除这两行外，公告语料给的都是**相邻面**：影响句含 "bypass Gatekeeper" 的 1 行属于 `copyfile`，含 "certificate validation" 的 2 行属于 `Security`（分别来自 `B/149227.json` 与 `B/149230.json`），解决句含 `entitlement` 的 10 行分布在 Accounts、App Intents、Apple Intelligence、MediaRemote、Photos Storage、Power Management、Safe Browsing、SpringBoard 八个组件；含 `signature` 的 1 行是 `Heimdal` 的 "An issue with signature validation was addressed with improved checks."。这 14 条 `arbitrary code` 影响句里没有任何一条的组件名属于签名或分发授权对象。

因此本层的结论上限是：**公告可以回查"哪一层有过缺陷"，不能回查"你的这条授权是否成立"**。后者只有台账与 `doc.line_ref` 能支撑，这正是脚本二把 X 族列为阻断而非提示的原因。

---

## 15. 归属矩阵：层 × 责任方 × 形态 × 证据

主键是"一次运行授权"，因此矩阵的每一行都回答同一组问题：**这一格的读数来自谁、它能证明到哪一步、证据落在哪个公开锚点**。表中"证据落点"一律用归档相对路径加行号，脚本一要求每一格都能以 `doc.source` + `doc.line_ref` 复现（缺则 `D01`）。

| 层 | 第一责任方 | 可归属形态 | 公开证据落点 | 主信号族 |
| --- | --- | --- | --- | --- |
| L1 身份 | 签名身份持有人 / 团队管理员 | 谁签的、签给哪个主体 | guide 第 2360—2362 行；TN3125 第 67—76 行；sharing 第 18—19、33 行 | A09 / A10 / A12 / B01 |
| L2 签发 | 证书签发方（Apple 侧）与请求发起方 | 证书从哪条路径签发、私钥在哪 | TN3161 第 102—125、147—173、181 行；sharing 第 18—19 行 | A01—A08 / A11 |
| L3 形态 | 构建执行者 | 授权对象的编码与代际 | 最新格式第 6、12、14、29—36 行；TN3126 第 69 行；TN3127 第 48—57 行 | B02—B07 / T06 |
| L4 范围 | 描述文件申请者与设备管理员 | 在哪些设备、哪些区域 | TN3125 第 77—78、86—87 行；locating 第 5—12 行；alt-dist 第 19、21 行；EU 页第 142、190、193 行 | C01—C06 |
| L5 权利 | 权利声明者（应用侧）与授权者（描述文件侧） | 授权了什么能力 | TN3125 第 94—114、133、141—142、150 行；TN3161 第 241、247—248 行；审核指南第 128、262、334 行 | H01—H04 |
| L6 时效 | 描述文件持有者与证书持有者（两个主体） | 什么时候不算了、以哪张对象为准 | TN3125 第 89—92 行；TN3161 第 244、250—269 行；PKI 页第 45—50 行 | T01—T05 / T08 / T09 |
| L7 失效与校验 | 设备（闸门）与 Apple 确认服务 | 是否被放行、卡在哪一步 | guide 第 2365 行；TN3126 第 138 行；installedapplicationlistitem-fields 第 21 行；validate-applications-command 第 14、18、21 行 | V01 / V02 / V06 |
| L8 观测 | 管理平面（MDM 服务器与访问权配置） | 这一格由谁读回、何时读回 | provisioningprofilelistitem-fields 第 5—7 行；provisioning-profile-list-command 第 14、18 行；declarations 第 13—23 行；payload 键第 46 行；status 项第 61 行 | O01—O04 / T07 / P01—P05 |
| L9 通道差异 | 通道选择者（构建与发布决策） | 同一要素在本通道该不该有 | TN3125 第 86—87、142、145—149 行；TN3161 第 233—249 行；install-enterprise-application-command 第 18 行 | C01—C06 / D01—D06 / T01—T04 |
| L10 处置 | 账号管理员与本地钥匙串持有者 | 撤销之后做了什么 | sharing 第 39—41 行；PKI 页第 24、52—56 行；载荷键第 46 行 | V03 / V04 / V05 / A06 / D01 |
| L11 公告回查 | 组件所有者（Apple 侧）与回查者（本文读者） | 哪一层有过缺陷 | `B/149041.json` CVE-2026-86881；KEV CVE-2023-41991；`C/advisory-entries.tsv` 全表 | X01—X06 / P03 |
| 判定层 | 台账维护者 | 这条记录能不能外发 | 脚本一第 341—349 行；脚本二第 333—341 行 | J1—J4 / Q1—Q4 |

矩阵里有三件事值得单独指出。**第一**，L2 与 L6 的责任方不同：签发路径的决定发生在账号里，而时效判定的失效时刻发生在两张不同对象上，把两者写成同一个"开发者"会掩盖续签与换身份这两类不同处置。**第二**，L8 的责任方是管理平面配置者而不是开发者：三格回读（`provisioningprofilelistitem-fields` 第 5—7 行）是平台能力上限，任何"管理面读不到签名身份"的表述都应写成平面建模事实，而不是某个团队的失误。**第三**，L11 一行是**外生**的：公告只在你主动回查时参与归属，它不进入任何判定链，这也是脚本二把 X 族与 D 族分开列出的原因。

---

## 16. 公开读数：这条链路上能数出来的十八件事

以下 18 条是本报告写作时可复核的公开读数，全部给出计数对象与来源。除注明外，文档行号指向本报告归档的纯文本抽取件；计数由 `C/readings-14.sh`、`C/readings-14b.sh` 在本地离线产出，结果见 `C/readings-14.txt`。

1. **四篇技术说明的体量**：TN3125（描述文件）207 行、TN3126（哈希）270 行、TN3127（requirement）200 行、TN3161（证书）277 行。四篇合计 954 行构成本报告 L1—L3 与 L5—L6 的规则主体。
2. **TN3125 的五问结构**：`# The who` / `# The what` / `# The where` / `# The when` / `# The how` 五个小节标题分别落在第 37、66、77、88、93 行。台账命名空间 `who./what./where./when./how.` 直接来自这五个标题，另外四个命名空间（`id./state./obs./doc.`）是本文为了归属表述补的。
3. **描述文件清单只有三格**：`ProvisioningProfileListItem` 全文三个字段（`A/provisioningprofilelistitem-fields.txt` 第 5—7 行）：`ExpiryDate`（optional）、`Name`（required）、`UUID`（required）。
4. **安装应用清单有 22 格，其中签名相关读数只有布尔与来源**：`InstalledApplicationListItem` 第 5—26 行共 22 个字段；与签名直接相关的只有 `AdHocCodeSigned`（第 5 行）、`IsValidated`（第 21 行）、`DistributorIdentifier`（第 10 行）与 `Source`（第 25 行）。
5. **管理面强制重校验的响应不给逐应用判定**：`ValidateApplicationsResponse` 第 5—14 行列出 10 个键，全部是命令回执类（`CommandUUID`、`Status`、`ErrorChain`、`UDID`、`NotOnConsole` 等），没有"某应用是否有效"这一格。
6. **声明式管理没有描述文件对象**：`devicemanagement-declarations` 第 13—23 行只列 `AppManaged`、`LegacyInteractiveProfile`、`LegacyProfile`，全清单 53 条声明类型中 `provision` 出现次数为 0。
7. **配置负载键表有证书吊销、没有描述文件**：`profile-specific-payload-keys` 中以 `Certificate` 开头的键有 7 项（含第 46 行 `CertificateRevocation`），全表 `provision` 出现次数为 0。
8. **状态项表同理**：`status-items` 共 65 个状态项，其中第 61 行 `StatusSecurityCertificateList` 只列被管理的证书，`provision` 出现次数为 0。
9. **两条命令的可用平台不对称**：`Install Provisioning Profile` 设备通道为六平台（第 17 行）并要求访问权 `AllowProvisioningInstallationRemoval`（第 21 行）；`Validate Applications` 设备通道只有四平台（第 14 行，iOS、Shared iPad、tvOS、visionOS）并要求 `AllowAppInstallation`（第 18 行）；`Install Enterprise Application` 的设备通道只写 macOS（第 18 行）。
10. **清单读取本身是一项被单独授权的能力**：`Provisioning Profile List` 要求访问权 `AllowProvisioningInspection`（第 18 行）；`Installed Application List` 要求 `AllowQueryApplications`（第 22 行）。
11. **吊销路径在三篇技术说明里都不存在**：TN3161 全文（277 行）不含 revoke / revocation / CRL 任一子串；TN3125（207 行）与 TN3127（200 行）同样为 0。
12. **CA 层失效时点是公开的，叶子层不是**：Apple PKI 页第 45—50 行逐张给出 Worldwide Developer Relations G2—G6 与 WWDR MP CA 1 的到期 UTC 时刻；第 51 行给出 "Certificate Revocation Lists" 标题，第 52—56 行列出 5 张证书吊销清单；第 24 行说明 PKI 覆盖生成、签发、分发、吊销、管理与治理。叶子证书没有对应的公开列表。
13. **设备侧链来自签名内嵌的中间证书**：TN3161 第 182 行说明 `codesign` 把完整信任链加进签名 CMS 结构，设备用其中的中间证书建链，因此用户设备不需要预装代码签名中间证书。
14. **两种时间戳的公开读数格式不同**：TN3161 第 258 行给 `Timestamp=27 Jan 2024 at 10:52:13`，第 266 行给 `Signed Time=27 Jan 2024 at 10:53:29`，第 260—261 行明确后者不受时间戳服务保护、由本机时间决定。
15. **公告语料的授权词形命中为 0**：392 行 CVE、101 个去重组件名，按 15 个签名/授权词形匹配只有 `kernel` 命中 1；九种授权对象短语（provisioning profile、notariz、team id、developer id、enterprise program、certificate revocation、revocation list、signing identity、app review）在整行匹配中命中 0 行。
16. **公告里与签名校验直接相关的解决句只有 2 条**：`Heimdal` 的 signature validation 1 条（`B/149230.json`）与 `Security` 的 certificate validation 1 条（`B/149041.json`）；`signing`、`trust`、`provisioning`、`revoked`、`chain of trust`、`code-signing` 六个词形命中 0。影响句含 `bypass Gatekeeper` 1 条（`copyfile`）、含 `certificate validation` 2 条（`Security`）、含 `arbitrary code` 14 条。
17. **在野利用目录的对应读数**：CISA KEV 目录版本 2026.10.30，共 1766 条，Apple 侧 95 条；按记录级关键词计数，`bypass` 9、`kernel` 26、`sandbox` 3、`certificate` 1、`gatekeeper` 1、`signatur` 1，`signing`、`trust`、`provisioning`、`entitlement`、`revoc`、`notariz` 全为 0；唯一匹配记录是 CVE-2023-41991（Multiple Products，2023-09-25，Improper Certificate Validation）。
18. **本报告两个脚本的信号码规模**：脚本一发出 64 个码（60 个阻断资格 + J1—J4 四档判定），脚本二发出 44 个码（40 个信号 + Q1—Q4 四档），合计 108 个；全部由 30 次实跑触发（脚本一 14 次、脚本二 16 次），逐码覆盖见第 23.3 与 23.4 节。

---

## 17. 可见性边界：这一层读者能拿到什么

第 15 章矩阵给出的是"能归属到什么"，本章给出的是另一半：**每一类读者手里实际有什么**。边界写不清，台账就会把"我看不到"写成"不存在"。

| 读者 | 能直接拿到的格 | 拿不到、只能推断或必须换平面的格 | 边界依据 |
| --- | --- | --- | --- |
| 应用开发者本人 | 自己的证书有效期与指纹、身份存放位置、描述文件五格（who/what/where/when/how） | App Store 重签后的最终签名内容；他人应用的权利来源 | TN3161 第 241—242、247—248 行；TN3125 第 38—110 行 |
| 构建执行者（CI 或本机） | 签名形态、代码目录版本、槽位、嵌套签名是否完整、本机时间戳字段 | 设备上是否被放行；描述文件在设备上的当前到期状态 | 最新格式第 12、14、29—36 行；TN3161 第 255—266 行 |
| 组织管理员（持有 MDM 服务器） | 设备上描述文件的名称、UUID、到期日三格；应用的 `IsValidated` / `AdHocCodeSigned` / `Source`；强制重校验命令的回执状态 | 签名身份本体（Team ID、证书指纹）、权利清单、设备清单格 | provisioningprofilelistitem-fields 第 5—7 行；installedapplicationlistitem-fields 第 5—26 行；validateapplicationsresponse-fields 第 5—14 行 |
| 设备使用者 | 设置里对未知开发者描述的批准动作；开发者模式开关；应用能否启动 | 授权主体、失效原因、吊销状态 | guide 第 2365 行；enabling-developer-mode-on-a-device 第 5—6 行 |
| 外部审计者 / 本报告读者 | 全部公开文档口径与三份公告、KEV 目录读数 | 任何单一对象的私钥、签名正文、描述文件正文 | 本文档边界：脚本一与脚本二都拒绝 `key.*` 与正文形态取值（`K01` / `K02`） |

三条边界值得展开。

**其一，管理面的边界是建模边界，不是权限边界。** 把 `AllowProvisioningInspection` 配全、把命令发下去，回来的仍然只有三格（第 16 章第 3 条）。所以"读不到签名身份"不是配置疏漏，而是平面没有这个字段；把它写成"MDM 权限不够"会导出错误的整改动作（申请更多访问权），而正确的表述是"要拿签名身份，读数面必须换到设备侧或构建归档侧"（第 18 章）。

**其二，设备侧的边界是时机边界。** TN3126 第 138 行说明内核按页在校验发生在页被载入的那一刻（"lazy per-page signature checking"，第 8 行），guide 第 2365 行说明企业应用首启还需要一次 Apple 侧肯定确认。两者合起来给出一个不对称：**放行判定的证据在设备上产生，但判定的依据不在设备上保存**。审计者能看到的只是结果布尔，看不到当时依据的是哪张证书、哪一份描述文件。

**其三，公开侧的边界是文档边界。** TN3161 不含任何吊销词（第 16 章第 11 条），TN3125 只给到期不给撤销，Apple PKI 只给 CRL 存在不给设备侧可见时点。第 26 章把这三处列为主缺口与附带缺口；在此之前，任何"吊销已对全部设备生效"的表述都应写为 `revocation_basis=assumed` 并被 `V05` 阻断。

---
## 18. 四个读数面：签发侧、构建侧、设备侧、管理面

同一条授权链上的格，分布在四个互不相通的读数面上。本章把四个面各自能给什么、不能给什么列清楚，因为第 11 章 L8 的绝大多数越界写法都来自"把某个面的读数当成另一个面的结论"。

### 18.1 签发侧

**能读到**：证书类型与用途（TN3161 第 102—125 行列出各类证书的职责与命名形态，例如第 121—123 行的开发者/分发区分）、有效期起止与指纹（同页第 147—150 行的读取方式）、链根与中间证书（同页第 80—83、159—173、181 行）、身份存放位置（同页第 152—157 行讲登录钥匙串与数据保护钥匙串的差别，第 176—179 行讲智能卡与硬件令牌）、共享与导出路径（sharing 第 18—19、33—38 行）、撤销与删除（同页第 39—41 行）。

**读不到**：设备侧是否放行、App Store 重签后的最终签名内容（TN3161 第 241—242、247—248 行）、别人团队的权利来源。

**台账映射**：`who.*` 全部九格加 `id.cert_fp`。本面是 L1、L2 与 L10 的唯一直接证据来源。

### 18.2 构建侧

**能读到**：签名形态与代际（最新格式第 6 行说明 iOS 15 起以 DER 嵌入权利为准则、旧形态不启动，第 12 行给出 "Look in the output for a string such as CodeDirectory v=20500. For any value of v less than 20400, you need to re-sign your app."，第 14 行给出槽位判据 "If -5 contains a value and -7 contains a zero value, or is not present, you need to re-sign your app to include the new DER entitlements."，第 16—19 行与第 23—27 行分别给出有效与不合形态的真实槽位读数）、代码目录哈希（TN3126 第 69 行）、requirement 与 Team ID 匹配（TN3127 第 15—19、48—57、71 行）、嵌套签名顺序（最新格式第 36 行）、时间戳字段种类（TN3161 第 255—266 行）。

**读不到**：授权是否被 Apple 侧撤销、设备上此刻是否可运行、描述文件在设备上的到期读数。

**台账映射**：`what.*` 与 `id.cdhash`、`when.time_source`。本面产出的信号族是 B 族与 T06——它们判的是"未生效"而不是"失效"。

### 18.3 设备侧

**能读到**：运行闸门结果（guide 第 2353 行说明内核启动后控制哪些进程与代码可运行、第 2362 行说明按 Team ID 做库链接校验、TN3126 第 138 行说明校验按页发生在页载入时）、企业通道的批准与首启确认（第 2365 行整段）、开发者模式状态（enabling-developer-mode-on-a-device 第 5—6 行）、替代分发通道的前提（alt-dist 第 19、21、22 行；EU 页第 142、190、193 行）。

**读不到**：授权主体是谁、失效原因属于证书还是描述文件、当初签进去的中间证书是哪一张（虽然链就嵌在签名里，TN3161 第 182 行，但设备不把这个信息输出成可读格）。

**台账映射**：`where.dev_mode_state`、`state.validate_state`、`state.first_launch_confirm`、`state.still_running`。本面与 L7 一一对应，且**只有结果没有原因**——这是全篇最硬的一条边界。

### 18.4 管理面

**能读到**：描述文件三格（名称、UUID、到期日）、安装应用的 22 个字段（其中签名相关只有 4 个，见第 16 章第 4 条）、命令回执类键、访问权配置（`AllowProvisioningInspection` / `AllowProvisioningInstallationRemoval` / `AllowQueryApplications` / `AllowAppInstallation` / `AllowInspection`）。

**读不到**：签名身份本体、权利清单内容、设备清单内容、逐应用校验判定明细（`ValidateApplicationsResponse` 只回标准键）。声明式平面连描述文件对象都没有建模（第 16 章第 6—8 条）。

**台账映射**：`obs.plane`、`obs.field_read`、`obs.command_name`、`obs.read_at`，以及 `id.profile_uuid`。本面产出的信号族是 O 族与脚本二的 P 族。

**四个面之间没有公开换算表**。这条是本报告对第 02、09、12、13 篇最直接的补充：那几篇分别在更新链、备份链、证据链上处理过"跨面推断"，本章把同样的边界固定在签名链上——签发侧的有效期不等于设备侧的可运行性，构建侧的校验通过不等于管理面能读回身份，管理面的三格齐备不等于授权主体可确定。

---

## 19. 两套判定模型：J1—J4 与 Q1—Q4

### 19.1 为什么是两套

一条链路的归属结论有两种失败方式：**主语定不下来**（谁签的、给谁、依据哪张对象），以及**覆盖面定不下来**（这一格在这条通道上该不该存在、该由哪个平面读回）。前者是单对象问题，后者是集合问题。用一套等级同时回答两件事，会出现"每格都齐但通道判据未建模"和"差集全但每条记录都没有主体"两种互相掩盖的情形。

因此两个脚本各出一套等级，且**都是每对象一行**：

- 脚本一给 **J1—J4**，回答"这条授权能不能进入对外归属表述"。
- 脚本二给 **Q1—Q4**，回答"这一格本应由哪条通道、哪个平面给出"。

两套等级都不评价代码好坏、不评价安全性，只评价**台账能否支撑表述**。

### 19.2 J1—J4：主语闭合等级

判定发生在脚本一第 341—345 行，输入是每对象的阻断信号条数 `hard`（`HB` 集合命中数）与四格主语要素（`id.channel`、`who.signer_type`、`obs.plane`、`doc.conclusion`）：

| 等级 | 触发条件（按优先级从高到低） | 允许的表述 | 禁止的表述 |
| --- | --- | --- | --- |
| J4 | 通道或签名者类型缺格，或观测平面与结论两格同时为空，或阻断信号不少于 5 条 | 仅"存在一条运行记录" | 任何"谁被授权、何时失效、谁能证明" |
| J3 | 有阻断信号，且缺核对时刻、证书指纹或描述文件到期任一格 | "这段代码被授权过" | "以哪张证书、到哪一刻" |
| J2 | 有阻断信号但主语与时效格齐备 | 内部处置可用 | 对外授权状态结论 |
| J1 | 九格齐备且无阻断信号（`S08` 一类提示不计入 `hard`） | 可进入对外归属表述 | — |

四档的文案由脚本一第 346—349 行直接印出，读者不需要另行解释——J 档行本身就是结论。九格指 `id.` / `who.` / `what.` / `where.` / `how.` / `when.` / `state.` / `obs.` / `doc.` 九个命名空间各有至少一格被有效登记，实现上由第 341—345 行的主语四格加上"无阻断"共同保证。

### 19.3 Q1—Q4：可得性闭合等级

判定发生在脚本二第 326—336 行（四档文案在第 338—341 行），输入是每对象的阻断信号数 `hard`、提示信号数 `soft`、词表合法性标记 `subjBad`、通道格与通道计数，以及全局的能力表行数 `capRows`：

| 等级 | 触发条件（按优先级从高到低） | 允许的表述 | 禁止的表述 |
| --- | --- | --- | --- |
| Q4 | 通道或要素取值本身不合，或阻断信号不少于 5 条，或通道格为空 | 不进入差集表述 | 任何"该通道缺这一格" |
| Q2 | 有阻断信号（平面越界、词表混用、公告归属悬空、差集冲突等） | 覆盖面可陈述 | 不能作为差集结论外发 |
| Q3 | 只有提示信号，或能力表一条有效行都没有 | "缺哪一格"清楚 | "这一格该由谁读回"未定 |
| Q1 | 通道×要素差集、平面可得性、公告词表三段齐备且无任何信号 | 可作为可得性与归属表述 | — |

8 个提示型码（`S08`、`D02`、`D05`、`P05`、`V04`、`X05`、`T02`、`T03`）落在 Q3 而不是 Q2：它们说明登记质量有问题但不构成口径冲突。`capRows == 0` 单独进 Q3 是刻意设计——能力表为空时"缺哪一格"根本无法计算，此时任何 Q1 都会是假阳性。

### 19.4 两档合读规则

两档一起看才有意义，常见组合与含义：

| 组合 | 含义 | 下一步 |
| --- | --- | --- |
| J1 × Q1 | 主语与覆盖面都闭合 | 可以外发归属表述 |
| J1 × Q2/Q3 | 单条记录完整，但通道判据或平面归属有问题 | 结论限定为"这一条成立"，不写成通道级结论 |
| J2/J3 × Q1 | 覆盖面清楚，主语差一段 | 补 `obs.`、`when.audit_at` 或 `id.cert_fp` |
| J4 × 任何 | 主语缺失 | 优先级最高，先补 `id.channel` 与 `who.signer_type` |
| 任何 × Q4 | 词表本身失控 | 先修通道与要素取值，信号解释一律搁置 |

一条硬规则：**两套等级互不豁免**。J1 不能把 Q2 洗成可外发，Q1 也不能替 J4 提供主语——脚本一只读台账、脚本二只读清单与能力表，两边都不看对方的输出，这正是"两套模型"的实现形式。

---

## 20. 运营指标 O1—O10

本章的指标写作 `O1`—`O10`（一位数字），与脚本一的观测平面信号 `O01`—`O04`（两位数字）不是同一套记号；下文每次引用都会带上位数。

十个指标全部可以从脚本输出的汇总块（脚本一末尾四行、脚本二末尾五行）与逐码计数直接算出，不需要额外读数面。

| 指标 | 定义 | 分子/分母来源 | 目标 | 触发信号 |
| --- | --- | --- | --- | --- |
| O1 台账齐备率 | J1 对象数 ÷ 授权对象数 | 脚本一"判定分布"行 | 越高越好，用于趋势 | — |
| O2 主语缺失率 | J4 对象数 ÷ 授权对象数 | 同上 | 0 | A01 / J4 |
| O3 时效可判率 | 同时有 `when.audit_at` 与至少一个到期格的对象 ÷ 全部对象 | 台账格；扣 `T02`/`T04`/`T05` | ≥ 0.95 | T01—T05 / T09 |
| O4 身份闭合率 | 有合法 `id.cert_fp` 的对象 ÷ 全部对象 | 扣 `A09`/`A12` | ≥ 0.9 | A09 / A12 |
| O5 观测闭合率 | `obs.plane` 非空且 `obs.field_read` 落在允许集合的对象 ÷ 全部对象 | 扣 `O01`—`O04` | 1.0 | O01 / O02 / O03 / O04 |
| O6 通道建模率 | 能力表覆盖通道数 ÷ 清单出现的通道数 | 脚本二"能力表通道数"与 `D04` 计数 | 1.0 | D04 / C06 |
| O7 required 空洞密度 | 未登记空洞数 ÷ required 要素读数总数 | 脚本二覆盖矩阵行的"未登记空洞"列 | 趋势下降，绝对值受第 26 章 N4 限制 | D02 / D05 |
| O8 处置闭环率 | `revoke_recorded` 与 `delete_verified` 同时为 yes 的对象 ÷ 记为已吊销对象 | 台账格 | 1.0 | V03 / V04 |
| O9 公告悬空率 | 挂在公告平面的要素读数中命中 `X01`/`X02`/`X04`/`X05` 的比例 | 脚本二"公告平面读数"计数与 X 族 | 0 | X01 / X02 / X04 / X05 / P03 |
| O10 表述越界率 | 对外表述为 yes 但命中 `V01`/`V02`/`V04` 或 `O02`/`O04` 的对象 ÷ 对外表述对象 | 脚本二 V 族与脚本一 O 族 | 0 | V01 / V02 / V04 / O02 / O04 |

三条使用说明：

1. **O2、O8、O9、O10 的目标值是 0，不是阈值**。这四类计数一旦非零就说明有结论已经外发出去而依据不成立，趋势图上的下降不代表可接受；把它们当阈值管理是这类指标最常见的误用。
2. **O6 与 O7 必须一起读**。O7 的空洞密度取决于能力表是否建模（`D04` 存在时，某些通道的 required 集根本不参与计算），单看 O7 会把"未建模"读成"很干净"。第 12 章 L9 的 `undocumented` 档也是同一件事：脚本二不猜未公开的判据。
3. **O1—O5 只统计台账，不统计代码**。这十个指标衡量的是"授权链的可归属程度"，不是应用质量，也不构成对任何具体包的安全评价；把它们写进产品结论即越界，与第 2.3 节的六条不做的事一致。

---
## 21. 只读核验脚本一：授权链台账审查器

### 21.1 输入、输出与不做什么

**输入**：一份或多份台账文本，每行一条记录，格式固定为 `<授权对象标识>,<字段名>,<值>` 三列。`#` 开头行与空行忽略，行尾 CR 忽略，值里不能含逗号。字段名必须带九个命名空间之一（`id.` / `who.` / `what.` / `where.` / `how.` / `when.` / `state.` / `obs.` / `doc.`），第十个 `key.` 是**拒收用命名空间**：出现在这一空间下的任何字段都直接触发 `K01` 并要求删除该字段。

**输出**：三段。① 逐条信号写到 stderr，格式 `码\t对象\t说明（公开口径出处）`；② 每个授权对象一行判定（J1—J4）写到 stdout，`-q` 时判定行并入汇总；③ 末尾汇总块给出授权对象数、信号行数、判定行数、不同信号码数、阻断信号条数、J1—J4 分布，以及逐码计数。

**退出码**：出现阻断信号为 1，输入不可用（无参数、文件不存在）为 2，其余为 0。

**不做什么**（这一节是硬约束，不是免责声明）：不联网；不调用 `codesign`、`security`、`devicectl`、`xcrun`、`altool`、`syspolicy_check` 等任何 Apple 命令行工具；不读取描述文件或证书正文；不修改任何输入文件；唯一写出目标是 `mktemp -d` 创建的临时目录并在 `trap` 中删除。它不提供任何伪造或替换描述文件、绕过签名校验、重签他人代码、提取私钥或规避设备侧执行闸门的做法，也不提供任何绕过管理面审计的手段。取值形态上，脚本对形似私钥、PKCS#12、证书签名请求、描述文件正文（`K01`）以及形似设备绝对路径或整段文件正文（`K02`）的取值直接判为拒收。

### 21.2 信号族分组

| 族 | 检查对象 | 码 | 条数 | 代表判据 |
| --- | --- | --- | --- | --- |
| S | 记录自身形态 | S01—S09 | 9 | 恰好三列、主键无空白、命名空间已登记、枚举/布尔/日期/数值取值域、同字段双值（S07）与重复同值（S08） |
| K | 秘密形态拒收 | K01—K02 | 2 | `key.*` 空间与形似私钥/正文的取值 |
| A | 身份与签发（L1/L2） | A01—A12 | 12 | 通道与签名者缺一（A01）、云端托管与私钥自持矛盾（A02/A03）、口令同渠道（A04）、有效期缺失或已过（A05/A06）、EKU 与链根（A07/A08）、指纹与 Team ID 形态（A09/A10）、持有人缺失（A11）、只有 Team ID 无指纹（A12） |
| B | 授权对象形态（L3） | B01—B07 | 7 | App ID 拼装一致性、声明侧通配、DER 形态、代码目录版本、权利槽、嵌套签名、代码目录哈希 |
| C | 范围（L4） | C01—C06 | 6 | 设备清单格、全设备声明、标识形态、开发者模式前置、区域前提 |
| H | 权利（L5） | H01—H04 | 4 | 受限项须授权、声明超出允许清单、部分覆盖给确认、App Store 重签后时效基准 |
| T | 时效（L6） | T01—T09 | 9 | 到期格、到期比较、时间基准类型、双时效、核对时刻、重签处置、读数时刻、一年口径、时效基准 |
| V | 失效、校验与处置（L7/L10） | V01—V06 | 6 | 企业通道校验、首启确认、吊销留痕、删除验证、吊销依据、是否仍在跑 |
| O | 观测平面（L8） | O01—O04 | 4 | 空平面给确认、把身份记成管理面格、声明式挂描述文件、形态布尔闭合身份 |
| D | 引用（横切） | D01 | 1 | 缺 `doc.source` 或 `doc.line_ref`（每对象必检） |
| J | 判定 | J1—J4 | 4 | 见第 19.2 节 |

合计 64 个不同信号码，其中 59 个计入阻断计数、`S08` 只提示、`J1`—`J4` 是判定行而非信号。族字母与前十章的层一一对应，`T`/`V`/`O`/`D`/`J` 五族覆盖 L6—L10 与判定层，因此读台账的人可以从码直接跳到章。

### 21.3 三个设计选择

**其一，把"自造字段"定为阻断而不是忽略。** 未登记的字段名给 `S09`，不带命名空间或命名空间未知的给 `S03`。理由是归属表述必须能落到一个有公开口径的格上；如果脚本容忍自由字段，一条 J1 记录可能只是"填了很多没有定义的东西"，判定就失去意义。副作用是台账迁移时需要显式扩表——这恰恰是本文希望发生的：扩表动作会逼出"这一格的公开依据是什么"这个问题。

**其二，把防御边界写在取值形态判定里，而不是写在文档注释里。** `K01` / `K02` 在读取阶段就 `next`，被拒收的记录不进入任何族的判定，也不给 J1。这样"台账不该收私钥材料"不是一句提醒，而是可执行且可验收的分支（第 23.2 节的 R14 就是专门跑这一分支的坏样本：六种秘密形态取值全部命中）。

**其三，每条信号自带出处。** 所有 A/B/C/H/T/V/O 族码通过 `DOC` 映射追加"见 <文档> 第 N 行"，出处指向本报告归档的 46 份文本（`A/` 组）与 6 份网页抽取（`B/pages`）。这意味着审查报告的每一行都能被第三方逐行复现，也是 `D01` 存在的原因：台账自己也要遵守同一条规则。

### 21.4 脚本全文

```bash
#!/usr/bin/env bash
# authorization-ledger-review.sh —— 签名与分发授权链台账审查器（离线 / 只读 / 不联网 / 不碰设备）
# 输入：一份或多份台账文本，每行一条记录：  <授权对象标识>,<字段名>,<值>
# 输出：逐条信号码（stderr） + 每条对象的四级判定（stdout） + 汇总
# 本脚本只做授权归属判定与口径核对：不含任何伪造或替换描述文件、绕过签名校验、重签他人代码、
# 提取私钥或规避设备侧执行闸门的做法；也不提供任何绕过管理面审计的手段。
# 台账里出现私钥、PKCS#12、证书签名请求或描述文件正文时直接触发 K01/K02 并要求删除该字段。
# 本脚本不联网、不调用 codesign/security/devicectl/xcrun 等任何 Apple 命令行工具、不修改输入文件；
# 唯一写出目标是 mktemp -d 创建的临时目录，退出时删除。
set -u
LC_ALL=C; export LC_ALL

usage() {
  cat <<'EOF'
用法: authorization-ledger-review.sh [-q] 台账文件 [...]
  -q  只输出汇总；-h/--help 显示本帮助
台账行格式: <授权对象标识>,<字段名>,<值>    # 开头与空行忽略，行尾 CR 忽略，值里不能含逗号
字段命名空间（九个 + 一个拒收空间）:
  id.*    身份（channel / app_id / bundle_id / team_id / profile_uuid / cert_fp / cdhash）
  who.*   签发与私钥（signer_type / issuing_path / cert_type / cert_not_before / cert_not_after /
           eku_codesign / chain_root / chain_depth / key_storage / key_custody / identity_exported /
           export_channel_split）
  what.*  授权对象形态（appid_form / claim_form / der_profile / sig_version / ent_slot /
           nested_signed / resource_sealed / entitlements_recorded）
  where.* 设备与地域范围（provisioned_listed / all_devices_claim / device_id_form /
           dev_mode_required / dev_mode_state / supervised / region）
  how.*   权利（profile_required / allowlist_covered / restricted_entitlement / appstore_resigned）
  when.*  时效（profile_expiry / audit_at / time_source / expiry_basis / resign_needed）
  state.* 失效与校验（validate_state / first_launch_confirm / revoke_action / revoke_recorded /
           delete_verified / revocation_basis / still_running）
  obs.*   观测通道（plane / field_read / command_name / read_at）
  doc.*   引用与结论（source / line_ref / conclusion）
  key.*   拒收用命名空间：本空间下任何字段都会触发 K01
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

TMPD=$(mktemp -d "${TMPDIR:-/tmp}/alr.XXXXXX") || { echo "无法创建临时目录" >&2; exit 2; }
trap 'rm -rf "$TMPD"' EXIT INT TERM

awk -v QUIET="$QUIET" '
function emit(code, id, msg) { cnt[code]++; lines[++nline] = sprintf("%s\t%s\t%s", code, (id==""?"-":id), msg) }
function GV(i, f,   k) { k = i SUBSEP f; return (k in valof) ? valof[k] : "" }
function istrue(v)  { return (v=="true"||v=="yes"||v=="1") }
function isfalse(v) { return (v=="false"||v=="no"||v=="0") }
function isbool(v)  { return (istrue(v) || isfalse(v) || v=="unknown" || v=="not_recorded" || v=="not_applicable") }
function isNA(v)    { return (v=="" || v=="not_recorded" || v=="unknown") }
function isISOdt(v) { return (v ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]([ T][0-9][0-9]:[0-9][0-9](:[0-9][0-9])?)?([Zz]|[+-][0-9][0-9]:?[0-9][0-9])?$/ && validCal(v)) }
function validCal(v,  p, mo, dy) { split(substr(v,1,10), p, "-"); mo = p[2]+0; dy = p[3]+0; return (mo>=1 && mo<=12 && dy>=1 && dy<=31) }
function stamp(v,  d, tm) { d = substr(v,1,10); gsub(/[^0-9]/, "", d); tm = substr(v,12); gsub(/[^0-9]/, "", tm); return (d substr(tm "000000", 1, 6)) + 0 }
function isHex(v, n) { return (v ~ ("^[0-9a-fA-F]{" n "}$")) }
function isInt(v)   { return (v ~ /^[0-9]+$/) }
function isTeamID(v){ return (v ~ /^[A-Za-z0-9]{10}$/) }
function isLineRef(v) { return (v ~ /^[0-9]+(-[0-9]+)?$/) }
function daysApart(a, b,  pa, pb, ya, ma, da, yb, mb, db, n, i) {
  split(substr(a,1,10), pa, "-"); split(substr(b,1,10), pb, "-")
  ya=pa[1]+0; ma=pa[2]+0; da=pa[3]+0; yb=pb[1]+0; mb=pb[2]+0; db=pb[3]+0
  n = (yb - ya) * 365 + (mb - ma) * 30 + (db - da)
  return n
}
function src(c) { return (c in DOC) ? "（" DOC[c] "）" : "" }
BEGIN {
  FS = ","
  DOM["id.channel"]=" app_store testflight ad_hoc development enterprise developer_id alternative_marketplace web_distribution notarized_direct none not_recorded unknown "
  DOM["who.signer_type"]=" apple_developer apple_enterprise apple_developer_id apple_cloud_managed apple_store_identity third_party none not_recorded unknown "
  DOM["who.issuing_path"]=" manual_csr xcode_managed cloud_managed enterprise_portal store_pipeline notary_service none not_recorded unknown "
  DOM["who.cert_type"]=" apple_development apple_distribution developer_id_application developer_id_installer enterprise_distribution app_store third_party none not_recorded unknown "
  DOM["who.chain_root"]=" apple_root_ca other_root none not_recorded unknown "
  DOM["who.key_storage"]=" login_keychain data_protection_keychain smart_card apple_cloud not_held none not_recorded unknown "
  DOM["who.key_custody"]=" self team_member ci_runner apple_cloud not_held none not_recorded unknown "
  DOM["what.appid_form"]=" explicit wildcard mixed none not_recorded unknown "
  DOM["what.claim_form"]=" explicit wildcard_in_claim mixed none not_recorded unknown "
  DOM["what.ent_slot"]=" none legacy_only der_present mixed not_recorded unknown "
  DOM["where.device_id_form"]=" udid40 udid25 serial mixed none not_recorded unknown "
  DOM["where.dev_mode_state"]=" on off not_applicable none not_recorded unknown "
  DOM["where.region"]=" eu jp br other not_applicable not_recorded unknown "
  DOM["how.allowlist_covered"]=" full partial exceeds not_applicable none not_recorded unknown "
  DOM["when.time_source"]=" tsa_timestamp local_signed_time none not_applicable not_recorded unknown "
  DOM["when.expiry_basis"]=" profile certificate both not_applicable not_recorded unknown "
  DOM["state.validate_state"]=" validated pending failed not_applicable none not_recorded unknown "
  DOM["state.first_launch_confirm"]=" received not_received not_applicable none not_recorded unknown "
  DOM["state.revoke_action"]=" revoked renewed none not_recorded unknown "
  DOM["state.revocation_basis"]=" crl ocsp apple_api admin_record assumed not_applicable not_recorded unknown "
  DOM["obs.plane"]=" mdm_command mdm_status ddm device_settings xcode_report build_archive none not_recorded unknown "
  DOM["obs.field_read"]=" profile_uuid expiry name signature_bool team_id cert_list none not_recorded unknown "
  DOM["doc.conclusion"]=" confirmed absent_in_channel not_determinable assumed not_recorded unknown "
  BOOL["who.eku_codesign"]=1; BOOL["who.identity_exported"]=1; BOOL["who.export_channel_split"]=1
  BOOL["what.der_profile"]=1; BOOL["what.nested_signed"]=1; BOOL["what.resource_sealed"]=1
  BOOL["what.entitlements_recorded"]=1; BOOL["where.provisioned_listed"]=1; BOOL["where.all_devices_claim"]=1
  BOOL["where.dev_mode_required"]=1; BOOL["where.supervised"]=1; BOOL["how.profile_required"]=1
  BOOL["how.appstore_resigned"]=1; BOOL["how.restricted_entitlement"]=1; BOOL["when.resign_needed"]=1
  BOOL["state.revoke_recorded"]=1; BOOL["state.delete_verified"]=1; BOOL["state.still_running"]=1
  DT["who.cert_not_before"]=1; DT["who.cert_not_after"]=1; DT["when.profile_expiry"]=1
  DT["when.audit_at"]=1; DT["obs.read_at"]=1
  NUM["who.chain_depth"]=1; NUM["what.sig_version"]=1
  NS["id"]=1; NS["who"]=1; NS["what"]=1; NS["where"]=1; NS["how"]=1
  NS["when"]=1; NS["state"]=1; NS["obs"]=1; NS["doc"]=1; NS["key"]=1
  split("S01 S02 S03 S04 S05 S06 S07 S09 K01 K02 A01 A02 A03 A04 A05 A06 A07 A08 A09 A10 A11 A12 B01 B02 B03 B04 B05 B06 B07 C01 C02 C03 C04 C05 C06 H01 H02 H03 H04 T01 T02 T03 T04 T05 T06 T07 T08 T09 V01 V02 V03 V04 V05 V06 O01 O02 O03 O04 D01", hb, " ")
  for (i in hb) HB[hb[i]] = 1
  split("id.channel id.app_id id.bundle_id id.team_id id.profile_uuid id.cert_fp id.cdhash obs.command_name doc.source doc.line_ref", extra, " ")
  for (i in extra) KNOWN[extra[i]] = 1
  for (f in DOM) KNOWN[f] = 1
  for (f in BOOL) KNOWN[f] = 1
  for (f in DT) KNOWN[f] = 1
  for (f in NUM) KNOWN[f] = 1
  DOC["A01"]="见 TN3161 第 102—103、147—150 行"
  DOC["A02"]="见 TN3161 第 122—125 行"
  DOC["A03"]="见 sharing-your-teams-signing-certificates 第 18 行"
  DOC["A04"]="见 sharing-your-teams-signing-certificates 第 19 行"
  DOC["A05"]="见 TN3161 第 147—150 行"
  DOC["A06"]="见 TN3161 第 159—173 行"
  DOC["A07"]="见 TN3161 第 150—157 行"
  DOC["A08"]="见 TN3161 第 80—83、181 行"
  DOC["A09"]="见 TN3161 第 173 行"
  DOC["A10"]="见 apple-platform-security-guide 第 2362 行"
  DOC["A11"]="见 TN3161 第 116、121—123 行"
  DOC["A12"]="见 TN3161 第 173 行与 apple-platform-security-guide 第 2362 行"
  DOC["B01"]="见 TN3125 第 67—76 行"
  DOC["B02"]="见 TN3125 第 111、114 行"
  DOC["B03"]="见 TN3125 第 198 行与 using-the-latest-code-signature-format 第 6、29 行"
  DOC["B04"]="见 using-the-latest-code-signature-format 第 12 行"
  DOC["B05"]="见 using-the-latest-code-signature-format 第 14 行与 TN3126 第 158 行"
  DOC["B06"]="见 using-the-latest-code-signature-format 第 36 行"
  DOC["B07"]="见 TN3126 第 69 行"
  DOC["C01"]="见 TN3125 第 77—78 行"
  DOC["C02"]="见 TN3125 第 86 行"
  DOC["C03"]="见 TN3125 第 87 行"
  DOC["C04"]="见 locating-device-identifiers 第 5—12 行"
  DOC["C05"]="见 distributing-your-app-to-registered-devices 第 29 行与 enabling-developer-mode-on-a-device 第 5—6 行"
  DOC["C06"]="见 B/pages/support-117767-alt-dist 第 19、21 行与 B/pages/dev-support-apps-in-eu 第 142 行"
  DOC["H01"]="见 TN3125 第 94—110、118—133 行"
  DOC["H02"]="见 TN3125 第 111—112 行"
  DOC["H03"]="见 TN3125 第 112、133 行"
  DOC["H04"]="见 TN3161 第 233—249 行与 TN3125 第 145—149 行"
  DOC["T01"]="见 TN3125 第 89—92 行"
  DOC["T02"]="见 TN3125 第 89—92 行"
  DOC["T03"]="见 TN3161 第 261—267 行"
  DOC["T04"]="见 TN3161 第 250—254 行"
  DOC["T05"]="见 TN3161 第 149 行与 TN3125 第 89 行"
  DOC["T06"]="见 using-the-latest-code-signature-format 第 30—35 行"
  DOC["T07"]="见 TN3125 第 89 行与 installedapplicationlistitem-fields 第 21 行"
  DOC["T08"]="见 TN3125 第 92 行"
  DOC["T09"]="见 TN3161 第 250—254 行与 TN3125 第 89 行"
  DOC["V01"]="见 apple-platform-security-guide 第 2365 行与 validate-applications-command 第 21 行"
  DOC["V02"]="见 apple-platform-security-guide 第 2365 行与 installedapplicationlistitem-fields 第 21 行"
  DOC["V03"]="见 sharing-your-teams-signing-certificates 第 39—41 行"
  DOC["V04"]="见 sharing-your-teams-signing-certificates 第 40—41 行"
  DOC["V05"]="见 B/pages/apple-certificateauthority 第 24、51—56 行"
  DOC["V06"]="见 TN3126 第 8、138 行"
  DOC["O01"]="见 provisioningprofilelistitem-fields 第 5—7 行与 validateapplicationsresponse-fields 第 5—14 行"
  DOC["O02"]="见 provisioningprofilelistitem-fields 第 5—7 行与 installedapplicationlistitem-fields 第 5—25 行"
  DOC["O03"]="见 devicemanagement-declarations 第 13—23 行与 install-provisioning-profile-command 第 9—21 行"
  DOC["O04"]="见 installedapplicationlistitem-fields 第 5—9 行"
}
{ sub(/\r$/, "") }
/^[[:space:]]*#/ { next }
/^[[:space:]]*$/ { next }
NF != 3 { emit("S01", $1, "记录不是恰好三列（<授权对象标识>,<字段名>,<值>）：" $0); next }
{
  id = $1; fld = $2; val = $3
  gsub(/^[[:space:]]+|[[:space:]]+$/, "", id)
  gsub(/^[[:space:]]+|[[:space:]]+$/, "", fld)
  gsub(/^[[:space:]]+|[[:space:]]+$/, "", val)
  if (id == "") { emit("S02", "", "授权对象标识为空"); next }
  if (id ~ /[ \t]/) { emit("S02", id, "授权对象标识内含空白，无法作为台账主键"); next }
  p = index(fld, ".")
  nsp = (p > 1) ? substr(fld, 1, p-1) : ""
  key = (p > 0) ? substr(fld, p+1) : ""
  if (nsp == "" || !(nsp in NS) || key == "") { emit("S03", id, "字段名不带命名空间或命名空间未知：" fld "（九个可用命名空间见 -h）"); next }
  if (nsp == "key") { emit("K01", id, "出现 key.* 命名空间字段（" fld "）：授权台账不收私钥、PKCS#12、证书签名请求与描述文件正文，请删除该字段"); if (!(id in seen)) { seen[id]=1; order[++nid]=id }; next }
  if (!(id in seen)) { seen[id] = 1; order[++nid] = id }
  if (!(fld in KNOWN)) { emit("S09", id, "字段名未登记：" fld "（拼写或自造字段；已登记字段名见 -h 的命名空间清单）"); next }
  if (val ~ /-----BEGIN[ ]?(RSA|EC|PRIVATE|ENCRYPTED)?/ || val ~ /\.(p12|pfx|certSigningRequest|mobileprovision|provisionprofile)$/ || val ~ /^MI[IEA][A-Za-z0-9+\/=]{40,}/) {
    emit("K01", id, "字段 " fld " 的取值形似私钥、PKCS#12、CSR 或描述文件材料：只登记证书指纹与 Team ID 形态的身份串")
    next
  }
  if (val ~ /^\/(Applications|private|var\/mobile|Users)\// || val ~ /^file:\/\// || length(val) > 200) {
    emit("K02", id, "字段 " fld " 的取值形似设备绝对路径或整段文件正文：台账只登记「哪条通道在什么时刻读回哪一格」，不登记内容")
    next
  }
  if (val == "" && !(fld == "doc.source" || fld == "doc.line_ref")) { emit("S02", id, "字段 " fld " 取值为空；留空、unknown 与 no 是三件事"); next }
  k = id SUBSEP fld
  if (k in valof) {
    if (valof[k] != val) emit("S07", id, "同一授权对象同一字段出现两个不同值：" fld " = " valof[k] " / " val)
    else emit("S08", id, "字段 " fld " 重复登记且值相同（不阻断，但台账行数虚高）")
    next
  }
  valof[k] = val
  if (fld in DOM) {
    if (!(val == "not_recorded" || val == "unknown" || val == "not_applicable")) {
      if (index(DOM[fld], " " val " ") == 0) emit("S04", id, "枚举字段 " fld " 取值不在允许集合内：" val "（不做近义替换）")
    }
  } else if (fld in BOOL) {
    if (!isbool(val)) emit("S05", id, "布尔字段 " fld " 取值不是 yes/no/true/false/unknown/not_recorded/not_applicable：" val)
  } else if (fld in DT) {
    if (!(val == "not_recorded" || val == "unknown" || val == "not_applicable")) {
      if (!isISOdt(val)) emit("S06", id, "日期字段 " fld " 不是可判定的 ISO 8601 形态：" val)
    }
  } else if (fld in NUM) {
    if (!(val == "not_recorded" || val == "unknown")) {
      if (!isInt(val)) emit("S06", id, "数值字段 " fld " 不是整数：" val)
      else if (fld == "who.chain_depth" && (val+0 < 1 || val+0 > 5)) emit("S04", id, "who.chain_depth 越出 1—5：" val "（公开口径给出三级链，TN3161 第 80—83 行）")
      else if (fld == "what.sig_version" && (val+0 < 20100 || val+0 > 20600)) emit("S04", id, "what.sig_version 越出 20100—20600 的公开观察区间：" val)
    }
  } else if (fld == "id.team_id") {
    if (!(val == "not_recorded" || val == "unknown" || val == "not_applicable") && !isTeamID(val)) emit("A10", id, "id.team_id 不是 10 位字母数字串：" val src("A10"))
  } else if (fld == "id.cert_fp") {
    if (!(val == "not_recorded" || val == "unknown" || val == "not_applicable") && !(isHex(val, 40) || isHex(val, 64))) emit("A09", id, "id.cert_fp 不是 40 或 64 位十六进制指纹：" val src("A09"))
  } else if (fld == "id.cdhash") {
    if (!(val == "not_recorded" || val == "unknown" || val == "not_applicable") && !isHex(val, 40)) emit("B07", id, "id.cdhash 不是 40 位十六进制（SHA-1 形态）代码目录哈希：" val src("B07"))
  } else if (fld == "id.profile_uuid") {
    if (!(val == "not_recorded" || val == "unknown" || val == "not_applicable" || val ~ /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/)) emit("S06", id, "id.profile_uuid 不是 UUID 形态：" val)
  }
}
END {
  nrec = nid
  for (ix = 1; ix <= nid; ix++) {
    id = order[ix]
    ch   = GV(id,"id.channel");      sg   = GV(id,"who.signer_type")
    ip   = GV(id,"who.issuing_path");ct   = GV(id,"who.cert_type")
    cnb  = GV(id,"who.cert_not_before"); cna = GV(id,"who.cert_not_after")
    eku  = GV(id,"who.eku_codesign"); cr  = GV(id,"who.chain_root")
    ks   = GV(id,"who.key_storage"); kc = GV(id,"who.key_custody")
    iexp  = GV(id,"who.identity_exported"); spl = GV(id,"who.export_channel_split")
    team = GV(id,"id.team_id"); bid = GV(id,"id.bundle_id"); aid = GV(id,"id.app_id")
    puuid= GV(id,"id.profile_uuid"); fp = GV(id,"id.cert_fp"); cdh = GV(id,"id.cdhash")
    aform= GV(id,"what.appid_form"); cform = GV(id,"what.claim_form")
    der  = GV(id,"what.der_profile"); sv = GV(id,"what.sig_version"); slot = GV(id,"what.ent_slot")
    nest = GV(id,"what.nested_signed"); res = GV(id,"what.resource_sealed")
    entre= GV(id,"what.entitlements_recorded")
    plist= GV(id,"where.provisioned_listed"); alld = GV(id,"where.all_devices_claim")
    dform= GV(id,"where.device_id_form"); dmr = GV(id,"where.dev_mode_required"); dms = GV(id,"where.dev_mode_state")
    reg  = GV(id,"where.region")
    preq = GV(id,"how.profile_required"); cover = GV(id,"how.allowlist_covered")
    rest = GV(id,"how.restricted_entitlement"); resign_app = GV(id,"how.appstore_resigned")
    pe   = GV(id,"when.profile_expiry"); at = GV(id,"when.audit_at")
    ts   = GV(id,"when.time_source"); eb = GV(id,"when.expiry_basis"); rn = GV(id,"when.resign_needed")
    vs   = GV(id,"state.validate_state"); flc = GV(id,"state.first_launch_confirm")
    ra   = GV(id,"state.revoke_action"); rr = GV(id,"state.revoke_recorded")
    dv   = GV(id,"state.delete_verified"); rb = GV(id,"state.revocation_basis")
    sr   = GV(id,"state.still_running")
    pl   = GV(id,"obs.plane"); fr = GV(id,"obs.field_read"); rat = GV(id,"obs.read_at")
    srcv = GV(id,"doc.source"); lref = GV(id,"doc.line_ref"); con = GV(id,"doc.conclusion")

    if (isNA(ch) && isNA(sg)) emit("A01", id, "通道与签名者类型两格都空：这段代码凭什么被允许运行，台账里没有主语" src("A01"))
    else if (isNA(ch) || isNA(sg)) emit("A01", id, "分发通道或签名者类型缺格（另一格为 " (isNA(ch) ? sg : ch) "）：只给一半不足以定位授权来源" src("A01"))
    if (ip == "cloud_managed" && !(ks == "apple_cloud" || ks == "not_held" || isNA(ks)))
      emit("A02", id, "签发路径记为云端托管，私钥保管却记为 " ks "：云端托管时私钥与证书都由 Apple 侧管理，你并不直接持有" src("A02"))
    if (istrue(iexp) && ks == "apple_cloud")
      emit("A03", id, "同时写「已导出签名身份」与「私钥在 Apple 云端」：云端托管证书由 Xcode 在团队内自动共享，没有手动导出这条路" src("A03"))
    if (istrue(iexp) && isfalse(spl))
      emit("A04", id, "导出了 PKCS#12 身份但口令走同一渠道：公开口径写明任何拿到导出身份并知道口令的人都能以你的账号分发代码，身份与口令要走不同渠道" src("A04"))
    if (isNA(kc) && (istrue(iexp) || ks=="login_keychain" || ks=="smart_card"))
      emit("A11", id, "登记了私钥保管位置但没登记持有人（key_custody 空）：私钥落谁手上决定泄露时算谁的" src("A11"))
    if (isNA(cna) || isNA(cnb)) { if (!isNA(eku) || !isNA(fp)) emit("A05", id, "有证书指纹或 EKU 却缺证书有效期（cert_not_before / cert_not_after）：codesign 选身份时要核对当前时间在有效期内" src("A05")) }
    if (!isNA(cna) && isISOdt(cna) && !isNA(at) && isISOdt(at) && stamp(cna) < stamp(at) && isNA(ra))
      emit("A06", id, "证书有效期止 " cna " 早于核对时刻 " at "，且无任何吊销或续签处置记录" src("A06"))
    if (isfalse(eku)) emit("A07", id, "证书扩展密钥用法不含 Code Signing：这不是一张代码签名证书，签名动作不可能由它发出" src("A07"))
    if (!isNA(ch) && ch != "developer_id" && ch != "notarized_direct" && cr != "apple_root_ca" && (ch=="app_store"||ch=="testflight"||ch=="ad_hoc"||ch=="development"||ch=="enterprise"||ch=="alternative_marketplace"||ch=="web_distribution"))
      emit("A08", id, "链根不是 Apple Root CA（记为 " cr "）：iOS 类通道要求由 Apple 签发的证书，链建不到自签根时签名动作本身就会失败" src("A08"))
    if (!isNA(fp) && !isNA(ch) && ch != "none" && !(isHex(fp,40) || isHex(fp,64)))
      emit("A09", id, "证书指纹形态不合，无法把授权回指到某一张具体证书：" fp src("A09"))
    if (!isNA(team) && isNA(fp)) emit("A12", id, "只有 Team ID 没有证书指纹：库校验按 Team ID 匹配，但授权签发与失效是按证书发生的，缺指纹时失效不可证" src("A12"))
    if (!isNA(aid) && !isNA(bid) && !isNA(team) && aform == "explicit" && aid != team "." bid)
      emit("B01", id, "App ID 与「Team ID . bundle ID」不一致：" aid " ≠ " team "." bid src("B01"))
    if (cform == "wildcard_in_claim") emit("B02", id, "应用声明里出现通配符：通配符只属于描述文件的允许清单侧，出现在声明侧即口径错误" src("B02"))
    if (isfalse(der)) emit("B03", id, "授权对象不是 DER 形态：iOS 15、iPadOS 15、tvOS 15、watchOS 8 起以 DER 编码形态为准，旧形态不启动" src("B03"))
    if (isInt(sv) && sv+0 < 20400) emit("B04", id, "代码目录版本 " sv " 低于 20400，需要重签后才可能被当前系统接受" src("B04"))
    if (slot == "legacy_only") emit("B05", id, "权利槽只在 -5（旧式 plist）有值、-7（DER）为空：iOS 15 起该签名视为不完整" src("B05"))
    if (isfalse(nest)) emit("B06", id, "嵌套代码未逐一签名：由内向外逐个签，框架与扩展不带权利与描述文件" src("B06"))
    if (isNA(cdh) && !isNA(ch) && ch != "none") emit("B07", id, "通道已定但未登记代码目录哈希：授权无法绑定到具体二进制形态" src("B07"))
    if (istrue(plist) && (ch=="app_store"||ch=="testflight"))
      emit("C02", id, "App Store / TestFlight 通道却登记了设备清单：App Store 分发描述文件按公开口径根本不含设备清单格" src("C02"))
    if ((ch=="development"||ch=="ad_hoc") && !istrue(plist))
      emit("C01", id, "开发或 Ad Hoc 通道但未登记设备范围：这两类靠设备清单限定「在哪台机器上能跑」" src("C01"))
    if ((ch=="development"||ch=="ad_hoc") && isNA(dform))
      emit("C04", id, "需要注册设备的通道未登记设备标识形态：清单里那串标识是哪一类（UDID/ECID/序列号）决定能不能回指到具体设备" src("C04"))
    if (istrue(alld) && ch!="enterprise" && ch!="developer_id")
      emit("C03", id, "声称适用于全部设备但通道是 " ch "：按公开口径只有 Developer ID 与企业（In-House）描述文件带「适用于所有设备」这一格" src("C03"))
    if (istrue(dmr) && (dms=="off" || isNA(dms)))
      emit("C05", id, "该通道要求设备开启开发者模式，但 dev_mode_state 为 " (dms==""?"未登记":dms) "：装了不等于能跑，运行授权还差设备侧这一格" src("C05"))
    if ((ch=="alternative_marketplace"||ch=="web_distribution") && !(reg=="eu"||reg=="jp"||reg=="br"))
      emit("C06", id, "替代分发通道但区域格为 " (reg==""?"未登记":reg) "：账号区域与实际所在地是这一通道的前提条件" src("C06"))
    if (istrue(rest) && isfalse(preq))
      emit("H01", id, "声明了受限 entitlement 却记为不需要描述文件授权：受限项必须由描述文件授权（macOS 的非受限清单是另一回事）" src("H01"))
    if (cover == "exceeds") emit("H02", id, "应用声明超出描述文件允许清单：每一个声明项都要落在允许清单内，否则系统不放行" src("H02"))
    if (cover == "partial" && con == "confirmed")
      emit("H03", id, "允许清单只覆盖部分声明却给出「已确认」结论：部分覆盖意味着有一格没有授权来源" src("H03"))
    if (istrue(resign_app) && ch=="app_store" && eb=="profile")
      emit("H04", id, "App Store 通道既记为「由 Apple 重签」又把时效基准记为描述文件：重签后的最终包不带描述文件，时效不能按 profile 判定" src("H04"))
    if (isNA(pe) && !isNA(ch) && ch != "none" && ch != "app_store" && ch != "testflight" && (istrue(preq) || ch=="ad_hoc" || ch=="development" || ch=="enterprise" || ch=="alternative_marketplace" || ch=="web_distribution"))
      emit("T01", id, ch " 通道需要描述文件却未登记到期格：到期是描述文件五个判据之一，没有时效格就谈不上失效" src("T01"))
    if (!isNA(pe) && isISOdt(pe) && !isNA(at) && isISOdt(at) && stamp(pe) < stamp(at))
      emit("T02", id, "描述文件到期 " pe " 早于核对时刻 " at "：这条授权已失效，台账不能继续记为可运行" src("T02"))
    if (ts == "local_signed_time") emit("T03", id, "时间基准取本机签名时刻：Signed Time 不受保护，它只说明那台 Mac 当时认为是几点" src("T03"))
    if (isNA(eb) && !isNA(ch) && ch != "none")
      emit("T09", id, "未登记时效基准（expiry_basis）：证书时效与描述文件时效分别发生在两张对象上，不写基准就无法判断失效来自哪一侧" src("T09"))
    if (!isNA(at) && isISOdt(at) && !isNA(cna) && isISOdt(cna) && stamp(cna) < stamp(at) && eb=="profile")
      emit("T04", id, "证书已过期但时效基准只记为描述文件：证书时效与描述文件时效是两格，混用后无法判断失效来自哪一侧" src("T04"))
    if (isNA(at) && (!isNA(pe) || !isNA(cna)))
      emit("T05", id, "登记了到期与有效期但没有核对时刻（audit_at）：没有基准时刻，任何「已过期/未过期」判定都不成立" src("T05"))
    if (!isNA(at) && isISOdt(at) && !isNA(pe) && isISOdt(pe) && daysApart(at, pe) > 400 && ch != "developer_id" && ch != "notarized_direct" && !isNA(ch))
      emit("T08", id, "核对时刻 " at " 之外 " daysApart(at, pe) " 天才到期，而通道是 " ch "：公开口径写明有效期通常不超过一年，远端例外只有 Developer ID 描述文件" src("T08"))
    if ((isInt(sv) && sv+0 < 20400 || slot=="legacy_only" || isfalse(der)) && isNA(rn))
      emit("T06", id, "签名形态不合（版本/DER 槽其一）却未登记是否需要重签：这一格的处置决定「失效还是未生效」" src("T06"))
    if (ch=="enterprise" && isNA(vs))
      emit("V01", id, "企业（In-House）通道但未登记校验状态：管理面可用命令强制重新校验开发者与通用描述文件" src("V01"))
    if ((vs=="pending"||vs=="failed") && isNA(flc))
      emit("V02", id, "校验状态为 " vs " 却未登记首启确认：专有 in-house 应用首次启动需要设备收到 Apple 的肯定确认才能运行" src("V02"))
    if (ra=="revoked" && !istrue(rr))
      emit("V03", id, "记为已吊销但 revoke_recorded 不为 yes：吊销是一个需要留痕的动作，不是结论" src("V03"))
    if (istrue(rr) && !istrue(dv))
      emit("V04", id, "有吊销留痕但删除未验证：只删本地副本不等于该身份不再被使用，两侧都要闭合" src("V04"))
    if (rb == "assumed") emit("V05", id, "吊销依据记为「应当已生效」：公开口径只给证书吊销清单的存在，不给设备侧何时可见" src("V05"))
    if (isNA(sr) && (!isNA(pe) && isISOdt(pe) && !isNA(at) && isISOdt(at) && stamp(pe) < stamp(at)))
      emit("V06", id, "授权已过期但未登记「代码当前是否仍在运行」：过期与在跑并存是这一层最常见的真实状态，运行时按页校验，已加载的页不会再查一次" src("V06"))
    if ((pl=="none" || isNA(pl)) && con=="confirmed")
      emit("O01", id, "观测通道为空或无通道，却给出「已确认」：确认结论要有可读回它的平面" src("O01"))
    if (fr=="team_id" || fr=="cert_list")
      emit("O02", id, "把 " fr " 记成管理面可读格：描述文件清单只给名称、UUID 与到期日，安装应用清单只给签名形态布尔值，两者都不含签名身份本体" src("O02"))
    if (pl=="ddm" && !isNA(puuid))
      emit("O03", id, "在声明式平面里挂描述文件对象：描述文件安装与清单查询属于命令面，声明式侧未建模这一对象" src("O03"))
    if (fr=="signature_bool" && con=="confirmed" && !isNA(fp))
      emit("O04", id, "用安装清单里的签名形态布尔值去闭合签名身份结论：AdHocCodeSigned 一类只说明形态，不说明是谁签的" src("O04"))
    if (isNA(srcv) || !isLineRef(lref))
      emit("D01", id, "缺来源文件或行号引用（doc.source / doc.line_ref）：这条判定无法回到公开文档逐行核对")
    if (!isNA(rat) && isISOdt(rat) && !isNA(pe) && isISOdt(pe) && stamp(rat) > stamp(pe) && con=="confirmed")
      emit("T07", id, "读数时刻晚于描述文件到期却结论为已确认：读到的只能是历史状态，不能写成当前授权有效" src("T07"))

    hard = 0
    for (j = 1; j <= nline; j++) { split(lines[j], sp, "\t"); if (sp[2] == id && (sp[1] in HB)) hard++ }
    if (isNA(ch) || isNA(sg) || (isNA(pl) && isNA(con))) grade = "J4"
    else if (hard >= 5) grade = "J4"
    else if (hard >= 1 && (isNA(at) || isNA(fp) || isNA(pe))) grade = "J3"
    else if (hard >= 1) grade = "J2"
    else grade = "J1"
    if (grade == "J4") emit("J4", id, "授权主语无法确定（通道、签名者类型或观测平面与结论缺一，或阻断信号不少于 5 条）：不能进入任何「谁被授权、何时失效、谁能证明」的表述")
    if (grade == "J3") emit("J3", id, "能定「这段代码被授权过」，不能定「以哪张证书、到哪一刻」：核对时刻、证书指纹或到期格缺失且伴随其他阻断信号")
    if (grade == "J2") emit("J2", id, "能定身份与范围，但时效、失效处置、观测通道三段至少一段未闭合：可用于内部处置，不能作为对外授权状态结论")
    if (grade == "J1") emit("J1", id, "身份、签发、形态、范围、权利、时效、失效处置、观测通道、引用九格齐备且无阻断信号：可进入对外归属表述")
    jcount[grade]++
  }

  for (j = 1; j <= nline; j++) { split(lines[j], sp, "\t"); if (sp[1] !~ /^J[1234]$/) print lines[j] > "/dev/stderr" }
  if (!QUIET) for (j = 1; j <= nline; j++) { split(lines[j], sp, "\t"); if (sp[1] ~ /^J[1234]$/) print lines[j] }
  nblk = 0; nc = 0; nsig = 0
  for (j = 1; j <= nline; j++) { split(lines[j], sp, "\t"); if (sp[1] !~ /^J[1234]$/) nsig++ }
  for (c in cnt) { if (c !~ /^J[1234]$/) nc++; if (c in HB) nblk += cnt[c] }
  printf "\n授权对象数=%d 信号行数=%d 判定行数=%d\n", nrec, nsig, nrec
  printf "不同信号码=%d 阻断信号条数=%d\n", nc, nblk
  printf "判定分布 J1=%d J2=%d J3=%d J4=%d\n", jcount["J1"], jcount["J2"], jcount["J3"], jcount["J4"]
  shown = ""
  for (j = 1; j <= nline; j++) { split(lines[j], sp, "\t"); if (sp[1] ~ /^J[1234]$/) continue; if (!(sp[1] in shn)) { shn[sp[1]] = 1; shown = shown sprintf("  %s=%d\n", sp[1], cnt[sp[1]]) } }
  printf "%s", shown
  exit (nblk > 0 ? 1 : 0)
}
' "$@"
```

---

## 22. 只读核验脚本二：通道要素差集与公告词表比对器

### 22.1 输入、输出与不做什么

**输入**（顺序固定，三份全部只读）：

1. **要素清单**：每行恰好 8 列 `<授权对象标识>,<通道>,<授权要素>,<登记状态>,<读数平面>,<词表归属>,<公告或文档引用>,<对外表述>`。
2. **通道能力表**：每行恰好 3 列 `<通道>,<授权要素>,<可得性>`，可得性取 `required` / `optional` / `not_applicable` / `undocumented`。
3. **公告词表**：Apple CSAF 导出形态（`file/cve/component/impact/description/avail`，制表符分隔，表头与 `#` 行忽略）；脚本只取 CVE 号与组件名两格，不读取影响句与解决句。

**输出**：逐条信号（stderr）、每对象判定行 Q1—Q4 与非 `-q` 模式下的**通道×required 要素覆盖矩阵**（每对象一行，给出通道、required 总数、已读数、未登记空洞数），末尾汇总块给出授权对象数、要素记录行、能力表行与通道数、公告词表可用行、组件去重数、签名授权词形命中、公告平面读数、信号行数、不同信号码、阻断信号条数与 Q1—Q4 分布。

**退出码**与脚本一相同：阻断为 1，输入不可用为 2，其余为 0。

**不做什么**：不联网取公告；不调用任何 Apple 命令行工具；不读取描述文件或证书正文；不修改输入文件；临时目录由 `mktemp -d` 创建且本实现不向其写入任何字节，退出时删除。它还有一条明确的解释边界：**给出"覆盖空洞"不等于授权补登记**——补登记需要新的读数来源，脚本只指出缺哪一格、以及按公开口径这一格本应由哪个平面给出。

### 22.2 信号族分组

| 族 | 检查对象 | 码 | 条数 | 代表判据 |
| --- | --- | --- | --- | --- |
| S | 要素清单自身形态 | S01—S09 | 9 | 八列、主键、通道与要素在词表内、四个取值域、重复登记（S08）与口径漂移（S09） |
| C | 通道能力表自身形态 | C01—C06 | 6 | 三列、通道与要素在词表内、可得性取值域、同要素双可得性（C05）、空表（C06） |
| D | 通道×要素差集 | D01—D06 | 6 | required 记为不存在（D01）、记为未登记（D02）、不适用却记为不适用（D03）、not_applicable 却有读数（D03）、通道未建模（D04）、required 完全无行（D05）、一对象两通道（D06） |
| P | 平面越界 | P01—P05 | 5 | 身份格记为管理面可读（P01）、描述文件挂声明式（P02）、读数挂公告（P03）、已读数但平面为无（P04）、其他类别与平面错配（P05） |
| V | 词表归属混用 | V01—V04 | 4 | `mixed` 写进对外结论（V01）、管理面字段写进对外结论（V02）、类别与归属不符（V03）、对外格未登记（V04，提示） |
| X | 公告词表比对 | X01—X06 | 6 | CVE 不在词表（X01）、组件名归一化后不在词表（X02）、词表不可用（X03）、组件词表零命中却有公告读数（X04）、公告平面无标识（X05，提示）、误引 MDM Identity management 页（X06） |
| T | 引用形态与口径闭合 | T01—T04 | 4 | 引用形似秘密（T01）、required 全无标识（T02，提示）、跨对象口径未统一（T03，提示）、引用形态两者都不是（T04） |
| Q | 判定 | Q1—Q4 | 4 | 见第 19.3 节 |

合计 44 个不同码：40 个信号（32 个计入阻断，`S08`、`D02`、`D05`、`P05`、`V04`、`X05`、`T02`、`T03` 共 8 个只提示）+ 4 档判定。

### 22.3 三个设计选择

**其一，"未公开文档化"是一档取值，不是缺失。** 可得性有 `undocumented` 一档，配对表也只对有公开口径的平面×类别组合放行。这样第 12 章 L9 反复强调的"分不清不该有和没说"就落在实现里：报告不会因为 Apple 没写某条通道的某一格就判它违规，但也不会把这一格当成已知。代价是能力表要人工维护，而漏维护会被 `D04` 与 `C06` 显式暴露出来。

**其二，平面可得性用配对表写死，不用启发式。** 22 项要素按五类归属，读数平面的 11 个取值里有 7 个在 `BEGIN` 段以 `vpair()` 列出可承载的类别（例如 `certificate_authority` 只承载 identity 类，`command_plane` 承载 mgmt/profile/device 三类，`declarative_plane` 只承载 mgmt/device 两类），`advisory` 不在任何配对里。任何未列出的组合走 `P05`，四种高频误写另有专码（`P01`—`P04`）。这让"管理面读不到签名身份"这类结论有确定来源，而不是靠读者理解一段文字。

**其三，公告词表只作回指，不作判定依据。** X 族全部围绕"引用的标识与组件名是否真的存在于词表"，没有任何一条 X 码试图推断缺陷性质。`X06` 是唯一一条定向码，专门拦"把 MDM 的 Identity management 页当作签名身份依据"这一具体误引，因为该页标题与"身份"一词在归一化匹配里最容易串味。

### 22.4 脚本全文

```bash
#!/usr/bin/env bash
# channel-element-diff.sh —— 分发通道×授权要素可得性差集与公告词表比对器（离线 / 只读 / 不联网 / 不碰设备）
# 作用：把三份已登记的清单放在一起算差集，专查逐条审查（authorization-ledger-review.sh）查不出的三类问题——
#       「某条通道明确需要的授权要素，台账里一条也没有」（覆盖空洞）；
#       「读数挂在某个平面上，但那个平面根本没有这一格」（平面越界）；
#       「台账引用的公告标识或组件名，公告词表里不存在」（归属悬空）。
# 输入（顺序固定，三个文件全部只读）：
#   1) 要素清单   每行 8 列：<授权对象标识>,<通道>,<授权要素>,<登记状态>,<读数平面>,<词表归属>,<公告或文档引用>,<对外表述>
#   2) 通道能力表 每行 3 列：<通道>,<授权要素>,<可得性>
#   3) 公告词表   制表符分隔（Apple CSAF 导出形态：file/cve/component/impact/description/avail；
#                 表头与 # 开头行忽略），本脚本只取 CVE 号与组件名两格
# 边界：本脚本不联网取公告、不调用 codesign/security/devicectl/xcrun 等任何 Apple 命令行工具、
#       不读取描述文件或证书正文、不修改输入文件；只核对三份清单之间是否自洽。
#       给出「覆盖空洞」不等于授权补登记：补登记需要新的读数来源，本脚本只指出缺哪一格、
#       按公开口径这一格本应由哪个平面给出。唯一写出目标是 mktemp -d 创建的临时目录，退出时删除，
#       本实现不向其写入任何字节。
set -u
LC_ALL=C; export LC_ALL

usage() {
  cat <<'EOF'
用法: channel-element-diff.sh [-q] 要素清单 通道能力表 公告词表
  -h|--help 显示本帮助；-q 只输出汇总，不逐条打印覆盖矩阵与闭合等级
要素清单行格式（8 列，逗号分隔；# 与空行忽略，行尾 CR 忽略，值里不能含逗号）:
  <授权对象标识>,<通道>,<授权要素>,<登记状态>,<读数平面>,<词表归属>,<公告或文档引用>,<对外表述>
通道（10 + 3）: app_store testflight ad_hoc development enterprise developer_id
  alternative_marketplace web_distribution notarized_direct none not_recorded unknown
授权要素（22 项，按五类归属）:
  identity  signing_identity cert_chain_root eku_code_signing cert_validity cert_revocation team_id
  profile   app_id bundle_id_claim provisioned_devices provisions_all_devices profile_expiry
            profile_name_uuid entitlement_allowlist der_profile developer_cert_list
  exec      cdhash designated_requirement nested_signature signature_format_version
  device    dev_mode_state first_launch_confirmation
  mgmt      validate_state
登记状态: recorded absent not_applicable not_recorded unknown
读数平面: provisioning_profile certificate_authority developer_console store_pipeline
  command_plane declarative_plane advisory device_console none not_recorded unknown
词表归属: profile_field identity_field hash_requirement management_field advisory_component
  mixed not_recorded unknown
对外表述: yes no not_recorded unknown
引用格: CVE-YYYY-NNNN / TN3125:89 / A/tn3125-...:89 / B/apple-platform-security-guide:2362 /
  none（确认无对应公告）/ not_recorded（未登记）；挂在 advisory 平面时写公告组件名
通道能力表行格式（3 列）: <通道>,<授权要素>,<可得性>    可得性: required optional not_applicable undocumented
信号族：S 要素清单自身形态 / C 通道能力表自身形态 / D 通道×要素差集 / P 平面越界 /
        V 词表归属混用 / X 公告词表比对 / T 引用形态与口径闭合
闭合等级：Q1 差集、平面可得性、公告词表三段齐备且无阻断 / Q2 存在阻断信号 /
          Q3 只能定覆盖面不能定归属 / Q4 连可得性都不能定
退出码：出现阻断信号时为 1，三份输入不可用时为 2，否则为 0。覆盖空洞与口径漂移不计入阻断，只落 Q3。
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

TMPD=$(mktemp -d "${TMPDIR:-/tmp}/ced.XXXXXX") || { echo "无法创建临时目录" >&2; exit 2; }
trap 'rm -rf "$TMPD"' EXIT INT TERM

awk -v QUIET="$QUIET" '
function emit(code, id, msg) { cnt[code]++; lines[++nline] = sprintf("%s\t%s\t%s", code, (id==""?"-":id), msg) }
function isNA(v)    { return (v=="" || v=="not_recorded" || v=="unknown") }
function trim(v)    { gsub(/^[[:space:]]+|[[:space:]]+$/, "", v); return v }
function nrm(v,  t) { t = tolower(v); gsub(/[[:space:]_\/.:-]/, "", t); return t }
function isCve(v)   { return (v ~ /^CVE-[0-9]{4}-[0-9]{4,}$/) }
function isDocRef(v){ return (v ~ /^(TN[0-9]{4,5}):[0-9]+(-[0-9]+)?$/) || (v ~ /^[AB]\/[A-Za-z0-9._-]+:[0-9]+(-[0-9]+)?$/) }
function isSecretish(v) {
  return (v ~ /-----BEGIN/ || v ~ /\.(p12|pfx|mobileprovision|provisionprofile|certSigningRequest)$/ || v ~ /^\/(Applications|private|var\/mobile|Users)\// || v ~ /^file:\/\// || length(v) > 200)
}
function src(c) { return (c in DOC) ? "（" DOC[c] "）" : "" }
function ck(a, b) { return a SUBSEP b }
function isBody(line) { return (line !~ /^[[:space:]]*#/ && line !~ /^[[:space:]]*$/) }
function mkset(set, str,  t, i, n) { n = split(str, t, " "); for (i = 1; i <= n; i++) set[t[i]] = 1 }
function mkel(set, cls, str,  t, i, n) { n = split(str, t, " "); for (i = 1; i <= n; i++) { set[t[i]] = 1; ELE[t[i]] = 1; ELCLS[t[i]] = cls } }
function vpair(vw, what) { PAIR[ck(vw, what)] = 1 }
function hasCapRows(ch) { return (ch in capChSet) }
function advCount(  kk, t) { t = 0; for (kk in statOf) if (statOf[kk]=="recorded" && planeOf[kk]=="advisory") t++; return t }
BEGIN {
  FS = ","
  mkset(CH, "app_store testflight ad_hoc development enterprise developer_id alternative_marketplace web_distribution notarized_direct none not_recorded unknown")
  mkel(ELE, "identity", "signing_identity cert_chain_root eku_code_signing cert_validity cert_revocation team_id")
  mkel(ELE, "profile", "app_id bundle_id_claim provisioned_devices provisions_all_devices profile_expiry profile_name_uuid entitlement_allowlist der_profile developer_cert_list")
  mkel(ELE, "exec", "cdhash designated_requirement nested_signature signature_format_version")
  mkel(ELE, "device", "dev_mode_state first_launch_confirmation")
  mkel(ELE, "mgmt", "validate_state")
  mkset(ST, "recorded absent not_applicable not_recorded unknown")
  mkset(PL, "provisioning_profile certificate_authority developer_console store_pipeline command_plane declarative_plane advisory device_console none not_recorded unknown")
  mkset(VW, "profile_field identity_field hash_requirement management_field advisory_component mixed not_recorded unknown")
  mkset(OUTW, "yes no not_recorded unknown")
  mkset(AV, "required optional not_applicable undocumented")
  # 平面能承载哪一类要素：按公开口径逐格对齐
  vpair("provisioning_profile", "profile"); vpair("provisioning_profile", "team_id")
  vpair("certificate_authority", "identity")
  vpair("developer_console", "identity"); vpair("developer_console", "profile")
  vpair("store_pipeline", "profile"); vpair("store_pipeline", "identity"); vpair("store_pipeline", "exec")
  vpair("command_plane", "mgmt"); vpair("command_plane", "profile"); vpair("command_plane", "device")
  vpair("declarative_plane", "mgmt"); vpair("declarative_plane", "device")
  vpair("device_console", "device"); vpair("device_console", "exec")
  # 词表归属能描述哪一类要素；management_field 例外只开给管理面确实能读回的那几格
  VWCLS["profile_field"]="profile"; VWCLS["identity_field"]="identity"
  VWCLS["hash_requirement"]="exec"; VWCLS["management_field"]="mgmt"
  vpair("profile_field", "profile"); vpair("identity_field", "identity"); vpair("hash_requirement", "exec")
  vpair("management_field", "mgmt"); vpair("management_field", "device")
  vpair("management_field", "profile_name_uuid")
  vpair("profile_field", "team_id")
  HB["S01"]=1; HB["S02"]=1; HB["S03"]=1; HB["S04"]=1; HB["S05"]=1; HB["S06"]=1; HB["S07"]=1; HB["S09"]=1
  HB["C01"]=1; HB["C02"]=1; HB["C03"]=1; HB["C04"]=1; HB["C05"]=1; HB["C06"]=1
  HB["D01"]=1; HB["D03"]=1; HB["D04"]=1; HB["D06"]=1
  HB["P01"]=1; HB["P02"]=1; HB["P03"]=1; HB["P04"]=1
  HB["V01"]=1; HB["V02"]=1; HB["V03"]=1
  HB["X01"]=1; HB["X02"]=1; HB["X03"]=1; HB["X04"]=1; HB["X06"]=1
  HB["T01"]=1; HB["T04"]=1
  DOC["S01"]="要素清单每行必须恰好八列（标识,通道,要素,状态,平面,词表,引用,对外）"
  DOC["S02"]="台账主键为空或含空白，无法与通道能力表对齐"
  DOC["S03"]="通道取值域按公开分发口径列出，见 TN3125 第 145—149 行与 TN3161 第 233—249 行"
  DOC["S04"]="授权要素词表为本报告五类 22 项，逐项出处见 TN3125 第 34、38—39、67—110、152—195 行，TN3126 第 69 行、TN3127 第 48—57 行与 TN3161 第 80—150 行"
  DOC["S05"]="留空、not_recorded 与 absent 是三件事：见 TN3125 第 86 行（App Store 分发描述文件根本不含设备清单格）"
  DOC["S06"]="读数平面取值不在允许集合：见 A/provisioningprofilelistitem-fields 第 5—7 行与 A/devicemanagement-declarations 第 13—23 行"
  DOC["S07"]="词表归属或对外表述取值不在允许集合：三套词表分离见 TN3125 第 94—110 行、TN3126 第 69 行、TN3127 第 48—57 行"
  DOC["S08"]="同一对象同一要素重复登记且三格一致（不阻断，但差集会重复计数）"
  DOC["S09"]="同一对象同一要素出现两种状态、平面或词表归属：口径漂移，见 TN3125 第 118—133 行"
  DOC["C01"]="通道能力表每行必须恰好三列（通道,要素,可得性）"
  DOC["C02"]="能力表里的通道取值不在允许集合"
  DOC["C03"]="能力表里的要素不在 22 项词表内"
  DOC["C04"]="可得性取值不在 required/optional/not_applicable/undocumented：见 TN3125 第 86—87 行"
  DOC["C05"]="同通道同要素两条不同可得性，差集失去唯一基准：见 TN3125 第 87 行与第 92 行"
  DOC["C06"]="通道能力表一条有效行都没有：无法计算任何差集"
  DOC["D01"]="required 要素明确登记为不存在：见 TN3125 第 77—85 行与第 88—91 行"
  DOC["D02"]="required 要素登记为未登记：覆盖空洞，见 TN3125 第 94—110 行"
  DOC["D03"]="not_applicable 要素却被记为已读数，或 required 要素被记为不适用：见 TN3125 第 86 行与第 87 行"
  DOC["D04"]="清单里的通道在能力表一行都没有：该通道判据未建模，见 TN3125 第 145—149 行"
  DOC["D05"]="required 要素在本对象完全没有登记行：与 D02 不同的第二种空洞形态，见 TN3125 第 88—91 行"
  DOC["D06"]="同一对象登记了两个通道：一次运行只有一条分发通道，见 TN3161 第 233—249 行"
  DOC["P01"]="签名身份与证书类要素记为管理面可读回：见 A/provisioningprofilelistitem-fields 第 5—7 行与 A/installedapplicationlistitem-fields 第 5—9 行"
  DOC["P02"]="描述文件类要素记为声明式平面：见 A/devicemanagement-declarations 第 13—23 行与 A/install-provisioning-profile-command 第 9—21 行"
  DOC["P03"]="公告词表只承载组件与 CVE，不承载授权要素读数：见 C/advisory-entries.tsv 的 component 列口径"
  DOC["P04"]="记为已读数但平面为无通道：见 A/validateapplicationsresponse-fields 第 5—14 行"
  DOC["P05"]="平面与要素类别不匹配（未列入前四种的组合）：见 B/apple-platform-security-guide 第 2362 行"
  DOC["V01"]="对外表述为 yes 却把两套词表混记在同一格：见 TN3125 第 111—112 行与 TN3127 第 71—72 行"
  DOC["V02"]="把管理面字段写进对外授权结论：见 A/provisioningprofilelistitem-fields 第 5—7 行"
  DOC["V03"]="平台执行口径与授权对象口径混用：见 TN3126 第 69 行、TN3127 第 48—57 行与 TN3125 第 94—110 行"
  DOC["V04"]="已读数但未登记这一格是否会对外（不阻断）：见 B/apple-platform-security-guide 第 2353 行"
  DOC["X01"]="引用的 CVE 号不在公告词表内：见 C/advisory-entries.tsv 的 cve 列"
  DOC["X02"]="引用的组件名归一化后不在公告组件词表内：见 C/advisory-entries.tsv 的 component 列"
  DOC["X03"]="公告词表无可用行：比对不可执行"
  DOC["X04"]="公告组件词表里签名授权词形（codesign、provisioning、entitlement、notarization、Team ID）命中为 0 却有读数挂在公告平面：component_absent 立场，见 C/readings-14.txt 的词表读数"
  DOC["X05"]="公告平面读数没有公告标识（不阻断）：见 C/advisory-entries.tsv 的 cve 列"
  DOC["X06"]="把 MDM 文档的 Identity management 页读成签名身份：该页讲通行码、平台单点登录与设备证明，见 A/identity-management 第 2—6 行"
  DOC["T01"]="引用格形似私钥、描述文件正文或设备绝对路径：台账只登记哪条通道在何时读回哪一格，不登记内容"
  DOC["T02"]="该对象所有 required 要素的引用格全为无标识（不阻断）：无任何可回指格，见 TN3161 第 173 行"
  DOC["T03"]="同通道同要素在对象之间既有 recorded 又有 absent（不阻断）：登记口径未统一，见 TN3125 第 118—133 行"
  DOC["T04"]="引用格既不是 CVE 也不是文档行号形态且平面非公告：这条判定无法回指，见 TN3125 第 198 行"
  DOC["Q1"]="差集、平面可得性与公告词表三段齐备且无阻断：见 TN3125 第 88—92 行与 TN3161 第 147—150 行"
  DOC["Q2"]="存在阻断信号：见 A/provisioningprofilelistitem-fields 第 5—7 行"
  DOC["Q3"]="只能定覆盖面不能定归属：见 TN3125 第 94—110 行"
  DOC["Q4"]="连可得性都不能定：见 TN3161 第 102—103 行与 A/devicemanagement-declarations 第 13—23 行"
}

# ---- 输入 1：要素清单 ----
FILENAME == ARGV[1] && isBody($0) {  line = $0; sub(/\r$/, "", line)
  n = split(line, c, ",")
  if (n != 8) { emit("S01", c[1], "要素清单记录不是恰好八列：" line src("S01")); next }
  id = trim(c[1]); ch = trim(c[2]); el = trim(c[3]); st = trim(c[4])
  pl = trim(c[5]); vw = trim(c[6]); rf = trim(c[7]); ow = trim(c[8])
  if (id == "" || id ~ /[ \t]/) { emit("S02", id, "授权对象标识为空或含空白，无法与能力表对齐" src("S02")); next }
  if (!(id in seen)) { seen[id] = 1; order[++nid] = id; chCnt[id] = 0 }
  subj = 0
  if (!(ch in CH)) { emit("S03", id, "通道取值不在允许集合：" ch src("S03")); subj = 1 }
  if (!(el in ELE)) { emit("S04", id, "授权要素不在 22 项词表内：" el src("S04")); subj = 1 }
  if (subj) subjBad[id] = 1
  if (!(st in ST)) emit("S05", id, "登记状态取值非法：" st src("S05"))
  if (!(pl in PL)) emit("S06", id, "读数平面取值非法：" pl src("S06"))
  if (!(vw in VW)) emit("S07", id, "词表归属取值非法：" vw src("S07"))
  if (!(ow in OUTW)) emit("S07", id, "对外表述取值非法：" ow src("S07"))
  if (!(el in ELE)) next
  elemRows++
  if (!(id in chSeen)) { chSeen[id] = 1; chOf[id] = ch; chCnt[id] = 1 }
  else if (chOf[id] != ch && !(ch in chAlt[id])) { chAlt[id][ch] = 1; chCnt[id]++ }
  k = ck(id, el)
  if (k in statOf) {
    if (statOf[k]==st && planeOf[k]==pl && vwOf[k]==vw) emit("S08", id, "要素 " el " 重复登记且三格一致（差集会重复计数）" src("S08"))
    else emit("S09", id, "要素 " el " 出现两种登记口径：" statOf[k] "/" planeOf[k] "/" vwOf[k] " 与 " st "/" pl "/" vw src("S09"))
    next
  }
  statOf[k] = st; planeOf[k] = pl; vwOf[k] = vw; refOf[k] = rf; outOf[k] = ow
  if (isSecretish(rf)) { emit("T01", id, "要素 " el " 的引用格形似私钥、描述文件正文或设备绝对路径：只登记引用标识，不登记内容" src("T01")) }
  else if (!(rf=="none" || isNA(rf) || rf=="") && !isCve(rf) && !isDocRef(rf) && pl != "advisory")
    emit("T04", id, "要素 " el " 的引用格既不是 CVE 也不是文档行号形态：" rf src("T04"))
  next
}

# ---- 输入 2：通道能力表 ----
FILENAME == ARGV[2] && isBody($0) {
  line = $0; sub(/\r$/, "", line)
  n = split(line, c, ",")
  if (n != 3) { emit("C01", c[1], "通道能力表记录不是恰好三列：" line src("C01")); next }
  ch = trim(c[1]); el = trim(c[2]); av = trim(c[3])
  if (!(ch in CH)) { emit("C02", ch, "能力表通道取值不在允许集合：" ch src("C02")); next }
  if (!(el in ELE)) { emit("C03", ch, "能力表要素不在 22 项词表内：" el src("C03")); next }
  if (!(av in AV)) { emit("C04", ch, "可得性取值不在允许集合：" av src("C04")); next }
  kk = ck(ch, el)
  if (kk in capOf) {
    if (capOf[kk] != av) emit("C05", ch, "要素 " el " 有两条不同可得性：" capOf[kk] " / " av src("C05"))
    next
  }
  capOf[kk] = av; capRows++
  if (!(ch in capChSet)) { capChSet[ch] = 1; capChN++ }
  next
}

# ---- 输入 3：公告词表（TSV，CSAF 导出形态，只取 CVE 与组件名两格）----
FILENAME == ARGV[3] && isBody($0) {
  line = $0; sub(/\r$/, "", line)
  if (line ~ /^file\t/) next
  n = split(line, a, "\t")
  if (n < 3) next
  cv = trim(a[2]); cp = trim(a[3])
  if (isCve(cv)) { cves[cv] = 1; vrows++ }
  if (cp != "" && cp != "component") {
    key = nrm(cp)
    if (!(key in comps)) {
      comps[key] = 1; compNames++
      if (cp ~ /[Cc]ode ?[Ss]ign|[Pp]rovision|[Ee]ntitlement|[Nn]otariz|[Tt]eam ?[Ii]d/) signHits++
    }
  }
  next
}

END {
  if (capRows == 0) emit("C06", "-", "通道能力表一条有效行都没有：通道×要素差集无法计算" src("C06"))
  if (vrows == 0 && compNames == 0) emit("X03", "-", "公告词表无可用行：公告标识与组件名比对均不可执行" src("X03"))
  advRec = advCount()
  if (vrows > 0 && compNames > 0 && signHits == 0 && advRec > 0)
    emit("X04", "-", "公告组件词表去重 " compNames " 个组件、签名授权词形命中 0，却有 " advRec " 条授权要素读数挂在公告平面：按这份词表口径，缺陷不能归到签名组件" src("X04"))

  # 差集一：能力表 required / not_applicable 对清单实际登记
  for (kk in capOf) {
    split(kk, sp, SUBSEP); ch = sp[1]; el = sp[2]; av = capOf[kk]
    if (av == "undocumented") continue
    for (ix = 1; ix <= nid; ix++) {
      id = order[ix]
      if (chOf[id] != ch) continue
      k = ck(id, el)
      if (!(k in statOf)) {
        if (av == "required") { holesReq[id]++; emit("D05", id, "通道 " ch " 的 required 要素 " el " 在本对象完全没有登记行" src("D05")) }
        continue
      }
      st = statOf[k]
      if (av == "required") {
        if (st == "absent") emit("D01", id, "通道 " ch " 需要 " el "，台账却明确记为不存在" src("D01"))
        else if (isNA(st)) { holesReq[id]++; emit("D02", id, "通道 " ch " 需要 " el "，台账记为 " st "：这一格没有读数" src("D02")) }
        else if (st == "not_applicable") emit("D03", id, "通道 " ch " 的 required 要素 " el " 被记为不适用：与能力表冲突" src("D03"))
        if (st == "recorded") { reqTot[id]++; if (isNA(refOf[k]) || refOf[k]=="none") reqNoRef[id]++ }
      }
      if (av == "not_applicable" && st == "recorded")
        emit("D03", id, "通道 " ch " 的 " el " 按公开口径不该出现，却登记了读数" src("D03"))
    }
  }
  # 差集二：清单里的通道在能力表无一行；一次运行两条通道
  for (ix = 1; ix <= nid; ix++) {
    id = order[ix]; ch = chOf[id]
    if (!isNA(ch) && ch != "none" && !hasCapRows(ch))
      emit("D04", id, "通道 " ch " 在能力表里一行都没有：这条通道的授权判据未建模，差集算不出缺哪一格" src("D04"))
    if (chCnt[id] > 1) emit("D06", id, "同一对象登记了 " chCnt[id] " 个通道：一次运行只有一条分发通道" src("D06"))
    if (reqTot[id] > 0 && reqTot[id] == reqNoRef[id])
      emit("T02", id, "本对象 " reqTot[id] " 条 required 要素读数全为无标识引用：没有任何可回指格" src("T02"))
  }
  # 平面越界与词表归属（同一格只落一个码）
  for (k in statOf) {
    if (statOf[k] != "recorded") continue
    split(k, sp, SUBSEP); id = sp[1]; el = sp[2]
    pl = planeOf[k]; vw = vwOf[k]; rf = refOf[k]; ow = outOf[k]; cls = ELCLS[el]
    if (pl == "advisory") emit("P03", id, "要素 " el " 记为公告侧读数：公告词表只给组件与 CVE，不给任何授权要素" src("P03"))
    else if (pl == "none") emit("P04", id, "要素 " el " 记为已读数但读数为零：管理面响应只回标准 ack 键，没有逐应用判定格" src("P04"))
    else if (cls=="identity" && (pl=="command_plane" || pl=="declarative_plane"))
      emit("P01", id, "要素 " el " 记为管理面可读回：描述文件清单只给名称、UUID 与到期日，安装应用清单只给签名形态布尔值，两者都不含签名身份本体" src("P01"))
    else if (cls=="profile" && pl=="declarative_plane")
      emit("P02", id, "要素 " el " 记为在声明式平面读到：描述文件安装与清单查询属于命令面，声明式侧未建模这一对象" src("P02"))
    else if (!isNA(pl) && !((pl SUBSEP cls) in PAIR) && !((pl SUBSEP el) in PAIR))
      emit("P05", id, "要素 " el "（" cls "类）挂在 " pl " 平面：这一格不属于该平面的可读集合" src("P05"))
    if (vw == "mixed" && ow == "yes")
      emit("V01", id, "要素 " el " 的词表归属为混用却写进对外结论：授权对象口径、平台执行口径与管理面口径不能在同一条结论里互换" src("V01"))
    else if (vw == "management_field" && ow == "yes")
      emit("V02", id, "要素 " el " 来自管理面字段且写进对外结论：管理面只证明「读到过这一格」，不证明授权本身" src("V02"))
    else if (!isNA(vw) && vw != "mixed" && !((vw SUBSEP cls) in PAIR) && !((vw SUBSEP el) in PAIR))
      emit("V03", id, "要素 " el "（" cls "类）的词表归属记为 " vw "：两套口径混用，结论无法回指" src("V03"))
    else if (isNA(ow)) emit("V04", id, "要素 " el " 已读数但未登记是否对外" src("V04"))
    if (isCve(rf) && vrows > 0 && !(rf in cves)) emit("X01", id, "引用的公告标识 " rf " 不在公告词表内" src("X01"))
    if (pl == "advisory" && (rf == "none" || isNA(rf))) emit("X05", id, "要素 " el " 挂在公告平面却没有公告标识" src("X05"))
    if (pl == "advisory" && rf != "" && !isCve(rf) && !(rf=="none" || isNA(rf)) && compNames > 0 && !(nrm(rf) in comps))
      emit("X02", id, "引用的组件名「" rf "」归一化后不在公告组件词表内" src("X02"))
    if (nrm(rf) ~ /identity.?management/) emit("X06", id, "引用指向 MDM「Identity management」页（讲通行码与平台单点登录，不含签名身份）：" rf src("X06"))
  }
  # 差集三：同通道同要素在多对象间口径漂移
  for (ch2 in capChSet) {
    for (e3 in ELE) {
      hasRec = 0; hasAbs = 0
      for (ix = 1; ix <= nid; ix++) {
        id = order[ix]; if (chOf[id] != ch2) continue
        kk2 = ck(id, e3); if (!(kk2 in statOf)) continue
        if (statOf[kk2] == "recorded") hasRec = 1
        if (statOf[kk2] == "absent") hasAbs = 1
      }
      if (hasRec && hasAbs) emit("T03", ch2, "通道 " ch2 " 的要素 " e3 " 在对象之间既有已读数又有明确不存在：登记口径未统一" src("T03"))
    }
  }

  if (!QUIET) {
    print "---- 通道×required 要素覆盖矩阵 ----"
    for (ix = 1; ix <= nid; ix++) {
      id = order[ix]; ch = chOf[id]; req = 0; rec = 0
      for (kk in capOf) {
        split(kk, sp, SUBSEP); if (sp[1] != ch || capOf[kk] != "required") continue
        req++
        if (ck(id, sp[2]) in statOf && statOf[ck(id, sp[2])] == "recorded") rec++
      }
      printf "%s\t通道=%s\trequired=%d\t已读数=%d\t未登记空洞=%d\n", id, (ch==""?"未登记":ch), req, rec, holesReq[id]+0
    }
  }

  for (ix = 1; ix <= nid; ix++) {
    id = order[ix]; hard = 0; soft = 0
    for (j = 1; j <= nline; j++) {
      split(lines[j], sp, "\t")
      if (sp[2] != id) continue
      if (sp[1] in HB) hard++
      else if (sp[1] !~ /^Q[1234]$/) soft++
    }
    if (subjBad[id] || hard >= 5 || isNA(chOf[id]) || chCnt[id] == 0) grade = "Q4"
    else if (hard >= 1) grade = "Q2"
    else if (soft >= 1 || capRows == 0) grade = "Q3"
    else grade = "Q1"
    qcount[grade]++
    if (grade == "Q4") emit("Q4", id, "连可得性都不能定（通道或要素本身不合、阻断信号不少于 5 条）：这条记录不能进入「哪条通道缺哪一格」的表述" src("Q4"))
    if (grade == "Q2") emit("Q2", id, "存在阻断信号：覆盖面能定，但平面越界、词表混用或公告归属悬空，不能作为差集结论" src("Q2"))
    if (grade == "Q3") emit("Q3", id, "只能定覆盖面不能定归属：required 要素存在未登记空洞或口径漂移，缺哪一格清楚，但这一格该由谁读回未定" src("Q3"))
    if (grade == "Q1") emit("Q1", id, "通道×要素差集、平面可得性、公告词表三段齐备且无阻断：可作为「这一格本应由哪条通道、哪个平面给出」的表述" src("Q1"))
  }

  for (j = 1; j <= nline; j++) { split(lines[j], sp, "\t"); if (sp[1] !~ /^Q[1234]$/) print lines[j] > "/dev/stderr" }
  if (!QUIET) for (j = 1; j <= nline; j++) { split(lines[j], sp, "\t"); if (sp[1] ~ /^Q[1234]$/) print lines[j] }
  nblk = 0; nc = 0; nsig = 0
  for (j = 1; j <= nline; j++) { split(lines[j], sp, "\t"); if (sp[1] !~ /^Q[1234]$/) nsig++ }
  for (c2 in cnt) { if (c2 !~ /^Q[1234]$/) nc++; if (c2 in HB) nblk += cnt[c2] }
  printf "\n授权对象数=%d 要素记录行=%d 能力表行=%d 能力表通道数=%d\n", nid, elemRows, capRows, capChN
  printf "公告词表可用行=%d 组件去重数=%d 签名授权词形命中=%d 公告平面读数=%d\n", vrows, compNames, signHits, advRec
  printf "信号行数=%d 不同信号码=%d 阻断信号条数=%d\n", nsig, nc, nblk
  printf "闭合等级 Q1=%d Q2=%d Q3=%d Q4=%d\n", qcount["Q1"], qcount["Q2"], qcount["Q3"], qcount["Q4"]
  shown = ""
  for (j = 1; j <= nline; j++) { split(lines[j], sp, "\t"); if (sp[1] ~ /^Q[1234]$/) continue; if (!(sp[1] in shn)) { shn[sp[1]] = 1; shown = shown sprintf("  %s=%d\n", sp[1], cnt[sp[1]]) } }
  printf "%s", shown
  exit (nblk > 0 ? 1 : 0)
}
' "$1" "$2" "$3"
```

---
## 23. 两个脚本的全量分支覆盖验收

第 21 章与第 22 章给出了脚本本身。这一章回答一个更容易被跳过、却决定这两份脚本能不能被引用的问题：**脚本里写过的每一条信号，是否真的在某个输入下出现过**。本报告采用一条硬规则——**不能触发的信号等于没有写过**。一条只存在于源码字符串里的信号，和一条作者随手编出来但没有对应输入形态的信号，在读者这边没有任何区别；两者都会让「这份台账合不合格」的判定变成一个不可复核的口头承诺。

### 23.1 验收标准

四条标准，全部可机械核对：

1. **逐码可达**：脚本一声明的 64 个信号码（59 个阻断码 + 软信号 `S08` + 判定档 `J1`—`J4`）与脚本二声明的 44 个（32 个阻断码 + 8 个软信号 + 判定档 `Q1`—`Q4`），每一个都必须在至少一次真实运行里被打印出来。不接受「读代码看出来会触发」作为替代。
2. **逐次留痕**：每次运行记录一条完整块——运行的命令行、逐条信号原文、脚本自己打印的汇总行（授权对象数、信号行数、不同信号码数、阻断信号条数、判定分布）、以及 shell 退出码。运行记录就是 `FX/run-log.txt`（14 次）与 `FX/run-log-2.txt`（16 次），本报告的每一处数字都来自这两份原始输出，不来自任何事后整理。
3. **好夹具必须有下界**：一个九格齐备、逐格有文档引用的台账（`FX/fixture-ledger-good.txt`）与一份三段齐备的要素清单（`FX/fixture-element-good.csv`）必须得到 **零信号 + 最高档**（分别是 `J1` 与 `Q1`）。没有这条，"阻断"就没有参照——读者无法判断脚本是严格，还是对任何输入都报错。
4. **只读约束的实证**：所有 30 次运行都在离线目录里执行，命令行只有 `sh 脚本 输入文件 [输入文件…] [选项]` 一种形状；运行前后对全部夹具做 `md5` 比对，没有任何输入被改写。两个脚本都没有网络调用、没有 `codesign`/`security`/`xcrun`/`devicectl`/`altool`/`syspolicy_check` 调用，唯一写出目标是 `mktemp -d` 的临时目录且由 trap 删除（源码里可见：脚本一最后一行是 `' "$@"`，脚本二最后一行是 `' "$1" "$2" "$3"`，都只把参数交给 awk 的只读 `getline`）。

### 23.2 三十次实跑

脚本一 `tools/authorization-ledger-review.sh`，14 次运行，记为 R1—R14：

| 次 | 运行标签 | 命令行要点 | 对象数 | 信号行 | 不同码 | 阻断条 | 判定分布 | 退出码 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| R1 | `codes` | 全码遍历夹具 | 69 | 307 | 60 | 306 | J2=1 J3=1 J4=67 | 1 |
| R2 | `good` | 九格齐备基准 | 3 | 0 | 0 | 0 | J1=3 | 0 |
| R3 | `mixed` | 混合缺陷 | 6 | 40 | 33 | 40 | J2=1 J4=5 | 1 |
| R4 | `multi` | 同时传入 good + mixed 两个文件 | 9 | 40 | 33 | 40 | J1=3 J2=1 J4=5 | 1 |
| R5 | `quiet` | 同 R3，加 `-q` | 6 | 40 | 33 | 40 | J2=1 J4=5 | 1 |
| R6 | `help` | `-h` | — | — | — | — | — | 0 |
| R7 | `noargs` | 不带任何参数 | — | — | — | — | — | 2 |
| R8 | `missing` | 传入不存在的文件 | — | — | — | — | — | 2 |
| R9 | `empty` | 零字节文件 | 0 | 0 | 0 | 0 | 全为 0 | 0 |
| R10 | `comments` | 只有注释与表头 | 0 | 0 | 0 | 0 | 全为 0 | 0 |
| R11 | `malformed` | 列数不是恰好三列 | 1 | 8 | 6 | 8 | J4=1 | 1 |
| R12 | `unknown-field` | 字段名未知或自造 | 1 | 5 | 4 | 5 | J4=1 | 1 |
| R13 | `shape` | 枚举/日期/数值/指纹形态不合 | 1 | 13 | 9 | 13 | J4=1 | 1 |
| R14 | `secret-shapes` | 取值形似私钥、PKCS#12 或正文 | 1 | 7 | 6 | 7 | J4=1 | 1 |

脚本二 `tools/channel-element-diff.sh`，16 次运行，记为 R15—R30：

| 次 | 运行标签 | 命令行要点 | 对象数 | 要素行/能力行/通道 | 信号行 | 不同码 | 阻断条 | 判定分布 | 退出码 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| R15 | `good` | 三段齐备基准 | 2 | 43 / 185 / 9 | 0 | 0 | 0 | Q1=2 | 0 |
| R16 | `mixed` | 混合缺陷要素清单 | 4 | 74 / 185 / 9 | 10 | 9 | 7 | Q2=3 Q3=1 | 1 |
| R17 | `codes` | 全码遍历夹具 | 27 | 36 / 13 / 4 | 185 | 33 | 34 | Q2=18 Q3=7 Q4=2 | 1 |
| R18 | `badcaps` | 能力表取值不合 | 27 | 36 / 1 / 1 | 66 | 32 | 61 | Q2=24 Q4=3 | 1 |
| R19 | `emptycaps` | 能力表零有效行 | 27 | 36 / 0 / 0 | 61 | 28 | 56 | Q2=24 Q4=3 | 1 |
| R20 | `emptyvocab` | 公告词表零可用行 | 27 | 36 / 13 / 4 | 183 | 31 | 32 | Q2=17 Q3=8 Q4=2 | 1 |
| R21 | `quiet` | 同 R17，加 `-q` | 27 | 36 / 13 / 4 | 185 | 33 | 34 | Q2=18 Q3=7 Q4=2 | 1 |
| R22 | `help` | `-h` | — | — | — | — | — | — | 0 |
| R23 | `noargs` | 不带参数 | — | — | — | — | — | — | 2 |
| R24 | `twoargs` | 只给两个输入 | — | — | — | — | — | — | 2 |
| R25 | `missing` | 第一个输入不存在 | — | — | — | — | — | — | 2 |
| R26 | `unreadable` | 第三个输入不可读 | — | — | — | — | — | — | 2 |
| R27 | `comments` | 只有注释与表头 | 0 | 0 / 13 / 4 | 0 | 0 | 0 | 全为 0 | 0 |
| R28 | `empty` | 零字节要素清单 | 0 | 0 / 13 / 4 | 0 | 0 | 0 | 全为 0 | 0 |
| R29 | `allempty` | 三个输入全为空 | 0 | 0 / 0 / 0 | 2 | 2 | 2 | 全为 0 | 1 |
| R30 | `crlf` | CRLF 换行的 good 夹具 | 2 | 43 / 185 / 9 | 0 | 0 | 0 | Q1=2 | 0 |

三处值得单独说明的读数形状：

- **R4 与 R5 证明脚本与选项不改变判定**。R4 把基准夹具和缺陷夹具拼在一起，对象数从 6 变成 9，`J1` 从 0 变成 3，缺陷侧的 `J2=1 J4=5` 一格未动；R5 加 `-q` 后汇总数字与 R3 完全一致，只是不再逐条打印判定行。判定不依赖调用形式。
- **R29 是退出码与判定档的一次分离**。三个输入全空时，对象数为 0，因此没有任何一条 `Q1`—`Q4` 被赋值（判定档是逐对象打的），但 `C06`（能力表一条有效行都没有）和 `X03`（公告词表无可用行）这两条阻断仍然成立，退出码为 1。脚本二结尾是 `exit (nblk > 0 ? 1 : 0)`——**退出码回答"这次运行有没有阻断信号"，等级回答"每条记录能不能用"**，两者不是同一个量。写成「Q 全 0 所以通过」是错的。
- **R30 证明换行符不是隐性失败**。CRLF 版夹具与 LF 版得到完全相同的读数（2 个对象、0 条信号、`Q1=2`），所以第 22 章说"要素清单可以用任何编辑器产出"是真的，不需要额外约束。

### 23.3 逐码表一：脚本一的 64 个码

`FX/codemap-1.txt` 由脚本一的真实输出逐码去重生成，"首次触发"是该码第一次出现的那次运行，"累计条数"是 R1—R14 全部输出里该码出现的次数总和（含判定行）。

信号族：

| 码 | 首次触发 | 累计条数 | | 码 | 首次触发 | 累计条数 | | 码 | 首次触发 | 累计条数 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| S01 | R1 | 4 | | K01 | R1 | 9 | | O01 | R1 | 7 |
| S02 | R1 | 4 | | K02 | R1 | 3 | | O02 | R1 | 5 |
| S03 | R1 | 7 | | A01 | R1 | 73 | | O03 | R1 | 4 |
| S04 | R1 | 5 | | A02 | R1 | 1 | | O04 | R1 | 1 |
| S05 | R1 | 1 | | A03 | R1 | 1 | | D01 | R1 | 74 |
| S06 | R1 | 6 | | A04 | R1 | 1 | | H01 | R1 | 4 |
| S07 | R1 | 1 | | A05 | R1 | 13 | | H02 | R1 | 4 |
| S08 | R1 | 1 | | A06 | R1 | 5 | | H03 | R1 | 1 |
| S09 | R1 | 2 | | A07 | R1 | 2 | | H04 | R1 | 1 |
| B01 | R1 | 4 | | A08 | R1 | 21 | | T01 | R1 | 16 |
| B02 | R1 | 4 | | A09 | R1 | 5 | | T02 | R1 | 4 |
| B03 | R1 | 4 | | A10 | R1 | 5 | | T03 | R1 | 4 |
| B04 | R1 | 4 | | A11 | R1 | 10 | | T04 | R1 | 4 |
| B05 | R1 | 4 | | A12 | R1 | 16 | | T05 | R1 | 3 |
| B06 | R1 | 1 | | C01 | R1 | 8 | | T06 | R1 | 6 |
| B07 | R1 | 30 | | C02 | R1 | 1 | | T07 | R1 | 4 |
| C03 | R1 | 1 | | C04 | R1 | 8 | | T08 | R1 | 4 |
| C05 | R1 | 4 | | C06 | R1 | 4 | | T09 | R1 | 22 |
| V01 | R1 | 5 | | V02 | R1 | 1 | | V03 | R1 | 1 |
| V04 | R1 | 4 | | V05 | R1 | 4 | | V06 | R1 | 4 |

判定档：

| 码 | 首次触发 | 累计条数 | 说明 |
| --- | --- | --- | --- |
| J1 | R2 | 6 | 唯一没有在全码遍历夹具里出现的码——`J1` 的条件是"该对象零阻断信号"，任何为触发其他码而设计的对象都不可能同时是 `J1`，只能由基准夹具给出 |
| J2 | R1 | 3 | |
| J3 | R1 | 1 | |
| J4 | R1 | 81 | |

64 个码全部可达，其中 60 个信号码在 R1 一次运行内全部触发（R1 汇总行的"不同信号码=60"正是这 60 个信号码，与逐码表的信号码行数一致），另外四个是判定档：`J2`/`J3`/`J4` 由同一次 R1 的判定分布给出（1 / 1 / 67），`J1` 只在零阻断对象上成立，由 R2 补齐。

### 23.4 逐码表二：脚本二的 44 个码

`FX/codemap-2.txt` 同源生成。

| 码 | 首次触发 | 累计条数 | | 码 | 首次触发 | 累计条数 | | 码 | 首次触发 | 累计条数 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| S01 | R17 | 5 | | D01 | R16 | 4 | | P01 | R16 | 6 |
| S02 | R17 | 10 | | D02 | R16 | 5 | | P02 | R17 | 5 |
| S03 | R17 | 5 | | D03 | R17 | 6 | | P03 | R16 | 16 |
| S04 | R17 | 5 | | D04 | R17 | 58 | | P04 | R17 | 5 |
| S05 | R17 | 5 | | D05 | R17 | 423 | | P05 | R17 | 5 |
| S06 | R17 | 5 | | D06 | R17 | 5 | | C01 | R18 | 2 |
| S07 | R17 | 10 | | T01 | R17 | 5 | | C02 | R18 | 1 |
| S08 | R17 | 10 | | T02 | R17 | 6 | | C03 | R18 | 1 |
| S09 | R17 | 5 | | T03 | R17 | 6 | | C04 | R18 | 1 |
| V01 | R17 | 5 | | T04 | R17 | 5 | | C05 | R18 | 1 |
| V02 | R16 | 6 | | X01 | R16 | 5 | | C06 | R19 | 2 |
| V03 | R16 | 21 | | X02 | R17 | 4 | | X03 | R20 | 2 |
| V04 | R16 | 6 | | X04 | R16 | 5 | | X05 | R17 | 5 |
| X06 | R17 | 5 | | | | | | | | |

判定档：

| 码 | 首次触发 | 累计条数 | 说明 |
| --- | --- | --- | --- |
| Q1 | R15 | 4 | 只由基准夹具与 CRLF 夹具给出（R15、R30 各 2 个对象） |
| Q2 | R16 | 86 | |
| Q3 | R16 | 16 | |
| Q4 | R17 | 10 | |

44 个码全部可达，分布方式和脚本一不同，这个差异本身就是内容：**`S`、`D`、`P`、`T`、`X` 五个族的绝大多数码在 R17（全码遍历夹具）触发，但 `C01`—`C05` 首次出现在 R18、`C06` 在 R19、`X03` 在 R20**。`C` 族是"通道能力表本身不合"，`X03` 是"公告词表无可用行"，它们检查的是**第二、第三个输入文件的形状**，不是台账记录的形状。所以无论要素清单写得多齐全，都不可能靠它触发这些码——必须专门构造一张坏能力表和一份空词表。同理 `V02`、`V03`、`V04`、`X01`、`X04`、`D01`、`D02`、`P01`、`P03`、`Q2`、`Q3` 首次出现在 R16（混合缺陷清单）而不是 R17：这些码要求"一个对象既有已读数又有明确不存在""平面取值越界"这类跨行的矛盾，单靠一份穷举夹具摆不出来，需要两条以上记录互相打脸。

`D05` 的累计条数 423 远高于其他码，不是缺陷放大，而是它的定义使然：required 要素在该对象完全没有登记行时逐条打印，R17—R20 四次运行里每次都是 27 个对象 × 多个未登记的 required 要素，第四次仍在全量重复。**读数多的码不等于更重要的码**，第 12 章的通道差集结论主要靠 `D01`/`D02` 的形态区分，`D05` 只提供"缺格"这一种最粗的信号。

### 23.5 可达性核对怎么做

过程可以复述成五步，任何一步都能被第三方独立重跑：

1. **先列码表**：从脚本源码里逐条抓 `emit("CODE"` 的第一个参数，得到声明码的完整集合（脚本一 64、脚本二 44）。这一步先于任何运行，因为它决定验收目标；否则会变成"跑出了什么就承认什么"。
2. **构造全码遍历夹具**：一份输入，使每个码的触发条件都至少有一个对象满足。脚本一的 R1 就是这一份，一次跑出 60 个信号码。
3. **差额补夹具**：把 R1 没打出来的码列出来，逐个问「它在什么输入形态下才可能出现」。脚本一的答案是 `J1`——它要求该对象零阻断，于是它只能由基准夹具（R2）给出，这是构造性的、不是遗漏。脚本二的答案是 `C` 族与 `X03`——它们由输入文件形状决定，于是分别构造坏能力表（R18）、空能力表（R19）、空词表（R20）。
4. **错误路径同样用输入验证**：`-h`、无参数、参数不足、文件不存在、文件不可读这六种不是靠读代码里的 `usage()` 分支确认的，而是各跑一次看退出码（R6—R8、R22—R26）。脚本一对后四种给 2，脚本二同样给 2；两者对帮助都给 0。这类运行的输出不参与逐码表，因为它们不针对具体对象。
5. **两条交叉核对**：其一，每次运行末尾脚本自己打印的逐码计数列表，行数必须等于同一运行汇总行的"不同信号码"——脚本一 R1 为 60/60，脚本二 R17 为 33/33、R18 为 32/32、R19 为 28/28、R20 为 31/31、R29 为 2/2，其余各次同法核对；其二，逐码表里的"累计条数"必须等于该码在三十次运行记录里各次计数之和，例如 `D05` 的 423 = R17 的 141 + R20 的 141 + R21 的 141。**两组数字分别由脚本自己算出，彼此一致才算通过**，任何一处不一致都说明提取环节有错，而不是判定有错。

注意"首次触发"与"该次出现的码数"是两个量：R17 一次出现 33 个码，但其中 25 个在逐码表里标 R17、8 个更早已在 R16 出现过。逐码表记的是第一次，不是全部。

一处诚实的限制：逐码表记录的是**首次触发**与累计次数，不记录每个码的每种文案分支。同一个码可能有多条措辞不同的句子（例如脚本一的 `A01` 既覆盖"两格都空"也覆盖"只给一半"），累计数 73 条里两种措辞都有，但没有分别计数。本报告只声明"该码至少可达"，不声明"该码的每一条文案都可达"。

### 23.6 全文一致性再核验

装配完成后，对最终 Markdown 单文件做六项机械核对，全部通过才提交：

| 核对项 | 做法 | 本报告的读数 |
| --- | --- | --- |
| 引用逐条回查 | 抽出正文所有英文引号片段，逐条在归档目录（`A/`、`B/`、`C/`、`RAW/`、`RAWW/`、`IDX/`）里做宽松匹配：按字符类切词、用连接符串成正则、允许标点与撇号形态差异 | 第 9—22 章新增引号全部命中，0 条 MISS；一条曾不命中的段落改写为两个片段（原文里含引号嵌套），仍逐段命中 |
| 文档行号核对 | 对每处「第 N 行」「第 N—M 行」引用，读取归档文件对应行，确认该行确实含被引内容；第 3 章三张词表的"行锚"列若写简称，按该章开头的简称对照表换成归档路径再比对 | 逐条通过；两处范围写窄或写偏（脚本二等级阶梯曾写成 324—332、签名格式文档曾写成 24—27）已改为 326—336 与 16—19 / 23—27 |
| 内嵌脚本重抽取 | 按围栏起止行把两个脚本从成品 Markdown 抽回文件，与 `tools/` 下的源文件做字节级比对 | 一致；抽取产物再 `bash -n`，并分别跑基准夹具与缺陷夹具，读数与 R2/R3、R15/R16 完全相同 |
| 章题与锚点 | 目录 28 项锚点按本报告的 slug 规则重算，与实际 `##` 标题逐字符比对 | 28/28 一致 |
| setext 污染 | 扫描每个 `---` 之前一行是否为正文；若是，该行会被渲染成额外的 `<h2>` 并污染站点目录 | 0 处；站点目录计数应等于 28（章节）+ 2（摘要与目录本身） |
| 数字自洽 | 正文出现的每一个计数（392、101、64、44、108、30、954、22、13、53、65、1766、95）都能指回某次脚本输出、某条 `C/readings-14.txt` 读数或某个归档文件的行数 | 逐条对齐 |

### 23.7 这份验收不能证明什么

覆盖验收只证明分支可达，不证明判定正确，更不被应被读成下面这五件事：

1. **不证明这些码在真实台账上会出现**。夹具是为本报告构造的，它们证明"给定这种输入形态，脚本会给这种判定"，不证明任何组织的真实台账里有或没有这种形态。第 20 章的目标值（多数指标目标为 0）是口径约定，不是预测。
2. **不证明信号文案里的文档行号构成因果**。每条信号的「见 TN3161 第 N 行」给出的是**可回查的引用坐标**——读者可以在归档里翻到那一行核对这句话；它不表示 Apple 的签名实现按这一行执行，也不表示该行的文档描述与设备行为一致（第 26 章列出的正是若干文档没有描述的路径）。
3. **不证明 `J1`/`Q1` 的记录对应一个真的能运行的程序**。脚本一给 `J1` 只说明"这份台账自洽且可回指"，不说明那台设备当时允许这段代码运行；执行判定在设备侧（第 4—8 章的核心不对称正是：执行侧判定充分但不输出归属信息，归属侧齐备却不参与执行判定）。把 `J1` 读成"这台机器会放行"是第 24 章的第 2 个误区。
4. **不证明离线夹具覆盖了真实数据形态**。夹具里没有真证书、真描述文件、真公告 JSON。脚本被设计成即便拿到这些也拒收（`K01`/`K02`/`T01`），所以"没有真实材料"不是缺陷，但同时也意味着"用真实材料跑一遍"这件事本报告没有做过，不能声称。
5. **不证明 Apple 内部实现**。两个脚本读的都是公开文档的**描述**与公告的**措辞**。第 13 章关于三个 TN 文档零吊销词形的读数，说的是这三份文档没有写；不是吊销机制不存在。
## 24. 十二个误区

每个误区给出：常见说法、错在哪、公开口径出处、正确写法，以及本文两个脚本里哪个码会拦它。所有信号名与文档行号都可在第 21—23 章和 `.srcx14` 归档里逐条回查。

### 误区一 "签名校验通过，所以授权有效"

签名校验回答的是**这段代码有没有被改动**，不是**这段代码凭什么被允许运行**。TN3126 第 9 行把它的作用范围写得很窄很清楚："This technology is absolutely central to code signing's core function: protecting code from malicious modification."（保护可执行页、资源与元数据不被篡改）。授权的主语在另外两张对象上：签名身份（证书 + 私钥，TN3161 第 102 行）与描述文件（授权了哪些设备、哪些权利、到哪天）。一份签名完好、未被篡改、描述文件却早已到期的应用，前半句成立、后半句失效。

正确写法：`obs.validation_passed` 与 `when.expiry_basis` 必须分两格；前者不能推出后者。**信号：`O04`（用签名形态布尔值闭合签名身份结论）、`T07`（读数时刻晚于到期却记为已确认）、`T09`（时效基准未登记）。**

### 误区二 "台账判到 J1，设备上就会放行"

第 23.7 节第三条限制。`J1` 的定义是"九格齐备且无阻断信号"，它是**台账自身的自洽度**，不是设备行为的预测。执行侧的判定发生在内核与安全校验组件里（第 4—8 章），它不读你的台账，也不产出可读回的归属字段——这正是本文反复使用的不对称：执行侧判定充分但不输出归属信息，归属信息齐备的台账不参与执行判定。

正确写法：`J1` 只授权一句"这条记录可以对外表述"，不授权"这台设备会放行"。**信号：无（这是等级被读错，不是数据缺失）。**

### 误区三 "Team ID 就是责任人"

Team ID 是 10 位字母数字串（`A10` 校验形态），它标识的是**团队**，不是某一次授权，也不是某个持钥人。同一 Team 下可以有多张分发证书、多个成员各自持有私钥副本，而签名动作只留下 Team 级标识。共享签名身份的公开口径就写着要把身份"share them with other team members, and keep your local identities synchronized with your developer account"（sharing-your-teams-signing-certificates 第 5 行）。团队内谁签的，要靠构建机、签发时刻与证书指纹三格交叉才能定。

正确写法：`id.team_id` 定责任范围，`id.cert_fp` 与 `when.sign_at` 才定到具体一次签发；只有前者时归属结论最多写到团队级。**信号：`A10`（形态不合）、`A12`（只有 Team ID 没有证书指纹，失效不可证）、`A11`（登记了保管位置却没登记持有人）。**

### 误区四 "证书一吊销，代码就全局跑不起来了"

吊销在**账号侧**是有公开口径的动作（sharing 文档第 39—41 行的 "Delete a revoked certificate"，且"You can only delete certificates that you or a team member revoke in your developer account."），在 **PKI 层**也有公开的吊销清单（apple-certificateauthority 第 52—56 行列出五张 CRL）。但从"清单里多了一项"到"某台设备上这段代码不再被允许运行"之间，公开文档没有给路径：TN3161 全文 277 行不含 revoke / revocation / CRL 任一子串，TN3125（207 行）与 TN3127（200 行）同样为 0（第 16 章读数 11）。

正确写法：能确认的只有"账号侧动作已发生"与"某台设备某一次校验未通过"；把"已对全部设备生效"写进台账时 `state.revocation_basis=assumed`，并按 `V05` 阻断。**信号：`V03`、`V04`、`V05`。**

### 误区五 "描述文件到期就是授权到期"

这条链上有**两个到期日**，各自落在不同对象上：证书有自己的有效期止（TN3161 第 147—150 行给出签名时要核对当前时间在有效期内），描述文件有自己的 `ExpirationDate`（TN3125 第 89 行）。二者可以相差数月，也可以方向相反。失效来自哪一侧决定了责任方是运营描述文件的人还是持有签名身份的人。

正确写法：`when.expiry_basis` 必填，取值只能是 `profile` 或 `certificate`；两侧都在时另记失效归因。**信号：`T09`（未登记基准）、`T01`/`T02`（把两侧混算成一个"剩余天数"）。**

### 误区六 "App Store 包里没有描述文件，说明它没有授权"

这是把"授权对象的物理落点"当成了"授权本身"。TN3125 第 149 行明说商店包不含内嵌描述文件的原因：商店在分发时替它做了校验；TN3161 第 242 行补上另一半——"While this example was from macOS, this re-signing happens for all App Store apps on all platforms."也就是说商店通道不是"没有授权"，而是**授权改由签名侧重写、描述文件这一格结构性不存在**。

正确写法：`what.der_profile=not_applicable`（不是 `absent`，也不是空），并在 `doc.source` 记这条 not_applicable 的依据。**信号：`D01`（把结构性不存在当缺失）、`H04`（App Store 通道既记为「由 Apple 重签」又把时效基准记为描述文件）。**

### 误区七 "管理面能读回签名与授权状态"

管理面这一格比多数人以为的窄得多。`ProvisioningProfileListItem` 只有三个字段：`UUID`、`Name`、`ExpiryDate`（第 5—7 行）——没有签名者、没有 Team ID、没有权利清单。`ValidateApplicationsResponse` 的十个键（第 5—14 行）里没有一个逐应用的判定格，`Status` 说的是这条命令的响应状态。声明式管理的 53 个 declaration 类型里 `provision` 词形出现 0 次；配置负载键表里 `CertificateRevocation` 存在（第 46 行）而描述文件类载荷不存在。

正确写法：管理面能给的是"这台设备上有这个 UUID 的描述文件，它写着哪天到期"；任何"管理面确认签名有效"的表述都要被平面越界拦下。**信号：`O02`（平面越界）、`P04`（记为已读数但读数为零）、`D02`（该通道根本没有这一格）。**

### 误区八 "独立可执行文件权利格全空是我们的台账漏填了"

TN3125 第 150 行："A standalone executable can’t claim a restricted entitlement because there’s no place to embed the provisioning profile that authorizes that claim."没有地方嵌描述文件，就没有授权来源可登记——这是**形态决定的必然空缺**，不是数据缺失（第 26 章 N6）。把它当漏填去补，会用一份不受签发规则约束的自建声明填空。

正确写法：`what.ent_slot=none` 并把这一格标为结构性不适用；需要受限权利就改成 bundle 形态。**信号：`H01`（声明了受限 entitlement 却记为不需要描述文件授权）、`K02`（用正文代替引用）。**

### 误区九 "把描述文件正文抄进台账更方便核对"

TN3125 第 33 行明说描述文件精确格式"isn’t documented and could change at any time"，并警告不要基于这些细节构建产品。把正文抄进台账，等于把一份本来只受密钥链与设备规则约束的凭证复制成一份不受任何签发规则约束的副本，而这份副本还会长在备份、工单与共享盘里。台账需要的是**引用坐标**：哪张证书指纹、哪条通道、什么时刻读回哪一格。

正确写法：只登记 `id.cert_fp`、`id.profile_uuid`、`doc.source`/`doc.line_ref`。**信号：`K01`（`key.*` 命名空间与形似私钥/PKCS#12/CSR/描述文件材料的取值）、`K02`（形似设备绝对路径或整段正文）、`S09`（把解析出来的内部字段名当字段登记）；脚本二里同一含义由 `T01`（引用格形似私钥、正文或设备绝对路径）承担。**

### 误区十 "公告里查不到签名组件，说明签名链没有缺陷"

这是把公告的词表当成了缺陷宇宙的名录。392 条 CVE 行、101 个去重组件名里，15 个签名与分发授权词形只有 `kernel` 命中 1 个组件（第 16 章读数 13）；解决句里 `signature` 1 条、`certificate` 1 条、`signing`/`trust`/`provisioning`/`revoked`/`chain of trust`/`code-signing` 全部 0 条（读数 16）。公告口径是**组件 × CVE**，不是授权对象；命中为 0 说明的是"公告这一平面无法表述这件事"，而不是"不存在"（第 14 章 P13）。

正确写法：授权要素不得挂到公告平面；公告只用于回指已有 CVE 标识。**信号：`P03`、`X04`。**

### 误区十一 "旧签名格式只是不推荐，先跑着"

旧格式不是"能用但不推荐"。《Using the latest code signature format》第 6 行："Apps signed with a previous signature format will not launch."第 12 行给出阈值："For any value of v less than 20400, you need to re-sign your app"。而现场补救那条路是被明确关掉的对移动平台："Re-signing apps from the command-line is not supported for iOS, iPadOS, tvOS, visionOS, and watchOS."（第 35 行）。也就是说：**唯一被支持的动作是回到 macOS 用 Xcode 重新签名并重新分发**，不是设备上想办法。

正确写法：`state.signature_version` 低于阈值时结论是"不能启动"，处置格只应指向重签与重新分发；任何"现场修补"的写法都要被处置边界拦下。**信号：`B03`（授权对象不是 DER 形态，旧形态不启动）、`B04`（代码目录版本低于 20400 需重签）、`B05`（权利槽只在 -5 有值、-7 为空）、`T06`（形态不合却未登记是否需要重签）。**

### 误区十二 "指标都是 0 就说明这条链健康"

`O2`（主语缺失率）、`O9`（公告悬空率）、`O10`（表述越界率）的目标确实是 0，但目标为 1.0 与"趋势下降"的几格不是同一回事。`O6` 通道建模率的分母是"清单出现的通道数"——把能力表删空时脚本二直接给 `C06`（第 23.2 节 R19），覆盖矩阵随之为空，此时"建模率 1.0"和"空洞 0"都是同一件事的两种假象；`O7` required 空洞密度的绝对值还受第 26 章 N4 的 `undocumented` 档压着下限。`O8` 处置闭环率更直接：它的分母是"记为已吊销的对象"，一条都没记时这个比率根本没有定义，不是 1.0。第 20 章第二条使用说明写的就是 `O6` 必须与 `O7` 同读。

正确写法：任何"0"都要与它所在档位的有效输入规模一起报出；`J` 档与 `Q` 档互不豁免——`Q1` 不使 `J4` 变轻，反之亦然。**信号：`C06`、`Q4` 与 `J4` 并存这一读数形态本身。**

---

## 25. 常见问题

**Q1：这一篇和前十三篇的分工线在哪？**

前十三篇里有九篇会碰到"签名"这个词，但主键都不是它：02 篇写应用运行时能碰什么（entitlement 的语义与访问后果），05 篇写设备与密钥的证明，07 篇用 Team ID 做匹配键，10 篇写设备归属与凭据作废，11 篇写数据副本在谁手上，12 篇写第三方依赖的构建归属，13 篇写记录能不能算证据。本文的主键是**一次运行授权**：这段代码凭什么被允许运行、授权什么时候失效、失效之后谁能证明。接缝线在第 2 章的视角声明里逐条给出。

**Q2：为什么是十一层加一个判定层？**

因为这十一层每层的**主语不同**：签发者、构建者、账号管理员、运营描述文件的人、商店、企业管理员、设备使用者、Apple PKI、公告作者、复核处置人、观测平面。写成"十条签名规则"会把最重要的事实掩盖掉——**同一份应用会同时被这十一个主语以不同词表描述，而公开侧没有一张换算表**。第 15 章的归属矩阵就是按主语摊开的。

**Q3：为什么脚本一和脚本二不能合成一支？**

输入形制不同，且形制本身就是结论的一部分。脚本一吃三元组台账（对象、字段、值），它要判断"这条授权记录能不能被表述"；脚本二吃三份文件（要素清单、通道能力表、公告词表），它要计算"通道 × 要素的差集里缺哪一格"。合成之后，"你的台账自洽"和"这个平面根本没有这一格"这两件完全不同的事会被压成同一批退出码——而这两件事的处置方根本不是同一拨人。第 19.4 节的"两套等级互不豁免"就是这个分离的理由。

**Q4：`undocumented` 和 `absent` 为什么要分成两档？**

因为处置不同。`absent` 意味着"这一格该有但没有"，处置是补登记或承认缺失；`undocumented` 意味着"公开口径没说这条通道有没有这一格"，处置是去问、去等，或在能力表里补一档，**而不是把它算成违规**。混用的后果是差集会同时报出两种性质完全不同的洞，读者无法分辨哪些是对方漏了、哪些是文档没写。脚本二把这一档做成显式取值，并让配对表只对"平面 × 类别"有公开口径的组合放行。

**Q5：为什么"重复登记且三格一致"只给软信号不阻断？**

因为它不影响单条记录的归属正确性，只影响**聚合读数**：同一个对象的同一个要素被登记两次，差集计算会重复计数，覆盖率会被推高。阻断它会让真正的平面越界（`O02`）与词表混用（`X` 族）和这种统计噪声混在同一批退出码里。脚本二因此把它记为软信号并仍然打印——第 23.4 节的 `S08` 累计 10 条就是这么来的。

**Q6：`J1` 为什么只能由基准夹具触发，这算不算验收漏洞？**

不算，是构造性的。`J1` 的条件是"该对象零阻断信号"，而全码遍历夹具里每个对象都是为了触发某条码而设计的，它们必然带着阻断信号。所以 `J1` 只能由一份**不为了触发任何码而写**的记录给出（R2 的 3 个对象、脚本二侧 R15 与 R30 的 `Q1`）。第 23.5 节第三步专门处理这类差额：不是放弃这个码，而是补一份基准夹具。

**Q7：这两个脚本能替代 `codesign` 或设备侧校验吗？**

不能，方向相反。它们审查的是**你自己写的台账和清单**，输入全是纯文本，不读任何真实签名对象，也不与任何设备通信。真正的签名校验在设备上（而且第 24 章误区二说明：设备侧校验和台账归属是两个平面）。脚本的价值在于把"我们有一套签名管理规范"这句话变成逐格可判定的读数。

**Q8：为什么不直接给一张通道 × 要素的对错表，而要写两支脚本？**

因为表是静态的，而差集要在**你的实际台账**上算。第 12 章那张 9 × 5 的可得性表只是基准（脚本二的能力表输入）；同一张基准，你的台账可能缺 `der_profile`、可能多记一个自造字段、可能把管理面的三格读数写成签名者类型。表不能告诉你这些，脚本可以，而且每条信号都自带出处，处置时能直接指着那一行说话。

**Q9：`V06`（是否仍在跑）这一格在很多组织里根本拿不到，为什么不干脆删掉它？**

删掉它就删掉了本文最重要的一类失败形态：**处置动作被写成运行结果**。吊销留痕齐备但运行时状态未登记时，正确表述只能到"该身份已被撤销"（第 13 章 L10）。如果这一格不存在，台账里"已吊销"会被自动读成"已停止运行"，而这恰是需要证据的那一步。脚本对"拿不到"给的出路是 `state.still_running=not_recorded`（区别于 `no`），并让到期早于核对时刻却仍未登记运行状态这一组合直接打在 `V06` 上——**登记"没有读数"是一种读数**。

**Q10：如果只能做三件事，做哪三件？**

按第 20 章的 `O1`、`O7`、`O8` 各选一件：① 给每一条授权记录补 `when.expiry_basis`，把两个到期日分开；② 用脚本二跑一遍通道 × required 要素差集，把"该有而没有"的洞列出来，并区分 `absent` 与 `undocumented`；③ 把所有"已吊销"记录逐条核对是否有 `revoke_recorded` 与 `delete_verified` 两格，缺哪一格就补哪一格的动作，不许用推断填。三件事都不需要新工具、不需要访问设备，也不涉及任何凭证内容。

---

## 26. 未公开文档化边界清单

这一节列出**公开文档没有写**的东西。它的用途不是批评文档，而是防止读者把"文档没写"读成"不存在"或"必然是另一种"。每条给出：缺什么、公开侧实际读到哪一步、台账该怎么记、影响哪个信号。前七条是本文判定的实际约束，后三条是附带边界。

| 编号 | 未公开文档化的内容 | 公开侧读到的最远处 | 台账记法 | 相关信号 |
| --- | --- | --- | --- | --- |
| N1 | **代码签名侧叶子证书的吊销如何被执行链路发现、以及何时对设备可见**。三篇技术说明全无吊销词形：TN3161（277 行）、TN3125（207 行）、TN3127（200 行）中 revoke / revocation / CRL 命中均为 0 | 账号侧有"撤销"这个动作与前置关系（sharing 文档第 39—41 行）；PKI 层有五张 CRL 与 CA 证书到期 UTC 时刻（apple-certificateauthority 第 24、45—56 行）；CA 层失效时点公开、叶子层没有对应公开列表 | `state.revocation_basis` 只允许 `crl_seen` / `validation_failed` / `assumed`，取 `assumed` 即视为无读数 | `V03`/`V04`/`V05` |
| N2 | **描述文件的精确格式**——官方明确它未文档化且随时可能变 | TN3125 第 33 行整段 ASIDE；第 34 行只说明 DER 形态是新的 source of truth，不给出 DER 结构定义 | 只登记 `id.profile_uuid` 与 `when.profile_expiry`，不登记任何解析出的内部字段名 | `K01`/`K02`/`S09` |
| N3 | **管理面对"代码签名授权对象"的建模**——有证书吊销载荷却没有描述文件类载荷，有证书状态项却没有描述文件状态项 | `profile-specific-payload-keys` 第 46 行 `CertificateRevocation`，以 `Certificate` 开头的键共 7 项、`provision` 词形全表 0 次；`status-items` 第 61 行 `StatusSecurityCertificateList`，65 个状态项里没有描述文件类；53 个 declaration 类型里没有授权对象类 | 管理面读数只能填 `UUID`/`Name`/`ExpiryDate` 三格，其余一律 `not_recorded` | `O02`/`P04`/`D02` |
| N4 | **若干通道在某些要素上是否真的没有那一格**——公开口径只给了三格回读，没有说明"为什么不更多" | `provisioningprofilelistitem-fields` 第 5—7 行；`validateapplicationsresponse-fields` 第 5—14 行十个键里无逐应用判定格 | 可得性写 `undocumented` 而不是 `absent`；这一档限制 `O7` 的绝对值下限 | `C01`—`C05`/`D02`/`P05` |
| N5 | **代码签名结构本身不是 API**，官方要求不得编码进产品 | TN3125 第 10 行、TN3126 第 14 行、TN3127 第 13 行、TN3161 第 9 行四处同一措辞："…code signing details that aren’t considered API…Don’t encode this information in your product." | 台账不登记签名内部结构字段；跨版本对比只登记 `state.signature_version` 与哈希形态 | `S09`/`K02` |
| N6 | **独立可执行文件的受限权利缺口没有替代登记口径** | TN3125 第 150 行给出"没有地方嵌描述文件"这一事实，但没有给出"那这一格该由谁负责"的口径 | `what.ent_slot=none` + `doc.source` 指该行；不得以自造声明填充 | `H01` |
| N7 | **时间戳服务的名称与行为是实现细节**，不能作为可依赖判据 | TN3161 第 268 行说明 Developer ID 签名必须能联网、走 `timestamp.apple.com`；第 269 行 ASIDE 明确"Its name and behaviour are considered implementation details." | 登记 `when.sign_at` 与 `when.time_source`（只允许 `tsa_timestamp` / `local_signed_time`），不登记该服务行为 | `T03`/`S04` |
| N8 | **信任链的组成不保证** | TN3161 第 80—83 行给出"leaf → 有限的中间证书集 → Apple Root CA"的三级链示例，第 84 行立刻写"Don’t rely on the exact details of this chain of trust; it could change in the future." | `who.chain_depth` 与 `id.cert_fp` 只作当期读数，不写成结构断言 | `S04`/`A08` |
| N9 | **嵌套代码在移动平台的引用形态与 macOS 不同，公开口径不给统一表述** | TN3126 第 260 行：iOS/watchOS/tvOS 把嵌套代码当作资源集合引用，"Nested code references are only used on macOS."；第 63 行另说明扩展属性存储的脆弱性 | 平台分栏登记，不合并成一个"嵌套代码校验通过" | `B06`/`S07` |
| N10 | **OID 断言只在 Apple 锚定范围内有意义** | TN3127 第 124 行："There’s nothing to stop a malicious CA from issuing certificates with these OIDs."（该检查只在 `anchor apple generic` 建立的范围内成立） | 权利/团队类断言必须同时带锚点格，缺一即不闭合 | `H02`/`A07` |

三条必须一起读的性质说明：

**其一，这份清单不是缺陷清单。**N1—N10 里没有一条说 Apple 的机制缺失；它们说的是**公开文档的表述范围**。吊销机制很可能存在且在运行，但公开侧没给可读回的判据，于是本文的判定只能到 `assumed` 为止并被 `V05` 阻断。把这个区分写清楚的价值在于：读者不会把"文档没写"当成"可以放心"，也不会当成"必然有问题"。

**其二，这类边界的正确反应是降低表述强度，不是提高登记密度。**最典型的错误响应是给 N4 补一格"我们内部知道它是有的"，或者给 N2 抄一份解析出来的正文。两者都把不可回查的东西伪装成可回查的。正确写法只有两种：`undocumented`/`not_recorded`，或者把该对象降到 `J3` 以下、不允许进入对外表述。

**其三，清单本身要靠回查维持。**N1、N5、N9 这几条的读数是"某文档不含某词形"这类负发现，文档一换版本就可能变。本文给的行号与命中数都以 `.srcx14/A/` 下 2026-11-01 取回的转文本件为准（四篇技术说明共 954 行）；任何引用者在另一个时间点复核，应先重跑 `C/readings-14.sh` 一类的关键词读数，再决定这一条是否仍然成立。

---

## 27. 结论

本文把"这段代码有签名"这句话拆开，拆成十一个各有主语的对象层，加一个不参与执行的判定层，并给出两个可以离线跑的审查器。三条结论按证据强度排列。

**第一条（同一份文档内可直接核对，却最常被判成同一件事）：授权对象有两种编码形态，而且旧形态不是"能用但不推荐"。**TN3125 第 34 行写明传统属性列表视图在新一代系统上不再是 source of truth，真正的新事实源是 `DER-Encoded-Profile` 属性；《Using the latest code signature format》第 6 行与第 12 行则把签名格式的旧档位写成硬失败——"Apps signed with a previous signature format will not launch."、"For any value of v less than 20400, you need to re-sign your app"；第 35 行同时关掉移动平台的现场重签（"Re-signing apps from the command-line is not supported for iOS, iPadOS, tvOS, visionOS, and watchOS."）。这三行合起来决定了一个处置边界：**形态层面的失效只能靠回到 macOS 重新签名并重新分发来闭合，不能靠设备侧的任何动作来闭合**。`B03`/`B04`/`B05`/`T06` 四条信号拦的就是把这件事写成"现场处理"的台账。

**第二条（跨文档可以核对，但公开侧没有换算表）：执行侧与归属侧是两套词表，四个读数面互不连通。**指南第 2353 行把内核描述成控制哪些进程与应用可以运行、并要求所有可执行代码有签名，第 2362 行给的是签名校验条目；而"谁被授权、授权到哪天、给了哪些权利"必须回到证书（TN3161 第 102—103、147—150 行）与描述文件（TN3125 第 89、141—142、150 行）——这两个平面在同一台设备上同时成立，却没有一张公开的换算表。四个读数面各自的边界可以量化：签发侧给证书有效期与链，构建侧给签名时戳与格式档位，设备侧给校验通过与槽位，管理面只给 `UUID`/`Name`/`ExpiryDate` 三格（第 5—7 行）与十个响应键里无逐应用判定格（第 5—14 行）。第 18 章按这四个面各写了一遍"能读到 / 读不到 / 如何映射进台账"，第 16 章的十八条公开读数就是这四个面的实测长度。

**第三条（本文量化出来的主缺口）：失效之后这条链在公开侧无法闭合。**392 条 CVE 行、101 个去重组件名里，15 个签名与分发授权词形只命中 `kernel` 一个组件；解决句只有 2 条与签名校验直接相关，影响句里 `bypass Gatekeeper` 1 条、`certificate validation` 2 条；CISA KEV（目录版本 2026.10.30，共 1766 条、Apple 95 条）的 Apple 记录中签名授权词形命中同样极稀。与此同时，三篇技术说明共 954 行里 revoke / revocation / CRL 命中为 0。**因此"这张证书被吊销了，所以现在这段代码不被允许运行"这类句子在公开口径下不能闭合**——不是因为机制不存在（N1），而是因为公开侧给不出从清单到设备可见之间的那一步。任何声称闭合的表述都缺少依据，只能写成"账号侧动作已发生 + 某设备某次校验未通过"两个独立读数。

第四条必须单列，因为它是本文的立场而不是结论：**授权台账需要登记"哪个身份、经哪条签发路径、给了哪一格权利、由哪个平面在什么时刻读回"，永远不需要登记凭证本身。**`K01`/`K02`/`T01` 不是顺带的卫生提示。把私钥、PKCS#12、证书签名请求或描述文件正文抄进台账，等于把一份本来只受密钥链与设备规则约束的凭证，复制成一份不受任何签发规则约束的副本；这一步完成后，第 8 章所有关于权利格与描述文件范围的约束都在这份副本上失效。

方法论上的验收与前十三篇同标准：每个信号码都要被真实输入触发、好输入要退出码 0 且不报警、不可用输入要与阻断分开。本文的 108 个码（64 + 44）全部可达，30 次实跑退出码为 1/0/1/1/1/0/2/2/0/0/1/1/1/1 与 0/1/1/1/1/1/1/0/2/2/2/2/0/0/1/0，正文两支脚本与 `tools/` 下源文件逐字节一致。**这份验收能证明脚本没有死码，不能证明真实世界的失败已被覆盖**——第 23.7 节那五条限制比第 23.2 节那两张表更值得被记住。

对读者的最小可执行建议是三件（对应第 25 章 Q10）：**把两个到期日拆开并登记时效基准；用脚本二跑一遍通道 × required 要素差集并把 `absent` 与 `undocumented` 分开；把每条"已吊销"记录核对到 `revoke_recorded` 与 `delete_verified` 两格。**这三件事不需要新工具，不需要访问设备，也不涉及任何凭证内容——一支纯文本台账加两支离线脚本就能跑完，这正是本文提供脚本而不是提供建议的原因。

---

## 28. 参考资料

本轮存档：`.srcx14/`（取回日期 2026-11-01，七组共 **127 个文件 / 5,585,352 字节**）。索引件 `.srcx14/IDX/files.tsv`（128 行 = 表头 + 127 条，列为组别、路径、字节、行数、md5；行数按"行号计数"口径，即末行不带换行符时也计一行，因此 `B/apple-platform-security-guide.txt` 记 4,886 而正文按 `wc -l` 口径引用 4,885，`C/kev.json` 记 28,041，`RAW/` 下单行 JSON 记 1 而非 0），重叠审计件 `.srcx14/IDX/overlap-14.md`（词表落点实测与相邻篇分界）。全部为公开文档，离线取回；**本轮未访问任何设备、未调用任何设备侧或 Apple 命令行工具（不执行 `codesign`、`security`、`devicectl`、`xcrun`、`altool`、`syspolicy_check`）、未构建、未签名、未提交任何账号侧动作**。

### Apple 开发者文档与技术说明（A 组派生转文本件 46 个 / 212,654 字节；对应原始件 36 个 / 882,531 字节）

1. **Inside Code Signing 四篇技术说明**（正文引用最多，行号可逐条回查）：TN3125 *Inside Code Signing: Provisioning Profiles*（207 行；第 10 行"not…considered API"警告、第 33 行格式未文档化警告、第 34 行 DER 为 new source of truth、第 89 行到期格、第 141—142 行受限权利与 TestFlight 例外、第 146—150 行内嵌位置 / 商店包 / 独立可执行文件）、TN3126 *Inside Code Signing: Hashes*（270 行；第 9 行核心功能表述、第 14 行同一警告、第 63 行扩展属性脆弱性、第 260 行嵌套代码平台差异）、TN3127 *Inside Code Signing: Requirements*（200 行；第 13 行同一警告、第 19 行 identifier / identity / code identity 三词辨析、第 124 行 OID 检查范围）、TN3161 *Inside Code Signing: Certificates*（277 行；第 9 行同一警告、第 80—84 行三级链与"别依赖它"、第 102—103 行签名身份定义、第 116/121/125 行 CSR 与私钥落点、第 147—150 行有效期核对、第 173 行指纹口径、第 242 行商店重签名、第 250—254 与 268—269 行时效与时间戳）。四篇合计 **954 行**，revoke / revocation / CRL 命中 **0**（第 16 章读数 11、第 26 章 N1）。
2. **签名格式与分发流程**：*Using the latest code signature format*（43 行；第 6、12、35 行是本篇形态层与处置层的直接依据）、*Sharing your team's signing certificates*（47 行；第 5 行同步与共享、第 39—41 行 "Delete a revoked certificate" 及其前置关系）、*Preparing your app for distribution*（73 行）、*Distributing your app to registered devices*（40 行；第 29 行开发者模式前提）、*Distributing your app for beta testing and releases*（81 行）、*Adding capabilities to your app*（48 行）、*Enabling developer mode on a device*（18 行）、*Locating device identifiers*（29 行）。
3. **管理面命令与画像字段**（第 11—13 章读数面事实来源）：*Provisioning Profile List*（28 行）与其响应两件（`ProvisioningProfileListResponse` 10 行、`ProvisioningProfileListItem` 7 行）及字段件（7 行，其中**第 5—7 行就是全部三格**）、*Install Provisioning Profile*（31 行，命令件 9 行、字段件 6 行）、*Install Profile*（30 行）、*Install Enterprise Application*（36 行）、*Validate Applications*（32 行）、`ValidateApplicationsCommand`（9 行）/`ValidateApplicationsResponse`（9 行）及字段件（6 / 14 行，响应字段件**第 5—14 行为十个键**）、*Installed Application List*（36 行）与 `InstalledApplicationListResponse`（10 行）/`InstalledApplicationListItem`（7 行）及其字段件（26 行、22 个字段格）、*Managed Application List*/*Managed Application Attributes*（37 / 34 行）与 `ManagedApp`/`ManagedAppDistribution`（34 / 26 行）、`ManagedApplicationListResponse`（10 行）、*Profile List*（28 行）、*Identity management*（16 行）、*Device Information*（34 行）、*Status items*（82 行、65 个状态项）、*Declarations*（75 行、53 个声明类型，`provision` 词形 0 次）、*Profile-specific payload keys*（158 行、第 46 行 `CertificateRevocation`、`Certificate*` 键 7 项）、*App, Book, and Subscription Management*（67 行）。取回 URL 清单记于 `A/urls.tsv`（37 行，每行为件名、行数、标题、路径、抓取时刻）。

### 安全指南、计划页与公告口径（B 组 10 个文件 / 1,563,759 字节，含 4 个原始 HTML / 437,768 字节记于 RAWW）

4. Apple, *Platform Security Guide*（`B/apple-platform-security-guide.txt`，4,885 行；与第 08—13 篇同一 `pdftotext -enc UTF-8` 转文本件，行号可直接互参。本篇引用集中在第 2353 行内核与运行控制、第 2362 行签名校验与 Team ID 库链接条目、第 2365 行企业应用首启批准与描述文件前提、第 2373 行"不允许从网站安装未签名应用"的默认闸门表述）。
5. Apple, *Apple PKI*（`B/pages/apple-certificateauthority.txt`，92 行；第 24 行 PKI 覆盖生成 / 签发 / 分发 / 吊销 / 管理与治理，第 45—50 行逐张给出 Worldwide Developer Relations 各级 CA 与 WWDR MP CA 1 的到期 UTC 时刻，第 52—56 行五张 CRL）。**CA 层失效时点公开、叶子层没有对应公开列表**（第 16 章读数 12、第 26 章 N1）。
6. Apple, *Apple Developer Enterprise Program*（236 行）、*Changes for apps in the European Union*（397 行）、*Installing apps through alternative app distribution*（Support 117767，80 行）、*App Review Guidelines*（593 行）、*Apple security releases* 索引（1,121 行，与第 10、12、13 篇同一取回件，用于定位三条并行版本线的公告编号）。

### 安全公告与派生词表（B 组 3 份 CSAF + C 组 5 个文件 / 1,991,602 字节）

7. 三条并行版本线 CSAF：`B/149041.json`（iOS 26.7）、`B/149227.json`（iOS 26.7.2）、`B/149230.json`（iOS 27.2），三件均为 `.srcx13/B/` 同名件的逐字节副本，合计导出 **392 条 CVE 行 / 101 个去重组件名**。派生件 `C/advisory-entries.tsv`（393 行 = 表头 + 392 条 / 154,078 字节；列为 `file / cve / component / impact / description / avail`，组件名在第 3 列）。第 14、16 章的公告读数与脚本二的公告词表输入全部出自这一件。
8. `C/kev.json`：CISA KEV 目录导出件（28,041 行 / 1,826,755 字节），本轮读数 `catalogVersion` = 2026.10.30、`count` = 1766、Apple `vendorProject` 记录 95 条。**正文只引用聚合词形计数，不引用任何可定位到具体设备或用户的组合。**
9. 只读读数脚本 `C/readings-14.sh`（72 行）与 `C/readings-14b.sh`（35 行）及其输出 `C/readings-14.txt`（112 行）：语料行数 / 文件数 / 去重组件数、组件名词形匹配、解决句与影响句匹配、授权对象词形全文检索、KEV 聚合与逐记录关键词计数。第 16 章第 13—17 条读数由这三件产出。

### 本轮产物（自写，只读处理公开存档文本）

10. 脚本一 `tools/authorization-ledger-review.sh`（366 行，**64 个信号码** = 59 个阻断码 + 软信号 `S08` + 判定档 `J1`—`J4`；49 条出处映射）：授权链台账审查器，输入 `<授权对象标识>,<字段名>,<值>` 三元组台账，九个命名空间（`id.` `who.` `what.` `where.` `how.` `when.` `state.` `obs.` `doc.`）加保留的 `key.` 拒收空间，逐对象输出信号与四档。脚本二 `tools/channel-element-diff.sh`（358 行，**44 个信号码** = 32 个阻断码 + 8 个软信号 + 判定档 `Q1`—`Q4`）：通道 × 要素差集与公告词表比对器，输入要素清单（8 列，9 类 22 项要素）+ 通道能力表（3 列，9 条通道）+ 公告词表（CSAF 派生 TSV，仅取 `cve` 与 `component` 两列）。两支脚本全文见第 21 章与第 22 章，都不联网、不访问设备、不修改输入，唯一写出目标是 `mktemp -d` 的临时目录（由 trap 在退出时删除）。附 `tools/doc-audit.pl`（文档行号自审器）。
11. 实跑驱动与留档：`FX/run-all.sh`（脚本一 14 次实跑 R1—R14）与 `FX/run-all-2.sh`（脚本二 16 次实跑 R15—R30），输出 `FX/run-log.txt`（878 行）与 `FX/run-log-2.txt`（1,307 行），每次实跑记录命令行、逐条信号、脚本自打的汇总行与 `exit=` 值；逐码可达性由 `FX/codemap.pl`、`FX/code-coverage.pl` 从这两份原始输出提取为 `FX/codemap-1.txt`（64 行）与 `FX/codemap-2.txt`（44 行），另有 `FX/doc-audit-2.txt`。
12. 样例输入（**全部为合成值**，不含任何真实证书、描述文件、Team ID 或设备标识）：脚本一侧 `fixture-ledger.txt`（混合缺陷）、`fixture-ledger-good.txt`（九格齐备，R2 的 3 个 `J1`）、`fixture-ledger-codes.txt`（逐码遍历，R1 的 69 个对象 / 60 个码）；脚本二侧 `fixture-element.csv`、`fixture-element-good.csv`、`fixture-element-codes.csv`、`capability.csv`（9 通道）、`capability-codes.csv`、`capability-bad.csv`、`capability-empty.csv`、`vocab.tsv`、`vocab-empty.tsv`；以及 `tmp-*` 系列探针件（空件、仅表头件、列数不合件、未知字段件、形态不合件、密钥形态件、CRLF 件）。临时探针写在临时目录，不进入任何台账。
13. 校验器（`.srcx14/` 根目录）：`x14-qcheck.pl`（引文逐条宽松回查，遍历 `A/`、`B/`、`C/`、`RAW/`、`RAWW/`、`IDX/`）、`x14-quotes.pl`（从成品 Markdown 抽取英文引文段）、`x14-cite-scan.pl`（「见 X 第 N 行」形态清点）、`x14-linecheck.pl`（行级回查：把正文每处英文引文片段与同一行的行锚比对，确认片段确实出现在被引的那一行或那一段；第 3 章词表的简称行锚按该章开头的对照表解析为归档路径）、`x14-doccheck.pl`（件名与行数存在性）、`x14-setext-scan.pl`（`---` 上方的 setext 误判扫描）。第 23.6 节六项核对由这六件执行。

### 同系列相邻篇目

14. **第 02 篇（访问控制与应用交互）**——entitlement 的语义与运行时后果归它，本篇只取 entitlement 作为描述文件允许清单的一侧（授权来源与失效），分界见第 2 章与第 8 章。**第 05 篇（生物识别与设备证明）**——App Attest / DeviceCheck 归它，TN3161 自己也把它们划到另一篇，本篇不写 attestation。**第 07 篇（推送链路）**——Team ID 与密钥在那篇只作匹配键，本篇写它的签发与失效。**第 09 篇（更新链与补丁传导）**——补丁走到哪一台；本篇写授权对象的时效与失效，接缝在第 14 章 P13/P14 与第 26 章 N1。**第 10 篇（设备生命周期与归属迁移）**——设备属于谁、凭据何时作废；本篇写授权对象在设备上如何被读回，激活锁与其状态项本篇不写。**第 11 篇（备份与恢复链路）**、**第 13 篇（日志与诊断证据链）**——方法形似（差集 + 四档判定 + 只读脚本），客体不同：那边是数据副本与记录的可归属，这边是运行授权的可归属与失效。**第 12 篇（第三方依赖与供应链）**——其签名与构建口径在本文第 4—5 章被直接引用为签发侧前提。**第 01、03、04、06、08 篇**——构成第 3 章词表 C（公告口径）与第 14 章类型学的既有基础，本篇 P1—P14 中与前篇同名的形态均已在前篇视角声明中划界。**第 15 篇（网络扩展与代理/VPN 通道归属）**——描述文件对 entitlement 的白名单授权归它，本文从「权利已被授权」之后开始；那边只把 entitlement 当作通道存在的三种证明之一（L1），接缝在 L1 与 L10 到期使通道失效。

---

咨询ios系统请咨询 telegram：https://t.me/one00190
