---
title: "iOS 设备生命周期与所有权移交归属防御分析报告"
description: "iOS 设备生命周期与所有权移交的十层表面分解：归属登记与设备标识、入册通道、监管与命令权限、锁定与托管凭据、丢失模式与远程锁定、抹除与密钥遗留、用户账户生命周期、管理服务迁移与移交、回执与读数、旁路与不可判定通道；P1—P12 缺陷类型学、归属口径/平台安全口径/公开公告口径三套词表与七处换算失败、层 × 责任方 × 通道 × 证据归属矩阵、四级判定模型与两个离线只读核验脚本（信号码 51 + 23）"
lang: zh-CN
---

# iOS 设备生命周期与所有权移交归属防御分析报告

## 摘要

本报告集前九篇问的是"缺陷在哪、补丁走到哪"。本文换一个主键：**这台设备现在归谁，上一位使用者的数据还能不能被读到，以及这两个问题各自要拿什么来证明**。这条链路和更新链一样每一格都有公开文档，但它比更新链多一个性质：**它的很多关键状态根本不落在设备上**。激活锁的判定发生在 Apple 的激活服务器（"Each time an iPhone or iPad is activated or recovered, the device contacts Apple to check whether Activation Lock is turned on."，《Activation Lock for iPhone and iPad》第 24 行），组织归属发生在 Apple School Manager / Apple Business 的设备清单，托管凭据（绕过码、UnlockToken、escrow keybag、bootstrap token）保存在服务端。**设备自己不是这些事实的权威来源**，于是"从设备上读一遍就能确认归属"这条常规取证直觉在这里直接失效。

第 3 章给三套词表和七处换算失败，其中三处是公开文档自己互相打脸：企业部署侧写"bypass codes are available for up to 15 days after the device is first supervised"（《Activation Lock on Apple devices》第 362 行），平台安全指南写设备在三种设置场景各自生成新码（第 4514、4520、4521 行）与 Mac 的两种（第 4547 行）——**没有任何一处给出"这台设备当前这一枚码从何时起不可取回"的读数**；`SecurityInfo` 的可用性表把 Activation Lock Bypass Code 与 Clear Activation Lock Bypass Code 两条列在同组的"Security"关联项里（第 25—26 行），而这两条命令的 `Required access right` 都写 `N/A`（第 25 行 / 第 18 行）——**取走和作废归属凭据的动作，在权限词表里没有对应项**；企业指南一边写释放后"Managing Activation Lock using Apple Business isn't possible after devices are released"（《Release devices in Apple Business》第 283 行），一边在操作末尾留一句"device may still indicate that Activation Lock is on … but you can still set up the device without authenticating as the previous user"（《Turn off Activation Lock in Apple Business》第 312 行）——**设备界面读数与管理能力在同一篇文档里分道**。

第 4—13 章逐层给出输入、输出、失败形态与可得证据；第 14 章按"在哪一次核对被放过"建立 P1—P12 类型学；第 15 章给出层 × 责任方 × 入册通道 × 证据的归属矩阵；第 16 章用本轮存档算出 18 条公开读数，其中五条定下本文基调：**42 张 MDM 命令可用性表里 32 张（76.2%）写"Allowed in user enrollment | N/A"，也就是在"设备属于用户、组织只碰一部分数据"的那条通道上，绝大部分生命周期动作在协议层就不存在；20 张（47.6%）的必需权限写作 `N/A`；三份并行版本线的公告共 392 条 CVE 行里，提到激活锁、绕过码或密钥托管的行数是 0；CISA KEV 的 95 条 Apple 在野条目描述里，20 个生命周期用词全部为 0；13 个与归属、身份、备份、存储相关的组件标签在并行版本线之间漂移**。结论不是"这些缺陷不重要"，而是**公告口径没有能力表达这一层，所以任何"某个 CVE 影响激活锁/抹除"的说法都不成立**。

核验部分提供两个纯文本、离线、只读的脚本：一个把一份"设备归属与移交台账"按 Apple 文档口径审一遍，逐条预演"这一格写成这样时，归属与清除还能不能被证明"；一个把归属清单件、生命周期活动件与命令回执件做清单/活动差集与移交时序核对，回答"这台设备上一次易主到底有没有走完、缺哪一步"。信号码共 74 个（脚本一 51 个、脚本二 23 个），全部在本轮环境实跑触发。

本文不提供任何可用的漏洞利用代码、提权或绕过步骤，**不含任何绕过激活锁的做法、不提供绕过码或解锁凭据的获取与使用步骤**，不提供抹除规避或恢复技巧，也不提供任何针对具体设备的攻击动作；给出的只有公开文档口径、归属判定、责任方划分、可见性边界与只读核验。**全部只写防御与归属判定。**两个脚本都不联网、不调用任何设备侧或 Apple 命令行工具、不修改输入文件；唯一写出目标是 `mktemp -d` 创建的临时目录，退出时删除。脚本一对台账里出现凭据值的写法直接报警并要求删除该字段——这不是顺带检查，而是本文的立场：把绕过码抄进台账这件事本身，就是归属层最严重的一次泄漏。

---

## 目录

1. [引言](#1-引言)
2. [视角声明与本文边界](#2-视角声明与本文边界)
3. [三套词表：归属口径、平台安全口径、公开公告口径](#3-三套词表归属口径平台安全口径公开公告口径)
4. [L1 身份与归属登记层](#4-l1-身份与归属登记层)
5. [L2 入册通道层](#5-l2-入册通道层)
6. [L3 监管与命令权限层](#6-l3-监管与命令权限层)
7. [L4 锁定与归属凭据层](#7-l4-锁定与归属凭据层)
8. [L5 丢失模式与远程锁定层](#8-l5-丢失模式与远程锁定层)
9. [L6 抹除与密钥遗留层](#9-l6-抹除与密钥遗留层)
10. [L7 用户账户生命周期层](#10-l7-用户账户生命周期层)
11. [L8 迁移与移交层](#11-l8-迁移与移交层)
12. [L9 回执与读数层](#12-l9-回执与读数层)
13. [L10 旁路与不可判定通道层](#13-l10-旁路与不可判定通道层)
14. [缺陷类型学 P1—P12](#14-缺陷类型学-p1p12)
15. [归属矩阵：层 × 责任方 × 入册通道 × 证据](#15-归属矩阵层--责任方--入册通道--证据)
16. [公开读数：这条链路上能数出来的十八件事](#16-公开读数这条链路上能数出来的十八件事)
17. [可见性边界：这一层读者能拿到什么](#17-可见性边界这一层读者能拿到什么)
18. [设备侧与管理侧读数面](#18-设备侧与管理侧读数面)
19. [四级判定模型](#19-四级判定模型)
20. [运营指标 O1—O10](#20-运营指标-o1o10)
21. [只读核验脚本一：设备归属与移交台账审查器](#21-只读核验脚本一设备归属与移交台账审查器)
22. [只读核验脚本二：生命周期与移交记录差集比对器](#22-只读核验脚本二生命周期与移交记录差集比对器)
23. [两个脚本的全量分支覆盖验收](#23-两个脚本的全量分支覆盖验收)
24. [十二个误区](#24-十二个误区)
25. [常见问题](#25-常见问题)
26. [未公开文档化边界清单](#26-未公开文档化边界清单)
27. [结论](#27-结论)
28. [参考资料](#28-参考资料)

---

## 1. 引言

### 1.1 为什么把"归属"单独立一篇

设备安全里有两类问题经常被混成一件：**这台机器有没有漏洞**，和**这台机器是不是你的**。第一类有编号、有日期、有组件名，可以查、可以数、可以排优先级；第二类没有编号。它出现在采购单、人员离职、部门合并、设备轮换、维修替换、二手处置、管理服务换供应商这些**跟漏洞无关的事件**里，而它一旦被搞错，后果不是"多一个 CVE"，而是**上一位使用者的数据对新持有者可读，或者一台机器从此谁都动不了**。

第二类问题在公开讨论里通常只有两种讲法。消费者侧讲成**处置清单**（"卖掉之前记得退出登录并抹掉"，《What to do before you sell, give away, or trade in your iPhone or iPad》第 18 行）；企业侧讲成**功能列表**（哪个 MDM 支持远程抹除、哪个支持激活锁托管）。两种讲法都对，但都不回答问题本身：**做完这些步骤之后，谁手里有什么证据**。本报告要写的正是这一格。

第三个动机是前九篇留下的空位。第 02 篇讲 Data Protection 的密钥层级，讲"哪一类文件在什么状态下可解密"；它不讲**谁持有解锁这一类密钥的凭据、设备换主之后旧凭据还在不在服务端**。第 09 篇讲一条补丁从公告走到设备的十格；它讲"这台设备装上了吗"，不讲"这台设备还归那个组织吗"。这两格合起来才是完整的资产结论——而它们之间没有任何公开产物做桥。

### 1.2 这一层的规模感：七个可以直接数出来的数字

以下七个数字全部来自本轮存档（`.srcx10/`，取回日期 2026-10-31，共 239 件、6 组，零件缺源地址），用来建立"这张表有多大"的直觉：

1. **命令面**。本轮取回 42 张 MDM 命令可用性表（每张四行：设备通道、用户通道、需要监管、允许在用户注册中、必需权限，例如《Erase Device》第 16—21 行）。其中 **32 张写 `Allowed in user enrollment | N/A`**（76.2%），**14 张写 `Requires supervision | macOS`**、14 张写 `N/A`、其余按平台列举。
2. **权限面**。`Required access right` 一词在 42 张表里出现 41 次，取值分布是 **20 次 `N/A`**、7 次 `DeviceLockAndRemovePasscode`、4 次 `AllowPasscodeRemovalAndLock`、2 次 `AllowInstallationRemoval`、2 次 `AllowInspection`、2 次 `AllowAppInstallation`，`AllowDeviceErase`、`AllowQuerySecurity`、`AllowQueryRestrictions`、`AllowSettings`、`Special Case` 各 1 次。**这一层能用的权限词只有 9 个，其中一半的动作无词可表。**
3. **错误码面**。本轮存档里出现的 MDM 数字错误码只有 8 个：12067、12068、12069、12071、12072、12073、12074、12078，全部集中在丢失模式与用户删除两组命令上（《Enable Lost Mode》第 10 行、《Disable Lost Mode》第 11—13 行、《Delete User》第 13—16 行、《Device Location》三处、《Play Lost Mode Sound》两处）。
4. **公告面**。三份并行公告的 CVE 行数分别是 95（149041）、134（149227）、163（149230），合计 392 行。**这 392 行里提到激活锁、绕过码或密钥托管的行数为 0**（`.srcx10/C/advisory-lifecycle-readings.txt` [E] 段）。
5. **在野面**。CISA KEV 里 Apple 条目 95 条，20 个生命周期用词（activation-lock / bypass-code / escrow / keybag / erase / remote-wipe / lost-mode / enrollment / supervision / sign-out / restore / setup-assistant / passcode / pairing / mdm / configuration-profile / apple-account / icloud-account / find-my / lock-screen）**命中数为 0 的全部是 0**。
6. **凭据时效**。企业文档给出一条唯一的时限句："On iPhone and iPad, the bypass codes are available for up to 15 days after the device is first supervised, or until a device management service obtains—and then clears—the code explicitly."（《Activation Lock on Apple devices》第 362 行）。
7. **移交动作面**。Apple Business 侧一次移交由三个互不等价的动作组成：改指派（Assign / Unassign，第 310—311 行）、释放（Release，第 289—290 行）、以及开发者侧的"通知 Apple 服务器本组织不再拥有这些设备"（"Disown Devices — Notify Apple's servers that your organization no longer owns the specified devices."，《Device assignment》第 11 行）。**三份文档没有任何一处把这三个动作串成一条流程。**

### 1.3 本文的三个提问方式

第 4—13 章每一层都用同三个问句切：

- **这一格的事实记在哪里？**（设备 / 设备管理服务 / Apple 服务侧 / 组织自己的台账——四者不同，第 17 章据此分级）
- **这一格的修改权在谁手里？**（用户、管理员、管理服务、Apple、reseller、维修方）
- **做完之后有没有任何读数会变？**（有 → 可自证；没有 → 只能靠台账；第 19 章据此判 J1—J4）

第三问是本篇的骨架。它给出的最不舒服的结论是：**归属这一层里"发生了什么"和"能被证明发生了什么"之间的落差，比更新链更大**。第 9.5 节会说明 `EraseDevice` 的应答句是"device sends a response to the server, but it doesn't retry if it isn't successful the first time"（《Erase Device》第 12 行）——一次可能永远不到的抹除，回执面只有"到了才会到"；第 8.4 节会说明丢失模式的关停要求管理员侧先存档状态（《Disable Lost Mode》第 14 行），也就是说**设备抹掉之后，"它当时在不在丢失模式里"这件事只存在于服务端的自选动作里**。

---

## 2. 视角声明与本文边界

### 2.1 自审清单（写作前设定的四条）

1. **每一句英文引文都必须能在本轮存档的对应件里按行找到原句。**行号是扁平转文本件的物理行。不满足的写"文档未展开"，不满足的推断写成推断。
2. **不提供任何绕过激活锁的做法。**这不是"我们不写攻击步骤"的一般性免责声明，而是本篇的实质约束：第 7 章写到托管凭据时，只允许写**存在这样一条组织侧托管路径、它由谁保管、它在什么事件下失效、它不可得时该判为哪一级**，不写取得、使用、拼接或验证它的任何操作序列。台账里出现凭据值会被脚本一直接记 L05（属阻断集）并要求删除该字段。
3. **两个脚本纯文本、离线、只读。**不联网、不调用 `softwareupdate` / `mdmclient` / `profiles` / Apple Configurator / Xcode，不访问任何设备或 Apple 服务端点，不写入输入文件；唯一写出目标是 `mktemp -d` 建的临时目录并在退出时删除。
4. **判定模型不给"安全"结论，只给"能不能自证"结论。**第 19 章的 J1—J4 里没有任何一级意味着"这台设备是安全的"；它们回答的是"你说这台设备归你、数据已清，这句话现在有什么支撑"。

### 2.2 与第 09 篇的边界（一句可核对的分工）

第 09 篇的主键是**补丁**：一条修复从公告出发，经过目录、签名、下载、装配、安装、回执，问它停在哪一格。第 10 篇的主键是**归属**：一台设备从采购进入组织清单，经过入册、监管、锁定、丢失模式、抹除、账户轮换、管理服务迁移，直到退出清单，问每一格上"它属于谁"和"上一位的凭据还在不在"。

两篇共享的存档件只有 7 个 slug（`commands-and-queries`、`status-items`、`device-information-command`、`devicemanagement-declarations`、`device-life-cycle`、`profile-specific-payload-keys`、`enrolling-a-device-in-a-beta-program`），本篇只把它们用作"词表从哪里来"，不重复第 09 篇的任何发布行读数。本篇对公告侧只使用一条**否定式**事实：某个生命周期组件标签在公告里不存在（第 16 章 R11—R13）。

一句话分工：**第 09 篇管补丁走到哪，本篇管设备属于谁、数据还能不能被证明已清。**

### 2.3 与第 02 / 04 / 05 篇的边界

- 第 02 篇（访问控制）讲类密钥体系本身——哪一类文件在何种锁定状态下可解。本篇引用 escrow keybag 与 `UnlockToken` 时**不重述类密钥体系**，只问一件事：**这一份密钥材料现在在谁手里，换主之后它有没有被作废**（第 7.5、9.4 节）。
- 第 04 篇（认证与通道加密）与第 05 篇（生物识别）不出现 MDM 协议，也不出现 Activation Lock。本篇涉及 Secure Enclave 只到"托管设备证明可以作为归属证据的一句"（第 4.6 节）为止；涉及生物识别只在第 10.5 节的"账户删除后生物识别数据随卷消失"这一句上使用平台安全指南的原文，不展开。

### 2.4 与"锁定模式"与"越狱"类篇目的边界：三个词的显式区分

iOS 语境内有三个词长得很像、指向完全不同的东西，本篇只用第一个：

| 词 | 是什么 | 谁能开 | 本篇是否写 |
| --- | --- | --- | --- |
| Managed Lost Mode（托管丢失模式） | 设备管理服务对**监督设备**的定位 + 锁定 + 可选发声动作 | 管理服务管理员 | **写**（第 8 章） |
| Lost Mode（用户侧丢失模式） | 用户在"查找"里对自己的设备做的动作 | 用户本人 | 只在归属判定时作为对照（第 8.6 节） |
| Lockdown Mode（锁定模式） | 用户侧的攻击面收敛开关 | 用户本人 | **不写**（见既有锁定模式篇目） |

平台安全指南第 4572 行给的定义句是："If a supervised iPad or iPhone is lost or stolen, a device management service administrator can remotely enable Lost Mode (called Managed Lost Mode) on that device."——**"supervised" 是这个词成立的前提**，因此本篇把"未监督设备上的丢失模式"归到用户口径，不算组织归属证据。

### 2.5 本文不覆盖的对象

五条边界要在阅读前知道：

1. **不覆盖 Apple 服务侧的内部机制。**激活服务器如何存账户、绕过码在服务端如何校验，公开文档只到"验证"这一句（"The activation server verifies this code to bypass Activation Lock on the device."，《Activation Lock Bypass Code》第 13 行）。本篇不推测其实现。
2. **不覆盖非 Apple 的 MDM 产品行为。**厂商实现差异不在本轮存档口径内；本篇只按协议文档判定"协议允许什么"。
3. **不覆盖法规与取证程序。**法律侧的持有、查扣、数据主体请求不在范围内；本篇的"归属"是工程与运维意义上的。
4. **不覆盖 macOS 的全部细节，但保留必要差异。**Mac 在本层反复与 iOS 走不同规则（Apple silicon 的 `SetRecoveryLock` 独占、bootstrap token 参与抹除、`AccountConfiguration` 被迁移忽略、迁移对 macOS 更宽松），凡差异处显式标注，其余以 iPhone / iPad 为主线。
5. **不覆盖一条记录作为证据的资格判定。**设备归属与证据归属是两张判定表：崩溃报告里的两个设备键（CrashReporter Key 与只在 TestFlight 构建出现并取代前者的 Beta Identifier）、日志级别与落盘留存规则、九条采集通道的可得性与同意口径，全部由**第 13 篇**负责。本篇只问"这台设备现在归谁、上一位的凭据还在不在"，不问"这台设备里那条日志能不能作证"。两篇唯一的共用事实是**抹除**：本篇写它让归属易主，第 13 篇写它让设备级匿名标识重置——**设备易主不自动让证据易主，证据键重置也不自动让归属失效**。

### 2.6 术语与写作约定

- 引用格式为"《文档标题》第 N 行"，标题取本轮存档件首行 `PAGE-TITLE`（支持站点页取标题行），行号为扁平转文本件的物理行；平台安全指南的 PDF 转文本件里**页眉页码与折行会打断句子**，本文按第 2.1 节约定原样保留不修补。
- 中文首次出现时括注英文原词，之后用中文。`Activation Lock` 一律译"激活锁"，`supervision` 译"监管"，`escrow` 译"托管/托存"，`bypass code` 译"绕过码"（仅作名词使用）。
- 所有"设备"如果不特别说明，指 iPhone / iPad 口径；涉及 Mac、Apple TV、Apple Vision Pro、Apple Watch 时显式写出。

---

## 3. 三套词表：归属口径、平台安全口径、公开公告口径

这一层的第一个可用结论是：**没有任何一份公开产物同时使用这三套词表**。三章的读数是分别算的，换算失败也是分别列的。

### 3.1 词表一 · 归属与设备管理口径

这套词表描述"一台设备在组织里的位置"。它是**服务端口径**，主要落在 Apple School Manager / Apple Business 的清单与 MDM 协议文档里。

| 词 | 出处（本轮存档） | 取值 / 形态 | 本篇用途 |
| --- | --- | --- | --- |
| 激活锁状态（界面读数） | 《Turn off Activation Lock in Apple Business》第 270、275、280、288、292 行 | `Activation Lock On (User)` / `On (Organization)` / `shows as Off` | 归属判定的唯一"半公开"读数 |
| 激活锁类型 | 《Activation Lock on Apple devices》第 346—348 行 | Organization-linked / User-linked | 决定谁有能力关闭 |
| 设备清单状态 | 《Release devices in Apple Business》第 279、297 行；《Assign, reassign, or unassign devices》第 310—312 行 | Assigned / Unassigned / Released | 移交的三段终点 |
| 所有权终态 | 《Device assignment》第 11 行 | Disown（通知 Apple 服务器不再拥有） | 与 Released 不等价 |
| 入册通道 | 《About Apple device supervision》第 346—359 行；《Device enrollment》 | Automated Device Enrollment / Device Enrollment / User Enrollment / Account-driven / Configurator 手工 | 决定命令面是否存在 |
| 监管 | 同上第 345 行；平台安全指南第 4505—4506 行 | supervised = 组织拥有 | 大量动作的前提 |
| 来源 | 《Assign, reassign, or unassign devices》第 284—288 行 | Apple（客户号）/ 授权经销商或运营商 / AppleCare（替换机）/ Apple Configurator | 责任方判定 |
| 待配置态 | 《Device Configured》第 14 行；《Migrating managed devices》第 33 行 | `await_device_configured=true` | 迁移期唯一可控闸门 |
| 迁移截止 | 《Migrating managed devices》第 30—31 行 | `mdm_migration_deadline` + `X-Server-Protocol-Version: 8` | 时序核对锚点 |
| 复用态 | 《Migrating managed devices》第 22 行；《Returning a managed device to service》第 42 行 | `is_multi_user` / `is_return_to_service` | 两者为 true 时不可迁移 |
| 释放主体 | 《Release devices in Apple Business》第 300—303、313 行 | 有权限的用户 / 联动的管理服务 / 授权经销商；服务已删时显示 `Deleted Device Management Services` | 移交责任的落款 |

这套词表里最值得注意的是最后两行：**清单能记下"谁做的释放"，甚至能记下"做一个释放动作的那个管理服务后来被删了"**。这是本篇找到的唯一一个由 Apple 侧维护、可被组织直接读出的移交责任读数（第 4.4 节、第 17 章 V1）。

### 3.2 词表二 · 平台安全口径

这套词表描述"一台机器上的密钥材料处于什么状态"，落在《Apple Platform Security》里。它是**设备侧与安全机制口径**，取值多数不带日期。

| 词 | 出处 | 关键句（原文） | 本篇用途 |
| --- | --- | --- | --- |
| 五类 keybag | 第 1976 行 | "These operating systems use the following keybags: user, device, backup, escrow, and iCloud Backup." | 遗留面清点 |
| escrow keybag | 第 2000 行 | "This keybag allows the Finder or iTunes to back up and sync without requiring the user to enter a passcode, and it allows a device management service to remotely clear a user's passcode." | 托管凭据的本体 |
| escrow 存放位置 | 第 2000 行 | "It is stored on the computer that's used to sync with the Finder or iTunes, or on the device management service that remotely manages the device." | 证明"凭据不在设备上" |
| escrow 分片 | 第 2006 行 | "The escrow keybag and the key protecting it are split between the device and the host or server" | 单侧不可解，但也不可见 |
| 可擦存储 | 第 1973 行 | "Because all the keys needed to decrypt files in this class are stored on the device, the encryption only affords the benefit of fast remote wipe." | 抹除语义的极限 |
| 即时抹除 | 第 4585 行 | "Instant remote wipe is achieved by securely discarding the media key." | 同上 |
| 激活锁存续 | 第 4508 行 | "It remains enabled even if the device is erased." | **抹除不解决归属** |
| 部件级激活锁 | 第 4510 行 | "if an iPhone detects that a supported part came from another iPhone with Activation Lock or Lost Mode turned on, calibration is restricted for that part" | 归属可以活在零件里 |
| 监督与激活锁默认 | 第 4512—4513 行 | 未监督：登录并开"查找"即自动开启；监督："Activation Lock is disallowed by default" | 两通道语义相反 |
| 服务端启用 | 第 4522 行 | "The device management service needs to create a 31-byte bypass code, then send it to Apple servers" | 组织可自建锁 |
| 生成时机 | 第 4514、4520、4521 行；Mac 第 4547 行 | 三种（iOS）/ 两种（Mac） | 时间不可读（G1） |
| 解锁凭据集合 | 第 4524—4526 行 / 第 4527—4531 行 | 未监督 2 种；监督 4 种 | 责任方宽度 |
| 闸门位置 | 第 4523、4532 行 | "Activation Lock is enforced through the activation process after the Wi-Fi selection screen in Setup Assistant."；"The Setup Assistant in iOS, iPadOS, and visionOS won't progress unless a valid certificate can be obtained." | 唯一强制点 |
| Apple silicon 侧 | 第 4549—4554 行 | LLB / LocalPolicy / anti-replay；"The LLB won't allow booting of macOS unless a valid LocalPolicy is present." | Mac 归属另有闸门 |
| T2 侧 | 第 4556—4565 行 | "UEFI firmware won't allow macOS to boot unless a valid activation certificate is present." | 同上 |
| 一次性解锁令牌 | 第 2007—2008 行 | 需用户口令才能生成，改口令即作废 | 托管路径的例外 |
| Managed Lost Mode | 第 4570、4572 行 | "the current user is logged out and the device can't be unlocked"；"When an administrator turns off Managed Lost Mode, which is the only way the mode can be exited" | 唯一退出路径 |
| 远程抹除回执 | 第 4575 行 | "the device sends an acknowledgment back to the service and performs the wipe." | 与 `EraseDevice` 页互证 |
| 不可抹除三情形 | 第 4576—4578 行 | User Enrollment / EAS+User Enrollment / EAS+监督 | 通道决定可行性 |
| Shared iPad 登出 | 第 4603 行 | "When a user signs out of Shared iPad, that user's keybag is immediately locked and all apps are shut down." | 账户层即时性 |
| 临时会话 | 第 4604 行 | "When a temporary session is ended, Shared iPad performs the full logout sequence and deletes the temporary session's APFS volume immediately." | 唯一"立即删卷"句 |

### 3.3 词表三 · 公开公告口径

这套词表描述"哪个版本的哪个组件修了哪个 CVE"。它是**发布侧口径**，两个实例：Apple 的 CSAF 公告（`cve / component / fixed / available_for / releaseDate / advisoryId`）与 CISA KEV（`cveID / vendorProject / dateAdded / dueDate / requiredAction`）。

本篇只用它做一件事：**证明它说不了这一层的话**。三份公告 392 条 CVE 行里，摘要或详情文本命中"activation-lock / bypass-code / escrow / keybag / erase / remote-wipe / lost-mode / enrollment / supervision / passcode / sign-out / restore / setup-assistant / find-my / icloud-account / apple-account / mdm / configuration-profile / lock-screen"的，除 `pairing`（3 行）、`lock-screen`（1 行）与组件标签层面的 `Accounts / AuthKit / DeviceCheck / Security` 之外全部为 0；KEV 的 95 条 Apple 条目里 20 个用词命中全为 0（完整读数见第 16 章 R10—R13）。

### 3.4 七处换算失败

七处换算失败记为 **F1—F7**，它是本篇的核心可核对结论：**每一条都指明"缺的是哪一句"，不是"这两套词不一样"**。需要注意一处编号约定：本篇的层号与误区号不带前导零（L1、M1），两个脚本的信号码一律带前导零（L01、M01），脚本二的结论模板同样占用 C1—C4，因此**正文里的 `C1—C7` 只用于脚本二的结论模板，换算失败一律写作 `F1—F7`**。

**F1 · 归属状态 → 公告面：整段不可换算。**激活锁、托管码、抹除都不在公告口径的对象域里。任何"这个 CVE 影响激活锁"的说法都不可核对，第 19 章对这类断言一律判 J4。

**F2 · 激活锁三值读数 ↔ 平台安全两值叙述。**企业口径给 `On (User)` / `On (Organization)` / `Off`（《Turn off Activation Lock in Apple Business》第 270—292 行）；平台安全口径讲"disallowed by default / enabled automatically"（第 4512—4513 行）与四条解锁路径（第 4527—4531 行），但**从不写这两值的映射**。特别注意《biz》表第 279—286 行把 Managed Lost Mode（无论由管理服务还是由 Apple Business 开启）都记成 `On (Organization)`——**"锁"与"丢失模式"在界面读数里塌成同一个词**。

**F3 · Released ↔ Disowned ↔ Unassigned。**三个动作都在文档里，但没有一个文档定义它们之间的关系：改指派只结束"由哪个服务管理"（《Assign…》第 311 行），释放结束"能否再指派"并留下日期与主体（《Release…》第 282、300 行），Disown 只"通知 Apple 服务器本组织不再拥有"（《Device assignment》第 11 行）。**同一台设备走完三个动作会留下三种读数，走完一个会留下另一种**；本篇第 11 章按"清单还剩哪一句可查"来给这层定序。

**F4 · 15 天可取回窗口 ↔ 生成时机列表。**企业口径的时限句（第 362 行）与平台安全口径的三/两种生成时机（第 4514/4520/4521、4547 行）**是两个不同性质的陈述**：前者说组织侧多久内能拿到，后者说设备何时换新。两者都不给"当前这一枚的年龄"读数，于是"能不能拿"在设备端不可判（G1）。**本篇不写怎么拿，只写这件事不可判。**

**F5 · 迁移必然撤锁 ↔ 台账里的锁状态。**《Migrating managed devices》第 38 行是硬规则："If the original service has a lock on the device before migration, the migration process always removes that lock and invalidates any bypass codes."；第 40 行给失败分支："If migration fails, Apple School Manager or Apple Business removes any prior lock and invalidates any bypass codes, and then applies a lock on the device that only the administrator can unlock."。这两句意味着**迁移是一次对归属凭据的强制作废**，但失败分支留下的那把"只有管理员能解的锁"在设备侧的读数是什么、和正常锁如何区分，文档未展开（G3）。

**F6 · 托管密钥残留 ↔ 迁移完成。**第 56 行："If the original device management service sets a FileVault Full Disk Encryption recovery key by installing a com.apple.security.FDERecoveryKeyEscrow profile payload, that key remains on the device after migration until the destination service sends its own com.apple.security.FDERecoveryKeyEscrow profile payload."。**"迁移成功"与"托管恢复密钥已换新"是两个不同时点**，而前者有活动记录、后者只在"目标服务自己发过 payload"这件事里；台账若只记迁移完成，就把一句"上一家的托管凭据可能还在"读丢了。

**F7 · 丢失模式关停 ↔ 抹除。**《Disable Lost Mode》第 14 行："Erasing a device also disables Lost Mode. To reenable Lost Mode, the MDM server needs to store the device's Lost Mode state before erasing it, and restore that state if the device enrolls again."。抹除顺带关掉丢失模式，而恢复它所需的状态**要求服务端预先自存**——这是一个由文档明确指派给管理服务的自选动作，没有任何回执强制它发生（G4）。

### 3.5 换算失败的处置原则

七处断点在本篇的处理方式统一为三条，读者可以把它们当成第 19 章判定模型的规则来源：

1. **不因两套词表不同而降级。**词表不同是常态；只有当**判定所需的那一格在两侧都无读数**时才降 J4（第 17 章 V4）。
2. **不替读者裁决互斥的两句。**F2、F5 这类地方本篇给出两读与出处，要求台账把采用的读法写在自己那一行——脚本一只校验"有没有写"，不校验"写得对不对"。
3. **凭据类字段一律不入库。**F4、F6 的根源之一是"把凭据当台账字段"。脚本一对这类写法直接报警：`lock.bypass_code_recorded=true` 触发 L05、`lock.unlock_token_received=true` 触发 B05，前者属阻断集、会把整轮核验的退出码置为 1（第 21 章）。这条不是格式检查，是本篇的立场。

---

## 4. L1 身份与归属登记层

这一层回答"这台设备在账上叫什么、属于谁"。它是所有后续判定的锚：**同一台机器在三套系统里有三种标识，而没有任何一份文档要求它们可换算**。

### 4.1 四种标识与它们的来源

| 标识 | 出处 | 谁生成 | 出现面 | 备注 |
| --- | --- | --- | --- | --- |
| 序列号（Serial） | Apple Business / School Manager 清单；《Assign, reassign, or unassign devices》第 292 行可按序列号批量指派 | 制造商 | 组织清单、Configurator 导出 | 唯一被 Apple 侧当作主键使用的形态 |
| IMEI（双卡两台） | 《Activation Lock on Apple devices》第 373 行 | 制造商 | 激活锁清除请求 | "the device management service needs to include both IMEI values in the request" |
| UDID | 设备侧与 Configurator | 设备 | 入册、恢复 | 与 MDM 设备标识不同域 |
| MDM 设备标识 / `device-id` | 状态项 `softwareupdate.device-id`（第 09 篇口径）与 TokenUpdate | 设备注册时 | 协议面 | **可与 UDID 形态冲突（脚本一 A09 要求声明主键）** |

序列号是 Apple 侧唯一接受批量对账的键："To search for specific devices, you can paste up to 1024 serial numbers from a text file, with each serial number separated by a comma."（《Release devices in Apple Business》第 288 行）。这一句给本篇一个实用结论：**清单差集只能按序列号做**，脚本二因此把 `serial` 定为唯一必需主键，并在活动件或回执件里出现清单没有的序列号时输出 N1，而不是猜测匹配。

### 4.2 归属的三条独立记录面

同一个"属于谁"在三个地方各有一份记录，三者**没有一份权威**：

1. **Apple 服务侧的清单**：设备是否注册在本组织、来源是哪一类（第 4.3 节）、当前指派给哪个管理服务、是否已释放、释放日期与主体。
2. **管理服务侧的设备记录**：TokenUpdate 送来的设备信息、`ServerCapabilities`、已装配置与状态项读数。
3. **组织自己的台账**：位置、使用人、轮换计划、处置单号——本篇脚本一的输入。

第 17 章的可见性分级就是按这三面能不能同时取得来划的。**本篇的核心工程判断是：任何一条只用第 2 面或只用第 3 面得出的归属结论都不能自证。**

### 4.3 来源即责任方

企业文档把设备来源写成四类，本表把它们与责任方对齐：

| 来源（原文，第 284—288 行） | 谁对"入册前状态"负责 | 入册时的副作用 |
| --- | --- | --- |
| Apple（Apple Customer Number） | 采购方 + Apple | 订单号可整批指派（第 282—283 行） |
| Apple Authorized Reseller or an authorized cellular carrier | 经销商 | 需本组织在清单里 |
| AppleCare（for replaced devices） | Apple 售后 | **替换机会带来新机而旧机留在台账**（第 4.5 节） |
| Apple Configurator（for devices added manually） | 组织自己 | "When you add a device with Apple Configurator, the device is erased."（第 281 行，前一行还写着 "Important: Don't add user devices with Apple Configurator."） |

四类来源在清单里是可辨的（《Assign, reassign, or unassign devices》第 284 行 "Source: You can assign devices from different sources."），**这一格在本层难得地属于 V1（组织可直接读出）**。本篇把它列为少数可自证的归属证据之一（第 17 章）。

### 4.4 释放记录：本层最好的落款

《Release devices in Apple Business》第 300—303 行给出一段本层最有价值的原文：

> "You can review the release date for a device, as well as who or what device management service released it. The following entities can release a device: A user who has permissions to manage devices / A linked device management service that can release devices / An Apple Authorized Reseller"

再加第 313 行的兜底读数："If someone removes the service, Deleted Device Management Services appears."，以及第 315 行的替换关联："If the device was replaced, the serial number of the new device appears."。

这四句合起来是**本篇找到的唯一一组由 Apple 维护、含时间、含主体、含"主体已消失"这一状态**的移交落款。第 20 章 O7（移交落款完备率）就以它为目标读数。同时它也暴露一个边界：**只有"释放"有这套落款**，改指派与 Disown 没有对等记录面（F3 的另一半）。

### 4.5 部件级归属：所有权可以活在零件里

平台安全指南第 4510 行把激活锁的对象从整机扩到零件："Apple is extending Activation Lock for iPhone to cover individual parts to help deter stolen parts from entering the market. During a repair, if an iPhone detects that a supported part came from another iPhone with Activation Lock or Lost Mode turned on, calibration is restricted for that part."。消费者文档给这条补上后果句："When Activation Lock is on for a device, it can also protect individual parts in an iPhone or iPad."（《Activation Lock for iPhone and iPad》第 26 行）与处置侧读数："Until you take these steps to unlock the part, the part isn't covered by the Apple Limited Warranty or an AppleCare plan, and you can't trade in your device."（《If a part is locked to someone else's Apple Account》第 18 行）。

对归属层来说这是本篇最反直觉的一条：**整机被处置干净之后，一台换过件的设备仍可能在某个零件上带着上一位使用者的归属状态**，且这个状态的可见形式不是"锁屏提示"而是"校准受限 / 无法以旧换新 / 保修不合格"。第 13.4 节据此把"部件归属"列进不可判定通道；脚本二只保留 `component_map` 这一列，它核对的是**这份清单能不能与部件读数对齐**（取值不为 `present` 记 C4），而不是部件归属本身。

### 4.6 可核对的归属证明：本层只有一种硬件证据

平台安全指南第 4317—4318 行提到 Managed Device Attestation，开发者文档把它列进 Identity management 主题（《Identity management》第 7—8 行："Validating a Managed Device Attestation — Verify an attestation that a managed device returns by performing the required steps."）。**这是本层唯一一种由设备硬件产生、可由服务验证的归属相关证据**，本篇只写到"它可以作为设备身份与配置声明绑定的证据"为止，验证流程不重述。

### 4.7 L1 的缺陷形态、责任方与证据归属

| 缺陷形态 | 表现 | 谁改 | 证据在哪 |
| --- | --- | --- | --- |
| 序列号 / UDID / MDM 标识混用 | 台账与清单差集算不出来 | 组织台账 | 脚本一 A09（主键未声明）、脚本二 N1 |
| 只按设备名或资产号建账 | 无法与任何 Apple 侧记录对账 | 组织台账 | 清单 V1 不可达 |
| 双卡设备只记一个 IMEI | 归属清除请求覆盖面不完整 | 管理服务 | 第 373 行 |
| 替换机入册、旧机未处置 | 两台都在账上 | 售后 + 组织 | 第 315 行的替换关联 |
| Configurator 手工加机当"无副作用" | 设备被抹（第 281 行）+ 30 天临时期（第 4613 行） | 组织自己 | 台账 `source` |
| 换过件的设备按"整机已清"处置 | 零件归属残留 | 维修方 + 处置方 | 不可判定（V4） |

---

## 5. L2 入册通道层

入册通道决定**这台设备上"组织能做哪些归属动作"这件事是否成立**。本篇把它放在第二层，因为它比策略更底层：策略写错只是不生效，通道选错是动作根本不存在。

### 5.1 五条通道与其监管后果

| 通道 | 出处 | 监管如何获得 | 归属能力 |
| --- | --- | --- | --- |
| Automated Device Enrollment（ADE） | 平台安全指南第 4506 行；《About Apple device supervision》第 346—353 行 | "Supervision gets automatically enabled on a device when using Automated Device Enrollment."；按系统版本列举 6 类设备 | 全：唯一支持组织侧激活锁、迁移、Return to Service 的通道 |
| Device Enrollment（profile-driven，Mac） | 《About Apple device supervision》第 354—357 行 | macOS 11+ 用账户驱动或配置文件驱动入册即监督 | 部分：激活锁管理受限（第 363 行） |
| Account-driven enrollment | 《Account-driven enrollment methods》；《Enrolling with Platform Single Sign-on》 | Mac 上同样触发监督 | 部分 |
| User Enrollment | 《User enrollment and device management》；平台安全指南第 4576—4578 行 | **不获得监督** | 几乎无：不能远程抹除（第 4577 行） |
| Apple Configurator 手工 | 平台安全指南第 4613 行 | "with mandatory supervision and device management service enrollment" | 全，但有 30 天临时期 |

第 4613 行的完整句值得全文抄录，它是本篇少见的"一个通道自带两个时间约束"："Administrators can also choose to add devices to Apple School Manager or Apple Business using Apple Configurator for Mac or Apple Configurator for iPhone, even if the devices weren't purchased directly from Apple, an Apple Authorized Reseller, or an authorized cellular carrier. When the administrator sets up a device that has been manually enrolled, it behaves like any other device in one of those services, with mandatory supervision and device management service enrollment. **For devices that weren't purchased directly, the user has a 30-day provisional period to release the device from one of those services, supervision, and a device management service.**"

### 5.2 通道如何收窄命令面：42 张可用性表的统计事实

本轮存档里有 42 张 MDM 命令可用性表。**32 张（76.2%）的 `Allowed in user enrollment` 写作 `N/A`**。这一句是纯统计、无解释空间的：**在被设计为"设备属于用户、组织只管理一部分数据"的通道上，绝大部分生命周期动作在协议层就不存在**，不是"策略没开"，而是"没有这条路"。

反过来看，剩余 10 张里 8 张写 `iOS, macOS, visionOS`、1 张写 `iOS, visionOS`（《Device Lock》第 20 行）、1 张写 `iOS, macOS`。也就是说，**允许在用户注册中使用的命令集中在"查询与配置"而不是"锁定与抹除"**：本篇存档里 `Erase Device`、`Enable/Disable Lost Mode`、`Delete User`、`Log Out User`、`Device Configured` 全部是 `N/A`。

### 5.3 监管是大多数归属动作的前提，且它的读数是文案

监督的定义句来自同一处（平台安全指南第 4505 行 = 《About Apple device supervision》第 345 行）："Supervision generally denotes that the device is owned by the organization, which provides additional control over its configuration and restrictions."——**文档把"监督"直接解释为"组织拥有"**，这是本层少见的语义对齐点。

但它给出的自查手段是一段界面文案而非结构化字段（第 371—375 行，按平台各一条）："iPhone and iPad: You can go to Settings and the text appears below the Search field, and above the Apple Account area: 'This [iPhone] [iPad] is supervised. [Organization name] can monitor your internet traffic and locate this device.'"。脚本一对监管只做两件与文档相符的事：`enroll.method=ade` 却 `enroll.supervised` 不为 true 时记 C02（对应自动入册即开启监管那句），以及把监管作为托管凭据字段是否必需的前提（监管设备缺 `lock.escrow_state` 记 L03）；**它不判断"这台设备到底有没有监督"——监督是设备侧读数，本轮两个脚本只吃台账与清单文本**。

### 5.4 通道与迁移资格：一条只在 ADE 上成立的规则

《Migrating managed devices》第 23 行把迁移资格直接绑定通道："The device needs to use Automated Device Enrollment."；第 24—25 行给出 iOS 与 macOS 的不同宽松度："An iOS device can migrate only if the device management service specified by Automated Device Enrollment still manages it. If the device unenrolls and then reenrolls in the same or a different service, it can't use the migration flow." / "A macOS device can migrate if any device management service manages it … provided the new enrollment is a profile-driven device enrollment."。

**"先退出再入册"在 iOS 上永久关闭迁移这条路，在 macOS 上只要满足配置文件驱动就仍然可行**。这一条对运维的实际含义是：同一类操作（重新入册）在两个平台上对"归属能否无损交接"的影响不对称，而台账里通常只有一句"已重挂"。本轮脚本不判断平台可行性——脚本一只能检查**记录是否齐全**（迁移或释放前没有记 `enroll.checkout_sent=true` 时记 C06），第 11 章给出判定所需的三项前置。

### 5.5 配件与固件线：不在本通道内

第 09 篇已给出一条可复用事实：Apple 发布表里存在不属于六套操作系统平台的行（耳机固件、键盘固件、CarPlay 通信插件等）。本篇沿用同一判定：**配件线不参与归属层**，因为它既没有激活锁面、也没有设备清单面。脚本一把 `receipt.channel=accessory` 记 B04（证据缺位类，不计退出码），同时**在判定环节直接给出 J4**（第 19 章的 v4 条件），第 13.1 节继续说明理由。

### 5.6 L2 的缺陷形态、责任方与更新通道

| 缺陷形态 | 表现 | 谁改 | 通道 |
| --- | --- | --- | --- |
| 在 User Enrollment 上规划远程抹除 | 协议不允许（第 4577 行） | 管理方 | 入册通道选择 |
| 把 Configurator 手工加机当采购入册 | 设备被抹 + 30 天临时期 | 组织自己 | 手工通道 |
| iOS 设备先退管再重挂 | 失去迁移资格（第 24 行） | 管理方 | ADE |
| 只看界面文案判断监督 | 无结构化读数 | 判定模型 | 台账 `supervised` |
| 配件线纳入归属台账 | 整段不可判 | 组织台账 | 非 iOS 通道 |

---

## 6. L3 监管与命令权限层

这一层回答"谁能改这一格"。它由两套彼此独立的闸门组成：**监管（设备侧属性）**与 **access right（协议侧授权）**，本层的多数误判来自把其中一个当成另一个。

### 6.1 两套闸门的分工

| 闸门 | 作用对象 | 出处形态 | 失败时表现 |
| --- | --- | --- | --- |
| Requires supervision | 命令在这个平台上要不要监督设备 | 可用性表第 3 行 | 命令不下发或被拒（无统一码） |
| Required access right | 下发该命令的配置文件里要声明哪一项权限 | 可用性表第 5 行 | 设备返回权限类错误 |

本轮可核对的权限词只有 9 个：`DeviceLockAndRemovePasscode`（7 次）、`AllowPasscodeRemovalAndLock`（4 次）、`AllowInstallationRemoval`（2 次）、`AllowInspection`（2 次）、`AllowAppInstallation`（2 次）、`AllowDeviceErase`、`AllowQuerySecurity`、`AllowQueryRestrictions`、`AllowSettings`、`Special Case` 各 1 次（其中 `Special Case` 属"未展开"）。**42 张表里 20 张的必需权限写作 `N/A`。**

### 6.2 权限词与归属动作的错配（G2）

本篇最需要注意的一处是 `Activation Lock Bypass Code` 与 `Clear Activation Lock Bypass Code` 两条命令：前者的表写 `Required access right | N/A`（《Activation Lock Bypass Code》第 25 行），后者同样写 `N/A`（《Clear Activation Lock Bypass Code》第 18 行）；它们与 `Security Info`（必需权限 `AllowQuerySecurity`，第 18 行）挂在同一个 SEEALSO "Security" 组里（《Security Info》第 23—26 行）。**取用与作废组织侧归属凭据这两件事，在权限词表里没有对应项**。

本篇只把这作为**审计义务的证据**记录：谁能在这一层说明"我们的配置里没有一项权限词覆盖这两个动作"，谁就能把这两个动作的发生与否归到"配置文件之外"的面上（第 17 章 V4）。脚本一在这件事上只做三件可执行的动作：**监管设备必须声明 `lock.escrow_state`，缺失或取值不在 `escrowed / not_escrowed / not_required / unknown` 内记 L03**；**记为 `escrowed` 时必须同时给出 `lock.bypass_code_available` 与 `lock.escrow_rollback`（可否再取得 / 是否已失效），任缺其一或取值出表记 L04**；**`enroll.access_rights` 里出现 `DeviceLock` 却没有 `lock.unlock_token_received` 同样记 L04**，因为文档把那份数据等同于设备主密码，它的"收取状态"是归属判定要的一格。三件事的共同点是**只记录存在性与失效口径，绝不记录值**——一旦台账落了值（`lock.bypass_code_recorded=true`），脚本一记 L05 并要求删除该字段；L05 属阻断集，出现即整轮核验退出码为 1。至于"这一枚码今天还可不可取回"，本轮没有读数，脚本一也无法判：本篇把它记入 G1（第 26 章），并在摘要里说明它属于"只写不可判、不写取得"的那一格。

### 6.3 命令可用性表是一个可核对的接口契约

一张可用性表五行，语义各不同，本文把它当成本层最结构化的公开产物（示例《Erase Device》第 16—21 行、《Security Info》第 14—18 行、《Device Lock》第 15—21 行）。三件事值得记：

1. **同一命令在不同平台上的约束不对称。**《Device Lock》第 18—20 行：需要监督只写 macOS，允许在用户注册中写 iOS 与 visionOS——**同一行里"要不要监督"与"能不能用户注册"分属不同平台**。台账若按"这条命令要不要监督"记一个布尔值，就会在 macOS 上记真、在 iOS 上记真但实际不需要，这也是脚本一对"动作已发生"与"权限词已声明"要求成对记录的原因：`lock.device_lock_sent=true` 而 `enroll.access_rights` 里没有 `AllowPasscodeRemovalAndLock` 时记 C04（同理还有 `AllowDeviceErase` 与 `AllowLostMode` 两对）。
2. **警告类句子写在同一页的 `ASIDE(warning)` 里。**《Device Lock》第 11 行："Sending this command to a Mac with Apple silicon running a version of macOS before 11.5 deactivates the Mac. To reactivate that Mac, it needs a network connection and authentication by a local administrator with Secure Token enabled."——**一条"锁屏"命令在特定版本上会让机器停用**，且恢复路径依赖本机安全令牌。这是本层最好的"命令副作用没有读数"案例（第 8.3 节继续）。
3. **N/A 有两种含义且不可区分。**在 `Device channel` 与 `User channel` 两行里 `N/A` 表示"这一面不存在"；在 `Required access right` 行里它表示"无权限要求"（或"未展开"）。**同一个字符串，两种语义。**本篇把它列为 G2 的一半，并要求台账对 `N/A` 注明采用哪种读法。

### 6.4 角色权限：组织侧的"谁能点按钮"

企业文档给出的角色句有两处：《Turn off Activation Lock in Apple Business》第 297 行"In Apple Business, sign in with a user whose role has permissions to remove Activation Lock from devices."、《Release devices in Apple Business》第 284 行"…whose role has permissions to release devices from the organization."，加上《Activation Lock on Apple devices》第 351 行的"…a user with Manage Device privileges can turn off organization-linked and user-linked Activation Lock…"与第 357 行对失败路径的角色列举（Administrator / Site Manager / Device Enrollment Manager）。

本层的可核对结论：**"谁有权在清单上做归属动作"只有 Apple Business 侧的角色模型可查，"谁有权让命令在设备上执行"只有配置文件的 access right 可查，两者没有任何映射表**。脚本一因此只校验后者这一侧（C04：动作已记、权限词未记），并额外把最危险的一组组合单独拎出来——`enroll.access_rights` 含 `ClearPasscode`、设备 `lock.passcode_set=true`、而抹除证据面为空时记 C05，因为文档明写该命令会关闭数据保护、且禁止对丢失的设备下发（《Managing passcodes》第 15—17 行）。**Apple Business 侧的角色（Administrator / Site Manager / Device Enrollment Manager）在本轮没有对应字段，也没有与任何 access right 的映射；本篇把它列为 G2 的第二半，脚本不检查。**

### 6.5 L3 的缺陷形态、责任方与证据归属

| 缺陷形态 | 表现 | 谁改 | 证据在哪 |
| --- | --- | --- | --- |
| 假设"监督 = 已授权" | 命令被权限面拒且无统一码 | 管理方 | 配置文件 access right |
| 台账按布尔记 supervision | 跨平台读错 | 组织台账 | 逐平台可用性表 |
| 凭据类动作无权限词 | 发生与否只能靠审计 | Apple 文档缺口 G2 | 服务端审计（V4） |
| `N/A` 语义混用 | 判定链条断裂 | 判定模型 | 台账注明读法 |
| 只看清单角色不看配置文件 | 移交主体不清 | 管理方 | 两侧各记一行 |

---

## 7. L4 锁定与归属凭据层

本层是全篇最敏感的一层：**这里保管的东西决定了上一位使用者的归属能不能被终结**。按第 2.1 节约束，本节只写"存在什么、由谁保管、何时失效、不可得时判什么级"，不写任何取得或使用步骤。

### 7.1 三值状态与它的产生方式

企业口径给三个读数（第 3.1 节表）；平台安全口径给四条产生路径：

1. **未监督设备自动开启**：第 4512 行"On an unsupervised iPad, iPhone, and Apple Vision Pro, Activation Lock is enabled automatically when the user signs in to their Apple Account and turns on Find My."
2. **监督设备默认不允许，由服务放开**：第 4513 行"On a supervised device, Activation Lock is disallowed by default, but a device management service can allow the user to enable it. This allows the service to escrow a bypass code from the device."
3. **服务侧直接建锁**：第 4522 行"…a device management service can contact Apple servers directly to enable Activation Lock. This is done entirely serverside and has no dependencies on user actions or the state of the device. The device management service needs to create a 31-byte bypass code…"
4. **两者并存时先到先得**：《Activation Lock on Apple devices》第 349 行"Some device management services support both Activation Lock methods; when attempting to use both, the first successful Activation Lock event takes precedence."

第 4 条是本层最重要的一条冲突规则，也是**唯一一个只在企业文档里出现、平台安全指南完全不提的规则**。它意味着：如果台账不知道哪件事先发生，就不知道这台设备上的锁是哪个主体的。脚本一能校验的是**读数与声明是否指向同一个主体**：`owner.activation_lock_state=On(User)` 而 `owner.user_activation_lock` 不为 on、或 `On(Organization)` 而 `owner.org_activation_lock` 不为 on、或读数为 `Off` 却仍有任一开启声明时记 A06；读数取值不在三态表内、或两栏声明都有而三态读数为空时记 L01。**"哪一个事件先成功"这一格本轮没有字段，也没有读数——脚本一无法判，本篇把它记入 G2 的第三项。**

### 7.2 唯一强制点在激活流程里

平台安全指南第 4523 行给出闸门位置："Activation Lock is enforced through the activation process after the Wi-Fi selection screen in Setup Assistant. When a device indicates that it's activating, it sends a request to the activation server to get an activation certificate."；第 4532 行给出后果句："The Setup Assistant in iOS, iPadOS, and visionOS won't progress unless a valid certificate can be obtained."。Apple Watch 上同构（第 4539 行"Pairing can't be completed unless a valid certificate can be obtained."），Mac 上则换成固件闸门：Apple silicon 是 LocalPolicy（第 4554 行"The LLB won't allow booting of macOS unless a valid LocalPolicy is present."）、T2 是激活证书（第 4565 行）。

**这四处闸门都在设置/启动流程里，不在运行期**。对归属判定的含义是：**设备能正常开机进系统，不能作为"它没有归属残留"的证据**——残留只在重新激活时暴露。第 24 章误区 M2 就是这条。

### 7.3 组织侧锁定的三个前提，其中一个是反直觉的

《Turn off Activation Lock in Apple Business》第 264 行的强调句："Important: You need to add the device to Apple Business and not release it before enabling Activation Lock; however, you don't need to assign it to a device management service."，《Activation Lock on Apple devices》第 351 行重复同一规则并加一句"Additionally, you can't have released the device"。再加第 4568 行的入册限制："Devices that are currently locked with Activation Lock can't be added to an Apple School Manager or Apple Business organization."。

三句合起来给出一个闭环约束，也是本篇第 12 章"回收二手设备"场景的根因：**已被激活锁锁住的设备进不了组织清单，而一旦释放又不能再在清单里管理激活锁——组织对一台设备的激活锁管理能力，只在"已入册且未释放"这个窗口内存在**。脚本二在这个窗口两端各设一条差集：清单已记 `released` 但活动件里既没有 `released` 也没有 `checked_out` 事件时记 N4（释放没有凭据），`released_date` 列为空同样记 N4；反向——活动件里已有释放事件而清单仍记 `assigned` 时记 N3（状态未回收）。脚本一则对"清单读数已是 `released`、`receipt.ownership` 却仍写 `apple_business`"记 A04——**释放之后这个服务不再能管理激活锁，两条记录不能同时为真**。

### 7.4 生成时机与可取回窗口：两处陈述，一句都没有闭合

平台安全口径给三种生成时机（iOS 侧第 4514、4520、4521 行）：首次设置、抹除后不从本机备份恢复地设置、抹除后从**另一台**设备的备份恢复地设置；Mac 侧第 4547 行只给两种："Setting up the device the first time · Setting up the device after an erase"。命令页与之一致（《Activation Lock Bypass Code》第 14—17 行）。企业口径给一个时限（第 362 行，15 天）。

三处放在一起的读法是：**"新凭据在哪些事件下产生"是设备侧规则，"旧凭据多久不再可用"是服务侧规则，而没有任何一处给出"当前这枚凭据的产生时间与剩余窗口"的读数**。这就是 F4/G1，也是本篇把"凭据时效"整段归入 V4 的原因。第 19 章的 J1 不试图补偿这件事：它对监管设备只要求 `lock.escrow_state` 取 `escrowed` 或 `not_required`（判定条件 p3），至于托管凭据的可得性与失效口径两个字段（`lock.bypass_code_available`、`lock.escrow_rollback`），是 L04 的通过条件而不是 J1 的必要条件。**两者都不检查凭据本身，也不假装能判断它今天还可不可用**——记存在性，不记值。

### 7.5 escrow keybag：设备之外的第二份可解能力

平台安全指南第 1999—2000、2006 行是本篇引用最密集的一段：

> 第 2000 行："The escrow keybag is used for syncing with the Finder or iTunes through USB and a device management service. This keybag allows the Finder or iTunes to back up and sync without requiring the user to enter a passcode, and it allows a device management service to remotely clear a user's passcode. It is stored on the computer that's used to sync with the Finder or iTunes, or on the device management service that remotely manages the device."
> 第 2006 行："The escrow keybag and the key protecting it are split between the device and the host or server, with the data stored on the device in the Protected Until First User Authentication class."

对本篇重要的三件事：**这份凭据的存放位置被明文写成"另一台机器上"**；它的**能力被明文写成"可以远程清除用户口令"**；它的分片方式（split）意味着任何一侧单独都不足用，但**没有任何一处文档说明设备换主或退出管理时它如何作废**。这条空白本篇不做推断，直接归 G5（第 26 章），而台账侧唯一能记的是**存在性**：`lock.escrow_state`（是否处于托管关系）与 `lock.escrow_rollback`（是否已失效），两者由 L03 / L04 校验齐全度，都不涉及凭据内容。

与它相邻的是 `UnlockToken`：《Managing passcodes》第 16 行"If your MDM payload specifies the Device Lock feature, the device includes an UnlockToken data value in the TokenUpdate message that it sends your device management service after installing the profile. This data contains a cryptographic package that can enable unlocking the device. **Treat this data as the equivalent of a primary passcode for the device.** Ensure that your IT policy specifies how to securely store this data, who has access to it, and the requirements to execute the ClearPasscodeCommand."。文档在这里**不是建议、而是要求**为这一项数据单独写 IT 策略。第 17 行进一步给出禁止句："Never send the ClearPasscodeCommand to a lost device, and always ensure physical possession of the device by a member of your organization before sending this command."。

本篇对这两项的处理一致：**台账只记"有没有这样一份材料、它是否已作废"，禁止把材料本身记进台账**。脚本一对这条边界给得很硬：值入台账（`lock.bypass_code_recorded=true`）记 L05 并要求删除该字段，`lock.unlock_token_received=true` 则记 B05 提示"该值等同设备主密码，只应记录存在性、不应记录内容"——一个是阻断信号、一个是提醒信号，因为前者违反本篇立场、后者只是台账写法风险。

### 7.6 同名单复义：redemption code 与 bypass code

《Apply Redemption Code》第 10 行的用途句是"This command provides a redemption code to complete installing an app. Use this when InstallApplication returns NeedsRedemption…"，其必需权限为 `AllowAppInstallation`（第 20 行）。它与激活锁没有任何关系，但两者在中文里都可以被写成"解锁码/兑换码"。**本篇统一：redemption code 译"应用兑换码"，bypass code 译"绕过码"（仅作名词使用），并禁止台账使用 `unlock_code` 一类无法区分二者的命名。**这一条脚本抓不住：脚本一只校验字段名的**命名空间前缀**（不属于 `owner/enroll/lock/erase/transfer/receipt/device` 七者之一才记 U01），一个自造的 `lock.unlock_code` 前缀合法、会被照常存进记录却永不参与任何判定。**语义污染在本轮不可检出**，本篇把它列入 G7 而不是伪装成一条信号。

### 7.7 Recovery Lock 的一条自动规则

《Set Recovery Lock》第 10 行给出本层少见的一条**自动回收**句："This command sets, or clears, a password on booting to recoveryOS. **When the device unenrolls MDM the system removes the recovery password.**"，并限定"only available on a Mac with Apple silicon"（第 11 行）、必需权限 `DeviceLockAndRemovePasscode`（第 19 行）。同组的 `Verify Recovery Lock`（第 10、18 行）只给可用性不给用途句。

这条与第 7.5 节形成对照：**文档明确说明 recoveryOS 口令会随退出管理被系统移除，但对 escrow keybag、UnlockToken、绕过码都没有等价句子**。本篇把它当作"能不能证明已清"的**基线事实**——只有存在自动回收句的那一项，"已作废"才是可谈的。但它不进判定式的计算：脚本一的 J1 条件（第 19 章 p1—p4）里没有 recovery lock 字段，因为本轮没有任何文档承认的"recovery 口令已清除"读数；这一格连同"设备侧能不能反查 recovery 状态"一起记入 G5 的例外清单（第 26 章）。

### 7.8 Mac 的两套启动闸门

Apple silicon 侧第 4549—4551 行说明 LLB 校验 LocalPolicy 与 Secure Storage Component 中的 anti-replay 值、三种条件下落到 recoveryOS；第 4553 行说明解锁后"that activation certificate key is used to obtain a RemotePolicy certificate. The Mac uses the LocalPolicy key and RemotePolicy certificate to produce a valid LocalPolicy."；T2 侧第 4556—4559 行说明由 T2 芯片持有激活证书、UEFI 查询。

对归属层的可核对结论：**Mac 的"这台机器能不能启动"和"这台机器属于谁"被绑在同一组策略件（LocalPolicy / 激活证书）上**，因此一台 Mac 的归属检查必然触及启动完整性面；iOS 侧没有这层耦合。脚本一把这一层耦合折算成一个可核对的服务侧字段：判定条件 p4 对 `device.class=mac` 额外要求 `transfer.bootstrap_token_available` 为 true（引导令牌是管理服务能参与这套闸门的存在证明），对 iOS 不要求。**这是一个字段要求，不是启动策略读数**——本轮没有读取 LocalPolicy 的手段，两个脚本都不读设备。

### 7.9 L4 的缺陷形态、责任方与证据归属

| 缺陷形态 | 表现 | 谁改 | 证据在哪 |
| --- | --- | --- | --- |
| 锁与丢失模式塌成同一读数 | 归属主体判错（F2） | 判定模型 | 台账分别记录 |
| 不知道两种建锁谁先发生 | 锁归谁不明（第 349 行） | 管理方 | 事件时间戳 |
| 已释放设备上试图管理锁 | 能力不存在（第 283 行） | 组织流程 | 清单 released_date |
| 锁着的新设备入册 | 直接被拒（第 4568 行） | 采购流程 | 入册失败记录 |
| 凭据年龄不可读（F4/G1） | 窗口内外无法区分 | Apple 文档缺口 | 无读数，只记存在性 |
| 托管材料入库 | 台账本身成为泄漏面 | 组织流程 | 脚本一 L05 |
| 把 redemption code 当归属凭据 | 字段语义污染 | 组织台账 | 本轮不可检出（G7） |

---

## 8. L5 丢失模式与远程锁定层

本层是"归属"与"可用性"最容易混的一层：**Device Lock 与 Managed Lost Mode 都能让设备立刻不能用，但对归属的证明力完全不同**。

### 8.1 三条锁定路径与它们各自证明什么

| 动作 | 出处 | 前提 | 退出方式 | 证明的到底是哪件事 |
| --- | --- | --- | --- | --- |
| Device Lock（`DeviceLockCommand`） | 《Device Lock》第 10、23 行 | iOS / macOS / Shared iPad / visionOS / watchOS；macOS 需监督 | 解锁设备 | **只证明"当前会话被中断"** |
| Managed Lost Mode（`EnableLostModeCommand`） | 平台安全指南第 4572 行；《Enable Lost Mode》第 15—19 行 | 监督的 iPad / iPhone（含 Shared iPad） | 只有管理员关闭 | 证明"组织主张这台机器在它手上丢了" |
| 用户侧 Lost Mode | 《Activation Lock for iPhone and iPad》第 30 行 | 用户自己的"查找" | 用户自己 | 属用户口径，不是组织证据 |

Managed Lost Mode 的定义与退出约束来自同一句（第 4572 行）："When Managed Lost Mode is enabled, the current user is logged out and the device can't be unlocked… When an administrator turns off Managed Lost Mode, **which is the only way the mode can be exited**, the user is informed of this action through a message on the Lock Screen or an alert on the Home Screen."——**"当前用户被登出"这件事是丢失模式自带的效果**，这一句让本层直接连到第 10 章的账户生命周期。

### 8.2 Device Lock 的三个前置条件与一条副作用

《Device Lock》第 10 行的条件句被写成一句三重的否定："You can display a message and phone number on the Lock Screen if the user has set a passcode for the device, it isn't a Shared iPad, and it isn't in Lost Mode. In macOS, this command uses the Find My framework to lock a device, and fails if there's no recovery partition on the device."

三件可核对的事：**(1) 没有口令就没有锁屏消息；(2) Shared iPad 不在这条路上；(3) 已经在丢失模式里就不叠加。** 加上第 11 行的警告（macOS 11.5 之前的 Apple silicon 会被"停用"，恢复需网络与带 Secure Token 的本地管理员），本层出现本篇第一个"动作的副作用比动作本身更严重且没有读数"的组合。脚本一把第 (1) 条编成一条可对账规则：`lock.device_lock_sent=true` 而 `lock.passcode_set=false` 时记 L08——**台账说锁了，但按文档这条命令在这种情况下根本显示不出锁屏消息**。第 (2)(3) 条与 macOS 版本副作用本轮都没有对应字段（脚本不读设备，也没有版本闸门规则），本篇把它们记入 G8。

### 8.3 丢失模式错误码是唯一结构化的读数

本轮存档里丢失模式族给出的错误码是 8 个数字码的全部来源：

- 《Enable Lost Mode》第 10 行："While in Lost Mode, a device responds to invalid commands with error code 12078."
- 《Disable Lost Mode》第 11—13 行：12067（不在此模式）/ 12069（关闭请求失败）/ 12078（在此模式下命令无效）
- 《Device Location》与《Play Lost Mode Sound》各引用同一族码

**12067 与 12078 之间没有"曾经在此模式"的状态**。也就是说：设备对"你现在不在丢失模式"和"你从没进过丢失模式"给出同一个回答。这是本层最干净的一条不可判定证据，也是本轮两个脚本**都碰不到**的一条：脚本一只看台账里的 `lock.managed_lost_mode` / `lock.user_lost_mode` 两个布尔字段（两者同时为真时记 L06，因为它按三态表认定"锁的发布方只能有一个读数来源"；处于托管丢失模式却没有 `lock.lost_mode_exit` 记 L07），脚本二只看活动件里的 `lost_mode_on` / `lost_mode_off` 事件名。**错误码本身不进这两个口径**，"从未开启"与"已关闭"的区分因此属于 G8（第 26 章）。

### 8.4 抹除顺带关闭丢失模式：一个必须由服务端自存的状态

《Disable Lost Mode》第 14 行是本篇引用频率最高的一句工程约束："Erasing a device also disables Lost Mode. To reenable Lost Mode, the MDM server needs to store the device's Lost Mode state before erasing it, and restore that state if the device enrolls again."

它给出三件事：抹除会**隐式**改变锁定状态；恢复所需的状态**只能由服务预先自存**；文档**没有要求服务必须这么做**，也没有任何回执证明它做了。企业侧的对应文档同样只描述动作、不描述状态留存。本篇把它定为 F7/G4，脚本一把它编成两个方向：`erase.command_sent=true` 且 `lock.managed_lost_mode=true` 而 `erase.lost_mode_state_stored` 不为 true 时记 K03（**该存的没记**）；若前一条不成立，而台账记了 `erase.lost_mode_state_stored=true`、`receipt.erase` 却为 `unavailable`，同样记 K03（**存了也没法自证**）。两个方向都是阻断信号，都只说明"这一格现在不能证明"，不推断设备实际发生了什么。

### 8.5 Lights-Out Management：本层唯一"以网络身份定位设备"的通道

《LOM Device Request》第 10—11 行："This command requires the DeviceLockAndRemovePasscode access right, LightsOutManagementLOM configuration and is available in macOS 11 and later on supported macOS devices. DeviceDNSName is the CommonName in the Identity issued on the client certificate from LightsOutManagementLOM."

本层只把它记为一条**归属相关的能力**：它需要配置文件里的一个专用载荷与一个身份证书，且权限词与 recoveryOS 口令族相同（`DeviceLockAndRemovePasscode`）。台账侧脚本能核对的只有一处对应：`lock.managed_lost_mode=true` 而 `enroll.access_rights` 里没有 `AllowLostMode` 时记 C04。载荷本身与身份证书没有字段位，本篇不假装覆盖。

### 8.6 与用户侧丢失模式的归属分界

消费者文档第 31 行给出一条清晰的分界句："While Activation Lock works in the background to make it more difficult for someone to use or sell your missing device, Lost Mode clearly shows anyone who finds your device that it still belongs to you and can't be reactivated without your password."——**Lost Mode 是声明，Activation Lock 是阻止**。本篇据此规定：**丢失模式不能作为归属证据，只能作为"归属主张"的证据**；判定时它必须与激活锁读数或清单记录同时出现，否则不能作为归属证据。本轮判定式没有把丢失模式写进 J1—J4 的条件（脚本一的 p1—p4 只看描述文件与 TokenUpdate、激活锁读数、抹除回执、托管状态与 Mac 引导令牌），丢失模式只以 L06、L07、K03 三种形态影响信号集，不影响级别。

### 8.7 L5 的缺陷形态、责任方与证据归属

| 缺陷形态 | 表现 | 谁改 | 证据在哪 |
| --- | --- | --- | --- |
| 把 Device Lock 当归属动作 | 会话中断≠归属变更 | 判定模型 | 台账分别记 |
| 抹除前未存档丢失模式状态 | 无法恢复主张（F7） | 管理服务 | 服务端自选记录 |
| 只看 12067 判定"从没丢过" | 与"已关闭"不可分 | 判定模型 | 回执序列 |
| 用丢失模式当归属证明 | 主张≠阻止 | 组织流程 | 需与锁/清单合取 |
| macOS 低版本发锁命令 | 机器被停用（第 11 行） | 管理方 | 版本记录 |

---

## 9. L6 抹除与密钥遗留层

这一层是全篇的技术核心：**"抹掉了"在这套文档里有四种不同含义，而只有一种留下服务端证据**。

### 9.1 四种抹除语义与它们的证据形态

| 语义 | 出处 | 发生了什么 | 服务端证据 |
| --- | --- | --- | --- |
| 远程命令抹除（`EraseDevice`） | 《Erase Device》第 12 行；平台安全指南第 4574—4575 行 | 设备应答后执行 | 仅"到了才应答" |
| 即时抹除（丢弃介质密钥） | 平台安全指南第 4585 行 | "Instant remote wipe is achieved by securely discarding the media key." | 无独立读数 |
| 本地 Erase All Content and Settings | 《Erase Apple devices》第 345、346—348 行 | 可擦存储里的密钥被销毁 | 无 |
| Return to Service 抹除（含保留应用） | 《Returning a managed device to service》第 6—11 行 | 抹 + 自动重新入册 | 有活动/入册记录 |

第 345 行的定义句把本地抹除的效果写成密钥事件："On the device, erasing (or wiping) obliterates all the keys in effaceable storage and renders all user data cryptographically inaccessible."；第 1973 行则给这类存储的能力上限一句坦率的说明："Because all the keys needed to decrypt files in this class are stored on the device, **the encryption only affords the benefit of fast remote wipe.**"

两句话合起来是本篇对"数据能不能被证明已清"的基本判断：**"已清"在这套文档里的定义是"密钥不可得"，而不是"字节被覆盖"**。这决定了第 19 章 J1 的定义方式——它要求的是密钥遗留面的证据，不是磁盘检查。

### 9.2 `EraseDevice` 的应答契约：一次性的

《Erase Device》第 12 行："This command allows the server to immediately erase a device, even a locked device, without warning the user. **The device sends a response to the server, but it doesn't retry if it isn't successful the first time.**"

这一句在归属层的分量：**协议自己声明了抹除不保证送达，并且不重试**。所以"我们发过抹除命令"不等于"设备被抹了"；唯一可用的证据是"设备回过了"。第 12 章的回执面按此定义：**只有带 `acknowledged=true` 的执行记录可以作为已抹证据**，且回执还必须能对时（有 `ack_at`）并带模式（有 `erase.mode`）。脚本一把这三格分别编成 K01（已发但 `erase.acknowledged` 为空）、K02（回执在但没有 `erase.ack_at`）与判定条件 p2（回执 + 模式 + 时刻三者齐全才可能进 J1）；脚本二在回执件侧做同一件事的镜像检查：`acknowledged=true` 而 `ack_date` 空、或 `ack_date` 早于 `sent_date` 记 T2，`EraseDevice` 行缺 `mode` 记 T5。

### 9.3 三种不能远程抹除的情形

平台安全指南第 4576—4578 行与《Erase Apple devices》第 355—357 行给出同一份三项清单：**User Enrollment 账户 / 以 User Enrollment 安装的 Microsoft Exchange ActiveSync 账户 / 监督设备上的 EAS 账户**。第 4574 行还把可抹平台列全："iPad, iPhone, Mac, Apple TV, Apple Vision Pro, and Apple Watch devices can be remotely erased by an administrator or user, rendering all data unreadable."

值得注意的是第三条：**监督设备用 EAS 反而不能抹**——这与"监督=控制更强"的直觉相反。本篇把它列为误区 M4，并要求台账把账户类型记成 `lock.apple_account_kind`（只取 `user / org / unknown` 三值）：取值出表记 E03，**激活锁为 `On(User)` 或 `On(Organization)` 而账户类型仍是 `unknown` 时记 L02**——也就是"这把锁由哪一侧关闭"不可判定。本轮脚本没有 EAS 账户与监督组合的字段位，第 4576—4578 行那张三项清单只能作为人工核对表使用（记入 G8）。

### 9.4 Mac 的抹除前置与降级路径

《Erase Apple devices》第 362—378 行给出 Mac 侧的条件表：Apple silicon 需 macOS 12.0.1+ **且需要管理服务提供 bootstrap token**（第 368 行"Needs to have a bootstrap token from the device management service."）；Apple silicon 或 T2 需从第一分区启动、需签名系统卷、不能从外部卷启动（第 369—373 行）；T2 需 Full Security 且不能设固件口令（第 374—377 行）。第 378 行给出降级："If one or more of the above conditions aren't met when receiving an EraseDevice command, a Mac by default falls back to using a macOS 11 behavior called obliteration. After a device is erased with obliteration, you need to reinstall macOS before the Mac can be used."

第 379—380 行还给出对降级本身的管理键（`ObliterationBehavior`），其中 `Default` 的行为是"The device responds to the server with an Error status or no status, and then attempts obliteration."——**"没有状态"也是一种被文档承认的应答**。本篇对 Mac 资产要求填 `erase.mode`，但**本轮词表只有三个请求侧取值**：`erase-all` / `erase-all-keep-data` / `preserve-installed-apps`。文档里的 obliteration 是执行失败后的回退行为、不是请求的模式，因此在这三个值里没有对应项；台账只能记"请求的模式"，把降级留给 `receipt.erase=unavailable`（B05）与 `erase.mode` 出表的 E03 报警。规则句是：取值不在词表内记 E03；`erase.acknowledged=true` 而模式缺失或出表时判定式 p2 不成立，这台设备最高只能到 J2。

### 9.5 密钥遗留面清点：换主之后还留在服务端的四类材料

这是本篇最重要的一张表。五类材料都**不在设备上**，都有文档承认的存放位置，其中只有一类有明确的自动作废句；最后一列写本轮脚本到底能不能核对这一格：

| 材料 | 存放位置（原文） | 作废条件（文档是否给出） | 台账字段（本轮） | 脚本能否核对 |
| --- | --- | --- | --- | --- |
| escrow keybag | 同步主机或管理服务（第 2000 行） | **未给出**（G5） | `lock.escrow_state`、`lock.escrow_rollback` | 能：缺失/出表记 L03，`escrowed` 却无失效口径记 L04 |
| UnlockToken | TokenUpdate 送进服务（《Managing passcodes》第 16 行） | **未给出**（G5） | `lock.unlock_token_received` | 部分：权限含 `DeviceLock` 而该字段空记 L04；字段为 true 时记 B05 提示"只记存在性" |
| 组织侧绕过码 | 服务保存（第 361—362、369—372 行） | 迁移时作废（《Migrating managed devices》第 38 行）；显式清除命令存在 | `lock.bypass_code_available`；值入台账即 `lock.bypass_code_recorded` | 部分：`escrowed` 而无可得性记 L04；**落了值记 L05 并要求删字段**（阻断） |
| FileVault 恢复密钥托管 | 设备 + 服务（《Migrating managed devices》第 56 行） | 目标服务发送自己的 payload 才换（同句） | 本轮**没有**对应字段 | 不能：残留窗口只能在人工核对表里，本篇记入 G8 |
| recoveryOS 口令 | 设备 | **自动**："When the device unenrolls MDM the system removes the recovery password."（《Set Recovery Lock》第 10 行） | 本轮**没有**对应字段 | 不能：有自动回收句但无读数，作为 G5 的例外记录 |

第 372 行是企业文档里唯一一句直接谈"换服务商时凭据怎么办"的话："The bypass codes that the device management service uses to manage Activation Lock are crucial to your ability to clear Activation Lock. Be sure to secure the bypass codes and back them up on a regular basis. **If you change to a different device management service, ensure that you receive a copy of those bypass codes, or that the device management service clears Activation Lock for all enrolled devices.**"——**"要么带走凭据，要么由旧服务商先把锁全清掉"，这是二选一，不存在第三条**；本篇第 11 章把它作为迁移前检查项。脚本一在这条上能做的只有"存在性与失效口径齐全度"（L04），**"有没有带走"这件事在协议里没有读数，因此不在任何信号码里**（G1）；本篇也不写带走的操作步骤。

### 9.6 保留应用的抹除：一句精确的数据边界

《Returning a managed device to service》第 10 行的旁注给出本篇最有用的一句边界："When using Return to Service with app preservation, **the device preserves only the app executable data during the erase, and always erases all locally stored user-generated data for the app.**"

同族约束在第 43、44、60 行：应用保留必须依赖 bootstrap token（"The device can preserve apps only when it receives the bootstrap token from the service. Without the bootstrap token, the device performs a Return to Service without app preservation."），而**bootstrap token 只在初次设置时发送**（"The device sends the bootstrap token only during the initial setup."），并且保留式抹除的退出路径是"设备从任何存在的设备管理服务取消注册，**但不移除受管应用**"（第 60 行）。

三句合起来给出一个真实运维陷阱：**"保留应用"这条路把数据清除与身份残留绑在同一次操作上**——一次快速复用的抹除会带走用户数据、留下托管身份。第 20 章 O5（复用轮次的身份残留率）就是为这一格设的。脚本一把"声明冲突"编成 K05：`transfer.rts_enabled=true` 且 `transfer.preserve_apps=true` 而 `erase.mode=erase-all` 时报——**Return to Service 只保留 app 可执行数据，与整机电抹的模式声明不能同时为真**。bootstrap token 的可用性由 `transfer.bootstrap_token_available` 记（第 43—44 行"只在初次设置时发送"这条时间约束本轮没有读数，属于第 13.3 节的时间旁路），RTS 键的完整性另由 M03 校验。

### 9.7 抹除与激活锁的交互：本篇标题级的结论

第 4508 行的第二句："**It remains enabled even if the device is erased.**"，加上消费者侧另有一句同义表述（《Activation Lock for iPhone and iPad》第 19 行："Even if you erase your device remotely, Activation Lock can continue to deter anyone from reactivating your device without your permission."）。

这是本篇最应该在采购与处置流程里被读到的结论：**抹除解决数据问题，不解决归属问题；而激活锁解决归属问题，不解决数据问题**。两件事在文档里被反复写成互不覆盖。第 24 章误区 M1、M3 都是这条。

### 9.8 L6 的缺陷形态、责任方与证据归属

| 缺陷形态 | 表现 | 谁改 | 证据在哪 |
| --- | --- | --- | --- |
| 以"发过抹除"当"已抹" | 协议不重试（第 12 行） | 判定模型 | 回执（V2） |
| 以"已抹"当"锁已解" | 第 4508 行直接反驳 | 组织流程 | 清单锁读数 |
| EAS + 监督设备上规划抹除 | 不支持（第 4578 行） | 管理方 | `lock.apple_account_kind`（L02/E03），组合项人工核对 |
| Mac 无 bootstrap token | 落到 obliteration（第 378 行） | 管理服务 | `transfer.bootstrap_token_available`（K06） |
| 托管材料随换服务商遗留 | G5 | 双方服务 | 存在性字段（L03/L04）+ 审计 |
| 保留应用式复用留下托管身份 | 第 60 行 | 组织流程 | `transfer.rts_enabled` 与 `erase.mode` 的组合（K05） |

---

## 10. L7 用户账户生命周期层

设备归属之外还有第二层归属：**设备里的某个账户属于谁**。本层在多用户形态（Shared iPad、Mac）上会成为主导。

### 10.1 三种多用户形态与它们的隔离方式

| 形态 | 出处 | 隔离机制 | 登出后的即时效果 |
| --- | --- | --- | --- |
| Shared iPad | 第 4586—4588 行 | 每用户独立 APFS 卷 + 独立数据保护域 + UNIX 权限 + 沙箱 | 卷卸载，"can't be mounted again without the user signing back in"（第 4600 行） |
| 临时会话 | 第 4588 行末句 | 不落后端账户 | "their APFS volume is deleted and its reserved space is returned to the system"（即时） |
| macOS 多账户 | 《Managing devices and users in macOS》 | 设备与用户作为两个实体管理 | 见 10.4 |

第 4587—4588 行的定义句："Shared iPad is a multiuser mode for use in iPad deployments… Each user gets their own private, reserved storage location, which is implemented as an Apple File System (APFS) volume protected by the user's credential."；第 4597 行给出容量冲突时的处置："the system identifies an existing user whose data has finished syncing to the cloud and evicts that user from the device so that the new user to sign in… have an administrator forcibly delete an existing user account, thereby risking data loss."

**"驱逐旧用户"是 Shared iPad 的正常机制，而强制删除被文档明写为"冒数据丢失风险"。** 这一格是本层少数文档自己承担风险的句子。本轮脚本没有为它设字段位：`transfer.*` 命名空间里只有多用户标记（`is_multi_user`），没有"被驱逐用户"或"同步是否完成"，**因此这条风险在两个脚本里都不可检出**，本篇把它列入 G8 并只作为人工核对项写在这里。

### 10.2 登出的即时性是唯一的强保证

第 4603 行："When a user signs out of Shared iPad, **that user's keybag is immediately locked and all apps are shut down.**"，第 4604 行："When a temporary session is ended, Shared iPad performs the full logout sequence and deletes the temporary session's APFS volume immediately."

第 4603 行同段紧接着给出一个时间窗："iPadOS defers some ordinary sign-out actions temporarily and presents a sign-in window to the new user. If a user signs in during this time (approximately 30 seconds), Shared iPad performs the deferred cleanup as part of signing in to the new user account."——**密钥锁定是即时的，其余清理可以延到下一个用户登录时**。本篇把这约 30 秒记为"已登出但清理未完"的窗口，并把它与第 4604 行的"临时会话立即删卷"并列成两种不同的收束方式。**这个窗口本轮不可核对**：台账里没有"上一次登出时刻"与"下一次登录时刻"两个字段位，脚本也不读设备，只能作为排班规则写进流程（G8）。可核对的是相邻的一条：登出后命令不可用（10.3）。

### 10.3 `LogOutUser` 的两分钟命令空窗

《Log Out User》第 10 行只有一句话，但它是本层的时间约束来源："After logging out the user, **MDM commands aren't available on the device for up to 2 minutes.**"

含义：**登出动作会让设备在最多 120 秒内对管理服务不可命令**。这解释了运维里一个真实现象——"登出之后紧接着下发的抹除/配置在窗口内不被执行"。同时它的必需权限是 `N/A`（第 19 行），也就是说这是一个**任何受管设备都会接受、且不产生权限审计痕迹**的动作。脚本一能核对的是成对记录：有 `enroll.logout_at` 却没有 `enroll.command_held_until` 时记 M05——**窗口本身没有被留档，后面那条命令为什么没执行就永远解释不了**。它不比较时间差，也不推断某个动作落在窗口内还是外。

### 10.4 `DeleteUser` 的四个错误码与两个安全阀

《Delete User》第 13—16 行：12071（用户不存在）、12072（当前已登录）、12073（有数据待同步且 `ForceDeletion` 为 false 或未指定）、12074（无法删除；macOS 上删除最后一个管理员账户也返回此码）。

第 12073 是本篇少见的**文档内置安全阀**：默认不删有未同步数据的账户。配合第 12072（先登录就先失败）与第 10.3 的两分钟窗口，一条正确的顺序是"登出 → 等待 → 删除"；而 macOS 的 `DeleteUser` 同样受这些错误码约束（第 20—21 行）。**台账里如果只记"账户已删除"而不记 `ForceDeletion` 取值，就丢了一次显式的知情同意**；但本轮命名空间里没有用户删除相关字段，这一格在两个脚本里都不可检出，本篇把它与 10.1 的驱逐风险一起列进 G8，只作为流程要求提出。

### 10.5 macOS：设备与用户是两个实体

《Managing devices and users in macOS》把两侧分开：`mdmclient` 作为守护进程负责设备侧、作为智能代理负责用户侧，两侧使用**不同的 push token**，`com.apple.mdm.per-user-connections` 出现在 `ServerCapabilities` 里表示服务能管到账户粒度，用户在设置助理阶段可返回 `UserConfiguration` 或 `NotNow`，删除账户返回 410。迁移文档第 51—54 行把同一件事写成迁移规则（受管本地用户未登录时**设备不能自主在截止日发起迁移**）。

本层结论：**在 macOS 上"设备归属已移交"与"账户归属已移交"是两件事，且第二件依赖前一件的服务能力声明**。脚本一只对 Mac 资产强制一项可核对的服务侧前提：`transfer.bootstrap_token_available` 不为 true 时，抹除记 K06、ReturnToService 记 M03，判定条件 p4 不成立因而最高 J2。

### 10.6 用户侧的登出与"不抹除"：一条被明确允许的数据残留

《What happens after you choose Sign Out But Don't Erase》第 23—38 行给出一份完整清单，第 23 行的定义句："This lets you sign out of your Apple Account without erasing your device so that later you can sign back in faster."，第 24—37 行列出保留项（Health、Passwords、Contacts、Photos、Documents、Apps、Safari and bookmarks、Wallet passes、Freeform、Reminders、Notes、Calendars、Data that hasn't yet synced with iCloud），第 38 行给对照句："To remove all of this data from your device when you sign out of your Apple Account, choose 'Erase this [device]' instead."

**这条通道是文档明确支持的，其结果是账号已退出而数据仍在。**对归属判定的含义：登录状态不能作为"数据已清"的证据——本篇把它与第 9.7 节并列为两条"两个问题互不覆盖"的结论。第 24 章误区 M6 即此。

### 10.7 L7 的缺陷形态、责任方与证据归属

| 缺陷形态 | 表现 | 谁改 | 证据在哪 |
| --- | --- | --- | --- |
| 以"已登出"当"已抹" | 第 24—38 行直接反驳 | 判定模型 | 设备侧账户读数 |
| Shared iPad 轮次间隔小于 30 秒 | 清理与下一用户登录叠合 | 组织流程 | 台账时间戳 |
| 登出后立刻下发关键命令 | 落入 2 分钟空窗 | 管理服务 | 回执时间 |
| `ForceDeletion` 未记录 | 知情同意缺失 | 管理服务 | 命令参数 |
| 驱逐未同步完的用户 | 第 4597 行明示风险 | 管理方 | 同步完成读数 |
| Mac 只记设备侧移交 | 账户侧未移交 | 组织流程 | per-user 能力声明 |

---

## 11. L8 迁移与移交层

本层是"所有权移交"的正题。文档在这一层写得比别处细，但也留下本篇最多的一处硬冲突。

### 11.1 移交有六条不同的路，终点各不相同

| 路 | 触发者 | 是否抹设备 | 服务端是否留记录 | 出处 |
| --- | --- | --- | --- | --- |
| 改指派（Reassign，不迁移） | 组织管理员 | 否 | 活动记录 | 《Assign…》第 310—311 行 |
| Apple 侧迁移流程 | 管理员 + 用户/截止日 | 否（保应用可选） | 活动 + `mdm_migration_deadline` | 《Migrating managed devices》第 8—16 行 |
| 手工退管再入册 | 用户/管理员 | 通常抹 | 仅清单侧 | 同第 7 行 |
| Release（释放） | 管理员 / 服务 / 经销商 | 需随后抹并恢复 | 日期 + 主体 | 《Release devices…》第 279—300 行 |
| Disown | 服务（API） | 否 | 仅一次 API 响应 | 《Device assignment》第 11 行 |
| Return to Service | 服务 / 用户 / 设备空闲 | 是（三种模式） | 命令 + 入册 | 《Returning a managed device…》第 6—11、45—48 行 |

第 1.2 节说过：**没有任何一份文档把这六条串成一条流程**。本篇把"移交"定义为"从任一 X 路进入、并留下一个能被第三面核对的记录"，第 19 章的 J 级判定按留下的记录种类分。

### 11.2 迁移的七项前置与一条取消权

《Migrating managed devices》第 18—25 行是清单式的。下表把它们转成台账字段，并在最后一列写清**本轮脚本能不能核对这一项**——七项里脚本一只覆盖到通道、监管与模式三类，其余四项没有读数来源：

| # | 前置（原文行号） | 台账字段（本轮口径） | 脚本是否核对 |
| --- | --- | --- | --- |
| 1 | 第 19 行：iOS 26+ / macOS 26+ | `device.os_version` | 只校验形态（E04），不判断版本是否够格 |
| 2 | 第 20 行：actively registered **且未释放** | `owner.assignment_state` | 是：已 `released` 却无 Check Out 记录时记 C06；`released` 但仍有组织侧锁声明记 A05 |
| 3 | 第 21 行：Configurator 加入的需过 30 天临时期 | 本轮无字段 | 否 |
| 4 | 第 22 行：非 Shared iPad、非 RTS | `transfer.is_multi_user` | 是（仅 RTS 模式侧：`migrate_mode=return-to-service` 而多用户标记不为 false 记 M02） |
| 5 | 第 23 行：使用 ADE | `enroll.method` | 是：`ade` 之外走 return-to-service 记 M02；自动入册未记监督记 C02 |
| 6 | 第 24 行：iOS 需 ADE 指定的服务仍在管理它 | `receipt.ownership` | 间接：已释放却仍记 `apple_business` 记 A04 |
| 7 | 第 25 行：macOS 允许任意服务，但需配置文件驱动 | 本轮无字段 | 否 |

**窗口与两端回执另有一组信号**（不在上表七项里，但同样是这段文档的产物）：`transfer.migration_started` 为真时，缺 `transfer.migration_window_days`、取值非整数或超过 30 天记 M01；缺 `transfer.migrate_mode` 或取值出表记 M02；`transfer.rts_enabled=true` 而 MDM 与无线配置两项数据都缺、或用于 Mac 却无引导令牌记 M03；`transfer.new_enroll_ack` 与 `transfer.old_checkout_ack` 两侧都不是 true 记 M04（**归属交接没有任何一侧可证**）。

第 34 行给出一条常被忽略的能力："The administrator can cancel the migration before it starts, reverting the device to the original device management service, and cancelling migration prompts on the device."——**取消只对"尚未开始"有效**。本轮没有独立的"取消"事件名，脚本二用 `migrated` 与 `migration_closed` 两个活动的日序差来表达这件事：差为负（结束早于开始）记 T1，差超过 30 天记 T4。**"取消发生在开始之前还是之后"这一格只能靠这两个事件名的相对顺序间接看出，文档没有给第三个读数。**

### 11.3 Check Out 是 best-effort：本层最大的时序漏洞

第 27—28 行给出迁移时旧服务看到什么："Apple School Manager or Apple Business removes the device from the original service's Device assignment, which the original service detects when it next synchronizes that list. When migration starts, the original service receives a Check Out request from the device, indicating unenrollment of the device."，紧接着一条旁注："ASIDE(note) **The device sends the Check Out request on a best-effort basis, and the device management service may not always receive it. The service needs to handle previously enrolled devices that no longer respond to requests.**"

这是本篇对"移交"最结构化的判断：**移交的完成信号之一是尽力送达的**。所以任何"旧服务说没收到 Check Out"都不能推断"迁移没发生"，唯一可靠路径是旧服务下一次同步设备指派列表的结果。脚本二实现的是**清单到活动这一个方向**：清单记 `released` 而活动件里既无 `released` 也无 `checked_out` 时记 N4（释放/解绑没有任何凭据）；`released_date` 列为空也在同一条 N4 里报。**反方向本轮没有信号位**——活动件里出现 `checked_out` 而清单仍记 `assigned` 时脚本二不作断言（它的 N3 只针对 `released` 事件与 `assigned` 状态的冲突，N1 只针对清单里完全没有这台设备的情形）。本篇把这一条不对称写进第 23 章的验收表，而不是假装它被覆盖。

### 11.4 硬规则：迁移一定撤锁并作废凭据

第 38 行是本篇引用最多的规则句之一："**If the original service has a lock on the device before migration, the migration process always removes that lock and invalidates any bypass codes.**"，配合第 40 行的失败分支（作废后再上一把"only the administrator can unlock"的锁）与第 41 行的目标服务上锁时序（先 `await_device_configured=true` → 入册进待配置态 → 发 `Activation Lock a Device` → 再发 `Device Configured`）。

三条合起来给出本层最有用的结论：**迁移是一次由 Apple 强制执行的凭据换代**。它同时意味着两件事——（正）上一家的锁与凭据在迁移成功时确实作废；（负）**台账若没记录迁移前锁状态，就永远无法区分"这把锁是目标服务上的"还是"迁移失败后 Apple 上的那把管理员锁"**（G3）。这一格本轮**不可检出**：`lock.*` 与 `owner.*` 命名空间都只保存"当前读数"，没有"迁移前快照"这一键，脚本一也无法用一条信号位表达"两个时刻的读数缺失"。本篇的处理是把它写成流程要求（迁移前必须先做一次快照并留下采集日 `device.snapshot_date`，快照与审计日的先后关系由 E05 校验），并在第 26 章把"迁移前锁状态无字段"列为 G3 的实际缺口。

### 11.5 待配置态：唯一能让管理服务"先装再交人"的闸门

《Device Configured》第 14 行的限定句："This command only works on Automated Device Enrollment (ADE) devices that have their cloud configuration set to await configuration."；《User Configured》第 20 行给出对应用途："The command to inform the device that it can continue past Setup Assistant and finish login."；迁移文档第 33 行与 RTS 文档第 42 行都要求这个闸门（后者还写明"`is_return_to_service=true` 时设备总是假定 `await_device_configured` 为 true"）。

本层的可核对结论：**待配置态是移交过程中唯一一段"设备已在新服务手里、但用户还不能用它"的时间**；本篇把"移交是否正确完成"定义为"这段是否存在过、并且由 `Device Configured` 显式结束"。RTS 第 65 行（服务发 `Device Configured` 退出该态）、第 66 行（等待未保留应用安装时对后续命令回 `NotNow`）、第 69 行（`Idle` 表示恢复处理）给出一段完整的应答时序。**这段时序本轮没有事件名**（活动词表里只有 `returned_to_service`，没有 `device_configured`），脚本二只能核对它的前提：活动件里有 `returned_to_service`、回执件里同一序列号有 `EraseDevice`，而退回服务日早于抹除发出日时记 T6——**"先退服务后抹设备"这条顺序在文档里不成立**（退回服务的前提是设备已清）。其余三行（Device Configured / NotNow / Idle）留在第 18 章的人工读数面里。

### 11.6 迁移中的账户与密钥两项残留风险

两项来自同一份文档，且都写在最后：

- **账户侧**：第 52—54 行的规则使 macOS 迁移能否发起取决于"受管本地用户是否登录"（未登录时设备**不会**在截止日自主迁移）。
- **密钥侧**：第 56 行的 FDERecoveryKeyEscrow 残留（F6）与第 57 行的能力前提："The destination device management service needs to support the bootstrap token management feature in order to create a new recovery key."

本篇对第 11.6 节的处理：**这两项都是"迁移成功"这个词不包含的内容**。判定模型也不为它们增设字段：第 19 章的 J1 条件里与迁移相关的只有一项——Mac 资产要求 `transfer.bootstrap_token_available` 为 true（p4）。**FDERecoveryKeyEscrow 的残留窗口与"目标服务是否支持引导令牌管理"这两格本轮没有读数位**，本篇把它们写进第 20 章 O6 的检查单和第 26 章 G8，不伪装成已覆盖。

### 11.7 账号与清单本身的转移：另一条不在设备上的路

企业文档另有两条与设备无关的移交：《About account transfers》（组织账号合并/转移）与《Remove users or devices from a plan》。本篇不展开流程，只记录一条对判定重要的事实：**账号转移改变的是"哪个组织能看见这台设备的清单"，不改变设备上的任何锁或凭据**。第 24 章误区 M8 即"以为组织合并会自动处理设备归属"。

### 11.8 L8 的缺陷形态、责任方与证据归属

| 缺陷形态 | 表现 | 谁改 | 证据在哪 |
| --- | --- | --- | --- |
| 等 Check Out 当移交完成信号 | 尽力送达（第 28 行） | 管理服务 | 列表同步（V1） |
| 未记迁移前锁状态 | 撤锁后不可回溯（第 38 行） | 双方服务 | 台账快照 |
| 迁移成功即认为密钥已换 | 第 56 行残留 | 目标服务 | payload 发送记录 |
| 目标服务不支持 bootstrap token | 无法创建新恢复密钥（第 57 行） | 选型 | 能力声明 |
| iOS 先退管再入册 | 失去迁移资格（第 24 行） | 管理方 | 通道记录 |
| 取消时点在迁移开始后 | 无效（第 34 行） | 管理员 | 事件序列 |
| 组织合并当作设备已移交 | 锁与凭据不变 | 组织流程 | 清单读数 |

---

## 12. L9 回执与读数层

本层的主题：**这条链路上"能被机器读到的东西"是什么形状**。

### 12.1 命令—轮询—应答的基本循环

《Commands and queries》第 5—6 行给出协议骨架："When a device registers with the device management service, the service sends push notifications to the device when there are commands to process on the device. When the device receives the notification, it polls the device management service for the command, processes the command, and reports the command results to the service. The device then checks for other commands to process."

这段给本层两个硬约束：**命令到达依赖 push 通道**（第 07 篇主题），**结果是设备轮询时主动上报的**。所以任何"我们发了"的记录都不能证明"设备收到"，也不能证明"设备执行"；只有上报本身是证据。第 20 章 O3 按此定义。

### 12.2 三种"没回应"的形状

本篇在回执面能识别的失败形态有三种，**它们在服务端的证据形状不同**：

| 形状 | 出处 | 服务端可见性 |
| --- | --- | --- |
| 完全没有应答 | 协议未强制（第 9.2 节 `EraseDevice` 不重试） | 只见"发了" |
| 显式 `NotNow` | RTS 第 66 行、macOS 设置助理阶段 | 可见，且会转 `Idle`（第 69 行） |
| "Error 或没有状态" | 《Erase Apple devices》第 380 行（Mac 抹除降级） | 文档明写两者并存 |

第三行是本层最刺眼的一句：官方文档在描述 Mac 抹除失败时，把"返回 Error"与"不返回任何状态"写在同一句里当作可接受的同一种结果。脚本二对这一格的处理值得单独写清：**回执件的 `acknowledged` 列为空时它不产生任何信号**（T2 只在 `acknowledged=true` 而 `ack_date` 空或早于 `sent_date` 时报），只把该行计入回执行数——**它连"不可判"都不说，因为文档承认"没有状态"也是一种应答**。真正要求留档的是脚本一：`erase.command_sent=true` 而 `erase.acknowledged` 空时记 K01。

### 12.3 状态上报面能回答归属问题吗

声明式状态报告（《Declarative status reports》与 `devicemanagement-declarations`）在本层只被使用一次：**它有版本、机型、账户等维度的报告，但没有一项报告的组织归属语义**。第 09 篇已把状态项词表核对完（两套 install-state 表），本篇沿用该结论并只补一句：本轮 239 件存档里**没有任何一个状态项的取值集合包含激活锁状态、指派状态或托管凭据状态**。这是第 16 章 R15 的来源，也是第 18 章"读数面"整节的动机。

### 12.4 服务端侧的可读清单：三个 API 面

| API 面 | 出处 | 可读内容 | 缺口 |
| --- | --- | --- | --- |
| Device assignment 列表 | 《Device assignment》第 9—12 行 | 设备列表、详情、替换机信息、同步增量 | 无历史（只给当前态 + `Sync` 增量） |
| 释放记录 | 《Release devices…》第 300—315 行 | 日期、主体、服务已删提示、替换关联 | 只覆盖 Release |
| Roster（仅教育） | 《Roster management》第 5—6 行 | 班级、人员、课程、地点 | "This API isn't supported for Apple Business organizations." |

最后一行值得单独注意：本轮存档里与"人员归属"相关的结构化 API **只在 Apple School Manager 可用**。对 Apple Business 组织，人员与设备的绑定关系只能落在自己的台账里（**本轮命名空间里没有人员字段**：`owner.*` 只有指派状态、复核日、两栏锁声明、三态读数、来源、主键声明、采购日与 `org_id`，脚本一不会因为缺"使用人"报任何信号；这一格连同 Shared iPad 的驱逐与 `ForceDeletion` 一起构成 G6、G8 的实际内容，只能作为采集要求写进第 20 章 O10）。

### 12.5 认证面：谁在服务端有权读这些清单

《Authenticating for Automated Device Enrollment》给出一整套服务端身份约束：PEM 公私钥对与证书上传（第 7、10 行）、S/MIME 加密的 token 文件与解密步骤（第 11—13 行）、四项字段（consumer key/secret、access token/secret，第 14 行）、`X-ADM-Auth-Session` 与 401（第 20 行）、OAuth 1.0a + HMAC-SHA1 + 时间戳与一次性 nonce 的反重放（第 21 行）。

本篇只取两点：**读清单的服务身份与设备侧凭据完全无关**（换服务商时服务身份消失，第 9.5 节第 372 行的两难正来自这里）；以及反重放与短时会话使"事后回放某次读取"不可行——也就是说，**"谁在什么时候读过归属清单"这件事，在协议口径里不留长期证据**。

### 12.6 L9 的缺陷形态、责任方与证据归属

| 缺陷形态 | 表现 | 谁改 | 证据在哪 |
| --- | --- | --- | --- |
| 以发送记录当执行记录 | 第 12.1 节 | 判定模型 | 设备上报 |
| 把 `NotNow` 当失败 | 语义相反（第 66 行） | 管理服务 | 后续 `Idle` |
| 无应答即断言未抹 | 不可判 | 判定模型 | J4 |
| 用状态项找归属 | 无对应项（R15） | 判定模型 | 清单 V1 |
| 服务删除后无法回溯读取者 | 身份面消失 | 双方服务 | 台账快照 |

---

## 13. L10 旁路与不可判定通道层

本层不是攻击面清单，而是一份**"哪些通道会绕过本层全部判定"的登记**——用途是让判定模型知道什么时候必须硬停在 J4。

### 13.1 通道旁路

- **配件与固件线**：没有清单归属语义，也没有激活锁面（第 5.5 节）。
- **EAS 通道**：可以发起远程抹除（平台安全指南第 4575 行、《Erase Apple devices》第 352 行），但**它绕开 MDM 服务与 Apple 清单之间的对应关系**，且第 4576—4578 行给出三条不能用的组合。台账若只记 MDM 面就看不见这条。
- **Microsoft Exchange 检查入**：第 4575 行"For remote wipe through Microsoft Exchange ActiveSync, the device checks in with the Microsoft Exchange Server before performing the wipe."——**回执去向不是 MDM 服务**。

### 13.2 物理与流程旁路

- **Configurator 的连线激活**：第 4614 行给出了明确的否定句，也是本篇喜欢的一句："This feature doesn't allow an administrator to bypass any existing Activation Lock requirements normally required during nontethered activation."（本层只引用它作为"文档明确排除了一条直觉路径"的证据。）
- **维修与替换**：AppleCare 替换机会引入新序列号（第 4.3、4.4 节），旧机在台账上仍可能被记为"在用"。
- **二手回收**：第 7.3 节的闭环（锁着的设备进不了清单）意味着**回收场景里唯一可靠的归属读数不在设备上**，而在购买前的清单核对（《Activation Lock for iPhone and iPad》第 39—40 行也给出这一句："Before you buy an iPhone or iPad from someone other than Apple or an Apple Authorized Reseller, make sure that the device is erased and no longer linked to the previous owner's account."，并在锁定时给出界面形态"You see an 'iPhone Locked to Owner' screen"）。

### 13.3 时间旁路：三段"文档给了时间但没给读数"

| 时间 | 出处 | 有没有读数 |
| --- | --- | --- |
| 绕过码 15 天窗口 | 第 362 行 | 无（G1） |
| Configurator 30 天临时期 | 第 4613 行 | 无（可由加入日期推算，但需台账自己记） |
| 口令策略 60 分钟宽限 | 《Managing passcodes》第 7 行 | 无（只有 `SecurityInfo` 可查合规，第 8 行） |
| 登出后 2 分钟不可命令 | 《Log Out User》第 10 行 | 无 |
| 入册重试退避至多 5 分钟 | RTS 第 38 行 | 有（最终入册与否可见） |
| 登出清理约 30 秒 | 第 4603 行 | 无 |

**六段里五段没有任何结构化读数。**本篇把这一整列定为运营指标 O9 的对象：台账必须自己保存事件时间戳，因为设备不会替你保存。

### 13.4 部件归属与"不可判定"的硬边界

第 4510 行的部件级激活锁 + 《If a part is locked to someone else's Apple Account》第 35—36 行（"You can use a part that is locked, but because it isn't configured, it might not perform as expected or have features that are critical to privacy, security, or safety. In Parts & Service on the device, the part will continue to show a Finish Repair label."；"If you can't unlock the part, the part is ineligible for service… You also can't trade in your device if the part is locked."）给出本层的终局事实：**一台设备的部分归属状态可以永久停留在"零件里"，而可见形式是维修标签而不是任何安全读数**。本篇对此显式声明不可判定（J4），不给出推断规则；管理服务侧没有任何 API 或状态项能读出"某个零件带着别人的锁"（G9），脚本二因此只保留 `component_map` 这一列——它记的是"这份清单能不能与部件读数对齐"（不等于 `present` 时记 C4），不是部件归属本身。

### 13.5 L10 的使用方式

本层不进归属矩阵的行，只作为**判定前的一次筛查**：第 19 章的判定树在检查任何证据之前，先问"这台资产是否落在 L10 的任一通道里"；若是，直接 J4 并写明命中的是哪一条。这一设计的原因是：**旁路通道会让其余九层的所有读数变成无关证据**，把它们混进平均数会系统性高估可信度（第 20 章 O10）。

---

## 14. 缺陷类型学 P1—P12

前十章按"层"切，本章按"缺陷在哪一次核对里被放过"切。这两种切法的差别很重要：**层告诉你去哪里看，核对点告诉你为什么没看见**。本篇把本轮存档能支撑的放过形态归成 12 类，每一类都给三件东西：它在哪一层发生、它被哪一次核对放过、它在本轮两个脚本里有没有对应信号位。

最后一条是本类型学与常见缺陷清单的差别：**P1—P12 里有一类（P5）根本没有信号位**，因为它对应的事实完全不在设备上；把它列出来恰恰是为了让读者知道"这一类只能靠流程，不能靠核验"。

| 编号 | 缺陷型 | 主发层 | 被哪一次核对放过 | 本轮信号位 |
| --- | --- | --- | --- | --- |
| P1 | 主键错置 | L1 | 采购入册时的对账 | A01 A09 / S3 N1 |
| P2 | 通道错配 | L2 L3 | 选型时对命令面的核对 | C01 C02 C04 |
| P3 | 读数塌缩 | L4 L5 | 读数入库时的分类 | A06 L01 L06 |
| P4 | 凭据入库 | L4 | 台账字段评审 | **L05**（阻断）B05 |
| P5 | 时效盲 | L4 | 迁移前的窗口检查 | **无**（G1） |
| P6 | 尽力信号当保证 | L8 L9 | 回执归档 | K01 K02 / T2 |
| P7 | 迁移即清空误信 | L6 L8 | 迁移完成后的确认 | M04（F6） |
| P8 | 抹除当撤锁 | L4 L6 | 处置放行 | A04 A05 / N3 N4 |
| P9 | 退出当清除 | L7 | 人员轮换验收 | K04（配合 M6） |
| P10 | 落款缺失 | L1 L8 | 移交审计 | A02 B01 / N3 N8 |
| P11 | 窗口未留档 | L5 L7 | 排班与脚本编排 | M05 / T4 |
| P12 | 不可判定当已判定 | 全层 | 判定模型本身 | J4 被写成 J1 |

### 14.1 P1 · 主键错置

**表现**：台账用资产编号、设备名或使用人姓名建账，而 Apple 侧的清单只按序列号做批量对账（《Release devices in Apple Business》第 288 行："you can paste up to 1024 serial numbers from a text file, with each serial number separated by a comma."）。双卡设备还要两个 IMEI（《Activation Lock on Apple devices》第 373 行）。

**为什么放过**：入册那一次没人要求把两侧的主键放在一起看。设备是采购单进来的，清单是按订单号指派的（第 282—283 行），台账是使用人签字时建的——三条路各有各的键。第一次需要合起来用的是**释放**或**移交**，那时已经隔了几年。

**后果**：清单/活动差集算不出来。脚本二把 `serial` 定为唯一必需主键，缺了它只能整行报 S3 或 N1，**不猜匹配**。P1 的代价不是判错，是**判不了**。

### 14.2 P2 · 通道错配

**表现**：在 User Enrollment 或 EAS 组合上规划归属动作。第 16 章 R3 给这一类的量化形式：**42 张命令可用性表里 32 张（76.2%）的 `Allowed in user enrollment` 写作 `N/A`**。这不是"策略没开"，是协议层没有这条路。第 4576—4578 行还给出三条不能远程抹除的情形，其中一条是**监督设备上的 EAS 账户**——控制更强反而不能抹。

**为什么放过**：计划阶段读的是功能列表（"支持远程抹除"），不是可用性表。功能列表按产品宣传，可用性表按通道分栏；两者在同一份文档体系里并不互相对齐。

**后果**：命令在管理台里显示"已下发"，设备侧从未收到。脚本一对这一类只能核对声明与权限词的对应（C04），**它不能判断通道本身允不允许**——因为那需要读设备。

### 14.3 P3 · 读数塌缩

**表现**：把锁与丢失模式记成同一个值。C2/F2 那条证据句在这里复述一次：企业清单界面读数表（《Turn off Activation Lock in Apple Business》第 279—286 行）把 Managed Lost Mode 无论由谁开启都记作 `On (Organization)`。

**为什么放过**：读数是从界面抄下来的，界面只给一栏。抄录的人没有义务区分"这栏写的是锁还是丢失模式"，因为**文档也没区分**。

**后果**：责任方判错——一把组织侧的锁被当成用户侧的，或一次丢失模式主张被当成归属变更。脚本一对这一类的处理是要求台账分栏记 `owner.org_activation_lock` / `owner.user_activation_lock` 与三态读数 `owner.activation_lock_state`，两栏与读数不一致时报 A06；两个丢失模式布尔同时为真时报 L06。

### 14.4 P4 · 凭据入库

**表现**：把绕过码、`UnlockToken`、escrow keybag 内容抄进台账或工单，理由是"方便移交时交接"。

**为什么放过**：字段评审通常只问"这个字段有没有值"，不问"这个字段该不该存在"。而文档在这里是**要求**而非建议（《Managing passcodes》第 16 行："Treat this data as the equivalent of a primary passcode for the device. Ensure that your IT policy specifies how to securely store this data…"）。

**后果**：台账本身变成最大的泄漏面，而且泄漏的不是"归属状态"而是"归属凭据"。这是本篇唯一一类**脚本直接拒收**的缺陷：`lock.bypass_code_recorded=true` 触发 L05，属阻断集，退出码置 1，并要求删除该字段。正确做法是记事件不记值——`lock.escrow_state`、`lock.bypass_code_available`、`lock.escrow_rollback`、`lock.rotated_at`。

### 14.5 P5 · 时效盲（无信号位）

**表现**：不知道当前这一枚托管凭据是什么时候产生的，因此不知道组织侧"15 天可取回"窗口（第 362 行）过没过。

**为什么放过**：这一类**不可能**在设备侧放过，因为它在设备侧根本不存在。文档给的两侧陈述都不含"年龄"读数：企业侧说窗口多久（服务侧规则），平台安全侧说哪些事件生成新码（设备侧规则，第 4514/4520/4521、4547 行）。

**后果**：迁移时才发现凭据取不回，而唯一的替代路径是"由旧服务商先把所有设备的锁清掉"（第 372 行）。**本篇不给任何补救操作，只把它列为 G1，并明确要求判定结果在最坏情况下写 J4。** 这也是 P1—P12 里唯一一类没有信号位的类型——它的存在本身是本文的论点之一：**有些归属缺陷只能靠流程预防，核验工具救不了**。

### 14.6 P6 · 尽力信号当保证

**表现**：把"我们发过命令"当成"设备执行过"。两个具体处：`EraseDevice` 的应答"doesn't retry if it isn't successful the first time"（《Erase Device》第 12 行），迁移时的 Check Out "sends the Check Out request on a best-effort basis, and the device management service may not always receive it"（《Migrating managed devices》第 28 行）。

**为什么放过**：管理台的"已发送"状态非常好读，"已确认"需要另外归档；而文档的失败分支写成了可接受的同一种结果——《Erase Apple devices》第 380 行明写 Mac 抹除降级时"The device responds to the server with an Error status **or no status**"。

**后果**：处置单上写着"已抹除"，机器实际没抹。脚本一 K01/K02 要求回执存在且能对时；脚本二 T2 要求 `acknowledged=true` 必须有 `ack_date` 且不早于发出日。值得记一笔：**脚本二对 `acknowledged` 为空的回执行不产生任何信号**，因为文档承认"没有状态"也是一种应答——它把这一格留给脚本一的 K01。

### 14.7 P7 · 迁移即清空误信

**表现**：把"迁移完成"当作"归属凭据与托管密钥都已换代"。第 38 行确实保证锁与绕过码作废（F5），但第 56 行的 FileVault 恢复密钥托管**明确不随之更新**："that key remains on the device after migration until the destination service sends its own com.apple.security.FDERecoveryKeyEscrow profile payload."（F6）。

**为什么放过**：迁移流程有活动记录（`migrated`、`migration_closed`），payload 发送没有对等的完成读数——它只是目标服务自己的一次配置动作。两边不在同一个记录面。

**后果**：上一家服务商的恢复密钥在新管理服务下继续可用。脚本一能核对的只有"两端回执至少有一个"（M04）与 Mac 侧的引导令牌可用性（K06/M03）；**F6 的实质内容本轮没有信号位**，本篇把它写进第 11.6 节的 J1 附加条件与第 26 章 G7。

### 14.8 P8 · 抹除当撤锁

**表现**：处置流程只做抹除，不查锁。第 4508 行的第二句直接反驳："It remains enabled even if the device is erased."；消费者侧另有一句同义表述（《Activation Lock for iPhone and iPad》第 19 行："Even if you erase your device remotely, Activation Lock can continue to deter anyone from reactivating your device without your permission."）。

**为什么放过**：处置清单（《What to do before you sell, give away, or trade in your iPhone or iPad》第 18 行）是给用户的动作列表，不是给组织的归属验收单；而组织侧的"释放"动作与"撤锁"动作在两个不同的界面页上（《Release devices in Apple Business》/《Turn off Activation Lock in Apple Business》），没有任何一处要求两者按顺序做完。

**后果**：一台数据已清、但归属仍在上一位使用者手上的设备进入二手或替换流程。脚本一对这一类给出三条方向不同的信号：已释放却仍把锁发布方记为管理服务（A04）、已释放但 org_id 空（A02 后半）、清单记 `released` 而活动件没有释放或解绑事件（N4）。

### 14.9 P9 · 退出当清除

**表现**：人员轮换时只让用户"退出但不抹掉"。文档明确支持这条通道并列出了保留内容（《What happens after you choose Sign Out But Don't Erase》第 24—37 行：Health、Passwords、Contacts、Photos、Documents、Apps、Safari and bookmarks、Wallet passes、Freeform、Reminders、Notes、Calendars、尚未同步到 iCloud 的数据）。

**为什么放过**：登录状态好查、数据残留不好查。"这个人已经不在这台机器上登录了"是一个可以截图的证据，"他退出不抹掉的那批数据已经不在了"没有对应读数。

**后果**：新持有者拿到的是上一位使用者的本地数据。脚本一对应用 `erase.instant_wipe_claim=true` 但没有 `erase.media_key_discarded` 时记 K04——**"已清"的定义是密钥不可得，不是登录状态已退出**（第 1973 行的可擦存储那句给出这个定义）。

### 14.10 P10 · 落款缺失

**表现**：移交只留下"改指派"或"Disown"，没有释放记录。三条路的落款面不对称：释放有日期与主体，甚至能记下"做这个动作的那个管理服务后来被删了"（第 300—303、313 行）；改指派只结束"由哪个服务管理"（第 311 行）；Disown 只留一次 API 响应（《Device assignment》第 11 行）。

**为什么放过**：操作者选了"最快的那条路"。三条路都能让设备离开当前管理服务，但只有第一条留下可第三面核对的记录。

**后果**：事后无法回答"这台设备上一次易主是谁批准的"。脚本一 B01（缺复核日期）与 A02（缺指派状态）、脚本二 N3（清单与活动状态冲突）、N8（两侧释放计数不等）合起来是本类型学的落款检查面。

### 14.11 P11 · 窗口未留档

**表现**：三段文档给了时长但没给读数的窗口被当成"不存在"：`LogOutUser` 之后最多 2 分钟命令不可用（《Log Out User》第 10 行）、Shared iPad 登出后约 30 秒的延后清理（第 4603 行）、Configurator 手工入册的 30 天临时期（第 4613 行）。

**为什么放过**：编排脚本按"命令发出即生效"写；排班按"上一位已退出即下一位可用"写；采购按"手工加机与采购入册等价"写。三处的文档句子都在，但都不在操作界面里。

**后果**：登出后紧接着下发的抹除落在窗口内不执行，运维把它解释成"命令丢了"；Shared iPad 轮次间隔小于清理窗，把两轮的残留叠在一起。脚本一对第一条给 M05（有 `enroll.logout_at` 却没有 `enroll.command_held_until`），对迁移窗口给 M01 与脚本二 T4（跨度 >30 天）；**30 秒窗口本轮没有字段位**，本篇在 10.2 节把它写成流程要求。

### 14.12 P12 · 不可判定当已判定

**表现**：把"没有告警""没有读数""清单里没显示"写成"已确认无风险"。本篇十条层里，V4 级（完全不可读）的格子数量并不少：凭据年龄、迁移前锁状态、失败分支的管理员锁读数、部件归属、服务端托管材料是否已作废。

**为什么放过**：判定表通常只留"通过 / 不通过"两栏，没有第三栏给"不可判"。第三栏要人写"我不知道，而且文档也没给"，这在验收会上最难通过。

**后果**：这是唯一一个会把 P1—P11 全部洗白的类型——一旦允许"无读数即无风险"，前面每一类都可以声称已核对。第 19 章的 J1—J4 因此**不设"安全"这一级**，最轻的一级是 J3（无归属动作待证），最重的是 J4（这一格不可自证）。

---

## 15. 归属矩阵：层 × 责任方 × 入册通道 × 证据

本章给一张可以拿去开会的表。四个轴的含义固定：

- **层**：L1—L10。
- **责任方**：这一格的读数**由谁产生、由谁保管**。本篇只承认四种落点——设备、管理服务、Apple 服务侧、组织台账；一台设备的同一格常常同时有两份，那正是断点所在。
- **入册通道**：ADE / 配置文件驱动 / 账户驱动 / User Enrollment / Configurator 手工；标 `—` 表示这一格与通道无关。
- **证据**：本轮能拿到的最好那一份，以及它落在第 17 章的哪一级可见性（V1—V4）。

| 层 | 事实记在哪 | 谁能改 | 通道敏感 | 最好证据 | 可见性 |
| --- | --- | --- | --- | --- | --- |
| L1 归属登记 | Apple 服务侧清单 + 组织台账 | 组织管理员 / 经销商 / AppleCare | 否 | 释放记录（日期 + 主体 + 替换关联，第 300—303、313、315 行） | **V1** |
| L2 入册通道 | 设备 + 清单 | 管理方（选型）| **是**（全部）| 可用性表 42 张的静态事实（R3—R5） | V2 |
| L3 监管与权限 | 设备（supervised）+ 配置文件 | 管理方 | 是 | 配置文件的 access right 列表 | V2 |
| L4 锁定与凭据 | **Apple 服务侧**（激活服务器）| 用户 / 管理服务 / Apple | 是 | 清单界面读数 `On (User)` / `On (Organization)` / `Off` | **V2**（三值）/ **V4**（凭据年龄） |
| L5 丢失模式 | 管理服务 + 设备 | 管理服务管理员（唯一退出路径） | 是（仅监督 iPhone/iPad） | 错误码 12067 / 12078 + 服务端状态存档 | V2 / **V4**（"曾经开启"） |
| L6 抹除与密钥 | 设备（介质密钥）+ 服务端（托管材料） | 用户 / 管理员 | 是 | 设备回执 `acknowledged` | V2（回执）/ **V4**（托管残留） |
| L7 账户生命周期 | 设备 + 管理服务（MaaS 账户） | 管理服务 / 用户 | 是 | `DeleteUser` 错误码 12071—12074 + `ForceDeletion` 参数 | V2 |
| L8 迁移与移交 | Apple 服务侧（清单与迁移状态） | 组织 + 双方服务 | **强**（iOS 仅 ADE） | `mdm_migration_deadline` + 活动件里的迁移起止 | V1（清单）/ V2（活动） |
| L9 回执与读数 | 服务端日志 | 管理服务 | 是 | 命令—轮询—应答三元组 | V3 |
| L10 旁路 | 无落点 | 物理持有者 / 维修方 | 否 | 无 | **V4** |

三点要读出来：

**(1) V1 只有两格。**L1 的释放记录与 L8 的清单状态是 Apple 侧唯一由它维护、组织可直接读出的归属证据。第 4.4 节说过为什么这是本层最漂亮的一句：它含时间、含主体，甚至含"主体已经不存在"（第 313 行）。**除此之外，这条链路上没有第三格 V1。**

**(2) L4 与 L6 各有一半落在 V4。**归属状态可以读到三值，凭据年龄完全读不到；抹除回执可以要求，服务端托管材料有没有作废读不到。这不是文档写得不够细，是**这两格的权威不在设备上**——摘要里那句"设备自己不是这些事实的权威来源"在矩阵里表现为两个半格塌到 V4。

**(3) 通道只在 L2、L8 两处是全轴。**其余层的通道敏感性都能被可用性表逐条核对；L2 的通道本身决定了动作是否存在，L8 的通道决定了迁移资格是否成立（iOS 先退管再重挂即永久失去这条路，第 24 行）。**运营上应当优先盯这两格**，因为它们的错误无法用后续动作补救。

### 15.1 责任方 × 层：谁对哪一层负全责

按"责任方能不能自证"重新投影一次，本表可以直接用于定责：

| 责任方 | 独占的格 | 共享的格 | 完全不能负责的格 |
| --- | --- | --- | --- |
| 用户（Apple Account 持有人） | 用户侧 Lost Mode、Find My、账户退出 | L4 用户侧锁、L6 本地抹除 | 组织侧凭据、清单状态 |
| 管理服务（MDM） | 命令下发、配置权限、状态回执 | L5 托管丢失模式、L8 迁移两端 | **凭据作废是否生效**（第 38 行由 Apple 执行） |
| 组织管理员 | 清单指派 / 释放 / 角色 | L1 全部、L8 触发 | 设备侧读数 |
| Apple 服务侧 | 激活锁判定、迁移强制作废、清单持久化 | L4、L8 | — |
| 经销商 / AppleCare | 来源标注、替换机关联 | L1 来源四类 | 释放之后的任何事 |
| 维修方 / 物理持有者 | 部件归属（第 4510 行） | L10 | **文档完全没有给这一方读数的义务** |

最后一行值得单独看：**L10 那一格的责任方是"维修方与物理持有者"，而这一方在本轮所有文档里没有任何读数义务**。它出现的地方只有《If a part is locked to someone else's Apple Account》的操作说明和"Finish Repair"标签（第 35—36 行）。也就是说：部件归属这条链的每一环都可以合法地不留记录。这是第 13.4 节直接判 J4 的原因。

---

## 16. 公开读数：这条链路上能数出来的十八件事

本章全部读数由本轮存档（`.srcx10/`，取回日期 2026-10-31）离线算出，输入只读，不联网、不调用任何设备侧或 Apple 命令行工具。**每条都给复算入口**，读者可以在自己的副本上重跑；口径不同的地方请显式写明，不要与本章默认口径混用。

先给归档本身的规模（R1），后面所有分母都取这里。

**R1 · 归档规模。**索引件 `.srcx10/IDX/files.tsv` 收录 **239 条**，分 **6 组**，合计 **42,463,088 字节 / 418,119 行**。按组的件数：A-docs 60、A-docs-raw 59、B-support 101、B-csaf 9、B-guide 2、C-kev 8。源地址完整性：**230 条带 https 源地址，6 条是本轮派生件**（源标注写明派生自哪个本地件），**3 条无源标注**。派生件不是缺陷——`C/release-readings.txt`、`C/kev-apple*.tsv` 这类必须由本地脚本生成——但引用它们时应连同生成器一起引用。
> 复算：`awk -F'\t' 'NR>1{t++; if($8=="")no++; if($8~/^https/)h++} END{print t, h, no}' .srcx10/IDX/files.tsv`

### 命令面（R2—R8）

**R2 · 42 张命令可用性表。**A 组 66 个转文本件里有 **42 件**带 `Command availability` 表（每表四或五行：Device channel / User channel / Requires supervision / Allowed in user enrollment / Required access right）。这 42 张表是本章一切分母；A 组其余 24 件是文章页、集合页与响应对象页。
> 复算：`grep -c '^Device channel |' .srcx10/A/*.txt` 后累加，或按 R3—R6 的四条行首串统计。

**R3 · 76.2% 的归属动作在用户注册通道上不存在。**`Allowed in user enrollment` 一行的取值分布：**`N/A` 32 张（76.2%）**、`iOS, macOS, visionOS` 8 张、`iOS, macOS` 1 张、`iOS, visionOS` 1 张。本篇对本文主题最要紧的一句在这里：**`Erase Device`、`Enable Lost Mode`、`Disable Lost Mode`、`Play Lost Mode Sound`、`Device Location`、`Device Lock`（在 macOS 侧）、`Delete User`、`Log Out User`、`Device Configured` 这些生命周期动作的这张表都写 `N/A`**。在被设计成"设备属于用户、组织只管理一部分数据"的通道上，**归属动作不是受限，而是不存在**。

**R4 · 71.4% 的命令根本没有用户面。**`User channel` 一行：`N/A` **30 张（71.4%）**、`macOS, Shared iPad` 7 张、`macOS` 4 张、`Shared iPad` 1 张。与 R3 合起来读：**用户面在这层是特例，不是常规**；它集中在 Mac 与 Shared iPad 的多用户形态上，正是第 10 章那两层归属会分叉的形态。

**R5 · 监督要求逐平台不一致。**`Requires supervision` 一行的完整分布：`macOS` **14 张**、`N/A` **14 张**、`iOS` 6 张、`iOS, macOS, tvOS` 3 张、`iOS, macOS` 2 张、`iOS, macOS, visionOS` 2 张、`iOS, macOS, tvOS, visionOS` 1 张。**22 张表点名 macOS、14 张点名 iOS，14 张整行 `N/A`**——同一命令在两个平台上"要不要监督"常常不同，因此台账必须逐平台记，不能记一个布尔值（第 6.3 节第 1 条）。

**R6 · 权限词只有 9 个，且 47.6% 的动作无词可表。**`Required access right` 在 42 张表里出现 **41 次**（有 1 张表缺这一行）。取值分布：**`N/A` 20 次（占 41 的 48.8%、占 42 的 47.6%）**、`DeviceLockAndRemovePasscode` 7、`AllowPasscodeRemovalAndLock` 4、`AllowInstallationRemoval` 2、`AllowInspection` 2、`AllowAppInstallation` 2、`AllowDeviceErase` 1、`AllowQuerySecurity` 1、`AllowQueryRestrictions` 1、`AllowSettings` 1、`Special Case` 1。**去掉 `N/A` 与 `Special Case`，这一层能用的权限词是 9 个。** 本篇的措辞在这里要谨慎：20/42 是本节口径（以 42 张表为分母），20/41 是"出现该行的表里占多少"；两个数都对，但**只能选一个写进台账口径并在文档里注明**。
> 复算：`grep -h '^Required access right |' .srcx10/A/*.txt | sort | uniq -c | sort -rn`

**R7 · 归属凭据的两个动作在权限词表里没有对应项。**《Activation Lock Bypass Code》第 25 行与《Clear Activation Lock Bypass Code》第 18 行都写 `Required access right | N/A`，而同一组 SEEALSO "Security" 里的 `Security Info` 写 `AllowQuerySecurity`（第 18 行）。**读安全状态要有权限词，取用与作废归属凭据不要。**这是 G2 的硬核形式。本篇不据此推测原因，只把它记为审计义务：这类动作的发生与否只能落在"配置文件之外"的面上（第 17 章 V4）。

**R8 · 开发者文档侧只有 10 件提到激活锁。**A 组 66 件转文本里，**10 件**出现 "Activation Lock"：`activation-lock-bypass-code-command`、`clear-activation-lock-bypass-code-command`、`certificate-list-command`、`commands-and-queries`、`device-assignment`、`disown-devices`、`migrating-managed-devices`、`returning-a-managed-device-to-service`、`rotate-filevault-key-command`、`security-info-command`。**声明式侧一件都没有**：`status-items.txt`（82 行）里 "activation" 出现 **0 次**。也就是说：**归属语义只存在于命令面，不存在于状态上报面**（第 12.3 节）。
> 复算：`grep -l -i 'activation lock' .srcx10/A/*.txt | wc -l`；`grep -ci activation .srcx10/A/status-items.txt`

### 平台安全指南侧（R9）

**R9 · 4,885 行里这五个词的出现行数。**平台安全指南转文本件共 **4,885 行**（PDF 转文本，页眉页码会打断句子，本文按第 2.6 节约定不修补）。按物理行计数：**Activation Lock 35 行、bypass code 7 行、escrow 30 行、supervis 21 行、lost mode 13 行**。这组数本身不说明问题，说明问题的是它落在哪几段：**"bypass code" 的 7 行里有 5 行是同一页的列表与两条定义**，也就是说整份指南对组织侧凭据的表述不足一页；而 escrow 的 30 行主要落在密钥层级那一段（第 1976—2008 行）。
> 复算：`for k in 'activation lock' 'bypass code' escrow supervis 'lost mode'; do printf "%s " "$k"; grep -ci "$k" .srcx10/B/apple-platform-security-guide.txt; done`

### 公告与在野面（R10—R14）

**R10 · 392 条 CVE 行里，生命周期三词命中 0 行。**三份并行版本线公告的 CVE 行数：**149041 = 95、149227 = 134、149230 = 163，合计 392**。摘要或详情文本提到 activation-lock / bypass-code / escrow 的行数（`advisory-lifecycle-readings.txt` [E] 段）：**三份都是 0，总计 0**。本篇据此得到的结论是**否定式**的：任何"某个 CVE 影响激活锁 / 托管码 / 抹除"的说法都不能在本轮存档里核对，第 19 章对这类断言一律判 J4。

**R11 · 20 个生命周期用词，18 个在三份公告里全为 0。**命中矩阵共 20 词 × 3 公告 = 60 组（`advisory-lifecycle-hits.tsv` 共 108 行数据，含 `row-summary-or-details` 与 `component-label` 两类口径）。文本面非零只有两处：**`pairing` 2 / 1 / 1**（三份都有，指配对通道而非归属），**`lock-screen` 0 / 1 / 0**。其余 18 个词（activation-lock、apple-account、bypass-code、configuration-profile、enrollment、erase、escrow、find-my、icloud-account、keybag、lost-mode、mdm、passcode、remote-wipe、restore、setup-assistant、sign-out、supervision）**在三份公告里全部为 0**。

**R12 · 13 个组件标签在并行版本线之间漂移。**"归属 / 身份 / 备份 / 存储"相关标签在三份公告里的行数（顺序 149041 / 149227 / 149230）：**Accounts 0/2/3**、**AuthKit 1/0/0**、**DeviceCheck 1/0/0**、**TCC 1/0/0**、**MobileBackup 2/0/0**、**APFS 1/0/0**、**Storage 2/0/0**、**Screen Time 0/0/1**、**Safety Check 0/0/1**、**HomeKit 0/0/2**、USB 0/1/1、MobileGestalt 0/1/1、BackgroundAssets 1/0/0；作为对照，SpringBoard 1/1/1、Security 1/4/2、Kernel 20/14/15。**派生读数 `drift_labels=13`**——13 个标签不是同时出现在三条版本线上。含义：**公告面的组件词表本身不稳定，因此不能用它做"某组件在某版本是否受控"的对账**。第 09 篇用同一份归档做过更新链侧的口径核对，本篇只取"漂移存在"这一条否定式事实。

**R13 · CISA KEV 的 95 条 Apple 条目，20 个用词命中全为 0。**KEV 目录版本 `2026.10.30`（全表 1,766 条），Apple 条目 **95 条**；`shortDescription` 里本篇 20 个生命周期用词的命中数**逐词为 0**（`advisory-lifecycle-readings.txt` [F] 段）。这一条比 R10 更有分量：**在野利用的公开描述也不表达归属层**。因此"这条 KEV 条目说明有人在利用激活锁"这类说法既无公告面支撑，也无在野面支撑。

**R14 · KEV 修复窗口只有两种标准值，10 条例外。**95 条 Apple 条目的 `dateAdded` → `dueDate` 跨度分布：**3 天 1 条、14 天 22 条、21 天 63 条、181 天 9 条**；非标准窗口 **10 条**（除 14/21 之外的全部），其中 9 条 181 天集中在 2014—2020 年的老条目，1 条 3 天是 2026-65400。含义：**"归属处置的时限"和"漏洞修复时限"是两套完全不同的时间体系**——后者有目录、有日期、有强制动作，前者只有第 362 行那一句 15 天。本篇把这条写进第 20 章 O9。

### 发布表与时间约束（R15—R17）

**R15 · 发布表 331 行里 61 行没有公布 CVE，17 行不属于六套系统平台。**安全发布表逐行统计：**331 行，61 行（18.4%）没有公布 CVE**；按平台族的空缺率，watchOS 15/36、iOS+iPadOS 17/79、iOS 4/5、macOS 10/91。另有 **17 行不属于六套操作系统平台**（耳机与键盘固件、CarPlay 通信插件、AirPlay SDK、Keynote / Pages / Compressor / GarageBand / iTunes 等）。本篇只在两处使用这组读数：**(a)** 第 5.5 节的"配件线不参与归属层"——它既没有激活锁面也没有清单面；**(b)** R16 的对照：**空缺在公告面是常态，所以"公告里查不到激活锁"不能被读成"激活锁没问题"。**

**R16 · 数字错误码只有 8 个，出现 16 次，全部集中在两族命令。**本轮存档里出现的 MDM 数字错误码及次数：**12078 × 4、12067 × 3、12068 / 12069 / 12071 / 12072 / 12073 / 12074 各 × 1**——合计 8 个码、16 处。分布只在两族：丢失模式（《Enable Lost Mode》第 10 行、《Disable Lost Mode》第 11—13 行、《Device Location》三处、《Play Lost Mode Sound》两处）与用户删除（《Delete User》第 13—16 行）。**激活锁、绕过码、抹除三个族一个码都没有。**这就是第 17 章 V3/V4 分界的技术依据：结构化读数是例外，而且集中在两个与归属凭据无关的族上。
> 复算：`grep -ohE '\b120[0-9]{2}\b' .srcx10/A/*.txt .srcx10/B/pages/*.txt | sort | uniq -c | sort -rn`

**R17 · 本层一共只有三处文档给出时长，都不给剩余量。**三句：① 15 天（"the bypass codes are available for up to 15 days after the device is first supervised, or until a device management service obtains—and then clears—the code explicitly"，第 362 行）；② 30 天临时期（Configurator 手工加入非直采设备，平台安全指南第 4613 行）；③ 最多 2 分钟（《Log Out User》第 10 行）。另有第三处只出现在指南里、没有管理读数：Shared iPad 的约 30 秒延后清理（第 4603 行）。**四处全部是"窗口"形式的陈述，没有一处给"当前还剩多少"的读数。**这就是 P5/G1 的全部公开材料——本篇能写的到此为止。

### 核验面（R18）

**R18 · 两个脚本的信号码共 74 个，其中 52 个属阻断集。**脚本一（`.x10-s1.sh`）51 个：A 组 10 + C 组 6 + L 组 8 + K 组 6 + M 组 5 + E 组 5 + U 组 2 = **42 个阻断**，B 组 5 个不计入退出码，J1—J4 是判定不是信号。脚本二（`.x10-s2.sh`）23 个：N 组 8 + T 组 6 + S 组 5 + C 组 4，其中阻断集为 S1—S5、N1、N2、T1、C1、C2 = **10 个**。合计 **74 个信号码，52 个阻断**。全部 74 个都在本轮环境实跑触发过，逐码触发条件见第 23 章验收表。

### 16.1 五条定调的读数

R3（76.2% 的归属动作在用户通道上不存在）、R6（47.6% 的动作无权限词可表）、R10（392 条 CVE 行里生命周期三词命中 0）、R13（KEV 的 95 条 Apple 条目里 20 个用词命中 0）、R12（13 个组件标签在版本线之间漂移）。

**这五条的结论不是"这些缺陷不重要"，而是"公告口径没有能力表达这一层"**。因此本篇在整份判定模型里只接受清单面与回执面作为证据，把公告面降级为"背景资料"（第 17 章 V3），并在脚本一里对以公告命中数声称覆盖的写法直接报 E02。

### 16.2 本章读数的三条使用限制

1. **分母只在本轮存档内成立。**"42 张表""95 条 KEV"是本轮取回件的数量，不是协议里命令或条目的总数；口径变化时 R3—R6 的百分比会跟着变。台账若引用百分比，必须连同分母一起写。
2. **零命中不等于零风险。**R10/R13 只证明"公告面说不出这一层的话"，不证明"这一层没有问题"。第 19 章对"零命中所以安全"的写法一律判 J4。
3. **计数与语义是两件事。**R5 说 14 张表在监督行写 `macOS`，本篇不解释为什么 Mac 需要而 iOS 不需要；那是产品线的设计问题，本文只把"逐平台记录"当成台账要求（第 6.3 节）。

---

## 17. 可见性边界：这一层读者能拿到什么

本篇拒绝使用"可观测/不可观测"这种笼统说法，改用四级，并且**每一级都必须举出具体那份产物**。分级依据只有一个问题：**你要的那一格，有没有一份你现在就能拿到的东西写着它。**

| 级 | 含义 | 定义 | 本层实例 |
| --- | --- | --- | --- |
| **V1** | 组织可直接读出 | Apple 侧维护、组织侧有界面或 API、含时间与主体 | 释放记录（日期 + 主体 + `Deleted Device Management Services` + 替换关联）；设备指派列表与 `Sync` 增量；`mdm_migration_deadline` |
| **V2** | 需先约定口径 | 读数存在但语义不唯一，必须先在台账里声明采哪种读法 | 激活锁三值读数（`On (User)` / `On (Organization)` / `Off`）；监督状态（界面文案）；`Requires supervision` 与 `N/A` 的双义；错误码 12067/12078 |
| **V3** | 只能自证一次 | 事件当时可见，过后不留；只有服务端自选归档才留下 | 命令回执（`acknowledged` + 时刻）；`NotNow` / `Idle` 应答；macOS 2 分钟命令空窗；Shared iPad 约 30 秒清理窗 |
| **V4** | 无读数 | 这条链路上不存在任何公开产物写着它 | 托管凭据的年龄与可取回性（G1）；迁移失败分支那把管理员锁的设备侧读数（G3）；服务端 escrow keybag / UnlockToken 是否已作废（G5）；部件归属（G9）；组织角色 ↔ 配置文件权限词的映射（G2） |

四条使用规则：

**规则一 · V1 只有两格，不要创造第三格。**本篇在 239 件归档里能找到 V1 级证据的只有两处（L1 释放记录、L8 清单与迁移状态）。任何声称"我这里还有第三种 Apple 侧权威归属读数"的写法，请先在存档里指出件名与行号；指不出来就按 V2 处理。**脚本二因此只把清单件当作可对账的一侧**，其它侧一律要活动件。

**规则二 · 从 V2 降到 V4 的常见原因是"抄录时丢了口径"。**最典型的一处：`N/A` 在 `Device channel` / `User channel` 行里表示"这一面不存在"，在 `Required access right` 行里表示"无权限要求或文档未展开"——**同一个字符串两种语义**（第 6.3 节第 3 条）。台账若不注明采哪种读法，这一格就从 V2 塌成 V4。脚本一对这类字段要求显式值，不认空值代表"没有"。

**规则三 · V3 只有一条出路：当场归档。**回执、`NotNow`、2 分钟窗口、30 秒清理窗都是**事件当时可读、事后不留**的。本层唯一一个由文档明确指派给管理服务的归档义务是丢失模式状态："the MDM server needs to store the device's Lost Mode state before erasing it"（《Disable Lost Mode》第 14 行）——注意动词是 **needs to**，且**没有任何回执证明它做了**。所以 K03 的两个方向都是阻断信号，而脚本二对 `lost_mode_off` 晚于 `erased` 报 T3 时**不断言谁对**，只声明两侧读数来源不同。

**规则四 · V4 的处置是判 J4，不是判"待观察"。**这是本篇和多数风险台账最容易分歧的一格。V4 意味着这一格无法自证，第 19 章直接给 J4。**"待观察"在归属层是一个会永久停留的状态**——因为观察动作本身需要一份 V1/V2 读数，而 V4 恰恰没有。第 24 章误区 M11 就是这一条。

### 17.1 责任方视角：谁能看到哪一级

同一格里，三类读者的可见性不同。这张表说明"为什么两个尽责的人都可能得出相反的归属结论"：

| 格 | 用户 | 管理服务管理员 | 组织清单管理员 |
| --- | --- | --- | --- |
| 激活锁状态 | V2（界面读数，但只看到自己的那半） | **V4**（协议里没有任何命令返回激活锁状态） | **V1**（清单直接写 `On (User)` / `On (Organization)` / `Off`） |
| 托管凭据可取回性 | V4 | **V4**（只有第 362 行那句窗口，没有年龄） | V4 |
| 是否已释放 | V4 | V3（入册/解绑事件） | **V1**（日期 + 主体） |
| 抹除是否生效 | V3（设备重启进设置助理） | **V3**（回执，一次性） | V4（清单不记录抹除） |
| 上一位使用者数据是否可读 | 不适用 | V4 | V4 |
| 迁移前锁状态 | V4 | V4（需事前自存快照） | V4 |
| 丢失模式当前状态 | V2（锁屏消息） | V2（错误码 12078 / 12067） | V2（`On (Organization)` 塌缩读数） |

第二行与第五行是本篇最想让人记住的两格：**没有任何一类读者能看到"托管凭据还剩多久"和"上一位使用者的数据现在能不能读"**。前者靠流程（第 11 章迁移前检查项），后者靠密钥遗留面的证据（第 9.5 节的表 + 第 19 章 J1 条件）。

### 17.2 为什么本篇不接受公告面作为归属证据

三个理由，都能在本章读数里对上：**R10**（392 行零命中）、**R13**（KEV 95 条零命中）、**R12**（13 个标签漂移，组件词表自身不稳定）。再加一条方法论理由：公告口径的对象是"哪个版本的哪个组件修了哪个缺陷"，而归属层的判定对象是"这台设备现在归谁"。**两者没有共享主键**——这是 F1 的完整表述，不是"两套词不一样"那种弱说法。

本篇对公告面唯一的合法用法是**否定式**：证明某条断言在公告面上没有支撑。脚本一把这条编码成两条信号：`receipt.advisory_lifecycle_hits` 为正数但 `receipt.component_map != present` 时报 **E02**（拿命中数声称覆盖却给不出对齐表）；填 `none` 或未填时报 **B03**（不计入退出码，只声明这一格不可由缺陷数推断）。

---

## 18. 设备侧与管理侧读数面

本章把第 17 章的四级落到"你打开哪个界面、哪一页、哪一栏"。它是给运维的一页纸，也是第 21—22 章脚本输入的来源约定。

### 18.1 设备侧能读到的八件事

| 读数 | 形式 | 结构化 | 归属可用度 |
| --- | --- | --- | --- |
| 监督状态 | 设置页文案"This [iPhone] is supervised. [Organization name] can monitor your internet traffic and locate this device."（第 371—375 行按平台各一条） | **否（文案）** | 低：只证明"组织声称"，不证明清单 |
| 已装配置描述文件 | 设置 → 通用 → 描述文件与设备管理 | 半 | 中：证明通道存在，不证明谁拥有 |
| 激活锁 | 设置 → Apple 账户 → 查找；抹除后在设置助理处暴露 | 否 | 中：只反映用户侧那半，组织侧不可见 |
| 入册状态 / 服务名 | 设置里显示的设备管理服务名 | 否 | 中：与清单指派可对照 |
| 托管丢失模式 | 锁屏消息 + 无法解锁（第 4572 行） | 否 | 中：主张证据，非归属证据 |
| 账户与登录态 | 设置顶部账户区 | 否 | **低**：退出登录 ≠ 数据已清（第 24—38 行） |
| 机型与版本 | 关于本机 | 是 | 不用于归属，用于通道/命令面判定 |
| 部件维修标签 | "Finish Repair"（《If a part is locked to someone else's Apple Account》第 35—36 行） | 否 | **唯一**能在设备侧看到的部件归属信号 |

一句总结：**设备侧没有一项结构化读数表达归属。**八格里只有两格能给"结构化"（机型/版本、部分配置元数据），而这两格都不是归属事实。这就是为什么本篇的台账输入必须来自设备之外（第 21 章），以及为什么"从设备上读一遍确认归属"这条常规直觉在第 10 层失效。

### 18.2 管理侧能读到的六件事

| 面 | 出处 | 内容 | 缺什么 |
| --- | --- | --- | --- |
| 设备指派列表 | 《Device assignment》第 9—12 行 | 设备列表、详情、替换机信息、`Sync` 增量 | **无历史**，只有当前态 + 增量 |
| 释放记录 | 《Release devices in Apple Business》第 300—315 行 | 日期、主体（用户 / 服务 / 经销商）、服务已删提示、替换关联 | 只覆盖 Release 一条路（C3/F3） |
| 激活锁读数 | 《Turn off Activation Lock in Apple Business》第 270—292 行 | 三值 + Managed Lost Mode 的塌缩读数 | 不区分锁与丢失模式；无凭据年龄 |
| TokenUpdate / 状态项 | 《Managing passcodes》第 16 行；声明式状态项族 | 设备信息、`ServerCapabilities`、安装状态 | **无一项状态项报告归属语义**（R8） |
| 命令回执 | 《Commands and queries》第 5—6 行 | 命令—轮询—应答三元组 | 尽力送达，不重试（R6/P6） |
| Roster | 《Roster management》第 5—6 行 | 班级、人员、课程、地点 | **仅 Apple School Manager 支持**，Business 组织不可用 |

**六面里只有第一、第二面是 Apple 侧持久维护且组织可直接读的（V1）。**其余四面要么由管理服务自己决定存不存，要么由设备在轮询时主动上报，要么根本不存在于该组织类型。这解释了本篇判定模型的一个选择：**J1 必须同时引用一份 V1 与一份 V2/V3 读数**——只有一份服务端自选日志时最高给 J2。

### 18.3 两份读数的对齐键：序列号，且只有序列号

第 4.1 节的四种标识里，Apple 侧只接受序列号做批量对账（第 288 行的 1024 个上限）。因此本篇规定：**脚本二的唯一必需主键是 `serial`**，UDID 与 MDM 设备标识只能作为台账的辅助字段，且必须显式声明主键（`owner.identifier_authority`，否则脚本一记 A09）。双卡设备要两个 IMEI（第 373 行）——这是本篇在标识面唯一的宽度要求，也是脚本一只校验形态、不做跨设备匹配的原因。

### 18.4 台账与清单的字段对照（脚本输入契约）

脚本一吃台账（`<设备标识>,<字段名>,<值>` 三列），脚本二吃三份 TSV（归属清单件、活动记录件、可选命令回执件）。两者的字段命名空间与词表互不共享，但语义必须能对齐；下表给出对齐点与**故意不对齐**的地方：

| 事实 | 脚本一字段 | 脚本二列 | 对齐方式 | 故意不对齐的理由 |
| --- | --- | --- | --- | --- |
| 设备主键 | `device.serial` | `serial` | 形态同为 `[A-Za-z0-9]{8,14}` | 脚本一只校验形态，脚本二要做差集，非法即整行跳过（S3） |
| 指派状态 | `owner.assignment_state` | `assignment_state` | 同词表 assigned/unassigned/released/deleted | 无 |
| 激活锁 | `owner.activation_lock_state` + 两栏开启声明 | `activation_lock_state` + `source_service` | 三值词表相同 | **脚本二不校验两栏与读数一致性**——那需要台账上下文 |
| 释放时间 | 由 `owner.assignment_state=released` 触发校验 | `released_date` | 脚本二要求日期形态（S5） | 脚本一不要求台账存释放日，它要求的是**复核日** `owner.assignment_reviewed_at` |
| 组织 | `owner.org_id` | `org_id` | 脚本二用于跨组织拒算（C2） | 脚本一只在已释放时要求非空（A02 后半） |
| 抹除 | `erase.command_sent` / `acknowledged` / `ack_at` / `mode` | 回执件 `command`/`sent_date`/`acknowledged`/`ack_date`/`mode` | 语义相同、字段不同 | 脚本一只对 `EraseDevice` 关心回执；脚本二对 10 条命令都收 |
| 托管凭据 | `lock.escrow_state` / `bypass_code_available` / `escrow_rollback` | **无对应列** | 单向 | 清单里没有这一格，因此脚本二不接受凭据字段——**连字段位都不给**，这是 P4 的结构性防线 |
| 公告命中 | `receipt.advisory_lifecycle_hits` | `advisory_lifecycle_hits` | 两边都是可选 | 两边都只用于"否定式声明"（E02 / C3），不参与判定 |

最后一行值得读两遍：**脚本一的命名空间里有托管凭据字段位，脚本二的清单件表头里没有。**这不是遗漏。清单件是从 Apple 侧导出的，它本来就没有这一格；如果脚本二给它一个凭据列，就是在邀请运维把绕过码抄进导出件。**结构上不给这个位置，比在文档里警告更可靠。**

---

## 19. 四级判定模型

判定模型只回答一个问题：**"这台设备归谁、上一位的数据还能不能被读到"这两句话，现在有什么支撑。**它不回答"这台设备安全吗"——第 2.1 节第 4 条已声明这一点，本章的条件把它变成可执行形式。

| 级 | 名称 | 含义 | 允许对外表述 |
| --- | --- | --- | --- |
| **J1** | 可自证 | 归属与清除都能引用一份 V1 或 V2 读数 + 一份执行回执 | "这台设备现在归 X 组织，上一位的数据按密钥遗留面已不可得，证据是 A 与 B。" |
| **J2** | 部分可证 | 有一半能引用，另一半依赖服务端自选归档 | "归属可证；清除只有下发记录，没有回执。" |
| **J3** | 无动作待证 | 这一格上没有任何归属动作发生，因此也无需证据 | "这台设备未纳入归属管理，本表对它不作结论。" |
| **J4** | 不可自证 | 判定所需的格在可读面上不存在，或存在但口径互相打脸 | "现在没有任何公开读数能证明这一点，需要补采集。" |

### 19.1 脚本一的判定式（逐条对应）

以下是脚本一实际实现的条件，本篇**不写比脚本更乐观的模型**。用第 21 章的字段名表述：

```
v4 = receipt.channel=accessory          # L10：这一格根本不在 iOS 命令面
   ∨ receipt.vocabulary=unset           # 词表未声明：读数不可解释
   ∨ enroll.method 缺失或不在词表         # 通道未知
   ∨ receipt.lock=unavailable           # 锁定证据面不可得
   ∨ receipt.erase=unavailable          # 抹除证据面不可得
   ∨ receipt.ownership=none             # 没有任何一侧声称发布读数
   → J4

j3 = owner.activation_lock_state=Off ∧ erase.command_sent≠true
     ∧ lock.managed_lost_mode≠true ∧ owner.assignment_state≠assigned
   → J3（该设备上没有任何待证的归属动作）

否则进入四条件：
  p1 = enroll.profile_installed ∧ enroll.token_update_seen
       ∧ owner.activation_lock_state ∈ {On(User), On(Organization)}
       # 命令通道存在，且归属锁有明确发布方读数
  p2 = erase.acknowledged=true ∧ erase.mode ∈ 词表 ∧ erase.ack_at 非空
       # 清除有回执、有模式、可对时
  p3 = 若设备受监督 → lock.escrow_state ∈ {escrowed, not_required}
       # 托管关系要么已声明、要么明确不适用；不接受"不知道"
  p4 = 若 device.class=mac → transfer.bootstrap_token_available=true
       # Mac 的抹除与保留式复用都依赖它（第 368、43 行）
  若 activation_lock_state 以 On 开头 且（已发送抹除但 p2 不成立，或从未发送）→ J2
  若 p1 ∧ p2 ∧ p3 ∧ p4 → J1，否则 J2
```

四点必须讲清楚，否则这张表会被读成"过四关就安全"：

**(a) J1 里没有出现"数据不可读"这一条正面证据。**它出现的形式是 `p2`（抹除有回执、带模式、可对时）加上第 9.5 节的字段声明。**"已清"在这套文档里的定义是"密钥不可得"**（第 1973、4585 行），而"不可得"的证据只有抹除回执与托管关系状态；本篇不敢把它写成更强的东西。

**(b) `p1` 要求激活锁读数存在，看起来与"已解除锁定"矛盾。**实际含义是：**J1 要求的是"谁在锁这台设备"这句话有 V2 级读数**，而不是"这台设备无锁"。一个 `Off` 的读数同样进入 `j3` 分支。原因在 F2：清单的三值与平台安全指南的两值叙述之间没有映射，**"没有读数"与"读数为 Off"在本层是两件不同的事**。

**(c) `p3` 把"unknown"排除在 J1 之外，这是刻意的。**第 26 章 G5 说托管材料的作废在文档里没有句子；本篇不能因为文档没写就给一个正面结论，于是把 `unknown` 留在 J1 门槛之外——**它让"我们不知道"在台账里表现为降级，而不是表现为空白**。

**(d) `p4` 是 Mac 独有的耦合。**第 7.8 节说明 Mac 的"能不能启动"与"属于谁"绑在同一组策略件上（LocalPolicy / 激活证书），Mac 的归属检查必然触及启动完整性面，因此引导令牌成为 Mac 分支的必要条件，而 iOS 分支不要求（`dcls=="mac"` 条件）。

### 19.2 三个跨条件的规则

**规则 A · 凭据入库直接判 J4，无条件。**`lock.bypass_code_recorded=true` 触发 L05，属阻断集（退出码 1）。本篇的处理是"要求删除该字段"，而**不是**"删掉后重新判级"——因为一旦凭据进过台账，这一格里所有其它读数的可信度都被污染（谁能保证抄凭据的人没同时改状态？）。脚本一在这里给 J4 是判定式的实现选择，正文本篇把它写成流程要求：**凭据类字段的正确形态是存在性与失效口径，永远不是值。**

**规则 B · 断言"某 CVE 影响激活锁 / 抹除"一律 J4。**依据是 R10 + R13 + F1。这类断言的判定所需那一格在两侧都无读数，脚本一对此报 E02（拿命中数声称覆盖却无对齐表）或 B03（命中为 `none` / 未填，不计入退出码）。

**规则 C · V4 一律 J4，禁止"待观察"。**第 17 章规则四。脚本一对应的实现是 `receipt.lock` / `receipt.erase` / `receipt.ownership` 三个 `observable / unavailable / unknown` 字段：**`unavailable` 直接落 J4；`unknown` 不落 J4，但因为它不在 `p` 条件的允许集合里，最高只能 J2。** 这两级差别是有意设计的——"我确定这一格没有读数"与"我知道得不够"是不同的结论。

### 19.3 判定与责任的配对

一个 J 级要落笔，得说清"这个结论归谁"。本篇规定判定行必须与一个责任方同现：

| 判定 | 谁有权写下这一行 | 谁必须复核 | 记录在哪 |
| --- | --- | --- | --- |
| J1 | 组织清单管理员（持有 V1 一侧） | 管理服务（回执与状态归档方） | 台账 + 清单导出件 |
| J2 | 管理服务管理员 | 组织（决定是否接受残留风险） | 台账 + 服务端日志 |
| J3 | 任一 | 任一（无动作即无争议） | 台账 |
| J4 | **只有组织可以声明**，且必须同时写补采集计划 | 资产负责人 | 台账 + 第 26 章边界编号 |

最后一行的重点是 J4 不许由工具自动产生后无人认领。脚本一会给 J4，**但它给不出补采集计划**——那必须是人的决定。第 20 章 O8（J4 存留时长）就是为这一格设的度量。

---

## 20. 运营指标 O1—O10

十个指标，全部可以从本轮两个脚本的输出直接算出，或从台账字段直接算出。**每个指标都注明它的失败方向**——一个不知道往哪边算坏的指标不能作为验收依据。

| # | 指标 | 定义 | 数据来源 | 失败方向 | 对应缺陷型 |
| --- | --- | --- | --- | --- | --- |
| O1 | 主键覆盖 | 有合法序列号形态的台账行数 / 总行数 | 脚本一 A01；脚本二 S3 | 低 → 差集算不出 | P1 |
| O2 | 归属自证率 | J1 设备数 / 全部设备数 | 脚本一判定行 | 低 → 依赖口头声明 | P3 P6 P8 |
| O3 | 回执齐备率 | `erase.acknowledged=true` 且带 `ack_at` 与 `mode` / 已发送抹除数 | K01 K02 / S2 T2 | 低 → 处置单不可信 | P6 |
| O4 | 凭据存在性登记率 | 受监督设备里 `lock.escrow_state` 有值的比例 | L03 L04 | 低 → 迁移时才发现取不回 | P5 |
| O5 | 复用轮次身份残留 | `transfer.preserve_apps=true` 的抹除次数 / 总抹除次数 | K05 | **高 → 差**（带走数据同时留下托管身份，第 9.6 节） | P7 P9 |
| O6 | 通道一致性 | 台账 `enroll.method` 与清单来源可对账的比例 | C01 C02 | 低 → 规划的动作不存在 | P2 |
| O7 | 移交落款完备率 | `released` 行里同时有日期与主体的比例 | A02 / N4 N8 | 低 → 无人批准易主 | P10 |
| O8 | J4 存留时长 | 每台 J4 设备从首次判定到关闭的天数 | 台账时间戳 | **高 → 差**（V4 长期无人认领） | P5 P12 |
| O9 | 窗口留档率 | 有 `command_held_until` / `migration_window_days` 的记录比例 | M05 M01 / T4 | 低 → 时序解释不了 | P11 |
| O10 | 人员绑定可核对率 | 能落到清单或台账人员字段的比例 | 脚本一不设人员字段；脚本二 N1 | 低 → 归属只有设备侧 | P10 |

三点关于这套指标的设计决定：

**（1）O5 与 O8 是"高即差"的例外，本篇显式标注。**绝大多数指标是"高 = 好"；O5 高意味着大量复用走"保留应用"这条路（第 60 行的退出路径是"取消注册但不移除受管应用"），O8 高意味着 V4 那一格长期没人认领。不标方向会让仪表盘把坏消息显示成好消息。

**（2）O4 与 O10 是本轮故意给不出好值的两个。**O4 的分母（受监督设备数）本身靠界面文案判定（第 371—375 行），因此本篇只把 O4 当作**台账登记率**，绝不当作"凭据健康状况"——第 4 个字母就是它的天花板。O10 更直接：本轮 Roster API 只在 Apple School Manager 可用（《Roster management》第 5—6 行），Apple Business 组织没有对应结构化面，人员绑定只能落自己台账。**一个指标的上限由文档决定时，要在表里写清楚，否则它会被读成"我们做得不够好"。**

**（3）这套指标里没有"漏洞修复率"。**第 09 篇有；本篇没有，因为 F1 已经说明归属状态不能与公告面换算。若组织的仪表盘把两个率放在同一页，请在页脚写明"第 09 篇 O3 与本表 O2 不是同一件事"，避免被读成"补丁装完了所以归属也清楚了"。

### 20.1 十项指标的最小可行采集

若一个组织只能做一件事，本篇的建议是：**先把清单导出件按季归档，并让它和台账在同一张表里按序列号对齐。**理由很实在：O1、O7、O10 与 J1 的 V1 一侧全都依赖这一份导出件，而它是本层唯一由 Apple 维护、含时间含主体、还会记录"主体已消失"的产物（第 300—315 行）。**除此之外本篇在 239 件归档里没有找到第二个可替代物。**

---

## 21. 只读核验脚本一：设备归属与移交台账审查器

### 21.1 它做什么、不做什么

`device-ownership-ledger-review.sh` 读一份或多份"设备归属与移交台账"（三列文本，一行一条字段），按 Apple 公开文档的口径逐条预演：**这一格写成这样的时候，归属与清除还能不能被证明**。

它做的事只有四件：校验字段形态与词表、校验字段之间的合取关系、校验带时刻字段的先后顺序、给每台设备一个 J1—J4 判定。**它不判断设备实际状态**——它不读设备，也没有那个能力。

它明确不做的事，逐条列出来（每一条都对应正文某处的一个"不可判"）：

1. **不联网、不调用任何设备侧或 Apple 命令行工具**（不用 `softwareupdate` / `mdmclient` / `profiles` / Apple Configurator / Xcode / `curl`），不访问任何 Apple 服务端点。
2. **不修改输入文件。**唯一写出目标是 `mktemp -d` 建的临时目录，退出时删除。
3. **不含任何绕过激活锁的做法**，不提供绕过码或解锁凭据的获取、验证、使用步骤。第 4 章到第 7 章的语义在这里变成一条硬约束：**台账里出现凭据值的写法，脚本直接报警并要求删除该字段**（L05），而不是把它当成一个可以读写的普通列。
4. **不推断缺失事实。**`N/A`、空值、`unknown` 三种写法在脚本里是三种不同情况，它不会把它们合并成"没有"。
5. **不跨设备匹配。**没有合法序列号形态的行只能整行报错（S 类在脚本二、A01 在这里），不做模糊对应。

### 21.2 输入契约

行格式：`<设备标识>,<字段名>,<值>`。`#` 开头行与空行忽略，行尾 CR 忽略（Windows 导出的台账可直接喂）。值里允许含逗号——第 4 列及以后全部并回值，所以 `enroll.access_rights,AllowDeviceErase,AllowQuerySecurity` 是合法的。

七个命名空间共 63 个字段位，全部列在下面。**命名空间前缀之外的字段触发 U01**，这是本篇防止"随手加个列"污染口径的机制。

| 命名空间 | 字段 |
| --- | --- |
| `owner.` | `assignment_state` / `assignment_reviewed_at` / `org_activation_lock` / `user_activation_lock` / `activation_lock_state` / `released` / `source` / `identifier_authority` / `purchase_date` / `org_id` |
| `enroll.` | `method` / `supervised` / `profile_installed` / `token_update_seen` / `token_update_at` / `access_rights` / `checkout_sent` / `checkout_ack` / `logout_at` / `command_held_until` |
| `lock.` | `apple_account_kind` / `escrow_state` / `escrow_rollback` / `bypass_code_available` / `bypass_code_recorded` / `unlock_token_received` / `managed_lost_mode` / `user_lost_mode` / `lost_mode_exit` / `device_lock_sent` / `passcode_set` / `find_my` / `observed_at` |
| `erase.` | `command_sent` / `acknowledged` / `ack_at` / `mode` / `instant_wipe_claim` / `media_key_discarded` / `lost_mode_state_stored` |
| `transfer.` | `migration_started` / `migration_window_days` / `migrate_mode` / `is_multi_user` / `rts_enabled` / `rts_profile_data` / `wifi_profile_data` / `bootstrap_token_available` / `preserve_apps` / `old_checkout_ack` / `new_enroll_ack` |
| `receipt.` | `vocabulary` / `ownership` / `lock` / `erase` / `component_map` / `channel` / `advisory_lifecycle_hits` |
| `device.` | `model` / `serial` / `udid` / `class` / `supervised` / `os_version` / `snapshot_date` / `audit_date` / `timezone` |

**`lock.` 里没有"绕过码值"这一栏，`transfer.` 里没有"托管密钥值"这一栏。**第 18.4 节说过这个选择的理由：结构上不给位置，比在文档里警告更可靠。可用的是存在性与失效口径三件套：`escrow_state` / `bypass_code_available` / `escrow_rollback`，加一个换代事件日（写进 `owner.assignment_reviewed_at` 或 `lock.observed_at` 都可，本篇建议后者）。

主要词表（脚本 `BEGIN` 段实际写死的那些）：

| 字段 | 允许值 | 文档依据 |
| --- | --- | --- |
| `owner.assignment_state` | `assigned` `unassigned` `released` `deleted` | 《Assign, reassign, or unassign devices》第 310—312 行、《Release devices in Apple Business》第 279 行 |
| `owner.activation_lock_state` | `Off` `On(User)` `On(Organization)` `unknown` | 《Turn off Activation Lock in Apple Business》第 270—292 行 |
| `enroll.method` | `user` `device` `ade` `account-driven` | 《About Apple device supervision》第 346—359 行、《Device enrollment》 |
| `lock.escrow_state` | `escrowed` `not_escrowed` `not_required` `unknown` | 平台安全指南第 2000、2006 行 |
| `lock.escrow_rollback` | `available` `expired` `unknown` | 《Activation Lock on Apple devices》第 361—362、369—372 行 |
| `lock.lost_mode_exit` | `admin_disabled` `erased` `user_disabled` | 平台安全指南第 4572 行、《Disable Lost Mode》第 14 行 |
| `erase.mode` | `erase-all` `erase-all-keep-data` `preserve-installed-apps` | 《Erase Apple devices》第 345—378 行、《Returning a managed device to service》第 10、42—48 行 |
| `transfer.migrate_mode` | `return-to-service` `re-enroll` `in-place` | 《Migrating managed devices》第 7—8、22 行、《Returning a managed device to service》第 45—48 行 |
| `receipt.lock` / `receipt.erase` | `observable` `unavailable` `unknown` | 第 17 章 V1—V4 的操作化 |
| `receipt.channel` | `ios` `accessory` `visionos` `unknown` | 第 5.5 节（配件线不参与归属层） |
| `device.class` | `iphone` `ipad` `ipod` `watch` `mac` `appletv` `vision` | 平台安全指南第 4574 行的可抹平台列举 |
| `lock.apple_account_kind` | `user` `org` `unknown` | 《Activation Lock on Apple devices》第 346—348 行 |

### 21.3 51 个信号码

分组与阻断属性：

| 组 | 码 | 数量 | 计入退出码 | 主题 |
| --- | --- | --- | --- | --- |
| A | A01—A10 | 10 | 是 | L1 归属登记与标识 |
| C | C01—C06 | 6 | 是 | L2/L3 通道、监管与权限 |
| L | L01—L08 | 8 | 是 | L4/L5 锁定与托管凭据 |
| K | K01—K06 | 6 | 是 | L6 抹除与密钥遗留 |
| M | M01—M05 | 5 | 是 | L7/L8 账户与移交 |
| E | E01—E05 | 5 | 是 | 词表与读数口径 |
| U | U01—U02 | 2 | 是 | 行解析 |
| B | B01—B05 | 5 | **否** | 证据缺位（只声明，不阻断） |
| J | J1—J4 | 4 | 否 | 判定 |

**阻断集 = A / C / L / K / M / E / U，共 42 个码。**B 组的设计意图值得说明：B01（缺复核日）、B02（TokenUpdate 无时间戳）、B03（公告面命中为 `none` 或未填）、B04（配件线）、B05（`find_my=unknown` / `unlock_token_received=true` / `receipt.lock=unavailable`）都是**"这一格现在不可自证"而不是"这一格写错了"**。把它们计入退出码会让每一次核验都失败，从而让核验失去被执行的动机；把它们排除又会让读者以为可以忽略。折中办法是：**单独成组、单独打印、明确标注不计入退出码**，并在第 20 章 O2/O8 里作为分母使用。

逐条语义（条件按脚本实际写法复述，不做美化）：

**A 组** — A01 序列号缺失或形态非法；A02 指派状态缺失、出词表，或"已释放但 `owner.org_id` 空"；A03 已释放且 Check Out 已发而 `enroll.checkout_ack` 不为 `false`（两端归属声明并存）；A04 已释放但 `receipt.ownership` 仍记 `apple_business`；A05 声明组织激活锁已开启但指派状态是 `unassigned` / `released` / `deleted`；A06 三态读数与两栏开启声明不一致（三个方向各一条）；A07 指派复核比审计日早超过 90 天；A08 采购日晚于快照日，或复核日早于采购日；A09 序列号与 UDID 同时入册但未声明主键；A10 台账含带时刻的字段而没有 `device.timezone`。

**C 组** — C01 入册方式缺失或出词表；C02 `ade` 而 `enroll.supervised` 不为 `true`；C03 描述文件已装但没有 TokenUpdate；C04 动作已记录而对应访问权限缺失（抹除→`AllowDeviceErase`、托管丢失模式→`AllowLostMode`、锁定命令→`AllowPasscodeRemovalAndLock`，三条）；C05 权限含 `ClearPasscode` 且设备已设口令而抹除证据面未归档；C06 迁移或释放前未记录 Check Out。

**L 组** — L01 三态读数非法，或有两栏声明而无读数；L02 锁为 `On(...)` 而账户类型为 `unknown`；L03 受监管而未声明托管状态或取值出词表；L04 记 `escrowed` 而缺可否再取得 / 缺失效口径，或权限含 Device Lock 而未记 `unlock_token_received`（四条）；**L05 台账落了凭据值，拒收并要求删除该字段**；L06 两种丢失模式同时为真；L07 处于托管丢失模式而缺退出方式或取值出词表；L08 已发锁定命令但该设备 `passcode_set=false`。

**K 组** — K01 已发抹除而回执字段空；K02 回执为真而缺 `ack_at`；K03 丢失模式下发抹除但未预先存档状态，或存了但抹除证据面不可得（两个方向）；K04 声称即时抹除而未记介质密钥已丢弃；K05 Return to Service + 保留应用 + 模式写 `erase-all`（声明冲突）；K06 Mac 已发抹除而未记引导令牌可用性。

**M 组** — M01 迁移窗口缺失 / 非整数 / 超过 30 天；M02 迁移模式缺失、出词表、退回服务但非 ADE、退回服务但标记多用户（四条）；M03 退回服务但 MDM 与无线配置两项数据都未提供，或用于 Mac 而无引导令牌；M04 迁移两端都没有回执；M05 记了注销而未记命令不可用窗口。

**E 组 / U 组** — E01 词表口径缺失或非 `lockstate3`；E02 以公告命中正数声称覆盖而组件对齐表缺失；E03 枚举值出词表（七个字段各一条）**或同一字段两条不同值**；E04 版本形态、十个日期字段的 ISO 形态、`logout_at` 缺时区串；E05 审计日早于快照日 / 锁定读数早于快照日 / 抹除回执早于 TokenUpdate。U01 记录无法解析成三列，或字段前缀不在七个命名空间内；U02 缺设备标识。

### 21.4 CLI 合同与实跑

```
用法: device-ownership-ledger-review.sh [-q] 台账文件 [...]
  -q, -h  -q 只输出汇总；-h/--help 显示本帮助
```

本轮实跑（环境：GNU bash + Gawk，`LC_ALL=C`）：

| 调用 | 退出码 | 结果 |
| --- | --- | --- |
| `-h` | 0 | 打印用法 |
| 无参数 | 2 | 用法打到 stderr |
| 不存在的文件 | 2 | `输入不可读: <路径>` |
| 空文件 | **0** | 0 台设备、0 条信号（脚本一不做"非空"检查） |
| 缺陷样例（54 台） | 1 | 阻断类信号合计 240；判定分布 `J1=0 J2=9 J3=0 J4=45` |
| 可自证样例（4 台） | 0 | 阻断类信号 0；判定分布 `J1=2 J2=0 J3=2 J4=0`；仅 1 条 B03 |

两处口径要如实说明。**第一，脚本一对空文件返回 0**，因为它按行驱动，没有行就没有设备也就没有可阻断的东西——这对"台账导出失败但流程继续跑"的情形是危险的，使用时请在外层先判 `-s`。**脚本二相反**：空文件返回 2 并打印 `输入为空文件`。**这是两个脚本之间唯一一处行为不对称，本篇选择不统一**：台账审查器要能容忍"一台都没有"的合法业务状态（新组织、刚拆分的部门），而差集比对器在缺输入件时给出任何结论都是错的。

**第二，缺陷样例里 J4=45 而不是 J2=54。**原因是判定式的第一支：本轮的 `v4` 条件包含"词表未声明"（`receipt.vocabulary` 为空时取值 `unset`）与"入册方式缺失或非法"，而缺陷样例里有 44 台设备根本没写这两个字段。**这正是本篇想让人看到的结果形态：一份不做口径声明的台账，绝大多数行的正确结论是"不可自证"，不是"有问题"。** J2 只有 9 台，是因为那 9 台把通道与词表写了、却在动作与证据的合取上不合格。

判定式逐条解释在第 19.1 节；第 23 章给逐码触发表。

### 21.5 源码

```bash
#!/usr/bin/env bash
# device-ownership-ledger-review.sh —— 设备所有权与生命周期台账审查器（离线 / 只读 / 不联网 / 不碰设备）
# 输入：一份或多份台账文本，每行一条记录：  <设备标识>,<字段名>,<值>
# 输出：逐条信号码 + 每台设备的四级判定（J1—J4） + 汇总
# 信号码共 51 个：A01—A10 归属登记 / C01—C06 入册通道与命令权限 /
#                L01—L08 锁定与托管凭据 / K01—K06 抹除与密钥遗留 /
#                M01—M05 迁移与移交 / E01—E05 词表与读数口径 / U01—U02 解析 /
#                B01—B05 证据缺位（不计入退出码）/ J1—J4 判定
# 阻断集 = A / C / L / K / M / E / U；退出码 0=无阻断信号，1=有，2=输入不可用
# 本脚本只做归属判定与口径核对，不含任何绕过激活锁的做法：
# 台账里出现旁路码 / 解锁凭据的值会直接触发 L05 并要求删除该字段。
# 本脚本不联网、不调用任何设备侧或 Apple 命令行工具、不修改输入文件；
# 唯一写出目标是 mktemp -d 创建的临时目录，退出时删除。
set -u
LC_ALL=C; export LC_ALL

usage() {
  cat <<'EOF'
用法: device-ownership-ledger-review.sh [-q] 台账文件 [...]
  -q, -h  -q 只输出汇总；-h/--help 显示本帮助
台账行格式: <设备标识>,<字段名>,<值>    # 开头与空行忽略，行尾 CR 忽略
字段命名空间:
  owner.*     归属登记（assignment_state / assignment_reviewed_at / org_activation_lock /
              user_activation_lock / activation_lock_state / released / source /
              identifier_authority / purchase_date / org_id）
  enroll.*    入册通道与命令权限（method / supervised / profile_installed /
              token_update_seen / token_update_at / access_rights / checkout_sent /
              checkout_ack / logout_at / command_held_until）
  lock.*      锁定与托管凭据（activation_lock_state 见 owner.*；apple_account_kind /
              escrow_state / escrow_rollback / bypass_code_available /
              bypass_code_recorded / unlock_token_received / managed_lost_mode /
              user_lost_mode / lost_mode_exit / device_lock_sent / passcode_set /
              find_my / observed_at）
  erase.*     抹除与密钥遗留（command_sent / acknowledged / ack_at / mode /
              instant_wipe_claim / media_key_discarded / lost_mode_state_stored）
  transfer.*  迁移与移交（migration_started / migration_window_days / migrate_mode /
              is_multi_user / rts_enabled / rts_profile_data / wifi_profile_data /
              bootstrap_token_available / preserve_apps / old_checkout_ack / new_enroll_ack）
  receipt.*   证据与口径（vocabulary / ownership / lock / erase / component_map / channel /
              advisory_lifecycle_hits）
  device.*    台账自带的元字段（model / serial / udid / class / supervised / os_version /
              snapshot_date / audit_date / timezone）
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

TMPD=$(mktemp -d "${TMPDIR:-/tmp}/dolr.XXXXXX") || { echo "无法创建临时目录" >&2; exit 2; }
trap 'rm -rf "$TMPD"' EXIT INT TERM

awk -v QUIET="$QUIET" '
function emit(code, dev, msg) { cnt[code]++; lines[++nline] = sprintf("%s\t%s\t%s", code, (dev==""?"-":dev), msg) }
function DV(d, f,   k) { k = d SUBSEP f; return (k in valof) ? valof[k] : "" }
function istrue(v)  { return (v=="true"||v=="TRUE"||v=="1"||v=="yes") }
function isfalse(v) { return (v=="false"||v=="FALSE"||v=="0"||v=="no") }
function isint(v)   { return (v ~ /^-?[0-9]+$/) }
function isISOdt(v) { return (v ~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}([ T][0-9]{2}:[0-9]{2}(:[0-9]{2})?)?([Zz]|[+-][0-9]{2}:?[0-9]{2})?$/) }
function hasTZ(v)   { return (v ~ /[Zz]$/ || v ~ /[+-][0-9]{2}:?[0-9]{2}$/) }
function dayNum(v,  t) { t=v; gsub(/[-:TZ ]/,"",t); return substr(t,1,8)+0 }
function isSerial(v)  { return (v ~ /^[A-Za-z0-9]{8,14}$/) }
function isUdid(v)    { return (v ~ /^[0-9A-Fa-f]{40}$/ || v ~ /^[0-9A-Fa-f]{25}$/) }
function isVersion(v) { return (v ~ /^[0-9]+(\.[0-9]+){1,2}$/) }
function isOrg(v)     { return (v ~ /^[0-9A-Za-z.-]+$/) }
BEGIN {
  FS=","
  split("assigned unassigned released deleted", a1, " "); for (i in a1) AST[a1[i]]=1
  split("user device ade account-driven", a2, " ");         for (i in a2) METH[a2[i]]=1
  split("Off On(User) On(Organization) unknown", a3, " ");  for (i in a3) LST[a3[i]]=1
  split("escrowed not_escrowed not_required unknown", a4, " "); for (i in a4) ESCR[a4[i]]=1
  split("available expired unknown", a5, " ");              for (i in a5) ROLL[a5[i]]=1
  split("erase-all erase-all-keep-data preserve-installed-apps", a6, " "); for (i in a6) EMODE[a6[i]]=1
  split("return-to-service re-enroll in-place", a7, " ");    for (i in a7) MMODE[a7[i]]=1
  split("lockstate3", a8, " ");                              for (i in a8) VOC[a8[i]]=1
  split("iphone ipad ipod watch mac appletv vision", a9, " "); for (i in a9) CLASS[a9[i]]=1
  split("apple_business external_dms none", b1, " ");        for (i in b1) OWN[b1[i]]=1
  split("user org unknown", b2, " ");                        for (i in b2) ACCT[b2[i]]=1
  split("admin_disabled erased user_disabled", b3, " ");     for (i in b3) LEXIT[b3[i]]=1
  split("observable unavailable unknown", b4, " ");          for (i in b4) RSTATE[b4[i]]=1
  split("purchase_record manual inherited unknown", b5, " "); for (i in b5) SRC[b5[i]]=1
  split("ios accessory visionos unknown", b6, " ");          for (i in b6) CHAN[b6[i]]=1
  DTF="device.snapshot_date device.audit_date owner.assignment_reviewed_at owner.purchase_date enroll.token_update_at enroll.logout_at enroll.command_held_until erase.ack_at lock.observed_at transfer.migration_started"
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
  k = dev SUBSEP fld
  if ((k in valof) && valof[k] != val) emit("E03", dev, "同一字段两条不同值: " fld " = [" valof[k] "] 与 [" val "]")
  valof[k]=val
  if (fld !~ /^(owner|enroll|lock|erase|transfer|receipt|device)\./) emit("U01", dev, "字段名前缀不在本轮口径的命名空间内: " fld)
}
END {
  for (i=1; i<=nd; i++) {
    d = ord[i]
    ser   = DV(d,"device.serial");      udid = DV(d,"device.udid")
    model = DV(d,"device.model");       dcls = DV(d,"device.class")
    sup   = DV(d,"device.supervised");  osv  = DV(d,"device.os_version")
    snap  = DV(d,"device.snapshot_date");  aud = DV(d,"device.audit_date")
    tzn   = DV(d,"device.timezone")
    astate = DV(d,"owner.assignment_state");  rev  = DV(d,"owner.assignment_reviewed_at")
    orgAL  = DV(d,"owner.org_activation_lock"); usrAL = DV(d,"owner.user_activation_lock")
    alst   = DV(d,"owner.activation_lock_state");    osrc   = DV(d,"owner.source");  idauth = DV(d,"owner.identifier_authority")
    pur    = DV(d,"owner.purchase_date");  orgid = DV(d,"owner.org_id")
    meth   = DV(d,"enroll.method");  esup = DV(d,"enroll.supervised")
    prof   = DV(d,"enroll.profile_installed");  tok = DV(d,"enroll.token_update_seen")
    tuat   = DV(d,"enroll.token_update_at");    ar = DV(d,"enroll.access_rights")
    chks   = DV(d,"enroll.checkout_sent");  chka = DV(d,"enroll.checkout_ack")
    logout = DV(d,"enroll.logout_at");  held = DV(d,"enroll.command_held_until")
    acctk  = DV(d,"lock.apple_account_kind");  esct = DV(d,"lock.escrow_state")
    escrb  = DV(d,"lock.escrow_rollback");  bcode = DV(d,"lock.bypass_code_available")
    bcrec  = DV(d,"lock.bypass_code_recorded");  utk = DV(d,"lock.unlock_token_received")
    mlm    = DV(d,"lock.managed_lost_mode");  ulm = DV(d,"lock.user_lost_mode")
    lx     = DV(d,"lock.lost_mode_exit");  dls = DV(d,"lock.device_lock_sent")
    pset   = DV(d,"lock.passcode_set");  fmy = DV(d,"lock.find_my")
    lobsv  = DV(d,"lock.observed_at")
    esent  = DV(d,"erase.command_sent");  eack = DV(d,"erase.acknowledged")
    eackat = DV(d,"erase.ack_at");        emode = DV(d,"erase.mode")
    inst   = DV(d,"erase.instant_wipe_claim");  mkey = DV(d,"erase.media_key_discarded")
    lms    = DV(d,"erase.lost_mode_state_stored")
    mstart = DV(d,"transfer.migration_started");  mwin = DV(d,"transfer.migration_window_days")
    mmode  = DV(d,"transfer.migrate_mode");  multi = DV(d,"transfer.is_multi_user")
    rtse   = DV(d,"transfer.rts_enabled");  rtsp = DV(d,"transfer.rts_profile_data")
    rtsw   = DV(d,"transfer.wifi_profile_data");  boot = DV(d,"transfer.bootstrap_token_available")
    pres   = DV(d,"transfer.preserve_apps")
    oack   = DV(d,"transfer.old_checkout_ack");  nack = DV(d,"transfer.new_enroll_ack")
    voc    = DV(d,"receipt.vocabulary");  rown = DV(d,"receipt.ownership")
    rl     = DV(d,"receipt.lock");  re = DV(d,"receipt.erase")
    cmap   = DV(d,"receipt.component_map");  chan = DV(d,"receipt.channel")
    adv    = DV(d,"receipt.advisory_lifecycle_hits")

    # ---- A 归属登记 ----
    if (ser=="") emit("A01", d, "无序列号：归属登记的长期主键缺失，释放与指派只能按临时标识对账")
    else if (!isSerial(ser)) emit("A01", d, "序列号形态非法 [" ser "]：与机型清单逐条比对时不可用")
    if (astate=="") emit("A02", d, "未记录指派状态：这台设备属于谁、归谁管不可判定")
    else if (!(astate in AST)) emit("A02", d, "owner.assignment_state [" astate "] 不在 assigned/unassigned/released/deleted 词表内")
    if (astate=="released" && DV(d,"owner.org_id")=="") emit("A02", d, "标记已释放但 org_id 空：记录将留在库存里且无法确定释放主体")
    if (astate=="released" && (chks=="true" || oack=="true") && chka!="false") emit("A03", d, "已释放且 Check Out 已发：旧服务解绑凭据仍非 false，两端归属声明并存")
    if (astate=="released" && rown=="apple_business") emit("A04", d, "设备已释放但激活锁发布方仍记为 apple_business：释放后该服务不再能管理激活锁")
    if (orgAL=="on" && (astate=="unassigned" || astate=="released" || astate=="deleted")) emit("A05", d, "声明组织激活锁已开启，但指派状态是 " astate "：开启前置条件不成立")
    if (alst=="On(User)" && usrAL!="on") emit("A06", d, "读数 On(User) 而 owner.user_activation_lock 不为 on：两栏指向不同主体")
    else if (alst=="On(Organization)" && orgAL!="on") emit("A06", d, "读数 On(Organization) 而 owner.org_activation_lock 不为 on：两栏指向不同主体")
    else if (alst=="Off" && (usrAL=="on" || orgAL=="on")) emit("A06", d, "读数为 Off 但仍有开启声明：三态表里的 Off 只对应未配置设备")
    if (rev!="" && aud!="" && dayNum(aud)-dayNum(rev) > 90) emit("A07", d, "指派复核比审计日早 " (dayNum(aud)-dayNum(rev)) " 天：归属名单过期")
    if (rev=="") emit("B01", d, "缺指派复核日期：移交与释放事件事后无法自证")
    if (pur!="" && snap!="" && dayNum(pur) > dayNum(snap)) emit("A08", d, "采购日晚于快照日 [" pur " / " snap "]：台账至少一侧时间口径错")
    else if (pur!="" && rev!="" && dayNum(rev) < dayNum(pur)) emit("A08", d, "指派复核早于采购日：这台设备还没有归属依据")
    if (ser!="" && udid!="" && idauth=="") emit("A09", d, "序列号与 UDID 同时入册但未声明主键（owner.identifier_authority）：迁移回执可能对不上")
    if (tzn=="" && (logout!="" || lobsv!="" || eackat!="")) emit("A10", d, "台账含带时刻的字段但没有 device.timezone：跨时区比对无法定序")

    # ---- C 入册通道与命令权限 ----
    if (meth=="") emit("C01", d, "未记录入册方式：无法确定归属通道与可用命令面")
    else if (!(meth in METH)) emit("C01", d, "enroll.method [" meth "] 不在 user/device/ade/account-driven 词表内")
    if (meth=="ade" && !istrue(esup)) emit("C02", d, "自动入册台账的 enroll.supervised 不为 true：按文档口径自动入册会同时开启监管")
    if (istrue(prof) && !istrue(tok)) emit("C03", d, "描述文件已装但没有 TokenUpdate：命令通道未建立，锁定与抹除只能记为已下发")
    if (istrue(tok) && tuat=="") emit("B02", d, "TokenUpdate 已收到但没有时间戳：命令通道建立时刻不可得")
    if (esent=="true" && !(ar ~ /AllowDeviceErase/)) emit("C04", d, "台账记录了抹除命令但访问权限里没有 AllowDeviceErase")
    if (mlm=="true" && !(ar ~ /AllowLostMode/)) emit("C04", d, "台账记录了托管丢失模式但访问权限里没有 AllowLostMode")
    if (dls=="true" && !(ar ~ /AllowPasscodeRemovalAndLock/)) emit("C04", d, "台账记录了设备锁定命令但访问权限里没有 AllowPasscodeRemovalAndLock")
    if (ar ~ /ClearPasscode/ && DV(d,"lock.passcode_set")=="true" && re=="") emit("C05", d, "权限含 ClearPasscode 且抹除证据未归档：该命令会关闭数据保护，只能作为恢复措施而非日常手段")
    if ((istrue(mstart) || astate=="released") && chks!="true") emit("C06", d, "迁移或释放前未记录 Check Out：旧服务的解绑凭据不可得（Check Out 本身是尽力而为，不可得时应显式记为不可得）")

    # ---- L 锁定与托管凭据 ----
    if (alst!="") {
      if (!(alst in LST)) emit("L01", d, "owner.activation_lock_state [" alst "] 不在 Off / On(User) / On(Organization) 三态表内")
    } else if (usrAL!="" || orgAL!="") emit("L01", d, "两栏开启声明都有但没有三态读数：无法记录这台设备的激活锁归属")
    if ((alst=="On(User)" || alst=="On(Organization)") && acctk=="unknown") emit("L02", d, "激活锁为 " alst " 但账户类型 unknown：由哪一侧关闭不可判定")
    if ((istrue(sup) || istrue(esup)) && esct=="") emit("L03", d, "监管设备未声明 lock.escrow_state：组织无法自证持有可用的恢复归属")
    if (esct!="" && !(esct in ESCR)) emit("L03", d, "lock.escrow_state [" esct "] 不在 escrowed/not_escrowed/not_required/unknown 词表内")
    if (esct=="escrowed" && bcode=="") emit("L04", d, "托管状态记为 escrowed 但没有 lock.bypass_code_available：只记录了托管、没记录可否再取得")
    if (esct=="escrowed" && escrb=="") emit("L04", d, "托管状态记为 escrowed 但没有 lock.escrow_rollback：托管凭据缺少失效或再取得口径")
    else if (escrb!="" && !(escrb in ROLL)) emit("L04", d, "lock.escrow_rollback [" escrb "] 不在 available/expired/unknown 词表内")
    if (ar ~ /DeviceLock/ && utk=="") emit("L04", d, "权限声明含 Device Lock 但 lock.unlock_token_received 空：该 token 等同设备主密码，必须记录收取状态")
    if (istrue(bcrec)) emit("L05", d, "台账里落了激活锁凭据值（lock.bypass_code_recorded=true）：本框架拒收，请删除该字段只保留存在性")
    if (mlm=="true" && ulm=="true") emit("L06", d, "托管丢失模式与用户丢失模式同时为真：三态表按发布方分列，两者不互斥说明读数来源不同")
    if (mlm=="true" && lx=="") emit("L07", d, "处于托管丢失模式但没有 lock.lost_mode_exit：退出该模式只有管理员关闭一条路径，缺字段即退出事件不可追")
    else if (lx!="" && !(lx in LEXIT)) emit("L07", d, "lock.lost_mode_exit [" lx "] 不在 admin_disabled/erased/user_disabled 词表内")
    if (dls=="true" && pset=="false") emit("L08", d, "已发设备锁定命令但该设备 passcode_set=false：没有密码时锁屏提示语不会显示，命令效果与台账预期不同")

    # ---- K 抹除与密钥遗留 ----
    if (esent=="true" && eack=="") emit("K01", d, "抹除命令已发但 erase.acknowledged 空：该命令不告警、不重试，回执未留档即无法证明生效")
    if (eack=="true" && eackat=="") emit("K02", d, "抹除回执存在但没有 ack_at：回执不可对时，无法与快照或复核日排序")
    if (mlm=="true" && esent=="true" && lms!="true") emit("K03", d, "托管丢失模式下发抹除但未预先存档丢失模式状态：抹除会同时关闭该模式，重新入册后无从恢复")
    else if (lms=="true" && re=="unavailable") emit("K03", d, "记录了丢失模式状态存档但抹除证据面不可得：存档动作本身无法自证")
    if (inst=="true" && !istrue(mkey)) emit("K04", d, "台账声称即时抹除但没有 erase.media_key_discarded：即时生效依赖丢弃介质密钥，不是回执")
    if (rtse=="true" && istrue(pres) && emode=="erase-all") emit("K05", d, "ReturnToService 与 preserve_apps=true 同时存在但抹除模式为 erase-all：前者只保留 app 可执行数据，两者声明冲突")
    if (dcls=="mac" && esent=="true" && !istrue(boot)) emit("K06", d, "Apple silicon 计算机的远程抹除需要设备管理服务提供的引导令牌，台账 transfer.bootstrap_token_available 不为 true")

    # ---- M 迁移与移交 ----
    if (istrue(mstart)) {
      if (mwin=="") emit("M01", d, "迁移已启动但没有 migration_window_days：30 天临时窗口无法核对（文档口径为暂定窗口）")
      else if (!isint(mwin)) emit("M01", d, "migration_window_days 不是整数: [" mwin "]")
      else if (mwin+0 > 30) emit("M01", d, "migration_window_days = " mwin " 超出 30 天临时窗口")
      if (mmode=="") emit("M02", d, "迁移已启动但没有 migrate_mode：无法判断走退回服务、重新入册还是原地迁移")
      else if (!(mmode in MMODE)) emit("M02", d, "transfer.migrate_mode [" mmode "] 不在 return-to-service/re-enroll/in-place 词表内")
      else if (mmode=="return-to-service" && meth!="ade") emit("M02", d, "migrate_mode=return-to-service 但 enroll.method 不是 ade：退回服务只对自动入册设备成立")
      else if (mmode=="return-to-service" && multi!="false") emit("M02", d, "退回服务标记了多用户形态：该模式要求单用户设备")
      if (rtse=="true" && rtsp!="true" && rtsw!="true") emit("M03", d, "transfer.rts_enabled=true 但 MDM 与无线配置两项数据都未提供：ReturnToService 键不完整")
      if (rtse=="true" && dcls=="mac" && !istrue(boot)) emit("M03", d, "ReturnToService 用于计算机但未记录引导令牌可用性")
      if (nack!="true" && oack!="true") emit("M04", d, "迁移两端都没有回执（new_enroll_ack / old_checkout_ack）：归属交接没有任何一侧可证")
    }
    if (logout!="" && held=="") emit("M05", d, "记录了注销用户但没有 enroll.command_held_until：注销后最多 2 分钟内 MDM 命令不可用，窗口必须留档")

    # ---- E 词表与读数口径 ----
    if (voc=="") emit("E01", d, "未声明词表口径（receipt.vocabulary 缺失）：激活锁三态与丢失模式发布方都按词表判定")
    else if (!(voc in VOC)) emit("E01", d, "receipt.vocabulary [" voc "] 未知，本轮只有 lockstate3 口径")
    if (adv ~ /^[0-9]+$/ && adv+0 > 0 && cmap!="present") emit("E02", d, "以公告面生命周期命中数 " adv " 声称覆盖，但组件对齐表缺失：命中无法映射到本层归属")
    if (dcls!="" && !(dcls in CLASS)) emit("E03", d, "device.class [" dcls "] 不在本轮机型类别词表内")
    if (rown!="" && !(rown in OWN)) emit("E03", d, "receipt.ownership [" rown "] 不在 apple_business/external_dms/none 词表内")
    if (rl!="" && !(rl in RSTATE)) emit("E03", d, "receipt.lock [" rl "] 不在 observable/unavailable/unknown 词表内")
    if (re!="" && !(re in RSTATE)) emit("E03", d, "receipt.erase [" re "] 不在 observable/unavailable/unknown 词表内")
    if (osrc!="" && !(osrc in SRC)) emit("E03", d, "owner.source [" osrc "] 不在 purchase_record/manual/inherited/unknown 词表内")
    if (chan!="" && !(chan in CHAN)) emit("E03", d, "receipt.channel [" chan "] 不在 ios/accessory/visionos/unknown 词表内")
    if (acctk!="" && !(acctk in ACCT)) emit("E03", d, "lock.apple_account_kind [" acctk "] 不在 user/org/unknown 词表内")
    if (emode!="" && !(emode in EMODE)) emit("E03", d, "erase.mode [" emode "] 不在本轮抹除模式词表内")
    if (osv!="" && !isVersion(osv)) emit("E04", d, "device.os_version 形态非法: [" osv "]")
    split(DTF, dts, " ")
    for (j = 1; j <= 10; j++) { v = DV(d, dts[j]); if (v!="" && !isISOdt(v)) emit("E04", d, dts[j] " 不是 ISO 8601 形态: [" v "]") }
    if (logout!="" && !hasTZ(logout)) emit("E04", d, "enroll.logout_at 无时区串: [" logout "]（注销后命令窗口按时刻判定）")
    if (snap!="" && aud!="" && dayNum(aud) < dayNum(snap)) emit("E05", d, "审计日早于快照日：两份读数至少一份的采集口径错")
    if (lobsv!="" && snap!="" && dayNum(lobsv) < dayNum(snap)) emit("E05", d, "锁定读数早于快照日：归属读数的采集顺序不可信")
    if (eackat!="" && tuat!="" && istrue(prof) && dayNum(eackat) < dayNum(tuat)) emit("E05", d, "抹除回执早于 TokenUpdate：命令通道建立之前不可能有回执")

    # ---- B 证据缺位（不计入退出码）----
    if (adv=="none") emit("B03", d, "公开公告词表在本层零命中：归属与移交覆盖不能由缺陷条目数推断")
    else if (adv=="") emit("B03", d, "台账未填公告面生命周期命中数：无法确认该缺陷在公告面存在")
    if (chan=="accessory") emit("B04", d, "该资产不在 iOS 生命周期命令通道上（配件 / 固件线）")
    if (fmy=="unknown") emit("B05", d, "查找读数为 unknown：用户侧与组织侧锁定来源不可分型")
    if (istrue(utk)) emit("B05", d, "台账标注 UnlockToken 已收取：该值等同设备主密码，只应记录存在性，不应记录内容")
    if (rl=="unavailable") emit("B05", d, "锁定证据面不可得：本轮只能给出不可自证判定")

    # ---- 四级判定 ----
    lvl=""
    v4 = (chan=="accessory" || voc=="unset" || meth=="" || !(meth in METH) || rl=="unavailable" || re=="unavailable" || rown=="none")
    if (v4) lvl="J4"
    else if (alst=="Off" && esent!="true" && mlm!="true" && astate!="assigned") lvl="J3"
    else {
      p1 = istrue(prof) && istrue(tok) && (alst=="On(User)" || alst=="On(Organization)")
      p2 = (eack=="true" && (emode in EMODE) && eackat!="")
      p3 = ((istrue(sup) || istrue(esup)) ? (esct=="escrowed" || esct=="not_required") : 1)
      p4 = (dcls=="mac" ? istrue(boot) : 1)
      if (alst ~ /^On/ && ((esent=="true" && !p2) || esent=="")) lvl="J2"
      else if (p1 && p2 && p3 && p4) lvl="J1"
      else lvl="J2"
    }
    J[lvl]++
    emit(lvl, d, "判定 " lvl " (lockstate=" (alst==""?"-":alst) ", assign=" (astate==""?"-":astate) ", erase_ack=" (eack==""?"-":eack) ")")
  }
  if (!QUIET) for (i=1; i<=nline; i++) print lines[i]
  print ""
  print "==== 汇总 ===="
  printf "设备数=%d\n", nd
  split("A01 A02 A03 A04 A05 A06 A07 A08 A09 A10 " \
        "C01 C02 C03 C04 C05 C06 " \
        "L01 L02 L03 L04 L05 L06 L07 L08 " \
        "K01 K02 K03 K04 K05 K06 " \
        "M01 M02 M03 M04 M05 " \
        "E01 E02 E03 E04 E05 " \
        "U01 U02 " \
        "B01 B02 B03 B04 B05 " \
        "J1 J2 J3 J4", cc, " ")
  bad=0
  for (j = 1; j <= 51; j++) { c=cc[j]; n=cnt[c]+0
    printf "%-4s %3d\n", c, n
    if (c ~ /^[ACLKMEU]/) bad+=n
  }
  printf "判定分布: J1=%d J2=%d J3=%d J4=%d\n", J["J1"], J["J2"], J["J3"], J["J4"]
  printf "阻断类信号(A/C/L/K/M/E/U)合计=%d\n", bad
  exit (bad>0 ? 1 : 0)
}
' "$@" > "$TMPD/out.txt"
rc=$?
cat "$TMPD/out.txt"
exit $rc
```

---

## 22. 只读核验脚本二：生命周期与移交记录差集比对器

### 22.1 它回答的问题

脚本一问"这一格能不能自证"，脚本二问另一件事：**这台设备上一次易主到底有没有走完、缺哪一步。**它的工作方式是把三种公开件当作三个独立记录面，做集合差与时序比对：

- **归属清单件**（`-e` 之外，位置参数）：对应 Apple Business / School Manager 的设备指派列表与释放记录。一行一台设备的当前状态。
- **活动记录件**（`-e`）：对应管理服务的生命周期事件流。一行一个事件。
- **命令回执件**（`-r`，可选）：对应命令—轮询—应答三元组。

三者**没有共同的所有者**，因此本篇不要求它们互相一致；脚本二只报告"对不上在哪一条、哪个方向"，不断言谁错。

安全边界与脚本一相同：不联网、不调用设备侧或 Apple 命令行工具、不修改输入文件、唯一写出目标是 `mktemp -d` 的临时目录并在退出时删除。**它不含任何绕过激活锁的做法**，也不判断设备状态。

### 22.2 输入契约

三份都是制表符分隔，脚本按**首行表头自动识别件种**（`FNR==1` 时按必需列的presence 分派）：

| 件种 | 必需列 | 可选列 | 识别条件 |
| --- | --- | --- | --- |
| 归属清单件 | `serial` `assignment_state` `activation_lock_state` `org_id` | `source_service` `released_date` `class` `component_map` `advisory_lifecycle_hits` | 四列齐 |
| 活动记录件 | `serial` `event` `event_date` | `detail` | 三列齐 |
| 命令回执件 | `serial` `command` `sent_date` | `acknowledged` `ack_date` `mode` | 三列齐 |

表头不匹配任何一件 → S1，且该件后续行不再按任何口径处理。`serial` 是唯一主键（第 18.3 节：Apple 侧只接受序列号做批量对账，上限一次 1024 个）。

活动词表 14 个：`enrolled` `assigned` `unassigned` `released` `checked_out` `disowned` `erased` `lost_mode_on` `lost_mode_off` `migrated` `migration_closed` `returned_to_service` `signed_out` `deleted_user`。
命令词表 10 个：`EraseDevice` `DeviceLock` `EnableLostMode` `DisableLostMode` `CheckOut` `LogOutUser` `DeleteUser` `InstallProfile` `ProfileRemove` `ClearPasscode`。

**注意词表里没有 `device_configured`。**第 11.5 节说明过原因：待配置态的结束在文档里由 `Device Configured` 命令表达，而本轮活动件口径不假设服务方把它单独记成一个事件；脚本二只核对退回服务的前提（T6），把 `Device Configured` / `NotNow` / `Idle` 三行留给第 18 章的人工读数面。**这是一个已知的覆盖缺口，写在第 23.3 节的"覆盖不到的清单"里，不假装它被覆盖。**

### 22.3 23 个信号码

| 组 | 码 | 触发条件（按脚本实际写法） | 方向 |
| --- | --- | --- | --- |
| N | N1 | 活动件或回执件里的序列号不在任何清单件里 | 活动 → 清单 |
| N | N2 | 清单记 `assigned` 而活动件里没有 `enrolled` 也没有 `assigned` | 清单 → 活动 |
| N | N3 | 清单记 `assigned` 但活动件里有 `released`；或清单记 `deleted` 而存在晚于最早活动的 `assigned` | 冲突 |
| N | N4 | 清单记 `released` 而 `released_date` 空；或有 `released` 状态而活动件既无 `released` 也无 `checked_out` | 落款缺失 |
| N | N5 | `On(Organization)` 而 `source_service` 空 | 组织侧锁无归属服务 |
| N | N6 | 同一序列号在清单里登记两个不同 `org_id` | 归属冲突 |
| N | N7 | `enrolled` 晚于 `released` 而清单仍记 `released` | 重新入册 vs 残留 |
| N | N8 | 清单 `released` 行数 ≠ 活动件 `released` 事件数 | 全局计数 |
| T | T1 | 释放早于入册 / 迁移结束早于开始 / 删除用户早于注销 / 放弃所有权早于释放 | 时序倒置 |
| T | T2 | `acknowledged=true` 而无 `ack_date`；或 `ack_date` 早于 `sent_date` | 回执不可对时 |
| T | T3 | `lost_mode_off` 晚于 `erased` | 两侧读数来源不同 |
| T | T4 | `migrated` → `migration_closed` 跨度 > 30 天 | 临时窗口 |
| T | T5 | `EraseDevice` 回执缺 `mode`；或回执件出现 `ClearPasscode` | 遗留面不可判 |
| T | T6 | `returned_to_service` 早于同序列号 `EraseDevice` 的 `sent_date` | 前提未发生 |
| S | S1—S5 | 表头缺必需列 / 同件序列号重复 / 序列号形态非法 / 除表头外无数据行 / 行级词表与日期形态违规 | 输入契约 |
| C | C1—C4 | 缺 `-e` 或 `-r`（整段不可算）/ ≥2 个组织号（拒算跨组织合并）/ 公告命中为 `0` 或 `none` / `class` 空或 `component_map ≠ present` | 结论模板 |

**阻断集 = S1—S5、N1、N2、T1、C1、C2，共 10 个码。**其余 13 个只打印不影响退出码。这个选择的理由与 B 组相同但侧重不同：N3—N8 与 T2—T6 多数指向"两份记录口径不同"而非"这份记录不可用"；本篇不希望因为一次计数不等（N8）就让整轮移交审计被判失败，但同时把**清单声明无活动支撑（N2）与活动无清单支撑（N1）留作阻断**——这两条是差集的全部意义所在。

三处值得单独说明的实现选择：

**（1）`ClearPasscode` 一进回执件就报 T5，与它有没有 `mode` 无关。**《Clear Passcode》与《Managing passcodes》第 16—17 行把这把命令定性为"会关闭数据保护"的恢复措施（还明写"Never send the ClearPasscodeCommand to a lost device"），本篇把它当作需要单独标注的动作；**脚本只报这一行存在，不解释怎么用它。**

**（2）`acknowledged` 列为空时，脚本二不产生任何信号。**第 12.2 节给过这句话的出处：《Erase Apple devices》第 380 行在描述 Mac 抹除降级时把"返回 Error 状态"与"不返回任何状态"写在同一句里当作可接受结果。因此"没有回执"本身不是脚本二可以断言的缺陷——**它连"不可判"都不说**，只把该行计入回执行数。真正要求留档的是脚本一的 K01。

**（3）跨组织时脚本二拒绝合并计算。**≥2 个 `org_id` 触发 C2 并明确"需按组织分别跑"。这不是省事，是判定正确性要求：第 11.7 节说明组织账号转移只改变"哪个组织能看见这台设备的清单"，跨组织做差集会把"看不见"读成"没有活动"。

### 22.4 CLI 合同与实跑

```
用法: lifecycle-transition-diff.sh [-q] [-e 活动记录件] [-r 命令回执件] 归属清单件 [...]
  -q   只输出汇总        -h 显示本帮助
```

本轮实跑：

| 调用 | 退出码 | 结果 |
| --- | --- | --- |
| `-h` | 0 | 打印用法 |
| 无参数 | 2 | 用法打到 stderr |
| 不存在的文件 | 2 | `输入不可读: <路径>` |
| 空文件 | 2 | `输入为空文件: <路径>` |
| 全量缺陷件（3 份清单 + 活动 + 回执） | 1 | 阻断类信号 29；读数行：清单唯一序列号 13、活动行 14（无归属记录 2）、回执行 6 |
| 缺 `-r` | 1 | 阻断类 25；C1 一条声明 T2/T5/T6 整段不可算；S5 由 9 降到 6（回执日期列不再被读） |
| 缺 `-e` | 1 | 阻断类 25；C1 一条声明 N3—N7 与 T1/T3/T4 整段不可算；读数行活动侧计 0 |
| 干净件（1 清单 + 活动 + 回执） | 0 | 全部 23 个码计数为 0；读数行：清单 4 / 活动 10（无归属 0）/ 回执 4 |

干净件那一轮值得贴出读数行，因为它是本篇对"移交走完了"能给的最强形式——**注意它没有说"安全"**：

```
读数	-	清单唯一序列号 4 个；活动行 10 条（其中无归属记录 0 条）；回执行 4 条
```

### 22.5 源码

```bash
#!/usr/bin/env bash
# lifecycle-transition-diff.sh —— 设备生命周期与移交差集比对器（离线 / 只读 / 不联网 / 不碰设备）
# 输入：若干份归属清单件（TSV），一份活动记录件（-e，TSV），可选一份命令回执件（-r，TSV）
# 输出：23 个信号码 + 汇总。退出码：0=无阻断类信号，1=有，2=输入不可用
#   N1—N8 清单与活动差集 / T1—T6 移交时序 / S1—S5 输入契约 / C1—C4 结论模板
# 阻断集 = S* / N1 / N2 / T1 / C1 / C2；本脚本不含任何绕过激活锁的做法，
# 只比对归属与移交记录之间能不能对上。
set -u
LC_ALL=C; export LC_ALL

usage() {
  cat <<'EOF'
用法: lifecycle-transition-diff.sh [-q] [-e 活动记录件] [-r 命令回执件] 归属清单件 [...]
  -q   只输出汇总        -h 显示本帮助
归属清单件：制表符分隔，首行表头需含 serial、assignment_state、activation_lock_state、org_id，
            另需 source_service、released_date、class、component_map、advisory_lifecycle_hits（可选）
活动记录件：制表符分隔，首行表头需含 serial、event、event_date，detail 可选；
            event 词表: enrolled assigned unassigned released checked_out disowned erased
                        lost_mode_on lost_mode_off migrated migration_closed
                        returned_to_service signed_out deleted_user
命令回执件：制表符分隔，首行表头需含 serial、command、sent_date，
            另需 acknowledged、ack_date、mode（可选）；
            command 词表: EraseDevice DeviceLock EnableLostMode DisableLostMode CheckOut
                          LogOutUser DeleteUser InstallProfile ProfileRemove ClearPasscode
本脚本不联网、不访问设备、不修改输入文件；临时件写在 mktemp -d 并在退出时删除。
EOF
}

QUIET=0; EVENTS=""; RECEIPTS=""
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    -q) QUIET=1; shift ;;
    -e) EVENTS="${2:-}"; shift 2 ;;
    -r) RECEIPTS="${2:-}"; shift 2 ;;
    -*) echo "未知选项: $1" >&2; usage >&2; exit 2 ;;
    *) break ;;
  esac
done
[ $# -ge 1 ] || { usage >&2; exit 2; }
for f in "$@"; do
  [ -f "$f" ] || { echo "输入不可读: $f" >&2; exit 2; }
  [ -s "$f" ] || { echo "输入为空文件: $f" >&2; exit 2; }
done
[ -z "$EVENTS" ]   || { [ -f "$EVENTS" ]   || { echo "输入不可读: $EVENTS"   >&2; exit 2; }; }
[ -z "$RECEIPTS" ] || { [ -f "$RECEIPTS" ] || { echo "输入不可读: $RECEIPTS" >&2; exit 2; }; }

TMPD=$(mktemp -d "${TMPDIR:-/tmp}/ltdf.XXXXXX") || { echo "无法创建临时目录" >&2; exit 2; }
trap 'rm -rf "$TMPD"' EXIT INT TERM

FILES=("$@")
[ -z "$EVENTS" ]   || FILES+=("$EVENTS")
[ -z "$RECEIPTS" ] || FILES+=("$RECEIPTS")

awk -v QUIET="$QUIET" -v EVFILE="$EVENTS" -v RCFILE="$RECEIPTS" '
function emit(code, obj, msg) { cnt[code]++; lines[++nline] = sprintf("%s\t%s\t%s", code, (obj==""?"-":obj), msg) }
function trim(s) { gsub(/^[ \t\r\n]+|[ \t\r\n]+$/, "", s); return s }
function lc(s) { return tolower(s) }
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
function isSerial(v) { return (v ~ /^[A-Za-z0-9]{8,14}$/) }
BEGIN {
  FS="\t"
  split("enrolled assigned unassigned released checked_out disowned erased lost_mode_on lost_mode_off migrated migration_closed returned_to_service signed_out deleted_user", ev, " ")
  for (i in ev) EVOK[ev[i]]=1
  split("EraseDevice DeviceLock EnableLostMode DisableLostMode CheckOut LogOutUser DeleteUser InstallProfile ProfileRemove ClearPasscode", cm, " ")
  for (i in cm) CMOK[cm[i]]=1
  split("assigned unassigned released deleted", astate, " ")
  for (i in astate) ASTOK[astate[i]]=1
  split("Off On(User) On(Organization) unknown", lst, " ")
  for (i in lst) LSTOK[lst[i]]=1
}
{ sub(/\r$/, "") }
FNR==1 {
  delete col
  for (i = 1; i <= NF; i++) col[lc(trim($i))] = i
  if (col["serial"] && col["assignment_state"] && col["activation_lock_state"] && col["org_id"]) ftype="inventory"
  else if (col["serial"] && col["event"] && col["event_date"]) ftype="events"
  else if (col["serial"] && col["command"] && col["sent_date"]) ftype="receipts"
  else {
    ftype="unknown"
    emit("S1", FILENAME, "表头缺必需列（清单需 serial/assignment_state/activation_lock_state/org_id；活动需 serial/event/event_date；回执需 serial/command/sent_date）: " substr($0,1,80))
  }
  nrow[FILENAME]=0; fileSeen[FILENAME]=1; fileType[FILENAME]=ftype
  if (ftype=="inventory") invSeen[FILENAME]=1
  next
}
# ---------------- 归属清单件 ----------------
ftype=="inventory" {
  nrow[FILENAME]++
  ser = trim($col["serial"]); ast = trim($col["assignment_state"])
  als = trim($col["activation_lock_state"]); oid = trim($col["org_id"])
  svc = (col["source_service"] ? trim($col["source_service"]) : "")
  rdt = (col["released_date"]  ? trim($col["released_date"])  : "")
  cls = (col["class"]          ? trim($col["class"])          : "")
  cmap= (col["component_map"]  ? trim($col["component_map"])  : "")
  adv = (col["advisory_lifecycle_hits"] ? trim($col["advisory_lifecycle_hits"]) : "")
  nInv++; invList[nInv]=ser
  if (ser=="") { emit("S5", FILENAME, "清单行的 serial 列为空，该行跳过"); next }
  if (!isSerial(ser)) { emit("S3", ser, "清单里的序列号形态非法（长度或字符集不符合机型清单可比对形态）"); next }
  if ((FILENAME SUBSEP ser) in perInv) emit("S2", ser, "同一清单文件里序列号重复出现")
  perInv[FILENAME SUBSEP ser]=1
  unionInv[ser]=1
  if (oid!="" && invOrgSeen[ser]!="" && invOrgSeen[ser]!=oid) emit("N6", ser, "同一序列号登记了两个不同组织号（" invOrgSeen[ser] " 与 " oid "）：归属冲突")
  if (oid!="") invOrgSeen[ser]=oid
  if (!(ast in ASTOK)) emit("S5", ser, "assignment_state [" ast "] 不在 assigned/unassigned/released/deleted 词表内")
  invState[ser]=ast
  if (!(als in LSTOK)) emit("S5", ser, "activation_lock_state [" als "] 不在 Off/On(User)/On(Organization)/unknown 词表内")
  invLock[ser]=als
  if (als=="On(Organization)" && svc=="") emit("N5", ser, "激活锁记为 On(Organization) 但 source_service 空：组织侧锁没有归属服务")
  if (ast=="released") { nRelInv++; if (rdt=="") emit("N4", ser, "标记已释放但没有 released_date：释放事件无时刻可追") }
  if (rdt!="" && dnum(rdt) < 0) emit("S5", ser, "released_date 不是 YYYY-MM-DD: [" rdt "]")
  if (cls=="") emit("C4", ser, "清单未标 class：跨机型类别的归属换算缺前置")
  if (cmap!="present") emit("C4", ser, "component_map=" (cmap==""?"空":cmap) "：生命周期读数到组件的映射不可得")
  if (adv=="0" || lc(adv)=="none") emit("C3", ser, "公告面生命周期命中为 [" adv "]：不得由缺陷条目数换算本层覆盖")
  next
}
# ---------------- 活动记录件 ----------------
ftype=="events" {
  nrow[FILENAME]++
  ser = trim($col["serial"]); e = trim($col["event"]); ed = trim($col["event_date"])
  if (NF < 3) { emit("S5", FILENAME, "活动件列数不足，该行跳过: " substr($0,1,60)); next }
  if (!isSerial(ser)) { emit("S3", ser, "活动件里的序列号形态非法: [" ser "]"); next }
  if (!(e in EVOK)) { emit("S5", ser, "event [" e "] 不在本轮活动词表内"); next }
  if (dnum(ed) < 0) { emit("S5", ser, "event_date 不是 YYYY-MM-DD: [" ed "]"); next }
  nEv++; evCount[e]++
  if (!(ser in unionInv)) { nGhost++; emit("N1", ser, "活动件里的这台设备不在任何归属清单里（" e " @ " ed "）：移交活动没有归属记录支撑") }
  evSeen[ser SUBSEP e]=1
  if (!(ser in evMin) || dnum(ed) < dnum(evMin[ser])) evMin[ser]=ed
  if (!(ser in evMax) || dnum(ed) > dnum(evMax[ser])) evMax[ser]=ed
  evDate[ser SUBSEP e]=ed
  if (e=="released") nRelEv++
  next
}
# ---------------- 命令回执件 ----------------
ftype=="receipts" {
  nrow[FILENAME]++
  ser = trim($col["serial"]); c = trim($col["command"]); sd = trim($col["sent_date"])
  ack = (col["acknowledged"] ? trim($col["acknowledged"]) : "")
  akt = (col["ack_date"]     ? trim($col["ack_date"])     : "")
  md  = (col["mode"]         ? trim($col["mode"])         : "")
  if (NF < 3) { emit("S5", FILENAME, "回执件列数不足，该行跳过: " substr($0,1,60)); next }
  if (!isSerial(ser)) { emit("S3", ser, "回执件里的序列号形态非法: [" ser "]"); next }
  if (!(c in CMOK)) { emit("S5", ser, "command [" c "] 不在本轮命令词表内"); next }
  if (dnum(sd) < 0) { emit("S5", ser, "sent_date 不是 YYYY-MM-DD: [" sd "]"); next }
  nRc++; rcCount[c]++
  if (!(ser in unionInv)) emit("N1", ser, "回执件里的这台设备不在任何归属清单里（" c " @ " sd "）：命令打到了无归属记录的设备")
  rcSent[ser SUBSEP c]=sd
  if (akt!="" && dnum(akt) < 0) emit("S5", ser, "ack_date 不是 YYYY-MM-DD: [" akt "]")
  if (ack=="true" && akt=="") emit("T2", ser, c " 的回执标 true 但没有 ack_date：回执不可对时，无法参与时序比对")
  if (akt!="" && dnum(akt) < dnum(sd)) emit("T2", ser, c " 的 ack_date (" akt ") 早于 sent_date (" sd ")：回执比命令先到，两份记录至少一侧时刻口径错")
  if (c=="EraseDevice" && md=="") emit("T5", ser, "EraseDevice 回执没有 mode：抹除模式决定密钥与数据遗留范围，缺字段即遗留面不可判定")
  if (c=="ClearPasscode") emit("T5", ser, "回执件里出现 ClearPasscode：该命令会关闭数据保护，抹除模式与密钥遗留范围需按恢复措施单独标注")
  next
}
END {
  for (f in fileSeen) if (nrow[f]==0 && fileType[f]!="unknown") emit("S4", f, "输入文件除表头外没有数据行")
  nuni=0; for (k in unionInv) nuni++
  if (EVFILE=="") emit("C1", "-", "未提供活动记录件：N3—N7 与 T1、T3、T4 整段不可算（本次只算清单与回执）")
  if (RCFILE=="") emit("C1", "-", "未提供命令回执件：T2、T5、T6 整段不可算（本次只算清单与活动）")
  # ---- 差集：清单侧有声明、活动侧无支撑 ----
  for (i = 1; i <= nInv; i++) { s = invList[i]; if (s=="") continue
    if (!(s in unionInv)) continue
    st = invState[s]
    if (st=="assigned" && !(s SUBSEP "enrolled" in evSeen) && !(s SUBSEP "assigned" in evSeen))
      emit("N2", s, "清单记 assigned 但活动件里没有任何入册或指派活动：归属声明无活动支撑")
    if (st=="released" && EVFILE!="") {
      if (!(s SUBSEP "released" in evSeen) && !(s SUBSEP "checked_out" in evSeen))
        emit("N4", s, "清单记 released 但活动件里没有 released 或 checked_out 事件：释放没有任何凭据")
      if ((s SUBSEP "enrolled" in evSeen) && (s SUBSEP "released" in evSeen) && dnum(evDate[s SUBSEP "enrolled"]) > dnum(evDate[s SUBSEP "released"]))
        emit("N7", s, "入册 (" evDate[s SUBSEP "enrolled"] ") 晚于释放 (" evDate[s SUBSEP "released"] ") 但清单仍记 released：需区分这是重新入册还是残留记录")
    }
    if (st=="assigned" && (s SUBSEP "released" in evSeen))
      emit("N3", s, "活动件里有释放事件 (" evDate[s SUBSEP "released"] ") 但清单仍记 assigned：状态未回收")
    if (st=="deleted" && (s SUBSEP "assigned" in evSeen) && dnum(evDate[s SUBSEP "assigned"]) > dnum(evMin[s]))
      emit("N3", s, "清单记 deleted 但活动件里存在晚于最早活动的指派活动：删除后仍有归属动作")
  }
  # ---- 全局差集计数 ----
  if (EVFILE!="" && nRelInv != nRelEv) emit("N8", "-", "清单里 released 行 " nRelInv + 0 " 条，活动件里 released 事件 " nRelEv + 0 " 条：两侧数量不等，按行相加会重复或漏算")
  # ---- 时序 ----
  for (k in evSeen) { split(k, pp, SUBSEP); s = pp[1]; e = pp[2]
    if (e=="released" && (s SUBSEP "enrolled" in evSeen)) {
      if (dnum(evDate[k]) < dnum(evDate[s SUBSEP "enrolled"])) emit("T1", s, "释放 (" evDate[k] ") 早于入册 (" evDate[s SUBSEP "enrolled"] ")：归属序列倒置")
    }
    if (e=="lost_mode_off" && (s SUBSEP "erased" in evSeen)) {
      if (dnum(evDate[k]) > dnum(evDate[s SUBSEP "erased"])) emit("T3", s, "关闭托管丢失模式 (" evDate[k] ") 晚于抹除 (" evDate[s SUBSEP "erased"] ")：按文档口径抹除本身会关闭该模式，两侧读数来源不同")
    }
    if (e=="migration_closed" && (s SUBSEP "migrated" in evSeen)) {
      span = dnum(evDate[k]) - dnum(evDate[s SUBSEP "migrated"])
      if (span > 30) emit("T4", s, "迁移起 (" evDate[s SUBSEP "migrated"] ") 到终 (" evDate[k] ") 共 " span " 天，超出 30 天临时窗口：两端归属不再同时可信")
      if (span < 0) emit("T1", s, "迁移结束日早于开始日：" e " 与 migrated 时刻倒置")
    }
    if (e=="deleted_user" && (s SUBSEP "signed_out" in evSeen)) {
      if (dnum(evDate[k]) < dnum(evDate[s SUBSEP "signed_out"])) emit("T1", s, "删除用户 (" evDate[k] ") 早于注销 (" evDate[s SUBSEP "signed_out"] ")：按文档口径顺序应先注销后删除")
    }
    if (e=="returned_to_service" && (RCFILE!="" && (s SUBSEP "EraseDevice" in rcSent))) {
      if (dnum(evDate[k]) < dnum(rcSent[s SUBSEP "EraseDevice"])) emit("T6", s, "退回服务 (" evDate[k] ") 早于抹除命令发出 (" rcSent[s SUBSEP "EraseDevice"] ")：退回服务的前提（设备已清）尚未发生")
    }
    if (e=="disowned" && (s SUBSEP "released" in evSeen)) {
      if (dnum(evDate[k]) < dnum(evDate[s SUBSEP "released"])) emit("T1", s, "放弃所有权 (" evDate[k] ") 早于释放 (" evDate[s SUBSEP "released"] ")：先解除组织所有权再释放，顺序倒置")
    }
  }
  # ---- 跨组织合并 ----
  no=0; for (i = 1; i <= nInv; i++) { s=invList[i]; if (s=="") continue; o=invOrgSeen[s]; if (o=="") continue; if (!(o in orgSeen)) { orgSeen[o]=1; no++; olist=olist " " o } }
  if (no >= 2) emit("C2", "-", "清单里同时出现 " no + 0 " 个组织号（" substr(olist,2) "）：跨组织合并计算移交差集被拒，需按组织分别跑")
  # ---------------- 输出 ----------------
  lines[++nline] = sprintf("读数	-	清单唯一序列号 %d 个；活动行 %d 条（其中无归属记录 %d 条）；回执行 %d 条", nuni, nEv, nGhost, nRc)
  if (!QUIET) for (i = 1; i <= nline; i++) print lines[i]
  print ""
  print "==== 汇总 ===="
  ninvf=0; for (nf in invSeen) ninvf++
  printf "清单件=%d  清单行=%d  唯一序列号=%d  活动行=%d  回执行=%d\n", ninvf, nInv, nuni, nEv, nRc
  split("N1 N2 N3 N4 N5 N6 N7 N8 T1 T2 T3 T4 T5 T6 S1 S2 S3 S4 S5 C1 C2 C3 C4", cc, " ")
  bad=0
  for (j = 1; j <= 23; j++) { c2=cc[j]; n2=cnt[c2]+0; printf "%-4s %4d\n", c2, n2
    if (c2 ~ /^S/ || c2=="N1" || c2=="N2" || c2=="T1" || c2=="C1" || c2=="C2") bad+=n2 }
  printf "阻断类信号(S*/N1/N2/T1/C1/C2)合计=%d\n", bad
  exit (bad > 0 ? 1 : 0)
}
' "${FILES[@]}" > "$TMPD/out.txt"
rc=$?
cat "$TMPD/out.txt"
exit $rc
```

---

## 23. 两个脚本的全量分支覆盖验收

本章按"逐码触发"验收：每个信号码都要给一个本轮实跑里真实触发它的样例输入，并给观测到的计数。**共 74 个码，全部触发，无遗漏**。下面两表按组列出触发条件与观测计数（计数来自本轮实际输出，非人工估计）。

### 23.1 脚本一（51 个码，缺陷样例 54 台 / 干净样例 4 台）

| 码 | 触发样例（设备名取自本轮台账） | 观测计数 |
| --- | --- | --- |
| A01 | `D-A01`（无 serial）、`D-A02b`（`AB12` 长度非法）等 | 4 |
| A02 | `D-A02a`（缺指派状态）、`D-A02b`（`pending_review` 出词表）、`D-A02c`（released 而 org_id 空） | 47 |
| A03 | `D-A03`（released + checkout_sent=true 而 checkout_ack 不为 false） | 1 |
| A04 | `D-A04`（released 而 receipt.ownership=apple_business） | 1 |
| A05 | `D-A05`（org_activation_lock=on 而状态 unassigned） | 1 |
| A06 | `D-A06`（读数 On(User) 而 user_activation_lock=off）等两个方向 | 2 |
| A07 | `D-A07`（复核 2025-01-05 对审计 2026-06-20，跨 532 天） | 1 |
| A08 | `D-A08`（采购 2026-09-10 晚于快照 2026-03-01） | 1 |
| A09 | `D-A09`（serial + udid 而无 identifier_authority） | 1 |
| A10 | `D-A10`（有带时区的 logout_at 而无 device.timezone） | 1 |
| C01 | `D-C01`（缺 enroll.method）等 | 42 |
| C02 | `D-A01`（method=ade 而 supervised 不为 true）等 | 7 |
| C03 | `D-C03`（profile_installed=true 而 token_update_seen=false） | 1 |
| C04 | `D-C04`（发抹除 / 托管丢失模式 / 锁定命令而权限列只写 AllowSettings） | 12 |
| C05 | `D-C05`（access_rights 含 ClearPasscode + passcode_set=true + 抹除证据未归档） | 1 |
| C06 | `D-C06`（迁移已启动而无 checkout_sent=true）等 | 7 |
| L01 | `D-L01a`（读数 `ENABLED` 出词表）、`D-L01b`（有开启声明而无三态读数）等 | 3 |
| L02 | `D-L02`（On(Organization) 而账户类型 unknown） | 1 |
| L03 | `D-L03a`（受监管而 escrow_state 空）、`D-L03b`（`escrow` 出词表） | 3 |
| L04 | `D-L04a`（escrowed 无 bypass_code_available）、`D-L04b`（rollback=`stale`）、`D-L04c`（权限含 DeviceLock 而无 unlock_token_received） | 4 |
| **L05** | `D-L05`（`lock.bypass_code_recorded,true`） | 1 |
| L06 | `D-L06`（两种丢失模式同时 true） | 1 |
| L07 | `D-L07a`（无 lost_mode_exit）、`D-L07b`（`user_turned_off` 出词表）等 | 5 |
| L08 | `D-L08`（发锁定命令而 passcode_set=false） | 1 |
| K01 | `D-K01`（erase.command_sent=true 而 acknowledged 空）等 | 4 |
| K02 | `D-K02`（acknowledged=true 而无 ack_at） | 1 |
| K03 | `D-K03a`（丢失模式下抹除未存档）、`D-K03b`（存档了但 receipt.erase=unavailable） | 3 |
| K04 | `D-K04`（instant_wipe_claim=true 而 media_key_discarded 不为 true） | 1 |
| K05 | `D-K05`（rts_enabled + preserve_apps + mode=erase-all） | 1 |
| K06 | `D-K06`（class=mac 发抹除而无 bootstrap_token_available） | 1 |
| M01 | `D-M01`（窗口 45 天）、`D-M01b`（`nine` 非整数）、其余缺窗口 | 3 |
| M02 | `D-M02`（`lift_and_shift` 出词表）、`D-M02b`（退回服务而 method=device）等 | 6 |
| M03 | `D-M03`（rts_enabled 而 MDM / 无线两项数据都缺 + Mac 无引导令牌） | 2 |
| M04 | `D-M04`（迁移两端回执都不为 true）等 | 7 |
| M05 | `D-M05`（有 logout_at 而无 command_held_until）、`D-A10` | 2 |
| E01 | 干净样例全部有词表；缺陷样例 44 台缺 `receipt.vocabulary` | 44 |
| E02 | `D-E02`（命中数 7 而 component_map=absent） | 1 |
| E03 | `D-E03a`（class=`ipad-pro-13`）、`D-E03b`（同一字段两条不同值） | 2 |
| E04 | `D-E04`（os_version=`15.x`、snapshot_date=`March 2026`）等 | 9 |
| E05 | `D-E05`（审计 2026-05-01 早于快照 2026-06-01） | 1 |
| U01 | `D-U01,only_two_columns`（两列）、`BAD-U02,,`（字段名空、前缀非法） | 2 |
| U02 | `,device.serial,AA00BB11CC22`（设备标识空） | 1 |
| B01 | 缺陷样例里绝大多数设备无 `assignment_reviewed_at` | 53 |
| B02 | `D-B02`（token_update_seen=true 而无 token_update_at） | 1 |
| B03 | `D-B02`（advisory_lifecycle_hits 未填）等；干净样例里 `G-MAC-02` 填 `none` | 53 / 1 |
| B04 | `D-V4A`（receipt.channel=accessory） | 1 |
| B05 | `D-B02`（find_my=unknown 且 unlock_token_received=true）、`D-V4C`（receipt.lock=unavailable） | 3 |
| **J1** | 干净样例 `G-IPHONE-01`、`G-MAC-02` | 2 |
| **J2** | 缺陷样例 9 台（有通道与词表但动作/证据合取不合格） | 9 |
| **J3** | 干净样例 `G-IPAD-03`、`G-IPAD-04`（无待证归属动作） | 2 |
| **J4** | 缺陷样例 45 台（词表 / 通道 / 证据面缺失，或配件线 / ownership=none / lock=unavailable） | 45 |

四个判定级都在本轮出现，且**同一份脚本在两份台账上给出方向相反的结果**（缺陷样例 J4=45、干净样例 J4=0），这是本篇对"判定模型不是装饰"的基本要求。

### 23.2 脚本二（23 个码，全量缺陷件 / 两次缺件 / 干净件）

| 码 | 触发样例 | 观测计数 |
| --- | --- | --- |
| S1 | `inv-badheader.tsv`（表头是 `asset_id / status / note`） | 1 |
| S2 | `GGG777HHH888` 在同一清单件里出现两次 | 1 |
| S3 | `II`（清单）、`ZZZ`（活动件） | 2 |
| S4 | `inv-empty.tsv`（只有表头） | 1 |
| S5 | `2026/03/01` 的 released_date、`pending` 状态、`ENABLED` 锁读数、`ping` 事件名、`2026/02/02` 事件日、`PingCommand`、`2026-13-45`、两行列数不足 | 9 |
| N1 | `TTT000UUU111`（两条活动 + 一条回执）、`DDD000EEE111`（ClearPasscode 回执） | 4 |
| N2 | `CCC333DDD444` / `LLL000MMM111` / `PPP000QQQ111` / `SSS000TTT111` / `YYY000ZZZ111` 等 | 8 |
| N3 | `NNN000OOO111`（清单 `deleted`，活动里 2026-05-01 仍有 `assigned`） | 1 |
| N4 | `EEE555FFF666`（released 而无 released_date） | 1 |
| N5 | `CCC333DDD444`（On(Organization) 而 source_service 空） | 1 |
| N6 | `SSS000TTT111`（ORG-1 与 ORG-2 两份清单各登一次） | 1 |
| N7 | `RRR000SSS111`（入册 2026-03-01 晚于释放 2026-02-01） | 1 |
| N8 | 清单 3 条 released 对活动 2 条 released 事件 | 1 |
| T1 | `RRR000SSS111`（释放早于入册）、`TTT000UUU111`（删除用户早于注销） | 2 |
| T2 | `AAA111BBB222`（ack true 无 ack_date）、`CCC333DDD444`（ack 早于 sent） | 2 |
| T3 | `NNN000OOO111`（lost_mode_off 2026-02-01 晚于 erased 2026-01-01） | 1 |
| T4 | `VVV000WWW111`（migrated 2026-01-05 → migration_closed 2026-03-01，55 天） | 1 |
| T5 | `NNN000OOO111`（EraseDevice 无 mode）、`DDD000EEE111`（ClearPasscode 行） | 2 |
| T6 | `XXX000YYY111`（退回服务 2026-01-10 早于 EraseDevice 2026-02-10） | 1 |
| C1 | 缺 `-r` 一轮、缺 `-e` 一轮 | 各 1 |
| C2 | `ORG-1` 与 `ORG-2` 同批清单 | 1 |
| C3 | `AAA111BBB222`（命中 `0`）、`EEE555FFF666`（命中 `none`） | 2 |
| C4 | `RRR000SSS111`（class 空）、`YYY000ZZZ111`（component_map=`absent`） | 2 |

干净件一轮：23 个码全部为 0，退出码 0。**这一轮同样是验收的一部分**——只证明"能报错"的脚本不能作为审计工具，因为它会在正常台账上持续报阻断信号，最终被人忽略。

### 23.3 覆盖不到的清单（显式声明）

一份核验工具的诚实部分在于它说清自己看不见什么。下面 12 项是本轮两个脚本**都没有字段位**的主题，每一项都对应正文里一个 G 编号或 P 类型。它们不是"未实现的检查"，而是"公开文档里没有对应读数，因此无法实现"。

| 主题 | 为什么不可核对 | 正文位置 |
| --- | --- | --- |
| 托管凭据的年龄与可取回性 | 只有第 362 行那句窗口，没有"当前这枚的产生时刻"读数 | G1 / F4 / P5 |
| 服务端 escrow keybag、UnlockToken 是否已作废 | 文档没有作废句 | G5 / 第 9.5 节 |
| 迁移失败分支那把管理员锁的设备侧读数 | 文档未展开 | G3 / F5 |
| FileVault 恢复密钥托管是否已被目标服务替换 | 只有"目标服务自己发过 payload"这一件事，没有对等完成读数 | G7 / F6 / P7 |
| 组织角色 ↔ 配置文件 access right 的映射 | 两侧词表无映射 | G2 / 第 6.4 节 |
| 迁移前锁状态快照 | 台账只保存当前读数，没有两个时刻的键 | G3 / 第 11.4 节 |
| EAS 账户与监督的组合（不能抹三种情形） | 命名空间没有账户类型与 EAS 组合位 | 第 9.3 节 / G8 |
| Shared iPad 被驱逐用户与同步完成状态 | `transfer.*` 只有 `is_multi_user` | G6 / 第 10.1 节 |
| `DeleteUser` 的 `ForceDeletion` 取值 | 无用户删除字段位 | 第 10.4 节 / G8 |
| 错误码 12067 / 12078 的语义（"从未开启"vs"已关闭"） | 两个脚本都不吃错误码 | 第 8.3 节 / G8 |
| `Device Configured` / `NotNow` / `Idle` 应答时序 | 活动词表没有对应事件名 | 第 11.5 节 / G8 |
| 人员 ↔ 设备绑定（Apple Business 侧） | Roster API 仅 School Manager 支持 | G6 / 第 12.4 节 |

再加三条使用侧的限制：**不读设备、不联网、不校验台账与清单之间的主键换算**（那是脚本二 N1/N2 的职责，而它只在序列号形态合法时有效）。第 2.1 节第 3 条的四项约束在这里全部兑现。

---

## 24. 十二个误区

每条一句结论、一句文档依据、一句"如果照做会怎样"。编号与第 4—13 章的引用一致。

**M1 · 把抹掉当作安全处置。**依据：平台安全指南第 4508 行"It remains enabled even if the device is erased."，消费者侧同义表述（《Activation Lock for iPhone and iPad》第 19 行）。照做的结果：数据问题解决了，归属问题一点没动，下一位持有者面对一把他解不开的锁。**抹除解决数据，激活锁解决归属，两件事在文档里被反复写成互不覆盖。**

**M2 · 设备能正常进系统就认为没有归属残留。**依据：闸门位置在激活流程里——第 4523 行（iOS 设置助理在 Wi-Fi 选择页之后的激活请求）、第 4532 行（"won't progress unless a valid certificate can be obtained"）、Apple silicon 第 4554 行、T2 第 4565 行。**四处闸门都不在运行期。**照做的结果：残留只在重新激活或重新启动时才暴露，而那时设备已经易主两次。

**M3 · 认为激活锁也保护数据。**依据：激活锁的定义句只讲"reactivating"（第 4508 行首句）。照做的结果：把一把防止重新激活的锁当成防止数据读取的锁，从而在"已解除激活锁但没抹"的设备上做二手处置。**归属清除 ≠ 数据清除，方向和 M1 相反。**

**M4 · 监督 = 可以远程抹除。**依据：第 4576—4578 行三项清单的第三条是**监督设备上的 Microsoft Exchange ActiveSync 账户**；《Erase Device》可用性表写 `Allowed in user enrollment | N/A`（第 16—21 行）。照做的结果：管理台显示"已下发"，设备永不执行。控制更强反而不能抹，这是本层最反直觉的一条。

**M5 · 改指派、释放、放弃所有权是一回事。**依据：三条各有独立定义且互不等价——第 310—311 行（改指派只结束"由哪个服务管理"）、第 282—290 行（释放结束"能否再指派"并留日期与主体）、《Device assignment》第 11 行（Disown 只"通知 Apple 服务器本组织不再拥有"）。**三份文档没有任何一处把三个动作串成一条流程。**照做的结果：走完最快那条路的设备，清单上仍写着本组织拥有。

**M6 · 退出登录就清掉了数据。**依据：《What happens after you choose Sign Out But Don't Erase》第 24—37 行整份保留清单（Health、Passwords、Contacts、Photos、Documents、Apps、Safari and bookmarks、Wallet passes、Freeform、Reminders、Notes、Calendars、尚未同步的数据），加第 38 行的对照句。**这条通道是文档明确支持的。**照做的结果：登录状态是一个可以截图的假证据，新持有者拿到的是上一位使用者的本地数据。

**M7 · 拿到清单读数就等于拿到归属证明。**依据：《Turn off Activation Lock in Apple Business》第 279—286 行把 Managed Lost Mode（无论由管理服务还是由 Apple Business 开启）都记作 `On (Organization)`（F2）。照做的结果：一次丢失模式主张被读成一次组织侧锁变更，责任方判错。三值读数属 V2，**必须与事件时间或第二面记录合取才成立**。

**M8 · 组织合并会自动处理设备归属。**依据：《About account transfers》改变的是"哪个组织能看见这台设备的清单"，不动设备上的任何锁或凭据（第 11.7 节）。照做的结果：账号迁完，设备上的托管凭据仍然在旧配置文件的发布方手里，而新组织以为整批已交接。

**M9 · 迁移完成就等于凭据已换代。**依据：第 38 行确实保证锁与绕过码作废（F5），但第 56 行的 FileVault 恢复密钥托管"remains on the device after migration **until** the destination service sends its own payload"（F6）。照做的结果：上一家服务商的恢复密钥在新管理服务下继续有效，而台账只写了一句"迁移完成"。

**M10 · 没收到 Check Out 就是没有迁移。**依据：第 28 行的旁注写得直白——"The device sends the Check Out request on a best-effort basis, and the device management service may not always receive it."照做的结果：旧服务永远等着一个可能不会到的信号，同时把已经离开的设备继续算在自己名下。唯一可靠路径是下一次同步设备指派列表的结果。

**M11 · 把"不可判"写成"待观察"。**依据：第 17 章规则四——V4 意味着判定所需的读数不存在，而"观察"这个动作本身需要一份 V1/V2 读数。照做的结果：这一格永久停留在待观察，而每次审计都把它当作已知项。**正确写法是 J4 + 补采集计划**（第 19.3 节规则 C）。

**M12 · 公告里没有生命周期条目就说明这一层没问题。**依据：三份并行公告 392 条 CVE 行里，activation-lock / bypass-code / escrow 命中行数为 0（R10），CISA KEV 95 条 Apple 条目的 20 个生命周期用词命中全为 0（R13），而 13 个身份/存储类组件标签在版本线之间漂移（R12）。照做的结果：把"公告口径说不出这句话"读成"公告说这句话是假的"。**零命中只是口径缺失的证据，不是风险缺席的证据。**

---

## 25. 常见问题

**Q1 · 这一层和"设备有没有漏洞"有什么关系？**
没有直接关系。归属问题出现在采购、离职、部门合并、轮换、维修替换、二手处置、换管理服务这些**跟漏洞无关的事件**里。它的后果不是"多一个 CVE"，而是"上一位使用者的数据对新持有者可读"或"一台机器从此谁都动不了"。第 09 篇管补丁走到哪，本篇管设备归谁、数据能不能被证明已清。

**Q2 · 为什么不直接写一份"处置清单"？**
处置清单（"卖掉之前退出登录并抹掉"）是对的，但它不回答**做完之后谁手里有什么证据**。本篇的主产物是那两份可核对的记录面：归属矩阵（第 15 章）与判定模型（第 19 章）。清单只覆盖第 9.1 节四种抹除语义里的一种。

**Q3 · 激活锁状态到底能不能从设备上读出来？**
不能可靠读出。判定发生在 Apple 激活服务器（《Activation Lock for iPhone and iPad》第 24 行："Each time an iPhone or iPad is activated or recovered, the device contacts Apple to check whether Activation Lock is turned on."）。设备侧可读的是界面文案与三值清单读数，两者都是 V2；组织侧锁与用户侧锁的区分不在设备上。

**Q4 · 那台设备上的托管凭据到底存在哪？**
两个位置，都不在设备上。平台安全指南第 2000 行写 escrow keybag"It is stored on the computer that's used to sync with the Finder or iTunes, or on the device management service that remotely manages the device."；第 2006 行写它与保护它的密钥**分片**存放在设备与主机/服务两侧。`UnlockToken` 由 TokenUpdate 送进管理服务（《Managing passcodes》第 16 行）。所以"从设备上读一遍确认归属"这条常规取证直觉在这里失效。

**Q5 · 本篇为什么不提供绕过码的操作步骤？我作为管理员怎么办？**
不提供。第 2.1 节第 2 条是实质约束：**只写存在什么、谁保管、何时失效、不可得时判哪一级**。作为管理员该做的是三件：在配置文档里为 `UnlockToken` 单独写一条 IT 策略（文档在这里用的是要求语气，不是建议）、把凭据的存在性与失效口径写进台账而不是把值写进去、在换服务商前落实第 372 行那句二选一——**要么带走凭据，要么由旧服务商先把所有 enrolled 设备的锁清掉**，没有第三条。

**Q6 · 一次移交要走几步才算完？**
本篇的定义是"从六条路（第 11.1 节）里任取一条进入，并留下一个能被第三面核对的记录"。最小可核对形式是：**清单侧有 V1 落款（释放日期 + 主体），活动侧有起止两个事件，回执侧至少一端 `acknowledged=true` 且可对时。** 缺任一侧都降到 J2；三侧都缺是 J4。

**Q7 · 迁移失败会留下什么？**
第 40 行给一句硬话：Apple School Manager / Apple Business 会移除任何先前的锁、作废任何绕过码，然后上一把"只有管理员能解的锁"。本篇的处理：这把锁在设备侧的读数是什么、与正常锁怎么区分，**文档未展开（G3）**，因此台账必须在迁移前做一次快照并留下采集日；没有快照时本篇不猜，直接 J2 起判。

**Q8 · 一台设备的"归属"和它零件的"归属"是一件事吗？**
不是。第 4510 行说明部件级激活锁：若 iPhone 检测到某个受支持零件来自另一台开着激活锁或丢失模式的 iPhone，**该零件的校准会被限制**。它的可见形式不是锁屏提示，而是"校准受限 / Finish Repair 标签 / 无法以旧换新 / 保修不合格"（《If a part is locked to someone else's Apple Account》第 18、35—36 行）。整机处置干净之后，一台换过件的设备仍可能在零件上带着上一位使用者的归属，且管理服务侧没有任何 API 能读出它（G9）→ **J4**。

**Q9 · 这些信号码能不能直接当成合规结论用？**
不能。它们回答的是"这一格现在能不能自证"，不是"这一格对不对"。脚本一只校验"有没有写"，不校验"写得对不对"（第 3.5 节第 2 条）。第 19 章的 J1—J4 里没有任何一级意味着"这台设备是安全的"。

**Q10 · 为什么公告与 KEV 的读数只用否定式？**
因为本篇只找到了这一条能核对的用法：证明"某个生命周期组件标签在公告面不存在"（R10、R13）。**公告口径与归属口径没有共享主键**（F1），所以正向使用会造出无法核对的因果句。第 20 章指标表因此不含修复率。

**Q11 · 我们组织没有 MDM，只有 Apple Business 清单，这两个脚本有用吗？**
有，但只有一半。清单件与台账字段大部分仍可填（`owner.*`、`device.*`、`receipt.*`）；`enroll.*` 与 `erase.*` 里依赖 TokenUpdate 与命令回执的格子会全部落到"不可得"，判定结果多为 J2 或 J4。**这不是脚本的限制，是你确实没有这一侧的证据**——第 17 章会把它标成 V3/V4，第 20 章 O2 会显示为归属自证率低。

**Q12 · 判成 J4 之后具体做什么？**
第 19.3 节的规定：J4 **只能由组织声明**，且必须同时写补采集计划，由资产负责人复核。脚本一会给 J4，但它给不出补采集计划——那必须是人的决定。第 20 章 O8（J4 存留时长）就是用来防止 J4 变成无人认领的永久状态。

---

## 26. 未公开文档化边界清单

九条，按"缺的是哪一句"写。**这一章是本篇唯一允许出现"文档未展开"的地方**；正文其它各处凡遇到未展开，都指回这里的编号。

**G1 · 托管凭据的"当前年龄"没有读数。**企业口径给窗口（第 362 行，15 天，且以"或直到服务显式取得并清除"结束），平台安全口径给生成事件（iOS 第 4514/4520/4521 行三种、Mac 第 4547 行两种）。两句性质不同、都不含年龄，而**没有任何一处给出"这台设备当前这一枚从何时起不可取回"**。影响：P5 整类缺陷无法检出；迁移时才发现取不回。台账做法：记换代事件日（`lock.observed_at`），不记值。

**G2 · 归属凭据动作没有权限词，且角色↔权限无映射。**《Activation Lock Bypass Code》第 25 行与《Clear Activation Lock Bypass Code》第 18 行的必需权限都写 `N/A`，而同组 SEEALSO 的 `Security Info` 要 `AllowQuerySecurity`。另外：Apple Business 的角色模型（第 297、284、351、357 行）与配置文件的 access right 之间**没有任何一份文档做过映射**。影响：谁能在配置里说明"没有一项权限词覆盖这两个动作"，谁就能把这两个动作归到配置文件之外的面上——也就是 V4。

**G3 · 迁移失败分支那把管理员锁在设备侧的读数未展开。**第 40 行只说"applies a lock on the device that only the administrator can unlock"，没说它与正常组织侧锁在读数上如何区分。同时台账没有"迁移前快照"这一键（第 11.4 节）。影响：撤锁之后不可回溯，判 J2 起。

**G4 · 丢失模式状态存档是服务方的自选动作。**《Disable Lost Mode》第 14 行用 "needs to store"，但没有任何回执证明它做了，也没有任何命令读回它做过。影响：C7/F7；K03 两个方向都是阻断，但**它们只说明"不能证明"，不说明"没做"**。

**G5 · 服务端托管材料的作废条件未文档化。**escrow keybag（第 2000 行，存在同步主机或管理服务上）与 `UnlockToken`（TokenUpdate 送进服务）在设备换主、退出管理、更换服务商这三个事件下**都没有作废句**。唯一有自动回收句的是 recoveryOS 口令（《Set Recovery Lock》第 10 行："When the device unenrolls MDM the system removes the recovery password."）。影响：第 19.1 节 `p3` 把 `unknown` 排除在 J1 之外；第 19 章基线是"有自动回收句的项可记 J1，没有的项最多 J2"。

**G6 · 人员归属没有结构化面。**与"人员 ↔ 设备"绑定的 Roster API 只在 Apple School Manager 可用（《Roster management》第 5—6 行："This API isn't supported for Apple Business organizations."）。台账命名空间里也没有人员字段。Shared iPad 的驱逐机制（第 4597 行）与 `ForceDeletion` 同意（《Delete User》第 12073 码）都落在这一格里。影响：O10 的上限由文档决定；第 12.4 节因此要求把人员绑定只写进自己的台账。

**G7 · "迁移成功"不含托管恢复密钥替换。**第 56 行用 until 从句把替换时点交给目标服务自己；第 57 行还要求目标服务支持 bootstrap token 管理特性才能创建新恢复密钥。**这两项都不是迁移完成的组成部分**，一个有活动记录、一个没有。影响：P7；J1 对迁移成功的额外要求写在第 11.6 节。

**G8 · 本轮核验口径里没有任何字段位的一组事实。**逐条列在 23.3 节的表里（EAS 组合、被驱逐用户、`ForceDeletion`、错误码语义、`Device Configured`/`NotNow`/`Idle` 时序、30 秒清理窗、macOS 版本与恢复分区闸门等）。这一条之所以单列，是为了把它与 G1—G7 区分开：**G1—G7 是文档缺口，G8 是本文档口径的覆盖缺口**——前者需要 Apple 补文档，后者需要我们补台账列定义。两者混在一起会让读者以为脚本"漏检"，实际上那些格子在公开文档里根本没有读数。

**G9 · 部件归属没有任何管理侧读数。**第 4510 行的机制只在维修流程里以"校准受限"暴露，《If a part is locked to someone else's Apple Account》第 35—36 行给的读数是 `Finish Repair` 标签与保修/以旧换新不合格。激活锁的清单面（第 270—292 行）按整机给三值，**没有一栏按零件给状态**。影响：第 13.4 节直接判 J4；脚本二只保留 `component_map` 一列，它记的是"这份清单能不能与部件读数对齐"，不是部件归属本身。

### 26.1 三条处置原则

1. **G1—G7 只允许以"补采集要求"的形式出现在流程里**，不允许以"检查项"的形式出现在脚本里——它们没有可读的输入。
2. **G8 允许扩展**：若下一轮补出台账列定义（例如把 `enroll.account_type` 加进 `lock.` 命名空间），应先更新第 21.2 节的字段表与本节的分界，再动脚本。**本篇不给脚本加没有文档依据的字段。**
3. **G9 是唯一一条应当写进采购与处置合同的**：换过件的设备在处置前必须按"可能存在零件归属残留"处理，因为这条链上的每一环（维修方、持有方、回收方）在本轮文档里都没有读数义务（第 15.1 节最后一行）。

---

## 27. 结论

本篇从一句不舒服的话开始：**这一层里"发生了什么"和"能被证明发生了什么"之间的落差，比更新链更大。**走完十章之后可以说清它为什么不大了、以及它到底在哪里。

**第一，落差来自权威位置。**归属的关键状态不落在设备上：激活锁由激活服务器判定（《Activation Lock for iPhone and iPad》第 24 行），组织归属落在 Apple Business / School Manager 的设备清单，托管凭据存在主机或管理服务的托管存储里（平台安全指南第 2000、2006 行），迁移时的凭据作废由 Apple 强制执行（《Migrating managed devices》第 38 行）。**设备不是这些事实的权威来源，因此任何只用设备侧读数的归属结论都不能自证。**十层分解（L1—L10）的全部作用就是把每一格的事实位置钉住；第 15 章矩阵里那两格 V1（释放记录、清单与迁移状态）是这条链上仅存的 Apple 侧权威证据。

**第二，落差有可数的形状。**第 16 章的 18 条读数给出它的量化形式：**42 张 MDM 命令可用性表里 32 张（76.2%）在被设计为"设备属于用户"的通道上根本不存在生命周期动作**；20 张（47.6%）的动作连权限词都没有；**三份并行公告的 392 条 CVE 行里，提到激活锁、绕过码或密钥托管的行数是 0**；CISA KEV 的 95 条 Apple 条目里 20 个生命周期用词命中全为 0；13 个身份/存储类组件标签在版本线之间漂移；8 个数字错误码全部集中在与归属凭据无关的两族命令上。**这不是"这些缺陷不重要"，这是"公告口径没有能力表达这一层"**——所以本篇把公告面降为 V3 背景资料，并在第 19 章规定：任何"CVE X 影响激活锁"的断言一律判 J4。

**第三，两条互不覆盖的结论是本文最应该被读到的部分。**抹除解决数据问题，不解决归属问题（第 4508 行"It remains enabled even if the device is erased."）；激活锁解决归属问题，不解决数据问题（M3）。同理，退出登录不解决数据问题（第 24—37 行那份保留清单是文档明确支持的通道），迁移完成不解决密钥遗留问题（第 56 行的 until 从句）。**每一对都是同一个结构：一个动作只覆盖一个维度，而流程把它们当成一个。**

**第四，判定模型不给"安全"。**J1—J4 回答的始终是"你说这台设备归你、数据已清，这句话现在有什么支撑"。所以本篇最重的结论不是 J4，而是**规则 C：V4 一律 J4，不许写"待观察"**——因为观察动作本身需要一份读数，而 V4 恰恰没有。第 23.3 节那 12 项"覆盖不到的清单"和第 26 章九条边界（G1—G7 是文档缺口、G8 是本文档口径的覆盖缺口、G9 应写进处置合同）合起来是本文真正交付的东西：**一张说清了"哪些格子只能靠流程、哪些格子可以靠核验"的地图。**

**最后，本篇不做的事仍然重要。**全文没有绕过激活锁的做法、没有绕过码或解锁凭据的获取与使用步骤、没有抹除规避或恢复技巧、没有任何针对具体设备的攻击动作。第 7 章与第 21.2 节的做法是把这条约束变成结构：**台账命名空间里根本没有凭据值这一栏，脚本二的清单件表头里也没有**——不给位置比写警告可靠。脚本一对把绕过码抄进台账的写法直接报警并要求删除该字段，因为它判断的不是格式，而是一次归属层最严重的泄漏本身。

一句话收束本篇与第 09 篇的分工：**第 09 篇管补丁走到哪，本篇管设备属于谁、数据还能不能被证明已清。**两篇之间没有公开产物做桥，这座桥只能由组织自己的台账与清单差集搭起来——第 21—22 章那两个脚本就是它的最小形式。

---

## 28. 参考资料

本轮存档：`.srcx10/`（取回日期 2026-10-31；索引件 `.srcx10/IDX/files.tsv` 收录 239 条，6 组，42,463,088 字节 / 418,119 行；派生件 6 条、缺源标注 3 条）。全部为公开文档，离线取回，未访问任何设备。

### 平台安全

1. Apple, *Platform Security Guide*（PDF 转文本件 `apple-platform-security-guide.txt`，4,885 行）。本篇引用的关键段落：数据保护类与 keybag（第 1973、1976、1999—2008 行）、Managed Device Attestation（第 4317—4318 行）、设备监管与激活锁（第 4505—4532 行）、部件级激活锁（第 4510 行）、Mac 侧启动闸门（第 4547—4565 行）、清单入册限制（第 4568 行）、丢失模式与远程抹除（第 4570—4585 行）、Shared iPad（第 4586—4604 行）、Configurator 手工入册与 30 天临时期（第 4613 行）。

### Apple 开发者文档 · 设备管理协议（A 组，66 件转文本）

2. *Commands and queries*；*Status items*（82 行，本篇用于 R8 的零命中读数）；*Declarative management command*。
3. 命令页与可用性表：*Erase Device*、*Device Lock*、*Enable Lost Mode*、*Disable Lost Mode*、*Play Lost Mode Sound*、*Device Location*、*Security Info*、*Activation Lock Bypass Code*、*Clear Activation Lock Bypass Code*、*Clear Passcode*、*Managing passcodes*、*Set Recovery Lock*、*Verify Recovery Lock*、*Delete User*、*Log Out User*、*Account Configuration*、*Apply Redemption Code*、*Device Configured*、*User Configured*、*Rotate FileVault Key*、*Certificate List*、*LOM Device Request*。
4. 入册、清单与移交：*Device enrollment*、*Device assignment*、*Disown Devices*、*Migrating managed devices*、*Returning a managed device to service*、*About Apple device supervision*、*User enrollment and device management*、*Configuring multiple devices using profiles*、*Deploying device management enrollment profiles*、*Enrolling a device in a beta program*。

### Apple 支持与企业部署文档（B 组 `pages/`，51 件转文本）

5. 激活锁与处置：*Activation Lock for iPhone and iPad*、*Activation Lock on Apple devices*、*Turn off Activation Lock in Apple Business*、*If a part is locked to someone else's Apple Account*、*What to do before you sell, give away, or trade in your iPhone or iPad*、*If your iPhone, iPad or iPod touch is lost or stolen*、*What happens after you choose Sign Out But Don't Erase*、*Find My*、*Erase Apple devices*、*Erase your iPhone*、*Return any device to service*。
6. 清单与入册：*Release devices in Apple Business*、*Assign, reassign, or unassign devices*、*Review device assignments*、*Manage devices in Apple Business Manager*、*Device management service migration*、*Account-driven enrollment methods*、*Enrolling with Platform Single Sign-On*、*Automated Device Enrollment management*、*Deploying devices to your organization*、*Add devices to your organization*、*Plan a migration*、*Remove users or devices from a plan*、*About account transfers*、*Managed Apple Accounts*、*iCloud managed accounts*、*Intro to device management*、*Device workflow*、*Enrollment methods*、*Supervision*、*Restrictions for supervised devices*、*Restore managed devices*、*Shared iPad: sign-in and single sign-on*、*Shared iPad passcodes*、*Unenroll and sign out*、*Roster management*、*Locate, lock, and erase devices*。

### 公告与在野利用口径（C 组，8 件）

7. Apple 安全发布三份并行版本线（CSAF `149041` / `149227` / `149230`；CVE 行 95 / 134 / 163）。派生件 `advisory-lifecycle-readings.txt`（六段读数）、`advisory-lifecycle-hits.tsv`（108 行命中矩阵）、`release-readings.txt` 与 `release-rows.tsv`（331 行发布表读数）。
8. CISA Known Exploited Vulnerabilities Catalog：`kev.json`（目录版本 2026.10.30，全表 1,766 条）、派生件 `kev-apple.tsv`（95 条 Apple 条目）与 `kev-apple-lag.txt`（修复窗口分布与非标准条目）。

### 本轮产物

9. 脚本一 `device-ownership-ledger-review.sh`（285 行，51 个信号码）；脚本二 `lifecycle-transition-diff.sh`（233 行，23 个信号码）。样例输入：`fx/ledger-bad.txt`（199 行、54 台）、`fx/ledger-good.txt`（4 台）、`fx/inv-{1,2,good,empty,badheader}.tsv`、`fx/events.tsv`、`fx/events-good.tsv`、`fx/receipts.tsv`、`fx/receipts-good.tsv`。全部实跑结果见第 21.4、22.4、23 章。

### 同系列相邻篇目

10. 第 02 篇（访问控制与数据保护类密钥体系）——本篇在第 7.5、9.4 节引用其类密钥体系，只问"这份材料现在在谁手里、换主后有没有作废"。第 09 篇（更新链与补丁传导归属）——本篇与之共享 7 个 slug，只用作词表来源，不重复发布行读数；一句话分工见第 2.2 节。第 11 篇（备份与恢复链路数据副本归属）——本篇管设备属于谁、托管凭据何时作废，第 11 篇管同一台设备的数据被复制成几份、每份对谁可解、能不能证明已清除；两篇在 escrow keybag 的落点（平台安全指南第 2000 行）与恢复后的退管后果（第 4416—4417 行）两处交接，本篇只保留"归属主体"这一层读数，副本内容与可证删除性由第 11 篇负责。第 13 篇（日志、诊断与崩溃证据链归属）——本篇管设备属于谁，它管**这台设备上那条记录能不能作证**：崩溃报告里的两个设备键、日志级别与留存规则、九条采集通道的可得性与同意口径全部归它；两篇共用"抹除"这一个事实但结论对象不同（本篇是归属易主，它是匿名设备标识重置），边界见第 2.5 节第 5 条。

---

咨询ios系统请咨询 telegram：https://t.me/one00190

