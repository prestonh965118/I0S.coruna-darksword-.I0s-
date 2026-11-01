---
title: "iOS 备份与恢复链路数据副本归属防御分析报告"
description: "iOS 备份与恢复链路的十层表面分解：副本产生与触发、副本落点与介质、内容集合、排除项与其效力、密钥形态、可解性归属与 custody、恢复与归属重建、删除与可证清除、管理面与组织可见性、公告与合规口径；P1—P12 缺陷类型学、副本口径/平台安全口径/公开公告口径三套词表与七处换算失败、层 × 责任方 × 介质 × 证据的归属矩阵、四级判定模型与两个离线只读核验脚本（信号码 86 + 32）"
lang: zh-CN
---

# iOS 备份与恢复链路数据副本归属防御分析报告

## 摘要

本报告集前十篇处理的两类问题是"缺陷在哪"和"这台设备归谁"。本文处理第三类，也是前两类都没覆盖的一类：**同一份用户数据在备份链路上被复制成几份、每一份此刻在谁手里、它对谁可解，以及"它已经不在了"这句话要拿什么来证明**。这三件事看起来像一件事——用户界面上只有一个"iCloud 备份"开关和一个"抹除本设备"按钮——但在 Apple 的公开文档里，它们各自有不同的归属主体、不同的密钥事实和不同的可核验证据。开关只管"要不要产生新副本"，不管"已经产生的副本归谁可读"；按钮只管"这台设备上的数据"，不管"账号侧那一代副本和它的密钥"。

第 3 章给三套词表和七处换算失败，其中四处是公开文档之间可以直接对出来的差：**数据类别计数**，平台安全指南写标准保护下"14 data categories"、高级数据保护下"rises to 23"（第 2645、2646 行），同一件事在支持文档《iCloud data security overview》里写成 15 与 25（第 28、31 行），两个数都进不了台账；**"加密"这个词**，支持文档里它是一个开关和一句"Encrypted backups don't include Face ID, Touch ID, or device passcode data."（《About encrypted backups》第 30 行），平台安全指南里它是 backup keybag、PBKDF2 与 UID 派生密钥三件不同的东西（第 1996—1998 行），照着开关去写合规声明必然漏掉钥匙串那一层；**排除项**，开发者文档明确 `isExcludedFromBackup`"exists only to provide guidance to the system … it's not a mechanism to guarantee those items never appear in a backup or on a restored device."（《Optimizing Your App's Data for iCloud Backup》第 38 行），但台账字段普遍按"保证不含"来记；**公告口径**，三份并行版本线安全公告共 392 条 CVE 行里，出现 backup 一词的只有 2 行，且都是 `MobileBackup` 作为组件名出现在同一份公告的两条路径处理类问题里，其描述文本没有任何一条涉及备份语义。

第 4—13 章逐层给出输入、输出、失败形态与可得证据。其中三条事实决定了整篇的判定结构：**iCloud Backup 的备份集落在用户的 Apple 账号里，keybag 由一个与备份集同存的随机密钥保护，"The user's iCloud password isn't used for encryption, so changing the iCloud password won't invalidate existing backups."**（平台安全指南第 2724 行）——所以改密码不等于副本失效；**加密本地备份的 backup keybag 存在"stored on the computer to which the device is backed up"**（第 1996 行），且"there's no tie to a specific device"（第 1997 行）——所以这一类副本的归属主体是那台电脑和掌握口令的人，不是被备份的手机；**设备管理协议里没有备份这个动作**——《Commands and queries》《Declarations》《Profile-specific payload keys》三份文档里 backup 与 restore 的词频均为 0，管理面对副本清单的可见性在协议层就是空集。

核验部分提供两个纯文本、离线、只读的脚本：脚本一把一份"备份副本台账"按 Apple 文档口径审一遍，逐条回答"这一格写成这样时，副本的可解性归属、内容集合和可证删除性还成不成立"；脚本二把副本清单件、密钥事实件与处置回执件做集合差集与事件时序核对，回答"这份副本在三件记录之间能不能闭合、删除与轮换的先后能不能同时为真"。信号码共 118 个（脚本一 86 个、脚本二 32 个），全部在本轮环境实跑触发，第 23 章给出逐码覆盖表。

本文不提供任何可用的漏洞利用代码、提权或绕过步骤，**不含任何备份口令破解、副本提取或解密的步骤与工具，不含针对具体设备或具体账号的攻击动作，不含任何"如何取回别人备份"的做法**；也不提供抹除规避或恢复技巧。本文给出的只有公开文档口径、副本归属判定、责任方划分、可见性边界与只读核验。**全部只写防御与归属判定。**两个脚本都不联网、不调用任何设备侧或 Apple 命令行工具、不修改输入文件；唯一写出目标是 `mktemp -d` 创建的临时目录，退出时删除。脚本一对台账里出现口令值的写法直接报警并要求删除该字段——这不是顺带检查，而是本文的立场：**把备份口令抄进台账这件事本身，就是副本归属层最严重的一次泄漏**，因为它把"这份副本对谁可解"从一个人变成了一本文件。

---

## 目录

1. [引言](#1-引言)
2. [视角声明与本文边界](#2-视角声明与本文边界)
3. [三套词表：副本口径、平台安全口径、公开公告口径](#3-三套词表副本口径平台安全口径公开公告口径)
4. [L1 副本产生与触发层](#4-l1-副本产生与触发层)
5. [L2 副本落点与介质层](#5-l2-副本落点与介质层)
6. [L3 内容集合层](#6-l3-内容集合层)
7. [L4 排除项与其效力层](#7-l4-排除项与其效力层)
8. [L5 密钥形态层](#8-l5-密钥形态层)
9. [L6 可解性归属与 custody 层](#9-l6-可解性归属与-custody-层)
10. [L7 恢复与归属重建层](#10-l7-恢复与归属重建层)
11. [L8 删除与可证清除层](#11-l8-删除与可证清除层)
12. [L9 管理面与组织可见性层](#12-l9-管理面与组织可见性层)
13. [L10 公告与合规口径层](#13-l10-公告与合规口径层)
14. [缺陷类型学 P1—P12](#14-缺陷类型学-p1p12)
15. [归属矩阵：层 × 责任方 × 介质 × 证据](#15-归属矩阵层--责任方--介质--证据)
16. [公开读数：这条链路上能数出来的十八件事](#16-公开读数这条链路上能数出来的十八件事)
17. [可见性边界：这一层读者能拿到什么](#17-可见性边界这一层读者能拿到什么)
18. [四个读数面：设备侧、电脑侧、账号侧、管理侧](#18-四个读数面设备侧电脑侧账号侧管理侧)
19. [四级判定模型](#19-四级判定模型)
20. [运营指标 O1—O10](#20-运营指标-o1o10)
21. [只读核验脚本一：备份副本台账审查器](#21-只读核验脚本一备份副本台账审查器)
22. [只读核验脚本二：三件差集与事件时序比对器](#22-只读核验脚本二三件差集与事件时序比对器)
23. [两个脚本的全量分支覆盖验收](#23-两个脚本的全量分支覆盖验收)
24. [十二个误区](#24-十二个误区)
25. [常见问题](#25-常见问题)
26. [未公开文档化边界清单](#26-未公开文档化边界清单)
27. [结论](#27-结论)
28. [参考资料](#28-参考资料)

---

## 1. 引言

### 1.1 一个开关与一份副本不是同一件事

在用户的认知里，"备份"是一个开关的状态：设置 → Apple 账户 → iCloud → iCloud 备份，绿或灰。在设备里，"备份"是一个每日在特定条件下发生的写动作。在服务商的口径里，"备份"是账号存储里的一批对象和一批密钥。在数据控制者（对企业部署来说就是那个 IT 部门）的口径里，"备份"通常是一件**他们不知道自己有没有**的事——因为管理协议里根本没有这个动作。

这四种口径各说各话，导致一个非常具体的运营问题：**当一个人离开组织、一台设备易主、或者一个账号注销时，没有任何单一读数能回答"这个人的数据副本现在有几份、分别归谁可读"**。第 24 章的十二条误区里，至少有六条属于同一个错误的不同写法：把开关的状态当成副本的清单，或者把设备的抹除当成副本的清除。

### 1.2 为什么"副本"要单独建一套归属语言

第 10 篇把设备生命周期立起来了，它的主键是**设备**：这台机器属于谁、上一次易主走完了没有、抹除之后凭据还在不在。本文的主键是**副本**：一份数据在备份链路上被复制出来的那一个实例。换主键不是因为术语偏好，而是因为这两者的责任方和证据完全不同。

| 主键 | 权威来源在哪 | 谁持有 | 可证的动作 | 本文关系 |
| --- | --- | --- | --- | --- |
| 设备（第 10 篇） | 激活服务器、MDM 服务、组织设备清单 | 领用该设备的人或组织 | 入册、释放、锁定、抹除 | 交接的"载体" |
| 副本（本文） | 用户 Apple 账号、执行备份的那台电脑 | 账号持有人、口令持有人、介质持有人 | 产生、可读、恢复、删除、轮换 | 交接的"载荷" |

一张设备可以带着三份不同归属的副本：账号侧的 iCloud Backup 备份集、某台电脑上的加密本地备份、以及第三方同步服务里的归档。反过来，一台设备被抹除之后，这三份可以都还在。**第 10 篇的结论说"设备属于谁已经可判"，本文要接着说的是：设备归属判对了，也不代表副本归属判对了。**

### 1.3 本文要回答的四个问题

本文不做攻击面测绘，也不给任何操作步骤。它只回答四组可以被公开文档支撑的问题：

1. **有几份？** 一份备份在这条链路上会留下哪些落点，每个落点由谁发起、存在谁的介质上（第 4—5 章）。
2. **含什么？** 哪些数据类别进副本、哪些明确不进、"排除"这件事在文档里到底是什么效力（第 6—7 章）。
3. **对谁可解？** 五类 keybag、逐文件密钥、服务密钥与端到端口径之间是什么关系，可解性归到哪个主体（第 8—9 章）。
4. **能不能证明它已经不在了？** 删除动作、密钥轮换、180 天窗口、旧副本存活与恢复副作用之间的先后与互斥关系（第 10—11 章），以及管理面和公告口径为什么不能承担这个证明责任（第 12—13 章）。

判定工具在第 19—23 章：一个四级模型（J1—J4）、一套运营指标（O1—O10）和两个可实跑的离线只读脚本，脚本一 86 个信号码、脚本二 32 个，全部在第 23 章逐码覆盖。

### 1.4 一个具体的例子

下面这条时间线只用本文的公开口径来读，每一步都有出处：

| 时刻 | 发生了什么 | 副本状态 | 谁可解 |
| --- | --- | --- | --- |
| T0 | 用户开着 iCloud 备份，设备夜间锁定、接电、连 Wi-Fi | 账号侧新增一代备份集 | 服务密钥默认在 Apple HSM，属"认证后可用"类（第 2722 行） |
| T1 | 用户在同一台设备上开启高级数据保护 | 备份集本身不变，iCloud Backup 服务密钥与 Messages 容器密钥各自轮换（第 2746 行） | 转为端到端，只有受信设备可解 |
| T2 | 用户关掉 iCloud 备份 | 已存的备份集**保留 180 天后才删除**（《What does iCloud back up?》第 45 行） | 关闭那一刻，副本仍然存在 |
| T3 | 用户改 iCloud 密码 | 无影响："changing the iCloud password won't invalidate existing backups"（第 2724 行） | 副本可读性不变 |
| T4 | 用户"作为新设备设置" | 新建的备份**替换**已保存的 iCloud 备份（《Restore your iPhone or iPad from a backup》第 47 行） | 旧一代在替换后不再可恢复 |
| T5 | 用户抹掉设备 | 设备侧数据不可用；账号侧副本与密钥不在抹除动作的作用域内 | 取决于 T1—T4 的实际状态 |

这条链上最容易被误读的是 T2 与 T3。**关闭开关是一个动作，副本消失是另一个动作，中间隔着最长 180 天；而改密码在这条链上根本不是删除动作。**任何"用户已关闭备份，因此副本已不存在"的声明，在这里都应当被降级成"已停止产生新副本"。

---

## 2. 视角声明与本文边界

### 2.1 本文的视角

本文站在**数据控制者与账号持有人做归属核对**这一侧，而不是安全评估者做缺陷挖掘这一侧。判据只有一个：某一份副本此刻的可解性、可见性与可证删除性，能不能用公开文档 + 台账 + 只读核验得出一个可交付的结论。得出不了结论的格子，本文写"不可判定"并给出为什么不可判定，而不是猜一个。

### 2.2 与本报告集其它篇目的分工

备份链路会碰到前几篇已经建过的表面，所以边界要先划清楚。

| 篇目 | 它管什么 | 本文不重复它的部分 | 本文接管的部分 |
| --- | --- | --- | --- |
| 第 02 篇 访问控制与应用交互 | 数据保护类（class）在**设备上**的运行时语义：谁能读、什么状态下能读 | 类语义本身、`Protected Until First User Authentication` 的运行时行为 | 这些类在**离开设备之后**由谁的密钥保护、恢复回来之后归谁 |
| 第 03 篇 应用防护与抓包审计 | 应用自身的数据出口与网络面 | 应用侧数据外发行为 | 应用容器在备份里的内容与 `isExcludedFromBackup` 的效力口径 |
| 第 05 篇 生物识别安全机制 | 生物特征数据的采集、存储与匹配 | 模板为什么不出设备（本文只引用一次该结论作为副本侧的排除项依据） | "加密备份不含 Face ID / Touch ID / 设备密码数据"这一支持文档口径的归属后果 |
| 第 08 篇 隐私授权与用途声明 | 数据**采集时**的授权与申报 | 授权链与用途声明的缺陷类型学 | 采集到的数据在备份里归谁、能不能被证明清掉 |
| 第 09 篇 更新链与补丁传导 | 补丁"走到哪"：版本、组件与公告归属 | 更新可用性与公告组件漂移的完整论证 | 备份链路在公告口径里的表达方式（`MobileBackup` 组件名 vs 备份语义） |
| 第 10 篇 设备生命周期与所有权移交 | 设备"归谁"：入册、锁定、托管凭据、抹除 | 激活锁、绕过码、bootstrap token、释放与移交流程 | 抹除之后仍然存在的**副本**、escrow keybag 与 backup keybag 在副本链路上的落点差异 |
| 第 13 篇 日志、诊断与崩溃证据链 | 一条记录本身能不能作证：级别与留存、两个设备键、三个钟、采集通道可得性与覆盖分母 | 日志字段口径、符号化档位、通道与管理面同意 | 客体不同：本文的客体是**一份数据复制品**（在谁手上、可不可解、可否证明已清），第 13 篇的客体是**一条证据记录**（谁写的、当时几点、能被谁看到、覆盖了多少）。两篇唯一的交接点在"一份报告交付之后归谁"：第 13 篇把它写成 L10 交付层的归属判定，本文只在该记录**成为备份内容**时才接管，且不讨论备份加密以外的任何日志口径 |

一句话概括本文与其它篇的差别：**别的篇处理"这台设备/这个缺陷/这条授权"，本文处理"这一份数据复制品"。**

### 2.3 明确的排除项

本文不提供、也不指向以下内容：

- 备份口令的破解、加速、并行尝试方法或任何相关工具与吞吐估算。Apple 自己在文档里给出了这一层的威胁模型与缓解手段（第 1997 行：迭代次数虽大但"there's no tie to a specific device"，"This threat can be mitigated with a sufficiently strong password."），本文只把它作为**归属判定依据**引用：口令归属是谁，这份副本的可解性就归谁。
- 从他人设备、他人电脑或他人账号中提取、导出、挂载或解密备份副本的任何步骤。
- 规避激活锁、绕过 MDM、绕过访问限制的做法——这三者分别由第 10 篇、第 09 篇和第 02 篇处理，且各自都明确排除了绕过。
- 恢复被删除的数据、规避抹除、篡改台账或伪造回执的技巧。
- 针对任何具体设备型号、序列号、账号或个人的操作性内容。

台账字段设计本身也遵守这条边界：**没有任何字段用来记录口令值**。脚本一对 `key.password_recorded=true` 直接报警（K05）并要求删除该字段，只保留 `key.password_owner`（归属）与 `key.device_bound`（绑定形态）。

### 2.4 证据分层

本文引用的公开材料分三层，各层能证明的东西不同，行文里会标明用的是哪一层：

- **平台安全层**：Apple 平台安全指南（本轮使用 4,885 行、697,288 字节、md5 `d106784191540ae19729ac4aeea7e602` 的段落逐行版本，与第 09、10 篇同一版本，行号可直接对照）。它能证明机制与密钥事实。
- **支持与法律层**：iCloud 备份、备份方式、加密备份、从备份恢复等支持文档，以及 Apple 隐私"数据与隐私"法律页。它们能证明**用户可见的行为与窗口**（例如 180 天），但口径颗粒度粗于平台安全层。
- **开发者与管理层**：`isExcludedFromBackup`、`URLResourceValues`、iCloud Backup 优化指南，以及设备管理的命令、声明与描述文件键文档。它们能证明协议与 API 面**有什么和没有什么**——"没有什么"这类证据在第 12 章承担主要作用。

三层之间不能互相换算的七处地方，就是第 3 章后半部分的 F1—F7。

---

## 3. 三套词表：副本口径、平台安全口径、公开公告口径

### 3.1 副本口径（台账语言）

这是本文自己定义、也是两个脚本实现的词表。它的设计目标是：**每一个字段都能在公开文档里找到对应的机制事实，且没有任何字段需要越界取证才能填。**

| 命名空间 | 字段 | 取值 | 对应机制事实 |
| --- | --- | --- | --- |
| `copy.` | `medium` | icloud / computer / external_volume / third_party_service / unknown | 副本落在谁的介质上（第 1996、2724 行） |
| | `kind` | icloud_backup / local_encrypted / local_plain / archive / unknown | 三套不同的密钥事实（第 1996—1998、2015—2016 行） |
| | `device_class` | iphone / ipad / ipod / watch / mac / appletv / vision | 内容集合与恢复语义随设备类型变（《Backup methods》第 60—64 行） |
| | `snapshot_date` | ISO 日期或日期时刻 | 一切删除与恢复声明的时间基准 |
| | `size_bytes` | 正整数 | 副本确实存在的第一读数 |
| | `backup_toggle` | on / off / unknown | 只表示是否继续产生新副本，不表示副本存在与否 |
| | `trigger_state` | idle_powered_wifi / manual / unknown | iCloud Backup 三前提 vs 电脑侧人工发起（第 2722 行） |
| | `retained_after_off_days` | 非负整数 | 关闭后的保留窗口，公开口径 180 天 |
| | `source_of_record` | settings_screen / computer_app / attested / unknown | 读数从哪个面来，决定可见性边界 |
| `key.` | `keybag_kind` | user / device / backup / escrow / icloud_backup / unknown | 五类 keybag（第 1976 行） |
| | `password_owner` | holder / org / third_party / unknown / none | 口令归属，即该副本对谁可解 |
| | `password_recorded` | true / false | 台账是否抄了口令值；true 一律拒收（K05） |
| | `pbkdf2_iterations` | 整数 | 公开口径 1,000 万次（第 1997 行） |
| | `device_bound` | true / false / unknown | "there's no tie to a specific device"（第 1997 行） |
| | `service_key_custody` | apple_hsm / trusted_devices / unknown / not_applicable | 认证后可用类 vs 端到端类（第 2665—2667、2722 行） |
| | `random_key_with_set` | true / false / unknown | keybag 由与备份集同存的随机密钥保护（第 2724 行） |
| | `rotated_at` | ISO 日期 | 轮换事件日，可证不可读性的唯一时间锚 |
| | `messages_key_copy` | true / false / unknown | 开启备份时备份集含 Messages 密钥副本（第 2745 行） |
| | `keychain_uid_protected` | true / false / unknown | 非迁移项始终 UID 封装（第 1996、1998 行） |
| | `escrow_attempts_locked` | true / false / unknown | 钥匙串托管 10 次失败后锁定（第 2938—2955 行） |
| `content.` | `includes_*` | true / false / unknown | 内容集合的正项（健康、钥匙串、消息、照片、手表） |
| | 排除类 | `includes_homekit` / `includes_energykit` / `includes_biometric` | 文档明确不进的项（第 4141、4095 行；《About encrypted backups》第 30 行） |
| | `icloud_photos_synced` | true / false / unknown | 开了 iCloud 照片则照片视频不进备份（第 2728 行） |
| | `cloudkit_app_data` | true / false / unknown | 用 iCloud Drive 存储的数据在 iCloud 而非副本里 |
| | `exclusion_marks_used` | true / false / unknown | 应用设过 `isExcludedFromBackup` |
| | `exclusion_guarantees` | true / false / unknown | 记 true 即误读：标记不是保证（第 38 行） |
| | `purchased_refs_only` | true / false / unknown | 只含购买记录，不含已购内容本体（第 2727 行） |
| | `sim_dependency` | true / false / unknown | 语音信箱密码与消息需要备份时那张实体 SIM（第 2740—2741 行） |
| `delete.` | `delete_requested` / `deleted_at` | bool / ISO | 请求与执行是两个事件，不是一个 |
| | `deletion_evidence` | attested / inferred / none / unknown | 结论的证据等级 |
| | `key_rotated_after_delete` | true / false / unknown | 账号侧可读性由密钥决定（第 2680、2745—2746 行） |
| | `old_copies_survive` | true / false / unknown | 只要有一份旧副本存活，任何一份都能被恢复 |
| | `erasure_witness` | holder / org / vendor / none | 谁为"已清除"作见证 |
| | `retention_days` | 非负整数 | 与 `copy.retained_after_off_days` 交叉核对 |
| `restore.` | `restore_target` | same_device / different_device / new_device / unknown | 同机与异机给出相反结论（第 1996、2742 行） |
| | `cross_device_type` | true / false / unknown | 跨类型恢复不迁移消息及附件等（《Backup methods》第 60—64 行） |
| | `nonmigratory_expected_loss` | true / false / unknown | 非迁移钥匙串项在别的设备上不可用是文档结论 |
| | `hardware_bound_key_present_before` | true / false / unknown | 恢复前是否存在硬件绑定密钥（第 4416—4417 行） |
| | `unenroll_after_restore` | true / false / unknown | 用该密钥作管理服务身份则恢复即退管 |
| | `watch_pairing_preserved` | true / false / unknown | 同机恢复保留 Apple Watch 配对（第 1635、1644 行） |
| | `setup_as_new_after` | true / false / unknown | 作为新设备设置会产生替换旧备份的新备份 |
| `mgmt.` | `surface` | none_documented / vendor_extension / unknown | 管理面词表的第一值是"没有这个东西" |
| | `command_expected` | 自由文本（约定 `none` 表示无） | 声明某条 MDM 命令能做备份动作时需报警 |
| | `profile_key_present` / `declaration_present` | true / false / unknown | 描述文件键与声明里都没有备份项 |
| | `org_visibility` | none / device_side_artifact / attested / unknown | 组织能看到什么，第 17 章承担 |
| `advisory.` | `component_label` | 本轮 18 个组件标签词表 | 公告口径的唯一入口是组件名 |
| | `label_present_in_advisory` | yes / no / unknown | 组件名是否真实出现 |
| | `semantic_hit` | true / false / unknown | 描述文本是否含备份语义 |
| | `kev_listed` / `kev_cve` | bool / CVE 主键 | 在野利用声明必须带可回查主键 |
| `holder.` | `role` | individual / org / third_party_service / unknown | 归属判定第一步：谁是持有者 |
| | `media_control` | owned / managed / unknown | 介质是自有还是受管 |
| | `obligation_recorded` | true / false / unknown | 义务是否落了记录 |
| | `password_knowledge` | holder_only / shared / org_held / unknown / not_applicable | 谁知道口令——不记口令值本身 |
| | `offsite_copy` | true / false / unknown | 异地副本承认存在，则删除结论只能覆盖登记那一份 |

`device.*` 命名空间（`model` / `serial` / `os_version` / `snapshot_date` / `audit_date` / `timezone`）是台账自带的元字段，只用于格式核验与时间定序；其中 `serial` 用来给副本配一个稳定的设备主键，脚本只校验格式（8—14 位字母数字），**不解析、不联网查询、不用于识别任何具体个人**。

### 3.2 平台安全口径（指南语言）

指南用的是一套密钥与结构词汇，和台账语言的关系是"一个字段对应一组机制"，不是一一对应：

| 指南术语 | 出处 | 它在副本链路上管什么 |
| --- | --- | --- |
| keybag（五类：user / device / backup / escrow / iCloud Backup） | 第 1976 行 | 文件与钥匙串数据保护类的密钥被收在哪一个容器里，容器在谁手上 |
| backup keybag | 第 1996—1997 行 | 加密本地备份创建，**存在被备份到的那台电脑上**；口令做 PBKDF2 一千万次；与具体设备无绑定 |
| UID 派生密钥 / 非迁移项 | 第 1996、1998、2150 行 | 未加密时钥匙串仍受 UID 保护；非迁移项只能回到原设备 |
| escrow keybag | 第 2000 行 | 存在同步用的那台电脑或设备管理服务上，可让 Finder/iTunes 免密码同步、也让管理服务远程清除密码 |
| iCloud Backup keybag | 第 2015—2016、2723—2724 行 | 全部类密钥为非对称（Curve25519）；备份集存在用户账号里，keybag 由同存的随机密钥保护；不用 iCloud 密码 |
| per-file key 与 class key | 第 2723 行 | 锁屏时不可访问的类，其逐文件密钥用 iCloud Backup keybag 的类密钥封装后随文件一起备份 |
| CloudKit 服务密钥两分类 | 第 2665—2667 行 | 端到端类私钥不下发到 Apple 服务器；认证后可用类存在 iCloud HSM，登录即可取 |
| 服务密钥删除与轮换 | 第 2680、2698—2699 行 | 关闭账号侧数据时 HSM 里的密钥删除是"immediate, permanent, and irrevocable"；关闭高级数据保护会把新旧两代服务密钥都重新上传 |
| Messages 容器密钥 | 第 2745—2746 行 | 开备份时备份集含密钥副本；关备份会生成新密钥、旧容器密钥解不开新写入数据 |
| 本地设备钥匙串的备份 | 第 2742 行 | 用 SEP UID 根密钥派生的密钥加密，"not known to Apple"，只能恢复到同一台设备 |
| 硬件绑定密钥 / ACME | 第 4416—4417 行 | 备份加恢复后无法再生产生，即使恢复到同一台设备；含该密钥的 ACME 配置在恢复时被移除，用作管理服务身份则设备退管 |
| EnergyKit / HomeKit | 第 4095、4141 行 | 本地备份排除这两类数据 |
| Apple Watch 配对 | 第 1635、1644 行 | 同机恢复 iCloud 备份保留既有配对，因此 iOS 17 起私钥不落在 SEP |

### 3.3 公开公告口径

公告侧的词汇表只有三类入口，且每一类都不覆盖本文的层：

- **组件名**：`MobileBackup`、`Backup`、`libarchive`、`copyfile`、`exFAT`、`APFS`、`Storage`、`file_cmds`、`Time Zone`、`Spotlight`、`Photos Storage`、`Health`、`HomeKit`、`Messages`、`CloudKit`、`Keychain`、`iCloud Drive` 等。本轮三份并行版本线公告里，只有 `MobileBackup` 出现过，出现在同一份公告的两条记录上。
- **CVE 行**：本轮共 95 + 134 + 163 = **392 条**。
- **KEV 条目**：本轮 CISA 已知被利用漏洞目录中的 Apple 行共 **95 条**。

### 3.4 换算失败 F1—F7

"换算失败"指：拿着 A 口径的读数，得不到 B 口径的结论。这七处是本文所有判定都必须绕开或显式声明的坑。

| 编号 | 表面现象 | 两个口径各自说什么 | 为什么换不过去 | 本文的处理 |
| --- | --- | --- | --- | --- |
| F1 | 数据类别计数对不上 | 指南：标准保护 14 类、高级数据保护 23 类（第 2645、2646 行）；支持文档：15 类、25 类（《iCloud data security overview》第 28、31 行） | 两处都没有把"类别"定义成可枚举集合，也没有版本生效日期；任何台账拿这两个数做完整性核对都会自相矛盾 | 台账不设"类别数"字段；脚本对 `advisory.*` 的口径只做组件与语义两级核对 |
| F2 | "加密备份"一词两种含义 | 支持文档：它是 Finder/Apple Devices/iTunes 里的一个开关，并声明不含 Face ID / Touch ID / 设备密码数据（《About encrypted backups》第 24、30 行）；指南：它是 backup keybag + 口令 + UID 派生密钥三件事（第 1996—1998 行） | 照开关口径写声明会漏掉"未加密时文件不加密但钥匙串仍受 UID 保护"这一层，进而把"我的备份不加密所以没有敏感数据"写成错误结论 | 脚本把 `kind` 与 `keybag_kind` 分列；`local_plain` + `backup` 直接报警（K02） |
| F3 | 同一句话在两个渠道行号不同 | 平台安全指南 PDF 的段落逐行版本与网页版安全指南存在同句不同行号，且网页版本身带一个发布日期（2024-12-19） | 引用行号跨版本会错位；本文所有行号统一指向本轮存档的 4,885 行版本 | 第 28 章把版本指纹写进参考资料 |
| F4 | 公告里"backup"只是组件名 | 392 条 CVE 行中提到 backup 一词的只有 2 行，两条都是 `MobileBackup` 作为组件；其描述分别是路径处理问题与路径穿越问题 | "MobileBackup 有 CVE"被读成"备份功能有漏洞"是错误换算；组件名描述的是代码位置，不是备份语义 | 脚本把 `label_present_in_advisory` 与 `semantic_hit` 分列（V01、V02） |
| F5 | 更新索引里根本没有备份 | 本轮公开安全发布索引 331 行里，backup / restore / keybag / escrow 四个词各出现 **0** 次 | 任何"某次更新修了备份问题"的说法在这份口径里都得不到证实，也证不伪；这是一片证据真空 | 判定模型把"仅凭更新记录断言备份层被修复"直接归入不可判定（V4） |
| F6 | 管理协议里没有备份动作 | 《Commands and queries》《Declarations》《Profile-specific payload keys》三份文档 backup 与 restore 词频均为 **0** | "MDM 能不能远程删除备份 / 列出备份 / 强制加密备份"这类问题在协议层没有对应项；把它写成"组织可见"就是无出处 | 台账第一值 `mgmt.surface=none_documented`；声明某条命令能做备份即报警（M02—M04） |
| F7 | 排除标记被读成排除保证 | 开发者文档：`isExcludedFromBackup` 只是给系统的提示，"not a mechanism to guarantee those items never appear in a backup or on a restored device"，且常见文档操作会把该属性重置为 false；台账普遍按"保证不含"记 | 应用侧可控性 ≠ 内容集合可证排除。把标记写成保证会让整份内容集合结论失效 | `content.exclusion_guarantees=true` 一律报警（C06） |

### 3.5 一句话记住三套口径

**平台安全口径说"谁握着密钥"，支持与法律口径说"用户看得见什么行为"，公告口径说"哪一段代码被改过"。**副本归属要用第一套，运营窗口要用第二套，第三套在这一层基本派不上用场——而绝大多数错误结论，都是拿第三套去答第一套的问题。

---

## 4. L1 副本产生与触发层

### 4.1 这一层管什么

L1 只回答一个问题：**一份副本是是被哪一个动作造出来的**。它不管副本内容（L3）、不管密钥（L5）、不管谁拿着（L6）。触发层之所以要单列，是因为这条链路上的产生动作有至少四种，发起方不同、可见面不同、失败形态也不同；把它们混成"备份"一个词，台账就没法解释"这份副本什么时候、被谁造出来"。

### 4.2 四种产生方式与其公开口径

| 触发 | 发起方 | 前提条件（公开口径） | 落点 | 出处 |
| --- | --- | --- | --- | --- |
| iCloud Backup 日常备份 | 设备自身在满足条件时自动执行 | "iCloud Backup occurs only when the device is locked, connected to a power source, and has Wi-Fi access to the internet."，且按日发生 | 用户 Apple 账号 | 平台安全指南第 2722 行 |
| 电脑端备份 | 人（在 Finder / Apple Devices / iTunes 里点下备份） | 无自动条件；加密与否取决于是否设置备份口令 | 执行备份的那台电脑 | 第 1996 行；《About encrypted backups》第 24、31 行 |
| 首次加密本地备份 | 人（勾选 Encrypt local backup） | 该动作**立即覆盖并加密此前的备份** | 同一台电脑 | 《About encrypted backups》第 38 行 |
| 作为新设备设置之后的新备份 | 人（走设置助理） | 新产生的备份**替换**已保存的 iCloud 备份 | 用户 Apple 账号 | 《Restore your iPhone or iPad from a backup》第 47 行 |

四条里最容易被漏掉的是第三条。"首次加密会覆盖并加密此前的备份"意味着：**同一台电脑上未必存在"加密前的那一代未加密副本"，除非它被复制走了**。这直接影响 L2 的落点清点——如果台账把"这台电脑以前有一份未加密副本"记成既成事实，就与公开口径不符；正确写法是记成"该副本在第 N 次加密动作时被覆盖，此后不再存在于该介质（除非有 offsite_copy 记录）"。

### 4.3 输入 / 输出

- 输入：一个动作（自动条件满足、人在电脑侧点击、勾选加密、走设置助理）＋ 一个开关状态。
- 输出：一代副本，带一个可归属的介质和一个可归属的密钥形态。
- 台账字段：`copy.trigger_state`、`copy.backup_toggle`、`copy.snapshot_date`、`copy.size_bytes`、`copy.source_of_record`。

### 4.4 失败形态

| 编号 | 失败形态 | 为什么这是问题而不是笔误 | 脚本信号 |
| --- | --- | --- | --- |
| T-1 | 把三前提（锁定 + 接电 + Wi-Fi）记在电脑侧副本上 | 这组前提是 iCloud Backup 的条件；电脑侧副本由人发起，记错说明这条记录是抄来的而不是观察来的 | A06 |
| T-2 | 没有快照日 | 副本与设备状态的对应时刻不可追，删除与恢复声明全部失去时间基准 | A01 |
| T-3 | 只有开关状态没有体积 | 开关说明"要不要继续产生"，体积才是"这一代存在"的读数 | A04 |
| T-4 | 读数来源与介质矛盾（电脑端应用显示 iCloud 副本） | 两端各自只显示自己那一侧的清单，跨端读数不可信 | A07 |
| T-5 | 把"设备已抹除"当成"没有副本产生" | 抹除作用在设备侧，账号侧的产生条件是三个前提 | 由 L8 的 D05/D07 承接 |

### 4.5 可得证据

这一层的证据几乎全是**设备侧与电脑侧的自陈读数**：设置界面里的最后一次备份时间与体积、电脑端备份管理界面里的备份列表与日期。平台安全层不提供"某一代副本何时产生"的读数，只提供"在什么条件下会产生"的机制。因此 L1 的结论强度天然受限：**任何单点读数都只能证明"读到它的那个面上有这一代"，不能证明"只有这一代"。**

---

## 5. L2 副本落点与介质层

### 5.1 三个官方落点，一个非官方落点

公开文档能证明的落点是三个：

1. **用户的 Apple 账号**。"The backup set is stored in the user's Apple Account and consists of a copy of the user's files and the iCloud Backup keybag."（第 2724 行）。这个落点的责任主体是账号持有人，不是设备持有人。
2. **执行同步/备份的那台电脑**。"The backup keybag is created when an encrypted backup is made by the Finder (macOS 10.15 or later) or iTunes (in macOS 10.14 or earlier) and stored on the computer to which the device is backed up."（第 1996 行）。第 2000 行同样把 escrow keybag 的位置写成"the computer that's used to sync with the Finder or iTunes, or on the device management service"。
3. **设备本身**。第 2742 行说明本地设备钥匙串以 SEP UID 根密钥派生的密钥加密并只能回到同一台设备；这把"设备"也变成一个落点——它是某些项**唯一**的落点。

第四个落点是**第三方同步/网盘服务里的归档**。Apple 文档不描述这一层的密钥形态与可解性，因此本文把它记为 `copy.medium=third_party_service` + `copy.kind=archive`，并在脚本里拒绝任何更细的声明（A03）。这一条不是"可能存在备份"的猜测，而是**责任划分的必要项**：只要介质不在持证方手里，任何"已删除"的结论都必须显式说明它覆盖不到哪里。

### 5.2 落点决定责任方，介质决定证据面

| 落点 | 责任方 | 组织可见性 | 可用证据 | 典型误记 |
| --- | --- | --- | --- | --- |
| 用户 Apple 账号 | 账号持有人 | 无（协议层没有该动作） | 账号侧设置界面读数、元数据表口径 | 把账号侧副本记成"公司资产" |
| 同步用的那台电脑 | 电脑持有者（可能与公司资产重合） | 取决于该电脑是否受管；受管也不等于能看到副本 | 电脑端备份列表、文件存在性 | 把"电脑归公司"当成"电脑上的副本归公司可读" |
| 设备本身 | 设备领用人 | 受管设备有管理面，但管理面没有备份项 | 设备侧设置界面 | 把设备抹除当成所有落点清除 |
| 第三方服务 | 与该服务的关系决定 | 无 | 只有该服务自己的口径 | 在 Apple 文档里找第三方副本的密钥事实 |

第二行是本文里最常见的责任误判。**"这台电脑是公司的"与"公司能读这份加密备份"是两件事**：加密本地备份的 backup keybag 落在这台电脑上，但可解性落在口令上，而口令归属可以是任何一个人（第 1997 行）。脚本对这种冲突给 H02（个人持有者的加密本地副本被记为组织掌握口令）与 M05（把组织可见性记成 attested 但介质是电脑）。

### 5.3 落点之间的可换算性

三个官方落点之间**不能互相换算**，因为它们的密钥事实不同：

- 账号侧副本 → 电脑侧副本：不存在这条换算路径，两者由不同 keybag 保护，且开启高级数据保护时账号侧转为端到端而电脑侧不变。
- 电脑侧副本 → 设备：非迁移钥匙串项只能回到原设备（第 1996、2150 行），因此一份加密备份对不同设备的"可用性"不同。
- 设备 → 账号侧：本地钥匙串数据库以 UID 派生密钥加密，"not known to Apple"（第 2742 行），所以账号侧那一代在这一点上并不等价。

这三条决定了：**"删掉一个落点"永远不等于"删掉这一份数据"。**

### 5.4 失败形态

| 编号 | 失败形态 | 脚本信号 |
| --- | --- | --- |
| M-1 | `medium=icloud` 但 `kind=local_encrypted` | A03 |
| M-2 | `medium=computer` 但 `kind=icloud_backup` | A03 |
| M-3 | 第三方服务副本声明了 Apple 的密钥形态 | A03 |
| M-4 | 承认有异地副本但不记旧副本是否存活 | H05 |
| M-5 | 外部介质副本形态不是 archive（本口径不接受更细声明） | B04（非阻断） |
| M-6 | 没有 `source_of_record`，导致无法判断这条记录来自哪个落点 | A01 |

---

## 6. L3 内容集合层

### 6.1 含什么：文档写明的两类清单

指南用一整节列 iCloud Backup 包含的内容，本文只取其中有归属后果的条目：

- **购买记录而非内容本体**："A user's iCloud Backup includes information about purchased content present on the user's device, but not the purchased content itself."（第 2727 行）。台账因此应记 `purchased_refs_only=true`；记成 false 意味着声明副本里有已购内容本体，与文档相反（C07）。
- **开了 iCloud Photos 就不含照片视频**：第 2728 行。这产生一个交叉核对：`icloud_photos_synced=true` 与 `includes_photos=true` 同时为真即矛盾（C05）。
- **SIM 依赖项**：语音信箱密码与消息条目"if necessary, requires the physical SIM card that was in use during backup"（第 2740—2741 行）。这一条把"内容集合"和"物理介质"绑在一起：**副本包含某项，不代表恢复到别的设备上时那一项还可用。**
- **Apple Watch 随 iPhone**："Your Apple Watch backup is included in the backup of your iPhone."（《What does iCloud back up?》第 34 行）。配件线不产生独立副本，也不给独立责任方（C08、B02）。
- **用 iCloud Drive 存储的应用数据不在副本里**："If the app uses iCloud Drive to store data, that information is stored in iCloud instead of your iCloud Backup."（同页第 43 行）。这是电脑/账号两侧最容易记反的一条（C09）。

明确**不进**本地备份的项在指南其它节里：

| 项 | 出处 | 原文口径 |
| --- | --- | --- |
| HomeKit 数据 | 第 4141 行 | "HomeKit data isn't backed up in local backups." |
| EnergyKit 数据 | 第 4095 行 | "local backups exclude EnergyKit data." |
| 生物特征 | 《About encrypted backups》第 30 行；指南第 568 行 | "Encrypted backups don't include Face ID, Touch ID, or device passcode data."；指纹数据"This data never leaves the device. It's not sent to Apple, nor is it included in device backups." |

还有两项是**条件包含**，最容易被写成无条件：

- 健康数据：面向 Finder/iTunes 的备份里"health data is stored only if the backup is encrypted"（第 2275 行；《Backup methods》第 57 行同口径："Activity, Health, and Keychain data (to back up this content, you'll need to create an encrypted backup)"）。在未加密副本上声明含健康数据即矛盾（C02）。
- Medical ID：iOS 13 及更早进 iCloud Backup，iOS 14 起改用 CloudKit 同步（第 2291 行）。**同一名数据在不同系统世代属于不同落点**，这是本文唯一一处必须由版本决定的内容集合结论。

### 6.2 "不在备份里"有两种，别混

| 类型 | 含义 | 归属后果 |
| --- | --- | --- |
| 结构性排除 | 文档写明该类数据不进备份（HomeKit、EnergyKit、生物特征、iCloud Photos 状态下的照片） | 可以出具"该项不在这一代副本里"的结论 |
| 条件性排除 | 只在特定条件下不进（健康数据只在加密备份里；Medical ID 只在 iOS 13 及更早进 iCloud Backup；已购内容只有记录） | 结论必须带条件，条件一变结论翻转 |
| 声明性排除 | 应用自己设置 `isExcludedFromBackup`（L4） | 不构成可证排除 |

脚本对第三类最严格：`content.exclusion_guarantees=true` 一律报警（C06）。

### 6.3 元数据是一个独立的内容集合

支持文档的加密说明表里有一格专门写 iCloud Backup：即使开启高级数据保护，以下元数据仍在标准保护下——**每份备份关联的设备名称、型号、颜色与序列号；备份里包含的应用与文件格式清单；每份备份快照的日期、时间与大小**（《iCloud data security overview》第 205—213 行）。同一页第 207 行还写明"This metadata is always encrypted, but the encryption keys are still stored by Apple."

这一格的内容集合在归属上很特殊：**它描述的是副本，而不是数据本身，但它泄露的恰恰是"这个人有哪些类别的数据、什么时候备份过、备份多大"**。对一个做人员离职核对的组织来说，这组元数据的敏感度往往高于"这个人的备份能不能被解开"。本文把它单独记入 V2（第 17 章）：账号侧元数据即使端到端开启也不随端到端。

### 6.4 失败形态

| 编号 | 失败形态 | 脚本信号 |
| --- | --- | --- |
| C-1 | 声明副本含生物特征 | C01 |
| C-2 | 未加密副本声明含健康数据 | C02 |
| C-3 / C-4 | 电脑侧副本声明含 HomeKit / EnergyKit | C03 / C04 |
| C-5 | iCloud 照片已同步又记副本含照片 | C05 |
| C-6 | 把排除标记写成保证不含 | C06 |
| C-7 | 记副本含已购内容本体 | C07 |
| C-8 | 把 Apple Watch 记成独立副本内容项 | C08 |
| C-9 | 电脑副本记 CloudKit/iCloud Drive 应用数据 | C09 |
| C-10 | 同一副本既有排除标记又有 CloudKit 数据且无轮换日，导致内容集合结论不可读 | C10 |

---

## 7. L4 排除项与其效力层

### 7.1 应用侧的可控性到底有多大

开发者文档对这件事的表述非常直白，值得完整引一次：

> "The isExcludedFromBackup resource value exists only to provide guidance to the system about which files and directories it can exclude; it's not a mechanism to guarantee those items never appear in a backup or on a restored device."
> —— 《Optimizing Your App's Data for iCloud Backup》第 38 行

同一属性自己的文档页还加了一句限制：

> "Some operations commonly made to user documents will cause this property to be reset to false and so this property should not be used on user documents."
> —— 《isExcludedFromBackup》第 10 行

配套的操作指引是：要排除一组相关文件，应把它们放进一个目录并设置该目录的资源值；每次保存文件后都要重新设置，因为"certain file operations can reset resource values"（同页第 37 行的 note 与第 39 行）。

### 7.2 三层效力，缺一层结论就翻转

| 层 | 谁做 | 效力 | 能否用于归属结论 |
| --- | --- | --- | --- |
| 声明层 | 应用设置 `isExcludedFromBackup` | 提示，可被常见操作重置为 false | 不能单独使用 |
| 执行层 | 系统决定是否真的不备份 | 文档不承诺 | 不能从台账推出 |
| 恢复层 | 恢复到设备时该项是否回来 | 文档明确"不保证不出现在恢复后的设备上" | 不能反向推 |

这三层之间的缺口就是 F7。它在实务里的表现形式是：**"我们把日志目录标了排除，所以备份里没有日志"是一个不成立的结论**；成立的写法是"应用对该目录提出了排除请求，标记可能被重置，因此不据此出具内容集合结论"。

### 7.3 谁负责维护标记

这是本篇少见的"应用开发者可以直接改进归属质量"的一层：

- 标记是**逐文件/逐目录**的属性，不是一次性配置。文档要求每次保存后重设（第 37 行 note）。
- 用户文档（user documents）不应使用该属性（第 10 行）。把用户文档标了排除，本身就是一种缺陷，而不是保护。
- 组织如果依赖"应用不会备份 X"来做数据处理声明，就必须能回答"谁在什么时候验过这个标记还在生效"。这个问题在本文的四个读数面（第 18 章）里**没有任何一个面上能读到**——因此它只能落到开发侧自测，且自测结论仍受"恢复层"缺口限制。

### 7.4 失败形态与脚本信号

| 失败形态 | 台账写法 | 脚本信号 |
| --- | --- | --- |
| 把标记写成保证 | `exclusion_guarantees=true` | C06 |
| 只声明标记、不声明 CloudKit 应用数据归属 | `exclusion_marks_used=true` + `cloudkit_app_data=true` + 无 `key.rotated_at` | C10 |
| 因标记存在而认为副本里没有应用数据 | 记 `includes_*` 全 false 但来源是 `settings_screen` | A07 + C06 组合暴露 |
| 完全没登记标记 | `exclusion_marks_used` 为空 | 由 J2 的"内容集合不完整"承接 |

---

## 8. L5 密钥形态层

### 8.1 五类 keybag，各自的落点不同

"The keys for both file and keychain Data Protection classes are collected and managed in keybags in iOS, iPadOS, macOS, tvOS, visionOS, and watchOS. These operating systems use the following keybags: user, device, backup, escrow, and iCloud Backup."（第 1976 行）

| keybag | 谁创建 | 存在哪 | 保护它的东西 | 归属后果 |
| --- | --- | --- | --- | --- |
| user | 设备 | 设备 | 设备密码派生 | 常规用户数据类，副本链路上由其它 keybag 接管 |
| device | 设备 | 设备 | 设备内部 | 不随账号或备份离开设备 |
| backup | Finder / iTunes 做**加密**备份时 | **那台电脑** | 备份口令经 PBKDF2 一千万次 | 可解性 = 口令归属；与设备无绑定 |
| escrow | 与 Finder/iTunes USB 同步及设备管理服务 | **同步用的那台电脑，或设备管理服务上** | 见第 2000 行 | 让电脑免密码备份同步、让管理服务远程清密码 |
| iCloud Backup | iCloud 备份链路 | 与备份集同处用户账号 | 与备份集同存的一把随机密钥（**不是 iCloud 密码**） | 改密码不使旧副本失效 |

三处需要精确理解：

1. **backup keybag 只在加密备份时创建**。"The backup keybag is created when an encrypted backup is made"（第 1996 行）。未加密时，"the files aren't encrypted regardless of their Data Protection class but the keychain remains protected with a UID-derived key. This is why keychain items migrate to a new device only if a backup password is set."（第 1998 行）。所以"未加密备份 = 钥匙串也明文"是错的；"未加密备份 = 文件明文"是对的。脚本对 `kind=local_plain` + `keybag_kind=backup` 直接报警（K02）。
2. **backup keybag 与设备没有绑定关系**。"Despite this large iteration count, there's no tie to a specific device"（第 1997 行）。这句话在归属层的作用不是"它脆弱"，而是"**它的可解性主体是掌握口令的一方，而不是持有设备的一方**"。Apple 给出的缓解手段也在这同一行："This threat can be mitigated with a sufficiently strong password."——所以口令强度与口令归属是这一层唯一的两件事，本文只登记它们，不做任何关于口令的运算、验证或恢复。
3. **iCloud Backup keybag 是全非对称结构**。"All the class keys in this keybag are asymmetric (using Curve25519, like the Protected Unless Open Data Protection class does)."（第 2016 行）；第 2724 行进一步说明备份集里同时存着文件副本与这把 keybag，keybag 由一把同存的随机密钥保护。

### 8.2 文件级：per-file key 与 class key 的两层封装

"When files are created in Data Protection classes that aren't accessible when the device is locked, their per-file keys are encrypted, using the class keys from the iCloud Backup keybag and backing the files up to iCloud in their original, encrypted state."（第 2723 行）

这一句给出一条重要的可换算关系：**副本里的文件保持其原始加密态，被封装的是逐文件密钥**。所以：

- 副本体积不等于明文体积，也不等于"可解密的数据量"；
- 一份副本是否可解，取决于能否解开 iCloud Backup keybag 的类密钥，而不是取决于文件本身；
- 恢复顺序是"取回文件 + keybag + keybag 的密钥 → 解 keybag → 用类密钥解逐文件密钥 → 写入文件系统并按类重新加密"（第 2725 行）。**这把恢复变成一次归属重建，而不是一次复制**——这一点在第 10 章展开。

### 8.3 钥匙串这一层单独存在

第 2742 行是整篇最锋利的一条：**iCloud Backup 也会备份本地设备钥匙串，但用从 SEP UID 根密钥派生的密钥加密，该密钥"unique to the device and not known to Apple"，因此这个数据库只能恢复到它 originates 的那台设备，"no one else, including Apple, can read it"。**

这条决定了三件事：

1. 在"钥匙串"这一项上，账号侧副本对服务提供方本身也是不可读的。
2. 同机恢复与异机恢复的结论必然相反（L7）。
3. 台账里 `keychain_uid_protected=false` 是一个**读数来源问题**而不是机制事实：如果记录的是加密本地备份，非迁移项始终仍由 UID 封装，false 只能说明这一格不是从设备上读来的（K11）。

另一条独立的钥匙串通道是 iCloud Keychain 托管记录：钥匙串被导出后用非对称 keybag 封装并放进用户的 iCloud 键值存储区，keybag 同时用用户的 iCloud 安全码与托管该记录的 HSM 集群公钥封装（第 2943 行）；恢复需要账户认证 + 注册手机号的 SMS + 安全码，HSM 用 SRP 校验且不接收安全码本身，尝试上限 10 次，若干次失败后记录被锁定需致电 Apple Support，第 10 次失败后 HSM 集群**销毁该托管记录**（第 2953—2954 行）。

对副本归属来说，这一段给出两个可用的读数：**它是钥匙串这一类数据的另一个落点**（既不在设备上也不在备份集里），以及**文档明确写得出"服务端把一条记录销毁"这件事**（第 2954 行）——这是本文里少见的、由文档承诺的密钥级不可逆清除。K13 的作用就是防止把"托管记录被锁定"（可用性事件）误当成"数据被清除"的证据。

### 8.4 数据保护类在离开设备之后仍然起作用

指南在多个框架章节里把类名直接写进"备份口径"：EnergyKit 用 `Protected Until First User Authentication` 但"local backups exclude EnergyKit data"（第 4095 行）；HomeKit 同样使用该但"HomeKit data isn't backed up in local backups"（第 4141 行）。而第 2145—2150 行给出钥匙串侧的对应规则：`kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` 这一类只存在于系统 keybag，**不同步到 iCloud Keychain、不进备份、也不进托管**；其它类都有"This device only"对偶，在备份离开设备时"always protected with the UID … rendering it useless if it's restored to a different device"（第 2150 行）。

第 02 篇已经处理过这些类的运行时语义，本文不重复；这里只取一条结论：**"This device only"这一族是链路里唯一一类"复制出去即失效"的数据**，因此它们是唯一可以用"没有落点"来表述的内容项。其余所有项在离开设备后都靠密钥归属来约束，而密钥归属是可以出错的。

### 8.5 失败形态

| 编号 | 失败形态 | 为什么致命 | 脚本信号 |
| --- | --- | --- | --- |
| K-1 | 未记 keybag 类 | 五类落点不同，等于没写这份副本归谁 | K01 |
| K-2 | 未加密副本挂 backup keybag | 与第 1996 行机制矛盾 | K02 |
| K-3 | 加密本地副本没有口令归属 | 这一类副本唯一的边界就是口令 | K03 |
| K-4 | 拉伸次数读数低于公开口径 | 要么读数错，要么这一代副本不是按该口径生成的 | K04 |
| K-5 | 台账里抄了口令值 | 把可解性主体从一个人变成一本文件 | K05（拒收） |
| K-6 | iCloud 副本没有服务密钥归属 | 默认态与端到端口径给相反结论 | K06 |
| K-7 | 服务密钥在 HSM 且记设备绑定 | 认证后可用类的绑定条件是账号不是设备 | K07 |
| K-8 | 端到端口径与"随机密钥同存"并存 | 两种保护模型被混写 | K08 |
| K-9 | 记了"密钥与副本同处"但没有轮换日 | 没有轮换事件就无法证明旧副本失去可读性 | K09 |
| K-10 | Messages 容器密钥入备份但无轮换日 | 关闭备份会生成新密钥（第 2745 行） | K10 |
| K-11 | 加密本地副本记钥匙串未受 UID 保护 | 该格只能是读数来源错 | K11 |
| K-12 | escrow keybag 记在 iCloud 副本上 | 第 2000 行给的是电脑或设备管理服务 | K12 |
| K-13 | 把可用性事件当清除证据 / backup keybag 与 HSM 托管混写 | 第 2954 行与第 1996 行分别对应 | K13 |

---

## 9. L6 可解性归属与 custody 层

### 9.1 可解性由三件事决定，且顺序固定

一份副本"对谁可解"，公开文档给出的答案可以拆成三问：

1. **密钥容器在哪一类里？**（L5）——决定物理落点。
2. **解开容器需要谁的输入？**——设备密码、备份口令、账号认证、还是受信设备上的本地密钥。
3. **有没有一个可以证明"输入已变更"的事件？**——口令变更、服务密钥轮换、Messages 容器密钥重生成、托管记录销毁。

第三问决定了这一层的交付质量：**前两问给出的是"谁可解"，第三问给出的是"何时不再可解"。** 只有前者没有后者，结论就停在 J3（第 19 章）。

### 9.2 两种服务密钥口径

CloudKit 服务密钥的两分类是本文最直接的"对谁可解"证据：

- **端到端类**："the relevant CloudKit service private keys are never made available to Apple servers … created locally on a user's trusted device and transferred to the user's other devices using iCloud Keychain security"，且最坏情况下"Apple can't help recover this data"（第 2666 行）。
- **认证后可用类**："the service keys are stored in iCloud Hardware Security Modules in Apple data centers, and can be accessed by some Apple services. When a user signs in to iCloud on a new device and authenticates their Apple Account, these keys can be accessed by Apple servers without further user interaction or input."（第 2667 行）。

iCloud Backup 落在这个二元里的哪一格，第 2722 行说得很清楚：**默认属"认证后可用"，开启高级数据保护后转为端到端。** 台账因此需要两栏：`key.service_key_custody`（apple_hsm / trusted_devices）与 `key.rotated_at`。

### 9.3 切换方向的不对称

指南把两个方向写成了不同的事件：

- **开启高级数据保护**：设备发起把"认证后可用"服务密钥从 Apple 数据中心移除；因为密钥由 iCloud HSM 保护，"this deletion is immediate, permanent, and irrevocable"；随后异步地为每个服务轮换出新密钥，失败会一直重试到成功（第 2680 行）。此外 iCloud Backup 服务密钥与 Messages 容器密钥都会轮换（第 2746 行）。
- **关闭高级数据保护**：设备先把新选择记录进 iCloud Keychain 参与元数据并同步到所有设备，然后**把服务密钥重新上传到 HSM**；且上传的是**两代密钥**——开启之前生成的原始密钥与开启之后生成的新密钥——结果是这些数据恢复为认证后可用（第 2698—2699 行）。

这个不对称有一个直接后果，值得单独写出来：**"曾经开过高级数据保护"不是一段安全历史，而是一个可被回滚的配置状态。** 判断某一代副本此刻归谁可解，必须看**判断时刻**的 custody 值与最后一次轮换日，不能看"用户以前开过 ADP"。台账里如果只有布尔开关而没有 `rotated_at`，就无法区分这两种状态（K09）。

### 9.4 口令归属与"谁知道"

本文不记录任何口令值，只记录两件事：**归属**（`key.password_owner`）与**知识范围**（`holder.password_knowledge`：holder_only / shared / org_held / unknown / not_applicable）。之所以后者也进台账，是因为第 1997 行把这一类副本的安全性系在"一个足够强的口令"上；**知识范围决定边界是几个人**。三条对应信号：

| 冲突 | 含义 | 信号 |
| --- | --- | --- |
| 个人持有者的加密本地副本记为组织掌握口令 | 角色与归属不一致 | H02 |
| 口令只有持有者知道，却由厂商见证删除 | 不掌握口令的一方无法见证该副本解密性的消失 | H03 |
| 口令共享且登记了拉伸次数 | 这类副本与设备无绑定，共享口令把单台设备的边界变成一组人的边界 | H06 |

第三行只陈述"边界变宽"这一归属事实。本文不提供任何针对口令的操作内容。

### 9.5 谁能替谁做决定

| 决策 | 谁能做 | 依据 | 副本侧后果 |
| --- | --- | --- | --- |
| 开关 iCloud 备份 | 账号持有人 | 第 2722 行 | 只停止新副本，不删除已有副本（180 天窗口） |
| 开启/关闭高级数据保护 | 账号持有人（需受信设备） | 第 2646、2698—2699 行 | 服务密钥轮换/回传，可解性主体迁移 |
| 设置/变更备份口令 | 电脑侧操作者 | 《About encrypted backups》第 24、38、55 行 | 首次加密覆盖旧副本；关闭加密后既有加密副本不可用 |
| 请求恢复钥匙串托管记录 | 账号持有人（认证 + SMS + 安全码） | 第 2953 行 | 不影响副本，但影响钥匙串那一格的可用性 |
| 远程清除用户密码 | 设备管理服务 | 第 2000 行（escrow keybag 的作用） | 属第 10 篇范围；本文只登记 escrow keybag 的落点 |
| **列出/删除/强制加密某个人的备份副本** | **无人** | 命令、声明、描述文件键三份文档 backup/restore 词频为 0 | 管理面在此为空集（L9） |

最后一行是本文与第 10 篇最重要的分界：**第 10 篇的处理动作里很多是"设备归属"的，本文这一行是"数据副本"的，而后者在协议里没有对应动作。**

### 9.6 失败形态

| 编号 | 失败形态 | 脚本信号 |
| --- | --- | --- |
| Q-1 | 服务密钥在 HSM 却记设备绑定 | K07 |
| Q-2 | 端到端口径与"随机密钥与备份集同存"同时为真 | K08 |
| Q-3 | 有 custody 值但没有轮换日 | K09 |
| Q-4 | 承认存在异地副本却不记旧副本存活 | H05 |
| Q-5 | 受管电脑上的副本没落义务记录 | H04 |
| Q-6 | 介质、形态、快照日或 keybag 任一缺格，导致连"有几份"都不可判 | A01/A02/K01 → J4 |

---

## 10. L7 恢复与归属重建层

### 10.1 恢复不是复制，是重新建立归属

第 2725 行给出的恢复顺序——取回文件、iCloud Backup keybag 与保护 keybag 的那把密钥；用密钥解 keybag；用 keybag 里的类密钥解逐文件密钥；把文件写入文件系统并按其数据保护类重新加密——意味着恢复过程做的第一件事是**把副本侧的密钥关系搬到设备侧**，第二件事才是搬运数据。因此恢复的结果不止取决于副本里有什么，还取决于**恢复到哪台设备、这台设备现在有什么密钥材料**。

这就是为什么本文把恢复单列为一层，并把它放在"归属"而不是"操作"的视角下讨论。

### 10.2 四种恢复目标给出四种归属结论

| 恢复目标 | 钥匙串那一项 | 非迁移项 | 配对与身份 | 公开依据 |
| --- | --- | --- | --- | --- |
| 同一台设备 | 可读（UID 派生，只回原设备） | 可用 | Apple Watch 既有配对被保留 | 第 2742 行；第 1635、1644 行 |
| 另一台设备 | 不可读 | **不可访问**（"rendering it useless if it's restored to a different device"） | 需重新配对；含硬件绑定密钥的 ACME 配置被移除 | 第 2150 行；第 4416—4417 行 |
| 作为新设备设置 | 不涉及（不从备份恢复） | 不涉及 | 新建的备份会**替换**已保存的 iCloud 备份 | 《Restore your iPhone or iPad from a backup》第 47 行 |
| 跨设备类型（如用 iPad 备份设置 iPhone） | 同上按 UID 规则 | 同上 | 明确不迁移的内容清单见下 | 《Backup methods》第 60—64 行 |

跨设备类型不迁移的清单值得完整列一次，因为它是少数**用户看得见、组织也能核对**的口径：照片（除非使用 iCloud Photos）、Messages 及消息附件（除非同步消息到 iCloud）、语音备忘录、以及目标设备不兼容的应用（同页第 61—64 行）。

### 10.3 硬件绑定密钥：一处必须写进退管结论的机制

第 4416—4417 行是本文里唯一一条"恢复动作会导致设备失去管理身份"的公开结论，值得整段读：

> "When the device is erased, the Secure Enclave effaces the stored entropy. Because of this, a hardware-bound key can't be regenerated after a backup and restore, even when restoring to the same device."
> "Any configurations containing an ACME payload with a hardware-bound key are removed upon restore. If a hardware-bound key is used as the device management service client identity, the device unenrolls."

在副本归属层，它给出一条反向教训：**恢复不仅会丢数据，还会丢身份**。如果组织把证书续期流程当成"备份恢复之后会自动回来"，那它会在恢复那一刻退管。脚本对这一格的处理是：`restore.hardware_bound_key_present_before=true` 而 `restore.unenroll_after_restore` 不为 true 时报 R04，并把结论留在 J2 以下（不能出具"恢复后归属不变"的判断）。

注意这条与设备类型的耦合：第 4416 行的前提是可擦除设备上 SEP 的熵被抹除，因此**它属于恢复链路而不是备份链路**——副本本身不受影响，受影响的是恢复到设备之后那一份身份的连续性。这一点在第 10 篇的抹除章里由另一侧（凭据遗留）处理，本文只取恢复侧后果，不重复其入册与释放流程。

### 10.4 恢复侧的五个归属反转

| 反转 | 备份侧看起来 | 恢复侧实际 | 依据 |
| --- | --- | --- | --- |
| R-1 钥匙串 | "备份里有钥匙串" | 只能回到原设备，异机不可读 | 第 2742、2150 行 |
| R-2 SIM 依赖项 | "副本含消息与语音信箱密码" | 需要备份时那张实体 SIM | 第 2740—2741 行 |
| R-3 已购内容 | "副本含购买记录" | 内容要各自重新下载，退款或下架后不可用 | 第 2727 行 |
| R-4 端到端 | "开启高级数据保护后就一直是端到端" | 关闭会把两代服务密钥重新上传 | 第 2698—2699 行 |
| R-5 管理身份 | "备份能完整恢复设备" | 含硬件绑定密钥的 ACME 配置在恢复时被移除 | 第 4416—4417 行 |

第二行是实务里最容易漏的一条，因为它要求台账同时持有"逻辑副本"与"一张物理卡"的关系。对做人员离职核对的组织，这意味着：**如果 SIM 卡已被回收或换人，那一代副本里的这两项在下一台设备上就是不可用的**——这既可以被当成"数据事实上已失去"的记录，也必须被写成"该结论依赖物理介质状态"，不能写成"已删除"。

### 10.5 失败形态

| 失败形态 | 脚本信号 |
| --- | --- |
| 未记恢复目标 | R01 |
| 异机恢复却记副本为设备绑定 | R02 |
| 异机恢复但没有登记"非迁移项预期丢失" | R03 |
| 恢复前有硬件绑定密钥但未记退管 | R04 |
| 同机恢复却记手表配对未保留 | R05 |
| 跨设备类型恢复且消息未同步，却记消息会迁移 | R06 |
| 副本含 SIM 依赖项却恢复到别的设备 | R07 |

---

## 11. L8 删除与可证清除层

### 11.1 四种"删除"，只有一种能证明不可读

| 动作 | 作用对象 | 文档口径 | 能否证明副本不可读 |
| --- | --- | --- | --- |
| 关闭 iCloud 备份开关 | 未来是否产生新副本 | 已存备份**保留 180 天**后删除（《What does iCloud back up?》第 45 行） | 否，且明确有窗口期 |
| 在账号里删除某代备份 | 账号侧对象 | 支持文档给操作，平台安全层不给"何时物理不可读"的读数 | 部分（对象删除≠密钥删除） |
| 抹掉设备 | 设备侧数据 | SEP 熵被抹除（第 4416 行） | 对设备侧成立，对账号/电脑侧不成立 |
| 密钥删除或轮换 | 副本的可读性本身 | 端到端开启时"this deletion is immediate, permanent, and irrevocable"（第 2680 行）；关闭备份时 Messages 容器生成新密钥，旧容器密钥解不开新写入数据（第 2745 行） | **是**，这是本文唯一承认为"可证"的机制 |

结论直接决定判定模型：**"已删除"的可证性来自密钥事件，不来自文件事件。** 台账如果只有 `delete.deleted_at` 而没有 `delete.key_rotated_after_delete`，脚本给 D04；如果有轮换证据却仍记 `deletion_evidence=inferred`，给 D08（记 inferred 会让这份副本被反复计入不可证清单）。

### 11.2 一个具体的窗口：180 天

这是本链路唯一一处由文档给出的明确时间窗：**关闭 iCloud 备份后，已存于 iCloud 的备份保留 180 天才删除。** 它有两个方向的用法：

- 作为**运营口径**：离职核对时，"用户已关闭备份"这一读数最多只能支持"停止产生新副本，最终删除时刻约为关闭后第 180 天"；把它写成"副本已删除"即 F 类换算失败，脚本对 `copy.retained_after_off_days` 与 180 不一致给 A05，对只记窗口但开关不是 off 也给 A05。
- 作为**边界声明**：180 天是 iCloud 侧的窗口，不覆盖电脑侧本地副本、外部介质副本与第三方服务副本。脚本用 D06 交叉核对同一副本的两处保留口径（`delete.retention_days` 与 `copy.retained_after_off_days`）是否一致。

### 11.3 加密状态变更也是一种删除事件

《About encrypted backups》第 38 行与第 55 行给了两条电脑侧的"事实删除"：

- 首次勾选加密时，备份"starts and immediately overwrites and encrypts your previous backups"。
- 关闭加密后，"You won't be able to use previous encrypted backups"，但仍可就当前数据重新备份并设新口令。

这两条对归属很有价值，因为它们是**用户可自主执行、且在支持文档中写明的可读性终结事件**。第 55 行尤其值得单独登记：它给出的不是"数据消失"，而是"口令不再可用从而副本不可用"——这与平台安全层第 1997 行的机制一致（可解性系在口令上）。台账应把它记成密钥/口令层事件，而不是文件删除事件；混用会让 D 组结论整体失真。

### 11.4 可证清除的四条要求

把上面几条合起来，本文对"可证清除"提出的最低要求是：

1. **有时刻**：`delete.deleted_at` 必须是可与快照排序的 ISO 时间（D01）。
2. **有先后**：删除时刻不早于快照日；轮换不早于删除；恢复晚于删除则两条至少一条不属于该副本（T01—T03；脚本二 Y01—Y03）。
3. **有密钥事件**：账号侧结论必须绑定 `key_rotated_after_delete`（D04）。
4. **有覆盖范围**：`old_copies_survive=true` 时任何"实证级删除"结论被撤销；承认有异地副本却不记该字段同样报警（D05、H05）。

四条齐备才允许写"该代副本对该主体已不可读"。缺任何一条，判定停在 J1 的第二种表述（能定责"该谁处置"，不能定责"是否已处置"）。

### 11.5 失败形态汇总

| 失败形态 | 脚本信号 |
| --- | --- |
| 请求为真但无删除时刻 | D01 |
| 未请求却有删除证据 | D02 |
| 实证级结论没有见证主体 | D03 |
| 实证级结论没有密钥轮换 | D04 |
| 实证级结论与旧副本存活并存 | D05 |
| 同一副本两处保留口径不一致 | D06 |
| 记"作为新设备设置"但没记删除请求 | D07 |
| 有轮换证据却只记 inferred | D08 |
| 已删回执但在册状态仍为 listed | 脚本二 Z08 |
| 退册但没有删除回执 | 脚本二 Z09 |

---

## 12. L9 管理面与组织可见性层

### 12.1 一个空集

本文的第三条主要论点在这里给出：设备管理协议里没有"备份"这个动作。核验方式很朴素——对三份公开文档做词频统计：

| 文档 | 内容 | `backup` 命中 | `restore` 命中 |
| --- | --- | --- | --- |
| Commands and queries（MDM 命令与查询） | 全部命令目录 | **0** | **0** |
| Declarations（声明式设备管理声明） | 全部声明清单 | **0** | **0** |
| Profile-specific payload keys（描述文件专用键） | 全部键清单 | **0** | **0** |

一个动作在命令目录里不存在、在声明清单里不存在、在描述文件键里也不存在，那就不是一个"暂时没实现的能力"，而是**协议里没有这一格**。这与第 10 篇的处理动作清单形成鲜明对照：那边有 Erase Device、有清密码、有锁定；这边一条关于备份的都没有。

由此，管理面对副本的可见性应记为 `mgmt.surface=none_documented`，这是台账的**第一值而不是缺省值**——它需要被显式登记，否则脚本按缺格处理（M01）。任何声称"通过 MDM 可以列出/删除/强制加密用户备份"的记录都会撞上 M02—M04：M02 针对把某个动作写成 MDM 命令的期望，M03 针对"存在备份相关描述文件键"的声明，M04 针对声明式管理里的备份声明。

### 12.2 那管理面能看到什么

只能看到**设备侧留下的产物**，而不是副本本身：设备是否在管、领用关系、已知的设备元数据。台账因此用 `mgmt.org_visibility` 的四值表达：

| 值 | 含义 | 允许的结论 |
| --- | --- | --- |
| none | 管理面对该副本零可见 | 不得据此出具任何副本层声明（脚本记 B03，非阻断，说明这是协议后果而非记录错误） |
| device_side_artifact | 只能看到设备上的产物，例如设备名、系统版本 | 可作线索，不可作副本存在性证据 |
| attested | 有与该副本直接对应的可回指证据 | 才允许出归属结论；但介质为电脑时该值不成立（M05） |
| unknown | 未核对 | 停在 J4 |

第三行需要限定：**`attested` 在介质为 iCloud 时只能来自账号侧自陈**，而账号属于用户；介质为电脑时，证据只能来自那台电脑，而"公司拥有这台电脑"和"公司能证明这份副本的状态"仍然隔着一层口令归属。这条区分是 M05 存在的原因。

### 12.3 高级数据保护对托管设备的作用

第 9.3 节已经给出机制：开启高级数据保护需要受信设备，端到端类私钥不下发到服务器，最坏情况下 Apple 也无法帮助恢复（第 2666 行）。把这条应用到组织场景，可以得出**一个纯归属结论**（不涉及任何绕过）：

- 若账号是个人 Apple 账户并开启了高级数据保护，则该副本的可解性主体是"该人的受信设备集合"。管理服务不在这一集合内，协议里也没有把它加进来的动作。
- 因此"组织可访问员工个人账号 iCloud 备份"这类假设，在文档层面同时缺两处支撑：没有协议动作（12.1），也没有密钥路径（第 2666 行）。

### 12.4 备份与设备管理服务之间的唯一连接点

整条链路里，设备管理服务与密钥体系有且只有一处被文档写明：**escrow keybag 可以存在设备管理服务上**，它允许 Finder/iTunes 免密码备份与同步，也允许设备管理服务远程清除用户密码（第 2000 行）。

这一处连接点有两层含义：

1. **它不是"管理服务能读副本"**。第 2000 行描述的是让电脑/服务免密码完成同步，而钥匙串侧另有 UID 与托管记录保护（第 2742、2938 行）。把它读成"托管即拥有副本可解性"是本文最常见的误记之一，脚本用 K12 拦住"escrow keybag 记在 iCloud 副本上"这种写法。
2. **它是"副本落点可能在服务侧"的唯一文档依据**。做归属清点时，托管设备的 escrow keybag 落点必须单独一格，因为它可能同时存在电脑与服务两处。

第 10 篇已经处理过托管凭据（绕过码、UnlockToken、bootstrap token）的归属与移交，本文不重复；这里只把 escrow keybag 作为**副本链路上的一个落点**登记，不讨论其入册、轮换与作废流程。

### 12.5 元数据是管理侧唯一可核对的东西

第 6.3 节那张表（支持文档第 205—213 行）里的三项——设备名称/型号/颜色/序列号、应用与文件格式清单、每次快照的日期/时间/大小——是账号侧唯一"描述副本但不需要解开副本"的信息。对组织而言它的价值是：

- **可核对**：这三项可以由账号持有人自行读出并提供，属于可交付证据。
- **有代价**：其中包含序列号与应用清单，本身就是可识别信息；把它纳入台账时要按个人信息处理，不能因为"它只是元数据"而降级保护。
- **有边界**：这三项证明"有这个人的副本存在、覆盖了哪些类别"，不证明"副本内容是什么"，也不证明"副本还在不在"。

---

## 13. L10 公告与合规口径层

### 13.1 公告在这一层能说什么

三份并行版本线公告共 392 条 CVE 行，其中出现 backup 一词的 2 行都来自组件 `MobileBackup`，两条描述分别是"An app may be able to modify protected parts of the file system"（路径处理问题）与"An attacker with physical access to a trust-paired device may be able to read and write arbitrary files"（路径穿越问题）。两条都在**文件系统路径处理**上，与"副本的归属、可解性或删除"无关。

因此公告口径在这一层能给出的最强表述是：**"处理备份相关代码路径的那个守护进程有缺陷"**，而不是"备份功能有缺陷"，更不是"备份数据可被读取"。这就是 F4 的具体内容，也是脚本把 `advisory.label_present_in_advisory` 与 `advisory.semantic_hit` 分成两栏的原因：组件名出现与否、和描述文本是否真的含备份语义，是两件事（V01、V02）。

### 13.2 三层口径都为空

| 口径 | 本轮读数 | 备份/恢复语义命中 |
| --- | --- | --- |
| 安全公告（CSAF，三份并行版本线） | 392 条 CVE 行 | 2 行含 backup 一词，均为组件名；语义命中 0 |
| CISA KEV（Apple 行） | 95 条 | **0**（本轮 24 个副本相关用词在该 95 条描述里全部为 0） |
| 公开安全发布索引 | 331 行 | backup / restore / keybag / escrow 各 **0** |

一片同时为空的证据不是"这里没问题"，而是"**这里无法用该口径表达**"。任何"某 CVE 影响 iCloud 备份"或"某次更新修复了备份链路的归属问题"的说法，本文按 F5 判定为不可证——不是判定为假。

### 13.3 合规声明应该落在哪一格

如果一个组织要就"员工设备上的数据副本"出具声明，可落点的强度排序如下：

| 落点 | 强度 | 说明 |
| --- | --- | --- |
| 台账本身（介质、形态、keybag、custody、快照日、删除与轮换事件） | 高 | 本文两个脚本能逐项核验 |
| 支持文档口径（180 天窗口、加密备份开关、跨类型不迁移清单） | 中高 | 面向用户，颗粒度粗但可核对 |
| 平台安全口径（第 1996—1998、2722—2746 行机制） | 高（作为依据，不作为读数） | 它给机制，不给"这台设备此刻"的状态 |
| 公告与 KEV | 低（在这一层几乎不可用） | 组件名能对上，语义对不上 |
| 管理协议 | 空集 | 没有对应动作，不能作为声明来源 |

第四、五行需要写明限制，否则声明会在审计时失效：一份"依据 Apple 安全公告，已修复备份相关风险"的表述，与本文第 13.2 节的三层读数直接冲突；一份"通过设备管理策略确保员工设备备份已加密"的表述，与第 12.1 节的空集冲突。脚本对这两处分别给 V04（公告面为空却登记义务记录）与 M02—M04。

### 13.4 组件标签漂移

第 09 篇已经完整处理过组件标签在并行版本线之间漂移的论证，本文不重复其方法。这里只取与副本有关的一点：**`MobileBackup` 只出现在一条版本线里**，在另外两条的 134 与 163 行中一次都没有出现。把"某组件名在公告里出现"当成"这一代版本修了备份"，是同一处换算失败的副本侧表现——脚本对此只要求 `label_present_in_advisory` 与 `semantic_hit` 都显式登记，缺项即 V01。

### 13.5 失败形态

| 失败形态 | 脚本信号 |
| --- | --- |
| 有组件名但没有命中读数 | V01 |
| 把 `MobileBackup` 的行当成备份语义命中 | V02 |
| 声明在 KEV 里但没给 CVE 主键 | V03 |
| 公告面为空却登记义务记录 | V04 |
| 三栏全空（无任何第三方口径） | B01（非阻断，说明缺少支撑而非记录错误） |

## 14. 缺陷类型学 P1—P12

前面十三章把这条链路一层层拆开，得到的是一个结论：**这一层上的问题绝大多数不是"漏洞"，而是"记错"**。介质记错、形态记错、口令归属记错、把组件名当成语义命中、把文件删除当成可读性消失——这些错误本身不产生数据泄露，但它们让所有后续的判定失去依据。所以本章给出十二种缺陷类型，每一种都对应脚本里的一组信号码，可以直接拿去做台账审计的清单。

需要先说明记法：P 系列的编号表示缺陷类型，不是严重程度。严重程度由第十九章的 J1—J4 给出，因为同一种类型在不同副本上的后果差别很大——P4（口令入台账）在一台个人设备上是可以靠删除字段解决的事情，在一份会被交接的组织台账里则是必须先解决的阻塞项。

### 14.1 十二种类型总览

| 编号 | 类型 | 一句话表述 | 主要信号（脚本一） | 主要信号（脚本二） |
| --- | --- | --- | --- | --- |
| P1 | 介质归属误记 | 把副本记在不能承载它的介质上 | A02、A03、A07、M05、B04 | Z01、Z02、Z05 |
| P2 | 形态误记 | 加密本地、未加密本地、iCloud 备份三者混记 | A02、A03、C10、K02 | Z01、Z03、Z04 |
| P3 | 口令归属无主 | 加密本地副本没记 `password_owner` | K03、H02 | Z04 |
| P4 | 口令入台账 | 把备份口令的值写进台账 | K05 | —（本口径直接拒收） |
| P5 | 拉伸读数与口径不符 | 迭代次数低于公开口径或未登记 | K04 | — |
| P6 | 服务密钥 custody 缺格 | iCloud 副本不声明密钥在哪 | K06、A08、K07 | Z05、Z06 |
| P7 | 端到端与"随机密钥同存"混用 | 两类密钥事实同时为真 | K08、K09、K10 | Z07 |
| P8 | 排除标记当成保证 | 把 `isExcludedFromBackup` 写成"保证不含" | C06 | — |
| P9 | 内容集合越界声明 | 声明副本含有被明确排除的类别 | C01—C05、C07—C09 | — |
| P10 | 删除结论只有文件级 | 说"删了"但没有密钥侧证据 | D01—D05、D08 | Z08、Z09 |
| P11 | 无轮换日的"已清除"声明 | 声称不可读但给不出事件时刻 | K09、D04 | Z07、Y02 |
| P12 | 恢复侧归属反转未记 | 恢复带来的密钥/退管/配对后果没登记 | R01—R07 | Y03、Y01 |

表中 P11 那一格留了个问号，是因为它在脚本一里没有独立编号——它由 K09（记了"密钥与副本同处"但无 `key.rotated_at`）与 D04（实证级删除结论但无 `key_rotated_after_delete`）两处共同覆盖。这不是遗漏，而是这类缺陷的真实表现方式：**它总是同时出现在"密钥登记"和"删除结论"两个位置**，单独修一个另一个仍然不闭合。

### 14.2 P1 介质归属误记

最常见的写法是把 iCloud 副本的状态记到电脑上去核对，或者反过来。这不只是流程混乱，它有明确的判定后果：

- `copy.medium=icloud` 与 `copy.kind=local_encrypted` 同时出现（A03）：加密本地备份的 backup keybag 落在那台用于同步的电脑上（平台安全指南第 1996 行）。把它记成 iCloud 介质，等于把一个"需要口令"的对象登记成"账号可及"的对象。
- `copy.medium=computer` 与 `copy.kind=icloud_backup` 同时出现（A03）：iCloud Backup keybag 属账号侧（第 2015—2016 行）。
- 第三方服务上的副本只有记为 `kind=archive` 才在本口径内（A03）：Apple 文档不描述第三方备份的密钥形态，这一格没有任何依据可以支撑更强的声明。
- 读数来源与介质冲突（A07）：`source_of_record=computer_app` 但介质是 iCloud。设备端只显示设备侧副本清单，电脑端只显示那台电脑上的副本清单，两端都不显示账号里的全部副本。这一条单独看像 clerical error，但它决定了这份记录**能不能被第三方向同一个读数复核**。
- 管理面越权声明（M05）：`mgmt.org_visibility=attested` 而介质是电脑。第 12.2 节已经给过理由。

脚本二的 Z01/Z02/Z05 是同一类缺陷在三件比对场景下的表现：keybag 类与介质矛盾。backup keybag 记在 iCloud 介质上、escrow keybag 记在 iCloud 介质上、iCloud 副本记为设备绑定，都是归属层的介质误记。

**修复动作**：介质与形态必须成对登记，且必须与 `source_of_record` 一致。缺任意一格即 A02，脚本判定为 J4（只观察到副本存在）。

### 14.3 P2 形态误记

三种形态对应三套完全不同的密钥事实，本文第二章那张分工表里已经说明形态归本篇、类归第 02 篇。这里的缺陷表现为"形态与密钥类对不上"：

- `kind=local_plain` 却挂 `keybag_kind=backup`（K02）：backup keybag 由加密备份创建（第 1996 行）。未加密时文件不加密，但钥匙串项仍受 UID 派生密钥保护（第 1998 行）——这两件事必须分开记，不能因为"整体没加密"就把钥匙串也记成明文。
- `medium=icloud` 与 `kind=local_plain` 冲突（C10）：iCloud 侧副本始终处于加密存储，公开口径的差异在**服务密钥归属**而不是"是否加密"。把 iCloud 副本记成"未加密"是一种尤其危险的误记，因为它会让人以为存在一个不需要处理密钥的分支。
- 脚本二侧对应 Z03（未加密本地副本挂了口令归属）与 Z04（加密本地副本的口令归属为空）。

**修复动作**：先定形态，再按形态决定哪几格是必填。`local_encrypted` → 必填 `password_owner`、`pbkdf2_iterations`；`local_plain` → 必须明确 `keychain_uid_protected`；`icloud_backup` → 必填 `service_key_custody`。

### 14.4 P3 口令归属无主

`local_encrypted` 这一类副本没有设备绑定——第 1997 行的原话是"there's no tie to a specific device"。这意味着它的可解密性**完全**落在口令归属上。不记口令归属等于把这一类副本记成了"谁都可能拿着"。

K03 拦住空值，H02 拦住冲突值（个人持有者的加密本地副本记为组织掌握口令），H06 拦住更隐蔽的一种：口令共享且登记了拉伸次数。第 1997 行给出的缓解手段只有口令本身，共享口令把单台设备的边界变成一组人的边界——注意这条不针对任何"口令强度计算"，它只是指出：**这一层唯一的人为控制点在多个主体之间扩散了**。

**修复动作**：`key.password_owner` 取 `holder` / `org` / `third_party` / `unknown` / `none` 五值之一。`unknown` 是合法值而不是失败——它是"承认不可判定"，脚本据此把该副本停在 J3。真正的问题是把 `unknown` 留空，因为留空与登记为未知在审计上是两件事。

### 14.5 P4 口令入台账

本文的硬性排除项之一，也是脚本一里唯一一条"不是判定而是拒收"的信号：**`key.password_recorded=true` 直接触发 K05，要求删除该字段**。

这与第 10 篇的 L05 是同一处口径。理由不是技术上的，而是台账性质上的：一份会交接、会被复制、会进入审计材料的台账，一旦含口令值，它就不再是"归属记录"而是"凭据存储"。本框架不接受这种对象，也不为它提供任何折中（例如"记哈希"或"记前四位"）。台账需要知道的只有两件事：**口令归谁**，以及**这一代副本有没有设备绑定**。

**修复动作**：删除 `key.password_recorded` 及其值，只保留 `password_owner` 与 `device_bound`。K05 是阻断信号，任何含它的副本最高只能到 J2。

### 14.6 P5 拉伸读数与口径不符

`key.pbkdf2_iterations` 低于公开口径的 1,000 万次（平台安全指南第 1997 行）触发 K04，加密本地备份完全没记该项也触发 K04。

两种触发对应两种不同问题。数值偏低意味着：要么读数来源不对，要么这一代副本不是按该口径生成的——后者是有价值的信息，它说明手上这份副本比口径所描述的更弱，需要单独定责。空值意味着：连"这一代是按什么强度生成的"都不知道。

这里要防止一种误用：**K04 不是强度评估**。本文不给出口令熵、破解时长或任何可用于评估"多久能解开"的数字；PBKDF2 迭代次数在这里的作用只有一个——它是判断"这份副本是否按公开口径的那一代生成"的时间戳型证据。

**修复动作**：读数只登记"来自哪份文档的哪一代口径"，不做任何派生计算；低于口径时按新一代处理并单独定责。

### 14.7 P6 服务密钥 custody 缺格

`kind=icloud_backup` 而未声明 `key.service_key_custody` 触发 K06。第 2722 行说明默认状态下 iCloud Backup 的服务密钥备份在 Apple 的 HSM 里，属"认证后可用"类（第 2667 行）。这一格是空的，就意味着这份 iCloud 副本"对谁可解"没有答案。

同类误记还有两处：
- `custody=apple_hsm` 同时记设备绑定（K07）：认证后可用类密钥由服务端在账户认证后发放（第 2667 行），绑定条件是账号不是设备。
- `kind=icloud_backup` 且 `device_bound=true`（A08）：账号侧备份集落在用户的 Apple 账号里（第 2724 行），绑定的是密钥而非设备。脚本二的 Z05 在同一处给出比对侧的信号。

**修复动作**：`service_key_custody` 取 `apple_hsm` / `trusted_devices` / `unknown` / `not_applicable` 四值之一；对 iCloud 副本而言前三值都有内容，只有 `not_applicable` 是错误答案。

### 14.8 P7 端到端与"随机密钥同存"混用

这是全篇最容易被写对也最容易写错的一格，因为**两句话都在官方文档里**：

- 第 2724 行：iCloud Backup keybag 含非可访问类的 Curve25519 非对称密钥，随机密钥与备份集同处。
- 第 2746 行：开启高级数据保护时，Messages in iCloud 始终端到端加密，且备份整体端到端加密。

把两句叠加成"这份副本端到端加密，并且密钥和备份放在一起"是自相矛盾的（K08）。真实关系是有先后的：默认状态下靠第 2724 行的同存机制；开启高级数据保护后靠第 2746 行的服务密钥轮换。所以正确记法必须带上 `key.rotated_at`（K09 拦住缺项），否则无法证明旧副本失去可读性（第 2680、2746 行）。

`content.messages_key_copy=true` 的两处登记要求（K10）属于同一类：第 2745 行说明关闭备份会生成新密钥、旧容器密钥解不开新写入数据。这条只在有轮换事件日时才成立。

**修复动作**：`service_key_custody=trusted_devices` 时，`random_key_with_set` 必须为 false 或 unknown，且 `rotated_at` 必填；三格里任缺其一，脚本按 J3 停在"密钥归属仍不确定"。

### 14.9 P8 排除标记当成保证

`content.exclusion_guarantees=true` 直接触发 C06。公开口径写得很清楚：`isExcludedFromBackup` 只是给系统的提示，不保证这些项永不出现在备份或恢复后的设备上（《Optimizing Your App's Data for iCloud Backup》第 38 行）；而且常见的文档操作会把该属性重置为 false（《isExcludedFromBackup》第 10 行）。

这一条对应用侧的意义特别大：一个 app 的开发者可能确实在文档里"排除了备份"，但副本清点不能以此为依据写"该 app 数据不在副本里"。正确的两格是：

- `exclusion_marks_used`：这个 app 打了标记（可作为线索）。
- `exclusion_guarantees`：必须为 false 或 unknown（不得为 true）。

第三行的组合值得单独说明：脚本对 `cloudkit_app_data=true, exclusion_marks_used=true, exclusion_guarantees=false` 这一组**不给信号**，因为它是唯一能同时成立的写法——打了标记、不声称保证、且承认数据仍在副本里。反过来，`cloudkit_app_data=true` 而介质是电脑（C09）就仍然要报，因为 app 通过 iCloud Drive 存储的数据存在 iCloud 而不是副本里（《What does iCloud back up?》第 43 行）。

### 14.10 P9 内容集合越界声明

一组"声明副本含有被文档明确排除的类别"的信号，每一条都有独立出处：

| 信号 | 越界声明 | 排除依据 |
| --- | --- | --- |
| C01 | 副本含 Face ID / Touch ID / 设备密码数据 | 加密备份明确不含（《About encrypted backups》第 30 行）；指纹模板不离开设备（第 568 行） |
| C02 | 未加密本地备份含健康数据 | 健康数据只在加密本地备份里存在（第 2275 行） |
| C03 | 电脑侧副本含 HomeKit 数据 | HomeKit 数据不进本地备份（第 4141 行） |
| C04 | 电脑侧副本含 EnergyKit 数据 | 本地备份排除 EnergyKit 数据（第 4095 行） |
| C05 | iCloud 照片已同步却记副本含照片 | 开启 iCloud Photos 后照片与视频不进 iCloud Backup（第 2728 行） |
| C07 | 副本含已购内容本体 | 只含购买记录，恢复时各自从商店下载（第 2727 行） |
| C08 | Apple Watch 记为独立副本内容项 | 手表备份包含在 iPhone 的备份里（《What does iCloud back up?》第 34 行） |

这类缺陷的害处不在"多写了几行"，而在于它会**反过来污染删除判定**：一份声明含健康数据但实际上不含的台账，会让删除范围算得比实际大；一份声明不含照片但实际上含的台账，会让删除范围算得比实际小。第二种才是危险的，而它恰好是最常见的写法（因为"我开了 iCloud Photos，所以照片不在备份里"这句话在开启的情况下成立，在未开启的情况下不成立，而开启状态本身需要单独登记）。

### 14.11 P10 删除结论只有文件级

`delete.deletion_evidence=attested` 但缺少以下任一项，都会撞上对应信号：

| 缺项 | 信号 | 依据 |
| --- | --- | --- |
| 没有 `delete.key_rotated_after_delete` | D04 | 账号侧的可读性由密钥决定（第 2680、2745—2746 行），删除文件本身不等于不可读 |
| `erasure_witness=none` | D03 | 实证级结论没有见证主体 |
| `old_copies_survive=true` | D05 | 仍有旧副本存活时任何一份都能被恢复 |
| 有删除证据但未请求删除 | D02 | 证据不可能先于动作 |
| 请求删除但无时刻 | D01 | 删除动作没有时刻即不可与快照排序 |
| 有轮换证据却记为 inferred | D08 | 轮换是可核验事件（第 2746 行），记 inferred 会让该副本被重复计入待处置队列 |

脚本二在这一格加了两个台账同步信号：已有 `deleted` 回执但在册状态仍是 `listed`（Z08），在册状态为 `retired` 但没有 `deleted` 回执（Z09）。之所以拆成两条，是为了让"清单与处置结果不同步"和"退册没有依据"这两种不同的管理缺陷各自可数，且让 Q1 在三件齐备、时序成立、形态一致时可达。

**P10 的正确出路**在第 11.4 节已经给出四项要求，这里只强调一点：`retention_days` 与 `retained_after_off_days` 两个口径必须一致（D06），否则一份记录同时说了两个删除时间。

### 14.12 P11 无轮换日的"已清除"声明

这一类没有独立编号（见 14.1 的说明），但它是组织场景里出现频率最高的一种。典型表述是"我们已确认该员工离职时的 iCloud 备份不可再访问"。这句话的可核验部分只有两个：**轮换发生在哪一天**，以及**那一天之后有没有新副本**。

- 缺前者 → K09（`random_key_with_set=true` 但 `rotated_at` 为空）或脚本二的 Z07（回执里有 `key_rotated` 事件但密钥件无轮换日，两处记法不一致）。
- 缺后者 → Y02（密钥轮换早于副本快照日：该副本是在轮换后生成的，旧密钥可读性结论要重算）。

Y02 是本篇认为最容易被忽略的一条时序信号。它的含义不是"记错了顺序"，而是**这份副本根本不在轮换的保护范围内**：轮换之后新建的副本用的是新密钥，旧密钥对它无效，但新密钥的可解性又回到第 14.8 节那个问题上。所以对这类副本，正确结论是"旧密钥事件不适用，需要单独一条处置记录"。

### 14.13 P12 恢复侧归属反转未记

恢复不是删除的逆操作，它在这条链路上产生**新的归属事实**。R 系列七条各自拦住一种未记：

| 信号 | 未记内容 | 依据 |
| --- | --- | --- |
| R01 | 没有 `restore_target` | 同机与异机在这条链路上给出相反结论 |
| R02 | 异机恢复但副本记为设备绑定 | 受 UID 保护的项回到别的设备即不可读（第 1996 行） |
| R03 | 异机恢复但未记 `nonmigratory_expected_loss` | 非迁移钥匙串项在别的设备上不可访问是文档写明的结果（第 1996、2742 行） |
| R04 | 恢复前存在硬件绑定密钥但未记退管 | 含该密钥的 ACME 配置在恢复时被移除；若它用于设备管理服务身份则设备退管（第 4416—4417 行） |
| R05 | 同机 iPhone 恢复却记手表配对未保留 | 同机恢复保留既有 Apple Watch 配对（第 1635、1644 行） |
| R06 | 跨设备类型恢复且消息未同步 | 这类恢复不迁移 Messages 及其附件（《Backup methods》第 62 行） |
| R07 | 含 SIM 依赖项却恢复到别的设备 | 语音信箱密码与消息条目需要备份时那张实体 SIM（第 2740—2741 行） |

脚本二的 Y01（删除事件日早于快照日）、Y03（恢复完成日晚于删除事件日）从时序侧覆盖同一件事：**"恢复已完成"与"副本已删除"是有先后的两个事件，任何台账让两者同时为真都会被拦下**。

R04 需要单独强调。它是本篇里唯一一条会改变**设备管理关系**的信号：归属反转不止发生在数据侧，还会发生在设备与组织的关系侧。这条不涉及任何绕过做法，它只是把一个文档写明的后果要求登记进台账。

---

## 15. 归属矩阵：层 × 责任方 × 介质 × 证据

本章把 L1—L10 压成一张可核对的表。四列各自的作用：层给问题，责任方给"该问谁"，介质给"这一格在三种副本上是否同答"，证据给"什么样的记录才算答过"。

| 层 | 归属问题 | 唯一可回答的主体 | 三种介质的答案是否相同 | 可接受证据 | 本篇信号族 |
| --- | --- | --- | --- | --- | --- |
| L1 触发 | 这份副本由谁发起 | 持有者（iCloud 侧为自动条件，电脑侧为发起人） | **不同**：iCloud 由"接电+闲置+Wi-Fi"（第 2722 行），电脑由人发起 | 触发状态 + 读数来源 | A06 |
| L2 落点 | 这份副本在谁的介质上 | 介质所有人 | 不同：icloud / computer / external_volume 三方不同 | 介质 + 形态成对登记 | A02、A03、B04 |
| L3 内容 | 副本里有什么类别 | 无（只有口径能答） | 不同：本地排除 HomeKit/EnergyKit，iCloud 侧照片视开启状态 | 类别逐项三态登记 | C01—C10 |
| L4 排除效力 | 标记是否生效 | 应用开发者 + 平台 | 大体相同（标记语义与介质无关） | 标记使用与保证分开登记 | C06、C09 |
| L5 密钥形态 | 用的是哪一类 keybag | 平台（给出机制）+ 持有者（给出实例） | 不同：backup / icloud_backup / escrow 落点各异 | keybag 类 + 落点 | K01、K02、K12、Z01、Z02 |
| L6 可解性 | 谁能解开它 | **口令归属 + 服务密钥归属两格共同决定** | 不同：电脑侧看口令，iCloud 侧看 custody 档位 | 归属五值 + custody 四值 + 轮换日 | K03—K11、H02、Z03—Z07 |
| L7 恢复 | 恢复后归属是否变化 | 恢复目标设备的主人 | 不同：同机保留配对、异机丢非迁移项 | 恢复目标 + 五项反转 | R01—R07、Y01、Y03 |
| L8 删除 | 是否可证不再可读 | 密钥持有者（不是文件删除者） | 不同：账号侧靠轮换，电脑侧靠口令作废与介质处置 | 四项齐备 | D01—D08、Z08、Z09、Y02 |
| L9 管理面 | 组织能看见什么 | 组织（但受协议空集限制） | 相同：**协议里没有这一格**，三介质一致为空 | `surface=none_documented` 显式登记 | M01—M06、B03 |
| L10 公告口径 | 第三方能否佐证 | 公告发布方 | 不同：组件名可出现，语义在本轮不可出现 | 标签 / 命中 / KEV 三栏分开 | V01—V04、B01 |

### 15.1 这张表里唯一一条跨介质不变式

L9 那一行的"相同"值得单独指出，因为它是本篇最容易被质疑的一条：管理面对副本的可见性在三种介质上一致为空。这条不是"没找到"，而是**在三个不同的协议文档里各自找到了零命中**（第 12.1 节）。它的价值在于：任何一处声称"组织可以通过管理面完成 X"的记录，其成立条件与该副本落在哪个介质无关——这就把一类本来需要逐个介质讨论的声明压缩成了一条可核对的排除项。

### 15.2 两条反直觉的归属

表里 L6 与 L8 各给了一条与直觉相反但文档支持的结论：

- **L6：iCloud 副本不是"Apple 拿着密钥"这么简单**。默认档是服务密钥备份在 Apple 的 HSM（第 2722 行），开启高级数据保护后相关服务私钥不下发到服务器（第 2666 行）。同一份台账里这两档的可解性主体完全不同，而 `custody` 一格必须能区分它们。
- **L8：删除文件的主体不是可解性消失的主体**。第 2680 行说明关闭 iCloud 服务时设备会发起把可用-after-authentication 服务密钥从 Apple 数据中心移除；第 2746 行说明开启高级数据保护时靠服务密钥轮换。两条都不是"删掉那个文件"。所以删除类记录里，`deleted_at` 只覆盖请求与执行，可读性结论必须回到 `key_rotated_after_delete`。

### 15.3 证据强度分层

| 强度 | 证据类型 | 允许的结论 |
| --- | --- | --- |
| 高 | 与该副本一一对应的处置回执（含事件日与见证主体） | 归属结论、删除结论 |
| 中高 | 账号侧元数据三项（设备名称/型号/序列号、应用与文件格式清单、每次快照日期时间大小，支持文档第 205—213 行） | 副本存在性、覆盖类别、时间点 |
| 中 | 设备侧或电脑侧界面读数（`source_of_record=settings_screen/computer_app`） | 单介质状态；不得跨介质引用 |
| 中低 | 机制口径（平台安全指南段落） | 只支持"这类副本如何工作"，不支持"这台设备此刻的状态" |
| 低 | 组件名出现在公告里 | 不支持任何副本层结论 |
| 空 | 管理协议动作 | 不存在，不能作为任何一层的证据 |

第三行与第四行的混用是本篇最常见的证据降级：**把机制读成实例**。脚本用 A01（缺快照日）与 B01（三栏全空）分别拦住"没有时间基准"和"没有任何第三方支撑"，这两处都属于把中低强度证据当高强度使用的后果。

---

## 16. 公开读数：这条链路上能数出来的十八件事

本篇所有结论都必须回到可复核的公开文本。这里把全文用到的读数集中给出，共十八条。每一条都是本轮实际统计或实际摘取的，未做插值；凡"本轮未出现"的表述都指在这些具体文件、这一份快照里的结果。

| 编号 | 读数 | 出处（本轮固定版本） | 本文用途 |
| --- | --- | --- | --- |
| R1 | 平台安全指南本轮快照 **4,885 行 / 697,288 字节 / md5 `d106784191540ae19729ac4aeea7e602`** | Apple Platform Security Guide（段落换行版） | 所有行号引用的定位基准；与第 09、10 篇同一版本，行号可直接互查 |
| R2 | 命中行数：`backup` **43**、`keybag` **42**、`escrow` **30** | 同上，不区分大小写、按行计 | 说明备份与密钥事实在同一份文档里高度集中，可整体覆盖 |
| R3 | 词组命中行数：`iCloud Backup` **23**、`Advanced Data Protection` **25**、`PBKDF2` **4**、`hardware-bound` **7**、`CloudKit` **31** | 同上 | 划定第 9、10 章讨论范围的依据 |
| R4 | keybag 五类：user / device / backup / escrow / iCloud Backup | 第 1976 行 | 第 8 章分类与 K01、Z01—Z02 的依据 |
| R5 | 加密本地备份三件事实：backup keybag 由加密备份创建、由所设口令保护、**无设备绑定** | 第 1996—1997 行 | K02、K03、R02 的依据 |
| R6 | 未加密本地备份两件事实：文件不加密（不论数据保护类）；钥匙串项仍受 UID 派生密钥保护 | 第 1998 行 | K11、Z03 与 P9 的依据 |
| R7 | escrow keybag 落点：用于经 USB 与 Finder/iTunes 同步，也可存在设备管理服务上 | 第 2000 行 | K12、Z02、第 12.4 节唯一连接点的依据 |
| R8 | CloudKit 服务密钥两类：端到端加密类 / 认证后可用类 | 第 2666—2667 行 | P6、P7 与 K07、K08 的依据 |
| R9 | 关闭 iCloud 服务时，设备发起把认证后可用类服务密钥从 Apple 数据中心移除 | 第 2680 行 | D04 与 P10 的核心依据 |
| R10 | 高级数据保护下 Messages in iCloud 始终端到端加密；备份整体端到端；靠服务密钥轮换 | 第 2746 行 | K08、K09、K10、Z07 的依据 |
| R11 | iCloud Backup 的触发前提与 keybag 内容：接电、闲置、连 Wi-Fi 时备份；keybag 含非可访问类的 Curve25519 非对称密钥，随机密钥与备份集同处 | 第 2722、2724 行 | A06、A08 与 P7 的依据 |
| R12 | 内容集合三条：已购内容只含记录（2727）；开启 iCloud Photos 后照片视频不进 iCloud Backup（2728）；健康数据只在加密本地备份（2275） | 第 2727、2728、2275 行 | C02、C05、C07 的依据 |
| R13 | SIM 依赖与钥匙串根：语音信箱密码需要备份时那张实体 SIM；iCloud Backup 备份本地设备钥匙串时用 Secure Enclave 派生密钥加密 | 第 2740—2741、2742 行 | R07、R03、K11 的依据 |
| R14 | iCloud Keychain 托管：向 Apple 托管密钥串数据但不允许 Apple 读取；用托管数据解开随机密钥；托管记录锁定后需联系支持 | 第 2938、2954 行 | K13 与第 10 篇分工的依据 |
| R15 | 两个被明确排除的框架：EnergyKit 数据不进本地备份；HomeKit 数据不进本地备份 | 第 4095、4141 行 | C03、C04 的依据 |
| R16 | 恢复时的两处反转：含硬件绑定密钥的 ACME 配置在恢复时被移除；同机恢复 iCloud 备份保留既有 Apple Watch 配对 | 第 4416—4417、1644（配对段落起于 1635）行 | R04、R05 的依据 |
| R17 | 支持文档五条用户口径：关闭 iCloud 备份后副本保留 **180 天**；手表内容随 iPhone 备份；iCloud Drive 数据存在 iCloud 而非副本；跨设备类型恢复不迁移 Messages 及附件；加密备份不含 Face ID/Touch ID/设备密码 | 《What does iCloud back up?》第 45、34、43 行；《Backup methods for your iPhone or iPad》第 62 行；《About encrypted backups》第 30 行 | A05、C01、C05、C08、R06 的依据 |
| R18 | 第三方口径四处空读数：CSAF 392 条 CVE 行中仅 **2** 行含 backup 一词且均为组件 `MobileBackup`（路径处理、路径穿越）；CISA KEV 的 95 条 Apple 行中副本相关 23 个用词命中 **0**；公开安全发布索引 331 行中 `backup`/`restore`/`keybag`/`escrow` 命中 **0**；MDM 三份文档（命令与查询、声明、描述文件键）中 `backup`/`restore` 各 **0** | 三份并行版本线公告 TSV（95+134+163 行）；KEV Apple 行表；发布索引表；`devicemanagement-commands` / `devicemanagement-declarations` / `profile-specific-payload-keys` | 第 13 章三层为空、第 12.1 节空集结论的依据 |

### 16.1 三条需要注意的读数性质

**R2、R3 是行计数而不是出现次数**。同一行里出现两次 `backup` 只算 1。这个选择是刻意的：本口径只关心"哪些段落涉及副本"，不关心词频本身；按行计可以直接回指到具体段落并逐段核对，按次计不能。

**R17 里的 180 天是唯一一个纯数值口径**。它同时也是最容易失效的一条——支持文档的用户界面表述会随版本变化。台账把它记成 `retained_after_off_days` 而不是写死数字，就是为了让这条在失效时能被 A05 检出（本文 A05 的实现把 180 当作参考值，任何其它值都要求重新核对出处）。

**R18 的四条空读数不能合并成"没有安全问题"**。第 13.2 节的表述是"这一层无法用该口径表达"。这里补一个方法论说明：把四处空读数并列展示，是为了让读者能对"某 CVE 影响 iCloud 备份"这类说法立即定位它在四个口径里的哪一个应当出现；四个都不出现时，该说法不可证。

### 16.2 KEV 那条读数的限制

R18 里 KEV 的 0 命中需要一条限制说明：同一批 95 条中有 1 条（CVE-2025-43200，处理特制照片时的问题，影响 iOS/iPadOS/macOS/watchOS/visionOS）的描述文本里出现 `iCloud` 一词。它属于产品/服务范围表述，与副本机制无关，且不属于本文统计的 23 个副本相关用词。之所以专门指出，是因为它是唯一一条会被粗心的检索误命中成"备份相关 KEV"的行——本文要求 `advisory.kev_listed` 与 `advisory.kev_cve` 分开登记（V03），正是为了让这种误命中在台账里留下痕迹而不是静默通过。

---

## 17. 可见性边界：这一层读者能拿到什么

上一章给读数，这一章给边界。所谓"可见性边界"指的是：**即使把所有公开文档读完、把所有界面读数记全，仍然有哪些事无法知道**。这一节对防御工作的意义比看起来大——它决定了哪些承诺是可以出的，哪些必须写成不可判定。

### 17.1 四条边界

**V1：能看见"副本存在"，看不见"副本内容"。**
账号侧可读出的最强信息是元数据三项（支持文档第 205—213 行）。它给出设备标识、应用与文件格式清单、每次快照的日期时间与大小。这三项不需要解开副本就能读出，因此可以交给审计；但它们证明的是"有这个人的副本存在、覆盖了哪些类别"，不证明内容。大小读数（`copy.size_bytes`）尤其容易被当成内容证据——A04 拦住非正数，但即便数值正确，它也只能与配额读数交叉核对，不能反推内容。

**V2：能看见"类别清单"，看不见"逐条数据"。**
第 6 章那张进/出清单是按类别给的。它无法回答"这条消息在不在里面""这个健康记录在不在里面"。跨设备类型恢复时 Messages 不迁移（《Backup methods》第 62 行）这类事实是**类别级**的，落到单条数据时需要另外的证据，而本层不提供。这也是 R06 只在类别级报警、不做更细断言的原因。

**V3：能看见"自己账号侧的读数"，看不见"别人手上的副本"。**
设备界面与电脑端应用各自只显示自己那一侧的副本清单。这意味着：**持有者无法穷举自己数据的副本**。第 11 章的可证删除性之所以要求 `old_copies_survive`，就是因为这一条边界使"确认没有别的副本"在文档层面不可达成——只能在登记范围内声明。脚本对承认异地副本却不记旧副本存活的写法给 H05。

**V4：能看见"机制口径"，看不见"这台设备此刻的状态"。**
第 1996—1998、2722—2746 行给的是机制，不给实例状态。把机制读成实例的代价在 15.3 节最后一行已经说明。台账里唯一能把两者连起来的是快照日期（`copy.snapshot_date`）：A01 之所以是硬性缺项，是因为没有时间基准时，机制口径与实例状态之间根本没有对接点。

### 17.2 四条边界各自的"越界代价"

| 边界 | 如果有人声称越过 | 该声称的代价 | 台账处理 |
| --- | --- | --- | --- |
| V1 | "我们核对了副本里的具体内容" | 需要能解开副本 → 落入本文排除项 | 不接受；改为记内容集合类别 |
| V2 | "该 app 的每条记录都不在备份里" | 需要逐条比对，且排除标记不保证（第 14.9 节） | C06；只允许 `exclusion_marks_used` |
| V3 | "确认全网只剩一份副本且已删除" | 需要跨账号、跨介质的穷举读数，本层无此读数 | H05、D05；删除结论限定在登记范围内 |
| V4 | "根据平台安全指南，该设备当前备份已加密" | 指南不描述设备状态；加密开关是可核对读数但不是该指南给的 | A01、B01；要求读数来源与快照日 |

V1 那一行需要说明：本文不是断言"核对内容不可能"，而是断言**在公开文档 + 只读台账这条路径上不可能**。后者才是本篇的口径边界，第二章 2.3 节列出的排除项对应的正是这一条。

### 17.3 一条被本文接受的"弱可见性"

`mgmt.org_visibility=none` 常被当成记账失败，但本篇把它记为合法值（B03，非阻断）。理由是第 12.1 节：协议里根本没有这一格，因此管理面的零可见是**协议缺位的直接后果，不是记录错误**。把这条与"没核对所以不知道"区分开很重要——前者是可以出具声明的（"依据管理协议公开文档，管理面不含列出或删除用户备份的动作"），后者不能。

这也是本篇对"可见性"与"可核对性"做的最后一处区分：**可见性描述你能看到什么，可核对性描述你的记录能不能被第三方向同一个来源复核**。`source_of_record` 那一格（A07）管的是后者，`org_visibility` 那一格管的是前者；两者混用是组织台账里最难追溯的一类错误，因为它在读数上完全一致。

---

## 18. 四个读数面：设备侧、电脑侧、账号侧、管理侧

同一份副本状态，在四个面上能读出的东西不一样，且**没有一面能读出全部**。本章把四个面各自的能力与限制钉住，供 `copy.source_of_record` 与 `mgmt.org_visibility` 两格选值时查。

| 面 | 能读出 | 读不出 | 对应台账值 | 主要风险 |
| --- | --- | --- | --- | --- |
| 设备侧（设置界面） | 备份开关、上一次备份时间、副本大小、iCloud 存储用量、高级数据保护开关状态 | 该副本的 keybag 类型、服务密钥档位、他人手上的副本 | `source_of_record=settings_screen` | 把开关状态读成加密状态（V4） |
| 电脑侧（Finder / iTunes / 设备管理应用） | 本机上的本地副本清单、是否勾选加密、口令是否已设 | 账号侧 iCloud 副本、口令归属的第三方认定 | `source_of_record=computer_app` | 跨介质引用（A07）；把"本机有"读成"只有本机有" |
| 账号侧（iCloud 设置 / 数据与隐私） | 元数据三项（第 205—213 行）、下载请求、备份列表与快照日期 | 内容本身、本地副本、任何已删除项的残留 | `source_of_record=attested`（需与处置回执配套） | 把类别清单当内容证据（V1、V2） |
| 管理侧（MDM 服务） | 设备在管状态、设备元数据 | **副本的一切**（第 12.1 节空集） | `org_visibility=none` / `device_side_artifact` | 把设备产物当副本证据（M05） |

### 18.1 四个面都不提供的读数：口令归属的第三方认定

口令归属（`key.password_owner`）在本篇里只能由持有者或组织的口令管理制度自陈，四个读数面都不输出它：设备侧只显示"已设口令"而不显示归谁，电脑侧只显示"这台电脑的备份口令"这一事实，账号侧与管理侧完全无关。

这就是为什么 K03 是阻断信号而不是警告：**在加密本地这一类副本上，唯一决定可解性的那一格，没有任何界面能替我们填**。台账只能靠流程（登记、交接、复核）而不是靠读数把它填上；这也意味着该格的证据强度上限只能到"高（自陈 + 回执）"，不能因为"界面上确认过"就升级。

### 18.2 快照必须同时记"面"和"时刻"

本篇推荐的最小可核对单元是 **(介质, 形态, 读数来源, 快照时刻)** 四元组。缺任何一项时对应信号：

| 缺项 | 信号 | 后果 |
| --- | --- | --- |
| 缺读数来源 | A01 | 无法判断这条能不能被第三方向同一处复核 |
| 缺快照时刻 | A01 | 删除、轮换、恢复三类事件无法排序（T01—T03 全部失去依据） |
| 缺介质 | A02 | 责任方无从确定（第 15 章整列塌掉） |
| 缺形态 | A02 | 三套密钥事实混成一格（P2） |
| 缺时区 | E04 / T04 | 跨区副本无法定序 |

四元组齐备的副本，在脚本一里满足 `have` 条件，最高可以走到 J2；再补上密钥归属与内容集合才到 J3、J1。第十九章给出完整判定条件。

### 18.3 台账自带的设备元数据不能替代四元组

`device.model` / `device.serial` / `device.os_version` / `device.snapshot_date` / `device.audit_date` 这些元字段描述**设备**，不描述**副本**。脚本对它们只做形态校验（U05—U07）与时序校验（T01—T04），一旦把设备元数据当成副本读数就会撞上 A 组信号：例如设备快照日与副本快照日不一致时，T01 报"审计对象不是这份副本"，这条比任何内容层面的讨论都更早决定台账有没有意义。

---

## 19. 四级判定模型

本篇的判定单位是**一份副本**，不是一个人、一台设备或一个组织。四级模型给出的不是"安全等级"，而是"**这份台账能支撑到哪一层结论**"。这一区别决定了它在实践中的用法：J2 不是不合格，J2 只是说明"还不可以就这份副本说任何关于内容的话"。

### 19.1 四级的定义与门槛

判定按四条齐备性递进，加一条阻断信号计数：

| 级 | 名称 | 齐备条件 | 允许的结论 | 禁止的结论 |
| --- | --- | --- | --- | --- |
| **J4** | 只观察到副本存在 | 介质、形态、时间基准、读数来源、密钥类五项未齐；**或**阻断信号 ≥ 6 条 | "某处有一份副本" | 一切归属、可解性、内容、删除结论 |
| **J3** | 本体可登记，密钥归属不确定 | 上述五项齐且阻断 < 6，但 `password_owner` 或 `service_key_custody` 缺格（或口令入台账） | 介质层责任划分、时间排序 | 任何"这份副本对谁可解"的结论 |
| **J2** | 可解性可判定，内容集合不完整 | 密钥两格齐，但内容五项（健康/钥匙串/HomeKit/EnergyKit/生物特征）未齐或阻断 ≥ 1 | 可解性归属、密钥形态判断 | 任何"副本含什么"的判断 |
| **J1** | 四项齐备 | 内容五项齐且无阻断信号 | 归责表述；若删除结论也可核验，则出具"已处置" | — |
| **J1（降级变体）** | 介质/密钥/内容齐，删除不可核验 | `delete` 组不达可核验条件 | 能定责"该谁处置" | **不能**定责"是否已处置" |

最后一行是本篇与常见四级模型的最大差异：**J1 有两种**。它们同属可出归责表述的层级，但在删除声明能力上完全不同，脚本用不同的消息文本区分（第 19 章末尾的 19.4 给出原文）。把两者合并成一个"合格"是危险的——那会让一份从未做过轮换登记的台账出现在"已删除"的统计里。

### 19.2 齐备条件的精确形式

四个谓词与脚本一里的实现一致，此处原样给出以便复核：

- `have` = 形态 ∧ 介质 ∧ 副本快照日 ∧ keybag 类 ∧ 读数来源
- `keyok` = 口令归属 ∧ 服务密钥归属 ∧ ¬(口令入台账)
- `sete` = 健康 ∧ 钥匙串 ∧ HomeKit ∧ EnergyKit ∧ 生物特征
- `dele` = 已请求删除 ∧ [（实证级 ∧ 删除后已轮换 ∧ 见证主体非 none ∧ ¬旧副本存活）∨（推断级 ∧ 有删除时刻 ∧ ¬旧副本存活）]

判定顺序（先命中先出）：

```
!have || blk >= 6      -> J4
!keyok || blk >= 3     -> J3
!sete  || blk >= 1     -> J2
!dele                  -> J1（降级变体）
否则                    -> J1（齐备）
```

其中 `blk` 是阻断类信号条数，不含 B 组（B01—B04 为非阻断结构性提示）。

### 19.3 为什么阈值取 6 / 3 / 1

三个门槛不是从统计里来的，而是从"错误传播范围"来的，选值过程值得写下来，因为它决定了一个副本被误降级时能不能看出来。

- **blk ≥ 6 判 J4**：一条阻断信号通常是笔误，六条同时存在时更可能是这份记录整体不可用。取 6 而不是 5，是因为枚举族（E01—E05）在一份字段很多的台账上很容易连带命中 2—3 条；如果阈值取 3，一份只写错枚举但实质可读的记录会被打成 J4。
- **blk ≥ 3 判 J3**：三条以上意味着错误已经跨出单一命名空间。本文的信号族彼此正交（U/E/A/K/C/D/R/M/V/H/T 各管一段），三条同时命中很难是同一处笔误的连锁。
- **blk ≥ 1 判 J2**：到这一层开始允许"副本含什么"的判断，因此要求零阻断。这里刻意严格：内容级声明是可交付的结论，而一条未清的枚举或形态冲突就能翻转它。

这套阈值的代价是**同一条错误在不同层级上的敏感度不同**：一份 J1 台账少一条信号就合格，一份 J4 台账多两条信号也不改变结论。运营上因此要用第二十章的 O2（阻断信号密度）而不是 O1（齐备率）来做趋势监测。

### 19.4 脚本一的实际输出行

四级判定在输出里每份副本一行，原文如下（这是脚本里 `emit` 的字符串，未改写）：

| 码 | 输出文本 |
| --- | --- |
| J4 | 只观察到副本存在：介质、形态、时间基准、读数来源或密钥类未齐，或阻断信号不少于 6 条 |
| J3 | 副本本体可登记，密钥归属仍不确定：不能判断该副本对谁可解 |
| J2 | 可判断可解性与密钥形态，内容集合与排除项不完整：不能对该副本做含什么的判断 |
| J1 | 介质、密钥、内容三项齐备，但没有可核验的删除结论：能定责"该谁处置"，不能定责"是否已处置" |
| J1 | 介质、密钥、内容、删除四项齐备且无阻断信号：可进入归责表述 |

脚本二给出的是另一套四级（Q1—Q4），单位同样是副本，但问的是"这份副本的身份能不能在三件文档之间闭合"：

| 码 | 输出文本 | 判定条件（脚本原文） |
| --- | --- | --- |
| Q4 | 三件不齐或本副本行形态不可解析：差集比对没有可比对象 | 清单/密钥/回执任一件未提供，或 W 组命中 |
| Q3 | 三件齐备但差集非空：这份副本的身份无法在三件之间闭合 | X 组命中 |
| Q2 | 集合闭合但时间序不成立：删除、轮换与恢复的先后不可同时为真 | Y 组命中 |
| Q2 | 集合闭合且时序成立，但密钥形态与介质矛盾：归属结论按最弱一环给出 | Z 组命中 |
| Q1 | 三件闭合、时序成立、形态一致：可对该副本出具归属结论 | 四组皆空 |

两套模型可以并列使用：J 系列管"这份台账本身够不够格"，Q 系列管"这份台账和处置记录之间同不同步"。一份 J1 但 Q3 的副本，其含义是"记录内部完备但外部对不上账"——这在离职交接场景里非常常见，因为两边的填写人不同。

---

## 20. 运营指标 O1—O10

前十几章给判定，本章给可长期跑的指标。所有指标只从两个脚本的汇总行与信号计数取数，不引入任何外部读数，因此可以离线周期化。**指标本身不做告警设计**：告警阈值属于组织自己的风险偏好，本文只给出定义、取数位置与不健康时先查哪一格。

| 编号 | 指标 | 定义与取数 | 健康方向 | 不健康时先查 |
| --- | --- | --- | --- | --- |
| **O1** | 台账齐备率 | (J1 + J2) 副本数 ÷ 副本总数；取脚本一汇总段各行 | ↑ | `have` 五项（A01、A02、A07） |
| **O2** | 阻断信号密度 | 阻断信号条数 ÷ 副本总数；脚本一汇总的"阻断信号条数" | ↓ | 命中的信号族分布；先修 E/U 组再修 A/K 组 |
| **O3** | 密钥归属确定率 | `keyok` 为真的副本数 ÷ 加密本地 + iCloud 两类副本数 | ↑ | K03（口令归属空）、K06（custody 空） |
| **O4** | 口令入册事件数 | K05 计数 | **恒为 0** | 台账采集表单；先删字段再重跑 |
| **O5** | 可证删除覆盖率 | `dele` 为真的副本数 ÷ `delete_requested=true` 的副本数 | ↑ | D01（无时刻）、D04（无轮换）、D05（旧副本存活） |
| **O6** | 轮换事件登记率 | `key.rotated_at` 非空副本数 ÷（`random_key_with_set=true` ∨ `custody=trusted_devices` ∨ `messages_key_copy=true` 的副本数） | ↑ | K09、K10 |
| **O7** | 三件闭合率 | Q1 副本数 ÷ 清单副本总数；取脚本二汇总 | ↑ | X01—X04（差集方向） |
| **O8** | 时序不成立率 | Y 组命中副本数 ÷ 三件齐备副本数 | ↓ | Y01、Y02、Y03 三条中最先命中的那条 |
| **O9** | 管理面越权声明数 | M02 + M03 + M04 计数 | **恒为 0** | 声明来源文档；对照 12.1 节三处零命中 |
| **O10** | 公告口径误用数 | V02 + V04 计数 | ↓，目标 0 | 组件名与语义命中的分栏是否合并填写 |

### 20.1 三组指标的关系

- **O1 与 O2 是一对张力**。O1 会因为大量 J4 记录被清出台账而"变好"，而 O2 会诚实反映同一件事（记录被删而不是被补全）。所以 O1 必须与副本总数并列展示，单独报 O1 会误导。
- **O4、O9 是零值指标**。它们的健康方向不是"越低越好"而是"出现即事件"：O4 意味着凭据进入台账（P4），O9 意味着出现了协议里不存在的动作声明（12.1）。这两条不参与趋势分析，参与审计事件记录。
- **O5 与 O6 必须一起看**。O5 高分母而 O6 低读数，意味着删除结论建立在推断级证据上（D08 的场景）。反过来 O6 高但 O5 低，意味着有轮换事实但没有对应的删除请求记录——这是 Y06 那条"有 deleted 回执但没有 delete_requested"的另一面。

### 20.2 指标的时间维度

所有指标在单份台账快照内计算，跨快照比较时**必须固定 R1 的版本基准**。指南换版会改变行号但不改变判定逻辑；改变判定逻辑的是词表（枚举值）与参考数值（180 天、10,000,000 次迭代）。这两类变动在脚本里都体现为常量，因此趋势断点需要与常量变更事件一并记录，否则会把口径调整读成质量变化。

### 20.3 指标不适用的三处

诚实标注边界：以下三类工作不能用这十条指标衡量。

1. **副本数量的完整性**。V3 边界使"我们已登记该人全部副本"这句话不可核验，因此没有"台账覆盖率"指标。分母只能是"已登记的副本数"。
2. **内容层面的准确性**。V1、V2 决定了本框架无法核对副本内容，也就无法给出"内容声明正确率"。O1 里的 `sete` 检查的是**五项是否登记**，不是登记得对不对。
3. **删除的实际效果**。O5 度量的是"结论是否可核验"，不是"数据是否真的不可读"。后者需要密钥侧证据，而密钥侧证据本身由 `rotated_at` 与见证主体构成，又回到 O6。

第 3 点是本篇最想留住的一条：**指标能证明的是我们的记录质量，不是处置结果**。把它写成前者，是这条链路上唯一诚实的表述方式。

---

## 21. 只读核验脚本一：备份副本台账审查器

### 21.1 用途与边界

`backup-copy-ledger-review.sh` 审查一份或多份**副本台账**，逐字段校验、逐条给信号码，并对每份副本输出 J1—J4 判定。它的定位与本系列前两篇的脚本一致：

- **纯文本、离线、只读**。不联网、不调用任何设备侧或 Apple 命令行工具（不用 `softwareupdate`、`mdmclient`、`profiles`，不调 Apple Configurator、Xcode、`curl`），不修改输入文件。
- **唯一写出目标**是 `mktemp -d` 创建的临时目录，退出时随 `trap` 删除。
- **不含任何备份口令破解、副本提取或解密他人备份的做法**；台账里出现口令值的写法直接触发 K05 并要求删除该字段，脚本不提供任何绕过、规避或恢复技巧。

它做的是**归属判定与口径核对**：字段有没有写、写的话与公开口径是否冲突、同一副本内部是否自相矛盾、事件之间能不能排序。它不校验"写得对不对"（第 3.5 节），因为那需要访问副本，而本脚本的设计前提就是不访问副本。

### 21.2 输入格式

```
用法: backup-copy-ledger-review.sh [-q] 台账文件 [...]
  -q, -h  -q 只输出汇总；-h/--help 显示本帮助
台账行格式: <副本标识>,<字段名>,<值>    # 开头与空行忽略，行尾 CR 忽略
```

一行一条记录，三列，逗号分隔；值里若含逗号，从第三个逗号起全部归入值。字段前缀共九个命名空间：`copy.` / `key.` / `content.` / `delete.` / `restore.` / `mgmt.` / `advisory.` / `holder.` / `device.`，完整字段清单见第 3.1 节；前缀不在清单内即 U01。

| 解析层信号 | 触发条件 |
| --- | --- |
| U01 | 行不足三列；或字段前缀不在本轮命名空间内 |
| U02 | 副本标识为空 |
| U03 | 同一副本同一字段出现两个不同值 |
| U04 | 值含首尾空格（会让枚举比对静默失败） |
| U05—U07 | `device.model` / `device.serial` / `device.os_version` 形态不符 |

### 21.3 输出形态

逐条信号行是 `信号码<TAB>副本标识<TAB>说明`，说明里带出处行号；末尾是按副本给出的 J1—J4 判定行，然后是一段汇总：

```
副本数=N 信号行数=M
不同信号码=K 阻断信号条数=B
  <码>=<计数>（按首次出现顺序）
```

**阻断信号**定义为除 `B*`（结构性提示）与 `J*`（判定本身）之外的全部信号；只要阻断条数大于 0，脚本退出码为 1（第 23.5 节）。这一条决定了它可以直接接进周期性检查任务：退出码即结论，不需要解析文本。

### 21.4 实跑结果

两个样本都在本轮实际执行过，输出原样摘录。

**好样本**（`fx/good.tsv`，2 份副本：一份 iCloud、一份加密本地）：

```
B03	COPY-ICLOUD	管理面对该副本零可见：这是协议层缺位的直接后果，不是记录错误
J1	COPY-ICLOUD	介质、密钥、内容、删除四项齐备且无阻断信号：可进入归责表述
B03	COPY-LOCAL	管理面对该副本零可见：这是协议层缺位的直接后果，不是记录错误
J1	COPY-LOCAL	介质、密钥、内容三项齐备，但没有可核验的删除结论：能定责「该谁处置」，不能定责「是否已处置」
副本数=2 信号行数=4
不同信号码=2 阻断信号条数=0
  B03=2
  J1=2
```

退出码 0。注意 J1 的两种形态在同一样本里同时出现：`COPY-ICLOUD` 走到"四项齐备"，`COPY-LOCAL` 停在"没有可核验的删除结论"——这正是第 19.1 节所说"J1 有两种"的实际输出。B03 保留而不视为缺陷，理由见第 17.3 节。

**坏样本**（`fx/bad.tsv`，11 份命名为 BAD-A…BAD-K 的副本 + 2 行畸形记录）：

```
副本数=11 信号行数=145
不同信号码=85 阻断信号条数=124
  J4=7  J3=3  J2=1
```

退出码 1。7 份落在 J4、3 份落在 J3、1 份落在 J2，没有一份到达 J1；145 条信号里 124 条为阻断级。这个样本的作用不是"演示很多错误"，而是第 23.2 节的覆盖证据：**85 个码全部被触发**，加上好样本提供的 J1，脚本一的全部 86 个信号码在本轮都有实跑记录。

### 21.5 使用限制

1. **枚举词表是本轮口径**，不是 Apple 的接口契约。词表变更要走"先改文档再改脚本"的顺序（第 26.1 节原则 2）。
2. **缺格与错格分开报**：缺格走 A/K/C/D/R/M/V/H 各族的"未记录"分支，错格走 E 族与冲突分支。合并这两类会让台账改进方向失真——缺格要补流程，错格要改表单。
3. **`unknown` 是合法值**。多数三态字段接受 `unknown`，它表示"承认不可判定"，与留空不同：留空触发缺格信号，`unknown` 不触发。第 14.4 节 P3 那一处说明了为什么这个区分重要。
4. **本脚本一次读入全部文件后按副本聚合**，因此多份台账合并审查时副本标识必须全局唯一；跨文件重名会在 U03 里表现为"同一字段两条不同值"，而不是"两份台账重名"。

脚本全文（337 行）：

```bash
#!/usr/bin/env bash
# backup-copy-ledger-review.sh —— 备份副本台账审查器（离线 / 只读 / 不联网 / 不碰设备）
# 输入：一份或多份台账文本，每行一条记录：  <副本标识>,<字段名>,<值>
# 输出：逐条信号码 + 每份副本的四级判定（J1—J4） + 汇总
# 本脚本只写归属判定与口径核对：不含任何备份口令破解、副本提取或解密他人备份的做法，
# 也不提供任何绕过、规避或恢复技巧。台账里出现口令值的写法直接触发 K05 并要求删除该字段。
# 本脚本不联网、不调用任何设备侧或 Apple 命令行工具、不修改输入文件；
# 唯一写出目标是 mktemp -d 创建的临时目录，退出时删除。
set -u
LC_ALL=C; export LC_ALL

usage() {
  cat <<'EOF'
用法: backup-copy-ledger-review.sh [-q] 台账文件 [...]
  -q, -h  -q 只输出汇总；-h/--help 显示本帮助
台账行格式: <副本标识>,<字段名>,<值>    # 开头与空行忽略，行尾 CR 忽略
字段命名空间:
  copy.*      副本本体（medium / kind / device_class / snapshot_date / size_bytes /
              backup_toggle / trigger_state / retained_after_off_days / source_of_record）
  key.*       密钥归属（keybag_kind / password_owner / password_recorded /
              pbkdf2_iterations / device_bound / service_key_custody /
              random_key_with_set / rotated_at / messages_key_copy /
              keychain_uid_protected / escrow_attempts_locked）
  content.*   内容集合（includes_health / includes_keychain / includes_homekit /
              includes_energykit / includes_biometric / includes_watch /
              includes_messages / includes_photos / icloud_photos_synced /
              cloudkit_app_data / exclusion_marks_used / exclusion_guarantees /
              purchased_refs_only / sim_dependency）
  delete.*    删除与可证清除（delete_requested / deleted_at / deletion_evidence /
              key_rotated_after_delete / old_copies_survive / erasure_witness / retention_days）
  restore.*   恢复与归属重建（restore_target / cross_device_type /
              nonmigratory_expected_loss / hardware_bound_key_present_before /
              unenroll_after_restore / watch_pairing_preserved / setup_as_new_after）
  mgmt.*      管理面（surface / command_expected / profile_key_present /
              declaration_present / org_visibility）
  advisory.*  公告口径（component_label / label_present_in_advisory / semantic_hit /
              kev_listed / kev_cve）
  holder.*    持有者与义务（role / media_control / obligation_recorded /
              password_knowledge / offsite_copy）
  device.*    台账自带元字段（model / serial / os_version / snapshot_date / audit_date / timezone）
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

TMPD=$(mktemp -d "${TMPDIR:-/tmp}/bclr.XXXXXX") || { echo "无法创建临时目录" >&2; exit 2; }
trap 'rm -rf "$TMPD"' EXIT INT TERM

awk -v QUIET="$QUIET" '
function emit(code, cp, msg) { cnt[code]++; lines[++nline] = sprintf("%s\t%s\t%s", code, (cp==""?"-":cp), msg) }
function DV(c, f,   k) { k = c SUBSEP f; return (k in valof) ? valof[k] : "" }
function istrue(v)  { return (v=="true"||v=="yes"||v=="1") }
function isfalse(v) { return (v=="false"||v=="no"||v=="0") }
function isbool(v)  { return (istrue(v) || isfalse(v)) }
function isint(v)   { return (v ~ /^-?[0-9]+$/) }
function isISOdt(v) { return (v ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]([ T][0-9][0-9]:[0-9][0-9](:[0-9][0-9])?)?([Zz]|[+-][0-9][0-9]:?[0-9][0-9])?$/ && validCal(v)) }
function validCal(v,  p, mo, dy) { split(substr(v,1,10), p, "-"); mo = p[2]+0; dy = p[3]+0; return (mo >= 1 && mo <= 12 && dy >= 1 && dy <= 31) }
function hasTime(v) { return (v ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9][T ].*:/) }
function hasTZ(v)   { return (v ~ /[Zz]$/ || v ~ /[+-][0-9][0-9]:?[0-9][0-9]$/) }
function dayNum(v,  t) { t=v; gsub(/[^0-9]/,"",t); return substr(t,1,8)+0 }
function isSerial(v)  { return (v ~ /^[A-Za-z0-9]{8,14}$/) }
function isModel(v)   { return (v ~ /^[A-Za-z][A-Za-z0-9,._ -]{1,40}$/) }
function isVersion(v) { return (v ~ /^[0-9]+(\.[0-9]+){1,2}$/) }
BEGIN {
  FS=","
  split("icloud computer external_volume third_party_service unknown", m1, " "); for (i in m1) MED[m1[i]]=1
  split("icloud_backup local_encrypted local_plain archive unknown", m2, " ");    for (i in m2) KIND[m2[i]]=1
  split("iphone ipad ipod watch mac appletv vision", m3, " ");                    for (i in m3) CLASS[m3[i]]=1
  split("on off unknown", m4, " ");                                              for (i in m4) TOGL[m4[i]]=1
  split("idle_powered_wifi manual unknown", m5, " ");                             for (i in m5) TRIG[m5[i]]=1
  split("settings_screen computer_app attested unknown", m6, " ");                for (i in m6) SOR[m6[i]]=1
  split("user device backup escrow icloud_backup unknown", m7, " ");              for (i in m7) KBAG[m7[i]]=1
  split("holder org third_party unknown none", m8, " ");                          for (i in m8) POWN[m8[i]]=1
  split("apple_hsm trusted_devices unknown not_applicable", m9, " ");             for (i in m9) CUST[m9[i]]=1
  split("attested inferred none unknown", n1, " ");                               for (i in n1) DEV[n1[i]]=1
  split("holder org vendor none", n2, " ");                                       for (i in n2) WITN[n2[i]]=1
  split("same_device different_device new_device unknown", n3, " ");              for (i in n3) TGT[n3[i]]=1
  split("none_documented vendor_extension unknown", n4, " ");                     for (i in n4) SURF[n4[i]]=1
  split("none device_side_artifact attested unknown", n5, " ");                   for (i in n5) ORGV[n5[i]]=1
  split("MobileBackup Backup libarchive copyfile exFAT APFS Storage file_cmds Time_Zone Spotlight Photos_Storage Health HomeKit Messages CloudKit Keychain iCloud_Drive none unknown", n6, " "); for (i in n6) LAB[n6[i]]=1
  split("individual org third_party_service unknown", n7, " ");                   for (i in n7) ROLE[n7[i]]=1
  split("owned managed unknown", n8, " ");                                        for (i in n8) MCTL[n8[i]]=1
  split("holder_only shared org_held unknown not_applicable", n9, " ");           for (i in n9) PKNO[n9[i]]=1
  split("yes no unknown", o1, " ");                                               for (i in o1) YN[o1[i]]=1
  DTF="copy.snapshot_date delete.deleted_at key.rotated_at device.snapshot_date device.audit_date"
  split("key.device_bound key.random_key_with_set key.messages_key_copy key.keychain_uid_protected key.escrow_attempts_locked content.includes_health content.includes_keychain content.includes_homekit content.includes_energykit content.includes_biometric content.includes_watch content.includes_messages content.includes_photos content.icloud_photos_synced content.cloudkit_app_data content.exclusion_marks_used content.exclusion_guarantees content.purchased_refs_only content.sim_dependency delete.delete_requested delete.key_rotated_after_delete delete.old_copies_survive restore.cross_device_type restore.nonmigratory_expected_loss restore.hardware_bound_key_present_before restore.unenroll_after_restore restore.watch_pairing_preserved restore.setup_as_new_after mgmt.profile_key_present mgmt.declaration_present advisory.semantic_hit advisory.kev_listed holder.obligation_recorded holder.offsite_copy", TBF, " ")
  PBKDOC=10000000
}
{ sub(/\r$/, "") }
/^[ \t]*#/ { next }
/^[ \t]*$/ { next }
{
  if (NF < 3) { emit("U01","-","记录无法解析成〈副本,字段,值〉三列: " $0); next }
  cp=$1; fld=$2; val=$3
  for (i=4; i<=NF; i++) val = val "," $i
  if (cp ~ /^$/) { emit("U02","-","记录缺副本标识，无法逐份判定: " fld); next }
  if (!(cp in seen)) { seen[cp]=++nc; ord[nc]=cp }
  k = cp SUBSEP fld
  if ((k in valof) && valof[k] != val) emit("U03", cp, "同一字段两条不同值: " fld " = [" valof[k] "] 与 [" val "]")
  valof[k]=val
  if (val != "" && (val ~ /^[ \t]/ || val ~ /[ \t]$/)) emit("U04", cp, "值含首尾空格，枚举比对会静默失败: " fld " = [" val "]")
  if (fld !~ /^(copy|key|content|delete|restore|mgmt|advisory|holder|device)\./) emit("U01", cp, "字段名前缀不在本轮口径的命名空间内: " fld)
}
END {
  for (i=1; i<=nc; i++) {
    c = ord[i]
    med  = DV(c,"copy.medium");        kind = DV(c,"copy.kind")
    dcls = DV(c,"copy.device_class");  csnap= DV(c,"copy.snapshot_date")
    size = DV(c,"copy.size_bytes");    tog  = DV(c,"copy.backup_toggle")
    trig = DV(c,"copy.trigger_state"); retof= DV(c,"copy.retained_after_off_days")
    sorc = DV(c,"copy.source_of_record")
    kb   = DV(c,"key.keybag_kind");    pown = DV(c,"key.password_owner")
    prec = DV(c,"key.password_recorded"); pbk = DV(c,"key.pbkdf2_iterations")
    dbnd = DV(c,"key.device_bound");   cust = DV(c,"key.service_key_custody")
    rkws = DV(c,"key.random_key_with_set"); rot = DV(c,"key.rotated_at")
    mkc  = DV(c,"key.messages_key_copy"); kup = DV(c,"key.keychain_uid_protected")
    eal  = DV(c,"key.escrow_attempts_locked")
    ih = DV(c,"content.includes_health");   ik = DV(c,"content.includes_keychain")
    ihome = DV(c,"content.includes_homekit"); ien = DV(c,"content.includes_energykit")
    ibio = DV(c,"content.includes_biometric"); iwa = DV(c,"content.includes_watch")
    imsg = DV(c,"content.includes_messages"); iph = DV(c,"content.includes_photos")
    ips  = DV(c,"content.icloud_photos_synced"); ckad = DV(c,"content.cloudkit_app_data")
    exmu = DV(c,"content.exclusion_marks_used"); exgu = DV(c,"content.exclusion_guarantees")
    pro  = DV(c,"content.purchased_refs_only");  simd = DV(c,"content.sim_dependency")
    dreq = DV(c,"delete.delete_requested"); ddat = DV(c,"delete.deleted_at")
    devi = DV(c,"delete.deletion_evidence");  kroa = DV(c,"delete.key_rotated_after_delete")
    ocs  = DV(c,"delete.old_copies_survive");  eran = DV(c,"delete.erasure_witness")
    rday = DV(c,"delete.retention_days")
    rtgt = DV(c,"restore.restore_target");      rcdt = DV(c,"restore.cross_device_type")
    rmig = DV(c,"restore.nonmigratory_expected_loss")
    rhb  = DV(c,"restore.hardware_bound_key_present_before")
    runr = DV(c,"restore.unenroll_after_restore")
    rwp  = DV(c,"restore.watch_pairing_preserved")
    rsan = DV(c,"restore.setup_as_new_after")
    msur = DV(c,"mgmt.surface");      mcmd = DV(c,"mgmt.command_expected")
    mpro = DV(c,"mgmt.profile_key_present"); mdec = DV(c,"mgmt.declaration_present")
    morg = DV(c,"mgmt.org_visibility")
    alab = DV(c,"advisory.component_label"); alabp = DV(c,"advisory.label_present_in_advisory")
    ase  = DV(c,"advisory.semantic_hit");    akev = DV(c,"advisory.kev_listed")
    akev_c = DV(c,"advisory.kev_cve")
    hrol = DV(c,"holder.role");        hmed = DV(c,"holder.media_control")
    hob  = DV(c,"holder.obligation_recorded"); hpk = DV(c,"holder.password_knowledge")
    hoff = DV(c,"holder.offsite_copy")
    dmod = DV(c,"device.model"); dser = DV(c,"device.serial"); dosv = DV(c,"device.os_version")
    dsnap= DV(c,"device.snapshot_date"); daud = DV(c,"device.audit_date"); dtzn = DV(c,"device.timezone")

    # ---- 元字段形态（U 组收尾） ----
    if (dmod != "" && !isModel(dmod))  emit("U05", c, "device.model [" dmod "] 不是可核对的型号写法")
    if (dser != "" && !isSerial(dser)) emit("U06", c, "device.serial [" dser "] 不在 8—14 位字母数字的窗口内：跨面比对需要稳定的设备主键")
    if (dosv != "" && !isVersion(dosv)) emit("U07", c, "device.os_version [" dosv "] 不是 x.y 或 x.y.z 形态")

    # ---- 枚举与形态（E 组） ----
    if (med !="" && !(med in MED))   emit("E01", c, "copy.medium [" med "] 不在 icloud/computer/external_volume/third_party_service/unknown 词表内")
    if (kind !="" && !(kind in KIND)) emit("E01", c, "copy.kind [" kind "] 不在 icloud_backup/local_encrypted/local_plain/archive/unknown 词表内")
    if (dcls !="" && !(dcls in CLASS)) emit("E01", c, "copy.device_class [" dcls "] 不在 iphone/ipad/ipod/watch/mac/appletv/vision 词表内")
    if (tog !="" && !(tog in TOGL))  emit("E01", c, "copy.backup_toggle [" tog "] 不在 on/off/unknown 词表内")
    if (trig !="" && !(trig in TRIG)) emit("E01", c, "copy.trigger_state [" trig "] 不在 idle_powered_wifi/manual/unknown 词表内")
    if (sorc !="" && !(sorc in SOR)) emit("E01", c, "copy.source_of_record [" sorc "] 不在 settings_screen/computer_app/attested/unknown 词表内")
    if (kb !="" && !(kb in KBAG))    emit("E01", c, "key.keybag_kind [" kb "] 不在 user/device/backup/escrow/icloud_backup/unknown 词表内")
    if (pown !="" && !(pown in POWN)) emit("E01", c, "key.password_owner [" pown "] 不在 holder/org/third_party/unknown/none 词表内")
    if (cust !="" && !(cust in CUST)) emit("E01", c, "key.service_key_custody [" cust "] 不在 apple_hsm/trusted_devices/unknown/not_applicable 词表内")
    if (devi !="" && !(devi in DEV)) emit("E01", c, "delete.deletion_evidence [" devi "] 不在 attested/inferred/none/unknown 词表内")
    if (eran !="" && !(eran in WITN)) emit("E01", c, "delete.erasure_witness [" eran "] 不在 holder/org/vendor/none 词表内")
    if (rtgt !="" && !(rtgt in TGT)) emit("E01", c, "restore.restore_target [" rtgt "] 不在 same_device/different_device/new_device/unknown 词表内")
    if (msur !="" && !(msur in SURF)) emit("E01", c, "mgmt.surface [" msur "] 不在 none_documented/vendor_extension/unknown 词表内")
    if (morg !="" && !(morg in ORGV)) emit("E01", c, "mgmt.org_visibility [" morg "] 不在 none/device_side_artifact/attested/unknown 词表内")
    if (alab !="" && !(alab in LAB)) emit("E01", c, "advisory.component_label [" alab "] 不在本轮公告组件标签词表内")
    if (hrol !="" && !(hrol in ROLE)) emit("E01", c, "holder.role [" hrol "] 不在 individual/org/third_party_service/unknown 词表内")
    if (hmed !="" && !(hmed in MCTL)) emit("E01", c, "holder.media_control [" hmed "] 不在 owned/managed/unknown 词表内")
    if (hpk !="" && !(hpk in PKNO))  emit("E01", c, "holder.password_knowledge [" hpk "] 不在 holder_only/shared/org_held/unknown/not_applicable 词表内")
    if (alabp !="" && !(alabp in YN)) emit("E01", c, "advisory.label_present_in_advisory [" alabp "] 不在 yes/no/unknown 词表内")

    # 三态字段（true/false/unknown）统一校验
    for (t = 1; t in TBF; t++) {
      f = TBF[t]; v = DV(c, f)
      if (v != "" && v != "unknown" && !isbool(v)) emit("E02", c, f " [" v "] 不是三态值（true/false/unknown）")
    }
    split(DTF, DL, " ")
    for (t = 1; t in DL; t++) {
      f = DL[t]; v = DV(c, f)
      if (v == "") continue
      if (!isISOdt(v)) { emit("E03", c, f " [" v "] 不是 ISO 日期或日期时刻"); continue }
      if (hasTime(v) && !hasTZ(v) && dtzn == "") emit("E04", c, f " 带时刻但无时区标记，且台账没有 device.timezone")
    }
    for (t = 1; t < 3; t++) {
      f = (t==1 ? "copy.size_bytes" : "key.pbkdf2_iterations")
      v = DV(c, f)
      if (v != "" && !isint(v)) emit("E05", c, f " [" v "] 不是整数")
    }
    split("copy.retained_after_off_days delete.retention_days", IN2, " ")
    for (t = 1; t in IN2; t++) { v = DV(c, IN2[t]); if (v != "" && (!isint(v) || v+0 < 0)) emit("E05", c, IN2[t] " [" v "] 不是非负整数") }

    # ---- A 副本本体 ----
    if (csnap == "") emit("A01", c, "没有 copy.snapshot_date：副本与设备状态的对应时刻不可追，任何删除或恢复声明都失去时间基准")
    if (sorc == "")  emit("A01", c, "缺 copy.source_of_record：这条读数从设备界面、电脑端应用还是自陈不可区分")
    if (med == "")   emit("A02", c, "未记录 copy.medium：这份副本落在谁的介质上不可判定")
    if (kind == "")  emit("A02", c, "未记录 copy.kind：加密本地备份、未加密本地备份与 iCloud 备份是三套不同的密钥事实")
    if (med == "icloud" && kind == "local_encrypted") emit("A03", c, "medium=icloud 与 kind=local_encrypted 冲突：加密本地备份的 backup keybag 落在那台电脑上（平台安全指南第 1996 行）")
    if (med == "computer" && kind == "icloud_backup") emit("A03", c, "medium=computer 与 kind=icloud_backup 冲突：iCloud Backup keybag 属账号侧（平台安全指南第 2015—2016 行）")
    if (med == "third_party_service" && kind != "archive") emit("A03", c, "第三方服务上的副本只有记为 archive 才在本口径内：Apple 文档不描述第三方备份的密钥形态")
    if (med == "icloud" && kind == "local_plain") emit("A03", c, "iCloud 介质与 local_plain 形态冲突：账号侧副本的公开口径差异在服务密钥归属，不在是否加密")
    if (size != "" && isint(size) && size+0 <= 0) emit("A04", c, "copy.size_bytes [" size "] 非正：副本体积是「这份副本到底存在」的第一读数")
    if (size == "") emit("A04", c, "未记录 copy.size_bytes：无法与账号侧配额读数交叉核对")
    if (retof != "" && isint(retof) && retof+0 != 180 && tog == "off") emit("A05", c, "关闭 iCloud 备份后的保留窗口记为 " retof " 天，公开口径是 180 天（《What does iCloud back up?》第 45 行）")
    if (retof != "" && tog != "off") emit("A05", c, "记了保留窗口但 copy.backup_toggle 不是 off：180 天窗口只在关闭备份之后适用")
    if (trig == "idle_powered_wifi" && med == "computer") emit("A06", c, "把「锁定、接通电源、接入 Wi-Fi」的触发前提记在电脑副本上：这组前提是 iCloud Backup 的条件（平台安全指南第 2722 行），电脑侧副本由人发起")
    if (sorc == "computer_app" && med == "icloud") emit("A07", c, "读数来源记为电脑端应用但介质是 iCloud：两端各自只显示自己那一侧的副本清单")
    if (kind == "icloud_backup" && istrue(dbnd)) emit("A08", c, "iCloud 副本记为设备绑定：账号侧备份集落在用户的 Apple 账号里（平台安全指南第 2724 行），绑定的是密钥而非设备")

    # ---- K 密钥归属 ----
    if (kb == "") emit("K01", c, "未记录 key.keybag_kind：五类 keybag（user / device / backup / escrow / iCloud Backup）各有不同归属（平台安全指南第 1976 行）")
    if (kind == "local_plain" && kb == "backup") emit("K02", c, "未加密本地备份不应挂 backup keybag：backup keybag 由加密备份创建（平台安全指南第 1996 行）；未加密时文件不加密、钥匙串仍受 UID 派生密钥保护（第 1998 行）")
    if (kind == "local_encrypted" && (pown == "" || pown == "unknown")) emit("K03", c, "加密本地备份未声明 key.password_owner：这类副本与设备之间「no tie to a specific device」（第 1997 行），可解密性完全落在口令归属上")
    if (pbk != "" && isint(pbk) && pbk+0 > 0 && pbk+0 < PBKDOC) emit("K04", c, "key.pbkdf2_iterations [" pbk "] 低于公开口径的 1000 万次（平台安全指南第 1997 行）：要么读数错，要么这一代副本不是按该口径生成的")
    if (pbk == "" && kind == "local_encrypted") emit("K04", c, "加密本地备份未记录拉伸次数读数：口令强度是这一层唯一的缓解手段（第 1997 行）")
    if (prec != "" && istrue(prec)) emit("K05", c, "台账落了备份口令（key.password_recorded=true）：本框架拒收，请删除该字段，只保留 key.password_owner 与 key.device_bound")
    if (kind == "icloud_backup" && cust == "") emit("K06", c, "iCloud 副本未声明 key.service_key_custody：默认状态下 iCloud Backup 服务密钥备份在 Apple 的 HSM 里、属「认证后可用」类（平台安全指南第 2722 行）")
    if (cust == "apple_hsm" && istrue(dbnd)) emit("K07", c, "服务密钥在 Apple HSM 同时又记设备绑定：认证后可用类密钥由服务端在账户认证后发放（第 2667 行），绑定条件是账号不是设备")
    if (cust == "trusted_devices" && istrue(rkws)) emit("K08", c, "端到端口径与「随机密钥随备份集同存」同时为真：公开口径是密钥与备份集同处账号（第 2724 行），开启高级数据保护时靠的是服务密钥轮换（第 2746 行）")
    if (istrue(rkws) && rot == "") emit("K09", c, "记了「密钥与副本同处」但没有 key.rotated_at：没有轮换事件日就无法证明旧副本失去可读性（第 2680、2746 行）")
    if (istrue(mkc) && rot == "") emit("K10", c, "Messages 容器密钥副本已入备份但没有 key.rotated_at：关闭备份会生成新密钥、旧容器密钥解不开新写入数据（第 2745 行）")
    if (kind == "local_encrypted" && isfalse(kup)) emit("K11", c, "加密本地备份记 keychain_uid_protected=false：非迁移钥匙串项始终仍由 UID 派生密钥封装（第 1996、1998 行），false 只能说明读数来源不是设备")
    if (kb == "escrow" && med == "icloud") emit("K12", c, "escrow keybag 记在 iCloud 副本上：escrow keybag 存在用于同步的那台电脑或设备管理服务上（第 2000 行）")
    if (istrue(eal) && devi == "attested") emit("K13", c, "托管记录已锁定与「删除已实证」并存：钥匙串托管记录锁定后需致电支持（第 2954 行），这是可用性事件不是清除证据")
    if (kb == "backup" && cust == "apple_hsm") emit("K13", c, "backup keybag 与服务密钥托管并存：本地加密备份的 keybag 落在那台电脑上（第 1996 行），不经 Apple 服务端")

    # ---- C 内容集合 ----
    if (istrue(ibio)) emit("C01", c, "副本声明含生物特征数据：加密备份明确不含 Face ID、Touch ID 或设备密码数据（《About encrypted backups》第 30 行），指纹模板不离开设备（平台安全指南第 568 行）")
    if (kind == "local_plain" && istrue(ih)) emit("C02", c, "未加密本地备份声明含健康数据：健康数据只在加密本地备份里存在（平台安全指南第 2275 行；《Backup methods》第 57 行同口径）")
    if (med == "computer" && istrue(ihome)) emit("C03", c, "电脑侧副本声明含 HomeKit 数据：HomeKit 数据不进本地备份（平台安全指南第 4141 行）")
    if (med == "computer" && istrue(ien)) emit("C04", c, "电脑侧副本声明含 EnergyKit 数据：本地备份排除 EnergyKit 数据（平台安全指南第 4095 行）")
    if (istrue(ips) && istrue(iph)) emit("C05", c, "iCloud 照片已同步却又记副本含照片：使用 iCloud Photos 时照片与视频不进 iCloud Backup（平台安全指南第 2728 行）")
    if (istrue(exgu)) emit("C06", c, "把排除标记写成「保证不含」：isExcludedFromBackup 只是给系统的提示，不保证这些项永不出现在备份或恢复后的设备上（《Optimizing Your App’s Data for iCloud Backup》第 38 行；《isExcludedFromBackup》第 10 行：常见文档操作会把该属性重置为 false）")
    if (isfalse(pro)) emit("C07", c, "副本声明含已购内容本体：公开口径是只含购买记录、恢复时再各自从商店下载（平台安全指南第 2727 行）")
    if (dcls == "watch" && istrue(iwa)) emit("C08", c, "Apple Watch 记为独立副本内容项：手表备份包含在 iPhone 的备份里（《What does iCloud back up?》第 34 行）")
    if (istrue(ckad) && med == "computer") emit("C09", c, "电脑副本声明含 CloudKit 应用数据：app 通过 iCloud Drive 存储的数据存在 iCloud 而不是副本里（《What does iCloud back up?》第 43 行）")
    if (kind == "icloud_backup" && istrue(exmu) && istrue(ckad) && rot == "") emit("C10", c, "同一副本既记了排除标记又含 CloudKit 应用数据且无轮换日：标记不生效（C06）与密钥未轮换（K09）叠加时，这层内容集合判断没有可读结论")

    # ---- D 删除与可证清除 ----
    if (istrue(dreq) && ddat == "") emit("D01", c, "delete.delete_requested=true 但没有 delete.deleted_at：删除动作没有时刻即不可与快照排序")
    if (dreq != "" && isfalse(dreq) && devi != "" && devi != "none") emit("D02", c, "未请求删除却有删除证据 [" devi "]：证据不可能先于动作")
    if (devi == "attested" && eran == "none") emit("D03", c, "deletion_evidence=attested 但 erasure_witness=none：实证级结论没有见证主体")
    if (devi == "attested" && !istrue(kroa)) emit("D04", c, "实证级删除结论但没有 delete.key_rotated_after_delete：账号侧的可读性由密钥决定（平台安全指南第 2680、2745—2746 行），删除文件本身不等于不可读")
    if (devi == "attested" && istrue(ocs)) emit("D05", c, "实证级删除结论与 delete.old_copies_survive=true 并存：仍有旧副本存活时任何一份都能被恢复")
    if (rday != "" && retof != "" && isint(rday) && isint(retof) && rday+0 != retof+0) emit("D06", c, "同一副本两个保留口径：delete.retention_days [" rday "] 与 copy.retained_after_off_days [" retof "] 不一致")
    if (istrue(rsan) && isfalse(dreq)) emit("D07", c, "记了「作为新设备设置」但 delete.delete_requested=false：该操作会创建替换已保存 iCloud 备份的新备份（《Restore your iPhone or iPad from a backup》第 47 行）")
    if (devi == "inferred" && istrue(kroa)) emit("D08", c, "已有密钥轮换证据却只记为 inferred：轮换是可核验事件（第 2746 行），记 inferred 会让该副本被重复计入「不可证」清单")

    # ---- R 恢复与归属重建 ----
    if (rtgt == "") emit("R01", c, "未记录 restore.restore_target：同机恢复与异机恢复在这条链路上给出相反结论")
    if (rtgt == "different_device" && istrue(dbnd)) emit("R02", c, "异机恢复且副本记为设备绑定：受 UID 保护的项回到别的设备即不可读（平台安全指南第 1996 行）")
    if (rtgt == "different_device" && !istrue(rmig)) emit("R03", c, "异机恢复但没有 restore.nonmigratory_expected_loss=true：非迁移钥匙串项在别的设备上不可访问是文档写明的结果（第 1996、2150 行）")
    if (istrue(rhb) && !istrue(runr)) emit("R04", c, "恢复前存在硬件绑定密钥但未记退管：含该密钥的 ACME 配置在恢复时被移除，若它用于设备管理服务身份则设备退管（平台安全指南第 4416—4417 行）")
    if (rtgt == "same_device" && dcls == "iphone" && isfalse(rwp)) emit("R05", c, "同机恢复 iCloud 备份却记手表配对未保留：同机恢复保留既有 Apple Watch 配对（平台安全指南第 1635、1644 行）")
    if (istrue(rcdt) && istrue(imsg) && isfalse(ips)) emit("R06", c, "跨设备类型恢复且消息未同步：这类恢复不迁移 Messages 及其附件（《Backup methods》第 62 行）")
    if (istrue(simd) && rtgt == "different_device") emit("R07", c, "副本含 SIM 依赖项却恢复到别的设备：语音信箱密码与消息条目需要备份时那张实体 SIM（平台安全指南第 2740—2741 行）")

    # ---- M 管理面 ----
    if (msur == "") emit("M01", c, "未记录 mgmt.surface：本口径的前提是设备管理协议里没有备份动作，需要显式登记为 none_documented")
    if (msur == "none_documented" && mcmd != "" && mcmd != "none") emit("M02", c, "mgmt.command_expected [" mcmd "] 指向一条管理命令，而《Commands and queries》与《Declarations》两份文档里 backup 词频均为 0：该动作在协议层不存在")
    if (istrue(mpro)) emit("M03", c, "mgmt.profile_key_present=true：《Profile-specific payload keys》里 backup 词频为 0，本轮口径不接受「存在备份相关描述文件键」的声明")
    if (istrue(mdec)) emit("M04", c, "mgmt.declaration_present=true：声明式管理的公开声明清单里没有备份相关声明，该声明无出处")
    if (morg == "attested" && med == "computer") emit("M05", c, "mgmt.org_visibility=attested 而介质是电脑：本地副本落在那台电脑上（平台安全指南第 1996 行），管理面没有任何读取动作可以证明它")
    if (morg == "" && hrol == "org") emit("M06", c, "持有者是组织但未记 mgmt.org_visibility：这一格决定组织能不能对自己的副本清单做声明")

    # ---- V 公告口径 ----
    if (alab != "" && alab != "none" && alabp == "") emit("V01", c, "advisory.component_label 有值但没有 label_present_in_advisory：组件名与实际是否命中是两件事")
    if (alab == "MobileBackup" && istrue(ase)) emit("V02", c, "MobileBackup 组件下的描述文本不含 backup 语义：本轮三份公告里该组件两行的描述分别是路径处理与路径穿越问题，semantic_hit 应为 no")
    if (akev != "" && istrue(akev) && akev_c == "") emit("V03", c, "advisory.kev_listed=true 但没有 advisory.kev_cve：没有 CVE 主键的在野利用声明无法回查")
    if (alab == "none" && istrue(hob)) emit("V04", c, "公告面为空却登记了义务记录：义务落点不能建立在一个不覆盖该层的口径上（本轮三份公告共 392 行里提到备份的行数为 0）")
    if (alab == "" && istrue(hob)) emit("V04", c, "登记了义务记录但没有 advisory.component_label：副本合规声明缺少公告面")

    # ---- H 持有者与义务 ----
    if (hrol == "") emit("H01", c, "未记录 holder.role：副本归属需要先确定谁是持有者")
    if (kind == "local_encrypted" && hpk == "org_held" && hrol == "individual") emit("H02", c, "个人持有者的加密本地副本记为组织掌握口令：口令归属与角色冲突，而这正是该类副本唯一的边界（平台安全指南第 1997—1998 行）")
    if (hpk == "holder_only" && devi == "attested" && eran == "vendor") emit("H03", c, "口令只有持有者知道，却由厂商见证删除：不掌握口令的一方无法见证该副本解密性的消失")
    if (hmed == "managed" && med == "computer" && !istrue(hob)) emit("H04", c, "介质受管但 holder.obligation_recorded!=true：受管电脑上的副本没有落义务记录")
    if (istrue(hoff) && !istrue(ocs)) emit("H05", c, "承认存在异地副本（holder.offsite_copy=true）却不记 delete.old_copies_survive：可证删除性的结论只能覆盖登记在案的那一份")
    if (hpk == "shared" && kind == "local_encrypted" && pbk != "") emit("H06", c, "口令共享且登记了拉伸次数：这类副本没有设备绑定、可并行尝试（第 1997 行），共享口令会把单台设备的边界变成一组人的边界")

    # ---- T 时间序 ----
    snapv = (csnap != "" ? csnap : dsnap)
    if (snapv != "" && isISOdt(snapv)) {
      if (daud != "" && isISOdt(daud) && dayNum(daud) < dayNum(snapv)) emit("T01", c, "审计日早于副本快照日 [" daud " / " snapv "]：审计对象不是这份副本")
      if (ddat != "" && isISOdt(ddat) && dayNum(ddat) < dayNum(snapv)) emit("T02", c, "删除时刻早于副本快照日：删除的不是这份副本")
      if (rot != "" && isISOdt(rot) && dayNum(rot) < dayNum(snapv)) emit("T03", c, "密钥轮换早于副本快照日：该副本是在轮换后生成的，旧密钥可读性结论要重算")
    }
    if (dtzn == "" && (snapv != "" || ddat != "" || daud != "")) emit("T04", c, "台账含日期字段但没有 device.timezone：跨区副本无法定序")

    # ---- B 组：结构性证据缺位（不计入退出码） ----
    if (alab == "" && ase == "" && akev == "") emit("B01", c, "公告面三栏全空：该副本的合规声明没有第三方口径支撑")
    if (dcls == "watch") emit("B02", c, "配件线副本：手表内容随 iPhone 备份，公告渠道独立（《What does iCloud back up?》第 34 行），本篇矩阵不给它独立责任方")
    if (morg == "none") emit("B03", c, "管理面对该副本零可见：这是协议层缺位的直接后果，不是记录错误")
    if (med == "external_volume" && kind != "archive") emit("B04", c, "外部介质副本形态不是 archive：本轮口径没有 Apple 文档描述该形态的密钥事实")

    # ---- J 判定 ----
    blk = 0
    for (q = 1; q <= nline; q++) {
      split(lines[q], parts, "\t")
      if (parts[2] != c) continue
      code = parts[1]
      if (code ~ /^B/ || code ~ /^J/) continue
      blk++
    }
    have  = (kind != "" && med != "" && csnap != "" && kb != "" && sorc != "")
    keyok = (pown != "" && cust != "" && !istrue(prec))
    sete  = (ih != "" && ik != "" && ihome != "" && ien != "" && ibio != "")
    dele  = (istrue(dreq) && ((devi == "attested" && istrue(kroa) && eran != "none" && !istrue(ocs)) || (devi == "inferred" && ddat != "" && !istrue(ocs))))
    if (!have || blk >= 6)       emit("J4", c, "只观察到副本存在：介质、形态、时间基准、读数来源或密钥类未齐，或阻断信号不少于 6 条")
    else if (!keyok || blk >= 3) emit("J3", c, "副本本体可登记，密钥归属仍不确定：不能判断该副本对谁可解")
    else if (!sete || blk >= 1)  emit("J2", c, "可判断可解性与密钥形态，内容集合与排除项不完整：不能对该副本做含什么的判断")
    else if (!dele)              emit("J1", c, "介质、密钥、内容三项齐备，但没有可核验的删除结论：能定责「该谁处置」，不能定责「是否已处置」")
    else                         emit("J1", c, "介质、密钥、内容、删除四项齐备且无阻断信号：可进入归责表述")
  }

  # ---- 汇总 ----
  if (nline > 0) {
    for (q = 1; q <= nline; q++) print lines[q] > "/dev/stderr"
    if (!QUIET) print "" > "/dev/stderr"
  }
  ndist = 0
  for (code in cnt) ndist++
  blk = 0
  for (code in cnt) if (code !~ /^B/ && code !~ /^J/) blk += cnt[code]
  printf "副本数=%d 信号行数=%d\n", nc, nline
  printf "不同信号码=%d 阻断信号条数=%d\n", ndist, blk
  for (code in cnt) printf "  %s=%d\n", code, cnt[code]
  exit (blk > 0 ? 1 : 0)
}
' "$@"
```

## 22. 只读核验脚本二：三件差集与事件时序比对器

### 22.1 它解决的问题与为什么必须分成三件

脚本一回答"这一格写了没有、写得是否与口径冲突"。它回答不了另一个同样致命的问题：**这份台账与处置记录之间对不对得上**。一份内部完全自洽的副本台账，可能描述的是一份早已被删除的副本；一份写了 `deleted` 的回执，可能指向一份清单上不存在、密钥件里也没有的副本。

所以脚本二把输入拆成三件独立文档，各自回答一件事：

| 件 | 回答的问题 | 谁通常持有 |
| --- | --- | --- |
| 清单件（L） | 有哪些副本、在谁的设备上、什么时候的 | 设备/账号台账维护方 |
| 密钥件（K） | 每份副本的密钥形态与归属事实 | 安全/密钥管理方 |
| 回执件（R） | 发生过哪些处置动作、何时、谁见证 | 处置执行方 |

三件分开的意义在于**它们由不同的人填写**。差集非空因此不是理论风险，而是这类文档最常见的实际状态；Q3 的存在就是把这件事变成一个可数的指标（第 20 章 O7）。

边界与脚本一完全相同：纯文本、离线、只读、不联网、不调用任何设备侧或 Apple 命令行工具、不修改输入文件，唯一写出目标是 `mktemp -d` 创建的临时目录且退出时删除。脚本同样不含口令破解、副本提取或解密他人备份的任何做法。

### 22.2 输入格式

```
用法: backup-copy-crosscheck.sh [-q] [-L 清单件] [-K 密钥件] [-R 回执件]
  -L 清单件  每行: <副本标识>,<设备标识>,<介质>,<形态>,<快照日>,<字节数>,<在册状态>
  -K 密钥件  每行: <副本标识>,<keybag类>,<口令归属>,<设备绑定>,<服务密钥归属>,<轮换日>
  -R 回执件  每行: <回执序号>,<副本标识>,<动作>,<事件日>,<见证主体>
```

三件可以混写在同一个文件里，用行首 `L:` / `K:` / `R:` 标记归属；不带前缀时按该文件由哪个选项传入来判定归属。`#` 开头与空行忽略，行尾 CR 忽略。

两个字段是脚本二特有的：

- **`在册状态`（`listed` / `retired` / `unknown`）**：清单件的第 7 列。它存在的唯一理由是把"这份副本还在不在清单上"与"有没有对它执行过删除"分开记。合并成一列会让 Z08（有 `deleted` 回执但仍在册）与 Z09（退册但没有删除回执）无法区分，而这两条的处置方完全不同。
- **`动作` 五值**：`copy_discovered` / `delete_requested` / `deleted` / `key_rotated` / `restore_completed`。第 4—13 章的每一层各自需要一个事件；这五个是本篇认定的"可被文档口径支撑的最小事件集"，不接受"已处理""已确认"这类无出处的动作词。

| 解析层信号 | 触发条件 |
| --- | --- |
| W01 | 行无法按所属件的列数解析 |
| W02 | 行缺副本标识（清单件还缺设备标识时也报） |
| W03 | 枚举值或日期形态不符（含介质、形态、在册状态、keybag 类、口令归属、设备绑定、服务密钥归属、轮换日、动作、事件日、见证主体） |
| N01—N03 | 清单件 / 密钥件 / 回执件未提供（非阻断，说明该层无法核对） |

### 22.3 四族比对

| 族 | 比什么 | 码 |
| --- | --- | --- |
| X | **集合差集**：清单 ↔ 密钥 ↔ 回执三件之间的引用闭合 | X01 清单有密钥无；X02 密钥有清单无；X03 回执引用清单外副本；X04 副本无任何处置动作；X05 同一标识两行事实不同或重复；X06 回执序号重复；X07 删除回执见证主体为 none |
| Y | **事件时序**：五类动作与快照日之间的先后 | Y01 删除早于快照；Y02 轮换早于快照；Y03 恢复完成晚于删除；Y04 同一副本两条同类事件同日冲突；Y05 发现回执早于快照；Y06 同日重复或删除缺请求 |
| Z | **密钥事实与介质形态的一致性** | Z01—Z09，见 22.3.1 |
| Q | **对该副本的闭合等级** | Q1—Q4，见第 19.4 节 |

Z 族九条是本篇第十二章"机制口径"的机械翻译，每条都直接对应第 16 章的一条读数：

| 码 | 矛盾 | 依据（第 16 章编号） |
| --- | --- | --- |
| Z01 | backup keybag 记在 iCloud 介质上 | R5（第 1996 行） |
| Z02 | escrow keybag 记在 iCloud 介质上 | R7（第 2000 行） |
| Z03 | 未加密本地副本挂了口令归属 | R6（第 1998 行） |
| Z04 | 加密本地副本的口令归属为空或 unknown | R5（第 1997 行，无设备绑定） |
| Z05 | iCloud 副本记为设备绑定 | R11（第 2724 行） |
| Z06 | iCloud 副本未落到服务密钥归属 | R8（第 2722 行） |
| Z07 | 服务密钥记为端到端可用但没有轮换日；或回执有 `key_rotated` 但密钥件无轮换日 | R9、R10（第 2680、2746 行） |
| Z08 | 已有 `deleted` 回执但在册状态仍是 `listed` | G1（已删除副本无回看面，只能靠回执） |
| Z09 | 在册状态为 `retired` 但没有 `deleted` 回执 | G1 |

Z08 与 Z09 是两条管理同步缺陷而不是机制矛盾，但它们与 Z01—Z07 同族，因为它们都在问"两份文档对同一份副本说了不同的话"。

### 22.4 实跑结果

四个样本本轮都实际执行过。

**好样本**（`fx/g-list.tsv` + `g-key.tsv` + `g-receipt.tsv`，3 份副本三件齐备）：

```
Q1	CIP-1	三件闭合、时序成立、形态一致：可对该副本出具归属结论
Q1	CIP-2	三件闭合、时序成立、形态一致：可对该副本出具归属结论
Q1	CIP-3	三件闭合、时序成立、形态一致：可对该副本出具归属结论

清单副本数=3 密钥登记数=3 回执引用副本数=3
不同信号码=1 阻断信号条数=0
  Q1=3
```

退出码 0。这一行同时是第 19.4 节 Q1 可达性的证据——为了让它可达，清单件必须带第 7 列入册状态；这一点在第 22.2 节已经说明。

**坏样本，三次运行**（同一批 `fx/b-list.tsv` / `b-key.tsv` / `b-receipt.tsv`，含两处刻意构造的差集与两组部分输入）：

```
R1 三件齐备:  清单副本数=7 密钥登记数=6 回执引用副本数=5
              不同信号码=28 阻断信号条数=48
R2 仅给清单:  清单副本数=7 密钥登记数=0 回执引用副本数=0
              不同信号码=10 阻断信号条数=25
R3 只给密钥+回执: 清单副本数=0 密钥登记数=6 回执引用副本数=5
              不同信号码=6 阻断信号条数=19
```

三次运行退出码均为 1。合起来 31 个码全部触发（缺 Q1，由好样本补齐），**脚本二的 32 个信号码在本轮全部有实跑记录**，明细见第 23.3 节。

这三次运行还有一个用途：**验证缺件时的行为**。R2 里没有密钥件与回执件，N02、N03 因此出现且把全部 7 份副本压到 Q4（三件不齐时差集比对没有可比对象，脚本不会去猜）；R3 反过来报 N01。三件缺任一件时结论一律降级，这是本篇刻意的行为——**缺输入不可被解释为"没有问题"**。

### 22.5 与脚本一的接续方式

两个脚本共用同一份副本标识。推荐用法：

1. 用脚本一逐副本修台账本身（把 A01/A02/K03/K05 这类缺格与拒收项清掉），退出码 0 且 J 级不再停在 J4。
2. 再用脚本二把这份台账与处置记录对账（X/Y/Z 三族）。
3. 两份输出并列归档：脚本一的 J 级说明这份记录**能支撑什么结论**，脚本二的 Q 级说明这份记录**与处置事实同不同步**。

第 20 章的 O1—O6 从脚本一取数，O7—O8 从脚本二取数，O9—O10 则是两脚本共同关注的两类零值指标。

脚本二全文（230 行）：

```bash
#!/usr/bin/env bash
# backup-copy-crosscheck.sh —— 副本清单、密钥事实与处置回执的三件差集比对器
# （离线 / 只读 / 不联网 / 不碰设备 / 不调用任何 Apple 命令行工具）
# 本脚本只做集合差集、时间序与口径一致性比对，输出归属结论；
# 不含任何备份口令破解、副本提取或解密他人备份的做法，也不提供任何绕过或恢复技巧。
# 本脚本不联网、不访问设备、不修改输入文件；临时件写在 mktemp -d 并在退出时删除。
set -u
LC_ALL=C; export LC_ALL

usage() {
  cat <<'EOF'
用法: backup-copy-crosscheck.sh [-q] [-L 清单件] [-K 密钥件] [-R 回执件]
  -q  只输出汇总与分级结论；-h 显示本帮助
  -L 清单件  每行: <副本标识>,<设备标识>,<介质>,<形态>,<快照日>,<字节数>,<在册状态>
             介质: icloud computer external_volume third_party_service unknown
             形态: icloud_backup local_encrypted local_plain archive unknown
             在册状态: listed retired unknown
  -K 密钥件  每行: <副本标识>,<keybag类>,<口令归属>,<设备绑定>,<服务密钥归属>,<轮换日>
             keybag类: user device backup escrow icloud_backup unknown
             口令归属: holder org third_party unknown none
             设备绑定: true false unknown
             服务密钥归属: apple_hsm trusted_devices unknown not_applicable
  -R 回执件  每行: <回执序号>,<副本标识>,<动作>,<事件日>,<见证主体>
             动作: copy_discovered delete_requested deleted key_rotated restore_completed
             见证主体: holder org vendor none
  三件可以混写在同一个文件里，用行首 L: / K: / R: 标记指定归属。
  # 开头与空行忽略，行尾 CR 忽略；日期接受 YYYY-MM-DD 或带时刻的 ISO 写法。
本脚本不联网、不访问设备、不修改输入文件；唯一写出目标是 mktemp -d 创建的临时目录，退出时删除。
EOF
}

QUIET=0; LF=""; KF=""; RF=""
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    -q) QUIET=1; shift ;;
    -L) LF=${2:-}; shift 2 ;;
    -K) KF=${2:-}; shift 2 ;;
    -R) RF=${2:-}; shift 2 ;;
    *) echo "未知参数: $1" >&2; usage >&2; exit 2 ;;
  esac
done
if [ -z "$LF" ] && [ -z "$KF" ] && [ -z "$RF" ]; then usage >&2; exit 2; fi
FILES=()
for f in "$LF" "$KF" "$RF"; do
  [ -z "$f" ] && continue
  [ -f "$f" ] || { echo "输入不可读: $f" >&2; exit 2; }
  FILES+=("$f")
done

TMPD=$(mktemp -d "${TMPDIR:-/tmp}/bcc.XXXXXX") || { echo "无法创建临时目录" >&2; exit 2; }
trap 'rm -rf "$TMPD"' EXIT INT TERM

awk -v QUIET="$QUIET" -v LF="$LF" -v KF="$KF" -v RF="$RF" '
function emit(code, cp, msg) { cnt[code]++; lines[++nline] = sprintf("%s\t%s\t%s", code, (cp==""?"-":cp), msg) }
function isISOdt(v) { return (v ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]([ T][0-9][0-9]:[0-9][0-9](:[0-9][0-9])?)?([Zz]|[+-][0-9][0-9]:?[0-9][0-9])?$/ && validCal(v)) }
function validCal(v,  p, mo, dy) { split(substr(v,1,10), p, "-"); mo = p[2]+0; dy = p[3]+0; return (mo >= 1 && mo <= 12 && dy >= 1 && dy <= 31) }
function dayNum(v,  t) { t = v; gsub(/[^0-9]/, "", t); return substr(t,1,8)+0 }
function istrue(v)  { return (v=="true"||v=="yes"||v=="1") }
function isBlank(v) { return (v ~ /^[ \t]*$/) }
function inSet(v, n, S,   i) { for (i=1; i<=n; i++) if (S[i]==v) return 1; return 0 }
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
  nMED=split("icloud computer external_volume third_party_service unknown", MED, " ")
  nKIND=split("icloud_backup local_encrypted local_plain archive unknown", KIND, " ")
  nSTAT=split("listed retired unknown", STAT, " ")
  nKB=split("user device backup escrow icloud_backup unknown", KBAG, " ")
  nOWN=split("holder org third_party unknown none", POWN, " ")
  nDB=split("true false unknown", DBND, " ")
  nCUST=split("apple_hsm trusted_devices unknown not_applicable", CUST, " ")
  nACT=split("copy_discovered delete_requested deleted key_rotated restore_completed", ACT, " ")
  nWIT=split("holder org vendor none", WIT, " ")
}
{ sub(/\r$/, "") }
/^[ \t]*#/ { next }
/^[ \t]*$/ { next }
{
  oline = $0
  kind = ""
  if (FILENAME == LF) kind = "L"
  else if (FILENAME == KF) kind = "K"
  else if (FILENAME == RF) kind = "R"
  if (oline ~ /^[ \t]*L[ \t]*:/) kind = "L"
  else if (oline ~ /^[ \t]*K[ \t]*:/) kind = "K"
  else if (oline ~ /^[ \t]*R[ \t]*:/) kind = "R"
  if (kind == "") { emit("W01","-","该行没有归属：三件同时提供时需用行首 L: / K: / R: 标记: " oline); next }
  sub(/^[ \t]*[LKR][ \t]*:/, "", $0)

  if (kind == "L") {
    if (NF < 7) { emit("W01","-","清单行不足七列: " oline); next }
    cid=$1; did=$2; med=$3; knd=$4; snap=$5; sz=$6; stt=$7
    if (isBlank(cid)) { emit("W02","-","清单行缺副本标识: " oline); next }
    if ((cid in Lseen)) {
      if (Lmed[cid] != med || Lkind[cid] != knd) emit("X05", cid, "同一副本标识在清单件里两行的介质或形态不同: [" Lmed[cid] "," Lkind[cid] "] 与 [" med "," knd "]")
      else emit("X05", cid, "同一副本标识在清单件里重复出现且内容相同: " cid)
    } else {
      Lseen[cid]=1; Lno[++Ln]=cid
      Lmed[cid]=med; Lkind[cid]=knd; Lsnap[cid]=snap; Lsize[cid]=sz; Ldid[cid]=did; Lstat[cid]=stt
    }
    if (!inSet(med, nMED, MED))   emit("W03", cid, "清单介质 [" med "] 不在词表内")
    if (!inSet(knd, nKIND, KIND)) emit("W03", cid, "清单形态 [" knd "] 不在词表内")
    if (!inSet(stt, nSTAT, STAT)) emit("W03", cid, "在册状态 [" stt "] 不在 listed/retired/unknown 词表内")
    if (!isISOdt(snap))           emit("W03", cid, "清单快照日 [" snap "] 不是可定序的日期")
    if (sz !~ /^-?[0-9]+$/ || sz+0 <= 0) emit("W03", cid, "清单字节数 [" sz "] 不是正整数：体积是这份副本确实存在的第一读数")
    if (isBlank(did))             emit("W02", cid, "清单行缺设备标识：副本无法回到具体设备")
    next
  }
  if (kind == "K") {
    if (NF < 6) { emit("W01","-","密钥行不足六列: " oline); next }
    cid=$1; kb=$2; po=$3; db=$4; cu=$5; ro=$6
    if (isBlank(cid)) { emit("W02","-","密钥行缺副本标识: " oline); next }
    if ((cid in Kseen) && (Kkb[cid] != kb || Kcust[cid] != cu || Kown[cid] != po)) emit("X05", cid, "同一副本标识在密钥件里两行的密钥事实不同: " cid)
    Kseen[cid]=1; Kno[++Kn]=cid; Kkb[cid]=kb; Kown[cid]=po; Kdb[cid]=db; Kcust[cid]=cu; Kro[cid]=ro
    if (!inSet(kb, nKB, KBAG))    emit("W03", cid, "keybag 类 [" kb "] 不在五类加 unknown 的词表内")
    if (!inSet(po, nOWN, POWN))   emit("W03", cid, "口令归属 [" po "] 不在词表内")
    if (!inSet(db, nDB, DBND))    emit("W03", cid, "设备绑定 [" db "] 不是 true/false/unknown")
    if (!inSet(cu, nCUST, CUST))  emit("W03", cid, "服务密钥归属 [" cu "] 不在词表内")
    if (ro != "" && !isISOdt(ro)) emit("W03", cid, "密钥轮换日 [" ro "] 不是可定序的日期")
    next
  }
  if (kind == "R") {
    if (NF < 5) { emit("W01","-","回执行不足五列: " oline); next }
    rid=$1; cid=$2; ac=$3; rd=$4; wi=$5
    if (isBlank(rid)) { emit("W02","-","回执行缺序号：结论无法回指该条: " oline); next }
    if ((rid in Rseen)) emit("X06","-", "回执序号重复: " rid "（该序号两条记录引用同一动作，须改用不同序号）")
    Rseen[rid]=1
    if (isBlank(cid)) { emit("W02","-","回执行缺副本标识: " oline); next }
    if (!inSet(ac, nACT, ACT)) emit("W03", cid, "回执动作 [" ac "] 不在词表内")
    if (!isISOdt(rd))          emit("W03", cid, "回执事件日 [" rd "] 不是可定序的日期")
    if (!inSet(wi, nWIT, WIT)) emit("W03", cid, "回执见证主体 [" wi "] 不在词表内")
    rn[cid]++
    ract[cid SUBSEP rn[cid]] = ac; rday[cid SUBSEP rn[cid]] = rd
    rwit[cid SUBSEP rn[cid]] = wi; rrid[cid SUBSEP rn[cid]] = rid
    if (!(cid in RallSeen)) { RallSeen[cid]=1; Rall[++Rn]=cid }
    next
  }
}
END {
  if (LF == "") emit("N01","-","清单件未提供：副本全集不可知，差集与归属结论都不成立")
  if (KF == "") emit("N02","-","密钥件未提供：密钥归属层不可核对")
  if (RF == "") emit("N03","-","回执件未提供：处置动作与时间序不可核对")

  for (i = 1; i <= Ln; i++) {
    c = Lno[i]
    if (!(c in Kseen)) emit("X01", c, "清单件有这份副本、密钥件没有：可解性归属无从判定")
    if (!(c in rn))    emit("X04", c, "该副本在回执件里没有任何处置动作：清单与处置之间断链")
  }
  for (i = 1; i <= Kn; i++) {
    c = Kno[i]
    if (!(c in Lseen)) emit("X02", c, "密钥件登记了清单件之外的副本标识：密钥事实对应不到已知副本")
  }
  for (i = 1; i <= Rn; i++) {
    c = Rall[i]
    if (!(c in Lseen)) emit("X03", c, "回执件引用了清单件之外的副本标识：处置记录落在集合外")
  }

  for (i = 1; i <= Ln; i++) {
    c = Lno[i]
    med = Lmed[c]; knd = Lkind[c]; snap = Lsnap[c]; stt = Lstat[c]
    kb  = Kkb[c]; pown = Kown[c]; dbnd = Kdb[c]; cust = Kcust[c]; ro = Kro[c]
    haveK = (c in Kseen)

    if (haveK) {
      if (kb == "backup" && med == "icloud") emit("Z01", c, "backup keybag 记在 iCloud 介质上：加密本地备份的 keybag 存在用于同步的那台电脑上（平台安全指南第 1996 行）")
      if (kb == "escrow" && med == "icloud") emit("Z02", c, "escrow keybag 记在 iCloud 介质上：它存在用于同步的电脑或设备管理服务上（平台安全指南第 2000 行）")
      if (knd == "local_plain" && pown != "none") emit("Z03", c, "未加密本地副本挂了口令归属 [" pown "]：未加密时文件不加密，钥匙串项另由 UID 派生密钥保护（平台安全指南第 1998 行）")
      if (knd == "local_encrypted" && (pown == "none" || pown == "unknown" || pown == "")) emit("Z04", c, "加密本地副本的口令归属为 [" pown "]：这类副本没有设备绑定（平台安全指南第 1997 行），可解性完全落在口令上，归属为空即无主")
      if (knd == "icloud_backup" && istrue(dbnd)) emit("Z05", c, "iCloud 副本记为设备绑定：备份集落在用户的 Apple 账号里，保护它的是与副本同存的随机密钥（平台安全指南第 2724 行）")
      if (knd == "icloud_backup" && (cust == "" || cust == "unknown")) emit("Z06", c, "iCloud 副本未落到服务密钥归属：默认状态下 iCloud Backup 服务密钥备份在 Apple 的 HSM 里（平台安全指南第 2722 行）")
      if (cust == "trusted_devices" && ro == "") emit("Z07", c, "服务密钥记为端到端可用但没有轮换日：该口径靠高级数据保护的服务密钥轮换才成立（平台安全指南第 2746 行）")
    }

    ndel=0; ndis=0; nrot=0; nres=0; ndreq=0
    for (t = 1; t <= rn[c]; t++) {
      a = ract[c SUBSEP t]; d = rday[c SUBSEP t]; w = rwit[c SUBSEP t]; qid = rrid[c SUBSEP t]
      if (a == "deleted")              { ndel++;  if (ndel==1) delday=d }
      else if (a == "copy_discovered") { ndis++;  if (ndis==1) disday=d }
      else if (a == "key_rotated")     { nrot++;  if (nrot==1) rotday=d }
      else if (a == "restore_completed") { nres++; if (nres==1) resday=d }
      else if (a == "delete_requested")  { ndreq++; if (ndreq==1) reqday=d }
      if (a == "deleted" && w == "none") emit("X07", c, "回执 " qid " 的删除事件没有见证主体（witness=none）：该删除不可回指到任何一方的声明")
      for (u = t+1; u <= rn[c]; u++) {
        if (ract[c SUBSEP u] != a) continue
        if (rday[c SUBSEP u] == d) emit("Y04", c, "同一副本两条同为 [" a "] 且事件日相同 [" d "]（回执 " qid " 与 " rrid[c SUBSEP u] "）：两条无法区分")
        else                       emit("Y06", c, "同一副本两条同为 [" a "] 但事件日不同 [" d " / " rday[c SUBSEP u] "]：结论要指明是哪一条")
      }
    }
    if (ndel > 0 && ndreq == 0) emit("Y06", c, "有 deleted 回执但没有 delete_requested：删除动作缺请求记录，事件序列不完整")

    if (isISOdt(snap)) {
      if (ndel > 0 && isISOdt(delday) && dayNum(delday) < dayNum(snap)) emit("Y01", c, "删除事件日 [" delday "] 早于清单快照日 [" snap "]：删掉的不是这份副本")
      if (ndis > 0 && isISOdt(disday) && dayNum(disday) < dayNum(snap)) emit("Y05", c, "发现回执 [" disday "] 早于清单快照日 [" snap "]：清单登记的对象不是被发现的那一份")
    }
    if (nrot > 0 && ndel > 0 && isISOdt(rotday) && isISOdt(delday) && dayNum(rotday) < dayNum(delday)) emit("Y02", c, "密钥轮换 [" rotday "] 早于删除 [" delday "]：可读性在删除前已由轮换改变，「删除导致不可读」的结论不成立")
    if (nres > 0 && ndel > 0 && isISOdt(resday) && isISOdt(delday) && dayNum(resday) > dayNum(delday)) emit("Y03", c, "恢复完成 [" resday "] 晚于删除 [" delday "]：两条回执至少有一条不属于同一份副本，清单需要重列")
    if (ndel > 0 && stt == "listed") emit("Z08", c, "已有 deleted 回执但在册状态仍是 listed：清单与处置结果不同步")
    if (stt == "retired" && ndel == 0) emit("Z09", c, "在册状态为 retired 但没有 deleted 回执：退册没有处置依据")
    if (nrot > 0 && ro == "") emit("Z07", c, "回执里有 key_rotated 事件但密钥件无轮换日：两处记法不一致")

    fmtbad = tally(c, "W"); setbad = tally(c, "X"); seqbad = tally(c, "Y"); sembad = tally(c, "Z")
    if (LF == "" || KF == "" || RF == "" || fmtbad > 0) emit("Q4", c, "三件不齐或本副本行形态不可解析：差集比对没有可比对象")
    else if (setbad > 0) emit("Q3", c, "三件齐备但差集非空：这份副本的身份无法在三件之间闭合")
    else if (seqbad > 0) emit("Q2", c, "集合闭合但时间序不成立：删除、轮换与恢复的先后不可同时为真")
    else if (sembad > 0) emit("Q2", c, "集合闭合且时序成立，但密钥形态与介质矛盾：归属结论按最弱一环给出")
    else emit("Q1", c, "三件闭合、时序成立、形态一致：可对该副本出具归属结论")
  }

  if (nline > 0) {
    for (q = 1; q <= nline; q++) print lines[q] > "/dev/stderr"
    if (!QUIET) print "" > "/dev/stderr"
  }
  ndist = 0
  for (code in cnt) ndist++
  blk = 0
  for (code in cnt) if (code !~ /^N/ && code !~ /^Q/) blk += cnt[code]
  printf "清单副本数=%d 密钥登记数=%d 回执引用副本数=%d\n", Ln, Kn, Rn
  printf "不同信号码=%d 阻断信号条数=%d\n", ndist, blk
  for (code in cnt) printf "  %s=%d\n", code, cnt[code]
  exit (blk > 0 ? 1 : 0)
}
' "${FILES[@]}"
```

## 23. 两个脚本的全量分支覆盖验收

### 23.1 验收方法

覆盖的定义很朴素：**脚本里每一个信号码，本轮都必须有一份实际输入把它触发出来，并能在输出里回指到触发它的那条记录**。不可触发的信号等于没有——它会让人以为该格被检查过。

做法是把两脚本各自的 `emit(...)` 调用抽成码表，把每次实跑的输出抽成"本轮实际出现的码"，取差集：

```
$ grep -o 'emit("[A-Z][0-9]*"' 脚本 | 去重 | 排序 > 码表
$ cat 各次输出 | 取行首码 | 去重 | 排序 > 实跑码表
$ comm -23 码表 实跑码表      # 未覆盖：期望为空
$ comm -13 码表 实跑码表      # 多余：期望为空（多余说明抽码方式有误）
```

本轮结果：

| 脚本 | 码表 | 实跑并集 | 未覆盖 | 多余 |
| --- | --- | --- | --- | --- |
| 一（台账审查器） | 86 | 86 | 0 | 0 |
| 二（三件比对器） | 32 | 32 | 0 | 0 |
| **合计** | **118** | **118** | **0** | **0** |

两脚本的 J1 与 Q1 各自只在好样本出现（坏样本刻意不含），因此每支脚本都需要"坏样本 + 好样本"两次运行才闭合；这不是覆盖不足，而是判定级信号的定义所致。

### 23.2 脚本一：86 个信号码的覆盖表

"触发样本"列取自 `fx/bad.tsv`（11 份副本 + 2 行畸形记录）与 `fx/good.tsv`（2 份副本）的实际输出，`(行级)` 表示该信号不带副本标识。

| 码 | 触发条件 | 触发样本 |
| --- | --- | --- |
| U01 | 行不足三列；或字段前缀不在九个命名空间内 | (行级) |
| U02 | 记录缺副本标识 | (行级) |
| U03 | 同一副本同一字段两条不同值 | BAD-A |
| U04 | 值含首尾空格 | BAD-A |
| U05 | `device.model` 形态不符 | BAD-A |
| U06 | `device.serial` 非 8—14 位字母数字 | BAD-A |
| U07 | `device.os_version` 非 x.y / x.y.z | BAD-A |
| E01 | 枚举值不在所属字段的词表内（21 个字段共用） | BAD-A,B,E,H |
| E02 | 三态字段不是 true/false/unknown | BAD-A |
| E03 | 日期不是 ISO 形式，或月日不在合法范围 | BAD-A |
| E04 | 带时刻但无时区标记且无 `device.timezone` | BAD-I |
| E05 | 整数字段非整数；天数字段非非负整数 | BAD-B |
| A01 | 缺 `copy.snapshot_date` 或缺 `copy.source_of_record` | BAD-A,G,H |
| A02 | 缺 `copy.medium` 或缺 `copy.kind` | BAD-G |
| A03 | 介质与形态冲突（三组冲突之一） | BAD-B,D,K |
| A04 | `size_bytes` 非正或未记录 | BAD-A,G,H,K |
| A05 | 保留窗口非 180 天却在开关 off；或开关非 off 却记窗口 | BAD-A,C |
| A06 | 把"接电+闲置+Wi-Fi"的触发前提记在电脑副本上 | BAD-B |
| A07 | 读数来源为电脑端应用但介质为 iCloud | BAD-I |
| A08 | iCloud 副本记为设备绑定 | BAD-B,E |
| K01 | 未记录 `key.keybag_kind` | BAD-A,G |
| K02 | 未加密本地副本挂 backup keybag | BAD-C,D |
| K03 | 加密本地副本未声明口令归属 | BAD-A |
| K04 | 拉伸次数低于 1,000 万次；或加密本地未记该项 | BAD-A,F,H |
| K05 | 台账落了备份口令（拒收项） | BAD-A |
| K06 | iCloud 副本未声明服务密钥归属 | BAD-K |
| K07 | 服务密钥在 Apple HSM 且记设备绑定 | BAD-A,E |
| K08 | 端到端口径与"随机密钥与备份集同存"并存 | BAD-B |
| K09 | 记了同存但没有 `key.rotated_at` | BAD-A,B |
| K10 | Messages 容器密钥副本已入备份但缺轮换日/未与轮换日一并登记 | BAD-A,B |
| K11 | 加密本地副本记 `keychain_uid_protected=false` | BAD-A,F |
| K12 | escrow keybag 记在 iCloud 副本上 | BAD-E |
| K13 | 托管记录已锁定与"删除已实证"并存 | BAD-A,C,D |
| C01 | 声明含生物特征数据 | BAD-A |
| C02 | 未加密本地备份声明含健康数据 | BAD-C,D |
| C03 | 电脑侧副本声明含 HomeKit 数据 | BAD-B |
| C04 | 电脑侧副本声明含 EnergyKit 数据 | BAD-B |
| C05 | iCloud 照片已同步却记副本含照片 | BAD-A |
| C06 | 把排除标记写成"保证不含" | BAD-A |
| C07 | 声明含已购内容本体 | BAD-A |
| C08 | Apple Watch 记为独立副本内容项 | BAD-A |
| C09 | 电脑副本声明含 CloudKit 应用数据 | BAD-B |
| C10 | iCloud 介质与 `local_plain` 形态冲突 | BAD-I |
| D01 | 请求删除但无 `deleted_at` | BAD-A |
| D02 | 未请求删除却有删除证据 | BAD-B,I |
| D03 | 实证级删除但见证主体为 none | BAD-A |
| D04 | 实证级删除但无删除后密钥轮换 | BAD-A |
| D05 | 实证级删除与旧副本存活并存 | BAD-A |
| D06 | 两个保留口径数值不一致 | BAD-A,C |
| D07 | 记了"作为新设备设置"但未请求删除 | BAD-D |
| D08 | 已有轮换证据却只记 inferred | BAD-B |
| R01 | 未记录 `restore.restore_target` | BAD-A,G,H |
| R02 | 异机恢复且副本记设备绑定 | BAD-B |
| R03 | 异机恢复但未记非迁移项预期丢失 | BAD-B |
| R04 | 恢复前有硬件绑定密钥但未记退管 | BAD-B |
| R05 | 同机 iPhone 恢复却记手表配对未保留 | BAD-C |
| R06 | 跨设备类型恢复且消息未同步 | BAD-B |
| R07 | 含 SIM 依赖项却恢复到别的设备 | BAD-B |
| M01 | 未记录 `mgmt.surface` | BAD-A,G |
| M02 | `mgmt.command_expected` 指向一条不存在的命令 | BAD-B |
| M03 | 声明存在备份相关描述文件键 | BAD-B |
| M04 | 声明存在备份相关声明式管理声明 | BAD-B |
| M05 | `org_visibility=attested` 而介质是电脑 | BAD-B |
| M06 | 持有者是组织但未记 `org_visibility` | BAD-G |
| V01 | 有组件名但未登记是否命中 | BAD-A |
| V02 | `MobileBackup` 下把描述文本读成备份语义命中 | BAD-A |
| V03 | 声明在 KEV 里但没给 CVE 主键 | BAD-A,G |
| V04 | 公告面为空却登记义务记录 | BAD-D |
| H01 | 未记录 `holder.role` | BAD-K |
| H02 | 个人持有者的加密本地副本记为组织掌握口令 | BAD-A |
| H03 | 口令只有持有者知道却由厂商见证删除 | BAD-I |
| H04 | 介质受管但未落义务记录 | BAD-B |
| H05 | 承认异地副本却不记旧副本存活 | BAD-C |
| H06 | 口令共享且登记了拉伸次数 | BAD-F |
| T01 | 审计日早于副本快照日 | BAD-C |
| T02 | 删除时刻早于副本快照日 | BAD-C |
| T03 | 密钥轮换早于副本快照日 | BAD-C |
| T04 | 含日期字段但没有 `device.timezone` | BAD-A,I,J,K |
| B01 | 公告面三栏全空（非阻断） | BAD-H,K |
| B02 | 配件线副本（非阻断） | BAD-A |
| B03 | 管理面对该副本零可见（非阻断） | BAD-A,C,E,F,I,J,K |
| B04 | 外部介质副本形态不是 archive（非阻断） | BAD-C |
| J2 | 密钥两格齐但内容五项未齐或阻断 ≥ 1 | BAD-J |
| J3 | 本体可登记但口令归属或服务密钥归属缺格 | BAD-E,F,K |
| J4 | 四元组或密钥类未齐，或阻断 ≥ 6 | BAD-A,B,C,D,G,H,I |
| J1 | 四项齐备（含降级变体） | good.tsv：COPY-ICLOUD, COPY-LOCAL |

### 23.3 脚本二：32 个信号码的覆盖表

"触发运行"列：R1 = 三件齐备的坏样本运行，R2 = 只给清单件，R3 = 只给密钥件与回执件，RG = 好样本。

| 码 | 触发条件 | 触发运行 |
| --- | --- | --- |
| W01 | 行无法按所属件的列数解析 | R1, R2 |
| W02 | 行缺副本标识（清单件缺设备标识同报） | R1, R2, R3 |
| W03 | 枚举值或日期形态不符（11 类字段共用） | R1, R2, R3 |
| X01 | 清单件有这份副本、密钥件没有 | R1, R2 |
| X02 | 密钥件登记了清单件之外的副本标识 | R1, R3 |
| X03 | 回执件引用了清单件之外的副本标识 | R1, R3 |
| X04 | 该副本在回执件里没有任何处置动作 | R1, R2 |
| X05 | 同一副本标识在同一件里两行不同（或完全重复） | R1, R2 |
| X06 | 回执序号重复 | R1, R3 |
| X07 | 删除回执的见证主体为 none | R1 |
| Y01 | 删除事件日早于快照日 | R1 |
| Y02 | 密钥轮换早于快照日 | R1 |
| Y03 | 恢复完成晚于删除事件日 | R1 |
| Y04 | 同一副本两条同类事件同日冲突 | R1 |
| Y05 | 发现回执早于快照日 | R1 |
| Y06 | 同日重复动作；或有 `deleted` 无 `delete_requested` | R1 |
| Z01 | backup keybag 记在 iCloud 介质上 | R1 |
| Z02 | escrow keybag 记在 iCloud 介质上 | R1 |
| Z03 | 未加密本地副本挂了口令归属 | R1 |
| Z04 | 加密本地副本口令归属为空或 unknown | R1 |
| Z05 | iCloud 副本记为设备绑定 | R1 |
| Z06 | iCloud 副本未落到服务密钥归属 | R1 |
| Z07 | 端到端口径无轮换日；或回执有轮换而密钥件无 | R1 |
| Z08 | 有 `deleted` 回执但在册状态仍是 `listed` | R1 |
| Z09 | 在册状态 `retired` 但无 `deleted` 回执 | R1, R2 |
| N01 | 清单件未提供（非阻断） | R3 |
| N02 | 密钥件未提供（非阻断） | R2 |
| N03 | 回执件未提供（非阻断） | R2 |
| Q2 | 集合闭合但时序不成立 / 形态矛盾 | R1 |
| Q3 | 三件齐备但差集非空 | R1 |
| Q4 | 三件不齐或行形态不可解析 | R1, R2 |
| Q1 | 三件闭合、时序成立、形态一致 | RG |

### 23.4 口径覆盖缺口（G8 的展开）

下表列的是**本轮两个脚本的字段命名空间里没有位置可放**的一组事实。它们不是漏检项，不能通过"再加一个信号"解决，因为公开文档里没有对应读数（第 26 章 G8 的回指目标就是这张表）。

| 事实 | 为什么没有字段位 | 处置 |
| --- | --- | --- |
| 某人/某设备名下副本的完整集合 | V3：四个读数面各自只显示一侧 | 分母只能是"已登记副本数"（第 20.3 节 1） |
| `isExcludedFromBackup` 的实际生效状态 | 标记可登记，生效状态无读数 | 只记 `exclusion_marks_used`，禁记保证（C06） |
| 人员与副本的直接绑定 | 台账只有 `holder.*` 角色格，无人员标识列 | 留在组织自有台账；G8、G6 |
| 逐条数据的进入/退出 | V2 只到类别级 | 类别级三态登记；不出条目级结论 |
| 电脑侧备份口令的强度、历史与更换次数 | 本文拒收任何口令事实（K05） | 只记归属与知识范围两格 |
| 账号侧哪些服务当前处于哪一档密钥类别 | G2：无按服务的读数 | `custody` 单格 + `inferred` 标注 |
| 删除后备份目录与 backup keybag 的各自命运 | G5：文档未展开 | 电脑侧删除一律记 `inferred` |
| 服务侧是否存在 escrow keybag | G9：协议无读回命令 | 记 `unknown`；要求服务方陈述 + 回执双要件 |

### 23.5 退出码约定与接入方式

| 脚本 | 退出码 | 含义 |
| --- | --- | --- |
| 一 | 0 | 无阻断信号（`B*` 与 `J*` 不计入） |
| 一 | 1 | 存在至少一条阻断信号 |
| 一 | 2 | 用法错误 / 参数缺失 / 输入不可读 |
| 二 | 0 | 无阻断信号（`N*` 与 `Q*` 不计入） |
| 二 | 1 | 存在至少一条阻断信号 |
| 二 | 2 | 用法错误 / 三件一个都没给 / 输入不可读 |

因此可以直接接进周期性检查：`脚本 台账文件 || 记为待处置`。两个脚本都不接受标准输入、都不写任何持久文件、都在退出时删除 `mktemp -d` 临时目录，重复执行同一输入的结果一致（无状态、无随机、无时间依赖——所有比较基于台账内登记的日期，不读系统时钟）。

最后一句限制与第 20.3 节同源：**这套验收证明的是信号可达与记录可核对，不是副本已被妥善处置**。

---

## 24. 十二个误区

每条一句结论、一句文档依据、一句"照做会怎样"。这里的 M 编号指误区，与脚本一里管理面信号族 `M01—M06` 不是同一套编号；两者在正文中的引用会分别写作"误区 M3"与"信号 M03"。

**误区 M1 · 关掉备份开关就等于副本不在了。**
依据：《What does iCloud back up?》第 45 行"If you turn off iCloud Backup for a device, any backups stored in iCloud are kept for 180 days"；平台安全指南第 2722 行的开关只决定新副本是否生成。
照做的结果：关闭动作之后半年内，账号侧仍可恢复。台账上对应 A05（保留窗口记成别的天数，或在开关不是 off 时记了窗口）与 D05（旧副本存活却出实证级删除结论）。

**误区 M2 · 删除文件等于数据不再可读。**
依据：第 2680 行说明可读性由服务密钥决定（"After the keys are deleted, Apple can no longer access any of the data protected by the user's service keys"），第 2746 行说明 iCloud Backup 服务密钥与 Messages 容器密钥的轮换才是那个事件。
照做的结果：一份"已删除"记录覆盖的是文件层动作；账号侧的可读性结论要等轮换事件日。对应 D04、K09、脚本二的 Y02。

**误区 M3 · iCloud 副本是设备绑定的，所以换设备就安全了。**
依据：第 2724 行——iCloud Backup keybag 含非可访问类的 Curve25519 非对称密钥，随机密钥与备份集同处；第 2667 行——认证后可用类密钥在服务端账户认证后发放，绑定条件是账号。
照做的结果：把"换了一台设备"当成"上一台设备的副本失去可解性"。对应 A08（iCloud 副本记设备绑定）与 K07（服务密钥在 Apple HSM 同时又记设备绑定）。

**误区 M4 · 加密本地备份跟着那台 iPhone 走。**
依据：第 1997 行"there's no tie to a specific device"；第 1996 行 backup keybag 存在用于同步的那台电脑上。
照做的结果：把手机处置干净，副本连同钥匙仍在电脑上；反过来把电脑处置干净，却不知道该副本还能被任何一台电脑用同一个口令解开。对应 A03、K03、脚本二的 Z01、Z04。

**误区 M5 · 未加密本地备份里什么都没有。**
依据：第 1998 行——不加密时文件不加密（不论数据保护类），而钥匙串项仍由 UID 派生密钥保护。
照做的结果：两个方向都错。写成"整体明文"会漏掉钥匙串那一层（K11 要求 `keychain_uid_protected` 不为 false）；写成"整体不可读"会漏掉文件层其实完全未加密这一事实（K02 拦住"未加密副本挂 backup keybag"）。**这一类副本的正确记法是分层：文件层明文，钥匙串层受 UID 密钥保护。**

**误区 M6 · app 打了排除标记，所以那些数据不在备份里。**
依据：《Optimizing Your App's Data for iCloud Backup》第 38 行——`isExcludedFromBackup` 只是给系统的提示，"it's not a mechanism to guarantee those items never appear in a backup or on a restored device"；《isExcludedFromBackup》第 10 行——常见的文档操作会把该属性重置为 false。
照做的结果：一份内容清单会因为一个不保证的标记而漏记类别，进而让删除范围算小。对应 C06（`exclusion_guarantees=true` 直接阻断）。

**误区 M7 · 曾经开过高级数据保护，所以这段历史会一直保护我。**
依据：第 2698—2699 行——关闭该功能时设备把服务密钥重新上传到 HSM，且**上传两代**（开启前生成的原始密钥与开启后生成的新密钥），"This makes all data in these services accessible after authentication"。
照做的结果："以前开过"不是安全历史，而是一个可回滚的配置状态。判断某一代副本归谁可解必须看**判断时刻**的 custody 值与最后一次轮换日。对应 K08、K09；台账上只有布尔开关而没有 `rotated_at` 时无法区分两种状态。

**误区 M8 · 健康数据在所有备份里都有。**
依据：《Backup methods for iPhone or iPad》第 57 行与平台安全指南第 2275 行同口径——要备份 Activity、Health 与 Keychain 数据需要创建加密备份。
照做的结果：在未加密本地副本上声明含健康数据（C02），或者在 iCloud 侧按本地备份的口径推断（第 6 章的进/出清单按介质分列，两条清单不同）。

**误区 M9 · 恢复只是把数据搬回去。**
依据：第 4416—4417 行——含硬件绑定密钥的 ACME 配置在恢复时被移除；若该密钥用于设备管理服务身份，设备退管。第 1644 行——同机恢复 iCloud 备份保留既有 Apple Watch 配对。第 2740—2741 行——语音信箱密码需要备份时那张实体 SIM。
照做的结果：恢复完成后设备脱离管理、配对关系与预期不同、某些条目不可用，而台账只写了一句"已恢复"。对应 R01—R07；其中 R04 是唯一一条改变**设备与组织关系**的信号。

**误区 M10 · MDM 能列出、加密或删除员工设备上的备份。**
依据：本轮对《Commands and queries》《Declarations》《Profile-specific payload keys》三份文档做词频统计，`backup` 与 `restore` 命中均为 0（R18）。
照做的结果：管理台里存在一条永远不会出现的动作，配置文档里留下一项无法交付的承诺。对应 M02—M04（脚本一信号），以及 M05（把管理面读数记成电脑侧副本的实证）。

**误区 M11 · 公告里出现 `MobileBackup` 就等于备份功能有缺陷。**
依据：三份并行版本线公告共 392 条 CVE 行，含 backup 一词的 2 行都属组件 `MobileBackup`，描述分别是路径处理与路径穿越（第 13.1 节）。
照做的结果：把"处理备份相关代码路径的守护进程有缺陷"读成"备份数据可被读取"。这正是 F4 的换算失败；对应 V01、V02。

**误区 M12 · 台账齐备就等于处置完成。**
依据：第 20.3 节第 3 条；脚本只校验"有没有写"，不校验"写得对不对"（第 3.5 节）。
照做的结果：O5（可证删除覆盖率）满分而实际可读性未变——因为 `dele` 谓词检查的是记录形式，形式由 `rotated_at` 与见证主体构成，两者都可以被填上而不发生实际轮换。**指标证明的是记录质量，不是处置结果**；这句话应当出现在任何一份基于本框架出具的声明里。

---

## 25. 常见问题

**Q1 · 这一层跟"设备有没有漏洞"有什么关系？**
没有直接关系。副本问题出现在备份策略调整、离职交接、换机、换电脑、账号合并、更换管理服务商这些**跟漏洞无关的事件**里。它的后果不是"多一个 CVE"，而是"上一位使用者的数据对新持有者仍可读"或"一份我们以为已经删掉的副本仍可恢复"。第 09 篇管补丁走到哪，第 10 篇管设备属于谁，本篇管数据副本落在谁手上、还能不能被证明清掉。

**Q2 · 为什么这篇不提供任何"验证副本可否解开"的做法？**
这是第 2.3 节的实质约束，不是行文保守。副本可解性一旦要"验证"，实际操作就变成提取或解密他人备份。本篇的替代做法是把可解性写成**归属问题**：`password_owner`、`service_key_custody`、`device_bound`、`rotated_at` 四格足以判定"归谁可解"，而不需要任何人去证明它真的可解。

**Q3 · 备份口令到底能不能进台账？**
不能。`key.password_recorded=true` 直接触发 K05 并要求删除该字段（第 14.5 节）。这与第 10 篇对托管凭据值的处理一致：台账记归属与失效条件，不记值；也不接受"记哈希""记前几位"这类折中。

**Q4 · 口令归谁，能不能从界面上读出来？**
不能。四个读数面（第 18 章）里，设备侧只显示"已设口令"，电脑侧只显示"这台电脑上的备份口令"这一事实，账号侧与管理侧完全无关。所以 K03 是阻断信号：**唯一决定这类副本可解性的那一格，没有任何界面能替我们填**，只能靠流程登记并复核。

**Q5 · 一份副本最少要记哪几格才不算空白？**
四元组：`(介质, 形态, 读数来源, 快照时刻)`（第 18.2 节）。缺任一项即 A01（快照时刻或读数来源）或 A02（介质或形态），脚本判 J4，也就是"只观察到副本存在"。要再往上走一级需要补 `keybag_kind`（K01）；再往上需要补口令归属与服务密钥归属两格（K03、K06）。

**Q6 · "已删除"这句话该怎么写才成立？**
按第 19.2 节 `dele` 谓词的四项要求写：请求动作 + 事件时刻 + 见证主体 + 密钥侧证据，且不存在旧副本存活。实证级（`deletion_evidence=attested`）要求轮换或等价事件（D04）与非 none 见证（D03）；推断级（`inferred`）要求有删除时刻且无旧副本存活。已有轮换证据却仍记 `inferred` 会撞上 D08——那会让这份副本被重复计入待处置队列。

**Q7 · 高级数据保护开着还是关着，对副本归属影响有多大？**
大到会翻转结论。开启时 iCloud Backup 服务密钥与 Messages 容器密钥都轮换（第 2746 行），旧密钥解不开新写入；关闭时两代密钥都被重新上传（第 2698—2699 行），账号回到"认证后可用"。所以 `custody` 一格不能只写当前值，必须与最后一次 `rotated_at` 成对出现（K08、K09）。

**Q8 · Apple Watch 这类配件要不要单独记一份副本？**
不单独记内容，但要单独标记。手表备份包含在 iPhone 的备份里（《What does iCloud back up?》第 34 行），把它的內容写成独立内容项触发 C08；`copy.device_class=watch` 触发 B02（非阻断），提示本篇矩阵不给它独立责任方，公告渠道也独立处理。

**Q9 · 这两个脚本能代替审计吗？**
不能。脚本一只校验"这一格有没有写、写的话是否与口径冲突"，脚本二只校验"三件文档之间对不对得上"。两者都不接触设备、不联网、不读副本，因此不可能校验内容真伪。它们的输出适合做审计前的准备与审计后的复核，不适合当作审计结论。

**Q10 · 为什么管理面与公告面全是空读数，还专门各写一章？**
因为空读数在本篇是可交付结论而不是背景说明。第 12.1 节的空集允许这样一句话：**依据公开协议文档，设备管理协议里不存在列出、强制加密或删除用户备份的动作**。第 13.2 节的三层空读数允许另一句：**本轮三个公告口径无法表达"某漏洞影响 iCloud 备份"这个命题**。两句都是负命题，都必须附口径范围；把它们从报告里删掉，剩下的文本就只剩机制描述，而机制描述容易被误用为实例声明（V4）。

**Q11 · 信号码能不能直接当成合规结论？**
不能。J1—J4 回答"这份台账能支撑到哪一层结论"，没有任何一级意味着"这台设备是安全的"或"这些数据已不可读"。同理 Q1—Q4 回答"三件之间同不同步"，与合规无关。

**Q12 · 我手上只有设备侧读数，能做什么？**
能做的比看上去多：可以出介质层与时间层的记录（`medium`/`kind`/`snapshot_date`/`source_of_record=settings_screen`），可以按第 15 章矩阵逐层标记"不可判定"，可以据此把该副本停在 J3 并列出补采集要求。不能做的是跨介质引用与任何内容级声明（V3）。

---

## 26. 未公开文档化边界清单

九条，按"缺的是哪一句"写。**这一章是本篇唯一允许出现"文档未展开"的地方**；正文其它各处凡遇到未展开，都指回这里的编号。

**G1 · 已删除副本没有回看面。**
账号侧元数据三项（支持文档第 205—213 行）只描述现存副本；本轮四份支持文档与指南的备份章节里，**没有任何一处描述"删除后还能不能列出该条目"**。影响：删除类结论只能靠回执（处置记录）而不是靠读数复核，因此 D01/D03 要求事件时刻与见证主体。台账做法：把删除当独立事件登记，不指望从读数反推。

**G2 · 服务密钥档位没有直接读数。**
指南给出机制两类（第 2666—2667 行），支持文档给出功能开关（《How to turn on Advanced Data Protection for iCloud》），但**没有任何一处描述"这个账号当前哪些服务处于哪一档"**。影响：`key.service_key_custody` 只能由账号持有人自陈或据开关推断；本文允许后者但要求标注为 `inferred`，且不允许据此出实证级删除结论（D08）。

**G3 · 电脑侧副本的口令归属没有第三方认定面。**
第 18.1 节。加密本地副本没有设备绑定（第 1997 行），而口令归属只能自陈。影响：K03 与 H02 只能靠流程（登记、交接、复核）满足；这一格的证据强度上限为"自陈 + 回执"，不能因"界面上确认过"而升级。

**G4 · 180 天窗口的三个分支未展开。**
支持文档第 45 行给"关闭 iCloud 备份后副本保留 180 天"，但**未展开：期间重新开启是否重置窗口；手动"删除旧的 iCloud 备份"（同一页第 45 行前半句）适用哪条保留语义；账号删除时该窗口是否适用**。影响：`retained_after_off_days` 与 `delete.retention_days` 两个口径必须一致（D06），否则一份记录同时说了两个删除时间——这不是记录混乱，而是把三条未展开的分支强行合并成一条。

**G5 · 本地副本删除时 backup keybag 的处置未展开。**
第 1996—1997 行说明 backup keybag 由加密备份创建、存在那台电脑上、由口令保护；**但删除备份目录时该 keybag 是否随之销毁、能否被单独移除，文档未展开**。影响：电脑侧的删除结论一律记 `inferred`，除非有介质层处置证据；这也是 H03（口令只有持有者知道却由厂商见证删除）之所以为阻断的原因——不掌握口令的一方无从见证该副本解密性的消失。

**G6 · escrow keybag 的作废条件未文档化。**
第 2000 行给它的两个存放位置（用于同步的电脑，或设备管理服务）与用途（免密码同步、远程清除用户密码）；**没有一句写它随副本删除、退出管理或更换服务商而作废**。第 10 篇 G5 处理的是同类缺口在凭据侧的表现，本篇只登记落点：`key.keybag_kind=escrow` 的副本必须单独成行（Z02 拦住"escrow 记在 iCloud 介质"）。

**G7 · 恢复后新旧副本之间的归属关系未展开。**
《Restore your iPhone, iPad, or iPod touch from a backup》第 47 行写"Setting up your device as new creates iCloud backups that replace your saved iCloud backups"，第 2745 行写关闭备份会生成新密钥、旧容器密钥解不开新写入数据；**但"作为新设备设置"之后旧副本的可读性与新副本的密钥归属之间关系未展开**。影响：D07（记了 setup_as_new 但未请求删除）只能要求一个动作记录，不能推出可读性变化；这一格在台账里应同时留 `setup_as_new_after` 与 `old_copies_survive`。

**G8 · 本文档口径里没有字段位的一组事实。**
逐条列在第 23.4 节：**副本的完整穷举**（V3 决定分母不可得）、**app 级排除标记的实际生效状态**（只有 `marks_used` 可记）、**人员 ↔ 副本的直接绑定**（台账命名空间只有 `holder.*`，没有人员字段）、**逐条数据的进入/退出**（V2 只到类别级）、**电脑侧口令的强度或历史**（本文拒收任何口令事实，只记归属）。这一条与 G1—G7 分开写，是因为前者需要 Apple 补文档，后者需要**我们补字段定义或承认不可得**；混在一起会让读者以为脚本"漏检"，实际是那些格子没有读数。

**G9 · 管理面唯一连接点没有对账命令。**
第 12.4 节：escrow keybag 可以存在设备管理服务上，这是整条链路里管理与密钥体系唯一被文档写明的连接；**但协议里没有任何命令可以读出"这台设备的服务侧是否有 escrow keybag、何时生成、是否作废"**。影响：托管设备的这一格只能记 `unknown`，脚本对 `key.keybag_kind=escrow` 与 `mgmt.org_visibility` 的组合不给正向结论；采购与处置合同里应把这一格写成"服务方陈述 + 事件回执"双要件，而不是写成管理侧读数。

### 26.1 三条处置原则

1. **G1—G7、G9 只允许以"补采集要求"的形式出现在流程里**，不允许以"检查项"的形式出现在脚本里——它们没有可读的输入。脚本里出现的每一条判断都必须能回指到本文某一处已核验文本。
2. **G8 允许扩展，但有顺序**：若下一轮补出字段定义（例如在 `holder.` 命名空间里加入人员标识列），应先更新第 3.1 节字段表与本节分界，再动脚本。**本篇不给脚本加没有文档依据的字段**，这条与第 10 篇同口径。
3. **G2、G5 决定了本篇的结论上限**：账号侧的删除声明与电脑侧的可解性声明，在任何组合下都不允许同时达到"实证 + 完整"。第 19 章 J1 的降级变体（三项齐备但删除不可核验）正是为这一处上限设计的落点。

---

## 27. 结论

本篇写了三件事：**副本落在谁手上、这一点能被谁知道、以及"清掉了"这句话要怎么写才成立**。

**第一，这一层的缺陷绝大多数是记录缺陷，不是实现缺陷。**十二章十层拆完以后，能在公开文档里找到"实现与此处口径不符"的点是零个，能找到"公开口径彼此换算失败"的点是七个（F1—F7）。第十二章那个空集与第十三章的三层空读数尤其说明问题：这一层上最难的不是"有没有洞"，而是**有些命题在当前口径里根本无法表达**，而组织与个人都在用没有出处的句子回答它们。第 14 章的 P1—P12 因此不是漏洞类型，而是十二种可复现的记错方式。

**第二，副本的可解性与副本的存在性由不同的人掌握。**第 15 章的矩阵里，L2（落点）由介质所有人回答，L6（可解性）由口令归属与服务密钥归属两格共同回答，L8（删除）由密钥持有者回答——三行没有一行是同一个人。这就是为什么"处置完成"在这条链路上特别容易被误写：执行处置的一方与能证明处置的一方往往不是同一方，而第三方可核对的面（管理侧）在协议里为空。**由此得到本篇最重要的一条操作性结论：删除类声明必须写成四要件（请求、时刻、见证、密钥侧证据），缺一不可**（D01—D05）。

**第三，可见性有边界，而且边界是文档给出的，不是实践给出的。**V1—V4 四条各自有出处：元数据三项只到类别为止（第 205—213 行）、四个读数面各只显示自己那一侧（第 18 章）、机制口径不给实例状态（第 1996—1998、2722—2746 行只描述"这类副本如何工作"）。这意味着**任何声称越界的读数都应被当成记录缺陷处理**，而不是当成更强的证据收下——这一条在 K05（口令入台账）、C06（排除标记当保证）、M02—M04（管理面越权声明）、V02（组件名当语义命中）四处分别落地。

**第四，两个脚本的作用是把上述四条变成可周期执行的动作。**86 个信号码 + 32 个信号码，全部由公开文本推导；离线、只读、不碰设备。第 23 章的分支覆盖验收给出全部 118 个码的可达性证据：坏样本能逐一触发到每一个码，好样本退出码为 0 且不产出任何阻断信号。**这套验收本身也是本篇口径的一部分**——不能触发的信号等于没有。

最后留一句限制：本篇所有结论成立于第 16 章 R1 固定的那份版本快照（4,885 行，md5 `d106784191540ae19729ac4aeea7e602`），以及本轮取回的支持文档、公告、KEV 目录与设备管理协议文本。指南换版会移动行号；词表与参考数值（180 天、1,000 万次迭代）变更会改变判定逻辑。**趋势断点必须与口径变更事件一并记录**（第 20.2 节），否则会把口径调整读成质量变化——这本身就是本篇第十二章之后最想留住的那类错误。

---

## 28. 参考资料

本轮存档：`.srcx11/`（取回日期 2026-11-01；索引件 `.srcx11/IDX/files.tsv` 收录 72 条；派生件 6 条）。全部为公开文档，离线取回，未访问任何设备、未调用任何设备侧或 Apple 命令行工具。

### 平台安全与机制（B 组）

1. Apple, *Platform Security Guide*（段落换行转文本件 `apple-platform-security-guide.txt`，4,885 行 / 697,288 字节 / md5 `d106784191540ae19729ac4aeea7e602`）。本篇引用的关键段落：指纹模板不离开设备（第 568 行）、Apple Watch 与安全配对（第 1635、1644 行）、数据保护类与 keybag 五类（第 1976 行）、加密与未加密本地备份、backup keybag 与 1,000 万次迭代、escrow keybag 落点（第 1996—1998、2000 行）、iCloud Backup keybag（第 2015—2016 行）、健康数据与本地备份（第 2275 行）、Advanced Data Protection 与服务密钥两类、密钥删除与轮换、关闭时的两代回传（第 2646、2666—2667、2674、2680—2681、2696—2699 行）、iCloud Backup 触发前提与内容清单（第 2722、2724、2727—2728 行）、SIM 依赖与本地钥匙串 SEP 派生密钥（第 2740—2742 行）、Messages 容器密钥与端到端（第 2745—2746 行）、iCloud Keychain 托管与解开（第 2938、2953—2954 行）、EnergyKit 与 HomeKit 的本地备份排除（第 4095、4141 行）、硬件绑定密钥与 ACME 配置在恢复时被移除（第 4416—4417 行）。
2. 派生的分节转文本件：*Keybags for Data Protection*、*iCloud Backup security*、*Data Protection classes*、*Keychain data protection*、*iCloud encryption*（`sg-*.txt`）。

### Apple 支持文档（B 组 `pages/`）

3. 备份与恢复：*What does iCloud back up?*（第 30、34、43、45 行）、*Backup methods for iPhone or iPad*（第 57、62 行）、*How to back up your iPhone or iPad with iCloud*、*About encrypted backups on your iPhone, iPad, or iPod touch*（第 24、30、38、55 行）、*Restore your iPhone, iPad, or iPod touch from a backup*（第 47 行）、*Use Advanced Data Protection for your iCloud data*。
4. iCloud 安全与高级数据保护：*iCloud data security overview*、*Advanced Data Protection for iCloud*、*How to turn on Advanced Data Protection for iCloud*。
5. 隐私与数据说明：*Data & Privacy*（索引）、*iCloud Keychain & Privacy*、*iCloud Analytics & Privacy*、*Advanced Data Protection Analytics & Privacy*、*Health App & Privacy*、*Messages & Privacy*；*App Review Guidelines*。

### Apple 开发者文档（A 组）

6. 备份排除标记：*Optimizing Your App's Data for iCloud Backup*（第 38 行）、*isExcludedFromBackup*（第 10 行）、*URLResourceValues*。
7. CloudKit：*CloudKit*、*Encrypting User Data*、*Responding to Requests to Delete Data*、*Providing User Access to CloudKit Data*、*Deciding whether CloudKit is right for your app*。
8. 设备管理协议（本篇的空集来源）：*Commands and queries*、*Declarations*、*Profile-specific payload keys*（三份文档 `backup` 与 `restore` 命中均为 0）。

### 公告与在野利用口径（C 组）

9. Apple 安全发布三份并行版本线（CSAF `149041` / `149227` / `149230`；CVE 行 95 / 134 / 163，合计 392）。派生件 `advisory-backup-hits.tsv`（145 行命中矩阵）、`release-rows.tsv`（331 行发布表）。
10. CISA Known Exploited Vulnerabilities Catalog：派生件 `kev-apple.tsv`（95 条 Apple 条目，本轮 23 个副本相关用词命中 0）；`guide-backup-hits.tsv`（763 行，指南备份/密钥段落命中矩阵）。

### 本轮产物

11. 脚本一 `backup-copy-ledger-review.sh`（337 行，86 个信号码）：副本台账逐字段审查器，输出逐条信号码与 J1—J4 四级判定。脚本二 `backup-copy-crosscheck.sh`（230 行，32 个信号码）：清单件、密钥件、处置回执件三件差集与事件时序比对器，输出 Q1—Q4 闭合等级。
12. 样例输入与实跑输出：`fx/good.tsv`（2 份副本，退出码 0，仅 B03 与 J1）、`fx/bad.tsv`（13 份副本 + 3 行畸形记录，124 条阻断信号，86 个码全部可达）、`fx/g-list.tsv` / `g-key.tsv` / `g-receipt.tsv`（3 份副本全部 Q1，退出码 0）、`fx/b-list.tsv` / `b-key.tsv` / `b-receipt.tsv`（三次运行合计 32 个码全部可达）。全部实跑结果见第 21.4、22.4 与第 23 章。

### 同系列相邻篇目

13. 第 02 篇（访问控制与数据保护类）——本篇只在 L5/L6 引用其类密钥体系作为口径来源，讨论对象是"密钥作为副本保管条件"，不重复类定义。第 03 篇（应用防护与数据外溢）、第 05 篇（生物特征）、第 08 篇（采集授权）——分别拥有 app 侧数据出口、Face ID/Touch ID 注册链路、授权与用途声明；本篇的 C01/C03/C04 只判断"是否越界声明进副本"。第 09 篇（更新链与补丁传导）——管补丁走到哪；本篇管副本在谁手上。第 10 篇（设备生命周期与归属迁移）——管设备属于谁、托管凭据何时作废；本篇管数据副本的可证删除性，两篇在 escrow keybag（第 2000 行）与恢复后果（第 4416—4417 行）两处交接，一句话分工见第 2.2 节。第 12 篇（第三方 SDK 与依赖代码供应链归属）——管代码本体从哪条通道进来、谁签名、版本钉在哪一刻、"已经移除"能否证明；本篇管它落进备份之后的副本归属，两篇不共用主键，第 12 篇另把本篇第 08 篇一侧的"强制名单不可核"缺口按取回正文关闭。第 13 篇（日志、诊断与崩溃证据链归属）——管一条记录本身能不能作证：级别与留存、崩溃报告里的两个设备键与三套时刻字段、九条采集通道的可得性与同意口径；本篇管这条记录一旦被复制成副本之后归谁、可不可解。两篇唯一的交接点是"一份报告交付之后归谁"，分工线见第 2.2 节新增的一行，本篇不重述任何日志或崩溃字段口径。

---

咨询ios系统请咨询 telegram：https://t.me/one00190
