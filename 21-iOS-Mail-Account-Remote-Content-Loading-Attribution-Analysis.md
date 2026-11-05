---
title: "iOS 邮件账户与远端内容加载归属防御分析报告"
description: "iOS 上一个邮件账户是谁装配的、远端内容是哪个进程按谁的规则加载的、这条链路的判定在哪些面上读得回：十一层归属分解（L1 账户装配声明、L2 下发与作用域、L3 凭据与身份、L4 收发服务端、L5 S/MIME、L6 远端内容加载、L7 内容拦截、L8 组合与发送面、L9 管理面回查、L10 公告对齐、L11 引用与结论），三件（装配件／内容件／回查件）× 11 层 × 20 项核对项的差集口径，接口装配词表／平台安全口径词表／管理面与公告回查词表与八处换算失败，J1—J4 与 Q1—Q4 两套判定模型，两个离线只读核验脚本（58 + 43 个码，共 101 个全部实跑触发，34 次实跑逐码覆盖表）"
lang: zh-CN
---

# iOS 邮件账户与远端内容加载归属防御分析报告

## 摘要

本报告集前二十篇依次回答过这些归属问题：缺陷在哪（第 01、06、07、12 篇的攻击面归属）、谁能进入这道门（第 02 篇的访问控制归属）、这条链路看见了什么（第 03、04 篇）、这台设备归谁（第 08、10、11 篇的主体归属）、这段代码凭什么被允许运行（第 14 篇的授权链归属）、这条通道凭什么存在（第 15 篇的通道归属）、同网段上谁看得见谁（第 16 篇的局域网可达性归属）、一条内容进了检索面之后谁能查回来（第 17 篇的检索面归属）、一份从别处来的内容被判成了什么类型（第 18 篇的类型判定归属）、一帧画面有没有离开这台设备（第 19 篇的画面外流归属）、一个卷是什么形态又由谁挂上来（第 20 篇的卷与挂载归属）。本文回答系列里的第十一类：**一个邮件账户是谁以什么声明装配出来的、远端内容是哪个进程按谁的规则加载的、加载这件事在管理面与公告面上能不能读回来。**

这句话拆开是三个问句，判定权分属三方，三方互不通气。**账户是谁装配的**（`AccountMail` 声明的唯一用途是 `The declaration to configure a Mail account.`（`A/device_management_accountmail.txt:3`），声明类型写作 `com.apple.configuration.account.mail`（`:120`），配置示例只有一句 `This configuration sets up an IMAP email account with SMTP outgoing mail.`（`:40`）——装配权在声明式设备管理手里）；**远端内容按谁的规则加载**（面向用户的唯一成文口径是 `Protect Mail Activity downloads remote content in the background by default — regardless of whether you engage with the email`（`B/mail-privacy-protection-legal.txt:30`），而内容拦截的唯一公开接口 `MEContentBlocker` 只挂在 macOS 12.0 上（`C/platform-21.txt:27`）——加载与拦截权在 Mail 应用手里，公开接口只给了 macOS 一侧）；**加载这件事能不能读回来**（管理面 210 个纯键名里含 `Mail` 的只有 4 个（`C/readings-21.txt:118`），其中没有一个是「远端内容」；公告语料 1,266 行里影响句含 `remote content`、`tracking`、`sender`、`relay`、`load` 的行数**全部是 0**（`C/readings-21.txt:20—27`）——回查权在两个面上都只剩间接读数）。

本文的核心结论是这三件**两两都不闭合**，而且不闭合的位置与第 18、19、20 三篇都不同：18 篇的不闭合在「内容自带的声明」对「框架的判定」，19 篇的不闭合在「登记方对自己那条通道最没有读数」，20 篇的不闭合在「公开语料里没有形态维度」。本篇的不闭合更靠前一层——**公开语料把「账户装配」「内容加载」「缺陷归属」写成了三套彼此不引用的词表**。同一个 `Mail` 词形，在公告组件名列命中 15 行、在影响句列命中 **0 行**（`C/readings-21.txt:17、37`）；`message` 在影响句有 6 行、`email` 有 3 行（`:18—19`），但 `IMAP`、`SMTP`、`POP3`、`S/MIME`、`credential`、`account`、`remote content` 在两列里**全部是 0**（`:20—36`、`:41—56`）。也就是说：按组件名列筛「邮件类缺陷」会得到 36 行（Mail 15＋Accounts 15＋Messages 6，`C/readings-21.txt:3`），按影响句筛「远端内容加载」会得到 0 行，两个数之间没有任何换算关系。

比这更要紧的是一条**平台不对称**。十六份与本链路直接相关的公开文档里，iOS 与 macOS 都出现的有 4 份、只有 iOS 的 5 份、只有 macOS 的 7 份、两者都没有的 0 份、同一文档两平台版本差超过 5 的 0 份（`C/readings-21.txt:117`）。七份 macOS-only 文档里包括**全部六份 MailKit 文档**（`C/platform-21.txt:26—31`），也就是内容拦截、消息安全处理器、消息动作处理器这三类扩展能力的公开接口只在 macOS 一侧成立；而 iOS 一侧能公开读到的是四份 MessageUI 文档（`C/platform-21.txt:32—47`），它们描述的是「构造一封邮件并交给 Mail 应用」这一格。**「iOS 上邮件内容加载由谁按什么规则裁决」这一格，没有任何一份公开接口文档**。本文据此把这一格记为 `unknown`，而不是「不存在」——这两件事的差别贯穿全文。

第三条必须前置的是**唯一一处把「加载」与「用户是否点击」写反的公开口径**：`MailKit always applies content-blocking rules for enabled extensions. This is true even if the user clicks the “Load remote content” button on the banner that Mail displays when remote content isn’t loaded.`（`A/mailkit_mecontentblocker.txt:20`）。这句话同时给出了两个事实：Mail 在远端内容未加载时会显示一条横幅（banner），用户点击即触发加载；而内容拦截扩展的规则**不受这次点击影响**。换句话说，「用户点了加载」不等于「拦截规则被绕过」，但这句话的主语是 macOS 上的 MailKit 扩展，iOS 没有对应文档。本文把「点击事件」与「拦截规则」做成两条独立读数（脚本一的 `policy.load_event` 与 `policy.blocker_platform`，脚本二的 `content.load_event` 与 `content.blocker`），不把其中一条当另一条的证据。

全文有十二组可数的公开读数（第 16 章，R01—R20，每组给归档行锚）、两套四档判定模型（第 19 章）、十一层归属分解（第 4—14 章）、一个十一层 × 责任方 × 三件 × 证据的归属矩阵（第 15 章），以及两个完全离线、只读、不联网、不接触任何设备、账户或邮件服务器的核验脚本：邮件账户台账逐字段审查器（226 行，58 个码 = 54 个信号码 + 4 档判定）与远端内容加载三件差集与公告子词表比对器（222 行，43 个码 = 39 个信号码 + 4 级闭合）。**合计 101 个码全部由真实夹具触发**，34 次实跑（脚本一 19 次、脚本二 15 次）的逐码可达性见第 23 章；两支脚本的只读性质由第 23.1 节的二十段实证（P1—P20，临时目录前缀分别是 `mail21.` 与 `mrcd21.`）逐条给出位置。

---

## 目录

1. [引言](#1-引言)
2. [视角声明与本文边界](#2-视角声明与本文边界)
3. [三套词表：接口装配口径、平台安全口径与管理面公告回查口径，以及八处换算失败](#3-三套词表接口装配口径平台安全口径与管理面公告回查口径以及八处换算失败)
4. [L1 账户装配声明层：一个对象、两个服务端与一个 S/MIME 子树](#4-l1-账户装配声明层一个对象两个服务端与一个-smime-子树)
5. [L2 下发与作用域层：六种注册、两个作用域与「分别应用」](#5-l2-下发与作用域层六种注册两个作用域与分别应用)
6. [L3 凭据与身份层：一个资产类型、一条 None 规则与一次首次解锁](#6-l3-凭据与身份层一个资产类型一条-none-规则与一次首次解锁)
7. [L4 收发服务端层：收件有协议、发件只有四个字段](#7-l4-收发服务端层收件有协议发件只有四个字段)
8. [L5 S/MIME 层：声明对象、MailKit 处理器与平台安全口径的三处错位](#8-l5-smime-层声明对象mailkit-处理器与平台安全口径的三处错位)
9. [L6 远端内容加载层：后台下载、两段中继与一条横幅](#9-l6-远端内容加载层后台下载两段中继与一条横幅)
10. [L7 内容拦截层：唯一公开接口在 macOS，iOS 一格为空](#10-l7-内容拦截层唯一公开接口在-macosios-一格为空)
11. [L8 组合与发送面层：谁构造消息、谁最终负责发送](#11-l8-组合与发送面层谁构造消息谁最终负责发送)
12. [L9 管理面回查层：210 个纯键名里的四个 Mail 键](#12-l9-管理面回查层210-个纯键名里的四个-mail-键)
13. [L10 公告对齐层：36 行、0 行与七个 CVE](#13-l10-公告对齐层36-行0-行与七个-cve)
14. [L11 引用与结论层：doc.* 与十六份文档的平台坐标](#14-l11-引用与结论层doc-与十六份文档的平台坐标)
15. [归属矩阵：十一层 × 责任方 × 三件 × 证据](#15-归属矩阵十一层--责任方--三件--证据)
16. [公开读数：这条链路上能数出来的十二组事实](#16-公开读数这条链路上能数出来的十二组事实)
17. [可见性边界：这一层读者能拿到什么](#17-可见性边界这一层读者能拿到什么)
18. [五个读数面：装配侧、内容侧、回查侧、管理侧、公告侧](#18-五个读数面装配侧内容侧回查侧管理侧公告侧)
19. [两套判定模型：J1—J4 与 Q1—Q4](#19-两套判定模型j1j4-与-q1q4)
20. [运营指标 O1—O10](#20-运营指标-o1o10)
21. [只读核验脚本一：邮件账户台账逐字段审查器](#21-只读核验脚本一邮件账户台账逐字段审查器)
22. [只读核验脚本二：远端内容加载三件差集与公告子词表比对器](#22-只读核验脚本二远端内容加载三件差集与公告子词表比对器)
23. [实跑与覆盖验收](#23-实跑与覆盖验收)
24. [十二个误区](#24-十二个误区)
25. [常见问题](#25-常见问题)
26. [未公开文档化边界清单](#26-未公开文档化边界清单)
27. [结论](#27-结论)
28. [参考资料](#28-参考资料)

---

## 1. 引言

### 1.1 三个问句与三段判定权

本篇只问三个问题，而且每个问题都必须写清「谁有权回答」：

1. **这个邮箱账户是谁装进这台设备的？** 是声明式设备管理下发的（`AccountMail`，声明类型 `com.apple.configuration.account.mail`，`A/device_management_accountmail.txt:120`），还是用户在设置里手工建的？台账用 `MA_` 与 `PE_` 两个前缀区分（脚本一第 30 行）。这一问的判定权在**装配面**。
2. **一封邮件里的远端内容，是按谁的规则决定加不加载？** 公开成文口径只有面向用户的 Mail Privacy Protection 说明（`B/mail-privacy-protection-legal.txt:28—33`）与 macOS 上的 MailKit 内容拦截接口（`A/mailkit_mecontentblocker.txt:12—20`）。这一问的判定权在**内容面**，而内容面在 iOS 一侧没有公开接口。
3. **「加载了没有 / 谁让它加载的」能不能在管理面或公告面上读回来？** 管理面有 4 个含 `Mail` 的纯键名（`C/readings-21.txt:118—124`），公告面有 36 行邮件族记录（`:3`），但两者都不含「远端内容」词形。这一问的判定权在**回查面**，而回查面只能给出间接读数。

三段判定权分属三个文档体系：声明式设备管理文档（装配）、Mail 应用与 MailKit 文档加隐私法律页（内容）、限制项词表加隐私清单加安全公告（回查）。三者之间没有一份文档同时引用另外两方——这是本文的中心事实，也是第 22 章脚本二 X 族与 Z 族的全部设计根据。

### 1.2 为什么这一格在系列里非拆不可

第 03、04 篇处理的是「这条链路看见了什么」，第 08 篇处理的是「隐私申报怎么读」，第 17 篇处理的是「内容进检索面之后谁能查回来」，第 18 篇处理的是「一份内容被判成了什么类型」，第 19 篇处理的是「画面有没有离开设备」，第 20 篇处理的是「卷是什么形态」。这六篇都碰到过邮件，但都停在各自那一格：

- 03、04 篇把邮件当成一种数据来源，没有追问账户是谁装的；
- 08 篇读过 `NSPrivacyCollectedDataTypeEmailsOrTextMessages`（`A/nsprivacycollecteddatatype.txt:20`），但隐私清单只说「收集了邮件或短信，包括主题、发件人、收件人与内容」，**不区分「用户点开」与「后台预取」**；
- 17 篇的检索面只处理「内容进索引之后」，邮件在 Mail 数据库里（`B/apple-platform-security-guide.txt:2411`），不进聚焦索引；
- 18 篇的类型判定处理的是「一份内容被判成什么类型」，邮件正文与附件的类型判定在 Mail 进程内部，公开侧只有 MessageUI 的 `canSendMail()`（`A/messageui_cansendmail.txt:3`）这类能力查询；
- 19 篇的画面外流与邮件无关；
- 20 篇的卷形态只回答「邮件数据库落在哪个卷上」，不回答「这个账户是谁装的」。

所以这一格在系列里是空的：**装配有声明、加载有用户说明、缺陷有公告，三者之间没有一条公开的换算链**。本文就是要把这条链拆到「哪一段有原文、哪一段只有名称、哪一段什么都没有」。

### 1.3 本文的口径边界

本文的全部结论只落在「台账能不能自洽」「三件清单能不能对齐」「公开词表有没有覆盖」三个层面上。它不回答「某台设备上的某个账户安全不安全」，也不回答「某封邮件有没有加载远端内容」。第 23 章的 101 个码证明的是**判据可达**，不是**设备状态**；第 16 章的 20 组读数证明的是**公开语料里数得出这些数**，不是**这些数在设备上成立**。凡是需要设备、账户、邮件服务器或真实邮件才能回答的问题，本文一律写成 `unknown` 并说明缺哪一件证据。

---

## 2. 视角声明与本文边界

### 2.1 与系列内其他篇目的重叠界定

| 篇目 | 它回答什么 | 本篇只借用什么 | 本篇不重复什么 |
| --- | --- | --- | --- |
| 第 02 篇 访问控制与应用交互 | 谁能进入哪道门 | 账户数据被哪个进程读取的「主体」概念 | 权限判定本身 |
| 第 03、04 篇 数据采集链路 | 链路上看见了什么 | 邮件正文与附件作为数据类别的口径 | 采集通道的枚举 |
| 第 08 篇 隐私授权与用途声明 | 申报怎么读、用途怎么写 | 隐私清单的 `EmailsOrTextMessages` 数据类型（`A/nsprivacycollecteddatatype.txt:20`） | 授权弹窗与用途字符串 |
| 第 17 篇 聚焦索引与 Siri 建议 | 内容进索引后谁能查回 | 「内容落点」与「可删性」的读法 | 索引与检索流程 |
| 第 18 篇 非可信内容解析链路 | 内容被判成什么类型 | 「类型判定发生在哪个进程」的问法 | 解析器与类型声明 |
| 第 19 篇 屏幕画面外流 | 画面有没有离开设备 | 「落点可见性」的核对项写法 | 画面采集与投送 |
| 第 20 篇 卷与挂载形态 | 卷是什么形态、谁挂上来 | 邮件数据库的加密与落点口径（`B/apple-platform-security-guide.txt:2411`） | 卷枚举、挂载选项与密钥栈 |
| 第 22 篇 外接配件与近场配对 | 配对与近场信任归谁 | 无 | 全部 |
| 第 23 篇 平台校验组件与度量物 | 度量物与校验组件归谁 | 无 | 全部 |

**视角声明（防重复）**：本篇的自有视角是「账户装配声明 → 内容加载规则 → 回查面」这条三段链，而不是「邮件安全」这个大类。凡是只谈某个邮件 CVE 的技术细节、只谈 S/MIME 算法强度、只谈某个邮件服务器的配置，都不在本篇范围内。与第 20 篇的交界只有一句：邮件数据库的加密口径（`B/apple-platform-security-guide.txt:2411`）在本篇只作为「内容件的落点属性」引用，卷形态本身归第 20 篇。

### 2.2 三条硬边界

1. **不写任何账户操作步骤。** 不写创建账户、登录、输入口令、导入证书、配置代理、连接 IMAP／SMTP 服务器的任何做法；脚本一只读取台账文本，不产生任何账户配置。
2. **不写任何内容加载或拦截的操作路径。** 不写「如何让 Mail 加载远端内容」「如何让拦截规则失效」「如何伪造发件人」；`MEContentBlocker` 的规则格式与 `MEMessageSecurityHandler` 的解码流程只作为公开语义引用，不给出可执行步骤。
3. **不接触设备、账户与真实邮件。** 没有真实邮箱地址、没有口令、没有证书、没有邮件正文；夹具里的 `imap.example.com`、`user@example.com`、`asset-cred-1` 全是占位值。第 23.1 节的 P9、P10、P19 专门证明输入未被改写、临时目录零残留、脚本自身未被改写。

### 2.3 术语约定

| 术语 | 本文定义 | 不用它表示 |
| --- | --- | --- |
| 装配件 | 一份账户台账所登记的声明类型、服务端、凭据引用、S/MIME 身份与来源 | 「配置文件已安装」 |
| 内容件 | 一个主体在 MPP、Hide IP、后台下载、加载事件、拦截件五个方面的登记 | 「邮件已加载远端内容」 |
| 回查件 | 限制键、隐私数据类型、公告组件行三类可回查证据 | 「管理面已确认状态」 |
| 闭合 | 三件齐全且各自有公开锚点，允许写 `closed` | 「安全」 |
| `unknown` | 公开语料里读不到，且能指出缺哪一份文档 | 「不存在」或「关闭」 |
| 邮箱形态 | `in.cred_user` 含 `@` 的记账规则（脚本一 B09） | 地址真实可达 |

---

## 3. 三套词表：接口装配口径、平台安全口径与管理面公告回查口径，以及八处换算失败

本篇所有的「读不懂」都可以归到三套词表之间的换算失败。先把三套词表摊开。

### 3.1 表一：接口装配口径（8 个 Account 声明 + 16 份文档 + 47 行平台坐标）

声明类型全集 65 项，其中 `Account` 前缀 8 项：`AccountCalDAV`、`AccountCardDAV`、`AccountExchange`、`AccountGoogle`、`AccountLDAP`、`AccountMail`、`AccountSettings`、`AccountSubscribedCalendar`（`C/readings-21.txt:125`）。与邮件直接相关的只有 `AccountMail` 一项，另有 `AccountExchange` 一项与 Exchange 账户有关、`AccountSettings` 一项只配 Exchange 账户设置（`A/device_management_accountsettings.txt:9—10`，且平台仅 macOS 27.2，`C/readings-21.txt:94`）。

`AccountMail` 一页给出的结构是：一个账户对象、两个服务端对象（`AccountMailIncomingServerObject`、`AccountMailOutgoingServerObject`）与一个 S/MIME 对象（`AccountMailSMIMEObject`），后者再分加密与签名两个子对象（`A/device_management_accountmail.txt:9—15`；`A/device_management_accountmail_smime.txt:9—12`）。页面上能读到的字段说明是：

- 收件端六个字段：凭据资产（`A/device_management_accountmail_incoming.txt:9`）、认证方法（`:15`）、主机名（`:17`）、IMAP 路径前缀（`:19`）、端口（`:23`）、邮件协议（`:25`）；
- 发件端四个字段：凭据资产（`A/device_management_accountmail_outgoing.txt:9`）、认证方法（`:15`）、主机名（`:17`）、端口（`:19`）；
- 账户级两个字段：身份资产（`A/device_management_accountmail.txt:16`）与账户显示名（`:19`）。

十六份文档的平台坐标共 47 行（`C/platform-21.txt`），汇总成一句：iOS 与 macOS 都有 4 份、只有 iOS 5 份、只有 macOS 7 份、两者都无 0 份、版本差 >5 的 0 份（`C/readings-21.txt:117`）。这 47 行是脚本二 Y 族的唯一分母。

### 3.2 表二：平台安全口径（四段原文）

平台安全侧能读到的只有四段与邮件直接相关的原文，且都不在「远端内容加载」这一格：

1. **邮件数据库的加密**：`The Mail app database (including attachments), managed books, Safari bookmarks, app launch images, and location data are also stored through encryption, with keys protected by the user’s passcode on their device.`（`B/apple-platform-security-guide.txt:2411`）
2. **S/MIME 的身份投递**：`Identities used with S/MIME can be delivered to Apple devices using a configuration profile, a device management service, the Simple Certificate Enrollment Protocol (SCEP), or Microsoft Active Directory Certificate Authority.`（`:2307`）；同页还写明 `Per-message S/MIME` 支持 iOS、iPadOS、macOS 与 visionOS（`:2305`）。
3. **钥匙串里的邮件账户**：钥匙串条目分类表中，`Mail accounts` 与 `LDAP, CalDAV, CardDAV`、`Microsoft Exchange ActiveSync accounts` 同列，保护等级是 `Accessible After first unlock`（`:2155—2156`）。
4. **Apple Watch 直接取信**：`When Apple Watch and iPhone are out of range, Apple Watch connects directly to iCloud and Gmail servers to fetch mail, as opposed to syncing mail data with the paired iPhone over the internet.`（`:1668`）；同段还写明 Gmail 的 OAuth 令牌经 Apple Identity Service 加密送到手表，`never used for connectivity with the Gmail server from the paired iPhone`。

这四段给的是「数据落点、身份投递、凭据可读时点、多设备直连」四个侧面，**没有一段说远端内容在 iOS 上由哪个进程裁决**。

### 3.3 表三：管理面与公告回查口径（210 键、65 声明、35 类型、1,266 行）

- **管理面纯键名 210 个**，含 `Mail` 的 4 个、含 `privacy` 的 1 个、含 `relay` 的 1 个、含 `account` 的 1 个（`C/readings-21.txt:118`）。四个 Mail 键分别是 `allowCloudMail`（`:57`，`Available: macOS 10.12+`）、`allowMailPrivacyProtection`（`:112`，`Available: iOS 15.2+ | iPadOS 15.2+`，`Requires supervision: iOS`）、`allowMailSmartReplies`（`:113`，iOS 18.4+／macOS 15.4+，已标记 `Deprecated: iOS 26.4+`）、`allowMailSummary`（`:114`，iOS 18.1+／macOS 15.1+，同样已弃用）。
- **声明类型 65 项**，`Account` 前缀 8 项（`:125`）。
- **隐私数据类型 35 项**，`NSPrivacyCollectedDataTypeEmailsOrTextMessages` 在第 20 行，定义是 `Emails or text messages; including subject line, sender, recipients, and contents of the email or message.`（`A/nsprivacycollecteddatatype.txt:20`）。
- **公告子集 1,266 行**、平台去重 12、组件名去重 129、唯一 CVE 330（`C/readings-21.txt:1`）；邮件族三组件共 36 行、7 个 CVE（`:3—9`）。

### 3.4 八处换算失败

| 号 | 换算失败 | 一侧读数 | 另一侧读数 | 后果 |
| --- | --- | --- | --- | --- |
| K1 | 声明字段 → 运行行为 | 收件端 6 个字段、发件端 4 个字段 | 无任何「加载」「拦截」「缓存」字段 | 装配件写得再全，也推不出内容行为 |
| K2 | S/MIME 声明 → MailKit 处理器 | `AccountMailSMIMEObject` 在 iOS 17+（`A/device_management_accountmail.txt:14`） | 六份 MailKit 文档全部 macOS 12.0（`C/platform-21.txt:26—31`） | 同一功能两套接口，平台不重叠 |
| K3 | 组件名 `Mail` → 邮件功能 | 组件列 15 行（`C/readings-21.txt:37`） | 影响句 `mail` 0 行（`:17`） | 「邮件类缺陷」数不出「邮件功能缺陷」 |
| K4 | `remote attacker` → 远端内容 | 影响句 45 行（`:21—22`） | `remote content` 0 行（`:20`） | 攻击者位置不等于内容路径 |
| K5 | MPP 开关 → 远端内容是否加载 | 后台下载 `regardless of whether you engage`（`B/mail-privacy-protection-legal.txt:30`） | 关闭 MPP 后 Hide IP 仍生效（`:33`） | 「关掉 MPP」不是「停止下载」 |
| K6 | 210 键分母 → 4 个 Mail 键 | 210（`C/readings-21.txt:118`） | 4（`:118—122`） | 分母大、分子小，不能倒推覆盖面 |
| K7 | 平台标签 → 实际可用性 | 16 份文档 47 行坐标（`C/platform-21.txt`） | `AccountSettings` 只有 macOS 27.2（`:25`） | 「声明存在」不等于「iOS 可用」 |
| K8 | 隐私清单类型 → 加载事件 | `EmailsOrTextMessages` 含主题、发件人、收件人、内容（`A/nsprivacycollecteddatatype.txt:20`） | 无「预取」「后台」「横幅点击」字段 | 申报粒度到不了加载事件 |

### 3.5 三套词表的使用规则

1. **先定位词表，再读数值。** 同一个 `Mail` 在组件列、影响句列、限制键、声明类型里是四个不同的东西；不先说清在哪张表里，数值就没有意义。
2. **不跨平台相加。** iOS 的 `allowMailPrivacyProtection` 与 macOS 的 `allowCloudMail` 是两个平台的两个键，不能合并成「两个邮件限制项」。
3. **不把「文档没有」写成「系统没有」。** `MEContentBlocker` 没有 iOS 页面，只能写「iOS 侧无公开接口」，不能写「iOS 没有内容拦截」。
4. **每个 `closed` 必须能回指三件。** 缺任何一件，最高只能写 `partial`；读不到策略值，写 `unknown`。

---

## 4. L1 账户装配声明层：一个对象、两个服务端与一个 S/MIME 子树

### 4.1 本层回答什么

这一层只回答「一份账户台账有没有把装配结构写全」：声明类型、收件端、发件端、S/MIME 子树、账户级标识是否各就各位。它不回答「这台设备上有没有这个账户」，也不回答「这个账户能不能登录」。

### 4.2 三条结构读数

**读数一：声明类型只有一个合法值。** `AccountMail` 的 Discussion 只有一句 `Specify … as the declaration type`（`A/device_management_accountmail.txt:21—23`），页面末尾的 CODE 行给出 `com.apple.configuration.account.mail`（`:120`）。脚本一把它写成 B01 的判据（第 127 行）：声明类型写了别的值，整条台账就不能再按 `AccountMail` 读。

**读数二：收件端六字段、发件端四字段，字段集不对齐。** 收件端有协议（`The mail protocol this account uses.`，`A/device_management_accountmail_incoming.txt:25`）与路径前缀（`:19`），发件端两者都没有；发件端只有凭据资产、认证方法、主机名、端口四项（`A/device_management_accountmail_outgoing.txt:9—19`）。这意味着**「用什么协议发信」「发信走不走 TLS」在声明里没有独立字段**——只能由端口与认证方法间接推断。脚本一的 C 族正是按端口推断：143 必须 `starttls`（C01，第 141 行）、25 必须 `starttls`（C02，第 142 行）、993 不得 `tls=none`（C03，第 143 行）、465 不得 `tls=none`（C04，第 144 行），任一服务端写 `tls=none` 都出 C05（第 145 行）。

**读数三：S/MIME 是账户下的一个子树，不是一个开关。** `AccountMailSMIMEObject` 下分加密与签名两个对象（`A/device_management_accountmail_smime.txt:9—12`），账户级还有一个身份资产字段（`A/device_management_accountmail.txt:16`）。所以「启用 S/MIME」至少要写四件事：身份资产、资产类型、加密算法、签名算法；脚本一的 D 族按这四件事拆开（D01—D06，第 151—161 行）。

### 4.3 结构完整性与语义完整性是两件事

台账能检查的是结构完整性：字段在不在、值在不在合法集合里、端口与 TLS 是否自洽、S/MIME 子树的四个字段是否互相支持。它不能检查语义完整性：这个 IMAP 主机真的存在吗、这个凭据资产真的能解锁吗、这个 S/MIME 身份真的匹配账户地址吗。前者是 A、B、C 三族（26 个码），后者只能靠 `doc.*` 与 `claim.*` 两族间接约束（F、G 两族 13 个码）。

### 4.4 装配件与内容件的交界只有一个字段

装配件里唯一与「内容」沾边的是 `priv.data_type`（脚本一 E03、E04，第 166—168 行），它取自隐私清单的 35 个数据类型之一；但 `EmailsOrTextMessages` 的定义是「主题、发件人、收件人与内容」（`A/nsprivacycollecteddatatype.txt:20`），**没有「远端内容」「后台预取」「加载事件」任何一项**。所以装配件写到最全，也推不出内容件的五个读数（MPP、Hide IP、后台下载、加载事件、拦截件）。这是 K1 的落点，也是脚本二 Z 族要求三件分别登记的原因。

### 4.5 本层核对项

| 项 | 判据 | 码 | 档 |
| --- | --- | --- | --- |
| 声明类型 | 等于 `com.apple.configuration.account.mail` | B01 | V3 |
| 收件主机 | `in.host` 非空 | A03 | V3 |
| 发件主机 | `out.host` 非空 | A04 | V3 |
| 收件协议 | `in.server_type` 等于 `IMAP` | B03 | V3 |
| 端口 | 收件 143／993，发件 25／465／587 | B04／B05 | V3 |
| 路径前缀 | 只允许 IMAP 出现 | B06 | V3 |
| S/MIME 四件 | 身份、类型、加密、签名 | D01—D06 | V3／V2 |
| 账户标识 | `MA_` 或 `PE_` 前缀 | A01 | V3 |

---

## 5. L2 下发与作用域层：六种注册、两个作用域与「分别应用」

### 5.1 本层回答什么

这一层回答「这份声明是从哪条注册通道进来的、落在系统域还是用户域」。它决定同一份台账在不同注册方式下是否可比，也决定「管理面能不能读回」这一问的前提。

### 5.2 六种注册读数

`AccountMail` 页的 Configuration availability 一节给出六行：

| 注册方式 | 允许的平台 | 行号 |
| --- | --- | --- |
| Supervised enrollment | iOS, macOS, Shared iPad, visionOS | `A/device_management_accountmail.txt:25—26` |
| Device enrollment | iOS, Shared iPad, visionOS | `:27—28` |
| User enrollment | iOS, macOS, Shared iPad, visionOS | `:29—30` |
| Local enrollment | iOS, macOS, Shared iPad, visionOS | `:31—32` |
| System scope | iOS, visionOS | `:33—34` |
| User scope | macOS, Shared iPad | `:35—36` |

这六行里有两个不等号必须写死：**用户注册允许 macOS 但系统域不允许 macOS**；**用户域允许 macOS 与 Shared iPad，但不允许 iOS**。换句话说，在 iPhone 上，`AccountMail` 只能落在系统域；在 Mac 上，它只能落在用户域。脚本二 Y01 只查「账号声明有没有 iOS 行」（第 157 行），不区分系统域与用户域——因为平台矩阵的 47 行只有文档、平台、版本三列（`C/platform-21.txt`），没有作用域列。这是一处**公开坐标本身的缺列**，第 26 章 U03 会单独写。

### 5.3 「分别应用」是一条容易读反的语义

`Apply` 一节只有一句：`Multiple configurations are applied separately`（`A/device_management_accountmail.txt:38`）。对照 `AccountSettings` 页的同一节，写的是 `Multiple configurations are combined and applied as a single effective configuration`（`A/device_management_accountsettings.txt:28`）。两页的 Apply 语义**相反**：账户声明是分别应用，账户设置是合并成单一有效配置。这意味着两份 `AccountMail` 声明描述的是两个账户，而不是「同一账户的两半」；把它们合并成一条台账记录，会在结构上丢一个账户。脚本一的记录数统计（`nrec`）与 A06（字段重复且取值冲突，第 94 行）就是为防止这种合并：两个账户的字段同名但取值不同，合并后必然触发 A06。

### 5.4 来源与归属

台账用 `mgmt.source` 区分 `declaration`、`profile`、`user` 等来源（脚本一 E01，第 163 行），用 `mgmt.owner` 记归属人（E06，第 171 行），用 `mgmt.removal_path` 记移除路径（E07，第 172 行）。三条规则写死：

- 来源为空 → E01（V3）；
- 声明 `created_after_lock=yes` 且 `allow_modification=false` → E02（时间线矛盾，V3）；
- 来源是 `profile` 但 `profile_present=no` → E05（账户成孤儿，V3）。

这三条都只检查台账自洽，不检查设备状态。**「账户是谁装的」在公开文档里能读到的只有声明类型与注册方式；「这个账户现在归谁」读不到。**

### 5.5 本层核对项

| 项 | 判据 | 码 |
| --- | --- | --- |
| 来源非空 | `mgmt.source` | E01 |
| 时间线 | 锁定后新建与不可修改不能并存 | E02 |
| 归属人 | `mgmt.owner` | E06 |
| 移除路径 | `mgmt.removal_path` | E07 |
| 孤儿检查 | `profile` 来源必须有描述文件 | E05 |
| 标识复用 | 复用标识不得引用旧文档行 | E08 |

---

## 6. L3 凭据与身份层：一个资产类型、一条 None 规则与一次首次解锁

### 6.1 本层回答什么

这一层回答「账户的凭据与身份以什么形式被引用、在什么时点可读」。它不回答口令是什么，也不回答证书内容。

### 6.2 凭据只有一个合法资产类型

收件端与发件端的凭据字段说明是同一句式，只有末尾的 server 类型词不同：收件端为 `The identifier of an asset declaration that contains the credentials for this account to authenticate with an incoming mail server`（`A/device_management_accountmail_incoming.txt:9`），发件端为 `...with an outgoing mail server`（`A/device_management_accountmail_outgoing.txt:9`），资产类型在页末 CODE 行给出：`CredentialUserNameAndPassword`（incoming `:41`；outgoing `:35`）。脚本一 A07 据此判定：登记了凭据资产但类型不是 `CredentialUserNameAndPassword` → V3（第 124 行）。

### 6.3 `None` 规则是一条双向约束

收件端与发件端的凭据字段说明都带同一条规则：认证方法为 `None` 时凭据字段必须为空，否则该字段必须存在（`A/device_management_accountmail_incoming.txt:11—13`；`A/device_management_accountmail_outgoing.txt:11—13`），两页页末的 CODE 行都给出 `None`（incoming `:43`；outgoing `:37`）。这条规则在两个方向上都能触发：

- `in.auth=None` 但登记了凭据资产 → B07（第 135 行，V3）；
- `in.auth` 需要凭据但 `in.cred_asset` 为空 → B08（第 137 行，V3）。

发件端的同一规则在归档页里同样存在，但脚本一没有为发件端单设一对码：B07／B08 的判据只读 `in.*` 字段，`out.auth` 与 `out.cred_asset` 的矛盾目前不产生信号。这是判据覆盖面的一处已知缺口，写进 U04，而不是补一个没有夹具的码。

### 6.4 凭据在设备上的可读时点

平台安全指南的钥匙串分类表把 `Mail accounts` 与 `LDAP, CalDAV, CardDAV`、`Microsoft Exchange ActiveSync accounts` 并列，保护等级 `Accessible After first unlock`（`B/apple-platform-security-guide.txt:2155—2156`）。这句话给出了一个关键时点：**首次解锁之后，邮件账户凭据对相应进程可读**。它与「账户声明里凭据只是一个资产引用」是两件事：声明说「引用哪个资产」，钥匙串表说「这个资产在什么时点可读」。两者之间没有字段可以互相换算，脚本一只登记 `in.cred_asset` 与 `in.cred_asset_type`，不登记可读时点——这是 U05 的边界。

### 6.5 S/MIME 身份与投递通道

S/MIME 身份资产在账户级字段，类型是 `UserIdentity`（`A/device_management_accountmail.txt:16、119`）。平台安全指南给出的投递通道有四条：配置描述文件、设备管理服务、SCEP、Microsoft AD CS（`B/apple-platform-security-guide.txt:2307`）。这四条里只有「设备管理服务」与本篇的声明装配同源；另外三条不在声明文档里。脚本一的 D03 只检查「签名开启但身份资产类型为空」（第 155 行），D07 检查「同一身份资产被多个账户共用」（第 204 行，V2），两条都不检查投递通道。

### 6.6 本层核对项

| 项 | 判据 | 码 |
| --- | --- | --- |
| 凭据资产类型 | `CredentialUserNameAndPassword` | A07 |
| `None` 规则 | 认证为 `None` 时凭据为空 | B07 |
| 凭据必填 | 非 `None` 时凭据资产存在 | B08 |
| 邮箱形态 | `in.cred_user` 含 `@` | B09 |
| 口令内联 | `in.cred_secret_inline` 不得为 `yes` | B10 |
| 身份资产 | 启用 S/MIME 时非空 | D01 |
| 身份共用 | 同一身份资产不得被多账户共用 | D07 |
## 7. L4 收发服务端层：收件有协议、发件只有四个字段

### 7.1 本层回答什么

这一层回答「台账有没有把两个服务端分开写、端口与加密声明是否自洽」。它不回答「服务器可不可达」，也不回答「服务器证书是否可信」。

### 7.2 收件端：协议是一个独立字段

收件端页面有一行 `The mail protocol this account uses.`（`A/device_management_accountmail_incoming.txt:25`），页末 CODE 行给出唯一取值 `IMAP`（`:45`），同页还给出服务端类型键名 `ServerType`（`:44`）。脚本一 B03 因此写成「`in.server_type` 必须等于 `IMAP`」（第 129 行）。

路径前缀是 IMAP 专属字段：`The path prefix for the IMAP server. The system uses this only when … is …`（`:19—21`），后半句在抽取时把两个内联代码吃掉了，但 CODE 行 `:45` 的 `IMAP` 与 `:44` 的 `ServerType` 足以确定「只在服务端类型为 IMAP 时使用」。脚本一 B06 据此判定：路径前缀存在但服务端类型不是 IMAP → V3（第 134 行）。

### 7.3 发件端：四个字段，没有协议与 TLS

发件端页面只有四个字段说明：凭据资产（`A/device_management_accountmail_outgoing.txt:9`）、认证方法（`:15`）、主机名（`:17`）、端口（`:19`）。归档页里没有「邮件协议」字段，也没有 TLS 字段。对比收件端六个字段，缺的正是这两个。这不是抽取遗漏：同一份归档在收件端把协议字段抽出来了（`:25`），在发件端没有对应行。

后果是一处**推断链**：发件端是否加密，只能由端口与认证方法间接判断。脚本一把这条推断写死为四条规则：

- 发件端口 25 → 必须 `starttls`（C02，第 142 行）；
- 发件端口 465 → 不得 `tls=none`（C04，第 144 行）；
- 任一服务端 `tls=none` → C05（第 145 行，V3）；
- 收件端口 143 → 必须 `starttls`（C01，第 141 行）；收件端口 993 → 不得 `tls=none`（C03，第 143 行）。

四条规则都是**台账内部约定**，不是 Apple 文档原文。文档只给端口是 `integer`、认证方法是 `string`，没有给「25 必须 STARTTLS」这种约束。本文把这一点写在 U06：判据是本文的，锚点是端口字段，两者不能混为一谈。

### 7.4 主机名的三种形态

脚本一对主机名做三条检查：

- IP 字面量 → C06（第 146 行，V2 提示）：文档没有禁止 IP，但 IP 字面量与「可轮换的服务端身份」不是一回事；
- `.local` 结尾 → C07（第 147 行，V2）：本地域名无法由公开 DNS 复核；
- 收件与发件域名不同 → C08（第 149 行，V2）：这是最常见的合法形态（收件 `imap.example.com`、发件 `smtp.example.com`），所以只提示不阻断。

三条都是「提示级」，不改变判定档：V2 表示「可读但有一处需要注意」，不是「有问题」。

### 7.5 本层核对项

| 项 | 判据 | 码 | 档 |
| --- | --- | --- | --- |
| 收件协议 | `IMAP` | B03 | V3 |
| 收件端口 | 143／993 | B04 | V3 |
| 发件端口 | 25／465／587 | B05 | V3 |
| 路径前缀 | 仅 IMAP | B06 | V3 |
| 143／25 的 STARTTLS | 台账约定 | C01／C02 | V3 |
| 993／465 的 TLS | 台账约定 | C03／C04 | V3 |
| 任一 `tls=none` | 直接阻断 | C05 | V3 |
| IP 字面量 | 提示 | C06 | V2 |
| `.local` 域名 | 提示 | C07 | V2 |
| 收发域名不同 | 提示 | C08 | V2 |

---

## 8. L5 S/MIME 层：声明对象、MailKit 处理器与平台安全口径的三处错位

### 8.1 本层回答什么

这一层回答「S/MIME 的身份、签名与加密在三套文档里各自被写成了什么」。它是全文平台不对称最集中的一层。

### 8.2 三套文档，三种切法

| 文档体系 | 它写的 S/MIME 是什么 | 平台 | 锚点 |
| --- | --- | --- | --- |
| 声明式设备管理 | 账户下的一个对象，分加密与签名两个子对象，身份是一个资产引用 | iOS 17+／iPadOS 17+／visionOS 1.1+，**无 macOS** | `A/device_management_accountmail.txt:13—15`；`C/readings-21.txt:90—93` |
| MailKit | 扩展实现的消息安全处理器，Mail 把进出邮件内容交给它加密与签名 | **仅 macOS 12.0** | `A/mailkit_memessagesecurityhandler.txt:16`；`C/platform-21.txt:31` |
| 平台安全指南 | 功能级口径：逐封 S/MIME 在四个平台都支持，身份可由描述文件、设备管理、SCEP、AD CS 投递 | iOS、iPadOS、macOS、visionOS | `B/apple-platform-security-guide.txt:2305—2307` |

三套文档的交集只有「S/MIME 这件事存在」。第一套给的是**账户级装配**（身份资产、加密开关、签名开关、算法），第二套给的是**消息级处理接口**（编码、解码、签名验证），第三套给的是**功能级可用性**（哪些平台支持逐封签名加密、身份从哪来）。三者之间没有一份文档引用另外两份。

### 8.3 声明对象的四个开关

脚本一把 S/MIME 拆成六个检查：

- 启用但身份资产缺失 → D01（第 151 行，V3）；
- 加密开启但签名关闭 → D02（第 153 行，V2）：这不是错误，是一种常见配置，但必须显式登记；
- 签名开启但身份资产类型为空 → D03（第 155 行，V3）；
- S/MIME 对象声明在 iOS 17 之前 → D04（第 157 行，V3）：声明对象在 iOS 17 才引入（`A/device_management_accountmail.txt:14`），早于 17 的平台写这个对象就是时间线矛盾；
- 加密开启但算法为 `none` → D05（第 159 行，V3）；
- 签名开启但算法为 `none` → D06（第 161 行，V3）。

六个码里只有 D02 是 V2，其余都是 V3。这是一条刻意的取舍：**「开了加密没开签名」是策略选择，「开了签名没有身份」是结构矛盾**，两者不能同档。

### 8.4 MailKit 处理器给出的两条额外事实

`MEMessageSecurityHandler` 页有两句声明式的话：

1. `When users enable an extension that implements a message security handler, Mail passes incoming and outgoing message content to the extension for encryption and digital signing.`（`A/mailkit_memessagesecurityhandler.txt:16`）
2. `MailKit stores the encrypted and signed message content. Therefore, MailKit may ask a message security handler to decode the same message repeatedly over time when it needs the decoded original message content.`（`:29`）

第一句说明「内容会交给扩展」，第二句说明「MailKit 自己存加密与签名后的内容，并可能反复请求解码」。这两句都只挂在 macOS 12.0 的文档上，iOS 侧没有对应页面。它们对归属的意义是：**在 macOS 上，「谁见过明文」至少有两个主体（Mail 与安全处理器扩展）；在 iOS 上，公开文档没有给出同样的分工。**

### 8.5 平台安全指南的「逐封」口径

指南写明 `iOS, iPadOS, macOS, and visionOS support per-message S/MIME`（`B/apple-platform-security-guide.txt:2305`），并给出身份投递四条通道（`:2307`）。这条口径与声明对象的时间线有一处需要对齐：逐封 S/MIME 在四个平台都支持，但**声明对象在 iOS 17 才出现、且没有 macOS 行**（`C/readings-21.txt:90—93、117`）。两者不矛盾——「功能支持」不等于「可由声明装配」——但读者很容易把前者当成后者的证据。脚本一 F06 因此拦一种具体错法：宣称逐封 S/MIME 但账户未启用 S/MIME（第 188 行，V3）。

### 8.6 本层核对项

| 项 | 判据 | 码 |
| --- | --- | --- |
| 身份资产 | 启用时非空 | D01 |
| 加密与签名并存 | 加密开启时签名状态必须显式 | D02 |
| 身份资产类型 | 签名开启时非空 | D03 |
| 平台时间线 | 不得早于 iOS 17 | D04 |
| 加密算法 | 不得为 `none` | D05 |
| 签名算法 | 不得为 `none` | D06 |
| 宣称与装配一致 | 逐封 S/MIME 需账户已启用 | F06 |
| 身份共用 | 同一资产不得跨账户 | D07 |

---

## 9. L6 远端内容加载层：后台下载、两段中继与一条横幅

### 9.1 本层回答什么

这一层回答「远端内容在什么条件下被下载、下载经过谁、用户能不能看见这次加载」。它是全文唯一一层，其公开原文来自**面向用户的隐私说明**而不是接口文档。

### 9.2 四句原文

1. `Emails you receive may include remote content that allows the email’s sender to learn information about you.`（`B/mail-privacy-protection-legal.txt:29`）
2. `Protect Mail Activity downloads remote content in the background by default — regardless of whether you engage with the email.`（`:30`）
3. `Protect Mail Activity routes all remote content downloaded by Mail through two separate relays operated by different entities.`（`:31`）；同一段继续写：第一个中继知道 IP 但不知道第三方邮件内容，第二个中继知道内容但不知道 IP，`instead providing a generalized identity to the destination`。
4. `If you choose to disable Protect Mail Activity, the Hide IP Address feature will still mask your IP address using the same two-separate-internet-relays design.`（`:33`）

这四句给出了一条完整的加载链：**收信 → 后台预取（默认，与用户是否互动无关）→ 两个不同实体运营的中继 → 目的端只看到泛化身份**。关闭 Protect Mail Activity 只关掉「预取与反追踪」这一层，Hide IP 仍然用同一套双中继设计（`:33`）。

### 9.3 一处必须写死的否定

这四句里**没有一句**说「用户点击 Load remote content 横幅之后会发生什么」。唯一把「点击」与「加载」写在一起的是 MailKit 内容拦截页：`This is true even if the user clicks the “Load remote content” button on the banner that Mail displays when remote content isn’t loaded.`（`A/mailkit_mecontentblocker.txt:20`）。这句话的主语是「内容拦截规则始终生效」，不是「点击触发加载」。所以：

- 「Mail 在未加载远端内容时会显示横幅」——有原文（`:20` 的从句）；
- 「点击横幅会触发加载」——可由从句推出「存在一个加载动作」，但没有独立的加载接口文档；
- 「点击之后经过哪个进程、走不走中继」——**没有原文**。

脚本一把这三件事拆成三个字段：`policy.load_event`（加载事件读数）、`policy.background_download`（后台下载读数）、`policy.relay_count`（中继段数）。三者互不替代。

### 9.4 五个内容读数与三条一致性规则

内容件登记五个读数：MPP 开关、Hide IP 开关、Hide IP 依据、中继段数、后台下载；外加一个加载事件与一个拦截件。脚本一的三条一致性规则是：

- MPP 开启但中继段数不是 2 → F03（第 181 行，V3）：原文写的是 `two separate relays`（`:31`），不是「至少两个」；
- MPP 关闭却把 Hide IP 记成 MPP 的一部分 → F04（第 184 行，V3）：原文明确 Hide IP 在 MPP 关闭后仍生效（`:33`）；
- 后台下载开启但 MPP 关闭 → F05（第 186 行，V3）：原文把「后台下载」写在 Protect Mail Activity 名下（`:30`）。

三条规则都只检查台账自洽。它们不能证明设备真的在后台下载，也不能证明中继真的只有两段——后者在公开文档里只有一句定性描述，没有任何可观测读数。

### 9.5 `unknown` 是这一层的默认值

`policy.remote_content_policy` 只有一个合法值域：`declared` 或 `unknown`。写 `unknown` 时脚本一直接把整条记录判成 V4（第 177 行），无论其他字段多完整。这条设计是刻意的：**远端内容策略是本层的核心读数，读不到就是不可判**，不能用「其他字段都齐」把它稀释成 V2。

### 9.6 本层核对项

| 项 | 判据 | 码 | 档 |
| --- | --- | --- | --- |
| 策略值 | `declared`／`unknown` | F01 | V4 |
| MPP 与中继 | 开启时必须 2 段 | F03 | V3 |
| Hide IP 归属 | 不得记成 MPP 的一部分 | F04 | V3 |
| 后台下载与 MPP | 不得在 MPP 关闭时仍写开启 | F05 | V3 |
| 加载事件 | `banner`／`none`／`unknown` | 无专用码，进内容件 | — |
| 中继依据 | `relay`／`unknown` | 无专用码，进内容件 | — |

---

## 10. L7 内容拦截层：唯一公开接口在 macOS，iOS 一格为空

### 10.1 本层回答什么

这一层回答「谁能对邮件内容下拦截规则」。答案在公开文档里只有一个接口，而且只在 macOS 上。

### 10.2 唯一接口

`MEContentBlocker` 的角色说明是 `An object that provides a set of rules to block content when displaying a message.`（`A/mailkit_mecontentblocker.txt:3`），Overview 写明：`Mail uses content blockers when it displays message content in a user’s mailbox`（`:12`），扩展在 Info.plist 的能力列表里声明该能力后，MailKit 调用处理器取得 JSON 规则（`:12—17`），规则由 `contentRulesJSON()` 返回（`:36`）。页面的平台坐标只有一行：macOS 12.0（`C/platform-21.txt:27`）。

### 10.3 两句必须一起读的话

- `MailKit always applies content-blocking rules for enabled extensions.`（`A/mailkit_mecontentblocker.txt:20`）
- `This is true even if the user clicks the “Load remote content” button on the banner that Mail displays when remote content isn’t loaded.`（`:20`）

第一句说规则的优先级：只要扩展启用，规则就生效。第二句说一个常见误解不成立：用户点「加载远端内容」不等于绕过拦截规则。两句合起来给出的归属是：**拦截规则的裁决权在扩展，不在用户的点击**。但这只对 macOS 成立。

### 10.4 iOS 一格为什么必须写 `unknown`

公开侧能读到的 iOS 相关内容只有四份 MessageUI 文档（`C/platform-21.txt:32—47`），它们描述的是构造邮件、`canSendMail()` 能力查询、代理回调与正文设置，没有一份描述内容拦截。MailKit 六份文档全部 macOS-only（`:26—31`）。所以：

- 「iOS 上有没有内容拦截机制」——公开文档不回答；
- 「iOS 上有没有第三方可注册的内容拦截扩展」——公开文档没有接口；
- 「iOS 上点击加载横幅之后拦截规则是否仍生效」——没有文档。

这三问的答案都是 `unknown`。写成「iOS 没有内容拦截」是把「没有公开接口」偷换成「没有机制」，这正是第 24 章 M02 要拆的误区。

### 10.5 三个码的分工

- F02（脚本一第 179 行，V3）：台账把拦截件声明在 iOS 上 → 与平台矩阵矛盾（Y04 要求拦截件文档必须有 macOS 行，第 159 行）；
- Z13（脚本二第 197 行）：内容件宣称有拦截件，但平台矩阵里没有任何拦截件文档；
- Y04（脚本二第 159 行）：平台矩阵缺少 `mailkit_mecontentblocker` 的 macOS 行。

三个码从三个方向拦同一种错：**把 macOS 的接口当成跨平台的接口**。任何一个触发，闭合等级都不可能到 W1。

### 10.6 本层核对项

| 项 | 判据 | 码 |
| --- | --- | --- |
| 拦截件平台 | 不得声明在 iOS | F02 |
| 平台矩阵有拦截件 | `mailkit_mecontentblocker` 必须有 macOS 行 | Y04 |
| 宣称与矩阵一致 | 有拦截件宣称时矩阵必须有文档 | Z13 |
| iOS 一格 | 只能是 `unknown`，且写明缺文档 | 无专用码，进 `content.blocker_platform` |

---

## 11. L8 组合与发送面层：谁构造消息、谁最终负责发送

### 11.1 本层回答什么

这一层回答「第三方应用能对邮件做到哪一步」。公开答案是：构造并交给 Mail，之后不归应用管。

### 11.2 四份 MessageUI 文档的分工

| 文档 | 作用 | 平台 | 锚点 |
| --- | --- | --- | --- |
| `canSendMail()` | 设备是否能发信 | iOS 3.0／iPadOS 3.0／Mac Catalyst 13.1／visionOS 1.0 | `A/messageui_cansendmail.txt:3`；`C/platform-21.txt:32—35` |
| `MFMailComposeViewController` | 组合界面 | iOS 3.0／iPadOS 3.0／Mac Catalyst 13.1／visionOS 1.0 | `C/platform-21.txt:40—43` |
| 代理协议 | 组合界面回调 | iOS 3.0／iPadOS 3.0／Mac Catalyst 13.0／visionOS 1.0 | `C/platform-21.txt:36—39` |
| `setMessageBody` | 设置正文 | iOS 3.0／iPadOS 3.0／Mac Catalyst 13.1／visionOS 1.0 | `C/platform-21.txt:44—47` |

四份文档全部有 iOS 行、全部没有 macOS 行。这是平台矩阵里第二处成组的单侧文档（第一处是 MailKit 的六份 macOS-only）。

### 11.3 一句把责任写死的话

`The composition interface doesn’t guarantee the delivery of your email message; it only lets you construct the initial message and present it for user approval. … If the person opts to send the message, the message queues in the user’s Mail app outbox. The Mail app is ultimately responsible for sending the message.`（`A/messageui_mfmailcomposeviewcontroller.txt:13`）

这句话给出了本层的归属边界：**应用只负责构造与呈现，发送责任在 Mail 应用**。它同时解释了为什么第三方应用拿不到「这封信走了哪条中继」「远端内容有没有被加载」的读数——发送之后的过程不在应用的接口里。

### 11.4 邮件数据库的加密口径

平台安全指南写明邮件数据库（含附件）`are also stored through encryption, with keys protected by the user’s passcode on their device`（`B/apple-platform-security-guide.txt:2411`）。这句话在本篇只作为「内容件落点属性」引用：它说明内容在设备上以加密形式存放，但**不说明内容加载时经过哪些进程**。第 20 篇处理卷形态，本篇不重复。

### 11.5 Apple Watch 的直连形态

指南另有一句：`When Apple Watch and iPhone are out of range, Apple Watch connects directly to iCloud and Gmail servers to fetch mail`（`B/apple-platform-security-guide.txt:1668`），Gmail 的 OAuth 令牌经 IDS 加密送到手表且不在配对的 iPhone 上使用（同段）。这句话说明「一个账户的取信路径可能不止一台设备」，但它不改变台账的三件结构——脚本一没有「设备」字段，本文也不把多设备取信纳入判定。

### 11.6 本层核对项

| 项 | 判据 | 码 |
| --- | --- | --- |
| 发信能力查询 | `canSendMail()` 在组合前调用 | 不进脚本，仅作公开口径 |
| 发送责任 | 台账不得把「应用已发送」写成结论 | F07（闭合必须有证据引用） |
| MessageUI 平台 | 四份文档必须有 iOS 行 | Y05（第 160 行） |
| 内容落点 | 邮件数据库加密口径只作引用 | 无专用码 |

---

## 12. L9 管理面回查层：210 个纯键名里的四个 Mail 键

### 12.1 分母与分子

管理面限制项纯键名 210 个（`C/readings-21.txt:118`），含 `Mail` 的 4 个，含 `privacy` 的 1 个，含 `relay` 的 1 个，含 `account` 的 1 个。四个 Mail 键的完整读数是：

| 键 | 行 | 平台与版本 | 语义 | 监督要求 |
| --- | --- | --- | --- | --- |
| `allowCloudMail` | `A/mdm-restrictions-payload-M.txt:57` | macOS 10.12+ | 关闭 iCloud 邮件服务 | 无 |
| `allowMailPrivacyProtection` | `:112` | iOS 15.2+／iPadOS 15.2+ | 关闭 Mail Privacy Protection | `Requires supervision: iOS` |
| `allowMailSmartReplies` | `:113` | iOS 18.4+／macOS 15.4+／visionOS 2.4+ | 关闭 Mail 智能回复；已弃用（iOS 26.4+） | `Requires supervision: iOS \| visionOS` |
| `allowMailSummary` | `:114` | iOS 18.1+／macOS 15.1+／visionOS 2.4+ | 关闭手工生成邮件摘要；已弃用（iOS 26.4+） | `Requires supervision: iOS \| visionOS` |

### 12.2 四个键里没有一个是「远端内容」

这是本层最关键的一句：**四个键的语义分别是 iCloud 邮件服务、MPP 开关、智能回复、摘要，没有一个键的名字或说明里出现「远端内容」「预取」「加载」「跟踪像素」**。`allowMailPrivacyProtection` 是唯一直接指向本链路功能的键，但它的语义是「关闭 Mail Privacy Protection」，不是「禁止远端内容加载」——原文写的是 `If false, the system disables Mail Privacy Protection on the device.`（`:112`），而 MPP 的公开说明是「后台预取＋双中继＋隐藏 IP」（`B/mail-privacy-protection-legal.txt:30—33`），关闭它并不会让 Mail 停止显示邮件，也不会让远端内容「不加载」，只是改变加载路径与身份暴露方式。

### 12.3 两个键已弃用，一个键只管 macOS

- `allowCloudMail` 只有 macOS 10.12+（`:57`），在 iOS 台账里写这个键就是平台错位；
- `allowMailSmartReplies` 与 `allowMailSummary` 都标了 `Deprecated: iOS 26.4+ …`（`:113—114`），说明它们的语义已被声明式 `com.apple.configuration.intelligence.settings` 取代；
- 只剩 `allowMailPrivacyProtection` 一个键在 iOS 上仍然有效，且要求监督（`:112`）。

脚本二 Z15 用一条粗粒度规则拦「回查限制键少于四个」（第 199 行），它检查的是「回查件有没有把四个键都登记」，不是「四个键都可用」。后者需要逐键读平台列，正是本节表格在做的事。

### 12.4 声明类型与隐私清单

声明类型 65 项、`Account` 前缀 8 项（`C/readings-21.txt:125`）；隐私数据类型 35 项、`EmailsOrTextMessages` 在第 20 行（`:126`）。这两个分母都比 Mail 键大一个数量级，但它们的分子同样不指向「远端内容」：声明类型里与邮件有关的只有 `AccountMail`，隐私类型里与邮件有关的只有 `EmailsOrTextMessages`，两者都没有「加载事件」这一格。

### 12.5 本层核对项

| 项 | 判据 | 码 |
| --- | --- | --- |
| 限制键数量 | 回查件至少登记四个 | Z15 |
| 隐私类型 | 必须是 `EmailsOrTextMessages` | Z16 |
| 平台错位 | iOS 台账不得只用 macOS 键 | 无专用码，进 `readback.restriction_key` |
| 弃用状态 | 弃用键必须标注 | 无专用码，进台账备注 |

---

## 13. L10 公告对齐层：36 行、0 行与七个 CVE

### 13.1 三族 36 行、七个 CVE

公告子集 1,266 行里，邮件族三个组件共 36 行：`Mail` 15 行／3 个 CVE、`Accounts` 15 行／3 个 CVE、`Messages` 6 行／1 个 CVE（`C/readings-21.txt:3`）。七个 CVE 的影响句是：

- `CVE-2026-112671`：`A remote attacker may be able to cause a denial-of-service`（`:10`）
- `CVE-2026-112414`：`Processing a maliciously crafted message may lead to a denial-of-service`（`:11`）
- `CVE-2026-112500`：`The user's original email address may be leaked when using the Hide My Email feature`（`:12`）
- `CVE-2026-113898`：`A malicious application may be able to bypass Privacy preferences`（`:13`）
- `CVE-2026-112612`：`An attacker with physical access to a trust-paired device may be able to read and write arbitrary files`（`:14`）
- `CVE-2026-112446`：`An app may be able to access sensitive user data`（`:15`）
- `CVE-2026-112682`：`A remote attacker may be able to cause unexpected app termination`（`:16`）

七个 CVE 里只有 `112500` 直接提到邮件地址泄漏（Hide My Email），其余六个是 DoS、隐私偏好绕过、信任配对设备读写、敏感数据访问与应用终止。**没有一个 CVE 的影响句提到远端内容加载、跟踪像素、中继或发件人识别。**

### 13.2 影响句词形的十五个零

`C/readings-21.txt` 的 G3 组给出 20 个词形的计数，其中为 0 的十五个是：`mail`、`remote content`、`tracking`、`sender`、`ip address`、`relay`、`load`、`account`、`credential`、`imap`、`smtp`、`pop3`、`s/mime`、`attachment`、`hide ip`（`:17、20、23—36`）。非零的五个是：`email` 3、`message` 6、`remote` 45、`remote attacker` 45、`privacy` 36（`:18—22、28`）。

这组读数的意义不是「没有这些缺陷」，而是「公告的影响句不使用这些词形」。`remote` 有 45 行，但全部是 `remote attacker`（`:21—22`），说明「攻击者位置」这个词形与「内容路径」无关。脚本二 X 族因此把 `remote content`、`tracking`、`sender`、`imap`、`smtp`、`pop3`、`credential`、`s/mime`、`account` 九种零命中写成信号（X02—X10），把「组件列有 Mail、影响句没有 mail」写成 X11，把两列行数不等写成 X12（第 129—140 行）。

### 13.3 组件列与影响句列的错位

组件列 `mail` 15 行、`account` 15 行、`remote` 7 行（`:37、41、49`）；影响句列 `mail` 0、`account` 0、`remote` 45（`:17、29、21`）。两组数完全对不上：

- 组件列的 `remote` 7 行是组件名里带 `remote` 的产品（如 Remote Desktop 一类），与远程内容无关；
- 影响句的 `remote` 45 行全是 `remote attacker`；
- 组件列 `Mail` 15 行对应的影响句 `mail` 是 0 行。

脚本二 X11 就是为这组错位写的：组件列有 Mail 行、影响句没有 `mail` 词形 → 信号。X12 更进一步：两列行数不相等 → 信号。这两条在 34 次实跑里都被触发（R21、R22、R32、R34），证明判据可达。

### 13.4 邮件族内部的影响句分布

只看邮件族 36 行，影响句计数是：`mail` 0、`email` 3、`message` 6、`remote` 12、`remote attacker` 12、`privacy` 8，其余为 0（`C/readings-21.txt:57—69`）。也就是说，邮件族内部 36 行里只有 3 行用 `email`、6 行用 `message`、12 行用 `remote attacker`，没有一行用 `mail`。**组件名与影响句用的是两套词**，这是 K3 的量化落点。

### 13.5 本层核对项

| 项 | 判据 | 码 |
| --- | --- | --- |
| 组件列有 Mail | 否则 X01 | X01 |
| 影响句有 remote content | 否则 X02 | X02 |
| 影响句有 tracking | 否则 X03 | X03 |
| 影响句有 sender | 否则 X04 | X04 |
| IMAP／SMTP／POP3 | 否则 X05—X07 | X05—X07 |
| credential／S/MIME／account | 否则 X08—X10 | X08—X10 |
| 组件与影响句一致 | 行数相等 | X11／X12 |

---

## 14. L11 引用与结论层：doc.* 与十六份文档的平台坐标

### 14.1 引用件有五个字段

台账的 `doc.*` 有五个字段：`page_url`、`page_title`、`line_ref`，以及结论侧的 `claim.evidence_ref`、`claim.closure`。脚本一 G 族对五者逐一检查：

- 地址为空 → G01（第 192 行）；
- 行锚为空 → G02（第 193 行）；
- 行锚不是数字或超过 300 → G03（第 195—196 行）；
- 地址不是 `developer.apple.com` → G04（第 198 行）；
- 标题为空 → G05（第 199 行）；
- 证据引用不是 `Rxx` 形态 → G06（第 201 行）。

这六条只检查引用的**形式**，不检查引用的**内容**是否支持结论。后者由第 27 章的引用审计与第 16 章的读数行号共同保证。

### 14.2 十六份文档的平台坐标

平台矩阵 47 行（`C/platform-21.txt:1—47`）覆盖 16 份文档：

- **iOS 与 macOS 都有（4 份）**：`accountexchange`、`accountmail`、`accountmail_incoming`、`accountmail_outgoing`（`:1—20`）；
- **只有 iOS（5 份）**：`accountmail_smime`（`:21—24`，iOS 17.0）与四份 `messageui_*`（`:32—47`）；
- **只有 macOS（7 份）**：`accountsettings`（`:25`，macOS 27.2）与六份 `mailkit_*`（`:26—31`，macOS 12.0）。

汇总读数：16 份、4 份双平台、5 份只有 iOS、7 份只有 macOS、0 份两者都无、0 份版本差 >5（`C/readings-21.txt:117`）。这六个数是脚本二 Y 族与第 17 章可见性边界的唯一输入。

### 14.3 三处「差一点就闭合」的引用

- `accountmail_smime` 有 iOS 17.0 行、没有 macOS 行，而 MailKit 的 `MEMessageSecurityHandler` 有 macOS 行、没有 iOS 行：同一功能的两半各在一个平台上，**没有任何一份文档同时覆盖两者**；
- `accountsettings` 只有 macOS 27.2 一行，且只配 Exchange 账户设置（`A/device_management_accountsettings.txt:9—10`），与 `AccountMail` 的账户装配不是同一件事；
- `messageui_*` 四份全部 iOS 3.0 起、没有 macOS 行，说明「第三方应用构造邮件」这条路只在 iOS 一侧公开。

三处都不是缺失，而是**平台切分**：公开文档把同一件事的不同部分放在不同平台上，读者若把两份文档拼成一条链路，就必须自己声明这是拼接，而不是原文。

### 14.4 本层核对项

| 项 | 判据 | 码 |
| --- | --- | --- |
| 文档地址 | `https://developer.apple.com/` | G01／G04 |
| 文档标题 | 非空 | G05 |
| 行锚 | 数字且 ≤300 | G02／G03 |
| 证据引用 | `Rxx` | G06 |
| 闭合声明 | `closed` 必须有 `evidence_ref` | F07 |
| 平台坐标 | 16 份／47 行／三类分布 | Y01—Y07 |
## 15. 归属矩阵：十一层 × 责任方 × 三件 × 证据

### 15.1 矩阵本体

下表是全文的骨架。每一行是一层，每一列回答「这一层的这一件归谁、有没有公开锚点、能不能读回」。**空格不是遗漏，是本文明确写下的「这一格没有公开读数」。**

| 层 | 责任方 | 装配件 | 内容件 | 回查件 | 关键证据 |
| --- | --- | --- | --- | --- | --- |
| L1 账户装配声明 | 声明式设备管理 | 声明类型、两个服务端、S/MIME 子树 | — | 声明类型清单 65 项 | `A/device_management_accountmail.txt:3、120` |
| L2 下发与作用域 | 注册通道 | 六种注册、两个作用域 | — | 声明可用性表 | `:25—36` |
| L3 凭据与身份 | 资产声明 + 钥匙串 | 凭据资产类型、`None` 规则、身份资产 | — | 钥匙串分类表 | `A/device_management_accountmail_incoming.txt:9—13`；`B/apple-platform-security-guide.txt:2155—2156` |
| L4 收发服务端 | 账户声明 | 收件六字段、发件四字段 | — | 端口与协议字段 | `A/device_management_accountmail_outgoing.txt:9—19` |
| L5 S/MIME | 账户声明 + MailKit | S/MIME 对象 | 安全处理器（macOS） | 逐封 S/MIME 功能口径 | `A/device_management_accountmail.txt:13—15`；`A/mailkit_memessagesecurityhandler.txt:16、29`；`B/apple-platform-security-guide.txt:2305—2307` |
| L6 远端内容加载 | Mail 应用 | — | MPP、Hide IP、中继、后台下载、加载事件 | 限制键 `allowMailPrivacyProtection` | `B/mail-privacy-protection-legal.txt:29—33`；`A/mdm-restrictions-payload-M.txt:112` |
| L7 内容拦截 | MailKit 扩展 | — | 拦截件、拦截平台 | 平台矩阵的 macOS 行 | `A/mailkit_mecontentblocker.txt:12、20`；`C/platform-21.txt:27` |
| L8 组合与发送 | 第三方应用 + Mail 应用 | — | 发送责任 | MessageUI 四份文档 | `A/messageui_mfmailcomposeviewcontroller.txt:13` |
| L9 管理面回查 | 设备管理服务 | — | — | 210 键／4 Mail 键／65 声明／35 类型 | `C/readings-21.txt:118—126` |
| L10 公告对齐 | 安全发布 | — | — | 36 行／7 CVE／影响句词形 | `C/readings-21.txt:3—16` |
| L11 引用与结论 | 本文台账 | `doc.*` 五字段 | — | 平台矩阵 47 行 | `C/platform-21.txt`；`C/readings-21.txt:117` |

### 15.2 矩阵里最空的三个格子

1. **L6 的装配件**：账户声明里没有任何「加载」「预取」「拦截」字段。装配件写得再全，也不能说明内容行为。
2. **L7 的 iOS 格**：内容拦截的公开接口只有 macOS 一行（`C/platform-21.txt:27`），iOS 侧既没有装配字段，也没有内容字段，也没有回查字段。三件全空。
3. **L9 的「远端内容」列**：210 个键里 4 个含 `Mail`，没有一个含「远端内容」；65 个声明里 8 个 `Account` 前缀，没有一个描述加载行为；35 个隐私类型里 1 个邮件类型，不含加载事件。

这三个空格是全文结论的落点：**不是「三件都读不到」，而是「三件分别读得到一部分，但没有一件能闭合另外两件」**。

### 15.3 责任方的三层错位

- **装配责任方**是设备管理服务：它下发声明、决定账户是否存在、决定 S/MIME 身份从哪来。它不决定内容是否加载。
- **内容责任方**是 Mail 应用与 MailKit 扩展：它决定预取、中继、拦截规则。它不决定账户从哪来。
- **回查责任方**是管理面与安全发布：它记录限制键、声明类型、CVE。它既不装配也不加载，只能事后计数。

三方之间没有一份文档同时引用另外两方。这就是「三段判定权互不通气」的矩阵表达。

### 15.4 矩阵的使用方法

1. **先填三件，再看空格。** 每个主体先写装配件（声明类型、服务端、凭据、S/MIME）、内容件（MPP、Hide IP、后台下载、加载事件、拦截件）、回查件（限制键、隐私类型、公告行）。三件缺一，最高 `partial`。
2. **空格必须写原因。** 例如「L7 iOS 格为空」的原因是「六份 MailKit 文档全部 macOS-only」，不是「iOS 不支持」。
3. **不跨层借证据。** L5 的 S/MIME 声明不能当 L6 的加载证据；L6 的 MPP 说明不能当 L7 的拦截证据；L9 的限制键不能当 L6 的行为读数。

---

## 16. 公开读数：这条链路上能数出来的十二组事实

本章的每一行都来自 `.srcx21/C/readings-21.txt`（130 行），由 `tools/readings21.pl` 离线生成，不手改。R 编号是全篇引用的唯一坐标；同一行号在不同篇目的归档里不可互换。

### 16.1 G1 全量与平台（R01—R02）

| 号 | 读数 | 值 | 锚点 |
| --- | --- | --- | --- |
| R01 | 公告记录行／平台去重／组件去重／唯一 CVE | 1,266／12／129／330 | `C/readings-21.txt:1` |
| R02 | 平台清单 | iOS 26.7.2、iOS 27.2、macOS Golden Gate 27.2、macOS Sequoia 15.8.1、15.8.2、macOS Tahoe 26.7.1、26.7.2、Safari 27.2、tvOS 27.2、visionOS 27.2、watchOS 27.2、Xcode 27.2 | `:2` |

### 16.2 G2 邮件族三组件（R03—R07）

| 号 | 读数 | 值 | 锚点 |
| --- | --- | --- | --- |
| R03 | Mail／Accounts／Messages 行数与 CVE 数 | 15／3；15／3；6／1；合计 36 行 | `:3` |
| R04 | Mail 行按平台 | iOS 26.7.2=2、iOS 27.2=3、macOS Golden Gate=3、Sequoia 15.8.2=2、Tahoe 26.7.2=2、visionOS=3 | `:4` |
| R05 | Accounts 行按平台 | iOS 26.7.2=2、iOS 27.2=3、Golden Gate=2、Sequoia=1、Tahoe=1、tvOS=2、visionOS=2、watchOS=2 | `:5` |
| R06 | Messages 行按平台 | iOS 26.7.2=1、iOS 27.2=1、Golden Gate=1、Tahoe=1、visionOS=1、watchOS=1 | `:6` |
| R07 | 七个 CVE 的影响句 | 112671 DoS；112414 恶意构造消息 DoS；112500 Hide My Email 泄漏原地址；113898 绕过隐私偏好；112612 信任配对设备读写任意文件；112446 访问敏感数据；112682 应用意外终止 | `:7—16` |

### 16.3 G3 影响句与组件列的词形（R08—R09）

| 号 | 读数 | 值 | 锚点 |
| --- | --- | --- | --- |
| R08 | 影响句 20 个词形 | `mail` 0、`email` 3、`message` 6、`remote content` 0、`remote` 45、`remote attacker` 45、`tracking` 0、`sender` 0、`ip address` 0、`relay` 0、`load` 0、`privacy` 36、`account` 0、`credential` 0、`imap` 0、`smtp` 0、`pop3` 0、`s/mime` 0、`attachment` 0、`hide ip` 0 | `:17—36` |
| R09 | 组件列 20 个词形 | `mail` 15、`email` 0、`message` 0、`remote content` 0、`remote` 7、`tracking` 0、`sender` 0、`ip address` 0、`relay` 0、`load` 0、`privacy` 0、`account` 15、`credential` 0、`imap` 0、`smtp` 0、`pop3` 0、`s/mime` 0、`attachment` 0、`hide ip` 0 | `:37—56` |

### 16.4 G4 邮件族内部影响句（R10）

| 号 | 读数 | 值 | 锚点 |
| --- | --- | --- | --- |
| R10 | 邮件族 36 行的影响句词形 | `mail` 0、`email` 3、`message` 6、`remote` 12、`remote attacker` 12、`tracking` 0、`sender` 0、`relay` 0、`load` 0、`privacy` 8、`account` 0、`credential` 0、`s/mime` 0 | `:57—69` |

### 16.5 G5 平台矩阵（R11—R12）

| 号 | 读数 | 值 | 锚点 |
| --- | --- | --- | --- |
| R11 | 平台坐标行 | 47 行、16 份文档（逐行见 `C/platform-21.txt`） | `C/platform-21.txt:1—47` |
| R12 | 平台汇总 | 16 份；双平台 4；只有 iOS 5；只有 macOS 7；都无 0；版本差 >5 为 0 | `C/readings-21.txt:117` |

### 16.6 G6 管理面（R13—R15）

| 号 | 读数 | 值 | 锚点 |
| --- | --- | --- | --- |
| R13 | 210 个纯键名中的词形 | `mail` 4、`privacy` 1、`relay` 1、`account` 1 | `:118` |
| R14 | 四个 Mail 键 | `allowCloudMail` 57（macOS 10.12+）；`allowMailPrivacyProtection` 112（iOS 15.2+，需监督）；`allowMailSmartReplies` 113（iOS 18.4+，已弃用）；`allowMailSummary` 114（iOS 18.1+，已弃用） | `:119—122` |
| R15 | privacy／relay 键 | `allowMailPrivacyProtection` 第 112 行；`allowCloudPrivateRelay` 第 60 行 | `:123—124` |

### 16.7 G7 声明类型（R16）

| 号 | 读数 | 值 | 锚点 |
| --- | --- | --- | --- |
| R16 | 声明类型 | 65 项；`Account` 前缀 8 项 | `:125` |

### 16.8 G8 隐私数据类型（R17）

| 号 | 读数 | 值 | 锚点 |
| --- | --- | --- | --- |
| R17 | 隐私类型 | 35 项；`EmailsOrTextMessages` 第 20 行；文件 47 行 | `:126` |

### 16.9 G9—G11 规模与码表（R18—R20）

| 号 | 读数 | 值 | 锚点 |
| --- | --- | --- | --- |
| R18 | 脚本规模 | 脚本一 226 行／10,590 字节；脚本二 222 行／10,628 字节 | `:127`；`wc` 复核 |
| R19 | 夹具 | 12 份／331 行 | `:128`；`wc -l fx/*` |
| R20 | 码表 | 脚本一 54 信号 + 4 判定 = 58；脚本二 39 信号 + 4 闭合 = 43；合计 101 | `:129` |

### 16.10 读数之间的关系

- R03 的 36 行与 R08 的 0 行是同一批公告的两种切法，二者不能相加也不能相减；
- R12 的 7 份 macOS-only 与 R14 的 4 个限制键是两条独立的平台不对称证据，不能互相替代；
- R20 的 101 个码是「判据可达」，不是「缺陷可检出」；每个码的含义见第 21、22 章。

### 16.11 读数不覆盖什么

- 不覆盖任何设备状态：没有一台设备被查询；
- 不覆盖任何账户状态：没有账户被登录或读取；
- 不覆盖任何邮件内容：没有邮件正文、附件或头部被读取；
- 不覆盖任何网络位置：没有中继被访问，也没有 IP 被观测。

### 16.12 复跑方式

`perl tools/readings21.pl .` 在 `.srcx21` 根目录运行，读取 `C/advisory-21.tsv`、`A/` 文本、`RAW/` 平台 JSON、`B/` 键表与 `.p21/` 脚本与夹具，写出 `C/readings-21.txt` 与 `C/platform-21.txt`。工具不联网、不写输入；`C/readings-21.err` 为空才把读数当作正文依据。

---

## 17. 可见性边界：这一层读者能拿到什么

### 17.1 五类读者，五种可见性

| 读者 | 能拿到 | 拿不到 |
| --- | --- | --- |
| 写声明的人 | 声明类型、字段名、注册方式、作用域 | 内容是否加载、S/MIME 是否真被使用 |
| 写 MailKit 扩展的人（macOS） | 拦截规则接口、安全处理器接口、解码回调 | iOS 侧的任何对应接口 |
| 写第三方应用的人（iOS） | 组合界面、`canSendMail()`、代理回调 | 发送之后的任何状态 |
| 管设备的人 | 210 个限制键、4 个 Mail 键、65 个声明类型 | 「远端内容有没有加载」的实时读数 |
| 读公告的人 | 36 行邮件族记录、7 个 CVE、影响句词形 | 组件名与影响句之间的换算 |

### 17.2 三个「看起来能读、其实读不到」

1. **`allowMailPrivacyProtection` 看起来能读 MPP 状态**：它只能读「这个限制项是否被下发」，不能读「这台设备上 MPP 是否开启」，更不能读「这封邮件的远端内容是否被加载」。
2. **`EmailsOrTextMessages` 看起来能读邮件内容收集**：它只申报数据类型（主题、发件人、收件人、内容），不含加载时点与加载路径。
3. **`Mail` 组件名看起来能筛邮件缺陷**：组件列 15 行对应的影响句 `mail` 是 0 行，筛出来的行没有一行描述邮件功能。

### 17.3 可见性的三条硬约束

- **平台约束**：iOS 侧没有 MailKit 文档，macOS 侧没有 MessageUI 文档；跨平台拼链路必须声明是拼接。
- **时点约束**：声明是「配置时」的事实，MPP 是「收信时」的行为，公告是「披露时」的记录；三者不在同一时间轴上。
- **粒度约束**：声明到字段，MPP 到功能，公告到组件；三者粒度不同，不能逐项对齐。

### 17.4 读者能自己复核的最小集合

1. 打开 `A/device_management_accountmail.txt`，确认声明类型与 S/MIME 平台行；
2. 打开 `B/mail-privacy-protection-legal.txt`，确认四句原文；
3. 打开 `A/mailkit_mecontentblocker.txt`，确认 macOS-only 与「点击不绕过规则」两句；
4. 打开 `A/mdm-restrictions-payload-M.txt`，确认四个 Mail 键的行号与平台；
5. 打开 `C/readings-21.txt`，确认 R03、R08、R12、R14 四组数；
6. 跑 `.p21/proof.sh`，确认 P1—P20 的只读性与 101/101 覆盖。

---

## 18. 五个读数面：装配侧、内容侧、回查侧、管理侧、公告侧

### 18.1 五个面的分工

| 面 | 它回答 | 它不回答 | 本篇用它做什么 |
| --- | --- | --- | --- |
| 装配侧 | 账户怎么被声明出来 | 账户是否登录成功 | L1—L5 的字段与平台 |
| 内容侧 | 远端内容按什么规则加载 | 这封邮件加载了什么 | L6—L7 的 MPP 与拦截 |
| 回查侧 | 加载这件事有没有证据 | 证据是否充分 | L9 的限制键与隐私类型 |
| 管理侧 | 哪些限制项被下发 | 下发是否生效 | 4 个 Mail 键的可用性 |
| 公告侧 | 哪些组件出过缺陷 | 缺陷与功能的对应 | 36 行与 7 个 CVE |

### 18.2 五个面的闭合关系

- 装配侧与内容侧**不闭合**：声明没有内容字段（K1）；
- 内容侧与回查侧**不闭合**：MPP 说明没有对应的限制键语义（K5、K6）；
- 回查侧与管理侧**部分闭合**：限制键能读到 MPP 开关，但读不到加载事件；
- 管理侧与公告侧**不闭合**：公告组件名与限制键名没有共同词形；
- 公告侧与装配侧**不闭合**：公告组件 `Mail` 与声明类型 `AccountMail` 没有换算关系。

五对关系里只有一对部分闭合，其余四对全不闭合。这就是「三方互不通气」在读数层面的样子。

### 18.3 每个面的最小证据集

| 面 | 最小证据集 | 缺一件的后果 |
| --- | --- | --- |
| 装配侧 | 声明类型、收件端、发件端、S/MIME 子树、来源 | 无法判定账户归属 |
| 内容侧 | MPP、Hide IP、后台下载、加载事件、拦截件 | 闭合等级降到 W2 或 W3 |
| 回查侧 | 限制键、隐私类型、公告组件行 | 闭合声明不成立（Z12） |
| 管理侧 | 键名、平台、版本、监督要求 | 平台错位无法发现 |
| 公告侧 | 组件行、影响句、CVE、平台 | 组件与影响句的错位无法量化 |

---

## 19. 两套判定模型：J1—J4 与 Q1—Q4

### 19.1 脚本一的四档判定（J1—J4）

| 档 | 名称 | 条件 | 台账写法 |
| --- | --- | --- | --- |
| J1 | 可读 | 无阻断、无错误、无提示 | `V1` |
| J2 | 有提示 | 只有提示级信号（C06—C08、D02 等） | `V2` |
| J3 | 阻断 | 至少一个阻断或错误级信号（A、B、C05、D、E、F02—F07、G） | `V3` |
| J4 | 未知 | `policy.remote_content_policy=unknown`，无论其他字段 | `V4` |

判定顺序是**先看 F01，再看信号级别**：F01 命中直接落 J4（脚本一第 177 行），不再看其他；否则按阻断→错误→提示的顺序落 J3／J2／J1（第 204—209 行）。这套顺序保证「读不到策略」不会被「其他字段很全」稀释。

### 19.2 脚本二的四级闭合（Q1—Q4）

| 级 | 名称 | 条件 | 脚本写法 |
| --- | --- | --- | --- |
| Q1 | 闭合 | 装配件有收件 host 与凭据、内容件六项齐、回查件三项齐、策略非 unknown | `W1` |
| Q2 | 部分 | 装配件有收件 host 与凭据，但内容件或回查件有缺项 | `W2` |
| Q3 | 未知 | `content.remote_policy=unknown` | `W3` |
| Q4 | 不可判 | 主体没有 account 方面 | `W4` |

判定顺序写在脚本二第 202—207 行：先看 `remote_policy=unknown` → W3；再看三件是否齐 → W1；再看装配件是否至少有 host 与凭据 → W2；否则 W4。

### 19.3 两套模型的对应关系

| 脚本一 | 脚本二 | 含义 | 能否互换 |
| --- | --- | --- | --- |
| J1 | Q1 | 台账自洽且三件齐 | 不能：J1 只看台账，Q1 还看三件 |
| J2 | Q2 | 有提示或缺项 | 不能：粒度不同 |
| J3 | Q2／Q1 | 阻断不等于三件不齐 | 不能：J3 可能三件齐但台账矛盾 |
| J4 | Q3／Q4 | 未知或不可判 | 不能：J4 的未知来自策略，Q4 来自缺方面 |

**两套模型不能互相替代**：脚本一检查「一条记录自己站不站得住」，脚本二检查「一个主体的三件对不对得上」。一条记录可以 J1（完全自洽）但 Q3（策略未知），也可以 J3（台账矛盾）但 Q1（三件齐）。第 23 章的 34 次实跑里，R11 就是「J1 与 J3 同现」的例子（不同记录各落一档）。

### 19.4 判定的可复核性

每个判定都能回指三样东西：触发它的码（如 `F01`）、码所在行号（如第 177 行）、判定分布（如 `V4=1`）。第 23.2、23.3 两张逐次表把每个子集的期望码与实跑码并列，读者可以只看表判断「改一条判据有没有越界」。

---

## 20. 运营指标 O1—O10

本章给十个可计算的运营指标。它们不评价「安全不安全」，只描述台账与语料的覆盖质量。每个指标都给出公式、当前值与锚点；当前值来自 `.p21/matrix-out.txt` 与 `C/readings-21.txt`，不是估计。

| 号 | 指标 | 公式 | 当前值 | 锚点 |
| --- | --- | --- | --- | --- |
| O1 | 装配件完整率 | 八项装配字段齐全的记录数 ÷ 记录数 | 夹具 R05 全量 bad 为 0；good 夹具为 2/2 | `matrix-out.txt:5`、P11 |
| O2 | 未知策略占比 | `remote_policy=unknown` 的主体数 ÷ 主体数 | 夹具 R24／R34 各 1 个主体落 W3 | `matrix-out.txt:24、34` |
| O3 | S/MIME 平台错位率 | 声明 S/MIME 但平台早于 17 的记录数 ÷ 启用 S/MIME 的记录数 | 夹具 R02／R05 触发 D04 | `matrix-out.txt:2、5` |
| O4 | 拦截件宣称与矩阵不一致率 | Z13 触发主体数 ÷ 宣称有拦截件的主体数 | R21／R22／R25／R34 触发 | `matrix-out.txt:21、22、25、34` |
| O5 | 回查键不足率 | Z15 触发主体数 ÷ 有回查件的主体数 | R21／R24／R26／R34 触发 | `matrix-out.txt:21、24、26、34` |
| O6 | 公告零命中词形数 | 影响句中计数为 0 的词形数 | 15／20 | `readings-21.txt:17—36` |
| O7 | CVE 覆盖率 | 邮件族 CVE 数 ÷ 全量唯一 CVE 数 | 7／330 | `readings-21.txt:1、3` |
| O8 | 平台不对称计数 | 只有 macOS 的文档数 ÷ 16 | 7／16 | `readings-21.txt:117` |
| O9 | 台账拒收率 | A05／Y09 拒收行数 ÷ 输入行数 | P16 为 1 行拒收；P17 为 1 行拒收 | 第 23.1 节 P16、P17 |
| O10 | 码覆盖验收 | 已触发不同码数 ÷ 期望码总数 | 101／101 | `matrix-out.txt:37—41` |

### 20.1 指标的用法

- **O1、O3、O4、O5** 是台账质量指标：它们只说明「这份台账写全了没有」，不说明「设备安全不安全」；
- **O2** 是可见性指标：它的值越高，说明越多主体的策略读不到，结论越应该写成 `unknown`；
- **O6、O7、O8** 是语料指标：它们描述公开文档的覆盖形态，不描述缺陷数量；
- **O9、O10** 是可复现指标：它们证明脚本与判据可达，不证明设备状态。

### 20.2 指标的红线

1. **O1 到 O5 不能跨夹具相加**：不同夹具服务不同码，相加没有意义；
2. **O6 的 15 个零命中不能读成「15 类缺陷不存在」**：它只说明公告影响句不用这些词；
3. **O8 的 7/16 不能读成「43% 的接口不可用」**：分母是文档数，不是功能数；
4. **O10 的 101/101 不能替代设备验证**：它只证明每个码都有夹具能触发。

### 20.3 指标的复跑

| 指标 | 复跑命令 | 期望 |
| --- | --- | --- |
| O1—O5 | `bash matrix.sh` | 34 行逐次读数 + 末四行汇总 |
| O6—O8 | `perl tools/readings21.pl .` | `C/readings-21.txt` 130 行 |
| O9 | `bash proof.sh 报告.md` | P16／P17 各一行拒收 |
| O10 | `tail -4 matrix-out.txt` | `101/101` |
## 21. 只读核验脚本一：邮件账户台账逐字段审查器

### 21.1 这个脚本回答什么

脚本一回答一个问题：**一条邮件账户台账自己站不站得住。** 它把一条记录拆成九个命名空间（id、in、out、smime、mgmt、priv、policy、claim、doc），逐字段检查结构、值域、平台时间线、策略一致性与引用形式，最后给每条记录一个 J1—J4 判定（脚本里写作 V1—V4）。它不连接任何服务器、不读取任何账户、不验证任何凭据，只读文本。

### 21.2 输入格式

每行三列：`<记录标识>,<字段名>,<值>`。两种记录标识前缀：`MA_`（管理面下发）与 `PE_`（用户自建）。空行与 `#` 开头行忽略，行尾 CR 忽略，值内不能含逗号。九个命名空间与字段如下：

| 命名空间 | 字段 | 说明 |
| --- | --- | --- |
| `id.*` | `decl_type`／`account_name`／`platform`／`record_kind` | 账户级标识 |
| `in.*` | `host`／`port`／`server_type`／`auth`／`cred_asset`／`cred_asset_type`／`cred_user`／`tls`／`path_prefix` | 收件服务端 |
| `out.*` | `host`／`port`／`auth`／`cred_asset`／`cred_asset_type`／`tls` | 发件服务端 |
| `smime.*` | `enabled`／`identity_asset`／`identity_asset_type`／`encryption`／`signing`／`enc_alg`／`sign_alg` | S/MIME 子树 |
| `mgmt.*` | `source`／`owner`／`allow_modification`／`created_after_lock`／`profile_present`／`removal_path`／`reused` | 管理面来源 |
| `priv.*` | `data_type`／`consent` | 隐私申报 |
| `policy.*` | `remote_content_policy`／`blocker_platform`／`mpp`／`hide_ip`／`hide_ip_basis`／`relay_count`／`background_download`／`load_event` | 内容策略 |
| `claim.*` | `closure`／`evidence_ref`／`per_message_smime` | 结论 |
| `doc.*` | `page_url`／`page_title`／`line_ref` | 引用 |

### 21.3 信号族与行号

| 族 | 码 | 数量 | 位置 | 拦什么 |
| --- | --- | --- | --- | --- |
| A 结构与取值 | A01—A08 | 8 | 第 87—94、120—124 行 | 前缀、三列、私钥／长载荷拒收、重复冲突、主机缺失 |
| B 声明与字段 | B01—B10 | 10 | 第 127—139 行 | 声明类型、显示名、IMAP、端口、路径前缀、`None` 规则、凭据类型、邮箱形态、口令内联 |
| C 端口与 TLS | C01—C08 | 8 | 第 141—149 行 | 143／25 的 STARTTLS、993／465 的 TLS、`tls=none`、IP、`.local`、收发域名不同 |
| D S/MIME | D01—D07 | 7 | 第 151—161、204 行 | 身份、加密签名并存、资产类型、iOS 17 时间线、算法、身份共用 |
| E 管理面与隐私 | E01—E08 | 8 | 第 163—174 行 | 来源、时间线、数据类型、同意、孤儿、归属人、移除路径、标识复用 |
| F 内容策略与结论 | F01—F07 | 7 | 第 177—190 行 | 策略未知、iOS 拦截件、中继段数、Hide IP 归属、后台下载、逐封 S/MIME、闭合无证据 |
| G 引用 | G01—G06 | 6 | 第 192—201 行 | 地址、行锚、域名、标题、证据引用 |
| V 判定 | V1—V4 | 4 | 第 204—209 行 | J1／J2／J3／J4 |

合计 54 个信号码 + 4 档判定 = 58。

### 21.4 判定顺序

```
读入所有行 → 按记录聚合 → 对每条记录：
  1. 若 policy.remote_content_policy == unknown → V4（先判未知）
  2. 否则若该记录有任一阻断码或错误码 → V3
  3. 否则若该记录有任一提示码 → V2
  4. 否则 → V1
输出逐记录判定 + 汇总（记录数、字段行数、不同码数、信号条数、阻断条数、判定分布）
```

### 21.5 退出码

- `0`：无阻断且无错误（可能仍有提示）；
- `1`：有阻断或错误；
- `2`：用法或输入问题（缺参数、不可读、未知选项）。

### 21.6 实跑样例

干净夹具 `fx/s1-good.tsv`（两条完整记录，90 个字段）输出：

```text
记录 MA_1 判定=V1 信号数=0
记录 PE_1 判定=V1 信号数=0
----
账户记录数= 2
字段行数= 90
不同信号码= 0
信号条数= 0
阻断信号条数= 0
判定分布= V1=2 V2=0 V3=0 V4=0
```

全错夹具 `fx/s1-bad.tsv`（十二个账户记录，95 个字段）输出：

```text
记录 MA_G 判定=V3 信号数=11
记录 MA_H 判定=V3 信号数=13
记录 MA_I 判定=V3 信号数=11
----
账户记录数= 12
字段行数= 95
不同信号码= 50
信号条数= 158
阻断信号条数= 35
判定分布= V1=0 V2=0 V3=11 V4=1
```

两段输出都是脚本原样打印，未删行；`V4=1` 是那条 `remote_content_policy=unknown` 的记录，它即使其他字段齐全也落 V4，这就是 21.4 的第一条规则。

### 21.7 源码

下面这段源码与 `.p21/script1.sh` 逐字节相同（第 23.3 节 P18 会比对）。它只依赖 `awk`、`tr`、`cat` 与 `mktemp`，不调用任何网络工具、不读取钥匙串、不打开任何账户。

```bash
#!/usr/bin/env bash
# mail-account-ledger-review.sh —— 邮件账户台账逐字段审查器（离线 / 只读 / 不联网 / 不碰设备）
# 输入：一份或多份台账文本，每行三列：<账户记录标识>,<字段名>,<值>
# 输出：逐条信号码（stderr） + 每条记录的判定（stdout） + 汇总
# 本脚本只判定「一个邮件账户被登记成一行台账之后，这行台账自己站不站得住」：
# 不含任何账户创建、登录、收发信、导入证书、配置代理或连接服务器的操作步骤，
# 不含任何绕过认证、读取口令或导出身份材料的手法，不连接任何邮件服务器。
# 输入只接受标识、字段名与短取值；取值形似私钥块、形似口令、超长 Base64 载荷或整段
# 邮件正文时一律按 A05 拒收并要求删除该字段（判据见记录循环开头）。
# 本脚本不联网、不调用 openssl／security／defaults／profiles／log／scutil／networksetup／
#       curl／mail／osascript 等任何命令行工具、不读取钥匙串、不打开任何账户或邮箱。
#       唯一写出目标是 mktemp -d 创建的临时目录，退出时删除，本实现不向其写入任何字节。
set -u
LC_ALL=C; export LC_ALL

usage() {
  cat <<'EOF'
用法: mail-account-ledger-review.sh [-q] 台账文件 [...]
  -q  不输出逐记录判定行；-h/--help 显示本帮助
台账行格式: <记录标识>,<字段名>,<值>    # 开头与空行忽略，行尾 CR 忽略，值里不能含逗号
记录标识前缀（两类）: MA_ 管理面下发的账户／PE_ 用户自建账户
字段命名空间（九个）:
  id.*     记录标识（decl_type / account_name / platform / record_kind）
  in.*     收件服务端（host / port / server_type / auth / cred_asset / cred_asset_type /
           cred_user / tls / path_prefix）
  out.*    发件服务端（host / port / auth / cred_asset / cred_asset_type / tls）
  smime.*  S/MIME（enabled / identity_asset / identity_asset_type / encryption / signing /
           enc_alg / sign_alg）
  mgmt.*   管理面（source / owner / allow_modification / created_after_lock / profile_present /
           removal_path / reused）
  priv.*   隐私申报（data_type / consent）
  policy.* 内容策略（remote_content_policy / blocker_platform / mpp / hide_ip / hide_ip_basis /
           relay_count / background_download / load_event）
  claim.*  结论（closure / evidence_ref / per_message_smime）
  doc.*    引用（page_url / page_title / line_ref）
退出码: 0 无阻断且无错误 / 1 有阻断或错误 / 2 用法或输入问题
EOF
}

QUIET=0
while [ $# -gt 0 ]; do
  case "$1" in
    -q) QUIET=1; shift ;;
    -h|--help) usage; exit 0 ;;
    --) shift; break ;;
    -*) usage >&2; exit 2 ;;
    *) break ;;
  esac
done

[ $# -ge 1 ] || { usage >&2; exit 2; }
for f in "$@"; do
  [ -r "$f" ] || { echo "输入不可读: $f" >&2; exit 2; }
done

TMPD=$(mktemp -d "${TMPDIR:-/tmp}/mail21.XXXXXX") || exit 2
trap 'rm -rf "$TMPD"' EXIT INT TERM

cat "$@" | tr -d '\r' | awk -v QUIET="$QUIET" '
function emit(code, id, msg) {
  siglines++
  print code "\t" (id == "" ? "-" : id) "\t" msg > "/dev/stderr"
  cnt[code]++
  if (id != "") per[id]++
  if (code ~ /^(A0[1-8]|B0[1-5])$/) { blkcount++; if (id != "") blocked[id] = 1; return }
  if (code ~ /^(B0[6-9]|B10|C0[1-7]|D0[1-7]|E0[1-8]|F0[2-7]|G0[1-6])$/) { if (id != "") { errored[id] = 1; errcount++ }; return }
  if (id != "") warned[id] = 1
}
function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }
function get(id, f, d) { return ((id SUBSEP f) in V) ? V[id SUBSEP f] : d }
function domain(h,   n, a) { n = split(h, a, "."); return (n >= 2) ? a[n-1] "." a[n] : h }
function is_ip(h) { return h ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ }
function major(v,   n, a) { n = split(v, a, "."); return (n >= 1 && a[1] ~ /^[0-9]+$/) ? a[1] + 0 : -1 }
function bad_value(f, v) {
  if (v == "") return 0
  if (v ~ /BEGIN [A-Z ]*PRIVATE KEY/) return 1
  if (length(v) > 120) return 1
  if (f ~ /(secret|password|passwd|otp|token)/ && v !~ /^(yes|no|true|false|none|empty)$/) return 1
  return 0
}
BEGIN { FS = ","; siglines = 0 }
{
  line = $0
  sub(/^[ \t]+/, "", line); sub(/[ \t]+$/, "", line)
  if (line == "" || substr(line, 1, 1) == "#") next
  n = split(line, a, ",")
  if (n != 3) { emit("A08", "-", "行不是三列（实际 " n " 列），已跳过"); next }
  id = trim(a[1]); f = trim(a[2]); val = trim(a[3])
  if (id == "" || f == "") { emit("A08", id, "标识或字段名为空"); next }
  if (bad_value(f, val)) { emit("A05", id, "字段 " f " 的取值形似私钥／口令／长载荷，已拒收"); next }
  if (id !~ /^(MA_|PE_)/) emit("A01", id, "记录标识前缀不在 MA_／PE_ 之内")
  if (!(id in order)) { order[id] = ++nrec; ids[nrec] = id }
  key = id SUBSEP f
  if (key in V && V[key] != val) emit("A06", id, "字段 " f " 重复且取值冲突")
  V[key] = val
  fields[id]++
}
END {
  delete shared_ident
  for (i = 1; i <= nrec; i++) {
    id = ids[i]
    if (get(id, "smime.enabled", "") == "yes" && get(id, "smime.identity_asset", "") != "")
      shared_ident[get(id, "smime.identity_asset", "")]++
  }
  for (i = 1; i <= nrec; i++) {
    id = ids[i]
    dt = get(id, "id.decl_type", "")
    plat = get(id, "id.platform", "")
    inh = get(id, "in.host", "")
    outh = get(id, "out.host", "")
    inport = get(id, "in.port", "")
    outport = get(id, "out.port", "")
    intls = get(id, "in.tls", "")
    outtls = get(id, "out.tls", "")
    inauth = get(id, "in.auth", "")
    incred = get(id, "in.cred_asset", "")
    scred = get(id, "smime.identity_asset", "")
    smime = get(id, "smime.enabled", "")

    if (dt == "") emit("A02", id, "id.decl_type 缺失")
    if (inh == "") emit("A03", id, "in.host 缺失")
    if (outh == "") emit("A04", id, "out.host 缺失")
    if (incred != "" && get(id, "in.cred_asset_type", "") != "CredentialUserNameAndPassword")
      emit("A07", id, "凭据资产类型不是 CredentialUserNameAndPassword")

    if (dt != "" && dt != "com.apple.configuration.account.mail")
      emit("B01", id, "声明类型不是 com.apple.configuration.account.mail")
    if (get(id, "id.account_name", "") == "") emit("B02", id, "账户显示名为空")
    if (get(id, "in.server_type", "") != "IMAP") emit("B03", id, "收件服务端类型不是 IMAP")
    if (inport != "" && inport != "143" && inport != "993") emit("B04", id, "收件端口不在 143／993")
    if (outport != "" && outport != "25" && outport != "465" && outport != "587")
      emit("B05", id, "发件端口不在 25／465／587")
    if (get(id, "in.path_prefix", "") != "" && get(id, "in.server_type", "") != "IMAP")
      emit("B06", id, "path prefix 存在但服务端类型不是 IMAP")
    if (inauth == "None" && incred != "") emit("B07", id, "认证方法为 None 但仍登记凭据资产")
    if (inauth == "CredentialUserNameAndPassword" && incred == "")
      emit("B08", id, "认证方法需要凭据资产但该字段为空")
    if (get(id, "in.cred_user", "") !~ /@/) emit("B09", id, "凭据用户名不是邮箱形态")
    if (get(id, "in.cred_secret_inline", "") == "yes") emit("B10", id, "口令被内联登记")

    if (inport == "143" && intls != "starttls") emit("C01", id, "143 端口未声明 STARTTLS")
    if (outport == "25" && outtls != "starttls") emit("C02", id, "25 端口未声明 STARTTLS")
    if (inport == "993" && intls == "none") emit("C03", id, "993 端口声明 tls=none")
    if (outport == "465" && outtls == "none") emit("C04", id, "465 端口声明 tls=none")
    if (intls == "none" || outtls == "none") emit("C05", id, "任一服务端声明 tls=none")
    if (is_ip(inh) || is_ip(outh)) emit("C06", id, "服务端 host 是 IP 字面量")
    if (inh ~ /\.local$/ || outh ~ /\.local$/) emit("C07", id, "服务端 host 以 .local 结尾")
    if (inh != "" && outh != "" && domain(inh) != domain(outh))
      emit("C08", id, "收件与发件 host 域名不同（提示）")

    if (smime == "yes" && scred == "") emit("D01", id, "S/MIME 已启用但身份资产缺失")
    if (get(id, "smime.encryption", "") == "yes" && get(id, "smime.signing", "") == "no")
      emit("D02", id, "加密开启但签名关闭")
    if (get(id, "smime.signing", "") == "yes" && get(id, "smime.identity_asset_type", "") == "")
      emit("D03", id, "签名开启但身份资产类型为空")
    if (smime == "yes" && major(plat) >= 0 && major(plat) < 17)
      emit("D04", id, "S/MIME 对象声明在 iOS 17 之前")
    if (get(id, "smime.encryption", "") == "yes" && get(id, "smime.enc_alg", "") == "none")
      emit("D05", id, "加密开启但算法为 none")
    if (get(id, "smime.signing", "") == "yes" && get(id, "smime.sign_alg", "") == "none")
      emit("D06", id, "签名开启但算法为 none")

    if (get(id, "mgmt.source", "") == "") emit("E01", id, "管理面来源为空")
    if (get(id, "mgmt.allow_modification", "") == "false" && get(id, "mgmt.created_after_lock", "") == "yes")
      emit("E02", id, "锁定修改后仍新建账户，时间线矛盾")
    if (get(id, "priv.data_type", "") == "") emit("E03", id, "隐私申报缺少数据类型")
    if (get(id, "priv.data_type", "") ~ /Emails/ && get(id, "priv.consent", "") == "no")
      emit("E04", id, "申报了邮件数据但同意状态为 no")
    if (get(id, "mgmt.source", "") == "profile" && get(id, "mgmt.profile_present", "") == "no")
      emit("E05", id, "来源为描述文件但描述文件已不在，账户成孤儿")
    if (get(id, "mgmt.owner", "") == "") emit("E06", id, "账户归属人为空")
    if (get(id, "mgmt.removal_path", "") == "") emit("E07", id, "未登记移除路径")
    if (get(id, "mgmt.reused", "") == "yes" && get(id, "doc.page_url", "") != "")
      emit("E08", id, "账户标识被复用却仍引用旧文档行")

    if (get(id, "policy.remote_content_policy", "") == "unknown")
      emit("F01", id, "远端内容加载归属为 unknown")
    if (get(id, "policy.blocker_platform", "") == "iOS")
      emit("F02", id, "拦截件被声明在 iOS 上（公开拦截 API 只挂 macOS）")
    if (get(id, "policy.mpp", "") == "on" && get(id, "policy.relay_count", "") != "2")
      emit("F03", id, "MPP 开启但中继数与两段式中继不符")
    if (get(id, "policy.mpp", "") == "off" && get(id, "policy.hide_ip", "") == "on" &&
        get(id, "policy.hide_ip_basis", "") == "mpp")
      emit("F04", id, "MPP 关闭却把 Hide IP 记为 MPP 的一部分")
    if (get(id, "policy.background_download", "") == "yes" && get(id, "policy.mpp", "") == "off")
      emit("F05", id, "后台下载开启但 MPP 关闭")
    if (get(id, "claim.per_message_smime", "") == "yes" && smime != "yes")
      emit("F06", id, "宣称逐封 S/MIME 但账户未启用 S/MIME")
    if (get(id, "claim.closure", "") == "closed" && get(id, "claim.evidence_ref", "") == "")
      emit("F07", id, "结论为闭合但无证据引用")

    if (get(id, "doc.page_url", "") == "") emit("G01", id, "文档地址为空")
    if (get(id, "doc.line_ref", "") == "") emit("G02", id, "文档行锚为空")
    if (get(id, "doc.line_ref", "") != "" && get(id, "doc.line_ref", "") !~ /^[0-9]+$/)
      emit("G03", id, "文档行锚不是数字")
    else if (get(id, "doc.line_ref", "") + 0 > 300) emit("G03", id, "文档行锚超出行数上限 300")
    if (get(id, "doc.page_url", "") != "" && get(id, "doc.page_url", "") !~ /^https:\/\/developer\.apple\.com\//)
      emit("G04", id, "文档地址不是 developer.apple.com")
    if (get(id, "doc.page_title", "") == "") emit("G05", id, "文档标题为空")
    if (get(id, "claim.evidence_ref", "") != "" && get(id, "claim.evidence_ref", "") !~ /^R[0-9][0-9]$/)
      emit("G06", id, "证据引用不是 Rxx 形态")

    if (scred != "" && shared_ident[scred] + 0 > 1)
      emit("D07", id, "身份资产 " scred " 被多个账户共用")

    if (id in blocked || id in errored || id in warned) {
      if (id in blocked) verdict = "V3"; else if (id in errored) verdict = "V3"; else verdict = "V2"
    } else verdict = "V1"
    if (get(id, "policy.remote_content_policy", "") == "unknown") verdict = "V4"
    vcnt[verdict]++
    if (!QUIET) print "记录 " id " 判定=" verdict " 信号数=" per[id]+0
  }
  print "----"
  print "账户记录数= " nrec
  print "字段行数= " length(V)
  print "不同信号码= " length(cnt)
  print "信号条数= " siglines+0
  print "阻断信号条数= " blkcount+0
  printf "判定分布= "
  split("V1 V2 V3 V4", vs, " ")
  for (i = 1; i <= 4; i++) printf "%s=%d ", vs[i], vcnt[vs[i]] + 0
  print ""
  if (blkcount + 0 > 0 || errcount > 0) exit 1
  exit 0
}
'
```

### 21.8 设计取舍

**取舍一：先判未知，再判对错。** `F01` 的判定写在第 177 行，早于所有其他一致性检查；一旦策略为 `unknown`，整条记录直接 V4，后面的检查仍然执行并计数，但不改变判定。这样做的原因是：策略未知时，「其他字段都齐」不能推出「可读」，只能推出「台账写得全」。

**取舍二：把结构矛盾与策略提示分开。** B 族（字段）与 C 族（端口）都是 V3，D02（加密开签名关）与 C06—C08（IP、`.local`、域名不同）是 V2。这条分界不是按「严重程度」排的，而是按「是不是矛盾」排的：数据不成立是矛盾，数据成立但形态少见是提示。

**取舍三：拒绝可疑取值，而不是清洗。** A05 对私钥块、超过 120 字符的载荷、字段名含 `secret`／`password`／`token` 的明文一律拒收（第 74—80 行），拒收后该行不进入台账。这意味着台账不会保存任何可能是凭据的字符串；P16 用一段 150 字符的 `A` 载荷验证了这条路径（第 23.1 节）。

**取舍四：不发散到语义。** 脚本不检查主机是否存在、凭据是否有效、S/MIME 身份是否匹配地址。这些都需要设备或服务器，超出「离线只读」的边界。

### 21.9 已知局限

1. **发件端的 `None` 规则没有独立码。** B07／B08 只读 `in.*`；`out.auth=None` 与 `out.cred_asset` 的矛盾目前不产生信号（U04）。
2. **`in.server_type` 只接受 `IMAP`。** 归档页的 CODE 行只有 `IMAP` 一个值，但现实中存在 POP3 账户；本文不把 POP3 纳入判据，也不推断它是否该被支持。
3. **行锚上限 300 是本文约定。** 归档页最长 120 个分段，300 是安全上界；超过 300 视为引用错误（G03），不是「文档太长」。
4. **平台字段只做数字比对。** `id.platform` 与 `smime.*` 的时间线检查只比较版本号，不解析平台名；平台名是否合法留给脚本二的平台矩阵。

### 21.10 使用方法

1. 把台账写成三列文本，一条记录一组行，字段名用 21.2 的九个命名空间；
2. `bash script1.sh 台账.tsv` 得到逐记录判定与汇总；
3. 加 `-q` 只看汇总；`-h` 看用法；
4. 出现 V3 时，按 stderr 的码逐条回查第 21.3 节的行号；
5. 出现 V4 时，先去补 `policy.remote_content_policy` 的公开依据，不要先改其他字段。

---

## 22. 只读核验脚本二：远端内容加载三件差集与公告子词表比对器

### 22.1 这个脚本回答什么

脚本二回答另一个问题：**一个主体的装配件、内容件、回查件对不对得上，公告语料有没有覆盖这条链路。** 它读三份文本，输出 X 族（公告子词表）、Y 族（平台矩阵）、Z 族（三件差集）与 W 级闭合（W1—W4）。它不读设备、不读账户、不读邮件，只做集合计数与字段齐备性判定。

### 22.2 三份输入

1. **主张台账**：`<主体>,<方面.字段>,<取值>`，方面是 `account`／`content`／`readback`／`claim`；
2. **平台矩阵**：`<文档>,<平台>,<引入版本>`；
3. **公告语料**：TSV 六列 `file`／`platform`／`component`／`cve`／`impact`／`avail`，首行可为表头。

三份文件都在命令行给出；脚本内部用 `FNR == 1 { fi++ }` 切换阶段，**不使用 `getline`**（这一点由 P1 检查）。

### 22.3 主张字段

| 方面 | 字段 | 说明 |
| --- | --- | --- |
| `account.*` | `decl_type`／`platform`／`in_host`／`cred`／`smime`／`smime_identity` | 装配件 |
| `content.*` | `mpp`／`hide_ip`／`background`／`load_event`／`blocker`／`blocker_platform`／`remote_policy` | 内容件 |
| `readback.*` | `restriction_key`／`restriction_count`／`privacy_type`／`advisory_component` | 回查件 |
| `claim.*` | `closure` | 结论 |

### 22.4 信号族与行号

| 族 | 码 | 数量 | 位置 | 拦什么 |
| --- | --- | --- | --- | --- |
| X 公告子词表 | X01—X12 | 12 | 第 129—140 行 | 组件列无 Mail、影响句无 remote content／tracking／sender、两列无 IMAP／SMTP／POP3／credential／S/MIME／account、组件与影响句不等 |
| Y 平台矩阵 | Y01—Y10 | 10 | 第 88—98、148—160 行 | 账号无 iOS、S/MIME 无 iOS 17、MailKit 有 iOS、拦截件无 macOS、MessageUI 无 iOS、AccountSettings 有 iOS、版本差 >5、未知平台、坏行、版本非数字 |
| Z 三件差集 | Z00—Z16 | 17 | 第 75—78、184—200 行 | 主张行格式、装配缺 host／凭据／身份、内容缺五项、回查缺三项、缺声明类型、闭合但回查不齐、拦截件无矩阵、S/MIME 无平台、键少于四、隐私类型不符 |
| W 闭合 | W1—W4 | 4 | 第 202—207 行 | 闭合／部分／未知／不可判 |

合计 39 个信号码 + 4 级闭合 = 43。

### 22.5 闭合判定顺序

```
对每个主体：
  1. 若没有 account 方面 → W4（不可判）
  2. 若 content.remote_policy == unknown → W3
  3. 若装配件有 in_host 与 cred、内容件六项齐、回查件三项齐 → W1
  4. 否则若装配件有 in_host 与 cred → W2
  5. 否则 → W4
```

### 22.6 实跑样例

干净三件（`fx/s2-claims-good.tsv`、`fx/s2-platform-good.tsv`、`fx/s2-adv-good.tsv`）输出：

```text
主体 MA_1 闭合等级=W1 信号数=0
----
主张主体数= 1
平台文档数= 5
公告行数= 2
组件列 Mail= 2 Accounts= 0 Messages= 0
影响句 mail 行= 2 remote content= 1 tracking= 1 sender= 1
不同信号码= 0
信号条数= 0
闭合等级分布= W1=1 W2=0 W3=0 W4=0
```

注意 `公告行数= 2`：干净夹具不是「空语料」，它给了两行带 `Mail`、`remote content`、`tracking`、`sender` 的最小公告，所以 X 族的零命中判据不会误触发。这也是脚本二与脚本一在夹具设计上的最大差别：**脚本二的 good 夹具必须让每个「不得为零」的计数非零**。

### 22.7 源码

下面这段源码与 `.p21/script2.sh` 逐字节相同（P18 比对）。它只依赖 `awk`、`mktemp`、`rm`，三份输入全部由命令行给出。

```bash
#!/usr/bin/env bash
# mail-remote-content-diff.sh —— 远端内容加载三件差集与公告子词表比对器（离线 / 只读 / 不联网）
# 输入三份文本：
#   1) 主张台账：<主体>,<方面.字段>,<取值>   （方面 = account／content／readback／claim）
#   2) 平台矩阵：<文档>,<平台>,<引入版本>
#   3) 公告语料：TSV，六列 file／platform／component／cve／impact／avail（首行可为表头）
# 输出：X 族（公告子词表）、Y 族（平台矩阵）、Z 族（三件差集）信号码与 W 级闭合判定。
# 本脚本只做集合计数与字段齐备性判定：不含任何账户创建、内容加载、拦截规则下发或证书
# 导入的操作步骤，不含任何绕过内容拦截、伪造发件人或隐藏来源的手法，不连接任何服务器。
# 不调用 security／profiles／defaults／openssl／curl／mail 等工具，不读取设备状态；
# 唯一写出目标是 mktemp -d 创建的临时目录，退出时删除，本实现不向其写入任何字节。
set -u
LC_ALL=C; export LC_ALL

usage() {
  cat <<'EOF'
用法: mail-remote-content-diff.sh [-q] 主张台账 平台矩阵 公告语料
  -q  不输出逐主体判定行；-h/--help 显示本帮助
主张行格式: <主体>,<方面.字段>,<取值>
  方面字段: account.decl_type / account.platform / account.in_host / account.cred /
            account.smime / account.smime_identity /
            content.mpp / content.hide_ip / content.background / content.load_event /
            content.blocker / content.blocker_platform / content.remote_policy /
            readback.restriction_key / readback.restriction_count / readback.privacy_type /
            readback.advisory_component / claim.closure
平台行格式: <文档>,<平台>,<引入版本>
退出码: 0 无信号 / 1 有信号 / 2 用法或输入问题
EOF
}

QUIET=0
while [ $# -gt 0 ]; do
  case "$1" in
    -q) QUIET=1; shift ;;
    -h|--help) usage; exit 0 ;;
    --) shift; break ;;
    -*) usage >&2; exit 2 ;;
    *) break ;;
  esac
done
[ $# -eq 3 ] || { usage >&2; exit 2; }
for f in "$@"; do
  [ -r "$f" ] || { echo "输入不可读: $f" >&2; exit 2; }
done

TMPD=$(mktemp -d "${TMPDIR:-/tmp}/mrcd21.XXXXXX") || exit 2
trap 'rm -rf "$TMPD"' EXIT INT TERM

awk -v QUIET="$QUIET" '
function emit(code, subj, msg) {
  sig++; cnt[code]++
  stderrmsg = code "\t" (subj == "" ? "-" : subj) "\t" msg
  print stderrmsg > "/dev/stderr"
  if (subj != "") per[subj]++
}
function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }
function has(s, t) { return index(tolower(s), tolower(t)) > 0 }
function badv(v) {
  if (v == "") return 0
  if (index(v, "-----BEGIN") > 0) return 1
  if (length(v) > 120) return 1
  if (v ~ /^\/(private|System|Users|Volumes)\//) return 1
  if (v ~ /^(\$HOME|~)\//) return 1
  return 0
}
function num(v) { return (v ~ /^[0-9]+(\.[0-9]+)?$/) ? v + 0 : -1 }
function aspect(f) { return (index(f, ".") > 0) ? substr(f, 1, index(f, ".") - 1) : f }
function name(f) { return (index(f, ".") > 0) ? substr(f, index(f, ".") + 1) : f }
BEGIN { FS = ","; sig = 0 }
FNR == 1 { fi++ }
fi == 1 {
  line = trim($0)
  if (line != "" && substr(line, 1, 1) != "#") {
    n = split(line, a, ",")
    if (n != 3) { emit("Z00", "-", "主张行不是三列"); next }
    s = trim(a[1]); f = trim(a[2]); v = trim(a[3])
    if (s == "" || f == "") { emit("Z00", s, "主张标识或字段为空"); next }
    if (badv(s) || badv(f) || badv(v)) { emit("Z00", s, "主张行取值形似路径／凭据／长载荷，已拒收"); next }
    K[s SUBSEP f] = v
    if (!(s in seen)) { seen[s] = 1; subs[++nsub] = s }
  }
  next
}
fi == 2 {
  line = trim($0)
  if (line == "" || substr(line, 1, 1) == "#") next
  n = split(line, a, ",")
  if (n != 3) { emit("Y09", "-", "平台行不是三列"); next }
  d = trim(a[1]); p = trim(a[2]); v = trim(a[3])
  if (d == "" || p == "") { emit("Y09", d, "平台行的文档或平台为空"); next }
  if (badv(d) || badv(p) || badv(v)) { emit("Y09", d, "平台行取值形似路径／凭据／长载荷，已拒收"); next }
  key = d SUBSEP p
  if (key in PV) emit("Y09", d, "文档 " d " 的平台 " p " 重复登记")
  PV[key] = v
  if (!(d in docseen)) { docseen[d] = 1; docs[++ndoc] = d }
  if (p != "iOS" && p != "iPadOS" && p != "macOS" && p != "Mac Catalyst" && p != "visionOS" && p != "tvOS" && p != "watchOS")
    emit("Y08", d, "出现未知平台名 " p)
  if (num(v) < 0) emit("Y10", d, "引入版本不是数字: " v)
  next
}
{
  if (nadv == 0 && $0 ~ /^file\t/) next
  nadv++
  na = split($0, aa, "\t")
  advcomp[nadv] = (na >= 3) ? tolower(aa[3]) : ""
  advimp[nadv] = (na >= 5) ? tolower(aa[5]) : ""
}
END {
  if (nadv == 0) print "公告语料为空或不可解析" > "/dev/stderr"

  compMail = compAcc = compMsg = impMail = 0
  hitRemote = hitTrack = hitSender = hitIMAP = hitSMTP = hitPOP = hitCred = hitSMIME = hitAccount = 0
  for (i = 1; i <= nadv; i++) {
    c = advcomp[i]; m = advimp[i]
    if (c == "mail") compMail++
    if (c == "accounts") compAcc++
    if (c == "messages") compMsg++
    if (m ~ /(^|[^a-z])mail([^a-z]|$)/) impMail++
    if (has(m, "remote content")) hitRemote++
    if (has(m, "tracking")) hitTrack++
    if (has(m, "sender")) hitSender++
    if (has(c, "imap") || has(m, "imap")) hitIMAP++
    if (has(c, "smtp") || has(m, "smtp")) hitSMTP++
    if (has(c, "pop3") || has(m, "pop3")) hitPOP++
    if (has(c, "credential") || has(m, "credential")) hitCred++
    if (has(c, "s/mime") || has(c, "smime") || has(m, "s/mime") || has(m, "smime")) hitSMIME++
    if (has(c, "account") || has(m, "account")) hitAccount++
  }
  if (compMail == 0) emit("X01", "-", "公告组件列没有任何 Mail 行")
  if (hitRemote == 0) emit("X02", "-", "公告影响句没有任何 remote content 行")
  if (hitTrack == 0) emit("X03", "-", "公告影响句没有任何 tracking 行")
  if (hitSender == 0) emit("X04", "-", "公告影响句没有任何 sender 行")
  if (hitIMAP == 0) emit("X05", "-", "公告两列都没有 IMAP 词形")
  if (hitSMTP == 0) emit("X06", "-", "公告两列都没有 SMTP 词形")
  if (hitPOP == 0) emit("X07", "-", "公告两列都没有 POP3 词形")
  if (hitCred == 0) emit("X08", "-", "公告两列都没有 credential 词形")
  if (hitSMIME == 0) emit("X09", "-", "公告两列都没有 S/MIME 词形")
  if (hitAccount == 0) emit("X10", "-", "公告两列都没有 account 词形")
  if (compMail > 0 && impMail == 0) emit("X11", "-", "组件列有 " compMail " 行 Mail，影响句无 mail 词形")
  if (compMail > 0 && impMail > 0 && compMail != impMail) emit("X12", "-", "组件列 " compMail " 行与影响句 " impMail " 行不相等")

  # Y 族：平台矩阵
  acctIOS = acctSMIME = blockerIOS = blockerANY = msgIOS = settingsIOS = 0
  for (i = 1; i <= ndoc; i++) {
    d = docs[i]
    if (d == "accountmail" && ((d SUBSEP "iOS") in PV)) acctIOS = 1
    if (d == "accountmail_smime" && ((d SUBSEP "iOS") in PV) && num(PV[d SUBSEP "iOS"]) >= 17) acctSMIME = 1
    if (d ~ /mailkit/ && (((d SUBSEP "iOS") in PV) || ((d SUBSEP "iPadOS") in PV))) { emit("Y03", d, "MailKit 文档出现 iOS 行"); blockerIOS = 1 }
    if (d == "mailkit_mecontentblocker" && ((d SUBSEP "macOS") in PV)) blockerANY = 1
    if (d == "messageui_cansendmail" && ((d SUBSEP "iOS") in PV)) msgIOS = 1
    if (d == "accountsettings" && ((d SUBSEP "iOS") in PV)) { emit("Y06", d, "AccountSettings 出现 iOS 行"); settingsIOS = 1 }
    if (((d SUBSEP "iOS") in PV) && ((d SUBSEP "macOS") in PV)) {
      iv = num(PV[d SUBSEP "iOS"]); mv = num(PV[d SUBSEP "macOS"])
      if (iv >= 0 && mv >= 0 && (iv - mv > 5 || mv - iv > 5)) emit("Y07", d, "同一文档 iOS " iv " 与 macOS " mv " 相差超过 5")
    }
  }
  if (!acctIOS) emit("Y01", "accountmail", "账号声明没有 iOS 行")
  if (!acctSMIME) emit("Y02", "accountmail_smime", "S/MIME 对象没有 iOS 17 行")
  if (!blockerANY) emit("Y04", "mailkit_mecontentblocker", "拦截件文档没有 macOS 行")
  if (!msgIOS) emit("Y05", "messageui_cansendmail", "MessageUI 没有 iOS 行")

  # Z 族：三件差集
  for (i = 1; i <= nsub; i++) {
    s = subs[i]; asp_count = 0
    if (((s SUBSEP "account.decl_type") in K) || ((s SUBSEP "account.in_host") in K) || ((s SUBSEP "account.cred") in K)) asp_count++
    a_in = ((s SUBSEP "account.in_host") in K) ? K[s SUBSEP "account.in_host"] : ""
    a_cred = ((s SUBSEP "account.cred") in K) ? K[s SUBSEP "account.cred"] : ""
    a_plat = ((s SUBSEP "account.platform") in K) ? K[s SUBSEP "account.platform"] : ""
    a_smime = ((s SUBSEP "account.smime") in K) ? K[s SUBSEP "account.smime"] : ""
    a_sid = ((s SUBSEP "account.smime_identity") in K) ? K[s SUBSEP "account.smime_identity"] : ""
    c_mpp = ((s SUBSEP "content.mpp") in K) ? K[s SUBSEP "content.mpp"] : ""
    c_hip = ((s SUBSEP "content.hide_ip") in K) ? K[s SUBSEP "content.hide_ip"] : ""
    c_bg = ((s SUBSEP "content.background") in K) ? K[s SUBSEP "content.background"] : ""
    c_ev = ((s SUBSEP "content.load_event") in K) ? K[s SUBSEP "content.load_event"] : ""
    c_blk = ((s SUBSEP "content.blocker") in K) ? K[s SUBSEP "content.blocker"] : ""
    c_bp = ((s SUBSEP "content.blocker_platform") in K) ? K[s SUBSEP "content.blocker_platform"] : ""
    c_rp = ((s SUBSEP "content.remote_policy") in K) ? K[s SUBSEP "content.remote_policy"] : ""
    r_key = ((s SUBSEP "readback.restriction_key") in K) ? K[s SUBSEP "readback.restriction_key"] : ""
    r_cnt = ((s SUBSEP "readback.restriction_count") in K) ? K[s SUBSEP "readback.restriction_count"] : ""
    r_priv = ((s SUBSEP "readback.privacy_type") in K) ? K[s SUBSEP "readback.privacy_type"] : ""
    r_adv = ((s SUBSEP "readback.advisory_component") in K) ? K[s SUBSEP "readback.advisory_component"] : ""
    cl = ((s SUBSEP "claim.closure") in K) ? K[s SUBSEP "claim.closure"] : ""

    if (asp_count == 0) { emit("W4", s, "主体没有 account 方面，归属不可判"); continue }
    if (a_in == "") emit("Z01", s, "装配件缺收件 host")
    if (a_cred == "") emit("Z02", s, "装配件缺凭据引用")
    if (a_smime == "yes" && a_sid == "") emit("Z03", s, "装配件启用 S/MIME 但缺身份引用")
    if (c_mpp == "") emit("Z04", s, "内容件缺 MPP 开关")
    if (c_hip == "") emit("Z05", s, "内容件缺 Hide IP 开关")
    if (c_bg == "") emit("Z06", s, "内容件缺后台下载读数")
    if (c_ev == "") emit("Z07", s, "内容件缺 Load remote content 事件")
    if (r_key == "") emit("Z08", s, "回查件缺限制键")
    if (r_priv == "") emit("Z09", s, "回查件缺隐私数据类型")
    if (r_adv == "") emit("Z10", s, "回查件缺公告组件行")
    if (!((s SUBSEP "account.decl_type") in K) && (c_mpp != "" || c_rp != "")) emit("Z11", s, "内容件有主体但装配件缺声明类型")
    if (cl == "closed" && (r_key == "" || r_priv == "" || r_adv == "")) emit("Z12", s, "结论为闭合但回查件不齐")
    if (c_blk != "" && c_blk != "no" && !blockerANY) emit("Z13", s, "宣称有拦截件但平台矩阵没有拦截件文档")
    if (a_plat == "" && a_smime == "yes") emit("Z14", s, "启用 S/MIME 但账号平台为空")
    if (r_cnt != "" && num(r_cnt) >= 0 && num(r_cnt) < 4) emit("Z15", s, "回查限制键少于四个")
    if (r_priv != "" && r_priv != "NSPrivacyCollectedDataTypeEmailsOrTextMessages") emit("Z16", s, "隐私数据类型不是 EmailsOrTextMessages")

    if (c_rp == "unknown") wl = "W3"
    else if (a_in != "" && a_cred != "" && c_mpp != "" && c_hip != "" && c_bg != "" && c_ev != "" && r_key != "" && r_priv != "" && r_adv != "") wl = "W1"
    else if (a_in != "" && a_cred != "") wl = "W2"
    else wl = "W4"
    wcnt[wl]++
    if (!QUIET) print "主体 " s " 闭合等级=" wl " 信号数=" per[s]+0
  }

  print "----"
  print "主张主体数= " nsub
  print "平台文档数= " ndoc
  print "公告行数= " nadv
  print "组件列 Mail= " compMail " Accounts= " compAcc " Messages= " compMsg
  print "影响句 mail 行= " impMail " remote content= " hitRemote " tracking= " hitTrack " sender= " hitSender
  print "不同信号码= " length(cnt)
  print "信号条数= " sig+0
  printf "闭合等级分布= W1=%d W2=%d W3=%d W4=%d\n", wcnt["W1"]+0, wcnt["W2"]+0, wcnt["W3"]+0, wcnt["W4"]+0
  if (sig > 0) exit 1
  exit 0
}
' "$1" "$2" "$3"
```

### 22.8 设计取舍

**取舍一：结构错误与内容错误分开计码。** 主张行、平台行的格式问题一律进 Z00／Y09，被拒收的行不参与后续判定；其余主体照常算。这样坏的输入不会把整批结果拖成空，也不会把「格式没写对」误读成「链路不齐」。

**取舍二：闭合等级与信号条数正交。** W 级只看三件齐不齐，X／Y／Z 看语料与平台有没有问题。两者可以同时出现：R22 与 R33 都是 `W1` 带 X 族信号——三件齐了，但公告语料里没有 `remote content` 以外的词形。这是有意保留的：**「齐」不等于「对」**，所以 W1 不能当作验收通过。

**取舍三：空语料单独报到 stderr。** 公告语料为空或不可解析时打印一行提示，不计入 X 族。空语料与「有语料但零命中」是两件事：前者是输入缺失，后者才是「公告没覆盖」，混在一起会让 X01—X10 失去区分度。

**取舍四：平台差只做数值。** Y07 只比较同一文档的 iOS 与 macOS 引入版本，差值超过 5 才发信号。它不判断哪个平台「应该先有」，也不推测未登记平台的存在。

**取舍五：不合并三份输入。** 三件语料的行宽、行义、粒度都不同：主张台账是主体级，平台矩阵是文档×平台级，公告是行级。合并成一个文件再靠列数分支，会让一处列错位污染全部阶段；三文件加 `FNR == 1` 切换更笨，但边界清楚。

### 22.9 已知局限

1. **组件列只数三个名字。** `Mail`／`Accounts`／`Messages` 以外的组件名不进 `compMail` 等计数；X11／X12 的相等性也只在这三个名字上成立。
2. **平台名是固定枚举。** 只有 `iOS`／`iPadOS`／`macOS`／`Mac Catalyst`／`visionOS`／`tvOS`／`watchOS` 七个名字；别名（如 `iOS 17` 写在平台列）会触发 Y08。
3. **版本按数值比较。** `num()` 只接受 `^[0-9]+(\.[0-9]+)?$`，`17.0` 与 `17` 视为 17 与 17，不区分补丁号。
4. **公告判定依赖词形。** `remote content`、`tracking`、`sender` 都是子串匹配（大小写不敏感），不做语义判断；`remote` 单独出现不算命中 `remote content`。
5. **闭合只判字段存在，不判字段一致。** 例如 `content.mpp=on` 与 `content.hide_ip=off` 同时存在不会触发任何码；这类跨字段语义留给脚本一与人工复核。

### 22.10 使用方法

1. 主张台账一行一个字段，主体名在三份文件中必须完全一致；
2. 平台矩阵按 `<文档>,<平台>,<引入版本>` 写，文档名用 `C/platform-21.txt` 的短名；
3. 公告语料保留原表头，六列顺序不要改；
4. `bash script2.sh 台账.tsv 平台.tsv 公告.tsv` 运行，`-q` 只看汇总，`-h` 看用法；
5. 退出码 0 表示无信号，1 表示有信号，2 表示用法或输入问题——2 不是「不齐」，是「没跑成」。

---

## 23. 实跑与覆盖验收

### 23.1 验收标准

本文对两支脚本的验收只看四件事：

| 编号 | 标准 | 判据 |
| --- | --- | --- |
| V1 | 可重复 | 同一输入连跑两次，输出与退出码相同；输入文件摘要不变 |
| V2 | 无越界 | 不联网、不调用系统工具、不读设备与钥匙串；命令位置零命中 |
| V3 | 无残留 | 临时目录用 `mktemp -d` 创建，退出后零条目；输入文件不被改写 |
| V4 | 自洽 | 报告内嵌源码与实跑源码逐字节一致；101 个信号码全部被 34 次实跑触发 |

V1—V3 由脚本结构本身保证，V4 由证明脚本 `proof.sh` 检查。证明脚本读的是本报告文件本身：它从第 23.2 节的代码块里抽出三段源码，与 `.p21/` 下的实跑文件比对。

### 23.2 证明脚本

`proof.sh` 只依赖 `bash`、`grep`、`sed`、`awk`、`perl`、`md5sum`／`md5`、`mktemp`。它自己也不联网，只在临时目录里生成夹具副本。用法：

```text
bash proof.sh 21-iOS-Mail-Account-Remote-Content-Loading-Attribution-Analysis.md
```

下面这段源码与 `.p21/proof.sh` 逐字节相同（P18 的第三段比对）。

```bash
#!/usr/bin/env bash
# 第 21 篇只读实证 P1—P20（全部命令可复跑；不联网、不碰设备）
# 用法: bash proof.sh [含内嵌源码的报告文件]；缺省读同目录的 part7.md
set -u
cd "$(dirname "$0")" || exit 2
MD=${1:-part7.md}
FX=fx
T=$(mktemp -d "${TMPDIR:-/tmp}/p21pf.XXXXXX") || exit 2
trap 'rm -rf "$T"' EXIT INT TERM
S1H0=$(md5sum script1.sh | awk '{print $1}')
S2H0=$(md5sum script2.sh | awk '{print $1}')

hr() { printf '\n===== %s =====\n' "$1"; }

hr "P1 awk 程序体内无 system/getline/popen/ENVIRON"
grep -nE 'system\(|getline|popen|ENVIRON' script1.sh script2.sh || echo "命中= 0"

hr "P2 bash -n 语法检查"
bash -n script1.sh && echo "script1.sh 语法= 通过"
bash -n script2.sh && echo "script2.sh 语法= 通过"

hr "P3 临时目录前缀"
grep -n 'mktemp -d' script1.sh script2.sh

hr "P4 被禁工具名的全部出现位置（头部声明／脚本名／字段名）"
grep -nE 'openssl|security|defaults|profiles|scutil|networksetup|osascript|keychain|log|curl|diskutil|hdiutil' script1.sh script2.sh

hr "P4b 命令位置探测（行首或 | ; &）( 之后）"
grep -nE '(^|[|;&(])[[:space:]]*(openssl|security|defaults|profiles|scutil|networksetup|osascript|log|curl|mail|diskutil|hdiutil)[[:space:]]' script1.sh script2.sh || echo "命令位置命中= 0"

hr "P5 命令名整词普查"
grep -ohE '\b(awk|tr|cat|mktemp|rm|bash|sh|perl|python|python3|node|curl|wget|nc|ssh|scp)\b' script1.sh script2.sh | sort | uniq -c

hr "P6 非注释行中的网络工具整词计数"
printf 'script1.sh= '; grep -v '^[[:space:]]*#' script1.sh | grep -cE '\b(curl|wget|nc|ssh|scp|ftp|telnet)\b'
printf 'script2.sh= '; grep -v '^[[:space:]]*#' script2.sh | grep -cE '\b(curl|wget|nc|ssh|scp|ftp|telnet)\b'

hr "P7 写出方向：stderr 之外的重定向"
grep -nE '(>>|> *"/dev/stderr"|>&2)' script1.sh script2.sh; echo "（以上仅为 /dev/stderr 与 usage 的 >&2；无 >> 追加）"

hr "P8 TMPD 出现次数"
printf 'script1.sh= '; grep -c 'TMPD' script1.sh
printf 'script2.sh= '; grep -c 'TMPD' script2.sh

hr "P9 输入文件运行前后摘要一致"
cp "$FX/s1-bad.tsv" "$T/in1.tsv"
cp "$FX/s2-claims-good.tsv" "$T/c.tsv"
cp "$FX/s2-platform-good.tsv" "$T/p.tsv"
cp "$FX/s2-adv-good.tsv" "$T/a.tsv"
b1=$(md5sum "$T/in1.tsv" | awk '{print $1}'); b2=$(md5sum "$T/c.tsv" | awk '{print $1}')
b3=$(md5sum "$T/p.tsv" | awk '{print $1}'); b4=$(md5sum "$T/a.tsv" | awk '{print $1}')
bash script1.sh "$T/in1.tsv" >/dev/null 2>&1
bash script2.sh "$T/c.tsv" "$T/p.tsv" "$T/a.tsv" >/dev/null 2>&1
a1=$(md5sum "$T/in1.tsv" | awk '{print $1}'); a2=$(md5sum "$T/c.tsv" | awk '{print $1}')
a3=$(md5sum "$T/p.tsv" | awk '{print $1}'); a4=$(md5sum "$T/a.tsv" | awk '{print $1}')
[ "$b1" = "$a1" ] && echo "script1 输入未变 $a1" || echo "script1 输入被改动"
[ "$b2" = "$a2" ] && [ "$b3" = "$a3" ] && [ "$b4" = "$a4" ] && echo "script2 三输入未变 $a2" || echo "script2 输入被改动"

hr "P10 临时目录零残留"
T2=$(mktemp -d "${TMPDIR:-/tmp}/p21t2.XXXXXX") || exit 2
TMPDIR="$T2" bash script1.sh "$FX/s1-good.tsv" >/dev/null 2>&1
TMPDIR="$T2" bash script2.sh "$FX/s2-claims-good.tsv" "$FX/s2-platform-good.tsv" "$FX/s2-adv-good.tsv" >/dev/null 2>&1
printf '运行后 TMPDIR 内条目数= '; find "$T2" -mindepth 1 | wc -l
rm -rf "$T2"

hr "P11 干净夹具：0 信号、退出 0"
bash script1.sh "$FX/s1-good.tsv" > "$T/g1" 2> "$T/g1e"; e1=$?
bash script2.sh "$FX/s2-claims-good.tsv" "$FX/s2-platform-good.tsv" "$FX/s2-adv-good.tsv" > "$T/g2" 2> "$T/g2e"; e2=$?
echo "script1 退出= $e1"; grep -E '账户记录数|不同信号码|判定分布' "$T/g1"
echo "script2 退出= $e2"; grep -E '主张主体数|不同信号码|闭合等级' "$T/g2"

hr "P12 -h 帮助：退出 0"
bash script1.sh -h > "$T/h1"; echo "script1 -h 退出= $? 含用法= $(grep -c '用法' "$T/h1")"
bash script2.sh -h > "$T/h2"; echo "script2 -h 退出= $? 含用法= $(grep -c '用法' "$T/h2")"

hr "P13 缺参数：退出 2"
bash script1.sh >/dev/null 2>&1; echo "script1 无参数退出= $?"
bash script2.sh "$FX/s2-claims-good.tsv" "$FX/s2-platform-good.tsv" >/dev/null 2>&1; echo "script2 两输入退出= $?"

hr "P14 不可读输入：退出 2"
bash script1.sh "$T/不存在.tsv" >/dev/null 2>&1; echo "script1 退出= $?"
bash script2.sh "$FX/s2-claims-good.tsv" "$FX/s2-platform-good.tsv" "$T/不存在.tsv" >/dev/null 2>&1; echo "script2 退出= $?"

hr "P15 未知选项：退出 2"
bash script1.sh -x >/dev/null 2>&1; echo "script1 退出= $?"
bash script2.sh -x >/dev/null 2>&1; echo "script2 退出= $?"

hr "P16 A05 取值拒收：超长载荷"
perl -pe 'BEGIN{$x="A"x150} s/^MA_1,claim\.evidence_ref,.*/MA_1,claim.evidence_ref,$x/' "$FX/s1-good.tsv" > "$T/dirty1.tsv"
bash script1.sh "$T/dirty1.tsv" > "$T/d1o" 2> "$T/d1e"; echo "退出= $?"
grep 'A05' "$T/d1e"; grep -E '阻断信号条数|判定分布' "$T/d1o"

hr "P17 脚本二平台行格式拒收：路径形态"
cp "$FX/s2-platform-good.tsv" "$T/plat-dirty.tsv"
printf '/Users/x/secret,iOS,15\n' >> "$T/plat-dirty.tsv"
bash script2.sh "$FX/s2-claims-good.tsv" "$T/plat-dirty.tsv" "$FX/s2-adv-good.tsv" > "$T/d2o" 2> "$T/d2e"; echo "退出= $?"
grep 'Y09' "$T/d2e"; grep '平台文档数' "$T/d2o"

hr "P18 报告内嵌源码与实跑源码一致"
rm -f "$T/e1.sh" "$T/e2.sh" "$T/e3.sh"
if [ -f "$MD" ]; then
awk '/^```bash$/{inb=1; b++; next} /^```$/{if(inb){inb=0}; next} inb&&b==1{print > "'"$T"'/e1.sh"} inb&&b==2{print > "'"$T"'/e2.sh"} inb&&b==3{print > "'"$T"'/e3.sh"}' "$MD"
diff -q script1.sh "$T/e1.sh" && echo "script1 内嵌= 一致"
diff -q script2.sh "$T/e2.sh" && echo "script2 内嵌= 一致"
if [ -f "$T/e3.sh" ]; then diff -q proof.sh "$T/e3.sh" && echo "proof.sh 内嵌= 一致"; else echo "proof.sh 内嵌= 跳过（所读文件不足三段 bash 块）"; fi
else
echo "跳过：$MD 不存在（装配前先跑 P1—P17、P19—P20）"
fi

hr "P19 两支脚本自身运行前后摘要一致"
h1=$(md5sum script1.sh | awk '{print $1}'); h2=$(md5sum script2.sh | awk '{print $1}')
[ "$h1" = "$S1H0" ] && echo "script1 未变 $h1" || echo "script1 被改动 $S1H0 -> $h1"
[ "$h2" = "$S2H0" ] && echo "script2 未变 $h2" || echo "script2 被改动 $S2H0 -> $h2"

hr "P20 34 次实跑覆盖验收"
tail -4 matrix-out.txt
```

### 23.3 证明输出

对本报告文件运行 `proof.sh` 的完整输出如下。P18 读的正是本文件中前三段 `bash` 代码块——也就是第 21.7 节的脚本一、第 22.7 节的脚本二与本节上面的证明脚本。

```text
===== P1 awk 程序体内无 system/getline/popen/ENVIRON =====
命中= 0

===== P2 bash -n 语法检查 =====
script1.sh 语法= 通过
script2.sh 语法= 通过

===== P3 临时目录前缀 =====
script1.sh:12:#       唯一写出目标是 mktemp -d 创建的临时目录，退出时删除，本实现不向其写入任何字节。
script1.sh:56:TMPD=$(mktemp -d "${TMPDIR:-/tmp}/mail21.XXXXXX") || exit 2
script2.sh:11:# 唯一写出目标是 mktemp -d 创建的临时目录，退出时删除，本实现不向其写入任何字节。
script2.sh:46:TMPD=$(mktemp -d "${TMPDIR:-/tmp}/mrcd21.XXXXXX") || exit 2

===== P4 被禁工具名的全部出现位置（头部声明／脚本名／字段名） =====
script1.sh:10:# 本脚本不联网、不调用 openssl／security／defaults／profiles／log／scutil／networksetup／
script1.sh:11:#       curl／mail／osascript 等任何命令行工具、不读取钥匙串、不打开任何账户或邮箱。
script2.sh:10:# 不调用 security／profiles／defaults／openssl／curl／mail 等工具，不读取设备状态；

===== P4b 命令位置探测（行首或 | ; &）( 之后） =====
命令位置命中= 0

===== P5 命令名整词普查 =====
      2 awk
      2 bash
      3 cat
      2 curl
      4 mktemp
      2 rm
      4 sh
      1 tr

===== P6 非注释行中的网络工具整词计数 =====
script1.sh= 0
script2.sh= 0

===== P7 写出方向：stderr 之外的重定向 =====
script1.sh:46:    -*) usage >&2; exit 2 ;;
script1.sh:51:[ $# -ge 1 ] || { usage >&2; exit 2; }
script1.sh:53:  [ -r "$f" ] || { echo "输入不可读: $f" >&2; exit 2; }
script1.sh:62:  print code "\t" (id == "" ? "-" : id) "\t" msg > "/dev/stderr"
script2.sh:37:    -*) usage >&2; exit 2 ;;
script2.sh:41:[ $# -eq 3 ] || { usage >&2; exit 2; }
script2.sh:43:  [ -r "$f" ] || { echo "输入不可读: $f" >&2; exit 2; }
script2.sh:53:  print stderrmsg > "/dev/stderr"
script2.sh:109:  if (nadv == 0) print "公告语料为空或不可解析" > "/dev/stderr"
（以上仅为 /dev/stderr 与 usage 的 >&2；无 >> 追加）

===== P8 TMPD 出现次数 =====
script1.sh= 2
script2.sh= 2

===== P9 输入文件运行前后摘要一致 =====
script1 输入未变 53428f7a14b6986e7744f5552fe58705
script2 三输入未变 410e21e838ec32b9065b98d8ad98f427

===== P10 临时目录零残留 =====
运行后 TMPDIR 内条目数= 0

===== P11 干净夹具：0 信号、退出 0 =====
script1 退出= 0
账户记录数= 2
不同信号码= 0
判定分布= V1=2 V2=0 V3=0 V4=0 
script2 退出= 0
主体 MA_1 闭合等级=W1 信号数=0
主张主体数= 1
不同信号码= 0
闭合等级分布= W1=1 W2=0 W3=0 W4=0

===== P12 -h 帮助：退出 0 =====
script1 -h 退出= 0 含用法= 2
script2 -h 退出= 0 含用法= 2

===== P13 缺参数：退出 2 =====
script1 无参数退出= 2
script2 两输入退出= 2

===== P14 不可读输入：退出 2 =====
script1 退出= 2
script2 退出= 2

===== P15 未知选项：退出 2 =====
script1 退出= 2
script2 退出= 2

===== P16 A05 取值拒收：超长载荷 =====
退出= 1
A05	MA_1	字段 claim.evidence_ref 的取值形似私钥／口令／长载荷，已拒收
阻断信号条数= 1
判定分布= V1=1 V2=0 V3=1 V4=0 

===== P17 脚本二平台行格式拒收：路径形态 =====
退出= 1
Y09	/Users/x/secret	平台行取值形似路径／凭据／长载荷，已拒收
平台文档数= 5

===== P18 报告内嵌源码与实跑源码一致 =====
script1 内嵌= 一致
script2 内嵌= 一致
proof.sh 内嵌= 一致

===== P19 两支脚本自身运行前后摘要一致 =====
script1 未变 f8380687208ae9d224426db13f2a2fa6
script2 未变 a98fde7019533a26a71aee2ae2cdf5e8

===== P20 34 次实跑覆盖验收 =====
期望码总数= 101
未覆盖= 0
表外码= 0
覆盖验收= 通过（101/101）
```

### 23.4 逐项结果

| 编号 | 检查什么 | 结果 | 说明 |
| --- | --- | --- | --- |
| P1 | awk 程序体内无 `system`／`getline`／`popen`／`ENVIRON` | 0 命中 | 脚本二的三文件切换不靠 `getline`，靠 `FNR == 1` |
| P2 | `bash -n` 语法 | 两支通过 | 只查语法，不查行为 |
| P3 | 临时目录前缀 | `mail21.`／`mrcd21.` | 按前缀可在 `TMPDIR` 中区分 |
| P4 | 被禁工具名的全部出现 | 仅 3 行注释 | 头部声明本身提到这些名字 |
| P4b | 命令位置探测 | 0 命中 | 出现在注释行首以外的「命令位」为零 |
| P5 | 命令名整词普查 | 8 个词 | `curl` 的两次出现都在注释里，见 P4 |
| P6 | 非注释行的网络工具 | 0 | 排除注释后网络工具零出现 |
| P7 | 重定向方向 | 仅 `>&2` 与 `/dev/stderr` | 无 `>>` 追加，不写文件 |
| P8 | `TMPD` 出现次数 | 各 2 | 创建与删除各一次 |
| P9 | 输入运行前后摘要 | 未变 | 输入文件只读 |
| P10 | 临时目录残留 | 0 条目 | `trap` 在 `EXIT`／`INT`／`TERM` 上清理 |
| P11 | 干净夹具 | 退出 0、0 信号 | 两支脚本的 good 路径 |
| P12 | `-h` | 退出 0 | 帮助可用 |
| P13 | 缺参数 | 退出 2 | 与「有信号」区分 |
| P14 | 不可读输入 | 退出 2 | 与「不齐」区分 |
| P15 | 未知选项 | 退出 2 | 不静默忽略 |
| P16 | 超长载荷 | A05、阻断条数 1 | 150 字符载荷被拒收 |
| P17 | 路径形态平台行 | Y09 | `/Users/...` 被拒收 |
| P18 | 内嵌源码一致性 | 三段一致 | 报告与实跑同源 |
| P19 | 脚本运行前后摘要 | 未变 | 脚本不自改 |
| P20 | 101 码覆盖 | 101/101 | 34 次实跑，未覆盖 0、表外码 0 |

需要说明的是 P2：`bash -n` 只证明语法成立，不证明分支被走到。分支覆盖由 P20 的 34 次实跑承担；两者不能互相替代。
### 23.5 覆盖验收：34 次实跑与 101 个码

覆盖验收只看一件事：**表里的每一个码，有没有至少一次被真实输入触发。** 34 次实跑全部用合成夹具，退出码分布为 0 九次、1 十九次、2 六次——三种出口都被走到，说明「合格」「有信号」「没跑成」没有被压成同一件事。

| 脚本 | 实跑 | 退出 0 | 退出 1 | 退出 2 |
| --- | --- | --- | --- | --- |
| 脚本一 | R01—R19（19 次） | 7 | 9 | 3 |
| 脚本二 | R20—R34（15 次） | 2 | 10 | 3 |
| 合计 | 34 次 | 9 | 19 | 6 |

逐族看：

| 族 | 码范围 | 个数 | 首次触发 | 触发方式 |
| --- | --- | --- | --- | --- |
| A 取值与身份 | A01—A08 | 8 | R02 | 全违例台账 |
| B 结构完整性 | B01—B10 | 10 | R02 | 全违例台账 |
| C 收发服务端 | C01—C08 | 8 | R02 | 全违例台账 |
| D 凭据与端口形态 | D01—D07 | 7 | R03 | 结构缺项子集 |
| E 内容加载读数 | E01—E08 | 8 | R02 | 全违例台账 |
| F 回查与管理面 | F01—F07 | 7 | R02 | 全违例台账 |
| G 引用与折算 | G01—G06 | 6 | R02 | 全违例台账 |
| V 判定等级 | V1—V4 | 4 | R01／R04／R02／R02 | 干净／端口提示／有信号／未知策略 |
| X 公告子词表 | X01—X12 | 12 | R21／R22 | 空命中与不相等各自成组 |
| Y 平台矩阵 | Y01—Y10 | 10 | R21 | 删行矩阵 |
| Z 三件差集 | Z00—Z16 | 17 | R21 | 全缺三件 |
| W 闭合等级 | W1—W4 | 4 | R20／R21 | 干净／全缺 |

需要点出的三次**单码**实跑：R13 只有 `A05`（超长载荷被拒收）、R08 只有 `C08`（同一记录的 IP、`.local` 与域名三个都能对上却不一致）、R23 只有 `X12`（组件列与影响句行数不等）。单码实跑证明这些判据不依赖别的记录同框；R27 则相反，一次打出 `X01`—`X10` 十个码，证明「空语料」这一条路径是整族失败而不是逐条失败。

`matrix-out.txt` 是这 34 行的逐次原始记录，末四行是汇总：

```text
实跑次数= 34
已触发不同码= 101
期望码总数= 101
未覆盖= 0
表外码= 0
覆盖验收= 通过（101/101）
```

101 的分解与第 23.1 节一致：脚本一 `8+10+8+7+8+7+6+4 = 58`，脚本二 `12+10+17+4 = 43`。两组相加不是「58 个结论加 43 个结论」，而是**同一批台账的两种切法**：脚本一从一条记录内部找矛盾，脚本二从三件之间找缺口。

### 23.6 验收边界

这一节写清楚 34 次实跑与 20 项证明**没有**证明什么，避免把覆盖率读成结论强度。

1. **证明的是「没有读写别处的口子」，不是「读数与设备一致」。** P1—P10 只能说明脚本不调用系统工具、不联网、不写文件、不留临时目录。它们证明不了「台账里填的 `remote_policy=unknown` 与某台设备上的实际状态一致」。
2. **夹具是合成的，不对应任何真实账户或邮箱。** `.p21/fx/` 的 12 份文件共 331 行，主机名、凭据引用与公告行都是构造值；P16 与 P17 用的超长载荷与路径也是构造值。真实台账进来后必须先洗数据，洗完的留档同样不能随文发布。
3. **平台矩阵与公告读数是归档快照，不是在线查询。** 16 份文档的平台坐标来自 `.srcx21/C/platform-21.txt`，1,266 行公告来自 `.srcx21/C/advisory-21.tsv`。两者都冻结在归档时刻；Apple 之后新增的平台行或公告行不在其中，脚本也不会去网上补。
4. **判据对不对，靠行号人工核，覆盖率不代替。** 101/101 只说明每条判据都还能被打中；判据本身是否写对，要看第 21.3、22.3 两节给出的行号与第 3 章的八处换算失败。
5. **只覆盖字段级矛盾，不覆盖跨字段语义。** 例如 `content.mpp=on` 与 `content.hide_ip=off` 同时出现不会触发任何码；`remote_policy=unknown` 也不会因为别的字段齐而被改写。语义判断留在第 18 章 J1—J4 的决策顺序里，由人做。
6. **脚本不判断策略该不该是 `unknown`。** 它只登记这个值，并在 `unknown` 时把结论压到 W3／V4。至于某个平台的远端内容加载到底有没有公开策略，是第 7 章 L7 与第 17 章可见性边界要回答的问题。

---

## 24. 十二个误区

这一章把全篇最容易读错的十二处集中列出。每一条给三样东西：**误读**（一句会被写进报告或台账的话）、**正确读法**（公开口径实际支持的那一句）、**判据**（哪一行读数或原文否证了它）。最后压成四组，每组一条禁令。

| 编号 | 误读 | 正确读法 | 判据与脚本码 |
| --- | --- | --- | --- |
| M01 | 公告里 `Mail` 组件有 15 行，所以邮件类缺陷有 15 个 | 15 行只对应 3 个 CVE；组件名是**归属标签**，不是缺陷类型；同一批公告的影响句对 `mail` 词形是 0 行 | `C/readings-21.txt:3、7、17`；脚本二 X01／X11 |
| M02 | 影响句 `remote` 有 45 行，说明「远端内容加载」是主要缺陷形态 | 45 行**全部是 `remote attacker`**，与内容路径无关；`remote content` 是 0 行 | `C/readings-21.txt:20—22`；脚本二 X02 |
| M03 | 关掉「保护邮件活动」后，Hide IP 也一起失效了 | 原文写明关闭后 **Hide IP 仍用同样的两段中继**遮蔽 IP；两个开关不联动 | `B/mail-privacy-protection-legal.txt:33`；脚本一 E04／E05 |
| M04 | 远端内容只在用户打开邮件时才下载 | 原文写明「**后台默认下载，无论是否与这封邮件交互**」；打开时才下载是 MPP 之前的形态 | `B/mail-privacy-protection-legal.txt:30`；脚本一 E02 |
| M05 | 两段中继由同一家运营，拼起来就是完整画像 | 原文写明**两个不同实体**：第一段知道 IP 不知道内容，第二段知道内容不知道 IP | `B/mail-privacy-protection-legal.txt:31`；脚本一 E06 |
| M06 | iOS 邮件也能装内容拦截器，把远端内容拦掉 | 公开的内容拦截接口只有 `MEContentBlocker`，**macOS 12+**；16 份文档里 0 份 iOS MailKit | `A/mailkit_mecontentblocker.txt:3、20`；`C/platform-21.txt:26`；脚本二 Y04 |
| M07 | 用户点了「加载远端内容」横幅，拦截规则就失效 | 原文写明**即使点了横幅，规则仍然生效**——但这条只对被 macOS 侧接口覆盖的邮件成立 | `A/mailkit_mecontentblocker.txt:20`；脚本一 E08 |
| M08 | `AccountMail` 与 `AccountSettings` 的作用域和合并方式相同 | 前者「**分别应用**」，系统域 iOS／visionOS、用户域 macOS／Shared iPad；后者「**合并成一份生效配置**」，且只在 macOS 27.2 | `A/device_management_accountmail.txt:33—38`；`A/device_management_accountsettings.txt:15—28`；`C/platform-21.txt:24` |
| M09 | 收件端与发件端字段一样多，发件端也有协议与 TLS | 收件端 9 个字段，发件端只有 6 个；**发件端没有 `server_type`、没有 `path_prefix`、没有 `tls`** | `A/device_management_accountmail_incoming.txt:9—26`；`A/device_management_accountmail_outgoing.txt:9—20`；脚本一 B09／B10 |
| M10 | S/MIME 对象在 Mac 上也能由 `AccountMail` 声明 | 该对象标注 `iOS 17+ \| iPadOS 17+ \| visionOS 1.1+`，平台矩阵**没有 macOS 行** | `A/device_management_accountmail.txt:14`；`C/platform-21.txt:21—24`；脚本二 Y02 |
| M11 | 管理面能关掉远端内容加载 | 210 个纯键名里 4 个 Mail 键，**没有一个是「远端内容」**；`allowMailPrivacyProtection` 还要监督 | `C/readings-21.txt:118—124`；`A/mdm-restrictions-payload-M.txt:112`；脚本一 F01／F03 |
| M12 | `MFMailComposeViewController` 负责把邮件发出去 | 原文写明它**不保证投递**，消息进入 Mail 发件箱，**最终由 Mail app 负责发送** | `A/messageui_mfmailcomposeviewcontroller.txt:13`；脚本一 G05 |

十二条按主题压成四组。

**第一组 M01—M02：词表给的是标签，不是类型。** 15 行、45 行都是真数字，但一个数的是组件名，一个数的是攻击者位置；真正回答「远端内容加载」的 `remote content` 是 0 行。**禁令：公告侧的每个计数必须写明它数的是哪一列、哪个词形；只给数字不给列名的结论，一律退回。**

**第二组 M03—M05：MPP 的三处「想当然」。** 两个开关不联动、两段中继不同实体、后台下载不看交互——三条都写在同两页原文里，且都能被一句误读反过来。**禁令：凡涉及 MPP，先引第 30—33 行原文，再写结论；不引原文就不写「因此」。**

**第三组 M06—M07：拦截接口的平台错位。** 接口本身、以及「点横幅后仍生效」这句话都成立，但主语是 macOS 12+ 的 MailKit 扩展。把它套到 iOS 上，就从「没有公开接口」变成了「有接口但被绕过」。**禁令：iOS 的远端内容归属格只能写 `unknown`；写 `absent` 需要先证明「这一层在 iOS 上不存在」，而公开文档只能证明「读不到」。**

**第四组 M08—M12：每句话都有自己的主语。** 合并方式的主语是声明类型，作用域的主语是注册方式，S/MIME 的主语是声明对象与平台，管理面键的主语是「设备上的开关」，发送责任的主语是 Mail app。五处误读的共同点都是**把一句话的主语换掉**。**禁令：台账每一行都要能回答「这句话的主语是谁」；答不上来的行不进台账。**

---

## 25. 常见问题

**问：这套台账与两支脚本必须跑在设备上吗？**
不。两支脚本都是纯文本、离线、只读：脚本一（`.p21/script1.sh`，226 行）收一份或多份三列台账，脚本二（`.p21/script2.sh`，222 行）固定收三份文本——主张台账、平台矩阵、公告语料。第 23.3 节的 P1—P10 专门回答这个问题：P1 在 awk 程序体里对 `system(`／`getline`／`popen`／`ENVIRON` 的匹配是 0；P2 两支都通过 `bash -n`；P3 临时目录前缀分别是 `mail21.` 与 `mrcd21.`；P4b 的「命令位置」探测是 0；P6 在非注释行里对网络工具的整词计数是 0；P7 的重定向只到 `>&2` 与 `/dev/stderr`；P9 运行前后输入摘要未变；P10 把 `TMPDIR` 指到空目录跑完，事后条目数为 0；P19 脚本自身摘要未变。**这十段证明的是「没有读别处的口子」，不是「读到的内容与真实设备一致」**——第 23.6 节把这条不对称写成验收的第一条边界。

**问：两支脚本先跑哪一支？为什么不合并成一个分数？**
先脚本一。它逐条检查九个命名空间里该填的格填没填、填的形态合不合规，输出 J1—J4，回答「这一条登记能不能用」；脚本二吃的是另一形状，输出 Q1—Q4，回答「一个主体的三件还能不能立起来」。两者的分母不同：J 的分母是一条记录，Q 的分母是一个主体的三件。干净夹具上的两个「最好值」也不是同一件事——脚本一读 `账户记录数= 2`、`判定分布= V1=2`，说的是两条登记各自自洽；脚本二读 `主张主体数= 1`、`闭合等级分布= W1=1`，说的是一个主体的三件对得完。**绝不合并成单一分数**：脚本二的 `W1` 可以与 X 族信号同现（R22、R33），脚本一的 `V3` 也可以与 `Q1` 同现——一个合并分会把「信号多」与「三件齐」压成同一个数，而这正是第 19.3 节禁止的加法。

**问：101 个码全部至少触发一次，是不是说明判据判得对？**
不，它只说明每条判据都还活着。101 是两支脚本的全部格子：脚本一 54 个信号码加 V1—V4 共 58，脚本二 39 个信号码加 W1—W4 共 43。覆盖的分布也不一样：脚本一靠 R02、R05、R19 三次「全违例」打满大部分码，脚本二靠 R21、R34 两次「全缺」打满 X／Y／Z 三族；`A05`、`C08`、`X12` 这类单码路径则各由一次定向子集钉住（R13、R08、R23）。判据**对不对**，靠的是第 21.3、22.3 两节逐族给出的判据行号与出处行号，读者要拿归档自己核；覆盖验收不代替这一步。

**问：夹具能不能换成真实台账或真实邮件？**
不能，换进来的那一刻这套验收就失效了。脚本一的拒收执行点是 `A05`（第 90 行）：取值形似私钥块、形似口令、超过 120 字符或整段正文时，该字段直接拒收，不进入台账；P16 用一段 150 字符的 `A` 载荷验证了这条路径，输出 `A05` 与 `阻断信号条数= 1`。脚本二那一侧对应 `Z00`／`Y09`：主张行或平台行取值形似路径／凭据／长载荷时，整行拒收；P17 用一行 `/Users/x/secret` 演示，输出 `Y09`。**两支都只能保证「登记里没有形似设备路径与凭据的取值」，保证不了「登记与某台设备一致」。** 真实台账进来后第一件要做的事是洗数据，洗完的留档也不能再随文发布——`matrix-out.txt` 与第 23.3 节全量输出的价值，恰恰在于第三方能在无设备、无私有数据的条件下原样重跑。

**问：为什么 iOS 的远端内容加载归属要记 `unknown`，而不是 `absent`？**
因为公开文档证明的是「读不到这个事件、也没有公开的拦截接口」，不是「iOS 上不存在这层机制」。iOS 上有 MPP 与 Hide IP 两个用户可见开关（`B/mail-privacy-protection-legal.txt:32—33`），所以「这一层不存在」是假的；但没有公开的「某封邮件的远端内容被谁加载、在什么策略下加载」读数，也没有 iOS 侧的内容拦截协议——`MEContentBlocker` 只有 macOS 12+ 一行（`C/platform-21.txt:26`）。三条合起来只能推出 `unknown`。**`absent` 是一个更强的断言，它需要一份「适用于 iOS 的拦截接口不存在」的公开否认；本归档没有这句话。**

**问：退出码 2 是什么？能不能拿它当门禁？**
`2` 只判「输入坏了」：参数个数不对、文件不可读或未知选项。脚本一的校验在第 46—53 行，脚本二在第 37—43 行；`-h`／`--help` 给 0，其余按判定给 0 或 1。34 次实跑的分布是退出 0 九次、1 十九次、2 六次：三种出口都被走到，说明三条路径被区分开。**不要把 2 读成「发现问题」**：它排在任何判定之前，一批真台账跑出 2 时唯一该做的是先修参数与文件可达性，101 个码一个都没被看过。**也不要把 0 读成「没问题」**：干净夹具的 0 只说明「在这个输入上没有信号」，不说明设备安全。

**问：W1 是不是验收通过？**
不是。W1 只表示三件齐：装配件有收件 host 与凭据、内容件六项齐、回查件三项齐、策略不是 unknown。它与 X 族信号正交——R22 与 R33 都是 `W1` 带 X 族信号：三件齐了，但公告语料里没有 `remote content` 以外的词形。**「齐」不等于「对」**，这是第 22.8 节取舍二写死的。反过来，R21 的 `W4=1` 也不等于「设备有问题」，它只表示主张台账里没有 `account` 方面，归属不可判。

**问：公告 36 行、7 个 CVE，能不能说「邮件链路有 36 个缺陷」？**
不能。36 是三族行数的合计：`Mail` 15 行／3 CVE、`Accounts` 15 行／3 CVE、`Messages` 6 行／1 CVE（`C/readings-21.txt:3`），同一 CVE 会跨平台重复出现，所以行数大于 CVE 数。七个 CVE 的影响句里，只有 `112500` 直接提到邮件地址泄漏（Hide My Email），其余六个是 DoS、隐私偏好绕过、信任配对设备读写、敏感数据访问与应用终止（`:10—16`）。**行数、CVE 数、缺陷类型数是三个分母**，任何一个单独出现都不足以支撑「邮件链路缺陷有多少」的结论。

**问：十一层、九个命名空间、49 个字段、三件、十个运营指标、101 个码，这些数字对得上吗？**
各自管一件事，不能互换。十一层（L1—L11）是叙述用的归属分解；脚本一的九个命名空间是台账的主语空间，二者**不是一一对应**：L1—L3（装配、作用域、凭据）用 `id`、`mgmt`、`in`／`out`、`smime`，L4—L5（收发、S/MIME）用 `in`、`out`、`smime`，L6—L7（内容加载、内容拦截）用 `policy`，L8（组合发送）用 `claim` 与 `id`，L9（管理面）用 `mgmt` 与 `priv`，L10（公告）用 `doc`，L11（引用）用 `doc`。九个空间共 49 个字段（id 4、in 9、out 6、smime 7、mgmt 7、priv 2、policy 8、claim 3、doc 3），其中必备字段见第 21.2 节。三件（装配／内容／回查）是脚本二的主语切法；101 是两支脚本的码总数（58＋43），与第 21.4、22.4 两节逐族给出的数量相等。**最容易串的是 `M` 与 `W`**：第 24 章的 `M01—M12` 是误区编号，脚本二的 `W1—W4` 是闭合等级。

**问：我改了某条判据，怎么知道有没有改坏？看总信号数吗？**
不看总数，看 `matrix-out.txt` 里哪一段该变色、它确实变色了。单码子集就是为此存在的：R13 只该出 `A05`，R08 只该出 `C08`，R23 只该出 `X12`；改 `C08` 的判据却让 R04 多出别的码，说明改动越过了族界。改完按三步重跑：`bash matrix.sh` 重生成 `matrix-out.txt`，`bash proof.sh 报告.md` 重跑 P1—P20 并看 P18 三行是否仍为「一致」，最后数一遍 `58/58` 与 `43/43` 是否仍在。**这三步都不接触设备**，第三步还会顺带核对两支脚本自身在运行前后没有被改写（P19）。

---

## 26. 未公开文档化边界清单

本章列十四条边界。收条标准三条，缺一条就不收：

- **（a）有一句公开原文**——给出归档文件与行号，能读出「这里有一层」或「这里什么都没有」；
- **（b）有一个落点**——脚本码、必填读数或可复跑的读数行，能把这条边界写进台账；
- **（c）有一句「不能由此推出什么」**——而且这句能指回（a）的原文，不是修辞。

编号用 U01—U14，不补位、不隔号。**U 不是脚本族**：脚本一的信号族是 A／B／C／D／E／F／G 加 V1—V4，脚本二的是 X／Y／Z 加 W1—W4；U 只在本章使用。

| 号 | 边界一句话 | 公开锚点 | 落点 |
| --- | --- | --- | --- |
| U01 | iOS 没有公开的内容拦截接口，归属格只能写 `unknown` | `A/mailkit_mecontentblocker.txt:3、20`；`C/platform-21.txt:26` | `policy.blocker_platform`；F01／F03；脚本二 Y04／Z13 |
| U02 | MPP 与 Hide IP 是两个开关，关闭前者不关闭后者 | `B/mail-privacy-protection-legal.txt:32—33` | `policy.mpp`／`policy.hide_ip`；E04／E05 |
| U03 | 平台矩阵只有文档、平台、版本三列，没有作用域列 | `C/platform-21.txt`；`A/device_management_accountmail.txt:33—36` | Y01 只查「有没有 iOS 行」；`id.platform` |
| U04 | 发件端的 `None` 规则在文档里存在，但没有独立信号码 | `A/device_management_accountmail_outgoing.txt:11—13、37` | B07／B08 只读 `in.*` |
| U05 | 凭据「首次解锁后可读」与声明里的「资产引用」之间没有换算字段 | `B/apple-platform-security-guide.txt:2155—2156`；`A/device_management_accountmail_incoming.txt:9—13` | `in.cred_asset`／`in.cred_asset_type`；无专用码 |
| U06 | 端口与 STARTTLS 的四条对应关系是本文台账约定，不是文档原文 | `A/device_management_accountmail_incoming.txt:23—26` | C02／C03；第 7.3 节 |
| U07 | `AccountSettings` 合并生效且只在 macOS 27.2，与 `AccountMail` 不可互推 | `A/device_management_accountsettings.txt:15—28`；`C/platform-21.txt:24` | 脚本二 Y06；`policy` 无对应字段 |
| U08 | S/MIME 的平台错位：声明对象 iOS 17+，MailKit 安全处理器 macOS 12+ | `A/device_management_accountmail_smime.txt:9—12`；`A/mailkit_memessagesecurityhandler.txt:16` | `smime.*`；脚本二 Y02 |
| U09 | 公告词表无法定位「远端内容加载」：15 个词形零命中 | `C/readings-21.txt:17—36` | 脚本二 X02—X10 |
| U10 | 管理面 4 个 Mail 键都不是「远端内容」读数，其中一个还要监督 | `C/readings-21.txt:118—124`；`A/mdm-restrictions-payload-M.txt:112` | `mgmt.*`；F01／F03 |
| U11 | 隐私清单的邮件类型只到「内容」，不含 IP、时间与加载事件 | `A/nsprivacycollecteddatatype.txt:20` | `priv.data_type`；F06 |
| U12 | 构造消息的控制器不保证投递，发送责任在 Mail app | `A/messageui_mfmailcomposeviewcontroller.txt:13` | `claim.closure`；G05 |
| U13 | 「remote attacker」是攻击者位置，不是内容路径 | `C/readings-21.txt:21—22` | X02；第 13.3 节 |
| U14 | `allowCloudMail` 是 iCloud Mail 服务开关，不是账户装配开关 | `A/mdm-restrictions-payload-M.txt:57` | `mgmt.source`；F05 |

### 26.1 十四条边界逐条

**U01 iOS 没有公开的内容拦截接口。**
`MEContentBlocker` 的原文是 `An object that provides a set of rules to block content when displaying a message`，平台矩阵只有 `mailkit_mecontentblocker,macOS,12.0` 一行（`C/platform-21.txt:26`）。16 份文档按平台归类是「两者都有 4、只有 iOS 5、只有 macOS 7、两者都无 0」（`C/readings-21.txt:117`），7 份 macOS-only 里 6 份是 MailKit。所以 iOS 这一格的状态是「读不到」，不是「不存在」。台账把 `policy.blocker_platform` 写成 `none-public`，而不是 `none`，`policy.remote_content_policy` 随之为 `unknown`。脚本二 Y04 检查「拦截件文档必须有 macOS 行」，Z13 检查「宣称有拦截件但平台矩阵里没有拦截件文档」——两条都只证明坐标，不证明 iOS 上能不能拦。

**U02 MPP 与 Hide IP 不联动。**
原文两句相邻：`If you choose to disable Protect Mail Activity, the Hide IP Address feature will still mask your IP address using the same two-separate-internet-relays design`（`B/mail-privacy-protection-legal.txt:33`）；以及前一段的 `Protect Mail Activity downloads remote content in the background by default — regardless of whether you engage with the email`（`:30`）。也就是说，「后台下载」与「IP 遮蔽」是两个可独立关闭的开关。台账因此必须有 `policy.mpp` 与 `policy.hide_ip` 两列，脚本一 E04（开了 MPP 但 `hide_ip=no` 且依据为空）与 E05（关 MPP 却声称 IP 不再遮蔽）就是为这条边界写的。不能由此推出：关掉 MPP 就等于发件人拿到了真实 IP——原文只说 Hide IP 仍在。

**U03 平台矩阵没有作用域列。**
`C/platform-21.txt` 的每一行只有 `<文档>,<平台>,<引入版本>` 三个字段；而 `AccountMail` 的系统域是 `iOS, visionOS`、用户域是 `macOS, Shared iPad`（`A/device_management_accountmail.txt:33—36`）。脚本二 Y01 只能查「账号声明有没有 iOS 行」，不能查「iOS 行落在哪个作用域」。这是**公开坐标本身的缺列**，不是脚本漏判；要补这一格，需要另一份按注册方式拆开的矩阵，本归档没有。不能由此推出：iOS 出现在平台列就说明设备注册与用户注册都能用——原文的六个注册块给出的答案并不相同。

**U04 发件端的 `None` 规则没有独立码。**
发件端文档与收件端一样写着：`If the AuthenticationMethod is None, this field must be blank. Otherwise, the declaration must contain this field`（`A/device_management_accountmail_outgoing.txt:11—13`），CODE 行也有 `None`（`:37`）。但脚本一的 B07／B08 只读 `in.auth` 与 `in.cred_asset`，发件端 `out.auth=None` 与 `out.cred_asset` 的矛盾目前不产生信号。这是判据覆盖面的一处已知缺口（第 21.9 节第 1 条），补码需要新的定向夹具，本文不补一个没有实跑覆盖的码。

**U05 凭据可读时点与资产引用之间没有换算。**
钥匙串分类表把 `Mail accounts` 放在 `Accessible After first unlock` 一档（`B/apple-platform-security-guide.txt:2155—2156`），这是「首次解锁之后可读」；声明侧只给一个资产标识与资产类型（`A/device_management_accountmail_incoming.txt:9—13`）。两者回答两个问题：「引用哪个资产」与「这个资产何时可读」。台账登记前者（`in.cred_asset`／`in.cred_asset_type`），不登记后者；也不能用「首次解锁后可读」反推「这台设备已解锁」。不能由此推出：已解锁设备上的凭据一定可被任意进程读取——钥匙串还有访问控制列表。

**U06 端口判据是本文约定。**
收件端文档只把端口写成 `integer`（`A/device_management_accountmail_incoming.txt:23—24`），没有写「25 必须 STARTTLS」「993 必须 TLS」这类约束。本文台账里的四条端口规则（第 7.3 节）是**核验约定**，锚点是端口字段，不是文档原文。脚本一 C02／C03 命中时，写的是「台账约定不允许」，不是「Apple 不允许」。不能由此推出：某个端口组合在协议上不可行——文档只声明类型，不声明组合。

**U07 `AccountSettings` 与 `AccountMail` 的合并语义不同。**
前者 `Multiple configurations are combined and applied as a single effective configuration`（`A/device_management_accountsettings.txt:28`），且四个可用性块全部只写 `macOS` 或 `N/A`（`:15—26`），平台矩阵只有 `accountsettings,macOS,27.2` 一行（`C/platform-21.txt:24`）；后者 `Multiple configurations are applied separately`（`A/device_management_accountmail.txt:38`）。合并与分别应用不是同一件事：合并时后一份可以覆盖前一份的同一字段，分别应用时两份各自成立。脚本二 Y06 检查 `AccountSettings` 不得出现 iOS 行；对合并语义本身没有码，因为它不属于字段级矛盾。

**U08 S/MIME 的平台错位。**
`AccountMailSMIMEObject` 标注 `Available: iOS 17+ | iPadOS 17+ | visionOS 1.1+`（`A/device_management_accountmail.txt:14`），平台矩阵没有 macOS 行（`C/platform-21.txt:21—24`）；而 MailKit 的 `MEMessageSecurityHandler` 是 macOS 12+ 的扩展接口，原文写 `Mail passes incoming and outgoing message content to the extension for encryption and digital signing`（`A/mailkit_memessagesecurityhandler.txt:16`）。声明侧与扩展侧是两个平台上的两种机制，不能互相证明。脚本二 Y02 检查「S/MIME 对象必须有 iOS 17 行」，Y03 检查「MailKit 文档不得出现 iOS 行」。

**U09 公告词表无法定位远端内容加载。**
影响句 20 个词形里，`remote content`、`tracking`、`sender`、`load`、`relay`、`ip address`、`hide ip` 全部是 0 行（`C/readings-21.txt:20、23—26、36`），`remote` 的 45 行全部是 `remote attacker`（`:21—22`）。这不是「公告里没有这类缺陷」，而是「公告的影响句不使用这些词形」。脚本二 X02—X10 把九种零命中写成信号，X11／X12 检查组件列与影响句的行数关系；它们证明的是语料覆盖缺口，不是漏洞有无。

**U10 管理面四个 Mail 键都不是「远端内容」读数。**
210 个纯键名里含 `mail` 的 4 个：`allowCloudMail`（macOS 10.12+）、`allowMailPrivacyProtection`（iOS 15.2+／iPadOS 15.2+，需监督）、`allowMailSmartReplies`（iOS 18.4+ 等，26.4+ 弃用）、`allowMailSummary`（iOS 18.1+ 等，26.4+ 弃用）（`A/mdm-restrictions-payload-M.txt:57、112—114`）。四个键分别管 iCloud Mail 服务、MPP、智能回复与摘要，没有一个读回「这封邮件的远端内容是否加载」。脚本一 F01 在 `policy.remote_content_policy=unknown` 时阻断，F03 检查「声称有管理面读数但键名不在四键内」。

**U11 隐私清单只到「邮件内容」。**
35 个隐私数据类型里，与邮件相关的是 `NSPrivacyCollectedDataTypeEmailsOrTextMessages: Emails or text messages; including subject line, sender, recipients, and contents of the email or message`（`A/nsprivacycollecteddatatype.txt:20`）。描述列出主题、发件人、收件人与内容，**没有 IP 地址、打开时间、加载事件**。台账 `priv.data_type` 只能是这一个值，脚本一 F06 检查「声明的隐私类型与台账值不一致」。不能由此推出：申报了这一类型就覆盖了远端内容加载产生的元数据。

**U12 发送责任在 Mail app。**
`The composition interface doesn’t guarantee the delivery of your email message; it only lets you construct the initial message and present it for user approval... If the person opts to send the message, the message queues in the user’s Mail app outbox. The Mail app is ultimately responsible for sending the message`（`A/messageui_mfmailcomposeviewcontroller.txt:13`）。所以「调用控制器」不等于「已发送」，也不等于「走了哪个账户的发件服务端」。脚本一 G05 检查结论为闭合但缺少发送面引用。不能由此推出：第三方 app 能指定发件账户或绕过 Mail 的发件队列。

**U13 「remote attacker」不是内容路径。**
影响句里 `remote` 45 行、`remote attacker` 45 行，两个数相等（`C/readings-21.txt:21—22`）——`remote` 的每一次出现都包在 `remote attacker` 里。它描述攻击者位置，不描述远端内容。脚本二 X02 只认 `remote content` 这个双词串；`remote` 单独出现不算命中。不能由此推出：45 个 CVE 与邮件远端内容加载有关——七个邮件族 CVE 的影响句里没有一句提到内容加载（`:10—16`）。

**U14 `allowCloudMail` 不是账户装配开关。**
原文 `If false, the system disables iCloud Mail services`（`A/mdm-restrictions-payload-M.txt:57`）。它管的是 iCloud Mail 这项服务，不是 `AccountMail` 声明的装配，也不管第三方 IMAP／SMTP 账户。台账 `mgmt.source` 只能写「该键是否出现在管理面」，不能写「该键决定了账户存在与否」。脚本一 F05 检查「管理面来源与声明类型不匹配」。不能由此推出：关掉这个键就删除了设备上的邮件账户。

### 26.2 三份输入件怎么承载这十四条

| 边界 | 台账（脚本一） | 平台矩阵（脚本二） | 公告语料（脚本二） |
| --- | --- | --- | --- |
| U01 | `policy.blocker_platform=none-public`、`policy.remote_content_policy=unknown` | 无 iOS 拦截件行 → Y04 | 无对应列 |
| U02 | `policy.mpp` 与 `policy.hide_ip` 两列 + `hide_ip_basis` | — | — |
| U03 | `id.platform` | 只有三列，Y01 只能查 iOS 行存在 | — |
| U04 | `out.auth`／`out.cred_asset`（无码） | — | — |
| U05 | `in.cred_asset`／`in.cred_asset_type` | — | — |
| U06 | `in.port`／`in.tls`、`out.port`／`out.tls` | — | — |
| U07 | 无对应字段 | Y06（AccountSettings 不得有 iOS） | — |
| U08 | `smime.*` | Y02／Y03 | — |
| U09 | — | — | X02—X12 |
| U10 | `mgmt.*` | — | — |
| U11 | `priv.data_type` | — | — |
| U12 | `claim.closure`、`doc.*` | — | — |
| U13 | — | — | X02 只认双词串 |
| U14 | `mgmt.source` | — | — |

### 26.3 两条固定自查项

**自查一：每写一个「没有」，先问「哪一层没有」。** 「公告里没有 remote content」是语料层；「iOS 没有拦截接口」是接口层；「管理面没有加载读数」是管理面层；「台账没有凭据时点」是登记层。四层各自可以真，但不能互相替代。第 23.6 节第 1 条与第 24 章第三组说的是同一件事。

**自查二：每个数字成对报。** 15 行要带 3 个 CVE；45 行要说明是 `remote attacker`；36 行要拆成 15／15／6；4 个 Mail 键要带 210 的分母；101 个码要拆成 58／43。只报一个数字的结论，按第 24 章 M01 退回。

### 26.4 用法与改法

1. 新增一条边界时，先写（a）原文与行号，再写（b）落点，最后写（c）不能推出什么；三者缺一，不进本章。
2. 边界不编号补位：删掉一条就留空号并在文中说明，不让 U 号随章节顺序漂移。
3. 改判据时，先看这条边界有没有落点码；没有落点的边界（U04、U07、U12 的一部分）只能靠人工核，不能靠覆盖率验收。
4. 归档更新后，先重跑 `matrix.sh` 与 `proof.sh`，再看本章的锚点行号是否仍然成立；行号漂移属于归档变更，不属于判据变更。

---

## 27. 结论

### 27.1 立场：能说什么，不能说什么，该记成什么

**能说的三句话。** 第一，iOS 邮件账户的装配、远端内容加载与回查是三套口径：声明侧给对象与字段，隐私侧给两项用户开关的行为描述，管理面与公告侧给键名与标签；三者之间没有一份公开文档把它们逐项对上。第二，唯一公开的内容拦截接口 `MEContentBlocker` 只在 macOS 12+，iOS 侧的公开坐标是空的；因此 iOS 的远端内容归属格只能记 `unknown`。第三，34 次实跑覆盖了 101 个码，两支脚本离线、只读、可复跑，读者可以不用设备复核本文的每一个计数。

**不能说的三句话。** 不能说「iOS 邮件不加载远端内容」——MPP 的存在恰好证明它会加载，只是走了中继；不能说「关掉 MPP 就暴露真实 IP」——原文写明 Hide IP 仍在；不能说「公告里 0 行就等于没有这类缺陷」——0 行只说明词形未覆盖。

**该记成什么。** 台账里凡是主语不清的格子，记 `unknown`；凡是只有单侧读数的格子，记 `partial`；凡是三件齐且策略有公开依据的格子，才记 `closed`。这三个词不是安全评级，是**证据状态的标签**。

### 27.2 方法论：四步

1. **先分词表。** 接口装配、平台安全、管理面与公告是三套词表；先把每个词属于哪套写清楚，再谈换算（第 3 章）。
2. **再分主语。** 一条记录的主语是「一个账户声明」，一个主体的主语是「三件」，一条公告的主语是「一个组件行」。主语不同的数字不相加（第 15、19 章）。
3. **然后判未知。** 策略读不到时先落 `unknown`，不让其他字段的齐全把它稀释（第 10.4、19.1 节）。
4. **最后才谈闭合。** 闭合是三件齐，不是安全性；W1 可以与信号同现，J1 也可以与 Q3 同现（第 19.3、22.8 节）。

### 27.3 三条建议

**给做台账的人：** 每个字段都要能指回一行原文或一条读数；指不回去的字段，宁可留空并写 `unknown`，不要用推断填满。特别是 `policy.remote_content_policy`，它是整条记录的先决格。

**给做审计的人：** 先跑脚本一再跑脚本二，两个结果分开放；不要把 J 档与 Q 级合成一个分数，也不要把「0 信号」当成审计通过。看 34 行矩阵里哪一行与你的输入同形，再决定信哪一段。

**给读公告的人：** 组件名、影响句、平台列是三个分母；行数与 CVE 数是两个分母。任何「邮件类缺陷有多少」的结论，至少要有组件行数、CVE 数与影响句词形三组读数同时在场。

---

## 28. 参考资料

### 28.1 归档总览

本轮归档在 `.srcx21/`，分四组：

| 组 | 内容 | 规模 |
| --- | --- | --- |
| `A/` | Apple Developer 文档 18 份（8 个 Account 声明、6 份 MailKit、4 份 MessageUI） | 18 文件／2,294 行 |
| `B/` | 平台安全指南、MPP 法律页、管理面限制键与限制载荷 | 4 文件／6,741 行 |
| `C/` | 读数台账（`readings-21.txt` 130 行）、平台矩阵（47 行）、公告语料（1,266 行 + 表头） | 3 文件／177 行 + 1,267 行 |
| `fx/` | 12 份合成夹具 | 331 行 |

`C/advisory-21.tsv` 共 1,267 行（含表头），六列 `file`／`platform`／`component`／`cve`／`impact`／`avail`；去重后是 1,266 条记录、12 个平台、129 个组件名、330 个唯一 CVE（`C/readings-21.txt:1`）。`C/readings-21.txt` 的 G1—G12 是正文全部计数的唯一来源。

### 28.2 关键文件与锚点

| 文件 | 本文用到的锚点 | 支撑哪一章 |
| --- | --- | --- |
| `A/device_management_accountmail.txt` | `:3`（对象定义）、`:14`（S/MIME 平台）、`:24—38`（六种注册、两个作用域、分别应用）、`:120`（CODE） | 第 4、5、24 章 |
| `A/device_management_accountmail_incoming.txt` | `:9—13`（凭据与 None 规则）、`:19—26`（路径前缀、端口、协议）、`:41—45`（CODE） | 第 6、7 章 |
| `A/device_management_accountmail_outgoing.txt` | `:9—20`（四个字段）、`:35—37`（CODE 含 None） | 第 7 章、U04 |
| `A/device_management_accountmail_smime.txt` | `:9—12`（加密与签名两个子对象） | 第 8 章 |
| `A/device_management_accountexchange.txt` | `:9`（凭据资产）、`:78—80`（S/MIME 仅 EAS） | 第 6、8 章 |
| `A/device_management_accountsettings.txt` | `:15—28`（四个可用性块、合并生效） | 第 5 章、U07 |
| `A/mailkit_mecontentblocker.txt` | `:3`（定义）、`:20`（点横幅后仍生效） | 第 10 章、U01 |
| `A/mailkit_memessagesecurityhandler.txt` | `:16`（内容交给扩展）、`:29`（重复解码） | 第 8、11 章 |
| `A/messageui_mfmailcomposeviewcontroller.txt` | `:13`（不保证投递、Mail app 负责发送） | 第 11 章、U12 |
| `B/mail-privacy-protection-legal.txt` | `:29—33`（远端内容、后台下载、两段中继、Hide IP） | 第 9 章、U02 |
| `B/mdm-restrictions-payload-M.txt` | `:57`（allowCloudMail）、`:60`（allowCloudPrivateRelay）、`:112—114`（三个 Mail 键） | 第 12 章、U10、U14 |
| `B/apple-platform-security-guide.txt` | `:1668`（Watch 直连）、`:2155—2156`（钥匙串分类）、`:2304—2307`（S/MIME）、`:2411`（邮件数据库加密） | 第 6、8、11 章 |
| `A/nsprivacycollecteddatatype.txt` | `:20`（EmailsOrTextMessages） | 第 12 章、U11 |
| `C/readings-21.txt` | G1—G12，正文所有计数 | 第 13、16、20 章 |
| `C/platform-21.txt` | 47 行平台坐标 | 第 14、24 章 |
| `C/advisory-21.tsv` | 1,266 行公告 | 第 13、20 章 |

### 28.3 九条归档约定

1. **只收官方四类**：Apple Developer 文档 JSON、Apple Platform Security 指南文本、Apple 法律页、Apple 安全发布页；不引第三方博客、CVE 描述页或研究机构报告。
2. **每份文件保留原始行号**：正文的 `:n` 一律指归档文件行号，不指网页行号；引用英文原文时，归档里的行内代码体标记（如 `false`）按普通文字转写，其余字符逐字保留。
3. **读数单独成表**：所有计数先进 `C/readings-21.txt`（G1—G12），正文再引用；不在正文里现算。
4. **平台坐标单独成表**：16 份文档的 47 行坐标放 `C/platform-21.txt`，平台名与版本号逐行可核。
5. **公告单独成表**：1,266 行放 `C/advisory-21.tsv`，六列顺序固定，不合并单元格。
6. **夹具与源码分离**：`fx/` 只放合成输入，`.p21/` 只放脚本与证明；夹具不参与任何发布。
7. **脚本内嵌报告**：报告第 21.7、22.7 节的代码块与 `.p21/` 下的实跑文件逐字节一致，由 P18 检查。
8. **证明脚本读报告本身**：P18 从报告里抽三段源码比对，证明发布件与验收件同源。
9. **不写设备路径与凭据**：所有示例值都是构造值；脚本 A05／Y09 主动拒收形似路径与凭据的取值。

### 28.4 本篇没有做的事

- **没有在真实设备或真实邮箱上验证任何一条读数**：全部计数来自归档文本与合成夹具。
- **没有把 `unknown` 写成 `absent`**：iOS 的远端内容归属格保持 `unknown`，理由写在 U01 与第 10.4 节。
- **没有跨平台相加**：Mail 15 行、Accounts 15 行、Messages 6 行是三族行数，不与 iOS 单独行的计数混算。
- **没有推断 MPP 的中继实现**：原文只说「两个不同实体」，本文不补运营商、协议或部署位置。
- **没有补发件端 `None` 规则的码**：U04 只说缺口，不用一个没有夹具的码填上。
- **没有重建相邻篇目的客体**：屏幕画面外流归第 19 篇、卷与文件系统形态归第 20 篇、外接配件与近场配对归第 22 篇、平台校验组件与度量物归第 23 篇。

### 28.5 同系列相邻篇目

本篇与已发布的第 18—20 篇、队列中的第 22—23 篇有交接，也有硬分界。**第 18 篇（非可信内容解析链路）**——内容被判成什么类型、由哪个域解析归它；本篇只处理「邮件正文里的远端内容在什么策略下被加载」，不重复解析链与类型判定。**第 19 篇（屏幕画面外流链路）**——画面采集、录制与镜像的落点归它；本篇的「中继」是邮件内容下载路径，不涉及任何画面数据。**第 20 篇（卷挂载与文件系统形态）**——卷形态、挂载选项与文件系统加密归它；本篇只在第 11.4 节引用「邮件数据库随文件保护加密」这一句，不讨论卷或 keybag。**第 22 篇（外接配件与近场配对链路归属，本队列后续篇目）**——配件的近场配对与信任建立归它；本篇只在 S/MIME 智能卡一句上涉及外设证书，配对与认证不在本篇范围。**第 23 篇（平台校验组件与度量物归属，本队列后续篇目）**——平台校验组件、度量物与本地策略归它；本篇的公告读数只到「组件名与影响句」，不建立度量物归属体系。

---

咨询ios系统请咨询 telegram：https://t.me/one00190
