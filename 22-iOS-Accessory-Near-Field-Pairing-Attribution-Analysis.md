---
title: "iOS 外接配件与近场配对链路归属防御分析报告"
description: "iOS 上一个外接配件是怎样被发现的、谁同意了它接入、谁证明了它是它、这条链路在哪一段读得回来：十一层归属分解（L1 发现描述符、L2 同意、L3 身份验证、L4 ExternalAccessory 协议声明、L5 BLE/BR-EDR 传输、L6 UWB 近场、L7 NFC、L8 USB 与有线限制、L9 管理面回查、L10 公告对齐、L11 引用与结论），三件（发现件／链路件／回查件）× 11 层 × 20 项核对项的差集口径，接口装配词表／平台安全口径词表／管理面与公告回查词表与八处换算失败，J1—J4 与 Q1—Q4 两套判定模型，两个离线只读核验脚本（58 + 43 个码，共 101 个全部实跑触发，34 次实跑逐码覆盖表）"
lang: zh-CN
---

# iOS 外接配件与近场配对链路归属防御分析报告

## 摘要

本报告集前二十一篇依次回答过这些归属问题：缺陷在哪（第 01、06、07、12 篇的攻击面归属）、谁能进入这道门（第 02 篇的访问控制归属）、这条链路看见了什么（第 03、04 篇）、这台设备归谁（第 08、10、11 篇的主体归属）、这段代码凭什么被允许运行（第 14 篇的授权链归属）、这条通道凭什么存在（第 15 篇的通道归属）、同网段上谁看得见谁（第 16 篇的局域网可达性归属）、一条内容进了检索面之后谁能查回来（第 17 篇的检索面归属）、一份从别处来的内容被判成了什么类型（第 18 篇的类型判定归属）、一帧画面有没有离开这台设备（第 19 篇的画面外流归属）、一个卷是什么形态又由谁挂上来（第 20 篇的卷与挂载归属）、一个邮件账户是谁以什么声明装配出来的（第 21 篇的账户装配归属）。本文回答系列里的第十二类：**一个外接配件是怎样被发现的、谁同意了它接入、谁证明了它是它、这条链路在哪一段读得回来。**

这句话拆开是四个问句，判定权分属四方，四方互不通气。**配件是怎样被发现的**（AccessorySetupKit 的公开描述符只有三个属性——16 位公司标识（`A/accessorysetupkit_asdiscoverydescriptor.txt:71`）、蓝牙名称子串（`:91`）与服务 UUID（`:128`）——发现权在**类**这一级，不在**个体**这一级）；**谁同意了它接入**（面向用户的成文口径是 `Allow seamless, privacy-preserving user consent and control for Bluetooth, Wi-Fi, and Local Network permissions.`（`A/accessorysetupkit.txt:6`），而 `ASAccessorySession` 的说明是 `Discover, select, and set up a specific Bluetooth accessory without requesting permission to use Bluetooth.`（`A/accessorysetupkit_asaccessorysession.txt:249`）——同意权在系统弹窗，作用域仍是一个类）；**谁证明了它是它**（平台安全指南写得很直白：`This process is entirely handled by a custom integrated circuit (IC) that Apple provides to approved accessory manufacturers and is transparent to the accessory itself.`（`B/apple-platform-security-guide.txt:1367`）——身份验证权在一块链路之外的认证 IC 上，公开接口读不到它的判定结果）；**这条链路在哪一段读得回来**（管理面 210 个纯键名里配件族只有 5 个（`C/readings-22.txt:136`），公告语料 27 行配件族记录的影响句里 `accessory`、`pairing`、`MFi`、`UWB`、`NFC` 全部是 0 行（`:54—63`）——回查权只剩能力开关与族级标签）。

本文的核心结论是这四段**两两都不闭合**，而且不闭合的位置与第 18、19、20、21 四篇都不同：18 篇的不闭合在「内容自带的声明」对「框架的判定」，19 篇的不闭合在「登记方对自己那条通道最没有读数」，20 篇的不闭合在「公开语料里没有形态维度」，21 篇的不闭合在「账户装配、内容加载、缺陷归属是三套词表」。本篇的不闭合更靠底层——**公开语料把「发现」「同意」「身份」「传输」写成了四套彼此不引用的词表，而唯一能回答「是不是这一个」的证据被放在一块公开接口看不见的认证 IC 里**。同一个 `Bluetooth` 词形，在公告组件名列命中 9 行、在影响句列命中 2 行（`C/readings-22.txt:24、35`）；`pairing` 在平台安全指南里有 53 行、在公告影响句里 0 行（`:159、27`）；`MFi` 在平台安全指南里有 6 行、在公告两列里 0 行（`:159、29`）。也就是说：按组件名列筛「配件类缺陷」会得到 27 行（AccessorySetupKit 2＋Bluetooth 9＋HomeKit 8＋Thread 3＋USB 5，`C/readings-22.txt:3`），按影响句筛「配对或身份」会得到 0 行，两个数之间没有任何换算关系。

比这更要紧的是一条**平台不对称**。十七份与本链路直接相关的公开文档里，iOS 与 macOS 都出现的有 7 份、只有 iOS 的 10 份、只有 macOS 的 0 份、两者都没有的 0 份、同一文档两平台版本差超过 5 的 5 份（`C/readings-22.txt:135`）。AccessorySetupKit 的五份文档**没有 macOS 行**，CoreNFC 的三份**没有 macOS 行**，NearbyInteraction 的三份里只有总览页有 macOS 行（`C/platform-22.txt:60—71`）；而 ExternalAccessory 的三份全部有 macOS 10.13 行（`:41—58`）。**「iOS 上配件是怎样被同意与验证的」这一格，没有任何一份 macOS 文档可以对照；「macOS 上配件是怎样被同意的」这一格，公开坐标是空的。** 本文据此把跨平台推断一律记为 `unknown`，而不是「相同」——这两件事的差别贯穿全文。

第三条必须前置的是**唯一一处把「不要蓝牙权限」与「仍然发现蓝牙配件」写在一起的公开口径**：`Discover, select, and set up a specific Bluetooth accessory without requesting permission to use Bluetooth.`（`A/accessorysetupkit_asaccessorysession.txt:249`）。这句话同时给出了两个事实：AccessorySetupKit 的会话可以绕过通用的蓝牙权限弹窗；但绕过的是**权限**，不是**同意**——系统仍然用一个配件选择器让用户选定一个具体配件。本文把「通用权限」与「配件级同意」做成两条独立读数（脚本一的 `consent.bluetooth_permission` 与 `consent.prompt`／`consent.scope`），不把其中一条当另一条的证据。

全文有十二组可数的公开读数（第 16 章，R01—R20，每组给归档行锚）、两套四档判定模型（第 19 章）、十一层归属分解（第 4—14 章）、一个十一层 × 责任方 × 三件 × 证据的归属矩阵（第 15 章），以及两个完全离线、只读、不联网、不接触任何设备或配件的核验脚本：外接配件配对台账逐字段审查器（223 行，58 个码 = 54 个信号码 + 4 档判定）与配件链路三件差集与公告子词表比对器（220 行，43 个码 = 39 个信号码 + 4 级闭合）。**合计 101 个码全部由真实夹具触发**，34 次实跑（脚本一 19 次、脚本二 15 次）的逐码可达性见第 23 章；两支脚本的只读性质由第 23.1 节的二十段实证（P1—P20，临时目录前缀分别是 `acc22.` 与 `acld22.`）逐条给出位置。

---

## 目录

1. [引言](#1-引言)
2. [视角声明与本文边界](#2-视角声明与本文边界)
3. [三套词表：接口装配口径、平台安全口径与管理面公告回查口径，以及八处换算失败](#3-三套词表接口装配口径平台安全口径与管理面公告回查口径以及八处换算失败)
4. [L1 发现描述符层：三个属性、一个类，没有个体](#4-l1-发现描述符层三个属性一个类没有个体)
5. [L2 同意层：允许的是「这一类」，不是「这一个」](#5-l2-同意层允许的是这一类不是这一个)
6. [L3 身份验证层：认证 IC 在链路之外](#6-l3-身份验证层认证-ic-在链路之外)
7. [L4 ExternalAccessory 协议声明层：厂商决定谁能说话](#7-l4-externalaccessory-协议声明层厂商决定谁能说话)
8. [L5 BLE 与 BR/EDR 传输层：配对、绑定与密钥派生](#8-l5-ble-与-bredr-传输层配对绑定与密钥派生)
9. [L6 UWB 近场层：令牌先于测距](#9-l6-uwb-近场层令牌先于测距)
10. [L7 NFC 层：一次一个会话，扩展里没有它](#10-l7-nfc-层一次一个会话扩展里没有它)
11. [L8 USB 与有线限制层：一小时、三天与两个开关](#11-l8-usb-与有线限制层一小时三天与两个开关)
12. [L9 管理面回查层：210 个纯键名里的五个配件键](#12-l9-管理面回查层210-个纯键名里的五个配件键)
13. [L10 公告对齐层：27 行、0 行与七个 CVE](#13-l10-公告对齐层27-行0-行与七个-cve)
14. [L11 引用与结论层：doc.* 与十七份文档的平台坐标](#14-l11-引用与结论层doc-与十七份文档的平台坐标)
15. [归属矩阵：十一层 × 责任方 × 三件 × 证据](#15-归属矩阵十一层--责任方--三件--证据)
16. [公开读数：这条链路上能数出来的十二组事实](#16-公开读数这条链路上能数出来的十二组事实)
17. [可见性边界：这一层读者能拿到什么](#17-可见性边界这一层读者能拿到什么)
18. [五个读数面：发现侧、同意侧、传输侧、管理侧、公告侧](#18-五个读数面发现侧同意侧传输侧管理侧公告侧)
19. [两套判定模型：J1—J4 与 Q1—Q4](#19-两套判定模型j1j4-与-q1q4)
20. [运营指标 O1—O10](#20-运营指标-o1o10)
21. [只读核验脚本一：外接配件配对台账逐字段审查器](#21-只读核验脚本一外接配件配对台账逐字段审查器)
22. [只读核验脚本二：配件链路三件差集与公告子词表比对器](#22-只读核验脚本二配件链路三件差集与公告子词表比对器)
23. [实跑与覆盖验收](#23-实跑与覆盖验收)
24. [十二个误区](#24-十二个误区)
25. [常见问题](#25-常见问题)
26. [未公开文档化边界清单](#26-未公开文档化边界清单)
27. [结论](#27-结论)
28. [参考资料](#28-参考资料)

---

## 1. 引言

### 1.1 四个问句与四段判定权

本篇只问四个问题，而且每个问题都必须写清「谁有权回答」：

1. **这个配件是怎样被发现、又被圈到哪一类的？** 是 AccessorySetupKit 的描述符（16 位公司标识、名称子串、服务 UUID，`A/accessorysetupkit_asdiscoverydescriptor.txt:71、91、128`），是 ExternalAccessory 的协议声明（`UISupportedExternalAccessoryProtocols`，`A/externalaccessory.txt:13`），还是 CoreBluetooth 的扫描与 CoreNFC 的标签会话？这一问的判定权在**发现面**，而发现面给出的最大分辨率是**类**。
2. **是谁同意了它接入？** 系统弹窗、用户移除、通用蓝牙权限，三者是三条不同的登记（`A/accessorysetupkit.txt:6—7`）。这一问的判定权在**同意面**，而同意面给出的最大分辨率也是**类**：用户选的是一个由描述符筛出来的名单项。
3. **是谁证明了「它是它」？** 公开成文口径只有 MFi 认证 IC 一段（`B/apple-platform-security-guide.txt:1366—1367`），以及「配件生态在建立数据连接之前不提供密码学可靠的识别方式」这一句（`:1362`）。这一问的判定权在**身份面**，而身份面在公开接口里没有逐配件的读数。
4. **「这条链路怎样了」能不能在管理面或公告面上读回来？** 管理面有 5 个配件族纯键名（`C/readings-22.txt:136—141`），公告面有 27 行配件族记录（`:3`），但两者都不含「这一个配件」的词形。这一问的判定权在**回查面**，而回查面只能给出能力开关与族级标签。

四段判定权分属四个文档体系：配件发现与同意文档（AccessorySetupKit、ExternalAccessory）、平台安全指南（MFi 与有线限制）、管理面键表与隐私清单（回查）、安全公告（标签）。四者之间没有一份文档同时引用另外三方——这是本文的中心事实，也是第 22 章脚本二 X 族与 Z 族的全部设计根据。

### 1.2 为什么这一格在系列里非拆不可

第 02 篇处理「谁能进入哪道门」，第 15 篇处理「这条通道凭什么存在」，第 16 篇处理「同网段上谁看得见谁」，第 18 篇处理「一份内容被判成了什么类型」，第 19 篇处理「画面有没有离开设备」，第 20 篇处理「卷是什么形态」，第 21 篇处理「账户是谁装配的」。这七篇都碰到过外设，但都停在各自那一格：

- 02 篇把外设当成一个权限主体，没有追问「这个主体是一个还是一类」；
- 15 篇的通道是 IP 报文与隧道，外设链路不是它的对象；
- 16 篇的发现是局域网广播，AccessorySetupKit 的发现是蓝牙与 Wi-Fi Aware 描述符，两者只在「发现」这个词上同名；
- 18 篇的解析对象是文件与流媒体，HomeKit 摄像头的视频解析行在本篇只作为公告读数出现；
- 19 篇的画面外流与配件链路无关；
- 20 篇把 USB 只当作「卷从哪来」的一个来源，本篇把 USB 限制模式与 Files 访问当作独立一层；
- 21 篇的装配对象是账户声明，本篇的装配对象是配件会话与协议声明。

所以这一格在系列里是空的：**发现有描述符、同意有弹窗、身份有认证 IC、缺陷有公告，四者之间没有一条公开的换算链**。本文就是要把这条链拆到「哪一段有原文、哪一段只有名称、哪一段什么都没有」。

### 1.3 本文的口径边界

本文的全部结论只落在「台账能不能自洽」「三件清单能不能对齐」「公开词表有没有覆盖」三个层面上。它不回答「某个配件安全不安全」，也不回答「某台设备上的某条链路有没有被验证」。第 23 章的 101 个码证明的是**判据可达**，不是**设备状态**；第 16 章的 20 组读数证明的是**公开语料里数得出这些数**，不是**这些数在设备上成立**。凡是需要设备、配件、配对记录或真实链路才能回答的问题，本文一律写成 `unknown` 并说明缺哪一件证据。

---

## 2. 视角声明与本文边界

### 2.1 与系列内其他篇目的重叠界定

| 篇目 | 它回答什么 | 本篇只借用什么 | 本篇不重复什么 |
| --- | --- | --- | --- |
| 第 02 篇 访问控制与应用交互 | 谁能进入哪道门 | 「权限主体」的概念 | 权限判定本身 |
| 第 15 篇 网络扩展与代理/VPN | 通道凭什么存在 | 「通道责任方」的写法 | 隧道、代理与 VPN 配置 |
| 第 16 篇 本地网络访问与局域网发现 | 同网段谁看得见谁 | 「发现面」与「可见性」的核对项写法 | Bonjour/mDNS 与局域网权限弹窗 |
| 第 18 篇 非可信内容解析链路 | 内容被判成什么类型 | 「类型判定发生在哪个进程」的问法 | 文件与流媒体解析 |
| 第 19 篇 屏幕画面外流 | 画面有没有离开设备 | 「落点可见性」的核对项写法 | 屏幕采集与投送 |
| 第 20 篇 卷与挂载形态 | 卷是什么形态、谁挂上来 | USB 作为「来源」的读法 | 卷格式、挂载点与文件系统实现 |
| 第 21 篇 邮件账户与远端内容加载 | 账户装配与内容加载归谁 | 「声明式装配」与「三件差集」的方法 | Mail/Accounts 的读数 |
| 第 23 篇 平台校验组件与度量物 | 度量物与校验组件归谁 | 无 | 全部 |

**视角声明（防重复）**：本篇的自有视角是「发现 → 同意 → 身份 → 传输 → 回查」这条五段链，而不是「蓝牙安全」或「外设安全」这个大类。凡是只谈某个蓝牙 CVE 的技术细节、只谈某个射频协议的攻击手法、只谈某个配件的固件更新流程，都不在本篇范围内。与第 20 篇的交界只有一句：USB 在本篇只作为「有线配件链路」的一层，不讨论卷形态；与第 21 篇的交界只有一句：两篇都数管理面键名，但本篇只数配件族五键与 Wi-Fi 三键，不重复 Mail/Accounts 的读数。

### 2.2 五条硬边界

1. **不写任何配件发现、配对或连接的操作步骤。** 不写如何扫描、如何伪造描述符、如何让系统弹出选择器、如何配对或绑定、如何读取或写入标签；脚本一只读取台账文本，不产生任何设备操作。
2. **不写任何绕过同意、冒用 MFi 认证或解除 USB 限制的做法。** 不写如何让配件在没有用户同意时接入、如何伪造认证 IC 的应答、如何关闭 USB 限制模式；`mfi_verified` 只作为台账字段，`allowUSBRestrictedMode` 只作为管理面键名引用。
3. **不写任何传输层攻击或嗅探手法。** 不写如何抓取 BLE、NFC、UWB 报文，不写如何重放、降级或注入；平台安全指南的协议描述只作为公开语义引用。
4. **不接触设备、配件与真实链路。** 没有真实配件名称、序列号、MAC 地址、配对记录或固件；夹具里的 `Desk Lamp`、`004C`、`181A` 全是占位值。第 23.1 节的 P9、P10、P19 专门证明输入未被改写、临时目录零残留、脚本自身未被改写。
5. **不把「读不到」写成「不存在」。** 公开接口没有逐配件的身份读数，不等于设备上没有身份验证；公开公告没有 `accessory` 词形，不等于没有配件类缺陷。两者的区别贯穿第 17 章与第 24 章。

### 2.3 术语约定

| 术语 | 本文定义 | 不用它表示 |
| --- | --- | --- |
| 发现件 | 一条链路所登记的发现方法、描述符、协议、entitlement 与用途声明 | 「配件已被发现」 |
| 链路件 | 一条链路所登记的传输层、配对、绑定、加密、密钥派生与限制模式 | 「链路已建立」 |
| 回查件 | 限制键、公告组件行、平台安全指南锚点三类可回查证据 | 「管理面已确认状态」 |
| 闭合 | 三件齐全且各自有公开锚点，允许写 `closed` | 「安全」 |
| `unknown` | 公开语料里读不到，且能指出缺哪一份文档 | 「不存在」或「关闭」 |
| 类级 | 描述符或同意只到公司标识／名称子串／服务 UUID 这一级 | 个体级 |
| 个体级 | 能回答「是不是这一个配件」的证据 | 类级 |

---

## 3. 三套词表：接口装配口径、平台安全口径与管理面公告回查口径，以及八处换算失败

本篇所有的「读不懂」都可以归到三套词表之间的换算失败。先把三套词表摊开。

### 3.1 表一：接口装配口径（8 个发现字段 + 17 份文档 + 71 行平台坐标）

接口装配口径由五个框架的十七份文档组成：AccessorySetupKit 五份、ExternalAccessory 三份、CoreBluetooth 三份、CoreNFC 三份、NearbyInteraction 三份（`C/readings-22.txt:14—33`）。它们共同给出八个发现／会话字段：

| 字段 | 出处 | 取值形态 | 能回答什么 |
| --- | --- | --- | --- |
| 公司标识 | `A/accessorysetupkit_asdiscoverydescriptor.txt:71` | 16 位整数 | 哪个厂商 |
| 名称子串 | `:91` | 字符串 | 哪一类名字 |
| 服务 UUID | `:128` | `CBUUID` | 哪一类服务 |
| 支持选项 | `:149` | 选项集合 | 这类配件支持什么 |
| 协议 | `A/externalaccessory.txt:13` | 字符串数组 | 哪个 MFi 协议 |
| entitlement | `A/corenfc.txt:8` | 权限声明 | 哪个框架被授权 |
| 用途字符串 | `A/corebluetooth.txt:156、158` | 文案 | 为什么需要蓝牙 |
| App 扩展 | `A/corenfc.txt:8` | 布尔 | 能否在扩展里用 |

八个字段里没有一个能单独定位到「这一个配件」：公司标识定位到厂商，名称子串定位到名字族，服务 UUID 定位到服务族，协议定位到协议族。**「个体」只在用户于系统选择器里点选的那一刻出现，而这次点选在公开接口里不产生一个可回查的标识。**

### 3.2 表二：平台安全口径（四段原文）

平台安全指南给出四段与本链路直接相关的成文口径：

1. **有线激活**：`Activating data connections securely`（`B/apple-platform-security-guide.txt:1359`）说明，若最近没有建立过数据连接，用户需要用 Face ID、Touch ID 或密码来激活 Thunderbolt、USB、Lightning、Smart Connector 或 SDXC 上的数据连接。
2. **无密码学识别**：`Is necessary because the accessory ecosystem doesn’t provide a cryptographically reliable way to identify accessories before establishing a data connection`（`:1362`）。这句话是全文的支点：**连接建立之前，没有密码学可靠的识别**。
3. **三天规则**：`In addition, if it’s been more than three days since a data connection has been established with an accessory, the device will disallow new data connections immediately after it locks.`（`:1363`）。
4. **认证 IC**：`The MFi licensing program provides vetted accessory manufacturers access to the iPod Accessories Protocol (iAP) and the necessary supporting hardware components.`（`:1366`）；`As proof of authorization, the accessory sends an Apple-provided certificate to the device, which the device then verifies. The device then sends a challenge, which the accessory needs to answer with a signed response. This process is entirely handled by a custom integrated circuit (IC) that Apple provides to approved accessory manufacturers and is transparent to the accessory itself.`（`:1367`）；`If an accessory doesn’t support authentication, its access is limited to analog audio and a small subset of serial (UART) audio playback controls.`（`:1373`）。

另有三个协议章节作为补充锚点：`Bluetooth security`（`:3905`）、`Ultra Wideband security in iOS`（`:3972`）、`NFC & SE Platform component security`（`:4186`）。全文引用平台安全指南 4,886 行，其中 `accessor` 45 行、`MFi` 6 行、`pairing` 53 行、`UWB` 6 行（`C/readings-22.txt:159`）。

### 3.3 表三：管理面与公告回查口径（210 键、65 声明、27 行、1,266 行）

回查口径由三份互不引用的材料组成：

- **管理面**：210 个纯键名（`C/readings-22.txt:136`），其中配件族五键——`allowBluetoothModification`（第 41 行）、`allowBluetoothSharingModification`（第 42 行）、`allowFilesUSBDriveAccess`（第 87 行）、`allowNFC`（第 122 行）、`allowUSBRestrictedMode`（第 170 行）；Wi-Fi 三键在第 211—213 行（`C/readings-22.txt:137—141`）。
- **声明类型**：65 项，其中只有一项以 `AudioAccessory` 开头，即 `AudioAccessorySettings`（`C/readings-22.txt:145`）。
- **公告语料**：1,266 行记录，配件族 27 行、7 个 CVE（`C/readings-22.txt:1、3`）。

### 3.4 八处换算失败

**第一处：描述符 → 个体。** AccessorySetupKit 的描述符只有公司标识、名称子串、服务 UUID 三个选择维度（`A/accessorysetupkit_asdiscoverydescriptor.txt:71、91、128`）。三个维度都能把候选集合缩小，但都不能把集合缩到 1；用户在选择器里点中的那一项，在公开接口里没有对应的稳定标识。**换算失败点：类级字段无法推出个体级结论。**

**第二处：同意 → 身份。** 同意弹窗记录的是「允许这一类接入」，不是「这个配件已被证明是它」。平台安全指南把识别问题单独写成一句（`B/apple-platform-security-guide.txt:1362`），并把它作为有线激活一小时规则的**理由**；也就是说，系统自己承认「连接前没有密码学可靠的识别」，所以用「用户在场」来补偿。**换算失败点：同意的对象是类，身份的对象是个体。**

**第三处：身份 → 链路。** MFi 的证书、挑战与签名应答全部由认证 IC 处理，而且 `is transparent to the accessory itself`（`B/apple-platform-security-guide.txt:1367`）。公开的 BLE、NFC、UWB 接口没有任何字段暴露这次验证的结果；本文的台账只能登记 `consent.mfi_verified=yes` 与 `consent.mfi_evidence=ic`，不能登记「IC 对哪一个配件说了 yes」。**换算失败点：硬件根在链路之外，链路读数看不见它。**

**第四处：传输 → 会话。** 平台安全指南把配对、绑定、认证、加密、消息完整性、Secure Simple Pairing 列为蓝牙安全模型的六个特征（`:3905`）。这六个词回答的是「两个端点是否共享密钥」，不是「这个端点是谁」。**换算失败点：传输层证明密钥一致，不证明身份一致。**

**第五处：公告组件 → 影响句。** 配件族 27 行里，组件名列的 `Bluetooth` 9 行、`HomeKit` 8 行、`USB` 5 行、`Thread` 3 行、`AccessorySetupKit` 2 行；影响句列里 `accessory` 0 行、`pairing` 0 行、`MFi` 0 行、`UWB` 0 行、`NFC` 0 行、`near field` 0 行（`C/readings-22.txt:54—63`）。**换算失败点：组件名是归属标签，不是缺陷类型；两列之间没有映射。**

**第六处：管理键 → 单机状态。** 五个配件族键全部是布尔开关：`allowBluetoothModification` 阻止修改蓝牙设置、`allowBluetoothSharingModification` 阻止在系统设置里修改蓝牙共享、`allowFilesUSBDriveAccess` 阻止 Files 访问 USB 设备、`allowNFC` 关闭 NFC、`allowUSBRestrictedMode` 控制锁屏时是否总是允许 USB 配件（`A/mdm-restrictions-payload-M.txt:41、42、87、122、170`）。没有一个键回答「某个配件当前是否已配对／已验证」。**换算失败点：能力开关不是逐配件状态。**

**第七处：平台坐标 → 能力。** 十七份文档里，只有 iOS 的 10 份、两者都有的 7 份、只有 macOS 的 0 份；5 份文档两平台版本差超过 5（`C/readings-22.txt:135`）。AccessorySetupKit 与 CoreNFC 完全没有 macOS 行，ExternalAccessory 三份全部有 macOS 10.13 行。**换算失败点：平台行出现不等于能力对等，平台行缺失不等于能力不存在。**

**第八处：文档词表 → 台账字段。** 平台安全指南 `pairing` 53 行、`MFi` 6 行、`accessor` 45 行；公告影响句 `pairing` 0 行、`MFi` 0 行、`accessory` 0 行（`C/readings-22.txt:159、54—63`）。同一个词在两套语料里的含义并不相同：指南里的 `pairing` 是蓝牙通用配对，公告里的 `proximity` 是攻击者位置。**换算失败点：词形相同不等于语义相同；台账必须给每个字段写清主语。**

### 3.5 三套词表的使用规则

1. **先问主语。** 一个数字的主语是「一个配件」「一类配件」「一个框架」还是「一个组件行」；主语不同的数字不相加。
2. **再问列名。** 公告侧的每个计数必须写明它数的是组件列还是影响句列；只给数字不给列名的结论，一律退回。
3. **最后问缺件。** 三件里缺哪一件，结论只能写到对应的等级；缺身份件时不许写 `closed`。

---
## 4. L1 发现描述符层：三个属性、一个类，没有个体

### 4.1 本层回答什么

L1 只回答一个问题：**一条链路是凭什么被筛出来的。** 公开接口把「筛」拆成三个可编程属性与一个选项集合：16 位公司标识、蓝牙名称子串、蓝牙服务 UUID、支持选项（`A/accessorysetupkit_asdiscoverydescriptor.txt:71、91、128、149`）。框架总览把用途写成两句：`Enable privacy-preserving discovery and configuration of accessories.`（`A/accessorysetupkit.txt:3`）与 `Use AccessorySetupKit to discover and configure Bluetooth or Wi-Fi accessories with images and names provided by the app.`（`:5`）。

### 4.2 三条结构读数

**读数一：三个属性都是类级。** 公司标识是 16 位整数，原文只写 `The accessory’s 16-bit Bluetooth Company Identifier.`（`:71`）；名称子串是 `The accessory’s over-the-air Bluetooth name substring.`（`:91`）；服务 UUID 是 `The accessory’s Bluetooth service UUID.`（`:128`）。三条都没有序列号、证书指纹、配对记录标识这类个体级字段。

**读数二：选项集合是能力声明，不是身份声明。** `Options supported by an accessory.`（`:149`）描述这类配件支持哪些行为，不描述这个配件是谁。

**读数三：Wi-Fi Aware 也走同一套描述符。** 总览这句话里嵌了两个链接，抽取文本只剩骨架：`To use AccessorySetupKit with ... specify Wi-Fi Aware properties in a ... prior to beginning accessory discovery.`（`A/accessorysetupkit.txt:8—10`）。也就是说，发现面覆盖蓝牙与 Wi-Fi Aware 两类，但两者的描述符语义仍然是「类」。

### 4.3 选择器把「类」收窄成「一个」，但不留下标识

`ASAccessorySession` 的说明是 `Discover, select, and set up a specific Bluetooth accessory without requesting permission to use Bluetooth.`（`A/accessorysetupkit_asaccessorysession.txt:249`）。这句话里的 `specific` 是**用户在选择器里点中的那一个**，不是**描述符能唯一指认的那一个**。两者的差别是本文 L1 的核心：

- 描述符能回答「候选集合里有哪几类」；
- 选择器能回答「用户点了哪一个」；
- 公开接口不能回答「这个被点中的配件，下一次还能不能被同一个标识认出来」。

所以台账把发现件拆成 `disc.method`、`disc.company_id`、`disc.name_substring`、`disc.service_uuid`、`disc.protocol`、`disc.entitlement`、`disc.usage_desc`、`disc.app_extension` 八个字段（脚本一第 127—147 行），并把「描述符被多条链路共用」写成 D07：**同一个类级描述符被两条链路共用时，台账不能假装它们指向两个个体。**

### 4.4 本层核对项

| 项 | 核对什么 | 判据 | 码 |
| --- | --- | --- | --- |
| L1-1 | 发现方法是否在允许集合内 | `ask`／`externalaccessory`／`uwb`／`nfc`／`ble` | B03 |
| L1-2 | 公司标识是否是四位十六进制 | `^[0-9A-Fa-f]{4}$` | B06 |
| L1-3 | 描述符是否缺方法或协议 | `disc.method`／`disc.protocol` 非空 | A03／A04 |
| L1-4 | 同一描述符是否被多条链路共用 | `company_id|name_substring` 计数 | D07 |
| L1-5 | 设备级同意是否被写成类级描述符 | `scope=device` 且描述符非空 | D06 |
| L1-6 | 结论为 `present` 但方法为空 | `claim.cell=present` | F07 |

### 4.5 这一层不能推出什么

不能从「描述符匹配」推出「配件身份已验证」；不能从「用户点选」推出「这个配件已被系统记住为一个稳定个体」；不能从「公司标识相同」推出「同一厂商的所有配件都可信」。三条都缺一件公开证据：一个逐配件的、可回查的标识。

---

## 5. L2 同意层：允许的是「这一类」，不是「这一个」

### 5.1 本层回答什么

L2 回答：**谁点了头，点的是哪一类的头。** AccessorySetupKit 的总览把同意与权限写在一起：`Allow seamless, privacy-preserving user consent and control for Bluetooth, Wi-Fi, and Local Network permissions.`（`A/accessorysetupkit.txt:6`）；紧接着一句是移除与重命名：`AccessorySetupKit apps can access enhanced accessory controls including accessory pairing removal and renaming.`（`:7`）。这两句把「同意」「权限」「移除」三件事放在同一段，但它们是三条不同的登记。

### 5.2 三条登记

| 登记 | 公开口径 | 台账字段 | 能回答什么 |
| --- | --- | --- | --- |
| 配件级同意 | 系统选择器让用户选定一个具体配件（`A/accessorysetupkit_asaccessorysession.txt:249`） | `consent.prompt`／`consent.scope` | 用户是否在系统弹窗里点过头 |
| 通用蓝牙权限 | 总览的 `Bluetooth, Wi-Fi, and Local Network permissions`（`A/accessorysetupkit.txt:6`） | `consent.bluetooth_permission`／`consent.local_network` | 通用权限是否被授予 |
| 移除与重命名 | 总览的 `pairing removal and renaming`（`:7`） | `consent.user_removal`／`mgmt.removal_path` | 用户是否还能撤回 |

三者的主语不同：第一条的主语是「这一次选择」，第二条的主语是「这个 App 的通用权限」，第三条的主语是「这条配对记录」。**把三条压成一个 `consent=yes` 是本文最常拦的误读。**

### 5.3 「不要蓝牙权限」不等于「不要同意」

`Discover, select, and set up a specific Bluetooth accessory without requesting permission to use Bluetooth.`（`A/accessorysetupkit_asaccessorysession.txt:249`）这句话最容易被读成「AccessorySetupKit 绕过了同意」。实际相反：它绕过的是**通用蓝牙权限弹窗**，换来的是**配件选择器**——用户仍然要在一个系统界面里选定一个配件。本文因此把 `consent.bluetooth_permission=denied` 与 `consent.prompt=system` 做成可以同时成立的两列；脚本一 C07 只在「蓝牙权限被拒但仍登记蓝牙发现」时报警，B08 只在「AccessorySetupKit 会话未登记同意弹窗」时报警，两条各管一段。

### 5.4 缺陷公告里的同意读数

配件族公告里唯一直接写「同意」的行是 CVE-2026-84493：`A malicious app may be able to access Bluetooth without user consent`（`C/readings-22.txt:7`）。这一行属于 AccessorySetupKit 组件，影响句含 `consent`。它是本文全部 27 行配件族公告里**唯一**把 `consent` 写进影响句的行；配件族影响句的 `consent` 计数因此是 2（另一行在族外，`C/readings-22.txt:63`）。这条读数证明的是「公告语料里同意是一个可被写出来的词」，不是「同意链路的缺陷只有这一条」。

### 5.5 本层核对项

| 项 | 核对什么 | 判据 | 码 |
| --- | --- | --- | --- |
| L2-1 | 发现方法需要同意但弹窗为 `none` | `method=ask|externalaccessory` 且 `prompt=none` | B07 |
| L2-2 | AccessorySetupKit 会话缺同意弹窗 | `method=ask` 且 `prompt` 空 | B08 |
| L2-3 | 同意范围为设备级但弹窗为 `none` | `scope=device` 且 `prompt=none` | D02 |
| L2-4 | 设备级同意却只有类级描述符 | `scope=device` 且三属性任一非空 | D06 |
| L2-5 | 结论宣称设备级但台账是类级 | `claim.consent_scope=device` | F03 |
| L2-6 | 链路未登记移除路径 | `user_removal=no` 且 `transport=ask` | D05 |

### 5.6 这一层不能推出什么

不能从「用户同意」推出「配件身份已验证」；不能从「通用蓝牙权限被拒」推出「配件无法被发现」——AccessorySetupKit 的会话正是为这个场景设计的；不能从「用户移除过」推出「这个配件以后不会再出现」——类级描述符仍可能匹配到同族的另一个配件。

---

## 6. L3 身份验证层：认证 IC 在链路之外

### 6.1 本层回答什么

L3 回答：**「它是它」这件事由谁证明，证明结果在哪里。** 平台安全指南给出的答案只有一段：MFi 授权厂商拿到 iAP 与配套硬件（`B/apple-platform-security-guide.txt:1366`）；配件把 Apple 提供的证书发给设备，设备验证后发挑战，配件用签名应答（`:1367`）；整个过程由 Apple 提供给授权厂商的定制 IC 处理，`and is transparent to the accessory itself`（`:1367`）。没有认证能力的配件被限制在模拟音频与一小部分串口（UART）播放控制（`:1373`）。

### 6.2 四个必须一起读的句子

1. `The MFi licensing program provides vetted accessory manufacturers access to the iPod Accessories Protocol (iAP) and the necessary supporting hardware components.`（`:1366`）——身份验证的根是**授权厂商 + 硬件**，不是软件声明。
2. `As proof of authorization, the accessory sends an Apple-provided certificate to the device, which the device then verifies.`（`:1367`）——证明的载体是**证书**，验证方是**设备**。
3. `The device then sends a challenge, which the accessory needs to answer with a signed response.`（`:1367`）——这是**挑战-应答**，不是静态指纹比对。
4. `This process is entirely handled by a custom integrated circuit (IC) ... and is transparent to the accessory itself.`（`:1367`）——IC 是**链路之外的根**，配件本身也看不见过程。

第四句是全文最关键的一句：**如果连配件本身都看不见这个过程，那么任何在配件侧抓到的链路日志都不足以证明「验证发生过」。** 本文因此把 `consent.mfi_evidence` 只允许取 `ic`（脚本一 A07）：如果台账写 `mfi_verified=yes` 却拿不出 `ic` 这个证据类型，直接按 A07 阻断。

### 6.3 认证 IC 与 AirPlay 的复用

平台安全指南随后写：`AirPlay also uses the authentication IC to verify that receivers have been approved by Apple.`（`:1374`）；AirPlay 音频与 CarPlay 视频使用 MFi-SAP，AES128-CTR 加密，ECDH（Curve25519）交换临时密钥，并用认证 IC 的 1024 位 RSA 密钥签名，作为 Station-to-Station 协议的一部分（`:1374`）。这段说明认证 IC 不是「配对时用一次」的组件，而是**多种配件形态共用的根**。本文只把它作为 L3 的公开锚点，不展开 AirPlay 或 CarPlay 的链路。

### 6.4 身份读数为什么只能记 `partial`

公开接口能读到「MFi 存在」「认证 IC 存在」「证书-挑战-应答存在」，但读不到「这一次验证的结果」。台账因此把身份件写成三列：`consent.mfi_verified`（是／否）、`consent.mfi_evidence`（只能是 `ic`）、`claim.mfi_claim`（结论是否宣称已验证）。脚本一 F04 检查「结论宣称 MFi 已验证但证据不是认证 IC」，Z13 检查「宣称 MFi 已验证但回查锚点不是 MFi 段落（1366／1367／1373）」。**身份件的最高等级是 `partial`，不是 `closed`。**

### 6.5 本层核对项

| 项 | 核对什么 | 判据 | 码 |
| --- | --- | --- | --- |
| L3-1 | MFi 已验证但证据不是 IC | `mfi=yes` 且 `evidence!=ic` | A07 |
| L3-2 | MFi 已验证但证据为空 | `mfi=yes` 且 `evidence` 空 | D01 |
| L3-3 | 未验证 MFi 却声明协议 | `mfi=no` 且 `protocol` 非空 | C05 |
| L3-4 | 已验证 MFi 却没有协议 | `mfi=yes` 且 `protocol` 空 | C04 |
| L3-5 | 结论宣称已验证但证据不是 IC | `claim.mfi_claim=yes` 且 `evidence!=ic` | F04 |
| L3-6 | 回查锚点不在 MFi 段落 | `mfi=yes` 且 `psg` 不含 1366／1367／1373 | Z13 |

### 6.6 这一层不能推出什么

不能从「MFi 已验证」推出「这个配件是正品」——验证的是认证 IC 的应答，不是整机来源；不能从「未验证」推出「配件不可用」——`:1373` 明确它仍可走模拟音频与 UART；不能从「认证 IC 存在」推出「每次连接都重新验证」——公开文档没有给出验证频率。

---

## 7. L4 ExternalAccessory 协议声明层：厂商决定谁能说话

### 7.1 本层回答什么

L4 回答：**一个 App 凭什么被允许与某个 MFi 配件通话。** ExternalAccessory 的公开口径把答案写成两层：框架层说明它支持 Lightning、30-pin 与蓝牙配件（`A/externalaccessory.txt:6`）；厂商层说明 `The manufacturer of an MFi accessory decides which third-party apps may communicate with their accessories.`（`:8`）。App 侧要声明 `UISupportedExternalAccessoryProtocols`（`:13`），也就是一份协议白名单。

### 7.2 三条结构读数

**读数一：协议声明是静态白名单。** `The protocols that the app uses to communicate with external accessory hardware.`（`:13`）——它描述 App 会说什么协议，不描述当前连着哪个配件。

**读数二：授权方是厂商，不是系统。** `The manufacturer of an MFi accessory decides which third-party apps may communicate with their accessories.`（`:8`）——这句话把「谁能说话」的判定权放在厂商侧；系统只执行协议声明与 entitlement 的匹配，不替厂商做商业授权。

**读数三：Apple silicon 上有一条例外。** `iPad and iPhone apps running on a Mac with Apple silicon can’t connect to external accessories using this framework.`（`:7`）——平台坐标里的 macOS 行不等于「同一个 App 在 Mac 上能用 ExternalAccessory 连配件」。

### 7.3 平台坐标的结构

ExternalAccessory 三份文档（`externalaccessory`、`eaaccessory`、`eaaccessorymanager`）在平台矩阵里都同时有 iOS 与 macOS 行：iOS 3.0、macOS 10.13（`C/platform-22.txt:41—58`）。这是本篇 7 份「两平台都有」文档里的 3 份，也是版本差超过 5 的 5 份里的 3 份（iOS 3.0 对 macOS 10.13）。**平台行齐全，但版本差 7 个大版本；「iOS 3.0 起可用」与「macOS 10.13 起可用」不能互相证明对方的实现形态。**

### 7.4 本层核对项

| 项 | 核对什么 | 判据 | 码 |
| --- | --- | --- | --- |
| L4-1 | 发现方法需要同意但弹窗为 `none` | `method=externalaccessory` 且 `prompt=none` | B07 |
| L4-2 | 传输层不在允许集合内 | `transport=ask|externalaccessory|usb|nfc|uwb` | B01 |
| L4-3 | 协议字段为空 | `disc.protocol` 空 | A04 |
| L4-4 | 未验证 MFi 却声明协议 | `mfi=no` 且 `protocol` 非空 | C05 |
| L4-5 | 结论为 `absent` 但发现方法存在 | `claim.cell=absent` 且 `method` 非空 | F02 |
| L4-6 | 文档地址不在 developer.apple.com | `doc.page_url` 前缀 | G04 |

### 7.5 这一层不能推出什么

不能从「App 声明了协议」推出「配件授权了这个 App」；不能从「厂商决定」推出「系统不校验」——系统仍校验 entitlement 与协议声明；不能从「macOS 10.13 有文档」推出「Apple silicon 上的 iPad App 能连配件」——`:7` 明确相反。

---

## 8. L5 BLE 与 BR/EDR 传输层：配对、绑定与密钥派生

### 8.1 本层回答什么

L5 回答：**这条链路在传输层登记了什么。** CoreBluetooth 的公开总览写明它同时覆盖低功耗（LE）与 Basic Rate／Enhanced Data Rate（BR/EDR）：`The Core Bluetooth framework provides the classes needed for your apps to communicate with Bluetooth-equipped low energy (LE) and Basic Rate / Enhanced Data Rate (BR/EDR) wireless technology.`（`A/corebluetooth.txt:6`）。平台安全指南把蓝牙安全模型拆成六个特征：配对、绑定、认证、加密、消息完整性、Secure Simple Pairing（`B/apple-platform-security-guide.txt:3905`）。

### 8.2 六个词的主语

| 词 | 平台安全指南的定义（`:3905`） | 回答什么 | 不回答什么 |
| --- | --- | --- | --- |
| Pairing | `The process for creating one or more shared secret keys` | 是否建立了共享密钥 | 对方是谁 |
| Bonding | `The act of storing the keys created during pairing for use in subsequent connections` | 是否记住了这次配对 | 记住的是哪一个配件 |
| Authentication | `Verifying that the two devices have the same keys` | 两端密钥是否一致 | 配件是否 MFi 认证 |
| Encryption | `Message confidentiality` | 报文是否加密 | 加密对象是谁 |
| Message integrity | `Protection against message forgeries` | 报文是否可伪造 | 身份是否可伪造 |
| Secure Simple Pairing | `Protection against passive eavesdropping and protection against man-in-the-middle attacks` | 配对过程是否抗窃听 | 配件是否正品 |

六个词全部是**传输层谓词**，没有一个是**身份层谓词**。台账因此把 `link.pairing`、`link.bonding`、`link.encryption`、`link.key_derivation` 四列分开登记；脚本一 C01（配对为 `none` 但加密开启）与 C02（加密开启但密钥派生为 `none`）只检查这四列之间的自洽，不把任何一列当成 MFi 的证据。

### 8.3 后台扫描的两条新口径

CoreBluetooth 总览有两条与后台有关的口径：`Core Bluetooth background execution modes aren’t supported in iPad apps running on macOS.`（`A/corebluetooth.txt:8`）；`In iOS 26 and later, your app can continue certain activities in the background if the app starts a Live Activity before it goes to the background.`（`:9`）。随后一句把范围写细：`This means activities like scanning without providing service UUID’s and scanning with duplicates filter disabled will be allowed while in the background.`（`:11`）。这两条说明**扫描能力会随平台与系统版本变化**，但变化的仍然是能力，不是身份。

### 8.4 用途字符串的两个键

CoreBluetooth 文档给出两个用途字符串键：`NSBluetoothAlwaysUsageDescription`（`A/corebluetooth.txt:156`）与 `NSBluetoothPeripheralUsageDescription`（`:158`）。前者是「为什么需要蓝牙」，后者是「为什么需要连接蓝牙外设」。两个键都是**面向用户的说明**，不是**面向系统的身份声明**；台账把 `disc.usage_desc` 只登记为 `present`／`absent`，不从文案内容推断权限。

### 8.5 本层核对项

| 项 | 核对什么 | 判据 | 码 |
| --- | --- | --- | --- |
| L5-1 | 配对为 `none` 但加密开启 | `pairing=none` 且 `encryption=yes` | C01 |
| L5-2 | 加密开启但密钥派生为 `none` | `encryption=yes` 且 `key_derivation=none` | C02 |
| L5-3 | AccessorySetupKit 会话未登记 BLE 角色 | `transport=ask` 且 `ble_role` 不在集合内 | B04 |
| L5-4 | 蓝牙权限被拒但仍登记蓝牙发现 | `bluetooth_permission=denied` 且方法为 `ask|ble` | C07 |
| L5-5 | 邻近性声明与传输层不符 | `claim.proximity=yes` 且传输层不是 `ble|uwb|thread` | F05 |
| L5-6 | 传输层缺失 | `disc.transport` 空 | Z14 |

### 8.6 这一层不能推出什么

不能从「已配对」推出「已认证」；不能从「已绑定」推出「绑定的是正品」；不能从「加密开启」推出「对方身份可信」；不能从「Secure Simple Pairing」推出「MFi 验证通过」。四个「不能」的共同原因是：传输层证明**密钥关系**，身份层证明**硬件来源**，两者不是同一套证据。

---
## 9. L6 UWB 近场层：令牌先于测距

### 9.1 本层回答什么

L6 回答：**近场测距之前，双方交换了什么。** NearbyInteraction 的总览写明它用于取得带 UWB 芯片的设备位置，`such as iPhone 11 or later, Apple Watch, and third-party accessories`（`A/nearbyinteraction.txt:6`）；参与交互的设备在物理邻近范围内运行 App，并共享位置与能唯一识别它们的设备令牌（`:7`）。第三方配件的口径更具体：`To begin an interaction session with a third-party accessory, establish a data link with the accessory, receive its configuration data, and create an ... session.`（`:19`）。

### 9.2 顺序：先链路，再配置，再令牌，最后测距

`:19` 这句话把顺序写得不能颠倒：**先建立数据链路，再接收配置数据，再创建会话**。也就是说，UWB 测距不是「先认出配件再连」，而是「先连上、再拿配置、再开始测距」。平台安全指南的 UWB 章节（`B/apple-platform-security-guide.txt:3972`）描述 U1 芯片与随机化（MAC 地址、Wi-Fi 帧序列号），这些是**隐私随机化**，不是**配件身份**。

### 9.3 令牌不是身份凭据

台账把 `link.uwb_token` 与 `link.uwb_config` 分成两列：前者登记「会话令牌是否存在」，后者登记「配置数据是否被接收」。脚本一 C08 在 `transport=uwb` 且令牌为空时报警；它检查的是**会话结构**，不是**令牌的真实性**。把令牌当成身份凭据，会得到一个错误结论：只要有令牌，就知道对方是谁。公开文档只说明令牌用于「唯一识别」参与交互的设备，没有说明令牌由谁签发、能否跨会话复用、是否与 MFi 验证绑定。

### 9.4 平台矩阵的一处内部不一致

`nearbyinteraction` 总览行是 iOS 14.0／macOS 11.0／watchOS 8.0；而 `nearbyinteraction_nisession` 与 `nearbyinteraction_ninearbypeerconfiguration` 的 watchOS 行是 7.3，且没有 macOS 行（`C/platform-22.txt:60—71`）。同一个框架内，总览与子页的 watchOS 版本相差 0.7，macOS 行只出现在总览页。本文不判断哪一行「对」，只把它记为**平台坐标的内部不一致**：读者若拿子页坐标去推断总览能力，会得到不同结论。脚本二 Y04 只查「NearbyInteraction 是否有 iOS 15 及以上的行」，不查 watchOS 一致性，因为后者没有一条公开口径可以裁决。

### 9.5 本层核对项

| 项 | 核对什么 | 判据 | 码 |
| --- | --- | --- | --- |
| L6-1 | UWB 链路缺会话令牌 | `transport=uwb` 且 `uwb_token` 空 | C08 |
| L6-2 | UWB 会话声明在 iOS 15 之前 | `method=uwb` 且主版本 <15 | D04 |
| L6-3 | 邻近性声明与传输层不符 | `claim.proximity=yes` 且传输层不是 `ble|uwb|thread` | F05 |
| L6-4 | 邻近性声明落在 NFC／USB 上 | `proximity=yes` 且 `transport=nfc|usb` | Z17 |
| L6-5 | 平台矩阵缺 iOS 15 行 | `nearbyinteraction` 行 | Y04 |

### 9.6 这一层不能推出什么

不能从「有 UWB 会话」推出「配件已通过 MFi 验证」；不能从「令牌唯一」推出「令牌不可伪造」；不能从「iOS 15 起支持第三方配件」推出「所有第三方配件都被支持」——原文的主语是 `UWB-enabled devices` 与 `third-party accessories you partner with or develop`（`:19`）。

---

## 10. L7 NFC 层：一次一个会话，扩展里没有它

### 10.1 本层回答什么

L7 回答：**NFC 这一格能读什么、不能读什么。** CoreNFC 的总览写明它能读 1—5 型 NDEF 标签（`A/corenfc.txt:6`），也能与 ISO 7816、ISO 15693、FeliCa、MIFARE 等协议标签交互（`:7`）；但 `Core NFC isn’t available for use in app extensions`（`:8`），并且 `Only one reader session of any type can be active in the system at a time.`（`A/corenfc_nfctagreadersession.txt:22`）。

### 10.2 三条硬读数

**读数一：扩展里没有 NFC。** `:8` 把 App 扩展排除在外。这意味着「App 扩展登记了 NFC 发现」在结构上就是矛盾，脚本一 B09 专门拦这一条。

**读数二：全系统一次一个会话。** `:22` 说明额外会话进入 FIFO 队列。这不是「每个 App 一个会话」，而是「整个系统一个活动会话」。台账因此把 `link.nfc_session` 的取值限定为 `ndef`／`tag`／`none`，并在管理面关闭 NFC 时检查链路是否仍登记会话（E04）。

**读数三：entitlement 是前置条件。** CoreNFC 文档在 `:8` 同段要求检查设备支持；NFC 发现没有 entitlement 时，脚本一 D03 直接报警。

### 10.3 NFC 与 NFC & SE Platform 是两条路

平台安全指南另有一章 `NFC & SE Platform component security`（`B/apple-platform-security-guide.txt:4186`），描述的是 Secure Element 上的交易凭证（`:4187—4225`）。这条路径与 CoreNFC 的标签读取不是同一条链路：前者是 SE 里的 applet 与交易授权，后者是 App 读标签。本文只把 SE 章节作为**边界锚点**引用，不把交易凭证的授权口径套到配件配对上。

### 10.4 平台坐标

CoreNFC 三份文档（`corenfc`、`corenfc_nfcndefreadersession`、`corenfc_nfctagreadersession`）都只有 iOS／iPadOS 与 Mac Catalyst 行，没有 macOS 行（`C/platform-22.txt:34—40`）。Mac Catalyst 13.1 不是 macOS 原生行；把它读成「macOS 支持 CoreNFC」会得到一个平台矩阵不支持的结论。

### 10.5 本层核对项

| 项 | 核对什么 | 判据 | 码 |
| --- | --- | --- | --- |
| L7-1 | NFC 会话类型不在集合内 | `link.nfc_session` 不在 `ndef|tag|none` | B05 |
| L7-2 | App 扩展登记了 NFC 发现 | `app_extension=yes` 且 `method=nfc` | B09 |
| L7-3 | NFC 发现未登记 entitlement | `method=nfc` 且 `entitlement!=yes` | D03 |
| L7-4 | 管理面关闭 NFC 但链路仍有会话 | `mgmt.allow_nfc=false` 且会话非空 | E04 |
| L7-5 | 平台矩阵缺 CoreNFC 的 iOS 行 | `corenfc` 行 | Y05 |

### 10.6 这一层不能推出什么

不能从「读到标签」推出「完成了配件配对」；不能从「一次一个会话」推出「同一时间只有一个配件在场」——队列说明的是会话调度，不是物理在场；不能从「Mac Catalyst 有行」推出「macOS 原生支持」。

---

## 11. L8 USB 与有线限制层：一小时、三天与两个开关

### 11.1 本层回答什么

L8 回答：**有线配件在什么条件下被允许建立数据连接，管理面又能关掉什么。** 平台安全指南的 `Activating data connections securely`（`B/apple-platform-security-guide.txt:1359`）给出三段规则：

1. 若最近没有建立过数据连接，用户要用 Face ID、Touch ID 或密码激活 Thunderbolt、USB、Lightning、Smart Connector 或 SDXC 上的数据连接（`:1359—1361`）。
2. 锁屏或配件数据连接终止超过一小时后，设备不允许新建数据连接，直到解锁；这一小时内只允许「解锁状态下连接过的配件」，这些配件在最后一次连接后记住 30 天（`:1360—1362`）。
3. 若距离上次与配件建立数据连接超过三天，设备在锁屏后立即禁止新数据连接（`:1363`）。

第 2 条的理由就是那句关键原文：`Is necessary because the accessory ecosystem doesn’t provide a cryptographically reliable way to identify accessories before establishing a data connection`（`:1362`）。

### 11.2 管理面的五个配件键

| 键 | 行 | 原文要点 | 平台 | 监督 |
| --- | --- | --- | --- | --- |
| `allowBluetoothModification` | 41 | 禁止修改蓝牙设置 | iOS 11+／iPadOS 11+／macOS 13+／visionOS 27+ | iOS／visionOS |
| `allowBluetoothSharingModification` | 42 | 禁止在系统设置里修改蓝牙共享 | macOS 14+ | 未列 |
| `allowFilesUSBDriveAccess` | 87 | 禁止 Files 访问已连接的 USB 设备 | iOS 13+／iPadOS 13+ | iOS |
| `allowNFC` | 122 | 关闭 NFC | iOS 14.2+／iPadOS 14.2+ | iOS |
| `allowUSBRestrictedMode` | 170 | 为 `false` 时允许锁屏时总是连接 USB 配件 | iOS 11.4.1+／iPadOS 11.4.1+／macOS 13+ | iOS |

`allowUSBRestrictedMode` 的原文还有三句必须一起读：`If the system has Lockdown mode enabled, it ignores this value.`、`This restriction isn’t supported on the user channel.`、默认值为 `true`（`A/mdm-restrictions-payload-M.txt:170`）。三句合起来说明：**这个键不是「USB 总开关」，而是一个在特定注册通道、特定模式下才生效的能力开关。**

### 11.3 两个 Wi-Fi 键与一个已弃用键

`forceWiFiPowerOn`、`forceWiFiToAllowedNetworksOnly`、`forceWiFiWhitelisting` 在第 211—213 行（`C/readings-22.txt:137—141`）。第三个键的原文写 `Use forceWiFiToAllowedNetworksOnly instead.`，并标注 `Deprecated: iOS 14.5+ | iPadOS 14.5+`（`A/mdm-restrictions-payload-M.txt:213`）。本文把它作为「管理面键会弃用」的例子：回查件不能把弃用键当成当前能力的证据。

### 11.4 公告里唯一的有线缺陷行

USB 组件在配件族里有 5 行、1 个 CVE：CVE-2026-112479，影响句是 `A malicious USB device may be able to cause unexpected system termination or read kernel memory`（`C/readings-22.txt:12`）。这是配件族里唯一把 `USB` 与内核内存写在一起的行。它证明的是「USB 设备是一个被公告的缺陷来源」，不证明「USB 限制模式能防住它」——两者的主语不同。

### 11.5 本层核对项

| 项 | 核对什么 | 判据 | 码 |
| --- | --- | --- | --- |
| L8-1 | USB 传输未登记限制模式 | `transport=usb` 且 `usb_restricted` 空或不是 `on` | C03 |
| L8-2 | USB 链路缺限制模式读数 | `transport=usb` 且 `usb_restricted` 空 | Z07 |
| L8-3 | 管理面来源为空 | `mgmt.source` 空 | E01 |
| L8-4 | 限制键数量未登记 | `mgmt.restriction_count` 空 | E03 |
| L8-5 | 回查限制键少于五个 | `restriction_count` <5 | Z15 |
| L8-6 | 邻近性声明落在 USB 上 | `proximity=yes` 且 `transport=usb` | Z17 |

### 11.6 这一层不能推出什么

不能从「USB 限制模式开启」推出「所有 USB 配件都被拒绝」——原文只约束锁屏时的数据连接；不能从「管理面键为 false」推出「设备一定总是允许」——Lockdown Mode 会忽略该值，用户通道不支持该键；不能从「三天规则」推出「三天后配件失效」——规则约束的是**新数据连接**，不是已建立的连接或模拟音频。

---

## 12. L9 管理面回查层：210 个纯键名里的五个配件键

### 12.1 分母与分子

管理面纯键名共 210 个（`C/readings-22.txt:136`）。与配件族直接相关的键 5 个，与 Wi-Fi 相关的键 3 个（第 211—213 行）。5 个键的分布是：蓝牙修改 2 个、Files 的 USB 访问 1 个、NFC 1 个、USB 限制模式 1 个。

### 12.2 五个键没有一个回答「哪一个配件」

五个键全部是布尔能力开关。它们能回答「这台设备是否允许修改蓝牙设置」「是否允许 Files 访问 USB」「NFC 是否被关闭」「锁屏时是否总是允许 USB 配件」，不能回答「某个配件当前是否已配对」「某个配件是否通过 MFi 验证」「某个配件最后一次连接是什么时候」。**分子是 5，但分子里没有一个是逐配件读数。**

### 12.3 监督与通道约束

`allowBluetoothModification`、`allowFilesUSBDriveAccess`、`allowNFC`、`allowUSBRestrictedMode` 都标注了 `Requires supervision: iOS`（`A/mdm-restrictions-payload-M.txt:41、87、122、170`）；`allowUSBRestrictedMode` 还额外写 `This restriction isn’t supported on the user channel.`（`:170`）。这意味着：**同一台设备上，管理面能不能读回这个键，取决于注册通道；用户通道上根本不存在这条读数。** 台账因此把 `mgmt.supervised` 与 `mgmt.source` 分成两列，脚本一 E02 检查「蓝牙修改锁定后仍新建链路」的时间线矛盾。

### 12.4 声明类型：65 项里只有 1 项以配件命名

声明类型共 65 项（`C/readings-22.txt:145`），其中只有 `AudioAccessorySettings` 以 `AudioAccessory` 开头。这一项是**音频配件设置**的声明类型，不是**配件配对**的声明类型。本文不把它当成「配件装配声明」；它只说明管理面词表里「配件」这个词出现过一次，而且是在音频设置语境里。

### 12.5 本层核对项

| 项 | 核对什么 | 判据 | 码 |
| --- | --- | --- | --- |
| L9-1 | 管理面来源为空 | `mgmt.source` 空 | E01 |
| L9-2 | 蓝牙修改锁定后仍新建链路 | `allow_bluetooth=false` 且 `created_after_lock=yes` | E02 |
| L9-3 | 未登记限制键数量 | `mgmt.restriction_count` 空 | E03 |
| L9-4 | NFC 关闭但链路仍有会话 | `allow_nfc=false` 且 `nfc_session` 非空 | E04 |
| L9-5 | 描述文件已不在但链路仍在 | `source=profile` 且 `profile_present=no` | E05 |
| L9-6 | 链路归属人为空 | `mgmt.owner` 空 | E06 |
| L9-7 | 未登记移除路径 | `mgmt.removal_path` 空 | E07 |
| L9-8 | 链路标识复用却仍引用旧文档 | `reused=yes` 且 `page_url` 非空 | E08 |

### 12.6 这一层不能推出什么

不能从「键存在」推出「键在这台设备上生效」——监督与通道是前置条件；不能从「键为 false」推出「对应能力已关闭」——Lockdown Mode 可能覆盖；不能从「210 个键」推出「配件管理面很丰富」——配件族只占 5 个，且全部是能力开关。

---

## 13. L10 公告对齐层：27 行、0 行与七个 CVE

### 13.1 三族五行、27 行、7 个 CVE

配件族由五个组件构成：AccessorySetupKit 2 行／1 个 CVE、Bluetooth 9 行／2 个 CVE、HomeKit 8 行／2 个 CVE、Thread 3 行／1 个 CVE、USB 5 行／1 个 CVE，合计 27 行／7 个 CVE（`C/readings-22.txt:3`）。按平台分：iOS 26.7.2 and iPadOS 26.7.2 4 行、iOS 27.2 and iPadOS 27.2 7 行、macOS Golden Gate 27.2 5 行、macOS Sequoia 15.8.2 1 行、macOS Tahoe 26.7.2 2 行、tvOS 27.2 4 行、visionOS 27.2 2 行、watchOS 27.2 2 行（`:4`）。

### 13.2 影响句词形的八个零

在 1,266 行全量语料里，影响句列的词形计数是：`bluetooth` 2、`proximity` 16、`physical access` 3、`denial-of-service` 52、`usb` 5、`accessory` 0、`thread` 3、`homekit` 0、`pairing` 0、`paired` 2、`mfi` 0、`uwb` 0、`nfc` 0、`near field` 0、`consent` 2、`permission` 8、`entitlement` 0、`kernel` 179、`malicious app` 69、`malicious usb` 5（`C/readings-22.txt:14—33`）。配件族内部的同一组计数是：`bluetooth` 2、`proximity` 12、`denial-of-service` 9、`usb` 5、`accessory` 0、`thread` 3、`pairing` 0、`paired` 0、`consent` 2、`permission` 0（`:54—63`）。

**八个零**是 `accessory`、`homekit`、`pairing`、`mfi`、`uwb`、`nfc`、`near field`、`entitlement`。这八个词在影响句列全部不出现；其中 `accessory`、`pairing`、`mfi`、`uwb`、`nfc` 五个词正是本文的五个核心概念。**公开公告不使用这些词来描述影响，不等于这些缺陷不存在；它只说明公告的影响句采用另一套词形。**

### 13.3 组件列与影响句列的错位

组件列里 `Bluetooth` 9 行，影响句列里 `bluetooth` 只有 2 行；组件列 `HomeKit` 8 行，影响句列 `homekit` 0 行；组件列 `AccessorySetupKit` 2 行，影响句列 `accessory` 0 行。三组数字放在一起说明：**组件名是归属标签，影响句是行为描述，两者不是同一列。** 脚本二 X12 只检查「组件列 Bluetooth 行数」与「影响句 bluetooth 行数」是否相等；在真实语料里它们不相等，所以 X12 是一条会响的信号，而不是一条应当被追平的规则。

### 13.4 七个 CVE 的原文

| CVE | 组件 | 影响句 |
| --- | --- | --- |
| CVE-2026-84493 | AccessorySetupKit | A malicious app may be able to access Bluetooth without user consent |
| CVE-2026-112566 | Bluetooth | An attacker in physical proximity may be able to cause a denial-of-service |
| CVE-2026-113906 | Bluetooth | An attacker in physical proximity may be able to cause a denial-of-service |
| CVE-2026-86978 | HomeKit | An app may be able to access sensitive user data |
| CVE-2026-112596 | HomeKit | Processing a maliciously crafted video file may lead to unexpected system termination |
| CVE-2026-112595 | Thread | An attacker in physical proximity may be able to craft malicious network traffic to gain access to a Thread network |
| CVE-2026-112479 | USB | A malicious USB device may be able to cause unexpected system termination or read kernel memory |

七行里只有一行含 `consent`，零行含 `accessory`、`pairing`、`MFi`、`UWB`、`NFC`。HomeKit 的两行里有一行是视频文件解析，与配件链路无关；本文把它保留在族内，是因为组件列把它归到 HomeKit，而不是因为它的影响句与配件有关。

### 13.5 本层核对项

| 项 | 核对什么 | 判据 | 码 |
| --- | --- | --- | --- |
| L10-1 | 组件列缺 AccessorySetupKit | 计数为 0 | X01 |
| L10-2 | 组件列缺 Bluetooth／USB／Thread／HomeKit | 计数为 0 | X02—X05 |
| L10-3 | 影响句缺 proximity／pairing／accessory | 计数为 0 | X06—X08 |
| L10-4 | 两列都缺 MFi／UWB | 计数为 0 | X09—X10 |
| L10-5 | 组件列有 ASK 行但影响句无 consent | 计数关系 | X11 |
| L10-6 | Bluetooth 组件行与影响句行不等 | 计数不等 | X12 |
| L10-7 | 公告组件不在五组件内 | 不在集合 | Z16 |

### 13.6 这一层不能推出什么

不能从「27 行」推出「27 个配件缺陷」——只有 7 个 CVE；不能从「proximity 16 行」推出「16 个近场配对缺陷」——proximity 描述攻击者位置；不能从「八个零」推出「八个概念没有缺陷」——零是词形计数，不是缺陷计数。

---

## 14. L11 引用与结论层：doc.* 与十七份文档的平台坐标

### 14.1 引用件的五个字段

引用件由 `doc.page_url`、`doc.page_title`、`doc.line_ref` 三列与 `claim.evidence_ref`、`claim.closure` 两列组成（脚本一第 192—201 行）。三列文档字段回答「这句话从哪来」，两列结论字段回答「这条结论凭什么」。脚本一 G01—G06 分别检查地址为空、行锚为空、行锚非数字、行锚超过 400、地址不是 developer.apple.com、标题为空、证据引用不是 `Rxx` 形态。

### 14.2 十七份文档的平台坐标

| 框架 | 文档数 | 两平台都有 | 只有 iOS | 版本差>5 |
| --- | --- | --- | --- | --- |
| AccessorySetupKit | 5 | 0 | 5 | 0 |
| ExternalAccessory | 3 | 3 | 0 | 3 |
| CoreBluetooth | 3 | 3 | 0 | 2 |
| CoreNFC | 3 | 0 | 3 | 0 |
| NearbyInteraction | 3 | 1 | 2 | 0 |
| 合计 | 17 | 7 | 10 | 5 |

合计行与 `C/readings-22.txt:135` 一致：文档 17 份；iOS 与 macOS 都有 7；只有 iOS／iPadOS 10；只有 macOS 0；两者都无 0；版本差>5 的 5。AccessorySetupKit 五份全是 iOS／iPadOS 18.0（`C/platform-22.txt:1—10`）；CoreNFC 三份全是 iOS 11.0（`:34—40`）；NearbyInteraction 总览是 iOS 14.0／macOS 11.0，两个子页只有 iOS 14.0／watchOS 7.3（`:60—71`）；ExternalAccessory 三份全是 iOS 3.0／macOS 10.13（`:41—58`）；CoreBluetooth 三份是 iOS 5.0／macOS 10.10、iOS 5.0／macOS 10.7、iOS 6.0／macOS 10.9（`:11—33`）。

### 14.3 三处「差一点就闭合」的引用

**第一处：ExternalAccessory 的 `UISupportedExternalAccessoryProtocols`。** 它给了协议白名单（`A/externalaccessory.txt:13`），但没有给「这个 App 是否被这个厂商授权」的公开读数；授权在厂商侧（`:8`）。引用能闭合到「协议声明」，不能闭合到「厂商授权」。

**第二处：MFi 的认证 IC。** 它给了证书-挑战-应答的完整链路（`B/apple-platform-security-guide.txt:1367`），但没有给逐配件的验证结果；引用能闭合到「机制存在」，不能闭合到「这一个配件已验证」。

**第三处：AccessorySetupKit 的选择器。** 它给了「选一个具体配件」的说明（`A/accessorysetupkit_asaccessorysession.txt:249`），但没有给选择结果的稳定标识；引用能闭合到「用户选过」，不能闭合到「这个配件是谁」。

### 14.4 本层核对项

| 项 | 核对什么 | 判据 | 码 |
| --- | --- | --- | --- |
| L11-1 | 文档地址为空 | `doc.page_url` 空 | G01 |
| L11-2 | 行锚为空或非数字 | `doc.line_ref` | G02／G03 |
| L11-3 | 行锚超过 400 | 数值比较 | G03 |
| L11-4 | 地址不是 developer.apple.com | 前缀 | G04 |
| L11-5 | 文档标题为空 | `doc.page_title` 空 | G05 |
| L11-6 | 证据引用不是 Rxx | 形态 | G06 |

### 14.5 这一层不能推出什么

不能从「引用了官方文档」推出「结论已闭合」；不能从「平台行存在」推出「能力对等」；不能从「行锚在 400 以内」推出「行锚指向正确的段落」。引用件只证明**出处结构**，不证明**语义正确**；后者要靠第 24 章的十二条误读逐条核。

---
## 15. 归属矩阵：十一层 × 责任方 × 三件 × 证据

### 15.1 矩阵本体

| 层 | 责任方 | 发现件 | 链路件 | 回查件 | 证据锚点 | 最高闭合 |
| --- | --- | --- | --- | --- | --- | --- |
| L1 发现描述符 | App（描述符）＋系统（选择器） | 三属性＋选项 | — | 文档行 | `A/accessorysetupkit_asdiscoverydescriptor.txt:71、91、128` | `partial`（类级） |
| L2 同意 | 系统（弹窗）＋用户 | 方法＋弹窗 | 移除／重命名 | 管理键（无） | `A/accessorysetupkit.txt:6—7`；`A/accessorysetupkit_asaccessorysession.txt:249` | `partial`（类级） |
| L3 身份验证 | Apple（认证 IC）＋厂商（证书） | — | MFi 读数 | 指南段落 | `B/apple-platform-security-guide.txt:1366—1367、1373` | `partial`（无逐配件结果） |
| L4 ExternalAccessory | 厂商（授权）＋系统（entitlement） | 协议白名单 | — | 文档行 | `A/externalaccessory.txt:8、13` | `partial`（协议级） |
| L5 BLE／BR-EDR | 系统（协议栈） | 扫描能力 | 配对／绑定／加密 | 指南段落 | `B/apple-platform-security-guide.txt:3905`；`A/corebluetooth.txt:6` | `partial`（密钥级） |
| L6 UWB | 系统＋App | 会话配置 | 令牌 | 指南段落 | `A/nearbyinteraction.txt:19`；`B/apple-platform-security-guide.txt:3972` | `partial`（会话级） |
| L7 NFC | 系统＋App | entitlement | 会话类型 | 指南章节 | `A/corenfc.txt:8`；`A/corenfc_nfctagreadersession.txt:22` | `partial`（标签级） |
| L8 USB／有线 | 系统（限制）＋管理面 | 限制模式 | 连接条件 | 管理键＋指南 | `B/apple-platform-security-guide.txt:1359—1363`；`A/mdm-restrictions-payload-M.txt:170` | `partial`（设备级） |
| L9 管理面回查 | 管理员／MDM | — | 能力开关 | 五键 | `C/readings-22.txt:136—141` | `partial`（能力级） |
| L10 公告对齐 | Apple（公告） | — | — | 27 行 | `C/readings-22.txt:3` | `partial`（族级） |
| L11 引用与结论 | 本文（台账） | 引用结构 | 证据引用 | 平台坐标 | `C/platform-22.txt`；`C/readings-22.txt:135` | `closed`（仅结构） |

### 15.2 矩阵里最空的三个格子

**第一空：L3 的「逐配件验证结果」。** 责任方是 Apple 的认证 IC 与厂商的证书，但公开接口没有一列登记「这一次验证的结果」。这是全表唯一一个**责任方明确、证据却完全在链路之外**的格子。

**第二空：L5 的「会话级身份」。** 责任方是系统协议栈，配对／绑定／加密全部有公开口径，但没有一列回答「这个会话的对方是哪一台上次配对的配件」。

**第三空：L9 的「逐配件状态」。** 责任方是管理员与 MDM，五个键全部是能力开关，没有一列回答「某个配件当前是否已配对／已验证」。

### 15.3 责任方的三层错位

- **第一层：发现责任在 App，同意责任在系统，身份责任在 Apple 与厂商。** 三者不是同一个主体，所以「App 说发现了」「用户说同意了」「IC 说验证了」是三句不能互相替换的话。
- **第二层：协议授权在厂商，协议执行在系统。** ExternalAccessory 的原文是 `The manufacturer of an MFi accessory decides which third-party apps may communicate with their accessories.`（`A/externalaccessory.txt:8`），而系统侧只要求 App 声明 `UISupportedExternalAccessoryProtocols`（`:13`）——协议授权与协议执行分别落在两个主体上。
- **第三层：能力开关在管理员，实际约束在系统。** 管理面的五个键只说明「管理员设置了什么」，不说明「系统在这条链路上执行了什么」；Lockdown Mode 的覆盖就是一例（`A/mdm-restrictions-payload-M.txt:170`）。

### 15.4 矩阵的使用方法

1. 先填「发现件」：没有发现方法或描述符，整条记录落 W4，不再往下判。
2. 再填「链路件」：传输层、配对、加密、限制模式四列缺一，链路件不齐。
3. 最后填「回查件」：限制键、公告组件行、指南锚点三列缺一，结论不得写 `closed`。
4. 三件都齐时，最高也只能写到 `partial`，因为 L3 的逐配件结果与 L5 的会话身份仍然缺公开读数；`closed` 只用于「引用结构闭合」，不用于「身份闭合」。

---

## 16. 公开读数：这条链路上能数出来的十二组事实

本章给 R01—R20 共 20 组读数。每组只写「数了什么、数出多少、锚在哪」，不写「因此安全」。全部读数来自 `C/readings-22.txt`（160 行）、`C/platform-22.txt`（71 行）与 `.p22/matrix-out.txt`（34 次实跑）。

### 16.1 G1 全量与平台（R01—R02）

- **R01 全量**：记录行 1,266，平台去重 12，组件名去重 129，唯一 CVE 330（`C/readings-22.txt:1`）。
- **R02 平台清单**：12 个平台坐标，含 `ios 26.7.2 and ipados 26.7.2`、`ios 27.2 and ipados 27.2`、`macos golden gate 27.2`、`macos sequoia 15.8.1`、`macos sequoia 15.8.2`、`macos tahoe 26.7.1`、`macos tahoe 26.7.2`、`safari 27.2`、`tvos 27.2`、`visionos 27.2`、`watchos 27.2`、`xcode 27.2`（`:2`）。

### 16.2 G2 配件族五组件（R03—R07）

- **R03 行数与 CVE**：AccessorySetupKit 2 行／1 CVE；Bluetooth 9 行／2 CVE；HomeKit 8 行／2 CVE；Thread 3 行／1 CVE；USB 5 行／1 CVE；合计 27 行／7 CVE（`:3`）。
- **R04 平台分布**：iOS 26.7.2 and iPadOS 26.7.2=4；iOS 27.2 and iPadOS 27.2=7；macOS Golden Gate 27.2=5；macOS Sequoia 15.8.2=1；macOS Tahoe 26.7.2=2；tvOS 27.2=4；visionOS 27.2=2；watchOS 27.2=2（`:4`）。
- **R05 组件分布**：AccessorySetupKit=2；Bluetooth=9；HomeKit=8；Thread=3；USB=5（`:5`）。
- **R06 CVE 清单**：CVE-2026-112479、CVE-2026-112566、CVE-2026-112595、CVE-2026-112596、CVE-2026-113906、CVE-2026-84493、CVE-2026-86978（`:6`）。
- **R07 七行原文**：见第 13.4 节表；七行影响句的全文在 `:7—13`。

### 16.3 G3 影响句与组件列的词形（R08—R09）

- **R08 影响句列**：20 个词形的计数见第 13.2 节；八个零是 `accessory`、`homekit`、`pairing`、`mfi`、`uwb`、`nfc`、`near field`、`entitlement`（`:14—33`）。
- **R09 组件列**：`accessory` 2、`bluetooth` 9、`homekit` 8、`thread` 3、`usb` 5、`kernel` 115；`proximity`、`pairing`、`mfi`、`uwb`、`nfc`、`near field`、`consent`、`permission`、`entitlement` 全部为 0（`:34—53`）。

### 16.4 G4 配件族内部影响句（R10）

- **R10 族内分布**：`bluetooth` 2、`proximity` 12、`denial-of-service` 9、`usb` 5、`accessory` 0、`thread` 3、`pairing` 0、`paired` 0、`consent` 2、`permission` 0（`:54—63`）。族内 12 行 `proximity` 与全量 16 行的差是 4 行，落在族外。

### 16.5 G5 平台矩阵（R11—R12）

- **R11 平台行**：71 行 `<文档>,<平台>,<引入版本>`（`C/platform-22.txt`）。
- **R12 对照**：文档 17 份；两平台都有 7；只有 iOS／iPadOS 10；只有 macOS 0；两者都无 0；版本差>5 的 5（`C/readings-22.txt:135`）。

### 16.6 G6 管理面（R13—R15）

- **R13 分母**：纯键名 210；配件族键 5；Wi-Fi 键 3（`:136`）。
- **R14 五键行号**：`allowBluetoothModification` 41、`allowBluetoothSharingModification` 42、`allowFilesUSBDriveAccess` 87、`allowNFC` 122、`allowUSBRestrictedMode` 170（`:137—141`）。
- **R15 三 Wi-Fi 键行号**：`forceWiFiPowerOn` 211、`forceWiFiToAllowedNetworksOnly` 212、`forceWiFiWhitelisting` 213（`:142—144`）。

### 16.7 G7 声明类型（R16）

- **R16**：声明类型 65 项；`AudioAccessory` 前缀 1 项，即 `AudioAccessorySettings`（`:145`）。

### 16.8 G8 平台安全指南（R17）

- **R17**：指南总行数 4,886；`accessor` 45 行、`MFi` 6 行、`pairing` 53 行、`UWB` 6 行（`:159`）。四段关键原文在 `:146—156`。

### 16.9 G9—G12 规模与码表（R18—R20）

- **R18 规模**：脚本一 223 行、脚本二 220 行；夹具 13 份、916 行（`:160`；`wc -l .p22/fx/*.tsv`）。注：readings 在装配前记的是「脚本 0 行／夹具 0 份」，装配后由 `wc` 复核为 223／220 与 13／916。
- **R19 码表**：脚本一 A08＋B10＋C08＋D07＋E08＋F07＋G06＝54 信号＋V4＝58；脚本二 X12＋Y10＋Z17＝39 信号＋W4＝43；合计 101（`:160`；第 23.5 节）。
- **R20 覆盖**：34 次实跑，101／101，未覆盖 0、表外码 0（`.p22/matrix-out.txt` 末四行）。

### 16.10 读数之间的关系

- R03 的 27 行是 R08、R09 的分母；R05 的五个组件是 R09 组件列的来源；R10 是 R08 中 `proximity`／`bluetooth` 的族内切分。
- R11 的 71 行是 R12 的计算底表；R13 的 210 是 R14／R15 的分母；R17 的 4,886 是四个词形计数的底表。
- R18—R20 是**方法读数**，不是语料读数：它们证明脚本与覆盖，不证明配件状态。

### 16.11 读数不覆盖什么

不覆盖任何真实设备的配对记录、任何真实配件的序列号、任何真实链路的验证结果；不覆盖管理面键在具体设备上的生效状态；不覆盖 Apple 在归档之后新增的公告行、平台行或文档。所有读数都是**归档快照**，不是在线查询。

### 16.12 复跑方式

| 读数 | 复跑命令 | 期望 |
| --- | --- | --- |
| R01—R10 | `perl tools/readings22.pl .` | 160 行 `C/readings-22.txt` |
| R11—R12 | `wc -l C/platform-22.txt` | 71 行 |
| R13—R17 | 同上 readings 生成器 | G6—G8 各行 |
| R18 | `wc -l script1.sh script2.sh fx/*.tsv` | 223／220；916 |
| R19—R20 | `bash matrix.sh` | 34 行 + 末四行 101／101 |

---

## 17. 可见性边界：这一层读者能拿到什么

### 17.1 五类读者，五种可见性

| 读者 | 能拿到 | 拿不到 | 原因 |
| --- | --- | --- | --- |
| App 开发者 | 描述符、选择器、协议白名单、会话 API | 配件的稳定个体标识、MFi 验证结果 | 公开接口只给类级字段 |
| 配件厂商 | 自己的认证 IC 与证书流程 | 其他厂商的授权关系、系统侧的逐配件状态 | 授权是厂商侧的，系统不公开 |
| MDM 管理员 | 五个能力开关、监督与通道约束 | 某个配件是否已配对／已验证 | 键是能力级，不是记录级 |
| 安全分析者 | 公告组件行、指南段落、平台坐标 | 逐配件的链路日志与验证结果 | 公告只到族级，指南只到机制级 |
| 终端用户 | 系统选择器、移除与重命名、通用权限 | 配件的身份验证结论 | 验证在认证 IC 内，界面不展示 |

### 17.2 三个「看起来能读、其实读不到」

**第一：配对记录。** 用户能看到「已配对」的设备列表，但公开接口没有把这条记录暴露成可编程字段；脚本的 `link.pairing` 只能登记「配对方式」，不能登记「配对对象」。

**第二：MFi 结果。** 设备在验证配件时会与认证 IC 交互，但公开文档没有给出「验证通过／失败」的 API 或日志字段；`consent.mfi_verified` 只能作为台账声明，不能作为系统读数。

**第三：逐配件管理状态。** 管理面能关掉「修改蓝牙设置」「Files 访问 USB」「NFC」「USB 限制模式」，但不能查询「某个配件当前是否被允许」。

### 17.3 可见性的三条硬约束

1. **类级字段不能升级为个体级结论。** 描述符三属性、同意弹窗、协议白名单都是类级。
2. **能力开关不能升级为状态读数。** 五个管理键都是能力级。
3. **机制存在不能升级为结果存在。** 认证 IC、挑战-应答、MFi-SAP 都是机制级；结果不在公开面。

### 17.4 读者能自己复核的最小集合

- 用 `C/platform-22.txt` 复核 17 份文档的平台行；
- 用 `C/readings-22.txt:3—13` 复核 27 行与 7 个 CVE；
- 用 `C/readings-22.txt:54—63` 复核族内词形；
- 用 `A/mdm-restrictions-payload-M.txt:41、42、87、122、170` 复核五个键；
- 用 `bash matrix.sh` 与 `bash proof.sh` 复核 101 个码与二十段证明。

---

## 18. 五个读数面：发现侧、同意侧、传输侧、管理侧、公告侧

### 18.1 五个面的分工

| 面 | 回答什么 | 主要材料 | 最大分辨率 |
| --- | --- | --- | --- |
| 发现侧 | 凭什么被筛出来 | ASK 描述符、EA 协议、CoreBluetooth 扫描、CoreNFC 会话 | 类 |
| 同意侧 | 谁点了头 | ASK 弹窗、通用权限、移除／重命名 | 类 |
| 传输侧 | 链路登记了什么 | 配对／绑定／加密／密钥派生、UWB 令牌、NFC 会话、USB 限制 | 会话 |
| 管理侧 | 管理员能关什么 | 五个配件键、三个 Wi-Fi 键 | 能力 |
| 公告侧 | 缺陷被贴了什么标签 | 27 行、7 CVE、影响句词形 | 族 |

### 18.2 五个面的闭合关系

- 发现侧与同意侧可以闭合到「类」，不能闭合到「个体」；
- 传输侧可以闭合到「会话」，不能闭合到「身份」；
- 管理侧可以闭合到「能力」，不能闭合到「状态」；
- 公告侧可以闭合到「族」，不能闭合到「链路」；
- 五个面之间**没有任何一个面能单独闭合到「这一个配件」**。这就是第 1.1 节的四段判定权分属四方在读数上的表现。

### 18.3 每个面的最小证据集

| 面 | 最小证据集 | 对应脚本字段 |
| --- | --- | --- |
| 发现侧 | 方法＋描述符＋协议 | `disc.method`／`disc.descriptor`／`disc.protocol` |
| 同意侧 | 弹窗＋作用域＋移除 | `consent.prompt`／`consent.scope`／`consent.user_removal` |
| 传输侧 | 配对＋加密＋限制 | `link.pairing`／`link.encryption`／`link.usb_restricted` |
| 管理侧 | 限制键＋数量＋来源 | `readback.restriction_key`／`readback.restriction_count`／`mgmt.source` |
| 公告侧 | 组件行＋指南锚点 | `readback.advisory`／`readback.psg_anchor` |

---

## 19. 两套判定模型：J1—J4 与 Q1—Q4

### 19.1 脚本一的四档判定（J1—J4）

脚本一把每条记录的判定写成 V1—V4（正文称 J1—J4）：

- **V1（J1）**：无阻断、无错误、无提示；台账自洽。
- **V2（J2）**：只有提示级信号；台账可用，但有形态异常（如 C08 UWB 缺令牌、F01 未知归属格）。
- **V3（J3）**：有阻断或错误码；台账不自洽。
- **V4（J4）**：`claim.cell=unknown`；归属格读不到，优先级高于 V1／V2／V3。

判定顺序写在脚本一第 203—207 行：先判 `unknown` → V4；否则有阻断／错误 → V3；否则有提示 → V2；否则 V1。**先判未知**是这套模型的唯一硬规则。

### 19.2 脚本二的四级闭合（Q1—Q4）

脚本二把每个主体的闭合等级写成 W1—W4（正文称 Q1—Q4）：

- **W1（Q1）**：发现、同意、链路、回查四组字段齐全；三件对得完。
- **W2（Q2）**：有发现方法与描述符，但同意／链路／回查不齐；部分闭合。
- **W3（Q3）**：`claim.cell=unknown`；归属格读不到。
- **W4（Q4）**：没有 `disc` 方面；归属不可判。

判定顺序写在脚本二第 199—204 行：`unknown` → W3；四组齐全 → W1；有方法与描述符 → W2；否则 W4。**W3 优先于 W1**，与脚本一的 V4 优先于 V1 对称。

### 19.3 两套模型的对应关系

| 脚本一 | 脚本二 | 共同点 | 不同点 |
| --- | --- | --- | --- |
| V1 | W1 | 都表示「这一层立得住」 | V1 的分母是一条记录；W1 的分母是一个主体的三件 |
| V2 | W2 | 都表示「部分成立」 | V2 是提示级信号；W2 是字段缺口 |
| V3 | W4／W2 | 都表示「不成立」 | V3 是记录内部矛盾；W4 是根本没有发现件 |
| V4 | W3 | 都表示「读不到」 | V4 由 `claim.cell=unknown` 触发；W3 同一触发，但作用在主体上 |

**绝不合并成单一分数**：V1 可以与 X 族信号同现（R22 的干净主张配空公告），W1 也可以与 Z 族信号同现（R21 的 BAD-C／BAD-D 仍有 W1 行）。一个合并分会把「记录自洽」与「三件齐全」压成同一个数，而这两件事的分母不同。

### 19.4 判定的可复核性

每个判定都能从夹具与脚本行号复核：V4／W3 的触发点是 `claim.cell=unknown`（脚本一第 206 行、脚本二第 199 行）；V3 的阻断集合是 A01—A08 与 B01—B05（脚本一第 65 行）；W1 的字段集合是脚本二第 200—202 行的十个字段。读者不需要设备，只需要夹具与脚本。

---

## 20. 运营指标 O1—O10

本章给十个可计算的运营指标。它们不评价「安全不安全」，只描述台账与语料的覆盖质量。每个指标都给出公式、当前值与锚点；当前值来自 `.p22/matrix-out.txt` 与 `C/readings-22.txt`，不是估计。

| 号 | 指标 | 公式 | 当前值 | 锚点 |
| --- | --- | --- | --- | --- |
| O1 | 配对件完整率 | 八项字段齐全的记录数 ÷ 记录数 | 干净夹具 2/2；全错夹具 0/10 | `matrix-out.txt` R01／R02 |
| O2 | 未知归属占比 | `claim.cell=unknown` 的记录数 ÷ 记录数 | 提示夹具 1/2；全错夹具 1/10 | R04／R02 |
| O3 | UWB 时间线错位率 | `method=uwb` 且平台 <15 的记录数 ÷ UWB 记录数 | 全错夹具触发 D04 | R02／R05 |
| O4 | 三件缺口率 | Z 族触发主体数 ÷ 主体数 | 全缺夹具 6/6（含 W4 无行主体） | R21／R34 |
| O5 | 回查键不足率 | Z15 触发主体数 ÷ 有回查件的主体数 | R21／R24／R34 触发 | `matrix-out.txt` |
| O6 | 公告零命中词形数 | 影响句计数为 0 的词形数 | 8/20 | `readings-22.txt:14—33` |
| O7 | CVE 覆盖率 | 配件族 CVE 数 ÷ 全量唯一 CVE 数 | 7/330 | `readings-22.txt:1、3` |
| O8 | 平台不对称计数 | 只有 iOS 的文档数 ÷ 17 | 10/17（只有 macOS 0/17） | `readings-22.txt:135` |
| O9 | 台账拒收率 | A05／Y09 拒收行数 ÷ 输入行数 | P16 1 行；P17 1 行 | 第 23.1 节 P16、P17 |
| O10 | 码覆盖验收 | 已触发不同码数 ÷ 期望码总数 | 101/101 | `matrix-out.txt` 末四行 |

### 20.1 指标的用法

- **O1、O3、O4、O5** 是台账质量指标：它们只说明「这份台账写全了没有」，不说明「设备安全不安全」；
- **O2** 是可见性指标：它的值越高，说明越多记录的归属格读不到，结论越应该写成 `unknown`；
- **O6、O7、O8** 是语料指标：它们描述公开文档的覆盖形态，不描述缺陷数量；
- **O9、O10** 是可复现指标：它们证明脚本与判据可达，不证明设备状态。

### 20.2 指标的红线

1. **O1—O5 不能跨夹具相加**：不同夹具服务不同码，相加没有意义；
2. **O6 的 8 个零命中不能读成「8 类缺陷不存在」**：它只说明公告影响句不用这些词；
3. **O8 的 10/17 不能读成「59% 的接口不可用」**：分母是文档数，不是功能数；0 份 macOS-only 也不能读成「macOS 没有配件能力」；
4. **O10 的 101/101 不能替代设备验证**：它只证明每个码都有夹具能触发。

### 20.3 指标的复跑

| 指标 | 复跑命令 | 期望 |
| --- | --- | --- |
| O1—O5 | `bash matrix.sh` | 34 行逐次读数 + 末四行汇总 |
| O6—O8 | `perl tools/readings22.pl .` | `C/readings-22.txt` 160 行 |
| O9 | `bash proof.sh 报告.md` | P16／P17 各一行拒收 |
| O10 | `tail -4 matrix-out.txt` | `101/101` |

---
## 21. 只读核验脚本一：外接配件配对台账逐字段审查器

### 21.1 这个脚本回答什么

脚本一回答一个问题：**一条外接配件配对台账自己站不站得住。** 它把一条记录拆成七个命名空间（id、disc、consent、link、mgmt、claim、doc；其中 id 内含链路级标识），逐字段检查结构、值域、平台时间线、同意与链路的一致性与引用形式，最后给每条记录一个 J1—J4 判定（脚本里写作 V1—V4）。它不连接任何配件、不扫描任何射频、不读取任何配对记录，只读文本。

### 21.2 输入格式

每行三列：`<记录标识>,<字段名>,<值>`。两种记录标识前缀：`AS_`（AccessorySetupKit 会话）与 `EA_`（ExternalAccessory 通道）。空行与 `#` 开头行忽略，行尾 CR 忽略，值内不能含逗号。七个命名空间共 50 个字段，逐一如下：

| 命名空间 | 字段 | 说明 |
| --- | --- | --- |
| `id.*` | `link_name`／`transport`／`platform`／`record_kind` | 链路级标识 |
| `disc.*` | `method`／`company_id`／`name_substring`／`service_uuid`／`protocol`／`entitlement`／`usage_desc`／`app_extension` | 发现面 |
| `consent.*` | `prompt`／`scope`／`mfi_verified`／`mfi_evidence`／`user_removal`／`bluetooth_permission`／`local_network`／`secret_inline` | 同意面 |
| `link.*` | `ble_role`／`br_edr`／`pairing`／`bonding`／`encryption`／`key_derivation`／`usb_restricted`／`nfc_session`／`uwb_token`／`uwb_config` | 传输面 |
| `mgmt.*` | `source`／`owner`／`restriction_count`／`allow_bluetooth`／`allow_nfc`／`usb_restricted_key`／`supervised`／`profile_present`／`removal_path`／`reused`／`created_after_lock` | 管理面 |
| `claim.*` | `cell`／`consent_scope`／`mfi_claim`／`proximity`／`closure`／`evidence_ref` | 结论 |
| `doc.*` | `page_url`／`page_title`／`line_ref` | 引用 |

`consent.secret_inline` 是同意命名空间下的拒收标记字段，只接受 `yes`／`no`；脚本一 B10 在它为 `yes` 时报警。

### 21.3 信号族与行号

| 族 | 码 | 数量 | 位置 | 拦什么 |
| --- | --- | --- | --- | --- |
| A 结构与取值 | A01—A08 | 8 | 第 84—91、127—130 行 | 前缀、三列、私钥／长载荷拒收、重复冲突、传输／方法／协议缺失、MFi 证据类型 |
| B 发现与同意 | B01—B10 | 10 | 第 132—147 行 | 传输集合、显示名、方法集合、BLE 角色、NFC 类型、公司标识、弹窗、扩展、密钥内联 |
| C 链路一致性 | C01—C08 | 8 | 第 149—156 行 | 配对与加密、密钥派生、USB 限制、MFi 与协议、本地网络、蓝牙权限、UWB 令牌 |
| D 同意与身份 | D01—D07 | 7 | 第 158—166 行 | MFi 证据、设备级同意、NFC entitlement、UWB 时间线、移除路径、类级描述符、描述符共用 |
| E 管理面 | E01—E08 | 8 | 第 168—179 行 | 来源、时间线、限制键数量、NFC 冲突、孤儿、归属人、移除路径、标识复用 |
| F 结论 | F01—F07 | 7 | 第 181—190 行 | 未知格、`absent` 与方法矛盾、同意作用域、MFi 宣称、邻近性、闭合无证据、`present` 无方法 |
| G 引用 | G01—G06 | 6 | 第 192—201 行 | 地址、行锚、行锚数字、400 上限、域名、标题、证据引用 |
| V 判定 | V1—V4 | 4 | 第 203—207 行 | J1／J2／J3／J4 |

合计 54 个信号码 + 4 档判定 = 58。

### 21.4 判定顺序

```text
读入所有行 → 按记录聚合 → 对每条记录：
  1. 若 claim.cell == unknown → V4（先判未知）
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

干净夹具 `fx/s1-good.tsv`（两条完整记录，100 个字段）输出：

```text
记录 AS_L1 判定=V1 信号数=0
记录 EA_L2 判定=V1 信号数=0
----
配对记录数= 2
字段行数= 100
不同信号码= 0
信号条数= 0
阻断信号条数= 0
判定分布= V1=2 V2=0 V3=0 V4=0
```

全错夹具 `fx/s1-bad.tsv`（十个记录，374 个字段）输出：

```text
记录 XX_BAD1 判定=V3 信号数=71
记录 AS_BAD2 判定=V4 信号数=14
记录 EA_BAD3 判定=V3 信号数=5
记录 AS_BAD4 判定=V3 信号数=10
记录 AS_BAD5 判定=V3 信号数=3
记录 AS_BAD6 判定=V3 信号数=3
记录 AS_BAD7 判定=V3 信号数=3
记录 AS_BAD8 判定=V3 信号数=2
记录 AS_D1 判定=V3 信号数=2
记录 AS_D2 判定=V3 信号数=2
----
配对记录数= 10
字段行数= 374
不同信号码= 46
信号条数= 115
阻断信号条数= 71
判定分布= V1=0 V2=0 V3=9 V4=1
```

提示夹具 `fx/s1-warn.tsv`（两条记录，100 个字段）输出：

```text
记录 AS_L1 判定=V4 信号数=1
记录 AS_W2 判定=V2 信号数=1
----
配对记录数= 2
字段行数= 100
不同信号码= 2
信号条数= 2
阻断信号条数= 0
判定分布= V1=0 V2=1 V3=0 V4=1
```

三段输出都是脚本原样打印，未删行。全错夹具里 `V4=1` 是那条 `claim.cell=unknown` 的记录，它即使其他字段齐全也落 V4；提示夹具里 `AS_L1` 的 V4 是人为把归属格改成 `unknown` 的结果，`AS_W2` 的 V2 是 C08（UWB 缺令牌）这一条提示级信号。

### 21.7 设计取舍

**取舍一：先判未知，再判对错。** `F01` 的判定写在第 181 行，早于所有其他结论检查；一旦 `claim.cell=unknown`，整条记录直接 V4，后面的检查仍然执行并计数，但不改变判定。原因是：归属格未知时，「其他字段都齐」不能推出「可读」，只能推出「台账写得全」。

**取舍二：把结构矛盾与形态提示分开。** A 族（结构）与 B 族的前五码是 V3；C08（UWB 缺令牌）、F01（未知格）是 V2 或 V4。分界不是按「严重程度」，而是按「是不是矛盾」：数据不成立是矛盾，数据成立但形态少见是提示。C08 被特意留在提示级，因为「UWB 链路没有令牌」在台账里可能只是漏填，不一定是结构错误。

**取舍三：拒绝可疑取值，而不是清洗。** A05 对私钥块、超过 120 字符的载荷、字段名含 `secret`／`password`／`token`／`payload` 的明文一律拒收（第 74—80 行），拒收后该行不进入台账。这意味着台账不会保存任何可能是凭据的字符串；P16 用一段 150 字符的 `A` 载荷验证了这条路径（第 23.3 节）。

**取舍四：不发散到语义。** 脚本不检查配件是否存在、认证 IC 是否通过、配对记录是否真实。这些都需要设备或配件，超出「离线只读」的边界。

### 21.8 已知局限

1. **`link.bonding` 与 `link.key_derivation` 没有单独的阻断码。** 它们被读入并参与 C01／C02 的一致性检查，但「绑定为 yes 却密钥派生为空」目前不产生独立信号。这是判据覆盖面的一处缺口，补码需要新的定向夹具，本文不补一个没有实跑覆盖的码。
2. **`disc.br_edr` 只作为登记字段。** 脚本不检查 BLE 与 BR/EDR 的互斥关系，因为公开文档没有给出这条互斥规则。
3. **公司标识只接受四位十六进制。** 这是 16 位公司标识的文本表示约定；BLE 规范的公司标识是 16 位，但归档只给出四个十六进制字符的写法。
4. **平台字段只做数字比对。** `id.platform` 与 D04 的时间线检查只比较主版本，不解析平台名；平台名合法性留给脚本二的平台矩阵。

### 21.9 使用方法

1. 把台账写成三列文本，一条记录一组行，字段名用 21.2 的七个命名空间；
2. `bash script1.sh 台账.tsv` 得到逐记录判定与汇总；
3. 加 `-q` 只看汇总；`-h` 看用法；
4. 出现 V3 时，按 stderr 的码逐条回查第 21.3 节的行号；
5. 出现 V4 时，先去补 `claim.cell` 的公开依据，不要先改其他字段。

### 21.10 源码

下面这段源码与 `.p22/script1.sh` 逐字节相同（第 23.3 节 P18 会比对）。它只依赖 `awk`、`tr`、`cat` 与 `mktemp`，不调用任何网络工具、不读取钥匙串、不打开任何配件会话。

```bash
#!/usr/bin/env bash
# accessory-pairing-ledger-review.sh —— 外接配件配对台账逐字段审查器（离线 / 只读 / 不联网 / 不碰设备）
# 输入：一份或多份台账文本，每行三列：<配对记录标识>,<字段名>,<取值>
# 输出：逐条信号码（stderr） + 每条记录的判定（stdout） + 汇总
# 本脚本只判定「一个外接配件被登记成一行配对台账之后，这行台账自己站不站得住」：
# 不含任何配件发现、配对、授权、传输或固件更新的操作步骤，
# 不含任何绕过同意、冒用 MFi 认证、解除 USB 限制或读取设备数据的手法，不连接任何配件。
# 输入只接受标识、字段名与短取值；取值形似私钥块、形似口令、超长 Base64 载荷或整段
# 传输日志时一律按 A05 拒收并要求删除该字段（判据见记录循环开头）。
# 本脚本不联网、不调用 bluetoothctl／ioreg／system_profiler／security／defaults／profiles／
#       log／curl／osascript 等任何命令行工具、不读取钥匙串、不打开任何配件会话。
#       唯一写出目标是 mktemp -d 创建的临时目录，退出时删除，本实现不向其写入任何字节。
set -u
LC_ALL=C; export LC_ALL

usage() {
  cat <<'EOF'
用法: accessory-pairing-ledger-review.sh [-q] 台账文件 [...]
  -q  不输出逐记录判定行；-h/--help 显示本帮助
台账行格式: <记录标识>,<字段名>,<取值>    # 开头与空行忽略，行尾 CR 忽略，值里不能含逗号
记录标识前缀（两类）: AS_ AccessorySetupKit 会话／EA_ ExternalAccessory 通道
字段命名空间（八个）:
  id.*     记录标识（link_name / transport / platform / record_kind）
  disc.*   发现（method / company_id / name_substring / service_uuid / protocol /
           entitlement / usage_desc / app_extension）
  consent.*同意（prompt / scope / mfi_verified / mfi_evidence / user_removal /
           bluetooth_permission / local_network）
  link.*   链路（ble_role / br_edr / pairing / bonding / encryption / key_derivation /
           usb_restricted / nfc_session / uwb_token / uwb_config）
  mgmt.*   管理面（source / owner / restriction_count / allow_bluetooth / allow_nfc /
           usb_restricted_key / supervised / profile_present / removal_path / reused /
           created_after_lock）
  claim.*  结论（cell / consent_scope / mfi_claim / proximity / closure / evidence_ref）
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

TMPD=$(mktemp -d "${TMPDIR:-/tmp}/acc22.XXXXXX") || exit 2
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
function major(v,   n, a) { n = split(v, a, "."); return (n >= 1 && a[1] ~ /^[0-9]+$/) ? a[1] + 0 : -1 }
function bad_value(f, v) {
  if (v == "") return 0
  if (v ~ /BEGIN [A-Z ]*PRIVATE KEY/) return 1
  if (length(v) > 120) return 1
  if (f ~ /(secret|password|passwd|otp|token|payload)/ && v !~ /^(yes|no|true|false|none|empty|present|absent)$/) return 1
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
  if (id !~ /^(AS_|EA_)/) emit("A01", id, "记录标识前缀不在 AS_／EA_ 之内")
  if (!(id in order)) { order[id] = ++nrec; ids[nrec] = id }
  key = id SUBSEP f
  if (key in V && V[key] != val) emit("A06", id, "字段 " f " 重复且取值冲突")
  V[key] = val
  fields[id]++
}
END {
  delete shared_disc
  for (i = 1; i <= nrec; i++) {
    id = ids[i]
    cid = get(id, "disc.company_id", "")
    nsub = get(id, "disc.name_substring", "")
    if (cid != "" || nsub != "") shared_disc[cid "|" nsub]++
  }
  for (i = 1; i <= nrec; i++) {
    id = ids[i]
    tr = get(id, "id.transport", "")
    plat = get(id, "id.platform", "")
    method = get(id, "disc.method", "")
    cid = get(id, "disc.company_id", "")
    proto = get(id, "disc.protocol", "")
    ent = get(id, "disc.entitlement", "")
    appext = get(id, "disc.app_extension", "")
    prompt = get(id, "consent.prompt", "")
    scope = get(id, "consent.scope", "")
    mfi = get(id, "consent.mfi_verified", "")
    mev = get(id, "consent.mfi_evidence", "")
    removal = get(id, "consent.user_removal", "")
    btperm = get(id, "consent.bluetooth_permission", "")
    lan = get(id, "consent.local_network", "")
    role = get(id, "link.ble_role", "")
    pair = get(id, "link.pairing", "")
    enc = get(id, "link.encryption", "")
    kd = get(id, "link.key_derivation", "")
    usbr = get(id, "link.usb_restricted", "")
    nfcs = get(id, "link.nfc_session", "")
    uwbt = get(id, "link.uwb_token", "")

    if (tr == "") emit("A02", id, "id.transport 缺失")
    if (method == "") emit("A03", id, "disc.method 缺失")
    if (proto == "") emit("A04", id, "disc.protocol 缺失")
    if (mfi == "yes" && mev != "ic") emit("A07", id, "MFi 已验证但证据类型不是认证 IC")

    if (tr != "" && tr != "ask" && tr != "externalaccessory" && tr != "usb" && tr != "nfc" && tr != "uwb")
      emit("B01", id, "传输层不是 ask／externalaccessory／usb／nfc／uwb")
    if (get(id, "id.link_name", "") == "") emit("B02", id, "链路显示名为空")
    if (method != "" && method != "ask" && method != "externalaccessory" && method != "uwb" && method != "nfc" && method != "ble")
      emit("B03", id, "发现方法不是 ask／externalaccessory／uwb／nfc／ble")
    if (tr == "ask" && role != "central" && role != "peripheral")
      emit("B04", id, "AccessorySetupKit 会话未登记 BLE 角色")
    if (nfcs != "" && nfcs != "ndef" && nfcs != "tag" && nfcs != "none")
      emit("B05", id, "NFC 会话类型不是 ndef／tag／none")
    if (cid != "" && cid !~ /^[0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f]$/)
      emit("B06", id, "公司标识不是四位十六进制")
    if (prompt == "none" && (method == "ask" || method == "externalaccessory"))
      emit("B07", id, "发现方法需要同意但弹窗被登记为 none")
    if (method == "ask" && prompt == "") emit("B08", id, "AccessorySetupKit 会话未登记同意弹窗")
    if (appext == "yes" && method == "nfc") emit("B09", id, "App 扩展登记了 NFC 发现")
    if (get(id, "consent.secret_inline", "") == "yes") emit("B10", id, "密钥材料被内联登记")

    if (pair == "none" && enc == "yes") emit("C01", id, "配对方式为 none 但加密开启")
    if (enc == "yes" && kd == "none") emit("C02", id, "加密开启但密钥派生为 none")
    if (tr == "usb" && usbr != "on") emit("C03", id, "USB 传输未登记限制模式")
    if (mfi == "yes" && proto == "") emit("C04", id, "MFi 已验证但没有声明协议")
    if (mfi == "no" && proto != "") emit("C05", id, "未验证 MFi 却声明了配件协议")
    if (lan == "yes" && get(id, "disc.service_uuid", "") == "") emit("C06", id, "本地网络开启但缺少服务 UUID")
    if (btperm == "denied" && (method == "ask" || method == "ble")) emit("C07", id, "蓝牙权限被拒但仍登记蓝牙发现")
    if (tr == "uwb" && uwbt == "") emit("C08", id, "UWB 链路缺少会话令牌")

    if (mfi == "yes" && mev == "") emit("D01", id, "MFi 已验证但证据为空")
    if (scope == "device" && prompt == "none") emit("D02", id, "同意范围为设备级但弹窗为 none")
    if (method == "nfc" && ent != "yes") emit("D03", id, "NFC 发现未登记 entitlement")
    if (method == "uwb" && major(plat) >= 0 && major(plat) < 15) emit("D04", id, "UWB 会话声明在 iOS 15 之前")
    if (removal == "no" && tr == "ask") emit("D05", id, "AccessorySetupKit 链路未登记移除路径")
    if (scope == "device" && (cid != "" || get(id, "disc.name_substring", "") != "" || get(id, "disc.service_uuid", "") != ""))
      emit("D06", id, "同意范围为设备级但描述符只到类级")
    if ((cid != "" || get(id, "disc.name_substring", "") != "") && shared_disc[cid "|" get(id, "disc.name_substring", "")] + 0 > 1)
      emit("D07", id, "同一描述符被多条链路共用")

    if (get(id, "mgmt.source", "") == "") emit("E01", id, "管理面来源为空")
    if (get(id, "mgmt.allow_bluetooth", "") == "false" && get(id, "mgmt.created_after_lock", "") == "yes")
      emit("E02", id, "蓝牙修改锁定后仍新建链路，时间线矛盾")
    if (get(id, "mgmt.restriction_count", "") == "") emit("E03", id, "未登记限制键数量")
    if (get(id, "mgmt.allow_nfc", "") == "false" && nfcs != "" && nfcs != "none")
      emit("E04", id, "NFC 管理面关闭但链路仍登记 NFC 会话")
    if (get(id, "mgmt.source", "") == "profile" && get(id, "mgmt.profile_present", "") == "no")
      emit("E05", id, "来源为描述文件但描述文件已不在，链路成孤儿")
    if (get(id, "mgmt.owner", "") == "") emit("E06", id, "链路归属人为空")
    if (get(id, "mgmt.removal_path", "") == "") emit("E07", id, "未登记移除路径")
    if (get(id, "mgmt.reused", "") == "yes" && get(id, "doc.page_url", "") != "")
      emit("E08", id, "链路标识被复用却仍引用旧文档行")

    if (get(id, "claim.cell", "") == "unknown") emit("F01", id, "归属格为 unknown")
    if (get(id, "claim.cell", "") == "absent" && method != "") emit("F02", id, "结论为 absent 但发现方法存在")
    if (get(id, "claim.consent_scope", "") == "device" && scope != "" && scope != "device")
      emit("F03", id, "结论宣称设备级同意但台账登记为类级")
    if (get(id, "claim.mfi_claim", "") == "yes" && mev != "ic") emit("F04", id, "结论宣称 MFi 已验证但证据不是认证 IC")
    if (get(id, "claim.proximity", "") == "yes" && tr != "ble" && tr != "uwb" && tr != "thread")
      emit("F05", id, "邻近性声明与传输层不符")
    if (get(id, "claim.closure", "") == "closed" && get(id, "claim.evidence_ref", "") == "")
      emit("F06", id, "结论为闭合但无证据引用")
    if (get(id, "claim.cell", "") == "present" && method == "") emit("F07", id, "结论为 present 但发现方法为空")

    if (get(id, "doc.page_url", "") == "") emit("G01", id, "文档地址为空")
    if (get(id, "doc.line_ref", "") == "") emit("G02", id, "文档行锚为空")
    if (get(id, "doc.line_ref", "") != "" && get(id, "doc.line_ref", "") !~ /^[0-9]+$/)
      emit("G03", id, "文档行锚不是数字")
    else if (get(id, "doc.line_ref", "") + 0 > 400) emit("G03", id, "文档行锚超出行数上限 400")
    if (get(id, "doc.page_url", "") != "" && get(id, "doc.page_url", "") !~ /^https:\/\/developer\.apple\.com\//)
      emit("G04", id, "文档地址不是 developer.apple.com")
    if (get(id, "doc.page_title", "") == "") emit("G05", id, "文档标题为空")
    if (get(id, "claim.evidence_ref", "") != "" && get(id, "claim.evidence_ref", "") !~ /^R[0-9][0-9]$/)
      emit("G06", id, "证据引用不是 Rxx 形态")

    if (id in blocked || id in errored || id in warned) {
      if (id in blocked) verdict = "V3"; else if (id in errored) verdict = "V3"; else verdict = "V2"
    } else verdict = "V1"
    if (get(id, "claim.cell", "") == "unknown") verdict = "V4"
    vcnt[verdict]++
    if (!QUIET) print "记录 " id " 判定=" verdict " 信号数=" per[id]+0
  }
  print "----"
  print "配对记录数= " nrec
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

## 22. 只读核验脚本二：配件链路三件差集与公告子词表比对器

### 22.1 这个脚本回答什么

脚本二回答另一个问题：**一个主体的发现件、链路件、回查件对不对得上，公告语料有没有覆盖这条链路。** 它读三份文本，输出 X 族（公告子词表）、Y 族（平台矩阵）、Z 族（三件差集）与 W 级闭合（W1—W4）。它不读设备、不读配件、不读链路，只做集合计数与字段齐备性判定。

### 22.2 三份输入

1. **主张台账**：`<主体>,<方面.字段>,<取值>`，方面是 `disc`／`consent`／`link`／`readback`／`claim`；
2. **平台矩阵**：`<文档>,<平台>,<引入版本>`；
3. **公告语料**：TSV 六列 `file`／`platform`／`component`／`cve`／`impact`／`avail`，首行可为表头。

三份文件都在命令行给出；脚本内部用 `FNR == 1 { fi++ }` 切换阶段，**不使用 `getline`**（这一点由 P1 检查）。

### 22.3 主张字段

| 方面 | 字段 | 说明 |
| --- | --- | --- |
| `disc` | `transport`／`method`／`descriptor`／`protocol`／`entitlement` | 发现件 |
| `consent` | `prompt`／`scope`／`mfi`／`mfi_evidence` | 同意件 |
| `link` | `pairing`／`encryption`／`usb_restricted`／`nfc_session`／`uwb_token` | 链路件 |
| `readback` | `restriction_key`／`restriction_count`／`advisory`／`psg_anchor` | 回查件 |
| `claim` | `closure`／`cell`／`proximity` | 结论 |

### 22.4 信号族与行号

| 族 | 码 | 数量 | 位置 | 拦什么 |
| --- | --- | --- | --- | --- |
| X 公告子词表 | X01—X12 | 12 | 第 124—135 行 | 五个组件缺失、proximity／pairing／accessory／MFi／UWB 缺失、consent 缺失、Bluetooth 行数不等 |
| Y 平台矩阵 | Y01—Y10 | 10 | 第 84—94、146—156 行 | 五份关键文档缺 iOS 行、ExternalAccessory 出现 macOS 行、版本差>5、未知平台、格式拒收、版本非数字 |
| Z 三件差集 | Z01—Z17 | 17 | 第 180—197 行 | 发现／同意／链路／回查四组缺件、闭合无证据、MFi 锚点错、限制键不足、组件越界、邻近性错配 |
| W 闭合等级 | W1—W4 | 4 | 第 199—204 行 | Q1／Q2／Q3／Q4 |

合计 39 个信号码 + 4 级闭合 = 43。另有 `Z00`（主张行格式／路径／长载荷拒收）与 `Y09`（平台行格式拒收）两条输入校验码；`Z00` 不在 101 码表内，`Y09` 在表内。

### 22.5 闭合判定顺序

```text
读入三份文件 → 按主体聚合 → 对每个主体：
  1. 若没有 disc 方面 → W4（先判不可判）
  2. 否则若 claim.cell == unknown → W3
  3. 否则若发现／同意／链路／回查四组齐全 → W1
  4. 否则若有方法且有描述符 → W2
  5. 否则 → W4
输出逐主体闭合等级 + 汇总（主体数、文档数、公告行数、组件计数、影响句计数、不同码数、信号条数、闭合分布）
```

### 22.6 实跑样例

干净夹具（`s2-claims-good.tsv`＋`s2-platform-good.tsv`＋`s2-adv-good.tsv`）输出：

```text
主体 ASK-1 闭合等级=W1 信号数=0
主体 EA-1 闭合等级=W1 信号数=0
主体 USB-1 闭合等级=W1 信号数=0
----
主张主体数= 3
平台文档数= 8
公告行数= 7
组件列 AccessorySetupKit= 1 Bluetooth= 1 USB= 1 Thread= 1 HomeKit= 1
影响句 proximity= 3 pairing= 1 accessory= 3 consent= 1
不同信号码= 0
信号条数= 0
闭合等级分布= W1=3 W2=0 W3=0 W4=0
```

全缺夹具（`s2-claims-bad.tsv`＋`s2-platform-bad.tsv`＋`s2-adv-uneven.tsv`）输出：

```text
主体 BAD-A 闭合等级=W3 信号数=5
主体 BAD-B 闭合等级=W4 信号数=12
主体 BAD-C 闭合等级=W1 信号数=2
主体 BAD-D 闭合等级=W1 信号数=1
主体 BAD-F 闭合等级=W2 信号数=5
----
主张主体数= 6
平台文档数= 7
公告行数= 5
组件列 AccessorySetupKit= 1 Bluetooth= 1 USB= 1 Thread= 1 HomeKit= 1
影响句 proximity= 0 pairing= 0 accessory= 0 consent= 0
不同信号码= 34
信号条数= 43
闭合等级分布= W1=2 W2=1 W3=1 W4=1
```

第二段只打印了五个主体：`BAD-E` 没有 `disc` 方面，脚本在第 180 行发 W4 后 `continue`，所以它计入信号但不出现在逐主体行里；`W4=1` 是 `BAD-B` 的闭合等级，`BAD-E` 的 W4 没有进入分布。**这是脚本的已知统计口径，不是漏行。** 另外 `BAD-C` 与 `BAD-D` 尽管有 Z 族信号，仍因字段齐全落 W1；这正说明「闭合等级」与「信号数量」不是同一个维度。

### 22.7 设计取舍

**取舍一：没有发现件就不往下判。** 一个主体在 `disc` 方面一条字段都没有时，脚本先发 W4 并 `continue`（第 180 行），不再逐项检查同意件、链路件与回查件。原因是：发现件是三件的第一件，缺了它，后面三件即使齐也只能说明「台账写得全」，不能说明「这条链路存在」。代价是这类主体的 Z 族信号不逐条打印，只计入汇总；第 22.6 节已把这个口径写明。

**取舍二：闭合等级与信号数量正交。** `BAD-C` 与 `BAD-D` 有 Z 族信号却仍落 W1，因为 W1 的条件是「三件的必填字段都非空」，不是「没有任何信号」。反过来，R22 与 R33 的 `W1` 都带 X 族信号：三件齐，公告词表却不覆盖。**把闭合等级当成质量分，是本脚本最容易被误读的地方**；W1 只回答「齐不齐」，不回答「对不对」。

**取舍三：公告只认五个组件。** X 族的组件计数只在 AccessorySetupKit、Bluetooth、USB、Thread、HomeKit 五个词形上进行；回查件的 `readback.advisory` 若写这五个之外的值，Z16 报警。原因是真实语料的组件列有 129 个名字，不先限定族，任何计数都没有分母。

**取舍四：平台差异写成信号，不写成错误。** Y06 在 ExternalAccessory 出现 macOS 行时报警，Y07 在同一文档两平台版本差超过 5 时报警。这两条不是「文档写错了」，而是「平台坐标出现本文需要人工解释的差异」；脚本只负责把它标出来，解释留在第 14.2 节与 U13。

### 22.8 已知局限

1. **`Z00` 不在 101 码表内。** 它是主张行的输入校验码（不是三列、标识或字段为空、取值形似路径／凭据／长载荷），触发后整行跳过。34 次实跑的夹具都是合法三列，所以 `Z00` 没有实跑记录；它与 `Y09` 共用 `badv` 判据，`Y09` 的拒收路径由 P17 实证。
2. **版本号只支持整数或一位小数。** `num(v)` 的正则是 `^[0-9]+(\.[0-9]+)?$`；像 `26.7.2` 这样的三段版本会被判为非数字并触发 Y10。平台夹具因此只写 `18`、`10.13` 这类两段以内的版本；把真实平台矩阵原样喂进来会得到一组 Y10 信号。这是判据的已知限制，不是语料错误。
3. **`readback.psg_anchor` 只查数值段落。** Z13 只在 `consent.mfi=yes` 时检查锚点是否落在 1366／1367／1373；其他段落的锚点只要非空就通过，不校验它是否真的支撑该结论。
4. **`claim.closure` 只认 `closed` 一词。** Z12 只在结论为 `closed` 时检查回查件；`partial` 与 `unknown` 没有对应的「够不够格」检查，因为公开口径没有给出这两档的字段门槛。
5. **W2 与 W4 的差别只在发现件。** `m != "" && dsc != ""` 落 W2，否则落 W4；同意件、链路件、回查件全缺但发现件齐的主体仍落 W2。这是闭合等级的设计口径，不表示 W2 比 W4「更接近正确」。

### 22.9 使用方法

1. 准备三份文本：主张台账（五个方面、三列）、平台矩阵（三列）、公告语料（六列 TSV，首行可为表头）；
2. `bash script2.sh 主张.tsv 平台.tsv 公告.tsv` 得到逐主体闭合等级与汇总；
3. 加 `-q` 只看汇总；`-h` 看用法；
4. 先看 X 族：公告词表缺哪个词形；再看 Y 族：平台行缺哪一份文档；最后看 Z 族：三件缺哪一件；
5. 闭合等级落 W3／W4 时，先补 `claim.cell` 与 `disc` 方面，不要先改其他字段。

### 22.10 源码

下面这段源码与 `.p22/script2.sh` 逐字节相同（第 23.3 节 P18 会比对）。它只依赖 `awk`、`tr`、`cat` 与 `mktemp`，不调用任何网络工具、不读取设备状态、不打开任何配件会话。


```bash
#!/usr/bin/env bash
# accessory-link-diff.sh —— 配件链路三件差集与公告子词表比对器（离线 / 只读 / 不联网）
# 输入三份文本：
#   1) 主张台账：<主体>,<方面.字段>,<取值>   （方面 = disc／consent／link／readback／claim）
#   2) 平台矩阵：<文档>,<平台>,<引入版本>
#   3) 公告语料：TSV，六列 file／platform／component／cve／impact／avail（首行可为表头）
# 输出：X 族（公告子词表）、Y 族（平台矩阵）、Z 族（三件差集）信号码与 W 级闭合判定。
# 本脚本只做集合计数与字段齐备性判定：不含任何配件发现、配对、授权或传输的操作步骤，
# 不含任何绕过同意、冒用 MFi 认证或解除 USB 限制的手法，不连接任何配件或网络。
# 不调用 bluetoothctl／ioreg／system_profiler／security／profiles／defaults／curl 等工具，
# 不读取设备状态；唯一写出目标是 mktemp -d 创建的临时目录，退出时删除，本实现不向其写入任何字节。
set -u
LC_ALL=C; export LC_ALL

usage() {
  cat <<'EOF'
用法: accessory-link-diff.sh [-q] 主张台账 平台矩阵 公告语料
  -q  不输出逐主体判定行；-h/--help 显示本帮助
主张行格式: <主体>,<方面.字段>,<取值>
  方面字段: disc.transport / disc.method / disc.descriptor / disc.protocol / disc.entitlement /
            consent.prompt / consent.scope / consent.mfi / consent.mfi_evidence /
            link.pairing / link.encryption / link.usb_restricted / link.nfc_session / link.uwb_token /
            readback.restriction_key / readback.restriction_count / readback.advisory /
            readback.psg_anchor / claim.closure / claim.cell / claim.proximity
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

TMPD=$(mktemp -d "${TMPDIR:-/tmp}/acld22.XXXXXX") || exit 2
trap 'rm -rf "$TMPD"' EXIT INT TERM

awk -v QUIET="$QUIET" '
function emit(code, subj, msg) {
  sig++; cnt[code]++
  print code "\t" (subj == "" ? "-" : subj) "\t" msg > "/dev/stderr"
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

  compAsk = compBT = compUSB = compThread = compHK = 0
  hitProx = hitPair = hitAcc = hitMFi = hitUWB = hitConsent = hitBTimp = 0
  for (i = 1; i <= nadv; i++) {
    c = advcomp[i]; m = advimp[i]
    if (c == "accessorysetupkit") compAsk++
    if (c == "bluetooth") compBT++
    if (c == "usb") compUSB++
    if (c == "thread") compThread++
    if (c == "homekit") compHK++
    if (has(m, "proximity")) hitProx++
    if (has(m, "pairing") || has(m, "paired")) hitPair++
    if (has(m, "accessor")) hitAcc++
    if (has(c, "mfi") || has(m, "mfi")) hitMFi++
    if (has(c, "uwb") || has(m, "uwb") || has(m, "ultra wideband") || has(m, "near field")) hitUWB++
    if (has(m, "consent")) hitConsent++
    if (has(m, "bluetooth")) hitBTimp++
  }
  if (compAsk == 0) emit("X01", "-", "公告组件列没有 AccessorySetupKit 行")
  if (compBT == 0) emit("X02", "-", "公告组件列没有 Bluetooth 行")
  if (compUSB == 0) emit("X03", "-", "公告组件列没有 USB 行")
  if (compThread == 0) emit("X04", "-", "公告组件列没有 Thread 行")
  if (compHK == 0) emit("X05", "-", "公告组件列没有 HomeKit 行")
  if (hitProx == 0) emit("X06", "-", "公告影响句没有 proximity 词形")
  if (hitPair == 0) emit("X07", "-", "公告影响句没有 pairing／paired 词形")
  if (hitAcc == 0) emit("X08", "-", "公告影响句没有 accessory 词形")
  if (hitMFi == 0) emit("X09", "-", "公告两列都没有 MFi 词形")
  if (hitUWB == 0) emit("X10", "-", "公告两列都没有 UWB／near field 词形")
  if (compAsk > 0 && hitConsent == 0) emit("X11", "-", "组件列有 AccessorySetupKit 行，影响句无 consent 词形")
  if (compBT > 0 && hitBTimp != compBT) emit("X12", "-", "组件列 " compBT " 行 Bluetooth 与影响句 " hitBTimp " 行 bluetooth 不相等")

  # Y 族：平台矩阵
  askIOS = sessIOS = eaIOS = ni15 = nfcIOS = eaMac = 0
  for (i = 1; i <= ndoc; i++) {
    d = docs[i]
    if (d == "accessorysetupkit" && (((d SUBSEP "iOS") in PV) || ((d SUBSEP "iPadOS") in PV))) askIOS = 1
    if (d == "accessorysetupkit_asaccessorysession" && (((d SUBSEP "iOS") in PV) || ((d SUBSEP "iPadOS") in PV))) sessIOS = 1
    if (d == "externalaccessory" && (((d SUBSEP "iOS") in PV) || ((d SUBSEP "iPadOS") in PV))) eaIOS = 1
    if (d == "nearbyinteraction" && ((d SUBSEP "iOS") in PV) && num(PV[d SUBSEP "iOS"]) >= 15) ni15 = 1
    if (d == "corenfc" && (((d SUBSEP "iOS") in PV) || ((d SUBSEP "iPadOS") in PV))) nfcIOS = 1
    if (d == "externalaccessory" && ((d SUBSEP "macOS") in PV)) { emit("Y06", d, "ExternalAccessory 出现 macOS 行"); eaMac = 1 }
    if (((d SUBSEP "iOS") in PV) && ((d SUBSEP "macOS") in PV)) {
      iv = num(PV[d SUBSEP "iOS"]); mv = num(PV[d SUBSEP "macOS"])
      if (iv >= 0 && mv >= 0 && (iv - mv > 5 || mv - iv > 5)) emit("Y07", d, "同一文档 iOS " iv " 与 macOS " mv " 相差超过 5")
    }
  }
  if (!askIOS) emit("Y01", "accessorysetupkit", "AccessorySetupKit 没有 iOS 行")
  if (!sessIOS) emit("Y02", "accessorysetupkit_asaccessorysession", "ASAccessorySession 没有 iOS 行")
  if (!eaIOS) emit("Y03", "externalaccessory", "ExternalAccessory 没有 iOS 行")
  if (!ni15) emit("Y04", "nearbyinteraction", "NearbyInteraction 没有 iOS 15 及以上的行")
  if (!nfcIOS) emit("Y05", "corenfc", "CoreNFC 没有 iOS 行")

  # Z 族：三件差集
  for (i = 1; i <= nsub; i++) {
    s = subs[i]
    asp_count = 0
    if (((s SUBSEP "disc.method") in K) || ((s SUBSEP "disc.descriptor") in K) || ((s SUBSEP "disc.protocol") in K)) asp_count++
    m = ((s SUBSEP "disc.method") in K) ? K[s SUBSEP "disc.method"] : ""
    tr = ((s SUBSEP "disc.transport") in K) ? K[s SUBSEP "disc.transport"] : ""
    dsc = ((s SUBSEP "disc.descriptor") in K) ? K[s SUBSEP "disc.descriptor"] : ""
    pr = ((s SUBSEP "consent.prompt") in K) ? K[s SUBSEP "consent.prompt"] : ""
    sc = ((s SUBSEP "consent.scope") in K) ? K[s SUBSEP "consent.scope"] : ""
    mfi = ((s SUBSEP "consent.mfi") in K) ? K[s SUBSEP "consent.mfi"] : ""
    pair = ((s SUBSEP "link.pairing") in K) ? K[s SUBSEP "link.pairing"] : ""
    enc = ((s SUBSEP "link.encryption") in K) ? K[s SUBSEP "link.encryption"] : ""
    usb = ((s SUBSEP "link.usb_restricted") in K) ? K[s SUBSEP "link.usb_restricted"] : ""
    rkey = ((s SUBSEP "readback.restriction_key") in K) ? K[s SUBSEP "readback.restriction_key"] : ""
    rcnt = ((s SUBSEP "readback.restriction_count") in K) ? K[s SUBSEP "readback.restriction_count"] : ""
    radv = ((s SUBSEP "readback.advisory") in K) ? K[s SUBSEP "readback.advisory"] : ""
    rpsg = ((s SUBSEP "readback.psg_anchor") in K) ? K[s SUBSEP "readback.psg_anchor"] : ""
    cl = ((s SUBSEP "claim.closure") in K) ? K[s SUBSEP "claim.closure"] : ""
    cell = ((s SUBSEP "claim.cell") in K) ? K[s SUBSEP "claim.cell"] : ""
    prox = ((s SUBSEP "claim.proximity") in K) ? K[s SUBSEP "claim.proximity"] : ""

    if (asp_count == 0) { emit("W4", s, "主体没有 disc 方面，归属不可判"); continue }
    if (m == "") emit("Z01", s, "发现件缺方法")
    if (dsc == "") emit("Z02", s, "发现件缺描述符")
    if (pr == "") emit("Z03", s, "同意件缺弹窗类型")
    if (sc == "") emit("Z04", s, "同意件缺取值范围")
    if (pair == "") emit("Z05", s, "链路件缺配对方式")
    if (enc == "") emit("Z06", s, "链路件缺加密读数")
    if (tr == "usb" && usb == "") emit("Z07", s, "USB 链路缺限制模式读数")
    if (rkey == "") emit("Z08", s, "回查件缺限制键")
    if (radv == "") emit("Z09", s, "回查件缺公告组件行")
    if (rpsg == "") emit("Z10", s, "回查件缺平台安全指南锚点")
    if (asp_count > 0 && m == "" && (pr != "" || sc != "")) emit("Z11", s, "同意件有主体但发现件缺方法")
    if (cl == "closed" && (rkey == "" || radv == "" || rpsg == "")) emit("Z12", s, "结论为闭合但回查件不齐")
    if (mfi == "yes" && rpsg !~ /1366|1367|1373/) emit("Z13", s, "宣称 MFi 已验证但回查锚点不是 MFi 段落")
    if (tr == "") emit("Z14", s, "发现件缺传输层")
    if (rcnt != "" && num(rcnt) >= 0 && num(rcnt) < 5) emit("Z15", s, "回查限制键少于五个")
    if (radv != "" && radv !~ /^(AccessorySetupKit|Bluetooth|HomeKit|Thread|USB)$/) emit("Z16", s, "公告组件不在配件族五个组件之内")
    if (prox == "yes" && (tr == "nfc" || tr == "usb")) emit("Z17", s, "邻近性声明与传输层不符")

    if (cell == "unknown") wl = "W3"
    else if (m != "" && dsc != "" && pr != "" && sc != "" && pair != "" && enc != "" &&
             rkey != "" && rcnt != "" && radv != "" && rpsg != "") wl = "W1"
    else if (m != "" && dsc != "") wl = "W2"
    else wl = "W4"
    wcnt[wl]++
    if (!QUIET) print "主体 " s " 闭合等级=" wl " 信号数=" per[s]+0
  }

  print "----"
  print "主张主体数= " nsub
  print "平台文档数= " ndoc
  print "公告行数= " nadv
  print "组件列 AccessorySetupKit= " compAsk " Bluetooth= " compBT " USB= " compUSB " Thread= " compThread " HomeKit= " compHK
  print "影响句 proximity= " hitProx " pairing= " hitPair " accessory= " hitAcc " consent= " hitConsent
  print "不同信号码= " length(cnt)
  print "信号条数= " sig+0
  printf "闭合等级分布= W1=%d W2=%d W3=%d W4=%d\n", wcnt["W1"]+0, wcnt["W2"]+0, wcnt["W3"]+0, wcnt["W4"]+0
  if (sig > 0) exit 1
  exit 0
}
' "$1" "$2" "$3"
```

## 23. 实跑与覆盖验收

### 23.1 验收标准

本文对两支脚本的验收只看四件事：

| 编号 | 标准 | 判据 |
| --- | --- | --- |
| V1 | 可重复 | 输入文件在运行前后摘要不变；干净夹具的退出码与输出可复现 |
| V2 | 无越界 | 不联网、不调用系统工具、不读设备与钥匙串、不打开配件会话；命令位置零命中 |
| V3 | 无残留 | 临时目录用 `mktemp -d` 创建，退出后零条目；本实现不向临时目录写入任何字节 |
| V4 | 自洽 | 报告内嵌源码与实跑源码逐字节一致；101 个码全部被 34 次实跑触发 |

V1—V3 由脚本结构本身保证，V4 由证明脚本 `proof.sh` 检查。证明脚本读的是本报告文件本身：它从本文件的 `bash` 代码块里按出现顺序抽出三段源码，与 `.p22/` 下的实跑文件比对。这也是第 21.10 节、第 22.10 节与本节三处代码块必须逐字节复制实跑文件、不允许「整理排版」的原因——`diff -q` 不认排版。

关于「零写入」需要说明一句：两支脚本都创建临时目录，但本实现只把它当作满足运行前置条件的空目录，`awk` 程序的全部输出走 stdout 与 stderr，没有任何一行写进 `TMPD`。P8 数到的 `TMPD` 出现次数各为 2（赋值与 `trap` 清理），P10 的运行后条目数为 0。

### 23.2 证明脚本

`proof.sh` 只依赖 `bash`、`grep`、`awk`、`perl`、`diff`、`md5sum`／`md5`、`mktemp`、`find`、`tail` 与 `cp`／`rm`／`printf` 这些常规命令行工具。它自己也不联网，只在临时目录里生成夹具副本；被它调用的两支脚本同样只读。用法：

```text
bash proof.sh 22-iOS-Accessory-Near-Field-Pairing-Attribution-Analysis.md
```

不带参数时读同目录的 `partF.md`（装配前的分段文件），因此装配前运行会得到 P18 的「跳过」一行，其余十九项照常执行。

二十项检查的分工如下：

| 编号 | 检查什么 | 通过判据 |
| --- | --- | --- |
| P1 | `awk` 程序体内无 `system(`、`getline`、`popen`、`ENVIRON` | 命中 0 |
| P2 | 两支脚本 `bash -n` 语法 | 均通过 |
| P3 | 临时目录前缀 | `acc22.` 与 `acld22.` 各一处 |
| P4 | 被禁工具名的全部出现位置 | 只在头部声明注释里 |
| P4b | 命令位置探测 | 行首或 `|`、`;`、`&`、`(` 之后零命中 |
| P5 | 命令名整词普查 | 只出现 `awk`、`tr`、`cat`、`mktemp`、`rm`、`bash`、`sh` |
| P6 | 非注释行的网络工具计数 | 两支脚本均为 0 |
| P7 | 写出方向 | 只有 `/dev/stderr` 与 `usage` 的 `>&2`，无 `>>` |
| P8 | `TMPD` 出现次数 | 各 2 |
| P9 | 输入文件运行前后摘要 | 四个输入均未变 |
| P10 | 临时目录零残留 | 条目数 0 |
| P11 | 干净夹具 | 退出 0、0 个信号码 |
| P12 | `-h` 帮助 | 退出 0、含用法两处 |
| P13 | 缺参数 | 退出 2 |
| P14 | 不可读输入 | 退出 2 |
| P15 | 未知选项 | 退出 2 |
| P16 | 脚本一取值拒收（A05） | 150 字符载荷被拒、`阻断信号条数=1` |
| P17 | 脚本二平台行拒收（Y09） | `/Users/x/secret` 被拒、其余 8 份文档照常计数 |
| P18 | 内嵌源码与实跑源码一致 | 三段 `diff -q` 全一致 |
| P19 | 两支脚本自身运行前后摘要 | 均未变 |
| P20 | 34 次实跑覆盖验收 | `101/101` |

P5 的普查结果里 `tr` 会显示 21 次，这不是脚本调用了 21 次 `tr`：脚本二把 `tr` 用作一个 `awk` 变量的名字（处理行尾 CR），而 P5 是按整词匹配的文本普查，无法区分变量名与命令名。区分「命令」与「标识符」的检查是 P4b（命令位置探测）与 P6（非注释行的网络工具计数），两者分别是 0 命中与 0 计数。本文保留 P5 的原始输出而不改写它，正是为了让读者看到这种普查方法的局限。

下面这段源码与 `.p22/proof.sh` 逐字节相同（P18 的第三段比对）。它调用的两个脚本文件与夹具都只在本目录内，不触达任何设备、配件、钥匙串或网络。

```bash
#!/usr/bin/env bash
# 第 22 篇只读实证 P1—P20（全部命令可复跑；不联网、不碰设备）
# 用法: bash proof.sh [含内嵌源码的报告文件]；缺省读同目录的 partF.md
set -u
cd "$(dirname "$0")" || exit 2
MD=${1:-partF.md}
FX=fx
T=$(mktemp -d "${TMPDIR:-/tmp}/p22pf.XXXXXX") || exit 2
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
grep -nE 'bluetoothctl|ioreg|system_profiler|security|defaults|profiles|log|curl|osascript|keychain|diskutil' script1.sh script2.sh

hr "P4b 命令位置探测（行首或 | ; &）( 之后）"
grep -nE '(^|[|;&(])[[:space:]]*(bluetoothctl|ioreg|system_profiler|security|defaults|profiles|log|curl|osascript|diskutil)[[:space:]]' script1.sh script2.sh || echo "命令位置命中= 0"

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
T2=$(mktemp -d "${TMPDIR:-/tmp}/p22t2.XXXXXX") || exit 2
TMPDIR="$T2" bash script1.sh "$FX/s1-good.tsv" >/dev/null 2>&1
TMPDIR="$T2" bash script2.sh "$FX/s2-claims-good.tsv" "$FX/s2-platform-good.tsv" "$FX/s2-adv-good.tsv" >/dev/null 2>&1
printf '运行后 TMPDIR 内条目数= '; find "$T2" -mindepth 1 | wc -l
rm -rf "$T2"

hr "P11 干净夹具：0 信号、退出 0"
bash script1.sh "$FX/s1-good.tsv" > "$T/g1" 2> "$T/g1e"; e1=$?
bash script2.sh "$FX/s2-claims-good.tsv" "$FX/s2-platform-good.tsv" "$FX/s2-adv-good.tsv" > "$T/g2" 2> "$T/g2e"; e2=$?
echo "script1 退出= $e1"; grep -E '配对记录数|不同信号码|判定分布' "$T/g1"
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
perl -pe 'BEGIN{$x="A"x150} s/^AS_L1,claim\.evidence_ref,.*/AS_L1,claim.evidence_ref,$x/' "$FX/s1-good.tsv" > "$T/dirty1.tsv"
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

对本报告文件运行 `proof.sh` 的完整输出如下。P18 读的正是本文件中前三段 `bash` 代码块——也就是第 21.10 节的脚本一、第 22.10 节的脚本二与本节上面的证明脚本。

```text
===== P1 awk 程序体内无 system/getline/popen/ENVIRON =====
命中= 0

===== P2 bash -n 语法检查 =====
script1.sh 语法= 通过
script2.sh 语法= 通过

===== P3 临时目录前缀 =====
script1.sh:12:#       唯一写出目标是 mktemp -d 创建的临时目录，退出时删除，本实现不向其写入任何字节。
script1.sh:55:TMPD=$(mktemp -d "${TMPDIR:-/tmp}/acc22.XXXXXX") || exit 2
script2.sh:11:# 不读取设备状态；唯一写出目标是 mktemp -d 创建的临时目录，退出时删除，本实现不向其写入任何字节。
script2.sh:45:TMPD=$(mktemp -d "${TMPDIR:-/tmp}/acld22.XXXXXX") || exit 2

===== P4 被禁工具名的全部出现位置（头部声明／脚本名／字段名） =====
script1.sh:10:# 本脚本不联网、不调用 bluetoothctl／ioreg／system_profiler／security／defaults／profiles／
script1.sh:11:#       log／curl／osascript 等任何命令行工具、不读取钥匙串、不打开任何配件会话。
script2.sh:10:# 不调用 bluetoothctl／ioreg／system_profiler／security／profiles／defaults／curl 等工具，

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
     21 tr

===== P6 非注释行中的网络工具整词计数 =====
script1.sh= 0
script2.sh= 0

===== P7 写出方向：stderr 之外的重定向 =====
script1.sh:45:    -*) usage >&2; exit 2 ;;
script1.sh:50:[ $# -ge 1 ] || { usage >&2; exit 2; }
script1.sh:52:  [ -r "$f" ] || { echo "输入不可读: $f" >&2; exit 2; }
script1.sh:61:  print code "\t" (id == "" ? "-" : id) "\t" msg > "/dev/stderr"
script2.sh:36:    -*) usage >&2; exit 2 ;;
script2.sh:40:[ $# -eq 3 ] || { usage >&2; exit 2; }
script2.sh:42:  [ -r "$f" ] || { echo "输入不可读: $f" >&2; exit 2; }
script2.sh:51:  print code "\t" (subj == "" ? "-" : subj) "\t" msg > "/dev/stderr"
script2.sh:105:  if (nadv == 0) print "公告语料为空或不可解析" > "/dev/stderr"
（以上仅为 /dev/stderr 与 usage 的 >&2；无 >> 追加）

===== P8 TMPD 出现次数 =====
script1.sh= 2
script2.sh= 2

===== P9 输入文件运行前后摘要一致 =====
script1 输入未变 1c53a0077a01c5ac9ce9fd5474aa86df
script2 三输入未变 d54e9f906d0d04617d11f87b54479090

===== P10 临时目录零残留 =====
运行后 TMPDIR 内条目数= 0

===== P11 干净夹具：0 信号、退出 0 =====
script1 退出= 0
配对记录数= 2
不同信号码= 0
判定分布= V1=2 V2=0 V3=0 V4=0 
script2 退出= 0
主体 ASK-1 闭合等级=W1 信号数=0
主体 EA-1 闭合等级=W1 信号数=0
主体 USB-1 闭合等级=W1 信号数=0
主张主体数= 3
不同信号码= 0
闭合等级分布= W1=3 W2=0 W3=0 W4=0

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
A05	AS_L1	字段 claim.evidence_ref 的取值形似私钥／口令／长载荷，已拒收
阻断信号条数= 1
判定分布= V1=1 V2=0 V3=1 V4=0 

===== P17 脚本二平台行格式拒收：路径形态 =====
退出= 1
Y09	/Users/x/secret	平台行取值形似路径／凭据／长载荷，已拒收
平台文档数= 8

===== P18 报告内嵌源码与实跑源码一致 =====
script1 内嵌= 一致
script2 内嵌= 一致
proof.sh 内嵌= 一致

===== P19 两支脚本自身运行前后摘要一致 =====
script1 未变 f302ab9e39208a5024dd50753cb7c97a
script2 未变 72c1163ee299d5de4a1fb1282c6d9ee6

===== P20 34 次实跑覆盖验收 =====
----
未覆盖=
表外码=
覆盖验收=通过（101/101）
```

### 23.4 逐项结果

| 编号 | 检查什么 | 结果 | 说明 |
| --- | --- | --- | --- |
| P1 | awk 程序体内无 `system`／`getline`／`popen`／`ENVIRON` | 0 命中 | 脚本二的三文件切换靠 `FNR == 1`，不靠 `getline` |
| P2 | `bash -n` 语法 | 两支通过 | 只查语法，不查分支 |
| P3 | 临时目录前缀 | `acc22.`／`acld22.` | 按前缀可在 `TMPDIR` 中区分 |
| P4 | 被禁工具名的全部出现 | 仅 3 行注释 | 头部声明本身提到这些名字 |
| P4b | 命令位置探测 | 0 命中 | 注释之外没有任何命令位 |
| P5 | 命令名整词普查 | 8 个词 | `tr` 的 21 次是变量名，见下文；`curl` 两次都在注释里 |
| P6 | 非注释行的网络工具 | 0／0 | 排除注释后网络工具零出现 |
| P7 | 重定向方向 | 仅 `>&2` 与 `/dev/stderr` | 无 `>>` 追加，不写文件 |
| P8 | `TMPD` 出现次数 | 各 2 | 创建与删除各一次 |
| P9 | 输入运行前后摘要 | 未变 | 四个输入只读 |
| P10 | 临时目录残留 | 0 条目 | `trap` 在 `EXIT`／`INT`／`TERM` 上清理 |
| P11 | 干净夹具 | 退出 0、0 信号 | 两支脚本的 good 路径 |
| P12 | `-h` | 退出 0、含用法 2 | 帮助可用 |
| P13 | 缺参数 | 退出 2 | 与「有信号」区分 |
| P14 | 不可读输入 | 退出 2 | 与「不齐」区分 |
| P15 | 未知选项 | 退出 2 | 不静默忽略 |
| P16 | 超长载荷 | A05、阻断条数 1 | 150 字符载荷被拒收 |
| P17 | 路径形态平台行 | Y09、文档数 8 | `/Users/...` 被拒收，其余 8 份仍在 |
| P18 | 内嵌源码一致性 | 三段一致 | 报告与实跑同源 |
| P19 | 脚本运行前后摘要 | 未变 | 脚本不自改 |
| P20 | 101 码覆盖 | 101/101 | 34 次实跑，未覆盖 0、表外码 0 |

P5 的 `tr` 计数需要单独解释。两支脚本里真正作为命令执行的 `tr` 只有一处（脚本二第 55 行附近把行尾 CR 去掉），其余 20 次是 `awk` 程序里名为 `tr` 的局部变量（例如 `tr = fld(s, "link.transport")`）。P5 是按整词匹配的文本普查，没有词法分析能力，所以变量名和命令名会被一起数进去。P4b 检查的是「行首或 `|`、`;`、`&`、`(` 之后」的命令位置，命中 0；P6 检查的是非注释行里的网络工具，计数 0。判定是否越界应以 P4b 与 P6 为准，P5 只用于让人看到全部词形。

P2 也需要一句限定：`bash -n` 只证明语法成立，不证明每个分支被走到。分支覆盖由 P20 的 34 次实跑承担，两者不能互相替代。

### 23.5 覆盖验收：34 次实跑与 101 个码

覆盖验收只看一件事：**表里的每一个码，有没有至少一次被真实输入触发。** 34 次实跑全部使用合成夹具，退出码分布为 0 九次、1 十九次、2 六次——三种出口都被走到，说明「合格」「有信号」「没跑成」没有被压成同一件事。

| 脚本 | 实跑 | 退出 0 | 退出 1 | 退出 2 |
| --- | --- | --- | --- | --- |
| 脚本一 | R01—R19（19 次） | 7 | 9 | 3 |
| 脚本二 | R20—R34（15 次） | 2 | 10 | 3 |
| 合计 | 34 次 | 9 | 19 | 6 |

逐族看：

| 族 | 码范围 | 个数 | 首次触发 | 触发方式 |
| --- | --- | --- | --- | --- |
| A 结构与取值 | A01—A08 | 8 | R02 | 全错台账；A05 由 R13 单码触发 |
| B 发现与同意 | B01—B10 | 10 | R02 | 全错台账 |
| C 链路一致性 | C01—C08 | 8 | R02 | 全错台账；C08 另由 R04 提示级触发 |
| D 同意与身份 | D01—D07 | 7 | R02 | 全错台账 |
| E 管理面 | E01—E08 | 8 | R02 | 全错台账 |
| F 结论 | F01—F07 | 7 | R02 | 全错台账；F01 另由 R04 触发 |
| G 引用 | G01—G06 | 6 | R03 | 引用子集台账 |
| V 判定等级 | V1—V4 | 4 | R01／R04／R02／R02 | 干净／提示／有信号／未知格 |
| X 公告子词表 | X01—X12 | 12 | R21 | 全缺公告；X06—X12 由 R21、R26 触发 |
| Y 平台矩阵 | Y01—Y10 | 10 | R21 | 缺行与重复登记矩阵 |
| Z 三件差集 | Z01—Z17 | 17 | R21 | 全缺三件 |
| W 闭合等级 | W1—W4 | 4 | R20／R21／R21／R21 | 干净／缺件／缺件／缺发现件 |

需要点出的两次**单码或近单码**实跑：R13 只有 `A05` 一个信号（私钥块被拒收），证明取值拒收不依赖同一台账里的其他记录；R28 是脚本二的 `-h`，输出为零码、退出 0，用来证明帮助路径不会被误当成「无信号」。R22 则相反，一次打出 `X01`—`X10` 与 `Y01`—`Y05`，说明「空平台／空公告」是整族失败而不是逐条失败。R21 同时打出 `W1`—`W4` 四级，是唯一一次四档闭合同框的实跑。

`matrix-out.txt` 是这 34 行的逐次原始记录，末四行是汇总：

```text
----
未覆盖=
表外码=
覆盖验收=通过（101/101）
```

101 的分解与第 23.1 节一致：脚本一 `8+10+8+7+8+7+6+4 = 58`，脚本二 `12+10+17+4 = 43`。两组相加不是「58 个结论加 43 个结论」，而是**同一批台账的两种切法**：脚本一从一条记录内部找矛盾，脚本二从三件之间找缺口。

还有一条表外码必须说明：脚本二在读取主张台账时，若某行不是三列、标识或字段为空、或取值形似路径／凭据／长载荷，会先发 `Z00` 并跳过该行（第 71—74 行）。`Z00` 是输入校验码，不属于 101 码表，34 次实跑也没有触发它——所有夹具的主张行都是三列且取值合法。它与 `Y09` 共用同一个 `badv` 判据，`Y09` 的拒收路径已由 P17 实证；`Z00` 本身只有代码路径、没有实跑记录，本文不把它算进覆盖率。

### 23.6 验收边界

这一节写清楚 34 次实跑与 20 项证明**没有**证明什么，避免把覆盖率读成结论强度。

1. **证明的是「没有读写别处的口子」，不是「读数与设备一致」。** P1—P10 只能说明脚本不调用系统工具、不联网、不写文件、不留临时目录。它们证明不了「台账里填的 `consent.mfi_verified=yes` 与某台设备上的实际验证结果一致」。
2. **夹具是合成的，不对应任何真实配件。** `.p22/fx/` 的 13 份文件共 916 行，`Desk Lamp`、`004C`、`181A` 与全部公告行都是构造值；P16 与 P17 用的超长载荷与路径也是构造值。真实台账进来后必须先洗数据，洗完的留档同样不能随文发布。
3. **平台矩阵与公告读数是归档快照，不是在线查询。** 17 份文档的平台坐标来自 `.srcx22/C/platform-22.txt`，1,266 行公告来自 `.srcx22/C/advisory-22.tsv`。两者都冻结在归档时刻；Apple 之后新增的平台行或公告行不在其中，脚本也不会去网上补。
4. **判据对不对，靠行号人工核，覆盖率不代替。** 101/101 只说明每条判据都还能被打中；判据本身是否写对，要看第 21.3、22.4 两节给出的行号与第 3 章的八处换算失败。
5. **只覆盖字段级矛盾，不覆盖跨字段语义。** 例如 `disc.method=bluetooth` 与 `link.pairing=no` 同时出现不会触发任何码；`consent.scope=class` 也不会因为写了 `mfi=yes` 就被改写。语义判断留在第 19 章 J1—J4 与 Q1—Q4 的决策顺序里，由人做。
6. **脚本不判断策略该不该是 `unknown`。** 它只登记这个值，并在 `unknown` 时把闭合压到 W3／W4、把记录压到 V4。至于某个平台到底有没有公开的配件身份口径，是第 6 章 L3 与第 17 章可见性边界要回答的问题。
## 24. 十二个误区

这一章把全篇最容易读错的十二处集中列出。每一条给三样东西：**误读**（一句会被写进报告或台账的话）、**正确读法**（公开口径实际支持的那一句）、**判据**（哪一行读数或原文否证了它）。最后压成四组，每组一条禁令。

| 编号 | 误读 | 正确读法 | 判据与脚本码 |
| --- | --- | --- | --- |
| M01 | 配件族公告有 27 行，所以有 27 个配件缺陷 | 27 行只对应 7 个 CVE；组件名是**归属标签**，不是缺陷类型；同一批公告的影响句里 `accessory` 是 0 行 | `C/readings-22.txt:3、7—13、14—33`；脚本二 X01／X08 |
| M02 | 影响句 `proximity` 有 16 行，说明近场配对是主要缺陷形态 | 16 行里 12 行在配件族内，全部是 `attacker in physical proximity`，描述**攻击者位置**，不描述配对 | `C/readings-22.txt:14—33、54—63`；脚本二 X06 |
| M03 | AccessorySetupKit 不请求蓝牙权限，所以它绕过了用户同意 | 它绕过的是**通用蓝牙权限弹窗**，换来的是**配件选择器**；用户仍要选定一个具体配件 | `A/accessorysetupkit_asaccessorysession.txt:249`；脚本一 B08／C07 |
| M04 | 台账写 `mfi_verified=yes`，就说明这个配件是正品 | 验证的是认证 IC 对挑战的签名应答，不是整机来源；公开口径没有给「正品」这一列 | `B/apple-platform-security-guide.txt:1366—1367`；脚本一 A07／F04 |
| M05 | 配对成功、绑定了、加密开了，身份就验证过了 | 配对、绑定、认证、加密、消息完整性、SSP 六个词全是**传输层谓词**，没有一个是身份层谓词 | `B/apple-platform-security-guide.txt:3905`；脚本一 C01／C02 |
| M06 | 认证 IC 在配件里，所以配件侧的链路日志能证明验证发生过 | 原文写明整个过程 `is transparent to the accessory itself`；配件自己也看不见 | `B/apple-platform-security-guide.txt:1367`；脚本一 D01／A07 |
| M07 | UWB 会话令牌唯一标识设备，所以令牌就是身份凭据 | 令牌用于会话内识别；公开文档没有说明由谁签发、能否跨会话复用、是否绑定 MFi | `A/nearbyinteraction.txt:7、19`；脚本一 C08 |
| M08 | NFC 全系统一次只允许一个会话，所以同一时间只有一个配件在场 | `:22` 约束的是**会话调度**与队列，不是物理在场；扩展里根本没有 NFC | `A/corenfc_nfctagreadersession.txt:22`；`A/corenfc.txt:8`；脚本一 B05／B09 |
| M09 | ExternalAccessory 有 macOS 10.13 行，所以 Apple silicon 上的 iPad App 能连配件 | 原文写明 `iPad and iPhone apps running on a Mac with Apple silicon can’t connect to external accessories using this framework` | `A/externalaccessory.txt:7`；`C/platform-22.txt:41—58`；无专用码 |
| M10 | `allowUSBRestrictedMode=false` 就是允许所有 USB 配件 | 该键在 Lockdown Mode 下被忽略、用户通道不支持、默认值为 `true`；它约束的是锁屏时的**新数据连接** | `A/mdm-restrictions-payload-M.txt:170`；`B/apple-platform-security-guide.txt:1359—1363`；脚本二 Z07 |
| M11 | 管理面有 5 个配件键，可以查「某个配件是否已配对」 | 5 个键全是布尔能力开关；没有一个回答逐配件的配对、验证或最后连接时间 | `C/readings-22.txt:136—141`；脚本一 F01／F03 |
| M12 | 17 份文档里 7 份两平台都有，说明 iOS 与 macOS 能力对等 | 7 份里有 5 份版本差超过 5；AccessorySetupKit 与 CoreNFC 一份 macOS 行都没有 | `C/readings-22.txt:135`；`C/platform-22.txt:1—10、34—40`；脚本二 Y01—Y07 |

十二条按主题压成四组。

**第一组 M01—M02：词表给的是标签，不是类型。** 27 行、16 行都是真数字，但一个数的是组件名，一个数的是攻击者位置；真正回答「配对」的 `pairing` 在影响句里是 0 行，`accessory` 也是 0 行。**禁令：公告侧的每个计数必须写明它数的是哪一列、哪个词形；只给数字不给列名的结论，一律退回。**

**第二组 M03—M06：同意、身份、传输是三套证据。** 选择器证明的是「用户选过」，认证 IC 证明的是「硬件应答过」，配对与加密证明的是「两端共享密钥」。三句话的主语分别是用户、IC、协议栈，任何一句都不能替换另一句。**禁令：台账里 `consent.*`、`link.*`、`claim.mfi_claim` 三组字段不得互相赋值；写 `closed` 之前先看第 15 章的矩阵。**

**第三组 M07—M08：近场会话不等于身份，也不等于在场。** UWB 令牌与 NFC 会话都是**会话语义**：令牌解决「这一次交互里认哪一个」，会话队列解决「同一时刻调度哪一个」。**禁令：凡写「令牌唯一」「一次一个」的地方，后面必须跟一句「这不能推出什么」；不跟就不写。**

**第四组 M09—M12：平台行与能力开关都有自己的限定语。** macOS 行不等于 Apple silicon 可用，`false` 不等于总开关，5 个键不等于 5 种读数，7 份两平台不等于能力对等。四处误读的共同点都是**把限定语删掉**。**禁令：引用平台坐标时带上版本，引用管理键时带上监督与通道，引用计数时带上分母。**

---

## 25. 常见问题

**问：这套台账与两支脚本必须跑在设备上吗？**
不。两支脚本都是纯文本、离线、只读：脚本一（`.p22/script1.sh`，223 行）收一份或多份三列台账，脚本二（`.p22/script2.sh`，220 行）固定收三份文本——主张台账、平台矩阵、公告语料。第 23.3 节的 P1—P10 专门回答这个问题：P1 在 awk 程序体里对 `system(`／`getline`／`popen`／`ENVIRON` 的匹配是 0；P2 两支都通过 `bash -n`；P3 临时目录前缀分别是 `acc22.` 与 `acld22.`；P4b 的「命令位置」探测是 0；P6 在非注释行里对网络工具的整词计数是 0；P7 的重定向只到 `>&2` 与 `/dev/stderr`；P9 运行前后输入摘要未变；P10 把 `TMPDIR` 指到空目录跑完，事后条目数为 0；P19 脚本自身摘要未变。**这十段证明的是「没有读别处的口子」，不是「读到的内容与真实配件一致」**——第 23.6 节把这条不对称写成验收的第一条边界。

**问：两支脚本先跑哪一支？为什么不合并成一个分数？**
先脚本一。它逐条检查七个命名空间里该填的格填没填、填的形态合不合规，输出 J1—J4，回答「这一条登记能不能用」；脚本二吃的是另一形状，输出 Q1—Q4，回答「一个主体的三件还能不能立起来」。两者的分母不同：J 的分母是一条记录，Q 的分母是一个主体的三件。干净夹具上的两个「最好值」也不是同一件事——脚本一读 `配对记录数= 2`、`判定分布= V1=2`，说的是两条登记各自自洽；脚本二读 `主张主体数= 3`、`闭合等级分布= W1=3`，说的是三个主体的三件对得完。**绝不合并成单一分数**：脚本二的 `W1` 可以与 X 族信号同现（R22、R33），脚本一的 `V3` 也可以与 `W3` 同现——一个合并分会把「信号多」与「三件齐」压成同一个数，而这正是第 19.3 节禁止的加法。

**问：101 个码全部至少触发一次，是不是说明判据判得对？**
不，它只说明每条判据都还活着。101 是两支脚本的全部格子：脚本一 54 个信号码加 V1—V4 共 58，脚本二 39 个信号码加 W1—W4 共 43。覆盖的分布也不一样：脚本一靠 R02、R05、R19 三次「全错」打满大部分码，脚本二靠 R21、R34 两次「全缺」打满 X／Y／Z 三族；`A05`、`C08`、`X12` 这类单码路径则各由一次定向子集钉住（R13、R04、R21）。判据**对不对**，靠的是第 21.3、22.4 两节逐族给出的判据行号与出处行号，读者要拿归档自己核；覆盖验收不代替这一步。

**问：夹具能不能换成真实台账或真实配件？**
不能，换进来的那一刻这套验收就失效了。脚本一的拒收执行点是 `A05`（第 74—80 行）：取值形似私钥块、形似口令、超过 120 字符或整段载荷时，该字段直接拒收，不进入台账；P16 用一段 150 字符的 `A` 载荷验证了这条路径，输出 `A05` 与 `阻断信号条数= 1`。脚本二那一侧对应 `Z00`／`Y09`：主张行或平台行取值形似路径／凭据／长载荷时，整行拒收；P17 用一行 `/Users/x/secret` 演示，输出 `Y09`。**两支都只能保证「登记里没有形似设备路径与凭据的取值」，保证不了「登记与某台设备一致」。** 真实台账进来后第一件要做的事是洗数据，洗完的留档也不能再随文发布——`matrix-out.txt` 与第 23.3 节全量输出的价值，恰恰在于第三方能在无设备、无私有数据的条件下原样重跑。

**问：为什么身份件最高只能写 `partial`，不能写 `closed`？**
因为公开接口能读到「MFi 存在」「认证 IC 存在」「证书-挑战-应答存在」，读不到「这一次验证的结果」。平台安全指南把过程完整写在 `B/apple-platform-security-guide.txt:1366—1367`，但结果留在链路之外的 IC 里，连配件本身都看不见（`:1367` 的 `transparent to the accessory itself`）。**`closed` 在本文只用于「引用结构闭合」**：地址、标题、行锚、证据引用四列齐；它不表示「身份闭合」。把 `closed` 写到身份件上，就是 M04 与 M06 两条误读的合体。

**问：为什么 iOS 的逐配件身份读数是 `unknown`，而不是 `absent`？**
因为公开文档证明的是「读不到这个结果」，不是「iOS 上不存在身份验证」。恰恰相反，MFi 认证 IC 的整段机制、AccessorySetupKit 的发现与同意、ExternalAccessory 的协议白名单都在公开文档里（`B/apple-platform-security-guide.txt:1366—1367`、`A/accessorysetupkit_asaccessorysession.txt:249`、`A/externalaccessory.txt:8、13`），所以「这一层不存在」是假的；但没有一份公开文档给出「某一个配件在这次连接里通过了验证」的读数。三条合起来只能推出 `unknown`。**`absent` 是一个更强的断言，它需要一份「适用于 iOS 的逐配件身份读数不存在」的公开否认；本归档没有这句话。**

**问：退出码 2 是什么？能不能拿它当门禁？**
`2` 只判「输入坏了」：参数个数不对、文件不可读或未知选项。脚本一的校验在第 45—53 行，脚本二在第 36—43 行；`-h`／`--help` 给 0，其余按判定给 0 或 1。34 次实跑的分布是退出 0 九次、1 十九次、2 六次：三种出口都被走到，说明三条路径被区分开。**不要把 2 读成「发现问题」**：它排在任何判定之前，一批真台账跑出 2 时唯一该做的是先修参数与文件可达性，101 个码一个都没被看过。**也不要把 0 读成「没问题」**：干净夹具的 0 只说明「在这个输入上没有信号」，不说明配件安全。

**问：W1 是不是验收通过？**
不是。W1 只表示三件齐：发现件有方法与描述符、同意件有弹窗与作用域、链路件有配对与加密、回查件有五个限制键与公告行与指南锚点，且归属格不是 `unknown`。它与 X 族信号正交——R22 与 R33 都是 `W1` 带 X 族信号：三件齐了，但公告语料里没有 `pairing` 或 `accessory` 词形。**「齐」不等于「对」**，这是第 22.7 节取舍二写死的。反过来，R21 的 `W4=1` 也不等于「设备有问题」，它只表示主张台账里有一个主体没有 `disc` 方面，归属不可判。

**问：公告 27 行、7 个 CVE，能不能说「配件链路有 27 个缺陷」？**
不能。27 是五个组件行数的合计：AccessorySetupKit 2 行／1 CVE、Bluetooth 9 行／2 CVE、HomeKit 8 行／2 CVE、Thread 3 行／1 CVE、USB 5 行／1 CVE（`C/readings-22.txt:3`），同一 CVE 会跨平台重复出现，所以行数大于 CVE 数。七个 CVE 的影响句里，只有 `84493` 直接写「未经用户同意访问蓝牙」，其余六个是物理邻近 DoS、HomeKit 数据访问、视频文件解析终止、Thread 网络流量与 USB 设备内核内存（`:7—13`）。**行数、CVE 数、缺陷类型数是三个分母**，任何一个单独出现都不足以支撑「配件链路缺陷有多少」的结论。

**问：十一层、七个命名空间、50 个字段、三件、十个运营指标、101 个码，这些数字对得上吗？**
各自管一件事，不能互换。十一层（L1—L11）是叙述用的归属分解；脚本一的七个命名空间是台账的主语空间，二者**不是一一对应**：L1—L2（发现、同意）用 `disc`、`consent`，L3—L4（身份、协议）用 `consent`、`disc`，L5—L7（BLE、UWB、NFC）用 `link`，L8—L9（USB、管理面）用 `link`、`mgmt`，L10（公告）用 `readback`，L11（引用）用 `claim`、`doc`、`id`。七个空间共 50 个字段（id 4、disc 8、consent 8、link 10、mgmt 11、claim 6、doc 3），其中必备字段见第 21.2 节。三件（发现／链路／回查）是脚本二的主语切法；101 是两支脚本的码总数（58＋43），与第 21.3、22.4 两节逐族给出的数量相等。**最容易串的是 `M` 与 `W`**：第 24 章的 `M01—M12` 是误区编号，脚本二的 `W1—W4` 是闭合等级。

**问：我改了某条判据，怎么知道有没有改坏？看总信号数吗？**
不看总数，看 `matrix-out.txt` 里哪一段该变色、它确实变色了。单码子集就是为此存在的：R13 只该出 `A05`，R04 只该出 `C08` 与 `F01`，R22 一次该出 `X01`—`X10` 与 `Y01`—`Y05`；改 `C08` 的判据却让 R04 多出别的码，说明改动越过了族界。改完按三步重跑：`bash matrix.sh` 重生成 `matrix-out.txt`，`bash proof.sh 报告.md` 重跑 P1—P20 并看 P18 三行是否仍为「一致」，最后数一遍 `58/58` 与 `43/43` 是否仍在。**这三步都不接触设备**，第三步还会顺带核对两支脚本自身在运行前后没有被改写（P19）。

---

## 26. 未公开文档化边界清单

本章列十四条边界。收条标准三条，缺一条就不收：

- **（a）有一句公开原文**——给出归档文件与行号，能读出「这里有一层」或「这里什么都没有」；
- **（b）有一个落点**——脚本码、必填读数或可复跑的读数行，能把这条边界写进台账；
- **（c）有一句「不能由此推出什么」**——而且这句能指回（a）的原文，不是修辞。

编号用 U01—U14，不补位、不隔号。**U 不是脚本族**：脚本一的信号族是 A／B／C／D／E／F／G 加 V1—V4，脚本二的是 X／Y／Z 加 W1—W4；U 只在本章使用。

| 号 | 边界一句话 | 公开锚点 | 落点 |
| --- | --- | --- | --- |
| U01 | 发现描述符只有类级三属性，没有逐配件标识 | `A/accessorysetupkit_asdiscoverydescriptor.txt:71、91、128、149` | `disc.*`；B06／D07；脚本二 Z02 |
| U02 | 「不请求蓝牙权限」不等于「不需要同意」 | `A/accessorysetupkit_asaccessorysession.txt:249`；`A/accessorysetupkit.txt:6` | `consent.prompt`／`consent.bluetooth_permission`；B08／C07 |
| U03 | MFi 验证由链路之外的认证 IC 处理，配件自身不可见 | `B/apple-platform-security-guide.txt:1366—1367` | `consent.mfi_evidence=ic`；A07／F04；脚本二 Z13 |
| U04 | 未认证配件仍可走模拟音频与 UART | `B/apple-platform-security-guide.txt:1373` | `consent.mfi`／`disc.protocol`；C05；F02 |
| U05 | 传输层六个词全是密钥谓词，没有身份谓词 | `B/apple-platform-security-guide.txt:3905` | `link.pairing`／`bonding`／`encryption`／`key_derivation`；C01／C02 |
| U06 | UWB 的顺序是先链路、再配置、再令牌、最后测距 | `A/nearbyinteraction.txt:19` | `link.uwb_config`／`uwb_token`；C08 |
| U07 | NFC 在 App 扩展里不可用，且全系统一次一个会话 | `A/corenfc.txt:8`；`A/corenfc_nfctagreadersession.txt:22` | `disc.app_extension`／`link.nfc_session`；B05／B09／E04 |
| U08 | 有线限制约束的是新数据连接：一小时、30 天、三天 | `B/apple-platform-security-guide.txt:1359—1363` | `link.usb_restricted`；C03；脚本二 Z07 |
| U09 | `allowUSBRestrictedMode` 不是 USB 总开关 | `A/mdm-restrictions-payload-M.txt:170` | `mgmt.allow_bluetooth`／`mgmt.restriction_count`；E02；脚本二 Z15 |
| U10 | 管理面五个配件键全是能力开关，没有逐配件状态 | `C/readings-22.txt:136—141` | `mgmt.*`；F01／F03 |
| U11 | 公告影响句的八个核心词形零命中 | `C/readings-22.txt:14—33、54—63` | 脚本二 X06—X10 |
| U12 | 组件列行数与影响句词形数不是同一列 | `C/readings-22.txt:34—53、54—63` | 脚本二 X11／X12 |
| U13 | 平台矩阵只有文档、平台、版本三列；两个框架无 macOS 行 | `C/platform-22.txt`；`C/readings-22.txt:135` | 脚本二 Y01—Y07 |
| U14 | ExternalAccessory 的 macOS 行不覆盖 Apple silicon 上的 iPad App | `A/externalaccessory.txt:7`；`A/externalaccessory.txt:8、13` | 无专用码；`doc.page_url` 只证出处 |

### 26.1 十四条边界逐条

**U01 发现描述符只有类级三属性。**
原文把三个可编程属性写得很短：`The accessory’s 16-bit Bluetooth Company Identifier.`（`A/accessorysetupkit_asdiscoverydescriptor.txt:71`）、`The accessory’s over-the-air Bluetooth name substring.`（`:91`）、`The accessory’s Bluetooth service UUID.`（`:128`）；选项集合是 `Options supported by an accessory.`（`:149`）。三属性加一个选项集合，没有序列号、证书指纹或配对记录标识。台账因此只能登记 `disc.company_id`、`disc.name_substring`、`disc.service_uuid` 与 `disc.method`；同一个类级描述符被两条链路共用时，D07 报警。不能由此推出：公司标识相同就说明是同一个配件，或同一厂商的所有配件都可信——描述符的分辨率停在**类**。

**U02 「不请求蓝牙权限」不等于「不需要同意」。**
原文是 `Discover, select, and set up a specific Bluetooth accessory without requesting permission to use Bluetooth.`（`A/accessorysetupkit_asaccessorysession.txt:249`）；总览另写 `Allow seamless, privacy-preserving user consent and control for Bluetooth, Wi-Fi, and Local Network permissions.`（`A/accessorysetupkit.txt:6`）。两句话合起来说明：AccessorySetupKit 绕过的是**通用蓝牙权限弹窗**，保留的是**配件选择器**。台账因此把 `consent.bluetooth_permission` 与 `consent.prompt` 做成两列，B08 在会话未登记弹窗时报警，C07 在蓝牙权限被拒但仍登记蓝牙发现时报警。不能由此推出：通用权限被拒就无法发现配件——选择器正是为这个场景设计的。

**U03 认证 IC 在链路之外。**
四句必须一起读：MFi 授权厂商拿到 iAP 与配套硬件（`B/apple-platform-security-guide.txt:1366`）；配件发 Apple 提供的证书、设备验证（`:1367`）；设备发挑战、配件用签名应答（`:1367`）；整个过程由定制 IC 处理，且 `is transparent to the accessory itself`（`:1367`）。台账因此把 `consent.mfi_evidence` 只允许取 `ic`（A07）；结论宣称已验证但锚点不在 1366／1367／1373 时，脚本二 Z13 报警。不能由此推出：在配件侧抓到的日志能证明验证发生过——连配件本身都看不见这个过程。

**U04 未认证配件仍可走模拟音频与 UART。**
原文写未通过认证的配件被限制在模拟音频与一小部分串口播放控制（`B/apple-platform-security-guide.txt:1373`）。这不是「不可用」，而是「可用范围被收窄」。台账把 `consent.mfi=no` 与 `disc.protocol` 分开登记；C05 在未验证 MFi 却声明协议时报警，F02 在结论写 `absent` 但发现方法存在时报警。不能由此推出：未验证配件一定不能建立任何数据连接——原文的「限制」本身承认它仍能走特定路径。

**U05 传输层六个词全是密钥谓词。**
平台安全指南把蓝牙安全模型拆成配对、绑定、认证、加密、消息完整性、Secure Simple Pairing 六个特征（`B/apple-platform-security-guide.txt:3905`），每个特征都有定义。六个定义的主语都是**密钥关系**：建立共享密钥、存储密钥、验证两端密钥一致、报文保密、防伪造、抗窃听。没有一个回答「配件是不是 MFi 认证」。台账因此把四列分开，C01 检查「配对为 `none` 但加密开启」，C02 检查「加密开启但密钥派生为 `none`」。不能由此推出：加密开启就说明对方身份可信。

**U06 UWB 的顺序不能颠倒。**
原文写 `To begin an interaction session with a third-party accessory, establish a data link with the accessory, receive its configuration data, and create an ... session.`（`A/nearbyinteraction.txt:19`）。顺序是：数据链路 → 配置数据 → 会话 → 测距。也就是说，测距不是「先认出配件再连」，而是「先连上、再拿配置」。台账把 `link.uwb_config` 与 `link.uwb_token` 分开，C08 在 `transport=uwb` 且令牌为空时报警。不能由此推出：令牌由谁签发、能否跨会话复用、是否与 MFi 绑定——公开文档三件都没写。

**U07 NFC 的扩展限制与单会话限制。**
原文两句：`Core NFC isn’t available for use in app extensions`（`A/corenfc.txt:8`）；`Only one reader session of any type can be active in the system at a time.`（`A/corenfc_nfctagreadersession.txt:22`）。第一句让「扩展登记 NFC 发现」成为结构矛盾（B09）；第二句把会话取值限定为 `ndef`／`tag`／`none`，并在管理面关闭 NFC 时检查链路是否仍登记会话（E04）。不能由此推出：同一时间只有一个配件物理在场——队列说明的是会话调度。

**U08 有线限制约束的是新数据连接。**
平台安全指南的三段规则：最近没有数据连接时要先解锁才能激活 Thunderbolt／USB／Lightning／Smart Connector／SDXC 上的数据连接（`B/apple-platform-security-guide.txt:1359—1361`）；锁屏或配件数据连接终止超过一小时后不允许新建，直到解锁，且解锁状态下连接过的配件在最后一次连接后记住 30 天（`:1360—1362`）；距上次数据连接超过三天，锁屏后立即禁止新连接（`:1363`）。第二段的理由就是 `the accessory ecosystem doesn’t provide a cryptographically reliable way to identify accessories before establishing a data connection`（`:1362`）。台账用 `link.usb_restricted` 登记这条链路的限制模式，C03 与脚本二 Z07 检查 USB 链路是否缺这一读数。不能由此推出：三天后配件失效——规则约束的是**新数据连接**，不是已建立的连接或模拟音频。

**U09 `allowUSBRestrictedMode` 不是 USB 总开关。**
原文三句必须一起读：`If the system has Lockdown mode enabled, it ignores this value.`、`This restriction isn’t supported on the user channel.`、默认值为 `true`（`A/mdm-restrictions-payload-M.txt:170`）。三句合起来说明：这个键只在特定注册通道、特定模式下生效。台账把 `mgmt.supervised` 与 `mgmt.source` 分开，E02 检查「蓝牙修改锁定后仍新建链路」的时间线矛盾，脚本二 Z15 检查回查限制键少于五个。不能由此推出：`false` 就等于设备总是允许 USB 配件——Lockdown Mode 会忽略它，用户通道根本没有这条读数。

**U10 管理面五个配件键全是能力开关。**
210 个纯键名里，配件族 5 个：`allowBluetoothModification`（第 41 行）、`allowBluetoothSharingModification`（第 42 行）、`allowFilesUSBDriveAccess`（第 87 行）、`allowNFC`（第 122 行）、`allowUSBRestrictedMode`（第 170 行）（`C/readings-22.txt:136—141`）。五个键都能回答「这台设备是否允许某项能力」，都不能回答「某个配件当前是否已配对／已验证／最后何时连接」。脚本一 F01 在归属格为 `unknown` 时阻断，F03 检查「声称有管理面读数但键名不在五键内」。不能由此推出：键存在就说明这台设备上生效——监督与注册通道是前置条件。

**U11 公告影响句的八个核心词形零命中。**
在 1,266 行全量语料里，影响句列 `accessory`、`homekit`、`pairing`、`mfi`、`uwb`、`nfc`、`near field`、`entitlement` 全部是 0 行（`C/readings-22.txt:14—33`）；配件族内部的 `accessory`、`pairing`、`paired`、`permission` 也是 0 行（`:54—63`）。这不是「公告里没有配件缺陷」，而是「公告的影响句不使用这些词形」。脚本二 X06—X10 把五种零命中写成信号，X11 检查「有 AccessorySetupKit 行但影响句无 consent」。不能由此推出：八个零等于八个概念没有缺陷——零是词形计数，不是缺陷计数。

**U12 组件列与影响句列不是同一列。**
组件列 `Bluetooth` 9 行、`HomeKit` 8 行、`AccessorySetupKit` 2 行（`C/readings-22.txt:34—53`）；影响句列 `bluetooth` 2 行、`homekit` 0 行、`accessory` 0 行（`:14—33`）。三组数字放在一起说明：组件名是归属标签，影响句是行为描述。脚本二 X12 只检查「组件列 Bluetooth 行数」与「影响句 bluetooth 行数」是否相等；在真实语料里它们不相等，所以 X12 是一条会响的信号，而不是一条应当被追平的规则。不能由此推出：组件列 9 行就代表 9 种蓝牙缺陷。

**U13 平台矩阵只有三列，且两个框架没有 macOS 行。**
`C/platform-22.txt` 的每一行只有 `<文档>,<平台>,<引入版本>` 三个字段，共 71 行；17 份文档里两平台都有 7、只有 iOS／iPadOS 10、只有 macOS 0、两者都无 0、版本差>5 的 5（`C/readings-22.txt:135`）。AccessorySetupKit 五份全无 macOS 行（`C/platform-22.txt:1—10`），CoreNFC 三份全无 macOS 行（`:34—40`）。脚本二 Y01—Y05 检查五份关键文档是否有 iOS 行，Y06 在 ExternalAccessory 出现 macOS 行时报警，Y07 检查同一文档两平台版本差是否超过 5。不能由此推出：两平台都有行就说明能力对等——7 份里有 5 份版本差超过 5。

**U14 ExternalAccessory 的 macOS 行不覆盖 Apple silicon 上的 iPad App。**
原文写 `iPad and iPhone apps running on a Mac with Apple silicon can’t connect to external accessories using this framework.`（`A/externalaccessory.txt:7`）；同一页还写框架支持 Lightning、30-pin 与蓝牙配件（`:6`），以及 `The manufacturer of an MFi accessory decides which third-party apps may communicate with their accessories.`（`:8`）。三句的主语不同：第一句是运行环境，第二句是硬件形态，第三句是授权主体。台账的 `doc.page_url` 只能证明出处，不能证明「这个 App 在 Mac 上能连配件」；本文没有为这条边界设专用码，因为它是运行环境限制，不是字段级矛盾。不能由此推出：平台矩阵有 macOS 10.13 行就说明这条链路在 Mac 上可用。

### 26.2 三份输入件怎么承载这十四条

| 边界 | 台账（脚本一） | 平台矩阵（脚本二） | 公告语料（脚本二） |
| --- | --- | --- | --- |
| U01 | `disc.company_id`／`name_substring`／`service_uuid` | — | — |
| U02 | `consent.prompt`／`bluetooth_permission` | — | — |
| U03 | `consent.mfi_verified`／`mfi_evidence` | — | — |
| U04 | `consent.mfi=no`＋`disc.protocol` | — | — |
| U05 | `link.pairing`／`bonding`／`encryption`／`key_derivation` | — | — |
| U06 | `link.uwb_config`／`uwb_token` | — | — |
| U07 | `disc.app_extension`／`link.nfc_session` | — | — |
| U08 | `link.usb_restricted` | — | — |
| U09 | `mgmt.supervised`／`source`／`restriction_count` | — | — |
| U10 | `mgmt.*` 五键 | — | — |
| U11 | — | — | X06—X10 |
| U12 | — | — | X11／X12 |
| U13 | `id.platform` | Y01—Y07 | — |
| U14 | `doc.page_url`（只证出处） | Y06 只看行是否存在 | — |

### 26.3 两条固定自查项

**自查一：每写一个「没有」，先问「哪一层没有」。** 「公告里没有 pairing」是语料层；「管理面没有逐配件状态」是管理面层；「公开接口没有验证结果」是接口层；「台账没有会话身份」是登记层。四层各自可以真，但不能互相替代。第 23.6 节第 1 条与第 24 章第二组说的是同一件事。

**自查二：每个数字成对报。** 27 行要带 7 个 CVE；16 行要说明是 `attacker in physical proximity`；5 个配件键要带 210 的分母；17 份文档要带 7／10／0／0／5 的拆分；101 个码要拆成 58／43。只报一个数字的结论，按第 24 章 M01 退回。

### 26.4 用法与改法

1. 新增一条边界时，先写（a）原文与行号，再写（b）落点，最后写（c）不能推出什么；三者缺一，不进本章。
2. 边界不编号补位：删掉一条就留空号并在文中说明，不让 U 号随章节顺序漂移。
3. 改判据时，先看这条边界有没有落点码；没有落点的边界（U14）只能靠人工核，不能靠覆盖率验收。
4. 归档更新后，先重跑 `matrix.sh` 与 `proof.sh`，再看本章的锚点行号是否仍然成立；行号漂移属于归档变更，不属于判据变更。

---

## 27. 结论

### 27.1 立场：能说什么，不能说什么，该记成什么

**能说的三句话。** 第一，iOS 外接配件的发现、同意、身份、传输与回查是五套口径：AccessorySetupKit 给类级描述符，系统弹窗给类级同意，MFi 认证 IC 给链路之外的证书-挑战-应答，BLE／UWB／NFC 给会话语义，管理面给五个布尔能力开关；五者之间没有一份公开文档把它们逐项对上。第二，公开语料唯一逐配件的那件证据在认证 IC 里，而且 `transparent to the accessory itself`，所以公开接口能写到的最高等级是 `partial`，`closed` 只用于引用结构。第三，34 次实跑覆盖了 101 个码，两支脚本离线、只读、可复跑，读者可以不用设备复核本文的每一个计数。

**不能说的三句话。** 第一，不能说「配对成功就是身份验证成功」——传输层证明密钥关系，身份层证明硬件来源。第二，不能说「公告里 `accessory` 是 0 行，所以没有配件缺陷」——0 是影响句的词形计数，组件列还有 27 行、7 个 CVE。第三，不能说「17 份文档 7 份两平台都有，所以能力对等」——7 份里 5 份版本差超过 5，AccessorySetupKit 与 CoreNFC 一份 macOS 行都没有。

**该记成什么。** 逐配件身份记 `unknown`；发现与同意记 `partial`（类级）；链路记 `partial`（密钥级）；管理面记 `partial`（能力级）；公告记 `partial`（族级）；引用结构记 `closed`。这六个值不是同一个刻度上的六档，而是六个不同主语的最高可见度；把它们并排放在一行「结论」里，就是本文最反对的那种压缩。

### 27.2 方法论：四步

1. **先分主语。** 发现件的主语是描述符，同意件的主语是用户与弹窗，链路件的主语是协议栈，身份件的主语是认证 IC，回查件的主语是管理员与公告。主语不同的两句话不得互相赋值。
2. **再分列。** 27 行、7 个 CVE、16 行 `proximity`、9 行 `Bluetooth`、2 行 `bluetooth`、210 个键、5 个配件键——每一个数都带列名与分母，不把组件列、影响句列、平台列混算。
3. **再判闭合。** 三件齐只能到 `partial`；`closed` 只给引用结构；`unknown` 必须在 `claim.cell` 里显式写出，不能用空白代替。
4. **最后实证。** 判据先写行号，再写码，再跑夹具；单码子集证明判据不依赖同框，全错夹具证明整族路径，34 次实跑证明每条码可达；覆盖率不代替语义核对。

### 27.3 三条建议

1. **给台账加一列「主语」。** 每条记录写明这句话的主语是描述符、用户、协议栈、IC、管理员还是公告；写不出来的记录，先别填结论。
2. **给数字加分母。** 组件行数带 CVE 数，平台行带版本差，管理键带 210，公告词形带 1,266；只给分子的周报一律退回重写。
3. **把 `unknown` 当成正常值。** 逐配件身份读不到是公开接口的结构事实，不是台账的失败；把 `unknown` 改写成 `absent` 或 `closed` 才是失败。

---

## 28. 参考资料

### 28.1 归档总览

本轮归档在 `.srcx22/`，分四组：

| 组 | 内容 | 规模 |
| --- | --- | --- |
| `A/` | Apple Developer 文档 18 份（AccessorySetupKit 5、CoreBluetooth 3、CoreNFC 3、ExternalAccessory 3、NearbyInteraction 3、管理面限制载荷 1） | 18 文件／3,658 行 |
| `B/` | 平台安全指南（含 MFi、有线限制、蓝牙安全模型、UWB、NFC & SE 章）与管理面限制键两份 | 2 文件／5,105 行 |
| `C/` | 读数台账（`readings-22.txt` 160 行）、平台矩阵（71 行）、公告语料（1,267 行含表头） | 3 文件／1,498 行 |
| `fx/` | 13 份合成夹具 | 916 行 |

`C/advisory-22.tsv` 共 1,267 行（含表头），六列 `file`／`platform`／`component`／`cve`／`impact`／`avail`；去重后是 1,266 条记录、12 个平台、129 个组件名、330 个唯一 CVE（`C/readings-22.txt:1`）。`C/readings-22.txt` 的 G1—G12 是正文全部计数的唯一来源。

### 28.2 关键文件与锚点

| 文件 | 本文用到的锚点 | 支撑哪一章 |
| --- | --- | --- |
| `A/accessorysetupkit.txt` | `:3`（隐私发现）、`:5`（蓝牙或 Wi-Fi 配件）、`:6`（同意与权限）、`:7`（移除与重命名）、`:8`（Wi-Fi Aware 描述符） | 第 4、5 章 |
| `A/accessorysetupkit_asdiscoverydescriptor.txt` | `:71`（16 位公司标识）、`:91`（名称子串）、`:128`（服务 UUID）、`:149`（选项） | 第 4 章、U01 |
| `A/accessorysetupkit_asaccessorysession.txt` | `:249`（不请求蓝牙权限、选择具体配件） | 第 5 章、U02 |
| `A/externalaccessory.txt` | `:6`（支持的配件形态）、`:7`（Apple silicon 限制）、`:8`（厂商决定授权）、`:13`（协议白名单） | 第 7 章、U14 |
| `A/corebluetooth.txt` | `:6`（LE 与 BR/EDR）、`:8—11`（后台执行）、`:156`／`:158`（两个用途键） | 第 8 章 |
| `A/corenfc.txt` | `:6—7`（标签类型与协议）、`:8`（扩展不可用） | 第 10 章、U07 |
| `A/corenfc_nfctagreadersession.txt` | `:22`（全系统一次一个会话） | 第 10 章、U07 |
| `A/nearbyinteraction.txt` | `:6—7`（UWB 设备与令牌）、`:19`（第三方配件的三步顺序） | 第 9 章、U06 |
| `B/apple-platform-security-guide.txt` | `:1359—1363`（有线限制与那句「不提供密码学可靠识别」）、`:1366—1367`（MFi 认证 IC）、`:1373`（未认证配件限制）、`:1374`（AirPlay 复用 IC）、`:3905`（蓝牙安全模型六词）、`:3972`（UWB 随机化）、`:4186`（NFC & SE） | 第 6、8、9、10、11 章 |
| `B/mdm-restrictions-payload-M.txt` | `:41—42`（蓝牙修改）、`:87`（Files USB）、`:122`（NFC）、`:170`（USB 限制模式）、`:211—213`（三个 Wi-Fi 键） | 第 11、12 章、U09、U10 |
| `C/readings-22.txt` | G1—G12，正文所有计数 | 第 13、16、20 章 |
| `C/platform-22.txt` | 71 行平台坐标 | 第 14、24 章 |
| `C/advisory-22.tsv` | 1,266 行公告 | 第 13、20 章 |

### 28.3 九条归档约定

1. **只收官方四类**：Apple Developer 文档 JSON、Apple Platform Security 指南文本、Apple 安全发布页、Apple 管理面限制文档；不引第三方博客、CVE 描述页或研究机构报告。
2. **每份文件保留原始行号**：正文的 `:n` 一律指归档文件行号，不指网页行号；引用英文原文时，归档里的行内代码体标记按普通文字转写，其余字符逐字保留。
3. **读数单独成表**：所有计数先进 `C/readings-22.txt`（G1—G12），正文再引用；不在正文里现算。
4. **平台坐标单独成表**：17 份文档的 71 行坐标放 `C/platform-22.txt`，平台名与版本号逐行可核。
5. **公告单独成表**：1,266 行放 `C/advisory-22.tsv`，六列顺序固定，不合并单元格。
6. **夹具与源码分离**：`fx/` 只放合成输入，`.p22/` 只放脚本与证明；夹具不参与任何发布。
7. **脚本内嵌报告**：报告第 21.10、22.10、23.2 节的代码块与 `.p22/` 下的实跑文件逐字节一致，由 P18 检查。
8. **证明脚本读报告本身**：P18 从报告里抽三段源码比对，证明发布件与验收件同源。
9. **不写设备路径与凭据**：所有示例值都是构造值；脚本 A05／Z00／Y09 主动拒收形似路径与凭据的取值。

### 28.4 本篇没有做的事

- **没有在真实设备或真实配件上验证任何一条读数**：全部计数来自归档文本与合成夹具。
- **没有写任何发现、配对、连接或标签读写的操作步骤**：脚本只读文本，正文只做归属分析。
- **没有把 `unknown` 写成 `absent`**：iOS 的逐配件身份读数保持 `unknown`，理由写在 U03 与第 6.4 节。
- **没有跨平台相加**：iOS 行、macOS 行、tvOS／visionOS／watchOS 行是不同平台的坐标，不与 iOS 单独行的计数混算。
- **没有推断 MFi 认证 IC 的内部实现**：原文只说证书-挑战-应答与「配件不可见」，本文不补算法、密钥长度或固件细节（AirPlay 的 1024 位 RSA 只作为公开锚点引用）。
- **没有补 `Z00` 的实跑覆盖**：它不在 101 码表内，34 次实跑也没有触发；本文只说明代码路径与它共用的 `badv` 判据。
- **没有重建相邻篇目的客体**：局域网发现归第 16 篇、非可信解析归第 18 篇、画面外流归第 19 篇、卷形态归第 20 篇、账户装配归第 21 篇、平台校验组件与度量物归第 23 篇。

### 28.5 同系列相邻篇目

本篇与已发布的第 15、16、18、19、20、21 篇有交接，也有硬分界。**第 15 篇（[网络扩展与代理/VPN 通道](15-iOS-Network-Extension-Proxy-VPN-Channel-Attribution-Analysis.md)）**——通道凭什么存在归它；本篇的「链路」是配件与设备之间的发现、同意与传输，不涉及隧道或代理配置。**第 16 篇（[本地网络访问与局域网发现](16-iOS-Local-Network-LAN-Discovery-Attribution-Analysis.md)）**——同网段谁看得见谁归它；AccessorySetupKit 的 Wi-Fi Aware 与本篇只在「发现」一词上同名，局域网广播与 Bonjour／mDNS 不在本篇范围。**第 18 篇（[非可信内容解析链路](18-iOS-Untrusted-Content-Parsing-Malformed-File-Attribution-Analysis.md)）**——内容被判成什么类型归它；本篇只把 HomeKit 的视频解析公告行当作族内读数，不重复解析链。**第 19 篇（[屏幕画面外流](19-iOS-Screen-Egress-Recording-Mirroring-Attribution-Analysis.md)）**——画面采集、录制与镜像归它；本篇不涉及任何画面数据。**第 20 篇（[卷与挂载形态](20-iOS-Volume-Mount-Filesystem-Form-Attribution-Analysis.md)）**——卷格式、挂载点与文件系统归它；本篇只把 USB 当作「有线配件链路」的一层，不讨论卷。**第 21 篇（[邮件账户与远端内容加载](21-iOS-Mail-Account-Remote-Content-Loading-Attribution-Analysis.md)）**——账户装配与内容加载归它；两篇都数管理面键名，但本篇只数配件族五键与 Wi-Fi 三键，不重复 Mail／Accounts 读数。**第 23 篇（平台校验组件与度量物归属，本队列后续篇目）**——平台校验组件、度量物与本地策略归它；本篇的公告读数只到「组件名与影响句」，不建立度量物归属体系。

---

咨询ios系统请咨询 telegram：https://t.me/one00190
