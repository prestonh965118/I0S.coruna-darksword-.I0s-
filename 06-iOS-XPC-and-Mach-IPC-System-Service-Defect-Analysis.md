---
title: "iOS XPC 与 Mach IPC 系统服务缺陷归属防御分析报告"
description: "Mach 端口、XPC 对象与 launchd 服务名这条系统服务通道的十层表面分解、X1–X12 缺陷类型学与 CWE 对齐、公告组件词表与设备侧读数的口径落差、层 × 责任方 × 更新通道归属矩阵、四级判定模型与运营指标、两个离线只读核验脚本及其夹具与全量分支覆盖验收"
lang: zh-CN
---

# iOS XPC 与 Mach IPC 系统服务缺陷归属防御分析报告

## 摘要

iOS 上几乎所有跨进程动作都要经过同一条通道：Mach 端口负责"权利"，XPC 负责"对象"，launchd 负责"名字到进程"的绑定，沙箱与 entitlement 负责"谁能连谁"。这条通道一旦出缺陷，读者在公告里看到的组件名是 `XPC`、`launchd`、`Kernel` 或 `IOKitUserClient`，但在设备上、日志里、崩溃报告里，它表现为某个守护进程的一次异常终止、某条服务名突然消失、或某个 `_kernelrpc_mach_msg2_trap` 帧出现在回溯里。这三种表述**不是同一张表**，本文的主线就是这张落差表：**一类 IPC 缺陷该归到哪一层、谁负责修、修完之后设备侧显示在哪个版本号上、读者手上有什么只读证据能自证**。

全文按十层拆开 Mach IPC 表面（端口对象、名称空间、消息、MIG 契约、XPC 对象、NSXPC 封装、launchd 装配、bootstrap 命名、沙箱与 entitlement 介入、IOKit user client），给出 X1–X12 的缺陷类型学（按"错误发生在哪一次校验"分型，而不是按 CVE 编号分型），一张层 × 责任方 × 更新通道 × 设备侧证据的归属矩阵，以及 Apple 安全公告口径下的公开读数。核验部分提供两个纯文本、离线、只读的分类脚本——一个把 `.ips` 崩溃报告归入 IPC 层或非 IPC 层，一个比对两份服务名清单的漂移——两者都在本轮做了全量分支覆盖验收，信号码共 53 个（脚本一 30 个、脚本二 23 个），其中 51 个在本轮环境实跑触发；剩下 2 个是"文件存在但不可读"分支（脚本一 E02b、脚本二 E02），在本轮的 Windows 管理员环境下无法构造，只给出 Linux/macOS 上的复现方法，见第 21.4 节。

本文不提供任何可用的漏洞利用代码、提权或绕过步骤、端口操纵或注入的操作方法；给出的只有公开文档口径、源码里可指认的字段与常量、以及读者对自己设备导出的文本能做的只读判定。

---

## 目录

1. [引言](#1-引言)
2. [视角声明与本文边界](#2-视角声明与本文边界)
3. [三套词表：公告、源码、运行时符号](#3-三套词表公告源码运行时符号)
4. [Mach 原语层：端口、权利、名称](#4-mach-原语层端口权利名称)
5. [MIG 层：接口契约由谁生成、校验到哪一步](#5-mig-层接口契约由谁生成校验到哪一步)
6. [XPC 对象层：序列化边界](#6-xpc-对象层序列化边界)
7. [NSXPC 层：远端对象与方法校验](#7-nsxpc-层远端对象与方法校验)
8. [launchd 装配层：Label、MachServices 与生命周期](#8-launchd-装配层labelmachservices-与生命周期)
9. [介入口层：entitlement 与沙箱的 mach-lookup](#9-介入口层entitlement-与沙箱的-mach-lookup)
10. [IOKit user client：另一侧的 Mach 表面](#10-iokit-user-client另一侧的-mach-表面)
11. [缺陷类型学 X1–X12](#11-缺陷类型学-x1x12)
12. [归属矩阵：层 × 责任 × 更新通道 × 证据](#12-归属矩阵层--责任--更新通道--证据)
13. [公开案例读数](#13-公开案例读数)
14. [可见性边界：没有 shell 的设备怎么取数](#14-可见性边界没有-shell-的设备怎么取数)
15. [崩溃读数侧：.ips 里读得到与读不到](#15-崩溃读数侧ips-里读得到与读不到)
16. [公告读数侧：Apple Security Releases 的口径与限度](#16-公告读数侧apple-security-releases-的口径与限度)
17. [四级判定模型](#17-四级判定模型)
18. [运营指标 K1–K10](#18-运营指标-k1k10)
19. [只读核验脚本一：.ips 分类器](#19-只读核验脚本一ips-分类器)
20. [只读核验脚本二：服务清单漂移比对器](#20-只读核验脚本二服务清单漂移比对器)
21. [两个脚本的全量分支覆盖验收](#21-两个脚本的全量分支覆盖验收)
22. [十二个误区](#22-十二个误区)
23. [常见问题](#23-常见问题)
24. [未公开文档化边界清单](#24-未公开文档化边界清单)
25. [结论](#25-结论)
26. [参考资料](#26-参考资料)

---

## 1. 引言

### 1.1 为什么把 IPC 单独立一篇

iOS 缺陷讨论里有一个长期存在的错位：研究者的题目、Apple 公告里的组件名、开发者在真机上看得见的现象，三者常常不在一个粒度上。

- 研究者说的是"某个 `ipc_port` 的引用计数在并发释放下少了 1"。
- 公告里那一行写的是组件 `Kernel`，或者 `XPC`，或者 `IOKitUserClient`。
- 开发者在设备侧看得见的是：某个守护进程在 03:14 崩了，`.ips` 里第三帧是 `_kernelrpc_mach_msg2_trap`，服务名列表里少了两条，或者某个 App 连不上一个它本来连得上的服务。

如果只读公告，得不到类型学；如果只读源码，得不到归属；如果只看设备现象，连"这一类缺陷存在过"都无法确认。本文把这三套口径放在一张桌子上，逐章说明**每一层能读到什么、读不到什么、读到之后该怎么归**。

### 1.2 这条通道的规模

一个可以直接读出来的规模感：Apple 在 `xnu` 公开镜像里把 IPC 子系统的实现放在 `osfmk/ipc/` 下，仅 `ipc_port.c` 一个文件就有 3485 行（本轮取回的 `xnu-12377.121.6` tag），端口对象头文件 `ipc_port.h` 里有 12 处 `XNU_PTRAUTH_SIGNED_PTR(...)` 注解——也就是说，**内核设计者自己认为这张表里的指针字段值得逐个加签名保护**。字段有签名保护，不等于字段里的"权利计数"有正确性保护；这正是第 4 章与第 11 章要分开的两件事。

### 1.3 本文的三个问题

1. **分型问题**：一次 IPC 缺陷的错误究竟发生在链条的哪一步——是权利记账、是名称解析、是消息尺寸、是接口校验、是反序列化，还是生命周期？（第 11 章 X1–X12）
2. **归属问题**：这一步的修改权在谁手里——Apple 内核、Apple 守护进程代码、第三方 App 的 XPC 服务、还是设备上的沙箱画像？修完之后设备显示在哪个版本号上？（第 12 章矩阵）
3. **自证问题**：读者手里只有公开文档和自己设备导出的文本时，能做哪几种可复现的只读判定？（第 14–16、19–21 章）

### 1.4 阅读顺序建议

只关心"我这台设备现在算什么状态"的读者，直接看第 17 章判定模型和第 19–20 章脚本；关心缺陷分类的看第 4–11 章；关心"这算谁的漏洞"的看第 12、13、16 章。第 2 章的边界声明必须先读一次，因为它规定了本文与既有 iOS 报告之间的重复内容怎么处理。

---

## 2. 视角声明与本文边界

本文是"归属与口径"视角的 IPC 层分析，不是利用手法汇编，也不是系统架构入门。与本报告集里已有的篇目关系如下：

| 主题 | 本文覆盖 | 去处 |
| --- | --- | --- |
| XNU 内核高危组件全景 | 只取 `osfmk/ipc/` 一层 | 内核高危组件篇（多子系统并列，本文不重复 IO/VM/文件系统） |
| 沙箱逃逸与 PAC 绕过 | 只讨论沙箱对 Mach 名称解析的介入口径 | 沙箱逃逸篇、PAC 系列篇（逃逸链条与指针认证机制的攻防不在本文） |
| 内存损坏原理与攻击面 | 只讨论 IPC 对象的生命周期缺陷（X4/X5 两型） | 内存损坏篇（堆/栈/越界的一般原理不重述） |
| WebKit / 浏览器引擎 | 不覆盖 | 浏览器引擎篇 |
| iMessage 等远程入口 | 只在第 12 章作为"入口到 IPC"的一环出现 | iMessage 入口篇、RCE 综合篇 |
| SPTM / TXM / Exclaves | 不覆盖（那是另一套隔离口径） | SPTM/TXM 架构篇 |
| 越狱与锁定模式 | 只在第 14 章影响"取数可得性"时出现 | 越狱篇、锁定模式篇 |
| 漏洞研究方法论 | 只给出两个可运行脚本 | 方法论篇、学习路线图篇 |

同系列的另外几篇（iMessage 攻击入口、访问控制与应用交互、应用防护与抓包审计、身份认证与通道加密、生物识别安全机制）讨论的是**边界两侧**的东西；本文讨论**边界本身**——名字怎么绑定到进程、权利怎么记账、消息怎么过校验。重复出现在本文里只做一句话引用，不重述。

**范围声明**：全文只讨论公开文档化的机制、Apple 公开镜像源码里可指认的字段与常量、公告口径，以及在这些公开规则之上可以安全实施的只读判定。不提供可用的漏洞利用代码、端口操纵或注入的操作步骤、服务劫持的实现方法；不针对任何具体机型给出攻防操作。本文两个脚本都是离线文本处理：一个读 `.ips`，一个读两份服务名清单，都不写设备、不联网、不改输入文件。所有"核验"指读者对**自有设备导出的文本**或**公开样本**执行采集与比对。

**引用转录约定**：英文原文按原样转录，只做两项字符归一——排版撇号（’）写作 ASCII 撇号（'），排版引号（“ ”）写作直引号（"）；其余字符、大小写不改。复核时还要允许下面六种**排版层差异**，它们不是转录差异：

1. **空白折叠**。存档页面会折行，词与词之间可能隔一个换行或一串空格；检索时把引语里的空格当作"至少一个空白字符"。
2. **手册页是 roff 源码**。`.Nm launchd` 在页面上渲染成 "launchd"，本文引的是渲染文本，roff 标记行不算引语的一部分（所以 "This required key uniquely identifies the job to launchd." 在源码里被 `.Nm` 劈成两行）。这类句子的词间会插进一段标记文本，纯字面检索需在词间放一个短空洞；本文对被劈开的句子逐条按存档行号人工核对过（复核口径见第 26 章首段）。
3. **破折号**。原文里的双连字符 `--` 在页面上渲染为破折号，本文按渲染形态（—）转录。
4. **反引号**。引语内出现的反引号是本文的 markdown 代码标记（为了让 `<Label>.plist` 这类字面量不被当成标签吞掉），不属于原文字符；反引号里的内容本身仍照原样、原大小写抄写。复核时把反引号当作**可选定界符**：原文若用一对引号包住同一个字面量（如手册页里的 `"com.apple.sshd.plist"`），本文写成反引号版本后，去掉定界符两边应完全一致。
5. **省略号**。`…` 与 `...` 都代表原文中被删去的一整段（可能是插入语或括号），长度不固定，复核时按不定长空洞匹配，且删除后剩下的碎片可能紧贴标点（例如 "when a binary runs …, its code directory" 的逗号其实来自被删括号之后）。
6. **引号内的引号**。英文引语里再出现引号时，本文用 `\"` 转写，它只是 markdown 层的转义，原文是普通的 `"`。

两条已知的存档缺口**就地注明、不做修补式改写**：Apple 开发者文档以 JSON 存档，正文代码项（如 `launchd.plist`）会留在行内，但**页面内超链接的标签文本只存在于该页的 references 表里**，扁平正文是空槽。遇到这种情况，本文要么按 references 表回填标签并注明（第 7.3 节 `init(machServiceName:options:)` 一句即如此），要么只引到可核对的前半句（第 6.4 节即如此）。若原文本身有拼写异常（例如 Apple 手册里把 "hierarchy" 写成 "hierachy"），本文保留原样并在需要处注明。

---

## 3. 三套词表：公告、源码、运行时符号

### 3.1 公告词表：Apple 写了什么

Apple 的安全公告文档在页面开头就把口径交代清楚了，这句话在本文里被反复引用：

> "For the protection of our customers, Apple doesn't disclose, discuss, or confirm security issues until an investigation has occurred and patches or releases are generally available."

也就是说，公告词表是**补丁发布之后才存在的表**。它有三个可以直接读出来的特征：

1. 条目按"发布"组织，不按"层"组织。同一次 `iOS 27.2 and iPadOS 27.2` 发布里可能同时出现 `Kernel`、`XPC`、`IOKitUserClient` 三行，它们之间的调用关系不在表里。
2. 组件名是产品口径，不是代码路径口径。`Kernel` 这一行既可能是 `osfmk/ipc/`，也可能是 `bsd/kern/`，从公告文字本身无法区分。
3. 版本线是并行的。本轮取回的公告页面上，同一发布日期 `26 Oct 2026` 下并列挂着 `iOS 27.2 and iPadOS 27.2`、`iOS 26.7.2 and iPadOS 26.7.2`、`iOS 18.7.11 and iPadOS 18.7.11` 三条，各自跟着不同的机型清单。**同一条缺陷在三条线上的修复编号不同**，这是"修到设备上显示在哪个版本号上"这个问题的第一个来源。

### 3.2 源码词表：目录与常量

Darwin 公开镜像侧的口径完全是另一套名词。本文用到的对应关系：

| 公告里可能写 | 源码里的位置与词 |
| --- | --- |
| Kernel | `osfmk/ipc/`（`ipc_port.c` / `ipc_object.c` / `ipc_kmsg.c` / `ipc_entry.c` / `ipc_space.c` / `ipc_mqueue.c` / `mach_port.c`） |
| Kernel | `osfmk/mach/message.h`（描述符类型常量）、`osfmk/mach/mach_port.defs`（Mach 端口接口的 MIG 定义） |
| XPC | `xpc` 对象层与 `libxpc`，`xpc_connection_*` API 族 |
| launchd | `launchd` 作业装配：`Label`、`MachServices`、`LimitLoadToSessionType` 等键 |
| IOKitUserClient | `IOKit` 的 `IOUserClient` 及其 connect 方法族 |

这一张表的用处很窄但很关键：**它只解决"这一行公告大概落在哪一层"，不解决"这一层有多少缺陷"**。缺陷计数不在公开源码里，公开源码里只有实现。

### 3.3 运行时符号词表：日志与崩溃报告里能看到的

第三套词表是设备侧导出的文本里出现的符号名。本文第 19 章脚本的分类词表就是这一套：

- `mach_msg` / `mach_msg2` / `_kernelrpc_mach_msg2_trap`：消息进出内核的那一刻。
- `xpc_*`：XPC 对象与连接层。
- `__NSXPCCONNECTION_*`：Foundation 侧封装等待回包的位置。
- `bootstrap_look_up` / `bootstrap_check_in` / `task_get_bootstrap_port`：名字解析那一刻。
- `CFMessagePort*`：CoreFoundation 侧的老端口封装。
- `_X_<interface>_<routine>`：MIG 生成的服务端例程形态。
- `ipc_port_*` / `mach_port_*`：端口对象与权利操作本身。

### 3.4 三套词表的落差有多大

三套表之间不是简单的一一映射，落差体现在三个方向：

1. **公告 → 源码：不可判定方向**。`Kernel` 一词覆盖整个内核，光看公告文字无法定位到 `osfmk/ipc/`。
2. **源码 → 运行时：命名丢失方向**。源码里的 `ip_mscount`、`imq_qlimit` 这类字段不会以字段名出现在崩溃报告里；回溯里只有函数符号，字段级状态看不到。
3. **运行时 → 公告：数量丢失方向**。设备侧一条崩溃读数不能告诉你它对应哪个 CVE；公告一侧一个 CVE 也不会告诉你它在设备上崩成什么回溯。二者要靠时间线（版本号 × 发布日期）间接对齐，而这种对齐在第 16 章会被明确标为"弱证据"。

**这三条落差是本文后面所有判定模型的基础**：任何声称"从公告直接得出设备风险等级"的做法，都在第 1 个方向上丢了信息；任何声称"看一条崩溃就知道中招没中招"的做法，都在第 3 个方向上丢了信息。

---

## 4. Mach 原语层：端口、权利、名称

### 4.1 三个概念必须分开

Mach IPC 的公开文档里，最容易混淆的三个词是**端口（port）**、**权利（right）**、**名称（name）**：

- 端口是内核里的对象，`ipc_port` 结构体。
- 权利是对这个对象的一种持有关系：发送权（send）、发送额度（send-once）、接收权（receive）、保证金（deposit）。
- 名称是**用户态进程手里的那个整数**，它要在该进程的端口名称空间里查一次才变成内核里的权利。

这一层区分直接决定了类型学：X2 型缺陷（权利记账错误）发生在内核对象上，X3 型缺陷（名称空间/索引错误）发生在"整数到对象"的查表环节上，两者的修复位置、崩溃形态、可见证据都不一样。

### 4.2 端口对象里的字段：能公开读到的部分

`osfmk/ipc/ipc_port.h` 里的字段是公开可读的，几个和缺陷归属直接相关的：

- `ip_receiver`（第 159 行）：这个端口的接收者指向哪个 `ipc_space`。它是"PAC 签名保护的指针"之一，注解写作 `XNU_PTRAUTH_SIGNED_PTR("ipc_port.ip_receiver")`。
- `ip_destination`（第 160 行）：发送权利指向的目标端口，用的是允许 NULL 的签名变体 `XNU_PTRAUTH_SIGNED_PTR_AUTH_NULL`。
- `ip_mscount`（第 193 行）：send-once / send 额度的记账字段。凡是涉及"额度"的缺陷（本文 X2 型），最后都会落到这个字段的收支平衡上。
- `ip_kobject`（第 165 行）：注释明确写着 "manually PAC-ed, see ipc_kobject_get_raw()"——这是"这个字段承载内核对象引用、且需要手工指针认证"的直接书面证据。

`ipc_port.h` 里 `XNU_PTRAUTH_SIGNED_PTR` 出现 12 次。这个读数只说明一件事：**这一层的指针字段是被逐个点名保护的**，因此后面第 11 章把"指针被伪造"和"记账被算错"分成两型是站得住的——前者的防线明确存在，后者不是指针保护能覆盖的。

### 4.3 权利的增减入口

用户态能触到的权利操作入口在内核侧是公开的：`osfmk/ipc/mach_port.c` 里 `mach_port_allocate`（函数体在第 514 行）、`mach_port_mod_refs`（第 889 行）、`mach_port_insert_right`（第 1638 行注释处起）、`mach_port_get_attributes`（第 128 行）。这几个函数就是"权利收支"的闸口：X2 型缺陷如果存在，几乎必然落在这几个入口之一与其调用者的契约不一致上。

`mach_port.defs` 的注释里能看到一条口径性描述：新建端口的引用计数为零、队列上限是 `MACH_PORT_QLIMIT_DEFAULT`。这两个词在后文两处都会用到：容量（第 4.5 节）与类型学 X6 型（消息堆积）。

### 4.4 名称到对象：查表与增长

`osfmk/ipc/ipc_entry.c` 里的 `ipc_entry_lookup`（第 151 行的 `Routine: ipc_entry_lookup` 注释、第 160 行的函数头）和 `ipc_entry_alloc`（第 304 行注释处）就是"整数名称 → 槽位 → 权利"这一步。名称空间本身的容量增长在 `ipc_space.c`。这一层是 X3 型的家：**槽位复用与查表结果的有效性判断**，是"用旧名称访问新对象"这一类缺陷的机制位置。

这一层对读者的可操作性结论只有一句：设备侧任何文本都不会显示槽位号，所以 X3 型**只能靠公告与修复说明间接识别**，不能靠自证发现。它会被登记进第 24 章的边界清单。

### 4.5 容量与配额：一个可读、一个不可读

队列上限是这一层少数"有明确公开常量"的东西：`ipc_mqueue.c` 第 134 行在初始化消息队列时写入 `mqueue->imq_qlimit = MACH_PORT_QLIMIT_DEFAULT`；`mach_port.c` 第 1976 行与第 2568 行分别检查 `mpl_qlimit > MACH_PORT_QLIMIT_MAX`、`options->mpl.mpl_qlimit > MACH_PORT_QLIMIT_MAX`；`ipc_kmsg.c` 第 5510、5562 行在处理消息时比较 `!= MACH_PORT_QLIMIT_DEFAULT`。

这两类读数含义不同：

- **默认值可读**：不设置时队列容量是多少这一档。
- **实际占用不可读**：iOS 没有公开接口让第三方读"某个守护进程端口现在堆了几条消息"。

因此"某个服务被消息堆到上限"这一类现象（X6 型）只能从后果侧识别：守护进程被杀、`.ips` 里出现 `EXC_GUARD` 或异常终止、服务名短暂消失。这是第 15 章脚本词表里 W01 码位存在的理由。

### 4.6 释放是异步的：一条容易被忽略的口径

`osfmk/ipc/ipc_object.c` 第 100 行定义了 `static struct mpsc_daemon_queue ipc_object_deallocate_queue;`，第 152 行把对象入队。也就是说，**权利释放请求与实际对象销毁之间隔着一个异步队列**。这条实现事实对本报告有两个直接推论：

1. "刚刚释放的名字又被查到"不一定是漏洞，可能只是异步窗口；把它判成 X3 需要额外证据。
2. 判定模型（第 17 章）里"单次观测"最多只能到第二级，因为异步销毁使得"两次相邻读数的因果"无法在设备侧文本上确认。

---

## 5. MIG 层：接口契约由谁生成、校验到哪一步

### 5.1 MIG 是什么，为什么它单独一层

Mach Interface Generator 把 `.defs` 文件里的接口声明翻译成两侧的胶水代码：客户端一个包装函数、服务端一个派发例程。内核侧公开可见的例子是 `osfmk/device/device.defs`，本轮取回的这份文件里有 854 行，其中的声明长这样（第 151、156、162 行）：

```
routine io_object_get_class(
routine io_object_conforms_to(
routine io_iterator_next(
```

`osfmk/mach/mach_port.defs` 是同一机制用在端口接口上的例子。MIG 层的价值在于：**接口契约是机器生成的，所以"签名不匹配""参数类型不对"这类错误在编译期就被消灭了**。这决定了本文对 MIG 层的类型学判断——它不是"校验太弱"的家，而是"校验到此为止"的分界线。

### 5.2 校验的分界线在哪里

MIG 生成代码校验的是**结构与类型**：消息大小、例程号、参数按声明的布局搬运。它不校验**语义**：一个 `io_object_t` 引用是否属于调用者、一个端口名是否在调用者的权利集合里、一个长度值在业务上是否合法。

这条分界线在缺陷归属上的意义非常具体：当公告里出现 `IOKitUserClient` 或 `Kernel` 而描述是"攻击者可以构造特定消息"时，最可能的落点是**语义校验缺失**（X7 型），而不是格式校验被绕过。因为格式校验是生成代码做的，跨所有接口一致存在。

### 5.3 服务端例程在符号表里的形态

MIG 生成的服务端例程在符号表里有可识别的名字形态（`_X_<interface>_<routine>`）。这就是第 19 章脚本 W07 码位的依据：一条崩溃如果回溯里出现这个形态，可以直接判"缺陷位置在 MIG 派发之后、服务端实现之内"，从而把归属从"内核通用代码"缩小到"该接口的服务端实现"。

需要明确的限度：**这是形态判断，不是接口身份判断**。脚本只说"这里像 MIG 例程"，不说"这是哪个接口"，因为符号名在真实 `.ips` 里可能被裁剪。

---

## 6. XPC 对象层：序列化边界

### 6.1 这一层的职责

XPC 把 Mach 消息包装成"有类型的对象"：字典、数组、字符串、数据、签名戳、文件描述符、端点。它的公开 API 是 `xpc_*` 族。这一层是 iOS 系统服务之间最常用的一层，因为它同时给了两样东西：**可跨进程传输的表示**与**类型标签**。

### 6.2 类型标签带来的两类缺陷

XPC 对象自带类型标签，取值 API 会检查标签。由此产生两个分立的缺陷类型：

- **X8 型（取错类型未拒绝）**：读取方按 A 类型取值，写入方放的是 B 类型，读取方没有正确处理"取不到"的情形。这是应用层与守护进程层都会犯的错，责任方不同。
- **X9 型（可信字段被当成可信来源）**：把由对端提供的字段（标识、路径、URL、账号名）当作已经由系统认证过的值使用。这一型的修复点几乎总在服务端实现里，不在传输层。

这两型在公告词表里常常被写成一行的 Impact 描述（"允许恶意应用…"），但在源码归属上是两件事：前者是取值路径的分支缺失，后者是信任赋值错误。

### 6.3 端点与反向连接：通道可以在会话中重开

Apple 文档对 `NSXPCListenerEndpoint` 的说明里有一句关键口径：端点对象"may be sent over an existing connection"，接收方可以用它建立到该 listener 的新连接，而且"uniquely names this listener object across connections"。

这条机制的缺陷学意义在于：**一次连接的权限判定不等于一整会话的权限判定**。反向连接是"在已建立的通道里传一个新通道的名字"，于是第 9 章的介入判定（沙箱/entitlement）是在**每一次名称解析**时发生的，不是只在第一次连接时发生。任何按"首次握手已鉴权"来设计的服务端逻辑，在这一点上是错位的（X10 型：生命周期与鉴权时刻错位）。

### 6.4 匿名 listener

同组文档里还有一个入口：`NSXPCListener.anonymous()` 返回一个新的匿名 listener，"Other processes can connect to this listener by passing this listener object's NSXPCListenerEndpoint"。原文这句在后面还有半句（把它交给某个 init 方法与某个连接对象），但存档的文档 JSON 只把 `NSXPCListenerEndpoint` 当作正文代码项抽出，另两个链接标签在存档里是空槽，所以本文只引到可核对的前半句（见第 2 章引用转录约定末段的缺口说明）。匿名 listener 没有可查询的全局名字。这带来一个读者必须知道的限度：**从"服务名清单"里读不到匿名 listener**，所以第 20 章脚本比对的只是**有名字的服务**，清单差集不等于连接面差集。这句话会被写进第 24 章边界清单。

---

## 7. NSXPC 层：远端对象与方法校验

### 7.1 接口对象是校验点

Apple 文档把这一层的职责说得很直白。`NSXPCInterface` 的总述是："This object holds all information about the interface of an exported object or remote object proxy. It describes what messages are allowed, what kinds of objects are allowed as arguments, what the signature of any reply blocks are, and information about additional proxy objects." 而连接上的两个属性各自是必填口径：`exportedInterface`"describes the protocol for the exported object on this connection"，并且"This value is required if a exported object is set."；`remoteObjectInterface` 同样是 required，条件是"if messages are sent over this connection"。

注意这句总述把校验面拆成了三件事：**哪些消息被允许**（方法名集合）、**哪些对象可以作为参数**（类型白名单）、**回包签名是什么**（reply block 类型）。X11 型缺陷因此可以再细分为三个可分别审计的格子，而不是笼统的"接口没配"。

换成缺陷语言：**没有显式声明接口的连接，就是没有方法级校验面的连接**。iOS 系统服务大多不用 NSXPC 而直接用 xpc，但第三方 App 的内嵌 helper 服务几乎都用 NSXPC。因此 X11 型（接口未声明即导出对象）是应用侧缺陷，责任方是开发者，更新通道是 App Store 而非系统更新——这一点在第 12 章归属矩阵里会体现为整行不同的值。

这一格还有两条 Apple 明确写出的边界，正好界定"这类缺陷的影响半径"："Elevating a service's privileges to root is not supported. Further, an XPC service is private, and is available only to the main application that contains it."（XPC 服务指南）。也就是说 App 内嵌 XPC 服务**既不会被授予 root，也不对同设备上其他 App 开放**——它的对端只有宿主 App 自己。因此同一型缺陷在 App 内嵌服务与系统 daemon 上的运营含义完全不同（第 11 章 X11 的"影响面"列与第 12 章的责任列都据此分开）。

### 7.2 对端身份：文档给出的两个可用属性

Apple 在这一层给了两个可用来做服务端判定的公开属性：

1. **审计会话标识**：`auditSessionIdentifier` 的文档写的是"The BSM audit session identifier for the connecting process"，并且明确"This attribute may be used by the listener delegate to accept or reject connections."
2. **代码签名要求（两个方向、两个 API）**：Apple 把这层校验拆给连接的两侧，且两侧的方法名不同：
   - 调用侧 `NSXPCConnection.setCodeSigningRequirement(_:)`："Sets the code signing requirement for this connection." / "Use this method to enforce a code-signing requirement on the peer process of an XPC connection."
   - 服务侧 `NSXPCListener.setConnectionCodeSigningRequirement(_:)`："Sets the code signing requirement for connections to this listener." / "Use this method to enforce a code-signing requirement on incoming XPC connections."，文档还给了用途口径："The following example shows how a listener can ensure that the XPC client service on the other end of a connection has a specific entitlement."

   两侧共用的失败行为口径是："Calling this method with a malformed requirement results in a fatal error in Swift, or throws an exception in Objective-C. If new messages don't match the requirement, the connection becomes invalidated."

3. **接入与否决点**：`NSXPCListenerDelegate` 的 `listener(_:shouldAcceptNewConnection:)` 文档口径是"To reject the connect, return a value of ... This causes the connection object to be invalidated."，即服务侧有一个显式的"每条新连接都可以被否决"的位置。

前三条是本文能给出的**最硬的防御建议依据**：判定对端不是靠对端自报的身份（那是 X9 型），而是靠内核/安全框架提供的这两个属性与这两个否决点。"malformed requirement 会导致 Swift 里致命错误、Objective-C 里抛异常"这一句还说明：**写错的签名要求不是静默放行，而是硬失败**——这决定了第 18 章 K5 指标的度量方式（要求是否存在且能解析，而不是要求是否"看起来严格"）。另需注意方向性：只配调用侧不配服务侧，等于只验"我要连的人"，不验"谁来连我"。

### 7.3 连接建立路径的三种命名口径

`NSXPCConnection` 的初始化入口在文档里分成几个不同来源，本文把它们当作"三种可核验的口径"：

- `init(serviceName:)`：连到 App 包内的 XPC 服务。文档口径："XPC services are helper processes that are usually part of your application bundle."
- `init(machServiceName:options:)`：连到 launchd 管的 agent/daemon。文档口径："Initializes an NSXPCConnection object to connect to a LaunchAgent or LaunchDaemon with a name advertised in a launchd.plist"（这句里的 `NSXPCConnection` 在文档存档里是一个链接项，扁平正文只留下空槽，标签按该页 references 表回填；`launchd.plist` 是正文代码项，存档里原样在位——见第 2 章约定的缺口说明），并且"If the connection is being made to a process that is running in a privileged Mach bootstrap context ... then pass the ... option."
- `init(endpoint:)` / `init(listenerEndpoint:)`：连到一个已经在手里传过来的端点，没有全局名字。

这三种入口对应三种不同的"名字在哪里解析"，也就对应三种不同的归属结论。第 8 章讲前两种的名字来源，第 9 章讲第三种没有名字来源时的判定。

---

## 8. launchd 装配层：Label、MachServices 与生命周期

### 8.1 名字是装配期绑定的，不是运行期注册的

launchd 的属性列表手册给了这一层最硬的公开口径。`MachServices` 键的说明是："This optional key is used to specify Mach services to be registered with the Mach bootstrap sub-system. Each key in this dictionary should be the name of service to be advertised. The value of the key must be a boolean and set to true."

三个推论：

1. 服务名是**声明**出来的，因此它是可枚举的（前提是拿得到 plist）。这就是第 20 章脚本比对的两类输入之一。
2. `true` 值才注册，字典形态还允许更细的属性——所以同一个 Label 在不同版本里可能改变服务集合而不改变可执行文件，这是服务清单漂移的第二种成因（第 20 章 D05 判定要区分"进程变了"与"装配变了"）。
3. 名字绑定发生在 bootstrap 子系统，而 bootstrap 上下文有多个（见 8.3），**同名不同域是两个服务**。
4. 名字还可以"先占后放"：`HideUntilCheckIn <boolean>` 的口径是"Reserve the name in the namespace, but cause `bootstrap_look_up()` to fail until the job has checked in with launchd."（同一份手册在 MachServices 段末尾还写明 "the values will be replaced with Mach ports at the time of check-in"）。也就是说**"名字存在于命名空间"与"名字可被查到"是两件事**——一条"服务名查不到"的读数，可能是装配期故意设成不可查，而不是服务缺失。这是第 20 章 D02（消失）必须与装配声明一起读的原因。

### 8.2 Label 的约定与它的取证价值

手册明确："it is the expected convention for launchd property list files to be named `<Label>.plist`. Thus, if your job label is `com.apple.sshd`, your plist file should be named `com.apple.sshd.plist`."；`Label` 是 "This required key uniquely identifies the job to launchd."

对只读核验的意义：Label、plist 文件名、MachServices 里的名字三者**本应一致或有可解释的差异**。差异本身就是读数。第 20 脚本的词表里 W04（非"段.段"形态）、W05（含空白）、W07（完全重复）、W06（大小写归一后重名）四个码位，就是在检查这个一致性有没有被采集口径破坏。

### 8.3 域：会话类型与特权 bootstrap

先立两个词的官方定义，后文的"域"才有着落。`launchd(8)` 写的是："In the launchd lexicon, a \"daemon\" is, by definition, a system-wide service of which there is one instance for all clients. An \"agent\" is a service that runs on a per-user basis. Daemons should not attempt to display UI or interact directly with a user's login session."——**daemon 与 agent 的差别不是权限高低，是"一个实例服务所有客户端"还是"每用户一个实例"**。这句话决定了第 12 章归属矩阵里"责任方"一列：同一型缺陷落在 daemon 上影响所有用户，落在 agent 上只影响该用户会话。

`LimitLoadToSessionType` 的文档口径是"This configuration file only applies to sessions of the type specified"，并且它与 `launchctl` 的 `-S` 参数配合使用；会话类型的公开列举是"Currently known session types include: Aqua, LoginWindow, Background, StandardIO and System"，域是"Valid domains include \"system,\" \"local,\" \"network\" and \"all.\""。加上第 7.3 节引的"privileged Mach bootstrap context"，可以得到一条常被忽略的判定规则：**一个服务名的可达性取决于调用者所在的域**。同一个名字在 GUI 会话里不可达、在系统域里可达，是完全正常的装配结果，不是缺陷。

这条规则有直接的书面依据，不再只是推论——`launchctl(1)` 的 `bslist` 子命令原文写着："While the namespace appears flat, it is in fact hierarchical, thus allowing for certain services to be only available to a subset of processes. The three states a service can be in are active (\"A\"), inactive (\"I\") and on-demand (\"D\")"。三态的存在还说明**"在名单里"本身不是单一状态**：一个名字可以是"已注册但当前不活跃"。第 20 章脚本比对的输入没有状态维度（它是文本清单），因此 D04（集合一致）**不能**用来回答"两侧的服务状态是否一致"——这是第 22 章误区 8 的书面根据。

这条规则决定了本文对"某某守护进程连不上"这一类现象的第一问不是"是不是漏洞"，而是"两侧在同一个域吗"。第 22 章误区 3 就是这一条。

### 8.4 生命周期：退出超时、按需拉起与 SIGKILL

生命周期有两段互补的公开口径。一段来自装配手册，`ExitTimeOut` 的文档："The amount of time launchd waits before sending a SIGKILL signal. The default value is 20 seconds. The value zero is interpreted as infinity."另一段来自 Apple 的 XPC 服务指南总述："XPC services are managed by launchd, which launches them on demand, restarts them if they crash, and terminates them (by sending SIGKILL) when they are idle."

两句合起来才有用：**拉起、崩溃重启、闲置回收三件事都由 launchd 做，且回收方式是 SIGKILL**。这条口径直接决定第 19 章脚本的可见范围——闲置回收不是异常终止，不产生 `exception` 对象，因此脚本读不到它；反过来，"这条崩溃读数里看不到某个服务被终止过"也不等于"这个服务没被终止过"。同一个道理适用于第 20 章：清单漂移读的是名字集合，不读进程生死。

这一条读数的用途是校准时间线：当设备侧日志里出现"某服务在某时刻消失、约 20 秒后重新出现"时，20 这个数字与一个公开的默认值吻合，说明"消失"更可能是退出流程而不是崩溃（崩溃的重启时机由另一种机制决定）。**这类校准是弱证据，只能降权，不能定案**——它会作为第 17 章判定模型第 2 级的一个例子出现。

同一份手册还把进程分类与 XPC 直接挂钩："Adaptive jobs move between the Background and Interactive classifications based on activity over XPC connections."（`ProcessType` 段，另注明 "Standard jobs are equivalent to no ProcessType being set."、"Interactive jobs run with the same resource limitations as apps, that is to say, none."）。这条口径的价值在于**解释一类容易被误读成缺陷的现象**：一个 Adaptive 型守护进程的资源限制会随 XPC 活动变化，因此"同一服务有时响应慢、有时被限流"可能是分类切换而不是 IPC 缺陷。第 22 章误区 6 用的就是这条。

### 8.5 装配层的缺陷位置

装配层的缺陷不体现在代码里，体现在**声明与实现不一致**上，本文登记两型：

- **X12 型（声明面大于实现面）**：`MachServices` 里 advertise 了一个服务端实际不处理的名字，或处理了但语义与调用者预期不符。后果是"接得上、行为未定义"。
- **X10 型的一个变体（域错配）**：只在某个会话类型装配，却在另一个会话类型被假定可达。它不是安全缺陷，但它是缺陷归属讨论里最常见的错判来源。

这两型的共同点：都能靠比对两份"声明清单"发现异常迹象，都不能靠比对清单确定它是漏洞。这正是第 20 章脚本的定位边界，也是第 24 章会写死的一句话：**脚本给出的是"该问哪个问题"，不是"答案"**。


---

## 9. 介入口层：entitlement 与沙箱的 mach-lookup

### 9.1 这一层为什么单列

第 4 章讲的是"权利对不对"，第 8 章讲的是"名字注册在哪"。中间还有一层：**一个进程能不能把一个名字解析成另一个进程的权利**。这一层是 iOS 上"越权连接"这条路径的唯一守门人，所以它的缺陷归属与前面两层的归属结论完全不同——修它不改 `ipc_port.c`，改的是画像（policy）或服务端的自检。

Apple 的平台安全文档在描述这类强制控制时给的口径可以直接引用（原文以 macOS 为主语，iOS 上同一套机制由同一实现承载）：

> "macOS uses mandatory access controls—policies that set security restrictions, created by the developer, that can't be overridden."
>
> "Mandatory access controls aren't visible to users, but they're the underlying technology that helps enable several important features, including sandboxing, parental controls, managed preferences, extensions, and SIP."

第二句里"aren't visible to users"这一条对本文特别重要：**它是"设备侧不可自证"这一判断的书面来源之一**。强制控制存在且生效，但它的规则内容与命中记录对普通用户（对第三方 App 也一样）不透明。

### 9.2 身份从哪来：entitlement 与代码签名

平台安全文档里对身份的两条口径：

> "Nonplatform binaries (for example, notarized third-party code) need to have valid certificate chains to execute, and the entitlements they may possess are constrained by the signing profile issued to the developer by the Apple Developer Program."

> "When a binary runs ..., its code directory is extracted and hashed. If the resulting hash is found in the trust cache, the executable mappings created for the binary will be granted platform privileges—that is, they may possess any entitlement and execute without further verification as to the authenticity of the signature."

这两句合起来给出了一个可操作的归属判据：**"谁被允许连"这个问题，答案在签名画像里，不在代码里**。所以 X10/X12 之外的"连接面过宽"缺陷，修复动作有两种：改服务端（加对端校验，见第 7.2 节两个属性），或改画像（收窄 entitlement / 沙箱规则）。前者随系统更新或 App 更新发布，后者随系统更新发布——这条区分在第 12 章矩阵里就是一列。

### 9.3 中介 lookup 的明文口径（Apple 归档的临时例外 entitlement）

沙箱"中介 Mach 名称解析"这件事，Apple 在归档的 entitlement 参考里给了最直白的一句（原文以 macOS App Sandbox 为主语，是归档文档，不是当前 iOS 画像的清单）：

> "With App Sandbox, lookup of global Mach services fails unless you configure the mach-lookup.global.name temporary exception entitlement."
>
> "com.apple.security.temporary-exception.mach-lookup.global-name — Enables lookup of one or more global Mach services."
>
> "With App Sandbox, dynamic registration of global Mach services fails unless you configure the mach-register.global-name temporary exception entitlement."

三条口径各对应本文的一个判定位：

1. **"默认失败"是明文口径**，不是推测。因此"连不上某个全局服务"在缺省状态下是**预期行为**，它本身不构成任何缺陷读数（第 22 章误区 3 的第一问）。
2. **lookup 与 registration 是两个独立的例外键**。也就是说"能不能查名字"和"能不能占名字"是两条分别审的通道——一个服务端画像允许注册但调用者画像不允许查询，是完全可能的配置结果。第 20 章脚本比对的"清单差异"里，有一类差异的成因就在这一格。
3. **临时例外是点名式白名单**（"one or more global Mach services"），因此可达集合是**可枚举的**——前提是可读到画像。iOS 上读者读不到画像（9.6 节表第二行），这一条只对 macOS 上的同类服务成立，属于类比证据。

需要写死的限度：这三个 entitlement 键出自 Apple 的 **macOS App Sandbox 归档文档**，Apple 未公开 iOS 侧的 mach-lookup allow/deny 规则清单，也未公开系统 daemon 使用的私有 entitlement。本节只能作为"机制形态"的口径，不能作为"iOS 上某服务名是否可达"的判定依据（第 24 章边界清单第 2 条）。

### 9.4 关于 Mach 对象的一条容易被忽略的口径

同一文档在讲签名与 SSV 关系时有一句话直接落在本文主题上：

> "Code signing is still present and enforced by the kernel. The signed system volume ... contrast, code signing provides protection when Mach objects are memory mapped as executable."

也就是说，**签名保护的覆盖面包含"Mach 对象被作为可执行映射"这条路径**，而不包含"某个 Mach 权利被谁持有"。这两件事在讨论"代码签名挡住了什么"时经常被合并成一句"签名挡住了未授权代码"，实际边界要窄一些。

### 9.5 解析层的隔离：一条公开的架构口径

对"不可信输入先在哪儿处理"这件事，文档给了 BlastDoor 的例子（原文）：

> "BlastDoor isolates, parses, transcodes, and validates untrusted data arriving in Messages, IDS and other vectors to help prevent attacks."
>
> "BlastDoor does this by employing sandbox restrictions and memory safe validation of output which creates a significant obstacle for attackers to overcome before reaching other parts of the operating system."

对本文的用处不是 Messages 本身，而是它示范的**结构**：把一个易错层（解析）搬到另一个沙箱里，只把经过校验的输出交给主进程。这就是 X9 型（把对端字段当可信来源）的系统级解法。凡是 IPC 服务端把"对端送来的已解析对象"直接用于路径、账号、URL 决策的，都属于没有做这一层拆分——第 18 章 K6 指标就是数这个。

### 9.6 设备侧可读到与读不到

| 问题 | 能否只读自证 | 说明 |
| --- | --- | --- |
| 我的 App 能不能连某个具名服务 | 能（在真机上写一个只读探测并记录结果） | 结果只能证明"这台设备上此刻可达/不可达"，不能证明画像规则内容 |
| 某个 daemon 的 MachServices 集合 | 不能（iOS 上取不到 plist） | 只能从公开文档、或从 macOS 上的同类画像间接推断 |
| 沙箱对某次 lookup 的判定 | 不能 | 强制控制"aren't visible to users"，命中记录不在用户可见导出里 |
| 对端进程的身份属性 | 服务端能，客户端不能 | 服务端可读 `auditSessionIdentifier` 等（第 7.2 节） |

这一张表是第 24 章边界清单的第一块内容。

---

## 10. IOKit user client：另一侧的 Mach 表面

### 10.1 为什么硬件侧的入口也在 IPC 讨论里

驱动的用户态入口 `IOUserClient` 不是一套新通道，它就是 Mach 消息：客户端拿到一个端口，向它发消息，内核侧的 `IOUserClient::ipcEnter` / `ipcExit`（公开源码 `Kernel/IOUserClient.cpp` 第 603、622 行）负责进出这次调用。也就是说第 4 章的权利模型、第 5 章的接口契约模型在这里全部适用，只是"接口的语义校验"换成了驱动自己写的 selector 分派。

公开源码里还能读到这一层有调用统计：`IOStatistics::registerUserClient` / `unregisterUserClient` / `countUserClientCall`（同一文件第 91、97、102 行的宏体内）。这说明"当前有多少 user client、每个被调用过多少次"在内核里是**有记账的**——但对第三方不导出。这是本章的可见性结论：统计存在，读者读不到。

### 10.2 接口契约的规模感

`osfmk/device/device.defs` 本轮取回件里以 `routine` 开头的声明共 **90** 条（其中 5 条写作 `routine FUNC_NAME(...)` 的 MIG 多态形态；该文件内**没有** `kernel_routine` 声明，这一点计数时也要说明，否则读者按两个字面量去复算会得到 85）。这是"一个 .defs 文件能带出多少个内核侧可调用入口"的一个具体数量级读数，也说明第 5 章那条分界线的现实体量：90 个入口的格式校验由生成代码统一负责，90 个入口的语义校验各自由实现负责。

### 10.3 类型学落点

IOKit user client 层的缺陷基本落在三型：

- **X7（语义校验缺失）**：selector/参数在内核侧被接受但没有做对象归属或范围校验。公告里 `IOKitUserClient` 一词的条目多数落这里。
- **X4（生命周期/引用）**：`IOUserClient::destroyUserReferences`（第 353 行）这一类"引用释放"路径上的记账问题。
- **X2（权利记账）**：与端口层同型，只是触发点在驱动的连接/断开流程。

对读者的可操作结论只有一条：**这一层完全不可自证**。iOS 上不导出 user client 清单，也不导出 selector 表；能做的只有把"设备侧某驱动进程异常"与公告条目做时间线对齐（弱证据）。

---

## 11. 缺陷类型学 X1–X12

本节按"错误发生在链条的哪一次校验"分型。每型给：定义、机制位置（可指认到公开源码或公开文档的位置）、设备侧可读到的现象、归属结论、缓解动作。**不按 CVE 编号分型**，因为编号是发布事件，不是类型。

| 型 | 名称 | 机制位置 | 设备侧现象 | 归属 |
| --- | --- | --- | --- | --- |
| X1 | 尺寸与取整错误 | `message.h` 的 `round_msg`（第 937 行）、`MACH_MSG_SIZE_MAX`（第 965 行）与调用者自算的长度 | 内核拒绝消息 / 守护进程崩溃，回溯里有 `mach_msg` 帧 | 发送方（可能是 App 侧） |
| X2 | 权利记账错误 | `ip_mscount`（`ipc_port.h:193`）、`mach_port_mod_refs`（`mach_port.c:889`） | 偶发 `EXC_GUARD`；或端口"该有权利时没有" | Apple 内核或调用方，取决于哪次收支不平 |
| X3 | 名称空间/槽位复用 | `ipc_entry_lookup`（`ipc_entry.c:160`）、`ipc_entry_alloc`（同文件第 304 行） | 无法从设备侧文本识别 | 内核 |
| X4 | 对象生命周期/释放竞态 | `ipc_object_deallocate_queue`（`ipc_object.c:100,152`）、`ipc_port_free`（`ipc_port.c:3216`）、`destroyUserReferences` | 服务突然消失又出现；UAF 型崩溃 | 内核 / IOKit |
| X5 | 守卫与所有权绕过 | `MPO_CONTEXT_AS_GUARD`、`MPO_STRICT`（`mach_port.h:509,514`）、`MACH_MSG_GUARDED_PORT_DESCRIPTOR`（`message.h:386`）、`MACH_PORT_GUARD_INFO`（`mach_port.h:445`） | 严格守卫断言触发；`EXC_GUARD`  subtype 可见 | 内核（守卫实现）或调用方（守卫值传错） |
| X6 | 配额与消息堆积 | `imq_qlimit = MACH_PORT_QLIMIT_DEFAULT`（`ipc_mqueue.c:134`）、`MACH_PORT_QLIMIT_MAX` 检查（`mach_port.c:1976,2568`） | 守护进程无响应后被杀、服务短暂不可达 | 服务端（未限流）+ 内核（默认容量） |
| X7 | 接口语义校验缺失 | MIG 派发之后的服务端实现；`device.defs` 90 条声明各对应一个 | 越权结果，崩溃不一定出现 | 该接口的实现方（Apple 守护进程或驱动） |
| X8 | 类型取值未拒绝 | xpc 对象取值 API 的返回分支 | 逻辑错误、异常；不一定崩 | 接收方实现 |
| X9 | 对端字段被当可信来源 | 服务端把 URL/路径/账号/标识直接采信 | 越权读写、隐私面扩大 | 服务端实现 |
| X10 | 鉴权时刻与生命周期错位 | 端点可在会话中传递（第 6.3 节），反向连接重新过一遍 lookup | 首次握手后的后续连接未再校验 | 服务端实现 |
| X11 | 接口未声明即导出对象 | `exportedInterface` required（第 7.1 节文档口径） | 任意可连者都能调到导出对象 | App 开发者 |
| X12 | 声明面与实现面不一致 | `MachServices` 声明（`launchd.plist(5)`）与服务端实际处理的名字 | 连得上但行为未定义；清单漂移 | 装配方（系统 or App 打包） |

### 11.1 分型的三条判据

三型之间容易混，本文用三条判据把它们分开：

1. **错在谁的代码里**：内核（X2/X3/X4/X5/X6 的容量侧）还是某个服务实现（X7–X12）。这条决定"谁修"。
2. **有没有崩溃**：X1–X6 通常在消息进出内核的那一刻有可观察后果；X7、X9、X10 常常**不崩**，因为语义错误本身就是被允许的行为。这条决定"能不能自证"。
3. **能不能复述成一句契约**：能写成"调用方应满足 P，被调方假定 P"的，是 X7/X8/X9/X10/X11；写成"内核应保证不变式 I"的，是 X2–X6。这条决定"缓解动作长什么样"。

### 11.2 一个必须写出来的限度

X3、X5 的守卫实现细节、X7 的 selector 表内容，在 iOS 设备侧**都没有只读导出路径**。因此本类型学里这几型的"现象"一列写成"无法从设备侧文本识别"不是省略，而是结论：任何声称能用设备侧日志筛出 X3 的方法都应被质疑。

---

## 12. 归属矩阵：层 × 责任 × 更新通道 × 证据

### 12.1 矩阵

行是本文前十章的层，列是四个归属问题：这段代码归谁、修好之后随什么通道发布、设备侧读者能拿到什么证据、证据强度。

| 层 | 责任方 | 更新通道 | 设备侧证据 | 强度 |
| --- | --- | --- | --- | --- |
| Mach 端口对象与权利（第 4 章） | Apple 内核 | 系统更新（整机版本） | `.ips` 里 `EXC_GUARD` / 内核帧；不显示字段状态 | 弱-中 |
| 名称空间/槽位（第 4.4 节） | Apple 内核 | 系统更新 | 无 | 无 |
| 消息构造与尺寸（第 4.5 节） | 发送方（可为 App 或守护进程） | 随发送方所在包 | 崩溃回溯、错误码 | 中 |
| MIG 契约（第 5 章） | 生成器 + 接口作者 | 系统更新 | 回溯里的 `_X_` 形态帧 | 中 |
| XPC 对象层（第 6 章） | Apple libxpc + 双侧实现 | 系统更新（服务端）/ App 更新（App 侧 helper） | 回溯 `xpc_*` 帧、清单漂移 | 中 |
| NSXPC 层（第 7 章） | 主要是 App 开发者 | App 更新 | App 侧崩溃、接口是否声明 | 中（对 App） |
| launchd 装配（第 8 章） | 声明文件作者（Apple 或 App 包） | 系统更新 / App 更新 | 服务名清单比对（第 20 章脚本） | 中 |
| bootstrap 命名与域（第 8.3 节） | Apple（launchd 与系统镜像） | 系统更新 | 无公开导出：某个 bootstrap 域里现在有哪些名字，第三方读不到（第 24 章 B5、B6） | 无 |
| 沙箱与 entitlement（第 9 章） | Apple 画像 + 签名画像 | 系统更新 | 可达性探测；规则内容不可见 | 弱 |
| IOKit user client（第 10 章） | Apple 内核 + 驱动方 | 系统更新（含固件部分） | 无公开导出 | 无 |

### 12.2 这张表的三个读法

1. **"层"决定"通道"**：同一型缺陷（比如 X9）发生在守护进程里就随系统更新，发生在 App 内嵌 helper 里就随 App 更新。归属讨论里最常见的错误是把两者混成"等 Apple 修"。
2. **强度列决定判定上限**：设备侧证据只有"无"或"弱"的层，任何判定最多到第 17 章的第二级。
3. **证据列与脚本对应**：表里"清单漂移"由第 20 章脚本产生，"`.ips` 回溯/EXC_GUARD"由第 19 章脚本产生。这两列是本文唯一可以复现地生产的证据。

### 12.3 "修了"在设备上显示成什么

iOS 侧的"修好了"只有三种可观察形态：

- 整机版本号前进（例如公告页上 `iOS 27.2 and iPadOS 27.2` 与其机型清单，本轮取回时同批还有 `iOS 26.7.2`、`iOS 18.7.11` 两条并行线）。
- 轻量安全更新生效。这一格在 2026 年发生了口径变化，两条都要记：RSR 时代的原文是"Rapid Security Responses deliver important security improvements between software updates and are available only for the latest versions of iOS, iPadOS, and macOS."（取回的该文档标题本身即限定在 `iOS 16.5.1 and iPadOS 16.5.1`）；Apple 现在对同一位置的描述是《About Background Security Improvements for iOS, iPadOS, and macOS》（Published Date: September 14, 2026），原文："Background Security Improvements deliver additional security protections between software updates."、"Background Security Improvements deliver lightweight security releases for components such as the Safari browser, WebKit framework stack, and other system libraries that benefit from smaller, ongoing security patches between software updates."、"Background Security Improvements are supported and enabled for future releases starting with iOS 26.1, iPadOS 26.1, and macOS 26.1."
  注意那句 "only for the latest versions" 与 "starting with iOS 26.1" 的组合作用：**不在最新版本的设备、低于 26.1 的版本线，既拿不到 RSR 也拿不到 BSI**，只能等完整更新。同时 BSI 的覆盖面口径是按组件写的（Safari / WebKit 栈 / 其他系统库），XNU 内核与 launchd 不在那句列举里——因此"某条 IPC 修复会不会走 BSI"这个问题，公开文档没有答案（第 24 章边界清单）。BSI 还有两条与取证时间线直接相关的口径："In rare instances of compatibility issues, Background Security Improvements may be temporarily removed and then enhanced in a subsequent software update."，以及"如果用户移除已应用的改进，设备回到基线更新"（原文 "your device reverts to the baseline software update (for example, iOS 26.3) with no Background Security Improvements applied"）——即这一格的到达与否**可以被撤销**，与下一条"单向"判断并不矛盾：可撤销的是轻量改进，不是整机版本。
- 什么都不显示。签名、权利、selector 层面的修复不会以任何设备侧可读字段呈现。

再加上文档里的另一条口径——"after a software update is installed for iOS, iPadOS, tvOS, watchOS, and visionOS, it cannot be downgraded to the previous version"——更新通道是单向的，所以"修复没修好"这类判断无法用回退验证，只能用行为验证；而第 12.1 那张表里多数层的行为验证强度是弱。这个组合是本文对 iOS IPC 缺陷运营的核心结论：**修得快不等于证得明**。

---

## 13. 公开案例读数

本章是第 17 章承诺过的那张"每行标注可达级"的表。它不是案例复盘：不还原攻击链、不讨论触发条件、不给任何可操作步骤。它只做一件事——把 Apple 安全公告里凡是被归到 `libxpc` 与 `XPC` 两个组件名下的条目**取出来、数清楚、并说明每一行最多能被读到什么程度**。本章所有数字都来自本地缓存的一次机械抽取，取数规则写在 13.1，三处会改变这些数字的口径落差写在 13.2，读者用同一规则重跑应当得到同一张表。

### 13.1 取数规则与总量

取数件：Apple Support 的《About the security content of …》系列文档，本地缓存 **366 份**（当前版式的 313 份在 `pages/`，早期版式的 53 份在 `oldpages/`，每份都同时保存渲染后的纯文本与原始 HTML）。抽取谓词只有三条，全部是行级文本判断，不需要任何设备访问：

1. **组件块头**：一条非空行，其**下一条非空行以 `Available for:` 开头**，且它自己不以 `CVE-`、`Impact`、`Description`、`Available`、`We would` 起始。命中即把该行文本当作组件名。
2. **字段行**：块头之后，以 `Impact:` 起首的行取其第 9 个字符起为影响原文，以 `Description:` 起首的行取其第 14 个字符起为处置原文。这两个偏移就是 `Impact: ` 与 `Description: ` 的字符长度。
3. **条目行**：块头之后出现的第一条 `^CVE-YYYY-NNNN` 行即关闭该块；若该行含冒号，冒号之后的文本按原文记为署名，若不含冒号则记为"无署名"（13.2 的第二条落差）。只有组件名恰为 `libxpc` 或 `XPC` 的块才进入本章统计。

按这三条重跑，总量如下：

| 读数 | 值 |
| --- | --- |
| 条目行（同一 CVE 在不同发布文档里各算一行） | **104** |
| 去重后的 CVE | **27** |
| 组件名为 `libxpc` 的行 / 为 `XPC` 的行 | 96 / 8 |
| 出现过的发布文档标题（去重） | 72 |
| 覆盖的产品线 | iOS、iPadOS、macOS、tvOS、watchOS、visionOS（6 条） |
| CVE 编号年份跨度 | 2020 → 2026 |

`104 / 27 ≈ 3.85`：平均每个缺陷在公告里占近四行。这个比例本身就是本章第一个结论，13.6 会把它变成一条口径纪律。

### 13.2 三处口径落差，全部能在这份数据里指认

这三条落差不是设想，是本轮实测出来、可复查的。它们分别会让同一个问题的答案变化 1、7、以及"归到哪一层"。

**落差 A：同一个子系统在公告词表里有两个名字。** 组件名 `libxpc` 出现 96 次、`XPC` 出现 8 次，而这两个名字**可以在同一份文档里并存**：缓存件 `pages/149035.txt`（《About the security content of macOS Golden Gate 27》）在行 4795、4820、8130 有三处 `libxpc` 块头，同时在行 7565 有一处 `XPC` 块头，前者关闭为 CVE-2026-86894 与 CVE-2026-84577，后者关闭为 CVE-2026-84617。也就是说，按组件名筛"XPC 相关的修复"必须同时筛两个字面量；只筛 `libxpc` 会漏掉 8 行，只筛 `XPC` 会漏掉 96 行。公告没有给出这两个名字何时用哪个的规则，本文也不做推断（第 24 章边界清单）。

**落差 B：冒号决定一条 CVE 是否被计数。** 抽取谓词第 3 条最初写作"以 `CVE-YYYY-NNNN:` 开头"，即要求冒号，因为绝大多数条目行的形态是 `CVE-2024-23201: Koh M. Nakagawa of FFRI Security, Inc. and an anonymous researcher`。但 Apple 对**没有外部署名的条目**会写成裸编号行。实测就在缓存件 `pages/120909.txt`（《About the security content of iOS 17.6 and iPadOS 17.6》）：`libxpc` 块之后依次是 `Available for:`、`Impact: An app may be able to bypass Privacy preferences`、`Description: A permissions issue was addressed with additional restrictions.`，然后是一行不带冒号的 `CVE-2024-40805`。要求冒号的规则得到 100 行 / 26 个 CVE；放宽到"裸编号也关闭块"得到 104 行 / 27 个 CVE。**唯一差的就是 CVE-2024-40805 这一族（4 份文档各一行）。** 这条落差值得单独写出来，因为它造成的偏差不是随机的：被漏掉的恰好是"无外部署名"那一条，而"有多少缺陷是内部发现、多少来自外部研究者"正是有人会用这张表回答的问题——用冒号规则回答它，答案会系统性偏向"外部"。

**落差 C：按行数组件名会多算。** 最省事的统计是 `grep` 出恰好等于 `libxpc` 或 `XPC` 的行并计数，本轮实测这个朴素计数在 `pages/` 得到 103 行，而抽取规则在同一个目录只得到 96 行，多出的 7 行**全部来自致谢段**：Apple 在每份文档末尾的 "We would like to acknowledge …" 清单里也会单行列出组件名，形如 `libxpc` 后面直接跟 `We would like to acknowledge Rasmus Sten, F-Secure (Mastodon: @pajp@blog.dll.nu) for their assistance.`。可指认的实例：`pages/121238.txt` 行 3300、`pages/149035.txt` 行 8130，另有 `pages/120881.txt`、`120882.txt`、`120893.txt`、`120895.txt`、`122373.txt` 各一处。抽取谓词第 1 条要求"下一非空行以 `Available for:` 开头"，正是这条限定把 7 处致谢挡掉。两个方向都查过了：本缓存里**不存在**一个块头关闭出两条 CVE 的情形，所以误差是单向的（朴素计数只会偏高，不会偏低）。

### 13.3 条目表

下表的"影响原文"与"处置原文"是公告字段的逐字转录（按第 2 章引用转录约定：弯引号转直引号、原文拼写不改），"页数"是该 CVE 在 72 份文档里出现的次数。归层一列是**本文口径的推断**，公告本身没有机制描述（见 13.5 的映射依据与置信说明）。

| CVE | 公告组件名 | 影响原文（Impact） | 处置原文（Description） | 页数 |
| --- | --- | --- | --- | --- |
| CVE-2020-9971 | libxpc | A malicious application may be able to elevate privileges | A logic issue was addressed with improved validation. | 2 |
| CVE-2020-10014 | libxpc | A malicious application may be able to break out of its sandbox | A parsing issue in the handling of directory paths was addressed with improved path validation. | 1 |
| CVE-2021-30652 | libxpc | A malicious application may be able to gain root privileges | A race condition was addressed with additional validation. | 2 |
| CVE-2023-27944 | XPC | An app may be able to break out of its sandbox | This issue was addressed with a new entitlement. | 1 |
| CVE-2023-32369 | libxpc | An app may be able to modify protected parts of the file system | A logic issue was addressed with improved state management. | 1 |
| CVE-2023-32405 | libxpc | An app may be able to gain root privileges | A logic issue was addressed with improved checks. | 1 |
| CVE-2023-38565 | libxpc | An app may be able to gain root privileges | A path handling issue was addressed with improved validation. | 3 |
| CVE-2023-38593 | libxpc | An app may be able to cause a denial-of-service | A logic issue was addressed with improved checks. | 3 |
| CVE-2024-0258 | libxpc | An app may be able to execute arbitrary code out of its sandbox or with certain elevated privileges | The issue was addressed with improved memory handling. | 4 |
| CVE-2024-23201 | libxpc | An app may be able to cause a denial-of-service | A permissions issue was addressed with additional restrictions. | 6 |
| CVE-2024-23278 | libxpc | An app may be able to break out of its sandbox | The issue was addressed with improved checks. | 6 |
| CVE-2024-40805 | libxpc | An app may be able to bypass Privacy preferences | A permissions issue was addressed with additional restrictions. | 4 |
| CVE-2024-44225 | libxpc | An app may be able to gain elevated privileges | A logic issue was addressed with improved checks. | 7 |
| CVE-2024-44250 | XPC | An app may be able to execute arbitrary code out of its sandbox or with certain elevated privileges | A permissions issue was addressed with additional restrictions. | 1 |
| CVE-2024-54514 | libxpc | An app may be able to break out of its sandbox | The issue was addressed with improved checks. | 6 |
| CVE-2025-24178 | libxpc | An app may be able to break out of its sandbox | This issue was addressed through improved state management. | 7 |
| CVE-2025-24238 | libxpc | An app may be able to gain elevated privileges | A logic issue was addressed with improved checks. | 6 |
| CVE-2025-31182 | libxpc | An app may be able to delete files for which it does not have permission | This issue was addressed with improved handling of symlinks. | 7 |
| CVE-2025-43196 | libxpc | An app may be able to gain root privileges | A path handling issue was addressed with improved validation. | 3 |
| CVE-2025-43413 | libxpc | A sandboxed app may be able to observe system-wide network connections | An access issue was addressed with additional sandbox restrictions. | 7 |
| CVE-2026-112497 | libxpc | An app may be able to break out of its sandbox | This issue was addressed with improved permissions checking. | 3 |
| CVE-2026-20607 | libxpc | An app may be able to access protected user data | A permissions issue was addressed with additional restrictions. | 3 |
| CVE-2026-20667 | libxpc | An app may be able to break out of its sandbox | A logic issue was addressed with improved checks. | 5 |
| CVE-2026-28882 | libxpc | An app may be able to enumerate a user's installed apps | This issue was addressed with improved checks. | 6 |
| CVE-2026-84577 | libxpc | An app may be able to bypass sandbox restrictions | An access issue was addressed with additional sandbox restrictions. | 2 |
| CVE-2026-84617 | XPC | An app may be able to access sensitive user data | An authorization issue was addressed with improved state management. | 6 |
| CVE-2026-86894 | libxpc | An app may be able to break out of its sandbox | A logic issue was addressed with improved checks. | 1 |

### 13.4 署名口径的三档与两个变体

27 个 CVE 按署名原文可分三档：**具名（个人或个人+机构）19 条**、**`an anonymous researcher` 7 条**（CVE-2024-23278、CVE-2024-54514、CVE-2025-24178、CVE-2025-24238、CVE-2025-43196、CVE-2026-20607、CVE-2026-20667）、**整行无署名 1 条**（CVE-2024-40805，落差 B）。另有两条的署名原文在不同文档里写法不一致，这对任何"按署名聚合"的统计都是陷阱：

- CVE-2024-23201：六个页数里两种写法，`Koh M. Nakagawa of FFRI Security, Inc. and an anonymous researcher` 与 `Koh M. Nakagawa of FFRI Security, Inc., an anonymous researcher`（差一个连接词形态）。
- CVE-2025-31182：同一句署名，顺序不同。`pages/122371.txt`、`122376.txt`、`122377.txt`、`122378.txt` 写作 `Alex Radocea and Dave G. of Supernetworks, 风沐云烟(@binary_fmyy) and Minghao Lin(@Y1nKoc)`，而 `pages/122373.txt`、`122374.txt`、`122375.txt` 把两组名字前后调转。

**读法**：署名是荣誉字段，不是归属字段。它既不指示责任层，也不指示修复通道，聚合时只能当元数据看，不能当分类轴。

### 13.5 归层：从两段官方用词能推到哪一步

公告没有函数名、没有 commit、没有代码路径。唯一带机制味道的信息是 `Description` 的**处置用词**，27 个 CVE 一共只有 16 种写法。本文用它做映射，并明确标注置信度——这是一次**词表到类型学的对齐**，不是 Apple 的表述。

| 处置用词（原文片段） | CVE 数 | 本文归层 | 可映射 X 型 | 置信 |
| --- | --- | --- | --- | --- |
| `improved checks`（含 `A logic issue …`、`The issue …`、`This issue …` 三种前缀） | 9 | 第 6/7 章 XPC 对象层与 NSXPC 层，或第 5 章 MIG 服务端 | X7、X8 | 低：`improved checks` 不区分"取值未拒绝"与"派发后未校验" |
| `A permissions issue … additional restrictions` | 4 | 第 9 章介入口层（entitlement / 沙箱判定） | X7、X10 | 中：restriction 一词指向判定集合收紧 |
| 路径与名字解析类：`A parsing issue in the handling of directory paths …`、`A path handling issue … improved validation`、`improved handling of symlinks` | 4 | 第 8 章装配层与第 9 章介入层的交叠（名字解析） | X9、X12 | 中：路径与目录解析是"对端字段被采信"的典型 |
| `improved state management` / `through improved state management` / `improved permissions checking` | 4 | 第 7 章 NSXPC 连接生命周期与第 9 章鉴权时刻 | X10 | 中：state 一词与"鉴权一次、连接长期有效"同形 |
| `An access issue … additional sandbox restrictions` | 2 | 第 9 章介入口层 | X7 | 中高：原文直接说 sandbox |
| `A race condition … additional validation` | 1 | 第 4 章端口对象层与第 6 章对象层 | X4 | 中低：竞态可能在用户态也可能在内核 |
| `improved memory handling` | 1 | 第 6 章序列化边界 | X1 | 中：本表里唯一的内存损坏型措辞 |
| `a new entitlement` | 1 | 第 9 章介入口层（用新增权利把可达面收窄） | X12 的缓解式写法 | 高：entitlement 一词是文档级可指认的机制对象 |
| `A logic issue … improved validation`（仅此一条，与前四组的 `improved checks` 用词不同） | 1 | 不定，只能停在第 6–9 章的并集 | — | 低 |

（这九组按互斥划分，27 条各归一组：9+4+4+4+2+1+1+1+1 = 27。）

三条必须同时读出来的限度：

1. **组件名不能定层。** `libxpc` 一个名字同时覆盖本文第 6、7、8、9 章的四层。上表的"归层"列没有一行是仅由组件名得到的。
2. **影响原文只写后果，而且后果用词会重叠。** 27 条 CVE 的 Impact 一共只有 16 种写法，其中含 `sandbox` 一词的 12 条（`break out of its sandbox` 8、`execute arbitrary code out of its sandbox or with certain elevated privileges` 2、`bypass sandbox restrictions` 1、`A sandboxed app may be able to observe system-wide network connections` 1），含 `privilege` 一词的 9 条（`gain root privileges` 4、`gain elevated privileges` 2、`elevate privileges` 1、以及上面那 2 条同时含两个词的）。两组重叠 2 条，说明这两组是**后果标签**而不是互斥类型；同一条 sandbox 逃逸可能落在 X5、X9、X10 任一型上。
3. **上表是低/中置信对齐，不是归因。** 按第 17 章的规则，它最多支持级 2 的一句话："按公告口径，这条修复在该机型所属版本线上已包含/尚未包含"；要走到级 4，需要第 19/20 章脚本产生设备侧读数且该层证据强度 ≥ 中，而本表 27 行里没有一行自带设备侧读数。

### 13.6 一个 CVE 占七行：归属单元不是设备

页数分布（27 个 CVE）：1 页 6 个、2 页 3 个、3 页 5 个、4 页 2 个、5 页 1 个、6 页 6 个、7 页 4 个。取最多的 CVE-2025-31182 作样本，它的 7 行分别出现在《About the security content of iOS 18.4 and iPadOS 18.4》《macOS Sequoia 15.4》《macOS Sonoma 14.7.5》《macOS Ventura 13.7.5》《tvOS 18.4》《watchOS 11.4》《visionOS 2.4》——**一个缺陷、七份发布文档、三条并行 macOS 版本线、六个产品名（iOS、iPadOS、macOS、tvOS、watchOS、visionOS）**。分布核算：6+3+5+2+1+6+4 = 27 个 CVE，加权行数 6×1+3×2+5×3+2×4+1×5+6×6+4×7 = 104 行，与第 13.1 节的两个总量对得上。

由此得到两条纪律，直接服务于第 18 章的指标：

- **分母纪律**：任何"XPC 一年多少个洞"的说法必须先声明按 CVE 去重还是按公告条目计数。本缓存里前者是 27，后者是 104。
- **通道纪律**：同一 CVE 在 macOS 三条并行线（15.4 / 14.7.5 / 13.7.5）各占一行，正是第 12.3 节"必须先选版本线"的实证；用 iOS 的行去回答 macOS 设备的问题，属于第 22 章误区清单里的一个（误区 9）。

另外，72 个标题里有 6 个是缺空格的形态（`iOS18.2 and iPadOS18.2`、`iPadOS17.7.3`、`macOSSonoma14.7.2`、`macOSVentura13.7.2`、`tvOS18.2`、`watchOS11.2`）。这是缓存件自身的排版差异，不是 Apple 写了两种版本名；但它足以让"按标题字符串精确匹配来配对产品线"的脚本静默失配——第 20 章脚本里 W06/W10 两码位针对的正是这一类"大小写/空白口径不统一"的读数。

### 13.7 在野口径：两个公开源的读数都是零

Apple 在部分早期文档的处置段里确实写过在野判定，两种句式都在本缓存中出现。计数口径必须先说清楚：**每份文档在缓存里同时存有渲染文本（`.txt`）与原始 HTML（`.html`）两份，同一次统计只能取一种格式，否则每处都被数两遍**（本文第一版就把两种格式加在一起，得到过 98 与 6 这两个翻倍的假读数；下面的数是只取 `.txt` 镜像重跑的）。按块头之后的整块文本扫描，只取 `.txt`：

- `Apple is aware of a report that this issue may have been actively exploited.`（句号收尾）出现 **49** 处；同一句式带尾巴的变体（`… exploited on Intel-based Mac systems.`、`… exploited against versions of iOS before iOS 17.2.` 等）另有 26 处，两种时态合计 78 处，分布在 **52** 份文档里。
- `Apple was aware of a report that this issue may have been actively exploited at the time of release.` 出现 **3** 处。

用同一套块头规则回查（独立的第二个扫描器，不复用抽取脚本），**这 104 行条目里没有一行落在带该句式的块内**（去重后 27 个 CVE，命中 0）。

第二个来源是 CISA 的 Known Exploited Vulnerabilities 目录（本地缓存件 `kev.json`，`catalogVersion` 为 `2026.10.29`，`count` 为 1764，其中 `vendorProject` 为 Apple 的条目 95 条）。把这 27 个 CVE 逐个在该文件里查串（KEV 的字段名是 `"cveID"`，不是 `"cve"`，检索式写成 `"CVE-…"` 带引号的形式才能命中条目本体），命中 **0**；同一查串方法用目录内已知的 CVE-2026-97229 做阳性对照，作为 `"cveID"` 命中 1 条（该号另有一处出现在同一条目的 `notes` 文本里，不计入），说明不是检索式失效。

两条零读数合起来是本章唯一的"跨源"结论：**在本轮取回的公开口径下，`libxpc`/`XPC` 组件族没有任何一条被公开标注为在野利用**。但要注意这两个零各自的成立条件——第一个零依赖"该句式只出现在部分发布文档里"这一事实，它不是 Apple 对全部条目做了在野判定后统一写否；第二个零依赖 KEV 的录入口径（该目录只收"有证据表明被利用"的条目）。所以这两个零支持"目前公开证据不足以把这族缺陷排进在野清单"，不支持"这族缺陷没被用过"。

### 13.8 每行的判定上限

按第 17 章的四级模型逐行落位：

| 判定级 | 本表行数 | 成立条件与缺口 |
| --- | --- | --- |
| 级 1 口径 | 104（全部） | 公告原文 + 本文第 4–10 章的机制位置，恒成立 |
| 级 2 对齐 | 100 | 需要读者先确定自己设备落在哪条版本线；`libxpc`/`XPC` 的组件名可与公告对齐 |
| 级 2 对齐（有条件） | 4 | CVE-2024-40805 的 4 行：无署名，且只出现在同一轮的四份文档里（《iOS 17.6 and iPadOS 17.6》《macOS Sonoma 14.6》《tvOS 17.6》《watchOS 10.6》），没有进入任何后续并行线；设备若不在这四条线内，这行只能停在级 1 |
| 级 3 读数 | 0 | 公告不提供任何设备侧读数；级 3 必须由第 19/20 章脚本对**读者自有导出件**产生，与 CVE 号无关 |
| 级 4 归因 | 0 | 需要机制公开 + 设备侧证据强度 ≥ 中；本表 27 行没有一行的机制是公开的 |

这张表最有用的一格其实是最后两行的 0：**公开案例读数不会替你产生设备侧证据**。级 3 与级 4 的产能全部落在第 19、20 章那两个脚本上，而它们处理的输入是 `.ips` 文本与服务名清单，不是 CVE 列表。这也是本文把公告侧与设备侧分章写（第 15、16 章）而不是合并成一章的原因。

### 13.9 这张表读不到的六件事

1. 具体函数与代码改动：公告不含符号名，`osfmk/ipc/` 侧的对应只能按第 4 章的字段位置推断。
2. 触发面：是系统守护进程还是某个 App 内嵌 helper，公告不说；而第 12.2 节已说明这一格决定修复通道。
3. 机型与版本的完整笛卡尔积：`Available for:` 是自然语言机型清单，跨文档不能机械求交。
4. 修复是否走轻量通道：第 12.3 节里 Background Security Improvements 的组件列举只写到 Safari / WebKit 栈 / 其他系统库，本表 27 行没有任何一行能据此判断通道。
5. 在野与靶向：13.7 的两个零之外，公告不提供"哪些人被打过"的信息。
6. 同一机型上的**相邻缺陷**：一张 IPC 修复表不能提示"这台设备还缺哪一条"，那需要逐条 CVE × 版本线求差，属于第 18 章 K2 的产能而不是本章的。

---

## 14. 可见性边界：没有 shell 的设备怎么取数

### 14.1 三条取数路径与它们各自的产出

| 路径 | 能拿到什么 | 拿不到什么 |
| --- | --- | --- |
| 设备内导出（设置里的分析数据） | 崩溃报告文本（`.ips`），含异常类型、终止命名空间、线程回溯符号 | 端口状态、名称表、沙箱判定、服务清单 |
| 公开文档与公开源码 | 机制、常量、字段名、接口声明、装配键 | 该设备上启用了哪些、实际取值 |
| 自己的 App 里做只读探测 | "某个具名服务在我这个域里连得上/连不上"、连接生命周期事件 | 连不上是因为画像、装配、还是缺陷 |

第 19、20 章两个脚本分别消费第 1 条与第 2/3 条的产物。

### 14.2 具名服务的枚举：公开研究做过什么

在没有 shell 的前提下枚举服务名，公开研究里能查到的做法有三类（都属于"在允许的环境里做只读枚举"，不是绕过）：在 macOS 同源代码上用 `launchctl print` 类只读命令与画像分析框架、在越狱研究设备上离线读 plist、在受限环境里由 App 侧发起连接试探。本文不复述任何具体实现步骤，只登记一条结论：**这三类做法得到的清单口径互不相同**，所以跨来源比对服务清单时必须先对齐口径——这正是第 20 章脚本把 W04/W05/W06/W07 四个形态码放在比对之前的原因。

### 14.3 与 Android 侧对照的一条差异

Android 系列同主题报告可以要求读者连自己的设备跑 `adb` 只读命令来枚举服务；iOS 没有等价的公开入口，本文的脚本因此**不接受设备句柄**，只接受文本文件。这条差异决定了：iOS 侧的判定模型里"第一级"（只有文档口径）能覆盖的层比 Android 多，但"第三级"（设备侧直接读数）能覆盖的层更少。

---

## 15. 崩溃读数侧：.ips 里读得到与读不到

### 15.1 读得到什么

一份现代 `.ips` 是"首行 JSON 头 + 主体 JSON"两段式。头里可读的字段里与本文有关的：`bug_type`（报告种类）、`app_name`（进程名）、`os_version`（版本口径）、`platform`、`roots_installed`（设备是否被改动）。主体里可读的：`exception.type` / `signal` / `subtype`、`termination.namespace` / `code`、`threads[].frames[].symbol`。

对 IPC 层判定最有用的三处：

1. **`exception.type` = `EXC_GUARD`** 配合 `subtype` 里出现 MACH PORT 字样——这是 X5/X2 的强提示，也是第 19 章脚本 W01 码位。
2. **回溯里的 `mach_msg` / `_kernelrpc_mach_msg2_*` 帧**——消息进出内核的位置，脚本 W02。
3. **回溯里的 `xpc_*`、`__NSXPCCONNECTION_*`、`bootstrap_*`、`_X_*`**——分别把归属推到对象层、Foundation 层、名字解析、MIG 派发（脚本 W03/W06/W04/W07）。

### 15.2 读不到什么

- 端口名、权利计数、队列长度：任何字段级内核状态都不在导出内容里。
- 触发这次消息的**调用方是谁**：崩溃报告描述的是崩掉的那个进程，不是给它发消息的那个。
- 沙箱判定结果：强制控制不可见（第 9.1 节引的原文）。
- 匿名 listener 与非具名端点：没有名字可出现在任何清单里（第 6.4 节）。

### 15.3 因此本文怎么用崩溃读数

用法只有两种，都写在第 17 章判定模型里：**（a）分层**——把一条崩溃从"未知层"移到"IPC 层/非 IPC 层"；**（b）降权**——当 `os_version` 缺失、`roots_installed` 非 0、或字段取不到时，把这条读数从判定里剔除（脚本 E 类码位存在的意义）。**不用来做缺陷确认**，因为 15.2 的四条缺失里任何一条都可能让"看起来是 X2"实际上是 X4 的异步窗口（第 4.6 节）。

---

## 16. 公告读数侧：Apple Security Releases 的口径与限度

### 16.1 口径（本轮取回时点的读数）

取回件为 `Apple security releases` 页面（Apple Support 文档，页面标注 Published Date: October 30, 2026）。可直接引用的结构事实：

- 该页是**发布列表**，表头依次是 "Name and information link"、"Available for"、"Release date" 三个独立单元格（本文不把并排的表头引成一句）。
- 同一发布日 `26 Oct 2026` 下并列 `iOS 27.2 and iPadOS 27.2`、`iOS 26.7.2 and iPadOS 26.7.2`、`iOS 18.7.11 and iPadOS 18.7.11`，三行各带不同的机型清单。
- 页面开头写明最新版本：iOS/iPadOS 为 `27.2`。
- 页面开头的安全沟通口径原文见第 3.1 节。
- 历史条目按年分页（页面底部列出 `(2022 to 2023)`、`(2020 to 2021)` 等链接）。

### 16.2 限度

1. **组件词表粗于类型学词表**。公告一行给 `Kernel` 或 `XPC`，不给"哪一次校验失败"。因此第 11 章的 X1–X12 不能从公告直接统计出来，只能从描述文本推断，而描述文本本身按 Apple 的口径是**修复之后才有的**。
2. **无层内数量**。公告不给"这一层今年共修了多少个"，只能人工按组件词表计数；本文的计数一律标注为"按本文词表归类的结果"，不写成 Apple 的口径。
3. **时间线对齐是弱证据**。用"我的版本 ≥ 修复版本"证明"我没有这个缺陷"，只在缺陷与版本一一对应时成立；跨并行版本线（27.x / 26.x / 18.x）时同一条缺陷的修复编号不同，需要按机型先选线。
4. **轻量通道的覆盖面**。见第 12.3 节引的"only for the latest versions"与"starting with iOS 26.1, iPadOS 26.1, and macOS 26.1"：不在最新版本的设备拿不到 RSR；BSI 的覆盖面按组件列举（Safari / WebKit 框架栈 / 其他系统库），内核与 launchd 未被点名；且 BSI "may be temporarily removed"、用户移除后"reverts to the baseline software update"，因此公告读数与设备实际生效内容之间有一个可撤销的差额。
5. **"actively exploited" 这类标注**只说明已被利用的事实，不提供机制。机制要靠研究者随后公开的材料，而那往往晚于补丁很久——这决定了第 17 章第四级（已知在野 + 机制公开）在 IPC 层很少能达到。

### 16.3 用公告的正确姿势

把公告当作**分母来源**（这层被修过多少次、跨哪几条版本线、哪条线什么时候到），把第 19/20 章脚本的输出当作**分子来源**（这台设备的读数落在哪一格），两者只在"版本线 × 日期"这一个交叉点上相交，任何更细的因果都标为推断。第 18 章 K1–K10 全部按这个姿势定义。


---

## 17. 四级判定模型

判定模型回答的问题是：**"我现在手上的证据，允许我说到哪一句话"**。四级由低到高，每级都写清楚允许的最大结论与不允许的推论。

### 17.1 级 1：口径级（Documented）

- 输入：公开文档、公开源码（本文第 4–10 章的所有引用都属于这一级）。
- 允许说的最大结论：**"这一层存在这一型缺陷的机制位置，因此这一型值得监控。"**
- 不允许：任何关于具体设备、具体版本、具体服务是否受影响的结论。
- 典型误用：把"源码里有 `ip_mscount` 记账"读成"这台设备有记账缺陷"。

### 17.2 级 2：对齐级（Aligned）

- 输入：公告条目 + 版本线 + 机型清单 + 设备当前版本号（设置里可读）。
- 允许说的最大结论：**"按公告口径，这条修复在该机型所属版本线上已包含/尚未包含。"**
- 三条硬约束：
  1. 必须先选版本线（同一时间并行挂着 27.x / 26.x / 18.x 三条线，机型决定线）。
  2. 只在"缺陷 ↔ 版本"一一对应时成立；跨线编号不同，不能拿一条线的号去问另一条线。
  3. 轻量通道只覆盖"最新版本"且有组件口径，因此对不在最新版本的设备，级 2 的结论要写成"未包含，且不会通过 RSR / Background Security Improvements 到达"；对已在最新版本的设备，也不能断定内核类修复会走这条通道（第 12.3 节的组件列举口径），已应用的改进还可能被临时移除或用户移除后回到基线。
- 不允许：把级 2 写成"这台设备安全"。级 2 只覆盖公告里被点名过的条目，而公告是按发布组织的（第 3.1 节）。

### 17.3 级 3：读数级（Observed）

- 输入：第 19 章脚本（`.ips` 分类）与第 20 章脚本（服务清单漂移）的输出，且没有触发 E 类码位。
- 允许说的最大结论：**"这台设备导出的文本里，这一格出现了这个读数。"** 例如 `D01 + W01 + W11` 允许说"这条崩溃落在 IPC 层，且带有守卫/端口对象的线索"。
- 三条降级规则（对应脚本里的码位）：
  1. `E04`/`E05`/`E07`/`E08`/`E09`/`E10` 任一出现 → 该条读数不可用（退出码 2），不进任何统计。
  2. `W08`（`roots_installed=1`）→ 读数保留，但**与本文基线口径分栏**，因为设备状态已变。
  3. `W09`（缺 `os_version`）→ 不能进级 2 对齐，只能停在级 3 描述。
- 不允许：从级 3 直接跳到"有漏洞"。第 15.2 节列的四类缺失里，任意一类都足以让一次 IPC 层崩溃与"缺陷"之间断开。

### 17.4 级 4：归因级（Attributed）

- 输入：级 3 读数 + 该型缺陷的机制描述已公开 + 第 12.1 矩阵里对应层的证据强度 ≥ 中。
- 允许说的最大结论：**"这条读数属于 X 型，责任方在 Y 层，修复通道是 Z。"**
- 现实约束：矩阵（第 12.1 节）的十行里证据强度 ≥ 中的只有 5 层（消息尺寸、MIG、XPC、NSXPC、launchd 装配）。**X3（名称空间）、bootstrap 命名与域、IOKit user client 三行永远达不到级 4**，因为它们的设备侧证据列是"无"。这不是保守，是矩阵的算术结果。

### 17.5 用法

对每一条可疑读数，从级 4 往下问："我能拿到机制公开吗 → 我能拿到设备侧证据吗 → 我能与版本线对齐吗 → 我只剩文档口径吗"。落在哪一级，就只用哪一级的句子表述。本文档里所有断言都按这个规则标注；第 13 章的案例表额外给每行标了它可达到的最高级。

---

## 18. 运营指标 K1–K10

指标只统计**能被复现地生产**的东西：分母与分子都来自第 19/20 章脚本的码位、或来自公告页面/文档的可读字段。每条给：定义、数据来源、判读、限度。

| 指标 | 定义 | 数据来源（码位/字段） | 判读 | 限度 |
| --- | --- | --- | --- | --- |
| K1 IPC 层占比 | `D01 / (D01 + D02)` | 脚本一 | 用于给"该不该继续看这条通道"排序，不是风险等级 | 崩溃样本受采集偏差影响极大 |
| K2 清单漂移率 | `D05 次数 / 比对次数`；或 `（D01 新增 + D02 消失条数）/ 基线条数` | 脚本二 | 版本升级前后各比一次，漂移率异常上升要先查采集口径 | 漂移≠缺陷（第 20.4 节三条解释路径） |
| K3 假漂移率 | `W10 触发次数 / D05 次数` | 脚本二 | 越高说明采集越不干净，优先修采集而不是查缺陷 | 只有大小写/CRLF 差异能被这一指标抓 |
| K4 读数不可用率 | `退出码=2 的文件数 / 输入文件数` | 脚本一 E 类 | 高于阈值时任何 K1/K7 都不成立，先修采集 | E 类包含"设备被改动"这类非质量问题（W08 单独算） |
| K5 对端校验覆盖率 | 自有服务/ helper 中同时声明接口与代码签名要求的比例 | 代码审查（第 7.1/7.2 节文档口径） | 目标 100%；`setCodeSigningRequirement` 必须在建连前调用且只调一次 | 只适用于读者自己拥有的代码 |
| K6 解析隔离率 | 服务端"直接把对端字段用于路径/账号/URL 决策"的调用点占比 | 代码审查（第 9.5 节结构口径） | 越低越好；每条都要能指出校验点 | 需要读源码，外部观察不到 |
| K7 守卫读数占比 | `W01 次数 / D01 次数` | 脚本一 | 守卫类读数上升是 X5/X2 的监控信号 | subtype 文本可能被裁剪，导致漏计 |
| K8 版本线到达时长 | 公告发布日 → 该机型可见版本可对齐日的天数 | 公告页 `Release date` × 机型清单 | 跨线（27.x / 26.x / 18.x）分别算，不合并 | 只能到"日"粒度；级 2 |
| K9 轻量通道可达比例 | 机型中可获得 RSR / Background Security Improvements 的比例 | 文档口径："only for the latest versions"（RSR）× "starting with iOS 26.1, iPadOS 26.1, and macOS 26.1"（BSI） | 不在最新版本或低于 26.1 的版本线记为不可达 | 只说明"能不能收到"，不说明收到什么；BSI 可被移除，可达≠当前生效 |
| K10 边界清单维护 | 第 24 章条目数与状态（仍在 / 已解决） | 本文自维护 | 每次有公开新材料能填补某条时，把该条从清单移出并记录来源 | 是自指指标，不反映真实风险 |

### 18.1 三条共同限度

1. 这些指标全部是**观察与排序**工具，不是合规判定；没有任何一条能证明"这台设备有漏洞"。
2. K1/K4/K7 完全依赖第 19 章脚本的码位；脚本改动必须同步更新本章定义与第 21 章验收，否则读数不可比。
3. K5/K6 需要读者对自己代码的可见性；对无法审计的第三方服务，这两项无定义（不是 0）。


---

## 19. 只读核验脚本一：`.ips` 分类器

### 19.1 它回答哪一个问题

第 15 章把"崩溃读数里读得到什么"列成了一张表，那张表的问题是定性的。本章的脚本把同一个问题变成**可复现的动作**：给定一份 `.ips` 文本，它属于 IPC 层读数、非 IPC 层读数，还是读数不可用？

这个脚本不回答的事同样重要，写在这里以免误读：

- 不回答"这台设备有没有漏洞"。它只给分型。
- 不回答"这个崩溃是不是被利用"。第 16 章的限度在脚本输出上同样成立。
- 不解析二进制、不联系设备、不联网、不修改输入。所有中间文件落在系统临时目录并在退出前删除；输入只以只读方式打开。

### 19.2 输入口径：为什么要先切首行

Apple 对 `.ips` 结构的官方口径就是脚本第一段的实现依据（取回文档原文）：

> "Typical JSON parsers expect a single JSON object in the body of the file. The IPS file for a crash report contains two JSON objects: an object containing IPS metadata about the report incident and an object containing the crash report data. When parsing the file, extract the JSON for the metadata object from the first line. If the bug_type property of the metadata object is 309, the log type for crash reports, you can extract the JSON for the crash report data from the remainder of the text."

三个直接后果，构成脚本的三条硬规则：

1. **头部与主体要分开取字段**：`bug_type` / `app_name` / `os_version` / `platform` / `roots_installed` 只在首行元数据对象里；`exception` / `termination` / `threads` 只在主体里。取错位置就会得到"键不存在"的假读数——这就是 E04/E05 与 E07/E09/E10 分开编码的原因。
2. **不能用严格 JSON 解析器一次读完**：主体里常见跨行排版与尾随内容，脚本因此用"键存在性 + 首个命中值"的宽松口径（`get_str` / `get_num` / `has` 三个函数），并把"取不到"显式登记为码位，而不是当成空字符串静默通过。
3. **`bug_type` 为 309 才是崩溃报告**。脚本把 309 之外的值照原样打进判定行（`bug_type=…`），由读者判断这份读数是崩溃、诊断还是别的种类，脚本不代作结论。

取数路径也是公开口径的一部分，本文一并记录，因为它决定了"读者手上到底有没有输入"：Apple 的设备分析文档写的是"You can review this information on your iOS device by going to Settings > Privacy & Security > Analytics & Improvements and tapping Analytics Data."。系统守护进程的崩溃报告在同一个入口里，其样例头部含 "Parent Process: launchd [1]" 这一字段形态——这正是第 8 章"launchd 是装配者"在设备侧唯一能直接看到的痕迹之一。

### 19.3 完整代码

以下为本轮验收通过的完整脚本（文件名 `xpc-ips-triage.sh`）。它与第 21 章逐分支验收的是同一份字节内容。

```bash
#!/bin/bash
# xpc-ips-triage.sh —— iOS/macOS .ips 崩溃报告的 XPC / Mach IPC 层只读分类器
# 只读：只读取入参文本，不写设备、不联网、不修改输入；中间文件只落在系统临时目录并被删除。
# 用途：把「这条崩溃读数落在类型学哪一格」变成可复现的动作，输出信号码 + 一句解释。
#
# 用法：  xpc-ips-triage.sh [-q] [-h] 文件 [文件...]
# 退出码：0 = 每个输入都取到了可用读数；2 = 至少一个输入触发过 E 类码位；9 = 调用形态错误。

set -u
LC_ALL=C
export LC_ALL

QUIET=0
FLAG_E=0

usage() {
  printf '%s\n' "用法: $0 [-q] [-h] 文件 [文件...]" \
                "  -q  只打印信号码，不打印解释行" \
                "  -h  打印本帮助"
}

emit() { # $1=码位 $2=解释：唯一的输出出口，负责记录 E 类
  case "$1" in E*) FLAG_E=1 ;; esac
  if [ "$QUIET" = 1 ]; then printf '%s\n' "$1"; else printf '%s  %s\n' "$1" "$2"; fi
}

# ---- 取字段：容忍 "k":v 与 "k" : v 两种排版；同名键多次出现时取首个 ----
get_str() { # $1=文件 $2=键名
  grep -o "\"$2\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" "$1" 2>/dev/null | head -n 1 \
    | sed 's/^[^:]*:[[:space:]]*"//; s/"$//'
}
get_num() { # $1=文件 $2=键名
  grep -o "\"$2\"[[:space:]]*:[[:space:]]*[-0-9][0-9.]*" "$1" 2>/dev/null | head -n 1 \
    | sed 's/^[^:]*:[[:space:]]*//'
}
has() { # $1=文件 $2=键名：只判断键是否存在
  grep -q "\"$2\"[[:space:]]*:" "$1" 2>/dev/null
}

# ---- 帧符号命中表：每条正则只负责一个码位，命中表与判定分离 ----
frame_scan() { # $1=主体文件；输出空格分隔的码位序列
  local f="$1" hits=""
  if grep -Eqi '"symbol"[[:space:]]*:[[:space:]]*"[^"]*(mach_msg|_kernelrpc_mach)' "$f"; then hits="$hits W02"; fi
  if grep -Eqi '"symbol"[[:space:]]*:[[:space:]]*"[^"]*xpc' "$f"; then hits="$hits W03"; fi
  if grep -Eqi '"symbol"[[:space:]]*:[[:space:]]*"[^"]*(bootstrap_check_in|bootstrap_look_up|task_get_bootstrap_port)' "$f"; then hits="$hits W04"; fi
  if grep -Eqi '"symbol"[[:space:]]*:[[:space:]]*"[^"]*CFMessagePort' "$f"; then hits="$hits W05"; fi
  if grep -Eqi '"symbol"[[:space:]]*:[[:space:]]*"[^"]*NSXPCCONNECTION' "$f"; then hits="$hits W06"; fi
  if grep -Eqi '"symbol"[[:space:]]*:[[:space:]]*"(_X[A-Za-z0-9_]+|[^"]*mach_msg_server)' "$f"; then hits="$hits W07"; fi
  if grep -Eqi '"symbol"[[:space:]]*:[[:space:]]*"[^"]*(ipc_port|mach_port_|port_deallocate)' "$f"; then hits="$hits W11"; fi
  printf '%s\n' "${hits# }"
}

classify_one() { # $1=候选文件；返回 0 = 未触发 E 类，1 = 触发过 E 类或提前退出
  local f="$1" hdr hbf bb body_flag=0
  local appname bugtype osver platform roots extype exsignal termns termcode hits isipc h

  if [ ! -e "$f" ];  then emit E02  "文件不存在：$f"; return 1; fi
  if [ ! -r "$f" ]; then emit E02b "文件不可读（权限或属主问题）：$f"; return 1; fi
  if [ ! -s "$f" ]; then emit E02c "文件为空：$f"; return 1; fi

  hdr=$(head -n 1 "$f")
  case "$hdr" in
    '{'*) ;;
    *) emit E03 "首行不是 JSON 头，不是本口径预期的 v2 形态 .ips：$f"; return 1 ;;
  esac

  hbf=$(mktemp) || { emit E93 "临时目录不可用，无法继续：$f"; return 1; }
  bb=$(mktemp)  || { emit E93 "临时目录不可用，无法继续：$f"; rm -f "$hbf"; return 1; }
  printf '%s\n' "$hdr" > "$hbf"
  tail -n +2 "$f" | tr -d '\000' > "$bb"

  bugtype=$(get_str "$hbf" bug_type)
  appname=$(get_str "$hbf" app_name)
  osver=$(get_str "$hbf" os_version)
  platform=$(get_num "$hbf" platform)
  roots=$(get_num "$hbf" roots_installed)

  [ -z "$bugtype" ] && emit E04 "头部缺少 bug_type，报告种类这一格取不到：$f"
  [ -z "$appname" ] && emit E05 "头部缺少 app_name，进程名这一格取不到：$f"
  [ -z "$osver" ]   && emit W09 "头部缺少 os_version，跨设备比对的版本口径缺失：$f"
  if [ -n "$platform" ] && [ "$platform" != "1" ] && [ "$platform" != "2" ]; then
    emit W10 "platform=$platform，不在常见 iOS / macOS 读数域内：$f"
  fi
  [ "$roots" = "1" ] && emit W08 "roots_installed=1，设备已被改动，同码位含义与本系列基线不同：$f"

  if [ ! -s "$bb" ]; then
    emit E06 "只有头部、没有主体：$f"; rm -f "$hbf" "$bb"; return 1
  fi
  if ! has "$bb" procName && ! has "$bb" exception; then
    emit E06b "主体既无 procName 也无 exception，无法定位进程与异常：$f"; rm -f "$hbf" "$bb"; return 1
  fi

  extype=$(get_str "$bb" type)
  exsignal=$(get_str "$bb" signal)
  termns=$(get_str "$bb" namespace)
  termcode=$(get_num "$bb" code)

  if ! has "$bb" exception; then
    emit E07 "主体缺少 exception 对象：$f"
  elif [ -z "$extype" ]; then
    emit E08 "exception 在，但 exception.type 取不到值：$f"
  fi
  [ "$extype" = "EXC_GUARD" ] && emit W01 "exception.type=EXC_GUARD，端口 / 守卫类违规的高提示信号"
  [ -z "$termns" ] && emit E09 "主体缺少 termination.namespace，终止来源这一格取不到：$f"

  if ! has "$bb" threads; then
    emit E10 "主体缺少 threads 数组，帧证据全部不可用：$f"; rm -f "$hbf" "$bb"; return 1
  fi

  hits=$(frame_scan "$bb")
  if [ -z "$hits" ]; then
    emit W12 "threads 存在，但帧里没有任何 IPC 符号命中"
  fi
  for h in $hits; do
    case "$h" in
      W02) emit W02 "帧命中 mach_msg / _kernelrpc_mach 系：消息进出内核的那一刻" ;;
      W03) emit W03 "帧命中 xpc 系：XPC 连接或对象层" ;;
      W04) emit W04 "帧命中 bootstrap 查找 / 注册系：服务名解析那一刻" ;;
      W05) emit W05 "帧命中 CFMessagePort 系：CoreFoundation 的老端口通道" ;;
      W06) emit W06 "帧命中 NSXPCCONNECTION 系：Foundation 侧封装" ;;
      W07) emit W07 "帧命中 MIG 生成例程形态（_X 前缀或 mach_msg_server）" ;;
      W11) emit W11 "帧命中 ipc_port / mach_port 系：端口对象本体" ;;
    esac
  done

  isipc=0
  for h in $hits; do isipc=1; done
  if [ "$isipc" = 1 ]; then
    emit D01 "判定：IPC 层读数（bug_type=${bugtype:-未知} proc=${appname:-未知} exc=${extype:-未取到} term=${termns:-未取到}/${termcode:-无}）"
  elif [ -n "$termns" ] || [ -n "$exsignal" ]; then
    emit D02 "判定：非 IPC 层读数（term=${termns:-无} signal=${exsignal:-无}）"
  else
    emit D03 "判定：不确定（无帧证据，且终止与信号两格都空）"
  fi

  # E 类记账必须在删除临时文件之前完成
  if [ -z "$bugtype" ] || [ -z "$appname" ] || [ -z "$extype" ] || [ -z "$termns" ] \
     || ! has "$bb" exception; then body_flag=1; fi
  rm -f "$hbf" "$bb"
  if [ "$body_flag" = 1 ] || [ "$FLAG_E" = 1 ]; then return 1; fi
  return 0
}

# ---------------- 主流程 ----------------
while getopts ":qh" opt; do
  case "$opt" in
    q) QUIET=1 ;;
    h) usage; exit 0 ;;
    \?) emit E90 "未知选项 -$OPTARG" >&2; usage >&2; exit 9 ;;
  esac
done
shift $((OPTIND - 1))

if [ "$#" -lt 1 ]; then
  printf 'E92  未提供输入文件\n' >&2
  usage >&2
  exit 9
fi

bad=0
for f in "$@"; do
  if ! classify_one "$f"; then bad=1; fi
done
[ "$bad" = 1 ] && exit 2
exit 0
```

### 19.4 信号码词表

码位分三类：**E**（读数不可用）、**W**（读数可用，但这一格需要注意）、**D**（判定）。`-q` 模式只打印码位、不打印解释，便于批量汇总与计数（第 18 章 K1/K4/K7 的分子分母就是这么来的）。

| 码位 | 含义 | 触发条件（口径来源） | 对判定的影响 |
| --- | --- | --- | --- |
| E02 | 文件不存在 | 入参路径不存在 | 该输入无读数，退出码 2 |
| E02b | 文件不可读 | 存在但 `-r` 为假（权限/属主） | 同上；本轮 Windows 环境不可触发，见第 21.4 节 |
| E02c | 文件为空 | `-s` 为假 | 同上 |
| E03 | 首行不是 JSON 头 | 首行不以 `{` 开头 | 不是 v2 形态 `.ips`，按第 19.2 节口径拒绝 |
| E04 | 缺 `bug_type` | 头部取不到该键值 | 报告种类未知；判定行仍给但记账为 E |
| E05 | 缺 `app_name` | 头部取不到该键值 | 进程名未知；记账为 E |
| E06 | 只有头部无主体 | 首行之后为空 | 帧与异常全不可用 |
| E06b | 主体无 `procName` 且无 `exception` | 两键皆不存在 | 无法定位进程与异常 |
| E07 | 缺 `exception` | 主体无该对象 | 异常类型未知 |
| E08 | `exception.type` 取不到值 | 对象在、字符串值取不到 | 异常类型未知（与 E07 区分"没有"与"读了空"） |
| E09 | 缺 `termination.namespace` | 取不到字符串值 | 终止来源未知；影响 D01/D02/D03 的第三格 |
| E10 | 缺 `threads` | 主体无该数组 | 帧证据全不可用，判定不做 IPC 断言 |
| E90 | 未知选项 | `getopts` 报 `\?` | 调用形态错误，退出码 9 |
| E92 | 未提供输入 | 参数数为 0 | 同上 |
| E93 | 临时目录不可用 | `mktemp` 失败 | 本轮环境不可触发，见第 21.4 节 |
| W01 | `EXC_GUARD` | `exception.type` 恰为该值 | X5/X2 的监控信号（第 18 章 K7） |
| W02 | 帧含 `mach_msg` / `_kernelrpc_mach` 系 | 符号正则命中 | 落到"消息进出内核"那一格 |
| W03 | 帧含 `xpc` 系 | 符号正则命中 | XPC 连接/对象层 |
| W04 | 帧含 bootstrap 查找/注册系 | `bootstrap_check_in`/`bootstrap_look_up`/`task_get_bootstrap_port` | 名称解析那一刻（第 8 章） |
| W05 | 帧含 `CFMessagePort` 系 | 符号正则命中 | CoreFoundation 老通道，不属于 XPC 但同为 Mach 权利 |
| W06 | 帧含 `NSXPCCONNECTION` 系 | 符号正则命中 | Foundation 侧封装（第 7 章） |
| W07 | 帧含 MIG 生成例程形态 | `_X` 前缀或 `mach_msg_server` | 契约层（第 5 章） |
| W08 | `roots_installed=1` | 头部数值为该值 | 设备被改动，同码位含义与本系列基线不同 |
| W09 | 缺 `os_version` | 头部取不到 | 跨设备版本对齐不可做（级 2 前提缺失） |
| W10 | `platform` 非 1/2 | 头部数值存在且不为 1 或 2 | 读数域异常，可能是别的平台产生的报告 |
| W11 | 帧含 `ipc_port`/`mach_port_`/`port_deallocate` | 符号正则命中 | 端口对象本体在栈上（第 4 章） |
| W12 | 有 `threads` 但零命中 | 命中表全空 | 不能据此说"与 IPC 无关"，只能说"符号不可用" |
| D01 | IPC 层读数 | 至少一个帧命中 | 可进入第 11 章分型 |
| D02 | 非 IPC 层读数 | 零命中且终止/信号至少一格有值 | 分型不成立，但进程与异常格仍可用于统计 |
| D03 | 不确定 | 零命中且终止与信号都空 | 该读数应从统计分母里剔除 |

同一份输入可以同时给多个 W；`D` 恒为末行且只有一个。

### 19.5 样例输出（本轮实跑）

第一个样本是一份构造的守护进程崩溃件（`backboardd`，`bug_type` 为 309，栈含 `_kernelrpc_mach2_trap`、`xpc_connection_send_message_with_reply_sync`、`__NSXPCCONNECTION_IS_WAITING_FOR_A_SYNCHRONOUS_REPLY__`、`_X_backboard_host`）：

```text
W02  帧命中 mach_msg / _kernelrpc_mach 系：消息进出内核的那一刻
W03  帧命中 xpc 系：XPC 连接或对象层
W06  帧命中 NSXPCCONNECTION 系：Foundation 侧封装
W07  帧命中 MIG 生成例程形态（_X 前缀或 mach_msg_server）
D01  判定：IPC 层读数（bug_type=309 proc=backboardd exc=EXC_BAD_ACCESS term=SIGNAL/11）
```

退出码 0。注意四行 W 是**四个不同层的命中**，不是同一件事说了四遍：W02 是原语层、W03 是 XPC 层、W06 是 NSXPC 封装层、W07 是 MIG 契约层。一条崩溃里四层同时出现是常态（一次同步调用本来就要穿过这四层），所以**命中数量不等于缺陷数量**——这是第 22 章误区 7 针对的对象。

第二个样本是三个坏输入拼一次批量调用，用 `-q` 只看码位：

```text
E04 E05 W09 W10 W08 W04 D01 E02c E03
```

退出码 2。这一行是三个文件的输出连起来读的：第一个文件（头部信息不全但主体可用）给 `E04 E05 W09 W10 W08 W04 D01`，第二个空文件给 `E02c`，第三个首行非 JSON 给 `E03`。**"最后一行是 D01、整体退出码却是 2"** 正是这个口径的含义：判定成立不等于所有输入都可用，退出码是按整批记的。做批量统计时必须按文件粒度解析，不能只看退出码。

### 19.6 判读规则

1. **`W12` 与 `D02` 的差别要守住**：`W12` 说"这条读数里没找到 IPC 符号"，`D02` 说"这条读数落在非 IPC 层"。前者可能是符号被裁剪（第 15.2 节），后者才是分层判断。把 `W12` 记成"与 IPC 无关"是本脚本最常见的误用。
2. **任何 E 码出现，该文件应从分母里剔除或单列**。第 18 章 K1 的定义特意把 `E` 类走"剔除"而不是"记为否"，否则 K1 会被采集质量而非真实分布驱动。
3. **`W08` 出现时，本文其余码位的含义都要打折**：越狱/改动过的设备上的守护进程可能被替换或打补丁，同一符号命中不代表同一实现（与本系列第 3 篇越狱报告的口径一致）。
4. **脚本给出的是层，不是原因**。`D01` 只说这条读数落在 IPC 表面上；第 11 章的 X1–X12 需要额外证据（服务清单、公告行、源码位置）才能选一格，脚本不代替这一步。

---

## 20. 只读核验脚本二：服务清单漂移比对器

### 20.1 它回答哪一个问题

第 8 章的结论是：服务名是 launchd 在装配期声明的、因此可枚举。本章脚本处理的是**两份可枚举清单之间的差异**：一份"基线"（某个版本的公开文档表、或某次采集件），一份"现网"（另一版本/另一次采集）。它回答三个问题：新增了什么、消失了什么、这些差异是不是采集口径造成的假差异。

它不回答"服务为什么消失"。iOS 上取不到画像文件（第 14 章），因此"为什么"永远只能是级 1 或级 2 的问题（第 17 章）。

输入形态是**每行一个服务标识**（launchd 的 `Label` 或 `MachServices` 里的键名），允许 `#` 注释、空行、CRLF 行尾。这类文本的合理来源是：读者自有设备导出的公开日志、Apple 公开文档里的服务名表、macOS 上同类 plist 的导出，或同一份采集件的不同版本。脚本不接触设备，因此它比对的是**文本**，不是设备状态。

### 20.2 完整代码

以下为本轮验收通过的完整脚本（文件名 `xpc-roster-diff.sh`）。

```bash
#!/bin/bash
# xpc-roster-diff.sh —— 两份 XPC / Mach 服务名清单的只读漂移比对器
# 只读：只读两个文本清单，不写设备、不联网、不改文件；中间文件只落在系统临时目录并被删除。
# 输入形态：每行一个服务标识（launchd 的 Label / MachService 名），允许 # 注释、空行、CRLF。
# 典型取数：读者自有设备导出的公开日志或配置文件、Apple 公开文档里的服务名表、
#           或两个不同 iOS 版本的同一份采集件。本脚本不接触设备。
#
# 用法：  xpc-roster-diff.sh [-q] [-h] 基线清单 现网清单
# 退出码：0 = 两侧清单都可用且给出判定；2 = 至少一格读数不可用（E 类）；9 = 调用形态错误。

set -u
LC_ALL=C
export LC_ALL

QUIET=0
FLAG_E=0

emit() { # $1=码位 $2=解释
  case "$1" in E*) FLAG_E=1 ;; esac
  if [ "$QUIET" = 1 ]; then printf '%s\n' "$1"; else printf '%s  %s\n' "$1" "$2"; fi
}

usage() {
  printf '%s\n' "用法: $0 [-q] [-h] 基线清单 现网清单" \
                "  -q  只打印信号码，不打印解释行" \
                "  -h  打印本帮助"
}

# ---- 归一化：去 CR、去首尾空白、丢空行与注释行，保留原始大小写 ----
normalize() { # $1=原始文件 $2=输出文件
  sed 's/\r$//' "$1" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | grep -v '^$' | grep -v '^#' > "$2"
}

scan_shape() { # $1=归一后文件 $2=标签（基线 / 现网）
  local f="$1" tag="$2" total bad nonrev dup ci
  total=$(grep -c '' "$f")
  emit N00 "$tag 归一后条目数：$total"

  nonrev=$(grep -Ev '^[A-Za-z][A-Za-z0-9.-]*\.[A-Za-z][A-Za-z0-9.-]*$' "$f" | grep -c '')
  [ "$nonrev" -gt 0 ] && emit W04 "$tag 有 $nonrev 条不符合「段.段」反向域名口径（多为截断或带路径的读数）"

  bad=$(grep -E '[[:space:]]' "$f" | grep -c '')
  [ "$bad" -gt 0 ] && emit W05 "$tag 有 $bad 条含空白字符（多半是采集时把整行说明带了进来）"

  dup=$(sort "$f" | uniq -d | grep -c '')
  [ "$dup" -gt 0 ] && emit W07 "$tag 有 $dup 条完全重复的标识"

  ci=$(tr 'A-Z' 'a-z' < "$f" | sort | uniq -d | grep -c '')
  [ "$ci" -gt 0 ] && emit W06 "$tag 有 $ci 组在大小写归一后重名（采集口径不统一制造的同名两份）"
}

# ---------------- 主流程 ----------------
while getopts ":qh" opt; do
  case "$opt" in
    q) QUIET=1 ;;
    h) usage; exit 0 ;;
    \?) emit E90 "未知选项 -$OPTARG" >&2; usage >&2; exit 9 ;;
  esac
done
shift $((OPTIND - 1))

if [ "$#" -ne 2 ]; then
  printf 'E92  需要恰好两个输入：基线清单 现网清单\n' >&2
  usage >&2
  exit 9
fi

base_raw="$1"; cur_raw="$2"

for p in "$base_raw" "$cur_raw"; do
  if [ ! -e "$p" ];  then emit E01 "清单不存在：$p"; fi
  if [ -e "$p" ] && [ ! -r "$p" ]; then emit E02 "清单不可读：$p"; fi
done
if [ "$FLAG_E" = 1 ]; then exit 2; fi

base=$(mktemp) || { emit E93 "临时目录不可用，无法归一化清单"; exit 2; }
cur=$(mktemp)  || { emit E93 "临时目录不可用，无法归一化清单"; rm -f "$base"; exit 2; }
bs=$(mktemp) || { emit E93 "临时目录不可用，无法排序比对"; rm -f "$base" "$cur" "$bs"; exit 2; }
cs=$(mktemp) || { emit E93 "临时目录不可用，无法排序比对"; rm -f "$base" "$cur" "$bs"; exit 2; }

for p in "$base_raw" "$cur_raw"; do
  # grep 在本机对单独的 CR 不可靠（会把 \r 当行分隔），这里用 tr 计数
  cr=$(tr -dc '\r' < "$p" 2>/dev/null | wc -c | tr -d ' ')
  [ "${cr:-0}" -gt 0 ] && emit W01 "文件含 $cr 个 CR（CRLF 行尾），已在归一化时去掉：$p"
done
for p in "$base_raw" "$cur_raw"; do
  n=$(grep -c '^$' "$p" 2>/dev/null)
  [ "$n" -gt 0 ] && emit W02 "文件含 $n 个空行，已丢弃：$p"
  c=$(grep -c '^#' "$p" 2>/dev/null)
  [ "$c" -gt 0 ] && emit W03 "文件含 $c 行注释，已丢弃：$p"
done

normalize "$base_raw" "$base"
normalize "$cur_raw"  "$cur"

if [ ! -s "$base" ]; then emit E10 "基线归一化后为空，没有可比对的条目"; fi
if [ ! -s "$cur"  ]; then emit E11 "现网归一化后为空，没有可比对的条目"; fi
if [ "$FLAG_E" = 1 ]; then rm -f "$base" "$cur" "$bs" "$cs"; exit 2; fi

scan_shape "$base" "基线"
scan_shape "$cur"  "现网"

# comm 只接受排序输入：这里统一用小写归一前的排序副本
sort -u "$base" > "$bs"
sort -u "$cur"  > "$cs"

only_new=$(comm -13 "$bs" "$cs" | grep -c '')
only_old=$(comm -23 "$bs" "$cs" | grep -c '')
shared=$(comm -12 "$bs" "$cs" | grep -c '')

emit D01 "新增（现网有、基线无）：$only_new 条"
emit D02 "消失（基线有、现网无）：$only_old 条"
emit D03 "共同：$shared 条"

sys_new=$(comm -13 "$bs" "$cs" | grep -E '^com\.apple\.' | grep -c '')
sys_old=$(comm -23 "$bs" "$cs" | grep -E '^com\.apple\.' | grep -c '')
[ "$sys_new" -gt 0 ] && emit W09 "新增里有 $sys_new 条 com.apple.* 前缀：新暴露出来的系统服务名，需要问归属"
[ "$sys_old" -gt 0 ] && emit W08 "消失里有 $sys_old 条 com.apple.* 前缀：系统服务口径变化，最需要追问的一格"

# 仅大小写差异不算漂移：把两侧都小写归一后再比一次
blc=$(mktemp) || { emit E93 "临时目录不可用，无法做大小写归一比对"; rm -f "$base" "$cur" "$bs" "$cs"; exit 2; }
clc=$(mktemp) || { emit E93 "临时目录不可用，无法做大小写归一比对"; rm -f "$base" "$cur" "$bs" "$cs" "$blc"; exit 2; }
tr 'A-Z' 'a-z' < "$base" | sort -u > "$blc"
tr 'A-Z' 'a-z' < "$cur"  | sort -u > "$clc"
case_only=$(comm -3 "$blc" "$clc" | grep -c '')
if { [ "$only_new" -gt 0 ] || [ "$only_old" -gt 0 ]; } && [ "$case_only" = 0 ]; then
  emit W10 "全部差异在大小写归一后消失：这是采集口径不一致，不是真实漂移"
fi
rm -f "$blc" "$clc"

if [ "$only_new" = 0 ] && [ "$only_old" = 0 ]; then
  emit D04 "判定：无漂移（两侧条目集合一致，共 $shared 条）"
else
  emit D05 "判定：有漂移（新增 $only_new / 消失 $only_old / 共同 $shared）"
fi

rm -f "$base" "$cur" "$bs" "$cs"
[ "$FLAG_E" = 1 ] && exit 2
exit 0
```

### 20.3 信号码词表

| 码位 | 含义 | 触发条件 | 判读要点 |
| --- | --- | --- | --- |
| E01 | 清单不存在 | 任一侧路径不存在 | 无读数，退出码 2 |
| E02 | 清单不可读 | 存在但 `-r` 为假 | 同上；本轮 Windows 环境不可触发，见第 21.4 节 |
| E10 | 基线归一化后为空 | 去掉 CR/空白/空行/注释后无条目 | "没有基线"不是"基线为空集"，不能记为全部新增 |
| E11 | 现网归一化后为空 | 同上，作用于现网侧 | 不能记为"服务全部消失" |
| E90 | 未知选项 | `getopts` 报 `\?` | 调用形态错误，退出码 9 |
| E92 | 参数数量不为 2 | 位置参数不是两个 | 同上；本脚本只比两份清单，不做多路比对 |
| E93 | 临时目录不可用 | `mktemp` 失败 | 见第 21.4 节的复现法（`TMPDIR` 指向不存在目录） |
| N00 | 条目计数（两侧各一次） | 恒定输出 | 第 18 章 K2 的分母来源；注意它数的是**归一后**条目 |
| W01 | 文件含 CR（CRLF 行尾） | `tr -dc '\r'` 计数 > 0 | 已自动去掉；出现它说明采集链路跨了平台 |
| W02 | 文件含空行 | `grep -c '^$'` > 0 | 已丢弃；不影响比对结果 |
| W03 | 文件含 `#` 注释行 | `grep -c '^#'` > 0 | 已丢弃；**如果服务名本身以 `#` 开头会被误丢**，本口径不允许这种命名 |
| W04 | 不符合"段.段"反向域名形态 | 正则不匹配 `[A-Za-z][A-Za-z0-9.-]*\.[A-Za-z][A-Za-z0-9.-]*` | 多为截断、带路径、或采集时把整段说明当成一条 |
| W05 | 条目内含空白字符 | 归一后仍含空白 | 采集时把说明文字带进来了；该条目的比对结果不可信 |
| W06 | 大小写归一后重名 | 小写化后 `uniq -d` 命中 | 同一服务被两套采集口径写成两种大小写 |
| W07 | 完全重复条目 | `sort \| uniq -d` 命中 | 采集时同一清单被拼接了两次 |
| W08 | 消失侧含 `com.apple.*` | 差集里命中该前缀 | **最需要追问的一格**：系统服务口径变化 |
| W09 | 新增侧含 `com.apple.*` | 差集里命中该前缀 | 新暴露出来的系统服务名，需要问归属与画像 |
| W10 | 差异全部由大小写造成 | 大小写归一后差集为 0 | **假漂移**：这是采集口径不一致，不是设备变化 |
| D01 | 新增条数 | 恒出 | 现网有、基线无 |
| D02 | 消失条数 | 恒出 | 基线有、现网无 |
| D03 | 共同条数 | 恒出 | 用于校验 D01+D03 ≤ 现网数、D02+D03 ≤ 基线数 |
| D04 | 判定：无漂移 | D01=0 且 D02=0 | 集合一致（注意：**条目顺序与重复次数不计**） |
| D05 | 判定：有漂移 | D01 或 D02 非 0 | 需再读 W08/W09/W10 才能定性 |

三个设计取舍写在这里，因为它们决定了读数的可比性：

1. **比对的是集合，不是列表。** `sort -u` 之后用 `comm`，所以"同一服务在清单里出现两次"不会产生漂移读数，只会产生 W07。这是刻意的：漂移要回答"有没有新服务/少了服务"，不是"采集有没有截断"。
2. **大小写敏感。** 服务名在 bootstrap 命名空间里是按字节比较的键，因此主比对区分大小写；但脚本同时给一条 W10，把"仅在大小写上有差异"这种情况单独标成假漂移。
3. **`com.apple.*` 只用于分组，不用于归属。** 前缀相同不代表同一团队，这一点在第 24 章边界清单里写死。

### 20.4 样例输出（本轮实跑）

真实漂移（10 条基线 vs 12 条现网，构造样本）：

```text
W03  文件含 1 行注释，已丢弃：.x6fx/r1-base.txt
N00  基线 归一后条目数：10
N00  现网 归一后条目数：12
D01  新增（现网有、基线无）：3 条
D02  消失（基线有、现网无）：1 条
D03  共同：9 条
W09  新增里有 3 条 com.apple.* 前缀：新暴露出来的系统服务名，需要问归属
W08  消失里有 1 条 com.apple.* 前缀：系统服务口径变化，最需要追问的一格
D05  判定：有漂移（新增 3 / 消失 1 / 共同 9）
```

退出码 0。

假漂移（同一份清单，只是大小写与 CRLF 变了，`-q` 模式）：

```text
W01 W03 W03 N00 N00 D01 D02 D03 W08 W10 D05
```

这一行是**最值得学会读的输出**：末位是 `D05`（有漂移），但同时出现了 `W10`（全部差异在大小写归一后消失）。也就是说"有漂移"与"这条漂移是采集造成的"可以同时成立。做 K2 统计时，带 `W10` 的 `D05` 要单独归类，不能与带 `W08`/`W09` 的 `D05` 混在同一个分子里。

一侧为空（现网清单只有注释）：

```text
W03  文件含 1 行注释，已丢弃：.x6fx/r1-base.txt
E11  现网归一化后为空，没有可比对的条目
```

退出码 2。这里刻意**不**输出 `D02 = 10`（"所有服务都消失了"）：按第 20.3 节的口径，E11 之后比对终止。把"取不到清单"读成"清单为空"是本系列第 16 篇（Mainline/APEX）里已经列过的同类错误，本文把它做成硬失败而不是警告。

### 20.5 判读规则

1. **先读 `N00` 再读 `D`。** 两侧条目数与 `D01/D02/D03` 必须自洽：`D03 + D02 ≤ 基线数`、`D03 + D01 ≤ 现网数`；不满足说明清单里有 W05/W04 那类脏条目在干扰。
2. **`W04`/`W05` 非零时，本轮漂移读数不可用于趋势。** 应该先去修采集，而不是把这次的 D05 记入历史序列。
3. **`D04` 不等于"没有变化"。** 它只说明"服务名集合相同"。`MachServices` 的值（布尔/字典形态）与 `LimitLoadToSessionType` 都可以变而集合不变（第 8.1 节推论 2）——这是第 22 章误区 8 的内容。
4. **`W08` 与 `W09` 是两个方向的追问，不是一个结论。** 前者要问"这条服务是被下线、改名，还是只是我这次没采到"，后者要问"新暴露的名字有没有对应的画像授权、属于哪条层（第 12 章）"。

---

## 21. 两个脚本的全量分支覆盖验收

### 21.1 验收口径

"全量分支覆盖"在本报告里的定义是三条，缺一不可：

1. **码位覆盖**：每个脚本声明的每个信号码，都要有一个具体输入能实际触发它（或明确登记为"本轮环境不可触发"）。
2. **退出码覆盖**：0 / 2 / 9 三种退出形态各自至少被一条用例命中。
3. **字节一致**：报告里内嵌的脚本与验收时实跑的脚本是同一份内容（用围栏区间重新抽出后逐字节比对，见第 21.5 节）。

输入全部是**构造样本**：`.ips` 样本按第 19.2 节的双 JSON 口径手工构造，清单样本是手工服务名列表。它们不含任何真实设备导出的数据，也不用于证明"真机上存在这些形态"——真机形态的口径来源是第 15 章引用的公开文档，不是这些样本。

### 21.2 脚本一：逐码位实跑结果

下表每一行都是本轮的一条实跑命令（`xpc-ips-triage.sh [-q] <样本>`），"命中码位"是该命令输出的原样码位序列。

| 用例 | 输入形态 | 命中码位 | 退出码 |
| --- | --- | --- | --- |
| S1-01 | 完整守护进程崩溃件，栈含 mach_msg/xpc/NSXPC/MIG 四类符号 | W02 W03 W06 W07 D01 | 0 |
| S1-02 | `EXC_GUARD` + 端口系符号 | W01 W11 D01 | 0 |
| S1-03 | 有 threads 但无 IPC 符号、有终止信息 | W12 D02 | 0 |
| S1-04 | 有 threads、`exception` 空壳、有终止信息 | E08 W12 D02 | 2 |
| S1-05 | 头部薄（缺 `bug_type`/`app_name`/`os_version`，`platform=5`，`roots_installed=1`）但主体可用 | E04 E05 W09 W10 W08 W04 D01 | 2 |
| S1-06 | 主体无 `threads` | E10 | 2 |
| S1-07 | 主体无 `exception`、无 `termination`，栈含 `CFMessagePort` | E07 E09 W05 D01 | 2 |
| S1-08 | 只有首行 | E06 | 2 |
| S1-09 | 空文件 | E02c | 2 |
| S1-10 | 首行不以 `{` 开头 | E03 | 2 |
| S1-11 | 栈含 `CFMessagePort` 与 MIG 形态符号 | W02 W05 W07 D01 | 0 |
| S1-12 | 有 threads、帧无符号、终止与信号两格都空 | E08 E09 W12 D03 | 2 |
| S1-13 | 主体既无 `procName` 也无 `exception` | E06b | 2 |
| S1-14 | 路径不存在 | E02 | 2 |
| S1-15 | 未知选项 `-z` | E90 | 9 |
| S1-16 | 无位置参数 | E92 | 9 |
| S1-17 | `-h` | 帮助文本 | 0 |
| S1-18 | `TMPDIR` 指向不存在目录 | E93 | 2 |
| S1-19 | 两个可用文件一次批量调用 | 两段 D01 | 0 |
| S1-20 | 三个坏文件一次批量调用（`-q`） | E04 E05 W09 W10 W08 W04 D01 E02c E03 | 2 |

覆盖核算：30 个码位里 29 个由上表实跑命中（W 类 12 个全部命中，D 类三格全部命中，E 类 15 个里除 `E02b` 之外全部命中）。唯一未命中的 `E02b` 见第 21.4 节。另有码位之外的分支未单独构造：`E93` 这个码位由 S1-18 命中，但产生它的同一函数内还有三个 `mktemp` 失败分支（清理路径）走的是同一个号码，本轮没有为它们各造一条输入——**"每个码位都被触发"不等于"每个分支都被触发"**，这条差额登记在第 21.5 节。

### 21.3 脚本二：逐码位实跑结果

| 用例 | 输入形态 | 命中码位 | 退出码 |
| --- | --- | --- | --- |
| S2-01 | 10 条 vs 12 条，含 3 新增 1 消失 | W03 N00 N00 D01 D02 D03 W09 W08 D05 | 0 |
| S2-02 | 同一清单的大小写 + CRLF 变体（`-q`） | W01 W03 W03 N00 N00 D01 D02 D03 W08 W10 D05 | 0 |
| S2-03 | 脏清单 vs 自身（形态检查全开） | N00 W04 W05 W07 W06 N00 W04 W05 W07 W06 D01 D02 D03 D04 | 0 |
| S2-04 | 同一清单自比 | W03 W03 N00 N00 D01 D02 D03 D04 | 0 |
| S2-05 | 基线只有注释与空行 | W02 W03 W03 E10 | 2 |
| S2-06 | 现网为空文件 | W03 E11 | 2 |
| S2-07 | 基线路径不存在 | E01 | 2 |
| S2-08 | 未知选项 `-z` | E90 | 9 |
| S2-09 | 只给一个位置参数 | E92 | 9 |
| S2-10 | `-h` | 帮助文本 | 0 |
| S2-11 | `TMPDIR` 指向不存在目录 | E93 | 2 |

覆盖核算：23 个码位里 22 个由上表实跑命中，唯一未命中的是 E02（存在但不可读），见第 21.4 节。D 类五格（D01–D05）全部命中，其中 D04 由 S2-03/S2-04 命中、D05 由 S2-01/S2-02 命中；`N00` 在每条正常用例里恒定出现。

### 21.4 本轮环境未触发的分支，以及怎么复现

诚实登记两条**没有**被实跑覆盖的码位。它们不是"逻辑上不可达"，而是"本轮这台机器的权限模型下构造不出输入"：

| 码位 | 脚本 | 为什么本轮没触发 | 复现方法 |
| --- | --- | --- | --- |
| E02b | 脚本一 | 本轮在 Windows 的 Git Bash 下以管理员身份运行：`chmod 000` 不生效，`icacls /deny Administrator:R` 之后 `-r` 测试仍为真（本轮实测两者均如此），因此构造不出"存在但不可读"的文件 | 在 Linux 或 macOS 上用普通用户身份：`cp good.ips noperm.ips && chmod 000 noperm.ips && ./xpc-ips-triage.sh noperm.ips` → 期望单行 `E02b`，退出码 2 |
| E02 | 脚本二 | 同上（同一台机器、同一个权限模型） | `cp roster.txt noperm.txt && chmod 000 noperm.txt && ./xpc-roster-diff.sh noperm.txt other.txt` → 期望单行 `E02`，退出码 2 |

顺带记录本轮踩到的两个环境陷阱，它们会让读者误判"分支没覆盖"：

- **`grep` 在这台机器上看不见单独的 CR。** 对含 CRLF 的清单，`grep -c $'\r'` 返回 0，但文件里确实有 11 个 CR。脚本二 W01 的实现因此改用 `tr -dc '\r' < f | wc -c` 计数，这一点在第 20.3 节词表里体现为"计数 > 0 才报"。
- **`comm` 只接受已排序输入。** 首版直接对未排序的归一化结果跑 `comm`，得到过假的 D01/D02；现在两侧都先 `sort -u` 成副本再比对（脚本内注释即此原因）。

### 21.5 校验程序与验收结论

验收程序本身要能被别人重跑，步骤写死如下：

1. 从本报告的代码围栏里按行区间抽出两份脚本，分别落成 `xpc-ips-triage.sh` 与 `xpc-roster-diff.sh`。
2. `bash -n` 做语法检查（两份都通过）。
3. 依次跑第 21.2 / 21.3 两张表的全部用例，比对码位序列与退出码。
4. 把抽出的脚本与验收时的原件做逐字节比对（`cmp`），差异必须为 0 行。

结论，按第 17 章的级别口径写：

- 本报告内嵌的两个脚本**达到了级 3（读数级）**——它们是本地可复现、输出确定、退出码确定的读数生产者。
- 它们对**任何设备状态**的结论强度不超过级 2，理由是输入由读者自备，脚本无法验证输入的真实性与完整性（第 15.2 节的裁剪问题、第 14 章的取数路径限制同样适用）。
- 覆盖结论：**51 / 53 码位实跑命中，2 码位待读者在自己机器上复现**。这条差额本身应当作为第 18 章 K4 的一个已知常量记下——任何声称"100% 覆盖"的复述都与本节不符。
- 覆盖口径的一条限定：本表的单位是**码位**，不是分支。`E93` 由一条用例命中，但它背后的 `mktemp` 失败点有四处；`E02`/`E02b` 之外的错误分支（例如同一 `emit` 函数内的其它早退）也没有逐条造样本。因此第 21.1 节第 1 条只承诺"每个码位都有输入触发它"，读者把它读成"每行代码都被执行过"时，这个验收不支持。


---

## 22. 十二个误区

每条误区都是本文前面某一节的反面表述：误区与依据同章号给出，读者复核时应当能立刻在正文里找到那句话。排序按"造成错误结论的代价"从大到小，不是按出现频率。

| # | 误区 | 为什么容易犯 | 依据所在 | 正确的问法 |
| --- | --- | --- | --- | --- |
| 1 | 把公告组件名当缺陷层 | `libxpc` 是一个看起来很像"模块"的名字，而它同时覆盖第 6、7、8、9 章四层；更糟的是同一份文档里 `libxpc` 与 `XPC` 并存（13.2 落差 A） | 第 3.1 节、第 13.5 节限度 1 | "这条修复改的是哪一次校验？"——而不是"它属于哪个组件？" |
| 2 | 把 Impact 后果词当缺陷类型 | 公告的 Impact 只有 16 种写法，其中 12 条含 `sandbox`、9 条含 `privilege`，且两组重叠 2 条；"逃逸沙箱"是结果，X5/X9/X10 都能产生它 | 第 13.5 节限度 2 | "这个后果由哪一层的校验缺失产生？"——答案通常不止一个 |
| 3 | 把"连不上某个服务"当缺陷读数 | 默认失败是明文口径：沙箱对 Mach 名称解析的介入就是 allowlist 语义，缺省拒绝是设计。iOS 上多数"连不上"是预期行为 | 第 9.3 节、第 8.3 节（bootstrap 命名空间的域） | "两侧在同一个 bootstrap 域吗？这个服务在该域里吗？" |
| 4 | 把公告条目数当缺陷数 | 一个 CVE 在 72 份文档里最多占 7 行（13.6），平均 3.85 行；不声明分母时，同一个问题的答案能差近四倍 | 第 13.1 节总量表、第 13.6 节分母纪律 | "你数的是去重 CVE 还是公告条目？" |
| 5 | 把"崩溃回溯里有 `mach_msg` 帧"当 IPC 层有缺陷 | 帧只说明消息经过内核，不说明哪一次校验失败；一次正常同步调用本来就要穿过原语层、XPC 层、NSXPC 层、MIG 层（第 19.5 节的四行 W 正是这一条） | 第 19.5 节、第 15.2 节四类缺失 | "这次崩溃的异常类型与终止来源是什么？命中在哪一层？" |
| 6 | 以为轻量安全更新能补上 IPC 内核类修复 | RSR 的原文限定 "only for the latest versions"，BSI 的组件口径写的是 Safari / WebKit 栈 / 其他系统库，XNU 内核与 launchd 不在那句列举里 | 第 12.3 节、第 17.2 节硬约束 3、第 24 章 B6 | "这条修复在这条版本线上以什么形态到达？公开口径说得出组件范围吗？" |
| 7 | 把脚本命中的 W 码数量当缺陷数量 | W02/W03/W06/W07 是四个层的命中，一条崩溃可以同时命中全部；命中数是路径证据，不是计数证据 | 第 19.5 节、第 19.6 节判据 4 | "这条读数落在哪一层？有几个独立缺陷？"（后者脚本不回答） |
| 8 | 把"两份清单集合相同"当"没有变化" | 脚本二比的是名字集合，`MachServices` 的布尔/字典值、`LimitLoadToSessionType` 都可以变而集合不变 | 第 8.1 节推论 2、第 20.5 节判据 3 | "集合相同只说明名字没增删，装配参数变了吗？" |
| 9 | 拿一条版本线的公告行去回答另一条线的设备 | 同一 CVE 同时挂在 iOS/tvOS/watchOS 与 macOS 三条并行线上（13.6 的 CVE-2025-31182 实例）；跨线编号还可能不同 | 第 17.2 节硬约束 1、2，第 13.6 节通道纪律 | "先确定设备在哪条线，再在该线的文档里找这一行。" |
| 10 | 把署名口径当归属口径 | 27 条里 7 条署名是 `an anonymous researcher`、1 条整行无署名（13.2 落差 B），且同一 CVE 在不同页面署名顺序不同（13.4） | 第 13.4 节 | "署名说明谁报告的，不说明谁负责修。" |
| 11 | 把在野口径的零读成"没有被利用过" | 两个零各有各的成立条件：`actively exploited` 句式只出现在部分早期文档，KEV 只收"有证据被利用"的条目 | 第 13.7 节 | "公开证据不足以把它排进在野清单" ≠ "它没被用过" |
| 12 | 把取不到数当"没问题"，或把级 3 读数直接写成级 4 归因 | 设备侧没有 shell、没有名称表导出、没有端口状态导出（第 14 章），"读不到"是可见性边界而非结论；反过来，一条 `EXC_GUARD` 读数也不能直接写成"X5 绕过" | 第 14.1 节、第 17.3 节、第 17.4 节 | "我手上的证据允许我说到哪一句话？" |

### 22.1 这十二条的共同结构

十二条里有八条（1、2、4、9、10、11，加上 5、7 的成因）都是同一个错误：**把某一层的表示法当成缺陷本身**。公告的组件名、Impact 用词、条目行数、署名文字、脚本码位——它们分别是五个不同系统的输出格式，而缺陷只有一个。本文的四级判定模型（第 17 章）之所以把"级"写死为"允许说的最大结论"，就是为了给这种混淆设置一个可检查的门槛：每一句结论都必须能被追溯到它所在级的输入类型。

### 22.2 两条不在表里、但更贵的误区

- **"我把机制搞清楚了，所以我知道风险。"** 机制层（第 4–10 章）与风险层（第 12–13 章）之间隔着整章的取数限制。机制清晰只能支持级 1。
- **"我做了比对，所以我有基线。"** 第 20.4 节给出漂移的三条解释路径（真实变化、采集口径、来源不同时点），只有第一条才是基线含义。脚本二把这三条都报出来，但不替你选。

---

## 23. 常见问题

**Q1：iOS 上跨进程通信只有 XPC 吗？**
不是。Mach 端口是底层权利载体，XPC 是对象与连接层，NSXPC 是 Foundation 封装，MIG 是接口契约生成器，CFMessagePort 是 CoreFoundation 侧的老通道，IOKit user client 是另一侧的 Mach 表面（第 4–10 章）。第 19 章脚本给这五类通道各设了一个码位（W02–W07、W11），就是因为它们是并行存在的通道而不是同义词。

**Q2：为什么公告里既有 `libxpc` 又有 `XPC`？**
本轮无法给出规则（第 13.2 落差 A）。可指认的事实是两者在同一份文档里并存（`pages/149035.txt`），且行数比为 96 : 8。筛选时必须同时取两名。

**Q3：我能在设备上列出所有 Mach 服务名吗？**
没有公开文档化的只读路径。可得的替代是把第 20 章脚本作用在"设备导出的文本"上（配置、日志、崩溃报告里出现的服务名字符串），并把它当**清单的一个视图**而不是清单本身（第 14.1 节）。

**Q4：崩溃报告里有 `mach_msg2_trap` 就说明是 IPC 漏洞吗？**
不。只说明消息经过内核那一刻（第 22 章误区 5）。判定要用异常类型 + 终止命名空间 + 码位组合，并且还要过第 15.2 节的四类缺失。

**Q5：`EXC_GUARD` 是什么？**
本报告的脚本一把它作为端口/守卫类违规的高提示信号（W01），并允许在级 3 说"这条读数带有守卫类线索"。它不等于任何一型缺陷成立（第 22 章误区 12）。

**Q6：一份 `.ips` 我要看哪几行？**
先看头部 JSON 的 `bug_type`、`app_name`、`os_version`、`roots_installed`，再看主体的 `exception.type`、`termination.namespace`/`code`、`threads` 里的符号。脚本一的 E 类码位就是按"这几格取不到"设计的——任一格取不到，这条读数不进任何统计（第 19.6 节判据 2）。

**Q7：为什么脚本二坚持比"集合"而不是比"顺序/数量"？**
服务名清单的顺序取决于采集方式，数量受重复行与注释影响；只有集合差对采集噪声最不敏感。代价是它看不见装配参数变化（第 20.3 节设计取舍 1、第 22 章误区 8）。

**Q8：iOS 上的缺陷修好后我怎么验证？**
只有三种可观察形态（第 12.3 节）：整机版本前进、轻量改进生效、或什么都不显示。签名/权利/selector 层面的修复没有设备侧可读字段。更新还不可回退，所以"修没修好"只能用行为验证，而多数层的行为验证强度是弱。

**Q9：`roots_installed=1` 的报告还能用吗？**
读数保留但必须与本系列基线分栏（W08 / K4 的单独记账）。设备状态已被改动时，同一码位的含义不成立（第 19.6 节判据 3）。

**Q10：为什么第 21 章说覆盖是 51/53 而不是 53/53？**
两个"文件存在但不可读"分支（脚本一 E02b、脚本二 E02）在本轮 Windows 管理员环境下无法构造：`chmod 000` 对管理员无效，`icacls /deny` 之后读探针仍成功。第 21.4 节给出 Linux/macOS 上的复现命令。这条差额作为 K4 的已知常量记录（第 21.5 节）。

**Q11：本文能回答"我的设备有没有 XPC 漏洞"吗？**
不能。本文能回答的是：这类缺陷在哪一层、由谁负责、修好后显示在哪、以及你手上导出的文本能支持到哪一句话。级 4 归因需要设备侧证据强度 ≥ 中，而 X3（名称空间）与 IOKit user client 两层的设备侧证据是"无"，永远到不了级 4（第 17.4 节）。

**Q12：为什么全文不提供任何操纵端口或注入服务的步骤？**
这些步骤的效果是把"名字—权利—进程"的绑定从校验者手里挪到调用者手里，一旦写出即可被直接照搬到未授权目标上。本文的边界写在第 2 章范围声明里：只给公开口径、可指认的字段与常量、以及读者对自有导出件的只读判定。

---

## 24. 未公开文档化边界清单

本章登记的是**本文想引而引不到的东西**，共 12 条，供第 18 章 K10 维护。每条给：想问的问题、已检索到的最接近公开口径、缺什么、以及一旦补上会影响本文哪一节。状态列"仍在"表示本轮无公开来源可填补。

| # | 边界项 | 已取到的最接近口径 | 缺的那一步 | 影响节 | 状态 |
| --- | --- | --- | --- | --- | --- |
| B1 | 服务类型三分法（ephemeral / stateless / persistent） | NSXPC 全部文档 JSON、launchd OSS 手册页（main 与 842 tag）、CreatingXPCServices 归档指南 | 该三分法在这四处均无；Apple 公开口径只区分 bundle 内 XPC service、LaunchAgent/LaunchDaemon 的 Mach 查找、匿名/端点连接 | §6、§7、§8 | 仍在 |
| B2 | `EnablePressuredExit` 键 | 官网与 TN2083（`tn2083-daemons-guide.html` 检索 0 命中）与 OSS launchd 手册页镜像均无该键 | 只有第三方本机 man 页摘要载有，不能作为 Apple 口径引用 | §8.4 | 仍在 |
| B3 | "pressured exit" 与 "multithreaded" 作业的官方网页文档 | OSS 手册页无 `multithreaded` / `pressured` 表述 | 无法以 Apple 官方 URL 引证 | §8.4 | 仍在 |
| B4 | `com.apple.*` 前缀是否保留 | 文档只规定反向 DNS 命名；launchd 手册页示例出现 `com.apple.sshd` | 一句可引的"保留"声明；论坛回答无法定位原帖 URL | §3.2、§8.1、脚本二 W09/W08 的解释力 | 仍在 |
| B5 | `launchctl print` / `launchctl procinfo` | OSS `launchctl(1)` 各版只文档化 `list`、`bslist`、`bstree`、`bsexec`、`managerpid/uid/name` 等 | 这两个子命令在任何 Apple 官方网页/镜像里均未出现，属本机 man 页口径 | §14.1 取数路径表 | 仍在 |
| B6 | 现代 launchd 域命名 `gui/<uid>` 与 auid/审计会话域 | 公开文档只给 session types（Aqua / LoginWindow / Background / StandardIO / System）与 "user" domain | `gui/<uid>` 字符串未在任何已取回的 Apple 官方页面出现 | §8.3、§12 归属矩阵 | 仍在 |
| B7 | iOS 沙箱 profile 内 mach-lookup 的 allow/deny 规则与私有 entitlement 门禁清单 | 可引的是 app-sandbox 布尔、macOS 全局 Mach lookup/registration 需 temporary exception、entitlement 控制特权操作的总口径 | iOS 侧的规则集合不公开；因此第 9.3 节只能借 macOS 归档文档说"介入存在"，不能说"iOS 的清单内容" | §9.3、§12.1、§23 Q3 | 仍在 |
| B8 | 崩溃文档里的 IPC 符号示例 | 崩溃文档样例仅含 EXC_BAD_ACCESS / EXC_BREAKPOINT、libdispatch、SPRINGBOARD watchdog 等 | `mach_msg2_trap`、`xpc_*` 等符号不出现在 Apple 文档示例里；脚本一的命中表是基于真实导出件而非文档示例建的 | §15、§19.4 | 仍在 |
| B9 | "iOS 不向用户暴露 shell / launchctl"的直接原文 | Platform Security 的等价表述："Unnecessary tools, such as remote login services, aren't included in the system software…" | 该句未点名 Terminal 或 launchctl；第 14 章只能写成"取数路径受工具面限制"而不能写"Apple 说 iOS 没有 shell" | §14.1 | 仍在 |
| B10 | 现行公告的 `Affected:` / `Provided by:` 字段名 | 现行版式为 `Available for:` + CVE 行内署名 + "We would like to acknowledge … for their assistance." | 旧式字段名只出现在早期文档；引旧字段需另取旧样本（本文未取） | §16、第 13 章抽取规则 | 仍在 |
| B11 | `opensource.apple.com` 的 Darwin 手册页在线版 | 该入口现返回 SPA 外壳，HTML 中无正文 | 需改用 Apple 官方 GitHub 镜像（`apple-oss-distributions`）取证，本文已全部改走镜像；引"Darwin Manual Pages @ opensource.apple.com"时须注明当前不可直接抓取 | §26 全部手册页引文 | 已绕行 |
| B12 | `.ips` 的公开完整格式规范 | Apple 给出结构与字段文档（JSON 版式、字段含义、异常类型三类页） | 没有独立的"文件格式规范"页；且 `vmRegionInfo`（JSON 属性名，小写驼峰）与渲染正文里的 "VM Region Info" 两个写法不可混用 | §15.1、§19.2 | 仍在 |

### 24.1 这张清单怎么用

三条规则：

1. **清单里的项不是本文的漏洞，是本文的墙。** 任何一条被公开材料填补时，受影响章节的表述等级会变化（例如 B7 若被填补，第 9.3 节可从"借 macOS 归档口径"升到"iOS 明文口径"，级 1 的结论强度随之改变）。
2. **不要在清单为空时借相邻平台的文档下 iOS 结论。** B7、B9、B10 都是"macOS/旧版式/未点名"的近似口径，本文引用它们时都写明了来源边界；读者复用这些句子时也必须带着这个限制。
3. **K10 只统计条数与状态变化，不解释变化原因。** 这是自指指标（第 18 章 K10 限度列已写），它衡量的是本文对自身的诚实程度。

---

## 25. 结论

本文回答的是一个比"iOS 有哪些 IPC 漏洞"更窄的问题：**当一个缺陷落在 Mach IPC 这条通道上时，公开材料允许我们知道到什么程度为止**。26 章的内容压缩成八条结论。

1. **通道是分层的，责任也是。** Mach 端口/权利/名称、名称空间、消息、MIG、XPC 对象、NSXPC、launchd 装配、bootstrap 命名、沙箱与 entitlement 介入、IOKit user client 十层里，"谁修"在层与层之间是不同的对象：内核、守护进程实现方、框架封装方、App 打包方。第 12.1 节那张矩阵的全部价值就是把"等 Apple 修"这句话拆成"等谁、走哪条通道、设备上显示在哪一格"。

2. **三套词表之间没有一一映射，且落差是可测的。** 公告用组件名（`libxpc` / `XPC` 两名并存于同一文档），源码用符号与字段（`ip_mscount`、`imq_qlimit`、`MPO_CONTEXT_AS_GUARD`），运行时与崩溃文本用帧符号。第 13.2 节量出了三处具体落差：一个冒号决定一条 CVE 是否被计数（100→104 行、26→27 个 CVE，漏掉的恰好是"无外部署名"那一条）；一个组件名覆盖四层；一次朴素的按行计数多算 7 行，全部来自致谢段。这三处落差都是可重跑的，不是修辞。

3. **公告侧的证据天花板是级 2，且 27 行无一例外。** 第 13.8 节按四级模型逐行落位：全部 104 行到级 1，100 行可到级 2（读者自选版本线后），4 行连级 2 都有条件；级 3 与级 4 的行数是 **0**，因为公告不产生设备侧读数。同时两个独立的在野口径给出零读数（`actively exploited` 句式命中 0、CISA KEV 命中 0，方法用已知条目做过阳性对照）——这两个零各有成立条件，支持"公开证据不足以列入在野清单"，不支持"没被用过"。

4. **设备侧的证据只有两种能复现地生产，本文把它们写成了脚本。** `.ips` 分类器（30 个码位）与服务清单漂移比对器（23 个码位）是级 3 的唯一产能；第 21 章的验收把 53 个码位中的 51 个实跑命中并逐字节锁定了报告内嵌代码，2 个（"文件存在但不可读"）在本轮环境无法构造，只给复现方法。这份差额必须留在那里——它比一个好看的 53/53 更有用。

5. **"修好了"在 iOS 上常常不显示。** 三种可观察形态里，签名/权利/selector 层面的修复属于"什么都不显示"那一格；轻量通道这一格在 2026 年换了口径（RSR 的 "only for the latest versions" → BSI 的组件列举 "Safari browser, WebKit framework stack, and other system libraries" 与 "starting with iOS 26.1"），而内核与 launchd 是否走这条通道公开文档没有答案；同时更新不可回退、已应用的改进还可被移除回基线。**修得快不等于证得明**是本文对运营的核心判断。

6. **可见性边界决定归因上限。** 没有 shell、没有名称表导出、没有端口状态导出，这不是操作上的不便，而是类型学的算术结果：X3（名称空间/槽位复用）与 IOKit user client 两层的设备侧证据列是"无"，因此这两型在本报告集里永远达不到级 4。任何声称能用设备侧日志筛出 X3 的方法应被质疑（第 11.2 节）。

7. **十二个误区里八条是同一个错误。** 把某一层的表示法当成缺陷本身（组件名、Impact 用词、条目行数、署名文字、脚本码位、帧符号）。四级判定模型的作用就是把这种混淆变成一次可检查的越级：每句结论都必须能追溯到它所在级的输入类型。

8. **本文留下的 12 条边界是正文的一部分。** 第 24 章的 B1–B12 记录了"想引而引不到"的位置，其中 B11（`opensource.apple.com` 已是 SPA 外壳，全部手册页改走 GitHub 官方镜像）已经绕行，其余 11 条状态为"仍在"。这份清单与本文的结论同等重要：它标出了下一次修订应当从哪里开始。

最后一句按本文自己的规则写：以上八条全部是级 1 与级 2 的结论，它们不构成对任何具体设备、具体版本、具体服务是否受影响判定。要做那一步，读者需要的是第 19 章与第 20 章那两个脚本对自己导出件产生的读数，而不是本文的任何一段。

---

## 26. 参考资料

全部条目均在 2026-10-30 取回并保存在本地存档（`.srcx6/A`、`.srcx6/B`、`.srcx6/C`），第 2、13、19–21 章的每一句英文引文与每一个源码行号都可在其中逐字检索。引用转录约定见第 2 章。

这条检索不是号召，是本文交付前跑过的一轮机器复核：从正文（跳过代码围栏）抽出所有四个词以上的直引号片段与反引号片段，按第 2 章那六条排版归一规则生成检索式，在 `.srcx6` 三个存档目录上逐条命中。复核范围只包含**对外部资料的英文引语**——本文自造的中文说明短语、内嵌脚本自身的命令行与正则字面量不参与，它们本来就不是任何人的原文。两处口径缺口按第 2 章的规定就地注明（第 6.4 节只引前半句、第 7.3 节标注链接标签回填），不做修补式改写。

### 26.1 Apple 官方文档：XPC / NSXPC / 沙箱 / 崩溃报告

- XPC（Foundation 集合页）：https://developer.apple.com/documentation/foundation/xpc
- NSXPCConnection：https://developer.apple.com/documentation/foundation/nsxpcconnection
- NSXPCConnection `init(serviceName:)`：https://developer.apple.com/documentation/foundation/nsxpcconnection/init(servicename:)
- NSXPCConnection `init(listenerEndpoint:)`：https://developer.apple.com/documentation/foundation/nsxpcconnection/init(listenerendpoint:)
- NSXPCConnection `init(machServiceName:options:)`：https://developer.apple.com/documentation/foundation/nsxpcconnection/init(machservicename:options:)
- NSXPCConnection `setCodeSigningRequirement(_:)`：https://developer.apple.com/documentation/foundation/nsxpcconnection/setcodesigningrequirement(_:)
- NSXPCConnection `exportedInterface`：https://developer.apple.com/documentation/foundation/nsxpcconnection/exportedinterface
- NSXPCConnection `auditSessionIdentifier`：https://developer.apple.com/documentation/foundation/nsxpcconnection/auditsessionidentifier
- NSXPCInterface：https://developer.apple.com/documentation/foundation/nsxpcinterface
- NSXPCListener：https://developer.apple.com/documentation/foundation/nsxpclistener
- NSXPCListener `init(machServiceName:)` / `service()` / `anonymous()` / `endpoint`：https://developer.apple.com/documentation/foundation/nsxpclistener/init(machservicename:) 、 https://developer.apple.com/documentation/foundation/nsxpclistener/service() 、 https://developer.apple.com/documentation/foundation/nsxpclistener/anonymous() 、 https://developer.apple.com/documentation/foundation/nsxpclistener/endpoint
- NSXPCListener `setConnectionCodeSigningRequirement(_:)`：https://developer.apple.com/documentation/foundation/nsxpclistener/setconnectioncodesigningrequirement(_:)
- NSXPCListenerEndpoint：https://developer.apple.com/documentation/foundation/nsxpclistenerendpoint
- NSXPCListenerDelegate `listener(_:shouldAcceptNewConnection:)`：https://developer.apple.com/documentation/foundation/nsxpclistenerdelegate/listener(_:shouldacceptnewconnection:)
- XPC Connections（C 层）：https://developer.apple.com/documentation/xpc/xpc-connections
- App Sandbox entitlement：https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.app-sandbox
- App Sandbox（Security 文档）：https://developer.apple.com/documentation/security/app-sandbox
- 沙箱 temporary exception 权利（归档文档，含 Mach lookup/registration 两项）：https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/AppSandboxTemporaryExceptionEntitlements.html
- Creating XPC Services（归档指南）：https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html
- Kernel Programming Guide：Boundaries：https://developer.apple.com/library/archive/documentation/Darwin/Conceptual/KernelProgramming/boundaries/boundaries.html
- 崩溃报告：JSON 版式：https://developer.apple.com/documentation/xcode/interpreting-the-json-format-of-a-crash-report
- 崩溃报告：字段含义：https://developer.apple.com/documentation/xcode/examining-the-fields-in-a-crash-report
- 崩溃报告：异常类型：https://developer.apple.com/documentation/xcode/understanding-the-exception-types-in-a-crash-report
- 设备分析与"通知与数据"口径：https://www.apple.com/legal/privacy/data/en/device-analytics/
- Apple 开发者论坛 XPC 资源栏（半正式，引用已注明性质）：https://developer.apple.com/forums/tags/xpc

### 26.2 Apple 开源分发：XNU 与 launchd 源码、手册页

- XNU 标签索引：https://github.com/apple-oss-distributions/xnu/tags ；`osfmk/ipc` 目录：https://github.com/apple-oss-distributions/xnu/tree/xnu-12377.121.6/osfmk/ipc
- Mach IPC 内核内文档：`doc/mach_ipc/port_types.md`、`ipc_security_concepts.md`、`kmsg.md`、`guard_exceptions.md`：https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/doc/mach_ipc/port_types.md 、 https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/doc/mach_ipc/ipc_security_concepts.md 、 https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/doc/mach_ipc/kmsg.md 、 https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/doc/mach_ipc/guard_exceptions.md
- `osfmk/ipc/ipc_port.h`（`ip_receiver`、`ip_kobject`、`ip_mscount`）：https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/osfmk/ipc/ipc_port.h#L119-L207
- `osfmk/ipc/ipc_port.c`：https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/osfmk/ipc/ipc_port.c#L192-L203
- `osfmk/ipc/ipc_entry.c`（`ipc_entry_lookup` / `ipc_entry_alloc`）：https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/osfmk/ipc/ipc_entry.c#L83-L148 、 https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/osfmk/ipc/ipc_entry.c#L624-L701
- `osfmk/ipc/ipc_entry.h`：https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/osfmk/ipc/ipc_entry.h#L100-L160
- `osfmk/ipc/ipc_object.h` / `ipc_object.c`（释放队列与 `ipc_port_free`）：https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/osfmk/ipc/ipc_object.h#L215-L247
- `osfmk/ipc/ipc_kmsg.c`：https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/osfmk/ipc/ipc_kmsg.c#L2189-L2230
- `osfmk/ipc/ipc_mqueue.c`（`imq_qlimit` 初始化）：见上目录树；`osfmk/ipc/ipc_policy.c`：https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/osfmk/ipc/ipc_policy.c#L694-L740
- `osfmk/ipc/ipc_right.c`、`ipc_space.h`、`ipc_types.h`、`ipc_service_port.h`：https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/osfmk/ipc/ipc_right.c 、 https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/osfmk/ipc/ipc_space.h#L141-L150 、 https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/osfmk/ipc/ipc_types.h#L120-L193 、 https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/osfmk/ipc/ipc_service_port.h#L30-L60
- `osfmk/mach/message.h`（描述符类型、守卫描述符、尺寸宏）：https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/osfmk/mach/message.h#L138-L190 、 https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/osfmk/mach/message.h#L336-L390 、 https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/osfmk/mach/message.h#L890-L980
- `osfmk/mach/port.h`、`mach_port.defs`、`host_special_ports.h`、`osfmk/man/mach_msg.html`：https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/osfmk/mach/port.h#L255-L365 、 https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/osfmk/mach/mach_port.defs#L154-L210 、 https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/osfmk/mach/host_special_ports.h#L85-L105 、 https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/osfmk/man/mach_msg.html
- `osfmk/device/device.defs`（MIG 声明计数样本）：https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/osfmk/device/device.defs#L142-L323
- `libsyscall/mach/mach_msg.c`（用户态发送侧）：https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/libsyscall/mach/mach_msg.c#L88-L145
- `osfmk/kern/mach_filter.h`、`security/mac_policy.h`、`iokit/Kernel/IOUserClient.cpp`、`bsd/kern/kern_sysctl.c`：https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/osfmk/kern/mach_filter.h#L35-L110 、 https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/security/mac_policy.h#L3970-L3990 、 https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/iokit/Kernel/IOUserClient.cpp#L5131-L5162 、 https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/kern/kern_sysctl.c#L2449
- XNU 内核测试里的 IPC 用例：https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/tests/unit/ipc/xpc_connection_port_pair.c#L40-L60
- IOKitUser 侧 `IOKitLib.h`（`destroyUserReferences` 等声明）：https://github.com/apple-oss-distributions/IOKitUser/blob/IOKitUser-100231.120.3/IOKitLib.h#L1502-L1534
- launchd 标签索引与 842 源码树：https://github.com/apple-oss-distributions/launchd/tags 、 https://github.com/apple-oss-distributions/launchd/tree/launchd-842.92.1/src
- 手册页 `launchd.plist(5)`（`MachServices`、`ProcessType`、Adaptive 段）：https://github.com/apple-oss-distributions/launchd/blob/launchd-842.92.1/man/launchd.plist.5 、 https://github.com/apple-oss-distributions/launchd/blob/main/man/launchd.plist.5
- 手册页 `launchd(8)`、`launchctl(1)`：https://github.com/apple-oss-distributions/launchd/blob/launchd-842.92.1/man/launchd.8 、 https://github.com/apple-oss-distributions/launchd/blob/launchd-842.92.1/man/launchctl.1
- 历史 tarball 入口（`libxpc`、`xnu`）：https://opensource.apple.com/tarballs/libxpc/ 、 https://opensource.apple.com/tarballs/xnu/ （注：`opensource.apple.com` 的手册页在线版现为 SPA 外壳，正文改由上述 GitHub 官方镜像取证，见第 24 章 B11）
- Apple OSS 组织仓库清单接口：https://api.github.com/orgs/apple-oss-distributions/repos

### 26.3 Apple 安全公告与更新机制

- Apple 安全平台发布页（Security Releases 索引）：https://support.apple.com/en-us/100100
- 《About security updates for Apple products》：https://support.apple.com/en-us/106354
- 《About Background Security Improvements for iOS, iPadOS, and macOS》：https://support.apple.com/en-us/HT201224 （Published Date: September 14, 2026）
- 单份发布内容文档样本（本文第 12.3、13 章引用其字段与机型清单）：https://support.apple.com/en-us/149230
- 第 13 章的取数件：Apple Support《About the security content of …》系列 366 份文档的本地缓存（当前版式 313 份 + 早期版式 53 份，均含渲染文本与原始 HTML）；被引用的具体缓存件在第 13 章正文内以 `pages/…`、`oldpages/…` 路径与行号标出
- Platform Security Guide（PDF）：https://help.apple.com/pdf/security/en_US/apple-platform-security-guide.pdf

### 26.4 第三方公开目录

- CISA Known Exploited Vulnerabilities 目录：https://www.cisa.gov/known-exploited-vulnerabilities-catalog （本地缓存件 `kev.json`，`catalogVersion` = `2026.10.29`，`count` = 1764；本文第 13.7 节只用它做"命中/未命中"判定。存档里同时保留了该目录的单条查询版式 `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2023-38606`，用作检索式写法参照）

### 26.5 本文内不来自外部来源的两件东西

第 19 章的 `xpc-ips-triage.sh` 与第 20 章的 `xpc-roster-diff.sh` 是本文为本报告编写的离线文本处理脚本，不引用任何第三方代码库；它们的码位表、命中正则与验收用例全部在第 19.4、20.2、21.2、21.3 节就地给出，读者可直接逐字节比对。两个脚本不访问网络、不写设备、不修改输入文件。

---

*本报告基于截至 2026-10-30 的公开资料（Apple 官方文档、Apple 开源分发源码与手册页、Apple 安全公告、CISA KEV 目录）整理。IPC 机制、公告口径与更新通道持续变化，应以 Apple 官方安全公告与最新文档为准。报告不含任何可用的漏洞利用代码、提权或绕过步骤、端口操纵或注入的操作方法；内嵌的两个脚本均为离线只读文本处理。*

---

咨询ios系统请咨询 telegram：https://t.me/one00190
