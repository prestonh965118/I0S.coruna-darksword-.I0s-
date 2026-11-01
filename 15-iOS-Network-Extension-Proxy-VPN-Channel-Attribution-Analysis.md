---
title: "iOS 网络扩展与代理/VPN 通道归属防御分析报告"
description: "iOS 上一条网络通道到底凭什么存在于这台设备上、此刻是否真的在承载流量、它消失之后谁能证明：十一条通道归属层（权利、装配、形态、生效、范围、内核、告知、观测平面、通道差异、移除与失效、公告回查）的逐层分解，十一通道类 × 22 通道要素的可得性矩阵、三套互不对接的词表与八处直接换算失败、J1—J4 与 Q1—Q4 两套判定模型和两个离线只读核验脚本（信号码 64 + 44，共 108 个全部实跑触发，31 次实跑逐码覆盖表）"
lang: zh-CN
---

# iOS 网络扩展与代理/VPN 通道归属防御分析报告

## 摘要

本报告集前十四篇回答过四类归属问题：**缺陷在哪**（第 01、06、07、12 篇的攻击面归属）、**这台设备归谁**（第 08、10、11 篇的主体归属）、**这条记录能不能作证**（第 13 篇的证据链归属）、**这段代码凭什么被允许运行**（第 14 篇的授权链归属）。本文回答第五类，也是前十四篇里被反复当作背景提到、却从未正面拆解的那一类：**这条网络通道凭什么存在于这台设备上、谁把它装配起来的、此刻它是否真的在承载流量、它消失之后谁能证明。**

这件事在组织里看起来也是一句话——"这台设备在 VPN 里"。在 Apple 的公开文档里，它同样被拆成十一条各自有主语的层：谁给的权利（`com.apple.developer.networking.networkextension` 的取值与申请渠道）、谁写的这一格（MDM 载荷键与声明式类型串）、装成什么形态（提供者类与嵌入位置）、此刻跑没跑（`NEVPNStatus` 与按需规则）、覆盖到谁（路由与例外清单）、内核认不认这条通道（NECP 策略结果与 network agent 注册）、用户看得见什么（状态栏图标面）、这一格是谁读回来的（观测平面）、不同通道到底要不要这一格（可得性）、通道没了之后做了什么（移除与失效）、这个缺陷对应哪个公告（回查）。十一层各有官方口径，而且**没有任何一条官方文档把它们串成一条链**。本文第 3 章给出这三套互不对接的词表和八处直接换算失败，其中五处可以在公开文档之间对出来：

**"设备上有 VPN 配置文件，所以流量走了 VPN"**——《NEVPNStatus》第 14 行对 `invalid` 给的定义是 "The associated VPN configuration doesn’t exist in the Network Extension preferences or isn’t enabled."，也就是说"配置存在"和"配置被启用"塌进同一个状态值里，且这一值既不是"断开"也不是"未装"。而《NEVPNManager》第 15 行的 `isEnabled` 是**另一格**："A Boolean used to toggle the enabled state of the VPN configuration."。台账只登记"有配置"，等于把权利格、装配格、生效格三件事压成一件。同一份口径还规定了失败形态：《Routing your VPN network traffic》第 49 行 "When the VPN transitions away from the connected state, the system drops network traffic."，第 85 行对 Always-On 补了一句 "When the VPN isn’t in a connected state, and while the device starts up before the VPN starts, the system drops network traffic."——**掉线时既不回落也不放行，而是丢包**。把"这台设备受 VPN 保护"写成"这台设备的所有流量都经过了企业网络"，在掉线窗口里既不成立也不被任何一格的读数否认。

**"状态栏没有 VPN 图标，所以这台设备上没有什么通道"**——本轮归档的《Status bar icons》页里，与网络通道相关的只有一条：第 1186 行 "VPN. iPhone is connected to a network using VPN."。第 1183—1187 行相邻的是"个人热点已连接""网络活动""呼叫转移"，其中第 1187 行的网络活动图标官方口径写的是 "Some third-party apps may also use it to show an active process."，也就是说这一格**不是通道归属**。内容过滤器、DNS 代理、透明代理、网络中继这几类通道，在这份图标页里没有任何条目。**图标面只覆盖 VPN 一类，因此"图标不在"只能否证 VPN 图标的显示条件，不能否证通道存在。**

**"MDM 装上了描述文件，所以管理面能回执通道状态"**——《InstallProfileCommand》第 23—24 行给的是命令与"设备处理完安装之后的响应"，《RemoveProfileCommand》第 21—22 行同构；两者回执的都是**描述文件**这一装配件，不是通道。而《Status items》全文 82 行列出的状态项里有账户清单、App 与描述包清单、内容缓存、设备属性、安全证书清单，**没有任何一项回报 VPN、代理、内容过滤器或 DNS 通道**。这条不对称——装配命令有回执、通道状态没有回报项——是第 11 章 L8 层与第 26 章边界清单的核心读数。

**"这条通道挂了哪个公告，公告里会写 NetworkExtension 或 VPN"**——本轮把 Apple 安全公告导出件（392 行 CVE 记录、101 个去重组件名）按词形实测：`vpn`、`proxy`、`tunnel`、`filter`、`relay`、`hotspot` 的组件名命中**全部为 0**；只有 `NetworkExtension` 命中 1 条（CVE-2026-84626，影响句是 "An app may be able to identify what other apps a user has installed"），`Wi-Fi` 命中 6 条、`mDNSResponder` 命中 1 条。CISA KEV 全目录 1766 条记录里 `vpn` 出现 61 次、`proxy` 47 次、`dns` 19 次，但其中 95 条 Apple 产品记录里这些词形（vpn / proxy / tunnel / content filter / relay / dns / hotspot / networkextension）命中全部为 0——**通道词形只出现在非 Apple 产品的记录里**。把通道要素挂到公告平面上，按这份词表是不可归属的——第 22 章的脚本二因此把这一立场做成了全局阻断信号 X04。

**"内核里有这条通道的记录，所以我们能把它登记进归属台账"**——XNU 开源侧确实有：《necp.h》第 240—258 行的 19 个策略结果取值（1—19，含 `USE_NETAGENT` 14、`NETAGENT_SCOPED` 15、`SCOPED_DIRECT` 16、`ALLOW_UNENTITLED` 17；`necp.c` 第 841—861 行的 `resultString` 表把这 19 格连同一个 `"INVALID"` 第 0 格一起列成 20 格），第 671—690 行的七族 agent 绑定参数（PROHIBIT 102 / REQUIRE 112 / PREFER 122 / AVOID 124 / TRIGGER 130 / ASSERT 131 / UNASSERT 132）；《network_agent.h》第 211—218 行的 `struct netagent` 七字段（两个字符串字段长度都是 32，第 144—145 行）与第 153—169 行的 17 个 `NETAGENT_FLAG_*`；《necp.c》第 620 行起的可观测面共 26 个 sysctl 节点，其中 20 个可写、只有 1 个是 ANYBODY 可读。但同一批文件里，读取这些格子的入口被闸门拦住：`necp.c` 第 956 行的 `PRIV_NET_PRIVILEGED_CLIENT_ACCESS`、第 1049、1385、3347、13935 行与 `network_agent.c` 第 2577 行的 `PRIV_NET_PRIVILEGED_NECP_POLICIES`。**内核侧有读数但没有归属主语，管理侧有装配主语但没有读数**——这条双向缺失是第 9 章与第 11 章的核心。

核验部分提供两个纯文本、离线、只读的脚本。**脚本一**把一份"通道归属台账"按 Apple 公开口径审一遍，十二个命名空间（`id. ent. reg. asm. trig. asrt. verd. tok. when. obs. undo. doc.`）逐格回答"这一格写成这样时，这条通道的权利、装配者、形态、生效、范围、内核注册、告知、观测平面、时效、失效处置与引用结论还成不成立"，给出 J1—J4 四档，并对 `sec.*` 命名空间与形似共享密钥、PKCS#12、CSR、描述文件正文、设备绝对路径、内联 base64 的取值直接报警（K01 / K02）。**脚本二**把要素清单、通道能力表与真实公告词表三份纯文本做差集与口径一致性比对，回答"这条通道类到底要不要这一格、这个读数挂的平面给不给得出这一格、台账引用的公告标识与组件名在词表里有没有"，给出 Q1—Q4 四档。信号码共 **108 个**（脚本一 64 个、脚本二 44 个），**全部在本轮环境实跑触发**，第 23 章给出三十一次实跑的逐码覆盖表与退出码。

本文不提供任何可用的漏洞利用代码、提权或绕过步骤，**不含任何搭建 VPN 或代理服务器、接入抓包工具、配置中间人、改写代理或 DNS 指向的做法；不含检测并绕过企业过滤器或强制 VPN 的做法；不含隐藏通道、规避状态告知或伪造通道判定的手段**；不给出针对具体设备、具体组织或具体 VPN 产品的通道判定结论；也不提供任何规避管理面审计的方法。本文给出的只有公开文档口径、通道归属判定、可见性边界、可得性矩阵与只读核验。**全部只写防御与归属判定。**

两个脚本都不联网、不调用任何设备侧或 Apple 命令行工具（不执行 `profiles`、`nectl`、`networkQuality`、`xcrun`、`sysctl`、`route`）、不读取载荷正文或凭据、不修改输入文件；唯一写出目标是 `mktemp -d` 创建的临时目录，退出时由 trap 删除。脚本一拒收密钥与载荷正文不是顺带检查，而是本文的立场：**把共享密钥、IKEv2 客户端证书正文或 VPN 载荷抄进通道台账，等于把一份本来只受密钥链与描述文件规则约束的凭证，变成一份不受任何装配规则约束的副本**——`NETunnelProviderManager` 第 21 行对系统自身的口径已经写明，导入的凭据存放在 `com.apple.managed.vpn.shared` 这个专用 keychain 访问组里，第 22 行还专门禁止扩展写入该组。台账需要登记的是"哪条通道、由谁装配、此刻由哪个平面读回哪一格"，永远不是凭证本身。

---

## 目录

1. [引言](#1-引言)
2. [视角声明与本文边界](#2-视角声明与本文边界)
3. [三套词表：权利与装配口径、状态与执行口径、公告口径，与八处换算失败](#3-三套词表权利与装配口径状态与执行口径公告口径与八处换算失败)
4. [L1 权利层：这条通道凭什么被允许存在](#4-l1-权利层这条通道凭什么被允许存在)
5. [L2 装配层：谁写入这一格](#5-l2-装配层谁写入这一格)
6. [L3 形态层：提供者类与嵌入位置](#6-l3-形态层提供者类与嵌入位置)
7. [L4 生效层：此刻它到底在不在跑](#7-l4-生效层此刻它到底在不在跑)
8. [L5 范围层：影响到谁、例外给谁](#8-l5-范围层影响到谁例外给谁)
9. [L6 内核层：NECP 策略结果与 network agent](#9-l6-内核层necp-策略结果与-network-agent)
10. [L7 告知层：用户看得见哪一格](#10-l7-告知层用户看得见哪一格)
11. [L8 观测平面层：这一格是谁读回来的](#11-l8-观测平面层这一格是谁读回来的)
12. [L9 通道差异层：同一要素在不同通道的可得性](#12-l9-通道差异层同一要素在不同通道的可得性)
13. [L10 移除与失效层：通道消失之后谁能证明](#13-l10-移除与失效层通道消失之后谁能证明)
14. [L11 公告回查层与缺陷类型学 P1—P14](#14-l11-公告回查层与缺陷类型学-p1p14)
15. [归属矩阵：层 × 责任方 × 形态 × 证据](#15-归属矩阵层--责任方--形态--证据)
16. [公开读数：这条通路上能数出来的十八件事](#16-公开读数这条通路上能数出来的十八件事)
17. [可见性边界：这一层读者能拿到什么](#17-可见性边界这一层读者能拿到什么)
18. [四个读数面：权利侧、装配侧、内核侧、告知侧](#18-四个读数面权利侧装配侧内核侧告知侧)
19. [两套判定模型：J1—J4 与 Q1—Q4](#19-两套判定模型j1j4-与-q1q4)
20. [运营指标 O1—O10](#20-运营指标-o1o10)
21. [只读核验脚本一：通道归属台账审查器](#21-只读核验脚本一通道归属台账审查器)
22. [只读核验脚本二：通道要素差集与公告词表比对器](#22-只读核验脚本二通道要素差集与公告词表比对器)
23. [两个脚本的全量分支覆盖验收](#23-两个脚本的全量分支覆盖验收)
24. [十二个误区](#24-十二个误区)
25. [常见问题](#25-常见问题)
26. [未公开文档化边界清单](#26-未公开文档化边界清单)
27. [结论](#27-结论)
28. [参考资料](#28-参考资料)

---
## 1. 引言

### 1.1 "这台设备在 VPN 里"是六句不同的话

在组织口径里，"这台设备挂了我们的 VPN"是一句话。把它拆开，它同时主张六件事，而这六件事各自主语不同、口径不同、失败方式也不同：

**第一件：有一个 App 拿到了实现这类通道的权利。**主语是开发者与 Apple 的审批。《Network Extensions Entitlement》第 4 行给出的是 `com.apple.developer.networking.networkextension`，`type=string`；第 6—17 行给出 12 个取值，其中四个带 `-systemextension` 后缀，官方描述一律带同一个限定："when signed with a Developer ID profile"（第 10—13、16 行）。第 20 行说明 App Store 路径要在 Xcode 里开 Network Extensions capability，第 21—25 行说明 macOS 非商店路径要重新生成描述文件、手工签名并"Update the project’s entitlements.plist to include the com.apple.developer.networking.networkextension key and the values of the entitlement."。这一件事只回答"能不能实现"，不回答"这台设备上有没有"。

**第二件：有人把这条通道写进了这台设备。**主语是装配者。《VPN》页第 8 行给的是载荷类型 `com.apple.vpn.managed`，第 86、92、93 行分别给出 `VPN.AlwaysOn`、`VPN.Proxies`、`VPN.TransparentProxy` 三个字典；《AppLayerVPN》页第 8 行给 `com.apple.vpn.managed.applayer`，第 9 行立刻限定 "This profile defines per-app VPN behavior and applies only to VPN services of type VPN, IPsec, and IKEv2."；《NETunnelProviderManager》第 30 行把 per-app 的装配者钉死在管理面："The only way to configure Per-App VPN is by enrolling the device in a Mobile Device Management (MDM) system…"。这一件事关心的是**谁写入这一格**，不关心它此刻跑不跑。

**第三件：这条通道此刻在承载流量。**主语是运行时状态。《NEVPNStatus》第 9—14 行给六态，第 7 行还规定了一种很容易读错的中间态：断开过程中"the system doesn’t close TCP connections, but ignores packets to and from established network connections"。第 20 行的 `connectedDate` 是"状态变为 connected 的日期与时间"。这一件事与第二件是两格，不能互推。

**第四件：它覆盖到哪些流量、把哪些流量排除在外。**主语是路由与例外。《Routing your VPN network traffic》第 20 行讲默认路由、第 70 行讲 `enforceRoutes` 与 `includeAllNetworks` 互斥、第 37 行讲系统路由表反过来覆盖这两个属性、第 86—89 行讲 Always-On 的 captive portal 与例外清单键。这一件事决定"这台设备受保护"这句话的**范围**，不决定它的真伪。

**第五件：用户看得见它。**主语是告知面。本轮归档的《Status bar icons》页第 1186 行是这份词汇表里唯一一条通道类图标："VPN. iPhone is connected to a network using VPN."。声明式侧另有《NetworkVPNAlwaysOn》第 27 行的 `UIToggleEnabled`。这一件事是**告知**，不是**证明**——第 10 章给出它覆盖不到哪几类通道。

**第六件：有人能证明第三件和第五件。**主语是观测平面与引用。第 11 章说明管理面的状态回报项里没有任何通道格（《Status items》全文 82 行），第 14 章说明公告组件词表里没有任何通道词形（实测命中 0）。**前四件都可以是组织内部自述，第五、六件决定它能不能对外说。**

六件事在管理界面里塌缩成一个开关（"VPN 已配置"），本文的任务是把它们重新拆开，并给出**每一格空白意味着哪一句结论不能写**的判定规则。

### 1.2 为什么通道归属要单独建一套语言

本报告集已有的归属语言不能直接搬用：

- 第 02 篇的**访问控制语言**处理"运行时进程能碰什么"。网络扩展权利在那一篇的 entitlement 清单里只有两行风险分级；本文从"权利已被授权"起步，处理的是这份权利**被谁装配成了一条什么通道**。两篇的接缝在权利取值词表与授权对象到期（本文 L1 与 L10）。
- 第 03 篇的**应用侧攻防语言**处理抓包、代理检测与自有流量审计。本文**不做任何抓包或代理接入**，只处理"通道存在与否、归属谁、能不能被登记并对外表述"。同一个 `HTTP_PROXY`，第 03 篇读的是应用自检怎么判断自己被套进了代理，本文读的是这条代理通道由哪个装配件写入。
- 第 04 篇的**协议与密码学语言**处理 IKEv2 / IPSec / TLS 的算法与凭据语义。本文把 DNS 泄露、split tunneling、kill switch 失效当作**通道失效形态的类型学输入**（第 14 章 P1—P14），主键换成"谁授权、谁装配、谁观测、谁负责"，不重讲协议本身。
- 第 08 篇的**隐私授权语言**处理用途声明与授权状态机。本文只在装配层引用其结论；`per-app` 这个词语面在两篇里同形不同义（第 08 篇是设置页授权列表，本文是 per-app VPN 通道），第 2 章显式分离。
- 第 09 篇的**更新链语言**处理补丁走到哪一台。那一篇已经登记"代理/VPN 阻断 OTA、无回执、读数为 `none`"这一格；本文**反向消费**：更新链是通道的一种消费者，本文写通道侧为什么给不出回执。
- 第 10 篇的**主体语言**处理这台设备归谁、限制项与声明式通道。两篇共用同一批 MDM 存档件，但主键不同：那一篇的对象是设备，本文的对象是通道。一条 `com.apple.vpn.managed` 载荷在两篇里分别被问"这台设备被谁托管"与"这条通道被谁装配"。
- 第 13 篇的**证据链语言**处理记录的产生、留存、送达。本文写通道的可观测面，**不写日志留存时长与采集同意**；两篇都用四档判定，但档位对象不同（第 19 章 19.4 给合读规则）。
- 第 14 篇的**授权链语言**处理描述文件对 entitlement 的白名单授权。本文从"网络扩展权利已被授权"起步，接缝正好在两处：权利取值词表（本文 L1 接第 14 篇 L5）与授权对象到期使通道失效（本文 L10 接第 14 篇 L6/L7）。

通道归属要补的缺失一段是：**一条网络通道从被授权、被装配、被执行到被移除之间，有多少个必须登记的读数，以及每一个读数缺失时哪句话不能写。**所以本文另建一套词表，并在第 2 章把与第 02、03、04、08、09、10、13、14 篇的分工线画清楚。

### 1.3 一条被普遍接受、但在文档里没有依据的表述

行业里最常见的通道表述是："员工设备都强制走我们的企业 VPN，所有内网访问都在受控通道里，未连接的设备会被阻断。"这句话在本文的框架里有六处需要台账支撑，任何一处空白都会让它降级：

- "强制走"的装配者是谁？《NETunnelProviderManager》第 30—33 行把 per-app 通道的装配钉死在 MDM（`com.apple.vpn.managed.applayer` + `VPNUUID` + `ProviderType`），第 17 行还给出优先级口径："Only one enterprise VPN configuration can be enabled on the system at a time… the enterprise VPN takes precedence"。这一句能不能写，取决于台账里 `asm.actor` 与 `asm.payload_type` 两格。
- "都走了"是哪一种走法？Always-On 与按需连接是两种触发方式（《Routing your VPN network traffic》第 5 行 "You can configure the routing of packets to per-app VPNs using rules, and make exceptions to always-on VPNs on MDM supervised devices."），覆盖范围与例外清单也不同（第 86—89 行）。
- "所有流量"这一格谁给读数？内核侧的策略结果里有 `SCOPED_DIRECT` 16（《necp.h》第 255 行注释 "N/A, scopes to primary physical interface"）与 `ALLOW_UNENTITLED` 17（第 256 行），它们描述的是**未走通道的流量为什么没走**；用户态文档里对应的是 `excludedRoutes` 与 `excludeLocalNetworks`（第 57、70 行）。两平面口径不互证。
- "受控"由哪个平面证明？第 11 章说明管理面没有通道状态回报项；第 9 章说明内核 sysctl 面的 26 个节点里只有 1 个 ANYBODY 可读。也就是说"受控"在公开口径里**没有一条现成的回读通道**，只能由组织自己的日志侧登记。
- "未连接就被阻断"是设备行为还是组织结论？《Routing your VPN network traffic》第 49、85 行给的官方行为是"the system drops network traffic"，也就是丢包而不是回落到直连——这一句支持"阻断"的说法，但它的主语是**系统对流量做了什么**，不是"设备被隔离在组织之外"；把两者混写属于口径越界。
- 这台设备上的通道是哪一次装配留下的？第 13 章：移除动作有回执对象（《RemoveProfileCommand》第 21—22 行），通道本身没有；`NEVPNManager` 第 13 行的 `removeFromPreferences(completionHandler:)` 是设备侧 API 动作，管理面读不回"这一条已经不在了"。

这六处空白不会让这句话变成假话，它让它变成**一句无法核对的话**。本文全部核验工作就是给出这六处的登记格式与判定档位。

---
## 2. 视角声明与本文边界

### 2.1 本文视角

本文站在**防御侧通道治理**（channel governance）视角：一个已经在用（或正在考虑用）网络扩展、MDM 通道载荷或声明式通道配置的组织，如何判断手里这份通道记录能不能支撑一句对外结论——"这条通道是我们装配的、到此刻为止在承载流量、覆盖这些范围、用户看得见、拆掉之后我们知道"。它不是 VPN 部署手册，不是 MDM 运维 SOP，不是网络准入方案选型建议，也不是对任何具体供应商产品的评价。

主键与相邻篇目不同：**一条网络通道的授权与可得性**——这条通道凭什么存在于这台设备上、此刻是否真的在承载流量、它消失之后谁能证明。

### 2.2 与前十四篇的分工

| 相邻篇目 | 它处理什么 | 本文处理什么 | 分界句 |
| --- | --- | --- | --- |
| 第 02 篇 访问控制 | entitlement 清单与运行时能碰什么 | 权利被装配成通道之后的装配者、生效判定与可见性 | 02 管"有没有这项权利"，本文管"这项权利被谁装配成了一条什么通道" |
| 第 03 篇 应用防护与抓包审计 | 抓包、代理检测与自有流量审计 | 通道存在与否能不能被组织侧登记并对外表述 | 本文**不写任何抓包或代理接入操作**，只写结论能不能被登记 |
| 第 04 篇 传输与协议安全 | IKEv2 / IPSec / TLS 的密码学语义 | 通道失效形态的类型学与归属层 | DNS 泄露、split tunneling、kill switch 失效在本文是**失效形态输入**，不重讲协议 |
| 第 08 篇 隐私授权 | 用途声明与授权状态机 | per-app 通道装配（与设置页 per-app 授权列表同形不同义） | 本文不审清单内容、不写权限弹窗 |
| 第 09 篇 更新链 | 补丁走到哪一台 | 通道侧为什么给不出回执 | 更新链是通道的一种消费者；本文反向消费其结论 |
| 第 10 篇 设备归属 | MDM 限制项、声明式通道与设备主权 | 通道载荷的装配与移除 | 共用同一批 MDM 存档件，主键不同：设备 vs 通道 |
| 第 13 篇 证据链 | 记录的产生、留存、送达 | 通道的可观测面 | 本文不写日志留存时长与采集同意；两篇都用四档但对象不同 |
| 第 14 篇 授权链 | 描述文件对 entitlement 的白名单授权 | 权利已被授权之后的通道装配与归属 | 接缝在 L1（权利取值词表）与 L10（授权对象到期使通道失效） |

`kill switch`、`Always-On`、`状态栏`、`per-app` 这四个词在本报告集里已经出现过，本文与它们的差别是视角而不是内容：第 03 篇里的 `SSL Kill Switch 2` 是越狱插件名，本文不写插件；第 04 篇里"断开时未阻止流量"是一条结论，本文只问这条结论能不能被登记（第 7、8 章）；第 02 篇的"蓝色指示器"属于越狱检测示意图，本文的告知面是官方支持文档口径（第 10 章）；第 08 篇的 `per-app` 是设置页授权列表，本文的 per-app 是 VPN 通道装配（第 5、8 章）。

### 2.3 明确不做的事

- 不提供搭建 VPN 或代理服务器、接入抓包工具、配置中间人、改写代理或 DNS 指向的任何操作步骤。本文全部网络通道话题都在**已经存在的通道**上做归属判定。
- 不写"检测并绕过企业过滤器 / 强制 VPN"的做法，不写如何隐藏通道、规避状态告知或伪造通道判定，不写如何规避管理面审计。第 10 章只写告知面**覆盖什么、不承诺什么**。
- 不写第三方 VPN 客户端的产品评测与选型建议；台账样例全部为合成值，第 21、22 章开头逐条声明。唯一非合成输入是第 22 章的公告词表导出件，它只用于词汇比对，不含任何通道结论。
- 不写协议密码学本身：IKEv2 / IPSec / TransparentProxy 的算法强度、证书与凭据语义归第 04 篇；本文只在 L10 引用"授权对象到期会让通道失效"这一结论。
- 不写抓包与自有流量审计（归第 03 篇），不写隐私用途声明的申报审查（归第 08 篇），不写设备归属与所有权移交（归第 10 篇），不写日志留存与同意（归第 13 篇），不写签名与描述文件的签发链（归第 14 篇）。
- 不给出任何具体设备、具体组织、具体网络环境的通道判定结论。本文的 J1—J4 与 Q1—Q4 是**文档口径下的可核对性档位**，不是"这台设备安全 / 不安全"的判断。

---

## 3. 三套词表：权利与装配口径、状态与执行口径、公告口径，与八处换算失败

本文用到的官方词汇分属三套互不对接的口径。三套都有独立文档来源，都没有给出跨套映射；第 21、22 章两个脚本里全部"取值域"就按这三套分别登记。

### 3.1 第一套：权利与装配口径（"这条通道凭什么存在"）

**权利取值**——《Network Extensions Entitlement》第 4 行给出键名与 `type=string`，第 6—17 行给出 12 个取值：

| 取值 | 官方描述要点 | 归档行号 |
| --- | --- | --- |
| `dns-proxy` | 代理 DNS 查询的 API | 第 6 行 |
| `app-proxy-provider` | 代理 TCP 与 UDP 连接的 API | 第 7 行 |
| `content-filter-provider` | 允许或 deny 由系统上其他 App 创建的网络连接的过滤 API | 第 8 行 |
| `packet-tunnel-provider` | 用任意自定义隧道协议把 IP 包隧道到远端网络 | 第 9 行 |
| `dns-proxy-systemextension` | 同上，"when signed with a Developer ID profile" | 第 10 行 |
| `app-proxy-provider-systemextension` | 同上 | 第 11 行 |
| `content-filter-provider-systemextension` | 同上 | 第 12 行 |
| `packet-tunnel-provider-systemextension` | 同上 | 第 13 行 |
| `dns-settings` | 创建与管理系统级 DNS 配置 | 第 14 行 |
| `app-push-provider` | 在无法访问更宽互联网时提供类似 APNs 的能力 | 第 15 行 |
| `relay` | 中继 TCP/UDP 连接，"when signed with a Developer ID profile" | 第 16 行 |
| `url-filter-provider` | 创建与管理 URL 过滤器 | 第 17 行 |

《Personal VPN Entitlement》页另有一条独立权利：第 4 行 `com.apple.developer.networking.vpn.api`，第 6 行取值 `allow-vpn`，第 9—10 行说明启用 Personal VPN capability 后由 Xcode 写入该值。也就是说**权利侧本身就是两个键**，不是"网络扩展"一键搞定。

**装配口径**——MDM 载荷类型与声明式类型串两套并存：

| 口径 | 取值 | 归档行号 |
| --- | --- | --- |
| 描述文件载荷 | `com.apple.vpn.managed` | mdm-vpn 第 8 行 |
| 描述文件载荷 | `com.apple.vpn.managed.applayer` | mdm-applayervpn 第 8 行 |
| 描述文件载荷 | `com.apple.vpn.managed.appmapping` | mdm-apptoapplayervpnmapping 第 8 行 |
| 描述文件载荷 | `com.apple.webcontent-filter` | mdm-webcontentfilter 第 8 行 |
| 声明式类型 | `com.apple.configuration.network.vpn.always-on` | dd-networkvpnalwayson 第 8 行 |
| 声明式类型 | `com.apple.configuration.network.dns-proxy` / `.dns-settings` / `.relay` / `webcontent-filter.plugin` | dd-networkdnsproxy / dd-networkdnssettings / dd-networkrelay / dd-webcontentfilterplugin 第 8 行 |
| 字段级 | `ProviderType` = `packet-tunnel` / `app-proxy` | netunnelprovidermanager 第 32 行 |
| 字段级 | `VPNUUID`（MDM 服务器定义、App 属性字典同值） | netunnelprovidermanager 第 31、33 行 |

### 3.2 第二套：状态与执行口径（"这条通道此刻在做什么"）

| 子口径 | 取值集 | 归档行号 |
| --- | --- | --- |
| 连接状态 | `invalid` `disconnected` `connecting` `connected` `reasserting` `disconnecting` | nevpnstatus 第 9—14 行（共 6 个） |
| 按需规则 | `NEOnDemandRuleConnect` / `Disconnect` / `EvaluateConnection` / `Ignore` | neondemandrule 第 20—23 行 |
| 提供者判定 | `NEFilterNewFlowVerdict` / `NEFilterDataVerdict` / `NEFilterControlVerdict` / `NEFilterRemediationVerdict` / `NEFilterVerdict` | content-filter-providers 第 24—28 行 |
| 数据判定动作 | `allow()` / `drop()` / `pause()` / `remediateVerdict(withRemediationURLMapKey:remediationButtonTextMapKey:)` / `needRules()` / `init(passBytes:peekBytes:)` | nefilterdataverdict 第 9—14 行 |
| 内核策略结果 | 19 个取值（`PASS` 1 … `REMOVE_NETAGENT_TYPE` 19；结果名表另有一格 `INVALID` 排在第 0 位） | necp.h 第 240—258 行；结果名表 necp.c 第 841—861 行 |
| 内核 agent 绑定 | PROHIBIT 102 / REQUIRE 112 / PREFER 122 / AVOID 124 / TRIGGER 130 / ASSERT 131 / UNASSERT 132 | necp.h 第 671—690 行 |
| 内核 agent 标志 | `NETAGENT_FLAG_REGISTERED` 0x0001 … `NETAGENT_FLAG_SUPPORTS_GROUPS` 0x20000（17 个） | network_agent.h 第 153—169 行 |
| 内核 agent 消息 | 22 个 `NETAGENT_MESSAGETYPE_*`（REGISTER 1 … CLIENT_ERROR 26） | network_agent.h，读数见第 16 章 |

### 3.3 第三套：公告口径（"这个缺陷对外怎么说"）

本轮归档的 Apple 安全公告导出件（CSAF 形态，列为 file / cve / component / impact / description / available）共 392 行记录、101 个去重组件名。与网络相关的组件名只有 `NetworkExtension`（1 条）、`Network`、`Wi-Fi`、`mDNSResponder`、`Thread`、`Bluetooth`。第 16 章给出逐词命中数；关键读数是 **`vpn`、`proxy`、`tunnel`、`filter`、`relay`、`hotspot` 六个词形的组件名命中全部为 0**。

### 3.4 八处换算失败

| 编号 | 从哪套到哪套 | 为什么换算不了 | 公开依据 |
| --- | --- | --- | --- |
| F1 | 权利取值 → 装配字段 | `packet-tunnel-provider` 是 entitlement 取值，`ProviderType` 的 `packet-tunnel` 是载荷字段值，两份字符串表不是同一份 | networkextension 第 9 行 vs netunnelprovidermanager 第 32 行 |
| F2 | 载荷类型 → 声明式类型 | 一个 `com.apple.vpn.managed` 载荷在声明式侧被拆成 always-on / ikev2 / ipsec / vpn-plugin 四条类型串，且可用性轴不同（always-on 只到 iOS / Shared iPad / visionOS，其余三条含 macOS，ikev2 与 vpn-plugin 另含 tvOS） | mdm-vpn 第 8 行 vs dd-networkvpnalwayson 第 8、12 行、dd-networkvpnikev2 第 12 行 |
| F3 | 声明式回执 → 运行时状态 | 《Declarative Management》页第 10 行只说明这条命令"turn on the declarative management engine on the device the first time the server sends it. Subsequent commands trigger a declarative management synchronization operation."，第 21—22 行只给命令与响应两个对象；回执语义里没有任何通道状态格，而 `NEVPNStatus` 六态在设备侧运行时 | declarative-management-command 第 10、21—22 行 vs nevpnstatus 第 9—14 行 |
| F4 | 六态 → 十九个内核结果 | `invalid` 一格同时表示"配置不存在"与"未启用"；内核侧对应的是策略结果与 agent 注册状态两套词汇，没有映射表 | nevpnstatus 第 14 行 vs necp.h 第 240—258 行 |
| F5 | 按需规则 → 内核触发 | 用户态 `NEOnDemandRuleConnect` 与内核 `NECP_POLICY_RESULT_TRIGGER*`（第 247—249 行三条全部注释为 Deprecated）不是同一层，且 per-app 场景里只有一种规则会被使用 | neondemandrule 第 20 行 vs necp.h 第 247—249 行、netunnelprovidermanager 第 39 行 |
| F6 | 提供者判定 → 内核判定 | 过滤器返回的是 verdict 对象（allow / drop / pause / remediation / needRules），内核侧是策略结果与 drop 级别 sysctl；"这一条流量由谁决定"没有跨层回读 | nefilterdataverdict 第 9—14 行 vs necp.c 第 627—629 行 |
| F7 | 通道类 → 公告组件名 | 公告组件词表里的网络词汇是产品功能名（NetworkExtension、Wi-Fi、mDNSResponder），不是通道类；六个通道词形命中 0 | C/advisory-entries.tsv 组件列读数，见第 16 章读数 1—6 |
| F8 | 告知面 → 归属结论 | 图标面只登记 VPN 一条，且相邻的"网络活动"图标官方口径允许第三方 App 复用；图标缺席/出现都不能推出通道归属 | status-icons 第 1186 行、第 1187 行 |

八处失败里有五处（F1、F2、F4、F6、F7）可以在两份公开文档之间直接对出来，另外三处（F3、F5、F8）是**公开文档根本没有给出那一格**。第 21、22 章两个脚本把这两种情况分开登记：前者落"口径混用"信号（V 族），后者落"未登记/未文档化"信号（D 族与 Q3、Q4 档）。

---
## 4. L1 权利层：这条通道凭什么被允许存在

### 4.1 官方口径

权利层回答的不是"谁能用网络"，而是"哪个 App 被允许实现哪一类通道"。公开口径由三个键与一份取值表构成：

- `com.apple.developer.networking.networkextension`（《Network Extensions Entitlement》第 4 行，`ideTitle=Network Extensions`，`type=string`），第 6—17 行 12 个取值（第 3.1 节表格）。
- `com.apple.developer.networking.vpn.api`（《Personal VPN Entitlement》第 4 行，`ideTitle=Personal VPN`），第 6 行唯一取值 `allow-vpn`；第 9 行 "With the Personal VPN Entitlement enabled, your app can use the NEVPNManager class to manage a Personal VPN configuration."
- 类级强制：《NEAppProxyProvider》第 10 行、《NEPacketTunnelProvider》第 17 行、《NETunnelProviderManager》第 13 行都以 important 提示开头，写明该类**必须**有 networkextension 权利；《NEDNSProxyProvider》第 11 行、《NEFilterDataProvider》第 13 行、《NEFilterManager》第 10 行、《NEFilterProvider》第 14 行的口径是"you must enable the Network Extensions capability in Xcode and select the … capability"。

授予路径在同一页里分成两条：第 20 行是 App Store 路径（"enable the Network Extensions capability in Xcode"），第 21—25 行是 macOS 非商店路径——第 22 行要求在开发者站点为 "Developer ID–signed app" 开启 capability 并重新生成描述文件，第 25 行要求把键与取值写进 `entitlements.plist`。带 `-systemextension` 后缀的四个取值（第 10—13 行）与 `relay`（第 16 行）的官方描述一律带 "when signed with a Developer ID profile"。

### 4.2 这一层的台账格

脚本一用 `ent.*` 命名空间登记本层，四格：

| 字段 | 取值域来源 | 缺失后果 |
| --- | --- | --- |
| `ent.name` | networkextension 第 6—17 行的 12 个取值 + `personal-vpn`（第 3.1 节） | 通道凭什么存在没有依据（A01） |
| `ent.granted_via` | `xcode_capability` / `developer_id_profile` / `provisioning_profile` / `built_in_profile`（第 20、22、25 行三条路径） | 权利名与扩展点无法对齐（A05） |
| `ent.system_variant` | 是否登记 `-systemextension` 变体（第 10—13、16 行） | 变体权利与 `app_extension` 扩展点冲突（A03） |
| `ent.provider_gate` | 类级强制（各提供者页的 important 提示） | 提供者类与权利不配对（A02） |

### 4.3 失败形态

**形态一：权利名与通道类各写一半。**`packet-tunnel-provider` 与 `content_filter` 都是公开词表里的合法串，但配对关系不在任何词表里（A02 阻断）。这一形态在真实台账里最常见，因为"我们有网络扩展权利"通常只在 entitlement 清单里登记，从不与"这台设备上跑的是哪一类通道"对齐。

**形态二：把变体权利当同一条权利。**第 10—13 行的四个 `-systemextension` 取值描述的是同一能力族在 Developer ID 签名下的形态，第 22 行的启用步骤与第 20 行的 App Store 步骤不是同一条路径。登记了变体权利却把扩展点记为 `app_extension`，等于声称一条不需要 Developer ID 的通道拥有只有 Developer ID 才给的权利（A03 阻断）。

**形态三：用权利证明存在。**权利格回答"能不能实现"，不回答"这台设备上有没有"。《Network Extension》页第 12 行的平台限定语在这里反过来起作用："The NetworkExtension framework is available in macOS, iOS, tvOS, and visionOS, but not all features are available on all platforms and some features have specific restrictions (for example, some features only work on supervised iOS devices)."——**同一份权利在不同平台与监督状态下能装配出的通道不同**，所以权利格无法回推装配格与生效格（第 5、7 章）。

### 4.4 这一层能支撑与不能支撑的结论

能支撑："这个开发者/这个 App 被允许实现 X 类通道，授予路径是 Y。"不能支撑："这台设备上有 X 类通道"（要 L2 装配格）、"这条通道正在承载流量"（要 L4 生效格）、"这条通道是组织装配的"（要 `asm.actor`）。

内核侧的权利口径是**另一套名字**，并且直接决定"谁能读这些格子"：《necp.c》第 7650—7651 行的判据是 `IOTaskHasEntitlement(task, "com.apple.private.necp.match")` 与 `com.apple.developer.CaptiveNetworkPlugin` 二者之一；第 1026 行对 `drop_all_bypass` 单独设闸。本轮在归档的网络源码里点名的私有权利共 6 个（`com.apple.private.necp.match`、`com.apple.private.necp.drop_all_bypass`、`com.apple.developer.CaptiveNetworkPlugin`、`com.apple.developer.networking.multicast`、`com.apple.developer.on-demand-install-capable`、`com.apple.private.network.aop2_offload`，读数见第 16 章读数 12）。**这些名字不在开发者文档的公开 entitlement 表里**，因此 L1 层的权利台账与内核侧闸门是两个平面，不能互相补格（脚本二的 P01 专门拦"把权利类要素记为内核调试面可读回"）。

---

## 5. L2 装配层：谁写入这一格

### 5.1 官方口径

装配层的公开口径分散在三处，且彼此不用同一串名字：

**描述文件载荷侧。**《VPN》页第 8 行 `com.apple.vpn.managed`，第 85—96 行的对象清单里有 `VPN.AlwaysOn`（第 86 行）、`VPN.Proxies`（第 92 行）、`VPN.TransparentProxy`（第 93 行）、`VPN.VendorConfig`；《AppLayerVPN》页第 8 行 `com.apple.vpn.managed.applayer`，第 9 行限定 "applies only to VPN services of type VPN, IPsec, and IKEv2. All the properties of VPN apply to the top level of this profile as well."；《AppToAppLayerVPNMapping》页第 8 行 `com.apple.vpn.managed.appmapping`，第 89、92 行的样例里出现 `AppLayerVPNMapping` 与 `VPNUUID` 两把键，第 125 行给出映射项对象；《WebContentFilter》页第 8 行 `com.apple.webcontent-filter`，样例里第 31 行 `AutoFilterEnabled`、第 41 行 `FilterType`（取值样例为 `BuiltIn`）、第 33—40 行 `DenylistURLs` / `FilterBrowsers` / `FilterSockets` / `PermittedURLs`；《Relay》页第 8 行 `com.apple.relay.managed`。《Profile-specific payload keys》第 83、87、105—107、143—145、148 行把 `DNSSettings`、`Relay`、`DNSProxy`、`GlobalHTTPProxy`、`NetworkProxyConfiguration`、`AppLayerVPN`、`AppToAppLayerVPNMapping`、`VPN`、`WebContentFilter` 列在同一条载荷清单里——**同一份清单里既有系统内置代理，也有网络扩展提供者通道，两者在文档层面是并列的两行。**

**声明式侧。**八条类型串，每条自带一张可用性表（第 12—18 行同构）：`network.vpn.always-on`（dd-networkvpnalwayson 第 8 行）、`.ikev2` / `.ipsec` / `.vpn-plugin`（各自第 8 行）、`network.dns-proxy`、`network.dns-settings`、`network.relay`、`webcontent-filter.plugin`（各自第 8 行）。always-on 那条的载荷样例给出四格语义：第 26 行 `VisibleName`、第 27 行 `UIToggleEnabled`（样例值 `false`）、第 28 行 `TunnelConfigurations` 数组、第 30 行 `ProtocolType": "IKEv2"` 与第 31—33 行的 `Interfaces": ["Cellular", "WiFi"]`。

**per-app 装配链。**《NETunnelProviderManager》第 30—35 行给出唯一路径，逐格指定主语：第 30 行只能经 MDM 注册；第 31 行 "The MDM server creates a configuration profile containing a com.apple.vpn.managed.applayer payload… also must contain a VPNUUID field, containing a unique string defined by the MDM server."；第 32 行按扩展类型写 `ProviderType` 为 `packet-tunnel` 或 `app-proxy`；第 33 行要求把同一个 `VPNUUID` 写进每个受管 App 的属性字典；第 35 行 "The MDM client running on the device creates one app rule in the VPN configuration for each managed app that is linked to the VPN configuration via the VPNUUID app attribute."——**这条链上每一格的写入者都不同**（MDM 服务器、MDM 客户端、扩展自身），是 L2 层归属分析的核心。

### 5.2 这一层的台账格

`asm.*` 七格：`actor`（`user_manual` / `mdm_command` / `mdm_declaration` / `dep_profile` / `enterprise_app` / `app_self` / `extension_self_config`）、`payload_type`（第 3.1 节 15 条串）、`scope`（device / user / supervised_only / system_scope / local_install）、`install_receipt`、`user_consent`、`enabled_toggle`、`supervised`。

可用性轴不是装饰，而是判定输入：同一类载荷在不同装配口径下的可用性差别很大——`com.apple.vpn.managed` 第 12 行设备通道含 iOS / macOS / Shared iPad / tvOS / visionOS、第 15 行 `Requires supervision | N/A`；`com.apple.vpn.managed.applayer` 第 13 行设备通道含 watchOS、第 16 行 `Requires supervision | watchOS`；`com.apple.vpn.managed.appmapping` 第 12 行在本轮归档件里只列 macOS；声明式 always-on 第 12—18 行里第 14 行是 `Allowed in user enrollment | N/A`、第 18 行是 `Apply | Only a single configuration is applied`，而 `network.dns-proxy` / `.relay` / `webcontent-filter.plugin` 第 12 行与 `network.dns-settings` 第 16 行的 supervised 清单里含 macOS。

### 5.3 失败形态

**形态一：装配者一格写"MDM"，但这一格其实由用户点确认。**声明式与描述文件两条路径下"谁写入"不同（B01 阻断）；`Always-On` 的启用条件在公开口径里是"installing an always-on VPN profile on an MDM-supervised device"（《Routing your VPN network traffic》第 84 行），因此把它记成用户自装属于口径冲突。

**形态二：把装配件的回执当成通道的回执。**《InstallProfileCommand》第 23—24 行与《RemoveProfileCommand》第 21—22 行给出的是命令与"设备处理完该命令之后的响应"，回执对象是描述文件；《Declarative Management》页第 10 行说明命令只负责开启引擎或触发一次同步，第 21—22 行只给命令与响应两个对象。两条都没有"通道此刻状态"这一格，因此脚本一把 `asm.install_receipt` 与 `when.status` 分成两个命名空间，且当回执被记成 `not_returned` / `not_polled` 时进入 Q3 而不是 Q1（B04、B06）。

**形态三：把 `enabled_toggle` 当成装配成功。**《NEVPNManager》第 15 行的 `isEnabled` 与《NERelayManager》第 14 行的 `isEnabled` 都是**开关格**，《NetworkVPNAlwaysOn》第 27 行的 `UIToggleEnabled` 是**是否允许用户看见开关**。第 7 章说明开关与 `NEVPNStatus` 是两格：开关为 true 不等于已连接，UI 不可见也不等于未装配（B07）。

### 5.4 与第 14 篇的接缝

本章只登记"谁写入这一格"，不登记"这个装配件凭什么被允许写入设备"——后者（描述文件的签名、白名单与到期）归第 14 篇 L5/L6。本文只在 L10 引用一个结论：**授权对象失效会让通道失去装配依据**，因此 `undo.revoke_basis` 允许取 `receipt` / `removal_command` / `provider_log` / `assumed` / `icon_absent`，而后两者不能作为对外结论的依据（V03）。

---

## 6. L3 形态层：提供者类与嵌入位置

### 6.1 官方口径

形态层登记的是"这条通道由哪一类提供者实现、以什么形态嵌在设备上"。《Network Extension》页第 8、9、10、11 行先给出框架支持的六类扩展动作（Wi-Fi 配置、热点助手、VPN 配置、网络中继、端侧内容过滤、系统级 DNS），第 17—19 行把 VPN 三分为 Personal VPN（内置协议 IPsec 或 IKEv2）、Packet tunnel provider（面向包的自定义协议）、App proxy provider（面向流的自定义协议）。

类级文档给出的形态差异点：

| 提供者类 | 关键形态事实（归档行号） |
| --- | --- |
| `NETunnelProviderManager` | 第 17 行：属企业 VPN，"Only one enterprise VPN configuration can be enabled on the system at a time… the enterprise VPN takes precedence"；第 21 行：导入凭据存放在 keychain 专用访问组 `com.apple.managed.vpn.shared`；第 22 行：App 与扩展**不得写入**该组 |
| `NEFilterProvider` | 第 7 行：内容过滤由 Data Provider 与 Control Provider **两个扩展**组成；第 9 行说明 Data Provider 因能接触全部流量而运行在极严格沙箱里，"blocking all network access, IPC, and disk write operations"；第 16 行：不应直接子类化 `NEFilterProvider` |
| `NETransparentProxyManager` | 第 12 行：继承自 `NEVPNManager`；配套对象是 `NETransparentProxyProvider`、`NETransparentProxyNetworkSettings`、`NENetworkRule`（第 8—10 行） |
| `NERelayManager` | 第 9—12 行：`shared()` / `loadFromPreferences` / `saveToPreferences` / `removeFromPreferences` 四动作；第 15 行：多中继时"application traffic routes through both of them in the order they appear in the array" |
| `NEProvider` | 生命周期入口与 `startSystemExtensionMode()`——"Starts the Network Extension machinery from inside a System Extension."（第 23 行） |
| `NEAppExtensionConfiguration` | 第 7 行：只为框架自身使用；第 11—13 行的被继承清单只有三项：热点认证提供者、热点评估提供者、URL Filter 控制提供者 |

`NEAppExtensionConfiguration` 这一页在归属分析里有一个特殊用途：它是本轮归档里**唯一一份直接列出"哪些通道类以 app extension 形态存在"的公开件**——第 11—13 行点名的三类（Hotspot 认证、Hotspot 评估、URL Filter 控制）之外，其余提供者类走的是 `startSystemExtensionMode()`（系统扩展）或随 App 嵌入。脚本一据此检查 `id.extension_point` 与 `ent.system_variant` 是否互相矛盾（A03）。

### 6.2 这一层的台账格

`id.*` 六格：`channel_type`（11 类 + `none` / `not_recorded` / `unknown`）、`provider_bundle_id`（反向域名形态，A04 检查）、`extension_point`（`app_extension` / `system_extension` / `mdm_installed` / `built_in`）、`agent_uuid`（内核侧标识，必须是 UUID 形态，A06）、`team_id`（10 位，A09）、`config_identifier`。

### 6.3 失败形态

**形态一：一条对象登记两个通道类。**一条通道只有一个提供者类，脚本二把这条做成 D06 阻断（依据是 `NEAppExtensionConfiguration` 第 11—13 行的被继承关系与各类页的唯一继承链）。真实台账里这一形态来自"同一 bundle id 既实现 App Proxy 又实现 Content Filter"这类扩展集合，此时应拆成两个通道对象。

**形态二：形态串与内核类型串混记。**内核侧的通道形态标识是 `struct netagent` 里的两个字符串字段——《network_agent.h》第 213—215 行的 `netagent_domain[NETAGENT_DOMAINSIZE]`、`netagent_type[NETAGENT_TYPESIZE]`、`netagent_desc[NETAGENT_DESCSIZE]`（`struct netagent` 本身起于第 211 行），两个 SIZE 宏都是 32（第 144—145 行）。用户态的类名（`NEPacketTunnelProvider` 等）与这里的 domain/type 串不是同一份词表，跨平面登记时必须标明词表归属（脚本二的 `vocab` 列，V01/V03）。

**形态三：把"内置"当成"不可归属"。**`built_in_vpn`（Personal VPN，内置 IKEv2/IPSec）这一类没有 provider 扩展，因而没有扩展点格；但它的权利格（`allow-vpn`）与装配格（`com.apple.vpn.managed`）都存在。台账把整条通道记为 `not_applicable` 会把两类不同的空白压成同一个（D03 的第二形态）。

---

## 7. L4 生效层：此刻它到底在不在跑

### 7.1 官方口径

《NEVPNStatus》页给出六态（第 9—14 行）与一条中间态行为：

> 第 7 行："After the VPN transitions from the NEVPNStatus.disconnected to the NEVPNStatus.disconnecting state, the system doesn’t close TCP connections, but ignores packets to and from established network connections."

第 14 行对 `invalid` 的定义是本篇最重要的口径之一：

> "The associated VPN configuration doesn’t exist in the Network Extension preferences or isn’t enabled."

也就是说**"配置不存在"与"配置未启用"共用一个状态值**。第 20 行给出 `connectedDate`——"The date and time when the connection status changed to NEVPNStatusConnected."，这是本篇唯一一处公开定义的、带时间戳的连接读数。

与开关的关系在《NEVPNManager》第 15 行（`isEnabled`）与第 11、13 行（`saveToPreferences` / `removeFromPreferences`）。触发方式在按需场景下由 `isOnDemandEnabled` 决定（《Routing your VPN network traffic》第 80 行："If you enable the on-demand feature (set the isOnDemandEnabled property to true) and provide a disconnect app rule, the system bypasses the per-app VPN for devices on the network that match the on-demand rule criteria."）。

失败形态的官方口径同样明确，而且方向与直觉相反——掉线不回落而是丢包：

> 《Routing your VPN network traffic》第 49 行："When the VPN transitions away from the connected state, the system drops network traffic. For example, the system drops the network traffic when a device transitions from a Wi-Fi network to a cellular network, and while the VPN is in the process of reconnecting to the VPN server over the cellular network."
> 第 85 行（Always-On）："When the VPN isn’t in a connected state, and while the device starts up before the VPN starts, the system drops network traffic."

《NETunnelProviderManager》第 17 行还给出两条通道并存时的生效关系：Personal VPN 与企业 VPN 同时活动时常驻连接，但路由冲突时企业优先。

### 7.2 这一层的台账格

`when.*` 七格：`status`（六态 + `not_applicable` / `not_recorded` / `unknown`）、`status_at`、`connected_date`、`audit_at`、`config_expiry`、`teardown_at`、`time_source`（`device_clock` / `server_log` / `provider_log` / `management_server`）。

`trig.*` 三格给出"为什么此刻是这个状态"：`mode`（`on_demand` / `always_on` / `manual` / `auto_connect`）、`rule_action`（四规则类之一）、`interface`（wifi / cellular / both / any）。

### 7.3 失败形态

**形态一：只登记"有配置"。**`isEnabled=true` 与 `status=connected` 是两格，`invalid` 又同时压了两种含义（T01 阻断）。台账必须同时有 `enabled_toggle`（L2）与 `vpn_status`（L4），否则"这台设备在通道里"这句话既不能被连接证实也不能被断开否证。

**形态二：拿管理面时间当设备时间。**`connectedDate` 的定义只说明"状态变化时间"，其时基来自设备（T02、T03）。当 `when.time_source=management_server` 而 `status_at` 取自设备读数时，两个时间戳的差不是通道延迟而是时基未对齐（T03 记录，不阻断但落 Q3）。

**形态三：把按需规则当成生效证据。**《NEOnDemandRule》第 8 行规定规则实例只能通过四个子类创建，第 20—23 行给出四种动作；《NETunnelProviderManager》第 38—39 行说明 per-app 场景下应用规则同时充当路由规则与按需规则，且**只有 `NEOnDemandRuleDisconnect` 会被使用**：

> 第 39 行："It is possible to set regular VPN On Demand rules in a Per-App VPN configuration via the onDemandRules property, but only NEOnDemandRuleDisconnect rules will be used."

这条口径决定了 L5 层的"为什么这个 App 没走 VPN"在 per-app 通道里只能由 Disconnect 规则解释（C01、C02）。把 Connect 规则登记为 per-app 通道的生效依据属于取值域错误。

**形态四：用掉线证明保护。**第 49、85 行的丢包语义支持"未连接时不回落到直连"，但它同时意味着：**"未连接"这一状态在设备侧是可观测的（丢包），在管理侧是不可观测的（没有回报项）**。台账若只登记管理侧，就会把"没有读数"写成"没有发生"（第 11 章 L8 层，P04）。

### 7.4 这一层能支撑与不能支撑的结论

能支撑："在 T 时刻，从 X 平面读到的状态是 connected，且上一次状态变化时间是 Y。"不能支撑："这台设备的所有流量都在通道里"（要 L5 范围格）、"这条通道由组织装配"（要 L2 装配者格）、"通道被拆掉了"（要 L10 移除格）。

---
## 8. L5 范围层：影响到谁、例外给谁

### 8.1 官方口径

范围层是十一条层里唯一**同时有强制语义与例外语义**的一层，它的公开口径集中在《Routing your VPN network traffic》一页，第 5 行给出适用范围："You can control some of the network traffic that the system routes to and from a personal VPN, packet tunnel provider, or app proxy provider. The Network Extension framework provides routing settings for all VPN types, and some settings specific to personal VPNs and packet tunnel providers. You can configure the routing of packets to per-app VPNs using rules, and make exceptions to always-on VPNs on MDM supervised devices."——一句话里出现三种通道类、两套机制（rules 与 exceptions）和一个监督状态前置条件。

四类范围口径分别落在四处：

| 范围口径 | 官方位置 | 原文关键句 |
| --- | --- | --- |
| 全量（默认路由） | 第 20 行 | "If you include the default route (0.0.0.0/0 or ::/0) in the includedRoutes property, the system routes network traffic that doesn’t match some other more specific rule in the system routing table through the VPN." |
| 表优先 | 第 37 行 | "Note that the system routing table supersedes the includedRoutes and excludedRoutes properties." |
| 作用域限定 | 第 70 行 | "The system scopes the included routes to the VPN and the excluded routes to the current primary network interface, such as a Wi-Fi or a cellular network. This property supersedes the system routing table and scoping operations by apps. It’s also mutually exclusive from the includeAllNetworks property. If you set includeAllNetworks to true, the system ignores the enforceRoutes property." |
| 逐 App | 第 78—79 行 | macOS 用 `appRules` 加 `excludedDomains`；iOS 侧 "For iOS apps, create rules using the MDM system and access the rules in your code using the copyAppRules() method." |

逐 App 那一格在《NETunnelProviderManager》第 30—39 行被展开成六步装配语义：第 30 行 "The only way to configure Per-App VPN is by enrolling the device in a Mobile Device Management (MDM) system, and then linking apps that are managed by the MDM system with a VPN configuration created from a com.apple.vpn.managed.applayer configuration profile payload."；第 31 行要求载荷必须含 `VPNUUID` 字段；第 32 行要求 `ProviderType` 按提供者类取 `packet-tunnel` 或 `app-proxy`；第 33 行要求把同一个 `VPNUUID` 写进每个受管 App 的属性字典；第 35 行是设备侧的换算结果——"The MDM client running on the device creates one app rule in the VPN configuration for each managed app that is linked to the VPN configuration via the VPNUUID app attribute."；第 36 行给出例外中的例外："It is not possible to create app rules for Apple system apps. The one exception to this rule is Safari."；第 38 行说明 App 规则一身二职——"The Per-App VPN app rules serve as both routing rules and VPN On Demand rules."；第 39 行给出限制："only NEOnDemandRuleDisconnect rules will be used. When a NEOnDemandRuleDisconnect rule matches, apps which match the Per-App VPN rules will bypass the VPN."

例外清单在 always-on 上有独立的一整套键。第 84 行先立强制语义："An always-on VPN acts as the only connection to the internet for an iOS device. You enable this feature by installing an always-on VPN profile on an MDM-supervised device."；第 85 行给失败形态："When the VPN isn’t in a connected state, and while the device starts up before the VPN starts, the system drops network traffic."；第 86 行划定系统自带的例外边界："The system always excludes network control plane traffic — such as DHCP — but only excludes captive portal negotiation traffic, if you enable the AllowAllCaptiveNetworkPlugins, AllowCaptiveWebSheet, or AllowedCaptiveNetworkPlugins payload keys in the profile."；第 88—89 行给出组织可写的两格：`ApplicationExceptions`（指定排除的 App）与 `ServiceExceptions`（官方列出的取值只有 `VoiceMail`、`AirPrint`、`CellularServices` 三种）。第 57 行还有一格常被漏登："To exclude network connections to hosts on the local network — such as AirPlay, AirDrop, and CarPlay — set the excludeLocalNetworks property to true."

内容过滤类通道的"范围"不由路由表达，而由判定表达。《NEFilterDataVerdict》第 9—14 行给出六个动作：`allow()`（放行当前分块及该流后续全部数据）、`drop()`（丢弃当前分块及后续）、`pause()`（暂停该流）、`remediateVerdict(withRemediationURLMapKey:remediationButtonTextMapKey:)`（丢弃并给整改 URL）、`needRules()`（控制提供者要先更新规则才能决定）、`init(passBytes:peekBytes:)`（按分块放行并指定下一次要交给它的数据）。《Content filter providers》第 24—28 行则把判定分成四类加一个基类：`NEFilterNewFlowVerdict`（首块检查的结果）、`NEFilterDataVerdict`（后续分块的结果）、`NEFilterControlVerdict`（控制提供者的结果）、`NEFilterRemediationVerdict`（用户请求整改后的结果）与抽象基类 `NEFilterVerdict`——**同一条流在不同分块位置由不同的判定类负责**，这是范围格里必须区分"首块判定"和"后续判定"的原因。

最后一条范围口径来自《Apple Platform Security Guide》第 3815 行，它把 always-on 的组织语义写成一个覆盖声明："Always On VPN eliminates the need for users to turn on VPN to enable protection when connecting to cellular and Wi-Fi networks. It also gives an organization full control over device traffic by tunneling all IP traffic back to the organization."——**"full control" 与第 86、88—89 行的三处例外同时成立**，所以范围结论必须写"除控制面、门户协商与登记例外之外的流量"。

### 8.2 这一层的台账格

脚本一用 `asrt.*`（断言机制与范围）与 `trig.*`（按需规则）登记本层，`verd.*` 登记判定侧：

| 字段 | 取值域来源 | 缺失后果 |
| --- | --- | --- |
| `asrt.mechanism` | `necp_assert` / `per_app_mapping` / `included_routes` / `excluded_routes` / `app_rules` / `captive_plugin_list` / `exception_list`（第 20、37、78、86、88—89 行） | 机制与通道类不配对（C05） |
| `asrt.scope` | `all_flows` / `selected_flows` / `scoped_direct` / `primary_interface`（第 20、70 行与 `necp.h` 第 255 行） | 范围写成全量却登记了逐 App 机制（C06） |
| `asrt.app_exceptions` | `ApplicationExceptions` / `ServiceExceptions` 清单（第 88—89 行） | 例外清单非空却把范围记为全量（C06） |
| `asrt.mapping_pairs` | `VPNUUID` 配对数量（`netunnelprovidermanager` 第 31、33、35 行） | 声称逐 App 却没有配对格（C05） |
| `trig.mode` / `trig.rule_action` | `on_demand` / `always_on` / `manual` / `auto_connect`；`connect` / `evaluate_connection` / `disconnect` / `ignore`（《NEOnDemandRule》第 8、20—23 行） | 按需模式与规则动作互斥（C01、C02） |
| `trig.interface` | `wifi` / `cellular` / `both` / `any`（声明式 always-on 第 31—33 行的 `Interfaces`） | 接口面与规则计数矛盾（C03） |
| `verd.kernel_result` / `verd.provider_verdict` | `necp.h` 第 240—258 行的 19 项结果 + 判定六动作（第 9—14 行） | 内核结果与提供者判定互否（D02） |
| `verd.remediation` | `web_block_page` / `append_notice`（第 12 行 `remediateVerdict`） | 判定为 deny 却没有任何整改出口（D06） |

### 8.3 失败形态

**形态一：把"表优先"读成"配置优先"。**第 37 行与第 70 行方向相反：前者说系统路由表压过 `includedRoutes` / `excludedRoutes`，后者说"作用域限定"这一格又压过系统路由表。台账里只写一个"生效范围：全量"，等于把三行互相克制的规则压成一句结论；脚本一的 D07 专门拦"引用第 37 行的表优先口径却同时声明全量范围"。

**形态二：把掉线窗口写成"回落到直连"。**第 49 行与第 85 行的口径是丢包而不是回落，第 81 行对逐 App 更直白："the apps generally can’t communicate over the network at all unless the VPN is in the connected state."，第 80 行还给出一个反向例外——启用按需并配了 disconnect 规则时，"the system bypasses the per-app VPN for devices on the network that match the on-demand rule criteria"。这三行合起来的工程含义是：**同一台设备在同一时刻对不同 App 可以既是"强制"也是"旁路"**，所以范围格必须与 `trig.rule_action` 同层登记，不能只挂一个全局值。

**形态三：把例外清单当作通道不存在。**always-on 的三处系统级例外（控制面、门户协商、`ServiceExceptions` 三值）是公开口径里的常态配置。台账把例外清单登记为"无"，通常只是"没读回"而不是"没有"；脚本一的 C06 要求：`asrt.scope` 记为全量时，例外清单格必须是 `recorded` 或明确的 `not_applicable`，`not_recorded` 一律不落 J1。

**形态四：用企业 VPN 的唯一性推范围。**《NETunnelProviderManager》第 17 行说的是一件很容易误读的事："Only one enterprise VPN configuration can be enabled on the system at a time. If both a Personal VPN and an enterprise VPN are active on the system simultaneously, the enterprise VPN takes precedence... The Personal VPN will remain active and connected while the enterprise VPN is active and connected, and any traffic that is routed to the Personal VPN and is not routed to the enterprise VPN will continue to traverse the Personal VPN."——**两条通道可以同时处于 active，且个人 VPN 的流量继续走个人 VPN**。把"企业 VPN 只有一条"换算成"这台设备只有一条通道"，范围结论会漏掉第二条通道的存在。

### 8.4 这一层能支撑与不能支撑的结论

能支撑："这台设备上的 X 通道按 Y 机制覆盖 Z 类流，例外清单登记为 W。"不能支撑："这台设备的全部流量都经过企业网络"（除非第 86、88—89 行三处例外都记为 `recorded` 且清单为空）、"这个 App 一定走了通道"（要逐 App 配对格）、"通道没覆盖的流量走了直连"（第 49、81、85 行的丢包语义排除了这个默认）。

---

## 9. L6 内核层：NECP 策略结果与 network agent

### 9.1 官方口径的缺失与源码口径的补位

本层是全文唯一没有开发者文档口径、只有开源代码口径的层。Apple 公开文档里对 NECP 与 network agent 的正面描述只有《Apple Platform Security Guide》第 1572 行那句间接表述（把 NetworkExtension 与 DriverKit、EndpointSecurity 并列为第三方代理应当使用的框架，"Third-party security agents should be used only if they take advantage of these APIs or have a robust road map to transition to them and away from kernel extensions."）。**换句话说：内核侧承认这些代理存在，但不给它们一份归属口径。**本轮从 XNU 开源侧补齐的四组读数：

**其一，策略结果是一份封闭词表。**《necp.h》第 240—258 行给出 19 个结果取值（`PASS` 1 至 `REMOVE_NETAGENT_TYPE` 19），第 260 行用 `NECP_POLICY_RESULT_MAX` 把上界钉在 19；《necp.c》第 841—861 行的 `resultString` 数组把这 19 格连同第 0 格 `"INVALID"` 一起列成 20 格，成为内核里唯一可读的结果名表。这张表的归属含义很直接：**"内核怎么处置这条流"能说的话只有这 19 句**，任何超出这张表的判定措辞都不是内核读数（脚本一 D01 拦词表外的结果串）。同一批定义里还有两处必须注意的标注：第 247—250 行的四条 trigger 系结果（`TRIGGER` 8、`TRIGGER_IF_NEEDED` 9、`TRIGGER_SCOPED` 10、`NO_TRIGGER_SCOPED` 11）逐条写着 `// Deprecated`；第 255 行对 `SCOPED_DIRECT` 16 的注释是 "N/A, scopes to primary physical interface"，与第 8.1 节第 70 行的用户态口径同一方向。第 256 行的 `ALLOW_UNENTITLED` 17 则是"无权利流量放行"这一特殊结果，它由第 627 行的 `drop_unentitled_level`（`necp.c` 第 162 行给 watchOS 的默认值是 `NECP_SESSION_PRIORITY_CONTROL + 1`，注释写明 "Block all unentitled traffic from policies below control level"）控制。

**其二，通道的内核身份是一串 UUID 加两个 32 字节字符串。**《network_agent.h》第 211—218 行的 `struct netagent` 共七个字段，其中 `netagent_uuid`（第 212 行）是唯一的身份格，`netagent_domain` / `netagent_type` / `netagent_desc`（第 213—215 行）三个字符串数组的长度都由第 144—145 行的 `NETAGENT_DOMAINSIZE` 与 `NETAGENT_TYPESIZE` 定为 32。第 153—169 行的 17 个 `NETAGENT_FLAG_*` 定义了这个身份的行为边界，与归属台账直接相关的六格是：`REGISTERED` 0x0001（第 153 行）、`ACTIVE` 0x0002（第 154 行）、`KERNEL_ACTIVATED` 0x0004 与 `USER_ACTIVATED` 0x0008（第 155—156 行，后者的注释点名触发系统调用 `netagent_trigger`）、`VOLUNTARY` 0x0010（第 157 行 "Use of agent is optional"）、`SPECIFIC_USE_ONLY` 0x0020（第 158 行）、`REQUIRES_ASSERT` 0x0200（第 162 行 "Assertions are expected to be taken against this agent"）、`NETWORK_PROVIDER` 0x0040（第 159 行 "Agent provides network access"）。第 150 行的 `NETAGENT_MAX_TOKEN_COUNT` 为 256，是令牌侧的硬上界。

**其三，"谁被允许绑到这条通道"由参数族表达。**《necp.h》第 671—690 行给出七族 agent 绑定参数：`PROHIBIT_AGENT` 102 / `PROHIBIT_AGENT_TYPE` 103（第 671—672 行）、`REQUIRE_AGENT` 112 / `REQUIRE_AGENT_TYPE` 113（第 676—677 行）、`PREFER_AGENT` 122 / `_TYPE` 123（第 681—682 行）、`AVOID_AGENT` 124 / `_TYPE` 125（第 686—687 行）、`TRIGGER_AGENT` 130 / `ASSERT_AGENT` 131 / `UNASSERT_AGENT` 132（第 688—690 行）。源码注释把三族的取舍写得像策略语言：Require "will choose an interface with that property, or none if not found"，Prefer "will choose an interface with an agent, or best otherwise if not found"，Avoid "will choose an interface without an agent, or best otherwise if unavoidable"。**"这条 App 必须走这条通道"在内核里是 REQUIRE，"最好走"是 PREFER——两者在归属台账里都写成"该 App 走通道"就是口径混用**（脚本一 C06、D03）。同一文件第 648、649、657、658 行的四个参数（`APPLICATION`、`REAL_APPLICATION`、`PID`、`UID`）各自在行尾写着 `// Requires entitlement`：想用"哪个 App"给通道归属作证，本身要先过权利闸门。

**其四，读取入口被闸门拦住。**《necp.c》第 956—957 行对未授权凭证返回 `necp_drop_unentitled_order`，判据是 `PRIV_NET_PRIVILEGED_CLIENT_ACCESS` 与 `PRIV_NET_PRIVILEGED_SERVER_ACCESS` 两者皆不通过；第 1049、1385、3347、13935 行四处用 `PRIV_NET_PRIVILEGED_NECP_POLICIES` 设闸；第 1026 行对 `com.apple.private.necp.drop_all_bypass` 单独校验；第 7650—7651 行把策略匹配能力限定给 `com.apple.private.necp.match` 或 `com.apple.developer.CaptiveNetworkPlugin` 二者之一。《network_agent.c》第 2575—2580 行对 `SIOCGIFAGENTLIST64`（代理清单 dump）同样先查 `PRIV_NET_PRIVILEGED_NECP_POLICIES`，不通过时写的日志是 "Client does not hold the necessary entitlement to get netagent information"。**这台设备上"通道在内核里存不存在"是一个真实可读的事实，但读取者必须是特权进程**——这就是第 11 章 L8 层里"内核平面"与"管理平面"无法互证的根本原因。

### 9.2 这一层的台账格

| 字段 | 取值域来源 | 缺失后果 |
| --- | --- | --- |
| `reg.agent_state` | `REGISTERED` / `ACTIVE` / `KERNEL_ACTIVATED` / `USER_ACTIVATED`（flags 第 153—156 行）与 `network_agent.c` 第 1085 行的注册计数递增 | 状态串不在内核词表里（A06） |
| `reg.domain` / `reg.agent_type` | 两个 32 字节字符串域（第 144—145、213—214 行） | 超长或空值无法作为标识（A06） |
| `reg.voluntary` / `reg.requires_assert` / `reg.specific_use_only` | flags 第 157、162、158 行 | 声明必走却没有断言要求（A08） |
| `reg.session_alive` | 会话注销路径（`network_agent.c` 第 938、978、1266、1308、1329、1354 行） | 记为已注销却仍记为承载中（A07） |
| `verd.kernel_result` | 19 项结果词表（`necp.h` 第 240—258 行 / `necp.c` 第 841—861 行） | 词表外结果（D01）、弃用结果当生效语义（D04） |
| `tok.agent_token` | `ACQUIRE_AGENT_TOKEN` 22（`necp.h` 第 641 行 "Get a one-time use token from an agent"）与 `NETAGENT_MAX_TOKEN_COUNT` 256 | 一次性令牌被登记成可复用（T04） |
| `tok.identity_basis` | 第 648、649、657、658 行四格（Application / RealApplication / PID / UID）与 `GET_SIGNED_CLIENT_ID` 24、`VALIDATE` 23（第 643、642 行） | 身份基础缺权利闸门（T06） |

### 9.3 失败形态

**形态一：把内核结果当授权结论。**`PASS` 与 `ALLOW_UNENTITLED` 都写作"通过"，但第 256 行的 `ALLOW_UNENTITLED` 是一条**为无权利流量准备的放行结果**，它配合第 627 行的可调级别使用；把这一格记成"这条流被企业策略允许"是层错位（D05 拦"通道需要权利闸门却给出无权利放行"）。

**形态二：把弃用结果当触发证据。**第 247—250 行四条 trigger 系结果全部标注 `// Deprecated`，而 `TRIGGER_AGENT` 130 与 `ASSERT_AGENT` 131（第 688—689 行）是**现役**参数。台账把两者混写成"由内核触发通道"，就丢掉了"谁断言、谁解除断言"这条可核对的链（D04、A08）。

**形态三：把注销路径当作消失证明。**`network_agent.c` 的注销有三个层次：会话整体注销（第 1266、1274 行的 `netagent_unregister` 与第 1329、1354 行的 `netagent_unregister_all_session_registrations`）、单条代理注销（第 978、1308 行的 `netagent_unregister_one_session_registration`），以及第 938 行那条"会话退出时清掉全部注册"的路径。**代理注销不等于通道消失**——前者只清掉一条注册记录，注册计数与代理对象本身由第 1085 行一带的计数器维护。脚本一 V02、V05 分别拦"用代理注销回执当通道移除证明"与"移除声明缺注销层次"。

**形态四：把特权可读当管理可得。**第 9 章全部闸门都是 `priv_check_cred` 级别的；本轮归档的 26 个 `net.necp` sysctl 节点里只有 1 个是 ANYBODY 可读（读数见第 16 章读数 14）。因此"内核里能读到"与"管理面/普通 App 能读到"必须分开登记——脚本二用 P 族信号（平面越界）专门拦这一类，例如把 `kernel_sysctl_node` 要素挂到 `advisory` 或 `mdm_status_item` 平面上。

### 9.4 这一层能支撑与不能支撑的结论

能支撑："内核在这一刻把这条流判为结果词表里的某一项，并且这条通道的代理注册标识是 Y、状态位是 Z。"不能支撑："这条通道是谁装的"（要 L2 装配格）、"用户是否知道它存在"（要 L7 告知格）、"这台设备的管理方能不能读到这一格"（普通凭证读不到，第 9.1 节其四）。

---

## 10. L7 告知层：用户看得见哪一格

### 10.1 官方口径

告知层是本文里唯一"官方文档只覆盖一小块"的层。本轮归档的支持文档《Status bar icons》全文里与网络通道直接相关的条目只有一行——第 1186 行："VPN. iPhone is connected to a network using VPN."。它的相邻四行分别是运营商卫星（第 1183 行）、Wi-Fi 通话（第 1184 行）、个人热点已连接（第 1185 行）与网络活动（第 1187 行）；第 1187 行的官方限定语把最后这一格排除出通道口径："Network activity. Shows that there’s network activity. Some third-party apps may also use it to show an active process. See Connect to the internet."。**这份图标页里没有内容过滤器、DNS 代理、DNS 设置、透明代理、应用代理、URL 过滤器或网络中继的任何条目**——这七类通道在用户可见面上没有专属图标。

设备侧的第二块告知面是设置里的开关。声明式 always-on 样例（《network.vpn.always-on》第 26—28 行）给出两格：`VisibleName`（第 26 行，样例值 "Always-On VPN"）与 `UIToggleEnabled`（第 27 行，样例值 `false`）。第 27 行这一格是告知层最有工程含量的一格：**它决定用户在设置界面里能不能自己拨动这个通道**。同页第 12—18 行的可用性轴把它限定在监督注册范围内（第 12 行 Allowed in supervised enrollment，第 14 行 Allowed in user enrollment 为 N/A），这与《Apple Platform Security Guide》第 3815 行"eliminates the need for users to turn on VPN"的口径方向一致。个人 VPN 侧的对应格是《NEVPNManager》第 15 行的 `isEnabled`（"A Boolean used to toggle the enabled state of the VPN configuration."）与第 18 行的 `localizedDescription`（"A string containing the display name of the VPN configuration."）——用户在界面上看到的文本来自后者，而通道是否被启用来自前者，两者不是同一格。

第三块告知面是连接态的可观测时刻。《NEVPNStatus》第 19 行 `status`（"The current status of the VPN connection."）与第 20 行 `connectedDate`（"The date and time when the connection status changed to NEVPNStatusConnected."）给出"什么时候变成 connected"这一时刻；第 9—14 行的六个状态里只有第 14 行的 `invalid` 把两种截然不同的情形压进一格："The associated VPN configuration doesn’t exist in the Network Extension preferences or isn’t enabled."。第 7 行还写明断开过程中的用户可见后果："After the VPN transitions from the NEVPNStatus.disconnected to the NEVPNStatus.disconnecting state, the system doesn’t close TCP connections, but ignores packets to and from established network connections."——**既有连接不断开、只是被忽略**，因此用户看不到"掉线"这一事件本身。

按需规则侧的告知口径在《NEOnDemandRule》第 8 行与第 20—23 行：四个子类分别是 connect、disconnect、ignore 与 evaluate connection，其中《NEOnDemandRuleEvaluateConnection》（第 4 行的类声明）把"是否执行动作"交给 App 的代码判断。这一格的意义在于：**通道可以在用户没有做出任何一次拨动动作的情况下被建立**，而建立之后的可见面只剩《Status bar icons》第 1186 行那一个 VPN 图标。

最后一块告知口径是管理面的"告知"。《Status items》一页 82 行按类别列出的回报项包含账户清单、App 与声明包清单、内容缓存、设备属性与安全证书清单，**没有任何一项回报 VPN、代理、内容过滤器或 DNS 通道**（本轮全文扫描的缺失读数见第 16 章读数 15—16）。装配侧的回报也只有装配件本身：《InstallProfileCommand》第 23—24 行与《RemoveProfileCommand》第 21—22 行给的是命令与响应对象，语义是描述文件的安装与移除。

### 10.2 这一层的台账格

| 字段 | 取值域来源 | 缺失后果 |
| --- | --- | --- |
| `asm.enabled_toggle` | `UIToggleEnabled`（第 27 行）与 `isEnabled`（NEVPNManager 第 15 行）、`NERelayManager` 第 14 行 | 开关格与状态格混记（B07） |
| `asm.supervised` | 可用性轴（第 12、14 行）与监督限制口径（《Device management restrictions for supervised Apple devices》第 345 行） | 需要监督的通道记成用户可自行装配（B05） |
| `obs.plane` | `status_icon` / `mdm_status_item` / `declarative_status` / `provider_api` / `kernel_sysctl` / `advisory`（第 10.1 节五块告知面） | 平面不承载该格（O02、O03） |
| `obs.icon_visible` | 仅 VPN 一类有图标（第 1186 行） | 用"图标不在"否证非 VPN 通道存在（N01、N02） |
| `obs.field_read` | `status`（第 19 行）、`connectedDate`（第 20 行）、install/remove 回执（第 23—24、21—22 行） | 把回执当状态（O03） |
| `when.status` | 六状态（第 9—14 行） | `invalid` 当作"未安装"或"已断开"（T01） |
| `doc.conclusion` | `confirmed` / `absent_in_channel` / `not_determinable` / `assumed` | 告知面空白写成"通道不存在"（X01） |

### 10.3 失败形态

**形态一：用图标面覆盖全部通道类。**第 1186 行只声明了 VPN 连接图标，七类通道无对应条目；因此"图标在"能支撑"这台设备此刻有一个处于 connected 的 VPN 通道"，"图标不在"只能否证图标自身的显示条件（N01）。反过来，把状态栏里的"网络活动"图标（第 1187 行）当作通道证据更不成立——那一格官方口径明确允许第三方 App 复用。

**形态二：把开关当作状态。**`UIToggleEnabled` / `isEnabled` 是"允许不允许用户拨动"，`status` 是"此刻跑没跑"。《NEVPNManager》第 15 行与《NEVPNStatus》第 19 行分属两个类；把开关拨到 on 记作"通道已建立"是 B07；反之把 `isEnabled = true` 与 `status = invalid` 同时登记，则是第 14 行那格塌缩语义的必然产物（T01）。

**形态三：把管理面无回报项当作无通道。**《Status items》82 行不含通道项，是一个**可得性事实**，不是**存在性事实**：管理面读不到不等于设备上不存在，装配命令回执也不等于通道在跑。脚本二用 D 族（覆盖空洞）把这一格标为"该通道类需要这一要素、但没有任何平面能给出"，落 Q3 而非 J 档——它限制的是"能说什么"，不是"是什么"。

**形态四：把 `connectedDate` 当作通道起始时刻。**第 20 行的定义只覆盖"状态变为 connected 的时刻"，配合第 7 行（既有连接不被关闭、只被忽略）与第 85 行（启动窗口丢包）看，这个时刻既不是"设备进入受保护状态"的时刻，也不是"配置生效"的时刻。台账若把它写成"生效时间"，第 13 章的失效判定会整体提前。

### 10.4 这一层能支撑与不能支撑的结论

能支撑："这一刻用户界面上应当出现 VPN 图标"、"这台设备的通道开关是否对用户可见可拨"、"connected 这一状态出现在某个时刻"。不能支撑："这台设备上没有内容过滤器/DNS 代理/中继"（告知面根本不覆盖，落 O02）、"用户知道这条通道存在"（开关可见性与知情不是同一格，第 08 篇的用途声明口径也不在本篇范围内）、"管理方掌握了通道状态"（第 10.1 节最后一块：没有回报项，只有装配件回执）。

---
## 11. L8 观测平面层：这一格是谁读回来的

### 11.1 官方口径：六个平面与它们的承载边界

观测平面层是本篇的中枢层：前十层决定"通道是什么"，这一层决定"你凭什么知道它是什么"。本轮归档件里能给出平面口径的，一共九块（内核面在一行里含 `kernel_netagent` 与 `kernel_sysctl` 两块）：

| 平面 | 口径来源 | 能读回的格 | 读不回的格 |
| --- | --- | --- | --- |
| 权利清单面 `entitlement_manifest` | 《com.apple.developer.networking.networkextension》第 4、6—17 行与《com.apple.developer.networking.vpn.api》第 4、6 行 | 权利键名与取值、`allow-vpn` | 设备上有没有装配、通道此刻状态 |
| 开发者门户面 `developer_portal` | 同页第 20—25 行的启用步骤（capability 勾选、描述文件重新生成） | 授予路径与审批状态 | 运行时判定结果 |
| 命令面 `command_plane` | 《InstallProfileCommand》第 23—24 行、《RemoveProfileCommand》第 21—22 行、《DeclarativeManagement》第 10、21—22 行 | 装配件的安装/移除回执 | 通道状态：三处回执语义里都没有状态格 |
| 声明面 `declarative_plane` | 《Declarations》页第 28—34、52 行八条通道类声明 + 各声明页第 12—18 行可用性轴 | 类型串、监督轴、`Apply` 单/多 | 内核注册与运行时判定 |
| 提供者 API 面 `provider_api` | 《NEVPNManager》第 11、13、15 行、《NEVPNStatus》第 19—20 行、《NERelayManager》第 9—15 行、《NETunnelProviderManager》第 30—39 行 | 开关、状态、连接时刻、App 规则 | 管理方能否读到（这是另一块平面） |
| 内核面 `kernel_netagent` / `kernel_sysctl` | 《necp.h》第 240—258、638—690 行、《necp.c》第 620 行起 26 个 sysctl 节点、《network_agent.c》第 2575—2580 行 | 代理注册位、策略结果、调试计数 | 通道归属主语（谁装的） |
| 图标面 `status_icons` | 《Status bar icons》第 1186 行（VPN）与第 1187 行（网络活动，含第三方复用限定） | VPN 连接图标 | 其余七类通道无条目 |
| 公告面 `advisory` | 《C/advisory-entries.tsv》的 cve / component 两列（392 行、101 个去重组件名） | 产品功能组件名 | 任何通道词形（命中 0） |

脚本二把这十三项取值（含 `device_settings`、`none`、`not_recorded`、`unknown`）做成封闭取值域，并给每类要素标注"哪个平面承载"：权利类由 `entitlement_manifest` / `developer_portal` 承载；内核类由 `kernel_netagent` / `kernel_sysctl` / `provider_api` 承载；装配件类由 `command_plane` / `declarative_plane` / `device_settings` 承载；运行类由 `provider_api` / `command_plane` / `declarative_plane` / `status_icons` / `device_settings` 承载；观测类由 `kernel_sysctl` / `provider_api` / `command_plane` / `declarative_plane` / `status_icons` / `advisory` 承载，另有两格例外显式放行（`provider_api` 可读 `enabled_toggle`、`device_settings` 可读 `netagent_uuid`）。**承载关系不是文档给的，是本文按文档口径逐格对齐的结果**，所以它本身就是判定输入：凡把某格挂到不承载它的平面上，脚本二给出 P 族信号。

P 族五种失败形态与它们的官方依据一一对应：P01 拦"权利类要素记为内核调试面或图标面可读回"（依据是 `necp.c` 第 649—668 行的 data_tracing 系节点只按 pid/port/proto/ifindex 过滤，与 `B/pages/status-icons` 第 1183—1187 行的图标条目）；P02 拦"把网络通道格登记为管理面状态回报项"（依据是 `status-items` 全文 82 行里没有任何网络、代理或网络扩展类回报项）；P03 拦"内核侧那一条记录登记成描述文件或图标里的格"（依据是 `network_agent.c` 第 938—1014 行的会话/注册路径与 `mdm-vpn` 第 9—16 行的可用性块）；P04 拦"记为已读数但平面为无平面"（依据是 `nevpnstatus` 第 14 行的塌缩语义与 `status-items` 第 21 行起的设备属性类条目）；P05 收其余平面与要素类别不匹配的组合（依据是 `devicemanagement-declarations` 第 4—71 行的声明清单——这份 52 条声明里只有 8 条属于网络通道）。

### 11.2 这一层的台账格

| 字段 | 取值域来源 | 缺失后果 |
| --- | --- | --- |
| `obs.plane` | 上表九块平面，但**两个脚本用的是两套平面命名**：脚本一按"读数由哪个管理对象给出"取 `status_icon` / `mdm_command` / `mdm_status_item` / `declarative_status` / `provider_api` / `kernel_sysctl` / `advisory` 七项加 `none` / `not_recorded` / `unknown`；脚本二按"公开口径出处"取上表十三项（另含 `device_settings`）。两套名字之间由本文对齐，脚本本身不做换算 | 平面不承载该格（O02、O03、P01—P05） |
| `obs.field_read` | `status_bool` / `enabled_toggle` / `identifier` / `install_receipt` / `icon_visible` / `agent_uuid` / `kernel_result` / `channel_name`，另加 `none` / `not_recorded` / `unknown` | 把回执读成状态（O03） |
| `obs.command_name` | `InstallProfile` / `RemoveProfile` / `DeclarativeManagement`（三页命令口径） | 命令名与回执格不配对（一 B06） |
| `when.time_source` | `device_clock` / `server_log` / `provider_log` / `management_server` / `none`，另加 `not_applicable` / `not_recorded` / `unknown` | 时刻无法回指（一 T03） |
| `doc.source` / `doc.line_ref` | 归档件相对路径（`A/…`、`B/pages/…`、`C/…`）与纯行号形态（`NN` 或 `NN—MM` 写成 `N-M`）；CVE 号只在公告面使用 | 判定无法回指（一 X01） |
| `doc.conclusion` | `confirmed` / `absent_in_channel` / `not_determinable` / `assumed`，另加 `not_recorded` / `unknown` | 空白平面写成确定结论（一 X01、一 O01） |

### 11.3 失败形态

**形态一：把"这条命令有响应对象"读成"这个命令回报通道状态"。**《DeclarativeManagement》第 21—22 行给出命令与响应两个对象，第 10 行说明这条命令的语义只是"turn on the declarative management engine … Subsequent commands trigger a declarative management synchronization operation."——**同步动作有回执，通道状态没有回报项**。同一件事在描述文件侧同样成立：《InstallProfileCommand》第 23—24 行与《RemoveProfileCommand》第 21—22 行回读的是装配件。

**形态二：把内核可读当管理可得。**第 9 章的四组 `priv_check_cred` 与 `IOTaskHasEntitlement` 闸门说明内核面是一块**特权可读、非特权不可读**的平面。台账若把 `kernel_sysctl_node` 记为管理面可读，就是把两块平面的可见性合并了（P01、P03）。

**形态三：把公告面当通道面。**本轮实测的公告组件词表里，`vpn` / `proxy` / `tunnel` / `filter` / `relay` / `hotspot` 六种通道词形命中全为 0，`NetworkExtension` 只命中 1 条且影响句与通道无关（读数见第 16 章读数 1—11）。因此任何挂在 `advisory` 平面上的通道要素都不可归属——脚本二把这条立场做成全局信号 X04，并用 X06 拦"把内核符号名（`necp`、`netagent`、`content_filter`）当公告组件名登记"。

**形态四：单平面读数。**同一格由两个平面给出、但只登记一个平面，是台账里最常见的隐性错误：`enabled_toggle` 在声明面是 `UIToggleEnabled`（第 27 行），在提供者 API 面是 `isEnabled`（《NEVPNManager》第 15 行），两者同名不同源。脚本二的 S09 拦"同一对象同一要素出现两种状态、平面或词表归属"，S08 则允许三格一致的重复登记（不阻断，但提示差集会重复计数）。

### 11.4 这一层能支撑与不能支撑的结论

能支撑："这一格由 X 平面在 T 时刻读回，读法是 F。"不能支撑：任何跨平面的补格——权利面补不出装配面、命令面补不出运行面、图标面补不出其余七类通道、公告面补不出任何通道格。**本层不给通道下结论，只给结论限定主语。**

---

## 12. L9 通道差异层：同一要素在不同通道的可得性

### 12.1 矩阵口径

可得性矩阵是本篇与脚本二的共用输入，它回答一个此前所有报告都没正面回答的问题：**"这一格读不回来"到底是台账没登记，还是这条通道根本不给这一格。**矩阵按 11 个通道类 × 22 个通道要素建表，取值四档：`required`（这条通道类必须有这一格才能定归属）、`optional`（有则增强，无可降级）、`not_applicable`（这一格对该类不成立）、`undocumented`（本轮归档件无口径）。要素按五类归属划分——权利类 4 项、内核类 5 项、装配件类 4 项、运行类 5 项、观测类 4 项，逐项出处见第 3.1 节与第 16 章。

本轮矩阵的规模与分布（完整 211 行见 `FX/capability.csv`，其口径注释在第 1—8 行）：

| 通道类 | 登记行数 | required 数 | required 要素 |
| --- | --- | --- | --- |
| `packet_tunnel` | 22 | 10 | `provider_entitlement_value` `entitlement_approval` `provider_class_gate` `netagent_registration` `payload_type` `on_demand_rule_set` `routing_scope` `user_consent` `vpn_status` `status_icon` |
| `dns_proxy` | 22 | 7 | `provider_entitlement_value` `provider_class_gate` `netagent_registration` `payload_type` `declarative_type` `on_demand_rule_set` `user_consent` |
| `built_in_vpn` | 18 | 7 | `personal_vpn_api` `payload_type` `install_receipt` `on_demand_rule_set` `routing_scope` `user_consent` `vpn_status` |
| `content_filter` | 22 | 6 | `provider_entitlement_value` `provider_class_gate` `netagent_registration` `payload_type` `on_demand_rule_set` `verdict_fail_mode` |
| `app_proxy` | 22 | 6 | `provider_entitlement_value` `provider_class_gate` `netagent_registration` `payload_type` `on_demand_rule_set` `verdict_fail_mode` |
| `relay` | 18 | 5 | `provider_entitlement_value` `payload_type` `declarative_type` `routing_scope` `user_consent` |
| `transparent_proxy` | 22 | 5 | `netagent_registration` `payload_type` `routing_scope` `user_consent` `status_icon` |
| `dns_settings` | 18 | 4 | `provider_entitlement_value` `payload_type` `declarative_type` `user_consent` |
| `url_filter` | 11 | 4 | `provider_entitlement_value` `provider_class_gate` `payload_type` `verdict_fail_mode` |
| `app_push` | 18 | 3 | `provider_entitlement_value` `provider_class_gate` `payload_type` |
| `captive_network` | 18 | 1 | `payload_type` |

四档合计 211 行：`required` 58 格、`optional` 95 格、`not_applicable` 39 格、`undocumented` 19 格。`undocumented` 这一档**不是"没查到"，而是本表拒绝建模**——它的定义写在矩阵自己的第 7 行注释里："公开文档既没说有也没说没有，本表拒绝建模（脚本二跳过，不据此定覆盖空洞）"。这 19 格全部落在四类通道上：`app_push` 6 格、`captive_network` 6 格、`relay` 4 格、`dns_settings` 3 格；按要素看集中在 `netagent_registration`（4）、`on_demand_rule_set`（4）、`kernel_sysctl_node`（3）三格。**这是矩阵给出的第三个结论：这四类通道连"要不要这一格"都无法从公开文档确定**，因此脚本二对它们既不报覆盖空洞、也不报不适用——把它记成 `not_applicable` 会造出假结论，记成 `optional` 会抬高覆盖率，两种写法都比 `undocumented` 更接近错误。第 26 章把这 19 格列为边界清单的读数之一。

### 12.2 矩阵的四个结构性结论

**其一，`payload_type` 是唯一在十一类通道上全部 required 的要素。**它的对应口径是 `com.apple.vpn.managed` / `.applayer` / `.appmapping`、`com.apple.webcontent-filter`、`com.apple.relay.managed`、`com.apple.configuration.network.dns-proxy` / `.dns-settings` / `.relay` / `.vpn.*` 与 `webcontent-filter.plugin` 这批载荷键与声明类型串（第 6 章）。这条结论的工程含义是**装配格是全通道公有的最低归属证据**：任何一条通道，只要台账里连载荷键或声明类型串都没有，就落 Q4（连可得性都不能定）。

**其二，内核类要素只在五类通道上 required。**`netagent_registration` 只出现在 `packet_tunnel`、`app_proxy`、`content_filter`、`dns_proxy`、`transparent_proxy` 五行 required 清单里；`built_in_vpn`（个人 VPN）、`dns_settings`、`relay`、`app_push`、`url_filter`、`captive_network` 六类不要求它。这一分布直接对应《NEAppExtensionConfiguration》第 7 行那句 "It exists only for use by the framework; you don’t need to use its methods and properties directly." 所代表的框架内部性，以及 `A/netunnelprovidermanager` 第 17 行把企业 VPN 与个人 VPN 分类的口径——**内核注册不是所有通道的必要条件，把它当全局必登记项会造出假空洞**。脚本二的 D03 专门拦"not_applicable 要素却被记为已读数"与"required 要素被记为不适用"两个方向。

**其三，`declarative_type` 只在 `dns_proxy`、`dns_settings`、`relay` 三类上 required，always-on VPN 上 optional。**依据是《Declarations》页第 28—34、52 行的八条通道声明里，`network.dns-proxy` / `.dns-settings` / `.relay` / `.vpn.always-on` / `.vpn.ikev2` / `.vpn.ipsec` / `.vpn.vpn-plugin` / `webcontent-filter.plugin` 各自的存在性，而 `app_proxy`、`content_filter`（非 plugin 形态）、`transparent_proxy`、`url_filter`、`app_push`、`captive_network` 六类在这份 52 条清单里**没有任何对应声明**。结论："声明式装配不可得"对这六类不是台账缺陷，而是通道口径；对那八类则是覆盖空洞。

**其四，告知面要素的 required 分布把 L7 层的结论量化了。**`status_icon` 只在 `packet_tunnel` 与 `transparent_proxy` 两类上 required——尽管透明代理在《Status bar icons》第 1183—1187 行里根本没有条目（透明代理复用 VPN 图标显示条件这一点在公开文档里没有口径，本轮按"该通道承载用户可见连接"归入 required 并在第 26 章列为待澄清边界）。`user_consent` 在六类上 required（`built_in_vpn`、`packet_tunnel`、`dns_proxy`、`dns_settings`、`relay`、`transparent_proxy`）。**这一格推不出自公开侧的可用性轴，两处甚至反向**：`Allowed in user enrollment` 那一格只写在描述文件页与声明对象页上——《NetworkRelay》第 14 行与《NetworkDNSProxy》第 14 行给 "iOS, Shared iPad, visionOS"、《Relay》页第 17 行给 iOS 与 visionOS，而《NetworkDNSSettings》第 18 行、《NetworkVPNAlwaysOn》第 14 行、《NetworkVPNIKEv2》第 14 行、《NetworkVPNIPSec》第 14 行与《MDM VPN payload》第 17 行一律记 N/A；API Collection 类的《Personal VPN》与《DNS proxy provider》两页整页没有可用性轴。照这两条轴读，六类 required 里只有 `relay` 与 `dns_proxy` 落在"允许用户自行注册"一侧，`dns_settings` 反而写 N/A，`built_in_vpn` 与 `packet_tunnel` 没有对应轴页。所以本篇把 `user_consent` 的 required 依据写成"该通道由用户可见地承载连接"这一告知层读取，不写成注册轴的推论，两处反向登记在第 26 章 N9；`install_receipt` 只在 `built_in_vpn` 上 required，因为它是唯一一类由用户在本机自行安装并由用户自行管理的通道——《NEVPNManager》第 7 行的定位是 "Personal VPN configurations are typically used to provide a service to users that protects their Internet browsing activity on insecure networks such as public Wi-Fi networks."，《Network Extension》页第 17 行同样把它单列（"Use Personal VPN to create and manage a VPN configuration that uses one of the built-in VPN protocols (IPsec or IKEv2)."），而《Apple Platform Security Guide》第 3811、3813、3815 行列出的三种组织侧部署（On Demand、Per-app、Always On）都以管理面为装配主语。

### 12.3 差集怎么用于判定

脚本二对三份输入做三段比对，得到的四类信号各有明确归属含义：

- **D 族（覆盖空洞）**：某条通道类 required 的要素，在该对象的登记行里一条也没有（D05）、登记为 `absent`（D01）、登记为 `not_recorded`（D02）、整个通道类在能力表里没有任何行（D04）、同一对象登记两个通道类（D06）。**空洞只降级判定档位（落 Q3），不阻断**——它说明"这一格该有但没有"，不说明"通道不存在"。
- **P 族（平面越界）**：见第 11.1 节，全部阻断。
- **V 族（词表混用）**：V01 拦"对外表述为 yes 却把两套词表混记在同一格"，V02 拦"用状态词表或公告组件词表去描述权利格与装配格"，V03 拦"平台执行口径与授权对象口径混用"（依据是 `necp.h` 第 240—258 行的结果词表与 networkextension 第 6—17 行的权利词表不可互换），V04 提示"已读数但未登记这一格是否会对外"。
- **X 族（公告比对）**：X01/X02 比对引用的 CVE 与组件名是否在词表内，X03 拦词表本身不可用，X04 是本篇的立场信号（通道词形在公告词表命中 0，因此公告平面不能承载通道要素），X05 提示公告平面读数缺公告标识，X06 拦把内核符号名当组件名。

三段齐备且无阻断 → Q1；存在阻断 → Q2；能定覆盖面但定不了归属（空洞、口径漂移）→ Q3；连可得性都定不了（能力表或清单不可用）→ Q4。**Q 档与第 19 章的 J 档分工：J 档看"这条通道的台账自洽吗"，Q 档看"这套登记体系覆盖吗"**——一个对象完全可以 J1 而整台账 Q3，这正是逐条审查与差集审查必须同时跑的原因（第 23 章的实跑对照表里能看到这两类结果的组合）。

### 12.4 这一层能支撑与不能支撑的结论

能支撑："对 packet_tunnel 这条通道，缺 `netagent_uuid` 是覆盖空洞；对 built_in_vpn，缺它是 `not_applicable`。"不能支撑：任何"某类通道安全性更高/更低"的比较结论——矩阵只登记口径可得性，不登记强度，也不评价任何具体产品。

---

## 13. L10 移除与失效层：通道消失之后谁能证明

### 13.1 官方口径

移除与失效层的公开口径有四条互不覆盖的路径：

**其一，装配件移除。**《RemoveProfileCommand》第 21—22 行给出移除命令与响应；它与《InstallProfileCommand》第 23—24 行同构，回读的都是描述文件本身。声明式侧的对应口径是《DeclarativeManagement》第 10 行的同步语义——**声明的移除同样只落在装配件层**。这两条路径都不能证明通道曾否运行，只能证明"某个键在这台设备上被写或被擦"。

**其二，配置从偏好库里移除。**《NEVPNManager》第 13 行的 `removeFromPreferences(completionHandler:)` 与第 11 行的 `saveToPreferences(completionHandler:)` 是同一组动作的两端，第 10 行 `loadFromPreferences` 说明这份配置的存放地是"the Network Extension preferences"。《NERelayManager》第 9—12 行给出中继侧同构动作（`shared()` / `loadFromPreferences` / `saveToPreferences` / `removeFromPreferences`，且第 10 行说明其存放地是"the system networking preferences"，与 VPN 侧的 Network Extension preferences 不是同一个库）。《NETunnelProviderManager》第 19 行补充了配置来源的一支：Packet Tunnel Provider 配置可以由配置描述文件创建。**移除动作的主语至少有三个：用户、App、管理方，且各自只能移除自己那一格。**

**其三，状态塌缩。**《NEVPNStatus》第 14 行的 `invalid` 是"配置不存在或未被启用"，第 13 行的 `disconnected` 是"已断开"。配置被移除后状态变成前者，用户手动关掉后是后者。台账若只有一个"通道状态"字段，这两种截然不同的失效就会记成同一个值——这是脚本一 T01 拦的第一件事。第 7 行还给出过程态语义（既有 TCP 连接不被关闭、只被忽略），意味着"移除后流量并没有一个可见的断点"。《NETunnelProviderManager》第 19 行还给出第四种情形：由载荷创建的配置需要把 App 的 bundle id 写进 `VPNSubType` 字段，App 才能用 `NETunnelProviderManager` 管理它——**移除路径的可用性本身由装配格决定**，装配时没写这一格的 App，事后连"由 App 侧移除"这条路径都不存在。

**其四，内核侧的注册注销。**《network_agent.c》的注销路径分三层：会话整体注销（第 1266、1274 行 `netagent_unregister` 及其内部对 `netagent_unregister_all_session_registrations` 的调用；第 1329、1354 行同样调用该函数）、按 UUID 注销单条注册（第 978、1308 行 `netagent_unregister_one_session_registration`）、以及会话退出时的清理（第 938 行）。第 1085 行的 `netagent_registered_count` 递增说明内核维护的是**注册计数**而不是布尔开关。**"一条注册没了"与"这条通道没了"在内核口径里不是同一件事**（脚本一 V02、V05）。

失效侧还有两条时效口径：声明式 always-on 的可用性轴（第 12—18 行）与《Device management restrictions for supervised Apple devices》第 345 行那句限制说明——监督状态变化会改变哪些通道可被装配；以及第 9 章第 255 行 `SCOPED_DIRECT` 那类"作用域随主接口变化"的语义。这两条都不是"到期"，但它们决定一条通道在某一天之后**能不能被重新装配**。

### 13.2 这一层的台账格

| 字段 | 取值域来源 | 缺失后果 |
| --- | --- | --- |
| `undo.removed` | 三条移除路径（命令回执 / `removeFromPreferences` / 内核注销） | 只写"没了"不写走哪条路（V01） |
| `undo.removal_actor` | `user` / `mdm_command` / `mgmt_server` / `extension_self` / `apple` | 主语缺位，无法判定谁的责任（V01） |
| `undo.removal_verified` | 回执（第 21—22 行）与状态（第 14 行）分列 | 回执当核验（V01） |
| `undo.still_carrying` | `status != invalid` 或内核仍在承载 | 记为已移除却仍记为承载中（A07、V02） |
| `undo.revoke_basis` | `receipt` / `removal_command` / `provider_log` / `assumed` / `icon_absent` | 依据为 `assumed` 或 `icon_absent` 时降级（V03） |
| `when.config_expiry` / `when.teardown_at` | 配置有效窗口与移除时刻 | 时效格缺失（T03） |

### 13.3 失败形态

**形态一：用图标消失证明移除。**图标面只在 `packet_tunnel` 与 `transparent_proxy` 两类上 required（第 12.2 节其四），且第 1186 行的显示条件是"connected"而不是"installed"。以图标不在为 `revoke_basis = icon_absent` 的记录，在脚本一里一律降档——它连"曾经存在"都不能证明。

**形态二：把企业通道的唯一性当成移除证明。**《NETunnelProviderManager》第 17 行的"Only one enterprise VPN configuration can be enabled on the system at a time"说的是**启用**唯一性，不是存在唯一性：其他配置可以仍然存在、只是未启用。因此"现在启用的是我们的通道"不能推出"他们的通道已被移除"（V04 拦这一类推论，并要求同时登记两条配置的来源格）。

**形态三：把声明式与描述文件两条来源混成一条。**同一台设备上，同一类通道可能由描述文件装配（`command_plane`）也可能由声明装配（`declarative_plane`），两处的移除是两次操作、两份回执。矩阵里 `declarative_type` 只在三类通道上 required 正是为了不把两侧强行为同一格（D03、P05）。

**形态四：无主体的失效时刻。**第 20 行的 `connectedDate` 记录"变为 connected 的时刻"，但对"最后一次承载流量的时刻"没有任何 API 给出。台账里 `when.teardown_at` 若来自管理服务器的日志，就必须同时登记 `when.time_source = management_server`；若来自设备时钟，则是 `device_clock`——两种来源在同一份台账里混用会让"通道 X 在 Y 时刻后不再承载"这类结论无法核对（T03）。

### 13.4 这一层能支撑与不能支撑的结论

能支撑："这条通道由谁、在哪条路径上被移除，移除动作有没有回执，回执之后设备侧那一格读回什么。"不能支撑："这台设备现在没有任何通道"（七类通道无告知面、内核面非特权不可读）、"这段时间没有流量经过外部通道"（`invalid` 不区分两种情形）、"某条已移除的通道曾经承载过这个 App 的流量"（要范围格与内核结果格同层，且读取需特权）。

---
## 14. L11 公告回查层与缺陷类型学 P1—P14

### 14.1 公告侧的输入与规则

这一层有两个用途：**把公告当作可回查的外部锚点**，以及**把前十一层的失败形态收成一套可命名的缺陷类型学**。

公告侧的输入只有两格可用。脚本二的第三个只读输入是 CSAF 导出件的 `cve` 与 `component` 两列，本轮归档的三份公告（`B/149041.json`、`B/149227.json`、`B/149230.json`）导出 **392 行 CVE 记录、101 个去重组件名**（`C/readings-15.txt` 的 `corpus_rows` 与 `distinct_components`）。按词形实测这一列（大小写不敏感子串，R1）：

| 词形 | 去重组件名命中 | 命中的名字 |
| --- | --- | --- |
| `vpn` `proxy` `tunnel` `filter` `relay` `hotspot` | **0** | — |
| `networkextension` | 1 | NetworkExtension |
| `network` | 1 | NetworkExtension（同上，不是第二个组件） |
| `dns` | 1 | mDNSResponder |
| `wi-fi` | 1 | Wi-Fi |
| `wifi` `tunneling` `interface` `necp` `agent` `configd` | 0 | — |

另两侧也实测过：解决句列（第五列）按十个通道词形匹配**全部为 0**（R2）；影响句列里 "network traffic" 只有第 357 行一条且组件是 `Thread`，"privileged network position" 三条分属 `Baseband`（第 13 行）、`Heimdal`（第 279 行）与 `Wi-Fi`（第 393 行）。也就是说：**这份词表里没有"VPN 通道""代理""网络扩展装配"这类组件**，任何把通道要素读数挂到公告平面的写法都不可回指。

规则因此全部关于回指，不关于缺陷（下表"信号"列用 `一 / 二` 前缀区分两套脚本——两个脚本共用字母族但取值域不同，脚本一的 X01 是"引用缺格"，脚本二的 X01 是"CVE 不在词表"；S、C、D、T、V 五族同理，见第 21、22 章）：

| 信号 | 触发条件 | 阻断 |
| --- | --- | --- |
| 一 X01 | 一条判定缺 `doc.source` 或 `doc.line_ref`，无法回到公开文档逐行核对 | 是（并直接压低判定档） |
| 二 X01 | 台账引用的 CVE 号不在公告词表内 | 是 |
| 二 X02 | 台账引用的组件名归一化后不在公告组件词表内 | 是 |
| 二 X03 | 公告词表整体无可用行：CVE 与组件名两格比对均不可执行 | 是 |
| 二 X04 | 词表可用、六个通道词形命中为 0、却仍有通道要素读数挂在公告平面——按这份词表口径，**缺陷不能归到网络通道组件** | 是（全局一次） |
| 二 X05 | 读数挂在公告平面却没有任何公告标识（公告只给 CVE 与组件名，缺任一格无法回指） | 否 |
| 二 X06 | 把内核符号名当公告组件名登记：`necp`、`netagent`、`content_filter` 这类名字不在这 101 个组件名里 | 是 |

引用锚点在本报告里的正确用法只有一个方向：**用它把一条台账判定钉回公开文档**（`doc.source` + `doc.line_ref`），而不是用它证明"某条通道有漏洞"。第 26 章把"公告组件词表与通道类之间没有任何公开映射"列为第一条未文档化边界。

### 14.2 缺陷类型学 P1—P14

十一层加判定层的失败形态可以合并成 14 种缺陷类型。类型的价值在于**它规定了归属结论最多能写到哪一步**：左列是台账里看得见的特征，右列是这种特征允许的表述上限。

| 类型 | 特征 | 归属结论能写到 | 信号 |
| --- | --- | --- | --- |
| P1 通道主语缺失 | 通道类与权利名两格空或只剩一格；或装配主体与观测平面、结论同时缺 | 只能写"设备上有台账的一行"，不能写"哪条通道、谁装的、谁能看见" | 一 A01 / 一 B01 / 一 J4 |
| P2 权利与通道类错配 | 两串都是公开词表里的值但配对不在词表里；`-systemextension` 变体权利配 `app_extension` 扩展点 | 能定"这一对不成立"，不能定通道此刻是否承载 | 一 A02 / 一 A03 |
| P3 授予路径或提供者缺格 | 有权利名无 `granted_via`；扩展点记为 app_extension 却无提供者标识 | 权利侧无法闭合，只能停在"申报过一项能力" | 一 A04 / 一 A05 |
| P4 内核标识不可回指 | `id.agent_uuid` 非 UUID；`reg.domain` / `reg.type` 超出内核登记的 32 字节上限 | 归属只能停在用户态，进不了第 9 章的内核层 | 一 A06 |
| P5 注册与承载互相否定 | 注册状态 `unregistered` 却记承载中；`requires_assert` 代理配"无断言机制"；captive／热点类通道配网络扩展权利闸门 | 内核层读数整体作废 | 一 A07 / 一 A08 / 一 A09 |
| P6 装配者—载荷—通道三方不符 | 命令面载荷配声明式主体（或反之）；扩展自配却未落到一个载荷／声明类型；类型串与通道类无公开装配关系 | 装配主语不成立，"谁写的这一格"待定 | 一 B02 / 一 B03 / 一 B04 |
| P7 前置与回执缺口 | 范围记"仅受监督"但 `supervised` 为否；无装配回执却写已确认；启用开关为否却记承载中 | 能定"装配动作未被证实"，不能定"通道不存在" | 一 B05 / 一 B06 / 一 B07 |
| P8 触发与断言口径不合 | 按需却零规则；逐连接评估未登记断言机制；只写接口不写范围；常开通道却把界面开关记为可切换；按应用映射却零对数；例外清单未登记却写闭合结论 | 触发与范围两段降级，第 8 章的路由结论不可外发 | 一 C01—C06 |
| P9 内核结果口径漂移 | 结果串不在"十九项 + `INVALID`"的封闭清单；内核 `drop` 与提供者 `allow` 同写；判定来源记为内核策略却无任何注册标识；用三条已弃用的 trigger 系结果表达当前语义；需要权利闸门却记无权利放行 | 内核层归属不成立，只能改写为"读到过一条策略结果" | 一 D01—D05 |
| P10 判定失败取向未登记 | 通道在承载但 `verd.fail_mode` 空；`block_proven` 为否却写已阻断或已确认 | 只能写"判定动作发生过"，不能写"连接被拦下" | 一 D06 / 一 D07 |
| P11 时效与令牌误用 | `invalid` 当承载；过渡态给闭合结论；无核对时刻 `when.audit_at`；一次性代理令牌记为可复用；身份依据取自标注 Requires entitlement 的那两格；读数时刻晚于配置到期 | "此刻在不在通道里"这类回溯表述全部不成立 | 一 T01—T07 |
| P12 观测平面越界 | 无平面却给确认；用状态栏图标闭合归属；把读数挂在管理面状态回报项上；把 sysctl 调试开关当通道存在性证明；启用格与状态格混写且不标时刻；把某格挂到不承载它的平面 | 结论降级为"某个面在某时刻读到过这一格" | 一 O01—O05 / 二 P01—P05 |
| P13 移除与告知未闭环 | 已移除但装配回执空；注销与移除混写且验证为否仍记承载中；失效依据写"应当已失效"；以图标消失作为失效依据；移除主体未登记；以图标可见对外表述 | 只能写"处置动作被登记过"，不能写"这台设备现在没有这条通道" | 一 V01—V05 / 一 N01—N02 |
| P14 公告归属悬空 | 引用不在词表；组件名归一化后不命中；把内核符号名当组件名；通道词形零命中仍有读数挂公告面；挂公告面无标识；缺 `doc` 引用 | 缺陷不能归到网络通道组件，也不能由此反推通道成立 | 一 X01 / 二 X01—X06 |

类型学有三处刻意不做的事。**其一**，不给 14 种类型排严重级：P1 与 P12 在运营上后果完全不同，但都属于"结论不能外发"，脚本一用 J4 与 O01—O05 表达，不用等级。**其二**，不把类型映射到处置动作：处置是第 20 章指标层的事，映射会把归属结论变成工单口径。**其三**，P14 不与其他十三类合并：前十三类是**台账内部**的口径失败，P14 是**台账与外部词表之间**的失败，判定链位置不同——前者改变结论档位（J1—J4），后者只决定这一格能不能对外署名。

还有一处读数缺口要如实登记：P9 里的"已弃用结果"这一条，脚本一只拦 `trigger`、`trigger_if_needed`、`trigger_scoped` 三个取值（`necp.h` 第 247—249 行），而第 250 行的 `NECP_POLICY_RESULT_NO_TRIGGER_SCOPED` 同样标注 `// Deprecated`，却不在该码的取值域里。这不是笔误而是覆盖范围声明：**这一格未拦，属第 26 章边界清单第 7 项**。

### 14.3 唯一落在框架名词上的那一条，和它支撑不了的表述

整份公告语料里，组件名与本篇主题同名的只有一行：《advisory-entries.tsv》第 69 行，CVE-2026-84626，组件 `NetworkExtension`，影响句 "An app may be able to identify what other apps a user has installed"，解决句 "An information disclosure issue was addressed with improved state management."。

这一行能用的方向只有一个：它证明**框架这一层在公开语料里有过一次缺陷**，而且缺陷内容属于本篇 L1／L3（谁被允许声明这条通道、扩展装在哪个 App 里、系统状态管理暴露了什么），**不属于承载、范围、告知或内核注册任何一层**。它支撑不了下面这四类表述：

- "NetworkExtension 有通道承载缺陷"——影响句讲的是 App 清单信息泄露，不是流量走向；
- "这台设备上的这条通道与某条公告相关"——公告给的是产品与版本（本页 `avail` 列给的是机型范围），没有任何一格指向设备侧的通道配置；
- "`Wi-Fi` 组件的公告可以回指到无线接口承载格"——`Wi-Fi` 在这份词表里出现了 6 行（第 95、229、230、391、392、393 行），组件名语义是无线功能面，与 `dd-networkvpnalwayson` 第 31—33 行的 `Interfaces`（Cellular / Wi-Fi 两格）**没有任何映射关系**，这正是第 3.4 节 F7 的实例；
- "`mDNSResponder` 有缺陷所以 DNS 通道不可信"——第 320 行这一条的影响句是 "A remote attacker may be able to leak memory"，与 DNS 代理通道的归属无关。

KEV 侧的读数同样只能限定，不能支撑：全目录 1766 条记录里 `vpn` 出现 61 次、`proxy` 47 次、`dns` 19 次、`tunnel` 6 次、`relay` 2 次、`hotspot` 2 次，但 `networkextension` 与 `content filter` 为 0；**按 Apple 产品记录过滤后（95 条），上述通道词形命中全部为 0，`channel_named_apple_records = 0`**，这 95 条里出现的是 `kernel`（26）与 `sandbox`（3）。产品标签分布为 `Multiple Products` 54、`iOS, iPadOS, and macOS` 11、`iOS` 8、`macOS` 6、`iOS and iPadOS` 5、`iOS, iPadOS, and watchOS` 4、`iOS and macOS` 4、`OS X` 2——没有一条以通道类命名。

因此本层的结论上限是：**公告可以回查"哪一层有过缺陷"，不能回查"你的这条通道凭什么存在、此刻是否在承载"**。后者只有台账十二格加 `doc.line_ref` 能支撑，这正是脚本二把 X 族（除 X05）做成阻断信号而不是提示信号的原因。

---

## 15. 归属矩阵：层 × 责任方 × 形态 × 证据

台账主键是"一条通道对象"（`id.*` 命名空间），因此矩阵的每一行都回答同一组问题：**这一格的读数来自谁、它能证明到哪一步、证据落在哪个公开锚点**。"证据落点"一律给归档相对文件名与行号，脚本一要求每条判定都能以 `doc.source` + `doc.line_ref` 复现（缺则 一 X01）。

| 层 | 第一责任方 | 可归属形态 | 公开证据落点 | 主信号族 |
| --- | --- | --- | --- | --- |
| L1 权利 | 权利申请者（开发者／企业持有者）与审批渠道（Apple 侧） | 这条通道凭什么被允许存在 | networkextension 第 6—17、20、22、25、27 行；vpn.api 第 4、6、9—10 行；ne-framework 第 8—12 行；guide 第 1572 行 | 一 A01—A05 / 一 A09 |
| L2 装配 | MDM 服务器运营者与声明式同步配置者 | 谁写入这一格、走哪条通道写入 | mdm-vpn 第 8、12—17 行；mdm-applayervpn 第 8、13、16—18 行；mdm-apptoapplayervpnmapping 第 8、12 行；mdm-webcontentfilter 第 8、16 行；relay 第 8、12 行；profile-specific-payload-keys 第 83、87、92、105—107、143—145、148 行；install-profile 第 23—24 行；remove-profile 第 21—22 行 | 一 B01—B06 |
| L3 形态 | 扩展构建者与嵌入位置决策者 | 通道装成什么形态、挂在哪个扩展点 | neappextensionconfiguration 第 7、10—13 行；netunnelprovidermanager 第 30—33 行；content-filter-providers 第 24—28 行；ne-framework 第 17—21 行 | 一 A04 / 一 B02 / 二 D06 |
| L4 生效 | 设备运行时（状态机）与按需规则作者 | 此刻它到底在不在跑 | nevpnstatus 第 7、9—14、19—20 行；nevpnmanager 第 10—11、13、15、16—17、19—20 行；neondemandrule 第 8、20—23 行；neondemandruleevaluateconnection 第 4 行 | 一 T01—T03 / 一 C01—C02 / 一 B07 |
| L5 范围 | 路由与例外策略作者（常为同一 MDM 运营者） | 影响到谁、例外给谁 | routing 第 5、20、37、49、57、70、78—79、80—81、84—89 行；netunnelprovidermanager 第 17、19、34—39 行；dd-networkvpnalwayson 第 26—33 行 | 一 C03—C06 / 一 D07 |
| L6 内核 | **无主语**：内核侧有读数但没有装配者；私有权利持有者可读，非特权进程不可读 | 内核认不认这条通道、以哪个代理身份 | necp.h 第 240—258、260、638—643、648—658、671—692 行；necp.c 第 620 行起 26 个 sysctl 节点、第 841—861、956—957、1025—1026、1049、1385、3347、7650—7651、13935 行；network_agent.h 第 144—145、150、153—169、211—218 行；network_agent.c 第 938—1014、1085—1086、1266、1274、2575—2580 行 | 一 A06—A08 / 一 D01—D05 / 一 T04—T06 |
| L7 告知 | 平台（Apple 文档口径），不是任何运营者 | 用户看得见哪一格、看不见哪一格 | status-icons 第 1183—1187、1189 行；dep-restrictions-supervised 第 345 行；dd-networkvpnalwayson 第 27 行；nevpnmanager 第 15、18 行；nerelaymanager 第 14 行 | 一 N01—N02 / 一 O01—O02 / 一 V04 |
| L8 观测平面 | 平面配置者与读数采集者（第 11 章八块平面各有其主） | 这一格由谁、在何时、以什么读法拿回 | status-items 全文（82 行内无网络、代理或网络扩展类回报项）；install-profile 第 23—24 行；remove-profile 第 21—22 行；declarative-management 第 10、21—22 行；devicemanagement-declarations 第 4—71 行（其中通道类 8 条）；necp.c 第 649—668 行 | 一 O03—O05 / 二 P01—P05 |
| L9 通道差异 | 通道选择者（构建与装配决策）与台账建模者 | 这一类通道到底要不要这一格 | networkextension 第 6—17 行；11 类通道的声明页与载荷页可用性轴（逐页行号见第 4—5 章）；psg 第 3809—3815 行；本轮矩阵 211 行、58 项 `required`、19 项 `undocumented`（第 12.1 节） | 二 C01—C06 / 二 D01—D06 |
| L10 移除与失效 | 移除主体三条路径各自的持有者：MDM 命令面、用户界面、会话结束 | 通道没了之后做了什么、谁能证明 | remove-profile 第 21—22 行；nevpnmanager 第 13 行；nerelaymanager 第 9—12 行；netunnelprovidermanager 第 13、21—22、30—33 行；network_agent.c 第 938、978、1266、1274、1308、1329、1354 行 | 一 V01—V05 / 二 V01—V04 |
| L11 公告回查 | 组件所有者（Apple 侧）与回查者（本文读者） | 哪一层在公开语料里有过缺陷 | C/advisory-entries.tsv 全表 392 行／101 组件；第 69 行 CVE-2026-84626；C/readings-15.txt R1—R5、R7 | 一 X01 / 二 X01—X06 |
| 判定层 | 台账维护者 | 这条记录能不能外发、能发到哪一步 | 脚本一第 382—391 行（J1—J4 的判据顺序）；脚本二第 293—296 行（Q1—Q4） | 一 J1—J4 / 二 Q1—Q4 |

矩阵里有四件事值得单独指出。

**第一，L6 一行的责任方写的是"无主语"，这不是排版偷懒。** 第 9 章的实测是双向缺失：内核侧的格由 `PRIV_NET_PRIVILEGED_NECP_POLICIES`（`necp.c` 第 1049、1385、3347、13935 行与 `network_agent.c` 第 2577 行）与 `PRIV_NET_PRIVILEGED_CLIENT_ACCESS`（第 956—957 行）把关，能读到的进程不等于装配这条通道的主体；而管理侧有装配主语（MDM 服务器）却没有任何通道回报项。**所以任何"内核证明这条通道由企业装配"的表述都不成立**，能写的只有"内核侧有一条注册记录，标识是某个 UUID"。

**第二，L7 与 L8 的缺格属平台，不属运营者。** 图标面只覆盖 VPN 一条（status-icons 第 1186 行），管理面回报项清单里没有通道类对象（status-items 全文）。这两件事应当写成**平面建模事实**，而不是"某团队没配置告知"或"某 MDM 产品能力不足"；脚本一因此在 O03 与 V04 的提示语里直接引用文档名，而不是引用配置项。

**第三，L2 与 L10 的责任方不是同一个人。** 装配发生在服务器侧的一次命令下发，移除可能发生在服务器、用户界面或会话结束三处（第 13 章的四条路径）。把两格写成同一个"管理员"会掩盖两类完全不同的处置：撤销一条通道的工单，与验证一台设备此刻是否仍承载的核对。

**第四，L11 一行是外生的。** 公告只在你主动回查时参与归属，它不进入任何判定链：J1—J4 的升降不看公告，Q1—Q4 的升降也不看公告是否命中，公告只决定"这一格能不能对外署名"。这也是脚本二把 X 族与 D 族分开列出、而不把 X 族并入差集计算的原因。

---
## 16. 公开读数：这条通路上能数出来的十八件事

以下 18 条是本报告写作时可复核的公开读数，全部给出计数对象与来源。除注明外，文档行号指向本报告归档的纯文本抽取件；计数由第 21、22 章两个脚本与 `C/readings-15.txt` 的生成过程在本地离线产出（R1—R9 分段）。

1. **公告语料的规模与六个通道词形**：三份 CSAF 公告导出件（`B/149041.json`、`B/149227.json`、`B/149230.json`）共 **392 行 CVE 记录、101 个去重组件名**。组件名列按子串匹配，`vpn`、`proxy`、`tunnel`、`filter`、`relay`、`hotspot` **命中全部为 0**（R1）。
2. **唯一与框架同名的那一条**：`NetworkExtension` 命中 1 个组件名，即 《advisory-entries.tsv》第 69 行的 CVE-2026-84626；`dns` 命中 1 个（第 320 行的 `mDNSResponder`）；`wi-fi` 命中 1 个名字（`Wi-Fi`）但覆盖 6 行（第 95、229、230、391、392、393 行）；`network` 与 `networkextension` 命中的是同一个组件名，不是两个。
3. **解决句与影响句的词形读数**：解决句列按十个通道词形匹配全部为 0（R2）。影响句列（第 4 列）的计数口径是「组件＋影响句原文＋来源公告文件」三元组去重后的条数——同一条影响句在两份公告文件里逐字重复时各计一次，同一文件内同组件同句只计一次；R3 段落把去重后的每一条都原文列了出来。按这一口径："network traffic" 1 条（《advisory-entries.tsv》第 357 行，组件 `Thread`），"privileged network position" 3 条（第 13 行 `Baseband`、第 279 行 `Heimdal`、第 393 行 `Wi-Fi`），"root privileges" 2 条（组件均为 `Kernel`），"elevated privileges" 1 条（第 350 行，组件 `Spotlight`），"proximity" 6 条（原始匹配 8 行，去重掉同文件内的 2 行重复），"arbitrary code" 14 条（原始匹配 22 行）（R3）。**这 14 条的组件名分布为 WebKit 家族 7 条（`WebKit`、`WebKit Canvas`、`WebKit JavaScript Bindings`、`WebKit Process Model`）、`CoreMedia` 2 条，`ImageIO`、`Bluetooth`、`Core Bluetooth`、`AVEVideoEncoder`、`Kernel` 各 1 条；没有一条的组件名属于本文的通道类（VPN、代理、内容过滤、DNS 设置、网络中继）。**
4. **整行范围内通道对象短语的命中**：把第 3—6 列拼起来匹配 13 个通道对象短语，`packet tunnel`、`per-app`、`content filter`、`url filter`、`dns proxy`、`private relay`、`network extension`、`configuration profile`、`supervised`、`bundle identifier`、`vpn` **命中 0 行**；只有 `keychain` 命中 1 行、`entitlement` 命中 10 行，且这 11 行的组件名都不属于网络通道（R4）。
5. **KEV 的两层读数**：目录版本 2026.10.30，共 **1766 条**记录，其中 Apple 产品 **95 条**。全目录出现次数：`vpn` 61、`proxy` 47、`dns` 19、`tunnel` 6、`relay` 2、`hotspot` 2、`sandbox` 53，而 `networkextension`、`content filter`、`wi-fi`、`entitlement` 为 0。按 Apple 产品记录过滤后，`vpn`、`proxy`、`tunnel`、`filter`、`content-filter`、`relay`、`hotspot`、`dns`、`networkextension`、`wi-fi` **命中全部为 0**（`channel_named_apple_records = 0`），这 95 条里出现的是 `kernel`（26）与 `sandbox`（3）。Apple 记录的产品标签分布为 `Multiple Products` 54、`iOS, iPadOS, and macOS` 11、`iOS` 8、`macOS` 6、`iOS and iPadOS` 5、`iOS, iPadOS, and watchOS` 4、`iOS and macOS` 4、`OS X` 2（R5、R7）。
6. **权利格的取值域是 12 个而不是 11 个**：`A/com.apple.developer.networking.networkextension.txt` 第 6—17 行列出 12 个取值，其中第 10—13 行与第 16 行是 Developer ID 描述文件专用的 `-systemextension` 变体与 `relay-systemextension`；第 20 行给 App Store／Xcode 路径，第 22 行给 Developer ID 的描述文件步骤，第 25 行给 `entitlements.plist` 步骤；第 27 行的 SEEALSO 指向 Personal VPN。`A/com.apple.developer.networking.vpn.api.txt` 只有 1 个取值（第 6 行 `allow-vpn`），第 9—10 行给可用渠道。
7. **框架侧的功能切分与限制句**：《Network Extension》页第 6—11 行分述 Wi-Fi、个人热点、VPN、网络中继、内容过滤、DNS 六件事，第 12 行给出平台与监督限制句；第 17—21 行给出 Personal VPN／packet tunnel／app proxy／Always-on 四个形态的口径，其中第 17 行对 Personal VPN 的限定是 "Use Personal VPN to create and manage a VPN configuration that uses one of the built-in VPN protocols (IPsec or IKEv2)."。
8. **提供者类只有三个，声明类有八个**：《NEAppExtensionConfiguration》第 11—13 行列出三个配置子类（DNS 代理、过滤器、隧道），第 7 行写明这一类"exists only for use by the framework"；《NETunnelProviderManager》第 32 行把 `ProviderType` 限定为 `packet-tunnel` 与 `app-proxy` 两个取值。两者合起来构成 L3 形态层的封闭取值域。
9. **状态机六态与一格两义**：《NEVPNStatus》第 9—14 行给出 `invalid`／`disconnected`／`connecting`／`connected`／`reasserting`／`disconnecting` 六个取值，第 14 行对 `invalid` 的定义同时包含"配置不存在"与"未启用"两件事；第 7 行给出断开过程的语义，第 19—20 行只给 `status` 与 `connectedDate` 两个读数。《NEVPNManager》第 15 行的 `isEnabled` 是**另一格**，第 19—20 行的 On Demand 又是第三格。
10. **按需规则四类与 per-app 只用一类**：《NEOnDemandRule》第 8 行列出四个子类，第 20—23 行给出四个取值；《Routing your VPN network traffic》第 80 行说明断开规则可被绕过，《NETunnelProviderManager》第 39 行对受托管 App 只使用 `NEOnDemandRuleDisconnect`。管理侧口径：第 30 行 per-app VPN 只能由 MDM 配置，第 31 行 `VPNUUID` 必填，第 35 行每个受托管 App 一条规则，第 36 行的 ASIDE 排除除 Safari 之外的 Apple 系统 App。
11. **判定动作与判定类各自封闭**：《NEFilterDataVerdict》第 9—14 行给出六个动作（`allow()`、`drop()`、`pause()`、`remediateVerdict(withRemediationURLMapKey:remediationButtonTextMapKey:)`、`needRules()`、`init(passBytes:peekBytes:)`），《Filter providers》第 24—28 行给出五个判定类。两套词表都在用户态，与内核的十九项策略结果之间没有任何公开映射（第 3.4 节 F6）。
12. **命令面载荷键有 10 项，命令回执没有状态格**：《Profile-specific payload keys》里通道相关键共 10 项——第 83 行 `DNSSettings`、第 87 行 `Relay`、第 92 行 `ParentalControlsContentFilter`、第 105 行 `DNSProxy`、第 106 行 `GlobalHTTPProxy`、第 107 行 `NetworkProxyConfiguration`、第 143—145 行 `AppLayerVPN`／`AppToAppLayerVPNMapping`／`VPN`、第 148 行 `WebContentFilter`。《InstallProfileCommand》第 23—24 行与《RemoveProfileCommand》第 21—22 行回执的都是装配件，《DeclarativeManagement》第 10 行只说明引擎开关与同步动作、第 21—22 行只给命令与响应两个对象。
13. **可用性轴在各页的位置**：`com.apple.vpn.managed` 第 12 行设备通道含 iOS／macOS／Shared iPad／tvOS／visionOS、第 15 行 `Requires supervision | N/A`；`com.apple.vpn.managed.applayer` 第 13 行含 watchOS、第 16 行 `Requires supervision | watchOS`；`com.apple.vpn.managed.apptoapplayervpnmapping` 第 12 行本轮归档只列 macOS；`com.apple.webcontent-filter` 第 16 行、`com.apple.relay` 第 12 行。声明式侧 always-on 页第 14 行 `Allowed in user enrollment | N/A`、第 18 行 `Apply | Only a single configuration is applied`，而 `network.dns-proxy`／`.dns-settings`／`.relay`／`webcontent-filter.plugin` 的 supervised 清单里含 macOS。
14. **声明式类型串只覆盖 8／11 类通道**：《Declarations》页第 4—71 行共 52 条声明类型，其中通道类 8 条——第 28 行 `NetworkDNSProxy`、第 29 行 `NetworkDNSSettings`、第 30 行 `NetworkRelay`、第 31 行 `NetworkVPNAlwaysOn`、第 32 行 `NetworkVPNIKEV2`、第 33 行 `NetworkVPNIPSec`、第 34 行 `NetworkVPNVPNPlugin`、第 52 行 `WebContentFilterPlugin`。**没有 app-proxy、透明代理、URL 过滤器、App 推送与 captive 类声明**，这五类只能走命令面载荷或提供者 API。
15. **管理面状态回报项里没有通道**：《Status items》全文 82 行、13 个分组小节、66 条列表项（其中第 82 行是 `Declarations`），按 `vpn`／`proxy`／`network`／`filter`／`relay`／`dns` 匹配**命中 0**。这条读数与第 14 条相减，给出本篇最重要的一处不对称：**声明式覆盖的 8 类通道有类型串但没有回报项，命令面覆盖的 11 类载荷有回执但没有状态格。**
16. **图标面只有 VPN 一条，而且相邻格允许第三方复用**：《Status bar icons》第 1183—1187 行是相邻五条，其中与通道相关的仅第 1186 行 "VPN. iPhone is connected to a network using VPN."；第 1187 行的网络活动图标官方口径含 "Some third-party apps may also use it to show an active process."；第 1189 行起是"活动会话"第二张表。内容过滤器、DNS 代理、透明代理、网络中继在这份页里没有任何条目。企业侧口径另见《Restrictions for supervised devices》第 345 行的默认开启限制说明。
17. **内核侧的封闭清单与闸门**：策略结果 19 项取值（《necp.h》第 240—258 行，同页第 260 行给出 `NECP_POLICY_RESULT_MAX`），内核结果名表 20 格（《necp.c》第 841—861 行，首格 `"INVALID"`），其中《necp.h》第 247—250 行四条 trigger 系结果标注 `// Deprecated`；客户端动作 31 个定义、28 个不同操作码、最大 32（R6.1），《necp.h》第 641 行的 `ACQUIRE_AGENT_TOKEN` 注释为 "Get a one-time use token from an agent"；同页第 648、649、657、658 行四格标注 `// Requires entitlement`；agent 绑定 7 族参数（《necp.h》第 671—690 行，组成员另见第 691—692 行）；`NETAGENT_MESSAGETYPE_*` 22 个（REGISTER 1 … CLIENT_ERROR 26，R6.4）；`NETAGENT_FLAG_*` 17 个（《network_agent.h》第 153—169 行）、`struct netagent` 7 字段（第 211—218 行，两个字符串字段长度均为 32，第 144—145 行），`NETAGENT_MAX_TOKEN_COUNT` 256（第 150 行）；sysctl 可观测面 26 个节点（《necp.c》第 620 行起：6 只读、20 可写、仅 1 个 ANYBODY 可读）；`PRIV_NET_PRIVILEGED_NECP_POLICIES` 判定 5 处（《necp.c》第 1049、1385、3347、13935 行与《network_agent.c》第 2577 行）、《necp.c》第 956—957 行给出 `PRIV_NET_PRIVILEGED_CLIENT_ACCESS` 与 `PRIV_NET_PRIVILEGED_SERVER_ACCESS` 双判定、`IOTaskHasEntitlement` 的两个权利名在《necp.c》第 7650—7651 行。
18. **矩阵与脚本规模**：本轮可得性矩阵 11 通道类 × 22 要素共 **211 行登记，其中 `required` 58 项、`optional` 95 项、`not_applicable` 39 项、`undocumented` 19 项**（第 12.1 节；这 19 项全部落在 `app_push`、`captive_network`、`relay`、`dns_settings` 四类上，脚本二按第 249 行跳过它们，既不报空洞也不报不适用）；两个脚本的信号码共 **108 个**（脚本一 64、脚本二 44），**全部在本轮环境实跑触发**，共 31 次实跑（14 + 17），运行日志 768 行与 1065 行。脚本一的 codes 夹具给 74 个通道对象、321 条信号行、60 个不同信号码、309 条阻断信号（退出码 1），good 夹具给 2 个对象、0 条信号、J1=2（退出码 0）；脚本二的 codes 夹具给 30 个对象、42 行要素登记、211 行能力表、269 条信号行、38 个不同码、36 条阻断（Q2=22／Q3=5／Q4=3），good 夹具给 4 个对象、0 条信号、Q1=4（R8、R9）。

十八件里，第 1—5 件属公告面、第 6—14 件属权利与装配面、第 15—16 件属观测与告知面、第 17 件属内核面、第 18 件属验收面。**六类通道在第 14、15 两件上同时缺格**：第 12.2 节"其三"给出的那六类——`app_proxy`、`content_filter`（非 plugin 形态，第 14 件里只有 `WebContentFilterPlugin` 一条对应它的 plugin 形态）、`transparent_proxy`、`url_filter`、`app_push`、`captive_network`——在第 14 件里没有声明式类型串；而第 15 件的回报项零命中覆盖全部 11 类通道，所以这六类是"两条装配路径都只有回执、没有状态"交集里最窄的一档。这就是第 26 章边界清单要逐条登记的内容。

---

## 17. 可见性边界：这一层读者能拿到什么

第 15 章矩阵给出的是"能归属到什么"，本章给出另一半：**每一类读者手里实际有什么**。边界写不清，台账就会把"我看不到"写成"不存在"——这正是脚本一的 O03、O04 与脚本二的 P01—P04 要拦的写法。

| 读者 | 能直接拿到的格 | 拿不到、只能推断或必须换平面的格 | 边界依据 |
| --- | --- | --- | --- |
| 扩展开发者本人 | 自己的权利名与取值、授予路径（capability 勾选或描述文件）、提供者类与扩展点、嵌入位置 | 设备上有几条同类通道、别人团队的权利来源、自己这条通道在企业设备上被装配成了哪格 | networkextension 第 20—25 行；neappextensionconfiguration 第 7、11—13 行 |
| 设备使用者 | 设置里的启用开关与名称、状态栏 VPN 图标、"此刻是否已连接"这一格 | 通道的装配者、覆盖范围与例外清单、内核侧是否注册、其余七类通道的任何告知 | nevpnmanager 第 15、18 行；nevpnstatus 第 19—20 行；status-icons 第 1186—1187 行 |
| 组织管理员（持有 MDM 服务器） | 自己下发过的载荷类型串与声明标识、安装／移除命令的回执、声明式同步的应答 | 通道此刻状态、内核注册标识、用户侧图标是否出现、判定结果与 fail-open 取向 | install-profile 第 23—24 行；remove-profile 第 21—22 行；declarative-management 第 10、21—22 行；status-items 全文 |
| 设备侧端点软件（不含特权取证场景） | 提供者 API 面可读的状态、开关、按需规则集合、路由例外清单 | 管理面是否装配过这一格、权利审批的历史状态、内核 sysctl 写入位 | netunnelprovidermanager 第 30—39 行；routing 第 57、86—89 行；necp.c 第 620 行起的 26 个节点中仅 1 个 ANYBODY 可读 |
| 外部审计者／本报告读者 | 全部公开文档口径、三份公告导出件与 KEV 目录读数、本轮矩阵 | 任何单一对象的密钥链内容、载荷正文、设备侧实时状态；**公告面给不出任何通道词形** | 本文档边界：脚本一拒收 `sec.*` 与正文形态取值（K01／K02），脚本二对公告面读数给 X01—X06 |

三条边界值得展开。

**其一，管理面的边界是建模边界，不是权限边界。** 把命令发全、把声明同步到底，回来的仍然只有装配件的回执（第 16 章第 12、15 条）。所以"MDM 读不到通道状态"不是配置疏漏，而是**这块平面没有这一格**；把它写成"权限不够"会导出错误的整改动作（申请更多访问权或换一台 MDM），而正确表述是"要拿通道状态，读数面必须换到提供者 API 侧或设备侧归档"（第 18 章）。脚本二把这条做成 P02 阻断信号。

**其二，内核面的边界是主语边界，不是可读性边界。** 内核确实有读数（第 16 章第 17 条：19 项结果、26 个 sysctl 节点、22 条消息类型、17 个标志位），但这些格子里没有"装配者"这一列——`struct netagent` 的七个字段是 uuid、domain、type、desc、flags、data_size、data，全部是**身份与形态**，不含来源主体。因此"内核证明这条通道由企业装配"这类句式在结构上不成立，能写的只有"内核侧有一条注册记录，其标识是某个 UUID"。脚本一用 A06（uuid 形态）与 D03（判定来源缺注册标识）表达这一缺口。

**其三，告知面的边界是覆盖边界。** 图标面只覆盖 VPN 一条，且相邻的网络活动格官方口径允许第三方复用（第 16 章第 16 条）。这条覆盖缺口是**双向**的：图标不在不能否证通道存在，图标在也不能确证是哪一类通道、覆盖到谁。脚本一用 O02 拦"以图标闭合归属"，N01／N02 拦"以图标可见作对外结论"与"以厂商说法作告知依据"。

一处必须点明的写法陷阱：上表每一行的"拿不到"都不能被合并成一句"这台设备上没有这条通道"。`absent`、`not_recorded` 与留空是三件事（脚本二的 S05 与脚本一的 S02 分别拦住后两种塌缩），而 `unknown` 与 `not_applicable` 又是另外两件事——**只有第 12 章矩阵判定该通道类不需要这一格时，`not_applicable` 才是合法读数**；其余情况下写 `not_applicable` 会落到 二 D03。

---

## 18. 四个读数面：权利侧、装配侧、内核侧、告知侧

同一条通道上的格分布在四个互不相通的读数面上。本章把四个面各自能给什么、不能给什么列清楚，因为第 11 章 L8 的绝大多数越界写法都来自"把某个面的读数当成另一个面的结论"。

### 18.1 权利侧

**能读到**：权利键名与 12 个取值（networkextension 第 6—17 行）、Developer ID 专用的两个 `-systemextension` 变体（第 10—13、16 行）、两条申请路径（第 20 行 App Store／Xcode，第 22 行 Developer ID 描述文件）、`entitlements.plist` 步骤（第 25 行）、SEEALSO 指向 Personal VPN（第 27 行）、`allow-vpn` 这一项独立权利（vpn.api 第 6、9—10 行）与框架侧的功能切分（ne-framework 第 6—12 行）。

**读不到**：设备上有没有装配这条通道、此刻是否在承载、企业侧把它配成了哪个载荷类型。**权利格只回答"被允许"，不回答"已发生"**——这是 一 A05（缺授予路径）与 一 B06（缺回执）两个码分属两层的原因。

**台账映射**：`id.channel_type`、`id.provider_bundle_id`、`id.extension_point`、`ent.name`、`ent.granted_via`、`ent.system_variant`、`ent.provider_gate`。本面是 L1 的唯一直接证据来源。

### 18.2 装配侧

**能读到**：载荷类型串与可用性四轴（mdm-vpn 第 8、12—17 行；mdm-applayervpn 第 8、13、16—18 行；mdm-apptoapplayervpnmapping 第 8、12 行；mdm-webcontentfilter 第 8、16 行；relay 第 8、12 行）、10 项通道载荷键（profile-specific-payload-keys 第 83—148 行）、8 条声明式类型串与各页可用性轴（devicemanagement-declarations 第 28—34、52 行；各声明页第 12—18 行）、两条命令的回执对象（install-profile 第 23—24 行、remove-profile 第 21—22 行）、声明式引擎与同步语义（declarative-management 第 10、21—22 行）、per-app 只能由 MDM 配置（netunnelprovidermanager 第 30 行）与 Always-On 的受监督前提（routing 第 84 行）。

**读不到**：装配之后通道是否启用（那是 `isEnabled`／`UIToggleEnabled` 两格，分属提供者 API 面与声明面）、是否承载流量、内核是否注册。**回执的对象是装配件，不是通道**——把回执读成状态是 一 B06 与 一 O03 的共同来源。

**台账映射**：`asm.actor`、`asm.payload_type`、`asm.scope`、`asm.install_receipt`、`asm.supervised`、`asm.user_consent`，以及公告面之外的 `doc.source` + `doc.line_ref`。本面产出的信号族是 一 B 族与 二 S03／S06。

### 18.3 内核侧

**能读到**（全部为源码口径，无产品文档）：19 项策略结果与 20 格结果名表、四条已弃用的 trigger 系结果、7 族 agent 绑定参数与四个 `// Requires entitlement` 条件格、`ACQUIRE_AGENT_TOKEN` 的一次性语义与六个相邻动作（第 638—643 行）、`struct netagent` 七字段与 32 字节上限、17 个 `NETAGENT_FLAG_*`（含 `REQUIRES_ASSERT` 第 162 行）、22 条消息类型、注册计数与注销路径（network_agent.c 第 1085、1266、1274、1308、1329、1354 行）、agent 清单读取的权利闸门（第 2575—2580 行）与 26 个 sysctl 节点。

**读不到**：这一条注册对应哪一份描述文件、哪一次命令下发、哪个扩展标识；`desc` 字段是 32 字节的自由文本，公开口径不规定它写什么（这正是 一 A06 要求 UUID 而放宽 domain／type 的原因——**只有长度上限是硬约束**）。同一批文件里的 `necp_drop_unentitled_level` 默认值（第 162 行）与 `com.apple.private.necp.drop_all_bypass`（第 1025 行）说明：**内核有丢弃等级，但没有通道归属主语**。

**台账映射**：`reg.agent_uuid`、`reg.domain`、`reg.type`、`reg.registration_state`、`reg.flags_assert`、`verd.kernel_result`、`asrt.mechanism`、`tok.reuse_allowed`、`obs.kernel_sysctl_node`。本面对应 L6，产出的信号族是 一 A06—A09、D 族与 T04—T06。

### 18.4 告知侧

**能读到**：状态栏 VPN 图标那一句（status-icons 第 1186 行）与相邻四格的官方语义（第 1183—1187 行）、活动会话表（第 1189 行起）、设置里的开关与本地化名称（nevpnmanager 第 15、18 行）、声明面的界面开关（dd-networkvpnalwayson 第 27 行 `UIToggleEnabled`）、连接时刻（nevpnstatus 第 20 行）、受监督设备的默认限制口径（dep-restrictions-supervised 第 345 行）。

**读不到**：其余七类通道的任何告知（图标面无条目）、管理面对通道的状态回报（status-items 全文无条目）、判定结果是否真的拦下过连接（第 8 章 fail_mode 与 一 D06）、装配者是谁。**告知面是"用户能看见什么"的面，不是"组织能证明什么"的面**——把前者当后者用是 N01／N02 的判定点。

**台账映射**：`obs.plane`、`obs.field_read`、`obs.command_name`、`when.audit_at`、`when.time_source`、`undo.icon_disappeared`。本面对应 L7 与 L8，产出的信号族是 一 O 族、N 族与 二 P 族。

**四个面之间没有公开换算表。** 这一条是本报告对第 02、03、04、08 篇最直接的补充：那几篇分别在设备状态、抓包可见性、协议密码学与隐私用途声明上处理过"跨面推断"，本章把同样的边界固定在通道归属上——权利侧的取值不等于装配侧的载荷，装配侧的回执不等于内核侧的注册，内核侧的注册不等于告知侧的可见，告知侧的不可见更不等于通道不存在。第 3.4 节的八处换算失败是这四条边界的逐格展开，第 14.2 节的 P1—P14 是它们的可命名形式。

---
## 19. 两套判定模型：J1—J4 与 Q1—Q4

### 19.1 两套模型分管两件事

脚本一与脚本二给出两套四档判定，**它们不是一套的粗化与细化，而是两个不同的问题**：

| | 脚本一 J1—J4 | 脚本二 Q1—Q4 |
| --- | --- | --- |
| 回答的问题 | 这条通道对象的**归属记录**能不能对外表述 | 这条通道类的**可得性差集**能不能对外表述 |
| 判定单位 | 单个通道对象（十二命名空间齐备度 + 阻断条数） | 单个通道对象（差集、平面承载、公告回指三段） |
| 输入 | 一份台账（`<标识>,<字段>,<值>`） | 要素清单 + 通道能力表（+ 公告词表） |
| 主要降级原因 | 关键格缺、口径互相否定 | required 未覆盖、无引用、通道类未建模 |
| 不能判的事 | 这一类通道该不该有这一格 | 这条具体通道的装配者是谁 |

两套之间**没有换算关系**，一个对象可以 J1 同时 Q3（十二格齐备、无阻断，但该类通道的某项 `required` 要素在本对象整格缺失），也可以 Q1 同时 J3（差集干净，但台账没有核对时刻或注册标识）。所以对外表述时必须同时给两个档：`J1/Q3` 的合法句式是"这条通道的归属可确认，但它缺 `mdm_status_item` 这一格"；`Q1/J3` 的句式是"这类通道应当有哪几格已核清，但这条记录本身还不能署名"。

### 19.2 J1—J4：判据与顺序

判据写在脚本一第 382—391 行，顺序本身就是语义（先判主语、再数阻断、最后查关键格）：

| 档 | 触发条件（按代码顺序） | 允许的表述 | 禁止的表述 |
| --- | --- | --- | --- |
| J4 | ①（通道类型或装配主体缺）**且**观测平面与结论同时缺；或 ② 阻断信号不少于 5 条 | "台账里有一行记录" | 任何"谁授权、谁装配、谁能观测、谁负责"的句式 |
| J3（入口一） | 有阻断信号（≥1 条）**且**核对时刻、注册标识、状态三者任一为空 | "这台设备上有一条什么形态的通道" | "谁装的""此刻在不在承载" |
| J2 | 有阻断信号（≥1 条），但上述三格齐备 | 内部处置可用（整改、复核、工单） | 对外归属表述 |
| J3（入口二） | 无阻断，但观测平面、结论、断言机制、内核结果任一为空 | 同 J3 入口一 | 同上 |
| J1 | 身份、权利、注册、装配、触发、断言、判定、令牌、时效、观测、处置、引用十二格齐备且零阻断 | 对外归属表述 | — |

三处顺序设计值得说明。**第一**，J4 的两个入口互相独立：主语缺失直接封顶，不需要累计阻断——一条连通道类都没登记的记录，阻断多少条都不会变成 J2。**第二**，J2 与 J3 的分界不是"轻重"而是**可处置性**：有阻断但核对时刻、注册标识、状态都在，说明差异发生在口径层（可整改）；这三格任一缺失时，连"什么时候、哪一条、什么状态"都没有，处置无从下手。**第三**，J3 的第二入口刻意不设阻断：四个"降级关键格"（`obs.plane`、`doc.conclusion`、`asrt.mechanism`、`verd.kernel_result`）单独缺失都不阻断，但它们决定主语与结论，缺任一格就只值 J3。

### 19.3 Q1—Q4：判据与顺序

判据写在脚本二第 289—292 行，四步短路：

| 档 | 触发条件 | 允许的表述 |
| --- | --- | --- |
| Q4 | 该通道类在能力表里一行都没有；**或**能力表整体无有效行；**或**本对象没有一行要素登记通过形态校验（`subjBad`） | 连"这一类通道应当有哪几格"都定不了 |
| Q2 | 本对象有 ≥1 条阻断信号 | 差集存在互相矛盾，不能作为对外可得性表述 |
| Q3 | 无阻断，但存在 required 覆盖空洞（`holesReq`>0）、required 全数无引用（`reqNoRef`>0）或整段无已读数（`recTot`=0） | 能定覆盖面，不能定"这一格由谁读回" |
| Q1 | 差集、平面可得性与公告词表三段齐备且无阻断 | 可对外表述"这条通道缺哪一格" |

Q4 有三个入口，对应三种"比对根本没法开始"的状态：通道类不在模型里（二 D04）、模型整表不可用（二 C06）、本对象有要素行的通道类或要素名越界（二 S03／S04 置 `subjBad`，见脚本二第 172—174 行）。**Q4 不代表通道有问题，只代表这一格无法比对**——这句话是第 24 章误区第 8 条的内容。

一处需要读者知道的实现事实：全局信号 X04 的标识位是 `-` 而不是某个对象，所以它**不会降低任何对象的档位**，但会计入阻断计数并把退出码置为 1（脚本二第 333—342 行的汇总口径）。设计意图是：公告词表零命中这件事属于词表本身，不该由某一条台账承担，但它必须让整次核验以非零码结束。同理，脚本二的 T03（跨对象口径漂移）与 X03（词表不可用）也挂在 `-` 上。

### 19.4 输出形态与退出码

两个脚本的输出与退出码同构，便于接进同一套核验流程：

- **信号行 → stderr**（`码<TAB>对象<TAB>说明（引用出处）`），判定行 → stdout；`-q` 只保留汇总，仍写 stderr 信号。
- 汇总三行：`通道对象数 / 信号行数 / 判定行数`、`不同信号码 / 阻断信号条数`、`判定分布 J1—J4`（脚本二为 `要素登记行 / 能力表行` 与 `闭合等级 Q1—Q4`），随后逐码计数。
- 退出码：**1** 出现阻断信号；**2** 输入不可用（无参数、文件不可读、列数或参数个数非法）；**0** 其余。判定行本身（J／Q）不计入阻断，所以一份全部为 J4 的台账若不含任何 HB 码，退出码仍为 0——这也是第 23 章要把退出码与档位分别登记的原因。

---

## 20. 运营指标 O1—O10

本章给十个可自算指标。命名上刻意区分：**信号码是两位数字（O01—O05），运营指标是一位数字（O1—O10）**，两者不可互换引用。每个指标都只依赖台账已登记的格，因此**都能由第 21、22 章两个脚本的输出直接算出**，不需要任何设备侧读数。

| 指标 | 定义 | 口径依据 | 计算来源 |
| --- | --- | --- | --- |
| O1 通道台账覆盖率 | 已登记对象数 ÷ 本轮应建模通道类数（11 类，见第 12.1 节） | networkextension 第 6—17 行与 ne-framework 第 8—17 行的通道切分 | 脚本一汇总行 `通道对象数`；脚本二 `通道对象数` 与 二 D04 计数 |
| O2 required 缺读率 | `holesReq` 合计 ÷ `required` 格总数（本轮 58） | 二 D01／D02／D05 三种空洞形态的并集 | 脚本二覆盖矩阵 `required=N 已读数=M 缺:…` |
| O3 引用可回指率 | `reqNoRef == 0` 的对象数 ÷ 对象数 | 一 X01（缺 `doc.source`／`doc.line_ref`）与 二 T02 | 脚本一 X01 计数、脚本二 T02 计数 |
| O4 核对新鲜度 | 读数时刻与 `when.audit_at` 的间隔分布；无核对时刻者单列为不可用 | 一 T03（有状态无基准时刻）与 一 T07（读数晚于配置到期） | 台账 `when.audit_at`／`obs.read_at` 两格，脚本一不输出数值，只输出 T03／T07 |
| O5 内核可回指率 | `id.agent_uuid` 为合法 UUID 且注册状态与承载不矛盾的对象占比 | 一 A06（UUID 形态与 32 字节上限）、一 A07（unregistered 与承载并存） | 脚本一 A06／A07 计数 |
| O6 告知覆盖缺口 | 已装配通道类数 − 图标面覆盖的通道类数（本轮为 1） | status-icons 第 1183—1187 行；第 1186 行唯一 VPN 条目 | 脚本一 N01／O02／V04 计数 + 第 12 章矩阵的 `status_icon` 分布 |
| O7 判定取向登记率 | 承载中对象里 `verd.fail_mode` 非空且非 `unknown`／`not_recorded` 的占比 | 一 D07；routing 第 37、49、85 行的丢包与优先级口径 | 脚本一 D07 计数 ÷ 承载中对象数 |
| O8 例外闭合率 | `asrt.exceptions_listed` 为真且 `asrt.scope` 非空的占比 | 一 C06、二 C 族；routing 第 57、86—89 行 | 脚本一 C06 计数 |
| O9 移除闭环率 | `undo.removed` 为真且 `undo.removal_actor`、`undo.removal_verified` 齐备的占比 | 一 V01／V02／V05；remove-profile 第 21—22 行 | 脚本一 V 族计数 |
| O10 公告误挂率 | 挂在公告平面且引用不可回指的对象数 ÷ 公告面读数对象数；X04 触发时该指标直接标为不可用 | 二 X01／X02／X05／X06 与 X04 的全局立场；C/readings-15.txt R1、R7 | 脚本二 X 族计数与"公告词表读数"行 |

四条使用限制必须与指标同时给出。

**其一，这些指标不改变判定档。** O2 从 0.4 降到 0.1 不会让任何对象从 J3 变 J1；档位只由第 19 章的判据决定。指标是台账维护者的自查节奏，不是对外结论的等级。

**其二，O6 与 O10 的"缺口"是平台事实，不是运营失职。** 图标面覆盖 1 类、管理面回报项 0 项（第 16 章第 15、16 条），任何组织的这两项指标都只能停在缺口值上。把缺口写进整改目标会导出无效动作；正确的动作是**换平面**（第 18 章），即把这两类的读数责任改记到提供者 API 面或设备侧归档，并在台账里写明平面。

**其三，O4 不能给统一阈值。** 通道状态的半衰期取决于按需规则与常开策略：常开通道的判定与断开语义（《Routing your VPN network traffic》第 84—85 行）意味着一次掉线就可能变成丢包，而手动触发的 VPN 配置可能在几天内都不变。所以本报告只规定"必须有核对时刻"（一 T03），不规定"间隔不得超过多久"——后者是第 26 章边界清单里的一项未文档化内容。

**其四，指标分母必须来自矩阵而不是台账行数。** O1、O2 的分母来自 11 类通道与 58 项 `required`（第 12.1 节）；若用"台账里出现的对象数"当分母，覆盖率会被自己写下的行数抬高。这是脚本二的覆盖矩阵每行都同时打印 `required=N` 与 `已读数=M` 的原因：**两个数必须成对出现，单独一个数没有意义。**

---
## 21. 只读核验脚本一：通道归属台账审查器

### 21.1 输入、输出与不做什么

**输入**：一份或多份台账文本，每行一条记录，格式固定为 `<通道对象标识>,<字段名>,<值>` 三列（脚本第 17 行把这句话写进帮助里）。`#` 开头行与空行忽略，行尾 CR 忽略，值里不能含逗号——第 165 行 `NF != 3` 就是这一条的执行处，多列与缺列同样落 `S01`。字段名必须带十二个命名空间之一（`id.` / `ent.` / `reg.` / `asm.` / `trig.` / `asrt.` / `verd.` / `tok.` / `when.` / `obs.` / `undo.` / `doc.`），第十三个 `sec.` 是**拒收用命名空间**：出现在这一空间下的任何字段都直接触发 `K01` 并要求删除该字段（第 177 行）。

**输出**：三段。① 逐条信号写到 stderr，格式 `码\t对象\t说明（公开口径出处）`；② 每个通道对象一行判定（J1—J4）写到 stdout，`-q` 时判定行也不打印（第 395—396 行）；③ 末尾汇总块给出通道对象数、信号行数、判定行数、不同信号码数、阻断信号条数、J1—J4 分布，以及逐码首次出现顺序的计数（第 400—405 行）。

**退出码**：出现阻断信号为 1，输入不可用（无参数、文件不存在）为 2，其余为 0。

**不做什么**（这一节是硬约束，不是免责声明）：不联网；不调用 `networkQuality`、`nectl`、`profiles`、`xcrun` 等任何 Apple 命令行工具——这句话原样写在脚本第 8 行的注释里，也是第 23.1 节"只读实证"检查的对象；不读取设备状态；不读取描述文件或代理配置正文；不修改任何输入文件；唯一写出目标是 `mktemp -d` 创建的临时目录，并在第 46 行的 `trap 'rm -rf "$TMPD"' EXIT INT TERM` 中删除。它不提供任何搭建 VPN 或代理服务器、接入抓包工具、配置中间人、改写代理或 DNS 指向的做法，也不提供任何隐藏通道、规避状态告知、伪造通道判定或绕过管理面审计的手段。取值形态上，脚本对形似共享密钥、PKCS#12、描述文件正文与代理凭据的取值直接判为拒收（`K01`，第 180—183 行），对形似设备绝对路径、内联 base64 或整段载荷正文（含超过 200 字符）的取值同样拒收（`K02`，第 184—187 行）。

### 21.2 十二个命名空间与六十四个字段

台账字段不是自由填写的。`-h` 输出的第 19—31 行列出十二个可用命名空间下的全部 64 个已登记字段名，脚本按取值形态把它们分成四种校验方式：

| 命名空间 | 字段数 | 正文对应层 | 代表字段 |
| --- | --- | --- | --- |
| `id.` | 6 | L1 与 L3 | `channel_type`、`provider_bundle_id`、`agent_uuid` |
| `ent.` | 4 | L1 | `name`、`granted_via`、`system_variant`、`provider_gate` |
| `reg.` | 7 | L6 | `agent_state`、`domain`、`agent_type`、`requires_assert` |
| `asm.` | 7 | L2 与 L3 | `actor`、`payload_type`、`install_receipt`、`enabled_toggle` |
| `trig.` | 5 | L4 | `mode`、`rule_action`、`interface`、`rules_count` |
| `asrt.` | 5 | L5 | `mechanism`、`scope`、`app_exceptions`、`exceptions_listed` |
| `verd.` | 6 | L6 | `kernel_result`、`provider_verdict`、`fail_mode`、`verdict_source` |
| `tok.` | 3 | L6 | `signed_client`、`agent_token`、`identity_basis` |
| `when.` | 7 | L4 与 L8 | `status`、`status_at`、`audit_at`、`config_expiry` |
| `obs.` | 5 | L8 | `plane`、`field_read`、`icon_visible`、`command_name` |
| `undo.` | 5 | L10 | `removed`、`removal_actor`、`removal_verified`、`still_carrying` |
| `doc.` | 4 | 横切 | `source`、`line_ref`、`conclusion`、`notice_basis` |

四种校验方式各自的字段数：**枚举域 29 项**（第 67—95 行的 `DOM`，每一项的允许集合都逐字抄自公开词表，例如 `verd.kernel_result` 的允许集合就是第 9.2 节那十九项结果加 `no_trigger_scoped` 与四个哨兵值）、**布尔 17 项**（第 96—101 行）、**日期 6 项**（第 102—103 行，用 `isISOdt` 判 ISO 8601 形态并检查月日范围）、**数值 3 项**（第 104 行）。剩下 **9 项只做形态校验**：`id.team_id`（10 位字母数字）、`id.agent_uuid`（UUID）、`id.provider_bundle_id`（反向域名）、`id.config_identifier`、`reg.domain` 与 `reg.agent_type`（32 字节上限）、`obs.command_name`、`doc.source`、`doc.line_ref`——这九项在读取阶段各有一条独立判定（第 211—219 行），越界直接落 `A04`／`A06`／`A09`。

### 21.3 信号族分组

| 族 | 检查对象 | 码 | 条数 | 代表判据 |
| --- | --- | --- | --- | --- |
| S | 记录自身形态 | S01—S09 | 9 | 恰好三列、主键非空无空白、命名空间已登记、枚举/布尔/日期/数值取值域、同字段双值（S07）与重复同值（S08） |
| K | 秘密形态拒收 | K01—K02 | 2 | `sec.*` 空间与形似密钥/凭据/载荷正文/设备绝对路径的取值 |
| A | 权利、装配与内核注册（L1/L2/L6） | A01—A09 | 9 | 通道类与权利名缺一（A01）、两者配对关系不在词表里（A02）、`-systemextension` 与扩展点矛盾（A03）、缺提供者标识（A04）、缺授予路径（A05）、UUID 与 32 字节上限（A06）、注销却记承载中（A07）、`requires_assert` 却无断言机制（A08）、热点类却记权利闸门（A09） |
| B | 装配与形态（L2/L3） | B01—B07 | 7 | 装配主体与载荷类型双空（B01）、扩展自配缺载荷类型（B02）、载荷类型与通道类不符（B03）、声明式与命令面载荷串互换（B04）、受监督前提（B05）、回执缺失却写已确认（B06）、开关为否却记承载中（B07） |
| C | 触发与断言（L4/L5） | C01—C06 | 6 | 按需却零条规则（C01）、逐连接评估却无断言机制（C02）、有接口无范围（C03）、常开通道却有可切换开关（C04）、按应用映射却零对（C05）、例外清单未登记却闭合结论（C06） |
| D | 判定与结果口径（L6） | D01—D07 | 7 | 结果串不在十九项词表（D01）、`drop` 与 `allow` 并写（D02）、判定来源为内核却无注册标识（D03）、三条已弃用 `trigger` 系结果（D04）、权利闸门与无权利放行并写（D05）、未证明阻断却写已阻断（D06）、承载中但 `fail_mode` 缺格（D07，不阻断） |
| T | 身份、令牌与时效（L4/L6/L8） | T01—T07 | 7 | `invalid` 却写承载中或已确认（T01）、过渡态给闭合结论（T02）、缺核对时刻（T03）、令牌记为可重复使用（T04）、未走签名校验却闭合身份（T05）、以 `pid`／`uid` 作归属依据（T06）、读数晚于配置到期（T07，不阻断） |
| O | 观测平面（L8） | O01—O05 | 5 | 无平面却"已确认"（O01）、用图标闭合归属（O02）、把读数挂在管理面回报项上（O03）、把内核调试开关当归属读数（O04）、启用格与状态格同时存在（O05，不阻断） |
| V | 失效与处置（L10） | V01—V05 | 5 | 已移除但回执空（V01）、移除已登记、验证为否且仍承载中（V02）、失效依据为"应当已失效"（V03）、以图标消失作失效依据（V04）、已移除但未登记移除主体（V05） |
| N | 告知面（L7） | N01—N02 | 2 | 图标可见闭合对外结论却未登记告知依据（N01）、告知依据为厂商说法（N02） |
| X | 引用（横切） | X01 | 1 | 缺 `doc.source` 或 `doc.line_ref`（每对象必检，第 377—378 行） |
| J | 判定 | J1—J4 | 4 | 见第 19.2 节，判据实现在第 382—391 行 |

合计 **64 个不同信号码**：60 个信号码 + 4 个判定码。60 个信号码里 **56 个计入阻断计数**——第 107 行 `split` 出的那份名单逐项列出这 56 个码，`S08`、`D07`、`O05`、`T07` 四个不在其中，因此只提示不阻断（第 24 章误区 10 用的就是这四个码）。族字母与第 4—13 章的层一一对应，读台账的人可以从码直接跳到章。

### 21.4 四个设计选择

**其一，把"自造字段"定为阻断而不是忽略。** 未登记的字段名给 `S09`（第 179 行），不带命名空间或命名空间未知的给 `S03`（第 176 行）。理由是通道归属表述必须能落到一个有公开口径的格上；如果脚本容忍自由字段，一条 J1 记录可能只是"填了很多没有定义的东西"，判定就失去意义。副作用是台账迁移时需要显式扩表——这恰恰是本文希望发生的：扩表动作会逼出"这一格的公开依据是什么"这个问题，而这个问题在第 26 章有 8 项至今没有答案。

**其二，把防御边界写在取值形态判定里，而不是写在文档注释里。** `K01`／`K02` 在读取阶段就 `next`（第 182、186 行），被拒收的记录不写入 `valof`，因而不进入任何族的判定，也不给 J1。这样"台账不该收代理凭据与载荷正文"不是一句提醒，而是可执行且可验收的分支——第 23.2 节的 R14 就是专门跑这一分支的坏样本：七行密钥／凭据／正文形态取值里，四行命中 `K01`、一行命中 `K02`。

**其三，每条信号自带出处。** 第 115—160 行的 `DOC` 映射共 **46 条**，覆盖 A/B/C/D/T/O/V/N 八个族；没有出处的 14 个码是 S 族九码与 K 族两码（判据是台账自身的形态，不指外部文档）、`X01`（判据是本报告自己的引用规则）与 `T07`／`O05` 两码——后两者刻意借用最近的锚点：`T07` 的出处写 `T03`（第 345 行），`O05` 的出处写 `O04`（第 357 行），因为公开文档里既没有"读数过期阈值"也没有"启用格与状态格的时点关系"。每条判据打印时通过 `src(c)`（第 64 行）在说明末尾追加"（见 <文档> 第 N 行）"，出处指向本报告归档的 `A/` 组 69 份文档抽取、`B/` 组 3 份 CSAF 公告导出件与 7 份 DEP／图标网页抽取（`B/pages/`）以及 `C/` 组 16 份内核源码与公告读数文件（逐份清单见第 28 章）。

**其四，判定的第一档不是"好"，而是"没有主语"。**第 382—383 行把 `J4` 的两个入口写在最前：通道类型与装配主体同缺、或阻断信号不少于 5 条。这一顺序决定了 R1 那份全码夹具里 74 个对象只有 J3 与 J4 两档——一个连主语都定不了的台账不会因为写得长而升档。

### 21.5 脚本全文

```bash
#!/usr/bin/env bash
# channel-ledger-review.sh —— 网络通道归属台账审查器（离线 / 只读 / 不联网 / 不碰设备）
# 输入：一份或多份台账文本，每行一条记录：  <通道对象标识>,<字段名>,<值>
# 输出：逐条信号码（stderr） + 每条通道的四级判定（stdout） + 汇总
# 本脚本只做通道归属判定与口径核对：不含任何搭建 VPN/代理、接入抓包、配置中间人、改写代理或 DNS 指向、
# 隐藏通道、规避状态告知或伪造通道判定的做法；也不提供任何绕过管理面审计的手段。
# 台账里出现共享密钥、身份证书正文、代理凭据或通道载荷正文时直接触发 K01/K02 并要求删除该字段。
# 本脚本不联网、不调用 networkQuality/nectl/profiles/xcrun 等任何命令行工具、不读取设备状态、不修改输入文件；
# 唯一写出目标是 mktemp -d 创建的临时目录，退出时删除。
set -u
LC_ALL=C; export LC_ALL

usage() {
  cat <<'EOF'
用法: channel-ledger-review.sh [-q] 台账文件 [...]
  -q  只输出汇总；-h/--help 显示本帮助
台账行格式: <通道对象标识>,<字段名>,<值>    # 开头与空行忽略，行尾 CR 忽略，值里不能含逗号
字段命名空间（十二个 + 一个拒收空间）:
  id.*    通道身份（channel_type / provider_bundle_id / extension_point / agent_uuid / team_id / config_identifier）
  ent.*   权利（name / granted_via / system_variant / provider_gate）
  reg.*   内核注册（agent_state / domain / agent_type / voluntary / requires_assert / specific_use_only / session_alive）
  asm.*   装配（actor / payload_type / scope / install_receipt / user_consent / enabled_toggle / supervised）
  trig.*  触发（mode / rule_action / interface / rules_count / evaluated）
  asrt.*  断言（mechanism / scope / app_exceptions / mapping_pairs / exceptions_listed）
  verd.*  判定（kernel_result / provider_verdict / block_proven / fail_mode / verdict_source / remediation）
  tok.*   身份与令牌（signed_client / agent_token / identity_basis）
  when.*  时效（status / status_at / connected_date / audit_at / config_expiry / teardown_at / time_source）
  obs.*   观测平面（plane / field_read / read_at / icon_visible / command_name）
  undo.*  失效与处置（removed / removal_actor / removal_verified / still_carrying / revoke_basis）
  doc.*   引用与结论（source / line_ref / conclusion / notice_basis）
  sec.*   拒收用命名空间：本空间下任何字段都会触发 K01
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

TMPD=$(mktemp -d "${TMPDIR:-/tmp}/clr.XXXXXX") || { echo "无法创建临时目录" >&2; exit 2; }
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
function isUUID(v)  { return (v ~ /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/) }
function isLineRef(v) { return (v ~ /^[0-9]+(-[0-9]+)?$/) }
function isBundle(v) { return (v ~ /^[A-Za-z0-9][A-Za-z0-9._-]*\.[A-Za-z0-9][A-Za-z0-9._-]*$/ && v !~ /[ ]/) }
function src(c) { return (c in DOC) ? "（" DOC[c] "）" : "" }
BEGIN {
  FS = ","
  DOM["id.channel_type"]=" packet_tunnel app_proxy content_filter url_filter dns_proxy dns_settings relay app_push transparent_proxy captive_network built_in_vpn none not_recorded unknown "
  DOM["id.extension_point"]=" app_extension system_extension mdm_installed built_in not_applicable none not_recorded unknown "
  DOM["ent.name"]=" app-proxy-provider content-filter-provider dns-proxy-provider packet-tunnel-provider url-filter-provider app-push-provider dns-settings relay app-proxy-provider-systemextension content-filter-provider-systemextension dns-proxy-systemextension packet-tunnel-provider-systemextension personal-vpn not_applicable none not_recorded unknown "
  DOM["ent.granted_via"]=" xcode_capability developer_id_profile provisioning_profile built_in_profile none not_recorded unknown "
  DOM["reg.agent_state"]=" registered unregistered kernel_activated user_activated not_registered not_applicable none not_recorded unknown "
  DOM["asm.actor"]=" user_manual mdm_command mdm_declaration dep_profile enterprise_app app_self extension_self_config not_applicable none not_recorded unknown "
  DOM["asm.payload_type"]=" com.apple.vpn.managed com.apple.vpn.managed.applayer com.apple.vpn.managed.appmapping com.apple.webcontent-filter com.apple.relay.managed com.apple.wifi.managed com.apple.configuration.network.vpn.always-on com.apple.configuration.network.vpn.ikev2 com.apple.configuration.network.vpn.ipsec com.apple.configuration.network.vpn.vpn-plugin com.apple.configuration.network.dns-proxy com.apple.configuration.network.dns-settings com.apple.configuration.network.relay com.apple.configuration.webcontent-filter.plugin not_applicable none not_recorded unknown "
  DOM["asm.scope"]=" device user supervised_only system_scope local_install not_applicable none not_recorded unknown "
  DOM["asm.install_receipt"]=" acknowledged error in_progress unsupported not_returned not_polled not_applicable none not_recorded unknown "
  DOM["trig.mode"]=" on_demand always_on manual auto_connect not_applicable none not_recorded unknown "
  DOM["trig.rule_action"]=" connect evaluate_connection disconnect ignore not_applicable none not_recorded unknown "
  DOM["trig.interface"]=" wifi cellular both any not_applicable none not_recorded unknown "
  DOM["asrt.mechanism"]=" necp_assert per_app_mapping included_routes excluded_routes app_rules captive_plugin_list exception_list none not_applicable not_recorded unknown "
  DOM["asrt.scope"]=" all_flows selected_flows scoped_direct primary_interface none not_applicable not_recorded unknown "
  DOM["verd.kernel_result"]=" pass skip drop socket_divert socket_filter ip_tunnel ip_filter trigger trigger_if_needed trigger_scoped no_trigger_scoped socket_scoped route_rules use_netagent netagent_scoped scoped_direct allow_unentitled remove_netagent remove_netagent_type not_applicable none not_recorded unknown "
  DOM["verd.provider_verdict"]=" allow deny more_data ignore dismiss remediation not_applicable none not_recorded unknown "
  DOM["verd.fail_mode"]=" fail_open fail_closed not_determinable not_applicable not_recorded unknown "
  DOM["verd.verdict_source"]=" provider_extension kernel_policy system_routing_table apple_default none not_recorded unknown "
  DOM["verd.remediation"]=" web_block_page append_notice none not_applicable not_recorded unknown "
  DOM["tok.agent_token"]=" one_time multi none not_applicable not_recorded unknown "
  DOM["tok.identity_basis"]=" bundle_id team_id agent_uuid signed_client_id application_uuid real_application_uuid application_id pid uid none not_recorded unknown "
  DOM["when.status"]=" invalid disconnected connecting connected reasserting disconnecting not_applicable not_recorded unknown "
  DOM["when.time_source"]=" device_clock server_log provider_log management_server none not_applicable not_recorded unknown "
  DOM["obs.plane"]=" status_icon mdm_command mdm_status_item declarative_status provider_api kernel_sysctl advisory none not_recorded unknown "
  DOM["obs.field_read"]=" status_bool enabled_toggle identifier install_receipt icon_visible agent_uuid kernel_result channel_name none not_recorded unknown "
  DOM["undo.removal_actor"]=" user mdm_command mgmt_server extension_self apple none not_recorded unknown "
  DOM["undo.revoke_basis"]=" receipt removal_command provider_log assumed icon_absent not_applicable not_recorded unknown "
  DOM["doc.conclusion"]=" confirmed absent_in_channel not_determinable assumed not_recorded unknown "
  DOM["doc.notice_basis"]=" official_icon official_text vendor_claim none not_applicable not_recorded unknown "
  BOOL["ent.system_variant"]=1; BOOL["ent.provider_gate"]=1
  BOOL["reg.voluntary"]=1; BOOL["reg.requires_assert"]=1; BOOL["reg.specific_use_only"]=1; BOOL["reg.session_alive"]=1
  BOOL["asm.user_consent"]=1; BOOL["asm.enabled_toggle"]=1; BOOL["asm.supervised"]=1
  BOOL["trig.evaluated"]=1; BOOL["asrt.exceptions_listed"]=1
  BOOL["verd.block_proven"]=1; BOOL["tok.signed_client"]=1
  BOOL["obs.icon_visible"]=1; BOOL["undo.removed"]=1; BOOL["undo.removal_verified"]=1; BOOL["undo.still_carrying"]=1
  DT["when.status_at"]=1; DT["when.connected_date"]=1; DT["when.audit_at"]=1; DT["when.config_expiry"]=1
  DT["when.teardown_at"]=1; DT["obs.read_at"]=1
  NUM["trig.rules_count"]=1; NUM["asrt.app_exceptions"]=1; NUM["asrt.mapping_pairs"]=1
  NS["id"]=1; NS["ent"]=1; NS["reg"]=1; NS["asm"]=1; NS["trig"]=1; NS["asrt"]=1
  NS["verd"]=1; NS["tok"]=1; NS["when"]=1; NS["obs"]=1; NS["undo"]=1; NS["doc"]=1; NS["sec"]=1
  split("S01 S02 S03 S04 S05 S06 S07 S09 K01 K02 A01 A02 A03 A04 A05 A06 A07 A08 A09 B01 B02 B03 B04 B05 B06 B07 C01 C02 C03 C04 C05 C06 D01 D02 D03 D04 D05 D06 T01 T02 T03 T04 T05 T06 O01 O02 O03 O04 V01 V02 V03 V04 V05 N01 N02 X01", hb, " ")
  for (i in hb) HB[hb[i]] = 1
  split("id.provider_bundle_id id.agent_uuid id.team_id id.config_identifier id.extension_point reg.domain reg.agent_type obs.command_name doc.source doc.line_ref", extra, " ")
  for (i in extra) KNOWN[extra[i]] = 1
  for (f in DOM) KNOWN[f] = 1
  for (f in BOOL) KNOWN[f] = 1
  for (f in DT) KNOWN[f] = 1
  for (f in NUM) KNOWN[f] = 1
  DOC["A01"]="见 com.apple.developer.networking.networkextension 第 7—9 行与 app-proxy-provider 第 10 行"
  DOC["A02"]="见 com.apple.developer.networking.networkextension 第 7—17 行"
  DOC["A03"]="见 com.apple.developer.networking.networkextension 第 10—13、22 行"
  DOC["A04"]="见 ne-framework 第 8、17 行与 nednsproxyprovider 第 10—11 行"
  DOC["A05"]="见 com.apple.developer.networking.networkextension 第 20 行与 adding-capabilities-to-your-app 第 5 行"
  DOC["A06"]="见 C/network_agent.h 第 144—145、213—216 行"
  DOC["A07"]="见 C/network_agent.c 第 1085、1266 行"
  DOC["A08"]="见 C/network_agent.h 第 162 行与 C/necp.h 第 689—690 行"
  DOC["A09"]="见 C/necp.c 第 7650—7651 行"
  DOC["B01"]="见 mdm-vpn 第 9—16 行与 dd-networkvpnalwayson 第 12—18 行"
  DOC["B02"]="见 mdm-vpn 第 8 行、mdm-applayervpn 第 8 行与 relay 第 8 行"
  DOC["B03"]="见 dd-networkvpnalwayson 第 8 行与 dd-webcontentfilterplugin 第 8 行"
  DOC["B04"]="见 install-profile-command 第 23—24 行与 remove-profile-command 第 21—22 行"
  DOC["B05"]="见 dd-networkvpnalwayson 第 12 行与 B/pages/dep-restrictions-supervised 第 345 行"
  DOC["B06"]="见 install-profile-command 第 24 行与 remove-profile-command 第 22 行"
  DOC["B07"]="见 nevpnmanager 第 15 行、nerelaymanager 第 14 行与 dd-networkvpnalwayson 第 27 行"
  DOC["C01"]="见 neondemandrule 第 8、20—23 行"
  DOC["C02"]="见 neondemandrule 第 20—23 行与 neondemandruleevaluateconnection 第 4 行"
  DOC["C03"]="见 dd-networkvpnalwayson 第 28—30 行与 routing-your-vpn-network-traffic 第 70 行"
  DOC["C04"]="见 dd-networkvpnalwayson 第 27 行与 netunnelprovidermanager 第 30 行"
  DOC["C05"]="见 mdm-apptoapplayervpnmapping 第 8、89、125 行"
  DOC["C06"]="见 dd-networkvpnalwayson 讨论节的例外清单口径与 routing-your-vpn-network-traffic 第 37 行"
  DOC["D01"]="见 C/necp.h 第 240—258 行与 C/necp.c 第 841 行起的结果名表"
  DOC["D02"]="见 C/necp.h 第 240—242 行与 content-filter-providers 第 24—28 行"
  DOC["D03"]="见 C/necp.c 第 841 行起的结果名表与 routing-your-vpn-network-traffic 第 37 行"
  DOC["D04"]="见 C/necp.h 第 247—249 行（三条 trigger 系结果标注 Deprecated）"
  DOC["D05"]="见 C/necp.h 第 256 行与 C/necp.c 第 162、627 行"
  DOC["D06"]="见 nefilterdataverdict 第 14 行与 content-filter-providers 第 24—28 行"
  DOC["D07"]="见 routing-your-vpn-network-traffic 第 37 行"
  DOC["T01"]="见 nevpnstatus 第 14 行"
  DOC["T02"]="见 nevpnstatus 第 7、10—12 行"
  DOC["T03"]="见 nevpnstatus 第 20 行"
  DOC["T04"]="见 C/necp.h 第 641 行（one-time use token）"
  DOC["T05"]="见 C/necp.h 第 638—643 行"
  DOC["T06"]="见 C/necp.h 第 648—658 行（四格标注 Requires entitlement）"
  DOC["O01"]="见 B/pages/status-icons 第 1186 行"
  DOC["O02"]="见 B/pages/status-icons 第 1183—1187 行"
  DOC["O03"]="见 status-items 全文（82 行内无网络、代理或网络扩展类回报项）"
  DOC["O04"]="见 C/necp.c 第 649—668、627—629 行"
  DOC["V01"]="见 remove-profile-command 第 22 行"
  DOC["V02"]="见 C/network_agent.c 第 938—1014 行"
  DOC["V03"]="见 B/pages/status-icons 第 1186 行与 nevpnstatus 第 14 行"
  DOC["V04"]="见 netunnelprovidermanager 第 30—33 行"
  DOC["V05"]="见 C/network_agent.c 第 1266、1274 行"
  DOC["N01"]="见 B/pages/status-icons 第 1186 行"
  DOC["N02"]="见 B/pages/status-icons 第 1183—1187 行与 mdm-vpn 第 9—16 行"
}
{ sub(/\r$/, "") }
/^[[:space:]]*#/ { next }
/^[[:space:]]*$/ { next }
NF != 3 { emit("S01", $1, "记录不是恰好三列（<通道对象标识>,<字段名>,<值>）：" $0); next }
{
  id = $1; fld = $2; val = $3
  gsub(/^[[:space:]]+|[[:space:]]+$/, "", id)
  gsub(/^[[:space:]]+|[[:space:]]+$/, "", fld)
  gsub(/^[[:space:]]+|[[:space:]]+$/, "", val)
  if (id == "") { emit("S02", "", "通道对象标识为空"); next }
  if (id ~ /[ \t]/) { emit("S02", id, "通道对象标识内含空白，无法作为台账主键"); next }
  p = index(fld, ".")
  nsp = (p > 1) ? substr(fld, 1, p-1) : ""
  key = (p > 0) ? substr(fld, p+1) : ""
  if (nsp == "" || !(nsp in NS) || key == "") { emit("S03", id, "字段名不带命名空间或命名空间未知：" fld "（十二个可用命名空间见 -h）"); next }
  if (nsp == "sec") { emit("K01", id, "出现 sec.* 命名空间字段（" fld "）：通道台账不收共享密钥、身份证书正文、代理凭据与载荷正文，请删除该字段"); if (!(id in seen)) { seen[id]=1; order[++nid]=id }; next }
  if (!(id in seen)) { seen[id] = 1; order[++nid] = id }
  if (!(fld in KNOWN)) { emit("S09", id, "字段名未登记：" fld "（拼写或自造字段；已登记字段名见 -h 的命名空间清单）"); next }
  if (val ~ /-----BEGIN[ ]?(RSA|EC|PRIVATE|ENCRYPTED)?/ || val ~ /\.(p12|pfx|mobileprovision|provisionprofile)$/ || val ~ /^MI[IEA][A-Za-z0-9+\/=]{40,}/ || val ~ /:<[^@ ]{1,64}@[^> ]+>/ || fld ~ /^id\.shared_secret$/ || val ~ /^[Ss]hared[ _-]?[Ss]ecret[A-Za-z0-9]{8,}/) {
    emit("K01", id, "字段 " fld " 的取值形似共享密钥、PKCS#12、证书正文或描述文件材料：只登记通道标识与形态串")
    next
  }
  if (val ~ /^\/(Applications|private|var\/mobile|Users|Library)\// || val ~ /^file:\/\// || val ~ /^data:[A-Za-z\/+]*;base64,/ || length(val) > 200) {
    emit("K02", id, "字段 " fld " 的取值形似设备绝对路径、内联 base64 或整段载荷正文：台账只登记「哪条通道在什么平面上被读回哪一格」，不登记内容")
    next
  }
  if (val == "" && !(fld == "doc.source" || fld == "doc.line_ref")) { emit("S02", id, "字段 " fld " 取值为空；留空、unknown 与 none 是三件事"); next }
  k = id SUBSEP fld
  if (k in valof) {
    if (valof[k] != val) emit("S07", id, "同一通道对象同一字段出现两个不同值：" fld " = " valof[k] " / " val)
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
      else if (fld == "trig.rules_count" && val+0 > 64) emit("S04", id, "trig.rules_count 超过 64：按需规则清单口径未公开这一档，疑似把整份路由表抄进了格子里" "（见 neondemandrule 第 8 行）")
    }
  } else if (fld == "id.team_id") {
    if (!(val == "not_recorded" || val == "unknown" || val == "not_applicable") && !isTeamID(val)) emit("A09", id, "id.team_id 不是 10 位字母数字串：" val src("A09"))
  } else if (fld == "id.agent_uuid") {
    if (!(val == "not_recorded" || val == "unknown" || val == "not_applicable") && !isUUID(val)) emit("A06", id, "id.agent_uuid 不是 UUID 形态，无法回指内核注册的那一个 netagent：" val src("A06"))
  } else if (fld == "id.provider_bundle_id") {
    if (!(val == "not_recorded" || val == "unknown" || val == "not_applicable" || val == "none") && !isBundle(val)) emit("A04", id, "id.provider_bundle_id 不是反向域名形态的扩展标识：" val src("A04"))
  } else if (fld == "reg.domain" || fld == "reg.agent_type") {
    if (!(val == "not_recorded" || val == "unknown" || val == "not_applicable" || val == "none") && length(val) > 32) emit("A06", id, fld " 超出内核登记的 32 字节上限（NETAGENT_" toupper(fld=="reg.domain"?"DOMAINSIZE":"TYPESIZE") "）：" val src("A06"))
  }
}
END {
  nrec = nid
  for (ix = 1; ix <= nid; ix++) {
    id = order[ix]
    ct   = GV(id,"id.channel_type"); pbi = GV(id,"id.provider_bundle_id"); ept = GV(id,"id.extension_point")
    auuid= GV(id,"id.agent_uuid");   team = GV(id,"id.team_id");           cid = GV(id,"id.config_identifier")
    en   = GV(id,"ent.name"); gv = GV(id,"ent.granted_via"); sv = GV(id,"ent.system_variant"); pg = GV(id,"ent.provider_gate")
    ast  = GV(id,"reg.agent_state"); rdom = GV(id,"reg.domain"); rtyp = GV(id,"reg.agent_type")
    rvol = GV(id,"reg.voluntary"); rass = GV(id,"reg.requires_assert"); rspe = GV(id,"reg.specific_use_only"); ralive = GV(id,"reg.session_alive")
    actor= GV(id,"asm.actor"); ptype = GV(id,"asm.payload_type"); scope = GV(id,"asm.scope")
    rcp  = GV(id,"asm.install_receipt"); cons = GV(id,"asm.user_consent"); tog = GV(id,"asm.enabled_toggle"); sup = GV(id,"asm.supervised")
    mode = GV(id,"trig.mode");raction = GV(id,"trig.rule_action"); tif = GV(id,"trig.interface")
    rcnt = GV(id,"trig.rules_count"); teval = GV(id,"trig.evaluated")
    mech = GV(id,"asrt.mechanism"); ascope = GV(id,"asrt.scope"); aexc = GV(id,"asrt.app_exceptions"); mpairs = GV(id,"asrt.mapping_pairs"); exl = GV(id,"asrt.exceptions_listed")
    kres = GV(id,"verd.kernel_result"); pv = GV(id,"verd.provider_verdict"); bprov = GV(id,"verd.block_proven")
    fmode= GV(id,"verd.fail_mode"); vsrc = GV(id,"verd.verdict_source"); rem = GV(id,"verd.remediation")
    sgn  = GV(id,"tok.signed_client"); tkn = GV(id,"tok.agent_token"); ibasis = GV(id,"tok.identity_basis")
    st   = GV(id,"when.status"); stat = GV(id,"when.status_at"); cdate = GV(id,"when.connected_date")
    at   = GV(id,"when.audit_at"); cexp = GV(id,"when.config_expiry"); td = GV(id,"when.teardown_at"); tsrc = GV(id,"when.time_source")
    pl   = GV(id,"obs.plane"); fread = GV(id,"obs.field_read"); rat = GV(id,"obs.read_at"); icon = GV(id,"obs.icon_visible"); cname = GV(id,"obs.command_name")
    rmed = GV(id,"undo.removed"); ractor = GV(id,"undo.removal_actor"); rveri = GV(id,"undo.removal_verified")
    carry= GV(id,"undo.still_carrying"); rbasis = GV(id,"undo.revoke_basis")
    srcv = GV(id,"doc.source"); lref = GV(id,"doc.line_ref"); con = GV(id,"doc.conclusion"); nb = GV(id,"doc.notice_basis")

    # ---- A 族：权利、装配与内核注册（L1/L2/L6）----
    if (isNA(ct) && isNA(en)) emit("A01", id, "通道类型与权利名两格都空：这条通道凭什么存在于这台设备上，台账里没有主语" src("A01"))
    else if (isNA(ct) || isNA(en)) emit("A01", id, "通道类型或权利名缺格（另一格为 " (isNA(ct) ? en : ct) "）：只给一半无法把通道回指到一项授权" src("A01"))
    pair = ct "|" en
    if (!isNA(ct) && !isNA(en) && en != "not_applicable" && en != "none") {
      okp = 0
      if (ct=="packet_tunnel" && (en=="packet-tunnel-provider"||en=="packet-tunnel-provider-systemextension")) okp=1
      else if (ct=="app_proxy" && (en=="app-proxy-provider"||en=="app-proxy-provider-systemextension")) okp=1
      else if ((ct=="content_filter"||ct=="transparent_proxy") && (en=="content-filter-provider"||en=="content-filter-provider-systemextension")) okp=1
      else if (ct=="url_filter" && en=="url-filter-provider") okp=1
      else if (ct=="dns_proxy" && (en=="dns-proxy-provider"||en=="dns-proxy-systemextension")) okp=1
      else if (ct=="dns_settings" && en=="dns-settings") okp=1
      else if (ct=="relay" && en=="relay") okp=1
      else if (ct=="app_push" && en=="app-push-provider") okp=1
      else if (ct=="built_in_vpn" && en=="personal-vpn") okp=1
      else if (ct=="captive_network" && en=="not_applicable") okp=1
      if (!okp) emit("A02", id, "权利名与通道类不匹配（" ct " 配 " en "）：两串都是公开词表里的值，但配对关系不在词表里" src("A02"))
    }
    if (istrue(sv) && ept=="app_extension") emit("A03", id, "登记了 systemextension 变体权利却把扩展点记为 app_extension：-systemextension 取值按公开口径是「以 Developer ID 描述文件签名」的那一路" src("A03"))
    if (isNA(pbi) && ept=="app_extension") emit("A04", id, "扩展点记为 app_extension 但未登记提供者标识：没有提供者类，通道只能停在配置对象这一层" src("A04"))
    if (!isNA(en) && en != "none" && en != "not_applicable" && isNA(gv))
      emit("A05", id, "登记了权利名但未登记授予路径（granted_via）：App Store 通道与 Developer ID 通道走的是两条不同的启用程序" src("A05"))
    if (!isNA(auuid) && !isUUID(auuid) && auuid != "none" && isNA(auuid)==0)
      emit("A06", id, "内核侧代理标识不是 UUID 形态，无法把通道回指到一次注册：" auuid src("A06"))
    if (ast=="unregistered" && (st=="connected" || istrue(carry)))
      emit("A07", id, "注册状态记为 unregistered 但通道仍记为承载中：注销后内核侧那一条记录已经不在了，两者不能同时为真" src("A07"))
    if (istrue(rass) && mech=="none")
      emit("A08", id, "登记为「需要断言」的内核代理（requires_assert）却把断言机制记为 none：这类代理只在被明确断言时才进入" src("A08"))
    if ((ct=="captive_network" || ptype=="com.apple.wifi.managed") && istrue(pg))
      emit("A09", id, " captive/热点类通道却记为需要网络扩展权利闸门：内核侧对这两类走的是另一项开发者权利" src("A09"))

    # ---- B 族：装配与形态（L2/L3）----
    if (isNA(actor) && isNA(ptype)) emit("B01", id, "装配主体与载荷类型两格都空：谁把这条通道写到这台设备上，台账里没有答案" src("B01"))
    if (!isNA(actor) && actor=="extension_self_config" && isNA(ptype))
      emit("B02", id, "装配主体记为扩展自配但未登记载荷类型：扩展自配仍然要落到一个已登记的载荷类型或声明类型上" src("B02"))
    pairp = ct "|" ptype
    if (!isNA(ct) && !isNA(ptype) && ptype != "none" && ptype != "not_applicable") {
      okq = 0
      if ((ct=="packet_tunnel"||ct=="built_in_vpn"||ct=="app_proxy") && (ptype=="com.apple.vpn.managed"||ptype=="com.apple.configuration.network.vpn.always-on"||ptype=="com.apple.configuration.network.vpn.ikev2"||ptype=="com.apple.configuration.network.vpn.ipsec"||ptype=="com.apple.configuration.network.vpn.vpn-plugin")) okq=1
      else if (ct=="content_filter" && (ptype=="com.apple.webcontent-filter"||ptype=="com.apple.configuration.webcontent-filter.plugin")) okq=1
      else if (ct=="url_filter" && ptype=="com.apple.webcontent-filter") okq=1
      else if (ct=="dns_proxy" && (ptype=="com.apple.configuration.network.dns-proxy"||ptype=="com.apple.vpn.managed")) okq=1
      else if (ct=="dns_settings" && (ptype=="com.apple.configuration.network.dns-settings"||ptype=="com.apple.vpn.managed")) okq=1
      else if (ct=="relay" && (ptype=="com.apple.relay.managed"||ptype=="com.apple.configuration.network.relay")) okq=1
      else if (ct=="app_push" && ptype=="com.apple.vpn.managed") okq=1
      else if (ct=="captive_network" && ptype=="com.apple.wifi.managed") okq=1
      if (!okq) emit("B03", id, "载荷或声明类型与通道类不符（" ct " 配 " ptype "）：这一对在公开口径里没有装配关系" src("B03"))
    }
    if (actor=="mdm_declaration" && ptype ~ /^com\.apple\.(vpn|webcontent-filter|relay|wifi)/) emit("B04", id, "装配主体记为声明式但载荷类型是命令面描述文件载荷：" ptype " 属于命令面，声明式侧另有类型串" src("B04"))
    if (actor=="mdm_command" && ptype ~ /^com\.apple\.configuration\./) emit("B04", id, "装配主体记为命令面但载荷类型是声明式类型串：" ptype " 由声明式管理通道装配，不在命令面载荷清单里" src("B04"))
    if (scope=="supervised_only" && isfalse(sup)) emit("B05", id, "范围记为仅受监督但 supervised 格为否：声明式通道类的可得性以受监督登记为前提" src("B05"))
    if ((rcp=="not_returned" || rcp=="not_polled" || rcp=="error" || rcp=="unsupported") && con=="confirmed")
      emit("B06", id, "装配回执为 " rcp " 却给出「已确认」结论：命令面与声明式都要求设备回给应答，回执缺失时结论没有落点" src("B06"))
    if (isfalse(tog) && (st=="connected" || istrue(carry)))
      emit("B07", id, "启用开关记为否但通道记为承载中：isEnabled / UIToggleEnabled 关掉之后这一格与状态不能并存" src("B07"))

    # ---- C 族：触发与断言（L4/L5）----
    if (mode=="on_demand" && isInt(rcnt) && rcnt+0 == 0)
      emit("C01", id, "触发模式记为按需但规则条数为 0：按需由四类规则实例决定，没有规则就没有触发" src("C01"))
    if (raction=="evaluate_connection" && isNA(mech))
      emit("C02", id, "按需动作记为逐连接评估但未登记断言机制：这一类动作要落到具体的连接归属机制上才有意义" src("C02"))
    if (!isNA(tif) && (st=="connected" || istrue(carry)) && isNA(ascope))
      emit("C03", id, "登记了承载接口但未登记断言范围：接口与范围是两件事，范围决定哪些连接真的进这条通道" src("C03"))
    if (mode=="always_on" && istrue(tog) && actor=="mdm_declaration")
      emit("C04", id, "常开声明式通道却把界面开关记为可切换：常开通道按公开口径只应用一份配置，界面开关与之不是同一层" src("C04"))
    if (mech=="per_app_mapping" && isInt(mpairs) && mpairs+0 == 0)
      emit("C05", id, "断言机制记为按应用映射但映射对数为 0：这一机制的公开口径就是「应用与通道成对登记」" src("C05"))
    if (isfalse(exl) && con=="confirmed" && (st=="connected" || ascope=="all_flows"))
      emit("C06", id, "例外清单未登记却给出闭合结论：例外清单为空与未登记是两件事，未登记时不能宣称全部流量都在这条通道里" src("C06"))

    # ---- D 族：判定与结果口径（L6）----
    if (!isNA(kres) && kres != "not_applicable" && kres != "none" && !(index(DOM["verd.kernel_result"], " " kres " ") > 0))
      emit("D01", id, "内核结果串不在公开结果词表里：" kres "（十九项结果与一项 INVALID 是封闭清单）" src("D01"))
    if (kres=="drop" && pv=="allow")
      emit("D02", id, "内核结果记为 drop 而提供者判定记为 allow：两套口径分属两层，同时写下即互相否定" src("D02"))
    if (vsrc=="kernel_policy" && pv=="allow" && con=="confirmed" && isNA(auuid))
      emit("D03", id, "把判定来源记为内核策略却没有任何注册标识：内核结果只能回指一条策略或一个代理，缺标识时归属悬空" src("D03"))
    if (kres=="trigger" || kres=="trigger_if_needed" || kres=="trigger_scoped")
      emit("D04", id, "结果记为 " kres "：这三条在公开源码里标注为已弃用，不能当作当前生效的触发语义登记" src("D04"))
    if (kres=="allow_unentitled" && istrue(pg))
      emit("D05", id, "通道记为需要权利闸门却给出无权利放行结果：这两格同时为真说明策略归属登记错了层" src("D05"))
    if (isfalse(bprov) && (con=="confirmed" || pv=="deny"))
      emit("D06", id, "阻断未经证明（block_proven 为否）却写下已阻断或已确认：判定动作发生了不等于连接被拦下" src("D06"))
    if (isNA(fmode) && (st=="connected" || istrue(carry)))
      emit("D07", id, "通道在承载但未登记判定失败时的取向（fail_mode）：判定超时的默认取向与系统路由表优先级决定了连接实际去哪" src("D07"))

    # ---- T 族：身份、令牌与时效（L4/L6/L8）----
    if (st=="invalid" && (istrue(carry) || con=="confirmed"))
      emit("T01", id, "状态记为 invalid（配置不在网络扩展偏好里或提供者被禁用）却仍写承载中或已确认" src("T01"))
    if ((st=="connecting" || st=="disconnecting" || st=="reasserting") && con=="confirmed")
      emit("T02", id, "状态处于过渡态 " st " 却给出闭合结论：重连与断开过程中读到的不是稳定归属" src("T02"))
    if (isNA(at) && (!isNA(st) || !isNA(cdate) || !isNA(stat)))
      emit("T03", id, "登记了状态或时刻但没有核对时刻（audit_at）：没有基准时刻，任何「当前在不在通道里」的判定都不成立" src("T03"))
    if (tkn=="multi" && (mech=="necp_assert" || !isNA(auuid)))
      emit("T04", id, "代理令牌记为可重复使用：公开源码写明这一动作取得的是「一次性使用」令牌" src("T04"))
    if (isfalse(sgn) && (ibasis=="signed_client_id" || team != "") && con=="confirmed")
      emit("T05", id, "未走签名与校验动作却把身份闭合到具体应用：认领、签名、校验、取签名标识是四个不同的动作" src("T05"))
    if ((ibasis=="pid" || ibasis=="uid") && istrue(pg))
      emit("T06", id, "身份依据记为 " ibasis "：内核侧这两格标注为需要权利，未登记权利来源时不能作为归属依据" src("T06"))
    if (!isNA(rat) && isISOdt(rat) && !isNA(cexp) && isISOdt(cexp) && stamp(rat) > stamp(cexp) && con=="confirmed")
      emit("T07", id, "读数时刻晚于配置到期却结论为已确认：读到的只能是历史状态" src("T03"))

    # ---- O 族：观测平面（L8）----
    if ((pl=="none" || isNA(pl)) && con=="confirmed")
      emit("O01", id, "观测平面为空或无平面却给出「已确认」：确认结论要有能读回它的那个面" src("O01"))
    if (pl=="status_icon" && con=="confirmed" && (mech=="per_app_mapping" || ascope=="selected_flows"))
      emit("O02", id, "用状态栏图标去闭合通道归属：公开口径那一句只说「已用 VPN 连到网络」，不含通道名、代理类型或例外范围" src("O02"))
    if (pl=="mdm_status_item" && (!isNA(fread)))
      emit("O03", id, "把读数挂在管理面状态回报项上：这份回报项清单里没有网络、代理或网络扩展类对象" src("O03"))
    if (pl=="kernel_sysctl")
      emit("O04", id, "把内核调试开关当作通道归属读数面：这一组开关是策略追踪与丢弃等级的写入位，不是某一通道的存在性证明" src("O04"))
    if (pl=="provider_api" && fread=="enabled_toggle" && !isNA(st))
      emit("O05", id, "同一对象既有提供者接口的启用格又有状态格：两个读数的时点与语义不同，未标读数时刻时容易混写" src("O04"))

    # ---- V 族：失效与处置（L10）----
    if (istrue(rmed) && isNA(rcp) && actor=="mdm_command")
      emit("V01", id, "记为已移除但装配回执格为空：移除动作有对应命令与应答，缺任一格就无法证明处置发生过" src("V01"))
    if (istrue(rmed) && isfalse(rveri) && istrue(carry))
      emit("V02", id, "移除已登记、验证为否且仍记为承载中：注销与移除是两条不同的路径，验证这一格不能靠推测" src("V02"))
    if (rbasis=="assumed" && con=="confirmed")
      emit("V03", id, "失效依据记为「应当已失效」却给出闭合结论：公开口径不给设备侧何时可见" src("V03"))
    if (rbasis=="icon_absent" && (st=="connected" || istrue(carry)))
      emit("V04", id, "以图标消失作为失效依据，但通道状态仍记为承载中：图标不提供通道级可见性承诺" src("V04"))
    if (isNA(ractor) && istrue(rmed))
      emit("V05", id, "记为已移除但未登记移除主体：注册随会话结束自动注销与显式移除，责任方不同" src("V05"))

    # ---- N 族：告知面（L7）----
    if (istrue(icon) && con=="confirmed" && isNA(nb))
      emit("N01", id, "以图标可见闭合对外结论但未登记告知依据：公开口径的那一句只描述连接状态" src("N01"))
    if (nb=="vendor_claim" && con=="confirmed")
      emit("N02", id, "告知依据记为厂商说法却进入对外结论：官方口径的图标说明与载荷可得性表不含这一承诺" src("N02"))

    if (isNA(srcv) || !isLineRef(lref))
      emit("X01", id, "缺来源文件或行号引用（doc.source / doc.line_ref）：这条判定无法回到公开文档逐行核对")

    hard = 0
    for (j = 1; j <= nline; j++) { split(lines[j], sp, "\t"); if (sp[2] == id && (sp[1] in HB)) hard++ }
    if ((isNA(ct) || isNA(actor)) && (isNA(pl) && isNA(con))) grade = "J4"
    else if (hard >= 5) grade = "J4"
    else if (hard >= 1 && (isNA(at) || isNA(auuid) || isNA(st))) grade = "J3"
    else if (hard >= 1) grade = "J2"
    else if (isNA(pl) || isNA(con) || isNA(mech) || isNA(kres)) grade = "J3"
    else grade = "J1"
    if (grade == "J4") emit("J4", id, "通道主语无法确定（通道类型或装配主体与观测平面、结论同缺，或阻断信号不少于 5 条）：不能进入任何「谁授权、谁装配、谁能观测、谁负责」的表述")
    if (grade == "J3") emit("J3", id, "能定「这台设备上有一条什么通道」，不能定「谁装的、此刻在不在承载」：装配主体之外的关键格缺一（核对时刻、注册标识、状态、断言机制、内核结果或观测平面）")
    if (grade == "J2") emit("J2", id, "能定身份与装配，但触发断言、判定口径、时效或处置至少一段有阻断：可用于内部处置，不能作为对外归属表述")
    if (grade == "J1") emit("J1", id, "身份、权利、注册、装配、触发、断言、判定、令牌、时效、观测、处置、引用十二格齐备且无阻断信号：可进入对外归属表述")
    jcount[grade]++
  }

  for (j = 1; j <= nline; j++) { split(lines[j], sp, "\t"); if (sp[1] !~ /^J[1234]$/) print lines[j] > "/dev/stderr" }
  if (!QUIET) for (j = 1; j <= nline; j++) { split(lines[j], sp, "\t"); if (sp[1] ~ /^J[1234]$/) print lines[j] }
  nblk = 0; nc = 0; nsig = 0
  for (j = 1; j <= nline; j++) { split(lines[j], sp, "\t"); if (sp[1] !~ /^J[1234]$/) nsig++ }
  for (c in cnt) { if (c !~ /^J[1234]$/) nc++; if (c in HB) nblk += cnt[c] }
  printf "\n通道对象数=%d 信号行数=%d 判定行数=%d\n", nrec, nsig, nrec
  printf "不同信号码=%d 阻断信号条数=%d\n", nc, nblk
  printf "判定分布 J1=%d J2=%d J3=%d J4=%d\n", jcount["J1"], jcount["J2"], jcount["J3"], jcount["J4"]
  shown = ""
  for (j = 1; j <= nline; j++) { split(lines[j], sp, "\t"); if (sp[1] ~ /^J[1234]$/) continue; if (!(sp[1] in shn)) { shn[sp[1]] = 1; shown = shown sprintf("  %s=%d\n", sp[1], cnt[sp[1]]) } }
  printf "%s", shown
  exit (nblk > 0 ? 1 : 0)
}
' "$@"
```

### 21.6 一次干净台账与一次全码触发

干净台账（`FX/fixture-channel-good.txt`，第 23.2 节的 R2）的实际输出是全部两次运行里唯一 exit 0 的一次：

```text
J1      tun-nyc-01    身份、权利、注册、装配、触发、断言、判定、令牌、时效、观测、处置、引用十二格齐备且无阻断信号：可进入对外归属表述
J1      dns-osa-02    身份、权利、注册、装配、触发、断言、判定、令牌、时效、观测、处置、引用十二格齐备且无阻断信号：可进入对外归属表述

通道对象数=2 信号行数=0 判定行数=2
不同信号码=0 阻断信号条数=0
判定分布 J1=2 J2=0 J3=0 J4=0
$ exit=0
```

这份夹具只有两个对象，但每个对象都把上表十二个命名空间里该填的格填满，包括 `undo.*`（`removed=false`、`removal_actor=not_applicable`）与 `doc.*` 两格。它的价值是给出下界：只要 J1 可达，判定就不是"永远为 J3／J4"的装饰。

全码夹具（`FX/fixture-channel-codes.txt`，R1）的汇总块是：

```text
通道对象数=74 信号行数=321 判定行数=74
不同信号码=60 阻断信号条数=309
判定分布 J1=0 J2=0 J3=7 J4=67
```

`不同信号码=60` 恰好等于全部信号码数，这就是"每个信号码都能被真实触发"的第一层证明；第二层是第 23.6 节用 `FX/code-coverage.pl` 从脚本源码里静态抽出 `emit` 码集合、与 64 码定义表逐一对齐得到的「定义 64 命中 64 未触发 []」。信号行数 321 比阻断条数 309 多出的 12 行，正是四个非阻断码的累计（`D07` 9 次 + `S08`、`O05`、`T07` 各 1 次），两数之差可自证。

---
## 22. 只读核验脚本二：通道要素差集与公告词表比对器

### 22.1 为什么需要第二个脚本

脚本一逐条审查台账，它的判定单位是"一条通道对象"。有三类问题在这一单位下结构上看不见：

1. **覆盖空洞**——某条通道类明确需要的通道要素，台账里一条也没有。逐条审查只能看见"写了的格对不对"，看不见"该写而没写"。
2. **平面越界**——读数挂在某个平面上，但那个平面根本不承载这一格。例如把权利类要素记成"由内核调试开关读回"。
3. **归属悬空**——台账引用的公告标识或组件名，公告组件词表里根本不存在。

这三类都需要把**两份独立登记的清单放在一起算差集**，再加第三份词表做集合归属检查。脚本二因此有三个固定顺序的只读输入，这也是它和脚本一最根本的区别：脚本一的输入是同一种格式的台账可以任意多份，脚本二的三份输入格式各不相同且必须按顺序给全（第 57 行 `[ $# -eq 3 ]`，少一份或多一份都直接 `exit 2`，对应第 23.2 节的 R7—R9 三次运行）。

### 22.2 三份输入与两套词表

**输入一：要素清单**，每行恰好 8 列：`<通道对象标识>,<通道类>,<通道要素>,<登记状态>,<读数平面>,<词表归属>,<引用>,<对外表述>`。取值域写在使用帮助第 26—39 行：11 个通道类加 `none`／`not_recorded`／`unknown` 三个哨兵值共 14 格；**22 个通道要素按五类归属**（权利类 4、内核类 5、装配件类 4、运行类 5、观测类 4，第 85—89 行）；登记状态 5 值、读数平面 13 值、词表归属 9 值、对外表述 4 值。

**输入二：通道能力表**，每行恰好 3 列：`<通道类>,<通道要素>,<可得性>`，可得性四档 `required`／`optional`／`not_applicable`／`undocumented`。本轮这份表是 `FX/capability.csv`，**211 行数据**（第 12.1 节）。

**输入三：公告词表**，制表符分隔的 CSAF 导出形态（`file/cve/component/impact/description/avail` 六列，表头与 `#` 行忽略，第 216—231 行）。脚本只取 `cve` 与 `component` 两格：前者建 CVE 集合，后者经 `nrm()`（第 67 行：转小写并去掉空格、下划线、斜杠、点、冒号、连字符）归一化后**去重**建组件名集合。本轮 `C/advisory-entries.tsv` 读出 **392 行 CVE、101 个去重组件名**。

两套词表之间的对齐关系不靠自由判断，而是脚本里两张显式的允许表：

| 允许表 | 位置 | 条目数 | 内容要点 |
| --- | --- | --- | --- |
| 平面 × 要素类 | 第 96—105 行 | 19 条 `ppair` + 2 条 `pex` | `entitlement_manifest`／`developer_portal` 只给权利类；`kernel_netagent` 只给内核类，`kernel_sysctl` 另可给观测类；`provider_api` 给内核／运行／观测三类，`command_plane` 与 `declarative_plane` 给装配／运行／观测三类；`status_icons` 只给运行与观测两类；`advisory` 只给观测类；`device_settings` 给装配与运行两类。两条 `pex` 是显式例外：`provider_api` 可读 `enabled_toggle`、`device_settings` 可读 `netagent_uuid` |
| 词表归属 × 要素类 | 第 107—109 行 | 9 条 `vpair` | `entitlement_value`→权利类、`kernel_symbol`→内核类与观测类、`payload_key`→装配类与运行类、`declarative_type_string`→装配类、`status_vocabulary`→运行类与观测类、`advisory_component`→观测类 |

P 族拦第一张表，V 族拦第二张表。**两张表里没有的组合不是"未定义"而是会被报出来**——`P05`（第 272 行）与 `V01`—`V03` 收的正是"不在允许清单里却被写下"的那些格。

### 22.3 信号族分组

| 族 | 检查对象 | 码 | 条数 | 代表判据 |
| --- | --- | --- | --- | --- |
| S | 要素清单自身形态 | S01—S09 | 9 | 恰好八列、主键非空无空白、通道类与要素在词表内（S03／S04，两者都会把对象标为 `subjBad`）、四个取值域非法（S05—S07）、重复同值（S08，不阻断）与同要素两种口径（S09） |
| C | 通道能力表自身形态 | C01—C06 | 6 | 恰好三列、通道类／要素／可得性取值域（C02—C04）、同通道同要素两条不同可得性（C05）、**能力表一条有效行都没有**（C06，全局码打在 `-` 上，第 234 行） |
| D | 通道 × 要素差集 | D01—D06 | 6 | required 却明确记为不存在（D01）、required 却未登记（D02，不阻断）、`not_applicable` 却有读数或 `required` 被记为不适用（D03）、本对象整格缺登记行（D05，不阻断）、清单里的通道类在能力表一行都没有（D04）、同一对象登记两个通道类（D06） |
| P | 平面越界 | P01—P05 | 5 | 权利类记为内核调试面或图标面（P01）、通道格记为管理面回报项（P02）、内核侧记录记为描述文件或图标里的格（P03）、已读数但平面为 `none`（P04）、其余平面与要素类不匹配（P05） |
| V | 词表归属混用 | V01—V04 | 4 | `mixed` 却对外表述为是（V01）、用状态词表或公告组件词表描述权利格与装配格（V02）、内核类词表归属写成载荷键或声明类型串（V03）、未登记是否对外（V04，不阻断） |
| X | 公告词表比对 | X01—X06 | 6 | 引用的 CVE 不在词表（X01）、组件名归一化后不在词表（X02）、**词表无可用行→比对不可执行**（X03，第 235 行）、词表可读但通道词形命中为 0 却有读数挂在公告平面（X04，第 237—238 行）、公告面读数缺公告标识（X05，不阻断）、把内核符号名当组件名（X06） |
| T | 引用形态与口径闭合 | T01—T04 | 4 | 引用格形似密钥／凭据／正文／设备绝对路径（T01）、本对象 required 要素引用全为无标识（T02，不阻断）、同通道同要素跨对象既 recorded 又 absent（T03，不阻断）、引用既非 CVE 也非文档行号形态（T04） |
| Q | 闭合等级 | Q1—Q4 | 4 | 见第 19.3 节，判据实现在第 289—292 行 |

合计 **44 个不同信号码**：40 个信号码 + 4 个等级码。第 110—116 行的 `HB` 名单给出 **33 个阻断码**，其余 7 个（`S08`、`D02`、`D05`、`V04`、`X05`、`T02`、`T03`）只提示。**脚本二没有 B 族**——脚本一的 B 族是"装配与形态"，而装配格本身是逐条审查的对象，差集脚本只处理通道×要素这一层，所以第 23.3 与 23.4 节的表里脚本二的码一律带「一／二」前缀以免混读。第 117—160 行的 `DOC` 映射 **44 条**，逐一覆盖全部码（含 Q1—Q4 四个等级码自己的出处）。

### 22.4 四个设计选择

**其一，`undocumented` 这一档不参与差集。** 第 249 行 `if (c2 != ch || av == "undocumented") continue` 把本轮 19 格 `undocumented` 全部跳过：既不报覆盖空洞，也不报不适用。这是刻意的设计而不是偷懒——把它记成 `not_applicable` 会造出"这一格对该类不成立"的假结论，记成 `optional` 会抬高覆盖率，两种写法都比"无法比对"更接近错误（第 12.1 节）。这 19 格的分布与后果登记在第 26 章边界清单。

**其二，全局码与逐对象码分开。** 能力表为空（`C06`）与公告词表不可用（`X03`）都是集合级事实，打在任何通道对象上都会造成虚增；脚本把它们打在标识 `-` 上，同时在第 289 行用 `capChN == 0` 让每个对象落到 `Q4`。R14（能力表为空）就是这一条的实证：**2 条阻断，8 个对象全部 Q4**——阻断条数与档位不是同一个量。

**其三，"比对做不了"与"比对结果为否"用两个码分别表达。** `X03` 只在 `vrows == 0 && compNames == 0` 时打（第 235 行），`X04` 只在 `vrows > 0 && compNames > 0 && chanHits == 0 && advRec > 0` 时打（第 237—238 行）——两个条件互斥，且 `X04` 必须等到词表真的可读、去重组件名非零、并且确实有读数挂在公告平面（`advRec` 由第 81 行 `advCount()` 统计 `statOf==recorded && planeOf==advisory` 的行数）才成立。R3 与 R15 是同一份清单配两份不同词表的对照：阻断条数、七类码、四个档位全部相同，只有 `-` 上那一格从 `X04` 换成 `X03`。**这是第 24 章误区 6 的全部依据。**

**其四，`X06` 与 `X02` 的区别是"认错词表"而不是"查无此名"。** 第 262 行先用一组内核符号前缀（`necp`、`netagent`、`networkagent`、`contentfilter`、`packet.?tunnel`、`vpnnecp`）判定这条引用是不是内核符号名，命中就报 `X06`（"把内核符号名当公告组件名登记"），否则才报 `X02`（归一化后不在词表）。这一区分之所以值得单开一个码，是因为本轮 101 个组件名里确实没有任何 `necp`／`netagent`／`content_filter`（`C/readings-15.txt` 的 R7 段给出内核面组件命中为 0），把源码文件名当组件名是一类可预期的错误，不是笔误。

### 22.5 输出形状

四段，顺序固定：

1. **覆盖矩阵**（第 315—326 行）：每个通道对象一行，`标识\t通道类\trequired=N 已读数=M 缺: …`。本轮 good 夹具的四行是 `required=10 已读数=10 缺:（无）`（packet_tunnel）、`7/7`（dns_proxy）、`6/6`（content_filter）、`5/5`（transparent_proxy），与第 12.1 节矩阵里这四类的 required 清单逐格对得上。
2. **公告词表读数**（第 328 行）：`CVE 行数= 去重组件名= 网络通道词形命中= 挂在公告平面的已读数=` 四个数一行打印。这四个数就是脚本二对第 14 章词表读数的现场复算。
3. **逐条信号**：非 Q 码全部走 stderr，Q1—Q4 走 stdout（`-q` 时整段判定与两段矩阵都不打印，第 314、332 行）。
4. **汇总块**（第 336—341 行）：通道对象数、要素登记行、能力表行、信号行数、不同信号码、阻断条数、Q1—Q4 分布与逐码计数。

`-q` 只压 stdout 的两段（矩阵与等级行，第 314、332 行），stderr 的逐条信号一条不少——因此 R5 汇总里的 264 条信号行是真实信号行数，不是"因为压掉了所以变少"。R5 与 R1 相差的那 5 条来自第二份输入换了文件（R1 用 `capability-bad.csv`，R5 用干净的 `capability.csv`），少掉的正好是 `C01`—`C05`。这一点在表里要对准，否则会把"码集变了"误读成"`-q` 会吞信号"。

### 22.6 脚本全文

```bash
#!/usr/bin/env bash
# channel-availability-diff.sh —— 网络通道×通道要素可得性差集与公告词表比对器（离线 / 只读 / 不联网 / 不碰设备）
# 作用：把三份已登记的清单放在一起算差集，专查逐条审查（channel-ledger-review.sh）查不出的三类问题——
#       「某条通道类明确需要的通道要素，台账里一条也没有」（覆盖空洞）；
#       「读数挂在某个平面上，但那个平面根本不承载这一格」（平面越界）；
#       「台账引用的公告标识或组件名，公告组件词表里不存在」（归属悬空）。
# 输入（顺序固定，三个文件全部只读）：
#   1) 要素清单   每行 8 列：<通道对象标识>,<通道类>,<通道要素>,<登记状态>,<读数平面>,<词表归属>,<引用>,<对外表述>
#   2) 通道能力表 每行 3 列：<通道类>,<通道要素>,<可得性>
#   3) 公告词表   制表符分隔（Apple CSAF 导出形态：file/cve/component/impact/description/avail；
#                 表头与 # 开头行忽略），本脚本只取 CVE 号与组件名两格
# 边界：本脚本不联网取公告、不调用 networkQuality/nectl/profiles/xcrun 等任何命令行工具、
#       不读取载荷正文或凭据、不修改输入文件；只核对三份清单之间是否自洽。
#       给出「覆盖空洞」不等于补登记：补登记需要新的读数来源，本脚本只指出缺哪一格、
#       按公开口径这一格本应由哪个平面给出。唯一写出目标是 mktemp -d 创建的临时目录，退出时删除，
#       本实现不向其写入任何字节。
set -u
LC_ALL=C; export LC_ALL

usage() {
  cat <<'EOF'
用法: channel-availability-diff.sh [-q] 要素清单 通道能力表 公告词表
  -h|--help 显示本帮助；-q 只输出汇总，不逐条打印覆盖矩阵与闭合等级
要素清单行格式（8 列，逗号分隔；# 与空行忽略，行尾 CR 忽略，值里不能含逗号）:
  <通道对象标识>,<通道类>,<通道要素>,<登记状态>,<读数平面>,<词表归属>,<引用>,<对外表述>
通道类（11 + 3）: packet_tunnel app_proxy content_filter url_filter dns_proxy dns_settings
  relay app_push transparent_proxy captive_network built_in_vpn none not_recorded unknown
通道要素（22 项，按五类归属）:
  grant     provider_entitlement_value entitlement_approval provider_class_gate personal_vpn_api
  kernel    netagent_registration netagent_uuid signed_client_identity agent_token necp_policy_result
  assemble  payload_type declarative_type install_receipt enabled_toggle
  run       on_demand_rule_set routing_scope user_consent vpn_status verdict_fail_mode
  observe   status_icon mdm_status_item kernel_sysctl_node advisory_component
登记状态: recorded absent not_applicable not_recorded unknown
读数平面: entitlement_manifest developer_portal kernel_netagent kernel_sysctl provider_api
  command_plane declarative_plane status_icons advisory device_settings none not_recorded unknown
词表归属: entitlement_value kernel_symbol payload_key declarative_type_string
  status_vocabulary advisory_component mixed not_recorded unknown
对外表述: yes no not_recorded unknown
引用格: CVE-YYYY-NNNN / TN3125:89 / A/tn3125-...:89 / B/pages/status-icons:1186 /
  none（确认无对应公告）/ not_recorded（未登记）；挂在 advisory 平面时写公告组件名
通道能力表行格式（3 列）: <通道类>,<通道要素>,<可得性>    可得性: required optional not_applicable undocumented
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

TMPD=$(mktemp -d "${TMPDIR:-/tmp}/cad.XXXXXX") || { echo "无法创建临时目录" >&2; exit 2; }
trap 'rm -rf "$TMPD"' EXIT INT TERM

awk -v QUIET="$QUIET" '
function emit(code, id, msg) { cnt[code]++; lines[++nline] = sprintf("%s\t%s\t%s", code, (id==""?"-":id), msg) }
function isNA(v)    { return (v=="" || v=="not_recorded" || v=="unknown") }
function trim(v)    { gsub(/^[[:space:]]+|[[:space:]]+$/, "", v); return v }
function nrm(v,  t) { t = tolower(v); gsub(/[[:space:]_\/.:-]/, "", t); return t }
function isCve(v)   { return (v ~ /^CVE-[0-9]{4}-[0-9]{4,}$/) }
function isDocRef(v){ return (v ~ /^(TN[0-9]{4,5}):[0-9]+(-[0-9]+)?$/) || (v ~ /^[ABC]\/[A-Za-z0-9._\/-]+:[0-9]+(-[0-9]+)?$/) }
function isSecretish(v) {
  return (v ~ /-----BEGIN/ || v ~ /\.(p12|pfx|mobileprovision|provisionprofile|certSigningRequest)$/ || v ~ /^\/(Applications|private|var\/mobile|Users|Library)\// || v ~ /^file:\/\// || v ~ /^data:[A-Za-z\/+]*;base64,/ || length(v) > 200)
}
function src(c) { return (c in DOC) ? "（" DOC[c] "）" : "" }
function ck(a, b) { return a SUBSEP b }
function isBody(line) { return (line !~ /^[[:space:]]*#/ && line !~ /^[[:space:]]*$/) }
function mkset(set, str,  t, i, n) { n = split(str, t, " "); for (i = 1; i <= n; i++) set[t[i]] = 1 }
function mkel(set, cls, str,  t, i, n) { n = split(str, t, " "); for (i = 1; i <= n; i++) { set[t[i]] = 1; ELE[t[i]] = 1; ELCLS[t[i]] = cls } }
function ppair(p, cls) { PAIR[ck(p, cls)] = 1 }
function pex(p, el)    { PAIR[ck(p, el)] = 1 }
function vpair(vw, cls) { PAIR[ck("VW:" vw, cls)] = 1 }
function advCount(  kk, t) { t = 0; for (kk in statOf) if (statOf[kk]=="recorded" && planeOf[kk]=="advisory") t++; return t }
BEGIN {
  FS = ","
  mkset(CH, "packet_tunnel app_proxy content_filter url_filter dns_proxy dns_settings relay app_push transparent_proxy captive_network built_in_vpn none not_recorded unknown")
  mkel(ELE, "grant",    "provider_entitlement_value entitlement_approval provider_class_gate personal_vpn_api")
  mkel(ELE, "kernel",   "netagent_registration netagent_uuid signed_client_identity agent_token necp_policy_result")
  mkel(ELE, "assemble", "payload_type declarative_type install_receipt enabled_toggle")
  mkel(ELE, "run",      "on_demand_rule_set routing_scope user_consent vpn_status verdict_fail_mode")
  mkel(ELE, "observe",  "status_icon mdm_status_item kernel_sysctl_node advisory_component")
  mkset(ST, "recorded absent not_applicable not_recorded unknown")
  mkset(PL, "entitlement_manifest developer_portal kernel_netagent kernel_sysctl provider_api command_plane declarative_plane status_icons advisory device_settings none not_recorded unknown")
  mkset(VW, "entitlement_value kernel_symbol payload_key declarative_type_string status_vocabulary advisory_component mixed not_recorded unknown")
  mkset(OUTW, "yes no not_recorded unknown")
  mkset(AV, "required optional not_applicable undocumented")
  # 平面承载哪一类要素：按公开口径逐格对齐
  ppair("entitlement_manifest","grant"); ppair("developer_portal","grant")
  ppair("kernel_netagent","kernel"); ppair("kernel_sysctl","kernel")
  ppair("kernel_sysctl","observe")
  ppair("provider_api","kernel"); ppair("provider_api","run"); ppair("provider_api","observe")
  ppair("command_plane","assemble"); ppair("command_plane","run"); ppair("command_plane","observe")
  ppair("declarative_plane","assemble"); ppair("declarative_plane","run"); ppair("declarative_plane","observe")
  ppair("status_icons","run"); ppair("status_icons","observe")
  ppair("advisory","observe")
  ppair("device_settings","assemble"); ppair("device_settings","run")
  pex("provider_api","enabled_toggle"); pex("device_settings","netagent_uuid")
  # 词表归属描述哪一类要素
  vpair("entitlement_value","grant"); vpair("kernel_symbol","kernel"); vpair("payload_key","assemble")
  vpair("declarative_type_string","assemble"); vpair("status_vocabulary","run"); vpair("advisory_component","observe")
  vpair("status_vocabulary","observe"); vpair("payload_key","run"); vpair("kernel_symbol","observe")
  HB["S01"]=1; HB["S02"]=1; HB["S03"]=1; HB["S04"]=1; HB["S05"]=1; HB["S06"]=1; HB["S07"]=1; HB["S09"]=1
  HB["C01"]=1; HB["C02"]=1; HB["C03"]=1; HB["C04"]=1; HB["C05"]=1; HB["C06"]=1
  HB["D01"]=1; HB["D03"]=1; HB["D04"]=1; HB["D06"]=1
  HB["P01"]=1; HB["P02"]=1; HB["P03"]=1; HB["P04"]=1; HB["P05"]=1
  HB["V01"]=1; HB["V02"]=1; HB["V03"]=1
  HB["X01"]=1; HB["X02"]=1; HB["X03"]=1; HB["X04"]=1; HB["X06"]=1
  HB["T01"]=1; HB["T04"]=1
  DOC["S01"]="要素清单每行必须恰好八列（标识,通道类,要素,状态,平面,词表,引用,对外）"
  DOC["S02"]="台账主键为空或含空白，无法与通道能力表对齐"
  DOC["S03"]="通道类取值域按公开提供者词表列出，见 com.apple.developer.networking.networkextension 第 7—17 行与 ne-framework 第 8—17 行"
  DOC["S04"]="通道要素词表为本报告五类 22 项，逐项出处见 A/neappextensionconfiguration 第 11—13 行、C/network_agent.h 第 144—216 行、mdm-vpn 第 9—16 行、neondemandrule 第 20—23 行与 B/pages/status-icons 第 1186 行"
  DOC["S05"]="留空、not_recorded 与 absent 是三件事：见 status-items 全文（82 行内无网络、代理或网络扩展类回报项）"
  DOC["S06"]="读数平面取值不在允许集合：见 A/devicemanagement-declarations 第 13—23 行与 A/nevpnstatus 第 7—14 行"
  DOC["S07"]="词表归属或对外表述取值不在允许集合：三套词表分离见 ne-framework 第 8—17 行、C/network_agent.h 第 138—216 行与 dd-networkvpnalwayson 第 12—18 行"
  DOC["S08"]="同一对象同一要素重复登记且三格一致（不阻断，但差集会重复计数）：见 neondemandrule 第 8 行"
  DOC["S09"]="同一对象同一要素出现两种状态、平面或词表归属：口径漂移，见 netunnelprovidermanager 第 30—33 行与 nevpnstatus 第 7—14 行"
  DOC["C01"]="通道能力表每行必须恰好三列（通道类,要素,可得性）"
  DOC["C02"]="能力表里的通道类取值不在允许集合：见 com.apple.developer.networking.networkextension 第 7—17 行"
  DOC["C03"]="能力表里的要素不在 22 项词表内：见 A/neappextensionconfiguration 第 11—13 行"
  DOC["C04"]="可得性取值不在 required/optional/not_applicable/undocumented：见 dd-networkvpnalwayson 第 12—18 行可得性四轴"
  DOC["C05"]="同通道同要素两条不同可得性，差集失去唯一基准：见 dd-webcontentfilterplugin 第 8 行与 dd-networkrelay 第 8 行"
  DOC["C06"]="通道能力表一条有效行都没有：无法计算任何差集"
  DOC["D01"]="required 要素明确登记为不存在：见 C/network_agent.h 第 144—145 行与 mdm-vpn 第 9—16 行"
  DOC["D02"]="required 要素登记为未登记：覆盖空洞，见 nevpnmanager 第 15 行与 status-items 全文"
  DOC["D03"]="not_applicable 要素却被记为已读数，或 required 要素被记为不适用：见 dd-networkdnsproxy 第 12 行与 ne-framework 第 8—17 行"
  DOC["D04"]="清单里的通道类在能力表一行都没有：该通道判据未建模，见 com.apple.developer.networking.networkextension 第 7—17 行"
  DOC["D05"]="required 要素在本对象完全没有登记行：与 D02 不同的第二种空洞形态，见 nednsproxyprovider 第 10—11 行"
  DOC["D06"]="同一对象登记了两个通道类：一条通道只有一个提供者类，见 A/neappextensionconfiguration 第 11—13 行"
  DOC["P01"]="权利类要素记为内核调试面或图标面可读回：见 C/necp.c 第 649—668 行与 B/pages/status-icons 第 1183—1187 行"
  DOC["P02"]="把网络通道格登记为管理面状态回报项：见 status-items 全文（82 行内无网络、代理或网络扩展类回报项）"
  DOC["P03"]="内核侧那一条记录不在描述文件或图标里：见 C/network_agent.c 第 938—1014 行与 mdm-vpn 第 9—16 行"
  DOC["P04"]="记为已读数但平面为无平面：见 nevpnstatus 第 14 行与 A/status-items 第 21 行"
  DOC["P05"]="平面与要素类别不匹配（未列入前四种的组合）：见 devicemanagement-declarations 第 13—23 行"
  DOC["V01"]="对外表述为 yes 却把两套词表混记在同一格：见 ne-framework 第 8—17 行与 C/network_agent.h 第 138—216 行"
  DOC["V02"]="用状态词表或公告组件词表去描述权利格与装配格：见 dd-networkvpnalwayson 第 12—18 行与 C/advisory-entries.tsv 的 component 列口径"
  DOC["V03"]="平台执行口径与授权对象口径混用：见 C/necp.h 第 240—258 行与 com.apple.developer.networking.networkextension 第 7—17 行"
  DOC["V04"]="已读数但未登记这一格是否会对外（不阻断）：见 A/nefilterdataverdict 第 4 行"
  DOC["X01"]="引用的 CVE 号不在公告词表内：见 C/advisory-entries.tsv 的 cve 列"
  DOC["X02"]="引用的组件名归一化后不在公告组件词表内：见 C/advisory-entries.tsv 的 component 列"
  DOC["X03"]="公告词表无可用行：比对不可执行"
  DOC["X04"]="公告组件词表里网络通道词形（vpn、proxy、tunnel、content filter、relay、hotspot）命中为 0，却有读数挂在公告平面：component_absent 立场，见 C/readings-15.txt 的词表读数"
  DOC["X05"]="公告平面读数没有公告标识（不阻断）：见 C/advisory-entries.tsv 的 cve 列"
  DOC["X06"]="把内核符号名当公告组件名登记：这份组件词表里没有 necp、netagent、content_filter 这些名字，见 C/advisory-entries.tsv 的 component 列"
  DOC["T01"]="引用格形似密钥、凭据、载荷正文或设备绝对路径：台账只登记哪条通道在何时读回哪一格，不登记内容"
  DOC["T02"]="该对象所有 required 要素的引用格全为无标识（不阻断）：无任何可回指格，见 A/neappextensionconfiguration 第 11—13 行"
  DOC["T03"]="同通道同要素在对象之间既有 recorded 又有 absent（不阻断）：登记口径未统一，见 netunnelprovidermanager 第 30—33 行"
  DOC["T04"]="引用格既不是 CVE 也不是文档行号形态且平面非公告：这条判定无法回指，见 com.apple.developer.networking.networkextension 第 20 行"
  DOC["Q1"]="差集、平面可得性与公告词表三段齐备且无阻断：见 dd-networkvpnalwayson 第 12—18 行与 C/network_agent.h 第 144—216 行"
  DOC["Q2"]="存在阻断信号：见 status-items 全文与 mdm-vpn 第 9—16 行"
  DOC["Q3"]="只能定覆盖面不能定归属：见 nevpnstatus 第 7—14 行与 C/necp.h 第 240—258 行"
  DOC["Q4"]="连可得性都不能定：见 com.apple.developer.networking.networkextension 第 7—17 行与 devicemanagement-declarations 第 13—23 行"
}

# ---- 输入 1：要素清单 ----
FILENAME == ARGV[1] && isBody($0) {  line = $0; sub(/\r$/, "", line)
  n = split(line, fx, ",")
  if (n != 8) { emit("S01", fx[1], "要素清单记录不是恰好八列：" line src("S01")); next }
  id = trim(fx[1]); ch = trim(fx[2]); el = trim(fx[3]); st = trim(fx[4])
  pl = trim(fx[5]); vw = trim(fx[6]); rf = trim(fx[7]); ow = trim(fx[8])
  if (id == "" || id ~ /[ \t]/) { emit("S02", id, "通道对象标识为空或含空白，无法与能力表对齐" src("S02")); next }
  if (!(id in seen)) { seen[id] = 1; order[++nid] = id; chCnt[id] = 0 }
  subj = 0
  if (!(ch in CH)) { emit("S03", id, "通道类取值不在允许集合：" ch src("S03")); subj = 1 }
  if (!(el in ELE)) { emit("S04", id, "通道要素不在 22 项词表内：" el src("S04")); subj = 1 }
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
  if (isSecretish(rf)) { emit("T01", id, "要素 " el " 的引用格形似密钥、凭据、载荷正文或设备绝对路径：只登记引用标识，不登记内容" src("T01")) }
  else if (!(rf=="none" || isNA(rf) || rf=="") && !isCve(rf) && !isDocRef(rf) && pl != "advisory")
    emit("T04", id, "要素 " el " 的引用格既不是 CVE 也不是文档行号形态：" rf src("T04"))
  next
}

# ---- 输入 2：通道能力表 ----
FILENAME == ARGV[2] && isBody($0) {
  line = $0; sub(/\r$/, "", line)
  n = split(line, fx, ",")
  if (n != 3) { emit("C01", fx[1], "通道能力表记录不是恰好三列：" line src("C01")); next }
  ch = trim(fx[1]); el = trim(fx[2]); av = trim(fx[3])
  if (!(ch in CH)) { emit("C02", ch, "能力表通道类取值不在允许集合：" ch src("C02")); next }
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
      if (cp ~ /[Vv][Pp][Nn]|[Pp]roxy|[Tt]unnel|[Ff]ilter|[Rr]elay|[Hh]otspot/) chanHits++
    }
  }
  next
}

END {
  if (capRows == 0) emit("C06", "-", "通道能力表一条有效行都没有：通道×要素差集无法计算" src("C06"))
  if (vrows == 0 && compNames == 0) emit("X03", "-", "公告词表无可用行：公告标识与组件名比对均不可执行" src("X03"))
  advRec = advCount()
  if (vrows > 0 && compNames > 0 && chanHits == 0 && advRec > 0)
    emit("X04", "-", "公告组件词表去重 " compNames " 个组件、网络通道词形命中 0，却有 " advRec " 条通道要素读数挂在公告平面：按这份词表口径，缺陷不能归到网络通道组件" src("X04"))

  for (ix = 1; ix <= nid; ix++) {
    id = order[ix]
    if (!(id in chSeen)) continue
    ch = chOf[id]
    if (chCnt[id] > 1) emit("D06", id, "同一通道对象登记了 " chCnt[id] " 个通道类：一条通道只有一个提供者类，差集无法定位" src("D06"))
    if (capChN > 0 && !(ch in capChSet)) emit("D04", id, "清单里的通道类 " ch " 在能力表一行都没有：这一类的判据未建模，缺哪一格无从判定" src("D04"))

    for (kk in capOf) {
      split(kk, sp, SUBSEP); c2 = sp[1]; el = sp[2]; av = capOf[kk]
      if (c2 != ch || av == "undocumented") continue
      k = ck(id, el)
      if (!(k in statOf)) {
        if (av == "required") { holesReq[id]++; emit("D05", id, "通道类 " ch " 的 required 要素 " el " 在本对象完全没有登记行" src("D05")) }
        continue
      }
      st = statOf[k]; pl = planeOf[k]; vw = vwOf[k]; rf = refOf[k]; ow = outOf[k]
      cls = ELCLS[el]
      if (av == "required") {
        if (st == "absent") emit("D01", id, "通道类 " ch " 需要 " el "，台账却明确记为不存在" src("D01"))
        else if (isNA(st)) { holesReq[id]++; emit("D02", id, "通道类 " ch " 需要 " el "，台账记为 " st "：这一格没有读数" src("D02")) }
        else if (st == "not_applicable") emit("D03", id, "通道类 " ch " 的 required 要素 " el " 被记为不适用：与能力表冲突" src("D03"))
        if (st == "recorded") { reqTot[id]++; if (isNA(rf) || rf=="none") reqNoRef[id]++ }
        if (st=="recorded" && pl=="advisory") { if (isNA(rf) || rf=="none") { emit("X05", id, "要素 " el " 挂在公告平面却没有公告标识：公告只给 CVE 与组件名，缺任一格就无法回指" src("X05")) } else if (isCve(rf)) { if (!(rf in cves)) emit("X01", id, "引用的 CVE 号 " rf " 不在公告词表内：这份词表里没有这一条" src("X01")) } else { nk = nrm(rf); if (nk ~ /^(necp|netagent|networkagent|contentfilter|packet.?tunnel|vpnnecp)/ && !(nk in comps)) emit("X06", id, "把内核符号名 " rf " 当作公告组件名登记：这份组件词表里没有这个名字" src("X06")) ; else if (!(nk in comps)) emit("X02", id, "引用的组件名 " rf " 归一化后不在公告组件词表内" src("X02")) } }
      }
      if (av == "not_applicable" && st == "recorded")
        emit("D03", id, "通道类 " ch " 的 " el " 在公开口径里不适用，却登记了已读数" src("D03"))
      if (st == "recorded") {
        recTot[id]++
        if (pl == "none") emit("P04", id, "要素 " el " 记为已读数但读数平面为无平面：这一格没有任何能读回它的面" src("P04"))
        else if (cls=="grant" && (pl=="kernel_sysctl" || pl=="status_icons")) emit("P01", id, "权利类要素 " el " 记为 " pl " 读回：内核调试面与状态图标面都不承载权利格" src("P01"))
        else if (el=="mdm_status_item" && pl!="advisory" && pl!="declarative_plane" && pl!="command_plane") emit("P02", id, "把网络通道格登记为管理面状态回报项：这份回报项清单里没有网络、代理或网络扩展类对象" src("P02"))
        else if (cls=="kernel" && (pl=="entitlement_manifest" || pl=="developer_portal" || pl=="status_icons")) emit("P03", id, "内核侧要素 " el " 记为 " pl " 读回：那一条注册记录只存在于内核侧" src("P03"))
        else if (!(ck(pl, cls) in PAIR) && !(ck(pl, el) in PAIR)) emit("P05", id, "平面 " pl " 与要素类 " cls "（" el "）不匹配：这一格不该由这个面给出" src("P05"))
        if (vw=="mixed" && ow=="yes") emit("V01", id, "要素 " el " 对外表述为是却把两套词表混记在同一格：三套词表分属三层" src("V01"))
        else if ((cls=="grant" || cls=="assemble") && (vw=="status_vocabulary" || vw=="advisory_component")) emit("V02", id, "要素 " el " 用状态词表或公告组件词表描述权利格与装配格：词表归属越层" src("V02"))
        else if (cls=="kernel" && (vw=="payload_key" || vw=="declarative_type_string")) emit("V03", id, "内核侧要素 " el " 把词表归属记为 " vw "：平台执行口径与授权对象口径混用" src("V03"))
        if (isNA(ow)) emit("V04", id, "要素 " el " 已读数但未登记这一格是否会对外（不阻断）" src("V04"))
        if (pl=="advisory" && !isNA(rf) && rf!="none" && !isCve(rf)) { nk = nrm(rf); if (!(nk in comps) && nk !~ /^(necp|netagent|networkagent|contentfilter|packet.?tunnel|vpnnecp)/) emit("X02", id, "要素 " el " 引用的组件名 " rf " 归一化后不在公告组件词表内" src("X02")) }
      }
    }
  }

  # 差集二：清单里有、能力表未建模的通道类已在上方 D04 给出；此处补对象级引用缺失
  for (ix = 1; ix <= nid; ix++) {
    id = order[ix]
    if (reqTot[id] > 0 && reqTot[id] == reqNoRef[id])
      emit("T02", id, "本对象 " reqTot[id] " 项 required 要素的引用格全为无标识：结论无法回指任何一格" src("T02"))
    hard = 0
    for (j = 1; j <= nline; j++) { split(lines[j], sp, "\t"); if (sp[2] == id && (sp[1] in HB)) hard++ }
    if (!(chOf[id] in capChSet) || capChN == 0 || subjBad[id] == 1) grade = "Q4"
    else if (hard >= 1) grade = "Q2"
    else if (holesReq[id] > 0 || reqNoRef[id] > 0 || recTot[id] == 0) grade = "Q3"
    else grade = "Q1"
    if (grade == "Q4") emit("Q4", id, "连可得性都不能定：该通道类在能力表里没有任何一行，或本对象没有一行能通过形态校验")
    if (grade == "Q3") emit("Q3", id, "只能定「这一类通道应当有哪几格」，不能定「这一格由谁读回」：存在覆盖空洞、无引用或整段缺读数")
    if (grade == "Q2") emit("Q2", id, "存在阻断信号：差集、平面可得性或公告词表至少一段互相矛盾，不能作为对外可得性表述")
    if (grade == "Q1") emit("Q1", id, "差集、平面可得性与公告词表三段齐备且无阻断：可用于对外表述这条通道缺哪一格")
    qcount[grade]++
  }

  # 口径漂移：同通道同要素在对象之间既有 recorded 又有 absent
  for (kk in statOf) {
    split(kk, sp, SUBSEP); id = sp[1]; el = sp[2]; ch = chOf[id]
    st = statOf[kk]
    key2 = ck(ch, el)
    if (st == "recorded") recByChannel[key2] = 1
    if (st == "absent") absByChannel[key2] = 1
  }
  for (key2 in recByChannel) if (key2 in absByChannel) {
    split(key2, sp, SUBSEP); nrec2 = 0
    for (kk in statOf) { split(kk, sp2, SUBSEP); if (chOf[sp2[1]] == sp[1] && sp2[2] == sp[2]) nrec2++ }
    emit("T03", "-", "通道类 " sp[1] " 的要素 " sp[2] " 在对象之间既有已读数又有明确不存在（不阻断）：登记口径未统一" src("T03"))
  }

  if (!QUIET) {
    print "---- 通道×required 要素覆盖矩阵 ----"
    for (ix = 1; ix <= nid; ix++) {
      id = order[ix]; ch = chOf[id]
      reqs = 0; hits = 0; hlist = ""
      for (kk in capOf) {
        split(kk, sp, SUBSEP); if (sp[1] != ch || capOf[kk] != "required") continue
        reqs++
        k = ck(id, sp[2])
        if ((k in statOf) && statOf[k] == "recorded") { hits++ } else { hlist = hlist " " sp[2] }
      }
      printf "%s\t%s\trequired=%d 已读数=%d 缺:%s\n", id, (ch==""?"-":ch), reqs, hits, (hlist==""?"（无）":hlist)
    }
    printf "---- 公告词表读数 ----\n"
    printf "CVE 行数=%d 去重组件名=%d 网络通道词形命中=%d 挂在公告平面的已读数=%d\n", vrows, compNames, chanHits, advRec
  }

  for (j = 1; j <= nline; j++) { split(lines[j], sp, "\t"); if (sp[1] !~ /^Q[1234]$/) print lines[j] > "/dev/stderr" }
  if (!QUIET) for (j = 1; j <= nline; j++) { split(lines[j], sp, "\t"); if (sp[1] ~ /^Q[1234]$/) print lines[j] }
  nblk = 0; nc = 0; nsig = 0
  for (j = 1; j <= nline; j++) { split(lines[j], sp, "\t"); if (sp[1] !~ /^Q[1234]$/) nsig++ }
  for (c in cnt) { if (c !~ /^Q[1234]$/) nc++; if (c in HB) nblk += cnt[c] }
  printf "\n通道对象数=%d 要素登记行=%d 能力表行=%d 信号行数=%d\n", nid, elemRows, capRows, nsig
  printf "不同信号码=%d 阻断信号条数=%d\n", nc, nblk
  printf "闭合等级 Q1=%d Q2=%d Q3=%d Q4=%d\n", qcount["Q1"], qcount["Q2"], qcount["Q3"], qcount["Q4"]
  shown = ""
  for (j = 1; j <= nline; j++) { split(lines[j], sp, "\t"); if (sp[1] ~ /^Q[1234]$/) continue; if (!(sp[1] in shn)) { shn[sp[1]] = 1; shown = shown sprintf("  %s=%d\n", sp[1], cnt[sp[1]]) } }
  printf "%s", shown
  exit (nblk > 0 ? 1 : 0)
}
' "$1" "$2" "$3"
```

### 22.7 一次干净比对与一次越界读数

干净比对（`FX/fixture-channel-good.csv` + `FX/capability.csv` + `C/advisory-entries.tsv`，第 23.2 节的 R2）是脚本二唯一 exit 0 的一次：

```text
---- 通道×required 要素覆盖矩阵 ----
tun-ok-01	packet_tunnel	required=10 已读数=10 缺:（无）
dns-ok-02	dns_proxy	required=7 已读数=7 缺:（无）
cfe-ok-03	content_filter	required=6 已读数=6 缺:（无）
trp-ok-04	transparent_proxy	required=5 已读数=5 缺:（无）
---- 公告词表读数 ----
CVE 行数=392 去重组件名=101 网络通道词形命中=0 挂在公告平面的已读数=0
...
通道对象数=4 要素登记行=28 能力表行=211 信号行数=0
不同信号码=0 阻断信号条数=0
闭合等级 Q1=4 Q2=0 Q3=0 Q4=0
$ exit=0
```

注意最后一行前面的那个 `挂在公告平面的已读数=0`：这份夹具没有任何读数挂在公告平面，因此即使词表可读、通道词形命中为 0，`X04` 也不成立（第 237 行的 `advRec > 0` 不满足）。**这条码不是"公告里没有通道组件"的通用抱怨，而是"你把读数挂在了一个没有通道组件的词表上"的具体指控。**

真实混合清单（`FX/fixture-channel.csv`，R3）里两个越界样本的输出是：

```text
X04	-	公告组件词表去重 101 个组件、网络通道词形命中 0，却有 1 条通道要素读数挂在公告平面：按这份词表口径，缺陷不能归到网络通道组件
P03	dns-osa-22	内核侧要素 netagent_registration 记为 entitlement_manifest 读回：那一条注册记录只存在于内核侧
D03	trp-sin-05	通道类 transparent_proxy 的 provider_entitlement_value 在公开口径里不适用，却登记了已读数
X02	rel-tor-12	要素 advisory_component 引用的组件名 VPNChannelKit 归一化后不在公告组件词表内
D04	chn-xxx-00	清单里的通道类 unknown 在能力表一行都没有：这一类的判据未建模，缺哪一格无从判定
```

`VPNChannelKit` 这一条值得单独看：它归一化后是 `vpnchannelkit`，既不在 101 个组件名里，也不匹配第 262 行的内核符号前缀，所以落 `X02` 而不是 `X06`——**一个看起来像产品名的引用，与一个把源码文件名当组件名的引用，是两种不同的错。** 这两次运行合起来给出脚本二的两极：Q1=4 且零信号，与 Q2=22／Q3=5／Q4=3、38 个码、36 条阻断。

---
## 23. 两个脚本的全量分支覆盖验收

第 21、22 章给出脚本本身。这一章回答一个更容易被跳过、却决定这两份脚本能不能被引用的问题：**脚本里写过的每一条信号，是否真的在某个输入下出现过。**本报告沿用一条硬规则——**不能触发的信号等于没有写过**。一条只存在于源码字符串里的信号，与一条作者设想出来但没有对应输入形态的信号，在读者这边没有任何区别：两者都会让"这份通道台账合不合格"变成一句不可复核的口头承诺。

本章的 R 编号沿用两份 harness 各自的运行日志序号：脚本一的 R1—R14 是 `FX/run-log.txt`（768 行）里的 14 次，脚本二的 R1—R17 是 `FX/run-log-2.txt`（1065 行）里的 17 次。R 号按日志内 `===== RUN:` 分段的先后次序数出来，分段头本身只写夹具标签、不写 R 字。两份日志各自从 R1 开始，因此下文出现两个 R1，分别指两份日志的第一次运行（都是全码遍历夹具）。**合计 31 次实跑。**

### 23.1 四条验收标准

1. **逐码可达**：脚本一声明的 64 个码（60 个信号码 + 4 个判定档 `J1`—`J4`）与脚本二声明的 44 个（40 个信号码 + 4 个判定档 `Q1`—`Q4`），每一个都必须在至少一次真实运行里被打印。不接受"读代码看出来会触发"作为替代。
2. **逐次留痕**：每次运行记录一条完整块——命令行、逐条信号原文、脚本自己打印的汇总行（对象数、信号行数、不同信号码数、阻断信号条数、判定分布）与 shell 退出码。本章表里的每个数字都是从这两份日志直接取出的，不是事后整理的。
3. **好夹具必须有下界**：一份十二格齐备、逐格有文档引用的台账（`FX/fixture-channel-good.txt`）与一份三段齐备的要素清单（`FX/fixture-channel-good.csv`）必须得到**零信号 + 最高档**（`J1=2` 与 `Q1=4`，退出码 0）。没有这条，"阻断"就没有参照——读者无法判断脚本是严格，还是对任何输入都报错。
4. **只读约束的实证**：31 次运行的命令行只有 `sh 脚本 输入文件 [输入文件…] [选项]` 一种形状；`profiles`、`nectl`、`networkQuality`、`xcrun` 这些词在两份脚本里只出现在第 8 行与第 12 行的"不调用"声明里，以及枚举取值域的字面量中（如 `kernel_sysctl`），没有任何一处是被执行的命令；唯一写出目标是 `mktemp -d` 的临时目录，由第 46 行与第 61 行的 `trap 'rm -rf "$TMPD"' EXIT INT TERM` 删除。

### 23.2 三十一次实跑

脚本一 `tools/channel-ledger-review.sh`，14 次，R1—R14：

| 次 | 运行标签 | 命令行要点 | 对象数 | 信号行 | 不同码 | 阻断条 | 判定分布 | 退出码 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| R1 | `codes` | 全码遍历夹具 `fixture-channel-codes.txt` | 74 | 321 | 60 | 309 | J3=7 J4=67 | 1 |
| R2 | `good` | 十二格齐备基准 | 2 | 0 | 0 | 0 | J1=2 | 0 |
| R3 | `mixed` | 混合缺陷台账 `fixture-channel.txt` | 6 | 16 | 13 | 15 | J2=2 J3=2 J4=2 | 1 |
| R4 | `multi` | 同时传入 good + mixed 两个文件 | 8 | 16 | 13 | 15 | J1=2 J2=2 J3=2 J4=2 | 1 |
| R5 | `quiet` | 同 R3，加 `-q` | 6 | 16 | 13 | 15 | J2=2 J3=2 J4=2 | 1 |
| R6 | `help` | `-h` | — | — | — | — | — | 0 |
| R7 | `noargs` | 不带任何参数 | — | — | — | — | — | 2 |
| R8 | `missing` | 传入不存在的文件 | — | — | — | — | — | 2 |
| R9 | `empty` | 零字节文件 | 0 | 0 | 0 | 0 | 全为 0 | 0 |
| R10 | `comments` | 只有注释与空行 | 0 | 0 | 0 | 0 | 全为 0 | 0 |
| R11 | `malformed` | 列数不是恰好三列、标识为空、字段名无命名空间 | 1 | 9 | 7 | 9 | J4=1 | 1 |
| R12 | `unknown-field` | 命名空间已知但字段名未登记 | 1 | 6 | 5 | 6 | J4=1 | 1 |
| R13 | `shape` | 枚举／布尔／日期／数值／Team ID／UUID／域长度越界 | 1 | 13 | 9 | 13 | J4=1 | 1 |
| R14 | `secret-shapes` | 取值形似私钥、PKCS#12、证书正文、内联 base64、设备路径 | 1 | 11 | 7 | 11 | J4=1 | 1 |

脚本二 `tools/channel-availability-diff.sh`，17 次，R1—R17（三份输入按固定顺序：要素清单、通道能力表、公告词表）：

| 次 | 运行标签 | 命令行要点 | 对象数 | 要素行／能力行 | 信号行 | 不同码 | 阻断条 | 判定分布 | 退出码 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| R1 | `codes` | 全码遍历清单 + `capability-bad.csv` | 30 | 42／211 | 269 | 38 | 36 | Q2=22 Q3=5 Q4=3 | 1 |
| R2 | `good` | 三段齐备基准 + `capability.csv` | 4 | 28／211 | 0 | 0 | 0 | Q1=4 | 0 |
| R3 | `mixed` | 混合缺陷清单 + `capability.csv` | 8 | 49／211 | 8 | 7 | 5 | Q1=3 Q2=3 Q3=1 Q4=1 | 1 |
| R4 | `mixed-badcap` | 同 R3 换 `capability-bad.csv` | 8 | 49／211 | 13 | 12 | 10 | Q1=3 Q2=3 Q3=1 Q4=1 | 1 |
| R5 | `quiet` | 同 R1 的清单，但换成干净的 `capability.csv` 并加 `-q` | 30 | 42／211 | 264 | 33 | 31 | Q2=22 Q3=5 Q4=3 | 1 |
| R6 | `help` | `-h` | — | — | — | — | — | — | 0 |
| R7 | `noargs` | 不带参数 | — | — | — | — | — | — | 2 |
| R8 | `twoargs` | 只给两份输入 | — | — | — | — | — | — | 2 |
| R9 | `fourargs` | 给四份输入 | — | — | — | — | — | — | 2 |
| R10 | `missing-elem` | 第一份不存在 | — | — | — | — | — | — | 2 |
| R11 | `missing-adv` | 第三份不存在 | — | — | — | — | — | — | 2 |
| R12 | `empty-elem` | 零字节要素清单 | 0 | 0／211 | 0 | 0 | 0 | 全为 0 | 0 |
| R13 | `comments-elem` | 只有注释的要素清单 | 0 | 0／211 | 0 | 0 | 0 | 全为 0 | 0 |
| R14 | `empty-cap` | 能力表零有效行（`capability-empty.csv`） | 8 | 49／0 | 2 | 2 | 2 | Q4=8 | 1 |
| R15 | `empty-adv` | 公告词表零可用行（`advisory-empty.tsv`） | 8 | 49／211 | 8 | 7 | 5 | Q1=3 Q2=3 Q3=1 Q4=1 | 1 |
| R16 | `empty-both` | 能力表与词表同时为空 | 4 | 28／0 | 2 | 2 | 2 | Q4=4 | 1 |
| R17 | `malformed` | 缺列／多列／空标识／CRLF 混合的一份清单 | 0 | 0／211 | 4 | 2 | 4 | 全为 0 | 1 |

### 23.3 逐码表一：脚本一的 64 个码

`FX/codemap-1.txt` 由脚本一的真实输出逐码去重生成（64 行）。"首次触发"是该码第一次出现的那次运行，"累计条数"是 R1—R14 全部输出里该码出现的次数总和（判定档的计数只数判定行本身）。

| 码 | 首触 | 累计 | 码 | 首触 | 累计 | 码 | 首触 | 累计 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| S01 | R1 | 6 | A01 | R1 | 76 | T01 | R1 | 1 |
| S02 | R1 | 4 | A02 | R1 | 4 | T02 | R1 | 1 |
| S03 | R1 | 7 | A03 | R1 | 1 | T03 | R1 | 15 |
| S04 | R1 | 4 | A04 | R1 | 4 | T04 | R1 | 1 |
| S05 | R1 | 2 | A05 | R1 | 6 | T05 | R1 | 1 |
| S06 | R1 | 5 | A06 | R1 | 8 | T06 | R1 | 1 |
| S07 | R1 | 1 | A07 | R1 | 1 | T07 | R1 | 1 |
| S08 | R1 | 1 | A08 | R1 | 1 | V01 | R1 | 1 |
| S09 | R1 | 2 | A09 | R1 | 2 | V02 | R1 | 1 |
| K01 | R1 | 9 | B01 | R1 | 75 | V03 | R1 | 4 |
| K02 | R1 | 4 | B02 | R1 | 1 | V04 | R1 | 1 |
| N01 | R1 | 1 | B03 | R1 | 4 | V05 | R1 | 3 |
| N02 | R1 | 1 | B04 | R1 | 2 | O01 | R1 | 12 |
| C01 | R1 | 4 | D01 | R1 | 1 | O02 | R1 | 4 |
| C02 | R1 | 1 | D02 | R1 | 1 | O03 | R1 | 1 |
| C03 | R1 | 1 | D03 | R1 | 1 | O04 | R1 | 1 |
| C04 | R1 | 1 | D04 | R1 | 2 | O05 | R1 | 1 |
| C05 | R1 | 1 | D05 | R1 | 1 | J1 | **R2** | 4 |
| C06 | R1 | 1 | D06 | R1 | 5 | J2 | **R3** | 4 |
| B05 | R1 | 1 | B06 | R1 | 2 | J3 | R1 | 11 |
| B07 | R1 | 4 | D07 | R1 | 12 | J4 | R1 | 75 |
| X01 | R1 | 87 | — | — | — | — | — | — |

**计数关系**：60 个信号码 + 4 个判定档 = 64。R1 的"不同信号码=60"恰好等于信号码总数，即一次全码遍历就触达了全部 60 个信号码；R1 里 321 条信号行 − 309 条阻断 = 12 条非阻断行，逐项为 `D07` 9 条、`S08`、`T07`、`O05` 各 1 条——脚本一源码第 108 行的阻断清单共 56 个码，非阻断的正是这 4 个。`X01` 累计 87 条、`A01` 76 条、`B01` 75 条，与 codes 夹具的 74 个对象数量级一致：**这三条码是"每个对象都会撞一次"的地板码**（缺引用、缺主语、缺装配者），它们的高计数不是脚本在重复报警，而是夹具的多数对象确实没有登记 `doc.*`、`id.*` 与 `asm.*` 三组格。

### 23.4 逐码表二：脚本二的 44 个码

`FX/codemap-2.txt`（44 行）同法生成。

| 码 | 首触 | 累计 | 码 | 首触 | 累计 | 码 | 首触 | 累计 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| S01 | R1 | 5 | D04 | R1 | 7 | V01 | R1 | 2 |
| S02 | R1 | 3 | D05 | R1 | 453 | V02 | R1 | 2 |
| S03 | R1 | 2 | D06 | R1 | 2 | V03 | R1 | 2 |
| S04 | R1 | 2 | P01 | R1 | 2 | V04 | R1 | 2 |
| S05 | R1 | 2 | P02 | R1 | 2 | X01 | R1 | 2 |
| S06 | R1 | 2 | P03 | R1 | 5 | X02 | R1 | 7 |
| S07 | R1 | 4 | P04 | R1 | 2 | X03 | **R15** | 2 |
| S08 | R1 | 4 | P05 | R1 | 4 | X04 | R1 | 5 |
| S09 | R1 | 2 | C01 | R1 | 2 | X05 | R1 | 2 |
| C02 | R1 | 2 | C03 | R1 | 2 | X06 | R1 | 2 |
| C04 | R1 | 2 | C05 | R1 | 2 | Q1 | **R2** | 13 |
| C06 | **R14** | 2 | D01 | R1 | 2 | Q2 | R1 | 31 |
| D02 | R1 | 8 | D03 | R1 | 7 | Q3 | R1 | 8 |
| — | — | — | — | — | — | Q4 | R1 | 18 |

**计数关系**：40 个信号码 + 4 个判定档 = 44；R1 的"不同信号码=38"，缺的 2 个是 `C06`（要能力表整表为空才触发，首次 R14）与 `X03`（要公告词表整表为空才触发，首次 R15）——这两个码在结构上不可能被一份"能力表与词表都可用"的夹具触达，所以只能由专门的两行输入完成。脚本二源码第 110—116 行的阻断清单共 33 个码，非阻断的 7 个是 `S08`、`D02`、`D05`、`V04`、`X05`、`T02`、`T03`。`D05` 累计 453 条最高，因为它是"required 要素在本对象完全没有登记行"的逐格计数：codes 夹具 30 个对象 × 每对象缺若干 required 格，正是第 20 章 O2 指标要的分母级明细。

### 23.5 七处值得单独说明的读数形状

**其一，`J1` 只能由好夹具给出。**R1 的 74 个对象里没有一个 `J1`——`J1` 的条件是"该对象零阻断信号"，而任何为触达其他码而设计的对象都必然带阻断。R2 给 2 个 `J1`，R4 因为把 good 与 mixed 拼在一起而再给 2 个，累计 4 条判定行。这条计数关系是第 21 章"好台账长什么样"的唯一实证。

**其二，拼接与 `-q` 都不改变判定。**R4 把基准夹具与缺陷夹具一起传入：对象数从 6 变 8，`J1` 从 0 变 2，缺陷侧的 `J2=2 J3=2 J4=2` 一格未动，阻断条数仍是 15。R5 加 `-q` 后汇总数字与 R3 完全一致（6／16／13／15），只是不再逐条打印判定行，因此日志里 R5 的判定行计数为 0 而汇总行的 `J2=2 J3=2 J4=2` 仍在。**判定不依赖调用形式，也不依赖打印详细度。**

脚本二的 R5 是同一句话的另一半，但要用对：它的 30／42／264／33／31 与 R1 的 30／42／269／38／36 差 5 条，**这 5 条不是 `-q` 造成的，而是这一行把 R1 的坏能力表换成了干净的 `capability.csv`**——少的正好是 `C01`—`C05` 各一条（这五码只在能力表自身畸形时成立）。同一份清单、同一份词表、只差一份能力表，档位仍是 `Q2=22 Q3=5 Q4=3`：**能力表自身形态影响码集，不影响闭合档位的分布形状**；而 `-q` 在脚本二里压掉的是 stdout 的矩阵与等级行（第 314、332 行），stderr 的逐条信号一条不少，所以汇总里的 264 依然是真实信号行数。

**其三，四种结构畸形都落 `J4=1`，但码集不同。**R11 是 `S01`×2、`S03`×2、`K01`、`S02`、`A01`、`B01`、`X01`；R12 是 `S03`×2、`S09`、`A01`、`B01`、`X01`；R13 是 `S04`、`S05`、`S06`×3、`A09`、`A06`×3、`A04`、`A01`、`B01`、`X01`；R14 是 `K01`×4、`K02`、`A06`×2、`S01`、`A01`、`B01`、`X01`。四次的共同点是末尾同时出现 `A01`、`B01`、`X01`——**这条通道"没有主语、没有装配者、没有可回指引用"**。这不是巧合，而是脚本一第 382—391 行判据里 J4 的第一条入口（通道类型与装配主体同缺，且观测平面与结论也缺）。R14 里 `K01` 出现 4 次、`K02` 1 次：`K01` 的四次分别是一个 `sec.*` 命名空间字段（`sec.proxy_credentials`）与三个取值形似密钥／证书正文的普通字段（`doc.source`、`id.config_identifier`、`ent.granted_via`）；`K02` 打在一个"形似设备绝对路径或内联 base64"的 `obs.command_name` 上；夹具里那条以 `data:application/json;base64,…` 作为 `asm.payload_type` 取值的行则同时撞了 `S01`——**内联 base64 带逗号，先把列数打乱了，形态检查才轮到密钥判断**。

**其四，能力表为空时，两条阻断打出八个 Q4。**R14 只有 2 条阻断（`C06` 打在标识 `-` 上、`X04` 同样打在 `-` 上），但 8 个对象全部 `Q4`；R16 只有 `C06` 与 `X03` 两条，4 个对象全部 `Q4`。**阻断条数与档位不是同一个量**：档位是逐对象打的，而 `C06`／`X03`／`X04` 是全局码——这正是第 19.3 节"全局码进退出码、不进档位"的实证，也是脚本二覆盖矩阵此时打印 `required=0 已读数=0 缺:（无）` 的原因：能力表为空时 `required` 集合本身是空，矩阵不能假装"无缺口"就是"已覆盖"。

**其五，R3 与 R15 是同一份清单换一份词表的对照。**两次运行的阻断条数都是 5、判定分布都是 `Q1=3 Q2=3 Q3=1 Q4=1`、退出码都是 1，**唯一变化是打在 `-` 上的全局码：R3 是 `X04`，R15 是 `X03`**。原因写在脚本二第 235—238 行：`X03` 的条件是 `vrows == 0 && compNames == 0`，而 `X04` 的前置条件里包含 `vrows > 0 && compNames > 0 && chanHits == 0 && advRec > 0`。词表为空时，"网络通道词形命中为 0"这件事无法证明，于是脚本只报"比对不可执行"，不报"比对结果为否"。这条优先级是刻意的，也是第 24 章第 6 个误区的内容。R15 的覆盖矩阵末尾仍打印 `CVE 行数=0 去重组件名=0 网络通道词形命中=0 挂在公告平面的已读数=1`：**那一个"挂在公告平面的已读数"依然存在，只是脚本拒绝据此给出归属结论。**

**其六，R17 证明退出码 1 可以伴随零个档位。**清单四行全部形态不合法：`S01` 三次（只有一列、多出一列、缺三列）、`S02` 一次（标识为空），于是 `通道对象数=0`、`要素登记行=0`，`Q1`—`Q4` 全为 0，但阻断 4 条、退出码 1。判定档是逐对象打的，没有对象就没有档——**"Q 全为 0 所以通过"是这个脚本最容易被误读的一处**。R17 的四行夹具全部使用 CRLF 换行，与 R2 的 LF 夹具相比，S 族读数完全由列数与标识决定，换行符没有造成第二次差异。

**其七，两个脚本之间没有可观测的组合。**第 12.3 节说过"一个对象完全可以 `J1` 而整台账 `Q3`"。本验收**不能**在同一行里同时给出 `J1` 与 `Q3`，因为两个脚本读的不是同一份输入：脚本一读 `<id>,<字段名>,<值>` 三列台账，脚本二读八列要素清单加两份参照表。R2 的 `J1=2` 与脚本二 R2 的 `Q1=4` 是两次独立运行的两份独立夹具（对象标识甚至不同：前者是 `tun-nyc-01`、`dns-osa-02`，后者是 `tun-ok-01`、`dns-ok-02`、`cfe-ok-03`、`trp-ok-04`）。所以那句话是**建模陈述，不是本次运行的产物**；把它写成组合证据，就是第 24 章第 7 个误区。要得到组合，必须对同一个通道对象同时登记台账与要素清单——本报告给出的是两份脚本各自的输入格式，衔接点只有对象标识命名。

### 23.6 三个核对工具

| 工具 | 作用 | 本轮读数 |
| --- | --- | --- |
| `FX/code-coverage.pl` | 从脚本源码提取全部 `emit()` 码集，与运行日志里实际打印的码求差 | 脚本一：定义 64 命中 64，未触发清单 `[]`（`FX/codemap-1.err`）；脚本二：定义 44 命中 44，未触发清单 `[]`（`FX/codemap-2.err`） |
| `FX/codemap.pl` | 逐码去重生成首次触达与累计条数（§23.3、§23.4 两张表的来源） | `FX/codemap-1.txt` 64 行、`FX/codemap-2.txt` 44 行 |
| `tools/doc-audit.pl` | 把两份脚本的每条 `DOC[...]` 文案与行号引用回指到归档件，检查文件是否存在、行号是否越界 | 未找到文件数 0，行号越界数 0（`C/readings-15.txt` R8、R9） |

`FX/run-all.sh` 与 `FX/run-all-2.sh` 会把 R9、R10、R17 这类畸形夹具现造现删（后者的第 60—86 行：`tmp-empty.csv`、`tmp-comments.csv`、`tmp-malformed.csv` 在末尾 `rm -f`），所以 31 次运行都可从头重放，不需要任何手工准备。

### 23.7 这次验收不证明什么

四条限制必须与验收表同时给出。

**其一，夹具是设计出来的。**逐码可达证明的是"每一条信号都有对应的输入形态"，不是"真实台账会长成这样"。codes 夹具里 74 个对象有 67 个落 `J4`、脚本二 30 个对象有 22 个落 `Q2`，这是为触达码而构造的极端口，**不能拿它当"贵司台账 J4 率"的参照**。

**其二，公告词表读数是本轮快照。**`X04` 的成立依赖具体词表：本轮三份 CSAF 导出件 392 行、101 个去重组件名、六个通道词形命中 0（第 16 章第 1、2 条）。脚本二每次运行都重新加载词表并重新计算 `chanHits` 与 `advRec`，不缓存上一轮结论；换一批公告件，`X04` 可能不触发，也可能变成 `X01`／`X02` 的逐条命中失败。

**其三，退出码不是判定。**两个脚本的退出码语义一致：**1** 出现阻断信号、**2** 输入不可用、**0** 其余。CI 门禁只应把 2 当"输入坏了"、1 当"有阻断"；档位需要读汇总行。把退出码当档位，就会在 R17（退出码 1、零档位）与"全部 `J4` 却不含任何 HB 码"（第 19.4 节，退出码 0）两种形状上得出反向结论。

**其四，本验收不覆盖内容安全之外的能力。**脚本只判"这一格写没写、写成这样合不合法"，不判通道是否真的在承载流量，也不判任何第三方 VPN 产品的实现质量。任何"脚本判 `J1` 所以设备安全"的表述都超出这两份脚本的口径——这是第 24 章第 3、第 9 个误区共同的根因。

---

## 24. 十二个误区

以下十二条是把第 3—23 章的读数压回成一句话时最容易压错的形状。每条给出**误区表述 → 依据读数 → 正确表述**，依据只用本报告归档件与实跑日志里的数。

**误区 1：设备上有 VPN 配置文件，所以流量走了 VPN。**
依据：《NEVPNStatus》第 14 行对 `invalid` 的定义同时包含"配置不存在"与"未被启用"两件事；《NEVPNManager》第 15 行的 `isEnabled` 是另一格；《Routing your VPN network traffic》第 49 行 "When the VPN transitions away from the connected state, the system drops network traffic."。
正确表述：**"有配置"是装配格，"启用了"是生效格，"此刻连着"是状态格，三格分属三层**。台账只写"有配置"时脚本一给 `A01`／`B01`（缺主语与装配者），不因为你看到了配置文件而免除。

**误区 2：`NEVPNStatus` 一格就把装配、生效、承载三件事说完了。**
依据：同页第 9—14 行六态里没有"未安装"这一态，第 19—20 行只给 `status` 与 `connectedDate` 两个读数；`invalid` 是**一格两义**。
正确表述：状态值只能否证"当前 connected"，不能否证"配置存在"，也不能证明"曾承载过流量"。要定承载，需要 `when.connected_date`（第 7 章）与观测平面格（第 11 章）同时在场。

**误区 3：状态栏图标就是通道清单。**
依据：《Status bar icons》第 1183—1187 行相邻五条里与通道相关的只有第 1186 行 VPN 一条；第 1187 行网络活动图标官方口径含 "Some third-party apps may also use it to show an active process."；内容过滤器、DNS 代理、透明代理、网络中继在这份页里没有任何条目。
正确表述：**图标面只覆盖 VPN 一类**，"图标不在"只能否证 VPN 图标的显示条件，不能否证通道存在；"图标在"也不能区分个人 VPN 与企业强制 VPN。把图标当清单会同时造出假阴性与假归属：脚本一用 `O02`（用图标闭合通道归属）、`N01`（以图标可见出对外结论却未登记告知依据）、`V04`（以图标消失作为失效依据）拦三种写法，脚本二用 `P01`（把权利类要素记成状态图标面读回）拦第四种。

**误区 4：MDM 装上了描述文件，所以管理面能回执通道状态。**
依据：《InstallProfileCommand》第 23—24 行与《RemoveProfileCommand》第 21—22 行回执的都是描述文件这一装配件；《Status items》全文 82 行、13 个分组、66 条列表项里按 `vpn`／`proxy`／`network`／`filter`／`relay`／`dns` 匹配命中 0。
正确表述：**装配命令有回执、通道状态没有回报项**。这条不对称是第 11 章与第 16 章第 15 条的核心读数；把管理面写成通道状态来源，脚本二给 `P02`。

**误区 5：内核里有这条通道的记录，所以能把它登记进归属台账。**
依据：《necp.c》第 620 行起 26 个 sysctl 节点中 20 个可写、只有 1 个 ANYBODY 可读；第 956—957 行 `PRIV_NET_PRIVILEGED_CLIENT_ACCESS`、第 1049／1385／3347／13935 行与《network_agent.c》第 2577 行 `PRIV_NET_PRIVILEGED_NECP_POLICIES` 五处闸门；`struct netagent` 的 `netagent_domain`／`netagent_type` 长度都是 32（《network_agent.h》第 144—145 行）。
正确表述：**内核侧有读数但没有归属主语，管理侧有装配主语但没有读数**。登记 `id.agent_uuid` 时要按 UUID 形态与 32 字节上限校验（一 `A06`），否则内核那一格根本回指不到。

**误区 6：比对做不了，就等于比对结果为否。**
依据：脚本二第 235—238 行的 `X03`／`X04` 优先级与 §23.5 其五的 R3／R15 对照（同样 5 条阻断、同样 `Q1=3 Q2=3 Q3=1 Q4=1`，只有全局码换了）。
正确表述：**词表不可用（`X03`）与词表可用且通道词形命中为 0（`X04`）是两件事**。前者只说明"这一格现在无从比对"，后者才承载本篇的 `component_absent` 立场。同理，`absent`、`not_recorded`、`unknown`、`not_applicable` 四格也不可互相塌缩（第 17 章）。

**误区 7：`J` 档与 `Q` 档可以互相换算，`J1` 大致就是 `Q1`。**
依据：第 19.1 节的对照表；§23.7 其四——两个脚本读的输入不同、对象标识也不同，本轮没有任何一次运行同时给出两档。
正确表述：**J 档回答"这条通道的台账自洽吗"，Q 档回答"这套登记体系覆盖吗"**。报告里要同时出现两档时，写成"台账侧 `J2`、登记侧 `Q3`"并注明各自的输入文件，不写成"综合评级 B"。

**误区 8：`Q4` 说明这条通道有问题。**
依据：脚本二第 289—292 行的判据（`Q4` 三个入口：通道类不在模型里／能力表整表不可用／本对象要素行的通道类或要素名越界）；R14 里 8 个对象全 `Q4` 而阻断只有 2 条。
正确表述：**`Q4` 不代表通道有问题，只代表这一格无法比对**。`Q4` 的可执行动作是"补模型或修清单形态"，不是"整改通道"。

**误区 9：退出码 0 就是台账合格。**
依据：§23.7 其三；R17（退出码 1、`Q` 全 0）；第 19.4 节"全部 `J4` 且不含 HB 码 → 退出码 0"。
正确表述：退出码回答"这次运行有没有阻断信号"，档位回答"每条记录能不能用"。**两者要分开登记**，第 22 章的输出契约里 `通道对象数`、`阻断信号条数`、`判定分布` 三行是给机器读的，退出码只是其中之一。

**误区 10：判定不阻断的信号可以先忽略。**
依据：脚本一 4 个非阻断码（`S08`、`D07`、`O05`、`T07`）与脚本二 7 个（`S08`、`D02`、`D05`、`V04`、`X05`、`T02`、`T03`）；R1 里 12 条非阻断行；脚本二的 `D05` 累计 453 条。
正确表述：**非阻断不等于无信息**。`D05`／`D02` 是第 20 章 O2 指标的唯一数据源，`D07`（判定取向未登记）决定第 9—10 章能不能说出"这条通道是丢弃还是放行"。忽略它们会让覆盖率指标失去分母。

**误区 11：`undocumented` 就是 `optional` 或 `not_applicable`，反正都是"没有"。**
依据：矩阵第 7 行注释的拒绝建模声明与脚本二第 249 行的 `if (c2 != ch || av == "undocumented") continue`；本轮 19 格 `undocumented` 全部落在 `app_push`（6）、`captive_network`（6）、`relay`（4）、`dns_settings`（3）。
正确表述：**`undocumented` 是"公开口径既没说有也没说没有"，脚本据此不产生任何结论**。把它记成 `not_applicable` 会造出假结论（"这一格不适用"是断言），记成 `optional` 会抬高 O1／O2 的覆盖率。四格各有语义，不能互相顶替。

**误区 12：台账里删掉这一行，就等于通道被移除了；顺手把密钥抄进台账也没关系。**
依据：《RemoveProfileCommand》第 21—22 行只回执描述文件；《NETunnelProviderManager》第 21 行写明导入的凭据存放在 `com.apple.managed.vpn.shared` 专用 keychain 访问组、第 22 行禁止扩展写入该组；脚本一对 `sec.*` 与四种密钥形态的 `K01`／`K02`（R14 打出 4 次 `K01`、1 次 `K02`）。
正确表述：**移除闭环要四格**——`undo.removed`、`undo.removal_actor`、`undo.removal_verified`、`undo.still_carrying`。只写"已移除"而装配回执格为空落 `V01`，不写谁执行的落 `V05`，"验证为否却仍记承载中"落 `V02`，"失效依据写成应当已失效却给闭合结论"落 `V03`。台账需要的是"哪条通道、由谁装配、此刻由哪个平面读回哪一格"，**永远不是凭证本身**：把共享密钥或 VPN 载荷抄进台账，等于把一份原本受密钥链与描述文件规则约束的凭证，变成一份不受任何装配规则约束的副本（一 `K01`／`K02`）。

---

## 25. 常见问题

**问：这套台账是不是必须跑在设备上？**
不是。两个脚本都是纯文本、离线、只读：输入是你自己维护的清单文件，不调用任何 Apple 命令行工具，不访问设备，不联网，也不读任何载荷正文。所以它可以跑在准备室里、评审会上，也可以跑在 CI 里；唯一的前提是台账内容与公开口径一致。

**问：我没有 MDM，只有员工自行安装的个人 VPN，这套东西还有用吗？**
有用，但重心会变。个人 VPN 的权利格与管理装配格天然为空（口径见《Network Extension》页第 17 行与《NEVPNManager》页第 7 行），此时可归属的证据转移到 `built_in_vpn` 唯一 required 的管理格 `install_receipt` 与运行格的 `vpn_status`／`on_demand_rule_set`／`routing_scope`（矩阵第 12.1 节：`built_in_vpn` 18 行、7 项 required）。**没有 MDM 不等于没有归属问题**：掉线时丢包不回落（《Routing your VPN network traffic》第 49 行）这条结论与有没有 MDM 无关。

**问：我要准备几份输入？**
脚本一 1 份（三列：`<通道对象标识>,<字段名>,<值>`，可一次传多份）；脚本二固定 3 份、顺序不可换（八列要素清单、三列通道能力表、CSAF 导出词表）。参数个数不对直接退出码 2（脚本二的 R7—R9 三次运行分别是 0 个、2 个、4 个参数，全部退出码 2）。

**问：通道能力表怎么建？我不想从零开始。**
可以直接从 `FX/capability.csv` 起步：211 行、11 个通道类（按类登记 11—22 行不等，`url_filter` 只有 11 行）、`required` 58 项，口径注释写在文件第 1—8 行，每档的语义都有指定。**扩 `required` 要谨慎**：把某一格升为 required 就等于宣称"公开口径里这一类通道必然有这一格"，必须能指到具体文件行号；指不到就记 `undocumented`（本轮 19 格就是这么处理的）。

**问：能不能把某个要素直接从矩阵里删掉，让覆盖率好看？**
不能，脚本会看出来。二 `D05` 是"required 要素在本对象没有登记行"的逐格计数（本轮 codes 夹具累计 453 条），删掉能力表某一行的效果是 `C06`／`D04`（模型整表或该类无行）→ 全部对象落 `Q4`，或者 `D01`／`D02`／`D03` 之类的方向冲突。**降低 O2 的唯一途径是补读数或换平面**，不是改分母。

**问：退出码该怎么做门禁？**
`2` 判"输入坏了"（文件不可读、参数个数非法、列数不对），`1` 判"有阻断信号"，`0` 判"无阻断"。不要按档位设门禁——R17 是退出码 1 但 `Q` 全 0，而一份全 `J4` 但不含 HB 码的台账退出码是 0（第 19.4 节）。要卡质量就把"汇总行的 `J1` 占比"或"`required` 缺读率 O2"作为评审指标（第 20 章），而不是塞进退出码。

**问：为什么不设计一个能直接读设备的脚本？那样不就一劳永逸了。**
三个理由，都在前文有对应读数。其一，可见性本身受限：内核那 26 个 sysctl 节点只有 1 个 ANYBODY 可读，其余被 5 处 `PRIV_NET_PRIVILEGED_NECP_POLICIES` 与 `PRIV_NET_PRIVILEGED_CLIENT_ACCESS` 闸门守着（第 18 章内核侧）。其二，读回来的是状态，不是归属：`NEVPNStatus` 的 `invalid` 一格两义，管理面根本没有通道回报项（第 7、11 章）。其三，本文的边界：提供读取通道状态、判定或规避告知的操作步骤不在本文范围内（第 2 章视角声明）。**离线台账审查是唯一能同时被评审者和被审计者接受的形式**，因为它审的是登记质量，不是设备状态。

**问：判定档里的 `J3` 和 `J4` 有什么区别？是不是都要下架？**
不是。`J4` 是"通道主语无法确定"——不能进任何"谁授权、谁装配、谁能观测、谁负责"的对外表述；`J3` 是"能定主语但缺关键回指"（无核对时刻、无内核标识、无告知平面，或阻断不少于 1 条但主语成立）。两者对应的动作不同：`J4` 要先补 `id.*` 与 `asm.*` 两组格，`J3` 要补 `when.audit_at`、`id.agent_uuid`、`obs.plane` 三格之一（判据见脚本一第 382—391 行）。**都不等于通道要下架**。

**问：`X04` 是不是说明 Apple 没在网络通道类上修过任何漏洞？**
不是，它说明的是更窄的一句话：**按本轮归档的这三份公告导出件，公告组件词表里没有任何一条通道词形（`vpn`／`proxy`／`tunnel`／`content filter`／`relay`／`hotspot`）命中，因此公告平面无法承载"这条通道挂过哪个缺陷"这一格。**词表里与框架同名的唯一一条是第 69 行 CVE-2026-84626（组件 `NetworkExtension`），其影响句是 "An app may be able to identify what other apps a user has installed"，与通道承载无关（第 14.3 节）。第 16 章第 5 条给了 KEV 的两层读数：全目录 `vpn` 出现 61 次，而 95 条 Apple 记录里通道词形命中 0——**这两个数是"公告写法"的差别，不是"缺陷数量"的差别**。

**问：这套台账能不能用来评价某个第三方 VPN 产品？**
不能，也不做。矩阵登记的是"通道类 × 要素"的公开可得性，不登记强度、不比优劣，也不对任何具体产品、具体设备、具体组织给出通道判定结论（第 2 章边界）。要评价产品需要的是产品文档与实测，两者都不在本文口径里。

**问：第 15 篇和前十四篇是什么分工？我要读哪一篇？**
按归属对象选：**代码为什么被允许运行**读第 14 篇；**这条记录能不能作证**读第 13 篇；**这台设备归谁**读第 08、10、11 篇；**缺陷在哪**读第 01、06、07、12 篇；**流量走了哪条路、被谁看过**读第 02、03、04、09 篇。本文只回答**这条通道凭什么存在、谁装配的、此刻在不在承载、消失后谁能证明**。如果你的问题是"这台设备现在是不是在 VPN 里"，本文给你的是判定所需的四格（权利、装配、生效、观测平面）与它们各自的公开口径，而不是一个当场读数的方法。

**问：报告里的数字会不会过期？**
会，而且已注明过期口径。公告件是本轮三份导出件（392 行、101 个组件名），KEV 是目录版本 2026.10.30（1766 条，Apple 95 条），XNU 侧行号按 `C/xnu-tags.json` 记录的标签取。第 16 章的 18 条读数每条都写了计数对象与来源，重跑 `C/readings-15.sh` 与两个 harness 就能得到新值；`doc-audit.pl` 的作用就是在行号漂移时让脚本自己的引用先失败。

---
## 26. 未公开文档化边界清单

这一节列出**公开文档没有写**的东西。它的用途不是批评文档，而是防止读者把"文档没写"读成"不存在"或"必然是另一种"。每条给出：缺什么、公开侧实际读到哪一步、台账该怎么记、影响哪个信号码。前七条直接约束本篇的 J1—J4 与 Q1—Q4 判定，第八条是覆盖面边界，第九条记录告知层与注册层两条公开口径的不同向。第 3.4 节的八处换算失败里，F3、F5、F8 三处属于"公开文档根本没有给出那一格"，在本章分别落在 N2、N7、N5 上。

| 编号 | 未公开文档化的内容 | 公开侧读到的最远处 | 台账记法 | 相关信号 |
| --- | --- | --- | --- | --- |
| N1 | **公告组件词表与通道类之间没有任何公开映射**——一份 CVE 记录说不出它属于哪一类网络通道 | 本轮三份 CSAF 导出件共 392 条 CVE 行、101 个去重组件名，与网络相关的只有 `NetworkExtension`（1 条，`C/advisory-entries.tsv` 第 69 行，CVE-2026-84626，影响格为 "An app may be able to identify what other apps a user has installed"）、`Network`、`Wi-Fi`（1 个组件名 6 行）、`mDNSResponder`、`Thread`、`Bluetooth`；`vpn`／`proxy`／`tunnel`／`filter`／`relay`／`hotspot` 六个词形的组件名命中**全为 0**（第 16 章读数 1）。CISA KEV（`catalogVersion` 2026.10.30，共 1766 条、Apple 95 条）里 `networkextension` 命中 0，而 `vpn` 61、`proxy` 47 散落在别的产品词形下（读数 5） | 组件名格只允许照抄公告词表里存在的字符串；不得把 `necp`／`netagent`／`content_filter` 这类内核符号名当公告组件名登记，也不得给通道格挂一个 CVE 号来证明归属 | 二 `X01`／`X02`／`X05`／`X06`（脚本二第 262、277 行）、二 `X04`（脚本二第 238 行）、二 `V01`—`V03`（脚本二第 273—275 行） |
| N2 | **通道状态在管理面没有回报项**——装配有回执，通道无状态格 | 《Status items》全文 82 行、13 个分组、66 条列表项（第 82 行是 `Declarations`），按 `vpn`／`proxy`／`network`／`filter`／`relay`／`dns` 匹配命中 **0**；《InstallProfileCommand》第 23—24 行与《RemoveProfileCommand》第 21—22 行只给"命令 + 设备处理完之后的响应"两个对象，回执主键是描述文件；《DeclarativeManagement》第 10、21—22 行的同步语义里同样没有通道状态格 | 通道状态格的 `obs.plane` 只能记提供者接口、设置页或公告面之一，不得记 `mdm_status_item`；管理面侧只填装配回执与配置标识两格 | 一 `O03`（脚本一第 352—353 行）、二 `P02`（脚本二第 270 行） |
| N3 | **读数的时效阈值**——"多久以前的读数还算当前"没有公开口径 | 一 T03 只规定"登记了状态或时刻就必须登记核对时刻"（脚本一第 336—337 行），依据是《NEVPNStatus》第 9—14 行只给六态不给时刻；《Routing your VPN network traffic》第 84—85 行的常开与断开语义说明一次掉线即可改变承载结果，但没有任何一份归档件给出间隔上限。第 20 章 O4 因此只给分布不给阈值 | `when.audit_at` 必填；跨期比较只允许写成"两个时刻各自的读数"，不允许写成"当前仍在通道里" | 一 `T03`、一 `T07`（脚本一第 344—345 行，出处刻意借用 `src("T03")`——公开侧没有"读数过期"这一格可指） |
| N4 | **提供者接口的启用格与状态格之间的时点关系**——两个属性是否同一时刻读回，文档不说 | 五个管理器页各只给一句开关：《NEVPNManager》第 15 行 "isEnabled — A Boolean used to toggle the enabled state of the VPN configuration."、《NERelayManager》第 14 行、《NEFilterManager》第 21 行、《NEDNSSettingsManager》第 15 行、《NEAppPushManager》第 24 行；状态侧只有《NEVPNStatus》第 9—14 行的六态。两份读数是否取自同一时刻、开关翻转后状态多久才可见，归档件里没有任何口径。一 O05 的存在本身就是这条边界的登记（脚本一第 356—357 行，出处借用 `src("O04")`） | 启用读数与状态读数分两格各带 `obs.read_at`；不得把启用开关当作承载证明（反方向由一 `B07`、二 `D03` 拦） | 一 `O05`、一 `B07`、二 `D03` |
| N5 | **透明代理是否复用 VPN 状态图标**——公开口径没有承诺，也没有否认 | 《Status bar icons》第 1183—1187 行是相邻五条，其中与通道相关的只有第 1186 行 "VPN. iPhone is connected to a network using VPN."；第 1187 行的网络活动图标官方口径含 "Some third-party apps may also use it to show an active process."；透明代理在这份页里没有任何条目，《NETransparentProxyProvider》第 9—12 行只给与 `NEAppProxyProvider` 的三处行为差异，全页无图标或告知词形。矩阵把 `status_icon` 在 `transparent_proxy` 上归入 required 依据的是"该通道承载用户可见连接"这一推定（第 12.2 节"其四"），**不是公开承诺** | 对外表述不得写"没有图标说明没有透明代理"；这一格的取值要写成推定并带 `doc.notice_basis`，缺依据时降到 `Q3` 以下 | 一 `O02`、一 `N01`／`N02`（脚本一第 372—375 行） |
| N6 | **四类通道连"要不要这一格"都无法从公开文档确定**——矩阵里 19 格 `undocumented` | `FX/capability.csv` 第 7 行注释给的就是这条边界自己的定义："公开文档既没说有也没说没有，本表拒绝建模（脚本二跳过，不据此定覆盖空洞）"。这 19 格全部落在 `app_push` 6、`captive_network` 6、`relay` 4、`dns_settings` 3 四类上，按要素集中在 `netagent_registration`（4）、`on_demand_rule_set`（4）、`kernel_sysctl_node`（3） | 记 `undocumented`，不记 `not_applicable`（会造出"这一格对该类不成立"的假结论）也不记 `optional`（会抬高覆盖率）；二脚本第 249 行按 `av == "undocumented"` 跳过，既不报空洞也不报不适用 | 二 `D02`／`D05`（脚本二第 249 行的跳过、脚本二第 252 行与第 259 行的逐格计数）、判定 `Q3`／`Q4` |
| N7 | **第四条已弃用结果不在脚本一的取值域里**——这是脚本覆盖范围声明，不是台账合规 | 《necp.h》第 247—250 行四条 trigger 系结果全部标注 `// Deprecated`：TRIGGER 8、TRIGGER_IF_NEEDED 9、TRIGGER_SCOPED 10、**NO_TRIGGER_SCOPED 11（第 250 行）**；一 D04 的判据只列前三个字符串（脚本一第 322—323 行），出处那格也写"第 247—249 行"（脚本一第 140 行） | 登记 `no_trigger_scoped` 不会被拦，但它仍是已弃用取值：本篇把它记为漏检面，任何引用者在复核 D04 通过率时必须同时人工核对这一格 | 一 `D04`（漏检）、第 14 章 P9 |
| N8 | **六类通道在声明式与状态回报两个面上同时无格**——本篇覆盖面结论的上限 | 《Declarations》页第 4—71 行 52 条声明类型里，通道类只有第 28—34 行与第 52 行共 8 条（DNS 代理、DNS 设置、网络中继、Always On / IKEv2 / IPSec / VPN plugin 四条 VPN 子型、WebContent Filter plugin）；`app_proxy`、`content_filter`（非 plugin 形态）、`transparent_proxy`、`url_filter`、`app_push`、`captive_network` 这六类没有任何对应声明（第 12.2 节"其三"），同时也不在第 15 件回报项里（第 16 章读数 15） | 这六类的 `declarative_type` 写 `not_applicable`——这是通道口径缺失，不是台账缺失；装配主体只能写命令面载荷或提供者 API。它们的能力表仍有 required 格，二 `D05` 会逐格报覆盖空洞，此时应降到 `Q3` 而不是补造一格 | 二 `D04`／`D05`／`Q3`／`Q4`、一 `B04` |
| N9 | **`user_consent` 的 required 判定与注册可用性轴不同向**——公开侧的注册层给不出告知层的依据 | `Allowed in user enrollment` 这一格只写在描述文件页与声明对象页上：《NetworkRelay》第 14 行与《NetworkDNSProxy》第 14 行给 "iOS, Shared iPad, visionOS"、《Relay》页第 17 行给 iOS 与 visionOS，而《NetworkDNSSettings》第 18 行、《NetworkVPNAlwaysOn》第 14 行、《NetworkVPNIKEv2》第 14 行、《NetworkVPNIPSec》第 14 行与《MDM VPN payload》第 17 行一律 N/A；《Personal VPN》《DNS proxy provider》《Packet tunnel provider》三页整页没有可用性轴 | `user_consent` 的取值依据写 `doc.notice_basis`（告知层），不得写成注册轴的推论；两处反向时保留 required 并在复核说明里点出反向，不为了对齐可用性轴把 `dns_settings` 降成 optional | 一 `B05`、二 `D02`／`D05`、判定 `Q3` |

三条必须一起读的性质说明：

**其一，这份清单不是缺陷清单。**N1—N9 里没有一条说 Apple 的机制缺失；它们说的是**公开文档的表述范围**。图标面很可能对透明代理有某种呈现，公告词表背后很可能有内部映射，但公开侧给不出可读回的那一格，于是本篇的判定只能停在 `undocumented`、`not_recorded` 或 `Q3` 为止。N9 是这一组里唯一一条"两份公开文档各有口径、方向不同"而不是"某一格完全缺失"的边界，它同样不构成缺陷指控：注册可用性轴管的是"谁能装"，告知层管的是"用户看得见什么"，两问本来不必同答，只是本篇不能把前者当后者的依据。把这个区分写清楚的价值在于：读者不会把"文档没写"当成"可以放心"，也不会当成"必然有问题"。

**其二，这类边界的正确反应是降低表述强度，不是提高登记密度。**最典型的错误响应是给 N5 补一格"我们内部知道它有图标"，或者给 N6 把 19 格改成 `not_applicable` 好让覆盖率好看，或者给 N2 把装配回执抄成通道状态。三种写法都把不可回查的东西伪装成可回查的。正确写法只有两种：照上表记 `undocumented`／`not_recorded`／`not_applicable`，或者把该对象降到 `J3`／`Q3` 以下、不允许进入对外表述。

**其三，清单本身要靠回查维持。**N1、N2、N5、N6、N8、N9 这六条的读数是"某文档不含某词形"这类负发现，文档一换版本就可能变。本篇给的行号与命中数以 `.srcx15/A/` 与 `.srcx15/B/pages/` 下 2026-11-01 取回的转文本件为准（取回时刻记于 `A/urls.tsv` 第 5 列，16:07Z—16:22Z），公告与 KEV 读数由 `C/readings-15.sh` 与 `C/readings-15b.sh` 产出、输出记于 `C/readings-15.txt`（352 行）。任何引用者在另一个时间点复核，应先重跑这两件，再决定这一条是否仍然成立。

---

## 27. 结论

本文把"这台设备在 VPN 里"这句话拆开，拆成十一个各有主语的对象层（L1 权利 … L11 公告回查），加两套离线审查器与一份 11 类 × 22 要素的可得性矩阵。三条结论按证据强度排列。

**第一条（同一份文档内可直接核对，却最常被判成同一件事）：权利、装配、内核注册是三种不同的存在证明，缺任一种就给不出"这条通道在这台设备上"。**《com.apple.developer.networking.networkextension》第 6—17 行给的是权利取值词表，《MDM VPN payload》第 8—16 行给的是载荷键与装配路径，《network_agent.h》第 211—218 行与第 144—145 行给的是内核侧那一条注册记录（两个字符串字段各限 32 字节），三者之间没有任何公开换算表。同一份《NEVPNStatus》第 9—14 行的六态里，`invalid` 一格同时表示"配置不在网络扩展偏好里"与"提供者被禁用"（第 14 行），而过渡态三格（`connecting`／`disconnecting`／`reasserting`）读到的不是稳定归属。一 `A01`／`A02`／`A05`／`B03`／`T01`／`T02` 与二 `D01`／`D06` 拦的就是把这三样东西写成一句话的台账。

**第二条（跨文档可以核对，但公开侧没有换算表）：四个读数面在同一台设备上同时成立、互不连通。**权利侧给 12 项 entitlement 取值与两条不同的启用程序；装配侧给 `com.apple.vpn.managed` 家族、`com.apple.webcontent-filter`、`com.apple.relay.managed` 与 8 条声明式类型串；内核侧给 19 项策略结果（《necp.h》第 240—258 行，第 260 行为 `NECP_POLICY_RESULT_MAX`）、26 个 sysctl 节点（《necp.c》第 620 行起：6 只读、20 可写、仅 1 个 ANYBODY 可读）与 agent 的 17 个标志位；告知侧只有一句 VPN 图标说明，且相邻一格的"网络活动"图标官方口径允许第三方 App 复用。第 18 章按这四个面各写了一遍"能读到 / 读不到 / 如何映射进台账"，第 16 章的十八条公开读数就是这四个面的实测长度。

**第三条（本文量化出来的主缺口）：一条已经装配好的通道，在管理面与公告面都读不回来。**《Status items》82 行、66 项里网络通道词形命中 0（N2）；三份公告导出件 392 行、101 个去重组件名里六个通道词形命中 0，KEV 的 95 条 Apple 记录里 `networkextension` 命中 0（N1）。两条相减给出本篇最想让人记住的一句话：**"这条通道存在"由命令面与声明式的回执说话，"这条通道此刻在承载"只能由提供者接口或设置页说话，而"这个缺陷属于这条通道"在公开侧没有说法。**任何把管理面回执、状态栏图标或 CVE 组件名当通道归属读数的表述，都缺一个能回指的格——这正是一 `O01`—`O04` 与二 `P01`—`P05`、`X01`—`X06` 六组信号的全部内容。

第四条必须单列，因为它是本文的立场而不是结论：**通道台账要登记"哪条通道、由谁装配、在什么平面上、于什么时刻被读回哪一格"，永远不登记通道内容。**`K01`／`K02`、一 `T01`、二 `T01` 与 `sec.*` 拒收空间不是顺带的卫生提示。把代理地址、DNS 指向、身份证书正文、共享密钥或载荷正文抄进台账，等于把一份本来只受该通道自身规则约束的材料，复制成一份不受任何授权规则约束的副本；同时它会把一篇防御分析变成一份操作指南——这两件事本文都不做，第 2.3 节的六条"明确不做"就是这个边界的书面形态。

方法论上的验收与前十四篇同标准：每个信号码都要被真实输入触发、好输入要退出码 0 且不报警、不可用输入要与阻断分开。本文的 108 个码（一 64、二 44）全部可达，31 次实跑的退出码为 1/0/1/1/1/0/2/2/0/0/1/1/1/1 与 1/0/1/1/1/0/2/2/2/2/2/0/0/1/1/1/1，逐码可达性由 `FX/codemap.pl` 与 `FX/code-coverage.pl` 从两份运行日志提取为 64 行与 44 行，正文两支脚本与 `tools/` 下源文件逐字节一致。**这份验收证明脚本没有死码，不证明真实世界的失败已被覆盖**——第 23.7 节那五条限制比第 23.2 节那两张表更值得被记住。

对读者的最小可执行建议是三件（对应第 25 章第 3、4、6 问）：**把 `FX/capability.csv` 当起点而不是自己重造一份能力表，并严格按 `absent`／`not_recorded`／`undocumented` 三档分开登记；给每条通道对象补齐 `when.audit_at` 与 `doc.source`／`doc.line_ref` 三格，缺任一格就不要写"当前"；用退出码做门禁——`2` 判输入坏了，`1` 判有阻断信号，`0` 才允许进入对外表述。**这三件事不需要新工具、不需要访问设备、也不涉及任何通道内容；一支纯文本台账加两支离线脚本就能跑完，这正是本文提供脚本而不是提供建议的原因。

---

## 28. 参考资料

本轮存档：`.srcx15/`（取回日期 2026-11-01，逐件抓取时刻记于 `A/urls.tsv` 第 5 列，16:07Z—16:22Z；九处目录共 **192 个文件 / 17,052,556 字节**，分组为 `A/` 69 件 / 245,303 字节、`B/` 4 件 / 1,379,932 字节、`B/pages/` 7 件 / 154,904 字节、`C/` 16 件 / 3,552,047 字节、`RAW/` 60 件 / 1,804,774 字节（含 `networkextension/` 39 件、`devicemanagement/` 15 件、`bundleresources/` 4 件、`xcode/` 1 件与顶层 1 件）、`RAWW/` 8 件 / 9,439,123 字节、`tools/` 6 件 / 78,779 字节、`FX/` 20 件 / 328,783 字节、`IDX/` 2 件 / 68,911 字节）。清点与审计件：`IDX/cite-15.txt`（666 行，正文每处「见 X 第 N 行」的逐条落点索引）与 `IDX/overlap-15.md`（53 行，与前十四篇的词表落点实测与相邻篇分界，含本文的内容安全边界声明）。全部为公开文档，离线取回；**本轮未访问任何设备、未调用任何设备侧或 Apple 命令行工具（不执行 `profiles`、`nectl`、`networkQuality`、`xcrun`、`sysctl`、`route`）、未搭建或接入任何 VPN／代理／内容过滤通道、未改写任何代理或 DNS 指向、未提交任何管理面命令**。

### Apple 开发者文档与管理面文档（A 组 69 件 / 245,303 字节，其中 68 件为派生转文本件，`A/urls.tsv` 68 行为取回索引）

1. **Network Extension 框架与形态页**（第 4—6、10 章口径来源）：*Network Extension*（`ne-framework.txt`，53 行；第 8—19 行给出框架支持的六类扩展动作与 VPN 三分）、*Personal VPN*（25 行）、*Packet tunnel provider*（40 行）、*App proxy provider*（46 行）、*Content filter providers*（34 行，第 24—28 行判定语义）、*DNS proxy provider*（23 行）、*DNS settings*（13 行）、*Relay*（30 行）、*Relays*（7 行）、*URL filters*（18 行）、*Hotspot helper*（25 行）、*Filtering network traffic*（9 行）、*Wi-Fi configuration*（25 行）、*Wi-Fi accessory*（37 行）、*Local push connectivity*（19 行）、*Routing your VPN network traffic*（94 行；第 37 行例外清单口径、第 49、70、80 行路由与匹配口径、第 84—85 行常开与断开语义）。
2. **类与属性页**（本篇行锚最密集的一组，共 26 件）：`nevpnstatus.txt` 27 行（第 9—14 行六态、第 14 行 `invalid` 双关、第 19—20 行方法与属性）、`nevpnmanager.txt` 48 行（第 7 行 Personal VPN 定位句、第 15 行企业／个人 VPN 分类）、`nevpnprotocol.txt` 50 行、`netunnelprovidermanager.txt` 87 行（第 17 行分类口径、第 30—33 行启用与协议格）、`netunnelprovidersession.txt` 24 行、`nepackettunnelprovider.txt` 66 行、`neappproxyprovider.txt` 56 行、`nefilterprovider.txt` 46 行、`nefilterdataprovider.txt` 69 行、`nefilterdataverdict.txt` 37 行（第 9—14 行 verdict 取值）、`nefiltermanager.txt` 44 行、`nednsproxyprovider.txt` 35 行、`nednssettings.txt` 36 行、`nednssettingsmanager.txt` 33 行、`nerelaymanager.txt` 43 行、`netransparentproxyprovider.txt` 25 行、`netransparentproxymanager.txt` 19 行、`neapppushmanager.txt` 49 行、`neapppushprovider.txt` 49 行、`neondemandrule.txt` 40 行（第 8 行规则计数口径、第 20—23 行四类规则实例）、`neondemandruleaction.txt` 20 行、`neondemandruleconnect.txt` 24 行、`neondemandruleevaluateconnection.txt` 27 行、`neprovider.txt` 45 行、`neappextensionconfiguration.txt` 17 行（第 7 行 "It exists only for use by the framework…"、第 11—13 行两个通道类参数）、`ne-framework.txt`（同第 1 项）。
3. **开发者权利与能力页**：*Network extension entitlement*（`com.apple.developer.networking.networkextension.txt`，37 行；第 6—17 行给出 12 项取值（第 10—13、16 行五条写明 "when signed with a Developer ID profile"），第 20—22 行给 App Store 与 Mac App Store 之外两条不同的启用程序；第 20 行的字符串形态同时是二 `T04`（引用格既不是 CVE 也不是文档行号）夹具的出处）、*VPN API entitlement*（22 行）、*Hotspot configuration entitlement*（21 行）、*Wi-Fi information entitlement*（19 行）、*Adding capabilities to your app*（48 行）。
4. **管理面命令、载荷与声明**（第 5、11、13 章读数面事实来源）：*Install Profile*（`install-profile-command.txt`，30 行；第 23—24 行命令与响应）、*Remove Profile*（28 行；第 21—22 行）、*Profile List*（28 行）、*DeclarativeManagement*（`declarative-management-command.txt`，22 行；第 10、21—22 行）、*Profile-specific payload keys*（158 行；第 83、87、92、105—107、143—145、148 行共十项网络相关载荷名——`DNSSettings`、`Relay`、`ParentalControlsContentFilter`、`DNSProxy`、`GlobalHTTPProxy`、`NetworkProxyConfiguration`、`AppLayerVPN`、`AppToAppLayerVPNMapping`、`VPN`、`WebContentFilter`）、*VPN payload*（`mdm-vpn.txt`，98 行；第 8—16 行）、*Web Content Filter payload*（75 行）、*Wi-Fi payload*（86 行）、*App Layer VPN*（214 行）、*App-to-app layer VPN mapping*（128 行；第 8、89、125 行）、*Configuring multiple devices using profiles*（100 行）、*Restrictions*（57 行）、*Declarations*（`devicemanagement-declarations.txt`，75 行；第 4—71 行 52 条声明类型，通道类为第 28—34、52 行共 8 条）、*Status items*（`status-items.txt`，82 行；13 个分组、66 条列表项，网络通道词形命中 0——第 16 章读数 15、第 26 章 N2）。
5. **声明式通道页**（`dd-*` 共 8 件）：*NetworkDNSProxy* 53 行、*NetworkDNSSettings* 62 行、*NetworkRelay* 37 行、*NetworkVPNAlwaysOn* 68 行（第 12—18 行可用性轴、第 27 行 `"UIToggleEnabled": false`、第 28—31 行示例正文里的 `TunnelConfigurations`、`ProtocolType` 与 `Interfaces` 三键）、*NetworkVPNIKEV2* 44 行、*NetworkVPNIPSec* 41 行、*NetworkVPNVPNPlugin* 44 行、*WebContentFilterPlugin* 51 行。各页第 8 行为类型串、第 12—18 行为可用性轴，是二 `D04`／`P05`／`V03` 的比对基准。

### 安全指南、支持页与公告口径（B 组 4 件 / 1,379,932 字节 + `B/pages/` 7 件 / 154,904 字节；原始件 8 件 / 9,439,123 字节记于 `RAWW/`）

6. Apple, *Platform Security Guide*（`B/apple-platform-security-guide.txt`，4,885 行；与第 08—14 篇同一 `pdftotext -enc UTF-8` 转文本件，行号可直接互参。本篇引用集中在第 1572 行"开发者可用 DriverKit、EndpointSecurity 与 NetworkExtension 编写 VPN 与网络工具而无需 kext"的框架定位句、第 3805—3815 行管理面部署三种 VPN 形态（On Demand / Per-app / Always On）、第 4474 行示例配置载荷清单——该行把 `Network and VPN settings` 与 `Credentials and identities`、`Certificates` 并列，是管理面把通道与凭据混在同一份清单里的公开口径）。
7. Apple 开发者支持页 7 件（`B/pages/`，原始 HTML 同批记于 `RAWW/`）：*Status bar icons*（`status-icons.txt`，1,237 行；第 1183—1187 行相邻五条、第 1186 行唯一一条 VPN 句 "VPN. iPhone is connected to a network using VPN."、第 1187 行第三方复用许可、第 1189 行起第二张表）、*About VPN usage*（`dep-vpn-overview.txt`，404 行）、*VPN and MDM*（`dep-vpn-mdm-overview.txt`，402 行）、*Always-on VPN declaration*（`dep-always-on-decl.txt`，415 行）、*VPN plugin declaration*（`dep-vpn-plugin-decl.txt`，611 行）、*Web content filter payload*（`dep-webcontentfilter-payload.txt`，453 行）、*Restrictions for supervised devices*（`dep-restrictions-supervised.txt`，896 行；第 345 行默认开启限制）。
8. 三条并行版本线 CSAF 导出件：`B/149041.json`、`B/149227.json`、`B/149230.json`（三件与 `.srcx13/B/` 同名件同源），合计导出 **392 条 CVE 行 / 101 个去重组件名**。派生件 `C/advisory-entries.tsv`（393 行 = 表头 + 392 条 / 157,214 字节；列为 `file / cve / component / impact / description / avail`，组件名在第 3 列）既是第 14、16 章的公告读数来源，也是脚本二的第三份输入。

### XNU 开源侧与公告聚合读数（C 组 16 件 / 3,552,047 字节）

9. **内核源码六件**（三件附 `.origin` 记录其在源码树内的路径）：`necp.h`（1,701 行；第 240—258 行 19 项策略结果、第 247—250 行四条 `// Deprecated`、第 260 行 `NECP_POLICY_RESULT_MAX`、第 629、638—643 行客户端动作与第 641 行 "Get a one-time use token from an agent"、第 648／649／657／658 行四格 `// Requires entitlement`、第 671—690 行 agent 绑定 7 族参数、第 691—692 行组成员）、`necp.c`（14,070 行；第 620 行起 26 个 sysctl 节点、第 627—629 行追踪与丢弃等级、第 649—668 行 `data_tracing` 系节点（只按 level／port／proto／pid／ifindex 过滤，第 641 行那一格 `drop_dest_level` 是 26 个节点里唯一 ANYBODY 可读的）、第 841—861 行 `resultString[20]`（首格 `"INVALID"`）、第 1049／1385／3347／13935 行 `PRIV_NET_PRIVILEGED_NECP_POLICIES`、第 956—957 行 `PRIV_NET_PRIVILEGED_CLIENT_ACCESS` 与 `PRIV_NET_PRIVILEGED_SERVER_ACCESS`、第 7650—7651 行两个 `IOTaskHasEntitlement` 权利名 `com.apple.private.necp.match` 与 `com.apple.developer.CaptiveNetworkPlugin`）、`necp_client.c`（13,310 行）、`network_agent.h`（348 行；第 144—145 行两个 32 字节字段、第 150 行 `NETAGENT_MAX_TOKEN_COUNT` 256、第 153—169 行 17 个标志位、第 211—218 行 `struct netagent` 7 字段）、`network_agent.c`（3,212 行；第 938—1014 行注册与断言流程、第 1085／1266／1274 行动作分派、第 2577／2579 行权限判定与那条 "Client does not hold the necessary entitlement" 日志）、`content_filter.c`（7,726 行，过滤器 verdict 的内核落点）。
10. 源码定位件：`C/xnu-bsd-net-tree.json`（1,395 行，`bsd/net` 目录树）、`C/xnu-tags.json`（102 行，标签与版本定位）；`RAW/networkextension.json`（32,341 字节，Network Extension 文档节点的原始结构化导出件，A 组第 1—2 项转文本件的来源）。
11. 只读读数脚本 `C/readings-15.sh`（134 行）与 `C/readings-15b.sh`（42 行）及其输出 `C/readings-15.txt`（352 行，生成时刻 2026-11-01T16:32:17Z）：语料行数／文件数／去重组件数、组件名词形匹配、影响句关键词邻近计数、entitlement 与 keychain 词形、KEV 聚合与逐记录关键词计数、两份脚本的验收读数。第 16 章十八条读数由这三件产出。

### 本轮产物（自写，只读处理公开存档文本）

12. 脚本一 `tools/channel-ledger-review.sh`（408 行，**64 个信号码** = 60 个信号 + 判定档 `J1`—`J4`；**56 条阻断**（`HB` 集在第 107 行））：通道归属台账审查器，输入 `<通道对象标识>,<字段名>,<值>` 三元组台账，十二个命名空间共 64 个已登记字段名，另设 `sec.*` 拒收空间，逐对象输出信号与四档。脚本二 `tools/channel-availability-diff.sh`（344 行，**44 个信号码** = 40 个信号 + 判定档 `Q1`—`Q4`；**33 条阻断**（第 110—116 行））：通道 × 要素差集与公告词表比对器，固定顺序三份输入——要素清单（8 列，11 类通道 × 22 项要素）、通道能力表（3 列）、公告词表（CSAF 派生 TSV，仅取 `cve` 与 `component` 两列）。两支脚本全文见第 21 章与第 22 章，都不联网、不访问设备、不修改输入，唯一写出目标是 `mktemp -d` 的临时目录（由 trap 在退出时删除）。
13. 实跑驱动与留档：`FX/run-all.sh`（脚本一 14 次实跑，日志内 14 个 `===== RUN:` 分段按序作 R1—R14）与 `FX/run-all-2.sh`（脚本二 17 次实跑，分段按序作 R1—R17），输出 `FX/run-log.txt`（768 行）与 `FX/run-log-2.txt`（1,065 行），每次实跑记录命令行、逐条信号、脚本自打的汇总行与 `exit=` 值；逐码可达性由 `FX/codemap.pl`（32 行）与 `FX/code-coverage.pl`（24 行）从这两份原始输出提取为 `FX/codemap-1.txt`（64 行）与 `FX/codemap-2.txt`（44 行），另存 `FX/codemap-1.err` 与 `FX/codemap-2.err`。
14. 样例输入（**全部为合成值**，不含任何真实通道地址、提供者标识、Team ID、凭据或载荷正文）：脚本一侧 `FX/fixture-channel.txt`（153 行，混合缺陷）、`FX/fixture-channel-good.txt`（131 行，十二格齐备，R2 的 2 个 `J1`）、`FX/fixture-channel-codes.txt`（153 行，逐码遍历，R1 的 74 个对象 / 60 个码 / 309 条阻断），对应 `.csv` 三件为 53／31／48 行；脚本二侧 `FX/capability.csv`（219 行物理、第 9—219 行共 **211 条数据行**：`required` 58、`optional` 95、`not_applicable` 39、`undocumented` 19）、`FX/capability-bad.csv`（226 行，专造 C01—C05 形态）、`FX/capability-empty.csv`、`FX/advisory-empty.tsv`。第 23.2 节的三十一次实跑全部只读这些件。
15. 引用与文档自审器：`tools/cite-index.sh`（156 行）与 `tools/cite-index-2.sh`（98 行）扫正文与两份脚本里的「见 X 第 N 行」形态，把文档简称解析到 `A/`、`B/pages/`、`C/` 下的实际件并打印该行内容，产出 `IDX/cite-15.txt`（666 行，列为模式序号、文件、行号、该行截断 160 列）；`tools/doc-audit.pl`（42 行）逐条把脚本的 DOC[...] 文案回指到归档件，核对被引件存在性与行号是否越界；`tools/refcheck.pl`（62 行）按「文件名之后 60 字符内的整数」粗筛越界引用，本轮把窗口截断到行尾与下一个归档文件名之前——原先窗口会吃到同一条 DOC 文案后半段的另一条引用，报出 3 处假阳性：network_agent.h 第 162 行那条把同行后半的 necp.h 第 689—690 行算了进来（2 处），necp.h 又跨过行尾把下一条的 necp.c 第 7650—7651 行算了进来（1 处），三处都逐条人工回查确认在范围内。修完之后脚本一核对 37 处、脚本二核对 28 处，异常各 0 处。判据是正文侧的行锚解析器 linecheck-15.pl（270 行，简称表从 19 行起）：逐条解析「书名号简称＋第 N 行」、ASCII 文件名＋第 N 行、同句继承的裸「第 N 行」，以及 18 个字符以上的英文引文，引文在被引行的 ±1 容差内回查归档件。末次运行读数为「行锚解析 2,140 处、引文落点检查 76 处、同段无具名文档的裸行锚 301 处、引用脚本自身行号 32 处」，三类判据（未解析文档、行号越界、引文未落在被引行）各 0 处；另有 4 处「非紧邻命中」——引文落在同一行锚所引多行区间之内、但不在区间端行的 ±1 内，只作信息项、不计入失败。这一件本轮改过两次：一是把 advisory-entries.tsv 加进简称表（解析数从 2,096 处升到 2,155 处；其后重写本段与第 16 章第 3 条的读数表述，末次运行解析 2,140 处）。二是试过把反引号里的文件名也当可继承的文档名，跑出 35 处误判后回滚——反引号在正文里既用于文件名、也用于字段名与取值，无法据此判定归属。新解析出的那批锚点随即暴露第 16 章第 3 条的一处含糊：该条对 elevated privileges 只写「1 行」不给行号，而 proximity 与 arbitrary code 两个计数走的是「组件＋影响句原文＋来源公告文件」三元组去重口径（6 条与 14 条，原始匹配分别是 8 行与 22 行），与「行」的字面不符；现已把口径写明、把「行」改称「条」，并补上 advisory-entries.tsv 第 350 行这一行锚。第 23.6 节的三项核对由前两件执行，结果口径为「未找到文件数 0、行号越界数 0」。

### 同系列相邻篇目

16. **第 02 篇（访问控制与应用交互）**——entitlement 清单与运行时能碰什么归它，本文只取 entitlement 作为通道存在的三种证明之一（L1），分界见第 2.2 节与第 4 章。**第 03 篇（应用防护与抓包审计）**——抓包、代理检测与自有流量审计归它，本文**不写任何抓包或代理接入操作**，只写结论能不能被登记（第 2.3 节）。**第 04 篇（传输与协议安全）**——IKEv2／IPSec／TLS 的密码学语义归它；DNS 泄露、split tunneling 与 kill switch 失效在本文只作失效形态输入（第 7、14 章）。**第 08 篇（隐私授权链）**——用途声明与授权状态机归它；本文的 per-app 是 VPN 通道装配（第 5、8 章），与设置页授权列表同形不同义。**第 09 篇（更新链与补丁传导）**——补丁走到哪一台归它；本文反向消费其结论，接缝在第 14 章 P13／P14。**第 10 篇（设备生命周期与归属迁移）**——设备属于谁、MDM 限制项与声明式通道归它；两篇共用同一批 MDM 存档件，主键不同：设备 vs 通道。**第 13 篇（日志与诊断证据链）**——记录的产生、留存与送达归它，本文不写留存时长与采集同意；两篇都用四档但对象不同。**第 14 篇（签名与分发授权链）**——描述文件对 entitlement 的白名单授权归它，本文从"权利已被授权"之后开始（L1 接缝与 L10 到期使通道失效）。**第 06、07、11、12 篇**——方法同源（差集 + 四档判定 + 两个离线只读脚本），客体分别是系统服务、推送链路、数据副本与第三方依赖。**第 01 篇**与**第 05 篇**——构成第 3 章词表 C（公告口径）与第 14 章类型学的既有基础；本文 P1—P14 中与前篇同名的形态均已在前篇视角声明里划界。

---

咨询ios系统请咨询 telegram：https://t.me/one00190
