# iOS APNs 推送通知投递链路缺陷归属防御分析报告

## 摘要

iOS 上有一条被大量讨论却很少被完整拆开的外部输入通道：Apple Push Notification service（APNs）。它的特殊之处在于**每一格关键状态都不在读者能打开的文件里**——设备令牌由系统与 APNs 之间的注册流程产生、鉴权令牌由 provider 服务器自己签、请求走 HTTP/2 + TLS 1.2 或更高、载荷由 APNs 存储并在设备上线后投递、到了设备上还要经过通知中心、服务扩展和内容扩展才变成用户看得见的一条横幅。这条链路上任何一格出错，公开可得的读数只有两种形态：provider 侧收到的一次 `:status` + `reason`，或者 Apple 公告里一行组件名是 `Notifications`、`Notification Services`、`Status Bar`、`VoiceOver` 的条目。**这两种读数都不写"哪一层错了"**，这就是本文要补的那张表。

全文按十层拆开推送链路（设备令牌注册、授权与 entitlement、provider 鉴权、传输与信任链、请求头语义、载荷、APNs 存储与投递、设备端派发与呈现、扩展执行、专用信道），给出 N1—N12 的缺陷类型学（按"错误发生在哪一次校验"分型，而不是按 CVE 编号分型），一张层 × 责任方 × 更新通道 × 设备侧证据的归属矩阵，以及 Apple 安全公告口径下的 13 条公开读数。核验部分提供两个纯文本、离线、只读的脚本——一个把一条 APNs 请求文本（HTTP/2 首部 + JSON 载荷）按 Apple 文档口径审一遍并预演它最可能收到的 `reason`，一个把一份响应台账按文档的 32 个 `reason` 串与十档状态码逐格对齐并分诊重试口径——两者都在本轮做了全量分支覆盖验收，信号码共 79 个（脚本一 49 个、脚本二 30 个），**79 个全部在本轮环境实跑触发**。其中两类分支需要特殊构造才能触发——"文件存在但读不到"要靠给临时文件施加只读拒绝 ACL（Windows 用 `icacls /deny`，类 Unix 用 `chmod 000`），"临时目录不可用"要靠把 `TMPDIR` 指到一个不存在的目录——两者的构造与复现方法见第 23.4 节。覆盖验收同时暴露并修好了两个真实缺陷：临时目录失败时 `exit` 只退出了命令替换的子 shell，导致脚本二会带着一份空读数给出乐观判定；以及 Git Bash 上 `-r` 测试对 ACL 拒绝不敏感，会把不可读误报成空行位置错误。这两处的修法与设计原则一并写在第 21、23 章。

本文不提供任何可用的漏洞利用代码、提权或绕过步骤、伪造鉴权令牌的实现方法，也不提供任何针对具体设备的攻击操作；给出的只有公开文档口径、公告口径、以及读者对**自己导出的文本**能做的只读判定。两个脚本都不联网、不写设备、不向 APNs 发出任何请求。

---

## 目录

1. [引言](#1-引言)
2. [视角声明与本文边界](#2-视角声明与本文边界)
3. [三套词表：文档口径、公告口径、设备侧可见口径](#3-三套词表文档口径公告口径设备侧可见口径)
4. [L1 设备令牌注册层](#4-l1-设备令牌注册层)
5. [L2 授权与 entitlement 层](#5-l2-授权与-entitlement-层)
6. [L3 Provider 鉴权层](#6-l3-provider-鉴权层)
7. [L4 传输与信任链层](#7-l4-传输与信任链层)
8. [L5 请求头语义层](#8-l5-请求头语义层)
9. [L6 载荷层](#9-l6-载荷层)
10. [L7 APNs 存储与投递层](#10-l7-apns-存储与投递层)
11. [L8 设备端派发与呈现层](#11-l8-设备端派发与呈现层)
12. [L9 扩展执行层](#12-l9-扩展执行层)
13. [L10 专用信道层](#13-l10-专用信道层)
14. [缺陷类型学 N1—N12](#14-缺陷类型学-n1n12)
15. [归属矩阵：层 × 责任 × 更新通道 × 证据](#15-归属矩阵层--责任--更新通道--证据)
16. [公开案例读数](#16-公开案例读数)
17. [可见性边界：这条链路上读者能拿到什么](#17-可见性边界这条链路上读者能拿到什么)
18. [崩溃与日志读数侧](#18-崩溃与日志读数侧)
19. [四级判定模型](#19-四级判定模型)
20. [运营指标 P1—P10](#20-运营指标-p1p10)
21. [只读核验脚本一：请求口径审查器](#21-只读核验脚本一请求口径审查器)
22. [只读核验脚本二：响应台账分诊器](#22-只读核验脚本二响应台账分诊器)
23. [两个脚本的全量分支覆盖验收](#23-两个脚本的全量分支覆盖验收)
24. [十二个误区](#24-十二个误区)
25. [常见问题](#25-常见问题)
26. [未公开文档化边界清单](#26-未公开文档化边界清单)
27. [结论](#27-结论)
28. [参考资料](#28-参考资料)

---

## 1. 引言

### 1.1 为什么把推送链路单独立一篇

推送通知在 iOS 安全讨论里长期处于两种极端待遇：要么被当成"某个远程利用链的第一跳"来讲，要么被当成开发者文档里的一节配置说明来讲。这两种讲法都错过了中间那一大块——**一条通知从 provider 服务器走到用户眼睛里的路上，一共有十格可能出错的校验，而这十格里只有一小部分归 Apple 修，其余分散在 provider 代码、App 的 entitlement、App Group 里那个扩展的 thirty 秒预算，以及设备侧的通知中心实现**。

错位在读数上最直接：

- Apple 文档给的是**规则**：`apns-push-type` 有 12 个取值、载荷上限 4 KB（VoIP 5 KB）、`reason` 有 32 个串、状态码有 10 档、令牌"1 小时内过期"。
- Apple 公告给的是**结果**：一行 `Notifications`，一句 "Impact: An attacker with physical access to an iOS device may be able to view notification contents from the Lock Screen"，跟着一个 CVE 编号和一组机型。
- 设备侧用户看得见的是**现象**：一条通知没到、到了但没弹、弹了但内容是旧的、该被删掉的还挂在通知中心、锁屏上出现了本不该出现的正文。

三份东西对不上，就会出现两种都有害的结论：一种是"推送这条链路没问题，公告里没有就是没有"（公告词表根本不按层组织，见第 3.2 节）；另一种是"推送是一个巨大的远程攻击面"（而文档明确写着载荷放不下敏感信息、APNs 只保留每 bundle ID 一条、且设备侧投递受功耗与用户授权双重限制）。本文的目标是把这两种结论都换成**可核对的层归属**。

### 1.2 这条链路的规模感

有三个可以直接从公开文档里读出来的规模数字，构成本文的"这张表有多大"的直觉：

1. **请求头与载荷的规则格**：Apple 在《Sending notification requests to APNs》一页里列了 9 个请求头字段（含两个 HTTP/2 伪首部）、12 个 `apns-push-type` 取值、以及 4 条 HPACK 编码要求（第 24—39 行）。
2. **响应的词表**：《Handling notification responses from APNs》给出 10 档状态码与 32 个 `reason` 串，每个串只挂一档状态码（第 14—63 行）；广播/信道侧另有一份《Handling error responses from》的表，**28 个串、8 档状态码，与设备推送那份不共用词表**（第 12—55 行）。
3. **公告侧的读数**：本轮从 Apple Security Releases 的 12 份发布文档里取到 13 条与通知直接相关的条目，组件名分别落在 `Accessibility`、`Status Bar`、`VoiceOver`、`Libnotify`、`Share Sheet`、`Notifications`、`Notification Services` 七个格子里（见第 16 章，逐条带存档行号）。

第 3 章会说明这三张表为什么不能互相换算；第 14 章给出跨越它们的类型学；第 21—23 章给出读者可以立刻执行的只读核验。

### 1.3 本文的三个问题

1. **分型问题**：一条通知没按预期出现，错误发生在哪一次校验——是令牌、是鉴权、是首部语义、是载荷结构、是存储与合并策略、是设备授权状态、还是扩展的时间预算？（第 14 章 N1—N12）
2. **归属问题**：这一格的修改权在谁手里——Apple 的 APNs 服务、Apple 的设备侧组件、provider 服务器代码、App 自己的 entitlement 与 payload 生成逻辑、还是那个通知服务扩展？修完之后公告落在哪个组件名、设备上显示在哪个版本号？（第 15 章矩阵）
3. **自证问题**：读者手上只有公开文档、自己的 provider 日志和控制台导出件时，能做哪几种可复现的只读判定？（第 17—18、21—23 章）

### 1.4 阅读顺序建议

只关心"我这条请求为什么会失败"的读者，直接看第 8、9 章和第 21 章脚本；关心"这个缺陷该谁修"的看第 14—16 章；关心"我怎么在不碰设备的前提下自证"的看第 17、19、22、23 章。第 2 章的边界声明要先读一次，它规定了本文与本报告集其他篇目之间的重叠怎么处理，也规定了本文的英文引语按什么口径转录与复核。

---

## 2. 视角声明与本文边界

本文是"归属与口径"视角的推送链路分析，不是推送服务搭建教程，不是利用手法汇编，也不是设备侧通知功能的入门。与本报告集里已有的篇目关系如下：

| 主题 | 本文覆盖 | 去处 |
| --- | --- | --- |
| iMessage 攻击入口（第 01 篇） | 只取"APNs 作为承载方"这一格：尺寸上限、投递即删、离线队列（第 10.4 节） | 第 01 篇讲消息链路本身的攻击面与远程触发条件 |
| 访问控制与应用交互（第 02 篇） | 只取推送相关 entitlement 与用户授权状态（第 5 章） | 第 02 篇讲权限模型全貌与跨应用交互限制 |
| 应用防护与抓包审计（第 03 篇） | 不覆盖。本文不讨论如何抓取或中间人查看任何流量 | 第 03 篇讲应用侧防护与自有流量的审计口径 |
| 身份认证与通道加密（第 04 篇） | 只取 APNs 自己的两套鉴权与根证书迁移（第 6、7 章） | 第 04 篇讲 TLS/ATS/OAuth 等认证链路全景，本文不重述密码学 |
| 生物识别安全机制（第 05 篇） | 只在第 11.4 节作为"锁屏内容可见性"的相邻条件出现一次 | 第 05 篇讲生物识别机制与取证口径 |
| XPC 与 Mach IPC（第 06 篇） | 不覆盖设备进程间通道。第 18 章的崩溃读数与第 06 篇互补：那篇分 IPC 层，本篇分推送层 | 第 06 篇讲端口、名称空间、MIG 与 XPC 对象层 |
| 越狱与锁定模式 | 只在第 17 章影响"读数可得性"时出现（`roots_installed`） | 越狱篇、锁定模式篇 |
| 内存损坏 / 沙箱逃逸 / 内核提权 | 不覆盖。本文第 16 章的公告读数只到"组件与影响"这一层，不推断利用原语 | 内存损坏篇、沙箱逃逸篇 |

一句话：**其他几篇讲的是边界两侧的东西，本文讲这条投递链路本身的十格校验，以及这三套词表之间的落差**。同一件事（例如"载荷里不该放敏感数据"）如果在别的篇目里已经讲过，本文只做一句话引用并给出行号，不重述。

**范围声明**：全文只讨论公开文档化的机制、Apple 安全公告的公开条目、以及在这些公开规则之上可以安全实施的只读判定。本文不提供：可用的漏洞利用代码；伪造或暴力获取鉴权令牌、设备令牌的操作方法；针对 APNs 或任何具体设备的请求重放、洪泛、拒绝服务实现（文档里的限流与封禁条款在本文只作为**口径证据**引用，不作为操作指引）；服务劫持、名称空间抢占或端口操纵步骤；提权、绕过用户授权或绕过锁屏保护的具体做法。第 21、22 章两个脚本都是离线文本处理：一个读一条"请求文本"（HTTP/2 首部 + JSON 载荷的文本导出件），一个读一份"响应台账"文本，两者都不写设备、不联网、不修改输入文件、不向 APNs 发出任何请求，中间文件只落在系统临时目录并在退出前删除。所有"核验"指读者对**自己 provider 的日志脱敏结果、自己的控制台导出件、或公开样本**执行采集与比对。

**引用转录约定**：英文原文按原样转录，只做两项字符归一——排版撇号（’）写作 ASCII 撇号（'），排版引号（“ ”）写作直引号（"）；其余字符、大小写不改。复核时还要允许下面六种**排版层差异**，它们不是转录差异：

1. **空白折叠**。存档页面会折行，词与词之间可能隔一个换行或一串空格；检索时把引语里的空格当作"至少一个空白字符"。
2. **文档页是 JSON 扁平件**。Apple 开发者文档的取回形态是一行一个内容项的扁平文本，表格行被拍平成 `键 | 值类型 | 说明` 一行，段内换行会造出"半句话"。本文引的表格行按整行引用，不做拼接。
3. **链接标签缺口**。扁平正文里页面内超链接只留下 `doc://…` 形式的目标标识，**标签文本在该页的 `--- REFERENCES ---` 表里**。遇到这种情况，本文要么按 references 表回填标签并注明，要么只引到可核对的前半句。第 7.4 节引《Setting up a remote notification server》的根证书段即属此情形：该句里两个链接的标签在扁平件里是空槽，本文只引可核对的残句并注明。
4. **破折号**。原文里的双连字符 `--` 在页面上渲染为破折号，本文按渲染形态（—）转录。
5. **省略号**。`…` 与 `...` 都代表原文中被删去的一整段（可能是插入语或链接残段），长度不固定，复核时按不定长空洞匹配。
6. **反引号**。引语内出现的反引号是本文的 markdown 代码标记（为了让 `apns-push-type` 这类字面量不被当成标签吞掉），不属于原文字符；反引号里的内容本身仍照原样、原大小写抄写。

两条已知的存档缺口**就地注明、不做修补式改写**：

- **缺口 A（示例代码不可得）**：Apple 文档页里的 Listing / code snippet 正文在扁平件里**只剩标题行**（形如 "Listing 1. A remote notification payload for showing an alert"），代码本体不随文本接口下发。因此本文凡是提到"某个 payload 样例"的地方，只引用文档表格里的键定义句与 Listing 标题句，不转写任何代码内容，也不声称某段 JSON 是 Apple 原文。
- **缺口 B（entitlement 页的原始 JSON）**：`aps-environment` 一页的 details / possibleValues 两段在扁平件里保留的是 Apple 服务端返回的原始 JSON（形如 `{"kind":"possibleValues",…}`），本文引用其中的英文句子时会说明它出现在 JSON 字段值内（第 4—6 行）。

本轮还有一类**取回但不可引用**的件需要交代：Apple Support 的推送 FAQ 与两篇 developer news 文章（AAA → UserTrust 根证书迁移、APNs 根证书变更）在本机取回后展平成的是站点导航壳，正文由页面脚本渲染，因此已从存档里剔除并在 `MANIFEST.txt` 标注，本文对这两件事只引用开发者文档里可核对的句子（第 7.4 节），不引用新闻页正文。

最后，原文本身的拼写异常一律保留原样并加注，本文不做"顺手修正"：Apple 文档里出现过 `maxiumum`（《Sending notification requests to APNs》第 40 行）、`seperates` / `occured` / `seperate` / `persistant`（《Viewing the status of push notifications using Metrics and APNs》第 15、28 行）、`recieve`（《Pushing background updates to your App》第 8 行）、`enviroment`（《Sending broadcast push notification requests to APNs》第 25 行）、以及一个明显的后缀残段 `h.complication`（同页第 48 行，见第 8.3 节）。

---

## 3. 三套词表：文档口径、公告口径、设备侧可见口径

### 3.1 文档口径：规则表长什么样

Apple 开发者文档里的推送词表是**按请求/响应结构**组织的：一条 POST 请求有 `:method`、`:path`、`authorization`、`apns-push-type`、`apns-id`、`apns-expiration`、`apns-priority`、`apns-topic`、`apns-collapse-id`（《Sending notification requests to APNs》第 24—33 行）；一个载荷有 `aps` 字典里的 20 个 Apple 定义键（《Generating a remote notification》第 31—50 行），`alert` 字典里的 10 个键（同页第 53—63 行），`sound` 字典里的 3 个键（同页第 66—69 行）；一个响应有 10 档状态码和 32 个 `reason` 串（《Handling notification responses from APNs》第 14—63 行）。

这套词表有三个特点决定了它在缺陷讨论里的位置：

1. **它是"应当如此"，不是"发生过什么"。** 它告诉你违反哪一格会收到哪个 `reason`，不告诉你历史上哪一格真的被违反过、以什么形式被修掉。
2. **它是分渠道的。** 设备推送、广播/信道、Web push 是三套不同的请求形态与词表：广播侧的 `reason` 表有 28 个串（《Handling error responses from Apple Push Notification service》第 28—55 行），且该页状态码表只列 400 / 403 / 404 / 405 / 413 / 429 / 500 / 503 八档、没有 410（同页第 13—20 行）；Web push 用的是 `TTL` / `Authorization` / `Content-Encoding` / `Topic` / `Urgency` 五个标准头（《Sending web push notifications in web apps and browsers》第 31—35 行）。**把设备推送的口径套到广播信道上，是本文第 14 章 N10 型的来源。**
3. **它自己就不完全自洽。** 最明显的两例：尺寸上限在一页里写 4 KB / VoIP 5 KB（《Generating a remote notification》第 7—9 行），而平台安全指南里描述 iMessage 时写的是 "APNs can only relay messages up to 4 or 16 KB in size, depending on the iOS or iPadOS version"（第 9346 行）；推送类型取值在《Sending notification requests to APNs》里是小写的 `liveactivity`（第 51 行），在广播两页里写成 `Liveactivity` 与 `LiveActivity`（《Sending broadcast push notification requests to APNs》第 23 行、《Sending channel management requests to APNs》第 26 行）。这类落差本文逐条列出（第 26 章），不当作自己的推断。

### 3.2 公告口径：Apple 写了什么、没写什么

Apple 的安全公告文档在页面开头就把口径交代清楚了，这句话在本文里被反复引用：

> "For the protection of our customers, Apple doesn't disclose, discuss, or confirm security issues until an investigation has occurred and patches or releases are generally available."

落到推送这一层，公告词表的特征是：

1. **组件名不是链路层名。** 本轮 13 条读数里，组件名是 `Accessibility`、`Status Bar`、`VoiceOver`、`Libnotify`、`Share Sheet`、`Notifications`、`Notification Services` 七个（见第 16 章）。**没有一个叫 APNs。** 也就是说，公告的组件粒度是"设备侧哪个子系统的代码被改了"，不是"链路上哪一格出了缺陷"。
2. **Impact 句是能力描述，不是层归属。** "An app may be able to spoof system notifications and UI"（120880 第 430 行）与 "Notifications marked for deletion could be unexpectedly retained on the device"（127002 第 430 行）两条，前者落在本文 L8/L9 的呈现侧，后者落在 L8 的持久化侧，但从句子本身看不出来。
3. **修复描述只到策略层。** 本轮 13 条里的 Description 句一共只有 5 种写法："additional entitlement checks"、"improved private data redaction for log entries"、"improved state management"、"adding additional logic"、"improved access restrictions"、"improved checks"、"improved data redaction"（详见第 16 章）。它们指向**校验点**，不指向**缺陷机理**。
4. **版本线是并行的。** 同一个 CVE-2026-28950 在 2026-04-22 与 2026-05-11 两次发布里出现在 5 份不同文档上，覆盖机型从 iPhone 11 一直排到 iPhone 6s / iPod touch 7（127002 第 425 行 对 127114 第 425 行）。**同一条缺陷在不同版本线上的文档编号不同**，这是"修完之后设备显示在哪个版本号上"这个问题的第一个来源。

### 3.3 设备侧可见口径：用户与开发者实际看得见什么

第三种词表最容易被忽略，因为它是**现象名**，不是字段名。本轮能直接从文档里取到的现象词包括：

- 通知中心与锁屏：横幅分两阶段呈现，先是一条 abbreviated banner，用户按下才展开完整界面（《Customizing the Appearance of Notifications》第 5 行）。
- 授权状态：`provisional` 送达时"安静"——不响、不弹横幅、不上锁屏，只进通知中心历史（《Asking permission to use notifications》第 14 行）。
- 投递结果的分类名：控制台与指标里叫 `delivered` / `stored` / `discarded`，并且 discarded 会带原因类别，如 `Stored - Device Offline`、`Discarded - Disabled`（《Viewing the status of push notifications using Metrics and APNs》第 10、15 行）。
- 后台通知的丢弃现象：系统会 hold 并延迟投递，且"收到新的后台通知时丢掉旧的只留最新一条"、"App 被强制退出则丢弃 held notification"（《Pushing background updates to your App》第 16—17 行）。
- 服务扩展超时：`didReceive(_:withContentHandler:)` 只有"大约 30 秒"，超时后系统改调 `serviceExtensionTimeWillExpire()`，两者都没调用完成块就显示原始内容（《Modifying content in newly delivered notifications》第 22 行、《UNNotificationServiceExtension》第 14 行）。

三套词表之间的换算关系是本文后面所有章节的公共前提：**文档口径给出"违反了哪一格"，公告口径给出"Apple 改了哪个组件"，设备侧口径给出"用户看见了什么现象"。知道任意两个，不能唯一推出第三个。** 第 14 章的类型学按"错误发生在哪一次校验"重新分型，就是为了给这三者提供一个公共锚点；第 15 章的矩阵则把锚点换成责任归属。

### 3.4 一条换算失败的实例

把一条真实读数走完三套词表，能看清落差有多大。读数：CVE-2026-28950，组件 `Notification Services`，Impact "Notifications marked for deletion could be unexpectedly retained on the device"，Description "A logging issue was addressed with improved data redaction."（127002 第 420、430、435、440 行）。

- 文档口径里，"被标记删除的通知仍然留在设备上"没有任何对应字段：删除动作不是 APNs 请求的一部分，`aps` 字典里也没有"删除"键。它在文档里是**不可表达的**。
- 设备侧口径里，它对应通知中心历史中的一条残留——用户能看见，但没有导出接口能把它变成结构化读数（第 17 章）。
- 公告口径里，它落在 `Notification Services` 这个组件名上，而 Description 说的是 logging 与 redaction——**Impact 讲留存，Description 讲日志脱敏**，两句在同一格上并不对齐。本文第 16.4 节把这一条作为"公告内部自相矛盾"的样本处理，只报告落差，不推断原因。

这一条正好说明：任何试图"从公告统计每层缺陷数"的做法都是在读一张不存在的表。可做的只有反向操作——**用文档口径把现象钉在层上，再问这一格的修改权归谁**。

---
---

## 4. L1 设备令牌注册层

### 4.1 这一层负责什么

L1 只管一件事：**让 APNs 知道"某个 app 在某台设备上的地址"是什么，并把这个地址交到 provider 服务器手里**。文档对这一格的定位很直白：

> "Apple Push Notification service (APNs) must know the address of a user's device before it can send notifications to that device. This address takes the form of a device token unique to both the device and your app. At launch time, your app communicates with APNs and receives its device token, which you then forward to your provider server."（《Registering your app with APNs》第 5 行）

注意这句话里的三个约束，它们是后面所有归属判断的地基：

1. **令牌是"设备 × app"二元组，不是设备 ID。** "You can't use the same device token for more than one app, even when the apps are on the same device. Every app must request their own unique device token and forward it to your provider server."（同页第 6 行）
2. **令牌是每次启动重新取的，不是安装时写死一次的。** "You register your app and receive your device token each time your app launches using Apple-provided APIs."（同页第 13 行）
3. **令牌对 provider 是"十六进制字节"这一种形态。** `:path` 头部要求 "the value of this header is `/3/device/<device_token>`, where `<device_token>` is the hexadecimal bytes that identify the user's device."（《Sending notification requests to APNs》第 26 行）

### 4.2 这一格的公开规则清单

| 编号 | 规则（文档口径） | 出处 |
| --- | --- | --- |
| R1-1 | 令牌在 app 启动时由系统 API 申请，成功后在 delegate 回调里给出 | 《Registering your app with APNs》第 13、14 行 |
| R1-2 | 失败路径必须实现 `application(_:didFailToRegisterForRemoteNotificationsWithError:)` | 同上第 17 行 |
| R1-3 | 失败原因只有三类：无网络、APNs 不可达、**代码签名 entitlement 不正确** | 同上第 17 行 |
| R1-4 | 不要在本地缓存令牌；恢复备份、换新设备、重装系统都会换新令牌 | 同上第 19 行 |
| R1-5 | 转发给 provider 时要加密："Encrypt any information you send over the network." | 同上第 21 行 |
| R1-6 | 一个用户可能有多个令牌，服务端要按设备条存 | 同上第 22 行 |
| R1-7 | 不要对令牌长度做假设："Don't make assumptions about device token size." | 《Sending notification requests to APNs》第 66 行 |

R1-3 和 R1-7 是这一层最容易被低估的两条。前者说明**注册失败的读数里混着 L2 的错**（entitlement 不对会表现为"注册失败"，而缺陷其实在授权层）；后者说明**任何把令牌当定长字段做校验或截断的 provider 代码，都踩在文档明确禁止的地方**。

### 4.3 这一格会怎么错

按"错误发生在哪一次校验"来看，L1 有四种错法，它们的读数完全不同：

| 错法 | 谁犯的 | provider 侧可见读数 | 设备侧可见读数 |
| --- | --- | --- | --- |
| 令牌根本没拿到（注册失败） | 设备侧（网络/entitlement/APNs 可达性） | 无（请求从未发出） | App 自己实现的失败分支，系统层面无统一读数 |
| 拿到但没送到服务端 / 送到但存错用户 | provider | `BadDeviceToken`（400）、`DeviceTokenNotForTopic`（400） | 通知不到 |
| 令牌已失效但仍被使用 | provider 的数据新鲜度 | `ExpiredToken`（410）、`Unregistered`（410） | 通知不到，且文档说"没必要再发" |
| 把令牌当定长处理 | provider 代码 | `BadDeviceToken`、`MissingDeviceToken`（400） | 部分设备永远收不到 |

第四行值得展开：`MissingDeviceToken` 的定义是 "The device token isn't specified in the request `:path`. Verify that the `:path` header contains the device token."（《Handling notification responses from APNs》第 42 行）——**它描述的是"路径里没令牌"这一格式事实**，而不是"用户没授权"。设备侧授权状态属于 L2，不会以这个串出现。

### 4.4 410 是一条特殊读数：它不是错误

L1 的归属判断里最容易做错的一步，是把 410 当成失败。文档两处明确：

- 状态码语义："410 | The device token is no longer active for the topic."（《Handling notification responses from APNs》第 20 行）
- 计入口径："Note that status code 410 isn't considered an error condition."（同页第 65 行）

而且 410 是唯一会带 `timestamp` 的一档："The time, represented in milliseconds since Epoch, at which APNs confirmed the token was no longer valid for the topic. This key is included only when the error in the `:status` field is 410."（同页第 29 行）

**这条规则本身就是本文第 21 章脚本一/脚本二实现的一个锚点**：脚本二对 `timestamp` 字段的合法性判定，正是"只有 410 两行可以带毫秒时间戳，其他行带时间戳属于读数与文档不符"。

对防御的意义：410 是链路里**唯一一个由 APNs 明确告知"这条数据过期了"的读数**。一个 provider 如果不消费 410，就会持续对失效令牌发请求，而文档同时警告 "APNs disconnects sooner with certain error conditions, such as `BadDeviceToken`."（同页第 65 行）——也就是说，L1 的数据卫生问题会以 L3/L4 的连接中断形式暴露出来。跨层的因果链是这一层最常出现的"缺陷看起来不在它出错的地方"。

### 4.5 归属

L1 的修改权分三段，**Apple 只拥有中段**：

| 段 | 归属 | 更新通道 |
| --- | --- | --- |
| 取令牌、失败重试、不落本地缓存 | App 开发者 | App 版本发布 |
| 令牌到 APNs 的注册流程、令牌签发与轮换 | Apple | 服务侧，无版本号 |
| 服务端令牌库的新鲜度（消费 410、多设备并存、加密传输） | provider 运营方 | 服务端部署 |

这就是为什么 13 条公告读数里**没有一条落在 L1**（第 16 章）：这一层的代码在 App 和服务端，不在 iOS 里；Apple 改 iOS 不会改变 L1 的行为，而 L1 的服务侧改动不产生 CVE。**L1 的缺陷统计只能来自 provider 侧日志，任何"按公告数 L1 缺陷"的做法统计的是零。**

---

## 5. L2 授权与 entitlement 层

### 5.1 这一层负责什么

L2 决定"这个 app 有没有资格收推送、以哪个环境的资格收、以及用户有没有资格被吵到"。它由两半组成，常被混为一谈：

- **签名侧（entitlement）**：开发者账号 + 配置描述文件决定，运行时由系统校验。
- **用户侧（授权状态）**：用户在设置里/弹窗里决定，运行时可变。

### 5.2 签名侧：`aps-environment`

打开 Push Notifications capability 的效果，文档写得非常具体：

> "Enabling this option in iOS adds the ... `aps-environment` to the app. In macOS, it adds the ... `com.apple.developer.aps-environment`."（《Registering your app with APNs》第 8 行）

而这个 entitlement 页给出的取值与语义（PAGE-TITLE 为 "APS Environment Entitlement"）：

- "This key specifies whether to use the development or production Apple Push Notification service (APNs) environment when registering for push notifications."（《APS Environment Entitlement》第 9 行）
- "Xcode sets the value of the entitlement based on your app's current provisioning profile. ... These default settings can be modified. The development environment is also referred to as the sandbox environment."（同页第 10 行）
- "Use this entitlement for both the UserNotifications and PushKit frameworks."（同页第 11 行）
- "To add this entitlement to your app, enable the Push Notifications capability in Xcode."（同页第 12 行）

账号侧还有一步独立的开关："In your developer account, enable the push notification service for the App ID assigned to your project."（《Registering your app with APNs》第 10 行）

这一页的第三类 entitlement 关联项值得单独记：**Critical Alerts** 与 **notification filtering** 各自的 entitlement 页（同页 REFERENCES 第 18、19 行分别给出 `com.apple.developer.usernotifications.critical-alerts` 与 `com.apple.developer.usernotifications.filtering`，后者的一句话说明是 "Enable receiving notifications without displaying the notification to the user."）。**这两个键不在推送请求链路里，却决定了 L8/L9 能不能"安静地处理一条通知"**，是典型的"授权在 L2、现象在 L8"跨层项。

### 5.3 用户侧：授权状态的读数形态

用户授权的可见状态是这一层唯一在设备侧可读的部分。文档口径里最关键的是 provisional（临时授权）的行为：

> provisional 送达时"安静"——不响、不弹横幅、不上锁屏，只进通知中心历史。（《Asking permission to use notifications》第 12 行）

以及请求授权的动作本身由 app 发起，系统弹窗结果通过 completion 回调给出（同页 overview 段）。**这里有一条容易被误读的因果**：`alert` 类型的推送在用户拒绝授权后并不会在 provider 侧产生任何错误读数——请求照样 200。**"用户没授权"在 APNs 词表里没有对应的 reason 串**（对照第 8.4 节的 32 串，没有一条讲授权状态）。它只在设备侧表现为"没弹"，在指标侧则可能表现为另一类：`Discarded - Disabled`（《Viewing the status of push notifications using Metrics and APNs》第 15 行）。

### 5.4 这一格会怎么错

| 错法 | 读数落点 | 说明 |
| --- | --- | --- |
| entitlement 与请求环境不匹配 | `BadDeviceToken`（400，"token matches the environment"）；证书侧为 `BadCertificateEnvironment`（403） | 同一件事在 L1/L2/L4 三处都有读数，第 24 章误区 2 专门处理这个 |
| 缺少 entitlement | 注册直接失败（L1 读数为空） | 文档 R1-3 的第三类原因；**永远不会有 APNs 响应** |
| 把 sandbox 令牌发到 production | 400/403 家族 | "Channels can't be shared across environments"（《Sending channel management requests to APNs》第 34 行）是同一原则在 L10 的表述 |
| 未申请用户授权就直接期望横幅 | 无 provider 读数 | 词表不覆盖；只有设备侧现象与指标 |
| 依赖 critical alert 但没有 entitlement | 载荷侧 `sound`/`critical` 组合失效 | 载荷层（L6）表现，责任在 L2 |

### 5.5 归属

| 段 | 归属 | 更新通道 |
| --- | --- | --- |
| entitlement 的授予与校验规则 | Apple（描述文件系统 + 内核/服务校验） | 配置描述文件、账号设置；不需要设备更新 |
| 用户授权状态、通知中心策略 | 用户 | 用户操作 |
| 何时申请授权、provisional 使用、权限被拒后的降级设计 | App 开发者 | App 版本发布 |

**L2 是"Apple 拥有规则、不拥有代码"的典型层**：校验逻辑在 iOS 里，但触发缺陷的动作（申请时机、拒绝后的重试、用 provisional 规避弹窗）全在 App 里。公告里以 entitlement 为修复手段的条目，正是打在这半格上——第 16 章会看到 "additional entitlement checks" 这一句修复描述出现在组件名与推送无关的条目上。

---

## 6. L3 Provider 鉴权层

### 6.1 两条鉴权路线，一条链路

文档给出两条互斥路线：**token-based（JWT）** 与 **certificate-based（mTLS）**。token 路线的动机写得很清楚：

> "Token-based authentication offers a stateless way to communicate with APNs. Stateless communication is faster than certificate-based communication because it doesn't require APNs to look up the certificate, or other information, related to your provider server."（《Establishing a token-based connection to APNs》第 5 行）

两条路线各有代价：

| 路线 | 优点（文档原文要点） | 代价（文档原文要点） |
| --- | --- | --- |
| token-based | 一个 token 可多服务器使用（第 6 行）；一个 token 覆盖全公司 app（第 7 行） | "Token-based requests are slightly larger than certificate-based requests because each request contains the token."（第 8 行）；每小时必须轮换 |
| certificate-based | 请求体更小、不含鉴权头 | 一个证书一个 app："To send remote notifications to multiple apps, you must create separate certificates for each app. You must also manage separate APNs connections for each app's notifications."（《Establishing a certificate-based connection to APNs》第 7 行）；一年有效期，"To avoid a disruption in service for your users, update your provider certificates before they expire."（同页第 22 行） |

另一条常被忽略的路线差异在**能发哪些 push type**："Certificate-based connection supports only a subset of push types and token-based connection supports all push-types."（《Sending notification requests to APNs》第 57 行）

### 6.2 JWT 的全部可校验字段

这是本文两个脚本里"能静态判定"的部分。文档定义了 token 内的四个键：

| 键 | 文档约束 | 出处 |
| --- | --- | --- |
| `alg` | "APNs supports only the ES256 algorithm, so set the value of this key to ES256." | 《Establishing a token-based connection to APNs》第 27 行 |
| `kid` | "The 10-character Key ID you obtained from your developer account" | 同页第 28 行 |
| `iss` | "the value for which is the 10-character Team ID" | 同页第 29 行 |
| `iat` | "Specify the value as the number of seconds since Epoch, in UTC. The value must be no more than one hour from the current time." | 同页第 30 行 |

分片方式也在文档里："The header of the token contains the encryption algorithm and Key ID, and the claims payload contains your Team ID and the token generation time."（第 31 行）

装配位置："include your encrypted token in the authorization header of your request. The token is in Base64URL-encoded JWT format, and is specified as `bearer <token data>`"（第 36 行）。

失效规则："If the value in the `iat` field is more than one hour old, APNs rejects any notifications containing the token, returning an `ExpiredProviderToken` (403) error."（第 32 行）

轮换窗口是最具体的一条数值："Refresh your token no more than once every 20 minutes and no less than once every 60 minutes. APNs rejects any request whose token contains a timestamp that's more than one hour old. Similarly, APNs report an error if you use a new token more than once every 20 minutes on the same connection."（第 39 行）

**这四条里，`alg`/`kid` 长度/`iss` 长度/`iat` 数值是纯静态可读的**——脚本一的 P 系列检查项就建在这上面。签名本身不做校验（无法离线验证，且本文不提供任何伪造签名的方法）。

### 6.3 键的拓扑：环境、topic 与关联键

文档的钥匙治理规则比"生成一个 .p8"复杂得多，且**每一条都能变成 provider 侧的读数**：

| 规则 | 原文 | 违反后的 reason 候选 |
| --- | --- | --- |
| 团队级密钥每环境最多两把 | "Each environment can have a maximum of two keys."（第 10 行） | 账号侧限制，不产生 APNs 读数 |
| 主题级密钥每环境 200、单密钥最多 400 topics | "You can create a maximum of 200 keys for Sandbox and 200 for Production, with up to 400 topics per topic-based key."（第 13 行） | 同上 |
| 关联密钥只有一把 | "A topic-specific key can have at most one related key in the same environment."（第 14 行） | `UnrelatedKeyIdInToken`（403，第 52 行） |
| 跨账号不能共用连接 | "APNs doesn't support authentication tokens from multiple developer accounts over a single connection."（第 15 行） | `UnrelatedKeyIdInToken` / `BadEnvironmentKeyIdInToken`（403） |
| 连接不能映射多团队 | "You can't map a connection to APNs to multiple teams. If you manage APNs for multiple developer accounts, open separate connection pools for each of them."（第 42 行） | 403 家族 |
| 首推决定团队与 bundle ID 绑定 | "APNs relates a team ID and associated bundle IDs to a connection on the first push. After the authentication process, attempting to associate a different team or sending a push to a newly added bundle ID causes an error."（第 43 行） | `TopicDisallowed`（400）/`DeviceTokenNotForTopic`（400） |
| 传输后的 app 要重建连接 | "For transferred apps, close and recreate any existing connections from your push provider server to APNs. If you don't, APNs can't start accepting push requests from the new team."（第 44 行） | 无响应或 403 家族 |
| 首推用了哪种密钥就锁定该族 | "If you use a token from a team-scoped key during the first push, trying to send a push with a topic-specific key or a team-scoped key from a different environment results in an error."（第 45 行） | `UnrelatedKeyIdInToken`、`BadEnvironmentKeyIdInToken` |

"first push 决定连接语义"是这一层最重要的结构性事实：**同一段代码，连接池里第一请求发什么，后面就只能发什么**。这类错误在日志里表现为随机分布的 403，且**与 payload 内容无关**——第 24 章误区 5 处理的就是"把 L3 的连接态问题当成 L6 的载荷问题去改代码"。

### 6.4 证书侧的可校验事实

证书路线的证据链在证书扩展里：

- 主题可在 Keychain Access 里读："In Keychain Access, you can find the Topic/Bundle ID under Details > Subject Name > Common Name."（《Establishing a certificate-based connection to APNs》第 23 行）
- 额外 topic 由两个 OID 承载："Also check for Extension 1.2.840.113635.100.6.3.4 and 1.2.840.113635.100.6.3.6 under Details > Public Key Info for additional Topics/Bundle IDs for Pushkit VoIP, watchOS complication, and Push to Talk. If a certificate doesn't have the push topic for a specific push type, you can't use the certificate to send a notification of that type."（《Establishing a certificate-based connection to APNs》第 23 行）
- 撤销有服务侧名单："APNs maintains a list of revoked certificates, and it refuses TLS connections from servers with certificates on that list. If your server uses a revoked certificate, close all existing connections to APNs and configure a new provider certificate for your server before opening any new connections."（《Establishing a certificate-based connection to APNs》第 29 行）

两个 OID 与"某 push type 是否可用"的对应，在《Sending notification requests to APNs》第 57 行也重复了一次（"Check Extension 1.2.840.113635.100.6.3.6 and 1.2.840.113635.100.6.3.4 of your push certificate."），**这是证书路线唯一可离线核对的准入事实**，也是脚本一对 `authorization` 头与证书路线互斥性做判定的依据（见第 21.4 节 E 系列）。

### 6.5 归属

| 段 | 归属 | 更新通道 |
| --- | --- | --- |
| JWT 校验规则、密钥配额、连接绑定语义 | Apple | 服务侧；文档变更即为口径变更 |
| 密钥的生成、保管、轮换调度、撤销响应 | provider 运营方 | 服务端部署 + 账号操作 |
| 证书有效期监控 | provider 运营方 | "remember to get a new certificate and deploy it with your service before the expiry of the current certificate."（《Sending notification requests to APNs》第 65 行） |

**L3 完全没有设备侧代码参与**：这一层的缺陷不会进 iOS 公告，也不会被任何设备侧读数观察到。它是"本文十层里唯一一层 100% 归 provider、0% 归 Apple 设备代码"的层——第 15 章矩阵里这一行的"更新通道"列是空的，这不是遗漏，是结论。

---

## 7. L4 传输与信任链层

### 7.1 协议要求与端点

这一层的规则只有一句主干加一组端点：

> "Use HTTP/2 and TLS 1.2 or later to establish a connection between your provider server and APNs server to send API requests."（《Establishing a connection to Apple Push Notification service (APNs)》第 5 行）

| 用途 | Sandbox | Production | 出处 |
| --- | --- | --- | --- |
| 设备推送 | `https://api.sandbox.push.apple.com:443` | `https://api.push.apple.com:443` | 《Sending notification requests to APNs》第 10、11 行 |
| 备选端口 | 2197 可替代 443 | 同 | 同页第 13 行 |
| 广播信道管理 | `api-manage-broadcast.sandbox.push.apple.com:2195` | `api-manage-broadcast.push.apple.com:2196` | 《Sending channel management requests to APNs》第 11、12 行 |
| 广播发布 | 复用设备推送端点 | 同 | 《Sending broadcast push notification requests to APNs》第 10、11 行 |

2197 的动机被明确写成防火墙策略："You might use this port to allow APNs traffic through your firewall but to block other traffic."（同上第 13 行）——**这意味着同一个 provider 的防火墙规则本身就是一个可核对的口径项**，第 20 章指标 P7 由此而来。

旧的二进制协议已经退出："APNs doesn't support legacy binary protocol as of March 31, 2021. Update to the HTTP/2-based API as soon as possible."（同页第 67 行）

### 7.2 流、HPACK 与连接复用

三组规则彼此耦合，构成"传输层的隐式校验"：

- 并发流数量不可假设："APNs allows for multiple concurrent streams for each connection, but don't assume a specific number of streams. The exact number varies based on server load and whether you use a provider certificate or an authentication token. For example, if you're using an authentication token, APNs allows only one stream until you post a request with a valid authentication token. APNs ignores HTTP/2 PRIORITY frames, so don't send them on your streams."（《Establishing a connection to Apple Push Notification service (APNs)》第 6 行）
- HPACK 动态表很小，必须按规则编码："APNs requires the use of HPACK (header compression for HTTP/2), which prevents repeatedly storing header keys and values. APNs maintains a small dynamic table for HPACK."（《Sending notification requests to APNs》第 34 行）
- 具体编码分工：**`:path` 与 `authorization` 的值必须以"不带索引的字面量"编码**（同页第 35 行）；`apns-id`、`apns-expiration`、`apns-collapse-id` 首次请求用增量索引、后续请求改为不带索引（第 36—38 行）；其余字段一律带增量索引（第 39 行）。
- 复用与心跳："Reuse a connection as long as possible. In most cases, you can reuse a connection for many hours to days. If your connection is mostly idle, you may send a HTTP2 PING frame after an hour of inactivity to keep it alive."（同页第 62 行）
- DNS 与流量分布："Make an uncached DNS query to resolve the APNs server name, before each connection. This helps distribute push traffic from all providers across all APNs servers."（同页第 60 行）；"Avoid push bursts over selective connections."（第 61 行）

**HPACK 这一组是十层里最"纯传输"的校验**：它不看内容、不看鉴权，只看编码方式。文档把它写成"为了不把动态表填满"的硬约束（第 34 行"to avoid filling up that table"），而违反它不会返回 400 家族的任何 reason——它的表现是连接被断。这就是"传输层缺陷不产生业务读数"的第一个实例。

### 7.3 GOAWAY 与连接终止

连接级错误只有一个载体：

> "APNs may also terminate a connection by sending a GOAWAY frame. The payload of the GOAWAY frame includes JSON data with a reason key, indicating the reason for the connection termination. For a list of values for the reason key, refer to the response error strings in ...《Handling notification responses from APNs》"（《Establishing a connection to APNs》第 7 行）

同一份 reason 词表也适用于响应体："The JSON data might also be included in a GOAWAY frame when a connection terminates."（《Handling notification responses from APNs》第 26 行）

**这条规则对判定很关键：GOAWAY 与单次请求失败共用 32 串词表**。因此脚本二在台账里看到 `IdleTimeout`、`Shutdown`、`ServiceUnavailable` 这类串时，输出的是"连接级读数候选"而不是"这条消息的失败原因"（第 22.3 节 W 系列）。同时文档给出 4XX 对吞吐的连带影响："An error code beginning with 4XX slows down your ability to send notifications."（第 65 行）以及 "APNs disconnects a provider connection with too many error conditions."（同页）——**错误率本身是 L4 的输入**，这是 L3/L4 联动的机制解释。

### 7.4 根证书迁移：一层会随时间变口径的校验

这一层的信任锚在文档里是**带迁移状态**的：

- "Communication between your provider server and APNs must take place over a secure connection. Creating a secure connection requires installing the ... root certificate"（《Setting up a remote notification server》第 23 行）
- "If your provider server runs macOS Sequoia or later, both AAA and UserTrust Certificate Services root certificate are in the keychain by default. On other systems, you might need to install this certificate."（同页第 24 行）
- "APNs is migrating from AAA to UserTrust Certificate Services root certificate. For migration dates, consult ..."（同页第 25 行，原文为一条 news 链接）

证书侧的对应要求："An up-to-date version of macOS includes the appropriate trust store to validate the certificate presented by APNs. For other platforms, ensure you include a proper root certificate in your trust store."（《Establishing a certificate-based connection to APNs》第 26 行）

**这是一条"今天合规、迁移日不合规"的规则**：信任链校验的口径由服务方在时间轴上移动，而 provider 的 trust store 属于自己。这类缺陷的读数形态是 TLS 握手失败——**不产生任何 APNs 状态码**。第 26 章未文档化边界清单会记录"迁移日期本身指向的 news 页在本轮不可引用"（那两页取回但不可用，见第 2 章末段）。

诊断动作是文档给的唯一一条 L4 自检路径："You can verify the TLS handshake between your provider server and APNs by running the OpenSSL s_client command from your server, as shown below. This command can also show if your TLS/SSL certificates are expired or revoked."（《Establishing a connection to Apple Push Notification service (APNs)》第 24 行）——本文不复述其参数与输出（Listing 正文在存档里缺失，缺口 A），只记录：**L4 是唯一有官方自诊断命令的一层，且该命令读的是自己的证书与自己的 trust store，不需要设备参与。**

### 7.5 频率惩罚：把连接行为写成安全口径

同页第 23 行有一条与其他规则性质不同的表述："Check how often your provider server connects to APNs. If your provider server opens and closes its connection to APNs repeatedly, APNs may treat it as a denial-of-service attack and temporarily block your server from connecting."

**这是整条链路上唯一一处把 provider 的正常运维动作（重连）定义为可能被拒绝服务的行为**。它的工程含义：连接池策略错误 → 服务端 IP 级封禁 → 表现为"所有推送都失败但没有 APNs 状态码"。第 24 章误区 6 针对它。

### 7.6 归属

| 段 | 归属 | 更新通道 |
| --- | --- | --- |
| TLS/HTTP2 服务侧行为、GOAWAY、流配额 | Apple | 服务侧 |
| 根证书信任库 | Apple（macOS 内置）/ provider 运营方（其他平台自行安装） | 系统更新 / 服务端部署 |
| 连接池、HPACK 编码、心跳、DNS 策略、防火墙端口 | provider 运营方 | 服务端部署 |

L4 的特殊之处是**责任边界随平台移动**：同一份代码在 macOS Sequoia 上不需要装根证书，在别处需要（《Setting up a remote notification server》第 24 行）。因此"L4 是否合规"的判定必须先声明 provider 的运行平台，否则口径不可比——第 19 章级 2（对齐）会用到这条前置声明。

---

## 8. L5 请求头语义层

### 8.1 九个字段，两种必选

设备推送请求的头字段清单是封闭的（《Sending notification requests to APNs》第 24—33 行，表头为 "Header field | Required | Description"）：

| 字段 | 必选条件 | 一句话规则（文档） |
| --- | --- | --- |
| `:method` | Required | "The value POST."（第 25 行） |
| `:path` | Required | "/3/device/`<device_token>`"（第 26 行） |
| `authorization` | Required for token-based authentication | "bearer `<provider_token>` ... APNs ignores this header if you use certificate-based authentication."（第 27 行） |
| `apns-push-type` | watchOS 6 起必选；macOS/iOS/tvOS/iPadOS 建议 | "The value of this header must accurately reflect the contents of your notification's payload."（第 28 行） |
| `apns-id` | Optional | "A canonical UUID that's the unique ID for the notification."（第 29 行） |
| `apns-expiration` | Optional | UNIX epoch 秒；非零则存储并重复投递至该日期（第 30 行） |
| `apns-priority` | Optional | "If you omit this header, APNs sets the notification priority to 10."（第 31 行） |
| `apns-topic` | Required | "In general, the topic is your app's bundle ID/app ID. It can have a suffix based on the type of push notification."（第 32 行） |
| `apns-collapse-id` | Optional | "The value of this key must not exceed 64 bytes."（第 33 行） |

**这一层的价值在于：九个字段里除 `authorization` 的签名外，全部可以离线静态判定**。这就是脚本一 H01—H20 共 20 个信号码的依据（第 21 章）。

### 8.2 `apns-push-type` 的 12 个取值与 topic 后缀

这是文档里最长的一段封闭枚举（第 44—56 行；第 44 行给出总纲 "Send an apns-push-type header with each push. Recent and upcoming features may not work if this header is missing."）。取值与要求的 `apns-topic` 后缀一一对应：

| push type | `apns-topic` 要求后缀（原文字面量） | 出处行 |
| --- | --- | --- |
| `accessory` | `.push-type.accessory` | 第 45 行 |
| `alert` | app bundle ID（无后缀） | 第 46 行 |
| `background` | app bundle ID（无后缀） | 第 47 行 |
| `complication` | `h.complication`（原文如此，见第 2 章拼写异常清单） | 第 48 行 |
| `controls` | `.push-type.controls` | 第 49 行 |
| `fileprovider` | `.pushkit.fileprovider` | 第 50 行 |
| `liveactivity` | `push-type.liveactivity` | 第 51 行 |
| `location` | `.location-query` | 第 52 行 |
| `mdm` | 不用 bundle ID："you must use the topic from the UID attribute in the subject of your MDM push certificate" | 第 53 行 |
| `pushtotalk` | `.voip-ptt` | 第 54 行 |
| `voip` | `.voip` | 第 55 行 |
| `widgets` | `.push-type.widgets` | 第 56 行 |

三个判定要点：

1. **后缀形态不统一**：三种风格混用（点号开头 + `push-type.` 中缀、`h.complication` 这种残段、以及 `push-type.liveactivity` 没有前导点）。任何"按 `<bundle>.<type>` 统一拼接"的 provider 抽象都会写错其中至少两格。
2. **`mdm` 是唯一 topic 不由 bundle ID 派生的类型**（第 53 行）——它把 L5 与证书内容（L3/L4）绑在了一起。
3. **类型与载荷必须自洽**："If there's a mismatch, or if the header is missing on required systems, APNs may return an error, delay the delivery of the notification, or drop it altogether."（第 28 行）——注意这句话给了三种可能结果，**没有承诺其中哪一种**，所以 `InvalidPushType`（400，第 41 行）只是三种出口之一。这是"文档口径与读数口径不是一对一"的典型，第 19 章级 3 用它做样本。

### 8.3 `apns-priority` 与 `apns-expiration` 的组合语义

优先级只有三个合法值，且省略即最高："Specify 10 to send the notification immediately." / "Specify 5 to send the notification based on power considerations on the user's device." / "Specify 1 to prioritize the device's power considerations over all other factors for delivery, and prevent awakening the device."（《Sending notification requests to APNs》第 31 行）

过期头的规则："If the value is nonzero, APNs stores the notification and attempts delivery at least once, repeating as necessary until the specified date. If the value is 0, APNs attempts to deliver the notification only once and doesn't store it."（第 30 行）

两条交叉出一个可静态判定的矛盾：**priority 1 要求"不要唤醒设备"，而 `liveactivity`/`background` 各有自己的功耗与时效口径**（第 10 章与第 13 章分别展开）。文档在 `background` 类型的定义里直接把它写成错误："Always use priority 5. Using priority 10 is an error."（《Sending notification requests to APNs》第 47 行）——**这一句是整份文档里唯一把某个头字段取值直接称为 error 的表述**，脚本一的 H 系列把它作为硬失败项。设备侧对同一件事的表述是"给后台通知分配低优先级且不保证送达"："The system treats background notifications as low priority: you can use them to refresh your app's content, but the system doesn't guarantee their delivery."（《Pushing background updates to your App》第 6 行）

### 8.4 `apns-id` 与 collapse-id 的格式约束

`apns-id` 必须是 canonical UUID："Canonical UUIDs are 32 lowercase hexadecimal digits, displayed in five groups separated by hyphens in the form 8-4-4-4-12"（《Sending notification requests to APNs》第 29 行；同一约束在信道管理页第 22 行以相同措辞重复）。

collapse-id 的上限是字节数不是字符数："The value of this key must not exceed 64 bytes."（第 33 行）。它的用途是合并呈现："An identifier you use to merge multiple notifications into a single notification for the user."（同页）——**L5 的一个头字段直接决定 L8 的呈现形态**，这类"头字段 → 设备现象"的映射是第 14 章 N7 型的定义基础。

超长的读数是 `BadCollapseId`（400）："The collapse identifier exceeds the maximum allowed size."（《Handling notification responses from APNs》第 32 行）。

### 8.5 归属

L5 是**十层里唯一一层"规则完全文档化、判定完全离线可做"**的层。责任分布因此也很干净：

| 段 | 归属 |
| --- | --- |
| 字段定义、必选条件、枚举取值 | Apple（文档 + 服务校验） |
| 拼写、大小写、后缀拼接、UUID 格式、字节长度 | provider 运营方 |
| 头字段与载荷内容是否自洽 | provider 运营方（写请求的一方） |

设备侧在 L5 **没有任何参与**：用户看不到头字段，系统也不会因为头字段错而产生设备侧现象。这一层的读数只在 provider 日志里存在——这既是它"容易核验"的原因，也是它"公开案例几乎为零"的原因（第 16 章的 13 条读数没有一条落在 L5）。

### 8.6 一个可核对的例子形态

为了说明 L5 判定有多机械，本文给出一个纯虚构的、不含任何真实令牌与 Team ID 的请求头片段（自造样本，非取回件，不参与引语核验）：

```text
:method: POST
:path: /3/device/abcdef0123
apns-push-type: alert
apns-topic: com.example.myapp
apns-id: 123E4567-E89B-12D3-A456-4266554400A0
apns-priority: 5
apns-collapse-id: chat-thread-01

{"aps":{"alert":{"title":"标题","body":"正文"},"sound":"default"}}
```

对照本章规则可静态得到的结论（这正是脚本一会输出的东西，第 21 章）：`:path` 里的令牌串长度与形态不可假设（R1-7）、`apns-id` 的大写十六进制违反 "32 lowercase hexadecimal digits"（第 29 行）、`alert` 类型与载荷里的 `alert` 自洽（第 28 行）、缺 `authorization` 时**必须**存在证书路线（第 27 行）。四条里只有两条是硬失败，另外两条是"文档未承诺读数"的口径提醒——**这个区分本身就是 L5 判定的核心**，第 23 章的验收表按这个区分统计信号码。

---
## 9. L6 载荷层

### 9.1 这一层负责什么

载荷是唯一会**同时被 provider、APNs 与设备三方正视**的东西，因此它也是十层里规则最密的一层。文档的定义：

> "Remote notifications convey important information to the user in the form of a JSON payload. The payload specifies the types of user interactions (alert, sound, or badge) that you want performed, and includes any custom data your app needs to respond to the notification."（《Generating a remote notification》第 5 行）

结构要求只有一句："Specify the payload for a remote notification using a JSON dictionary. Inside this dictionary, include an `aps` key whose value is a dictionary containing one or more additional Apple-defined keys, listed in Table 1."（同页第 11 行）

**但紧接着的那句是十层里最容易违反、却最没有读数的一条**：

> "Don't add your own custom keys to the `aps` dictionary; APNs ignores custom keys. Instead, add your custom keys as peers of the `aps` dictionary."（同页第 29 行）

把自定义键放进 `aps` 里，**APNs 不报错、不返回 reason、不降级**——它只是忽略。这条规则的违反在 provider 日志里完全隐形，只在设备侧表现为"我的字段读不到"。这是第 14 章 N6 型（静默丢弃型）的定义样本，也是本文唯一一组"文档明写、读数为零"的项。

### 9.2 尺寸上限：三处数字，两种口径

| 口径 | 数值 | 出处 |
| --- | --- | --- |
| 设备推送（请求体） | 4 KB（4096 bytes），且"must not use a compressed JSON payload" | 《Sending notification requests to APNs》第 40 行 |
| VoIP | 5 KB（5120 bytes） | 同页第 40 行；《Generating a remote notification》第 8 行；《Supporting PushKit Notifications in Your App》第 19 行 |
| 其他远程通知 | 4 KB（4096 bytes） | 《Generating a remote notification》第 9 行 |
| 广播/信道 | 5 KB（5,120 bytes），"Don't use a compressed JSON payload" | 《Sending broadcast push notification requests to APNs》第 24 行 |
| 平台安全指南口径 | "APNs can only relay messages up to 4 or 16 KB in size, depending on the iOS or iPadOS version." | 《Apple Platform Security》第 9346 行 |

两处需要明确记录：

1. **第 40 行含原文拼写异常 `maxiumum`**（本文保留原样，见第 2 章清单）。
2. **provider 侧文档（4/5 KB）与平台安全指南（4 或 16 KB）不是同一个口径**：前者讲"你的请求体上限"，后者讲"APNs 能中继的消息尺寸，随 iOS/iPadOS 版本变化"。**两者不可互换引用**，第 26 章把"16 KB 那档对应的具体版本与消息类型"列入未文档化边界（本轮存档中该句没有给出映射表）。

### 9.3 `aps` 键表：19 行、18 个键名

表 1（"Table 1. Keys to include in the aps dictionary"，第 30 行）从第 32 行到第 50 行共 **19 行**，其中 `sound` 出现两次（String 与 Dictionary 两种值类型），去重后 **18 个键名**：

| # | 键 | 值类型 | 与哪一层耦合 |
| --- | --- | --- | --- |
| 1 | `alert` | Dictionary（或 String） | L8 呈现 |
| 2 | `badge` | Number | L8 图标角标 |
| 3 | `sound` | String / Dictionary（两行） | L8 声音 + L2 critical entitlement |
| 4 | `thread-id` | String | L8 分组 |
| 5 | `category` | String | L9 动作类别（须在 app/扩展里声明） |
| 6 | `content-available` | Number | L10 后台信道 |
| 7 | `mutable-content` | Number | L9 服务扩展开关 |
| 8 | `target-content-id` | String | L9 内容扩展窗口 |
| 9 | `interruption-level` | String | L8 打扰级别 |
| 10 | `relevance-score` | Number | L8 排序 |
| 11 | `filter-criteria` | String | L8 Focus 判定 |
| 12 | `stale-date` | Number | L10 Live Activity |
| 13 | `content-state` | Dictionary | L10 Live Activity |
| 14 | `timestamp` | Number | L10 Live Activity |
| 15 | `event` | String | L10 Live Activity（start/update/end） |
| 16 | `dismissal-date` | Number | L10 Live Activity |
| 17 | `attributes-type` | String | L10 Live Activity（远程启动） |
| 18 | `attributes` | Dictionary | L10 Live Activity（远程启动） |

表头说明句："Table 1 lists the keys that you may include in the `aps` dictionary. To interact with the user, include the `alert`, `badge`, or `sound` keys."（第 29 行）

几条关键的行内规则（脚本一 P 系列即按这些判定）：

- `content-available`："The background notification flag. To perform a silent background update, specify the value 1 and don't include the alert, badge, or sound keys in your payload."（第 38 行）——**这一句把 L10 的后台信道约束放进了 L6 的载荷里**。
- `mutable-content`："The notification service app extension flag. If the value is 1, the system passes the notification to your notification service app extension before delivery."（第 39 行）——L9 的**唯一开关**。
- `interruption-level`："The importance and delivery timing of a notification. The string values "passive", "active", "time-sensitive", or "critical" correspond to the `UNNotificationInterruptionLevel` enumeration cases."（第 41 行；链接标签按该页 references 表回填）——四个取值是封闭集，越界即口径违规。
- `badge`："Specify 0 to remove the current badge, if any."（第 33 行）——0 不是"无变化"而是"清除"，这是设备侧现象与 provider 直觉不一致的一格。

### 9.4 `alert` 与 `sound` 子表

`alert` 字典（"Table 2. Keys to include in the alert dictionary"，第 52 行）第 54—63 行共 **10 个键**：`title`、`subtitle`、`body`、`launch-image`、`title-loc-key`、`title-loc-args`、`subtitle-loc-key`、`subtitle-loc-args`、`loc-key`、`loc-args`。表头句（第 51 行）说明用途："Table 2 lists the keys that you may include in the alert dictionary."

`sound` 字典（第 65 行标题）第 67—69 行共 **3 个键**，且这 3 键只服务于 critical alert：

- `critical`："The critical alert flag. Set to 1 to enable the critical alert."（第 67 行）
- `name`："The name of a sound file in your app's main bundle or in the Library/Sounds folder of your app's container directory..."（第 68 行）
- `volume`："The volume for the critical alert's sound. Set this to a value between 0 (silent) and 1 (full volume)."（第 69 行）

**这里有一条贯穿 L2 与 L6 的隐藏依赖**：`sound` 的 Dictionary 形态只为 critical alert 服务（第 35 行："A dictionary that contains sound information for critical alerts. For regular notifications, use the sound string..."），而 critical alert 需要 `com.apple.developer.usernotifications.critical-alerts` entitlement（第 5.2 节）。所以"载荷合规但设备不响"的成因之一就在这一格——**L6 静态审查会判它合法，实际行为取决于 L2 授权**。第 19 章级 4（归因）把这种"跨层不可判"列为显式限制。

### 9.5 本地化两条路

> "There are two ways to localize the content of remote notifications: Include localized strings directly in the payload. Add localized message strings in your app bundle, and let the system choose which strings to display."（《Generating a remote notification》第 21—23 行）

两条路的取舍被写成成本对比："Placing localized strings directly into the payload gives you more flexibility, but requires you to track the user's preferred language."（第 24 行）；而预置文案可以放 `Localizable.strings`（第 25 行）。

安全相关的推论在**载荷内容策略**，不在本地化机制：

> "Don't include customer information or any sensitive data, like a credit card number, in a notification's payload. If you must include customer information or sensitive data, encrypt it before adding it to the payload. You can use a notification service app extension to decrypt the data on the user's device."（同页第 19 行）

这一句同时给出**问题、策略与配套机制**，是本文 L6 与 L9 归因的分界依据：加密数据 + `mutable-content=1` + 服务扩展解密 = 文档推荐的组合；缺任一环即回落为"密文直接呈现"或"扩展不被调用"（第 12 章）。

### 9.6 归属

| 段 | 归属 |
| --- | --- |
| 键名/值类型/枚举取值/尺寸上限 | Apple（文档 + 服务校验 + 设备侧解释器） |
| 键放进 `aps` 还是与 `aps` 平级、后缀、加密策略、本地化路线 | provider 运营方 + App 开发者 |
| 载荷内容在设备侧如何变成界面 | Apple 的通知中心 + App 的扩展（L8/L9） |

L6 的判定特点是：**结构可静态判、语义要跨层判**。第 21 章脚本一因此把 P 系列分成两组——格式违规（可硬判）与自洽提示（不可硬判）。

---

## 10. L7 APNs 存储与投递层

### 10.1 这一层的三条核心行为

L7 是唯一"用户与 provider 都碰不到、但决定通知到底会不会出现"的层。文档给出三条：

1. **不保证顺序**："As a best-effort service, APNs may reorder notifications you send to the same device token."（《Sending notification requests to APNs》第 5 行）
2. **存储有时限且只存一条**："If APNs can't deliver a notification immediately, it may store the notification for 30 days or less, depending on the date you specify in the `apns-expiration` header."（同页第 5 行）；"APNs stores only one notification per bundle ID. When you send multiple notifications to the same device for a bundle ID, APNs selects only one notification to store. In most cases, the latest notification is stored. However, this behavior isn't always guaranteed when multiple notifications are stored in a short duration."（同页第 6 行）
3. **优先级与功耗决定成批投递**："Notifications with apns-priority 5 and apns-priority 1 might get grouped and delivered in bursts to a person's device. Your notifications may also get throttled, saved in storage, and in some cases, not delivered. The way a person interacts with your app and the power state of the device determines the exact behavior."（同页第 6 行）

"只存一条"是十层里对"用户没收到通知"最常见的机械解释——**它不是丢包的偶然事件，而是文档写明的存储策略**。第 24 章误区 3 专门处理把它误判为"链路故障"的做法。

### 10.2 设备侧排队约束

《Troubleshooting push notifications》给出了更严的一句："APNs queues only one notification at a time for each device, and the device must acknowledge receipt of the notification before APNs dequeues it. If you send multiple notification requests in a very short period of time, each new request might overwrite the previous request."（第 15 行）

**注意这句与第 10.1 条 2 的措辞不同**：一处讲"存一条/每 bundle ID"，一处讲"排一条/每设备 + 需确认后才出队"。两条规则口径不同但同向，因此：
- 短窗口内连发，可观测结果是"后者覆盖前者"（排队侧）与"只保留最新"（存储侧）叠加；
- **provider 无法从任何单一读数区分这两者**（两者都不产生 reason 串）。这是第 17 章可见性边界里的"策略性丢失不可归因"项。

### 10.3 指标：三种状态、两类分类、隐私口径

指标页把投递结果写成可统计的三态，并给出分类示例（原文含拼写异常 `seperates` / `occured`，保留原样）：

> "If APNs stores or discards a notification, Metrics seperates the notifications into categories that explain why that status occured. For example, Stored - Device Offline means APNs stored the notificatio..."（《Viewing the status of push notifications using Metrics and APNs》第 15 行）

丢弃有三条明确原因（同页第 21—23 行）：

| 原因 | 原文要点 | 行 |
| --- | --- | --- |
| 令牌不再有效 | 人移除了 App，或该 App 的 push token 发生变化 | 第 21 行 |
| 用户关掉推送 | "A person disabled push notifications for your app in Settings on the destination device." | 第 22 行 |
| 通知过期 | "The push notification expires. You can adjust the expiration attribute accordingly for future notifications." | 第 23 行 |

存储侧的功耗因素："If the destination device is connected to APNs but it has power restrictions, APNs may defer delivery of a notification to conserve battery. In that case, APNs stores the notificatio..."（第 27 行）；以及投递时刻的两种可能："When APNs tries to deliver a notification from the APNs persistent storage, it might get delivered successfully or get discarded, depending on a number of factors."（第 28 行）

指标本身的形态被限定为聚合值："The ... Metrics tab provides aggregated, rounded reports on notification states as your notifications pass through APNs."（第 10 行），并列出影响投递的四类因素（第 11—14 行：通知属性、目标设备、外部因素、人的行为）。**"aggregated, rounded" 意味着指标不能用于逐条对账**——这是第 20 章指标 P6 的定义基础，也是"不要用指标数字做取证"的文档依据。

`Discarded - Disabled` 的解读口径文档给得很直白："an uptick of Discarded - Disabled means that people who use your app find notifications for your app irrelevant or noisy."（第 16 行）——**它同时是链路读数与产品信号**，本文第 20 章把它放在"双归属"位置。

### 10.4 系统消息队列的例外：iMessage

平台安全指南给出一个重要的"不是所有远程通知都走同一条投递策略"的实例：

> "As with all push notifications, the message is deleted from APNs when it's delivered. Unlike other APNs notifications, however, iMessage messages are queued for delivery to offline devices. Messages are stored on Apple servers for up to 30 days."（《Apple Platform Security》第 9361—9363 行）

以及尺寸口径的对应：APNs 中继上限一句（第 9346 行）出现在同一段落语境中。

**这段的意义不是"iMessage 特殊"，而是"投递即删"是通用规则**：普通通知在 APNs 上不留副本（第 9361 行），所以 provider 无法事后向 APNs 查询"那条通知的内容"。这条与第 17 章的读数可得性直接相关：**内容不可回查，只有状态可回查**。

### 10.5 令牌不可迁移：一条只在指南里出现的规则

> "Apple Push Notification service (APNs) token — Always, nonmigratory"（《Apple Platform Security》第 4941 行，安全指南的凭据迁移性表格行）

这一格是 L1 与 L7 的接缝：设备令牌"不迁移"，与开发者文档那句"Never cache device tokens in local storage. APNs issues a new token when the user restores a device from a backup..."（《Registering your app with APNs》第 19 行）**说的是同一件事的两侧**（系统口径 vs provider 口径）。两份文档一致，因此这条可以进硬判规则——第 21 章 D 系列的"令牌迁移性提示"由此而来。

### 10.6 归属

| 段 | 归属 | 可见性 |
| --- | --- | --- |
| 存储策略、重试、功耗节流、合并、聚合指标 | Apple（服务侧） | 只能通过指标与 reason 间接观察 |
| `apns-expiration`/`apns-priority` 取值、发送节奏 | provider | provider 日志 |
| 设备侧确认（ack）与唤醒时机 | Apple（设备侧实现） | 无公开读数 |

L7 是**唯一一段"责任完全在 Apple 服务侧、但缺陷后果由 provider 承担"的层**：provider 改不了存储策略，只能按策略设计自己的发送与合并逻辑。所以第 14 章 N5（投递语义型）的修复动作全部落在 provider 侧，尽管成因在服务侧。

---

## 11. L8 设备端派发与呈现层

### 11.1 呈现是两阶段的

设备侧的可见现象从这一层开始，而它的机械结构被写得很具体：

> "When an iOS device receives a notification containing an alert, the system displays the contents of the alert in two stages. Initially, it displays an abbreviated banner with the title, subtitle, and two to four lines of body text from the notification. If the user presses the abbreviated banner, iOS displays the full notification interface, including any notification-related actions. The system provides the interface for the abbreviated banner, but you can customize the full interface using a notification content app extension."（《Customizing the Appearance of Notifications》第 5 行）

三个后果：

1. **"两到四行正文"是系统截断，不是 App 丢内容**。用户看到的正文可能少于 `body` 的实际内容。
2. **abbreviated banner 完全由系统提供**，App 无法参与第一阶段；这解释了公告里 "view notification contents from the Lock Screen" 类条为什么修的是呈现侧代码而不是推送侧（第 16 章）。
3. **完整界面才归内容扩展**（L9）。所以"横幅显示对了、点进去不对"这种读数天然把缺陷定位到 L9 而不是 L8。

### 11.2 分组、排序与打扰控制

载荷里的四个键在这一层变成设备行为，构成"L6 写、L8 现"的映射表：

| 载荷键 | 设备侧效果 | 出处 |
| --- | --- | --- |
| `thread-id` | "An app-specific identifier for grouping related notifications." | 《Generating a remote notification》第 36 行 |
| `apns-collapse-id`（头字段） | "merge multiple notifications into a single notification for the user" | 《Sending notification requests to APNs》第 33 行 |
| `interruption-level` | passive / active / time-sensitive / critical 四值 | 《Generating a remote notification》第 41 行 |
| `relevance-score` | "the system uses to sort the notifications from your ... " | 同页第 42 行 |
| `filter-criteria` | "The criteria the system evaluates to determine if it displays the notification in the current Focus." | 同页第 43 行 |

**`thread-id`（载荷）与 `apns-collapse-id`（头字段）是两个不同机制**：前者是 App 内的会话分组，后者是 APNs 侧的合并投递。混用是 L8 现象里最难归因的一类——用户只看见"通知被合了"，而合并可能来自任一个。这是第 14 章 N7 的两个来源。

### 11.3 授权状态与静默呈现

第 5.3 节的 provisional 现象在这一层落地："The system delivers provisional notifications quietly — they don't interrupt the person with a sound or banner, or appear on the lock screen. Instead, they only appear in the notification center's his..."（《Asking permission to use notifications》第 14 行）

同页还有一条与呈现策略直接相关的用户选择："If a person presses the Keep button, the system prompts them to choose between two options: Deliver Immediately or Deliver in Scheduled Summary."（第 16 行）——**定时摘要**会改变"通知何时出现"，而 provider 侧读数完全不变。第 24 章误区 7 处理"把摘要当成延迟投递"。

授权流程本身也有口径约束："The first time your app makes this authorization request, the system prompts the person to grant or deny the request and records that response. Subsequent authorization requests don't prompt the perso..."（第 9 行）——**弹窗只有一次**，因此"升级授权"只能靠 provisional 转正式的路径，而不是重试。

### 11.4 锁屏可见性与相邻机制

平台安全指南侧的相邻条件（本文只作为"读数可得性"与"内容暴露面"的边界引用，不展开机制）：

- iMessage 依赖 APNs 建立初始连接："Apple Vision Pro. Relying on the Apple Push Notification service (APNs), iMessage lets..."（《Apple Platform Security》第 9294 行，同一段落语境）
- FaceTime："Like iMessage, FaceTime calls use the Apple Push Notification service (APNs) to establish an initial connection to the user's registered devices. The audio/video contents of FaceTime calls are protected by end-to-end encryption, so no one but the sender and receiver can access them. Apple can't decrypt the data."（第 9489—9493 行）
- SharePlay："SharePlay uses the Apple Push Notification service (APNs) for signaling, reusing the same push channel FaceTime establishes between registered devices..."（第 9526—9527 行）
- MDM："APNs is used to wake the device and trigger it to communicate directly with its device management service over a secured connection. No confidential or proprietary information is transmitted over APNs."（第 11319—11321 行）

**这四组句子给出同一条设计约束的四个实例：APNs 只用于唤醒/信令，不承载机密内容。** 它是 L6 第 19 行"不要放敏感数据"的系统级印证，也是本文判断"锁屏上一条通知能暴露什么"的口径上限：**暴露在载荷与本地资源范围内，不暴露在系统级密钥与内容上。**

### 11.5 归属

| 段 | 归属 | 更新通道 |
| --- | --- | --- |
| 通知中心、横幅、锁屏、Focus、摘要、角标渲染 | Apple（iOS 设备侧代码） | **iOS 版本更新**——这是十层里第一个真正出现在公告词表里的层 |
| `category` 声明、动作按钮、分组策略设计 | App 开发者 | App 版本发布 |
| 用户自己的通知设置 | 用户 | 无 |

L8 与 L9 是本文里"会进公告"的两层。第 16 章的 13 条读数里，组件名 `Notifications`、`Notification Services`、`Status Bar`、`VoiceOver`、`Share Sheet`、`Accessibility`、`Libnotify` 全部对应这两层的设备侧代码。**这也是本文与"provider 运维文章"的根本差别：可归属为 Apple 缺陷的那部分，只在这里出现。**

---

## 12. L9 扩展执行层

### 12.1 两种扩展，两种职责

iOS 在通知呈现路径上有两类 app extension，文档分别规定：

| 类型 | 时机 | 能做什么 | 出处 |
| --- | --- | --- | --- |
| Notification Service Extension | 显示**之前** | 修改载荷（解密、下载附件、更新内容） | 《Modifying content in newly delivered notifications》第 9 行 |
| Notification Content Extension | 显示**完整界面时** | 自定义界面（视图控制器） | 《Customizing the Appearance of Notifications》第 7 行 |

服务扩展的定义句：

> "Modifying a remote notification requires a notification service app extension, which you include inside your iOS app bundle. The app extension receives the contents of your remote notifications before the system displays them to the user, giving you time to update the notification payload. You control which notifications your extension handles."（第 9 行）

三类合法动机是文档列的（第 6—8 行）："Decrypt data sent in an encrypted format." / "Download images or other media attachments whose size would exceed the maximum payload size." / "Update the notification's content, perhaps by incorporating data from the user's device."

### 12.2 触发条件：两个都要满足

这是 L9 最重要的可静态判定规则，文档写成"only when"清单：

> "The payload must include the `mutable-content` key with a value of 1."（同页第 27 行）
> "The payload must include an alert dictionary with title, subtitle, or body information."（同页第 28 行）

再加上一条 [important] 的范围限制：

> "Notification service app extensions only operate on remote notifications configured in the system to display an alert to the user. If alerts are disabled for your app, or if the payload specifies only the playing of a sound or the badging of an icon, the extension isn't employed."（同页第 10 行）

API 页重复了同一个开关条件："The remote notification's `aps` dictionary includes the `mutable-content` key with the value set to 1."（《UNNotificationServiceExtension》第 12 行）以及"You can't modify silent notifications or those that only play a sound or badge the app's icon."（同页第 13 行）

**四条合起来给出一条硬判规则**：`mutable-content` 不为 1、或缺 `alert`（或 `alert` 里三个字段全无）、或用户关了 alert——扩展一定不被调用。前两条 provider 可静态判定，第三条只有设备侧知道。脚本一 P 系列把前两条作为"H 提示 + P 判定"输出，第 21.6 节给出实例。

### 12.3 时间预算与兜底

> "Your `didReceive(_:withContentHandler:)` method has only about 30 seconds to modify the payload and call the provided completion handler. If your code takes longer than that, the system calls the `serviceExtensionTimeWillExpire()` method, at which point you must return whatever you can to the system immediately. If you fail to call the completion handler from either method, the system displays the original contents of the notification."（同页第 22 行）

API 侧的同一规则表述为"That method has a limited amount of time to perform its task and execute the provided completion block. If your method doesn't finish in time, the system calls the ... `serviceExtensionTimeWillExpire()` method to give you one last chance to submit your changes. If you don't update the notification content before time expires, the system displays the original content."（《UNNotificationServiceExtension》第 14 行）

内容扩展侧另有一条性能要求："Your app extension must configure its view controller using the data immediately available, such as the contents of the notification and the files present in your app extension's bundle. If you use an app group to share data between your app and your app extension, you may also use any files found in the app group. To ensure your notifications are delivered in a timely manner, configure the views as quickly as possible. Don't perform any long-running tasks, like trying to retrieve data over the network."（《Customizing the Appearance of Notifications》第 12 行）

**这三段合起来定义了 L9 的缺陷形态：它几乎总是"扩展超时 → 回落原始内容"，而不是"扩展失败 → 通知消失"**。回落是静默的、provider 不可见的，用户看到的是一条"内容不对"的通知。第 14 章 N9 型即此。

### 12.4 沙盒边界：app group 是唯一共享面

两处文档共同画出扩展的可见数据范围：

- 服务扩展"ships as a separate bundle inside your iOS app"（《Modifying content in newly delivered notifications》第 12 行；同页第 9 行另一种说法是 "which you include inside your iOS app bundle"），第 13—17 行给出在 Xcode 里添加该 target 的步骤清单。
- 内容扩展只能有一个视图控制器："Don't add additional view controllers to your app extension or storyboard file. Your app extension must contain exactly one view controller..."（《Customizing the Appearance of Notifications》第 25 行）
- 内容扩展仅支持 iOS："Notification content app extensions are supported only in iOS apps."（同页第 13 行）
- 一个项目可以有多个内容扩展，但"each one must support a unique set of notification categories"（同页第 21 行）——**类别（`category`）是 L6 键与 L9 扩展之间的连接键**。

所以"扩展读不到 App 刚写入的数据"这一类现象，在文档口径里是**设计边界而非缺陷**（app group 之外的路径不可见）。本文第 26 章把"扩展的精确执行时限与内存约束数值"列为未文档化边界（30 秒是"about 30 seconds"，非承诺值）。

### 12.5 归属

| 段 | 归属 | 更新通道 |
| --- | --- | --- |
| 扩展宿主进程、时限执行、回落策略 | Apple（iOS） | iOS 版本更新 |
| 扩展代码、超时任务设计、app group 内容 | App 开发者 | App 版本发布 |
| `mutable-content` 与 `alert` 的装配 | provider | 服务端部署 |

L9 的判定要点是**三方共担且证据形态互斥**：provider 能证明"我要求了扩展"（载荷），Apple 决定"是否给时间"（系统），App 决定"时间内做了什么"（代码）。当用户报"锁屏内容是密文"时，正确的读数是**载荷里 `mutable-content` 与 `alert` 是否在**（provider 可自证），而不是去猜扩展做了什么。这正是脚本一设计 P 系列的原因。

---

## 13. L10 专用信道层

### 13.1 为什么单列一层

前面九层讲完，"一条 alert 通知"的链路已经完整。但同一套 HTTP/2 + `aps` 机制上还挂着四条**语义完全不同的信道**：PushKit（VoIP/complication/fileprovider）、后台静默、广播 Live Activity、MDM，外加一条 web push。它们共用大部分层，但在 L5/L7/L8 各有例外规则，因此必须单列——第 14 章 N10—N12 只在 L10 出现。

### 13.2 VoIP / PushKit 信道

这条信道的设备侧接口不是 `UNUserNotificationCenter`，而是 `PKPushRegistry`："A `PKPushRegistry` object manages only certain types of notifications, such as high-priority notifications needed by a VoIP app. PushKit wakes up your app as needed to deliver incoming notifications and delivers the notifications directly to the push registry object that requested them."（《PKPushRegistry》第 9 行）

注册方式也不同，而且**两页措辞不一致**：《PKPushRegistry》第 12 行写 "Assigning a new value to the `desiredPushTypes` property registers the push registry object with the PushKit servers."（链接标签按 URL 末段回填），《Supporting PushKit Notifications in Your App》第 12 行写 "Assigning a value to the `desiredPushTypes` property begins the registration process, so always update that property last."（同页第 29 行的 references 表把该属性释义为 "Registers the push types for this push registry object."）。两句都是"赋值即注册"，但前者的说法是 registers the push registry object with the PushKit servers，后者的说法是 begins the registration process，并额外要求 "always update that property last"——**这句附加约束只在其中一页出现**，第 26 章把它列入"单页独有规则"。

**令牌是独立的一套**："PushKit provides the address to you in the form of a device token, which is an opaque data object."（《Supporting PushKit Notifications in Your App》第 14 行）；"Because users can run your app on multiple devices, be prepared to handle multiple tokens for each notification type your app supports."（同页第 15 行）——**同一 App 里 VoIP 令牌与 UserNotifications 令牌不是同一个值**，这直接解释了 `DeviceTokenNotForTopic`（400）在 VoIP 场景的高频出现：topic 后缀 `.voip`（第 8.2 节）+ 独立令牌 = 两处都可写错。

强制 CallKit 的约束是这一信道最重要的口径变化：

> "For apps built using the iOS 13 SDK or later, PushKit requires you to use CallKit when handling VoIP calls. CallKit ensures that apps providing call-related services on a user's device work seamlessly together on the user's device, and respect features like Do Not Disturb. CallKit also operates the system's call-related UIs, including the incoming or outgoing call screens."（《Responding to VoIP Notifications from PushKit》第 6 行）
> "If you are unable to support CallKit in your app, you cannot use PushKit to handle push notifications. Instead, configure your app's push notification support with the User Notifications framework. If you need to do work in response to an incoming notification—for example, to decrypt content—use a notification service extension to perform that work."（同页第 7 行）

请求侧的时效规则与其他信道相反：

> "Set the value of the `apns-expiration` header field to 0, or to only a few seconds. Doing so prevents the system from delivering the notification at a much later time."（同页第 17 行）

以及"一次推送、之后走自有连接"的模式："After sending the initial push notification, don't send additional push notifications to cancel the call or communicate new details to your app. Instead, communicate with the app directly over the network connection you established between it and your server. Using an existing network connection is generally faster than sending a push notification, and if network conditions are poor, APNs may be unable to deliver push notifications to the device anyway."（同页第 31 行）

尺寸上限另算（5 KB，第 9.2 节），类型走 `voip`（+ `pushtotalk` → `.voip-ptt`）。

### 13.3 后台静默信道

背景通知的定义与限制（第 10 章已给投递侧，这里给信道侧）：

- 定义："A background notification is a remote notification that doesn't display an alert, play a sound, or badge your app's icon. It wakes your app in the background and gives it time to initiate downloads from your server and update its content."（《Pushing background updates to your App》第 5 行）
- 频率："The number of background notifications allowed by the system depends on current conditions, but don't try to send more than two or three per hour."（同页第 6 行）
- 载荷：`aps` 只含 `content-available`，且"the `aps` dictionary must not contain any keys that would trigger user interactions"（同页第 12 行）；头字段 `apns-push-type: background` + `apns-priority: 5`（同页第 13 行）
- 设备侧三条副作用："When the system receives a new background notification, it discards the older notification and only holds the newest one."（第 16 行）；"If something force quits or kills the app, the system discards the held notification."（第 17 行）；"If the user launches the app, the system immediately delivers the held notification."（第 18 行）
- 执行预算："Your app has 30 seconds to perform any tasks and call the provided completion handler."（同页第 19 行）

**这条信道的能力边界与 L9 完全互斥**：背景通知不能带 alert/badge/sound（第 12 行），而服务扩展只在带 alert 时运行（第 12.2 节），且"You can't modify silent notifications"（《UNNotificationServiceExtension》第 13 行）。所以"想静默处理并改写内容"在文档口径下**没有实现路径**——只能走 `content-available` + App 自己下载，或走 alert + 扩展。第 24 章误区 9 针对这一类设计错误。

### 13.4 广播 / Live Activity 信道

广播是十层里唯一"以信道为投递单位"的形态：

> "Broadcast push notifications use channels to reach a large number of people with Live Activities."（《Sending channel management requests to APNs》第 5 行）
> "Broadcast push notifications are only available on Live Activities."（《Setting up broadcast push notifications》第 8 行）

管理面与发布面是**两个不同的主机与端口**（这是 L4 表格里那两行的来源）：`api-manage-broadcast.sandbox.push.apple.com:2195` / `api-manage-broadcast.push.apple.com:2196`（《Sending channel management requests to APNs》第 11、12 行）管理；`api(.sandbox).push.apple.com:443`（《Sending broadcast push notification requests to APNs》第 10、11 行）发布。

信道生命周期与限额：

- 上限："In order to support several simultaneous events, you can maintain up to 10,000 channels for your app in the development and production environment, respectively."（《Sending channel management requests to APNs》第 8 行）
- 独立生命周期："a channel ID exists even if there are no active subscribers, or all subscribers remove the Live Activity"（同页第 8 行）→ 因此**必须显式删除**（同页第 8 行末句）。
- 不可跨环境："Channels can't be shared across environments: a channel created in the development environment can't be used in the production environment. Also, don't make assumptions on the channel ID size."（第 34 行）
- 不可指定 ID："Channel IDs generate randomly when you create them, and you can't request a channel with a specific ID."（第 15 行）
- 存储策略创建后不可改："Message storage policy configured as part of the request can't be modified later."（第 16 行）；两档为 No Message Storage / Most Recent Message Stored，"Messages in Most Recent Message store for a maximum duration of 8 hours."（第 16 行）

发布请求的头部集合与设备推送不同：`:path` 为 `/4/broadcasts/apps/<bundle ID>`（《Sending broadcast push notification requests to APNs》第 17 行）、`apns-channel-id` 必选（base64）、`apns-expiration` **必选**（设备侧为可选）、`apns-push-type` 允许值是 `Liveactivity`（第 23 行，原文如此拼写）。

**这里有一处与 L5 的正面冲突必须记录**：设备推送要求 `liveactivity` 类型的 topic 带后缀 `push-type.liveactivity`（《Sending notification requests to APNs》第 51 行），而广播排障要求 "The bundle ID string you use in the `:path` needs to exactly match your app's bundle ID. The string can't include a suffix, such as `.push-type.liveactivity`."（《Troubleshooting push notifications》第 19 行）。**两者不矛盾（一个讲 `apns-topic`，一个讲 `:path` 里的 bundle ID），但极易写错**——本文把它列为 N10 的定义样本，脚本二在读到广播台账时会显式提示这一区分（第 22.3 节）。

指标口径在这条信道上也独立：`Notifications published` / `Notifications delivered` / `Total subscriptions`（"APNs records subscription snapshots throughout the day and reports the highest val..."）/ `Unique subscribers`（《Setting up broadcast push notifications》第 23—26 行），且"Metrics only record in the production environment; they aren't available in the development environment."（第 19 行），Channels tab 在删除后仍可见（第 20 行）。

### 13.5 MDM 信道

MDM 的 push type 规则是十层里唯一"topic 不来自 bundle ID"的一条："If you set this push type, you must use the topic from the UID attribute in the subject of your MDM push certificate"（《Sending notification requests to APNs》第 53 行）。它的用途与内容边界由安全指南给出（第 11.4 节 MDM 引文：唤醒设备 + "No confidential or proprietary information is transmitted over APNs."）。

**MDM 信道的判定特殊性**：`apns-topic` 的正确性只能对照证书 subject 校验，而证书属于 MDM 厂商/企业部署方，不属于 App 开发者。因此本文十层矩阵里 MDM 相关的读数（`TopicDisallowed`、`BadTopic`、`DeviceTokenNotForTopic`）在归属上必须再分一格——第 15 章矩阵用 "MDM 部署方" 作为第四责任方。

### 13.6 web push 信道

web push 完全不走前面九层的规则集，只共享"APNs 是投递方"这一事实。它的可核对项：

- 订阅侧三步 + 一条硬限制："Ask the user for permission to send them push notifications."（《Sending web push notifications in web apps and browsers》第 9 行）、"Add a service worker that handles receiving push notifications."（第 11 行）、"Safari doesn't support invisible push notifications. Present push notifications to the user immediately after your service worker..."（第 13 行）
- 服务端准备：VAPID 密钥对（第 17 行）、"Set up your server to build and encrypt the payload for each push notification."（第 18 行）、URL 白名单"allow access for `https://*.push.apple.com`"（第 20 行）
- 传输与头部：**走 HTTP/1.1 或 HTTP/2 到订阅 endpoint**（第 29 行），头部为 `TTL`（第 32 行）、`Authorization`（VAPID JWT + public key，第 33 行）、`Content-Encoding`（第 34 行）、`Topic`（"Use a maximum of 32 characters from the URL or filename-s..."，第 35 行）、`Urgency`（第 36 行）；pipelining 限制"100 unacknowledged push requests"（第 30 行）
- 状态码词表**是另一套**：201 Success / 400 Bad request / 403 鉴权错误（第 43—45 行）——注意 201 而不是 200，与设备推送词表不通用。
- 角标：`navigator.setAppBadge`（第 38 行），且权限由用户在 iOS 16.4 起的通知设置里配置（第 39 行）

**这条信道在本文只作为"词表不可互换"的证据使用**：同一份文档族里存在至少三套状态码/头部词表（设备推送、广播信道、web push），任何"按 APNs 词表统一实现客户端"的做法都会在其中两套上出错。第 14 章 N11 定义此型。

### 13.7 归属

L10 是十层里责任方最多的一层，共四种：

| 信道 | 责任方 |
| --- | --- |
| PushKit/VoIP | App 开发者（CallKit 合规）+ provider（`.voip` topic、expiration 0） |
| 后台静默 | App 开发者（30 s 预算）+ provider（priority 5、频率） |
| 广播/Live Activity | provider（信道管理、限额、存储策略）+ Apple（ActivityKit 订阅、指标） |
| MDM | MDM 部署方（证书 subject/UID）+ 设备管理策略 |
| web push | Web 服务端（VAPID、加密、endpoint）+ 浏览器实现（Safari） |

第 15 章矩阵会把这五种拆到行里，这也是本文矩阵"每层可以有多个责任方"的原因——单层单责任方的假设在 L10 直接失效。

---
## 14. 缺陷类型学 N1—N12

前三章按"链路走到哪一格"分层，本章按"**哪一次校验失败了**"分型。两套坐标不是重复：分层回答"错在哪一段路上"，分型回答"是谁的规则没有被满足"。分型的价值在于它可直接映射到公告与响应串——一条公告的 `Description` 句子几乎总能落到某一型里，而一个 `reason` 串只属于一型。

分型只用到两类公开证据：Apple 文档写的校验规则（第 4—13 章逐格列出），以及 `:status` + `reason` 的两套词表（《Handling notification responses from APNs》第 32—63 行的 32 个设备侧串、《Handling error responses from Apple Push Notification service》第 28—55 行的 28 个广播/信道侧串）。凡文档没有写明"谁做这次校验"的格子，本章标为口径缺口并进第 26 章。

### 14.1 十二型的定义

| 型 | 名称 | 失败的那次校验 | 主责层 | 文档口径锚点 | 可见读数 |
| --- | --- | --- | --- | --- | --- |
| N1 | 令牌—主题绑定错误 | "这个设备令牌是否属于这个 topic" | L1 / L7 边界 | 《Handling notification responses from APNs》第 33、38 行 | `BadDeviceToken`、`DeviceTokenNotForTopic`（400）；第 65 行明确这两串属于"APNs 会更快断开连接"的错误 |
| N2 | 授权与 entitlement 缺口 | "这个 App 是否被允许做这件事" | L2 | 《Handling error responses from Apple Push Notification service》第 28 行 `FeatureNotEnabled`；公告侧见第 16.6 节 | `TopicDisallowed`（第 45 行）、`FeatureNotEnabled`（第 28 行）；公告 `Sensitive notifications now require restricted entitlements.`（122066 第 955 行） |
| N3 | Provider 鉴权错误 | "发请求的服务器是不是这个 Team 的合法 provider" | L3 | 第 6.3 节 JWT 字段表 | `MissingProviderToken`/`ExpiredProviderToken`/`InvalidProviderToken`（第 51、48、50 行）、`UnrelatedKeyIdInToken`/`BadEnvironmentKeyIdInToken`（第 52、53 行）、`BadCertificate`/`BadCertificateEnvironment`（第 46、47 行） |
| N4 | 传输与信任链错误 | "这条 HTTP/2 连接本身是否成立" | L4 | 第 7.3 节 GOAWAY、第 7.4 节根证书迁移 | `IdleTimeout`（第 40 行）、`ServiceUnavailable`/`Shutdown`（第 62、63 行）；GOAWAY 的 JSON `reason` |
| N5 | 请求头语义错误 | "9 个字段的取值是否落在文档允许的枚举里" | L5 | 第 8.1—8.3 节字段表与 12 个 push-type 后缀表 | `MissingTopic`/`BadTopic`/`MissingPushType`/`InvalidPushType`/`BadPriority`/`BadExpirationDate`/`BadMessageId`/`BadCollapseId`/`DuplicateHeaders`/`BadPath`/`MethodNotAllowed`（第 34—45、54、55 行） |
| N6 | 载荷结构错误 | "这段 JSON 能不能被解析、装不装得下" | L6 | 第 9.1 节尺寸表 | `PayloadEmpty`（第 44 行）、`PayloadTooLarge`（第 58 行）；广播侧 `BadRequestPayload`/`BadRequestParams`/`PayloadEmpty`（《Handling error responses from Apple Push Notification service》第 33、32、34 行） |
| N7 | 载荷内容信任错误 | "设备把载荷里的字符串当成可信内容呈现" | L6 → L8 | 第 9.5 节敏感数据条款 | 公告主战场：锁屏正文可见（125108 第 940 行）、伪造系统通知（120880 第 430 行）、日志残留（127002 第 430 行） |
| N8 | 存储与投递策略错误 | "APNs 存了几条、什么时候丢" | L7 | 第 10.2 节"每个 bundle ID 只存一条"、第 10.4 节丢弃原因 | 无响应串——只有指标 `Stored - Device Offline` / `Discarded - Disabled`（第 20 章 P6/P7） |
| N9 | 设备端呈现与用户授权错误 | "用户/系统是否允许这条通知露出来" | L8 | 第 11.3 节 provisional 与 Scheduled Summary | 无响应串；设备侧现象（不弹、聚合、静音）＋公告锁屏类条目 |
| N10 | 信道规则错误 | "这条专用信道的专属字段规则是否满足" | L10 | 第 13 章各小节 | 广播/信道侧整表：`MissingChannelId`/`BadChannelId`/`ChannelNotRegistered`/`CannotCreateChannelConfig`（《Handling error responses from Apple Push Notification service》第 29、30、31、38 行）、`InvalidPushType` 的广播解释"仅允许 LiveActivity"（同页第 37 行）；跨环境信道（第 13.4 节第 34 行） |
| N11 | 扩展执行错误 | "扩展在时间预算内是否完成" | L9 | 第 12.3 节 30 秒与回退条款 | 无响应串；呈现为"弹了但是旧内容"（第 3.4 节的换算落差第三例） |
| N12 | 治理与归属错误 | "谁该修、走哪条更新通道" | 跨层 | 第 15 章矩阵 | 公告的组件名与机型列表（第 16 章 13 条读数）；`Available for:` 行的机型边界 |

### 14.2 每型一段展开

**N1 令牌—主题绑定错误。** 这一型的全部难点在于"绑定关系由谁维护"。设备令牌由系统与 APNs 产生（第 4 章 R1-1…R1-7），provider 只能存储与回传；topic 由 provider 在 `apns-topic` 里声明。于是绑定错误有两种成因，文档给了两条不同的串：令牌本身不合法（第 33 行 "The specified device token is invalid. Verify that the request contains a valid token and that the token ma…")与令牌合法但不属于这个 topic（第 38 行 "The device token doesn't match the specified topic."）。**只有后者说明"两侧都正确但配对错了"**，例如同一 App 的 UserNotifications 令牌被发到带 `.voip` 后缀的 topic（第 13.2 节）。这一型还包含 410 分支：`ExpiredToken`（第 56 行）与 `Unregistered`（第 57 行）——第 4.3 节已经说明 410 不是错误而是生命周期读数，而第 65 行又把它排除在错误条件之外（"Note that status code 410 isn't considered an error condition."），所以 N1 的判定动作是"清理令牌库"，不是"修代码"。

**N2 授权与 entitlement 缺口。** 校验发生在"App 是否被授予该能力"这一层，而不是请求本身。文档侧的读数是 `FeatureNotEnabled`（"The feature isn't enabled for this topic."，《Handling error responses from Apple Push Notification service》第 28 行）与 `TopicDisallowed`（同页第 40 行、设备侧第 45 行）。公告侧给出这一型最干净的一例：`Libnotify` 组件、`Impact: An app may be able to cause a denial-of-service`、`Description: An app could impersonate system notifications. Sensitive notifications now require restricted entitlements.`（122066 第 940、950、955 行）。**这句话同时给出缺陷（App 可冒充系统通知）与修复方向（改为需要受限 entitlement）**，是本文全部 13 条读数里唯一一条把"授权层"写进 `Description` 的；同一串文字也出现在 iPadOS 17.7.3（121838 第 670 行），机型不同（同页第 660 行只列三款旧 iPad）。

**N3 Provider 鉴权错误。** 全部落在 403，共 8 串（第 46—53 行）。这一型内部要再切两刀：证书路线（`BadCertificate`、`BadCertificateEnvironment`）与令牌路线（其余 6 串）。令牌路线里最容易被误读的是 `UnrelatedKeyIdInToken`——文档写的是"这个 kid 与**第一次推送**用的那个 token 的 key ID 无关"（第 52 行），也就是说它的判定基准不是"key 是否有效"，而是"key 是否与这条连接上第一次推送一致"（第 6.4 节）。这是 N3 里唯一一条**连接上下文相关**的错误：同一段合法 JWT，在另一条新连接上是 200，在这条已绑定的连接上是 403。归属上因此只能记给 provider（轮换策略），不记给 Apple。

**N4 传输与信任链错误。** 校验发生在"连接是否成立"这一格，读数形态与 N3/N5 不同：一半是 GOAWAY 帧里的 JSON `reason`（第 7.3 节），一半是 503/`IdleTimeout`。这一型的边界必须说清楚：**本文只把文档写明的 GOAWAY 与重连条款当作口径证据，不讨论任何造成断连的操作**（第 2 章范围声明）。可安全使用的读数是"连接被 APNs 主动结束"这一事实本身，以及第 65 行的因果说明（"APNs disconnects a provider connection with too many error conditions. APNs disconnects sooner with certain error conditions, such as BadDeviceToken."）——它把 N4 与 N1/N3/N5 串起来了：**大量 N1 读数会表现为 N4 的断连**，运维只看到断连会找错方向。

**N5 请求头语义错误。** 数量最多的一型（第 34—45、54、55 行共 11 串），但也是**最可预防**的一型：全部判据都是第 8 章那张 9 字段表和 12 值后缀表，属于纯本地可静态核对的规则集合。脚本一（第 21 章）就是把这 11 串的判据前置执行，输出"最可能收到的 `reason`"。这一型的归属几乎全部在 provider，唯一例外是 `IdleTimeout`（第 40 行）——名字像请求头问题，实际是连接空闲被结束，属 N4，本文按定义把它归 N4、在 N5 只留交叉引用。

**N6 载荷结构错误。** `PayloadEmpty`、`PayloadTooLarge` 两条设备侧串，加上广播侧的 `BadRequestPayload`（"The JSON Request payload is unparseable."，《Handling error responses from Apple Push Notification service》第 33 行）。这一型与 N7 的分界要写清：**N6 是"读不懂"，N7 是"读得懂但内容是别人的"**。第 9.1 节的尺寸冲突（文档口径 4 KB / VoIP 5 KB 对安全指南口径 4 或 16 KB，第 9346 行）属于 N6 的口径缺口：同一格校验有两套数字，本文两边都列（第 26 章 U3）。

**N7 载荷内容信任错误。** 十层里唯一"每层都没做错、结果仍然出问题"的一型：请求合法、载荷可解析、状态 200、通知也弹了，但**呈现出来的内容本身**造成泄露或欺骗。公告 13 条读数里有 8 条属于这一型（第 16 章逐条给），其 `Description` 句式高度收敛在三种："improved checks"（125108 第 945 行）、"improved state management"（120905 第 1435 行）、"additional entitlement checks"（120880 第 435 行）。设备侧对应第 11.1 节的两段式呈现（先占位后替换）与第 9.5 节的敏感数据条款。**修复动作一半在 provider（不要把敏感正文放进载荷），一半在设备侧实现（锁屏未解锁时的呈现策略），因此归属矩阵里 N7 是唯一横跨两个责任方的型。**

**N8 存储与投递策略错误。** 唯一没有任何响应串的一型：APNs 的行为（每 bundle ID 只存一条、每设备一次只排一条、上线后合并突发）都只体现在指标里。第 10.2 节的两条规则句是全部判据。判定这一型需要读侧导出件（第 20 章 P6/P7），因此它在实践里最容易被误归为 N1 或 N9——"用户说没收到"既可能是令牌失效、也可能是被存储策略覆盖，而**前者有 410 读数、后者只有指标**。

**N9 设备端呈现与用户授权错误。** 校验主体是用户与系统，不是 provider。provisional 授权、专注模式、Scheduled Summary、静音开关都在这一格（第 11.3 节）。这一型在公告里的形态最"难读"：组件名写成 `Status Bar`、`VoiceOver`、`Notifications` 而不是任何推送相关名字，机型行（`Available for:`）却各不相同。第 16 章用 120905 与 121837 两条同句式读数说明这个现象：**同一句 Impact 会挂在不同组件名下**，因此按组件名检索公告必然漏。

**N10 信道规则错误。** L10 五条专用信道各有自己的字段规则，广播侧一整张错误表（《Handling error responses from Apple Push Notification service》第 28—55 行）就是这一型的读数。三处最容易犯：`apns-channel-id` 缺失或编码超界（第 29、30 行）、信道不存在（第 31 行）、信道数达到上限（第 38 行 "You have reached the maximum channel limit for your application."）。第 13.4 节的 `:path` 无后缀 vs `apns-topic` 带后缀属于这一型的定义样本——两个规则分属两页，都不冲突，但写成一处就 400。

**N11 扩展执行错误。** 判据只有第 12.3 节那一组：`mutable-content`=1 + 带 alert 字典才会进扩展、约 30 秒预算、超时后 `serviceExtensionTimeWillExpire()`、否则呈现原始内容。这一型的现象与 N8 相反：**通知一定到，内容一定旧**。它不产生任何 APNs 读数（扩展在设备侧执行），因此是"provider 台账 100% 200、用户投诉内容不对"这种组合的唯一解释。归属上落在 App 的扩展 target，与 provider 服务器无关。

**N12 治理与归属错误。** 前面十一型都假定"知道该谁修"，这一型的缺陷恰恰是**归属判定本身做错**：把 N11（App 扩展）当成 Apple 侧缺陷提单、把 N2（entitlement）当成 provider 代码 bug、把 N1 的 410 分支当成缺陷上报。第 15 章矩阵的存在理由就是把 N12 变成可核对动作：每一层给出责任方 + 更新通道 + 证据类型。公告侧的对应证据是机型行的差异——同一条 CVE 在 5 个页面出现而 `Available for:` 各不相同（127002/127003/127112/127113/127114 均第 425 行），说明"修了"与"这台设备能拿到修"是两件事。

### 14.3 型 ↔ 层 ↔ 读数 对照

| 型 | 层 | 有响应串 | 有指标读数 | 有公告读数 | 可在本地预检 |
| --- | --- | --- | --- | --- | --- |
| N1 | L1,L7 | 是 | 是 | 弱 | 否（令牌不可本地验证） |
| N2 | L2 | 是 | 否 | 是 | 是（entitlement 清单） |
| N3 | L3 | 是 | 否 | 否 | 是（JWT 字段与 kid/iss 规则） |
| N4 | L4 | 部分 | 否 | 否 | 部分（端点与证书 OID） |
| N5 | L5 | 是 | 否 | 否 | 是（脚本一全量） |
| N6 | L6 | 是 | 否 | 否 | 是（尺寸与可解析性） |
| N7 | L6,L8 | 否 | 是 | 是 | 是（敏感键检查） |
| N8 | L7 | 否 | 是 | 否 | 部分（collapse 规则） |
| N9 | L8 | 否 | 否 | 是 | 否 |
| N10 | L10 | 是 | 是 | 否 | 是（脚本一广播分支） |
| N11 | L9 | 否 | 否 | 否 | 是（mutable-content 与 alert 同现） |
| N12 | 跨层 | 否 | 否 | 是 | 是（第 15 章矩阵） |

"可在本地预检"一列直接决定工程性价比：**能在发出请求前判定的型（N2、N3、N5、N6、N7、N10、N11、N12）合计 8 型**，脚本一覆盖其中的 N5/N6/N10/N11/N3-字段级/N2-清单级；必须等一次真实往返才能判定的只有 N1/N3-签名级/N4；完全没有请求侧读数的 N8/N9/N11-超时需要指标或设备侧观察。

---

## 15. 归属矩阵：层 × 责任 × 更新通道 × 证据

第 14 章回答"哪一次校验失败"，本章回答"因此该谁改、改了怎么到位、读者拿到什么证据"。四个坐标的取值集合都是文档或公告里可核对的，不引入自定义角色。

### 15.1 责任方取值

| 代号 | 责任方 | 判定依据 |
| --- | --- | --- |
| A | Apple 平台侧（iOS 更新） | 公告条目按机型发布；`Available for:` 行给出边界 |
| B | Apple 服务侧（APNs 行为） | 文档描述的服务端规则（存储、排队、限流、断连） |
| C | Provider 服务器代码 | 请求构造、令牌轮换、重试与退避 |
| D | App 开发者（容器/target/entitlement） | entitlement 声明、扩展 target 实现、通知呈现配置 |
| E | 用户/设备状态 | 授权开关、专注模式、联网与电量 |
| F | MDM 部署方 | MDM 证书 subject 里的 UID topic（第 13.5 节） |

### 15.2 十层归属矩阵

| 层 | 关键规则句（章节） | 责任方 | 更新通道 | 读者可得的证据类型 | 主要型 |
| --- | --- | --- | --- | --- | --- |
| L1 设备令牌注册 | 第 4 章 R1-1…R1-7 | A + C + E | iOS 更新 / provider 令牌库改造 | 410 串 + `timestamp` 字段（《Handling notification responses from APNs》第 29 行） | N1 |
| L2 授权与 entitlement | `aps-environment`、critical-alerts、provisional（第 5 章） | D（声明）+ A（强制） | App 重新构建签名 | 403/400 串 + 公告 `restricted entitlements`（122066 第 955 行） | N2 |
| L3 Provider 鉴权 | JWT `alg`/`kid`/`iss`/`iat` 与 key 拓扑（第 6 章） | C + D（key 归属） | provider 部署 + 开发者账号 key 管理 | 403 全 8 串；`UnrelatedKeyIdInToken` 需连接上下文 | N3 |
| L4 传输与信任链 | 端点、TLS、GOAWAY、根证书迁移（第 7 章） | A + C | iOS/服务端证书信任库 + provider TLS 配置 | GOAWAY JSON `reason`、`IdleTimeout`、503 两串 | N4 |
| L5 请求头语义 | 9 字段表 + 12 push-type 后缀表（第 8 章） | C | provider 代码 | 11 个 400 串，全部可本地预检 | N5 |
| L6 载荷 | 尺寸表、18 键 `aps`、本地化、敏感数据条款（第 9 章） | C + D | provider 代码 + App 内容策略 | `PayloadEmpty`/`PayloadTooLarge`；内容类只有公告 | N6, N7 |
| L7 APNs 存储与投递 | 每 bundle ID 存一条、每设备排一条、≤30 天（第 10 章） | B | 无（行为由 Apple 服务侧持有） | 只有指标：`Stored - Device Offline`、`Discarded - Disabled`（第 20 章 P6/P7） | N8, N1 |
| L8 设备端派发与呈现 | 两段式呈现、thread-id、provisional/Scheduled Summary（第 11 章） | A + E | iOS 更新 + 用户设置 | 公告（组件名 `Notifications`/`Status Bar`/`VoiceOver`）；无响应串 | N7, N9 |
| L9 扩展执行 | `mutable-content` + alert 才进扩展、约 30 秒、回退原内容（第 12 章） | D | App 重新构建（扩展 target 在 App bundle 内） | 无 APNs 读数；设备侧内容新旧 | N11 |
| L10 专用信道 | VoIP/后台/广播/MDM/web 五套专属规则（第 13 章） | C + D + F（MDM） | 各自通道：App 更新、provider 代码、MDM 部署 | 广播侧 28 串独立词表；web push 独立状态码集合 | N10 |

### 15.3 三条读法约束

1. **一格多责任方时必须写明判定动作。** L1 同时是 A/C/E，但 410 与 400 的分工是文档给的：`Unregistered` 说明"这个令牌对该 topic 已失效，无需再发"（第 57 行）→ 动作在 C（清理令牌库）；锁屏呈现变化 → 动作在 A（iOS 更新）。**不写判定动作的归属矩阵等于没有归属**，因为它不能排除 N12。
2. **责任方 B（Apple 服务侧）没有更新通道。** L7 的规则由 APNs 行为持有，provider 只能顺应（例如"每 bundle ID 只存一条"决定了不能用同一 topic 排队多条）。因此本文不把任何 L7 读数写成"待 Apple 修复"，只写成"待 provider 改变用法"。这是第 24 章误区 M6 的正面表述。
3. **公告组件名不是层名。** `Notifications`、`Notification Services`、`Status Bar`、`VoiceOver`、`Libnotify`、`Passwords`、`Share Sheet` 都是公告词表里的组件标签（第 16 章给出这 7 个的实际出现页与行号）。矩阵用层组织、公告用组件组织，两者之间唯一的桥是 `Impact`/`Description` 句子本身。第 3.2 节把这个缺口命名为"公告词表不按层组织"，本章把它落成动作：**归属判定按句子的校验对象来定层，不按组件名来定层。**

### 15.4 更新通道与"到位"的判定

| 通道 | 覆盖层 | 到位证据 | 不到位时的表现 |
| --- | --- | --- | --- |
| iOS 主版本/安全更新 | L1、L7 内容呈现部分、L8 | 公告页 `Released` 行 + 设备设置里的版本号 | 旧机型仍在 `Available for:` 列表外（127114 第 425 行只列 iPhone 6s/7/SE1 等） |
| App 重新构建签名 | L2、L9 | App Store/内部分发版本号 | entitlement 缺失 → 403/400 串；扩展超时 → 旧内容 |
| provider 部署 | L3、L4、L5、L6、L10 | 请求侧文本（脚本一输入） | 400/403 串集合变化 |
| MDM 部署 | L10（MDM） | MDM 厂商证书 subject 的 UID topic | 该信道的 topic 判定只能由 F 完成 |
| 用户设置 | L8、L9 呈现 | 无（读者自己的设备） | 通知到达但不显示 |

矩阵到此为止是"静态归属"。第 19 章的四级判定模型给出动态流程：口径 → 对齐 → 读数 → 归因，每一步只依赖上面一格，任何一步缺证据就停在该步，不做跳步归因。
## 16. 公开案例读数

本章把 13 条与推送链路直接相关的 Apple 安全公告条目**按原文逐格抄出**（组件行 / `Available for:` 行 / `Impact:` 行 / `Description:` 行 / CVE 行），并给出各自行号。这些条形的作用不是证明"推送有漏洞"，而是提供**公告口径下这条链路能被读到的全部粒度**：一条公告既不写层、也不写 `reason`，只写组件名 + 一句影响 + 一句修复 + 一组机型。把 13 条并排放，才能看清第 15.3 节约束三的必要性。

### 16.1 总表

| 读数 | 公告页 | 发布日 | 组件行 | `Impact:` / `Description:` 行 | CVE |
| --- | --- | --- | --- | --- | --- |
| R1 | 120880（iOS 16.7.6） | 第 415 行 Released March 5, 2024 | 第 420 行 Accessibility | 第 430 / 435 行 | 第 440 行 CVE-2024-23262 |
| R2 | 120893（iOS 17.4） | — | 第 445 行 Accessibility | 第 455 / 460 行 | 第 465 行 CVE-2024-23262 |
| R3 | 120893 | — | 第 475 行 Accessibility | 第 485 / 490 行 | 第 495 行 CVE-2024-23291 |
| R4 | 120905（iOS 17.5） | — | 第 1420 行 Status Bar | 第 1430 / 1435 行 | 第 1440 行 CVE-2024-40839 |
| R5 | 121837（iOS 18.2） | — | 第 1290 行 VoiceOver | 第 1300 / 1305 行 | 第 1310 行 CVE-2024-54485 |
| R6 | 121838（iPadOS 17.7.3） | — | 第 655 行 Libnotify | 第 665 / 670 行 | 第 675 行 CVE-2025-24091 |
| R7 | 121838 | — | 第 785 行 VoiceOver | 第 795 / 800 行 | 第 805 行 CVE-2024-54485 |
| R8 | 122066（iOS 18.3） | — | 第 940 行 Libnotify | 第 950 / 955 行 | 第 960 行 CVE-2025-24091 |
| R9 | 122066 | — | 第 1470 行 Notifications | 无 `Impact:`/`Description:`/CVE 行，仅第 1475 行致谢 | — |
| R10 | 122371（iOS 18.4） | — | 第 2015 行 Share Sheet | 第 2025 / 2030 行 | 第 2035 行 CVE-2025-30438 |
| R11 | 125108（iOS 26） | — | 第 930 行 Notifications | 第 940 / 945 行 | 第 950 行 CVE-2025-43309 |
| R12 | 127002（iOS 26.4.2） | 第 415 行 Released April 22, 2026 | 第 420 行 Notification Services | 第 430 / 435 行 | 第 440 行 CVE-2026-28950 |
| R13 | 127003 / 127112 / 127113 / 127114 | 各页第 415 行 | 各页第 420 行 Notification Services | 各页第 430 / 435 行 | 各页第 440 行 CVE-2026-28950 |

### 16.2 R1 / R2：伪造系统通知，同一个 CVE 落在两条版本线

Impact: "An app may be able to spoof system notifications and UI"，Description: "This issue was addressed with additional entitlement checks."（120880 第 430、435 行；120893 第 455、460 行文字相同）。两点必须记下：

- **修复手段写在授权层**："additional entitlement checks" 是校验位置的直接陈述，按第 14 章落 N2、按第 15 章矩阵主责方是 D（声明 entitlement）+ A（强制校验实现）。但组件行是 `Accessibility`，不是任何推送相关名字——**只按组件名检索会整条漏掉**。
- 两页的 `Available for:` 不同：120880 第 425 行列 iPhone 8/8 Plus/X 与两款旧 iPad，120893 第 450 行从 iPhone XS 起算。同一条 CVE 的机型边界随版本线变化，这就是第 20 章 P10 之后的"到位判定"依据。

### 16.3 R3：通知相关日志里能读到用户数据

Impact: "A malicious app may be able to observe user data in log entries related to accessibility notifications"，Description: "A privacy issue was addressed with improved private data redaction for log entries."（120893 第 485、490 行，CVE-2024-23291 第 495 行）。**这一条的校验对象是"日志内容"而不是"通知内容"**，因此属 N7 的日志侧分支，第 18 章按它给出读者可以自己执行的脱敏核对（只针对自己的日志）。

### 16.4 R4 / R5 / R7 / R11：锁屏正文可见，四种组件名一句影响

四句话几乎同义，措辞略有差别：

- Impact: "An attacker with physical access to an iOS device may be able to view notification contents from the Lock Screen"（120905 第 1430 行；125108 第 940 行完全相同）。
- Impact: "An attacker with physical access to an iOS device may be able to view notification content from the lock screen"（121837 第 1300 行，`content` 单数、`lock screen` 小写）。
- 121838 第 795 行同句但设备词为 iPadOS："An attacker with physical access to an iPadOS device may be able to view notification content from the lock screen"。

`Description:` 三式："This issue was addressed through improved state management."（120905 第 1435 行）、"The issue was addressed by adding additional logic."（121837 第 1305 行、121838 第 800 行）、"A logic issue was addressed with improved checks."（125108 第 945 行）。

**四张页的组件名分别是 `Status Bar`、`VoiceOver`、`VoiceOver`、`Notifications`，两句影响语义相同。** 这是第 15.3 节约束一的最强证据：组件行不能用来定层。归属上这一组全部落 N7（载荷内容信任）+ N9（设备端呈现），责任方 A + E，更新通道为 iOS 更新；provider 侧唯一能做的动作在第 9.5 节（不承载敏感正文）。

### 16.5 R10：锁屏上的"正在录音"提示可被消除

Impact: "A malicious app may be able to dismiss the system notification on the Lock Screen that a recording was started"，Description: "This issue was addressed with improved access restrictions."（122371 第 2025、2030 行，CVE-2025-30438 第 2035 行）。组件行 `Share Sheet`（第 2015 行）。**这一条属 N9 而不是 N7**：内容没有泄露，被破坏的是"呈现的不可撤销性"。它给出 L8 的第二种失败模式——第 11.1 节的两段式呈现只管"内容怎么出现"，管不了"谁能把它划掉"。安全指示类通知（录音、定位、屏幕共享）的不可消除性属设备侧实现，provider 无对应读数。

### 16.6 R6 / R8：冒充系统通知，DoS 表述 + 授权修复

Impact: "An app may be able to cause a denial-of-service"，Description: "An app could impersonate system notifications. Sensitive notifications now require restricted entitlements."（122066 第 950、955 行；121838 第 665、670 行文字相同，CVE-2025-24091）。组件行 `Libnotify`——**十层里唯一一个以通知基础设施库命名的组件**。三点观察：

1. `Impact:` 与 `Description:` 描述的不是同一件事：前者说可用性（DoS），后者说明冒充与修复方向。**按第 3.2 节，这是公告词表内部的对齐缺口**——单看 `Impact:` 会把这条读成 L7 的可用性问题，实际校验点在 L2。
2. "Sensitive notifications now require restricted entitlements" 是全部 13 条读数里唯一明示 entitlement 收紧的一条，直接对应第 5.2 节的受限 entitlement 口径。归属 D + A。
3. 两条页的机型差异（121838 第 660 行只列三款旧 iPad，122066 第 945 行从 iPhone XS 起）说明同一个 CVE 在旧版本线上更晚到位。

### 16.7 R9：只有致谢、没有 CVE 的 Notifications 段

122066 第 1470 行有组件行 `Notifications`，第 1475 行是一句致谢（"We would like to acknowledge Abhay Kailasia … Xingjian Zhao … for their assistance."），**中间没有 `Available for:`、`Impact:`、`Description:`、CVE 四行**。本文把这条列为读数，是因为它给出公告口径的一个真实边界：**组件名出现不等于该组件在本版本有独立修复条目**。这条无法进入任何型的归因（级 3 读数缺失，见第 19 章），只能作为"检索时不可据此计数"的反例。

### 16.8 R12 / R13：同一条读数镜像在五个页面

`Notification Services` / Impact: "Notifications marked for deletion could be unexpectedly retained on the device" / Description: "A logging issue was addressed with improved data redaction." / `CVE-2026-28950`，五个页面分别在第 420、430、435、440 行，`Released` 行分别为 April 22, 2026（127002 第 415 行、127003 第 415 行）与 May 11, 2026（127112 / 127113 / 127114 各页第 415 行）。`Available for:` 行差异见第 3.4 节：127002 第 425 行从 iPhone 11 起，127003 第 425 行列 iPhone XR/XS/XS Max/11 系列与 SE2，127112 第 425 行只列三款旧 iPad，127113 第 425 行列 iPhone 8/8 Plus/X，127114 第 425 行列 iPhone 6s/7/SE1 与 iPad Air 2、iPad mini 4。

**这条读数是本文三套词表落差的样本**（第 3.4 节）：影响句说的现象——"标记删除的通知仍留在设备上"——属 L8/L9 之间的删除态一致性；修复句说的是日志脱敏。**两者不在同一层，且都没有对应的 `reason` 串或指标分类**，因此级 3 读数只能来自设备侧观察（通知已划掉但仍在列表里），级 4 归因只能停在"责任方 A，通道 iOS 更新"。

### 16.9 13 条读数给出的四条口径结论

1. **组件名不可用于定层**：7 个不同组件名（Accessibility、Status Bar、VoiceOver、Libnotify、Share Sheet、Notifications、Notification Services）覆盖同一条链路的同一型。
2. **`Impact:` 与 `Description:` 可能不同轴**（R6/R8 最明显），归因要同时读两句。
3. **同一 CVE 跨页镜像且机型不同**（R1/R2、R5/R7、R6/R8、R12/R13），"已修复"必须写成"在哪条版本线的哪些机型上已修复"。
4. **公告不提供层内定位**：13 条里 0 条提到 `reason` 串、`aps` 键、topic、payload 尺寸或扩展时间预算。**因此"公告里没有"不能推出"这一层没问题"**——第 1.1 节的第一种错误结论就在这里被证伪。

---

## 17. 可见性边界：这条链路上读者能拿到什么

前面十章的规则全部来自公开文档，第 16 章的读数全部来自公开公告。本章回答一个实践问题：**一个正当持有 provider 凭证与自家 App 控制台权限的人，能拿到哪些一手数据，不能拿到哪些。** 这条边界决定了第 19 章哪一级能走通。

### 17.1 五类一手读数与其范围

| 类别 | 内容 | 范围限制（原文口径） | 章节锚点 |
| --- | --- | --- | --- |
| 响应头与响应体 | `apns-id`、`:status`、`apns-unique-id`；失败时 JSON 的 `reason` + `timestamp` | 每次请求都有；`apns-unique-id` 只在开发环境返回 | 《Handling notification responses from APNs》第 10—12、28—29 行 |
| 指标（Metrics） | delivered / stored / discarded 及各自动分类 | "aggregated, rounded reports"，非逐条 | 《Viewing the status of push notifications using Metrics and APNs》第 10 行 |
| 投递日志（Delivery Log） | 一条通知的状态迁移历史 | 开发环境专有、按 bundle ID 查询、发送后 7 天内、需自行下载留存 | 《Testing notifications using the Push Notification Console》第 27 行 |
| 控制台 | 发送测试、管理信道、JWT 校验 | "monitor delivery status for device push notifications in the development environment"（同页第 6 行）；部分功能仅 admin 角色（Metrics 页第 8 行） | 同页第 6、21、29 行 |
| 设备侧观察 | 用户在自己设备上看见/关闭/授权的状态 | 只有本机、只有当下；无历史 | 第 11 章 |

投递日志的原文限制句值得整句抄出："To view the delivery log for a particular push notification sent to APNs, you need to select the bundle ID that you used to send the notification from the dashboard. You can only query delivery logs of notifications sent for the selected bundle ID. Delivery logs are only available in the development environment. You can access the logs for up to seven days after you send the notification. Download and save the logs to retain them for future analysis or reference."（同页第 27 行）。**四重限制（bundle ID × 开发环境 × 7 天 × 需自行留存）叠加的结果是：生产环境事故几乎没有一手逐条证据**，只剩聚合指标。这是本章最重要的工程结论：任何"事后按条追责"的方案在生产 iOS 推送上不具备公开文档支持的实现路径。

### 17.2 明确不可见的三格

1. **APNs 内部队列与覆盖顺序。** 指标页第 30 行只说"APNs persistent storage only stores one notification per application per device"并且"because APNs doesn't have any ordering guarantees, this isn't always the case"——**哪一条被留下是不可预测且不可查询的**。
2. **离线设备的状态。** 同页第 16 行："To preserve privacy, APNs doesn't track states of offline devices, other than preserving notifications." provider 无法区分"设备离线"与"设备已卸载但令牌未回收"，只能靠 P9（410 比率）间接推断。
3. **设备侧呈现结果。** 第 12 章扩展执行、第 11 章呈现与用户授权都不回传任何状态；`200` 只说明 APNs 接受了请求（Metrics 页第 5 行的措辞是 "after APNs accepts your request"）。

### 17.3 本文全部核验动作的可行域

据此，两个脚本（第 21、22 章）的输入被限定为**读者自己持有的文本**：脚本一接收一条由读者自己导出的请求文本（首部 + 载荷），脚本二接收一份由读者自己从 provider 日志或控制台导出并脱敏后的响应台账。两者都不访问 APNs、不读取设备、不需要投递日志。任何需要 17.2 三格数据才能判定的结论，本文一律停在级 3（读数）以下并写进第 26 章。

---

## 18. 崩溃与日志读数侧

本章只处理**读者自己系统的文本**：provider 侧日志、自家 App 的 os_log 导出、以及公告里关于日志脱敏的条目。不提供任何读取他人设备日志或系统日志的方法。

### 18.1 两条以"日志"为修复对象的公告读数

第 16 章 13 条里，两条把 `Description:` 写在日志上：

- "A privacy issue was addressed with improved private data redaction for log entries."（120893 第 490 行，CVE-2024-23291 第 495 行），配套影响句明确对象是 "log entries related to accessibility notifications"（第 485 行）。
- "A logging issue was addressed with improved data redaction."（127002 第 435 行，CVE-2026-28950 第 440 行；五个页面镜像同句，见 R13）。

**两式的差异是口径信息而不是排版差异**：前者说"隐私问题 + 改进私有数据脱敏"，后者说"日志问题 + 改进数据脱敏"。两句都不写涉及哪一层，因此归属仍需按第 15.3 节约束一用"校验对象"定层：R3 的校验对象是日志写入（L8 之外的旁路），R12 的校验对象是删除态与日志。

### 18.2 provider 日志的三格可读文本

一条被拒请求在 provider 侧留下的最小文本是三格：`:status`、`reason`、`timestamp`（《Handling notification responses from APNs》第 11、28、29 行）。第 29 行对 `timestamp` 的定义把它的用途限定得很窄："The time, represented in milliseconds since Epoch, at which APNs confirmed the token was no longer valid for the topic"——**只有令牌失效类读数才带有意义的时间戳**。因此脚本二（第 22 章）在处理台账时只在 410 分支使用 `timestamp`，其他分支把它记为"不参与判定"。

失败响应还会带 GOAWAY 的 JSON `reason`（第 7.3 节）。两类文本混在同一份日志里时，脚本二按行分派（响应行 / GOAWAY 行 / 未知行），未知行不猜测语义、只计数并进 P8 的分母。

### 18.3 扩展与派发侧的文本读数边界

第 12 章说明扩展运行在 App 的独立进程里；它的失败在设备侧表现为"呈现原内容"或"通知不出现"，**不会在 provider 侧留下任何文本**。第 17.1 节的投递日志范围限制（开发环境、7 天）意味着这一侧的文本读数只在开发阶段可得。本文因此不把"扩展崩溃"写成可远程判定的型，N11 的判定动作限定为本地代码审查：`mutable-content` 与 alert 字典是否同现（第 12.2 节两条触发条件句）、`serviceExtensionTimeWillExpire()` 是否实现、下载/解密是否在预算内。

### 18.4 崩溃报告：本文的口径

在公开文档与公告范围内，与推送链路直接相关的崩溃读数**没有稳定的公开口径**：13 条读数的 `Description:` 里 0 条提到崩溃（improved checks、state management、additional logic、access restrictions、redaction 五式覆盖了全部）。因此本文不建立"崩溃 → 层"的映射，只保留一条可核对事实：第 16 章的修复句式集合是封闭可数的，读者遇到不在集合内的句式即说明该条不属于本文 13 条读数范围。

---

## 19. 四级判定模型

级 1—4 是从"有没有规则"走到"该谁改"的唯一允许路径；任何跳步都属 N12。

### 19.1 四级定义

| 级 | 名称 | 必须产出的证据 | 通过条件 | 失败时停在哪 |
| --- | --- | --- | --- | --- |
| 级 1 | 口径 | 一句可定位到页/行的文档规则句，或一句公告 `Impact:`/`Description:` | 原文存在且已抄出 | 无规则 → 进第 26 章未文档化清单，不得继续 |
| 级 2 | 对齐 | 该规则作用在哪一层（L1—L10）与哪一型（N1—N12） | 能同时给出层与型，并说明校验对象 | 校验对象不明 → 停在级 2，标注"待补" |
| 级 3 | 读数 | 一次可复现的只读观察：响应串 / 指标分类 / 设备侧现象 / 公告条目 | 读数落在第 17 章五类之内且注明来源 | 读数不可得（如生产逐条）→ 停在级 3，禁止归因 |
| 级 4 | 归因 | 责任方（A—F）+ 更新通道 + 修复动作 | 三者齐备且与第 15 章矩阵一致 | 任一缺失 → 停在级 4 之前，写成"归属待定" |

### 19.2 三级停止的三种真实形态

1. **停在级 1**：第 9.1 节的尺寸口径冲突（文档 4 KB / VoIP 5 KB 对安全指南第 9346 行的 "APNs can only relay messages up to 4 or 16 KB in size, depending on the iOS or iPadOS version"）。规则存在但相互冲突，本文不选边，只并列（第 26 章 U3）。
2. **停在级 2**：R9（122066 第 1470 行）只有组件行与致谢行，没有影响句与修复句，校验对象无从确定。
3. **停在级 3**：第 17.1 节说明生产环境无逐条投递日志；因此"这条通知到底有没有覆盖掉前一条"（L7 / N8）在生产的公开口径下不可判定，只能给聚合指标推断并标注推断性质。

### 19.3 走通四级的两个完整样例

**样例 A（N5 型）**：`apns-priority` 填 10 但 `apns-push-type` 为 `background`。
级 1：《Sending notification requests to APNs》第 47 行的后台信道条款写明该情形应使用优先级 5（第 8.3 节整句抄出）。
级 2：校验对象是请求头取值 → L5、N5。
级 3：本地预检即可复现（脚本一 H 组槽位），无需真实往返。
级 4：责任方 C，通道 provider 部署，动作改为 5。
**这是唯一能全程离线走通四级的型别**，因为 L5 的规则全是声明式的。

**样例 B（N7 型）**：R11（125108 第 930—950 行）。
级 1：Impact: "An attacker with physical access to an iOS device may be able to view notification contents from the Lock Screen"。
级 2：校验对象是"锁屏未解锁时的正文呈现" → L8 为主、L6 参与（正文是否被放进载荷），型 N7 + N9。
级 3：读数只能来自设备侧观察（本机锁屏）与公告条目本身；无响应串、无指标分类。
级 4：责任方 A（iOS 更新，通道为 125108 对应版本）+ E（用户是否开启锁屏显示）+ D（provider/App 不放敏感正文）。**三个责任方各自的动作不同，且都不能从公告句式推定实现细节**，因此本文把这条写成"归属可定、根因不可定"。

---

## 20. 运营指标 P1—P10

指标是这条链路上唯一被 Apple 承诺可批量获取的读数（Metrics 页第 10 行），但它被明确声明为聚合与取整："The Metrics tab provides aggregated, rounded reports on notification states as your notifications pass through APNs."（同页第 10 行）。因此本章每个 P 都写出**读数来源、口径、以及不可用于什么**。

| 代号 | 指标 | 定义 | 口径锚点 | 不可用于 |
| --- | --- | --- | --- | --- |
| P1 | 接受率 | `:status` = 200 的占比（provider 自有台账） | 状态码表《Handling notification responses from APNs》第 15 行 `200 \| Success.` | 不代表设备收到（第 17.2 节） |
| P2 | 存储占比 | `Stored - *` / 总量 | 同页第 15 行分类规则 | 无法区分被覆盖前的多条 |
| P3 | 丢弃占比 | `Discarded - *` / 总量 | Metrics 页第 20—23 行三因 | 不能反推具体用户 |
| P4 | `Discarded - Disabled` 趋势 | 环比上升视为"通知被认为无关或嘈杂" | 同页第 16 行 "an uptick of Discarded - Disabled means that people who use your app find notifications for your app irrelevant or noisy." | 不属缺陷，属产品口径 |
| P5 | 存储后被送达 | 从存储送达数 / 存储数 | 同页第 16 行前半句（"Check the number of notifications preserved in APNs storage for offline devices and compare it with the number of push notifications delivered from APNs storage."） | 取整后小样本失真 |
| P6 | 离线堆积 | `Stored - Device Offline` 绝对量 | 同页第 15 行示例句 | 不能推断设备状态（第 16 行隐私条款） |
| P7 | 到期丢弃 | 因过期丢弃 / 存储数 | 同页第 23 行 `The push notification expires.`；TTL 上限见第 31 行（默认 30 天，以先到者为准） | 与用户卸载无法分离 |
| P8 | 4XX 占比与断连 | 4XX / 总请求；连接被结束次数 | 《Handling notification responses from APNs》第 65 行（"An error code beginning with 4XX slows down your ability to send notifications." + "APNs disconnects a provider connection with too many error conditions."） | 断连计数不区分原因，需与 N3/N4 交叉 |
| P9 | 令牌失效率 | 410（`ExpiredToken` / `Unregistered`）/ 总量 | 同页第 56—57 行；第 65 行"status code 410 isn't considered an error condition" | 不计入错误率分母（口径要单独说明） |
| P10 | 功耗延迟 | 因省电推迟的存储量 | Metrics 页第 27 行（"APNs may defer delivery of a notification to conserve battery"） | 与 P6 在指标里同族不同因 |

### 20.1 指标口径的四条使用规则

1. **P9 不进错误率。** 文档明确 410 不算错误条件（第 65 行），把它并入 P8 会同时污染两个指标。脚本二因此在分诊输出里把 410 单列一组（第 22.3 节 `retry_class()` 的 `drop` 类）。
2. **P8 的重试口径来自同一页第 64 行**：5XX 在 15 分钟后可重试、可用退避；"Most notifications with the status code 4XX can be retried after you fix the error noted in the reason field."；且明确列出六个不得重试的串（`BadDeviceToken`、`DeviceTokenNotForTopic`、`Forbidden`、`ExpiredToken`、`Unregistered`、`PayloadTooLarge`）。**这六串横跨 N1、N6、N7 三型**，说明"重试策略"不能按型统一，只能按串配置——脚本二按串给结论。
3. **P2/P3/P5/P6/P10 都依赖同一份聚合报表**，彼此不是独立样本；把它们当独立信号做相关性分析在口径上不成立（同页第 10 行的 "aggregated, rounded"）。
4. **广播信道的指标独立**（第 13.4 节），与设备推送的 P1—P10 不可相加；台账混装时脚本二按 `:path` 前缀分派两套词表。

### 20.2 指标与型的闭合

第 14.3 节标出"只有指标读数"的两格（N8、N9 的一部分）在本章落成 P2/P3/P6/P7/P10；反过来，P1/P8/P9 是型判定的输入而不是型本身。**这套闭合的意义在于：任何一条"用户说没收到"的工单，都能被写成 P1—P10 中若干个数的变化 + 一个型的候选集合，而不是直接进入归因。**
## 21. 只读核验脚本一：请求口径审查器

### 21.1 这个脚本要补的是哪一格缺口

前面十章把请求体拆成首部格与载荷键，第 14 章把它们归成 N1—N12，第 15 章给出「哪一层错了归谁修」。但这三章都停在同一句话上：**读者手上没有一条真实的 APNs 请求**。provider 侧的日志通常只留下 `:status` 与 `reason` 两个读数，请求本身要么在采集前就被丢弃，要么以「我们发过一条推送」这种不可核对的形式存在于工单里。于是第 19 章的四级判定模型在级 2（对齐）就断了：没有请求文本，就没有可对齐的口径。

`apns-request-audit.sh` 补的就是这一格。它接受**读者自己构造或自己导出的请求文本**，按 Apple 文档口径逐格静态审查，并预演这条请求最可能收到的 `reason`。它做的事严格限定在三件：读一份文本、按文档规则判定、打印信号码与解释行。它不做的事同样严格限定：不联网、不连 APNs、不构造任何真实请求、不写设备、不修改输入文件、不解析任何二进制或私有格式。

因此这个脚本的产出既不是"这条推送失败的原因"，也不是"设备端为什么没弹"。它唯一的断言范围是：**如果这条文本被原样发给 APNs，按文档表格它会在哪几格上不符合口径，以及最可能落到 32 个 `reason` 串里的哪一个**。这两句话都只以文档为依据，不以真实响应为依据。

### 21.2 输入形态与它的三种不可用

脚本的输入是一个纯文本文件，形态固定为三段（脚本头注释第 11—14 行写明）：

```text
以 # 开头的行 → 注释，直接忽略
HTTP/2 风格首部块：每行「名称: 值」；:method / :path 这类伪首部按同样规则读
一个空行
JSON 载荷（一行或多行都可以）
```

首部块与载荷之间必须有空行；这个空行同时是脚本判定「首部到此为止」的唯一依据。三种情况会让整条读数被判为不可用（E 类），脚本此时只报 E 类信号码，不给出口径判定：

- 文件不存在、文件不可读、文件为空；
- 整份输入里第一个空行出现在首部块之前（例如首行就是空行后面才是首部），此时首部与载荷无法分离；
- 首部块里所有行都不是「名称: 值」形态，归一后首部表为空。

这三类与口径违规是两种不同的东西：**E 类说的是"这份读数本身不可用"，H/P 类说的是"读数可用且它违反了文档某一格"**。把它们混成一行结论，就是第 24 章 M1 误区。

### 21.3 信号码命名：49 格分五族

脚本一共 49 个信号码位，分五族。命名规则是「族字母 + 两位序号」，E 族末尾另加 90/98/99 三个调用面码位。

| 族 | 格数 | 含义 | 是否带预演 reason |
|---|---|---|---|
| E | 6 + 3 | 读数不可用（文件面 4 格、归一面 2 格、调用面 3 格） | 否 |
| S | 1 | 分隔行，标记一份新输入的起点 | 否 |
| H | 20 | 首部层口径命中（H01—H20） | 大部分是 |
| P | 14 | 载荷层口径命中（P01—P14） | 部分是 |
| D | 5 | 单份输入的计数与判定出口 | 否 |

计数：6 + 3 + 1 + 20 + 14 + 5 = 49。

调用面三个码位单独说明：`E90` 是临时目录不可用（在第 116 行申请四个中间文件之后、第 122 行统一探测，任一不可写即判 E 类）；`E98` 是未提供输入文件（第 321 行）；`E99` 是未知选项（第 315 行）。这三个不属于"文档口径"，属于"脚本自身能否运行"，因此在第 23 章的覆盖验收里被单列成一档。

`E90` 的实现值得说一句，因为它在本轮验收中被实跑推翻过一次：早期版本在 `newtmp()`（第 39 行）里直接 `exit 2`，而该函数是被 `hb=$(newtmp)` 这种命令替换调用的，`exit` 只退出了子 shell，主流程继续带着空路径往下跑，最终给出一份内容全空却判定为"每格都在口径内"的台账。现在的写法是让 `newtmp()` 在失败时返回空串，由调用处统一做一次可写性探测（第 120—124 行），失败就发 `E90` 并把本条读数列进 E 类。这条修正也说明了本系列脚本的一条设计原则：**任何"读不到"的情况都必须走到 E 类出口，不允许退化成"读到空"从而产出乐观判定**。

### 21.4 `__R=` 约定：预演与打印是两件事

H 族与部分 P 格的解释文本末尾带一段 ` __R=BadTopic` 形态的内容。这一段**不会出现在正常输出里**。实现见脚本第 44—54 行的 `emit()`：它先剥掉解释尾部以 ` __R=` 之后的部分再打印，同时把剥下来的 reason 记进本份输入的候选表；到判定格时按"出现最早的那一个"输出为 `TOPREASON`。

这么设计有三个理由：

1. 打印出来的必须是给人读的中文解释，不该混进机器字段；
2. 预演结果需要被判定格使用，但不能伪装成"APNs 真的返回了这个 reason"；
3. 有些格在文档里根本没有对应 reason（H11、H12、H13、H18 与 P03—P14 的多数），它们只能作为提示存在，不能被塞进 reason 表。

因此 `D03` 这一档（"命中项都落在无 reason 的提示格里"）存在的意义就是：**这条输入有口径提示，但按文档它落不进任何 `reason` 串**，读者不能据此猜 APNs 会怎么回。

### 21.5 E 族与 S/D 族逐格

| 码位 | 触发条件 | 解释行要点 | 脚本行号 |
|---|---|---|---|
| E01 | 入参路径不存在 | 直接带上路径 | 106 |
| E02 | 存在但读不到 | 权限或属主问题；第 107 行的 `-r` 测试与第 111 行的真实读取探测两道 | 107、111 |
| E03 | 存在可读但零字节 | 空文件 | 108 |
| E04 | 第一个空行不在首部块之后 | 首部与载荷无法分离 | 116 |
| E05 | 首部块某行不是「名称: 值」 | 该行被丢弃，读数仍可用 | 128 |
| E06 | 归一后没有任何可用首部行 | 整条不可用 | 132 |
| E90 | 中间文件无法创建 | 临时目录不可用，本条进 E 类 | 122 |
| E98 | 未传文件参数 | 打印用法，退出码 9 | 321 |
| E99 | 未知选项 | 打印用法，退出码 9 | 315 |
| S00 | 每份输入开始 | 「=== 审查 <路径> ===」 | 329 |
| D00 | 每份输入结束 | 请求头命中数、载荷命中数 | 332 |
| D01 | 无 H/P 命中且读数可用 | 静态审查范围内未见口径违规 | 336 |
| D02 | 有带 reason 的命中 | 本条最可能的 reason 读数为 X | 338 |
| D03 | 有命中但全部无 reason | 命中项都落在无 reason 的提示格里 | 340 |
| D04 | 本条触发 E 类 | 不给出口径判定 | 334 |

`E05` 与其余 E 格的区别值得强调：它是**逐行降级**（丢掉坏行继续跑，第 128 行），其它 E 格是**整条作废**。所以一份输出里同时出现 `E05` 与 `D02` 是正常的；同时出现 `E04` 与 `D02` 才是脚本 bug。

`E02` 的两道判据也要说明：第 107 行是 `[ ! -r "$f" ]`，第 111 行才是一次真实读取（`sed -n '1,1p'`）。加第二道的原因是本轮验收实测到的：在 Windows/Git Bash 上对文件施加只读拒绝 ACL 之后，`-r` 仍然返回真，脚本会把它误报成 `E04`（读不到任何行 → 误判为"空行位置不对"）。第二道判据把这种平台差异收敛回 `E02`，读者拿到的解释与实际情况一致。

### 21.6 H 族 20 格：每格对应文档哪一句

下表把 20 个首部格与文档口径逐一对齐。「文档依据」列给的是取回记录里的页与行号（本机 `.srcx7/A/` 存档），行号即该 txt 文件的物理行。

| 码位 | 审查的格 | 文档依据（页 第N行） | 预演 reason | 脚本行号 |
|---|---|---|---|---|
| H01 | `:method` 缺失或非 POST | 《Handling notification responses from APNs》第 19 行 | MethodNotAllowed | 140—141 |
| H02 | `:path` 缺失或令牌为空 | 同上 第 42 行 | MissingDeviceToken | 144、147 |
| H03 | `:path` 形态不是 `/3/device/<十六进制>` | 同上 第 18 行 | BadPath | 149 |
| H04 | 令牌长度不在常见 32 / 64 两档 | 同上 第 33 行 | BadDeviceToken | 152 |
| H05 | `apns-topic` 缺失 | 《Sending notification requests to APNs》第 32 行；响应表第 43 行 | MissingTopic | 156 |
| H06 | `apns-push-type` 缺失 | 同上 第 28 行 | InvalidPushType | 159 |
| H07 | `apns-push-type` 不在 12 值内 | 同上 第 44—55 行取值表 | InvalidPushType | 163 |
| H08 | 主题后缀与 push-type 不配对 | 同上 第 32 行 + 各类型的后缀句 | BadTopic | 184、189 |
| H09 | `apns-priority` 不在 10/5/1 | 同上 第 31 行；响应表第 36 行 | BadPriority | 195 |
| H10 | background 配 priority 10 | 同上 第 47 行 | BadPriority | 198 |
| H11 | alert 配 priority 1 | 同上 第 46 行 | 无（提示格） | 201 |
| H12 | location 配 priority 5 | 同上 第 52 行 | 无（提示格） | 204 |
| H13 | mdm 主题口径不可静态核对 | 《Establishing a certificate-based connection to APNs》主题段 | 无（提示格） | 178 |
| H14 | `apns-expiration` 非 UNIX 秒整数 | 《Sending notification requests to APNs》第 30 行；响应表第 34 行 | BadExpirationDate | 208 |
| H15 | `apns-id` 非小写 canonical UUID | 同上 第 29 行；响应表第 35 行 | BadMessageId | 212 |
| H16 | `apns-collapse-id` 超 64 字节 | 同上 第 33 行；响应表第 32 行 | BadCollapseId | 216 |
| H17 | 重复首部名 | 响应表第 39 行 | DuplicateHeaders | 219 |
| H18 | 无 `authorization`（按证书鉴权读） | 《Sending notification requests to APNs》第 27 行 | 无（口径声明） | 222 |
| H19 | `authorization` 非 `bearer <token>` 形态 | 同上 第 27 行；响应表第 50 行 | InvalidProviderToken | 226 |
| H20 | location 类型且无 `authorization` | 同上 第 52 行；响应表第 51 行 | MissingProviderToken | 230 |

三处需要说明的判定细节：

- **H04 不是文档断言，是统计口径。** 文档只说令牌是十六进制串，没有规定长度。脚本第 152 行的判据是"长度不等于 32 或 64 时提示"，解释行写的是"不在文档示例常见的 32 / 64 两档"。这是本脚本唯一一个非文档级判据，因此它预演的 `BadDeviceToken` 只是"最可能"，不是"必然"。
- **H08 有两种形态。** 一种是非专用类型却带后缀（第 177 行），一种是类型与后缀不匹配（第 182 行）。两者的 `reason` 同为 `BadTopic`，但归属不同：前者是开发者的主题拼装规则写错，后者是 push-type 与业务通道对不上——按第 15 章矩阵，前者责任方是 D（App 开发者），后者常常同时落在 C（Provider 代码）与 D。
- **H13 承认自己看不见。** mdm 的主题取自 MDM 推送证书 subject 的 UID 属性，纯文本审查拿不到证书，所以这一格只声明"静态审查无法核对"，不给 reason，也不给结论。这正是第 17 章"不可见格"清单里的一条被写进了脚本。

### 21.7 P 族 14 格：载荷层的口径与授权前置

载荷切片由 `aps_slice()`（脚本第 79—95 行）完成：取载荷里第一个 `"aps"` 键对应对象的花括号片段，字符串内部的花括号不参与计数。这是**近似解析**，不是 JSON 解析器——脚本第 250 行的 `P04` 明确承认："取不到 aps 字典：载荷顶层没有 aps 键或花括号不闭合"。近似解析的代价在 P 族里一律表现为提示而非结论。

| 码位 | 审查的键 | 判据 | 预演 reason | 脚本行号 |
|---|---|---|---|---|
| P01 | 整体 | 载荷为空 | PayloadEmpty | 235 |
| P02 | 整体 | 超过上限（普通 4096 / voip 5120 字节） | PayloadTooLarge | 243 |
| P03 | 整体 | 用到上限的 80% 以上 | 无（容量提示） | 245 |
| P04 | `aps` | 取不到 aps 字典 | 无（解析声明） | 250 |
| P05 | `mutable-content` | 值为 1 但无 `alert` | 无（前置要求提示） | 256 |
| P06 | `alert` 字典 | 字典存在但六个文案键一个都没有 | 无（服务扩展提示） | 262 |
| P07 | `content-available` | 与 `alert`/`badge`/`sound` 并存 | 无（静默语义提示） | 270 |
| P08 | `alert` | 用字符串而非字典 | 无（推荐形态提示） | 276 |
| P09 | `interruption-level` | 不在四值内 | 无（设备侧行为提示） | 282 |
| P10 | `sound.critical` | 值为 1 | 无（entitlement 提示） | 287 |
| P11 | `sound.volume` | 不在 0—1 | 无（取值域提示） | 290 |
| P12 | `relevance-score` | 非数字，或不在 0—1 | 无（取值域提示） | 296—297 |
| P13 | `filter-criteria` | 键存在 | 无（entitlement 提示） | 302 |
| P14 | `aps` 内容 | 出现敏感字段名 | 无（隐私口径提示） | 305 |

P 族与 H 族的结构性差别在这里看得最清楚：**H 族几乎每格都能落进一个 `reason`，P 族几乎每格都落不进**。原因是文档把载荷层的多数规则写成"推荐""需要授权""必须包含时先加密"这类不产生 400 的规范句，而不是"违反即拒绝"的协议句。于是 P 族命中在归因时全部属于第 14 章的 N6/N7/N9/N11 型，而不是 N5 型。

三条与授权直接相关的格子值得单独列出：

- `P10` 的判据来自文档对 critical alert 的 entitlement 要求（`com.apple.developer.usernotifications.critical-alerts`）。脚本命中它时说的不是"这条会被拒"，而是"这一格需要授权，读者应回查 App 的 entitlement 与描述文件"——把 L6 读数拉回 L2 归属。
- `P13` 同理，对应 `com.apple.developer.usernotifications.filtering`。
- `P05` 与 `P06` 是一对：前者是 `mutable-content=1` 缺 `alert`（服务扩展没有可改的文案格），后者是 `alert` 字典在但文案键全空。两者的下游后果相同——第 13 章 L9 里那个三十秒预算的扩展拿不到可改内容——但在请求文本上的位置不同，所以脚本分两格报。

`P02` 的字节上限判定也带一条口径冲突的说明，见第 26 章 U3：文档在不同页对"载荷上限"给的计量对象不一致（有的按整个 JSON，有的按编码后的帧）。脚本第 243 行按**载荷文本自身字节数**与 4096/5120 比较，并在解释里带上 `voip=` 标志位，读者据此知道用的是哪一档。

### 21.8 完整脚本

以下即为 `apns-request-audit.sh` 全文，345 行，与随附文件逐字节一致。它只依赖 `bash`、`awk`、`sed`、`grep`、`cut`、`sort`、`tr`、`mktemp`，不联网、不调用任何推送库。

```bash
#!/bin/bash
# apns-request-audit.sh —— 一条 APNs 请求（HTTP/2 首部 + JSON 载荷）的离线静态审查器
# 只读：只读取入参文本，不写设备、不联网、不修改输入，也不向 APNs 发出任何请求；
#       中间文件只落在系统临时目录，退出前删除。
# 口径来源：Apple 文档《Sending notification requests to APNs》《Generating a remote
#           notification》《Handling notification responses from APNs》《Modifying content in
#           newly delivered notifications》四页的规则表与原句。
#           每条 H / P 命中都附「按该口径 APNs 会回哪个 reason 字符串」，
#           是请求文本的口径预演，不是对任何设备或服务的探测。
#
# 输入形态（一个文本文件 = 一条请求）：
#   前段为请求头，每行「名称: 值」，允许 HTTP/2 伪首部（:method、:path）；
#   一个空行分隔首部与载荷；载荷是 JSON 文本，可跨多行；无载荷时留空或只写一个 -；
#   # 开头的行不计入首部。
#
# 用法：  apns-request-audit.sh [-q] [-h] 文件 [文件...]
# 退出码：0 = 每个输入都取到可用读数；2 = 至少一个输入触发 E 类；9 = 调用形态错误。

set -u
LC_ALL=C
export LC_ALL

QUIET=0
FLAG_E=0
CNT_H=0
CNT_P=0
TOPREASON=""
TMPS=""

usage() {
  printf '%s\n' "用法: $0 [-q] [-h] 文件 [文件...]" \
                "  -q  只打印信号码，不打印解释行" \
                "  -h  打印本帮助"
}

cleanup() { [ -n "$TMPS" ] && rm -f $TMPS; TMPS=""; }
trap cleanup EXIT INT TERM

newtmp() { local t; t=$(mktemp 2>/dev/null) || t=""; [ -n "$t" ] && TMPS="$TMPS $t"; printf '%s\n' "$t"; }

emit_text() {
  if [ "$QUIET" = 1 ]; then printf '%s\n' "$1"; else printf '%s  %s\n' "$1" "$2"; fi
}
emit() { # $1=码位 $2=解释（解释里以「 __R=」结尾的那段只用于取最后一个 reason，不打印）
  case "$1" in
    H*) CNT_H=$((CNT_H + 1)) ;;
    P*) CNT_P=$((CNT_P + 1)) ;;
    E*) FLAG_E=1 ;;
  esac
  case "$2" in
    *"__R="*) TOPREASON="${2##* __R=}"; emit_text "$1" "${2%% __R=*}" ;;
    *) emit_text "$1" "$2" ;;
  esac
}

trim() { printf '%s' "$1" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//'; }

# ---- 首部表：归一为「名称<TAB>值」，保留原始大小写；伪首部取第二个冒号 ----
get_h()   { awk -F'\t' -v k="$2" 'tolower($1)==tolower(k){print substr($0, index($0, "\t") + 1); exit}' "$1"; }
dup_h()   { cut -f1 "$1" 2>/dev/null | tr 'A-Z' 'a-z' | sort | uniq -d | tr '\n' ' '; }

parse_headers() { # $1=原始文件 $2=首部表 $3=拒绝行表
  awk -v hb="$2" -v rj="$3" '
    { sub(/\r$/, "", $0) }
    /^[[:space:]]*$/ { next }
    /^[[:space:]]*#/ { next }
    {
      i = index($0, ":")
      if (substr($0, 1, 1) == ":") i = index(substr($0, 2), ":") + 1
      if (i < 2) { print $0 >> rj; next }
      n = substr($0, 1, i - 1); v = substr($0, i + 1)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", n); gsub(/^[[:space:]]+|[[:space:]]+$/, "", v)
      if (n == "") { print $0 >> rj; next }
      printf "%s\t%s\n", n, v >> hb
    }' "$1"
}

# ---- 载荷切片：取第一个 "aps" 键对应对象的花括号片段（字符串内的花括号不计）----
aps_slice() {
  tr -d '\012\015' < "$1" | awk '
    { buf = $0; p = index(buf, "\"aps\"")
      if (p == 0) exit 1
      rest = substr(buf, p + 5); q = index(rest, "{")
      if (q == 0) exit 1
      s = substr(rest, q); depth = 0; instr = 0; esc = 0; out = ""
      for (i = 1; i <= length(s); i++) {
        c = substr(s, i, 1); out = out c
        if (esc) { esc = 0; continue }
        if (instr) { if (c == "\\") esc = 1; else if (c == "\"") instr = 0; continue }
        if (c == "\"") { instr = 1; continue }
        if (c == "{") depth++
        else if (c == "}") { depth--; if (depth == 0) { print out; exit 0 } }
      }
      exit 1 }'
}
has_key() { printf '%s\n' "$1" | grep -q "\"$2\"[[:space:]]*:"; }
str_of()  { printf '%s\n' "$1" | grep -o "\"$2\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" | head -n 1 | sed 's/.*:[[:space:]]*"//; s/"$//'; }
num_of()  { printf '%s\n' "$1" | grep -o "\"$2\"[[:space:]]*:[[:space:]]*[-0-9][0-9.]*" | head -n 1 | sed 's/.*:[[:space:]]*//; s/[[:space:]]//g'; }

audit_one() { # $1=请求文件；返回 1 = 触发 E 类
  local f="$1" hb rj body blank hdrblk
  local method path token topic ptype prio exps apid coll auth dup clen
  local aps psize limit warn n i
  local PTS="accessory alert background complication controls fileprovider liveactivity location mdm pushtotalk voip widgets"

  [ ! -e "$f" ]  && { emit E01 "文件不存在：$f"; return 1; }
  [ ! -r "$f" ]  && { emit E02 "文件不可读（权限或属主问题）：$f"; return 1; }
  [ ! -s "$f" ]  && { emit E03 "文件为空：$f"; return 1; }
  # 有些平台的 -r 测试对 ACL 拒绝不敏感（Windows/Git Bash 即如此），因此再做一次真实读取。
  if ! sed -n '1,1p' "$f" >/dev/null 2>&1; then
    emit E02 "文件不可读（权限或属主问题）：$f"; return 1
  fi

  blank=$(grep -n '^[[:space:]]*$' "$f" | head -n 1 | cut -d: -f1)
  if [ -z "$blank" ] || [ "$blank" = "1" ]; then
    emit E04 "整份输入里第一个空行不在首部块之后，首部与载荷无法分离：$f"
    return 1
  fi

  hb=$(newtmp); rj=$(newtmp); body=$(newtmp); hdrblk=$(newtmp)
  if ! ( : > "$hb" && : > "$rj" && : > "$body" && : > "$hdrblk" ) 2>/dev/null; then
    emit E90 "临时目录不可用：四个中间文件无法创建，本条读数不可用：$f"
    return 1
  fi
  sed -n "1,$((blank - 1))p" "$f" > "$hdrblk"
  parse_headers "$hdrblk" "$hb" "$rj"
  while IFS= read -r line; do
    emit E05 "首部块里这行不是「名称: 值」形态，已丢弃：$line"
  done < "$rj"
  tail -n +"$((blank + 1))" "$f" | tr -d '\r' > "$body"

  if [ ! -s "$hb" ]; then emit E06 "归一后没有任何可用首部行：$f"; return 1; fi

  method=$(get_h "$hb" ':method'); path=$(get_h "$hb" ':path')
  topic=$(get_h "$hb" 'apns-topic'); ptype=$(get_h "$hb" 'apns-push-type')
  prio=$(get_h "$hb" 'apns-priority'); exps=$(get_h "$hb" 'apns-expiration')
  apid=$(get_h "$hb" 'apns-id'); coll=$(get_h "$hb" 'apns-collapse-id')
  auth=$(get_h "$hb" 'authorization')

  if [ -z "$method" ]; then emit H01 ":method 缺失，APNs 只支持 POST __R=MethodNotAllowed"
  elif [ "$method" != "POST" ]; then emit H01 ":method=$method，不是 POST __R=MethodNotAllowed"; fi

  if [ -z "$path" ]; then
    emit H02 ":path 缺失，设备令牌没有承载处 __R=MissingDeviceToken"
  else
    token=${path##*/}
    [ -z "$token" ] && emit H02 ":path 里的设备令牌为空 __R=MissingDeviceToken"
    printf '%s' "$path" | grep -q '^/3/device/[0-9A-Fa-f]*$' \
      || emit H03 ":path 形态不是 /3/device/<十六进制>：$path __R=BadPath"
    n=${#token}
    if [ "$n" != 0 ] && [ "$n" != 32 ] && [ "$n" != 64 ]; then
      emit H04 "设备令牌长 $n 个字符，不在文档示例常见的 32 / 64 两档 __R=BadDeviceToken"
    fi
  fi

  [ -z "$topic" ] && emit H05 "apns-topic 缺失，该首部在文档表里标为 Required __R=MissingTopic"

  if [ -z "$ptype" ]; then
    emit H06 "apns-push-type 缺失：文档原话是缺失或不匹配时 APNs 可能返回错误、延迟投递或直接丢弃 __R=InvalidPushType"
  else
    i=0
    for warn in $PTS; do [ "$warn" = "$ptype" ] && i=1; done
    [ "$i" = 0 ] && emit H07 "apns-push-type=$ptype 不在文档列出的 12 个取值内 __R=InvalidPushType"
  fi

  if [ -n "$ptype" ] && [ -n "$topic" ]; then
    suffix=""
    case "$ptype" in
      voip) suffix=".voip" ;;
      complication) suffix=".complication" ;;
      fileprovider) suffix=".pushkit.fileprovider" ;;
      location) suffix=".location-query" ;;
      pushtotalk) suffix=".voip-ptt" ;;
      liveactivity) suffix="push-type.liveactivity" ;;
      controls) suffix="push-type.controls" ;;
      accessory) suffix="push-type.accessory" ;;
      widgets) suffix="push-type.widgets" ;;
      mdm) emit H13 "mdm 的主题口径取自 MDM 推送证书 subject 的 UID 属性，静态审查无法核对" ;;
      *) suffix="@" ;;
    esac
    if [ "$suffix" = "@" ]; then
      case "$topic" in
        *.voip|*.pushkit.fileprovider|*.location-query|*.voip-ptt|*push-type.*)
          emit H08 "push-type=$ptype 却带专用后缀主题 $topic：文档要求该类型以 bundle ID 为本体 __R=BadTopic" ;;
      esac
    elif [ -n "$suffix" ]; then
      case "$topic" in
        *"$suffix") : ;;
        *) emit H08 "push-type=$ptype 而 apns-topic=$topic 未以 $suffix 结尾 __R=BadTopic" ;;
      esac
    fi
  fi

  if [ -n "$prio" ]; then
    case "$prio" in 1|5|10) : ;; *) emit H09 "apns-priority=$prio 不在 10 / 5 / 1 三档内 __R=BadPriority" ;; esac
  fi
  if [ "$ptype" = "background" ] && [ "$prio" = "10" ]; then
    emit H10 "background 类型配 priority 10：文档原话是 Using priority 10 is an error __R=BadPriority"
  fi
  if [ "$ptype" = "alert" ] && [ "$prio" = "1" ]; then
    emit H11 "alert 类型配 priority 1：文档要求需立即处理时取 10，否则取 5"
  fi
  if [ "$ptype" = "location" ] && [ "$prio" = "5" ]; then
    emit H12 "location 类型配 priority 5：文档要求需立即响应位置查询时取 10，否则取 5（本条落在允许区间，仅作提示）"
  fi

  if [ -n "$exps" ]; then
    case "$exps" in *[!0-9]*|'') emit H14 "apns-expiration=$exps 不是 UNIX 秒级整数 __R=BadExpirationDate" ;; esac
  fi
  if [ -n "$apid" ]; then
    printf '%s' "$apid" | grep -Eq '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' \
      || emit H15 "apns-id 不是小写 canonical UUID（8-4-4-4-12）：$apid __R=BadMessageId"
  fi
  if [ -n "$coll" ]; then
    clen=$(printf '%s' "$coll" | wc -c | tr -d ' ')
    [ "$clen" -gt 64 ] && emit H16 "apns-collapse-id 长 $clen 字节，超过文档的 64 字节上限 __R=BadCollapseId"
  fi
  dup=$(dup_h "$hb")
  [ -n "$(trim "$dup")" ] && emit H17 "重复首部名：$dup __R=DuplicateHeaders"

  if [ -z "$auth" ]; then
    emit H18 "没有 authorization 首部：本条按证书鉴权读，token 鉴权口径下的 403 类命中无法预演"
  else
    case "$auth" in
      *[Bb][Ee][Aa][Rr][Ee]*[[:space:]]*[A-Za-z0-9._-]*) : ;;
      *) emit H19 "authorization 值不是 bearer <provider_token> 形态 __R=InvalidProviderToken" ;;
    esac
  fi
  if [ "$ptype" = "location" ] && [ -z "$auth" ]; then
    emit H20 "location 类型且无 authorization：文档原话是 The location push type supports only token-based authentication __R=MissingProviderToken"
  fi

  # ---------------- 载荷层 ----------------
  if [ ! -s "$body" ] || [ "$(trim "$(cat "$body")")" = "-" ]; then
    emit P01 "载荷为空 __R=PayloadEmpty"
    return 0
  fi
  psize=$(tr -d '\012' < "$body" | wc -c | tr -d ' ')
  limit=4096
  [ "$ptype" = "voip" ] && limit=5120
  warn=$((limit * 3 / 4))
  if [ "$psize" -gt "$limit" ]; then
    emit P02 "载荷 $psize 字节，超过 $limit 字节上限（voip=$([ "$ptype" = voip ] && echo 1 || echo 0)） __R=PayloadTooLarge"
  elif [ "$psize" -gt "$warn" ]; then
    emit P03 "载荷 $psize 字节，已用掉 $limit 上限的 $((psize * 100 / limit))%"
  fi

  aps=$(aps_slice "$body") || aps=""
  if [ -z "$aps" ]; then
    emit P04 "取不到 aps 字典：载荷顶层没有 aps 键或花括号不闭合，文档 Table 1 的 Apple 定义键全部住在 aps 里"
    return 0
  fi

  if has_key "$aps" 'mutable-content' && [ "$(num_of "$aps" 'mutable-content')" = "1" ]; then
    if ! has_key "$aps" 'alert'; then
      emit P05 "mutable-content=1 却无 alert：文档两条前置要求的第二条没有满足"
    else
      i=0
      for warn in title subtitle body loc-key title-loc-key subtitle-loc-key; do
        has_key "$aps" "$warn" && i=$((i + 1))
      done
      [ "$i" = 0 ] && emit P06 "alert 字典在，但六个文案键一个都没有：服务扩展没有可改的文案格"
    fi
  fi

  if has_key "$aps" 'content-available' && [ "$(num_of "$aps" 'content-available')" = "1" ]; then
    i=0
    for warn in alert badge sound; do has_key "$aps" "$warn" && i=$((i + 1)); done
    if [ "$i" -gt 0 ] && [ "$ptype" != "alert" ]; then
      emit P07 "content-available=1 与 alert / badge / sound 并存（命中 $i 个）：文档要求静默更新载荷不含这三个键，本条会让设备侧把它当可见通知处理"
    fi
  fi

  if has_key "$aps" 'alert'; then
    printf '%s\n' "$aps" | grep -Eq '"alert"[[:space:]]*:[[:space:]]*\{' \
      || emit P08 "alert 用的是字符串而非字典：文档称字典为推荐形态"
  fi

  if has_key "$aps" 'interruption-level'; then
    n=$(str_of "$aps" 'interruption-level')
    case "$n" in passive|active|time-sensitive|critical) : ;; *)
      emit P09 "interruption-level=$n 不在 passive / active / time-sensitive / critical 四值内" ;;
    esac
  fi

  if has_key "$aps" 'sound' && printf '%s\n' "$aps" | grep -Eq '"critical"[[:space:]]*:[[:space:]]*1'; then
    emit P10 "sound 字典里 critical=1：文档口径需要 com.apple.developer.usernotifications.critical-alerts 授权"
    n=$(num_of "$aps" 'volume')
    if [ -n "$n" ]; then
      awk -v v="$n" 'BEGIN{ exit !(v < 0 || v > 1) }' && emit P11 "sound.volume=$n 不在 0（静音）到 1（满音量）区间"
    fi
  fi

  if has_key "$aps" 'relevance-score' && [ "$ptype" != "liveactivity" ]; then
    n=$(num_of "$aps" 'relevance-score')
    case "$n" in ''|*[!0-9.]*) emit P12 "relevance-score 取不到数字" ;; *)
      awk -v v="$n" 'BEGIN{ exit !(v < 0 || v > 1) }' && emit P12 "relevance-score=$n 不在 0 到 1 区间（文档对 Live Activity 才放开任意 Double 值）" ;;
    esac
  fi

  has_key "$aps" 'filter-criteria' && \
    emit P13 "载荷里有 filter-criteria：文档口径需要 com.apple.developer.usernotifications.filtering 授权"

  if printf '%s\n' "$aps" | grep -Eiq '"[A-Za-z]*(token|password|passwd|secret|cardnumber|cvv|ssn|authorization)[A-Za-z]*"[[:space:]]*:'; then
    emit P14 "aps 里出现敏感字段名：文档明确要求不要把客户信息或敏感数据放进载荷，必须包含时先加密"
  fi
  return 0
}

# ---------------- 主流程 ----------------
while getopts ":qh" opt; do
  case "$opt" in
    q) QUIET=1 ;;
    h) usage; exit 0 ;;
    \?) emit_text E99 "未知选项 -$OPTARG" >&2; usage >&2; exit 9 ;;
  esac
done
shift $((OPTIND - 1))

if [ "$#" -lt 1 ]; then
  printf 'E98  未提供输入文件\n' >&2
  usage >&2
  exit 9
fi

bad=0
for f in "$@"; do
  CNT_H=0; CNT_P=0; TOPREASON=""
  emit_text S00 "=== 审查 $f ==="
  usable=1
  audit_one "$f" || { usable=0; bad=1; }
  emit_text D00 "本条计数：请求头命中 $CNT_H 条、载荷命中 $CNT_P 条"
  if [ "$usable" = 0 ]; then
    emit_text D04 "判定：本条读数不可用（见上方 E 类），不给出口径判定"
  elif [ "$CNT_H" = 0 ] && [ "$CNT_P" = 0 ]; then
    emit_text D01 "判定：静态审查范围内未见口径违规"
  elif [ -n "$TOPREASON" ]; then
    emit_text D02 "判定：按文档口径，本条最可能的 reason 读数为 $TOPREASON"
  else
    emit_text D03 "判定：命中项都落在无 reason 的提示格里"
  fi
done

[ "$bad" = 1 ] && exit 2
exit 0
```

### 21.9 三份真实输出

下面三段是本轮环境实跑结果（`bash apns-request-audit.sh <文件>`），逐字未改。

**其一：口径内的一条 alert 请求。**

```text
S00  === 审查 good-alert.req ===
D00  本条计数：请求头命中 0 条、载荷命中 0 条
D01  判定：静态审查范围内未见口径违规
```

输入里带了 `authorization: bearer ...`、`apns-push-type: alert`、无后缀主题、priority 10、合法 UUID、64 字节内的 collapse-id，以及一个含 `title`/`body` 的 alert 字典。这条的作用不是演示"命中"，而是演示**空手而归是合法输出**：`D01` 只说静态审查范围内没发现违规，不说这条一定会送达。

**其二：首部层一次踩中 11 格。**

```text
S00  === 审查 bad-headers.req ===
H01  :method=PUT，不是 POST
H03  :path 形态不是 /3/device/<十六进制>：/3/device/zzzz-not-hex
H04  设备令牌长 12 个字符，不在文档示例常见的 32 / 64 两档
H07  apns-push-type=reminder 不在文档列出的 12 个取值内
H08  push-type=reminder 却带专用后缀主题 com.example.notes.voip：文档要求该类型以 bundle ID 为本体
H09  apns-priority=7 不在 10 / 5 / 1 三档内
H14  apns-expiration=2026-10-30 不是 UNIX 秒级整数
H15  apns-id 不是小写 canonical UUID（8-4-4-4-12）：123E4567-E89B-12D3-A456-426655440000
H16  apns-collapse-id 长 70 字节，超过文档的 64 字节上限
H17  重复首部名：apns-topic 
H18  没有 authorization 首部：本条按证书鉴权读，token 鉴权口径下的 403 类命中无法预演
P07  content-available=1 与 alert / badge / sound 并存（命中 1 个）：文档要求静默更新载荷不含这三个键，本条会让设备侧把它当可见通知处理
D00  本条计数：请求头命中 11 条、载荷命中 1 条
D02  判定：按文档口径，本条最可能的 reason 读数为 DuplicateHeaders
```

这一段是全文最有信息量的一份输出，三处细节要指出来：

1. `H01` 到 `H16` 是**并列**关系而不是因果链。真实情况下 APNs 只会在一个校验点返回一个 `reason`，`D02` 取的是"最早命中的那个"，这里取到 `DuplicateHeaders`；但这绝不意味着其它 10 格不存在——它们同样会让请求失败，只是被前面的格子挡住而看不见。这是第 17 章"读数掩盖"问题在脚本层的再现。
2. `H15` 的命中很典型：UUID 只有大写这一处错，文档口径是小写 canonical 形态（第 21 章 21.6 表指向的《Sending notification requests to APNs》第 29 行）。这类"只差大小写"的缺陷在任何测试面都表现为随机失败，因为有些 SDK 会自己转小写、有些不会。
3. `H18` 与 `H17` 同时出现说明这份读数是证书鉴权下的样本；此时 403 族（H19/H20）本来就无从判定，`H18` 那句"无法预演"就是在给读者划定不可推断区。

**其三：载荷层一次踩中 7 格、全部无 reason。**

```text
S00  === 审查 bad-payload.req ===
P05  mutable-content=1 却无 alert：文档两条前置要求的第二条没有满足
P09  interruption-level=urgent 不在 passive / active / time-sensitive / critical 四值内
P10  sound 字典里 critical=1：文档口径需要 com.apple.developer.usernotifications.critical-alerts 授权
P11  sound.volume=3 不在 0（静音）到 1（满音量）区间
P12  relevance-score=42 不在 0 到 1 区间（文档对 Live Activity 才放开任意 Double 值）
P13  载荷里有 filter-criteria：文档口径需要 com.apple.developer.usernotifications.filtering 授权
P14  aps 里出现敏感字段名：文档明确要求不要把客户信息或敏感数据放进载荷，必须包含时先加密
D00  本条计数：请求头命中 0 条、载荷命中 7 条
D03  判定：命中项都落在无 reason 的提示格里
```

`D03` 与 `D02` 的对比就是这张表的意义：**七格命中，却一格都预演不出 `reason`**。这条输入在真实世界里很可能返回 `200` 并被正常投递——它的缺陷全部落在设备侧行为与隐私口径上，而不是协议校验上。换句话说，如果只看 `reason` 台账（第 22 章那个脚本的输入），这七格完全不存在。这就是为什么两个脚本必须并用，以及为什么第 20 章 P1—P10 里"请求侧口径命中率"与"响应侧失败率"是两个不能互换的指标。

### 21.10 脚本一的可见性边界

这个脚本看不见的内容，与它能看见的内容同样重要：

- 看不见真实 `:status`/`reason`；它的 `D02` 是预演，不是读数。
- 看不见设备令牌与主题的绑定关系（N1 型）。`H04` 只看长度，不看这个令牌是不是本机、本环境、本 topic 的。
- 看不见鉴权令牌的内容与签名（N3 型）。`H19` 只看 `authorization` 的形态是不是 `bearer <...>`，不解析 JWT、不验签。这也是本文不提供任何伪造鉴权令牌实现方法的一环。
- 看不见传输层（N4 型）。HTTP/2 帧、TLS 版本、证书链、GOAWAY 全在脚本视野之外；`H13` 与 `H18` 是这一边界上被明确写进输出的两处声明。
- 看不见设备侧（N9/N11 型）。通知授权状态、专注模式、锁屏隐私设置、服务扩展是否安装、扩展有没有超时，全部不在输入文本里。`P05`/`P06` 只能指出"扩展拿不到可改文案"，不能指出"扩展是否被系统调起"。
- 近似解析可能漏判。嵌套 `aps`、字符串里含 `aps` 键名、非 ASCII 转义都会影响 `aps_slice()`；这类情况脚本用 `P04` 自认失败，而不是给出错误结论。

---

## 22. 只读核验脚本二：响应台账分诊器

### 22.1 分工：一个看请求文本，一个看响应台账

脚本一处理"我发了什么"，脚本二处理"我收到了什么"。它的输入是读者自有的响应台账——自家 provider 日志的脱敏导出、Push Notification Console 投递日志的整理结果，或任一按同样四列形态书写的文本。

与脚本一相比，脚本二的性质不同：**它不预测，它对齐**。每条读数都已经真实发生过，脚本要做的是判断这条读数在不在文档口径内、串与码配不配对、以及按文档重试段该归进哪一档。所有"这一格为什么错"的判断都留给读者，脚本只把"这一格能不能被文档解释"说清楚。

### 22.2 输入形态

台账每行四个空白分隔字段（脚本头注释第 9—12 行）：

```text
〈:status〉〈reason〉〈令牌或 apns-id 前缀〉〈timestamp〉
```

- 后两列可省略；成功行（200）的 reason 用 `-` 占位；
- `#` 开头为注释行，计入排除；
- 状态码不足三位、或以非数字开头的行，计入"不可解释行"并被排除在统计之外（第 104 行 `E04`、第 110 行 `W00`）。

一份空台账是**可用**的：它给出 `D03`「整份台账无失败读数，不构成任何投递问题的证据」，而不是报错。这一点与脚本一相反（脚本一里空文件是 `E03`），差别来自语义：空响应台账是合法事实，空请求文本是无从审查。

### 22.3 30 格命名族

| 族 | 格数 | 含义 | 是否影响退出码 |
|---|---|---|---|
| E | 4 + 3 | 台账不可用（存在性 3 格 + 形态 1 格 + 调用面 3 格） | 是（退出码 2） |
| K | 7 | 口径内读数（已知事实，直接引文档口径） | 否 |
| W | 12 | 口径外或自相矛盾（警告，需回查采集面） | 否 |
| D | 4 | 汇总与判定出口 | 否 |
| 合计 | 30 | — | — |

E 族：`E01` 台账不存在（第 78 行）、`E02` 读不到（第 79 行的 `-r` 测试与第 83 行的真实读取探测两道）、`E03` 为空（第 80 行）、`E04` 没有任何以三位状态码开头的读数行（第 104 行）、`E90` 临时目录不可用（第 88 行）、`E98` 未提供台账（第 209 行）、`E99` 未知选项（第 203 行）。

K 族：`K00` 可用读数计数（第 107 行）、`K01` 5xx 与 15 分钟重试口径（第 116 行）、`K02` 410 与"410 不算 error condition"（第 150 行）、`K03` 不可重试类（第 152 行）、`K04` TooManyRequests 可延迟重试（第 155 行）、`K05` 逐 reason 的表内状态码与重试档（第 163、166 行）、`K06` 失败读数的令牌前缀计数（第 179 行）。

W 族：`W00` 不可解析行被排除（第 110 行）、`W01` 状态码不在十档内（第 119 行）、`W02` 非 200 缺 reason（第 122 行）、`W03` 200 带了 reason（第 125 行）、`W04` reason 不在 32 串内（第 135 行）、`W05` 串码不配对（第 145 行）、`W06` 410 的 timestamp 位数异常（第 140 行）、`W07` 410 缺 timestamp（第 146 行）、`W08` 非 410 带 timestamp（第 147 行）、`W09` TooManyProviderTokenUpdates 与 20 分钟一次（第 157 行）、`W10` BadDeviceToken 与连接断开（第 174 行）、`W11` BadDeviceToken 占比达 5%（第 175 行）。

D 族：`D00` 汇总（第 182 行）、`D01` 每格都在口径内（第 184 行）、`D02` 有格在口径外或自相矛盾（第 186 行）、`D03` 三种结论出口（第 189、191、193 行）。

### 22.4 两张硬编码表：32 串配对与 5 档重试

`reason_status()`（脚本第 46—62 行）把文档《Handling notification responses from APNs》Response error strings 表的 32 串与各自状态码写死。这张表的用途只有一个：**检验台账里 reason 与 :status 是否来自同一次响应**。文档里每个 reason 只挂一个状态码，所以"403 + BadDeviceToken"这种组合不是"另一种更严重的错"，而是**采集面出错**（列错位、跨行合并、或把两条读数粘成一行）。这就是 `W05`。

| 状态码 | 串数 | 该档的 reason（脚本硬编码，顺序同文档表） |
|---|---|---|
| 400 | 14 | BadCollapseId、BadDeviceToken、BadExpirationDate、BadMessageId、BadPriority、BadTopic、DeviceTokenNotForTopic、DuplicateHeaders、IdleTimeout、InvalidPushType、MissingDeviceToken、MissingTopic、PayloadEmpty、TopicDisallowed |
| 403 | 8 | BadCertificate、BadCertificateEnvironment、ExpiredProviderToken、Forbidden、InvalidProviderToken、MissingProviderToken、UnrelatedKeyIdInToken、BadEnvironmentKeyIdInToken |
| 404 | 1 | BadPath |
| 405 | 1 | MethodNotAllowed |
| 410 | 2 | ExpiredToken、Unregistered |
| 413 | 1 | PayloadTooLarge |
| 429 | 2 | TooManyProviderTokenUpdates、TooManyRequests |
| 500 | 1 | InternalServerError |
| 503 | 2 | ServiceUnavailable、Shutdown |

合计 14+8+1+1+2+1+2+1+2 = 32，与文档表 32 串一一对应。注意 410 只有两串，且这两串都不在"错误条件"里——文档重试段明确写着状态码 410 不算 error condition（第 21.6 表所引的《Handling notification responses from APNs》第 65 行）。这条口径直接决定了第 20 章指标 P5 的分母：把 410 计入失败率，等于用一条文档明令不算错误的读数去污染分母。

`retry_class()`（脚本第 64—71 行）把文档重试段翻成五档：

| 档 | 成员 | 文档依据 |
|---|---|---|
| no | BadDeviceToken、DeviceTokenNotForTopic、Forbidden、ExpiredToken、Unregistered、PayloadTooLarge | 《Handling notification responses from APNs》第 64 行："Don’t retry notification responses with the error code BadDeviceToken, DeviceTokenNotForTopic, Forbidden, ExpiredToken, Unregistered, or PayloadTooLarge." |
| delay | TooManyRequests | 同页 第 64 行："You can retry with a delay, if you get the error code TooManyRequests." |
| later | InternalServerError、ServiceUnavailable、Shutdown | 同页 第 64 行："After 15 minutes, you can retry JSON payloads that receive response status codes that begin with 5XX." |
| after-fix | 其余 4xx（按状态码首字符推得） | 同页 第 64 行："Most notifications with the status code 4XX can be retried after you fix the error noted in the reason field." |
| na | 状态码未知（即 `W04` 的口径外串） | 不给档 |

`K05` 每行打印的"重试口径"就是这个字段。它给的是文档规定的动作，不是脚本建议；两者在 `after-fix` 一档尤其容易混淆——文档的措辞是"修好 reason 里那个错之后可以重试"，前提是**先定位错在哪一格**，而这一步是脚本二明确不做的。

### 22.5 完整脚本

以下即为 `apns-ledger-triage.sh` 全文，220 行，与随附文件逐字节一致。同样只依赖 `bash`/`awk`/`sed`/`grep`/`sort`/`uniq`/`head`/`mktemp`；它不重发任何请求，也不改写台账。

```bash
#!/bin/bash
# apns-ledger-triage.sh —— APNs 响应台账的只读分诊器
# 只读：只读取入参文本台账，不写设备、不联网、不修改输入，也不向 APNs 重发任何请求；
#       中间文件只落在系统临时目录，退出前删除。台账本身来自读者自有导出件、
#       Push Notification Console 的投递日志或自家 provider 日志的脱敏结果。
# 口径来源：Apple 文档《Handling notification responses from APNs》的状态码表、
#           Response error strings 表与重试策略段，逐格硬编码在本脚本里。
#
# 输入形态（每个文本文件 = 一份台账）：
#   每行四个空白分隔字段：〈:status〉〈reason〉〈令牌或 apns-id 前缀〉〈timestamp〉；
#   后两列可省略；成功行的 reason 用 - 占位；# 开头为注释行；
#   状态码不足三位或以外字符开头的行计入「不可解释行」并被排除。
#
# 用法：  apns-ledger-triage.sh [-q] [-h] 台账 [台账...]
# 退出码：0 = 台账可用且给出判定；2 = 至少一份台账读数不可用（E 类）；9 = 调用形态错误。

set -u
LC_ALL=C
export LC_ALL

QUIET=0
FLAG_E=0
TMPS=""
TAB=$(printf '\t')

usage() {
  printf '%s\n' "用法: $0 [-q] [-h] 台账 [台账...]" \
                "  -q  只打印信号码，不打印解释行" \
                "  -h  打印本帮助"
}

cleanup() { [ -n "$TMPS" ] && rm -f $TMPS; TMPS=""; }
trap cleanup EXIT INT TERM

newtmp() { local t; t=$(mktemp 2>/dev/null) || t=""; [ -n "$t" ] && TMPS="$TMPS $t"; printf '%s\n' "$t"; }

emit_text() {
  if [ "$QUIET" = 1 ]; then printf '%s\n' "$1"; else printf '%s  %s\n' "$1" "$2"; fi
}
emit() {
  case "$1" in E*) FLAG_E=1 ;; esac
  emit_text "$1" "$2"
}

# ---- 文档口径：Response error strings 表里每个 reason 只挂一个状态码 ----
reason_status() {
  case "$1" in
    BadCollapseId|BadDeviceToken|BadExpirationDate|BadMessageId|BadPriority|BadTopic|\
    DeviceTokenNotForTopic|DuplicateHeaders|IdleTimeout|InvalidPushType|MissingDeviceToken|\
    MissingTopic|PayloadEmpty|TopicDisallowed) printf '400' ;;
    BadCertificate|BadCertificateEnvironment|ExpiredProviderToken|Forbidden|\
    InvalidProviderToken|MissingProviderToken|UnrelatedKeyIdInToken|BadEnvironmentKeyIdInToken) printf '403' ;;
    BadPath) printf '404' ;;
    MethodNotAllowed) printf '405' ;;
    ExpiredToken|Unregistered) printf '410' ;;
    PayloadTooLarge) printf '413' ;;
    TooManyProviderTokenUpdates|TooManyRequests) printf '429' ;;
    InternalServerError) printf '500' ;;
    ServiceUnavailable|Shutdown) printf '503' ;;
    *) printf 'unknown' ;;
  esac
}
# ---- 文档重试段的四类口径 ----
retry_class() { # $1=reason -> no / delay / later / after-fix / na
  case "$1" in
    BadDeviceToken|DeviceTokenNotForTopic|Forbidden|ExpiredToken|Unregistered|PayloadTooLarge) printf 'no' ;;
    TooManyRequests) printf 'delay' ;;
    InternalServerError|ServiceUnavailable|Shutdown) printf 'later' ;;
    *) case "$(reason_status "$1")" in 4*) printf 'after-fix' ;; *) printf 'na' ;; esac ;;
  esac
}

triage_one() { # $1=台账文件；返回 1 = 触发 E 类
  local f="$1" norm rej total st rs tk ts want
  local ok200 err4xx err5xx outside stale nodate extra410 emptyreason badpair hasreason
  local cnt_top mismatch i cls seen

  [ ! -e "$f" ]  && { emit E01 "台账不存在：$f"; return 1; }
  [ ! -r "$f" ]  && { emit E02 "台账不可读（权限或属主问题）：$f"; return 1; }
  [ ! -s "$f" ]  && { emit E03 "台账为空：$f"; return 1; }
  # 有些平台的 -r 测试对 ACL 拒绝不敏感（Windows/Git Bash 即如此），因此再做一次真实读取。
  if ! sed -n '1,1p' "$f" >/dev/null 2>&1; then
    emit E02 "台账不可读（权限或属主问题）：$f"; return 1
  fi

  norm=$(newtmp); rej=$(newtmp)
  if ! ( : > "$norm" && : > "$rej" ) 2>/dev/null; then
    emit E90 "临时目录不可用：两个中间文件无法创建，本份台账不可分诊：$f"
    return 1
  fi
  awk -v rj="$rej" '
    { sub(/\r$/, "", $0) }
    /^[[:space:]]*$/ { next }
    /^[[:space:]]*#/ { next }
    NF < 1 { next }
    {
      st = $1
      rs = (NF >= 2 ? $2 : "-"); tk = (NF >= 3 ? $3 : "-"); ts = (NF >= 4 ? $4 : "-")
      if (st !~ /^[0-9][0-9][0-9]$/) { print $0 > rj; next }
      printf "%s\t%s\t%s\t%s\n", st, rs, tk, ts
    }' "$f" > "$norm"
  total=$(grep -c '' "$norm")
  if [ "$total" = 0 ]; then
    emit E04 "台账里没有任何以三位状态码开头的读数行：$f"
    return 1
  fi
  emit K00 "$f：可用读数 $total 条（注释、空行与非三位状态码行已排除）"
  rejn=$(grep -c '' "$rej")
  if [ "$rejn" -gt 0 ]; then
    emit W00 "另有 $rejn 行状态码格不可解析，已排除在本份统计之外；首个被排除的行是「$(head -n 1 "$rej")」"
  fi

  ok200=$(awk -F'\t' '$1 == "200"' "$norm" | grep -c '')
  err4xx=$(awk -F'\t' 'substr($1, 1, 1) == "4"' "$norm" | grep -c '')
  err5xx=$(awk -F'\t' 'substr($1, 1, 1) == "5"' "$norm" | grep -c '')
  [ "$err5xx" -gt 0 ] && emit K01 "5xx 读数 $err5xx 条：文档段给出「15 分钟后可重试 5XX，可退避」"

  outside=$(awk -F'\t' '$1!="200" && $1!="400" && $1!="403" && $1!="404" && $1!="405" && $1!="410" && $1!="413" && $1!="429" && $1!="500" && $1!="503"' "$norm" | grep -c '')
  [ "$outside" -gt 0 ] && emit W01 "有 $outside 条状态码不在文档的 200 / 400 / 403 / 404 / 405 / 410 / 413 / 429 / 500 / 503 十档内：这些行按本系列口径不可解释"

  emptyreason=$(awk -F'\t' '$1 != "200" && $2 == "-"' "$norm" | grep -c '')
  [ "$emptyreason" -gt 0 ] && emit W02 "有 $emptyreason 条非 200 行缺 reason：文档说失败响应体是含 reason 键的 JSON 字典，缺这一格无法归因"

  hasreason=$(awk -F'\t' '$1 == "200" && $2 != "-"' "$norm" | grep -c '')
  [ "$hasreason" -gt 0 ] && emit W03 "有 $hasreason 条 200 行带了 reason：文档写明成功时响应体为空，这一格自相矛盾，需回查采集脚本"

  # reason 词表命中 + reason 与状态码配对
  nodate=0; extra410=0; badpair=0
  seen=""
  while IFS="$TAB" read -r st rs tk ts; do
    [ "$rs" = "-" ] && continue
    [ "$st" = "200" ] && continue
    want=$(reason_status "$rs")
    if [ "$want" = "unknown" ]; then
      case "$seen" in *"|$rs|"*) : ;; *) seen="$seen|$rs|"; emit W04 "reason=$rs 不在文档 Response error strings 表的 32 个串内：可能是台账截断，也可能是口径外新串" ;; esac
    elif [ "$want" != "$st" ]; then
      badpair=$((badpair + 1))
    fi
    if [ "$st" = "410" ]; then
      case "$ts" in ''|*[!0-9]*) nodate=$((nodate + 1)) ;; *) [ ${#ts} != 13 ] && emit W06 "410 行的 timestamp 是 $ts（${#ts} 位）：文档口径是毫秒级 Epoch，正常为 13 位" ;; esac
    elif [ "$ts" != "-" ]; then
      case "$ts" in ''|*[!0-9]*) : ;; *) extra410=$((extra410 + 1)) ;; esac
    fi
  done < "$norm"
  [ "$badpair" -gt 0 ] && emit W05 "有 $badpair 条 reason 与所在状态码不配对：文档表里每个 reason 只挂一个状态码，串与码必须来自同一次响应"
  [ "$nodate" -gt 0 ] && emit W07 "有 $nodate 条 410 行缺数字 timestamp：文档说该键只在 410 时出现，缺了就没有令牌失效时刻可比"
  [ "$extra410" -gt 0 ] && emit W08 "有 $extra410 条非 410 行带了纯数字 timestamp：与文档「该键只在 410 出现」不符，多为列错位"

  stale=$(awk -F'\t' '$1 == "410"' "$norm" | grep -c '')
  [ "$stale" -gt 0 ] && emit K02 "410 读数 $stale 条：文档口径是令牌对该 topic 已失效，且明确 410 不算 error condition"
  unreg=$(awk -F'\t' '$2 == "Unregistered" || $2 == "ExpiredToken"' "$norm" | grep -c '')
  [ "$unreg" -gt 0 ] && emit K03 "不可重试类（Unregistered / ExpiredToken）$unreg 条：文档原话是同一令牌无需再发，除非应用重新取到设备令牌"

  t2many=$(awk -F'\t' '$2 == "TooManyRequests"' "$norm" | grep -c '')
  [ "$t2many" -gt 0 ] && emit K04 "TooManyRequests $t2many 条：文档口径是同一令牌被连续请求过多，可加延迟重试"
  t2prov=$(awk -F'\t' '$2 == "TooManyProviderTokenUpdates"' "$norm" | grep -c '')
  [ "$t2prov" -gt 0 ] && emit W09 "TooManyProviderTokenUpdates $t2prov 条：文档要求鉴权令牌每 20 分钟内更新不超过一次"

  # 文档口径的重试面分组（至多展示 8 个 reason）
  i=0
  while IFS="$TAB" read -r rs cnt; do
    [ -z "$rs" ] && continue
    i=$((i + 1)); [ "$i" -gt 8 ] && { emit K05 "（其余 reason 从略，本份台账去重后多于 8 类）"; break; }
    cls=$(retry_class "$rs")
    want=$(reason_status "$rs")
    emit K05 "reason $rs x $cnt：表内状态码 $want，重试口径 $cls"
  done <<EOF
$(awk -F'\t' '$2 != "-" { print $2 }' "$norm" | sort | uniq -c | sed 's/^ *//' | awk '{ printf "%s\t%s\n", $2, $1 }')
EOF

  bdt=$(awk -F'\t' '$2 == "BadDeviceToken"' "$norm" | grep -c '')
  if [ "$bdt" -gt 0 ]; then
    i=$((bdt * 100 / total))
    emit W10 "BadDeviceToken $bdt 条（占 $i%）：文档说 APNs 会因过多错误条件断开 provider 连接，且在 BadDeviceToken 这类条件下断开得更快"
    [ "$i" -ge 5 ] && emit W11 "BadDeviceToken 占比 $i% 已达 5%：本份读数以环境错配为主，后续统计应把它单独分栏"
  fi

  cnt_top=$(awk -F'\t' '$2 != "-" && $3 != "-" { print $3 }' "$norm" | sort | uniq -c | sort -rn | head -n 5 | tr '\n' ';' | sed 's/;/ /g')
  [ -n "$cnt_top" ] && emit K06 "带失败 reason 的令牌前缀计数（至多 5 项）：$cnt_top"

  mismatch=$((outside + badpair + emptyreason + hasreason))
  emit D00 "读数汇总：总 $total、200 共 $ok200、4xx 共 $err4xx、5xx 共 $err5xx、410 共 $stale"
  if [ "$mismatch" = 0 ] && [ "$nodate" = 0 ] && [ "$extra410" = 0 ]; then
    emit D01 "判定：本份台账每一格都落在文档口径内，可直接用于归因"
  else
    emit D02 "判定：有 $((mismatch + nodate + extra410)) 格落在文档口径之外或自相矛盾，归因前先回查采集面"
  fi
  if [ "$ok200" = "$total" ]; then
    emit D03 "判定：整份台账无失败读数，不构成任何投递问题的证据"
  elif [ "$err4xx" -gt "$err5xx" ]; then
    emit D03 "判定：失败读数以 4xx 为主（$err4xx 对 $err5xx），问题面在本侧 provider 的请求构造与令牌治理，不在 APNs 可用性"
  else
    emit D03 "判定：失败读数不以 4xx 为主，需按 5xx 择期重试与连接态两段口径继续分诊"
  fi
  return 0
}

# ---------------- 主流程 ----------------
while getopts ":qh" opt; do
  case "$opt" in
    q) QUIET=1 ;;
    h) usage; exit 0 ;;
    \?) emit_text E99 "未知选项 -$OPTARG" >&2; usage >&2; exit 9 ;;
  esac
done
shift $((OPTIND - 1))

if [ "$#" -lt 1 ]; then
  printf 'E98  未提供输入台账\n' >&2
  usage >&2
  exit 9
fi

bad=0
for f in "$@"; do
  triage_one "$f" || bad=1
done

[ "$bad" = 1 ] && exit 2
exit 0
```

### 22.6 三份真实输出

**其一：一份被刻意写坏的台账。**

```text
K00  .x7-fx/bad.ledger：可用读数 9 条（注释、空行与非三位状态码行已排除）
W00  另有 1 行状态码格不可解析，已排除在本份统计之外；首个被排除的行是「http-429	tokG7」
W01  有 1 条状态码不在文档的 200 / 400 / 403 / 404 / 405 / 410 / 413 / 429 / 500 / 503 十档内：这些行按本系列口径不可解释
K01  5xx 读数 1 条：文档段给出「15 分钟后可重试 5XX，可退避」
W03  有 1 条 200 行带了 reason：文档写明成功时响应体为空，这一格自相矛盾，需回查采集脚本
W04  reason=NotARealReason 不在文档 Response error strings 表的 32 个串内：可能是台账截断，也可能是口径外新串
W05  有 4 条 reason 与所在状态码不配对：文档表里每个 reason 只挂一个状态码，串与码必须来自同一次响应
W07  有 1 条 410 行缺数字 timestamp：文档说该键只在 410 时出现，缺了就没有令牌失效时刻可比
W08  有 1 条非 410 行带了纯数字 timestamp：与文档「该键只在 410 出现」不符，多为列错位
K02  410 读数 1 条：文档口径是令牌对该 topic 已失效，且明确 410 不算 error condition
K03  不可重试类（Unregistered / ExpiredToken）1 条：文档原话是同一令牌无需再发，除非应用重新取到设备令牌
K04  TooManyRequests 1 条：文档口径是同一令牌被连续请求过多，可加延迟重试
K05  reason BadCollapseId x 1：表内状态码 400，重试口径 after-fix
K05  reason BadDeviceToken x 1：表内状态码 400，重试口径 no
K05  reason ExpiredToken x 1：表内状态码 410，重试口径 no
K05  reason NotARealReason x 1：表内状态码 unknown，重试口径 na
K05  reason PayloadTooLarge x 2：表内状态码 413，重试口径 no
K05  reason Shutdown x 1：表内状态码 503，重试口径 later
K05  reason TooManyRequests x 1：表内状态码 429，重试口径 delay
W10  BadDeviceToken 1 条（占 11%）：文档说 APNs 会因过多错误条件断开 provider 连接，且在 BadDeviceToken 这类条件下断开得更快
W11  BadDeviceToken 占比 11% 已达 5%：本份读数以环境错配为主，后续统计应把它单独分栏
K06  带失败 reason 的令牌前缀计数（至多 5 项）：      2 tokH8       1 tokF6       1 tokE5       1 tokD4       1 tokC3 
D00  读数汇总：总 9、200 共 2、4xx 共 5、5xx 共 1、410 共 1
D02  判定：有 8 格落在文档口径之外或自相矛盾，归因前先回查采集面
D03  判定：失败读数以 4xx 为主（5 对 1），问题面在本侧 provider 的请求构造与令牌治理，不在 APNs 可用性
```

逐格读：`W00` 与 `W01` 是两种不同的"不可解释"——前者连状态码字段都没解析出来（`http-429` 这种带前缀的采集写法），后者解析出来了但值不在十档内（`999`）。两者都要处理，但只有后者会被计入 `D00` 的分母之外且仍然出现在台账里，所以 `W01` 的严重度高于 `W00`。

`W05` 命中 4 条是本份台账最有价值的一格：403+BadDeviceToken、500+Shutdown、200+BadCollapseId、400+PayloadTooLarge。这四行**单看每一行都"合理"**，但都不符合文档表。把它们读成"APNs 返回了意外的组合"是把采集面的 bug 归因给了服务端。脚本在这里给的是 `D02`（先回查采集面），不是任何缺陷类型判断。

`K06` 里 `tokH8` 出现两次——同一令牌同时以 400 和 413 被记录，这正是 `W05` 之外另一种列错位特征。这个格子是给人做样本级复查用的，脚本不给结论。

**其二：410 时间戳位数异常。**

```text
K00  .x7-fx/ts410.ledger：可用读数 3 条（注释、空行与非三位状态码行已排除）
W02  有 1 条非 200 行缺 reason：文档说失败响应体是含 reason 键的 JSON 字典，缺这一格无法归因
W06  410 行的 timestamp 是 1764000（7 位）：文档口径是毫秒级 Epoch，正常为 13 位
K02  410 读数 1 条：文档口径是令牌对该 topic 已失效，且明确 410 不算 error condition
K03  不可重试类（Unregistered / ExpiredToken）1 条：文档原话是同一令牌无需再发，除非应用重新取到设备令牌
K05  reason Unregistered x 1：表内状态码 410，重试口径 no
K06  带失败 reason 的令牌前缀计数（至多 5 项）：      1 tokZ9 
D00  读数汇总：总 3、200 共 1、4xx 共 2、5xx 共 0、410 共 1
D02  判定：有 1 格落在文档口径之外或自相矛盾，归因前先回查采集面
D03  判定：失败读数以 4xx 为主（2 对 0），问题面在本侧 provider 的请求构造与令牌治理，不在 APNs 可用性
```

`W06` 看着像吹毛求疵，实际是这条链路上少见的可核对量：410 的 timestamp 是"APNs 确认该令牌对该 topic 不再有效"的时刻（《Handling notification responses from APNs》第 29 行）。它是**唯一一格带服务端权威时刻的读数**。如果它被采集成 7 位（秒级而非毫秒级），那么第 20 章 P6 指标——"令牌失效时刻与注册时刻之差"——整列作废。脚本为这一格单独设码位，就是因为它的失效方式是静默的：410 仍然计数、重试口径仍然正确、只有时间维度上的推论全部失真。

**其三：全是 5xx 的台账。**

```text
K00  .x7-fx/fivexx.ledger：可用读数 3 条（注释、空行与非三位状态码行已排除）
K01  5xx 读数 2 条：文档段给出「15 分钟后可重试 5XX，可退避」
K05  reason InternalServerError x 1：表内状态码 500，重试口径 later
K05  reason Shutdown x 1：表内状态码 503，重试口径 later
D00  读数汇总：总 3、200 共 1、4xx 共 0、5xx 共 2、410 共 0
D01  判定：本份台账每一格都落在文档口径内，可直接用于归因
D03  判定：失败读数不以 4xx 为主，需按 5xx 择期重试与连接态两段口径继续分诊
```

这份是 `D01` 与 `D03` 的第二种出口。值得注意的是：`D01`（每一格都在口径内）与"这条链路上没有缺陷"是两件事——一份 100% 由 5xx 组成的台账说明问题面在 APNs 可用性或连接治理，按第 15 章矩阵责任方是 B（Apple 服务）；但**同一个请求文本如果本身就有 H 族违规，两个读数会同时存在**，脚本二看不见请求，所以它给不出这个结论。这正是第 24 章 M7 误区的来源。

### 22.7 脚本二的可见性边界

- 看不见请求。台账只有结果，没有产生结果的那条请求；同一条 `BadTopic` 可能来自主题拼错、也可能来自 push-type 选错，脚本二无法区分。这就是两个脚本必须串起来用的原因：**先跑脚本一，把静态口径违规清干净；再跑脚本二，把剩余读数当作真实服务端行为来读**。
- 看不见时间对齐。台账里的 timestamp 只有 410 一格是服务端权威时刻，其余时刻若由本地采集产生，就带采集机时钟偏差；脚本不做任何跨行时间推论。
- 看不见投递结果。`:status` 为 200 只表示 APNs 接受了请求，不表示设备收到、更不表示用户看到。文档里这一格从来没有被写成投递确认，本文也不把它当确认。
- 看不见连接面。GOAWAY、流控窗口、连接被断开这些事件在响应台账里没有对应列；文档只在两处间接提到（错误码可能出现在 GOAWAY 帧里、以及错误条件过多会断开连接），脚本二只能以 `W10` 的形态给出提示，不能给出连接诊断。
- 分诊不是归因。`D03` 的三句话里，"问题面在本侧 provider"是按文档状态码族做的责任面划分（4xx → 请求构造与令牌治理），不是按第 14 章 N 型做的缺陷定位。把 `D03` 直接写成根因，属于第 19 章级 4 的越界。
## 23. 两个脚本的全量分支覆盖验收

### 23.1 验收目标写清楚：覆盖分支，不覆盖正确性

这一章只做一件事：证明第 21、22 章里那张信号码表**不是纸面清单**。每个码位都要在本轮环境里被真实触发一次，输出要留档，退出码要核对。

同时把验收的边界写在前面：**分支覆盖不等于判定正确**。触发到 `H17` 只说明"重复首部名这一格在样例输入下会走到"，不说明"APNs 真的会在这种情况下返回 `DuplicateHeaders`"——后者本文无法验证，也明确不主张。所以本章的结论形态是"79 格全部可达、输出与表内解释一致"，不是"79 格判定与真实服务端行为一致"。

第三条边界：验收用的夹具（fixture）全部是**人工构造的文本**，不含任何真实设备令牌、真实鉴权令牌或真实主题。台账里的令牌列写成 `tokA1`、`tokH8` 这种占位前缀；鉴权令牌列写成 `eyABCD1234.<占位>.<占位>` 形态，只满足"看起来像 bearer 值"的形态判据。这既是隐私口径（本文不复现任何一条真实请求），也是第 2.2 节自审清单里"输入不来自他人设备"这条的执行。

### 23.2 覆盖结果

| 脚本 | 信号码位 | 本轮触发 | 未触发 | 触发率 |
|---|---|---|---|---|
| 脚本一 `apns-request-audit.sh` | 49 | 49 | 0 | 100% |
| 脚本二 `apns-ledger-triage.sh` | 30 | 30 | 0 | 100% |
| 合计 | 79 | 79 | 0 | 100% |

运行环境：Windows 10 (18363) 上的 Git Bash，`bash` 4.4，`LC_ALL=C`（脚本一第 20—21 行、脚本二第 18—19 行自行设定，不依赖调用者环境）。执行方式为 `bash <脚本> <输入>`，脚本自身不联网。

按族核对：

| 族 | 码位 | 全部触发 |
|---|---|---|
| 脚本一 E | E01 E02 E03 E04 E05 E06 E90 E98 E99 | 是（E02 与 E90 需特殊构造，见 23.4） |
| 脚本一 S | S00 | 是 |
| 脚本一 H | H01—H20 | 是 |
| 脚本一 P | P01—P14 | 是 |
| 脚本一 D | D00—D04 | 是（五种判定出口全部出现过） |
| 脚本二 E | E01 E02 E03 E04 E90 E98 E99 | 是（同上） |
| 脚本二 K | K00—K06 | 是 |
| 脚本二 W | W00—W11 | 是 |
| 脚本二 D | D00—D03（其中 D03 三个出口） | 是 |

值得单独指出的是 `D` 族的完整性：脚本一 D01/D02/D03/D04 四个互斥出口都出现过，脚本二 D01/D02 与 D03 的三句话也都出现过。一个只跑通"有命中"路径的验收会让 `D01`（无违规）和 `D04`（读数不可用）成为无人走过的分支，而这两格恰恰是最容易被读错的两格。

### 23.3 夹具清单与码位对应

两张表的"专门触发的码位"列只列该夹具被设计用来踩中的格子。每份输入都会出现的通用格（脚本一的 `S00`、`D00`，脚本二的 `K00`、`D00`）、按判据必然连带的提示格（例如未带 `authorization` 时的 `H18`）以及互斥判定出口的其它格（例如 `good.ledger` 同时给出 `D01` 与 `D03` 的"无失败读数"出口）不逐一列出——它们由覆盖表按"该码位首次出现在哪一段"归到对应夹具，逐格对应关系按同一方法可复现。

脚本一（15 份 `.req` 文本 + 4 次调用面运行）：

| 夹具 | 构造目的 | 专门触发的码位 |
|---|---|---|
| `good-alert.req` | 全部口径内 | S00、D00、D01 |
| `no-topic.req` | 缺 topic 与缺 push-type | H05、H06、D02 |
| `bad-headers.req` | 首部层逐格写错 | H01、H03、H04、H07、H08、H09、H14、H15、H16、H17、H18、P07 |
| `bad-payload.req` | 载荷层逐格写错 | P05、P09、P10、P11、P12、P13、P14、D03 |
| `misc-1.req` | background+priority10、非 bearer 鉴权、alert 字典无文案 | H10、H19、P06 |
| `misc-2.req` | location 类型的两格规则 | H12、H20 |
| `misc-3.req` | alert 配 priority 1 | H11 |
| `misc-4.req` | mdm 主题与 aps 缺失 | H13、P04 |
| `oversize.req` | 载荷超上限 | P02 |
| `voip-ok.req` | VoIP 5 KB 档、接近上限 | P03 |
| `empty-dash.req` | 载荷只有 `aps` 空壳 | P01 |
| `bad-header-line.req` | 首部行形态错误 + `:path` 缺失 + alert 字符串 | E05、H02、P08 |
| `no-blank.req` | 首行即空行 | E04、D04 |
| `no-headers.req` | 归一后无可用首部 | E06 |
| `empty.req` | 零字节 | E03 |
| `nope.req`（不存在） | 路径不存在 | E01 |
| `-h` / 无参数 / `-x` | 调用面 | 用法打印、E98、E99 |
| 只读拒绝 ACL 的临时件 | 真实不可读 | E02 |
| `TMPDIR=/nonexistent-dir-xyz` | 临时目录不可用 | E90 |

脚本二（8 份 `.ledger` 台账 + 4 次调用面运行）：

| 夹具 | 构造目的 | 专门触发的码位 |
|---|---|---|
| `good.ledger` | 每格都在口径内 | K00—K06、D00、D01 |
| `all200.ledger` | 全是成功行 | K00、D03（"无失败读数"出口） |
| `bad.ledger` | 串码不配对、口径外状态码、口径外串、200 带 reason、410 缺 timestamp、非 410 带 timestamp、不可解析行 | W00、W01、W03、W04、W05、W07、W08、W10、W11、D02 |
| `ts410.ledger` | 非 200 缺 reason、410 timestamp 位数异常 | W02、W06 |
| `many.ledger` | TooManyProviderTokenUpdates | W09 |
| `fivexx.ledger` | 5xx 为主的出口 | K01、D03（"不以 4xx 为主"出口） |
| `comments.ledger` | 只有注释与空行 | E04 |
| `empty.ledger` | 零字节 | E03 |
| `nope.ledger`（不存在） | 路径不存在 | E01 |
| `-h` / 无参数 / `-x` | 调用面 | 用法打印、E98、E99 |
| 只读拒绝 ACL 的临时件 | 真实不可读 | E02 |
| `TMPDIR=/nonexistent-dir-xyz` | 临时目录不可用 | E90 |

这份表里 `bad.ledger` 一份就覆盖 10 个码位，不是省事，而是**这些码位描述的是同一种病**：采集面把不同响应粘成一行、列错位、或把成功行写成带 reason。一份刻意混写的台账比九份单错台账更能证明分诊器的判据是彼此独立的——否则任何一个聚合计数器都能一次性"覆盖"它们。

### 23.4 两个需要特殊构造的分支

这两个分支在"随便给个坏文件"的验收里永远走不到，但它们对应的恰是运营里最容易出事的两种环境。

**其一：`E90` 临时目录不可用。** 两个脚本都把中间文件放在系统临时目录，并声明不落盘到输入目录。构造方式是把 `TMPDIR` 指向一个不存在的目录：

```bash
TMPDIR=/nonexistent-dir-xyz bash apns-request-audit.sh good-alert.req
# S00 → E90 → D00 → D04，退出码 2
TMPDIR=/nonexistent-dir-xyz bash apns-ledger-triage.sh good.ledger
# E90，退出码 2
```

容器里 `/tmp` 被挂成只读、`TMPDIR` 指向尚未就绪的卷、或者 CI 环境把临时目录设成不存在的清理路径，都会走到这里。它是"环境坏了"而不是"读数坏了"，但两者在输出上必须同形（都进 E 类），否则读者会把环境问题读成口径问题。

**其二：`E02` 文件存在但读不到。** 这一格在 Windows 上不好构造，原因是 `bash` 的 `-r` 测试走的是 stat 权限位启发式，对 ACL 拒绝不敏感。本轮用 ACL 显式拒绝当前账户读取来构造，并只作用于一个刚创建的临时件，验证完立刻恢复权限、删掉目录：

```bash
T=$(mktemp -d)
printf ':method: POST\napns-topic: com.example.notes\n\n{"aps":{"alert":"x"}}' > "$T/nr.req"
cmd //c icacls "$(cygpath -w "$T/nr.req")" //deny '<域>\<账户>:(R)'
bash apns-request-audit.sh "$T/nr.req"; echo $?          # E02 → D04，退出码 2
cmd //c icacls "$(cygpath -w "$T/nr.req")" //remove:d '<域>\<账户>'
rm -rf "$T"
```

在 Linux 或 macOS 上，用非 root 账户执行更简单：`chmod 000 "$T/nr.req"` 即可让 `[ ! -r ]` 直接为真；root 身份下这两条都不成立（root 可绕过权限位），这也是"用管理员账户跑验收"会漏掉这一格的根本原因。

**验收夹具的写入边界**：上面两段命令确实做了 ACL 变更与删除，但作用对象**仅是该次验收当场创建的临时文件**，路径由 `mktemp -d` 决定、结束时 `rm -rf` 收回，且执行前不读取任何既有文件。第 21、22 章发布的两个脚本本身不做任何权限变更、不删除任何不属于它们的文件——这段差异要在验收记录里写明，否则"验收脚本能改 ACL"会被误读成"报告脚本能改 ACL"。

### 23.5 覆盖验收暴露的两个真实缺陷

分支覆盖的价值不在于给出一个 100%，而在于它推翻过东西。本轮它推翻了两处。

**缺陷一：`E90` 的 `exit` 退错了 shell。** 两个脚本原先都写成：

```bash
newtmp() { local t; t=$(mktemp) || { printf 'E90  临时目录不可用\n' >&2; exit 2; }; ... }
```

而调用处是 `hb=$(newtmp)` 这种命令替换——它运行在子 shell 里，`exit 2` 只结束子 shell。主流程于是拿到一个空字符串当作临时文件路径，继续往下跑。实测后果分两种，都不是好事：

- 脚本一：后续所有 `get_h` 读空，走到 `E06`，最后 `D04`。结论仍然保守，但解释行指向"归一后没有可用首部行"，与真实原因（临时目录不可用）不符。
- 脚本二：`awk` 输出落进无效路径、`grep -c ''` 失败得到空串，于是 `K00` 打印出"可用读数  条"、`D00` 打印"总 "，而 `D01` 照样输出**"本份台账每一格都落在文档口径内，可直接用于归因"，退出码 0**。

第二条是本文最不愿发布的一种输出：**在完全读不到数据的情况下给出乐观判定**。这不是理论风险——把 `TMPDIR` 设错、容器只读挂载，都是常态。

修法：让 `newtmp()` 失败时返回空串而不退进程，由调用处统一做一次可写性探测，探测不过就发 `E90` 并走 E 类出口（脚本一第 120—124 行、脚本二第 86—90 行）。这条修法背后的设计原则值得单独写一句：**"读不到"与"读到空"必须是两种码位**；只要允许"读到空"继续走到判定格，任何环境故障都可能伪装成健康。

**缺陷二：`-r` 测试在 Windows 上说不，读取却失败。** 加了第一版 `E02` 判据之后，23.4 那个 ACL 实验仍然没触发 `E02`：`[ ! -r "$f" ]` 为假（bash 认为可读），而实际 `grep`/`sed` 读该文件被系统拒绝，脚本把结果解释成 `E04`「第一个空行不在首部块之后」。这是一次**诊断错位**：真实原因是权限，报出来的是形态。

修法：在 `-r` 之后追加一次真实读取探测（脚本一第 111 行、脚本二第 83 行，`sed -n '1,1p' "$f"`，失败即 `E02`）。这也是第 21.5 节 `E02` 那行写"两道判据"的原因。

两个缺陷的共同点：**都不是判定逻辑错，是失败路径错**。前者把故障伪装成健康，后者把故障伪装成另一种故障。对一份以"停在能证实的层次"为口径的报告来说，这类错误比少识别一个口径违规严重得多——它会让读者把脚本的沉默当成系统的清白。

### 23.6 发布件与实跑件的一致性核对

报告里内嵌的是脚本全文，而实跑的是仓库里那两个独立文件。两者必须逐字节相同，否则第 21.9、22.6 节的输出样例就与读者手上的脚本无关。核对方法（本轮实际执行）：

1. 在装配后的报告里定位两个 ` ```bash ` 围栏的行号范围；
2. 用 `sed -n '<a>,<b>p'` 从报告抽出围栏内容，写入临时文件；
3. `bash -n` 语法检查；
4. `cmp` 与 `.x7-s1.sh`、`.x7-s2.sh` 逐字节比较；
5. 用抽出来的那份（而非原文件）重跑 23.3 的全套夹具，确认码位集合不变。

| 项 | 脚本一 | 脚本二 |
|---|---|---|
| 报告内围栏行范围 | 第 1390—1734 行 | 第 1882—2101 行 |
| 抽出行数 | 345 行 | 220 行 |
| `bash -n` | 通过 | 通过 |
| `cmp` 与独立文件 | 与 `apns-request-audit.sh` 字节一致 | 与 `apns-ledger-triage.sh` 字节一致 |
| 抽取件重跑后的码位集合 | 49/49 | 30/30 |

第 5 步是最容易被跳过、也最能抓错的一步：围栏里如果少一个反斜杠、被编辑器折了一行、或者行尾多了 `CR`，第 4 步的 `cmp` 会发现；但如果有人在独立文件里改了判据而没同步围栏，只有第 5 步（用抽取件重跑）能暴露判定漂移。

### 23.7 验收没有覆盖的内容

- 未与真实 APNs 对照。本文不发送任何请求，因此"D02 预演的 reason"与真实响应的一致性**未被验证**，也不可被验证——除非读者用自己的 provider 凭证向自己的测试设备发一条，那是读者的动作，不在本文范围。
- 未覆盖 iOS 版本差异。第 8.4 节记录的"较新推送类型对旧版本设备的行为"没有公开口径，脚本也无从判断。
- 未做多语言与转义压力。载荷样例只覆盖 ASCII 与少量中文，未测试 Unicode 转义、代理对、超长字符串对近似解析（`aps_slice()`）的影响；这一项在 21.10 已标为已知限制。
- 未覆盖广播/信道侧的 28 个 `reason` 串。脚本二的表用的是设备侧 32 串；广播请求的响应台账需要另一套表（第 10 章），本轮未实现，也明确不在"已覆盖"里声称。

---

## 24. 十二个误区

每条都写成"错误说法 / 为什么错 / 正确的读法"三行，且都能在前面某一章找到落点。这一章不是提醒，是复核清单。

**M1 把 E 类当成"通过审查"。**
错误说法："脚本只报了 E05，没有口径违规。"
为什么错：`E05` 是逐行降级（丢掉坏行继续跑），但 `E01—E04`、`E06`、`E90` 是整条作废；作废时脚本仍然会打印 `D00` 计数行，扫读时很容易被当成正常输出。
正确读法：只看 `D` 族出口。`D04` 出现即本条不产生任何口径判定；`D01` 只有在没有 E 类时才存在（脚本一第 334—340 行的分支互斥性保证这一点）。

**M2 把 `D02` 预演的 reason 当成真实响应。**
错误说法："脚本说是 `BadTopic`，APNs 就是返回了 `BadTopic`。"
为什么错：`D02` 是静态审查产物，与真实响应无关（第 21.4 节）。真实情况下 APNs 只在一个校验点返回一个 reason，而一条请求可能同时有 11 格违规（见 21.9 其二）。
正确读法：`D02` 是"最可能的读数控格"，用来决定回查哪一格；台账里真实出现过的 reason 只属于脚本二的输入。

**M3 用 `reason` 表覆盖载荷口径。**
错误说法："载荷里 `interruption-level` 写错了，所以台账里该有个对应 reason。"
为什么错：32 串表里没有这一格——文档把载荷内容规则写成推荐句和授权句，不产生 400（第 21.7 节）。`D03`（"命中项都落在无 reason 的提示格里"）存在的意义就是防止读者去表里硬找。
正确读法：P 族命中归 N6/N7/N9/N11 型，不归 N5 型；它的证据面在设备侧，不在响应台账。

**M4 把公告组件名当成层级。**
错误说法："公告写 `Notifications`，所以这是设备端派发层（L8）的问题。"
为什么错：第 16 章统计的七种组件标签（Accessibility、Status Bar、VoiceOver、Libnotify、Share Sheet、Notifications、Notification Services）描述的是同一条链路的不同切面，标签与层之间没有函数关系（第 3.2、16.9 节）。
正确读法：组件名只用于定位公告条目；层归属要靠 `Description:` 里那句被修的东西（如"通知中心里的旧通知未被移除"→ L7/L8；"锁屏可见正文"→ L8/L9 的呈现与授权面）。

**M5 把"锁屏上看到通知正文"一律当成泄露。**
错误说法："锁屏能看到内容，说明通知泄露。"
为什么错：文档口径里这件事由两格独立决定——通知授权与锁屏隐私展示设置（第 11 章）。`Status Bar` / `VoiceOver` 标签的公告条目里，"谁能在锁屏看到什么"是用户设置的直接后果。
正确读法：先分"这条读数是否越过了用户自己设置的边界"。越过了才是缺陷；没越过而只是不喜欢，是设置问题（归 E 类责任方，第 15.2 矩阵）。

**M6 把 L7 读数写成"待 Apple 修复"。**
错误说法："通知被合并、被延迟、根本没到，这是 Apple 服务端的问题，等修复。"
为什么错：这是本文最需要挡住的一类误归。文档把 APNs 的存储与投递写成 best-effort，且明确"同一 device token + 同一 bundle ID 的在库通知可以被覆盖"、"默认按功耗考虑推迟"（第 4、7、10 章）。这些不是待修缺陷，是公开的服务语义。按第 15.2 矩阵，L7 的多数读数是"无需修复"，可执行动作在 provider 侧：`apns-collapse-id` 是否唯一、`apns-expiration` 是否设得合理、priority 是否为功耗让路。
正确读法：L7 上写"等 Apple 修"之前，先回答三个问题——这条读数能否落到一个 `reason`？同一 bundle ID 是否有多条在库？设置 priority 时是否考虑了设备功耗？三问都排除后，才谈得上第 14 章 N8 型的缺陷归属。

**M7 把脚本二的 `D01` 读成"这条链路没有缺陷"。**
错误说法："台账分诊结果是每一格都在口径内，说明推送没问题。"
为什么错：`D01` 断言的是**这份台账的每一格都可被文档解释**。它不知道请求长什么样（P 族七格完全不出现在台账里，见 21.9 其三），也不知道设备有没有弹。22.6 其三那份全 5xx 台账就是反例：`D01` 与"链路有问题"同时成立。
正确读法：`D01` 是级 2（对齐）通过，不是级 4（归因）通过；两个脚本必须按"先一后二"的顺序并用。

**M8 把 410 计入失败率。**
错误说法："本月失败率 3.2%，其中大部分是 410。"
为什么错：文档重试段明写 "status code 410 isn’t considered an error condition"（《Handling notification responses from APNs》第 65 行），且 `Unregistered` 的含义是"这个令牌本就不该再发"。把 410 计入分母会同时污染两个指标（第 20 章 P5）。
正确读法：410 单独成栏，作为令牌治理的输入（对应 N1 型），不作为投递失败证据。

**M9 把 `:status` 200 当投递确认。**
错误说法："200 就说明用户收到了。"
为什么错：200 的文档语义是 APNs 接受了这次 POST 请求；接受之后的存储、推迟、合并、丢弃全部在另一套口径里（第 7 章）。`all200.ledger` 那份台账只证明"没有请求面错误"。
正确读法：把"接受率"与"呈现率"分成两个指标（P1 与 P7），后者只能由读者自有设备侧读数或自家应用日志给出，且受 17.2 三格限制。

**M10 把 `BadDeviceToken` 当纯格式问题。**
错误说法："令牌不合法，肯定是拼错了，检查一下字符串就行。"
为什么错：文档该串的原文同时包含两件事——令牌本身无效，以及"令牌与环境的匹配"（"Verify that the request contains a valid token and that the token matches the environment"，《Handling notification responses from APNs》第 33 行）。开发/生产环境错配是常态来源（第 4 章），且第 22.6 其一里那条 `403 + BadDeviceToken` 恰好提醒：这个串只属于 400。
正确读法：`BadDeviceToken` 排查顺序为——环境（证书环境或令牌签发环境）→ 令牌与 topic 绑定 → 字符串本身。反过来只会让占比一直压在 5% 以上（`W11` 那一档）。

**M11 用聚合指标做单条归因。**
错误说法："控制台显示这一小时 Discarded 占比 40%，所以这条通知是被丢弃的。"
为什么错：聚合指标按小时聚合且四舍五入，且 APNs 不追踪离线设备状态（第 5、6 章）。它回答"这一批"，不回答"这一条"。
正确读法：单条归因只能走投递日志，而投递日志有开发环境、按 bundle ID、7 天、需自取四重限制（第 17.1 节）。用聚合数据解释个案，就是把级 3 的读数当级 4 的证据。

**M12 把崩溃符号名当层归属。**
错误说法："崩溃栈里有 `NotificationService`，所以缺陷在 L9 扩展层。"
为什么错：第 18.4 节记录的口径是——公开侧没有稳定的"符号名 ↔ 层"映射表；`NotificationService` 是进程内常见符号命名，与扩展实现是否被调起不是同一件事。
正确读法：崩溃读数只用于确认"哪个进程挂了"，层归属仍要靠文档句与公告句。缺映射表这一点本身已列进第 26 章 U12。

---

## 25. 常见问题

**Q1 这篇与第 06 篇（XPC 与 Mach IPC）有什么关系？会不会重复？**
不重复，且在两处相接。第 06 篇的对象是设备内部进程间通信通道本身（发送权、消息流、服务生命周期）；本篇的对象是一条**从外部输入进来的通知信道**，只在两处碰到内部 IPC：设备端派发（L8）与扩展执行（L9）。相接处已经用视角声明划开（第 2 章）并在 L8/L9 里指向第 06 篇。重叠面如果被写成两篇各自的"缺陷"，就会造成同一读数被两次归因——所以本篇对 L8/L9 只主张口径与读数形态，不主张实现层缺陷定位。

**Q2 为什么不直接给一份"APNs 常见错误对照表"就结束？**
因为对照表只解决级 1（口径），不解决级 2（对齐）与级 3（读数）。对照表的每一行都对应一份真实读数，而真实读数在 provider 日志里通常是聚合的、截断的、或者只有状态码没有 reason（第 17.2 三格）。本篇把这三步分开写，是为了让读者在缺少某一步时明确知道自己停在哪一级，而不是把对照表当成诊断结论。

**Q3 两个脚本会不会发出真实请求、或者需要我的 provider 凭证？**
不会，也没有这个能力。脚本一与脚本二的输入都是纯文本文件，全文没有网络调用、没有 `openssl`、没有 curl、没有读环境变量里的凭证；中间文件只落系统临时目录，退出前由 `trap` 删除。它们不需要、也不会使用任何 `.p8`、`.p12`、`.pkey` 或鉴权令牌私钥。

**Q4 为什么脚本一里 `H04` 那条不写进文档口径？**
因为它不是文档口径。文档没有规定设备令牌长度，脚本判的是"常见 32 / 64 两档之外的长度"，属于统计提示。把它伪装成文档级判据会让整份输出的可信度失去锚点，所以第 21.6 节专门标注了它是本脚本唯一的非文档级判据。

**Q5 我能用这些脚本判断"通知为什么没弹出来"吗？**
不能，至少要配合别的证据。"没弹出"落在 L8/L9：授权状态、专注模式、锁屏隐私设置、扩展是否被调起、扩展是否超时。脚本一只看到请求，脚本二只看到 APNs 的响应。第 17.1 节列的五类证据里，设备端呈现这一类需要读者自有设备的系统读数，不在两脚本范围内。

**Q6 `BadDeviceToken` 与 `DeviceTokenNotForTopic` 都写"不重试"，它们不是一回事吗？**
在重试口径上是一回事（文档同一句列了它们，见 22.4 的 no 档），在校验对象上不是：前者是令牌本身或令牌与环境的关系，后者是令牌与 topic 的绑定关系。N1 型缺陷（令牌—主题绑定）通常表现为 `DeviceTokenNotForTopic` 而不是 `BadDeviceToken`；把两者混成一栏会让多环境多 bundle 场景下的定位失效。

**Q7 载荷到底 4 KB、5 KB 还是 16 KB？**
文档给了三个不同口径的数字，本文不选边（第 9.1 节、第 26 章 U3）。provider 侧写请求时按 4 KB（VoIP 5 KB）；平台安全指南在描述 iMessage 中继能力时写 4 或 16 KB 且随版本变化。两者不可互换引用：一个是"你的请求上限"，一个是"APNs 能中继的消息尺寸"，且后者没有给出 16 KB 对应的版本与消息类型映射。

**Q8 为什么广播信道的错误表是 28 个串而不是 32 个？**
因为两页文档各自给出自己的词表，且集合不同：设备侧 32 串含 `ExpiredToken` / `Unregistered`（410），而广播/信道侧 28 串那一页没有 410 档（第 10 章）。这不是笔误，是两套接口。两脚本用了设备侧那张表；广播台账需要另一套判据，这一点在第 23.7 节明确列为未覆盖。

**Q9 公告里那 13 条能说明推送链路"有多少漏洞"吗？**
不能。公告词表不按层组织（第 3.2 节），组件标签有七种且互相重叠（M4），机型范围与"是否受影响"依赖版本判断（第 16 章换算实例）。13 条读数能支持的结论是"这条链路上有公开被修的组件与 CVE 记录"，不是数量、不是可利用性，也不是当前设备的暴露状态。

**Q10 我看到一条公告写"锁屏可查看通知内容"，我的设备现在有问题吗？**
本篇不回答这个问题，也无法回答——它需要读者设备的版本号与更新到位状态（第 15.4 节"更新通道 × 到位"那格）。可回答的只有：公告给出的受影响机型范围、修复该问题的系统版本，以及读者自己核对的"当前版本 ≥ 修复版本"这一条判断。这类判断只有级 1 与级 2 的意义。

**Q11 两个脚本能不能改造成向 APNs 发请求、做在线检测？**
本文不提供该改造，也不建议把这两个脚本当作改造起点。它们的价值完全建立在"不联网、只读文本、不产生任何外部副作用"之上；一旦加入发送能力，输入里就需要真实令牌与鉴权凭证，第 21.1、17.3 节的可见性边界与安全边界同时失效。要做在线核验，请使用官方 Push Notification Console 与自家 provider 的既有通道（第 6 章记录的官方测试路径）。

**Q12 如果我只想要一句结论呢？**
"一条通知没到"在公开读数上有三种完全不同的归属：provider 请求构造错（4xx，责任方 C/D）、令牌治理错（410，责任方 C/D/E）、服务语义（合并、推迟、丢弃，责任方 B 且无需修复）。第 21、22 章两个脚本的作用是让你先分清自己在哪一种读数里；分清之前，任何"这是谁的 bug"的判断都是没有落点的猜测。

---

## 26. 未公开文档化边界清单

这一章集中收录取文中**不能靠公开文档判定**的格子。写法约束：每条都给类型、给已知口径的原句位置、给"缺的是什么"、给停在哪一级。凡进本章的格子，前 20 章不得给出归因结论。

| 编号 | 类型 | 已知口径 | 缺的是什么 | 停在哪一级 |
|---|---|---|---|---|
| U1 | 校验主体未写明 | 32 串表逐条给了"哪个键的值不合规则"（《Handling notification responses from APNs》第 32—63 行） | 每格校验由 APNs 的哪个环节执行、执行顺序如何；因此多条同时违规时哪条先返回，文档无表 | 级 2 |
| U2 | 词表不同源 | 设备侧 32 串（同页 第 32—63 行）与广播/信道侧 28 串（《Handling error responses from Apple Push Notification service》第 28—55 行） | 两者为何不同、同一语义在两表里的对应关系；广播侧无 410 档的原因 | 级 1 |
| U3 | 尺寸口径冲突 | 请求侧 4 KB / VoIP 5 KB（《Generating a remote notification》第 7—9 行）；中继侧 "APNs can only relay messages up to 4 or 16 KB in size, depending on the iOS or iPadOS version"（第 15 章所引平台安全指南第 9346 行） | 16 KB 对应的具体 iOS/iPadOS 版本与消息类型映射；以及上限计的是 JSON 文本还是编码后的帧 | 级 1（并列，不选边） |
| U4 | 失败无读数形态 | 第 4 章：证书链/TLS 迁移是 provider 侧义务 | 握手失败时没有任何 APNs 状态码或 reason；诊断只落到 openssl 自检那条路径（《Establishing a connection to Apple Push Notification service (APNs)》第 24 行） | 级 3（只能证明"通不通"，不能证明哪层错） |
| U5 | 取回缺口（外部页不可引用） | 第 7 章记录的信任链迁移日期由 Apple 通知 | 迁移日期本身指向的 news/support 页在本轮取回为 JS 外壳，扁平正文只有导航（第 2 章末段与存档件清单已标为不可作引用源） | 级 1（日期与页均不可引用，只记录"存在这么一条义务"） |
| U6 | 数值非承诺值 | 服务扩展口径 "has only about 30 seconds to modify the payload and call the provided completion handler"（《Modifying content in newly delivered notifications》第 22 行；第 12.3 节） | 扩展精确执行时限、内存上限、超时的可核对读数；超时后设备侧行为是否产生任何读数字段 | 级 2 |
| U7 | 单页独有规则 | "always update that property last" 只出现在《Supporting PushKit Notifications in Your App》第 12 行；《PKPushRegistry》第 12 行的同主题句没有这句附加约束 | 两页措辞差异的原因；这条顺序约束的强制程度（是建议还是必需） | 级 1（按出现的那页照录，不外推） |
| U8 | 读数的环境限制 | 投递日志：开发环境、按 bundle ID、7 天、需自行下载（第 17.1 节所引控制台页） | 生产环境等价物、跨 7 天窗口的事后核查路径 | 级 3（无日志即无个案证据） |
| U9 | 单环境才有的字段 | `apns-unique-id` "An identifier that is only available in the Development environment"（《Handling notification responses from APNs》第 12 行） | 生产环境是否有等价可关联标识；跨请求去重该用什么字段 | 级 2 |
| U10 | 聚合口径不可下钻 | 指标聚合且四舍五入、分类只有 Stored-/Discarded- 与三种丢弃原因（第 5、6 章所引指标页） | 单条通知的入库/丢弃判定过程；功耗限制（同页 第 27 行）具体如何影响某一条 | 级 3 |
| U11 | 公告标签与层不可映射 | 同一链路上出现七种组件标签（第 16 章） | 标签到层、标签到模块的官方映射 | 级 2 |
| U12 | 崩溃/日志符号无稳定映射 | 第 18 章记录的口径 | 符号名与推送层的对应表；公开侧不存在 | 级 2 |
| U13 | 缺口 A：示例代码不可得 | 存档里 Listing 只剩标题行（第 2.3 节） | 所有 Listing 代码本体；因此本文不转写任何 Apple 示例 payload | 级 1（只引表格定义句与 Listing 标题句） |
| U14 | 缺口 B：entitlement 页原始 JSON | `aps-environment` 页 details/possibleValues 以服务端 JSON 形态保留（第 4—6 行） | 该 JSON 之外是否还有渲染后的散文说明 | 级 1（引用时注明句子出现在 JSON 字段值内） |
| U15 | 原文拼写异常 | 指标页原文含 "seperates"、"occured"、"separate" 形态（第 6 章逐条照录） | 规范写法；本文按"原句优先"原则保留不改写 | 级 1（不影响口径判定） |
| U16 | 存储语义无排队读数 | "APNs stores only one notification per bundle ID"、可被覆盖（《Sending notification requests to APNs》第 5—6 行；指标页 第 30 行） | 被覆盖/被合并这一事件本身是否产生任何 provider 可读字段；文档只给"没有顺序保证" | 级 2 |
| U17 | 静态不可核对的一格 | mdm 主题取自 MDM 推送证书 subject 的 UID（第 4 章） | 纯文本审查拿不到证书，故无判据；脚本以 `H13` 显式声明不可核对 | 级 1（承认看不见） |
| U18 | best effort 无保证 | 过期时刻的处理 "APNs uses best efforts to honor the expiry date without any guarantee"（《Sending notification requests to APNs》第 30 行）；默认 TTL 30 天（指标页 第 31 行） | 任何可预测的投递时刻上界；"设了 expiration 就一定在到期前/后如何"这类规则 | 级 2 |
| U19 | 旧版本设备对新类型未知 | 类型可用性按系统版本给出（第 8.4 节） | 向不支持某 push-type 的旧设备发送该类型时的读数（无对应 reason 串） | 级 1 |
| U20 | 用户授权状态的公开可见性 | 隐私口径：APNs 不追踪离线设备状态（第 6 章所引指标页） | 任何"该设备是否已授予通知权限"的服务侧读数 | 级 3 |

本章三条使用规则：

1. **进过本章的格子，前面章节不得二次归因。** 若某处结论看起来越了界，以本章为准回退到"级 N"标注。
2. **新增缺口按同一格式追加**，且必须写清"已知口径的原句在哪一页哪一行"——没有原句可指的新条目本身就应该被删掉。
3. **类型分布本身就是读数**：U1/U6/U11/U16/U18 都是"校验或投递语义"缺口，U8/U9/U10/U20 都是"可见性"缺口，U13/U14/U15 是取回质量缺口。可见性缺口多于规则缺口，正是第 17 章"这条链路的关键一格不在读者手上"的另一种统计口径。

---

## 27. 结论

回到摘要里提出的问题：**一条通知从 provider 走到用户眼睛，路上有十格可能出错，读者能否只看公开读数说出错在哪一格、归谁修**。

十层拆解给出的答案是"部分能"，且"部分"是可以精确划界的。能的那一半：请求头 12 格的取值域、载荷的键定义与上限、32 个 `reason` 串与十档状态码、重试口径的六个不重试串、投递日志的四重限制、公告里"组件 + Impact + CVE + 机型"的四元组——这些都有原句，都能落到页与行，因此第 21、22 章两个脚本可以离线把它们逐格审一遍。

不能的那一半同样有清单，而且它比能的那一半更能说明问题：设备令牌与主题的绑定关系看不见（U1、N1 型），鉴权令牌内容与验签看不见，TLS/信任链失败不产生任何 APNs 读数（U4），存储侧被覆盖/被合并没有可关联字段（U16），功耗推迟只落到聚合四舍五入的指标里（U10），扩展是否被调起、有没有超时没有公开映射（U6、U12），锁屏呈现受用户设置决定（M5），广播信道另有一套 28 串词表（U2、Q8）。**这七格里，只有两格是"Apple 尚未文档化"，其余五格是"这条链路的性质决定了读数不在这一侧"**——也就是说，即使文档补齐，可见性缺口也不会消失。

由此得出三条本篇结论：

1. **缺陷类型学必须按"哪一次校验失败"分型，而不是按 CVE 编号分型。** N1—N12 之所以能用，是因为每个型都对应到文档里一句校验规则或一个 `reason` 串；CVE 编号对应的是修复动作，不对应校验位置。第 16 章那 13 条公告读数全部只能定位到"某个组件被修了"，没有一条能单独支撑层归属——这不是公告的缺陷，是公告口径与本问题不同形。
2. **归属矩阵里最大的一格不是 Apple，是 provider 与 App 开发者自己。** 第 15 章十层里，责任方含 C/D 的格子明显多于只含 A/B 的格子；而第 14 章标为"可在本地预检"的 8 个型（N1、N2、N4—N8、N10 的可静态判定部分）都在这一侧。换句话说，这条链路上多数可核对的口径违规不需要 Apple 修任何东西——这正是 M6 与 Q12 那句结论的来源。
3. **判定必须停在有读数支撑的那一级。** 级 1 靠原句，级 2 靠对齐，级 3 靠自有读数，级 4 需要跨侧关联；每升一级都要多一类证据，而第 17.2 那三格在多数人的数据面上根本不存在。本篇把停止规则写成表（19.1）而非原则，就是为了让"我停在这里"是一个可交付的结论，而不是一种失败。

方法上，本篇留下的可复用形态有三件：把外部输入通道拆成"校验层 × 责任方 × 更新通道 × 设备侧证据"四列表；用两套词表（文档口径与公告口径）分别取读数并承认它们不同形；以及两个只读、离线、可用夹具做全分支覆盖的核验脚本——第 23.5 节记录的那两个缺陷（失败路径伪装成健康、伪装成另一种故障）恰恰是这种"先把判据写成可跑文本"的写法才暴露出来的，纯叙述式的分析不会暴露它们，因为叙述不会失败退出。

最后一条限制说在前面：本篇的所有结论都建立在**公开文档与公开公告**上，没有任何一条来自真机抓包、私有接口或逆向结果。第 26 章列出的 20 条边界里，凡是本文想断言而断言不了的，都留了"缺的是什么"这一列。这份清单本身，就是本报告对读者最有用的部分：**它告诉你，在 APNs 这条链路上，哪些问题今天就能自查，哪些问题必须先补上第三种读数才有资格被问。**

---

## 28. 参考资料

以下即本轮全部取回记录。凡正文引用的句子都必须能在对应存档件里按行找到原句（第 2.1 节自审清单第 1 条），引用格式为"《标题》第 N 行"。取回日期：2026-10-30。

### 28.1 A 组 · Apple 开发者文档（UserNotifications 及相关框架页面）

取回形态：Apple 文档数据接口 `developer.apple.com/tutorials/data/documentation/…` 的 JSON 与由其展开的扁平文本（每组两份，`MANIFEST.txt` 记录字节数与标题行）。存档标识列给出文档内部 `doc://` 引用路径的末段，即扁平件里同名链接的可定位形式。

（以下 46 件即本轮 A 组全部取回件，按存档件名排序逐件列出）

| 存档件名 | 文档标题（取回件首行 PAGE-TITLE） |
|---|---|
| accessing-and-modifying-per-device-data | Accessing and modifying per-device data |
| aps-environment | APS Environment Entitlement |
| asking-permission-to-use-notifications | Asking permission to use notifications |
| customizing-the-appearance-of-notifications | Customizing the Appearance of Notifications |
| dcappattestservice | DCAppAttestService |
| dcdevice | DCDevice |
| declaring-your-actionable-notification-types | Declaring your actionable notification types |
| establishing-a-certificate-based-connection-to-apns | Establishing a certificate-based connection to APNs |
| establishing-a-connection-to-apns | Establishing a connection to Apple Push Notification service (APNs) |
| establishing-a-token-based-connection-to-apns | Establishing a token-based connection to APNs |
| establishing-your-app-s-integrity | Establishing your app’s integrity |
| exporting-delivery-metrics-logs | Exporting delivery metrics logs |
| generating-a-remote-notification | Generating a remote notification |
| handling-error-responses-from-apns | Handling error responses from Apple Push Notification service |
| handling-notification-responses-from-apns | Handling notification responses from APNs |
| handling-notifications-and-notification-related-actions | Handling notifications and notification-related actions |
| implementing-alert-push-notifications | Implementing Alert Push Notifications |
| implementing-background-push-notifications | Implementing Background Push Notifications |
| implementing-communication-notifications | Implementing communication notifications |
| modifying-content-in-newly-delivered-notifications | Modifying content in newly delivered notifications |
| pkpushregistry | PKPushRegistry |
| pkpushtype | PKPushType |
| pushing-background-updates-to-your-app | Pushing background updates to your App |
| registering-your-app-with-apns | Registering your app with APNs |
| responding-to-voip-notifications-from-pushkit | Responding to VoIP Notifications from PushKit |
| sending-broadcast-push-notification-requests-to-apns | Sending broadcast push notification requests to APNs |
| sending-channel-management-requests-to-apns | Sending channel management requests to APNs |
| sending-notification-requests-to-apns | Sending notification requests to APNs |
| sending-push-notifications-using-command-line-tools | Sending push notifications using command-line tools |
| sending-web-push-notifications-in-web-apps-and-browsers | Sending web push notifications in web apps and browsers |
| setting-up-a-remote-notification-server | Setting up a remote notification server |
| setting-up-broadcast-push-notifications | Setting up broadcast push notifications |
| supporting-pushkit-notifications-in-your-app | Supporting PushKit Notifications in Your App |
| testing-notifications-using-the-push-notification-console | Testing notifications using the Push Notification Console |
| troubleshooting-push-notifications | Troubleshooting push notifications |
| unmutablenotificationcontent | UNMutableNotificationContent |
| unnotificationattachment | UNNotificationAttachment |
| unnotificationcontentextension | UNNotificationContentExtension |
| unnotificationresponse | UNNotificationResponse |
| unnotificationserviceextension | UNNotificationServiceExtension |
| unnotificationsettings | UNNotificationSettings |
| unpushnotificationtrigger | UNPushNotificationTrigger |
| unusernotificationcenter | UNUserNotificationCenter |
| validating-apps-that-connect-to-your-server | Validating apps that connect to your server |
| viewing-the-status-of-push-notifications-using-metrics-and-apns | Viewing the status of push notifications using Metrics and APNs |
| voip-calling-with-callkit | VoIP calling with CallKit |

（上表按存档件名列出；正文引用时一律用标题行，例如《Handling notification responses from APNs》第 32—63 行。存档件名的字节数与标题行同时记录在 `MANIFEST.txt`。）

### 28.2 B 组 · Apple Platform Security 指南

- `apple-platform-security-guide.pdf` / `apple-platform-security-guide.txt`：整本 PDF 与展开文本。正文引用行号（如第 9346 行的中继尺寸句）以 `.txt` 扁平件的物理行为准。
- 不可引用的两件：`devnews-*` 与 `push-notification-faq`、`support-102635-mobilegestalt` 的展开文本在本轮为 JS 渲染外壳，扁平正文只有导航内容，已在存档清单里标为"不得作引用源"，对应第 26 章 U5。

### 28.3 C 组 · Apple 安全发布（Security Releases）页面与 KEV

按 `ios_pages_used.tsv` 列出正文引用过的公告页（编号即 `support.apple.com/en-us/<编号>` 的编号；扁平件为 `pages/<编号>.txt`）：

| 编号 | 公告标题 |
|---|---|
| 120880 | iOS 16.7.6 and iPadOS 16.7.6 |
| 120893 | iOS 17.4 and iPadOS 17.4 |
| 120905 | iOS 17.5 and iPadOS 17.5 |
| 121837 | iOS 18.2 and iPadOS 18.2 |
| 121838 | iPadOS 17.7.3 |
| 122066 | iOS 18.3 and iPadOS 18.3 |
| 122371 | iOS 18.4 and iPadOS 18.4 |
| 125108 | iOS 26 and iPadOS 26 |
| 127002 | iOS 26.4.2 and iPadOS 26.4.2 |
| 127003 | iOS 18.7.8 and iPadOS 18.7.8 |
| 127112 | iPadOS 17.7.11 |
| 127113 | iOS 16.7.16 and iPadOS 16.7.16 |
| 127114 | iOS 15.8.8 and iPadOS 15.8.8 |

另有 KEV（Known Exploited Vulnerabilities）Apple 子集与公告扫描中间件（`cve_*.txt`、`kev_apple.json`），仅用于第 16 章读数的机型与版本换算核对；凡正文引用的公告句，都以 `pages/<编号>.txt` 的行号为准。

### 28.4 协议与标准

正文对 HTTP/2 的引用（如首部压缩与索引、SETTINGS 帧、GOAWAY 帧）取自《Establishing a certificate-based connection to APNs》《Handling notification responses from APNs》两页内的链接与句子；文档以 `rfc9113` 形式指向 HTTP/2 规范（响应页 第 65 行给出的 datatracker 链接），本文不直接转写 RFC 句，只记录"文档把吞吐调整口径指向该规范"这一事实。

### 28.5 核验脚本与夹具

- 脚本一：`apns-request-audit.sh`（345 行，全文见第 21.8 节围栏）
- 脚本二：`apns-ledger-triage.sh`（220 行，全文见第 22.5 节围栏）
- 夹具：15 份 `.req` 请求文本、8 份 `.ledger` 响应台账，另有调用面（`-h`、无参数、未知选项）、只读拒绝 ACL 件与 `TMPDIR` 不可用件；运行记录与逐码位覆盖表见第 23 章。

---

咨询ios系统请咨询 telegram：https://t.me/one00190
