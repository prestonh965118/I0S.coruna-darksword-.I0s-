---
title: "iOS 聚焦索引与 Siri 建议链路归属防御分析报告"
description: "iOS 上一条内容被写进聚焦索引之后到底谁能查回来、谁判的、判在哪一格、这一格由哪个面读回来、删掉之后谁能证明删干净了：十一层归属分解（写入、声明身份、资格、属性、建议与捐赠、服务端边界、场景门、告知、观测平面、管理与公告回查、删除与复位），三件（声明件／通道件／观测件）× 10 类对象 × 21 项核对项的差集口径，J1—J4 与 Q1—Q4 两套判定模型，两个离线只读核验脚本（信号码 67 + 51，共 118 个全部实跑触发，38 次实跑逐码覆盖表）"
lang: zh-CN
---

# iOS 聚焦索引与 Siri 建议链路归属防御分析报告

## 摘要

本报告集前十六篇回答过六类归属问题：**缺陷在哪**（第 01、06、07、12 篇的攻击面归属）、**谁能进入这道门**（第 02 篇的访问控制归属）、**这条链路看见了什么**（第 03、04 篇）、**这台设备归谁**（第 08、10、11 篇的主体归属）、**这段代码凭什么被允许运行**（第 14 篇的授权链归属）、**这条通道凭什么存在**（第 15 篇的通道归属）、**同网段上谁看得见谁**（第 16 篇的局域网可达性归属）。本文回答第七类，也是前面每一篇在做台账时都会撞到、却从未被正面拆解的那一类：

**一条内容被写进检索面之后，它的可查询面归谁。** 具体拆开是三个问句——**谁把它写进去的、凭什么写**（写入权在谁手里）；**谁被允许查回来、这一格由哪个面读回**（读取权在谁手里）；**删掉之后谁能证明删干净了**（回读权在谁手里）。

这三个问句的答案落在**三个互不对接的平面**上，而日常讨论总把三者混成一句话：

- **声明件**：`CSSearchableItem` 的身份三元组（`initWithUniqueIdentifier:domainIdentifier:attributeSet:`，`A/cssearchableitem.txt:208`）、四个 `isEligibleFor*` 资格位（`B/nsuseractivity.txt:313/319/325/331`）、索引名与保护等级（`A/adding-your-app-s-content-to-spotlight-indexes.txt:157/169`）、`expirationDate`（`A/cssearchableitem.txt:129—131`）、App Intents 实体的可发现性（`A/cssearchableindex.txt:294—297`）。它们由**每个 App 自己**写在代码里，构建期或运行期就定了。
- **通道件**：哪条 API 能把它读回来——`CSSearchQuery`／`CSUserQuery`（`A/corespotlight_csuserquery.txt:13—16`）、Spotlight 搜索工具（`A/spotlight-search-tool.txt:19/21/27/29—30`）、按标识符／按域／全量的五级删除粒度（`A/cssearchableindex.txt:58/70/88/100/116`）。这一件规定的是「查询发起方是谁、取回哪几格、取回多少条」。
- **观测件**：设置页开关与 App 列表、配置画像里的 11 个限制键、`com.apple.configuration.siri.settings` 声明式类型、安全公告的组件列、告知文本两页。这一件是各种读数面各自给出的片段。

本文的核心结论是这三件**两两都不闭合**，而且不闭合的方向与前六篇相反。前六篇的判定权都在系统或管理面手里，管理面往往**根本不能配置**那一格（第 16 篇：220 个公开限制键里没有一个管本地网络隐私）；本篇的**写入权在每个 App 自己手里**——`A/corespotlight.txt:17` 直接写「Your app is responsible for indexing your app's content and maintaining those indexes」，管理面只提供开关型限制，不能逐项审阅某条内容进了哪个索引。三件的不闭合表现为：写了声明件不代表此刻查得回来（资格位为真、场景门却关着，第 6、10 章）；查得回来不代表读得到那几格属性（`A/corespotlight_searching-for-information-in-your-app.txt:22—24`：系统只取回你明确请求的属性，第 7 章）；删掉了不代表任何一面能证明删干净（索引侧**没有面向 App 的「当前可查询状态」读数**，只能靠「再查一次应当未命中」这一间接口径，第 14 章）。

比这三条更要紧的是一条**平面错位读数**：把 12 篇安全发布的 1,266 条公告记录按组件列筛出检索面子集（Spotlight 26、Shortcuts 16、Siri 15、Apple Intelligence 4、App Intents 4、Help Viewer 3，共 68 行），**组件列明确写着这些名字，影响句列里 `index`、`search`、`suggest`、`query`、`dictation` 全部 0 次命中**（`C/query-plane-17-summary.txt`）。也就是说：检索面的**存在性**由组件列承载，检索面的**后果**在影响句里一个字都不提。第 15、16 篇处理的是「平面在两列都缺位」的负空间，本篇处理的是「一列有、一列无」——防守方如果按影响文本做关键词筛选，这一整层是 0 命中。这是本文的中心事实，也是第 21、22 章两支脚本里 X 族信号码的设计根据。

全文有二十处可数的公开读数（第 16 章，每处给归档行锚）、两套四档判定模型（第 19 章）、十一层归属分解（第 4—14 章）、一个十一层 × 责任方 × 三件 × 证据的归属矩阵（第 15 章），以及两个完全离线、只读、不联网、不接触任何设备或索引库的核验脚本：检索面台账逐字段审查器（442 行，67 个信号码）与检索面三件差集与公告子词表比对器（502 行，51 个信号码）。**118 个信号码全部由真实夹具触发**，38 次实跑的逐码可达性见第 23 章。

---

## 目录

1. [引言](#1-引言)
2. [视角声明与本文边界](#2-视角声明与本文边界)
3. [三套词表：开发者侧索引声明口径、平台侧放行口径、管理与公告回查口径，与八处换算失败](#3-三套词表开发者侧索引声明口径平台侧放行口径管理与公告回查口径与八处换算失败)
4. [L1 写入层：内容什么时候进索引](#4-l1-写入层内容什么时候进索引)
5. [L2 声明层：条目的身份三元组与所属域](#5-l2-声明层条目的身份三元组与所属域)
6. [L3 资格层：四个资格位与公开索引那一个](#6-l3-资格层四个资格位与公开索引那一个)
7. [L4 属性层：查询只取回被请求的那几格](#7-l4-属性层查询只取回被请求的那几格)
8. [L5 建议与捐赠层：活动、意图捐赠与实体](#8-l5-建议与捐赠层活动意图捐赠与实体)
9. [L6 服务端边界层：本机索引不上送与检索词上送是两件事](#9-l6-服务端边界层本机索引不上送与检索词上送是两件事)
10. [L7 场景门层：锁定、外部智能、听写出设备与专注压制](#10-l7-场景门层锁定外部智能听写出设备与专注压制)
11. [L8 告知层：三页告知文本与可选加入](#11-l8-告知层三页告知文本与可选加入)
12. [L9 观测平面层：这一格是谁读回来的](#12-l9-观测平面层这一格是谁读回来的)
13. [L10 管理与公告回查层：11 个限制键与 68 行子词表的列间错位](#13-l10-管理与公告回查层11-个限制键与-68-行子词表的列间错位)
14. [L11 删除与复位层：五级删除粒度与再检索证明](#14-l11-删除与复位层五级删除粒度与再检索证明)
15. [归属矩阵：十一层 × 责任方 × 三件 × 证据](#15-归属矩阵十一层--责任方--三件--证据)
16. [公开读数：这条通路上能数出来的二十件事](#16-公开读数这条通路上能数出来的二十件事)
17. [可见性边界：这一层读者能拿到什么](#17-可见性边界这一层读者能拿到什么)
18. [五个读数面：索引侧、查询侧、设置侧、管理侧、公告侧](#18-五个读数面索引侧查询侧设置侧管理侧公告侧)
19. [两套判定模型：J1—J4 与 Q1—Q4](#19-两套判定模型j1j4-与-q1q4)
20. [运营指标 O1—O10](#20-运营指标-o1o10)
21. [只读核验脚本一：检索面台账逐字段审查器](#21-只读核验脚本一检索面台账逐字段审查器)
22. [只读核验脚本二：检索面三件差集与公告子词表比对器](#22-只读核验脚本二检索面三件差集与公告子词表比对器)
23. [三十八次实跑与全量信号覆盖验收](#23-三十八次实跑与全量信号覆盖验收)
24. [十二个误区](#24-十二个误区)
25. [常见问题](#25-常见问题)
26. [未公开文档化边界清单](#26-未公开文档化边界清单)
27. [结论](#27-结论)
28. [参考资料](#28-参考资料)

---

## 1. 引言

### 1.1 为什么这是第七类归属问题

前十六篇里，「归属」这个词一直被用在**主体**上：这台设备归谁（第 10、11 篇）、这段代码由谁签名（第 14 篇）、这份记录由谁写出（第 13 篇）、这条通道由谁装配（第 15、16 篇）。本文要用的归属落在**客体**上：一条内容一旦被某个 App 写进某个索引，它就不再属于写它的那段代码——它进入了一个人人可查的面上，而这个面的边界**不由写它的人单独决定**，也不由读它的人单独决定，更不由设置页单独决定。

这类归属之所以必须单独拆出来，有三个可数的理由。

**第一，判定权被切成三段，而且分属三方。** 写入权在开发者侧：`A/corespotlight.txt:17` 把维护责任直接交给 App，`A/corespotlight.txt:18—19` 进一步允许「App 运行时索引，或提供 App 扩展在系统请求时索引」，`A/corespotlight.txt:19—21` 明确可以索引「App 当前没有显示的文件与其他内容」。读取权在平台侧：锁屏放不放行、受限用户放不放行、外部智能开不开，都不在 App 手里。回读权在设置面与公告面两处：索引本身**没有**给 App 的「当前可查询状态」读数，`A/cssearchableindex.txt:266—272` 的 `isIndexingAvailable` 只回答「这台设备能不能索引」，不回答「这一条现在查不查得到」。

**第二，这个面的范围会随场景变，而不随身份变。** 同一条索引项，在解锁后与锁屏前、在专注模式内与外、在允许外部智能与禁止外部智能两种配置下，可查询面不同；但它的身份三元组（uniqueIdentifier／domainIdentifier／attributeSet）一个字节都没变。第 02 篇管的是「谁能调这个 API」，本篇管的是「调了以后内容对谁可见」——两件事的判定依据不是同一格。

**第三，删除是不可直接证明的。** App 侧有五级删除接口（第 14 章），但删除之后唯一可登记的公开口径是「再查一次应当未命中」——`A/adding-your-app-s-content-to-spotlight-indexes.txt:67—72` 只说系统会按期过期条目、并要求「用户从 App 里删掉原始数据时，把索引里的关联条目一并移除」，这是一句**义务句**，不是一句「删除会立刻生效」的机制句。把义务句当机制句读，是这一层最常见的口径事故。

### 1.2 主键与三个问句

本文主键：**一份内容被索引之后的可查询面**。它和系列里任何一篇都不重合，因为它同时要求三格独立判定，而每格分别属于不同篇目：

| 问句 | 谁持有判定权 | 落在本文哪一层 | 系列里的最近邻（但不重合） |
| --- | --- | --- | --- |
| 这条内容凭什么在检索面上 | 开发者（App 或其 App 扩展） | L1 写入、L2 声明、L3 资格 | 08 篇的隐私申报（申报了不等于写进索引）、02 篇的 entitlement（有权调用不等于内容可见） |
| 谁能把它查回来、能查回哪几格 | 平台（锁屏／受限用户／专注／外部智能）+ 发起查询的代码 | L4 属性、L7 场景门、L9 平面 | 05 篇的生物识别（本文只读「锁屏前助理是否可用」，不解释由哪种生物特征判定）、16 篇的可达性（同网段的可见 vs 同一台设备内的可查） |
| 它失效之后谁能证明删干净了 | 开发者（删除接口）+ 用户（开关级删除）+ 无第三方读数面 | L11 删除与复位 | 11 篇的可证删除（那是备份侧的副本语义，本篇是同一台设备上的另一个对象） |

三个问句合起来构成第 19 章的两套四档判定模型：脚本一的 J1—J4 回答「这一条能不能进入对外归属表述」，脚本二的 Q1—Q4 回答「三件对完之后，归属还能不能立起来」。

### 1.3 本文不做什么

本文是归属与口径分析，不是操作手册。以下内容明确不做，且第 21、22 章两支脚本在设计上不可用于这些目的：

- **不提供任何绕过锁屏检索、提取索引库、导出本机索引、构造恶意快捷指令或恶意意图、规避屏幕使用时间／专注模式限制的做法**；不提供语音唤醒、录音或声纹仿制方法。
- **不指导关闭、伪装或绕过任何隐私提示**，不指导规避管理面审计，不指导抓取或解密查询文本。
- **不采集设备状态**。两支脚本全程离线、只读，不调用 `mdfind`、`mdls`、`mdimport`、`mdutil`、`spotlight`、`profiles`、`sysctl`、`xcrun`、`defaults`、`log` 等任何命令行工具——这些命令名在脚本里只出现在注释与拒收分支中，第 23 章的只读实证逐条给出位置。
- **不判定索引内容的价值或敏感性**。台账登记的是「这条内容在哪一格被谁读到」，不是「这条内容要紧不要紧」。
- **不代替厂商口径**。凡是只有厂商承诺、没有公开文档支撑的判断，一律落在第 26 章的未公开文档化边界清单里，不进结论。

---

## 2. 视角声明与本文边界

系列里任何一篇在开篇都必须回答「这件事第 X 篇不是已经写过了吗」。本节逐条回答，并把边界写成可检查的句子——每一行的「不重复部分」都能在对应篇目里找到原句位置。

### 2.1 与第 08 篇的分界（最近邻）

第 08 篇处理隐私授权与用途声明，其中 `NSSiriUsageDescription` 作为 69 个隐私键之一被登记过。**分界**：08 篇回答「这个键申报了没有、申报文本合不合格、审核链怎么走」；本文回答「申报完成之后，内容进了哪个索引、这条查询能不能命中它」。这两次判定互相独立——`A/corespotlight.txt:19—21` 允许索引「App 当前没有显示的内容」，这一步不产生任何新的用途申报；反过来，申报了某个用途也不给任何一条内容开检索面。本文不重建隐私键表，不讨论 required reason 与隐私清单。

### 2.2 与第 02 篇的分界

第 02 篇的权限图里有 `com.apple.developer.siri` 这一行与 Siri Intent 的两格。**分界**：02 篇管调用权（谁可以调这个 API），本文管调了之后的可见性。这两件事在文档里也是分开的：`A/cssearchableindex.txt:26—28` 说的是「只能从已签名的 App 或 App 扩展改索引，多线程或从未签名 bundle 访问自定义索引是编程错误」——这是**写入方的身份要求**；而一条内容写入之后对谁可见，取决于资格位（`B/nsuseractivity.txt:331`）与场景门（第 10 章），与调用方有没有 entitlement 无关。本文不重建 entitlement 表。

### 2.3 与第 16 篇的分界（结构最近邻）

第 16 篇用「声明件／权限件／观测件」三件法分析局域网可达性，并给出一条重要负空间：管理面不能配置本地网络隐私。**分界有两处。**

**方向不同**：16 篇管同一网段上的「可见与被可见」，本文管同一台设备内的「可查与被可查」。16 篇里内容不出设备就没有问题；本文里内容不出设备恰恰是主体——`A/corespotlight.txt:22—23` 写得非常直白：「你用 Core Spotlight 建立的索引留在设备上，并且对该设备的所有者是私有的。设备不会与 Apple 共享索引数据，也不会把该数据与这个人的其他设备同步」。

**判定权位置相反**：16 篇的判定权在守护进程与用户手里，管理面不能逐项配置；本文的写入权在**每个 App 自己手里**，管理面只提供 11 个开关型限制键（第 13 章），一个都不能审阅某条内容进了哪个索引。这个差别决定了本篇的两套脚本形态与 16 篇不同：16 篇的差集器主要查「声明了但没有权限件」，本文的差集器主要查「声明件写了这一项、通道件与观测件两格却一条也没有」——因为写入侧太容易，缺口几乎总在读回侧。

三件命名沿用 16 篇（声明件／通道件／观测件），但**对象类、核对项与信号码全部重列**，不复用 16 篇任何信号码。

### 2.4 与其余各篇的分界

| 篇 | 它已经写过 | 本文不重复 | 本文独占 |
| --- | --- | --- | --- |
| 05 生物识别 | 「Siri、照片分析等 AI 功能不访问生物识别模板」 | 不判定生物特征本体、不谈模板与匹配阈值 | 只读「锁屏前助理是否可用」这一条口径（`B/mdm-restriction-keys.txt:24`），不解释它由哪种生物识别判定 |
| 11 数据副本 | `Spotlight` 出现在公告组件名单里 | 不谈副本、密钥轮换与备份侧可证删除 | 索引不是副本：一次删除内容之后索引项的留存与重建，是同一台设备上的另一个对象（`A/regenerating-your-app-s-indexes-on-demand.txt:6—11`：App 更新索引时崩溃可能把索引留在不正确状态） |
| 13 证据链 | Spotlight 只作为 Xcode 操作路径出现 | 不采集日志、不定义留存与同意口径 | 查询面是**被检索的存量**，日志是**被写入的事件**；本文主键不是事件记录 |
| 14 授权链 | 运行授权的三段位置与到期语义 | 不谈描述文件、证书与分发通道 | 可发现性与代码能否运行无关：签名校验通过不等于内容不进索引 |
| 15 通道存在性 | 组件名与通道类的差集读数法 | 不建立「通道类 ↔ 组件名」映射，不引用 NECP | 查询文本是否离开设备由告知口径登记（第 9 章），不是隧道问题；本文不做任何抓包 |
| 01 攻击入口 | 附件解析作为触发链 | 不讨论入口与消息体解析 | 一条从未被打开的文本也可能进入可查询面（`A/corespotlight.txt:19—21`） |
| 06 IPC／07 推送 | 服务面与 APNs 链路 | 不重建服务清单，不谈推送装配 | 索引服务只登记「谁写入、谁查询」两格，不展开其缺陷面 |
| 09 更新链 | 补丁传导与公告覆盖验收法 | 不建立补丁时延指标 | 公告影响句词形是本文独占读数（第 13 章），用途不是补丁验收而是平面错位 |
| 10 设备归属 | 设备在谁手上、激活锁与托管凭据 | 不判定设备所有权 | 一台设备「可查」与一台设备「归谁」是两格；受限用户与设备所有权也是两格 |
| 12 第三方代码 | SDK 台账与归属主体 | 不重建 SDK 名单 | 索引项与意图词汇表由 App 自己声明，与它内嵌了谁的代码无关 |

### 2.5 三件法与本文的可证性边界

本文的可证边界由一句文档事实决定：**索引侧没有面向 App 的「当前可查询状态」读数。** 因此本文所有关于「此刻还能不能查回来」的表述，只能写成三种形态之一：

1. **接口口径**——某 API 的公开说明写了它会或不会做什么（例如 `A/cssearchableindex.txt:16—17`：执行查询时 Core Spotlight 在索引里找请求的信息并把结果返回给代码）；
2. **开关口径**——设置面或限制键把整条通道关掉（例如 `B/mdm-restriction-keys.txt:22` 的 `allowAssistant`）；
3. **告知口径**——告知页写了某类数据会不会送到 Apple（例如 `B/legal-siri-suggestions-search.txt:49`）。

**没有第四种。** 本文不允许任何「实测发现某条内容查不到」的表述，因为那需要设备侧查询操作，属于本文红线。这也带来一条必须写清的负面结论：**「删干净」在本文里只能表达为「按标识符发起过删除 + 再检索未命中 + 该格登记了核对时刻」这一间接三段，不能表达为「索引库中已无此条」。** 第 14、19 章与脚本一的 V 族信号码全部围绕这条边界设计。

---

## 3. 三套词表：开发者侧索引声明口径、平台侧放行口径、管理与公告回查口径，与八处换算失败

三套词表各说各话，是这一层最容易产生假结论的原因。本节先把三套词表各自的取值列清楚，再逐条给出八处**换算失败**——即「从一套词表的说法推不出另一套词表的结论」的固定位置。第 21、22 章两支脚本的每一个信号码都能归到某一条失败上。

### 3.1 词表 A：开发者侧索引声明口径（声明件）

来源是组 A 归档（15 件，`A/`）。可枚举取值：

| 词形 | 出处 | 含义 |
| --- | --- | --- |
| `primary`／`private_secure`／`separate_index` | `A/adding-…:76—79`（可建多个索引，例如把歌曲目录放主索引、把私人歌单放另一索引）、`:80—82`（更敏感的数据建更安全的索引） | 索引种类的三分 |
| `default_index` | `A/cssearchableindex.txt:50`（返回默认设备侧索引）、`:25`（默认索引只在测试或原型阶段使用）、`A/adding-…:86—88`（只用于原型与测试，生产版本不要用它存内容） | 唯一被文档明令不要用于生产的种类 |
| `complete`／`complete_until_first_unlock`／`after_first_unlock`／`when_unlocked` | `A/adding-…:157/164—166`（`protectionClass`／`FileProtectionType`）、`A/cssearchableindex.txt:274—277` | 索引的保护等级四分 |
| `isEligibleForSearch`／`isEligibleForPrediction`／`isEligibleForPublicIndexing`／`isEligibleForHandoff` | `B/nsuseractivity.txt:331/333`、`:319/321`、`:325/327`、`:313/315` | 四个资格位，各自独立 |
| `uniqueIdentifier`／`domainIdentifier`／`attributeSet` | `A/cssearchableitem.txt:222/224`、`:122/124`、`:208` | 条目身份三元组 |
| `expirationDate` | `A/cssearchableitem.txt:129/131`、`B/nsuseractivity.txt:249/251` | 条目「应当不再存在」的日期 |
| `relatedAppEntityIdentifier` | `A/cssearchableitem.txt:216/218` | 索引项与 App 实体的挂接点 |
| `CSSearchableItemActivityIdentifier` | `A/cssearchableitem.txt:242/244` | 索引项与用户活动之间的键 |
| `contactKeywords`／`contentModificationDate`／`creator` | `A/cssearchableitemattributeset.txt:299/346/418` | 属性集字段（1,746 行归档逐条列出可承载字段） |
| `AppEntity`／`isDiscoverable` 类可发现性口径 | `A/cssearchableindex.txt:294—297`、`A/appintents_appentity.txt:3/57` | 由 App Intents 侧声明的可发现性 |

这套词表的特点：**全部由 App 自己填**，且没有任何一格是系统替 App 反过来写的。

### 3.2 词表 B：平台侧放行口径（通道件与场景门）

来源是组 A 的检索文档与组 B 的限制键清单。可枚举取值：

| 词形 | 出处 | 含义 |
| --- | --- | --- |
| `CSSearchQuery`／`CSUserQuery` | `A/corespotlight_csuserquery.txt:13—16`（与 App 的搜索界面组合，做词法与语义检索；可返回排序或不排序结果；可用来取建议列表） | 两条查询通道 |
| `CoreSpotlightSource`／`FileSource` | `A/spotlight-search-tool.txt:19/21`、`:27/29—30` | 把索引暴露给基础模型的两种数据源 |
| `attributes_requested` 白名单 | `A/corespotlight_searching-for-information-in-your-app.txt:22—24`（系统不自动取回每个属性，只取回你明确请求的）、`:29—30`（要标题与显示名就得把这两个字符串列进去） | 结果字段的请求制 |
| `maxResults` 未设=跑到底 | `A/corespotlight_csuserquery.txt:35—41`（查询一直跑到返回指定的最大结果数；没指定最大数就返回全部结果；开始新查询前应取消旧查询） | 结果条数与取消语义 |
| `allowAssistant`／`allowAssistantWhileLocked`／`allowAssistantUserGeneratedContent`／`allowDictation`／`allowSpotlightInternetResults` | `B/mdm-restriction-keys.txt:22/24/23/61/143` | 五道放行闸门 |
| `allowExternalIntelligenceIntegrations(+SignIn)`／`allowSiriAI`／`forceAssistantProfanityFilter`／`forceOnDeviceOnlyDictation`／`forceOnDeviceOnlyTranslation` | `B/mdm-restriction-keys.txt:70/71/141/182/196/197` | 六道外部智能与听写闸门 |
| `isIndexingAvailable` | `A/cssearchableindex.txt:266—272` | 唯一一处设备侧可用性读数，且只回答「这台设备能不能索引」 |

### 3.3 词表 C：管理面、告知面与公告口径（观测件的另三个来源）

| 词形 | 出处 | 含义 |
| --- | --- | --- |
| 11 个限制键（全部为开关） | `B/mdm-restriction-keys.txt:22—197`（见上） | 管理面唯一能表达的东西：允许或不允许 |
| `com.apple.configuration.siri.settings` | `B/mdm-restrictions.txt:1250+`；`B/mdm-siri-keys.tsv` 的 10 个旧键全部标注 Deprecated 并迁往该声明式类型 | 声明式管理的接管位置 |
| 「Suggestions 使用本地设备侧处理……不存储在 Apple 服务器上，也不与其他第三方 App 共享」 | `B/siri-dictation-legal.txt:64—65` | 建议面personalization 的云端边界 |
| 「Siri 请求不与你的 Apple Account 关联；检索请求会被 Apple 存储并用于改进 Search、Siri 与相关功能，可在设置里关掉 Help Apple Improve Search」 | `B/siri-dictation-legal.txt:28/34` | 请求侧（与索引侧是两段不同口径） |
| 「关掉 Siri 与听写之后，设备上存储的、用于个性化体验的转录会被删除」 | `B/siri-dictation-legal.txt:72/73`、`B/legal-improve-siri-dictation.txt:40` | 用户侧唯一的删除口径，且是开关级 |
| iCloud.com 上的搜索使用设备本地索引、四条授权条件 | `B/apple-platform-security-guide.txt`（PSG）第 2749、2750—2752、2759—2762 行 | 设备侧索引被远程查询时的唯一公开边界描述 |
| 公告组件列六个检索面具名组件（Spotlight／Siri／Shortcuts／App Intents／Apple Intelligence／Help Viewer） | `C/query-plane-17.tsv` 68 行 | 存在性读数 |
| 公告影响句九句去重（`An app … may be able to access sensitive user data` 44 次最高） | `C/query-plane-17-summary.txt` | 后果读数，且**不含任何检索面词形** |

### 3.4 八处换算失败

这八条是本文的负面骨架。每条都写成「A 词表的这一句**推不出** B 词表的那一句」，并给出行锚。

**失败 1：申报口径 → 检索面存在。** 第 08 篇的隐私键申报完成，只证明 App 有资格调用相应 API；`A/corespotlight.txt:19—21` 允许索引 App 未显示的内容，这一步不产生任何申报。换算失败的方向是「写了说明就以为内容不在面上」。

**失败 2：资格位为真 → 此刻查得回来。** `B/nsuseractivity.txt:331`（是否把活动加入设备侧索引）与 `:319`（Siri 能否把它作为快捷指令建议）是两个独立的位，而两者都设为真也不覆盖场景门：`B/mdm-restriction-keys.txt:24` 的 `allowAssistantWhileLocked` 关闭时，锁屏前那一段可查询面直接消失。资格位是**声明件**，场景门是**通道件**，中间没有换算关系。

**失败 3：内容在索引里 → 属性读得到。** `A/corespotlight_searching-for-information-in-your-app.txt:22—24`：执行查询时系统只取回你明确请求的属性。所以「这条内容被索引了」与「这条查询能不能读到它的创建者字段」是两次判定。台账里把这两格合并登记是最常见的假闭合。

**失败 4：本机索引不上送 → 检索词也不上送。** 这是本文最需要拆开的一条。`A/corespotlight.txt:22—23` 说的是**索引数据**不共享给 Apple、不同步到其他设备；`B/siri-dictation-legal.txt:28` 与 `B/legal-siri-suggestions-search.txt:28/35` 说的是**检索请求**会被 Apple 存储并用于改进 Search 与 Siri。两句口径各自成立，但绝不能互相换算——脚本一的 N03 信号码专门盯这条（用「请求侧不关联 Apple Account」闭合「本机索引不上传」）。

**失败 5：公告组件列有 → 影响句说了。** 第 13 章的中心读数：68 行子集里组件列全部具名，影响句里 `index`／`search`／`suggest`／`query`／`dictation` 全 0 命中。按影响文本关键词筛选检索面缺陷，会漏掉整层。

**失败 6：限制键关掉通道 → 索引内容被清掉。** 管理面 11 个键全是开关，`B/mdm-restrictions.txt` 的 10 个旧 Siri 键也全部标注 Deprecated；没有任何一键是「清空索引」。开关改变的是**谁还能查**，不是**面上还有没有**。

**失败 7：调用了删除 API → 删干净了。** `A/adding-…:67—72` 是义务句（用户删了原始数据你要移除索引项），`A/adding-…:91` 说异步并入并通知完成，但删除侧的公开文本只到「发起」与「回调」为止；`A/cssearchableindex.txt:58/70/88/100/116` 五个删除粒度的说明句都不包含「立即生效」或「可在索引中验证」。因此删除只能登记为间接三段（第 2.5 节）。

**失败 8：App 的索引 → 只影响这个 App。** `A/corespotlight.txt:3` 直说索引内容供 Spotlight 与 Safari 搜索；`A/corespotlight_searching-for-information-in-your-app.txt:9—10` 说「索引你的内容使它同时对你的 App 和系统的 Spotlight 搜索可用」；`A/spotlight-search-tool.txt:3—4` 进一步把它开放给基础模型作为回答提示的额外上下文；`A/spotlight-search-tool.txt:27/29—30` 的 `FileSource` 甚至检索「对 Spotlight 可见的文件与目录的已索引元数据」。一条 App 侧写入，读数面至少有四个，而写入方通常只登记了一个。

---



---

## 4. L1 写入层：内容什么时候进索引

### 4.1 这一格的公开口径

写入这一格的四条公开句子，全部来自 `A/corespotlight.txt` 与 `A/adding-…`：

- **责任归属**：`A/corespotlight.txt:17` 「Your app is responsible for indexing your app's content and maintaining those indexes」——索引的建立与维护责任在 App，不在系统。
- **两个时机**：`A/corespotlight.txt:18—19` 「You can index content when your app runs, or provide an app extension to index content when the system requests it」；`A/adding-…:95—96` 进一步说明「Provide a reindexing app extension to keep the index up to date even when your app isn't running」。
- **范围**：`A/corespotlight.txt:19—21` 「You can index any content your app manages, including files and other content that your app isn't currently displaying」。
- **推荐范围**：`A/adding-…:13—15` 建议索引「这个人关心或直接交互的内容，例如收藏、已购项、发过与收到的消息」——这是**建议**，不是限制。

`A/adding-…:18—19` 另有一条与用户动作相关的写入入口：在用户发起的活动上启用该属性，会把那些活动加入设备侧索引并进入后续检索。这条要和第 8 章的捐赠区分开：这里是**属性启用**导致入索引，那里是**活动捐赠**导致可被建议。

### 4.2 这一格由哪一件持有

**声明件**，且只有一个持有人：写代码的一方（App 本体或它的 App 扩展）。这一格没有对应的平台侧记录——平台不参与「要不要把这条内容放进索引」的决定，它只决定「放进来之后谁能查回来」。

`A/cssearchableindex.txt:26—28` 给写入方加了三个身份与并发约束：一次只能从一个线程或任务改一个索引对象；只能从**已签名的 App 或 App 扩展**改；从未签名 bundle 或多线程同时访问自定义索引是编程错误。`A/corespotlight.txt:15` 另有一条平台差异：Spotlight 文件导入扩展在 macOS 上不提供功能——同一种装配形态在不同平台上可查面不同。

### 4.3 谁读得回它

三处，且互相不等价：

1. **App 自己的查询**：`A/cssearchableindex.txt:16—17` 执行查询时框架在索引里检索并把结果返回给代码。这是唯一「写的人能读回」的通道，但读回的是**被请求的属性**（第 7 章）。
2. **系统 Spotlight**：`A/corespotlight_searching-for-information-in-your-app.txt:9—10`。
3. **再索引扩展被系统回调时**：`A/corespotlight_cssearchableindexdelegate.txt:13` 说明长驻或批量更新索引的 App 应在 delegate 对象或 App 扩展里实现必需方法；`:76` 「Tells the delegate to reindex all searchable data and clear all local state information」；`:88` 按标识符再索引。这三句里最要紧的是 `:76` 的「clear all local state information」——系统要求再索引时可以同时要求 App 清掉自己的本地状态，也就是说**索引的正确性可以由系统单方面要求重建**，而 App 侧登记的历史读数随之失效。

### 4.4 与 L2、L3 的接缝（失败点 1 与 2 的落点）

写入层最常见的两类台账错误：

- 把「App 用过这个 API」当成「这条内容在索引上」。`A/adding-…:91` 说并入是异步的并会在完成时通知——异步意味着**发起 ≠ 落面**，台账必须分别登记发起时刻与核对时刻。
- 把「内容在索引上」当成「内容只在 App 自己的面上」。`A/corespotlight.txt:26—27` 的口径里，加入设备侧索引时还有一项「标识这些条目是否适合公开索引」的选择。

**台账字段**：`id.obj_kind`、`id.index_kind`、`id.index_name`、`id.protection_class`、`cap.api_path`、`when.indexed_at`、`when.state_checked_at`。
**信号口径**：脚本一的 A 族（身份、声明与权利，276—293 行）覆盖对象种类与索引种类缺失或不合法；T 族（345—358 行）覆盖发起时刻与核对时刻缺失或倒序；S 族覆盖异步未回读。

---

## 5. L2 声明层：条目的身份三元组与所属域

### 5.1 这一格的公开口径

一个条目「是谁」，在文档里由构造器签名直接给出：`A/cssearchableitem.txt:208` 「`initWithUniqueIdentifier:domainIdentifier:attributeSet:`」。三元组各自的说明句是：

- `A/cssearchableitem.txt:222/224` 「The value that uniquely identifies the searchable item within your app」／`uniqueIdentifier`——**在 App 内**唯一，不是全局唯一。
- `A/cssearchableitem.txt:122/124` 「An optional identifier that represents the domain or owner of the item」／`domainIdentifier`——可选，代表条目所属域或所有者。
- `A/cssearchableitem.txt:12—19`：条目唯一标识 App 内容的一部分，并提供 Spotlight 索引与后续查找所用的元数据；「随后可以用 Core Spotlight API 执行查询来找到你索引过的条目，人们也可以用系统的 Spotlight 搜索界面找到你 App 的内容」。

`A/cssearchableitem.txt:216/218` 的 `relatedAppEntityIdentifier` 把索引项与 App 实体连起来；`:242/244` 的 `CSSearchableItemActivityIdentifier` 是「在用户活动对象里访问某条可搜索项所用的键」；`:228—230` 的 `updateListenerOptions` 规定「向 Spotlight 请求哪几类通知」。`A/searchableitem.txt:20—21` 另有一条并发口径：`SearchableItem` 是线程安全类型，其值可在任意并发上下文共享而不引入数据竞争。

属性集一侧，`A/cssearchableitemattributeset.txt`（1,746 行）逐条列出条目可携带的字段，其中三条对归属最要紧：`:299` `contactKeywords`（联系人关键词）、`:346` 文件内容最后修改日期、`:418` `creator`，以及 `:1227`「表示内容创建者的角色」。

### 5.2 这一格由哪一件持有

**声明件**——三元组全部由 App 自选。这带来一个必须写清的结构性事实：**条目的身份不来自平台，也不来自内容本身，而来自开发者选定的字符串。** `uniqueIdentifier` 是「App 内唯一」，`domainIdentifier` 是可选，于是同一个 App 里两条内容是否可区分、按域删除能不能圈准，完全取决于开发者当时怎么填。

### 5.3 谁读得回它

按标识符与按域这两种删除粒度直接把三元组当读回键：`A/cssearchableindex.txt:116`「Removes from the index all items with the specified identifiers」、`:100`「Removes from the index all searchable items associated with the specified domain」；Obj-C 侧对应 `:356` 与 `:354`。查询侧 `A/corespotlight_csuserquery.txt:24—29` 说查询参数用一个上下文来配置。也就是说三元组在删除通道上是**可寻址**的，但在观测面上不可枚举——没有任何公开文档给出「列出当前索引里所有 uniqueIdentifier」的接口。

### 5.4 台账字段与信号口径

三元组的登记要区分三件事：**填了**、**填得能圈准**、**此刻还在**。第二件事决定删除粒度能不能落地，第三件事决定归属表述能不能对外。

**台账字段**：`id.item_uid`、`id.domain_id`、`id.type_identifier`、`cap.content_owner`、`doc.source`、`doc.line_ref`。
**信号口径**：脚本一 A 族的身份形态检查（标识符形态、点分段类型标识）与 `doc.*` 缺失（X01，408 行）；脚本二对 `item_uid`／`domain_id`／`type_identifier` 三项按公开词形与标识形态双检（M01/M02），并把「声明了这一项但通道件一条没有」落进 T 族差集。

---

## 6. L3 资格层：四个资格位与公开索引那一个

### 6.1 这一格的公开口径

四个资格位各自一句文档，且**互相独立**：

| 资格位 | 归档 | 公开说明 |
| --- | --- | --- |
| `isEligibleForSearch` | `B/nsuseractivity.txt:331/333/336` | A Boolean value that indicates whether to add the activity to the on-device index |
| `isEligibleForPrediction` | `:319/321/324` | A Boolean value that determines whether Siri can suggest the activity as a shortcut |
| `isEligibleForPublicIndexing` | `:325/327/330` | A Boolean value that indicates whether the activity is publicly accessible by all iOS users |
| `isEligibleForHandoff` | `:313/315` | A Boolean value that indicates whether the activity can continue on another device using Handoff |

`B/nsuseractivity.txt:34` 「enable the features your activity supports such as Handoff and Spotlight indexing」把这四位放在同一个对象上；`:249/251` 的 `expirationDate` 说明是「该日期之后此活动不再具备 Handoff 或索引资格」——**到期同时关掉两个资格**，这是四格里唯一一处「一位变动由时间触发」的口径。`:337/339` 的 `keywords` 是「一组本地化关键词，能帮助用户在检索结果里找到该活动」；`:379/381` 的 `requiredUserInfoKeys` 决定「关于该活动的最小信息中，哪几把键应当被存储以便日后恢复」。

Core Spotlight 侧的对应口径是 `A/corespotlight.txt:26—27`（加入设备侧索引，并**可选择**标识条目是否适合公开索引）与 `A/adding-…:206`（一个布尔值，指示是否把该活动加入设备侧索引）。

`isEligibleForPublicIndexing` 单独值得一段：`:325` 的措辞是「publicly accessible by **all iOS users**」。这条与 `A/corespotlight.txt:30` 的 web markup 口径呼应——用网页标记索引服务器上的内容会进入 Apple 的**服务端索引**，使该数据对所有 iOS 用户在 Spotlight 与 Safari 检索结果里可用。两者是同一件事的两个入口：一个从设备上把某条内容标成公开，一个从服务器上把内容交给服务端索引。

### 6.2 这一格由哪一件持有

资格位本身在**声明件**（App 设置），资格位的效果在**通道件**（平台按资格位放行或不放行）。这就是失败点 2 的确切位置：`isEligibleForSearch=true` 是 App 的一句话，「这条查询能不能命中它」是系统的另一次判定，二者之间没有任何换算。

Secure index 一侧还有第三条独立口径：`A/adding-…:80—82`「如果你需要索引更敏感的数据，例如某人的联系人信息，请创建一个更安全的索引」，`:76—79` 给出「主索引放通用目录、单独索引放私人歌单」的分法，`:86—88` 与 `A/cssearchableindex.txt:25` 则两次明令默认索引只能用于原型与测试。`A/cssearchableindex.txt:18—21` 说明自定义索引支持数据保护，可加密数据并防止未授权访问——**保护等级也是这一层的格，不是 L1 的格**。

### 6.3 谁读得回它

只有一格勉强算读数：`A/cssearchableindex.txt:266—272` 的 `isIndexingAvailable`——「返回一个布尔值，指示当前设备上索引是否可用」。注意它的粒度：整台设备，不是某个条目、不是某个索引。文档里**没有**条目级的可查询状态读数。

第二处间接读数来自结果本身：查询命中（`A/corespotlight_csuserquery.txt:52` 的批次回调、`:72—74` 的结果对象）说明这一格此刻在面上；未命中**不能**说明不在面上——因为查询还有属性白名单（第 7 章）、最大条数（`:35—41`）与排序（`:13—16` 的 ranked/unranked）三个变量。所以台账里 `query_result` 只有三个合法取值：`hit`、`no_hit`、`not_run`，而「no_hit 不等于不在面上」必须由脚本二的 V 族口径检查强制登记。

### 6.4 台账字段与信号口径

**台账字段**：`cap.eligible_for_search`／`_prediction`／`_public_indexing`／`_handoff`、`id.index_kind`、`id.protection_class`、`obs.plane`、`obs.field_read`。
**信号口径**：脚本一 B 族（294—312 行）专门处理「资格位为真但没有对应开关或闸门读数」「用默认索引承载生产内容」「保护等级缺失或不合法」；D 族（333—344 行）处理公开索引资格与范围表述的冲突；脚本二的 M01 按公开词形校验 `eligibility_decl`（四个资格名加 `none`），T 族检查「声明了公开索引资格、通道件与观测件两格皆空」。

---

## 7. L4 属性层：查询只取回被请求的那几格

### 7.1 这一格的公开口径

三条句子构成这一层的全部：

- `A/corespotlight_searching-for-information-in-your-app.txt:7—9`「不要自建搜索工具，用 Core Spotlight API 索引内容并使用框架提供的查询取回信息」；
- `:13—15`「在这个查询对象上，你指定要匹配条目的哪些属性，以及什么值构成匹配」；
- **`:22—24`「执行查询时，系统不会自动取回每个属性……它只取回你明确请求的属性」**；
- `:29—30` 举例：要拿标题与显示名，就得把 `title` 与 `displayName` 这两个字符串列进去。

`A/corespotlight_building-a-search-interface-for-your-app.txt`（258 行）与 `A/corespotlight_csuserquery.txt` 一起补出另一半：`:24—29` 说查询参数用 `CSSearchQueryContext` 配置（`:61/63—64`），`:65` 列出「查询中使用的建议种类」，`:13—16` 说明可返回排序或不排序结果并可用于取建议列表。

### 7.2 这一格由哪一件持有

**通道件**——由发起查询的那段代码持有。这是本篇三件切分里最容易误读的一格：属性层既不是写入方决定的（它决定的是索引里存了什么），也不是平台决定的（平台决定放行与场景门），而是**读取方的代码决定了这次能看见哪几格**。`attributes_requested` 与 `max_results` 两格因此都属于通道件而不属于声明件。

发起方可以是四种：App 自己（`:7—9` 的框架提供查询）、系统 Spotlight（`A/corespotlight.txt:3`）、快捷指令与建议面（`A/appintents.txt:13`「Spotlight helps people navigate to your data directly from search results」）、基础模型（`A/spotlight-search-tool.txt:3—4/81`）。`A/corespotlight_csuserquery.txt:35—41` 的「不指定最大条数就一直跑到返回全部结果」在这四种发起方下含义不同——这是本篇把 `max_results` 独立列一格的原因。

### 7.3 属性层的字段承载面

`A/cssearchableitemattributeset.txt` 1,746 行逐条列出可承载字段，构成「一个条目可能被读回哪些格」的证据面。对归属最要紧的四组：

| 字段类 | 归档行 | 归属含义 |
| --- | --- | --- |
| 人物指向 | `:299` `contactKeywords`、`:418/422/1584` `creator`、`:1227` 创建者角色 | 条目可携带指向真实人物的字段；这些字段一旦入索引，可查询面就包含「按人查」 |
| 时间指向 | `:346` 文件内容最后修改日期 | 时效判定（L11）与再索引触发都读这一类 |
| 展示指向 | 标题、显示名、关键词、内容描述、缩略图（`A/corespotlight_searching-…:29—30` 举例的前两项） | 请求制：不列就不回 |
| 类型指向 | `A/generating-summary-…:36—39`「该类型必须是 message／email／audio-transcript 类型，Apple Intelligence 不处理其他类型的条目」 | 摘要与优先级生成按类型限定，是属性层里唯一一处类型硬门 |

摘要与优先级那一格还有独立的口径：`A/generating-summary-…:17—23`「Spotlight 只为你指定的对象返回摘要与优先级数据……要求你**逐条**启用摘要与优先级信息生成，以减少对系统性能与续航的影响」；`:6—11` 说明「当你索引 App 的邮件或消息线程、或 App 的音频转录时，可以要求 Spotlight 借助 Apple Intelligence 摘要这些内容，也可以要求它对 SMS 消息分类优先级，Spotlight 异步把这些请求的结果返回给你」；`:12—15` 说明 App 会用这些摘要与优先级增强自己的界面。这一串合起来给出一个双层结论：**是否生成摘要由逐条资格位控制，生成结果回给谁由 API 决定（回给 App），而不是回给用户或系统面。**

### 7.4 台账字段与信号口径

属性层要求把「请求了哪几格」和「回回了哪几格」分开登记，否则查询命中一次就把整层当成可读，是最典型的假闭合。

**台账字段**：`op.attributes_requested`、`op.max_results`、`op.query_api`、`op.actor`、`op.plane_target`、`obs.field_read`。
**信号口径**：脚本一 C 族（313—332 行）覆盖查询发起方、通道与结果格缺失；脚本二 M01 按公开词形校验 `attributes_requested`（`displayName`／`title`／`keywords`／`contentDescription`／`thumbnailURL`）与 `max_results`（`unset`／`default` 或 1—4 位数字，由 M01 独检，V02 显式不重复告警）。

---

## 8. L5 建议与捐赠层：活动、意图捐赠与实体

### 8.1 这一格的公开口径

三种不同的「让系统知道用户做过什么」的形态，文档里分属三份归档：

**用户活动（Handoff／Spotlight 索引）**：`B/nsuseractivity.txt:14` 「like Handoff and Quick Notes…」与 `:34` 「enable the features your activity supports such as Handoff and Spotlight indexing」；`:39—40` 「Handoff 与其他特性在当前活动上运作，并把它当作其行为上下文」；`:46` 「要让 Handoff 生效，系统需要知道它可以把哪几类活动交付给你的…」；`:388/390` 「把这个活动对象标记为非活动，但不使其失效」与 `resignCurrent`；`:301` 「Invalidate」— 使活动失效并标记其不再具备继续资格。

**意图捐赠**：`B/intents.txt:7—8`「Intents 是你用来支持与 Siri、快捷指令与小组件交互的框架。为特定动作用户可以触发的事件定义自定义意图，并**捐赠意图以帮助 Siri 随时间学习用户的习惯并建议相关快捷指令**。你还可以提供快捷指令建议，出现在快捷指令 App 或 Siri 的推荐中，以提升可发现性」；`:5—6`「SiriKit、Intents 与 IntentsUI 继续为快捷指令动作、小组件配置与既有 Siri 交互提供遗留支持；要实现这些特性的现代支持并与 Apple Intelligence、Siri AI 集成，请使用 App Intents 框架」；`:9` 说明 SiriKit 按 App 类型把意图分域；`:3` 说明这个框架让人在**其设备上**定制与该 App 的交互。

**App 实体与可发现性**：`A/appintents.txt:3`「让内容与动作可被 Apple Intelligence 发现，并支持 Siri、Spotlight、快捷指令与小组件这类系统体验」；`:10—11`「用结构化方式表达 App 的动作与数据，使它们可被 Apple Intelligence 发现，并 People 常用系统特性提供更深的集成」；`:12`「人们可以通过 Siri 与你的 App 内容交互」；`:13`「Spotlight 帮助人们直接从检索结果导航到你的数据」；`:14`「快捷指令 App 帮助人们配置包含你的 App 动作的工作流」。协议约束在 `A/appintents_appentity.txt:5—18`：实体类型必须同时满足 `AppValue`／`DisplayRepresentable`／`Identifiable`／`EntityIdentifierConvertible`——既要能展示也要能标识，才可能被系统侧检索。

### 8.2 这一格由哪一件持有

**声明件 + 通道件各一半**，且两半的持有人不同。捐不捐、实体可不可发现是 App 决定（声明件）；捐了之后 Siri 是否据此建议、建议出现在哪一面是平台决定（通道件）。`A/cssearchableindex.txt:294—297` 把 `AppEntity` 直接放进 Core Spotlight 索引对象的关联条目里，说明「索引项 ↔ 实体」这一挂接在文档层面是一格（`:216/218` 的 `relatedAppEntityIdentifier`），但它是**声明件里的一格**，不是观测件——没有任何公开读数面会告诉你「这个实体现在对 Siri 可发现」。

### 8.3 词汇表上送：这一层唯一一条明确出设备的口径

`B/apple-platform-security-guide.txt:4261`（PSG 归档）：「支持 SiriKit 的 App 可以向 Siri 发送 App 特定或用户特定的词汇……这些信息让 Siri 的语音识别与自然语言理解能够识别该 App 的词汇，并与一个**随机标识符**关联。**这些自定义信息在该标识符使用期间保持可用，或者直到用户在设置里关掉该 App 的 Siri 集成，或者直到这个支持 SiriKit 的 App 被卸载。**」

这一句同时给出三件事：上送的是**词汇**不是内容；关联方式是**随机标识符**；留存终止条件有三个（标识符不再使用／用户关闭该 App 的 Siri 集成／App 卸载）。这是本文唯一一处「检索面相关的远端存量有明确失效条件」的公开口径，因此也是第 16 章把它单列为一条读数的原因。`A/cssearchableitemattributeset.txt` 的 `contactKeywords`（`:299`）与 `:418` 的 `creator` 是本地属性面，绝不能与这条词汇面口径混写成同一格。

### 8.4 台账字段与信号口径

这一层的对象类要分三种登记，不能都写成 `app`：`user_activity`、`intent_donation`、`app_entity`。脚本二对这三类各自给了 required 集合（`FX/capability-17.csv` 168 数据行中，`user_activity`／`intent_donation`／`app_entity` 三类共占 63 行）。

**台账字段**：`id.obj_kind`（后三类）、`cap.usage_notice`、`cap.secure_index`、`when.expires_at`、`undo.original_data_gone`。
**信号口径**：脚本一 A 族与 V 族（371—390 行）覆盖「活动失效与索引删除是否分别登记」；脚本二的 `index_kind` 公开词形枚举里 `nsuseractivity`／`intent_donation`／`app_entity` 是三个独立取值，把三者混为一谈会触发 M02。

---



---

## 9. L6 服务端边界层：本机索引不上送与检索词上送是两件事

### 9.1 这一格的公开口径

这一层有**四处彼此独立**的公开表述，各自覆盖一段不同的通路。把它们列全，是避免失败点 4 的唯一办法。

| 通路 | 归档行 | 公开口径要点 |
| --- | --- | --- |
| Core Spotlight 索引 | `A/corespotlight.txt:22—23` | 用 Core Spotlight 建立的索引留在设备上，对设备所有者私有；设备不与 Apple 共享索引数据，也不把它与该人的其他设备同步 |
| 网页标记索引 | `A/corespotlight.txt:30` | 用网页标记索引服务器上的内容，进入 **Apple 的服务端索引**，使该数据对所有 iOS 用户在 Spotlight 与 Safari 检索结果里可用 |
| 用户活动公开资格 | `B/nsuseractivity.txt:325/327` | 该活动是否**对全体 iOS 用户公开可访问** |
| 建议面个性化 | `B/siri-dictation-legal.txt:64—65` | Suggestions 用本地设备侧处理学习你如何使用设备与 App；用设备上存的信息（Safari 浏览历史、邮件、消息、图像、通知、通讯录，以及其他已安装 App 捐赠或贡献的信息）来建议快捷指令并在搜索、分享面板、日历、查询、视觉查询、Safari 等处提供建议；**Suggestions 可用于个性化 Apple 服务，但不存储在 Apple 服务器上，也不与其他第三方 App 共享；当你运行一个 Siri 建议的快捷指令时，受该 App 的条款约束** |
| 检索请求 | `B/siri-dictation-legal.txt:28/34`、`B/legal-siri-suggestions-search.txt:28/35` | 像播放某张专辑或检索世界知识这类 Search 请求，其查询串**会被 Apple 存储并用于改进 Search、Siri 与相关功能**；可在设置里关掉 Help Apple Improve Search |
| iCloud.com 上的搜索 | PSG `:2749—2752` | iCloud.com 的搜索让 iCloud 网页应用从一个网页会话搜索用户已同步的 iCloud 文件，**这种搜索使用用户 iPhone／iPad／Mac 上的本地索引，使 iCloud.com 无需在 iCloud 服务器上提供一份索引**；四条保护：多层加密认证、会话绑定、用户同意；**没有用户明确选择加入就不会在设备上执行任何搜索查询**；除非设备独立授权该 iCloud.com 会话的请求，否则不返回结果；连接范围限定为仅访问跨 iCloud 同步的文件的索引数据，**仅本地的文件不可访问**；需要 iCloud 双重认证，且不适用于托管 Apple 账户 |

最后一行值得单独强调：这是全套公开文档里**唯一一处「设备侧索引被远程查询」**的成文口径，而且它的授权模型是「设备独立授权 + 密码学配对键」（PSG `:2759—2762`：网页浏览器与授予索引访问的设备之间需要建立密码学配对键；握手成功之前设备不处理任何搜索请求；浏览器周期性向 Apple 服务器请求一个令牌，确认该会话登录了用户的 Apple 账户且与配对键绑定的是同一个会话）。

### 9.2 这一格由哪一件持有

三段分属三件：**索引存量**由声明件（谁写的）与设备共同持有；**查询串出不出设备**由平台与告知口径持有，属于通道件；**远端授权模型**由平台持有。台账里把这三段合成「本地索引不上传」一句，就是失败点 4。

Siri AI 那一段另给了一个分叉：`B/siri-dictation-legal.txt:33`——如果选择启用 Siri AI，请求可能在设备上处理，也可能发送到 Private Cloud Compute，而在 Private Cloud Compute 处理的数据不存储、Apple 也访问不到，不使用设备上 App 的信息；**如果不选择启用 Siri AI**，尽可能在设备上处理，并可能提供来自 Search 的相关且最新信息。同页 `:37` 还有一条读数口径：设备会在 Siri 设置或键盘设置里指示你说的内容是在设备上处理还是发送给 Apple；`:38` 说明 Apple 还会存储与请求相关的数据（请求类别、是否成功完成、设备规格、设备配置、性能统计）；`:39` 说明这些属于 Siri 与听写请求历史的一部分，Apple 可以保留并使用**至多两年**。

### 9.3 谁读得回它

只有告知页与设置路径：`B/legal-siri-suggestions-search.txt:49`（不想让检索词被 Apple 存储并用于改进 Search，可到 设置 > Search 关闭 Improve Search）、`:50`（关闭 Show Recent Searches 与 Show Related Content）、`:51`（在 隐私与安全 > 定位服务 > 系统服务 里关掉 Search 的定位）、`B/siri-dictation-legal.txt:80`（在 系统服务 里关掉 Suggestions & Search 的定位）。`:30` 那句「Search 旨在保护你的信息并让你选择分享什么」是这一层的总口径。

**没有 API 读数。** 这一层可登记的只有「告知页写了什么 + 设置项当前状态 + 该状态的核对时刻」三格。

### 9.4 台账字段与信号口径

**台账字段**：`scope.reach`、`scope.sync`、`scope.field_carried`、`cap.usage_notice`、`doc.notice_basis`。
**信号口径**：脚本一 N 族（403—407 行）三码全部围绕这一层——N01 要求对外结论、设置面读数或告知页引用必须登记告知依据；N02 拒收「厂商说法」作为对外结论依据；**N03 专查失败点 4**：用「Siri 请求不与 Apple Account 关联」闭合「本机索引不上传」。D 族（333—344 行）检查公开索引资格与 `scope.reach` 是否互相矛盾。

---

## 10. L7 场景门层：锁定、外部智能、听写出设备与专注压制

### 10.1 这一格的公开口径

场景门是一组「同一条内容在不同场景下可查询面不同」的判定，共四道：

**门 1：锁定。** `B/mdm-restriction-keys.txt:24` `allowAssistantWhileLocked`（对应 `B/mdm-restrictions.txt:112`「锁定时禁用 Siri」）；`:22` `allowAssistant`、`:23` `allowAssistantUserGeneratedContent`（`:96`「Siri 关闭」、`:104`「Siri 不得查询用户生成内容」）。锁屏前助理是否可用决定锁屏前检索面是否可用——这是本篇从第 05 篇借来的唯一一条口径，本文不解释它由哪种生物特征判定。

**门 2：外部智能与 Siri AI。** `:70` `allowExternalIntelligenceIntegrations`、`:71` `...SignIn`、`:141` `allowSiriAI`（`B/mdm-restrictions.txt:356`「外部云端智能」、`:780`「Apple Intelligence 集成」）。这一道门改变的是**处理位置**（设备侧／私有云／外部服务），从而改变 `scope.reach`。

**门 3：听写与翻译是否出设备。** `:196` `forceOnDeviceOnlyDictation`、`:197` `forceOnDeviceOnlyTranslation`、`:61` `allowDictation`（`:294`「禁用听写」）。告知侧对应 `B/siri-dictation-legal.txt:37`（设备会指示你说的内容是否在设备上处理而不发送给 Apple，否则发送并由 Apple 处理；音频数据除非你选择加入否则不被 Apple 存储）与 `:58`（如果你允许 App 使用语音识别做转录，待转录的音频数据可能发送给 Apple）。

**门 4：内容过滤与结果范围。** `:182` `forceAssistantProfanityFilter`（`:979` 脏话过滤）、`:143` `allowSpotlightInternetResults`（`:796` Spotlight Internet 结果）。后者直接决定一次检索是否走网络结果——它是本篇唯一一处「检索面是否延伸到服务端」的可配置开关。

### 10.2 这一格由哪一件持有

**通道件**，由平台判定、由管理面或用户设置。写入方对此**没有任何一项权利**：App 能声明资格位，不能声明「锁定后也要放行我这条内容」。这一点与第 16 篇形成对称——16 篇里管理面不能配置那一格，本篇里管理面**能**配置但只能配成开关，不能逐项审阅。

`B/mdm-restrictions.txt:1250+` 处的 `com.apple.configuration.siri.settings` 是这一层的声明式接管位置；`B/mdm-siri-keys.tsv` 登记的 **10 个**旧 Siri 相关限制键全部标注 Deprecated 并指向该声明式类型。这个迁移状态本身要进台账（`mgmt.migration_state`），因为它决定同一句限制在不同版本上由哪个平面给出。

### 10.3 谁读得回它

`B/siri-dictation-legal.txt:37` 给出设备侧指示（Siri 设置或键盘设置里指示是否本地处理）；`A/cssearchableindex.txt:266—272` 给出设备级索引可用性。除此之外没有编程读数——文档不提供「当前场景门状态」的 API。因此脚本二把「读数平面 = `settings_ui` 但核对项是条目级的可查询性」判为平面越界（P 族）。

### 10.4 场景门的组合后果：一条资格读数能推出的六种结论

同一条 `isEligibleForSearch=true` 的读数，叠上门 1 与门 2 的两种取值，可得六种对外表述，其中只有两种是完整的：

| 门 1（锁定可用） | 门 2（外部智能） | 可成立的对外表述 |
| --- | --- | --- |
| 开 | 开 | 锁屏前后可查，处理位置需按 `B/siri-dictation-legal.txt:33` 分别登记 |
| 开 | 关 | 锁屏前后可查，尽可能设备侧处理 |
| 关 | 开 | **只能**说解锁后可查；锁屏前的检索面不能写「不存在」，只能写「该场景不放行」 |
| 关 | 关 | 同上，且处理位置口径为设备侧 |
| 未登记 | 任意 | 不得对外表述（脚本一 J3） |
| 任意 | 未登记 | 不得表述处理位置（脚本二 Q3） |

**台账字段**：`state.siri_state`、`state.suggestions_state`、`state.decided_by`、`state.decided_at`、`state.toggle_visible`、`gate.owner`、`gate.basis`、`mgmt.restriction_key`。
**信号口径**：脚本一 B 族检查三态与决定主体；G 族（391—402 行）检查限制键是否在公开词表里、迁移状态是否登记；脚本二的 P 族检查场景门读数挂在哪个平面。

---

## 11. L8 告知层：三页告知文本与可选加入

### 11.1 这一格的公开口径

面向用户的原话集中在**三份文档**，超出这三份都要另找出处（脚本一 N01 的设计依据）：

1. **Ask to Siri & Dictation**（`B/siri-dictation-legal.txt`，154 行）：`B/siri-dictation-legal.txt:28/31/33/37/38/39/41/48—49/58/63/64—65/69/72/73/76/80/81/82/100` 逐条覆盖关联标识、请求处理位置、存储与留存、建议面来源、端到端加密同步、关闭即删转录、逐 App 建议开关、定位系统服务、语音识别授权、政府信息请求。
2. **Siri Suggestions & Search**（`B/legal-siri-suggestions-search.txt`，124 行）：`:28/30/31/32—33/34/35/36/37—38/39—42/44/45—47/49/50/51/52/54` 覆盖 Improve Search 的定义、「Search 旨在保护你的信息并让你选择分享什么」、发送与不关联、使用与改进、聚合信息再用于其他产品、随机抽样的一小部分检索词、向战略伙伴提供的非个人数据、Safari 引擎建议与 Preload Top Hit、视觉智能用私有云与私有信息检索使 Apple 不知道图像内容、位置分发、关闭路径与定位路径、可信第三方服务提供者处理与存储、页面日期 2026-10-30。
3. **Improve Siri & Dictation**（`B/legal-improve-siri-dictation.txt`，118 行）：`:28/30/32/33/34/35/36/38—39/40/41/43—44/46/47/48` 覆盖可选加入存的是什么（音频与文本、Siri 的回复）、随机设备生成标识每小时轮换多次、留存至多两年而**被抽检的一小部分可超过两年**、不用于建营销画像也不出售、抽检用于判定准确度、ChatGPT 扩展、关闭即删设备上转录、翻译请求留存至多两年、首设选择继承到新连接设备、同意条款、页面日期。

第四份支撑件是设置路径文档 `B/support-127070.txt`（77 行）：`:20` 说明在设置新设备或首次开启使用 Siri、听写、翻译时会被询问是否加入 Improve Siri & Apple Intelligence；`:21—24` 说明各端继承口径（Apple Watch／HomePod／Apple TV 跟随首设 iPhone）；`:28—30` 给出 iOS 路径 隐私与安全 > 分析与改进 > 开关；`:32—34`／`:36—38`／`:40—43`／`:45+` 分别给出 macOS／watchOS／HomePod（由 Home 组织者经 Home App 调整）／Apple TV 的路径。

### 11.2 这一格由哪一件持有

**观测件**。告知文本不是声明件——App 不能改它；也不是通道件——它不改变放行逻辑。它是唯一一处「用户侧可核对的口径来源」，因此在三件法里承担闭合表述的最后一格。

### 11.3 告知层的三条硬口径

- **留存上限两条不同**：Siri 与听写请求历史至多两年（`B/siri-dictation-legal.txt:39`、`B/legal-improve-siri-dictation.txt:34`），但被抽检的一小部分是「可以超过两年」；翻译请求另有一条至多两年（`:43—44`）。台账里把「两年」写成统一口径是错的。
- **关闭即删只覆盖转录**：`B/siri-dictation-legal.txt:72` 的删除对象是「设备上存储的、用于个性化体验的 Siri 与听写请求**转录**」，不是索引项。**这条与第 14 章的索引删除是两件不同的事**，混用是本篇第十二个误区。
- **建议面不上服务器，但运行建议的快捷指令受第三方条款约束**：`:64—65` 两句在同一行里，必须一起引用。

### 11.4 台账字段与信号口径

**台账字段**：`cap.usage_notice`、`doc.notice_basis`、`obs.plane=notice_page`、`obs.read_at`、`when.state_checked_at`。
**信号口径**：脚本一 N 族；脚本二的 `notice_page` 取值枚举（`siri_dictation_legal`／`improve_siri_optin`／`speech_recognition`／`none`）与 `usage_notice` 的公开词形由 M01 校验，引用形态由 V01/V02 校验。

---

## 12. L9 观测平面层：这一格是谁读回来的

### 12.1 九个平面与各自能承载的格

| 平面 | 能读回的格 | 依据 |
| --- | --- | --- |
| `core_spotlight_api` | 索引名与保护等级、删除接口调用、查询发起、`isIndexingAvailable` | `A/cssearchableindex.txt:242/251/263/266—272` |
| `app_intents_schema` | 实体的可发现性声明、动作与数据的结构化表达 | `A/appintents.txt:10—11`、`A/appintents_appentity.txt:5—18` |
| `nsuseractivity_api` | 四个资格位、活动失效、按键删除 | `B/nsuseractivity.txt:301/313/319/325/331/230` |
| `web_markup_source` | 服务端索引的内容来源 | `A/corespotlight.txt:30` |
| `settings_ui` | 开关与逐 App 建议列表、定位系统服务项 | `B/siri-dictation-legal.txt:76/80/81/82`、`B/legal-siri-suggestions-search.txt:49/50/51` |
| `configuration_profile` / `mdm_declaration` / `declarative_management` | 11 个限制键、`com.apple.configuration.siri.settings` | `B/mdm-restriction-keys.txt:22—197`、`B/mdm-restrictions.txt:1250+` |
| `advisory_component` | 组件存在性与 CVE 归属 | `C/advisory-17.tsv` 1,266 条、`C/query-plane-17.tsv` 68 行 |
| `query_response` | 一次查询是否命中、回了哪几格 | `A/corespotlight_csuserquery.txt:52/72—74` |
| `notice_page` | 云端边界与留存口径 | 第 11 章三页 |
| `vendor_claim` / `app_self_report` | **不承载任何对外表述** | 脚本一 N02、脚本二 P 族拒收 |

### 12.2 「没有通用读点」把这一层变成投影层

这一层的核心事实是：**没有任何一个面能读回「这条内容当前是否在检索面上」。** 每个面只能读回自己那一格，因此可查询面只能由多面投影拼出。这与第 16 篇的「没有通用接口能读回当前进程有没有本地网络权限」结构相同，但后果更严重：16 篇缺的是**状态**读数，本篇缺的是**存量**读数——不但不知道状态，连面上现在有几条都不知道。

三条由此产生的时间不对称必须登记：

1. **写入与落面之间**：`A/adding-…:91` 说明是异步并入并在完成时通知。
2. **改判与生效之间**：管理面关掉 `allowAssistant` 之后，检索面变化没有回执；`B/mdm-restrictions.txt:1250+` 的迁移状态进一步使同一句限制在不同版本上由不同平面给出。
3. **删除与可证之间**：`A/adding-…:67—72` 只保证系统按期过期条目；再索引回调（`A/corespotlight_cssearchableindexdelegate.txt:76`）可以要求 App 清掉本地状态重建索引——此时先前的所有观测读数全部作废。

### 12.3 谁读得回「谁在读」

只有 App 自己的查询回调能证明「这次是这段代码发起的」；系统 Spotlight、快捷指令、基础模型三种发起方的读数**不回到写入方**。`A/spotlight-search-tool.txt:81`「Give a language model access to your app's Core Spotlight index to enable natural-language queries over searchable content」说明基础模型可以自然语言查询你的索引；`:15` 的 `ContactResolver` 是「帮助你用 App 的人被引用时协助基础模型解析」的接口——这意味着**人物指向字段可以被模型侧解析**，是属性层（第 7 章）与观测层的一处直接接缝，台账必须把它登记成独立一格而不是并入 `attributes_requested`。

### 12.4 台账字段与信号口径

**台账字段**：`obs.plane`、`obs.field_read`、`obs.read_at`、`obs.list_visible`、`obs.command_name`、`gate.read_back_api`。
**信号口径**：脚本一 O 族（359—370 行）检查平面与字段是否匹配、读数时刻是否缺失、命令名字段是否填了设备侧命令（拒收）；脚本二 P 族六码专查平面越界，T 族六码查两平面读数互相矛盾，V03 查同一对象类同一核对项在不同对象间既「已读数」又「明确不存在」（口径未统一，不阻断）。

---

## 13. L10 管理与公告回查层：11 个限制键与 68 行子词表的列间错位

### 13.1 管理面读数：216 个键里只有 11 个与检索面有关

`B/mdm-restriction-keys.txt` 从限制文档的 `"name"` 字段全集导出，**220 行文件、216 个键名**（正文与台账一律写 216，不得写 220——这是行数与键数的固定差）。按子串筛与检索面相关的键，命中 11 个：

| 行 | 键 | 管的到底是什么 |
| --- | --- | --- |
| 22 | `allowAssistant` | 助理整条通道的存在 |
| 23 | `allowAssistantUserGeneratedContent` | 助理能否查询用户生成内容 |
| 24 | `allowAssistantWhileLocked` | 锁定场景门 |
| 61 | `allowDictation` | 听写通道 |
| 70 | `allowExternalIntelligenceIntegrations` | 外部智能接入 |
| 71 | `allowExternalIntelligenceIntegrationsSignIn` | 外部智能登录 |
| 141 | `allowSiriAI` | Siri AI 开关（对应告知页 `B/siri-dictation-legal.txt:33` 的「选择启用」） |
| 143 | `allowSpotlightInternetResults` | 检索是否延伸到网络结果 |
| 182 | `forceAssistantProfanityFilter` | 内容过滤 |
| 196 | `forceOnDeviceOnlyDictation` | 听写是否出设备 |
| 197 | `forceOnDeviceOnlyTranslation` | 翻译是否出设备 |

**这 11 个键没有一个是「索引项级」的。** 全部形如 `allow*`／`force*`，即「允许或强制某条通道」；不存在任何键名含 `index`、`spotlight-index`、`searchable` 或等义写法。这条负空间读数与第 16 篇的「220 键里没有 Bonjour／Multicast／Peer」同构，但结论不同：16 篇据此说**管理面不能配置这一格**，本篇据此说**管理面只能整条关掉通道，不能审阅面上有什么**。

声明式接管与迁移状态：`B/mdm-siri-keys.tsv` 登记 **10** 个 Siri 相关旧键（键名→说明成对），全部标注 Deprecated 并迁往 `com.apple.configuration.siri.settings`（`B/mdm-restrictions.txt:1250/1252/1254/1406/1449`）。也就是说，这一层的管理面形态正在从「限制载荷里的散键」迁移到「声明式类型」，台账必须登记 `mgmt.migration_state`，否则同一句限制在两台设备上的读数平面不同。

### 13.2 公告面读数：68 行的列间错位

基线 `C/advisory-17.tsv`：1,267 行 = 表头 + **1,266 条**记录，来自 12 篇安全发布（各发布条数 134/1/1/163/263/213/197/72/62/125/33/2），`component` 列去重 **129 个组件名**，唯一 CVE **330 个**。

按组件列**全等**筛出检索面子集（不做子串匹配——`Siri` 按子串会误吞 `SiriKit`）：

| 读数 | 数值 |
| --- | --- |
| 子集行数 | **68**（`C/query-plane-17.tsv` 69 行含表头） |
| 组件分布 | Spotlight 26、Shortcuts 16、Siri 15、Apple Intelligence 4、App Intents 4、Help Viewer 3 |
| 去重 CVE | 20（Siri 7、Spotlight 6、Shortcuts 3、Apple Intelligence 2、App Intents 1、Help Viewer 1） |
| 平台发布分布 | macOS Sequoia 15.8.2 13、macOS Tahoe 26.7.2 12、macOS Golden Gate 27.2 12、iOS/iPadOS 27.2 9、visionOS 27.2 7、watchOS 27.2 6、iOS/iPadOS 26.7.2 5、tvOS 27.2 4 |
| 影响句句式 | 越权访问敏感数据 44、绕过 10、提权 4，另有访问用户敏感数据／信息类 6、物理访问 1、拒绝服务 1、远程访问 1、通知内容 1 |

**中心读数：把这 68 行只取 `impact` 列做不区分大小写子词计数，`index`／`indexing`／`search`／`suggest`／`shortcut`／`Siri`／`Spotlight`／`dictation`／`query`／`consent`／`credential` 全部 0 次命中；只有 `contact` 4 次、`lock` 1 次、`notification` 1 次。**

同一批 68 行的 `component` 列却明确写着 Spotlight／Siri／Shortcuts（合计 68）。也就是：**检索面的存在性由组件列承载，后果描述里一个字都不提。** 第 15、16 篇处理的是「平面在两列都缺位」，本篇是「一列有、一列无」——防守方若按影响文本做关键词筛选，这一整层 0 命中。这正是脚本二 X04 信号码的判定内容：以 FACE 词形（spotlight／siri／shortcuts／intents／intelligence／help）匹配到 6 个具名组件，而 ENTRY 词形（searchable／csssearchable／indexitem／donation／entity／attributeset／reindex）在组件列 **0** 命中。

影响句去重后只有 **9 句**，且高频写法分叉，匹配器必须容错：`An app may be able to access sensitive user data` 44 次 vs `…user-sensitive data` 3 次；主语分叉 `An app` 54 次 vs `A malicious application/app` 11 次。其余为 `bypass Privacy preferences` 10、`gain elevated privileges` 4、`A remote attacker …` 1、`An attacker with physical access … access contacts from the lock screen` 1、`cause a denial-of-service` 1、`access notifications from other iCloud devices` 1。

### 13.3 相邻但排除的平面

同一批公告里另有 `Model I/O` 43 行、`Apple Neural Engine` 10 行（影响句形如「Processing a maliciously crafted 3D model…」，属解析器平面，其中 29 行）、`Screen Time` 3 行。**这些不属于本篇**：模型执行栈与设备侧推理归属是下一篇的客体。本篇只在视角声明里划界，不引用其读数——脚本二的公开词表也不加载这些组件名，避免把解析器平面读数错挂到检索面上。

### 13.4 这一格由哪一件持有，谁读得回它

管理与公告两面都是**观测件**，且都是**唯一不能由 App 影响**的两面。它们的读数形态互不相同：管理面读「这台设备允不允许」，公告面读「哪个组件上出过哪个 CVE」。**两面都不读「这台设备上现在有哪些条目」。** 因此本篇的归属矩阵里，L10 这一行的证据列只能填「开关 + 组件名」，不能填「条目」——把公告组件名当条目级读数，是脚本二 X 族三码（X01—X03）的判定对象。

公开词表 `FX/vocab-17.tsv`：722 行 = 表头 + **721 条**，归一化去重 **720**（唯一一次折叠是 `Remote Management` 与 `RemoteManagement`）。类别分布 `advisory_cve` 330、`restriction_key` 216、`advisory_component` 129、`api_symbol` 32、`activity_property` 7、`declarative_type` 6、`plist_key` 1。脚本二自报「检索面具名组件=6 条目级组件名=0」，这一对数字就是本节中心读数的机器版本。

---

## 14. L11 删除与复位层：五级删除粒度与再检索证明

### 14.1 这一格的公开口径：App 侧五级删除

| 粒度 | 归档行 | 说明句 |
| --- | --- | --- |
| 全量 | `A/cssearchableindex.txt:58`（Obj-C `:352`） | Deletes all searchable items from the index |
| 按域 | `:100`（Obj-C `:354`） | Removes from the index all searchable items associated with the specified domain |
| 按标识符 | `:116`（Obj-C `:356`） | Removes from the index all items with the specified identifiers |
| 按实体标识与类型 | `:70` | Deletes entities with the specified identifiers and type from the current index |
| 按实体类型全量 | `:88` | Deletes all app entities of the specified type from the current index |

活动侧另有两把：`B/nsuseractivity.txt:230/241` 的 `deleteSavedUserActivitiesWithPersistentIdentifiers:completionHandler:`（按持久标识删除已保存活动）与 `:301` 的 `invalidate`（使活动失效并标记不再具备继续资格）。批量操作侧的状态恢复在 `A/cssearchableindex.txt:22—24`（自定义索引支持批量操作，可为每批加自定义状态信息，以便 App 或扩展崩溃后重启索引过程）与 `:357/359` 的 `endIndexBatchWithClientState:`／`endIndexBatchWithExpectedClientState:newClientState:`。

义务句两条，语义等价、分别落在条目面与索引面：`A/adding-…:67—72`（系统会自动按期过期条目，设定到期日可让系统保留到你指定的日期；**如果这个人从你的 App 里删除了原始数据，就把索引里的关联条目一并移除**）与 `A/cssearchableitem.txt:36—37`（**如果你删除了内容，也要相应从索引里删除可搜索项。保持索引最新能确保检索返回有效信息**）。

### 14.2 这一格由哪一件持有

三段分开看：**删除动作**在声明件一侧（只有写入方或它的扩展能调；`A/cssearchableindex.txt:26—28` 要求从未签名的 App／扩展访问自定义索引是编程错误）；**删除是否生效**在平台一侧，且**没有回执面**；**用户侧的删除**只有开关级——`B/siri-dictation-legal.txt:72/73/76/80/81`、`B/legal-improve-siri-dictation.txt:40` 给出的全部路径是「关掉某个开关」或「从某个列表里改选择」，其中唯一一句删除语义（`:72`）删的是**转录**，不是索引项。

`B/apple-platform-security-guide.txt:4261` 补出词汇面的三个失效条件（标识符不再使用／用户关闭该 App 的 Siri 集成／App 卸载），这是全篇唯一一处「远端存量的失效条件写在文档里」的地方。

### 14.3 复位：三种系统单方面发起的重建

1. **全量再索引并要求清本地状态**：`A/corespotlight_cssearchableindexdelegate.txt:76`（Tells the delegate to reindex all searchable data and clear all local state information），按标识符版本在 `:88`。
2. **索引缺失或需要更新数据时系统请求重建**：`A/regenerating-your-app-s-indexes-on-demand.txt:6—11`——保持索引最新需要周期性维护；**App 在更新索引时崩溃可能把索引留在不正确状态**；系统也可能在索引缺失或需要更新数据时要求 App 重新生成；如果系统在需要这些更新时 App 没在运行，就改用再索引 App 扩展来生成。`:12—14` 要求扩展能访问 App 全部可索引数据；`:25—30` 要求为关键索引函数调用确认处理器。
3. **到期自动过期**：`A/adding-…:67—72`、`A/cssearchableitem.txt:129/131`、`B/nsuseractivity.txt:249/251`。

这三种复位的共同后果是：**先前登记的一切观测读数在重建后失效**，因此 `when.reset_at` 与 `when.stale_after_days` 必须是台账字段，而脚本一的 T 族把「核对时刻早于复位时刻」判为阻断。

### 14.4 可证删除的唯一合法形态

本文允许的表述只有一种三段式：**按标识符或按域发起过删除（登记方法与时刻）+ 之后按同一标识发起过再检索且未命中 + 明确写出该未命中不排除属性请求／最大条数／场景门三个混淆变量**。三段缺一，脚本一 V 族（371—390 行）与脚本二 T 族分别降级。

`undo.*` 六格（脚本一第 27 行的命名空间）分别是 `delete_method`、`delete_actor`、`delete_verified`、`original_data_gone`、`residue_claimed`、`rebind_basis`，其中三格的合法取值在两支脚本里形态不同，必须分开登记：`undo.delete_method` 取 `delete_all`／`delete_by_identifier`／`delete_by_domain`／`delete_app_entities`／`activity_delete`／`activity_invalidate`／`expiry_only`／`uninstall`／`reindex_delegate` 九个动作值加三个控制值（第 91 行），`undo.delete_actor` 取 `app`／`user`／`mdm`／`system`／`not_determinable` 加控制值（第 92 行），`undo.rebind_basis` 取 `item_uid`／`domain_id`／`bundle_id`／`signature`／`assumed`／`not_applicable` 加控制值（第 93 行）。**`delete_verified` 在脚本一是布尔格**（`yes`／`no`／`true`／`false`／`unknown`／`not_recorded`／`not_applicable`，第 105 与 212 行），**在脚本二是核对项 `delete_verified` 的三个公开词形**（`verified`／`not_verified`／`requery_missing`，第 147 行）——同一件事两种写法，跨脚本对齐时按对象标识而不是格名（第 26 章 N3）。三段式的第三段在两处各有各的抓法：脚本一在「登记了删除方法、`delete_verified` 记为否、`residue_claimed` 记为是」时打 `V01`（第 373 行，原文是「删除是否发生只能靠再查一次，不能靠推测」）；脚本二在「`delete_verified=verified` 而 `query_result` 是 `no_hit`、明确不存在或未登记」以及「`verified` 但 `item_uid`／`domain_id` 两格都空」时打 `T05`（第 362—365 行，属阻断档）。**这里有一处残余必须坦白**：`delete_verified=verified` 与 `query_result=hit` 同时出现不会被 `T05` 抓住——`T05` 查的是「声称已验证却没有正向回读」，不查反向；反向那一格由脚本一的 `V` 族与人工评审兜，脚本二不给信号。

---



---

## 15. 归属矩阵：十一层 × 责任方 × 三件 × 证据

这张表是全文的落点。「证据」列只允许填三类形态之一（接口口径／开关口径／告知口径，见第 2.5 节），任何「实测」都不允许出现。

| 层 | 这一格答什么 | 判定权持有方 | 三件归属 | 可登记证据（归档行） | 不可登记 |
| --- | --- | --- | --- | --- | --- |
| L1 写入 | 这条内容什么时候进的面 | App／其 App 扩展 | 声明件 | 责任句 `A/corespotlight.txt:17`；两时机 `:18—19`；范围 `:19—21`；平台差 `:15` | 「此刻在面上」 |
| L2 声明 | 这条内容是谁、归哪个域 | App | 声明件 | 三元组 `A/cssearchableitem.txt:208/222/122`；挂接 `:216/242`；监听 `:228—230` | 条目的可枚举清单 |
| L3 资格 | 允许它被哪些体验检索 | App 设位、平台放行 | 声明件 + 通道件 | 四位 `B/nsuseractivity.txt:313/319/325/331`；公开索引 `A/corespotlight.txt:26—27`；安全索引 `A/adding-…:76—88` | 条目级可用性读数 |
| L4 属性 | 这次查询能读回哪几格 | 发起查询的代码 | 通道件 | 请求制 `A/corespotlight_searching-…:22—24/29—30`；上下文 `A/corespotlight_csuserquery.txt:24—29/61—64`；最大条数 `:35—41` | 条目全字段 |
| L5 建议捐赠 | 用户做过什么被谁学到 | App + 平台 | 声明件 + 通道件 | 捐赠句 `B/intents.txt:7—8`；实体 `A/appintents.txt:10—14`；约束 `A/appintents_appentity.txt:5—18` | 建议命中记录 |
| L6 服务端边界 | 什么出设备、什么不出 | 平台 + 用户选择 | 通道件 + 观测件 | 索引留在设备 `A/corespotlight.txt:22—23`；服务端索引 `:30`；建议不上服务器 `B/siri-dictation-legal.txt:64—65`；检索词会被存储 `:28/34`；iCloud.com 四条件 PSG `:2749—2752/2759—2762` | 二者互相换算 |
| L7 场景门 | 这个场景放不放行 | 平台、用户、管理面 | 通道件 | 11 键 `B/mdm-restriction-keys.txt:22—197`；Siri AI 分叉 `B/siri-dictation-legal.txt:33`；本地处理指示 `:37` | 编程读数 |
| L8 告知 | 用户被告知的原话 | Apple 法务文本 | 观测件 | 三页（第 11 章）+ 路径件 `B/support-127070.txt:20/28—30` | 超出三页的推定 |
| L9 观测平面 | 这一格由哪一面读回 | 各平面各自 | 观测件 | `A/cssearchableindex.txt:266—272`；`A/corespotlight_csuserquery.txt:52`；`A/spotlight-search-tool.txt:15/19/27/81` | 统一状态面 |
| L10 管理与公告 | 出过哪个 CVE、能配什么 | MDM、公告 | 观测件 | 216 键（11 个相关）；10 个旧键 Deprecated 迁声明式；68 行子集与 0 命中影响句 | 条目级公告读数 |
| L11 删除复位 | 谁删、怎么证明删净 | App（动作）、平台（生效）、无（证明） | 声明件 + 观测件 | 五粒度 `A/cssearchableindex.txt:58/70/88/100/116`；两把活动删除 `B/nsuseractivity.txt:230/301`；义务句 `A/adding-…:67—72`、`A/cssearchableitem.txt:36—37`；重建 `A/corespotlight_cssearchableindexdelegate.txt:76`、`A/regenerating-…:6—11` | 「索引库中已无此条」 |

矩阵的三条读法：

1. **「判定权持有方」出现两个及以上主体的层（L3、L6、L7、L11）就是假闭合高发层。** 这四层各对应脚本一的一个信号码族（B 族、N 族、G 族、V 族）。
2. **「不可登记」列非空的层，对外表述必须写成条件句。** 全表只有 L8 的「不可登记」列可以靠引用原文清空。
3. **三件在 L1—L2 全为声明件、在 L8—L10 全为观测件，中间的 L3—L7 是混合格。** 这意味着写入侧与观测侧之间**没有一件是单一持有人**，第 22 章的三件差集因此只能对「同一格在三份登记里各出现一次」做核对，不能对「三件之间有没有换算关系」做核对——换算关系根本不存在（第 3.4 节八处失败）。

---

## 16. 公开读数：这条通路上能数出来的二十件事

每处都给归档行锚；所有行锚都已在 `.srcx17/IDX/sources-17.md` 用 `grep -n -F` 逐条回验。

1. **索引责任在 App**：`A/corespotlight.txt:17`。
2. **两种写入时机**（运行时索引，或用扩展在系统请求时索引）：`A/corespotlight.txt:18—19`。
3. **可索引未显示的内容与文件**：`A/corespotlight.txt:19—21`。
4. **Core Spotlight 索引留在设备、不与 Apple 共享、不同步到其他设备**：`A/corespotlight.txt:22—23`。
5. **公开索引是可选标识**：`A/corespotlight.txt:26—27`。
6. **网页标记进入 Apple 的服务端索引并对所有 iOS 用户可用**：`A/corespotlight.txt:30`。
7. **文件导入扩展在 macOS 不提供功能**：`A/corespotlight.txt:15`。
8. **默认索引只能用于原型与测试**（两处独立表述）：`A/cssearchableindex.txt:25`、`A/adding-…:86—88`。
9. **自定义索引才支持数据保护**：`A/cssearchableindex.txt:18—21`；保护等级由 `protectionClass` 指定：`:274—277`、`A/adding-…:157/164—166/169`。
10. **修改索引的三项约束**（单线程、只从已签名 App 或扩展、多线程或未签名访问自定义索引是编程错误）：`A/cssearchableindex.txt:26—28`。
11. **五级删除接口**：`A/cssearchableindex.txt:58/70/88/100/116`（Obj-C 三名同段 `:352/354/356`）。
12. **设备级索引可用性是唯一的可用性读数**：`A/cssearchableindex.txt:266—272`。
13. **条目身份三元组写在构造器签名里**：`A/cssearchableitem.txt:208`，各元素说明在 `:122/222`，删除义务句在 `:36—37`，到期日在 `:129—131`。
14. **查询只取回明确请求的属性**：`A/corespotlight_searching-for-information-in-your-app.txt:22—24`；索引使内容同时对 App 与系统 Spotlight 可用：`:9—10`。
15. **不指定最大条数就返回全部结果，且开始新查询前应取消旧查询**：`A/corespotlight_csuserquery.txt:35—41`。
16. **摘要与优先级需逐条启用，且只处理三类类型**：`A/generating-summary-and-priority-data-for-indexed-items.txt:17—23/36—39`。
17. **Spotlight 搜索工具把索引开放给基础模型，两种数据源**（App 的 Spotlight 索引、对 Spotlight 可见的文件与目录的已索引元数据）：`A/spotlight-search-tool.txt:3—4/19/21/27/29—30/81`；人物引用解析接口 `:15`。
18. **管理面 216 个限制键中 11 个与检索面有关，且全为通道级开关；10 个旧 Siri 键全部 Deprecated 并迁往 `com.apple.configuration.siri.settings`**：`B/mdm-restriction-keys.txt:22—197`、`B/mdm-siri-keys.tsv`（10 行）、`B/mdm-restrictions.txt:1250+`。
19. **公告检索面子集 68 行、组件列具名 6 个、影响句检索面词形 0 命中**：`C/query-plane-17.tsv`、`C/query-plane-17-summary.txt`；去重影响句 9 句且高频写法分叉（44 次 vs 3 次）。
20. **iCloud.com 的搜索使用设备本地索引，且四条授权条件齐备（明确选择加入、设备独立授权、连接范围限同步文件、需双重认证且不适用托管账户）**：PSG `:2749—2752/2753`，配对键与会话绑定模型在 `:2759—2762`。

另附三条**跨层**读数，不计入上面的二十（它们属于第 05、11、13 篇的对象，本文只作对照）：Siri 不访问生物识别模板（05 篇口径）、`Spotlight` 出现在备份公告组件名单（11 篇口径）、Spotlight 作为 Xcode 操作路径（13 篇口径）。

---

## 17. 可见性边界：这一层读者能拿到什么

本文的读者假定是防守方（App 安全负责人、设备管理负责人、隐私合规负责人）。这一层读者能拿到的东西只有五类：

1. **接口义务**：哪些事文档明确要求 App 做（维护索引 `:17`、删除原始数据时同步删条目、为每批操作加状态、实现再索引扩展）。
2. **接口禁令**：哪些事文档明确不要做（生产用默认索引、未签名访问自定义索引、多线程同时改一个索引对象）。
3. **可配置闸门**：11 个限制键与一个声明式类型的接管位置。
4. **可引用口径**：三份告知页与一份路径说明件里，与索引、建议、检索词、留存、删除有关的原话。
5. **存在性证据**：公告组件列给出的「这个组件上出过这个 CVE」，以及它明确**不**给出的「这个缺陷发生在检索面的哪一格」。

**拿不到的四类**（写进台账就是越界，脚本会以 V 族与 P 族拒绝）：

- 设备上当前有哪些条目、共几条、属于哪些域；
- 某条内容此刻能不能被某类发起方查回；
- 一次删除之后索引库的真实状态；
- 一次检索请求在服务端留下什么（本文只登记告知页怎么说，不做任何流量观测）。

这条边界决定了一个必须坦白的结论：**本文所有关于「可查询面」的表述都是口径表述，不是状态表述。** 第 19 章两套判定模型的 J4／Q4 档，本质上就是在给「越界尝试」定档，而不是给「风险高低」定档——风险判断需要状态读数，而状态读数在本层不可得。

---

## 18. 五个读数面：索引侧、查询侧、设置侧、管理侧、公告侧

把第 12 章的九个平面按**谁能在不接触设备的前提下引用**收敛成五个面，便于运营与审计分工：

| 面 | 载体 | 能回答 | 不能回答 | 更新滞后 |
| --- | --- | --- | --- | --- |
| 索引侧（声明面） | App 源码与 App 扩展装配 | 写了什么、写到哪个索引、保护等级、有没有再索引扩展 | 系统是否放行、条目是否在面上 | 每次发版 |
| 查询侧（通道面） | 查询代码与结果回调 | 这次请求了哪几格、最大条数、命中与否 | 未请求的格是否存在、未命中的原因 | 每次调用 |
| 设置侧（用户面） | 设置页开关与逐 App 列表 | 用户当前允许到哪一层 | 面上存量、索引内容 | 用户随时可改 |
| 管理侧（配置面） | 限制载荷与声明式类型 | 这台设备被限制到哪一层、迁移状态 | 条目级审阅、删除 | 配置下发时 |
| 公告侧（外部面） | 12 篇安全发布 1,266 条 | 哪个组件出过哪个 CVE | 后果发生在检索面哪一格（影响句 0 命中） | 发布时 |

五个面之间没有主键。唯一能把它们连起来的是**台账自造的检索面对象标识**（脚本一与脚本二共用的第一列），这也是为什么本篇两支脚本都要求同一对象在三份登记里各出现一次——三件差集的本质是「五个面里，同一条内容被几个面各自说过一次，说的还是不是同一件事」。

---

## 19. 两套判定模型：J1—J4 与 Q1—Q4

两套模型都只有四档，都从 1 到 4 **变差**，且都是**表述资格**而不是风险等级。

### 19.1 J1—J4：逐条台账能不能进入对外表述（脚本一）

判据按脚本一的实现（416—421 行）逐字给出：

| 档 | 触发条件 | 允许表述 |
| --- | --- | --- |
| J4 | 对象类型或索引种类与观测平面、范围**同缺**；或阻断信号不少于 5 条 | 不得进入任何「谁能查回来、谁能删干净、谁能证明已删」的表述 |
| J3 | 存在阻断信号且核对时刻／条目标识／删除方法／范围四格至少缺一；或平面、结论、范围、闸门主体、决定方、索引种类六格任一未登记 | 只能定「这条内容进了检索面」，不能定「谁判的、此刻还能不能查回来」 |
| J2 | 有阻断信号但上述四格齐备 | 能定身份与落点，可用于内部处置，不能作为对外归属表述 |
| J1 | 十一格（身份、声明、权利、开关、查询发起、闸门、范围、时效、观测、删除、管理、引用）齐备且无阻断信号 | 可进入对外归属表述 |

阻断集一侧要分开说。**脚本一**在第 113—114 行把全部 63 个信号码一次性写进 `HB`，只有 `J1`—`J4` 四个判定档不计阻断——也就是说这支脚本里没有「警告级」信号，任何一条信号出现都算阻断（因此它的汇总行里「信号行数」与「阻断信号条数」两个数字必然相等，第 23.3 节的表可逐次验证）。**脚本二**的阻断集（第 190—198 行）只收 39 个码，**明确不收** `S08`、`D02`、`D03`、`D05`、`X03`、`X04`、`V03`、`V04` 这 8 个：它们的语义是「登记口径未统一」「覆盖空洞」「公告平面的列间错位」，属于**必须呈现但不该拦停**的一类——尤其 `X04`，它承载的正是本文的中心读数（组件列具名、影响句 0 命中），把它设成阻断会让每次正常运行都退出 1，反而让这支脚本失去「干净输入给 0」的下界。这是两支脚本在阻断设计上的唯一不对称，第 23.7 节解释它带来的退出码后果。

### 19.2 Q1—Q4：三件对完之后归属还能不能立起来（脚本二）

判据按脚本二的实现（448—455 行）：

| 档 | 触发条件 | 允许表述 |
| --- | --- | --- |
| Q4 | 该对象类不在能力表里、或该类没有任何 required 项、或对象本身不可用（`unknown`／`not_recorded`） | 连「这一格按公开口径可不可能有读数」都不能定 |
| Q3 | 存在 required 覆盖空洞、或存在有读数但无引用、或该对象一条已读数都没有 | 只能定覆盖面，不能定归属（口径漂移与整格漏登记落在此档） |
| Q2 | 存在任一阻断信号（HB，不含 S08／D02／D03／D05／X03／X04／V03／V04） | 有实质矛盾：三件不成对、平面越界或内容越界 |
| Q1 | 三件差集、平面可得性、公开词表三段齐备且无阻断 | 归属可对外 |

### 19.3 两套模型的接缝

J 查**一条登记内部**的完整性，Q 查**三份登记之间**的一致性。因此一条 J1 的登记完全可能配一个 Q2 的三件对账结果——本文的推荐口径是把两者并列写出（「逐条审查 J1，三件对账 Q2，原因是……」），绝不合并成单一分数。合并会掩盖一件事：**逐条越严谨，越容易让三件缺口看起来像已闭合。**

---

## 20. 运营指标 O1—O10

十个指标全部可用第 21、22 章两支脚本的输出直接算出，不需要设备侧数据。

| 号 | 指标 | 计算方式 | 建议口径 |
| --- | --- | --- | --- |
| O1 | 条目登记覆盖率 | 已登记 `item_uid` 的对象数 ÷ 台账对象总数 | 低于 1 时不得对外表述删除能力 |
| O2 | 域划分率 | `domain_id` 非空的索引对象占比 | 决定能否用按域删除（`:100`）而不是逐条删 |
| O3 | 默认索引违规数 | 脚本一 B 族命中数（`default_index` 且非测试） | 目标为 0 |
| O4 | 安全索引使用率 | `protection_class=complete` 的敏感对象占比 | 与 `A/adding-…:80—82` 对齐 |
| O5 | 再索引扩展装配率 | 含 `cs_index_extension` 对象类的 App 数 | 决定崩溃后能否重建（`A/regenerating-…:6—11`） |
| O6 | 属性白名单收敛度 | `attributes_requested` 平均格数 | 越低越好；`A/corespotlight_searching-…:22—24` 是依据 |
| O7 | 场景门登记完整率 | L7 六格（三态 + 决定方 + 时刻 + 可见性）齐备的对象占比 | 缺一即 J3 |
| O8 | 三件不成对数 | 脚本二 T 族命中数 | 目标为 0；非 0 时禁止对外表述「谁能查回来」 |
| O9 | 公告引用错位数 | 脚本二 X 族命中数（含 X04 的 0 命中负空间使用是否规范） | 非 0 表示把组件级读数当条目级读数用了 |
| O10 | 删除可证率 | `delete_verified=verified` 且同时有 `query_result` 读数的对象占比 ÷ 有删除动作登记的对象数 | 本文承认为最难达标的指标，其上限受第 17 章「拿不到的四类」约束 |

O10 值得补一句运营口径：**这个指标永远不可能到 1**，因为再检索未命中不排除三个混淆变量。它的正确用法是趋势对照（同一条口径下季度间是否恶化），不是达标。

---



---

## 21. 只读核验脚本一：检索面台账逐字段审查器

这支脚本回答一个问题：**一条内容被写成一行台账之后，这行台账自己站不站得住。**它不检查索引、不检查设备，只检查登记。

### 21.1 它查什么

`tools/query-plane-ledger-review.sh`（442 行）逐对象核对十一格：身份、声明、权利、开关、查询发起、闸门、范围、时效、观测、删除、管理面与引用。它的判据全部来自组 A／B／C 归档的公开句子，每一条信号都在消息尾部带上出处（脚本第 121—170 行的 `DOC` 数组把 63 个码各自绑到一句文档原文与行号），因此**任何一条信号都能被读者自己回查**——这是本文用「信号带引用」而不是「信号带解释」的原因。

它专查的六类错误对应第 3.4 节的六处换算失败：默认索引承载生产内容（失败点 1 的极端形态）、资格位与闸门分家（失败点 2）、属性请求与条目存在混登（失败点 3）、用请求侧口径闭合索引侧口径（失败点 4，`N03`）、义务句当机制句（失败点 7，V 族）、引用回不到行（`X01`）。

### 21.2 输入格式与命名空间

台账每行一条记录：`<检索面对象标识>,<字段名>,<值>`；`#` 开头与空行忽略，行尾 CR 忽略，**值里不能含逗号**。字段名必须带命名空间前缀，共十一个登记空间加一个拒收空间（第 18—30 行的 `-h` 文本逐空间列出）：`id.*` 身份、`cap.*` 声明与权利、`state.*` 三态、`op.*` 查询发起、`gate.*` 判定闸门、`scope.*` 可查询面范围、`when.*` 时效、`obs.*` 观测平面、`undo.*` 删除与闭合、`mgmt.*` 管理面、`doc.*` 引用与结论，以及 `sec.*`——`sec.*` 下任何字段直接触发 `K01`（第 188 行）。

枚举值在 `BEGIN` 段逐格写死（第 65 行起，`DOM[]`）。举两格：`id.obj_kind` 的合法取值是 `app app_extension cs_index user_activity app_entity intent_donation web_markup spotlight_tool shortcut_suggestion system_service built_in_service framework_library not_applicable none not_recorded unknown`；`id.index_kind` 是 `primary private_secure separate_index default_index shared none not_applicable not_recorded unknown`。枚举之外一律算越界，不做「相近即可」的宽容——`shared` 这一格在文档里没有任何一句支撑（`A/corespotlight.txt:22—23` 恰恰相反），它出现在枚举里只为了被 `A` 族拒绝。

### 21.3 信号族与判定档

| 族 | 码数 | 行段 | 覆盖对象 |
| --- | --- | --- | --- |
| S 行形态 | 9 | 186—250（读行阶段） | 列数、空标识、重复行、未登记字段名、枚举与形态越界 |
| K 内容越界 | 2 | 188、192、196、237 | `sec.*` 空间、形似检索词／转录／私钥／base64 的取值、形似设备路径或整段载荷的取值、`obs.command_name` 填了命令行入口 |
| A 身份声明 | 8 | 276—293 | 对象类型与索引种类、包标识与团队标识形态、条目标识与所属域形态、`web_markup` 落点、公开索引资格与范围 |
| B 权利闸门 | 8 | 294—312 | 三态与决定主体、资格位与索引名、默认索引承载生产、保护等级、逐 App 关闭口径 |
| C 查询发起 | 7 | 313—332 | 发起方、通道、最大条数、属性请求、后台发起、类型标识形态 |
| D 范围暴露 | 5 | 333—344 | 本机／跨端／服务端范围与资格位矛盾、承载字段、同步口径 |
| T 时效 | 5 | 345—358 | 核对时刻缺失、日期形态、时刻倒序、过期与复位 |
| O 观测平面 | 5 | 359—370 | 平面与字段不匹配、读数时刻缺失、列表可见性 |
| V 删除闭合 | 5 | 371—390 | 删除方法与粒度、删除与再检索矛盾、原始数据与残留声明、重绑依据 |
| G 管理面 | 5 | 391—402 | 限制键形态与是否在 216 键词表内、声明式类型、迁移状态、受监管 |
| N 告知面 | 3 | 403—407 | 告知依据缺失、厂商说法、请求侧口径闭合索引侧口径 |
| X 引用 | 1 | 412 | 缺来源文件或行号 |
| J 判定档 | 4 | 415—426 | 第 19.1 节四档 |

全部 63 个信号码一次性进阻断集（第 113—114 行），只有 J 档不计阻断。

### 21.4 输出与退出码

逐条信号写 **stderr**，形如 `码<TAB>对象<TAB>说明（见 … 第 N 行）`；四个判定档写 **stdout**；末尾固定三行汇总（对象数／信号行数／判定行数；不同信号码数／阻断信号条数；J 分布），随后按码打印一张计数表。`-q` 关掉的是 stdout 上那四行判定档（第 430 行 `if (!QUIET)`）；stderr 的逐条信号（第 429 行）、末尾三行汇总（第 434—436 行）与按码计数表（第 437—439 行）一行不少地照打。它是纯输出开关，既不改判定也不改退出码（第 23.3 节用 R5 与 R3 的逐字段对照证明这一点）。

退出码：有阻断信号 1、输入不可用 2、否则 0。参数校验只要求「至少一份输入且每份存在」（第 41—42 行），所以带多个文件是合法用法（R4 一次传两份）。

### 21.5 它不做什么

- 不调用任何设备侧命令。`mdfind`／`mdls`／`mdimport`／`mdutil`／`spotlight`／`profiles`／`sysctl`／`xcrun`／`defaults`／`log`／`siriscreencapture` 这些名字在整支脚本里只出现在**注释**（第 8 行）与 usage 文本里；`obs.command_name` 一旦填了任何命令行入口就触发 `K02`（第 237 行）。第 23.1 节 P4 那条 grep 是全量实证。
- 不联网、不读索引库、不修改输入。唯一写出目标是 `mktemp -d` 建的临时目录（第 44 行，前缀 `qpr.XXXXXX`），第 45 行 `trap` 在 EXIT／INT／TERM 删除；awk 程序体内没有 `system()`、没有 `getline < 文件`、没有 `popen()`。
- 不接受内容。索引条目正文、用户检索词、转录文本、联系人明文、形似共享密钥或口令的取值、设备绝对路径、整段文件正文、超长度阈值载荷一律拒收（第 7 行的头部注释就是拒收声明，第 188／192／196 行是执行点）。所有夹具取值均为合成词表，不含真实姓名、地址、电话号码与应用账号。

### 21.6 合格夹具读数

`FX/fixture-query-good.txt`（199 行、190 条数据行、3 个对象）跑出的完整输出（取自 `FX/run-log.txt` 第 475—483 行，逐字）：

```text
$ tools/query-plane-ledger-review.sh FX/fixture-query-good.txt
J1	CS_INDEX_OK	身份、声明、权利、开关、查询发起、闸门、范围、时效、观测、删除、管理面、引用十一格齐备且无阻断信号：可进入对外归属表述
J1	UA_OK	身份、声明、权利、开关、查询发起、闸门、范围、时效、观测、删除、管理面、引用十一格齐备且无阻断信号：可进入对外归属表述
J1	PUB_OK	身份、声明、权利、开关、查询发起、闸门、范围、时效、观测、删除、管理面、引用十一格齐备且无阻断信号：可进入对外归属表述

检索面对象数=3 信号行数=0 判定行数=3
不同信号码=0 阻断信号条数=0
判定分布 J1=3 J2=0 J3=0 J4=0
$ exit=0
```

三个对象分别代表三种典型形态：App 自建索引 + 按标识删除 + 查询回读（`CS_INDEX_OK`）、用户活动 + 失效 + 开关级删除（`UA_OK`）、网页标记 + 服务端索引范围（`PUB_OK`）。`PUB_OK` 能拿 J1 很关键：它证明脚本不把「内容进入服务端索引」本身当错误，只要求 `scope.reach` 与 `cap.eligible_for_public_indexing` 两格一致。

### 21.7 全量源码

```bash
#!/usr/bin/env bash
# query-plane-ledger-review.sh —— 检索面台账逐字段审查器（离线 / 只读 / 不联网 / 不碰设备）
# 输入：一份或多份台账文本，每行一条记录：  <检索面对象标识>,<字段名>,<值>
# 输出：逐条信号码（stderr） + 每个对象的四级判定（stdout） + 汇总
# 本脚本只判定「一条内容被写进检索面之后，谁能查回来、谁能删干净、失效之后谁能证明」：
# 不含索引内容抽取、检索词构造、建议命中放大、批量导出本机索引，也不含任何绕过 Siri／建议开关或规避管理面审计的做法。
# 台账里出现索引条目正文、用户检索词、转录文本、联系人明文、键串材料或设备绝对路径时直接触发 K01/K02 并要求删除该字段。
# 本脚本不联网、不调用 mdfind/spotlight/profiles/sysctl/log/defaults/xcrun 等任何命令行工具、
# 不读取设备状态、不修改输入文件；唯一写出目标是 mktemp -d 创建的临时目录，退出时删除。
set -u
LC_ALL=C; export LC_ALL

usage() {
  cat <<'EOF'
用法: query-plane-ledger-review.sh [-q] 台账文件 [...]
  -q  只输出汇总；-h/--help 显示本帮助
台账行格式: <检索面对象标识>,<字段名>,<值>    # 开头与空行忽略，行尾 CR 忽略，值里不能含逗号
字段命名空间（十一个 + 一个拒收空间）:
  id.*     对象身份（obj_kind / index_kind / index_name / protection_class / bundle_id / team_id / signature / item_uid / domain_id / type_identifier）
  cap.*    声明与权利（platform / content_owner / api_path / eligible_for_search / eligible_for_prediction / eligible_for_public_indexing / eligible_for_handoff / usage_notice / secure_index）
  state.*  三态（siri_state / suggestions_state / decided_by / decided_at / toggle_visible）
  op.*     查询发起（actor / plane_target / query_api / max_results / attributes_requested / in_background / initiated_by）
  gate.*   判定闸门（owner / basis / read_back_api / deletable / delete_actor / partial_result_ok）
  scope.*  可查询面范围（reach / sync / field_carried）
  when.*   时效（indexed_at / expires_at / observed_at / state_checked_at / reset_at / stale_after_days / time_source）
  obs.*    观测平面（plane / field_read / read_at / list_visible / command_name）
  undo.*   删除与闭合（delete_method / delete_actor / delete_verified / original_data_gone / residue_claimed / rebind_basis）
  mgmt.*   管理面（mdm_configurable / payload / restriction_key / declarative_key / declarative_type / migration_state / supervised / key_source）
  doc.*    引用与结论（source / line_ref / conclusion / notice_basis）
  sec.*    拒收用命名空间：本空间下任何字段都会触发 K01
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

TMPD=$(mktemp -d "${TMPDIR:-/tmp}/qpr.XXXXXX") || { echo "无法创建临时目录" >&2; exit 2; }
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
function isInt(v)   { return (v ~ /^[0-9]+$/) }
function isTeamID(v){ return (v ~ /^[A-Za-z0-9]{10}$/) }
function isLineRef(v) { return (v ~ /^[0-9]+(-[0-9]+)?$/) }
function isBundle(v) { return (v ~ /^[A-Za-z0-9][A-Za-z0-9._-]*\.[A-Za-z0-9][A-Za-z0-9._-]*$/ && v !~ /[ ]/) }
function src(c) { return (c in DOC) ? "（" DOC[c] "）" : "" }
BEGIN {
  FS = ","
  AITYPE_OK = "(^|\\.)message$|(^|\\.)email$|(^|\\.)audio-transcript$"
  DOM["id.obj_kind"]=" app app_extension cs_index user_activity app_entity intent_donation web_markup spotlight_tool shortcut_suggestion system_service built_in_service framework_library not_applicable none not_recorded unknown "
  DOM["id.index_kind"]=" primary private_secure separate_index default_index shared none not_applicable not_recorded unknown "
  DOM["id.protection_class"]=" complete complete_until_first_unlock after_first_unlock when_unlocked none not_applicable not_recorded unknown "
  DOM["id.signature"]=" signed_store signed_dev signed_enterprise signed_adhoc unsigned platform_binary app_extension_signed not_applicable none not_recorded unknown "
  DOM["cap.platform"]=" ios ipados macos tvos watchos visionos not_recorded unknown "
  DOM["cap.content_owner"]=" app user system mdm_profile not_recorded unknown "
  DOM["cap.api_path"]=" cssearchableindex useractivity appintents_appentity intents_donation web_markup spotlight_tool csuserquery not_applicable none not_recorded unknown "
  DOM["cap.usage_notice"]=" declared missing not_required not_applicable none not_recorded unknown "
  DOM["cap.secure_index"]=" separate_index required_and_absent not_required not_applicable none not_recorded unknown "
  DOM["state.siri_state"]=" on off per_app_off not_recorded unknown "
  DOM["state.suggestions_state"]=" on off per_app_off per_app_on not_recorded unknown "
  DOM["state.decided_by"]=" user_prompt user_settings app_code mdm platform_auto_allow not_determinable not_recorded unknown "
  DOM["op.actor"]=" user_typing system_suggestion foundation_model apple_intelligence app_code app_extension mdm_query not_determinable none not_recorded unknown "
  DOM["op.plane_target"]=" on_device_index apple_server_side public_index suggestions shortcut_suggestion not_recorded unknown "
  DOM["op.query_api"]=" csuserquery none indirect_error indirect_timeout settings_scraper not_applicable not_recorded unknown "
  DOM["op.initiated_by"]=" app_code app_extension embedded_library system_service user_action not_recorded unknown "
  DOM["gate.owner"]=" app_code user_settings mdm platform_auto_allow not_determinable not_recorded unknown "
  DOM["gate.basis"]=" bundle_id team_id signature domain_identifier item_identifier user_toggle assumed none not_recorded unknown "
  DOM["gate.read_back_api"]=" none requested_attributes_only item_identifiers settings_ui not_determinable not_recorded unknown "
  DOM["gate.deletable"]=" app_only user_toggle_only mdm_channel_only expiry_only not_determinable none not_recorded unknown "
  DOM["gate.delete_actor"]=" app user mdm system none not_determinable not_recorded unknown "
  DOM["scope.reach"]=" device_only icloud_synced apple_server_side public_all_ios_users not_recorded unknown "
  DOM["scope.sync"]=" e2ee plain none not_recorded unknown "
  DOM["when.time_source"]=" device_clock app_log settings_ui legal_page developer_doc advisory vendor_claim screenshot not_recorded unknown "
  DOM["obs.plane"]=" app_query_result settings_ui mdm_status_item developer_doc legal_page advisory app_self_report vendor_claim not_determinable none not_recorded unknown "
  DOM["obs.field_read"]=" eligibility flag_state item_uid domain_id index_name list_membership usage_notice none not_recorded unknown "
  DOM["undo.delete_method"]=" delete_all delete_by_identifier delete_by_domain delete_app_entities activity_delete activity_invalidate expiry_only uninstall reindex_delegate none not_recorded unknown "
  DOM["undo.delete_actor"]=" app user mdm system not_determinable none not_recorded unknown "
  DOM["undo.rebind_basis"]=" item_uid domain_id bundle_id signature assumed not_applicable not_recorded unknown "
  DOM["mgmt.mdm_configurable"]=" channel_only content_only yes no not_recorded unknown "
  DOM["mgmt.payload"]=" com.apple.applicationaccess com.apple.configuration.siri.settings none not_applicable not_recorded unknown "
  DOM["mgmt.migration_state"]=" legacy_deprecated declarative both not_recorded unknown "
  DOM["mgmt.key_source"]=" restrictions_inventory official_doc vendor_claim none not_recorded unknown "
  DOM["doc.conclusion"]=" confirmed absent_in_ledger not_determinable assumed not_recorded unknown "
  DOM["doc.notice_basis"]=" official_legal_page official_doc official_support_note vendor_claim none not_applicable not_recorded unknown "
  BOOL["cap.eligible_for_search"]=1; BOOL["cap.eligible_for_prediction"]=1
  BOOL["cap.eligible_for_public_indexing"]=1; BOOL["cap.eligible_for_handoff"]=1
  BOOL["state.toggle_visible"]=1
  BOOL["obs.list_visible"]=1
  BOOL["op.in_background"]=1; BOOL["gate.partial_result_ok"]=1
  BOOL["undo.delete_verified"]=1; BOOL["undo.original_data_gone"]=1; BOOL["undo.residue_claimed"]=1
  BOOL["mgmt.supervised"]=1
  DT["state.decided_at"]=1; DT["when.indexed_at"]=1; DT["when.expires_at"]=1
  DT["when.observed_at"]=1; DT["when.state_checked_at"]=1; DT["when.reset_at"]=1; DT["obs.read_at"]=1
  NUM["op.max_results"]=1; NUM["op.attributes_requested"]=1
  NUM["scope.field_carried"]=1; NUM["when.stale_after_days"]=1
  NS["id"]=1; NS["cap"]=1; NS["state"]=1; NS["op"]=1; NS["gate"]=1; NS["scope"]=1
  NS["when"]=1; NS["obs"]=1; NS["undo"]=1; NS["mgmt"]=1; NS["doc"]=1; NS["sec"]=1
  split("S01 S02 S03 S04 S05 S06 S07 S08 S09 K01 K02 A01 A02 A03 A04 A05 A06 A07 A08 B01 B02 B03 B04 B05 B06 B07 B08 C01 C02 C03 C04 C05 C06 C07 D01 D02 D03 D04 D05 T01 T02 T03 T04 T05 O01 O02 O03 O04 O05 V01 V02 V03 V04 V05 G01 G02 G03 G04 G05 N01 N02 N03 X01", hb, " ")
  for (i in hb) HB[hb[i]] = 1
  split("id.index_name id.item_uid id.domain_id id.type_identifier id.bundle_id id.team_id mgmt.restriction_key mgmt.declarative_key mgmt.declarative_type obs.command_name doc.source doc.line_ref", extra, " ")
  for (i in extra) KNOWN[extra[i]] = 1
  for (f in DOM) KNOWN[f] = 1
  for (f in BOOL) KNOWN[f] = 1
  for (f in DT) KNOWN[f] = 1
  for (f in NUM) KNOWN[f] = 1
  DOC["A01"]="见 cssearchableindex.txt 第 3、10—11 行（An on-device index for your app'\''s searchable content）"
  DOC["A02"]="见 nsuseractivity.txt 第 325、327 行与 corespotlight.txt 第 30 行"
  DOC["A03"]="见 corespotlight.txt 第 30 行（web markup 进的是 Apple 的服务端索引，makes the data available to all iOS users）"
  DOC["A04"]="见 adding-your-app-s-content-to-spotlight-indexes.txt 第 86—88 行（Use the … index only for prototyping and testing… Don'\''t use it to store content in the production version of your app）"
  DOC["A05"]="见 cssearchableindex.txt 第 26—28 行（modify it only from your signed app or app extension… or from an unsigned bundle 是 programming error）"
  DOC["A06"]="见 adding-… 第 80—82 行（If you need to index more sensitive data, such as someone'\''s contact information, create a more secure index）"
  DOC["A07"]="见 cssearchableindex.txt 第 18—21 行（Custom indexes support data protection… instead of using the default index）"
  DOC["A08"]="见 cssearchableitem.txt 第 122、208、222—224 行（initWithUniqueIdentifier:domainIdentifier:attributeSet: 与 uniqueIdentifier / domainIdentifier）"
  DOC["B01"]="见 siri-dictation-legal.txt 第 76 行（Settings > Siri > Suggestions > [app name]，逐 App 关闭）"
  DOC["B02"]="见 adding-… 第 18—19 行（Enabling this property in user-initiated activities adds those activities to the on-device index）"
  DOC["B03"]="见 siri-dictation-legal.txt 第 72 行（同一段只承诺删除转录，通篇没有一句说关 Siri 会清掉 Core Spotlight 索引）"
  DOC["B04"]="见 corespotlight_searching-for-information-in-your-app.txt 第 22—24 行（系统只取回你明确请求的属性）"
  DOC["B05"]="见 mdm-siri-keys.tsv allowAssistantWhileLocked（The system ignores this restriction if the device doesn'\''t have a passcode set）"
  DOC["B06"]="见 siri-dictation-legal.txt 第 65 行（Suggestions… are not stored on Apple servers or shared with other third-party apps）"
  DOC["B07"]="见 generating-summary-and-priority-data-for-indexed-items.txt 第 36—39 行（Apple Intelligence doesn'\''t operate on items with other types）"
  DOC["B08"]="见 generating-… 第 17—23 行（requires you to enable the generation of summary and priority information on an item-by-item basis）"
  DOC["C01"]="见 spotlight-search-tool.txt 第 19、21、71—73 行（Foundation Models 经 CoreSpotlightSource 取索引）"
  DOC["C02"]="见 corespotlight.txt 第 22—23 行（Devices don'\''t share indexed data with Apple, or synchronize that data…）"
  DOC["C03"]="见 cssearchableindex.txt 第 294—297 行与 appintents_appentity.txt 第 3 行（AppEntity 是另一条发现通道）"
  DOC["C04"]="见 intents.txt 第 5—8 行（SiriKit/Intents/IntentsUI 为 legacy support，现代支持要用 App Intents）"
  DOC["C05"]="见 corespotlight.txt 第 15 行（Spotlight File Import extensions don’t provide functionality in macOS）、第 18—19 行与 adding-… 第 95—96 行（provide a reindexing app extension）"
  DOC["C06"]="见 corespotlight_csuserquery.txt 第 35—41 行（不指定上限时查询一直跑到返回全部结果）"
  DOC["C07"]="见 corespotlight_csuserquery.txt 第 18—21 行（use a query object only once… cancel the old query）"
  DOC["D01"]="见 siri-dictation-legal.txt 第 69 行（Siri settings and Siri Suggestions personalization will sync… using end-to-end encryption）"
  DOC["D02"]="见 apple-platform-security-guide.txt 第 2759—2762 行（iCloud.com 检索需要浏览器与设备之间的配对密钥与逐次放行）"
  DOC["D03"]="见 apple-platform-security-guide.txt 第 2752 行（Local-only files aren'\''t accessible）"
  DOC["D04"]="见 adding-… 第 11—12 行（create a private, on-device index…）"
  DOC["D05"]="见 cssearchableitemattributeset.txt 第 3 行（The detailed metadata for a searchable item）"
  DOC["T01"]="见 cssearchableindex.txt 第 16—17 行（返回结果只发生在执行查询那一刻）"
  DOC["T02"]="见 adding-… 第 60—61 行（very important to keep your app'\''s indexes up to date so that searches return current information）"
  DOC["T03"]="见 adding-… 第 60—61 行"
  DOC["T04"]="见 legal-siri-suggestions-search.txt 第 54 行（页面日期只说明告知文案何时更新，不说明索引何时仍然成立）"
  DOC["T05"]="见 adding-… 第 69—72 行与 cssearchableitem.txt 第 36—37 行（原数据删除后要同步删除索引条目）"
  DOC["O01"]="见 cssearchableindex.txt 第 16—17 行"
  DOC["O02"]="见 siri-dictation-legal.txt 第 76、80 行（设置面里 Suggestions 与 Suggestions & Search 是两格）"
  DOC["O03"]="见 mdm-siri-keys.tsv 与 mdm-restriction-keys.txt 全 220 行、216 个键名（十个 Siri 键全部是通道开关，没有一个读取 App 写了哪些索引条目）"
  DOC["O04"]="见 adding-… 第 177、181 行（expirationDate 出现在 API 清单里，不是设置面读数）"
  DOC["O05"]="见 siri-dictation-legal.txt 第 72、76 行（关闭开关与删除条目是两件事）"
  DOC["V01"]="见 cssearchableindex.txt 第 58、116 行（删除入口在索引对象上，验证只能靠再查一次）"
  DOC["V02"]="见 cssearchableindex.txt 第 26—28 行（删除权绑在签名的 App 或 App 扩展上）"
  DOC["V03"]="见 cssearchableitem.txt 第 36—37 行、adding-… 第 69—72 行"
  DOC["V04"]="见 cssearchableindex.txt 第 58、100、116、352—356 行（四个删除入口的调用方都是索引对象自己）"
  DOC["V05"]="见 adding-… 第 67—71 行与 cssearchableitem.txt 第 129—131 行（expirationDate 只决定保留下限）"
  DOC["G01"]="见 mdm-siri-keys.tsv（allowAssistantUserGeneratedContent 管的是 Siri 向 Web 查用户生成内容，不是本机索引）"
  DOC["G02"]="见 mdm-restriction-keys.txt 全 220 行、216 个键名（完整键清单本身是负空间结论的落点，第 1—4 行是页面分段标题）"
  DOC["G03"]="见 mdm-restrictions.txt 第 1250、1252、1254、1406、1449 行（同一条说明同时写着命令面键与 com.apple.configuration.siri.settings）"
  DOC["G04"]="见 mdm-siri-keys.tsv（十个键的说明全部带 Deprecated: use the declarative management com.apple.configuration.siri.settings）"
  DOC["G05"]="见 mdm-siri-keys.tsv allowSpotlightInternetResults 与 allowAssistantUserGeneratedContent（前者 unsupervised 支持已弃用，后者 Requires supervision: iOS）"
  DOC["N01"]="见 siri-dictation-legal.txt 第 28、34 行与 legal-siri-suggestions-search.txt 第 28 行"
  DOC["N02"]="见 legal-siri-suggestions-search.txt 第 30 行（Search is designed to protect your information… 之外的承诺不含厂商口径）"
  DOC["N03"]="见 siri-dictation-legal.txt 第 28—31 行与 corespotlight.txt 第 22—23 行（请求不与 Apple Account 关联，说的是 Siri 请求，不是本机索引）"
}
{ sub(/\r$/, "") }
/^[[:space:]]*#/ { next }
/^[[:space:]]*$/ { next }
NF != 3 { emit("S01", $1, "记录不是恰好三列（<检索面对象标识>,<字段名>,<值>）：" $0); next }
{
  id = $1; fld = $2; val = $3
  gsub(/^[[:space:]]+|[[:space:]]+$/, "", id)
  gsub(/^[[:space:]]+|[[:space:]]+$/, "", fld)
  gsub(/^[[:space:]]+|[[:space:]]+$/, "", val)
  if (id == "") { emit("S02", "", "检索面对象标识为空"); next }
  if (id ~ /[ \t]/) { emit("S02", id, "检索面对象标识内含空白，无法作为台账主键"); next }
  p = index(fld, ".")
  nsp = (p > 1) ? substr(fld, 1, p-1) : ""
  key = (p > 0) ? substr(fld, p+1) : ""
  if (nsp == "" || !(nsp in NS) || key == "") { emit("S03", id, "字段名不带命名空间或命名空间未知：" fld "（十一个可用命名空间见 -h）"); next }
  if (nsp == "sec") { emit("K01", id, "出现 sec.* 命名空间字段（" fld "）：检索面台账不收索引条目正文、检索词、转录文本与键串材料，请删除该字段"); if (!(id in seen)) { seen[id]=1; order[++nid]=id }; next }
  if (!(id in seen)) { seen[id] = 1; order[++nid] = id }
  if (!(fld in KNOWN)) { emit("S09", id, "字段名未登记：" fld "（拼写或自造字段；已登记字段名见 -h 的命名空间清单）"); next }
  if (tolower(val) ~ /transcript[ :=]/ || val ~ /^query[ :=]/ || val ~ /-----BEGIN[ ]?(RSA|EC|PRIVATE|ENCRYPTED)?/ || val ~ /^MI[IEA][A-Za-z0-9+\/=]{40,}/ || val ~ /^[A-Za-z0-9+\/]{48,}={0,2}$/) {
    emit("K01", id, "字段 " fld " 的取值形似检索词、转录文本、私钥材料或 base64 凭据：检索面台账只登记「哪一个对象在哪一格被判定成什么」")
    next
  }
  if (val ~ /^\/(Applications|private|var\/mobile|Users|Library)\// || val ~ /^file:\/\// || val ~ /^data:[A-Za-z\/+]*;base64,/ || val ~ /^([0-9a-fA-F]{2} ){8}/ || length(val) > 200) {
    emit("K02", id, "字段 " fld " 的取值形似设备绝对路径、索引条目正文、导出字节片段或整段载荷：台账只登记判定与读数，不登记内容")
    next
  }
  if (val == "" && !(fld == "doc.source" || fld == "doc.line_ref")) { emit("S02", id, "字段 " fld " 取值为空；留空、unknown 与 none 是三件事"); next }
  k = id SUBSEP fld
  if (k in valof) {
    if (valof[k] != val) emit("S07", id, "同一检索面对象同一字段出现两个不同值：" fld " = " valof[k] " / " val)
    else emit("S08", id, "字段 " fld " 重复登记且值相同（本脚本没有非阻断档：这一条照样计入阻断，因为它让台账行数虚高）")
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
      else if (fld == "op.attributes_requested" && val+0 > 64) emit("S04", id, "op.attributes_requested 超过 64：属性清单按公开口径是一格一条地明确请求，这一档说明把整张属性表抄进了格子里")
    }
  } else if (fld == "id.team_id") {
    if (!(val == "not_recorded" || val == "unknown" || val == "not_applicable") && !isTeamID(val)) emit("A05", id, "id.team_id 不是 10 位字母数字串：" val src("A05"))
  } else if (fld == "id.bundle_id") {
    if (!(val == "not_recorded" || val == "unknown" || val == "not_applicable" || val == "none") && !isBundle(val)) emit("A05", id, "id.bundle_id 不是反向域名形态：" val src("A05"))
  } else if (fld == "id.item_uid") {
    if (!(val == "not_recorded" || val == "unknown" || val == "not_applicable" || val == "none") && val !~ /^[A-Za-z0-9][A-Za-z0-9._:\/-]{2,127}$/) emit("A08", id, "id.item_uid 不是可作为删除主键的标识串：" val src("A08"))
  } else if (fld == "id.domain_id") {
    if (!(val == "not_recorded" || val == "unknown" || val == "not_applicable" || val == "none") && val !~ /^[A-Za-z0-9][A-Za-z0-9._:\/-]{2,127}$/) emit("A08", id, "id.domain_id 不是可作为按域删除主键的标识串：" val src("A08"))
  } else if (fld == "id.type_identifier") {
    if (!(val == "not_recorded" || val == "unknown" || val == "not_applicable" || val == "none") && !isBundle(val)) emit("C03", id, "id.type_identifier 不是 UTType 反向域名形态：" val src("C03"))
  } else if (fld == "mgmt.restriction_key") {
    if (!(val == "not_recorded" || val == "unknown" || val == "not_applicable" || val == "none") && val !~ /^(allow|force)[A-Z][A-Za-z0-9]*$/) emit("G02", id, "mgmt.restriction_key 不是限制负载键形态（allow*/force*）：" val src("G02"))
  } else if (fld == "mgmt.declarative_key" || fld == "mgmt.declarative_type") {
    if (!(val == "not_recorded" || val == "unknown" || val == "not_applicable" || val == "none") && val !~ /^com\.apple\.(configuration|declarative)/) emit("G03", id, "mgmt.declarative_type 不是声明式类型串形态：" val src("G03"))
  } else if (fld == "obs.command_name") {
    if (val != "none" && val != "not_recorded" && val != "unknown") emit("K02", id, "字段 obs.command_name 登记了命令行入口（" val "）：本脚本与台账都不以任何设备侧命令作为读数来源，请删除该格")
  }
}
END {
  nrec = nid
  for (ix = 1; ix <= nid; ix++) {
    id = order[ix]
    kind = GV(id,"id.obj_kind"); ikind = GV(id,"id.index_kind"); iname = GV(id,"id.index_name")
    pcls = GV(id,"id.protection_class"); bid = GV(id,"id.bundle_id"); team = GV(id,"id.team_id")
    sig = GV(id,"id.signature"); iuid = GV(id,"id.item_uid"); domid = GV(id,"id.domain_id")
    tid = GV(id,"id.type_identifier")
    plat = GV(id,"cap.platform"); api = GV(id,"cap.api_path")
    eSearch = GV(id,"cap.eligible_for_search"); ePred = GV(id,"cap.eligible_for_prediction")
    ePub = GV(id,"cap.eligible_for_public_indexing"); eHand = GV(id,"cap.eligible_for_handoff")
    usage = GV(id,"cap.usage_notice"); secidx = GV(id,"cap.secure_index")
    sst = GV(id,"state.siri_state"); sugst = GV(id,"state.suggestions_state")
    dby = GV(id,"state.decided_by"); dat = GV(id,"state.decided_at"); tvis = GV(id,"state.toggle_visible")
    actor = GV(id,"op.actor"); ptarget = GV(id,"op.plane_target"); qapi = GV(id,"op.query_api")
    maxr = GV(id,"op.max_results"); attrs = GV(id,"op.attributes_requested")
    inbg = GV(id,"op.in_background"); oinit = GV(id,"op.initiated_by")
    gown = GV(id,"gate.owner"); gbasis = GV(id,"gate.basis"); qback = GV(id,"gate.read_back_api")
    delable = GV(id,"gate.deletable"); dactor = GV(id,"gate.delete_actor"); partial = GV(id,"gate.partial_result_ok")
    reach = GV(id,"scope.reach"); syncv = GV(id,"scope.sync")
    carried = GV(id,"scope.field_carried")
    idx_at = GV(id,"when.indexed_at"); exp_at = GV(id,"when.expires_at")
    chk_at = GV(id,"when.state_checked_at"); rst_at = GV(id,"when.reset_at")
    stale = GV(id,"when.stale_after_days"); tsrc = GV(id,"when.time_source")
    pl = GV(id,"obs.plane"); fread = GV(id,"obs.field_read"); lvis = GV(id,"obs.list_visible")
    dmeth = GV(id,"undo.delete_method"); dact2 = GV(id,"undo.delete_actor"); dveri = GV(id,"undo.delete_verified")
    origgone = GV(id,"undo.original_data_gone"); residue = GV(id,"undo.residue_claimed"); rebind = GV(id,"undo.rebind_basis")
    mcfg = GV(id,"mgmt.mdm_configurable"); mpay = GV(id,"mgmt.payload"); mkey = GV(id,"mgmt.restriction_key")
    mdec = GV(id,"mgmt.declarative_type"); mig = GV(id,"mgmt.migration_state"); msup = GV(id,"mgmt.supervised"); msrc = GV(id,"mgmt.key_source")
    srcv = GV(id,"doc.source"); lref = GV(id,"doc.line_ref"); con = GV(id,"doc.conclusion"); nb = GV(id,"doc.notice_basis")

    ONDEV = (ptarget=="on_device_index")
    PUB   = (ePub=="true" || ePub=="yes" || ePub=="1")
    IDXOBJ = (kind=="cs_index" || kind=="app" || kind=="app_extension" || kind=="app_entity" || kind=="user_activity" || kind=="intent_donation" || kind=="web_markup" || kind=="spotlight_tool")
    APPDEL = (dmeth=="delete_all" || dmeth=="delete_by_identifier" || dmeth=="delete_by_domain" || dmeth=="delete_app_entities")

    # ---- A 族：身份、声明与权利（L1/L2/L5）----
    if (isNA(kind) && isNA(ikind)) emit("A01", id, "对象类型与索引种类两格都空：这条记录凭什么算一个检索面对象，台账里没有主语" src("A01"))
    else if (isNA(kind) || isNA(ikind)) emit("A01", id, "对象类型或索引种类缺格（另一格为 " (isNA(kind) ? ikind : kind) "）：只给一半无法把可查询面回指到一个对象上" src("A01"))
    if (PUB && reach!="public_all_ios_users" && reach!="apple_server_side" && !isNA(reach))
      emit("A02", id, "公开索引资格记为真但可查询面未落到公开／服务端：这一格的公开语义是「all iOS users 都能取到」" src("A02"))
    if (kind=="web_markup" && ONDEV)
      emit("A03", id, "对象类型记为 web markup 却把查询落点写在设备本机索引上：网页标记进的是 Apple 的服务端索引" src("A03"))
    if (ikind=="default_index" && reach!="not_recorded" && IDXOBJ && (con=="confirmed" || eSearch=="true"))
      emit("A04", id, "使用默认索引却登记可查询范围或闭合结论：默认索引按公开口径只用于原型与测试，生产内容不该落在这一格" src("A04"))
    if ((sig=="unsigned" || sig=="platform_binary") && IDXOBJ && (dmeth!="none" && !isNA(dmeth)))
      emit("A05", id, "签名状态记为 " sig " 却登记了删除方法：索引对象的修改与删除只对签名的 App 或 App 扩展成立" src("A05"))
    if (carried!="not_recorded" && isInt(carried) && carried+0 > 0 && secidx=="required_and_absent")
      emit("A06", id, "登记了携带字段但单独安全索引记为「应有却缺失」：敏感内容按公开口径要另建一个更安全的索引" src("A06"))
    if (ikind=="default_index" && !isNA(pcls) && pcls!="none" && pcls!="not_applicable")
      emit("A07", id, "索引种类记为默认索引却登记数据保护级别：保护级别是自建索引才有的能力" src("A07"))
    if (kind=="cs_index" && isNA(iuid) && isNA(domid) && (dmeth=="delete_by_identifier" || dmeth=="delete_by_domain"))
      emit("A08", id, "删除方法指向按标识或按域删除，但条目标识与域标识两格都空：这一对标识串就是删除主键" src("A08"))

    # ---- B 族：权利、开关与判定闸门（L3/L4/L6）----
    if (isNA(sst) && isNA(dby)) emit("B01", id, "Siri 状态与决定主体两格都空：谁被允许在建议面查到这条内容，台账没有答案" src("B01"))
    if ((istrue(eSearch) || istrue(ePred) || istrue(eHand) || istrue(ePub)) && isNA(iname) && ikind!="default_index" && kind!="web_markup" && kind!="system_service" && kind!="built_in_service")
      emit("B02", id, "登记了入本机索引／被建议／跨端／公开索引的资格位却没写索引名：资格位回答「允许进哪一面」，索引名才回答「进了哪一面」，缺一格就无法回查" src("B02"))
    if (sst=="off" && dmeth=="none" && origgone=="true" && con=="confirmed")
      emit("B03", id, "Siri 已关闭且原数据已删，却以「无删除方法」闭合可查询面：公开口径只承诺关 Siri 删转录，没有任何一处说会清掉本机索引" src("B03"))
    if (!isNA(qback) && qback!="none" && qback!="requested_attributes_only" && qback!="item_identifiers" && qback!="settings_ui" && qback!="not_applicable")
      emit("B04", id, "把「整面读回索引里都有什么」当作可用回读接口登记：公开口径写明查询只返回你明确请求的属性，设置面只回开关档位，没有列举整面的接口" src("B04"))
    if (qapi=="settings_scraper")
      emit("B04", id, "把查询通道记成抓取设置面：设置面给的是开关档位与逐 App 选择，不是一条检索查询通道，读不回任何索引条目" src("B04"))
    if (!isNA(mkey) && mkey=="allowAssistantWhileLocked" && msup=="true" && isNA(gbasis))
      emit("B05", id, "引用锁定时禁用 Siri 的键却未登记判定基准：该键在无密码设备上被系统直接忽略，写成生效需要另一格证据" src("B05"))
    if (ptarget=="suggestions" && reach=="apple_server_side")
      emit("B06", id, "查询落点记为建议面却把可查询范围写成服务端：建议面的公开口径是个性化信息不存 Apple 服务器、不分享给第三方 App" src("B06"))
    if (!isNA(tid) && (pl=="apple_intelligence" || actor=="apple_intelligence") && tid !~ AITYPE_OK && con=="confirmed")
      emit("B07", id, "把摘要／优先级能力用于其它类型并给出闭合结论：这一能力按公开口径只作用于消息、邮件与音频转录三类" src("B07"))
    if (actor=="apple_intelligence" && attrs!="not_recorded" && isNA(attrs))
      emit("B08", id, "以 Apple Intelligence 作为查询发起者但未登记请求的属性数：摘要与优先级要逐条打开，不是整面默认开" src("B08"))

    # ---- C 族：查询发起与通道（L6/L7/L8）----
    if (actor=="foundation_model" && api!="spotlight_tool" && ONDEV)
      emit("C01", id, "Foundation 模型查本机索引但未登记检索工具通道：模型侧取索引内容只经由检索工具与索引来源" src("C01"))
    if (reach=="apple_server_side" && api=="cssearchableindex" && kind!="web_markup")
      emit("C02", id, "用 Core Spotlight 索引通道却把范围写成服务端：Core Spotlight 建的本机索引不与 Apple 共享，也不跨设备同步" src("C02"))
    if ((kind=="app_entity" || kind=="intent_donation") && api=="cssearchableindex")
      emit("C03", id, "实体／意图捐赠类对象却记在 Core Spotlight 索引通道上：App Entity 是另一条面向 Apple Intelligence 与 Siri 的发现通道" src("C03"))
    if (kind=="intent_donation" && ePred=="true" && api=="intents_donation" && con=="confirmed" && usage=="not_recorded")
      emit("C04", id, "以 legacy 意图框架闭合建议面结论但未标注框架代际：公开口径写明 SiriKit/Intents 仍为 legacy support，现代支持走 App Intents" src("C04"))
    if (istrue(inbg) && (kind=="app"||kind=="cs_index") && isNA(oinit) && !isNA(dmeth) && dmeth!="none")
      emit("C05", id, "登记了后台执行与删除方法但未写明发起方：不在前台时替 App 维护索引的公开路径是 App 扩展与再索引回调，这一格决定删除主键还在不在" src("C05"))
    if (oinit=="app_extension" && sig!="app_extension_signed" && sig!="not_applicable" && !isNA(sig))
      emit("C05", id, "查询由 App 扩展发起但签名状态未记为扩展签名：扩展索引路径要求扩展自己实现协议方法，身份不是含糊的" src("C05"))
    if (plat=="macos" && oinit=="app_extension")
      emit("C05", id, "平台记为 macOS 却把索引发起方记为 App 扩展：Spotlight File Import 扩展在 macOS 上不提供功能，这一格的扩展索引通道落不了地" src("C05"))
    if (isNA(maxr) && partial=="true" && con=="confirmed")
      emit("C06", id, "结果上限未登记却把「取到部分」当作可闭合：不指定上限时查询一直跑到返回全部结果，两格不能同时成立" src("C06"))
    if (!isNA(attrs) && isInt(attrs) && attrs+0==0 && pl=="app_query_result" && con=="confirmed")
      emit("C07", id, "请求属性数为 0 却以查询结果闭合结论：一次查询只回请求过的属性，零属性查询回不到任何可登记的字段" src("C07"))

    # ---- D 族：范围与暴露（L8）----
    if (reach=="icloud_synced" && syncv!="e2ee" && syncv!="plain" && isNA(syncv))
      emit("D01", id, "范围记为 iCloud 同步但未登记同步通道形态：Siri 个性化按公开口径走端到端加密同步，这一格要写明" src("D01"))
    if (reach=="icloud_synced" && actor!="user_typing" && !isNA(actor) && qback=="not_determinable")
      emit("D02", id, "跨端检索发起者不是本机用户但回读记为不可判：iCloud.com 侧检索要浏览器与设备各自授权并建立配对密钥，缺这一格就无法归属" src("D02"))
    if (reach=="icloud_synced" && ikind=="private_secure" && (carried!="not_recorded" && isInt(carried) && carried+0>0) && isNA(gbasis))
      emit("D03", id, "把仅本机文件计入跨端可查询面：跨端检索的连接按公开口径只覆盖已同步到 iCloud 的文件，仅本机文件不可访问" src("D03"))
    if (reach=="public_all_ios_users" && usage!="declared" && IDXOBJ)
      emit("D04", id, "范围记为全体 iOS 用户可查但用途声明不为「已声明」：私有本机索引与公开可查询面是两个面，不能混写" src("D04"))
    if (carried!="not_recorded" && isInt(carried) && carried+0==0 && !isNA(reach) && reach!="not_recorded")
      emit("D05", id, "携带字段数为 0 却登记了非空可查询范围：一个索引条目的可查询面就是它携带的属性集合，零属性时这一格没有落点" src("D05"))

    # ---- T 族：时效（L4/L11）----
    if (isNA(chk_at) && (!isNA(reach) || !isNA(idx_at) || !isNA(dat) || !isNA(sst)))
      emit("T01", id, "登记了范围、入索引时刻、决定时刻或开关状态但没有核对时刻（state_checked_at）：没有基准时刻，任何「此刻还能不能查回来」的判定都不成立" src("T01"))
    if (!isNA(exp_at) && isISOdt(exp_at) && !isNA(chk_at) && isISOdt(chk_at) && stamp(chk_at) > stamp(exp_at) && con=="confirmed" && dmeth=="none")
      emit("T02", id, "核对时刻晚于过期时刻却在无删除方法的前提下闭合结论：过期只决定保留下限，索引新鲜度另有义务" src("T02"))
    if (isNA(stale) && con=="confirmed")
      emit("T03", id, "给出闭合结论但未登记台账过期阈值：公开文档给出的「保持索引更新」是义务而不是阈值，任何「还算数」的表述都要把自己的阈值写出来" src("T03"))
    else if (isInt(stale) && stale+0 == 0)
      emit("T03", id, "stale_after_days 记为 0：零阈值等于宣称任何时刻的读数都还算数，公开口径不支持这一读法" src("T03"))
    if ((tsrc=="legal_page"||tsrc=="advisory"||tsrc=="vendor_claim"||tsrc=="screenshot") && con=="confirmed")
      emit("T04", id, "时刻来源记为 " tsrc " 却给出对外闭合结论：能作为基准的只有设备本机时钟与查询结果读数；告知页与公告的日期说的是文案何时更新" src("T04"))
    if (origgone=="true" && !isNA(idx_at) && isISOdt(idx_at) && !isNA(rst_at) && isISOdt(rst_at) && stamp(idx_at) > stamp(rst_at) && dmeth=="none")
      emit("T05", id, "原数据删除时刻早于入索引时刻且没有删除方法：公开口径把「原数据删除后同步删除索引条目」写成 App 的义务，这一组合就是漏删" src("T05"))

    # ---- O 族：观测平面（L9）----
    if ((pl=="none"||pl=="not_determinable"||isNA(pl)) && con=="confirmed")
      emit("O01", id, "观测平面为空或不可判却给出「已确认」：确认结论要有能读回它的那个面" src("O01"))
    if (pl=="settings_ui" && isNA(fread))
      emit("O02", id, "把读数挂在设置面却没登记读到的是哪一格：设置面里 Siri 建议开关、逐 App 选择与 Suggestions & Search 定位是不同格子" src("O02"))
    if (pl=="mdm_status_item" && fread=="item_uid")
      emit("O03", id, "把 App 写了哪些索引条目挂在管理面回报项上：限制键清单里十个 Siri 键全是通道开关，没有任何一项读回条目级索引" src("O03"))
    if (pl=="developer_doc" && fread=="flag_state")
      emit("O04", id, "以开发文档作为资格位当前取值的读数面：文档给的是字段语义与默认值，不是这台设备的状态" src("O04"))
    if (fread=="list_membership" && (sst=="off" || sugst=="off" || isfalse(tvis) || isfalse(lvis)) && con=="confirmed")
      emit("O05", id, "用「设置面关着」或「这一格／这一条在清单里看不到」闭合「索引里没有了」：关闭开关与删除条目在公开口径里是两件事" src("O05"))

    # ---- V 族：删除与闭合（L11）----
    if (!isNA(dmeth) && dmeth!="none" && isfalse(dveri) && istrue(residue))
      emit("V01", id, "登记了删除方法、验证为否且仍记有残留：删除是否发生只能靠再查一次，不能靠推测" src("V01"))
    if (rebind=="assumed" && con=="confirmed")
      emit("V02", id, "把删除主键的重绑依据记为「应当还是同一个」却给出闭合结论：删除权绑在签名的 App／App 扩展与标识串上，不绑在猜测上" src("V02"))
    if (rebind=="bundle_id" && isNA(bid) && con=="confirmed")
      emit("V02", id, "重绑依据记为 bundle id 但台账里没有这一格：删除权绑在签名的 App 上，而签名要落到 bundle id 才能回指同一个对象" src("V02"))
    if (rebind=="signature" && isNA(team) && con=="confirmed")
      emit("V02", id, "重绑依据记为签名但未登记 Team ID：签名身份由证书与团队共同确定，只写「签过名」无法把删除权回绑到同一个开发方" src("V02"))
    if (origgone=="true" && isNA(dmeth) && con=="confirmed")
      emit("V03", id, "原数据已删除、删除方法未登记却闭合结论：公开口径两处写明条目要随原数据一起删" src("V03"))
    if (dact2=="user" && APPDEL)
      emit("V04", id, "删除主体记为用户但方法指向索引对象自身的 API：这四个删除入口的调用方是 App／扩展，用户侧途径只有开关与卸载" src("V04"))
    if (delable=="user_toggle_only" && APPDEL)
      emit("V04", id, "闸门面记为「只有用户侧开关能删」但删除方法指向索引对象自身的 API：两处指向两个不同的持有者，删除权不能同时成立" src("V04"))
    if (dactor ~ /^(app|user|mdm|system)$/ && dact2 ~ /^(app|user|mdm|system)$/ && dactor != dact2)
      emit("V04", id, "闸门门面与删除门面把删除主体记成两个不同的人（" dactor " 与 " dact2 "）：一条内容的删除权只有一个归属，两处要回指同一格" src("V04"))
    if (dmeth=="expiry_only" && isNA(exp_at) && con=="confirmed")
      emit("V05", id, "把唯一闭合手段记为过期但未登记过期时刻：过期时间只决定保留下限，没有这一时刻就不能说条目已经不在了" src("V05"))

    # ---- G 族：管理面（L10）----
    if (mcfg=="content_only" && !isNA(mkey) && mkey!="none")
      emit("G01", id, "把管理面记为「只能关通道不能清内容」却又引用了一个键作为内容删除依据：限制键里没有清索引内容的那一个" src("G01"))
    if (mcfg=="no" && isNA(msrc))
      emit("G02", id, "写下「管理面不可清索引内容」却未登记键清单来源：这一负空间结论必须回指到完整限制键清单本身" src("G02"))
    if (!isNA(mkey) && mkey!="none" && ((!isNA(mdec) && mdec!="none") || mpay=="com.apple.configuration.siri.settings") && isNA(mig))
      emit("G03", id, "同一对象同时登记命令面键与声明式配置（载荷或类型串）但未标注迁移状态：同一条说明里两套写法并存，回读要分两处" src("G03"))
    if (mig=="legacy_deprecated" && con=="confirmed" && isNA(chk_at))
      emit("G04", id, "引用已弃用键并闭合结论却没有核对时刻：十个 Siri 键的说明全部标注 Deprecated 并指向 com.apple.configuration.siri.settings" src("G04"))
    if (isfalse(msup) && (mkey=="allowSpotlightInternetResults"||mkey=="allowAssistantUserGeneratedContent"))
      emit("G05", id, "受监督登记为否却引用 " mkey "：前者非受监督支持已弃用，后者公开口径写明 Requires supervision: iOS" src("G05"))

    # ---- N 族：告知面（L1/L9）----
    if (isNA(nb) && (con=="confirmed" || pl=="settings_ui" || pl=="legal_page"))
      emit("N01", id, "对外结论、设置面读数或告知页引用未登记告知依据：面向用户的原话集中在 Siri 与听写、Improve Search 两页，超出这一范围的都要另找出处" src("N01"))
    if (nb=="vendor_claim" && con=="confirmed")
      emit("N02", id, "告知依据记为厂商说法却进入对外结论：公开口径写明检索面按保护用户信息设计并让用户自选分享范围，这一句之外不含厂商承诺" src("N02"))
    if (nb=="official_legal_page" && reach=="device_only" && isNA(ePub) && con=="confirmed" && (sst=="on"||sst=="per_app_off"))
      emit("N03", id, "用「Siri 请求不与 Apple Account 关联」闭合「本机索引不上传」：前者说的是请求侧的标识轮换，后者是 Core Spotlight 索引的另一段口径" src("N03"))

    if (isNA(srcv) || !isLineRef(lref))
      emit("X01", id, "缺来源文件或行号引用（doc.source / doc.line_ref）：这条判定无法回到公开文档逐行核对")

    hard = 0
    for (j = 1; j <= nline; j++) { split(lines[j], sp, "\t"); if (sp[2] == id && (sp[1] in HB)) hard++ }
    if ((isNA(kind) || isNA(ikind)) && (isNA(pl) && isNA(reach))) grade = "J4"
    else if (hard >= 5) grade = "J4"
    else if (hard >= 1 && (isNA(chk_at) || isNA(iuid) || isNA(dmeth) || isNA(reach))) grade = "J3"
    else if (hard >= 1) grade = "J2"
    else if (isNA(pl) || isNA(con) || isNA(reach) || isNA(gown) || isNA(dby) || isNA(ikind)) grade = "J3"
    else grade = "J1"
    if (grade == "J4") emit("J4", id, "可查询面主语无法确定（对象类型或索引种类与观测平面、范围同缺，或阻断信号不少于 5 条）：不能进入任何「谁能查回来、谁能删干净、谁能证明已删」的表述")
    if (grade == "J3") emit("J3", id, "能定「这条内容进了检索面」，不能定「谁判的、此刻还能不能查回来」：观测平面、范围、决定主体、核对时刻、条目标识或删除方法至少缺一个")
    if (grade == "J2") emit("J2", id, "能定身份与检索面落点，但声明、权利、开关、时效、观测或删除至少一段有阻断：可用于内部处置，不能作为对外归属表述")
    if (grade == "J1") emit("J1", id, "身份、声明、权利、开关、查询发起、闸门、范围、时效、观测、删除、管理面、引用十一格齐备且无阻断信号：可进入对外归属表述")
    jcount[grade]++
  }

  for (j = 1; j <= nline; j++) { split(lines[j], sp, "\t"); if (sp[1] !~ /^J[1234]$/) print lines[j] > "/dev/stderr" }
  if (!QUIET) for (j = 1; j <= nline; j++) { split(lines[j], sp, "\t"); if (sp[1] ~ /^J[1234]$/) print lines[j] }
  nblk = 0; nc = 0; nsig = 0
  for (j = 1; j <= nline; j++) { split(lines[j], sp, "\t"); if (sp[1] !~ /^J[1234]$/) nsig++ }
  for (c in cnt) { if (c !~ /^J[1234]$/) nc++; if (c in HB) nblk += cnt[c] }
  printf "\n检索面对象数=%d 信号行数=%d 判定行数=%d\n", nrec, nsig, nrec
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

## 22. 只读核验脚本二：检索面三件差集与公告子词表比对器

脚本一逐条查登记内部，这一支查**三份登记之间**：同一条内容在声明件、通道件、观测件里各被说过一次，说的还是不是同一件事，说的东西在公开词表里存不存在。

### 22.1 它查什么

`tools/query-plane-tripartite-diff.sh`（502 行）专查逐条审查查不出的四类问题（第 5—9 行的头部注释逐条写出）：

1. **三件不成对**——「声明了这一项，通道件与观测件两格却一条也没有」；
2. **覆盖空洞**——「某类对象明确需要的核对项，台账里一条也没有」；
3. **平面越界**——「读数挂在某个平面上，但那个平面按公开口径根本不承载这一格」；
4. **归属悬空**——「台账引用的公告组件、CVE、限制键或声明式类型，公开词表里不存在」。

### 22.2 三份输入与 21 项核对项

三份输入**顺序固定、全部只读**（第 84—88 行要求恰好三份且都可读，少给多给都是 2）：

1. **三件清单**，每行 8 列：`<对象标识>,<对象类>,<核对项>,<三件状态>,<读数平面>,<词表归属>,<引用>,<对外表述>`；
2. **三件能力表**，每行 3 列：`<对象类>,<核对项>,<可得性>`，可得性取 `required`／`optional`／`not_applicable`／`undocumented`；
3. **公开词表**，制表符三列：`<词表类别>\t<词表值>\t<来源标识>`。

10 个对象类（8 个真实 + `not_recorded`／`unknown`）、**21 项核对项**按三件切分：声明件 6 项（`index_name`／`index_kind`／`eligibility_decl`／`type_identifier`／`usage_notice`／`content_owner_decl`）、通道件 7 项（`api_path`／`query_api`／`initiated_by`／`item_uid`／`domain_id`／`attributes_requested`／`max_results`）、观测件 8 项（`settings_toggle`／`settings_list`／`profile_key`／`restriction_key`／`advisory_component`／`query_result`／`notice_page`／`delete_verified`）。16 个读数平面、11 类词表归属（含 `doc_ref`）与 7 个公开词表类别都在 usage 文本里枚举（第 33—70 行）。

能力表 `FX/capability-17.csv`：182 行 = 14 行注释 + **168 数据行**（8 类 × 21 项），其中 required 76、optional 30、not_applicable 46、undocumented 16。公开词表 `FX/vocab-17.tsv`：722 行 = 表头 + **721 条**，归一化去重 **720**（唯一一次折叠是 `Remote Management` 与 `RemoteManagement`）。

### 22.3 信号族与非对称的阻断设计

| 族 | 码数 | 覆盖 | 是否阻断 |
| --- | --- | --- | --- |
| S 清单自身形态 | 9 | 列数、空标识、CRLF、重复登记、非法枚举、内容越界形态 | `S08` 不阻断（同一对象同一核对项重复登记但读数一致） |
| K 内容越界 | 2 | 正文／检索词／转录／凭据形态；设备绝对路径 | 阻断 |
| M 公开词形 | 2 | 逐核对项的公开词形与标识形态（`max_results` 由 `M01` 独检，`V02` 不重复告警） | 阻断 |
| C 能力表自身形态 | 6 | 未知对象类、未知核对项、可得性非法、四列、空表 | 阻断 |
| D 覆盖空洞 | 6 | required 这一格没有读数（`D02`）、required 被记成不适用或与公开口径相反（`D03`）、整类缺对象、这一格整段没有登记行（`D05`） | `D02`／`D03`／`D05` 不阻断：它们说的是「台账缺登记」，不是「登记互相矛盾」 |
| P 平面越界 | 5 | 平面不承载该格、`vendor_claim`／`app_self_report` 承载对外表述、设备侧命令作为来源 | 阻断 |
| T 三件差集与矛盾 | 6 | 声明了却没有通道、有观测却没声明、两平面读数互相矛盾、场景门配对 | 阻断 |
| X 公开词表比对 | 6 | 组件名／CVE／限制键／声明式类型悬空（`X01`／`X02`／`X05`／`X06`）、词表自身形态（`X03`）、**`X04` 列间错位** | `X03`／`X04` 不阻断：前者只让比对降级，后者承载本文的中心读数 |
| V 引用形态与口径闭合 | 5 | 引用形态与是否对外表述的闭合（`V01`／`V02`／`V05`）、跨对象口径统一（`V03`） | `V03`／`V04` 不阻断（同一格在不同对象间既「已读数」又「明确不存在」属口径未统一） |
| Q 闭合等级 | 4 | 第 19.2 节四档 | 不计 |

阻断集写死在第 190—198 行，共 39 码。8 个不阻断码的设计理由写在第 19.1 节末尾——其中 `X04` 承载本文的中心读数，若设为阻断，干净输入也无法退出 0，脚本就失去下界。

### 22.4 输出与退出码

stdout 三段：**三件覆盖矩阵**（每对象一行，给出声明件／通道件／观测件已读数格数与该类 required 总数、命中数与缺项清单）、**公开词表读数**（一行七个计数）、逐对象的 Q 档。stderr 给逐条信号。`-q` 关掉的是第 470—487 行那两段 stdout（矩阵与词表读数）加上第 490 行的逐对象 Q 档；信号（第 489 行）与汇总照旧。汇总三行（第 494—496 行）给出对象数、登记行、能力表行、词表词条、信号行数、不同码数、阻断条数与 Q 分布，随后才是按码计数表（第 497—499 行）。退出码同脚本一（第 500 行）。

公开词表读数那行是本文中心事实的机器版本，合格夹具下逐字为：

```text
去重词条=720 CVE 词条=330 组件词条=128 检索面具名组件=6 条目级组件名=0 键类词条=222 挂在公告平面的已读数=0
```

`检索面具名组件=6` 与 `条目级组件名=0` 这一对（第 160—163 行定义 FACE 与 ENTRY 两组词形，第 320—322 行匹配）就是第 13.2 节表格里「组件列具名 6 个、影响句检索面词形 0 命中」的同一条读数在词表侧的形态。当有读数挂在公告平面时（`aRec>0`），`X04` 就打出「按这份词表口径，检索面缺陷只能归到组件，不能归到某一条索引条目」（第 336 行）。

### 22.5 它不做什么

同脚本一：不联网取公告、不读索引正文与凭据、不修改输入。第 13—16 行明确「给出三件不成对或覆盖空洞**不等于补登记**：补登记需要新的读数来源，本脚本只指出缺哪一格、按公开口径这一格本应由哪个平面给出」。唯一写出目标是 `mktemp -d`（第 90 行，前缀 `qpt.XXXXXX`，与脚本一的 `qpr.XXXXXX` 分开，两者可并存不冲突），第 91 行 trap 删除，且本实现不向其写入任何字节。

### 22.6 合格夹具读数

`FX/inventory-17-good.txt`（91 行、8 个对象，逐类一个）配干净能力表与词表，输出八行矩阵全部 `缺:（无）`、Q 分布 `Q1=8`、0 条信号、退出码 0。矩阵首行与末行取自 `FX/run-log-2.txt` 第 814—839 行这一段（两行分别是第 817 行与第 824 行）：

```text
QRY-NOTE-APP	cs_index_app	声明件=5 通道件=6 观测件=5	required=16 已读数=16 缺:（无）
QRY-SHORT-SUGEST	shortcut_suggestion	声明件=2 通道件=1 观测件=3	required=6 已读数=6 缺:（无）
```

`cs_index_app` 的 required 是 16 项中的 21，`shortcut_suggestion` 只要求 6 项——这两个数字来自能力表而不是脚本硬编码，因此换一份能力表就会改变 Q3 的触发面（R36 用一行畸形能力表把 9 个对象打到 Q4，正是这条设计的实证）。

### 22.7 全量源码

```bash
#!/usr/bin/env bash
# query-plane-tripartite-diff.sh —— 检索面三件差集与公告子词表比对器（离线 / 只读 / 不联网 / 不碰设备）
# 作用：把「声明件（App 往索引里写了什么）× 通道件（哪条 API 通道能把它读回来）×
#       观测件（哪一面真能读回这一格）」三份登记放在一起算差集，专查逐条审查
#       （query-plane-ledger-review.sh）查不出的四类问题——
#       「声明了这一项，通道件与观测件两格却一条也没有」（三件不成对）；
#       「某类对象明确需要的核对项，台账里一条也没有」（覆盖空洞）；
#       「读数挂在某个平面上，但那个平面按公开口径根本不承载这一格」（平面越界）；
#       「台账引用的公告组件、CVE、限制键或声明式类型，公开词表里不存在」（归属悬空）。
# 输入（顺序固定，三个文件全部只读）：
#   1) 三件清单   每行 8 列：<对象标识>,<对象类>,<核对项>,<三件状态>,<读数平面>,<词表归属>,<引用>,<对外表述>
#   2) 三件能力表 每行 3 列：<对象类>,<核对项>,<可得性>
#   3) 公开词表   制表符分隔三列：<词表类别>	<词表值>	<来源标识>    # 开头与空行忽略
# 边界：本脚本不联网取公告、不调用 mdfind/mdls/mdimport/mdutil/profiles/sysctl/xcrun/defaults/log/
#       find/ls 等任何命令行工具、不读取索引正文或凭据、不修改输入文件；只核对三份登记与公开词表是否自洽。
#       给出「三件不成对」或「覆盖空洞」不等于补登记：补登记需要新的读数来源，本脚本只指出缺哪一格、
#       按公开口径这一格本应由哪个平面给出。唯一写出目标是 mktemp -d 创建的临时目录，退出时删除，
#       本实现不向其写入任何字节。
set -u
LC_ALL=C; export LC_ALL

usage() {
  cat <<'EOF'
用法: query-plane-tripartite-diff.sh [-q] 三件清单 三件能力表 公开词表
  -h|--help 显示本帮助；-q 只输出汇总，不逐条打印三件覆盖矩阵与词表读数
三件清单行格式（8 列，逗号分隔；# 与空行忽略，行尾 CR 忽略，值里不能含逗号）:
  <对象标识>,<对象类>,<核对项>,<三件状态>,<读数平面>,<词表归属>,<引用>,<对外表述>
对象类（8 + 2）: cs_index_app cs_index_extension app_entity intent_donation user_activity
  web_markup system_service shortcut_suggestion not_recorded unknown
核对项（21 项，按三件归属）:
  声明件 declared  index_name index_kind eligibility_decl type_identifier usage_notice
                   content_owner_decl
  通道件 channel   api_path query_api initiated_by item_uid domain_id
                   attributes_requested max_results
  观测件 observed  settings_toggle settings_list profile_key restriction_key
                   advisory_component query_result notice_page delete_verified
三件状态: recorded absent not_applicable not_recorded unknown
读数平面: core_spotlight_api app_intents_schema nsuseractivity_api web_markup_source
  settings_ui configuration_profile mdm_declaration declarative_management
  advisory_component query_response notice_page vendor_claim app_self_report
  none not_recorded unknown
词表归属: api_symbol activity_property plist_key declarative_type restriction_key doc_ref
  advisory_component advisory_cve mixed not_recorded unknown
对外表述: yes no not_recorded unknown
引用格: 公开词形值（见下）/ 词表值本身 / A/adding-...:147 / C/mdm-restriction-keys.txt:143 /
  none（确认无对应条目）/ not_recorded（未登记）
逐核对项的公开词形值（M01/M02 据此判定）:
  index_name             default_index named_index
  index_kind             core_spotlight nsuseractivity app_entity intent_donation web_markup system_service
  eligibility_decl       eligibleForSearch eligibleForPublicIndexing eligibleForHandoff eligibleForPrediction none
  type_identifier        标识符形态（点分段类型标识）
  usage_notice           siri_dictation_legal improve_siri_optin none
  content_owner_decl     app user system
  api_path               csssearchquery csuserquery core_spotlight_source app_shortcuts
  query_api              user_query search_query spotlight_tool none
  initiated_by           app app_extension system_service user shortcut
  item_uid               标识符形态（开发者自选的条目标识）
  domain_id              标识符形态（表示条目所属域或所有者）
  attributes_requested   displayName title keywords contentDescription thumbnailURL
  max_results            unset default 或 1—4 位数字
  settings_toggle        on off not_available
  settings_list          listed not_listed
  query_result           hit no_hit not_run
  notice_page            siri_dictation_legal improve_siri_optin speech_recognition none
  delete_verified        verified not_verified requery_missing
  profile_key            填声明式类型词表值本身
  restriction_key        填限制键词表值本身
  advisory_component     填公告组件词表值本身或 CVE 号
三件能力表行格式（3 列）: <对象类>,<核对项>,<可得性>    可得性: required optional not_applicable undocumented
公开词表行格式（3 列，制表符分隔）: <词表类别>	<词表值>	<来源标识>
  词表类别: api_symbol activity_property plist_key declarative_type restriction_key
  advisory_component advisory_cve
信号族：S 清单自身形态 / C 能力表自身形态 / K 内容越界 / M 公开词形 / D 覆盖空洞 / P 平面越界 /
        T 三件差集与互相矛盾 / X 公开词表比对 / V 引用形态与口径闭合 / Q1—Q4 闭合等级
闭合等级：Q1 三件差集、平面可得性、公开词表三段齐备且无阻断 / Q2 存在阻断信号 /
          Q3 只能定覆盖面不能定归属 / Q4 连可得性都不能定
退出码：出现阻断信号时为 1，输入不可用时为 2，否则为 0。覆盖空洞与口径漂移不计入阻断，只落 Q3。
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

TMPD=$(mktemp -d "${TMPDIR:-/tmp}/qpt.XXXXXX") || { echo "无法创建临时目录" >&2; exit 2; }
trap 'rm -rf "$TMPD"' EXIT INT TERM

awk -v QUIET="$QUIET" '
function emit(code, id, msg) { cnt[code]++; lines[++nline] = sprintf("%s\t%s\t%s", code, (id==""?"-":id), msg) }
function isNA(v)    { return (v=="" || v=="not_recorded" || v=="unknown") }
function trim(v)    { gsub(/^[[:space:]]+|[[:space:]]+$/, "", v); return v }
function nrm(v,  t) { t = tolower(v); gsub(/[[:space:]_\/.:-]/, "", t); return t }
function isCve(v)   { return (v ~ /^CVE-[0-9]{4}-[0-9]{4,}$/) }
function isDocRef(v){ return (v ~ /^[ABC]\/[A-Za-z0-9._\/-]+:[0-9]+(-[0-9]+)?$/) }
function isIdForm(v){ return (v ~ /^[A-Za-z][A-Za-z0-9_-]*(\.[A-Za-z0-9_-]+)+$/) || (v ~ /^[a-z]+[A-Z][A-Za-z0-9]*$/) }
function isCount(v) { return (v ~ /^[0-9]{1,4}$/) }
function isSecretish(v) {
  return (v ~ /-----BEGIN/ || v ~ /\.(p12|pfx|mobileprovision|provisionprofile|cap|pcap|plist|sqlite|shmdir)$/ \
      || v ~ /^\/(Applications|private|var\/mobile|Users|Library)\// || v ~ /^file:\/\// \
      || v ~ /^data:[A-Za-z\/+]*;base64,/ || length(v) > 200)
}
function isHexDump(v) { return (v ~ /^([0-9a-fA-F][0-9a-fA-F] )+[0-9a-fA-F][0-9a-fA-F]/) }
function src(c) { return (c in DOC) ? "（" DOC[c] "）" : "" }
function ck(a, b) { return a SUBSEP b }
function isBody(line) { return (line !~ /^[[:space:]]*#/ && line !~ /^[[:space:]]*$/) }
function mkset(set, str,  t, i, n) { n = split(str, t, " "); for (i = 1; i <= n; i++) set[t[i]] = 1 }
function mkit(set, fam, str,  t, i, n) { n = split(str, t, " "); for (i = 1; i <= n; i++) { set[t[i]] = 1; ITM[t[i]] = 1; ITFAM[t[i]] = fam } }
function mktok(str,  t, i, n) { n = split(str, t, " "); for (i = 1; i <= n; i++) TSET[t[i]] = 1 }
function tok(it,  t) { return (it in TOK) ? TOK[it] : "" }
function hasTok(it, v,  t, i, n) {
  n = split(tok(it), t, " ")
  for (i = 1; i <= n; i++) if (t[i] == v) return 1
  return 0
}
function ppair(p, fam) { PAIR[ck(p, fam)] = 1 }
function pex(p, it)    { PAIR[ck(p, it)] = 1 }
function vpair(vw, fam) { PAIR[ck("VW:" vw, fam)] = 1 }
function GV(i, f,  k) { k = ck(i, f); return (k in statOf) ? statOf[k] : "" }
function GR(i, f,  k) { k = ck(i, f); return (k in refOf) ? refOf[k] : "" }
function GP(i, f,  k) { k = ck(i, f); return (k in planeOf) ? planeOf[k] : "" }
function advRecCount(  kk, t) { t = 0; for (kk in statOf) if (statOf[kk]=="recorded" && planeOf[kk]=="advisory_component") t++; return t }
BEGIN {
  FS = ","
  mkset(KD, "cs_index_app cs_index_extension app_entity intent_donation user_activity web_markup system_service shortcut_suggestion not_recorded unknown")
  mkit(ITM, "declared", "index_name index_kind eligibility_decl type_identifier usage_notice content_owner_decl")
  mkit(ITM, "channel",  "api_path query_api initiated_by item_uid domain_id attributes_requested max_results")
  mkit(ITM, "observed", "settings_toggle settings_list profile_key restriction_key advisory_component query_result notice_page delete_verified")
  TOK["index_name"]            = "default_index named_index"
  TOK["index_kind"]            = "core_spotlight nsuseractivity app_entity intent_donation web_markup system_service"
  TOK["eligibility_decl"]      = "eligibleForSearch eligibleForPublicIndexing eligibleForHandoff eligibleForPrediction none"
  TOK["usage_notice"]          = "siri_dictation_legal improve_siri_optin none"
  TOK["content_owner_decl"]    = "app user system"
  TOK["api_path"]              = "csssearchquery csuserquery core_spotlight_source app_shortcuts"
  TOK["query_api"]             = "user_query search_query spotlight_tool none"
  TOK["initiated_by"]          = "app app_extension system_service user shortcut"
  TOK["attributes_requested"]  = "displayName title keywords contentDescription thumbnailURL"
  TOK["max_results"]           = "unset default"
  TOK["settings_toggle"]       = "on off not_available"
  TOK["settings_list"]         = "listed not_listed"
  TOK["query_result"]          = "hit no_hit not_run"
  TOK["notice_page"]           = "siri_dictation_legal improve_siri_optin speech_recognition none"
  TOK["delete_verified"]       = "verified not_verified requery_missing"
  TOK["type_identifier"]       = "type_identifier"
  TOK["item_uid"]              = "item_uid"
  TOK["domain_id"]             = "domain_id"
  for (t in TOK) mktok(TOK[t])
  # 近义词：形似公开词形但不在这份公开口径里
  mkset(NEAR, "enabled disabled true false on_off indexable searchable indexed deleted gone removed confirmed_result no_result allow deny permitted blocked granted donated donated_intent spotlight_index siri_suggestion auto")
  mkset(ST, "recorded absent not_applicable not_recorded unknown")
  mkset(PL, "core_spotlight_api app_intents_schema nsuseractivity_api web_markup_source settings_ui configuration_profile mdm_declaration declarative_management advisory_component query_response notice_page vendor_claim app_self_report none not_recorded unknown")
  mkset(VW, "api_symbol activity_property plist_key declarative_type restriction_key doc_ref advisory_component advisory_cve mixed not_recorded unknown")
  mkset(OUTW, "yes no not_recorded unknown")
  mkset(AV, "required optional not_applicable undocumented")
  mkset(VK, "api_symbol activity_property plist_key declarative_type restriction_key advisory_component advisory_cve")
  # 检索面词形（用于 X04 负空间读数）：具名组件里能数到的面
  mkset(FACE, "spotlight siri shortcuts intents intelligence help")
  # 条目级词形：公告组件词表里应当出现却没有出现的层级
  mkset(ENTRY, "searchable csssearchable indexitem donation entity attributeset reindex")
  # 平面承载哪一件：按公开口径逐格对齐（adding 第 119—128、142—156、184—231 行；corespotlight 第 15、18—19、79 行；
  # cssearchableindex 第 57—131、207、241、263 行；csuserquery 第 6、50、63、67 行；spotlight-search-tool 第 19—21 行；
  # siri-dictation-legal 第 72—73、82 行；mdm-restrictions 第 1243—1385 行）
  ppair("core_spotlight_api","declared");   ppair("core_spotlight_api","channel")
  ppair("app_intents_schema","declared");   ppair("nsuseractivity_api","declared")
  ppair("web_markup_source","declared")
  ppair("app_intents_schema","channel");    ppair("nsuseractivity_api","channel")
  ppair("web_markup_source","channel")
  ppair("query_response","channel")
  ppair("settings_ui","observed");          ppair("settings_ui","channel")
  ppair("configuration_profile","observed"); ppair("mdm_declaration","observed")
  ppair("declarative_management","observed"); ppair("advisory_component","observed")
  ppair("query_response","observed");       ppair("notice_page","observed")
  ppair("notice_page","declared");          ppair("vendor_claim","observed")
  ppair("app_self_report","observed")
  pex("core_spotlight_api","delete_verified"); pex("query_response","delete_verified")
  pex("core_spotlight_api","max_results");     pex("query_response","max_results")
  pex("settings_ui","index_kind");             pex("app_intents_schema","content_owner_decl")

  # 词表归属描述哪一件
  vpair("api_symbol","declared");   vpair("api_symbol","channel")
  vpair("activity_property","declared"); vpair("plist_key","declared")
  vpair("declarative_type","observed"); vpair("restriction_key","observed")
  vpair("advisory_component","observed"); vpair("advisory_cve","observed")
  vpair("api_symbol","observed");   vpair("activity_property","channel")
  vpair("doc_ref","declared"); vpair("doc_ref","channel"); vpair("doc_ref","observed")
  HB["S01"]=1; HB["S02"]=1; HB["S03"]=1; HB["S04"]=1; HB["S05"]=1; HB["S06"]=1; HB["S07"]=1; HB["S09"]=1
  HB["K01"]=1; HB["K02"]=1
  HB["M01"]=1; HB["M02"]=1
  HB["C01"]=1; HB["C02"]=1; HB["C03"]=1; HB["C04"]=1; HB["C05"]=1; HB["C06"]=1
  HB["D01"]=1; HB["D04"]=1; HB["D06"]=1
  HB["P01"]=1; HB["P02"]=1; HB["P03"]=1; HB["P04"]=1; HB["P05"]=1
  HB["T01"]=1; HB["T02"]=1; HB["T03"]=1; HB["T04"]=1; HB["T05"]=1; HB["T06"]=1
  HB["X01"]=1; HB["X02"]=1; HB["X05"]=1; HB["X06"]=1
  HB["V01"]=1; HB["V02"]=1; HB["V05"]=1
  DOC["S01"]="三件清单每行必须恰好八列（标识,对象类,核对项,三件状态,读数平面,词表归属,引用,对外表述）"
  DOC["S02"]="清单主键为空或含空白，无法与三件能力表对齐"
  DOC["S03"]="对象类取值域按公开口径列出：App 自建索引、Spotlight 索引扩展、App Entity、Intent 捐赠、用户活动与网页标记分属不同通道，见 adding 第 95—96、119、147、184、204 行与 appintents_appentity 第 1、186 行"
  DOC["S04"]="核对项词表为本报告三件 21 项，逐项出处见 adding 第 119—231 行、corespotlight 第 79 行、cssearchableindex 第 57—131 行、csuserquery 第 6—67 行、nsuseractivity 第 71、315—336 行、siri-dictation-legal 第 72—82 行与 mdm-restriction-keys.txt 全 220 行、216 个键名"
  DOC["S05"]="留空、not_recorded 与 absent 是三件事：公开口径没有面向第三方的索引条目清单接口，见 adding 第 86—88 行与 spotlight-search-tool 第 19—21 行"
  DOC["S06"]="读数平面取值不在允许集合：索引写入面、查询面、设置面与管理面分属四类，见 corespotlight 第 15、79 行与 csuserquery 第 6、50 行"
  DOC["S07"]="词表归属或对外表述取值不在允许集合：三套词表分离见 cssearchableitem 第 124、195 行、mdm-restriction-keys.txt 全 220 行、216 个键名与 advisory-17.tsv 组件列"
  DOC["S08"]="同一对象同一核对项重复登记且三格一致（不阻断，但差集会重复计数）：见 nsbonjourservices 之外的 adding 第 230—231 行（资格开关要逐个写）"
  DOC["S09"]="同一对象同一核对项出现两种状态、平面或词表归属：口径漂移，见 cssearchableindex 第 69—131 行（三种删除入口各自成一条）"
  DOC["K01"]="引用格形似密钥、凭据、索引库文件、设备绝对路径或整段载荷正文：台账只登记哪一个对象在哪一格被判定成什么，不登记内容"
  DOC["K02"]="引用格登记了设备侧命令行入口名：本脚本与台账都不以任何命令行工具作为读数来源，见 adding 第 86—88 行（索引工具只用于原型与测试）"
  DOC["M01"]="该核对项的引用值不在公开词形表里（资格开关、索引名形态、设置开关与公告标识各自成词）：见 adding 第 208—231 行、nsuseractivity 第 315—336 行与 siri-dictation-legal 第 72—73 行"
  DOC["M02"]="引用值是公开词形的近义词：公开口径只给 eligibleForSearch / eligibleForPublicIndexing / eligibleForHandoff / eligibleForPrediction 四个资格词与 Turn Off Siri 一条删除途径，自造开关词无法回指"
  DOC["C01"]="三件能力表每行必须恰好三列（对象类,核对项,可得性）"
  DOC["C02"]="能力表对象类取值不在允许集合：见 adding 第 119—204 行与 appintents_appentity 第 1、186 行"
  DOC["C03"]="能力表核对项不在 21 项词表内：见 cssearchableitem 第 124、131、195 行与 csuserquery 第 6、50、63、67 行"
  DOC["C04"]="可得性取值不在 required/optional/not_applicable/undocumented：见 corespotlight 第 15 行（Spotlight 文件导入扩展在 macOS 上不提供功能）"
  DOC["C05"]="同对象类同核对项两条不同可得性，差集失去唯一基准：见 cssearchableindex 第 69、115、131 行与 adding 第 95—96 行"
  DOC["C06"]="三件能力表一条有效行都没有：三件差集无法计算"
  DOC["D01"]="required 核对项明确登记为不存在：见 adding 第 145、156 行（条目必须带标识与属性集才能入索引）"
  DOC["D02"]="required 核对项登记为未登记：覆盖空洞，见 adding 第 86—88 行（没有对外可查的条目清单）"
  DOC["D03"]="not_applicable 项却被记为已读数，或 required 项被记为不适用：见 corespotlight 第 15 行与 adding 第 95—96 行"
  DOC["D04"]="清单里的对象类在能力表一行都没有：这一类的判据未建模，见 appintents_appentity 第 1、186 行与 intents 第 8、30 行"
  DOC["D05"]="required 核对项在本对象完全没有登记行：与 D02 不同的第二种空洞形态，见 cssearchableitem 第 195 行（删除按标识符定位）"
  DOC["D06"]="同一对象登记了两个对象类：一条索引内容只有一个发起通道，见 adding 第 119、147、184、204 行"
  DOC["P01"]="通道件格记在管理面平面上：公开限制键清单（全 220 行、216 个键名）里没有任何一条能删掉或读出某一条索引条目，见 mdm-restriction-keys.txt 与 mdm-restrictions 第 1243—1385 行"
  DOC["P02"]="声明件格记在查询响应或公告平面上：条目资格与类型标识写在索引写入调用里，不由查询面给出，见 adding 第 208—231 行与 corespotlight_cssearchableindexdelegate 第 42、63 行"
  DOC["P03"]="观测件格记在配置画像或限制键面上且该键在公开清单里不存在：这一格没有管理面对应项，见 mdm-restriction-keys.txt 全 220 行、216 个键名与 mdm-restrictions 第 1250 行"
  DOC["P04"]="记为已读数但读数平面为无平面：见 adding 第 86—88 行与 spotlight-search-tool 第 19—21 行"
  DOC["P05"]="平面与核对项所属件不匹配（未列入前四种的组合）：见 corespotlight 第 15、79 行与 csuserquery 第 6、50 行"
  DOC["T01"]="三件只登记了声明件：写了索引调用不等于任何一面读得回来，公开口径没有面向第三方的条目清单接口，见 adding 第 86—88 行"
  DOC["T02"]="有观测件读数却无声明件：条目内容必须先在索引写入面登记标识与属性集，未登记时的读数落在对象之外，见 adding 第 145—156 行与 cssearchableitem 第 195 行"
  DOC["T03"]="声明件用公告组件词表或管理面键词表描述索引写入：词表归属越层，见 advisory-17.tsv 组件列与 mdm-restriction-keys.txt 全 220 行、216 个键名"
  DOC["T04"]="资格未授予却把查询命中记为真：eligibleForSearch 决定内容是否进入设备内索引与搜索结果，未授予时查询面不该读回它，见 adding 第 208、230—231 行与 nsuseractivity 第 333、336 行"
  DOC["T05"]="删除登记为已验证却没有回读依据：删除按条目标识、域标识或全量三种入口执行，公开口径未承诺即时生效，验证必须落在再一次查询上，见 cssearchableindex 第 69、115、131 行"
  DOC["T06"]="告知面有声明却没有能读回它的面（或反之）：Siri 与听写的告知文本、关闭即删除本设备转录这两条都写在法律页，不在设置开关之外，见 siri-dictation-legal 第 72—73、82 行与 legal-improve-siri-dictation 第 40—41 行"
  DOC["X01"]="引用的 CVE 号不在公开公告词表内：见 advisory-17.tsv 的 cve 列（1266 行去重为 330 个 CVE）"
  DOC["X02"]="引用的组件名归一化后不在公告组件词表内：见 advisory-17.tsv 的 component 列（1266 行去重为 129 个组件名）"
  DOC["X03"]="公开词表自身形态非法（类别不在允许集合、值缺格或记录不足两列）：见 advisory-17.tsv 表头与 mdm-restriction-keys.txt 第 1—220 行（第 1—4 行是页面分段标题）"
  DOC["X04"]="公告组件词表里检索面具名组件只有 Spotlight、Shortcuts、Siri、Apple Intelligence、App Intents、Help Viewer 六个，条目级组件名（searchable、index item、donation、entity 一类）为 0，却有读数挂在公告平面：见 advisory-17.tsv 的 component 列"
  DOC["X05"]="引用的限制键或声明式类型不在公开清单内：这一格在管理面词表里不存在，见 mdm-restriction-keys.txt 全 220 行、216 个键名与 mdm-restrictions 第 1243—1385 行"
  DOC["X06"]="挂在公告面或管理面的读数没有词表标识：公告只给 CVE 与组件名，管理面只给键名与声明式类型，缺任一格就无法回指，见 advisory-17.tsv 表头"
  DOC["V01"]="本对象所有 required 核对项的引用格全为无标识：结论无法回指任何一格，见 adding 第 119—128 行"
  DOC["V02"]="引用格既不是公开词表值也不是文档行号形态且平面非公告：这条判定无法回到公开文档逐行核对，见 cssearchableitem 第 124、195 行"
  DOC["V03"]="同一对象类同一核对项在对象之间既有已读数又有明确不存在（不阻断）：登记口径未统一，见 cssearchableindex 第 69—131 行"
  DOC["V04"]="已读数但未登记这一格是否会对外（不阻断）：捐赠与建议的对外性由设置面开关与法律页共同决定，见 siri-dictation-legal 第 72—73 行与 intents 第 8 行"
  DOC["V05"]="对外表述为是却把两套词表混记在同一格：三套词表分属三层，见 cssearchableitem 第 195 行、mdm-restriction-keys.txt 第 5—220 行与 advisory-17.tsv 组件列"
  DOC["Q1"]="三件差集、平面可得性与公开词表三段齐备且无阻断：见 adding 第 119—231 行与 csuserquery 第 6—67 行"
  DOC["Q2"]="存在阻断信号：见 corespotlight 第 15 行、cssearchableindex 第 69—131 行与 mdm-restriction-keys.txt 全 220 行、216 个键名"
  DOC["Q3"]="只能定覆盖面不能定归属：见 adding 第 86—88 行与 mdm-restrictions 第 1243—1385 行"
  DOC["Q4"]="连可得性都不能定：见 adding 第 95—96 行与 appintents_appentity 第 1、186 行"
}

# ---- 输入 1：三件清单 ----
FILENAME == ARGV[1] && isBody($0) {
  line = $0; sub(/\r$/, "", line)
  n = split(line, fx, ",")
  if (n != 8) { emit("S01", fx[1], "三件清单记录不是恰好八列：" line src("S01")); next }
  id = trim(fx[1]); kd = trim(fx[2]); it = trim(fx[3]); st = trim(fx[4])
  pl = trim(fx[5]); vw = trim(fx[6]); rf = trim(fx[7]); ow = trim(fx[8])
  if (id == "" || id ~ /[ \t]/) { emit("S02", id, "对象标识为空或含空白，无法与三件能力表对齐" src("S02")); next }
  if (!(id in seen)) { seen[id] = 1; order[++nid] = id }
  subj = 0
  if (!(kd in KD)) { emit("S03", id, "对象类取值不在允许集合：" kd src("S03")); subj = 1 }
  if (!(it in ITM)) { emit("S04", id, "核对项不在三件 21 项词表内：" it src("S04")); subj = 1 }
  if (subj) subjBad[id] = 1
  if (!(st in ST)) emit("S05", id, "三件状态取值非法：" st src("S05"))
  if (!(pl in PL)) emit("S06", id, "读数平面取值非法：" pl src("S06"))
  if (!(vw in VW)) emit("S07", id, "词表归属取值非法：" vw src("S07"))
  if (!(ow in OUTW)) emit("S07", id, "对外表述取值非法：" ow src("S07"))
  if (!(it in ITM)) next
  itemRows++
  if (!(id in kdSeen)) { kdSeen[id] = 1; kdOf[id] = kd; kdCnt[id] = 1 }
  else if (kdOf[id] != kd && !(kd in kdAlt[id])) { kdAlt[id][kd] = 1; kdCnt[id]++ }
  k = ck(id, it)
  if (k in statOf) {
    if (statOf[k]==st && planeOf[k]==pl && vwOf[k]==vw) emit("S08", id, "核对项 " it " 重复登记且三格一致（差集会重复计数）" src("S08"))
    else emit("S09", id, "核对项 " it " 出现两种登记口径：" statOf[k] "/" planeOf[k] "/" vwOf[k] " 与 " st "/" pl "/" vw src("S09"))
    next
  }
  statOf[k] = st; planeOf[k] = pl; vwOf[k] = vw; refOf[k] = rf; outOf[k] = ow
  famRows[id, ITFAM[it]]++
  if (st == "recorded") famRec[id, ITFAM[it]]++
  next
}

# ---- 输入 2：三件能力表 ----
FILENAME == ARGV[2] && isBody($0) {
  line = $0; sub(/\r$/, "", line)
  n = split(line, fx, ",")
  if (n != 3) { emit("C01", fx[1], "三件能力表记录不是恰好三列：" line src("C01")); next }
  kd = trim(fx[1]); it = trim(fx[2]); av = trim(fx[3])
  if (!(kd in KD)) { emit("C02", kd, "能力表对象类取值不在允许集合：" kd src("C02")); next }
  if (!(it in ITM)) { emit("C03", kd, "能力表核对项不在 21 项词表内：" it src("C03")); next }
  if (!(av in AV)) { emit("C04", kd, "可得性取值不在允许集合：" av src("C04")); next }
  kk = ck(kd, it)
  if (kk in capOf) {
    if (capOf[kk] != av) emit("C05", kd, "核对项 " it " 有两条不同可得性：" capOf[kk] " / " av src("C05"))
    next
  }
  capOf[kk] = av; capRows++
  if (!(kd in capKdSet)) { capKdSet[kd] = 1; capKdN++ }
  next
}

# ---- 输入 3：公开词表（制表符分隔三列：类别 / 值 / 来源）----
FILENAME == ARGV[3] && isBody($0) {
  line = $0; sub(/\r$/, "", line)
  if (line ~ /^kind\tvalue/) next
  n = split(line, a, "\t")
  if (n < 2) { emit("X03", trim(a[1]), "公开词表记录不足两列（类别<TAB>值）：" line src("X03")); next }
  vk = trim(a[1]); vv = trim(a[2])
  if (!(vk in VK)) { emit("X03", vk, "公开词表类别不在允许集合：" vk src("X03")); next }
  if (vv == "") { emit("X03", vk, "公开词表值为空：" line src("X03")); next }
  nk = nrm(vv)
  if (!(nk in vocab)) { vocab[nk] = vk; vrows++ }
  if (vk == "advisory_cve") { if (!(vv in cves)) { cves[vv] = 1; cveN++ } }
  else if (vk == "advisory_component") {
    if (!(nk in compSeen)) {
      compSeen[nk] = 1; compN++
      low = tolower(vv)
      f = 0; e = 0
      for (w in FACE)  if (low ~ ("(^|[ ()])" w)) f = 1
      for (w in ENTRY) if (low ~ w) e = 1
      if (f) faceN++
      if (e) { entryN++; entryList = entryList " " vv }
    }
  }
  else if (vk == "restriction_key" || vk == "declarative_type") { if (!(nk in keySeen)) { keySeen[nk] = 1; keyN++ } }
  next
}

END {
  if (capRows == 0) emit("C06", "-", "三件能力表一条有效行都没有：三件差集无法计算" src("C06"))
  if (vrows == 0) emit("X03", "-", "公开词表无可用行：公告标识、限制键与声明式类型比对均不可执行" src("X03"))
  aRec = advRecCount()
  if (vrows > 0 && compN > 0 && faceN > 0 && entryN == 0 && aRec > 0)
    emit("X04", "-", "公告组件词表去重 " compN " 个组件名，其中检索面具名组件 " faceN " 个、条目级组件名 0 个，却有 " aRec " 条读数挂在公告平面：按这份词表口径，检索面缺陷只能归到组件，不能归到某一条索引条目" src("X04"))

  for (ix = 1; ix <= nid; ix++) {
    id = order[ix]
    if (!(id in kdSeen)) continue
    kd = kdOf[id]
    if (kdCnt[id] > 1) emit("D06", id, "同一对象登记了 " kdCnt[id] " 个对象类：一条索引内容只有一个发起通道，差集无法定位" src("D06"))
    if (capKdN > 0 && !(kd in capKdSet)) emit("D04", id, "清单里的对象类 " kd " 在能力表一行都没有：这一类的判据未建模，缺哪一格无从判定" src("D04"))

    dec  = famRec[id,"declared"] + 0
    chan = famRec[id,"channel"] + 0
    obsv = famRec[id,"observed"] + 0
    if (dec > 0 && chan == 0 && obsv == 0)
      emit("T01", id, "三件只登记了声明件（" dec " 格已读数），通道件与观测件一条已读数都没有：调用过索引写入不等于任何一面读得回来" src("T01"))
    if ((obsv > 0 || chan > 0) && dec == 0)
      emit("T02", id, "通道件与观测件共有 " chan+obsv " 格已读数但声明件一格都没有：条目内容必须先在索引写入面登记标识与属性集，未登记时的读数落在对象之外" src("T02"))

    elig = GV(id,"eligibility_decl"); er = GR(id,"eligibility_decl")
    qres = GV(id,"query_result");  qr = GR(id,"query_result")
    dd   = GV(id,"delete_verified"); dr = GR(id,"delete_verified")
    iu   = GV(id,"item_uid");  irf = GR(id,"item_uid")
    dm   = GV(id,"domain_id"); dmr = GR(id,"domain_id")
    un   = GV(id,"usage_notice"); ur = GR(id,"usage_notice")
    np   = GV(id,"notice_page");  nr = GR(id,"notice_page")
    if (elig=="recorded" && er=="none" && qres=="recorded" && qr=="hit")
      emit("T04", id, "资格格登记为未授予检索资格，观测件却把查询命中记为真：未授予资格的内容不该被查询面读回" src("T04"))
    if (dd=="recorded" && dr=="verified" && (ck(id,"query_result") in statOf) && (qr=="no_hit" || qres=="absent" || isNA(qr)))
      emit("T05", id, "删除格登记为已验证，但查询回读格为 " (qres=="absent"?"明确不存在":(isNA(qr)?"未登记":qr)) "：删除按标识符、域标识或全量执行，公开口径未承诺即时生效，验证必须落在再一次查询上" src("T05"))
    if (dd=="recorded" && dr=="verified" && isNA(iu) && isNA(dmr))
      emit("T05", id, "删除格登记为已验证，但条目标识与域标识两格都没有读数：删除入口按标识定位，无标识时无法回指删的是哪一条" src("T05"))
    if (un=="recorded" && (np=="absent" || np=="not_recorded" || isNA(nr)))
      emit("T06", id, "告知格登记为已读数但观测件的通知页面为 " np "：法律页写了关闭即删除本设备转录，没有能读回它的面时这一格落不了地" src("T06"))
    if (np=="recorded" && un=="absent")
      emit("T06", id, "观测件有通知页面读数但声明件把告知格记为不存在：两处指向同一份法律页，不能一处有一处无" src("T06"))

    for (kk in capOf) {
      split(kk, sp, SUBSEP); c2 = sp[1]; it = sp[2]; av = capOf[kk]
      if (c2 != kd) continue
      k = ck(id, it)
      if (!(k in statOf)) {
        if (av == "required") { holesReq[id]++; emit("D05", id, "对象类 " kd " 的 required 核对项 " it " 在本对象完全没有登记行" src("D05")) }
        continue
      }
      st = statOf[k]; pl = planeOf[k]; vw = vwOf[k]; rf = refOf[k]; ow = outOf[k]
      fam = ITFAM[it]
      if (av == "required") {
        if (st == "absent") emit("D01", id, "对象类 " kd " 需要 " it "，台账却明确记为不存在" src("D01"))
        else if (isNA(st)) { holesReq[id]++; emit("D02", id, "对象类 " kd " 需要 " it "，台账记为 " st "：这一格没有读数" src("D02")) }
        else if (st == "not_applicable") { holesReq[id]++; emit("D03", id, "对象类 " kd " 的 required 核对项 " it " 被记为不适用：与能力表冲突" src("D03")) }
        if (st == "recorded") { reqTot[id]++; if (isNA(rf)) reqNoRef[id]++ }
      }
      if (av == "not_applicable" && st == "recorded") {
        holesReq[id]++
        emit("D03", id, "对象类 " kd " 的 " it " 在公开口径里不适用（例如 Spotlight 索引扩展不提供 macOS 侧功能、系统服务不拥有属性表），却登记了已读数" src("D03"))
      }
      if (st != "recorded") continue
      recTot[id]++

      # ---- 内容越界 ----
      if (isSecretish(rf) || isHexDump(rf))
        emit("K01", id, "核对项 " it " 的引用格形似密钥、凭据、索引库文件、设备绝对路径或整段载荷正文：只登记引用标识，不登记内容" src("K01"))
      else if (rf ~ /^(mdfind|mdls|mdimport|mdutil|mdopen|mds|mdworker|profiles|sysctl|route|arp|ifconfig|log|xcrun|defaults|find|ls|tcpdump|wdutil|system_profiler|siriscreencapture)$/)
        emit("K02", id, "核对项 " it " 的引用格登记了设备侧命令行入口名（" rf "）：本脚本与台账都不以任何命令行工具作为读数来源" src("K02"))
      # ---- 公开词形 ----
      if (tok(it) != "" && st == "recorded" && !isNA(rf) && rf != "none") {
        if (it=="type_identifier" || it=="item_uid" || it=="domain_id") {
          if (!isIdForm(rf) && !isDocRef(rf)) emit("M01", id, "核对项 " it " 的引用格不是标识符形态也不是文档行号形态：" rf src("M01"))
        } else if (it == "max_results") {
          if (!isCount(rf)) emit("M01", id, "结果上限格不是 1—4 位数字，也不是 unset 或 default：" rf src("M01"))
        } else if (hasTok(it, rf)) { /* 落在公开词形表内 */ }
        else if (rf in NEAR) emit("M02", id, "核对项 " it " 的引用值 " rf " 是公开词形的近义词：公开口径只给本脚本帮助里逐格列出的那几个词，自造开关词无法回指" src("M02"))
        else if (!(nrm(rf) in vocab) && !isCve(rf) && !isDocRef(rf))
          emit("M01", id, "核对项 " it " 的引用值 " rf " 不在这一格的公开词形表里" src("M01"))
      }
      # ---- 引用形态 ----
      if (!(rf=="none" || isNA(rf) || rf=="") && !isCve(rf) && !isDocRef(rf) && !(nrm(rf) in vocab) && !hasTok(it, rf) && pl != "advisory_component" && it != "type_identifier" && it != "item_uid" && it != "domain_id" && it != "max_results")
        emit("V02", id, "核对项 " it " 的引用格既不是公开词表值也不是文档行号形态：" rf src("V02"))

      # ---- 平面越界 ----
      if (pl == "none") emit("P04", id, "核对项 " it " 记为已读数但读数平面为无平面：这一格没有任何能读回它的面" src("P04"))
      else if (fam=="channel" && (pl=="mdm_declaration" || pl=="declarative_management" || pl=="configuration_profile"))
        emit("P01", id, "通道件核对项 " it " 记在管理面平面上：设备管理器无法用管理面配置删掉或读出某一条索引条目，公开限制键清单里也没有这一项" src("P01"))
      else if (fam=="declared" && (pl=="query_response" || pl=="advisory_component" || pl=="settings_ui" || pl=="mdm_declaration" || pl=="declarative_management" || pl=="configuration_profile"))
        emit("P02", id, "声明件核对项 " it " 记为 " pl " 读回：条目资格、类型标识与索引归属写在索引写入调用里，不由查询响应、公告面或设置面给出" src("P02"))
      else if ((it=="profile_key" || it=="restriction_key" || vw=="declarative_type" || vw=="restriction_key") && !isNA(rf) && rf!="none" && !(nrm(rf) in vocab) && vrows>0)
        emit("P03", id, "把 " rf " 这一格当作检索面读数面，但该键在公开管理面键清单里不存在" src("P03"))
      else if (!(ck(pl, fam) in PAIR) && !(ck(pl, it) in PAIR))
        emit("P05", id, "平面 " pl " 与核对项 " it "（属 " fam "）不匹配：这一格不该由这个面给出" src("P05"))

      # ---- 词表归属与件层 ----
      if (vw=="mixed" && ow=="yes") emit("V05", id, "核对项 " it " 对外表述为是却把两套词表混记在同一格：三套词表分属三层" src("V05"))
      if (!isNA(vw) && !(ck("VW:" vw, fam) in PAIR))
        emit("T03", id, "核对项 " it "（属 " fam "）把词表归属记成 " vw "：这一层词表描述不了这一件，公告组件名与管理面键名都落不到索引写入调用上" src("T03"))
      if (isNA(ow)) emit("V04", id, "核对项 " it " 已读数但未登记这一格是否会对外（不阻断）" src("V04"))

      # ---- 公开词表比对 ----
      if (pl=="advisory_component" || vw=="advisory_component" || vw=="advisory_cve" || vw=="restriction_key" || vw=="declarative_type") {
        if (isNA(rf) || rf=="none") emit("X06", id, "核对项 " it " 挂在公告面或管理面却没有词表标识：缺任一格就无法回指" src("X06"))
        else if (isCve(rf)) { if (vrows>0 && cveN>0 && !(rf in cves)) emit("X01", id, "引用的 CVE 号 " rf " 不在公开公告词表内" src("X01")) }
        else if (vw=="restriction_key" || vw=="declarative_type" || it=="profile_key" || it=="restriction_key") { if (vrows>0 && keyN>0 && !(nrm(rf) in vocab)) emit("X05", id, "引用的限制键或声明式类型 " rf " 不在公开清单内" src("X05")) }
        else { if (vrows>0 && compN>0 && !(nrm(rf) in vocab)) emit("X02", id, "引用的组件名 " rf " 归一化后不在公告组件词表内" src("X02")) }
      }
    }
  }

  for (ix = 1; ix <= nid; ix++) {
    id = order[ix]
    if (!(id in kdSeen)) continue
    if (reqTot[id] > 0 && reqTot[id] == reqNoRef[id])
      emit("V01", id, "本对象 " reqTot[id] " 项 required 核对项的引用格全为无标识：结论无法回指任何一格" src("V01"))
    hard = 0
    for (j = 1; j <= nline; j++) { split(lines[j], sp, "\t"); if (sp[2] == id && (sp[1] in HB)) hard++ }
    if (!(kdOf[id] in capKdSet) || capKdN == 0 || subjBad[id] == 1) grade = "Q4"
    else if (hard >= 1) grade = "Q2"
    else if (holesReq[id] > 0 || reqNoRef[id] > 0 || recTot[id] == 0) grade = "Q3"
    else grade = "Q1"
    if (grade == "Q4") emit("Q4", id, "连可得性都不能定：该对象类在能力表里没有任何一行，或本对象没有一行能通过形态校验")
    if (grade == "Q3") emit("Q3", id, "只能定「这一类对象应当有哪几格」，不能定「这一格由谁读回」：存在覆盖空洞、无引用或整段缺读数")
    if (grade == "Q2") emit("Q2", id, "存在阻断信号：三件差集、平面可得性或公开词表至少一段互相矛盾，不能作为对外可得性表述")
    if (grade == "Q1") emit("Q1", id, "三件差集、平面可得性与公开词表三段齐备且无阻断：可用于对外表述这个对象缺哪一格")
    qcount[grade]++
  }

  for (kk in statOf) {
    split(kk, sp, SUBSEP); id = sp[1]; it = sp[2]; kd = kdOf[id]; st = statOf[kk]
    key2 = ck(kd, it)
    if (st == "recorded") recByKind[key2] = 1
    if (st == "absent") absByKind[key2] = 1
  }
  for (key2 in recByKind) if (key2 in absByKind) {
    split(key2, sp, SUBSEP)
    emit("V03", "-", "对象类 " sp[1] " 的核对项 " sp[2] " 在对象之间既有已读数又有明确不存在（不阻断）：登记口径未统一" src("V03"))
  }

  if (!QUIET) {
    print "---- 三件覆盖矩阵（声明件 / 通道件 / 观测件 已读数格数）----"
    for (ix = 1; ix <= nid; ix++) {
      id = order[ix]; kd = kdOf[id]
      reqs = 0; hits = 0; hlist = ""
      for (kk in capOf) {
        split(kk, sp, SUBSEP); if (sp[1] != kd || capOf[kk] != "required") continue
        reqs++
        k = ck(id, sp[2])
        if ((k in statOf) && statOf[k] == "recorded") hits++
        else hlist = hlist " " sp[2]
      }
      printf "%s\t%s\t声明件=%d 通道件=%d 观测件=%d\trequired=%d 已读数=%d 缺:%s\n", id, (kd==""?"-":kd), famRec[id,"declared"]+0, famRec[id,"channel"]+0, famRec[id,"observed"]+0, reqs, hits, (hlist==""?"（无）":hlist)
    }
    printf "---- 公开词表读数 ----\n"
    printf "去重词条=%d CVE 词条=%d 组件词条=%d 检索面具名组件=%d 条目级组件名=%d 键类词条=%d 挂在公告平面的已读数=%d\n", vrows, cveN, compN, faceN, entryN, keyN, advRecCount()
    if (entryN > 0) printf "条目级组件名读数：%s\n", entryList
  }

  for (j = 1; j <= nline; j++) { split(lines[j], sp, "\t"); if (sp[1] !~ /^Q[1234]$/) print lines[j] > "/dev/stderr" }
  if (!QUIET) for (j = 1; j <= nline; j++) { split(lines[j], sp, "\t"); if (sp[1] ~ /^Q[1234]$/) print lines[j] }
  nblk = 0; nc = 0; nsig = 0
  for (j = 1; j <= nline; j++) { split(lines[j], sp, "\t"); if (sp[1] !~ /^Q[1234]$/) nsig++ }
  for (c in cnt) { if (c !~ /^Q[1234]$/) nc++; if (c in HB) nblk += cnt[c] }
  printf "\n三件对象数=%d 核对项登记行=%d 能力表行=%d 词表词条=%d 信号行数=%d\n", nid, itemRows, capRows, vrows, nsig
  printf "不同信号码=%d 阻断信号条数=%d\n", nc, nblk
  printf "闭合等级 Q1=%d Q2=%d Q3=%d Q4=%d\n", qcount["Q1"], qcount["Q2"], qcount["Q3"], qcount["Q4"]
  shown = ""
  for (j = 1; j <= nline; j++) { split(lines[j], sp, "\t"); if (sp[1] ~ /^Q[1234]$/) continue; if (!(sp[1] in shn)) { shn[sp[1]] = 1; shown = shown sprintf("  %s=%d\n", sp[1], cnt[sp[1]]) } }
  printf "%s", shown
  exit (nblk > 0 ? 1 : 0)
}
' "$1" "$2" "$3"
```

---



---

## 23. 三十八次实跑与全量信号覆盖验收

第 21、22 章交出两支脚本本身。这一章只回答一个问题：**脚本里写过的每一条信号，是否真的在某一次真实运行里被打印过。**本文沿用一条硬规则——**不能触发的信号等于没有写过**。一条只存在于源码字符串里的信号，和一条作者设想出来、却没有任何输入形态能让它出现的信号，在读者这边没有任何区别：两者都会让「这份检索面台账合不合格」退化成一句不可复核的口头承诺。

R 编号在本篇是一条连续序号。`FX/run-log.txt`（862 行）里的 19 段是 **R1—R19**，全部跑脚本一；`FX/run-log-2.txt`（2,342 行）里的 19 段是 **R20—R38**，全部跑脚本二，**合计 38 次实跑**。分段头只有一行 `===== RUN: <夹具标签>`，R 号按段落先后数出来，因此段数是可复核的：`grep -c '^===== RUN:'` 在两份日志里分别给出 19 与 19。两份 harness 的形状相同：`FX/run-all.sh`（142 行）与 `FX/run-all-2.sh`（109 行）的第 9—10 行分别把 `S` 与 `LOG` 绑定到各自的脚本与日志，第 13—24 行的 `run()` 把 stdout 与 stderr 合并追加进日志、运行结束后补打一行 `$ exit=N`，末段的 `rm -f`（第 140 行与第 107 行）删除运行中现场生成的临时夹具，最后一行（第 142 行与第 109 行）打印日志行数。harness 自身也不联网：23.1 节 P7 那条 grep 给出实证。

### 23.1 四条验收标准

1. **逐码可达**：脚本一声明的 67 个码（63 个信号码 + 4 个判定档 `J1`—`J4`）与脚本二声明的 51 个码（47 个信号码 + 4 个闭合等级 `Q1`—`Q4`），每一个都必须在至少一次真实运行里被打印过。不接受「读代码看出来会触发」作为替代；不接受「这一条显然能触发」的口头推理。23.4、23.5 两张表逐码给出首次触发那次运行的 R 号，23.6 再从静态定义集反向对齐。
2. **逐次留痕**：每次运行在日志里留下一个完整块——命令行、逐条信号原文、脚本自己打印的汇总行，以及 shell 退出码。23.2、23.3 两张表里的每个数字都是从这两份日志直接取出的，不是事后整理的；第 21.6、22.6 节引用的每一段读数都注明自己取自日志的哪一行的连续区间，可以逐字比对。
3. **好夹具给下界**：一份十一格齐备、逐格有文档引用的台账（`FX/fixture-query-good.txt`）与一份三段齐备的三件登记（`FX/inventory-17-good.txt`）必须分别得到**零信号 + 最高档**——R2 是 `J1=3`、0 条信号、退出码 0；R21 是 `Q1=8`、0 条信号、退出码 0。没有这条，「阻断」就没有参照：读者无法判断脚本是在按判据拦，还是对任何输入都报错。
4. **只读约束的实证**：这一条不接受声明，只接受可复算的检查。`FX/readonly-proof.sh`（43 行）本身就是本文产物之一，它只做三件事——grep 两支脚本的源码、各跑一次合格夹具、检查临时目录是否残留；它的完整输出 `FX/readonly-proof.txt`（61 行）逐字嵌在下面。

```bash
#!/usr/bin/env bash
# readonly-proof.sh —— 第 17 篇「只读约束」的实证脚本
# 只做三件事：grep 两支核验脚本的源码、各跑一次合格夹具、检查临时目录是否残留。
# 本脚本不联网、不访问设备、不修改任何输入文件。输出写 stdout，供文档逐字引用。
# 约定：show 的参数是一个用单引号包住的完整命令行，先原样打印再交给 bash -c 执行。
set -u
LC_ALL=C; export LC_ALL
cd "$(dirname "$0")/.." || exit 1

S1=tools/query-plane-ledger-review.sh
S2=tools/query-plane-tripartite-diff.sh

show() {
  printf '$ %s\n' "$*"
  bash -c "$*" 2>&1
  printf '$ exit=%s\n\n' "$?"
}

echo "=== P1 awk 程序体内没有任何系统调用型函数 ==="
show 'grep -nE "system[(]|getline *[<]|popen[(]|close[(]|cmd |exec " tools/query-plane-ledger-review.sh tools/query-plane-tripartite-diff.sh'

echo "=== P2 外壳里唯一被执行的命令替换：两处 mktemp，临时目录前缀互不相同 ==="
show 'grep -n "mktemp" tools/query-plane-ledger-review.sh tools/query-plane-tripartite-diff.sh'

echo "=== P3 TMPD 只在赋值与 trap 里出现，正文从不向它写入 ==="
show 'grep -n "TMPD" tools/query-plane-ledger-review.sh tools/query-plane-tripartite-diff.sh'

echo "=== P4 设备侧命令行工具名在两支脚本里的全部出现位置（只应出现在注释与拒收分支） ==="
show 'grep -nwE "mdfind|mdls|mdimport|mdutil|mdopen|mds|mdworker|profiles|sysctl|route|arp|ifconfig|xcrun|defaults|tcpdump|wdutil|system_profiler|siriscreencapture" tools/query-plane-ledger-review.sh tools/query-plane-tripartite-diff.sh'

echo "=== P5 两支脚本的语法检查 ==="
show 'bash -n tools/query-plane-ledger-review.sh && bash -n tools/query-plane-tripartite-diff.sh && echo "两支脚本 bash -n 均无输出，即通过"'

echo "=== P6 合格夹具各跑一次，随后检查临时目录残留 ==="
show 'bash tools/query-plane-ledger-review.sh FX/fixture-query-good.txt >/dev/null 2>&1'
show 'bash tools/query-plane-tripartite-diff.sh FX/inventory-17-good.txt FX/capability-17.csv FX/vocab-17.tsv >/dev/null 2>&1'
show 'ls -d "${TMPDIR:-/tmp}"/qpr.* "${TMPDIR:-/tmp}"/qpt.*'

echo "=== P7 harness 里不存在任何 URL 或设备节点路径 ==="
show 'grep -nE "https?://|/dev/[a-z]" FX/run-all.sh FX/run-all-2.sh'

echo "=== P8 三十八次实跑的命令行归一化后只剩「脚本 + 选项 + 夹具」这一种形状 ==="
show 'grep -h "^\$ " FX/run-log.txt FX/run-log-2.txt | grep -v "^\$ exit=" | sed "s#FX/[A-Za-z0-9._-]*#FX/<夹具>#g; s#tools/query-plane-[a-z-]*\.sh#tools/<脚本>#g" | sort | uniq -c | sort -rn'
```

```text
=== P1 awk 程序体内没有任何系统调用型函数 ===
$ grep -nE "system[(]|getline *[<]|popen[(]|close[(]|cmd |exec " tools/query-plane-ledger-review.sh tools/query-plane-tripartite-diff.sh
$ exit=1

=== P2 外壳里唯一被执行的命令替换：两处 mktemp，临时目录前缀互不相同 ===
$ grep -n "mktemp" tools/query-plane-ledger-review.sh tools/query-plane-tripartite-diff.sh
tools/query-plane-ledger-review.sh:9:# 不读取设备状态、不修改输入文件；唯一写出目标是 mktemp -d 创建的临时目录，退出时删除。
tools/query-plane-ledger-review.sh:32:本脚本不联网、不访问设备、不修改输入文件；临时件写在 mktemp -d 并在退出时删除。
tools/query-plane-ledger-review.sh:44:TMPD=$(mktemp -d "${TMPDIR:-/tmp}/qpr.XXXXXX") || { echo "无法创建临时目录" >&2; exit 2; }
tools/query-plane-tripartite-diff.sh:17:#       按公开口径这一格本应由哪个平面给出。唯一写出目标是 mktemp -d 创建的临时目录，退出时删除，
tools/query-plane-tripartite-diff.sh:90:TMPD=$(mktemp -d "${TMPDIR:-/tmp}/qpt.XXXXXX") || { echo "无法创建临时目录" >&2; exit 2; }
$ exit=0

=== P3 TMPD 只在赋值与 trap 里出现，正文从不向它写入 ===
$ grep -n "TMPD" tools/query-plane-ledger-review.sh tools/query-plane-tripartite-diff.sh
tools/query-plane-ledger-review.sh:44:TMPD=$(mktemp -d "${TMPDIR:-/tmp}/qpr.XXXXXX") || { echo "无法创建临时目录" >&2; exit 2; }
tools/query-plane-ledger-review.sh:45:trap 'rm -rf "$TMPD"' EXIT INT TERM
tools/query-plane-tripartite-diff.sh:90:TMPD=$(mktemp -d "${TMPDIR:-/tmp}/qpt.XXXXXX") || { echo "无法创建临时目录" >&2; exit 2; }
tools/query-plane-tripartite-diff.sh:91:trap 'rm -rf "$TMPD"' EXIT INT TERM
$ exit=0

=== P4 设备侧命令行工具名在两支脚本里的全部出现位置（只应出现在注释与拒收分支） ===
$ grep -nwE "mdfind|mdls|mdimport|mdutil|mdopen|mds|mdworker|profiles|sysctl|route|arp|ifconfig|xcrun|defaults|tcpdump|wdutil|system_profiler|siriscreencapture" tools/query-plane-ledger-review.sh tools/query-plane-tripartite-diff.sh
tools/query-plane-ledger-review.sh:8:# 本脚本不联网、不调用 mdfind/spotlight/profiles/sysctl/log/defaults/xcrun 等任何命令行工具、
tools/query-plane-tripartite-diff.sh:14:# 边界：本脚本不联网取公告、不调用 mdfind/mdls/mdimport/mdutil/profiles/sysctl/xcrun/defaults/log/
tools/query-plane-tripartite-diff.sh:397:      else if (rf ~ /^(mdfind|mdls|mdimport|mdutil|mdopen|mds|mdworker|profiles|sysctl|route|arp|ifconfig|log|xcrun|defaults|find|ls|tcpdump|wdutil|system_profiler|siriscreencapture)$/)
$ exit=0

=== P5 两支脚本的语法检查 ===
$ bash -n tools/query-plane-ledger-review.sh && bash -n tools/query-plane-tripartite-diff.sh && echo "两支脚本 bash -n 均无输出，即通过"
两支脚本 bash -n 均无输出，即通过
$ exit=0

=== P6 合格夹具各跑一次，随后检查临时目录残留 ===
$ bash tools/query-plane-ledger-review.sh FX/fixture-query-good.txt >/dev/null 2>&1
$ exit=0

$ bash tools/query-plane-tripartite-diff.sh FX/inventory-17-good.txt FX/capability-17.csv FX/vocab-17.tsv >/dev/null 2>&1
$ exit=0

$ ls -d "${TMPDIR:-/tmp}"/qpr.* "${TMPDIR:-/tmp}"/qpt.*
ls: cannot access '/tmp/qpr.*': No such file or directory
ls: cannot access '/tmp/qpt.*': No such file or directory
$ exit=2

=== P7 harness 里不存在任何 URL 或设备节点路径 ===
$ grep -nE "https?://|/dev/[a-z]" FX/run-all.sh FX/run-all-2.sh
$ exit=1

=== P8 三十八次实跑的命令行归一化后只剩「脚本 + 选项 + 夹具」这一种形状 ===
$ grep -h "^\$ " FX/run-log.txt FX/run-log-2.txt | grep -v "^\$ exit=" | sed "s#FX/[A-Za-z0-9._-]*#FX/<夹具>#g; s#tools/query-plane-[a-z-]*\.sh#tools/<脚本>#g" | sort | uniq -c | sort -rn
     16 $ tools/<脚本> FX/<夹具>
     13 $ tools/<脚本> FX/<夹具> FX/<夹具> FX/<夹具>
      2 $ tools/<脚本> FX/<夹具> FX/<夹具>
      2 $ tools/<脚本> -h
      2 $ tools/<脚本> 
      1 $ tools/<脚本> FX/<夹具> FX/<夹具> FX/<夹具> FX/<夹具>
      1 $ tools/<脚本> -q FX/<夹具> FX/<夹具> FX/<夹具>
      1 $ tools/<脚本> -q FX/<夹具>
$ exit=0

```

八段检查各自的结论如下，其中 P1 与 P7 的「零命中」是用 grep 自己的退出码 1 表达的，不是本文的口头断言：

| 检查 | 结论 | 关键证据 |
| --- | --- | --- |
| P1 | awk 程序体内没有任何系统调用型入口 | `system(`、`getline <`、`popen(`、`close(`、`cmd `、`exec ` 六个模式跨两支脚本共 944 行**零命中**（grep 退出码 1）。awk 只能读 `ARGV` 里传入的文件，也就只能读命令行给的那几份夹具 |
| P2 | 外壳里唯一被执行的命令替换是 `mktemp` | `mktemp` 共 5 处，其中 3 处在注释（脚本一第 9、32 行，脚本二第 17 行），只有脚本一第 44 行与脚本二第 90 行是可执行语句；两处临时目录前缀分别是 `qpr.XXXXXX` 与 `qpt.XXXXXX`，互不相同 |
| P3 | 声明的写出目标从不被写入 | `TMPD` 在两支脚本里各只出现 2 次：一次赋值、一次 `trap 'rm -rf "$TMPD"' EXIT INT TERM`（第 45 行与第 91 行）。正文没有任何一处向 `$TMPD` 写东西，所以脚本二第 17—18 行「本实现不向其写入任何字节」是可核对的事实而不是姿态 |
| P4 | 设备侧命令名只作为**被拒绝的值**出现 | 检查模式列 18 个命令名（脚本二第 397 行的拒收正则实际列 21 个，多出的 `log`／`find`／`ls` 不放进这次搜索，否则会与两份脚本正文里的「日志」词形和 shell 词形大量相撞），共 3 处命中：脚本一第 8 行、脚本二第 14—15 行是「不调用」声明；脚本二第 397 行是判定分支里的正则，它拦的是「把命令名当来源登记」这个动作，本身不执行任何命令 |
| P5 | 两支脚本语法检查通过 | `bash -n` 两次都无输出，随后那句「均无输出，即通过」才被打印 |
| P6 | 运行不残留临时目录 | 两次合格夹具都退出码 0，紧接着 `ls -d "${TMPDIR:-/tmp}"/qpr.* …/qpt.*` 报 `No such file or directory`、退出码 2。这里的 2 是 `ls` 自己的码，恰好是期望结果：目录已被 `trap` 删除 |
| P7 | harness 里没有外部依赖入口 | `https?://`、`/dev/[a-z]` 两个模式在 `FX/run-all.sh` 与 `FX/run-all-2.sh` 里零命中（退出码 1） |
| P8 | 命令行形状收敛 | 38 条命令行归一化后只有 8 种，按次数排开是 16+13+2+2+2+1+1+1 = **38**，逐项对得上 23.2 的两张表。全部形状都是「脚本 + 可选 `-q`／`-h` + 零到四份 `FX/<夹具>`」，没有任何一种形状带网络地址、设备参数或写目标 |

**这里要说清一处不对称。**P1 检查的是「有没有能读别的地方的口子」，检查不到「读到的内容是不是设备事实」。两支脚本读的是登记件，登记件由人填写；本文能保证的是**判定过程可离线复算**，不能保证**登记内容与某台真实设备一致**。这一条限制写进第 26 章边界清单的 N12，也在 23.8 里作为「这次验收不证明什么」的第一条重述。

### 23.2 三十八次实跑的清单与退出码

脚本一 `tools/query-plane-ledger-review.sh`，19 次，R1—R19。下表「命令行要点」按日志里的原始命令行去掉 `tools/query-plane-ledger-review.sh` 前缀书写：

| 次 | 标签 | 命令行要点 | 退出码 |
| --- | --- | --- | --- |
| R1 | `codes` | `FX/fixture-query-codes.txt` | 1 |
| R2 | `good` | `FX/fixture-query-good.txt` | 0 |
| R3 | `mixed` | `FX/fixture-query.txt` | 1 |
| R4 | `multi` | `FX/fixture-query-good.txt FX/fixture-query.txt`（一次传两份） | 1 |
| R5 | `quiet` | `-q FX/fixture-query.txt` | 1 |
| R6 | `help` | `-h` | 0 |
| R7 | `noargs` | 不带任何参数 | 2 |
| R8 | `missing` | `FX/does-not-exist.txt` | 2 |
| R9 | `empty` | `FX/tmp-empty.txt`（零字节） | 0 |
| R10 | `comments` | `FX/tmp-comments.txt`（只有注释与空行） | 0 |
| R11 | `malformed` | `FX/tmp-malformed.txt`（缺列／多列／空标识／CRLF／非法枚举） | 1 |
| R12 | `unknown-field` | `FX/tmp-unknown.txt`（命名空间已知、字段名未登记） | 1 |
| R13 | `shape` | `FX/tmp-shape.txt`（枚举／布尔／日期／数值形态越界） | 1 |
| R14 | `duplicate` | `FX/tmp-dup.txt`（同字段重复登记且值一致／同字段两值） | 1 |
| R15 | `secret-shapes` | `FX/tmp-secret.txt`（形似检索词、转录、私钥、base64、设备路径的取值） | 1 |
| R16 | `command-legal` | `FX/tmp-command-legal.txt`（`obs.command_name=none`） | 1 |
| R17 | `command-blocking` | `FX/tmp-command-blocking.txt`（同一格填 `mdfind`） | 1 |
| R18 | `readback-legal` | `FX/tmp-readback-legal.txt`（回读接口记 `settings_ui`） | 1 |
| R19 | `readback-blocking` | `FX/tmp-readback-blocking.txt`（回读接口记 `full_listing`） | 1 |

R9—R19 这十一份夹具由 harness 在第 50—138 行现场写入、随即运行、并在第 140 行随其余临时件一起删除，所以 `.srcx17/FX/` 下留档的不是这些夹具而是它们的输出本身（23.3 逐段引用）。R16—R19 是两组**正反用例对**：同一格式只差被检查的那一格，用来证明 `K02`（命令行入口）与 `B04`（条目级整面回读）是「按判据拦」而不是「按文件名拦」。

脚本二 `tools/query-plane-tripartite-diff.sh`，19 次，R20—R38。三份输入**按固定顺序**给出（清单、能力表、词表），下表同样去掉脚本名前缀：

| 次 | 标签 | 命令行要点 | 退出码 |
| --- | --- | --- | --- |
| R20 | `codes` | `FX/inventory-17-codes.txt FX/capability-17-bad.csv FX/vocab-17-bad.tsv` | 1 |
| R21 | `good` | `FX/inventory-17-good.txt FX/capability-17.csv FX/vocab-17.tsv` | 0 |
| R22 | `mixed` | `FX/inventory-17.txt FX/capability-17.csv FX/vocab-17.tsv` | 1 |
| R23 | `codes-valid-tables` | `FX/inventory-17-codes.txt FX/capability-17.csv FX/vocab-17.tsv` | 1 |
| R24 | `quiet` | `-q FX/inventory-17.txt FX/capability-17.csv FX/vocab-17.tsv` | 1 |
| R25 | `help` | `-h` | 0 |
| R26 | `noargs` | 不带任何参数 | 2 |
| R27 | `one-arg` | 只给清单 | 2 |
| R28 | `two-args` | 给清单与能力表 | 2 |
| R29 | `four-args` | 第四份重复给词表 | 2 |
| R30 | `missing` | 第三份换成 `FX/does-not-exist.tsv` | 2 |
| R31 | `cap-empty` | `FX/inventory-17-good.txt FX/capability-empty.csv FX/vocab-17.tsv` | 1 |
| R32 | `vocab-empty` | `FX/inventory-17-good.txt FX/capability-17.csv FX/vocab-empty.tsv` | 1 |
| R33 | `inv-empty` | `FX/tmp-empty.txt FX/capability-17.csv FX/vocab-17.tsv` | 0 |
| R34 | `comments` | `FX/tmp-comments.txt FX/capability-17.csv FX/vocab-17.tsv` | 0 |
| R35 | `malformed` | `FX/tmp-malformed.txt FX/capability-17.csv FX/vocab-17.tsv` | 1 |
| R36 | `cap-shapes` | `FX/inventory-17.txt FX/tmp-cap.txt FX/vocab-17.tsv` | 1 |
| R37 | `vocab-shapes` | `FX/inventory-17.txt FX/capability-17.csv FX/tmp-voc.txt` | 1 |
| R38 | `optout-gate` | `FX/inventory-17-optout.txt FX/capability-17.csv FX/vocab-17.tsv` | 1 |

脚本二这边有三处形状是脚本一没有的。**R27—R29 是参数个数的三段扫描**（1、2、4 份），加上 R26 的 0 份，把第 84—88 行「必须恰好三份且都可读」这条约束的四个边界各测一次——脚本一只要求「至少一份」，所以它没有这一段。**R20 与 R23 是同一份清单配两套表**：R20 用畸形能力表与畸形词表，R23 用干净的两份；这一对是 23.7 那段算术的输入。**R24** 是 `-q`。R33—R35 与 R36—R37 分别把「空清单」「只有注释」「清单自身畸形」与「能力表畸形」「词表畸形」分开测，避免把「表的问题」记成「清单的问题」。

38 条命令行的退出码序列是：R1—R19 为 `1 0 1 1 1 0 2 2 0 0 1 1 1 1 1 1 1 1 1`，R20—R38 为 `1 0 1 1 1 0 2 2 2 2 2 1 1 0 0 1 1 1 1`。合并计数是 **0 出现 8 次、2 出现 7 次、1 出现 23 次**（两段各自是 13 与 19 项，相加 38；把两段序列抄进一个文件再 `tr -d ' ' | fold -1 | sort | uniq -c` 可独立复现这三个数）。8 次 0 里，R2／R21 是好夹具（判据意义上的下界），R6／R25 是帮助，R9／R10／R33／R34 是空输入与只有注释的输入；7 次 2 全部落在「输入不可用」这一类（R7／R8 与 R26—R30），与「内容有阻断」在退出码上严格分开——这正是第 25 章第 11 问要给出的那条门禁依据。


### 23.3 每次运行的读数

下面两张表的每一个数字都取自日志里脚本自己打印的汇总行，「日志行段」给出该段在日志中的起止行，读者可以用 `sed -n '起,止p'` 逐字比对。两张表都按 R 号顺序排。

**脚本一（`FX/run-log.txt`，862 行）**

| 次 | 标签 | 对象 | 信号行 | 不同码 | 阻断 | 判定分布 | 退出码 | 日志行段 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| R1 | `codes` | 69 | 344 | 52 | 344 | J3=3 J4=66 | 1 | 1—472 |
| R2 | `good` | 3 | 0 | 0 | 0 | J1=3 | 0 | 474—483 |
| R3 | `mixed` | 6 | 16 | 12 | 16 | J1=1 J2=1 J3=1 J4=3 | 1 | 485—525 |
| R4 | `multi` | 9 | 16 | 12 | 16 | J1=4 J2=1 J3=1 J4=3 | 1 | 527—570 |
| R5 | `quiet` | 6 | 16 | 12 | 16 | stdout 无 J 行 | 1 | 572—606 |
| R6 | `help` | — | — | — | — | — | 0 | 608—628 |
| R7 | `noargs` | — | — | — | — | — | 2 | 630—650 |
| R8 | `missing` | — | — | — | — | — | 2 | 652—655 |
| R9 | `empty` | 0 | 0 | 0 | 0 | 四档全 0 | 0 | 657—663 |
| R10 | `comments` | 0 | 0 | 0 | 0 | 四档全 0 | 0 | 665—671 |
| R11 | `malformed` | 1 | 9 | 7 | 9 | J4=1 | 1 | 673—696 |
| R12 | `unknown-field` | 1 | 7 | 5 | 7 | J4=1 | 1 | 698—717 |
| R13 | `shape` | 1 | 15 | 10 | 15 | J4=1 | 1 | 719—751 |
| R14 | `duplicate` | 1 | 5 | 5 | 5 | J4=1 | 1 | 753—770 |
| R15 | `secret-shapes` | 1 | 10 | 6 | 10 | J4=1 | 1 | 772—795 |
| R16 | `command-legal` | 1 | 3 | 3 | 3 | J4=1 | 1 | 797—810 |
| R17 | `command-blocking` | 1 | 4 | 4 | 4 | J4=1 | 1 | 812—827 |
| R18 | `readback-legal` | 1 | 3 | 3 | 3 | J4=1 | 1 | 829—842 |
| R19 | `readback-blocking` | 1 | 5 | 5 | 5 | J4=1 | 1 | 844—861 |

R6／R7／R8 三段落在参数与文件检查分支上（第 41—42 行），脚本在读取输入之前就退出，所以没有汇总行，表里记 `—` 而不是 0——把「没跑起来」记成「跑起来且读数为零」是台账里最常见的一类错，这张表先把自己管住。剩下 16 段里，**「信号行」与「阻断」两列逐段相等**：344／0／16／16／16／0／0／9／7／15／5／10／3／4／3／5，16 对数字全部相同。这个恒等式不是巧合，而是第 19.1 节那条设计的直接后果——脚本一的第 113—114 行把全部 63 个信号码都写进 `HB`，没有非阻断档，所以「信号行数」与「阻断信号条数」必然相等。反过来用也成立：一旦某天这两列出现不等，说明有人往脚本一里加了非阻断码而没同步第 19.1 节的表述。

16 段的「信号行」相加是 **453**，与「阻断」列相加同值。「对象」列相加是 102（69+3+6+9+6+9 段各 1），即十一次单对象运行与 R1—R5 的对象数之和；而 `grep -cP '^J[1234]\t' FX/run-log.txt` 只给 **96**。差的 6 行全部来自 R5：那一段用 `-q` 运行，汇总行照打 `判定行数=6`，stdout 上一行 J 都没打。这是 `-q` 是纯输出开关的第一处算术证据，第二处在下面的逐字段对照里。

**R3 与 R5 是同一份输入的两个开关状态**（`FX/fixture-query.txt`，一次不带 `-q`、一次带），逐字段对照如下：

| 字段 | R3（无 `-q`） | R5（`-q`） | 是否相同 |
| --- | --- | --- | --- |
| 对象数 | 6 | 6 | 相同 |
| 信号行数 | 16 | 16 | 相同 |
| 不同信号码 | 12 | 12 | 相同 |
| 阻断信号条数 | 16 | 16 | 相同 |
| 判定分布 | J1=1 J2=1 J3=1 J4=3 | J1=1 J2=1 J3=1 J4=3 | 相同 |
| 逐码计数表 | 12 项，逐项相加 16 | 12 项，逐项相同 | 相同 |
| stderr 逐条信号 | 16 条 | 16 条 | 相同 |
| stdout 的 J 行 | 6 行 | 0 行 | **唯一差异** |
| 退出码 | 1 | 1 | 相同 |

也就是说 `-q` 只删掉 stdout 上那六行判定档输出，**连汇总行里那句「判定分布」都照样给出**。第 21.4 节据此把 `-q` 的行为写成「去掉 stdout 判定档，stderr 信号、汇总行与逐码计数表全部保留」。这条区别在运营上有实际意义：把脚本挂进流水线时，如果下游靠解析 stdout 的 J 行取结论，就不能加 `-q`；如果只取退出码与汇总行，加 `-q` 可以让日志短三成。

**脚本二（`FX/run-log-2.txt`，2,342 行）**

| 次 | 标签 | 对象 | 登记行 | 能力表 | 词表 | 挂公告面 | 信号行 | 不同码 | 阻断 | 闭合等级 | 退出码 | 日志行段 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| R20 | `codes` | 42 | 57 | 168 | 720 | 4 | 673 | 46 | 95 | Q2=37 Q3=2 Q4=2 | 1 | 1—812 |
| R21 | `good` | 8 | 77 | 168 | 720 | 0 | 0 | 0 | 0 | Q1=8 | 0 | 814—839 |
| R22 | `mixed` | 10 | 81 | 168 | 720 | 1 | 7 | 5 | 3 | Q1=4 Q2=1 Q3=3 Q4=2 | 1 | 841—882 |
| R23 | `codes-valid-tables` | 42 | 57 | 168 | 720 | 4 | 664 | 40 | 89 | Q2=37 Q3=2 Q4=2 | 1 | 884—1681 |
| R24 | `quiet` | 10 | 81 | 168 | 720 | — | 7 | 5 | 3 | stdout 无矩阵无 Q 行 | 1 | 1682—1700 |
| R25 | `help` | — | — | — | — | — | — | — | — | — | 0 | 1702—1760 |
| R26 | `noargs` | — | — | — | — | — | — | — | — | — | 2 | 1761—1819 |
| R27 | `one-arg` | — | — | — | — | — | — | — | — | — | 2 | 1820—1878 |
| R28 | `two-args` | — | — | — | — | — | — | — | — | — | 2 | 1879—1937 |
| R29 | `four-args` | — | — | — | — | — | — | — | — | — | 2 | 1938—1996 |
| R30 | `missing` | — | — | — | — | — | — | — | — | — | 2 | 1997—2001 |
| R31 | `cap-empty` | 8 | 77 | **0** | 720 | 0 | 1 | 1 | 1 | Q4=8 | 1 | 2002—2030 |
| R32 | `vocab-empty` | 8 | 77 | 168 | **0** | 0 | 19 | 3 | 18 | Q1=3 Q2=5 | 1 | 2031—2079 |
| R33 | `inv-empty` | 0 | 0 | 168 | 720 | 0 | 0 | 0 | 0 | 四档全 0 | 0 | 2080—2090 |
| R34 | `comments` | 0 | 0 | 168 | 720 | 0 | 0 | 0 | 0 | 四档全 0 | 0 | 2091—2101 |
| R35 | `malformed` | 4 | 4 | 168 | 720 | 0 | 76 | 8 | 16 | Q2=4 | 1 | 2102—2204 |
| R36 | `cap-shapes` | 10 | 81 | **1** | 720 | 1 | 17 | 8 | 15 | Q3=1 Q4=9 | 1 | 2205—2260 |
| R37 | `vocab-shapes` | 10 | 81 | 168 | **1** | 1 | 27 | 7 | 21 | Q1=1 Q2=5 Q3=2 Q4=2 | 1 | 2261—2325 |
| R38 | `optout-gate` | 2 | 32 | 168 | 720 | 0 | 1 | 1 | 1 | Q1=1 Q2=1 | 1 | 2326—2342 |

「能力表」「词表」两列加粗的三个数字（R31 的 0、R36 的 1、R37 的 1）是三段**表侧形状测试**的结果，它们与 R32 的「词表 0」一起构成第 22 章说的「换一份能力表就会改变 Q3 的触发面」的四组实证：同一份干净清单 `FX/inventory-17-good.txt` 在 R21 得 `Q1=8`、在 R31 得 `Q4=8`，两个结论之间只差能力表那一份输入。

「挂公告面」这一列就是 `X04` 的触发条件那一格（第 320—322 行统计、第 335 行判 `aRec > 0`）。全表只有 R20／R23／R22／R36／R37 五次非零，`X04` 的累计数正好是 5——23.5 的逐码表可以逐条对上。R24 那一格记 `—` 是因为 `-q` 把「公开词表读数」整行删掉了，不是脚本没算。

`grep -cP '^[A-Z]{1,2}[0-9]+\t' FX/run-log-2.txt` 给 **1634**，其中 Q 档 142 行（`grep -cP '^Q[1234]\t'`）、信号 1492 行。13 段有效运行的「信号行」逐项相加正是 1492（673+0+7+664+7+1+19+0+0+76+17+27+1），「阻断」列相加是 **262**。1492 − 262 = **1230** 条非阻断信号，八个非阻断码逐项贡献是 `D05`=1197、`V03`=8、`X03`=7、`X04`=5、`D02`=5、`D03`=4、`S08`=2、`V04`=2，相加 1230。与脚本一的恒等式对照，这就是两支脚本输出形状的全部区别所在（算术细节见 23.7 第（6）段）。

Q 档 142 行同样比「逐段对象数相加」少 10：13 段的对象数是 42+8+10+42+10+8+8+0+0+4+10+10+2 = 154，其中 R20／R23 各有 1 个对象只被计数不被判定（见 23.7 第（5）段），所以被判定的是 152；再减去 R24 因 `-q` 未打印的 10 行，得到 142。两处差一个不同的原因，都必须写出来，否则下一节改成 `-q` 少打一段矩阵时会误判。

**R22 与 R24 是 `-q` 的第二个对照**（同一份 `FX/inventory-17.txt` + 干净能力表与词表）：

| 字段 | R22（无 `-q`） | R24（`-q`） | 是否相同 |
| --- | --- | --- | --- |
| 对象数 / 登记行 / 能力表 / 词表 | 10 / 81 / 168 / 720 | 10 / 81 / 168 / 720 | 相同 |
| 信号行数 | 7 | 7 | 相同 |
| 不同信号码 | 5 | 5 | 相同 |
| 阻断信号条数 | 3 | 3 | 相同 |
| 闭合等级分布 | Q1=4 Q2=1 Q3=3 Q4=2 | Q1=4 Q2=1 Q3=3 Q4=2 | 相同 |
| 逐码计数表 | X04=1 D05=2 P01=1 D02=1 D04=2 | 同 | 相同 |
| stderr 逐条信号 | 7 条 | 7 条 | 相同 |
| stdout：三件覆盖矩阵 | 10 行 | 无 | **差异一** |
| stdout：公开词表读数行 | 1 行 | 无 | **差异二** |
| stdout：逐对象 Q 档 | 10 行 | 无 | **差异三** |
| 退出码 | 1 | 1 | 相同 |

第 22.4 节据此改写为：`-q` 删的是 stdout 的三段可读输出（矩阵、词表读数行、Q 档行），保留 stderr 信号与末尾汇总＋逐码计数表。脚本二比脚本一多删两段，因为它的 stdout 本来就有三段而脚本一只有一段。**两支脚本的 `-q` 都不改判定、不改退出码**，这一点由这两对对照共同证明，而不是由声明证明。

### 23.4 脚本一的逐码触发表（67 码）

下表由 `FX/codemap.pl`（32 行）扫 `FX/run-log.txt` 生成：按 `===== RUN:` 分段编号，取每行行首的信号码，记录**首次打印该码那一段的 R 号**与**跨 19 段的累计次数**。三列一组、九列一行只为压行数，读取顺序是先行后列。加粗的「首现」表示该码不在基线段 R1 出现。

| 码 | 首现 | 累计 | 码 | 首现 | 累计 | 码 | 首现 | 累计 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `A01` | R1 | 82 | `A02` | R1 | 1 | `A03` | R1 | 1 |
| `A04` | R1 | 4 | `A05` | R1 | 5 | `A06` | R1 | 1 |
| `A07` | R1 | 1 | `A08` | R1 | 4 | `B01` | R1 | 80 |
| `B02` | R1 | 3 | `B03` | R1 | 4 | `B04` | R1 | 4 |
| `B05` | R1 | 1 | `B06` | R1 | 1 | `B07` | R1 | 1 |
| `B08` | R1 | 2 | `C01` | R1 | 1 | `C02` | R1 | 1 |
| `C03` | R1 | 3 | `C04` | R1 | 1 | `C05` | R1 | 3 |
| `C06` | R1 | 1 | `C07` | R1 | 1 | `D01` | R1 | 4 |
| `D02` | R1 | 1 | `D03` | R1 | 1 | `D04` | R1 | 1 |
| `D05` | R1 | 1 | `G01` | R1 | 1 | `G02` | R1 | 2 |
| `G03` | R1 | 5 | `G04` | R1 | 1 | `G05` | R1 | 1 |
| `J1` | **R2** | 8 | `J2` | **R3** | 2 | `J3` | R1 | 5 |
| `J4` | R1 | 81 | `K01` | **R11** | 4 | `K02` | **R15** | 4 |
| `N01` | R1 | 22 | `N02` | R1 | 1 | `N03` | R1 | 1 |
| `O01` | R1 | 22 | `O02` | R1 | 1 | `O03` | R1 | 1 |
| `O04` | R1 | 1 | `O05` | R1 | 6 | `S01` | **R11** | 3 |
| `S02` | **R11** | 1 | `S03` | **R11** | 4 | `S04` | **R13** | 3 |
| `S05` | **R13** | 1 | `S06` | **R13** | 4 | `S07` | **R14** | 1 |
| `S08` | **R14** | 1 | `S09` | **R12** | 2 | `T01` | R1 | 20 |
| `T02` | R1 | 1 | `T03` | R1 | 29 | `T04` | R1 | 4 |
| `T05` | R1 | 1 | `V01` | R1 | 1 | `V02` | R1 | 6 |
| `V03` | R1 | 1 | `V04` | R1 | 3 | `V05` | R1 | 1 |
| `X01` | R1 | 79 |  |  |  |  |  |  |  |  |

四点读法：

**（1）13 个码不在 R1，全部可以解释。**`J1`（首现 R2）与 `J2`（首现 R3）是结构性例外：`J1` 的判据含「无阻断信号」，而 R1 的夹具 `FX/fixture-query-codes.txt` 是按「每个码至少有一个对象能让它出现」写的，69 个对象每一个都带阻断，所以 `J1` 在 R1 不可能出现，它只能由合格夹具给出；`J2` 要「有阻断但四格齐备」，codes 夹具里没有对象长成那样。剩下 11 个码（`K01`、`K02`、`S01`—`S09`）属于**行形态与内容拒收族**：它们在读写入阶段（第 186—250 行）判定，而 codes 夹具的行本身是干净的三列、合法命名空间、无 `sec.*`、无形似凭据取值——不是遗漏，而是「行形态畸形」与「语义缺格」无法共存于同一行：把某行写成两列，那一行就再也带不动 `A01`/`B01` 之类的缺格判定。所以这两族各由 R11—R15 五段专项夹具覆盖。

**（2）33 个码是「单点证明」。**累计数为 1 的码共 33 个：`A02 A03 A06 A07 B05 B06 B07 C01 C02 C04 C06 C07 D02 D03 D04 D05 G01 G04 G05 N02 N03 O02 O03 O04 S02 S05 S07 S08 T02 T05 V01 V03 V05`。它们全部只在 R1 打印过一次。这是本次覆盖验收的真实强度上限：**「可达」只被一次运行证明**。改动这些分支时只有 R1 那一段日志会变色，其余 18 段毫无反应，因此 `FX/run-all.sh` 必须整段重跑，不能只跑合格夹具。

**（3）高累计数是「缺格族」的放大。**`A01`=82、`J4`=81、`B01`=80、`X01`=79，四个数都远大于其余码。机制是 codes 夹具的一个对象通常同时缺多格，一个对象就打出 `A01`+`B01`+`X01` 三条，并且顺带把该对象按到 `J4`——这是同一判据在不同对象上的重复出现，不是同一信号被重复计。紧随其后的是 `T03`=29、`N01`=22、`O01`=22、`T01`=20，四者分别对应「台账过期阈值未登记」「告知依据缺失」「观测平面缺格」「核对时刻缺失」，都是缺格族的常态项。

**（4）四个判定档的分解。**`J1`=8 = R2 的 3 + R3 的 1 + R4 的 4；`J2`=2 = R3 的 1 + R4 的 1；`J3`=5 = R1 的 3 + R3 的 1 + R4 的 1；`J4`=81 = R1 的 66 + R3 的 3 + R4 的 3 + R11—R19 各 1。四个式子里都没有 R5——它用 `-q` 运行，汇总行的 J 分布照样是 `J1=1 J2=1 J3=1 J4=3`，但 stdout 一行 J 都没打，逐码累计因此为 0。这与 23.3 那张对照表是同一件事的两种数法：一种看字段，一种看行数。

累计总和 **549** 独立可核：`grep -cP '^[A-Z]{1,2}[0-9]+\t' FX/run-log.txt` 给 549，其中 J 档 96 行（8+2+5+81）、信号 453 行（23.3 的「信号行」列相加）。两侧数出同一个 549，说明这张表既没漏行也没重复计数。

### 23.5 脚本二的逐码触发表（51 码）

同一支 `codemap.pl` 扫 `FX/run-log-2.txt` 得到 `FX/map2.txt`（51 行），基线段是 R20。

| 码 | 首现 | 累计 | 码 | 首现 | 累计 | 码 | 首现 | 累计 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `C01` | R20 | 4 | `C02` | R20 | 2 | `C03` | R20 | 2 |
| `C04` | R20 | 2 | `C05` | R20 | 2 | `C06` | **R31** | 1 |
| `D01` | R20 | 8 | `D02` | R20 | 5 | `D03` | R20 | 4 |
| `D04` | R20 | 19 | `D05` | R20 | 1197 | `D06` | R20 | 2 |
| `K01` | R20 | 4 | `K02` | R20 | 3 | `M01` | R20 | 33 |
| `M02` | R20 | 2 | `P01` | R20 | 5 | `P02` | R20 | 4 |
| `P03` | R20 | 4 | `P04` | R20 | 2 | `P05` | R20 | 4 |
| `Q1` | **R21** | 17 | `Q2` | R20 | 90 | `Q3` | R20 | 10 |
| `Q4` | R20 | 25 | `S01` | R20 | 3 | `S02` | R20 | 4 |
| `S03` | R20 | 2 | `S04` | R20 | 2 | `S05` | R20 | 2 |
| `S06` | R20 | 2 | `S07` | R20 | 4 | `S08` | R20 | 2 |
| `S09` | R20 | 2 | `T01` | R20 | 42 | `T02` | R20 | 32 |
| `T03` | R20 | 6 | `T04` | R20 | 3 | `T05` | R20 | 2 |
| `T06` | R20 | 4 | `V01` | R20 | 2 | `V02` | R20 | 35 |
| `V03` | R20 | 8 | `V04` | R20 | 2 | `V05` | R20 | 2 |
| `X01` | R20 | 2 | `X02` | R20 | 2 | `X03` | R20 | 7 |
| `X04` | R20 | 5 | `X05` | R20 | 4 | `X06` | R20 | 2 |

四点读法：

**（1）只有两个码不在 R20。**`Q1`（首现 R21）与脚本一的 `J1` 同理：判据含「无阻断」，而 R20 的 codes 夹具里 42 个对象全带阻断，所以 `Q1` 不可能在基线段出现。`C06`（首现 R31，累计 1）判的是「能力表整表没有一条有效行」，这是聚合级判据：只要 `FX/capability-17.csv` 还有一行合法记录它就不成立，全 19 段里只有 R31 传入 `FX/capability-empty.csv`。R35 用畸形清单跑，能力表是干净的那份，所以没有第二次。

**（2）这张表只有一个单点码。**累计为 1 的只有 `C06`，其余 50 个码都 ≥2。与脚本一的 33 个单点码相比，差别来自夹具形状：脚本二的 codes 夹具是「三件登记 × 对象类」的笛卡尔结构，一条畸形登记会同时被 D 族、M 族、P 族、V 族多个判据看到；再叠加 R22／R24（同一对夹具跑两次）与 R20／R23（同一份清单配两套表）两组重复，绝大多数码天然拿到 ≥2 的样本。也就是说 **脚本二的覆盖强度不体现在码多，而体现在同一码有多条独立触发路径**；反过来，`C06` 这种「整表级」判据只有一条路径，它也是全表最脆的一个码——改动能力表解析分支时，只有 R31 一段日志会变色。

**（3）`D05`=1197 的分布。**`D05` 是「required 核对项在本对象完全没有登记行」的逐对象×逐核对项判据，一份几十行的登记件会打出几百条，所以它主导总数。跨段分布是 R20 565、R22 2、R23 565、R24 2、R35 60、R36 1、R37 2，**合计 1197**，`grep -c '^D05' FX/run-log-2.txt` 独立给出同一个数。三个数值得停一下：R36 只有 1 条，因为那一段能力表只剩 1 行，`D05` 的分母（required 集合）随之塌缩；R35 的 60 条来自一份只有 4 个对象的畸形清单，说明 `D05` 的条数与登记行数不成比例，而与「对象数 × 该类 required 数」成比例。这两点合起来给出一条使用约束：**`D05` 的绝对值不能跨运行比较**，它是第 19.2 节 Q3 的触发项而不是量度项。

**（4）四个闭合档的分解。**`Q1`=17 = R21 的 8 + R22 的 4 + R32 的 3 + R37 的 1 + R38 的 1；`Q2`=90 = R20 的 37 + R23 的 37 + R22 的 1 + R32 的 5 + R35 的 4 + R37 的 5 + R38 的 1；`Q3`=10 = R20 2 + R23 2 + R22 3 + R36 1 + R37 2；`Q4`=25 = R20 2 + R23 2 + R22 2 + R31 8 + R36 9 + R37 2。同样没有 R24 的贡献（`-q`）。累计总和 **1634** = `grep -cP '^[A-Z]{1,2}[0-9]+\t' FX/run-log-2.txt` 的 1634，其中 Q 档 142 行（17+90+10+25）、信号 1492 行（13 段有效运行的信号行相加）。

### 23.6 码集合的静态反向对齐

23.4、23.5 是「从脚本里的定义出发，逐个找到一次真实打印」。还缺反方向：**日志里打出来的码，是否都在脚本的定义集里。**这一步由 `FX/code-coverage.pl`（24 行）完成——它从脚本源码提取 `emit("CODE"` 的出现集合，从日志行首提取命中集合，做双向差集，两个差集都为空才返回 0。下面是原样输出：

```text
$ perl FX/code-coverage.pl tools/query-plane-ledger-review.sh FX/run-log.txt
定义 67 命中 67 未触发清单 [] 未定义命中 []
$ exit=0

$ perl FX/code-coverage.pl tools/query-plane-tripartite-diff.sh FX/run-log-2.txt
定义 51 命中 51 未触发清单 [] 未定义命中 []
$ exit=0
```

`定义 67 命中 67`、`定义 51 命中 51`，两次退出码都是 0，四条差集清单全为空。它与两张逐码表合起来给出的是**码集合相等**，不是互相包含：

| 方向 | 检查 | 结果 |
| --- | --- | --- |
| 定义 → 打印 | 每个定义码至少被一段真实运行打印过 | 67 个 R 号、51 个 R 号（23.4、23.5 逐码可查） |
| 打印 → 定义 | 日志里每个行首码都在定义集内 | 「未定义命中」清单为空（上面两段输出） |
| 行数闭合 | 逐码累计之和 = 日志实际行数 | 549 = 549、1634 = 1634（`grep -c` 独立数出） |
| 汇总自洽 | 脚本自己打的「信号行数／判定行数／阻断条数」与逐码表一致 | J 档 96 = 四档累计和；Q 档 142 = 四档累计和 |

定义集的提取方式本身要说清楚：`code-coverage.pl` 用正则 `emit\("([A-Z][A-Z0-9]+)"` 扫源码，`grep -o` 同一模式对两支脚本去重后分别得 **67** 与 **51**，与静态定义集一致。这个口径**只承认 `emit()` 出口**，因此任何绕过 `emit()` 的写法（直接 `print` 一条带码文本）会同时表现为「日志里出现未定义命中」——这是本项检查唯一能抓到的实现走形，也是最容易走形的一种。第三、四行不需要读脚本源码，只需要两份日志，却能在「某个码被加了两处打印」或「某条信号因字符串拼接导致行首不是码」时立刻报警。harness 之所以把 stdout 与 stderr 合并进同一份日志（`FX/run-all.sh` 第 13—24 行、`FX/run-all-2.sh` 同段），就是为了这四行有共同的计数基底。

### 23.7 六组必须留意的读数形状

**（1）R16 与 R17：只差一条的对照。**两份夹具只差一格 `obs.command_name`：R16 填 `none`，打 3 条（`A01`、`B01`、`X01`）；R17 填 `mdfind`，打同样 3 条再加一条 `K02`（日志第 814 行逐字为「字段 obs.command_name 登记了命令行入口（mdfind）：本脚本与台账都不以任何设备侧命令作为读数来源，请删除该格」）。**这两段的 J4 都是 1**，所以这对夹具不是用来判定「谁合格」的，而是用来证明 `K02` 能单独出现——它把第 21.5 节那条「设备侧命令名只作为被拒绝的值出现」变成了可核对的行数差。

**（2）R18 与 R19：一格越界被两条码分别记到。**R18 的 `gate.read_back_api=settings_ui` 打 3 条；R19 换成 `full_listing` 打 5 条，多出的两条是 `S04`（枚举越界）与 `B04`（把「整面读回索引里都有什么」当作可用回读接口，日志第 849 行）。同一次填写错误被两个判据各记一次，是因为两个判据问的不是同一个问题：`S04` 问「这个值在不在允许集合里」（`gate.read_back_api` 的枚举表写在脚本一第 83 行，只有 `none requested_attributes_only item_identifiers settings_ui not_determinable not_recorded unknown` 八个取值），`B04` 问「这个值主张的能力有没有公开口径支撑」（判据在第 301 行，依据 `A/corespotlight_searching-for-information-in-your-app.txt:22—24`）。**下游若把「信号条数」当「错误条数」用，在这里会翻倍。**这是本文推荐用「不同信号码」而不是「信号行数」做台账质量趋势指标的直接原因（对照第 20 章 O8 的计算方式）。

**（3）R31、R32、R33、R34：四个「空」给出的四种结论。**同一份干净清单配上四种空输入，结论彼此独立：能力表为空（R31）⇒ 1 条 `C06`、`Q4=8`、退出 1；词表为空（R32）⇒ 19 条（`X03`=1 聚合非阻断 + `M01`=9 + `V02`=9，后两族阻断）、`Q1=3 Q2=5`、退出 1；清单为空（R33）与清单只有注释（R34）⇒ 全零、退出 0。R32 是这一组里最值得读的一段：干净台账在词表被清空之后**仍然拿到 3 个 `Q1`**，那三个对象是 `QRY-TRIP-DONATE`、`QRY-SYS-DEVICE-IX`、`QRY-SHORT-SUGEST`，它们的引用格全部是文档行号形态而不是词表值，因此 `M01`／`V02` 无从告警。这条形状说明 `Q1` 那句「公开词表三段齐备」在词表整表为空时**对这 3 个对象并未被真正检查过**——聚合级 `X03` 只是提示，不是拦停。第 26 章把「核对 `词表词条` 这一格非 0」列为使用脚本二的固定自查项，实证就在这段里。

**（4）R20 与 R23：差集恰好六个码。**两份夹具的清单完全相同（42 个对象、57 行登记），只差能力表与词表的行形态。逐码差集是 `C01`(2)、`C02`(1)、`C03`(1)、`C04`(1)、`C05`(1)、`X03`(3)，**只在 R20 出现，R23 一条都没有**；其余 40 个码在两段里的计数逐项相等（把两段末尾的逐码计数表按码对齐即可核对，`diff` 结果为这 6 行）。信号行差 673 − 664 = **9** = 五条 C 族 + 三条 `X03`；阻断差 95 − 89 = **6** = 五条 C 族全部（`X03` 不在阻断清单里）。**9 与 6 的分配，就是第 19.1 节末段那条阻断设计的独立实证**——它不依赖读代码，只依赖两次运行的差。退出码两边都是 1，所以这个区别从退出码上看不出来，只能从「阻断」这一列读出来；这正是第 20 章 O9 把 `X04` 单列成指标的理由。

**（5）主语不是同一个空间：42、41、51 三个数。**R20 的 `三件对象数=42`，而 Q 档只打了 **41** 行。三个数都正确，各自回答不同问题：

| 对象 | 夹具形状 | 实现后果 |
| --- | --- | --- |
| `QRY-C-S01` | 该行只有 7 列 | 第 256 行 `n != 8` → 打 `S01` 后 `next`，**连「对象」都不算**，所以夹具里去掉注释、空行与空标识后得到的 43 个标识只进来 42 个 |
| `QRY-C-S04` | 8 列合法，但核对项是 `icloud_relay_state` | 第 260 行已把它计入 `order`（42 里有它），第 269 行 `if (!(it in ITM)) next` 让它一条核对项都没登记，第 271 行的 `kdSeen` 因此没置位，第 443 行 `continue` → **被计数、永不被判定**，所以 42 → 41 |

再加上信号行的主语本来就有四个空间——对象标识（`QRY-*`、`M-*`）、对象类（R20 的 `C01`/`C02`/`C03`/`C04`/`C05` 分别以 `cs_index_app`、`widget_kiosk`、`cs_index_extension`、`web_markup` 作主语）、词表类别（`X03` 逐行支的 `advisory_component`、`spotlight_markup`、`plist_key`），以及聚合级信号的 `-`（`S02`、`X03` 聚合、`X04`、`C06`）。**读脚本二的输出时，同一列「主语」在不同码族下指的不是同一种东西**，任何把它当单一键去 join 的下游用法都会错。这也解释了两支脚本在这一点上的形状差别：脚本一只有一个主语空间（对象标识），所以它的 69 个对象数与 69 行判定数恒等，不存在上面那种「计数但不判定」的洞。

**（6）阻断不对称在退出码上的后果。**把两支脚本的恒等式并排放：

| | 脚本一 | 脚本二 |
| --- | --- | --- |
| 信号行数 | 453 | 1492 |
| 阻断条数 | 453 | 262 |
| 差值 | **0** | **1230** |
| 恒等式 | 逐段成立（16 段全等） | 不成立，差值全部来自 8 个非阻断码 |
| 有汇总行且退出码为 0 的段 | R2、R9、R10（3 段） | R21、R33、R34（3 段） |
| 干净夹具段的退出码 | R2 = 0 | R21 = 0 |

脚本二那 1230 条里 1197 条是 `D05`。如果把 `D02`/`D03`/`D05` 设成阻断，R21（合格三件登记）仍然退出 0，R22 的阻断数从 3 条（`P01` 1 + `D04` 2）变成 6 条（加 `D02` 1 + `D05` 2），退出码不变——差别要等到第三份台账才看得出来。真正的后果在判据语义上：`D05` 说的是「这一格漏登记」，而**任何一份有对象缺登记的台账都会因此永久退出 1**，脚本失去「干净输入给 0」这个下界，也就失去了 23.1 第 3 条验收标准。同理，`X04` 若设成阻断，R20／R22／R23／R36／R37 五段全部退出 1，而它承载的读数（组件列具名 6 个、条目级组件名 0 个）恰好是本文的中心事实——一个每次运行都报警的信号等于一个没有信息的信号。第 19.1 节说这两支脚本的阻断设计「唯一不对称」，不对称的代价在这里可以量化成一行：**1230**。

### 23.8 这次验收不证明什么

覆盖验收容易被读成「脚本已经正确」，所以这里把边界逐条写清。

1. **码可达 ≠ 分支枚举完整。**本节证明的是「每个码至少被一次真实输入触发」，不证明「每个码的每一条判据都各自被触发过」。一个由四个合取项组成的条件（脚本一第 294—312 行的 B 族里有好几条）只要有一条输入让整体成立，就只显示一次该码；缺哪一个合取项使它不成立，日志里没有答案。33 个单点码（23.4 第（2）段）连「多次独立触发」都还没有。合取项级别的覆盖需要「每项各缺一次」的夹具矩阵，本文没做到 63 × 项数 这个量级。
2. **夹具是人写的形状，不是设备读数。**`FX/fixture-query-codes.txt` 的 69 个对象、`FX/inventory-17-codes.txt` 的 42 个标识、`FX/capability-17.csv` 的 168 行，都是为了命中判据而构造的。它们**不是任何一台设备的读数**，字段组合在真实系统里可能根本不存在。这些数字只支撑「脚本按判据工作」，不支撑「iOS 在这台设备上就是这样」。所有取值均为合成词表，不含真实姓名、地址、电话号码与应用账号。
3. **词表整表为空时 `Q1` 的第三段可能是空的。**23.7 第（3）段给了实证：3 个对象在 `词表词条=0` 的情况下仍判 `Q1`。使用脚本二的结论时，必须同时核对汇总行的 `词表词条` 非 0；`X03` 那条聚合信号只是提示，不拦停。本文不修这个行为（理由见 23.7 第（6）段的下界论证），但把它记进第 26 章的固定自查项。
4. **合格夹具是下界，不是上界。**R2 与 R21 给 0 信号，只说明「这样的输入不被拦」，不说明「所有该被拦的输入都会被拦」。特别是第 20 章 O10 那条：一次删除之后没有任何再检索登记，两支脚本都给不出信号——**没有信号本来就不是信号**。这一类漏登只能靠台账自查动作补，不能靠脚本补。
5. **`exit 0` 不等于「已获授权」或「已删净」。**两支脚本判的都是登记内容的自洽性。退出码 0 的含义是「这份台账在当前判据下无阻断」，与「这条内容按公开口径不可能被某类发起方查回」以及「索引库里已无此条」是三个不同命题（第 15 章归属矩阵的「不可登记」列就是为此而设）。
6. **单一环境。**38 次实跑在同一个 shell 与同一个 `gawk` 上完成。`bash -n`（23.1 P5）只证明语法，不证明 mawk、busybox awk、BWK awk 给出同样输出。两支脚本用到的 awk 特性限于 POSIX 子集（关联数组、`SUBSEP`、`/dev/stderr` 写入除外——最后这一项是 gawk 与多数 GNU 实现的行为，在严格 POSIX awk 上需改为具名文件），但**未做跨实现验证**。
7. **判定只读登记件。**这是 23.1 末段那条不对称的重述：P1 的零命中证明脚本没有可读别处的口子，因此判定过程完全可离线复算；它不能证明登记内容与真实设备一致。**本文能保证的是复算，不是采集。**要得到后者，需要设备上的采集流程与本文之外的授权，那是第 17 章「拿不到的四类」写死的那堵墙，也是这一系列每一篇都会撞上的同一堵墙。



---

## 24. 十二个误区

以下十二条是把第 3—23 章的读数压回成一句话时最容易压错的形状。每条给出**误区表述 → 依据读数 → 正确表述**，依据只用本篇归档件里的行锚与第 23 章那 38 次实跑的日志，不引入新事实。前八条与第 3.4 节那八处换算失败一一对应——这不是省事，是因为那八处失败本来就是「两格被压成一格」的八个具体形态；后四条压的是失败点之外的四个惯性读法（读数粒度、实测冲动、退出码语义、删除语义）。

**误区 1：索引是系统在维护的，App 只要按隐私口径申报完用途，内容自然就能被搜到。**
依据：`A/corespotlight.txt:17` 把责任直白地写在开发者一侧——「Your app is responsible for indexing your app's content and maintaining those indexes」，第 18—19 行给的两种时机（内容变更时、App 被后台刷新时）也都是 App 侧动作；第 19—21 行还允许索引「App 当前没有显示的文件与其他内容」，而**这一步不产生任何新的用途申报**。第 2.1 节给 08 篇划的分界正落在这一句上：申报完成与入面与否是两次互不相干的判定，申报了某个用途也不给任何一条内容开检索面。台账侧：`A/adding-your-app-s-content-to-spotlight-indexes.txt:18—19` 是脚本一 `B02` 的出处（启用属性才把活动送进本机索引，累计 3 次、首现 R1），脚本二在 R20 一次打出 `T01`=42 条「声明件写了而通道件或观测件全空」的差集。
正确表述：**申报与入面之间没有换算关系。**只有声明件那一格有值时，能说的极限是「这段代码按公开口径有权把这条内容写进某个具名索引」；要说「这条内容现在可查」，必须通道件与观测件也各有值且各有核对时刻。脚本一把缺主语的登记压成 `A01`（R1 一次 82 条），脚本二压成 `T01`——两支脚本用不同形状说同一件事：入面是**写入动作的读数**，不是**申报动作的读数**。

**误区 2：`isEligibleForSearch` 为真，所以这条内容此刻一定查得回来。**
依据：`B/nsuseractivity.txt:331` 与 `:319` 是两个**互相独立**的位（前者管「加进本机索引」，后者管「参与预测」），而第 10 章的四道场景门全部作用在通道件上：`B/mdm-restriction-keys.txt:24` 的 `allowAssistantWhileLocked` 一旦关闭，锁屏段的可查询面整体消失，与任何一条条目的资格位取值无关。第 3.4 节失败点 2 的原话是「资格位是**声明件**，场景门是**通道件**，中间没有换算关系」。更常见的一处写反在 `B05` 的判据里：`B/mdm-siri-keys.tsv` 对 `allowAssistantWhileLocked` 明写「The system ignores this restriction if the device doesn't have a passcode set」——**没有设密码时这条限制被系统忽略**，所以「我把锁屏助理关了」这个治理动作在未设密码的设备上根本不成立（该码累计 1 次、首现 R1）。
正确表述：**资格位为真只成立「有资格被判定」，不成立「此刻放行」。**台账要 `cap.eligible_for_search` 与 `state.gate_*` 各自有值、各自记时刻，第 10.4 节那张六种组合表里只有两行能给出完整结论；「关/开」那一行的正确写法是「锁屏前的检索面不能写『不存在』，只能写『该场景不放行』」。缺任一一格，脚本一判 J3（第 19.1 节）。

**误区 3：内容在索引里，所以查它的时候属性自然读得到。**
依据：`A/corespotlight_searching-for-information-in-your-app.txt:22—24`——「执行查询时，系统不会自动取回每个属性……它只取回你明确请求的属性」，第 29—30 行还补了一句 `title`／`displayName` 也得列进请求里才回得来。这条是脚本一 `B04` 的固定出处（DOC 数组第 132 行、发出点第 301 与 303 行，累计 4 次）；第 7.2 节把它写成三件法里最容易误读的一格：**读取方的代码决定了这次能看见哪几格**。反向的读数同样存在：`A/cssearchableindex.txt:16—17` 只承诺「执行查询那一刻」把结果返回给代码，`A/csuserquery.txt:35—41` 规定不指定上限时查询会一直跑到返回全部结果——两者都在通道件里，但一个管「回不回」、一个管「回多少」。
正确表述：**「在面上」与「这次回得来几格」是两格，台账里把这两格合并登记是最常见的假闭合。**`attributes_requested` 必须逐格列，且注明这次查询由谁发起（App 自己、系统 Spotlight、快捷指令与建议面、基础模型四种发起方见第 7.1 节）。第 20 章 O6 用「属性白名单收敛度」单独量这一格，越低越好。

**误区 4：Core Spotlight 的索引不上送 Apple，所以用户输入的检索词也不上送。**
依据：`A/corespotlight.txt:22—23`「设备不会与 Apple 共享索引数据，也不会把该数据与这个人的其他设备同步」与 `B/siri-dictation-legal.txt:28`／`:34`「（检索词）会被 Apple 存储并用于改进 Search、Siri 与相关功能」是**两句不同文档里的两件事**，`B/legal-siri-suggestions-search.txt:28` 独立重复了后者。脚本一为这一处换算失败单独设了 `N03`（累计 1 次、首现 R1），`C02` 的 DOC 串（第 141 行）则固定引用上一句。第 9.1 节那张六路口径表里，这两行分属不同列且不可合并。
正确表述：**「存量不上送」与「查询词上送」同时成立，任何一侧都不构成另一侧的证据。**台账里 `scope.reach`（本机面／服务端面／公开索引）与 `doc.notice_ref`（告知页那句关于请求记录的承诺）必须分别成格。同理，反向的写法也错：`B/siri-dictation-legal.txt:65` 说建议「不存储在 Apple 服务器上，也不与其他第三方 App 共享」，这一句不能用来否证检索词上送，因为两句的主语不是同一个对象。

**误区 5：安全公告的组件列写了 Spotlight，所以公告说清了索引侧的问题；反过来说，影响句没提检索面，就表示这批条目与检索面无关。**
依据：这是本篇的中心读数，两个方向都错。`C/query-plane-17.tsv` 的 68 行子集里，组件列具名 6 个检索面组件（Spotlight 26、Shortcuts 16、Siri 15、Apple Intelligence 4、App Intents 4、Help Viewer 3，按全等筛而非子串——`Siri` 按子串会误吞 `SiriKit`），而对 `impact` 列做不区分大小写的子词计数，`index`／`search`／`suggest`／`query`／`dictation` 等检索面词形**全部 0 次命中**，只有 `contact` 4 次、`lock` 1 次、`notification` 1 次（第 13.2 节，独立复算见 `C/query-plane-17-summary.txt`）。脚本二把这件事写成非阻断的 `X04`（第 160—163 行定义词形、第 320—322 行匹配、第 335—336 行输出，累计 5 次、首现 R20），合格夹具逐字读数 `检索面具名组件=6 条目级组件名=0`。
正确表述：**检索面的存在性由组件列承载，检索面的后果在影响句里一个字都不提。**`X04` 那句实现文本给的结论是「按这份词表口径，检索面缺陷只能归到组件，不能归到某一条索引条目」——它约束的是**归因粒度**，不是缺陷存在性。第 15、16 篇处理的是「平面在两列都缺位」，本篇是「一列有、一列无」，两种形状不能互推，所以 `X04` 故意不阻断：否则干净输入也退不出 0，脚本失去下界。

**误区 6：下发一个限制键把 Siri 关掉，索引里的内容就被清掉了。**
依据：`B/mdm-restriction-keys.txt` 全 220 行、216 个键名（第 1—4 行是页面分段标题，所以行数与键数的差固定为 4），与检索面有关的只有 11 个：第 22、23、24、61、70、71、141、143、182、196、197 行。这 11 个全部形如 `allow*`／`force*`，**没有任何一个键名含 `index`、`spotlight-index`、`searchable` 或等义写法**；另外 10 个旧 Siri 键在 `B/mdm-siri-keys.tsv` 里全部标着 Deprecated，接管方是 `com.apple.configuration.siri.settings`（`B/mdm-restrictions.txt:1250+`）。脚本一 `G02`（DOC 数组第 165 行，累计 2 次）与 `O03`（累计 1 次）分别钉住「键清单本身是负空间结论的落点」和「十个 Siri 键全是通道开关，没有一个读取 App 写了哪些索引条目」。
正确表述：**开关改变的是「谁还能查」，不是「面上还有没有」。**管理面对这一格是空白，不是「暂时没读到」。第 20 章 O8、O9 的正确目标值因此是**登记数为 0**：任何「管理面读到某条索引项」的登记都越界，脚本二会以 P 族拒收（`P01` 累计 5 次、首现 R20）。注意两个适用条件别丢：`G05` 记录 `allowSpotlightInternetResults` 的 unsupervised 支持已弃用、`allowAssistantUserGeneratedContent` 标注 Requires supervision，`G04` 记录迁移态——`mgmt.migration_state` 不登记，第 10 章那道门就只能判 J3。

**误区 7：调用过删除接口，所以这条内容已经删干净了。**
依据：`A/adding-your-app-s-content-to-spotlight-indexes.txt:67—72` 与 `A/cssearchableitem.txt:36—37` 是两条语义等价的义务句（分别落在条目面与索引面），而 `:91` 写的是删除会**异步并入**索引更新；`A/cssearchableindex.txt` 第 58、70、88、100、116 行给出五个删除粒度（全量／按实体类型全量／按实体标识与类型／按域／按标识符），Obj-C 侧第 352、354、356 行是四个入口的签名，**所有说明句里都没有「立即生效」或「可在索引中验证」**。脚本一 `V01` 的 DOC 串就是这一句：「删除入口在索引对象上，验证只能靠再查一次」（累计 1 次）；`V04`（累计 3 次）拦「把四个入口的调用方写成别人」，`V03` 钉义务句。
正确表述：**本文允许的表述只有一种三段式**（第 14.4 节）：按标识符发起过删除 ＋ 再检索未命中 ＋ 该格登记了核对时刻；三段缺一，脚本一 V 族与脚本二 T 族分别降级，`query_result=hit` 却声称已删净时 `T04` 直接阻断。写台账时还要分清三个计数：**五粒度、四 Obj-C 入口、三条语义级说明**——摘要里的 `:58/70/88/100/116` 是行号序，散文里按「按标识符／按域／全量」是另一种顺序，两者不是矛盾。另外，三种复位（第 14.3 节：全量再索引并要求清本地状态 `A/corespotlight_cssearchableindexdelegate.txt:76`；系统请求重建 `A/regenerating-your-app-s-indexes-on-demand.txt:6—11`；到期自动过期）之后**先前登记的一切观测读数全部作废**，所以 `when.reset_at` 缺格时 T 族判阻断——「删干净」和「查不到」之间还夹着一次可能已经发生的重建。

**误区 8：App 自己建的索引，可见性只影响这个 App。**
依据：写入方只有一个，读数面至少有四个。`A/corespotlight.txt:3` 把 Core Spotlight 定义成系统级检索面的底座，第 19—21 行允许索引未显示内容；`A/spotlight-search-tool.txt:3—4` 与第 27、29—30 行把 Spotlight 搜索工具开放给基础模型，并区分 `FileSource` 与索引侧来源；第 81 行给出模型侧读到的字段，第 15 行的 `ContactResolver` 说明**人物指向字段可以被模型侧解析**。第 3.4 节失败点 8 的结论句是「读数面至少有四个，而写入方通常只登记了一个」。脚本一 `C01`（DOC 第 137 行，指向 `A/spotlight-search-tool.txt:19、21、71—73` 的 `CoreSpotlightSource`）累计 1 次、首现 R1，是这条通路上唯一一次单点证明；第 12.3 节补了另一半：只有 App 自己的查询回调能证明「这次是这段代码发起的」，另外三种发起方的读数**不回到写入方**。
正确表述：**「谁能查回我的索引」不由写入方登记决定，而由发起方与属性请求决定。**`obs.plane` 与 `gate.read_back_api` 必须逐发起方各记一行；把 `ContactResolver` 那类模型侧解析并入 `attributes_requested` 会同时丢两条读数，脚本一按 `V03`／`T01` 处理。平台差异另记：`A/corespotlight.txt:15` 说明文件导入扩展在 macOS 不提供功能（`C05` 的出处之一），别把 iOS 侧的再索引扩展形状外推。

**误区 9：`isIndexingAvailable` 返回 false，或者我查一次没命中，所以这条内容不在面上。**
依据：`A/cssearchableindex.txt:266—272` 给的读数粒度是**整台设备**，不是某个条目，而且它是全套公开文档里唯一一处索引可用性读数（第 6.3 节）。第 12.2 节的核心事实更硬：「没有任何一个面能读回『这条内容当前是否在检索面上』」——与第 16 篇的缺格不同，16 篇缺的是**状态**读数，本篇缺的是**存量**读数：不但不知道状态，连面上现在有几条都不知道（第 5.3 节：没有任何公开文档给出「列出当前索引里所有 `uniqueIdentifier`」的接口）。台账侧 `query_result` 只允许三个取值，其中 `no_hit` **不等于**「不在面上」；`A/cssearchableindex.txt:16—17`（`T01` 的 DOC 串）把结果限定在「执行查询那一刻」。
正确表述：**一次未命中只能否证「这次这一格回不来」，不能否证「这条不在面上」。**要么把这次查询登记成 `not_run` 或 `no_hit` 并附核对时刻与发起方，要么不写。第 17 章「拿不到的四类」里第一条就是「设备上当前有哪些条目、共几条、属于哪些域」，写进台账就是越界，脚本会以 V 族与 P 族拒绝。

**误区 10：拿设备实测一下最直接——跑一次 `mdfind`，或者在锁屏上搜一遍就知道口径了。**
依据：这是方法论越界，不是结论分歧。第 2.5 节把本文可证形态限死为三种——接口口径、开关口径、告知口径，并写明「**没有第四种。**本文不允许任何『实测发现某条内容查不到』的表述」。两支脚本在设计上不留口子：第 23.1 节 P1 那条 grep 用 `system(`／`getline <`／`popen(`／`close(`／`cmd `／`exec ` 六个模式跨 944 行给出**零命中**（以 grep 自己的退出码 1 表达），P4 列出 18 个设备侧命令名，全篇只有 3 处命中，且三处都在注释或拒收分支里——脚本二第 397 行那个正则拦的就是「把命令名当来源登记」这个动作。台账侧两个码专管此事：`K01`（`sec.*` 命名空间拒收，第 188 行，累计 4 次、首现 R11）与 `K02`（`obs.command_name` 填了命令行入口，第 237 行，累计 4 次、首现 R15）。
正确表述：**本篇的全部结论都必须是离线可复算的口径结论。**要得到设备事实，需要另一套流程与本文之外的授权（第 23.8 节第 7 条：「本文能保证的是复算，不是采集」）；这条限制也是第 26 章 N12 的正文。把实测冲动写进脚本，脚本就从「口径审查器」变成「采集器」，两者不能共存。

**误区 11：脚本退出码 0、或者某个对象判到 `J1`／`Q1`，就说明这条通路没问题。**
依据：三种形状都会给出你不想看到的 0。其一，**空登记**：R33（`FX/tmp-empty.txt`）与 R34（`FX/tmp-comments.txt`）都是「三件对象数=0 核对项登记行=0 词表词条=720 信号行数=0 / 不同信号码=0 阻断信号条数=0 / 闭合等级 Q1=0 Q2=0 Q3=0 Q4=0」，退出码 0——日志第 2086—2089 与 2097—2100 行逐字如此，矩阵那一段只打了两行标题中间空着。其二，**输出开关**：R5 与 R3 是同一份夹具（第 23.3 节逐字段对照），R5 加 `-q` 后 stdout 的 6 行 J 档归零而 stderr 信号 16 条照旧、退出码仍是 1；只看 stdout 会读到「一个判定都没有」。其三，**合格夹具是下界不是上界**（第 23.8 节第 4 条）：R2 与 R21 给 0 信号只说明「这样的输入不被拦」，而第 20 章 O10 那条「删除可证率永远不可能到 1」的缺口，合格夹具同样给不出——**没有信号本来就不是信号**。
正确表述：**退出码只跟随阻断族，不表达任何正向结论。**脚本一的恒等式是「信号行数 = 阻断条数」（63 个码全部在阻断集里，第 113—114 行），所以它的 0 只表示「一份登记都没有被拦」；脚本二有 8 个非阻断码（`S08 D02 D03 D05 X03 X04 V03 V04`，第 190—198 行只收 39 码），R20 一次就打出 673 条信号而只有 95 条阻断，非阻断存量在两段之间相差 1,230 条。`exit 0` 也不等于「已获授权」或「已删净」：两支脚本判的都是登记内容的自洽性，第 9 章的三态问题不能靠一个退出码抹平。使用时固定核对三格：`三件对象数` 是否为 0、`词表词条` 是否为 0（R32 词表清空后仍有 3 个对象判 `Q1`）、核对时刻是否早于最近一次复位。

**误区 12：关闭 Siri 与听写会把索引内容一起删掉——告知页那句「删除」覆盖整条通路。**
依据：`B/siri-dictation-legal.txt:72` 的删除对象是「设备上存储的、用于个性化体验的 Siri 与听写请求**转录**」，通篇没有一句说关 Siri 会清掉 Core Spotlight 索引——这正是脚本一 `B03` 的 DOC 串（累计 4 次、首现 R1），`O05` 的 DOC 串把它压成最短一句「关闭开关与删除条目是两件事」（第 72、76 行）。同一份告知文本里还有两条容易被合并的口径：留存上限有两条不同的（第 39 行「至多两年」与被抽检的一小部分可以超过两年；翻译另有第 43—44 行），`B/support-127070.txt` 与另两份法律页给的是页面日期而不是索引成立时刻（`T04` 的 DOC 串指向 `B/legal-siri-suggestions-search.txt:54`）。设置面侧第 76 行给的是逐 App 的 `Settings > Siri > Suggestions > [app name]`，脚本一 `B01` 用它钉「开关粒度到 App 不到条目」（累计 80 次），`O02` 记录 Suggestions 与 Suggestions & Search 是两格，`O04` 记录 `expirationDate` 出现在 API 清单里而不是设置面读数。
正确表述：**告知面的「删除」与索引侧的「删除」是两件不同的事，混用是本篇第十二个误区**（第 11.3 节预告过这一条）。用户侧关闭只有开关级粒度，删的是转录；索引项的删除只有第 14 章那五格接口，且没有任何回执面。台账里 `notice_page` 与 `undo.method` 必须各自有值：前者登记「告知页承诺删掉什么、页面日期是哪天」，后者登记「对哪个对象、用哪个入口、什么时候、再检索结果是什么」。跨页引用时 `B/siri-dictation-legal.txt:65` 那两句（不存储、不共享）必须同一行一起引，只引半句会同时错开第 9 章与第 11 章的口径。

十二张形状对照如下，末列给出该误区在两支脚本里的落点与第 23 章的实证次数；「累计」为跨 38 段的逐码累计（脚本一取自 `FX/map1.txt`，脚本二取自 `FX/map2.txt`）：

| 误区 | 压错的换算 | 层 | 主要信号码（累计） | 实证段 |
| --- | --- | --- | --- | --- |
| 1 | 申报 → 入面 | L1／L2 | 一 `A01`(82)、二 `T01`(42) | R1、R20 |
| 2 | 资格 → 此刻放行 | L3／L7 | 一 `B05`(1) | R1 |
| 3 | 在面上 → 属性回得来 | L4 | 一 `B04`(4) | R1 |
| 4 | 存量不上送 → 查询词不上送 | L6 | 一 `N03`(1)、`C02`(1) | R1 |
| 5 | 组件列具名 → 影响句说了 | L10 | 二 `X04`(5，非阻断) | R20 |
| 6 | 关掉通道 → 清掉内容 | L7／L11 | 一 `G02`(2)、`O03`(1) | R1 |
| 7 | 调过删除 → 删干净 | L11 | 一 `V01`(1)、`V03`(1)、`V04`(3) | R1 |
| 8 | 我的索引 → 只影响我 | L9 | 一 `C01`(1) | R1 |
| 9 | 未命中 → 不在面上 | L3／L9 | 一 `T01`(20) | R1 |
| 10 | 实测 → 可证 | 全篇 | 一 `K01`(4)、`K02`(4) | R11、R15 |
| 11 | 退出码 0 → 没问题 | 全篇 | 二 `Q1`(17)、`C06`(1) | R21、R31、R33、R34 |
| 12 | 关 Siri → 删索引 | L8／L11 | 一 `B03`(4)、`B01`(80)、`O05`(6) | R1 |

最后一列里三个「累计＝1」值得单独看一眼：`N03`、`C01`、`V01` 都只在 R1 打印过一次，也就是说误区 4、8、7 的守卫各自只被一次真实运行证明过（第 23.4 节读法 2 把那 33 个「单点证明」码列全了）。改到这三条判据时，只有 R1 那一段日志会变色，其余各段毫无反应——这是本文当前覆盖强度的真实上限，不是笔误。



---

## 25. 常见问题

**问：这套台账必须跑在设备上吗？**
不。两支脚本都是纯文本、离线、只读：脚本一收一份或多份三列台账，脚本二收固定三份登记件（清单、能力表、词表），全程不调用任何 Apple 命令行工具、不访问设备、不联网、不读索引库。第 23.1 节那八段检查（P1—P8）是这件事的实证而不是一句声明——P1 用六个系统调用型模式跨两支脚本 944 行找出零命中（用 grep 自己的退出码 1 表达），P4 列 18 个设备侧命令名只找到 3 处且全在注释与拒收分支里，P6 跑完两份合格夹具后 `ls -d` 两个临时目录通配都报 `No such file or directory`，P8 把 38 条命令行归一化后只剩 8 种形状、全部是「脚本 + 可选 `-q`／`-h` + 零到四份夹具」。所以它可以跑在准备室、评审会或 CI 里。**但要说清一处不对称**：P1 检查的是「有没有能读别处的口子」，检查不到「读到的内容是不是设备事实」——登记件由人填写，本文能保证的是判定过程可离线复算，不能保证登记内容与某台真实设备一致（第 23.8 节第 7 条，第 26 章 N12）。

**问：两支脚本我该先跑哪一支？**
先脚本一。它逐条检查单个对象的十一格完整性，输出的是 J1—J4，回答「这一条登记能不能进入对外表述」；脚本二吃的是另一形状——八列三件清单加两份表——输出 Q1—Q4，回答「三份登记对完之后归属还能不能立起来」。两者判的不是同一个东西（第 19.3 节：J 查**一条登记内部**的完整性，Q 查**三份登记之间**的一致性），**绝不合并成单一分数**：合并会掩盖一件事——逐条越严谨，越容易让三件缺口看起来像已闭合。实际用法里 R20 那段最能说明问题：42 个对象里 37 个落 `Q2`，而同样的内容按对象逐格交给脚本一看，问题形状完全不同（`A01`、`B01`、`X01` 三条一组反复出现）。

**问：要准备几份输入？顺序能换吗？**
脚本一 1 份起，可一次传多份，格式是三列 `<检索面对象标识>,<字段名>,<值>`（`#` 开头与空行忽略、行尾 CR 忽略、值里不能含逗号）。R4 那次一次传两份（`FX/fixture-query-good.txt` 与 `FX/fixture-query.txt`），9 个对象 = 3 + 6，互不污染。脚本二固定 **3 份且顺序不可换**：八列三件清单、三列能力表（CSV）、三列公开词表（TSV）。参数校验不对称：脚本一只要求「至少一份且每份存在」（第 41—42 行），脚本二硬检查恰好三份（第 84—88 行），因为差集必须同时有基准。这条不对称有实证——脚本一侧只有 R7（无参数）与 R8（文件不存在）两次退出码 2，脚本二侧有 R26—R30 五次（0、1、2、4 个参数各一次，加第三份不存在一次）。

**问：「十一格」和「21 项核对项」是一回事吗？**
不是，而且这是两支脚本之间最容易串的地方。**十一格**属于脚本一，是命名空间：`id.`、`cap.`、`state.`、`op.`、`gate.`、`scope.`、`when.`、`obs.`、`undo.`、`mgmt.`、`doc.` 十一类（外加一个纯拒收的 `sec.`，第 188 行），逐对象检查每类里该填的字段填没填，判据写在第 415—426 行。**21 项核对项**属于脚本二，是三件切分：声明件 6 项（`index_name`、`index_kind`、`eligibility_decl`、`type_identifier`、`usage_notice`、`content_owner_decl`）、通道件 7 项（`api_path`、`query_api`、`initiated_by`、`item_uid`、`domain_id`、`attributes_requested`、`max_results`）、观测件 8 项（`settings_toggle`、`settings_list`、`profile_key`、`restriction_key`、`advisory_component`、`query_result`、`notice_page`、`delete_verified`），6＋7＋8 = 21。两者有交集但不是一一映射：例如 `undo.*` 那一整类在脚本一是六个字段，在脚本二只落到 `delete_verified` 一项上；而 `restriction_key` 在脚本二是观测件一项，在脚本一是 `mgmt.restriction_key` 一个字段并由 G 族五个码单独判形态。**跨脚本对齐台账时，用对象标识，不要用格名。顺带解掉一处数字歧义：J1 那句判定文本里列了十二个中文名（身份、声明、权利、开关、查询发起、闸门、范围、时效、观测、删除、管理面、引用），而计数写作「十一格」——因为「声明」与「权利」同属 cap.* 一个命名空间（脚本 usage 那段第 20 行写的就是 `cap.*` 后的「声明与权利」），十一是空间数、十二是说法数。台账与判据一律按十一格对齐。**

**问：能力表怎么建？我不想从零开始。**
从 `FX/capability-17.csv` 起步：182 行 = 14 行口径注释 + **168 行数据**，形状是 8 个真实对象类 × 21 项核对项，每行 `<对象类>,<核对项>,<required|optional|not_applicable|undocumented>`，取值分布是 required 76、optional 30、not_applicable 46、undocumented 16。注释里逐条写了口径来源（哪个文件哪几行支持这一格对该类对象成立）。三条规则：`required` 必须能指到具体文件与行号，指不到就记 `undocumented`；`undocumented` 的处理是**整格跳过**（既不报覆盖空洞也不报不适用），这是第 26 章那条「公开文档既没说要也没说不要」边界的实现；`not_applicable` 要有公开口径明确说这一格对该类不成立，不能拿它当「我不想登记」的写法。改完必须重跑 `FX/run-all-2.sh`：`D05` 的条数会随 required 集合乘法变化，R20 一次就打出 **1,197** 条 `D05`，占脚本二全部 1,492 条信号的八成——这不是脚本变严格了，是分母变大了。

**问：公开词表那 720 条哪来的？为什么合格夹具读到「组件词条=128」，而公告基线里明明有 129 个组件名？**
`FX/vocab-17.tsv` 是 722 行 = 表头 + **721 条**，三列 `kind<TAB>value<TAB>source`；脚本二读进来做归一化去重，得到 `去重词条=720`。类别分布是 `advisory_cve` 330、`restriction_key` 216、`advisory_component` 129、`api_symbol` 32、`activity_property` 7、`declarative_type` 6、`plist_key` 1，相加 721。少掉的那一条与组件列的 129 → 128 是**同一个事件**：`C/advisory-17.tsv` 里 `Remote Management`（第 462 行）与 `RemoteManagement`（第 465 行）在归一化后折叠成一对。所以「129 个去重组件名」说的是公告基线表自己的原始计数，「组件词条=128」说的是词表归一化之后的计数，两个数都对，**并列出现时必须带上这句解释**，否则下游会读成矛盾。另外 `键类词条=222` 也比 216 多 6，因为词表里除了 216 个限制键还收了声明式类型名与 `plist_key` 等键形词条——这也是第 3.3 节词表 C 与管理面键清单不是同一个集合的原因。

**问：68 行检索面子集是怎么筛出来的？影响句一个检索面词都没有，为什么脚本二还能给出 `Q1`？**
筛法是按 `component` 列**全等**匹配六个检索面具名组件（`C/advisory-17.tsv` 基线 1,266 条、129 个去重组件，筛出 `C/query-plane-17.tsv` 69 行含表头 = 68 条：Spotlight 26、Shortcuts 16、Siri 15、Apple Intelligence 4、App Intents 4、Help Viewer 3；去重 CVE 20 个，跨 8 个平台发布）。用全等而不是子串，是因为 `Siri` 按子串会误吞 `SiriKit`。影响句的 0 命中是脚本二的**非阻断**读数：承载它的 `X04`（第 335—336 行，累计 5 次）故意不在第 190—198 行那 39 个阻断码里，8 个不阻断码是 `S08 D02 D03 D05 X03 X04 V03 V04`。所以一个对象完全可以「三件差集干净、平面可得性干净、词表三段齐备」而同时被 `X04` 提示一次列间错位——`Q1` 与 `X04` 并存是设计结果，不是漏检。若把 `X04` 设成阻断，任何引用了检索面公告的干净输入都退不出 0，脚本就失去下界（第 23.8 节第 4 条要的正是这个下界）。

**问：能不能把某一格从台账里删掉，让覆盖率好看一点？**
不能，脚本会看出来，而且方向常常与预期相反。删掉能力表里某对象类的一行 → `D04`（该类无行）；把能力表清成只有注释 → `C06`（整表无有效行）→ 8 个对象全部落 `Q4`、退出码 1（R31 那一段就是这一条）。删掉台账里的读数行 → `D05` 逐格计数、`Q` 档降。**把清单本身清空反而更糟**：R33 与 R34 给出「对象 0、登记行 0、信号 0、四档全 0、退出码 0」——看起来最干净的一次运行，其实是什么都没判。词表清空也不干净：R32 打出 19 条信号（`X03`=1 非阻断、`M01`=9、`V02`=9）与 `Q1=3 Q2=5`、退出码 1。**降低覆盖指标的唯一途径是补读数或换平面，不是改分母**（第 20 章 O1—O10 全部按这个前提写）。

**问：脚本二报的「三件对象数」为什么和它自己打的 Q 档行数不一样？**
因为三个数回答三个问题。`FX/inventory-17-codes.txt` 第一列去掉注释、空行与空标识后有 **43** 个标识；R20 读到 `三件对象数=42`，而 Q 档只打 **41** 行。两处差各有原因：`QRY-C-S01` 那行只有 7 列，脚本二第 256 行 `n != 8` 打出 `S01` 之后直接 `next`，**连「对象」都不算**，所以 43 → 42；`QRY-C-S04` 那行 8 列合法但核对项写的是 `icloud_relay_state`（不属于 21 项），第 260 行已把它计入 `order`，第 269 行 `if (!(it in ITM)) next` 让它一条核对项都没登记，`kdSeen` 因此没置位，第 443 行 `continue` → **被计数、永不被判定**，所以 42 → 41。脚本一没有这个洞（69 个对象数与 69 行判定数恒等），因为它的信号行只有一个主语空间。还要提醒一句：脚本二同一列「主语」在四个码族下指的不是同一种东西——对象标识（`QRY-*`／`M-*`）、对象类（`C01`—`C05` 分别以 `cs_index_app` 等作主语）、词表类别（`X03` 逐行支）、聚合级信号的 `-`（第 23.7 节第（5）段列全）。**任何把它当单一键去 join 的下游用法都会错。**

**问：「当前场景门开着还是关着」到底能不能读到？平面枚举为什么一会儿说九个、一会儿说十六个？**
读不到，这一点第 10 章和第 12 章各证一次：`B/siri-dictation-legal.txt:37` 给的是设置路径而不是读数，`A/cssearchableindex.txt:266—272` 的 `isIndexingAvailable` 粒度是整台设备而不是某个条目，而 `B/mdm-siri-keys.tsv` 还补了一条容易漏的——`allowAssistantWhileLocked` 在设备没设密码时被系统**忽略**（脚本一 `B05`）。所以第 10.4 节那张六种组合表里，「锁屏／外部智能开」那一行只能写「该场景不放行」，不能写「检索面不存在」。数字不矛盾：**九个**是第 12.1 节里能承载读数的平面组（管理面那一组同时有 `configuration_profile`／`mdm_declaration`／`declarative_management` 三个名字，按一组算）；**十六个**是脚本二 `PL` 集合里的合法取值，即那十一具名平面 ＋ `vendor_claim`／`app_self_report` 两个**不承载**值（填了就落 P 族，`N02` 在脚本一侧拦「厂商说法」）＋ `none`／`not_recorded`／`unknown` 三个控制值。第 17 章「拿不到的四类」第一条——设备上当前有哪些条目、共几条、属于哪些域——不在任何一个平面上，写进台账会同时被 V 族与 P 族拒绝。

**问：退出码该怎么做门禁？**
`2` 判「输入坏了」（参数个数非法、文件不可读、清单整段形态非法），`1` 判「有阻断信号」，`0` 判「无阻断信号」——三者严格分开：38 段实跑的序列合并计数是 **0 出现 8 次、1 出现 23 次、2 出现 7 次**，7 次 2 全部落在「输入不可用」这一类（R7／R8 与 R26—R30）。**不要按档位设门禁**，档位与退出码不是同一个量。三个反例都在第 23 章：R21 的 8 个对象全判 `Q1`、信号 0、退出码 0，这是下界而不是达标；R33／R34 退出码 0 却一个对象都没判；R24 用 `-q` 跑，stdout 上一行 Q 档都没有，退出码仍是 1、汇总三行照打（第 23.3 节的逐字段对照）。要卡质量就把汇总行里的 `J1` 占比、`Q1` 占比与 `required` 缺读率作为评审指标（第 20 章 O1—O10），让退出码只承担「这次运行能不能被采信」这一件事。最后一条边界：**`exit 0` 不等于「已获授权」，也不等于「已删净」**——两支脚本判的都是登记内容的自洽性；把脚本输出当授权用，是把第 9 章那个三态问题重新抹平。



---

## 26. 未公开文档化边界清单

本章收录的是「公开文档没给，本文就不结论」的那些格子。一条边界要进这张表，必须同时满足三个条件之一：**（a）** 公开文档对这一格既没写成「该类对象必须登记」，也没写成「对该类对象不成立」——即三件能力表里 `undocumented` 的那种状态；**（b）** 公开侧有读数，但粒度与本文要的格子不匹配（设备级读数不能当条目级用，通道级开关不能当存量用）；**（c）** 完全没有公开读点，而第 2.5 节的红线又不允许用设备侧操作补齐。**不属于这三类的不进表**：文档明确写了义务的格子归第 4—14 章的层叙述，文档明确写了不适用的格子归能力表的 `not_applicable`。

**编号约定**：本章编号写作 N1—N12，**不补零**，与脚本一第 405、407、409 行那三个补零信号码 `N01`、`N02`、`N03`（告知依据检查）不是同一个东西——本表 N7 会引用那三个码，其余各条引用的都是别的码族。把 `N01` 当成「第一条边界」去 join 会串。

### 26.1 十二条边界

**N1 · 条目级「此刻还能不能查回来」没有读数面。** 缺的是这一格：给定一个 `uniqueIdentifier`，它此刻是否可被某一类发起方查回。公开侧最远读到两处：`A/cssearchableindex.txt:266—272` 的 `isIndexingAvailable` 只回答「这台设备当前能不能索引」，粒度是整台设备；`A/corespotlight_csuserquery.txt:52` 与 `:72—74` 的批次回调只在**命中**那一侧给证据。台账记法：脚本一的 `obs.field_read` 只登记「读回来的是哪一格」，枚举是 `eligibility`／`flag_state`／`item_uid`／`domain_id`／`index_name`／`list_membership`／`usage_notice` 七个加三个控制值（第 90 行），**里面没有「命中与否」这一项**；命中与否只能落在脚本二的 `query_result` 三值 `hit`／`no_hit`／`not_run` 上（第 145 行词形表），且 `no_hit` 必须同现一行「不排除属性请求、最大条数、场景门三个混淆变量」的说明。相关信号：脚本一 `O01`（平面为空或不可判却给「已确认」，第 361 行）、`O04`（拿开发文档当资格位当前取值的读数面，第 367 行），脚本二 `T04`（资格记未授予却登记命中，第 360 行）。**这条边界是整个第 17 章「口径表述而不是状态表述」的来处，也是第 24 章误区 9 的落点。**

**N2 · 面上的存量与域清单不可枚举。** 缺的是「现在这个索引里有几条、分别属于哪些域」。公开侧读到的是**可寻址但不可枚举**：`A/cssearchableindex.txt:100`／`:116`（Obj-C 侧 `:354`／`:356`）按域、按标识符删，说明这两把键存在；但没有任何一份文档给出「列出全部 `uniqueIdentifier`」的接口（第 5.3 节）。台账记法：`obs.list_visible` 是布尔格（第 103 行登记，第 212 行校验形态），只能写 `no`；脚本一没有条目数量字段，「有几条」这个问题在台账里没有格子可填。相关信号：脚本一 `K02`（登记设备侧命令行入口即拒收，第 237 行）、`O03`（把「App 写了哪些索引条目」挂在管理面回报上，第 365 行），脚本二 `P01`—`P05` 平面越界。**把「我数不出来」写成「面上只有 N 条」是越界，脚本判 J4／Q4。**

**N3 · 删除生效没有回执面。** 缺的是五级删除（`A/cssearchableindex.txt:58`、`:100`、`:116`、`:70`、`:88`）的任何一条完成回执：公开侧只写了动作语义（Deletes／Removes）与**写入**侧的异步通知（`A/adding-…:91`），删除侧连异步通知都没承诺。台账记法：唯一合法的三段式（第 14.4 节）——`undo.delete_method` ＋ 发起时刻 ＋ 再一次查询的回读。这里有一处跨脚本形态差必须写清：**脚本一的 `undo.delete_verified` 是布尔格**（`yes`／`no`／`true`／`false`／三个控制值，第 105、212 行），**脚本二的 `delete_verified` 核对项才有 `verified`／`not_verified`／`requery_missing` 三个公开词形**（第 147 行）——同一件事在两支脚本里写法不同，对齐时按对象标识而不是按格名。相关信号：脚本一 `V01`—`V05`（第 373—389 行；`V01` 那句「删除是否发生只能靠再查一次，不能靠推测」就是这条边界的原文），脚本二 `T05`（第 362—365 行：登记已验证但回读是 `no_hit`／`absent`／未登记，或标识与域两格都空）。**后果：本文不允许任何「索引库中已无此条」的表述，只允许间接三段（第 2.5 节、误区 7）。**

**N4 · 「当前场景门开着还是关着」没有编程读数。** 缺的是四道门（锁定、外部智能与 Siri AI、听写/翻译是否出设备、内容过滤与网络结果）在**这台设备此刻**的状态读数。公开侧读到设置路径（`B/siri-dictation-legal.txt:37`：设备会在 Siri 设置或键盘设置里指示内容是否本地处理）与限制键语义句（`B/mdm-restriction-keys.txt:22/23/24/61/70/71/141/143/182/196/197`）；`allowAssistant` 的**配置意图**不等于**设备当前状态**。还有一条容易漏的负口径：`B/mdm-siri-keys.tsv` 写明 `allowAssistantWhileLocked` 在没有密码的设备上被系统直接忽略（脚本一 `B05`，第 305 行——它要求引用这把键却未登记判定基准时阻断）。台账记法：`state.siri_state`、`suggestions_state`、`decided_by`、`decided_at`、`toggle_visible` 五格分别填（第 21 行的命名空间就是这五格），不许用一格 `confirmed` 覆盖五格。相关信号：脚本一 `B01`—`B08`、`G01`—`G05`，脚本二 `P` 族（把条目级可查询性挂在 `settings_ui` 即平面越界）。**第 10.4 节组合表里「该场景不放行」与「检索面不存在」的分别，全部由这一条决定。**

**N5 · 限制键与索引条目之间没有任何公开换算。** 缺的是「关掉 `allowAssistant` 之后，已经写进索引的条目还在不在面上」。公开侧读到：216 个键名（`B/mdm-restriction-keys.txt`，220 行文件）里与检索面有关的只有 11 个（第 13.1 节列全），**这 11 个全是 `allow*`／`force*` 通道开关，没有一个键名含 `index`、`searchable` 或等义写法**；文档也没写关掉之后条目存量怎么走。台账记法：`scope.reach` 不因开关取值改判；要改判必须另填 `gate.owner` 与 `gate.basis`，`mgmt.restriction_key` 的取值必须是 `allow*`／`force*` 形态（脚本一第 233 行 `G02` 的形态检查）。相关信号：脚本一 `G02`（写下「管理面不可清索引内容」却不回指键清单，第 395 行）、`O05`（用「设置面关着」或「清单里看不到」闭合「索引里没有了」，第 369 行），脚本二 `X05`（引用的限制键不在词表内，第 435 行）。**这条是误区 6 与误区 12 的共同来源。**

**N6 · 旧键到声明式类型的接管时刻没有公开口径。** 缺的是「从哪个系统版本起，那 10 个旧 Siri 键不再下发、由 `com.apple.configuration.siri.settings` 给出」，以及「新旧载荷同时存在时以哪一份为准」。公开侧读到：`B/mdm-siri-keys.tsv` 的 10 个键全部标注 Deprecated 并指向该声明式类型；`B/mdm-restrictions.txt:1250` 起给出声明式类型的字段说明。**两份材料都没写切换时刻。** 台账记法：`mgmt.migration_state` 只能取 `legacy_deprecated`／`declarative`／`both`／三个控制值（第 96 行），填 `both` 就意味着同一句限制在该设备上有两个平面来源，必须各自登记；引用旧键的对外结论必须有 `when.state_checked_at`。相关信号：脚本一 `G04`（引用已弃用键并闭合结论却没有核对时刻，第 399 行）、`G05`（受监督登记为否却引用 `Requires supervision: iOS` 的键，第 401 行）。**后果就是第 12.2 节第二条时间不对称：同一句限制在两台设备上的读数平面可以不同。**

**N7 · 检索词离开设备的确切范围没有字段级口径。** 缺的是「哪一类查询串、存多久、存在哪」。公开侧读到类目级三句：`B/legal-siri-suggestions-search.txt:28`（开启后 Safari／Spotlight 里输入的以及通过 Siri 发起的检索会被存储）、`:35`（发送的信息用于处理请求并开发改进 Search）、`:36`（Apple 还可能把**一小份随机抽样的检索词**发给搜索工具用于评测——这一句既没给留存期也没给存储位置）；`B/siri-dictation-legal.txt:38/39` 另给一组请求元数据（请求类别、是否成功完成、设备规格、设备配置、性能统计）与「至多两年」，`B/legal-improve-siri-dictation.txt:34` 补一句「被抽检的一小部分可以超过两年」。台账记法：`scope.field_carried` 只能登记这些页面上写出来的类目名，页面没写的字段一律 `not_recorded`；`doc.notice_basis` 必须指到具体页与行。相关信号：脚本一 `N01`（对外结论、设置面读数或告知页引用未登记告知依据，第 405 行）、`N02`（告知依据记为厂商说法却进入对外结论，第 407 行）、`N03`（用请求侧口径闭合索引侧口径，第 409 行）。**本文不做任何流量观测，也不以任何方式抓取或解密查询文本。**

**N8 · 进入服务端索引的条目没有公开的删除接口。** 缺的是网页标记内容进入 Apple 服务端索引之后，条目级怎么撤、多久失效。公开侧读到：`A/corespotlight.txt:30` 说明用网页标记索引服务器上的内容会进入服务端索引、对所有 iOS 用户在 Spotlight 与 Safari 结果里可用，**同一段没有给删除或过期接口**。对照组是词汇面：`B/apple-platform-security-guide.txt:4261` 是全套文档里唯一一处把远端存量失效条件写明的地方（随机标识符不再使用／用户关掉该 App 的 Siri 集成／App 卸载）。台账记法：`scope.reach` 的合法取值里与服务端有关的两个是 `apple_server_side` 与 `public_all_ios_users`（第 86 行，共五值含控制值），登记它们必须与 `cap.eligible_for_public_indexing` 一致；`undo.*` 六格对服务端存量只能逐格 `not_applicable`。相关信号：脚本一 `D01`—`D05`（第 335—343 行的范围族；`D04` 那句「范围记为全体 iOS 用户可查但用途声明不为已声明：私有本机索引与公开可查询面是两个面」正是这条边界），脚本二 `X06`（挂在公告面或管理面却没有词表标识，第 433 行）。**服务端索引与本机索引是两段口径，不能互相闭合（第 9.1 节、误区 4）。**

**N9 · 「谁读过这条内容」不回写入方。** 缺的是系统 Spotlight、快捷指令与建议面、基础模型这三种发起方的读数回路。公开侧读到：`A/spotlight-search-tool.txt:81` 说明可以把 Core Spotlight 索引开放给语言模型做自然语言查询，`:15` 的 `ContactResolver` 说明人物指向字段可被模型侧解析，而 `A/corespotlight_csuserquery.txt` 的回调只回到发起查询的那段代码。也就是说写入方只能证明「我这次自己查了」，不能证明「别人没查」。台账记法：脚本一的 `op.actor` 有十一个合法取值（第 77 行：`user_typing`、`system_suggestion`、`foundation_model`、`apple_intelligence`、`app_code`、`app_extension`、`mdm_query`、`not_determinable`、`none`、`not_recorded`、`unknown`），第 7.2 节说的四种发起形态分别落在前六项上；脚本二对应的是通道件 `initiated_by` 的五值（第 140 行：`app`／`app_extension`／`system_service`／`user`／`shortcut`），两处的词形表不同名、不同基数。回读能否成立由 `gate.read_back_api` 的八个取值登记（第 83 行）。相关信号：脚本一 `C01`（模型查本机索引却不登记检索工具通道，第 315 行）、`B08`（以 Apple Intelligence 为发起者却不登记请求的属性数，第 311 行）、`O02`（读数挂在设置面却不登记读到哪一格，第 363 行）。**这是第 24 章误区 8 的证据。**

**N10 · 公告的影响句与检索面格位之间没有公开映射。** 缺的是「这条 CVE 落在检索面的哪一格」。公开侧读到：`C/query-plane-17.tsv` 68 行的 `component` 列具名六个组件（Spotlight 26、Shortcuts 16、Siri 15、Apple Intelligence 4、App Intents 4、Help Viewer 3），而同一批 68 行的 `impact` 列对 `index`／`indexing`／`search`／`suggest`／`shortcut`／`Siri`／`Spotlight`／`dictation`／`query`／`consent`／`credential` **十一个检索面词形全部 0 次命中**，只有 `contact` 4 次、`lock` 1 次、`notification` 1 次（第 13.2 节中心读数；影响句去重后只有 9 句，高频写法还分叉）。台账记法：`advisory_component` 只作存在性读数，条目级读数不得引用公告行；引用形态必须是词表里的组件名或 CVE 号。相关信号：脚本二 `X04`（非阻断，第 336 行，本篇累计 5 次）、`X01`／`X02`（引用的 CVE 或组件名不在公开词表内，第 434、436 行）、`X03`（词表自身不可用，第 309、311、312、333 行）。**这条是本篇的中心读数，它本身也是一条边界：存在性可证，格位不可证。**

**N11 · 摘要与优先级生成时条目内容是否离开设备没有口径。** 缺的是「Spotlight 借助 Apple Intelligence 摘要一条消息、邮件线程或音频转录时，这条条目的内容走设备侧还是走私有云」。公开侧读到：`A/generating-summary-….txt:6—11`（可以要求 Spotlight 借助 Apple Intelligence 摘要邮件、消息线程与音频转录，并对 SMS 消息排优先级，结果异步返回）、`:17—23`（**逐条**启用，理由是减少对系统性能与续航的影响）、`:36—39`（类型硬门：只处理 message／email／audio-transcript 三类，其他类型不处理）。**这三段没有任何一段写处理位置。** 台账记法：这一格在两支脚本里都没有对应字段——脚本一的 `scope.*` 只有 `reach`／`sync`／`field_carried` 三格（第 24 行），脚本二 21 项核对项里没有「处理位置」一项，最接近的声明件格子是 `usage_notice`。因此本文只登记「逐条开关」与「类型硬门」这两个形态事实，`scope.reach` 不因「用了 Apple Intelligence」而改判。相关信号：**无。** 这是本表十二条里唯一一条没有脚本码兜着的边界——脚本拦不住任何倾向性表述，拦它的只有本章和第 1.3 节的自我约束。**结论侧本文对这一格不下判断，既不说「不出设备」也不说「出设备」。**

**N12 · 判定本身的可证边界（本表唯一自指的一条）。** 缺的是「台账内容与某台真实设备一致」的证明。公开侧读到：无——这不是文档缺口，而是本文方法的边界。第 23.1 节 P1—P8 八段检查能证明两支脚本没有任何读设备、读网络、读索引库的口子（P1 用六个系统调用型模式跨 944 行找出零命中，P4 列 18 个设备侧命令名只找到 3 处且全在注释与拒收分支里，P6 两份合格夹具跑完后 `ls -d` 两个临时目录通配都报 `No such file or directory`），**但证明不了登记件本身填得对**。台账记法：每一条对外表述前加限定语「按台账」，或在同一行给出 `doc.source` ＋ `doc.line_ref`。相关信号：脚本一 `X01`（缺来源文件或行号，第 412 行——这条判定无法回到公开文档逐行核对）。**这条与第 23.8 节第 7 条是同一件事的两面，也是第 25 章第 1 问末尾那句「不对称」的正式收录处。**

### 26.2 能力表怎么承载这些边界

`FX/capability-17.csv` 的 168 行数据（8 个对象类 × 21 项核对项）里，取值 `undocumented` 的格子**恰好 16 个**，全部落在两项核对项上：`profile_key` 8 个、`restriction_key` 8 个——即 8 个对象类（`cs_index_app`、`cs_index_extension`、`user_activity`、`intent_donation`、`app_entity`、`shortcut_suggestion`、`web_markup`、`system_service`）各自的「管理面两格」。这不是偷懒，而是 N5、N6 两条边界的机器形态：**公开文档既没要求任何一类检索面对象登记配置描述文件键或限制键，也没说这一格对该类不成立**（文档只写了那 11 个键管的都是通道开关，与谁的内容在面上无关）。脚本二对 `undocumented` 的处理是**整格跳过**：既不报覆盖空洞（不进 `D05`），也不报不适用。因此它不会伪造出「补齐管理面两格就能升档」的假指标，但代价是这两格永远不会出现在 Q 档的缺口清单里——**这一代价就是 N5、N6 必须写进本章而不能只留在表格里的那个「为什么」**。

对照看第 25 章第 5 问：全表 required 76、optional 30、not_applicable 46、undocumented 16，四个数相加 168，四条口径定义写在该文件第 11—14 行的注释里（`required` 必须能指到具体文件与行号，指不到就记 `undocumented`；`not_applicable` 要有公开口径明确说这一格对该类不成立，不能当「我不想登记」的写法）。**只有 `required` 参与差集与 `D05` 计数**，所以改 `optional`／`not_applicable` 的口径不会改变档位，把 `undocumented` 改成 `required` 会立刻放大 `D05`——R20 那一次 1,197 条 `D05` 是 42 个对象乘 required 集合的结果，不是「脚本变严了」。

### 26.3 一条固定自查项

**每次把脚本输出交给下游之前，先核对汇总行里的 `词表词条` 是否非 0。** 依据是 R32：把公开词表清空后，脚本二不会因为「比对不了」而全部降级，它打 19 条信号（`X03`=1 且非阻断、`M01`=9、`V02`=9）之后**仍然给出 3 个 `Q1`**，退出码 1。也就是说词表读数的缺失只被削弱、不会被放大成「全 Q4」，而 `词表词条=0` 时那些需要引用词的格子等于没被检查过（N10 那条边界失去它的机器读数）。与它并列的第二条自查是第 23.2 节那条：**退出码 0 只表示这次运行没有阻断信号，不表示输入覆盖了什么**——R33／R34 两次「对象 0、登记行 0、信号 0、四档全 0、退出码 0」是本表 12 条边界同时被绕开的极端形状。

### 26.4 这张表怎么用、怎么改

三条用法：**（1）这 12 条一律不进结论。** 第 1.3 节承诺过「凡是只有厂商承诺、没有公开文档支撑的判断，一律落在第 26 章的未公开文档化边界清单里，不进结论」，本表就是这个存放处；第 27 章的三条结论没有一条落在本表任一行上。**（2）每条边界要求在台账里显式写一个值**——`no`、`not_recorded`、`not_applicable` 或对应枚举里的一个，**留空不等于承认边界**：留空会被 `A01`、`B01`、`X01` 这类「该格未登记」信号计入，反而把对象推到 J3／J4，而 J3／J4 说的是这条登记不成立，不是说这条边界成立。**（3）跨篇引用边界时带上层号。** N1—N5 是条目级边界（第 4—10 章各层的观测缺口），N6—N9 是通路与回路边界（第 9、12、13 章），N10—N12 是证据与方法边界（第 13、17、23 章）。

改这张表的规则只有一条：**新增一个边界，必须同时给出三件东西——一个承担它的脚本码（或一条拒收规则）、一个必填的台账字段、至少一次实跑的 R 号证据。** 给不出脚本码的（如本表 N11）只能在结论里写成「不下判断」，不能写成倾向性表述；给不出 R 号证据的（如本表 N12）只能写成方法论限制，不能写成事实断言。这一规则与第 23 章的覆盖验收同源：**不能触发的信号等于没有写过**，反过来也一样——没有实跑过的边界不该进这张表。



---

## 27. 结论

本篇把「谁把内容写进检索面、谁被允许查回来、锁定前能不能查、查询文本会不会离开设备、谁能删、谁能证明已删」这六个问句拆成十一层与三件法，用两支离线只读脚本把 43 个检索面对象、168 行能力表、721 条公开词表对完。结论按证据强度排序，每条都注明它靠什么成立、靠什么不成立。

**结论一（最强：可复算，且有下界实证）——公开文档给的全是「可寻址、可开关、可告知」三类口径，没有一类给出条目级的当前状态；因此三个归属问句里只有前两个能在台账层面立住，第三个只能是间接三段。** 支撑它的是四处彼此独立的负读数：`A/cssearchableindex.txt:266—272` 的 `isIndexingAvailable` 粒度是整台设备而非条目；没有任何公开接口能枚举面上现有几条、属于哪些域，而 `:100`／`:116` 两把删除入口又证明这些标识**可寻址**——「能删但数不出来」正是这一格的形状；五级删除（`:58`、`:100`、`:116`、`:70`、`:88`）没有一条完成回执，删除侧连写入侧那条异步通知（`A/adding-…:91`）都没有；11 个限制键（`B/mdm-restriction-keys.txt:22—197` 里的 11 行）全是 `allow*`／`force*` 通道开关，**没有一个键名含 `index` 或 `searchable`**。这条结论的证据形式是「四处读数同时为空」，而它的下界由 R21 给出：同一套口径下，一份干净输入退出码 0、8 个对象全判 `Q1`——也就是说这条结论不是「什么都判不过」的悲观读数，而是判得过后仍然没有状态读数。**它不成立的适用范围**：任何关于「某台设备此刻面上有什么」的表述。

**结论二（中强：结构错位，可复算但不决定档位）——公告平面承认检索面存在，却不承认检索面有任何后果；防守流程若按影响文本做关键词筛选，这一整层会 0 命中。** 支撑它的是本篇的中心读数：`C/advisory-17.tsv` 1,266 条、129 个去重组件里，按 `component` 列**全等**筛出 68 条（Spotlight 26、Shortcuts 16、Siri 15、Apple Intelligence 4、App Intents 4、Help Viewer 3，去重 CVE 20 个，跨 8 个平台发布），这批 68 行的 `component` 列明确写着六个具名组件，而 `impact` 列对 `index`／`indexing`／`search`／`suggest`／`shortcut`／`Siri`／`Spotlight`／`dictation`／`query`／`consent`／`credential` **十一个检索面词形 0 次命中**，只有 `contact` 4 次、`lock` 1 次、`notification` 1 次。去重后影响句只有 9 句，高频写法还分叉（`sensitive user data` 44 次 vs `user-sensitive data` 3 次；主语 `An app` 54 次 vs `A malicious application/app` 11 次）。脚本二把这一对读数做成机器版本（自报「检索面具名组件=6 条目级组件名=0」），并由 `X04` 承载——`X04` 是**非阻断**码（第 190—198 行的 39 个阻断码不含它），因为把它设成阻断会让任何引用检索面公告的干净输入都退不出 0，脚本就失去结论一那个下界。**这条结论的分寸**：0 命中是列间错位，不是公告写错，也不是检索面没有缺陷——`component` 列已经承认这六个面存在，本篇不据 0 命中推出任何「影响被隐瞒」的判断。

**结论三（较弱：只能靠台账纪律挡住的换算失败）——这一层最贵的三处错误都不是「写漏了」，而是「把一面的说法当成另一面的结论」。** 三处依次是：把「App 调用过索引 API」当成「这条内容在面上」（`A/adding-…:91` 的异步语义把它拆成发起与落面两格）；把「资格位为真」当成「此刻放行」（`B/nsuseractivity.txt:319—336` 四个资格位互相独立，且第 10.4 节的六种组合里只有两种能完整对外表述，`allowAssistantWhileLocked` 还在无密码设备上被系统直接忽略——脚本一 `B05`）；把「关掉开关」当成「清掉内容」（`B/siri-dictation-legal.txt:72` 唯一一句删除语义删的是**转录**不是索引项，与第 14 章的索引删除是两件不同的事）。三处的共同成因是词表 A、B、C 之间没有任何换算，而两套判定模型的阻断设计不对称恰好说明了为什么不能用单一分数：脚本一在第 113—114 行把全部 63 个码写成阻断（它的汇总行里「信号行数」恒等于「阻断条数」），脚本二只把 39 个码写成阻断、留 8 个作呈现（`S08 D02 D03 D05 X03 X04 V03 V04`）。**合并成一张分数表必然掩盖这件事**：逐条登记载严谨，越容易让三件缺口看起来像已闭合——R20 那一次 42 个对象里 37 个落 `Q2`、`D05` 达 1,197 条，而同样的内容交给脚本一逐格判，问题形状完全不同。

### 27.1 立场

本篇的主张不是「iOS 的检索面不安全」，而是**这条链路的归属表述必须分层持有，缺一格就降级**。写入责任在 App（`A/corespotlight.txt:17`），放行判定在平台，场景门在管理面与用户设置，告知在三份法律页，存在性在公告组件列，删除证明只能由写入方自己拼出间接三段。六段里没有任何一段能替另一段说话，而现有实践普遍把它们的词表混写——第 3.4 节的八处换算失败与第 24 章的十二个误区是同一件事的两个方向。

因此本篇拒绝三类常见做法：**文档摘录式**（把「建议索引你关心或直接交互的内容」这类建议句当限制句用）、**关键词筛选式**（用影响文本筛公告，从而整层漏掉，见结论二）、**实测冲动式**（用 `mdfind` 一类设备侧命令补状态读数，本文红线，见第 2.5 节「没有第四种」与第 24 章误区 10）。

### 27.2 方法论

四步，全部可离线复算：

1. **归档普查**：组 A 开发者文档 15 件、组 B 告知与管理面 10 件、组 C 公告导出 4 件，逐件带行号；所有引用写成 `文件:行` 而不是 `文件`。
2. **三件切分**：把十一层各自的公开口径归到声明件 6 项、通道件 7 项、观测件 8 项（共 21 项核对项），并规定每格的可得性取值（`required`／`optional`／`not_applicable`／`undocumented`）。
3. **两支脚本与覆盖验收**：脚本一逐对象判十一格完整性给 J1—J4，脚本二对三份登记给 Q1—Q4；两支合计 118 个码，用 `FX/codemap.pl` 与 `FX/code-coverage.pl` 做双向差集，确保**每一个码都在 38 段实跑里至少触发一次**——不能触发的信号等于没有写过。
4. **收口**：把换算失败写成误区、把不可证的那十二格单独列成第 26 章的边界清单，让它们有存放处而不是渗进结论。

这套方法的可迁移性不在具体码名，而在两条纪律：**判定与档位的分母必须显式登记**（`undocumented` 整格跳过，不然 `D05` 会被虚增），**呈现与拦停必须分档**（否则中心读数会把干净输入也判成失败）。

### 27.3 三条最小可执行建议

三条都不需要接触设备，也不需要新工具：

1. **把「发起时刻」与「核对时刻」拆成两列。** 台账里凡是写「已索引」「已删除」「已关闭」的格子，都补一个时刻列；两者混写会让异步落面（`A/adding-…:91`）和系统单方面的三种复位（第 14.3 节）在同一条记录上看不出来。对应脚本一的 T 族（`T01`=20、`T03`=29 是两支脚本合计数最高的时刻类信号）。
2. **对外结论必须带一个可回指的引用。** 每条对外表述配 `doc.source` ＋ `doc.line_ref`，指不到就把这一条降级为「不下判断」，而不是留空。对应脚本一 `X01`（累计 79 次，是脚本一 X 族唯一的码，也是除 `A01`＝82、`J4`＝81、`B01`＝80 之外累计最高的一个）。
3. **评审清单里加一条固定自查。** 先核对汇总行的 `词表词条` 是否非 0，再确认 `exit 0` 只表示「本次无阻断信号」而不是达标——38 段实跑里退出码 0 出现 8 次，其中 4 次是空输入与只有注释的输入（R33／R34 连一个对象都没判）。这两条是第 26.3 节与第 23.2 节的直接产物。

一句话收尾：**这条链路上，「谁能查回来」与「谁能删干净」可以按台账表述，「谁能证明已删」永远只能是一段带时刻的间接三段——把这三件事写成分开的三格，就是本篇的全部工程主张。**



---

## 28. 参考资料

本轮存档：`.srcx17/`（取回日期 2026-11-02；七个归档目录共 **95 个文件 / 4,225,698 字节**，分组为 `A/` 15 件 / 119,593 字节、`B/` 10 件 / 819,044 字节、`C/` 4 件 / 281,729 字节、`RAW/` 25 件 / 1,772,694 字节、`tools/` 12 件 / 122,000 字节、`FX/` 26 件 / 799,651 字节、`IDX/` 3 件 / 310,987 字节）。同级的 `DOC/` 与 `PART/` 是本章成文之前的分章草稿中间件与装配切片，不属于公开存档，也不计入这份清点。索引三件：`IDX/sources-17.md`（88 行，逐件登记归档路径、来源 URL 与关键锚点，正文所有「见《某文档》第 N 行」的行号以它为准；文件头部另登记两条抓取陷阱——Apple 文档 JSON 统一走 `https://developer.apple.com/tutorials/data/documentation/<slug>.json`，HTML 页为 JS 渲染不能直接文本化；**404 会返回一个 15,639 字节的同形错误 JSON**，所以每次抓取要同时核对 `http=200` 与字节数）、`IDX/overlap-17.md`（50 行，主键选择依据、与前十六篇的逐篇分界、语料可行性预检与本篇的拒收口径／红线清单）与 `IDX/cite-17.txt`（2,701 行，正文与两支内嵌脚本里每一处行锚的逐条落点索引，由 `tools/cite-index-17.pl` 在正文装配完成后运行生成，判据与末次读数见下面第 37 条）。全部为公开文档，离线取回；**本轮未访问任何设备、未调用任何设备侧或 Apple 命令行工具（不执行 `mdfind`、`mdls`、`mdimport`、`mdutil`、`spotlight`、`profiles`、`sysctl`、`xcrun`、`defaults`、`log`、`siriscreencapture`）、未导出或解析任何设备侧索引数据库、未构造任何快捷指令或意图捐赠、未做绕过锁屏检索／屏幕使用时间／专注模式限制的操作、未采集语音样本或声纹、未抓取或解密任何检索词、未关闭或伪装任何隐私提示、未规避任何管理面审计**。两支内嵌脚本的输入只有台账文本文件，运行期间不联网、不碰设备（只读性八项检查见第 35 条）。

### 索引面与检索面文档（A 组 15 件 / 119,593 字节 / 4,826 行）

1. **Core Spotlight 框架页**（`A/corespotlight.txt`，180 行）：本篇主键的公开口径来源，也是行锚最密集的一件。承重行按第 4—14 章的顺序是——第 3 行框架目的句；**第 15 行 "Spotlight File Import extensions don't provide functionality in macOS."**（同一种装配形态在不同平台上可查面不同，L1 的唯一平台差异）；**第 17 行 "Your app is responsible for indexing your app's content and maintaining those indexes."**（写入责任归属，第 4.1 节的第一句）；第 18—19 行两个写入时机（App 运行时，或由省下的 App 扩展在系统请求时索引）；第 19—21 行可索引范围（含当前没在显示的文件与其他内容）；**第 22—23 行 "The indexes you create using Core Spotlight remain on device, and are private to the owner of the device. Devices don't share indexed data with Apple, or synchronize that data with the person's other devices."**（L6 服务端边界的第一条，与第 30 行是一对必须同时引用的句子）；第 26—27 行「加入设备侧索引，并可选择标识条目是否适合公开索引」；**第 30 行 "Use web markup to index content on your web server in Apple's server-side index, which makes the data available to all iOS users in Spotlight and Safari search results."**（全篇唯一一处「内容进 Apple 服务端索引」的公开口径，第 9.1 节与第 26 章 N8 的落点）；第 73 行「App 可搜索内容的设备侧索引」；第 77 行 delegate／扩展协议句；第 133 行摘要与优先级条目。
2. **《把 App 内容加入聚焦索引》**（`A/adding-your-app-s-content-to-spotlight-indexes.txt`，234 行）：写入侧的操作文档，本篇把它当**义务件**而不是教程件使用。第 6—7 行检索的角色句；第 11—12 行「建私有设备侧索引并把数据加进去」；第 13—15 行建议索引范围（收藏、已购、收发过的消息）；第 18—19 行「在用户发起的活动上启用该属性会把活动加入设备侧索引并进入后续检索」（与第 8 章的捐赠分开登记）；第 60—61 行保持索引最新的义务；第 62—63 行高参与度提升条目排序；**第 67—72 行「系统按期自动过期条目；设定到期日可保留到指定日期；如果这个人从 App 里删除了原始数据，就把索引里的关联条目一并移除」**（本篇唯一一条把「删原始数据」与「删索引项」写在同一句的义务句，第 14.1 节与 `D` 族判据）；第 75 行「索引存的是 App 专有数据并留在设备上」；**第 76—79 行多索引分法**（主索引放通用目录、私人歌单放单独索引）；**第 80—82 行「需要索引更敏感的数据（例如联系人信息）就创建更安全的索引」**；**第 86—88 行与 `A/cssearchableindex.txt:25` 两次明令默认索引只能用于原型与测试**；第 91 行「异步并入索引并在完成时通知」（失败点 1 的落点）；第 93 行提交条目以延长过期日；**第 95—96 行「提供再索引 App 扩展，使索引在 App 未运行时也能保持最新」**；第 119—128、142—156 行装配步骤（`FX/capability-17.csv` 的口径注释第 3—4 行即引用这两段）；第 157、164—166、169 行 `protectionClass`／`FileProtectionType` 与 `initWithName:protectionClass:`；第 177、181 行 `expirationDate`；第 206 行「指示是否把该活动加入设备侧索引」的布尔位。
3. **`CSSearchableIndex` 页**（`A/cssearchableindex.txt`，393 行）：索引对象的接口面，本篇「五级删除粒度」与「唯一一处设备侧可用性读数」都出自这一件。第 3、10—11 行对象定义；**第 16—17 行「执行查询时 Core Spotlight 在索引里检索请求的信息并把结果返回给代码」**（接口口径的样板句，第 2.5 节列的第一条）；**第 18—21 行「生产代码用自定义索引而不是默认索引；自定义索引支持数据保护，可加密并防未授权访问」**；第 22—24 行批量操作与自定义状态（App 或扩展崩溃后可重启索引过程）；**第 25 行「默认索引只在测试或原型阶段使用」**；**第 26—28 行「一次只从一个线程或任务改，且只从已签名的 App 或扩展改；多线程同时访问自定义索引或从未签名 bundle 访问是编程错误」**；第 50 行返回默认索引；**第 58/352 行 `deleteAllSearchableItems`「Deletes all searchable items from the index」**；**第 70/354—356 行按实体标识与类型删除、按域删除、按标识符删除**；第 88 行按实体类型全量删除；**第 100 行按域删除**；**第 116 行按标识符删除**；第 242 行按名取索引；第 251/263 行按名与保护等级取索引；**第 266—272 行 `isIndexingAvailable`「返回一个布尔值，指示当前设备上索引是否可用」**（全篇唯一一处设备侧读数，且粒度是整台设备——第 6.3 节与第 26 章 N1 的根据）；第 274—277 行 `protectionClass`；第 283 行 delegate 协议；第 294—297 行 `AppEntity`（索引对象直接挂接 App 实体的那一格）；第 302 行加入设备侧索引的布尔位；第 348/350/357/359 行 `beginIndexBatch`、`defaultSearchableIndex`、`endIndexBatchWithClientState:`、`endIndexBatchWithExpectedClientState:newClientState:`。
4. **`CSIndexExtensionRequestHandler`／再索引 delegate 协议页**（`A/corespotlight_cssearchableindexdelegate.txt`，210 行）：第 3、26 行协议定义句；**第 13 行「长驻或批量更新索引的 App 应在 delegate 对象或 App 扩展里实现必需方法」**；**第 76 行 "Tells the delegate to reindex all searchable data and clear all local state information."**（系统可单方面要求重建并清掉 App 本地状态，第 4.3 节与第 14.3 节据此判定「先前所有观测读数在重建后失效」）；第 82/87、94/103 行两个回调的 Swift 与 Obj-C 名；**第 88 行按标识符再索引**；第 166 行摘要与优先级；第 192—194 行两个回调完整签名；第 19—25 行与 `CSSearchableIndex` 的关联条目。
5. **《在 App 内检索信息》**（`A/corespotlight_searching-for-information-in-your-app.txt`，372 行）：L4 属性层的全部三条句子。第 6 行副题；**第 7—9 行「不要自建搜索工具，用 Core Spotlight API 索引内容并用框架提供的查询取回信息」**；第 9—10 行「索引后的内容同时对自己的 App 与系统 Spotlight 可用」；第 13—15 行「在查询对象上指定要匹配哪些属性、什么值构成匹配」；**第 22—24 行「执行查询时系统不会自动取回每个属性，只取回明确请求的属性」**（本篇属性请求制的核心句，脚本一 `C` 族与脚本二 `attributes_requested` 判据）；第 29—30 行要标题与显示名就得把 `"title"`／`"displayName"` 两个字符串列进去。
6. **《为 App 搭建检索界面》**（`A/corespotlight_building-a-search-interface-for-your-app.txt`，258 行）：与上一件配对，用来证明「谁发起查询」与「谁决定取回哪些属性」是两个动作。检索界面装配、建议列表与结果渲染的段落都在这一件里；本篇不引用其界面细节，只引用它与第 5 件的分工。
7. **`CSUserQuery` 页**（`A/corespotlight_csuserquery.txt`，288 行）：第 6、50、63、67 行是能力表口径注释的引用来源；**第 13—16 行「与 App 的检索界面组合，对人输入的检索词做词汇与语义检索；可配置为返回排序或不排序结果；也可用来取一份建议列表」**；第 18—21 行「一个查询对象只用一次；上一个查询仍在进行时要取消旧查询」；第 24—29 行用 `CSSearchQueryContext` 配置查询参数；**第 35—41 行「每次查询一直跑到返回所请求的最大结果数；不指定最大数就一直跑到返回全部结果」**（`max_results` 必须独立列一格的依据，也是 `D05`／`Q2` 这类高频信号的来源）；第 52 行批次回调；第 61、63—64 行行为配置；第 65 行「查询中使用的建议种类」；第 72—74 行结果对象。
8. **Spotlight 检索工具页（基础模型侧）**（`A/spotlight-search-tool.txt`，82 行）：第 3—4 行「让 App 已索引的内容作为附加上下文供系统基础模型回答提示」；第 6—11 行工具与 `CoreSpotlightSource` 的关系与可配置项；**第 15 行 `ContactResolver`「帮助基础模型解析对使用该 App 的人的引用」**（人物指向可被模型侧解析，第 12.3 节要求单列一格）；第 19/21 行 `CoreSpotlightSource`；第 27/29—30 行 `FileSource`（从 Spotlight 可见的文件与目录取已索引元数据）；第 31/33 `ResolvedContact`；第 35/37 配对相关度分值；第 39/41 `SearchCount`；第 43—65 行管线数据类型、表格、来源、统计与摘要各格；**第 71/73 行 `SpotlightSearchTool`**；第 75/77 `Configuration`；**第 81 行「让语言模型访问你的 Core Spotlight 索引，从而对可搜索内容做自然语言查询」**。
9. **《为已索引条目生成摘要与优先级》**（`A/generating-summary-and-priority-data-for-indexed-items.txt`，240 行）：第 3—4 行标题句；**第 6—11 行「邮件、消息或音频转录类 App 可要求 Spotlight 借助 Apple Intelligence 摘要内容，也可要求它对 SMS 分类优先级；结果异步返回」**；第 12—15 行 App 用摘要与优先级增强自己的界面；**第 17—23 行「只为你指定的对象返回摘要与优先级数据……要求逐条启用生成，以减少对系统性能与续航的影响」**；第 22—23 行可只对邮件内容启用；第 24—26 行为每个条目更新属性数据；**第 36—39 行「该类型必须是 message／email／audio-transcript 类型，Apple Intelligence 不处理其他类型的条目」**（属性层里唯一一处类型硬门；第 26 章 N11 的「处理位置无口径」正是这一件没有写的那一格）。
10. **App Intents 框架页**（`A/appintents.txt`，107 行）：第 3 行「让内容与动作可被 Apple Intelligence 发现，并支持 Siri、Spotlight、快捷指令与小组件」；第 6—9 行动作与数据外溢句；**第 10—11 行「用结构化方式表达 App 的动作与数据，使其可被 Apple Intelligence 发现」**；第 12 行「人们可通过 Siri 与 App 内容交互」；**第 13 行「Spotlight 帮助人们直接从检索结果导航到你的数据」**；第 14 行快捷指令工作流；第 49 行是能力表注释引用的实体口径。
11. **`AppEntity` 协议页**（`A/appintents_appentity.txt`，227 行）：第 3 与 57 行「让自定义类型或 App 专有概念可被 Apple Intelligence 与 Siri／快捷指令发现」；**第 5—18 行协议约束 `AppValue`／`DisplayRepresentable`／`Identifiable`／`EntityIdentifierConvertible`**（既需能展示也需能标识，才可能被系统侧检索——L8 层可发现性的判据）；第 1、186 行是能力表 `Q4` 档注释引用的两行。
12. **`SearchableItem`（Swift 值类型）页**（`A/searchableitem.txt`，30 行）：第 3、12 行「代表一条 Spotlight 检索结果的 Swift 值类型」；第 16—19 行示例；**第 20—21 行「线程安全类型，其值可在任意并发上下文中共享而不引入数据竞争」**；第 22—27 行 `Sendable`／`SendableMetatype`。这一件只有 30 行，但它与第 3 件第 26—28 行的并发口径配对，构成「并发限制按对象分层」的读数。
13. **`CSSearchableItem` 页**（`A/cssearchableitem.txt`，381 行）：L2 声明层的身份三元组全部写在构造器签名里。第 3—4 行「某人可能在设备上检索的 App 内容详情」；**第 12—19 行「条目唯一标识 App 内容的一部分，并提供 Spotlight 索引与后续查找所用的元数据；随后可用 Core Spotlight API 执行查询找到你索引过的条目，人们也可以用系统的 Spotlight 检索界面找到 App 的内容」**；**第 36—37 行「如果你删除了内容，也要相应从索引里删除可搜索项；保持索引最新能确保检索返回有效信息」**；第 122/124 行 `domainIdentifier`「可选、代表条目所属域或所有者」；**第 129/131 行 `expirationDate`「该日期之后此条目应当不再存在」**；第 195 行属性集关联；第 208 行 **`initWithUniqueIdentifier:domainIdentifier:attributeSet:`**；第 209—212 行 `isUpdate`；**第 216/218 行 `relatedAppEntityIdentifier`**；**第 222/224 行 `uniqueIdentifier`「在 App 内唯一标识该条目」**；第 228—230 行 `updateListenerOptions`「向 Spotlight 请求哪几类通知」；**第 242/244 行 `CSSearchableItemActivityIdentifier`「在用户活动对象里访问某条可搜索项所用的键」**。
14. **`CSSearchableItemAttributeSet` 页**（`A/cssearchableitemattributeset.txt`，1,746 行 / 28,340 字节）：本篇最长的一件属性承载面，第 7.3 节那张「人物／时间／展示／类型」四类字段表逐条来自它。第 3 行「可搜索项的详细元数据」；**第 299 行 `contactKeywords`**；**第 346 行「文件内容最后修改的日期」**；第 418/422/1584 行 `creator`；第 446、830 行是能力表注释引用的两格；**第 1227 行「表示内容创建者的角色」**。它的体量本身就是读数：一个条目可携带的字段数量级远大于任何一次查询会请求的属性数量，因此「存了什么」与「这次能看见什么」必然分属两件（第 3.4 节失败点 3）。
15. **《按需重新生成 App 的索引》**（`A/regenerating-your-app-s-indexes-on-demand.txt`，78 行）：复位路径的专件。第 6—11 行「保持索引最新需要周期性维护；**App 在更新索引时崩溃可能把索引留在不正确状态**；系统也可能在索引缺失或需要更新数据时要求 App 重新生成；如果系统在需要这些更新时 App 没在运行，就改用再索引 App 扩展」；第 12—14 行扩展必须能访问 App 全部可索引数据；第 25—30 行为关键索引函数调用确认处理器。第 14.3 节的三种复位路径中有两种出自这一件与第 4 件。

### 告知面、控制面与管理面（B 组 10 件 / 819,044 字节 / 7,858 行）

16. **Ask to Siri & Dictation 法律页**（`B/siri-dictation-legal.txt`，154 行，原始 HTML `RAW/siri-dictation-legal.html` 116,388 字节）：L6 与 L11 两层的主要来源。第 28 行「Siri 请求不与 Apple Account 关联；像播放某张专辑或检索世界知识这类 Search 请求，其查询串也会被 Apple 存储并用于改进 Search、Siri 与相关功能，可在设置里关掉 Help Apple Improve Search」（一句话里同时给出关联标识与检索词留存，第 26 章 N7 的核对对象）；第 31、33 行请求处理位置与 **Siri AI 分叉**（启用后可能在设备上处理也可能发往 Private Cloud Compute，PCC 处理的数据不存储、Apple 访问不到、不使用设备上 App 的信息；不启用则尽可能在设备上处理并可能提供 Search 的最新信息）；第 34—37 行设备侧指示「你说的内容是在设备上处理还是发送给 Apple」；第 38 行另存请求类别、是否成功完成、设备规格、配置与性能统计；**第 39 行「这些属于 Siri 与听写请求历史的一部分，Apple 可保留并使用至多两年」**；第 41、48—49 行使用与改进；第 58 行「允许 App 使用语音识别做转录时，待转录的音频数据可能发送给 Apple」；第 63—65 行建议面口径，含 **第 64—65 行「Suggestions 使用本地设备侧处理……可用于个性化 Apple 服务，但不存储在 Apple 服务器上，也不与其他第三方 App 共享；运行 Siri 建议的快捷指令时受该 App 的条款约束」**（两句必须一起引用）；**第 72—73 行「关掉 Siri 与听写之后，设备上存储的、用于个性化体验的转录会被删除」**（用户侧唯一的删除语义，且删的是转录不是索引项——第 11.3 节第十二个误区的出处）；第 76/80/81/82 行逐 App 建议开关与定位系统服务路径；第 100 行政府信息请求。
17. **Siri Suggestions & Search 法律页**（`B/legal-siri-suggestions-search.txt`，124 行，`RAW/legal-siri-suggestions-search.html` 108,245 字节）：第 28 行「让你进入 Safari 与 Spotlight 的检索词以及通过 Siri 发出的检索被存储以改进 Search」；第 30 行「Search 旨在保护你的信息并让你选择分享什么」（L6 总口径）；第 31—36 行发送与不关联、使用与改进、聚合信息再用于其他产品、**随机抽样的一小部分检索词**；第 37—42 行向战略伙伴提供的非个人数据；第 44—47 行 Safari 引擎建议与 Preload Top Hit、视觉智能用私有云与私有信息检索使 Apple 不知道图像内容、位置分发；**第 49 行「不想让检索词被 Apple 存储并用于改进 Search，可到 设置 > Search 关闭 Improve Search」**（告知口径的标准落点，第 2.5 节列的第三种形态）；第 50 行关闭 Show Recent Searches 与 Show Related Content；第 51 行定位服务路径；第 52、54 行可信第三方服务提供者处理与存储与页面日期 2026-10-30。
18. **Improve Siri & Dictation 法律页**（`B/legal-improve-siri-dictation.txt`，118 行，`RAW/legal-improve-siri-dictation.html` 107,849 字节）：可选加入面的留存口径。第 28/30 行存的是「对 Siri、听写与翻译说的内容，包括音频与文本以及 Siri 的回复」；第 32—33 行「Apple 可能存储全部交互」；**第 34 行「留存至多两年，但被抽检的一小部分可以超过两年」**（与第 16 件第 39 行的「两年」不是同一口径，第 11.3 节的硬口径两条之一）；第 35—36 行不用于建营销画像、不出售；第 38—39 行抽检用于判定准确度；**第 40 行「关闭即删除设备上存储的转录」**；第 41 行 ChatGPT 扩展；**第 43—44 行「翻译请求留存至多两年」**（第三条独立留存上限）；第 46—48 行首设选择继承到新连接设备与同意条款。
19. **支持文档 127070**（`B/support-127070.txt`，77 行，`RAW/support-127070.html` 165,299 字节；另有 `RAW/supp-.html` 104,979 字节是同页早期抓取残件，未进入 `B/` 派生集）：设置路径的唯一公开件。第 20 行「新设备首次开启 Siri、听写或翻译时会被询问是否加入 Improve Siri & Apple Intelligence」；第 21—24 行各端继承口径（Apple Watch／HomePod／Apple TV 跟随首设 iPhone）；**第 28—30 行 iOS 路径 隐私与安全 > 分析与改进 > 开关**；第 32—34、36—38、40—43、45+ 行分别是 macOS、watchOS、HomePod（由 Home 组织者经 Home App 调整）与 Apple TV 的路径。L7 场景门与 L11 用户侧删除的「怎么走到那一格」全部由这一件给出。
20. **`NSUserActivity` 页**（`B/nsuseractivity.txt`，609 行，`RAW/nsuseractivity.json` 104,231 字节）：L3 资格层四个资格位与 L8 活动捐赠的读点。第 14 行「例如 Handoff 与 Quick Notes」；**第 34 行「启用你的活动支持的特性，例如 Handoff 与 Spotlight 索引」**；第 39—40 行「Handoff 与其他特性在当前活动上运作并把它当行为上下文」；第 46 行「要让 Handoff 生效，系统需要知道它可以把哪几类活动交付给你的 App」；第 71 行是能力表注释引用的关联条目；第 230/241 行 **`deleteSavedUserActivitiesWithPersistentIdentifiers:completionHandler:`**（按持久标识删除已保存活动）；**第 249/251 行 `expirationDate`「该日期之后此活动不再具备 Handoff 或索引资格」**（四格里唯一一处「一位变动由时间触发」）；**第 301 行 `invalidate`「使活动失效并标记不再具备继续资格」**；第 313/315 行 `isEligibleForHandoff`；**第 319/321/324 行 `isEligibleForPrediction`「决定 Siri 能否把该活动建议为快捷指令」**；**第 325/327/330 行 `isEligibleForPublicIndexing`「该活动是否对全体 iOS 用户公开可访问」**；**第 331/333/336 行 `isEligibleForSearch`「是否把该活动加入设备侧索引」**；第 337/339 行 `keywords`；第 379/381 行 `requiredUserInfoKeys`；第 388/390 行与 `resignCurrent`「标记为非活动但不使其失效」；第 578—581 行是能力表注释引用的段落。四个资格位各自独立、互相不换算，是第 3.1 节词表 A 的第四行。
21. **Intents 框架页**（`B/intents.txt`，131 行，`RAW/intents.json` 39,988 字节）：第 3 行「让人在其设备上定制与该 App 的交互」；**第 5—6 行「SiriKit、Intents 与 IntentsUI 继续为快捷指令动作、小组件配置与既有 Siri 交互提供遗留支持；要实现现代支持并与 Apple Intelligence、Siri AI 集成，请改用 App Intents 框架」**（迁移状态读数，`mgmt.migration_state` 的框架侧对照）；**第 7—8 行「定义自定义意图，并捐赠意图以帮助 Siri 随时间学习用户习惯并建议相关快捷指令；还可提供出现在快捷指令 App 或 Siri 推荐中的快捷指令建议以提升可发现性」**；第 9 行 SiriKit 按 App 类型分域；第 30、33—34 行是能力表注释引用处。
22. **MDM 限制键全集**（`B/mdm-restriction-keys.txt`，220 行 = **216 个键名** + 结构行，由 `tools/names.pl` 从 `RAW/mdm-restrictions.json` 的 `"name"` 字段抽全、去重、排序）：L10 管理面唯一形态的完整输入。**「220 行 / 216 键」是正文与台账一律写 216、不得写 220 的固定差。** 检索面相关的 11 个键在第 22（`allowAssistant`）、23（`allowAssistantUserGeneratedContent`）、24（`allowAssistantWhileLocked`）、61（`allowDictation`）、70/71（`allowExternalIntelligenceIntegrations` 及其 `SignIn`）、141（`allowSiriAI`）、143（`allowSpotlightInternetResults`）、182（`forceAssistantProfanityFilter`）、196/197（`forceOnDeviceOnlyDictation`／`Translation`）行。**这 11 个键没有一个含 `index`／`searchable`／`spotlight-index` 或等义写法，全部形如 `allow*`／`force*`**——本篇管理面负空间读数的机器可复核形态（第 13.1 节，与第 16 篇「220 键里没有 Bonjour／Multicast／Peer」同构但结论相反）。
23. **Siri 相关限制键的键名—说明配对清单**（`B/mdm-siri-keys.tsv`，10 行 = 表头 + **10 个旧键**，由 `tools/mdm-key-desc.pl` 从同一 JSON 逐条配对「键名 → 说明 → 监督口径」）：`allowAssistant`「If false, the system disables Siri」；**`allowAssistantUserGeneratedContent`「the system prevents Siri from querying user-generated content from the web」（Requires supervision: iOS｜watchOS）**；`allowAssistantWhileLocked`「锁定时禁用 Siri」；其余键逐条标注 **Deprecated** 并迁往 `com.apple.configuration.siri.settings`。这一件承载的是「同一句限制在不同版本上由哪个平面给出」的迁移状态，是 `G04`／`G05` 两个信号的公开依据。
24. **MDM `Restrictions` 载荷文档全文**（`B/mdm-restrictions.txt`，1,530 行，同 JSON 经 `tools/jsondump.pl` 文本化）：键说明侧的落点。第 96 行 Siri 关闭；第 104 行 Siri 不得查询用户生成内容；第 112 行锁定时禁用 Siri；第 294 行禁用听写；第 356 行外部云端智能；第 780 行 Apple Intelligence 集成；**第 796 行 Spotlight Internet 结果**；第 979 行脏话过滤；第 1063 行听写不连 Siri 服务器；第 1071 行翻译不连 Siri 服务器；**第 1243、1250、1252、1254、1256、1298、1338、1385、1406、1449 行 `com.apple.configuration.siri.settings` 声明式接管位置**（第 10 章门 1—4 的说明句与第 13.1 节的迁移段都指这里）。
25. **Apple Platform Security 中文版底稿文本**（`B/apple-platform-security-guide.txt`，4,885 行 / 697,288 字节，与 `.srcx10`—`.srcx13` 使用的同一版本副本，本篇不重复抓取，`.srcx17/RAW/` 里没有它的原始件）：本篇只取两处。**第 2749、2750—2752 行「iCloud.com 上的搜索让 iCloud 网页应用从网页会话搜索用户已同步的 iCloud 文件，**这种搜索使用用户 iPhone／iPad／Mac 上的本地索引，使 iCloud.com 无需在 iCloud 服务器上提供一份索引**」+ 四条保护（多层加密认证、会话绑定、用户同意，**没有用户明确选择加入就不会在设备上执行任何搜索查询**，除非设备独立授权否则不返回结果）」；第 2759—2762 行「网页浏览器与授予索引访问的设备之间需要建立**密码学配对键**；握手成功前设备不处理任何搜索请求；浏览器周期性向 Apple 服务器请求令牌，确认该会话登录了同一 Apple 账户且与配对键绑定」**；**第 4261 行「支持 SiriKit 的 App 可向 Siri 发送 App 特定或用户特定的词汇……与一个**随机标识符**关联；这些自定义信息在该标识符使用期间保持可用，或者直到用户在设置里关掉该 App 的 Siri 集成，或者直到这个 App 被卸载」**。第 2749—2762 行是全套公开文档里唯一一处「设备侧索引被远程查询」的成文口径；第 4261 行是唯一一处「检索面相关的远端存量有明确失效条件」的口径，同时给出 L6 的留存终止三条件与词汇面／属性面必须分格的理由。

### 公告子词表与索引可删性口径（C 组 4 件 / 281,729 字节）

26. **安全发布聚合词表**（`C/advisory-17.tsv`，1,267 行 = 表头 + **1,266 条记录**；列 `file / platform / component / cve / impact / avail`）：为第 17 篇自包含而从 `.srcx16/C/advisory-16.tsv` 复制，`cmp` 逐字节相同；原始出处是 12 篇 Apple 安全发布页面，由 `tools/adv-parse.pl` 解析 `.srcx16/RAW/adv-*.html`（文本化件在 `.srcx16/C/pages/adv-*.txt`，`file` 列沿用上次解析时的相对命名）。各发布条数 134/1/1/163/263/213/197/72/62/125/33/2（合计 1,266），`component` 列去重 **129 个组件名**，唯一 CVE **330 个**。本篇不使用 `RAW/` 里的公告 HTML——公告平面的读数一律从这份 TSV 出发，以保证第 13.2 节的每个数字都能用一条 `awk` 复现。
27. **检索面公告子集**（`C/query-plane-17.tsv`，69 行 = 表头 + **68 条**；按 `component` 列**全等**匹配 `{Spotlight, Siri, Shortcuts, App Intents, Apple Intelligence, Help Viewer}` 筛出，复现命令记在 `IDX/sources-17.md` 的「复现命令（离线，只读）」段）：组件分布 Spotlight 26、Shortcuts 16、Siri 15、Apple Intelligence 4、App Intents 4、Help Viewer 3；去重 CVE 20 个（Siri 7、Spotlight 6、Shortcuts 3、Apple Intelligence 2、Help Viewer 1、App Intents 1）；平台发布分布 8 项（macOS Sequoia 15.8.2 13、macOS Tahoe 26.7.2 12、macOS Golden Gate 27.2 12、iOS/iPadOS 27.2 9、visionOS 27.2 7、watchOS 27.2 6、iOS/iPadOS 26.7.2 5、tvOS 27.2 4）。**组件名一律全等匹配、不做子串匹配**（`Siri` 按子串会误吞 `SiriKit`），本批 129 个组件名里不存在这类复合名，但口径仍写死以防复用错判。
28. **子集统计输出**（`C/query-plane-17-summary.txt`，37 行）：第 27 件的统计留档，四节分别是子词表命中、每组件去重 CVE、平台发布分布、全量对照。**中心读数出自第一节末段——把这 68 行只取 `impact` 列做不区分大小写子词计数，`index`／`indexing`／`search`／`suggest`／`shortcut`／`Siri`／`Spotlight`／`dictation`／`query`／`consent`／`credential` 十一个词形全部 **0** 次命中，只有 `contact` 4、`lock` 1、`notification` 1。** 同一批行的 `component` 列却明确写着 Spotlight／Siri／Shortcuts（合计 68）。影响句去重后只有 **9 句**，且高频写法分叉（`sensitive user data` 44 次 vs `user-sensitive data` 3 次；主语 `An app` 54 次 vs `A malicious application/app` 11 次），这是脚本二的匹配器必须容错、并把 `X04` 设为非阻断的直接原因。第四节的对照列出被排除的相邻平面（`Model I/O` 43 行、`Apple Neural Engine` 10 行、`Screen Time` 3 行），第 13.3 节的划界据此写成，脚本二的公开词表也不加载这些组件名。
29. **索引可删性读数汇编**（`C/index-removal-readings.md`，61 行）：组 A／B 归档的行级回查留档，四组读数各对应一章——① App 侧删除权（五级删除粒度、两条义务句、`expirationDate`、活动侧两把、再索引回调）＝第 14.1 节；② 用户侧只有开关级删除（法律页四段路径 + PSG 第 4261 行）＝第 14.2 节；③ 管理面 10 个旧键全部为「关闭通道」而非「清索引」且整层标注 Deprecated＝第 13.1 节；④ 云端边界四处独立表述（框架页第 22—23／30 行、活动公开资格、建议面个性化、PSG 第 2749—2762 行）＝第 9.1 节。第 26 章 N3、N8 两条边界的「公开侧读到哪」一格逐条取自这一件。

### 原始抓取件与派生器（`RAW/` 25 件 / 1,772,694 字节 · `tools/` 派生与制表 7 件 / 7,451 字节，另有两支内嵌脚本 86,931 字节与下面第 37 条的三件校验器 27,618 字节）

30. `RAW/` 存**未加工的抓取原样件**：**20 件 JSON**（组 A 的 15 个文档页各一件，另含 `corespotlight_csssearchableindexdelegate.json` 与 `corespotlight_cssuserquery.json` 两个 **15,639 字节的 404 同形错误件**——它们留在存档里正是为了让「slug 猜错时会拿到同尺寸的错误 JSON」这条陷阱可被复核）+ **5 件 HTML**（三份法律页、`support-127070.html` 与早期残件 `supp-.html`）。`A/`、`B/` 下的 `.txt` 全部由它们派生；`B/apple-platform-security-guide.txt` 与 `C/` 四件不在本目录派生（前者沿用 `.srcx10`—`.srcx13` 同版本副本，后者沿用 `.srcx16` 已解析件），这两处跨轮次复用已在 `IDX/sources-17.md` 与上面第 25、26 条就地标明，避免读者按「每篇都有原始件」的假设去找不存在的文件。
31. `tools/` 七件派生与制表器，全部只读输入、写 stdout：`jsondump.pl`（46 行，Apple 文档 JSON → 行式可 grep 文本）、`html2txt.pl`（47 行，HTML → 行式纯文本）、`names.pl`（14 行，从 JSON 的 `"name"` 字段抽限制键全集、去重、排序）、`mdm-key-desc.pl`（45 行，限制键 → 说明 → 监督口径的成对导出）、`adv-parse.pl`（34 行，公告文本 → 六列 TSV，结构假设为「组件名行紧接在 Available for: 之前，随后是 Impact／Description／CVE」）；另有两件正文档落生成器：`table17.pl`（22 行，用法 `perl tools/table17.pl <FX/mapN.txt> <输出> <R 起始号>`，把「码 → 首现实跑号 → 累计命中」渲染成第 23.3 节两张九列表，`PART/tbl1.md` 起始号 R1、`PART/tbl2.md` 起始号 R20）与 `runsum17.pl`（34 行，用法 `perl tools/runsum17.pl <日志> <脚本名> <R 起始号>`，从两份日志抽取每次实跑的标签、命令行要点、脚本自打汇总行与 `exit=`，生成第 23.2 节的 38 段总表）。

### 本轮产物（自写，只读处理公开存档文本）

32. **脚本一 `tools/query-plane-ledger-review.sh`（442 行 / 45,381 字节，67 个信号码 = 63 条信号 + 判定档 `J1`—`J4`；阻断集 `HB` 在第 113—114 行，收全部 63 码）**：检索面台账审查器。输入 `<检索面对象标识>,<字段名>,<值>` 三元组台账；**十一个可用命名空间 + 一个拒收空间 `sec.*`**（第 18—30 行的 `-h` 清单，命名空间判定在第 187 行，`sec.*` 命中即 `K01` 拒收，第 188 行），共 **70 个已登记字段名**——35 个取值域为枚举集（`DOM` 第 65—99 行）、12 个布尔（第 100—102 行）、7 个日期形态（第 104—105 行 `DT`）、4 个数值形态（第 106 行 `NUM`）、12 个仅按形态校验的自由格（第 115—116 行 `extra`：索引名、条目标识、域标识、类型标识、bundle id、Team ID、限制键、声明式键与类型、命令名、来源文件、行号）；未登记字段名触发 `S09`（第 190 行）。判定档在第 416—421 行（`J4` 两条触发：种类与平面范围同缺、或阻断 ≥5 条；`J3` 两条：有阻断且四格至少缺一、或六格任一未登记），四档成文文案在第 422—425 行；信号行恒写 stderr（第 429 行），判定行按 `-q` 开关决定是否同时打印（第 430 行），汇总三行在第 434—436 行，退出码在第 440 行（`nblk > 0 ? 1 : 0`）。**因为全部 63 码都在 `HB` 里，这支脚本没有「警告级」信号，汇总行的「信号行数」与「阻断信号条数」两个数字恒等**——第 19.1 节与第 23.3 节的表可逐次验证这一条。
33. **脚本二 `tools/query-plane-tripartite-diff.sh`（502 行 / 41,552 字节，51 个信号码 = 47 条信号 + 闭合等级 `Q1`—`Q4`；阻断集 `HB` 在第 190—198 行，收 39 码；非阻断 8 码 = `S08`、`D02`、`D03`、`D05`、`X03`、`X04`、`V03`、`V04`）**：检索面三件差集与公告子词表比对器。三份输入顺序固定——三件清单（8 列：对象标识、对象类、核对项、三件状态、读数平面、词表归属、引用、对外表述）、三件能力表（3 列）、公开词表（制表符 3 列）。**21 个核对项按三件归属：声明件 6、通道件 7、观测件 8**；对象类 8 + 2 个保留值；可得性 4 值（`AV` 在第 158 行）。逐核对项的公开词形值写在 `-h` 帮助里并由 `M01`／`M02` 消费（`max_results` 只由 `M01` 独检，`V02` 显式不重复告警）。等级判定四档在第 448—451 行，四档成文文案在第 452—455 行；`undocumented` 整格跳过机制使等级数可以少于对象数；词表读数自报行在第 485 行（「检索面具名组件=6 条目级组件名=0」这一对数字就是第 13.2 节中心读数的机器版本）；汇总在第 494—496 行，退出码在第 500 行。**两支脚本在阻断设计上的不对称**（一支全阻断、一支留 8 码不阻断）在第 19.1、23.7 节解释。
34. **实跑驱动与运行日志**：`FX/run-all.sh`（142 行）跑脚本一 19 次、`FX/run-all-2.sh`（109 行）跑脚本二 19 次，合并 stdout+stderr 得 `FX/run-log.txt`（**862 行**，19 个 `RUN:` 分段 = R1—R19）与 `FX/run-log-2.txt`（**2,342 行**，19 个分段 = R20—R38），每次记录命令行、逐条信号、脚本自打汇总行与 `exit=`。38 次实跑的退出码为 **0 共 8 次、1 共 23 次、2 共 7 次**（逐次为 1/0/1/1/1/0/2/2/0/0/1/1/1/1/1/1/1/1/1 与 1/0/1/1/1/0/2/2/2/2/2/1/1/0/0/1/1/1/1）。`exit=2` 全部是「输入不可用」档：文件不存在、三份输入缺一、空表只剩注释行。两段驱动各自在运行期现场生成畸形输入临时件并在末尾 `rm -f` 清理，因此 `FX/` 稳定为 26 件。
35. **覆盖与只读性验收器**：`FX/codemap.pl`（32 行，用法 `perl FX/codemap.pl <脚本> <日志> <起始实跑号>`）从两份日志提取逐码首现行号与累计命中，产出 `FX/map1.txt`（67 行）与 `FX/map2.txt`（51 行）；`FX/code-coverage.pl`（24 行，用法 `perl FX/code-coverage.pl <脚本> <日志…>`）反向求「定义了但没触发」与「触发了但没定义」的差集，产出 `FX/coverage-proof.txt`（7 行，两支读数均为「定义 = 命中、未触发清单 [] 未定义命中 []」，即 **67/67 与 51/51**，也就是第 23.1 节那条纪律——「不能触发的信号等于没有写过」——的机器版本）；`FX/readonly-proof.sh`（43 行）跑八项只读检查 P1—P8 并产出 `FX/readonly-proof.txt`（61 行）：P1 awk 程序体内没有任何系统调用型函数（无 `system(`、`getline <`、`popen`、`close`、`cmd`、`exec`）、P2 外壳里唯一被执行的命令替换是两处 `mktemp`、P3 临时目录只在赋值与 `trap` 里出现、P4 设备侧命令行工具名（`mdfind`／`mdls`／`mdimport`／`mdutil`／`spotlight`／`profiles`／`sysctl`／`xcrun`／`defaults`／`log`）在两支脚本里只出现在注释与拒收分支、P5 `bash -n` 语法检查、P6 合格夹具各跑一次后检查临时目录无残留、P7 harness 里不存在任何 URL 或设备节点路径、P8 三十八次实跑的命令行归一化后只剩「脚本 + 选项 + 夹具」一种形状。`FX/map1.err` 与 `FX/map2.err` 各 1 行，是提取时的 stderr 留档。
36. **夹具与样例输入（全部为合成值：不含任何真实姓名、地址、电话号码、应用账号、真实检索词、可还原身份的语音描述、通讯录／健康／位置样本，也不含任何形似共享密钥或口令的取值）**：脚本一侧 `FX/fixture-query.txt`（209 行，6 号对象混合缺陷）、`FX/fixture-query-good.txt`（199 行，3 号对象全 `J1`、0 条信号、退出码 0，即第 23.4 节那条下界）、`FX/fixture-query-codes.txt`（215 行，逐码遍历，69 个对象标识）；三件清单侧 `FX/inventory-17.txt`（106 行，现实混排样本，11 个对象）、`FX/inventory-17-good.txt`（91 行，9 个对象全格齐备）、`FX/inventory-17-codes.txt`（70 行，逐码遍历，45 个对象）、`FX/inventory-17-optout.txt`（41 行，3 个对象，专用于证明「关闭即删转录」与「索引项删除」两格不可互推）；能力表侧 `FX/capability-17.csv`（182 行 = 第 1—14 行口径注释 + 168 条数据行，**8 类对象 × 21 核对项**，取值为 `required` 76、`optional` 30、`not_applicable` 46、`undocumented` 16，后者恰好是 8 类对象各自的 `profile_key` 与 `restriction_key` 两格，出现在第 30/31、51/52、72/73、93/94、114/115、135/136、156/157、177/178 行——这就是第 26.2 节「undocumented 恰好 16 格」的出处）；`FX/capability-17-bad.csv`（190 行 = 15 行注释 + 168 条正样 + 7 条形态缺陷行：列数不足、对象类不在词表、核对项不在清单、可得性取值非法、同类同项两档冲突等）、`FX/capability-empty.csv`（1 行）；词表侧 `FX/vocab-17.tsv`（722 行 = 表头 + **721 条**，归一化去重 720，唯一一次折叠是 `Remote Management` 与 `RemoteManagement`；七类分布 `advisory_cve` 330、`restriction_key` 216、`advisory_component` 129、`api_symbol` 32、`activity_property` 7、`declarative_type` 6、`plist_key` 1）、`FX/vocab-17-bad.tsv`（726 行，在正样之外追加 4 行：一行注释与三行形态缺陷样本——类别非法且列数溢出、值格为空、整行无制表符分隔，用于证明 `X03` 可达）、`FX/vocab-empty.tsv`（1 行，R33／R34 的输入，其形状就是第 26.3 节第二条自查的全部内容）。
37. **引用与行数校验器**：三件自写工具，都在正文与两支内嵌脚本装配完成之后运行，只读输入、产物留在存档里。
    - **`tools/cite-index-17.pl`（372 行 / 18,148 字节）** 把正文与两支内嵌脚本里的每一处「第 N 行／第 N—M 行」逐条落回归档件，按五条模式解析并打印该行原文：`E` 具名文档（同一行内出现书名号简称、反引号件名、`A/cssearchableindex.txt` 这类 ASCII 文件名或已登记别名，解析到 `A/`、`B/`、`C/`、`FX/`、`IDX/`、`tools/` 或同系列相邻篇目下的实际件，同行有多个具名件时按就近者）；`I` 就近继承（锚点前同一行没有具名文档时，沿用该行最近一个已解析文档）；`X` 上下文栈回退（前两种都落不到件时，在本章内向前累积至多八个文档名，遇 `##` 级标题清空）；`P` 冒号行段（紧跟件名的 `:26—28`、`:299` 这类锚，件名即归属）；`K` 计数核对（「216 个键名」「129 个组件」「唯一 CVE 330」「表头 + 1,266 条」这类断言回查归档件的实际去重数，每次运行现算，不读常量）。`RAW/` 从可解析集里剔除，因为正文行锚一律指向文本化件；裸 ASCII 词必须满 9 个字符才计为文档名，这是防止 Siri、Intents、index 这类散文词抢走锚点——上一轮的同型工具就因缺少这条约束，把本该落在《TN3179》表格里的锚点让给了一个 29 行的件名。本轮在该工具上新增三类句式解析，它们不是容错分支，而是正文的实际写法：「脚本一／脚本二 第 N 行」锚到 `tools/` 下的两支脚本本体；「日志第 N 行」按同一行里的 R 号分流到 `FX/run-log.txt`（R1—R19）或 `FX/run-log-2.txt`（R20—R38）；「08 第 200、1348 行」这类两位号跨篇引用解析到 `Publish-2026-10-22/` 下的相邻篇目文件，顿号并列按多个单号处理、不按区间。末次运行读数为**具名 186 处、就近继承 361 处、上下文栈 45 处、冒号行段 335 处、计数核对 19 处；越界 0 处、计数不符 0 处、未能落点 0 处**。第一版报出 8 处未能落点，逐条查明全部属于上面三类新句式而非引用错误，补齐解析规则后归零——**没有一处落点靠人工豁免**。K 模式的基准读数就是正文与本章用到的那几个数字：`B/mdm-restriction-keys.txt` 键名 **216**、`C/advisory-17.tsv` 记录 **1,266** 条／去重组件 **129**／唯一 CVE **330**、`C/query-plane-17.tsv` **68** 条、`FX/vocab-17.tsv` **721** 条。产物为 `IDX/cite-17.txt`（2,701 行，每条落点是「模式 + 正文行号 + 解析到的件 + 件内行号 + 该行原文」，原文按 UTF-8 字符边界截断，不会把多字节汉字切半以致这份索引被当成二进制）。开发期修掉三个工具自身缺陷：`find` 输出仍带 `.srcx17/` 前缀会让每件都被算成 0 行；内层 `=~ /(\d+)/g` 改写 `$1`，导致顿号并列的末号被重复打印两遍，改为先把捕获组固化成变量；`NAME_RE` 扫描结束后 `pos` 停在行尾，使随后的注入扫描只匹配到行末，跨篇引用一度只有 13、15 两个篇号生效，08／02／05／11 四处的锚点因此错落进 `FX/` 日志件——现在每次扫描前显式复位 `pos`。
    - **`tools/linecount-audit-17.pl`（77 行 / 2,847 字节）** 只核对一种断言：正文里「`某件`（N 行）」与「`某件`，N 行」两种写法中的 N 必须等于该件的实际行数。它跳过围栏代码块，脚本源码注释与实跑输出里的行数不会被误当成声明。末次运行**核对 90 处、不符 0 处**。唯一的初判不符在本章第 25 条：`B/apple-platform-security-guide.txt` 正文写 4,885 行，而工具按「读到的记录数」算出 4,886——该件末尾是一个没有换行符的分页符。行数口径按全系列一致的 `wc -l`（换行符计数）定为 4,885，改的是工具的统计法，不是正文的数字。
    - **`tools/docquote-audit-17.pl`（136 行 / 6,623 字节）** 补上前面两件工具明说不做的那一层：它校验两支脚本 DOC 数组里 102 条「见某件，随后用括号给出英文引文」的断言，判据是**引文原文是否真在被引窗口里**。比对前先归一化——转小写、删去撇号（归档件用 U+2019、shell 里写的是 `'\''` 转义，两边一律删掉）、去掉除字母数字与空格外的全部字符、压缩连续空格；括号里的引文再按省略号与顿号、「与」「和」「是」「。」切段（「是」这类字在本篇只作改写连接词用，不作正文内容），每段都必须落在所引行段前后各两行的窗口文本里。件名解析走五级：整件路径 → 短名表 → 全 stem 唯一 → 下划线分段唯一 → basename stem 前缀唯一，因此 `adding-…` 这种省略写法也能回落到全名；表格件常按列引用而不给出行号，这类条目退化为整件粗窗口，且只核对归一化后不短于二十个字节的段，以免把词形片段或"去重条数"一类的自计断言当成文档原文。末次运行读数为 **DOC 条目 102、引文段全命中 24、待回查 0、件名未解析 0**；其余条目只给行锚、不给英文引文，属工具设计上的跳过项而非豁免。首版报出八条待回查，逐条回读归档件后分成两类：**七条是工具自身的缺陷**——弯引号未参与归一、同名前缀的四个件撞在一起（为此补了精确 stem 那一级）、省略式件名不被解析、切段符漏了「是」导致把「原文 + 中文连接词 + 原文」当成一整段去搜；**一条是真的引文错写**——某条把归档件里的 `You use a query object only once to perform a search` 记成了 `use one query object only once`，多出来的那个词不在原文里。改的是那支脚本的 DOC 串、`FX/run-log.txt` 里的对应回显、`IDX/sources-17.md` 的锚点登记与正文引用它的同一句，**不是改工具的判据**。这是本篇写作过程中唯一一处被机器抓出来的原文失真。同一判据随后还以一次性脚本扫了正文围栏外的 32 个成句英文引文段：**30 段能在 `A/`、`B/`、`C/` 三组公开件里原文命中，另 2 段不是文档原文**——一段是中文译文里夹带的 API 名（原文为复数形式），一段是本报告自造的术语标签；这支一次性脚本不留在存档里，因为它对正文的几千处中文转述没有判据，只能验「这句英文是否真的出现在公开件里」。
    - **这三件校验器不能证明什么**：它们验证行号落点、区间是否越界、计数断言与行数断言，以及两支脚本 DOC 条目里的英文引文是否真在被引窗口内，**不验证被引原文是否支撑正文的结论**，也不覆盖正文自身那几千处中文转述——那一层靠 `IDX/sources-17.md` 的逐件锚点登记与正文引文块人工回查。行锚全部可回查、脚注引文全部落地，不等于每一句解读都正确。

### 同系列相邻篇目

38. **第 08 篇（隐私授权链与用途声明）**——`NSSiriUsageDescription` 作为 69 个隐私键之一的申报档位与 required-reason 审核链归它（08 第 200、1348 行）；本文从「包内已经写了这句话」之后开始，独占的问题是内容入索引之后的可查询面：「这个键申报了」与「这条查询能查到它」是两次独立判定（第 2.2、6 章）。**第 02 篇（访问控制与应用层交互）**——`com.apple.developer.siri` 权利行（02 第 360 行）与 Siri Intent 在进程／权限图里的两格（02 第 2064、2160 行）归它；本文不重建权利表，因为**索引内容的可见性不以权利为条件**：02 管谁能调这个 API，本篇管调了之后内容对谁可见。**第 05 篇（生物识别安全机制）**——「Siri、照片分析等 AI 功能不访问生物识别模板」（05 第 566 行）与声纹一句（第 706 行）归它；本文只借「锁屏前助理是否可用」这一条口径作场景门 1，不解释它由哪种生物特征判定，也不提供任何声纹相关做法。**第 11 篇（备份与恢复数据副本）**——`Spotlight` 在它的公告组件名单里出现（11 第 238 行）并作为脚本标签使用（第 1411 行）；本文不谈副本与密钥轮换，因为**索引不是副本**：删一条内容之后索引项的留存与重建，是同一台设备上的另一个对象。**第 13 篇（日志与诊断证据链）**——Spotlight 只在「在 Xcode 里找 dSYM 的操作路径」意义上出现（13 第 383 行）；本文的主键不是事件记录：**查询面是被检索的存量，日志是被写入的事件**。**第 14 篇（签名与分发授权链）**——运行授权三段与到期语义归它；本文取的是「签名校验通过不等于内容不进索引」这一格（`A/cssearchableindex.txt:26—28` 只约束谁能改索引对象，不约束条目对谁可见）。**第 15 篇（网络扩展与代理／VPN 通道归属）**——通道类 ↔ 公告组件名的差集法（15 第 760 行的词形读数法）与全部通道存在性归它；本文不建立该映射，因为**检索词是否离开设备是服务端与告知口径问题，不是隧道问题**。**第 16 篇（本地网络访问与局域网发现）**——三件对账法与「管理面不能配置本地网络隐私」那条负空间是本文方法的直接来源；两篇方向相反（16 管同网段的可见与被可见，本篇管同一台设备内的可查与被可查），且对管理面的结论也相反（16：那一格管理面不能配；本篇：能配但只能配成开关、不能逐项审阅）。**第 01、03、04、06、07、09、10、12 篇**——分别持有入口触发、抓包与链路加密、IPC 服务面、推送装配、补丁传导、设备归属、SDK 台账；本文与它们的接缝全部写在第 2 章视角声明的分界表里，其中 03/04 两篇对应一条红线：**本文不用抓包证明检索词是否出设备，只登记告知页怎么说**。各篇分界的逐条实测（含词表落点与红线清单）记于 `IDX/overlap-17.md`。

---

咨询ios系统请咨询 telegram：https://t.me/one00190
