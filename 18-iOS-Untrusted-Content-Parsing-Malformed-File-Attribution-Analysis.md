---
title: "iOS 非可信内容解析链路与恶意构造文件归属防御分析报告"
description: "iOS 上一条从别处来的字节被打开之后到底被判成了什么类型、由哪条框架通道读回来解析、这一格的后果能对外说到哪一层：十一层归属分解（来源面与容器形态、类型声明、承载方身份、类型判定、解析装配、执行域、触发条件、告知、观测平面、管理与公告回查、复位与再核对），三件（声明件／通道件／观测件）× 11 类对象 × 20 项核对项的差集口径，J1—J4 与 Q1—Q4 两套判定模型，两个离线只读核验脚本（75 + 64 个码，共 139 个全部实跑触发，32 次实跑逐码覆盖表）"
lang: zh-CN
---

# iOS 非可信内容解析链路与恶意构造文件归属防御分析报告

## 摘要

本报告集前十七篇回答过七类归属问题：**缺陷在哪**（第 01、06、07、12 篇的攻击面归属）、**谁能进入这道门**（第 02 篇的访问控制归属）、**这条链路看见了什么**（第 03、04 篇）、**这台设备归谁**（第 08、10、11 篇的主体归属）、**这段代码凭什么被允许运行**（第 14 篇的授权链归属）、**这条通道凭什么存在**（第 15 篇的通道归属）、**同网段上谁看得见谁**（第 16 篇的局域网可达性归属）、**一条内容进了检索面之后谁能查回来**（第 17 篇的检索面归属）。本文回答第八类，也是前七篇里每一份台账都会引用、却从未被正面拆解的那一格：**一份从别处来的字节被打开之后，它被判成了什么类型、由谁判的、判在哪一层、这一格的后果由哪个面读回来。**

这句话拆开是三个问句，而且三个问句的判定权分属三方：**谁声明了它的类型**（内容自带的导出／导入声明、扩展名与 MIME 标签、包结构标记——声明权在内容生产者与承载 App 手里）；**哪条通道把它读回来解析**（`UTType` 反查、`CGImageSource`、Quick Look 预览、`WKWebView` 加载、`UIDocument` 打开、Activity 分享——通道权在框架手里）；**这一格的后果谁能说**（呈现面、崩溃报告标识、公告组件与 CVE、管理面限制键四处——观测权分散，且四处互不通气）。

本文的核心结论是这三件**两两都不闭合**，而不闭合的方向与第 17 篇又相反。17 篇的写入权在每个 App 自己手里，缺口几乎总在读回侧；**本篇的声明权在内容生产者手里，而判定权在框架手里，两者之间没有任何一次可登记的握手**。具体表现为三条：内容自带声明不代表系统按它判（`A/uikit_uidocument.txt:35` 直言 `UIDocument` 的文件类型是「the Uniform Type Identifier associated with the file extension」——打开一条本地文档时先读的是**扩展名**，不是内容里那份声明）；被判成某类型不代表任何一面读得回这一格的后果（`C/readings-18.txt:25—30`：1,266 行公告的影响句里，五类后果词形没有一类写成「内容被误判类型」或「被自动解析」，这一类措辞的行数 = **0**）；读回来了也不代表这一格能换算成归属（`B/mdm-restriction-keys.txt` 的 218 个键名里，没有一个键指名解析器或解码器，`C/readings-18.txt:93`）。

比这三条更要紧的是一条**列间错位读数**。把 12 份安全发布的 1,266 条公告记录按「影响句是否写明恶意构造对象」切出 467 行子集，再按解析层词形表（38 个词形）切组件名：**组件名含解析层词形的 23 个、不含的 11 个**（APFS／Calendar／CoreServicesUIAgent／CoreStorage／CoreSymbolication／GPUTools／Grapher／HFS／HomeKit／Mail／OpenBSM，`C/subset-18.txt:9`）；把两列放在一起算反向错位，**影响句写明恶意构造对象、组件名却不含任何解析层词的有 46 行**，其中 `image` 16 行、`file` 19 行、`web content` 与 `font` 各 0 行（`C/readings-18.txt:54—59`）。也就是说：公告的**组件列**与**影响句列**互不校验，同一行里两列可以各说各话。第 15、16 篇处理的是「两列都缺位」的负空间，第 17 篇处理的是「一列有、一列无」，本篇处理的是「**同一行两列不同形**」——防守方按组件名筛选解析面缺陷，会漏掉这 46 行；按影响文本筛选，会漏掉那 11 个不含解析层词的组件。这是本文的中心事实，也是第 22 章脚本二里 X 族与 T 族信号码的设计根据。

还有一条必须前置的**结构性负读数**：影响句里写成「without user interaction」这一类免交互措辞的去重 CVE 数 = **0**（`C/readings-18.txt:73—74`）。全档案里唯一一处对 `0-click` 下定义的地方是平台安全指南第 1442 行，而那一行讲的是 BlastDoor 的设计目标、讲的是消息与身份服务，**不是任何一条文件解析链**。因此本文对解析发生时点的表述一律收敛到「**打开／预览／分享这三类动作之后**」这一种形态，不写任何免交互判定；第 10 章把这条约束做成 `trg.*` 三个字段的枚举，脚本一的 E01 信号码专门拦「把公告文本读成免交互证据」这个动作。

全文有十一组可数的公开读数（第 16 章，每组给归档行锚）、两套四档判定模型（第 19 章）、十一层归属分解（第 4—14 章）、一个十一层 × 责任方 × 三件 × 证据的归属矩阵（第 15 章），以及两个完全离线、只读、不联网、不接触任何设备或任何被登记对象的核验脚本：解析链台账逐字段审查器（363 行，71 个信号码 + 4 档判定）与解析链三件差集与公告子词表比对器（572 行，64 个码 = 60 个信号码 + 4 级闭合）。**合计 139 个码全部由真实夹具触发**，32 次实跑的逐码可达性见第 23 章；两支脚本的只读性质由第 23.1 节的二十段实证逐条给出位置。

---

## 目录

1. [引言](#1-引言)
2. [视角声明与本文边界](#2-视角声明与本文边界)
3. [三套词表：内容自带的类型声明口径、框架侧解析通道口径、管理与公告回查口径，与八处换算失败](#3-三套词表内容自带的类型声明口径框架侧解析通道口径管理与公告回查口径与八处换算失败)
4. [L1 来源面与容器形态](#4-l1-来源面与容器形态)
5. [L2 类型声明层：内容自带的三张票](#5-l2-类型声明层内容自带的三张票)
6. [L3 承载方身份层](#6-l3-承载方身份层)
7. [L4 类型判定层：三条票源与判定漂移](#7-l4-类型判定层三条票源与判定漂移)
8. [L5 解析装配层：哪条框架通道把这一格读回来](#8-l5-解析装配层哪条框架通道把这一格读回来)
9. [L6 执行域层：沙箱、entitlement 与内存安全类](#9-l6-执行域层沙箱entitlement-与内存安全类)
10. [L7 触发条件层：打开、预览与分享之后的三种时点](#10-l7-触发条件层打开预览与分享之后的三种时点)
11. [L8 告知层：同意、隔离标记与来源披露](#11-l8-告知层同意隔离标记与来源披露)
12. [L9 观测平面层：这一格是谁读回来的](#12-l9-观测平面层这一格是谁读回来的)
13. [L10 管理与公告回查层：218 个限制键与 46 行列间错位](#13-l10-管理与公告回查层218-个限制键与-46-行列间错位)
14. [L11 复位与再核对层：清缓存、复位与再打开证明](#14-l11-复位与再核对层清缓存复位与再打开证明)
15. [归属矩阵：十一层 × 责任方 × 三件 × 证据](#15-归属矩阵十一层--责任方--三件--证据)
16. [公开读数：这条通路上能数出来的十一组事实](#16-公开读数这条通路上能数出来的十一组事实)
17. [可见性边界：这一层读者能拿到什么](#17-可见性边界这一层读者能拿到什么)
18. [五个读数面：声明侧、通道侧、呈现侧、管理侧、公告侧](#18-五个读数面声明侧通道侧呈现侧管理侧公告侧)
19. [两套判定模型：J1—J4 与 Q1—Q4](#19-两套判定模型j1j4-与-q1q4)
20. [运营指标 O1—O10](#20-运营指标-o1o10)
21. [只读核验脚本一：解析链台账逐字段审查器](#21-只读核验脚本一解析链台账逐字段审查器)
22. [只读核验脚本二：解析链三件差集与公告子词表比对器](#22-只读核验脚本二解析链三件差集与公告子词表比对器)
23. [三十二次实跑与全量信号覆盖验收](#23-三十二次实跑与全量信号覆盖验收)
24. [十二个误区](#24-十二个误区)
25. [常见问题](#25-常见问题)
26. [未公开文档化边界清单](#26-未公开文档化边界清单)
27. [结论](#27-结论)
28. [参考资料](#28-参考资料)

---

## 1. 引言

### 1.1 为什么这是第八类归属问题

系列前十七篇里，「类型」这个词出现过三次，但每次都落在别的归属上：第 09 篇的脚本按 CSV 表头识别**自己的输入文件**（那是核验器的输入纪律，不是系统判定）；第 17 篇的索引项 `type_identifier` 说的是「**索引项声明**它是什么」；第 02 篇的剪贴板代码示例里 `UTType.png.identifier` 说的是「**谁能够读写这一份剪贴板数据**」。这三处都不是本篇的对象。本篇的对象是一件事：**一份从别处来的字节被交给系统之后，系统按哪一格把它判成某个类型、由哪条通道把它读回来解析、判错或判不成之后这一格的后果由谁说出。**

这类归属必须单独拆出来，有三个可数的理由。

**第一，判定权被切成三段，而且三段互不引用。** 声明权在内容生产者与承载 App 手里：`A/uniformtypeidentifiers_defining_file_and_data_types_for_your_app.txt:9—10` 给出四步（在 `Info.plist` 里声明、新建或复用标识、声明一致性、给扩展名与 MIME 标签），`:12` 进一步要求「当你要定义一个类型时，必须把它声明为导出类型或导入类型……如果你的 App 用到框架已经提供的类型，不要在自己的 bundle 里重复声明」，`:13` 说导出类型是 canonical source，`:14` 说导入别人的类型时**不要再造一个标识，直接用原标识**。判定权在框架手里：同一份字节，`A/uikit_uidocument.txt:35` 说打开文档时类型来自**扩展名所关联的 UTI**，`A/imageio.txt:3、6` 说 Image I/O 直接读写多数图像格式并访问其元数据（类型来自字节本身），`A/webkit_wkwebview.txt:776` 的 `loadData:mimeType:characterEncodingName:baseURL:` 更直接——**类型由调用方口头断言**。观测权分散在四个面：呈现面（Quick Look 的两份清单）、崩溃面（报告标识）、公告面（组件名与 CVE）、管理面（限制键）。三段之间没有任何一条公开口径把它们接起来。

**第二，同一个对象的判定结果会随通道变，而不随内容变。** 一条扩展名、一份 `UTType` 反查、一段字节嗅探是三条互不校验的票源（第 7 章）。`A/uniformtypeidentifiers_defining_file_and_data_types_for_your_app.txt:88` 给出了全篇唯一一条**优先级**句：「如果同一个类型同时存在导出声明与导入声明，导出声明优先」。除此之外，公开文档没有一处规定「扩展名与内容嗅探冲突时听谁的」——`:42—46` 只警告「如果你的类型不 conform 到 `public.data` 或 `public.content`，系统就无法判断存储项是否属于该类型」。所以本篇把「三条票源一致」做成一条**独立的核对项**（`conforms_chain`），并把「三票全无」做成阻断信号（脚本一的 B01）。

**第三，这一格的后果在公开口径里说不出。** `C/readings-18.txt:25—30` 列出公告影响句的全部五类后果词形：`unexpected app termination` 133 行、`disclosure of` 84 行、`bypass` 78 行、`memory corruption` 77 行、`arbitrary code execution` 58 行。**没有一类写成「内容被误判类型」或「内容被自动解析」**。把 `opened as`／`rendered as`／`incorrectly`／`assumed` 四个词形拿去扫 1,266 行影响句，命中 **0 行**；第五个词形 `identif` 命中 2 行（`C/advisory-18.tsv:78、226`，两行同为 Maps／`CVE-2026-112707`，句子是「An app may be able to identify what other apps a user has installed」——说的是 App 清单泄露，与类型判定无关）。因此本篇的归属表述只能停在「哪一个对象在哪一格被判定成什么、由哪条通道读回、哪一个面承载这一格」，不能停在「判错会导致什么」——后者在公开档案里没有对应句式。这正是脚本一的 X01 信号码与第 3.4 节失败点 8 的落点。

### 1.2 主键与三个问句

本文主键：**一份非可信字节被打开这一次动作上的类型判定与解析归属**。它和系列里任何一篇都不重合，因为它要求三格独立判定，而每格分别属于不同篇目：

| 问句 | 谁持有判定权 | 落在本文哪一层 | 系列里的最近邻（但不重合） |
| --- | --- | --- | --- |
| 这份字节凭什么被判成这个类型 | 内容生产者（声明件）+ 框架（票源与优先级） | L1 来源面、L2 声明、L3 承载方身份、L4 判定 | 17 篇的类型标识（那是索引项的自我声明，本篇是内容被谁反查）、14 篇的签名校验（那是代码能不能运行，与内容被判成什么无关） |
| 哪条通道把它读回来解析、解析跑在谁的域里 | 框架（`asm.*`）+ 平台（`dom.*`） | L5 装配、L6 执行域、L7 触发 | 06 篇的 IPC 服务面（本篇只登记宿主进程与 XPC 服务两格，不展开其缺陷）、02 篇的沙箱与 entitlement（本篇只登记结论格，不重建权限模型） |
| 这一格的后果与复位由谁说出 | 呈现面／崩溃面／公告面／管理面四处，互不通气 | L8 告知、L9 观测、L10 管理与公告、L11 复位 | 13 篇的证据链（那是被写入的事件记录，本篇是被读回的对象属性）、09 篇的补丁传导（那是版本覆盖，本篇是类型归属） |

三个问句合起来构成第 19 章的两套四档判定模型：脚本一的 J1—J4 回答「这一条能不能进入对外归属表述」，脚本二的 Q1—Q4 回答「三件对完之后，归属还能不能立起来」。

### 1.3 本文不做什么

本文是归属与口径分析，不是操作手册。以下内容明确不做，且第 21、22 章两支脚本在设计上不可用于这些目的：

- **不含恶意文件构造、不含解析缺陷定位、不含崩溃复现与载荷投递**。本篇不写「把某字段改成某值会让解析器走到哪一段」这类句子，也不给任何缺陷位置、内存布局或利用链时序。
- **不提供任何绕过隔离、告知或管理面审计的做法**；不指导关闭、伪装或跳过任何同意弹窗；不指导用外部工具替代系统判定来「证明」类型。
- **不写任何免交互判定**。依据是 `C/readings-18.txt:73—74` 的 0 命中读数与 PSG 第 1442 行的定义位置：那一段讲的是 BlastDoor 对消息与身份服务的设计目标，不是文件解析链。全文对解析发生时点的唯一允许形态是「打开／预览／分享这三类动作之后」。
- **不采集设备状态、不打开任何被登记的对象**。两支脚本全程离线、只读，不调用 `file`／`mdls`／`mdimport`／`mdutil`／`mdfind`／`spctl`／`codesign`／`defaults`／`log`／`sysctl`／`xcrun`／`profiles`／`plutil`／`sips`／`qlmanage`／`otool` 等任何命令行工具——这些命令名在两支脚本里只出现在头部注释与拒收分支的正则里，第 23.1 节 P1—P4d 与 P11—P14b 逐条给出位置与阳性对照。
- **台账一律拒收**：真实用户检索词、可还原身份的语音描述、真实联系人／健康／位置样本、形似共享密钥或口令的取值、设备绝对路径、整段文件正文、超长度阈值载荷。全部夹具为合成标识与合成取值；这一条由脚本一的 K01—K03 实现为阻断信号，不是写在正文里的承诺。
- **不代替厂商口径**。凡是只有厂商承诺、没有公开文档支撑的判断，一律落在第 26 章的未公开文档化边界清单里，不进结论。第 26 章的 N12 与本篇 23.1 节末段说的是同一件事：本文能保证**判定过程可离线复算**，不能保证**登记内容与某台真实设备一致**。

---

## 2. 视角声明与本文边界

系列里任何一篇在开篇都必须回答「这件事第 X 篇不是已经写过了吗」。本节逐条回答，并把边界写成可检查的句子——每一行的「不重复部分」都能在对应篇目里找到原句位置。

### 2.1 与第 17 篇的分界（最近邻，且是显式交接）

第 17 篇在第 13.3 节把 `Model I/O` 与 `Apple Neural Engine` 的「Processing a maliciously crafted 3D model…」这一组读数**留给了下一篇的客体**，并把解析层组件名排除在它自己的公开词表之外。本篇就是那一篇，且只接管解析器平面的**归属**问题。

**分界在两处。**

**对象不同**：17 篇的类型标识是「索引项声明它是什么」——一个由 App 写进索引的自我描述，读数面是查询能不能命中它；本篇的类型标识是「内容自带的声明被谁读回来」——一个在打开动作上被系统反查、可能被扩展名覆盖的判定结果，读数面是它被判成了什么、由哪条通道解析。同一条 `public.png` 在两篇里分属两个平面，本篇不复用 17 篇任何一个信号码。

**判定权位置不同**：17 篇的缺口几乎总在读回侧（写入太容易）；本篇的缺口在**声明与判定之间没有握手**——内容生产者写了导出声明，框架按扩展名判、按标签反查判、或按调用方断言判，三者都不引用那份声明。这决定了本篇脚本二的形态与 17 篇不同：本篇的差集器主要查「声明件写了这一项，通道件与观测件两格里一条也没有」（T 族）与「某类内容按公开口径需要的核对项，台账里一条也没有」（D 族）。

三件命名沿用 16、17 篇（声明件／通道件／观测件），但**第二件换了轴**：16 篇第二件是权限件（系统判定并持有），17 篇是通道件（哪条 API 能读回），本篇的通道件是**框架能否把这一格读回来解析**——这是三篇里唯一一处需要重新定义对象类与核对项的替换，本篇的 11 类对象与 20 项核对项全部重列（第 22 章），不复用前两篇任何信号码。

### 2.2 与第 01 篇的分界

第 01 篇写过「消息接收后自动解析、渲染预览、预处理附件」与「图像附件 → ImageIO 解码」，并给过一张附件类型 × 解码器对照表。**分界**：01 篇论证的是**入口**（内容从哪条消息进来、链路的时序），本篇论证的是**判定**（同一份字节被判成哪个类型与它从哪条消息进来无关）。本篇不重建攻击链时序、不给任何免交互判定，并把这一点做成硬约束：`trg.trigger_mode` 的枚举里没有任何「自动／无需交互」取值（第 10 章），脚本一的 E01 信号拦的就是这一格被写成免交互口径。同一份字节经 AirDrop、经预览、经分享或经索引读回，判定可以落在三个不同的格上——这正是本篇的主键，而 01 篇的对照表里没有这一格。

### 2.3 与第 14 篇的分界（最容易混的一对概念）

第 14 篇处理签名与分发授权链，其中有公证票据「checked that code for malicious components」一句。**分界**：**恶意代码**与**恶意构造内容**是两类对象。14 篇判的是「这段代码凭什么被允许运行」，本篇判的是「这份内容被读成了什么类型」；14 篇那条 `bypass Gatekeeper` 读数（且属 `copyfile`）不能作为解析链的任何判据。本篇在 L6 执行域只登记 `dom.domain_class` 与 `dom.entitlement_needed` 两格的**结论**，并明确这两格的公开出处是 PSG 第 2391、2446、4740 行（沙箱、声明式 entitlement、XNU 强制项），不重述 14 篇的描述文件、证书与通道分析。

### 2.4 与其余各篇的分界

| 篇 | 它已经写过 | 本文不重复 | 本文独占 |
| --- | --- | --- | --- |
| 02 访问控制 | Pasteboard 章与剪贴板读写里的 `UTType.png.identifier` 代码示例 | 不重建 entitlement／沙箱／剪贴板权限模型 | 只把 `pasteboard_transfer` 当作一个读数平面登记：跨 App 传递时类型标识是否被**重判**，与谁能读剪贴板是两次判定 |
| 05 生物识别 | 「Siri、照片分析等 AI 功能不访问生物识别模板」 | 不判定生物特征本体、不谈模板与匹配阈值 | 解锁与否改变的是内容能否被**呈现**，不改变内容被判成什么类型 |
| 06 IPC／07 推送 | 「公告组件名 ↔ 设备侧表现」的落差表；通知服务扩展「显示之前修改载荷、下载附件」 | 不重建服务清单、不谈 APNs 装配与载荷下发 | 崩溃在本篇只登记**报告标识**这一格（`crash_ref`）；附件被下载之后由谁判定类型才是本篇的客体 |
| 08 隐私授权 | 同一批公告里 "A maliciously crafted webpage…" 的影响句 | 不再讨论用途串、隐私清单与 required reason | 解析链**没有授权申报面**：内容被判成某类型不需要任何隐私键，因此不能用「申报了」推「会被解析」 |
| 09 更新链 | 其脚本按表头识别输入文件类型、不看扩展名也不看文件名 | 不建补丁时延指标、不重述其 CSV 表头纪律 | 那是核验脚本**自身**的输入识别；本篇的判定发生在设备上，两者只在「表头不等于扩展名」这一条方法上同形 |
| 10 设备归属／11 副本 | 设备在谁手上、激活锁与托管凭据；副本在谁手上、可不可解 | 不判定设备所有权，不谈副本与密钥轮换 | 一台设备归谁与一份内容被判成什么类型无因果；同一份字节在不同设备上可被判成两个类型（声明缺失时由扩展名或嗅探决定） |
| 12 第三方代码 | 「组件名不是 SDK 名」、去重组件标题 101 个 | 不重建 SDK 名单、不判代码来自哪条通道 | `ImageIO`／`FontParser`／`ColorSync` 在本篇是**系统解析器**的名字，用作词表比对而不作归属主体判定 |
| 13 证据链 | sysdiagnose 的时刻—采集—导出时序 | 不采集日志、不定义留存与同意口径 | 崩溃面只允许登记报告标识；堆栈、设备路径与正文一律拒收（脚本一 K03、脚本二 M04／P07） |
| 15 网络通道 | 六个通道词形在 101 个去重组件名里全部命中 0 的词形差集法 | 不建立「通道类 ↔ 组件名」映射、不引用隧道装配 | 方法同源而方向相反：本篇的组件词表**正向命中 23 个解析层组件**（`C/subset-18.txt:7`），并把「命中但不属恶意构造子集」做成一条独立读数 |
| 16 局域网可达性 | 三件 × 对象类 × 核对项的差集口径、`allowAirDrop` 等相邻键差集 | 不复用其权限件模型——解析链没有「权限件」这一件 | 管理面在本篇同样只能关承载内容的 App 与浏览器行为（`allowSafari`、`safariAllowJavaScript`），**不能逐项约束类型判定**（`C/readings-18.txt:93`） |

### 2.5 三件法与本文的可证性边界

本文的可证边界由一句文档事实决定：**这一份字节被判定成某类型之后，没有任何公开接口能把「判定过程」读回来。** 因此本篇所有关于「它到底被判成了什么」的表述，只能写成三种形态之一：

1. **接口口径**——某 API 的公开说明写了它按什么取类型（`A/uikit_uidocument.txt:35`：文件类型是「与扩展名相关联的那个 UTI」；`A/webkit_wkwebview.txt:776`：由调用方给出 `mimeType`；`A/imageio.txt:56`：`CGImageSource` 可从 URL、数据对象或数据消费者三种来源读图）。
2. **清单口径**——某一面逐行列出了它承载哪些类型（Quick Look 的两份清单：`A/quicklook.txt:7—13` 七行、`A/quicklook_qlpreviewcontroller.txt:12—21` 十行）。
3. **回查口径**——公告、KEV、限制键这三份公开登记里这一格写了什么（`C/advisory-18.tsv` 六列、`C/kev-apple.tsv` 七列、`B/mdm-restriction-keys.txt` 218 个键名行）。

**没有第四种。** 本文不允许任何「实测发现这份字节被判成了另一类」的表述，因为那需要在设备上打开对象并读取判定结果，属于本篇红线。这条边界带来一处必须写清的负面结论：**「判定正确」在本篇里不能表达为「系统确实按声明判的」，只能表达为「三票一致 + 判定依据取自哪一格已登记 + 该格引用能落回归档行号」这一间接三段。** 第 7、19 章与脚本一的 B 族、X 族信号码全部围绕这条边界设计。

---

## 3. 三套词表：内容自带的类型声明口径、框架侧解析通道口径、管理与公告回查口径，与八处换算失败

三套词表各说各话，是这一层最容易产生假结论的原因。本节先把三套词表各自的取值列清楚，再逐条给出八处**换算失败**——即「从一套词表的说法推不出另一套词表的结论」的固定位置。第 21、22 章两支脚本的每一个信号码都能归到某一条失败上。

### 3.1 词表 A：内容自带的类型声明口径（声明件）

来源是组 A 的三份 UniformTypeIdentifiers 归档与 `Info.plist` 键表。可枚举取值：

| 词形 | 出处 | 含义 |
| --- | --- | --- |
| `exported`／`imported` | `A/uniformtypeidentifiers_defining_file_and_data_types_for_your_app.txt:12—14`（定义类型必须二选一；用框架已有的类型不要重复声明；导入别人的类型时沿用原标识） | 声明方向的二分，全篇唯一一处「谁拥有这个标识」的公开口径 |
| `UTExportedTypeDeclarations`／`UTImportedTypeDeclarations` | 同上 `:89—102`（七个键名逐条）、`A/uniformtypeidentifiers.txt:53—54`（自定义声明与系统声明分属两份文档） | 两份声明清单，落在承载 App 的 `Info.plist` 里 |
| `UTTypeIdentifier`／`UTTypeConformsTo`／`UTTypeDescription`／`UTTypeTagSpecification`／`UTTypeReferenceURL` | 同上 `:89—102`；`:78`（`UTTypeIdentifier` 是类型声明的必需键）、`:82`（一致性数组） | 一条声明的五个组成 |
| `public.filename-extension`／`public.mime-type` | 同上 `:61—65`（标签字典的写法）；`A/uniformtypeidentifiers_system_declared_uniform_type_identifiers.txt:20—23`（两条标签类标识） | 两类标签，各自只映射到标识 |
| 三个保留前缀 `public`／`dyn`／`com.apple` | `A/uniformtypeidentifiers_defining_file_and_data_types_for_your_app.txt:29—35`（逐个字给出 reserved 主体）、`:118—123`（CODE 行） | App 自有类型不得使用 |
| 派生链 `public.png` → `public.image` → `public.content`／`public.data` → `public.item` | `A/uniformtypeidentifiers.txt:8—20`（「通过把类型标为其他类型的子类型来显式指定它们之间的关系」） | 一致性链，判定面的分母 |
| `public.data`／`com.apple.package` 一致性要求 | 同上 `:42—46`（**「如果你的类型不 conform 到它们，系统就无法判断存储项是否属于该类型」**）、`:47—49`（文档类型另须 conform 到 `public.content`，这一层 conformance 使用户能通过 AirDrop 共享）、`:50—52`（conform 到最具体的子类型）、`:53`（非公开父类型也要一并声明） | 唯一一处「不声明会怎样」的公开后果句 |
| 系统声明条目 201 个 | `A/uniformtypeidentifiers_system_declared_uniform_type_identifiers.txt:24` 起，逐条以「A type that represents …」开头；提及 conforming／base type／declare 的行 67（`C/readings-18.txt:99、112`） | 判定面的分母 |
| `exported` 优先 | 同上 `:88`（同一类型同时存在导出与导入声明时，导出声明优先） | 全篇唯一一处优先级规则 |

这套词表的特点：**全部由内容生产者或承载 App 自己填**，且没有任何一格是系统在判定之后反过来写回的。

### 3.2 词表 B：框架侧解析通道口径（通道件）

来源是组 A 的六份框架文档。可枚举取值（与脚本二的 `通道件` 七个核对项一一对应）：

| 核对项 | 词形 | 出处 |
| --- | --- | --- |
| `uti_lookup` | `UTType`、`UTTypeIdentifier` | `A/uniformtypeidentifiers.txt:25—52`（`UTType`／`UTTagClass`／`UTTypeReference` 家族符号清单） |
| `ext_lookup` | `filenameExtension`、`UTTagClassFilenameExtension`、`public.filename-extension` | `A/uniformtypeidentifiers_system_declared_uniform_type_identifiers.txt:8—13、20—23` |
| `mime_lookup` | `mimeType`、`UTTagClassMIMEType` | 同上 `:14—19、20—23` |
| `decode_entry` | `CGImageSource`、`CGAnimateImageAtURLWithBlock`、`WKWebView`、`UIDocument`、`QLPreviewController` | `A/imageio.txt:56`（从 URL、数据对象或数据消费者读图）、`A/imageio.txt` 动画入口、`A/coregraphics.txt:6`（位图与 PDF 的创建、显示与解析由框架本身承担）、`A/webkit_wkwebview.txt:13、21—22、776`、`A/uikit_uidocument.txt:35、568` |
| `preview_entry` | `QLPreviewController`、`ql_extension`、`none` | `A/quicklook.txt:7—13`（7 行清单）、`:17`（自有类型可自行给出预览）、`:18`（清单随系统版本变化）、`:19—22`（`QLSupportedContentTypes` 写在扩展的 `Info.plist` 里）；`A/quicklook_qlpreviewcontroller.txt:12—21`（10 行清单）、`:22`（同一句版本警告） |
| `open_entry` | `application_open`、`scene_openurl`、`uidocument_open`、`activity_share` | `A/uikit_uiapplicationdelegate_application(__open_options_).txt:3—4`（同一条「打开」语义有两套公开口径：旧委托方法与其明示的 `scene(_:openURLContexts:)` 替代）、`:49`（要打开的资源可以是网络资源或文件）、`A/uikit_uidocument.txt:34、39、42—43、476、568、895`、`A/uikit_uiactivityviewcontroller.txt:3、10—11` |
| `resolved_uti` | 判定落点（反查结果） | 由上述任一通道给出；`:35`（扩展名反查）与 `A/imageio.txt:3`（字节本身）给出的是两个不同来源 |

这套词表的特点：**每一格只说「我能读什么」，不说「我读成了什么」。** 全部六份框架文档里，没有一处给出「扩展名与内容不一致时听谁的」这类仲裁口径。

### 3.3 词表 C：管理面、告知面与公告口径（观测件的另四个来源）

| 词形 | 出处 | 含义 |
| --- | --- | --- |
| 218 个限制键名行 | `B/mdm-restriction-keys.txt:5—8` 起逐行（全部是 `allow` 前缀的小驼峰单标识；`:1—4` 是页面分段标题，**不是键**） | 管理面唯一能表达的东西：允许或不允许 |
| 命中内容接收／打开／预览／网页／文件词形的键 = 6 个 | `C/readings-18.txt:93—94`：`allowUIConfigurationProfileInstallation`、`safariAcceptCookies`、`safariAllowAutoFill`、`safariAllowJavaScript`、`safariAllowPopups`、`safariForceFraudWarning` | 五个是 Safari 行为键，一个不是内容类键 |
| 可**间接**约束内容能否被打开／预览／联网取回的键 = 19 个 | 同上 `:95—96`（含 `allowAirDrop`:9、`allowAppClips`、`allowSafari`:133、`requireManagedPasteboard`、`allowedCameraRestrictionBundleIDs`:162 等） | 关掉的是承载 App 与浏览器行为，不是判定本身 |
| **没有任何一个键能逐项约束类型判定** | 同上 `:91—96` 全表；`C/subset-18.txt` 无对应条目 | 本篇管理面负空间的主读数，脚本二 P02（通道件记在管理面）的判据来源 |
| Restrictions payload 的两句机制句 | `B/mdm-restrictions.txt:24`（关闭 AirDrop）、`:738`（禁用 Safari 并移除图标、且阻止打开 web clip，需受监督设备）、`:960`（系统把 AirDrop 视为非受管投递目标） | 管理面能做到的粒度：整 App 或整通道 |
| 公告六列 | `C/advisory-18.tsv` 表头 `file`／`platform`／`component`／`cve`／`impact`／`avail`；1,266 行、330 CVE、129 组件、12 平台版本行（`C/readings-18.txt:2—5`） | 存在性读数的载体，且两列互不校验 |
| KEV 七列 | `C/kev-apple.tsv` 表头 `cveID`／`vendorProject`／`product`／`dateAdded`／`dueDate`／`ransomware`／`shortDescription`；95 条 Apple 条目，`catalogVersion 2026.10.30`、全目录 `count 1766`（分母必须用全目录数，见 `C/kev-apple.tsv.meta.txt`） | 在野利用读数；两列日期都是 `YYYY-MM-DD` 形态，脚本的日期校验按同一形态 |
| 告知与隔离 | `B/apple-platform-security-guide.txt:2557`（自定义键盘扩展默认在极受限沙箱内运行，开发者可在**取得用户同意**后申请 Open Access）、`:1448`（锁定模式以功能换取防护） | 本篇唯一两处「同意」与「复位」的公开出处 |

### 3.4 八处换算失败

这八条是本文的负面骨架。每条都写成「A 词表的这一句**推不出** B 词表的那一句」，并给出行锚。第 21、22 章的信号码族名在括号里标出，读者可以拿任一码回到对应章。

**失败 1：内容写了声明 → 系统按声明判。** `A/uniformtypeidentifiers_defining_file_and_data_types_for_your_app.txt:12—14` 要求声明导出或导入；`A/uikit_uidocument.txt:35` 说打开文档时的文件类型来自**扩展名所关联的 UTI**。两句之间没有换算关系：一份带完整导出声明的文件，若扩展名被改掉，`UIDocument` 那条通道读到的是另一条票源。脚本一的 B 族（B01 三票全无、B02 只有标签、B05 依据为假定）与脚本二的 K 族全部落在这里。

**失败 2：三条票源都有值 → 三票一致。** 三条票源是三个独立字段，公开文档里没有一处规定它们必须一致，`A/uniformtypeidentifiers_defining_…txt:88` 只解决「导出声明与导入声明冲突」这一种情形，不解决「扩展名与内容嗅探冲突」。所以三票全有仍可能是三票各异。脚本一的 `typ.type_conflict` 与 B04（冲突未解却给确认结论）专拦这一条。

**失败 3：判定成某类型 → 后果能被说出。** `C/readings-18.txt:25—30` 的五类后果句里没有一类写「误判类型」或「被自动解析」；`opened as`／`rendered as`／`incorrectly`／`assumed` 四个词形扫 1,266 行影响句命中 **0 行**，`identif` 命中的那 2 行讲的是 App 清单泄露（`C/advisory-18.tsv:78、226`）。判定与后果之间在公开档案里断开。脚本二的 V 族（口径闭合）与 X 族的 `X01` 由此而来。

**失败 4：公告组件列写了 → 影响句说的是同一件事。** `C/readings-18.txt:54—59`：影响句写明恶意构造对象、组件名却不含任何解析层词的 46 行（`image` 16、`file` 19、`web content` 0、`font` 0）；反过来 `C/subset-18.txt:8—9` 的 11 个组件（APFS／Calendar／CoreServicesUIAgent／CoreStorage／CoreSymbolication／GPUTools／Grapher／HFS／HomeKit／Mail／OpenBSM）在恶意构造子集里但组件名不指向任何解析层。两列互不校验，按任一列筛选都会漏。这是本文中心事实，对应脚本二的 X 族与 T 族。

**失败 5：某框架能读这类格式 → 这一面就能给出结论。** Quick Look 的两份清单**不同形**：`A/quicklook.txt:7—13` 取到 7 项（iWork 与 Office／Images／Live Photos／Text files／PDFs／Audio and video／USDZ），`A/quicklook_qlpreviewcontroller.txt:12—21` 取到 10 项（iWork／Office／RTF／PDF／Images／Text files（要 conform 某 UTI）／CSV／USDZ）；共有词形 8 个，只在总览出现的 `audio`／`live photo`／`video`，只在类文档出现的 `csv`／`rtf`（`C/subset-18.txt:19—42`）。两份文档各自还都带一句「清单可能随系统版本变化」（总览 `:18`、类文档 `:22`）。**引用其中任一份都不构成闭合。** 脚本二的 `preview_entry`／`render_result` 判据与 P 族（平面越界）围绕这条设计。

**失败 6：截屏与厂商说法 → 机制依据。** 观测件里有两个平面按公开口径**不承载机制**：`vendor_claim`（厂商说法）与 `settings_ui`（设置界面读数）。它们在脚本二的能力表里被允许作为**存在性**读数，但不允许作为**判定依据**——`A/quicklook.txt:18` 那句「清单可能随系统版本变化」正好说明：任何一次界面读数只能证明那一天这一面显示过什么。台账里把这两类来源写进 `dom.domain_source`／`typ.type_source`／`notice.warning_text_source` 时，脚本一分别报 D06、B05、N04 三个阻断信号。**这一条是第 21 章 DOC 表里 `N04` 的逐字出处**：截屏与厂商说法不能充当机制依据。

**失败 7：管理面关掉某个 App → 判定链被约束。** 218 个键里没有一个指名解析器或解码器（`C/readings-18.txt:93`）；`B/mdm-restrictions.txt:738` 的粒度是「禁用 Safari 这个 App、并阻止打开 web clip」，不是「禁用某个解析通道」。关掉承载 App 改变的是**谁还能打开内容**，不是**内容被读成什么类型**。脚本二的 P02（通道件记在管理面）由此设成阻断。

**失败 8：口径之间可以互相换算 → 结论可以写成一句。** 这是本篇最重要的一条，因为它约束的是**写法**。三套词表之间没有任何一条公开换算句，所以任何跨套结论都必须落回「哪个对象、哪一格、取自哪份归档的哪一行」。台账的 `doc.source` 与 `doc.line_ref` 两格就是把这条约束做成字段：行号引用只写 `1234` 或 `6-9` 这一种形态，带「第／行」前缀的写法在两份台账之间不可换算（脚本一 X02）；结论句若写成跨套换算而没有行号，落 X01 阻断。**这一条是第 22 章 DOC 表里 `X01` 的逐字出处**：口径不能直接换算，结论必须回到文件与行号。

八条失败的分布可以逐码核对：1→B／K 族（脚本一 8 个码、脚本二 5 个码），2→B04／`type_conflict`，3→V 族与 X01，4→X 族与 T 族，5→P 族与 `preview_entry`，6→D06／B05／N04，7→P02 与 G 族，8→X01／X02。第 23.6 节的静态反向对齐会把这八组逐条数一遍。

---

## 4. L1 来源面与容器形态

### 4.1 这一格的公开口径

「一份非可信内容怎么到这台设备上、它以什么形态待着」在公开文档里由三组句子给出，而且**每组只给一个方向**：

- **进入方向三条**：`A/uniformtypeidentifiers_system_declared_uniform_type_identifiers.txt:5` 「Uniform type identifiers declare common types for resources an app **loads, saves, or opens from other apps**」。这是全篇唯一一处把「内容从哪来」写成枚举的地方，它的粒度是三个动词，不是三个通道。
- **承载形态三条**：`A/uniformtypeidentifiers.txt:7` 明说这些类型描述帮系统正确处理「file storage formats or in-memory data for transfer——例如与剪贴板之间的传输」，并且「The identifier types can also identify other resources, such as **directories, volumes, or packages**」。同一份归档的 `:15` 「which implies the type can be a document」、`:17` 「which implies the type is representable as a byte stream」、`:20` 「a generic base type for most items in a file system, such as files or directories」把「文件 / 字节流 / 目录或包」四种形态挂在同一条派生链上（`public.png` → `public.image` → `public.content`／`public.data` → `public.item`）。包形态另有独立标识：`A/uniformtypeidentifiers_defining_file_and_data_types_for_your_app.txt:128、130` 的 `com.apple.package`。
- **位置与来源两条**：`A/uikit_uidocument.txt:34` 「you must pass a file URL locating the document file **in the app sandbox**」；`A/uikit_uiapplicationdelegate_application(__open_options_).txt:49` 「This resource can be a **network resource or a file**」。网页侧再给三个来源：`A/webkit_wkwebview.txt:21—22` 要求「Before your web view appears onscreen, load content from a web server using a `URLRequest` structure **or** load content directly from a local file **or HTML string**」。

执行域一侧的公开口径不在组 A，而只有一条：`B/apple-platform-security-guide.txt:2446` 「All apps from the App Store are **sandboxed to restrict access to data stored by other apps**」与 `:4740`（XNU 强制 code signing、sandboxing、entitlement checking 与 ASLR）。这两句说明**内容落在谁的沙箱里由承载 App 决定**，与内容自己声明了什么类型无关。引用 `:2446` 时必须带上它的平台段：这一句在 `:2438`「Gatekeeper and runtime protection in **macOS**」一节内，iOS 侧的对应句是 `:2393`（第 9 章逐字给出），两者不可互换。

### 4.2 这一格由哪一件持有

**声明件**，但持有人不是内容生产者而是**承载 App**。这是 L1 与 L2 的关键差别：L2 的类型声明由内容生产者写进包里的 `Info.plist`，L1 的来源面只能由登记方（做归属核验的人）在台账里补写——**内容字节里不带 provenance**。于是 `id.provenance` 与 `id.source_face` 是整张台账里仅有的两格「无法从对象本身读出、只能从旁证推」的格。

由此产生 L1 的两个失败点：

1. **把签名形态当来源形态**。台账里 `id.signature` 描述的是承载 App 的签名来源（`signed_store`／`signed_dev`／`signed_enterprise`／`signed_adhoc`／`unsigned`／`platform_binary`／`remote_no_signature`），`id.provenance` 描述的是内容怎么到设备上（`local_user_created`／`remote_untrusted`／`remote_trusted`／`app_built_in`／`system_built_in`／`mdm_delivered`）。写「App 来自 App Store」推不出「这份附件是可信来源」——脚本一的 **A02** 专门拦这对矛盾（`remote_untrusted` 却记 `signed_store`／`platform_binary`）。
2. **来源不可判却给了确认结论**。`id.provenance = not_determinable` 与 `doc.conclusion = confirmed` 同时出现时触发 **A01**。这一条没有对应的公开句子，它是本篇的**写法约束**：来源面拿不到旁证时，结论档位必须降级。

### 4.3 谁读得回它

三处，且都不给逐条对象的读数：

1. **管理面**：`C/readings-18.txt:95` 给出可约束「内容能否被打开／预览／联网取回」的 19 个键（`allowAirDrop`、`allowAppClips`、`allowSafari`、`requireManagedPasteboard` 等），它们约束的是**进入通道开不开**，不是这一条内容从哪条通道进来。
2. **公告面**：`C/advisory-18.tsv:1` 的六列是 `file／platform／component／cve／impact／avail`——**没有来源列**。公告永远不告诉你恶意构造对象是从哪条通道进的设备。
3. **KEV 面**：`C/kev-apple.tsv:2` 给 `dateAdded` 与 `dueDate` 两列，形如 `YYYY-MM-DD`。这是唯一一处「时间」读数，但它是**目录收录时间**，不是内容到达时间；脚本一把日期形态统一按这一格校验（S08），防止有人把到达时刻写成自由文本。

`A/uikit_uidocument.txt:34` 要求台账写文件 URL，而本篇的拒收清单禁止设备绝对路径。这一处冲突按**台账侧让步**处理：`id.source_face` 只登记枚举值，不登记路径；触发 **K02** 的判据是取值形似设备绝对路径、长载荷或密钥串（`/var/mobile/`、`/Users/…`、40 字符以上的 Base64 形状、`glpat-`/`ghp_`/`AKIA`/`Bearer `/`-----BEGIN` 开头）。**这是本篇唯一一处公开口径与拒收规则直接对撞的格。**

### 4.4 台账字段与信号口径

**台账字段**：`id.obj_kind`、`id.container_kind`、`id.source_face`、`id.provenance`、`id.signature`、`id.container_size_bucket`；`doc.source`。
**信号口径**：脚本一的 S 族拦行式与命名空间（S01 列数不足、S02 对象标识为空、S04 未登记命名空间、S05 清单外字段、S06 取值为空、S07 枚举越界），S09 拦 `id.obj_kind`／`id.source_face`／`id.provenance` 三格缺失（必备格，缺任一落 J4），K02 拦路径与载荷形状，A01／A02 如 4.2。脚本二把「内容来源」独立成清单第 9 列（`local_copy／remote_download／received_share／message_attachment／web_page／clipboard`），并要求对象标识前缀与对象类一致——**S10** 拦前缀与对象类不符，**S02** 拦标识为空或含空白（无法与三件能力表对齐）。前缀之所以要单独校验，是因为 `C/subset-18.txt:19—42` 证明同一份内容在两份文档里的清单段行号不同，台账只能靠前缀定位。

---

## 5. L2 类型声明层：内容自带的三张票

### 5.1 这一格的公开口径

声明层是全文档口径最密的一层，`A/uniformtypeidentifiers_defining_file_and_data_types_for_your_app.txt`（143 行）逐条给出：

| 口径 | 归档行 | 逐字要点 |
| --- | --- | --- |
| 声明四步 | `:5—10` | 在 `Info.plist` 里声明／新建或复用标识／定义对系统类型的一致性／列出关联的扩展名或 MIME |
| 二选一 | `:12` | 「you need to define it as an **exported or imported** type… If your app uses a type that this framework provides, **don't redeclare it** in your app's bundle」 |
| 导出＝源 | `:13` | 「Define an exported type when your app is the **canonical source** of information for that type」 |
| 导入＝沿用 | `:14` | 「When importing a type from another app, **don't declare your own identifier**; instead, use the same type identifier as the original」 |
| 标识形态 | `:16—24` | 反向 DNS 起始，只含字母数字、连字符与点 |
| 三个保留前缀 | `:29—35`、`:118—123` | 不得使用 `public`／`dyn`／`com.apple`，并逐个给出 reserved 主体 |
| 一致性后果句 | `:42—46` | **「If your type doesn't conform to `public.data` or `com.apple.package`, the system can't tell if a stored item has that type.」**（同段前半句要求文档类型 conforms to 这两个标识，理由是「to ensure the Finder or Files app can represent it」） |
| 共享后果句 | `:47—49` | 文档类型须一致到 `public.content`，「This conformance allows users to share your type over **AirDrop**」 |
| 最具体子类型 | `:50—52` | 「Conform your type to the most specific subtype applicable」 |
| 非公共父类型 | `:53` | 「If you specify conformance to a nonpublic type, make sure that you **also declare that type** in your bundle」 |
| 标签字典 | `:61—65`、`:140` | 扩展名与 MIME 写进 `UTTypeTagSpecification`，键为 `public.filename-extension` |
| 键表 | `:69—88` | 七个键；`:78` 「**This key is required for type declarations.**」（`UTTypeIdentifier`）；`:82` 一致性数组；**`:88` 「If both exported and imported declarations for a type exist, the exported declaration takes precedence over the imported declaration」** |
| 所有权措辞 | `:89—102` | `UTExportedTypeDeclarations` = 「owned **and exported** by the app」；`UTImportedTypeDeclarations` = 「inherently supported, but **not owned**」 |

系统侧的分母另给一份：`A/uniformtypeidentifiers_system_declared_uniform_type_identifiers.txt:5`（清单只覆盖系统声明的公共类型）、`:24` 起逐条以「A type that represents …」开头，共 201 条（`C/readings-18.txt:99`），按类别切 12 档（`:100—111`），提及 conforming／base type／declare 的行 67（`:112`）。`A/uniformtypeidentifiers.txt:53—54` 那句「Declare uniform type identifiers to support your app's proprietary data formats.／Common types that the system declares.」是**自定义声明与系统声明分属两份文档**的公开依据。

### 5.2 这一格由哪一件持有

**纯声明件**。这一层有三条结构性事实：

1. 每一格都由内容生产者或承载 App 自己填，**没有任何一格是系统判定之后写回的**。
2. 全篇唯一一处优先级规则是 `:88` 的「导出优先于导入」，它只解决**同一类型两份声明并存**，不解决声明与字节内容冲突。
3. `:78` 的「必需」只约束声明文件本身合法，不约束这份声明会被读到。一条完全合法的声明可以永远没有读数。

由此产生声明层的失败点：**声明权不等于通道权**。台账里把「App 声明了这个类型」写成「这类内容会被判成这个类型」时，脚本二落 **T01／T02**（声明件记了、通道件与观测件一条没有；或不一致到 `public.data`／`com.apple.package` 时系统本就判不出）；（**K03／K04／K05**，逐个字按 `:29—35` 的 `public`／`dyn`／`com.apple` 拦，且这三码只守 `declared_uti` 一格——`conforms_chain` 里出现 `public.` 与 `com.apple.` 父类型是公开口径要求的正常写法）说明这一格不是照公开材料登记的。

### 5.3 谁读得回它

**没有平面会给出「系统这一次把这份内容判成了什么」的读数。** 脚本二的 23 个读数平面里有三个是**登记来源平面**（`plist_declaration`、`uttype_framework`、`tag_mapping_api`）——它们说明这一格的值抄自哪份声明或哪个反查接口，不说明某一对象在运行时被判成了什么。剩下的平面里，公告六列没有类型列（声明件核对项记在公告面直接触发 **P03**），218 个限制键没有一个指向类型声明，设置界面不显示某份内容被声明成什么。

因此声明层只能以两种方式进入对外表述：(a) 作为**声明件的一格**，与同一对象的通道件、观测件配对出现；(b) 作为**公开口径**被引用（例如 `:42—46` 那句后果句可以支撑「不声明一致性则系统判不出」这类一般结论），但不能被当作某个具体对象的判定证据。第二种用法在脚本二里由引用格承担：引用格必须是**公开词表值**或**文档行号形态**二者之一（都不是时落阻断码 **V02**，其判据出处正是 `:87、98`——声明本身允许挂一个描述该类型的参考文档，所以文档行号是合法引用形态）；而一个对象所有 required 核对项的引用格全为无标识时，结论无法回指任何一格，落 **V01**。

### 5.4 台账字段与信号口径

**台账字段**：`typ.declared_uti`、`typ.declared_mime`、`typ.filename_ext`、`rights.exported_type_declared`、`rights.content_owner`。
**信号口径**：脚本一 B08 一格三检（UTI／MIME／扩展名各按自己的形态规则，判据 stem 写明是哪一票）、A03 拦包标识形态、S07 拦 `rights.*` 枚举与布尔位越界、S09 在 `typ.type_source` 缺失时落 J4。`typ.declared_*` 三格允许 `not_applicable`（这一票本就不存在），但不允许空值——空值等同未登记（S06）。脚本二对应声明件七个核对项：`declared_uti`、`declared_mime`、`filename_ext`、`conforms_chain`、`decl_ownership`、`tag_spec`、`pkg_layout`；其中 `conforms_chain`／`filename_ext`／`tag_spec` 是**数组型**（同一对象可多行，逐行一个值，重复值按 **S08** 报、两种登记口径按 **S09** 报），`decl_ownership` 只接受 `exported／imported／system_declared` 三值（`:12—14`），M01—M06 按公开词形逐格校验；D 族按能力表逐类给覆盖空洞：**D01**（该类需要这一项，台账却明确记为不存在）、**D02**（required 项完全没有登记行，对应 `:78` 的必需键）、**D03**（required 项被记成不适用，与能力表冲突）、**D04**（这一对象类在能力表里一行都没有，缺哪一格无从判定）、**D05**（某个核对项在整张清单里零登记）。

---

## 6. L3 承载方身份层

### 6.1 这一格的公开口径

身份层的公开口径全部围绕「谁的包」与「谁拥有这个标识」两句：

- **包是声明的容器**：`:12` 的「don't redeclare it **in your app's bundle**」与 `:14` 的「use the same type identifier **as the original**」共同说明：一条声明的可追溯对象是**包**，不是开发者本人。
- **所有权两词**：`:89` 「owned and exported by the app」／`:101` 「inherently supported, but not owned, by the app」。这是全篇唯一一处把「拥有」写成公开措辞的地方，也是 `rights.content_owner` 与 `rights.owns_document` 两个字段唯一的公开锚点。
- **沙箱位置**：`A/uikit_uidocument.txt:34`（文件 URL 必须在 App 沙箱内）与同类句 `:593、628、731、756`（四处 in the application sandbox）。`:56—60` 另给一条冲突口径：`UIDocument` 采用 `NSFilePresenter` 协议，**当另一个客户端尝试读取该文档时，系统会挂起读取**，直到该对象有机会保存修改——这是公开文档里唯一一处「两个承载方同时接触同一份内容」的排序规则。
- **扩展的身份边界**：`B/apple-platform-security-guide.txt:2557`（自定义键盘扩展默认在极受限沙箱内运行，要联网需申请 Open Access 且**先取得用户同意**）；`:2446`（App Store 的 App 一律沙箱化，跨 App 取数只能走系统提供的 API 与服务）。
- **分享面板的角色划分**：`A/uikit_uiactivityviewcontroller.txt:3` 「standard services **from your app**」、`:10—11` 「The system provides several standard services… **Your app is responsible for configuring, presenting, and dismissing** this view controller. Configuration… involves specifying the **data objects on which the view controller should act**」——服务由系统给，被作用的数据对象由 App 指定。这一句同时给出 L3 与 L8 的分工，脚本二把 `activity_share` 归到通道件、把面板提示归到观测件。

### 6.2 这一格由哪一件持有

**声明件填写、通道件生效**。`id.bundle_id`／`id.team_id`／`id.signature` 三格由登记方从包上抄（声明件），但它们决定的是「哪条通道有权读这份内容」（通道件效果）。`rights.sandbox_profile` 是这一层里唯一**不由 App 自报**的格——它的合法取值（`app_sandbox／extension_sandbox／restricted_helper／detached_renderer／kernel_none／not_determinable`）只能来自平台口径，而平台口径在本篇归档里只给到 `:2446`／`:2557` 两句一般性描述，**没有任何一句给出「这个进程用的是哪份沙箱画像」的读数接口**。因此 `rights.sandbox_profile` 与 `dom.*`（第 9 章）之间存在一条必须写明的关系：前者是权利面，后者是执行面，二者可以分别缺失，**不能互相补位**。

### 6.3 本层的失败点：身份形态与所有权措辞

**失败点（团队标识形态）**：公开口径里团队标识是 **10 位字母数字串**，脚本一按 `/^[A-Za-z0-9]{10}$/` 校验，写成别的形状（长度不符、含连字符、含空格、写成团队名）时报 **A06** 并计入阻断。判据不是「这个值不对」，而是一个方法论结论：**登记成别的形状，说明这一格不是从公开材料抄来的**——它是被推测或被转述的。同一族里 `id.bundle_id` 按反向 DNS 字符集校验（**A03**，锚点 `:16—17`：标识需唯一、以反向 DNS 形态起始、只含字母数字），两格都用 `not_recorded`／`unknown` 表示未登记，用 `not_applicable` 表示这一格在本对象上不存在（例如系统内建承载方没有团队标识）。

本层另外三个可复现的失败点：

1. **所有权措辞被放宽**：把 `:89`「owned and exported」写成「这个类型是它的」，同时把 `:101`「inherently supported, but not owned」也写成同一种归属。两份清单在公开口径里是两种权利，台账必须用 `decl_ownership` 的三个取值区分——写成自由文本时，脚本二的 M06 报「这一格的引用值不在公开词形表里」（`exported／imported／system_declared` 三值之外的任何说法，包括「我们的类型」）。
2. **身份与来源串台**：用 `id.signature` 支撑 `id.provenance`（见 4.2 失败点 1）。
3. **跨承载方推断**：由「A App 能打开这类内容」推「B App 打开同一份内容也判成同一类型」。`A/quicklook.txt:18` 与 `A/quicklook_qlpreviewcontroller.txt:22` 两次声明清单会随版本变化，`A/uikit_uiapplicationdelegate_application(__open_options_).txt:4` 更是明说同一条「打开」语义有两套公开口径（旧委托方法已被 `scene(_:openURLContexts:)` 取代）——身份层的任何跨承载方结论都必须落进行号（脚本一 **X01**）。

### 6.4 谁读得回它

两处间接读数：`B/apple-platform-security-guide.txt:2388`（App 侧防护由 App Review 与平台保护共同构成——说明「这个 App 被审过」是**平台侧有过一次判定**的事实，但不给类型）；`C/advisory-18.tsv` 的 `component` 列（公告给的是**系统组件名**，不是承载 App 的标识）。管理面对身份层的可配面只有一格：`B/mdm-restriction-keys.txt:162` 的 `allowedCameraRestrictionBundleIDs` 是唯一一个以包标识为取值的限制键，它约束的是相机能力的允许名单，**不约束内容判定**。

身份层其余格全部只能登记，不能读回。因此本篇对身份层的对外表述上限是：**「某包标识与某团队标识在台账里被登记为这份内容的承载方」**，到此为止；不写「因此它有权解析」或「因此它被授权处理该类型」。

### 6.5 台账字段与信号口径

**台账字段**：`id.bundle_id`、`id.team_id`、`id.signature`、`rights.content_owner`、`rights.owns_document`、`rights.open_mode`、`rights.sandbox_profile`、`rights.requires_user_consent`。
**信号口径**：脚本一 A03／A06（形态），S07（`rights.*` 枚举与布尔位），S09（`id.provenance` 属必备格）；脚本二 K01（引用格形似密钥、归档文件、设备绝对路径或整段载荷正文时只登记引用标识，不登记内容——身份层最容易把包路径整段抄进引用格）、T04（`:53` 指定非公共类型的一致性时必须同时在自己的包里声明该类型：承载方身份与父类型归属必须同侧）、D03（对象类的某个反查核对项在公开口径里不适用——扩展名反查与 MIME 反查分属两条通道，`A/uniformtypeidentifiers_system_declared_…:8—17`——却登记了已读数）。

---

## 7. L4 类型判定层

### 7.1 这一格的公开口径

`typ.type_source` 的六个合法取值，逐个字给出处；两个没有出处的取值单独说明：

| 取值 | 公开锚点 | 逐字要点 |
| --- | --- | --- |
| `declared_by_owner` | `A/uniformtypeidentifiers_defining_…:12—14` | 判定来自内容自带的导出／导入声明 |
| `sniffed_content` | `A/imageio.txt:3、6` | 「Read and write most image file formats, and **access an image's metadata**」——读的是字节，文件名不参与；类型来自内容本身 |
| `system_inferred` | `A/uikit_uidocument.txt:35` | 「determines the file type (**the Uniform Type Identifier associated with the file extension**) and the document name… **from the file URL**」——由扩展名反查 UTI |
| `extension_only` | 同上 `:35` 与 `A/uniformtypeidentifiers_system_declared_…:8—13、20—23` | 只有 `filenameExtension`／`UTTagClassFilenameExtension` 一条标签参与时，判定退化为一票 |
| `vendor_claim` | **无公开锚点** | 厂商说法不是系统判定；写进这一格即阻断（B05） |
| `assumed` | **无公开锚点** | 登记方的假定不是判定；同样阻断（B05） |

标签与结论的分别在两份文档里各有一句：`A/uniformtypeidentifiers.txt:7` 说框架「provides a collection of common types that **map to** MIME and file types」——框架只做映射；`A/uniformtypeidentifiers_system_declared_…:8—19` 给出两个标签类属性（`filenameExtension` 与 `mimeType`，各自 `:20—23` 的 `UTTagClassFilenameExtension`／`UTTagClassMIMEType`），`:84—87` 与 `:270` 则说明归档类与字体类同样只是被声明的公共类型。**没有任何一句规定标签冲突时听谁的。**

网页通道把这条缺口放大：`A/webkit_wkwebview.txt:761、765、776` 的 `loadData(_:mimeType:characterEncodingName:baseURL:)` 要求**调用方自己断言** MIME 与编码；`A/webkit.txt:8` 「Display **multiple** MIME types and compound frame elements」。同一份字节可以因调用方给出的 MIME 不同而进入不同判定。预览通道另有第三种：`A/quicklook.txt:17` 允许自有类型「by either rendering a view with your own view controller or by returning a supported preview format, **such as PDF or HTML**」——预览结果类型与被预览内容类型不是同一个格（**N05**：登记有提示却说告知文本不适用，同族错位在脚本一里另有判据）。

### 7.2 这一格由哪一件持有

**三件都在场，但没有仲裁件**。声明件给票（L2），通道件给反查（L5 与本章），观测件只能给后果（L9 与第 13 章）。判定层没有第四件来裁决三者分歧——这是本篇与第 16 篇的第二个轴差：16 篇的第二件是权限件（系统判定并持有），本篇的第二件是通道件（框架能否把这一格读回来），而**通道件不裁决，只放行**。

于是判定层的三条可数漂移：

1. **三票全无**（B01）：`typ.declared_uti`／`declared_mime`／`filename_ext` 三格同时为 `not_applicable`。此时判定只能靠内容嗅探或承载方假定，台账必须显式写 `type_source`。
2. **一票独大**（B02）：只有扩展名有值且 `type_source = extension_only`。这条合法但必须标注——`A/uikit_uidocument.txt:35` 说的正是这条通道，而它是**唯一一条把扩展名写成判定来源的公开句子**。
3. **两票相异**（B03）：`typ.sniffed_type` 与 `typ.declared_uti` 都有值且不等，却把 `typ.type_conflict` 记成 `none`。这是判定漂移的实证形态；`type_conflict` 的四个合法取值（`none／recorded／unresolved／not_applicable`）里只有 `recorded` 与 `unresolved` 承认漂移存在，**unresolved 而结论写 confirmed 触发 B04**。

### 7.3 判定层与公告面的接口

公告列只回答「哪个组件」，不回答「判成了什么」。三条实测接口：

- 后果句的五类（`C/readings-18.txt:26—30`：unexpected app termination 133 行、disclosure of 84、bypass 78、memory corruption 77、arbitrary code execution 58）**没有一类写「内容被误判类型」或「被自动解析」**；按 `opened as`／`rendered as`／`incorrectly`／`assumed` 四个词形扫影响句，命中 **0 行**；第五个词形 `identif` 命中 2 行（`C/advisory-18.tsv:78、226`，同为 Maps／`CVE-2026-112707`，句子是「An app may be able to identify what other apps a user has installed」，与类型判定无关）。
- 列间错位（`:55—59`）：影响句写明恶意构造对象、组件名却不含任何解析层词的 46 行，其中 `image` 16 行、`file` 19 行、`web content` 0 行、`font` 0 行；错位名单前 12 个组件（`:60—71`）里 `libarchive`、`ArchiveService`、`Accelerate Framework`、`Core Image` 四个按名字看像解析层，按词表比对却落在解析层词形之外。
- WebKit 同族自洽（`:115—117`）：组件名以 WebKit 开头的 165 行里，157 行含 crafted、161 行含 web content。同族组件下对象词几乎恒为一类——**这条正例正是 B03／R05 的分母**：能自洽的地方不代表别处也自洽。

因此判定层的对外表述上限是：**「同一份字节在通道 X 上被判成 Y，登记依据是 Z 票」**，不写「系统把它误判成 Y」或「导致解析失败」——后者需要后果句支撑，而后果句没有这一类（失败 3）。

### 7.4 台账字段与信号口径

**台账字段**：`typ.type_source`（必备格）、`typ.sniffed_type`、`typ.type_conflict`、`typ.resolver_choice`、`doc.conclusion`、`doc.source`、`doc.line_ref`。
**信号口径**：脚本一 B 族七个码（B01 三票全无、B02 只用扩展名、B03 嗅得与声明相异却记无冲突、B04 冲突未解却给确认、B05 依据为假定或厂商说法、B06 解析对象已知但解析器选择未登记、B07 解析器选择不可判却给确认、B08 三票形态）＋ X01（确认结论缺来源文件或行号）＋ X02（行号引用形态）。`typ.resolver_choice` 的七个合法取值（`system_default／app_declared／importer_plugin／extension_quicklook／web_engine／host_library／not_determinable`）里，只有 `web_engine` 与 `extension_quicklook` 两格有公开框架文档支撑（`A/webkit_wkwebview.txt`、`A/quicklook.txt:19—22`），其余五格只能作为登记方的推断面存在，必须在 `doc.line_ref` 里落到能支撑它的那一行。脚本二对应通道件七个核对项（`uti_lookup／ext_lookup／mime_lookup／decode_entry／preview_entry／open_entry／resolved_uti`）：两格标识值（`declared_uti`／`resolved_uti`）必须回指公开词表，回指不到时落 **X05**（框架符号与 `plist` 键回指不到落 X06，扩展名与 MIME 标签回指不到落 X07）；M06 拦「引用值不在这一格的公开词形表里或是它的近义词」（判据出处是 `:52`——要一致到最具体的子类型，泛化的自造词无法回指）；`resolved_uti` 与 `declared_uti` 不同时还有一码专拦：**T06**（反查回来的类型既不同于声明、又不在声明的一致性链上）。

---

## 8. L5 解析装配层

### 8.1 这一格的公开口径

装配层由两半组成：**框架半**有公开文档，**实例半**没有。

框架半的句子逐字如下：

- `A/imageio.txt:6` 「The Image I/O framework allows applications to read and write most image file formats. This framework offers high efficiency, **color management**, and access to image metadata」；`:40` 写出口（write to a URL, data object, or data consumer）、`:56` 写入口（**read image data from a URL, data object, or data consumer**）、`:44、52、64` 给出元数据对象家族（XMP、单条元数据、可变元数据）。同一份图像数据有三条读回通道，这是复位面（第 14 章）必须区分「删了文件」与「断了通道」的依据。
- `A/coregraphics.txt:3、6` 把「image data management, image creation, and image masking, as well as **PDF document creation, display, and parsing**」划给框架本身；`:19、55、95` 给出颜色空间、色彩转换与 ICC 描述句。位图与 PDF 的解析同样是框架职责，不是 App 职责。
- `A/webkit_wkwebview.txt:13` 「a **platform-native view** that you use to incorporate web content」＋ `:21—22`（内容必须由调用方显式交给它）＋ `A/quicklook.txt:14`（USDZ 模型还能进 AR 视图）。
- `A/uikit_uidocument.txt:13—17`（异步读写、云协调、版本冲突发现、safe-saving、自动保存）与 `:38—49`（文档生命周期五段：创建／打开／编辑／可选云端整合／关闭）给出**文档类装配的可登记段**；`:566—568` 的 `open`／`:895` 的 `openWithCompletionHandler:` 是打开动作的符号名。
- `A/quicklook.txt:19—22` 给出扩展装配：自建 Quick Look 预览扩展，并把受支持类型加进扩展 `Info.plist` 的 `QLSupportedContentTypes` 数组。这一句是**唯一一处 App 可以把自己插进解析链的公开口径**。

实例半（哪一个进程、哪一个解析器、哪一条 XPC 端点）**在本篇归档里没有公开口径**。`A/` 组没有 Model I/O、SceneKit、RealityKit、AVFoundation、FontParser、libarchive 的文档件；脚本一 `asm.parser_framework` 枚举里的那些名字，其**唯一来源是公告组件列**（`C/readings-18.txt:33—52`），不是框架文档。这一点必须在正文里写明，否则装配层会变成「凭组件名想象实现」。

### 8.2 这一格由哪一件持有

**通道件**。持有人是框架与承载 App 的装配选择，不是内容生产者。四个可登记的装配位：`asm.parser_framework`（必备格）、`asm.parser_layer`（必备格）、`asm.process_kind`、`asm.host_process`，另有 `asm.xpc_service`、`asm.runs_in_extension`、`asm.third_party_codec` 三个补充位。

三个可数失败点：

1. **进程种类未登记**（C01，累计 192 次）：只写「在某个进程里解析」等于没写。
2. **宿主缺失**（C03，累计 198 次——C 族最高频信号）：`asm.process_kind` 有值但 `asm.host_process` 空，且该种类不是 `kernel_task`／`not_recorded`。
3. **端点与身份矛盾**（C04）：声明为 `xpc_helper` 却把 `asm.xpc_service` 记成 `not_applicable`。**服务清单、端点校验与 Mach 层归第 06 篇**，本篇只登记「有／无端点标识」这一格，不重建服务名单。

扩展与第三方两格各有独立判据：`asm.runs_in_extension = true` 而无 `rights.sandbox_profile`（C05，锚点 `:2557`）；`asm.third_party_codec = true` 却把 `asm.parser_framework` 记成 `none`／`not_applicable`（C07，锚点 `A/coregraphics.txt:6`——框架本身承担解码时不需要这一格，用了第三方就必须登记）；`third_party_codec = true` 且执行域为 `privileged_extension`（C06）是本篇唯一一处「装配选择与执行域直接矛盾」的组合，判为阻断。`asm.parser_layer = kernel_filesystem` 而未记内核域，落 C02（锚点 `C/subset-18.txt:9`：`APFS` 2 行、`HFS` 5 行、`CoreStorage` 2 行——三个文件系统组件在恶意构造子集里，组件名却不含任何解析层词形，所以「内核文件系统层」这一格只能由登记方按公告组件名加平台口径共同给出，缺一侧就断）。

### 8.3 谁读得回它

**两个平面，且都不给堆栈。**

1. **公告面**：`C/readings-18.txt:33—52` 给出 top-20 组件的「含 crafted 行 ÷ 全组件行」比值。20 个组件里 **11 个落在全含线上**（比值 1/1）：`ImageIO` 79/79、`CoreGraphics` 15/15、`RealityKit` 8/8、`ColorSync` 8/8、`BOM` 8/8、`WebRTC` 8/8、`CoreText` 8/8、`WebKit JavaScript Bindings` 7/7、`Accelerate Framework` 6/6、`WebKit Canvas` 6/6、`LinkPresentation` 5/5；**9 个明显不在**：`WebKit` 139/143、`Model I/O` 37/43、`SceneKit` 22/29、`FontParser` 21/26、`CoreAudio` 13/37、`AppleAVD` 12/21、`Audio` 8/11、`CoreMedia` 8/22、`Mail` 6/15。**「这个组件出现在公告里」与「这个组件是解析层」是两次判定**，脚本一分别用 R03（组件名不属于解析层却用来给确认结论）与 R05（对象词为 image 但组件名与之无关且未核对）拦这两次。
2. **崩溃面**：只允许登记报告标识本身。`obs.crash_report_ref` 的合法形状是 6—40 个 `[A-Za-z0-9-]`，或 `absent`／`not_applicable`；写成堆栈片段、路径或带空格的描述触发 **K03**（判据逐字见第 12 章：崩溃引用只登记报告标识，不粘贴堆栈正文）。

管理面对装配层没有可配面：`C/readings-18.txt:93` 的 6 个命中键里 5 个是 `safari*` 行为键，约束的是网页内容获取行为，没有一个键指名解析器或解码器（**G04／C06** 的分母）。

### 8.4 台账字段与信号口径

**台账字段**：`asm.parser_framework`（必备格）、`asm.parser_layer`（必备格）、`asm.host_process`、`asm.process_kind`、`asm.xpc_service`、`asm.runs_in_extension`、`asm.third_party_codec`；`adv.component`、`adv.component_is_parser_layer`。
**信号口径**：脚本一 C 族七个码（C01—C07）＋ R 族五个码中与组件相关的 R01／R03／R05（R01：登记了 impact 对象词却没有组件名；R03：组件名不属于解析层却给确认结论；R05：对象词与组件名无关且未核对）。脚本二对应 `decode_entry`（`CGImageSource／CGAnimateImageAtURLWithBlock／WKWebView／UIDocument／QLPreviewController`）、`preview_entry`（`QLPreviewController／ql_extension／none`）、`open_entry`（`application_open／scene_openurl／uidocument_open／activity_share／none`）三项；P05 拦「某类内容只有类型声明面、没有解析入口文档面」——**字体与归档两类正是这种情形**（`A/uniformtypeidentifiers_system_declared_…:84—87、270` 有 `archive` 与 `font` 两个基类型，而组 A 没有任何一份字体或归档解析文档），这条不是缺陷，是本篇归档面的边界，必须原样登记。

---

## 9. L6 执行域层：沙箱、entitlement 与内存安全类

### 9.1 这一格的公开口径

这一层有一个必须先说的结构性事实：**组 A 的十二份框架文档里，没有一句描述「解析发生在哪个域」。** 执行域的全部公开口径都在组 B（平台安全指南），而且**集中在一节之内**——`:2391` 一句话给出三件套：「iOS, iPadOS, and visionOS help ensure runtime security by using a **sandbox**, declared **entitlements**, and Address Space Layout Randomization (**ASLR**)」。本篇 `dom.*` 的七个字段就是从这一句拆出来的，拆法照原文顺序。

四组支撑句：

- **沙箱段**（`:2392` 段标题起）：`:2393` 「All third-party apps are sandboxed. Sandboxing is designed to prevent apps from gathering or modifying information stored by other apps or from making changes to the device. Each app has a **unique home directory** for its files, which is **randomly assigned when the app is installed**. If a third-party app needs to access information other than its own, it does so **only by using services explicitly provided by** iOS, iPadOS, and visionOS」；`:2394` 「Most … system files and resources run as the **nonprivileged user mobile**, as do all third-party apps. The entire operating system partition is mounted as **read-only**…APIs don't allow apps to escalate their own privileges to modify other apps or iOS, iPadOS, and visionOS」。
- **entitlement 段**（`:2395` 段标题起）：`:2396` 「Access by third-party apps to user information, and to features such as iCloud and extensibility, is controlled using **declared entitlements**. Entitlements are key-value pairs that are **signed in to an app**…**Since entitlements are digitally signed, they can't be changed**. Entitlements are used extensively by **system apps and daemons** to perform specific privileged operations that would otherwise require the process to run as root」；`:2397` 「apps can only perform **background processing through system-provided APIs**」（这一句同时是 L7 的锚点，第 10 章按触发侧再引一次）。
- **内存安全段**：`:2404` ASLR「helps protect against the exploitation of memory corruption bugs…Built-in apps use ASLR…Xcode, and the iOS or iPadOS development environments, **automatically compile third-party programs with ASLR support turned on**」；`:2405—2406` Execute Never 与 JIT——「The kernel checks for the presence of the Apple-only **dynamic code-signing entitlement**. Even then, **only a single mmap call** can be made to request an executable and writable page…Safari uses this functionality for its **JavaScript just-in-time (JIT) compiler**」；`:1333` Memory Integrity Enforcement「a comprehensive memory safety defense…**available on A19 and M5 processors or later**…always-on memory safety protection for key attack surfaces **including the kernel**」；`:1322` 指针签名「The signature is **verified before use**…**Failure to verify results in an abort**」。
- **隔离机制段**：`:1441—1443` BlastDoor——`:1441` 「The goal of BlastDoor is to help protect the system by **corralling attackers**…BlastDoor **isolates, parses, transcodes, and validates untrusted data** arriving in Messages, IDS and other vectors」，`:1442` 「by employing **sandbox restrictions and memory safe validation of output**」，`:1443` 「**segmenting known versus unknown data into distinct BlastDoor instances**」；`:1446` 锁定模式「certain apps, websites, and features are **strictly limited** for security, and some experiences might not be available at all」，`:1448` 「Lockdown Mode makes **tradeoffs** for increased security at the expense of functionality, performance, or both. These tradeoffs impact: • Background services」。
- **内核与扩展两个域**：`:4740`「XNU The kernel at the heart of the Apple operating systems. It's **assumed to be trusted**, and it enforces security measures such as code signing, sandboxing, entitlement checking, and Address Space Layout Randomization (ASLR)」；`:2555`「**Extensions run in their own address space**. Communication between the extension and the app from which it was activated uses interprocess communications mediated by the system framework. They don't have access to each other's files or memory spaces…**They are sandboxed like any other third-party app and have a container separate from the containing app's container. However, they share the same access to privacy controls as the container app.** If a user grants an app access to Contacts, this grant is extended to the extensions that are **embedded within** the app **but not to the extensions activated by** the app」。

最后这一句是 `dom.domain_class` 里 `helper_detached`／`renderer_detached`／`privileged_extension` 三个取值能分开的唯一依据：**同样是扩展，嵌入式与被激活式在权限传导上不同形**。而 `:2446` 那句（第 4 章引过）在 macOS 一节内，不能作为 iOS 侧沙箱口径的替代引用。

### 9.2 这一格由哪一件持有

**本篇十一层里唯一一层「登记方只有引用权、没有填写权」的层。** L2 的类型声明由内容生产者写进包里，L5 的装配由框架与承载 App 的选择决定，而 L6 的执行域**由平台决定，登记方只能选一个"依据"来支撑自己写下的那一格**。这就是 `dom.domain_source` 存在的原因：它的七个实值（`platform_doc`／`advisory`／`crash_report`／`mdm_status_item`／`vendor_claim`／`screenshot`／`assumed`）不是七种域，而是**七种「你凭什么说这一格是这个域」**。

三条结构性事实：

1. **归档里没有任何一句「某类内容由哪个进程解析」。** `:2393` 说的是 App 与 App 之间隔离，`:2396` 说的是 daemon 需要特权操作，`:2555` 说的是扩展的地址空间——**没有一处把「一份图像数据」映射到「ImageIO 在哪个进程里跑」**。所以 `dom.domain_class` 的 `system_service` 与 `privileged_extension` 两值只能由公告组件名（组 C）加平台口径（组 B）共同推出，缺一侧就断。
2. **执行域与解析装配是两层，但公开句子在同一节里给出。** `:2391` 一句话里同时有 sandbox（域）与 entitlement（权利），而 `A/imageio.txt:6` 一句话里有编解码（装配）。**两层的字段不可互相补位**：写了 `asm.parser_framework = ImageIO` 不能推 `dom.domain_class`，写了 `rights.sandbox_profile` 不能推 `dom.memory_safety_class`。本篇把这条写成两个判据：`dom.domain_class` 有值而 `dom.domain_source` 缺位落 **D01**（登记了执行域却没写它的来源平面）；`asm.*` 与 `dom.*` 的交叉矛盾由 C02／C05／C06 拦。
3. **内存安全类是版本与代际相关的读数。** `:1333` 把 MIE 限定在「A19 and M5 processors or later」，`:2404` 说内置 App 与第三方编译产物都用 ASLR。因此 `dom.memory_safety_class` 只能与 `adv.fix_version`／平台版本一起读；写成设备无关结论是台账错误（`:180` 给出本指南的版本覆盖，R06 按「平台名 + 主.次」形态校验版本号）。

四个失败点与判据（逐字按脚本一的 emit 条件）：

| 码 | 判据（代码里的条件） | 本层的含义 |
| --- | --- | --- |
| C02 | `asm.parser_layer = kernel_filesystem` 且 `dom.domain_class` 不是 `kernel`／`not_recorded`／`not_determinable` | 把内核文件系统层的解析记在用户域里 |
| C05 | `asm.runs_in_extension = true` 且 `rights.sandbox_profile` 为空 | 在扩展进程内解析却没有沙箱画像（锚 `:2555、:2557`） |
| C06 | `asm.third_party_codec = true` 且 `dom.domain_class = privileged_extension` | 第三方编解码在特权域内执行——**本篇唯一一处装配与域的硬矛盾，判为阻断** |
| D02／D03／D04／D05 | 自动处理且隔离为 `none`／`legacy_unsafe` 且 ASLR 明确未启用／`jit_allowed = true` 且域不是 `renderer_detached`／`app_sandboxed`／`not_recorded`／`entitlement_needed = required` 且沙箱画像缺失或不可判 | 四条「域内缓解措施与声明不自洽」；D04 的直接依据是 `:2406`——公开口径里 JIT 的那一处例子是 Safari 的 JavaScript 编译器 |

`dom.entitlement_needed` 的枚举只有 `none`／`required`／`unknown` 一类，**没有登记具体 entitlement 名的字段**。这不是遗漏：本篇归档里没有 entitlement 名单件（`:2396` 只说它是签名过的键值对），所以台账只能记「需不需要」，不能记「哪一条」。

### 9.3 谁读得回它

三处，全部是间接读数：

1. **崩溃面**：`A` 组没有崩溃文档件，但组 B 给了两条「域内校验会表现为崩溃」的句子——`:1335`「If the secrets don't match, **the app crashes, and the event is logged**」（Memory Tagging Extension）与 `:1322`「Failure to verify results in an **abort**」。**这两句只说明崩溃与执行域校验有关联，没有任何一句说明崩溃报告里能读出 `dom.*` 的哪一格**。因此本篇对崩溃面的登记纪律只有一句（见第 12 章）：崩溃引用只登记报告标识，不粘贴堆栈正文。
2. **管理面**：`dom.domain_source = mdm_status_item` 与观测平面里的 `settings_ui`／`configuration_profile`／`mdm_declaration` 能读出「某个限制键在这台设备上生效」，读不出「这一条内容当时在哪个域里被解析」。脚本二把这条写成 **P02**，判据文案逐字是「通道件核对项记在管理面平面上：**管理面关掉的是承载内容的 App，不是解析链本身**」。
3. **公告面**：`C/advisory-18.tsv:1` 的六列是 `file／platform／component／cve／impact／avail`——**没有域列，也没有进程列**。`adv.component` 是组件不是执行域，所以脚本二把「声明件核对项记在公告／KEV／崩溃面」判为 **P03**，理由句是「公告六列里没有类型声明列」。

**对外表述上限**：这一层最多说到「按平台文档，这一类承载形态运行在哪一类域里」，不能说到「这条内容就在这一格里被解析」——后者需要一个进程级读数面，而本篇归档里没有。

### 9.4 台账字段与信号口径

**台账字段**：`dom.domain_class`（9 个取值，6 个域）、`dom.isolation_mechanism`（8 个取值，4 个具名机制＋`none`）、`dom.memory_safety_class`（6 个取值，3 个内存安全档）、`dom.aslr_used`、`dom.jit_allowed`、`dom.entitlement_needed`（5 个取值，只有 `required`／`none` 两档是结论，其余是未登记档）、`dom.domain_source`（9 个取值，7 种依据，其中 `screenshot`／`assumed` 是劣化依据）。
**信号口径**：脚本一 D 族七码（D01—D06 加 C02 交叉）与本层同族；**脚本二也有 D 族（D01—D05），但两族同号不同义**——脚本一 D 族说的是执行域自洽性，脚本二 D 族说的是「能力表要求的核对项在台账里缺位」。台账跨脚本引用时必须带脚本名，这条纪律在第 19 章与第 23 章各落一次。

---

## 10. L7 触发条件层：打开、预览与分享之后的三种时点

### 10.1 这一格的公开口径

触发面由**四类动作句**给出，每类一句到两句，且都是 API 侧口径而不是安全侧口径：

- **打开**：`A/uikit_uidocument.txt:39—43`「You create a new document or open an existing document…To open an existing document (**selected by the user**), allocate and initialize an instance of your subclass and then call…」——`selected by the user` 是全篇唯一一处把打开动作与用户选择绑定的公开句子；`:47—49` 关闭并在有未保存改动时保存；`:566—568` 的 `open(completionHandler:)` 与 `:577、:895` 的 `openWithCompletionHandler:` 是符号侧证据，`:578`「**Schedules a document-reading or document-writing operation on a concurrent background queue**」。URL 打开侧有 `A/uikit_uiapplicationdelegate_application(__open_options_).txt:3`「Asks the delegate to open a resource specified by a URL, and provides a dictionary of launch options」与 `:49`「This resource can be a **network resource or a file**」，而 `:4`「**Use UIScene lifecycle and `scene(_:openURLContexts:)` from `UISceneDelegate` instead**」把同一语义拆成两套公开口径——**脚本二 `open_entry` 枚举里的 `application_open` 与 `scene_openurl` 两个取值就来自这两行，台账必须写明用的是哪一套**；`:51—52` 补一句「By default, the value of this parameter is an **empty dictionary**」。
- **预览**：`A/quicklook.txt:6`（在 App 内快速预览文件及其内容）、`:15`（iOS 上 Quick Look 提供对预览做简单编辑的能力，例如给图像加标记）、`:17`（自有数据类型要 App 自己提供视图或返回受支持的预览格式）、`:18` 与 `A/quicklook_qlpreviewcontroller.txt:22`（受支持常见类型清单**可能随系统版本变化**）；`:14` 是唯一一处把内容送进设备传感器视图的预览句子（USDZ 模型可进 AR 视图）。预览清单本身两份不同形（第 3 章已给逐行对照）。
- **分享**：`A/uikit_uiactivityviewcontroller.txt:3、:10—11`——面板提供的标准服务由系统给出，App 只负责配置、呈现、取消与被作用的数据对象。**这三句里没有任何自动处理的表述。**
- **网页**：`A/webkit_wkwebview.txt:21—22`——内容必须在网页视图上屏前由调用方显式交给它（`URLRequest`、本地文件或 HTML 串三选一）。
- **后台**：`B/apple-platform-security-guide.txt:2397`「apps can only perform **background processing through system-provided APIs**」——这是 `trg.trigger_mode = background_auto` 的唯一公开支撑，且它约束的是**入口必须是系统 API**，不是「后台会自动解析内容」。

第五种形态是公开口径里最难登记的一种：`A/uikit_uidocument.txt:56—60` 的 NSFilePresenter——「When another client attempts to read the document of a `-based app, **the system suspends reading** until the system provides the object an opportunity to save any changes made to the document」。这一句给的是**由别的客户端发起、被系统挂起的读取**，`trg.trigger_mode` 的五个实值里没有一个描述它（`background_auto` 说的是自家 App 的后台处理，`render_pipeline` 说的是渲染管线）。本篇的处理是原样承认：**这一格只能记 `not_determinable`，并进第 26 章未公开文档化边界清单**，不为了填满枚举而借用邻值。

### 10.2 免交互这条红线在本层的落点

本篇对触发时点的表述受一条硬约束，必须先给读数再给结论：

- `C/readings-18.txt:73—74`：1,266 行公告的影响句里，写成「without user interaction」这一类免交互措辞的**去重 CVE 数 = 0**。
- `C/readings-18.txt:25—30`：影响句的五类后果词形是 `unexpected app termination` 133 行、`disclosure of` 84 行、`bypass` 78 行、`memory corruption` 77 行、`arbitrary code execution` 58 行——**五类里没有任何一类写触发条件**。
- 全档案唯一一处对免交互下定义的句子是 `B/apple-platform-security-guide.txt:1442`，而那一行讲的是 BlastDoor 的设计目标、讲的是消息与身份服务，**不是任何一条文件解析链**。

所以 `trg.auto_processed` 与 `trg.remote_initiated` 两格**不能从公告侧推**，只能从动作侧登记：谁调了哪条 API、用户是否选了这份文档、预览是否被呈现。本篇正文对解析发生时点的表述一律收敛到「打开／预览／分享这三类动作之后」，不写任何免交互判定。三个码专门拦违反这条的动作：

| 码 | 判据 | 拦的是什么 |
| --- | --- | --- |
| E01 | `trg.user_action_required = true` 且 `trg.auto_processed = true` | 台账内部自相矛盾：既需用户动作又记自动处理 |
| E05 | `trg.trigger_mode = message_auto` 且 `id.source_face = files_app` | 进入面与触发面串台：从文件 App 打开的内容被记成消息侧自动触发 |
| A04 | `id.source_face = url_scheme_open` 且 `trg.auto_processed = true` | 把 `A/webkit_wkwebview.txt:21—22` 的显式加载读成自动处理 |

`E02`（自动处理却没有告知位，累计 18 次）与 `E04`（网络投递且自动处理却未登记补丁通道）不拦免交互表述本身，它们拦「写了自动处理却不写任何后果面」——这类记录在台账里看起来完整，实际一格都核对不了。

### 10.3 这一格由哪一件持有

**声明件与通道件各半，且分界可数。** App 决定用哪条动作 API（`open_entry` 的四值里三个是 App 侧调用），系统在什么时刻回调它属通道件。可登记位共六个：`trg.trigger_mode`（必备格）、`trg.user_action_required`、`trg.auto_processed`、`trg.preview_only`、`trg.remote_initiated`、`trg.renders_thumbnail`。

这一层的口径密度不均匀，必须写清：`open_entry` 的四个实值逐个有文档句（`application_open`／`scene_openurl` ← 上面 `:3、:4`；`uidocument_open` ← `:42—43、:566—568`；`activity_share` ← `:10—11`），`preview_entry` 的两个实值逐个有文档句；但 `trg.trigger_mode` 的 `background_auto` 只有 `:2397` 一句间接支撑、`render_pipeline` **在本篇归档里没有对应句子**。「哪一格有文档、哪一格只有口径」的这条差别是第 26 章清单的主体，也是脚本二要求引用格必须落回 `A/`／`B/`／`C/` 归档行号或公开词表值（V02）的原因。

### 10.4 谁读得回它

1. **动作发生侧**：只有 App 自己。`A/uikit_uidocument.txt:50—54` 给出主线程调用与完成回调在同一队列、失败时传 error——这是台账能拿到「打开成功／失败」的唯一公开通道，也是**发起 ≠ 落面**的公开依据（异步）。
2. **呈现侧**：`A/quicklook_qlpreviewcontroller.txt:24` 说明多项数据源会给出导航箭头，即预览面能看到的是**条目数与是否呈现**，不是解析结果；`trg.renders_thumbnail` 与 `E03`（预览触发却未登记缩略图渲染位）就落在这里。
3. **版本侧**：`A/quicklook.txt:18` 与 `A/quicklook_qlpreviewcontroller.txt:22` 两次明说清单随版本变化——**同一份内容在不同版本上的触发面可以不同形**，所以 `trg.*` 的读数必须与 `adv.fix_version` 一起登记。
4. **公告侧**：读不出（`:73—74` 命中 0）。**这是本篇唯一一个「某一层在公开档案里明确没有读数面」的层**，第 15 章的归属矩阵在这一格填的是「无」，不填「未记录」。

### 10.5 台账字段与信号口径

**台账字段**：`trg.trigger_mode`（8 个取值，5 个实值）、`trg.user_action_required`、`trg.auto_processed`、`trg.preview_only`、`trg.renders_thumbnail`、`trg.remote_initiated`（5／2）、`obs.field_read = trigger_mode`。
**信号口径**：脚本一 E 族五码（E01—E05）＋ A04；脚本二 `open_entry`（`application_open／scene_openurl／uidocument_open／activity_share／none`）与 `preview_entry`（`QLPreviewController／ql_extension／none`）两格，`render_result` 四值（`rendered／blank／failed／not_run`）与 P04（渲染结果记在非预览／自述面）、V03（渲染结果只由自述面给出）。

---

## 11. L8 告知层：同意、隔离标记与来源披露

### 11.1 这一格的公开口径

本章只登记「有没有告知、告知文本从哪来」，**不给出任何关闭、伪装或绕过提示的做法**。公开口径一共四处：

- **同意**：`B/apple-platform-security-guide.txt:2557`「Developers of custom keyboards can request that their extension have **Open Access**, which lets the system run the extension in the default sandbox **after getting consent from the user**」，同一句前半段还给出默认态「custom keyboards run by default in a very restrictive sandbox that blocks access to the network, to services that perform network operations on behalf of a process, and to APIs that would allow the extension to exfiltrate typing data」。**适用边界必须写明**：这句讲的是自定义键盘扩展的网络访问，不是文件解析；本篇只把它作为「公开口径里存在一种『默认受限 + 显式取得同意后才放开』的告知形态」的实例引用。
- **同意的传导范围**：`:2555`「they share the same access to privacy controls as the container app. If a user grants an app access to Contacts, this grant is extended to the extensions that are **embedded within** the app **but not to the extensions activated by** the app」——同意是否随扩展传导由**扩展的装配形态**决定，不由内容类型决定。
- **降级告知**：`:1446`「certain apps, websites, and features are strictly limited for security, and **some experiences might not be available at all**」与 `:1448`「Lockdown Mode makes **tradeoffs**…These tradeoffs impact: • Background services」。锁定模式是**以功能换防护**的告知面：它不解释为什么某功能不可用，只让它不可用。
- **呈现侧告知**：`A/uikit_uiactivityviewcontroller.txt:10—11`——标准服务由系统给出，App 负责配置与呈现。分享面板这一面上，「用户看到哪些服务」由系统决定，「面板是否出现」由 App 决定。

**隔离标记（quarantine）在本篇归档里是负空间。** 组 A 与组 B 的全部归档里，`quarantine` 一词只出现 1 次：`B/apple-platform-security-guide.txt:2344`，而且它出现在 macOS 侧的一张能力表里（`:2343—2348`，与 App notarization、System Integrity Protection、Gatekeeper、XProtect/YARA 并列），对应「第三方等价物」列写的是 `Virus/Malware definitions`。**没有任何一句说明这个标记在 iOS 上如何被设置、由谁读回、是否影响类型判定或解析装配。** 因此 `notice.quarantine_flag` 的三个非哨兵取值（`set`／`absent`／`not_supported`）里，本篇只承认 `not_supported`（= 本层无此口径）与 `not_recorded` 为可核对登记；`set`／`absent` 若被写下，引用格必须落到本篇归档之外的公开件，而那是第 26 章清单的 N2 那条边界（不是本章结论，也与脚本一的 `N02` 不是同一个编号——见第 26 章编号约定）。

`notice.origin_disclosed`（来源是否披露）同理：**组 A 十二份文档没有一处说明「打开一份内容时界面上会不会显示它从哪来」。** 唯一间接证据是 `A/uikit_uiactivityviewcontroller.txt:10`（系统提供标准服务）与 `B/…:2393`（每个 App 有独立容器）——两者都只说明「来源在容器层面是分开的」，不说明「来源对用户可见」。

### 11.2 这一格由哪一件持有

**告知位的存在性在通道件，告知文本在观测件。** 这一句是本章的全部结构：App 不能决定系统是否弹提示（通道件），但登记方要写下「提示文本是从哪儿抄来的」（观测件）。`notice.warning_text_source` 的六个实值把这条分成三档：`platform_doc`／`advisory`／`support_note` 是可回指的三档，`vendor_claim`／`screenshot`／`assumed` 是不可回指的三档。

四个失败点：

| 码 | 判据 | 落点 |
| --- | --- | --- |
| N01 | `trg.auto_processed = true` 且 `notice.prompt_shown = not_recorded` | 自动处理却不登记告知位——与 E02 同判据不同族，E 族查触发、N 族查告知 |
| N05 | `notice.prompt_shown = yes` 且 `notice.warning_text_source = not_applicable` | 说「有提示」又说「告知文本不适用」：提示必然有文本 |
| N03 | `warning_text_source ∈ {screenshot, assumed}` | 告知文本依据是截屏或假定 |
| N02 | `notice.quarantine_flag = not_supported` 且 `notice.origin_disclosed = disclosed` | 说本层没有隔离标记，又说来源已披露——两格共用同一个「系统在某处记住了这份内容的来历」的隐含前提 |

`N04` 是本层唯一一条落回本文的信号码：`trg.auto_processed = true` 且 `notice.prompt_shown = no` 且 `notice.notice_note` 为空。它的判据文案指向**本文第 3.4 节失败点 6**（截屏与厂商说法不能充当机制依据）——即「无提示」本身可以接受，但必须留下一句说明，否则这一格在跨台账复算时不可换算。

### 11.3 谁读得回它

三处，且第一处明确不可读：

1. **崩溃面读不出告知状态**。`obs.plane = crash_report` 与 `obs.field_read = prompt_state` 同时出现触发 **O01**——这是脚本一里唯一一处「平面与字段直接互斥」的判据，理由与第 12 章同源：崩溃面限定为报告标识本身。
2. **管理面**。`C/mdm-restriction-keys.txt` 的 218 个形态命中行里（第 13 章给这条分母的构成）没有任何键描述告知；`B/mdm-restrictions.txt:738` 这类句子的结构是「If `<key>`, the system disables…Requires a supervised device」——**管理面能关掉承载内容的 App，不能让告知位变成已告知**。
3. **App 自述面**。`A/uikit_uiactivityviewcontroller.txt:11` 的「Your app is responsible for configuring, presenting, and dismissing」说明面板呈现可登记，但它属自述（`app_self_report` 平面），与 O03／O04 的判定同档。

`A/quicklook.txt:14`（USDZ 可进 AR 视图）是预览面唯一一处把内容送到相机取景的场景，也是脚本二 `notice_surface` 词表里 `ql_ar_notice` 一值的来源；但**归档里没有一句给出这一场景的告知口径**，所以这一格在台账里的合法取值只有 `not_recorded`，脚本二要求引用格落回词表值或文档行号（V02）时它会失败——这条失败是预期行为，不是缺陷，正文与第 26 章按同一口径写。

### 11.4 台账字段与信号口径

**台账字段**：`notice.prompt_shown`（必备格，5 个取值，`yes`／`no` 两档结论）、`notice.quarantine_flag`（6 个取值，`set`／`absent`／`not_supported` 三档）、`notice.origin_disclosed`（5 个取值，`disclosed`／`absent` 两档）、`notice.warning_text_source`（9 个取值，6 种来源，三档可回指、三档不可回指，另三档是 `not_applicable`／`not_recorded`／`unknown`）、`notice.notice_note`（自由文本，但受 K02 的长度与形态拒收约束）、`rights.requires_user_consent`、`obs.field_read = prompt_state`。
**信号口径**：脚本一 N 族五码（N01—N05）＋ E02／O01／N04 交叉；脚本二 `notice_surface`（`lockdown_notice／preview_notice／ql_ar_notice／none`）与 `pkg_layout` 之外的观测件六项共用平面纪律（P01—P07）。

---

## 12. L9 观测平面层：这一格是谁读回来的

### 12.1 这一格的公开口径：23 个取值、20 个实体平面、23 个「平面 × 件」对

观测平面层不给新事实，它给**坐标系**：本篇每一格的读数都必须说明它从哪个面来。脚本二的平面词表有 23 个取值，其中 3 个是哨兵（`none`／`not_recorded`／`unknown`），20 个实体平面按「它承载哪一件」分成六组——这个分组就是脚本二 `PAIR` 表本身：

| 组 | 平面 | 归档出处 |
| --- | --- | --- |
| 只承载声明件（1） | `plist_declaration` | `A/uniformtypeidentifiers_defining_file_and_data_types_for_your_app.txt:5—10、70—88`（四步与键表） |
| 同时承载声明件与通道件（2） | `uttype_framework`、`tag_mapping_api` | `A/uniformtypeidentifiers.txt:7、25—52`；`A/…system_declared….txt:8—13`（`filenameExtension`）、`:14—19`（`mimeType`）、`:20—23`（两条标签类标识） |
| 只承载通道件（8） | `imageio_api`、`coregraphics_api`、`modelio_api`、`webkit_load`、`uidocument_open`、`openurl_callback`、`activity_share`、`pasteboard_transfer` | 依次是 `A/imageio.txt:3、6、40、56`；`A/coregraphics.txt:3、6`；**归档无件**；`A/webkit.txt:5—8`＋`A/webkit_wkwebview.txt:21—22、761、765、776`；`A/uikit_uidocument.txt:34—35、39—49、566—568`；`A/uikit_uiapplicationdelegate_application(__open_options_).txt:3、4、49`；`A/uikit_uiactivityviewcontroller.txt:3、10—11`；`A/uniformtypeidentifiers.txt:7`（与剪贴板之间传输那句） |
| 同时承载通道件与观测件（1） | `quicklook_preview` | `A/quicklook.txt:6—13、17、19—22`＋`A/quicklook_qlpreviewcontroller.txt:11—21、22、24` |
| 只承载观测件（6） | `settings_ui`、`configuration_profile`、`mdm_declaration`、`advisory_entry`、`kev_entry`、`crash_report` | `B/mdm-restrictions.txt:3、24—26、738、960`；`C/advisory-18.tsv:1`；`C/kev-apple.tsv:1—2`＋`C/kev-apple.tsv.meta.txt`；组 B `:1322、:1335`（只给关联句，不给承载格） |
| 自述面（2） | `vendor_claim`、`app_self_report` | `B/apple-platform-security-guide.txt:2388`（App Review 与平台保护共同构成 App 侧防护）＋ `A/uikit_uiactivityviewcontroller.txt:11` |

三个必须写下的结论：

1. **「平面 → 件」不是一对一**：20 个实体平面给出 23 个「平面 × 件」对，因为 `uttype_framework`、`tag_mapping_api`、`quicklook_preview` 三个平面跨两件。跨件平面是本层最有信息量的三格——同一个 `UTType` 反查，既是声明的读回（这一类型标识在不在系统清单里），也是通道的读回（反查值落到哪一格），**只有这两次读回都被登记，才不构成 T01／T02。**
2. **`modelio_api` 是唯一一个「词表里有、归档里没有件」的平面**。它保留的理由与 P05 的字体／归档负空间同源：公告组件列里有 `Model I/O` 37 行（`C/readings-18.txt:35`），而组 A 没有 Model I/O 文档件，所以这个平面既不能删（组件侧真实存在）也不能填（没有承载它的文档句）。
3. **两支脚本的平面词表不闭合。** 脚本一的 `obs.plane` 是 12 个取值（8 个实体），脚本二是 23 个（20 个实体）；**两侧同名的实体平面只有 4 个**（`crash_report`、`settings_ui`、`app_self_report`、`vendor_claim`）；只在脚本一侧的有 4 个（`diagnostic_log`、`mdm_status_item`、`advisory`、`developer_doc`）；只在脚本二侧的有 16 个（九个通道平面、三个登记来源平面、`configuration_profile`、`mdm_declaration`、`kev_entry`）。这不是笔误，是两把尺子的粒度不同：脚本一按「读数的证据种类」分面，脚本二按「框架 API 与配置面」分面。**跨脚本引用平面时必须写全名并落 `doc.source`＋`doc.line_ref`**，否则两条台账无法换算（这是第 3.4 节失败点 8 在本层的落点，也是 X01 的判据：确认结论缺来源文件或行号）。

### 12.2 崩溃面的边界：三句规范，逐字照抄进两份脚本

本章是两支脚本里四条 DOC 引用共同的落点，规范一共三句：

- 对**台账字段** `obs.crash_report_ref`：**崩溃引用只登记报告标识，不粘贴堆栈正文**（脚本一 K03 的判据文案）。形态判据是 `[A-Za-z0-9-]{6,40}`，或 `absent`／`not_applicable`；写成堆栈片段、路径或带空格的描述即触发。
- 对**清单引用格** `crash_ref`：**崩溃只登记报告标识，不粘贴正文、堆栈或设备路径**（脚本二 M04 的判据文案）。形态判据是 ≤40 字符、无空格、无斜杠的标识串，或文档行号形态。
- 对**读数平面**：**崩溃面限定为报告标识本身，其余平面不承载崩溃读数**（脚本二 P07 的判据文案）。`crash_ref` 的平面只要不是 `crash_report` 就触发。

为什么定得这么窄，有三条依据：组 A 没有崩溃文档件；组 B 只给关联句（`:1335`「secrets 不匹配则 App 崩溃且事件被记录」、`:1322`「校验失败即 abort」）；而本篇的红线是不做崩溃复现与缺陷定位。**登记一个报告标识是为了把归属结论挂到一个可回查的外部对象上，不是为了从崩溃里读出任何一格。** 与之配套的是拒收族：`K02`（脚本一）拦形似设备绝对路径、长载荷、密钥串的取值；`K01`（脚本二）拦引用格形似密钥、凭据、归档文件、设备绝对路径或整段载荷正文；脚本二的 `K02` 另拦一种——引用格写成设备侧命令行入口名，判据文案逐字是「本脚本与台账都不以任何命令行工具作为读数来源」。

### 12.3 这一格由哪一件持有

**观测件，但坐标系由登记方选。** `obs.plane` 是十二格之一（必备格），`obs.field_read` 规定「这个平面这次读回来的是哪一格」，它的六个实值（`parser_name`／`host_process`／`domain_class`／`trigger_mode`／`prompt_state`／`reset_proof`）就是本篇**可被观测面读回的格的全集**——其余层的格（L2 的声明内容、L4 的判定过程、L5 的解析器实例）在公开口径里没有可枚举的读数面。

三个失败点：

| 码 | 判据 | 含义 |
| --- | --- | --- |
| O02 | 平面有值（非 `none`／`not_recorded`／`not_determinable`）且 `obs.read_at` 为空 | **累计 194 次，脚本一非阻断信号里的最高频码**：观测必须有时刻，否则「此刻在面上」与「登记时在面上」无法区分 |
| O03 | `obs.plane = vendor_claim` 且 `doc.conclusion = confirmed` | 只靠厂商自述面给确认结论 |
| O04 | `obs.plane = app_self_report` 且 `dom.domain_source = platform_doc` 且结论为确认 | 平台文档与 App 自述并用却未说明冲突处理——**这是唯一一处要求登记"两格冲突时听谁的"的判据**，而公开口径本身没有规定这件事（第 3 章八处换算失败在观测侧的落点） |

脚本二一侧，平面越界分七个码：P01（记为已读数但平面为 `none`）、P02（通道件记管理面）、P03（声明件记公告／KEV／崩溃面）、P04（渲染结果不在预览面或自述面）、P05（平面与核对项所属件不匹配，以及按 `DEOK` 表限定「哪一类内容的解码入口能记在哪些面」——`font_content` 与 `archive_content` 的 `DEOK` 是空集，即本篇没有承载这两类解析入口的文档面）、P06（观测件记声明或标签反查面）、P07（崩溃引用记非崩溃面）。V03 另拦一种：渲染结果只由 `vendor_claim`／`app_self_report` 给出——**呈现面由 App 自己配置，其自述不独立构成观测。**

### 12.4 谁读得回它

`obs.list_visible`（布尔位）是「这一格在界面上可见」的唯一登记位，脚本二没有对应列；`obs.read_at` 与 `undo.verified_at` 是脚本一里仅有的两个日期字段，按 `C/kev-apple.tsv` 表头两列的 `YYYY-MM-DD` 同形校验（S08）。这两格合起来给出本层的可核对形态：**平面 + 字段 + 时刻**三件齐备才算一条读数，缺一律按 O02 记。

### 12.5 台账字段与信号口径

**台账字段**：`obs.plane`（必备格，12 个取值，其中 8 个实体平面）、`obs.field_read`（9 个取值，6 个可观测字段）、`obs.read_at`、`obs.crash_report_ref`、`obs.list_visible`；脚本二清单里本层落第 5 列（读数平面）、第 6 列（词表归属）、第 7 列（引用）与第 8—10 列（对外表述、内容来源、解析时点）。
**信号口径**：脚本一 O 族四码（O01—O04）＋ K03＋S08＋X01；脚本二 P 族七码（P01—P07，P05 有两条 emit 路径）＋ V03＋K01／K02＋M04／P07 的三句规范联动。

---

## 13. L10 管理与公告回查层：218 个限制键与 46 行列间错位

### 13.1 管理面口径：先给分母的构成，再给命中

`B/mdm-restriction-keys.txt` 共 220 行。读这一份清单必须先说清 218 这个数是**形态命中数**而不是键名数：按 `^[a-zA-Z][a-zA-Z0-9]*$` 逐行匹配得 218 行，其中 **8 行不是键名**——两行恰好是单个字母标识的分段标题（`:2` Important、`:4` Note）与六行平台名（`:203—205` iOS／iPadOS／macOS、`:217—219` tvOS／visionOS／watchOS）。**纯键名分母取 210。** 脚本一与脚本二都按「形态命中集合」做包含判断，因此两者对「不在清单内」的判定实际以 218 为准；这条差异必须写在正文而不是脚注里，因为它是 X08（词表自身形态非法）与 G02（键不在清单内却用来给确认结论）共同的口径前提：**按行直接取键会虚增分母 8，用虚增的分母做命中判断会漏判。**

三条逐字口径：

- 页面结构：`:1—4` 是分段标题（`Device Management`／`Important`／`Mac Catalyst`／`Note`）；`:5—8` 起逐行都是 `allow` 前缀的小驼峰单标识（`allowARDRemoteManagementModification`、`allowAccountModification`、`allowActivityContinuation`、`allowAddingGameCenterFriends`）；`:9` `allowAirDrop`；`:133` `allowSafari`；`:162` `allowedCameraRestrictionBundleIDs`；`:211` `requireManagedPasteboard`；`:220` `whitelistedAppBundleIDs`。G05 的形态判据（小驼峰单标识）就是照 `:5—8` 这一形态写的。
- 语义结构：`B/mdm-restrictions.txt:3`「The payload that configures restrictions on a device」；`:22—26` 一条限制的完整形态是三行——`boolean`、`If <key>, the system disables AirDrop`、`Available: iOS 7+ | iPadOS 7+ | macOS 10.13+ | visionOS 2+`＋`Requires supervision: iOS | visionOS`；`:738`「the system disables the Safari web browser app, and the system removes its icon from the Home Screen. **This setting also prevents users from opening web clips.** Requires a supervised device in iOS 13 and later」；`:960`「the system considers AirDrop to be an unmanaged drop target」。**每条限制都带 Available 与 Requires supervision 两行**——这就是 `mgmt.supervised` 的口径来源：管理面结论必须与监督态同侧登记。
- 命中读数：`C/readings-18.txt:92—96` 给四个数——键名形态命中 218、命中内容接收／打开／预览／网页／文件类词形的键 **6 个**（`allowUIConfigurationProfileInstallation`／`safariAcceptCookies`／`safariAllowAutoFill`／`safariAllowJavaScript`／`safariAllowPopups`／`safariForceFraudWarning`）、可直接约束「内容能否被打开／预览／联网取回」的键 **19 个**（`allowAirDrop`、`allowAirPlayIncomingRequests`、`allowAppClips`、`allowBookstore`、`allowBookstoreErotica`、`allowCamera`、`allowEnablingRestrictions`、`allowMediaSharingModification`、`allowPasswordAutoFill`、`allowSafari`、`allowSafariHistoryClearing`、`allowSafariPrivateBrowsing`、`allowSafariSummary`、`allowedCameraRestrictionBundleIDs`、`forceAirPlayIncomingRequestsPairingPassword`、`forceAirPlayOutgoingRequestsPairingPassword`、`forceAuthenticationBeforeAutoFill`、`requireManagedPasteboard`、`safariAllowAutoFill`）。
- **两个名单里没有一个键名含 parser／codec／decode 任一词形**（对整份清单做词形检索，命中 0）。管理面对解析链的作用只到「承载内容的 App 开不开、网页内容取不取得回」，不到「内容按什么类型被谁解析」。这就是脚本二 P02 判据文案「管理面关掉的是承载内容的 App，不是解析链本身」的实证来源，也是 `mgmt.mdm_configurable` 里 `content_only` 一值必然触发 G01（称可配内容却没键名）的原因——按上面两份名单，**没有任何键的内容维度是"解析层"**。

唯一一处管理面与承载方身份直接相接的是 `:162` `allowedCameraRestrictionBundleIDs`：**这是清单里唯一以包标识为取值的键**，它约束哪些包能用相机，与类型判定、解析装配都不相干（第 6.4 章已用它说明「能圈准包标识不等于能约束判定」）。

### 13.2 公告与 KEV 口径：六列、三档切片与一个错位

- 结构：`C/advisory-18.tsv:1` 六列 `file／platform／component／cve／impact／avail`。第 2 行给出一条真实形态：`iOS 26.7.2 and iPadOS 26.7.2`＋`Accelerate Framework`＋`CVE-2026-86971`＋「Processing a maliciously crafted image may lead to unexpected app termination」。
- 规模：`C/readings-18.txt:2—7` 六条——组件×CVE 对 1,266 行、去重 CVE 330、去重组件名 129、平台版本行 12、含 `maliciously crafted` 的 467 行、其中去重 CVE 95。
- 对象词（impact 列，行级）：`:10—23` 十四个词形，前六个是 `web content` 175、`file` 164、`image` 105、`model` 37、`font` 34、`video` 25，后八个是 `audio` 7、`archive` 6、`message` 6、`photo` 6、`zip` 5、`calendar` 4、`contacts` 4、`mail` 3。**脚本二 S03 的对象类词表（`image_content／web_content／model_content／font_content／audio_video_content／archive_content／document_content／package_content／system_service`）就是照这一段的词形命名法造的**——每个内容类后缀 `_content`，与公告对象词一一对得上，这是「对象类」这一列能被公开口径核对的唯一依据。
- 组件集中度：`:33—52` top-20，含 crafted 行数÷全组件行数的比值第 8.3 章已逐个列出。
- **列间错位**：`:54—59`——影响句写明恶意构造对象、组件名却不含任何解析层词形的有 **46 行**，其中 `web content` 0 行、`image` 16 行、`file` 19 行、`font` 0 行；`:60—71` 给前 12 个这类组件（`CoreServicesUIAgent`、`Accelerate Framework`、`libarchive`、`CoreSymbolication`、`ArchiveService`、`Mail`、`OpenBSM`、`GPUTools`、`Grapher`、`LinkPresentation`、`HomeKit`、`Core Image`），**每个组件在这 46 行里都只有 1 个 CVE**。这一组数是本篇的中心事实：按组件名筛选会整批漏掉它们，按影响文本筛选会拿到组件名对不上的行。
- 切片闭合：`C/subset-18.txt:5—11`——crafted 子词表组件去重 34、其中含解析层词形 23、不含 11（名单与行数见第 8.2 章引用的 `:9`）；全量词表里但不属 crafted 子词表的 95 个组件（`:10—11`）。**34 + 95 = 129，与 `:4` 的全量组件去重数闭合**，这条算术是脚本二 X01／X02 互差检查的静态基准：`X01` 拦「组件只出现在子词表却不在全量词表」，`X02` 拦「组件在全量词表但不含 crafted 行，却把解析类归属对外表述为是」。
- KEV 侧：`C/kev-apple.tsv.meta.txt` 三行给出目录元数据——`catalogVersion: 2026.10.30`、`dateReleased: 2026-10-30T17:02:45.3665Z`、`count: 1766`。**1,766 是全目录条目数，不是 Apple 条目数**；Apple 条目 95 条（`C/readings-18.txt:76` 起，L2—7 为列头与首条）。KEV 侧三档：`C/subset-18.txt:14—16`——95 条中 42 条短描述含 crafted 类措辞、41 条含解析对象词、其中网页内容类 36 条。`C/kev-apple.tsv:2` 一条同时给出 `dateAdded 2026-09-29` 与 `dueDate 2026-10-13`，是 R07 的锚点（在 KEV 名单内却把补丁通道记为 `not_release` 即触发）与 S08 日期形态的锚点。
- 换算失败读数：`C/readings-18.txt:119—121`——同一 CVE 最多出现在 **8 行**（CVE-2026-112470，跨 8 个平台版本行），**47 个 CVE 只出现在 1 行**（330 个去重 CVE 中）。这两个数是 O02「有观测平面却未登记读数时刻」在本层的实际后果：同一缺陷的多行平台记录若不带时刻，跨平台复算会得到 8 个或 1 个两种答案。
- 版本号形态：`B/apple-platform-security-guide.txt:180`「Unless otherwise noted, this documentation covers … iOS 26.5, iPadOS 26.5, macOS 26.5…」——R06 的「纯数字点分」形态校验与「本指南覆盖版本」这条限定同源。

### 13.3 这一格由哪一件持有

**观测件，两半都在平台侧。** 管理面键表与公告／KEV 都不是 App 能写的，也不是框架 API 能读的——登记方只有回查权。`mgmt.key_source` 的三实值（`restrictions_inventory`／`official_doc`／`vendor_claim`）与 `adv.kev_listed` 的 `not_checked` 是这一层的两个诚实位：**没查过必须写没查过，不能留空**。留空会同时躲过 G02 与 R04。

七个失败点（脚本一 G 族五条＋R 族七条里与本层相关的部分）：

| 码 | 判据 | 依据 |
| --- | --- | --- |
| G01 | `mgmt.mdm_configurable = content_only` 且 `mgmt.restriction_key` 为空 | 第 13.1 段的两个名单里没有任何键的内容维度是解析层 |
| G02 | `mgmt.key_in_inventory = no` 且结论为 `confirmed` | 键不在清单内，就不能用它给确认结论 |
| G03 | 登记了 `mgmt.payload` 却没写 `mgmt.key_source` | payload 名（`com.apple.applicationaccess`／`com.apple.webcontentfilter`／`com.apple.configuration.device.management`）不带键出处 |
| G04 | `mgmt.mdm_configurable = yes` 且未指名任何键 | 与 G01 同族不同档：`yes` 是更强的断言，必须给键名 |
| R01 | 登记了 `adv.object_word_in_impact` 却没有 `adv.component` | 六列里两列同属一行，缺一列就断了行内互证 |
| R03 | `adv.component_is_parser_layer = no` 且结论为 `confirmed` | 组件名不属于解析层却用它给确认结论——46 行错位正是这一格 |
| R05 | `component_is_parser_layer = not_checked` 且对象词为 `image` 但组件名与图像无关 | 第 5 组读数里 `image` 16 行的构成 |

脚本二一侧本层落 X 族：X01／X02（组件与 crafted 子词表互差）、X03（CVE 不在公告与 KEV 的 CVE 词表内）、X04（限制键不在公开键清单内）、V06（核对项挂在公告面或管理面却没有词表标识——缺任一格就无法回指）。**注意 `X08` 不属这一层，它守的是词表自身的形态**（记录不足两列、类别列不在允许集合、值格为空、来源标识既不是文档行号形态也不是 `fixture`），也就是第 13.1 段那条「分母纪律」在词表侧的镜像。

### 13.4 谁读得回它

本层的读数面只有两个，且都给集合不给个体：管理面给「这台设备上哪些键被配置了」（`settings_ui`／`configuration_profile`／`mdm_declaration` 三面），公告面给「哪些组件在哪些版本被修过」（`advisory_entry`／`kev_entry` 两面）。**两者都不给「这一条内容」的任何读数**，所以本层的所有对外表述都必须是集合级的：「这一类组件在公告里出现过」「这一族行为可被键约束」，不能是「这条内容不安全」。这一条上限与第 3 章失败点 8 同源：**口径之间不能直接换算，结论必须回到文件与行号**（X01 的判据文案所指）。

### 13.5 台账字段与信号口径

**台账字段**：`mgmt.mdm_configurable`（6／4）、`mgmt.restriction_key`、`mgmt.key_in_inventory`（5／2）、`mgmt.payload`（7／3）、`mgmt.supervised`、`mgmt.key_source`（6／3）；`adv.component`、`adv.component_is_parser_layer`（5／2）、`adv.cve`、`adv.kev_listed`（6／2）、`adv.object_word_in_impact`（12 个取值，9 个实体对象词）、`adv.patch_channel`（7 个取值，4 个具名通道 `whole_version`／`rapid_security_response`／`background_improvement`／`not_release`，另三档不可回指）；`adv.fix_version` 是自由版本串，由 R06 管形态。
**信号口径**：脚本一 G 族五码＋R 族七码（R01—R07）＋X01＋S08；脚本二 X01—X04＋X08＋V06，加 `advisory_component／advisory_component_crafted／advisory_cve／restriction_key` 四类词表归属（共 13 个词表归属取值，其中 9 类是实体词表）。

---

## 14. L11 复位与再核对层：清缓存、复位与再打开证明

### 14.1 这一格的公开口径

本篇十一层里，这一层的公开口径**最薄**，必须先说清哪些复位方法有句子、哪些没有：

- **有直接句子的只有两种**。`reinstall` ← `B/apple-platform-security-guide.txt:2393`「Each app has a unique home directory for its files, which is **randomly assigned when the app is installed**」——重装会换一个容器，这条是唯一一处「复位动作改变承载位置」的公开口径。`mdm_reapplied` ← `B/mdm-restrictions.txt` 每条限制的 `Available: …`／`Requires supervision: …` 两行（第 13.1 段给的三行结构）——键重新下发是管理侧可登记事件，**本章只登记这一事件是否发生，不描述如何下发或如何核对下发结果**（规避管理面审计不在本文范围内）。
- **有一种借到口径**：`expiry_only` 只能借 `C/kev-apple.tsv:2` 的 `dueDate` 一列，而那是**修复期限**不是内容失效；台账写下 `expiry_only` 时引用格必须落到 KEV 或公告行号，否则按 V02 处理。
- **其余四种（`delete_file`／`clear_cache`／`reimport`／`restart`）在本篇归档里没有对应句子**。`reimport` 最接近的是 `A/uikit_uidocument.txt:42—43`（重新打开由用户选定的既有文档），但那句描述打开，不描述「重新导入会让类型判定改变」。

可核对的时间与状态口径有四处：

1. **文档生命周期五段**：`A/uikit_uidocument.txt:38—49`——创建／打开／编辑（`:45`「periodically notes when there are unsaved changes and writes the document data to its file」）／可选云端整合与冲突解决（`:46`）／关闭（`:47—49`「saves the document if there are any unsaved changes」）。**每一段都是一次可登记的状态转换**，这是本篇把「发起时刻」与「核对时刻」分两格登记的正向依据。
2. **异步完成句**：`:50—54`——主线程调用、完成回调跑在同一 dispatch queue、失败时传 error；`:578`「Schedules a document-reading or document-writing operation on a **concurrent background queue**」。**发起 ≠ 落面**（第 4 章已落过一次，本层是它的复位侧后果）。
3. **读回通道与承载体是两回事**：`A/imageio.txt:40、56`——同一个不透明类型分别用于「向 URL、数据对象或数据消费者写出图像」与「从 URL、数据对象或数据消费者读入图像」。**复位针对的是承载文件与缓存，不针对读回通道**；这正是 V02 的判据文案所指（声称已再证明但缓存未清）。
4. **清单随版本变化**：`A/quicklook.txt:18`＋`A/quicklook_qlpreviewcontroller.txt:22`；`B/…:1448` 锁定模式 tradeoffs；`B/…:1904—1908` Data Protection 按类控制可读性——**数据保护类与解析面正交**，它决定密钥是否解锁，不决定内容被判成什么类型。这条正交关系是 O04 的锚点，也是本篇不把「锁屏后读不到」写成「解析被复位」的原因。

### 14.2 这一格由哪一件持有

**声明件与观测件混合。** 复位动作由登记方（做归属核验的人）执行并登记，属声明件一侧的填写权；复位之后系统按什么判属通道件；「复位后是否还残留」这一句是观测件。三件在同一段台账里必须分三格写，这是本篇最容易串台的一段——因为口语里「清掉之后就没有了」同时说了动作、判定与残留。

两个时刻字段是本层的骨架：`obs.read_at`（读数时刻，第 12 章）与 `undo.verified_at`（核对时刻）。`V03` 的判据是「声称有残留（`undo.residue_claimed = true`）却未登记核对时刻」——**残留是一个时刻性的断言，没有时刻就等于没写**。日期形态按 `C/kev-apple.tsv` 表头两列同形校验（S08）。

### 14.3 失败点与再证明依据

`undo.reproof_basis` 八个取值里只有四个是可核对的：

| 取值 | 可核对性 | 依据 |
| --- | --- | --- |
| `reopened` | 可核对 | `A/uikit_uidocument.txt:42—43`（重新打开是一条显式动作） |
| `re_rendered` | 可核对 | `A/quicklook.txt:6—13、17`＋`A/quicklook_qlpreviewcontroller.txt:11—21`（呈现结果落在 `render_result` 四值里） |
| `user_visible_prompt` | 可核对但受第 11 章限制 | 告知文本源必须落在 `platform_doc`／`advisory`／`support_note` 三档之一，否则 N03 |
| `advisory_component` | 可核对 | `C/advisory-18.tsv` 组件列与修复版本列同行 |
| `assumed` | **不可核对** | `V04`（再证明依据为假定）＋ 第 3.4 节失败点 6 |

四个码的判据逐字：`V01` = `undo.reset_method = not_determinable` 且 `undo.reproof_done = true`（复位方法不可判定却声称已再证明）；`V02` = `reproof_done = true`、`reset_method = clear_cache` 而 `cache_cleared` 不为真；`V03` 同上；`V04` 同上。**四者都是非阻断**，本层没有任何阻断判据——这与它的性质一致：复位层不改变归属结论的对错，只改变结论的**时效**。

因此本层与判定档的关系只有一条：J1／Q1 级结论必须带 `undo.verified_at`；缺核对时刻的 J1 在第 20 章 O10（再证明覆盖率）里计为未覆盖，但不降级。**脚本二里没有复位层的核对项**——本层通过 `render_result` 四值与 V05（同一对象类同一核对项在不同对象之间既有已读数又有明确不存在，登记口径未统一，非阻断）间接核对。这是本篇的已知不完备，进第 26 章边界清单：复位与再核对没有独立的三件核对项，它只能靠状态分布反查。

### 14.4 谁读得回它

`obs.field_read = reset_proof` 是本层唯一的可观测字段，它与 `undo.reproof_done`／`undo.reproof_basis` 同格登记才成立。三个面能给旁证：预览面（重新呈现的结果差异）、公告面（修复版本已发布，`adv.patch_channel` 的四个实值 `whole_version`／`rapid_security_response`／`background_improvement`／`not_release`）、管理面（键是否重新下发）。**三者都不能证明「这条内容现在被复位了」**，只能证明「复位条件成立」——这是本层对外表述的上限，也是第 24 章里「把已发布修复当成已复位」这条误区的落点。

### 14.5 台账字段与信号口径

**台账字段**：`undo.reset_method`（11／7）、`undo.cache_cleared`、`undo.residue_claimed`、`undo.reproof_done`、`undo.reproof_basis`（8／4＋1 假定）、`undo.verified_at`；`obs.read_at`、`obs.field_read = reset_proof`；`adv.patch_channel`、`adv.fix_version`。
**信号口径**：脚本一 V 族四码（V01—V04）＋ S08＋O02；脚本二 `render_result` 与 V05（非阻断的口径未统一）、V02（引用格既非词表值也非文档行号）。

## 15. 归属矩阵：十一层 × 责任方 × 三件 × 证据

### 15.1 这张矩阵怎么读

矩阵是第 4—14 章的收束件，不是新证据。它只有四列有信息量：**填写权在谁**（这一格谁有权写值）、**三件归属**（声明件／通道件／观测件，混合要写清哪一半）、**公开读数面**（哪一侧真能给回这一格的值）、**主判据族**（哪几个码守这一格）。后两列之间的关系就是本篇的中心事实：**填写权与读数面错位的层，才是归属争议的层**。

三条读法规矩：

1. 「公开读数面」写 **无** 与写 **未记录** 不是一回事。「无」是本篇归档里明确找不到承载面（第 10.4 节第 4 条，触发层在公告侧命中 0 行）；「未记录」是台账里这一格可以填 `not_recorded`，面本身存在。矩阵里只有一格是前者，就是 L7 的公告侧。混用这两值会让第 26 章的边界清单与台账的 `not_recorded` 计数互相污染。
2. 「主判据族」只列脚本一（大写字母族）与脚本二（同族名但判据不同）两侧各自主守的码，同号不同义的族（D 族、K 族、X 族、V 族）在第 9.4、第 12.5 与第 13.3 节已逐次交代，本表不重复消歧。
3. 每一行的「三件归属」必须能回指本章的某一句原文。若某层写成「混合」，第 4—14 章里必须出现「哪一半属哪一件」的分段句——L3（声明件填写、通道件生效）、L8（告知位存在性属通道件、文本属观测件）、L11（动作属声明件、判属通道件、残留属观测件）三处满足这条；其余八层里七层是单件表述，L4 是第四形态「三件都在场、无仲裁件」，它既不分段也不归单件。

### 15.2 矩阵

| 层 | 填写权在谁 | 三件归属 | 公开读数面 | 主判据族 | 证据锚点 |
| --- | --- | --- | --- | --- | --- |
| L1 来源面与容器形态 | 登记方（内容字节不带 provenance） | 声明件，但持有人是承载 App | 管理侧（19 个键约束通道开不开）、KEV 侧（只有目录时间）；**读不回这一条对象的来源** | 一：S09 三格、A01、A02、K02／二：S10、S02、清单第 9 列 | `C/readings-18.txt:95—96`、`C/advisory-18.tsv:1`、`C/kev-apple.tsv:2` |
| L2 类型声明层 | 内容生产者或承载 App 自己 | 纯声明件 | 无登记来源平面之外的面；三个登记来源平面只说明「值抄自哪儿」 | 一：B08、A03、S07、S09（`typ.type_source` 落 L4）／二：声明件七项、D01—D05、K03—K05、T01 | `A/…defining…:12—14、78、88`、`A/…system_declared….txt:8—17` |
| L3 承载方身份层 | 登记方从包上抄；`rights.sandbox_profile` 只能来自平台口径 | 声明件填写、通道件生效 | 自述面（App Review 那次判定）、公告组件列（系统组件名，不是包标识）、管理侧唯一 `allowedCameraRestrictionBundleIDs` | 一：A03、A06、S07、S09／二：K01、T04、D03 | `B/apple-platform-security-guide.txt:2388`、`B/mdm-restriction-keys.txt:162`、`C/advisory-18.tsv:1` |
| L4 类型判定层 | 三条票源各自持有人，**没有仲裁件的填写方** | 三件都在场、无仲裁件 | 呈现侧（预览条目与渲染结果）、公告侧（组件×对象词的列间关系） | 一：B01—B07、X01、X02／二：通道件七项、X05—X07、M06、T06 | `A/uniformtypeidentifiers.txt:25—52`、`A/uikit_uidocument.txt:35`、`C/readings-18.txt:54—59` |
| L5 解析装配层 | 框架与承载 App 的装配选择 | 通道件 | 公告侧（top-20 比值，见 8.3）、崩溃侧（只给报告标识） | 一：C01—C07、R01、R03、R05／二：`decode_entry`、`preview_entry`、`open_entry`、P05 | `C/readings-18.txt:33—52`、`A/coregraphics.txt:6`、`C/subset-18.txt:9` |
| L6 执行域层 | **平台**；登记方只有引用权 | 观测件（`dom.domain_source` 是「你凭什么写这一格」） | 三处间接：崩溃侧关联句、管理侧生效句、公告侧无域列 | 一：D01—D06、C02、C05、C06／二：P02、P03 | `B/…guide.txt:2391—2397、1335、1322、2555、:2446`（macOS 段）、`C/advisory-18.tsv:1` |
| L7 触发条件层 | 用户动作或系统；App 只能自述 | 通道件 | 动作发生侧（打开成功／失败回调）、呈现侧（条目数与是否呈现）、版本侧（清单随版本变化）；**公告侧：无** | 一：E01—E05、A04／二：`open_entry`、`preview_entry`、`render_result`、P04、V03 | `A/uikit_uidocument.txt:50—54、578`、`A/quicklook.txt:18`、`C/readings-18.txt:73—74` |
| L8 告知层 | 系统；App 不能决定是否弹提示 | 通道件（存在性）＋观测件（文本） | 管理侧不能让告知位变成已告知、崩溃侧禁止承载告知读数、自述面可登记面板呈现 | 一：N01—N05、O01、D06／二：`notice_surface`、V02 | `B/…guide.txt:2557、1446、1448`、`A/uikit_uiactivityviewcontroller.txt:10—11`、`A/quicklook.txt:14` |
| L9 观测平面层 | 登记方（这一层是坐标系，不是事实源） | 观测件 | 本层即读数面本身：23 个平面×件对 | 一：O01—O04、K03、S08、X01／二：P01—P07、V03、K01、K02、M04 | 第 12.1 节六组分解；`A/…defining…:5—10、70—88`、`A/imageio.txt:3、6、40、56` |
| L10 管理与公告回查层 | MDM 管理员（键）、Apple（公告与 KEV 条目） | 观测件 | 管理侧（这台设备上哪些键被配置）、公告侧（哪些组件在哪些版本被修过）；两者都只给集合 | 一：G01—G04、R01—R07、X01、S08／二：X01—X04、X08、V06、四类词表归属 | `B/mdm-restrictions.txt:3、24—26、738、960`、`C/readings-18.txt:2—7、91—96、119—121` |
| L11 复位与再核对层 | 登记方执行、系统判定、观测残留 | 三件混合（6.1 节式的分段） | 呈现侧、公告侧（修复版本已发布）、管理侧（键是否重新下发）三处旁证 | 一：V01—V04、S08、O02（全为非阻断）／二：`render_result`、V05、V02 | `B/…guide.txt:2393`、`C/kev-apple.tsv:2`、第 14.1 节「四种复位方法无句」 |

### 15.3 矩阵的五个可数结论

1. **12 个必备格落在 9 层，L2 与 L3 一个都没有。** 分布是 L1 三格（`id.obj_kind`／`id.source_face`／`id.provenance`）、L4 一格（`typ.type_source`）、L5 两格、L6—L11 各一格。这条分布有直接后果：**声明层与身份层缺格不会单独把对象打到 J4**，它只会落 B08、A03、A06、S07 这类非阻断信号，需要与别的层叠加才降级；而来源面与回查面缺任一格立即 J4。第 19 章的判定模型因此不是「按层加权」，是「按必备格定位 + 按信号计数定档」。
2. **填写权与读数面完全错位的层有四个**：L1（登记方填，没有面读回这一条对象的来源）、L6（平台决定，登记方只能引）、L8（系统决定，管理面读不出告知状态）、L11（登记方执行，三个旁证都不能证明「现在被复位」）。这四个层就是本篇归属争议的全部来源，第 17 章的可见性档位也按这四个层定上限。
3. **只有一层既没有填写权也没有读数面**：L6。所以第 9.2 节把它写成「十一层里唯一一层登记方只有引用权、没有填写权」，第 9.3 节的三处读数全为间接。这也是 `dom.*` 全部六格的对外表述上限都比 `asm.*` 低一档的原因。
4. **公告侧被 7 层的读数面引用，被 1 层明确写为「无」。** 引用它的七层是 L1（六列没有来源列）、L3（给系统组件名，不给包标识）、L4（组件×对象词的列间关系）、L5（top-20 比值）、L6（没有域列）、L10（本层主体）、L11（修复版本已发布）；写「无」的是 L7（`C/readings-18.txt:73—74` 命中 0）。但这七层里**没有一层能靠公告侧定个体**：公告六列（`C/advisory-18.tsv:1`）给的是组件×CVE 粒度，与台账的对象标识之间没有换算句——这就是失败点 4 与失败点 8 在矩阵上的形状。
5. **混合归属只有三层（L3、L8、L11），且都写成「哪一半属哪一件」。** 剩下八层里，单件表述七层：声明件 2 层（L1、L2）、通道件 2 层（L5、L7）、观测件 3 层（L6、L9、L10）；L4 既不是单件也不是分段混合，而是「三件都在场、没有仲裁件」这一第四形态。这个计数决定了脚本二的输入结构：三件各成一族核对项（声明 7／通道 7／观测 6，共 20 项），而不是按层分族——**按层分族会把 L4 无处安放**。

### 15.4 矩阵与判定档的关系

必备格缺失或 S／K 族命中 → J4（脚本一逐对象）；能力表里该对象类一行都没有、或本对象没有一行能通过形态校验 → Q4（脚本二逐对象）。两套档的输入不同，因此**同一个对象可以 J1 而 Q4**：台账写满且形态合规（J1），但它所属对象类在能力表里没有行，三件差集无从计算（Q4）。本篇把这档组合写成第 20 章 O6（三件齐备率）与 O7（能力表覆盖率）两个分母不同的指标，而不是新增第三套档位。**对外表述必须同时给两档**，只给 J 档会掩盖能力表缺口，只给 Q 档会掩盖台账形态缺陷。

---

## 16. 公开读数：这条通路上能数出来的十一组事实

### 16.1 读数纪律

十一组全部来自 `C/readings-18.txt`（122 行，`END-READINGS-18` 在第 122 行），派生器是 `tools/readings18.pl`；另有三组对照读数在 `C/subset-18.txt`（43 行，`END-SUBSET-18` 在第 43 行），派生器是 `tools/subset18.pl`。两组读数的输入都是本轮抓下来的公开档案件（公告 TSV、KEV TSV、MDM 键表、系统声明 UTI 清单、框架文档），**读的是档案文本，不是设备、不是任何被登记的对象**，也不调用任何命令行工具去判定文件类型。

三条计数规矩，逐组适用：

- **行级与去重级要分开说**。公告 TSV 的粒度是「组件×CVE 对」，同一个 CVE 可以在多个平台版本行出现（第 11 组给出 8 行的上限与 47/330 的单行数），所以「行=175」与「CVE=32」是两个必须各自命名的量。本篇凡引用行数就写行数。
- **命中口径就是派生器里的那一个正则**。第 16.3 节给出同一件事在两个派生器里口径不同的实例。
- **读数只支撑集合级结论**，不支撑个体级结论（第 13.4 节的上限同样适用于本章）。

### 16.2 十一组

**第 1 组 语料规模（`:2—7`）**：组件×CVE 对 1,266 行、去重 CVE 330、去重组件名 129、平台版本行 12、影响句含 `maliciously crafted` 的行 467、其中去重 CVE 95。这一组是后面九组的分母。467 与 95 说明「恶意构造对象」这一措辞在公告里的占比（36.9% 的行、28.8% 的 CVE），**不能**用它反推「这类缺陷的实际比例」——公告的措辞由发布方选，不由缺陷性质定。

**第 2 组 对象词（`:10—23`）**：`web content` 175 行／32 CVE、`file` 164／41、`image` 105／25、`model` 37／7、`font` 34／5、`video` 25／4、`audio` 7／1、`archive` 6／3、`message` 6／1、`photo` 6／1、`zip` 5／2、`calendar` 4／1、`contacts` 4／2、`mail` 3／1。十四个词形，**行级降序不是风险降序**：`file` 41 个 CVE 比 `web content` 32 个多，而 `file` 是公告里最泛的一词。这一组是脚本二 S03 对象类词表的命名依据（第 13.2 节），每个内容类后缀 `_content` 与这里逐词对得上。

**第 3 组 后果词（`:26—30`）**：`unexpected app termination` 133、`disclosure of` 84、`bypass` 78、`memory corruption` 77、`arbitrary code execution` 58。五个词形扫 1,266 行影响句，**没有任何一类写触发条件，也没有任何一类写「类型被误判」**（失败点 3 的实证）。这一组给出 L9 崩溃侧与 L11 复位侧的上限：公告只说后果，不说条件，也不说复位。

**第 4 组 组件集中度（`:33—52`）**：top-20 组件的「含 crafted 行 ÷ 全组件行」。11 个比值 1/1（`ImageIO` 79/79、`CoreGraphics` 15/15、`RealityKit` 8/8、`ColorSync` 8/8、`BOM` 8/8、`WebRTC` 8/8、`CoreText` 8/8、`WebKit JavaScript Bindings` 7/7、`Accelerate Framework` 6/6、`WebKit Canvas` 6/6、`LinkPresentation` 5/5），9 个明显不满（`WebKit` 139/143、`Model I/O` 37/43、`SceneKit` 22/29、`FontParser` 21/26、`CoreAudio` 13/37、`AppleAVD` 12/21、`Audio` 8/11、`CoreMedia` 8/22、`Mail` 6/15）。第 8.3 节用它作为 L5 公告侧唯一读数，本章补一条：`Accelerate Framework` 6/6 同时出现在第 5 组的错位 top-12 里（`:61`，1 个 CVE）——**同一个组件既在「全含 crafted」线上，又在「组件名不含解析层词形」名单里**，这一对就是失败点 4 的最小实例。

**第 5 组 列间错位（`:55—71`）**：影响句写明恶意构造对象、组件名却不含任何解析层词形的 46 行，切片是 `web content` 0、`image` 16、`file` 19、`font` 0（`:56—59`）；这 46 行落在 top-12 组件上，每个组件 1 个 CVE：`CoreServicesUIAgent`、`Accelerate Framework`、`libarchive`、`CoreSymbolication`、`ArchiveService`、`Mail`、`OpenBSM`、`GPUTools`、`Grapher`、`LinkPresentation`、`HomeKit`、`Core Image`。两个 0（`web content` 与 `font`）与两个非 0（`image` 16、`file` 19）合起来说明：**错位只发生在泛化对象词上**，网页与字体这两类在公告里始终由名字里带 `WebKit`／`FontParser` 的组件承担。这一组直接对应脚本二 X 族与 T 族，也是本篇中心事实。

**第 6 组 免交互线索（`:73—74`）**：影响句写成 `without user interaction` 一类措辞的去重 CVE = **0**。这一组是第 10.2 节红线的读数来源，也是本篇正文一律不出现免交互解析表述的唯一依据。0 的含义要收窄：它说的是「公告没有这样写」，不是「系统不会自动处理」；后台处理的公开口径在 `B/…guide.txt:2397`，与公告无关。

**第 7 组 KEV 档案（`:77—89`）**：Apple 条目 95；短描述含恶意措辞的 CVE 52（派生判据是短描述列含 `malicious`，按 CVE 去重）、含 `image` 2、含网页内容类 36、含 `font` 2、含 file/archive/document 类 2；组件词形命中 top-7：`webkit` 78、`kernel` 29、`sandbox` 3、`coregraphics` 2、`imageio` 1、`font` 1、`pdf` 1。这一组与第 2 组的比例完全不同：KEV 的短描述里网页内容类占 36／95，而对象词表里 `file` 才是第二。**在野利用名单的对象词分布与公告的对象词分布不同形**，所以第 13 章把 KEV 侧写成独立一档（`adv.kev_listed`），不与公告侧合并计数。`C/kev-apple.tsv.meta.txt` 给 `catalogVersion` 2026.10.30 与 `count` 1766（全目录条目，Apple 条目 95 是其中一部分）。

**第 8 组 MDM 键表（`:92—96`）**：键名形态命中 218 行，其中 8 行不是键名（`Important`／`Note` 两行加六个平台名行，第 13.1 节逐条给），**纯键名分母 210**；命中内容接收／打开／预览／网页／文件类词形的键 6 个（`allowUIConfigurationProfileInstallation` 与五个 `safari*`，`:94`）；可直接约束「内容能否被打开／预览／联网取回」的键 19 个（`:96` 的名单，含 `allowAirDrop`、`allowAppClips`、`allowCamera`、`allowSafari`、`requireManagedPasteboard` 等）。**210 个键里没有一个指名解析器或解码器**——这就是失败点 7 的分母，也是 P02 与 G04 两条阻断判据的存在理由。

**第 9 组 系统声明 UTI 清单（`:99—112`）**：形如「A type that represents …」的条目 201，分 12 档：文本／代码 54、其他 51、图像 20、可执行／扩展 16、音频 14、视频 12、归档 10、目录与替身 8、3D 模型 6、网页／数据交换 6、个人信息类 2、PDF／打印 2；另有 67 行提到 `conforming`／`base type`／`declare`。这一组是 L4 判定层「反查票」的分母：201 条是公开可回指的声明上限，67 行说明一致性关系在系统清单里本身就是被显式书写的。第 2 档「其他 51」最大，说明公开清单的分类粒度不支持用它给对象类定档——因此脚本二的 `declared_uti`／`resolved_uti` 只回指具体标识串，不回指这 12 档分类。

**第 10 组 WebKit 与「web content」口径（`:115—117`）**：组件名以 `WebKit` 开头的 165 行，其中影响句含 `maliciously crafted` 157 行、含 `web content` 161 行。注意 161 > 157：**存在写明 `web content` 却不含「恶意构造」措辞的 WebKit 行**。所以「组件是 WebKit」与「对象词是 web content」与「措辞是 maliciously crafted」是三个独立筛子，任取两个都不等于第三个——这是把 `adv.component_is_parser_layer` 与 `adv.object_word_in_impact` 设成两个字段而不是一个的原因（G03／R05 的判据）。

**第 11 组 同一 CVE 跨平台行数（`:120—121`）**：单 CVE 最多出现 8 行（`CVE-2026-112470`），只出现 1 行的 CVE 是 47／330。这一组给 X02 与 R02 的形态约束：一个 CVE 在档案里不是一个唯一定位，**跨行换算必须带平台版本行**（`:120` 的 8 行就是同一个 CVE 在 8 个版本条目里各写一次）。本篇所有 CVE 引用都写「CVE 编号 + 行数」两个量，不写单值。

### 16.3 同一件事的两个口径（失败点 8 的实证）

KEV 短描述里「恶意措辞」的计数在两个派生器里不同：`C/readings-18.txt:78` 给 **52**，判据是短描述列含 `malicious`、按 CVE 去重；`C/subset-18.txt:14` 给 **42**，判据是短描述含 `craft` 词形、按条目计数。**两者量纲不同、正则不同**，所以不能互相替换，也不能取其一当作「KEV 里解析类条目的比例」。本篇的处理方式是：正文凡引用 KEV 恶意措辞比例，一律写明派生器与判据（第 13.2 节与本章都用 52 那条，并注明判据是 `malicious`）；第 23.6 节的静态反向对齐把「同一命名、两种正则」列为一条必查项。这一对数字是失败点 8「口径之间不能直接换算」最省事的例子：**它发生在同一个作者的两个脚本之间**，因此对任何台账读者都成立。

`C/subset-18.txt` 另三处本篇要用到的对照读数：`crafted 行 467／组件去重 34／CVE 去重 95`（`:5`，与第 1 组闭合）；解析层词形表 38 个词（`:6`），crafted 子词表里组件名含解析层词形 23 个、不含 11 个（`:7—8`），不含的名单带行数（`:9`：`APFS` 2、`Calendar` 4、`CoreServicesUIAgent` 2、`CoreStorage` 2、`CoreSymbolication` 2、`GPUTools` 1、`Grapher` 2、`HFS` 5、`HomeKit` 5、`Mail` 6、`OpenBSM` 2）；全量词表里但不属 crafted 子词表的 95 个组件（`:10`，前 12 个在 `:11`）。KEV 侧解析对象词 41、其中网页内容类 36（`:15—16`）与第 7 组的 36 同值不同判据（那里的判据是 `web content|browser|safari`，这里同一判据），**41 与 36 之差 5 是文件类词形（pdf／archive／document／image／font）的命中**，说明 KEV 里非网页的解析对象是少数。Quick Look 两份清单的对照（`:19—42`）已在第 17.3 与失败点 5 使用，本章不重复。

### 16.4 读数与章的映射

| 组 | 主要落点 | 作为分母的信号族 |
| --- | --- | --- |
| 1 语料规模 | 13.2、16 全章 | R01／R02 |
| 2 对象词 | 13.2（S03 词表命名）、15.3 | S03、R05、X03 |
| 3 后果词 | 7.3、10.2、12.3 | E05、V 族 |
| 4 组件集中度 | 8.3 | R03、C02 |
| 5 列间错位 | 13.2、3.4 失败点 4 | X01—X04、T 族 |
| 6 免交互 | 10.2 | E01、A04 |
| 7 KEV | 13.2、16.3 | R04／R07、`adv.kev_listed` |
| 8 MDM 键表 | 13.1、4.3 | G01—G04、P02 |
| 9 系统 UTI | 5.1、7.1 | X05、M06 |
| 10 WebKit 口径 | 13.2 | G03、R05 |
| 11 跨平台行数 | 13.2 | X02、R02 |

---

## 17. 可见性边界：这一层读者能拿到什么

### 17.1 三个档位

本篇把「可见性」定义成三档，且这三档是**读者档位**，不是责任档位：

- **A 可核对**：读者拿着一份公开档案就能复核这一格的值。判据是这一格能落到「组 A／组 B 的某文件某行」或「组 C 的某个词表值」。
- **B 可登记不可复核**：读者能理解这一格写的是什么，但无法从公开档案复核其值——它来自设备侧旁证（配置描述文件快照、管理端查询记录）或来自登记方推断。`dom.*` 七格、`rights.sandbox_profile`、`undo.*` 的四种无句复位方法都在这一档。
- **C 不可见**：公开档案里既没有承载这一格的句子，也没有承载它的读数面。L7 的公告侧是唯一一处明确的 C；L8 的隔离标记与来源披露两格是「iOS 侧 C、macOS 侧另有口径」的半 C。

档位与判定档无关：B 档不等于信号，C 档也不等于缺格。**档位影响的是这一格能不能进入对外表述**，A 档可以，B 档只能进内部台账，C 档必须写成边界而不是结论。

### 17.2 十一层逐层

| 层 | 读者能拿到 | 读者拿不到 | 对外表述的上限句 |
| --- | --- | --- | --- |
| L1 | 对象类、容器形态枚举值、`C/readings-18.txt:95—96` 的 19 个键名单、KEV 两个日期列 | 这一条内容的到达时刻与到达通道（公告六列无来源列） | 「台账把这一条登记为来自 X 面，管理面当天没有关闭该通道」 |
| L2 | 声明票的三格形态、`public`／`dyn`／`com.apple` 三个前缀规则、导出优先于导入那一句 | 「系统这一次把它判成了什么」的任何读数 | 「这份内容自带 X 声明，声明形态合规」 |
| L3 | 包标识与团队标识的形态、`B/…guide.txt:2388` 那次平台判定存在性、唯一 bundle 取值的限制键 | 签名验证结果、这一格是否被授权处理该类型 | 「某包标识与某团队标识在台账里被登记为这份内容的承载方」 |
| L4 | 三条票源是否齐备、冲突是否登记、`A/uikit_uidocument.txt:35` 那条扩展名通道句 | 判定优先级（全篇唯一优先级句只解决导出／导入并存） | 「三票中 X 与 Y 相异且已登记为未解」 |
| L5 | 组件×crafted 比值、五个解析入口 API 名、`asm.*` 枚举 | 进程级装配读数、堆栈正文 | 「公告把这一类对象记在 X 组件名下」 |
| L6 | 平台文档的四组域句子（`:2391—2397、1335、1322、2555`） | 这一条内容当时在哪个进程里被解析 | 「按平台文档，这一类承载形态运行在哪一类域里」 |
| L7 | 五类动作的框架句、打开成功／失败回调、清单随版本变化那两句 | 任何免交互读数（命中 0）、后台处理与公告的连接 | 「这一条内容在打开／预览／分享之后被处理」 |
| L8 | 四处口径句（`:2557、2555、1446、1448`）与 `activityvc:10—11` | 隔离标记的 iOS 口径（全档案 `quarantine` 仅 1 次且在 macOS 能力表）、来源披露口径 | 「台账登记提示位为已呈现，提示文本取自 X 来源」 |
| L9 | 23 个平面×件对与六组分解、日期同形规则 | 「平面→件」的一对一关系（三个跨件平面） | 「这一格取自 X 平面，读数时刻为 YYYY-MM-DD」 |
| L10 | 键名单两套（6 与 19）、公告六列结构、KEV meta 三行 | 个体级结论（两个面都只给集合） | 「这一类组件在公告里出现过／这一族行为可被键约束」 |
| L11 | 两种有句的复位方法、五个时间／状态口径段 | 「这条内容现在被复位了」 | 「复位条件成立，核对时刻为 X」 |

### 17.3 四个负空间

本章把第 4—14 章逐章发现的「公开档案里没有」集中登记一次，四条全部进第 26 章边界清单，每条都给出**为什么它不是漏写**：

1. **iOS 侧的隔离标记（quarantine）没有口径（第 26 章 N2）。** 组 A 与组 B 的归档命中一次（`B/…guide.txt:2344`，macOS 能力表），组 C 公告表另有 8 行组件名就叫 `quarantine`（`C/advisory-18.tsv:458—459、708—710、905—907`），平台列逐行是 macOS，`C/readings-18.txt` 命中 0；`notice.quarantine_flag` 的 `set`／`absent` 两值因此没有归档来源。不是漏写：本篇归档里没有 iOS 侧描述这一位的句子，硬引 macOS 那句会造出跨平台换算（失败点 8）。
2. **来源披露（`notice.origin_disclosed`）同理（第 26 章 N3）**，两档 `disclosed`／`absent` 都只能由登记方旁证支撑，属 B 档。
3. **`NSFilePresenter` 的挂起读取态没有对应枚举值（第 26 章 N4）。** `A/uikit_uidocument.txt:56—60` 说的是「别的客户端尝试读取该文档时，系统会**暂停读取**，先给呈现对象保存变更的机会」，`trg.trigger_mode` 的 8 个取值里没有一格叫「挂起后被读」，所以这一类只能记 `not_determinable`。不是漏写：新增取值等于自造词表，回指不到任何公开句子。
4. **复位与再核对层在脚本二里没有独立核对项（第 26 章 N9）**，只能靠 `render_result` 四值与 V05 反查（第 14.3 节）。不是漏写：三件核对项的词表来自声明／通道／观测三段公开口径，复位是登记方动作，公开档案里没有「复位核对项」这一格可对应。

另有两处负空间在第 12 与 13 章已经交代，这里只列名以免遗漏：`modelio_api`（词表有平面、归档无件，第 12.1 结论 2，第 26 章 N6）与字体／归档两类（P05 的「只有类型声明面、没有解析入口文档面」，第 8.4 节，第 26 章 N7）。

### 17.4 能拿到不等于能登记

可见性档位与第 3.3 节的拒收清单是两条独立的闸门，都要过：

- A 档但被拒收清单拦下的，只有**设备绝对路径**这一类：`A/uikit_uidocument.txt:34` 要求台账写文件 URL，而本篇拒收路径，冲突按台账侧让步处理（第 4.3 节，本篇唯一一处公开口径与拒收规则直接对撞的格）。
- B 档但可登记的，全部要在 `doc.source`／`doc.line_ref` 里落到「你凭什么写这一格」，由 `dom.domain_source` 的七种依据承担（第 9.2 节）。
- C 档不进台账，只进边界清单——**台账里没有 C 档这一值**，写成 `unknown` 会与「未登记」混淆，本篇因此要求 C 档在台账里根本不成行。

这一条是第 24 章「把边界清单当成台账缺口」误区的落点。

---

## 18. 五个读数面：声明侧、通道侧、呈现侧、管理侧、公告侧

### 18.1 把 23 个「平面 × 件」对切成五侧

第 12.1 节的六组分解按「平面承载哪一件」分组，适合定 `obs.plane` 的合法值；本章按「读者从哪一侧去看」重新切一次，适合定对外表述。**切分对象是 23 个「平面×件」对（不是 20 个实体平面），每对只归一侧，所以五侧计数相加必须等于 23**：

| 侧 | 对数 | 平面 |
| --- | --- | --- |
| 声明侧 | 3 | `plist_declaration`、`uttype_framework`（声明半）、`tag_mapping_api`（声明半） |
| 通道侧 | 10 | `uttype_framework`（通道半）、`tag_mapping_api`（通道半）、`imageio_api`、`coregraphics_api`、`modelio_api`、`webkit_load`、`uidocument_open`、`openurl_callback`、`activity_share`、`pasteboard_transfer` |
| 呈现侧 | 2 | `quicklook_preview`（通道半与观测半各一对） |
| 管理侧 | 3 | `settings_ui`、`configuration_profile`、`mdm_declaration` |
| 公告侧 | 5 | `advisory_entry`、`kev_entry`、`crash_report`、`vendor_claim`、`app_self_report` |

3 + 10 + 2 + 3 + 5 = 23 ✓。两个类型平面被横切成声明半与通道半，这一件事本身就是第 18 章要说的：**同一个 `UTType` 反查，从声明侧看是「这一格抄自哪儿」，从通道侧看是「反查值落到哪一格」**。呈现侧只有 `quicklook_preview` 一个平面、却占两对，是因为它是唯一一个「通道件与观测件共用」的平面——预览既是入口（通道）也是结果（观测）。

### 18.2 五侧逐条

**声明侧（3 对）**：给的是**登记来源**，不是判定。三个平面里两个（`plist_declaration`、`tag_mapping_api`）只承载声明件，`uttype_framework` 跨两件。锚点：`A/…defining…:5—10、70—88`（四步与键表）、`A/uniformtypeidentifiers.txt:7、25—52`、`A/…system_declared….txt:8—13、14—19、20—23`。上限句：「这一格的值取自 X 声明件」。台账字段：`typ.declared_*`、`rights.exported_type_declared`。码：脚本一 B08、S07、S09；脚本二声明件七项、M01—M06、K03—K05、D01—D05。**声明侧最容易犯的错是把登记来源当成运行时读数**，这就是 T01／T02 的成因。

**通道侧（10 对）**：给的是**入口存在性**——框架能不能把这一格读回来。八个只承载通道件的平面里，`modelio_api` 是词表有值、归档无件的那一个，登记时只能配 `not_determinable` 并把引用格落到公告组件名（第 12.1 结论 2）。锚点见第 12.1 节六组表的第三行。上限句：「这一类内容在这一条通道上有公开入口」。字段：`asm.*`、`typ.resolver_choice`、`typ.type_source`。码：脚本一 C01—C07、R01／R03／R05；脚本二通道件七项、X05—X07、M06、T04、T06、P01、P05、P06。

**呈现侧（2 对）**：给的是**是否呈现与条目数**，不给解析结果。这是五侧里唯一同时属于通道件与观测件的一侧，也是失败点 5 的落点：两份 Quick Look 清单不同形（总览 7 项 `:7—13`，类文档 10 项 `:12—21`，共有词形 8，只在一侧的 `audio`／`live photo`／`video` 与 `csv`／`rtf`，`C/subset-18.txt:19—42`），两份各带一句「清单随版本变化」（`:18`、`:22`）。上限句：「当天这一面呈现过 X」。字段：`trg.preview_only`、`trg.renders_thumbnail`；脚本二的 `render_result` 四值。码：P04（渲染结果记在非预览／自述面）、V03（渲染结果只由自述面给出）、E03。

**管理侧（3 对）**：给的是**这台设备上哪些键被配置**，集合级。`settings_ui` 属 B 档（第 17.1 节，失败点 6 里不承载机制依据），`configuration_profile` 与 `mdm_declaration` 承载同一族句子的三种形态。锚点：`B/mdm-restrictions.txt:3、22—26、738、960`、`C/readings-18.txt:92—96`。上限句：「配置里存在 X 键」。字段：`mgmt.*` 六格。码：脚本一 G01—G04、K01；脚本二 P02（通道件记在管理面，阻断）、P03、X08、`restriction_key` 词表归属。**管理侧向通道侧的换算就是失败点 7**：关掉承载 App 改变的是谁还能打开内容，不是内容被读成什么类型。

**公告侧（5 对）**：给的是**组件×CVE 集合与报告标识**。三个观察平面（`advisory_entry`、`kev_entry`、`crash_report`）加两个自述平面（`vendor_claim`、`app_self_report`）同侧，是因为它们都不承载机制、只承载「外部写过的一句话」。锚点：`C/advisory-18.tsv:1—2`、`C/kev-apple.tsv:1—2`＋meta 三行、`B/…guide.txt:1322、1335`（只给关联句）、`B/…guide.txt:2388`。上限句：「公告把这一类对象记在 X 组件名下」「崩溃只登记报告标识」。字段：`adv.*` 七格、`obs.crash_report_ref`。码：脚本一 R01—R07、X01、X02、K03、O01；脚本二 X01—X04、P01、P07、M04。

### 18.3 三条跨侧换算禁令

1. **声明侧 → 通道侧不可换算**（失败点 1）。合法声明不保证被读到，`:78` 的「必需」只约束声明文件本身合法。落点：T01、D02、B02。
2. **管理侧 → 通道侧不可换算**（失败点 7）。P02 阻断的正是「把通道件核对项记在管理面平面上」。
3. **公告侧 → 任一侧的个体格不可换算**（失败点 4）。`adv.component` 是系统组件名，与 `asm.parser_framework` 之间没有公开换算句；第 5 组的 46 行错位证明两侧连筛选结果都不重合。落点：X01—X04、R03、R05、T08。

禁令的写法约束只有一句：**跨侧结论必须同时给出两侧的平面名、字段与行号**（`doc.source` + `doc.line_ref`），否则按 X01 阻断处理。这一句就是第 3.4 节失败点 8 的可执行形式。

### 18.4 五侧与两支脚本的输入

脚本一只有一个输入（台账），它的 `obs.plane` 12 个取值按「证据种类」分面，与五侧的关系是**多对多**（第 12.1 结论 3：两侧同名实体平面只有 4 个）。脚本二有三个输入，与五侧是一一对得上的：10 列清单承载声明侧、通道侧、呈现侧的登记（第 5—8 列分别是读数平面、词表归属、引用、对外表述），3 列能力表定义每类对象**应当**有哪几格，制表符 3 列词表提供管理侧与公告侧的公开词形回指。**词表回指失败就是公开侧证据缺失**，所以 X05—X07 三条（标识类、符号与键类、标签类分别回指不到）落在这条线上，而不是落在清单自身的形态线上。

五侧齐备的对象，在本篇里记作「三件差集、平面可得性、公开词表三段齐备」，也就是脚本二的 Q1；缺任一段只能定覆盖面，不能定归属（Q3）。这一句是第 19 章两套判定模型的入口。

## 19. 两套判定模型：J1—J4 与 Q1—Q4

两套模型都只有四档，都从 1 到 4 **变差**，都是**表述资格**而不是风险等级，也都只由两支脚本的输出决定——**不需要任何设备侧数据**。

### 19.1 J1—J4：一条台账自己站不站得住（脚本一）

判据按脚本一的实现（`tools/parsing-chain-ledger-review.sh:342—345`）逐字给出，四档文案在第 144—147 行：

| 档 | 触发条件（代码原义） | 文案（脚本第 144—147 行逐字） |
| --- | --- | --- |
| J4 | 该对象缺任一必备格（`miss[id]`），或命中任一阻断码（`hard[id]`，第 58 行置位） | 存在结构性或拒收信号（S／K 族或必备格缺失）：本行不可用 |
| J1 | 无阻断且 `percnt[id] = 0` | 十二格齐备且无阻断信号：这条解析链可进入对外归属表述 |
| J2 | 无阻断且 `percnt[id]` 为 1—2 | 仅 1—2 条非结构性信号：可作内部台账使用，暂不对外表述 |
| J3 | 无阻断且 `percnt[id] ≥ 3` | 3 条以上非结构性信号：归属结论尚未收敛 |

三个必须写清的机制事实：

1. **阻断集只有 12 个码**：`S01—S09`＋`K01 K02 K03`（第 135—136 行写死），其余 59 个码全为非阻断。因此 J2／J3 的分母天然只含非阻断信号——一旦有 S／K 族命中就直接 J4，不会再落 J2。
2. **`percnt[id]` 计的是该对象的信号行数，不是码数**（第 57 行：每次 `emit()` 都自增）。同一码在同一对象上出现三次就计三次，所以第 3 档的门槛比「三个不同码」更容易达到。第 23.2 节的逐次实跑表里，`codes` 夹具的 63 个对象全部落 J4，正是因为每个对象都至少被一条 S 或 K 族命中。
3. **信号一律带出处**。`emit()` 写出的每一行末尾由 `src(code)`（第 81 行）拼上 `DOC[code]`，`DOC` 数组共 71 条，与 71 个码一一对应（第 23.4 节的码数唯一性与覆盖验收逐码核对）。**任何一条信号都能被读者自己回到归档行核**——这是本文用「信号带引用」而不是「信号带解释」的原因。

### 19.2 Q1—Q4：三件对完之后归属还能不能立起来（脚本二）

判据按脚本二的实现（`tools/parsing-chain-tripartite-diff.sh:519—522`），四档文案在第 523—526 行：

| 档 | 触发条件（代码原义） | 允许表述 |
| --- | --- | --- |
| Q4 | 该对象所属对象类不在能力表里（`!(kdOf[id] in capKdSet)`）、能力表一行都没有（`capKdN = 0`）、或该对象在读取阶段就有形态失败（`subjBad[id]`，第 292 行：对象类越界 S03 或核对项越界 S04） | 连可得性都不能定：这一格按公开口径可不可能有读数都说不清 |
| Q2 | `hardN ≥ 1`，即该对象至少有一条阻断码（HB 42 个码，第 204—211 行） | 三件差集、平面可得性或公开词表至少一段互相矛盾，不能作为对外归属表述 |
| Q3 | `holesReq > 0`（required 覆盖空洞）、`reqNoRef > 0`（required 有读数无引用）、`recTot = 0`（整段无已读数）或 `soft > 0`（任一非阻断码） | 只能定「这一类内容应当有哪几格」，不能定「这一格由谁读回」 |
| Q1 | 以上全不触发 | 三件差集、平面可得性与公开词表三段齐备且无阻断，可用于对外表述这一条解析链缺哪一格 |

**Q 档自身不计信号**：第 105 行 `else if (code !~ /^Q[1234]$/) soft[id]++` 明确把四档排除在 `soft` 之外，否则 Q3 会因为自己刚发出的 Q3 行而无限自证。同一条件还出现在另外三处：非 Q 信号写 stderr（第 559 行）、逐对象 Q 档写 stdout（第 560 行）、`信号行数`（第 562 行）与`不同信号码`（第 563 行）都只统计非 Q 行，按码计数表（第 568 行）同样跳过 Q 码。**四档因此永远不进「阻断信号条数」，也就永远不会把一次干净运行推出退出码 0**——这是 Q 档与 J 档共用退出码语义（第 570 行）却不破坏下界的原因。

### 19.3 两套模型的接缝

J 查**一条登记内部**的完整性与形态，Q 查**三份登记之间**的成对性与公开词表回指。因此四种组合全部真实可达，其中两对容易被误读：

- **J1 而 Q4**：台账十二格齐备、形态全合规，但它所属对象类在能力表里没有一行（`!(kdOf[id] in capKdSet)`），或能力表整体退化（`capKdN = 0`）。第 23.2 节 R32（`same-file`：三份输入都指向同一个文件，能力表与词表各读到 0 行）与 R29（`empty-tables`）就是 4 个对象整批落 Q4 的实证。
- **J4 而 Q1**：在同一份数据上不可达。J4 的两类原因各有各的落点：S／K 族在脚本二一侧全部在阻断集里（`S01—S10`、`K01—K05`，第 204—205、207 行），命中即 Q2；「必备格缺失」在脚本二一侧对应 required 覆盖空洞 `D02`（第 414、421 行），`D02` 是非阻断码且会把 `holesReq` 置位，落 Q3。**若某条台账 J4 而三件对账 Q1，说明两份输入的形态规则被改过，属工具漂移，不是结论。**注意两处的 `S09` 同号不同义：脚本一的 `S09` 是必备格缺失，脚本二的 `S09` 是同一核对项出现两种登记口径（第 312 行），按第 15.1 节第二条规矩各自消歧，不互相引用。

推荐口径是把两档并列写出（「逐条审查 J2，三件对账 Q3，原因是……」），**绝不合并成单一分数**。合并会掩盖一件事：逐条越严谨，越容易让三件缺口看起来像已闭合。第 15.4 节讲的「必须同时给两档」就是这条。

---

## 20. 运营指标 O1—O10

十个指标全部可用第 21、22 章两支脚本的输出算出，不需要设备侧数据，也不需要任何新读数源。**它们是台账质量指标，不是风险指标**：任何一个到 1 都不表示更安全，只表示表述资格更完整。

| 号 | 指标 | 计算方式 | 建议口径 |
| --- | --- | --- | --- |
| O1 | 必备格齐备率 | 未触发 `S09` 的对象数 ÷ 台账对象总数 | 必须为 1；低于 1 时该批台账整体不可对外（12 格分布见第 15.3 结论 1） |
| O2 | 三票登记率 | `typ.declared_uti`／`declared_mime`／`filename_ext` 至少两格有实值的对象占比 | 反证码 `B01`（三票全无）、`B02`（只有扩展名）；与第 7.2 的三条漂移直接对应 |
| O3 | 结论可回指率 | `doc.conclusion = confirmed` 且未触发 `X01`／`X02` 的对象 ÷ 所有 confirmed 对象 | 必须为 1；这是失败点 8 的唯一机器化落点 |
| O4 | 组件-对象一致率 | 1 −（`R01`＋`R03`＋`R05` 命中对象数 ÷ 登记了 `adv.component` 的对象数） | 反证第 5 组 46 行列间错位被误用为个体结论的比例 |
| O5 | 执行域依据率 | `dom.domain_class` 有实值且 `dom.domain_source` ∈ 可回指四档的对象 ÷ 登记了执行域的对象 | 反证码 `D01`、`D06`；`screenshot`／`assumed`／`vendor_claim` 三档不计入分子（失败点 6） |
| O6 | 三件齐备率 | 脚本二 `Q1` 对象数 ÷ 三件清单对象数 | 非 1 时禁止对外表述「这一格由谁读回」；只看 J 档会掩盖这项缺口 |
| O7 | 能力表覆盖率 | `kdOf[id]` 命中 `capKdSet` 的对象数 ÷ 对象总数 | 必须为 1；低于 1 说明对象类拼写或能力表退化，对应 `D04` 与 `Q4` |
| O8 | 平面-时刻齐备率 | `obs.plane`＋`obs.field_read`＋`obs.read_at` 三格齐备的对象占比 | 第 12.4 节「三件齐备才算一条读数」的指标化；反证码 `O02`（有观测平面却未登记读数时刻，`codes` 夹具上命中 63 次＝每个对象一次） |
| O9 | 告知一致性 | `notice.prompt_shown = shown` 且 `notice.warning_text_source` ∈ 可回指三档的对象 ÷ 声称已告知的对象 | 必须为 1；反证 `N04`（截屏／厂商说法充当机制依据） |
| O10 | 再证明覆盖率 | `undo.reproof_done = true` 且带 `undo.verified_at` 的对象 ÷ 登记了复位动作的对象 | 本文承认为最难达标的指标；缺核对时刻只计未覆盖、不降级（第 14.3 节） |

三条使用说明：

- **O1、O3、O5、O7、O9 是「必须为 1」的一类**，它们的分子分母同源，任何一条命中就说明该批台账有格被写成自由文本或有结论没有回指处。O3 与 O7 是两个不同侧的可回指：O3 管引用（行号），O7 管分类（对象类）。
- **O2、O4、O6、O8、O10 是「趋势指标」**，不达标不等于错误。O4 的分子里那 46 行错位本身不是缺陷——`C/readings-18.txt:54—59` 是真实读数，缺陷只发生在把它写成个体结论时。
- **O10 永远不可能到 1**。`reproof_basis` 的四档可核对依据之外还允许 `assumed`（第 14.3 节表），而「复位后再打开一次没出问题」这个观测本身不排除缓存、版本与内容三个混淆变量。它的正确用法是趋势对照（同一口径下季度间是否恶化），不是达标。

---

## 21. 只读核验脚本一：解析链台账逐字段审查器

这支脚本回答一个问题：**一段非可信字节被写成一行台账之后，这行台账自己站不站得住。**它不检查文件、不检查设备、不检查解析器，只检查登记。

### 21.1 它查什么

`tools/parsing-chain-ledger-review.sh`（363 行）逐对象核对十二格：来源、类型、权利、装配、执行域、触发、观测、告知、复位、管理面、公告对齐、引用与结论。它的判据全部来自组 A／B／C 归档的公开句子，每条信号末尾自带出处——第 148—218 行的 `DOC` 数组共 71 条，把 71 个码逐一绑到一句文档原文或一段 usage 文本，因此**任何一条信号都能被读者自己回到归档行核**。这是本文用「信号带引用」而不是「信号带解释」的原因。

它专查的六类错误对应第 3.4 节的六处换算失败：把签名形态当来源形态（失败点 1 的近亲，`A02`）、三票相异却记无冲突（`B03`／`B04`，失败点 2）、用公告后果句支撑判定结论（`B05`、`X01`，失败点 3）、组件名与对象词互不校验（`R03`／`R05`，失败点 4）、告知文本取自截屏或假定（`N03`；`N04` 的信号出处那一句直接写成「见本文第 3.4 节失败点 6」）、管理面结论不指名键（`G01`／`G04`，失败点 7）。

### 21.2 输入格式与十二个命名空间

台账每行一条记录：`<内容对象标识>,<字段名>,<值>`；`#` 开头与空行忽略，行尾 CR 忽略，**值里不能含逗号**（usage 第 17 行逐字写明）。字段名必须带命名空间前缀，共十二个登记空间加一个拒收空间（usage 第 18—31 行逐空间列出，每个空间还带出自己的字段清单）：`id.*` 对象与来源、`typ.*` 类型判定、`rights.*` 权利、`asm.*` 解析装配、`dom.*` 执行域、`trg.*` 触发条件、`obs.*` 观测平面、`notice.*` 告知、`undo.*` 复位、`mgmt.*` 管理面、`adv.*` 公告对齐、`doc.*` 引用与结论，以及 `sec.*`——`sec.*` 下任何字段直接触发 `K01`（第 233 行）。

必备格十二个（第 32—34 行），缺任一按 `S09` 记并落 J4：`id.obj_kind`、`id.source_face`、`id.provenance`、`typ.type_source`、`asm.parser_framework`、`asm.parser_layer`、`dom.domain_class`、`trg.trigger_mode`、`obs.plane`、`notice.prompt_shown`、`undo.reset_method`、`doc.source`。第 15.3 节的分布结论（L2 与 L3 一个必备格都没有）就是照这一行清单数出来的。

枚举值在 `BEGIN` 段逐格写死（第 84 行起，`DOM[]`）。举两格：`id.obj_kind` 的合法取值是 `image photo font video audio archive zip bundle document pdf text_page web_markup model_3d scene_reality plist xml_json contacts_entry calendar_event mail_message chat_message note thumbnail icon` 加四个哨兵；`id.container_kind` 是 `single_file container_directory app_bundle extension_bundle network_response message_attachment push_payload backup_item web_page stream` 加四个哨兵。枚举之外一律算越界（`S07`），不做「相近即可」的宽容。

一个能看清这套宽容边界的设计细节是 `push_payload`：它同时出现在 `id.container_kind`（第 85 行）与 `id.source_face`（第 86 行）两个枚举里，也就是**允许登记「这段字节是从推送载荷进来的」**；但 `trg.trigger_mode`（第 105 行）只有 `user_open`／`user_preview`／`background_auto`／`render_pipeline`／`message_auto` 五档实值加三档哨兵，没有任何一档表示「不经任何动作即被解析」。于是「把推送载荷写成免交互解析」这种写法只有两条出路：生造一个取值直接撞 `S07`；写成 `background_auto` 则撞 `E02`（自动处理却没有告知位）。这条枚举缺口对应第 10.2 节读到的事实——`C/readings-18.txt:73—74` 那 467 行 impact 里免交互措辞命中 0，`E01` 的信号出处（第 175 行）写的就是这条读数。

### 21.3 信号族与阻断设计

| 族 | 码数 | 覆盖 | 是否阻断 |
| --- | --- | --- | --- |
| S 行式与命名空间 | 9 | 列数、空标识、同字段重复登记、未登记命名空间、清单外字段、空值、枚举与布尔越界、日期形态、必备格缺失 | 全部阻断（J4） |
| K 内容越界 | 3 | `sec.*` 空间；形似设备绝对路径／长载荷／Base64 形状／密钥串的取值；崩溃引用形态 | 全部阻断（J4） |
| A 来源与承载方身份 | 6 | 来源不可判却给确认（`A01`）、来源标记与签名形态矛盾（`A02`）、包标识与团队标识形态（`A03`／`A06`）、URL 打开面登记为自动处理（`A04`）、解析层为网页引擎但对象是图像（`A05`） | 非阻断 |
| B 类型声明与判定 | 8 | 三票全无（`B01`）、一票独大（`B02`）、嗅得与声明相异却记无冲突（`B03`）、冲突未解却给确认（`B04`）、依据为假定或厂商说法（`B05`）、解析器选择缺失或不可判却给确认（`B06`／`B07`）、三格形态同检（`B08`） | 非阻断 |
| C 解析装配 | 7 | 进程种类未登记（`C01`，301 行）、内核文件系统层却未记内核域（`C02`，306 行）、宿主进程未登记（`C03`，302 行）、声明为 XPC 助手却把端点记为不适用（`C04`，303 行）、在扩展进程内解析却无沙箱画像（`C05`，304 行）、第三方编解码在特权域内执行（`C06`，305 行）、使用第三方编解码却未登记解析框架（`C07`，293 行） | 非阻断 |
| D 执行域 | 6 | 登记了执行域却没写来源平面（`D01`，312 行）、自动处理且无隔离机制（`D02`，307 行）、非内存安全层却未启用 ASLR（`D03`，308 行）、开启 JIT 的执行域不是被分离渲染域或 App 域（`D04`，309 行）、需 entitlement 却无沙箱画像（`D05`，310 行）、执行域结论只来自厂商说法／截屏／假定（`D06`，311 行） | 非阻断 |
| E 触发条件 | 5 | 同时登记需用户动作与自动处理（`E01`）、自动处理却无告知位（`E02`）、预览未登记缩略图位（`E03`）、网络投递且自动处理却无补丁通道（`E04`）、触发面与进入面矛盾（`E05`） | 非阻断 |
| G 管理面 | 5 | 称管理面可配内容却没有键名（`G01`，331 行）、键不在 218 键清单内却用来给确认结论（`G02`，332 行）、登记了 payload 却没写键来源（`G03`，333 行）、管理面结论为可配但未指名任何键（`G04`，334 行）、限制键形态非法（`G05`，247 行：`mgmt.restriction_key` 必须是小驼峰） | 非阻断 |
| N 告知 | 5 | 自动处理但告知位未登记（`N01`）、称不支持隔离位却称来源已披露（`N02`）、告知文本依据是截屏或假定（`N03`）、自动处理且无提示又无说明句（`N04`）、登记有提示却说告知文本不适用（`N05`） | 非阻断 |
| O 观测平面 | 4 | 崩溃报告面读不出告知状态（`O01`）、有观测平面却未登记读数时刻（`O02`）、只靠厂商自述平面给确认（`O03`）、平台文档与 App 自述并用却未说明冲突处理（`O04`） | 非阻断 |
| R 公告对齐 | 7 | 登记了 impact 对象词却没有组件名（`R01`，335 行）、CVE 形态非法（`R02`，245 行）、组件名不属于解析层却用它给确认结论（`R03`，336 行）、有组件名但既未核对 KEV 也未登记补丁通道（`R04`，339 行）、对象词为 image 而组件名与之无关且未核对（`R05`，338 行）、修复版本形态非法（`R06`，246 行）、在 KEV 名单内却把补丁通道记为非发布（`R07`，337 行） | 非阻断 |
| V 复位与再证明 | 4 | 复位方法不可判定却声称已再证明（`V01`，330 行）、声称已再证明但缓存未清（`V02`，327 行）、声称有残留但未登记核对时刻（`V03`，328 行）、再证明依据为假定（`V04`，329 行） | 非阻断 |
| X 引用 | 2 | 确认结论缺来源文件或行号（`X01`，340 行）、行号引用形态非法（`X02`，248 行） | 非阻断 |

阻断集只收 S 与 K 两族（第 135—136 行，12 码），设计理由与脚本二同源：**S／K 族说的是「这一行不能读」，其余族说的是「这一行要降级使用」**。因此这支脚本的汇总里「信号行数」与「阻断信号条数」两个数字**天然不等**（`codes` 夹具：1,055 行信号、736 条阻断），这与第 19.1 节结论 1 是同一条设计的两侧。

### 21.4 输出与退出码

逐条信号写 **stderr**，形如 `码<TAB>对象<TAB>说明（见 … 第 N 行）`；四档判定写 **stdout**；末尾固定三行汇总（第 353—355 行：解析链对象数／信号行数／判定行数、不同信号码／阻断信号条数、判定分布 J1—J4），随后把逐条信号（第 356 行）与按码排序的计数表（第 357—360 行）写 stderr。`-q` 关掉的只有 stdout 上那几行逐对象判定（第 346 行 `if (!QUIET)`）；stderr 的信号、汇总与计数表一行不少地照打——它是输出开关，不改判定也不改退出码（第 23.2 节 R6 就是同一份 `codes` 夹具带 `-q` 再跑一次，与 R1 逐字段对照：对象数、信号行数、不同码数、阻断条数与 J 分布五个数全等，只差 stdout 那 63 行）。

退出码：`exit (blocked > 0 ? 1 : 0)`（第 361 行）；参数校验只要求「至少一份输入且每份都存在」（第 49—50 行），不满足给 2，所以一次传多份台账是合法用法。第 4 次实跑（`multi`）把 good／mid／bad 三份一次传入，得到 `解析链对象数=68 信号行数=1059 不同信号码=71 阻断信号条数=736`、`判定分布 J1=3 J2=1 J3=1 J4=63`（`FX/run-log.txt` 第 2427—2430 行）——71 个码在这一份输出里全部非零，这是第 23 章覆盖验收的主证据。第 5 次实跑（`twice`）把同一份 good 台账传两遍，`S03 同一字段重复登记` 命中 216 次，三个对象整批落 J4（第 2655—2658 行：`对象数=3 信号行数=216 不同信号码=1 阻断信号条数=216`）：合并读入而不是分批读入，是这支脚本刻意选定的行为，同一对象的同一字段不允许有两个取值。

### 21.5 它不做什么

- **不调用任何命令行工具。** `mdls`／`mdimport`／`spctl`／`codesign`／`defaults`／`log`／`sysctl`／`xcrun`／`profiles` 这九个名字在整支脚本里各只出现一次，就是头部注释第 8 行那句「不调用……等任何命令行工具」；`file` 一词另在第 121、158、198 行以英文单词形态出现在枚举与公告读数引用里，同样不是命令入口。第 23.1 节 P4 那条 grep 是全量实证（它扫的是十六个工具名），P4b 是同一条规则的整词复核——注意 P4b 在 `LC_ALL=C` 下只列出前三行：第 198 行那处 `file、` 后面紧跟全角顿号，字节级词边界判定与 UTF-8 语言环境不同，所以那一行在 `C` 下不整词命中。这不是遗漏而是记录口径，第 23.1 节把这条差异原样写出。usage 文本、`BEGIN` 段与判定段都没有任何命令入口，P4d 那条「命令位置探测」（P4c 用两条样例证明它不是空转）在脚本一全文为空匹配。
- 不联网、不读设备状态、**不打开任何被登记的对象**、不修改输入。唯一写出目标是 `mktemp -d` 建的临时目录（第 52 行，前缀 `pcl.XXXXXX`），第 53 行 `trap` 在 EXIT／INT／TERM 删除；awk 程序体内没有 `system()`、没有 `getline < 文件`、没有 `popen()`，本实现也不向该目录写入任何字节。
- 不接受内容。文件正文、形似设备绝对路径的取值、形似共享密钥或口令的串、超长 Base64 载荷、真实联系人／健康／位置样本、可还原身份的语音描述、真实用户检索词一律拒收（头部注释第 7 行是拒收声明；执行点是第 233 行 `K01`、第 239 行 `K02`、第 249 行 `K03`——分别对应 `sec.*` 空间、`devPath()`／`longBlob()`／`b64ish()`／`secretish()` 四个形态函数（第 77—80 行）与崩溃引用非报告标识形态）。所有夹具取值均为合成词表，不含真实姓名、地址、电话号码与应用账号。

### 21.6 合格夹具读数

`FX/ledger-18-good.txt`（217 行）跑出的完整输出（取自 `FX/run-log.txt` 第 1198—1207 行，逐字）：

```text
$ tools/parsing-chain-ledger-review.sh FX/ledger-18-good.txt
J1	IMG_PNG_LOCAL	十二格齐备且无阻断信号：这条解析链可进入对外归属表述
J1	WEB_PAGE_REMOTE	十二格齐备且无阻断信号：这条解析链可进入对外归属表述
J1	ARC_ZIP_DOWNLOAD	十二格齐备且无阻断信号：这条解析链可进入对外归属表述

解析链对象数=3 信号行数=0 判定行数=3
不同信号码=0 阻断信号条数=0
判定分布 J1=3 J2=0 J3=0 J4=0
$ exit=0
```

三个对象分别代表三种典型形态：本地单文件图像（`IMG_PNG_LOCAL`）、远端网页内容（`WEB_PAGE_REMOTE`）、下载来的归档（`ARC_ZIP_DOWNLOAD`）。`ARC_ZIP_DOWNLOAD` 能拿 J1 很关键：它证明脚本不把「内容来自远端且是容器」本身当错误，只要求 `id.provenance = remote_untrusted` 与 `id.signature` 两格不互相矛盾（`A02` 的判据）、并且归档一侧承认 `asm.parser_layer = archive_content` 无解析入口文档面（第 8.4 节的 P05 负空间）。

### 21.7 全量源码

```bash
#!/usr/bin/env bash
# parsing-chain-ledger-review.sh —— 解析链台账逐字段审查器（离线 / 只读 / 不联网 / 不碰设备）
# 输入：一份或多份台账文本，每行一条记录：  <内容对象标识>,<字段名>,<值>
# 输出：逐条信号码（stderr） + 每个对象的四级判定（stdout） + 汇总
# 本脚本只判定「一段非可信字节被登记为一条解析链台账之后，这行台账自己站不站得住」：
# 不含构造恶意文件、不含解析缺陷定位、不含崩溃复现与载荷投递，也不含任何绕过隔离、告知或管理面审计的做法。
# 台账里出现文件正文、形似设备绝对路径的取值、形似共享密钥或口令的串、超长 Base64 载荷或真实人名地址时触发 K01—K03 并要求删除该字段。
# 本脚本不联网、不调用 file/mdls/mdimport/spctl/codesign/defaults/log/sysctl/xcrun/profiles 等任何命令行工具、
# 不读取设备状态、不打开任何被登记的对象；唯一写出目标是 mktemp -d 创建的临时目录，退出时删除。
set -u
LC_ALL=C; export LC_ALL

usage() {
  cat <<'EOF'
用法: parsing-chain-ledger-review.sh [-q] 台账文件 [...]
  -q  不输出逐对象判定行；-h/--help 显示本帮助
台账行格式: <内容对象标识>,<字段名>,<值>    # 开头与空行忽略，行尾 CR 忽略，值里不能含逗号
字段命名空间（十二个 + 一个拒收空间）:
  id.*      对象与来源（obj_kind / container_kind / source_face / provenance / signature / bundle_id / team_id / container_size_bucket）
  typ.*     类型判定（declared_uti / declared_mime / filename_ext / sniffed_type / type_source / type_conflict / resolver_choice）
  rights.*  权利（content_owner / open_mode / exported_type_declared / owns_document / sandbox_profile / requires_user_consent）
  asm.*     解析装配（parser_framework / parser_layer / host_process / process_kind / xpc_service / runs_in_extension / third_party_codec）
  dom.*     执行域（domain_class / isolation_mechanism / memory_safety_class / aslr_used / jit_allowed / entitlement_needed / domain_source）
  trg.*     触发条件（trigger_mode / user_action_required / auto_processed / preview_only / remote_initiated / renders_thumbnail）
  obs.*     观测平面（plane / field_read / read_at / crash_report_ref / list_visible）
  notice.*  告知（prompt_shown / quarantine_flag / origin_disclosed / warning_text_source / notice_note）
  undo.*    复位（reset_method / cache_cleared / residue_claimed / reproof_done / reproof_basis / verified_at）
  mgmt.*    管理面（mdm_configurable / restriction_key / key_in_inventory / payload / supervised / key_source）
  adv.*     公告对齐（component / component_is_parser_layer / cve / kev_listed / object_word_in_impact / patch_channel / fix_version）
  doc.*     引用与结论（source / line_ref / conclusion）
  sec.*     拒收用命名空间：本空间下任何字段都会触发 K01
必备格（缺任一按 S09 记，并落 J4）：id.obj_kind id.source_face id.provenance typ.type_source
  asm.parser_framework asm.parser_layer dom.domain_class trg.trigger_mode obs.plane
  notice.prompt_shown undo.reset_method doc.source
形态受检字段（形状不合法按对应信号码记）：
  typ.declared_uti / typ.declared_mime / typ.filename_ext 按 B08；id.bundle_id 按 A03；id.team_id（10 位字母数字）按 A06；
  adv.cve（CVE-年-序号）按 R02；adv.fix_version（纯数字点分）按 R06；mgmt.restriction_key（小驼峰单标识）按 G05；
  doc.line_ref 只写 `1234` 或 `6-9` 这一种形态，带「第／行」前缀的写法在两份台账之间不可换算，按 X02。
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

TMPD=$(mktemp -d "${TMPDIR:-/tmp}/pcl.XXXXXX") || { echo "无法创建临时目录" >&2; exit 2; }
trap 'rm -rf "$TMPD"' EXIT INT TERM

awk -v QUIET="$QUIET" '
function emit(code, id, msg,   k) {
  cnt[code]++; percnt[id]++; lines[++nline] = sprintf("%s\t%s\t%s", code, (id==""?"-":id), msg src(code))
  if (code in HB) hard[id] = 1
}
function GV(i, f,   k) { k = i SUBSEP f; return (k in valof) ? valof[k] : "" }
function hasToken(s, t,   n, arr, i2) { n = split(s, arr, " "); for (i2 = 1; i2 <= n; i2++) if (arr[i2] == t) return 1; return 0 }
function istrue(v)  { return (v=="true"||v=="yes"||v=="1") }
function isfalse(v) { return (v=="false"||v=="no"||v=="0") }
function isbool(v)  { return (istrue(v) || isfalse(v) || v=="unknown" || v=="not_recorded" || v=="not_applicable") }
function isNA(v)    { return (v=="" || v=="not_recorded" || v=="unknown") }
function isISOdt(v) { return (v ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]([ T][0-9][0-9]:[0-9][0-9](:[0-9][0-9])?)?([Zz]|[+-][0-9][0-9]:?[0-9][0-9])?$/ && validCal(v)) }
function validCal(v,  p, mo, dy) { split(substr(v,1,10), p, "-"); mo = p[2]+0; dy = p[3]+0; return (mo>=1 && mo<=12 && dy>=1 && dy<=31) }
function isInt(v)   { return (v ~ /^[0-9]+$/) }
function isCVE(v)   { return (v ~ /^CVE-[0-9]{4}-[0-9]{4,}$/) }
function isUTI(v)   { return (v ~ /^public\.[a-z0-9][a-z0-9._-]*$/ || v ~ /^ut-[a-z0-9.-]+$/ || v ~ /^[a-z][a-z0-9-]*(\.[a-z0-9-]+)+$/) }
function isMIME(v)  { return (v ~ /^[A-Za-z0-9.+-]+\/[A-Za-z0-9.+-]+$/) }
function isExt(v)   { return (v ~ /^[A-Za-z0-9]{1,10}$/) }
function isBundle(v){ return (v ~ /^[A-Za-z0-9][A-Za-z0-9._-]*\.[A-Za-z0-9][A-Za-z0-9._-]*$/ && v !~ /[ ]/) }
function isTeamID(v){ return (v ~ /^[A-Za-z0-9]{10}$/) }
function isLineRef(v) { return (v ~ /^[0-9]+(-[0-9]+)?$/) }
function isVer(v)   { return (v ~ /^[0-9]+(\.[0-9]+){0,3}$/) }
function devPath(v) { return (v ~ /^\/(Applications|private|var|Users|System)\// || v ~ /\/var\/mobile\//) }
function longBlob(v){ return (length(v) > 120) }
function b64ish(v)  { return (v ~ /^[A-Za-z0-9+\/]{40,}={0,2}$/) }
function secretish(v){ return (v ~ /^(glpat-|ghp_|gho_|xox|AKIA|Bearer |-----BEGIN)/) }
function src(c)     { return (c in DOC) ? "（" DOC[c] "）" : "" }
BEGIN {
  FS = ","
  DOM["id.obj_kind"]="image photo font video audio archive zip bundle document pdf text_page web_markup model_3d scene_reality plist xml_json contacts_entry calendar_event mail_message chat_message note thumbnail icon not_applicable none not_recorded unknown "
  DOM["id.container_kind"]="single_file container_directory app_bundle extension_bundle network_response message_attachment push_payload backup_item web_page stream not_applicable none not_recorded unknown "
  DOM["id.source_face"]="files_app share_sheet safari_download mail_attachment messages_attachment airdrop cloud_download url_scheme_open universal_link quicklook_preview spotlight_preview in_app_open web_view_response push_payload backup_restore app_group_drop not_applicable none not_recorded unknown "
  DOM["id.provenance"]="local_user_created remote_untrusted remote_trusted app_built_in system_built_in mdm_delivered not_determinable not_recorded unknown "
  DOM["id.signature"]="signed_store signed_dev signed_enterprise signed_adhoc unsigned platform_binary remote_no_signature not_applicable none not_recorded unknown "
  DOM["id.container_size_bucket"]="tiny small medium large oversize not_applicable none not_recorded unknown "
  DOM["typ.type_source"]="declared_by_owner sniffed_content system_inferred extension_only vendor_claim assumed not_determinable not_recorded unknown "
  DOM["typ.type_conflict"]="none recorded unresolved not_applicable not_recorded unknown "
  DOM["typ.resolver_choice"]="system_default app_declared importer_plugin extension_quicklook web_engine host_library not_determinable not_applicable none not_recorded unknown "
  DOM["rights.content_owner"]="app user system mdm_profile not_recorded unknown "
  DOM["rights.open_mode"]="read_only read_write editable preview_only not_applicable not_recorded unknown "
  DOM["rights.sandbox_profile"]="app_sandbox extension_sandbox restricted_helper detached_renderer kernel_none not_determinable not_applicable none not_recorded unknown "
  DOM["asm.parser_framework"]="ImageIO CoreGraphics CoreText FontParser ColorSync AVFoundation CoreMedia MediaToolbox AVEVideoEncoder AppleAVD ModelIO SceneKit RealityKit WebKit JavaScriptCore Foundation libarchive Compression BOM APFS HFS udf open_source_codec vendor_codec not_applicable none not_recorded unknown "
  DOM["asm.parser_layer"]="image_codec font_parser text_shaping vector_raster media_demux video_decoder audio_decoder web_engine js_engine model_loader archive_unpack color_profile metadata_parser plist_parser contacts_calendar_parser kernel_filesystem driver_firmware not_parser_layer not_applicable not_recorded unknown "
  DOM["asm.process_kind"]="app_process system_service xpc_helper renderer_service extension_process kernel_task not_determinable not_recorded unknown "
  DOM["asm.xpc_service"]="named_endpoint anonymous not_applicable not_recorded unknown "
  DOM["dom.domain_class"]="app_sandboxed helper_detached renderer_detached system_service kernel privileged_extension not_determinable not_recorded unknown "
  DOM["dom.isolation_mechanism"]="sandbox xpc_boundary separate_process blastdoor_style none not_determinable not_recorded unknown "
  DOM["dom.memory_safety_class"]="memory_safe_languages mixed legacy_unsafe not_determinable not_recorded unknown "
  DOM["dom.entitlement_needed"]="none required unknown not_recorded not_applicable "
  DOM["dom.domain_source"]="platform_doc advisory crash_report mdm_status_item vendor_claim screenshot assumed not_recorded unknown "
  DOM["trg.trigger_mode"]="user_open user_preview background_auto render_pipeline message_auto not_determinable not_recorded unknown "
  DOM["trg.remote_initiated"]="device_side network_delivered not_applicable not_recorded unknown "
  DOM["obs.plane"]="crash_report diagnostic_log settings_ui mdm_status_item advisory developer_doc app_self_report vendor_claim not_determinable none not_recorded unknown "
  DOM["obs.field_read"]="parser_name host_process domain_class trigger_mode prompt_state reset_proof none not_recorded unknown "
  DOM["notice.prompt_shown"]="yes no not_applicable not_recorded unknown "
  DOM["notice.quarantine_flag"]="set absent not_supported not_applicable not_recorded unknown "
  DOM["notice.origin_disclosed"]="disclosed absent not_applicable not_recorded unknown "
  DOM["notice.warning_text_source"]="platform_doc advisory support_note vendor_claim screenshot assumed not_applicable not_recorded unknown "
  DOM["undo.reset_method"]="delete_file clear_cache reimport reinstall restart mdm_reapplied expiry_only not_determinable none not_recorded unknown "
  DOM["undo.reproof_basis"]="reopened re_rendered user_visible_prompt advisory_component assumed not_applicable not_recorded unknown "
  DOM["mgmt.mdm_configurable"]="channel_only content_only yes no not_recorded unknown "
  DOM["mgmt.payload"]="com.apple.applicationaccess com.apple.webcontentfilter com.apple.configuration.device.management none not_applicable not_recorded unknown "
  DOM["mgmt.key_in_inventory"]="yes no not_checked not_recorded unknown "
  DOM["mgmt.key_source"]="restrictions_inventory official_doc vendor_claim none not_recorded unknown "
  DOM["adv.component_is_parser_layer"]="yes no not_checked not_recorded unknown "
  DOM["adv.kev_listed"]="yes no not_checked not_applicable not_recorded unknown "
  DOM["adv.object_word_in_impact"]="image font video audio archive web_content file model document none not_recorded unknown "
  DOM["adv.patch_channel"]="whole_version rapid_security_response background_improvement not_release not_determinable not_recorded unknown "
  DOM["doc.conclusion"]="confirmed absent_in_ledger not_determinable assumed not_recorded unknown "
  BOOL["rights.exported_type_declared"]=1; BOOL["rights.owns_document"]=1; BOOL["rights.requires_user_consent"]=1
  BOOL["asm.runs_in_extension"]=1; BOOL["asm.third_party_codec"]=1
  BOOL["dom.aslr_used"]=1; BOOL["dom.jit_allowed"]=1
  BOOL["trg.user_action_required"]=1; BOOL["trg.auto_processed"]=1
  BOOL["trg.preview_only"]=1; BOOL["trg.renders_thumbnail"]=1
  BOOL["obs.list_visible"]=1
  BOOL["undo.cache_cleared"]=1; BOOL["undo.residue_claimed"]=1; BOOL["undo.reproof_done"]=1
  BOOL["mgmt.supervised"]=1
  DT["obs.read_at"]=1; DT["undo.verified_at"]=1
  NS["id"]=1; NS["typ"]=1; NS["rights"]=1; NS["asm"]=1; NS["dom"]=1; NS["trg"]=1
  NS["obs"]=1; NS["notice"]=1; NS["undo"]=1; NS["mgmt"]=1; NS["adv"]=1; NS["doc"]=1; NS["sec"]=1
  split("S01 S02 S03 S04 S05 S06 S07 S08 S09 K01 K02 K03", hb, " ")
  for (i in hb) HB[hb[i]] = 1
  split("id.bundle_id id.team_id typ.declared_uti typ.declared_mime typ.filename_ext typ.sniffed_type asm.host_process adv.component obs.crash_report_ref mgmt.restriction_key doc.source doc.line_ref adv.cve adv.fix_version notice.notice_note", extra, " ")
  for (i in extra) KNOWN[extra[i]] = 1
  for (f in DOM) KNOWN[f] = 1
  for (f in BOOL) KNOWN[f] = 1
  for (f in DT) KNOWN[f] = 1
  split("id.obj_kind id.source_face id.provenance typ.type_source asm.parser_framework asm.parser_layer dom.domain_class trg.trigger_mode obs.plane notice.prompt_shown undo.reset_method doc.source", REQ, " ")
  REQNS["id.obj_kind"]="id"; REQNS["id.source_face"]="id"; REQNS["id.provenance"]="id"
  VD["J1"]="十二格齐备且无阻断信号：这条解析链可进入对外归属表述"
  VD["J2"]="仅 1—2 条非结构性信号：可作内部台账使用，暂不对外表述"
  VD["J3"]="3 条以上非结构性信号：归属结论尚未收敛"
  VD["J4"]="存在结构性或拒收信号（S／K 族或必备格缺失）：本行不可用"
  DOC["A01"]="见 A/uniformtypeidentifiers_system_declared_uniform_type_identifiers.txt 第 5 行（Uniform type identifiers declare common types for resources an app loads, saves, or opens from other apps）"
  DOC["A02"]="见 A/uikit_uidocument.txt 第 3、35 行（UIDocument 是管理 App 数据的基础类；它从文件 URL 里按扩展名所关联的类型标识推出文件类型）"
  DOC["A03"]="见 A/uniformtypeidentifiers_defining_file_and_data_types_for_your_app.txt 第 16—17 行（标识要用反向 DNS 形态且只含字母数字，包标识按同一形状校验）"
  DOC["A06"]="见本文第 6.3 节失败点（团队标识在公开口径里是 10 位字母数字串；登记成别的形状说明这一格不是从公开材料抄来的）"
  DOC["A04"]="见 A/webkit_wkwebview.txt 第 21—22 行（在网页视图出现在屏幕上之前，必须显式地用 URLRequest 结构、本地文件或 HTML 串把内容交给它加载）"
  DOC["A05"]="见 A/imageio.txt 第 6 行（Image I/O 框架让 App 读写多数图像格式，编解码由框架自身完成）"
  DOC["B01"]="见 A/uniformtypeidentifiers_system_declared_uniform_type_identifiers.txt 第 5 行（类型标识声明 App 载入、保存或从别的 App 打开的资源）与第 20—23 行（扩展名与 MIME 是挂在类型标识上的两类标签）"
  DOC["B02"]="见 A/uniformtypeidentifiers_system_declared_uniform_type_identifiers.txt 第 20—23 行（扩展名标签与 MIME 标签各自只映射到类型标识，本身不是类型结论）"
  DOC["B08"]="见 A/uniformtypeidentifiers_defining_file_and_data_types_for_your_app.txt 第 16—20 行（标识需要唯一、以反向 DNS 形态起始，且只含字母数字、破折号与点）"
  DOC["B03"]="见 A/imageio.txt 第 3 行（读取并写出多数图像文件格式并访问其元数据——类型来自字节本身而不是文件名）"
  DOC["B04"]="见 C/readings-18.txt 读数 2（对象词 web content 175 行、file 164 行、image 105 行）"
  DOC["B05"]="见 A/uniformtypeidentifiers_defining_file_and_data_types_for_your_app.txt 第 10—14 行（声明以 App 自己的 Info.plist 为准）"
  DOC["B06"]="见 A/quicklook_qlpreviewcontroller.txt 第 10—11、22 行（预览控制器能显示哪些常见类型由这份清单决定，而清单本身可能随系统版本变化）"
  DOC["B07"]="见 C/readings-18.txt 读数 5（46 行的 impact 写明恶意构造对象，但组件名不属于任何解析层）"
  DOC["C01"]="见 B/apple-platform-security-guide.txt 第 2391 行（iOS、iPadOS 与 visionOS 用沙箱、声明式 entitlement 与 ASLR 保证运行期安全）"
  DOC["C02"]="见 C/readings-18.txt 读数 4（含 crafted 的 467 行按组件集中在 WebKit 139、ImageIO 79、Model I/O 37）"
  DOC["C03"]="见 B/apple-platform-security-guide.txt 第 2388 行（App 侧防护由 App Review 与平台保护共同构成）"
  DOC["C04"]="见 B/apple-platform-security-guide.txt 第 1442 行（BlastDoor 用沙箱限制与对输出的内存安全校验阻断 0-click）"
  DOC["C05"]="见 B/apple-platform-security-guide.txt 第 2557 行（自定义键盘扩展默认在极受限沙箱内运行）"
  DOC["C06"]="见 C/readings-18.txt 读数 8（218 个限制键里没有任何键指名解析器或解码器）"
  DOC["C07"]="见 A/coregraphics.txt 第 6 行（image data management、image creation、image masking 与 PDF 的 display、parsing 由框架本身承担，用了第三方编解码就必须登记框架字段）"
  DOC["D01"]="见 B/apple-platform-security-guide.txt 第 4740 行（XNU 强制代码签名、沙箱、entitlement 校验与 ASLR）"
  DOC["D02"]="见 B/apple-platform-security-guide.txt 第 1442 行（0-click 指不需要用户交互的攻击）"
  DOC["D03"]="见 B/apple-platform-security-guide.txt 第 2404 行（ASLR 降低内存损坏缺陷被利用的可能）"
  DOC["D04"]="见 B/apple-platform-security-guide.txt 第 1333 行（MIE 是自 A19 与 M5 起的内存安全强制）"
  DOC["D05"]="见 B/apple-platform-security-guide.txt 第 1322 行（指针签名校验失败即 abort）"
  DOC["D06"]="见 B/apple-platform-security-guide.txt 第 2446 行（沙箱限制 App 访问其他 App 的数据）"
  DOC["E01"]="见 C/readings-18.txt 读数 6（467 行 impact 中没有任何免交互措辞：触发面不能从公告文本读出）"
  DOC["E02"]="见 B/apple-platform-security-guide.txt 第 1442 行（自动处理链路上的告知与隔离是设计目标）"
  DOC["E03"]="见 A/quicklook.txt 第 6—13 行（Quick Look 用于在 App 内呈现文档内容）"
  DOC["E04"]="见 A/uikit_uidocument.txt 第 39、42—43 行（新建或打开文档是一条显式生命周期动作，打开由用户选定的文档触发）"
  DOC["E05"]="见 C/readings-18.txt 读数 3（unexpected app termination 133 行、memory corruption 77 行、arbitrary code execution 58 行）"
  DOC["O01"]="见 B/apple-platform-security-guide.txt 第 2391 行（运行期安全三件套：沙箱、entitlement、ASLR）"
  DOC["O02"]="见 C/readings-18.txt 读数 11（同一 CVE 最多出现在 8 行，47 个 CVE 只出现 1 行）"
  DOC["O03"]="见 C/readings-18.txt 读数 10（WebKit 165 行中 157 行含 crafted、161 行含 web content）"
  DOC["O04"]="见 B/apple-platform-security-guide.txt 第 1904—1908 行（数据保护按类控制可读性，与解析面正交）"
  DOC["N01"]="见 B/apple-platform-security-guide.txt 第 2557 行（Open Access 需要取得用户同意）"
  DOC["N02"]="见 A/uikit_uiactivityviewcontroller.txt 第 10—11 行（面板提供的服务由系统给出，App 只负责配置、呈现与被作用的数据对象）"
  DOC["N03"]="见 C/readings-18.txt 读数 8（safari 族键约束的是网页内容获取，不是解析器）"
  DOC["N04"]="见本文第 3.4 节失败点 6（截屏与厂商说法不能充当机制依据）"
  DOC["N05"]="见 A/webkit.txt 第 5—8 行（WebKit 呈现网页内容并显示多种 MIME 类型与复合帧元素：同一份字节可由不同的 MIME 声明进入）"
  DOC["V01"]="见 B/apple-platform-security-guide.txt 第 1448 行（锁定模式以功能换取防护，属于复位面）"
  DOC["V02"]="见 A/imageio.txt 第 40、56 行（同一份图像数据可从 URL、数据对象或数据消费者三种来源读回；复位只针对承载文件与缓存，不针对读回通道）"
  DOC["V03"]="见 A/uikit_uidocument.txt 第 38—45、49 行（文档生命周期逐段可核对：创建、打开、编辑、关闭与保存各是一次可登记的状态转换）"
  DOC["V04"]="见 C/readings-18.txt 读数 7（KEV 95 条中 36 条短描述指向网页或浏览器、2 条指向图像）"
  DOC["G01"]="见 B/mdm-restriction-keys.txt（218 个键名，命中内容接收与网页词形的只有 6 个）"
  DOC["G02"]="见 C/readings-18.txt 读数 8（allowSafari、safariAllowJavaScript、requireManagedPasteboard 等）"
  DOC["G03"]="见 B/apple-platform-security-guide.txt 第 1448 行（锁定模式关闭部分自动处理，管理面不重复该开关）"
  DOC["G04"]="见 C/readings-18.txt 读数 8（19 个键可约束内容获取与联网，但没有键能约束解析器）"
  DOC["G05"]="见 B/mdm-restriction-keys.txt 第 5—8 行（逐行都是 allow 前缀的小驼峰单标识，写成路径或带空格即不是这一份清单里的键）"
  DOC["R01"]="见 C/advisory-18.tsv 表头（file、platform、component、cve、impact、avail 六列）"
  DOC["R02"]="见 C/readings-18.txt 读数 1（1266 行、330 个去重 CVE、129 个组件名、12 个平台版本行）"
  DOC["R03"]="见 C/readings-18.txt 读数 5（组件名与对象词分列且互不校验）"
  DOC["R04"]="见 C/kev-apple.tsv 表头（cveID、dateAdded、dueDate、shortDescription）"
  DOC["R05"]="见 C/readings-18.txt 读数 10（同族组件下 impact 的对象词几乎恒为一类）"
  DOC["R06"]="见 B/apple-platform-security-guide.txt 第 180 行（除特别注明外，本指南覆盖 iOS 26.5、iPadOS 26.5、macOS 26.5 等版本——版本号是「平台名 + 主.次」形态）"
  DOC["R07"]="见 C/kev-apple.tsv 第 2 行（Apple iOS/iPadOS/macOS 的 CVE-2026-86950 已同时给出 dateAdded 与 dueDate，说明存在已发布版本）"
  DOC["X01"]="见本文第 3.4 节失败点 8（口径之间不能直接换算，结论必须回到文件与行号）"
  DOC["X02"]="见 usage 文本（行号引用只写 `1234` 或 `6-9` 这一种形态，带「第／行」前缀的写法在两份台账之间不可换算）"
  DOC["S01"]="见 usage 文本的行格式（一行只登记一条对象的字段，列数固定为三）"
  DOC["S02"]="见 usage 文本的行格式（对象标识是行的第一列，缺失时无法判断这行属于哪条解析链）"
  DOC["S03"]="见 usage 文本（同一对象的同一字段只能有一个取值，重复登记会让后值静默覆盖前值）"
  DOC["S04"]="见 usage 文本的十二个命名空间清单（命名空间是字段归属判断层的唯一依据）"
  DOC["S05"]="见 usage 文本的字段清单（清单外的字段名不会被任何判定读取）"
  DOC["S06"]="见 usage 文本（值里不能含逗号；留空等同没有登记这一格）"
  DOC["S07"]="见 usage 文本的枚举字段与布尔位（枚举值必须由登记方选定，不接受自由文本）"
  DOC["S08"]="见 C/kev-apple.tsv 表头（dateAdded、dueDate 两列使用 YYYY-MM-DD 形态，本脚本的日期格按同一形态校验）"
  DOC["S09"]="见 usage 文本的必备格清单"
  DOC["K01"]="见本脚本头部注释的拒收声明"
  DOC["K02"]="见本脚本头部注释：文件正文、设备路径、密钥串与超长载荷一律拒收"
  DOC["K03"]="见本文第 12 章（崩溃引用只登记报告标识，不粘贴堆栈正文）"
}
{
  if ($0 ~ /^[ ]*#/ || $0 ~ /^[ ]*$/) next
  sub(/\r$/, "")
  if (NF < 3) { emit("S01", $1, "列数不足 3：" $0); next }
  id = $1; f = $2; v = $3
  for (i = 4; i <= NF; i++) v = v "," $i
  if (id == "") { emit("S02", "", "对象标识为空：" f); next }
  if (!(id in SEEN)) { SEEN[id] = 1; ORD[++noid] = id }
  k = id SUBSEP f
  if (k in valof) emit("S03", id, "同一字段重复登记：" f)
  valof[k] = v
  ns = f; sub(/\..*$/, "", ns)
  if (!(ns in NS)) { emit("S04", id, "未登记的命名空间：" f); next }
  if (ns == "sec") { emit("K01", id, "sec.* 拒收空间出现字段：" f); next }
  if (!(f in DOM) && !(f in BOOL) && !(f in DT) && !(f in KNOWN)) { emit("S05", id, "未登记字段名：" f); next }
  if (v == "") { emit("S06", id, "取值为空：" f); next }
  if (f in DOM) { if (!hasToken(DOM[f], v)) emit("S07", id, "枚举越界：" f "=" v) }
  else if (f in BOOL) { if (!isbool(v)) emit("S07", id, "布尔位取值非法：" f "=" v) }
  else if (f in DT)  { if (!isISOdt(v)) emit("S08", id, "日期形态非法：" f "=" v) }
  if (devPath(v) || longBlob(v) || b64ish(v) || secretish(v)) emit("K02", id, "取值形似设备路径／长载荷／密钥串，拒收：" substr(v,1,20) "...")
  if (f == "typ.declared_uti" && !isUTI(v) && !isNA(v))   emit("B08", id, "声明类型标识形态非法：" v)
  if (f == "typ.declared_mime" && !isMIME(v) && !isNA(v)) emit("B08", id, "声明 MIME 形态非法：" v)
  if (f == "typ.filename_ext" && !isExt(v) && !isNA(v))   emit("B08", id, "扩展名形态非法：" v)
  if (f == "id.bundle_id" && !isBundle(v) && !isNA(v))    emit("A03", id, "包标识形态非法：" v)
  if (f == "id.team_id" && !isTeamID(v) && !isNA(v))      emit("A06", id, "团队标识形态非法：" v)
  if (f == "adv.cve" && !isCVE(v) && v != "none" && !isNA(v)) emit("R02", id, "CVE 形态非法：" v)
  if (f == "adv.fix_version" && !isVer(v) && v != "none" && !isNA(v)) emit("R06", id, "修复版本形态非法：" v)
  if (f == "mgmt.restriction_key" && v !~ /^[a-z][a-zA-Z0-9]+$/ && v != "none" && !isNA(v)) emit("G05", id, "限制键形态非法：" v)
  if (f == "doc.line_ref" && !isLineRef(v) && !isNA(v))   emit("X02", id, "行号引用形态非法：" v)
  if (f == "obs.crash_report_ref" && v !~ /^[A-Za-z0-9-]{6,40}$/ && v != "absent" && v != "not_applicable" && !isNA(v)) emit("K03", id, "崩溃引用不是报告标识形态")
  next
}
END {
  for (oi = 1; oi <= noid; oi++) {
    id = ORD[oi]
    for (ri = 1; ri <= 12; ri++) {
      if (!REQ[ri]) break
      if (isNA(GV(id, REQ[ri]))) { emit("S09", id, "必备格缺失：" REQ[ri]); miss[id] = 1 }
    }
    prov = GV(id, "id.provenance"); sig = GV(id, "id.signature")
    concl = GV(id, "doc.conclusion"); face = GV(id, "id.source_face")
    tsrc = GV(id, "typ.type_source"); tconf = GV(id, "typ.type_conflict")
    sniff = GV(id, "typ.sniffed_type"); decl = GV(id, "typ.declared_uti")
    extv = GV(id, "typ.filename_ext"); mime = GV(id, "typ.declared_mime")
    resv = GV(id, "typ.resolver_choice"); kind = GV(id, "id.obj_kind")
    fw = GV(id, "asm.parser_framework"); pk = GV(id, "asm.process_kind")
    hp = GV(id, "asm.host_process"); xs = GV(id, "asm.xpc_service")
    extn = GV(id, "asm.runs_in_extension"); tpc = GV(id, "asm.third_party_codec")
    sand = GV(id, "rights.sandbox_profile")
    layer = GV(id, "asm.parser_layer")
    dcls = GV(id, "dom.domain_class"); iso = GV(id, "dom.isolation_mechanism")
    mem = GV(id, "dom.memory_safety_class"); dsrc = GV(id, "dom.domain_source")
    aslr = GV(id, "dom.aslr_used"); jit = GV(id, "dom.jit_allowed"); ent = GV(id, "dom.entitlement_needed")
    tm = GV(id, "trg.trigger_mode"); auto = GV(id, "trg.auto_processed")
    uar = GV(id, "trg.user_action_required"); prev = GV(id, "trg.preview_only")
    thr = GV(id, "trg.renders_thumbnail"); rmt = GV(id, "trg.remote_initiated")
    plane = GV(id, "obs.plane"); fld = GV(id, "obs.field_read"); rat = GV(id, "obs.read_at")
    ps = GV(id, "notice.prompt_shown"); qf = GV(id, "notice.quarantine_flag")
    od = GV(id, "notice.origin_disclosed"); wts = GV(id, "notice.warning_text_source")
    note = GV(id, "notice.notice_note")
    rmth = GV(id, "undo.reset_method"); cc = GV(id, "undo.cache_cleared")
    rc = GV(id, "undo.residue_claimed"); rp = GV(id, "undo.reproof_done")
    rb = GV(id, "undo.reproof_basis"); vat = GV(id, "undo.verified_at")
    mc = GV(id, "mgmt.mdm_configurable"); rk = GV(id, "mgmt.restriction_key")
    kii = GV(id, "mgmt.key_in_inventory"); pay = GV(id, "mgmt.payload"); ksrc = GV(id, "mgmt.key_source")
    cmpn = GV(id, "adv.component"); cpl = GV(id, "adv.component_is_parser_layer")
    kev = GV(id, "adv.kev_listed"); owi = GV(id, "adv.object_word_in_impact")
    pch = GV(id, "adv.patch_channel"); srcf = GV(id, "doc.source")

    if (prov == "not_determinable" && concl == "confirmed") emit("A01", id, "来源不可判定却给确认结论")
    if (prov == "remote_untrusted" && (sig == "signed_store" || sig == "platform_binary")) emit("A02", id, "来源标记与签名形态矛盾：" prov " vs " sig)
    if (face == "url_scheme_open" && istrue(auto)) emit("A04", id, "URL 打开面被登记为自动处理")
    if (layer == "web_engine" && kind == "image") emit("A05", id, "解析层为网页引擎但对象是图像")
    if (tpc == "true" && (fw == "none" || fw == "not_applicable")) emit("C07", id, "使用第三方编解码却未登记解析框架")
    if (isNA(decl) && isNA(mime) && isNA(extv)) emit("B01", id, "类型三票（UTI／MIME／扩展名）全无")
    if (!isNA(extv) && isNA(decl) && isNA(mime) && tsrc == "extension_only") emit("B02", id, "只用扩展名当类型结论")
    if (!isNA(sniff) && !isNA(decl) && sniff != decl && tconf == "none") emit("B03", id, "嗅得类型与声明类型不同却记为无冲突：" sniff " vs " decl)
    if (tconf == "unresolved" && concl == "confirmed") emit("B04", id, "类型冲突未解却给确认结论")
    if (tsrc == "assumed" || tsrc == "vendor_claim") emit("B05", id, "类型判定依据为假定或厂商说法：" tsrc)
    if (isNA(resv) && layer ~ /^(image_codec|font_parser|media_demux|video_decoder|web_engine|model_loader|archive_unpack)$/) emit("B06", id, "解析对象已知但解析器选择未登记")
    if (resv == "not_determinable" && concl == "confirmed") emit("B07", id, "解析器选择不可判定却给确认结论")
    if (isNA(pk)) emit("C01", id, "进程种类未登记")
    if (isNA(hp) && pk != "kernel_task" && pk != "not_recorded") emit("C03", id, "宿主进程未登记")
    if (pk == "xpc_helper" && xs == "not_applicable") emit("C04", id, "声明为 XPC 助手却把端点记为不适用")
    if (extn == "true" && isNA(sand)) emit("C05", id, "在扩展进程内解析却无沙箱画像")
    if (tpc == "true" && dcls == "privileged_extension") emit("C06", id, "第三方编解码在特权域内执行")
    if (layer == "kernel_filesystem" && dcls != "kernel" && dcls != "not_recorded" && dcls != "not_determinable") emit("C02", id, "内核文件系统层却未记内核域：" dcls)
    if (iso == "none" && istrue(auto)) emit("D02", id, "自动处理且无隔离机制")
    if (mem == "legacy_unsafe" && istrue(aslr) == 0 && aslr != "unknown" && aslr != "not_recorded") emit("D03", id, "非内存安全层却未启用 ASLR")
    if (istrue(jit) && dcls !~ /^(renderer_detached|app_sandboxed|not_recorded)$/) emit("D04", id, "开启 JIT 的执行域不是被分离的渲染域或 App 域")
    if (ent == "required" && (sand == "kernel_none" || sand == "not_determinable")) emit("D05", id, "需要 entitlement 却无沙箱画像")
    if (dsrc == "vendor_claim" || dsrc == "screenshot" || dsrc == "assumed") emit("D06", id, "执行域结论只来自厂商说法、截屏或假定：" dsrc)
    if (isNA(dsrc) && !isNA(dcls)) emit("D01", id, "登记了执行域却没写它的来源平面")
    if (istrue(uar) && istrue(auto)) emit("E01", id, "同时登记需用户动作与自动处理")
    if (istrue(auto) && isNA(ps)) emit("E02", id, "自动处理却没有告知位")
    if (istrue(prev) && tm == "user_preview" && isNA(thr)) emit("E03", id, "预览触发却未登记缩略图渲染位")
    if (rmt == "network_delivered" && istrue(auto) && isNA(pch)) emit("E04", id, "网络投递且自动处理却未登记补丁通道")
    if (tm == "message_auto" && face == "files_app") emit("E05", id, "触发面与进入面矛盾：" tm " vs " face)
    if (plane == "crash_report" && fld == "prompt_state") emit("O01", id, "崩溃报告面读不出告知状态")
    if (plane != "none" && plane != "not_recorded" && plane != "not_determinable" && isNA(rat)) emit("O02", id, "有观测平面却未登记读数时刻")
    if (plane == "vendor_claim" && concl == "confirmed") emit("O03", id, "只靠厂商自述平面给出确认结论")
    if (plane == "app_self_report" && dsrc == "platform_doc" && concl == "confirmed") emit("O04", id, "平台文档与 App 自述并用却未说明冲突处理")
    if (ps == "not_recorded" && istrue(auto)) emit("N01", id, "自动处理的告知位未登记")
    if (qf == "not_supported" && od == "disclosed") emit("N02", id, "称不支持隔离位却称来源已披露")
    if (wts == "screenshot" || wts == "assumed") emit("N03", id, "告知文本依据是截屏或假定：" wts)
    if (istrue(auto) && ps == "no" && note == "") emit("N04", id, "自动处理且无提示，却没有任何说明句")
    if (ps == "yes" && wts == "not_applicable") emit("N05", id, "登记有提示却说告知文本不适用")
    if (istrue(rp) && rmth == "clear_cache" && !istrue(cc)) emit("V02", id, "声称已再证明但缓存未清")
    if (istrue(rc) && isNA(vat)) emit("V03", id, "声称有残留但未登记核对时刻")
    if (istrue(rp) && rb == "assumed") emit("V04", id, "再证明依据为假定")
    if (rmth == "not_determinable" && istrue(rp)) emit("V01", id, "复位方法不可判定却声称已再证明")
    if (mc == "content_only" && isNA(rk)) emit("G01", id, "称管理面可配内容却没有键名")
    if (kii == "no" && concl == "confirmed") emit("G02", id, "键不在 218 键清单内却用来给确认结论")
    if (!isNA(pay) && pay != "not_applicable" && isNA(ksrc)) emit("G03", id, "登记了 payload 却没写键来源")
    if (mc == "yes" && isNA(rk)) emit("G04", id, "管理面结论为可配但未指名任何键")
    if (!isNA(owi) && owi != "none" && isNA(cmpn)) emit("R01", id, "登记了 impact 对象词却没有组件名")
    if (cpl == "no" && concl == "confirmed") emit("R03", id, "组件名不属于解析层却用它给确认结论")
    if (kev == "yes" && (pch == "not_release")) emit("R07", id, "在 KEV 名单内却把补丁通道记为非发布")
    if (cpl == "not_checked" && owi == "image" && cmpn !~ /Image|CoreGraphics|ColorSync|Photos/) emit("R05", id, "对象词为 image 但组件名与之无关且未核对")
    if (kev == "not_checked" && !isNA(cmpn) && pch == "not_recorded") emit("R04", id, "有组件名但既未核对 KEV 也未登记补丁通道")
    if (concl == "confirmed" && (isNA(srcf) || isNA(GV(id, "doc.line_ref")))) emit("X01", id, "确认结论缺来源文件或行号")

    if (miss[id] || (id in hard)) verdict = "J4"
    else if (percnt[id] + 0 == 0) verdict = "J1"
    else if (percnt[id] + 0 <= 2) verdict = "J2"
    else verdict = "J3"
    if (!QUIET) print verdict "\t" id "\t" VD[verdict]
    JDIST[verdict]++
  }
  tot = 0; codes = 0
  for (c in cnt) { tot += cnt[c]; codes++ }
  blocked = 0
  for (c in cnt) if (c in HB) blocked += cnt[c]
  printf "\n解析链对象数=%d 信号行数=%d 判定行数=%d\n", noid, nline, noid
  printf "不同信号码=%d 阻断信号条数=%d\n", codes, blocked
  printf "判定分布 J1=%d J2=%d J3=%d J4=%d\n", JDIST["J1"]+0, JDIST["J2"]+0, JDIST["J3"]+0, JDIST["J4"]+0
  for (i = 1; i <= nline; i++) print lines[i] > "/dev/stderr"
  m = 0
  for (c in cnt) KEYS[++m] = c
  for (a = 1; a <= m; a++) for (b = a + 1; b <= m; b++) if (KEYS[b] < KEYS[a]) { t = KEYS[a]; KEYS[a] = KEYS[b]; KEYS[b] = t }
  for (a = 1; a <= m; a++) printf "%s\t%d\n", KEYS[a], cnt[KEYS[a]] > "/dev/stderr"
  exit (blocked > 0 ? 1 : 0)
}
' "$@"
```

---

## 22. 只读核验脚本二：解析链三件差集与公告子词表比对器

脚本一逐条查登记内部，这一支查**三份登记之间**：同一条内容在声明件、通道件、观测件里各被说过一次，说的还是不是同一件事，说的东西在公开词表里存不存在。

### 22.1 它查什么

`tools/parsing-chain-tripartite-diff.sh`（572 行）专查逐条审查查不出的四类问题（第 3—9 行的头部注释逐条写出）：

1. **三件不成对**——「声明了这一项，通道件与观测件两格却一条也没有」；
2. **覆盖空洞**——「某类内容明确需要的核对项，台账里一条也没有」；
3. **平面越界**——「读数挂在某个平面上，但那个平面按公开口径根本不承载这一格」；
4. **归属悬空**——「台账引用的类型标识、框架符号、公告组件、CVE 或限制键，公开词表里不存在」。

这四类问题与第 18 章的五侧一一对应：三件不成对跨声明侧与通道侧，覆盖空洞发生在通道侧与呈现侧，平面越界是管理侧与公告侧最容易越的一界，归属悬空则整条都在公告侧与管理侧的词表上。

### 22.2 三份输入与 20 项核对项

三份输入**顺序固定、全部只读**（第 96 行要求恰好三份，少给多给都是退出码 2；第 97 行逐份检查可读性，任一份不可读同样是 2）：

1. **三件清单**，每行 10 列：`<对象标识>,<对象类>,<核对项>,<三件状态>,<读数平面>,<词表归属>,<引用>,<对外表述>,<内容来源>,<解析时点>`；
2. **三件能力表**，每行 3 列：`<对象类>,<核对项>,<可得性>`，可得性取 `required`／`optional`／`not_applicable`／`undocumented`；
3. **公开词表**，制表符三列：`<词表类别>\t<词表值>\t<来源标识>`，九个实体类别（`uti_identifier`／`api_symbol`／`plist_key`／`restriction_key`／`advisory_component`／`advisory_component_crafted`／`advisory_cve`／`mime_tag`／`extension_tag`）加 `doc_ref`／`mixed` 两个结构类别与两个哨兵。

11 个对象类（9 个真实 + `not_recorded`／`unknown`，第 135 行）、**20 项核对项**按三件切分（第 136—138 行三行 `mkit`）：声明件 7 项（`declared_uti`／`declared_mime`／`filename_ext`／`conforms_chain`／`decl_ownership`／`tag_spec`／`pkg_layout`）、通道件 7 项（`uti_lookup`／`ext_lookup`／`mime_lookup`／`decode_entry`／`preview_entry`／`open_entry`／`resolved_uti`）、观测件 6 项（`advisory_component`／`advisory_cve`／`mgmt_restriction`／`notice_surface`／`crash_ref`／`render_result`）。三项是数组型（`conforms_chain`／`filename_ext`／`tag_spec`，第 155 行 `MULTI`），同一对象可多行登记。23 个读数平面（第 156 行：20 个实体面 + `none`／`not_recorded`／`unknown`）、13 类词表归属（第 157 行：9 个实体类别 + `doc_ref`／`mixed` + 两个哨兵）、4 个对外表述位、8 个内容来源、7 个解析时点、4 种可得性（第 158—161 行）与 9 个公开词表类别（第 162 行 `VK`）都在 `BEGIN` 段（第 133—211 行）逐格写死，并在 usage（第 23—88 行）里全文枚举。23 个「平面×件」配对逐条播种在第 179—191 行，15 个「词表归属×件」配对在第 197—203 行——这两段就是第 18 章五侧划分的代码出处。

夹具规模：能力表 `FX/capability-18.csv` 182 行 = 2 行注释 + **180 数据行**；公开词表 `FX/vocab-18.tsv` 73 行 = 1 行注释 + 1 行表头 + **71 条数据行**，合格运行按归一化值去重后 **65 条**（6 次折叠）；三件清单 `FX/tri-18-good.txt` 49 行 = 2 行注释 + 47 条数据行。畸形对照件 `FX/capability-18-bad.csv` 13 行、`FX/vocab-18-bad.tsv` 6 行。

两处「空集」是这支脚本的设计核心而不是缺陷：`DEOK["font_content"] = ""` 与 `DEOK["archive_content"] = ""`（第 175—176 行，其余七类在第 168—174 行各有承载面清单）。第 12.1 节说过，字体与归档两类在公告侧真实存在（`font` 34 行、`archive` 6 行，`C/readings-18.txt:14、17`），而组 A 没有任何一份字体或归档解析文档，所以这两类的解码入口平面**按公开口径就是空**——登记了任何平面都会落 `P05`（第 476—477 行把 `DEOK` 空集打印成「（无）」），而 `P05` 是非阻断码。

### 22.3 信号族与非对称的阻断设计

| 族 | 码数 | 覆盖 | 是否阻断 |
| --- | --- | --- | --- |
| S 清单自身形态 | 10 | 列数（`S01`）、空标识或含空白（`S02`）、对象类越界（`S03`）、核对项越界（`S04`）、三件状态非法（`S05`）、读数平面非法（`S06`）、词表归属／对外表述／内容来源／解析时点四格枚举越界（`S07`）、重复登记（`S08`）、同一核对项两种登记口径（`S09`）、前缀与对象类不符（`S10`） | 全部阻断（Q2） |
| C 能力表自身形态 | 5 | 未知对象类、未知核对项、可得性非法、列数不符、空表 | 全部阻断（Q2） |
| K 内容越界与保留前缀 | 5 | 引用格形似密钥／凭据／设备绝对路径／整段载荷正文（`K01`）、引用格登记命令行入口名（`K02`，第 436—437 行的十个工具名是**拒绝**模式不是执行点）、把 `public.`／`dyn.`／`com.apple.` 三个保留前缀登记为自己的声明（`K03`—`K05`） | 全部阻断（Q2） |
| M 公开词形 | 6 | 标识形态（`M01`）、扩展名形态（`M02`）、MIME 缺斜杠（`M03`）、崩溃引用形态（`M04`）、CVE 形态（`M05`）、引用值是公开词形的近义词或不在该格词形表内（`M06`） | 全部阻断（Q2） |
| D 覆盖空洞 | 5 | required 这一格没有读数（`D02`）、required 被记成不适用（`D03`）、整类缺对象（`D04`）、某核对项零登记（`D05`）、记了不存在（`D01`） | 全部非阻断（Q3）：说的是「台账缺登记」，不是「登记互相矛盾」 |
| P 平面越界 | 7 | 读数平面为「无平面」却记已读数（`P01`）、管理面承载通道件（`P02`）、公告面承载声明件（`P03`）、渲染结果记在非预览面（`P04`）、解码入口不在该类承载面清单上（`P05`，两条 emit 路径）、观测件记在类型声明或标签反查面（`P06`）、崩溃引用记在非崩溃报告面（`P07`） | 全部非阻断（Q3） |
| T 三件差集与矛盾 | 8 | 声明了却没通道／没观测（`T01`／`T02`）、词表归属与所属件不配对（`T03`）、一致性链指向非 `public.` 父类型（`T04`）、同标识既导出又导入（`T05`）、反查值与声明矛盾（`T06`）、包结构却无 `com.apple.package`（`T07`）、对外表述为是但该类必需声明格缺位（`T08`） | `T01`／`T02` 非阻断，`T03`—`T08` 阻断 |
| X 公开词表比对 | 8 | 组件悬空（`X01`：归一化后不在全量组件词表，或只在 crafted 子词表而不在全量词表）、组件在但无 crafted 行却对外表述解析类归属（`X02`）、CVE 悬空（`X03`）、限制键悬空（`X04`）、类型标识悬空（`X05`）、符号或声明键悬空（`X06`）、标签悬空（`X07`）、**公开词表自身形态非法（`X08`，五条 emit 路径，含「整表无可用行」）** | 全部阻断（Q2） |
| V 引用形态与口径闭合 | 6 | required 全为无标识（`V01`）、引用既非词表值也非文档行号（`V02`）、渲染结果只由自述面给出（`V03`）、已读数却未登记这一格是否会对外（`V04`）、同一核对项在对象之间既有已读数又有明确不存在（`V05`）、管理面读数无键（`V06`） | 仅 `V02`／`V06` 阻断 |
| Q 闭合等级 | 4 | 第 19.2 节四档 | 不计入信号，也不计入阻断（第 105 行） |

阻断集写死在第 204—211 行，共 **42 码**；18 个非阻断码（D 族 5、P 族 7、`T01`／`T02`、`V01`／`V03`／`V04`／`V05`）的设计理由与脚本一同源。真正的非对称发生在 X 族与脚本一 R 族的接缝上：**同一件「公告组件名与对象类对不对」的事，脚本一只降级、脚本二拦停**。脚本一的 `R03`／`R05`（组件名不属于解析层却给确认、对象词与组件无关未核对）都是非阻断码；脚本二则把 crafted 子词表的一致性做成阻断——`X01` 有两条 emit 路径（归一化后不在全量组件词表内，第 496 行；只在全量里不存在却出现在 crafted 子词表里，第 493 行），`X02` 也有两条（子词表非空却在子词表里找不到，第 492 行；在全量词表里但没有 crafted 行、却把解析类归属对外表述为是，第 498 行），四个方向缺一即 Q2。差别不在现象而在**输入**：脚本一读的是单条台账的自由文本，只能提示「这里该再核一次」；脚本二读的是整份公开词表，能判定「这个组件名在词表里到底存不存在」——词表在手时，悬空归属就是错误登记，不是待办事项。`X08` 的阻断理由又是一类：它不说某条归属错了，而说**比对本这件事不可执行**——第 370 行那条 emit 的文案直接写「整表无可用行，类型标识、符号、公告与限制键比对均不可执行」，词表读不出行时后续 `X01`—`X07` 全部无从判断，所以只能拦。这两条与第 19.3 节所说「两档必须并列」互为实证：**同一现象在 J 档降一级，在 Q 档拦停；而 Q 档拦的可能是「还没法判」而不是「判出错了」。**

### 22.4 输出与退出码

stdout 三段：**三件差集矩阵**（每对象一行，给出声明件／通道件／观测件已读数格数与该类 required 总数、命中数与缺项清单，第 553 行那一处 `printf`）、**公开词表读数**（第 555—556 行，一行八个计数）、逐对象的 Q 档。stderr 给逐条信号，分流写在相邻两行：第 559 行把非 Q 行送 stderr，第 560 行把 Q 行送 stdout（且同样受 `-q` 约束）。`-q` 关掉的是第 541—557 行整个 `if (!QUIET)` 段（矩阵与词表读数两段 stdout 都在里面）和第 560 行的逐对象 Q 档；信号、汇总与按码计数照旧。汇总三行在第 564—566 行，给出三件对象数、核对项登记行、能力表行、词表词条、信号行数（`nsig`，第 562 行只数非 Q 行）、不同码数（`nc`，第 563 行同样跳过 Q 码）、阻断条数与 Q 分布，随后才是按码计数（第 568—569 行，`shown` 从第 567 行起累积）。退出码同脚本一的语义（第 570 行 `exit (nblk > 0 ? 1 : 0)`）：有阻断 1、输入不可用 2、否则 0。

公开词表读数那行是本文中心事实的机器版本，合格夹具下逐字为：

```text
去重词条=65 类型标识词条=14 符号词条=22 标签词条=6 CVE 词条=10 组件词条=7 子词表组件=7 限制键词条=5
```

`组件词条=7` 与 `子词表组件=7` 这一对（craft 子词表与非 craft 全量词表的差集在第 340—360 行的词表装载段计算）就是第 16.2 节第 1 组读数在词表侧的形态：夹具只装了 crafted 子集，因此两份相等；换成全量词表时 `子词表组件` 会小于 `组件词条`，差额正是 `C/subset-18.txt:10` 的那 95 个组件。

### 22.5 它不做什么

同脚本一：不联网取公告、不打开任何被登记的对象、不修改输入。头部边界段第 14—18 行逐句写明这几条，其中第 16—17 行那句是这支脚本最重要的自我限制：给出「三件不成对」或「覆盖空洞」**不等于补登记**——补登记需要新的读数来源，本脚本只指出缺哪一格、按公开口径这一格本应由哪个平面给出。第 14 行同时列出被禁的命令入口清单（`file`／`mdls`／`mdimport`／`spctl`／`codesign`／`defaults`／`log`／`sysctl`／`xcrun`／`profiles`），第 23.1 节 P14 那条 grep 给出这两个名字在脚本二里的全部落点：头部声明（第 14 行）与第 436 行的**拒收正则**，P14b 用同一条命令位置规则扫全文为空匹配。唯一写出目标是 `mktemp -d`（第 99 行，前缀 `pct.XXXXXX`，与脚本一的 `pcl.XXXXXX` 分开，两者可并存不冲突），第 100 行 trap 删除，第 18 行明写「本实现不向其写入任何字节」。

### 22.6 合格夹具读数

`FX/tri-18-good.txt`（49 行、4 个对象，逐类一个）配干净能力表与词表，输出四行矩阵全部 `缺:（无）`、Q 分布 `Q1=4`、0 条信号、退出码 0。下面取自 `FX/run-log-tri.txt` 第 526—543 行，是**摘录**：矩阵、词表读数、汇总与退出码逐字照抄，中间第 535—538 行那四条逐对象 Q1 判定（每条末尾带 `DOC["Q1"]` 出处）从略。

```text
$ tools/parsing-chain-tripartite-diff.sh FX/tri-18-good.txt FX/capability-18.csv FX/vocab-18.tsv
---- 三件差集矩阵（声明件 / 通道件 / 观测件 已读数格数与登记格数）----
IMG_01	image_content	声明件=4 通道件=5 观测件=3	required=11 已读数=11 缺:（无）
WEB_01	web_content	声明件=3 通道件=4 观测件=4	required=9 已读数=9 缺:（无）
DOC_01	document_content	声明件=3 通道件=6 观测件=3	required=10 已读数=10 缺:（无）
PKG_01	package_content	声明件=6 通道件=4 观测件=2	required=12 已读数=12 缺:（无）
---- 公开词表读数 ----
去重词条=65 类型标识词条=14 符号词条=22 标签词条=6 CVE 词条=10 组件词条=7 子词表组件=7 限制键词条=5

三件对象数=4 核对项登记行=47 能力表行=180 词表词条=65 信号行数=0
不同信号码=0 阻断信号条数=0
闭合等级 Q1=4 Q2=0 Q3=0 Q4=0
$ exit=0
```

`image_content` 的 required 是 20 项中的 11 项，`web_content` 只要求 9 项、`package_content` 要求 12 项——**这三个数字来自能力表而不是脚本硬编码**，因此换一份能力表就会改变 Q3 与 Q4 的触发面。第 22 次实跑（`bad-capability`，`FX/tri-18-bad.txt` + `FX/capability-18-bad.csv`）就是这条设计的实证：那份 13 行的畸形能力表只被读进 **4 条有效行**（`FX/run-log-tri.txt` 第 755—757 行逐字为 `三件对象数=32 核对项登记行=67 能力表行=4 词表词条=65 信号行数=110` / `不同信号码=35 阻断信号条数=48` / `闭合等级 Q1=0 Q2=8 Q3=5 Q4=18`），32 个对象因此整批失去 required 基准，退出码 1。矩阵里 `PKG_01` 的声明件 6 格最高，对应归档侧 `com.apple.package` 那条一致性链与包结构声明句；`WEB_01` 的观测件 4 格最高，对应 `web content` 在公告里 175 行的读数密度（第 16.2 节第 2 组）。

### 22.7 全量源码

```bash
#!/usr/bin/env bash
# parsing-chain-tripartite-diff.sh —— 解析链三件差集与公告子词表比对器（离线 / 只读 / 不联网 / 不碰设备）
# 作用：把「声明件（内容自己声明了什么类型）× 通道件（哪条框架通道能把它读回来解析）×
#       观测件（哪一面真能读回这一格的后果与归属）」三份登记放在一起算差集，专查逐条审查
#       （parsing-chain-ledger-review.sh）查不出的四类问题——
#       「声明了这一项，通道件与观测件两格却一条也没有」（三件不成对）；
#       「某类内容明确需要的核对项，台账里一条也没有」（覆盖空洞）；
#       「读数挂在某个平面上，但那个平面按公开口径根本不承载这一格」（平面越界）；
#       「台账引用的类型标识、框架符号、公告组件、CVE 或限制键，公开词表里不存在」（归属悬空）。
# 输入（顺序固定，三个文件全部只读）：
#   1) 三件清单   每行 10 列：<对象标识>,<对象类>,<核对项>,<三件状态>,<读数平面>,<词表归属>,<引用>,<对外表述>,<内容来源>,<解析时点>
#   2) 三件能力表 每行 3 列：<对象类>,<核对项>,<可得性>
#   3) 公开词表   制表符分隔三列：<词表类别>	<词表值>	<来源标识>    # 开头与空行忽略
# 边界：本脚本不联网取公告，不调用 file/mdls/mdimport/spctl/codesign/defaults/log/sysctl/xcrun/profiles
#       等任何命令行工具，不打开或解析任何被登记的对象，不修改输入文件；只核对三份登记与公开词表是否自洽。
#       给出「三件不成对」或「覆盖空洞」不等于补登记：补登记需要新的读数来源，本脚本只指出缺哪一格、
#       按公开口径这一格本应由哪个平面给出。唯一写出目标是 mktemp -d 创建的临时目录，退出时删除，
#       本实现不向其写入任何字节。
set -u
LC_ALL=C; export LC_ALL

usage() {
  cat <<'EOF'
用法: parsing-chain-tripartite-diff.sh [-q] 三件清单 三件能力表 公开词表
  -h|--help 显示本帮助；-q 只输出汇总，不逐条打印三件差集矩阵与词表读数
三件清单行格式（10 列，逗号分隔；# 与空行忽略，行尾 CR 忽略，值里不能含逗号）:
  <对象标识>,<对象类>,<核对项>,<三件状态>,<读数平面>,<词表归属>,<引用>,<对外表述>,<内容来源>,<解析时点>
对象类（11：8 个内容类 + 1 个服务类 + 2 个兜底类，与对象标识前缀一一对应）:
  IMG_ image_content    WEB_ web_content        MOD_ model_content     FNT_ font_content
  AV_  audio_video_content  ARC_ archive_content  DOC_ document_content  PKG_ package_content
  SVC_ system_service   NA_  not_recorded       UNK_ unknown
核对项（20 项，按三件归属）:
  声明件 declared  declared_uti declared_mime filename_ext conforms_chain
                   decl_ownership tag_spec pkg_layout
  通道件 channel   uti_lookup ext_lookup mime_lookup decode_entry preview_entry
                   open_entry resolved_uti
  观测件 observed  advisory_component advisory_cve mgmt_restriction notice_surface
                   crash_ref render_result
三件状态: recorded absent not_applicable not_recorded unknown
数组型核对项（同一对象可多行登记，逐行给一个值）: conforms_chain filename_ext tag_spec；其余核对项一号一行，重复行按 S08/S09 报出
读数平面（23）: plist_declaration uttype_framework tag_mapping_api imageio_api coregraphics_api
  modelio_api webkit_load quicklook_preview uidocument_open openurl_callback activity_share
  pasteboard_transfer settings_ui configuration_profile mdm_declaration advisory_entry kev_entry
  crash_report vendor_claim app_self_report none not_recorded unknown
词表归属: uti_identifier api_symbol plist_key restriction_key advisory_component
  advisory_component_crafted advisory_cve mime_tag extension_tag doc_ref mixed not_recorded unknown
对外表述: yes no not_recorded unknown
内容来源: local_copy remote_download received_share message_attachment web_page clipboard none
  not_recorded unknown
解析时点: on_open on_preview on_background_fetch on_user_action on_arrival not_recorded unknown
引用格: 公开词形值 / 词表值本身 / A/quicklook.txt:16 / C/subset-18.txt:10 /
  none（确认无对应条目）/ not_recorded（未登记）
逐核对项的公开词形值（M01—M06 据此判定；标识形态、扩展名形态、MIME 形态、CVE 形态、
  报告标识形态各按帮助里的形态规则判定）:
  conforms_chain        public.data public.content public.image public.item public.json
                        public.database public.spreadsheet com.apple.package public.filename-extension
  decl_ownership        exported imported system_declared
  tag_spec              UTTypeIdentifier UTTypeConformsTo UTTypeDescription UTTypeReferenceURL
                        UTTypeTagSpecification UTExportedTypeDeclarations UTImportedTypeDeclarations
  pkg_layout            package nonpackage not_applicable
  uti_lookup            UTType UTTypeIdentifier
  ext_lookup            filenameExtension UTTagClassFilenameExtension public.filename-extension
  mime_lookup           mimeType UTTagClassMIMEType
  decode_entry          CGImageSource CGAnimateImageAtURLWithBlock WKWebView UIDocument QLPreviewController
  preview_entry         QLPreviewController ql_extension none
  open_entry            application_open scene_openurl uidocument_open activity_share none
  notice_surface        lockdown_notice preview_notice ql_ar_notice none
  render_result         rendered blank failed not_run
三件能力表行格式（3 列）: <对象类>,<核对项>,<可得性>    可得性: required optional not_applicable undocumented
公开词表行格式（3 列，制表符分隔）: <词表类别>	<词表值>	<来源标识>
  词表类别: uti_identifier api_symbol plist_key restriction_key advisory_component
  advisory_component_crafted advisory_cve mime_tag extension_tag
形态规则（M 族逐条判据）:
  标识形态 declared_uti / resolved_uti：以字母开头、点分段、段内只用字母数字与连字符
  自有声明形态：K03—K05 只守 declared_uti 一格；conforms_chain 里的 public. 与 com.apple. 父类型是公开口径要求的正常写法
  扩展名形态 filename_ext：纯小写字母数字，不含点、斜杠与空格
  MIME 形态 declared_mime：两段且以斜杠分隔
  CVE 形态 advisory_cve：CVE-年-序号
  报告标识形态 crash_ref：点分段标识，不含空格与斜杠，长度不超过 40
信号族：S 清单自身形态 / C 能力表自身形态 / K 内容与声明越界 / M 公开词形 / D 覆盖空洞 /
        P 平面越界 / T 三件差集与矛盾 / X 公开词表比对 / V 引用形态与口径闭合 / Q1—Q4 闭合等级
阻断信号码（出现即为 Q2）：S01—S10 C01—C05 K01—K05 M01—M06 T03—T08 X01—X08 V02 V06
非阻断信号码（只落 Q3，计入口径漂移）：D01—D05 P01—P07 T01 T02 V01 V03 V04 V05
闭合等级：Q1 三件差集、平面可得性、公开词表三段齐备且无任何信号 / Q2 存在阻断信号 /
          Q3 只有非阻断信号（覆盖空洞、平面越界、无引用或整段缺读数）：只能定覆盖面不能定归属 / Q4 连可得性都不能定
退出码：出现阻断信号时为 1，输入不可用时为 2，否则为 0。覆盖空洞、平面越界与三件不成对不计入阻断，只落 Q3（此时退出码仍为 0）。
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

TMPD=$(mktemp -d "${TMPDIR:-/tmp}/pct.XXXXXX") || { echo "无法创建临时目录" >&2; exit 2; }
trap 'rm -rf "$TMPD"' EXIT INT TERM

awk -v QUIET="$QUIET" '
function emit(code, id, msg,  k) {
  cnt[code]++; lines[++nline] = sprintf("%s\t%s\t%s", code, (id==""?"-":id), msg src(code))
  if (code in HB) hard[id] = 1; else if (code !~ /^Q[1234]$/) soft[id]++
}
function isNA(v)  { return (v=="" || v=="not_recorded" || v=="unknown") }
function trim(v)  { gsub(/^[[:space:]]+|[[:space:]]+$/, "", v); return v }
function nrm(v,  t) { t = tolower(v); gsub(/[[:space:]_\/.:-]/, "", t); return t }
function hasToken(s, t,  a, i, n) { n = split(s, a, " "); for (i = 1; i <= n; i++) if (a[i] == t) return 1; return 0 }
function hasTok(it, v,  t, i, n) { n = split(TOK[it], t, " "); for (i = 1; i <= n; i++) if (t[i] == v) return 1; return 0 }
function isCve(v)    { return (v ~ /^CVE-[0-9]{4}-[0-9]{4,}$/) }
function isIdForm(v) { return (v ~ /^[A-Za-z][A-Za-z0-9_-]*(\.[A-Za-z0-9_-]+)+$/) }
function isExtForm(v){ return (v ~ /^[a-z0-9]{1,15}$/) }
function isMIME(v)   { return (v ~ /^[a-z0-9.+-]+\/[a-z0-9.+-]+$/) }
function isDocRef(v) { return (v ~ /^[ABC]\/[A-Za-z0-9._\/-]+:[0-9]+(-[0-9]+)?$/) }
function isRepId(v)  { return (isIdForm(v) || v ~ /^[A-Za-z0-9_-]+$/) && length(v) <= 40 && v !~ /[ ]/ && v !~ /\// }
function isSecretish(v) {
  return (v ~ /-----BEGIN/ || v ~ /\.(p12|pfx|mobileprovision|provisionprofile|cap|pcap|sqlite|dmg|zip|tar)$/ \
      || v ~ /^\/(Applications|private|var\/mobile|Users|Library)\// || v ~ /^file:\/\// \
      || v ~ /^data:[A-Za-z\/+]*;base64,/ || length(v) > 200)
}
function src(c) { return (c in DOC) ? "（" DOC[c] "）" : "" }
function ck(a, b) { return a SUBSEP b }
function isBody(line) { return (line !~ /^[[:space:]]*#/ && line !~ /^[[:space:]]*$/) }
function mkset(set, str,  t, i, n) { n = split(str, t, " "); for (i = 1; i <= n; i++) set[t[i]] = 1 }
function mkit(set, fam, str,  t, i, n) { n = split(str, t, " "); for (i = 1; i <= n; i++) { set[t[i]] = 1; ITFAM[t[i]] = fam } }
function ppair(p, fam) { PAIR[ck(p, fam)] = 1 }
function vpair(vw, fam) { PAIR[ck("VW:" vw, fam)] = 1 }
function GV(i, f,  k) { k = ck(i, f); return (k in statOf) ? statOf[k] : "" }
function GR(i, f,  k) { k = ck(i, f); return (k in refOf) ? refOf[k] : "" }
function GP(i, f,  k) { k = ck(i, f); return (k in planeOf) ? planeOf[k] : "" }
BEGIN {
  FS = ","
  mkset(KD, "image_content web_content model_content font_content audio_video_content archive_content document_content package_content system_service not_recorded unknown")
  mkit(ITM, "declared", "declared_uti declared_mime filename_ext conforms_chain decl_ownership tag_spec pkg_layout")
  mkit(ITM, "channel",  "uti_lookup ext_lookup mime_lookup decode_entry preview_entry open_entry resolved_uti")
  mkit(ITM, "observed", "advisory_component advisory_cve mgmt_restriction notice_surface crash_ref render_result")
  mkset(ITOK, "conforms_chain decl_ownership tag_spec pkg_layout uti_lookup ext_lookup mime_lookup decode_entry preview_entry open_entry notice_surface render_result")
  TOK["conforms_chain"] = "public.data public.content public.image public.item public.json public.database public.spreadsheet com.apple.package public.filename-extension"
  TOK["decl_ownership"] = "exported imported system_declared"
  TOK["tag_spec"]       = "UTTypeIdentifier UTTypeConformsTo UTTypeDescription UTTypeReferenceURL UTTypeTagSpecification UTExportedTypeDeclarations UTImportedTypeDeclarations"
  TOK["pkg_layout"]     = "package nonpackage not_applicable"
  TOK["uti_lookup"]     = "UTType UTTypeIdentifier"
  TOK["ext_lookup"]     = "filenameExtension UTTagClassFilenameExtension public.filename-extension"
  TOK["mime_lookup"]    = "mimeType UTTagClassMIMEType"
  TOK["decode_entry"]   = "CGImageSource CGAnimateImageAtURLWithBlock WKWebView UIDocument QLPreviewController"
  TOK["preview_entry"]  = "QLPreviewController ql_extension none"
  TOK["open_entry"]     = "application_open scene_openurl uidocument_open activity_share none"
  TOK["notice_surface"] = "lockdown_notice preview_notice ql_ar_notice none"
  TOK["render_result"]  = "rendered blank failed not_run"
  # 近义词：形似公开词形但不在这份公开口径里
  mkset(NEAR, "declarative export import dynamic reserved generic binary raw stream bytes asset resource attachment payload thumbnail content_kind handler viewer renderer sandboxed permitted denied confirmed verified unsigned")
  mkset(ST, "recorded absent not_applicable not_recorded unknown")
  mkset(MULTI, "conforms_chain filename_ext tag_spec")
  mkset(PL, "plist_declaration uttype_framework tag_mapping_api imageio_api coregraphics_api modelio_api webkit_load quicklook_preview uidocument_open openurl_callback activity_share pasteboard_transfer settings_ui configuration_profile mdm_declaration advisory_entry kev_entry crash_report vendor_claim app_self_report none not_recorded unknown")
  mkset(VW, "uti_identifier api_symbol plist_key restriction_key advisory_component advisory_component_crafted advisory_cve mime_tag extension_tag doc_ref mixed not_recorded unknown")
  mkset(OUTW, "yes no not_recorded unknown")
  mkset(SRCW, "local_copy remote_download received_share message_attachment web_page clipboard none not_recorded unknown")
  mkset(WHEN, "on_open on_preview on_background_fetch on_user_action on_arrival not_recorded unknown")
  mkset(AV, "required optional not_applicable undocumented")
  mkset(VK, "uti_identifier api_symbol plist_key restriction_key advisory_component advisory_component_crafted advisory_cve mime_tag extension_tag")
  # 对象标识前缀与对象类一一对应（S10 判据）
  PFX["IMG_"]="image_content"; PFX["WEB_"]="web_content"; PFX["MOD_"]="model_content"; PFX["FNT_"]="font_content"
  PFX["AV_"]="audio_video_content"; PFX["ARC_"]="archive_content"; PFX["DOC_"]="document_content"
  PFX["PKG_"]="package_content"; PFX["SVC_"]="system_service"; PFX["NA_"]="not_recorded"; PFX["UNK_"]="unknown"
  # 解码入口按公开口径能承载的对象类（P05 判据；空集＝归档里没有承载该类解析的面）
  DEOK["image_content"]   = "imageio_api coregraphics_api"
  DEOK["web_content"]     = "webkit_load"
  DEOK["model_content"]   = "modelio_api"
  DEOK["document_content"]= "uidocument_open quicklook_preview"
  DEOK["package_content"] = "uidocument_open quicklook_preview"
  DEOK["audio_video_content"] = "quicklook_preview"
  DEOK["system_service"]  = "openurl_callback"
  DEOK["font_content"]    = ""
  DEOK["archive_content"] = ""
  # 平面承载哪一件：按公开口径逐格对齐（uniformtypeidentifiers 第 7、8—20、25—52 行；
  # defining 第 9—14、16—24、42—46、53、61—65、78、88、90—102 行；system_declared 第 5、8—23 行；
  # imageio 第 3、6 行；coregraphics 第 3、6 行；webkit 第 4、6 行；wkwebview 第 21—22 行；
  # quicklook 第 6、17、19—20 行；qlpreviewcontroller 第 11、22 行；uidocument 第 35 行；
  # open:options 第 3、4、49 行；activityvc 第 9、10 行；mdm-restriction-keys 第 5—8、9、133、162 行；
  # mdm-restrictions 第 24、738、960 行；平台安全指南第 1442、1448、2388、2391、2557 行）
  ppair("plist_declaration","declared");  ppair("uttype_framework","declared")
  ppair("tag_mapping_api","declared")
  ppair("uttype_framework","channel");   ppair("tag_mapping_api","channel")
  ppair("imageio_api","channel");        ppair("coregraphics_api","channel")
  ppair("modelio_api","channel");        ppair("webkit_load","channel")
  ppair("quicklook_preview","channel");  ppair("uidocument_open","channel")
  ppair("openurl_callback","channel");   ppair("activity_share","channel")
  ppair("pasteboard_transfer","channel")
  ppair("settings_ui","observed");       ppair("configuration_profile","observed")
  ppair("mdm_declaration","observed");   ppair("advisory_entry","observed")
  ppair("kev_entry","observed");         ppair("crash_report","observed")
  ppair("quicklook_preview","observed"); ppair("vendor_claim","observed")
  ppair("app_self_report","observed")
  # 词表归属描述哪一件
  vpair("uti_identifier","declared");  vpair("uti_identifier","channel")
  vpair("mime_tag","declared");        vpair("extension_tag","declared")
  vpair("plist_key","declared");       vpair("api_symbol","channel")
  vpair("doc_ref","declared");         vpair("doc_ref","channel"); vpair("doc_ref","observed")
  vpair("advisory_component","observed"); vpair("advisory_component_crafted","observed")
  vpair("advisory_cve","observed");    vpair("restriction_key","observed")
  vpair("mixed","declared");           vpair("mixed","observed")
  HB["S01"]=1; HB["S02"]=1; HB["S03"]=1; HB["S04"]=1; HB["S05"]=1; HB["S06"]=1; HB["S07"]=1
  HB["S08"]=1; HB["S09"]=1; HB["S10"]=1
  HB["C01"]=1; HB["C02"]=1; HB["C03"]=1; HB["C04"]=1; HB["C05"]=1
  HB["K01"]=1; HB["K02"]=1; HB["K03"]=1; HB["K04"]=1; HB["K05"]=1
  HB["M01"]=1; HB["M02"]=1; HB["M03"]=1; HB["M04"]=1; HB["M05"]=1; HB["M06"]=1
  HB["T03"]=1; HB["T04"]=1; HB["T05"]=1; HB["T06"]=1; HB["T07"]=1; HB["T08"]=1
  HB["X01"]=1; HB["X02"]=1; HB["X03"]=1; HB["X04"]=1; HB["X05"]=1; HB["X06"]=1; HB["X07"]=1; HB["X08"]=1
  HB["V02"]=1; HB["V06"]=1
  DOC["S01"]="见 usage 文本的三件清单行格式（一行十列、列序固定、值里不能含逗号）"
  DOC["S02"]="见 usage 文本的对象标识（标识是行的第一列，也是与能力表对齐的唯一依据）"
  DOC["S03"]="见 C/readings-18.txt 第 10—23 行的公告对象词（web content / file / image / model / font / video / audio / archive 各成一行）"
  DOC["S04"]="见 A/uniformtypeidentifiers_defining_file_and_data_types_for_your_app.txt 第 9—14、42—46、61—65 行与 A/uniformtypeidentifiers.txt 第 7、25—52 行（三件 20 项逐项有出处）"
  DOC["S05"]="见 A/uniformtypeidentifiers_defining_file_and_data_types_for_your_app.txt 第 12 行（一个类型要么是导出声明要么是导入声明，框架已提供的类型不得在 App 内重复声明）"
  DOC["S06"]="见 A/uniformtypeidentifiers_system_declared_uniform_type_identifiers.txt 第 8 行与第 14 行"
  DOC["S07"]="见 A/uniformtypeidentifiers_defining_file_and_data_types_for_your_app.txt 第 90—102 行与 C/subset-18.txt 第 3 行（公告全量组件去重 129 个）"
  DOC["S08"]="见 A/uniformtypeidentifiers_defining_file_and_data_types_for_your_app.txt 第 82 行（一致性类型是一个数组，同一个父类型重复列出不改变判定）"
  DOC["S09"]="见 A/uniformtypeidentifiers.txt 第 8—20 行（同一个类型标识只有一条派生链）"
  DOC["S10"]="见 C/subset-18.txt 第 19—42 行（同一份内容在两份文档里的清单段行号不同，必须靠前缀定位）"
  DOC["C01"]="见 usage 文本的三件能力表行格式（一行三列：对象类,核对项,可得性）"
  DOC["C02"]="见 A/uniformtypeidentifiers_system_declared_uniform_type_identifiers.txt 第 5 行（清单只覆盖系统声明的公共类型）"
  DOC["C03"]="见 A/uniformtypeidentifiers_defining_file_and_data_types_for_your_app.txt 第 70—102 行（声明用的键逐条列出，不在此列的键名无处登记）"
  DOC["C04"]="见 A/uniformtypeidentifiers_defining_file_and_data_types_for_your_app.txt 第 78 行（类型标识格对类型声明是必需的）"
  DOC["C05"]="见 A/uniformtypeidentifiers_defining_file_and_data_types_for_your_app.txt 第 88 行（导出与导入声明同时存在时只有一条优先规则）"
  DOC["K01"]="见本文第 3.4 节失败点 8（台账只登记哪一个对象在哪一格被判定成什么，不登记内容本身）"
  DOC["K02"]="见 B/apple-platform-security-guide.txt 第 2388 行（App 侧防护由 App Review 与平台保护共同构成）"
  DOC["K03"]="见 A/uniformtypeidentifiers_defining_file_and_data_types_for_your_app.txt 第 29—33 行"
  DOC["K04"]="见 A/uniformtypeidentifiers_defining_file_and_data_types_for_your_app.txt 第 34 行与第 119、122 行"
  DOC["K05"]="见 A/uniformtypeidentifiers_defining_file_and_data_types_for_your_app.txt 第 35 行与第 120、123 行"
  DOC["M01"]="见 A/uniformtypeidentifiers_defining_file_and_data_types_for_your_app.txt 第 16—24 行"
  DOC["M02"]="见 A/uniformtypeidentifiers_defining_file_and_data_types_for_your_app.txt 第 61—65 行与第 138—139 行"
  DOC["M03"]="见 A/uniformtypeidentifiers.txt 第 7 行与 A/uniformtypeidentifiers_system_declared_uniform_type_identifiers.txt 第 14—17 行"
  DOC["M04"]="见本文第 12 章（崩溃只登记报告标识，不粘贴正文、堆栈或设备路径）"
  DOC["M05"]="见 C/advisory-18.tsv 第 2 行与 C/kev-apple.tsv 第 2 行（两份档案的 CVE 列同形）"
  DOC["M06"]="见 A/uniformtypeidentifiers_defining_file_and_data_types_for_your_app.txt 第 52 行（要一致到最具体的子类型，泛化自造词无法回指）"
  DOC["D01"]="见 A/uniformtypeidentifiers_defining_file_and_data_types_for_your_app.txt 第 9—10 行"
  DOC["D02"]="见 A/uniformtypeidentifiers_defining_file_and_data_types_for_your_app.txt 第 78 行（类型标识格是必需的）"
  DOC["D03"]="见 A/uniformtypeidentifiers_system_declared_uniform_type_identifiers.txt 第 8—17 行"
  DOC["D04"]="见 A/uniformtypeidentifiers.txt 第 53—54 行（自定义声明与系统声明分属两份文档）"
  DOC["D05"]="见 C/readings-18.txt 第 99 行（201 个条目）与第 112 行（提及 conforming、base type 或 declare 的行 = 67）"
  DOC["P01"]="见 A/quicklook.txt 第 17 行（自有数据类型的预览要 App 自己提供视图或返回受支持的预览格式）"
  DOC["P02"]="见 C/readings-18.txt 第 93 行（命中内容接收、打开、预览、网页、文件类词形的键只有 6 个）与 B/mdm-restrictions.txt 第 738 行（管理面关掉的是承载内容的 App，不是解析链本身）"
  DOC["P03"]="见 C/advisory-18.tsv 第 1 行（file、platform、component、cve、impact、avail）"
  DOC["P04"]="见 A/quicklook_qlpreviewcontroller.txt 第 22 行（受支持的常见类型清单可能随系统版本变化）"
  DOC["P05"]="见 A/imageio.txt 第 3、6 行与 A/webkit.txt 第 5—8 行；字体与归档两类只有类型声明（A/uniformtypeidentifiers_system_declared_uniform_type_identifiers.txt 第 84—87、270 行）而没有承载其解析入口的文档面"
  DOC["P06"]="见 A/uniformtypeidentifiers_system_declared_uniform_type_identifiers.txt 第 8—23 行"
  DOC["P07"]="见本文第 12 章（崩溃面限定为报告标识本身，其余平面不承载崩溃读数）"
  DOC["T01"]="见 A/uniformtypeidentifiers.txt 第 7 行（类型描述由 App 提供，框架只做映射）与 A/quicklook.txt 第 19—20 行（自有类型要另建预览扩展并把受支持类型加进清单）"
  DOC["T02"]="见 A/uniformtypeidentifiers_defining_file_and_data_types_for_your_app.txt 第 46 行（不声明一致类型时系统无法判断存储项属于该类型）"
  DOC["T03"]="见 C/advisory-18.tsv 第 1 行与 B/mdm-restriction-keys.txt 第 5—8 行"
  DOC["T04"]="见 A/uniformtypeidentifiers_defining_file_and_data_types_for_your_app.txt 第 53 行（指定非公共类型的一致性时必须在自己的包里同时声明该类型）"
  DOC["T05"]="见 A/uniformtypeidentifiers_defining_file_and_data_types_for_your_app.txt 第 88 行（两者同时存在时导出声明优先）"
  DOC["T06"]="见 A/uniformtypeidentifiers.txt 第 8—20 行（一个类型标识只有一条派生链，父类型再派生自内容类与数据类）"
  DOC["T07"]="见 A/uniformtypeidentifiers_defining_file_and_data_types_for_your_app.txt 第 42—46 行与第 128—130 行"
  DOC["T08"]="见 A/uniformtypeidentifiers_defining_file_and_data_types_for_your_app.txt 第 46 行"
  DOC["X01"]="见 C/subset-18.txt 第 3 行（全量组件去重 129 个）"
  DOC["X02"]="见 C/subset-18.txt 第 10 行（全量词表里但不属子词表的组件 = 95）"
  DOC["X03"]="见 C/subset-18.txt 第 4—5 行（全量 CVE 去重 330 个，子词表 95 个）"
  DOC["X04"]="见 C/readings-18.txt 第 92 行（键名行 = 218）与 B/mdm-restriction-keys.txt 第 9、133、162 行"
  DOC["X05"]="见 A/uniformtypeidentifiers.txt 第 57—61 行（五个归档里逐字出现的公共标识）"
  DOC["X06"]="见 A/uniformtypeidentifiers.txt 第 25—52 行（UTType 家族符号清单）与 A/uniformtypeidentifiers_system_declared_uniform_type_identifiers.txt 第 11、17、21、23 行"
  DOC["X07"]="见 A/uniformtypeidentifiers_defining_file_and_data_types_for_your_app.txt 第 140 行（标签类标识 public.filename-extension）"
  DOC["X08"]="见 C/advisory-18.tsv 第 1 行与 B/mdm-restriction-keys.txt 第 1—4 行（前四行是页面分段标题，不是键名）"
  DOC["V01"]="见 A/uniformtypeidentifiers_defining_file_and_data_types_for_your_app.txt 第 95—96 行（类型标识格逐条给值）"
  DOC["V02"]="见 A/uniformtypeidentifiers_defining_file_and_data_types_for_your_app.txt 第 87、98 行（声明本身允许挂一个描述该类型的参考文档）"
  DOC["V03"]="见 A/quicklook.txt 第 17 行与 A/quicklook_qlpreviewcontroller.txt 第 22 行"
  DOC["V04"]="见 A/quicklook.txt 第 17、19 行"
  DOC["V05"]="见 A/uniformtypeidentifiers_system_declared_uniform_type_identifiers.txt 第 8—23 行（扩展名与 MIME 两条标签类各自成格）"
  DOC["V06"]="见 C/advisory-18.tsv 第 1 行与 B/mdm-restriction-keys.txt 第 9 行"
  DOC["Q1"]="见 A/uniformtypeidentifiers_defining_file_and_data_types_for_your_app.txt 第 9—14 行与 A/uniformtypeidentifiers.txt 第 8—20 行"
  DOC["Q2"]="见 A/uniformtypeidentifiers_defining_file_and_data_types_for_your_app.txt 第 29—35、53、88 行"
  DOC["Q3"]="见 A/quicklook.txt 第 17、19 行与 C/subset-18.txt 第 40—41 行"
  DOC["Q4"]="见 A/uniformtypeidentifiers.txt 第 53—54 行与 C/readings-18.txt 第 99、112 行"
}

# ---- 输入 1：三件清单 ----
FILENAME == ARGV[1] && isBody($0) {
  line = $0; sub(/\r$/, "", line)
  n = split(line, fx, ",")
  if (n != 10) { emit("S01", fx[1], "三件清单记录不是恰好十列：" line); subjAll = 1; next }
  id = trim(fx[1]); kd = trim(fx[2]); it = trim(fx[3]); st = trim(fx[4])
  pl = trim(fx[5]); vw = trim(fx[6]); rf = trim(fx[7]); ow = trim(fx[8])
  sw = trim(fx[9]); wh = trim(fx[10])
  if (id == "" || id ~ /[ \t]/) { emit("S02", id, "对象标识为空或含空白，无法与三件能力表对齐"); subjAll = 1; next }
  if (!(id in seen)) { seen[id] = 1; order[++nid] = id }
  subj = 0
  if (!(kd in KD)) { emit("S03", id, "对象类取值不在允许集合：" kd); subj = 1 }
  if (!(it in ITM)) { emit("S04", id, "核对项不在三件 20 项词表内：" it); subj = 1 }
  for (p in PFX) { if (substr(id, 1, length(p)) == p && PFX[p] != kd && kd != "") emit("S10", id, "对象标识前缀 " p " 与对象类 " kd " 不一致") }
  if (subj) subjBad[id] = 1
  if (!(st in ST)) emit("S05", id, "三件状态取值非法：" st)
  if (!(pl in PL)) emit("S06", id, "读数平面取值非法：" pl)
  if (!(vw in VW)) emit("S07", id, "枚举越界：词表归属列 " vw)
  if (!(ow in OUTW)) emit("S07", id, "枚举越界：对外表述列 " ow)
  if (!(sw in SRCW)) emit("S07", id, "枚举越界：内容来源列 " sw)
  if (!(wh in WHEN)) emit("S07", id, "枚举越界：解析时点列 " wh)
  if (!(it in ITM)) next
  itemRows++
  if (it == "decl_ownership") ownRef[id] = ownRef[id] " " rf
  if (it == "conforms_chain") confRef[id] = confRef[id] " " rf
  if (!(id in kdSeen)) { kdSeen[id] = 1; kdOf[id] = kd }
  k = ck(id, it)
  if (k in statOf) {
    if (it in MULTI && statOf[k]==st && planeOf[k]==pl && vwOf[k]==vw) {
      if (refOf[k]==rf) emit("S08", id, "核对项重复登记：" it " 数组型两次列同一个值（差集会重复计数）")
      else refOf[k] = refOf[k] " " rf
      next
    }
    if (statOf[k]==st && planeOf[k]==pl && vwOf[k]==vw) emit("S08", id, "核对项重复登记：" it " 两行的状态、平面与归属三格完全一致（差集会重复计数）")
    else emit("S09", id, "核对项 " it " 出现两种登记口径：" statOf[k] "/" planeOf[k] "/" vwOf[k] " 与 " st "/" pl "/" vw)
    next
  }
  statOf[k] = st; planeOf[k] = pl; vwOf[k] = vw; refOf[k] = rf; outOf[k] = ow
  if (st == "recorded" && ow == "yes") outYes[id] = 1
  famRec[id, ITFAM[it]] += (st == "recorded" ? 1 : 0)
  famAny[id, ITFAM[it]]++
  itemSeen[it] = 1
  next
}

# ---- 输入 2：三件能力表 ----
FILENAME == ARGV[2] && isBody($0) {
  line = $0; sub(/\r$/, "", line)
  n = split(line, fx, ",")
  if (n != 3) { emit("C01", fx[1], "三件能力表记录不是恰好三列：" line); next }
  kd = trim(fx[1]); it = trim(fx[2]); av = trim(fx[3])
  if (!(kd in KD)) { emit("C02", kd, "能力表对象类取值不在允许集合：" kd); next }
  if (!(it in ITM)) { emit("C03", kd, "能力表核对项不在 20 项词表内：" it); next }
  if (!(av in AV)) { emit("C04", kd, "可得性取值不在允许集合：" av); next }
  kk = ck(kd, it)
  if (kk in capOf) {
    if (capOf[kk] != av) emit("C05", kd, "可得性基准不可用：核对项 " it " 有两条不同可得性（" capOf[kk] " / " av "）")
    else emit("C05", kd, "可得性基准不可用：核对项 " it " 重复登记同一条可得性")
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
  if (n < 2) { emit("X08", trim(a[1]), "公开词表形态非法：记录不足两列（类别<TAB>值）" line); next }
  vk = trim(a[1]); vv = trim(a[2])
  if (!(vk in VK)) { emit("X08", vk, "公开词表形态非法：类别列不在允许集合 " vk); next }
  if (vv == "") { emit("X08", vk, "公开词表形态非法：值格为空 " line); next }
  nk = nrm(vv)
  if (!(nk in vocab)) { vocab[nk] = vk; vrows++ }
  if (vk == "advisory_cve") { if (!(nk in cveSeen)) { cveSeen[nk] = 1; cveN++ } }
  else if (vk == "advisory_component") { if (!(nk in compSeen)) { compSeen[nk] = 1; compN++ } }
  else if (vk == "advisory_component_crafted") { if (!(nk in craftSeen)) { craftSeen[nk] = 1; craftN++ } }
  else if (vk == "restriction_key") { if (!(nk in keySeen)) { keySeen[nk] = 1; keyN++ } }
  else if (vk == "uti_identifier") { if (!(nk in utiSeen)) { utiSeen[nk] = 1; utiN++ } }
  else if (vk == "api_symbol" || vk == "plist_key") { if (!(nk in symSeen)) { symSeen[nk] = 1; symN++ } }
  else if (vk == "mime_tag" || vk == "extension_tag") { if (!(nk in tagSeen)) { tagSeen[nk] = 1; tagN++ } }
  if (n >= 3 && trim(a[3]) != "" && !isDocRef(trim(a[3]) "0")) {
    srcv = trim(a[3])
    if (!isDocRef(srcv) && srcv != "fixture") { emit("X08", vv, "公开词表形态非法：来源标识既不是文档行号形态也不是 fixture " srcv) }
  }
  next
}

END {
  if (capRows == 0) emit("C05", "-", "可得性基准不可用：三件能力表一条有效行都没有，三件差集无法计算")
  if (vrows == 0) emit("X08", "-", "公开词表形态非法：整表无可用行，类型标识、符号、公告与限制键比对均不可执行")
  for (t in ITM) if (!(t in itemSeen)) emit("D05", "-", "核对项 " t " 在整张清单里零登记")

  for (ix = 1; ix <= nid; ix++) {
    id = order[ix]
    if (!(id in kdSeen)) continue
    kd = kdOf[id]
    if (capKdN > 0 && !(kd in capKdSet)) emit("D04", id, "清单里的对象类 " kd " 在能力表一行都没有：这一类的判据未建模，缺哪一格无从判定")

    dec = famRec[id,"declared"] + 0; chan = famRec[id,"channel"] + 0; obsv = famRec[id,"observed"] + 0
    if (dec > 0 && chan == 0 && obsv == 0)
      emit("T01", id, "三件只登记了声明件（" dec " 格已读数），通道件与观测件一条已读数都没有：App 写了类型声明不等于任何一面读得回来")
    if ((chan > 0 || obsv > 0) && dec == 0)
      emit("T02", id, "通道件与观测件共有 " chan+obsv " 格已读数但声明件一格都没有：内容自带的声明缺失时读回来的类型落在对象之外")
    if (ownRef[id] ~ /exported/ && ownRef[id] ~ /imported/)
      emit("T05", id, "同一对象把类型标识同时登记为导出声明与导入声明")
    nc2 = split(confRef[id], ct, " ")
    for (ci = 1; ci <= nc2; ci++) {
      pv = ct[ci]
      if (pv == "" || pv ~ /^public\./ || pv ~ /^com\.apple\./ || pv ~ /^(none|not_recorded|unknown)$/) continue
      if (!hasToken(utiRefOf[id], pv)) emit("T04", id, "一致性类型指向非 public. 前缀的父类型 " pv "，但本对象的声明件里没有登记它")
    }
    dv = GR(id, "declared_uti"); rv = GR(id, "resolved_uti")
    if (dv != "" && rv != "" && !isNA(dv) && !isNA(rv) && dv != rv && !hasToken(confRef[id], rv))
      emit("T06", id, "反查回来的类型 " rv " 与声明的类型 " dv " 不同且不在声明的一致性链上")
    if (GR(id,"pkg_layout") == "package" && !hasToken(confRef[id], "com.apple.package"))
      emit("T07", id, "登记为包结构但一致性链里没有包类型 com.apple.package")
    if (outYes[id] == 1) {
      miss = ""
      for (mi = 1; mi <= 2; mi++) {
        it8 = (mi == 1 ? "declared_uti" : "conforms_chain")
        if (!((ck(kd, it8) in capOf) && capOf[ck(kd, it8)] == "required")) continue
        st8 = GV(id, it8)
        if (st8 == "" || st8 == "absent" || isNA(st8)) miss = miss (miss==""?"":"、") it8
      }
      if (miss != "")
        emit("T08", id, "对外表述为是但该类必需的声明格缺位（" miss "）：此时公开口径明说系统判不出存储项属于该类型")
    }

    for (kk in capOf) {
      split(kk, sp, SUBSEP); c2 = sp[1]; it = sp[2]; av = capOf[kk]
      if (c2 != kd) continue
      k = ck(id, it)
      if (!(k in statOf)) {
        if (av == "required") { holesReq[id]++; emit("D02", id, "对象类 " kd " 的 required 核对项 " it " 在本对象完全没有登记行") }
        continue
      }
      st = statOf[k]; pl = planeOf[k]; vw = vwOf[k]; rf = refOf[k]; ow = outOf[k]
      fam = ITFAM[it]
      if (av == "required") {
        if (st == "absent") emit("D01", id, "对象类 " kd " 需要 " it "，台账却明确记为不存在")
        else if (isNA(st)) { holesReq[id]++; emit("D02", id, "对象类 " kd " 需要 " it "，台账记为 " st "：这一格没有读数") }
        else if (st == "not_applicable") { holesReq[id]++; emit("D03", id, "对象类 " kd " 的 required 核对项 " it " 被记为不适用：与能力表冲突") }
        if (st == "recorded") { reqTot[id]++; if (isNA(rf) || rf=="none") reqNoRef[id]++ }
      }
      if (av == "not_applicable" && st == "recorded") {
        holesReq[id]++
        emit("D03", id, "对象类 " kd " 的 " it " 在公开口径里不适用（扩展名反查与 MIME 反查分属两条通道），却登记了已读数")
      }
      if (st != "recorded") continue
      recTot[id]++
      if (it == "declared_uti") utiRefOf[id] = utiRefOf[id] " " rf

      # ---- 内容与声明越界 ----
      if (isSecretish(rf))
        emit("K01", id, "核对项 " it " 的引用格形似密钥、凭据、归档文件、设备绝对路径或整段载荷正文：只登记引用标识，不登记内容")
      else if (rf ~ /^(file|mdls|mdimport|mdutil|mdfind|spctl|codesign|defaults|sysctl|xcrun|profiles|plutil|sips|qlmanage|otool|log|ls|find)$/)
        emit("K02", id, "核对项 " it " 的引用格登记了设备侧命令行入口名（" rf "）：本脚本与台账都不以任何命令行工具作为读数来源")
      if (fam == "declared" && it == "declared_uti" && rf ~ /^public\./) emit("K03", id, "声明件把 public. 前缀的类型标识登记为自己的声明：" rf)
      else if (fam == "declared" && it == "declared_uti" && rf ~ /^dyn\./) emit("K04", id, "声明件把 dyn. 前缀的类型标识登记为自己的声明：" rf)
      else if (fam == "declared" && it == "declared_uti" && rf ~ /^com\.apple\./) emit("K05", id, "声明件把 com.apple. 前缀的类型标识登记为自己的声明：" rf)

      # ---- 公开词形 ----
      if (!isNA(rf) && rf != "none") {
        if (it == "declared_uti" || it == "resolved_uti") { if (!isIdForm(rf) && !isDocRef(rf)) emit("M01", id, "核对项 " it " 的引用格既不是标识形态也不是文档行号形态：" rf) }
        else if (it == "filename_ext")   { if (!isExtForm(rf) && !isDocRef(rf)) emit("M02", id, "扩展名标签不是纯小写字母数字形态：" rf) }
        else if (it == "declared_mime")  { if (!isMIME(rf) && !isDocRef(rf)) emit("M03", id, "声明的 MIME 标签不含斜杠：" rf) }
        else if (it == "crash_ref")      { if (!isRepId(rf) && !isDocRef(rf)) emit("M04", id, "崩溃引用格不是报告标识形态：" rf) }
        else if (it == "advisory_cve")   { if (!isCve(rf) && !isDocRef(rf)) emit("M05", id, "公告 CVE 号不是 CVE-年-序号形态：" rf) }
        else if (it in ITOK) {
          if (hasTok(it, rf)) { /* 落在公开词形表内 */ }
          else if (rf in NEAR) emit("M06", id, "核对项 " it " 的引用值 " rf " 是公开词形的近义词")
          else if (!(nrm(rf) in vocab) && !isDocRef(rf)) emit("M06", id, "核对项 " it " 的引用值 " rf " 不在这一格的公开词形表里")
        }
      }

      # ---- 引用形态 ----
      if (!(rf=="none" || isNA(rf))) {
        if (!isCve(rf) && !isDocRef(rf) && !(nrm(rf) in vocab) && !hasTok(it, rf))
          emit("V02", id, "核对项 " it " 的引用格既不是公开词表值也不是文档行号形态：" rf)
      }

      # ---- 平面越界 ----
      if (pl == "none") emit("P01", id, "核对项 " it " 记为已读数但读数平面为无平面")
      else if (fam=="channel" && (pl=="settings_ui" || pl=="configuration_profile" || pl=="mdm_declaration"))
        emit("P02", id, "通道件核对项 " it " 记在管理面平面上：管理面关掉的是承载内容的 App，不是解析链本身")
      else if (fam=="declared" && (pl=="advisory_entry" || pl=="kev_entry" || pl=="crash_report"))
        emit("P03", id, "声明件核对项 " it " 记在 " pl " 读回：公告六列里没有类型声明列")
      else if (it == "render_result" && !(pl=="quicklook_preview" || pl=="vendor_claim" || pl=="app_self_report"))
        emit("P04", id, "渲染结果记在 " pl "：预览面是唯一能读回渲染结果的面")
      else if (it == "crash_ref" && pl != "crash_report")
        emit("P07", id, "崩溃引用记在 " pl "：崩溃面限定为报告标识本身")
      else if (fam=="observed" && (pl=="plist_declaration" || pl=="uttype_framework" || pl=="tag_mapping_api"))
        emit("P06", id, "观测件核对项 " it " 记在类型声明或标签反查平面上：这两个面只给出类型映射")
      else if (!(ck(pl, fam) in PAIR) && !(ck(pl, it) in PAIR))
        emit("P05", id, "平面越界：读数平面 " pl " 与核对项 " it "（属 " fam "）不匹配，这一格不该由这个面给出")
      if (it == "decode_entry" && (kd in DEOK) && !hasToken(DEOK[kd], pl))
        emit("P05", id, "平面越界：对象类 " kd " 的解码入口记在 " pl "，按公开口径该类内容由这些面承载（" (DEOK[kd]==""?"（无）":DEOK[kd]) "）")

      # ---- 词表归属与件层 ----
      if (!isNA(vw) && !(ck("VW:" vw, fam) in PAIR))
        emit("T03", id, "核对项 " it "（属 " fam "）把词表归属记成 " vw "：这一层词表描述不了这一件")
      if (isNA(ow)) emit("V04", id, "核对项 " it " 已读数但未登记这一格是否会对外（不阻断）")
      if (it == "render_result" && (pl=="vendor_claim" || pl=="app_self_report"))
        emit("V03", id, "渲染结果只由 " pl " 给出：呈现面由 App 自己配置，其自述不独立构成观测")

      # ---- 公开词表比对 ----
      if (it=="advisory_component" || it=="advisory_cve" || it=="mgmt_restriction" || vw=="advisory_component" || vw=="advisory_component_crafted" || vw=="advisory_cve" || vw=="restriction_key") {
        if (isNA(rf) || rf=="none") emit("V06", id, "核对项 " it " 挂在公告面或管理面却没有词表标识：缺任一格就无法回指")
        else if (isCve(rf)) { if (vrows>0 && cveN>0 && !(nrm(rf) in cveSeen)) emit("X03", id, "引用的 CVE 号 " rf " 不在公告与 KEV 的 CVE 词表内") }
        else if (it=="mgmt_restriction" || vw=="restriction_key") { if (vrows>0 && keyN>0 && !(nrm(rf) in keySeen)) emit("X04", id, "引用的限制键 " rf " 不在公开管理面键清单内") }
        else if (vw=="advisory_component_crafted") {
          if (vrows>0 && craftN>0 && !(nrm(rf) in craftSeen)) emit("X02", id, "引用的组件 " rf " 被标注为「含恶意构造对象」子词表成员，但子词表里没有它")
          if (vrows>0 && compN>0 && craftN>0 && !(nrm(rf) in compSeen) && (nrm(rf) in craftSeen)) emit("X01", id, "引用的公告组件 " rf " 只在「含恶意构造对象」子词表里而不在全量组件词表里")
        }
        else {
          if (vrows>0 && compN>0 && !(nrm(rf) in compSeen)) emit("X01", id, "引用的公告组件 " rf " 归一化后不在全量组件词表内")
          else if (vrows>0 && craftN>0 && (nrm(rf) in compSeen) && !(nrm(rf) in craftSeen) && ow=="yes")
            emit("X02", id, "引用的组件 " rf " 在全量词表里但不含「恶意构造对象」行，却把解析类归属对外表述为是")
        }
        if ((it=="declared_uti" || vw=="uti_identifier") && utiN>0 && !isDocRef(rf) && !(nrm(rf) in utiSeen) && rf !~ /^(com|io|net|org)\./)
          emit("X05", id, "引用的类型标识 " rf " 既不在声明类型词表里也不是自有导出前缀")
      }
      if (vw=="uti_identifier" && utiN>0 && !isNA(rf) && rf!="none" && !isDocRef(rf) && !(nrm(rf) in utiSeen))
        emit("X05", id, "引用的类型标识 " rf " 不在声明类型词表内")
      if ((vw=="api_symbol" || vw=="plist_key") && symN>0 && !isNA(rf) && rf!="none" && !isDocRef(rf) && !(nrm(rf) in symSeen))
        emit("X06", id, "引用的框架符号或声明键 " rf " 不在符号词表内")
      if ((vw=="mime_tag" || vw=="extension_tag") && tagN>0 && !isNA(rf) && rf!="none" && !isDocRef(rf) && !(nrm(rf) in tagSeen))
        emit("X07", id, "引用的扩展名或 MIME 标签 " rf " 不在标签词表内")
    }
  }

  for (ix = 1; ix <= nid; ix++) {
    id = order[ix]
    if (!(id in kdSeen)) continue
    if (reqTot[id] > 0 && reqTot[id] == reqNoRef[id])
      emit("V01", id, "本对象 " reqTot[id] " 项 required 核对项的引用格全为无标识：结论无法回指任何一格")
    hardN = 0
    for (j = 1; j <= nline; j++) { split(lines[j], sp, "\t"); if (sp[2] == id && (sp[1] in HB)) hardN++ }
    if (!(kdOf[id] in capKdSet) || capKdN == 0 || subjBad[id] == 1) grade = "Q4"
    else if (hardN >= 1) grade = "Q2"
    else if (holesReq[id] > 0 || reqNoRef[id] > 0 || recTot[id] == 0 || soft[id] > 0) grade = "Q3"
    else grade = "Q1"
    if (grade == "Q4") emit("Q4", id, "连可得性都不能定：该对象类在能力表里没有任何一行，或本对象没有一行能通过形态校验")
    if (grade == "Q3") emit("Q3", id, "只能定「这一类内容应当有哪几格」，不能定「这一格由谁读回」：存在覆盖空洞、平面越界、无引用或整段缺读数等非阻断信号")
    if (grade == "Q2") emit("Q2", id, "存在阻断信号：三件差集、平面可得性或公开词表至少一段互相矛盾，不能作为对外归属表述")
    if (grade == "Q1") emit("Q1", id, "三件差集、平面可得性与公开词表三段齐备且无阻断：可用于对外表述这一条解析链缺哪一格")
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
    emit("V05", "-", "对象类 " sp[1] " 的核对项 " sp[2] " 在对象之间既有已读数又有明确不存在（不阻断）：登记口径未统一")
  }

  if (!QUIET) {
    print "---- 三件差集矩阵（声明件 / 通道件 / 观测件 已读数格数与登记格数）----"
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
    printf "去重词条=%d 类型标识词条=%d 符号词条=%d 标签词条=%d CVE 词条=%d 组件词条=%d 子词表组件=%d 限制键词条=%d\n", vrows, utiN, symN, tagN, cveN, compN, craftN, keyN
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

## 23. 三十二次实跑与全量信号覆盖验收

本章不给出任何新读数，只做一件事：**把第 21、22 章那两支脚本的输出与源码逐条对齐，并证明它们能在读者自己机器上原样复现。**四条验收标准贯穿全章：

| 号 | 标准 | 判据 | 落点 |
| --- | --- | --- | --- |
| V1 | **码数覆盖** | 两支脚本定义的每一个码（含四档判定行）都在留档里至少触发一次，且未定义码命中清单为空 | 23.4 的 C5 与 C15 |
| V2 | **只读与离线** | 二十段 grep 实证：awk 程序体内无系统调用型函数、被禁命令名只出现在注释与拒收正则里、临时目录建后即删且从不写入 | 23.1 的 P1—P20 |
| V3 | **可回指** | 每一条信号的出处都要落到归档文件行号或 usage 文本；指向本文自身的自引用要逐条列出而不是笼统承认 | 23.6 的反向对齐表 |
| V4 | **可复现** | 同一夹具重跑逐字节一致；`-q` 只关输出不关判定；退出码只由阻断条数决定 | 23.2 的 R6／R24 对照与 23.7 |

四条标准里 **V1 与 V4 是可数的，V2 是可 grep 的，V3 是可回查的**——没有一条需要读者拿设备或第三方数据来验证。这是本文把验收放在最后一章而不是第一章的原因：验收必须针对已经写完全文的脚本，而不是针对计划。

### 23.1 只读与离线性质的二十段实证（V2）

`FX/readonly-proof.sh`（96 行）是这一节的唯一证据来源。它自己也是同一类脚本：只做四件事——grep 两支脚本的源码、各跑一遍夹具、检查临时目录残留、把两次运行留档里的命令行归一化；不联网、不访问设备、不修改任何输入，输出写 stdout 供本文逐字引用。`P1—P10` 针对脚本一，`P11—P20` 针对脚本二，两半结构完全对称。

```bash
@@ROSH@@
```

下面是它在本文归档上跑出的**全量输出**（`FX/readonly-proof.txt`，145 行，逐字照抄，未删行）：

```console
@@ROOUT@@
```

二十段逐段结论：

| 段 | 一句话结论 | 若失效说明什么 |
| --- | --- | --- |
| P1 | 脚本一的 awk 程序体里没有 `system()`、没有 `getline < 文件`、没有 `popen()`／`close()`，也没有 `cmd `／`exec ` 形态的命令拼装（空匹配，退出码 1） | 有匹配即脚本能起外部进程，只读声明作废 |
| P2 | 全文只有第 52 行一处 `mktemp -d`，前缀 `pcl.XXXXXX`；另外两次命中是第 9 行头部注释与第 40 行 usage 的自述 | 出现第二处目录创建即写出目标不止一个 |
| P3 | `TMPD` 只出现在赋值（52）与 `trap`（53）两行，正文没有任何 `> "$TMPD"` 写入 | 出现第三处即脚本往临时目录写了东西 |
| P4 | 十六个设备侧工具名里，九个只命中头部拒收声明那一行（第 8 行） | 命中行号一旦落到 `BEGIN` 段或判定段，就是命令入口 |
| P4b | `file`／`log` 两个与正文用词重叠的名字整词命中三行（第 8、121、158 行），逐行看分别是注释、`adv.object_word_in_impact` 枚举与 `DOC["B04"]` 的公告读数引用 | 这三行都是数据不是命令；本段的存在是为了让读者自己确认 P4 的空白不是漏扫 |
| P4c | 同一条命令位置规则的**阳性对照**：`log show --last 1h` 与 `mdls -name kMDItemContentType` 两条样例命中数 = 2 | 若为 0，说明 P4d 的空匹配是规则失效而不是脚本干净 |
| P4d | 用该规则扫脚本一全文：被禁工具名出现在命令位置的行 = **空匹配**（退出码 1） | 有任何一行即脚本在命令位上调用了设备工具 |
| P5 | 网络与外部程序调用词（`curl`／`wget`／`nc`／`ssh`／`git`／`python`／`node`／`osascript` 等十六个）在脚本一里空匹配 | 有匹配即存在联网或解释器执行路径 |
| P6 | 脚本一实际调用的外部命令普查结果：`awk=1 cat=1 mktemp=3 rm=1`；`perl`／`python`／`node` 计数为 0 因此不显示 | 出现第二个数据处理解释器即「只用 awk 做判定」这条不成立 |
| P7 | `bash -n` 通过（无输出） | 语法不过即整个留档不可信 |
| P8 | 合格夹具跑一次后 `pcl.*` 匹配为空：**无残留** | 有残留即 `trap` 未生效，写出目标不止 stdout／stderr |
| P9 | 运行留档的 harness（`FX/run-all.sh`）里没有任何 URL 或 `/dev/` 设备节点路径 | 有即整批实跑不是离线产生 |
| P10 | 十八次实跑的命令行归一化后只剩六种形状，全部是「脚本 + 可选 `-q` 或 `-h` + 一至三份夹具」；最多的一份输入三份文件 | 出现任何其它形状说明实跑做过本文没写的事 |
| P11—P20 | 与 P1—P10 同构，作用在脚本二上：`pct.XXXXXX`（第 99 行）与 `trap`（第 100 行）；`mktemp=2 rm=1 awk=1 cat=1`；十四次实跑归一化后只剩五种形状，全部是三份夹具的排列 | 同上一条对读 |
| P14 | 脚本二的十六个工具名命中两行：第 14 行的头部拒收声明与**第 436 行的拒收正则**——后者是 `K02` 的执行点，把「把命令行工具名登记成来源」当错误登记拦下 | 第 436 行若落在命令位而不是正则字面量里，就是执行点 |
| P14c | `file`／`log` 整词命中四行（第 14、120、214、436 行）：注释、`devPath()` 形态判断、`DOC["S03"]` 出处、拒收正则 | 四处都是数据或声明 |

三处需要如实说明的细节：

1. **P4b 只列三行，而脚本一源码里 `file` 出现在四处**（第 8、121、158、198 行）。差异是 `LC_ALL=C` 造成的字节级词边界判定：第 198 行那处写作 `file、platform`，紧跟全角顿号，在 `C` 语言环境下不构成整词命中。本文把留档原样照抄（该 harness 第 8 行显式 `LC_ALL=C; export LC_ALL`），并在此处点明差异，而不是改留档去凑第 21.5 节那句话。
2. **P6 与 P16 的普查词表是固定的 17 个**（`awk sed grep tr cut sort uniq wc cat head tail mktemp rm date perl python node`），计数为 0 的名字不显示。因此这两段的正确读法是「只显示出来的那几个才是实际调用点」，而不是「未显示即未检测」。`perl` 只出现在 `FX/` 的派生器与验收件里，**两支脚本本体一次都没有**。
3. **P10 与 P20 归一化掉了文件名**，只保留形状。这是刻意的：留档的价值在于「跑过什么类型的输入」，具体哪个夹具在 23.2 的逐次表里逐行给出，两者互为索引。

### 23.2 三十二次实跑逐次读数（V4 的一半）

十八次跑脚本一（`FX/run-log.txt`，4,155 行，18 个 `===== RUN:` 段），十四次跑脚本二（`FX/run-log-tri.txt`，2,215 行，14 段）。下表每一次的四个数字都取自该段末尾的汇总行，退出码取自该段的 `$ exit=` 行。

**脚本一（R1—R18）**

| 号 | 夹具 | 对象数 | 信号行数 | 不同码 | 阻断条数 | J1／J2／J3／J4 | 退出码 | 这次证明什么 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| R1 | `ledger-18-bad.txt` | 63 | 1,055 | **71** | 736 | 0／0／0／63 | 1 | 单个畸形夹具就能把 71 个码各触发至少一次 |
| R2 | `ledger-18-good.txt` | 3 | 0 | 0 | 0 | 3／0／0／0 | 0 | 下界：零信号、全 J1、退出码 0 |
| R3 | `ledger-18-mid.txt` | 2 | 4 | 3 | 0 | 0／1／1／0 | **0** | J2 与 J3 同现且退出码仍为 0：非阻断信号不改退出码 |
| R4 | good + mid + bad 三份同输入 | 68 | 1,059 | **71** | 736 | 3／1／1／63 | 1 | 多文件合并读入，71 码再次全覆盖 |
| R5 | good 传两遍 | 3 | 216 | 1 | 216 | 0／0／0／3 | 1 | 同字段重复登记 = `S03`×216，整批落 J4 |
| R6 | `-q ledger-18-bad.txt` | 63 | 1,055 | **71** | 736 | 0／0／0／63 | 1 | 与 R1 逐字段全等：`-q` 只关 stdout 那 63 行判定 |
| R7 | `-h` | — | — | — | — | — | 0 | 帮助是输出开关之外的唯一开关，退出码 0 |
| R8 | 无参数 | — | — | — | — | — | 2 | 参数校验的下界 |
| R9 | `does-not-exist.txt` | — | — | — | — | — | 2 | 文件不存在同样是 2，不是 1 |
| R10 | 空文件 | 0 | 0 | 0 | 0 | 0／0／0／0 | 0 | 零对象不报错：没有登记就没有可判的东西 |
| R11 | 只有注释与空行 | 0 | 0 | 0 | 0 | 0／0／0／0 | 0 | 注释与空行忽略是实现的而不是约定的例外 |
| R12 | 行格式畸形六种 | 4 | 69 | 10 | 53 | 0／0／0／4 | 1 | S 族单族覆盖测试（缺列／多列／无命名空间／CRLF／`sec.*`／空标识） |
| R13 | 未知命名空间与未登记字段 | 1 | 20 | 7 | 16 | 0／0／0／1 | 1 | `S04`／`S05` 的边界：命名空间清单与字段清单是两层不同的检查 |
| R14 | 取值形态越界十三处 | 1 | 26 | 13 | 15 | 0／0／0／1 | 1 | 一次夹具同时喂出 `S07` 与 `B08`／`A03`／`A06`／`R02`／`R06`／`G05`／`X02` 等形态码 |
| R15 | 重复登记与同字段双值 | 1 | 16 | 6 | 12 | 0／0／0／1 | 1 | `S03` 的两条路径：完全相同与取值不同 |
| R16 | 拒收形态取值五处 | 1 | 20 | 8 | 16 | 0／0／0／1 | 1 | K 族全覆盖：设备路径、正文形状、私钥头、崩溃描述、Base64 载荷 |
| R17 | 只登记一行 | 1 | 15 | 5 | 11 | 0／0／0／1 | 1 | 必备格缺失的算术：缺 11 格 → `S09`，`J4` |
| R18 | `not_determinable` 与 `absent` 对照 | 1 | 0 | 0 | 0 | 1／0／0／0 | 0 | **合法一侧的反面对照**：四格写哨兵值既不算缺失也不算拒收 |

**脚本二（R19—R32）**

| 号 | 清单 | 能力表 | 词表 | 对象数 | 信号行数 | 不同码 | 阻断条数 | Q1／Q2／Q3／Q4 | 退出码 | 这次证明什么 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| R19 | `tri-18-bad.txt` | 干净 | 干净 | 32 | 397 | 54 | 93 | 0／20／9／2 | 1 | 清单畸形一侧的全量触发 |
| R20 | `tri-18-good.txt` | 干净 | 干净 | 4 | 0 | 0 | 0 | 4／0／0／0 | 0 | 下界：三段齐备、全 Q1 |
| R21 | `tri-18-mid.txt` | 干净 | 干净 | 3 | 9 | 5 | 1 | 0／1／1／1 | 1 | 四档里的三档同现（缺 Q1） |
| R22 | bad | **畸形件** | 干净 | 32 | 110 | 35 | 48 | 0／8／5／**18** | 1 | 能力表退化 → 18 个对象整批落 Q4（`能力表行=4`） |
| R23 | bad | 干净 | **畸形件** | 32 | 409 | 49 | 105 | 0／24／5／2 | 1 | 词表退化：`词表词条=1`，`X08` 首现在此跑 |
| R24 | `-q` + bad | 干净 | 干净 | 32 | 397 | 54 | 93 | 0／20／9／2 | 1 | 与 R19 五个数全等：`-q` 不改判定 |
| R25 | `-h` | — | — | — | — | — | — | — | 0 | 帮助退出码 0 |
| R26 | 无参数 | — | — | — | — | — | — | — | 2 | 参数校验 |
| R27 | 只给清单一份 | — | — | — | — | — | — | — | 2 | 「恰好三份」这条硬约束的实证 |
| R28 | 清单不存在 | — | — | — | — | — | — | — | 2 | 三份输入任一份缺失都是 2 |
| R29 | good | **空壳** | **空壳** | 4 | 2 | 2 | 2 | 0／0／0／**4** | 1 | `C05`＋`X08` 两条「整表无有效行」同时命中，四个对象整批 Q4 |
| R30 | **空清单** | 干净 | 干净 | 0 | 20 | 1 | 0 | 0／0／0／0 | **0** | 零对象：整张清单没有一行登记，20 项核对项全部落 `D05`；这一族非阻断，所以退出码 0 |
| R31 | 单行清单 | 干净 | 干净 | 1 | 31 | 4 | 1 | 0／1／0／0 | 1 | 只登记一项：`D05`×19（其余核对项整表零登记）＋ `D02`×10（该类 11 个 required 项里 10 个无行）＋ `T01`（三件只出现声明件）＋ `T08`（唯一阻断） |
| R32 | good | **同一份** | **同一份** | 4 | 96 | 3 | 96 | 0／0／0／**4** | 1 | 三份输入指向同一文件：`核对项登记行=141`（47×3）、`能力表行=0`、`词表词条=0`，于是 `S08`×94 ＋ `C05` ＋ `X08` 同框，四个对象整批 Q4 |

**退出码算术**：脚本一 6 个 0、10 个 1、2 个 2，共 18；脚本二 3 个 0、8 个 1、3 个 2，共 14；合计 32 次，与两个留档里 `===== RUN:` 段数（`grep -c` 分别为 18 与 14）逐项相等。这三种退出码的分布本身就是验收项——只出现 0 和 1 说明输入校验没被跑到，只出现 1 说明下界没被证明。

**三个「零」各自证明不同的事**，放在一起看最容易误读：

- R2 与 R20 的 `信号行数=0` 证明**存在**一条能通过两套模型的登记，这是下界；
- R10、R11、R30 的 `对象数=0` 或零阻断证明**空输入不是错误**：没有登记就没有可判的东西，脚本不因此报错；
- R29 与 R32 的 `能力表行=0` 或 `词表词条=0` 证明**退化输入必须拦停**：这两个零都以 `C05`／`X08` 阻断码落 Q4 并以退出码 1 结束。

三者都叫「零」，但一个是合格、一个是无关、一个是不可用。第 21.6 与 22.6 节给的是第一种，本节给的是第三种，第 26 章的未文档化边界清单给的正是把它们区分开的那份口径。

---

### 23.3 逐码首现与累计（V1 的两张成品表）

表 1 覆盖脚本一，共 75 格：71 个信号码（A/B/C/D/E/G/K/N/O/R/S/V/X 十三族）＋ J1—J4 四行判定。「首现」列是第 23.2 节里 R1—R18 那十八次实跑中第一次出现该码的那一次，「累计」列等于第 23.4 节 C6 串里同号的那个数。

**表 1｜脚本一逐码首现与累计（75 格）**

| 码 | 首现 | 累计 | 码 | 首现 | 累计 | 码 | 首现 | 累计 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `A01` | R1 | 3 | `A02` | R1 | 3 | `A03` | R1 | 4 |
| `A04` | R1 | 3 | `A05` | R1 | 3 | `A06` | R1 | 4 |
| `B01` | R1 | 188 | `B02` | R1 | 3 | `B03` | R1 | 3 |
| `B04` | R1 | 5 | `B05` | R1 | 7 | `B06` | R1 | 6 |
| `B07` | R1 | 3 | `B08` | R1 | 12 | `C01` | R1 | 192 |
| `C02` | R1 | 3 | `C03` | R1 | 198 | `C04` | R1 | 3 |
| `C05` | R1 | 3 | `C06` | R1 | 3 | `C07` | R1 | 3 |
| `D01` | R1 | 12 | `D02` | R1 | 3 | `D03` | R1 | 3 |
| `D04` | R1 | 3 | `D05` | R1 | 3 | `D06` | R1 | 5 |
| `E01` | R1 | 3 | `E02` | R1 | 18 | `E03` | R1 | 3 |
| `E04` | R1 | 3 | `E05` | R1 | 3 | `G01` | R1 | 3 |
| `G02` | R1 | 3 | `G03` | R1 | 3 | `G04` | R1 | 3 |
| `G05` | R1 | 4 | `J1` | **R2** | 7 | `J2` | **R3** | 2 |
| `J3` | **R3** | 2 | `J4` | R1 | 138 | `K01` | R1 | 4 |
| `K02` | R1 | 6 | `K03` | R1 | 5 | `N01` | R1 | 6 |
| `N02` | R1 | 3 | `N03` | R1 | 3 | `N04` | R1 | 3 |
| `N05` | R1 | 3 | `O01` | R1 | 3 | `O02` | R1 | 194 |
| `O03` | R1 | 3 | `O04` | R1 | 3 | `R01` | R1 | 3 |
| `R02` | R1 | 4 | `R03` | R1 | 3 | `R04` | R1 | 3 |
| `R05` | R1 | 3 | `R06` | R1 | 4 | `R07` | R1 | 3 |
| `S01` | R1 | 4 | `S02` | R1 | 4 | `S03` | R1 | 221 |
| `S04` | R1 | 7 | `S05` | R1 | 5 | `S06` | R1 | 12 |
| `S07` | R1 | 7 | `S08` | R1 | 4 | `S09` | R1 | 2268 |
| `V01` | R1 | 3 | `V02` | R1 | 3 | `V03` | R1 | 3 |
| `V04` | R1 | 3 | `X01` | R1 | 21 | `X02` | R1 | 4 |

表 2 覆盖脚本二，共 64 格：60 个信号码（C/D/K/M/P/S/T/V/X 九族）＋ Q1—Q4 四行闭合等级；它的起点是 R19，所以首现列读法与表 1 相同，只是 R 号落在另一份留档里。

**表 2｜脚本二逐码首现与累计（64 格）**

| 码 | 首现 | 累计 | 码 | 首现 | 累计 | 码 | 首现 | 累计 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `C01` | **R22** | 1 | `C02` | **R22** | 1 | `C03` | **R22** | 1 |
| `C04` | **R22** | 1 | `C05` | **R22** | 5 | `D01` | R19 | 7 |
| `D02` | R19 | 790 | `D03` | R19 | 12 | `D04` | R19 | 25 |
| `D05` | R19 | 52 | `K01` | R19 | 4 | `K02` | R19 | 3 |
| `K03` | R19 | 4 | `K04` | R19 | 3 | `K05` | R19 | 3 |
| `M01` | R19 | 8 | `M02` | R19 | 3 | `M03` | R19 | 3 |
| `M04` | R19 | 3 | `M05` | R19 | 3 | `M06` | R19 | 15 |
| `P01` | R19 | 3 | `P02` | R19 | 3 | `P03` | R19 | 3 |
| `P04` | R19 | 3 | `P05` | R19 | 7 | `P06` | R19 | 6 |
| `P07` | R19 | 6 | `Q1` | **R20** | 4 | `Q2` | R19 | 54 |
| `Q3` | R19 | 20 | `Q4` | R19 | 31 | `S01` | R19 | 4 |
| `S02` | R19 | 4 | `S03` | R19 | 4 | `S04` | R19 | 4 |
| `S05` | R19 | 4 | `S06` | R19 | 4 | `S07` | R19 | 16 |
| `S08` | R19 | 122 | `S09` | R19 | 20 | `S10` | R19 | 4 |
| `T01` | R19 | 58 | `T02` | R19 | 40 | `T03` | R19 | 3 |
| `T04` | R19 | 4 | `T05` | R19 | 4 | `T06` | R19 | 4 |
| `T07` | R19 | 4 | `T08` | R19 | 45 | `V01` | R19 | 7 |
| `V02` | R19 | 70 | `V03` | R19 | 3 | `V04` | R19 | 3 |
| `V05` | R19 | 4 | `V06` | R19 | 3 | `X01` | R19 | 6 |
| `X02` | R19 | 2 | `X03` | R19 | 2 | `X04` | R19 | 2 |
| `X05` | R19 | 11 | `X06` | R19 | 18 | `X07` | R19 | 8 |
| `X08` | **R23** | 6 |  | |  |  | |  |

两表相加 75 + 64 = **139**，与文首 front matter 声明的信号码总数一致；拆开是 71 + 4 + 60 + 4。这 139 个码里有 139 个至少命中一次、0 个未触发、0 个未定义命中、0 个一号多义——这三句话各自对应一次数数，分别是 C5／C15、C3／C13 与 C10／C20，全部落在第 23.4 节。

三件读表须知，写在表旁边而不是写在脚注里，因为它们决定了这些数能拿来支持什么结论：

- **累计次数是夹具的性质，不是现实的性质。** 脚本一的 `S09`（必备格缺失）累计 2,268 次、脚本二的 `D02`（required 核对项在本对象零登记）累计 790 次，都远高于其它码，原因很朴素：这两条判据都是「逐对象逐格」计数，而 R1 与 R19 那两次畸形夹具实跑一次性给了 63 与 32 个对象、每对象缺若干格。它们说明夹具按设计覆盖了这条判据，**不能**说明现实台账里每 2,268 行缺格就会出一次信号。
- **首现列能反过来读出实跑顺序。** 表 1 里只有 `J1`（R2）、`J2` 与 `J3`（R3）三格加粗，说明脚本一的信号码全部在第一次实跑（R1，畸形夹具）里就命中过，晚出现的只有判定档；表 2 里加粗的七格分别是 `C01—C05`（R22，畸形能力表那次）、`X08`（R23，畸形词表那次）与 `Q1`（R20，干净夹具那次），说明这六族判据在 R19 那次实跑里根本不可能触发——不是漏跑，是输入退化到无法比对的程度才成立的判据。
- **两个表都只到「号—次」这一层。** 每一个号讲什么、归哪一族、阻断还是非阻断、出处落在哪份归档，是第 21.3 与 22.3 节的内容；这两张表不重复那些语义，只把「覆盖过了没有」这一件事钉死。

### 23.4 全量信号覆盖的二十二项读数（V1）

`FX/coverage-proof.txt`（137 行，`C1—C22`）是这一节的唯一证据来源：它把两支脚本的源码与两份运行留档做二十二次数数，每一段都带原命令与退出码，读者可以逐段抄回自己的终端再跑一遍。下面是它的**全量输出**（逐字照抄，未删行）：

```console
@@COVOUT@@
```

二十二项读数各自的判据与「若失效说明什么」：

| 项 | 读数 | 判据 | 若失效说明什么 |
| --- | --- | --- | --- |
| C1／C11 | 71／64 | 源码里 `emit("XX"` 的调用点去重计数 | 少一个即有一个码写了出处却没有任何判定会产出它 |
| C2／C12 | 71／64 | 源码里 `DOC["XX"]` 的赋值去重计数 | 与上一项不等即脚本自身不一致：有码无出处，或有出处无码 |
| C3／C13 | 空集 | 两个集合的 `comm -3` 差集 | 任何一行都是「定义了却没写出处」或反过来的实锤 |
| C4／C14 | 18 次／4,155 行；14 次／2,215 行 | 留档里 `===== RUN` 段数与总行数 | 段数不等于第 23.2 节的 R 号计数即留档被增删过 |
| C5／C15 | 定义 71 命中 71／定义 64 命中 64，两个清单都空 | `FX/code-coverage.pl`（29 行） | 「未触发清单」非空即 V1 不成立；「未定义命中」非空即留档里有源码没写的码 |
| C6／C16 | 逐号次数一行一串 | 从留档按第一列制表符切分后 `uniq -c` | 这一串是第 23.3 节两张表的「累计」列的唯一来源 |
| C7／C17 | 最少的号 3 次／1 次 | 同一串按次数升序取头五个 | 出现 0 即 C5／C15 数错了；脚本一最低 3、脚本二最低 1（`C01—C04` 只在畸形能力表那一次实跑里各命中一次） |
| C8／C18 | 九种／八种判定分布 | 留档里 `判定分布` 与 `闭合等级` 两行去重 | 四档里有一档从未出现，第 19 章那套模型就没被证明可达 |
| C9／C19 | 6／10／2 与 3／8／3 | 留档里 `$ exit=` 行的分布 | 三种退出码缺一种即对应那条路径没跑到 |
| C10／C20 | 71 号＝69 一号一判据＋1 形态族＋1 参数化＋0 多义；64 号＝64 一号一判据 | `FX/code-uniqueness.pl`（33 行） | 「一号多义」非 0 即同一个码在两份判定里说两件不同的事，第 23.3 节的表就不可能被读出唯一含义 |
| C21／C22 | 表内格 75／64，脚本定义码 75／64，不一致 0，表内未出现的码为空 | `FX/tbl-check.pl`（56 行） | 任何一格的首现 R 号、累计次数或加粗标记与留档不符都在这里报出 |

### 23.5 三个校验器各数什么

上面那些数字要能被读者复算，先得说清三个助手各自剔掉了什么。三处规则不说明白，这些数字就容易被误读成「脚本自己数自己」：

1. **留档里两种「不是信号的行」必须被同一种口径剔掉。** 除了逐条信号行，留档末尾还有脚本自己按码打印的计数行（第一列是码、第二列是纯数字，用制表符分隔），以及判定行（第一列是 J 码、第二列是对象标识）。三套工具各剔各的那一半：`tbl-check.pl` 用「第二列是纯数字就跳过」把计数行剔掉，因此表里的「累计」只数真信号行；`code-coverage.pl` 用 `verdict = "XX"` 建判定位集合、把 J 码从命中集合里剔除，它对计数行不做处理，但这类行第一列的码早已由真信号行命中，集合去重之后不影响结果；`C6` 那条 shell 命令用 `grep -vE "^J[1-4][[:space:]]"` 与 `grep -vE "^[A-Z][0-9]+[[:space:]]+[0-9]+[[:space:]]*$"` 两个过滤器把两种行一起剔掉，`C16` 那条只用后一个——因为脚本二的 Q 码本来就是被统计的信号码。两条命令与两个 perl 助手口径一致，才是「表 1 的累计列与留档现场重数逐号相等」这句结论的前提。
2. **判定行的计入方式在两支脚本里不同，而且这是源码结构决定的。** 脚本一里 J1—J4 由 `verdict = "J1"` 这类赋值产生、不经过 `emit()`，所以 `C1=71` 不含判定行，表 1 的 75 格是 71 个信号码外加四行判定；脚本二里 Q1—Q4 就写 `emit("Q1", …)`（第 523—526 行），所以 `C11=64` 已含判定行，表 2 的 64 格是 60 个信号码加四行等级。`code-coverage.pl` 用 `verdict = "XX"` 建判定位集合并把它们从命中里剔除，因此脚本二的 Q 码留在命中集合里、脚本一的 J 码本就不在定义集合里——这正是第 19 章讲的「Q 档不进阻断计数、J 档进」在验收工具上的投影。
3. **加粗也是被校验的对象。** `tbl-check.pl` 里 `want_b = (首现 R 号 ≠ 起始 R 号)`：表 1 以 R1 为起点、表 2 以 R19 为起点，凡是首现晚于起点的格子必须加粗，加粗错了同样计入「不一致」。所以 C21／C22 报的「不一致 0」同时管住了数字和排版。

### 23.6 静态反向对齐（V3）：每一条信号的出处都能回到文件与行号

第 21、22 章各给过一张族表，那是「族 → 码」方向。本节做反方向：**码 → 出处**，即把两支脚本里 `DOC[]` 数组的 75 条与 64 条出处逐条归类，看它们落在哪些归档文件上。

**按族落到哪些归档（脚本一，十三个族里 11 个有归档引用；K 族三条与 X 族两条没有）**

| 族 | 归档 |
| --- | --- |
| A 声明与来源 | `A/imageio.txt`、`A/uikit_uidocument.txt`、`A/uniformtypeidentifiers_defining_file_and_data_types_for_your_app.txt`、`A/uniformtypeidentifiers_system_declared_uniform_type_identifiers.txt`、`A/webkit_wkwebview.txt` |
| B 形态与换算 | `A/imageio.txt`、`A/quicklook_qlpreviewcontroller.txt`、`A/uniformtypeidentifiers_defining_file_and_data_types_for_your_app.txt`、`A/uniformtypeidentifiers_system_declared_uniform_type_identifiers.txt`、`C/readings-18.txt` |
| C 解析装配 | `A/coregraphics.txt`、`B/apple-platform-security-guide.txt`、`C/readings-18.txt` |
| D 通道与平面 | `B/apple-platform-security-guide.txt` |
| E 告知与呈现 | `A/quicklook.txt`、`A/uikit_uidocument.txt`、`B/apple-platform-security-guide.txt`、`C/readings-18.txt` |
| G 执行域 | `B/apple-platform-security-guide.txt`、`B/mdm-restriction-keys.txt`、`C/readings-18.txt` |
| N 通知与外发 | `A/uikit_uiactivityviewcontroller.txt`、`A/webkit.txt`、`B/apple-platform-security-guide.txt`、`C/readings-18.txt` |
| O 对象类 | `B/apple-platform-security-guide.txt`、`C/readings-18.txt` |
| R 公告与修复 | `B/apple-platform-security-guide.txt`、`C/advisory-18.tsv`、`C/kev-apple.tsv`、`C/readings-18.txt` |
| S 结构 | `C/kev-apple.tsv`（只有 `S08` 一条落到归档，其余八条指向 usage） |
| V 回指 | `A/imageio.txt`、`A/uikit_uidocument.txt`、`B/apple-platform-security-guide.txt`、`C/readings-18.txt` |

**按族落到哪些归档（脚本二，10 个族全部有归档引用）**

| 族 | 归档 |
| --- | --- |
| C 三件能力表 | `A/uniformtypeidentifiers_defining_…txt`、`A/uniformtypeidentifiers_system_declared_…txt` |
| D 差集 | `A/uniformtypeidentifiers.txt`、`A/uniformtypeidentifiers_defining_…txt`、`A/uniformtypeidentifiers_system_declared_…txt`、`C/readings-18.txt` |
| K 拒收 | `A/uniformtypeidentifiers_defining_…txt`、`B/apple-platform-security-guide.txt` |
| M 崩溃与诊断 | `A/uniformtypeidentifiers.txt`、`A/uniformtypeidentifiers_defining_…txt`、`A/uniformtypeidentifiers_system_declared_…txt`、`C/advisory-18.tsv`、`C/kev-apple.tsv` |
| P 平面 | `A/imageio.txt`、`A/quicklook.txt`、`A/quicklook_qlpreviewcontroller.txt`、`A/uniformtypeidentifiers_system_declared_…txt`、`A/webkit.txt`、`B/mdm-restrictions.txt`、`C/advisory-18.tsv`、`C/readings-18.txt` |
| Q 闭合等级 | `A/quicklook.txt`、`A/uniformtypeidentifiers.txt`、`A/uniformtypeidentifiers_defining_…txt`、`C/readings-18.txt`、`C/subset-18.txt` |
| S 行结构 | `A/uniformtypeidentifiers.txt`、`A/uniformtypeidentifiers_defining_…txt`、`A/uniformtypeidentifiers_system_declared_…txt`、`C/readings-18.txt`、`C/subset-18.txt` |
| T 三件对齐 | `A/quicklook.txt`、`A/uniformtypeidentifiers.txt`、`A/uniformtypeidentifiers_defining_…txt`、`B/mdm-restriction-keys.txt`、`C/advisory-18.tsv` |
| V 回指与对外 | `A/quicklook.txt`、`A/quicklook_qlpreviewcontroller.txt`、`A/uniformtypeidentifiers_defining_…txt`、`A/uniformtypeidentifiers_system_declared_…txt`、`B/mdm-restriction-keys.txt`、`C/advisory-18.tsv` |
| X 公开词表 | `A/uniformtypeidentifiers.txt`、`A/uniformtypeidentifiers_defining_…txt`、`A/uniformtypeidentifiers_system_declared_…txt`、`B/mdm-restriction-keys.txt`、`C/advisory-18.tsv`、`C/readings-18.txt`、`C/subset-18.txt` |

汇总成可核对的四个数：

| 脚本 | 出处条数 | 落到归档的条数 | 归档引用处数 | 不同归档 |
| --- | --- | --- | --- | --- |
| 脚本一 | 71 | 56 | 56（每条恰一处） | 15 |
| 脚本二 | 64 | 58 | 75（42 条一处、15 条并列两处、`P05` 一条三处） | 14 |

**剩下的 15 条与 6 条不是没写出处，而是出处指向本文或 usage 文本。** 这是本节唯一必须逐条列出来的部分，因为「脚本自证」正是这类验收最容易被含混过去的地方。脚本一的十五条：

| 码 | 出处原文（逐字） | 指向 |
| --- | --- | --- |
| `S01` | 见 usage 文本的行格式（一行只登记一条对象的字段，列数固定为三） | usage |
| `S02` | 见 usage 文本的行格式（对象标识是行的第一列，缺失时无法判断这行属于哪条解析链） | usage |
| `S03` | 见 usage 文本（同一对象的同一字段只能有一个取值，重复登记会让后值静默覆盖前值） | usage |
| `S04` | 见 usage 文本的十二个命名空间清单（命名空间是字段归属判断层的唯一依据） | usage |
| `S05` | 见 usage 文本的字段清单（清单外的字段名不会被任何判定读取） | usage |
| `S06` | 见 usage 文本（值里不能含逗号；留空等同没有登记这一格） | usage |
| `S07` | 见 usage 文本的枚举字段与布尔位（枚举值必须由登记方选定，不接受自由文本） | usage |
| `S09` | 见 usage 文本的必备格清单 | usage |
| `X02` | 见 usage 文本（行号引用只写 `1234` 或 `6-9` 这一种形态，带「第／行」前缀的写法在两份台账之间不可换算） | usage |
| `K01` | 见本脚本头部注释的拒收声明 | 脚本自身注释（第 8 行） |
| `K02` | 见本脚本头部注释：文件正文、设备路径、密钥串与超长载荷一律拒收 | 脚本自身注释（第 8 行） |
| `A06` | 见本文第 6.3 节失败点（团队标识在公开口径里是 10 位字母数字串；登记成别的形状说明这一格不是从公开材料抄来的） | 本文 |
| `N04` | 见本文第 3.4 节失败点 6（截屏与厂商说法不能充当机制依据） | 本文 |
| `X01` | 见本文第 3.4 节失败点 8（口径之间不能直接换算，结论必须回到文件与行号） | 本文 |
| `K03` | 见本文第 12 章（崩溃引用只登记报告标识，不粘贴堆栈正文） | 本文 |

脚本二的六条：`S01`、`S02`、`C01` 三条指向 usage 文本（分别是三件清单行格式、对象标识、能力表行格式），`K01`、`M04`、`P07` 三条指向本文（第 3.4 节失败点 8 与第 12 章的两处约定）。

这个差别本身就是一条结论：**usage 族的自引用两份都有，因为行格式、字段清单这类判据的权威只能写在脚本自己身上；归档族的引用比例脚本二更高（58/64 对 56/71），因为它的判据几乎全部围绕公开类型声明文档的三件差集展开，而脚本一里 S／K 两族十个码守的是台账自身的可解析性。** 谁也不比谁更「外部」——但读者应该能一眼看出哪几条是脚本自己定的规矩。

反向对齐的两个限制必须同时说清：

- **方向只有一边。** 上面证的是「每条信号都有出处」，不是「每份归档都被引用」。归档目录里 20 份 `.txt`／`.tsv` 材料中，被引用的是 18 份；`A/uikit_uiapplicationdelegate_application(__open_options_).txt` 与 `C/kev-apple.tsv.meta.txt` 没有落在任何一条 `DOC[]` 上——前者是本文第 11 章讨论打开动作时用的材料，后者是 KEV 抓取的元信息说明，两者都不是任何一条判据的依据。`C/readings-18.err` 与 `C/subset-18.err` 是抓取时的 stderr 留档，按设计不作为引用目标。
- **行号属于快照，不属于网址。** 所有 `第 N 行` 指的是本文随附归档那份纯文本的行号，即第 28 章资料表里标注视作日期抓取的版本；同一份文档换一次抓取，行号会变。这也是 `X01`／`X02` 两条判据要求台账里「行号引用只写一种形态」的原因：两份台账之间不可换算的写法，最后连验收也做不了。

### 23.7 重跑一致性（V4）

三组对照，都不需要新数据。

1. **验收 harness 自身可重跑。** `bash FX/readonly-proof.sh` 重跑一次、与留档 `FX/readonly-proof.txt` 逐字节比对：**145 行完全一致**（两边 MD5 同为 `a8dd3344d1224eeab22d8b10d48c6ddb`），退出码 0；重跑后临时目录里 `pcl.*` 与 `pct.*` 匹配数为 0，即第 23.1 节 P8 那条「建后即删」不是留档里的一次侥幸。
2. **脚本一的 `-q` 只关输出，不关判定。** R1 与 R6 传同一份 `FX/ledger-18-bad.txt`，差别恰好只有 63 行：R1 有 63 条 `J1—J4` 判定行、R6 一条都没有（源码第 346 行那个 `if (!QUIET)` 包住的就是这段），而三次汇总行逐字相同（`解析链对象数=63 信号行数=1055 判定行数=63`／`不同信号码=71 阻断信号条数=736`／`判定分布 J1=0 J2=0 J3=0 J4=63`），末尾按码计数那 71 行两边**逐字节相同**（MD5 `d7931e751f4bc1ce292634f23e972f6e`），退出码同为 1。
3. **脚本二同理，关掉的是三块输出。** R19 与 R24 传同样三份夹具，行数差 525 − 459 = 66，正好是 31 条 `Q` 等级行＋差集矩阵 33 行（表头 1 行 + 32 个对象）＋公开词表读数 2 行（表头 + 读数行）；三次汇总行逐字相同（`三件对象数=32 … 信号行数=397`／`不同信号码=54 阻断信号条数=93`／`闭合等级 Q1=0 Q2=20 Q3=9 Q4=2`），按码计数的 54 行数量一致，退出码同为 1。

这组对照里还露出一处边界，值得记下来：**R19 报 `三件对象数=32`，等级行只有 31 条。** 缺的那条是 `IMG_B3`——它唯一的一行把核对项写成了 `not_an_item`，被 `S04` 判掉之后这个对象再没有任何合法登记，于是它照常出现在差集矩阵里（`声明件=0 通道件=0 观测件=0`、`required=0 已读数=0 缺:（无）`），却不落任何闭合等级。「有对象、无判定」是第 23.2 节那三种零之外的第四种，本文把它归入第 26 章的未文档化边界清单，而不是回头改脚本让数字好看。

### 23.8 本章没有证明什么

四条验收标准管住的是**脚本与留档之间的关系**，管不住下面这几件事，写在最后一章末尾比藏在开头更有用：

- 没有证明任何判据在现实设备上会发生。所有数字都产自本文自己写的合成夹具；第 16 章那十一组公开读数证明的是「公开文档这么说」，不是「某台 iPhone 上量到了」。
- 没有证明 139 个码划得对。`code-uniqueness.pl` 查的是同一个码不说两件事，`tbl-check.pl` 查的是表与留档一致；一条判据该不该存在、该归阻断还是非阻断，是第 19 章的论证问题，不是本章的数数问题。
- 没有证明覆盖是均衡的。累计列最高与最低差三个数量级，这由夹具规模和逐格计数方式决定，读表时不能把「命中多」当「更重要」。
- 没有做设备侧、联网侧或真实文件的核验，也刻意不做：脚本第 21.1／22.1 节的只读声明一旦要核验「是否真的只读」，就只能靠 grep 源码与普查外部命令（P1—P6、P11—P16），而不是靠把脚本拿去跑真文件。
- 没有证明归档文本与厂商线上页面永远一致。第 28 章给了每份材料的抓取视作日期；行号失效时，失效的是这份快照，不是这条判据的逻辑。
- 没有穷尽边界。本章是被夹具逼出来的读数：`IMG_B3` 那种「有对象、无判定」的第四种零，就是重跑对照时撞上的，不在最初的写作计划里。撞到新的就记进第 26 章，而不是回头改数据或改脚本让数字好看——这是本章对「验收」二字划的界。

## 24. 十二个误区

以下十二条是把第 3—23 章的读数压回成一句话时最容易压错的形状。每条给出**误区表述 → 依据读数 → 正确表述**，依据只用本篇归档件里的行锚、第 23.2 节那三十二次实跑的留档与第 23.3 节两张表的累计数，不引入新事实。前八条与第 3.4 节那八处换算失败一一对应——这不是省事，那八处失败本来就是「两格被压成一格」的八个具体形态；后四条压的是失败点之外的四个惯性读法（触发时点、实测冲动、退出码语义、边界清单的用途）。

**误区 1：内容里写了类型声明，系统就会按这份声明判。**
依据：`A/uikit_uidocument.txt:35` 把 `UIDocument` 打开文档时的类型来源写得很直白——「the Uniform Type Identifier associated with the file extension」，先读的是**扩展名**；`A/uniformtypeidentifiers_defining_file_and_data_types_for_your_app.txt:12` 要求声明成导出或导入类型、`:14` 要求导入别人的类型时沿用同一标识，`:78` 说 `UTTypeIdentifier` 是声明文件的必需键——这一句约束的是**声明本身是否合法**，不是「系统采信它」。公开档案里唯一一处「不这样声明会怎样」的后果句是同一份文档的 `:42—46`：不 conform 到 `com.apple.package`／`public.data` 时「the system can't tell if a stored item has that type」，它说的是判不出，不是按你的判。台账侧的落点很密：脚本一 `B01`（类型三票全无，累计 188、首现 R1）、`B02`（只用扩展名当类型结论，3）、`B05`（判定依据为假定或厂商说法，7）；脚本二 `T01`（三件只登记了声明件，累计 58，R19／R21／R22／R23／R24／R31 六段都有）、`D02`（required 核对项在本对象零登记，790）。K 族五个码守的是反向动作：把 `public.`／`dyn.`／`com.apple.` 前缀登记成自己的声明（脚本二 `K03` 4、`K04` 3、`K05` 3），以及标识本身写得不合规（脚本一 `B08`，12，判据文案逐字是「声明类型标识形态非法／声明 MIME 形态非法／扩展名形态非法」三选一，出处是那份声明文档 `:16—20` 的「反向 DNS 起始、只含字母数字、破折号与点」）。
正确表述：**声明件有值只成立「内容自带一份声明」，不成立「判定采信它」。**要说「这一格被系统按声明判了」，必须通道件的 `uti_lookup`／`ext_lookup`／`mime_lookup` 与 `resolved_uti` 各有值且同行号（第 18.3 节禁令 1）。缺通道件时能说的极限是「这份内容自带一张写得合格的票」，脚本二把这种形状固定压成 `T01`，脚本一压成 `B01`／`B02`。

**误区 2：三条票源都有值，所以三票一致。**
依据：三条票源是三个独立字段。`A/uniformtypeidentifiers_defining_…txt:88` 那句「If both exported and imported declarations for a type exist, the exported declaration takes precedence」是**全篇唯一一处优先级规则**，它只解决「导出声明与导入声明冲突」这一种情形，不解决「扩展名反查与内容嗅探冲突」；组 A 的六份框架文档里没有任何一处给出「扩展名与内容不一致时听谁的」的仲裁口径（第 3.2 节结论句）。所以三票全有值仍可能三票各异。实测侧：脚本一 `B03`（嗅得类型与声明类型不同却记为无冲突，累计 3、首现 R1）、`B04`（类型冲突未解却给确认结论，5，除 R1／R4／R6 外还在 R3 的中档夹具里出现）、`B07`（解析器选择不可判定却给确认结论，3）；脚本二 `T06`（反查回来的类型与声明不同且不在一致性链上，4）、`T05`（同一对象把类型标识同时登记为导出与导入，4）、`S09`（同一核对项出现两种登记口径，累计 20，在 R19／R22／R23／R24 四段各 5 条，与 `T05`／`T06` 同属阻断族）。
正确表述：**三票齐全是登记完整度的读数，不是判定一致的读数。**冲突必须在 `typ.type_conflict` 里显式取值，且取值不是 `none` 时不得给 `confirmed` 结论——这正是 `B04` 的判据形状。一致性链能解释一部分关系（`:8—20` 的派生链），但「反查结果落在链上」与「反查结果等于声明」是两格，脚本二用 `T06` 分开拦。

**误区 3：内容被判成某类型，所以这一格的后果能被说出来。**
依据：`C/readings-18.txt:25—30` 给了公告影响句的五类后果词形——`unexpected app termination` 133 行、`disclosure of` 84 行、`bypass` 78 行、`memory corruption` 77 行、`arbitrary code execution` 58 行；把这五类与「类型被误判」「内容被自动解析」这类措辞放在一起扫，**后者命中 0 行**。也就是说判定与后果之间在公开档案里是断开的，公告侧说不出「判错类型」这件事本身。台账侧：脚本一 `X01`（确认结论缺来源文件或行号，累计 21、首现 R1）、`O03`（只靠厂商自述平面给出确认结论，3）；脚本二 `V01`（本对象 required 核对项的引用格全为无标识，7）、`V02`（引用格既不是公开词表值也不是文档行号形态，累计 70）、`V04`（已读数但未登记这一格是否会对外，3，非阻断）。
正确表述：**「判成什么」与「后果是什么」分属两件，跨件结论必须两侧各给行号。**写成「会被误判为图像」这类句子时，能引的只有声明侧与通道侧的映射句（`A/uniformtypeidentifiers_system_declared_…txt:8—19`），后果侧一句都没有——所以这类句子最多说到「这一格判据不足」，不能说到「会造成什么」。第 20 章 O3（结论可回指率）就是这条的机器化落点，口径为必须等于 1。

**误区 4：公告组件列写了 ImageIO，所以影响句说的是解析；反过来说，影响句没提解析词，就表示这批条目与解析面无关。**
依据：这是本篇的中心读数，两个方向都错。`C/readings-18.txt:54—59`：影响句写明恶意构造对象、组件名却不含任何解析层词形的有 **46 行**，其中 `image` 16 行、`file` 19 行、`web content` 与 `font` 各 0 行；反过来 `C/subset-18.txt:8—9` 列出 11 个组件（APFS／Calendar／CoreServicesUIAgent／CoreStorage／CoreSymbolication／GPUTools／Grapher／HFS／HomeKit／Mail／OpenBSM）在「含恶意构造对象」子集里，组件名却不指向任何解析层。两列互不校验，按任一列筛都会漏。台账侧：脚本一 `R03`（组件名不属于解析层却用它给确认结论，累计 3、首现 R1）、`R05`（对象词为 image 但组件名与之无关且未核对，3）、`R01`（登记了 impact 对象词却没有组件名，3）；脚本二 `X01`（引用的公告组件只在子词表里或归一化后不在全量词表内，累计 6）、`X02`（在全量词表里但不含恶意构造行，却把解析类归属对外表述为是，累计 2）、`X03`（引用的 CVE 不在公告与 KEV 的 CVE 词表内，2）、`X04`（引用的限制键不在公开键清单内，2）——这四个码只在 R19 与 R24 两段打印过，是同一份畸形清单的两种调用形状。
正确表述：**解析面的存在性由组件列承载，解析面的后果由影响句承载，两列各说各话是这份档案的性质而不是缺陷。**`C/readings-18.txt:54—59` 那 46 行本身不是问题，问题只发生在把它写成个体结论时（第 20 章 O4 的分子就是这个误用率）。跨列引用必须同时给出组件名与影响句的行号，并按第 18.3 节禁令 3 处理；把组件名当作「这条 CVE 影响某个解析器」的证据，脚本一按 `R03` 阻断。

**误区 5：某个框架能读这类格式，所以这一面就能给出结论。**
依据：Quick Look 的两份文档**不同形**。`A/quicklook.txt:7—13` 取到 7 项（iWork 与 Office／Images／Live Photos／Text files／PDFs／Audio and video／USDZ），`A/quicklook_qlpreviewcontroller.txt:12—21` 取到 10 项（iWork／Office／RTF／PDF／Images／Text files（要 conform 某 UTI）／CSV／USDZ 3D）；共有词形 8 个，只在总览出现的 `audio`／`live photo`／`video`，只在类文档出现的 `csv`／`rtf`（逐行对照见 `C/subset-18.txt:19—42`）。两份各自还带一句「The list of supported common file types may change between operating system releases」（总览 `:18`、类文档 `:22`）。**引用其中任一份都不构成闭合。**台账侧：脚本一 `B06`（解析对象已知但解析器选择未登记，累计 6、首现 R1）、`A05`（解析层为网页引擎但对象是图像，3）；脚本二 `P04`（渲染结果记在非预览面，3）、`P05`（平面越界，7，是唯一一条并列三处归档出处的码）、`D04`（清单里的对象类在能力表一行都没有，25，其中 R22 一次就占 18）。
正确表述：**「框架支持这类格式」是能力表的一行，不是「这一面读得回结果」的证明。**清单不同形本身就是第 3.4 节失败点 5 的实证，因此引用时必须写明引的是哪一份、第几行，并把「这一格可能随系统版本变化」一起登记。渲染结论只在呈现面读得回（`render_result` 四值），把渲染结果记在声明面或公告面上由 `P04` 阻断；能力表里根本没有这一类对象时，缺哪一格无从判定，这是 `D04` 与 `Q4` 的落点。

**误区 6：截屏和厂商说法能当机制依据。**
依据：观测件里有两个平面按公开口径**不承载机制**——`vendor_claim`（厂商说法）与 `settings_ui`（设置界面读数）。第 3.4 节失败点 6 给的依据句是 `A/quicklook.txt:18`：既然清单本身随版本变化，任何一次界面读数只能证明那一天这一面显示过什么。两支脚本把这条做成了六个码：脚本一 `D06`（执行域结论只来自厂商说法、截屏或假定，累计 5、首现 R1，另在 R3 出现）、`B05`（类型判定依据为假定或厂商说法，7）、`N03`（告知文本依据是截屏或假定，3）、`N04`（自动处理且无提示却没有任何说明句，3；这一条的 DOC 串逐字是「见本文第 3.4 节失败点 6」，属自引用）、`O03`／`O04`（自述平面给确认结论、并用未说明冲突处理，各 3）；脚本二 `P03`（声明件记在公告面，3）、`P06`（观测件记在类型声明或标签反查面，6）、`P07`（崩溃引用记在非崩溃面，6）、`V03`（渲染结果只由 App 自述面给出，3）。
正确表述：**这两类来源可以证明「存在」，不能证明「机制」。**第 17.4 节把这条做成闸门：B 档读数要登记，但必须落到 `dom.domain_source` 的七种依据里可回指的那几档，`screenshot`／`assumed`／`vendor_claim` 三档不计入第 20 章 O5 的分子。反过来写也错：把平台文档与 App 自述并排引用却不说明冲突处理，落 `O04`——引用两份不等于闭合一条。

**误区 7：管理面关掉某个 App，所以解析链被约束了。**
依据：`C/readings-18.txt:91—96` 给出分母的构成——218 个键名行里命中内容接收／打开／预览／网页词形的只有 6 个（其中 5 个是 Safari 行为键），可**间接**约束内容能否被打开或联网取回的 19 个，**没有任何一个键能逐项约束类型判定或指名解析器／解码器**。`B/mdm-restrictions.txt:738` 那句是最好的粒度示例：禁用 Safari 这个 App、移除图标、并阻止打开 web clip，需受监督设备——它关掉的是承载 App 与浏览器行为。台账侧：脚本一 `G01`（称管理面可配内容却没有键名，累计 3、首现 R1）、`G02`（键不在 218 键清单内却用来给确认结论，3）、`G04`（管理面结论为可配但未指名任何键，3）、`G05`（限制键形态非法，4，另在 R14 出现）；脚本二 `P02`（通道件核对项记在管理面平面上，3，只在 R19／R23／R24 打印）。
正确表述：**开关改变的是「谁还能打开内容」，不是「内容被读成什么类型」。**管理面对类型判定这一格是空白而不是「暂时没读到」（第 18.3 节禁令 2）；写「这条解析链被策略禁止」需要的是键能约束解析器的证据，而这份证据在 218 键的清单里不存在。落到字段级就是两个码：脚本二 `P01`（核对项记为已读数、读数平面却填成无平面，累计 3，出处 `A/quicklook.txt:17` 那句「自有数据类型的预览要 App 自己提供视图或返回受支持的预览格式」）拦的是平面填成空，`P02` 拦的是平面填成管理面；两个码都只在 R19／R23／R24 三段各打印一次。

**误区 8：口径之间可以互相换算，所以结论可以写成一句。**
依据：三套词表之间没有任何一条公开换算句，第 18.3 节把这条写成三条跨侧禁令，每条都给了落点码。同一件事有两个口径的活例在第 16.3 节：KEV 恶意措辞计数 `C/readings-18.txt:78` 给 52（判据 `malicious`、按 CVE 去重）与 `C/subset-18.txt:14` 给 42（判据 `craft` 词形、按条目计数），量纲与正则都不同，**这两个数出自同一作者的两支派生器**。台账侧：脚本一 `X01`（缺来源文件或行号，21）、`X02`（行号引用形态非法，4，另在 R14 出现）；脚本二 `X05`（引用的类型标识不在声明类型词表里，11）、`X06`（框架符号或声明键不在符号词表内，18）、`X07`（扩展名或 MIME 标签不在标签词表内，8）、`M06`（引用值是公开词形的近义词、或不在这一格的公开词形表里，15）、`V06`（挂在公告面或管理面却没有词表标识，3）。
正确表述：**跨套结论必须同时给出两侧的平面名、字段与行号**，否则按 `X01` 阻断处理——这一句就是失败点 8 的可执行形式。「引用了某个公开词表里的字符串」也不等于可换算：`X07` 与 `M06` 拦的是近义词与错表，同一个值放错格子照样阻断。引用形态必须统一（`X02`），否则两份台账之间连验收都做不了，这一点第 23.6 节末尾那条限制已经说过。

**误区 9：公告里没写需要用户交互，所以这一格解析是免交互发生的。**
依据：这是一条**结构性负读数**，也是本篇的硬约束。`C/readings-18.txt:73—74`：1,266 行影响句里写成「without user interaction」这一类免交互措辞的**去重 CVE 数 = 0**；`:25—30` 那五类后果词形里**没有一类写触发条件**；全档案唯一一处对免交互下定义的句子是 `B/apple-platform-security-guide.txt:1442`，而那一行讲的是 BlastDoor 的设计目标、讲的是消息与身份服务，**不是任何一条文件解析链**。所以「公告没提交互」推不出「不需要交互」——它只推出这一列不记载这件事。四个码专拦这类写法：`E01`（同时登记需用户动作与自动处理，累计 3、首现 R1）、`E05`（触发面与进入面矛盾，3）、`A04`（URL 打开面被登记为自动处理，3，出处是 `A/webkit_wkwebview.txt:21—22` 那句「必须显式地把内容交给它加载」）、`E02`（自动处理却没有告知位，18）与 `E04`（网络投递且自动处理却未登记补丁通道，3）拦的是「写了自动处理却不写任何后果面」。
正确表述：**本篇对解析发生时点的表述只允许一种形态：「打开／预览／分享这三类动作之后」。**`trg.auto_processed` 与 `trg.remote_initiated` 两格不能从公告侧推，只能从动作侧登记：谁调了哪条 API、用户是否选了这份文档、预览是否被呈现（第 10.2 节）。正文不写任何免交互判定，也不把平台安全指南里那句关于消息的设计目标外推到文件解析链——那是第 26 章边界清单里的一条，不是台账里的一格。

**误区 10：拿设备实测一下最直接——跑一次 `mdls` 或 `file` 就知道判成什么类型了。**
依据：这是方法论越界，不是结论分歧。第 2.5 节把本文可证形态限死为公开口径三种，两支脚本在设计上不留口子：第 23.1 节 P1 用六个系统调用型模式在脚本一的 awk 程序体里得到空匹配（以 grep 自己的退出码 1 表达），P4 扫十六个设备侧工具名只命中头部拒收声明那一行（第 8 行），P4d 的「命令位置探测」在 P4c 阳性对照（命中 2）之后同样为空；P6 的外部命令普查结果是 `awk=1 cat=1 mktemp=3 rm=1`，没有第二个数据处理解释器。拒收侧的码：脚本一 `K01`（`sec.*` 命名空间出现字段，累计 4、首现 R1，四次分散在 R1／R4／R6 与 R12 那批行格式畸形里）、`K02`（取值形似设备路径／长载荷／密钥串，6，其中 R16 那次畸形取值夹具独占 3）、`K03`（崩溃引用不是报告标识形态，5，另在 R14、R16 出现）；脚本二 `K01`（引用格形似密钥、凭据、归档文件、设备绝对路径或整段载荷正文，4）、`K02`（引用格登记了设备侧命令行入口名，3，判据文案逐字是「本脚本与台账都不以任何命令行工具作为读数来源」）、`M04`（崩溃引用格不是报告标识形态，3）。第 12.2 节那三句规范就是把这条做成字段级约束的位置。
正确表述：**本篇全部结论必须是离线可复算的口径结论。**要得到设备事实需要另一套流程与本文之外的授权；这条限制同时是第 26 章 N12 的正文——本文能保证判定过程可复算，不能保证登记内容与某台真实设备一致。把实测写进脚本，脚本就从「台账审查器」变成「采集器」，而它头部那句只读声明（第 21.1／22.1 节）立刻作废；这也是台账拒收清单里「设备绝对路径、整段文件正文、超长载荷」三项存在的理由。

**误区 11：脚本退出码 0，或者某个对象判到 `J1`／`Q1`，就说明这条解析链没问题。**
依据：四种形状都会给出你不想看到的 0。其一，**空登记**：R10（空文件）与 R11（只有注释与空行）都是 `对象数=0 信号行数=0 判定行数=0`、退出码 0；R30（空清单）报 `三件对象数=0 信号行数=20 不同信号码=1 阻断信号条数=0`、退出码 **0**，那 20 条全是非阻断的 `D05`（核对项在整张清单里零登记）。其二，**合法哨兵值**：R18 把四格写成 `not_determinable`／`absent`，得到零信号、`J1` 与退出码 0——既不算缺失也不算拒收。其三，**输出开关**：R6 与 R1 传同一份畸形台账，`-q` 之后 stdout 上那 63 条判定行一条没有，而三次汇总行逐字相同、退出码仍是 1（第 23.7 节第 2 条）；只看 stdout 会读到「一个判定都没有」。其四，**合格夹具是下界不是上界**：R2 与 R20 给 0 信号只说明「这样的输入不被拦」，而第 20 章 O10 那条「再证明覆盖率永远不可能到 1」的缺口，合格夹具同样给不出。
正确表述：**退出码只跟随阻断族，不表达任何正向结论。**脚本一的恒等式是「信号行数 = 阻断条数」吗？不是——R3 给出 4 条信号、0 条阻断、退出码 0，因为 J2／J3 落在非阻断档。使用时固定核对四格：`对象数` 是否为 0、`信号行数` 是否为 0、这 0 是「下界」还是「无输入」、核对时刻是否早于最近一次复位。`exit 0` 不等于「这条链安全」，也不等于「已获授权」；两支脚本判的都是登记内容的自洽性，不是内容本身的安全性。

**误区 12：把第 26 章的边界清单当成台账的缺口，觉得补一格就闭合了。**
依据：第 17.3 节登记了四个负空间，每一条都写明了「为什么它不是漏写」。iOS 侧的隔离标记（quarantine）在全档案只命中 1 次，且出现在 macOS 侧的能力表里（`B/apple-platform-security-guide.txt:2344`），所以 `notice.quarantine_flag` 的两值没有归档来源——硬引那句 macOS 的话就造出一次跨平台换算（失败点 8）。`notice.origin_disclosed` 同理，两档只能由登记方旁证支撑。`A/uikit_uidocument.txt:56—60` 说别的客户端读取该文档时系统会**暂停读取**，而 `trg.trigger_mode` 的五个实值（连三个控制值共八个）里没有一格叫「挂起后被读」，新增一个取值等于自造词表，回指不到任何公开句子。第四条是复位与再核对层在脚本二里没有独立核对项（第 14.3 节），只能靠 `render_result` 四值与 `V05`（跨对象口径未统一，累计 4，非阻断）反查。台账侧的码管不到这里：`S09`（必备格缺失，累计 2,268）查的是「该填的没填」，`D05`（核对项整张清单零登记，52）查的是「这一格全表没人登记」，两者都预设这一格在公开口径里存在。
正确表述：**边界清单不是待办清单。**C 档不进台账（第 17.4 节：台账里没有 C 档这个值，写成 `unknown` 会与「未登记」混淆），它进的是第 26 章，作用是说明**为什么本文在这些格上给不出结论**。把边界清单上的条目补成台账里的一格，制造的是第 23.6 节那种最坏的情况——一条回指不到任何公开句子的信号。

十二张形状对照如下，末列给出该误区在两支脚本里的落点与第 23.2 节实跑的段号；「累计」取自第 23.3 节两张表（脚本一为 71 个信号码加四档判定的 75 格，脚本二为 60 个信号码加四档等级的 64 格）：

| 误区 | 压错的换算 | 层 | 主要信号码（累计） | 实证段 |
| --- | --- | --- | --- | --- |
| 1 | 声明 → 采信 | L2／L4 | 一 `B01`(188)、`B02`(3)；二 `T01`(58)、`K03`(4) | R1、R12、R19、R31 |
| 2 | 三票齐 → 三票一致 | L4 | 一 `B03`(3)、`B04`(5)；二 `T06`(4)、`S09`(20) | R1、R3、R19 |
| 3 | 判定 → 后果 | L4／L9 | 一 `X01`(21)、`O03`(3)；二 `V01`(7)、`V02`(70) | R1、R19 |
| 4 | 组件列 → 影响句 | L10 | 一 `R03`(3)、`R05`(3)；二 `X01`(6)、`X02`(2) | R1、R19、R24 |
| 5 | 框架支持 → 这一面能读回 | L5／L9 | 一 `B06`(6)；二 `P04`(3)、`P05`(7)、`D04`(25) | R1、R19、R22 |
| 6 | 截屏／厂商说法 → 机制 | L6／L8 | 一 `D06`(5)、`N03`(3)；二 `P06`(6)、`P07`(6) | R1、R3、R19、R23 |
| 7 | 关掉 App → 约束判定 | L6／L10 | 一 `G01`(3)、`G02`(3)；二 `P02`(3) | R1、R19、R23 |
| 8 | 跨套换算 → 一句结论 | 全篇 | 一 `X01`(21)、`X02`(4)；二 `X06`(18)、`M06`(15) | R1、R14、R19 |
| 9 | 公告未写交互 → 免交互 | L7 | 一 `E01`(3)、`E05`(3)、`A04`(3) | R1、R4、R6 |
| 10 | 实测 → 可证 | 全篇 | 一 `K01`(4)、`K02`(6)；二 `K01`(4)、`K02`(3) | R1、R12、R16、R19、R23 |
| 11 | 退出码 0 → 没问题 | 全篇 | 一 `J1`(7)、`J2`(2)；二 `Q1`(4)、`D05`(52) | R2、R3、R20、R30 |
| 12 | 边界清单 → 待办清单 | 全篇 | 一 `S09`(2,268)；二 `V05`(4) | R1、R17、R19 |

末列之后还有一处值得单独看的覆盖强度差异，它比任何一句「覆盖充分」都更能说明这套验收的边界。**脚本一的 71 个信号码里，46 个只在 `codes`／`multi`／`quiet` 三段出现过**——而这三段跑的是同一份畸形台账的三种调用形状（R1 直跑、R4 与另两份合并读入、R6 带 `-q`），其中 40 个码的累计恰为 3，也就是这份夹具里只有一个对象触发它；剩下 25 个码必须靠第 12—17 段那六份专项畸形夹具才命中（行格式、命名空间、取值形态、重复登记、拒收形态、必备格）。**脚本二更窄：`C01`—`C04` 四个码累计各为 1，且只在 `bad-capability`（R22）那一段打印过**，因为它们校验的是能力表的列数与三个取值集合，只有把能力表本身喂畸形才可能命中；`X02`／`X03`／`X04` 三个词表差集码累计各为 2，同样只在同一份输入的两种调用形状里出现。改到这九条判据时，只有那一段日志会变色，其余各段毫无反应——这是本文当前覆盖强度的真实上限，不是笔误，也是第 23.8 节第三条「没有证明覆盖是均衡的」的具体形状。

## 25. 常见问题

**问：这套台账必须跑在设备上吗？**
不。两支脚本都是纯文本、离线、只读：脚本一（`tools/parsing-chain-ledger-review.sh`，363 行）收一份或多份三列台账，脚本二（`tools/parsing-chain-tripartite-diff.sh`，572 行）收固定三份登记件（清单、能力表、词表），全程不调用任何 Apple 命令行工具、不访问设备、不联网、不打开任何被登记的对象。第 23.1 节那二十段检查（P1—P20）是这件事的实证而不是一句声明——P1 用六个系统调用型模式在脚本一的 awk 程序体里得到空匹配（以 grep 自己的退出码 1 表达），P4 把十六个设备侧工具名扫遍全文只命中头部拒收声明那一行（第 8 行），P6 的外部命令普查是 `awk=1 cat=1 mktemp=3 rm=1`，P8 跑完夹具后 `pcl.*` 匹配为空，P10 把十八次实跑的命令行归一化后只剩六种形状。**但要说清一处不对称**：P1—P6 检查的是「有没有能读别处的口子」，检查不到「读到的内容是不是设备事实」。登记件由人填写，本文能保证判定过程可离线复算，不能保证登记内容与某台真实设备一致（第 26 章 N12）。

**问：两支脚本我该先跑哪一支？**
先脚本一。它逐对象检查十二个命名空间里该填的格填没填、填的形态合不合规，输出 `J1`—`J4`，回答「这一条登记能不能进入对外表述」；脚本二吃的是另一形状——十列三件清单加两份表——输出 `Q1`—`Q4`，回答「三份登记对完之后归属还能不能立起来」。两者判的不是同一个东西（第 19.3 节：J 查**一条登记内部**的完整性，Q 查**三份登记之间**的一致性），**绝不合并成单一分数**：合并会掩盖一件事——逐条越严谨，越容易让三件缺口看起来像已闭合。实际用法里 R20 那段最能说明问题：同一份内容交给脚本二，四个对象全部 `Q1`、信号 0 行；而把 R19 那批畸形清单交给脚本一，63 个对象打出 1,055 行信号、71 个码各至少命中一次。两支脚本对着同一份现实给出两种粒度，不是矛盾，是两件事。

**问：要准备几份输入？顺序能换吗？**
脚本一 1 份起，可一次传多份，格式是三列 `<对象标识>,<字段名>,<值>`（`#` 开头与空行忽略、行尾 CR 忽略、值里不能含逗号）。R4 一次传三份（good + mid + bad），68 个对象 = 3 + 2 + 63，互不污染；R5 把同一份 good 传两遍，得到 216 条 `S03`（同字段重复登记）——**传两遍不是幂等的**。脚本二固定 **3 份且顺序不可换**：十列三件清单、三列能力表（CSV）、三列公开词表（TSV）；第 86 行 `[ $# -eq 3 ]` 是硬检查，只给一份就退出码 2（R27）。参数校验也不对称：脚本一侧只有 R8（无参数）与 R9（文件不存在）两次退出码 2，脚本二侧有 R26（无参数）、R27（只给一份）、R28（第三份不存在）三次——因为差集必须同时有基准。

**问：「十二个命名空间」和「二十项核对项」是一回事吗？**
不是，而且这是两支脚本之间最容易串的地方。**十二个命名空间**属于脚本一：`id.`、`typ.`、`rights.`、`asm.`、`dom.`、`trg.`、`obs.`、`notice.`、`undo.`、`mgmt.`、`adv.`、`doc.`（外加一个纯拒收的 `sec.`，它下面任何字段都触发 `K01`），其中标为必备的是十二格：`id.obj_kind`、`id.source_face`、`id.provenance`、`typ.type_source`、`asm.parser_framework`、`asm.parser_layer`、`dom.domain_class`、`trg.trigger_mode`、`obs.plane`、`notice.prompt_shown`、`undo.reset_method`、`doc.source`，缺任一按 `S09` 记并落 `J4`。R17 只登记一行，于是缺满十一格、打出 15 行信号、判 `J4`。**二十项核对项**属于脚本二，是三件切分：声明件 7 项（`declared_uti`、`declared_mime`、`filename_ext`、`conforms_chain`、`decl_ownership`、`tag_spec`、`pkg_layout`）、通道件 7 项（`uti_lookup`、`ext_lookup`、`mime_lookup`、`decode_entry`、`preview_entry`、`open_entry`、`resolved_uti`）、观测件 6 项（`advisory_component`、`advisory_cve`、`mgmt_restriction`、`notice_surface`、`crash_ref`、`render_result`），7 + 7 + 6 = 20。两者有交集但不是一一映射：例如 `notice.*` 那一整类在脚本一是五个字段，在脚本二只落到 `notice_surface` 一项上；而 `mgmt_restriction` 在脚本二是观测件一项，在脚本一是 `mgmt.*` 那一整类六个字段之一，并由 G 族五个码合起来管「管理面这一格能不能这么写」（`G05` 单独管键形态）。**跨脚本对齐台账时，用对象标识，不要用格名。**顺带记一条形状差异：脚本二里有三个核对项是**数组型**（`conforms_chain`、`filename_ext`、`tag_spec`，同一对象可多行），其余十七项一号一行，重复行按 `S08`／`S09` 报出。

**问：能力表怎么建？我不想从零开始。**
从 `FX/capability-18.csv` 起步：182 行 = 2 行口径注释 + **180 行数据**，形状是 9 个对象类 × 20 项核对项，每行 `<对象类>,<核对项>,<可得性>`，取值分布是 required 85、optional 47、not_applicable 47、undocumented 1。注释里逐条写了口径来源（哪个文件哪几行支持这一格对该类对象成立）。三条规则：`required` 必须能指到具体文件与行号，指不到就记 `undocumented`；`undocumented` 是**这一格公开口径既没说要也没说不要**，第 26 章的边界清单与它就是同一件事的两种写法；`not_applicable` 要有公开口径明确说这一格对该类不成立，不能拿它当「我不想登记」的写法。改完必须重跑 `FX/run-all-tri.sh`：`D05`（该核对项在整张清单零登记）的条数会随 required 集合乘法变化——R30 那份空清单一次就打出 **20** 条 `D05`（二十项全零登记），R31 只登记一项时打出 19 条 `D05` 加 10 条 `D02`（那一类 11 个 required 项里 10 个在本对象无行）。**这不是脚本变严格了，是分母变大了。** 另外记一条容量差：脚本二接受 11 个对象类（8 个内容类 + 1 个服务类 + `not_recorded`／`unknown` 两个兜底类），能力表只覆盖前 9 个，兜底类按设计不进能力表——它们存在的意义是让对象标识前缀与对象类一一对应，而不是提供读数。

**问：公开词表那 71 条哪来的？为什么汇总行读到「词表词条=65」？**
`FX/vocab-18.tsv` 是 73 行 = 1 行注释 + 表头 + **71 条**，三列 `<词表类别>\t<词表值>\t<来源标识>`，类别分布是 `uti_identifier` 14、`api_symbol` 15、`plist_key` 7、`restriction_key` 5、`advisory_component` 7、`advisory_component_crafted` 7、`advisory_cve` 10、`mime_tag` 2、`extension_tag` 4。脚本二读进来时按 `nrm(值)` 单键去重（第 353 行 `if (!(nk in vocab))`），**键里没有类别**，所以同一个值挂在两个类别下只计一次。少掉的六条正是这件事：`ImageIO`、`Model I/O`、`WebKit`、`CoreGraphics`、`FontParser`、`APFS` 六个组件名同时登记在 `advisory_component` 与 `advisory_component_crafted` 两个类别下，且来源行号逐字相同（如 `C/advisory-18.tsv:40`）——前者是公告里出现过的组件全集，后者是第 16.3 节那套「恶意措辞」子集，65 = 71 − 6 是这个包含关系的算术结果，不是丢数据。两个数都对，**并列出现时必须带上这句解释**，否则下游会读成矛盾。还要提醒一句：`advisory_component_crafted` 里那条 `Zzsubonly` 的来源列写的是 `fixture`——它是合成词形，只用来测 `X06` 那条判据能不能命中，不代表任何公告里的组件。台账拒收清单同样适用于词表：真实用户检索词、可还原身份的语音描述、真实联系人／健康／位置样本一律不进夹具。

**问：为什么有些码在大部分实跑里一次都不出现？**
因为覆盖强度本身不均匀，而这不是缺陷。第 23.3 节两张表的「首现／累计」两列把这件事钉死了：**脚本一的 71 个信号码里 46 个只在 R1／R4／R6 三段出现过**，而这三段跑的是同一份畸形台账 `FX/ledger-18-bad.txt` 的三种调用形状（直跑、与另两份合并读入、带 `-q`），其中 40 个码累计恰为 3；剩下 25 个码必须靠 R12—R17 那六份专项畸形夹具才命中。**脚本二更窄**：`C01`—`C04` 四个码累计各为 1、只在 R22（畸形能力表）那一段打印过，`X02`／`X03`／`X04` 三个词表差集码累计各为 2、只在 R19 与 R24 两段出现。所以改到这几条判据时，只有一段日志会变色，其余各段毫无反应——这就是第 23.8 节第三条「没有证明覆盖是均衡的」的具体形状，也是第 24 章末尾那段话的来处。**改判据之后要做的不是看总信号数变没变，是回到第 23.2 节那张逐次表，确认哪一段该变色、它确实变色了。**

**问：能不能把某一格从台账里删掉，让覆盖率好看一点？**
不能，脚本会看出来，而且方向常常与预期相反。删掉清单里某个对象的一行 → 该对象少一项核对项，`D02`（required 项在本对象零登记）逐格计数；删掉能力表里某对象类的一行 → `D04`（该类无行）；把能力表清成只剩注释 → `C05`（整表无有效行）；把三份输入指向同一个文件 → R32 给出 `核对项登记行=141`（47×3）、`能力表行=0`、`词表词条=0`，`S08`×94 加 `C05` 加 `X08`，四个对象整批 `Q4`、退出码 1。**把清单本身清空反而更糟**：R30 给出「对象 0、阻断 0、四档全 0、退出码 0」——看起来最干净的一次运行，其实是什么都没判。两张退化表同框是 R29：`能力表行=0` 且 `词表词条=0`，两条「整表无有效行」同时命中，四个对象全落 `Q4`。**降低覆盖指标的唯一途径是补读数或换平面，不是改分母**（第 20 章 O1—O10 全部按这个前提写）。

**问：脚本二报的「三件对象数」为什么和它自己打的 `Q` 档行数不一样？**
因为三个数回答三个问题。R19 读到 `三件对象数=32`，而 `Q` 档只有 **31** 行（20 + 9 + 2）。缺的那条是 `IMG_B3`：它唯一的一行把核对项写成了 `not_an_item`，被 `S04` 判掉之后这个对象再没有任何合法登记，于是它照常出现在差集矩阵里（`声明件=0 通道件=0 观测件=0`、`required=0 已读数=0 缺:（无）`），却不落任何闭合等级——**被计数、永不被判定**。脚本一没有这个洞（R1 的 63 个对象数与 63 行判定数恒等），因为它的信号行只有一个主语空间。还要提醒一句：脚本二同一列「主语」在四个码族下指的不是同一种东西——对象标识（`IMG_*`／`WEB_*`）、对象类（`C01`—`C05` 以对象类作主语）、词表类别（`X08` 逐行支）、聚合级信号的 `-`（`D05`、`V05` 那类整表判定）。**任何把它当单一键去 join 的下游用法都会错。** 这条差异本身进了第 26 章的边界清单。

**问：「这一格内容到底有没有被读回」「隔离标记到底置没置」这些问题到底能不能登记？**
有一半不能，而且**不能的那一半要写进边界清单，不能塞进台账**。三条活例：其一，iOS 侧的隔离标记（quarantine）在本篇归档里只命中 1 次，且出现在 macOS 侧的能力表里（`B/apple-platform-security-guide.txt:2344`），没有任何一句说明它在 iOS 上如何被设置、由谁读回，所以 `notice.quarantine_flag` 的 `set`／`absent` 两值没有归档来源；其二，`A/uikit_uidocument.txt:56—60` 说别的客户端读取该文档时系统会**暂停读取**，而 `trg.trigger_mode` 的五个实值（连三个控制值共八个）里没有一格描述它，本篇的处理是原样记 `not_determinable` 并进第 26 章，不为了填满枚举而借用邻值；其三，`A/quicklook.txt:14` 那句 USDZ 进 AR 视图是预览面唯一一处把内容送到相机取景的场景，但归档里没有一句给出这一场景的告知口径，所以 `notice_surface` 的 `ql_ar_notice` 一值在台账里的合法取值只有 `not_recorded`，脚本二要求引用格落回词表值或文档行号（`V02`）时它会失败——**这条失败是预期行为，不是缺陷**。

**问：正文里为什么不写「零点击」「免交互」这类词？**
因为本篇归档给不出支撑这句话的读数，写下来就是无依据的结论外推。`C/readings-18.txt:73—74`：1,266 行影响句里写成「without user interaction」这一类措辞的**去重 CVE 数 = 0**；`:25—30` 那五类后果词形里没有一类记载触发条件；全档案唯一一处对免交互下定义的句子是 `B/apple-platform-security-guide.txt:1442`，而那一行讲的是消息与身份服务的设计目标，**不是任何一条文件解析链**。所以「公告没提交互」推不出「不需要交互」，它只推出这一列不记载这件事。本篇对解析发生时点的表述只允许一种形态：**「打开／预览／分享这三类动作之后」**，对应台账里 `trg.trigger_mode` 与「解析时点」那两格的登记值（`on_open`／`on_preview`／`on_user_action`／`on_arrival`／`on_background_fetch`）。「不写这个词」是写作约束，不是回避话题：第 24 章误区 9 把它当成一条换算失败来拆，脚本一用 `E01`（同时登记需用户动作与自动处理）、`E05`（触发面与进入面矛盾）、`A04`（URL 打开面被登记为自动处理）三个码拦住「把这一格写成不需要动作」的登记，另用 `E02`／`E04` 拦住「写了自动处理却不写后果面」的登记。

**问：退出码该怎么做门禁？**
`2` 判「输入坏了」（参数个数非法、文件不可读），`1` 判「有阻断信号」，`0` 判「无阻断信号」——三者严格分开。三十二次实跑的分布是脚本一 **6 个 0、10 个 1、2 个 2**，脚本二 **3 个 0、8 个 1、3 个 2**；那五个 2 全部落在「输入不可用」这一类（R8／R9 与 R26／R27／R28）。**不要按档位设门禁**，档位与退出码不是同一个量。三个反例都在第 23.2 节：R2 与 R20 信号 0、退出码 0，这是下界而不是达标；R30 退出码 0 却一个对象都没判；R3 打出 4 行信号、3 个码，阻断 0、退出码仍是 **0**，因为那三条落在非阻断档（`J2`／`J3`）。要卡质量就把汇总行里的 `J1` 占比、`Q1` 占比与 `required` 缺读率作为评审指标（第 20 章 O1—O10），让退出码只承担「这次运行能不能被采信」这一件事。最后一条边界：**`exit 0` 不等于「这条链安全」，也不等于「已获授权」**——两支脚本判的都是登记内容的自洽性，不是内容本身的安全性，也不提供任何绕过告知、隔离或管理面审计的做法。

## 26. 未公开文档化边界清单

本章收录的是「公开文档没给，本文就不结论」的那些格子。一条边界要进这张表，必须同时满足三个条件之一：**（a）** 公开文档对这一格既没写成「该类对象必须登记」，也没写成「对该类对象不成立」——即三件能力表里 `undocumented` 的那种状态；**（b）** 公开侧有读数，但读数所在的面与本文要的格子不匹配（组件名不能当文档件用，词表取值不能当口径句用，聚合级读数不能当个体级用）；**（c）** 完全没有公开读点，而第 1.3 节的红线又不允许用设备侧操作补齐。**不属于这三类的不进表**：文档明确写了义务的格子归第 4—14 章的层叙述，文档明确写了不适用的格子归能力表的 `not_applicable`（本篇有 47 格属后者）。

**编号约定**：本章编号写作 N1—N12，**不补零**，与脚本一第 11.2 节那五个补零信号码 `N01`—`N05`（告知层）不是同一个东西。这两组编号在本篇撞得比第 17 篇更近，必须逐字说清：`N02` 是脚本一的判据「`notice.quarantine_flag = not_supported` 且 `notice.origin_disclosed = disclosed`」（拦的是**同一行登记内部**共用了一个未声明的隐含前提），本章 N2 说的是「quarantine 这一位在 iOS 侧根本没有公开口径」（说的是**登记之外的公开文档**）。前者是登记自洽性，后者是登记可能性，`N02` 触发一次并不意味着 N2 这条边界闭合。脚本二没有 N 族（它的十族是 S／C／D／K／M／P／Q／T／V／X），所以本表十二条里凡是引用脚本码的地方，脚本一侧一律带「脚本一」前缀。把 `N01` 当成「第一条边界」去 join 会串。

### 26.1 十二条边界

**N1 · 内容在什么时刻被解析，公告侧给不出任何读数。** 缺的是这一格：给定一份内容，它被读回来的时刻是不是解析发生的时刻。公开侧最远读到三处负读数：`C/readings-18.txt:73—74`（1,266 行影响句里写成那一类免交互措辞的**去重 CVE 数 = 0**）、`:25—30`（五类后果词形 `unexpected app termination` 133 行、`disclosure of` 84 行、`bypass` 78 行、`memory corruption` 77 行、`arbitrary code execution` 58 行，**五类里没有任何一类写触发条件**）、`B/apple-platform-security-guide.txt:1442`（全档案唯一一处对免交互下定义的句子，讲的是 BlastDoor 对消息与身份服务的设计目标，不是任何一条文件解析链）。台账记法：`trg.auto_processed` 与 `trg.remote_initiated` 只能从动作侧登记，归属矩阵 L7 的「公开读数面」因此写作**无**而不是**未记录**——第 15.1 节规矩 1 说得很死，混用这两值会让本表与台账的 `not_recorded` 计数互相污染，全矩阵只有一格是前者。这里有一处形态差必须写清：脚本二的「解析时点」列有七个取值（第 160 行 `on_open`／`on_preview`／`on_background_fetch`／`on_user_action`／`on_arrival` 加两个控制值），但它**只判形态**（第 298 行 `S07`，累计 16），不判这一格能否回指公开句；于是 `on_arrival` 与 `on_background_fetch` 两值在脚本里合法、在归档里没有对应句子，**本文正文不使用这两值**。相关信号：脚本一 `E01`（3）、`E05`（3）、`A04`、`E02`（18，拦「写了自动处理却不写告知位」）；脚本二 M 族与 T 族都不覆盖这一格。**后果：本篇对外表述里，解析发生时刻只允许一种形态——「打开／预览／分享这三类动作之后」。第 24 章误区 10 就是这条边界的落点。**

**N2 · iOS 侧的隔离标记（quarantine）没有口径。** 缺的是「这份内容带着隔离标记吗、由谁设置、是否影响类型判定」三句中的任何一句。公开侧读到：组 A 与组 B 全部归档里 `quarantine` 只命中 **1 次**，`B/apple-platform-security-guide.txt:2344`，而且位于 macOS 侧一张能力表里（`:2343—2348`，与 App notarization、System Integrity Protection、Gatekeeper、XProtect/YARA 同行，「第三方等价物」列写的是 `Virus/Malware definitions`）；组 C 公告表里 `quarantine` 作为组件名出现 **8 行**（`C/advisory-18.tsv:458—459、708—710、905—907`），但平台列逐行都是 macOS（Golden Gate 27.2、Tahoe 26.7.2、Sequoia 15.8.2），`C/readings-18.txt` 对这个词命中 0。**公告面有这个名字、文档面没有这句话**，正是条件（b）。台账记法：`notice.quarantine_flag` 六个取值里本篇只承认 `not_supported`（本层无此口径）与 `not_recorded`；写下 `set`／`absent` 时引用格必须落到本篇归档之外。相关信号：脚本一 `N02`（3，见上面编号约定那段——它判的是两格矛盾，不是这一格有无来源）、`O03`（3，读数挂在自述面却不登记读到哪一格）。**后果：第 17.3 节第 1 条；硬引 macOS 那一句造出跨平台换算，即第 3.4 节失败点 8。**

**N3 · 来源是否披露给用户，没有任何面能读回。** 缺的是「打开一份内容时界面上会不会显示它从哪来」。公开侧读到：组 A 十二份文档没有一处说明这件事；唯一两处间接证据是 `A/uikit_uiactivityviewcontroller.txt:10`（标准服务由系统给出）与 `B/…guide.txt:2393`（每个 App 有独立容器），两者都只说明「来源在容器层面是分开的」，不说明「来源对用户可见」。台账记法：`notice.origin_disclosed` 的五个取值里两档结论 `disclosed`／`absent` 只能由旁证支撑，属第 17.2 节的 **B 档**——可以登记，不能进入对外结论。相关信号：脚本一 `N02`（3，与 N2 共用同一判据行）、`N03`（3，告知文本依据是截屏或假定）。**这条与 N2 是本表唯一成对出现的一对：两格隐含同一个「系统在某处记住了这份内容的来历」的前提，而该前提在本篇归档里没有句子。**

**N4 · `NSFilePresenter` 的挂起读取态没有对应枚举值。** 缺的是「由别的客户端发起、被系统挂起的读取」这一种触发形态。公开侧读到 `A/uikit_uidocument.txt:56—60`：「When another client attempts to read the document of a …-based app, **the system suspends reading** until the system provides the object an opportunity to save any changes made to the document」——句子在，形态格不在：`trg.trigger_mode` 的八个取值（`user_open`／`user_preview`／`background_auto`／`render_pipeline`／`message_auto` 加三个控制值，脚本一第 105 行）里没有一格描述「挂起后被读」，`background_auto` 说的是自家 App 的后台处理、`render_pipeline` 说的是渲染管线。台账记法：只能记 `not_determinable`，不为了填满枚举而借用邻值。相关信号：脚本二 `S07`（枚举越界，累计 16）——它是这条边界唯一的机器兜底，作用是防止有人**新造取值**：新增取值等于自造词表，回指不到任何公开句子。**第 17.3 节第 3 条；这是「文档有句、词表无格」形态，与 N6 的「词表有格、文档无句」正好反向。**

**N5 · 同一层内部口径密度不均，`render_pipeline` 与 `background_auto` 各缺一半。** 缺的是这两格分别对应的公开句子。公开侧读到：`pipeline` 一词在归档出现 5 次（`B/…guide.txt:1513、1522、1527、1532、2442`），逐条查过去全部讲的是 Rosetta 的 JIT／AOT 转换链与 macOS 公证流程，**没有一处讲内容渲染管线**；`B/…guide.txt:2397`「apps can only perform **background processing through system-provided APIs**」这一句确实存在，但它约束的是**入口必须是系统 API**，读不出「后台会自动解析内容」。与 N4 对照要补一句：`A/quicklook_qlpreviewcontroller.txt:41`（视图不在前台时显示一张与其尺寸一致的缩略图）**能**支撑 `trg.renders_thumbnail` 这一格，但不能支撑 `trigger_mode = render_pipeline`——同一层的两格，一格有句一格无句。台账记法：无句的两格只能整格不登或记 `not_determinable`；「哪一格有文档、哪一格只有口径」这条差别是本章的主体，也是脚本二要求引用格必须落回 `A/`／`B/`／`C/` 归档行号或公开词表值的原因。相关信号：脚本二 `V02`（引用格既不是词表值也不是文档行号形态，累计 **70**，是本篇最大面积的负读数族）。**第 10.3 节末段。**

**N6 · `modelio_api` 词表有平面、归档没有承载它的文档件。** 缺的是「模型内容经哪条公开入口被读回来解析」的文档句。公开侧读到：这个值在脚本二里出现四处（第 42 行 usage 列举、第 156 行 `PL` 集合、第 170 行 `DEOK["model_content"] = "modelio_api"`、第 187 行 `ppair("modelio_api","channel")`），**词表侧完整**；组件侧也真实存在——`C/readings-18.txt:35` 给 `Model I/O` 37 行。但组 A 没有 Model I/O 文档件。于是这一平面**既不能删（组件侧真实）也不能填（没有承载它的文档句）**，属条件（b）。台账记法：登记模型类时 `asm.parser_framework` 一侧只能配 `not_determinable`，引用格落到公告组件名而不是文档行号。相关信号：脚本二 `P05`（平面越界第二类，第 477 行——它按 `DEOK` 强制模型类的解码入口只能填 `modelio_api`，也就是说这一格的合法填法与它的可回指填法是同一个值）、`M06`（引用值不在公开词形表里，累计 15）。**第 12.1 节结论 2；这条与 N7 同源——词表先于文档成形的地方，边界就出现在词表与文档之间。**

**N7 · 字体与归档两类没有解析入口文档面，连 `decode_entry` 的可填取值都没有。** 缺的是「字体文件与归档包各由哪个公开符号解析」。公开侧读到：`A/uniformtypeidentifiers_system_declared_uniform_type_identifiers.txt:84—87、270` 给出这两类的**类型声明**（它们在 UTI 清单里有名有姓），但组 A 没有一句给出解析入口。形态面上的证据更硬：脚本二 `TOK["decode_entry"]` 一共五个值（第 147 行 `CGImageSource`／`CGAnimateImageAtURLWithBlock`／`WKWebView`／`UIDocument`／`QLPreviewController`），**五个里没有一个字体符号或归档符号**——词表本身就是这条边界的机器形状。台账记法：能力表把两格分开登记，`archive_content,decode_entry` 记 `not_applicable`（第 113 行：公开口径明说扩展名反查与 MIME 反查分属两条通道，对归档类不成立），`font_content,decode_entry` 记 `undocumented`（第 73 行，**全表 180 行里唯一一条**：文档既没说字体类必须登记这一格，也没说它不成立）。相关信号：`P05` 累计 7 条，但**七条的主语全是 image_content 的对象**（IMG_P1、IMG_P2），这条边界作为判据文案里的括注存在（「字体与归档两类只有类型声明……而没有承载其解析入口的文档面」），不以自己的主语出现过；字体类对象自己拿到的是 `T07`／`T08` 与 X 族信号，其中 `FNT_X1` 一个对象在 R19 打出 16 条 `V02`，是全套日志里 `V02` 主语最集中的一格。**后果：本表里唯一一条「能力表已经承认、但脚本永远不会报出来」的边界，详见 26.2。**

**N8 · `ql_ar_notice` 有词表值、没有告知口径。** 缺的是「内容被送进 AR 预览时用户看到什么告知」。公开侧读到 `A/quicklook.txt:14`——USDZ 模型可以进入 AR 视图，这是预览面唯一一处把内容送到相机取景的场景；`TOK["notice_surface"]` 四个值（第 150 行 `lockdown_notice`／`preview_notice`／`ql_ar_notice`／`none`）里第三值就来自这一行。但**归档里没有一句给出这个场景的告知口径**。台账记法：这一格在台账里的合法取值只有 `not_recorded`；脚本二要求引用格落回词表值或文档行号（`V02`，第 459 行），填了 `ql_ar_notice` 又要给引用格时它**必然失败——这条失败是预期行为，不是缺陷**，第 11.3 节与本章按同一口径写。相关信号：`V02`（预期失败处）。**这是本表十二条里唯一一条「脚本会主动把合格登记判下去」的边界，所以要留在表里而不是留在夹具里。**

**N9 · 复位与再核对层在脚本二里没有独立核对项。** 缺的是「复位动作本身」的三件核对项。公开侧读到：三件 20 项的词表来自声明／通道／观测三段公开口径，而复位是**登记方自己的动作**，公开档案里没有「复位核对项」这一格可对应。台账记法：本层通过 `render_result` 四值（第 151 行 `rendered`／`blank`／`failed`／`not_run`）与脚本二 `V05`（累计 4，同一对象类同一核对项在不同对象之间既有已读数又有明确不存在）间接反查；脚本一 `undo.*` 六个字段自己承担，四个码 `V01`—`V04` 各 3 条且**全部非阻断**。相关信号：脚本一 `V01`—`V04`（本层没有任何阻断判据，这与它的性质一致：复位层不改变归属结论的对错，只改变结论的时效）、脚本二 `V05`。**后果：J1／Q1 级结论必须带 `undo.verified_at`；缺核对时刻的 J1 在第 20 章 O10（再证明覆盖率）里计为未覆盖但不降级。这是本篇承认的已知不完备（第 14.3 节末段）。**

**N10 · 「有对象、无判定」是第四种零，脚本形状本身在此处不闭合。** 缺的是「三件对象数」与「Q 档判定行数」恒等这件事。读数：R19 打 `三件对象数=32`，而闭合等级只有 **31** 行（Q2=20、Q3=9、Q4=2）。原因逐段可查：`IMG_B3` 唯一的一行把核对项写成 `not_an_item`，脚本二第 287 行已经把它计入 `order`（所以「对象数」算它），第 290 行 `S04` 判掉这一行，第 299 行 `if (!(it in ITM)) next` 让它一条核对项都没登记，第 303 行的 `kdSeen` 因此没置位，第 375 行与第 514 行两处 `if (!(id in kdSeen)) continue` 又把它从差集矩阵与档位判定里都跳过——**它被计数、在矩阵里留下全零一行、却永不落任何等级**。（`声明件=0 通道件=0 观测件=0`、`required=0 已读数=0 缺:（无）` 那一行照常出现在矩阵里，是因为第 543 行那个打印矩阵的循环**不查** `kdSeen`，而第 375 行（逐对象的 D／X 族核对）与第 514 行（定档）两个循环都查——三个循环共用同一个 `order` 数组，却只有一半设了闸门。）脚本一没有这个洞：R1 读到 `解析链对象数=63 判定行数=63`，恒等，因为它的信号行只有一个主语空间。相关信号：`S04`（核对项不在三件 20 项词表内，累计 4，**属阻断族**）。**后果：任何把「对象数 = 判定数」当前提的下游统计都会漏掉这类对象，第 23.2 节三种零（合格零、无关零、不可用零）之外的第四种由本节收录（第 23.6 节末段）。**

**N11 · 行号属于快照，不属于网址。** 缺的是「`第 N 行` 这个引用长期稳定」。公开侧读到：无——这不是文档缺口，是引用机制的性质。所有 `第 N 行` 指的是第 28 章资料表里标注视作日期抓取的那份纯文本的行号；同一份文档换一次抓取，行号会变。台账记法：脚本一 `X01`（21，缺来源文件或行号）、`X02`（4，行号引用形态不可换算）与脚本二 `X01`（6）、`X02`（2）**只统一形态，不保证稳定**：本篇要求行号引用只写 `1234` 或 `6-9` 一种形态，带「第／行」前缀的写法在两份台账之间不可换算。相关信号：上面四码。**后果：行号失效时，失效的是这份快照，不是这条判据的逻辑（第 23.8 节）；但两份台账之间如果连形态都不统一，最后连验收也做不了——这才是这四条码真正的用途。**

**N12 · 判定本身的可证边界（本表唯一自指的一条）。** 缺的是「台账内容与某台真实设备一致」的证明。公开侧读到：无——这不是文档缺口，而是本文方法的边界。第 23.1 节 P1—P20 二十段检查能证明两支脚本没有任何读设备、读网络、读索引、读文件属性的口子（P1 用系统调用型模式跨两支脚本找零命中，P4 列设备侧命令名只找到注释与拒收分支里的位置，P11—P14b 给阳性对照，P6 两份合格夹具跑完后临时目录通配都报不存在），**但证明不了登记件本身填得对**。台账记法：每一条对外表述前加限定语「按台账」，或在同一行给出 `doc.source` ＋ `doc.line_ref`。相关信号：脚本一 `X01`（缺来源文件或行号——这条判定无法回到公开文档逐行核对）。**第 1.3 节末条与第 24 章误区 11 说的是同一件事：本文能保证判定过程可离线复算，不能保证登记内容与某台真实设备一致。把实测写进脚本，脚本就从「台账审查器」变成「采集器」。**

### 26.2 能力表怎么承载这些边界

`FX/capability-18.csv` 一共 182 行 = 2 行口径注释 + **180 行数据**，形状是 9 个对象类 × 20 项核对项，取值分布 **required 85、optional 47、not_applicable 47、undocumented 1**，四个数相加正好 180。注释第 2 行给出四值口径（`r=required o=optional n=not_applicable u=undocumented`），并要求 `required` 必须能指到具体文件与行号、指不到就记 `undocumented`。

**全表那一条 `undocumented` 就是本章 N7 的机器形态**（第 73 行 `font_content,decode_entry,undocumented`）：公开文档既没写成字体类必须登记解码入口，也没写成这一格对字体类不成立——两个否定都读不到，所以既不能升成 `required` 也不能降成 `not_applicable`。脚本二对它的处理是**整格跳过**，可以从判据位置逐行确认：第 414 行（该类 required 项在本对象零登记）与第 419—423 行（required 项被记 `absent`／`not_applicable`）两支都 gate 在 `av == "required"`，第 425—427 行那一支 gate 在 `av == "not_applicable" && st == "recorded"`，第 547 行汇总矩阵那一支同样只数 `capOf[kk] == "required"`；**没有一支匹配 `undocumented`**。因此它既不报覆盖空洞（不进 `D01`／`D02`／`D03`／`D05`），也不报不适用，代价是这一格**永远不会出现在 Q 档的缺口清单里**——不会出现「补齐字体类的解码入口就能升档」的假指标，但也不会提醒任何人它空着。这就是 N7 必须写进本章、而不能只留在表格里的那个「为什么」。

对照看另外两格的分工：`not_applicable` 的 47 格是**正面读数**（文档明说这一格对该类不成立，例如第 113 行 `archive_content,decode_entry` 那句「扩展名反查与 MIME 反查分属两条通道」），脚本二会检查有没有人违反它——登记了已读数就打 `D03`（第 425—427 行，本篇累计 12 条）。而 `undocumented` 没有任何一侧的检查。所以「能不能被脚本看出来」这一条区分了 47 与 1，也把本表条件（a）与条件（b）（c）分开：只有条件（a）这一种状态在表格里留下格子，其余十一条都只能在正文里留位置。

顺带一处常被读错的乘法：R30（清单清空那一次）报 `核对项登记行=0`、`信号行数=20`、退出码 0，那 20 条全是 `D05` 的聚合行（第 371 行逐 `ITM` 打「核对项 X 在整张清单里零登记」），**20 = 核对项总数**，与对象数无关；R31（只留一行的清单）`D05=19`、`D02=10`，19 = 20 − 1，同样不是「脚本变严了」。**改 `optional`／`not_applicable` 的口径不改变档位，把 `undocumented` 改成 `required` 会让这一格立刻进入 `D02`／`D05` 的计数**——本篇只有这一格可改，改完 `D05` 的上界从 20 变成 20（聚合行按核对项名数，不按类乘），`D02` 则随对象数放大。

### 26.3 两条固定自查项

**第一条：每次把脚本输出交给下游之前，先核对汇总行的 `三件对象数` 与闭合等级行数是否相等。** 依据是 N10——R19 那一次 32 与 31 不等，差的是 `IMG_B3`，而它同时是阻断码 `S04` 的主语，看起来「已经报过了」，实际从未进入任何档位。第二处要一起核对的是 `词表词条` 与 `能力表行` 两个数：R23（把公开词表换成坏夹具那一次）读到 `词表词条=1`，脚本二不会因为「比对不了」而全部降级，它把信号行数从 397 抬到 409、打 `X08`=4 之后**仍然给出 Q2=24、Q3=5、Q4=2**，退出码 1；R22（能力表只剩 4 行那一次）读到 `能力表行=4`、`Q4=18`。也就是说词表与能力表的缺失**只被削弱、不会被放大成「全 Q4」**，而 `词表词条=1` 时那些需要引用词表值的格子等于没被检查过（N6、N7 两条边界同时失去机器读数）。

**第二条：退出码 0 只表示这次运行没有阻断信号，不表示输入覆盖了什么。** 与本表 12 条边界同时相关的极端形状是 R30：`三件对象数=0 核对项登记行=0 信号行数=20`、四个等级全 0、退出码 0——看起来最干净的一次运行，其实什么都没判。它与 R20（4 个对象、47 行登记、`信号行数=0`、`Q1=4`、退出码 0）不是同一件事：R20 是**合格下界**，R30 是**空输入**。把这两次混为一谈会让本表十二条边界一起被绕开。这两条自查与第 23.2 节末段同源：**不能触发的信号等于没有写过**；反过来说，没有实跑过的边界不该进这张表。

### 26.4 这张表怎么用、怎么改

三条用法：**（1）这 12 条一律不进结论。** 第 1.3 节承诺过「凡是只有厂商承诺、没有公开文档支撑的判断，一律落在第 26 章的未公开文档化边界清单里，不进结论」，本表就是这个存放处；第 27 章的三条结论没有一条落在本表任一行上。**（2）每条边界要求在台账里显式写一个值**——`not_determinable`、`not_recorded`、`not_applicable` 或对应枚举里的一个，**留空不等于承认边界**：留空会被 `S01`—`S10`、`B01`、`X01` 这类形态与引用信号计入，反而把对象推到 J4／Q4，而 J4／Q4 说的是这条登记不成立，不是说这条边界成立。**（3）跨篇引用边界时带上层号。** N1—N5 是触发与告知层的边界（第 10、11 章的观测缺口），N6—N9 是平面与层完备性的边界（第 8、12、14 章），N10—N12 是证据与方法边界（第 23 章）。引用第 17 篇的 N 系列时必须写成「17 篇 N2」——两篇各有一套 N，本篇不复用前一编任何信号码（第 2.1 节）。

改这张表的规则只有一条：**新增一个边界，必须同时给出三件东西——一个承担它的脚本码（或一条拒收规则）、一个必填的台账字段、至少一次实跑的 R 号证据。** 本表里有两条给不全：N7 有码但主语错位（`P05` 的七条实例主语全是图像类对象，这条边界只活在判据文案的括注里），N8 有字段但引用格必然失败（`V02` 在这里拦的是合格登记）。这两条因此都只能写成「本文对这一格不下判断」，不能写成倾向性表述；N12 连 R 号证据之外的东西都给不出，只能写成方法论限制。给得出三件东西的（N1、N2、N10、N11）才可以被下游当作用途限制来引用。这一规则与第 23 章的覆盖验收同源。

## 27. 结论

本章给三条结论，按证据强度从强到弱排。每条都写两件事：**靠什么成立**（本篇归档里能落到行号的读数与两支脚本的实跑累计）与**靠什么不成立**（这一条不能被读成什么）。三条结论都不落在第 26 章的任何一条边界上——第 26 章那十二条说的是「公开文档没给，所以本文不能往哪一步走」，本章说的是「公开文档给了，所以本文能往哪一步走」；两者是同一条通路的两侧，混着写会让读者把边界当成结论、或把结论当成边界。

**结论一 · 声明件、通道件、观测件两两都不闭合，而且不闭合的方向与第 17 篇相反。**（证据强度最高：两支脚本的阻断判据同时指向它，且每一段都有归档行号。）

靠什么成立。三段判定权分属三方，逐段有句：**声明权在内容生产者与承载 App**——`A/uniformtypeidentifiers_defining_file_and_data_types_for_your_app.txt:12`「When defining a type, you need to define it as an exported or imported type … If your app uses a type that this framework provides, don't redeclare it in your app's bundle」、`:14`「When importing a type from another app, don't declare your own identifier; instead, use the same type identifier as the original」，两份句子说的都是「谁来拥有这个标识」，不是「系统会怎么判」。**判定权在框架，而且判定入口不止一条**——`A/uikit_uidocument.txt:35`「determines the file type (the Uniform Type Identifier associated with the file extension)」（先读扩展名）、`A/imageio.txt:6`（图像格式与元数据由框架自己读写，类型来自字节本身）、`A/webkit_wkwebview.txt:776`「loadData:mimeType:characterEncodingName:baseURL:」（类型由调用方在参数里断言）。三条入口给出三种判定，公开文档没有一处规定它们必须一致。**两者之间没有一次可登记的握手**——全篇唯一一条优先级句是 `:88`「If both exported and imported declarations for a type exist, the exported declaration takes precedence」，它只解决「导出声明 vs 导入声明」这一对，不解决「内容里的声明 vs 扩展名反查」「断言的 MIME vs 字节嗅探」。台账侧的累计与这个结构一致：脚本一 `B01`（类型三票 UTI／MIME／扩展名全无）累计 **188**、`O02`（有观测平面却未登记读数时刻）**194**；脚本二 `T01`（三件只登记了声明件）**58**、`T02`（只有标签、标签不是类型结论）**40**、`T08`（对外表述为是但该类必需的声明格缺位）**45**。

不闭合的方向也要写清。第 17 篇的写入权在每个 App 自己手里，缺口几乎总在**读回侧**；本篇的声明权在内容生产者手里、判定权在框架手里，缺口在**两者之间那一次握手从来没有被登记过**。所以 17 篇的补救是「让读回面可核」，本篇的补救只能是「让判定过程可核」，而公开档案里没有一格记判定过程——这是第 26 章 N5 那条边界（口径密度不均）之所以存在的根因。

靠什么不成立。第一，不成立的是「把三件补齐就能闭合」：补齐需要一条公开换算句把声明面接到判定面，而第 3.4 节八处失败逐条说明这条句子在归档里不存在，第 18.3 节因此把它写成三条跨侧禁令。第二，不成立的是「本篇可以对某一条具体解析链下结论」：本篇所有公告侧读数都是聚合级（组件×CVE 对），聚合级不能当个体级用——脚本二的 X 族四个阻断码拦的就是引用侧越界：组件名不在公告全量 129 个组件里、或在全量里却不在 467 行的 crafted 子词表里、CVE 不在 330 条里、限制键不在 218 个键名里（`X01` 累计 6、`X02` 2、`X03` 2、`X04` 2）。第三，不成立的是「三票都有值就说明三票一致」：三条票源是三个独立字段，`A/uikit_uidocument.txt:35` 那条通道先读扩展名、`A/imageio.txt:6` 那条通道读字节本身，公开档案没有一处仲裁句——这正是第 24 章误区 2 拆的形状。

**结论二 · 公告面的组件列与影响句列互不校验：同一行里两列可以各说各话。**（证据强度中等：一个行级读数，两个派生器各自独立复算得到同一结果。）

靠什么成立。把 12 份安全发布的 1,266 条组件×CVE 记录按「影响句是否写明恶意构造对象」切出 467 行子集，再按 38 个解析层词形切组件名：**组件名含解析层词形的 23 个、不含的 11 个**（`C/subset-18.txt:7—9`，名单逐个给出 APFS／Calendar／CoreServicesUIAgent／CoreStorage／CoreSymbolication／GPUTools／Grapher／HFS／HomeKit／Mail／OpenBSM 及其行数）；把两列放在一起算反向错位，**影响句写明恶意构造对象、组件名却不含任何解析层词的有 46 行**，其中 `image` 16 行、`file` 19 行、`web content` 与 `font` 各 0 行（`C/readings-18.txt:54—59`）。这两组数出自两支派生器（`tools/readings18.pl` 与 `tools/subset18.pl`），彼此不调用、只读同一份归档。

这条读数直接决定筛选方式的后果：防守方按组件名筛「解析面缺陷」，会漏掉这 46 行；按影响文本筛，会漏掉那 11 个不含解析层词的组件。第 15、16 篇处理的是「两列都缺位」的负空间，第 17 篇处理「一列有、一列无」，本篇处理「同一行两列不同形」——这也是脚本二里 X 族（引用侧越界，`X05`=11／`X06`=18／`X07`=8／`X08`=6）与 T 族（三件缺位，`T01`=58／`T02`=40／`T08`=45）分成两族的设计根据：一族管你说的东西在不在公开词表里，一族管你说全了没有。

靠什么不成立。第一，不成立的是「那 46 行不属于解析面」——组件名不含解析层词只说明这一列不记载，不说明缺陷不在解析路径上。第二，不成立的是「那 11 个组件没有解析缺陷」——同理，这是列的记载范围问题。第三，不成立的是「把两列做交集就能得到解析面缺陷全集」：交集会同时丢掉上面两侧，而公开档案里没有第三列可以补足。第 24 章误区 4 与误区 8 就是这两种反向读法。

**结论三 · 三处换算各自失败，两支脚本的阻断设计也不对称——这个不对称本身是结论一的实证。**（证据强度较低，但完全可核对：每一格都是实跑累计数。）

三处换算逐个给数。**其一，组件名有 ≠ 系统按内容声明判。** 声明侧的越界登记在脚本二的保留前缀三码里：`K03`（把 `public.` 前缀的类型标识登记为自己的声明）累计 **4**、`K04`（`dyn.`）**3**、`K05`（`com.apple.`）**3**，出处是 `A/uniformtypeidentifiers_defining_file_and_data_types_for_your_app.txt:29—35` 那三个保留前缀；判定侧的缺格在脚本一的 `B01`（188）与 `O02`（194）里。**其二，组件名有 ≠ 影响句写。** 就是结论二的 46 行。**其三，修复已发布 ≠ 已复位。** 复位层的四个码在脚本一里全部非阻断（`V01`—`V04` 各 3），脚本二里只有 `V05`（扩展名与 MIME 两条标签类各自成格，累计 4）——没有任何一支脚本能阻断「按公告修复版本对外称已复位」这种写法，只能靠第 20 章 O10 与第 14.3 节的再打开证明。

不对称要有数。**脚本一 71 个信号码里只有 12 个是阻断码**（第 135 行的 `S01`—`S09` 加 `K01`—`K03`），其余 59 个只登记不拦；**脚本二 60 个信号码里有 42 个阻断**（第 204—211 行：S 族 10、C 族 5、K 族 5、M 族 6、T 族 6、X 族 8、加 `V02` 与 `V06`），非阻断 18 个（D 族 5、P 族 7、`T01`—`T02`、`V01`／`V03`／`V04`／`V05`）。同一个「类型判定」对象，在单条台账层面只用形态与必备格拦（因为逐字段本身不构成对外表述），到了三件差集层面就变成大面积阻断（因为那一层的输出直接就是可对外说的话）。这个不对称不是笔误，是把「能说什么」写进判据的结果。

靠什么不成立。不成立的是「非阻断码等于可以不管」：`D02`（累计 790）与 `S08`（122）都是非阻断或半阻断量级，它们给出的是一次核对里最大的两个计数面，第 23.6 节的反向对齐就是靠这两族把重复登记暴露出来。也不成立「42 个阻断比 12 个更严格所以脚本二更好」：两支脚本的输入不同形（台账行 vs 三件清单行），阻断数不可跨脚本比较——这条正是第 3.4 节失败点 8 在本篇自身工具上的复现。

### 27.1 立场

本篇的立场是一句话：**在公开档案允许的范围内，把「这份字节被判成了什么」说成一次可登记的判定，而不是说成一个可回答的安全结论。** 这句话有三层含义，逐层给边界。

第一层，能说的：某一份被登记的对象，在哪一条通道上，被系统按哪一格判成了什么类型，哪一个面把这格的后果读回来；这三格齐备时，可以对「这一格的归属」对外表述，判据是脚本一的 J1—J4 与脚本二的 Q1—Q4 两套四档（第 19 章）。第二层，不能说的：判错会导致什么后果（公开侧没有那一类句式，第 1.3 节与本章结论一）、内容在什么时刻被解析（第 26 章 N1）、这台设备上某一份具体文件属于哪一类（本篇所有读数都是聚合级）。第三层，最容易说错的：把「公告里出现了这个组件名」读成「这个组件有解析缺陷」，或把「公告里没写」读成「没有」。

还有一条关于本篇自身的立场：**本篇的两个核验器不是产品，是口径的显式化。** 它们不接触设备、不联网、不调用任何命令行工具，只读台账文本与公开词表；这一点由第 23.1 节的二十段实证逐条给位置。读者如果把这两支脚本当成检测工具去跑，就已经越过了本篇的立场——它们能告诉你「这条台账记录说不说得出口」，不能告诉你「这台设备上有没有事」。

### 27.2 方法论：本篇是怎么把这三条结论做出来的

四步，每步都可复算。

**第一步，先把「判定权在谁手里」拆成三套词表，不给统一表。** 声明面口径（`A/uniformtypeidentifiers*.txt` 三件共 1,292 行）、通道面口径（Image I/O、Core Graphics、WebKit、Quick Look、`UIDocument`、Activity 六组）、管理与公告面口径（218 个限制键 + 1,266 行公告 + 95 条 KEV）。本篇全程不做跨表替换；第 3 章给出的八处换算失败，就是把「替换会发生什么」逐处写成句子。**这套做法的价值在负空间**：正因为没有统一表，才能把「同一行两列不同形」这件事读出来——如果一开始就把两列并成一列，结论二根本不存在。

**第二步，把每一个对外能说的字段做成一格，再给每格找一个归档行号或公开词表取值。** 本篇的十一层分解（第 4—14 章）落成一个十一层 × 责任方 × 三件 × 证据的矩阵（第 15 章），矩阵里每一格要么给出 `A/`／`B/`／`C/` 的行号，要么写「无」。「无」和「未记录」在矩阵里是两个值，不混用（第 15.1 节规矩 1）。这一步的成果是可以机器核对的：脚本二的 `V02`（引用格既不是公开词表值也不是文档行号形态）累计 70，就是「说不清出处」的格子的数量。

**第三步，两套四档判定模型 + 十一组公开读数 + 32 次实跑。** J1—J4 管单条台账能否进入对外表述，Q1—Q4 管一类对象的三件是否闭合；十一组读数（第 16 章）把「能数出来的事实」一次性摊开，任何一条结论被质疑时都能回到某一行；139 个码全部由真实夹具触发（第 23 章），也就是说每一条判据都不只是设计过，而是跑出来过。

**第四步，把不能说的集中登记，并给每条一个「为什么不是漏写」。** 第 26 章十二条边界，每条都写清缺的是哪一格、公开侧最远读到哪、台账里怎么记、哪些信号与之相关、越过这条会撞到哪个码。这一章是本篇对自己最严的一章：它给结论一和结论三标出了上限。

四步的次序不能换。跳过第一步会造出一张统一表，那张表会掩盖结论二；跳过第二步，第三步的读数就没有引用格可回指；跳过第三步，第四步就只能写成「本文不做 X」而不是「X 这一格公开档案里没有，且越界有码可拦」。

### 27.3 三条最小可执行建议

三条全部只动台账文本与公开档案，不要求任何设备侧操作、不调用任何命令行工具，也不给出任何绕过路径。

**建议一 · 把「类型三票」逐票登记，并在任一票为空时禁止对外给确认结论。** 逐票指 `typ.declared_uti`、`typ.declared_mime`、`typ.filename_ext` 三格分别填写，另加 `typ.conforms_chain` 一格记录一致性链是否声明（公开依据：`:42—46` 那句「the system can't tell if a stored item has that type」）。三格全空时只能记「无法判定」，不能记「不是某类型」——第 24 章误区 1 的正确表述把这一格的极限说得很死：能说的只是「这份内容自带一张写得合格的票」。对应判据：脚本一 `B01`（188）、`B02`（3）、`B05`（7）是非结构性信号，它们的作用是累计进该对象的信号计数、把判定压到 J2／J3（第 342—345 行的判档次序：缺必备格或命中 S／K 族直接落 J4，否则零信号 J1、一至两条 J2、三条以上 J3），真正阻断的是 `S09`（必备格缺失，累计 226）；脚本二 `T02`／`T08` 是阻断码。

**建议二 · 每一次对外表述前做一次引用格回指检查，并在系统版本更新后重跑。** 引用格只允许两种形态：本篇归档的 `A/`／`B/`／`C/` 文件加行号，或第 16 章公开词表的逐字取值；自由文本、近义词、跨平台换算句一律不接受（`V02` 累计 70 就是这一类的量级）。之所以要在版本更新后重跑，是因为观测面本身随版本变——`A/quicklook.txt:18` 与 `A/quicklook_qlpreviewcontroller.txt:22` 两次明说「The list of supported common file types may change between operating system releases」，同一份内容在不同版本上的可观测面可以不同形。对应判据：脚本二 `V01`／`V02`／`V06`、`X01`—`X08`；脚本一 `X01`（21）／`X02`（4）。

**建议三 · 解析面缺陷回查时按两种筛法各跑一遍，保存差集，并把差集当作「公开档案说不清」而不是「缺陷不存在」。** 一种按组件名过解析层词形表，一种按影响句过同一张表；本篇的实跑差集是 46 行（影响句写了恶意构造对象、组件名不含解析层词）对 11 个组件（组件名不含解析层词但行数不为零，`C/subset-18.txt:9`），两列都保留、不取交集。管理面回查同理：218 个限制键里命中内容类词形的只有 6 个（`C/readings-18.txt:92—94`），**没有一个键指名解析器或解码器**，所以「已下发限制键」不能换算成「解析面已受控」。对应判据：脚本二 `M06`（15，近义词或词形不在表内）、`X04`（限制键不在 218 键表内）、`T01`；第 20 章 O4（组件-对象一致率，反证这 46 行被误用为个体结论）给这一条的可核对表达，第 24 章误区 7 给它的反向读法。

---

**一句话收尾。** 本篇能交出去的，是一张把「一份从别处来的字节被判成什么、由谁读回来、这一格能说到哪一层」拆到可登记、可回指、可复算的表；交不出去的是任何关于「判错会发生什么」的断言——那一句在公开档案里连一个对应的句式都没有。

## 28. 参考资料

本轮存档目录 `.srcx18/`（取回日期 2026-11-03；复用件按下面「抓取与派生约定」逐件 `cmp` 核验）。**七个归档目录共 65 个文件 / 3,286,606 字节**，分组为 `A/` 12 件 / 131,942 字节 / 5,658 行、`B/` 3 件 / 756,290 字节 / 6,635 行、`C/` 7 件 / 294,705 字节 / 1,531 行、`RAW/` 12 件 / 986,170 字节、`tools/` 8 件 / 101,721 字节、`FX/` 21 件 / 985,127 字节、`IDX/` 2 件 / 30,651 字节。

正文里的每一处 `A/`、`B/`、`C/` 行号都指下面这些**文本化归档件**的行号，不是原始 JSON 或 HTML 的行号，也不是 Apple 文档站页面上的序号。逐件的承重行清单在 `IDX/sources-18.md`（本轮索引件，第 64 条）；两支脚本的判据文案里已经把这些行号写死，第 23.6 节的静态反向对齐会把每一条落回本表的某一件。

### 类型声明面与解析通道面文档（A 组 12 件 / 131,942 字节 / 5,658 行）

1. **Uniform Type Identifiers 框架页**（`A/uniformtypeidentifiers.txt`，62 行 / 2,116 字节；原始件 `RAW/uniformtypeidentifiers.json` 17,917 字节）：本篇「类型描述由内容自带、框架只做映射」这条判据的出处。**第 7 行**「The … framework provides a collection of common types that map to MIME and file types」；**第 8—20 行**「Explicitly specify relationships between types by marking them as subtypes of other types」与 `public.png` → `public.image` → `public.content`／`public.data` → `public.item` 的派生链（第 4 章、第 7 章与第 19 章的 `conforms_chain` 都落在这段）；第 25—52 行 `UTType`／`UTTagClass`／`UTTypeReference` 家族符号清单（脚本二符号词表的输入）；**第 53—54 行**「Declare uniform type identifiers to support your app's proprietary data formats.」／「Common types that the system declares.」——自定义声明与系统声明分属两份文档的公开依据；第 57—61 行五个逐字出现的公共标识（脚本二 `X05` 的词表分母）。
2. **《为你的 App 定义文件与数据类型》**（`A/uniformtypeidentifiers_defining_file_and_data_types_for_your_app.txt`，143 行 / 5,843 字节；`RAW/…json` 21,228 字节）：第 5 章（类型声明层）的主体件，也是本篇被引用最多的一件。第 9—10 行声明四步；**第 12 行**「When defining a type, you need to define it as an exported or imported type … If your app uses a type that this framework provides, don't redeclare it in your app's bundle.」；第 13 行 exported＝canonical source；**第 14 行**「When importing a type from another app, don't declare your own identifier; instead, use the same type identifier as the original.」；第 16—24 行反向 DNS 形态与字符集；**第 29—35 行**「Don't use public, dyn, or com.apple as the prefix in your app's types.」三个保留前缀逐个给出 reserved 主体（脚本二 `K03`／`K04`／`K05` 的判据）；**第 42—46 行**「make sure that it conforms to … **If your type doesn't conform to … the system can't tell if a stored item has that type.**」；第 50—52 行「Conform your type to the most specific subtype applicable.」；第 53 行「If you specify conformance to a nonpublic type, make sure that you also declare that type in your bundle.」；第 61—65 行扩展名与 MIME 标签字典写法；第 70—88 行键表（**第 78 行**「This key is required for type declarations.」、第 82 行一致性数组、**第 88 行**「If both exported and imported declarations for a type exist, the exported declaration takes precedence」——全篇唯一一处优先级句）；第 89—102 行七个键名逐条；第 115—123 行示例标识与三个保留前缀的 CODE 行；第 127—134 行 `public.data`／`com.apple.package`／`public.content`／`public.database`／`public.spreadsheet`；第 138—140 行 `greatappdoc`、`greatapp`、`public.filename-extension`。
3. **系统声明的公共类型标识清单**（`A/uniformtypeidentifiers_system_declared_uniform_type_identifiers.txt`，1,087 行 / 21,588 字节；`RAW/…json` 209,118 字节，本轮最大的一份 JSON）：类型判定面的分母件。**第 5 行**「Uniform type identifiers declare common types for resources an app loads, saves, or opens from other apps.」——本篇进入方向三条的出处；第 8—13 行扩展名标签类属性 `filenameExtension`；**第 14—19 行**同形的 MIME 标签类属性 `mimeType`；第 20—23 行 `UTTagClassFilenameExtension`／`UTTagClassMIMEType` 两条标签类标识；第 24 行起逐类型条目，「A type that represents …」共 **201 条**（读数 9，`C/readings-18.txt:99`），按类别切 12 档（`:100—111`），提及 conforming／base type／declare 的行 **67**（`:112`）。第 7 章与第 16 章的判定面分母、脚本二的声明类型词表都从这一件取。
4. **Image I/O 框架页**（`A/imageio.txt`，344 行 / 9,122 字节；`RAW/imageio.json` 80,311 字节）：第 8 章「类型来自字节本身而不是文件名」的第一条通道证据。第 3 行「Read and write most image file formats, and access an image's metadata.」；**第 6 行**「The Image I/O framework allows applications to read and write most image file formats. This framework offers high efficiency, color management, and access to image metadata.」；第 56 行 `CGImageSource`「An opaque type that you use to read image data from a URL, data object, or data consumer」（脚本一 `V02` 的复位面出处）；第 44／52／64 行元数据对象与 `CGImageMetadata` 家族；第 284 行 WebP 元数据键；第 285—286 行空间照片与 XMP 命名段。
5. **Quartz 2D（Core Graphics）框架页**（`A/coregraphics.txt`，582 行 / 10,603 字节；`RAW/coregraphics.json` 118,331 字节）：位图与 PDF 解析同样由框架本身承担的第二条通道证据。第 3 行「Handle path-based drawing, antialiased rendering, gradients, images, color management, PDF documents, and more.」；**第 6 行**「… image data management, image creation, and image masking, as well as PDF document creation, display, and parsing.」；第 19／55／95 行颜色空间、色彩转换与 ICC profile；第 174／205 行 `bitmapInfo`；第 290 行「A bitmap image or image mask.」。
6. **WebKit 框架页**（`A/webkit.txt`，34 行 / 1,743 字节；`RAW/webkit.json` 11,440 字节）：本轮最短的一件，用途是给「网页这条通道的类型口径由框架声明」。**第 6—10 行**「Display rich web content using HTML, CSS, and JavaScript」「**Display multiple MIME types and compound frame elements**」；第 25—27 行「Improve your website by optimizing it for Safari」（本篇按视角声明不进入 Safari 侧行为）。
7. **`WKWebView` 页**（`A/webkit_wkwebview.txt`，1,402 行 / 29,135 字节；`RAW/webkit_wkwebview.json` 208,179 字节）：第 8 章「调用方断言类型」的最强证据。第 13 行「a platform-native view that you use to incorporate web content seamlessly into your app's UI.」；**第 21—22 行**「Before your web view appears onscreen, load content from a web server using a `URLRequest` structure or load content directly from a local file or HTML string.」（脚本一 `A04` 的判据出处）；第 761 行 `mimeType`、第 765 行 `characterEncodingName`；**第 776 行**「`loadData:mimeType:characterEncodingName:baseURL:`」——类型与编码由调用方在参数里写死。
8. **Quick Look 框架页**（`A/quicklook.txt`，132 行 / 4,662 字节；`RAW/quicklook.json` 25,380 字节）：观测面的第一件。**第 7—13 行**受支持常见类型清单 **7 行**（iWork 与 Office／Images／Live Photos／Text files／PDFs／Audio and video files／USDZ）；第 14 行 USDZ 可进设备传感器视图；第 16 行「use … to provide advanced video playback features」；**第 17 行**「You can provide previews for your own data types by either rendering a view with your own view controller or by returning a supported preview format, such as PDF or HTML.」；**第 18 行**「The list of supported common file types may change between operating system releases.」；第 19—22 行预览扩展与 `QLSupportedContentTypes`；第 53—90 行 `QLFilePreviewRequest`／`QLPreviewItem`／`QLPreviewProvider`／`QLPreviewReply`／`QLPreviewingController`。
9. **`QLPreviewController` 页**（`A/quicklook_qlpreviewcontroller.txt`，292 行 / 8,484 字节；`RAW/…json` 50,963 字节）：**第 11 行**「can display previews for many common file types, including the following：」之后是 **第 12—21 行清单 10 行**（iWork／Office／RTF／PDF／Images／Text files（要 conforming to a UTI）／CSV／USDZ）。第 8 与第 9 两条**清单不同形**（7 行对 10 行，逐行对照见 `C/subset-18.txt:19—42`）是本篇「观测面不能引用单一文档闭合」的实证，也是脚本二把 `preview_entry`／`render_result` 分格登记的原因；第 22 行重复了「清单可能随系统版本变化」那句；第 24 行多项数据源给出导航箭头；第 25—60 行数据源与预览项协议方法；第 41 行支撑 `trg.renders_thumbnail`。
10. **`UIDocument` 页**（`A/uikit_uidocument.txt`，948 行 / 23,605 字节；`RAW/uikit_uidocument.json` 141,359 字节）：第 7 章「扩展名反查 UTI」与第 10 章「打开是一条显式生命周期动作」的主体件。**第 35 行**「… determines the file type (the Uniform Type Identifier associated with the file extension) and the document name (the filename component) from the file URL.」——本篇中心事实里引用最多的一行；第 12—16 行异步／协作读写、冲突发现、安全保存四条能力句；第 20—26 行文档型 App 定义；第 34 行「you must pass a file URL locating the document file in the app sandbox」；**第 39—43 行**「To open an existing document (**selected by the user**)…」（全篇唯一把打开动作与用户选择绑定的句子）；第 50—54 行主线程调用与完成回调；**第 56—60 行** `NSFilePresenter`「the system suspends reading until…」（第 26 章 N4 那条边界的出处）；第 476 行扩展名追加；第 566—568／577／895 行 `open` 系符号；第 578 行「Schedules a document-reading or document-writing operation on a concurrent background queue」；第 593／628／731／756 行 sandbox 四句。
11. **`UIActivityViewController` 页**（`A/uikit_uiactivityviewcontroller.txt`，272 行 / 7,859 字节；`RAW/…json` 53,753 字节）：分享通道的主体件。**第 3 行**「A view controller that you use to offer standard services from your app.」；第 10—11 行「The system provides several standard services… Apps can also define custom services.」与「Your app is responsible for configuring, presenting, and dismissing this view controller.」；第 11 行同段另有「Configuration for the view controller involves specifying the **data objects** on which the view controller should act」与「you must do so using the appropriate means for the current device… On iPad, you must present the view controller in a popover」。**这三句里没有任何自动处理的表述**——第 10.1 节据此把 `activity_share` 的登记口径收敛到「动作之后」。
12. **`application(_:open:options:)` 页**（`A/uikit_uiapplicationdelegate_application(__open_options_).txt`，360 行 / 7,182 字节；`RAW/…json` 48,191 字节）：**第 3 行**「Asks the delegate to open a resource specified by a URL, and provides a dictionary of launch options.」；**第 4 行**「Use UIScene lifecycle and `scene(_:openURLContexts:)` from `UISceneDelegate` instead.」——同一条打开语义有两套公开口径，脚本二 `open_entry` 的 `application_open` 与 `scene_openurl` 两个取值由此而来；第 49 行「This resource can be a network resource or a file」；第 51—52 行「By default, the value of this parameter is an empty dictionary」。**注意**：本件的 slug 含括号，归档文件名里的 `(__open_options_)` 不满足脚本二引用格的 `isDocRef` 形态（`^[ABC]\/[A-Za-z0-9._\/-]+:[0-9]+(-[0-9]+)?$`），所以它的行号**只能写进正文，不能写进台账的引用格**——这一件是本轮唯一为夹具特意绕开的形态陷阱。

### 执行域、隔离与管理面（B 组 3 件 / 756,290 字节 / 6,635 行）

13. **Apple Platform Security 指南文本**（`B/apple-platform-security-guide.txt`，4,885 行 / 697,288 字节，August 2026 版 PDF 文本化；与 `.srcx9`—`.srcx15`、`.srcx17` 各份为**同一版本副本，本轮 `cmp` 逐字节相同、未重抓，故 `RAW/` 里没有它的原始件**）：第 9 章（执行域层）与第 26 章若干边界的唯一来源。第 180 行版本口径句；**第 1322 行**「The signature is verified before use…」；第 1333 行 MIE 与 A19／M5；**第 1441—1443 行** BlastDoor（含**第 1442 行**全档案唯一一处对 `0-click` 下定义的句子，讲消息与身份服务）；第 1446 行锁定模式；第 1904—1908 行 Data Protection 密钥层级；**第 2344 行** quarantine（macOS 能力表内，第 26 章 N2 的全部依据）；第 2388 行「robust App Review … and robust platform protections」；**第 2391 行**「iOS, iPadOS, and visionOS help ensure runtime security by using a sandbox, declared entitlements, and Address Space Layout Randomization (ASLR).」；第 2397 行「apps can only perform background processing through system-provided APIs」（`trg.trigger_mode = background_auto` 的唯一公开支撑）；第 2404 行 ASLR；第 2446 行 App Store 全部沙箱化；**第 2557 行**自定义键盘扩展的 Open Access 与用户同意；第 4740 行 XNU 词条（code signing／sandboxing／entitlement checking／ASLR）。
14. **设备管理限制键全集**（`B/mdm-restriction-keys.txt`，220 行 / 5,453 字节；与 `.srcx17/B/` 同名件逐字节相同）：第 13 章管理面回查的分母件。**第 1—4 行是页面分段标题**（`Device Management`／`Important`／`Mac Catalyst`／`Note`），**不是键名**——按行直接取键会虚增分母，本篇一律写作「220 行 / **218 个键名**」（`C/readings-18.txt:92`）；第 5—8 行起逐行都是 `allow` 前缀小驼峰单标识；第 9 行 `allowAirDrop`、第 133 行 `allowSafari`、第 162 行 `allowedCameraRestrictionBundleIDs`。命中内容类词形的键只有 6 个、可间接约束「能否被打开／预览／联网取回」的 19 个（`:93—96`），**没有一个键指名解析器或解码器**。
15. **`Restrictions` 载荷文档全文**（`B/mdm-restrictions.txt`，1,530 行 / 53,549 字节；同上，与 `.srcx17/B/` 同名件相同）：键说明侧的落点。第 3 行载荷定义句；第 24 行「the system disables AirDrop」；**第 738 行**「the system disables the Safari web browser app, and the system removes its icon from the Home Screen. This setting also prevents users from opening web clips. Requires a supervised device…」；第 960 行 AirDrop 视为非受管投递目标。每条限制都带「Available: …」与「Requires supervision: …」两行，这是第 13.3 节「管理面只能配开关、不能逐项审阅」的形态依据。

### 公告、KEV 与派生读数（C 组 7 件 / 294,705 字节 / 1,531 行）

16. **安全发布聚合词表**（`C/advisory-18.tsv`，1,267 行 = 表头 + **1,266 条记录** / 260,925 字节；列 `file / platform / component / cve / impact / avail`）：本篇中心事实的唯一输入。由 12 份 Apple 安全内容页（`adv-149227.txt`…`adv-149589.txt`，物理位于 `.srcx16/C/pages/`，本轮复用未重抓）经 `tools/adv-parse.pl` 解析；与 `.srcx16/C/advisory-16.tsv`、`.srcx17/C/advisory-17.tsv` **逐字节相同**。1,266 条组件×CVE 对、330 个去重 CVE、129 个去重组件名、12 个平台版本行；467 行 impact 含 "maliciously crafted"。**第 78 与 226 行**是全表唯二含 `identif` 的行（Maps／`CVE-2026-112707`，App 清单泄露句）；`quarantine` 作为组件名出现 8 行（第 458—459、708—710、905—907 行），平台列逐行 macOS。
17. **CISA KEV 目录的 Apple 切片**（`C/kev-apple.tsv`，96 行 = 表头 + 95 条 / 26,154 字节；列 `cveID / vendorProject / product / dateAdded / dueDate / ransomware / shortDescription`）：从 `known_exploited_vulnerabilities.json` 按 `vendorProject == Apple` 筛出。第 2 行 `CVE-2026-86950` 同时给出 `dateAdded 2026-09-29` 与 `dueDate 2026-10-13`，是脚本一 R07 与 `S08` 日期形态校验的锚点。
18. **KEV 目录元数据**（`C/kev-apple.tsv.meta.txt`，3 行 / 79 字节）：`catalogVersion: 2026.10.30`、`dateReleased`、**`count: 1766`**。分母是 KEV **全目录**条目数而不是 Apple 条目数，本篇凡引用 KEV 比例必须带上这一格。
19. **十一组公开读数**（`C/readings-18.txt`，122 行 / 5,020 字节，`tools/readings18.pl` 只读产出）：第 16 章的主体。读数 1 语料规模（`:2—7`）、读数 2 对象词（`:9—23`，`web content` 175 行／32 CVE、`file` 164／41、`image` 105／25、`model` 37／7、`font` 34／5、`video` 25／4、`audio` 7／1、`archive` 6／3）、读数 3 后果词五类（`:25—30`）、读数 4 组件集中度、**读数 5 列间错位**（`:54—59`，46 行：`image` 16、`file` 19、`web content` 与 `font` 各 0）、**读数 6 免交互线索 = 0**（`:73—74`）、读数 7 KEV（`:76—80`，短描述含 crafted 类措辞的 CVE = 52）、读数 8 MDM 键表（`:91—96`）、读数 9 系统声明 UTI 分母（`:98—112`，201 条 / 12 档 / 67 行）、读数 10 WebKit 口径（`:114—117`，165 行中 157 含 crafted、161 含 web content）、读数 11 同一 CVE 跨平台行数（`:119—121`，单 CVE 最多 8 行、47 个 CVE 只出现 1 行）。
20. **三张子词表**（`C/subset-18.txt`，43 行 / 2,527 字节，`tools/subset18.pl` 只读产出）：第 1—10 行是公告全量与 crafted 子集（1266／129／330；467 行／34 组件／95 CVE；含解析层词形 23、不含 11 与逐个组件的行数名单在第 7—9 行；全量内但不属子集 95）；第 14—16 行是 KEV 侧读数；**第 19—42 行是 Quick Look 两份清单的逐行对照**（框架页 7 项对类文档 10 项，共有词形 8 个，只在总览出现的 `audio`／`live photo`／`video`，只在类文档出现的 `csv`／`rtf`）。
21. **读数器告警留档**（`C/readings-18.err`，0 字节）：空文件。
22. **子词表器告警留档**（`C/subset-18.err`，0 字节）：空文件。**第 21、22 两条本身就是验收项**——第 23.4 节的派生器告警检查要求这两个文件长度为 0，非 0 即说明某一组读数的输入形态发生了变化。

### 原始抓取件（RAW 组 12 件 / 986,170 字节）

23—34. 十二份 Apple 文档 JSON，与上面第 1—12 条一一对应（大小取自本轮实测，逐件列出以便重放）：`uniformtypeidentifiers.json` 17,917、`uniformtypeidentifiers_defining_file_and_data_types_for_your_app.json` 21,228、`uniformtypeidentifiers_system_declared_uniform_type_identifiers.json` 209,118、`imageio.json` 80,311、`coregraphics.json` 118,331、`webkit.json` 11,440、`webkit_wkwebview.json` 208,179、`quicklook.json` 25,380、`quicklook_qlpreviewcontroller.json` 50,963、`uikit_uidocument.json` 141,359、`uikit_uiactivityviewcontroller.json` 53,753、`uikit_uiapplicationdelegate_application(__open_options_).json` 48,191（`RAW/` 合计 986,170 字节）。**本轮没有把任何一份 JSON 直接当归档引用**：全部经 `tools/jsondump.pl` 文本化成 `A/` 后才进正文，理由见下面的约定第 2 条。

### 派生器与两支内嵌脚本（tools 组 8 件 / 101,721 字节）

35. `tools/jsondump.pl`（1,098 字节）：Apple 文档 JSON → 行式文本。
36. `tools/html2txt.pl`（1,089 字节）：HTML → 行式文本。
37. `tools/adv-parse.pl`（1,165 字节）：安全内容页 → 六列 TSV。
38. `tools/gen-tbl18.pl`（2,135 字节）：从留档日志逐码取「首现那一段运行」与「跨全部运行累计条数」，渲染成正文第 23.2 节的两张三列表（`PART/tbl1.md` 27 行、`PART/tbl2.md` 24 行）。输入为脚本路径＋日志路径＋起始 R 号＋输出文件，只读日志、不改日志。
39. `tools/readings18.pl`（9,036 字节）：十一组读数器，输出到 stdout（第 19 条）。
40. `tools/subset18.pl`（5,137 字节）：三张子词表器，输出到 stdout（第 20 条）。
41. **正文第 21 章内嵌件：解析链台账逐字段审查器**（`tools/parsing-chain-ledger-review.sh`，363 行 / 35,897 字节）：71 个信号码 + J1—J4 四档判定；阻断码只有 12 个（第 135 行的 `S01`—`S09` 加 `K01`—`K03`）；判档次序在第 342—345 行（缺必备格或命中 S／K 族 → J4，否则零信号 J1、一至两条 J2、三条以上 J3）。
42. **正文第 22 章内嵌件：解析链三件差集与公告子词表比对器**（`tools/parsing-chain-tripartite-diff.sh`，572 行 / 46,164 字节）：60 个信号码 + Q1—Q4 四级闭合；阻断码 42 个（第 204—211 行：S 族 10、C 族 5、K 族 5、M 族 6、T 族 6、X 族 8，加 `V02` 与 `V06`）；三件清单行格式、对象标识与十二个命名空间都写在它的 usage 文本里。两支脚本的逐条只读实证见第 23.1 节。

### 夹具、校验器与留档（FX 组 21 件 / 985,127 字节）

43—45. 三档台账夹具：`FX/ledger-18-good.txt`（9,779 字节）、`FX/ledger-18-mid.txt`（5,724）、`FX/ledger-18-bad.txt`（4,458）——分别对应 J1／J2—J3／J4 三种形状。
46—48. 三档三件清单夹具：`FX/tri-18-good.txt`（5,513）、`FX/tri-18-mid.txt`（2,507）、`FX/tri-18-bad.txt`（8,345）。
49—50. 三件能力表：`FX/capability-18.csv`（7,348 字节，182 行 = 2 行注释 + 180 行 = 9 个对象类 × 20 个核对项）与 `FX/capability-18-bad.csv`（497）。
51—52. 公开词表：`FX/vocab-18.tsv`（4,688）与 `FX/vocab-18-bad.tsv`（227）。**夹具合计 49,086 字节、全部为合成标识与合成取值**，不含真实文件名、真实内容正文、设备绝对路径或任何形似密钥的串。
53. `FX/code-uniqueness.pl`（1,727 字节）：校验两支脚本的信号码不重号、族内连续。
54. `FX/code-coverage.pl`（1,110 字节）：校验留档日志里每个码都至少触发过一次。
55. `FX/tbl-check.pl`（2,269 字节）：校验正文两张三列表的累计数与日志逐码累计一致。
56. `FX/run-all.sh`（4,619 字节）：脚本一的 18 次实跑驱动（good／mid／bad × 档位与形态组合）。
57. `FX/run-all-tri.sh`（2,827 字节）：脚本二的 14 次实跑驱动。
58. `FX/coverage-report.sh`（5,942 字节）：逐码可达性汇总，产出第 23.3 节的覆盖表。
59. `FX/readonly-proof.sh`（7,096 字节，96 行）：第 23.1 节二十段只读实证的执行器——P1—P10 针对脚本一、P11—P20 针对脚本二，两半结构对称。
60. **`FX/run-log.txt`（脚本一 18 次实跑留档）**与 61. **`FX/run-log-tri.txt`（脚本二 14 次实跑留档）**：两件合计 893,910 字节，是第 23.2 节两张表与第 27 章全部累计数的唯一来源。
62. `FX/coverage-proof.txt` 与 63. `FX/readonly-proof.txt`：两份验收转录，合计 16,541 字节——前者记 139 个码全部触发（71+4 与 60+4），后者记二十段实证与临时目录残留检查。

### 本轮索引（IDX 组 2 件 / 30,651 字节）

64. **`IDX/sources-18.md`（52 行）**：逐件承重行清单＋分组小结＋工具与夹具清单。它是「行号落在哪一件」的台账；正文与两支脚本判据文案里的每一处 `文件:行` 都应能在这里找到对应条目。
65. **`IDX/overlap-18.md`（51 行）**：与既有十七篇的逐篇分界表（主键选择依据、18 篇视角声明要点、语料可行性预检、本篇红线与拒收）。第 2 章的分界表与本表第 38 条的分界句都从这一件来。

### 抓取与派生约定（九条）

1. **Apple 文档 JSON 端点**：统一走 `https://developer.apple.com/tutorials/data/documentation/<slug>.json`。这些是静态可取的，而对应的 HTML 页面由 JS 渲染，直接文本化取不到正文——本轮 12 件里没有任何一件来自 HTML 页。
2. **一律先文本化再引用**：正文与脚本的行号只指 `A/`／`B/`／`C/` 三组文本件，不指 `RAW/`。同一份内容在 JSON 与文本件里的行序无关，混用会让行号失去意义。
3. **404 会返回一个同形的错误 JSON**，所以每次抓取都要同时核对 HTTP 状态与字节数——只看文件存在与否不足以判定抓到了正文。第 23 条至第 34 条逐个记了字节数就是为了这一条可复算。
4. **slug 里的 `/` 在 JSON 内转义成 `\/`**，派生器不做还原；符号名比对必须在还原形态上做，脚本二的 X 族判据即按还原形态写。
5. **文件名带括号或括号的 slug 不能进引用格**：见上面第 12 条的 `isDocRef` 形态说明。本轮的处理是把这一件的行号只写进正文。
6. **键表类页面按行取键必须先剔除分段标题**：见第 14 条（220 行 / 218 键）。直接按行数当键数会让管理面分母虚增 2。
7. **同一份清单在两份文档里不同形**：见第 8、9 两条与 `C/subset-18.txt:19—42`。凡"受支持类型清单"都必须两份并引，不取其一。
8. **复用件必须 `cmp` 而不是只比行数**：本轮三组复用（第 13、14、15、16 条）全部逐字节比对通过才写作「同一版本副本、本轮不重抓」；KEV 切片（第 17 条）与公告页输入（第 16 条的来源目录）则按目录级 `cmp` 核对。
9. **正文引句里的行内标识符是从 `RAW/` 补回的，文本件里没有它**：文本化器把 JSON 里的 `codeVoice` 片段单独成行或整段丢弃，所以 `A/` 件里凡是被反引号包围的标识符都不在句子原位——例如 `A/uniformtypeidentifiers_defining_file_and_data_types_for_your_app.txt` 的 29—35 行连起来是「Don't use ⟨空⟩, ⟨空⟩, or ⟨空⟩as the prefix in your app's types.」，`A/webkit_wkwebview.txt:21—22` 连起来是「…using a ⟨空⟩structure or load content directly…」，行内码位为空。因此本篇凡是引句中出现 `public.data`／`com.apple.package`／`URLRequest` 这类标识符，其**句子其余部分逐字来自文本件、标识符本身来自同一段 `RAW/` JSON 的 `codeVoice`**；正文行号仍指文本件的行号，补回的标识符一律写成反引号形态以便与逐字部分区分。这条约定由 `DOC/quote-audit-18.pl` 复核：它把正文代码块外的每条引句归一化后回查 `A/`／`B/`／`C/`，逐字可回指的自动通过，剩下的就是本条覆盖的标识符补回位与命令行示例，需逐处人工核对。

### 本篇没有做的事

- **没有做任何设备侧操作**：不采集 Console、不跑 `mdls`／`mdimport`／`qlmanage`／`file`／`codesign`／`spctl`／`plutil`／`sips`／`otool`／`profiles`／`sysctl`／`log`／`defaults`／`xcrun`／`mdfind`／`mdutil`，不打开任何被登记的对象，不构造任何文件。两支脚本的输入只有台账文本、三件清单、能力表与公开词表四类夹具。
- **没有构造恶意文件、没有定位解析缺陷、没有复现崩溃、没有投递载荷**，也没有给出任何绕过隔离标记、告知面板或管理面审计的做法。
- **没有把公告文本读成免交互证据**：全文对解析发生时点只写「打开／预览／分享这三类动作之后」，依据是 `C/readings-18.txt:73—74` 的 0 命中与 `B/apple-platform-security-guide.txt:1442` 的定义位置。
- **没有引用 XNU／Darwin 开源侧实现、没有引用第三方研究博客或 CVE 描述页**：本轮全部来源限于 Apple 文档 JSON、Apple Platform Security 指南文本、Apple 安全发布页与 CISA KEV 官方目录四类。
- **没有重建 Safari 行为模型、没有重建 entitlement／沙箱权限表、没有重述 SDK 名单与代码运行授权链**：分别归第 02、06、12、14 篇（逐条分界见 `IDX/overlap-18.md`）。
- **没有给每一格都配上一段文档句**：第 10.3 节与第 26 章 N5 明确区分「哪一格有文档、哪一格只有口径」，这是本篇承认的方法论限制，不是遗漏。

---

**同系列相邻篇目。** 本篇与已发布的十七篇有交接，也有硬分界：**第 01 篇（iMessage 入口与附件类型 × 解码器对照表）**——「消息接收后自动解析、渲染预览、预处理附件」那条入口时序与附件解码表归它（01 第 50、169、242—247、257 行）；本篇不论证入口是否自动触发，因为**同一份字节经 AirDrop、预览、分享或索引读回，判定可以落在三个不同的格上**，与它从哪条消息进来无关。**第 02 篇（访问控制与应用层交互）**——剪贴板读写、`UTType.png.identifier` 代码示例与权限模型归它（02 第 1472、1520、1534—1538 行）；本篇只把 `pasteboard_transfer` 当一个读数平面，因为跨 App 传递时类型标识是否被**重判**与谁能读剪贴板是两次判定。**第 05 篇（生物识别）**——「AI 功能不访问生物识别模板」（05 第 566 行）归它；解锁与否改变内容能否被呈现，不改变它被判成什么类型。**第 06 篇（XPC 与 Mach IPC）**——「公告组件名 ↔ 设备侧表现」的落差表与解析进程的宿主归属归它（06 第 11、13、138 行）；本篇的崩溃面只登记报告标识这一格。**第 07 篇（推送链路）**——载荷装配与通知服务扩展的「显示之前修改内容」归它（07 第 762、778 行）；推送链管载荷到不到，本篇管到了以后被判成什么。**第 08 篇（隐私授权与用途声明）**——同一批公告里的用途串与 required-reason 审核链归它（08 第 966 行）；本篇不能借它推任何东西，因为**解析链没有授权申报面**：内容被判成某类型不需要任何隐私键，「申报了」推不出「会被解析」。**第 09 篇（更新链与补丁传导）**——它的脚本按表头识别输入文件类型、不看扩展名也不看文件名（09 第 1553 行）；那是核验脚本自身的输入纪律，与系统的类型判定只在「表头不等于扩展名」这一条方法上同形。**第 10、11 篇（设备归属与数据副本）**——设备在谁手上、副本可不可解归它们；本篇的处理是同一份字节在两台设备上可以被判成两个类型（声明缺失时由扩展名或内容嗅探决定），所有权与副本状态都不参与这一格。**第 12 篇（第三方代码供应链）**——「组件名不是 SDK 名」（12 第 238、240、695 行）归它；本篇用同一批组件名做词表比对而不做归属主体判定，因为 `ImageIO`／`FontParser`／`ColorSync` 在解析链这一层是系统解析器的名字。**第 13 篇（日志与诊断证据链）**——sysdiagnose 的时刻—采集—导出时序（13 第 370 行）归它；本篇只允许登记报告标识，堆栈、设备路径与正文一律拒收。**第 14 篇（签名与分发授权链）**——公证票据「checked that code for malicious components」（14 第 208、244 行）与那条唯一的 `bypass Gatekeeper` 读数（第 653、701 行）归它；**恶意代码与恶意构造内容是两类对象**：签名链判代码能不能运行，本篇判内容被读成什么类型。**第 15 篇（网络扩展与代理／VPN 通道归属）**——六个通道词形在 101 个去重组件名里全部命中 0 的词形差集法归它（15 第 21、201 行）；方法与本篇同源而方向相反——本篇的组件词表**正向命中 23 个解析层组件**，并把「命中但不在恶意构造子集」做成阻断信号。**第 16 篇（本地网络访问与局域网发现）**——三件 × 对象类 × 核对项的差集口径与 `allowAirDrop` 等相邻键差集归它（16 第 17—19、190、538、2726 行）；本篇沿用差集法但把第二件换轴：16 用权限件（系统判定并持有），本篇用**通道件**（框架能否把这一格读回来），两篇对管理面的结论同形——只能关承载内容的 App 与浏览器行为，不能逐项约束判定本身。**第 17 篇（聚焦索引与 Siri 建议链路归属）**——它在第 13.3 节显式把 `Model I/O` 与 `Apple Neural Engine` 的「Processing a maliciously crafted 3D model…」读数让给下一篇（17 第 600 行），并把解析层组件名排除在它自己的公开词表之外；本篇就是接那一条的一篇。两篇的「类型标识」分属两个平面（17 第 291、1440 行的 `type_identifier` 说的是索引项声明它是什么，本篇说的是内容自带的声明被谁读回来），交接处只在视角声明。**第 19 篇（屏幕画面外流链路归属）**——一帧画面走哪条通道离开设备、落到哪儿、用户看见哪一格归它，本篇不判画面外流；两篇的「三件」里第二件含义不同，本篇的通道件是「解析器能否把这一格的类型读回来」，19 篇的通道件是「画面能否被带走」，所以本篇 `screenshot` 一词的 10 处用法讲的是内容形态标识而不是采集会话，不进入它的出流判定；反过来 19 篇直接引用本篇同一件同一行的那条负读数（含 `maliciously crafted` 的 467 行里同时出现画面语义词的为 0，19 篇 `C/readings-19.txt:56`）作为「内容侧口径与出流侧口径互不相通」的实证。各篇分界的逐条实测记于 `IDX/overlap-18.md`。

---

咨询ios系统请咨询 telegram：https://t.me/one00190
