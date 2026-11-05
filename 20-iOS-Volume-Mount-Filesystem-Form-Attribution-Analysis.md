---
title: "iOS 卷、挂载与文件系统形态归属防御分析报告"
description: "iOS 上一个卷到底是什么形态、由谁挂上来、哪一层密钥栈在保护它：十一层归属分解（L1 容器与卷结构、L2 形态声明、L3 能力承载、L4 挂载与枚举、L5 卸载与弹出、L6 容量与计数、L7 加密与密钥栈、L8 远端域与外部卷、L9 管理面回查、L10 公告对齐、L11 引用与结论），三件（形态件／挂载件／加密件）× 11 类卷 × 20 项核对项的差集口径，接口形态词表／平台安全口径词表／管理面与公告回查口径词表与八处换算失败，J1—J4 与 Q1—Q4 两套判定模型，两个离线只读核验脚本（66 + 52 个码，共 118 个全部实跑触发，34 次实跑逐码覆盖表）"
lang: zh-CN
---

# iOS 卷、挂载与文件系统形态归属防御分析报告

## 摘要

本报告集前十九篇依次回答过这些归属问题：缺陷在哪（第 01、06、07、12 篇的攻击面归属）、谁能进入这道门（第 02 篇的访问控制归属）、这条链路看见了什么（第 03、04 篇）、这台设备归谁（第 08、10、11 篇的主体归属）、这段代码凭什么被允许运行（第 14 篇的授权链归属）、这条通道凭什么存在（第 15 篇的通道归属）、同网段上谁看得见谁（第 16 篇的局域网可达性归属）、一条内容进了检索面之后谁能查回来（第 17 篇的检索面归属）、一份从别处来的内容被判成了什么类型（第 18 篇的类型判定归属）、一帧画面有没有离开这台设备（第 19 篇的画面外流归属）。本文回答系列里的第十类，也是第 11 篇（备份落点）与第 18 篇（容器形态）都引用过、却从未被正面拆解的那一格：**一个卷到底是什么形态、由谁以什么选项挂上来、这一格的数据到底在哪一层密钥栈的保护之下、这些判定在哪些面上读得回、能对外说到哪一层。**

这句话拆开是三个问句，而且三个问句的判定权分属三方，三方互不通气。**这个卷是什么形态**（`volumeTypeNameKey` 给文件系统类型名 `A/foundation_urlresourcekey_all.txt:1095`、`volumeSubtypeKey` 给「the file system subtype value」`A/foundation_urlresourcekey_all.txt:908`、`volumeLocalizedFormatDescriptionKey` 给面向用户的格式描述 `A/foundation_urlresourcekey_all.txt:861`；整套词表只有 131 个标识符，其中 volume 前缀 47 个、`volumeSupports*` 20 个、`volumeIs*` 10 个（`C/readings-20.txt:150`）——形态权在接口词表手里）；**它由谁挂上来、以什么选项挂**（`mountedVolumeURLs(includingResourceValuesForKeys:options:)`「Returns an array of URLs that identify the mounted volumes available on the device」`A/dev_filemanager_mountedvolumeurlsincludingresourcevaluesforkeysoptions_S.txt:3`，枚举选项里有一条「The enumeration skips hidden volumes」`A/dev_filemanager_volumeenumerationoptions_S.txt:76`，卸载侧「If the volume is encrypted, it is relocked after being unmounted」`A/dev_filemanager_unmountvolumeatoptionscompletionhandler_S.txt:72`——挂载权在 FileManager 与 DiskArbitration 手里）；**它的密钥栈是哪一层**（Data Protection「controlled on a per-file basis by assigning each file to a class」`A/security_data_protection_overview-S.txt:241`、Apple silicon 上的 Mac「defaults to Class C … but uses a volume key rather than a per-extent or per-file key」`A/security_data_protection_overview-S.txt:245`、Class D「protected only with the UID, and is kept in Effaceable Storage」`A/security_data_protection_classes-S.txt:272`——加密权在 Secure Enclave 与 UID 手里，且**明确不按卷形态划分，而按文件类划分**）。

本文的核心结论是这三件**两两都不闭合**，而且不闭合的方向与第 18、19 两篇都不同：18 篇的不闭合在「内容自带的声明」对「框架的判定」，19 篇的不闭合在「登记方对自己那条通道最没有读数」。本篇的不闭合更靠前一层——**公开语料里根本没有一个面向缺陷归属的「形态」维度**。同一个 `apfs` 词形，在公告的组件名列命中 8 行、`hfs` 命中 11 行、`corestorage` 命中 13 行（`C/readings-20.txt:4—6`），但在同一批公告行里，影响句列命中 `apfs`／`hfs`／`corestorage`／`exfat`／`ntfs`／`ms-dos`／`filesystem`／`volume`／`mount`／`unmount`／`automount` 的数量**全部是 0**（`C/readings-20.txt:47—51、55—58`）；`mount` 一词在影响句里只有 5 行、`disk` 7 行、`file system` 19 行，而且这 19 行涉及的 4 个组件名**没有一个含形态词**（`C/readings-20.txt:53、56、59`）。也就是说：按组件名列筛「文件系统类缺陷」会得到 32 行，按影响句筛会得到 0 行，两个 32 与 0 之间没有任何换算关系。这是本文的中心事实，也是第 22 章脚本二里 X 族与 Z 族信号码的设计根据。

比这更要紧的是一条**跨平面缺读**。管理面 216 个纯键名里，`volume`、`mount`、`unmount`、`automount`、`removable`、`fileprovider`、`smb`、`webdav`、`apfs`、`exfat` **十个词形全部命中 0 个键**，有命中的只有 `disk`=1（`allowStartupDiskModification`）、`usb`=2、`external`=4、`storage`=1、`media`=1（`C/readings-20.txt:115`）；声明类型 66 项里与盘有关的只有 `DiskManagementSettings` 一项，且它 `PLATFORM macOS 15.0 [available]`、`Allowed in user enrollment || N/A`、`Allowed in device enrollment || N/A`（`A/mdm-diskmanagementsettings-M.txt:6、18、19`）。换句话说：**iOS 侧的管理面既不知道卷是什么格式，也不知道卷挂没挂上来**；能读回的只有一条 macOS 状态项 `StatusDiskManagementFileVaultEnabled`「The status item that reports whether FileVault is enabled」`A/mdm-status-items-M.txt:73`。形态、挂载、加密这三格里，管理面只在「加密」那一格、只在 macOS 一侧、只给一个布尔值。

第三条必须前置的是**唯一一处把挂载与完整性写在同一句里的公开口径**：`iBoot is also responsible for verifying the root hash for the signed system volume (SSV), to check that the file system the kernel will mount is fully integrity verified`（`B/apple-platform-security-guide.txt:772`）。这句话给出了本层唯一一条真正的「挂载归属」读法——**挂载点由谁校验，卷的完整性就归谁**。与之配对的是 Intel T2 侧的分工差异：`the bootloader forwards the measurement and signature to the kernel, which then verifies the seal directly before mounting the root file system`（`B/apple-platform-security-guide.txt:1128`），以及 Apple silicon 侧「the bootloader verifies the seal before transferring control to the kernel」（同一行）。两套顺序不同，但都落在「mount 之前」这一格。本文据此把「校验发生在 mount 之前还是之后」做成一条**独立核对项**（脚本一的 H 族正是拦这一格），而不把「这个卷是可信的」当作可以顺推的结论。

全文有十三组可数的公开读数（第 16 章，R01—R38，每组给归档行锚）、两套四档判定模型（第 19 章）、十一层归属分解（第 4—14 章）、一个十一层 × 责任方 × 三件 × 证据的归属矩阵（第 15 章），以及两个完全离线、只读、不联网、不接触任何设备或任何被登记卷的核验脚本：卷挂载台账逐字段审查器（308 行，66 个码 = 62 个信号码 + 4 档判定）与形态／挂载／加密三件差集与公告子词表比对器（236 行，52 个码 = 48 个信号码 + 4 级闭合）。**合计 118 个码全部由真实夹具触发**，34 次实跑（脚本一 19 次、脚本二 15 次）的逐码可达性见第 23 章；两支脚本的只读性质由第 23.1 节的二十段实证（P1—P20，临时目录前缀分别是 `vol20.` 与 `vft20.`）逐条给出位置。

---

## 目录

1. [引言](#1-引言)
2. [视角声明与本文边界](#2-视角声明与本文边界)
3. [三套词表：接口形态口径、平台安全口径与管理面公告回查口径，以及八处换算失败](#3-三套词表接口形态口径平台安全口径与管理面公告回查口径以及八处换算失败)
4. [L1 容器与卷结构层：五卷、隐藏三卷与「至少两个卷」](#4-l1-容器与卷结构层五卷隐藏三卷与至少两个卷)
5. [L2 形态声明层：47 个 volume 前缀键里的三个形态读数](#5-l2-形态声明层47-个-volume-前缀键里的三个形态读数)
6. [L3 能力承载层：20 个 volumeSupports* 键](#6-l3-能力承载层20-个-volumesupports-键)
7. [L4 挂载与枚举层：谁把卷列出来、列出的是哪一类 URL](#7-l4-挂载与枚举层谁把卷列出来列出的是哪一类-url)
8. [L5 卸载与弹出层：两个选项、一个异议进程与一次重锁](#8-l5-卸载与弹出层两个选项一个异议进程与一次重锁)
9. [L6 容量与计数层：共享空闲空间让求和失效](#9-l6-容量与计数层共享空闲空间让求和失效)
10. [L7 加密与密钥栈层：卷键、文件键、区段键与 UID](#10-l7-加密与密钥栈层卷键文件键区段键与-uid)
11. [L8 远端域与外部卷层：FileProvider 域落在哪个卷上](#11-l8-远端域与外部卷层fileprovider-域落在哪个卷上)
12. [L9 管理面回查层：216 个纯键名分母与十个零命中词形](#12-l9-管理面回查层216-个纯键名分母与十个零命中词形)
13. [L10 公告对齐层：32 行、0 行与 150/78 的双向错位](#13-l10-公告对齐层32-行0-行与-15078-的双向错位)
14. [L11 引用与结论层：doc.* 与 devicemanagement 空间](#14-l11-引用与结论层doc-与-devicemanagement-空间)
15. [归属矩阵：十一层 × 责任方 × 三件 × 证据](#15-归属矩阵十一层--责任方--三件--证据)
16. [公开读数：这条链路上能数出来的十三组事实](#16-公开读数这条链路上能数出来的十三组事实)
17. [可见性边界：这一层读者能拿到什么](#17-可见性边界这一层读者能拿到什么)
18. [五个读数面：接口侧、结构侧、加密侧、管理侧、公告侧](#18-五个读数面接口侧结构侧加密侧管理侧公告侧)
19. [两套判定模型：J1—J4 与 Q1—Q4](#19-两套判定模型j1j4-与-q1q4)
20. [运营指标 O1—O10](#20-运营指标-o1o10)
21. [只读核验脚本一：卷挂载台账逐字段审查器](#21-只读核验脚本一卷挂载台账逐字段审查器)
22. [只读核验脚本二：形态／挂载／加密三件差集与公告子词表比对器](#22-只读核验脚本二形态挂载加密三件差集与公告子词表比对器)
23. [三十四次实跑与全量信号覆盖验收](#23-三十四次实跑与全量信号覆盖验收)
24. [十二个误区](#24-十二个误区)
25. [常见问题](#25-常见问题)
26. [未公开文档化边界清单](#26-未公开文档化边界清单)
27. [结论](#27-结论)
28. [参考资料](#28-参考资料)

---

## 1. 引言

### 1.1 三个问句与三段判定权

「这台设备上有一个卷」这句话，在公开语料里被拆给了三方，而且没有任何一方给出全量。

**第一方：接口词表方**。`URLResourceKey` 这一页的自述只有一句：`Keys that apply to file system URLs`（`A/foundation_urlresourcekey_all.txt:3`）。这页列出的标识符总数 131 个，其中 volume 前缀 47 个；47 个里 `volumeSupports*` 20 个、`volumeIs*` 10 个（`C/readings-20.txt:150`）。47 个键名逐个可在页内定位（`A/foundation_urlresourcekey_all.txt:756—1124`），从 `volumeAvailableCapacityForImportantUsageKey` 一直到 `volumeUUIDStringKey`。这一方给的是**属性快照**：它回答「这个卷支持不支持 X」，不回答「这个卷是什么时候、被谁、以什么选项挂上来的」。

**第二方：文件系统与容器实现方**。这一方的公开表述集中在两处。一处是开发者文档：`Apple File System replaces HFS Plus as the default file system for iOS 10.3 and later, and for macOS High Sierra and later`（`A/dev_about_apple_file_system-S.txt:5`），同页给出形态带来的六个后果：`cloning, snapshots, space sharing, fast directory sizing, atomic safe-save, and sparse files`（同一行）。另一处是平台安全文档：`Apple File System (APFS) is a proprietary file system designed with encryption in mind`（`A/security_role_of_apfs-S.txt:239`），以及容器结构的硬读数：`an APFS container used to start up the Mac needs to contain at least five volumes, the first three of which are hidden from the user`（`A/security_role_of_apfs-S.txt:243`）。这一方给的是**结构事实**：哪三个卷存在、哪三个对用户不可见、系统卷为什么写不进去。

**第三方：密钥栈方**。`Data Protection is implemented by constructing and managing a hierarchy of keys and builds on the hardware encryption technologies built into Apple devices. Data Protection is controlled on a per-file basis by assigning each file to a class; accessibility is determined according to whether the class keys have been unlocked. Apple File System (APFS) allows the file system to further subdivide the keys into a per-extent basis (where portions of a file can have different keys)`（`A/security_data_protection_overview-S.txt:241`）。这一方给的是**保护粒度**，而且这句话本身就否掉了「按卷形态归属加密强度」的直觉：粒度是文件与区段，不是卷。

三方的判定权互不交接，因此本文不把任何一格的缺失解释为「该格不存在」。本文做的是另一件事：把三方的公开读数**逐格对齐**，指出哪一格由哪一方负责、哪一格三方都不负责，并把「三方都不负责」这件事本身做成可核验的读数（第 12、13 章的 0 命中读数正是这一格）。

### 1.2 为什么这一格在系列里非拆不可

第 11 篇（备份与恢复链路数据副本归属）整篇建立在「副本落在哪个介质上」这一格上，其形态口径只能引到「internal storage」「external storage」两级；第 18 篇（非可信内容解析链路）的 L1 层把「容器形态」当作来源面的一格处理，但它回答的是「这个包是什么类型」，不是「这个包落在哪个卷上、那个卷是什么形态」；第 19 篇的 L5 层（落点与存储）明确把「落点卷的形态」列为本层不处理的格子。三篇都需要这一格，三篇都把它留成了空。

更实际的理由是一条会直接影响读数的口径：同一份「可用空间」读数，在 APFS 容器里是**共享的**。`Each volume in the container can use the shared free space, so they all include that amount when reporting the available free space`，而下一句是 `Computing the sum of each volume's available free space isn't a reliable way to determine the total free space within a partition`（`A/dev_about_apple_file_system-S.txt:19、22`）。任何按卷相加的容量台账在这个口径下都不成立；这类台账在本系列前十一篇的落点统计里反复出现。本文用第 9 章正面处理这一格，并把它写成脚本一的 E 族。

### 1.3 本文的口径边界

本文只谈**归属**与**读数**：一个卷的形态由哪个公开面声明、挂载由哪个公开面执行、加密由哪一层密钥栈承担、这三格各能在哪些面上读回、读不回的格子叫什么名字。本文不谈也不构成以下内容：不给出任何卸载保护的绕过做法，不给出任何磁盘镜像的构造或篡改步骤，不给出任何卷解锁口令的处理方法，不给出越狱或重装绕过 `LocalPolicy` 的路径。所有管理面词汇（`allowStartupDiskModification`、`DiskManagementSettings`、`ExternalStorage`/`NetworkStorage`）只作为**管理方已有的读数**被核对存在形态，不作为配置建议。所有 API 名称与键名只作为公开词表的成员被引用，本文不编写任何触发路径。第 21、22 两章的脚本只审查一份已经由读者自己登记的台账文本，既不枚举真实卷、也不访问任何设备。

---

## 2. 视角声明与本文边界

### 2.1 与系列内其他篇目的重叠界定

本篇与七篇有实质重叠，逐篇界定如下。

**与第 02 篇（访问控制与应用交互）**：02 篇处理「谁能进入这道门」，即授权与权限判定；本篇处理「这个卷是什么、由谁挂上、谁校验它」。交集只在 `volumeSupportsAccessPermissionsKey`（`A/foundation_urlresourcekey_all.txt:920`）与 `volumeSupportsExtendedSecurityKey`（`A/foundation_urlresourcekey_all.txt:973`）两个键：本篇只把它们当作形态读数（该卷能不能承载 POSIX 权限与 ACL），不讨论权限判定本身。

**与第 11 篇（备份与恢复链路数据副本归属）**：11 篇处理副本的产生、落点、密钥形态与可解性；本篇处理落点所在卷的**形态与挂载语义**。分工线：同一句「`neither external storage devices connected over USB nor PCIe-based storage added to the 2019 Mac Pro are encrypted in this fashion`」（`B/apple-platform-security-guide.txt:313`）在 11 篇里属于「可解性归属」，在本篇里属于「形态归属」——本篇只追问「这条口径把哪些卷排除在 UID 绑定之外」，不追问「备份能不能解」。

**与第 14 篇（签名与分发授权链）**：14 篇处理代码签名的授权与时效；本篇处理 SSV 的 seal 与挂载时点的校验顺序。分工线：14 篇的口径是「Mach 对象被内存映射为可执行时的保护」，本篇的口径是「从内部存储设备读取任意字节时的保护」——这句区分是公开写的：`the signed system volume provides protection when any bytes at all are read from the internal storage device. In contrast, code signing provides protection when Mach objects are memory mapped as executable`（`B/apple-platform-security-guide.txt:1131`，该节标题 `SSV and code signing` 在 `B/apple-platform-security-guide.txt:1130`）。本篇只取「读取路径上的保护」这一格。

**与第 18 篇（非可信内容解析链路与恶意构造文件）**：18 篇处理「内容被判成什么类型」；本篇处理「承载该内容所在的卷是什么形态」。两篇在 `libarchive`、`disk images` 两处组件名上有交集（`C/readings-20.txt:16、33`），本篇只把这些组件名当作公告词表成员统计，不重复 18 篇的解析链分析。

**与第 19 篇（屏幕画面外流链路）**：19 篇的 L5 落点层引用了「写到哪块存储」；本篇处理「那块存储的形态与挂载」。分工线：19 篇的落点口径是目录与进程可见性，本篇的口径是卷类型、挂载选项与密钥栈；本篇不重复任何画面采集侧内容。

**与第 22 篇（外接配件与近场配对链路归属， queued）**：本篇只在「外设承载的卷以什么形态被挂载」这一格涉及外设。配对、认证、近场信任一律不在本篇范围；`allowUSBRestrictedMode`、`allowFilesUSBDriveAccess` 两个键在本篇只作为管理面 216 键分母中的成员被计数。

**与第 23 篇（平台校验组件与度量物归属，queued）**：`cryptex`、`preboot`、`LocalPolicy` 的 4CC 字段（`spih`、`stng`、`nsih`）在本篇只作为「系统卷形态与挂载校验时点」的读数被引用（第 4、10 章），度量物本身的归属体系留给 23 篇。

### 2.2 三条硬边界

**边界一：本文不做「形态归因」的因果判断。** 公告里组件名含 `apfs` 的 8 行（`C/readings-20.txt:4`）不等于「APFS 有 8 个缺陷」。组件名是 Apple 的**归属标签**，影响句是 Apple 的**行为描述**；本文只报这两列各自的命中数与它们之间的错位（第 13 章），绝不推定「某个文件系统形态导致了某个缺陷」。

**边界二：本文不给出任何挂载/卸载的操作路径。** `unmountVolume(at:options:completionHandler:)` 与 `UnmountOptions` 的两个成员只作为**公开语义读数**引用：`Specifies that all partitions on an unmountable disk should be unmounted`（`A/dev_filemanager_unmountoptions_S.txt:54`）、`Specifies that no UI should accompany the unmount operation`（`A/dev_filemanager_unmountoptions_S.txt:70`）。后者是本篇唯一一条与「无提示」相关的公开句子，它描述的是系统 API 的选项语义，不是绕过告知的做法；本文不给出任何把它用于规避用户确认的示例。

**边界三：本文不把「管理面读不到」写成「管理面不能管」。** `volume` 词形在 216 个纯键名里命中 0（`C/readings-20.txt:115`）是一条**可见性读数**，不是一条能力读数。管理面能不能限制外接存储，与它能不能读回卷形态，是两件事：前者在 `DiskManagementSettings` 的 `ExternalStorage: Disallowed` 里明确存在（`A/mdm-diskmanagementsettings-M.txt:34`），后者在整个管理面语料里为 0。本文只报后者。

### 2.3 术语约定

为避免把「卷」「容器」「磁盘」当同义词混用，本文按公开口径固定五个层次，第 21 章脚本一的字段表也按这五层命名：

| 层 | 本文用词 | 公开出处 |
| --- | --- | --- |
| 介质 | 内部存储设备 | `the internal storage device`（`B/apple-platform-security-guide.txt:1122`） |
| 容器 | APFS container / partition | `Apple File System supports multiple volumes within a single partition`（`A/dev_about_apple_file_system-S.txt:18`） |
| 卷 | volume | `volumeTypeNameKey` 等 47 键（`A/foundation_urlresourcekey_all.txt:756—1124`） |
| 快照 | snapshot | `SSV uses Apple File System (APFS) snapshots`（`B/apple-platform-security-guide.txt:1120`） |
| 文件 | file / extent | `per-file key`、`per-extent basis`（`A/security_data_protection_overview-S.txt:241、242`） |

「形态」在本文里专指**卷这一层的可读属性集合**：类型名、子类型、格式描述、读写性、可移除性、可弹出性、是否加密、是否内部总线、是否根文件系统、是否自动挂载、挂载来源位置与重挂载 URL。它不包括内容类型（那是 18 篇），不包括设备标识（那是 10 篇）。

---

## 3. 三套词表：接口形态口径、平台安全口径与管理面公告回查口径，以及八处换算失败

本篇的三套词表分别来自三个互不引用的公开面。表一回答「接口能读出哪些形态属性」，表二回答「平台安全文档用哪些词描述卷与文件系统」，表三回答「管理面与公告面能回查哪些形态线索」。三套词表的规模与命中数全部是可数读数，逐条给归档行锚。

### 3.1 表一：接口形态口径（47 个 volume 前缀键 + 6 个非 volume 前缀的挂载键 + 3 组选项）

`URLResourceKey` 页的自述是 `Keys that apply to file system URLs`（`A/foundation_urlresourcekey_all.txt:3`）。本页标识符总数 131，volume 前缀 47，非 volume 前缀 84（`C/readings-20.txt:150、151`）。47 个键按语义分八组，键名与行号一一对应：

| 组 | 成员（键名 / 页内行号） | 计数 |
| --- | --- | --- |
| 形态声明 | volumeTypeNameKey:1098、volumeSubtypeKey:911、volumeLocalizedFormatDescriptionKey:865、volumeLocalizedNameKey:873 | 4 |
| 存在与拓扑 | volumeIsRootFileSystemKey:857、volumeIsInternalKey:822、volumeIsLocalKey:836、volumeIsBrowsableKey:801、volumeURLKey:1115、volumeResourceCountKey:904 | 6 |
| 挂载语义 | volumeIsAutomountedKey:794、volumeMountFromLocationKey:889、volumeURLForRemountingKey:1107、isMountTriggerKey:368 | 4 |
| 弹出与移除 | volumeIsEjectableKey:808、volumeIsRemovableKey:850 | 2 |
| 读写与加密 | volumeIsReadOnlyKey:843、volumeIsEncryptedKey:815、volumeIsJournalingKey:829 | 3 |
| 容量 | volumeTotalCapacityKey:1091、volumeAvailableCapacityKey:770、volumeAvailableCapacityForImportantUsageKey:756、volumeAvailableCapacityForOpportunisticUsageKey:763、volumeMaximumFileSizeKey:882、volumeSupportsVolumeSizesKey:1076 | 6 |
| 身份与时间 | volumeIdentifierKey:787、volumeUUIDStringKey:1124、volumeCreationDateKey:779 | 3 |
| 能力承载 | volumeSupports*：AccessPermissions:920、AdvisoryFileLocking:930、CasePreservedNames:938、CaseSensitiveNames:946、Compression:955、ExclusiveRenaming:965、ExtendedSecurity:973、FileCloning:982、FileProtection:989、HardLinks:997、ImmutableFiles:1007、Journaling:1015、PersistentIDs:1023、Renaming:1031、RootDirectoryDates:1039、SparseFiles:1047、SwapRenaming:1057、SymbolicLinks:1065、VolumeSizes:1076、ZeroRuns:1084 | 20 |

表一有三条结构读数。**其一**，`volumeIs*` 恰好 10 个（`C/readings-20.txt:150`），十个全是布尔属性快照，没有一个带时点。**其二**，键名里含 `mount` 的只有 4 个：`isMountTriggerKey`、`volumeIsAutomountedKey`、`volumeMountFromLocationKey`、`volumeURLForRemountingKey`（`C/readings-20.txt:153`）；含 `eject`／`unmount`／`remov` 的只有 2 个：`volumeIsEjectableKey`、`volumeIsRemovableKey`（`C/readings-20.txt:154`）。表里含 `unmount` 的键是 0 个。**其三**，47 键里没有任何一键的键名或定义提到密钥层级；与加密有关的两键是 `volumeIsEncryptedKey`（定义：`A key for determining whether the volume is encrypted.`，`A/foundation_urlresourcekey_all.txt:812、815`）与 `volumeSupportsFileProtectionKey`（定义：`A Boolean value that indicates the volume supports data protection for files.`，`A/foundation_urlresourcekey_all.txt:986、989`）。一个是卷级布尔，一个是「这个卷支不支持逐文件保护」的能力声明，两者都不是保护强度读数。

表一之外还有三组选项型口径，同属接口形态：

| 组 | 公开句子 | 出处 |
| --- | --- | --- |
| 枚举选项 | The enumeration produces file reference URLs rather than path-based URLs | `A/dev_filemanager_volumeenumerationoptions_S.txt:67` |
| 枚举选项 | The enumeration skips hidden volumes | `A/dev_filemanager_volumeenumerationoptions_S.txt:76` |
| 枚举入参 | An array of keys that identify the file properties that you want pre-fetched for each volume | `A/dev_filemanager_mountedvolumeurlsincludingresourcevaluesforkeysoptions_S.txt:37` |
| 卸载选项 | Specifies that all partitions on an unmountable disk should be unmounted | `A/dev_filemanager_unmountoptions_S.txt:54` |
| 卸载选项 | Specifies that no UI should accompany the unmount operation | `A/dev_filemanager_unmountoptions_S.txt:70` |
| 卸载失败 | The process identifier of the process that prevented a volume from unmounting | `A/dev_filemanager_unmountoptions_S.txt:101` |
| 卸载后态 | If the volume is encrypted, it is relocked after being unmounted | `A/dev_filemanager_unmountvolumeatoptionscompletionhandler_S.txt:72` |

这七句是公开语料里**仅有的**把挂载与卸载动作写成语义的条目，全部在接口侧。第 8 章逐条处理。

### 3.2 表二：平台安全口径（4,886 行正文里的十五个词形计数）

`B/apple-platform-security-guide.txt` 正文 4,886 行，十五个词形的总出现次数（`C/readings-20.txt:128`）：

| 词形 | 次数 | 词形 | 次数 |
| --- | --- | --- | --- |
| Data Protection | 141 | file system | 39 |
| volume | 135 | APFS | 28 |
| FileVault | 77 | mount | 25 |
| keybag | 64 | cryptex | 24 |
| Apple File System | 10 | read-only | 11 |
| mounted | 7 | removable | 6 |
| snapshot | 5 | external storage | 2 |
| preboot | 4 | | |

含 volume／mount／APFS／cryptex／preboot 任一词形的正文行合计 **99 行**（`C/readings-20.txt:129`）。表二与表一的换算关系是**单向**的：表一的 47 个键名，几乎每一个都能在表二找到对应的概念段落；表二的 99 行里描述的容器、快照、seal、密钥层级，绝大部分在表一**没有一个键能读回**。最典型的三格：`snapshot`（表二 5 次）在表一 0 键；`preboot`（表二 4 次）在表一 0 键；`keybag`（表二 64 次）在表一 0 键。第 26 章把这三种「文档有词、接口无键」的格子列为未公开文档化边界的三条。

### 3.3 表三：管理面与公告回查口径

表三是两个分母叠在一起。管理面分母：`B/mdm-restriction-keys.txt` 纯键名 216 行（`C/readings-20.txt:102`）+ 声明类型 66 项（`C/readings-20.txt:141`，逐项见 `C/mdm-declarations.txt`）+ 状态项与命令集合。公告面分母：安全公告记录行 1,266、平台去重 12、组件名去重 129、唯一 CVE 330（`C/readings-20.txt:1`），CISA KEV 里 Apple 条目 95 条（`C/readings-20.txt:100`）。

表三对形态词表的命中数是这篇报告最关键的一组分母对照，逐词形给出：

| 词形 | 管理面 216 键（`C/readings-20.txt:115`） | 公告组件名列（`C/readings-20.txt:4—45`） | 公告影响句列（`C/readings-20.txt:47—88`） | KEV Apple 条目（`C/readings-20.txt:100） |
| --- | --- | --- | --- | --- |
| volume | 0 | 0 | 0 | 0 |
| mount | 0 | 0 | 5 行／3 组件 | 0 |
| unmount／automount | 0 | 0 | 0 | 0 |
| apfs | 0 | 8 行／1 组件 | 0 | 0 |
| hfs | 0 | 11 行／1 组件 | 0 | 0 |
| corestorage | 0 | 13 行／1 组件 | 0 | 0 |
| exfat／ntfs／ms-dos | 0 | 0 | 0 | 0 |
| file system | 0 | 0 | 19 行／4 组件 | 0 |
| disk | 1 | 6 行／2 组件 | 7 行／4 组件 | 0 |
| storage | 1 | 54 行／5 组件 | 0 | 1 |
| usb | 2 | 5 行／1 组件 | 5 行／1 组件 | 1 |
| external | 4 | 0 | 0 | 0 |
| removable／ejectable | 0 | 0 | 0 | 0 |
| cryptex | 0 | 3 行／1 组件（libcryptex） | 0 | 0 |
| preboot／snapshot／clone | 0 | 0 | 0 | 0 |
| data protection／keybag | 0 | 0 | 0 | 0 |
| sandbox | — | 1 行／1 组件 | 51 行／14 组件 | 3 |
| media | 1 | 33 行／3 组件 | 10 行／2 组件 | 1 |

KEV 里写明 volume／mount／file system／APFS 任一词形的条目数 = **0**（`C/readings-20.txt:101`）。管理面 216 键里与盘有关的只有 `allowStartupDiskModification` 一键（`C/readings-20.txt:106`、`B/mdm-restriction-keys.txt:144`），与 `storage` 有关的只有 `allowAirPrintCredentialsStorage` 一键且其语义是打印凭据缓存（`C/readings-20.txt:113`、`B/mdm-restriction-keys.txt:12`）——**这是一个词形巧合，不是一个存储形态读数**。这类假命中在第 21 章脚本一里由 D 族（D09）单独拦截。

### 3.4 八处换算失败

以下八处是表一／表二／表三之间**不能直接换算**的位置。每一处给失败原因与对应章节。

**F1 组件名列命中换不到影响句列命中。** `apfs`／`hfs`／`corestorage` 三个词形在组件名列合计 8+11+13 = 32 行（`C/readings-20.txt:4—6`），在影响句列合计 0 行（`C/readings-20.txt:47—49`）。因此「按组件名统计出的文件系统类缺陷数」与「按影响句统计出的文件系统类缺陷数」是两个没有换算关系的数。见第 13 章。

**F2 反向同样失败，而且规模更大。** 影响句含 `mount` 的 5 行、含 `disk` 的 7 行、含 `file system` 的 19 行，其组件名列前 20 位是 `packagekit`=7、`app store`=6、`coreaudio`=6、`quarantine`=6、`security`=6、`bom`=5、`printing`=4、`webkit`=4（`C/readings-20.txt:91`）——没有一个含形态词。全量双向错位：组件名含形态词而影响句不含 = 150 行；影响句含而组件名不含 = 78 行（`C/readings-20.txt:89`）。见第 13 章。

**F3 47 键里没有「挂载时点」这一维。** `volumeIsAutomountedKey` 的定义只说「whether the volume is automounted」（`A/foundation_urlresourcekey_all.txt:790`），是一个状态布尔；`volumeMountFromLocationKey` 只说「The key for the volume mounted-from location」（`A/foundation_urlresourcekey_all.txt:886`），是一个来源位置；两者都不带时间戳。表二的 99 行里则大量按时间叙述（boot 序列、mount 前校验）。**状态口径换不到时点口径**，因此本文在任何表格里都不写「卷挂载时间」这一列，只写「挂载读数来源」。见第 7、17 章。

**F4 容量读数不可求和。** `Each volume in the container can use the shared free space, so they all include that amount when reporting the available free space`，且 `Computing the sum of each volume's available free space isn't a reliable way to determine the total free space within a partition`（`A/dev_about_apple_file_system-S.txt:19、22`）。同一卷上的 `volumeAvailableCapacityKey`、`...ForImportantUsageKey`、`...ForOpportunisticUsageKey` 三键定义各自只写「Key for the volume's available capacity in bytes …（read-only）」（`A/foundation_urlresourcekey_all.txt:753、760、767`），三者之间没有公开加减关系。**容量类读数只能逐卷引用，不能相加、不能互推。** 见第 9 章与脚本一 E 族。

**F5 卷级加密布尔换不到文件级保护类。** `volumeIsEncryptedKey` 只回答「这个卷是不是加密的」（`A/foundation_urlresourcekey_all.txt:812`）；表二的保护粒度是「controlled on a per-file basis by assigning each file to a class」（`A/security_data_protection_overview-S.txt:241`），而且在 Mac 上「Data Protection defaults to Class C … but uses a volume key rather than a per-extent or per-file key」（`A/security_data_protection_overview-S.txt:245`）。同一句又写在表二两处（`B/apple-platform-security-guide.txt:1912`、`A/security_data_protection_classes-S.txt:250`：`macOS uses a volume key to recreate FileVault protection characteristics`）。**「卷加密 = 全卷同强度保护」在 iOS 侧不成立，在 macOS 侧成立但语义是「复刻 FileVault」而不是「更强」。** 见第 10 章。

**F6 卸载后重锁语义只存在于接口侧一处。** `If the volume is encrypted, it is relocked after being unmounted`（`A/dev_filemanager_unmountvolumeatoptionscompletionhandler_S.txt:72`）是全语料里唯一一句把「卸载」与「重锁」写在一起的公开句子；管理面 216 键、声明类型 66 项、公告两列对 `unmount` 的命中全是 0（`C/readings-20.txt:14、57、115`）。**这条语义无法在任何管理面或公告面上交叉验证**，本文因此把它列为「单源读数」，并在第 17 章的可见性边界里单独标出。

**F7 管理面对卷形态 0 读数，唯一相关格是 macOS 侧一个布尔。** 声明类型 66 项里与盘有关的只有 `DiskManagementSettings`（`C/readings-20.txt:145`），它的可用性行是 `PLATFORM macOS 15.0 [available]`、`Allowed in device enrollment || N/A`、`Allowed in user enrollment || N/A`、`Allowed in system scope || macOS`（`A/mdm-diskmanagementsettings-M.txt:6、18、19、21`）；状态项侧唯一的一条是 `StatusDiskManagementFileVaultEnabled`，定义 `The status item that reports whether FileVault is enabled.`（`A/mdm-status-items-M.txt:73`）。**iOS 侧既读不到卷形态，也读不到卷加密态**；管理面在这两格上是空分母，不是弱分母。见第 12 章。

**F8 恶意构造子集对形态几乎不敏感。** 含 `maliciously crafted` 的 467 行、组件去重 34（`C/readings-20.txt:92`）里，组件名命中卷／形态词形的只有 24 行（`C/readings-20.txt:93`），明细只有 7 个「影响句词形 ≤ 组件名」配对：`apfs<=apfs`、`archiveservice<=archive`、`corestorage<=corestorage`、`corestorage<=storage`、`hfs<=hfs`、`libarchive<=archive`、`libarchive<=libarchive`（`C/readings-20.txt:94`）。注意后四个配对里的 `archive` 与 `storage` 是**词形碰撞**：`Archive Service`／`libarchive` 处理归档容器，`CoreStorage` 处理逻辑卷，两者与「恶意构造的文件系统镜像」不是同一件事。**按形态词筛恶意构造子集会引入碰撞行**；本文对这类配对一律标注碰撞并单独计数。见第 13 章与脚本二 Z 族。

### 3.5 三套词表的使用规则

后续各章与两个脚本按以下三条规则使用三套词表：

1. **一格只允许由它自己的口径填。** 形态格用表一填，结构与时点格用表二填，回查格用表三填。跨口径填格必须在同一行标注 `换算失败` 与对应的 F 编号。
2. **0 命中要写成 0，不写成「不适用」。** 表三有七个词形是 0 命中（volume、mount、unmount、removable、apfs、exfat、snapshot），这些 0 本身是本篇的读数，不是缺测。
3. **词形碰撞单独标。** `storage` 撞上打印凭据、`archive` 撞上归档容器、`sandbox` 撞上容器目录：三处碰撞在第 13 章逐条列出，并从形态分子里剔除后再计数。

---

## 4. L1 容器与卷结构层：五卷、隐藏三卷与「至少两个卷」

### 4.1 本层回答什么

L1 回答的是最靠前的一个问题：**在这台设备上，「一个卷」这个计数单位从哪里来。** 这一格决定后面所有台账的粒度。如果台账按「卷」登记，而系统按「容器」共享空间、按「快照」提供回滚，那么按卷登记的每一行都携带一个隐含假设：卷与容器、卷与快照之间是 1:1。公开口径明写这个假设不成立。

### 4.2 三条结构读数

**读数一：Mac 上至少五个卷，前三个对用户隐藏。** `In macOS 10.15 or later, an APFS container used to start up the Mac needs to contain at least five volumes, the first three of which are hidden from the user`（`A/security_role_of_apfs-S.txt:243`）。三个隐藏卷各自有独立的加密态声明：

| 卷 | 公开加密态 | 出处 |
| --- | --- | --- |
| Preboot | This volume is unencrypted and contains data needed for booting each system volume in the container | `A/security_role_of_apfs-S.txt:244` |
| VM | This volume is unencrypted and is used by macOS for storing encrypted swap files | `A/security_role_of_apfs-S.txt:245` |
| Recovery | This volume is unencrypted and needs to be available without unlocking a system volume to start up in recoveryOS | `A/security_role_of_apfs-S.txt:246` |
| System | Contains the following…；By default, no process can write to the System volume, even Apple system processes | `A/security_role_of_apfs-S.txt:247、250` |
| Data | Contains data that's subject to change | `A/security_role_of_apfs-S.txt:251` |

同页还有一句结构性补充：`A data volume is created for each additional system volume. The preboot, VM, and recovery volumes are all shared and not duplicated`（`A/security_role_of_apfs-S.txt:256`）。这一句是本层的**计数换算规则**：多系统卷场景下 Data 卷数量与 System 卷数量同步增长，而三个隐藏卷不增长。因此「卷数」不是「安装数」的代理读数。

**读数二：iOS／iPadOS／visionOS 上是「至少两个卷」。** `On devices with iOS, iPadOS, and visionOS, storage is divided into at least two APFS volumes: System volume / Data volume`（`A/security_role_of_apfs-S.txt:258、259、260`）。这条是本报告系列里 iOS 侧最直接的形态读数：**iPhone 与 iPad 的公开口径只声明两个卷**，因此第 8、11 章处理远端域落点与备份落点时，「落在哪个卷」的公开答案空间是「Data 卷」或「未公开」，不存在第三种公开选项。

**读数三：系统卷是从快照启动的，不是从可变卷的只读挂载启动的。** `On devices with macOS 11 or later, the system volume is captured in a snapshot. The operating system boots from a snapshot of the system volume, not just from a read-only mount of the mutable system volume`（`A/security_role_of_apfs-S.txt:257`）。这一句给出了本篇唯一一个把「快照」「只读挂载」「启动」三格绑在一起的公开句子，也是第 10 章挂载校验时点的起点。

### 4.3 容器与分区的形态差别

接口侧对容器形态有一句明确的对照：`Many files systems, including HFS Plus, support only a single volume per partition. Because free space can't be shared across partitions, each volume's size is set when partitioning the storage device, and each volume can only grow into its available free space. In contrast, Apple File System supports multiple volumes within a single partition, which allows all of those volumes to share their free space. All of the volumes in an APFS partition can grow and shrink independently`（`A/dev_about_apple_file_system-S.txt:18、19`）。这段话给出两条归属结论：**其一**，「卷的大小」在 APFS 下不是分区时刻定死的，因此任何按「卷容量」做的固定分配判断都过期得很快；**其二**，HFS Plus 与 APFS 的差别不在功能列表而在**空间归属单位**（分区 vs 容器），这决定了 L6 容量层能不能求和（见 F4）。

同页给出的形态替换时点是一条硬事实：`Apple File System replaces HFS Plus as the default file system for iOS 10.3 and later, and for macOS High Sierra and later`（`A/dev_about_apple_file_system-S.txt:5`）。这条与公告侧的读数配对起来看才有意义：`hfs` 词形在组件名列仍有 11 行（`C/readings-20.txt:5`），说明**已替换的形态仍留在归属标签里**，这是 F1 的一个具体样本——组件名列的 `hfs` 11 行不构成「HFS 仍在被使用」的读数。

### 4.4 系统卷的完整性归属

结构层的最后一格是「谁校验系统卷」。表二给了分工：

- `iBoot is also responsible for verifying the root hash for the signed system volume (SSV), to check that the file system the kernel will mount is fully integrity verified`（`B/apple-platform-security-guide.txt:772`）
- `the bootloader verifies the seal before transferring control to the kernel`（Apple silicon）与 `the bootloader forwards the measurement and signature to the kernel, which then verifies the seal directly before mounting the root file system`（Intel + T2），两句同在 `B/apple-platform-security-guide.txt:1128`
- `Users aren't allowed to turn off the protection of a signed system volume on iOS and iPadOS`（`B/apple-platform-security-guide.txt:1129`）
- `During iOS and iPadOS software updates, the system volume is prepared and recomputed in a similar fashion`（同一行 1129）

四条合起来给出的归属结论是：**iOS 侧系统卷形态的完整性判定权在启动链，且对用户与管理面都不可配置**；管理面在这格的读数是 0（`C/readings-20.txt:115`）。因此本篇不把「系统卷是否被篡改」写成一条可回查项，只写成一条不可配置项。seal 的定义在 `B/apple-platform-security-guide.txt:1122`：`the root node's hash value, called a seal, encompasses every byte of data in the SSV`；这一格与表一的对应关系是 0 键——接口词表里没有 `seal`，也没有任何 `volumeSupportsSealedKey`。这是 F3 之外最干净的一条「文档有词、接口无键」样本，列入第 26 章。

### 4.5 本层的核对项

| 编号 | 核对项 | 需要的读数 | 来源面 |
| --- | --- | --- | --- |
| L1-a | 卷数与容器数是否分开登记 | 每容器卷数、隐藏卷数 | 表二（结构） |
| L1-b | 三个隐藏卷的加密态是否逐卷登记 | preboot/VM/Recovery 三条 unencrypted 声明 | 表二 `:244—246` |
| L1-c | Data 卷是否随系统卷成对增长 | 附加系统卷数 | 表二 `:256` |
| L1-d | 是否把「只读挂载」与「从快照启动」混为一格 | snapshot 启动声明 | 表二 `:257` |
| L1-e | seal 校验发生在 mount 之前还是之后 | 分工差异 | 表二 `:772、1128` |
| L1-f | iOS 侧是否承认「至少两个卷」之外的卷 | 平台口径 | 表二 `:258` |

L1-b、L1-c、L1-d 三条在接口词表里都没有对应键（表一 47 键里 snapshot 0 个、preboot 0 个、隐藏卷只有一个枚举选项 `skips hidden volumes`）。这三条因此构成 L1 层的三个管理面与接口面双盲格。

---

## 5. L2 形态声明层：47 个 volume 前缀键里的三个形态读数

### 5.1 本层回答什么

L2 回答「这个卷是什么格式」。公开口径里能承担这一格的只有三个键：`volumeTypeNameKey`、`volumeSubtypeKey`、`volumeLocalizedFormatDescriptionKey`。三个键的定义各自只有一句话，都在同一页：

| 键 | 公开定义 | 行号 |
| --- | --- | --- |
| volumeTypeNameKey | The key for the name of the file system type | `A/foundation_urlresourcekey_all.txt:1095、1098` |
| volumeSubtypeKey | The key for the file system subtype value | `A/foundation_urlresourcekey_all.txt:908、911` |
| volumeLocalizedFormatDescriptionKey | Key for the volume’s descriptive format name, returned as an object (read-only) | `A/foundation_urlresourcekey_all.txt:861、865` |
| volumeLocalizedNameKey | The name of the volume as it should be displayed in the user interface, returned as an object (read-only) | `A/foundation_urlresourcekey_all.txt:869、873` |

这里要写的第一个事实是：**四个键里没有一个给出取值域。** `volumeTypeNameKey` 只说「the name of the file system type」，不列合法值；`volumeSubtypeKey` 只说「the file system subtype value」，不说明它是数值还是字符串、不说明编码方式；`volumeLocalizedFormatDescriptionKey` 与 `volumeLocalizedNameKey` 两句定义分别落在「descriptive format name」与「as it should be displayed in the user interface」上（`A/foundation_urlresourcekey_all.txt:861、869`），两句都只描述展示形态，都不与类型名建立等式。也就是说，公开接口口径给出的是**四个空槽加一条展示名**，而不是一个形态词表。这就是为什么本篇必须引入第二处来源——支持文档里那份真正列出取值的清单。

顺带先登记一条与 L4 相关的定义范围差：`volumeURLForRemountingKey` 的定义是 `Key for the URL needed to remount the network volume, returned as an object, or if a URL is not available (read-only)`（`A/foundation_urlresourcekey_all.txt:1102、1107`）。四个 mount 语义键里唯一能给出「重挂载 URL」的这一键，公开定义把适用范围写在 **network volume** 上。本地卷没有对应的重挂载 URL 键。第 7 章据此规定：台账里出现「重挂载 URL」这一格时，必须同时登记卷类是否为网络卷，否则该格悬空（脚本一的 H04）。

### 5.2 唯一列出取值域的公开清单，在非安全文档里

`If you can read files from an external storage device that is directly connected to your Mac, but you can't write files to it, try these solutions`（`A/mac_cant_save_files_external_drive-S.txt:18`）之后是一段直接列出形态取值域的文本：

```
In the Info window that opens, the listed Format should be one of the formats available in Disk Utility :
APFS or Mac OS Extended: These are Mac formats.
MS-DOS (FAT) or ExFat: These are Windows-compatible formats.
Disk Utility does not support NTFS format, which your Mac might be able to read from, but not write to.
If the storage device isn't using one of these formats, use Disk Utility to erase and reformat the storage device .
```

出处：`A/mac_cant_save_files_external_drive-S.txt:24、25、26、27、28`。

这段文本是本篇最重要的一处**跨平面错位**：全语料里唯一把 `APFS`／`Mac OS Extended`／`MS-DOS (FAT)`／`ExFat`／`NTFS` 五个形态取值并列列出，并给出读写后果（`NTFS … might be able to read from, but not write to`）的地方，是一篇故障排查支持文档，而不是任何一份安全文档、一份接口文档或任何一份公告。与之对照：`exfat`、`ntfs`、`ms-dos` 三个词形在公告组件名列与影响句列**都是 0 行**（`C/readings-20.txt:7、8、9、50、51、52`），在管理面 216 键里也全是 0（`C/readings-20.txt:115`）。

这条错位给出 L2 的一条硬结论：**Windows 兼容形态在 Apple 的安全归属口径里是不可见的**。它不是「风险低」，而是「没有任何一个安全面承载这个词形」。因此本篇规定：任何把「卷是 exFAT/NTFS」当作安全属性的表述，都没有公开归属口径支撑，只能作为运维描述使用（第 24 章误区 M04 正是这一条）。

### 5.3 只读性、可移除性与可弹出性：三个正交布尔

表一里与「这个卷会不会被拿走」有关的三个键是：`volumeIsReadOnlyKey`（`A key for determining whether the volume is read-only.`，`A/foundation_urlresourcekey_all.txt:840、843`）、`volumeIsRemovableKey`（`A key for determining whether the volume is removable from the drive mechanism.`，`A/foundation_urlresourcekey_all.txt:847、850`）、`volumeIsEjectableKey`（键名 `A/foundation_urlresourcekey_all.txt:808`）。三句定义揭示了三格互不等价：`removable` 说的是**驱动机构**层面能不能取出，`ejectable` 说的是有没有弹出接口，`read-only` 说的是当前写权限状态。一篇支持文档给出的运维表述与此一致：读得到写不进，第一动作是「Check the format」（`A/mac_cant_save_files_external_drive-S.txt:21`）而不是检查挂载选项。

同族还有 `volumeIsBrowsableKey`：`A key for determining whether the volume is visible in GUI-based file-browsing environments, such as the Desktop or the Finder app.`（`A/foundation_urlresourcekey_all.txt:798、801`）。这一键与 L4 的枚举选项 `skips hidden volumes`（`A/dev_filemanager_volumeenumerationoptions_S.txt:76`）是一对**跨口径同名不同域**：一个是「在 GUI 文件浏览环境里可见」，一个是「枚举时跳过隐藏卷」，两者不保证同一集合。这是本篇列出的第九类观察，归入第 17 章可见性边界。

### 5.4 内部总线与本地性：两个决定归属的布尔

`volumeIsInternalKey` 定义是 `A key for determining whether the volume is connected to an internal bus.`（`A/foundation_urlresourcekey_all.txt:819、822`）；`volumeIsLocalKey` 键名在 `A/foundation_urlresourcekey_all.txt:836`。这两个键是本篇唯一一组能与管理面口径对上语义的接口读数，因为表二的 UID 绑定判断正是按「是否内部」切开的：`On a Mac, only fully internal storage linked to the AES Engine receives this level of encryption. For example, neither external storage devices connected over USB nor PCIe-based storage added to the 2019 Mac Pro are encrypted in this fashion`（`B/apple-platform-security-guide.txt:313`）。

这条对齐是 L2 与 L7 之间唯一一条可换算的路径，而且它只往一个方向走：**「非内部」可以推「不享受 UID 绑定的那层加密」**；「内部」不能推「享受」，因为 313 行还额外要求 `fully internal storage linked to the AES Engine`——`linked to the AES Engine` 是第三个条件，接口词表里没有对应的键。因此本篇规定：`volumeIsInternalKey == true` 只能登记为「未排除」，不能登记为「受 UID 绑定保护」。脚本一的 D06 码正是拦这一格误推。

### 5.5 根文件系统与卷 URL：两个定位键

`volumeIsRootFileSystemKey`：`A key for determining whether the volume is the root file system.`（`A/foundation_urlresourcekey_all.txt:854、857`）。`volumeURLKey`：`The root directory of the resource's volume, returned as an object (read-only).`（`A/foundation_urlresourcekey_all.txt:1112、1115`）。另有一条与容器根目录判定相关的定义：`Key for determining whether the resource is the root directory of a volume, returned as a Boolean`（`A/foundation_urlresourcekey_all.txt:439`）。三键合起来构成「定位」这一格的全部公开读数。本层要指出的是：定位格只回答「在哪」，不回答「由谁挂上」——后者需要 `volumeMountFromLocationKey` 与 `volumeURLForRemountingKey`，见第 7 章。

### 5.6 本层核对项

| 编号 | 核对项 | 公开可得性 | 备注 |
| --- | --- | --- | --- |
| L2-a | 类型名取值域 | 接口侧无取值域；支持文档侧有五个取值 | F-错位：取值域在非安全文档 |
| L2-b | 子类型编码 | 无定义 | 第 26 章 U02 |
| L2-c | 格式描述与类型名一致性 | 无公开换算 | 脚本二 F02 |
| L2-bis | 面向用户的名字与卷名是否同值 | 两键并存（873／896） | 无公开合并规则 |
| L2-d | 只读／可移除／可弹出三格是否分开登记 | 三独立键 | 8.2 节配对卸载选项 |
| L2-e | 内部总线是否被当作 UID 绑定充分条件 | 否（313 行有三条件） | D06 |
| L2-f | GUI 可见集合与枚举隐藏集合是否同域 | 不同域 | 第 17 章 |
| L2-g | exFAT／NTFS／MS-DOS 是否有安全归属读数 | 全语料 0 | `C/readings-20.txt:7—9` |

---

## 6. L3 能力承载层：20 个 volumeSupports* 键

### 6.1 本层回答什么

L3 回答「这个卷能不能承载某种文件语义」。这一格在归属上的作用是：**它决定一份内容在这个卷上能有什么形态后果**，而不是这个卷本身有什么缺陷。20 个 `volumeSupports*` 键（`C/readings-20.txt:150`）构成一个封闭集合，逐个可在页内定位（`A/foundation_urlresourcekey_all.txt:920—1084`）。本层把它们分成四组，并指出其中两组的公开定义不完整。

### 6.2 四组能力读数

**第一组：命名与大小写（4 键）。** `volumeSupportsCasePreservedNamesKey`:938、`volumeSupportsCaseSensitiveNamesKey`:946、`volumeSupportsPersistentIDsKey`:1023、`volumeSupportsRootDirectoryDatesKey`:1039。这一组的归属意义是「同一份内容在这个卷上可能有两个合法名字」。`CaseSensitive` 与 `CasePreserved` 是两键而不是一个三态键，说明公开口径允许「保留大小写但不区分」这一态存在——因此台账里把「大小写」登记成单值会丢一态（脚本一 P03）。

**第二组：链接与克隆（3 键）。** `volumeSupportsHardLinksKey`:997、`volumeSupportsSymbolicLinksKey`:1065、`volumeSupportsFileCloningKey`:982。克隆有独立的口径支撑：`A clone is a copy of a file or directory that occupies no additional space on disk. Clones let you make fast, power-efficient file copies on the same volume`（`A/dev_about_apple_file_system-S.txt:12`），以及 `Modifications to the data are written elsewhere, and both files continue to share the unmodified blocks`（`A/dev_about_apple_file_system-S.txt:16`）。这一组是 L3 里唯一一组**在结构口径与安全口径两侧都有定义**的能力，因此也是本篇唯一允许写「该卷上的两份内容可能共享物理块」的能力格。第 9 章说明它与容量计数的冲突。

**第三组：重命名与锁（4 键）。** `volumeSupportsRenamingKey`:1031、`volumeSupportsExclusiveRenamingKey`:965、`volumeSupportsSwapRenamingKey`:1057、`volumeSupportsAdvisoryFileLockingKey`:930。四种重命名/锁定语义并存，公开口径没有给出它们之间的蕴含关系；`Atomic safe-save` 在结构侧被列进 APFS 特性（`A/dev_about_apple_file_system-S.txt:5`），但在接口侧对应的是三个独立键而不是一个 `supportsAtomicSave` 键。**这构成一处口径粒度差**：结构侧一个词，接口侧三个布尔。

**第四组：稀疏、零区段与压缩（3 键）。** `volumeSupportsSparseFilesKey`:1047、`volumeSupportsZeroRunsKey`:1084、`volumeSupportsCompressionKey`:955。稀疏文件在结构侧有独立定义：`HFS Plus and other formats that don't support sparse files allocate three blocks for the file, one for each block that was written, and one empty block in the middle. With support for sparse files, only two blocks are allocated, and the empty block is omitted`（`A/dev_about_apple_file_system-S.txt:28`）。这一句是本报告系列里**唯一一条把「文件大小」与「占用块数」明确区分开的公开句子**，它直接决定第 9 章的容量归属规则。

**第五组（未归组）：权限、安全与保护（6 键）。** `volumeSupportsAccessPermissionsKey`:920、`volumeSupportsExtendedSecurityKey`:973、`volumeSupportsImmutableFilesKey`:1007、`volumeSupportsJournalingKey`:1015、`volumeSupportsFileProtectionKey`:989、`volumeSupportsVolumeSizesKey`:1076。其中 `FileProtection` 一键的定义是本层最重要的一句：`A Boolean value that indicates the volume supports data protection for files.`（`A/foundation_urlresourcekey_all.txt:986`）。

### 6.3 两条必须写死的换算规则

**规则一：`volumeSupportsFileProtectionKey` 是承载能力，不是保护状态。** 定义句只有一个 `supports`（`A/foundation_urlresourcekey_all.txt:986`）。与表二的对照是：保护的实际状态由「文件被分到哪个类」决定（`Data Protection is controlled on a per-file basis by assigning each file to a class`，`A/security_data_protection_overview-S.txt:241`）。因此「该卷 supports=1」这条读数**不能写成「该卷上的文件受保护」**。这一格误推的代价很具体：`Class D: No Protection`（`A/security_data_protection_classes-S.txt:272` 定义句 `This class key is protected only with the UID, and is kept in Effaceable Storage`）里的文件也在这个卷上。脚本一对「同一枚 `supports` 布尔被读成另一种状态」设了 D02（`supports=1` 被写成 `mount.state=1`），但 `supports`→「文件受保护」这一格没有专用码，只能靠第 10 章的键级对照判定。

**规则二：`volumeSupportsVolumeSizesKey` 不是容量读数。** 这一键的键名在 `A/foundation_urlresourcekey_all.txt:1076`，其定义行在归档里只剩尾词 `keys.`（`A/foundation_urlresourcekey_all.txt:1073`），完整句子没有落在同一行内；因此本篇**不引用该键的定义语义，只引用其存在性**。它与 `volumeTotalCapacityKey`:1091、`volumeAvailableCapacityKey`:770 之间没有任何公开换算。本篇因此把「supports=0 但同一卷已登记容量数值」当作允许并存的一条读数，而不是数据错误（E04）。

### 6.4 能力组与恶意构造子集的对照

L3 与第 18 篇有一条必须点明的分界。`libarchive` 词形在公告组件名列 5 行、`archive` 词形 13 行 3 组件（`C/readings-20.txt:33、35`），而 `archive` 类组件的解析行为与「卷支持不支持稀疏文件」是两件事：前者是容器内容解析，后者是落点卷能力。表三的影响句列里 `libarchive`、`copyfile` 两词形各 0 行（`C/readings-20.txt:76、77`）。因此本篇不把任何归档类缺陷计入形态归属，只在 F8 里把它们作为词形碰撞样本列出。

### 6.5 本层核对项

| 编号 | 核对项 | 公开可得性 | 失败模式 |
| --- | --- | --- | --- |
| L3-a | 20 个 supports 键是否逐键登记 | 全部有键 | 只登记「支持/不支持」二值 → 丢大小写两态 |
| L3-b | supports=1 是否被写成状态 | 否（定义只说 supports） | D02（只覆盖被写成挂载状态这一形态） |
| L3-c | 克隆与硬链接是否同格 | 两独立键 | 共享块读数丢失 |
| L3-d | 稀疏导致的「大小≠占用」是否登记 | 结构侧有定义、接口侧无键 | E02 |
| L3-e | 重命名四语义是否收敛成一个 | 四独立键、无蕴含关系 | 第 26 章 U05 |
| L3-f | supportsVolumeSizes=0 与容量数值并存 | 允许并存 | E04 |

---

## 7. L4 挂载与枚举层：谁把卷列出来、列出的是哪一类 URL

### 7.1 本层唯一的动作句

公开语料里描述「把卷列出来」这个动作的句子只有一组：`Returns an array of URLs that identify the mounted volumes available on the device`（`A/dev_filemanager_mountedvolumeurlsincludingresourcevaluesforkeysoptions_S.txt:3`，同句在 :146 重复出现于文档的另一区块）。入参侧的说明是 `An array of keys that identify the file properties that you want pre-fetched for each volume. For each returned URL, the values for these keys are cached in the corresponding … objects identifying the mounted volumes`（`A/dev_filemanager_mountedvolumeurlsincludingresourcevaluesforkeysoptions_S.txt:37、44`），并且同页把键的来源指回表一：`Keys that apply to file system URLs`（`A/dev_filemanager_mountedvolumeurlsincludingresourcevaluesforkeysoptions_S.txt:201`）。

这一组句子给出 L4 的三条归属结论。**其一**，「有哪些卷」的公开判定权在调用方：调用者给键数组，系统预取并缓存；系统不主动通知挂载变化。**其二**，形态读数是一次**预取快照**（`pre-fetched`、`cached`），不是订阅量——这是 F3（状态换不到时点）在动作层的对应。**其三**，返回的是 URL 对象集合，而 URL 有两种形态：`The enumeration produces file reference URLs rather than path-based URLs`（`A/dev_filemanager_volumeenumerationoptions_S.txt:67`）。

### 7.2 文件引用 URL 与路径 URL：同一卷的两个身份

这是本层最要紧的一格。两种 URL 形态不是显示差异而是**身份差异**：文件引用 URL 标识卷这个对象，路径 URL 标识挂载位置。公开句子没有进一步说明两者在卷被卸载再挂载之后是否等价，因此本篇把它列为未公开文档化边界（第 26 章 U03），并在台账格式里强制两列分开：`url_kind` 一列取值只允许 `file_ref` 或 `path`。任何「同一卷的两条台账指向同一对象」的判断，如果两条记录的 `url_kind` 不同，脚本一直接判为 A08（身份不可比对）。

### 7.3 隐藏卷：一条枚举侧与一条接口侧的不同口径

枚举侧：`The enumeration skips hidden volumes`（`A/dev_filemanager_volumeenumerationoptions_S.txt:76`）。接口侧：`A key for determining whether the volume is visible in GUI-based file-browsing environments, such as the Desktop or the Finder app`（`A/foundation_urlresourcekey_all.txt:798`）。结构侧：`the first three of which are hidden from the user`（`A/security_role_of_apfs-S.txt:243`）。三句里的「隐藏」不是同一个集合：枚举选项跳过的是枚举可见性，`volumeIsBrowsableKey` 描述的是 GUI 可见性，结构句描述的是 Finder/桌面层面的用户可见性。

这条三重口径的直接后果是：**一个卷可以在一个面上隐藏、在另一个面上可见，而且这不是异常。** 台账里若要写「隐藏」列，必须写明是哪一面（`hidden_by` 一列，取值 `enum`／`gui`／`structure`／`unknown`）。脚本一 H06 拦「写了 hidden 但没写哪一面」。

### 7.4 挂载来源与自动挂载：两个只有名字没有语义的键

`volumeIsAutomountedKey` 的定义句是 `A key for determining whether the volume is automounted.`（`A/foundation_urlresourcekey_all.txt:791`），`volumeMountFromLocationKey` 的定义句是 `The key for the volume mounted-from location.`（`A/foundation_urlresourcekey_all.txt:886`）。两句话的共同问题是：**「automounted」的施动者没有被写出来**。公开语料里没有任何一句说明是谁执行自动挂载（是 DiskArbitration、是 launchd、还是文件系统驱动），也没有任何一句说明 `mounted-from location` 的取值格式。与之相邻的只有 `isMountTriggerKey`（键名 `A/foundation_urlresourcekey_all.txt:368`）——它是 mount trigger 而非 mount action。

本篇因此规定：**挂载施动者一律登记为 `unknown`，除非有其它面的读数**。这不是保守，而是这一格在四个面（接口、结构、管理、公告）上都没有施动者读数：管理面 `mount` 词形 0 键（`C/readings-20.txt:115`），公告组件名列 `mount`/`diskarbitration` 只有 6 行且组件是 `Disk Images`、`DiskArbitration`（`C/readings-20.txt:16`），影响句列 `mount` 5 行 3 组件（`C/readings-20.txt:56`）。`DiskArbitration` 作为一个组件名在公告里出现过，但公开语料没有一份文档描述它的挂载决策——这就是第 26 章 U04 那条边界。

### 7.5 用户面的挂载词汇

用户面上「一个位置」的词汇与接口层完全不同。`Learn where to find your files, folders, downloads, and other saved items in the Files app on your iPhone or iPad`（`A/iphone_find_files-S.txt:18`）之后给出四类位置：

| 用户面位置名 | 公开句子 | 行号 |
| --- | --- | --- |
| 本机 | Choose On My iPhone or On My iPad for files saved locally on your device | `A/iphone_find_files-S.txt:23` |
| iCloud Drive | Choose iCloud Drive for files, folders, and downloads that sync across your devices in iCloud Drive | `A/iphone_find_files-S.txt:24` |
| 外接设备 | Choose the name of your external storage device for files stored on a connected USB drive or SD card reader | `A/iphone_find_files-S.txt:25` |
| 第三方云服务 | Choose the name of a third-party app for files saved in third-party cloud services that you've added to the Files app, such as Box, Dropbox, and OneDrive | `A/iphone_find_files-S.txt:26` |

四类位置里**只有第二类与第三类有形态词对应**：第三类直接给出承载介质（USB drive／SD card reader），第二类不是卷而是同步服务。同一页还有一句必须保留的例外：`If you can't find a photo, check the Photos app. While you can save photos to iCloud Drive (or another cloud service) in the Files app, your photo library is stored in the Photos app`（`A/iphone_find_files-S.txt:29`）——**照片库不在 Files 的位置体系里**。这条与第 19 篇的落点层直接冲突过（19 篇 L5 登记过照片落点），本篇据此声明：照片库的落点不进入本篇的卷台账，两篇的分工以这一句为准。

另一条错位同样直接：`SD card reader`（`A/iphone_find_files-S.txt:25`）与 `card reader`、`sd card`、`thunderbolt`、`removable`、`ejectable` 五个词形在公告组件名列**全部 0 行**（`C/readings-20.txt:19、20、21、22、23`），在影响句列同样全 0（`C/readings-20.txt:59—66` 区间内的对应行）。用户面上明确存在的四类位置，与安全公告的归属标签之间，有整整一类是零交叠。

### 7.6 本层核对项

| 编号 | 核对项 | 公开可得性 |
| --- | --- | --- |
| L4-a | 枚举调用时刻与快照时点是否分开登记 | 只写 pre-fetched/cached，无时点 |
| L4-b | URL 种类是否登记 | file_ref / path 两态（`:67`） |
| L4-c | 「隐藏」属于哪一面 | 三套口径并存 |
| L4-d | 挂载施动者 | 四面均无 → unknown |
| L4-e | mounted-from 取值格式 | 无定义 |
| L4-f | 用户面位置与卷是否同格 | 四类位置、仅两类有卷 |
| L4-g | 照片库是否进卷台账 | 否（`:29`） |

---

## 8. L5 卸载与弹出层：两个选项、一个异议进程与一次重锁

### 8.1 三个公开动作

卸载侧的公开句子一共三组，全部在接口文档内。

`Starts the process of unmounting the specified volume`（`A/dev_filemanager_unmountvolumeatoptionscompletionhandler_S.txt:3`，同句在 :92 重复）与参数说明 `A file URL specifying the volume to be unmounted`、`A block executed when the unmount operation completes. The block receives an error parameter which is … if unmounting was successful. Otherwise, it indicates why unmounting failed`（`A/dev_filemanager_unmountvolumeatoptionscompletionhandler_S.txt:66、69、70`）。注意第一个词是 `Starts the process`：**这是一个开始动作，不是完成动作**，完成由回调告知。这一句决定了本篇对「卸载成功」的登记规则：台账里 `unmount_state` 一列必须区分 `started`／`completed`／`failed`，写 `completed` 却没有任何可复核的完成依据（选项名为空）触发 H08。

两个选项：`Specifies that all partitions on an unmountable disk should be unmounted`（`A/dev_filemanager_unmountoptions_S.txt:54`，成员名 `NSFileManagerUnmountAllPartitionsAndEjectDisk` 在 :62）与 `Specifies that no UI should accompany the unmount operation`（`A/dev_filemanager_unmountoptions_S.txt:70`，成员名 `NSFileManagerUnmountWithoutUI` 在 :78）。第一个选项把**卷单位换成盘单位**——这是本篇唯一一处公开承认「卷与分区的归属单位可以互换」的地方，也是第 4 章容器-卷计数规则的例外。第二个选项是**告知面**的开关；本文只把它当作告知可见性的一格登记（见 8.3），不给出任何使用建议。

一个失败读数：`The process identifier of the process that prevented a volume from unmounting`（`A/dev_filemanager_unmountoptions_S.txt:101`，键名 `NSFileManagerUnmountDissentingProcessIdentifierErrorKey` 在 :103 与 :106）。这一键是本报告系列里**唯一一条公开把「谁挡住了卸载」写成可读回数据**的口径。它给出主语（一个进程标识符），但不给出进程身份、不给出所属 App、不给出为何在用。归属结论因此是两半：**「卸载失败有明确责任进程」是可证的；「那个进程代表谁」不可证。** 第 17 章把后者列入读者拿不到的一格。

### 8.2 卸载与加密的耦合：唯一的 relock 句

`If the volume is encrypted, it is relocked after being unmounted`（`A/dev_filemanager_unmountvolumeatoptionscompletionhandler_S.txt:72`）。

这一句在本篇的地位与 `B/apple-platform-security-guide.txt:772` 并列。它给出三条读数：**其一**，卷加密态在卸载动作之后被主动恢复（`relocked`），说明加密的卷生命周期不是挂载周期，而是「解锁—挂载—卸载—重锁」四段；**其二**，这句话的主语是「the volume」，不是「the file」——这与表二的逐文件类粒度（`A/security_data_protection_overview-S.txt:241`）是两套不同层的机制，正是 F5 的正面表述；**其三**，它是**单源句**：管理面、公告两列、KEV 对 `unmount` 全 0（`C/readings-20.txt:14、57、115`）。任何台账把「卸载后重锁」写成一条策略项而不是接口语义项，都没有第二处来源支撑（脚本一 D07）。

### 8.3 告知面与弹出面

与 `UnmountWithoutUI`（`:70`）相对的一格是「有 UI 的弹出」：`volumeIsEjectableKey`（`A/foundation_urlresourcekey_all.txt:808`）与 `volumeIsRemovableKey`（`A/foundation_urlresourcekey_all.txt:847、850`）分别描述弹出接口与驱动机构取出性，两者都不是告知面读数。本篇在告知这一格上只登记一个事实：**公开语料里没有任何一句把「卷被卸载」写成会向用户呈现提示的动作**（`C/readings-20.txt` 全量扫描：`mount` 词形在影响句 5 行、组件名 0 行，且这 5 行的组件是 `PackageKit`、`StorageKit`、`Directory Utility` 一类，见 `C/readings-20.txt:91、97`）。因此第 18 章的读数面里，「告知侧」在本篇是**空面**，与其他九篇不同。唯一可登记的是接口侧存在一个显式的无 UI 选项（`A/dev_filemanager_unmountoptions_S.txt:70`）：这说明「不伴随 UI」是公开承认的一种卸载形态，而不是异常形态；但公开语料没有一句说明谁在什么条件下使用它。

### 8.4 卸载失败子集的落点分布

影响句里明确写到 `volume/mount/unmount/file system` 的 24 行给出了一组分布，是本篇少见的可直接引用的行级读数：组件名分布 `apfs=2 ; appleraid=1 ; copyfile=3 ; corestorage=2 ; directory utility=3 ; packagekit=7 ; storagekit=6`，平台分布 `iOS 26.7.2 and iPadOS 26.7.2=1 ; macOS Golden Gate 27.2=10 ; macOS Sequoia 15.8.2=6 ; macOS Tahoe 26.7.2=7`，其中组件名与影响句同时含词形的只有 13 行（`C/readings-20.txt:96、97、98、99`）。

两条结论：**其一**，24 行里有 23 行是 macOS 平台行，iOS 侧只有 1 行；这说明「挂载/文件系统语汇」在公告里基本是 Mac 专属叙述，把它当作 iOS 的攻击面叙述来用会引入 23/24 的平台错位。**其二**，这 24 行的组件分布里出现了 `Directory Utility`（3 行）与 `PackageKit`（7 行）——前者是磁盘/目录工具，后者是安装事务，都不是文件系统实现本体。`appleraid=1` 一行同样不属于文件系统实现。也就是说：**按影响句筛出的「挂载相关缺陷」，其组件归属有半数落在文件系统实现之外。** 这是 F1 的镜像证据，第 13 章据此给出 13/24 的双命中率。

### 8.5 本层核对项

| 编号 | 核对项 | 规则 |
| --- | --- | --- |
| L5-a | 卸载状态三段是否分开 | started / completed / failed |
| L5-b | 卸载单位是卷还是盘 | 选项可把单位换成整盘（`:54`） |
| L5-c | 异议进程是否登记 | 只登记 PID 存在性，不推身份 |
| L5-d | 重锁是否被写成策略 | 单源句，不得写成策略项 |
| L5-e | 卸载是否有告知 | 公开无句 → 告知面空 |
| L5-f | 弹出/可移除/无 UI 三格是否混用 | 三独立语义 |

---

## 9. L6 容量与计数层：共享空闲空间让求和失效

### 9.1 五个容量键与三套语义

表一里与容量有关的键是 6 个（含 `volumeMaximumFileSizeKey`:882 与 `volumeSupportsVolumeSizesKey`:1076）。核心三键的定义各自只有一句：`Key for the volume's available capacity in bytes for storing important resources (read-only)`（`A/foundation_urlresourcekey_all.txt:753`）、`…for storing nonessential resources (read-only)`（`:760`）、`Key for the volume's available capacity in bytes (read-only)`（`:767`）。三句都只给单位（bytes）与只读性，**不给三者之间的加减或大小关系**。`volumeTotalCapacityKey`（键名 `:1091`）与之并列。

结构侧则给出唯一一条约束：`APFS allocates storage space on demand. When a single APFS container has multiple volumes, the container's free space is shared and can be allocated to any of the individual volumes as needed. Each volume uses only part of the overall container, so the available space is the total size of the container, minus the space used in all volumes in the container`（`A/security_role_of_apfs-S.txt:241`）。注意这句与接口侧那句是同一段话的两半：`Each volume in the container can use the shared free space, so they all include that amount when reporting the available free space`（`A/dev_about_apple_file_system-S.txt:19`）——**每个卷报告的可用空间都包含同一份共享额度**。

### 9.2 三条计数规则

**规则一：跨卷求和禁止。** 公开句子直接把求和写成不可靠：`Computing the sum of each volume's available free space isn't a reliable way to determine the total free space within a partition. In general, check whether the space required to perform a particular operation is available on the volume, rather than trying to calculate the partition's total free space`（`A/dev_about_apple_file_system-S.txt:22`）。这是本篇唯一一条**公开写在文档里的反模式**，因此脚本一把它做成硬信号而不是软提示：台账里任何一行以 `available_capacity` 为字段名、以 `sum`／`total_across_volumes` 为值语义，触发 E01。

**规则二：`important` 与 `opportunistic` 不是互补两半。** 定义句分别用「important resources」与「nonessential resources」（`A/foundation_urlresourcekey_all.txt:753、760`），两者与裸 `available capacity`（`:767`）之间的公开关系没有写在任何一处；因此本篇规定这三键只能**并列引用**，禁止「三键取其一代表可用空间」。台账必须逐键登记键名（`capacity_kind` 一列，取值 `available`／`important`／`opportunistic`／`total`），缺 `capacity_kind` 触发 E03。

**规则三：文件大小不等于占用。** 稀疏句给出唯一一条容量归属的换算修正：`With support for sparse files, only two blocks are allocated, and the empty block is omitted`（`A/dev_about_apple_file_system-S.txt:28`），克隆句给出第二条：`A clone is a copy of a file or directory that occupies no additional space on disk`（`A/dev_about_apple_file_system-S.txt:12`），以及 `they each need three on-disk blocks, but on an Apple File System volume, the two common blocks are shared`（`A/dev_about_apple_file_system-S.txt:16`）。三句合起来：**在一个 APFS 卷上，「N 份内容」不能换算成「N 倍占用」。** 因此本篇在所有落点统计里禁用「按份数估空间」，只允许「按卷报告值引用」。这条规则同时约束第 11 篇（备份副本数）与本篇（卷内容数）的接口。

### 9.3 快照与回滚带来的计数缺口

容量层的最后一格是快照。`SSV not only helps prevent tampering with any Apple software that's part of the operating system, it also makes macOS software update more reliable and much safer. And because SSV uses Apple File System (APFS) snapshots, if an update can't be performed, the old system version can be restored without reinstallation`（`B/apple-platform-security-guide.txt:1120`）。同页另有一条：`Since its introduction, APFS has provided file-system metadata integrity using noncryptographic checksums on the internal storage device`（`B/apple-platform-security-guide.txt:1121`）。

本层要指出的是接口侧的一个空白：**表一 47 键里没有任何一键报告快照的存在、数量或年龄**（`snapshot` 词形在表一命中 0；`C/readings-20.txt:38` 是表三的公告侧 0 命中，`C/readings-20.txt:150` 的 47 键清单里同样没有）。因此一个卷报告的 `volumeAvailableCapacityKey` 数值与「系统能回滚到旧版本」这两件事在公开口径里**没有任何换算**。本篇把这一格列为第 26 章 U06，并且规定：涉及回滚能力的台账必须写成「文档声明有快照机制」+「本卷无快照读数」两行，不允许合并。

### 9.4 本层核对项

| 编号 | 核对项 | 结论 |
| --- | --- | --- |
| L6-a | 跨卷求和 | 禁止（`:22` 明写不可靠） |
| L6-b | 三键关系 | 未公开，并列引用 |
| L6-c | 份数与占用 | 不可换算（`:12、16、28`） |
| L6-d | 快照读数 | 接口侧 0 键 |
| L6-e | supportsVolumeSizes=0 与数值并存 | 允许，不算错误 |
| L6-f | 最大文件尺寸与卷容量 | 两独立键，无关系 |

---

---

## 10. L7 加密与密钥栈层：卷键、文件键、区段键与 UID

这一层是全篇唯一一处**公开句子足够长、但没有任何读回接口**的层。前六层（容器、形态、能力、挂载、卸载、容量）都还能在接口词表里找到至少一个键名做锚点；到密钥栈这一层，接口侧只剩下 `volumeIsEncryptedKey` 一个布尔，其余全部由平台安全指南的散文给出。因此本层的写法与前面不同：**先把公开句子按「谁见过这把键」重新排列，再逐条标注它在接口侧有没有对应读数。** 结论是：这一层的归属证据全部来自文档声明，**没有任何一条能在设备上读回**。

### 10.1 接口侧只有一个布尔，且它是形态无关的

整套 47 个 volume 前缀键里，与加密有关的只有一键：定义句 `A key for determining whether the volume is encrypted.`（`A/foundation_urlresourcekey_all.txt:812`），键名 `volumeIsEncryptedKey`（`:815`）。这句话有三处必须点出来。

第一，它用的是「determining whether」，与同一批键的写法完全一致（automounted `:791`、browsable `:798`、ejectable `:805`、internal `:819`、journaling `:826`、local `:833`、read-only `:840`、removable `:847`、root file system `:854`），**全批没有一个键报告「以什么方式加密」或「用哪一层键加密」**。第二，它不与 `volumeTypeNameKey`（`:1098`）或 `volumeSubtypeKey`（`:911`）发生任何公开关系：文档没有写「类型名为 APFS 时该键为真」，也没有写反例，因此这一对组合在台账里必须是两个独立字段。第三，`encrypted` 在公开格式清单里**是一个可选格式而不是一个属性**：iOS/iPadOS 的外接存储格式白名单里出现的是 `APFS（encrypted）` 这一项，与裸 `APFS` 并列（`A/iphone_external_storage-S.txt:1154`、`A/ipad_external_storage-S.txt:1070`）。也就是说用户侧文档把「加密」写成了格式菜单里的一行，接口侧把它写成了一个布尔，两侧之间没有公开换算。第 24 章 M07 处理的就是这一格。

### 10.2 结构侧点名了三个「不加密」的卷

`A/security_role_of_apfs-S.txt` 在列举 macOS 五卷时，对前三个隐藏卷逐个写了加密状态：`Preboot volume: This volume is unencrypted and contains data needed for booting each system volume in the container.`（`:244`）、`VM volume: This volume is unencrypted and is used by macOS for storing encrypted swap files.`（`:245`）、`Recovery volume: This volume is unencrypted and needs to be available without unlocking a system volume to start up in recoveryOS.`（`:246`）。

这三句在本篇里承担两个作用。**其一是给出一处内部矛盾口径必须逐字保留**：VM 卷同一句里既是 `unencrypted`，又承载 `encrypted swap files`——**卷不加密、卷内文件加密**，这是公开文档里唯一一处把「卷级加密」与「文件级加密」写成相反取值的句子。任何把 `volumeIsEncryptedKey=false` 读成「这个卷上的内容不加密」的写法，都被这一句直接否证。**其二是给出挂载顺序的结构性理由**：Recovery 卷那句写明它必须 `available without unlocking a system volume`——**一个不加密的卷存在的理由，就是它必须能在加密卷解锁之前被挂载**。这一句与本层第 10.8 小节的重锁句、第 4 章的 mount 前校验句构成三脚，共同支撑「校验发生在挂载之前」这条核对项。

同一页的总述句是 `Apple File System (APFS) is a proprietary file system designed with encryption in mind.`（`:239`）——注意这句只说设计意图，不说默认取值，**不能引成「APFS 卷默认加密」**。

### 10.3 五级密钥栈：按「谁见过这把键」排列

平台安全指南把 Data Protection 的密钥栈写成一条链。本篇按**每个环节是否暴露给 Application Processor（AP）**重排，因为这条判据是文档自己给出的、而且可以逐句核对：

| 级 | 键 | 谁生成 | 是否暴露给 AP | 公开原句锚点 |
| --- | --- | --- | --- | --- |
| K1 | 元数据键 / 文件系统键 | 系统首次安装或用户完成抹掉时 | 否：`never directly exposed to the Application Processor; the Secure Enclave provides an ephemeral, per-boot version instead` | `B/apple-platform-security-guide.txt:1923` |
| K2 | 类键（class key） | 由 user keybag 或 device keybag 保管 | 文档只写「在 Secure Enclave 里解包」，未写暴露 | `:1925`、`:1976`、`:1978` |
| K3 | 文件键 / 区段键 | 每文件或每区段一把 | 否：`All wrapped file key handling occurs in the Secure Enclave; the file key is never directly exposed to the Application Processor` | `:1921` |
| K4 | 临时键（per-boot ephemeral） | 启动时 SEP 与 AES Engine 协商 | 是：解出的键用临时键重包后送回 AP | `:1921` |
| K5 | 包封键（key-wrapping key） | 仅 SEP 所知 | 文档明写 `known only to the Secure Enclave`，且每次抹机更换 | `:1922` |

把这张表读成归属口径，得到三条硬结论。**结论一：类键同时保护文件与区段，粒度不改变保护者。** `If a file is cloned, each half of the clone gets a new key to accept incoming writes… Over time, the file may become composed of various extents (or fragments), each mapping to different keys. However, all of the extents that comprise a file are guarded by the same class key.`（`:1920`）——一个文件在 APFS 上可以持有 N 把键，但只归一个类。**因此「这个文件属于哪一层保护」的判定权在类键手里，不在键的数量手里**，这条正是第 6 章规则三（份数与占用不可换算）在加密层的对应物。**结论二：换密码不换键，只换包封。** `changing a file’s class only requires rewrapping its per-file key, and a change of passcode just rewraps the class key`（`:1925`）——所以任何「改密码后旧数据仍可解」的推断在公开口径里既不被支持也不被否证，本篇把它列进第 26 章 U07。**结论三：类键的保护者是两样东西。** `The class key is protected with the hardware UID and, for some classes, the user’s passcode.`（`:1925`）——注意 `for some classes`：文档自己承认不是所有类都绑密码，这与第 5 章 L2 的内部总线三条件句（`:313`）是同一件事的两半。

### 10.4 可擦性与保密性被公开写成两件事

`:1923` 里紧跟在包装描述之后的两句，是全篇最需要原样保留的一句：`This key doesn’t provide additional data confidentiality. Instead, it’s designed to be quickly erased on demand (by the user with the “Erase All Content and Settings” option, or by a user or administrator issuing a remote wipe command from a device management service, Microsoft Exchange ActiveSync, or iCloud).` 词汇表那条更直白：`file system key The key that encrypts each file’s metadata, including its class key. This is kept in Effaceable Storage to facilitate fast wipe, rather than confidentiality.`（`B/apple-platform-security-guide.txt:4688`）

这两句给本篇的口径是：**Effaceable Storage 的出现不等于加密强度**。类 D 句 `protected only with the UID, and is kept in Effaceable Storage`（`A/security_data_protection_classes-S.txt:272`）同样只报保护者与存放位置，不报强度。因此台账里凡出现 `effaceable=yes` 字段，必须同时有一列 `effaceable_means`，取值只能是 `wipe-speed`；把它填成 `strength` 或 `confidentiality` 由脚本一 E12 直接判错。配套的是那句 Important：`Erasing the key in this manner renders all files cryptographically inaccessible.`（`:1924`）——**「不可访问」是抹键的结果，不是加密的属性**，两者在文本上必须分开写。

另外，可擦机制在两个世代上是两套：`For devices with SoCs earlier than the A9, the .plist file contents are encrypted with a key held in Effaceable Storage. To give forward security to keybags, this key is wiped and regenerated each time a user changes their passcode.`（`:1979`）与 `For devices with the A9 or later, S series, and M series SoCs (other than Mac computers), the .plist file contains a key which indicates that the keybag is stored in a locker protected by the Secure Enclave-controlled anti-replay value.`（`:1980`）。**同一个 keybag 的存放方式按芯片世代分叉，而且 `other than Mac computers` 把 Mac 排除在第二套之外**——这是本篇唯一一处按 SoC 世代给出的密钥栈归属分界，脚本二把它做成 X 族信号（X09）。

### 10.5 五类 keybag：一份清单，三种归属

`The keys for both file and keychain Data Protection classes are collected and managed in keybags in iOS, iPadOS, macOS, tvOS, visionOS, and watchOS. These operating systems use the following keybags: user, device, backup, escrow, and iCloud Backup.`（`:1976`）这是管理面之外唯一一份公开的五类清单。逐个核对归属：

| keybag | 公开职责句 | 归属对象 | 锚点 |
| --- | --- | --- | --- |
| user | `where the wrapped class keys used in normal operation of the device are stored` | 用户密码（部分类） | `:1978` |
| device | `used to store the wrapped class keys used for operations involving device-specific data` | 设备本身 | `:1991` |
| backup | `created when an encrypted backup is made by the Finder … or iTunes … and stored on the computer to which the device is backed up` | 备份所在的那台电脑 | `:1996` |
| escrow | 本篇归档内无独立职责句 | 托管方 | 仅 `:1976` 列出 |
| iCloud Backup | 仅在同一句里列出，无展开 | iCloud | 仅 `:1976` 列出 |

`escrow` 与 `iCloud Backup` 两项**只在清单里出现名字**，本层因此不能对它们做任何判定；第 26 章 U08 登记这一点。真正有后果的是 backup 那一句：备份 keybag 存在**电脑**上，而 `A new keybag is created with a new set of keys, and the backed-up data is reencrypted to these new keys.`（`:1996`）——**一次加密备份会产生一套新键**。同句还给出唯一一处 UID 绑定的可迁移性判据：`nonmigratory keychain items remain wrapped with the UID-derived key, allowing them to be restored to the device they were originally backed up from but rendering them inaccessible on a different device.`（`:1996`）这三件（第 11 篇的备份落点、本篇的卷形态、系列的主体归属）在这一句上交汇，但本篇不越界讨论备份链路，只取「备份换键」与「UID 派生键不可迁移」两条读数。

user keybag 还有一条容易被略过的自指句：`It is a binary property list (.plist) file stored in the No Protection class.`（`:1978`）——**保管所有类键的那个文件，自己存放在「无保护」类里**。这一句不能引成缺陷（它的机密性来自包封链而不来自存放位置），但必须在台账里登记为一条独立事实：凡写「keybag 受某类保护」而不写它所在类的，脚本一触发 K03。

### 10.6 iOS 与 macOS 在这一层有两处方向相反的差异

**差异一：iOS 不按用户分卷，macOS 侧才可能分。** `iOS, iPadOS, and visionOS don’t support cryptographic separation of per-user file system content, which means the system uses class keys from the device keybag to wrap per-file keys. The keychain, however, uses class keys from the user keybag to protect items in the user keychain. On iPad and iPhone devices configured for use by a single user (the default configuration), the device keybag and the user keybag are one and the same, and are protected by the user’s passcode.`（`:1993`）这句给出三个方向：文件走 device keybag、钥匙串走 user keybag、默认配置下两者是同一个。**因此「按用户划归属」这一格在 iOS 文件系统上不成立**，而钥匙串侧成立——这条正反差异正是第 24 章 M06 的内容。

**差异二：Mac 把卷键说成「复刻模型」，不说「更强」。** `On a Mac with Apple silicon, Data Protection defaults to Class C (see Data Protection classes) but uses a volume key rather than a per-extent or per-file key—effectively recreating the security model of FileVault for user data.`（`:1912`），配套两句 `Note: macOS uses a volume key to recreate FileVault protection characteristics.`（`:1944`）和 `FileVault on a Mac with Apple silicon is implemented using Data Protection Class C with a volume key.`（`:2184`）。`recreating`／`recreate` 用词三次一致，**没有任何一处写「替代」或「等同」**。同一句里的 `On a Mac with macOS 26.4 or later, FileVault is turned on by default`（`:1912`）是这一格里唯一一条带版本号的默认值声明，与 iOS 侧没有任何对应句。

### 10.7 IRK 与恢复键：一条公开自陈「功能价值为零」

`FileVault on both CoreStorage and APFS volumes supports using an institutional recovery key (IRK, previously known as a FileVault Master identity) to unlock the volume.`（`:2247`）——这是公开文档里唯一一句把**两种文件系统形态并列**的句子，也是唯一一处把 `CoreStorage` 这个词写在句子而不是组件名里的地方。紧接着是这一格的自陈：`And on a Mac with Apple silicon, IRKs provide no functional value for two primary reasons: IRKs can’t be used to access recoveryOS, and because target disk mode is no longer supported, the volume can’t be unlocked by connecting it to another Mac.`（`:2247`）

本篇取这条的原因不是结论本身，而是它的**句式**：这是整个语料里唯一一处「某项管理性密钥能力在某硬件世代上被公开宣布无效」。它与第 12 章的 `Error.ConfigurationNotSupported`（`A/mdm-declaration-base-M.txt:32`）构成同一类证据——**能力存在与能力可用是两栏，不能合并**。因此本篇在恢复键上的口径是：台账必须为每个恢复类读数带 `hardware_generation` 与 `availability_note` 两列，缺列触发 K05；把 IRK 写成「企业可用的解锁手段」而不带 Apple silicon 限定，触发 K06。

### 10.8 挂载与加密的唯一一条公开交点

全篇里把「挂载动作」与「加密状态」写在同一句的公开文本，只有一条，位于卸载侧：`If the volume is encrypted, it is relocked after being unmounted`（`A/dev_filemanager_unmountvolumeatoptionscompletionhandler_S.txt:72`）。这一句有三个可核对的限定：条件式（`If … is encrypted`）、动作是 `relocked` 而不是 `locked` 或 `destroyed`、时序在 `after being unmounted`。

由此得到本篇对「重锁」的唯一口径：**重锁是卸载的后置效果，不是卸载选项，也不是策略项。** 卸载侧的两个选项（`allPartitionsAndEjectDisk`，说明 `:54`、成员名 `:57`、ObjC 名 `:62`；`withoutUI`，说明 `:70`、成员名 `:73`、ObjC 名 `:78`）里没有任何一项名为 relock，公开文本也没有写「强制不重锁」的路径。因此：写「用某选项可以不重锁」在公开口径里没有依据；写「卸载后键被销毁」同样没有依据（`relock` 与 `erase` 在文档中是分开的两个动词，后者只出现在 `:1923`、`:1924` 的抹机语境）。脚本一的 H 族把这一格做成硬信号：凡 `unmount` 事件的后续状态字段填 `key_destroyed`，直接触发 H09。

### 10.9 管理面在这一格读到什么

管理面对本层的读数集中在一份字典里，而且**逐条带平台限定**（`A/mdm-securityinfo-dictionary-M.txt`）。这份字典本身声明覆盖 iOS 4.0 起的全部平台（`:6`—`:12`），但其中与卷和加密有关的属性各有自己的可用范围：`AuthenticatedRootVolumeEnabled` 的句末是 `Available: macOS 11+`（`:16`）、`FDE_Enabled` 是 `Available: macOS 10.9+`（`:21`）。唯一一条覆盖 iOS 的加密形态读数反而不是布尔：`HardwareEncryptionCaps : integer … An integer that indicates the underlying hardware encryption capabilities of the device, which is one of the following values: * 1: Block-level encryption * 2: File-level encryption * 3: Both block-level and file-level encryption Available: iOS 4+ | iPadOS 4+ | tvOS 9+ | visionOS 1.1+ | watchOS 10+`（`:28`）。

这一条在本篇的地位很重要，因为它是**整个管理面里唯一一处把「块级」与「文件级」并列的公开取值**——也即本层唯一一处由管理面给出的「加密形态」维度。它同时暴露了管理面与本层的错位：这个整数按**设备**取值（`capabilities of the device`），而 K1—K5 按**卷、类、文件、区段**取值；两者之间公开文档没有任何换算。第 3 章 F6 记的就是这一格，脚本二 X 族把它做成码。

### 10.10 本层核对项

| 编号 | 核对项 | 口径 |
| --- | --- | --- |
| L7-a | 卷加密布尔能否推文件保护 | 不能（`:812` 只答 whether；`:1925` 保护粒度是类键） |
| L7-b | `unencrypted` 卷上能否有加密内容 | 能（VM 卷 `:245` 同句两半） |
| L7-c | Effaceable 的语义 | 只表示抹除速度（`:4688`、`:1923`） |
| L7-d | 一个文件的键数量 | 可多于一把，仍同一类（`:1920`） |
| L7-e | keybag 五类是否都有职责句 | 否，escrow 与 iCloud Backup 只有名字（`:1976`） |
| L7-f | iOS 是否按用户分离文件内容 | 否（`:1993`） |
| L7-g | 卸载与重锁的时序 | 重锁是后置效果，非选项（`:72`） |
| L7-h | 管理面能否读本层 | 只读到一个设备级整数与两个 macOS 布尔（`:28`、`:16`、`:21`） |

---

## 11. L8 远端域与外部卷层：FileProvider 域落在哪个卷上

### 11.1 三种「外」不共用一套读数

本篇把「外部分」拆成三种，因为公开文档给它们的读法彼此不通：**外接存储**（物理插在充电口上的设备）、**文件服务器**（在 Files 里连上的共享）、**FileProvider 域**（iCloud Drive 与第三方云在 Files 里呈现的位置）。三者的归属方分别是 DiskArbitration/挂载层、网络与会话层、FileProvider 框架。表三里的 `smb` 18 行、`afp` 1 行、`usb` 5 行、`icloud` 4 行、`cloudkit` 5 行、`fileprovider` 6 行（`C/readings-20.txt:24、25、26、28、29、31`）分属这三类，**任何把三者合并成一栏「外部存储」的台账都会掩盖它们读数面的不同**。

### 11.2 外接存储：唯一的公开格式白名单与唯一的公开结构约束

iOS/iPadOS 侧对这一格说得最多的一份文本是用户指南：`Note: An external storage device must have only a single data partition, and it must be formatted as APFS, APFS (encrypted), macOS Extended (HFS+), exFAT (FAT64), FAT32, or FAT. To change the formatting of a storage device, use the Files app or a Mac or PC.`（`A/iphone_external_storage-S.txt:1154`；iPad 版同句 `A/ipad_external_storage-S.txt:1070`，只在末尾写作 `use the Files app on iPad or a Mac or PC`）。

这是**整个语料里唯一一份把 iOS 能挂载的文件系统形态逐条列出的公开清单**，因此本篇把这一格定为 L2/L8 的形态基线：白名单含 6 项（其中一项是加密变体），且白名单里**没有 NTFS**。对照 macOS 侧那份「写不进去」清单——`APFS`／`Mac OS Extended`／`MS-DOS (FAT)`／`ExFat`，NTFS 只读不写（`A/mac_cant_save_files_external_drive-S.txt:18、21、24、25、26、27、28`）——两份清单**口径不同**：iOS 给的是「能不能挂」，macOS 给的是「能不能写」；把 macOS 那份当成 iOS 的支持矩阵是本篇第 24 章 M04 的实际写法。

同一页还给出唯一一条**结构性**约束（而非形态约束）：`must have only a single data partition`。**分区数**在接口侧没有任何键报告（表一 47 键里没有 partition 词形），第 7 章的枚举选项只有两枚（`NSVolumeEnumerationProduceFileReferenceURLs` 与 `NSVolumeEnumerationSkipHiddenVolumes`，`A/dev_filemanager_volumeenumerationoptions_S.txt:75、84`），都不涉及分区；卸载侧 `NSFileManagerUnmountAllPartitionsAndEjectDisk`（定义 `A/dev_filemanager_unmountoptions_S.txt:54`、成员名 `:62`）是唯一一处出现 partition 的接口名。也就是说：**用户文档要求「一个分区」，接口文档只有一个「对所有同类型分区」的卸载选项，两者之间没有读回**。脚本一把这一格做成 V 族信号：台账写 `single_partition=yes` 而无出处的，判错。

### 11.3 「断开」在 iOS 是拔线：一处公开的空告知面

`Disconnect the drive or card reader: Remove it from the charging port on iPhone.`（`A/iphone_external_storage-S.txt:1159`；iPad 同句 `A/ipad_external_storage-S.txt:1075`）。这一句是 Apple 对 iOS 外接存储**给出的唯一断开步骤**，动作是物理移除。同一页的浏览步骤是 `View the contents of the drive or memory card: In a supported app (for example, Files), tap Browse, then tap the name of the device below Locations.`（`:1158`／`:1074`），全页没有 eject、unmount、安全弹出之类的任何措辞。

对照第 8 章：接口侧有完整的 `unmountVolume(at:options:completionHandler:)` 与两个卸载选项，管理面侧 `unmount`／`eject`／`removable` 三个词形命中 0 键，用户文档侧唯一的断开动作是拔线。**三面在这一格互不相通**，而这三面给出的组合结果才是本篇对 iOS 外接存储的正式判定：**能力存在（接口），策略缺失（管理面），告知缺失（用户文档）**。这正是第 19 章 Q1—Q4 模型里 Q3 档（能力有、读回无、告知无）的范例。

另外，供电句 `External hard drives often require an external power source when used with iPhone.`（`:1160`／iPad `:1076`）与 iPad 的链式连接句 `On models that support Thunderbolt / USB 4, you can connect multiple USB drives and other Thunderbolt devices to each other, and then connect the chain of devices to the charging port on your iPad.`（`:1069`）是**仅有的两条把「设备拓扑」写进公开文本的句子**，但它们都没有对应读数（`thunderbolt` 词形在公告里 0 行，`C/readings-20.txt:21`）。

### 11.4 网络卷：remount 键只覆盖网络卷，且 disconnect 有 UI

`volumeURLForRemountingKey` 的定义句自带范围限定：`Key for the URL needed to remount the network volume, returned as an … if a URL is not available (read-only).`（`A/foundation_urlresourcekey_all.txt:1102、1107`）。**它不是通用重挂键**，句子里的主语是 network volume。与之配对的是 `volumeIsLocalKey` 的 `A key for determining whether the volume is on a local device.`（`:833`）与 `volumeMountFromLocationKey` 的 `The key for the volume mounted-from location.`（`:886`）。三者合起来构成网络卷在接口侧的唯一读法，而**本地外接卷没有任何 remount 读数**。

用户侧则给出网络卷独有的一个动作：`To disconnect from the file server, tap next to the server in the Browse screen.`（`A/ipodtouch_connect_servers_external_devices_files-S.txt:583`；Vision Pro 版 `A/visionpro_connect_external_servers_files-S.txt:419`）。**同一份 Files 体验里，网络服务器有 disconnect 按钮，外接存储只有拔线**——这是本篇能拿到的、关于「谁控制断开」的最直接公开差异，且它与第 8 章的 `UnmountOptions` 无任何公开关联。连接侧的公开步骤还给出了身份选择的两个取值：`Guest: You can connect as a Guest user if the shared computer permits guest access.` 与 `Registered User: If you select Registered User, enter your user name and password.`（`:581`、`:582`），这两行属于第 21 篇（账户）与第 22 篇（配件）的边界，本篇只登记「连接形态由用户在 UI 上二选一、无管理面读数」。

### 11.5 FileProvider 域不是卷：四个标识与一条资格检查

这一节是 L8 的核心。**域（domain）在 Files 里与卷并列出现在 Locations 下**（`A/iphone_find_files-S.txt:18、23、24、25、26`），但它的全部标识都不是卷标识：

- `volumeUUID`：`A universally unique value to identify types, interfaces, and other items.`（`A/fileprovider_nsfileproviderdomain_volumeUUID.txt:16`），属性名 `volumeUUID`（`:4`）。这是一个**指向卷的引用**，不是卷自身的读数。
- `documentStorageURL`：`The root URL for all shared documents.`（`A/fileprovider_nsfileprovidermanager_documentStorageURL.txt:3`）。
- `pathRelativeToDocumentStorage`：`The path of the domain’s subdirectory relative to the file provider’s shared container.`（`A/fileprovider_nsfileproviderdomain_pathRelativeToDocumentStorage.txt:3`）——**域的位置是用「相对共享容器的路径」表达的，不是用挂载点表达的**。
- `backingStoreIdentity`：`A unique identifier for the backing store used by the system.`（`A/fileprovider_nsfileproviderdomain_backingStoreIdentity.txt:3`），职责句 `Changes to this identifier indicate that the system has dropped its backing store and is creating a new one. The system may create a new backing store if the old store becomes corrupted.`（`:18`）。

**`backingStoreIdentity` 是本层唯一一处把「存储被系统重建」写成一个可观察事件的公开读数**，而且它的语义是「变了就说明换过底」，不是「换过内容」。`volumeUUID` 另给一个**可空的卷引用**（声明 `NSUUID *`，`:4`），但这一页对它的说明只有通用 UUID 那一句，没有一句把它接到「已挂载卷」或「卷形态」上。因此本篇把这一格定为：**域的数据落点有标识变化事件、有一个可空 UUID，但「这个 UUID 对应哪个已挂载卷、那个卷是什么形态」两处都不可读。** 与之相关的第 26 章 U09 登记的正是这一点。

框架提供了一条资格检查：`Checks whether the specified URL is eligible for storing a domain.`（`A/fileprovider_nsfileprovidermanager_checkDomainsCanBeStoredOnVolume.txt:3`），返回 `Constants that specify whether a URL is eligible for storing a domain.`（`:45`）的 `EligibilityResult`。**这条 API 是「域能不能落在这个卷上」的唯一公开判定入口**，但归档页只给出摘要与签名（`:49`—`:63`），**`EligibilityResult` 的取值集合在本篇归档内没有列出**；因此本篇只能引用「存在这样一个检查」，不能引用它有哪些结果（第 26 章 U10）。

### 11.6 域的三态与删除三档

域有三个彼此正交的布尔／枚举态，公开句子各管一件事：`isDisconnected`——`A Boolean value indicating that the domain is present, but disconnected from the file extension.`（`:3`），职责句 `Users can continue to browse the content from a disconnected domain; however, the File Provider extension no longer sends or receives updates about modifications to the files.`（`A/fileprovider_nsfileproviderdomain_isDisconnected.txt:17`）；`userEnabled`——`A Boolean value that indicates whether the user has enabled or disabled the domain.`（`:3`），职责句 `By default, the property is …; however, If the user disables the domain in the System Preferences, the property is …`（`:17`、`:18`）；以及 `DomainRemovalMode`——`A mode indicating how the system handles user data when removing a domain.`（`A/fileprovider_nsfileprovidermanager_DomainRemovalMode.txt:3`）的三档：`Deletes the domain but keeps any items with unsynced, local changes.`（`:55`）、`Deletes the domain, but keeps the downloaded user data.`（`:59`）、`Deletes all items in the domain.`（`:63`）。

这三组句子在本篇里被用作**「域态不等于卷态」的证据**：`isDisconnected` 描述的是扩展与域之间的连接，而不是卷与挂载表之间的关系；`userEnabled` 的主语是用户；三档删除语义里全部在讲**条目**，没有一处在讲卷或挂载点。因此把 Files 里一个消失的 iCloud 位置记成「卷被卸载」是范畴错误——本篇把它登记为第 24 章 M12。另两处必须一并登记：`isDisconnected` 的修复路径是 `To change the disconnected state, create a new … using the same identifier, and pass it to …`（`:18`）——**重连靠重建同标识对象，不靠 remount**；`userEnabled` 的关闭入口被写成 System Preferences，这是 macOS 措辞，iOS 侧无对应句（第 26 章 U11）。

### 11.7 「处理外接卷」的协议：名字在，成员不在

归档里出现了一个直接命名本层的协议：`A protocol that defines the interface for handling external volumes.`（`A/fileprovider_nsfileprovidermanager.txt:43`；同一句在 `A/fileprovider_nsfileprovidermanager_checkDomainsCanBeStoredOnVolume.txt:37`），协议名 `NSFileProviderExternalVolumeHandling`（manager 页 `:44`、`:45`）。

本篇对它的用法**只有一个**：证明 FileProvider 框架侧存在一个被明确命名为「处理外接卷」的接口面，因此「外接卷」与「域」在框架内是两件事。**不引用它的任何行为**——因为在归档的 107 个 FileProvider 页里没有该协议的成员清单页。这条负发现同时给出一条跨平面结论：**框架侧唯一命名到「外接卷」的公开实体，其成员面在本篇归档里不可读**，脚本二把它做成 Z 族一条码（见第 22 章 Z12）。

### 11.8 本层核对项

| 编号 | 核对项 | 口径 |
| --- | --- | --- |
| L8-a | iOS 外接格式白名单 | 6 项、含 APFS (encrypted)、不含 NTFS（`:1154`／`:1070`） |
| L8-b | 分区数读数 | 有要求（单分区）无读数（表一 0 键） |
| L8-c | iOS 外接断开方式 | 拔线，无 eject 措辞（`:1159`／`:1075`） |
| L8-d | remount 键适用范围 | 仅网络卷（`:1102`） |
| L8-e | 域的位置表达 | 相对共享容器的路径，非挂载点（`:3`） |
| L8-f | 域落点是否可读 | 只可读标识变化事件与可空 UUID，不可读 UUID→卷形态映射（`:4`、`:16`、`:18`） |
| L8-g | 域态与卷态 | 三轴正交，不可互换（`:3`、`:17`、`:55—63`） |
| L8-h | ExternalVolumeHandling 成员 | 归档内不可读，仅可引名字 |

---

## 12. L9 管理面回查层：216 个纯键名分母与十个零命中词形

### 12.1 分母与十个零命中

管理面本层用两份独立归档：一份是限制键名表（`B/mdm-restriction-keys.txt`，纯键名行 216 条，`C/readings-20.txt:102`），一份是声明与状态项清单（`A/mdm-*.txt` 共 27 页 2084 行）。对 216 条纯键名跑第 3 章的形态词表，结果是**十个词形命中 0**：`volume`、`mount`、`unmount`、`automount`、`removable`、`fileprovider`、`smb`、`webdav`、`apfs`、`exfat`（`C/readings-20.txt:115`）。非零的只有 `disk`=1、`usb`=2、`external`=4、`storage`=1、`media`=1、`cloud`=14、`icloud`/`file`/`backup`/`camera`/`document`/`photo`/`share` 若干（`:103—114`）。

这份零命中清单是本篇最重要的一组负读数，因为它把「管理面能不能问这个卷是什么格式、挂没挂上来」这个问题直接判死。但必须同样强调它的**分母限定**：216 是限制类键名，不含查询键与状态项；后两者在下一节单独跑。

### 12.2 非零词形里只有一个真的与盘有关

`disk` 唯一命中是 `allowStartupDiskModification`，其正文句是 `…prevents modification of Startup Disk settings in System Settings`（`A/mdm-restrictions-payload-M.txt:161`，键名行 `B/mdm-restriction-keys.txt:144`）——它管的是**启动盘设置这个界面**，不管任何卷的形态或挂载。`storage` 唯一命中是 `allowAirPrintCredentialsStorage`，正文句 `the system disables keychain storage of user name and password for airprint`（`C/readings-20.txt:117`，原句在 `B/mdm-restrictions.txt:39`）——**名字里有 storage，语义里是钥匙串**，这是第 3 章 F3（词形撞车）在管理面里的最强样本。`media` 命中是 `allowMediaSharingModification`（`A/mdm-restrictions-payload-M.txt:118`）。四个 `external` 键全部指向 external intelligence，与外接存储无关（`C/readings-20.txt:108`，其正文句 `:119—121`）。

真正能管到「外接卷能不能用」的是两条 USB 句：`allowFilesUSBDriveAccess` 的正文 `If false, the system prevents connecting to any connected USB devices in the Files app.`（`A/mdm-restrictions-payload-M.txt:87`，同表 `C/readings-20.txt:122` 记为「the system prevents connecting to any connected USB devices in the files app」，原句在 `B/mdm-restrictions.txt:381`），与 `allowFilesNetworkDriveAccess`（`:86`）配对。再加一条平台差异句：`the system allows iOS devices to always connect to USB accessories while locked. In macOS, allows new USB and Thunderbolt accessories, and SD cards to connect without authorization. If the system has Lockdown mode enabled, it ignores this value. This restriction isn’t supported on the user channel.`（`B/mdm-restrictions.txt:845`，读数行 `C/readings-20.txt:123`）。

这三条合起来给出本层唯一一条**可用的管控口径**：管理面对外接介质的控制粒度是**「Files 里能不能连 USB / 网络盘」与「锁定时能不能连配件」**，而不是「什么格式的卷能不能挂」。前者是可达性，后者才是形态——**iOS 管理面只有前者，没有后者**。

### 12.3 唯一的公开挂载策略，写在 macOS 一侧

整份 MDM 归档 2084 行里，把 mount 写成动词的只有两行，都在同一个对象里：`PROPERTY ExternalStorage : string [required=no] [since=15.0.0] [allowedValues=Allowed/ReadOnly/Disallowed] -- Specifies the mount policy for external storage: * Allowed: The system can mount external storage that’s read-write or read-only. * ReadOnly: The system can only mount read-only external storage. Note that external storage that’s read-write won’t be mounted read-only. * Disallowed: The system can’t mount any external storage.`（`A/mdm-diskmgmt-restrictions-object-M.txt:10`），以及同格式的 `NetworkStorage`（`:11`）。承载它的声明是 `DiskManagementSettings`——`ABSTRACT The declaration to configure disk management settings on the device.`、`PLATFORM macOS 15.0 [available]`、`Specify com.apple.configuration.diskmanagement.settings as the declaration type.`、唯一属性 `Restrictions : DiskManagementSettingsRestrictionsObject`（`A/mdm-diskmanagementsettings-M.txt:5、6、13、10`），示例句 `This configuration prevents the use of external and network storage devices.`（`:26`）。

这一格有三个必须同时保留的限定。其一，**平台只有 macOS**：`PLATFORM macOS 15.0 [available]`；其二，**注册与 scope 也只有 macOS**：`Allowed in supervised enrollment || macOS`、`Allowed in device enrollment || N/A`、`Allowed in user enrollment || N/A`、`Allowed in system scope || macOS`、`Allowed in user scope || N/A`（`:17—22`）；其三，**这个「ReadOnly」不降权**：`Note that external storage that’s read-write won’t be mounted read-only`（`:10`）——三档里的 `ReadOnly` 是「只接受本来就只读的外设」，不是「把它挂成只读」。第三点最容易被误写成一条降权策略，本篇把它登记为第 24 章 M08。

结论要说得比「iOS 没有这个键」更准：**公开文档里唯一一条挂载策略原语，其粒度是「介质类别 × 读写许可」，且只在 macOS 的受监督系统 scope 下可用。** 本篇因此把 iOS 侧的挂载管控定为空集，并把「用 DiskManagementSettings 论证 iOS 管控」列为第 24 章 M08。

### 12.4 SecurityInfo：管理面唯一两条卷侧读数

`A/mdm-securityinfo-dictionary-M.txt` 的字典声明覆盖 iOS 4.0 起的全平台（`:6`—`:12`），但与卷形态有关的两条属性各自带更窄的范围：`AuthenticatedRootVolumeEnabled : boolean … If true, the system booted using an Authenticated Root Volume. Available: macOS 11+`（`:16`）与 `FDE_Enabled : boolean … If true, the device has enabled FileVault full disk encryption (FDE). Available: macOS 10.9+`（`:21`），后者的两条兄弟项 `FDE_HasInstitutionalRecoveryKey`（`:22`）与 `FDE_HasPersonalRecoveryKey`（`:23`）同为 macOS 10.9+，`FDE_PersonalRecoveryKeyCMS`（`:24`）与 `FDE_PersonalRecoveryKeyDeviceKey`（`:25`）为 macOS 10.13+。

这组读数给出两条本篇要用的判定。**第一，「已用认证根卷启动」这一事实在公开管理面上只属于 macOS**，尽管字典本身跨平台；这与第 4 章引用的 iOS 侧 SSV 声明（`B/apple-platform-security-guide.txt:1119`）**方向相反**：文档说 iOS 15 起系统卷也有 SSV 保护，管理面不提供对应读回。**第二，`HardwareEncryptionCaps`（`:28`）是 iOS 侧唯一的加密形态读数，而且是设备级整数**。两者合起来即本篇对 L9 的正式判词：**管理面能读到「这台设备硬件支持哪一级加密」，读不到「这台设备上哪个卷以什么形态挂着」。**

状态回传机制本身也值得登记：`A dictionary where the keys are the status item paths and values are the corresponding status item value.`（`A/mdm-statusreport-M.txt:16`）与 `The device sends a status report when a subscribed status item changes.`（`:22`），另有每日一次全量：`FullReport … the system sets this to true when sending a “safety sync” status report, which is typically sent every 24 hours or so.`（`:18`）。**这条 24 小时兜底机制意味着：管理面对任何单条读数的「最新性」上限是订阅变更或日更，本篇不得把状态值当成实时挂载表。**

### 12.5 三个不存在的原语

本篇对 MDM 归档做了穷举核对，覆盖 63 条命令全表、49 个 configuration 声明类型加 1 个 activation、7 个 assets 与 4 个 credentials 与 3 个 management 声明、95 个状态项、210 个 Restrictions 键、DeviceInformation 的查询键与响应字典、SecurityInfo 的 23 个键。在这份穷举上，三个动作**没有原语**：**挂载一个卷**、**弹出介质**、**列出设备上已挂载的卷**。同一批归档里 `unmount`／`eject`／`removable`／`AvailableStorage` 四个词形 0 命中，而 `mount` 词形只命中上述两行策略字段与 `Volume Purchase Program` 一句误命中。

作为对照，同一份词表在平台安全指南里命中约 90 行。**系统层有完整的卷概念，管理层没有对应原语**——这是本篇 L9 与 L10 两层的连接点：正因为管理面缺原语，公告侧也没有一个可归属的「卷管理组件」，于是形态类缺陷只能落在 `apfs`／`hfs`／`corestorage` 这类实现组件名上（第 13 章）。另外三条可作边界的负发现：`ConnectedContentAccess` 这一类声明在四个拼写变体上均不存在；用户自装声明的边界句是 `Users use this profile to install declarations without requiring an MDM enrollment. A device management server can’t install a configuration profile containing this payload type.`（`A/mdm-declarations-payload-M.txt:20`）；不支持时的报错句是 `Error.ConfigurationNotSupported: The configuration is not supported for this platform, scope, or enrollment type.`（`A/mdm-declaration-base-M.txt:32`）。**这三条合起来给管理面本身的失败模式提供一个可引用口径**：平台/范围/注册类型三者任一不合，声明以错误终止，而不是静默降级。

容量这一格也归本层：DeviceInformation 的两个查询键分别是 `The key to get the available capacity.`（`AvailableDeviceCapacity`，`A/mdm-deviceinformation-queries-M.txt:20`）与 `The key to get the device’s total capacity.`（`DeviceCapacity`，`:31`），两者都 `Requires the Device Information access right` 且都按**设备**取值。**设备级容量与第 9 章的卷级容量之间没有任何公开换算**，这是第 3 章 F7 的实证，脚本一 C 族直接拦这一格。

### 12.6 本层核对项

| 编号 | 核对项 | 口径 |
| --- | --- | --- |
| L9-a | 管理面能否问卷格式 | 否（十个词形 0 命中） |
| L9-b | 管理面能否问挂载状态 | 否（无列卷/挂载/弹出原语） |
| L9-c | 唯一挂载策略 | 介质类别 × 读写许可，macOS 15+ 受监督系统 scope（`:10`、`:17—22`） |
| L9-d | ReadOnly 档语义 | 只接受本就只读的外设，不降权（`:10`） |
| L9-e | iOS 侧加密形态读数 | 只有设备级整数 `HardwareEncryptionCaps`（`:28`） |
| L9-f | 认证根卷读数平台 | 仅 macOS 11+（`:16`） |
| L9-g | 状态新鲜度上限 | 订阅变更或约 24 小时全量（`:18`、`:22`） |
| L9-h | 设备容量与卷容量 | 无换算（`:20`、`:31`） |

---

## 13. L10 公告对齐层：32 行、0 行与 150/78 的双向错位

### 13.1 语料与四个总量

本章的分母来自本地归档的一份 Apple 安全公告合并表（`C/advisory-20.tsv`，列序 `file / platform / component / cve / impact / avail`）：记录行 1266，平台去重 12，组件名去重 129，CVE 去重 330（`C/readings-20.txt:1`）。12 个平台串里与本篇相关的是 `ios 26.7.2 and ipados 26.7.2`、`ios 27.2 and ipados 27.2`、`macos golden gate 27.2`、`macos sequoia 15.8.1`／`15.8.2`、`macos tahoe 26.7.1`／`26.7.2`、`safari 27.2`、`tvos/visionos/watchos/xcode 27.2`（`:2`）。

### 13.2 中心不对齐：组件名列 32 行对影响句列 0 行

对第 3 章的形态词表分别在两列上跑一遍，得到本篇的中心数字：

| 词形 | 组件名列行数 | 组件名去重数 | 影响句列行数 |
| --- | --- | --- | --- |
| apfs | 8 | 1 | 0 |
| hfs | 11 | 1 | 0 |
| corestorage | 13 | 1 | 0 |
| exfat / ntfs / ms-dos | 0 | 0 | 0 |
| file system | 0 | 0 | 19 |
| filesystem | 0 | 0 | 0 |
| volume / unmount / automount | 0 | 0 | 0 |
| mount | 0 | 0 | 5 |

（组件名侧 `C/readings-20.txt:4—45`；影响句侧 `:47—88`。）

`apfs + hfs + corestorage = 32` 行，全部落在**同一个组件名**上（各自 1 个去重组件）；影响句列上这三个词形**以及 volume/filesystem/unmount/automount 全部是 0**。反过来，影响句列有 19 行 `file system`、5 行 `mount`、7 行 `disk`、6 行 `archive`，而这 19 行涉及的 4 个组件名**没有一个含形态词**（`:53、56、59`）。

这张表的可复用结论是：**按组件名筛「文件系统类缺陷」得 32，按影响句筛得 0，两侧之间不存在换算。** 任何「本批公告里有多少条 APFS 缺陷」的提问，在本语料上必须按两栏分别回答，且第二栏回答是「0 条把 APFS 写进了影响描述」。

### 13.3 双向错位的两份名单

错位是相互的，两个方向各有一批行：组件名含形态词而影响句不含的行 150，影响句含形态词而组件名不含的行 78（`C/readings-20.txt:89`）。两份前 20 名单如下——

**方向一（组件名命中，`:90`）**：`coremedia`=22、`photos storage`=18、`smbx`=12、`corestorage`=11、`hfs`=11、`storagekit`=9、`mediaanalysis`=8、`apfs`=6、`archiveservice`=6、`fileprovider`=6、`smb`=6、`cloudkit`=5、`iostoragefamily`=5、`libarchive`=5、`icloud`=4、`disk images`=3、`libcryptex`=3、`mediaremote`=3、`storage`=3、`archive utility`=2。

**方向二（影响句命中，`:91`）**：`packagekit`=7、`app store`=6、`coreaudio`=6、`quarantine`=6、`security`=6、`bom`=5、`printing`=4、`webkit`=4、`webkit process model`=4、`appleavd`=3、`directory utility`=3、`dyld`=3、`kernel`=3、`libxpc`=3、`system settings`=3、`zsh`=3、`coreservicesuiagent`=2、`cups`=2、`metal`=2、`appleraid`=1。

两份名单的前 20 项**交集为空**（`storage` 只出现在方向一，且是泛词命中）。这条事实比任何单点数字都更硬：**在公告语料里，「形态组件」和「形态描述」是两个几乎不相交的集合**。方向二里的 `packagekit`、`dyld`、`kernel`、`libxpc` 属于第 14、18 篇的处理范围；`quarantine` 6 行属于第 18 篇；本篇只保留与卷/挂载直接相关的 `directory utility`=3、`appleraid`=1、以及 `system settings`=3 中的启动盘语境。

### 13.4 恶意构造子集与七对撞车

`C/readings-20.txt:92` 给出一个专用子集：影响描述里出现「crafted／malformed」类字样的行 467，涉及组件去重 34；其中组件名同时命中形态词表的行 24（`:93`）。命中的七对是 `apfs<=apfs`、`archiveservice<=archive`、`corestorage<=corestorage`、`corestorage<=storage`、`hfs<=hfs`、`libarchive<=archive`、`libarchive<=libarchive`（`:94`）。

这七对里必须指出三处**词形撞车**，因为它们是「把恶意构造类缺陷读成文件系统类缺陷」的实际来源：`archiveservice<=archive` 与 `libarchive<=archive` 命中的是 `archive`（归档包），不是文件系统；`corestorage<=storage` 命中的是 `storage` 这个泛词；`libarchive<=libarchive` 与 `apfs<=apfs` 才是真同名。子集按平台的分布是 iOS/iPadOS 133、macOS 184、其余 150（`:95`）。本篇因此把这一格写成一条禁令：**在恶意构造语境里，`archive` 词形不得计入文件系统类**——第 18 篇正是处理这一族的篇目，两者在此处按视角分工（见第 2 章 2.1 的视角声明）。

### 13.5 24 行的构成：唯一一处两栏同时命中

影响句写明 `volume`／`mount`／`unmount`／`file system` 的行共 24 条（`C/readings-20.txt:96`），其组件名分布为 `packagekit`=7、`storagekit`=6、`copyfile`=3、`directory utility`=3、`corestorage`=2、`apfs`=2、`appleraid`=1（`:97`）；平台分布为 `macos golden gate 27.2`=10、`macos tahoe 26.7.2`=7、`macos sequoia 15.8.2`=6、`ios 26.7.2 and ipados 26.7.2`=1（`:98`）。**两栏同时含词形的行 13 条**（`:99`）。

这 24 行是本篇能引用的最贴近「卷/挂载类缺陷」的公开集合，但对它的读法必须带三个限定：其一，**23/24 是 macOS**（10+7+6=23），iOS 只有 1 行；其二，命中最多的组件 `packagekit` 是安装事务，不是文件系统；其三，13 条双栏命中里才包含 `apfs`=2 与 `corestorage`=2。因此本篇在 R 组读数里把这 24 行整体登记为「**面向 macOS 的挂载与卷描述缺陷集合**」，并在第 27 章结论里明确：**iOS 侧本层没有可比规模的公告证据**，这不是「iOS 没有此类缺陷」，而是「公开公告没有把这层写成 iOS 的一个组件」。

### 13.6 KEV 侧：95 条 Apple 条目里形态词形全零

`C/kev-apple.tsv` 里 Apple 条目 95 条，其组件/标题描述按同一词表命中：`sandbox`=3、`usb`=1、`storage`=1、`icloud`=1、`media`=1（`C/readings-20.txt:100`）；**写明 `volume`／`mount`／`file system`／`APFS` 的条目 0 条**（`:101`）。清单快照的目录版本与总条目数记在 `C/kev-apple.tsv.meta.txt`（`catalogVersion 2026.10.30`，count 1766）。

`storage`=1 一条命中的是 `allowAirPrintCredentialsStorage` 那一类词形撞车语境还是真实存储组件，本篇按第 3 章规则不做推断，只登记计数。KEV 侧的结论因此与公告侧一致：**在野利用清单里，没有一条被写成文件系统/卷/挂载类**。这把第 13.2 节的 32/0 错位延伸到了「在野」这一层。

### 13.7 归因规则

本章只留六条规则，其余归第 19 章判定模型。**规则一**：组件名列与影响句列分别计数，禁止合并成「文件系统类缺陷数」。**规则二**：`archive`／`storage`／`disk` 三个泛词在进入文件系统类之前必须先解撞车（13.4 的七对是唯一豁免名单）。**规则三**：影响句含 `file system` 的 19 行不得写成「APFS 缺陷」，因为它们的 4 个组件名不含形态词。**规则四**：iOS 侧只有 1 行挂载描述时，任何「iOS 挂载层缺陷统计」都必须显式给出分母 1 与来源平台串。**规则五**：KEV 0 命中只支持「公开在野清单未把这层写成卷/文件系统类」，不支持「本层无在野风险」。**规则六**：本篇所有公告读数都限定在 `C/advisory-20.tsv` 这一份 1266 行归档上；跨语料比较必须先对齐列序 `file/platform/component/cve/impact/avail`。

### 13.8 本层核对项

| 编号 | 核对项 | 口径 |
| --- | --- | --- |
| L10-a | 形态词的两栏计数 | 32 与 0，禁止合并 |
| L10-b | 影响句 4 个组件名 | 无一含形态词 |
| L10-c | 双向错位 | 150 与 78，两份名单交集为空 |
| L10-d | 泛词撞车 | archive×2、storage×1 须先解 |
| L10-e | 24 行的平台 | 23 行 macOS、1 行 iOS |
| L10-f | KEV 形态词 | 4 个词形全零 |
| L10-g | 分母声明 | 每处读数须附 1266 行语料 |

---

## 14. L11 引用与结论层：doc.* 与 devicemanagement 空间

### 14.1 两个命名空间，和一批没有 URL 的页

本篇归档里带机器可读来源标识的页只有一种命名空间：`PAGE-URL doc://com.apple.devicemanagement/documentation/DeviceManagement/…`，共 27 页（`A/mdm-*-M.txt`）。接口侧与用户指南侧的页在本归档里**只有 `PAGE-TITLE` 与 `ROLE` 行，没有 `PAGE-URL` 行**（对照 `A/dev_filemanager_mountedvolumeurlsincludingresourcevaluesforkeysoptions_S.txt:1—2`、`A/fileprovider_nsfileproviderdomain_volumeUUID.txt:1—2`、`A/mac_cant_save_files_external_drive-S.txt:1—2`）。

这条差异不是采集缺陷，而是**引用面本身的结构**：声明式管理文档用一个稳定的 `doc://` 空间标识对象与属性路径，接口文档与用户指南在归档里没有携带同层标识。对读者与台账的实际后果是：**同一份台账里两类来源的「可复核粒度」不同**——管理面一行可以复核到属性路径（`DiskManagementSettingsRestrictionsObject.ExternalStorage`），接口面一行只能复核到页标题加正文行号。本篇据此在第 28 章把来源分成 A/B/C 三组，并在脚本一的 Q 族要求每行带 `source_kind`，缺列触发 Q02。

### 14.2 证据四级

本篇对每一处结论标注证据级，四级定义如下。**一级：接口定义句**——键名加摘要句，能在归档里逐字回读（表一 47 键、7 个枚举选项、卸载 5 选项）。**二级：结构声明句**——平台安全指南与 APFS 角色页里对机制的直述（五卷清单、SSV/seal、cryptex、密钥栈、keybag）。**三级：面向用户的支持文本**——用户指南与故障页里的操作与约束句（外接格式白名单、断开步骤、连接服务器步骤、写不进去的格式清单）。**四级：本地计数读数**——第 13 章与第 16 章的全部统计，来源是本机归档表的行号，不带平台侧解释。

四级之间的方向性很重要：**一二级说「有什么读数」，三级说「用户被允许做什么」，四级说「缺陷被写成了什么」。** 本篇的三件不闭合，正是这三种说法两两互不覆盖：一二级有卷与挂载的读数、三级有格式白名单与拔线、四级里这两族词全零。任何把四级读成一二级之缺失证明的写法都是越级。

### 14.3 本层十一层汇总的可下结论与不可下结论

十一层里，本篇**可以**下的结论是：容器与卷结构（L1）有公开逐卷清单；形态声明（L2）有三个键但空位四处；能力承载（L3）有 20 键但 supports≠状态；挂载与枚举（L4）只有一条动作句且挂载方为 `unknown`；卸载与弹出（L5）有三态一选项但告知面空；容量与计数（L6）有公开反模式；加密与密钥栈（L7）句子最密但读回最少；远端域与外部卷（L8）三面互不相通；管理面回查（L9）十个词形零命中；公告对齐（L10）双向错位。

本篇**不可以**下的结论也应当与结论同权重列出：**不能**说 iOS 上某个具体卷是或不是某种格式（本篇无任何设备读数）；**不能**说某次挂载由哪个进程发起（L4 的 `unknown`）；**不能**说卸载后密钥是否仍然可用（L7 只有 `relocked` 一词）；**不能**说管理面零命中即管控缺失（零命中的是分母为 216 的键名表，且挂载策略原语确实存在，只是平台为 macOS）；**不能**说公告与 KEV 零命中即无风险（四级证据的方向性见 14.2）。这五条不可下结论同时进入第 26 章的 U 清单与第 24 章的误区表，避免只作为散文出现而被读者跳过。

### 14.4 本层核对项

| 编号 | 核对项 | 口径 |
| --- | --- | --- |
| L11-a | 来源是否带 `doc://` 标识 | 仅 MDM 27 页；其余须以页标题＋行号回读 |
| L11-b | 证据级 | 一/二/三/四级，禁止跨级推 |
| L11-c | 四级证据的方向 | 不能当一二级缺失的证明 |
| L11-d | 五条不可下结论 | 须与可下结论同权重呈现 |
| L11-e | 台账字段 | 每行须带 `source_kind` |

---

## 15. 归属矩阵：十一层 × 责任方 × 三件 × 证据

这一章把第 4—14 章的十一层压成一张表。每一层给四样东西：**谁负责**（公开口径里承载这一层判定的组件或文档面）、**三件各自处于什么状态**（形态件／挂载件／加密件：闭合、半闭合、不适用）、**最高证据级**（按本篇四级证据标度）、**对应读数**（第 16 章的 R 编号）。表后有三条读表规则。

### 15.1 矩阵

| 层 | 责任方 | 形态件 | 挂载件 | 加密件 | 最高证据级 | 读数 |
| --- | --- | --- | --- | --- | --- | --- |
| L1 容器与卷结构 | APFS 容器与卷管理器 | 半闭合：结构侧写明「至少两个卷」，接口侧无容器键 | 不适用 | 不适用（密钥按文件类，不按容器） | 二级 | R28—R31 |
| L2 形态声明 | URLResourceKey 词表 + 平台支持文档 | 闭合：3 个键 + 2 份白名单 | 不适用 | 半闭合：`encrypted` 是格式项而非属性 | 一级 | R03—R07、R32—R38 |
| L3 能力承载 | 20 个 `volumeSupports*` 键 | 闭合：能力可逐项读回 | 半闭合：`supports` 不等于「已挂载」 | 不适用 | 一级 | R34—R38 |
| L4 挂载与枚举 | FileManager 枚举接口 | 不适用 | 闭合：URL 列表 + 枚举选项 | 不适用 | 一级 | R07、R37 |
| L5 卸载与弹出 | FileManager 卸载接口 + 异议进程 | 不适用 | 闭合：2 个选项（5 个公开标识符）+ 开始/完成语义 | 半闭合：重锁是后置效果 | 一级 | R37—R38 |
| L6 容量与计数 | 卷级可用空间读数 | 不适用 | 不适用 | 不适用 | 二级 | R10—R12 |
| L7 加密与密钥栈 | Secure Enclave + Data Protection 类 | 不适用 | 半闭合：与挂载只有一个交点 | 半闭合：五级密钥栈可读，卷键归属性不可推 | 二级 | R28—R31 |
| L8 远端域与外部卷 | FileProvider + 外接存储白名单 | 闭合：6 项白名单 | 半闭合：外接卷协议成员不可读 | 半闭合：`volumeIsEncrypted` 与类无换算 | 一级/二级 | R07、R17—R20 |
| L9 管理面回查 | 限制键 + 声明类型 + StatusReport | 不闭合：`volume`=0 | 半闭合：唯一挂载策略在 macOS | 半闭合：只有设备级布尔 | 一级 | R23—R24 |
| L10 公告对齐 | 安全公告组件列与影响句列 | 不闭合：32 行对 0 行 | 不闭合：`mount` 5 行无形态组件 | 不闭合：影响句零加密词形 | 四级 | R08—R22 |
| L11 引用与结论 | `doc://` 空间与页标题 | 闭合：两种引用粒度都在 | 同上 | 同上 | 一级/二级 | R25—R27 |

### 15.2 三条读表规则

**规则一：矩阵里「闭合」只表示三面都有读数，不表示三面互相可换算。** L2 的形态件是闭合的（三个键加两份白名单），但加密件只有一项格式菜单里的 `APFS（encrypted）`（`A/iphone_external_storage-S.txt:1154`），与 `volumeIsEncryptedKey` 的布尔之间没有公开换算——这就是第 3 章 F1 的落点。

**规则二：只有 L2、L3、L4、L5 四层的最高证据级是一级（接口定义）。** 结构侧（L1、L7）与公告侧（L10）都只能到二级或四级。任何把公告组件名当作「这一层的一级读数」的写法，都越了一级。

**规则三：「不适用」不是缺口。** L3 与 L4 的加密件不适用，是因为能力键与枚举接口本身不承载加密语义；把这些格子记成「缺失」会让三件闭合面数虚高，脚本二因此在三件闭合计算里对不适用的格子取 0 而不取 1。

---

## 16. 公开读数：这条链路上能数出来的十三组事实

本章给 R01—R38。每条读数都限定在两份归档上：公告归档 `C/advisory-20.tsv`（1266 行）与在野清单 `C/kev-apple.tsv`（Apple 条目 95 条，目录版本 `catalogVersion 2026.10.30`，总条目 1766）。**所有行号都是 `C/readings-20.txt` 的行号**，不是原始 TSV 的行号；这样任何读者都能用同一份读数表复核。

### 16.1 第一组：语料总量

| 编号 | 读数 | 锚 |
| --- | --- | --- |
| R01 | 公告归档 1266 行，平台去重 12，组件名去重 129，唯一 CVE 330 | `C/readings-20.txt:1` |
| R02 | 12 个平台串，含 iOS/iPadOS 26.7.2 与 27.2、macOS Golden Gate 27.2 等 | `C/readings-20.txt:2` |

R01 的分母关系要说清楚：1266 行不等于 1266 条缺陷，因为同一 CVE 会在多个平台串下重复出现；330 才是唯一 CVE 数。**任何「每行一条缺陷」的统计都会高估约 3.8 倍。**

### 16.2 第二组：平台清单

R02 的价值不在数量，而在**平台串的写法**：iOS 与 iPadOS 永远成对出现（`ios 26.7.2 and ipados 26.7.2`），因此「iOS 侧有多少行」这个问题在归档里没有独立答案——只能回答「成对平台串有多少行」。

### 16.3 第三组：组件名列的词形命中

| 编号 | 读数 | 锚 |
| --- | --- | --- |
| R03 | `apfs` 8 行/1 组件、`hfs` 11 行/1 组件、`corestorage` 13 行/1 组件 | `C/readings-20.txt:4—6` |
| R04 | `disk` 6 行/2 组件（disk images、diskarbitration）、`storage` 54 行/5 组件 | `C/readings-20.txt:16—17` |
| R05 | `smb` 18 行/2 组件、`afp` 1 行/1、`icloud` 4 行/1、`cloudkit` 5 行/1、`fileprovider` 6 行/1 | `C/readings-20.txt:25—29、31` |
| R06 | `archive` 13 行/3 组件、`libarchive` 5 行/1、`copyfile` 3 行/1、`cryptex` 3 行/1、`media` 33 行/3、`usb` 5 行/1 | `C/readings-20.txt:24、33—36、44` |
| R07 | **25 个零命中词形**：`volume`、`mount`、`unmount`、`automount`、`file system`、`filesystem`、`exfat`、`ntfs`、`ms-dos`、`external storage`、`removable`、`ejectable`、`thunderbolt`、`card reader`、`sd card`、`file provider`、`webdav`、`nfs`、`preboot`、`snapshot`、`clone`、`data protection`、`keybag`、`container`、`folder` | `C/readings-20.txt:7—15、18—23、27、30、32、37—41、43、45` |

R03 是「形态组件」这一侧唯一的三个真同名：`apfs`、`hfs`、`corestorage` 的组件名与词形完全一致。R04 的两个词必须分开读：`disk` 的 2 个组件里没有一个是文件系统驱动（一个是镜像工具、一个是仲裁守护进程），`storage` 的 5 个组件里只有 `corestorage` 是存储管理层，其余四个是媒体与照片侧的泛词。

R07 是第 2 章视角声明的数据基础：**在最该出现「卷」这个词的地方（组件名列），`volume` 是 0。** 这一条比任何单点命中都更能说明本层没有形态维度——不是命中少，而是根本不出现。

### 16.4 第四组：影响句列

| 编号 | 读数 | 锚 |
| --- | --- | --- |
| R08 | 影响句命中 `apfs`／`hfs`／`corestorage`／`exfat`／`ntfs`／`ms-dos`／`filesystem`／`volume`／`unmount`／`automount` 全部为 0 | `C/readings-20.txt:47—52、54—55、57—58` |
| R09 | 影响句命中 `file system` 19 行/4 组件、`mount` 5 行/3 组件、`disk` 7 行/4 组件、`archive` 6 行/2 组件、`usb` 5 行/1、`icloud` 1 行/1、`media` 10 行/2 | `C/readings-20.txt:53、56、59、67—68、78、87` |

R08 与 R09 合起来是本篇的中心事实：**影响句里出现的从来不是「文件系统类型」，而是「挂载这个动作」与「磁盘这个东西」。** 19 行 `file system` 分布在第 13 章点名的 4 个组件上，这 4 个组件名没有一个含形态词。

### 16.5 第五组：双向错位

| 编号 | 读数 | 锚 |
| --- | --- | --- |
| R10 | 组件名含词形而影响句不含 = 150 行；影响句含而组件名不含 = 78 行 | `C/readings-20.txt:89` |
| R11 | 两个前 20 名单（方向一以 `coremedia`=22 起，方向二以 `packagekit`=7 起） | `C/readings-20.txt:90—91` |
| R12 | 两份名单交集为空（除 `storage` 一侧） | `C/readings-20.txt:90—91` |

R12 的证明方式是把 R11 的两份名单逐项比对：方向一的前 20 里出现的都是媒体、存储、归档组件；方向二的前 20 里出现的是安装事务（`packagekit`）、商店（`app store`）、隔离（`quarantine`）、内存管理（`dyld`）、内核（`kernel`）、shell（`zsh`）。**两组组件在工程上几乎没有重叠，这不是巧合，是「形态归属」与「形态描述」被写在了两套不同的组件分类里。**

### 16.6 第六组：恶意构造子集

| 编号 | 读数 | 锚 |
| --- | --- | --- |
| R13 | 含「恶意构造」类字样的 467 行，组件去重 34 | `C/readings-20.txt:92` |
| R14 | 其中组件名命中形态词形 24 行 | `C/readings-20.txt:93` |
| R15 | 七对「影响句词形 ≤ 组件名」：`apfs<=apfs`、`archiveservice<=archive`、`corestorage<=corestorage`、`corestorage<=storage`、`hfs<=hfs`、`libarchive<=archive`、`libarchive<=libarchive` | `C/readings-20.txt:94` |
| R16 | 按平台：iOS/iPadOS 133、macOS 184、其余 150 | `C/readings-20.txt:95` |

R15 里只有两对是真同名（`apfs<=apfs`、`hfs<=hfs`），另有两对是「同一组件对同一词形的包络」（`corestorage<=corestorage`、`libarchive<=libarchive`），剩下三对是词形撞车（`archive` 两次，`storage` 一次）。**24 行这个数字不能直接当作「恶意构造文件中文件系统缺陷 24 行」使用**，必须先扣掉撞车项——这是第 13.4 节与第 24 章 M02 的同一个禁令。

### 16.7 第七组：面向挂载的 24 行

| 编号 | 读数 | 锚 |
| --- | --- | --- |
| R17 | 影响句写明 `volume`／`mount`／`unmount`／`file system` 的行 = 24 | `C/readings-20.txt:96` |
| R18 | 组件分布：`packagekit`=7、`storagekit`=6、`copyfile`=3、`directory utility`=3、`corestorage`=2、`apfs`=2、`appleraid`=1 | `C/readings-20.txt:97` |
| R19 | 平台分布：macOS Golden Gate 27.2=10、macOS Tahoe 26.7.2=7、macOS Sequoia 15.8.2=6、iOS/iPadOS 26.7.2=1 | `C/readings-20.txt:98` |
| R20 | 上述行里组件名与影响句同时含词形的行数 = 13 | `C/readings-20.txt:99` |

R19 是本篇对 iOS 侧下的最重要一个限定：**24 行里 23 行是 macOS，iOS 只有 1 行。** 因此本篇所有「挂载描述缺陷」的结论都只能写成「面向 macOS 的公开集合」，iOS 侧的分母是 1，且必须显式给出。

### 16.8 第八组：KEV

| 编号 | 读数 | 锚 |
| --- | --- | --- |
| R21 | Apple 条目 95，词形命中：`sandbox`=3、`usb`=1、`storage`=1、`icloud`=1、`media`=1 | `C/readings-20.txt:100` |
| R22 | 写明 `volume`／`mount`／`file system`／`APFS` 的条目 = 0 | `C/readings-20.txt:101` |

R22 只能支持一个弱结论：**公开在野清单没有把这一层写成卷或文件系统类。** 它不支持「这一层没有在野风险」——清单的收录标准是针对已被利用的 CVE，未收录的原因既可能是没被利用，也可能是被利用但未被归到这个词形。第 20 章 O6 因此把这个指标定义为「覆盖缺口」，不是「风险为零」。

### 16.9 第九组：管理面键名

| 编号 | 读数 | 锚 |
| --- | --- | --- |
| R23 | 限制键纯键名 216 个；`disk`=1（`allowStartupDiskModification`）、`storage`=1（`allowAirPrintCredentialsStorage`）、`usb`=2、`external`=4、`file`=5、`cloud`=14 | `C/readings-20.txt:102—108` |
| R24 | 关键读数：`volume`=0、`mount`=0、`disk`=1、`usb`=2、`external`=4、`removable`=0、`fileprovider`=0、`smb`=0、`webdav`=0、`apfs`=0、`exfat`=0、`media`=1 | `C/readings-20.txt:115` |

R24 的 12 个读数里，**有 8 个是 0**。这 8 个零命中的意义与 R07 相同：管理面不是「控制得弱」，而是「没有这个维度的键」。

### 16.10 第十组：限制项正文

| 编号 | 读数 | 锚 |
| --- | --- | --- |
| R25 | 限制项正文 1530 行，词形命中：`disk`=1、`external`=6、`icloud`=15、`media`=2、`storage`=2、`usb`=2、`volume`=1 | `C/readings-20.txt:116` |
| R26 | `allowAirPrintCredentialsStorage` 的正文语义是「禁用钥匙串中存储的用户名与密码」 | `C/readings-20.txt:117` |
| R27 | `allowUSBRestrictedMode` 的正文在 macOS 侧写的是「允许新的 USB 与雷雳配件以及 SD 卡在未授权情况下连接」 | `C/readings-20.txt:123` |

R25 里那个唯一的 `volume` 出现在 :909 的正文中，语境是「用户级批量采购计划」（volume purchase program），**与卷无关**。这是本篇登记的第二处词形撞车，也是脚本一 D09 的第二个用例。

### 16.11 第十一组：平台安全指南

| 编号 | 读数 | 锚 |
| --- | --- | --- |
| R28 | 指南 4886 行；词频：`volume`=135、`Data Protection`=141、`FileVault`=77、`keybag`=64、`file system`=39、`APFS`=28、`mount`=25、`mounted`=7、`cryptex`=24、`preboot`=4、`read-only`=11、`removable`=6、`snapshot`=5、`external storage`=2、`Apple File System`=10 | `C/readings-20.txt:128` |
| R29 | 含 `volume`／`mount`／`APFS`／`cryptex`／`preboot` 的行数 = 99 | `C/readings-20.txt:129` |
| R30 | 99 行的行号首现集合（32 个行号，从 58 到 1131） | `C/readings-20.txt:129` |
| R31 | 四条关键口径：UID 与内部存储（:313）、SSV（:1119）、cryptex（:1174）、Data Protection 与 FileVault 的分工（:1748） | `C/readings-20.txt:130—133` |

R28 的词频里有一个容易被忽略的比例：`volume` 出现 135 次，而 `mount` 只出现 25 次、`mounted` 7 次。**指南大量在讲「卷」，很少在讲「挂载这个动作」**——这与公告侧的分布正好相反（公告侧 `file system` 19 行、`mount` 5 行、`volume` 0 行）。两侧的用词习惯不同，是第 3 章 F2 的直接来源。

### 16.12 第十二组：声明类型

| 编号 | 读数 | 锚 |
| --- | --- | --- |
| R32 | 声明类型 66 项，分 8 族：Account 8、App 2、Content 2、Disk 1、External 1、File 1、Network 7、Passcode 1 | `C/readings-20.txt:141—149` |
| R33 | 与盘直接相关的只有 `DiskManagementSettings` 一项 | `C/readings-20.txt:145` |

R32 的分族里，`External` 那一项是 `ExternalIntelligenceSettings`——**与外部存储无关**，是外部智能服务的开关。这是本篇登记的第三处词形撞车，出现在声明类型的族名上。

### 16.13 第十三组：URLResourceKey 词表

| 编号 | 读数 | 锚 |
| --- | --- | --- |
| R34 | 标识符 131 个：volume 前缀 47、`volumeSupports*` 20、`volumeIs*` 10、非 Key 结尾 4 | `C/readings-20.txt:150` |
| R35 | 非 volume 前缀 = 84 | `C/readings-20.txt:151` |
| R36 | 纯「形态与挂载语义」键 = 0 | `C/readings-20.txt:152` |
| R37 | 键名含 `mount` 的 4 个：`isMountTriggerKey`、`volumeIsAutomountedKey`、`volumeMountFromLocationKey`、`volumeURLForRemountingKey` | `C/readings-20.txt:153` |
| R38 | 键名含 `eject`／`unmount`／`remov` 的 2 个：`volumeIsEjectableKey`、`volumeIsRemovableKey` | `C/readings-20.txt:154` |

R36 是本篇最硬的一条负读数：**131 个标识符里，没有任何一个键的语义是「这个卷以什么方式挂载」或「这个卷属于哪种文件系统形态」。** 形态靠 `volumeTypeNameKey`／`volumeSubtypeKey`／`volumeLocalizedFormatDescriptionKey` 三个描述性键给出，挂载靠 `volumeIsMountTriggerKey` 一类布尔给出，两者在词表里没有关系。

---

## 17. 可见性边界：这一层读者能拿到什么

### 17.1 能拿到的四类

**一、接口面的完整词表。** 131 个标识符全部公开，47 个 volume 前缀键的定义逐条可读（`C/readings-20.txt:150`）。这是本篇唯一一个「分母确定」的读数面。

**二、结构面的定性描述。** 5 个卷的角色、SSV 的校验时机、cryptex 的存放位置、keybag 的两套可擦机制，全部有正文（`C/readings-20.txt:130—133`）。

**三、管理面的键名清单。** 216 个纯键名与 66 个声明类型逐项可读（`C/readings-20.txt:102—108、141—149`）。

**四、公告侧的行级计数。** 1266 行、129 个组件名、330 个 CVE，按任意词形可重算（`C/readings-20.txt:1`）。

### 17.2 拿不到的五类

**一、驱动内部的挂载路径。** 没有任何公开文档描述从 `mount(2)` 到 APFS 卷挂载的调用链；能读到的只有「谁负责校验」这一句（`B/apple-platform-security-guide.txt:772`）。

**二、实际生效的挂载选项。** 接口给出 2 个卸载选项（`A/dev_filemanager_unmountoptions_S.txt:54、62、70、78`），但没有任何接口返回「当前这个卷是以哪些选项挂上的」。

**三、逐卷密钥。** 五级密钥栈的结构可读，但「这个具体卷的卷键是什么、由哪一级包裹」没有任何公开读数；`volumeIsEncryptedKey` 只回答布尔。

**四、分区布局。** 用户文档要求「只有一个数据分区」（`A/iphone_external_storage-S.txt:1154` 所在页），接口侧只有 `NSFileManagerUnmountAllPartitionsAndEjectDisk` 一个卸载选项名提到分区（`A/dev_filemanager_unmountoptions_S.txt:62`）——**没有任何键报告分区数量**。

**五、iOS 侧的挂载策略原语。** 唯一的公开策略原语 `DiskManagementSettings` 只在 macOS 可用（`A/mdm-diskmanagementsettings-M.txt:6`）。iOS 侧这一格是空集，不是「策略为默认值」。

### 17.3 边界表

| 想回答的问题 | 能不能回答 | 依据 |
| --- | --- | --- |
| 这个卷是 APFS 吗 | 能 | `volumeTypeNameKey`（`A/foundation_urlresourcekey_all.txt:1098`） |
| 这个卷加密了吗 | 能，但只是布尔 | `volumeIsEncryptedKey` |
| 它用哪一级密钥加密 | 不能 | 无公开键 |
| 它挂在哪、以什么选项挂 | 部分能（只知枚举与卸载选项） | `mountedVolumeURLs`／`UnmountOptions` |
| 它有几个分区 | 不能 | 无公开键 |
| 它在公告里算哪类缺陷 | 不能 | 组件名列 32 行、影响句 0 行 |
| 它在野被利用过吗 | 不能 | KEV 0 条（R22） |
| 它受MDM管控吗（iOS） | 不能 | 策略原语仅 macOS |

---

## 18. 五个读数面：接口侧、结构侧、加密侧、管理侧、公告侧

五个面不是五种证据级，而是五种**观察位置**。同一个事实在五个面上的可读性不同，混用会产生第 24 章的十二个误区。

### 18.1 接口侧

**读什么**：131 个 URLResourceKey、FileManager 的枚举与卸载接口、FileProvider 的域资格检查。
**读得到**：类型名、子类型、本地化描述、20 项能力、10 项布尔、2 个卸载选项、域的四种标识。
**读不到**：挂载方式、分区数、逐卷密钥、任何 iOS 侧策略。
**代表读数**：R34—R38。
**误读风险**：把 `volumeSupportsCaseSensitiveNames` 一类能力键当作「已生效」；把 `volumeIsInternalKey` 推成「受 UID 绑定保护」（第 2 章已列为禁区，脚本一 D06 拦）。

### 18.2 结构侧

**读什么**：平台安全指南中关于卷、SSV、cryptex、keybag 的正文。
**读得到**：5 卷角色、校验时机（mount 之前）、cryptex 位于 preboot、两套可擦机制。
**读不到**：任何具体的挂载表、任何逐卷状态。
**代表读数**：R28—R31。
**误读风险**：把「系统卷受 SSV 保护」推成「所有卷受 SSV 保护」；把「Class C 使用卷键」推成「iOS 的每个卷都有独立卷键」。

### 18.3 加密侧

**读什么**：Data Protection 的类定义、五类 keybag、UID 与 Effaceable Storage。
**读得到**：类与策略、keybag 存放方式按 SoC 世代分叉、Class D 仅 UID。
**读不到**：类与卷形态的对应关系、任意一卷的实际类分布。
**代表读数**：R31（:313、:1748、:1912、:1927、:1944、:1970、:1974、:2184）。
**误读风险**：把 `APFS（encrypted）` 这个格式项当作加密类；把「卷已挂载即所有类可访问」（:1974，且该句限定 macOS）当作 iOS 规则。

### 18.4 管理侧

**读什么**：216 个限制键、66 个声明类型、SecurityInfo 与 StatusReport。
**读得到**：一个盘相关限制键、一个存储声明、一个 macOS 状态项、两个设备级容量查询键。
**读不到**：卷形态、挂载状态、逐卷容量、iOS 侧任何挂载策略。
**代表读数**：R23—R24、R32—R33。
**误读风险**：把 `allowAirPrintCredentialsStorage` 当作存储形态读数（D09）；把 `DiskManagementSettings` 当作 iOS 策略（M08）。

### 18.5 公告侧

**读什么**：1266 行公告的组件名列与影响句列。
**读得到**：按词形的行级计数、双向错位、恶意构造子集、KEV 命中。
**读不到**：任何形态与缺陷类型的对应关系。
**代表读数**：R08—R22。
**误读风险**：把组件名列命中当作缺陷类型（M01）；把 `archive`／`storage` 撞车计入文件系统类（M02）；把 KEV 0 命中读成无风险（M03）。

### 18.6 五面对照表

| 面 | 分母 | 形态可读 | 挂载可读 | 加密可读 | 最高证据级 |
| --- | --- | --- | --- | --- | --- |
| 接口侧 | 131 键 | 3 描述键 + 20 能力键 | 枚举 + 2 选项 | 1 布尔 | 一级 |
| 结构侧 | 4886 行 / 99 相关行 | 定性 | 校验时机 | 五级结构 | 二级 |
| 加密侧 | 5 类 + 5 keybag | 无 | 1 个交点 | 类与策略 | 二级 |
| 管理侧 | 216 键 / 66 声明 | 0 | 1（macOS） | 1 设备布尔 | 一级 |
| 公告侧 | 1266 行 | 32 行 | 5 行（无形态组件） | 0 行 | 四级 |

---

## 19. 两套判定模型：J1—J4 与 Q1—Q4

### 19.1 J1—J4：记录级判定

J 模型作用在**一条台账记录**上，回答「这条记录能不能用」。

| 判定 | 含义 | 触发条件 | 脚本一动作 |
| --- | --- | --- | --- |
| J1 | 完整 | 无信号，或只有提示类信号 | 计入 `判定分布 J1` |
| J2 | 有缺口 | 命中非阻断类的警告码 | 计入 `判定分布 J2`，退出码不变 |
| J3 | 有错误 | 命中错误类码（字段冲突、越界、误推） | 计入 `判定分布 J3`，退出码 1 |
| J4 | 阻断 | 命中阻断类码（行式与标识 `A01—A08`、证据级 `Q01`／`Q02`／`Q04`、密钥栈 `K01`／`K04`／`K06`、容器必填 `C01`） | 计入 `判定分布 J4`，退出码 1 |

阻断类码的集合是 `A01—A08`、`Q01`、`Q02`、`Q04`、`K01`、`K04`、`K06`、`C01`；错误类的集合是 `C03`、`C05`、`C07`、`D01`、`D02`、`D04`、`D06`、`D07`、`D09`、`D11`、`D12`、`E01`、`E03`、`E05`、`H02`、`H03`、`H08`、`H09`、`K03`、`K07`、`K08`。两组之间不重叠，其余码为警告类。

### 19.2 Q1—Q4：集合级闭合等级

Q 模型作用在**三件（形态件／挂载件／加密件）的面上**，回答「这一类结论闭合到什么程度」。

| 等级 | 含义 | 面数（每件固定四面） |
| --- | --- | --- |
| Q1 | 闭合 | ≥ 3/4 面有读数 |
| Q2 | 半闭合 | 2/4 面 |
| Q3 | 单面 | 1/4 面 |
| Q4 | 空 | 0/4 面 |

三件的面定义是：

- **形态件**：volume 前缀键 > 0；平台侧卷语句 > 0；公告组件列或影响列有形态词形；盘类声明 > 0。
- **挂载件**：挂载语义键 > 0；平台侧挂载语句 > 0；公告影响列有形态词形；管理面有挂载类键名。
- **加密件**：卷级加密键 > 0；平台侧加密语句 > 0；卷级加密与文件类换算读数 > 0；管理面有加密能力读数。

**总判定**取三件里最差的一件（任一件 Q4 则总判定 Q4）。脚本二在夹具上的实测是：干净读数三件都 4 面、总判定 Q1；全零读数三件都 0 面、总判定 Q4；公告与回查全坏时总判定 Q3（形态件剩接口与结构两面、加密件剩结构一面）。

### 19.3 两套模型不能相加

J 与 Q 的对象不同、分母不同、方向也不同：J 越大越差（J4 最差），Q 越小越差（Q1 最好）。任何「J2 + Q2 = 4」式的合并都无意义。本篇的做法是**并列呈现**：台账逐条给 J，三件给 Q，两者之间只有一条对应关系——**被 J4 阻断的记录不参与 Q 的面计数**，因为它的面读数不可用。

### 19.4 两套模型的适用边界

J 模型只适用于「有台账」的场景：读者需要自己维护一份卷挂载台账（字段表见第 21.2 节），脚本逐字段审。Q 模型只适用于「有读数」的场景：读者按第 16 章的口径重算 44 个度量，脚本按面计数。**没有台账就不要用 J，没有读数就不要用 Q。**

---

## 20. 运营指标 O1—O10

这一章把前面的事实折成十个可跟踪的指标。每个指标给定义、本期取值与阈值。本期取值的分母全部来自 R01—R38，不引入新数据。

| 编号 | 指标 | 定义 | 本期取值 | 阈值 |
| --- | --- | --- | --- | --- |
| O1 | 形态词组件命中率 | 组件名列命中形态词的行 / 总行 | 32/1266 = 2.5% | < 5% 视为「无形态维度」 |
| O2 | 形态词影响句命中率 | 影响句列命中形态词的行 / 总行 | 0/1266 = 0% | 0 即视为不闭合 |
| O3 | 换算失败数 | 三套词表之间无法换算的处数 | 8（F1—F8） | > 0 即须逐处声明 |
| O4 | 双向错位比 | 方向一行数 / 方向二行数 | 150/78 = 1.92 | 交集为空即视为两套分类 |
| O5 | 恶意构造撞车率 | 撞车配对数 / 命中配对数 | 3/7 = 42.9% | > 0 即须扣减 |
| O6 | 在野覆盖缺口 | 1 − KEV 形态命中 / KEV 总条目 | 1 − 0/95 = 100% | 100% 记「未覆盖」，不记「无风险」 |
| O7 | 管理面形态键命中率 | 管理面命中形态词键数 / 216 | 1/216 = 0.46% | < 1% 视为无该维度 |
| O8 | 声明类型盘类命中率 | 盘类声明 / 66 | 1/66 = 1.5% | < 2% 视为无该维度 |
| O9 | 挂载集合平台集中度 | macOS 行 / 24 行挂载集合 | 23/24 = 95.8% | > 90% 时禁止外推 iOS |
| O10 | KEV 语料占比 | Apple 条目 / KEV 总条目 | 95/1766 = 5.4% | 仅作分母登记 |

### 20.1 指标之间的三条约束

**约束一：O1 与 O2 必须同时报。** 只报 O1 会得出「公告里有 2.5% 的文件系统类缺陷」，只报 O2 会得出「公告里完全没有文件系统类缺陷」。两个数字合起来才是本篇要表达的事实：**同一批公告里，组件名有 32 行、影响句 0 行。**

**约束二：O3 与 O4 是同一件事的两种量法。** O3 数的是词表之间缺换算的处数，O4 数的是行之间错位的比例。前者是结构性的（八处换算失败），后者是统计性的（150 与 78）。两者不能互相替代。

**约束三：O6 与 O10 的分母必须写清。** O6 的分母是 95（Apple 条目），O10 的分母是 1766（KEV 全部条目）。混用分母会把 0/95 写成 0/1766，看起来结论一样，实际是两次不同的统计。

### 20.2 指标的采集方式

十个指标里 O1、O2、O4、O5、O7、O8、O9 可以直接用脚本二的读数文件重算，只需把 44 个度量里的对应项填好；O3 需要人工确认（词表之间的换算关系不是计数）；O6 与 O10 需要 KEV 快照的目录版本与条目总数（`C/kev-apple.tsv.meta.txt`）。**没有任何一个指标需要接触真实设备、真实卷或联网服务。**

---

## 21. 只读核验脚本一：卷挂载台账逐字段审查器

这支脚本回答一个问题：**一个卷被登记成一行台账之后，这行台账自己站不站得住**（头部第 5 行逐字）。它不检查设备、不打开任何被登记的卷、不调用任何磁盘工具，只检查登记本身。

### 21.1 输入与边界

输入是一份或多份台账文本，每行三列：`<卷或域记录标识>,<字段名>,<值>`；`#` 开头与空行忽略，行尾 CR 由 `tr -d '\r'` 去掉，**值里不能含逗号**（usage 第 20 行逐字），列数不是三即 `A01`（第 122 行）。记录标识四类前缀与 `id.url_kind` 的取值域一一对应：`V_` 本地卷／`D_` FileProvider 域／`M_` 外接介质／`N_` 网络卷（usage 第 21 行）；前缀不在四类内即 `C02`（第 156 行），末尾的 `前缀记录数 V_= D_= M_= N_=` 一行（第 304 行）是这支脚本特有的分组读数。

参数校验只有两条：至少一份输入（第 50 行）、每份都存在且可读（第 51—53 行），不满足一律退出码 2。多份一次传入是合法用法且**合并读入而不是分批读入**（`cat "$@"`，第 58 行）：同一记录的同一字段出现两次即 `A06`（第 131 行）并丢弃第二次的值——台账不是流水账，一个字段只能有一个取值。边界句在头部第 5—12 行：不含挂载、卸载、格式化、加密或抹除的操作步骤，不含绕过保护或降权的手法，不含对任何具体设备、卷或密钥材料的采集与还原。

### 21.2 九个命名空间、54 个字段与必备 20 格

命名空间集合写死在第 91 行，恰好 9 项：`id`／`vol`／`mnt`／`umn`／`cap`／`key`／`mgmt`／`adv`／`doc`。usage 第 22—34 行逐空间列出字段清单；`KNOWN` 清单在第 92—103 行，共 **54 个字段**，按空间分布是 id 4 个、vol 10 个、mnt 10 个、umn 4 个、cap 5 个、key 9 个、mgmt 3 个、adv 5 个、doc 4 个。字段名不在 `KNOWN` 内按 `A04` 记（第 127 行），命名空间不在 `NS` 内按 `A03` 记（第 126 行）。

必备格 20 个由第 104—106 行的 `REQ` 写死：`id.volume_id id.url_kind id.source_kind id.evidence_level vol.role vol.fs_form vol.type_name vol.subtype vol.supports vol.seal mnt.state mnt.options mnt.actor mnt.verify_order umn.state umn.after cap.kind key.scope key.keybag_class adv.component`。缺格不是统一发一个码，而是按字段归属分派（第 145—152 行）：

| 缺的字段 | 发出的码 | 落入哪一档 |
| --- | --- | --- |
| `id.url_kind` | `A07` | J4 阻断 |
| `id.source_kind` | `Q02` | J4 阻断 |
| `id.evidence_level` | `Q01` | J4 阻断 |
| `vol.*` 任一 | `C01` | J4 阻断 |
| `key.scope`／`key.keybag_class` | `K01` | J4 阻断 |
| `cap.kind` | `E03` | J3 错误 |
| `mnt.*`／`umn.*` 任一 | `H01` | J2 警告 |
| `adv.component` | `Q06` | J2 警告 |

这张表纠正一个常见误读：**「必备格缺失」不等于「一律 J4」**。卷结构、证据级、密钥栈三类缺格确实阻断；容量类缺格只到 J3；挂载／卸载类与公告组件名缺格只到 J2，因为这两类读数可以在别处补，记录本身还能用。第 19.1 节把 J4 的触发条件收窄到具体码集，正是为了避免把这张表压成一句「缺必填即阻断」。

枚举取值在第 107—117 行逐格写死：`vol.role` 9 值、`vol.fs_form` 8 值、`id.url_kind` 5 值、`umn.state` 4 值、`id.source_kind` 7 值、`id.evidence_level` 4 值、`cap.kind` 5 值、`key.scope` 5 值、`mnt.options` 6 值、`mnt.verify_order` 3 值。越界分别按 `C02`、`D01`、`A08`、`H01`、`Q02`、`Q01`、`E03`、`K01`、`H02`、`H11` 记。

### 21.3 形态受检字段、行号形态与取值拒收

形态受检字段的判定点分散在记录循环与 END 段：

- `A05` 拦两类取值：空值（第 128 行）与 `dirty()` 命中的取值（第 129 行）。`dirty()` 定义在第 82—88 行，四条判据是：以 `/private/`、`/System/`、`/Volumes/`、`/Users/`、`$HOME/`、`~/` 开头的路径形态；含 `glpat-`、`ghp_`、`gho_`、`xox[baprs]-`、`AKIA…`、`Bearer `、`-----BEGIN` 之一的凭据形态；长度超过 160 字符；80 字符以上的 Base64 形状。命中即拒收该字段。A05 是阻断码。
- `Q04` 拦 `doc.line_ref`：只允许 `1234` 或 `6-9` 两种形态（第 245 行）。带「第／行」前后缀的中文写法在归档行号与台账行号之间不可换算。
- `D01` 拦 `vol.fs_form` 越界（第 194 行）；`D04` 用 `typeForm()`（第 72—81 行）把 `APFS`／`APFS (Encrypted)`／`Mac OS Extended`／`HFS+`／`ExFAT`／`MS-DOS (FAT)` 等写法折成同一形态名，再与 `fs_form` 比对（第 201 行）。
- `C02` 拦记录前缀（第 156 行）与 `vol.role` 越界（第 167 行）；`A08` 拦 `id.url_kind` 越界（第 158 行）与同一声称对象的 `url_kind` 冲突（第 162 行）；`H11` 拦 `mnt.verify_order` 越界（第 270 行）。

**自由文本字段的边界要说清**：`vol.claim`、`mnt.claim`、`umn.relock_basis`、`key.claim`、`cap.claim`、`mgmt.notice`、`adv.claim`、`doc.note` 八格是自然语言断言，脚本按关键词做语义矛盾检查（例如 `D03`、`D06`、`D09`、`E01`、`K06`），但**不做全文事实核验**。它们能通过 `dirty()` 的形态拒收，不等于断言为真；台账里的每一句仍然要在 `doc.line_ref` 指到的归档行上复核。

### 21.4 七族 62 个信号码一览

| 族 | 码数 | 管什么（判据行号在本支脚本内） | 是否阻断 |
| --- | --- | --- | --- |
| A | 8 | 行式与记录标识：列数不是三（`A01`，122 行）、标识为空（`A02`，124 行）、命名空间未登记（`A03`，126 行）、字段在清单外（`A04`，127 行）、空值或拒收取值（`A05`，128—129 行）、同记录同字段重复登记（`A06`，131 行）、缺 `id.url_kind`（`A07`，145 行）、`url_kind` 越界或身份冲突（`A08`，158 与 162 行） | `A01—A08` 全阻断 |
| C | 8 | 容器与卷结构：缺 `vol.*` 必备格（`C01`，150 行）、前缀或角色越界（`C02`，156 与 167 行）、系统卷 `seal=no`（`C03`，169 行）、cryptex 未指向 preboot（`C04`，171 行）、cryptex 无对应 preboot 卷（`C05`，279 行）、快照容量的卷角色不对（`C06`，181 行）、同一卷两条记录 role 冲突且无说明（`C07`，176 行）、「至少两个卷」断言缺 page 级出处（`C08`，185 行） | 仅 `C01` 阻断 |
| D | 12 | 形态与推导：`fs_form` 越界（`D01`，194 行）、`supports=1` 写成 `mount.state=1`（`D02`，195 行）、抹机／Effaceable 写成保密性（`D03`，198 行）、`type_name` 与 `fs_form` 冲突（`D04`，201 行）、`subtype` 当形态（`D05`，203 行）、`internal` 推出 UID 绑定（`D06`，204 行）、relock 写成策略项（`D07`，208 行）、NTFS 计入安全归属（`D08`，209 行）、管理面词形假命中用于形态结论（`D09`，211 行）、加密变体写成独立形态（`D10`，212 行）、无形态读数却断言形态（`D11`，213 行）、形态读数缺行号（`D12`，214 行） | 全非阻断，其中六码落 J3 |
| E | 8 | 容量与计数：容量求和语义（`E01`，217 行）、稀疏卷未登记 size≠usage（`E02`，219 行）、`cap.kind` 越界或缺失（`E03`，148 与 220 行）、`supports=0` 与容量并存且无说明（`E04`，221 行）、跨卷容量相加（`E05`，222 行）、快照容量计入卷容量（`E06`，223 行）、设备级容量用于卷级结论（`E07`，224 行）、共享空闲空间写成各卷之和（`E08`，225 行） | 非阻断，`E01`／`E03`／`E05` 落 J3 |
| H | 12 | 挂载与卸载：`mnt`／`umn` 必备格缺失或 `umn.state` 越界（`H01`，151 与 258 行）、未知挂载选项（`H02`，252 行）、挂载主体写成已知进程（`H03`，255 行）、网络卷未登记 remount 范围（`H04`，256 行）、卸载记录缺异议进程（`H05`，260 行）、`hidden=yes` 却无 `hidden_by`（`H06`，262 行）、枚举跳过隐藏卷却声明该卷隐藏（`H07`，264 行）、写 `completed` 却无完成依据（`H08`，265 行）、卸载后状态写 `key_destroyed`（`H09`，266 行）、外接卷断开写成弹出并重锁（`H10`，268 行）、`verify_order` 越界（`H11`，270 行）、同一卷重复挂载记录且无说明（`H12`，274 行） | 非阻断，`H02`／`H03`／`H08`／`H09` 落 J3 |
| K | 8 | 密钥栈：`key.scope` 越界或缺失（`K01`，149 与 228 行）、class 键与 per-file／extent 混用（`K02`，229 行）、keybag 未写保护类（`K03`，230 行）、托管／云备份 keybag 当一二级证据（`K04`，232 行）、恢复类读数缺硬件世代与可用性说明（`K05`，234 行）、IRK 写成解锁手段（`K06`，235 行）、per-file 与 per-extent 混用（`K07`，237 行）、跨 SoC 世代结论未分叉（`K08`，238 行） | `K01`／`K04`／`K06` 阻断，`K03`／`K07`／`K08` 落 J3 |
| Q | 6 | 来源与证据：`evidence_level` 越界或缺失（`Q01`，147 与 241 行）、`source_kind` 越界或缺失（`Q02`，146 与 242 行）、PAGE-URL 与 PAGE-TITLE 混级（`Q03`，243 行）、行号引用形态非法或缺失（`Q04`，245 行）、三级证据当接口定义（`Q05`，246 行）、本地计数写成公告组件结论或公告记录缺组件名（`Q06`，152 与 247 行） | `Q01`／`Q02`／`Q04` 阻断 |

8＋8＋12＋8＋12＋8＋6 = 62，与第 23.2 节的 C1（`emit` 去重 62）一致。**判定位 J1—J4 不计入信号码**，所以脚本一侧是 62 个信号码加 4 个判定位共 66 个码。

**关于 H 族改名**：这支脚本的挂载／卸载族原用 `M` 前缀，后改为 `H`。原因是本系列第 24 章有十二个以 `M01—M12` 编号的误区，若脚本族名也用 M，读者会把「脚本一 M04」误读成「第 24 章误区 M04」。改名后代码与正文统一为 `H01—H12`，第 24 章的 `M01—M12` 只指误区，不再有第二种含义。同理，脚本二的加密族用 `X`、回查族用 `Z`，避开误区编号与「形态件 V」「挂载件 W」的族名冲突。

### 21.5 四级判定与退出码

逐条信号写 **stderr**（第 61 行），形如 `码<TAB>记录<TAB>说明`；四档判定写 **stdout**（第 287—293 行），末尾固定四行汇总（第 301—304 行：`卷台账记录数= 信号行数= 判定行数=`、`不同信号码= 阻断信号条数=`、`判定分布 J1= J2= J3= J4=`、`前缀记录数 V_= D_= M_= N_=`），随后是按码排序的计数表（第 294—305 行，同样写 stderr）。`-q` 只关掉 stdout 上那几行逐记录判定（第 287—293 行的 `if (!QUIET)`；开关在第 42 行），信号、汇总与计数表一行不少。

判定分派在 `emit()` 里一次完成（第 59—66 行）：命中 `^(A0[1-8]|Q0[124]|K0[146]|C01)$` 记阻断并锁 J4；命中 `^(C0[357]|D0[124679]|D1[12]|E0[135]|H0[2389]|K0[378])$` 记错误并锁 J3；其余锁 J2；无信号为 J1。退出码三条路：`exit ((J3 + J4 + blkcount) > 0 ? 1 : 0)`（第 306 行）；输入缺失或不可读给 2（第 50—53 行）；`-h`／`--help` 给 0（第 43 行）。19 次实跑里 `S1-08`（只有 H01）、`S1-13`（只有 E04）、`S1-15`（只有 K05）三次都是 J2=1 而退出码 0；`S1-19` 格式破坏台账则 J1—J4 全 0 但退出码 1——因为 `blkcount` 被单独计入退出表达式，**格式破坏不会因为「没有记录」而冒充成功**。

### 21.6 只读与拒收纪律

**唯一写出目标**是 `mktemp -d` 建的临时目录，前缀 `vol20.`（第 55 行），第 56 行在 EXIT／INT／TERM 三个信号上 `rm -rf`；`TMPD` 只出现在赋值与 trap 两处，实现不向其写入任何字节。awk 程序体内没有 `system()`、没有 `getline < 文件`、没有 `popen()`。**本支脚本不调用 `diskutil`／`hdiutil`／`mount`／`umount`／`fdesetup`／`security`／`defaults`／`log`／`sysctl`／`plutil`／`apfs.util`／`fsck`／`xcrun` 中的任何一个**：第 23.1 节 P4 把这十三个词形在两支脚本里的每一次出现都列了出来——脚本一是第 2 行与第 18 行的脚本名、第 10—11 行两行拒收声明、第 195 行字段名 `mount.state`，脚本二是第 14—15 行两行拒收声明与第 113 行字段名 `psg_mount`；P4b 用「行首或 `|` `;` `&` `(` 之后、后跟空白」的命令位置规则扫全文，命中 **0**。也就是说：词形出现过七处，命令位置一处也没有。P5 的整词普查给出七个名字——`awk` 2、`bash` 2、`cat` 3、`mktemp` 4、`rm` 2、`sh` 4、`tr` 1；`perl`／`python`／`node`／`curl`／`wget`／`nc`／`ssh`／`scp` 一行都不出现。不联网、不读设备状态、不打开任何被登记的卷、不修改输入文件。

拒收执行点两条：`A05`（第 128—129 行，空值与 `dirty()`）与 `A01`（第 122 行，列数不是三）。真实设备绝对路径、凭据串、超长载荷、整段文件正文一律进不了台账；本篇全部夹具为合成标识与合成取值。

**这支脚本在设计上不可用于以下目的**：挂载或卸载任何卷、格式化任何介质、开关 FileVault、构造任何绕过保护或降权的路径、从任何真实设备提取卷标识或密钥材料。它只读一份人工台账，输出的是「这行登记自洽不自洽」。

### 21.7 全量源码

```bash
#!/usr/bin/env bash
# volume-mount-ledger-review.sh —— 卷挂载台账逐字段审查器（离线 / 只读 / 不联网 / 不碰设备）
# 输入：一份或多份台账文本，每行三列：  <卷或域记录标识>,<字段名>,<值>
# 输出：逐条信号码（stderr） + 每条记录的四档判定（stdout） + 汇总
# 本脚本只判定「一个卷被登记成一行台账之后，这行台账自己站不站得住」：
# 不含任何挂载、卸载、格式化、加密或抹除的操作步骤，不含任何绕过保护或降权的手法，
# 不含对任何具体设备、卷或密钥材料的采集与还原。
# 输入只接受标识、字段名与短取值；取值形似设备绝对路径、形似共享密钥或口令的串、超长 Base64 载荷
# 或整段文件正文时一律按 A05 拒收并要求删除该字段（判据见记录循环开头）。
# 本脚本不联网、不调用 diskutil／hdiutil／mount／umount／fdesetup／security／defaults／log／sysctl／
#       plutil／apfs.util／fsck／xcrun 等任何命令行工具、不读取设备状态、不打开任何被登记的卷；
#       唯一写出目标是 mktemp -d 创建的临时目录，退出时删除，本实现不向其写入任何字节。
set -u
LC_ALL=C; export LC_ALL

usage() {
  cat <<'EOF'
用法: volume-mount-ledger-review.sh [-q] 台账文件 [...]
  -q  不输出逐记录判定行；-h/--help 显示本帮助
台账行格式: <记录标识>,<字段名>,<值>    # 开头与空行忽略，行尾 CR 忽略，值里不能含逗号
记录标识前缀（四类）: V_ 本地卷／D_ FileProvider 域／M_ 外接介质／N_ 网络卷
字段命名空间（九个）:
  id.*    记录标识（volume_id / url_kind / source_kind / evidence_level）
  vol.*   容器与形态（role / fs_form / type_name / subtype / supports / seal / internal / single_partition /
          cryptex_on / claim）
  mnt.*   挂载与枚举（state / options / actor / hidden / hidden_by / dissenting_pid / enum_skips_hidden /
          remount_scope / verify_order / claim）
  umn.*   卸载（state / after / relock_basis / option_name）
  cap.*   容量与计数（kind / value / sparse / shared_free / claim）
  key.*   密钥栈（scope / class / keybag_class / escrow / soc_gen / hardware_generation / availability_note /
          irk_limit / claim）
  mgmt.*  管理面（restriction_key / availability / notice）
  adv.*   公告回查（component / impact / kev / cve / claim）
  doc.*   引用（page_url / page_title / line_ref / note）
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

TMPD=$(mktemp -d "${TMPDIR:-/tmp}/vol20.XXXXXX") || exit 2
trap 'rm -rf "$TMPD"' EXIT INT TERM

cat "$@" | tr -d '\r' | awk -v QUIET="$QUIET" '
function emit(code, id, msg) {
  siglines++
  print code "\t" (id == "" ? "-" : id) "\t" msg > "/dev/stderr"
  cnt[code]++
  if (code ~ /^(A0[1-8]|Q0[124]|K0[146]|C01)$/) { blkcount++; if (id != "") blocked[id] = 1; return }
  if (code ~ /^(C0[357]|D0[124679]|D1[12]|E0[135]|H0[2389]|K0[378])$/) { if (id != "") errored[id] = 1; return }
  if (id != "") warned[id] = 1
}
function inlist(v, list,   n, i, a) {
  n = split(list, a, " ")
  for (i = 1; i <= n; i++) if (a[i] == v) return 1
  return 0
}
function typeForm(t) {
  if (t == "APFS") return "apfs"
  if (t == "APFS (Encrypted)") return "apfs-encrypted"
  if (t == "Mac OS Extended" || t == "HFS+") return "hfs+"
  if (t == "ExFAT" || t == "ExFAT (FAT64)") return "exfat"
  if (t == "MS-DOS (FAT)" || t == "MS-DOS (FAT32)") return "fat32"
  if (t == "MS-DOS (FAT16)") return "fat"
  if (t == "NTFS") return "ntfs"
  return ""
}
function dirty(v) {
  if (v ~ /^(\/(private|System|Volumes|Users)\/|\$HOME\/|~\/)/) return 1
  if (v ~ /(glpat-|ghp_|gho_|xox[baprs]-|AKIA[0-9A-Z]+|Bearer |-----BEGIN)/) return 1
  if (length(v) > 160) return 1
  if (v ~ /^[A-Za-z0-9+\/]{80,}={0,2}$/) return 1
  return 0
}
BEGIN {
  FS = ","
  NS = "id vol mnt umn cap key mgmt adv doc"
  KNOWN = "id.volume_id id.url_kind id.source_kind id.evidence_level " \
          "vol.role vol.fs_form vol.type_name vol.subtype vol.supports vol.seal vol.internal " \
          "vol.single_partition vol.cryptex_on vol.claim " \
          "mnt.state mnt.options mnt.actor mnt.hidden mnt.hidden_by mnt.dissenting_pid " \
          "mnt.enum_skips_hidden mnt.remount_scope mnt.verify_order mnt.claim " \
          "umn.state umn.after umn.relock_basis umn.option_name " \
          "cap.kind cap.value cap.sparse cap.shared_free cap.claim " \
          "key.scope key.class key.keybag_class key.escrow key.soc_gen key.hardware_generation " \
          "key.availability_note key.irk_limit key.claim " \
          "mgmt.restriction_key mgmt.availability mgmt.notice " \
          "adv.component adv.impact adv.kev adv.cve adv.claim " \
          "doc.page_url doc.page_title doc.line_ref doc.note"
  REQ = "id.volume_id id.url_kind id.source_kind id.evidence_level vol.role vol.fs_form vol.type_name " \
        "vol.subtype vol.supports vol.seal mnt.state mnt.options mnt.actor mnt.verify_order " \
        "umn.state umn.after cap.kind key.scope key.keybag_class adv.component"
  ROLE = "system system-data preboot recovery vm external network fileprovider unknown"
  FSOK = "apfs apfs-encrypted hfs+ exfat fat32 fat ntfs unknown"
  URLK = "file-url volume-url document-url backing-store none"
  MST  = "0 1 unknown"
  UMNS = "started completed failed not_applicable"
  UK   = "api page platform_support mgmt_local advisory_count local_count"
  EV   = "1 2 3 4"
  CAPK = "volume device snapshot share none"
  KSC  = "volume class file extent metadata none"
  OPT  = "read-only noexec nosuid nodev automounted remountable"
  VORD = "before after unknown"
  idsn = 0; siglines = 0; blkcount = 0; cn = 0
}
{
  if ($0 == "" || substr($0, 1, 1) == "#") next
  if (NF != 3) { emit("A01", "", "line " NR ": 列数不是三"); next }
  id = $1; f = $2; v = $3
  if (id == "") { emit("A02", "", "line " NR ": 记录标识为空"); next }
  split(f, p, ".")
  if (!inlist(p[1], NS)) { emit("A03", id, "未登记的命名空间: " p[1]); next }
  if (!inlist(f, KNOWN)) { emit("A04", id, "清单外字段: " f); next }
  if (v == "") { emit("A05", id, "取值为空: " f); next }
  if (dirty(v)) { emit("A05", id, "取值形似设备路径／凭据／超长载荷，拒收: " f); next }
  k = id SUBSEP f
  if (k in seen) { emit("A06", id, "同一记录同一字段重复登记: " f); next }
  seen[k] = 1
  if (!(id in firstseen)) { firstseen[id] = NR; idorder[++idsn] = id }
  val[k] = v
}
END {
  blockedn = 0
  for (n = 1; n <= idsn; n++) {
    id = idorder[n]
    # 必备格
    nf = split(REQ, rq, " ")
    for (i = 1; i <= nf; i++) {
      f = rq[i]
      if ((id SUBSEP f) in val) continue
      if (f == "id.url_kind") emit("A07", id, "缺 id.url_kind")
      else if (f == "id.source_kind") emit("Q02", id, "缺 id.source_kind")
      else if (f == "id.evidence_level") emit("Q01", id, "缺 id.evidence_level")
      else if (f == "cap.kind") emit("E03", id, "缺 cap.kind")
      else if (f == "key.scope" || f == "key.keybag_class") emit("K01", id, "缺 " f)
      else if (f ~ /^vol\./) emit("C01", id, "缺 " f)
      else if (f ~ /^(mnt|umn)\./) emit("H01", id, "缺 " f)
      else if (f == "adv.component") emit("Q06", id, "缺 adv.component（公告类记录必备）")
    }
    # A 行式与身份
    pf = substr(id, 1, 2)
    if (!inlist(pf, "V_ D_ M_ N_")) emit("C02", id, "记录前缀不在四类内: " pf)
    uk = val[id SUBSEP "id.url_kind"]
    if (uk != "" && !inlist(uk, URLK)) emit("A08", id, "url_kind 越界: " uk)
    vid = val[id SUBSEP "id.volume_id"]
    if (vid != "") {
      if (vid in vidurl && vidurl[vid] != uk && uk != "") {
        emit("A08", id, "同一声称对象的 url_kind 不同（" vidurl[vid] " vs " uk "），身份不可比对")
      } else if (!(vid in vidurl)) vidurl[vid] = uk
    }
    # C 容器与卷结构
    role = val[id SUBSEP "vol.role"]
    if (role != "" && !inlist(role, ROLE)) emit("C02", id, "vol.role 越界: " role)
    seal = val[id SUBSEP "vol.seal"]
    if (role == "system" && seal == "no") emit("C03", id, "系统卷 seal=no，与 SSV 口径矛盾")
    cy = val[id SUBSEP "vol.cryptex_on"]
    if (cy != "" && cy != "preboot") emit("C04", id, "cryptex 记录未指向 preboot 卷: " cy)
    if (role == "preboot") haspreboot = 1
    if (cy != "") cryptexids[++cnx] = id
    if (vid != "" && role != "") {
      if ((vid in vidrole) && vidrole[vid] != role && val[id SUBSEP "doc.note"] == "")
        emit("C07", id, "同一卷两条记录的 role 冲突（" vidrole[vid] " vs " role "）且无说明")
      else if (!(vid in vidrole)) vidrole[vid] = role
    }
    ck = val[id SUBSEP "cap.kind"]
    if (ck == "snapshot" && role != "" && role != "system" && role != "system-data")
      emit("C06", id, "快照容量记录的卷角色为 " role)
    keyv = id SUBSEP "vol.claim"
    if (keyv in val && val[keyv] ~ /(至少两个卷|at least two volumes)/) {
      sk = val[id SUBSEP "id.source_kind"]
      if (sk != "page") emit("C08", id, "「至少两个卷」断言缺 page 级出处")
    }
    # D 形态与推导
    fs = val[id SUBSEP "vol.fs_form"]
    tn = val[id SUBSEP "vol.type_name"]
    st = val[id SUBSEP "vol.subtype"]
    sup = val[id SUBSEP "vol.supports"]
    mstate = val[id SUBSEP "mnt.state"]
    opts = val[id SUBSEP "mnt.options"]
    if (fs != "" && !inlist(fs, FSOK)) emit("D01", id, "fs_form 越界: " fs)
    if (sup == "1" && mstate == "1" && opts == "") emit("D02", id, "supports=1 被写成 mount.state=1（无独立挂载读数）")
    vc = val[id SUBSEP "vol.claim"]; kc = val[id SUBSEP "key.claim"]
    if (vc ~ /(抹机|Effaceable|effaceable)/ && kc ~ /(保密性|confidentiality)/)
      emit("D03", id, "抹机/Effaceable 被写成保密性结论")
    if (tn != "" && fs != "" && fs != "unknown") {
      tf = typeForm(tn)
      if (tf != "" && tf != fs) emit("D04", id, "type_name 与 fs_form 冲突: " tn " vs " fs)
    }
    if (st != "" && tn == "") emit("D05", id, "subtype 被当作 fs_form（type_name 缺失）")
    if (val[id SUBSEP "vol.internal"] == "yes" && kc ~ /UID/) emit("D06", id, "internal 被推出 UID 绑定保护")
    mc = val[id SUBSEP "mnt.claim"]; uc = val[id SUBSEP "umn.relock_basis"]
    sk = val[id SUBSEP "id.source_kind"]
    if ((mc ~ /relock/ || uc ~ /relock/) && sk != "api" && sk != "page")
      emit("D07", id, "relock 被写成策略项（source_kind=" sk "）")
    if (fs == "ntfs" && sk != "" && sk != "page") emit("D08", id, "Windows 兼容形态被计入安全归属")
    rk = val[id SUBSEP "mgmt.restriction_key"]
    if (tolower(rk) ~ /(disk|storage|volume)/ && vc ~ /(形态|format)/) emit("D09", id, "管理面词形假命中被用于形态结论")
    if (fs == "apfs-encrypted" && vc ~ /独立文件系统/) emit("D10", id, "加密变体被写成独立形态")
    if ((fs == "" || fs == "unknown") && vc ~ /(APFS|HFS|ExFAT|FAT32)/) emit("D11", id, "无形态读数却断言形态")
    if (fs != "" && fs != "unknown" && val[id SUBSEP "doc.line_ref"] == "") emit("D12", id, "形态读数缺行号")
    # E 容量与计数
    cc = val[id SUBSEP "cap.claim"]; cv = val[id SUBSEP "cap.value"]
    if (cc ~ /(sum|total_across_volumes|求和)/) emit("E01", id, "容量求和语义")
    if (val[id SUBSEP "cap.sparse"] == "yes" && cc !~ /(size.*usage|占用.*大小|大小.*占用)/)
      emit("E02", id, "稀疏卷未登记 size≠usage")
    if (ck != "" && !inlist(ck, CAPK)) emit("E03", id, "cap.kind 越界: " ck)
    if (sup ~ /sizes=0/ && cv != "" && val[id SUBSEP "doc.note"] == "") emit("E04", id, "supports=0 与容量并存且无说明")
    if (cc ~ /(各卷相加|卷与卷相加)/) emit("E05", id, "跨卷容量相加")
    if (ck == "volume" && cc ~ /snapshot/) emit("E06", id, "快照容量被计入卷容量")
    if (ck == "device" && cc ~ /(该卷|this volume)/) emit("E07", id, "设备级容量用于卷级结论")
    if (val[id SUBSEP "cap.shared_free"] == "yes" && cc ~ /(总和|total)/) emit("E08", id, "共享空闲空间被写成各卷之和")
    # K 密钥栈
    ks = val[id SUBSEP "key.scope"]
    if (ks != "" && !inlist(ks, KSC)) emit("K01", id, "key.scope 越界: " ks)
    if (ks == "class" && kc ~ /per-(file|extent)/) emit("K02", id, "class 键与 per-file/extent 键混用")
    if (val[id SUBSEP "key.keybag_class"] != "" && kc != "" && kc !~ /(类|class)/) emit("K03", id, "keybag 未写所在保护类")
    if (kc ~ /(escrow|iCloud Backup)/ && val[id SUBSEP "id.evidence_level"] ~ /^[12]$/)
      emit("K04", id, "托管/云备份 keybag 结构被当作一二级证据")
    if (val[id SUBSEP "key.soc_gen"] != "" && (val[id SUBSEP "key.hardware_generation"] == "" || val[id SUBSEP "key.availability_note"] == ""))
      emit("K05", id, "恢复类读数缺 hardware_generation/availability_note")
    if (kc ~ /IRK/ && kc ~ /(解锁|unlock)/) emit("K06", id, "IRK 被写成解锁手段")
    if ((ks == "file" || ks == "extent") && kc ~ /per-(file|extent)/ && kc ~ /(两者|both)/)
      emit("K07", id, "per-file 与 per-extent 键混用")
    if (val[id SUBSEP "key.soc_gen"] == "" && kc ~ /(pre-A9|A9\+|世代)/) emit("K08", id, "跨 SoC 世代的密钥栈结论未分叉")
    # Q 来源与证据
    el = val[id SUBSEP "id.evidence_level"]
    if (el != "" && !inlist(el, EV)) emit("Q01", id, "evidence_level 越界: " el)
    if (sk != "" && !inlist(sk, UK)) emit("Q02", id, "source_kind 越界: " sk)
    if ((sk == "api" && val[id SUBSEP "doc.page_url"] != "") || (sk == "mgmt_local" && val[id SUBSEP "doc.page_title"] != "" && val[id SUBSEP "doc.page_url"] == "")) emit("Q03", id, "PAGE-URL 与 PAGE-TITLE 混级")
    lr = val[id SUBSEP "doc.line_ref"]
    if (lr != "" && lr !~ /^[0-9]+(-[0-9]+)?$/) emit("Q04", id, "行号引用形态非法: " lr)
    if (el == "3" && vc ~ /(接口定义|interface defines)/) emit("Q05", id, "三级证据被当作接口定义")
    if (sk == "local_count" && val[id SUBSEP "adv.claim"] ~ /公告组件/) emit("Q06", id, "本地计数被写成公告组件结论")
    # H 挂载与卸载
    opts = val[id SUBSEP "mnt.options"]
    if (opts != "") {
      no = split(opts, oa, "+")
      for (i = 1; i <= no; i++) if (!inlist(oa[i], OPT)) emit("H02", id, "未知挂载选项: " oa[i])
    }
    ac = val[id SUBSEP "mnt.actor"]
    if (ac != "" && ac != "unknown") emit("H03", id, "挂载主体写成已知进程: " ac)
    if (role == "network" && val[id SUBSEP "mnt.remount_scope"] == "") emit("H04", id, "网络卷未登记 remount 范围")
    us = val[id SUBSEP "umn.state"]
    if (us != "" && !inlist(us, UMNS)) emit("H01", id, "umn.state 越界: " us)
    if (us != "" && us != "not_applicable" && val[id SUBSEP "mnt.dissenting_pid"] == "")
      emit("H05", id, "卸载记录缺异议进程字段")
    if (val[id SUBSEP "mnt.hidden"] == "yes" && val[id SUBSEP "mnt.hidden_by"] == "")
      emit("H06", id, "写了 hidden 但没写 hidden_by")
    if (val[id SUBSEP "mnt.enum_skips_hidden"] == "yes" && val[id SUBSEP "mnt.hidden"] == "yes")
      emit("H07", id, "枚举跳过隐藏卷却同时声明该卷隐藏")
    if (us == "completed" && val[id SUBSEP "umn.option_name"] == "") emit("H08", id, "unmount 未完成即写 completed")
    if (val[id SUBSEP "umn.after"] == "key_destroyed") emit("H09", id, "卸载后状态写成 key_destroyed")
    if (role == "external" && us == "completed" && val[id SUBSEP "umn.after"] == "relocked")
      emit("H10", id, "外接卷断开被写成弹出并重锁")
    vo = val[id SUBSEP "mnt.verify_order"]
    if (vo != "" && !inlist(vo, VORD)) emit("H11", id, "verify_order 越界: " vo)
    mt = id SUBSEP "mnt.state"
    if (mt in val) {
      if (vid != "" && (vid in vidmnt) && val[mt] == vidmnt[vid] && val[id SUBSEP "doc.note"] == "")
        emit("H12", id, "同一卷重复挂载记录且无说明")
      if (vid != "" && !(vid in vidmnt)) vidmnt[vid] = val[mt]
    }
    # 判定在全部信号落定后统一给出，见下
  }
  for (i = 1; i <= cnx; i++) if (!haspreboot) emit("C05", cryptexids[i], "cryptex 记录无对应 preboot 卷")
  for (i = 1; i <= idsn; i++) {
    pfx = substr(idorder[i], 1, 2)
    if (pfx == "V_") pv++
    else if (pfx == "D_") pd++
    else if (pfx == "M_") pm++
    else if (pfx == "N_") pn++
  }
  for (i = 1; i <= idsn; i++) {
    id = idorder[i]
    if (id in blocked) { J4++; if (!QUIET) print "J4\t" id }
    else if (id in errored) { J3++; if (!QUIET) print "J3\t" id }
    else if (id in warned) { J2++; if (!QUIET) print "J2\t" id }
    else { J1++; if (!QUIET) print "J1\t" id }
  }
  for (c in cnt) codelist[++cn] = c
  # 计数表按码排序
  for (i = 2; i <= cn; i++) {
    x = codelist[i]; j = i - 1
    while (j >= 1 && codelist[j] > x) { codelist[j+1] = codelist[j]; j-- }
    codelist[j+1] = x
  }
  print "卷台账记录数= " idsn " 信号行数= " siglines " 判定行数= " idsn
  print "不同信号码= " cn " 阻断信号条数= " blkcount
  print "判定分布 J1= " J1+0 " J2= " J2+0 " J3= " J3+0 " J4= " J4+0
  printf "前缀记录数 V_= %d D_= %d M_= %d N_= %d\n", pv, pd, pm, pn
  for (i = 1; i <= cn; i++) print codelist[i] "\t" cnt[codelist[i]] > "/dev/stderr"
  exit ((J3 + J4 + blkcount) > 0 ? 1 : 0)
}
'
```

---

## 22. 只读核验脚本二：形态／挂载／加密三件差集与公告子词表比对器

这支脚本回答另一个问题：**三份读数表之间，哪些格子对不上、哪些换算根本没发生**。它不审台账，只审读数；输入只有计数与词形，不接受任何文件正文、设备路径或身份描述。

### 22.1 输入与边界

输入恰好三份 TSV（usage 第 24—27 行）：

| 文件 | 列 | 取值域 |
| --- | --- | --- |
| `keys.tsv` | `<词形>,<组>,<计数>` | 组：`volume`／`supports`／`is`／`semantic` |
| `statements.tsv` | `<主题>,<计数>,<来源>` | 来源：`psg`／`guide`／`fileprovider` |
| `readings.tsv` | `<度量>,<计数>` | 度量名见 22.2 |

参数校验：恰好三个（第 52 行）、每份可读（第 53—55 行），不满足退出码 2。三份按 `FILENAME` 分流（第 92—103 行），**不是按扩展名或列数猜的**。`keys.tsv` 的组取值越界计入 `badgroup`、`statements.tsv` 的来源越界计入 `badsource`，两者只提示不参与判定；格式不符或 `dirty()` 命中的行计入 `badline` 并跳过（第 93、97、101 行），`dirty()` 与脚本一同为四条判据（第 68—75 行）。边界句在头部第 9—16 行：不含挂载、卸载、格式化、加密、抹除的操作步骤，不含绕过保护或降权的手法，不含对任何具体设备、卷或密钥材料的采集与还原。

### 22.2 44 个度量与 17 个派生

`REQUIRED` 在第 78—87 行写死，恰好 **44 个度量**，分十组：

| 组 | 个数 | 度量 |
| --- | --- | --- |
| 接口侧 | 6 | `form_keys` `volume_keys` `supports_keys` `is_keys` `mount_semantic` `encrypted_is` |
| 平台安全口径 | 7 | `psg_volume` `psg_mount` `psg_encryption` `psg_keybag` `psg_cryptex` `psg_seal` `psg_removable` |
| 用户指南 | 3 | `guide_whitelist` `guide_eject` `guide_single_partition` |
| FileProvider | 2 | `fp_ext_volume_handling` `fp_ext_volume_members` |
| 公告结构 | 4 | `comp_form_rows` `impact_form_rows` `comp_only` `impact_only` |
| 恶意构造子集 | 5 | `crafted_rows` `crafted_comp_hits` `crafted_collisions` `impact_form_macos` `impact_form_ios` |
| KEV 与管理面 | 5 | `kev_total` `kev_form_hits` `mdm_keys` `mdm_form_hits` `mdm_mount_keys` |
| 声明类型 | 2 | `decl_total` `decl_disk` |
| 容量与世代 | 5 | `cap_device` `cap_volume` `soc_gen_split` `mgmt_hw_enc_caps` `volume_encrypted_classes` |
| 其余误读读数 | 5 | `keybag_named_only` `effaceable_confusion` `irk_no_value` `impact_top_is_form` `unmount_options` |

**读数文件优先，清单可派生**（第 106—123 行）。`readings.tsv` 里给了的度量直接采用；没给的按两条路补：5 个从 `keys.tsv` 的组计数派生（`form_keys`／`volume_keys` 取 `volume` 组、`supports_keys` 取 `supports` 组、`is_keys` 取 `is` 组、`mount_semantic` 取 `semantic` 组），12 个从 `statements.tsv` 的主题计数派生（7 个 `psg_*`、3 个 `guide_*`、2 个 `fp_*`）。合计 17 个可派生，剩余 27 个必须出现在 `readings.tsv` 里，缺一个就 `缺度量` 并以退出码 2 结束（第 124—127 行）——**缺度量是输入问题，不是信号，所以不给判定等级**。夹具 `S2-01`（读数齐全）与 `S2-02`（读数缺派生项、键语句补齐）都是 0 码 Q1，`S2-12`（只缺不可派生项）退出码 2，三者正好把这条优先级钉住。

组计数用 `gc[g] += num($3)`（第 95 行）而不是逐行计数，因此 `keys.tsv` 里可以写族汇总行（`volume,volume,47`、`supports,supports,20`、`is,is,10`、`semantic,semantic,4`），派生结果与接口页的 47／20／10／4 一致；`partition,partition,1` 这类族外行用于 `V08`／`Z11` 的「有没有分区计数键」判定。

### 22.3 八处换算失败 F01—F08

| 码 | 判据（第 132—149 行） | 本期语料上的含义 |
| --- | --- | --- |
| `F01` | `comp_form_rows=0` 且 `form_keys>0` | 接口有形态词形，公告组件列零命中 |
| `F02` | `impact_form_rows=0` 且 `form_keys>0` | 接口有形态词形，公告影响句零命中 |
| `F03` | `mount_semantic=0` 且 `psg_mount>0` | 平台侧有挂载语句，接口侧无挂载语义键 |
| `F04` | `guide_whitelist>0` 且 ≠ `supports_keys` | 用户指南白名单项数与 supports 键数对不上 |
| `F05` | `psg_volume>0` 且 `volume_keys=0` | 平台侧有卷语句，接口词表无 volume 前缀键 |
| `F06` | `mgmt_hw_enc_caps>0` 且 `encrypted_is=0` | 管理面有设备级加密整数，接口无卷级加密键 |
| `F07` | `cap_device>0` 且 `cap_volume=0` | 有设备级容量读数而无卷级容量读数 |
| `F08` | `psg_keybag>0` 且 `soc_gen_split=0` | 平台侧有 keybag 语句，读数未按 SoC 世代分叉 |

这八条不是八个独立缺陷，而是**三套词表之间八条不存在的换算关系**：接口词表说「这个键存在」，平台文档说「这个机制存在」，公告说「这个组件出过问题」，三者之间没有一张公开对照表。F01 与 F02 是形态词形的两条（组件列与影响列），F03 与 F05 是挂载与卷的两条，F04 是白名单与能力键的一条，F06 与 F07 是管理面与容量各一条，F08 是密钥栈的一条。

### 22.4 五族 48 个信号码一览

| 族 | 码数 | 管什么（判据行号在本支脚本内） | 阻断码 |
| --- | --- | --- | --- |
| F | 8 | 八处换算失败（第 132—149 行） | `F05` `F07` `F08` |
| V | 8 | 形态件：无 volume 前缀键（`V01`）、平台侧无卷语句（`V02`）、组件列无形态词形（`V03`）、影响列无形态词形（`V04`）、管理面形态零命中（`V05`）、盘类声明不超过一项（`V06`）、白名单少于能力键（`V07`）、单一分区要求无接口读回（`V08`）（第 150—161 行） | 无 |
| W | 8 | 挂载件：无挂载语义键（`W01`）、平台侧无挂载语句（`W02`）、影响列无挂载词形（`W03`）、KEV 挂载词形零命中（`W04`）、管理面无挂载类键名（`W05`）、指南无 eject 词形（`W06`）、可移动介质语句无挂载语义键（`W07`）、卸载相关公开标识符少于 5（`W08`）（第 162—171 行） | 无 |
| X | 12 | 加密件：平台侧无加密语句（`X01`）、无 keybag 语句（`X02`）、无卷级加密键（`X03`）、卷级与文件类换算缺失（`X04`）、只有设备级容量（`X05`）、管理面无加密能力读数（`X06`）、有加密语句而换算未登记（`X07`）、volume 前缀键里无加密读数（`X08`）、密钥栈未按 SoC 世代分叉（`X09`）、keybag 名称可读结构不可读（`X10`）、抹除语义与保密性混同（`X11`）、IRK 无功能价值一句未登记（`X12`）（第 172—188 行） | `X02` `X03` `X06` `X09` |
| Z | 12 | 回查：组件列有行而影响列 0 行（`Z01`）、双向错位（`Z02`）、恶意构造子集形态命中（`Z03`）、词形撞车（`Z04`）、影响列偏向 macOS（`Z05`）、影响列命中最多的组件不含形态词（`Z06`）、KEV 零命中（`Z07`）、管理面零命中（`Z08`）、盘类声明不超过一项（`Z09`）、白名单少于能力键（`Z10`）、单一分区要求无读回（`Z11`）、FileProvider 外接卷实体存在而成员面不可读（`Z12`）（第 189—209 行） | `Z01` `Z07` `Z08` |

8＋8＋8＋12＋12 = 48。**同一个事实会在不同族里被登记两次或三次**，这是三件模型的刻意设计，不是重复计数：`V05` 与 `Z08` 都判「管理面形态零命中」，前者从形态件看，后者从回查看；`V06` 与 `Z09` 都判「盘类声明不超过一项」；`V07` 与 `Z10` 都判「白名单少于能力键」；`W04` 与 `Z07` 都判「KEV 零命中」；`V08` 与 `Z11` 都判「单一分区要求无读回」。读信号时按「事实」去重，按「面」计分。

### 22.5 三件闭合等级与退出码

三件的面定义在第 211—213 行，每件四面：

- **形态件** `f_form`：`volume_keys>0` ＋ `psg_volume>0` ＋ 组件列或影响列有形态词形 ＋ `decl_disk>0`。
- **挂载件** `f_mount`：`mount_semantic>0` ＋ `psg_mount>0` ＋ `impact_form_rows>0` ＋ `mdm_mount_keys>0`。
- **加密件** `f_enc`：`encrypted_is>0` ＋ `psg_encryption>0` ＋ `volume_encrypted_classes>0` ＋ `mgmt_hw_enc_caps>0`。

面数 4／3／2 记 Q1／Q2／Q3，其他记 Q4（面数为 0 或 1 时按第 215—217 行的三目表达式落到 Q3／Q4；`f>=3` 是 Q1，`f==2` 是 Q2，`f==1` 是 Q3，其余 Q4）。总判定取三件里最差的一件（第 220—223 行），任一件 Q4 则总判定 Q4。

汇总三行写 stdout（第 230—232 行）：`三件合计面数= 信号行数=`、`不同信号码= 阻断信号条数=`、`闭合等级 形态= 挂载= 加密= 总判定=`，随后是按码排序的计数表（第 233 行，写 stderr）。`-q` 只关掉三件明细（第 214 行），汇总与计数表不变。退出码只有三条路：`exit (siglines > 0 ? 1 : 0)`（第 234 行）；输入缺失或不可读给 2（第 52—55 行）；`-h`／`--help` 给 0（第 45 行）。

**Q1 不等于「没有信号」**：退出码只看 `siglines`，等级只看面数。夹具 `S2-08`（键清单组名越界）有 6 个信号、退出码 1，但三件面数仍齐、总判定 Q1；`S2-09`（语句清单全零）有 11 个信号、总判定仍是 Q1。反过来，`S2-11`（双清单皆空）12 个信号、总判定 Q2。这两个维度必须分开报：**「这一件有没有读数」与「读数之间对不对得上」是两个问题**。

### 22.6 只读与拒收纪律

**唯一写出目标**是 `mktemp -d` 建的临时目录，前缀 `vft20.`（第 57 行），第 58 行在 EXIT／INT／TERM 三个信号上 `rm -rf`；实现不向其写入任何字节。awk 程序体内没有 `system()`、没有 `getline < 文件`、没有 `popen()`。本支脚本不调用任何磁盘、加密、日志或设备命令行工具（头部第 14—15 行），不联网、不读设备状态、不打开任何卷、不修改输入文件。

拒收执行点在三个分流分支的行首（第 93、97、101 行）：任一词形或主题形似设备路径、凭据串、超长载荷时该行直接计入 `badline`，不进入任何判定。**输入只接受计数与词形**，所以本支脚本天然不接触卷内容、密钥材料或设备标识。

**这支脚本在设计上不可用于以下目的**：挂载或卸载卷、格式化介质、开关加密、构造绕过路径、从真实设备采集任何读数。它只做三份人工读数表之间的差集。

### 22.7 全量源码

```bash
#!/usr/bin/env bash
# volume-form-tripartite-diff.sh —— 形态／挂载／加密三件差集与公告子词表比对器
#                                  （离线 / 只读 / 不联网 / 不碰设备）
# 输入：三份读数表——
#   keys.tsv       <词形>,<组>,<计数>        接口词表侧（volume 前缀／supports／is／semantic）
#   statements.tsv <主题>,<计数>,<来源>      平台安全口径侧（psg／guide／fileprovider）
#   readings.tsv   <度量>,<计数>             公告、KEV、管理面与容量侧
# 输出：逐条信号码（stderr） + 三件闭合等级（stdout） + 汇总
# 本脚本只做「三份读数表之间的差集与换算失败」判定：
# 不含任何挂载、卸载、格式化、加密、抹除的操作步骤，不含任何绕过保护或降权的手法，
# 不含对任何具体设备、卷或密钥材料的采集与还原；输入只接受计数与词形，不接受任何文件正文、
# 设备路径、密钥串或可还原身份的描述。取值里出现形似设备绝对路径、"$HOME"/"/private/var/" 等前缀、
# 形似共享密钥或口令的串、超长 Base64 载荷时该行按格式不符跳过（计入 badline），不进入任何判定。
# 本脚本不联网、不调用 diskutil／hdiutil／mount／umount／fdesetup／security／defaults／log／sysctl／
#       plutil／apfs.util／fsck／xcrun 等任何命令行工具、不读取设备状态、不打开任何被登记的卷；
#       唯一写出目标是 mktemp -d 创建的临时目录，退出时删除，本实现不向其写入任何字节。
set -u
LC_ALL=C; export LC_ALL

usage() {
  cat <<'EOF'
用法: volume-form-tripartite-diff.sh [-q] keys.tsv statements.tsv readings.tsv
  -q  不输出三件明细行；-h/--help 显示本帮助
keys.tsv       <词形>,<组>,<计数>      组取值: volume supports is semantic
statements.tsv <主题>,<计数>,<来源>    来源取值: psg guide fileprovider
readings.tsv   <度量>,<计数>
必填度量（缺一即无法给出闭合等级）:
  form_keys volume_keys supports_keys is_keys mount_semantic encrypted_is
  psg_volume psg_mount psg_encryption psg_keybag psg_cryptex psg_seal psg_removable
  guide_whitelist guide_eject guide_single_partition
  fp_ext_volume_handling fp_ext_volume_members
  comp_form_rows impact_form_rows comp_only impact_only
  crafted_rows crafted_comp_hits crafted_collisions impact_form_macos impact_form_ios
  kev_total kev_form_hits mdm_keys mdm_form_hits mdm_mount_keys decl_total decl_disk
  cap_device cap_volume soc_gen_split mgmt_hw_enc_caps volume_encrypted_classes
  keybag_named_only effaceable_confusion irk_no_value impact_top_is_form unmount_options
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

TMPD=$(mktemp -d "${TMPDIR:-/tmp}/vft20.XXXXXX") || exit 2
trap 'rm -rf "$TMPD"' EXIT INT TERM

awk -v QUIET="$QUIET" '
function emit(code, msg) {
  siglines++
  print code "\t-\t" msg > "/dev/stderr"
  cnt[code]++
  if (code ~ /^(F0[578]|X0[2369]|Z0[178])$/) blkcount++
}
function num(v) { return v + 0 }
function dirty(v) {
  if (v ~ /^(\/(private|System|Volumes|Users)\/|\$HOME\/|~\/)/) return 1
  if (v ~ /(glpat-|ghp_|gho_|xox[baprs]-|AKIA[0-9A-Z]+|Bearer |-----BEGIN)/) return 1
  if (length(v) > 160) return 1
  if (v ~ /^[A-Za-z0-9+\/]{80,}={0,2}$/) return 1
  return 0
}
BEGIN {
  FS = ","
  for (i = 1; i < ARGC; i++) kind[ARGV[i]] = (i == 1 ? "keys" : (i == 2 ? "statements" : "readings"))
  REQUIRED = "form_keys volume_keys supports_keys is_keys mount_semantic encrypted_is " \
             "psg_volume psg_mount psg_encryption psg_keybag psg_cryptex psg_seal psg_removable " \
             "guide_whitelist guide_eject guide_single_partition " \
             "fp_ext_volume_handling fp_ext_volume_members " \
             "comp_form_rows impact_form_rows comp_only impact_only " \
             "crafted_rows crafted_comp_hits crafted_collisions impact_form_macos impact_form_ios " \
             "kev_total kev_form_hits mdm_keys mdm_form_hits mdm_mount_keys decl_total decl_disk " \
             "cap_device cap_volume soc_gen_split mgmt_hw_enc_caps volume_encrypted_classes " \
             "keybag_named_only effaceable_confusion irk_no_value impact_top_is_form unmount_options"
  idsn = 0; siglines = 0; blkcount = 0; cn = 0
}
{
  sub(/\r$/, "")
  if ($0 == "" || substr($0, 1, 1) == "#") next
  if (FILENAME == ARGV[1]) {
    if (NF < 3 || dirty($1) || dirty($2)) { badline++; next }
    g = $2; if (g != "volume" && g != "supports" && g != "is" && g != "semantic") badgroup++
    kc[$1] = num($3); kg[$1] = g; idn++; gc[g] += num($3)
  } else if (FILENAME == ARGV[2]) {
    if (NF < 3 || dirty($1)) { badline++; next }
    s = $3; if (s != "psg" && s != "guide" && s != "fileprovider") badsource++
    sc[$1] = num($2); ss[$1] = s
  } else {
    if (NF < 2 || dirty($1)) { badline++; next }
    rv[$1] = num($2)
  }
}
END {
  # 读数文件优先；缺失时由键清单与语句清单派生，两侧都缺才算缺度量
  if (!("form_keys" in rv)) rv["form_keys"] = num(gc["volume"])
  if (!("volume_keys" in rv)) rv["volume_keys"] = num(gc["volume"])
  if (!("supports_keys" in rv)) rv["supports_keys"] = num(gc["supports"])
  if (!("is_keys" in rv)) rv["is_keys"] = num(gc["is"])
  if (!("mount_semantic" in rv)) rv["mount_semantic"] = num(gc["semantic"])
  if (!("psg_volume" in rv)) rv["psg_volume"] = num(sc["volume"])
  if (!("psg_mount" in rv)) rv["psg_mount"] = num(sc["mount"])
  if (!("psg_encryption" in rv)) rv["psg_encryption"] = num(sc["encryption"])
  if (!("psg_keybag" in rv)) rv["psg_keybag"] = num(sc["keybag"])
  if (!("psg_cryptex" in rv)) rv["psg_cryptex"] = num(sc["cryptex"])
  if (!("psg_seal" in rv)) rv["psg_seal"] = num(sc["seal"])
  if (!("psg_removable" in rv)) rv["psg_removable"] = num(sc["removable"])
  if (!("guide_whitelist" in rv)) rv["guide_whitelist"] = num(sc["whitelist"])
  if (!("guide_eject" in rv)) rv["guide_eject"] = num(sc["eject"])
  if (!("guide_single_partition" in rv)) rv["guide_single_partition"] = num(sc["single_partition"])
  if (!("fp_ext_volume_handling" in rv)) rv["fp_ext_volume_handling"] = num(sc["external_volume_handling"])
  if (!("fp_ext_volume_members" in rv)) rv["fp_ext_volume_members"] = num(sc["external_volume_members"])
  n = split(REQUIRED, rq, " ")
  missing = 0
  for (i = 1; i <= n; i++) if (!(rq[i] in rv)) { print "缺度量: " rq[i] > "/dev/stderr"; missing++ }
  if (missing > 0) exit 2
  if (badline > 0) print "跳过格式不符行: " badline > "/dev/stderr"
  if (badgroup > 0) print "词表组取值越界行: " badgroup > "/dev/stderr"
  if (badsource > 0) print "来源取值越界行: " badsource > "/dev/stderr"

  # ---- F 词形换算失败（八处） ----
  if (rv["comp_form_rows"] == 0 && rv["form_keys"] > 0)
    emit("F01", "接口有形态词形而公告组件列零命中（" rv["form_keys"] " → 0）")
  if (rv["impact_form_rows"] == 0 && rv["form_keys"] > 0)
    emit("F02", "接口有形态词形而公告影响句零命中")
  if (rv["mount_semantic"] == 0 && rv["psg_mount"] > 0)
    emit("F03", "平台侧有挂载语句而接口侧无挂载语义键")
  if (rv["guide_whitelist"] > 0 && rv["guide_whitelist"] != rv["supports_keys"])
    emit("F04", "用户指南白名单项数（" rv["guide_whitelist"] "）≠ supports 键数（" rv["supports_keys"] "）")
  if (rv["psg_volume"] > 0 && rv["volume_keys"] == 0)
    emit("F05", "平台侧有卷语句而接口词表无 volume 前缀键")
  if (rv["mgmt_hw_enc_caps"] > 0 && rv["encrypted_is"] == 0)
    emit("F06", "管理面有设备级加密整数而接口无卷级加密键")
  if (rv["cap_device"] > 0 && rv["cap_volume"] == 0)
    emit("F07", "有设备级容量读数而无卷级容量读数")
  if (rv["psg_keybag"] > 0 && rv["soc_gen_split"] == 0)
    emit("F08", "平台侧有 keybag 语句而读数未按 SoC 世代分叉")

  # ---- V 形态件（八码） ----
  if (rv["volume_keys"] == 0) emit("V01", "接口侧无 volume 前缀键")
  if (rv["psg_volume"] == 0) emit("V02", "平台侧无卷语句")
  if (rv["comp_form_rows"] == 0) emit("V03", "公告组件列无形态词形")
  if (rv["impact_form_rows"] == 0) emit("V04", "公告影响列无形态词形")
  if (rv["mdm_keys"] > 0 && rv["mdm_form_hits"] == 0) emit("V05", "管理面 216 键里形态词形零命中")
  if (rv["decl_total"] > 0 && rv["decl_disk"] <= 1) emit("V06", "声明类型里盘类声明不超过 1 项")
  if (rv["guide_whitelist"] > 0 && rv["supports_keys"] > 0 && rv["guide_whitelist"] < rv["supports_keys"])
    emit("V07", "支持文本白名单项数少于 supports 键数（" rv["guide_whitelist"] " < " rv["supports_keys"] "）")
  if (rv["guide_single_partition"] > 0 && !("single_partition" in kc) && !("partition" in kc))
    emit("V08", "支持文本要求单一分区而接口无分区计数键")

  # ---- W 挂载件（八码） ----
  if (rv["mount_semantic"] == 0) emit("W01", "接口侧无挂载语义键")
  if (rv["psg_mount"] == 0) emit("W02", "平台侧无挂载语句")
  if (rv["impact_form_rows"] == 0 && rv["psg_mount"] > 0) emit("W03", "公告影响列无挂载词形而平台侧有挂载语句")
  if (rv["kev_total"] > 0 && rv["kev_form_hits"] == 0) emit("W04", "KEV 里挂载/卷类词形零命中")
  if (rv["mdm_mount_keys"] == 0) emit("W05", "管理面无挂载类键名")
  if (rv["guide_eject"] == 0 && rv["guide_whitelist"] > 0) emit("W06", "用户指南无 eject 词形")
  if (rv["psg_removable"] > 0 && rv["mount_semantic"] == 0) emit("W07", "可移动介质语句无对应挂载语义键")
  if (rv["unmount_options"] < 5) emit("W08", "卸载相关标识符读数少于 5（" rv["unmount_options"] "）")

  # ---- X 加密件（十二码） ----
  if (rv["psg_encryption"] == 0) emit("X01", "平台侧无加密语句")
  if (rv["psg_keybag"] == 0) emit("X02", "平台侧无 keybag 语句")
  if (rv["encrypted_is"] == 0) emit("X03", "接口侧无卷级加密键")
  if (rv["volume_encrypted_classes"] == 0) emit("X04", "卷级加密与文件类的换算读数缺失")
  if (rv["cap_volume"] == 0 && rv["cap_device"] > 0) emit("X05", "只有设备级容量读数")
  if (rv["mgmt_hw_enc_caps"] == 0) emit("X06", "管理面无加密能力读数")
  if (rv["psg_encryption"] > 0 && rv["volume_encrypted_classes"] == 0)
    emit("X07", "有加密语句而卷级/文件级换算仍未登记")
  if (rv["volume_keys"] > 0 && rv["encrypted_is"] == 0)
    emit("X08", "47 个 volume 前缀键里无加密读数")
  if (rv["soc_gen_split"] == 0) emit("X09", "密钥栈结论未按 SoC 世代分叉")
  if (rv["psg_keybag"] > 0 && rv["keybag_named_only"] > 0)
    emit("X10", "keybag 名称可读而结构不可读（" rv["keybag_named_only"] " 个）")
  if (rv["effaceable_confusion"] > 0) emit("X11", "抹除语义与保密性结论混同（" rv["effaceable_confusion"] " 处）")
  if (rv["irk_no_value"] > 0) emit("X12", "IRK 在 Apple silicon 无功能价值一句未登记")

  # ---- Z 回查（十二码） ----
  if (rv["comp_form_rows"] > 0 && rv["impact_form_rows"] == 0)
    emit("Z01", "组件名列 " rv["comp_form_rows"] " 行 / 影响列 0 行")
  if (rv["comp_only"] > 0 && rv["impact_only"] > 0)
    emit("Z02", "双向错位 " rv["comp_only"] "/" rv["impact_only"])
  if (rv["crafted_rows"] > 0 && rv["crafted_comp_hits"] > 0)
    emit("Z03", "恶意构造子集 " rv["crafted_rows"] " 行中形态命中 " rv["crafted_comp_hits"] " 行")
  if (rv["crafted_collisions"] > 0) emit("Z04", "恶意构造命中含 " rv["crafted_collisions"] " 处词形撞车")
  if (rv["impact_form_macos"] > rv["impact_form_ios"] && rv["impact_form_ios"] > 0)
    emit("Z05", "影响列形态行 macOS=" rv["impact_form_macos"] " / iOS=" rv["impact_form_ios"] "（面向 macOS）")
  if (rv["impact_top_is_form"] == 0) emit("Z06", "影响列命中最多的组件不含形态词")
  if (rv["kev_total"] > 0 && rv["kev_form_hits"] == 0) emit("Z07", "KEV " rv["kev_total"] " 条里形态词形零命中")
  if (rv["mdm_keys"] > 0 && rv["mdm_form_hits"] == 0) emit("Z08", "管理面 " rv["mdm_keys"] " 键里形态词形零命中")
  if (rv["decl_total"] > 0 && rv["decl_disk"] <= 1) emit("Z09", "声明类型 " rv["decl_total"] " 项里盘类 " rv["decl_disk"] " 项")
  if (rv["guide_whitelist"] > 0 && rv["supports_keys"] > 0 && rv["guide_whitelist"] < rv["supports_keys"])
    emit("Z10", "用户指南白名单 " rv["guide_whitelist"] " 项 < supports 键 " rv["supports_keys"] " 个")
  if (rv["guide_single_partition"] > 0 && !("single_partition" in kc) && !("partition" in kc))
    emit("Z11", "单一分区要求无接口读回")
  if (rv["fp_ext_volume_handling"] > 0 && rv["fp_ext_volume_members"] == 0)
    emit("Z12", "FileProvider 外接卷实体命名存在而成员面不可读")

  # ---- 三件闭合等级 ----
  f_form = (rv["volume_keys"] > 0) + (rv["psg_volume"] > 0) + (rv["comp_form_rows"] > 0 || rv["impact_form_rows"] > 0) + (rv["decl_disk"] > 0)
  f_mount = (rv["mount_semantic"] > 0) + (rv["psg_mount"] > 0) + (rv["impact_form_rows"] > 0) + (rv["mdm_mount_keys"] > 0)
  f_enc = (rv["encrypted_is"] > 0) + (rv["psg_encryption"] > 0) + (rv["volume_encrypted_classes"] > 0) + (rv["mgmt_hw_enc_caps"] > 0)
  if (!QUIET) {
    printf "形态件 面=%d 等级=%s\n", f_form, (f_form >= 3 ? "Q1" : (f_form == 2 ? "Q2" : (f_form == 1 ? "Q3" : "Q4")))
    printf "挂载件 面=%d 等级=%s\n", f_mount, (f_mount >= 3 ? "Q1" : (f_mount == 2 ? "Q2" : (f_mount == 1 ? "Q3" : "Q4")))
    printf "加密件 面=%d 等级=%s\n", f_enc, (f_enc >= 3 ? "Q1" : (f_enc == 2 ? "Q2" : (f_enc == 1 ? "Q3" : "Q4")))
  }
  # 判定汇总：任一件 Q4 即 Q4，否则最差件等级
  qq[1] = f_form; qq[2] = f_mount; qq[3] = f_enc
  worst = 1
  for (i = 2; i <= 3; i++) if (qq[i] < qq[worst]) worst = i
  lvl = (qq[worst] >= 3 ? "Q1" : (qq[worst] == 2 ? "Q2" : (qq[worst] == 1 ? "Q3" : "Q4")))
  for (c in cnt) codelist[++cn] = c
  for (i = 2; i <= cn; i++) {
    x = codelist[i]; j = i - 1
    while (j >= 1 && codelist[j] > x) { codelist[j+1] = codelist[j]; j-- }
    codelist[j+1] = x
  }
  print "三件合计面数= " (f_form + f_mount + f_enc) " 信号行数= " siglines
  print "不同信号码= " cn " 阻断信号条数= " blkcount
  printf "闭合等级 形态=%d 挂载=%d 加密=%d 总判定=%s\n", f_form, f_mount, f_enc, lvl
  for (i = 1; i <= cn; i++) print codelist[i] "\t" cnt[codelist[i]] > "/dev/stderr"
  exit (siglines > 0 ? 1 : 0)
}
' "$@"
```

---


## 23. 三十四次实跑与全量信号覆盖验收

本章不给出任何新读数：第 16 章那十三组公开读数已经写完，第 21、22 章两支脚本的源码也已经完整给出，本章只做一件事——把源码、夹具、实跑输出与覆盖计数逐条对齐，并说明这套验收能证明什么、不能证明什么。四条标准贯穿全章。

| 号 | 标准 | 判据 | 落点 |
| --- | --- | --- | --- |
| V1 | **码数覆盖** | 脚本一的 62 个信号码与 J1—J4 四档判定、脚本二的 48 个信号码与 Q1—Q4 四级闭合，各自在留档里至少触发一次；两支脚本合计 118 个码（62+4+48+4）全部可达 | 23.4 的族计数与逐项可达性 |
| V2 | **只读与离线** | 二十段实证：awk 程序体内无 `system`／`getline`／`popen`／`ENVIRON`，被禁工具名不出现于命令位置，临时目录建后即删，输入文件摘要运行前后不变，脚本自身摘要运行前后不变 | 23.1 的 P1—P20 |
| V3 | **可回指** | 每个信号码在 21.4 与 22.4 的族表里有一行判据、一处行号、一处公开出处；指向本文自身的引用逐条写明节号 | 21.4、22.4 |
| V4 | **可复现** | 三十四次实跑的输入组合逐条列出；矩阵脚本 `matrix.sh`（113 行）可重跑；两支脚本的内嵌源码与实跑源码逐字节相同 | 23.2、23.3 与 P18 |

四条标准里 **V1 与 V4 是可数的，V2 是可 grep 的，V3 是可回查的**——没有一条要求读者拿设备、拿真实卷或拿第三方数据来验证。

### 23.1 二十段只读实证（V2）

`proof.sh`（107 行）是这一节的唯一证据来源。它和被它检查的两支脚本属于同一类东西，自己只做四类动作：grep 两支脚本的源码、各跑一遍夹具、比对运行前后的摘要、把矩阵留档的末四行原样引出；不联网、不访问设备、不修改任何输入，输出写 stdout 供本文逐字引用。

它有一个参数：含内嵌源码的报告文件路径。缺省值是同目录的 `part6.md`（写作时的分片文件，第 21、22 章各含一段完整源码）。报告装配成单文件之后，直接传报告文件名即可——P18 只取前三个 ```bash 代码块，依次比对 `script1.sh`、`script2.sh` 与这段实证脚本自己；第四个 ```bash 代码块是 23.3 节那条读三件分项的一行命令，不参与比对。所读文件不足三段时（例如只读 `part6.md`），第三段比对打印「跳过」而不是失败。P1—P17、P20 与报告文件无关，P18 依赖它，P19 是自校验。

```bash
#!/usr/bin/env bash
# 第 20 篇只读实证 P1—P20（全部命令可复跑；不联网、不碰设备）
# 用法: bash proof.sh [含内嵌源码的报告文件]；缺省读同目录的 part6.md
set -u
cd "$(dirname "$0")" || exit 2
MD=${1:-part6.md}
FX=fx
T=$(mktemp -d "${TMPDIR:-/tmp}/p20pf.XXXXXX") || exit 2
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

hr "P4 十三个被禁工具名的全部出现位置（头部声明／脚本名／字段名）"
grep -nE 'diskutil|hdiutil|fdesetup|plutil|apfs\.util|fsck|xcrun|\bmount\b|\bumount\b|\bsecurity\b|\bdefaults\b|\blog\b|\bsysctl\b' script1.sh script2.sh

hr "P4b 命令位置探测（行首或 | ; &）( 之后）"
grep -nE '(^|[|;&(])[[:space:]]*(diskutil|hdiutil|mount|umount|fdesetup|security|defaults|log|sysctl|plutil|fsck|xcrun|apfs\.util)[[:space:]]' script1.sh script2.sh || echo "命令位置命中= 0"

hr "P5 命令名整词普查"
grep -ohE '\b(awk|tr|cat|mktemp|rm|bash|sh|perl|python|python3|node|curl|wget|nc|ssh|scp)\b' script1.sh script2.sh | sort | uniq -c

hr "P6 网络工具整词计数"
printf 'script1.sh= '; grep -cE '\b(curl|wget|nc|ssh|scp|ftp|telnet)\b' script1.sh
printf 'script2.sh= '; grep -cE '\b(curl|wget|nc|ssh|scp|ftp|telnet)\b' script2.sh

hr "P7 写出方向：追加与 stderr 之外的写重定向"
grep -nE '(>>|> *"/dev/stderr"|>&2)' script1.sh script2.sh; echo "（以上仅为 /dev/stderr 与 usage 的 >&2；无 >> 追加）"

hr "P8 TMPD 出现次数"
printf 'script1.sh= '; grep -c 'TMPD' script1.sh
printf 'script2.sh= '; grep -c 'TMPD' script2.sh

hr "P9 输入文件运行前后摘要一致"
cp "$FX/s1-bad.tsv" "$T/in1.tsv"; cp "$FX/s2-r-bad.tsv" "$T/in2.tsv"
b1=$(md5sum "$T/in1.tsv" | awk '{print $1}'); b2=$(md5sum "$T/in2.tsv" | awk '{print $1}')
bash script1.sh "$T/in1.tsv" >/dev/null 2>&1
bash script2.sh "$FX/s2-keys-good.tsv" "$FX/s2-st-good.tsv" "$T/in2.tsv" >/dev/null 2>&1
a1=$(md5sum "$T/in1.tsv" | awk '{print $1}'); a2=$(md5sum "$T/in2.tsv" | awk '{print $1}')
[ "$b1" = "$a1" ] && echo "script1 输入未变 $a1" || echo "script1 输入被改动"
[ "$b2" = "$a2" ] && echo "script2 输入未变 $a2" || echo "script2 输入被改动"

hr "P10 临时目录零残留"
T2=$(mktemp -d "${TMPDIR:-/tmp}/p20t2.XXXXXX") || exit 2
TMPDIR="$T2" bash script1.sh "$FX/s1-good.tsv" >/dev/null 2>&1
TMPDIR="$T2" bash script2.sh "$FX/s2-keys-good.tsv" "$FX/s2-st-good.tsv" "$FX/s2-r-good.tsv" >/dev/null 2>&1
printf '运行后 TMPDIR 内条目数= '; find "$T2" -mindepth 1 | wc -l
rm -rf "$T2"

hr "P11 干净夹具：0 信号、退出 0"
bash script1.sh "$FX/s1-good.tsv" > "$T/g1" 2> "$T/g1e"; e1=$?
bash script2.sh "$FX/s2-keys-good.tsv" "$FX/s2-st-good.tsv" "$FX/s2-r-good.tsv" > "$T/g2" 2> "$T/g2e"; e2=$?
echo "script1 退出= $e1"; grep -E '卷台账记录数|不同信号码|判定分布' "$T/g1"
echo "script2 退出= $e2"; grep -E '三件合计面数|不同信号码|闭合等级' "$T/g2"

hr "P12 -h 帮助：退出 0"
bash script1.sh -h > "$T/h1"; echo "script1 -h 退出= $? 含用法= $(grep -c '用法' "$T/h1")"
bash script2.sh -h > "$T/h2"; echo "script2 -h 退出= $? 含用法= $(grep -c '用法' "$T/h2")"

hr "P13 缺参数：退出 2"
bash script1.sh >/dev/null 2>&1; echo "script1 无参数退出= $?"
bash script2.sh "$FX/s2-keys-good.tsv" "$FX/s2-st-good.tsv" >/dev/null 2>&1; echo "script2 两输入退出= $?"

hr "P14 不可读输入：退出 2"
bash script1.sh "$T/不存在.tsv" >/dev/null 2>&1; echo "script1 退出= $?"
bash script2.sh "$FX/s2-keys-good.tsv" "$FX/s2-st-good.tsv" "$T/不存在.tsv" >/dev/null 2>&1; echo "script2 退出= $?"

hr "P15 未知选项：退出 2"
bash script1.sh -x >/dev/null 2>&1; echo "script1 退出= $?"
bash script2.sh -x >/dev/null 2>&1; echo "script2 退出= $?"

hr "P16 A05 取值拒收：路径形态"
printf 'V_x,doc.note,/private/var/db/x\n' > "$T/dirty1.tsv"
bash script1.sh "$T/dirty1.tsv" > "$T/d1o" 2> "$T/d1e"; echo "退出= $?"
grep 'A05' "$T/d1e"; grep '阻断信号条数' "$T/d1o"

hr "P17 脚本二格式不符行跳过：路径形态"
cp "$FX/s2-keys-good.tsv" "$T/keys-dirty.tsv"
printf '/Users/x/secret,volume,1\n' >> "$T/keys-dirty.tsv"
bash script2.sh "$T/keys-dirty.tsv" "$FX/s2-st-good.tsv" "$FX/s2-r-good.tsv" > "$T/d2o" 2> "$T/d2e"; echo "退出= $?"
grep '跳过格式不符行' "$T/d2e"; grep '三件合计面数' "$T/d2o"

hr "P18 报告内嵌源码与实跑源码一致"
rm -f "$T/e1.sh" "$T/e2.sh" "$T/e3.sh"
awk '/^```bash$/{inb=1; b++; next} /^```$/{if(inb){inb=0}; next} inb&&b==1{print > "'"$T"'/e1.sh"} inb&&b==2{print > "'"$T"'/e2.sh"} inb&&b==3{print > "'"$T"'/e3.sh"}' "$MD"
diff -q script1.sh "$T/e1.sh" && echo "script1 内嵌= 一致"
diff -q script2.sh "$T/e2.sh" && echo "script2 内嵌= 一致"
if [ -f "$T/e3.sh" ]; then diff -q proof.sh "$T/e3.sh" && echo "proof.sh 内嵌= 一致"; else echo "proof.sh 内嵌= 跳过（所读文件不足三段 bash 块）"; fi

hr "P19 两支脚本自身运行前后摘要一致"
h1=$(md5sum script1.sh | awk '{print $1}'); h2=$(md5sum script2.sh | awk '{print $1}')
[ "$h1" = "$S1H0" ] && echo "script1 未变 $h1" || echo "script1 被改动 $S1H0 -> $h1"
[ "$h2" = "$S2H0" ] && echo "script2 未变 $h2" || echo "script2 被改动 $S2H0 -> $h2"

hr "P20 34 次实跑覆盖验收"
tail -4 matrix-out.txt
```

它在装配成单文件的报告上跑出的**全量输出**（119 行、20 段，逐字照抄，未删行）：

```text

===== P1 awk 程序体内无 system/getline/popen/ENVIRON =====
命中= 0

===== P2 bash -n 语法检查 =====
script1.sh 语法= 通过
script2.sh 语法= 通过

===== P3 临时目录前缀 =====
script1.sh:12:#       唯一写出目标是 mktemp -d 创建的临时目录，退出时删除，本实现不向其写入任何字节。
script1.sh:55:TMPD=$(mktemp -d "${TMPDIR:-/tmp}/vol20.XXXXXX") || exit 2
script2.sh:16:#       唯一写出目标是 mktemp -d 创建的临时目录，退出时删除，本实现不向其写入任何字节。
script2.sh:57:TMPD=$(mktemp -d "${TMPDIR:-/tmp}/vft20.XXXXXX") || exit 2

===== P4 十三个被禁工具名的全部出现位置（头部声明／脚本名／字段名） =====
script1.sh:2:# volume-mount-ledger-review.sh —— 卷挂载台账逐字段审查器（离线 / 只读 / 不联网 / 不碰设备）
script1.sh:10:# 本脚本不联网、不调用 diskutil／hdiutil／mount／umount／fdesetup／security／defaults／log／sysctl／
script1.sh:11:#       plutil／apfs.util／fsck／xcrun 等任何命令行工具、不读取设备状态、不打开任何被登记的卷；
script1.sh:18:用法: volume-mount-ledger-review.sh [-q] 台账文件 [...]
script1.sh:195:    if (sup == "1" && mstate == "1" && opts == "") emit("D02", id, "supports=1 被写成 mount.state=1（无独立挂载读数）")
script2.sh:14:# 本脚本不联网、不调用 diskutil／hdiutil／mount／umount／fdesetup／security／defaults／log／sysctl／
script2.sh:15:#       plutil／apfs.util／fsck／xcrun 等任何命令行工具、不读取设备状态、不打开任何被登记的卷；
script2.sh:113:  if (!("psg_mount" in rv)) rv["psg_mount"] = num(sc["mount"])

===== P4b 命令位置探测（行首或 | ; &）( 之后） =====
命令位置命中= 0

===== P5 命令名整词普查 =====
      2 awk
      2 bash
      3 cat
      4 mktemp
      2 rm
      4 sh
      1 tr

===== P6 网络工具整词计数 =====
script1.sh= 0
script2.sh= 0

===== P7 写出方向：追加与 stderr 之外的写重定向 =====
script1.sh:45:    -*) usage >&2; exit 2 ;;
script1.sh:50:[ $# -ge 1 ] || { usage >&2; exit 2; }
script1.sh:52:  [ -r "$f" ] || { echo "输入不可读: $f" >&2; exit 2; }
script1.sh:61:  print code "\t" (id == "" ? "-" : id) "\t" msg > "/dev/stderr"
script1.sh:305:  for (i = 1; i <= cn; i++) print codelist[i] "\t" cnt[codelist[i]] > "/dev/stderr"
script2.sh:47:    -*) usage >&2; exit 2 ;;
script2.sh:52:[ $# -eq 3 ] || { usage >&2; exit 2; }
script2.sh:54:  [ -r "$f" ] || { echo "输入不可读: $f" >&2; exit 2; }
script2.sh:63:  print code "\t-\t" msg > "/dev/stderr"
script2.sh:126:  for (i = 1; i <= n; i++) if (!(rq[i] in rv)) { print "缺度量: " rq[i] > "/dev/stderr"; missing++ }
script2.sh:128:  if (badline > 0) print "跳过格式不符行: " badline > "/dev/stderr"
script2.sh:129:  if (badgroup > 0) print "词表组取值越界行: " badgroup > "/dev/stderr"
script2.sh:130:  if (badsource > 0) print "来源取值越界行: " badsource > "/dev/stderr"
script2.sh:233:  for (i = 1; i <= cn; i++) print codelist[i] "\t" cnt[codelist[i]] > "/dev/stderr"
（以上仅为 /dev/stderr 与 usage 的 >&2；无 >> 追加）

===== P8 TMPD 出现次数 =====
script1.sh= 2
script2.sh= 2

===== P9 输入文件运行前后摘要一致 =====
script1 输入未变 728315e575b561c14aadd0e7b879dd24
script2 输入未变 8ac5259559e275dd40357e8d40b89ce3

===== P10 临时目录零残留 =====
运行后 TMPDIR 内条目数= 0

===== P11 干净夹具：0 信号、退出 0 =====
script1 退出= 0
卷台账记录数= 4 信号行数= 0 判定行数= 4
不同信号码= 0 阻断信号条数= 0
判定分布 J1= 4 J2= 0 J3= 0 J4= 0
script2 退出= 0
三件合计面数= 12 信号行数= 0
不同信号码= 0 阻断信号条数= 0
闭合等级 形态=4 挂载=4 加密=4 总判定=Q1

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

===== P16 A05 取值拒收：路径形态 =====
退出= 1
A05	V_x	取值形似设备路径／凭据／超长载荷，拒收: doc.note
A05	1
不同信号码= 1 阻断信号条数= 1

===== P17 脚本二格式不符行跳过：路径形态 =====
退出= 0
跳过格式不符行: 1
三件合计面数= 12 信号行数= 0

===== P18 报告内嵌源码与实跑源码一致 =====
script1 内嵌= 一致
script2 内嵌= 一致
proof.sh 内嵌= 一致

===== P19 两支脚本自身运行前后摘要一致 =====
script1 未变 aa0dbd2122adf22f47bab7d9b611b68d
script2 未变 31f3cfcc4fe76556dd05cf4ffc352f26

===== P20 34 次实跑覆盖验收 =====

实跑次数合计= 34（脚本一 19 + 脚本二 15）
脚本一覆盖码= 62/62  脚本二覆盖码= 48/48
覆盖验收= 通过
```

二十段里最需要逐行读的是 P4、P4b 与 P16、P17。P4 的第五、六、七处命中分别是：脚本名 `volume-mount-ledger-review.sh`、字段名 `mount.state`、`psg_mount`，其余四处是头部两行拒收声明——**没有一处是命令调用**。P4b 用同一条规则只认「行首或 `|` `;` `&` `(` 之后、后跟空白」的位置，两支脚本的命中数为 0；这说明「不调用被禁工具」不是靠词形不出现，而是靠命令位置为空。P16 与 P17 是一对：同一个路径形态的取值，脚本一按 `A05` 拒收并阻断（退出 1、阻断信号 1 条），脚本二按格式不符跳过该行（`跳过格式不符行: 1`），**两支脚本对同一种污染给出两种不同但都显式的处理**——拒收与跳过，都不静默接受。

P19 是自校验：脚本开头取一次 md5，跑完全部实证后再取一次，两次相同才打印「未变」。这条检查的作用是排除「实证过程本身改写了被检查对象」——包括 P9 对输入的复制、P10 对 `TMPDIR` 的重定向、P18 对代码块的抽取，都不落在脚本本体上。

### 23.2 脚本一 19 次实跑（V4 前半）

脚本一的夹具分四类。**基准三份**：`s1-good.tsv` 是 4 条干净记录（0 信号、J1=4、退出 0）；`s1-mid.tsv` 是 1 条中间态记录，触发 `E02`、`H06`、`K05` 三个警告码（J2=1、退出 0）；`s1-bad.tsv` 是 61 条记录、146 条信号，一次打满 62 个码，判定分布 `J1=1 J2=23 J3=22 J4=15`。**十二个定向子集**由 `matrix.sh` 第 12—17 行从 `s1-bad.tsv` 按记录标识切出，每个子集只保留一类记录，用来证明该码在**没有其它码同框**的情况下仍可单独触发：`V_A03`→`A03`、`V_C03`→`C03`、`V_D02`→`D02`+`H01`、`V_E01`→`E01`、`V_H01`→`H01`、`V_K03`→`K03`、`V_Q02`→`Q02`、`V_C05`→`C05`、`V_D07`→`D07`、`V_E04`→`E04`、`V_H09`→`H09`、`V_K05`→`K05`。**三条用法错误**：无参数、未知选项 `-x`、输入不可读，全部退出 2、零信号。**一条格式破坏台账**：`broken.tsv` 只有两行有效内容（`broken,line` 与 `,vol.role,system`），分别触发 `A01`（列数不是三）与 `A02`（记录标识为空），两条都是阻断码，退出 1，且因为没有任何完整记录，判定行为 0。

```text
===== 脚本一（19 次） =====
S1-01  干净台账                         码=0   退出=0/0  判定分布 J1= 4 J2= 0 J3= 0 J4= 0
S1-02  中间态台账                      码=3   退出=0/0  判定分布 J1= 0 J2= 1 J3= 0 J4= 0
S1-03  全码覆盖台账                   码=62  退出=1/1  判定分布 J1= 1 J2= 23 J3= 22 J4= 15
S1-04  定向子集 V_A03                   码=1   退出=1/1  判定分布 J1= 0 J2= 0 J3= 0 J4= 0
S1-05  定向子集 V_C03                   码=1   退出=1/1  判定分布 J1= 0 J2= 0 J3= 1 J4= 0
S1-06  定向子集 V_D02                   码=2   退出=1/1  判定分布 J1= 0 J2= 0 J3= 1 J4= 0
S1-07  定向子集 V_E01                   码=1   退出=1/1  判定分布 J1= 0 J2= 0 J3= 1 J4= 0
S1-08  定向子集 V_H01                   码=1   退出=0/0  判定分布 J1= 0 J2= 1 J3= 0 J4= 0
S1-09  定向子集 V_K03                   码=1   退出=1/1  判定分布 J1= 0 J2= 0 J3= 1 J4= 0
S1-10  定向子集 V_Q02                   码=1   退出=1/1  判定分布 J1= 0 J2= 0 J3= 0 J4= 1
S1-11  定向子集 V_C05                   码=1   退出=1/1  判定分布 J1= 0 J2= 0 J3= 1 J4= 0
S1-12  定向子集 V_D07                   码=1   退出=1/1  判定分布 J1= 0 J2= 0 J3= 1 J4= 0
S1-13  定向子集 V_E04                   码=1   退出=0/0  判定分布 J1= 0 J2= 1 J3= 0 J4= 0
S1-14  定向子集 V_H09                   码=1   退出=1/1  判定分布 J1= 0 J2= 0 J3= 1 J4= 0
S1-15  定向子集 V_K05                   码=1   退出=0/0  判定分布 J1= 0 J2= 1 J3= 0 J4= 0
S1-16  无参数                            码=0   退出=2/2  
S1-17  未知选项 -x                      码=0   退出=2/2  
S1-18  输入不可读                      码=0   退出=2/2  
S1-19  格式破坏台账                   码=2   退出=1/1  判定分布 J1= 0 J2= 0 J3= 0 J4= 0
```

这张表有两处需要解释。**其一，`S1-04` 到 `S1-15` 的判定分布几乎全零**：定向子集只保留一条记录，脚本按记录逐行判定，所以 `J1=J2=J3=J4=0` 不代表没有判定，而是那一条记录的判定落在**一个**桶里——`码=1` 那列才是该次实跑的信号数。表里 `S1-10` 是唯一一个 `J4=1` 的定向子集，因为 `Q02` 属阻断类；`S1-08`、`S1-13`、`S1-15` 的退出码是 0，因为 `H01`、`E04`、`K05` 都属警告类。**其二，`S1-06` 的 `码=2`**：`V_D02` 那一条记录同时触发 `D02`（supports=1 被写成 mount.state=1）与 `H01`（挂载读数缺一项），说明一个记录可以同时命中两个族的码，定向子集不等于「单码夹具」。

### 23.3 脚本二 15 次实跑（V4 后半）

脚本二的输入固定为三份表（键清单、语句清单、读数表），夹具因此分五类。**干净与派生**：`S2-01` 三份齐全、0 信号、三件各 4 面、总判定 Q1；`S2-02` 读数表只给不可派生的度量，键清单与语句清单补齐全部可派生项，仍然 0 信号 Q1——这一条证明「读数优先、缺项由清单派生」的规则（第 22 章 22.2 节）。**换算缺口**：`S2-03` 把 `volume_keys`、`mount_semantic`、`encrypted_is` 三个接口读数置 0，触发 7 个码，三件仍有足够面数，总判定 Q1——**信号存在与闭合等级是两件事**。**公告与回查全坏**：`S2-04` 触发 35 个码、总判定 Q3；`S2-06` 在键清单里加入分区键，仍为 Q3（33 个码）。**全零**：`S2-05` 触发 32 个码、总判定 Q4；`S2-07` 带分区键、30 个码、Q4。**清单退化**：`S2-08` 键清单只剩一行 `form,volume,0`，触发 `F03`、`F04`、`F05`、`V01`、`W01`、`W07` 六个码，但读数表仍给出足够的面，总判定 Q1；`S2-09` 语句清单全零，触发 11 个码（`F04`、`V02`、`V07`、`V08`、`W02`、`W06`、`X01`、`X02`、`Z10`、`Z11`、`Z12`），Q1；`S2-10` 语句清单只缺 `seal` 与 `removable` 的语义分叉，7 个码，Q1；`S2-11` 双清单皆空，12 个码，总判定 Q2。**用法错误**：`S2-12` 缺一个不可派生度量（`unmount_options`），退出 2；`S2-13` 只给两个输入、`S2-14` 未知选项、`S2-15` 输入不可读，均退出 2。

```text
===== 脚本二（15 次） =====
S2-01  读数齐全·干净                 码=0   退出=0/0  判定=Q1
S2-02  读数缺派生项·键语句补齐  码=0   退出=0/0  判定=Q1
S2-03  三处换算缺口                   码=7   退出=1/1  判定=Q1
S2-04  公告与回查全坏                码=35  退出=1/1  判定=Q3
S2-05  全零读数                         码=32  退出=1/1  判定=Q4
S2-06  带分区键·公告全坏           码=33  退出=1/1  判定=Q3
S2-07  带分区键·全零读数           码=30  退出=1/1  判定=Q4
S2-08  键清单仅一行                码=6   退出=1/1  判定=Q1
S2-09  语句清单全零                   码=11  退出=1/1  判定=Q1
S2-10  语句清单分叉                   码=7   退出=1/1  判定=Q1
S2-11  双清单皆空                      码=12  退出=1/1  判定=Q2
S2-12  读数缺不可派生项             码=0   退出=2/2  判定=-
S2-13  只给两个输入                   码=0   退出=2/2  判定=-
S2-14  未知选项 -x                      码=0   退出=2/2  判定=-
S2-15  输入不可读                      码=0   退出=2/2  判定=-
```

两处值得单独指出。**其一，`S2-03` 的 7 个码与 Q1 并存**：三处换算缺口（`F03`、`F06`、`F07` 一类）是「面上有读数但换算失败」的信号，不是「面缺失」；闭合等级只数面，所以面数够就是 Q1。这正是 19.3 节说的「J 与 Q 不能相加」在脚本二内部的对应物——**信号数与闭合等级不是同一根轴**。

**其二，`S2-11` 是唯一一个「面数与面数不等」的读数**。`matrix-out.txt` 每行只留总判定，三件分项要直接看标准输出：对同三份输入（`fx/s2-keys-empty.tsv`、`fx/s2-st-empty.tsv`、`fx/s2-r-metrics.tsv`）重跑一次，把五行过滤出来——

```bash
bash script2.sh fx/s2-keys-empty.tsv fx/s2-st-empty.tsv fx/s2-r-metrics.tsv 2>&1 \
  | grep -E '形态件|挂载件|加密件|三件合计面数|闭合等级'
```

得到 `形态件 面=2 等级=Q2`、`挂载件 面=2 等级=Q2`、`加密件 面=3 等级=Q1`、`三件合计面数= 7 信号行数= 12`、`闭合等级 形态=2 挂载=2 加密=3 总判定=Q2`。三件面数是 **2／2／3**，最差件两面，按 19.2 的阈值（≥3 面 Q1、2 面 Q2、1 面 Q3、0 面 Q4）总判定落在 Q2，与 `matrix-out.txt` 的 `判定=Q2` 逐字相符。**双清单皆空而加密件仍有 3 面**，是因为读数表 `s2-r-metrics.tsv` 里保留了不可派生的加密类读数，加密件的第三面因此还站着——这恰好演示了「派生清单可以整块缺失、直接读数不能缺失」这条输入规则（22.2 节）。

### 23.4 覆盖比对（V1）

覆盖计数只看两件事：脚本源码里 `emit` 的码集合，与三十四次实跑的 stderr 里出现的码集合；两者的差集必须为空。脚本一的码按族分布是 A 8（`A01`—`A08`）、C 8、D 12、E 8、H 12、K 8、Q 6，合计 62；加上 stdout 上的 J1—J4 四档判定，脚本一定义 66 个码。脚本二的码按族分布是 F 8、V 8、W 8、X 12、Z 12，合计 48；加上 Q1—Q4 四级闭合，脚本二定义 52 个码。**118 = 66 + 52**，与第 21、22 章逐族列出的数目逐项相等。

| 验收项 | 脚本一 | 脚本二 |
| --- | --- | --- |
| 信号码覆盖 | 62/62（`S1-03` 一次打满） | 48/48（分布在 11 个带信号的实跑里） |
| 判定位可达 | J1（`S1-01`）、J2（`S1-02`）、J3（`S1-05` 等）、J4（`S1-10`） | Q1（`S2-01`）、Q2（`S2-11`）、Q3（`S2-04`）、Q4（`S2-05`） |
| 退出码分布 | 0×6、1×10、2×3 | 0×2、1×9、2×4 |
| 零信号基准 | `S1-01` 4 条记录全 J1 | `S2-01` 三件各 4 面全 Q1 |
| 拒收路径 | `S1-19` 的 `A01`+`A02`；P16 的 `A05` | P17 的 `跳过格式不符行`；`S2-12` 的缺度量 |

退出码分布本身是验收项：只出现 0 与 1 说明输入校验那条路径没被跑到；只出现 1 说明合格一侧的下界没被证明；出现 2 且只出现在用法与输入错误上，才说明三条出口都被区分开。脚本一的 0×6、1×10、2×3 与脚本二的 0×2、1×9、2×4 都满足这一点。

覆盖验收的**逐码可达性**由三个层次支撑。第一层是 `S1-03` 的 62/62：61 条记录、146 条信号一次覆盖全部码，说明码集合内部没有死码。第二层是十二个定向子集：每个子集只带一类记录，证明那些码在「没有别的记录同框」时也能触发，不依赖上下文巧合。第三层是格式破坏与用法错误：`A01`、`A02`、`A05` 与退出码 2 的四条路径（无参数、未知选项、不可读、缺度量）都在这里被单独触发。三层合起来，**62 与 48 不是「至少出现过一次」的弱计数，而是「每个码都能被一条最小输入单独打到」的强计数**——除了 `D02`+`H01` 那一对，它们是同一个记录的两个后果，本文在第 23.2 节已经点明。

### 23.5 这套验收不证明什么

**第一，不证明判据正确。** 覆盖只回答「码能不能被触发」，不回答「这条判据是否该这样写」。判据的正确性由 21.4、22.4 两节的族表逐行给出出处，并由第 24 章十二个误区逐条反向约束；读者若不同意某条判据，应当去改那两节与对应源码，而不是看覆盖数。

**第二，不证明夹具真实。** 全部夹具是合成的标识与计数，不含任何真实设备名、真实卷名、真实密钥材料或可还原身份的描述。`s1-bad.tsv` 的 61 条记录是构造出来的「每条记录命中一类码」，不对应任何一次真实事故。

**第三，不证明任何真实卷的状态。** 两支脚本都不接触设备、不调用 `diskutil`／`mount`／`fdesetup`，因此它们对一台真实 iPhone 的卷形态、挂载状态、加密状态**一无所知**；它们只审查「你写下来的台账」与「你抄下来的读数表」。

**第四，Q 等级不是安全评分。** Q1—Q4 数的是「三件各有几面有读数」，不是「安全性高低」。一个 Q4 的读数集合可能对应一台完全正常的设备，只是公开面读不到；一个 Q1 的读数集合也可能对应一台已经被改动的设备，只是台账写全了。第 19.3 节已经把这条写成模型边界。

**第五，三十四次不等于全部输入空间。** 矩阵没有覆盖 `-q` 分支与「多份台账合并读入」的形态；这两条只在第 21.5 节的用法说明里按源码行号声明，属于**代码可读事实**，不是**实跑已验证事实**。同理，脚本二的 `--` 选项终止符也没有单独实跑。把这三条列出来，是为了让读者知道 34 这个数字的边界在哪里，而不是把「34 次通过」当成「所有路径都通过」。

---

## 24. 十二个误区

这一章把全篇最容易读错的十二处集中列出。每一条给三样东西：**误读**（一句会被写进报告或台账的话）、**正确读法**（公开口径实际支持的那一句）、**判据**（哪一行读数否证了它）。最后给三条禁令。

| 编号 | 误读 | 正确读法 | 判据与脚本码 |
| --- | --- | --- | --- |
| M01 | 公告组件名列命中 `apfs`／`hfs`／`corestorage`，所以这几类是「文件系统缺陷」的主体 | 组件名列命中只是**归属标签**，不是缺陷类型；同一批公告的影响句列对这三个词形是 0 行 | `C/readings-20.txt:4—6、47—49`；F1／F2；脚本二 Z01 |
| M02 | 恶意构造子集里 24 行命中形态词，就是 24 行「恶意构造的文件系统镜像」 | 24 行里只有 4 对是真同名／真包络，`archive` 两次、`storage` 一次是词形撞车，必须先扣减 | `C/readings-20.txt:92—94`；F8；脚本二 Z03／Z04 |
| M03 | KEV 里形态词形 0 命中，说明文件系统类缺陷没有在野利用 | 0/95 只说明**归因词形未覆盖**，不说明风险为零；记「未覆盖」，不记「无风险」 | `C/readings-20.txt:100、101`；O6 |
| M04 | 卷是 exFAT／NTFS，所以安全属性弱；macOS 的读写清单就是 iOS 的挂载矩阵 | 三个 Windows 兼容词形在公告、管理面、KEV 全部 0 命中；macOS 清单回答「能不能写」，iOS 白名单回答「能不能挂」 | `C/readings-20.txt:7—9、115`；`A/mac_cant_save_files_external_drive-S.txt:24—28`；`A/iphone_external_storage-S.txt:1154`；脚本一 D08／D09 |
| M05 | `volumeSupportsFileProtectionKey=1`，所以这个卷上的文件受保护 | 这是**承载能力**，不是保护状态；保护由文件所属的类决定，Class D 的文件也在同一卷上 | `A/foundation_urlresourcekey_all.txt:986`；`A/security_data_protection_overview-S.txt:241`；`A/security_data_protection_classes-S.txt:272`；脚本一无专用码（D02 只拦 `supports=1`→`mount.state=1`；本格靠键级对照） |
| M06 | iOS 按用户把文件系统内容分卷，所以可以按用户划归属 | iOS／iPadOS／visionOS **不支持**按用户密码学分离文件内容；文件走 device keybag，默认配置下 device 与 user keybag 是同一个 | `B/apple-platform-security-guide.txt:1993`；脚本一 K06 |
| M07 | 用户能选 `APFS（encrypted）`，所以「加密」是卷的一个属性；`volumeIsEncryptedKey=true` 就是「全卷同强度」 | 加密在用户面是**格式菜单的一项**，在接口面是一个**布尔**，两者无公开换算；卷级布尔也不回答强度 | `A/iphone_external_storage-S.txt:1154`；`A/foundation_urlresourcekey_all.txt:812`；F5；脚本一 D07 |
| M08 | `DiskManagementSettings` 能管 iOS 的挂载；其中 `ReadOnly` 是把外设降成只读 | 该声明只在 macOS 15.0 可用、只在 supervised／local 与系统 scope 可用；`ReadOnly` 只挂载本来就只读的外设，文档明写「读写外设不会被降成只读」 | `A/mdm-diskmanagementsettings-M.txt:6、18—22`；`A/mdm-diskmgmt-restrictions-object-M.txt:10`；无脚本码（可用性行与策略枚举都是文档读数，两支脚本都不解析平台列） |
| M09 | 每个卷报告的可用空间相加就是容器总空闲；N 份内容就是 N 倍占用 | 同一容器的卷共享空闲额度，求和被文档明写为不可靠；克隆与稀疏使「份数×大小」不等于占用 | `A/dev_about_apple_file_system-S.txt:19、22、12、16、28`；脚本一 E01／E02 |
| M10 | 设备级容量或 `HardwareEncryptionCaps` 能当卷级读数 | 前者是设备级整数，后者是「设备的硬件加密能力」，与卷、类、文件之间没有公开换算 | `A/mdm-securityinfo-dictionary-M.txt:28`；F6／F7；脚本二 X05／X06 |
| M11 | 启动链在 mount 之前校验了 seal，所以这个卷是可信的；系统卷完整性可以回查 | 校验句的主语是「内核将要挂载的那个文件系统」，只覆盖系统卷启动路径；接口侧没有 seal 读数，管理面也不可配置 | `B/apple-platform-security-guide.txt:772、1122、1128、1129`；脚本一 H12 |
| M12 | Files 里一个 iCloud／第三方位置消失，就是这个卷被卸载了 | FileProvider 的 `isDisconnected` 描述扩展与域的连接，不是卷与挂载表的关系；重连靠重建同标识对象 | `A/fileprovider_nsfileproviderdomain_isDisconnected.txt:18`；`A/fileprovider_nsfileproviderdomain_userEnabled.txt`；脚本一 H05 |

十二条按主题可以压成四组，每组一条共同禁令。

**第一组 M01—M03：公告面只给标签，不给类型。** 三处的共同结构是「一个数字看起来像结论」。32 行是组件名命中，0 行是影响句命中，24 行里还混着撞车，95 条 KEV 里 0 条带形态词——四个数字分别回答四个不同的问题，任何一个都不能单独写成「文件系统类缺陷有多少」。**禁令：公告侧的计数必须成对报，分子与分母同时给出；只报一个数字即视为 M01。**

**第二组 M04—M07：形态、能力、加密是三栏。** exFAT 是形态名，不是安全等级；`supports` 是能力，不是状态；`encrypted` 是格式项或布尔，不是强度；`APFS（encrypted）` 与 `volumeIsEncryptedKey` 之间没有换算。四条的共通点是**把一个名词当成一个形容词用**。**禁令：形态栏只填形态名，能力栏只填 0/1，加密栏只填布尔与粒度；三栏之间不得互相赋值。**

**第三组 M08—M10：管理面与容量的分母都不是卷。** 唯一的挂载策略原语是 macOS 的、介质类别粒度的；设备级容量与设备级加密整数的主语是设备；卷容量不能求和。三处的共同点是**把设备或介质的分母套到卷上**。**禁令：写到「卷」的读数必须能指到卷级键；指不到就写 unknown，不写设备值。**

**第四组 M11—M12：校验与连接都不是「卷可信」的同义词。** seal 校验证明的是「内核将要挂载的文件系统」的完整性，不证明这台设备上所有卷可信；FileProvider 的断开证明的是域与扩展的连接状态，不证明卷被卸载。两处的共同点是**把一条局部真命题扩写成全称命题**。**禁令：任何「可信」「已卸载」的结论，必须写明它覆盖的是哪一个对象、由哪一句公开文本给出。**

---

## 25. 常见问题

**问：这套台账与两支脚本必须跑在设备上吗？**
不。两支脚本都是纯文本、离线、只读：脚本一（`tools/volume-mount-ledger-review.sh`，308 行）收一份或多份三列台账，脚本二（`tools/volume-form-mount-encryption-diff.sh`，236 行）固定收三份读数表——键清单、语句清单、读数表。第 23.1 节那二十段实证专门回答这个问题：P1 在 awk 程序体里对 `system(`／`getline`／`popen`／`ENVIRON` 的匹配是空的；P4b 用「行首或 `|` `;` `&` `(` 之后、后跟空白」的命令位置规则扫两支脚本，命中 0；P5 的整词普查只有 `awk`、`bash`、`cat`、`mktemp`、`rm`、`sh`、`tr` 七个名字，`perl`／`python`／`node`／`curl`／`wget`／`nc`／`ssh`／`scp` 一行都不出现；P6 的网络工具计数两支都是 0；P9 比对运行前后的输入摘要，两份都没有变；P10 把 `TMPDIR` 指到一个空目录跑完两支脚本，事后条目数为 0；P19 在开头与结尾各取一次脚本自身的 md5，两次相同。**这二十段证明的是「没有读别处的口子」，不是「读到的内容与真实设备一致」**——第 23.5 节把这条不对称写成验收的第一条限制。

**问：两支脚本先跑哪一支？为什么不合并成一个分数？**
先脚本一。它逐条检查九个命名空间里该填的格填没填、填的形态合不合规，输出 `J1`—`J4`，回答「这一条登记能不能用」；脚本二吃的是另一形状，输出 `Q1`—`Q4`，回答「三件的面还能不能立起来」。两者的对象与分母都不同：`J` 的分母是一条记录，`Q` 的分母是一件三件之一的四面。合格夹具上的两个「最好值」也不是同一件事——`S1-01` 读 `卷台账记录数= 4 信号行数= 0`、`判定分布 J1= 4`，说的是四条登记各自自洽；`S2-01` 读 `三件合计面数= 12`、`总判定=Q1`，说的是三份读数对得完。**绝不合并成单一分数**：脚本二的退出码只看 `siglines`（第 234 行），等级只看面数，`S2-08`（键清单只剩一行）打 6 个信号、退出码 1，三件面数仍齐、总判定 `Q1`；一个合并分会把「信号多」与「面数少」压成同一个数，而这正是第 19.3 节禁止的加法。

**问：118 个码全部至少触发一次，是不是说明判据判得对？**
不，它只说明每条判据都还活着。118 是两支脚本的全部格子：脚本一 62 个信号码加 `J1`—`J4` 共 66，脚本二 48 个信号码加 `Q1`—`Q4` 共 52。覆盖的分布也不一样：脚本一靠 `S1-03` 一次打满——61 条记录、146 条信号、`判定分布 J1= 1 J2= 23 J3= 22 J4= 15`；脚本二没有这样的单次全集，48 个码分布在 11 次带信号的实跑里，最全的一次 `S2-04` 也只打 35 个。所以第 23.4 节又加了十二个定向子集（`V_A03`→`A03`、`V_C03`→`C03`、`V_Q02`→`Q02` 等），每个子集只保留一类记录，证明这些码在没有别的记录同框时也能触发；`A01`／`A02`／`A05` 与四条退出码 2 的路径则由 `S1-19`、P16 与三条用法错误单独钉住。判据**对不对**，靠的是第 21.4、22.4 两节逐族给出的判据行号与出处行号，读者要拿归档自己核；覆盖验收不代替这一步，第 23.5 节第一条写的也是这句话。

**问：夹具能不能换成真实台账或真实卷上的读数？**
不能，换进来的那一刻这套验收就失效了。台账侧的拒收执行点是 `A05`：空值（第 128 行）与 `dirty()` 命中（第 129 行）都直接拒收该字段。`dirty()` 的四条判据写死在第 82—88 行——以 `/private/`、`/System/`、`/Volumes/`、`/Users/`、`$HOME/`、`~/` 开头的路径形态；含 `glpat-`、`ghp_`、`gho_`、`xox[baprs]-`、`AKIA…`、`Bearer `、`-----BEGIN` 之一的凭据形态；超过 160 字符；80 字符以上的 Base64 形状。脚本二那一侧对应的是三个分流分支的行首（第 93、97、101 行）：格式不符或 `dirty()` 命中的行计入 `badline` 并跳过，P17 用一行 `/Users/x/secret,volume,1` 演示了这条路径，输出 `跳过格式不符行: 1`、`三件合计面数= 12`、退出码仍是 0。**一支脚本拒收、另一支跳过，都不静默接受**；但两支都只能保证「登记里没有形似设备路径与凭据的取值」，保证不了「登记与某台设备一致」。真实台账进来后第一件要做的事是洗数据，洗完的留档也不能再随文发布——`matrix-out.txt` 与第 23.1 节全量输出的价值，恰恰在于第三方能在无设备、无私有数据的条件下原样重跑。

**问：必备格缺失是不是一律 J4？**
不是。第 21.2 节那张分派表就是为纠正这个误读写的：缺 `id.url_kind` 发 `A07`、缺 `id.source_kind` 发 `Q02`、缺 `id.evidence_level` 发 `Q01`、缺任一 `vol.*` 发 `C01`、缺 `key.scope` 或 `key.keybag_class` 发 `K01`，这五类按第 19.1 节的阻断集合落 J4；缺 `cap.kind` 发 `E03`，落 J3；缺任一 `mnt.*`／`umn.*` 发 `H01`，缺 `adv.component` 发 `Q06`，两者都只落 J2。差别来自「这一格能不能在别处补」：卷结构、证据级与密钥栈的缺格会让整条记录失去主语，所以阻断；容量类的缺格让结论失去分母，所以是错误；挂载／卸载读数与公告组件名可以在相邻记录或公告侧补，所以只是警告。`S1-08`（只有 `H01`）、`S1-13`（只有 `E04`）、`S1-15`（只有 `K05`）三次都是 `J2= 1` 而退出码 0；而 `S1-19` 的 `A01`＋`A02` 虽然一条完整记录都没有、判定分布四档全 0，退出码仍是 1——`blkcount` 被单独计入退出表达式（第 306 行），格式破坏不会因为「没有记录」而冒充成功。

**问：退出码 2 是什么？能不能拿它当门禁？**
`2` 只判「输入坏了」：参数个数不对或文件不可读。脚本一的两条校验在第 50—53 行，脚本二的三条在第 52—55 行；`-h`／`--help` 给 0，其余按判定给 0 或 1。34 次实跑的分布是脚本一 `0×6、1×10、2×3`、脚本二 `0×2、1×9、2×4`：只出现 0 与 1 说明输入校验那条路径没跑到，只出现 1 说明合格一侧的下界没被证明，三种都出现才说明三条出口被区分开。**不要把 2 读成「发现问题」**：它排在任何判定之前，一批真台账跑出 2 时唯一该做的是先修参数与文件可达性，118 个码一个都没被看过。**也不要把 0 读成「没问题」**：`S1-19` 判定了 0 条记录却因格式破坏退出 1，`S2-08` 有 6 个信号却因面数齐而退出 0——退出码与判定等级是两个维度。

**问：管理面读不到卷形态，是不是等于管理面不能管？**
不是。这是一条**可见性读数**，不是能力读数。第 16.9 节的 216 个纯键名里，`volume`=0、`mount`=0、`removable`=0、`fileprovider`=0、`smb`=0、`webdav`=0、`apfs`=0、`exfat`=0，有命中的只有 `disk`=1、`usb`=2、`external`=4、`media`=1（`C/readings-20.txt:115`）。同时，管理面确实能约束外接介质的访问：`allowFilesUSBDriveAccess`、`allowUSBRestrictedMode` 都在那 216 个键里。两件事不矛盾——管理面能关掉「这类介质能不能接」，读不回「这个卷是什么形态、挂没挂上来」。声明类型侧同样如此：66 项里与盘直接相关的只有 `DiskManagementSettings` 一项，而它 `PLATFORM macOS 15.0 [available]`、用户注册 `N/A`、设备注册 `N/A`（`A/mdm-diskmanagementsettings-M.txt:6、18、19`）；整个管理面唯一能读回的存储加密状态是 macOS 的状态项 `StatusDiskManagementFileVaultEnabled`，一个**设备级**布尔（`A/mdm-status-diskmgmt-filevault-M.txt:5、6、10`）。第 24 章 M08 与第 26 章 U14 说的是同一条边界。

**问：Q1 是不是一个安全评分？**
不是。Q1—Q4 数的是「三件各有几面有读数」，不是「安全性高低」。形态件、挂载件、加密件各四面，面数 ≥3 记 Q1、2 记 Q2、1 记 Q3、0 记 Q4，总判定取三件里最差的一件（第 19.2 节）。一个 Q4 的读数集合可能对应一台完全正常的设备，只是公开面读不到；一个 Q1 的集合也可能对应一台已经被改动的设备，只是三件都写全了。`S2-03` 是最好的反例：三处换算缺口打 7 个信号，但三件的面仍然够，总判定 `Q1`——**信号数与闭合等级不是同一根轴**；`S2-11` 则是另一头，双清单皆空打 12 个信号，三件面数 2／2／3，总判定 `Q2`。把 Q 当评分，会同时误读这两个夹具。

**问：公告里 32 行组件名命中，是不是 32 个文件系统缺陷？**
不是。32 是 `apfs` 8 行、`hfs` 11 行、`corestorage` 13 行的合计（`C/readings-20.txt:4—6`），它回答「组件名里出现了这三个词形几次」；同一批公告的影响句列，`apfs`／`hfs`／`corestorage`／`exfat`／`ntfs`／`ms-dos`／`filesystem`／`volume`／`unmount`／`automount` 的命中**全部是 0**（`:47—52、54—55、57—58`），`file system` 19 行、`mount` 5 行、`disk` 7 行（`:53、56、59`），而这 19 行涉及的 4 个组件名没有一个含形态词。第 20 章的 O1 与 O2 因此必须成对报：O1 = 32/1266 = 2.5%，O2 = 0/1266 = 0%。恶意构造子集里那个 24 行也要先扣减：七对「影响句词形 ≤ 组件名」里只有两对真同名（`apfs<=apfs`、`hfs<=hfs`）、两对同一组件包络（`corestorage`、`libarchive`），`archive` 两次与 `storage` 一次是词形撞车（`C/readings-20.txt:94`，第 24 章 M02）。**只报一个数字即视为 M01。**

**问：十一层、九个命名空间、54 个字段、三件、44 个度量、118 个码，这些数字对得上吗？**
各自管一件事，不能互换，也不能拿格名跨脚本对齐。十一层（L1—L11）是叙述用的归属分解；脚本一的九个命名空间是台账的主语空间，二者**不是一一对应**：L1—L3（容器、形态、能力）共用 `vol` 与 `cap`，L4—L5（挂载、卸载）用 `mnt` 与 `umn`，L6 用 `cap`，L7 用 `key`，L8 用 `id` 与 `doc`，L9 用 `mgmt`，L10 用 `adv`，L11 用 `doc`。九个空间共 54 个字段（id 4、vol 10、mnt 10、umn 4、cap 5、key 9、mgmt 3、adv 5、doc 4），其中 20 个必备。脚本二的主语是另一切法：三件（形态／挂载／加密）、每件 20 项核对项中的一部分、共 44 个度量——17 个可由两份清单派生，27 个必须出现在 `readings.tsv` 里，缺一个即退出 2。118 则是两支脚本的码总数（66＋52），与第 22.4 节的五族 48 个信号码、第 21.4 节的七族 62 个信号码逐项相等。**最容易串的是 `H` 族与第 24 章的 `M01—M12`**：第 21.4 节末尾专门写过这次改名，脚本一的挂载族是 `H01—H12`，误区的 `M` 只指误区。

**问：我改了某条判据，怎么知道有没有改坏？看总信号数吗？**
不看总数，看第 23.2、23.3 两张逐次表里哪一段该变色、它确实变色了。十二个定向子集就是为此存在的：`V_A03` 只该出 `A03`，`V_C03` 只该出 `C03`，`V_D02` 只该出 `D02`＋`H01`，`V_Q02` 只该出 `Q02` 并落 `J4=1`；改 `C03` 的判据却让 `V_C05` 或 `S1-03` 的码数变了，说明改动越过了族界。改完按三步重跑：`bash matrix.sh` 重生成 `matrix-out.txt`（34 行逐次读数与末四行汇总），`bash volume-form-proof.sh 报告.md` 重跑 P1—P20 并看 P18 三行是否仍为「一致」，最后数一遍 `62/62` 与 `48/48` 是否仍在。**这三步都不接触设备**，第三步还会顺带核对两支脚本自身在运行前后没有被改写（P19）。

## 26. 未公开文档化边界清单

本章列十四条边界。收条标准三条，缺一条就不收：

- **（a）有一句公开原文**——给出归档文件与行号，能读出「这里有一层」或「这里什么都没有」；
- **（b）有一个落点**——脚本码、必填读数或可复跑的读数行，能把这条边界写进台账；
- **（c）有一句「不能由此推出什么」**——而且这句能指回（a）的原文，不是修辞。

编号用 U01—U14，不补位、不隔号。**U 不是脚本族**：脚本一的信号族是 A／C／D／E／H／K 加 Q1—Q4，脚本二的是 F／V／W／X／Z 加 Q1—Q4；U 只在本章使用。凡 U 与码同段出现，码带脚本来源，不写成「U 族」。

| 号 | 边界一句话 | 公开锚点 | 落点 |
| --- | --- | --- | --- |
| U01 | 系统卷 seal 有定义、有校验主语，但接口词表没有 seal 读数 | `B/apple-platform-security-guide.txt:1122、1128、1129`；`A/foundation_urlresourcekey_all.txt` 中 `seal` 0 行 | `C03`／`C04`／`C05`／`C06`；`psg_seal` 只作必填读数 |
| U02 | `subtype` 与 `type_name` 只给名称，不给取值域；八个 `FSOK` 值是本文自己的归一 | `A/foundation_urlresourcekey_all.txt:908、1095` | `D01`／`D05`／`D11` |
| U03 | 卸载侧只有两个选项成员，但公开标识符有五个；「选项数」与「标识符数」不能互换 | `A/dev_filemanager_unmountoptions_S.txt:54、57、62、70、73、78` | `A08`／`H10`／`W08` |
| U04 | 公开语料只说「启动链在 mount 之前校验」，不说运行时由哪个进程挂载 | `B/apple-platform-security-guide.txt:772、1128、1129` | `H03`／`H04`／`W01`／`W05` |
| U05 | 四个 rename／lock 键是文件操作能力，不是卷的锁状态 | `A/foundation_urlresourcekey_all.txt:930、965、1031、1057` | `D02`／`D11`（无专用码） |
| U06 | 快照在 APFS 文档里有角色，在接口词表里不是卷角色 | `A/security_role_of_apfs-S.txt:257`；`B/apple-platform-security-guide.txt:1120` | `C06`／`E06` |
| U07 | 改密码重包类密钥、作废一次性解锁令牌，不等于重写文件数据 | `B/apple-platform-security-guide.txt:355、1925、1979、2007` | `K02`／`K07` |
| U08 | 五个 keybag 各有结构，备份 keybag 是新密钥集，托管 keybag 是同组类密钥加新保护密钥 | `B/apple-platform-security-guide.txt:1976、1996、2006、2016` | `K03`／`K04`／`X10` |
| U09 | FileProvider 域有卷 UUID 与后备存储标识，但读不回卷形态 | `A/fileprovider_nsfileproviderdomain_volumeUUID.txt:4、16`；`…_backingStoreIdentity.txt:3、18` | `D11`／`Z12` |
| U10 | `EligibilityResult` 只给类型名，归档页不枚举取值 | `A/fileprovider_nsfileprovidermanager_checkDomainsCanBeStoredOnVolume.txt:3、45` | 无专用码；`Z12` 与 `fp_ext_volume_*` |
| U11 | `userEnabled` 的原文是 macOS 的 System Preferences，iOS 不能逐字照搬 | `A/fileprovider_nsfileproviderdomain_userEnabled.txt:3、18` | 无专用码 |
| U12 | iOS 外接存储要求单一数据分区，但接口没有分区计数键 | `A/iphone_external_storage-S.txt:1154`；`A/dev_filemanager_volumeenumerationoptions_S.txt:67、76` | `V08`／`Z11` |
| U13 | KEV 的 0 命中是归因词形未覆盖，不是风险为零 | `C/readings-20.txt:100、101` | `Z07`／`W04` |
| U14 | 管理面唯一的存储加密读数是一个 macOS 设备级布尔 | `A/mdm-status-diskmgmt-filevault-M.txt:5、6、10`；`A/mdm-diskmanagementsettings-M.txt:5、6、18、19` | `K01`／`F06`／`X06` |

### 26.1 十四条边界逐条

**U01 系统卷 seal：有定义，没有接口读数。**
平台安全指南把 `seal` 写成 Merkle 树的根哈希：`the root node’s hash value, called a seal, encompasses every byte of data in the SSV`（`B/apple-platform-security-guide.txt:1122`）。校验主语也写得很清楚：Apple silicon 上 `the bootloader verifies the seal before transferring control to the kernel`，Intel T2 上 `the bootloader forwards the measurement and signature to the kernel, which then verifies the seal directly before mounting the root file system`（`:1128`）；iOS／iPadOS 上 `The iOS and iPadOS bootloaders verify that the seal is intact and that it matches an Apple-signed value before allowing the device to start the kernel`（`:1129`）。cryptex 则是 `cryptographically sealed disk images that reside on the preboot volume`（`:1174`）。

但接口词表里没有这一格：131 个 `URLResourceKey` 标识符中，`seal` 出现 **0 次**（`A/foundation_urlresourcekey_all.txt` 全文）。公告侧同样读不回：组件名列里 `cryptex` 有 3 行、`preboot` 0 行、`snapshot` 0 行（`C/readings-20.txt:36—38`），影响句列对这三个词形**全部 0 行**（`:79—81`）。

脚本一能拦四类内部矛盾：系统卷写 `seal=no`（`C03`，第 169 行）、cryptex 不指向 preboot（`C04`，第 171 行）、cryptex 找不到对应 preboot 卷（`C05`，第 279 行）、快照容量记到错误卷角色（`C06`，第 181 行）。要说明一处：`psg_seal` 与 `psg_cryptex` 是脚本二的**必填读数**（第 78—87 行的 `REQUIRED`），但**没有任何信号码、也没有任何面公式使用它们**——它们只负责让「缺度量」以退出码 2 暴露，不参与判定。换句话说，台账能检查「你有没有声称 seal 通过」的前后一致，**不能检查「seal 是否真的通过」**。

不能由此推出：用户数据卷的完整性；某个已挂载卷「通过了 seal 校验」；或者「系统卷可信所以数据卷也可信」。原文的主语是启动路径上的系统卷，而且校验发生在内核启动之前。

**U02 `subtype` 与 `type_name`：只有名称，没有取值域。**
`volumeSubtypeKey` 的说明只有一句 `The key for the file system subtype value`（`A/foundation_urlresourcekey_all.txt:908`），`volumeTypeNameKey` 只有一句 `The key for the name of the file system type`（`:1095`，单页 `A/foundation_urlresourcekey_volumeTypeNameKey.txt:3`）。两页都没有列出合法值，也没有给出两者之间的换算。

脚本一的 `FSOK` 八个取值（`APFS`、`APFS (Encrypted)`、`HFS+`、`ExFAT`、`FAT32`、`NTFS`、`MS-DOS (FAT)`、`unknown`，第 30 行）是**本文自己的归一**，来源是用户指南的外接存储白名单（`A/iphone_external_storage-S.txt:1154`）与两页键说明，不是某个 API 的枚举。`typeForm()`（脚本一第 72—81 行）把 `APFS (Encrypted)` 折回 `APFS` 再比对，也是本文的写法。

三个码分工不同：`D05` 拦「有 `subtype` 无 `type_name`，把子类型当形态」（第 203 行，J2）；`D01` 拦 `fs_form` 越界（第 194 行，J3）；`D11` 拦「没有任何形态读数却断言形态」（第 213 行，J3）。三者的共同前提是：**本报告先定义了八个取值**，读者若换一套取值，必须先换 `FSOK` 与 `typeForm()`，否则码会全部错位。

不能由此推出：`subtype=xx` 就是 APFS；`type_name` 是一个安全属性；或者八个取值与 Apple 的某个内部枚举一一对应。

**U03 卸载侧：两个选项，五个标识符。**
`UnmountOptions` 页只有两个选项成员：`allPartitionsAndEjectDisk`（说明 `:54`、成员名 `:57`、ObjC 名 `:62`）与 `withoutUI`（说明 `:70`、成员名 `:73`、ObjC 名 `:78`），加一个方法 `unmountVolume(at:options:completionHandler:)`（`:3`）。这就是**两个选项、五个公开标识符**——本文的 `unmount_options` 读数是**标识符计数**（夹具取 5），`W08` 的阈值 5 判的是「这一页的选项面是否完整」，不是「有五个不同选项」。两个数不能互换，这正是第 3 章 F 族要处理的换算问题的一个小样本。

挂载侧同样要分开读：`mountedVolumeURLs(includingResourceValuesForKeys:options:)` 返回 `an array of URLs that identify the mounted volumes available on the device`（`A/dev_filemanager_mountedvolumeurlsincludingresourcevaluesforkeysoptions_S.txt:3`）；枚举选项有 `produceFileReferenceURLs`（说明 `A/dev_filemanager_volumeenumerationoptions_S.txt:67`、标识符 `:70`）与 `skipHiddenVolumes`（说明 `:76`、标识符 `:79`）。`A08` 拦 `url_kind` 越界或同一声称对象身份冲突（脚本一第 158、162 行，J4）；`H10` 拦「外接卷断开被写成弹出并重锁」（第 268 行，J2）。

不能由此推出：URL 列表能说明「谁挂载了这个卷」；`skipHiddenVolumes=1` 说明隐藏卷不存在；或者两个选项加上方法就等于「卸载语义已经闭合」。

**U04 挂载主体：公开语料只写到校验，不写到进程。**
指南里唯一把挂载与完整性写在同一句的地方是：`iBoot is also responsible for verifying the root hash for the signed system volume (SSV), to check that the file system the kernel will mount is fully integrity verified`（`B/apple-platform-security-guide.txt:772`）。前半句的主语是 iBoot，后半句的宾语是「内核将要挂载的那个文件系统」；两句都没有说运行时是哪个进程执行了 mount。`:1128` 与 `:1129` 只是把 macOS 与 iOS 的校验顺序分开，仍然停在「mount 之前」。

接口词表没有「挂载主体」这一格。脚本一的 `mnt.actor` 只有一个合法值 `unknown`（第 30 行）；写入任何已知进程名即触发 `H03`（第 255 行，J3）。网络卷还要登记 remount 范围，缺了触发 `H04`（第 256 行，J2）。脚本二从另外两个面复核：`mount_semantic=0` 触发 `W01`（第 163 行），`mdm_mount_keys=0` 触发 `W05`（第 167 行），两个读数在本文语料上都是 0（`C/readings-20.txt:115`）。

不能由此推出：`diskarbitrationd` 或任何具体进程挂载了这个卷；「iBoot 校验过」等于「运行时挂载可信」；或者管理面知道挂载主体。

**U05 四个 rename／lock 键：能力，不是状态。**
`volumeSupportsAdvisoryFileLockingKey`（`:930`）说明卷「implements whole-file advisory locks in the style of flock」；`volumeSupportsExclusiveRenamingKey`（`:965`）说明能用独占重命名；`volumeSupportsRenamingKey`（`:1031`）说明卷「can be renamed」；`volumeSupportsSwapRenamingKey`（`:1057`）说明支持交换重命名。四条都是**文件系统实现了什么操作**，没有一条说「这个卷现在是锁定的」。

平台安全指南里 `advisory` 与 `file lock` 各 **0 行**；`renam` 只有 1 行，还是 Apple Configurator「rename and change wallpaper on devices」（`B/apple-platform-security-guide.txt:4611`），与文件系统无关。公告归档里 `advisory` 与 `file lock` 也都是 0 行（`C/advisory-20.tsv`）。这四把键没有专用码；最接近的两条误读由 `D02`（把 `supports=1` 写成 `mount.state=1`，脚本一第 195 行，J3）与 `D11`（无形态读数却断言形态，第 213 行，J3）拦住。

不能由此推出：卷被锁定；重命名被策略禁止；或者 `supportsAdvisoryFileLocking=1` 意味着强制锁已经生效。

**U06 快照：APFS 文档里有角色，接口词表里不是卷角色。**
`On devices with macOS 11 or later, the system volume is captured in a snapshot. The operating system boots from a snapshot of the system volume, not just from a read-only mount of the mutable system volume`（`A/security_role_of_apfs-S.txt:257`）。指南侧只说 SSV 用 APFS 快照回滚更新（`B/apple-platform-security-guide.txt:1120`）。这两句都是 macOS 语境的系统卷，不能平移到 iOS 的任意卷。

公告侧 `snapshot` 在组件名列 0 行（`C/readings-20.txt:38`）、影响句列 0 行（`:81`）。脚本一的 `vol.role` 九个取值里**没有 snapshot**，而 `cap.kind` 五个取值里**有 snapshot**（第 30 行）——快照是容量的一种记法，不是卷的一个角色。`C06` 拦「快照容量记录的卷角色不对」（第 181 行，J2），`E06` 拦「快照容量被计入卷容量」（第 223 行，J2）。

不能由此推出：启动的系统卷就是可变的那个；快照是一个独立卷、有独立空闲空间；或者 iOS 的每个卷都有快照。

**U07 改密码：重包类密钥，不重写文件。**
指南把「Passcode change」列进防重放边界：`Anti-replay services … revocation of data over events that mark anti-replay boundaries including, but not limited to, the following: • Passcode change`（`B/apple-platform-security-guide.txt:354—355`）。同一份指南又写：`a change of passcode just rewraps the class key`（`:1925`）——原文的完整条件是类密钥「protected with the hardware UID and, for some classes, the user’s passcode」，所以这句话只覆盖「受密码保护的那些类」。再往下，A9 以前的 keybag 加密密钥 `is wiped and regenerated each time a user changes their passcode`（`:1979`）；A9 以后 keybag 放进由 Secure Enclave 防重放值保护的 locker（`:1980`）；OTA 更新的一次性解锁令牌 `any previously generated token is invalidated if the user’s passcode changed`（`:2007`）。

脚本一拦两类混淆：`K02` 把 class 键与 per-file／extent 键混用（第 229 行，J2）；`K07` 把 per-file 与 per-extent 混用（第 237 行，J3）。

不能由此推出：改密码会重写全部文件数据；所有保护类都受影响；或者改密码等于抹除设备。

**U08 五个 keybag：结构可读，归属不可推。**
`These operating systems use the following keybags: user, device, backup, escrow, and iCloud Backup`（`B/apple-platform-security-guide.txt:1976`）。备份 keybag 是**新密钥集**：`A new keybag is created with a new set of keys, and the backed-up data is reencrypted to these new keys`（`:1996`），口令经 1000 万次 PBKDF2（`:1997`）。托管 keybag 是**同一组类密钥加新保护密钥再拆分**：`containing the same class keys used on the device, protected by a newly generated key. The escrow keybag and the key protecting it are split between the device and the host or server`（`:2006`）。iCloud 备份 keybag 用 Curve25519 非对称密钥（`:2016`）。

脚本一的三个码分别拦「keybag 未写保护类」（`K03`，第 230 行，J3）、「托管／云备份 keybag 结构被当作一二级证据」（`K04`，第 232 行，J4）、「keybag 名称可读而结构不可读」（脚本二 `X10`，第 185 行）。

不能由此推出：备份 keybag 装着与设备相同的密钥；托管 keybag 是用户 keybag 的副本；或者五个名字对应五份可独立读出的密钥材料。

**U09 FileProvider 域：有卷标识，没有卷形态。**
`volumeUUID` 的说明是 `A universally unique value to identify types, interfaces, and other items`（`A/fileprovider_nsfileproviderdomain_volumeUUID.txt:16`），这是一句**通用** UUID 说明，不是卷形态说明；声明在 `:4`。`backingStoreIdentity` 说明「系统用来标识后备存储」并在讨论里写：标识变化表示系统丢弃了旧后备存储、正在建新的（`…_backingStoreIdentity.txt:3、18`）。`isDisconnected` 说明域仍在、但与扩展断开，用户仍可浏览，扩展不再收发修改（`…_isDisconnected.txt:3、18`）。

脚本一的 `D11` 拦「无形态读数却断言形态」（第 213 行，J3）；脚本二的 `Z12` 记「FileProvider 外接卷实体命名存在而成员面不可读」（第 208 行）。

不能由此推出：`volumeUUID` 能说明卷的格式；`backingStoreIdentity` 变化等于卷被重新挂载；`isDisconnected` 等于卷被卸载。

**U10 `EligibilityResult`：有类型名，没有取值表。**
`checkDomainsCanBeStoredOnVolume(at:)` 的摘要是 `Checks whether the specified URL is eligible for storing a domain`（`A/fileprovider_nsfileprovidermanager_checkDomainsCanBeStoredOnVolume.txt:3`），返回类型说明是 `Constants that specify whether a URL is eligible for storing a domain`（`:45`）。但归档页**没有枚举这些常量**，只给出类型名。所以读者能知道「有一个资格判定」，不能知道「哪几种资格」。

这一条没有专用码；相关的只有脚本二的两项 FileProvider 读数（`fp_ext_volume_handling`、`fp_ext_volume_members`）与回查码 `Z12`（第 208 行）。

不能由此推出：「eligible」等于 APFS 或内置卷；资格判定在检查卷的安全形态；或者返回类型名就等于拿到了取值域。

**U11 `userEnabled`：原文是 macOS 的界面。**
`A Boolean value that indicates whether the user has enabled or disabled the domain`（`A/fileprovider_nsfileproviderdomain_userEnabled.txt:3`）；讨论里写 `If the user disables the domain in the System Preferences, the property is …`（`:18`）。`System Preferences` 是 macOS 的名称，iOS 的对应界面不叫这个名字。把这条读数平移到 iOS 时，至少要说明「界面名称不同、开关语义未必相同」。

这一条没有专用码。它影响的是台账里「远端域是否启用」这一格的**证据级**：一条 macOS 原文只能给 macOS 侧的一级证据，不能当作 iOS 侧的一级证据。

不能由此推出：用户的启用／停用状态等于卷的挂载状态；或者 `userEnabled=false` 说明扩展没有运行。

**U12 单一数据分区：要求可读，计数不可读。**
用户指南写：`An external storage device must have only a single data partition, and it must be formatted as APFS, APFS (encrypted), macOS Extended (HFS+), exFAT (FAT64), FAT32, or FAT`（`A/iphone_external_storage-S.txt:1154`）。这是**格式化要求**，不是接口枚举；接口侧只有枚举选项 `produceFileReferenceURLs`（`A/dev_filemanager_volumeenumerationoptions_S.txt:67`）与 `skipHiddenVolumes`（`:76`），没有「分区计数」这一格。

脚本二用两个码记这条缺口：`V08` 判「白名单要求单一分区，而键清单里没有分区计数键」（第 160 行），`Z11` 判「单一分区要求没有接口读回」（第 206 行）。两者都非阻断，因为它们记的是**可见性缺口**，不是台账错误。

不能由此推出：iOS 会因为 Mac 能挂多分区就挂多分区；白名单是 API 枚举；或者「只有一个数据分区」能从某个 URL 列表数出来。

**U13 KEV 的 0 命中：未覆盖，不是无风险。**
在野清单里 Apple 条目 95 条，形态词形的命中是 `icloud=1`、`media=1`、`sandbox=3`、`storage=1`、`usb=1`（`C/readings-20.txt:100`）；`volume`、`mount`、`file system`、`APFS` 四个词形在 KEV 里是 **0 条**（`:101`）。这四个 0 只说明**归因词形没有覆盖到 KEV 的写法**，不说明文件系统类缺陷没有在野利用。

脚本二用 `Z07`（第 200 行，阻断）与 `W04`（第 166 行）分别从回查面与挂载面记这条零命中。`Z07` 阻断的含义是「归因链断了」，不是「发现了在野利用」。

不能由此推出：没有在野的文件系统缺陷；或者 KEV 的 0 命中能反证公告的 32 行不重要。

**U14 管理面的存储加密：一个 macOS 设备级布尔。**
状态项 `StatusDiskManagementFileVaultEnabled` 的摘要是 `The status item that reports whether FileVault is enabled`（`A/mdm-status-diskmgmt-filevault-M.txt:5`），平台 `macOS 14.0 [available]`（`:6`），属性是一个必填布尔 `diskmanagement.filevault.enabled`（`:10`）。声明 `DiskManagementSettings` 的平台是 `macOS 15.0 [available]`（`A/mdm-diskmanagementsettings-M.txt:6`），设备注册与用户注册都是 `N/A`（`:18、19`）。

脚本一的 `K01` 在 `key.scope` 或 `key.keybag_class` 缺失时阻断（第 149、228 行，J4）——这个设备级布尔**填不了** `key.scope` 这一格，留空就是阻断，不能拿它冒充卷级密钥范围。脚本二的 `F06` 记「管理面有设备级加密整数而接口无卷级加密键」（第 144 行），`X06` 记「管理面无加密能力读数」（第 178 行，阻断）。

不能由此推出：`FileVault enabled=true` 说明某个卷的保护类或密钥范围；这个布尔覆盖 iOS 卷；或者管理面能读回卷级加密状态。

### 26.2 三份输入件怎么承载这十四条

十四条边界不是十四份新输入，而是现有输入里**缺失或不可换算**的位置。按脚本二的三个输入件与脚本一的台账分开看：

| 输入件 | 能承载的 U | 承载方式 | 不能承载的 |
| --- | --- | --- | --- |
| `keys.tsv`（词形计数） | U02、U05、U06 | `volume`／`supports`／`is`／`semantic` 四组的计数；`partition` 这类族外行用于 `V08`／`Z11` | 键的取值域、卷的实际状态 |
| `statements.tsv`（语句主题计数） | U01、U04、U07、U08、U09、U10、U11、U12、U14 | `psg`／`guide`／`fileprovider` 三个来源的主题计数；缺一个主题就少一面 | 语句的主语是不是当前平台、是不是当前卷 |
| `readings.tsv`（44 个度量） | U01、U03、U13、U14 | 27 个不可派生度量必须出现；`unmount_options` 与 `psg_seal` 都在其中 | 度量背后的语义；读数之间的换算 |
| 脚本一 54 字段台账 | U02、U04、U05、U06、U09 | 每格一个字段，20 个必备 | 公开面没有的格；跨平台平移的格 |

这张表要说明一件事：**同一句话可以在三个输入件里出现三次，但三次回答的是不同问题**。例如 U01 的 `seal`：`keys.tsv` 回答「接口词表有没有这个键」（0），`statements.tsv` 回答「指南有没有这个主题」（有），`readings.tsv` 回答「这批语料里这个主题被数到几次」（必填，但不过门）。三份都齐，也不等于「这个卷的 seal 通过了」。

### 26.3 两条固定自查项

**自查一：每条 U 必须有一处原文锚点与一句「不能由此推出」。**
只有「不能由此推出」而没有原文的，是意见；只有原文而没有「不能推出」的，是摘抄。两条都在，才是一条边界。检查方法很笨但有效：把该 U 段落里的 `A/`、`B/`、`C/` 行号逐个用 `sed -n` 打开，确认原文能读出这句判断；再把「不能由此推出」那句读一遍，确认它没有偷偷加上原文没有的主语（尤其是把 macOS 的主语换成 iOS、把系统卷换成数据卷、把设备级换成卷级）。

**自查二：每个码的等级必须与 `emit()` 的分派一致。**
脚本一的阻断集合是 `^(A0[1-8]|Q0[124]|K0[146]|C01)$`，错误集合是 `^(C0[357]|D0[124679]|D1[12]|E0[135]|H0[2389]|K0[378])$`，其余落 J2（第 59—65 行）；脚本二的阻断集合是 `^(F0[578]|X0[2369]|Z0[178])$`（第 61—66 行），其余只计信号、不阻断。写「某码落 J3」之前，先在 `emit()` 里对一遍；写「某码阻断」之前，先在 `blkcount` 那一行对一遍。等级写错，U 的「落点」就错了，哪怕正文说得对。

### 26.4 用法与改法

- **新增一条 U**：先过（a）（b）（c）三条；没有专用码就写「无专用码」，并指出最近的那条检查。不要把 U 直接变成脚本族——脚本一、二的族字母已经被 118 个码占满，新增族会让覆盖计数与第 23 章的三张表全部失效。
- **改一条码的等级**：同时改 26.1、第 21.2 或 22.4 的族表与 `emit()`；然后 `bash matrix.sh` 重生成 34 行读数，确认 `62/62` 与 `48/48` 没有被破坏；再 `bash volume-form-proof.sh 报告.md` 看 P18 三行是否仍为「一致」。
- **撤回一条 U**：不重编号，写「Uxx 已撤回」与理由，保留号码，避免所有交叉引用错位。十四条的编号本身就是一份稳定引用表。
- **换一份语料**：先重跑第 16 章的十三组读数，再重跑两支脚本；读数变了而码没变，说明码绑在结构上；码变了而读数没变，说明码绑在措辞上——这两种情况要分开记，不要合成一句「结果有变化」。

## 27. 结论

### 27.1 立场：能说什么，不能说什么，该记成什么

**能说的三句。** 第一，卷的**形态**、卷的**挂载**与卷的**密钥栈**是三个判定权分属三方的格子：形态在 `URLResourceKey` 词表手里，挂在 `FileManager` 与启动链手里，密钥在 Secure Enclave、UID 与 Data Protection 类手里（第 3—14 章）。第二，这三方在公开语料上**没有一张统一换算表**：八处换算失败 F01—F08 就是八条不存在的换算（第 22.3 节）。第三，iOS 侧的管理面对「形态」与「挂载」两格是**读不回**的：216 个纯键名里 `volume`、`mount`、`removable`、`fileprovider`、`smb`、`webdav`、`apfs`、`exfat` 全部 0 命中（`C/readings-20.txt:115`），声明类型 66 项里与盘有关的只有一项 macOS 15.0 声明（`A/mdm-diskmanagementsettings-M.txt:6、18、19`）。

**不能说的五句。** 不能说「APFS 所以安全」；不能说「`volumeSupportsFileProtection=1` 所以这个卷上的文件受保护」；不能说「管理面能读回 iOS 的卷形态」；不能说「`FileVault enabled=true` 覆盖 iOS 卷」；不能说「公告组件名列 32 行等于 32 个文件系统缺陷」。这五句分别被 M05、M08、M03、U14、M01 挡住，挡它们的不是观点，是行号。

**该记成什么。** 每一格记四件事：**角色**（这个卷在这台设备上干什么）、**形态**（公开面读到什么格式）、**密钥范围**（卷键、类键、文件键、区段键，读到哪一级）、**证据级**（一级接口定义、二级平台文档、三级公告、四级推断）。四件事里缺一件就写 `unknown`，并在相邻格写清缺的原因。`unknown` 是一个值，不是空白；空白会让下一位读者以为「没查」，`unknown` 会让他知道「查过，公开面没有」。

### 27.2 方法论：四步

1. **先把三套词表分开列。** 接口词表（131 个 URLResourceKey）、平台安全口径（指南里 volume／mount／APFS／cryptex 的 99 行）、管理面与公告回查口径（216 个键名、66 项声明、1266 行公告、95 条 KEV）。三套词表各自成表，不先做合并；合并发生在第 3 章的八处换算失败里，而且以「失败」的形式记录，不以「等价」的形式记录。
2. **一格一字段，能导出的才导出。** 脚本一把台账拆成 9 个命名空间、54 个字段、20 个必备；脚本二把读数拆成 44 个度量、17 个可派生、27 个必须显式给出。`D12`（形态读数缺行号）与 `A05`（空值或拒收取值）是两条机器检查，专门防止「看起来填了、其实没填」。
3. **用码和实跑把判定钉住。** 118 个码（62＋4＋48＋4）、34 次实跑（19＋15）、`62/62` 与 `48/48` 的覆盖验收、退出码 0／1／2 的三条出口。码回答「哪一格不成立」，实跑回答「这条码有没有被走到」，覆盖计数回答「有没有漏掉整族」。
4. **用边界清单止住过度解读。** 第 26 章的十四条 U 不是新结论，是十四句「到这里为止」。每写一条归属结论，先问它有没有越过某条 U；越过了，就把结论降回那一格。

### 27.3 三条建议

- **给每个卷格写「角色＋形态＋密钥范围＋证据级」四件事，缺一件写 `unknown` 并写原因。** 不要用「安全／不安全」二值替代这四件事；二值会把「读不到」误记成「没问题」。
- **系统版本更新后重跑三件差集，并把差集留档，不要沿用旧读数。** 第 22 章的输入是三份表，任何一份随版本变化，`F01—F08` 与三件面数都会变；旧读数直接搬过来，等于把上一版的结论贴到这一版上。
- **公告口径与管理面口径分开跑、分开存，不要取交集，也不要跨平台相加。** 组件名列的 32 行与影响句列的 0 行是两个口径（M01）；`DiskManagementSettings` 的 macOS 15.0 可用性与 iOS 的挂载问题是两个平台（M08）；KEV 的 0 命中是归因词形未覆盖（M03）。交集会把「没覆盖」洗成「没有」，相加会把「两个平台的各一半」洗成「一个平台的全量」。

**一句话收尾：卷的形态是可以读的，卷的归属不是；把读不到的那一格写成 `unknown`，比补一个看起来完整的结论更接近事实。**

## 28. 参考资料

### 28.1 归档总览

本篇的每一个行号都指向本轮建立并留档的公开语料归档 `.srcx20/`，不是指向网络上的当前页面。归档按「原始响应—去标签文本—读数—工具—夹具—索引」分成七组，另有三份抓取清单；下表的行数是物理行数（`wc -l`），字节数是文件字节数，同一句长段落在归档里占一行，所以行数不能当作句子数使用。

| 组 | 文件数 | 字节 | 行数 | 内容 |
| --- | --- | --- | --- | --- |
| `A/` | 141 | 1,175,877 | 35,601 | 接口与平台文档的去标签文本，正文引用的一级锚点 |
| `B/` | 3 | 756,290 | 6,635 | Apple Platform Security 指南全文与两份管理面限制项文本 |
| `C/` | 6 | 325,331 | 1,597 | 公告表、KEV 表、声明类型清单与十三组读数 `readings-20.txt` |
| `RAW/` | 141 | 21,927,287 | 245,875 | `A/` 各页对应的原始 JSON 响应，只用于复核文本抽取 |
| `tools/` | 23 | 91,267 | 1,932 | 抓取、抽取、读数、矩阵与三支只读脚本及其实跑输出 |
| `fx/` | 16 | 41,358 | 1,707 | 两支脚本的 bad／good／边界夹具，逐码触发用 |
| `IDX/` | 14 | 73,282 | 989 | 键名词表、个案表、公告批次表与跨篇重叠索引 |
| **合计** | **344** | **24,390,692** | **294,336** | 七组小计 |

三份抓取清单都在归档根目录：`MANIFEST-A2.txt`（107 行、18,181 字节）、`MANIFEST-A3.txt`（26 行、3,928 字节）、`MANIFEST-B2.txt`（37 行、5,006 字节），逐条记录 HTTP 状态码、字节数与落盘文件名；被拒或跳过的条目留在清单里，不删行——`mdm` 根路径 `404` 与 `SKIPPED` 就是一条留在 `MANIFEST-B2.txt` 里的记录。加上这三份清单，归档共 347 个文件、24,417,807 字节。

### 28.2 关键文件与锚点

正文引用最多的是下面这些文件。表中锚点全部是本归档内的物理行号；同名文件在不同篇目的归档里行号不同，不能互换。

| 文件 | 规模 | 用途 | 关键锚点 |
| --- | --- | --- | --- |
| `A/foundation_urlresourcekey_all.txt` | 131 个标识符 | 形态词表全集 | `:3` 自述 `Keys that apply to file system URLs`；`:756—1124` 47 个 volume 键逐个可定位 |
| `A/dev_about_apple_file_system-S.txt` | APFS 开发者口径 | 形态与容器结构 | `:5` 取代 HFS Plus；`:18` 单分区多卷；`:19`、`:22` 共享空闲空间与「按卷求和不可靠」 |
| `A/security_role_of_apfs-S.txt` | 平台安全口径 | 设计目标与容器硬读数 | `:239` 以加密为设计目的；`:243` 启动容器至少五卷、前三对用户隐藏；`:257` 系统卷从快照启动 |
| `A/security_data_protection_overview-S.txt` | Data Protection 总述 | 密钥粒度 | `:241` 按文件分class、APFS 可细分到区段；`:245` Apple silicon Mac 用卷键 |
| `A/security_data_protection_classes-S.txt` | 四个保护类 | 类键与 UID | `:272` Class D 仅由 UID 保护、存放于 Effaceable Storage |
| `A/dev_filemanager_mountedvolumeurlsincludingresourcevaluesforkeysoptions_S.txt` | 枚举接口 | 挂载面 | `:3` 返回已挂载卷的 URL 数组 |
| `A/dev_filemanager_volumeenumerationoptions_S.txt` | 枚举选项 | 枚举语义 | `:67`、`:70`、`:76`（跳过隐藏卷）、`:79` |
| `A/dev_filemanager_unmountoptions_S.txt` | 两个卸载选项 | 卸载语义 | `:3` 页面口径；`:54` 卸载磁盘上全部分区；`:70` 不伴随 UI |
| `A/dev_filemanager_unmountvolumeatoptionscompletionhandler_S.txt` | 卸载接口 | 重锁时点 | `:72` 加密卷卸载后被重新锁定 |
| `A/mdm-diskmanagementsettings-M.txt` | 唯一与盘有关的声明 | 管理面形态 | `:5` 摘要；`:6` `PLATFORM macOS 15.0`；`:18`、`:19` 两种注册均 `N/A`；`:34` `ExternalStorage: Disallowed` |
| `A/mdm-status-items-M.txt` | 状态项清单 | macOS 侧单一布尔 | `:73` `StatusDiskManagementFileVaultEnabled` |
| `A/mdm-status-diskmgmt-filevault-M.txt` | 状态项页 | 平台限定 | `:5` 摘要；`:6` `PLATFORM macOS 14.0`；`:10` 布尔属性 |
| `A/iphone_external_storage-S.txt` | iPhone 外接存储支持页 | 单一数据分区口径 | `:1154` |
| `B/apple-platform-security-guide.txt` | 4,885 行 | 平台安全指南全文 | `:772` iBoot 校验 SSV 根哈希；`:1120` SSV 使用 APFS 快照；`:1128` T2 侧内核在挂载前校验 seal；`:1131` SSV 与代码签名的保护边界 |
| `B/mdm-restrictions.txt` | 1,530 行 | 限制项正文 | `:1231` 起为 299 行 `CODE|` 段；`:1530` 段结束 |
| `B/mdm-restriction-keys.txt` | 220 行 | 纯键名分母 | 4 行标题加 216 个键名；`volume`／`mount`／`removable`／`fileprovider`／`smb`／`webdav`／`apfs`／`exfat` 零命中 |
| `C/readings-20.txt` | 156 行 | 十三组公开读数 R01—R38 | `:4—6` 组件名列 apfs/hfs/corestorage 8/11/13 行；`:47—51` 影响句列全 0；`:115` 管理面 G8.2 读数；`:150` 131／47／20／10 |
| `C/advisory-20.tsv` | 1,266 条记录 | 公告子集 | 平台、组件名、影响句三列 |
| `C/kev-apple.tsv` | 95 条 | 在野利用目录 | 与公告子集分开统计，不取交集 |
| `C/mdm-declarations.txt` | 66 项声明 | 管理面声明类型 | 与盘有关的只有 `DiskManagementSettings` 一项 |

### 28.3 九条归档约定

1. **原始响应与去标签文本分层存放。** `RAW/` 保留原始 JSON，`A/` 只放抽取后的文本；正文引用一律指 `A/`、`B/`、`C/` 的行号，不指 URL，也不指「当前页面第几段」。
2. **每次抓取都留清单，失败也留。** 三份 `MANIFEST-*` 记录 HTTP 码、字节数与落盘文件名；`404` 与 `SKIPPED` 是读数的一部分，不因为「没抓到」而从清单里删掉。
3. **同名件先逐字节比较再声明复用。** 与既有篇目归档同源的 `B/` 组文件，先 `cmp` 再写「同一版本副本」；没有比较过的文件不写「相同」。
4. **抽取文本保留页面标题行与表格分隔。** 每份 `A/` 文件开头保留 `PAGE-TITLE`／`PAGE-URL`／`ROLE`，表格单元格以 ` | ` 分隔，保证引用能回到原页结构而不是一段无出处的纯文字。
5. **读数只由工具生成。** `C/readings-20.txt` 由 `tools/readings20.pl` 生成，不手改；`C/readings-20.err` 为空，才把这份读数当作正文引用的依据。
6. **改脚本先跑矩阵再改读数。** 任何一支脚本的措辞或阈值变动，先 `bash matrix.sh` 重生成 34 行读数并与旧输出 `diff`；差异能逐条解释才更新读数，不能解释就回退。
7. **行号是归档内坐标，不是跨篇坐标。** 第 18、19 篇也引用 Apple 文档，但它们的归档行号与本篇不同；跨篇引用只借结论与分工，不借行号。
8. **夹具与脚本分离，bad／good 成对。** `fx/` 里每个信号码至少有一份能触发它的 bad 夹具和一份不该触发它的 good 夹具；新增码必须同时补两侧，否则第 23 章的 `62/62` 与 `48/48` 不成立。
9. **归档不写入设备数据。** 没有真实卷标识、没有设备序列号、没有用户目录清单；两支脚本的临时目录分别用 `vol20.` 与 `vft20.` 前缀，退出时清理，这一点由第 23.1 节的二十段实证逐条给出位置。

### 28.4 本篇没有做的事

- **没有做任何设备侧操作**：不枚举真实卷、不挂载、不卸载、不弹出、不读分区表、不构造磁盘镜像、不接触任何被登记的对象；两支脚本的输入只有台账文本、三件清单、能力表与公开词表四类夹具。
- **没有给出任何挂载／卸载／解锁的操作路径**：`UnmountOptions` 的两个成员只作为公开语义读数引用；不给出「无提示卸载」「强制弹出」「绕过重锁」的任何做法，也不把 `allowStartupDiskModification` 一类管理键写成配置建议。
- **没有做密钥抽取或口令处理**：卷键、类键、文件键、区段键只作为「保护粒度在哪一级」的公开口径被引用；不讨论任何解锁材料的取得、保存或恢复。
- **没有把公告侧读数写成 iOS 结论，也没有跨平台相加**：组件名列的 32 行与影响句列的 0 行是两个口径（第 13 章）；`DiskManagementSettings` 的 macOS 15.0 可用性与 iOS 的挂载问题是两个平台（第 12 章）；KEV 的 0 命中是归因词形未覆盖，不是「没有在野利用」。
- **没有引用 XNU／Darwin 开源侧实现、第三方研究博客或 CVE 描述页**：本轮全部来源限于 Apple 文档 JSON、Apple Platform Security 指南文本、Apple 安全发布页与 CISA KEV 官方目录四类。
- **没有重建相邻篇目的客体**：备份副本的可解性归第 11 篇、代码签名授权链归第 14 篇、内容类型判定归第 18 篇、画面外流的落点可见性归第 19 篇、外设配对与近场信任归第 22 篇、平台校验组件与度量物归第 23 篇（逐条分界见第 2.1 节与 `IDX/` 下的重叠索引）。

### 28.5 同系列相邻篇目

本篇与已发布的五篇、队列中的两篇有交接，也有硬分界。**第 02 篇（访问控制与应用交互）**——授权与权限判定归它；本篇只在 `volumeSupportsAccessPermissionsKey` 与 `volumeSupportsExtendedSecurityKey` 两个键上取「这个卷能不能承载 POSIX 权限与 ACL」的形态读数，不讨论权限判定本身。**第 11 篇（备份与恢复链路数据副本归属）**——副本的产生、落点、密钥形态与可解性归它；同一句「USB 外接与 2019 Mac Pro 的 PCIe 存储不按这种方式加密」在 11 篇里是可解性归属，在本篇里只是形态归属，本篇不追问备份能不能解。**第 14 篇（签名与分发授权链）**——代码签名的授权与时效归它；本篇只取「从内部存储设备读取任意字节时的保护」这一格，即 SSV 的 seal 与挂载时点的校验顺序，不重复 Mach 对象内存映射时的保护。**第 18 篇（非可信内容解析链路）**——内容被判成什么类型归它；本篇处理承载该内容所在的卷是什么形态，两篇只在 `libarchive`、`disk images` 两处组件名上有交集，本篇不重复解析链分析。**第 19 篇（屏幕画面外流链路）**——落点的目录与进程可见性归它；本篇处理那块存储的卷类型、挂载选项与密钥栈，不涉及任何画面采集侧内容。**第 22 篇（外接配件与近场配对链路归属）**——本篇只在「外设承载的卷以什么形态被挂载」这一格涉及外设，配对、认证、近场信任一律不在本篇范围；`allowUSBRestrictedMode`、`allowFilesUSBDriveAccess` 两个键在本篇只作为 216 键分母中的成员被计数。**第 23 篇（平台校验组件与度量物归属，本队列后续篇目）**——`cryptex`、`preboot`、`LocalPolicy` 的 4CC 字段在本篇只作为「系统卷形态与挂载校验时点」的读数被引用，度量物本身的归属体系留给 23 篇。

---

咨询ios系统请咨询 telegram：https://t.me/one00190

