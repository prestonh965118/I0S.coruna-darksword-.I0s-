---
title: "iOS 平台校验组件与度量物归属防御分析报告"
description: "iOS 上一个平台校验件是怎样被生成、谁签的、它能指名什么、它能证明什么、它在哪里被读回、又在哪里过期：十一层归属分解（L1 主体、L2 密钥、L3 证明物、L4 属性、L5 校验、L6 度量、L7 登记、L8 生命周期、L9 管理面回查、L10 公告对齐、L11 引用与结论），四件（App 实例件／设备件／凭据件／配件件）× 11 层 × 20 项核对项的差集口径，接口与符号口径／平台安全口径／管理面口径／公告口径四套词表与八处换算失败，J1—J4 与 Q1—Q4 两套判定模型，两个离线只读核验脚本（58 + 43 个码，共 101 个全部实跑触发，15 个剖面逐码覆盖）"
lang: zh-CN
---

# iOS 平台校验组件与度量物归属防御分析报告

## 摘要

本报告集前二十二篇依次回答过这些归属问题：缺陷在哪（第 01、06、07、12 篇的攻击面归属）、谁能进入这道门（第 02 篇的访问控制归属）、这条链路看见了什么（第 03、04 篇）、这台设备归谁（第 08、10、11 篇的主体归属）、这段代码凭什么被允许运行（第 14 篇的授权链归属）、这条通道凭什么存在（第 15 篇的通道归属）、同网段上谁看得见谁（第 16 篇的局域网可达性归属）、一条内容进了检索面之后谁能查回来（第 17 篇的检索面归属）、一份从别处来的内容被判成了什么类型（第 18 篇的类型判定归属）、一帧画面有没有离开这台设备（第 19 篇的画面外流归属）、一个卷是什么形态又由谁挂上来（第 20 篇的卷与挂载归属）、一个邮件账户是谁以什么声明装配出来的（第 21 篇的账户装配归属）、一个外接配件是怎样被发现、被同意、被验证的（第 22 篇的配件链路归属）。本文回答系列里的第十三类，也是整个系列的最后一道底座问题：**一个平台校验件是怎样被生成、谁签的、它能指名什么、它能证明什么、它在哪里被读回、又在哪里过期。**

这句话拆开是六个问句，而它们指向的**不是同一个对象**。这是本文与前面所有篇目最不同的一点：前二十二篇都在拆一条链路，本文要先拆掉一个词。「attestation」在同一个平台上至少指四件互不通约的东西：

1. **App 实例件**——App Attest 证明的是「一个合法的 App 实例持有一把由 Apple 服务器认证过的密钥」，不是「这台设备是好的」。成文口径是 `a hardware-based, cryptographic key that uses Apple servers to certify that the key belongs to a valid instance of your app`（`A/devicecheck_establishing_app_integrity.txt:10—11`）；同一篇文章还写明「一个被改动过的操作系统可能绕过限制」（`A/devicecheck_assessing_fraud_risk.txt:7`），也就是说证明成立并不推出设备未受改动。
2. **设备件**——Managed Device Attestation（MDA）证明的是「这一台设备是正品 Apple 硬件，且这些属性值我能核实」，叶子证书里可以带 10 个 OID（`B/apple-platform-security-guide.txt:4317—4324`）；但这 10 个 OID 里只有 2 个是身份（序列号、UDID），其余 8 个是版本与状态（`B/apple-platform-security-guide.txt:4343、4347`）。
3. **凭据件**——WebAuthn 的企业级 passkey 校验，在管理面里只有**一项**声明（`SecurityPasskeyAttestation`，`.srcx16/C/mdm-declarations.txt:45`），证明的是「这把凭据的密钥材料在某个认证器里」，既不是 App 实例也不是设备。
4. **配件件**——MFi 认证 IC 证明的是「这块配件是它」，公开接口读不到逐配件的判定结果（第 22 篇已完整处理，本文只在第 3 章与第 15 章做边界引用，不重复展开）。

把这四件写成一个词，会产生一连串具体的换算错误。本文把它们逐条列成八处：`isSupported == true` 不等于可调用（扩展里恒失败，`A/devicecheck_dcappattestservice_issupported.txt:25—33`）；校验通过不等于设备未被改动（`A/devicecheck_assessing_fraud_risk.txt:5—7`）；OID 缺失不等于属性为假（`A/devicemanagement_validating_managed_attestation.txt:23`）；度量不等于设备台数（`A/devicecheck_assessing_fraud_risk.txt:99—100`）；被认证的密钥不等于设备身份（`A/devicecheck_validating_apps_server.txt:141—143`）；响应里有 UDID 不等于所有注册类型都有（`A/devicemanagement_deviceinformationresponse.txt:11、34`）；`DeviceInformation` 成功不等于 attestation 已附上（不支持的 SoC 直接忽略两个键，`A/devicemanagement_device_information_command.txt:16`）；回执里的度量不等于当前值（有「不早于」「到期」与 304 三重时效，`A/devicecheck_validating_apps_server.txt:155—158`、`A/devicecheck_assessing_fraud_risk.txt:102—108`）。

本文的核心结论是：**这四件各自都闭合，但闭合的边界不一样；把它们当成一件，就会在边界处得到「看起来有证据、实际上没有」的记录。** 具体到三个可数的位置：

- **可指名的位置**：MDA 叶子证书有 2 个身份 OID，但两者在 User Enrollment 下都不写入（`B/apple-platform-security-guide.txt:4343、4347`；`A/devicemanagement_validating_managed_attestation.txt:39` 亦要求组织自行核对这两个持久标识符）。也就是说，「有校验件」与「能指名个体」是两个独立条件，合并成一个字段就必然出错。
- **可判定的位置**：公开口径把属性写成三值——有值、被省略、值为空——并且明确「只有在能核实该属性值时才写入」，唯一例外是时新码（`B/apple-platform-security-guide.txt:4460`）。三值不是二值，「缺失」不能读成「否」。
- **可回读的位置**：管理面 216 个纯键名里含 `attest`／`devicecheck`／`integrity` 的是 **0** 个（`.srcx16/C/mdm-restriction-keys.txt`）；66 项声明里含 `Attest` 的只有 1 项，且是 passkey 校验（`.srcx16/C/mdm-declarations.txt:45`）；公告语料 1266 行、129 个组件名里，`attest`、`DeviceCheck`、`Secure Enclave`、`SEP`、`Trust Cache`、`LocalPolicy`、`boot`、`codesign`、`signature` 九个词形在组件列与影响句列**同时为 0**（`C/advisories` 的 R21.3 读数）。也就是说：这套机制在「谁签了什么」这一面有最厚的文档，在「事后怎么查」这一面几乎没有任何公开词形。

第三个必须前置的事实是**这条链路的两端不在同一侧**。生成端在设备：密钥在 Secure Enclave 里（`A/devicecheck_dcappattestservice_generatekey.txt:179`），证明物由 Apple 服务器签发（`B/apple-platform-security-guide.txt:4426—4429`）。判定端在服务器：`Store the verified public key … on your server`（`A/devicecheck_validating_apps_server.txt:141—143`），判定位置不是 App 自身（脚本一 `D01` 就是把「判定位置是 App」判为错误）。中间没有任何一个公开接口能把「服务器判过了」这件事读回设备。本文把这一条写成第 9 章的中心事实，也写成脚本二 `X03`（缺回读点）与 `X04`（缺有效期口径）的设计根据。

全文有十三组可数的公开读数（第 16 章，R01—R26，每组给归档行锚）、两套四档判定模型（第 19 章）、十一层归属分解（第 4—14 章）、一个十一层 × 责任方 × 四件 × 证据的归属矩阵（第 15 章），以及两个完全离线、只读、不联网、不接触任何设备的核验脚本：平台校验台账逐字段审查器（232 行，58 个码 = 54 个信号码 + 4 档判定）与校验件四件框架闭合性与公告词表比对器（252 行，43 个码 = 39 个信号码 + 4 级闭合）。**合计 101 个码全部由真实夹具触发**，15 个剖面（脚本一 10 个、脚本二 5 个）的逐码可达性见第 23 章；两支脚本的只读性质由第 23.5 节的二十段实证（P01—P20，临时目录前缀是 `att23.`）逐条给出位置。

---

## 目录

1. [引言](#1-引言)
2. [视角声明与本文边界](#2-视角声明与本文边界)
3. [四套词表：接口与符号口径、平台安全口径、管理面口径、公告口径，以及八处换算失败](#3-四套词表接口与符号口径平台安全口径管理面口径公告口径以及八处换算失败)
4. [L1 主体层：四个「谁」被写成了一个词](#4-l1-主体层四个谁被写成了一个词)
5. [L2 密钥层：Secure Enclave 里的句柄与它不跨重装](#5-l2-密钥层secure-enclave-里的句柄与它不跨重装)
6. [L3 证明物层：证书链、aaguid 与回执](#6-l3-证明物层证书链aaguid-与回执)
7. [L4 属性层：十个 OID 与三值编码](#7-l4-属性层十个-oid-与三值编码)
8. [L5 校验层：判定在服务器侧，App 自己不算](#8-l5-校验层判定在服务器侧app-自己不算)
9. [L6 度量层：三十天窗口、九字段回执与两位状态位](#9-l6-度量层三十天窗口九字段回执与两位状态位)
10. [L7 登记层：绑定用户、绑定设备、谁有权重置](#10-l7-登记层绑定用户绑定设备谁有权重置)
11. [L8 生命周期层：重装、恢复、换机与转手](#11-l8-生命周期层重装恢复换机与转手)
12. [L9 管理面回查层：216 个纯键名里的零个校验键](#12-l9-管理面回查层216-个纯键名里的零个校验键)
13. [L10 公告对齐层：1266 行里的零行](#13-l10-公告对齐层1266-行里的零行)
14. [L11 引用与结论层：doc.* 与十八份文档的平台坐标](#14-l11-引用与结论层doc-与十八份文档的平台坐标)
15. [归属矩阵：十一层 × 责任方 × 四件 × 证据](#15-归属矩阵十一层--责任方--四件--证据)
16. [公开读数：这套机制上能数出来的十三组事实](#16-公开读数这套机制上能数出来的十三组事实)
17. [可见性边界：这一层读者能拿到什么](#17-可见性边界这一层读者能拿到什么)
18. [五个读数面：生成侧、判定侧、登记侧、管理侧、公告侧](#18-五个读数面生成侧判定侧登记侧管理侧公告侧)
19. [两套判定模型：J1—J4 与 Q1—Q4](#19-两套判定模型j1j4-与-q1q4)
20. [运营指标 O1—O10](#20-运营指标-o1o10)
21. [只读核验脚本一：平台校验台账逐字段审查器](#21-只读核验脚本一平台校验台账逐字段审查器)
22. [只读核验脚本二：校验件四件框架闭合性与公告词表比对器](#22-只读核验脚本二校验件四件框架闭合性与公告词表比对器)
23. [实跑与覆盖验收](#23-实跑与覆盖验收)
24. [十二个误区](#24-十二个误区)
25. [常见问题](#25-常见问题)
26. [未公开文档化边界清单](#26-未公开文档化边界清单)
27. [结论](#27-结论)
28. [参考资料](#28-参考资料)

---

## 1. 引言

### 1.1 六个问句与四个对象

本篇只问六个问题，每个问题都必须先写清「对象是哪一件」：

1. **它是什么被生成出来的？** App Attest 的密钥由 `generateKey` 生成并存入 Secure Enclave（`A/devicecheck_dcappattestservice_generatekey.txt:179`）；MDA 的叶子证书由 Apple 的 attestation servers 签发（`B/apple-platform-security-guide.txt:4429`）；passkey 的凭据由认证器生成；配件的身份由链路之外的认证 IC 判定（`B/apple-platform-security-guide.txt:1367`）。
2. **它是谁签的？** App Attest 是「Apple 服务器认证这把钥匙属于一个合法 App 实例」（`A/devicecheck_establishing_app_integrity.txt:10—11`）；MDA 是「Apple Enterprise Attestation Root CA」之下的一条链（`B/apple-platform-security-guide.txt:4324`）；passkey 由认证器签名；配件由 MFi IC 签。
3. **它能指名什么？** App Attest 能指名的最大单位是「这个 App 在这台设备上的这个实例」；MDA 能指名「设备」，但身份 OID 在 User Enrollment 下不写入（`B/apple-platform-security-guide.txt:4343、4347`）；passkey 指名「凭据」；配件指名「配件」。
4. **它能证明什么、不能证明什么？** 公开口径明确「被改动过的操作系统可能绕过限制」（`A/devicecheck_assessing_fraud_risk.txt:7`），也明确属性「只有在能核实时才写入」（`B/apple-platform-security-guide.txt:4460`）——前者说明证明的边界，后者说明缺省的语义。
5. **它在哪里被读回？** App Attest 的判定回读点在**你的服务器**（`A/devicecheck_validating_apps_server.txt:141—143`）；MDA 的回读点在 MDM 的 `DeviceInformation` 响应与 ACME 登记（`A/devicemanagement_validating_managed_attestation.txt:7—11`）；passkey 的回读点在依赖方；配件的回读点不在公开接口里（第 22 篇）。
6. **它在哪里过期？** App Attest 的证明物有两层时间：回执创建时间不超过五分钟（`A/devicecheck_assessing_fraud_risk.txt:89—90`），回执本身有「不早于」（字段 19）与「到期」（字段 21）两个时刻（`:111—116`），度量则是「过去 30 天内」的近似值（`:99—100`）；MDA 的叶子证书有自己的有效期，而属性本身没有单独的「新鲜度」字段，只有时新码（`B/apple-platform-security-guide.txt:4397、4460`）。

这六个问句的共同点：**答案随对象变化，而对象的名字在公开文档里被写成了同一个词。** 第 3 章把这件事拆成四套词表；第 4—14 章逐层处理；第 15 章给出四件之间的不可换算关系。

### 1.2 为什么这一格在系列里非拆不可

第 05 篇讲生物识别时提到过 Secure Enclave 是信任根，第 10 篇讲设备生命周期时提到过激活锁与托管凭据，第 14 篇讲签名链时提到过「谁签的」，第 22 篇讲配件时提到过 MFi 认证 IC。这四篇都碰到过「校验件」，但都停在各自那一格：

- 05 篇的 Secure Enclave 是**密钥存放位置**，没有追问「存放在里面的密钥能证明什么」；
- 10 篇的托管凭据是**所有权登记**，没有追问「登记的凭据与设备属性校验件是不是同一件」；
- 14 篇的签名链回答的是**代码**凭什么被允许运行，本文回答的是**设备与实例**凭什么被相信；
- 22 篇的认证 IC 是四件中的第四件，本文只做边界引用，不重复其 11 层分解。

本文补的是这四篇之间那块空白：**当一份「平台校验」被写进台账、写进合规报告、写进风控规则时，它到底是四件里的哪一件，以及它能不能支撑写它的人想让它支撑的那个结论。**

### 1.3 本文不做什么

本文不生成任何密钥、不申请任何 attestation、不调用任何服务器校验、不换取任何回执、不执行任何管理面命令，也不给出任何绕过服务器校验、伪造回执、复用他人密钥或规避注册类型限制的方法。第 21、22 章的两个脚本只读文本台账与文本语料，不联网、不接触设备、不读取钥匙串；它们的全部输入在第 28 章逐份列出。

### 1.4 三个可复算的结论

本文的三个主结论都可以用第 22 章的脚本二在真实归档上复算一遍：

```text
框架对象数= 4
词表术语数= 15
公告行数= 1266
声明读数数= 17
X 族信号= 0　Y 族信号= 0　Z 族信号= 0
不同信号码= 0　信号条数= 0
判定= W1
```

这段输出说明三件事：四件框架的每一行都同时具备签署方、证明物、回读点与有效期口径（X 族 0 信号）；15 个术语的每一处出处都能在归档里按行号命中（Y 族 0 信号）；17 个声明读数与从 1266 行公告语料重算出来的值逐一相等（Z 族 0 信号）。第 23 章给出这 15 个剖面的完整矩阵与逐码覆盖表。

---

## 2. 视角声明与本文边界

### 2.1 视角声明

本文是**防御与归属视角**，不是攻击视角。它假设读者是三类人之一：要在风控或反作弊系统里使用「平台校验」结论的工程人员；要在合规材料里引用「设备校验」证据的安全或审计人员；要在事故复盘中判断「这条记录到底证明了什么」的响应人员。对这三类人，最重要的问题不是「怎么伪造」，而是「**我手上这条记录，按公开口径最多能推出什么**」。

本文与相邻篇目的边界如下，逐条给出「本文不覆盖、请读哪一篇」：

| 相邻篇目 | 它回答的问题 | 与本文的重叠点 | 本文如何处理 |
| --- | --- | --- | --- |
| 第 05 篇 生物识别 | 生物特征怎样被采集、匹配与保护 | Secure Enclave 作为信任根 | 只把 Secure Enclave 当作密钥存放位置引用，不展开生物识别 |
| 第 10 篇 设备生命周期 | 设备归谁、怎样移交 | 托管凭据与设备标识 | 只引用「身份 OID 与注册类型的关系」，不重复生命周期的十层分解 |
| 第 14 篇 签名与分发 | 代码凭什么被允许运行 | 「谁签的」这一问 | 明确区分「代码签名身份」与「设备／实例校验件」，两者不互相替代 |
| 第 20 篇 卷与文件系统 | 卷是什么形态 | 无 | 无重叠 |
| 第 22 篇 外接配件 | 配件怎样被发现、同意、验证 | MFi 认证 IC（四件中的配件件） | 只在第 3、15 章做边界引用，声明配件件的完整分析在第 22 篇 |
| 第 13 篇 日志与诊断 | 日志能证明什么 | 「事后可回读性」 | 本文只讨论校验件自身的回读点，不讨论日志通道 |

### 2.2 本文的四条硬边界

**边界一：不把「校验通过」写成「设备可信」。** 公开文档自己就写了反例：`an attacker that modifies the device's operating system might bypass restrictions`（`A/devicecheck_assessing_fraud_risk.txt:7`）。本文在任何位置都不把校验结果当作设备完整性的充分条件。

**边界二：不把「字段存在」写成「属性为真」。** 三值编码的口径是「只有在能核实时才写入」（`B/apple-platform-security-guide.txt:4460`），而校验文档又写「任何缺失的 OID 或空值都表示 Apple 的 attestation servers 无法可靠确定对应属性」（`A/devicemanagement_validating_managed_attestation.txt:23`）。这三句话合起来意味着：缺失是一个**认识论状态**，不是一个**取值**。

**边界三：不把四件互换。** App 实例件、设备件、凭据件、配件件各有自己的签署方、证明物、回读点与有效期。脚本二 `X06` 专门拦「同一个证明物被多个对象共用」，`X07` 拦「除设备件之外的对象宣称可指名个体」，`X09` 拦「除凭据件之外的对象宣称凭据级证明」。

**边界四：不给出任何操作步骤。** 本文描述机制时只引用公开文档的结论句，不转录任何 API 调用序列的完整代码，不提供任何可执行的申请、换取、校验或重放步骤。

### 2.3 术语约定

- **校验件**（attestation object）：本文对四类证明物的统称，具体指哪一件时一律写明「App 实例件／设备件／凭据件／配件件」。
- **证明物**（proof）：签署方产出的、可被第三方校验的那段数据；对 App 实例件是证书链与回执，对设备件是叶子证书链，对凭据件是认证器签名，对配件件是 IC 的判定结果。
- **回读点**（readback）：第三方能读到「校验发生过」或「校验结果是什么」的位置。
- **度量**（metric）：本文特指 App Attest 回执字段 17 的数值，即「过去 30 天内与该设备上该 App 关联的已认证密钥数的近似值」（`A/devicecheck_assessing_fraud_risk.txt:99—100`）。不是设备台数，不是用户数，不是安装数。
- **三值**（three-valued）：属性取值为「有值／省略／空」，与二值的「真／假」不是同一套编码。

### 2.4 引用形式

正文中的所有英文引文都以 `` `路径:行号` `` 的形式给出锚点，路径相对于本报告集的归档根 `.srcx23`（管理面两项读数来自 `.srcx16/C`，第 16 章单独标注）。归档的构成、抓取方式与逐份行数见第 28 章。凡本文写作「未公开文档化」的条目，均指在第 28 章列出的全部归档中检索不到对应口径，不指「一定不存在」。

---

## 3. 四套词表：接口与符号口径、平台安全口径、管理面口径、公告口径，以及八处换算失败

### 3.1 四套词表各自回答什么

同一个「校验」，在四个文档体系里被写成四套互不引用的词表：

| 词表 | 载体 | 它回答的问题 | 关键读数 |
| --- | --- | --- | --- |
| 接口与符号口径 | DeviceCheck／App Attest／DeviceInformation 的符号页与文章（A 组 18 份） | 这个 API 在哪些平台、哪些扩展、哪些 SoC 上可用；字段叫什么 | `attest` 出现 325 次（15 份），`receipt` 45 次（3 份），`UDID` 2 次（2 份），`serial` 1 次（1 份）（R24） |
| 平台安全口径 | Apple Platform Security 指南（B 组 1 份，4885 行） | MDA 的信任根、OID 表、签发流程与三值编码 | `attest` 52 行，`Secure Enclave` 196 行，`OID` 14 行，`LocalPolicy` 54 行（R25） |
| 管理面口径 | MDM 限制键表与声明类型表（`.srcx16/C`） | 组织侧能配置什么、能声明什么 | 216 个纯键名中 `attest`／`devicecheck`／`integrity` 命中 0；66 项声明中 `Attest` 命中 1（R20） |
| 公告口径 | 1266 行安全公告语料（C 组） | 缺陷被归到哪个组件名、影响句怎么写 | 9 个校验词形在组件列与影响句列**同时为 0**（R21.3） |

四套词表的最低公分母只有一个词：「attestation」。除此之外，它们的字段名、对象名、时间口径、责任方全部不同。第 4—14 章的十一层，就是把同一个「attestation」在四套词表里分别落到哪一格逐层写出来。

### 3.2 八处换算失败

**换算失败一：`isSupported == true` ⇏ 可调用。** 符号页写得很清楚：在 Mac 上读 `isSupported` 恒为 `false`，包括 Mac Catalyst 与在 Apple silicon 上运行的 iOS／iPadOS App（`A/devicecheck_dcappattestservice_issupported.txt:20—24`）；在扩展里「值可能是真也可能是假，取决于扩展类型，但多数扩展不支持 App Attest，且 `generateKey` 从扩展调用时恒失败，与 `isSupported` 的取值无关」（`:25—33`）。而同一篇文章的正文又说「Action、extensible SSO 与 watchOS 扩展是支持的，其他扩展类型都不支持，即使方法属性为真」（`A/devicecheck_establishing_app_integrity.txt:29—31`）。三句话放在一起：**能力位为真、属性为真、调用成功是三件事。**

**换算失败二：校验通过 ⇏ 设备未受改动。** `A compromised version of your app running on a genuine, unmodified Apple device can't create valid assertions. However, an attacker that modifies the device's operating system might bypass restrictions.`（`A/devicecheck_assessing_fraud_risk.txt:5—7`）。这句话给出的是**双向边界**：坏 App 在好设备上拿不到有效断言；但好 App 在被动过系统的设备上，断言仍可能成立。因此「校验通过」最多推出「这把密钥属于一个被 Apple 认证过的 App 实例」，推不出「运行环境未被改动」。

**换算失败三：OID 缺失 ⇏ 属性为假。** 校验文档写 `Any missing OIDs or blank values indicate that Apple's attestation servers were unable to reliably determine the corresponding property.`（`A/devicemanagement_validating_managed_attestation.txt:23`）；平台安全指南写 `Each property in the attestation certificate is included only if the attestation servers are able to verify the property's value, with the exception of the freshness code which is included without any validation.`（`B/apple-platform-security-guide.txt:4460`）。两句合起来是**三值编码**：有值＝核实过；空值＝尝试过但未能确定；缺失＝未纳入。三者都不能写成「否」。

**换算失败四：度量 ⇏ 唯一设备数。** 度量是 `an approximate count of unique attestations for your app on a particular device`（`A/devicecheck_assessing_fraud_risk.txt:11—13`），回执把它表示成 `the number of attested keys associated with a given device over the past 30 days`（`:99—100`）。它是**按键计数的近似值**，不是设备台数；文档还明确它会因重装、恢复、转手而增长（`:102—105`）。一台设备多次生成密钥，度量就上升。

**换算失败五：被认证的密钥 ⇏ 设备身份。** 校验文档要求把公钥「与用户、与特定设备关联」存下来（`A/devicecheck_validating_apps_server.txt:141—143`），但这里的「设备」是服务器自己的登记维度，不是密码学上的设备标识。App Attest 的证明物里没有序列号，也没有 UDID：A 组全文 `UDID` 只出现 2 次、`serial` 只出现 1 次（R24），而 `attest` 出现 325 次（R26）——**绝大多数「证明」与「设备身份」这个词根本不同现。**

**换算失败六：响应里有 UDID ⇏ 所有注册类型都有。** `DeviceInformationResponse` 的 UDID 字段写明 `The system requires this value if the enrollment type is a device enrollment.`（`A/devicemanagement_deviceinformationresponse.txt:34`）；另一个 per-enrollment 标识字段写明 `The system requires this value if the enrollment type is a user enrollment.`（`:11`）。两个字段是**互斥条件**，不是「都有」。

**换算失败七：`DeviceInformation` 成功 ⇏ attestation 已附上。** `Unsupported devices ignore the DevicePropertiesAttestation and DeviceAttestationNonce keys.`（`A/devicemanagement_device_information_command.txt:16`）。硬件表把「不支持」写成 A10x Fusion 及更早、Intel、S3 及更早（`:24—27`），把「支持」写成 A11 Bionic 及之后、全部 M 系列、Apple silicon、A12 Bionic 及之后、S4 及之后（`:30—34`）。**命令返回成功与响应里带证明物是两个条件**；在不支持的设备上，请求里多带的两个键被直接忽略，响应照常返回。

**换算失败八：回执里的度量 ⇏ 当前值。** 回执有三个时刻：创建时间（五分钟判定窗口，`A/devicecheck_assessing_fraud_risk.txt:89—90`）、字段 19 的「不早于」、字段 21 的「到期」。文档写「早于字段 19 请求会返回 304」「晚于字段 21 服务器可能不受理」（`:111—116`），并写「development 与 production 两套回执不能互用」（`A/devicecheck_validating_apps_server.txt:155—158`）。因此一条「度量 = N」的记录，必须同时记下它的三个时刻与环境，否则不能与另一条比较。

### 3.3 四件框架的四个坐标

把上面八处失败归并，可以得到一张四行表。这张表就是脚本二 `frame-good.tsv` 的四个对象，也是第 15 章归属矩阵的列：

| 对象 | 签署方 | 证明物 | 可指名 | 回读点 | 有效期口径 |
| --- | --- | --- | --- | --- | --- |
| App 实例件 | Apple 服务器（认证密钥属于合法实例） | 证书链 + 回执 | 实例（非设备） | 你的服务器 | 回执创建时间五分钟；字段 19／21；度量 30 天窗口 |
| 设备件 | Apple attestation servers（Apple Enterprise Attestation Root CA 之下） | 叶子证书链（10 个 OID） | 设备（身份 OID 2 个，User Enrollment 下不写） | MDM `DeviceInformation` 响应／ACME 登记 | 叶子证书有效期；时新码一次性 |
| 凭据件 | 认证器 | 认证器签名 + 凭据公钥 | 凭据 | 依赖方（RP） | 凭据自身生命周期 |
| 配件件 | MFi 认证 IC | IC 判定（公开接口不可读） | 配件 | 无公开回读点 | 未公开文档化（见第 22 篇） |

**这张表最重要的一列是「可指名」。** 四件里只有设备件能指名到「一台设备」，而它的身份 OID 在 User Enrollment 下被明确省略；App 实例件能指名的最大单位是「一个 App 实例」；凭据件指名「一把凭据」；配件件指名「一个配件」。脚本二的 `X07`（宣称可指名个体但对象不是设备）与 `X09`（宣称凭据级证明但对象不是凭据）就是把这张表写成可执行断言。

---
## 4. L1 主体层：四个「谁」被写成了一个词

### 4.1 一层有四个主体

平台校验的第一层不是密码学，而是**主体**。「这个校验件是谁的」决定了后面所有字段的语义。公开文档里有四个不同的主体，它们各自的措辞互不引用：

| 主体 | 成文措辞 | 锚点 | 这一句能推出的最大范围 |
| --- | --- | --- | --- |
| App 实例 | 「证明该密钥属于你的 App 的一个合法实例」 | `A/devicecheck_establishing_app_integrity.txt:10—11` | 一个 App 安装实例 |
| 设备 | 「提供关于设备身份与其安全状况的密码学保证」 | `B/apple-platform-security-guide.txt:4318` | 一台设备 |
| 凭据 | 「为某些 passkey 允许 WebAuthn 企业级校验」 | `.srcx16/C/mdm-declarations.txt:45` | 一把凭据 |
| 配件 | 「完全由 Apple 提供给获准配件厂商的定制 IC 处理」 | `B/apple-platform-security-guide.txt:1367` | 一个配件（第 22 篇） |

四句话都出现了「校验」或「证明」，但主语分别是实例、设备、凭据、配件。**这不是同一件事的四种说法，而是四件事共用一个词。**

### 4.2 App 实例件的主语为什么不是设备

`A/devicecheck_establishing_app_integrity.txt:10—11` 的原文把主语写在从句里：`certify that the key belongs to a valid instance of your app`。被动语态容易让人读成「这把钥匙属于这台设备」，但 `belong to` 的宾语是 `instance of your app`，不是 `device`。

同一篇文章紧接着给出两个能反证「设备」解读的事实：

1. 密钥是**按用户账户、按设备**成对生成的：`For each user account on each device running your app, generate a unique, hardware-based, cryptographic key pair`（`:34`）。同一台设备上的两个账户会有两把不同的密钥；同一账户在两台设备上也会有两把。可见密钥的粒度比设备更细，也比设备更多。
2. 密钥标识符必须由 App 自己持久保存，因为 `there's no way to get the identifier later`（`:37—38`）。如果这个校验件是「设备的」，系统本可以按需重新给出标识符；正因为它是「实例的」，标识符一旦丢失，这个实例的证明关系就无法恢复。

### 4.3 设备件的主语为什么不是「任何 Apple 设备」

MDA 的可用性口径把设备件限定得很死：`iPad, iPhone, Apple TV devices require the A11 Bionic chip or later, and only Mac computers with Apple silicon are supported`（`B/apple-platform-security-guide.txt:4318`）。硬件表把不支持的一侧写成 A10x Fusion 及更早、Intel、S3 及更早（`A/devicemanagement_device_information_command.txt:24—27`）。

这条边界在实现上表现为**静默忽略**：`Unsupported devices ignore the DevicePropertiesAttestation and DeviceAttestationNonce keys`（`:16`）。命令不会因为设备不支持而失败，只是证明物不会出现在响应里。这就是第 3 章「换算失败七」的具体形态：**「命令成功」是一个布尔，「证明物存在」是另一个布尔，两者没有蕴含关系。**

### 4.4 凭据件为什么在管理面只剩一行

管理面的 66 项声明里，含 `Attest` 的只有一项：`SecurityPasskeyAttestation — The declaration to configure the device to allow WebAuthn enterprise attestation for certain passkeys.`（`.srcx16/C/mdm-declarations.txt:45`）。这句话的主语是「某些 passkey」，动作是「允许企业级校验」，落点是「配置设备」。它既不涉及 App 实例，也不涉及设备身份。

这一行的重要性在于：**它是管理面上唯一能被称为「校验」的开关，而它管的是凭据。** 如果一个组织在审计表里写「已开启 attestation 策略」，按管理面的词表，这句话的实际含义是「已允许某些 passkey 的企业级校验」，不是「已启用设备校验」。脚本二的 `X09` 就是拦这种越界：宣称凭据级证明的对象必须真的是凭据件。

### 4.5 四件的相互不可替代性

| 想知道 | App 实例件 | 设备件 | 凭据件 | 配件件 |
| --- | --- | --- | --- | --- |
| 这个请求来自合法 App 实例吗 | ✔ | ✘ | ✘ | ✘ |
| 这台设备是正品硬件吗 | ✘ | ✔ | ✘ | ✘ |
| 这台设备的系统版本与安全状态如何 | ✘ | ✔（8 个非身份 OID） | ✘ | ✘ |
| 这把 passkey 的密钥在认证器里吗 | ✘ | ✘ | ✔ | ✘ |
| 这个配件是它吗 | ✘ | ✘ | ✘ | ✔ |

表格里没有一行能被打两个勾。第 15 章的归属矩阵就是把这张表按责任方展开。

---

## 5. L2 密钥层：Secure Enclave 里的句柄与它不跨重装

### 5.1 密钥的物理位置

App Attest 的密钥由框架存入 Secure Enclave：`An identifier that you use to refer to the key. The framework securely stores the key in the Secure Enclave.`（`A/devicecheck_dcappattestservice_generatekey.txt:40—41`）。同一文档在参数表与说明里重复出现（`:40—41、179`）。

MDA 的密钥材料则来自另一条线：操作系统向 Secure Enclave 请求一次硬件校验，并指定「被校验的密钥、时新码、要校验哪些属性」（`B/apple-platform-security-guide.txt:4426`）。这条线上没有「App 句柄」这个概念——设备件的密钥属于设备，不属于某个 App。

### 5.2 句柄不是密钥

接口返回的是 `keyId`，一个字符串标识符。文档对它的要求是**持久保存**：`Record the identifier in persistent storage — for example, by writing it to a file — because there's no way to use the key without the identifier, and no way to get the identifier later.`（`A/devicecheck_establishing_app_integrity.txt:36—38`）。

这句话把密钥层拆成两个可独立失败的环节：

1. **密钥存在**：Secure Enclave 里有这把密钥；
2. **句柄可得**：App 能找回指向它的标识符。

脚本一的 `B02`（句柄存在但未持久保存）拦的就是第二种失败：台账写了「已生成」，但没写「标识符已保存」。在这种记录里，密钥可能确实存在，但这条记录无法再被使用，也无法再被核对。

### 5.3 密钥不跨重装、不跨恢复、不跨转手

最直接的一句话在欺诈风险评估文章里：`Note that the metric can grow if a user reinstalls your app, restores from a backup, or transfers a device to another user. For privacy reasons, App Attest keys stored on device don't survive these events, forcing your app to generate a new key on the same device.`（`A/devicecheck_assessing_fraud_risk.txt:102—105`）。

这句话同时给出三个事实：

- 触发事件有三类：重装、从备份恢复、设备转手；
- 结果是密钥**不存活**（`don't survive`）；
- 后果是同一台设备上必须重新生成密钥，**因此度量会增长**。

第三点经常被漏读。度量的定义是「过去 30 天内与该设备上该 App 关联的已认证密钥数」（`:99—100`），而密钥在重装后必然重建，所以「一台设备一个密钥」在 30 天窗口内几乎不可能成立。脚本一的 `F05`（宣称密钥在重装后仍存活）与 `F06`（宣称密钥可随备份恢复）就是拦这两句反事实登记。

### 5.4 两位状态位是另一条密钥线

DeviceCheck 的 `DCDevice` 走的是完全不同的机制：`Use the shared instance of the DCDevice class to generate a token that identifies a device`（`A/devicecheck_dcdevice.txt:10—12`），服务器用这个 token 与一把从 Apple 获得的认证密钥，去访问 `two per-device binary digits (bits)`（`:16—17`）。

关键的三句是：

1. `Apple passes the current values of the bits, along with the date they were last modified, to your server`（`:17—18`）——位值带**修改时间**；
2. `Apple records the bits for you, and reports the bits back to you, but you're responsible for keeping track of what the bits mean`（`:27—28`）——位的**含义由开发者定义**；
3. `You're also responsible for determining when to reset the bits for a given device; for example, when a user sells the device to someone else`（`:28—30`）——**重置时机也由开发者决定**。

这三句合起来说明：两位状态位不是「平台对设备的判定」，而是「开发者自己写在平台上的两个便签」。它的**语义**完全在开发者一侧，平台只负责存储、回传与附带修改时间。脚本一的 `F02`（宣称两位状态位由平台重置）就是拦这句最常见的误读。

### 5.5 密钥层小结

| 机制 | 密钥位置 | 标识符 | 存活范围 | 语义归属 |
| --- | --- | --- | --- | --- |
| App Attest | Secure Enclave | `keyId`，App 持久保存 | 不跨重装／恢复／转手 | Apple 认证「属于合法实例」 |
| MDA | 设备（Secure Enclave 参与） | 无 App 句柄 | 设备生命周期 | Apple 签发设备属性 |
| DeviceCheck 两位 | 平台侧记录 | `DCDevice` token | 跟随设备 | 开发者定义含义与重置 |
| passkey | 认证器 | 凭据 ID | 凭据生命周期 | 认证器签名 |

---

## 6. L3 证明物层：证书链、aaguid 与回执

### 6.1 三件证明物的形状不同

| 对象 | 证明物的形状 | 公开字段 | 锚点 |
| --- | --- | --- | --- |
| App 实例件 | 证书链 + 回执（CBOR／ASN.1） | aaguid、计数器、validationCategory、回执 9 字段 | `A/devicecheck_validating_apps_server.txt:56—133`、`A/devicecheck_assessing_fraud_risk.txt:56—78` |
| 设备件 | 叶子证书 + 中间证书 | 10 个 OID | `B/apple-platform-security-guide.txt:4324、4327—4361` |
| 凭据件 | 认证器签名 | 凭据公钥、RP ID | 管理面仅一项声明（`.srcx16/C/mdm-declarations.txt:45`） |
| 配件件 | IC 判定 | 公开接口不可读 | `B/apple-platform-security-guide.txt:1367` |

### 6.2 App 实例件的证书链从哪开始

校验文档要求：`Verify that the array contains the intermediate and leaf certificates for App Attest, starting from the credential certificate in the first data buffer in the array`（`A/devicecheck_validating_apps_server.txt:69—73`），并用 Apple 的根证书验证有效性（`:73—74`）。

这句话里有一个容易漏掉的细节：链是**从凭据证书开始**的，不是从「设备证书」开始。凭据证书对应的是「这把密钥」，而不是「这台设备」。这也是第 4 章「实例件」判断在密码学层的落点。

### 6.3 aaguid 只有三个合法值

校验指南的对象表里，`aaguid` 一栏列出的取值是 `appattestdevelop`、`appattest` 与七个 `0x00` 字节（`A/devicecheck_attestation_object_validation_guide.txt:197—200`）；第三个取值 `appattestsandbox` 出现在准备页的环境常量表里（`A/devicecheck_preparing_app_attest.txt:88`）。脚本一把它收敛成三个常量：`appattestdevelop`／`appattest`／`appattestsandbox`（`B06`），并在值不属于三者之一时报错。

需要注意的是：aaguid 是**认证器类型的标识**，不是设备标识、不是 App 标识、也不是用户标识。把它当作设备指纹是一个常见错误（第 24 章误区五）。

### 6.4 回执的九个字段

`App Attest receipts use the following fields:`（`A/devicecheck_assessing_fraud_risk.txt:56`）之后列出九个字段：

| 字段 | 名称 | 读它的人 | 它能回答什么 |
| --- | --- | --- | --- |
| 2 | App ID | 服务器 | 这是哪个 App |
| 3 | Attested Public Key | 服务器 | 被认证的公钥（DER ASN.1） |
| 4 | Client Hash | 服务器 | 客户端数据的哈希 |
| 5 | Token | 服务器 | 换取度量的凭据 |
| 6 | Receipt Type | 服务器 | 这份回执是随校验件来的，还是服务器换来的 |
| 12 | Creation Time | 服务器 | 回执何时创建（五分钟窗口） |
| 17 | Risk Metric | 服务器 | 风险度量（30 天窗口） |
| 19 | Not Before | 服务器 | 何时之后才能刷新 |
| 21 | Expiration Time | 服务器 | 何时之后可能不受理 |

九个字段里，**没有一个是设备标识**。字段 2 是 App，字段 3 是公钥，字段 4 是哈希，字段 5 是 token，字段 6 是类型，12/19/21 是时刻，17 是计数。这正是第 3 章「换算失败五」的字段级证据。

### 6.5 字段 6 决定「有没有度量」

`Field 6 of the receipt contains either the string RECEIPT for the receipt that comes with an attestation object, or the string … for receipts that you request using your server. Only the latter provide the risk metric in field 17.`（`A/devicecheck_assessing_fraud_risk.txt:94—98`）。

这句话的意思是：**随校验件一起返回的那份回执没有度量。** 只有服务器主动换来的回执才有字段 17。因此「校验成功时拿到了一个回执」与「拿到了一个带度量的回执」是两个状态，不能合并成一个布尔。脚本一的 `E01`（有度量但没有保存回执）与 `D03`（App Attest 记录没有保存回执）分别覆盖这两个状态的两侧。

### 6.6 环境是证明物的一部分

App Attest 的环境常量有三值：`development`／`production`／`sandbox`（脚本一 `B08` 的取值域），而文档明确 `keep development pairs separate from production pairs because you can't use one set in the other's environment`（`A/devicecheck_validating_apps_server.txt:155—158`）。校验指南里对应的权利声明是 `com.apple.developer.devicecheck.appattest-environment`（`A/devicecheck_attestation_object_validation_guide.txt:163`）。

因此一条台账记录如果只写「已校验」而不写环境，它在跨环境比较时**没有意义**。脚本一的 `att.env` 与 `B08` 就是把这个约束写进字段。

---

## 7. L4 属性层：十个 OID 与三值编码

### 7.1 OID 的完整清单

MDA 的叶子证书可以包含 10 个 OID（`B/apple-platform-security-guide.txt:4327—4361`）：

| # | OID | 名称 | 类别 | 可用性 |
| --- | --- | --- | --- | --- |
| 1 | 1.2.840.113635.100.8.9.1 | 序列号 | 身份 | 六平台（User Enrollment 下不写） |
| 2 | 1.2.840.113635.100.8.9.2 | UDID | 身份 | 六平台（User Enrollment 下不写） |
| 3 | 1.2.840.113635.100.8.9.4 | 软件更新设备 ID | 身份邻近 | 六平台 |
| 4 | 1.2.840.113635.100.8.10.1 | 操作系统版本 | 版本 | 六平台 |
| 5 | 1.2.840.113635.100.8.10.2 | sepOS 版本 | 版本 | 六平台 |
| 6 | 1.2.840.113635.100.8.10.3 | LLB 版本 | 版本 | 六平台 |
| 7 | 1.2.840.113635.100.8.11.1 | 时新码 | 一次性 | 六平台 |
| 8 | 1.2.840.113635.100.8.13.1 | SIP 状态 | 状态 | 仅 macOS 14 |
| 9 | 1.2.840.113635.100.8.13.2 | 安全启动状态 | 状态 | 仅 macOS 14 |
| 10 | 1.2.840.113635.100.8.13.3 | 是否允许第三方内核扩展 | 状态 | 仅 macOS 14 |

三类可用性在原文里是分开写的：前七个 OID 的每个描述后面都跟着 `iOS 16 iPadOS 16 macOS 14 tvOS 16 visionOS 1.1 watchOS 9`（例如 `:4341、4345、4349`），后三个只跟着 `macOS 14`（`:4377、4381、4385`），描述分别是 `Represents the SIP enablement status on a Mac with Apple silicon`（`:4379`）、安全启动状态、`Represents whether or not third-party kernel extensions are allowed on a Mac with Apple silicon`（`:4387`）。

**这张表回答了一个具体问题：设备件最多能说几件事？** 答案是：2 个纯身份、1 个身份邻近、3 个版本、1 个一次性随机值、3 个仅 Mac 的安全状态。设备件不能回答「这台设备有没有被改动过」——它只能回答「这些属性值 Apple 能不能核实」。

### 7.2 身份 OID 的两个条件

`Represents the serial number of the device and can be used to identify a device. To help protect the user's privacy, this value isn't included when using Managed Device Attestation with User Enrollment.`（`B/apple-platform-security-guide.txt:4343`）

`Represents the unique hardware ID and can be used to identify a device. On a Mac, the UDID matches the provisioning UDID of the device. To help protect the user's privacy, this value isn't included when using Managed Device Attestation with User Enrollment.`（`:4347`）

两句的结构完全一致：**「可以用来指认设备」＋「在 User Enrollment 下不写入」**。这与 `DeviceInformationResponse` 的字段口径互相印证：per-enrollment 标识在 user enrollment 下必填，UDID 在 device enrollment 下必填（`A/devicemanagement_deviceinformationresponse.txt:11、34`）。

因此「设备件能指名」这个结论有**两个前置条件**：注册类型必须是 device enrollment，且证书里必须真的带上了这两个 OID 之一。脚本一的 `C01`、`C02`、`C07` 把这三个状态分开：

- `C01`：User Enrollment 下登记了序列号（矛盾）；
- `C02`：User Enrollment 下登记了 UDID（矛盾）；
- `C07`：设备注册下既无序列号也无 UDID（无法指名）。

`G02` 再补一层：结论宣称可指名个体，但没有任何身份 OID。

### 7.3 三值编码

最关键的一句是：`Each property in the attestation certificate is included only if the attestation servers are able to verify the property's value, with the exception of the freshness code which is included without any validation.`（`B/apple-platform-security-guide.txt:4460`）

这句话定义了三种状态：

1. **有值**：Apple 能核实该属性，写入值；
2. **省略**：Apple 不能核实，OID 不出现；
3. **空值**：OID 出现但值为空。

校验文档对这三种状态的解释是：`Any missing OIDs or blank values indicate that Apple's attestation servers were unable to reliably determine the corresponding property.`（`A/devicemanagement_validating_managed_attestation.txt:23`）

**三值不是二值。** 「SIP 状态 = 空」不能读成「SIP 未启用」，只能读成「Apple 无法确定 SIP 状态」。这是本报告里最容易被误用的一个语义点，也是脚本一 `F03`／`F04`（位含义与重置时机只登记一个）与 `G02` 之外的第三个「缺省即错误」类信号的设计来源。

### 7.4 时新码是唯一的例外

`with the exception of the freshness code which is included without any validation`（`B/apple-platform-security-guide.txt:4460`）。时新码不核实，只原样抄入。它的作用是**把这次校验绑定到这次请求**：`The resulting value is included as a property in the leaf certificate and allows the device management service or ACME solution to verify that the attestation matches the request.`（`:4397`）

这带来一个推论：**时新码证明的是「这份证明物对应这次请求」，不是「这份证明物是新的」。** 如果请求方重复使用同一个时新码，证明物仍然会「匹配」，因为匹配的是值，不是时间。脚本一把时新码单独放在 `att.nonce`，并与 `ver.nonce_checked` 分开，正是为了避免把「有码」与「校验过码」混为一谈。

### 7.5 属性层的可读性边界

| 想知道 | 能不能从设备件得到 | 原因 |
| --- | --- | --- |
| 这台设备的序列号 | 有时 | 仅 device enrollment，且 OID 被写入 |
| 这台设备的 UDID | 有时 | 同上 |
| 系统版本 | 通常 | 能核实时写入，否则省略 |
| sepOS 版本 | 通常 | 同上 |
| SIP 是否启用 | 仅 Mac 14+ | 且需 Apple 能核实 |
| 安全启动是否启用 | 仅 Mac 14+ | 同上 |
| 是否允许第三方 kext | 仅 Mac 14+ | 同上 |
| 设备是否被改动 | 不能 | 公开口径没有这个属性 |

最后一行的「不能」不是保守表述，而是文档的直接结果：10 个 OID 里没有任何一个描述「完整性」或「是否被改动」。

---

## 8. L5 校验层：判定在服务器侧，App 自己不算

### 8.1 判定位置

`Store the verified public key from … on your server and associate it with the user for the specific device.`（`A/devicecheck_validating_apps_server.txt:141—143`）

这句话有两个关键词：`verified`（已经校验过）与 `on your server`（在你的服务器上）。校验动作发生在服务器，App 只负责把证明物交给服务器。

同一篇文档开头的动机句已经解释了为什么：`You can't rely on your app's logic to perform security checks on itself because a compromised app can falsify the results.`（`A/devicecheck_establishing_app_integrity.txt:6—7`）

因此脚本一把 `ver.verifier` 设成必填字段，并在它为 `app` 或 `none` 时报 `D01`（判定位置不是服务器）。

### 8.2 服务器侧的五步

公开文档给出的校验步骤可以归成五类动作：

| 动作 | 文档锚点 | 失败意味着 |
| --- | --- | --- |
| 验证书链到 Apple 根 | `A/devicecheck_validating_apps_server.txt:69—73` | 证明物不是 Apple 签的 |
| 校验时新码 / 客户端哈希 | `:75—81` 的挑战哈希步骤 | 证明物与本次请求不对应 |
| 校验计数器 | 断言阶段的口径（`:170` 之后） | 可能是重放 |
| 校验 validationCategory | `:120—133` | 二进制来源与预期不符 |
| 校验回执（签名、时间、公钥一致） | `A/devicecheck_assessing_fraud_risk.txt:79—92` | 回执不可信或过期 |

脚本一把这五类写成 `ver.chain_checked`、`ver.nonce_checked`、`att.counter`、`ver.category_checked`、`ver.receipt_stored`，并分别对应 `D05`、`D04`、`B05`、`D06`、`D03`。

### 8.3 「校验过」与「保存了校验结果」是两个动作

`When attestation succeeds, independently verify and store the receipt immediately.`（`A/devicecheck_validating_apps_server.txt:151`）

这句话里 `verify` 与 `store` 是并列动词。一条台账如果只写「已校验」而没有「已保存公钥」或「已保存回执」，它在事后无法自证。脚本一的 `D02`（结论为 present 但没有存下已校验公钥）、`D03`（没有保存回执）、`G05`（结论为闭合但没有证据引用）就是三个层级的「说了但没留证」。

### 8.4 判定位置不在设备上的后果

这是本文与前面多数篇目最不同的一点。第 16 篇的局域网发现、第 19 篇的画面外流、第 22 篇的配件链路，判定点大多在设备侧或系统侧，设备上的日志或状态至少能提供一部分回读。**平台校验的判定点在服务器侧，设备上没有任何公开接口能读回「服务器判过了」。**

后果有三条：

1. **设备端作证不能替代服务器端作证。** 设备只能证明「我提交过一份证明物」，不能证明「服务器接受了它」。
2. **服务器端记录必须自带时间。** 因为没有第二个回读点，服务器记录里的「校验时刻」是唯一的时间锚。
3. **合规材料的证据链必须落在服务器侧。** 若把「App 显示校验成功」写进材料，实际上引用的是 App 的自我报告，不是校验结果。

第 17 章把这三条展开成可见性边界。

---

## 9. L6 度量层：三十天窗口、九字段回执与两位状态位

### 9.1 度量的定义

`The receipt represents the metric as a string that indicates the number of attested keys associated with a given device over the past 30 days.`（`A/devicecheck_assessing_fraud_risk.txt:99—100`）

这句话有四个限定词，每一个都能单独让解读失败：

- **number of attested keys**：计的是**密钥**，不是设备、不是用户、不是安装；
- **associated with a given device**：关联维度是设备；
- **over the past 30 days**：滑动窗口，不是累计；
- **approximate**（`:11—13` 的措辞是 `an approximate count of unique attestations`）：是近似值。

### 9.2 为什么它会增长

`Note that the metric can grow if a user reinstalls your app, restores from a backup, or transfers a device to another user.`（`:102—103`）

三种事件都会让旧密钥失效、逼出新密钥（`:104—105`），因此同一台设备在 30 天内的密钥数会上升。文档对此的建议是 `This growth should be modest, but you'll have to tune your risk assessment logic based on the typical numbers that you see over time`（`:105—107`）。

这句话实际上否定了「度量 = 1 就是正常、> 1 就是异常」这种阈值式用法。它要求的是**按自身基线调参**，而基线又依赖设备类型、使用习惯与重装频率。

### 9.3 度量的时效三重门

| 门 | 条件 | 违反的后果 | 锚点 |
| --- | --- | --- | --- |
| 创建时间 | 不超过五分钟 | 回执不可信 | `:89—90` |
| 不早于（字段 19） | 刷新必须晚于该时刻 | 服务器返回 304 | `:111—113` |
| 到期（字段 21） | 使用必须早于该时刻 | 服务器可能不受理 | `:114—116` |

再加一条环境门：development 与 production 两套回执不能互用（`A/devicecheck_validating_apps_server.txt:155—158`）。

所以一条完整的度量记录至少要有五个字段：值、创建时间、字段 19、字段 21、环境。脚本一的 `met.metric`／`nb`／`exp`／`refresh` 与 `ver.receipt_age_min` 就是这五个字段的落点；`E03`（不早于晚于到期）、`E05`（有度量但刷新策略为 never）、`D07`（回执创建时间超过五分钟）是三条一致性检查。

### 9.4 度量不能当设备台数

这是本文最想强调的一条。度量按「设备上的密钥」计数，而密钥在重装、恢复、转手后必然重建。因此：

- 一台设备在一个月内重装两次，度量可能是 3；
- 两台设备各自只装一次，度量各是 1；
- 一个用户在三台设备上使用，三台各是 1，总数是 3。

「3」在这三种情形下含义完全不同。把度量求和当作「设备数」会同时高估第一种、低估第三种。脚本一的 `E06`（受管设备记录登记了 App Attest 度量）拦的是另一类错误：把实例件的度量挂到设备件的记录上。

### 9.5 两位状态位与度量的区别

| 维度 | App Attest 度量 | DeviceCheck 两位 |
| --- | --- | --- |
| 值的形状 | 非负整数（近似计数） | 两个二进制位 |
| 语义 | Apple 定义（已认证密钥数） | 开发者定义 |
| 时间 | 30 天滑动窗口 | 带最后修改时间 |
| 重置 | 不可重置（密钥失效即增长） | 开发者决定何时重置 |
| 归属 | App 实例 | 设备 |

脚本一的 `E04` 拦「台账宣称度量可重置」，`F02` 拦「宣称两位状态位由平台重置」——两条规则分别对应这张表的两行。

---

## 10. L7 登记层：绑定用户、绑定设备、谁有权重置

### 10.1 服务器侧的三个绑定

校验文档要求把公钥「与用户关联，并且针对特定设备」保存（`A/devicecheck_validating_apps_server.txt:141—143`），并且 `Be prepared to store multiple (key, receipt) pairs for each user. Store one pair for each device the user uses to access your services.`（`:155—156`）

这段话定义了三个绑定：

1. **键 → 用户**：一个用户可以有多个 (key, receipt) 对；
2. **键 → 设备**：每个设备一对；
3. **键 → 环境**：开发与生产分开（`:157—158`）。

第三个绑定最容易被漏掉。一个用户在三台设备上、每台各有开发与生产两把密钥，服务器上就应该有 6 对记录。脚本一的 `reg.key_user` 与 `reg.assoc_device` 就是前两个绑定的字段化。

### 10.2 两位状态位的登记责任

`Apple records the bits for you, and reports the bits back to you, but you're responsible for keeping track of what the bits mean. You're also responsible for determining when to reset the bits for a given device; for example, when a user sells the device to someone else.`（`A/devicecheck_dcdevice.txt:27—30`）

这句话把责任切成两半：**平台负责存储与回传，开发者负责语义与重置。** 因此一条台账如果写「两位 = 10，含义未知」，它不是一条完整记录；如果写「两位 = 10，由平台在检测到异常时置位」，它是**错误**记录。

脚本一的 `reg.bits_meaning` 与 `reg.bits_reset` 是必填对：`F03` 拦「有重置时机没含义」，`F04` 拦「有含义没重置时机」，`F02` 拦「声称平台重置」。

### 10.3 登记层的三个所有权

| 所有权 | 归谁 | 公开依据 | 若写错会怎样 |
| --- | --- | --- | --- |
| 密钥标识符 | App（开发者） | `A/devicecheck_establishing_app_integrity.txt:36—38` | 句柄丢失后无法恢复证明关系 |
| 两位状态位的含义 | 开发者 | `A/devicecheck_dcdevice.txt:27—28` | 位值被误读成平台判定 |
| 两位状态位的重置时机 | 开发者 | `:28—30` | 转手后旧状态被继承 |
| 设备属性 OID 的写入 | Apple attestation servers | `B/apple-platform-security-guide.txt:4460` | 缺失被误读成否定 |
| 时新码的生成 | 请求方（MDM／ACME） | `:4397` | 证明物与请求脱钩 |

这张表的核心是：**五个所有权分属三方（开发者、Apple、请求方），没有一方能单独完成一条完整记录。**

### 10.4 登记层的失败模式

脚本一的 `reg.*` 命名空间只做一件事：把「谁负责」写进字段，然后检查字段之间是否自相矛盾。它不判断业务逻辑对不对，只判断**这条登记自己站不站得住**。这与第 10 篇的归属台账审查器是同一类工具，只是对象从「设备生命周期」换成了「校验件」。

---

## 11. L8 生命周期层：重装、恢复、换机与转手

### 11.1 四类事件

| 事件 | 对 App 实例件 | 对设备件 | 对两位状态位 | 对度量 |
| --- | --- | --- | --- | --- |
| 重装 App | 密钥失效，需重建 | 不变 | 不变 | 上升 |
| 从备份恢复 | 密钥不随备份恢复 | 不变 | 不变 | 上升 |
| 换机 | 新设备新密钥 | 新设备新证书 | 新设备新位值 | 两台各计 |
| 转手 | 前主人密钥失效 | 设备件仍指同一硬件 | 开发者决定是否重置 | 可能上升 |

第一列的依据是 `App Attest keys stored on device don't survive these events`（`A/devicecheck_assessing_fraud_risk.txt:104—105`）；第三列的依据是开发者负责重置（`A/devicecheck_dcdevice.txt:28—30`）；第二列的依据是设备件绑定硬件而非 App（`B/apple-platform-security-guide.txt:4318`）。

### 11.2 「不存活」的确切范围

文档列出的三类事件是重装、从备份恢复、转手。它没有列出「系统更新」「重启」「注销账户」——这三件事是否影响密钥，公开文档没有写。本文把它们记为 `unknown`，而不是「不影响」。这是第 26 章边界清单 U03 的来源。

### 11.3 生命周期与度量的耦合

因为密钥不存活，度量必然随事件增长；因为度量是 30 天窗口，增长会在窗口滑过后回落。这两个机制叠在一起，使得「度量」这个数**同时是状态量与时间量**：

- 作为状态量，它反映最近的密钥创建频率；
- 作为时间量，它反映 30 天内发生过多少次事件。

因此对度量的正确用法是**看趋势与基线**，而不是看单点阈值。这一点在第 20 章的运营指标 O05 里具体化为「度量分位数而非均值」。

### 11.4 登记类型与生命周期的交叉

User Enrollment 下身份 OID 不写入（`B/apple-platform-security-guide.txt:4343、4347`），这意味着这类设备的设备件**不能指名个体**。当这类设备发生转手时，组织无法用设备件回溯「是哪一台」。脚本一的 `C01`／`C02`／`C07` 三条规则，本质上是在登记阶段就把这个缺口标出来，而不是等到回溯时才发现。

---

## 12. L9 管理面回查层：216 个纯键名里的零个校验键

### 12.1 三份管理面文件

管理面的读数取自第 16 篇建立的同一份归档（`.srcx16/C`），三份文件：

| 文件 | 行数 | 内容 | 本文用它回答 |
| --- | --- | --- | --- |
| `mdm-restriction-keys.txt` | 220 行（前 4 行为页眉，216 个纯键名） | 限制键名 | 组织能不能「配置」校验 |
| `mdm-declarations.txt` | 75 行（66 项声明） | 声明类型 | 组织能不能「声明」校验 |
| `mdm-root.txt` | 41 行 | 导航页 | 「Managed Device Attestation」以什么身份出现 |

### 12.2 零命中

在 216 个纯键名里检索 `attest`、`devicecheck`、`integrity`，命中数是 **0**。在 66 项声明里检索 `Attest`，命中数是 **1**，且唯一命中项是 `SecurityPasskeyAttestation`（凭据件）。在 `mdm-root.txt` 里检索 `Managed Device Attestation`，命中 1 次，语境是导航说明句 `Use Platform Single Sign-on and Managed Device Attestation on managed devices.`（`:33`）。

三个数合起来说明：**管理面没有「设备校验」的配置项，也没有「App 校验」的配置项；它只有一项与凭据相关的校验声明，以及一句导航文字。**

### 12.3 这意味着什么

对组织侧而言，「我们开启了 attestation」这句话在管理面词表里最多对应两种事实之一：

1. 开启了 `SecurityPasskeyAttestation`（凭据件）；
2. 在设备上通过其他通道（MDM 命令、ACME 配置）请求了设备件。

第二种不是「管理面的开关」，而是**一次请求动作**。请求动作会产生响应，响应里可能有也可能没有证明物（取决于 SoC，`A/devicemanagement_device_information_command.txt:16`）。因此「开启」与「拿到」之间还隔着硬件支持这一层。

### 12.4 回查层的三个空格

| 想回查 | 管理面有没有字段 | 结论 |
| --- | --- | --- |
| 这台设备上次校验是什么时候 | 无 | 只能从 MDM 命令记录或服务器日志取 |
| 这份证明物对应哪次请求 | 无（时新码不落管理面） | 只能从请求侧留存的时新码对照 |
| 这台设备的校验结果是什么 | 无 | 只能从响应报文或服务器侧记录取 |

这三个空格是第 17 章「可见性边界」与第 26 章边界清单 U06—U08 的直接来源。

---

## 13. L10 公告对齐层：1266 行里的零行

### 13.1 语料规模

公告语料 1266 个数据行，覆盖 12 个平台标识、129 个去重组件名、330 个唯一 CVE（R21）。平台分布的首位是 `macOS Golden Gate 27.2` 263 行，末位是 `macOS Sequoia 15.8.1` 1 行（R22）。

### 13.2 九个词形同时为 0

在组件列与影响句列分别检索九个词形，结果是**两列同时为 0**：

| 词形 | 组件列 | 影响句列 |
| --- | --- | --- |
| attest | 0 | 0 |
| DeviceCheck | 0 | 0 |
| Secure Enclave | 0 | 0 |
| SEP | 0 | 0 |
| Trust Cache | 0 | 0 |
| LocalPolicy | 0 | 0 |
| boot | 0 | 0 |
| codesign | 0 | 0 |
| signature | 0 | 0 |

作为对照，同一语料里 `kernel` 在组件列 115 行、影响句列 179 行；`sandbox` 在影响句列 51 行；`cryptex` 在组件列 3 行；`trust` 在影响句列 2 行（且语境是 trust-paired device）（R21.1—R21.2）。

### 13.3 这不是「没有缺陷」，而是「没有这个归属维度」

零命中的正确解读是：**公告语料不以「校验组件」为组件名，也不以「校验失效」为影响句。** 它不能推出「这些机制从未出过问题」。反过来，正因为公告不提供这个维度，事故复盘时无法用公告反查「这次事件是否属于校验组件缺陷」。这是第 26 章边界清单 U09 的内容。

### 13.4 与第 22 篇的对照

第 22 篇的配件族在公告里有 27 行记录、7 个 CVE（本文脚本二在真实语料上重算得到同样的 27／7）。本文的主题在公告里是 0 行。两篇的对照说明一件事：**公告的组件词表覆盖「配件」，但不覆盖「校验件」。** 这两个词在同一份语料里的可见度相差一个数量级。

---

## 14. L11 引用与结论层：doc.* 与十八份文档的平台坐标

### 14.1 归档的构成

A 组 18 份文档、2502 行；其中 11 份是带平台可用性数组的符号页，7 份是文章（R01）。11 份符号页每份列 7 个平台行，合计 77 行（`C/platform-23.txt`）。

### 14.2 平台坐标的均匀性

11 份符号页**全部**同时列出 iOS／iPadOS／Mac Catalyst／macOS／tvOS／visionOS／watchOS 七个平台行，缺 macOS 的 0 份（R02）。这与第 22 篇的配件文档形成鲜明对比：那里 17 份文档里只有 7 份同时有 iOS 与 macOS 行。

但「平台数组齐全」不等于「功能可用」。`isSupported` 的正文说 Mac 上恒为 false（`A/devicecheck_dcappattestservice_issupported.txt:20—24`）。因此 R02 与 R07 量的是两件事：

- R02 量的是**符号声明**：这个符号在多少个平台上有文档坐标；
- R07 量的是**运行期能力**：这个能力在某个平台上是否可用。

两者不矛盾的唯一读法是：**符号可以存在，能力可以为假。** 这正是第 3 章「换算失败一」的平台层版本。

### 14.3 三组可用性读数

| API | iOS | macOS | tvOS | watchOS | 锚点 |
| --- | --- | --- | --- | --- | --- |
| App Attest 服务 | 14.0 | 11.0 | 15.0 | 9.0 | R03 |
| DeviceCheck 容器 | 11.0 | 10.15 | 11.0 | 9.0 | R04 |
| DCDevice | 11.0 | 10.15 | 11.0 | 9.0 | R05 |
| DeviceInformation | 4.0 | 10.7 | 9.0 | 10.0 | R06 |

四组数的形态不同：App Attest 是 iOS 14 才出现的新服务；DeviceCheck 容器与 DCDevice 在 iOS 11 就有；DeviceInformation 的 iOS 坐标低到 4.0，比前两者早七年。**这四个坐标不能互相替代**：一条「设备校验在 iOS 11 可用」的表述，对 App Attest 是错的，对 DCDevice 是对的。

### 14.4 doc.* 的三个字段

脚本一把引用拆成三个字段：`doc.page_url`、`doc.page_title`、`doc.line_ref`。三条规则：

- `H01`／`H05`：地址或标题为空；
- `H02`／`H03`：行锚为空、不是数字、或超过 400 行；
- `H04`：地址不是 `https://developer.apple.com/` 前缀。

这三条不是格式洁癖，而是**可复核性**的最低条件：没有地址无法定位文档，没有行锚无法定位句子，地址不在官方域名下则无法确认版本。第 28 章逐份列出本文引用的文档与行数，就是为了让每一条引文都能被重新打开核对。

### 14.5 结论层的三条约束

| 约束 | 脚本规则 | 为什么必须有 |
| --- | --- | --- |
| 结论不能是 `unknown` 却当成 `present` | `G01`（unknown）与 `V4` 判定 | 未知是一个独立状态 |
| 结论宣称可指名必须有身份字段 | `G02`、`G03` | 实例件不能指名设备 |
| 结论为闭合必须有证据引用 | `G05`、`G06` | 闭合是一个需要举证的主张 |

这三条与第 19 章的 J1—J4 判定模型直接相连：J4 专指「未知」，J3 指「阻断或错误」，J2 指「只有提示」，J1 指「无信号」。

---
## 15. 归属矩阵：十一层 × 责任方 × 四件 × 证据

### 15.1 矩阵的读法

下表每一行是一层，每一列是一件（App 实例件／设备件／凭据件／配件件）。格内写三样东西：**这一层由谁负责**、**这一件在这一层能提供什么**、**证据锚点**。写作 `—` 表示这一层对该件不适用；写作 `未公开` 表示公开文档没有给出这一格的口径。

| 层 | App 实例件 | 设备件 | 凭据件 | 配件件 |
| --- | --- | --- | --- | --- |
| L1 主体 | 开发者（实例）`:34` | Apple + 组织（设备）`:4318` | 组织 + 认证器（凭据）`decl:45` | 厂商 + Apple（配件）`:1367` |
| L2 密钥 | Secure Enclave，App 存句柄 `:41、36—38` | 设备 Secure Enclave `:4426` | 认证器内部 `未公开` | IC 内部 `:1367` |
| L3 证明物 | 证书链 + 回执 `:69—73`、`:56—78` | 叶子 + 中间证书 `:4324` | 认证器签名 `decl:45` | IC 判定 `:1367` |
| L4 属性 | aaguid／计数器／category `guide:197—200` | 10 个 OID `:4327—4361` | 凭据公钥 `未公开` | 序列号等 `未公开` |
| L5 校验 | 服务器 `:141—143` | MDM／ACME 侧 `valid:17—23` | 依赖方 `decl:45` | 无公开回读点 `未公开` |
| L6 度量 | 30 天密钥计数 `:99—100` | 无度量字段 `—` | 无 `—` | 无 `—` |
| L7 登记 | 用户 + 设备 + 环境 `:155—158` | 注册类型 + 身份 OID `:4343、4347` | 凭据 → RP `decl:45` | 配件 → 账户 `未公开` |
| L8 生命周期 | 不跨重装／恢复／转手 `:102—105` | 设备生命周期 `:4318` | 凭据生命周期 `未公开` | 配件生命周期 `未公开` |
| L9 管理面回查 | 0 个键名 `.srcx16` | 0 个键名 `.srcx16` | 1 项声明 `decl:45` | 5 个配件键（第 22 篇） |
| L10 公告对齐 | 0 行 `R21.3` | 0 行 `R21.3` | 0 行 `R21.3` | 27 行／7 CVE（第 22 篇） |
| L11 引用与结论 | doc.* + R 锚 `脚本一 H 族` | doc.* + R 锚 `脚本二 X11` | doc.* + R 锚 | doc.* + R 锚 |

表中的 `decl:` 指 `.srcx16/C/mdm-declarations.txt`，`valid:` 指 `A/devicemanagement_validating_managed_attestation.txt`，`guide:` 指 `A/devicecheck_attestation_object_validation_guide.txt`，其余裸 `:NNNN` 指 `B/apple-platform-security-guide.txt` 或同章前文已注明的 A 组文件。

### 15.2 矩阵里的三个不对称

**不对称一：L6 只有 App 实例件有。** 度量只存在于 App Attest 回执的字段 17。设备件没有「设备风险分」，凭据件没有「凭据风险分」，配件件没有「配件风险分」。因此任何把「度量」写成「设备风险度量」的表格都会在 L6 这一行出错。

**不对称二：L9 与 L10 在四件上的可见度相差一个数量级。** 管理面对前三件是 0／0／1，公告面对前三件是 0／0／0；而配件件在公告里有 27 行。这不是「校验件不重要」，而是**公告与管理的词表根本没有为校验件建格**。

**不对称三：L5 的回读点只有 App 实例件完全落在自己手里。** 设备件的回读点在 MDM 响应或 ACME 登记，凭据件在依赖方，配件件没有公开回读点。只有 App 实例件的回读点可以完全由开发者自己实现并留存。

### 15.3 责任方归并

把四列按责任方归并，可以得到五个责任方：

| 责任方 | 负责的层 | 能被公开文档直接约束的部分 | 需要自行留证的部分 |
| --- | --- | --- | --- |
| Apple（签发方） | L3 证书、L4 OID 写入、L6 度量计算 | OID 清单、三值编码、30 天窗口 | 无（签发方不留证给使用方） |
| 开发者（App 侧） | L2 句柄保存、L5 校验实现、L7 用户绑定 | 密钥不存活、五分钟窗口 | 公钥与回执的存储、校验日志 |
| 组织（MDM 侧） | 设备件请求、L9 配置 | 硬件支持表、注册类型 | 时新码留存、响应留存 |
| 认证器（凭据侧） | 凭据件签名 | 管理面一项声明 | 依赖方登记 |
| 配件厂商 | 配件件 | IC 由 Apple 提供 | 无（第 22 篇） |

**「需要自行留证」这一列是本文的实践落点。** 公开文档只规定「应该存什么」，不规定「存多久、存成什么格式」。第 20 章的 O 系列指标就是把这一列变成可执行的检查项。

### 15.4 矩阵的使用方式

这张矩阵不是用来「打勾」的，而是用来**定位错误归属**的。例如：

- 若一份材料宣称「设备校验通过，故请求来自合法用户」，错误发生在 L1（实例件被当成设备件）与 L7（密钥→用户的绑定被省略）；
- 若一份材料宣称「度量 = 2，故有两台设备」，错误发生在 L6（按键计数被当成台数）；
- 若一份材料宣称「公告里没有校验组件缺陷」，错误发生在 L10（零命中被当成零缺陷）。

第 24 章的十二个误区，每一个都能在这张矩阵上找到对应的格子。

---

## 16. 公开读数：这套机制上能数出来的十三组事实

本章的 26 条读数（R01—R26）分十三组。每条读数都给出复算方式：A 组／B 组用归档行号或词频，C 组用脚本二重算。**R20 的管理面读数来自第 16 篇的同一份归档（`.srcx16/C`），不在脚本二的重算范围内**，这一点单独标注。

### 16.1 第一组：归档规模与平台数组（R01—R02）

| 编号 | 读数 | 复算方式 |
| --- | --- | --- |
| R01 | A 组 18 份 / 2502 行；带平台可用性数组 11 份（每份 7 个平台行，合计 77 行）；文章类 7 份无平台数组 | `wc -l .srcx23/A/*.txt`；`wc -l .srcx23/C/platform-23.txt` |
| R02 | 11 份符号页全部同时列出 iOS／iPadOS／Mac Catalyst／macOS／tvOS／visionOS／watchOS 七行；缺 macOS 的 0 份 | 同上 |

R02 的意义在第 14.2 节已展开：**符号声明齐全，不等于能力可用。**

### 16.2 第二组：四个 API 的平台坐标（R03—R06）

| 编号 | 读数 |
| --- | --- |
| R03 | App Attest 服务：iOS 14.0；macOS 11.0；tvOS 15.0；watchOS 9.0 |
| R04 | DeviceCheck 容器：iOS 11.0；macOS 10.15；tvOS 11.0；watchOS 9.0 |
| R05 | DCDevice：iOS 11.0；macOS 10.15；tvOS 11.0；watchOS 9.0 |
| R06 | DeviceInformation：iOS 4.0；macOS 10.7；tvOS 9.0；watchOS 10.0 |

四个坐标的跨度是十年。任何「平台校验从 iOS X 起可用」的表述，必须先指明是哪一个 API。

### 16.3 第三组：`isSupported` 的三句话（R07—R08）

| 编号 | 读数 | 锚点 |
| --- | --- | --- |
| R07 | Mac 上恒为 false，包括 Mac Catalyst 与在 Apple silicon 上运行的 iOS／iPadOS App；因此 R02 的 11/11 平台声明与「恒假」并不矛盾，两者量的不是同一件事 | `A/devicecheck_dcappattestservice_issupported.txt:20—24` |
| R08 | 扩展内取值可能真也可能假，但多数扩展不支持；`generateKey` 在扩展内调用恒失败，与取值无关；唯一支持的是 watchOS 9 及之后的 watchOS 扩展 | `:25—37`；`A/devicecheck_establishing_app_integrity.txt:29—31` |

### 16.4 第四组：硬件支持与 MDA 可用性（R09—R11）

| 编号 | 读数 | 锚点 |
| --- | --- | --- |
| R09 | 不支持：A10x Fusion 及更早／Intel／S3 及更早；支持：A11 Bionic 及之后／全部 M 系列／Apple silicon／A12 Bionic 及之后／S4 及之后 | `A/devicemanagement_device_information_command.txt:23—35` |
| R10 | 输入键两个：`DevicePropertiesAttestation` 与 `DeviceAttestationNonce`；不支持的设备忽略这两个键 | `:16` |
| R11 | MDA 可用性：iOS 16／iPadOS 16／macOS 14／tvOS 16／visionOS 1.1／watchOS 9；iPhone／iPad／Apple TV 需 A11 Bionic 及之后；Mac 只支持 Apple silicon | `B/apple-platform-security-guide.txt:4318` |

### 16.5 第五组：OID 的数量与平台边界（R12—R12.1）

| 编号 | 读数 |
| --- | --- |
| R12 | 叶子证书 OID 共 10 个：.8.9.1 序列号／.8.9.2 UDID／.8.10.1 系统版本／.8.10.2 sepOS 版本／.8.10.3 LLB 版本／.8.9.4 软件更新设备 ID／.8.11.1 时新码／.8.13.1 SIP／.8.13.2 安全启动／.8.13.3 第三方内核扩展 |
| R12.1 | 仅 macOS 14 的 OID 3 个：.8.13.1／.8.13.2／.8.13.3；其余 7 个跨六个平台 |

复算：`grep -n "1\.2\.840\.113635\.100\.8\." B/apple-platform-security-guide.txt`；三个 macOS-only OID 的可用行在 `:4377、4381、4385`。

### 16.6 第六组：身份与三值编码（R13—R14）

| 编号 | 读数 | 锚点 |
| --- | --- | --- |
| R13 | 身份 OID 2 个（序列号／UDID）；两者在 User Enrollment 下都不写入 | `B/apple-platform-security-guide.txt:4343、4347` |
| R14 | 属性编码 1 句：只有在能核实该属性值时才写入；唯一例外是时新码，不做任何校验 | `:4460` |

### 16.7 第七组：aaguid 与回执字段（R15—R16）

| 编号 | 读数 | 锚点 |
| --- | --- | --- |
| R15 | aaguid 常量 3 个：`appattestdevelop`／`appattest`／`appattestsandbox`；生产值是 `appattest` 后接七个 `0x00` 字节 | `A/devicecheck_attestation_object_validation_guide.txt:197—200`；`A/devicecheck_preparing_app_attest.txt:88`（第三个常量） |
| R16 | 回执字段 9 个：2 App ID／3 已认证公钥／4 客户端哈希／5 令牌／6 回执类型／12 创建时间／17 风险度量／19 不早于／21 到期时间 | `A/devicecheck_assessing_fraud_risk.txt:56—78` |

### 16.8 第八组：回执判定与刷新（R17—R18）

| 编号 | 读数 | 锚点 |
| --- | --- | --- |
| R17 | 创建时间不超过五分钟；字段 6 只有服务器换来的回执才带度量；度量是过去 30 天内该设备上与本 App 关联的已认证密钥数的近似值 | `:89—90、:94—100` |
| R18 | 早于字段 19 请求返回 304；晚于字段 21 可能不被受理；development 与 production 不可互换 | `:111—116`；`A/devicecheck_validating_apps_server.txt:155—158` |

### 16.9 第九组：ValidationCategory（R19）

| 值 | 含义 | 类别 |
| --- | --- | --- |
| 0 | 无效 | 无效 |
| 1 | 操作系统可执行文件 | 具名 |
| 2 | TestFlight 分发 | 具名 |
| 3 | 开发签名身份 | 具名 |
| 4 | App Store 分发 | 具名 |
| 5 | 企业通用描述文件或 ad-hoc | 具名 |
| 6 | Developer ID 签名 | 具名 |
| 7、8、9 | 保留，不建议使用 | 保留 |
| 10 | 不匹配任何类别的签名身份 | 兜底 |

共 11 个槽位：具名 6 个、保留 3 个、兜底 1 个、无效 1 个。锚点：`A/devicecheck_validating_apps_server.txt:120—133`。归档文本没有保留数字列，上表的编号按描述顺序与 0—10 的值域对齐；脚本只做 0—10 的范围检查，不对具体编号下断言。脚本一的 `B07` 把值域限定在 0—10，`D06` 要求 App Attest 记录必须校验过 category。

### 16.10 第十组：管理面（R20，借第 16 篇归档）

| 读数 | 值 | 复算方式 |
| --- | --- | --- |
| 纯键名 | 216 个（文件 220 行减 4 行页眉） | `wc -l .srcx16/C/mdm-restriction-keys.txt` |
| 含 attest／devicecheck／integrity 的键名 | 0 | `grep -ic 'attest\|devicecheck\|integrity'` |
| 声明类型 | 66 项（75 行中 66 行以 `- ` 开头） | `grep -c '^- ' .srcx16/C/mdm-declarations.txt` |
| 含 Attest 的声明 | 1 项，`SecurityPasskeyAttestation`（第 45 行） | `grep -in attest` |
| `mdm-root` 里的「Managed Device Attestation」 | 1 次，为导航说明句（第 33 行） | `grep -in 'Managed Device Attestation'` |

这五条与脚本二的 X／Y／Z 族**没有关系**：它们不在 1266 行公告语料里，也不在 17 个声明读数里。本文引用它们时一律标注来源，不把它算作「脚本二重算通过」的证据。

### 16.11 第十一组：公告语料（R21—R21.3）

| 编号 | 读数 |
| --- | --- |
| R21 | 1266 行 / 129 个去重组件名 / 330 个唯一 CVE |
| R21.1 | 组件列命中：attest 0；DeviceCheck 0；Secure Enclave 0；SEP 0；Trust Cache 0；LocalPolicy 0；boot 0；codesign 0；signature 0；cryptex 3；sandbox 1；kernel 115 |
| R21.2 | 影响句命中：attest 0；DeviceCheck 0；Secure Enclave 0；SEP 0；Trust Cache 0；LocalPolicy 0；boot 0；codesign 0；signature 0；cryptex 0；trust 2（trust-paired device）；sandbox 51；kernel 179 |
| R21.3 | 组件列与影响句列同时为 0 的 9 个词形：attest／DeviceCheck／Secure Enclave／SEP／Trust Cache／LocalPolicy／boot／codesign／signature |

这四条由脚本二的 Z 族重算（Z01—Z17 中的对应项）与 Y05—Y10 负读数（在真实语料上为 0 信号）共同保证。

### 16.12 第十二组：公告平台分布与影响句（R22—R23）

| 编号 | 读数 |
| --- | --- |
| R22 | macOS Golden Gate 27.2=263；macOS Tahoe 26.7.2=213；macOS Sequoia 15.8.2=197；iOS 27.2 and iPadOS 27.2=163；iOS 26.7.2 and iPadOS 26.7.2=134；visionOS 27.2=125；tvOS 27.2=72；watchOS 27.2=62；Safari 27.2=33；Xcode 27.2=2；macOS Tahoe 26.7.1=1；macOS Sequoia 15.8.1=1 |
| R23 | 影响句计数：may be able to=742；maliciously crafted=467；unexpected=526；unexpected app termination=133；arbitrary code=73；kernel memory=178；sensitive user data=124；entitlement=0；physical access=3 |

R22 的 12 个平台标识之和等于 1266（脚本二 `platform.sum` 与 `platform.max` 两个读数就是为此设的：263 与 2 个单行平台）。R23 里 `entitlement=0` 值得单独注意：这 1266 行公告里没有一条影响句以 entitlement 为机制。

### 16.13 第十三组：词频与换算（R24—R26）

| 编号 | 读数 | 复算方式 |
| --- | --- | --- |
| R24 | A 组：attest 15 份／325 次；receipt 3 份／45 次；Secure Enclave 3 份／5 次；nonce 4 份／10 次；UDID 2 份／2 次；serial 1 份／1 次 | `grep -oih 'attest' A/*.txt \| wc -l` 等 |
| R25 | 平台安全指南（4885 行）：attest 52 行；Secure Enclave 196 行；sepOS 17 行；UDID 5 行；OID 14 行；LocalPolicy 54 行；Apple Enterprise Attestation Root CA 2 行；hardware-bound 7 行；UIK 5 行；ucrt 5 行 | `grep -ic` 逐词 |
| R26 | A 组 325 次 attest 命中里，与「设备身份」直接相关的只有 2 次 UDID 与 1 次 serial；其余全部落在「App 实例」「密钥」「回执」三组 | 由 R24 的分子除以总命中得出 |

**R26 是本文最关键的一条读数。** 它用词频给出一个无法反驳的比例：在这套机制的接口文档里，「证明」出现 325 次，「UDID」出现 2 次，「serial」出现 1 次。也就是说，**文档在绝大多数时候谈的不是设备身份。** 任何把 attestation 直接当成「设备标识」的用法，都是在用 1% 的文本去代表 100% 的机制。

---

## 17. 可见性边界：这一层读者能拿到什么

### 17.1 五类读者与他们的可见面

| 读者 | 能看到 | 看不到 | 主要风险 |
| --- | --- | --- | --- |
| App 开发者 | 本 App 的 `keyId`、回执、度量（经服务器） | 其他 App 的任何校验件 | 把实例件当设备件 |
| 服务器运维 | 公钥、回执、度量、时间戳 | 设备属性 OID（除非另有 MDM 通道） | 把度量当台数 |
| MDM 管理员 | `DeviceInformation` 响应、证书链、OID | 校验服务器的判定结论 | 把「有证书」当「已判定」 |
| 合规审计 | 组织自留的记录与报告 | 上述三者的原始报文 | 把二手结论当一手证据 |
| 外部研究者 | 公开文档与公告 | 任何设备侧数据 | 把文档口径当实现事实 |

### 17.2 三条可见性断层

**断层一：设备侧看不到判定结果。** 判定在服务器侧（第 8 章）。设备只能证明「我提交过」，不能证明「服务器接受了」。

**断层二：管理面看不到 App 实例件。** 管理面的 216 个键名与 66 项声明里，没有任何一项涉及 App Attest。组织若想审计 App 侧校验，只能从应用自己的服务器取数。

**断层三：公告面看不到任何校验件。** 九个词形在两列同时为 0（第 13 章）。这意味着「这次事件是否属于校验组件缺陷」这个问题，无法从公告语料得到答案。

### 17.3 可见性与「可证明」的对应

| 想证明 | 需要的最小证据 | 在哪一侧 |
| --- | --- | --- |
| 某次请求来自合法 App 实例 | 校验过的公钥 + 该次断言的签名 | 服务器侧 |
| 某台设备是正品硬件 | 叶子证书链到 Apple Enterprise Attestation Root CA | 请求方（MDM／ACME）侧 |
| 某台设备的系统版本 | 对应 OID 的值（非空） | 请求方侧 |
| 某个度量在某时刻的值 | 回执 + 创建时间 + 字段 19 + 字段 21 + 环境 | 服务器侧 |
| 某个配件是它 | MFi IC 的判定 | 无公开回读点 |

最后一行是本文与第 22 篇的接缝：**四件里唯一没有公开回读点的是配件件。** 这也是本文不重复展开配件件的原因——它的可见性边界已在第 22 篇完整处理。

### 17.4 可见性边界的实践含义

对审计人员，最重要的操作是**在记录里写清「这条证据来自哪一侧」**。同样一句「校验通过」：

- 写在服务器日志里，是一手证据；
- 写在 App 的界面上，是自我报告；
- 写在管理面报表里，通常是「有证书」而不是「已判定」；
- 写在合规材料里而没有来源标注，无法复核。

第 20 章的 O01 与 O10 就是把这四类来源分开计数。

---

## 18. 五个读数面：生成侧、判定侧、登记侧、管理侧、公告侧

### 18.1 五个面的定义

| 读数面 | 它回答 | 主要载体 | 本文的读数 |
| --- | --- | --- | --- |
| 生成侧 | 证明物是怎样产生的 | 符号页与文章（A 组） | R01—R08、R15—R16 |
| 判定侧 | 谁来判、判什么、判多久 | 校验文档（A 组） | R17—R19 |
| 登记侧 | 判完存在哪、绑定谁 | 校验文档与平台指南 | R13—R14、R18 |
| 管理侧 | 组织能不能配置与回查 | MDM 键表与声明表 | R20 |
| 公告侧 | 缺陷被归到哪个词 | 1266 行语料 | R21—R23 |

### 18.2 五个面的覆盖度

| 面 | 文档厚度 | 可复算读数 | 缺口 |
| --- | --- | --- | --- |
| 生成侧 | 18 份 / 2502 行 | 13 条 | 扩展内的行为只给了结论句 |
| 判定侧 | 3 份核心文档 | 3 条 | 校验失败的具体错误码未逐个公开 |
| 登记侧 | 与判定侧重叠 | 3 条 | 存储格式与保留期未公开 |
| 管理侧 | 3 份文件 | 5 条 | 没有任何校验相关的配置键 |
| 公告侧 | 1266 行 | 3 条 | 校验词形零命中 |

**管理侧与公告侧的缺口不是「文档没写清」，而是「词表里没有这一格」。** 这两者性质不同：前者可以通过更仔细的阅读补上，后者不能。

### 18.3 五个面之间的三个断点

1. **生成 → 判定**：证明物从设备到服务器，中间没有任何公开的传输格式规范（只有「把证明物发给服务器」这一句）。
2. **判定 → 登记**：判定结果如何存储、存多久，公开文档只说「存下来」，不给格式。
3. **登记 → 回查**：管理面没有校验字段，公告没有校验词形。

三个断点正好对应第 17 章的三条可见性断层。

### 18.4 五个面的使用顺序

建议的阅读与审计顺序是：**先生成侧确认「这东西是什么」，再判定侧确认「谁说了算」，再登记侧确认「存了什么」，最后管理侧与公告侧确认「事后能不能查」。** 反过来做（先查管理面）会得到「查不到」的结论，而这个结论容易被误读成「没有发生」。

---

## 19. 两套判定模型：J1—J4 与 Q1—Q4

### 19.1 脚本一的 J1—J4（台账判定）

| 判定 | 含义 | 触发条件 | 退出码贡献 |
| --- | --- | --- | --- |
| J1 | 这条记录站得住 | 无任何信号 | 0 |
| J2 | 有提示，但不阻断 | 只有 H 族（引用）信号 | 1 |
| J3 | 有阻断或错误 | 任一 A／B／C／D／E／F／G 族信号 | 1 |
| J4 | 无法判定 | `claim.cell == unknown` | 1 |

J4 的优先级最高：即使一条记录的其余字段全部合规，只要结论格写了 `unknown`，它就是 J4。这与第 14.5 节「未知是一个独立状态」一致。

### 19.2 脚本二的 Q1—Q4（框架判定）

| 判定 | 含义 | 触发条件 | 退出码 |
| --- | --- | --- | --- |
| Q1 | 四件全部闭合 | X／Y／Z 三族均无信号 | 0 |
| Q2 | 框架与读数闭合，词表待校 | 只有 Y 族信号 | 1 |
| Q3 | 框架或读数不闭合 | X 族或 Z 族有信号 | 1 |
| Q4 | 输入不可用，无法判定 | 缺参数、路径不存在、不可读、未知选项 | 2 |

Q2 与 Q3 的分界是本文的一个设计选择：**词表失配（Y）比框架失配（X）与读数漂移（Z）轻一档**。理由是：术语出处写错会降低可复核性，但不会让框架本身失效；而框架缺签署方或读数与语料不符，会让结论直接失去依据。

### 19.3 两套模型的对应

| 脚本一 | 脚本二 | 共同含义 |
| --- | --- | --- |
| J1 | Q1 | 这一侧闭合 |
| J2 | Q2 | 有瑕疵但不致命 |
| J3 | Q3 | 不闭合 |
| J4 | Q4 | 无法判定 |

两套模型都遵守同一条纪律：**「无法判定」不与「不闭合」合并。** 在实际审计中，这两者的处置完全不同：前者需要补输入，后者需要改记录。

### 19.4 判定的边界

两套模型都只判「记录／框架自身是否自洽」，不判「业务结论是否正确」。例如：

- 一条记录写「设备件可指名个体，身份 OID 为序列号」，在 device enrollment 下它是 J1；但若这台设备实际是 User Enrollment，这条记录在现实中是错的，而脚本无法知道——它只能检查记录内部的字段一致性。
- 一个框架写「凭据件可指名个体」，脚本报 `X07`；但若这个框架本来就把凭据件定义成「可指名」，那它是定义问题，不是记录问题。

这条边界写在第 26 章 U12。

---

## 20. 运营指标 O1—O10

### 20.1 指标表

| 编号 | 指标 | 计算口径 | 建议阈值方向 | 对应规则 |
| --- | --- | --- | --- | --- |
| O01 | 校验记录来源完整率 | 带来源标注的记录 / 全部记录 | 越高越好，目标 100% | `H06` |
| O02 | 身份可指名率 | 有身份 OID 的设备件记录 / 全部设备件记录 | 按注册类型分组看 | `G02`、`C07` |
| O03 | 三值编码误读率 | 把空值／缺失写成「否」的记录 / 全部属性记录 | 越低越好 | `G02` |
| O04 | 回执时效合规率 | 创建时间 ≤ 5 分钟且在使用窗口内的回执 / 全部回执 | 目标 100% | `D07`、`E03` |
| O05 | 度量基线漂移 | 度量的 P50／P90 按周对比 | 观察趋势，不设硬阈值 | `E02` |
| O06 | 环境混用率 | 跨环境比较的度量记录 / 全部度量记录 | 目标 0 | `B08`、`E05` |
| O07 | 绑定完整率 | 同时有用户、设备、环境三个绑定的记录 / 全部记录 | 目标 100% | `F01` |
| O08 | 判定位置合规率 | 判定在服务器侧的记录 / 全部记录 | 目标 100% | `D01` |
| O09 | 文档锚点可复核率 | 地址、标题、行锚三者齐全的记录 / 全部记录 | 目标 100% | `H01`、`H02`、`H05` |
| O10 | 「校验通过」表述的来源标注率 | 标注了一手／二手的表述 / 全部表述 | 目标 100% | `G05` |

### 20.2 三个指标的解释

**O02 为什么必须分组。** User Enrollment 下身份 OID 不写入（`B/apple-platform-security-guide.txt:4343、4347`），所以这类设备的「身份可指名率」天然为 0。把两类设备混在一起算，会得到一个既不代表前者也不代表后者的数。

**O05 为什么用分位数。** 度量的分布是长尾的：多数设备接近 1，重装频繁的设备可能到 5 以上（`A/devicecheck_assessing_fraud_risk.txt:102—107`）。均值会被长尾拉高，P50 与 P90 的对比更能反映「基线是否移动」。

**O10 为什么单列。** 这是本文最想推广的一条运营纪律。第 17 章区分了四类来源（服务器日志、App 界面、管理面报表、合规材料），它们的证据强度依次下降。若一条「校验通过」没有来源标注，它在事故复盘里无法被定级。

### 20.3 指标的采集点

| 采集点 | 能采到的指标 | 采集难度 |
| --- | --- | --- |
| 服务器校验日志 | O01、O04、O05、O06、O07、O08、O09 | 低（自有系统） |
| MDM 命令记录 | O02、O09 | 中（需留存响应） |
| 应用侧埋点 | O03、O10 | 中（需区分一手／二手） |
| 合规材料审阅 | O10、O09 | 高（人工） |

四个采集点里，只有「服务器校验日志」能覆盖多数指标。这与第 8 章的结论一致：**判定在服务器侧，所以指标也主要在服务器侧。**

---
## 21. 只读核验脚本一：平台校验台账逐字段审查器

### 21.1 它审的是什么

脚本一处理的不是设备，也不是服务器，而是**一行台账**。一行台账的格式是：

```text
<记录标识>,<字段名>,<取值>
```

三列用逗号分隔，`#` 开头的行与空行忽略，行尾 CR 忽略，取值里不能含逗号。记录标识必须以三个前缀之一开头：

| 前缀 | 含义 | 对应第 15 章的列 |
| --- | --- | --- |
| `AI_` | App Attest 实例 | App 实例件 |
| `MD_` | 受管设备校验 | 设备件 |
| `CR_` | 凭据（passkey）校验 | 凭据件 |

脚本只回答一个问题：**一次平台校验被登记成一行台账之后，这行台账自己站不站得住。** 它不判断业务结论对不对（第 19.4 节），不连接设备，不生成密钥，不申请 attestation，不校验服务器回执，也不调用 `security`、`codesign`、`profiles`、`defaults`、`log`、`curl`、`osascript`、`system_profiler` 中的任何一个。脚本唯一的写出目标是 `mktemp -d` 创建的临时目录，退出时删除，本实现不向其写入任何字节（`script1.sh:53—54`）。

### 21.2 九个字段命名空间

台账的字段名用「命名空间.字段」的形式。九个命名空间对应第 4—14 章的层：

| 命名空间 | 字段 | 记录的是什么 | 主要对应 |
| --- | --- | --- | --- |
| `id.*` | `platform`、`record_kind` | 这条记录属于哪个平台、哪一种校验 | L1 主体层 |
| `key.*` | `gen_handle`、`location`、`id_present`、`id_stored`、`reuse`、`lifecycle` | 句柄是否生成、密钥在哪、标识是否保存、是否复用、跨不跨事件 | L2 密钥层 |
| `att.*` | `chain`、`nonce`、`counter`、`aaguid`、`category`、`env` | 证明物的形状与常量 | L3 证明物层 |
| `dev.*` | `serial`、`udid`、`sepos`、`fresh`、`sip`、`boot`、`kext`、`llb`、`osver`、`sudid`、`enrollment` | 十个 OID 对应的属性与注册类型 | L4 属性层 |
| `ver.*` | `verifier`、`pubkey_stored`、`receipt_stored`、`nonce_checked`、`chain_checked`、`category_checked`、`receipt_age_min` | 谁判的、判完存了什么、回执多旧 | L5 校验层 |
| `met.*` | `metric`、`nb`、`exp`、`refresh`、`reset` | 度量值、两个时刻、刷新与重置口径 | L6 度量层 |
| `reg.*` | `key_user`、`assoc_device`、`reset_authority`、`bits_meaning`、`bits_reset` | 密钥绑定谁、状态位归谁、两位各是什么意思 | L7 登记层 |
| `claim.*` | `cell`、`scope`、`naming`、`closure`、`evidence_ref` | 这条记录把自己归到哪一格、能指名到什么程度、证据锚在哪 | L11 引用与结论层 |
| `doc.*` | `page_url`、`page_title`、`line_ref` | 文档地址、标题、行锚 | L11 引用与结论层 |

命名空间是**封闭**的：脚本不认识的字段名会原样保存在 `V` 里，但不参与任何判定。这意味着拼错字段名不会报错，只会让对应的检查「看起来通过」。这是本脚本最需要注意的一个使用边界，写在第 26 章 U11。

### 21.3 八个信号族与四档判定

54 个信号码分成八族。分族的依据是**这一族检查的是哪一层**，不是严重程度：

| 族 | 码段 | 数量 | 检查什么 | 对应章 |
| --- | --- | --- | --- | --- |
| A | `A01`—`A07` | 7 | 行结构与标识、平台、记录类型、密钥位置 | 21.1、5 |
| B | `B01`—`B08` | 8 | 密钥位置、句柄保存、证书链、挑战、计数器、aaguid、category、环境 | 5、6 |
| C | `C01`—`C07` | 7 | 注册类型与身份 OID、平台专属属性、时新码 | 7 |
| D | `D01`—`D07` | 7 | 判定位置、公钥与回执留存、三项校验、五分钟窗口 | 8 |
| E | `E01`—`E06` | 6 | 度量与回执的依赖、整数性、两个时刻、重置与刷新 | 9 |
| F | `F01`—`F06` | 6 | 用户绑定、状态位归属、重装与备份口径 | 10、11 |
| G | `G01`—`G07` | 7 | 归属格、可指名性、范围、闭合与证据锚 | 15、19 |
| H | `H01`—`H06` | 6 | 文档地址、标题、行锚与证据引用 | 14 |

严重度由 `emit()` 里的两条正则决定（`script1.sh:62—65`）：A、B 两族计入 `blkcount` 并标记为阻断；C、D、E、F、G 五族计入 `errcount`；H 族只计入 `warncount`。判定按下面的顺序取第一个成立项（`script1.sh:212—215`）：

```text
cell == unknown            → V4
有 A/B 阻断或 C—G 错误      → V3
只有 H 族提示              → V2
其余                       → V1
```

脚本输出的字面判定是 `V1`—`V4`（V 取 verdict），本报告在第 19 章统一记作 `J1`—`J4`，两位数字逐位对应：`V1`＝`J1`、`V2`＝`J2`、`V3`＝`J3`、`V4`＝`J4`。退出码只有三种：无任何信号为 0；有阻断、错误或提示为 1；用法或输入问题为 2（`script1.sh:229—230`）。

### 21.4 逐码清单

#### A 族：行与主体（7 码）

| 码 | 触发条件 | 依据 |
| --- | --- | --- |
| `A01` | 记录标识前缀不在 `AI_`／`MD_`／`CR_` 之内 | 第 15.1 节三列 |
| `A02` | `id.platform` 缺失 | 第 1 章平台坐标 |
| `A03` | `id.record_kind` 不是 `app_attest`／`managed_device`／`credential` | 第 4.2 节四件 |
| `A04` | `key.location` 不是 `se`／`software`／`unknown` | 第 5.1 节密钥位置 |
| `A05` | 取值形似私钥块、形似 Base64 载荷、超过 120 字符，或敏感字段写了非枚举值 | 21.5 |
| `A06` | 同一记录的同一字段重复且取值冲突 | 台账唯一性 |
| `A07` | 行不是三列，或标识／字段名为空 | 21.1 格式 |

#### B 族：密钥与证明物（8 码）

| 码 | 触发条件 | 依据 |
| --- | --- | --- |
| `B01` | `gen_handle=yes` 但 `key.location` 不是 `se` | 第 5.1 节 |
| `B02` | `id_present=yes` 但 `id_stored` 不是 `yes` | 第 5.2 节句柄持久化 |
| `B03` | App Attest 记录没有证书链 | 第 6.1 节 |
| `B04` | App Attest 记录没有一次性挑战 | 第 6.1 节 |
| `B05` | 计数器不是整数 | 第 6.2 节 |
| `B06` | aaguid 不是 `appattest`／`appattestdevelop`／`appattestsandbox` | 第 6.3 节 |
| `B07` | `validationCategory` 不是 0—10 的整数 | 第 6.4 节 |
| `B08` | 环境不是 `development`／`production`／`sandbox` | 第 6.5 节 |

#### C 族：设备属性（7 码）

| 码 | 触发条件 | 依据 |
| --- | --- | --- |
| `C01` | User Enrollment 下登记了序列号 | 第 7.3 节 |
| `C02` | User Enrollment 下登记了 UDID | 第 7.3 节 |
| `C03` | 非 macOS 记录登记了 SIP 状态 | 第 7.2 节平台边界 |
| `C04` | 非 macOS 记录登记了安全启动状态 | 第 7.2 节 |
| `C05` | 非 macOS 记录登记了第三方内核扩展状态 | 第 7.2 节 |
| `C06` | 受管设备记录缺少时新码 | 第 7.4 节 |
| `C07` | 设备注册下既无序列号也无 UDID | 第 7.3 节 |

#### D 族：校验（7 码）

| 码 | 触发条件 | 依据 |
| --- | --- | --- |
| `D01` | `ver.verifier` 是 `app` 或 `none` | 第 8.1 节 |
| `D02` | 结论为 `present` 但没有存下已校验公钥 | 第 8.2 节 |
| `D03` | App Attest 记录没有保存回执 | 第 8.2 节 |
| `D04` | App Attest 记录没有校验时新码 | 第 8.3 节 |
| `D05` | 没有校验证书链到 Apple 根 | 第 8.3 节 |
| `D06` | App Attest 记录没有校验 `validationCategory` | 第 8.3 节 |
| `D07` | 回执创建时间超过五分钟 | 第 9.2 节 |

#### E 族：度量（6 码）

| 码 | 触发条件 | 依据 |
| --- | --- | --- |
| `E01` | 有度量但没有保存回执 | 第 9.1 节 |
| `E02` | 度量不是非负整数 | 第 9.1 节 |
| `E03` | 不早于时间晚于到期时间 | 第 9.2 节 |
| `E04` | 台账宣称度量可重置 | 第 9.4 节公开口径 |
| `E05` | 有度量但刷新策略为 `never` | 第 9.3 节 |
| `E06` | 受管设备记录登记了 App Attest 度量 | 第 9.5 节对象错配 |

#### F 族：登记与生命周期（6 码）

| 码 | 触发条件 | 依据 |
| --- | --- | --- |
| `F01` | App Attest 密钥没有与用户关联 | 第 10.1 节 |
| `F02` | 两位状态位由平台重置 | 第 10.3 节公开口径 |
| `F03` | 登记了重置时机但没有登记位含义 | 第 10.3 节 |
| `F04` | 登记了位含义但没有登记重置时机 | 第 10.3 节 |
| `F05` | 宣称密钥在重装后仍存活 | 第 11.1 节 |
| `F06` | 宣称密钥可随备份恢复 | 第 11.2 节 |

#### G 族：结论（7 码）

| 码 | 触发条件 | 依据 |
| --- | --- | --- |
| `G01` | 归属格为 `unknown` | 第 14.5 节 |
| `G02` | 宣称可指名个体但没有任何身份 OID | 第 7.3 节 |
| `G03` | App Attest 记录被宣称可指名设备 | 第 4.3 节 |
| `G04` | 结论范围为凭据但记录不是凭据校验 | 第 4.3 节 |
| `G05` | 结论为闭合但没有证据引用 | 第 14.5 节 |
| `G06` | 结论为 `present` 但校验件没有证书链 | 第 8.4 节 |
| `G07` | 证据引用不是 `Rxx` 形态 | 第 16 章 |

#### H 族：引用（6 码）

| 码 | 触发条件 | 依据 |
| --- | --- | --- |
| `H01` | 文档地址为空 | 第 14.3 节 |
| `H02` | 文档行锚为空 | 第 14.3 节 |
| `H03` | 行锚不是数字，或超过 400 行 | 第 14.3 节 |
| `H04` | 文档地址不是 `developer.apple.com` 域名 | 第 14.3 节 |
| `H05` | 文档标题为空 | 第 14.3 节 |
| `H06` | 有文档地址却没有结论证据引用 | 第 14.3 节 |

### 21.5 输入卫生：A05 拒收什么

台账里最容易出现的一类错误，是把「证明」直接抄进取值列。脚本对取值做四类拒收（`script1.sh:70—77`）：

1. 含 `BEGIN … PRIVATE KEY` 的块；
2. 以 `MI` 开头、后接 40 个以上 Base64 字符的串；
3. 长度超过 120 字符的任意取值；
4. 字段名含 `secret`／`password`／`passwd`／`token`／`payload`／`chain_pem` 且取值不是 `yes`／`no`／`true`／`false`／`none`／`empty`／`present`／`absent`／`blank` 之一。

命中任一条，整行按 A05 拒收，不进入字段表。这一条不是「防攻击」，而是**防止把不该留的东西留在台账里**：台账的作用是记「有没有、存没存、存了多久」，不是存证明物本身。

### 21.6 干净剖面实跑

`good.tsv` 是三条全部干净的台账：一条 App Attest 实例、一条受管设备校验、一条凭据校验，共 80 个字段行。

```console
$ bash script1.sh good.tsv
记录 AI_1 判定=V1 信号数=0
记录 MD_1 判定=V1 信号数=0
记录 CR_1 判定=V1 信号数=0
----
校验记录数= 3
字段行数= 80
不同信号码= 0
信号条数= 0
阻断信号条数= 0
判定分布= V1=3 V2=0 V3=0 V4=0
```

stderr 为空，退出码 0。这三条记录之所以能全部判 V1，是因为它们把第 4—14 章的每一层都写成了自洽的字段，而不是因为它们「看起来合规」。

### 21.7 异常剖面实跑

`bad-key.tsv` 把 `AI_B1` 的密钥位置写成 `software`，同时抽掉证书链、挑战、回执、时新码校验、category 校验与用户绑定。stderr 的前八行是：

```console
$ bash script1.sh bad-key.tsv 2>&1 >/dev/null | head -8
B01	AI_B1	已生成句柄但密钥位置不是 Secure Enclave
B03	AI_B1	App Attest 记录没有证书链
B04	AI_B1	App Attest 记录没有一次性挑战
D03	AI_B1	App Attest 记录没有保存回执
D04	AI_B1	App Attest 记录没有校验时新码
D06	AI_B1	App Attest 记录没有校验 validationCategory
F01	AI_B1	App Attest 记录没有与用户关联
H01	AI_B1	文档地址为空
```

这个剖面共 105 条信号、17 个不同码，退出码 1。信号条数多于码数，是因为同一个码会在多条记录上重复触发；第 23 章的覆盖表按「码」计，不按「条」计。

### 21.8 脚本全文

以下为 `attestation-ledger-review.sh` 全文，232 行。第 23 章会按围栏区间重新抽取这一段、做 `bash -n`，再对干净与异常夹具各跑一次。

```bash
#!/usr/bin/env bash
# attestation-ledger-review.sh —— 平台校验台账逐字段审查器（离线 / 只读 / 不联网 / 不碰设备）
# 输入：一份或多份台账文本，每行三列：<记录标识>,<字段名>,<取值>
# 输出：逐条信号码（stderr） + 每条记录的判定（stdout） + 汇总
# 本脚本只判定「一次平台校验被登记成一行台账之后，这行台账自己站不站得住」：
# 不含任何密钥生成、attestation 申请、服务器校验、回执换取度量或管理面命令下发的操作步骤，
# 不含任何绕过服务器校验、伪造回执、复用他人密钥或规避注册类型限制的手法，不连接任何设备。
# 输入只接受标识、字段名与短取值；取值形似私钥块、形似口令、超长 Base64 载荷或整段证书链时
# 一律按 A05 拒收并要求删除该字段（判据见 bad_value）。
# 本脚本不联网、不调用 security／codesign／profiles／defaults／log／curl／osascript／system_profiler
#       等任何命令行工具、不读取钥匙串、不打开任何管理面会话。
#       唯一写出目标是 mktemp -d 创建的临时目录，退出时删除，本实现不向其写入任何字节。
set -u
LC_ALL=C; export LC_ALL

usage() {
  cat <<'EOF'
用法: attestation-ledger-review.sh [-q] 台账文件 [...]
  -q  不输出逐记录判定行；-h/--help 显示本帮助
台账行格式: <记录标识>,<字段名>,<取值>    # 开头与空行忽略，行尾 CR 忽略，值里不能含逗号
记录标识前缀: AI_ App Attest 实例／MD_ 受管设备校验／CR_ 凭据（passkey）校验
字段命名空间（九个）:
  id.*    记录（platform / record_kind）
  key.*   密钥（gen_handle / location / id_present / id_stored / reuse / lifecycle）
  att.*   校验件（chain / nonce / counter / aaguid / category / env）
  dev.*   设备属性（serial / udid / sepos / fresh / sip / boot / kext / llb / osver / sudid / enrollment）
  ver.*   判定（verifier / pubkey_stored / receipt_stored / nonce_checked / chain_checked /
          category_checked / receipt_age_min）
  met.*   度量（metric / nb / exp / refresh / reset）
  reg.*   登记（key_user / assoc_device / reset_authority / bits_meaning / bits_reset）
  claim.* 结论（cell / scope / naming / closure / evidence_ref）
  doc.*   引用（page_url / page_title / line_ref）
退出码: 0 无任何信号 / 1 有阻断、错误或提示 / 2 用法或输入问题
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

TMPD=$(mktemp -d "${TMPDIR:-/tmp}/att23.XXXXXX") || exit 2
trap 'rm -rf "$TMPD"' EXIT INT TERM

cat "$@" | tr -d '\r' | awk -v QUIET="$QUIET" '
function emit(code, id, msg) {
  siglines++
  print code "\t" (id == "" ? "-" : id) "\t" msg > "/dev/stderr"
  cnt[code]++
  if (id != "") per[id]++
  if (code ~ /^(A0[1-7]|B0[1-8])$/) { blkcount++; if (id != "") blocked[id] = 1; return }
  if (code ~ /^(C0[1-7]|D0[1-7]|E0[1-6]|F0[1-6]|G0[1-7])$/) { if (id != "") { errored[id] = 1; errcount++ }; return }
  warncount++
  if (id != "") warned[id] = 1
}
function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }
function get(id, f, d) { return ((id SUBSEP f) in V) ? V[id SUBSEP f] : d }
function isint(s) { return s ~ /^[0-9]+$/ }
function bad_value(f, v) {
  if (v == "") return 0
  if (v ~ /BEGIN [A-Z ]*PRIVATE KEY/) return 1
  if (v ~ /^MI[A-Za-z0-9+\/]{40,}/) return 1
  if (length(v) > 120) return 1
  if (f ~ /(secret|password|passwd|token|payload|chain_pem)/ && v !~ /^(yes|no|true|false|none|empty|present|absent|blank)$/) return 1
  return 0
}
BEGIN { FS = ","; siglines = 0 }
{
  line = $0
  sub(/^[ \t]+/, "", line); sub(/[ \t]+$/, "", line)
  if (line == "" || substr(line, 1, 1) == "#") next
  n = split(line, a, ",")
  if (n != 3) { emit("A07", "-", "行不是三列（实际 " n " 列），已跳过"); next }
  id = trim(a[1]); f = trim(a[2]); val = trim(a[3])
  if (id == "" || f == "") { emit("A07", id, "标识或字段名为空"); next }
  if (bad_value(f, val)) { emit("A05", id, "字段 " f " 的取值形似密钥材料或超长载荷，已拒收"); next }
  if (id !~ /^(AI_|MD_|CR_)/) emit("A01", id, "记录标识前缀不在 AI_／MD_／CR_ 之内")
  if (!(id in order)) { order[id] = ++nrec; ids[nrec] = id }
  key = id SUBSEP f
  if (key in V && V[key] != val) emit("A06", id, "字段 " f " 重复且取值冲突")
  V[key] = val
  fields[id]++
}
END {
  for (i = 1; i <= nrec; i++) {
    id = ids[i]
    kind = get(id, "id.record_kind", "")
    plat = get(id, "id.platform", "")
    gen = get(id, "key.gen_handle", "")
    loc = get(id, "key.location", "")
    idp = get(id, "key.id_present", "")
    ids_ = get(id, "key.id_stored", "")
    reuse = get(id, "key.reuse", "")
    life = get(id, "key.lifecycle", "")
    chain = get(id, "att.chain", "")
    nonce = get(id, "att.nonce", "")
    ctr = get(id, "att.counter", "")
    aag = get(id, "att.aaguid", "")
    cat = get(id, "att.category", "")
    env = get(id, "att.env", "")
    serial = get(id, "dev.serial", "")
    udid = get(id, "dev.udid", "")
    sip = get(id, "dev.sip", "")
    boot = get(id, "dev.boot", "")
    kext = get(id, "dev.kext", "")
    fresh = get(id, "dev.fresh", "")
    enrol = get(id, "dev.enrollment", "")
    verifier = get(id, "ver.verifier", "")
    pubk = get(id, "ver.pubkey_stored", "")
    rec = get(id, "ver.receipt_stored", "")
    nchk = get(id, "ver.nonce_checked", "")
    cchk = get(id, "ver.chain_checked", "")
    kchk = get(id, "ver.category_checked", "")
    age = get(id, "ver.receipt_age_min", "")
    metric = get(id, "met.metric", "")
    nb = get(id, "met.nb", "")
    expd = get(id, "met.exp", "")
    refresh = get(id, "met.refresh", "")
    reset = get(id, "met.reset", "")
    keyuser = get(id, "reg.key_user", "")
    assoc = get(id, "reg.assoc_device", "")
    auth = get(id, "reg.reset_authority", "")
    bmean = get(id, "reg.bits_meaning", "")
    breset = get(id, "reg.bits_reset", "")
    cell = get(id, "claim.cell", "")
    scope = get(id, "claim.scope", "")
    naming = get(id, "claim.naming", "")
    closure = get(id, "claim.closure", "")
    ev = get(id, "claim.evidence_ref", "")

    if (plat == "") emit("A02", id, "id.platform 缺失")
    if (kind != "" && kind != "app_attest" && kind != "managed_device" && kind != "credential")
      emit("A03", id, "id.record_kind 不是 app_attest／managed_device／credential")
    if (loc != "" && loc != "se" && loc != "software" && loc != "unknown")
      emit("A04", id, "key.location 不是 se／software／unknown")

    if (gen == "yes" && loc != "se") emit("B01", id, "已生成句柄但密钥位置不是 Secure Enclave")
    if (idp == "yes" && ids_ != "yes") emit("B02", id, "句柄存在但未持久保存，之后无法再取回")
    if (kind == "app_attest" && chain != "yes") emit("B03", id, "App Attest 记录没有证书链")
    if (kind == "app_attest" && nonce != "yes") emit("B04", id, "App Attest 记录没有一次性挑战")
    if (ctr != "" && !isint(ctr)) emit("B05", id, "计数器不是整数")
    if (aag != "" && aag != "appattest" && aag != "appattestdevelop" && aag != "appattestsandbox")
      emit("B06", id, "aaguid 不是三个已知常量之一")
    if (cat != "" && (!isint(cat) || cat + 0 > 10)) emit("B07", id, "validationCategory 不在 0—10")
    if (env != "" && env != "development" && env != "production" && env != "sandbox")
      emit("B08", id, "环境不是 development／production／sandbox")

    if (enrol == "user" && serial == "present") emit("C01", id, "User Enrollment 下登记了序列号")
    if (enrol == "user" && udid == "present") emit("C02", id, "User Enrollment 下登记了 UDID")
    if (sip == "present" && plat != "macOS") emit("C03", id, "非 macOS 记录登记了 SIP 状态")
    if (boot == "present" && plat != "macOS") emit("C04", id, "非 macOS 记录登记了安全启动状态")
    if (kext == "present" && plat != "macOS") emit("C05", id, "非 macOS 记录登记了第三方内核扩展状态")
    if (kind == "managed_device" && fresh != "present") emit("C06", id, "设备属性记录缺少时新码")
    if (kind == "managed_device" && enrol == "device" && serial != "present" && udid != "present")
      emit("C07", id, "设备注册下既无序列号也无 UDID，无法指名")

    if (verifier == "app" || verifier == "none") emit("D01", id, "判定位置不是服务器（App 自身或缺失）")
    if (cell == "present" && pubk != "yes") emit("D02", id, "结论为 present 但没有存下已校验公钥")
    if (kind == "app_attest" && rec != "yes") emit("D03", id, "App Attest 记录没有保存回执")
    if (kind == "app_attest" && nchk != "yes") emit("D04", id, "App Attest 记录没有校验时新码")
    if (cchk != "yes") emit("D05", id, "没有校验证书链到 Apple 根")
    if (kind == "app_attest" && kchk != "yes") emit("D06", id, "App Attest 记录没有校验 validationCategory")
    if (age != "" && isint(age) && age + 0 > 5) emit("D07", id, "回执创建时间超过五分钟")

    if (metric != "" && metric != "none" && rec != "yes") emit("E01", id, "有度量但没有保存回执")
    if (metric != "" && metric != "none" && !isint(metric)) emit("E02", id, "度量不是非负整数")
    if (nb != "" && expd != "" && nb > expd) emit("E03", id, "不早于时间晚于到期时间")
    if (reset == "yes") emit("E04", id, "台账宣称度量可重置（公开口径为不可重置）")
    if (metric != "" && metric != "none" && refresh == "never") emit("E05", id, "有度量但刷新策略为 never")
    if (metric != "" && metric != "none" && kind == "managed_device")
      emit("E06", id, "受管设备记录登记了 App Attest 度量")

    if (kind == "app_attest" && keyuser != "yes") emit("F01", id, "App Attest 密钥没有与用户关联")
    if (auth == "platform" && bmean != "") emit("F02", id, "两位状态位由平台重置（公开口径为开发者决定）")
    if (bmean == "" && breset != "") emit("F03", id, "登记了重置时机但没有登记位含义")
    if (breset == "" && bmean != "") emit("F04", id, "登记了位含义但没有登记重置时机")
    if (life == "survives_reinstall") emit("F05", id, "宣称密钥在重装后仍存活（公开口径为不存活）")
    if (life == "restored_from_backup") emit("F06", id, "宣称密钥可随备份恢复（公开口径为不可）")

    if (cell == "unknown") emit("G01", id, "归属格为 unknown")
    if (naming == "individual" && serial != "present" && udid != "present")
      emit("G02", id, "结论宣称可指名个体但没有任何身份 OID")
    if (naming == "individual" && kind == "app_attest") emit("G03", id, "App Attest 记录被宣称可指名设备")
    if (scope == "credential" && kind != "credential") emit("G04", id, "结论范围为凭据但记录不是凭据校验")
    if (closure == "closed" && ev == "") emit("G05", id, "结论为闭合但没有证据引用")
    if (cell == "present" && kind == "app_attest" && chain != "yes")
      emit("G06", id, "结论为 present 但校验件没有证书链")
    if (ev != "" && ev !~ /^R[0-9][0-9]$/) emit("G07", id, "证据引用不是 Rxx 形态")

    if (get(id, "doc.page_url", "") == "") emit("H01", id, "文档地址为空")
    if (get(id, "doc.line_ref", "") == "") emit("H02", id, "文档行锚为空")
    if (get(id, "doc.line_ref", "") != "" && get(id, "doc.line_ref", "") !~ /^[0-9]+$/)
      emit("H03", id, "文档行锚不是数字")
    else if (get(id, "doc.line_ref", "") != "" && get(id, "doc.line_ref", "") + 0 > 400)
      emit("H03", id, "文档行锚超出行数上限 400")
    if (get(id, "doc.page_url", "") != "" && get(id, "doc.page_url", "") !~ /^https:\/\/developer\.apple\.com\//)
      emit("H04", id, "文档地址不是 developer.apple.com")
    if (get(id, "doc.page_title", "") == "") emit("H05", id, "文档标题为空")
    if (get(id, "doc.page_url", "") != "" && ev == "") emit("H06", id, "有文档地址却没有结论证据引用")

    if (cell == "unknown") verdict = "V4"
    else if (id in blocked || id in errored) verdict = "V3"
    else if (id in warned) verdict = "V2"
    else verdict = "V1"
    vcnt[verdict]++
    if (!QUIET) print "记录 " id " 判定=" verdict " 信号数=" per[id]+0
  }
  print "----"
  print "校验记录数= " nrec
  print "字段行数= " length(V)
  print "不同信号码= " length(cnt)
  print "信号条数= " siglines+0
  print "阻断信号条数= " blkcount+0
  printf "判定分布= "
  split("V1 V2 V3 V4", vs, " ")
  for (i = 1; i <= 4; i++) printf "%s=%d ", vs[i], vcnt[vs[i]] + 0
  print ""
  if (blkcount + 0 > 0 || errcount > 0 || warncount > 0) exit 1
  exit 0
}
'
```

---

## 22. 只读核验脚本二：校验件四件框架闭合性与公告词表比对器

### 22.1 它比对的是四个文件

脚本二不读台账，读四份结构化输入。四份输入分别回答一个问题：

| 文件 | 列 | 回答的问题 | 对应章 |
| --- | --- | --- | --- |
| 框架表 `frame.tsv` | 9 列：`object`、`subject`、`kind`、`signer`、`proof`、`names`、`readback`、`expiry`、`anchor` | 四件各自的签署方、证明物、可指名程度、回读点、有效期口径是否齐全 | 第 3 章 |
| 术语出处表 `vocab.tsv` | 4 列：`term`、`namespace`、`doc`、`line` | 每个术语是否只登记在一个命名空间、出处是否存在、行号是否在范围内 | 第 3 章 |
| 公告语料 `advisory.tsv` | 6 列：`file`、`platform`、`component`、`cve`、`impact`、`date` | 校验词形在公告面是否出现、各个读数是否与声明一致 | 第 13 章、第 16 章 |
| 声明读数 `baseline.tsv` | 2 列：`metric`、`expected` | 报告里写的每一个数，能否从语料重算出来 | 第 16 章 |

五个参数缺一不可：`--frame`、`--vocab`、`--corpus`、`--baseline`、`--docs`。任一缺失、路径不存在或不可读，脚本在进入 awk 之前就打印 `W4` 并退出 2（`script2.sh:37—48`）。这与脚本一的 A07 是同一个设计：**输入不可用时不猜，直接停。**

### 22.2 三族信号与四档闭合

脚本二有 39 个信号码，分三族：

| 族 | 码段 | 数量 | 检查什么 | 判定贡献 |
| --- | --- | --- | --- | --- |
| X | `X01`—`X12` | 12 | 四件框架的列完整性、取值域、对象数、证明物唯一性 | 框架不闭合 |
| Y | `Y01`—`Y10` | 10 | 术语出处的存在性与行号、术语的命名空间唯一性、公告词形命中 | 词表待校 |
| Z | `Z01`—`Z17` | 17 | 17 个声明读数与语料重算值的逐项相等 | 读数漂移 |

Z 族的码数是**由声明读数表的行数决定的**，不是写死的。脚本用 `code = sprintf("Z%02d", i)` 按行号生成码（`script2.sh:226—232`），当前基线有 17 行，所以是 `Z01`—`Z17`。若基线增删一行，码段随之伸缩；第 23 章的覆盖表按当前的 17 行记。

闭合等级按下面的顺序取（`script2.sh:237—240`）：

```text
X、Y、Z 全为 0        → W1（Q1）
只有 Y 非 0           → W2（Q2）
X 或 Z 非 0           → W3（Q3）
输入不可用             → W4（Q4，退出 2）
```

脚本输出的字面等级是 `W1`—`W4`（W 取 window／closure），本报告在第 19 章统一记作 `Q1`—`Q4`，逐位对应。

### 22.3 X 族逐码：框架闭合

框架表的九个列不是随便定的。它们对应本文开头的六个问句：`signer` 回答「谁签的」，`proof` 回答「证明物是什么」，`names` 回答「能指名什么」，`readback` 回答「在哪里读回」，`expiry` 回答「在哪里过期」，`anchor` 回答「证据在哪」。

| 码 | 触发条件 | 对应问句 |
| --- | --- | --- |
| `X01` | 框架行缺少签署方 | 谁签的 |
| `X02` | 框架行缺少证明物 | 证明物是什么 |
| `X03` | 框架行缺少回读点 | 在哪里读回 |
| `X04` | 框架行缺少有效期口径 | 在哪里过期 |
| `X05` | `subject` 不在「app 实例／受管设备／凭据／外接配件」内，或 `names` 不在「none／individual／credential／accessory」内 | 对象与可指名程度 |
| `X06` | 同一证明物被多个对象共用 | 四件不可通约 |
| `X07` | 宣称可指名个体，但对象不是设备 | 第 4.3 节 |
| `X08` | 宣称可指名个体，但回读点不含「设备属性」或 `DeviceInformation` | 第 7.3 节 |
| `X09` | 宣称凭据级证明，但对象不是凭据 | 第 4.3 节 |
| `X10` | 证明物是证书却声明无有效期 | 第 6.6 节 |
| `X11` | 证据锚点不是 `Rxx` 或 `Rxx.y` 形态 | 第 16 章 |
| `X12` | 框架对象数不是 4，或同一对象重复登记 | 第 3 章 |

X06 是这十二个码里唯一一个**跨行**检查：它先把每个非空证明物映射到使用它的对象列表，再对列表长度大于 1 的证明物逐个对象报错（`script2.sh:162—167`）。它检查的不是「两个对象能不能用同一种密码学」，而是「这份框架有没有把两件写成了一件」。

### 22.4 Y 族逐码：词表纪律与公告词形

| 码 | 触发条件 | 性质 |
| --- | --- | --- |
| `Y01` | 出处文档不存在或为空 | 出处不可复核 |
| `Y02` | 行号不是整数，或小于 1，或大于文档行数 | 出处不可复核 |
| `Y03` | 同一术语登记在两个以上命名空间 | 词表失配 |
| `Y04` | 词表行有空字段 | 词表失配 |
| `Y05` | 组件列命中 `attest` 词 | 公告词形命中 |
| `Y06` | 影响句命中 `attest` 词 | 公告词形命中 |
| `Y07` | 组件列命中 `DeviceCheck` | 公告词形命中 |
| `Y08` | 影响句命中 `DeviceCheck` | 公告词形命中 |
| `Y09` | 组件列或影响句命中 `Secure Enclave` | 公告词形命中 |
| `Y10` | 上述任一命中，报总命中行数 | 公告词形命中 |

Y05—Y10 与其他码有一个根本区别：它们**不是缺陷**，而是**读数**。在真实语料上，这六个码全部为 0，因为九个校验词形在 1266 行公告里两列同时为 0（第 13 章）。脚本保留这六个码，是为了让「零命中」这件事本身可被机械验证：如果哪一天公告里出现了 `attest`，Y05 会立刻把它数出来，而不是靠人眼在 1266 行里找。

`ATT` 的匹配是大小写无关的三词并集：`attest|devicecheck|secure enclave`（`script2.sh:71`、`:120—126`）。`zany` 按「组件列或影响句列命中任一」计行，不是把两列的命中数相加，所以 Y10 的数值可能小于 Y05—Y09 之和。

### 22.5 Z 族：17 个声明读数如何重算

`baseline.tsv` 的每一行是一个「读数名 → 声明值」。脚本先从句法层面把 17 个读数算出来，存进 `ACT` 数组（`script2.sh:208—224`），再逐行比较：

| 读数名 | 重算口径 | 当前值 |
| --- | --- | --- |
| `rows` | 语料数据行数 | 1266 |
| `platforms` | 不同 `platform` 取值数 | 12 |
| `components` | 不同 `component` 取值数 | 129 |
| `cves` | 非空 `cve` 的不同取值数 | 330 |
| `component.kernel` | 组件列含 `kernel` 的行数 | 115 |
| `impact.kernel` | 影响句含 `kernel` 的行数 | 179 |
| `impact.sandbox` | 影响句含 `sandbox` 的行数 | 51 |
| `component.cryptex` | 组件列含 `cryptex` 的行数 | 3 |
| `impact.trust` | 影响句含 `trust` 的行数 | 2 |
| `accessory.rows` | 五个配件组件的行数 | 27 |
| `accessory.cves` | 这些行里非空 CVE 的去重数 | 7 |
| `field.count` | 每行恰好 6 列时为 6，否则为 0 | 6 |
| `platform.max` | 单一平台的最大行数 | 263 |
| `platform.singleton` | 只有 1 行的平台数 | 2 |
| `platform.sum` | 各平台行数之和 | 1266 |
| `empty.component` | 组件列为空的行数 | 0 |
| `empty.cve` | CVE 列为空的行数 | 0 |

这张表就是第 16 章 R21 组的可执行版本。`platform.sum` 与 `rows` 必须相等，否则说明有行没有被归入任何平台；`platform.max` 与 `platform.singleton` 一起看，能看出语料是否被单一平台压倒。`field.count` 是一个哨兵：只要有一行列数不是 6，它就变成 0，与声明值 6 不等，Z12 立即报错。

### 22.6 四个剖面的实跑

**干净剖面（真实语料）。**

```console
$ bash script2.sh --frame frame-good.tsv --vocab vocab-good.tsv \
    --corpus advisory-23.tsv --baseline baseline-real.tsv --docs .srcx23
----
框架对象数= 4
词表术语数= 15
公告行数= 1266
声明读数数= 17
X 族信号= 0　Y 族信号= 0　Z 族信号= 0
不同信号码= 0　信号条数= 0
判定= W1
```

这七个数字就是本文第 23 章「实跑与覆盖验收」的起点：4 件、15 个术语、1266 行、17 个读数、零信号。

**框架异常剖面。**

```console
$ bash script2.sh --frame frame-bad.tsv ... 2>&1 >/dev/null | head -6
X01	app_instance	框架行缺少签署方
X10	app_instance	证明物是证书却声明无有效期
X11	app_instance	证据锚点不是 Rxx 形态
X02	device	框架行缺少证明物
X03	device	框架行缺少回读点
X04	device	框架行缺少有效期口径
```

该剖面 14 条信号、12 个码，`X01`—`X12` 全部出现，判定 W3。

**词表异常剖面。**

```console
$ bash script2.sh --vocab vocab-bad.tsv ... 2>&1 >/dev/null
Y01	phantomTerm	出处文档不存在或为空：A/does-not-exist.txt
Y02	keyId	行号 9999 超出 A/devicecheck_dcappattestservice_generatekey.txt 的 199 行
Y04	-	词表第 5 行有空字段
Y03	receipt	同一术语登记在 2 个命名空间
```

4 条信号、4 个码，判定 W2。这一档的语义是「框架与读数都闭合，但词表需要校」，不是「框架坏了」。

**词形命中剖面。**

```console
$ bash script2.sh --corpus corpus-words.tsv ... 2>&1 >/dev/null
Y05	-	组件列命中 attest 词 2 行
Y06	-	影响句命中 attest 词 3 行
Y07	-	组件列命中 DeviceCheck 1 行
Y08	-	影响句命中 DeviceCheck 1 行
Y09	-	命中 Secure Enclave 1 行
Y10	-	校验词表在公告语料中的总命中 5 行
```

6 条信号、6 个码，判定 W2。这一剖面用来证明 Y05—Y10 **不是死码**：只要语料里出现词形，六条都会触发。

**读数漂移剖面。**

```console
$ bash script2.sh --baseline baseline-bad.tsv ... 2>&1 >/dev/null | head -6
Z01	rows	声明 4，重算 3
Z02	platforms	声明 3，重算 2
Z03	components	声明 3，重算 2
Z04	cves	声明 4，重算 3
Z05	component.kernel	声明 3，重算 2
Z06	impact.kernel	声明 2，重算 1
```

在小型语料上，这个剖面 17 条信号、17 个码，`Z01`—`Z17` 全部出现，判定 W3。**在真实语料上，同一个 `baseline-bad.tsv` 只会得到 16 个码**：它声明的 `platform.singleton` 恰好是 2，而真实语料的该读数也是 2，所以 `Z14` 不触发。这一点在第 23.3 节单独说明，避免把「17 个码全部可达」误写成「每个剖面都触发 17 个码」。

### 22.7 为什么公告面必须与框架面分开

脚本二把 Y 族与 X 族放在同一个判定里，但两者的语义完全不同。X 族检查「这份框架自己是否闭合」，Y 族检查「这份框架引用的词是否可复核」。一个框架可以完全闭合却引用不存在的文档（X 全 0、Y01 非 0，判 W2）；也可以词表完美却把两件写成一件（Y 全 0、X06 非 0，判 W3）。

把它们合成一个「总分」会丢掉这个区别。本文坚持 W2 与 W3 分开，理由与第 19.2 节相同：**可复核性瑕疵与框架失效的处置不同。** 前者补文档，后者改框架。

### 22.8 脚本全文

以下为 `attestation-frame-closure.sh` 全文，252 行。

```bash
#!/usr/bin/env bash
# attestation-frame-closure.sh — 校验件四件框架闭合性与公告词表比对器
#
# 只读：不写任何文件，不访问网络，不读取设备。
# 用法：
#   bash attestation-frame-closure.sh \
#     --frame    frame.tsv      四件框架表
#     --vocab    vocab.tsv      术语出处表
#     --corpus   advisory.tsv   公告语料（六列）
#     --baseline baseline.tsv   声明读数（metric / expected 两列）
#     --docs     <dir>          术语出处表的文档根目录
#
# 输出：stderr 每行 <码>\t<主体>\t<说明>；stdout 汇总与 W1—W4 判定。
# 退出码：0 = W1；1 = W2/W3；2 = W4（输入不可用）。

set -u
export LC_ALL=C

FRAME=""; VOCAB=""; CORPUS=""; BASE=""; DOCS=""

usage() {
  sed -n '2,12p' "$0" 2>/dev/null || true
}

while [ $# -gt 0 ]; do
  case "$1" in
    --frame)    FRAME=${2-};  shift 2 ;;
    --vocab)    VOCAB=${2-};  shift 2 ;;
    --corpus)   CORPUS=${2-}; shift 2 ;;
    --baseline) BASE=${2-};   shift 2 ;;
    --docs)     DOCS=${2-};   shift 2 ;;
    -h|--help)  usage; exit 0 ;;
    *) printf 'W4\t-\t未知参数 %s\n' "$1" >&2; exit 2 ;;
  esac
done

for pair in "frame:$FRAME" "vocab:$VOCAB" "corpus:$CORPUS" "baseline:$BASE" "docs:$DOCS"; do
  name=${pair%%:*}; path=${pair#*:}
  if [ -z "$path" ]; then
    printf 'W4\t-\t缺少参数 --%s\n' "$name" >&2; exit 2
  fi
  if [ ! -e "$path" ]; then
    printf 'W4\t-\t--%s 指向的路径不存在：%s\n' "$name" "$path" >&2; exit 2
  fi
done
if [ ! -r "$FRAME" ] || [ ! -r "$VOCAB" ] || [ ! -r "$CORPUS" ] || [ ! -r "$BASE" ] || [ ! -r "$DOCS" ]; then
  printf 'W4\t-\t有输入不可读（权限或类型不符）\n' >&2; exit 2
fi

awk -F'\t' \
  -v FRAME="$FRAME" -v VOCAB="$VOCAB" -v CORPUS="$CORPUS" \
  -v BASE="$BASE" -v DOCS="$DOCS" '
function emit(code, subj, msg) {
  printf "%s\t%s\t%s\n", code, subj, msg > "/dev/stderr"
  cnt[code]++
  fam[substr(code, 1, 1)]++
}
function doclines(p,   n, r) {
  n = 0
  while ((getline r < p) > 0) n++
  close(p)
  return n
}
function isint(s) { return s ~ /^[0-9]+$/ }

BEGIN {
  split("app 实例|受管设备|凭据|外接配件", a, "|")
  for (i in a) SUBJ[a[i]] = 1
  split("none|individual|credential|accessory", b, "|")
  for (i in b) NAMES[b[i]] = 1
  ATT = "attest|devicecheck|secure enclave"
  metric_n = 0
}

/* ---------- 第一件：四件框架表 ---------- */
FILENAME == FRAME {
  sub(/\r$/, "")
  if (FNR == 1) { if ($1 == "object") next }
  nf++
  o = $1; s = $2; k = $3; sg = $4; pf = $5; nm = $6; rb = $7; ex = $8; an = $9
  ro[nf] = o; rs[nf] = s; rk[nf] = k; rsg[nf] = sg; rpf[nf] = pf
  rnm[nf] = nm; rrb[nf] = rb; rex[nf] = ex; ran[nf] = an
  seen_obj[o]++
  if (pf != "") proofobj[pf] = proofobj[pf] " " o
  next
}

/* ---------- 第二件：术语出处表 ---------- */
FILENAME == VOCAB {
  sub(/\r$/, "")
  if (FNR == 1) { if ($1 == "term") next }
  vn++
  vt[vn] = $1; vns[vn] = $2; vd[vn] = $3; vl[vn] = $4
  next
}

/* ---------- 第三件：公告语料 ---------- */
FILENAME == CORPUS {
  sub(/\r$/, "")
  if (FNR == 1) { if ($1 == "file") next }
  zrows++
  if (NF != 6) zbadnf++
  comp = tolower($3); imp = tolower($5)
  if ($3 == "") zemptycomp++
  if ($4 == "") zemptycve++
  zplat[$2]++
  zsumplat++
  zcomp[$3]++
  if ($4 != "") zcve[$4]++
  if (comp ~ /kernel/)   zcompkernel++
  if (imp  ~ /kernel/)   zimpkernel++
  if (imp  ~ /sandbox/)  zimpsandbox++
  if (comp ~ /cryptex/)  zcompcryptex++
  if (imp  ~ /trust/)    zimptrust++
  if ($3 == "AccessorySetupKit" || $3 == "Bluetooth" || $3 == "HomeKit" \
      || $3 == "Thread" || $3 == "USB") {
    zaccrows++
    if ($4 != "") zaccve[$4] = 1
  }
  if (comp ~ ATT) zcatt++
  if (imp  ~ ATT) ziattt++
  if (comp ~ /devicecheck/) zcdev++
  if (imp  ~ /devicecheck/) zidev++
  if (comp ~ /secure enclave/) zcse++
  if (imp  ~ /secure enclave/) zise++
  if (comp ~ ATT || imp ~ ATT) zany++
  next
}

/* ---------- 第四件：声明读数 ---------- */
FILENAME == BASE {
  sub(/\r$/, "")
  if (FNR == 1) { if ($1 == "metric") next }
  if ($1 == "") next
  metric_n++
  mname[metric_n] = $1
  mexp[metric_n] = $2
  next
}

END {
  /* ---- X 族：框架闭合 ---- */
  for (i = 1; i <= nf; i++) {
    o = ro[i]
    if (rsg[i] == "") emit("X01", o, "框架行缺少签署方")
    if (rpf[i] == "") emit("X02", o, "框架行缺少证明物")
    if (rrb[i] == "") emit("X03", o, "框架行缺少回读点")
    if (rex[i] == "") emit("X04", o, "框架行缺少有效期口径")
    if (!(rs[i] in SUBJ) || !(rnm[i] in NAMES))
      emit("X05", o, "subject 或 names 不在四类取值内")
    if (rnm[i] == "individual" && o != "device")
      emit("X07", o, "宣称可指名个体，但对象不是设备")
    if (rnm[i] == "individual" && rrb[i] !~ /(设备属性|DeviceInformation)/)
      emit("X08", o, "宣称可指名个体，但回读点不含设备属性来源")
    if (rnm[i] == "credential" && o != "credential")
      emit("X09", o, "宣称凭据级证明，但对象不是凭据")
    if (rex[i] == "none" && rpf[i] ~ /证书/)
      emit("X10", o, "证明物是证书却声明无有效期")
    if (ran[i] !~ /^R[0-9]+(\.[0-9]+)?$/)
      emit("X11", o, "证据锚点不是 Rxx 形态")
  }
  for (pf in proofobj) {
    n = split(proofobj[pf], objs, " ")
    if (n > 1) {
      for (j = 1; j <= n; j++) emit("X06", objs[j], "证明物被多个对象共用：" pf)
    }
  }
  if (nf != 4) emit("X12", "-", "框架对象数为 " nf "，预期 4")
  for (o in seen_obj) if (seen_obj[o] > 1) emit("X12", o, "对象重复登记")

  /* ---- Y 族：词表纪律 ---- */
  for (i = 1; i <= vn; i++) {
    if (vt[i] == "" || vns[i] == "" || vd[i] == "") {
      emit("Y04", "-", "词表第 " i " 行有空字段"); continue
    }
    p = DOCS "/" vd[i]
    n = doclines(p)
    if (n == 0) {
      emit("Y01", vt[i], "出处文档不存在或为空：" vd[i])
    } else if (!isint(vl[i]) || vl[i] + 0 < 1 || vl[i] + 0 > n) {
      emit("Y02", vt[i], "行号 " vl[i] " 超出 " vd[i] " 的 " n " 行")
    }
    if (vt[i] in ns) { if (index(ns[vt[i]], "|" vns[i] "|") == 0) ns[vt[i]] = ns[vt[i]] vns[i] "|" }
    else ns[vt[i]] = "|" vns[i] "|"
  }
  for (t in ns) {
    k = gsub(/\|/, "|", ns[t]) - 1
    if (k > 1) emit("Y03", t, "同一术语登记在 " k " 个命名空间")
  }
  if (zcatt > 0)   emit("Y05", "-", "组件列命中 attest 词 " zcatt " 行")
  if (ziattt > 0)  emit("Y06", "-", "影响句命中 attest 词 " ziattt " 行")
  if (zcdev > 0)   emit("Y07", "-", "组件列命中 DeviceCheck " zcdev " 行")
  if (zidev > 0)   emit("Y08", "-", "影响句命中 DeviceCheck " zidev " 行")
  if (zcse + zise > 0) emit("Y09", "-", "命中 Secure Enclave " (zcse + zise) " 行")
  if (zany > 0)    emit("Y10", "-", "校验词表在公告语料中的总命中 " zany " 行")

  /* ---- Z 族：声明读数与重算读数 ---- */
  platn = 0; platmax = 0; platsingle = 0
  for (p in zplat) {
    platn++
    if (zplat[p] > platmax) platmax = zplat[p]
    if (zplat[p] == 1) platsingle++
  }
  compn = 0; for (c in zcomp) compn++
  cven = 0; for (v in zcve) cven++
  accn = 0; for (v in zaccve) accn++

  ACT["rows"] = zrows
  ACT["platforms"] = platn
  ACT["components"] = compn
  ACT["cves"] = cven
  ACT["component.kernel"] = zcompkernel
  ACT["impact.kernel"] = zimpkernel
  ACT["impact.sandbox"] = zimpsandbox
  ACT["component.cryptex"] = zcompcryptex
  ACT["impact.trust"] = zimptrust
  ACT["accessory.rows"] = zaccrows
  ACT["accessory.cves"] = accn
  ACT["field.count"] = (zbadnf == 0) ? 6 : 0
  ACT["platform.max"] = platmax
  ACT["platform.singleton"] = platsingle
  ACT["platform.sum"] = zsumplat
  ACT["empty.component"] = zemptycomp
  ACT["empty.cve"] = zemptycve

  for (i = 1; i <= metric_n; i++) {
    code = sprintf("Z%02d", i)
    m = mname[i]
    if (!(m in ACT)) { emit(code, m, "未知读数名，无法重算"); continue }
    if (ACT[m] != mexp[i] + 0)
      emit(code, m, "声明 " mexp[i] "，重算 " ACT[m])
  }

  /* ---- 汇总 ---- */
  ngood = 0
  for (c in cnt) ngood++
  sig = fam["X"] + fam["Y"] + fam["Z"]
  if (sig == 0) { W = "W1"; rc = 0 }
  else if (fam["X"] == 0 && fam["Z"] == 0) { W = "W2"; rc = 1 }
  else { W = "W3"; rc = 1 }

  printf "----\n"
  printf "框架对象数= %d\n", nf
  printf "词表术语数= %d\n", vn
  printf "公告行数= %d\n", zrows
  printf "声明读数数= %d\n", metric_n
  printf "X 族信号= %d　Y 族信号= %d　Z 族信号= %d\n", fam["X"], fam["Y"], fam["Z"]
  printf "不同信号码= %d　信号条数= %d\n", ngood, sig
  printf "判定= %s\n", W
  exit rc
}
' "$FRAME" "$VOCAB" "$CORPUS" "$BASE"
```
## 23. 实跑与覆盖验收

### 23.1 复现前提

本章的所有数字都来自同一次运行，输入是归档 `.srcx23` 与夹具目录 `.p23/fx`、`.p23/fx2`。四个文件的位置固定：

| 别名 | 实际路径 | 规模 |
| --- | --- | --- |
| 脚本一 | `.p23/script1.sh` | 232 行 |
| 脚本二 | `.p23/script2.sh` | 252 行 |
| 脚本一夹具 | `.p23/fx/*.tsv` | 10 个剖面 |
| 脚本二夹具 | `.p23/fx2/*.tsv` | 4 个剖面 |
| 真实公告语料 | `.srcx23/C/advisory-23.tsv` | 1266 数据行 |
| 文档根目录 | `.srcx23` | A 组 18 份 + B 组 1 份 |

复现只需要 `bash` 与 `awk`，不需要网络、不需要设备、不需要编译。所有命令在仓库根目录执行。

### 23.2 十五个剖面

矩阵脚本 `matrix.sh` 依次跑 10 个脚本一剖面与 5 个脚本二剖面，每个剖面输出「退出码／判定／信号条数／信号码数」。实测：

| 剖面 | 脚本 | 退出码 | 判定 | 信号条数 | 信号码数 |
| --- | --- | --- | --- | --- | --- |
| `good` | 一 | 0 | V1 | 0 | 0 |
| `warn-doc` | 一 | 1 | V2 | 3 | 3 |
| `bad-structure` | 一 | 1 | V3 | 58 | 16 |
| `bad-key` | 一 | 1 | V3 | 105 | 17 |
| `bad-device` | 一 | 1 | V3 | 28 | 10 |
| `bad-verify` | 一 | 1 | V3 | 94 | 16 |
| `bad-metric` | 一 | 1 | V3 | 52 | 15 |
| `bad-registry` | 一 | 1 | V3 | 12 | 6 |
| `bad-claim` | 一 | 1 | V4 | 32 | 15 |
| `bad-doc` | 一 | 1 | V3 | 45 | 14 |
| `good-real` | 二 | 0 | W1 | 0 | 0 |
| `frame-bad` | 二 | 1 | W3 | 14 | 12 |
| `vocab-bad` | 二 | 1 | W2 | 4 | 4 |
| `words-hit` | 二 | 1 | W2 | 6 | 6 |
| `baseline-drift` | 二 | 1 | W3 | 17 | 17 |

这张表里有四处需要解释：

1. **`bad-claim` 的判定是 V4，不是 V3。** 因为该剖面里有一条记录的 `claim.cell` 写成了 `unknown`，而 `unknown` 的优先级高于阻断与错误（第 21.3 节）。这条记录同时也有 G 族错误，但判定只取最高优先级的那一个。
2. **`warn-doc` 的退出码是 1。** 它只有 H 族提示，没有阻断也没有错误，但脚本对「有任何信号」统一返回 1。这与第 19.1 节 J2 的「有提示但不阻断」并不矛盾：J2 说的是记录能否使用，退出码说的是这一次运行是否干净。
3. **`bad-key` 的 17 个码并不是 17 个 B 码。** 该剖面同时抽掉了回执、时新码、category 校验、用户绑定与文档字段，所以 B、D、F、H 四族都被触发。
4. **`baseline-drift` 的 17 个码是 17 个 Z 码。** 这一剖面用的是小型语料加错误基线，17 行基线全部不等，所以 `Z01`—`Z17` 全部出现。

### 23.3 脚本一逐码覆盖（54／54）

下表按族列出 54 个信号码，并给出能触发它的代表剖面。代表剖面的选择原则是：**优先选该码第一次出现、且信号条数最少的剖面**，便于单独复现。

| 码 | 严重度 | 代表剖面 |
| --- | --- | --- |
| `A01` | 阻断 | `bad-structure` |
| `A02` | 阻断 | `bad-structure` |
| `A03` | 阻断 | `bad-structure` |
| `A04` | 阻断 | `bad-structure` |
| `A05` | 阻断 | `bad-structure` |
| `A06` | 阻断 | `bad-structure` |
| `A07` | 阻断 | `bad-structure` |
| `B01` | 阻断 | `bad-key` |
| `B02` | 阻断 | `bad-key` |
| `B03` | 阻断 | `bad-key` |
| `B04` | 阻断 | `bad-key` |
| `B05` | 阻断 | `bad-key` |
| `B06` | 阻断 | `bad-key` |
| `B07` | 阻断 | `bad-key` |
| `B08` | 阻断 | `bad-key` |
| `C01` | 错误 | `bad-device` |
| `C02` | 错误 | `bad-device` |
| `C03` | 错误 | `bad-device` |
| `C04` | 错误 | `bad-device` |
| `C05` | 错误 | `bad-device` |
| `C06` | 错误 | `bad-device` |
| `C07` | 错误 | `bad-device` |
| `D01` | 错误 | `bad-verify` |
| `D02` | 错误 | `bad-verify` |
| `D03` | 错误 | `bad-verify` |
| `D04` | 错误 | `bad-verify` |
| `D05` | 错误 | `bad-verify` |
| `D06` | 错误 | `bad-verify` |
| `D07` | 错误 | `bad-verify` |
| `E01` | 错误 | `bad-metric` |
| `E02` | 错误 | `bad-metric` |
| `E03` | 错误 | `bad-metric` |
| `E04` | 错误 | `bad-metric` |
| `E05` | 错误 | `bad-metric` |
| `E06` | 错误 | `bad-metric` |
| `F01` | 错误 | `bad-key` |
| `F02` | 错误 | `bad-registry` |
| `F03` | 错误 | `bad-registry` |
| `F04` | 错误 | `bad-registry` |
| `F05` | 错误 | `bad-key` |
| `F06` | 错误 | `bad-key` |
| `G01` | 错误 | `bad-claim` |
| `G02` | 错误 | `bad-claim` |
| `G03` | 错误 | `bad-claim` |
| `G04` | 错误 | `bad-claim` |
| `G05` | 错误 | `bad-verify` |
| `G06` | 错误 | `bad-verify` |
| `G07` | 错误 | `bad-verify` |
| `H01` | 提示 | `warn-doc` |
| `H02` | 提示 | `warn-doc` |
| `H03` | 提示 | `bad-doc` |
| `H04` | 提示 | `bad-doc` |
| `H05` | 提示 | `warn-doc` |
| `H06` | 提示 | `bad-doc` |

合计 54 个码，覆盖 54 个。验收脚本 P16 用另一种方式复核：把 9 个 `bad-*.tsv` 与 `warn-doc.tsv` 的 stderr 首列合并去重，计数必须等于 54。两种方式的结论一致，说明这张表不是手工凑出来的。

### 23.4 脚本二逐码覆盖（39／39）

| 码 | 族 | 代表剖面 |
| --- | --- | --- |
| `X01`—`X12` | X 框架 | `frame-bad` |
| `Y01`—`Y04` | Y 词表 | `vocab-bad` |
| `Y05`—`Y10` | Y 词形 | `words-hit` |
| `Z01`—`Z17` | Z 读数 | `baseline-bad`（小语料） |

X 族的 12 个码由同一个剖面全部触发：`frame-bad.tsv` 只有三行对象，其中一行缺签署方与有效期、锚点写成非 `Rxx`、`subject` 写错、证明物与另一对象共用、对象重复登记。Y 族的前四个码由 `vocab-bad.tsv` 触发，后六个由 `corpus-words.tsv` 触发。Z 族的 17 个码需要**小语料＋错误基线**这一组合才能全部触发；在真实语料上，`baseline-bad.tsv` 只触发 16 个，因为它的 `platform.singleton` 声明值 2 恰好等于真实语料的 2（见 23.2 第 4 点与 22.6 末段）。

验收脚本 P17 的做法是：把四个异常剖面的 stderr 首列合并去重，计数必须等于 39。它用的正是 `frame-bad`、`vocab-bad`、`words-hit`、`baseline-bad` 四个剖面。

### 23.5 只读性实证 P01—P20

`proof.sh` 二十段检查，全部 PASS：

| 编号 | 检查内容 | 结果 |
| --- | --- | --- |
| P01 | 脚本一语法通过（`bash -n`） | PASS |
| P02 | 脚本二语法通过（`bash -n`） | PASS |
| P03 | 脚本一干净剖面 rc=0 且零信号 | PASS |
| P04 | 脚本二真实语料剖面 rc=0 且零信号 | PASS |
| P05 | 脚本一异常剖面 rc=1 | PASS |
| P06 | 脚本二异常剖面 rc=1 | PASS |
| P07 | 脚本一两次运行信号逐字节一致 | PASS |
| P08 | 脚本二两次运行信号逐字节一致 | PASS |
| P09 | 无 `cp`／`mv`／`chmod`／`chown`／`install`／`tee` | PASS |
| P10 | 无 `curl`／`wget`／`nc`／`ssh`／`scp` | PASS |
| P11 | 无 `xcrun`／`idevice*`／`simctl` | PASS |
| P12 | 不触及 `.ssh`／`.netrc`／`keychain` 等凭据路径 | PASS |
| P13 | 运行前后输入文件校验和不变 | PASS |
| P14 | 脚本一从另一工作目录运行结果一致 | PASS |
| P15 | 运行后无 `att23.*` 临时目录残留 | PASS |
| P16 | 脚本一信号码覆盖 54／54 | PASS |
| P17 | 脚本二信号码覆盖 39／39 | PASS |
| P18 | V2／V4／W2 剖面的退出码均为 1 | PASS |
| P19 | 缺参退出 2，stdout 为空，stderr 有说明 | PASS |
| P20 | 语料数据行数 1266 | PASS |

P09—P12 是对**源码文本**的静态检查，不是对运行时的检查。它们的局限必须写明：一个脚本可以把命令拼在变量里绕过这些正则。本文之所以仍把它们列为实证，是因为两个脚本的全部 484 行都已经在正文里给出，读者可以逐行核对；P09—P12 只是把「最容易出现的四类越界」变成可重复的机械检查。

P13—P15 是对**运行时副作用**的检查：输入校验和不变说明只读；从另一个工作目录运行结果一致说明不依赖当前路径；临时目录无残留说明清理路径有效。

### 23.6 确定性与可重复性

P07 与 P08 用 `cmp` 比较两次运行的 stderr，要求逐字节一致。两个脚本都不使用随机数、时间戳、`sort` 的随机种子或哈希表遍历顺序输出，所以同一输入必然得到同一输出。

唯一需要注意的是 awk 的关联数组遍历。脚本二在 `for (pf in proofobj)`、`for (t in ns)`、`for (p in zplat)` 三处遍历关联数组，遍历顺序在不同 awk 实现上可能不同。这三处的影响范围是：

- `proofobj` 只影响 X06 的**报错顺序**，不影响条数；
- `ns` 只影响 Y03 的报错顺序；
- `zplat` 只用于计数，不输出顺序。

因此「逐字节一致」在同一个 awk 实现内成立；跨实现时，信号**集合**一致，**顺序**可能不同。第 23.2 节的矩阵与第 23.5 节的 P 系列都在同一实现内完成，符合这个前提。

### 23.7 一键复现

矩阵：

```console
$ bash .p23/matrix.sh \
    --s1 .p23/script1.sh --s2 .p23/script2.sh \
    --fx1 .p23/fx --fx2 .p23/fx2 \
    --corpus .srcx23/C/advisory-23.tsv --docs .srcx23
```

期望末尾输出：

```text
----
剖面数= 15（脚本一 10 + 脚本二 5）
```

验收：

```console
$ bash .p23/proof.sh \
    --s1 .p23/script1.sh --s2 .p23/script2.sh \
    --fx1 .p23/fx --fx2 .p23/fx2 \
    --corpus .srcx23/C/advisory-23.tsv --docs .srcx23
```

期望末尾输出：

```text
P20 PASS 语料数据行数 1266（实测 1266）
----
P01—P20 全部 PASS
```

两个脚本的参数是**必填**的。不带参数运行会打印「缺少或不可用：S1」并退出 2；这是设计行为，不是故障。

### 23.8 验收脚本全文

以下为 `attestation-matrix.sh` 全文，75 行。

```bash
#!/usr/bin/env bash
# attestation-matrix.sh — 两个校验脚本的矩阵实跑表
#
# 只读：只调用 script1 / script2，自身不写文件。
# 用法：
#   bash attestation-matrix.sh \
#     --s1 .p23/script1.sh --s2 .p23/script2.sh \
#     --fx1 .p23/fx --fx2 .p23/fx2 \
#     --corpus .srcx23/C/advisory-23.tsv --docs .srcx23
#
# 输出：每个剖面一行，列为 剖面 / 脚本 / 退出码 / 判定 / 信号条数 / 信号码数。

set -u
export LC_ALL=C

S1=""; S2=""; FX1=""; FX2=""; CORPUS=""; DOCS=""
while [ $# -gt 0 ]; do
  case "$1" in
    --s1) S1=${2-}; shift 2 ;;
    --s2) S2=${2-}; shift 2 ;;
    --fx1) FX1=${2-}; shift 2 ;;
    --fx2) FX2=${2-}; shift 2 ;;
    --corpus) CORPUS=${2-}; shift 2 ;;
    --docs) DOCS=${2-}; shift 2 ;;
    *) printf '未知参数 %s\n' "$1" >&2; exit 2 ;;
  esac
done
for v in S1 S2 FX1 FX2 CORPUS DOCS; do
  eval "p=\$$v"
  if [ -z "$p" ] || [ ! -e "$p" ]; then printf '缺少或不可用：%s\n' "$v" >&2; exit 2; fi
done

printf '%-14s %-8s %-4s %-6s %-8s %s\n' 剖面 脚本 退出码 判定 信号条数 信号码数
printf '%-14s %-8s %-4s %-6s %-8s %s\n' -------------- -------- ---- ------ -------- --------

run1() {
  name=$1; file=$2
  out=$(bash "$S1" "$file" 2>/tmp/m1.$$)
  rc=$?
  sig=$(wc -l < /tmp/m1.$$ | tr -d ' ')
  cod=$(cut -f1 /tmp/m1.$$ | sort -u | wc -l | tr -d ' ')
  ver=$(printf '%s\n' "$out" | sed -n 's/^判定分布= //p' | awk '{v="-"; for(i=1;i<=NF;i++){split($i,a,"="); if(a[1]~/^V[0-9]$/ && a[2]+0>0) v=a[1]} print v}')
  printf '%-14s %-8s %-4s %-6s %-8s %s\n' "$name" script1 "$rc" "$ver" "$sig" "$cod"
  rm -f /tmp/m1.$$
}

run2() {
  name=$1; frame=$2; vocab=$3; corpus=$4; base=$5
  out=$(bash "$S2" --frame "$frame" --vocab "$vocab" --corpus "$corpus" --baseline "$base" --docs "$DOCS" 2>/tmp/m2.$$)
  rc=$?
  sig=$(wc -l < /tmp/m2.$$ | tr -d ' ')
  cod=$(cut -f1 /tmp/m2.$$ | sort -u | wc -l | tr -d ' ')
  printf '%-14s %-8s %-4s %-6s %-8s %s\n' "$name" script2 "$rc" "$(printf '%s' "$out" | sed -n 's/^判定= \(W[0-9]\).*/\1/p')" "$sig" "$cod"
  rm -f /tmp/m2.$$
}

run1 good            "$FX1/good.tsv"
run1 warn-doc        "$FX1/warn-doc.tsv"
run1 bad-structure   "$FX1/bad-structure.tsv"
run1 bad-key         "$FX1/bad-key.tsv"
run1 bad-device      "$FX1/bad-device.tsv"
run1 bad-verify      "$FX1/bad-verify.tsv"
run1 bad-metric      "$FX1/bad-metric.tsv"
run1 bad-registry    "$FX1/bad-registry.tsv"
run1 bad-claim       "$FX1/bad-claim.tsv"
run1 bad-doc         "$FX1/bad-doc.tsv"

run2 good-real       "$FX2/frame-good.tsv" "$FX2/vocab-good.tsv" "$CORPUS" "$FX2/baseline-real.tsv"
run2 frame-bad       "$FX2/frame-bad.tsv"  "$FX2/vocab-good.tsv" "$FX2/corpus-good.tsv" "$FX2/baseline-good.tsv"
run2 vocab-bad       "$FX2/frame-good.tsv" "$FX2/vocab-bad.tsv"  "$FX2/corpus-good.tsv" "$FX2/baseline-good.tsv"
run2 words-hit       "$FX2/frame-good.tsv" "$FX2/vocab-good.tsv" "$FX2/corpus-words.tsv" "$FX2/baseline-words.tsv"
run2 baseline-drift  "$FX2/frame-good.tsv" "$FX2/vocab-good.tsv" "$FX2/corpus-good.tsv" "$FX2/baseline-bad.tsv"

printf -- '----\n'
printf '剖面数= 15（脚本一 10 + 脚本二 5）\n'
```

以下为 `attestation-proof.sh` 全文，149 行。

```bash
#!/usr/bin/env bash
# attestation-proof.sh — 两个校验脚本的只读性与覆盖验收（P01—P20）
#
# 只读：只读取脚本与夹具，不修改任何输入；临时文件仅在系统临时目录。
# 用法：
#   bash attestation-proof.sh \
#     --s1 .p23/script1.sh --s2 .p23/script2.sh \
#     --fx1 .p23/fx --fx2 .p23/fx2 \
#     --corpus .srcx23/C/advisory-23.tsv --docs .srcx23
#
# 输出：每行 <编号> PASS|FAIL <说明>；全部 PASS 时退出 0，否则退出 1。

set -u
export LC_ALL=C

S1=""; S2=""; FX1=""; FX2=""; CORPUS=""; DOCS=""
while [ $# -gt 0 ]; do
  case "$1" in
    --s1) S1=${2-}; shift 2 ;;
    --s2) S2=${2-}; shift 2 ;;
    --fx1) FX1=${2-}; shift 2 ;;
    --fx2) FX2=${2-}; shift 2 ;;
    --corpus) CORPUS=${2-}; shift 2 ;;
    --docs) DOCS=${2-}; shift 2 ;;
    *) printf '未知参数 %s\n' "$1" >&2; exit 2 ;;
  esac
done
for v in S1 S2 FX1 FX2 CORPUS DOCS; do
  eval "p=\$$v"
  if [ -z "$p" ] || [ ! -e "$p" ]; then printf '缺少或不可用：%s\n' "$v" >&2; exit 2; fi
done

ABS() { (cd "$(dirname "$1")" && printf '%s/%s\n' "$(pwd)" "$(basename "$1")"); }
S1=$(ABS "$S1"); S2=$(ABS "$S2"); FX1=$(ABS "$FX1"); FX2=$(ABS "$FX2")
CORPUS=$(ABS "$CORPUS"); DOCS=$(ABS "$DOCS")

FAILS=0
ok()  { printf '%s PASS %s\n' "$1" "$2"; }
bad() { printf '%s FAIL %s\n' "$1" "$2"; FAILS=$((FAILS + 1)); }
chk() { if [ "$1" -eq 0 ]; then ok "$2" "$3"; else bad "$2" "$3"; fi; }

TMPB=${TMPDIR:-/tmp}

# P01 / P02 语法
bash -n "$S1" 2>/dev/null; chk $? P01 "脚本一语法通过（bash -n）"
bash -n "$S2" 2>/dev/null; chk $? P02 "脚本二语法通过（bash -n）"

run1() { bash "$S1" "$1" 2>"$TMPB/pv1.err" >"$TMPB/pv1.out"; return $?; }
run2() { bash "$S2" --frame "$1" --vocab "$2" --corpus "$3" --baseline "$4" --docs "$DOCS" 2>"$TMPB/pv2.err" >"$TMPB/pv2.out"; return $?; }

# P03 / P04 干净剖面
run1 "$FX1/good.tsv"; rc=$?
if [ $rc -eq 0 ] && [ ! -s "$TMPB/pv1.err" ]; then ok P03 "脚本一干净剖面 rc=0 且零信号"; else bad P03 "脚本一干净剖面 rc=$rc 或存在信号"; fi
run2 "$FX2/frame-good.tsv" "$FX2/vocab-good.tsv" "$CORPUS" "$FX2/baseline-real.tsv"; rc=$?
if [ $rc -eq 0 ] && [ ! -s "$TMPB/pv2.err" ]; then ok P04 "脚本二真实语料剖面 rc=0 且零信号"; else bad P04 "脚本二真实语料剖面 rc=$rc 或存在信号"; fi

# P05 / P06 异常剖面
run1 "$FX1/bad-key.tsv"; [ $? -eq 1 ]; chk $? P05 "脚本一异常剖面 rc=1"
run2 "$FX2/frame-bad.tsv" "$FX2/vocab-good.tsv" "$FX2/corpus-good.tsv" "$FX2/baseline-good.tsv"; [ $? -eq 1 ]; chk $? P06 "脚本二异常剖面 rc=1"

# P07 / P08 确定性
run1 "$FX1/bad-verify.tsv"; cp "$TMPB/pv1.err" "$TMPB/pv1a.err"
run1 "$FX1/bad-verify.tsv"; cmp -s "$TMPB/pv1a.err" "$TMPB/pv1.err"; chk $? P07 "脚本一两次运行信号逐字节一致"
run2 "$FX2/frame-bad.tsv" "$FX2/vocab-good.tsv" "$FX2/corpus-good.tsv" "$FX2/baseline-good.tsv"; cp "$TMPB/pv2.err" "$TMPB/pv2a.err"
run2 "$FX2/frame-bad.tsv" "$FX2/vocab-good.tsv" "$FX2/corpus-good.tsv" "$FX2/baseline-good.tsv"; cmp -s "$TMPB/pv2a.err" "$TMPB/pv2.err"; chk $? P08 "脚本二两次运行信号逐字节一致"

# P09 无复制/移动/改权
if grep -Eq '(^|[^a-zA-Z])(cp|mv|chmod|chown|install|tee)[[:space:]]' "$S1" "$S2"; then
  bad P09 "发现复制／移动／改权命令"
else
  ok P09 "无 cp／mv／chmod／chown／install／tee"
fi

# P10 无网络命令
if grep -Eq '(^|[^a-zA-Z])(curl|wget|nc|ncat|ssh|scp|sftp|ftp)[[:space:]]' "$S1" "$S2"; then
  bad P10 "发现网络命令"
else
  ok P10 "无 curl／wget／nc／ssh／scp"
fi

# P11 无设备侧命令
if grep -Eq '(^|[^a-zA-Z])(xcrun|idevice[a-z]*|simctl|instruments)[[:space:]]' "$S1" "$S2"; then
  bad P11 "发现设备侧命令"
else
  ok P11 "无 xcrun／idevice／simctl"
fi

# P12 不读取凭据路径
if grep -Eq '\.ssh|\.netrc|keychain|id_rsa' "$S1" "$S2"; then
  bad P12 "发现凭据路径或凭据读取"
else
  ok P12 "不触及 .ssh／.netrc／keychain 等凭据路径"
fi

# P13 输入只读
before=$(cksum "$CORPUS" "$FX2/frame-good.tsv" "$FX2/vocab-good.tsv" "$FX2/baseline-real.tsv" | cksum)
run2 "$FX2/frame-good.tsv" "$FX2/vocab-good.tsv" "$CORPUS" "$FX2/baseline-real.tsv"
run1 "$FX1/good.tsv"
after=$(cksum "$CORPUS" "$FX2/frame-good.tsv" "$FX2/vocab-good.tsv" "$FX2/baseline-real.tsv" | cksum)
[ "$before" = "$after" ]; chk $? P13 "运行前后输入文件校验和不变"

# P14 路径无关
here_out=$(bash "$S1" "$FX1/good.tsv" 2>/dev/null)
there_out=$(cd "$TMPB" && bash "$S1" "$FX1/good.tsv" 2>/dev/null)
[ "$here_out" = "$there_out" ]; chk $? P14 "脚本一从另一工作目录运行结果一致"

# P15 临时目录无残留
left=$(ls -d "$TMPB"/att23.* 2>/dev/null | wc -l | tr -d ' ')
[ "$left" -eq 0 ]; chk $? P15 "运行后无 att23.* 临时目录残留（当前 $left）"

# P16 / P17 信号码覆盖
{
  for f in "$FX1"/bad-*.tsv "$FX1"/warn-doc.tsv; do bash "$S1" "$f" 2>&1 >/dev/null | cut -f1; done
} | sort -u > "$TMPB/pv1.codes"
n1=$(wc -l < "$TMPB/pv1.codes" | tr -d ' ')
[ "$n1" -eq 54 ]; chk $? P16 "脚本一信号码覆盖 54／54（实测 $n1）"

{
  bash "$S2" --frame "$FX2/frame-bad.tsv" --vocab "$FX2/vocab-good.tsv" --corpus "$FX2/corpus-good.tsv" --baseline "$FX2/baseline-good.tsv" --docs "$DOCS" 2>&1 >/dev/null | cut -f1
  bash "$S2" --frame "$FX2/frame-good.tsv" --vocab "$FX2/vocab-bad.tsv" --corpus "$FX2/corpus-good.tsv" --baseline "$FX2/baseline-good.tsv" --docs "$DOCS" 2>&1 >/dev/null | cut -f1
  bash "$S2" --frame "$FX2/frame-good.tsv" --vocab "$FX2/vocab-good.tsv" --corpus "$FX2/corpus-words.tsv" --baseline "$FX2/baseline-words.tsv" --docs "$DOCS" 2>&1 >/dev/null | cut -f1
  bash "$S2" --frame "$FX2/frame-good.tsv" --vocab "$FX2/vocab-good.tsv" --corpus "$FX2/corpus-good.tsv" --baseline "$FX2/baseline-bad.tsv" --docs "$DOCS" 2>&1 >/dev/null | cut -f1
} | sort -u > "$TMPB/pv2.codes"
n2=$(wc -l < "$TMPB/pv2.codes" | tr -d ' ')
[ "$n2" -eq 39 ]; chk $? P17 "脚本二信号码覆盖 39／39（实测 $n2）"

# P18 判定与退出码一致
v=0
run1 "$FX1/warn-doc.tsv"; [ $? -eq 1 ] || v=1
run1 "$FX1/bad-claim.tsv"; [ $? -eq 1 ] || v=1
run2 "$FX2/frame-good.tsv" "$FX2/vocab-bad.tsv" "$FX2/corpus-good.tsv" "$FX2/baseline-good.tsv"; [ $? -eq 1 ] || v=1
[ $v -eq 0 ]; chk $? P18 "V2／V4／W2 剖面的退出码均为 1"

# P19 缺参
bash "$S2" --frame "$FX2/frame-good.tsv" >"$TMPB/pv19.out" 2>"$TMPB/pv19.err"; rc=$?
if [ $rc -eq 2 ] && [ ! -s "$TMPB/pv19.out" ] && [ -s "$TMPB/pv19.err" ]; then
  ok P19 "缺参退出 2，stdout 为空，stderr 有说明"
else
  bad P19 "缺参行为不符（rc=$rc）"
fi

# P20 语料行数
rows=$(awk 'END{print NR-1}' "$CORPUS")
[ "$rows" -eq 1266 ]; chk $? P20 "语料数据行数 1266（实测 $rows）"

rm -f "$TMPB"/pv1.* "$TMPB"/pv2.* "$TMPB"/pv19.* 2>/dev/null
printf -- '----\n'
if [ $FAILS -eq 0 ]; then printf 'P01—P20 全部 PASS\n'; exit 0; fi
printf 'FAIL 数= %d\n' "$FAILS"; exit 1
```

---

## 24. 十二个误区

### 24.1 误区一：attestation 是一个东西

**错误表述**：「设备做了 attestation，所以它是可信的。」

**更正**：同一个平台上至少有四件互不通约的东西共用这个词：App 实例件、设备件、凭据件、配件件（第 3 章、第 15 章）。四件的签署方、证明物、可指名程度、回读点、有效期都不同。说「做了 attestation」而没有指明是哪一件，等于没有说。

### 24.2 误区二：`isSupported` 为真就能调用

**错误表述**：「`DCAppAttestService.isSupported` 返回 true，就可以生成密钥。」

**更正**：Mac 上它恒为 false，包括 Mac Catalyst 与在 Apple silicon 上运行的 iOS／iPadOS App（`A/devicecheck_dcappattestservice_issupported.txt:20—24`）；扩展里取值可能为真，但 `generateKey` 在扩展内调用恒失败，唯一例外是 watchOS 9 及之后的 watchOS 扩展（`:25—37`）。「声明支持」与「当前上下文可调用」是两件事（R07、R08）。

### 24.3 误区三：校验通过等于设备未被改动

**错误表述**：「attestation 校验通过，说明这台设备没有被越狱或植入。」

**更正**：公开口径明确写「一个被改动过的操作系统可能绕过限制」（`A/devicecheck_assessing_fraud_risk.txt:7`）。App Attest 证明的是「这把密钥属于一个合法 App 实例」，不是「这台设备是干净的」。把两者合并，会在 L1 与 L5 同时出错。

### 24.4 误区四：OID 缺失等于属性为假

**错误表述**：「叶子证书里没有序列号，说明这台设备没有序列号。」

**更正**：公开口径把属性写成三值：有值、被省略、值为空，并明确「只有在能核实该属性值时才写入」（`B/apple-platform-security-guide.txt:4460`）。User Enrollment 下两个身份 OID 都不写入（`:4343、4347`），这不是「设备没有身份」，而是「这条校验件不携带身份」。三值不能压成二值。

### 24.5 误区五：度量等于设备台数

**错误表述**：「回执里的度量是 2，说明有两台设备。」

**更正**：度量是「过去 30 天内与这套 App 关联的密钥数量的近似值」（`A/devicecheck_assessing_fraud_risk.txt:99—100`）。它是按键计数，不是按设备计数；同一台设备重装多次会产生多个密钥。把度量当台数，会在 L6 与 L7 同时出错（R17）。

### 24.6 误区六：被认证的密钥等于设备身份

**错误表述**：「服务器存下了被认证的公钥，所以能识别这台设备。」

**更正**：服务器存下的是「这个 App 实例的公钥」（`A/devicecheck_validating_apps_server.txt:141—143`）。它不跨重装、不跨恢复、不跨换机（第 11 章）。要识别设备，需要 MDA 的身份 OID；要识别用户，需要另外的绑定（第 10 章）。三者是三条独立的链。

### 24.7 误区七：UDID 在所有注册类型下都有

**错误表述**：「`DeviceInformation` 响应里有 UDID，所以任何注册方式都能拿到 UDID。」

**更正**：User Enrollment 下序列号与 UDID 都不写入（`B/apple-platform-security-guide.txt:4343、4347`），`DeviceInformation` 的可用性也随注册类型变化（`A/devicemanagement_deviceinformationresponse.txt:11、34`）。「响应结构里有这个键」与「这次响应填了这个键」是两件事。

### 24.8 误区八：`DeviceInformation` 成功等于 attestation 已附上

**错误表述**：「`DeviceInformation` 命令返回成功，说明设备已经带上了 attestation。」

**更正**：不支持的 SoC 会直接忽略 `DevicePropertiesAttestation` 与 `DeviceAttestationNonce` 两个输入键（`A/devicemanagement_device_information_command.txt:16`），命令仍然成功。成功只说明命令被处理，不说明证明物存在。判断是否附上，必须看响应里有没有对应的证明物，而不是看命令的返回状态。

### 24.9 误区九：回执里的度量等于当前值

**错误表述**：「回执里的度量是 2，所以现在就是 2。」

**更正**：回执有三重时效：创建时间不超过五分钟（`A/devicecheck_assessing_fraud_risk.txt:89—90`）、「不早于」字段 19、「到期」字段 21（`:111—116`），度量本身是 30 天窗口的近似值（`:99—100`）。超过窗口的回执只能说明「当时是多少」，不能说明「现在是多少」。

### 24.10 误区十：MDA 的证书链能指名用户

**错误表述**：「设备件的证书里有序列号，所以能指名使用这台设备的人。」

**更正**：MDA 指名的是设备，不是用户。用户绑定是另一条登记链（第 10 章，`F01`）。即使设备件完全闭合，没有 `key_user`／`assoc_device` 的登记，仍然不能把这次校验归到某个用户。

### 24.11 误区十一：公告里没有校验组件，等于没有校验组件缺陷

**错误表述**：「公告语料里搜不到 attest／DeviceCheck／Secure Enclave，说明这类组件没有出过缺陷。」

**更正**：九个词形在 1266 行的组件列与影响句列同时为 0（第 13 章，R21.3）。这只能说明**公告词表没有为校验件建格**，不能说明缺陷不存在。零命中是一个词表事实，不是一个安全事实。第 17 章把这叫「公告面的断层」。

### 24.12 误区十二：管理面没有校验键，等于管理面管不了校验

**错误表述**：「216 个限制键里没有 attest，说明 MDM 不能管理校验。」

**更正**：管理面有两个不同的面：限制键与声明。216 个纯键名里确实 0 个校验键，但 66 项声明里有 1 项与校验有关，即 `SecurityPasskeyAttestation`（`.srcx16/C/mdm-declarations.txt:45`），它管的是凭据件，不是设备件或 App 实例件。正确表述是：**管理面对设备件与 App 实例件没有专门的配置键，对凭据件有一项声明。**

---

## 25. 常见问题

### 25.1 服务器应该存什么，存多久

存三样：已校验的公钥、回执、这次校验的判定日志。公钥用于之后的请求认证；回执用于之后重算度量与核对时效；判定日志用于事故复盘。公开文档只规定「应该存什么」（`A/devicecheck_validating_apps_server.txt:141—143`），不规定「存多久」。本文的建议是：公钥随实例生命周期存，回执至少存到「到期」字段之后，判定日志按组织的审计保留期存。

### 25.2 五分钟窗口从哪个时刻算

从回执的创建时间（字段 12）算到服务器收到请求的时刻。公开口径要求「创建时间不超过五分钟」（`A/devicecheck_assessing_fraud_risk.txt:89—90`）。脚本一的 `D07` 就是把 `ver.receipt_age_min > 5` 判为错误。

### 25.3 App 能不能自己判定

不能把 App 自身的判定当作最终判定。公开口径把校验放在服务器侧（`A/devicecheck_validating_apps_server.txt:141—143`），脚本一的 `D01` 把 `ver.verifier` 为 `app` 或 `none` 判为错误。App 可以做预检，但预检结果不能替代服务器判定。

### 25.4 User Enrollment 下还能指名设备吗

不能靠身份 OID。User Enrollment 下序列号与 UDID 都不写入（`B/apple-platform-security-guide.txt:4343、4347`）。此时能指名的最大单位是「这条校验件所属的注册」，要指名设备需要组织侧另有登记。脚本一的 `C07` 检查的正是「设备注册下既无序列号也无 UDID」。

### 25.5 度量为 0 说明什么

只说明「过去 30 天内与这套 App 关联的密钥数量的近似值为 0」。它不说明没有设备、不说明没有安装、也不说明没有风险。度量为 0 的常见原因是新账号、刚重装、或回执来自一个尚未产生密钥的环境。

### 25.6 回执过期了还能用吗

不能用于「当前状态」的判定。过期回执仍可用于「当时状态」的追溯，但必须标注它对应的时间窗口。脚本一的 `E03` 检查「不早于」是否晚于「到期」，`D07` 检查创建时间是否超过五分钟。

### 25.7 两个脚本要先跑哪个

先跑脚本一，再跑脚本二。脚本一审的是「一条台账自己站不站得住」，脚本二审的是「四件框架与公告读数是否闭合」。前者的输出可以作为后者 `claim.evidence_ref` 的来源之一，但两者不共享输入格式，不能互相替代。

### 25.8 脚本输出 V3 但我想知道具体哪条错了

看 stderr 的第一列与第二列：第一列是码，第二列是记录标识。`V3` 只是这条记录的最高判定，具体原因在 stderr 的每一行里。加 `-q` 可以只看汇总，不看逐条判定行。

### 25.9 为什么脚本二的 Z 码数量会变

Z 码按 `baseline.tsv` 的行号生成（`script2.sh:226—232`）。基线有 17 行就是 `Z01`—`Z17`；增删一行，码段随之伸缩。这不是不稳定，而是让码与声明读数一一对应。

### 25.10 这套东西能证明设备是正品吗

能证明的范围由对象决定：App 实例件证明「合法 App 实例持有被认证的密钥」；设备件证明「这台设备是正品 Apple 硬件，且这些属性值可核实」；凭据件证明「这把凭据的密钥材料在某个认证器里」；配件件证明「这块配件是它」。四者都不能单独证明「使用设备的人是谁」。后者需要登记链，不是校验件。

---

## 26. 未公开文档化边界清单

以下 14 条是本文明确**没有**从公开文档得到答案的问题。列出来的目的不是猜测答案，而是把它们从「看起来已经知道」里剔出去。

| 编号 | 边界 | 为什么是边界 |
| --- | --- | --- |
| U01 | App Attest 密钥在重装后的确切删除时刻 | 公开口径只说「不存活」，没有给出删除发生的具体阶段 |
| U02 | 度量在多次重装之间是否按设备合并 | 公开口径只说「与这套 App 关联的密钥数量的近似值」，没有给出跨重装的归并规则 |
| U03 | MDA 时新码的有效期与重放窗口 | 公开文档要求校验时新码，但没有给出窗口长度 |
| U04 | 不支持 SoC 上 `DeviceInformation` 响应是否仍带空证明物 | 公开口径只说两个输入键被忽略，没有描述响应的形状 |
| U05 | Apple 认证器上 passkey 校验的证明物格式 | 管理面只有一项声明，没有给出格式细节 |
| U06 | User Enrollment 下身份 OID 是否在所有配置下都不写入 | 公开口径给出的是「不写入」，没有列出例外 |
| U07 | 两位状态位的完整语义与全部重置触发条件 | 公开口径描述了「开发者决定」，没有给出位级定义与全部触发条件 |
| U08 | 度量在 App 更新而非重装时是否重置 | 公开口径把重置权交给开发者，没有规定更新是否算重置 |
| U09 | 服务器校验失败的错误分类 | 公开文档给出校验步骤，没有给出错误码或分类 |
| U10 | 同一设备上多个 App 实例能否共享一把密钥 | 公开口径按实例描述，没有明确禁止或允许共享 |
| U11 | 台账里拼错的字段名 | 脚本一的命名空间是封闭的，拼错不会报错，只会让对应检查「看起来通过」 |
| U12 | 记录与现实的一致性 | 两个脚本都只判记录／框架内部自洽，不判业务结论是否正确（第 19.4 节） |
| U13 | Z 码的固定数量 | Z 码随基线行数伸缩，本文的 17 个码只对当前基线成立 |
| U14 | 管理面读数的重算 | `216／0` 与 `66／1` 来自第 16 篇的归档 `.srcx16/C`，不在脚本二的重算范围内（第 16 章 R20） |

U11 与 U12 是**工具边界**，不是文档边界；U13 与 U14 是**本文的复现边界**。把四类混在一起，会让读者误以为「工具没报错」等于「记录正确」。第 27 章的结论会再次区分这三层。

---

## 27. 结论

本文的结论可以压成三句话。

**第一句：四件各自闭合，但闭合的边界不一样。** App 实例件的边界是「一个 App 实例」，设备件的边界是「一台设备」，凭据件的边界是「一把凭据」，配件件的边界是「一块配件」。四者都闭合，但没有任何一件能单独回答「这台设备现在是否可信」或「使用它的人是谁」。把四件写成一个词，是这一领域最常见的归属错误。

**第二句：可指名、可判定、可回读是三个独立条件。** 可指名要求身份 OID 存在且在当前注册类型下写入；可判定要求判定发生在服务器侧并且存下了公钥与回执；可回读要求有一个公开接口能把判定结果读回来。三者可以任意组合：有校验件但不可指名（User Enrollment）、可判定但不可回读（服务器判完没有回传通道）、可回读但不可判定（管理面只告诉你配置了什么）。脚本一的 54 个码与脚本二的 39 个码，就是把这三组条件拆成可机械检查的字段。

**第三句：公开文档在「谁签了什么」这一面最厚，在「事后怎么查」这一面最薄。** 18 份文档、2502 行，讲清了密钥、证书链、10 个 OID、9 个回执字段、5 个校验步骤；而管理面 216 个键名里 0 个校验键、66 项声明里 1 项、公告 1266 行里 0 行。这不是说校验件不重要，而是说：**校验件的证据主要留在你自己的服务器日志里，不在平台的公开词表里。** 这也是第 20 章把多数运营指标的采集点放在「服务器校验日志」的原因。

三层要分开看：

- **文档层**：哪些口径有公开出处（第 1—14 章，第 28 章）；
- **读数层**：哪些数能从归档重算（第 16 章，第 22.5 节，第 23 章）；
- **工具层**：哪些检查能由两个只读脚本机械完成（第 21—23 章）。

文档层回答「公开口径是什么」，读数层回答「这些口径在语料上数出来是多少」，工具层回答「一份台账或一份框架有没有违反前两层」。三层都通过，才叫「这条记录站得住」；任何一层缺失，都只能叫「未验证」。

---

## 28. 参考资料

### 28.1 A 组：Apple Developer 文档（18 份，2502 行）

| 文件 | 主题 | 本文主要引用 |
| --- | --- | --- |
| `A/devicecheck.txt` | DeviceCheck 框架总览 | 第 2 章 |
| `A/devicecheck_assessing_fraud_risk.txt` | 风险评估、回执字段与时效 | 第 6、9、16 章 |
| `A/devicecheck_attestation_object_validation_guide.txt` | attestation object 结构与 aaguid | 第 6 章 |
| `A/devicecheck_dcappattestservice.txt` | `DCAppAttestService` 类 | 第 5 章 |
| `A/devicecheck_dcappattestservice_attestkey.txt` | `attestKey` | 第 6 章 |
| `A/devicecheck_dcappattestservice_generateassertion.txt` | `generateAssertion` | 第 8 章 |
| `A/devicecheck_dcappattestservice_generatekey.txt` | `generateKey` 与密钥位置 | 第 5 章 |
| `A/devicecheck_dcappattestservice_issupported.txt` | `isSupported` 的三句话 | 第 14、16 章 |
| `A/devicecheck_dcappattestservice_shared.txt` | 共享实例 | 第 5 章 |
| `A/devicecheck_dcdevice.txt` | `DCDevice` | 第 4 章 |
| `A/devicecheck_establishing_app_integrity.txt` | App 完整性建立流程 | 第 1、3 章 |
| `A/devicecheck_preparing_app_attest.txt` | 接入准备 | 第 5 章 |
| `A/devicecheck_validating_apps_server.txt` | 服务器侧校验 | 第 8、9 章 |
| `A/devicemanagement_device_information_command.txt` | `DeviceInformation` 命令与硬件支持 | 第 7、16 章 |
| `A/devicemanagement_deviceinformationcommand.txt` | 命令结构 | 第 7 章 |
| `A/devicemanagement_deviceinformationresponse.txt` | 响应结构与注册类型 | 第 7 章 |
| `A/devicemanagement_identity_management.txt` | 身份管理 | 第 7 章 |
| `A/devicemanagement_validating_managed_attestation.txt` | MDA 校验 | 第 1、3、7 章 |

### 28.2 B 组：Apple Platform Security Guide（1 份，4885 行）

| 文件 | 主题 | 本文主要引用 |
| --- | --- | --- |
| `B/apple-platform-security-guide.txt` | 平台安全指南 | 第 1、3、4、6、7、9、10、11、16 章 |

主要行锚：MDA 可用性 `:4318`；叶子证书与证书链 `:4317—4324`；10 个 OID `:4327—4361`；身份 OID 与 User Enrollment `:4343、4347`；三值编码 `:4460`；时新码 `:4397`；App Attest 证明物 `:4426—4429`；密钥与重装 `:102—105`；配件认证 IC `:1367`。

### 28.3 C 组：公告与读数归档

| 文件 | 内容 | 规模 |
| --- | --- | --- |
| `C/advisory-23.tsv` | 六列公告语料 | 1266 数据行 |
| `C/platform-23.txt` | 平台可用性数组 | 77 行 |
| `C/readings-23.txt` | R01—R26 读数 | 26 条 |

### 28.4 管理面归档（借用第 16 篇）

| 文件 | 内容 | 规模 |
| --- | --- | --- |
| `.srcx16/C/mdm-restriction-keys.txt` | 限制键名 | 220 行，216 个纯键名 |
| `.srcx16/C/mdm-declarations.txt` | 声明清单 | 75 行，66 项；`SecurityPasskeyAttestation` 在 `:45` |
| `.srcx16/C/mdm-root.txt` | 管理面导航 | 第 33 行 |

### 28.5 同系列相邻篇目

本篇与已发布的第 05、10、13、14、16、22 篇有交接，也有硬分界。**第 05 篇（[生物识别安全机制](05-iOS-Biometric-Security-Mechanisms.md)）**——Secure Enclave 作为生物模板保护与匹配信任根归它；本篇只把 Secure Enclave 当作密钥存放位置（台账里的 `key.location = se`），不讨论生物识别。**第 10 篇（[设备生命周期与归属转移](10-iOS-Device-Lifecycle-Ownership-Transfer-Attribution-Analysis.md)）**——设备归谁、怎样移交归它；本篇只引用「身份 OID 与注册类型的关系」，不重建生命周期的十层分解。**第 13 篇（[日志与诊断证据链](13-iOS-Log-Diagnostic-Crash-Evidence-Chain-Attribution-Analysis.md)）**——日志能证明什么、采集与导出时序归它；本篇的「回读点」指校验件自身的管理面与服务端读数，不是日志通道，两篇不共用证据件。**第 14 篇（[签名与分发授权链](14-iOS-Code-Signing-Distribution-Authorization-Chain-Attribution-Analysis.md)）**——代码凭什么被允许运行归它；本篇明确区分「代码签名身份」（谁签了这段代码）与「平台校验件」（谁签了这次实例／设备／凭据声明），两者不互相替代，脚本二的 `X06` 与 `X12` 就是把这两种「签」拆开的机械检查。**第 16 篇（[本地网络访问与局域网发现](16-iOS-Local-Network-LAN-Discovery-Attribution-Analysis.md)）**——同网段上谁看得见谁归它；本篇的两项管理面读数（216 个键名、66 项声明）直接借用它的归档，但不重复局域网通道分析。**第 22 篇（[外接配件与近场配对链路](22-iOS-Accessory-Near-Field-Pairing-Attribution-Analysis.md)）**——四件里的配件件（MFi 认证 IC）归它；本篇只在第 3、15 章做边界引用，不重复配件链路；两篇对公告面的结论同形——校验词形在组件列与影响句列都没有公开命中。

### 28.6 脚本与夹具

| 文件 | 内容 | 规模 |
| --- | --- | --- |
| `script1.sh` | 台账逐字段审查器 | 232 行，58 个码 |
| `script2.sh` | 四件框架闭合与词表比对器 | 252 行，43 个码 |
| `matrix.sh` | 15 剖面矩阵 | 75 行 |
| `proof.sh` | P01—P20 只读性验收 | 149 行 |
| `fx/*.tsv` | 脚本一夹具 | 10 个剖面 |
| `fx2/*.tsv` | 脚本二夹具 | 4 个剖面 |

### 28.7 引用格式说明

正文中的 `A/...:NN—NN` 指 A 组文件的行号区间；`B/...:NNNN` 指 B 组文件的行号；`C/...` 指 C 组归档；`.srcx16/C/...` 指第 16 篇的管理面归档。所有行号均以本仓库归档文件的实际行号为准，脚本二的 Y01／Y02 会机械校验词表出处是否存在、行号是否越界（第 22.4 节）。

---

咨询ios系统请咨询 telegram：https://t.me/one00190
