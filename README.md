# iOS Security Report Series

本仓库收录 iOS 系统安全防御分析报告，全部基于公开资料（Apple 官方文档与开源分发源码、Apple 安全公告、CISA KEV 目录）整理，不含可用的漏洞利用代码、提权或绕过步骤。

在线站点（渲染后的正文主版本）：<https://ios-security-reports-0e8t10askpz.qoder.website/>
- sitemap：<https://ios-security-reports-0e8t10askpz.qoder.website/sitemap.xml>

| # | 报告 | 主题 |
| --- | --- | --- |
| 01 | [iMessage 为什么成为攻击入口](01-iMessage-Attack-Entry-Analysis.md) | 消息链路的攻击面与防御口径 |
| 02 | [iOS 访问控制与应用层交互限制](02-iOS-AccessControl-App-Interaction.md) | 权限模型、跨应用交互与限制面 |
| 03 | [iOS 应用防护与抓包审计](03-iOS-App-Protection-Packet-Audit.md) | 应用侧防护机制与传输审计口径 |
| 04 | [iOS 身份认证与通道加密](04-iOS-Authentication-Channel-Encryption.md) | 认证链路与加密通道全景 |
| 05 | [iOS 系统生物识别安全机制](05-iOS-Biometric-Security-Mechanisms.md) | 生物识别的机制、边界与取证口径 |
| 06 | [iOS XPC 与 Mach IPC 系统服务缺陷归属防御分析](06-iOS-XPC-and-Mach-IPC-System-Service-Defect-Analysis.md) | 十层 Mach IPC 表面、X1–X12 缺陷类型学、层 × 责任 × 更新通道归属矩阵、四级判定模型与两个离线只读核验脚本 |
| 07 | [iOS APNs 推送通知投递链路缺陷归属防御分析](07-iOS-APNs-Push-Delivery-Chain-Defect-Analysis.md) | 十层推送投递表面、N1–N12 缺陷类型学、层 × 责任方 × 更新通道归属矩阵、文档口径与公告口径两套词表、四级判定模型与两个离线只读核验脚本 |
| 08 | [iOS 隐私授权链路与用途声明缺陷归属防御分析](08-iOS-Privacy-Authorization-Chain-Defect-Analysis.md) | 十层授权链路表面、P1–P12 缺陷类型学、声明口径/框架状态机口径/申报口径三套词表、层 × 责任方 × 更新通道归属矩阵、四级判定模型与两个离线只读核验脚本 |
| 09 | [iOS 更新链与补丁传导归属防御分析](09-iOS-Update-Chain-Patch-Propagation-Attribution-Analysis.md) | 十层更新链路表面（公告与 CSAF、版本目录与签名时效、安装授权、分发形态、整版本与 Background Security Improvements、MDM 延期、声明式强制、状态回执、回滚与移除、外设旁路）、P1–P12 缺陷类型学、三套词表与七处换算失败、归属矩阵、18 条公开读数、四级判定模型与两个离线只读核验脚本 |
| 10 | [iOS 设备生命周期与所有权移交归属防御分析](10-iOS-Device-Lifecycle-Ownership-Transfer-Attribution-Analysis.md) | 十层归属表面（归属登记与设备标识、入册通道、监管与命令权限、锁定与托管凭据、丢失模式与远程锁定、抹除与密钥遗留、账户生命周期、管理服务迁移、回执与读数、旁路与不可判定通道）、P1–P12 缺陷类型学、三套词表与七处换算失败、层 × 责任方 × 通道 × 证据归属矩阵、四级判定模型与两个离线只读核验脚本（51 + 23 个信号码） |
| 11 | [iOS 备份与恢复链路数据副本归属防御分析](11-iOS-Backup-Restore-Data-Copy-Attribution-Analysis.md) | 十层副本链路表面（副本产生与触发、副本落点与介质、内容集合、排除项与其效力、密钥形态、可解性归属与 custody、恢复与归属重建、删除与可证清除、管理面与组织可见性、公告与合规口径）、P1–P12 缺陷类型学、副本口径/平台安全口径/公开公告口径三套词表与七处换算失败、层 × 责任方 × 介质 × 证据归属矩阵、18 条公开读数、四级判定模型与两个离线只读核验脚本（86 + 32 个信号码） |
| 12 | [iOS 第三方 SDK 与依赖代码供应链归属防御分析](12-iOS-Third-Party-SDK-Dependency-Supply-Chain-Attribution-Analysis.md) | 十层供应链表面（声明与锁定、解析与装配、二进制形态与签名身份、平台签名与库校验口径、强制名单与隐私清单申报、版本可观测性、公告与 CVE 归属、移除与可证消失、组织侧可见性、构建可重现与审核口径）、P1–P12 缺陷类型学、装配口径/平台签名口径/公告归属口径三套词表与七处换算失败、四个归属主体的层 × 主体 × 形态 × 证据矩阵、18 条公开读数、四级判定模型两套（J1—J4 与 Q1—Q4）与两个离线只读核验脚本（64 + 34 个信号码） |
| 13 | [iOS 日志、诊断与崩溃证据链归属防御分析](13-iOS-Log-Diagnostic-Crash-Evidence-Chain-Attribution-Analysis.md) | 十条证据链层（产生、留存、隐私、标识、时间、符号、通道、同意与管理面、覆盖与分母、交付与归属、公告回查）、P1–P14 缺陷类型学、日志口径/崩溃字段口径/通道能力口径三套词表与八处换算失败、层 × 主语 × 通道 × 证据归属矩阵、18 条公开读数、四级判定模型两套（J1—J4 与 Q1—Q4）与两个离线只读核验脚本（58 + 34 个信号码） |
| 14 | [iOS 签名与分发授权链归属防御分析](14-iOS-Code-Signing-Distribution-Authorization-Chain-Attribution-Analysis.md) | 十一层授权链（身份、签发、形态、范围、权利、时效、失效与校验、观测平面、通道差异、复核处置、公告回查）、P1–P14 缺陷类型学、授权对象口径/执行口径/公告口径三套词表与八处换算失败、九通道 × 22 要素可得性矩阵、两个到期日与两种时间戳、18 条公开读数、四个读数面、两套四级判定模型（J1—J4 与 Q1—Q4）、10 项运营指标与两个离线只读核验脚本（64 + 44 = 108 个信号码全部实跑触发） |

Contact: telegram https://t.me/one00190
