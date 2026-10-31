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

Contact: telegram https://t.me/one00190
