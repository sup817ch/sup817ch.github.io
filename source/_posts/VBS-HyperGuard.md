---
title: VBS & HyperGuard
date: 2020-07-03 15:02:00
tags:
---

# Virtualization-based security

Virtuallization-based security (VBS)是在Windows10添加的新功能，通过使用硬件虚拟化功能来创建和隔离安全内存区域与正常操作系统。VBS通过virtual trust level (VTL)来区分安全内存区域和正常操作系统，正常的用户模式和内核代码都运行在VTL 0当中，VTL 1中的代码对于VTL 0来说是隐藏的且不可访问的。VBS仅支持Windows企业版和服务器版。

<!-- more -->

开启方法：

1.运行gpedit (Win+R gpedit.msc)，修改本地组策略。

2.找到计算机配置 -> 管理模板 -> 系统 -> Device Guard，选择Turn On Virtualization Based Security。

![](https://techcommunity.microsoft.com/t5/image/serverpage/image-id/86562i0698EB0C6CEA92B2)

3.设置对应选项。

![](https://techcommunity.microsoft.com/t5/image/serverpage/image-id/86563iCF55809E21D55921)

4.重启



VBS有两个重要的功能，Credential Guard和Device Guard。

## Credential Guard

一些重要的凭据会呈现在lsass的内存当中，攻击者可以轻易的通过各种方法从内存中获取这些凭据。Credential Guard通过使用运行在VTL 1当中的Lsaiso.exe代替lsass等技术来解决这一问题。

## Device Guard

Device Guard的作用是保护用户的机器不受各种基于软件和硬件的攻击。Device Guard通过HyperVisor Code Integrity (HVCI)来增强Windows Code Integrity 服务。

Device Guard提供的功能如下：

- 如果强制执行内核模式代码签名，则只有签名过的代码可以被加载，不管内核本身是否被破坏。
- 如果强制执行内核模式代码签名，则已签名的代码在加载后不能被修改。
- 如果强制执行内核模式代码签名，则动态分配代码是被禁止的（不能分配可执行的内存）。
- 如果强制执行内核模式代码签名，则UEFI运行时代码不能被修改。
- 如果强制执行内核模式代码签名，则只有已签名的内核模式(Ring 0)代码可以执行。
- 如果强制执行用户模式代码签名，则只有已签名的用户模式映像能被加载。
- 如果强制执行用户模式代码签名，则内核不允许用户模式的应用让现有的可执行代码页可写。
- 如果强制执行用户模式代码签名，并且签名策略请求硬编码保证(hard code guarantees)，则禁止动态分配代码。
- 如果强制执行用户模式PowerShell受限语言模式，则必须对所有使用动态类型，反射或其他语言功能来执行Windows/.NET API函数的PowerShell脚本签名。

# HyperGuard

HyperGuard是在运行了VBS的系统上的一项机制，用于保护内核完整性，在Windows 10 1607上就已出现。HyperGuard与PatchGuard的检查范围相似，但更为强大。HyperGuard不依赖混淆且提供了所有的符号文件，使得完整的静态分析HyperGuard变为可能，但即使知道了HyperGuard的实现原理也难以对其造成影响。

HyperGuard不同于PatchGuard，破坏内核的行为一发生就会被检测到，进而使系统蓝屏，蓝屏代码为0x18C (HYPERGUARD_VIOLATION)。