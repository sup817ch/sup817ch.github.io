---
title: Windows 域控笔记（一）
date: 2020-12-24 11:09:26
tags:
---

本篇介绍一些基础概念和相关知识

<!-- more -->

# 什么是域？

Windows域通常用于大型网络——公司网络、学校网络和政府网络。除非你有雇主或学校提供的笔记本电脑，否则你在家里不会遇到这种情况。

典型的家用计算机是一个孤立的实体。您可以控制计算机上的设置和用户帐户。连接到域的计算机是不同的——这些设置是在**域控制器(DC, domain controller)** 上控制的。

Windows域为网络管理员提供了一种方法来管理大量的pc机，并从一个地方控制它们。一个或多个服务器(称为域控制器)控制域及其上的计算机。

域通常由在同一本地网络上的计算机组成。但是，连接到某个域的计算机可以通过VPN或Internet连接继续与域控制器通信。这使得企业和学校能够远程管理他们提供给员工和学生的笔记本电脑。

当计算机连接到一个域时，它不会使用自己的本地用户帐户，用户帐户和密码都是在域控制器上统一管理。当您登录到该域中的计算机时，计算机将使用域控制器验证您的用户帐户名称和密码。这意味着您可以在任何连接到该域的计算机上使用相同的用户名和密码登录。

网络管理员可以更改“域控制器”上的组策略设置。域上的每台计算机将从“域控制器”获得这些设置，它们将覆盖用户在其pc上指定的任何本地设置。所有的设置都是从一个地方控制的。这也“锁定”了计算机。您可能不允许更改连接到域的计算机上的许多系统设置。



# 域环境搭建

http://blog.sina.com.cn/s/blog_6ce0f2c901014okt.html

http://www.it165.net/os/html/201306/5493.html



# Kerberos

[Windows 2000](https://zh.wikipedia.org/wiki/Windows_2000)和后续的操作系统使用Kerberos为其默认认证方法。[RFC 3244](https://tools.ietf.org/html/rfc3244) "微软Windows 2000 Kerberos变更密码与设置密码协议" 记录整理一些[微软](https://zh.wikipedia.org/wiki/微软)对Kerberos协议软件包的添加。[RFC 4757](https://tools.ietf.org/html/rfc4757) 记录整理微软对[RC4](https://zh.wikipedia.org/wiki/RC4)密码的使用。虽然微软使用Kerberos协议，却并没有用麻省理工的软件。

维基：

https://zh.wikipedia.org/wiki/Kerberos

其他资料：

[能用通用的语言介绍下 Kerberos 协议么？](https://www.zhihu.com/question/22177404)（通俗解释）

[Kerberos Authentication Explained](https://www.varonis.com/blog/kerberos-authentication-explained/)

[kerberos认证原理](https://blog.csdn.net/wulantian/article/details/42418231)

[Steal or Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558/) （对Kerberos的一些攻击方式）



# Mimikatz

Mimikatz是一款开源应用程序，允许用户查看和保存Kerberos tickets之类的身份验证凭据。本杰明·德尔皮（Benjamin Delpy）继续领导Mimikatz的开发，因此该工具集可与当前版本的Windows配合使用，并包括最新的攻击。

**Mimikatz能做什么**

- **Pass-the-Hash:** Windows used to [store password data in an NTLM hash](https://www.varonis.com/blog/windows-10-authentication-the-end-of-pass-the-hash/). Attackers use Mimikatz to pass that exact hash string to the target computer to login. Attackers don’t even need to crack the password, they just need to use the hash string as is. It’s the equivalent of finding the master key to a building on the floor. You need that one key to get into all the doors.
- **Pass-the-Ticket:** Newer versions of windows store password data in a construct called a ticket.  Mimikatz provides functionality for a user to pass a kerberos ticket to another computer and login with that user’s ticket. It’s basically the same as pass-the-hash otherwise.
- **Over-Pass the Hash (Pass the Key):** Yet another flavor of the pass-the-hash, but this technique passes a unique key to impersonate a user you can obtain from a domain controller.
- **Kerberos Golden Ticket:** This is a pass-the-ticket attack, but it’s a specific ticket for a hidden account called KRBTGT, which is the account that encrypts all of the other tickets. A [golden ticket](https://www.varonis.com/blog/kerberos-how-to-stop-golden-tickets/) gives you domain admin credentials to any computer on the network that doesn’t expire.
- **Kerberos Silver Ticket:** Another pass-the-ticket, but a [silver ticket](https://www.varonis.com/blog/kerberos-attack-silver-ticket/) takes advantage of a feature in Windows that makes it easy for you to use services on the network. Kerberos grants a user a TGS ticket, and a user can use that ticket to log into any services on the network. Microsoft doesn’t always check a TGS after it’s issued, so it’s easy to slip it past any safeguards.
- **Pass-the-Cache:** Finally an attack that doesn’t take advantage of Windows! A pass-the-cache attack is generally the same as a pass-the-ticket, but this one uses the saved and encrypted login data on a Mac/UNIX/Linux system.

![](https://blogvaronis2.wpengine.com/wp-content/uploads/2018/12/what-can-mimikatz-do@2x-1-960x669.png)

Mimikatz github: 

https://github.com/gentilkiwi/mimikatz

其他资料：

[What is Mimikatz: The Beginner’s Guide](https://www.varonis.com/blog/what-is-mimikatz/)

[[后渗透]Mimikatz使用大全](https://www.cnblogs.com/-mo-/p/11890232.html)

[九种姿势运行Mimikatz](https://www.freebuf.com/articles/web/176796.html)（包含了一些绕过杀软的手段）

