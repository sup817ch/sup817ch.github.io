---
title: intel VT笔记
date: 2018-12-04 22:59:51
tags:
---

# 检查是否支持VT

## 检查CPU

> System software can determine whether a processor supports VMX operation using CPUID. If
> CPUID.1:ECX.VMX[bit 5] = 1, then VMX operation is supported.

通过CPUID指令检查VMX位，为1则代表CPU支持VT。

<!-- more -->

## 检查CR0和CR4

> The first processors to support VMX operation require that the following bits be 1 in VMX operation:
> CR0.PE, CR0.NE, CR0.PG, and CR4.VMXE. The restrictions on CR0.PE and CR0.PG imply that VMX
> operation is supported only in paged protected mode (including IA-32e mode). Therefore, guest
> software cannot be run in unpaged protected mode or in real-address mode. See Section 31.2,“Supporting Processor Operating Modes in Guest Environments,” for a discussion of how a VMM
> might support guest software that expects to run in unpaged protected mode or in real-address
> mode.
> Later processors support a VM-execution control called “unrestricted guest” (see Section 24.6.2).
> If this control is 1, CR0.PE and CR0.PG may be 0 in VMX non-root operation (even if the capability
> MSR IA32_VMX_CR0_FIXED0 reports otherwise). 1 Such processors allow guest software to run in
> unpaged protected mode or in real-address mode.

检查CR0.PE，CR0.NE，CR0.PG，为1则代表可以开启VT。

检查CR4.VMXE，为1表示可能有其他驱动开启了VT，必须先关闭VT。

各标志位相关信息：

> **Protection Enable (bit 0 of CR0)** — Enables protected mode when set;
>
> **Numeric Error (bit 5 of CR0)** — Enables the native (internal) mechanism for reporting x87 FPU errors
> when set;
>
> **Paging (bit 31 of CR0)** — Enables paging when set;

> **VMX-Enable Bit (bit 13 of CR4)** — Enables VMX operation when set.



## 检查MSR

> VMXON is also controlled by the IA32_FEATURE_CONTROL MSR (MSR address 3AH). This MSR is cleared to zero when a logical processor is reset. The relevant bits of the MSR are:
> • **Bit 0 is the lock bit.** If this bit is clear, VMXON causes a general-protection exception. If the lock bit is set, WRMSR to this MSR causes a general-protection exception; the MSR cannot be modified until a power-up reset condition. System BIOS can use this bit to provide a setup option for BIOS to disable support for VMX. To enable VMX support in a platform, BIOS must set bit 1, bit 2, or both (see below), as well as the lock bit.
> • **Bit 1 enables VMXON in SMX operation.** If this bit is clear, execution of VMXON in SMX operation causes a general-protection exception. Attempts to set this bit on logical processors that do not support both VMX operation (see Section 23.6) and SMX operation (see Chapter 6, “Safer Mode Extensions Reference,” in Intel® 64 and IA-32 Architectures Software Developer’s Manual, Volume 2D) cause general-protection exceptions.
> • **Bit 2 enables VMXON outside SMX operation.** If this bit is clear, execution of VMXON outside SMX
> operation causes a general-protection exception. Attempts to set this bit on logical processors that do not support VMX operation (see Section 23.6) cause general-protection exceptions.

> Ensure that the IA32_FEATURE_CONTROL MSR (MSR index 3AH) has been properly programmed and that its lock bit is set (Bit 0 = 1). This MSR is generally configured by the BIOS using WRMSR.

检查MSR IA32_FEATURE_CONTROL的lock bit (bit 0)，为1则代表可以开启VT，否则根据文档描述会产生异常。



# VMCS region

## VMCS region 结构

VMCS region的大小可在 MSR IA32_VMX_BASIC 中查询得到，一般申请4KB内存即可。

​								**Format of the VMCS Region**

| Byte Offset | Contents                                                     |
| ----------- | ------------------------------------------------------------ |
| 0           | Bits 30:0: VMCS revision identifier
Bit 31: shadow-VMCS indicator (see Section 24.10) |
| 4           | VMX-abort indicator                                          |
| 8           | VMCS data (implementation-specific format)                   |

**VMCS revision identifier：**用于避免处理器使用非对应格式的VMCS region，在MSR IA32_VMX_BASIC中可查询得到对应值。

**VMX-abort indicator：**当VMX终止时处理器会填写该区域。

**VMCS data：**VMCS region剩下的区域为VMCS data，用于设置一些属性，是VMCS region最重要的区域。



## VMCS data

VMCS data由6个区域组成：

> • **Guest-state area.** Processor state is saved into the guest-state area on VM exits and loaded from there on VM entries.
> • **Host-state area.** Processor state is loaded from the host-state area on VM exits.
> • **VM-execution control fields.** These fields control processor behavior in VMX non-root operation. They determine in part the causes of VM exits.
> • **VM-exit control fields.** These fields control VM exits.
> • **VM-entry control fields.** These fields control VM entries.
> • **VM-exit information fields.** These fields receive information on VM exits and describe the cause and the nature of VM exits. On some processors, these fields are read-only.



### Guest-state area

**需要填充的区域：**

**Register部分**

- 控制寄存器 CR0，CR3，CR4 (64 bits each)。

- 调试寄存器 DR7 (64 bits)。

- RSP，RIP，RFLAGS (64 bits each)。

- 段寄存器CS，SS，DS，ES，FS，GS，LDTR，TR的

  — Selector (16 bits)

  — Base address (64 bits)

  — Segment limit (32 bits)

  — Access rights (32 bits)

- GDTR，LDTR的

  — Base address (64 bits)

  — Limit (32 bits)

- MSR的

  — IA32_DEBUGCTL  (64 bits)

  — IA32_SYSENTER_CS (32 bits)

  — IA32_SYSENTER_ESP (64 bits) 

  Guest的堆栈。

  — IA32_SYSENTER_EIP (64 bits) 

  vmlaunch后Guest的入口点。

  — IA32_EFER (64 bits)

**Non-Register部分**

- Activity state (32 bits). This field identifies the logical processor’s activity state.

  — 0: Active. The logical processor is executing instructions normally.

  — 1: HLT. The logical processor is inactive because it executed the HLT instruction.

  — 2: Shutdown. The logical processor is inactive because it incurred a triple fault 2 or some other serious
  error.

  — 3: Wait-for-SIPI. The logical processor is inactive because it is waiting for a startup-IPI (SIPI). Future processors may include support for other activity states. Software should read the VMX capability MSR
  IA32_VMX_MISC (see Appendix A.6) to determine what activity states are supported.

  一般填0即可。

- Interruptibility state (32 bits). The IA-32 architecture includes features that permit certain events to be
  blocked for a period of time.

  一般填0即可。

- VMCS link pointer

  当VMCS类型为shadow时，vmread和vmwrite指令通过该指针访问VMCS。

  当VMCS类型为ordinary时，设置该指针为0xFFFFFFFF'FFFFFFFF。



### Host-state area

**需要填充的区域：**

- 控制寄存器 CR0，CR3，CR4 (64 bits each)。

- RSP，RIP (64 bits each)。

- 段寄存器CS，SS，DS，ES，FS，GS，TR的Selector (16 bits)

- 段寄存器FS，GS，TR，GDTR，IDTR的Base-address (64 bits each)

- MSR的

  — IA32_SYSENTER_CS (32 bits)

  — IA32_SYSENTER_ESP (64 bits)

  Host的堆栈，需要自己申请内存。

  — IA32_SYSENTER_EIP (64 bits)

  Host的入口点，即vmm处理程序的入口点。

  — IA32_EFER (64 bits)



### VM-execution control fields

暂时搁置。



### VM-exit control fields

