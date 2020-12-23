---
title: XTrap简略分析
date: 2019-05-25 13:59:18
tags:
---

这是棒子的一款游戏保护，知名度好像不是很高，网上搜了一圈得到的信息很少，于是只能自己动手了。中途因为难度太大（对我而言）弃坑了好几次，现在基本上放弃，遂分享一下成果。环境是win 10 64位系统下的某32位游戏。

<!-- more -->

# 驱动层

通过`PCHunter`观察得知，该保护的驱动文件在路径`C:\Windows\SysWOW64\drivers`下。拖进`DIE`中显示驱动是没有壳的，于是可以很高兴的直接拖进IDA中。

整个驱动文件其实不大，只有几十kb，IDA中分析出来的函数也只有二三十个，允许我们一个个看过去。在这个驱动中有个贯穿全文的全局变量，我把它命名为`XtrapGlobalData`，在这里我先把我分析得到该变量有限的结构体贴出。

```c
struct XTRAP_GLOBAL_DATA
{
  ULONG32 MajorVersion;
  ULONG32 MinorVersion;
  ULONG32 BuildNumber;
  ULONG32 Unknown1;
  WINDOWS_VERSION WindowsVersionMark;
  XTRAP_FIELD_OFFSET Offset;
  CHAR Unknown2[36];
  SYSTEM_HANDLE_TABLE_ENTRY_INFO Unknown3[2];
  ULONG64 Unknown4;
  ULONG64 ThreadHandle1;
  ULONG64 ThreadHandle2;
  ULONG32 Start;
  ULONG64 CurrentPid;
  ULONG64 CurrentEpr;
  ULONG32 Unknown5;
  XTRAP_HANDLE_INFORMATION XtrapHandleInfo;
  CHAR Unknown6[16];
  ULONG64 CallbackHandle;
  ULONG32 UnknownPid[6];
};

struct XTRAP_FIELD_OFFSET
{
  ULONG32 KPROCESS_ThreadListHead;
  ULONG32 EPROCESS_UniqueProcessId;
  ULONG32 EPROCESS_ImageFileName;
  ULONG32 EPROCESS_InheritedFromUniqueProcessId;
  ULONG32 EPROCESS_ThreadListHead;
  ULONG32 KTHREAD_ThreadListEntry;
  ULONG32 KTHREAD_WaitMode;
  ULONG32 KTHREAD_WaitReason;
  ULONG32 KTHREAD_FreezeCount;
  ULONG32 KTHREAD_SuspendCount;
  ULONG32 ETHREAD_Win32StartAddress;
  ULONG32 ETHREAD_Cid;
  ULONG32 ETHREAD_ThreadListEntry;
  ULONG32 ETHREAD_CrossThreadFlags;
};

struct XTRAP_HANDLE_INFORMATION
{
	ULONG HandleCounts;
	ULONG UniqueProcessId[30];
	ULONG GrantedAccess[30];
};
```

## DriverEntry

首先初始化了设备名和符号链接名，从而得知了应用层和驱动层是通过设备通信的。

```c
memmove(&SourceString, L"\\Device\\X6va066", 0x20u);// DeviceName
memmove(&Dst, L"\\DosDevices\\X6va066", 0x28u);// SymbolicLinkName
```

使用`PsGetVersion`获取版本号，确认系统版本。

```c
PsGetVersion(&MajorVersion, &MinorVersion, &BuildNumber, 0i64);
WindowsVersionMark = WINDOWS_UNKNOWN0;
if ( MajorVersion == WINDOWS_7 )
{
    if ( MinorVersion != WINDOWS_XP_PRO_X64 )
        return 0xC00000BB;
    WindowsVersionMark = WINDOWS_XP_PRO_X64;    // Windows XP Professional x64
}
if ( MajorVersion != WINDOWS_8 )
    goto LABEL_13;
if ( !MinorVersion )
    WindowsVersionMark = WINDOWS_VISTA;         // Windows Vista
if ( MinorVersion == 1 )
    WindowsVersionMark = WINDOWS_7;             // Windows 7
if ( MinorVersion == 2 )
    WindowsVersionMark = WINDOWS_8;             // Windows 8
if ( MinorVersion == 3 )
{
    WindowsVersionMark = 7;                     // Window 8.1
    LABEL_13:
    if ( MajorVersion == WINDOWS_10_14393 && !MinorVersion )
    {                                           // Win 10
        WindowsVersionMark = 8;                   // Win 10 under 10586 ?
        if ( BuildNumber >= 10586 )
            WindowsVersionMark = WINDOWS_10_10586;  // Win 10 10586
        if ( BuildNumber >= 14393 )
            WindowsVersionMark = WINDOWS_10_14393;  // Win 10 14393
        if ( BuildNumber >= 15063 )
            WindowsVersionMark = WINDOWS_10_15063;  // Win 10 15063
        if ( BuildNumber >= 16299 )
            WindowsVersionMark = WINDOWS_10_16299;  // Win 10 16299
        if ( BuildNumber >= 17133 )
            WindowsVersionMark = WINDOWS_10_17133;  // Win 10 17133
    }
}
if ( WindowsVersionMark == WINDOWS_UNKNOWN0 )
    return 0xC00000BB;
```

根据系统版本，填写一些硬编码，比如各种结构的偏移。

```c
if ( result == WINDOWS_10_10586 )
{
    v1_XtrapGlobalData->Offset.KPROCESS_ThreadListHead = 0x30;
    v1_XtrapGlobalData->Offset.EPROCESS_UniqueProcessId = 744;
    v1_XtrapGlobalData->Offset.EPROCESS_InheritedFromUniqueProcessId = 992;
    v1_XtrapGlobalData->Offset.EPROCESS_ImageFileName = 1104;
    v1_XtrapGlobalData->Offset.EPROCESS_ThreadListHead = 1160;
    v1_XtrapGlobalData->Offset.KTHREAD_ThreadListEntry = 0x2F8;
    v1_XtrapGlobalData->Offset.KTHREAD_WaitMode = 391;
    v1_XtrapGlobalData->Offset.KTHREAD_WaitReason = 643;
    v1_XtrapGlobalData->Offset.KTHREAD_FreezeCount = 120;
    v1_XtrapGlobalData->Offset.KTHREAD_SuspendCount = 644;
    v1_XtrapGlobalData->Offset.ETHREAD_Win32StartAddress = 1664;
    v1_XtrapGlobalData->Offset.ETHREAD_Cid = 1576;
    v1_XtrapGlobalData->Offset.ETHREAD_ThreadListEntry = 1680;
    v1_XtrapGlobalData->Offset.ETHREAD_CrossThreadFlags = 1724;
}
```

设置了设备的派遣函数。

```c
Device->MajorFunction[0xE] = DispatchGeneral;// IRP_MJ_DEVICE_CONTROL
Device->MajorFunction[0] = DispatchGeneral; // IRP_MJ_CREATE
Device->MajorFunction[2] = DispatchGeneral; // IRP_MJ_CLOSE
Device->MajorFunction[0x12] = DispatchGeneral;// IRP_MJ_CLEANUP
```

具体是在`DispatchGeneral`中判断功能号再调用对应的Dispatcher。

## 派遣函数

总共有3个函数，`DispatchCreate` `DispatchClose` 和 `DispatchIoControl` 分别对应`IRP_MJ_CREATE` `IRP_MJ_CLOSE` 和 `IRP_MJ_DEVICE_CONTROL`。

### DispatchCreate

该函数做了几件事：一是使用`PsCreateSystemThread`创建了两个线程，这两个线程分别用来检测线程和查句柄；二是使用`ObRegisterCallbacks`注册了一个进程回调。

先讲两个线程，其中一个线程用来检测被保护的游戏进程的线程是否被暂停，具体操作如下：

```c
do
{
    KeDelayExecutionThread(0, 0, &Interval);    // 每秒循环一次
    SuspendedThreadCount = 0;
    if ( XtrapGlobalData.CurrentEpr )
    {
        ThreadListHead = (XtrapGlobalData.CurrentEpr + XtrapGlobalData.Offset.EPROCESS_ThreadListHead);
        if ( ThreadListHead )
        {
            ThreadListEntry = ThreadListHead->Flink;
            do
            {
                EThread = ThreadListEntry - XtrapGlobalData.Offset.ETHREAD_ThreadListEntry;
                if ( *(&ThreadListEntry->Flink
                       + XtrapGlobalData.Offset.KTHREAD_SuspendCount
                       - XtrapGlobalData.Offset.ETHREAD_ThreadListEntry)
                    && *(EThread + XtrapGlobalData.Offset.KTHREAD_WaitReason) == 5// _KWAIT_REASON Suspended
                    && *(EThread + XtrapGlobalData.Offset.ETHREAD_Win32StartAddress) >= *&XtrapGlobalData.Unknown2[4]
                    && *(EThread + XtrapGlobalData.Offset.ETHREAD_Win32StartAddress) <= *&XtrapGlobalData.Unknown2[12] )// 猜测这里的两个Unknown指的是XTrapVa.dll的起始地址和结束地址
                {
                    ++SuspendedThreadCount;             // 记录被暂停的线程个数
                }
                ThreadListEntry = ThreadListEntry->Flink;
            }
            while ( ThreadListEntry != ThreadListHead );
            if ( SuspendedThreadCount >= 3 && !LODWORD(XtrapGlobalData.Unknown4) )// 暂停的线程大于等于3个就关闭游戏进程
                TerminateProcessByPid(XtrapGlobalData.CurrentPid);
            if ( *&XtrapGlobalData.Unknown2[24] )
                TerminateProcessByPid(XtrapGlobalData.CurrentPid);
        }
    }
}
while ( XtrapGlobalData.Start );
```

通过遍历游戏的ThreadList来检测游戏某个地址范围内的线程，我猜测这个范围是该保护本身的模块XTrapVa.dll（下面会讲），如果暂停的线程大于等于3个就结束进程，目的应该是为了防止调试器附加或者人为暂停该保护的检测线程。

第二个线程是用来枚举拥有被保护游戏进程句柄的进程，操作如下：

```c
if ( XtrapGlobalData.Start )
{
    while ( 1 )                                 // 每秒循环一次
    {
        CurrentEpr = XtrapGlobalData.CurrentEpr;
        RetLength = 0;
        if ( !XtrapGlobalData.CurrentEpr )
            goto LABEL_22;
        ZwQuerySystemInformation = GetAddrZwQuerySystemInformation();// 获取ZwQuerySystemInformation的地址
        if ( !ZwQuerySystemInformation )
            goto LABEL_22;
        buffer_v3 = ExAllocatePoolWithTag(0, 0x1000ui64, &Tag);
        v4 = buffer_v3;
        if ( !buffer_v3 )
            goto LABEL_22;
        status = ZwQuerySystemInformation(16i64, buffer_v3, 0x1000i64, &RetLength);// SystemHandleInformation
        v6 = v4;
        if ( status != 0xC0000004 )
            goto LABEL_21;
        ExFreePoolWithTag(v4, &Tag);
        v7 = RetLength + 0x1000;
        buffer_v8 = ExAllocatePoolWithTag(0, (RetLength + 0x1000), &Tag);
        SysHandleInfo = buffer_v8;
        if ( buffer_v8 )
            break;
        LABEL_22:
        KeDelayExecutionThread(0, 0, &Interval);  // 1s
        if ( !XtrapGlobalData.Start )
            goto LABEL_23;
    }
    if ( !ZwQuerySystemInformation(16i64, buffer_v8, v7, &RetLength) )// SystemHandleInformation 枚举系统句柄
    {
        v10 = 0;
        if ( LODWORD(SysHandleInfo->NumberOfHandles) )
        {
            v11 = XtrapGlobalData.XtrapHandleInfo.HandleCounts;
            v12 = &SysHandleInfo->Handles[0].GrantedAccess;
            do
            {
                if ( *(v12 - 1) == CurrentEpr )       // Handles->Object 判断句柄对象是否是本身进程
                {
                    UniqueProcessId = *(v12 - 8);       // Handles->UniqueProcessId
                    GrantedAccess = *v12;
                    if ( *(v12 - 8) )                   // Handles->UniqueProcessId
                    {
                        if ( UniqueProcessId != 4 )       // 判断是否是System进程
                        {                                 // 不是System进程
                            v15 = 0;
                            if ( v11 )
                            {
                                v16 = XtrapGlobalData.XtrapHandleInfo.UniqueProcessId;
                                while ( UniqueProcessId != *v16 )
                                {                             // 检查UniqueProcessId是否重复
                                    ++v15;
                                    ++v16;
                                    if ( v15 >= v11 )
                                        goto LABEL_17;
                                }
                            }
                            else
                            {
                                LABEL_17:
                                if ( v11 < 30 )               // 如果UniqueProcessId没有重复且总量小于30个就记录
                                {
                                    XtrapGlobalData.XtrapHandleInfo.UniqueProcessId[v11 + 1] = UniqueProcessId;
                                    XtrapGlobalData.XtrapHandleInfo.GrantedAccess[XtrapGlobalData.XtrapHandleInfo.HandleCounts + 1] = GrantedAccess;
                                    v11 = XtrapGlobalData.XtrapHandleInfo.HandleCounts++ + 1;
                                }
                            }
                        }
                    }
                }
                ++v10;
                v12 += 6;                             // 下一个句柄
            }
            while ( v10 < LODWORD(SysHandleInfo->NumberOfHandles) );
        }
    }
    v6 = SysHandleInfo;
    LABEL_21:
    ExFreePoolWithTag(v6, &Tag);
    goto LABEL_22;
}
```

通过调用`ZwQuerySystemInformation`的16号功能`SystemHandleInformation`遍历系统中所有的句柄，从中找出指向被保护的游戏进程的句柄，将拥有该句柄的进程的`PID`以及权限`GrantedAccess`记录到`XtrapGlobalData`当中。记录的格式是`UniqueProcessId[i]`对应`GrantedAccess[i]`。

然后是进程回调，做的事情和上面那个线程大同小异，代码如下：

```c
__int64 __fastcall PreProcessCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation)
{
  struct _EPROCESS *TargetEpr; // rbx
  POB_PRE_OPERATION_INFORMATION OperationInformation_v3; // rsi
  XTRAP_GLOBAL_DATA *XtrapGlobalData; // rdi
  struct _EPROCESS *CurrentEpr; // rbp
  int TargetPid; // ebx
  int CurrentPid; // eax
  ULONG DesiredAccess; // edx
  ULONG32 v9; // ecx
  int v10; // ecx
  int v11; // er8

  TargetEpr = OperationInformation->Object;
  OperationInformation_v3 = OperationInformation;
  XtrapGlobalData = RegistrationContext;
  CurrentEpr = IoGetCurrentProcess();
  if ( CurrentEpr != TargetEpr && !(OperationInformation_v3->Flags & 1) )// 句柄的对象不是自身且句柄不是内核句柄
  {
    TargetPid = PsGetProcessId(TargetEpr);
    CurrentPid = PsGetProcessId(CurrentEpr);
    DesiredAccess = OperationInformation_v3->Parameters->CreateHandleInformation.OriginalDesiredAccess;
    v9 = XtrapGlobalData->UnknownPid[5];        // 推测为被保护进程的PID
    if ( TargetPid == v9 )
    {
      if ( DesiredAccess & 0x20 )               // PROCESS_VM_WRITE
      {
        if ( CurrentPid != XtrapGlobalData->UnknownPid[0]
          && CurrentPid != XtrapGlobalData->UnknownPid[1]
          && CurrentPid != XtrapGlobalData->UnknownPid[2]
          && CurrentPid != XtrapGlobalData->UnknownPid[3]
          && CurrentPid != v9
          && OperationInformation_v3->Operation == 1 )// OB_OPERATION_HANDLE_CREATE
        {
          v10 = XtrapGlobalData->Unknown3[0].UniqueProcessId;
          if ( CurrentPid != v10 )
          {
            v11 = XtrapGlobalData->Unknown3[1].UniqueProcessId;
            if ( CurrentPid != v11 )
            {
              if ( v10 )
              {
                if ( !v11 )
                {
                  XtrapGlobalData->Unknown3[1].UniqueProcessId = CurrentPid;
                  XtrapGlobalData->Unknown3[1].GrantedAccess = DesiredAccess;
                  XtrapGlobalData->Unknown3[1].Object = CurrentEpr;
                }
              }
              else
              {
                XtrapGlobalData->Unknown3[0].UniqueProcessId = CurrentPid;
                XtrapGlobalData->Unknown3[0].GrantedAccess = DesiredAccess;
                XtrapGlobalData->Unknown3[0].Object = CurrentEpr;
              }
            }
          }
        }
      }
    }
  }
  return 0i64;
}
```

记录以`PROCESS_VM_WRITE`权限打开游戏的进程的`PID`和`EPROCESS`以及打开的权限`GrantedAccess`。

### DispatchClose

主要做了一些清理操作，比如取消进程回调，结束两个检测的线程等等。

```c
void *DispatchClose()
{
  void (__fastcall *ObUnRegisterCallbacks)(void *); // rax
  UNICODE_STRING DestinationString; // [rsp+20h] [rbp-48h]
  WCHAR SourceString[2]; // [rsp+30h] [rbp-38h]
  char Dst; // [rsp+34h] [rbp-34h]

  *SourceString = 0;
  memset(&Dst, 0, 0x2Cu);
  DecryptString(&encstr_ObUnRegisterCallbacks, 0x30u, SourceString);
  RtlInitUnicodeString(&DestinationString, SourceString);
  ObUnRegisterCallbacks = MmGetSystemRoutineAddress(&DestinationString);// ObUnRegisterCallbacks
  if ( ObUnRegisterCallbacks && XtrapGlobalData.CallbackHandle )
  {
    (ObUnRegisterCallbacks)();
    XtrapGlobalData.Unknown3[0].UniqueProcessId = 0;
    XtrapGlobalData.Unknown3[1].UniqueProcessId = 0;
    XtrapGlobalData.CallbackHandle = 0i64;
  }
  *XtrapGlobalData.Unknown2 = 0;
  *&XtrapGlobalData.Unknown2[4] = 0i64;
  *&XtrapGlobalData.Unknown2[12] = 0i64;
  *&XtrapGlobalData.Unknown2[20] = 0;
  *&XtrapGlobalData.Unknown2[24] = 0;
  *&XtrapGlobalData.Unknown2[28] = 0;
  XtrapGlobalData.Start = 0;
  XtrapGlobalData.CurrentPid = 0i64;
  XtrapGlobalData.CurrentEpr = 0i64;
  return memset(&XtrapGlobalData.Unknown5, 0, 0x108u);
}
```



### DispatchIoControl

这个就是负责通信的函数了，很常规的通过自己定义的控制码来进行通信。总共定义了5个控制码`0x86000880` `0x8600089C` `0x860008C0` `0x86000900` `0x86001804`，这里挑几个通过已知条件能整得明白的讲。

#### 控制码0x86000880

主要工作就是把之前通过进程回调和检测线程记录下来的游戏认为的可疑进程的相关信息稍做加工后传回应用层。

```c
case 0x86000880:
    if ( SystemBuffer && InputBufferLength == 0x790 && OutBuffer && OutputBufferLength == 0x790 )
    {
        memmove(Dst, SystemBuffer, 0x790u);
        CurrentEpr = IoGetCurrentProcess();
        sub_11CC0(&XtrapGlobalData, CurrentEpr, Dst);// 记录拥有自身进程句柄的非指定进程的各种信息
        sub_11BA0(&XtrapGlobalData, XtrapGlobalData.CurrentEpr, &Dst[424]);// 记录SuspectProcess的EPROCESS 父进程ID ImageFileName
        memmove(OutBuffer, Dst, 0x790u);
        IoStatus->Information = 0x790i64;
        break;
    }
```

`sub_11CC0`做的工作好像和之前有点重复，这里不再讲。`sub_11BA0`则是获取之前记录下来的可疑进程的父进程ID和进程名，然后将它们传回应用层。

#### 控制码0x86001804

主要工作是遍历游戏的线程，然后把相关信息传回应用层。

```c
PEPROCESS __fastcall sub_12160(XTRAP_GLOBAL_DATA *XtrapGlobalData, _DWORD *a2, _DWORD *a3)
{
  _DWORD *v3; // rbx
  _DWORD *v4; // rdi
  XTRAP_GLOBAL_DATA *XtrapGlobalData_v5; // rsi
  PEPROCESS v6; // rax
  __int64 v7; // r8
  _QWORD **ThreadListHead; // rcx
  _QWORD *ThreadListEntry; // r9
  _QWORD *v10; // rdx
  _DWORD *v11; // r10
  char *Thread; // r11
  char WaitMode; // bp
  char WaitReason; // r12
  char SuspendCount; // r13
  int CrossThreadFlags; // er14
  __int64 Win32StartAddress; // r15
  struct _EPROCESS *ThreadId; // rax
  struct _EPROCESS *v19; // [rsp+60h] [rbp+18h]

  v3 = a3;
  v4 = a2;
  XtrapGlobalData_v5 = XtrapGlobalData;
  *a3 = 0x60001;
  a3[3] = 0x600000;
  v6 = IoGetCurrentProcess();
  v7 = 0i64;
  if ( !v6 )
  {
    v3[1] = 0x60002;
LABEL_3:
    v3[2] = 0;
    return v6;
  }
  ThreadListHead = (v6 + XtrapGlobalData_v5->Offset.EPROCESS_ThreadListHead);
  if ( !ThreadListHead )
  {
    v3[1] = 0x60003;
    goto LABEL_3;
  }
  ThreadListEntry = *ThreadListHead;
  v10 = v4 + 566;
  v11 = v4 + 115;
  do
  {
    Thread = ThreadListEntry - XtrapGlobalData_v5->Offset.ETHREAD_ThreadListEntry;
    WaitMode = Thread[XtrapGlobalData_v5->Offset.KTHREAD_WaitMode];
    WaitReason = Thread[XtrapGlobalData_v5->Offset.KTHREAD_WaitReason];
    SuspendCount = Thread[XtrapGlobalData_v5->Offset.KTHREAD_SuspendCount];
    CrossThreadFlags = *&Thread[XtrapGlobalData_v5->Offset.ETHREAD_CrossThreadFlags];
    Win32StartAddress = *&Thread[XtrapGlobalData_v5->Offset.ETHREAD_Win32StartAddress];
    ThreadId = *&Thread[XtrapGlobalData_v5->Offset.ETHREAD_Cid + 8];
    ++*v4;
    v19 = ThreadId;
    v6 = v4[1];
    if ( v6 < 150 )
    {                                           // 获取当前进程每个线程的状态
      v4[1] = v6 + 1;
      v6 = v19;
      *(v4 + v7 + 8) = WaitMode;
      *(v4 + v7 + 158) = WaitReason;
      *(v4 + v7 + 308) = SuspendCount;
      *v11 = CrossThreadFlags;
      *(v10 - 150) = v19;                       // ThreadId
      *v10 = Win32StartAddress;
      v10[150] = Thread;
    }
    ThreadListEntry = *ThreadListEntry;
    ++v7;
    ++v11;
    ++v10;
  }
  while ( ThreadListEntry != ThreadListHead );
  *v3 = 0x60001;
  v3[3] = 0x600001;
  return v6;
}
```

通过该函数和一些其它信息可以整理出一个结构体。

```c
typedef struct _XTRAP_THREAD_ENUM_INFO
{
	ULONG32 ThreadCount1;
	ULONG32 ThreadCount2;
	UCHAR WaitMode[150];
	UCHAR WaitReason[150];
	UCHAR SuspendCount[150];
	ULONG32 CrossThreadFlags[150];
	ULONG64 UniqueThread[150];
	ULONG64 Win32StartAddress[150];
	ULONG64 EthreadAddress[150];
}XTRAP_THREAD_ENUM_INFO, *PXTRAP_THREAD_ENUM_INFO;
```

这个结构体就是该控制码传回应用层的内容，也就是说记录了游戏每个线程在这个结构体里有的成员。和`XTRAP_HANDLE_INFORMATION`类似，每个结构体成员同一个索引对应的就是同一个线程。不过这里还有一个有趣的地方就是这个结构体不是明文传回应用层的，还做了一个很简单的加密。

```c
do
{                                             // buffer内容加密
    *buffer = ~*buffer;
    ++buffer;
    --buffer_len;
}
while ( buffer_len );
```

大概就是把这个结构体的每个字节取反，加解密都是同样的操作。

#### 其他控制码

其他的控制码做的工作主要是让应用层传了一些信息过来设置了`XtrapGlobalData`中的`Unknown`部分，以及一些蜜汁操作（反调试？），比如修改`ETHREAD`中的`FreezeCount`和`SuspendCount`。通过已知条件尚不能解释得很清楚，所以这里就不讲了。

## 驱动层总结

驱动部分其实没做多少事情，主要是收集信息然后传回应用层接着分析。



# 应用层

其实应用层才是让人崩溃的地方。

看了一下`XTrap`的文件夹，确定了两个比较主要的文件`XTrap.xt`和`XTrapVa.dll`。使用`DIE`

查壳显示` Themida/Winlicense(2.X)[-]`，WDNMD直接就来了个下马威。不过通过大量的百度我还是稀里糊涂的把壳脱掉了（？）。把这两个程序拖进IDA后，导入表看不到太多函数，一开始我还以为是我脱壳失败，后来才发现是通过`GetProcAddress`动态获取需要用的函数。比如像这样：

```c
*EnumProcesses = GetProcAddress_0(v4, aEnumprocesses);
*EnumProcessModules = GetProcAddress_0(v4, aEnumprocessmod);
*GetModuleFileNameExA = GetProcAddress_0(v4, aGetmodulefilen_1);
*GetModuleFileNameExW = GetProcAddress_0(v4, aGetmodulefilen_2);
*GetModuleInformation = GetProcAddress_0(v4, aGetmoduleinfor);
*GetModuleBaseNameA = GetProcAddress_0(v4, aGetmodulebasen);
```

于是我只能每个变量慢慢的重命名过去。

大致浏览过后，猜测`XTrap.xt`应该主要负责UI和其他工作，重头戏还是在`XTrapVa.dll`中（当然并不是说`XTrap.xt`没什么用，我感觉里面应该也有一部分操作，只是我没仔细研究过）。当我开始浏览`XTrapVa.dll`后，我崩溃了，到处都是神奇的函数调用，放一些代码让大家感受一下。

比如虚函数

```c
int __thiscall sub_40796B60(int (__thiscall ***this)(_DWORD))
{
  return (*this[295])(this + 295);
}
```

或者加密调用

```c
void __thiscall sub_404225B0(_DWORD *this, int a2)
{
  sub_4041D280(this + 442, (this + 441), &a2);
}

void __thiscall sub_4041D280(_DWORD *this, unsigned int a2, unsigned int *a3)
{
  _DWORD *v3; // ebx
  unsigned int v4; // eax
  unsigned int v5; // ebp
  char v6; // dl
  unsigned int v7; // ecx
  int *v8; // edi
  int v9; // ebp
  unsigned int v10; // esi
  unsigned int v11; // [esp+4h] [ebp-28h]
  unsigned int v12; // [esp+8h] [ebp-24h]
  unsigned int v13; // [esp+Ch] [ebp-20h]
  unsigned int v14; // [esp+10h] [ebp-1Ch]
  char v15; // [esp+14h] [ebp-18h]
  int v16; // [esp+18h] [ebp-14h]
  int v17; // [esp+1Ch] [ebp-10h]
  char v18; // [esp+20h] [ebp-Ch]
  unsigned int v19; // [esp+24h] [ebp-8h]
  int v20; // [esp+28h] [ebp-4h]
  unsigned int v21; // [esp+30h] [ebp+4h]

  v3 = this;
  v20 = 0;
  if ( this[4] & 0xFFFFFFFC )
  {
    v4 = a2;
    v5 = a2;
    v11 = (a2 >> 6) & 7;
    v6 = a2 & 7;
    v12 = (a2 >> 9) & 7;
    v13 = (a2 >> 12) & 7;
    v14 = (a2 >> 15) & 7;
    v7 = (a2 >> 18) & 7;
    v21 = a2 & 7;
    v15 = v7;
    v8 = 2;
    v16 = (v4 >> 21) & 7;
    v17 = (v4 >> 24) & 7;
    v9 = (v5 >> 3) & 7;
    v19 = v4 >> 30;
    v18 = (v4 >> 27) & 7;
    while ( 1 )
    {
      v10 = *a3;
      sub_4041D210(v3, (v8 - 2), *a3 & 1, v6);
      sub_4041D210(v3, (v8 - 1), (v10 >> 1) & 1, v21);
      sub_4041D210(v3, v8, (v10 >> 2) & 1, v21);
      sub_4041D210(v3, (v8 + 1), (v10 >> 3) & 1, v9);
      sub_4041D210(v3, (v8 + 2), (v10 >> 4) & 1, v9);
      sub_4041D210(v3, (v8 + 3), (v10 >> 5) & 1, v9);
      sub_4041D210(v3, v8 + 1, (v10 >> 6) & 1, v11);
      sub_4041D210(v3, (v8 + 5), (v10 >> 7) & 1, v11);
      sub_4041D210(v3, (v8 + 6), v10 >> 8, v11);
      sub_4041D210(v3, (v8 + 7), (v10 >> 9) & 1, v12);
      sub_4041D210(v3, v8 + 2, (v10 >> 10) & 1, v12);
      sub_4041D210(v3, (v8 + 9), (v10 >> 11) & 1, v12);
      sub_4041D210(v3, (v8 + 10), (v10 >> 12) & 1, v13);
      sub_4041D210(v3, (v8 + 11), (v10 >> 13) & 1, v13);
      sub_4041D210(v3, v8 + 3, (v10 >> 14) & 1, v13);
      sub_4041D210(v3, (v8 + 13), (v10 >> 15) & 1, v14);
      sub_4041D210(v3, (v8 + 14), v10 >> 16, v14);
      sub_4041D210(v3, (v8 + 15), (v10 >> 17) & 1, v14);
      sub_4041D210(v3, v8 + 4, (v10 >> 18) & 1, v15);
      sub_4041D210(v3, (v8 + 17), (v10 >> 19) & 1, v15);
      sub_4041D210(v3, (v8 + 18), (v10 >> 20) & 1, v15);
      sub_4041D210(v3, (v8 + 19), (v10 >> 21) & 1, v16);
      sub_4041D210(v3, v8 + 5, (v10 >> 22) & 1, v16);
      sub_4041D210(v3, (v8 + 21), (v10 >> 23) & 1, v16);
      sub_4041D210(v3, (v8 + 22), HIBYTE(v10) & 1, v17);
      sub_4041D210(v3, (v8 + 23), (v10 >> 25) & 1, v17);
      sub_4041D210(v3, v8 + 6, (v10 >> 26) & 1, v17);
      sub_4041D210(v3, (v8 + 25), (v10 >> 27) & 1, v18);
      sub_4041D210(v3, (v8 + 26), (v10 >> 28) & 1, v18);
      sub_4041D210(v3, (v8 + 27), (v10 >> 29) & 1, v18);
      sub_4041D210(v3, v8 + 7, (v10 >> 30) & 1, v19);
      sub_4041D210(v3, (v8 + 29), (v10 & 0x80000000) != 0, v19);
      ++a3;
      v8 += 8;
      if ( ++v20 >= v3[4] >> 2 )
        break;
      v6 = v21;
    }
  }
}

int *__thiscall sub_4041D210(_DWORD *this, int *a2, char a3, char a4)
{
  int *result; // eax
  int v5; // esi

  result = a2;
  v5 = this[1];
  *(a2 + v5) = a3 << a4;
  if ( (a2 & 3) == 3 )
  {
    result = (v5 + 4 * (a2 >> 2));
    *result = this[2] ^ *(v5 + 4 * (a2 >> 2));
  }
  return result;
}
```

当然恶心的东西还不止是这些。这么一看，只靠静态分析这条路确实是会让人崩溃的。于是我努力地靠着有限的动态调试和有限的静态分析以及自杀式的尝试得出了一些结果，当然得出的这些结果并不一定准确。

## 窗口检测

使用了`EnumWindow`，并且可能调用`GetWindowLong`获取了以下属性：

- GWL_HINSTANCE
- GWL_HWNDPARENT
- GWL_WNDPROC
- GWL_STYLE

还调用了`GetClassName`获取了类名。

## 创建快照

调用了`CreateToolhelp32Snapshot`，参数为`TH32CS_SNAPMODULE`和`TH32CS_SNAPPROCESS`，即遍历了自身模块和进程。至于干了什么，我觉得需要靠完整的动态调试才能略窥一二。

## x64代码调用

在有限的动态调试过程中，我发现了一个很有趣的函数。

```asm
___:40D224D0 55                                                  push    ebp
___:40D224D1 8B EC                                               mov     ebp, esp
___:40D224D3 83 EC 20                                            sub     esp, 20h
___:40D224D6 8B 45 08                                            mov     eax, [ebp+8]
___:40D224D9 8B 4D 0C                                            mov     ecx, [ebp+arg_0]
___:40D224DC 8B 55 10                                            mov     edx, [ebp+arg_4]
___:40D224DF 89 45 F8                                            mov     [ebp+var_8], eax ; ssdt index
___:40D224E2 8B 45 14                                            mov     eax, [ebp+arg_8]
___:40D224E5 89 4D FC                                            mov     [ebp+var_4], ecx
___:40D224E8 8B 4D 18                                            mov     ecx, [ebp+arg_C]
___:40D224EB 89 55 E0                                            mov     [ebp+var_20], edx ; para1
___:40D224EE 8B 55 1C                                            mov     edx, [ebp+arg_10]
___:40D224F1 89 45 E4                                            mov     [ebp+var_1C], eax
___:40D224F4 8B 45 20                                            mov     eax, [ebp+arg_14]
___:40D224F7 89 4D E8                                            mov     [ebp+var_18], ecx ; para2
___:40D224FA 8B 4D 24                                            mov     ecx, [ebp+arg_18]
___:40D224FD 89 55 EC                                            mov     [ebp+var_14], edx
___:40D22500 8B 55 28                                            mov     edx, [ebp+arg_1C]
___:40D22503 89 45 F0                                            mov     [ebp+var_10], eax ; para3
___:40D22506 8B 45 2C                                            mov     eax, [ebp+arg_20]
___:40D22509 89 4D F4                                            mov     [ebp+var_C], ecx
___:40D2250C 8B 4D 30                                            mov     ecx, [ebp+arg_24]
___:40D2250F 89 55 20                                            mov     [ebp+arg_14], edx ; para4
___:40D22512 8B 55 34                                            mov     edx, [ebp+arg_28]
___:40D22515 89 45 24                                            mov     [ebp+arg_18], eax
___:40D22518 8B 45 38                                            mov     eax, [ebp+arg_2C]
___:40D2251B 89 4D 10                                            mov     [ebp+arg_4], ecx ; para5
___:40D2251E 8B 4D 3C                                            mov     ecx, [ebp+arg_30]
___:40D22521 89 55 14                                            mov     [ebp+arg_8], edx
___:40D22524 89 45 18                                            mov     [ebp+arg_C], eax ; para6
___:40D22527 89 4D 1C                                            mov     [ebp+arg_10], ecx
___:40D2252A C7 45 0C 00 00 00 00                                mov     [ebp+arg_0], 0
___:40D22531 89 65 0C                                            mov     [ebp+arg_0], esp
___:40D22534 83 E4 F8                                            and     esp, 0FFFFFFF8h
___:40D22537 6A 33                                               push    33h
___:40D22539 E8 00 00 00 00                                      call    $+5
___:40D2253E 83 04 24 05                                         add     [esp+28h+var_28], 5
___:40D22542 CB                                                  retf
___:40D22542                                     x64syscall      endp ; sp-analysis failed
___:40D22542
___:40D22543                                     ; ---------------------------------------------------------------------------
___:40D22543 48                                                  dec     eax             ; mov rcx, qword ptr ss:[rbp-0x20]
___:40D22543                                                                             ; mov rdx, qword ptr ss:[rbp-0x18]
___:40D22543                                                                             ; push qword ptr ss:[rbp-0x10]
___:40D22543                                                                             ; pop r8
___:40D22543                                                                             ; push qword ptr ss:[rbp+0x20]
___:40D22543                                                                             ; pop r9
___:40D22543                                                                             ; push qword ptr ss:[rbp+0x18]
___:40D22543                                                                             ; push qword ptr ss:[rbp+0x10]
___:40D22543                                                                             ; sub rsp, 0x28
___:40D22543                                                                             ; mov rax, qword ptr ss:[rbp-0x08]
___:40D22543                                                                             ; mov r10, rcx
___:40D22543                                                                             ; syscall
___:40D22543                                                                             ; add rsp, 0x38
___:40D22543                                                                             ; mov qword ptr ss:[rbp-0x08], rax
___:40D22543                                                                             ; call 0x0000000000000032
___:40D22543                                                                             ; mov dword ptr ss:[rsp+0x04], 0x23
___:40D22543                                                                             ; add dword ptr ss:[rsp], 0x0D
___:40D22543                                                                             ; ret far
___:40D22544 8B 4D E0                                            mov     ecx, [ebp-20h]
___:40D22547 48                                                  dec     eax
___:40D22548 8B 55 E8                                            mov     edx, [ebp-18h]
___:40D2254B FF 75 F0                                            push    dword ptr [ebp-10h]
___:40D2254E 49                                                  dec     ecx
___:40D2254F 58                                                  pop     eax
___:40D22550 FF 75 20                                            push    dword ptr [ebp+20h]
___:40D22553 49                                                  dec     ecx
___:40D22554 59                                                  pop     ecx
___:40D22555 FF 75 18                                            push    dword ptr [ebp+18h]
___:40D22558 FF 75 10                                            push    dword ptr [ebp+10h]
___:40D2255B 48                                                  dec     eax
___:40D2255C 83 EC 28                                            sub     esp, 28h
___:40D2255F 48                                                  dec     eax
___:40D22560 8B 45 F8                                            mov     eax, [ebp-8]
___:40D22563 4C                                                  dec     esp
___:40D22564 8B D1                                               mov     edx, ecx
___:40D22566 0F 05                                               syscall                 ; Low latency system call
___:40D22568 48                                                  dec     eax
___:40D22569 83 C4 38                                            add     esp, 38h
___:40D2256C 48                                                  dec     eax
___:40D2256D 89 45 F8                                            mov     [ebp-8], eax
___:40D22570 E8 00 00 00 00                                      call    $+5
___:40D22575 C7 44 24 04 23 00 00 00                             mov     dword ptr [esp+4], 23h
___:40D2257D 83 04 24 0D                                         add     dword ptr [esp], 0Dh
___:40D22581 CB                                                  retf
```

很经典的一段32位调用64位代码，通过

```asm
___:40D22537 6A 33                                               push    33h
___:40D22539 E8 00 00 00 00                                      call    $+5
___:40D2253E 83 04 24 05                                         add     [esp+28h+var_28], 5
___:40D22542 CB                                                  retf
```

这段代码，改变了段寄存器`cs`，进入了x64代码模式。因为ida32没办法看x64代码，于是我用注释将x64代码补了上去。从代码中可以看到调用了`syscall`，所以整个函数其实就是一个利用`syscall`调用Nt函数的封装。该函数的格式如下：

```c
NTSTATUS
NTAPI
x64syscall(ULONG64 Index, ULONG64 Para1, ULONG64 Para2, ULONG64 Para3, ULONG64 Para4, ULONG64 Para5, ULONG64 Para6);
```

第一个参数为要调用的Nt函数的Index，其余参数就为该Nt函数的参数。通过搜索特征码，我得知在`XTrapVa.dll`中一共有**两个函数**实现了类似的效果，即利用`syscall`调用Nt函数。并通过测试发现，`XTrap`使用该函数调用过以下几个Nt函数（可能不全）：

- NtQueryInformationProcess
- NtTerminateProcess
- NtReadVirtualMemory

至于干了什么，任凭各位想象。

## 应用层总结

虽然应用层没有vm也没有混淆之类的东西，但它还是用了一些神奇的操作阻挡了我的静态分析（毕竟我太菜了）。当然肯定不只干了我讲的这些，还有内存扫描、线程检测等等，然而精力和技术的双重限制让我只能讲到这了。



# Bypass

虽然没有能够完全透烂这个保护，但是Bypass的话我还是能提供一点思路的。首先需要准备一个dll，该dll需要实现的功能如下：

- 结束`XTrapVa.dll`的所有线程
- 结束`XTrap.xt`进程
- Hook`NtTerminateProcess`和`x64syscall`

结束进程和线程的部分：

```c
VOID KillThread()
{
	HANDLE hSnap;
	THREADENTRY32 te32;
	HANDLE hThread;
	MODULEINFO mi;
	ULONG DllBase;
	ULONG DllSize;
	DWORD RetLen;
	ULONG StartAddress;
	decltype(NtQueryInformationThread)* pfnNtQueryInformationThread;

	GetModuleInformation(GetCurrentProcess(), GetModuleHandle(_T("XTrapVa.dll")), &mi, sizeof(MODULEINFO));
	DllBase = (ULONG)mi.lpBaseOfDll;
	DllSize = mi.SizeOfImage;
	pfnNtQueryInformationThread = (decltype(NtQueryInformationThread)*)GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "NtQueryInformationThread");

	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hSnap == INVALID_HANDLE_VALUE)
	{
		return;
	}

	te32.dwSize = sizeof(THREADENTRY32);
	if (!Thread32First(hSnap, &te32))
	{
		CloseHandle(hSnap);
		return;
	}
	do
	{
		if (te32.th32OwnerProcessID == GetCurrentProcessId())
		{
			hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
			pfnNtQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress, &StartAddress, sizeof(StartAddress), &RetLen);
			if (StartAddress > DllBase && StartAddress < DllBase + DllSize)
			{
				TerminateThread(hThread, 0);
			}
			CloseHandle(hThread);
		}

	} while (Thread32Next(hSnap, &te32));

	CloseHandle(hSnap);
}

VOID KillProcess()
{
	PROCESSENTRY32 pe32;
	HANDLE hSnap;
	HANDLE hProcess;

	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE)
	{
		return;
	}

	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(hSnap, &pe32))
	{
		CloseHandle(hSnap);
		return;
	}
	do
	{
		if (!_tcsicmp(pe32.szExeFile, _T("XTrap.xt")))
		{
			hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
			TerminateProcess(hProcess, 0);
			CloseHandle(hProcess);
		}
	} while (Process32Next(hSnap, &pe32));

	CloseHandle(hSnap);
}
```

Hook部分：

```c
NTSTATUS
NTAPI
MyNtTerminateProcess(
	_In_opt_ HANDLE ProcessHandle,
	_In_ NTSTATUS ExitStatus
)
{
	return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
Myx64syscall(ULONG64 Index, ULONG64 Para1, ULONG64 Para2, ULONG64 Para3, ULONG64 Para4, ULONG64 Para5, ULONG64 Para6)
{
	switch (Index)
	{
	case 0x2c:	//NtTerminateProcess 这里根据系统自己改
		return STATUS_SUCCESS;

	default:
		break;
	}

	return pfnx64syscall(Index, Para1, Para2, Para3, Para4, Para5, Para6);
}
```

准备好dll之后用任意注入方式注入游戏进程即可，只需要注意一点就是注入一定要快。

当我注入后发现我可以使用CE正常附加和调试了（VEH），于是我兴冲冲的准备使用动态调试进行深入分析，然后我发现。。。

有关检测的线程都被我干掉了，我还调试个鸡儿。

