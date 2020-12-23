---

title: 绕过ObRegisterCallbacks注册的回调
date: 2018-11-21 00:32:26
tags:
---

其实我感觉这个东西挺鸡肋的，只是雕虫小技，大佬们笑笑就好。

如有错误，请大佬们指出。

<!-- more -->

测试环境：win7 x64

这里以ObjectType类型为PsProcessType的PreCallback为例子。

先自己注册一个回调，下个断点看看是什么在调用我们注册的回调。

![](http://wx3.sinaimg.cn/mw690/006juYZNly1fxf0s1hz9cj30cu05c0t1.jpg)

查看栈回溯得到关键函数ObpCallPreOperationCallbacks，ida上看有三个参数，网上搜了一圈只确定了前两个参数。

```c
signed __int64 __fastcall ObpCallPreOperationCallbacks(POBJECT_TYPE pObjectType, POB_PRE_OPERATION_INFORMATION OperationInformation, _QWORD *a3);
```

ida f5如下（做了一点重命名）

```c
signed __int64 __fastcall ObpCallPreOperationCallbacks(POBJECT_TYPE pObjectType, POB_PRE_OPERATION_INFORMATION pOperationInformation, _QWORD *a3)
{
  struct _KTHREAD *v3; // rax
  _QWORD *v4; // rbp
  POB_PRE_OPERATION_INFORMATION v_pOperationInformation; // r12
  POBJECT_TYPE v6; // rsi
  _QWORD *v7; // r13
  _OB_CALLBACK *pCallbackList; // r15
  signed __int64 v10; // rdx
  void (__fastcall *PreOperationCallback)(_QWORD, POB_PRE_OPERATION_INFORMATION); // r8
  __int64 v12; // r9
  struct _KTHREAD *v13; // r11
  signed __int64 v16; // rtt
  signed __int64 v17; // rax
  signed __int64 v18; // rcx
  volatile signed __int64 v19; // rtt
  struct _KTHREAD *v20; // rax
  bool v21; // zf
  signed __int64 v22; // rax
  unsigned __int64 v23; // rtt
  _QWORD *v24; // rax
  _QWORD *v25; // rcx
  _KTHREAD *v26; // rax
  signed __int64 v27; // rax
  unsigned __int64 v28; // rcx
  bool v29; // cf
  signed __int64 v30; // rcx
  volatile signed __int64 v31; // rtt
  struct _KTHREAD *v32; // rax
  signed __int64 v33; // rtt
  __int64 v34; // rdx
  __int64 v35; // rcx
  __int64 v36; // r8
  __int64 v37; // r9
  struct _KTHREAD *v38; // r11
  signed __int64 v41; // rtt
  int v42; // er11
  __int64 v43; // rcx
  PVOID v44; // rcx
  int Dst; // [rsp+20h] [rbp-58h]
  ULONG v46; // [rsp+24h] [rbp-54h]
  PVOID v47; // [rsp+28h] [rbp-50h]
  __int64 v48; // [rsp+30h] [rbp-48h]
  int v49; // [rsp+40h] [rbp-38h]

  v3 = KeGetCurrentThread();
  v4 = a3;
  --v3->KernelApcDisable;
  v_pOperationInformation = pOperationInformation;
  v6 = pObjectType;
  v7 = 0i64;
  _RDI = 0i64;
  pCallbackList = &pObjectType->CallbackList;   // 获得Object的CallbackList
  ObfReferenceObject(pOperationInformation->Object);
  v13 = KeGetCurrentThread();
  --v13->SpecialApcDisable;
  _RSI = &v6->TypeLock;
  if ( _InterlockedCompareExchange(_RSI, 17i64, 0i64) )
    ExfAcquirePushLockShared(_RSI);
  for ( _RBX = pCallbackList->ListEntry.Flink; ; _RBX = _RBX->ListEntry.Flink )
  {
    if ( _RBX == pCallbackList )                // 判断CallbackList是否遍历完毕
    {
      __asm { prefetchw byte ptr [rsi] }
      v27 = *_RSI;
      v28 = *_RSI & 0xFFFFFFFFFFFFFFF0ui64;
      v29 = v28 < 0x10;
      v21 = v28 == 16;
      v30 = *_RSI - 16;
      if ( v29 || v21 )
        v30 = 0i64;
      if ( v27 & 2 || (v31 = *_RSI, v31 != _InterlockedCompareExchange(_RSI, v30, v27)) )
        ExfReleasePushLock(_RSI);
      v32 = KeGetCurrentThread();
      v21 = v32->SpecialApcDisable++ == -1;
      if ( v21 && v32->ApcState.ApcListHead[0].Flink != &v32->80 )
        KiCheckForKernelApcDelivery(v30, v10, PreOperationCallback, v12);
      if ( _RDI )
      {
        __asm { prefetchw byte ptr [rdi] }
        v33 = *_RDI & 0xFFFFFFFFFFFFFFFEui64;
        if ( v33 != _InterlockedCompareExchange(_RDI, v33 - 2, v33) )
          ExfReleaseRundownProtection(_RDI);
      }
      if ( *v4 == v4 )
      {
        ObfDereferenceObject(v_pOperationInformation->Object);
        v38 = KeGetCurrentThread();
        v21 = v38->KernelApcDisable++ == -1;
        if ( v21 && v38->ApcState.ApcListHead[0].Flink != &v38->80 && !v38->SpecialApcDisable )
          KiCheckForKernelApcDelivery(v35, v34, v36, v37);
      }
      return 0i64;
    }
    if ( _RBX->Unknown1 & 0x100000000i64 )
    {
      if ( _RBX->Unknown1 & v_pOperationInformation->Operation )
      {
        __asm { prefetchw byte ptr [rbx+38h] }
        v16 = _RBX->RundownProtect.Count & 0xFFFFFFFFFFFFFFFEui64;
        if ( v16 == _InterlockedCompareExchange(&_RBX->RundownProtect, v16 + 2, v16)
          || ExfAcquireRundownProtection(&_RBX->RundownProtect) )
        {
          break;
        }
      }
    }
LABEL_31:
    ;
  }
  __asm { prefetchw byte ptr [rsi] }
  v17 = *_RSI;
  if ( (*_RSI & 0xFFFFFFFFFFFFFFF0ui64) <= 0x10 )
    v18 = 0i64;
  else
    v18 = v17 - 16;
  if ( v17 & 2 || (v19 = *_RSI, v19 != _InterlockedCompareExchange(_RSI, v18, v17)) )
    ExfReleasePushLock(_RSI);
  v20 = KeGetCurrentThread();
  v21 = v20->SpecialApcDisable++ == -1;
  if ( v21 && v20->ApcState.ApcListHead[0].Flink != &v20->80 )
    KiCheckForKernelApcDelivery(1i64, v10, PreOperationCallback, v12);
  if ( _RDI )
  {
    __asm { prefetchw byte ptr [rdi] }
    v22 = *_RDI & 0xFFFFFFFFFFFFFFFEui64;
    v10 = v22 - 2;
    v23 = *_RDI & 0xFFFFFFFFFFFFFFFEui64;
    if ( v23 != _InterlockedCompareExchange(_RDI, v22 - 2, v22) )
      ExfReleaseRundownProtection(_RDI);
    _RDI = 0i64;
  }
  if ( !_RBX->PostCall )
  {
LABEL_24:
    PreOperationCallback = _RBX->PreCall;
    if ( PreOperationCallback )
    {
      PreOperationCallback(*(_RBX->ObHandle + 8), v_pOperationInformation);// 调用PreOperationCallback
      if ( _RBX->PostCall )
        v7[3] = v_pOperationInformation->CallContext;
      else
        _RDI = &_RBX->RundownProtect;
      v_pOperationInformation->CallContext = 0i64;
    }
    v26 = KeGetCurrentThread();
    --v26->SpecialApcDisable;
    if ( _InterlockedCompareExchange(_RSI, 17i64, 0i64) )
      ExfAcquirePushLockShared(_RSI);
    goto LABEL_31;
  }
  v24 = ExAllocatePoolWithTag(PagedPool, 0x20u, 0x6C46624Fu);
  v7 = v24;
  if ( v24 )
  {
    v24[3] = 0i64;
    v24[2] = _RBX;
    v25 = v4[1];
    v24[1] = v25;
    *v24 = v4;
    *v25 = v24;
    v4[1] = v24;
    goto LABEL_24;
  }
  _RCX = &_RBX->RundownProtect;
  __asm { prefetchw byte ptr [rcx] }
  v41 = _RBX->RundownProtect.Count & 0xFFFFFFFFFFFFFFFEui64;
  if ( v41 != _InterlockedCompareExchange(&_RBX->RundownProtect, v41 - 2, v41) )
    ExfReleaseRundownProtection(_RCX);
  if ( *v4 != v4 )
  {
    memset(&Dst, 0, 0x30u);
    v42 = v_pOperationInformation->Operation;
    v46 = v_pOperationInformation->Flags;
    v43 = v_pOperationInformation->ObjectType;
    Dst = v42;
    v48 = v43;
    v44 = v_pOperationInformation->Object;
    v49 = 0xC000009A;
    v47 = v44;
    ObfReferenceObject(v44);
    ObpCallPostOperationCallbacks(&Dst, v4);
  }
  return 0xC000009Ai64;
}
```

虽然这个f5问题很大，但是大致可以看出来ObpCallPreOperationCallbacks是通过循环遍历_OBJECT_TYPE里的CallbackList来调用注册的回调的。

TA教程里提供的有关CallbackList的结构如下，里面的ListEntry就是CallbackList。

```c
typedef struct _OB_CALLBACK
{
    LIST_ENTRY  ListEntry;
    ULONG64 Unknown;
    ULONG64 ObHandle;
    ULONG64 ObjTypeAddr;
    ULONG64 PreCall;
    ULONG64 PostCall;
} OB_CALLBACK, *POB_CALLBACK;
```

但是通过阅读f5的函数之后，我发现TA提供的结构并不完整，现补充一下。

```c
typedef struct _OB_CALLBACK
{
    LIST_ENTRY  ListEntry;
    ULONG64 Unknown;
    ULONG64 ObHandle;
    ULONG64 ObjTypeAddr;
    ULONG64 PreCall;
    ULONG64 PostCall;
    EX_RUNDOWN_REF RundownProtect;
} OB_CALLBACK, *POB_CALLBACK;
```

有关RundownProtect可以看https://bbs.pediy.com/thread-173763.htm

这个补充的成员在后面绕过的时候会用到。



现在看看有关循环的部分

```c
for ( _RBX = pCallbackList->ListEntry.Flink; ; _RBX = _RBX->ListEntry.Flink )
```

可以发现ObpCallPreOperationCallbacks通过RBX来存储当前的CallbackList节点，我寻思着能不能通过在自己注册的回调里面改变这个RBX来跳过其他的回调，于是我做了一个实验。

先写两个回调

回调1

```c
OB_PREOP_CALLBACK_STATUS PreCallbackProcess(
	PVOID RegistrationContext,
	POB_PRE_OPERATION_INFORMATION OperationInformation
)
{
	DbgPrint("我没被拦截\n");
	return OB_PREOP_SUCCESS;
}
```

回调2（因为要操作RBX 想了想就用汇编来写了，代码有点渣，请见谅）

```asm
DbgPrint proto
ExAcquireRundownProtection proto
ExReleaseRundownProtection proto

.data
	EXTERN PsProcessType:QWORD
	str1 db '我开始拦截了',0Ah,0

.code
PreCallbackProcess2 proc
	sub rsp,64h
	lea rcx,str1
	call DbgPrint
	mov rax,rbx
	lea rcx,[rax+38h]
	call ExReleaseRundownProtection	;减少原本回调引用计数
	mov rax,PsProcessType
	mov rax,[rax]
	mov rax,[rax+0c8h]				;CallbackList的最后一个节点
	mov rbx,rax						;提前结束循环
	lea rcx,[rax+38h]
	call ExAcquireRundownProtection	;增加修改后回调的引用计数
	xor rax,rax
	add rsp,64h
	ret
PreCallbackProcess2 endp

end
```

这里需要用到ExAcquireRundownProtection和ExReleaseRundownProtection是因为ObpCallPreOperationCallbacks里有维护每个回调的RundownProtect成员，如果我们通过修改RBX来跳过其他回调的话，就需要自己动手维护这个成员，否则在卸载回调的时候会出大问题。

然后通过ObRegisterCallbacks来注册这两个回调，因为回调的顺序是根据Altitude来确定的，所以PreCallbackProcess2的高度要比PreCallbackProcess高，否则将起不到绕过其他回调的效果。

载入驱动后用DebugView看看

![](http://wx4.sinaimg.cn/mw690/006juYZNly1fxg0kgeyskj30sl0bqmy5.jpg)

可以看到PreCallbackProcess并没有执行，证明可以成功绕过。

后来我在win10 x64也测试过了，暂时没发现啥大问题。



然而一通操作下来我发现用处似乎不大，大家看着乐一乐就好。