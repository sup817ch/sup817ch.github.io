---
title: Windows x64 SEH笔记
date: 2020-09-04 17:58:25
tags:
---

之前一直没有整理过的东西，现在补一下。

<!-- more -->

# x64 SEH简介

先回顾一下x86的SEH构造：

 1. 在自身的栈空间中分配并初始化一个 EXCEPTION_REGISTRATION(_RECORD) 结构体。
 2. 将该 EXCEPTION_REGISTRATION(_RECORD) 挂入当前线程的异常链表。

可以看出x86的SEH都是动态构建的。

x64不再基于链式存储SEH，而是使用表式存储，信息直接存储在PE文件中的.pdata节中，具体位置可于DataDirectory的Exception Table(IMAGE_DIRECTORY_ENTRY_EXCEPTION)中找到 。

Exception Table由结构为RUNTIME_FUNCTION的数组组成。

```c++
typedef struct _RUNTIME_FUNCTION {
    ULONG BeginAddress;
    ULONG EndAddress;
    ULONG UnwindData;
} RUNTIME_FUNCTION, *PRUNTIME_FUNCTION;
```

每个RUNTIME_FUNCTION就是一个FunctionEntry，记录了函数的信息，其中BeginAddress和EndAddress就是函数的地址范围，而UnwindData指向UNWIND_INFO。

```c++
typedef enum _UNWIND_OP_CODES {
    UWOP_PUSH_NONVOL = 0, /* info == register number */
    UWOP_ALLOC_LARGE,     /* no info, alloc size in next 2 slots */
    UWOP_ALLOC_SMALL,     /* info == size of allocation / 8 - 1 */
    UWOP_SET_FPREG,       /* no info, FP = RSP + UNWIND_INFO.FPRegOffset*16 */
    UWOP_SAVE_NONVOL,     /* info == register number, offset in next slot */
    UWOP_SAVE_NONVOL_FAR, /* info == register number, offset in next 2 slots */
    UWOP_SAVE_XMM128 = 8, /* info == XMM reg number, offset in next slot */
    UWOP_SAVE_XMM128_FAR, /* info == XMM reg number, offset in next 2 slots */
    UWOP_PUSH_MACHFRAME   /* info == 0: no error-code, 1: error-code */
} UNWIND_CODE_OPS;

typedef union _UNWIND_CODE {
    struct {
        UBYTE CodeOffset;
        UBYTE UnwindOp : 4;
        UBYTE OpInfo   : 4;
    };
    USHORT FrameOffset;
} UNWIND_CODE, *PUNWIND_CODE;

#define UNW_FLAG_EHANDLER  0x01
#define UNW_FLAG_UHANDLER  0x02
#define UNW_FLAG_CHAININFO 0x04

typedef struct _UNWIND_INFO {
    UBYTE Version       : 3;
    UBYTE Flags         : 5;
    UBYTE SizeOfProlog;
    UBYTE CountOfCodes;
    UBYTE FrameRegister : 4;
    UBYTE FrameOffset   : 4;
    UNWIND_CODE UnwindCode[1];
/*  UNWIND_CODE MoreUnwindCode[((CountOfCodes + 1) & ~1) - 1];
*   union {
*       OPTIONAL ULONG ExceptionHandler;
*       OPTIONAL ULONG FunctionEntry;
*   };
*   OPTIONAL ULONG ExceptionData[]; */
} UNWIND_INFO, *PUNWIND_INFO;

typedef struct _SCOPE_TABLE {
    DWORD Count;
    struct {
        DWORD BeginAddress;
        DWORD EndAddress;
        DWORD HandlerAddress;
        DWORD JumpTarget;
    } ScopeRecord[1];
} SCOPE_TABLE, *PSCOPE_TABLE;
```

该结构包含了函数的序幕操作和异常处理信息，序幕操作包括开辟栈空间、保存非易失寄存器等。CountOfCodes记录了UnwindCode结构的个数。UnwindCode之后的成员是可选的，取决于是否有异常处理过程或者是否是链式的。ExceptionHandler指向异常处理函数，在MSVC中通常是\__C_specific_handler，ExceptionData则是ExceptionHandler指定使用的数据，MSVC中通常是SCOPE_TABLE结构。SCOPE_TABLE包含了函数中try的信息，具体含义在下面代码的注释当中。首先异常会先分发到__C_specific_handler，然后通过RIP和SCOPE_TABLE结构判断是哪个try。

# 实验代码测试

代码如下

```c++
#include <iostream>
#include <windows.h>
#include <stdio.h>

typedef enum _UNWIND_OP_CODES {
	UWOP_PUSH_NONVOL = 0, /* info == register number */
	UWOP_ALLOC_LARGE,     /* no info, alloc size in next 2 slots */
	UWOP_ALLOC_SMALL,     /* info == size of allocation / 8 - 1 */
	UWOP_SET_FPREG,       /* no info, FP = RSP + UNWIND_INFO.FPRegOffset*16 */
	UWOP_SAVE_NONVOL,     /* info == register number, offset in next slot */
	UWOP_SAVE_NONVOL_FAR, /* info == register number, offset in next 2 slots */
	UWOP_SAVE_XMM128 = 8, /* info == XMM reg number, offset in next slot */
	UWOP_SAVE_XMM128_FAR, /* info == XMM reg number, offset in next 2 slots */
	UWOP_PUSH_MACHFRAME   /* info == 0: no error-code, 1: error-code */
} UNWIND_CODE_OPS;

typedef union _UNWIND_CODE {
	struct {
		UCHAR CodeOffset;
		UCHAR UnwindOp : 4;
		UCHAR OpInfo : 4;
	};
	USHORT FrameOffset;
} UNWIND_CODE, *PUNWIND_CODE;

#define UNW_FLAG_EHANDLER  0x01
#define UNW_FLAG_UHANDLER  0x02
#define UNW_FLAG_CHAININFO 0x04

typedef struct _UNWIND_INFO {
	UCHAR Version : 3;
	UCHAR Flags : 5;
	UCHAR SizeOfProlog;
	UCHAR CountOfCodes;
	UCHAR FrameRegister : 4;
	UCHAR FrameOffset : 4;
	UNWIND_CODE UnwindCode[1];
	/*  UNWIND_CODE MoreUnwindCode[((CountOfCodes + 1) & ~1) - 1];
	*   union {
	*       OPTIONAL ULONG ExceptionHandler;
	*       OPTIONAL ULONG FunctionEntry;
	*   };
	*   OPTIONAL ULONG ExceptionData[]; */
} UNWIND_INFO, *PUNWIND_INFO;

#define GetUnwindCodeEntry(info, index) \
    ((info)->UnwindCode[index])

#define GetLanguageSpecificDataPtr(info) \
    ((PVOID)&GetUnwindCodeEntry((info),((info)->CountOfCodes + 1) & ~1))

#define GetExceptionHandler(base, info) \
    ((PVOID)((base) + *(PULONG)GetLanguageSpecificDataPtr(info)))

#define GetChainedFunctionEntry(base, info) \
    ((PRUNTIME_FUNCTION)((base) + *(PULONG)GetLanguageSpecificDataPtr(info)))

#define GetExceptionDataPtr(info) \
    ((PVOID)((PULONG)GetLanguageSpecificDataPtr(info) + 1))

VOID FindExceptionTable();

ULONG64 imageBase = 0;

int main()
{
	imageBase = (ULONG64)GetModuleHandle(NULL);
	printf("This is a SEH test\nimagebase:%p main:%p\n", imageBase, main);
	__try
	{
		printf("in try\n");
		int *p = 0;
		*p = 1;
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		printf("in except\n");
	}

	FindExceptionTable();

	return 0;
}

VOID FindExceptionTable()
{
	auto ntHeader = (PIMAGE_NT_HEADERS)(((PIMAGE_DOS_HEADER)imageBase)->e_lfanew + imageBase);
	auto exceptionTable = (PIMAGE_RUNTIME_FUNCTION_ENTRY)(ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress + imageBase);
	auto size = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
	printf("exceptionTable rva:%08X size:%d\n", (ULONG64)exceptionTable - imageBase, size);
	for (int i = 0; i < size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY); i++)
	{
		//BeginAddress为升序排序
		if (exceptionTable[i].BeginAddress + imageBase >= (ULONG64)main)
		{
			auto et = &exceptionTable[i];
			printf("exceptionTable[%d] BeginAddress:%08X EndAddress:%08X UnwindInfoAddress:%08X\n",
				i, et->BeginAddress, et->EndAddress, et->UnwindInfoAddress);
			auto unwind = (PUNWIND_INFO)(et->UnwindInfoAddress + imageBase);
			if (unwind->Flags & UNW_FLAG_EHANDLER)
			{
				printf("ExceptionHandler:%p\n", GetExceptionHandler(imageBase, unwind)); //指向__C_specific_handler
				auto st = (PSCOPE_TABLE)GetExceptionDataPtr(unwind);
				for (int j = 0; j < st->Count; j++)
				{
					printf("ScopeRecord[%d] BeginAddress:%08X EndAddress:%08X HandlerAddress:%08X JumpTarget:%08X",
						j, 
						st->ScopeRecord[j].BeginAddress,	//try的起始地址
						st->ScopeRecord[j].EndAddress,		//try的结束地址
						st->ScopeRecord[j].HandlerAddress,	//当为try except时为filter函数地址，当为try finally时为finally_handler
						st->ScopeRecord[j].JumpTarget);		//当为try except时为except_handler，当为try finally时为0
				}
			}
			
			break;
		}
	}
}
```

编译时将增量链接关闭，确保取得真实函数地址，运行的结果如下

```
This is a SEH test
imagebase:00007FF6E9190000 main:00007FF6E9191400
in try
in except
exceptionTable rva:00008000 size:1284
exceptionTable[5] BeginAddress:00001400 EndAddress:00001492 UnwindInfoAddress:00006200
ExceptionHandler:00007FF6E9194522
ScopeRecord[0] BeginAddress:00001454 EndAddress:00001474 HandlerAddress:00004740 JumpTarget:00001474
```

接下来通过ida验证一下

![1](http://tvax4.sinaimg.cn/large/006juYZNly1gieywnc3r2j30u90k341u.jpg)

其中except里的filter指向了一个直接返回EXCEPTION_EXECUTE_HANDLER的函数。

# 无模块注入中SEH的处理办法

这里直接抄一下xjun大佬的代码

```c++
static VOID
InsertExceptionTable(PMEMORYMODULE module)
{
#if defined(_WIN64)

	PIMAGE_DATA_DIRECTORY		pDataTable = \
		&module->headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

	PIMAGE_RUNTIME_FUNCTION_ENTRY pFuncTable = \
		(PIMAGE_RUNTIME_FUNCTION_ENTRY)((ULONG_PTR)module->codeBase + pDataTable->VirtualAddress);


	if (pfnRtlAddFunctionTable64 != NULL)
	{
		pfnRtlAddFunctionTable64(pFuncTable, pDataTable->Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), (DWORD64)module->codeBase);
	}

#else
	if (dwMajorVersion == 6 && dwMinorVersion == 1) //WIM7
	{
		if (pfnRtlInsertInvertedFunctionTable_Win7 != NULL);
		{
			pfnRtlInsertInvertedFunctionTable_Win7(LdrpInvertedFunctionTable, module->codeBase, module->headers->OptionalHeader.SizeOfImage);
		}
	}
	else if (dwMajorVersion == 6 && dwMinorVersion == 3) //WIN8
	{
		if (pfnRtlInsertInvertedFunctionTable_Win8_Win10 != NULL);
		{
			pfnRtlInsertInvertedFunctionTable_Win8_Win10(module->codeBase, module->headers->OptionalHeader.SizeOfImage);
		}
	}
	else if (dwMajorVersion == 10 && dwMinorVersion == 0) //WIN10
	{
		if (pfnRtlInsertInvertedFunctionTable_Win8_Win10 != NULL);
		{
			pfnRtlInsertInvertedFunctionTable_Win8_Win10(module->codeBase, module->headers->OptionalHeader.SizeOfImage);
		}
	}
	else
	{
		// not support
	}
#endif
}
```

函数分成了两个部分，一部分是处理64位程序，另一部分是处理32位程序，分析一下为什么这么写：

首先简单复习一下用户层的异常分发，异常处理从内核层返回到用户层之后首先是到KiUserExceptionDispatcher，然后x64环境下会先判断是否是Wow64，如果是的话就分发到32位的ntdll当中，处理过程和原生32位的一致。

之后KiUserExceptionDispatcher会调用RtlDispatchException。64位的RtlDispatchException会调用RtlLookupFunctionEntry，RtlLookupFunctionEntry不但会查找原本就存在于PE当中FunctionEntry，还会再调用RtlpLookupDynamicFunctionEntry来查找通过动态方式添加到RtlpDynamicFunctionTableTree中的FunctionEntry。微软文档在说明如何处理动态生成函数时提到了两个函数RtlInstallFunctionTableCallback和RtlAddFunctionTable，这两个函数就是把FunctionEntry动态添加到了RtlpDynamicFunctionTableTree当中。而32位的RtlDispatchException还是通过老规矩SEH链来调用异常处理函数，至于这里为啥还要插个InvertedFunctionTable，大概是因为32位的RtlDispatchException还会调用一个RtlIsValidHandler来检查Handler是否合法，wrk中RtlIsValidHandler的实现如下

```c
BOOLEAN
RtlIsValidHandler (
    IN PEXCEPTION_ROUTINE Handler
    )
{
    PULONG FunctionTable;
    ULONG FunctionTableLength;
    PVOID Base;

    FunctionTable = RtlLookupFunctionTable(Handler, &Base, &FunctionTableLength);

    if (FunctionTable && FunctionTableLength) {
        PEXCEPTION_ROUTINE FunctionEntry;
        LONG High, Middle, Low;

        if ((FunctionTable == LongToPtr(-1)) && (FunctionTableLength == (ULONG)-1)) {
            // Address is in an image that shouldn't have any handlers (like a resource only dll).
            RtlInvalidHandlerDetected((PVOID)((ULONG)Handler+(ULONG)Base), LongToPtr(-1), -1);
            return FALSE;
        }
    
        // Bias the handler value down by the image base and see if the result
        // is in the table

        (ULONG)Handler -= (ULONG)Base;
        Low = 0;
        High = FunctionTableLength;
        while (High >= Low) {
            Middle = (Low + High) >> 1;
            FunctionEntry = (PEXCEPTION_ROUTINE)FunctionTable[Middle];
            if (Handler < FunctionEntry) {
                High = Middle - 1;
            } else if (Handler > FunctionEntry) {
                Low = Middle + 1;
            } else {
                // found it
                return TRUE;
            }
        }
        // Didn't find it
        RtlInvalidHandlerDetected((PVOID)((ULONG)Handler+(ULONG)Base), FunctionTable, FunctionTableLength);

        return FALSE;
    }

    // Can't verify
    return TRUE;
}
```

可以发现如果找不到FunctionTable就直接返回TRUE了，所以32位似乎不插这个InvertedFunctionTable也是没关系的。

# 参考

[x64 exception handling](https://docs.microsoft.com/en-us/cpp/build/exception-handling-x64?view=vs-2019)

[x64的seh](https://blog.csdn.net/shevacoming/article/details/7777530)

[SEH分析笔记（X64篇）](https://cloud.tencent.com/developer/article/1471316)

《加密与解密》第四版