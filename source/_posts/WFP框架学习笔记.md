---
title: WFP框架学习笔记
date: 2020-05-06 13:36:36
tags:
---

# WFP简介

Windows Filtering Platform (WFP) 是用来创建网络过滤应用的一组API和系统服务，以代替以前的过滤技术比如Transport Driver Interface (TDI) filters，Network Driver Interface Specification (NDIS) filters，和Winsock Layered Service Providers (LSP)。

<!-- more -->

# WFP框架结构

![basic architecture of the windows filtering platform diagram](https://docs.microsoft.com/en-us/windows/win32/fwp/images/wfp-architecture.png)

从图中可知WFP分为用户模式的Base Filtering Engine (BFE)和内核模式的KM Filter Engine。用户可以在用户层通过API与BFE交互，BFE再与KMFE交互，也可以再内核层直接与KMFE交互。

# WFP运作方式

WFP通过以下四个部分执行任务：Layers, Filters, Shims and Callouts.

## Layers

WFP过滤引擎分为多个层（Layers），对应系统网络协议栈的各个层，从中接受特定的数据。分层是一个容器，包含了各种过滤器。

## Filters

过滤器是一组规则用来匹配传入和传出的网络数据包，并告诉过滤引擎对这些网络数据包进行什么操作，包括调用callout来进行深层次检查。

## Shims

垫片（Shims）是一个内核模式组件，被安插在网络协议栈的不同层中，将网络数据分类到过滤引擎的不同分层，并让过滤引擎做出判断，最终也是垫片对这些网络数据执行对应操作。

## Callouts

Callouts是驱动程序注册的一组接口，用来对网络数据包进行分析和处理。如果过滤器有指定callout，那么当过滤器匹配到对应的网络数据时便可以调用该接口。Callouts只能通过驱动注册，但可以在内核层和用户层中添加到过滤器，系统也内置了一些callouts。



# WFP例子

比较重要的几个成员的文档介绍：

Filtering Conditions: https://docs.microsoft.com/en-us/windows/win32/fwp/filtering-conditions

Filtering Layer Identifiers: https://docs.microsoft.com/en-us/windows/win32/fwp/management-filtering-layer-identifiers-

## 用户层

通过FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4对指定程序在分配端口等资源的时候进行拦截。

```c++
#include <windows.h>
#include <fwpmu.h>
#include <accctrl.h>
#include <aclapi.h>
#include <stdio.h>

#pragma comment (lib, "fwpuclnt.lib")
#pragma comment (lib, "advapi32.lib")

#define SESSION_NAME L"SDK Examples"

#define EXIT_ON_ERROR(fnName) \
   if (result != ERROR_SUCCESS) \
   { \
      printf(#fnName " = 0x%08X\n", result); \
      goto CLEANUP; \
   }

// {817922AE-E4DF-46D0-BDAE-CEE9E3EFD18B}
static const GUID TRAFFIC_FILTER =
{ 0x817922ae, 0xe4df, 0x46d0, { 0xbd, 0xae, 0xce, 0xe9, 0xe3, 0xef, 0xd1, 0x8b } };

DWORD FilterByUserAndApp(
	__in HANDLE engine,
	__in PCWSTR filterName,
	__in_opt const GUID* providerKey,
	__in const GUID* layerKey,
	__in_opt const GUID* subLayerKey,
	__in_opt PCWSTR userName,
	__in_opt PCWSTR appPath,
	__in FWP_ACTION_TYPE actionType,
	__out_opt UINT64* filterId
)
{
	DWORD result = ERROR_SUCCESS;
	FWPM_FILTER_CONDITION0 conds[2];
	UINT32 numConds = 0;
	EXPLICIT_ACCESS_W access;
	ULONG sdLen;
	PSECURITY_DESCRIPTOR sd = NULL;
	FWP_BYTE_BLOB sdBlob, *appBlob = NULL;
	FWPM_FILTER0 filter;

	// Add an FWPM_CONDITION_ALE_USER_ID condition if requested.
	if (userName != NULL)
	{
		// When evaluating SECURITY_DESCRIPTOR conditions, the filter engine
		// checks for FWP_ACTRL_MATCH_FILTER access. If the DACL grants access,
		// it does not mean that the traffic is allowed; it just means that the
		// condition evaluates to true. Likewise if it denies access, the
		// condition evaluates to false.
		BuildExplicitAccessWithNameW(
			&access,
			(PWSTR)userName,
			FWP_ACTRL_MATCH_FILTER,
			GRANT_ACCESS,
			0
		);

		result = BuildSecurityDescriptorW(
			NULL,
			NULL,
			1,
			&access,
			0,
			NULL,
			NULL,
			&sdLen,
			&sd
		);
		EXIT_ON_ERROR(BuildSecurityDescriptorW);

		// Security descriptors must be in self-relative form (i.e., contiguous).
		// The security descriptor returned by BuildSecurityDescriptorW is
		// already self-relative, but if you're using another mechanism to build
		// the descriptor, you may have to convert it. See MakeSelfRelativeSD for
		// details.
		sdBlob.size = sdLen;
		sdBlob.data = (UINT8*)sd;

		conds[numConds].fieldKey = FWPM_CONDITION_ALE_USER_ID;
		conds[numConds].matchType = FWP_MATCH_EQUAL;
		conds[numConds].conditionValue.type = FWP_SECURITY_DESCRIPTOR_TYPE;
		conds[numConds].conditionValue.sd = &sdBlob;
		++numConds;
	}

	// Add an FWPM_CONDITION_ALE_APP_ID condition if requested.
	if (appPath != NULL)
	{
		// appPath must be a fully-qualified file name, and the file must
		// exist on the local machine.
		result = FwpmGetAppIdFromFileName0(appPath, &appBlob);
		EXIT_ON_ERROR(FwpmGetAppIdFromFileName0);

		conds[numConds].fieldKey = FWPM_CONDITION_ALE_APP_ID;
		conds[numConds].matchType = FWP_MATCH_EQUAL;
		conds[numConds].conditionValue.type = FWP_BYTE_BLOB_TYPE;
		conds[numConds].conditionValue.byteBlob = appBlob;
		++numConds;
	}

	memset(&filter, 0, sizeof(filter));
	// For MUI compatibility, object names should be indirect strings. See
	// SHLoadIndirectString for details.
	filter.displayData.name = (PWSTR)filterName;
	// Link all objects to our provider. When multiple providers are installed
	// on a computer, this makes it easy to determine who added what.
	filter.providerKey = (GUID*)providerKey;
	filter.layerKey = *layerKey;
	// Generally, it's best to add filters to our own sublayer, so we don't have
	// to worry about being overridden by filters added by another provider.
	if (subLayerKey != NULL)
	{
		filter.subLayerKey = *subLayerKey;
	}
	filter.numFilterConditions = numConds;
	if (numConds > 0)
	{
		filter.filterCondition = conds;
	}
	filter.action.type = actionType;

	result = FwpmFilterAdd0(engine, &filter, NULL, filterId);
	EXIT_ON_ERROR(FwpmFilterAdd0);

CLEANUP:
	FwpmFreeMemory0((void**)&appBlob);
	LocalFree(sd);
	return result;
}

int main()
{
	DWORD result = ERROR_SUCCESS;
	HANDLE engine = NULL;
	FWPM_SESSION0 session = { 0 };
	UINT64 filterId = 0;

	session.displayData.name = SESSION_NAME;
	session.txnWaitTimeoutInMSec = INFINITE;
	result = FwpmEngineOpen0(
		NULL,
		RPC_C_AUTHN_DEFAULT,
		NULL,
		&session,
		&engine
	);
	EXIT_ON_ERROR(FwpmEngineOpen0);

	result = FwpmTransactionBegin0(engine, 0);
	EXIT_ON_ERROR(FwpmTransactionBegin0);

	result = FilterByUserAndApp(
		engine,
		L"Traffic Filter",
		NULL,
		&FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4,
		NULL,
		NULL,
		L"D:\\src\\mysrc\\vs17\\SocketTest\\Debug\\echo_client.exe",
		FWP_ACTION_BLOCK,
		&filterId);
	EXIT_ON_ERROR(FilterByUserAndApp);

	result = FwpmTransactionCommit0(engine);
	EXIT_ON_ERROR(FwpmTransactionCommit0);

	printf("filter add\n");

	system("pause");

	result = FwpmTransactionBegin0(engine, 0);
	EXIT_ON_ERROR(FwpmTransactionBegin0);

	result = FwpmFilterDeleteById0(engine, filterId);

	result = FwpmTransactionCommit0(engine);
	EXIT_ON_ERROR(FwpmTransactionCommit0);

CLEANUP:
	FwpmEngineClose0(engine);
	return result;
}

```

## 内核层

还是通过FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4对指定端口进行拦截，但是是从callout处进行拦截，此处用的是最简单的功能，callout能做的事远不止如此。

```c
#define INITGUID

#include <ntifs.h>
#include <fwpmk.h>
#include <fwpsk.h>

#define DEVICE_NAME L"\\Device\\WfpDeviceTest"
#define SYM_LINK_NAME L"\\??\\WfpDeviceTest"

// {1564FA31-FF28-4CD2-9DFD-95715542CC5C}
static const GUID WFP_CALLOUT_TEST_GUID =
{ 0x1564fa31, 0xff28, 0x4cd2, { 0x9d, 0xfd, 0x95, 0x71, 0x55, 0x42, 0xcc, 0x5c } };

// {33472182-2834-41DB-A46D-CF709CFD88C0}
static const GUID WFP_SUBLAYER_TEST_GUID =
{ 0x33472182, 0x2834, 0x41db, { 0xa4, 0x6d, 0xcf, 0x70, 0x9c, 0xfd, 0x88, 0xc0 } };

// {B04E145F-E3BD-472A-9E57-7F79A159F1EC}
static const GUID WFP_FILTER_TEST_GUID =
{ 0xb04e145f, 0xe3bd, 0x472a, { 0x9e, 0x57, 0x7f, 0x79, 0xa1, 0x59, 0xf1, 0xec } };


HANDLE g_hEngine = NULL;
PDEVICE_OBJECT g_DeviceObject = NULL;

void ClassifyFn(
	const FWPS_INCOMING_VALUES *inFixedValues,
	const FWPS_INCOMING_METADATA_VALUES *inMetaValues,
	void *layerData,
	const void* classifyContext,
	const FWPS_FILTER *filter,
	UINT64 flowContext,
	FWPS_CLASSIFY_OUT *classifyOut
)
{
	UINT16 LocalPort = 0;

	DbgPrint("ClassifyFn\n");
	
	__try
	{
		if (!(classifyOut->rights & FWPS_RIGHT_ACTION_WRITE))
		{
			return;
		}

		LocalPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_IP_LOCAL_PORT].value.uint16;
		DbgPrint("LocalPort:%d\n", LocalPort);

		classifyOut->actionType = FWP_ACTION_PERMIT;

		if (LocalPort == 6888)
		{
			classifyOut->actionType = FWP_ACTION_BLOCK;
			classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
		}

		if (filter->flags & FWPS_FILTER_FLAG_CLEAR_ACTION_RIGHT)
		{
			classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint("ClassifyFn Exception");
	}
}

NTSTATUS NotifyFn(
	FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	const GUID *filterKey,
	FWPS_FILTER *filter
)
{
	DbgPrint("NotifyFn notifyType:%d\n", notifyType);
	return STATUS_SUCCESS;
}

void FlowDeleteNotifyFn(
	UINT16 layerId,
	UINT32 calloutId,
	UINT64 flowContext
)
{
	DbgPrint("FlowDeleteNotifyFn\n");
}

NTSTATUS WfpOpenEngine(IN PHANDLE hEngine)
{
	NTSTATUS status = STATUS_SUCCESS;

	status = FwpmEngineOpen(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, hEngine);
	return status;
}

NTSTATUS WfpResgisterCallouts(IN PDEVICE_OBJECT DeviceObject)
{
	NTSTATUS status = STATUS_SUCCESS;
	FWPS_CALLOUT FwpsCallout = { 0 };

	FwpsCallout.calloutKey = WFP_CALLOUT_TEST_GUID;
	FwpsCallout.flags = 0;
	FwpsCallout.classifyFn = ClassifyFn;
	FwpsCallout.notifyFn = NotifyFn;
	FwpsCallout.flowDeleteFn = FlowDeleteNotifyFn;

	status = FwpsCalloutRegister(DeviceObject, &FwpsCallout, NULL);
	return status;
}

NTSTATUS WfpAddCallouts()
{
	NTSTATUS status = STATUS_SUCCESS;
	FWPM_CALLOUT FwpmCallout = { 0 };

	FwpmCallout.calloutKey = WFP_CALLOUT_TEST_GUID;
	FwpmCallout.displayData.name = L"Callout test name";
	FwpmCallout.displayData.description = L"Callout test description";
	FwpmCallout.flags = 0;
	FwpmCallout.applicableLayer = FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4;

	status = FwpmCalloutAdd(g_hEngine, &FwpmCallout, NULL, NULL);
	return status;
}

NTSTATUS WfpAddSubLayer()
{
	NTSTATUS status = STATUS_SUCCESS;
	FWPM_SUBLAYER FwpmSubLayer = { 0 };

	FwpmSubLayer.subLayerKey = WFP_SUBLAYER_TEST_GUID;
	FwpmSubLayer.displayData.name = L"Sublayer test name";
	FwpmSubLayer.displayData.description = L"Sublayer test description";
	FwpmSubLayer.flags = 0;
	FwpmSubLayer.weight = 65535;
	status = FwpmSubLayerAdd(g_hEngine, &FwpmSubLayer, NULL);
	return status;
}

NTSTATUS WfpAddFilters()
{
	NTSTATUS status = STATUS_SUCCESS;
	FWPM_FILTER FwpmFilter = { 0 };
	FWPM_FILTER_CONDITION FwpmFilterCondition = { 0 };

	FwpmFilterCondition.fieldKey = FWPM_CONDITION_IP_PROTOCOL;
	FwpmFilterCondition.matchType = FWP_MATCH_EQUAL;
	FwpmFilterCondition.conditionValue.type = FWP_UINT8;
	FwpmFilterCondition.conditionValue.uint8 = 6; //TCP
	
	FwpmFilter.filterKey = WFP_FILTER_TEST_GUID;
	FwpmFilter.displayData.name = L"Filter test name";
	FwpmFilter.displayData.description = L"Filter test description";
	FwpmFilter.flags = 0;
	FwpmFilter.layerKey = FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4;
	FwpmFilter.subLayerKey = WFP_SUBLAYER_TEST_GUID;
	FwpmFilter.weight.type = FWP_EMPTY;
	FwpmFilter.numFilterConditions = 1;
	FwpmFilter.filterCondition = &FwpmFilterCondition;
	FwpmFilter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
	FwpmFilter.action.calloutKey = WFP_CALLOUT_TEST_GUID;

	status = FwpmFilterAdd(g_hEngine, &FwpmFilter, NULL, NULL);
	return status;
}

NTSTATUS WfpCloseEngine()
{
	NTSTATUS status = STATUS_SUCCESS;

	if (g_hEngine != NULL)
	{
		status = FwpmEngineClose(g_hEngine);
	}
	return status;
}

NTSTATUS WfpRemoveFilter()
{
	NTSTATUS status = STATUS_SUCCESS;

	if (g_hEngine != NULL)
	{
		status = FwpmFilterDeleteByKey(g_hEngine, &WFP_FILTER_TEST_GUID);
	}
	return status;
}

NTSTATUS WfpRemoveSubLayer()
{
	NTSTATUS status = STATUS_SUCCESS;

	if (g_hEngine != NULL)
	{
		status = FwpmSubLayerDeleteByKey(g_hEngine, &WFP_SUBLAYER_TEST_GUID);
	}
	return status;
}

NTSTATUS WfpRemoveCallouts()
{
	NTSTATUS status = STATUS_SUCCESS;

	if (g_hEngine != NULL)
	{
		status = FwpmCalloutDeleteByKey(g_hEngine, &WFP_CALLOUT_TEST_GUID);
	}
	return status;
}

NTSTATUS WfpUnregisterCallouts()
{
	NTSTATUS status = STATUS_SUCCESS;

	if (g_hEngine != NULL)
	{
		status = FwpsCalloutUnregisterByKey(&WFP_CALLOUT_TEST_GUID);
	}
	return status;
}

NTSTATUS WfpInit(IN PDEVICE_OBJECT DeviceObject)
{
	NTSTATUS status = STATUS_SUCCESS;

	status = WfpOpenEngine(&g_hEngine);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("WfpOpenEngine failed! status:%08X\n", status);
		return status;
	}

	status = WfpResgisterCallouts(DeviceObject);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("WfpRegisterCallouts failed! status:%08X\n", status);
		return status;
	}

	status = WfpAddCallouts();
	if (!NT_SUCCESS(status))
	{
		DbgPrint("WfpAddCallouts failed! status:%08X\n", status);
		return status;
	}

	status = WfpAddSubLayer();
	if (!NT_SUCCESS(status))
	{
		DbgPrint("WfpAddSubLayer failed! status:%08X\n", status);
		return status;
	}

	status = WfpAddFilters();
	if (!NT_SUCCESS(status))
	{
		DbgPrint("WfpAddFilters failed! status:%08X\n", status);
		return status;
	}

	return status;
}

NTSTATUS WfpUninstall()
{
	NTSTATUS status = STATUS_SUCCESS;

	status = WfpRemoveFilter();
	if (!NT_SUCCESS(status))
	{
		DbgPrint("WfpRemoveFilter failed! status:%08X\n", status);
		return status;
	}

	status = WfpRemoveSubLayer();
	if (!NT_SUCCESS(status))
	{
		DbgPrint("WfpRemoveSubLayer failed! status:%08X\n", status);
		return status;
	}

	status = WfpRemoveCallouts();
	if (!NT_SUCCESS(status))
	{
		DbgPrint("WfpRemoveCallouts failed! status:%08X\n", status);
		return status;
	}

	status = WfpUnregisterCallouts();
	if (!NT_SUCCESS(status))
	{
		DbgPrint("WfpUnregisterCallouts failed! status:%08X\n", status);
		return status;
	}

	status = WfpCloseEngine();
	if (!NT_SUCCESS(status))
	{
		DbgPrint("WfpCloseEngine failed! status:%08X\n", status);
		return status;
	}
}

PDEVICE_OBJECT CreateDevice(IN PDRIVER_OBJECT DriverObject)
{
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING DeviceName = { 0 };
	UNICODE_STRING SymLinkName = { 0 };
	PDEVICE_OBJECT DeviceObject = NULL;

	RtlInitUnicodeString(&DeviceName, DEVICE_NAME);
	RtlInitUnicodeString(&SymLinkName, SYM_LINK_NAME);
	status = IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("IoCreateDevice failed! status:%08X\n", status);
		return NULL;
	}
	status = IoCreateSymbolicLink(&SymLinkName, &DeviceName);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("IoCreateSymbolicLink failed! status:%08X\n", status);
		IoDeleteDevice(DeviceObject);
		return NULL;
	}
	return DeviceObject;
}

void DeleteDevice(IN PDEVICE_OBJECT DeviceObject)
{
	UNICODE_STRING SymlinkName;

	RtlInitUnicodeString(&SymlinkName, SYM_LINK_NAME);

	IoDeleteSymbolicLink(&SymlinkName);
	IoDeleteDevice(DeviceObject);
}

void DriverUnload(PDRIVER_OBJECT DriverObject)
{
	WfpUninstall();
	DeleteDevice(g_DeviceObject);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	NTSTATUS status = STATUS_SUCCESS;

	DbgPrint("DriverEntry\n");

	DriverObject->DriverUnload = DriverUnload;

	g_DeviceObject = CreateDevice(DriverObject);
	if (g_DeviceObject == NULL)
	{
		DbgPrint("CreateDevice failed!\n");
		return STATUS_UNSUCCESSFUL;
	}

	status = WfpInit(g_DeviceObject);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("WfpInit failed!\n");
		DeleteDevice(g_DeviceObject);
		return STATUS_UNSUCCESSFUL;
	}

	return status;
}
```

