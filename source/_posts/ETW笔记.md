---
title: ETW笔记
date: 2021-01-12 14:28:19
tags:
---

# ETW概述

Event Tracing for Windows (ETW)是一种高效率的内核级跟踪工具，可以将内核或者应用程序定义的事件记录到日志文件中。使用者可以实时处理事件，也可以从日志文件中处理。

ETW可以动态地启用或禁用事件跟踪，无需重启计算机或应用程序。

<!-- more -->

Event Tracing API分为三个组件：

- Controllers，用于启动或停止事件跟踪会话（Event tracing session）和启用提供程序(providers)
- Providers，提供事件
- Consumers，消费事件

下图为事件跟踪模型

![](https://docs.microsoft.com/en-us/windows/win32/etw/images/etdiag2.png)



## Controllers

Controllers用于定义日志文件的大小和位置，启动和停止事件跟踪会话以及启用提供程序，以便提供程序能将事件记录到会话，管理缓冲池的大小以及获取会话的执行统计信息。会话的统计信息包括缓冲区的使用数量，投递数量以及事件和缓冲区的丢失数量。



## Providers

Providers具有提供事件的能力。在provider注册之后，controller就可以启用或禁用provider的事件跟踪。provider定义其对启用或禁用的解释。通常，一个启用的provider将生成事件，而禁用的provider则不会。这让使用者可以添加事件跟踪到应用程序中而无需一直生成事件。

尽管ETW模型将controller和provider分成了两个程序，但一个程序可以同时包含这两个组件

Providers有以下几种类型：

**MOF (classic) providers:**

- Use the [RegisterTraceGuids](https://docs.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-registertraceguidsa) and [TraceEvent](https://docs.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-traceevent) functions to register and write events.
- Use MOF classes to define events so that consumers know how to consume them.
- Can be enabled by only one trace session at a time.

**WPP providers:**

- Use the [RegisterTraceGuids](https://docs.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-registertraceguidsa) and [TraceEvent](https://docs.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-traceevent) functions to register and write events.
- Have associated TMF files (compiled into a binary's .pdb) containing decoding information inferred from the preprocessor's scan of WPP instrumentation in source code.
- Can be enabled by only one trace session at a time.

**Manifest-based providers:**

- Use [EventRegister](https://docs.microsoft.com/en-us/windows/desktop/api/Evntprov/nf-evntprov-eventregister) and [EventWrite](https://docs.microsoft.com/en-us/windows/desktop/api/Evntprov/nf-evntprov-eventwrite) to register and write events.
- Use a manifest to define events so that consumers know how to consume them.
- Can be enabled by up to eight trace sessions simultaneously.

**[TraceLogging](https://docs.microsoft.com/en-us/windows/desktop/tracelogging/trace-logging-about) providers:**

- Use [TraceLoggingRegister](https://docs.microsoft.com/en-us/windows/desktop/api/traceloggingprovider/nf-traceloggingprovider-traceloggingregister) and [TraceLoggingWrite](https://docs.microsoft.com/en-us/windows/desktop/api/traceloggingprovider/nf-traceloggingprovider-traceloggingwrite) to register and write events.
- Use self-describing events so that the events themselves contain all required information for consuming them.
- Can be enabled by up to eight trace sessions simultaneously.

所有的providers都基于事件跟踪系列API ([TraceEvent](https://docs.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-traceevent) for legacy technologies and [EventWrite](https://docs.microsoft.com/en-us/windows/desktop/api/Evntprov/nf-evntprov-eventwrite)/[EventWriteEx](https://docs.microsoft.com/en-us/windows/desktop/api/Evntprov/nf-evntprov-eventwriteex) for newer ones).



## Consumers

Consumers可以选择一个或多个事件跟踪会话作为事件的源。consumer可以同时从多个事件跟踪会话中请求事件；系统按事件顺序投递事件。consumer可以从日志文件中接收事件，也可以从会话中实时接收事件。当处理事件时，consumer可以指定开始和结束时间，只有在指定时间内的事件才会被投递。



# logman使用

## 列出所有正在运行的跟踪会话

```
> logman query -ets
Data Collector Set                Type    Status
-------------------------------------------------
Circular Kernel Context Logger    Trace   Running
AppModel                          Trace   Running
ScreenOnPowerStudyTraceSession    Trace   Running
DiagLog                           Trace   Running
EventLog-Application              Trace   Running
EventLog-System                   Trace   Running
LwtNetLog                         Trace   Running
NtfsLog                           Trace   Running
TileStore                         Trace   Running
UBPM                              Trace   Running
WdiContextLog                     Trace   Running
WiFiSession                       Trace   Running
UserNotPresentTraceSession        Trace   Running
Diagtrack-Listener                Trace   Running
MSDTC_TRACE_SESSION               Trace   Running
WindowsUpdate_trace_log           Trace   Running
```

## 列出所有订阅跟踪会话的提供者

```
> logman query "EventLog-Application" -ets
Name:                 EventLog-Application
Status:               Running
Root Path:            %systemdrive%PerfLogsAdmin
Segment:              Off
Schedules:            On
Segment Max Size:     100 MB

Name:                 EventLog-ApplicationEventLog-Application
Type:                 Trace
Append:               Off
Circular:             Off
Overwrite:            Off
Buffer Size:          64
Buffers Lost:         0
Buffers Written:      242
Buffer Flush Timer:   1
Clock Type:           System
File Mode:            Real-time

Provider:
Name:                 Microsoft-Windows-SenseIR
Provider Guid:        {B6D775EF-1436-4FE6-BAD3-9E436319E218}
Level:                255
KeywordsAll:          0x0
KeywordsAny:          0x8000000000000000 (Microsoft-Windows-SenseIR/Operational)
Properties:           65
Filter Type:          0

Provider:
Name:                 Microsoft-Windows-WDAG-Service
Provider Guid:        {728B02D9-BF21-49F6-BE3F-91BC06F7467E}
Level:                255
KeywordsAll:          0x0
KeywordsAny:          0x8000000000000000
Properties:           65
Filter Type:          0

...

Provider:
Name:                 Microsoft-Windows-PowerShell
Provider Guid:        {A0C1853B-5C40-4B15-8766-3CF1C58F985A}
Level:                255
KeywordsAll:          0x0
KeywordsAny:          0x9000000000000000 (Microsoft-Windows-PowerShell/Operational,Microsoft-Windows-PowerShell/Admin)
Properties:           65
Filter Type:          0
```

## 列出所有已注册的ETW提供者

```
> logman query providers
```

## 单独查看提供者

```
> logman query providers Microsoft-Windows-PowerShell
Provider                        GUID
----------------------------------------------------------------------
Microsoft-Windows-PowerShell    {A0C1853B-5C40-4B15-8766-3CF1C58F985A}

Value               Keyword              Description
----------------------------------------------------------------------
0x0000000000000001  Runspace             PowerShell Runspace
0x0000000000000002  Pipeline             Pipeline of Commands
0x0000000000000004  Protocol             PowerShell remoting protocol
0x0000000000000008  Transport            PowerShell remoting transport
0x0000000000000010  Host                 PowerShell remoting host proxy calls
0x0000000000000020  Cmdlets              All remoting cmdlets
0x0000000000000040  Serializer           The serialization layer
0x0000000000000080  Session              All session layer
0x0000000000000100  Plugin               The managed PowerShell plugin worker
0x0000000000000200  PSWorkflow           PSWorkflow Hosting And Execution Layer
0x0001000000000000  win:ResponseTime     Response Time
0x8000000000000000  Microsoft-Windows-PowerShell/Operational Microsoft-Windows-PowerShell/Operational
0x4000000000000000  Microsoft-Windows-PowerShell/Analytic Microsoft-Windows-PowerShell/Analytic
0x2000000000000000  Microsoft-Windows-PowerShell/Debug Microsoft-Windows-PowerShell/Debug
0x1000000000000000  Microsoft-Windows-PowerShell/Admin Microsoft-Windows-PowerShell/Admin

Value        Level                Description
--------------------------------------------------------------------
0x02         win:Error            Error
0x03         win:Warning          Warning
0x04         win:Informational    Information
0x05         win:Verbose          Verbose
0x14         Debug                Debug level defined by PowerShell (which is above Informational defined by system)

PID          Image
----------------------------------------------------------------------
0x00000730   C:WindowsSystem32WindowsPowerShellv1.0powershell.exe
0x0000100c   C:WindowsSystem32WindowsPowerShellv1.0powershell.exe
```

## 查看进程向哪些提供者写入事件

```
> logman query providers -pid 5244
Provider                                 GUID
-------------------------------------------------------------------------------
FWPUCLNT Trace Provider                  {5A1600D2-68E5-4DE7-BCF4-1C2D215FE0FE}
Microsoft-Antimalware-Protection         {E4B70372-261F-4C54-8FA6-A5A7914D73DA}
Microsoft-Antimalware-RTP                {8E92DEEF-5E17-413B-B927-59B2F06A3CFC}
Microsoft-Antimalware-Service            {751EF305-6C6E-4FED-B847-02EF79D26AEF}
Microsoft-IEFRAME                        {5C8BB950-959E-4309-8908-67961A1205D5}
Microsoft-Windows-AppXDeployment         {8127F6D4-59F9-4ABF-8952-3E3A02073D5F}
Microsoft-Windows-ASN1                   {D92EF8AC-99DD-4AB8-B91D-C6EBA85F3755}
Microsoft-Windows-AsynchronousCausality  {19A4C69A-28EB-4D4B-8D94-5F19055A1B5C}
Microsoft-Windows-CAPI2                  {5BBCA4A8-B209-48DC-A8C7-B23D3E5216FB}
Microsoft-Windows-COM-Perf               {B8D6861B-D20F-4EEC-BBAE-87E0DD80602B}
Microsoft-Windows-COM-RundownInstrumentation {2957313D-FCAA-5D4A-2F69-32CE5F0AC44E}
Microsoft-Windows-COMRuntime             {BF406804-6AFA-46E7-8A48-6C357E1D6D61}
Microsoft-Windows-Crypto-BCrypt          {C7E089AC-BA2A-11E0-9AF7-68384824019B}
Microsoft-Windows-Crypto-NCrypt          {E8ED09DC-100C-45E2-9FC8-B53399EC1F70}
Microsoft-Windows-Crypto-RSAEnh          {152FDB2B-6E9D-4B60-B317-815D5F174C4A}
Microsoft-Windows-Deplorch               {B9DA9FE6-AE5F-4F3E-B2FA-8E623C11DC75}
Microsoft-Windows-DNS-Client             {1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}
Microsoft-Windows-Heap-Snapshot          {901D2AFA-4FF6-46D7-8D0E-53645E1A47F5}
Microsoft-Windows-Immersive-Shell-API    {5F0E257F-C224-43E5-9555-2ADCB8540A58}
Microsoft-Windows-Kernel-AppCompat       {16A1ADC1-9B7F-4CD9-94B3-D8296AB1B130}
Microsoft-Windows-KnownFolders           {8939299F-2315-4C5C-9B91-ABB86AA0627D}
Microsoft-Windows-MPS-CLNT               {37945DC2-899B-44D1-B79C-DD4A9E57FF98}
Microsoft-Windows-Networking-Correlation {83ED54F0-4D48-4E45-B16E-726FFD1FA4AF}
Microsoft-Windows-NetworkProfile         {FBCFAC3F-8459-419F-8E48-1F0B49CDB85E}
Microsoft-Windows-RPC                    {6AD52B32-D609-4BE9-AE07-CE8DAE937E39}
Microsoft-Windows-RPC-Events             {F4AED7C7-A898-4627-B053-44A7CAA12FCD}
Microsoft-Windows-Schannel-Events        {91CC1150-71AA-47E2-AE18-C96E61736B6F}
Microsoft-Windows-Shell-Core             {30336ED4-E327-447C-9DE0-51B652C86108}
Microsoft-Windows-URLMon                 {245F975D-909D-49ED-B8F9-9A75691D6B6B}
Microsoft-Windows-User Profiles General  {DB00DFB6-29F9-4A9C-9B3B-1F4F9E7D9770}
Microsoft-Windows-User-Diagnostic        {305FC87B-002A-5E26-D297-60223012CA9C}
Microsoft-Windows-WebIO                  {50B3E73C-9370-461D-BB9F-26F32D68887D}
Microsoft-Windows-Windows Defender       {11CD958A-C507-4EF3-B3F2-5FD9DFBD2C78}
Microsoft-Windows-WinHttp                {7D44233D-3055-4B9C-BA64-0D47CA40A232}
Microsoft-Windows-WinRT-Error            {A86F8471-C31D-4FBC-A035-665D06047B03}
Microsoft-Windows-Winsock-NameResolution {55404E71-4DB9-4DEB-A5F5-8F86E46DDE56}
Network Profile Manager                  {D9131565-E1DD-4C9E-A728-951999C2ADB5}
Security: SChannel                       {37D2C3CD-C5D4-4587-8531-4696C44244C8}
Windows Defender Firewall API            {28C9F48F-D244-45A8-842F-DC9FBC9B6E92}
WMI_Tracing                              {1FF6B227-2CA7-40F9-9A66-980EADAA602E}
WMI_Tracing_Client_Operations            {8E6B6962-AB54-4335-8229-3255B919DD0E}
{05F95EFE-7F75-49C7-A994-60A55CC09571}   {05F95EFE-7F75-49C7-A994-60A55CC09571}
{072665FB-8953-5A85-931D-D06AEAB3D109}   {072665FB-8953-5A85-931D-D06AEAB3D109}
{7AF898D7-7E0E-518D-5F96-B1E79239484C}   {7AF898D7-7E0E-518D-5F96-B1E79239484C}
... output truncated ...
```



# 代码示例

## NT Kernel Logger的开启与事件获取（TdhFormatProperty）

```c++
#define INITGUID  // Include this #define to use SystemTraceControlGuid in Evntrace.h.

#include <windows.h>
#include <stdio.h>
#include <conio.h>
#include <strsafe.h>
#include <wmistr.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <in6addr.h>

#pragma comment(lib, "tdh.lib")

TRACEHANDLE g_SessionHandle = 0;
EVENT_TRACE_PROPERTIES* g_pSessionProperties = NULL;
EVENT_TRACE_LOGFILE g_TraceLogFile = { 0 };
TRACEHANDLE g_TraceHandle = 0;

void WINAPI ProcessEvent(PEVENT_RECORD pEvent);
DWORD GetEventInformation(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO & pInfo);
PBYTE PrintProperties(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, DWORD PointerSize, USHORT i, PBYTE pUserData, PBYTE pEndOfUserData);
DWORD GetPropertyLength(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, PUSHORT PropertyLength);
DWORD GetArraySize(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, PUSHORT ArraySize);
DWORD GetMapInfo(PEVENT_RECORD pEvent, LPWSTR pMapName, DWORD DecodingSource, PEVENT_MAP_INFO & pMapInfo);
void RemoveTrailingSpace(PEVENT_MAP_INFO pMapInfo);

PBYTE PrintProperties(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, DWORD PointerSize, USHORT i, PBYTE pUserData, PBYTE pEndOfUserData)
{
    TDHSTATUS status = ERROR_SUCCESS;
    USHORT PropertyLength = 0;
    DWORD FormattedDataSize = 0;
    USHORT UserDataConsumed = 0;
    USHORT UserDataLength = 0;
    LPWSTR pFormattedData = NULL;
    DWORD LastMember = 0;  // Last member of a structure
    USHORT ArraySize = 0;
    PEVENT_MAP_INFO pMapInfo = NULL;


    // Get the length of the property.

    status = GetPropertyLength(pEvent, pInfo, i, &PropertyLength);
    if (ERROR_SUCCESS != status)
    {
        printf("[%s] GetPropertyLength failed with %lu\n", __FUNCTION__, status);
        pUserData = NULL;
        goto cleanup;
    }

    // Get the size of the array if the property is an array.

    status = GetArraySize(pEvent, pInfo, i, &ArraySize);

    for (USHORT k = 0; k < ArraySize; k++)
    {
        // If the property is a structure, print the members of the structure.

        if ((pInfo->EventPropertyInfoArray[i].Flags & PropertyStruct) == PropertyStruct)
        {
            LastMember = pInfo->EventPropertyInfoArray[i].structType.StructStartIndex +
                pInfo->EventPropertyInfoArray[i].structType.NumOfStructMembers;

            for (USHORT j = pInfo->EventPropertyInfoArray[i].structType.StructStartIndex; j < LastMember; j++)
            {
                pUserData = PrintProperties(pEvent, pInfo, PointerSize, j, pUserData, pEndOfUserData);
                if (NULL == pUserData)
                {
                    printf("[%s] Printing the members of the structure failed.\n", __FUNCTION__);
                    pUserData = NULL;
                    goto cleanup;
                }
            }
        }
        else
        {
            // Get the name/value mapping if the property specifies a value map.

            status = GetMapInfo(pEvent,
                (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].nonStructType.MapNameOffset),
                pInfo->DecodingSource,
                pMapInfo);

            if (ERROR_SUCCESS != status)
            {
                printf("GetMapInfo failed\n");
                pUserData = NULL;
                goto cleanup;
            }

            // Get the size of the buffer required for the formatted data.

            status = TdhFormatProperty(
                pInfo,
                pMapInfo,
                PointerSize,
                pInfo->EventPropertyInfoArray[i].nonStructType.InType,
                pInfo->EventPropertyInfoArray[i].nonStructType.OutType,
                PropertyLength,
                (USHORT)(pEndOfUserData - pUserData),
                pUserData,
                &FormattedDataSize,
                pFormattedData,
                &UserDataConsumed);

            if (ERROR_INSUFFICIENT_BUFFER == status)
            {
                if (pFormattedData)
                {
                    free(pFormattedData);
                    pFormattedData = NULL;
                }

                pFormattedData = (LPWSTR)malloc(FormattedDataSize);
                if (pFormattedData == NULL)
                {
                    printf("[%s] Failed to allocate memory for formatted data (size=%lu).\n", __FUNCTION__, FormattedDataSize);
                    status = ERROR_OUTOFMEMORY;
                    pUserData = NULL;
                    goto cleanup;
                }

                // Retrieve the formatted data.

                status = TdhFormatProperty(
                    pInfo,
                    pMapInfo,
                    PointerSize,
                    pInfo->EventPropertyInfoArray[i].nonStructType.InType,
                    pInfo->EventPropertyInfoArray[i].nonStructType.OutType,
                    PropertyLength,
                    (USHORT)(pEndOfUserData - pUserData),
                    pUserData,
                    &FormattedDataSize,
                    pFormattedData,
                    &UserDataConsumed);
            }

            if (ERROR_SUCCESS == status)
            {
                printf("%ws: %ws\n",
                    (PWCHAR)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[i].NameOffset),
                    pFormattedData);

                pUserData += UserDataConsumed;
            }
            else
            {
                printf("[%s] TdhFormatProperty failed with %lu.\n", __FUNCTION__, status);
                pUserData = NULL;
                goto cleanup;
            }
        }
    }

cleanup:

    if (pFormattedData)
    {
        free(pFormattedData);
        pFormattedData = NULL;
    }

    if (pMapInfo)
    {
        free(pMapInfo);
        pMapInfo = NULL;
    }

    return pUserData;
}


// Get the length of the property data. For MOF-based events, the size is inferred from the data type
// of the property. For manifest-based events, the property can specify the size of the property value
// using the length attribute. The length attribue can specify the size directly or specify the name 
// of another property in the event data that contains the size. If the property does not include the 
// length attribute, the size is inferred from the data type. The length will be zero for variable
// length, null-terminated strings and structures.

DWORD GetPropertyLength(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, PUSHORT PropertyLength)
{
    DWORD status = ERROR_SUCCESS;
    PROPERTY_DATA_DESCRIPTOR DataDescriptor;
    DWORD PropertySize = 0;

    // If the property is a binary blob and is defined in a manifest, the property can 
    // specify the blob's size or it can point to another property that defines the 
    // blob's size. The PropertyParamLength flag tells you where the blob's size is defined.

    if ((pInfo->EventPropertyInfoArray[i].Flags & PropertyParamLength) == PropertyParamLength)
    {
        DWORD Length = 0;  // Expects the length to be defined by a UINT16 or UINT32
        DWORD j = pInfo->EventPropertyInfoArray[i].lengthPropertyIndex;
        ZeroMemory(&DataDescriptor, sizeof(PROPERTY_DATA_DESCRIPTOR));
        DataDescriptor.PropertyName = (ULONGLONG)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[j].NameOffset);
        DataDescriptor.ArrayIndex = ULONG_MAX;
        status = TdhGetPropertySize(pEvent, 0, NULL, 1, &DataDescriptor, &PropertySize);
        status = TdhGetProperty(pEvent, 0, NULL, 1, &DataDescriptor, PropertySize, (PBYTE)&Length);
        *PropertyLength = (USHORT)Length;
    }
    else
    {
        if (pInfo->EventPropertyInfoArray[i].length > 0)
        {
            *PropertyLength = pInfo->EventPropertyInfoArray[i].length;
        }
        else
        {
            // If the property is a binary blob and is defined in a MOF class, the extension
            // qualifier is used to determine the size of the blob. However, if the extension 
            // is IPAddrV6, you must set the PropertyLength variable yourself because the 
            // EVENT_PROPERTY_INFO.length field will be zero.

            if (TDH_INTYPE_BINARY == pInfo->EventPropertyInfoArray[i].nonStructType.InType &&
                TDH_OUTTYPE_IPV6 == pInfo->EventPropertyInfoArray[i].nonStructType.OutType)
            {
                *PropertyLength = (USHORT)sizeof(IN6_ADDR);
            }
            else if (TDH_INTYPE_UNICODESTRING == pInfo->EventPropertyInfoArray[i].nonStructType.InType ||
                TDH_INTYPE_ANSISTRING == pInfo->EventPropertyInfoArray[i].nonStructType.InType ||
                (pInfo->EventPropertyInfoArray[i].Flags & PropertyStruct) == PropertyStruct)
            {
                *PropertyLength = pInfo->EventPropertyInfoArray[i].length;
            }
            else
            {
                *PropertyLength = pInfo->EventPropertyInfoArray[i].length;
                printf("[%s] Unexpected length of 0 for intype %d and outtype %d\n",
                    __FUNCTION__,
                    pInfo->EventPropertyInfoArray[i].nonStructType.InType,
                    pInfo->EventPropertyInfoArray[i].nonStructType.OutType);

                //status = ERROR_EVT_INVALID_EVENT_DATA;
                //goto cleanup;
            }
        }
    }

cleanup:

    return status;
}


// Get the size of the array. For MOF-based events, the size is specified in the declaration or using 
// the MAX qualifier. For manifest-based events, the property can specify the size of the array
// using the count attribute. The count attribue can specify the size directly or specify the name 
// of another property in the event data that contains the size.

DWORD GetArraySize(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, PUSHORT ArraySize)
{
    DWORD status = ERROR_SUCCESS;
    PROPERTY_DATA_DESCRIPTOR DataDescriptor;
    DWORD PropertySize = 0;

    if ((pInfo->EventPropertyInfoArray[i].Flags & PropertyParamCount) == PropertyParamCount)
    {
        DWORD Count = 0;  // Expects the count to be defined by a UINT16 or UINT32
        DWORD j = pInfo->EventPropertyInfoArray[i].countPropertyIndex;
        ZeroMemory(&DataDescriptor, sizeof(PROPERTY_DATA_DESCRIPTOR));
        DataDescriptor.PropertyName = (ULONGLONG)((PBYTE)(pInfo)+pInfo->EventPropertyInfoArray[j].NameOffset);
        DataDescriptor.ArrayIndex = ULONG_MAX;
        status = TdhGetPropertySize(pEvent, 0, NULL, 1, &DataDescriptor, &PropertySize);
        status = TdhGetProperty(pEvent, 0, NULL, 1, &DataDescriptor, PropertySize, (PBYTE)&Count);
        *ArraySize = (USHORT)Count;
    }
    else
    {
        *ArraySize = pInfo->EventPropertyInfoArray[i].count;
    }

    return status;
}


// Both MOF-based events and manifest-based events can specify name/value maps. The
// map values can be integer values or bit values. If the property specifies a value
// map, get the map.

DWORD GetMapInfo(PEVENT_RECORD pEvent, LPWSTR pMapName, DWORD DecodingSource, PEVENT_MAP_INFO & pMapInfo)
{
    DWORD status = ERROR_SUCCESS;
    DWORD MapSize = 0;

    // Retrieve the required buffer size for the map info.

    status = TdhGetEventMapInformation(pEvent, pMapName, pMapInfo, &MapSize);

    if (ERROR_INSUFFICIENT_BUFFER == status)
    {
        pMapInfo = (PEVENT_MAP_INFO)malloc(MapSize);
        if (pMapInfo == NULL)
        {
            printf("Failed to allocate memory for map info (size=%lu).\n", MapSize);
            status = ERROR_OUTOFMEMORY;
            goto cleanup;
        }

        // Retrieve the map info.

        status = TdhGetEventMapInformation(pEvent, pMapName, pMapInfo, &MapSize);
    }

    if (ERROR_SUCCESS == status)
    {
        if (DecodingSourceXMLFile == DecodingSource)
        {
            RemoveTrailingSpace(pMapInfo);
        }
    }
    else
    {
        if (ERROR_NOT_FOUND == status)
        {
            status = ERROR_SUCCESS; // This case is okay.
        }
        else
        {
            printf("TdhGetEventMapInformation failed with 0x%x.\n", status);
        }
    }

cleanup:

    return status;
}


// The mapped string values defined in a manifest will contain a trailing space
// in the EVENT_MAP_ENTRY structure. Replace the trailing space with a null-
// terminating character, so that the bit mapped strings are correctly formatted.

void RemoveTrailingSpace(PEVENT_MAP_INFO pMapInfo)
{
    DWORD ByteLength = 0;

    for (DWORD i = 0; i < pMapInfo->EntryCount; i++)
    {
        ByteLength = (wcslen((LPWSTR)((PBYTE)pMapInfo + pMapInfo->MapEntryArray[i].OutputOffset)) - 1) * 2;
        *((LPWSTR)((PBYTE)pMapInfo + (pMapInfo->MapEntryArray[i].OutputOffset + ByteLength))) = L'\0';
    }
}


// Get the metadata for the event.

DWORD GetEventInformation(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO & pInfo)
{
    DWORD status = ERROR_SUCCESS;
    DWORD BufferSize = 0;

    // Retrieve the required buffer size for the event metadata.

    status = TdhGetEventInformation(pEvent, 0, NULL, pInfo, &BufferSize);

    if (ERROR_INSUFFICIENT_BUFFER == status)
    {
        pInfo = (TRACE_EVENT_INFO*)malloc(BufferSize);
        if (pInfo == NULL)
        {
            printf("Failed to allocate memory for event info (size=%lu).\n", BufferSize);
            status = ERROR_OUTOFMEMORY;
            goto cleanup;
        }

        // Retrieve the event metadata.

        status = TdhGetEventInformation(pEvent, 0, NULL, pInfo, &BufferSize);
    }

    if (ERROR_SUCCESS != status)
    {
        printf("TdhGetEventInformation failed with 0x%x.\n", status);
    }

cleanup:

    return status;
}

BOOL WINAPI BufferCallback(
    PEVENT_TRACE_LOGFILEA Logfile
)
{
    printf("[%s] In BufferCallback\n", __FUNCTION__);

    return TRUE;
}

void WINAPI RecordCallback(
    PEVENT_RECORD EventRecord
)
{
    DWORD status = ERROR_SUCCESS;
    PTRACE_EVENT_INFO pInfo = NULL;
    LPWSTR pwsEventGuid = NULL;
    PBYTE pUserData = NULL;
    PBYTE pEndOfUserData = NULL;
    DWORD PointerSize = 0;
    ULONGLONG TimeStamp = 0;
    ULONGLONG Nanoseconds = 0;
    SYSTEMTIME st;
    SYSTEMTIME stLocal;
    FILETIME ft;


    // Skips the event if it is the event trace header. Log files contain this event
    // but real-time sessions do not. The event contains the same information as 
    // the EVENT_TRACE_LOGFILE.LogfileHeader member that you can access when you open 
    // the trace. 

    if (IsEqualGUID(EventRecord->EventHeader.ProviderId, EventTraceGuid) &&
        EventRecord->EventHeader.EventDescriptor.Opcode == EVENT_TRACE_TYPE_INFO)
    {
        ; // Skip this event.
    }
    else
    {
        // Process the event. The pEvent->UserData member is a pointer to 
        // the event specific data, if it exists.

        status = GetEventInformation(EventRecord, pInfo);

        if (ERROR_SUCCESS != status)
        {
            printf("[%s] GetEventInformation failed with %lu\n", __FUNCTION__, status);
            goto cleanup;
        }

        // Determine whether the event is defined by a MOF class, in an
        // instrumentation manifest, or a WPP template; to use TDH to decode
        // the event, it must be defined by one of these three sources.

        printf("\nProcess Id: %d\n", EventRecord->EventHeader.ProcessId);
        if (DecodingSourceWbem == pInfo->DecodingSource)  // MOF class
        {
            HRESULT hr = StringFromCLSID(pInfo->EventGuid, &pwsEventGuid);

            if (FAILED(hr))
            {
                printf("StringFromCLSID failed with 0x%x\n", hr);
                status = hr;
                goto cleanup;
            }

            printf("Event GUID: %ws\n", pwsEventGuid);
            CoTaskMemFree(pwsEventGuid);
            pwsEventGuid = NULL;

            printf("Event version: %d\n", EventRecord->EventHeader.EventDescriptor.Version);
            printf("Event type: %d\n", EventRecord->EventHeader.EventDescriptor.Opcode);
        }
        else if (DecodingSourceXMLFile == pInfo->DecodingSource) // Instrumentation manifest
        {
            printf("Event ID: %d\n", pInfo->EventDescriptor.Id);
        }
        else // Not handling the WPP case
        {
            printf("Not handling the WPP case\n");
            goto cleanup;
        }

        // Print the time stamp for when the event occurred.

        ft.dwHighDateTime = EventRecord->EventHeader.TimeStamp.HighPart;
        ft.dwLowDateTime = EventRecord->EventHeader.TimeStamp.LowPart;

        FileTimeToSystemTime(&ft, &st);
        SystemTimeToTzSpecificLocalTime(NULL, &st, &stLocal);

        TimeStamp = EventRecord->EventHeader.TimeStamp.QuadPart;
        Nanoseconds = (TimeStamp % 10000000) * 100;

        printf("%02d/%02d/%02d %02d:%02d:%02d.%I64u\n",
            stLocal.wMonth, stLocal.wDay, stLocal.wYear, stLocal.wHour, stLocal.wMinute, stLocal.wSecond, Nanoseconds);

        // If the event contains event-specific data use TDH to extract
        // the event data. For this example, to extract the data, the event 
        // must be defined by a MOF class or an instrumentation manifest.

        // Need to get the PointerSize for each event to cover the case where you are
        // consuming events from multiple log files that could have been generated on 
        // different architectures. Otherwise, you could have accessed the pointer
        // size when you opened the trace above (see pHeader->PointerSize).

        if (EVENT_HEADER_FLAG_32_BIT_HEADER == (EventRecord->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER))
        {
            PointerSize = 4;
        }
        else
        {
            PointerSize = 8;
        }

        pUserData = (PBYTE)EventRecord->UserData;
        pEndOfUserData = (PBYTE)EventRecord->UserData + EventRecord->UserDataLength;

        // Print the event data for all the top-level properties. Metadata for all the 
        // top-level properties come before structure member properties in the 
        // property information array.

        for (USHORT i = 0; i < pInfo->TopLevelPropertyCount; i++)
        {
            pUserData = PrintProperties(EventRecord, pInfo, PointerSize, i, pUserData, pEndOfUserData);
            if (NULL == pUserData)
            {
                wprintf(L"Printing top level properties failed.\n");
                goto cleanup;
            }
        }
    }

cleanup:

    if (pInfo)
    {
        free(pInfo);
    }

    if (ERROR_SUCCESS != status || NULL == pUserData)
    {
        CloseTrace(g_TraceHandle);
    }
}

BOOL MyInitTrace()
{
    ULONG status = ERROR_SUCCESS;
    ULONG BufferSize = 0;

    // Allocate memory for the session properties. The memory must
    // be large enough to include the log file name and session name,
    // which get appended to the end of the session properties structure.

    BufferSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(KERNEL_LOGGER_NAME);
    g_pSessionProperties = (EVENT_TRACE_PROPERTIES*)malloc(BufferSize);
    if (NULL == g_pSessionProperties)
    {
        printf("[%s] Unable to allocate %d bytes for properties structure.\n", __FUNCTION__, BufferSize);
        goto cleanup;
    }

    // Set the session properties. You only append the log file name
    // to the properties structure; the StartTrace function appends
    // the session name for you.
starttrace:
    ZeroMemory(g_pSessionProperties, BufferSize);
    g_pSessionProperties->Wnode.BufferSize = BufferSize;
    g_pSessionProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    g_pSessionProperties->Wnode.ClientContext = 1; //QPC clock resolution
    g_pSessionProperties->Wnode.Guid = SystemTraceControlGuid;
    g_pSessionProperties->EnableFlags = EVENT_TRACE_FLAG_PROCESS;
    g_pSessionProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    g_pSessionProperties->FlushTimer = 1;
    g_pSessionProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    // Create the trace session.

    status = StartTrace((PTRACEHANDLE)&g_SessionHandle, KERNEL_LOGGER_NAME, g_pSessionProperties);

    if (ERROR_SUCCESS != status)
    {
        if (ERROR_ALREADY_EXISTS == status)
        {
            printf("[%s] The NT Kernel Logger session is already in use.\n", __FUNCTION__);

            status = ControlTrace(NULL, KERNEL_LOGGER_NAME, g_pSessionProperties, EVENT_TRACE_CONTROL_UPDATE);
            if (ERROR_SUCCESS != status)
            {
                printf("[%s] ControlTrace(update) failed with %lu\n", __FUNCTION__, status);
            }
        }
        else
        {
            printf("[%s] StartTrace() failed with %lu\n", __FUNCTION__, status);
            goto cleanup;
        }
    }

    status = EnableTraceEx2(g_SessionHandle, &SystemTraceControlGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE, 0, 0, 0, NULL);

    if (ERROR_SUCCESS != status)
    {
        printf("[%s] EnableTraceEx2() failed with %lu\n", __FUNCTION__, status);
    }

opentrace:
    g_TraceLogFile.LoggerName = KERNEL_LOGGER_NAME;
    g_TraceLogFile.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME;
    g_TraceLogFile.BufferCallback = (PEVENT_TRACE_BUFFER_CALLBACK)BufferCallback;
    g_TraceLogFile.EventRecordCallback = (PEVENT_RECORD_CALLBACK)RecordCallback;

    g_TraceHandle = OpenTrace(&g_TraceLogFile);
    if (INVALID_PROCESSTRACE_HANDLE == g_TraceHandle)
    {
        printf("[%s] OpenTrace() failed with %lu\n", __FUNCTION__, GetLastError());
        goto cleanup;
    }


    return TRUE;



cleanup:

    if (g_TraceHandle && INVALID_PROCESSTRACE_HANDLE != g_TraceHandle)
    {
        status = CloseTrace(g_TraceHandle);

        if (ERROR_SUCCESS != status)
        {
            printf("[%s] CloseTrace() failed with %lu\n", __FUNCTION__, status);
        }
    }

    if (g_SessionHandle)
    {
        status = EnableTraceEx2(g_SessionHandle, &SystemTraceControlGuid, EVENT_CONTROL_CODE_DISABLE_PROVIDER, TRACE_LEVEL_VERBOSE, 0, 0, 0, NULL);

        if (ERROR_SUCCESS != status)
        {
            printf("[%s] EnableTraceEx2(disable) failed with %lu\n", __FUNCTION__, status);
        }

        status = ControlTrace(g_SessionHandle, KERNEL_LOGGER_NAME, g_pSessionProperties, EVENT_TRACE_CONTROL_STOP);

        if (ERROR_SUCCESS != status)
        {
            printf("[%s] ControlTrace(stop) failed with %lu\n", __FUNCTION__, status);
        }
    }

    if (g_pSessionProperties)
        free(g_pSessionProperties);

    return FALSE;
}

DWORD MyStratTrace(LPVOID lpParam)
{
    ULONG status = ERROR_SUCCESS;

    status = ProcessTrace(&g_TraceHandle, 1, 0, 0);

    if (ERROR_SUCCESS != status)
    {
        printf("[%s] ProcessTrace() failed with %lu\n", __FUNCTION__, status);
    }
    else
    {
        printf("[%s] ProcessTrace() return\n", __FUNCTION__);
    }

    return ERROR_SUCCESS;
}

VOID MyStopTrace()
{
    ULONG status = ERROR_SUCCESS;

    if (g_TraceHandle && INVALID_PROCESSTRACE_HANDLE != g_TraceHandle)
    {
        status = CloseTrace(g_TraceHandle);

        if (ERROR_SUCCESS != status)
        {
            printf("[%s] CloseTrace() failed with %lu\n", __FUNCTION__, status);
        }
    }

    if (g_SessionHandle)
    {
        status = EnableTraceEx2(g_SessionHandle, &SystemTraceControlGuid, EVENT_CONTROL_CODE_DISABLE_PROVIDER, TRACE_LEVEL_VERBOSE, 0, 0, 0, NULL);

        if (ERROR_SUCCESS != status)
        {
            printf("[%s] EnableTraceEx2(disable) failed with %lu\n", __FUNCTION__, status);
        }

        status = ControlTrace(g_SessionHandle, KERNEL_LOGGER_NAME, g_pSessionProperties, EVENT_TRACE_CONTROL_STOP);

        if (ERROR_SUCCESS != status)
        {
            printf("[%s] ControlTrace(stop) failed with %lu\n", __FUNCTION__, status);
        }
    }

    if (g_pSessionProperties)
        free(g_pSessionProperties);
}

int main(void)
{
    HANDLE hThread;

    if (!MyInitTrace())
    {
        return 0;
    }

    hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MyStratTrace, NULL, 0, NULL);
    if (!hThread)
    {
        printf("[%s] CreateThread() failed with %lu\n", __FUNCTION__, GetLastError());
        return 0;
    }

    printf("Press any key to end trace session\n");
    _getch();

    MyStopTrace();
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    return 0;
}
```

