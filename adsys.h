//
//  This defines what we want to filter with FltMgr
//
#include "S_File.h"
#include "S_Common.h"
#include "S_Ctx.h"
#include "dll32.h"
#include "dll64.h"
#include "memload.h"
#include <ntimage.h>


#define BUFFER_SWAP_TAG                   'bdBS'
#define CONTEXT_TAG                       'xcBS'
#define NAME_TAG                          'mnBS'
#define PRE_2_POST_TAG                    'ppBS'
#define STREAM_CONTEXT_TAG                'cSxC'
#define STRING_TAG                        'tSxC'
#define RESOURCE_TAG                      'cRxC'
#define FILEFLAG_POOL_TAG 'FASV'
#define MIN_SECTOR_SIZE 0x200


#define kprintf     DbgPrint
#define kmalloc(_s) ExAllocatePoolWithTag(NonPagedPool, _s, 'SYSQ')
#define kfree(_p)   ExFreePool(_p)


typedef struct _RTL_USER_PROCESS_PARAMETERS32 {
    ULONG MaximumLength;
    ULONG Length;
    ULONG Flags;
    ULONG DebugFlags;
    ULONG ConsoleHandle;
    ULONG ConsoleFlags;
    ULONG StandardInput;
    ULONG StandardOutput;
    ULONG StandardError;
    UCHAR  CURDIR[0xc];
    UNICODE_STRING32 DllPath;
    UNICODE_STRING32 ImagePathName;     //进程完整路径
    UNICODE_STRING32 CommandLine;
} RTL_USER_PROCESS_PARAMETERS32, *PRTL_USER_PROCESS_PARAMETERS32;


typedef struct _RTL_USER_PROCESS_PARAMETERS64 {
    ULONG MaximumLength;
    ULONG Length;
    ULONG Flags;
    ULONG DebugFlags;
    ULONG64 ConsoleHandle;
    ULONG64 ConsoleFlags;
    ULONG64 StandardInput;
    ULONG64 StandardOutput;
    ULONG64 StandardError;
    UCHAR  CURDIR[0x14];
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;     //进程完整路径
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS64, *PRTL_USER_PROCESS_PARAMETERS64;

typedef struct _PEB32 { // Size: 0x1D8
    UCHAR InheritedAddressSpace;
    UCHAR ReadImageFileExecOptions;
    UCHAR BeingDebugged;
    UCHAR SpareBool;
    HANDLE Mutant;
    ULONG ImageBaseAddress;
    ULONG DllList;
    ULONG ProcessParameters;    //进程参数块
} PEB32, *PPEB32;

typedef struct _PEB64 { // Size: 0x1D8
    UCHAR InheritedAddressSpace;
    UCHAR ReadImageFileExecOptions;
    UCHAR BeingDebugged;
    UCHAR SpareBool[5];
    ULONG64 Mutant;
    ULONG64 ImageBaseAddress;
    ULONG64 DllList;
    ULONG64 ProcessParameters;    //进程参数块
} PEB64, *PPEB64;




typedef struct _VOLUME_CONTEXT {
    UNICODE_STRING Name;
    ULONG SectorSize;
} VOLUME_CONTEXT, *PVOLUME_CONTEXT;



typedef PPEB(__stdcall *P_PsGetProcessWow64Process)(PEPROCESS);
P_PsGetProcessWow64Process PsGetProcessWow64Process = NULL;
typedef PPEB(__stdcall *P_PsGetProcessPeb)(PEPROCESS);
P_PsGetProcessPeb     PsGetProcessPeb = NULL;

DWORD_PTR GetSystemRoutineAddress(WCHAR *szFunCtionAName);


BOOLEAN GetNameByUnicodeString(PUNICODE_STRING pSrc, WCHAR name[]);

NTSTATUS DriverEntry (__in PDRIVER_OBJECT DriverObject,__in PUNICODE_STRING RegistryPath);

NTSTATUS FilterUnload ( __in FLT_FILTER_UNLOAD_FLAGS Flags);

BOOLEAN GetProcessNameByObj(PEPROCESS ProcessObj, WCHAR name[]);

VOID CleanVolumCtx(IN PFLT_CONTEXT Context,IN FLT_CONTEXT_TYPE ContextType);


NTSTATUS
InstanceSetup (
    IN PCFLT_RELATED_OBJECTS FltObjects,
    IN FLT_INSTANCE_SETUP_FLAGS Flags,
    IN DEVICE_TYPE VolumeDeviceType,
    IN FLT_FILESYSTEM_TYPE VolumeFilesystemType
);
NTSTATUS
InstanceQueryTeardown (
    IN PCFLT_RELATED_OBJECTS FltObjects,
    IN FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
);


CONST FLT_CONTEXT_REGISTRATION ContextNotifications[] = {

    { FLT_VOLUME_CONTEXT,0,CleanVolumCtx,sizeof(VOLUME_CONTEXT),CONTEXT_TAG },
    { FLT_STREAM_CONTEXT,0,CleanVolumCtx, STREAM_CONTEXT_SIZE,    STREAM_CONTEXT_TAG },
    { FLT_CONTEXT_END }
};

FLT_PREOP_CALLBACK_STATUS
PreCleanup(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
);
FLT_PREOP_CALLBACK_STATUS
PreClose(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
);

FLT_PREOP_CALLBACK_STATUS
PreCreate(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
);


FLT_POSTOP_CALLBACK_STATUS
PostCreate(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __inout_opt PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
);


FLT_POSTOP_CALLBACK_STATUS
PostRead(
    IN OUT PFLT_CALLBACK_DATA Data,
    IN PCFLT_RELATED_OBJECTS FltObjects,
    IN PVOID CompletionContext,
    IN FLT_POST_OPERATION_FLAGS Flags
);
FLT_PREOP_CALLBACK_STATUS
PreRead(
    IN OUT PFLT_CALLBACK_DATA Data,
    IN PCFLT_RELATED_OBJECTS FltObjects,
    OUT PVOID *CompletionContext
);


FLT_POSTOP_CALLBACK_STATUS
PostReadWhenSafe (
    IN OUT PFLT_CALLBACK_DATA Data,
    IN PCFLT_RELATED_OBJECTS FltObjects,
    IN PVOID CompletionContext,
    IN FLT_POST_OPERATION_FLAGS Flags
);



typedef struct _PRE_2_POST_CONTEXT {
    PVOLUME_CONTEXT VolCtx;
    PSTREAM_CONTEXT pStreamCtx ;
    PVOID SwappedBuffer;
    PMDL  pMdl;
} PRE_2_POST_CONTEXT, *PPRE_2_POST_CONTEXT;


NPAGED_LOOKASIDE_LIST Pre2PostContextList;



CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE,  FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO, PreCreate, PostCreate},
    { IRP_MJ_READ, 0,PreRead,PostRead },
    { IRP_MJ_CLEANUP, FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO, PreCleanup,  NULL },
    { IRP_MJ_CLOSE,   0, PreClose,NULL },
    { IRP_MJ_OPERATION_END }
};


CONST FLT_REGISTRATION FilterRegistration = {

    sizeof( FLT_REGISTRATION ),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags
    ContextNotifications,               //  Context
    Callbacks,                          //  Operation callbacks
    FilterUnload,                       //  MiniFilterUnload
    InstanceSetup,                      //  InstanceSetup
    InstanceQueryTeardown,              //  InstanceQueryTeardown
    NULL,                               //  InstanceTeardownStart
    NULL,                               //  InstanceTeardownComplete

    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent

};

PFLT_FILTER gFilterHandle;










// 注册表回调Cookie
LARGE_INTEGER g_liRegCookie;
NTSTATUS SetRegisterCallback();


NTSTATUS RegisterMonCallback(
    PVOID CallbackContext,
    // 操作类型（只是操作编号，不是指针）
    PVOID Argument1,
    // 操作详细信息的结构体指针
    PVOID Argument2
) ;


VOID DriverUnload(IN PDRIVER_OBJECT pDriverObj);
VOID RemoveRegisterCallback() ;

//模块注入部分


#pragma pack()
typedef struct _INITIAL_TEB {
    struct {
        PVOID OldStackBase;
        PVOID OldStackLimit;
    } OldInitialTeb;
    PVOID StackBase;
    PVOID StackLimit;
    PVOID StackAllocationBase;
} INITIAL_TEB, *PINITIAL_TEB;

typedef NTSTATUS(*TYPE_NtCreateThread)(PHANDLE  ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES  ObjectAttributes,
                                       HANDLE ProcessHandle, PCLIENT_ID ClientId, PCONTEXT ThreadContext, PINITIAL_TEB InitialTeb, BOOLEAN  CreateSuspended);
TYPE_NtCreateThread ZwCreateThread;
TYPE_NtCreateThread NtCreateThread;




typedef NTSTATUS(__stdcall *TYPE_NtCreateThreadEx)(PHANDLE hThread, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID lpStartAddress,
        PVOID lpParameter, ULONG Flags, SIZE_T StackZeroBits, SIZE_T SizeOfStackCommit, SIZE_T SizeOfStackReserve, PVOID lpBytesBuffer);

TYPE_NtCreateThreadEx NtCreateThreadEx = NULL;
TYPE_NtCreateThreadEx ZwCreateThreadEx = NULL;
PVOID       m_pCreateThread;


typedef NTSTATUS(__stdcall *TYPE_ZwWriteVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG BufferLength, PULONG ReturnLength OPTIONAL);

TYPE_ZwWriteVirtualMemory NtWriteVirtualMemory = NULL;
TYPE_ZwWriteVirtualMemory ZwWriteVirtualMemory = NULL;





#define   HOOKADDR     "ZwCreateFile"
PVOID     fnHookfunc = NULL;
ULONG    g_mode = 0;


NTSTATUS BBSearchPattern(IN PUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound);
NTSTATUS NTAPI NewNtWriteVirtualMemory(IN HANDLE ProcessHandle, IN PVOID BaseAddress, IN PVOID Buffer,
                                       IN ULONG BufferLength, OUT PULONG ReturnLength OPTIONAL);
NTSTATUS NTAPI NewNtCreateThreadEx(PHANDLE hThread, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle,
                                   PVOID lpStartAddress, PVOID lpParameter, ULONG Flags, SIZE_T StackZeroBits, SIZE_T SizeOfStackCommit,
                                   SIZE_T SizeOfStackReserve, PVOID lpBytesBuffer);

typedef NTSTATUS(__stdcall *TYPE_ZwProtectVirtualMemory)(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize,
        ULONG NewProtect, PULONG OldProtect);
TYPE_ZwProtectVirtualMemory NtProtectVirtualMemory = NULL;
TYPE_ZwProtectVirtualMemory ZwProtectVirtualMemory = NULL;

NTSTATUS MyZwCreateThread(HANDLE ProcessHandle, PVOID  ThreadStartAddress, PVOID   ThreadParameter, PSIZE_T ThreadStackSize,
                          PVOID *ThreadStackAddress, HANDLE *ThreadHandle, PEPROCESS processObj);
NTSTATUS NTAPI NewNtProtectVirtualMemory(IN HANDLE ProcessHandle, IN PVOID* BaseAddress, IN SIZE_T* NumberOfBytesToProtect,
        IN ULONG NewAccessProtection, OUT PULONG OldAccessProtection);

BOOLEAN IsX64Module(IN PVOID pBase);
PVOID GetProcAddress(IN PVOID pBase, IN PCCHAR name_ord);

VOID ImageNotify(PUNICODE_STRING       FullImageName, HANDLE ProcessId, PIMAGE_INFO  ImageInfo);


#pragma pack(1)
typedef struct ServiceDescriptorEntry
{
  unsigned int *ServiceTableBase;
  unsigned int *ServiceCounterTableBase;
  unsigned int NumberOfService;
  unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;

typedef struct _SERVICE_DESCRIPTOR_TABLE
{
  ServiceDescriptorTableEntry_t   ntoskrnl; // ntoskrnl.exe
  ServiceDescriptorTableEntry_t   win32k;   // win32k.sys
  ServiceDescriptorTableEntry_t   NotUsed1;
  ServiceDescriptorTableEntry_t   NotUsed2;
} SYSTEM_DESCRIPTOR_TABLE, *PSYSTEM_DESCRIPTOR_TABLE;

void InjectDll(PEPROCESS ProcessObj, int ibit);


#ifdef _AMD64_
PServiceDescriptorTableEntry_t  KeServiceDescriptorTable;
#else
__declspec(dllimport) ServiceDescriptorTableEntry_t    KeServiceDescriptorTable;
#endif


#define   SERVICE_ID64(_function)     (*(PULONG)((PUCHAR)_function + 4))  //64位进程
#define   SERVICE_ID32(_function)     (*(PULONG)((PUCHAR)_function + 1))  //32位进程


#define SERVICE_FUNCTION(_function)   \
  ((ULONG)(KeServiceDescriptorTable.ServiceTableBase) + 4*SERVICE_ID32(_function))

ULONGLONG GetKeServiceDescriptorTable64();

typedef struct _PARAMX
{
  ULONG64 lpFileData;
  ULONG64 DataLength;
  ULONG64 LdrGetProcedureAddress;
  ULONG64 dwNtAllocateVirtualMemory;
  ULONG64 dwLdrLoadDll;
  ULONG64 RtlInitAnsiString;
  ULONG64 RtlAnsiStringToUnicodeString;
  ULONG64 RtlFreeUnicodeString;

  UCHAR oldcode[20];
  //unsigned char code1[14] = {0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x40, 0x18, 0xC3};
  UCHAR pFunction[100];
}PARAMX,*PPARAMX;

ULONG_PTR GetSSDTFuncCurAddr(LONG id);

typedef struct _MY_PROCESS_INFO{
	LIST_ENTRY Entry;
	WCHAR    exename[216];
}MY_PROCESS_INFO, *PMY_PROCESS_INFO;
	
NTSTATUS AppendListNode(CONST WCHAR name[]);

LIST_ENTRY g_ListProcess;
BOOLEAN  IsByInjectProc(const WCHAR* name);
NTSTATUS MzReadFile(LPWCH pFile,PVOID* ImageBaseAddress,PULONG ImageSize);
ULONG 	 MzGetFileSize(HANDLE hfile);
PVOID      g_pDll64=NULL;
ULONG      g_iDll64=0;
PVOID      g_pDll32=NULL;
ULONG      g_iDll32=0;

void MyDecryptFile(PVOID pdata, int len);



typedef struct _WORKITEMPARAM 
{    
    ULONG pid;
    ULONG bit;
} WORKITEMPARAM, * PWORKITEMPARAM;
 
void  newWorkItem(ULONG bit);
VOID WorkerItemRoutine(PDEVICE_OBJECT  DeviceObject, PVOID  Context, PIO_WORKITEM IoWorkItem);
VOID IoUninitializeWorkItem( __in PIO_WORKITEM IoWorkItem);

PDRIVER_OBJECT  g_drobj;
void  InitGlobeFunc(PIMAGE_INFO     ImageInfo);
