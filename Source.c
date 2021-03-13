
//obCallback.h
#pragma once

#ifdef __cplusplus
extern "C"
{
#endif
#include <ntifs.h>

#ifdef __cplusplus
}
#endif 


#define arraysize(p) (sizeof(p)/sizeof((p)[0]))
#define PROCESS_TERMINATE         0x0001  
#define PROCESS_VM_OPERATION      0x0008  
#define PROCESS_VM_READ           0x0010  
#define PROCESS_VM_WRITE          0x0020 

typedef struct _DEVICE_EXTENSION {
	PDEVICE_OBJECT pDevice;
	UNICODE_STRING ustrDeviceName; //Device name
	UNICODE_STRING ustrSymLinkName; //symbolic link name
} DEVICE_EXTENSION, * PDEVICE_EXTENSION; //Device extension information structure


typedef struct _LDR_DATA_TABLE_ENTRY64
{
	LIST_ENTRY64    InLoadOrderLinks;
	LIST_ENTRY64    InMemoryOrderLinks;
	LIST_ENTRY64    InInitializationOrderLinks;
	PVOID            DllBase;
	PVOID            EntryPoint;
	ULONG            SizeOfImage;
	UNICODE_STRING    FullDllName;
	UNICODE_STRING     BaseDllName;
	ULONG            Flags;
	USHORT            LoadCount;
	USHORT            TlsIndex;
	PVOID            SectionPointer;
	ULONG            CheckSum;
	PVOID            LoadedImports;
	PVOID            EntryPointActivationContext;
	PVOID            PatchInformation;
	LIST_ENTRY64    ForwarderLinks;
	LIST_ENTRY64    ServiceTagLinks;
	LIST_ENTRY64    StaticLinks;
	PVOID            ContextInformation;
	ULONG64            OriginalBase;
	LARGE_INTEGER    LoadTime;
} LDR_DATA_TABLE_ENTRY64, * PLDR_DATA_TABLE_ENTRY64;


NTSTATUS CreateDevice(IN PDRIVER_OBJECT pDrvObj); //Create device routines
Void UnloadDriver(IN PDRIVER_OBJECT pDrvObj); //Drive unload function

NTSTATUS ProtectProcess(); / / process protection
OB_PREOP_CALLBACK_STATUS MyCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation); //callback function
Char* GetProcessNameByProcessID(HANDLE pid); // fetch the process name


//obCallback.cpp

#include "obCallback.h"

#ifdef __cplusplus
extern "C"
{
#endif
	UCHAR* PsGetProcessImageFileName(PEPROCESS EProcess);
#ifdef __cplusplus
}
#endif

BOOLEAN pre = FALSE;
extern "C" NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverOb, IN PUNICODE_STRING pRegistryPath)
{
	KdPrint(("Start loading driver"));
	NTSTATUS status = 0;
	pDriverOb->DriverUnload = UnloadDriver;

	status = CreateDevice(pDriverOb);
	KdPrint(("Drive Load Complete 1"));

	PLDR_DATA_TABLE_ENTRY64 ldrDataTable;
	ldrDataTable = (PLDR_DATA_TABLE_ENTRY64)pDriverOb->DriverSection;
	ldrDataTable->Flags |= 0x20; //Over MmVerifyCallbackFunction

	Status = ProtectProcess(); //Implement object callback
	if (NT_SUCCESS(status))
	{
		KdPrint(("Register callback function succeeded"));
		pre = TRUE;
	}
	else
		KdPrint(("registration callback function failed"));
	return status;
}



PVOID obHandle; / / store callback handle
NTSTATUS ProtectProcess()
{

	OB_CALLBACK_REGISTRATION obReg;
	OB_OPERATION_REGISTRATION opReg;

	memset(&obReg, 0, sizeof(obReg));
	obReg.Version = ObGetFilterVersion();
	obReg.OperationRegistrationCount = 1;
	obReg.RegistrationContext = NULL;
	RtlInitUnicodeString(&obReg.Altitude, L"321000");

	Memset(&opReg, 0, sizeof(opReg)); //Initialize structure variables

	opReg.ObjectType = PsProcessType;
	opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;

	opReg.PreOperation = (POB_PRE_OPERATION_CALLBACK)(&MyCallback); //Register callback function pointer

	obReg.OperationRegistration = &opReg; //Note this statement
	Return ObRegisterCallbacks(&obReg, &obHandle); //Register callback function
}

OB_PREOP_CALLBACK_STATUS MyCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation)
{
	HANDLE pid = PsGetProcessId((PEPROCESS)pOperationInformation->Object);
	char szProcName[16] = { 0 };
	UNREFERENCED_PARAMETER(RegistrationContext);
	strcpy(szProcName, GetProcessNameByProcessID(pid));

	if (!_stricmp(szProcName, "infANT.exe"))
	{
		if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
		{
			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_TERMINATE) == PROCESS_TERMINATE)
			{
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
			}
			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_OPERATION) == PROCESS_VM_OPERATION)
			{
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;
			}
			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_READ) == PROCESS_VM_READ)
			{
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;
			}
			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_WRITE) == PROCESS_VM_WRITE)
			{
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;
			}
		}
	}
	return OB_PREOP_SUCCESS;
}

char* GetProcessNameByProcessID(HANDLE pid)
{
	NTSTATUS status;
	PEPROCESS EProcess = NULL;
	status = PsLookupProcessByProcessId(pid, &EProcess);

	if (!NT_SUCCESS(status))
	{
		return FALSE;
	}
	ObDereferenceObject(EProcess);
	return (char*)PsGetProcessImageFileName(EProcess);
}



NTSTATUS CreateDevice(
	IN PDRIVER_OBJECT pDriverObject) //Initialize the device object Return to the initialization state
{
	NTSTATUS status;
	PDEVICE_OBJECT pDevObj;
	PDEVICE_EXTENSION pDevExt;

	/ / Create a device name
		UNICODE_STRING devName;
	RtlInitUnicodeString(&devName, L"\\Device\\ObCALL");

	/ / Create a device
		status = IoCreateDevice(pDriverObject,
			sizeof(DEVICE_EXTENSION),
			&(UNICODE_STRING)devName,
			FILE_DEVICE_UNKNOWN,
			0, TRUE,
			&pDevObj);
	if (!NT_SUCCESS(status))
		return status;

	pDevObj->Flags |= DO_BUFFERED_IO;
	pDevExt = (PDEVICE_EXTENSION)pDevObj->DeviceExtension;
	pDevExt->pDevice = pDevObj;
	pDevExt->ustrDeviceName = devName;
	/ / Create a symbolic link
		UNICODE_STRING symLinkName;
	RtlInitUnicodeString(&symLinkName, L"\\??\\Object");
	pDevExt->ustrSymLinkName = symLinkName;
	status = IoCreateSymbolicLink(&symLinkName, &devName);
	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(pDevObj);
		return status;
	}
	return STATUS_SUCCESS;
}


Void UnloadDriver(IN PDRIVER_OBJECT pDriverObject) //Uninstallation of the driver
{
	PDEVICE_OBJECT	pNextObj;
	KdPrint(("Enter DriverUnload\n"));
	If(pre) / / delete callback if the registration callback function is successful
		ObUnRegisterCallbacks(obHandle);
	KdPrint(("Deleted Callback"));
	pNextObj = pDriverObject->DeviceObject;
	while (pNextObj != NULL)
	{
		PDEVICE_EXTENSION pDevExt = (PDEVICE_EXTENSION)
			pNextObj->DeviceExtension;

		/ / Delete the symbolic link
			UNICODE_STRING pLinkName = pDevExt->ustrSymLinkName;
		IoDeleteSymbolicLink(&pLinkName);
		pNextObj = pNextObj->NextDevice;
		IoDeleteDevice(pDevExt->pDevice);
	}
	KdPrint(("Drive is uninstalled!"));
}