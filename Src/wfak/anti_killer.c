/****************************************************************
	Anti-Killer driver. Hooks OpenProcess 
****************************************************************/
#include <ntddk.h>
#include "wfak_io_codes.h"
//################################### CONST #########################################//
#define DEVICENAME L"\\Device\\wfak"
#define SYMLINK	   L"\\??\\wfak"
#define MAX_PIDS 32
#define W2K_BUILDNUMBER 2969 // 2195
#define WXP_BUILDNUMBER 2600

//################################### PROTO ##################################//
NTSTATUS IrpCreateCloseRoutine( PDEVICE_OBJECT pfdo, PIRP pIrp ) ;
NTSTATUS IOCTLRoutine( PDEVICE_OBJECT pfdo, PIRP pIrp ) ;
void DriverUnloadRoutine( PDRIVER_OBJECT pfdo ) ;
ULONG ReleaseHook(void) ;
NTSTATUS NtOpenProcessRoutine( HANDLE *ProcessHandle, ACCESS_MASK AcessMask, OBJECT_ATTRIBUTES *pObjAttr, CLIENT_ID *pClientID ) ;
typedef NTSTATUS (*NtOpenProcessPointer) (PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);


//################################### GLOBAL #########################################//
ULONG dwServiceID ;
NTSTATUS status ;
UCHAR i ;
HANDLE ProcessID ;
UNICODE_STRING usSymLink ;
HANDLE dwaPID[MAX_PIDS] ;
UCHAR bPidCounter ;
NtOpenProcessPointer OldNtOpenProcess ;


extern struct SERVICE_DESCRIPTOR_TABLE 
{
	struct SYSTEM_SERVICE_TABLE 
	{
		ULONG	*ServiceTable; 
		ULONG	*CounterTable; 
		ULONG	ServiceLimit; 
		UCHAR	*ArgumentTable;
	} ntkrnl_sst, win32k_sst, reserverd1_sst, reserved2_sst ;
} *KeServiceDescriptorTable;

//################################### DRIVER ENTRY ##################################//
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pusRegistryPath)
{
PDEVICE_OBJECT pfdo ;
UNICODE_STRING usDevName ;
ULONG NtBuildNumber ;
#if DBG
	DbgPrint("In entry point") ;
#endif
//------------------- what os ?
		PsGetVersion( 0, 0, &NtBuildNumber, 0 ) ;
		switch( NtBuildNumber ) 
		{
		//============ WIN 2k
			case W2K_BUILDNUMBER :
				dwServiceID = 0x6A ;
				break ;
		//============ WIN XP
			case WXP_BUILDNUMBER :
				dwServiceID = 0x7A ;
				break ;
		//============ UNSUPORTED
			default :
				return STATUS_NOT_SUPPORTED ;
		}
//------------------- if it is xp or w2k
	OldNtOpenProcess = 0 ;
	bPidCounter = 0 ;
//-------- set routines
	pDriverObject->DriverUnload = DriverUnloadRoutine ;
	pDriverObject->MajorFunction[IRP_MJ_CREATE]	= IrpCreateCloseRoutine ;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE]	= IrpCreateCloseRoutine ;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]	= IOCTLRoutine ;
//-------- create device and sym link
	RtlInitUnicodeString(&usDevName, DEVICENAME ) ;
	status = IoCreateDevice( (DRIVER_OBJECT *)pDriverObject, 0, &usDevName, FILE_DEVICE_UNKNOWN, 0, 1, &pfdo ) ;
	if( status != STATUS_SUCCESS )
		return status ;
	RtlInitUnicodeString(&usSymLink, SYMLINK ) ;
	status = IoCreateSymbolicLink(&usSymLink, &usDevName ) ;
	pfdo->Flags |= DO_BUFFERED_IO ;
//------- ret
	return status ;
}

//################################### DRIVER UNLOAD ROUTINE ##################################//
void DriverUnloadRoutine( PDRIVER_OBJECT pfdo ) 
{
	#if DBG
		DbgPrint("In unload routine") ;
	#endif
	ReleaseHook() ;
	IoDeleteDevice( pfdo->DeviceObject ) ;
	IoDeleteSymbolicLink( &usSymLink ) ;
	return ; 
}

//################################### DRIVER IRP CREATE/CLOSE routine##################################//
NTSTATUS IrpCreateCloseRoutine( PDEVICE_OBJECT pfdo, PIRP pIrp ) 
{
	#if DBG
		DbgPrint(" in CREATE/CLOSE ROUTINE ") ;
	#endif
	pIrp->IoStatus.Status = STATUS_SUCCESS ;
	pIrp->IoStatus.Information = 0 ;
	IoCompleteRequest( pIrp, IO_NO_INCREMENT ) ;
	return STATUS_SUCCESS ;
}
//################################### IOCTL Routine ##################################//
NTSTATUS IOCTLRoutine( PDEVICE_OBJECT pfdo, PIRP pIrp ) 
{
	UCHAR *pParams1 ;
	UCHAR bCur ;
	PIO_STACK_LOCATION pIrpStack ;
	pIrpStack = IoGetCurrentIrpStackLocation(pIrp) ;
	pIrp->IoStatus.Information = 0 ;
	switch( pIrpStack->Parameters.DeviceIoControl.IoControlCode )
	{
		
	//################ IOCTL_ SET AK HOOK
	case IOCTL_SETAKHOOK :
	#if DBG
			DbgPrint(" in IOCTL_SETAKHOOK ROUTINE ") ;
		#endif
	if(OldNtOpenProcess)
		goto IrpReq_BadParam_lb ;
			__asm
			{
				cli
				mov eax, cr0
				push eax
				and eax, 0xFFFFFEFF
			}
			OldNtOpenProcess = (NtOpenProcessPointer) KeServiceDescriptorTable->ntkrnl_sst.ServiceTable[dwServiceID] ;
			KeServiceDescriptorTable->ntkrnl_sst.ServiceTable[dwServiceID] = (ULONG)NtOpenProcessRoutine ; 
			__asm
			{
				pop eax
				mov cr0, eax
				sti
			}
		
		break ;
		
	//################ IOCTL_ RELEASE AK HOOK
	case IOCTL_RELEASEAKHOOK :
		#if DBG
			DbgPrint(" in IOCTL_RELEASEHOOK ROUTINE ") ;
		#endif
		if( ReleaseHook() )
			goto IrpReq_BadParam_lb ;
		break ;
		
	//################ IOCTL_ ADD PROCESS ID
	case IOCTL_ADDPROCESSID :
		#if DBG
			DbgPrint(" in IOCTL_ADDPROCESSID ROUTINE ") ;
		#endif
		if( pIrpStack->Parameters.DeviceIoControl.InputBufferLength < 5  )
			goto IrpReq_BadParam_lb ;
		pParams1 = (UCHAR *)(pIrp->AssociatedIrp.SystemBuffer) ;
		if( *((UCHAR *)pParams1) == 0xFF )
		{
			if( bPidCounter >= MAX_PIDS ) 
				goto IrpReq_BadParam_lb ;
			dwaPID[bPidCounter] = *( (HANDLE *)(pParams1+1)) ;
			bPidCounter++ ;
		} 
		else
			dwaPID[*((UCHAR *)pParams1)] = *((HANDLE *) (pParams1+1)) ;
		break ;
		
	//################ IOCTL_ REM PROCESS ID
	case IOCTL_REMPROCESSID :
		#if DBG
			DbgPrint(" in IOCTL_REMPROCESSID ROUTINE ") ;
		#endif
		if( ( (pIrpStack->Parameters.DeviceIoControl.InputBufferLength != 1) || ( bPidCounter == 0 ) ) )
			goto IrpReq_BadParam_lb ;
		bCur = (UCHAR)(*((UCHAR *)pIrp->AssociatedIrp.SystemBuffer) ) ;
		if( bCur > (bPidCounter-1) ) 
			goto IrpReq_BadParam_lb ;
		for( ; bCur < (bPidCounter-1) ; bCur++ )
			dwaPID[bCur] = dwaPID[bCur+1] ;
		break ;
	
	//################ IOCTL_ GET PROCESS ID LIST
	case IOCTL_GETPROCESSIDLIST :
		#if DBG
			DbgPrint(" in IOCTL_GETPROCESSIDLIST ROUTINE ") ;
		#endif
		if( (pIrpStack->Parameters.DeviceIoControl.OutputBufferLength < MAX_PIDS*4 +1 ) || ((pIrpStack->Parameters.DeviceIoControl.InputBufferLength !=0 ) ) )
		{
		IrpReq_BadParam_lb :
			pIrp->IoStatus.Status = STATUS_INVALID_PARAMETER ;
			IoCompleteRequest( pIrp, IO_NO_INCREMENT ) ;
			return STATUS_INVALID_PARAMETER ;
		}	
		* (PUCHAR)pIrp->AssociatedIrp.SystemBuffer  = (UCHAR)bPidCounter ; 
		RtlCopyMemory( ( ((PUCHAR)pIrp->AssociatedIrp.SystemBuffer)+1), &(dwaPID[0]), MAX_PIDS*4 ) ;
		pIrp->IoStatus.Information = MAX_PIDS*4+1 ;
		break ;
	//############## DEFAULT
	default :
		#if DBG
			DbgPrint(" Unknow IOCTL code ") ;
		#endif
		break ;
	}

	pIrp->IoStatus.Status = STATUS_SUCCESS ;
	IoCompleteRequest( pIrp, IO_NO_INCREMENT ) ;
	return STATUS_SUCCESS ;
}

//######################################### RELEASE HOOK FUNCTION #######################################//
ULONG ReleaseHook() 
{
	if(OldNtOpenProcess == 0)
		return -1 ;
	__asm
	{
		cli
		mov eax, cr0
		push eax
		and eax, 0xFFFFFEFF
	}
	KeServiceDescriptorTable->ntkrnl_sst.ServiceTable[dwServiceID] = (ULONG)OldNtOpenProcess ; 
	__asm
	{
	pop eax
	mov cr0, eax
	sti
	}
	OldNtOpenProcess = 0 ;
	return 0;
}

//########################################## NT OPEN PROCESS ROUTINE #########################################//
NTSTATUS NtOpenProcessRoutine( HANDLE *ProcessHandle, ACCESS_MASK AcessMask, OBJECT_ATTRIBUTES *pObjAttr, CLIENT_ID *pClientID ) 
{
#if DBG
	DbgPrint(" In fake NtOpenProcess routine\n" ) ;
#endif
//-------------------- get process id
	__try
	{
		ProcessID = pClientID->UniqueProcess ;
	} 
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
	#if DBG
		DbgPrint(" Exception in fake NtOpenProcess routine ") ;
	#endif
		return STATUS_INVALID_PARAMETER ;
	}
//-------------------- compare it with list
	for( i = 0 ; i < bPidCounter ; i ++ )
		if( dwaPID[i] == ProcessID )
		{
			#if DBG
				DbgPrint(" Attempt to close was hooked. The killer is ") ;
			#endif
			return STATUS_ACCESS_DENIED ;
		}
//-------------------- call real NtOpenProcess
	return OldNtOpenProcess( ProcessHandle, AcessMask, pObjAttr, pClientID) ;
}