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
	D_API( RtlReAllocateHeap );
	D_API( RtlAllocateHeap );
	D_API( RtlCompactHeap );
	D_API( RtlZeroHeap );
	D_API( RtlSizeHeap );
	D_API( RtlFreeHeap );
} API ;

/* API Hashes */
#define H_API_RTLREALLOCATEHEAP		0xaf740371 /* RtlReAllocateHeap */
#define H_API_RTLALLOCATEHEAP		0x3be94c5a /* RtlAllocateHeap */
#define H_API_RTLCOMPACTHEAP		0xccd9c63c /* RTlCompactHeap */
#define H_API_RTLZEROHEAP		0x1f2175d5 /* RtlZeroHeap */
#define H_API_RTLSIZEHEAP		0xef31e6b0 /* RtlSizeHeap */
#define H_API_RTLFREEHEAP		0x73a9e4d7 /* RtlFreeHeap */

/* LIB Hashes */
#define H_LIB_NTDLL			0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * Allocates a block of memory in the style of LIBC MALLOC 
 * Uses with the rest of the Mem* routines to ensure our 
 * memory is cleaned up.
 *
!*/
D_SEC( F ) PVOID MemAlloc( _In_ SIZE_T Length )
{
	API	Api;
	PVOID	Mem = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	Api.RtlAllocateHeap = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLALLOCATEHEAP );

	/* Allocate a block of memory */
	Mem = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Length );

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	/* Return the address */
	return C_PTR( Mem );
};

/*!
 *
 * Purpose:
 *
 * Frees a block of memory and condenses the heap, to 
 * ensure all unused allocations are zeroed and freed.
 *
!*/
D_SEC( F ) VOID MemFree( _In_ PVOID Memory )
{
	API	Api;

	SIZE_T	Len = 0;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	Api.RtlCompactHeap = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLCOMPACTHEAP ); 
	Api.RtlSizeHeap    = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLSIZEHEAP );
	Api.RtlFreeHeap    = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLFREEHEAP );
	Api.RtlZeroHeap    = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLZEROHEAP );

	Len = Api.RtlSizeHeap( NtCurrentPeb()->ProcessHeap, 0, Memory );

	if ( Len != -1 ) {

		/* Zero the block of memory */
		__builtin_memset( Memory, 0, Len );

		/* Free the block of memory */
		Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Memory );

		/* Compact the heap */
		Api.RtlCompactHeap( NtCurrentPeb()->ProcessHeap, 0 );

		/* ZEro the full heap */
		Api.RtlZeroHeap( NtCurrentPeb()->ProcessHeap, 0 );
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
};

/*!
 *
 * Purpose:
 *
 * Reallocates a allocated buffer in the same style as 
 * realloc
 *
!*/
D_SEC( F ) PVOID MemReAlloc( _In_ PVOID Buffer, _In_ SIZE_T Length )
{
	API	Api;

	PVOID	Ptr = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	Api.RtlReAllocateHeap = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLREALLOCATEHEAP );
	Api.RtlCompactHeap    = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLCOMPACTHEAP );
	Api.RtlZeroHeap       = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLZEROHEAP );

	if ( Buffer != NULL ) {
		/* Allocate a new block of memory */
		Ptr = Api.RtlReAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Buffer, Length );
	} else
	{
		/* Allocate a fresh buffer */
		Ptr = MemAlloc( Length );
	};

	/* Zero all the heap allocations */
	Api.RtlZeroHeap( NtCurrentPeb()->ProcessHeap, 0 );

	/* Compact the heap */
	Api.RtlCompactHeap( NtCurrentPeb()->ProcessHeap, 0 );

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	/* Return a pointer */
	return C_PTR( Ptr );
};
