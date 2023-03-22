/*!
 *
 * BOOTLICKER
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation Team
 *
!*/

#pragma once

/*!
 *
 * Purpose:
 *
 * Allocates a block of memory in the style of LIBC MALLOC 
 * Uses with the rest of the Mem* routines to ensure our 
 * memory is cleaned up.
 *
!*/
D_SEC( F ) PVOID MemAlloc( _In_ SIZE_T Length );

/*!
 *
 * Purpose:
 *
 * Frees a block of memory and condenses the heap, to 
 * ensure all unused allocations are zeroed and freed.
 *
!*/
D_SEC( F ) VOID MemFree( _In_ PVOID Memory );

/*!
 *
 * Purpose:
 *
 * Reallocates a allocated buffer in the same style as
 * realloc
 *
!*/
D_SEC( F ) PVOID MemReAlloc( _In_ PVOID Buffer, _In_ SIZE_T Length );
