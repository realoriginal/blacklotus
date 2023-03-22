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
 * Inject a shellcoed into the existing process we 
 * are within.
 *
!*/
D_SEC( F ) VOID Inject( _In_ PVOID Buffer, _In_ SIZE_T Length );
