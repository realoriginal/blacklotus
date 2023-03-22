/*!
 *
 * vmware-bootkit
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
 * Locates a module in memory.
 *
!*/
D_SEC( F ) PVOID PebGetModule( _In_ UINT32 ModuleHash );
