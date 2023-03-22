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

#define SECURITY_WIN32
#include <windows.h>
#include <ntstatus.h>
#include <wininet.h>
#include "global/Macros.h"
#include "global/Labels.h"
#include "global/Hash.h"
#include "global/Pe.h"
#include "Native.h"

#include "Inject.h"
#include "Mem.h"
#include "Peb.h"
