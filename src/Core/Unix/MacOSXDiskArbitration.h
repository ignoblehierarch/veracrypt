/*
 Copyright (c) 2013-2026 AM Crypto. All rights reserved.

 Governed by the Apache License 2.0 the full text of which is contained in
 the file License.txt included in VeraCrypt binary and source code
 distribution packages.
*/

#ifndef TC_HEADER_Core_Unix_MacOSXDiskArbitration
#define TC_HEADER_Core_Unix_MacOSXDiskArbitration

namespace VeraCrypt
{
	// Initializes the DiskArbitration framework in the calling process.
	//
	// Must be called from main(), before VeraCrypt forks anything; see the call
	// site in Main/Unix/Main.cpp. It deliberately lives in its own translation
	// unit: <DiskArbitration/DiskArbitration.h> drags in <mach/error.h>, whose
	// ERR_SUCCESS macro collides with the ERR_SUCCESS enumerator in Tcdefs.h.
	void PrewarmDiskArbitration ();
}

#endif // TC_HEADER_Core_Unix_MacOSXDiskArbitration
