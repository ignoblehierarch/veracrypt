/*
 Copyright (c) 2013-2026 AM Crypto. All rights reserved.

 Governed by the Apache License 2.0 the full text of which is contained in
 the file License.txt included in VeraCrypt binary and source code
 distribution packages.
*/

#include <CoreFoundation/CoreFoundation.h>
#include <DiskArbitration/DiskArbitration.h>

#include "MacOSXDiskArbitration.h"

namespace VeraCrypt
{
	void PrewarmDiskArbitration ()
	{
		// Runs __DAInitialize() and initializes the Objective-C classes it
		// touches. Must be called before VeraCrypt forks: both CoreService::Start()
		// and FuseService::Mount() fork without exec(), and a fork child of a
		// multithreaded Cocoa process cannot run +initialize for a class that was
		// not already initialized in its parent. The child inherits both the
		// pthread_once token and the per-class initialized flags.
		//
		// Failure is not fatal: if the session cannot be created, the children are
		// no worse off than they were before this call existed.
		DASessionRef session = DASessionCreate (kCFAllocatorDefault);

		if (session)
			CFRelease (session);
	}
}
