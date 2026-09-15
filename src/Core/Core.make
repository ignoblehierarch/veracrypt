#
# Derived from source code of TrueCrypt 7.1a, which is
# Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
# by the TrueCrypt License 3.0.
#
# Modifications and additions to the original source code (contained in this file)
# and all other portions of this file are Copyright (c) 2013-2017 AM Crypto
# and are governed by the Apache License 2.0 the full text of which is
# contained in the file License.txt included in VeraCrypt binary and source
# code distribution packages.
#

OBJS :=
OBJS += CoreBase.o
OBJS += CoreException.o
OBJS += FatFormatter.o
OBJS += HostDevice.o
OBJS += MountOptions.o
OBJS += RandomNumberGenerator.o
OBJS += VolumeCreator.o
OBJS += Unix/CoreService.o
OBJS += Unix/CoreServiceRequest.o
OBJS += Unix/CoreServiceResponse.o
OBJS += Unix/CoreUnix.o
OBJS += Unix/$(PLATFORM)/Core$(PLATFORM).o
OBJS += Unix/$(PLATFORM)/Core$(PLATFORM).o
ifeq "$(PLATFORM)" "MacOSX"
OBJS += Unix/FreeBSD/CoreFreeBSD.o
# macFUSE 5 mounts in-process and creates a DiskArbitration session on a helper
# thread inside the fork()ed FUSE child, which the Objective-C runtime will not
# allow. main() pre-initializes it before anything forks. FUSE-T does not use
# DiskArbitration and does not need this.
ifeq "$(VC_OSX_FUSET)" "0"
OBJS += Unix/MacOSXDiskArbitration.o
endif
endif

include $(BUILD_INC)/Makefile.inc
