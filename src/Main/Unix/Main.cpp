/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2026 AM Crypto
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#include "System.h"
#include <sys/mman.h>

#include "Platform/Platform.h"
#include "Platform/SystemLog.h"
#include "Volume/EncryptionThreadPool.h"
#include "Core/Unix/CoreService.h"
#include "Core/Unix/UnixUser.h"
#include "Main/Application.h"
#include "Main/Main.h"
#include "Main/UserInterface.h"

#if defined (TC_MACOSX) && !defined (TC_NO_GUI)
#include <ApplicationServices/ApplicationServices.h>
#endif

#if defined (TC_MACOSX) && !defined (VC_MACOSX_FUSET)
#include "Core/Unix/MacOSXDiskArbitration.h"
#include "Core/MountOptions.h"
#include "Driver/Fuse/FuseService.h"
#include "Platform/MemoryStream.h"
#include "Volume/Cipher.h"
#include "Volume/Volume.h"
#endif

using namespace VeraCrypt;

#if defined (TC_MACOSX) && !defined (VC_MACOSX_FUSET)
namespace
{
	// Entry point of the FUSE daemon that FuseService::Mount() exec()s.
	//
	// Nothing in this process has initialized wxWidgets, Cocoa, the encryption
	// thread pool or the core service, and nothing here is going to: that is the
	// entire point. macFUSE 5 performs the mount in-process, so the mount has to
	// happen somewhere the Objective-C and libdispatch runtimes are pristine,
	// which a fork child of the GUI process is not and cannot be made to be.
	int FuseDaemonMain (int argc, char **argv)
	{
		try
		{
			// The request is a serialized MountOptions, written to our stdin by
			// Process::Execute() in the caller. It carries the password, which is
			// why it comes through a pipe rather than argv or the environment.
			SecureBuffer request;
			{
				vector <uint8> data;
				uint8 buf[4096];
				ssize_t bytesRead;

				while ((bytesRead = read (STDIN_FILENO, buf, sizeof (buf))) > 0)
					data.insert (data.end(), buf, buf + bytesRead);

				throw_sys_if (bytesRead == -1);

				if (data.empty())
					throw ParameterIncorrect (SRC_POS);

				request.CopyFrom (ConstBufferPtr (&data[0], data.size()));
				Memory::Zero (&data[0], data.size());
			}

			shared_ptr <Stream> stream (new MemoryStream (request));
			shared_ptr <MountOptions> options = Serializable::DeserializeNew <MountOptions> (stream);
			request.Erase();

			VeraCrypt::Cipher::EnableHwSupport (!options->NoHardwareCrypto);

			make_shared_auto (Volume, volume);
			volume->Open (
				*options->Path,
				options->PreserveTimestamps,
				options->Password,
				options->Pim,
				options->Kdf,
				options->Keyfiles,
				options->EMVSupportEnabled,
				options->Protection,
				options->ProtectionPassword,
				options->ProtectionPim,
				options->ProtectionKdf,
				options->ProtectionKeyfiles,
				options->SharedAccessAllowed,
				VolumeType::Unknown,
				options->UseBackupHeaders,
				options->PartitionInSystemEncryptionScope
				);

			options->Password.reset();
			options->ProtectionPassword.reset();

			// argv[0] is this binary and argv[1] is the daemon option; libfuse gets
			// the rest, which starts with the device type it expects as its argv[0].
			// RunDaemon() does not return.
			FuseService::RunDaemon (argc - 2, argv + 2, volume, options->SlotNumber, true);
			return 0;
		}
		catch (exception &e)
		{
			// Still attached to the stderr Process::Execute() is reading, so this
			// reaches the caller as the text of an ExecutedProcessFailed.
			cerr << StringConverter::GetTypeName (typeid (e)) << endl << e.what() << endl;
		}
		catch (...)
		{
			cerr << "Unknown exception in FUSE daemon" << endl;
		}

		return 1;
	}
}
#endif

int main (int argc, char **argv)
{
	try
	{
#if defined (TC_MACOSX) && !defined (VC_MACOSX_FUSET)
		// First, ahead of everything below: this process may have been exec()ed by
		// FuseService::Mount() to be a FUSE daemon and nothing else. It must reach
		// libfuse without having initialized Cocoa, DiskArbitration, libdispatch or
		// the core service, because it is going to fork one last time and the child
		// is the process that mounts, serves and unmounts the filesystem.
		if (argc > 2 && strcmp (argv[1], FuseService::GetDaemonCommandLineOption()) == 0)
			return FuseDaemonMain (argc, argv);

		// Fallback path only. Where Mount() cannot exec() a daemon it forks one,
		// and that child runs under the Objective-C runtime's fork-safety rule: a
		// class whose +initialize did not already run in the parent cannot be
		// initialized in the child, and touching one aborts the process
		// (objc_initializeAfterForkError, SIGABRT). macFUSE 5 trips exactly that,
		// because it mounts in-process and creates a DiskArbitration session while
		// doing so. Initializing DiskArbitration here, before anything forks, gets
		// that work done in the true parent; descendants inherit it and never have
		// to run +initialize. Note that this cannot help with teardown, where
		// libdispatch -- which has no such escape hatch -- is the one being used in
		// a fork child. Only the exec()ed daemon fixes that.
		PrewarmDiskArbitration();
#endif

		// Make sure all required commands can be executed via default search path
		string sysPathStr = "/usr/sbin:/sbin:/usr/bin:/bin";

		char *sysPath = getenv ("PATH");
		if (sysPath)
		{
			sysPathStr += ":";
			sysPathStr += sysPath;
		}

		setenv ("PATH", sysPathStr.c_str(), 1);

		if (argc > 1 && (strcmp (argv[1], TC_CORE_SERVICE_CMDLINE_OPTION) == 0 || strcmp (argv[1], TC_CORE_SERVICE_NO_FORK_CMDLINE_OPTION) == 0))
		{
			// Process elevated requests
			try
			{
				bool forkProcess = strcmp (argv[1], TC_CORE_SERVICE_CMDLINE_OPTION) == 0;
				if (!forkProcess)
					setenv (TC_DOAS_CORE_SERVICE_ENV, "1", 1);

				CoreService::ProcessElevatedRequests (forkProcess);
				return 0;
			}
			catch (exception &e)
			{
#ifdef DEBUG
				SystemLog::WriteException (e);
#endif
			}
			catch (...)	{ }
			return 1;
		}

		// Start core service
		CoreService::Start();
		finally_do ({ CoreService::Stop(); });

		// Start encryption thread pool
		EncryptionThreadPool::Start();
		finally_do ({ EncryptionThreadPool::Stop(); });

#ifdef TC_NO_GUI
		bool forceTextUI = true;
#else
		bool forceTextUI = false;
#endif

#ifdef __WXGTK__
		if (!getenv ("DISPLAY") && !getenv ("WAYLAND_DISPLAY"))
			forceTextUI = true;
#endif

		// Initialize application
		if (forceTextUI || (argc > 1 && (strcmp (argv[1], "-t") == 0 || strcmp (argv[1], "--text") == 0)))
		{
			Application::Initialize (UserInterfaceType::Text);
		}
		else
		{
#if defined (TC_MACOSX) && !defined (TC_NO_GUI)
			if (argc > 1 && !(argc == 2 && strstr (argv[1], "-psn_") == argv[1]))
			{
				ProcessSerialNumber p;
				if (GetCurrentProcess (&p) == noErr)
				{
					TransformProcessType (&p, kProcessTransformToForegroundApplication);
					SetFrontProcess (&p);
				}
			}
#endif
			Application::Initialize (UserInterfaceType::Graphic);
		}

		Application::SetExitCode (1);

		// Start application
		if (::wxEntry (argc, argv) == 0)
			Application::SetExitCode (0);
	}
	catch (ErrorMessage &e)
	{
		wcerr << wstring (e) << endl;
	}
	catch (SystemException &e)
	{
		wstringstream s;
		if (e.GetSubject().empty())
			s << e.what() << endl << e.SystemText();
		else
			s << e.what() << endl << e.SystemText() << endl << e.GetSubject();
		wcerr << s.str() << endl;
	}
	catch (exception &e)
	{
		stringstream s;
		s << StringConverter::GetTypeName (typeid (e)) << endl << e.what();
		cerr << s.str() << endl;
	}

	return Application::GetExitCode();
}
