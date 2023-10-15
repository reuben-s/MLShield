#include <Windows.h>

const LPCSTR DllPath = "placeholder";

int InjectDLL(DWORD pid)
{

	// Aquire handle to process to be injected into
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess == NULL)
	{
		// No need to free anything as the process didn't successfully allocate any memory!
		return -1;
	}

	// Allocate memory in process 
	LPVOID pDllPath = VirtualAllocEx(hProcess, NULL, strlen(DllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
	if (pDllPath == NULL)
	{
		CloseHandle(hProcess);
		return -1;
	}

	// Write DLL path to remote process
	BOOL bProcWriteSuccess = WriteProcessMemory(hProcess, pDllPath, DllPath, strlen(DllPath) + 1, NULL);
	if (!bProcWriteSuccess)
	{
		VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return -1;
	}

	// Get kernel32 module handle. As far as I know this function will never fail as kernel32.dll is loaded into every application but my intellisense kept complaining so I added the error handling code.
	HMODULE hmKernel32 = GetModuleHandleA("kernel32.dll");
	if (hmKernel32 == NULL)
	{
		VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return -1;
	}

	// Get a pointer to the LoadLibraryA function.
	LPVOID lpLoadLibraryAddress = (LPVOID)GetProcAddress(hmKernel32, "LoadLibraryA");
	if (lpLoadLibraryAddress == NULL)
	{
		VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return -1;
	}

	HANDLE hRemoteThread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)lpLoadLibraryAddress, pDllPath, 0, 0);
	if (hRemoteThread == NULL)
	{
		VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return -1;
	}

	WaitForSingleObject(hRemoteThread, INFINITE);

	// Clean up allocations
	VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
	CloseHandle(hRemoteThread);
	CloseHandle(hProcess);

	return 0;
}
