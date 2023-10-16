#include "pch.h"
#include "NamedPipe.h"

#define LP_TEXT_STRING(s) ((LPTSTR)TEXT(s))

Pipe* pServer; // pointer to pipe object on the heap
LPTSTR lpszPipename = LP_TEXT_STRING("\\\\.\\pipe\\TestPipe");

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        // Perform initialization tasks when the DLL is loaded
        // Create a named pipe client
        pServer = new Pipe(lpszPipename);
        pServer->SendMessage(LP_TEXT_STRING("NEW CONNECTION PID: " + GetCurrentProcessId()));

        break;

    case DLL_PROCESS_DETACH:
        // Perform cleanup tasks when the DLL is unloaded
        if (pServer) {
            pServer->SendMessage(LP_TEXT_STRING("Goodbye from remote process"));
            delete pServer;
        }
        break;

    case DLL_THREAD_ATTACH:
        break;

    case DLL_THREAD_DETACH:
        break;
    }

    return TRUE;
}
