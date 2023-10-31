#include "pch.h"
#include "NamedPipe.h"
#include "HookManager.h"

#define LP_TEXT_STRING(s) ((LPTSTR)TEXT(s))

Pipe* pServer; // pointer to pipe object on the heap
HookManager* pHookManager;
const LPTSTR lpszPipename = LP_TEXT_STRING("\\\\.\\pipe\\TestPipe");

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        // Perform initialization tasks when the DLL is loaded
        // Create a named pipe client
        pServer = new Pipe(lpszPipename);
        if (!pServer->bPipeOpen)
        {
            // Pipe connection failed to open so delete the object from the heap and exit DllMain.
            delete pServer;
            return FALSE;
        }
        // Initialise function hooks.
        pHookManager = new HookManager();
        if (!pHookManager->HooksActive)
        {
            // Failed to inisialize hooks so delete hook manager and server object then exit DllMain.
            delete pHookManager;
            pServer->SendMessage(LP_TEXT_STRING("Failed to initialise hooks."));
            delete pServer;
            return FALSE;
        }
        // Otherwise notify the pipe server that the hooks were initalized.
        pServer->SendMessage(LP_TEXT_STRING("Successfully initialised hooks."));


        break;

    case DLL_PROCESS_DETACH:
        // Perform cleanup tasks when the DLL is unloaded
        if (pServer) {
            delete pServer;
        }
        if (pHookManager)
        {
            delete pHookManager;
        }
        break;

    case DLL_THREAD_ATTACH:
        break;

    case DLL_THREAD_DETACH:
        break;
    }

    return TRUE;
}
