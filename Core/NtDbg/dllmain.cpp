#include "pch.h"
#include "NamedPipe.h"
#include "HookManager.h"

Pipe* pPipe; // Pointer to pipe object on the heap
HookManager* pHookManager; // Pointer to HookManager object on heap
constexpr LPTSTR lpszPipename = LP_TEXT_STRING("\\\\.\\pipe\\TestPipe");

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        // Perform initialization tasks when the DLL is loaded
        // Create a named pipe client
        AllocConsole();
        FILE* pConsole;
        freopen_s(&pConsole, "CONOUT$", "w", stdout);

        pPipe = new Pipe(lpszPipename);
        if (pPipe == nullptr)
        {
            // Failed to create pipe object
            return FALSE;
        }
        if (pPipe->bPipeOpen == FALSE)
        {
            // Pipe connection failed to open so delete the object from the heap and exit DllMain.
            delete pPipe;
            return FALSE;
        }
        pPipe->SendMessage(LP_TEXT_STRING("New client connected."));
       
        pHookManager = new HookManager(pPipe);

        break;

    case DLL_PROCESS_DETACH:
        // Perform cleanup tasks when the DLL is unloaded
        if (pPipe != nullptr) {
            delete pPipe;
        }
        if (pHookManager != nullptr)
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
