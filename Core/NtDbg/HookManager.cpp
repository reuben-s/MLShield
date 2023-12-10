#include "pch.h"
#include "HookManager.h"
#include "WinApiFunctionPointers.h"

int WINAPI MessageBoxA_Detour(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
    pPipe->SendMessage(LP_TEXT_STRING("MessageBoxA Called"));
    return WinApiFunctionPointers::pMessageBoxA(hWnd, lpText, lpCaption, uType);
}

HookManager::HookManager(Pipe* pPipe)
{
    DetourRestoreAfterWith();

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)WinApiFunctionPointers::pMessageBoxA, MessageBoxA_Detour);
    DetourTransactionCommit();

    pPipe->SendMessage(LP_TEXT_STRING("Detours hooks initalised."));
}

HookManager::~HookManager()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID&)WinApiFunctionPointers::pMessageBoxA, MessageBoxA_Detour);
    DetourTransactionCommit();

    delete pHookManager;
}