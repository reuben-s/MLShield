#include "pch.h"
#include "HookManager.h"

static int (WINAPI* pMessageBoxA)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) = MessageBoxA;

int WINAPI MessageBoxA_Detour(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
    pPipe->SendMessage(LP_TEXT_STRING("MessageBoxA Called"));
    return pMessageBoxA(hWnd, lpText, lpCaption, uType);
}

HookManager::HookManager(Pipe* pPipe)
{
    DetourRestoreAfterWith();

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)pMessageBoxA, MessageBoxA_Detour);
    DetourTransactionCommit();

    pPipe->SendMessage(LP_TEXT_STRING("Detours hooks initalised."));
}

HookManager::~HookManager()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID&)pMessageBoxA, MessageBoxA_Detour);
    DetourTransactionCommit();

    delete pHookManager;
}