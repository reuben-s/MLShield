#include "pch.h"
#include "HookManager.h"

HookManager::HookManager(Pipe* pPipe)
{
    DetourRestoreAfterWith();

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)HookUtil::FunctionPointers::pMessageBoxA, HookUtil::DetouredFunctions::MessageBoxA_Detour);
    DetourTransactionCommit();

    pPipe->SendMessage(LP_TEXT_STRING("Detours hooks initalised."));
}

HookManager::~HookManager()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID&)HookUtil::FunctionPointers::pMessageBoxA, HookUtil::DetouredFunctions::MessageBoxA_Detour);
    DetourTransactionCommit();

    delete pHookManager;
}