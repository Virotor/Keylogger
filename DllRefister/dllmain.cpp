﻿// dllmain.cpp : Определяет точку входа для приложения DLL.
#include "pch.h"


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
        InterceptFunctionsJmp();
    return TRUE;
}

