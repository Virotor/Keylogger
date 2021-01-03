#include "pch.h"




void assigningNewAddress(DWORD* isd, DWORD buf)
{
    if (*isd == 0) {
        return;
    }
    DWORD op;

    // Обычно страницы в этой области недоступны для записи
    // поэтому принудительно разрешаем запись
    VirtualProtect((void*)(isd), 4, PAGE_READWRITE, &op);
    SIZE_T* written = new SIZE_T[10];
    // Пишем новый адрес
    WriteProcessMemory(GetCurrentProcess(), (void*)(isd),
        (void*)&buf, 4, written);
    //восстанавливаем первоначальную защиту области по записи
    VirtualProtect((void*)(isd), 4, op, &op);
    //если записать не удалось – увы, все пошло прахом…
    if (*written != 4)
    {
        std::cout << "Unable rewrite address Error!" << std::endl;
        return;
    }

}

// Эта функция ищет в таблице импорта - .idata нужный адрес и меняет на
// адрес процедуры-двойника 
void InterceptFunctions(void)
{
    // Начало отображения в памяти процесса
    BYTE* pimage = (BYTE*)GetModuleHandle(NULL);
    BYTE* pidata;
    // Стандартные структуры описания PE заголовка
    IMAGE_DOS_HEADER* idh;
    IMAGE_OPTIONAL_HEADER* ioh;
    IMAGE_SECTION_HEADER* ish;
    IMAGE_IMPORT_DESCRIPTOR* iid;
    std:: vector<DWORD*> isd(91,0);  //image_thunk_data dword
   


    // Получаем указатели на стандартные структуры данных PE заголовка
    idh = (IMAGE_DOS_HEADER*)pimage;
    ioh = (IMAGE_OPTIONAL_HEADER*)(pimage + idh->e_lfanew
        + 4 + sizeof(IMAGE_FILE_HEADER));
    ish = (IMAGE_SECTION_HEADER*)((BYTE*)ioh + sizeof(IMAGE_OPTIONAL_HEADER));
    //если не обнаружен магический код, то у этой программы нет PE заголовка
    if (idh->e_magic != 0x5A4D)
    {
        return;
    }

    int j;
    //ищем секцию .idata
    for (j = 0; j < 16; j++)
        if (strcmp((char*)((ish + j)->Name), ".idata") == 0) break;

    if (j == 16)
    {
        std::cout << "Unable to find.idata section Error! " << std::endl;
        return;
    }
    // Получаем адрес секции .idata(первого элемента IMAGE_IMPORT_DESCRIPTOR)
    iid = (IMAGE_IMPORT_DESCRIPTOR*)(pimage + (ish + j)->VirtualAddress);

    // Получаем абсолютный адрес функции для перехвата

    for (int i = 0; i < adr_Reester_Func.size(); i++) {
        auto temp = (DWORD)GetProcAddress(
            GetModuleHandle(convertStr("Advapi32.dll")), name_of_func[i]);
        if (temp == 0)
        {
            std::cout << "Can`t get adr, Error!" << std::endl;
        }
        else {
            adr_Reester_Func[i]=temp;


            // В таблице импорта ищем соответствующий элемент для 
            // библиотеки user32.dll
            while (iid->Name)  //до тех пор пока поле структуры не содержит 0
            {
                if (strcmp((char*)(pimage + iid->Name), "Advapi32.dll") == 0) break;
                iid++;
            }

            // Ищем в IMAGE_THUNK_DATA нужный адрес
            isd[i]=(DWORD*)(pimage + iid->FirstThunk);
            while (*isd[i] != adr_Reester_Func[i] && *isd[i] != 0)  isd[i]++;

          
        }
    }



    // Заменяем адрес на свою функцию
 
    bool retflag;
    if(adr_Reester_Func[0]!=0)
        assigningNewAddress(isd[0], (DWORD)&AbortSystemShutdownAInt);
    if (adr_Reester_Func[1] != 0)   
        assigningNewAddress(isd[1], (DWORD)&AbortSystemShutdownWInt);
    if (adr_Reester_Func[2] != 0)   
        assigningNewAddress(isd[2], (DWORD)&InitiateShutdownAInt);
    if (adr_Reester_Func[3] != 0)   
        assigningNewAddress(isd[3], (DWORD)&InitiateShutdownWInt);
    if (adr_Reester_Func[4] != 0)   
        assigningNewAddress(isd[4], (DWORD)&InitiateSystemShutdownAInt);
    if (adr_Reester_Func[5] != 0)   
        assigningNewAddress(isd[5], (DWORD)&InitiateSystemShutdownExAInt);
    if (adr_Reester_Func[6] != 0)   
        assigningNewAddress(isd[6], (DWORD)&InitiateSystemShutdownExWInt);
    if (adr_Reester_Func[7] != 0)   
        assigningNewAddress(isd[7], (DWORD)&InitiateSystemShutdownWInt);
    if (adr_Reester_Func[8] != 0)   
        assigningNewAddress(isd[8], (DWORD)&RegCloseKeyInt);
    if (adr_Reester_Func[9] != 0)   
        assigningNewAddress(isd[9], (DWORD)&RegConnectRegistryAInt);
    if (adr_Reester_Func[10] != 0)
        assigningNewAddress(isd[10],(DWORD)&RegConnectRegistryWInt);
    if (adr_Reester_Func[11] != 0)
        assigningNewAddress(isd[11],(DWORD)&RegCopyTreeAInt);
    if (adr_Reester_Func[12] != 0)
        assigningNewAddress(isd[12],(DWORD)&RegCopyTreeWInt);
    if (adr_Reester_Func[13] != 0)
        assigningNewAddress(isd[13],(DWORD)&RegCreateKeyAInt);
    if (adr_Reester_Func[14] != 0)
        assigningNewAddress(isd[14],(DWORD)&RegCreateKeyExAInt);
    if (adr_Reester_Func[15] != 0)
        assigningNewAddress(isd[15],(DWORD)&RegCreateKeyExWInt);
    if (adr_Reester_Func[16] != 0)
        assigningNewAddress(isd[16],(DWORD)&RegCreateKeyTransactedAInt);
    if (adr_Reester_Func[17] != 0)
        assigningNewAddress(isd[17],(DWORD)&RegCreateKeyTransactedWInt);
    if (adr_Reester_Func[18] != 0)
        assigningNewAddress(isd[18],(DWORD)&RegCreateKeyWInt);
    if (adr_Reester_Func[19] != 0)
        assigningNewAddress(isd[19],(DWORD)&RegDeleteKeyAInt);
    if (adr_Reester_Func[20] != 0)
        assigningNewAddress(isd[20],(DWORD)&RegDeleteKeyWInt);
    if (adr_Reester_Func[21] != 0)
        assigningNewAddress(isd[21],(DWORD)&RegDeleteKeyExAInt);
    if (adr_Reester_Func[22] != 0)
        assigningNewAddress(isd[22],(DWORD)&RegDeleteKeyExWInt);
    if (adr_Reester_Func[23] != 0)
        assigningNewAddress(isd[23],(DWORD)&RegDeleteKeyTransactedAInt);
    if (adr_Reester_Func[24] != 0)
        assigningNewAddress(isd[24],(DWORD)&RegDeleteKeyTransactedWInt);
    if (adr_Reester_Func[25] != 0)
        assigningNewAddress(isd[25],(DWORD)&RegDisableReflectionKeyInt);
    if (adr_Reester_Func[26] != 0)
        assigningNewAddress(isd[26],(DWORD)&RegEnableReflectionKeyInt);
    if (adr_Reester_Func[27] != 0)
        assigningNewAddress(isd[27],(DWORD)&RegQueryReflectionKeyInt);
    if (adr_Reester_Func[28] != 0)
        assigningNewAddress(isd[28],(DWORD)&RegDeleteValueAInt);
    if (adr_Reester_Func[29] != 0)
        assigningNewAddress(isd[29],(DWORD)&RegDeleteValueWInt);
    if (adr_Reester_Func[30] != 0)
        assigningNewAddress(isd[30],(DWORD)&RegEnumKeyAInt);
    if (adr_Reester_Func[31] != 0)
        assigningNewAddress(isd[31],(DWORD)&RegEnumKeyWInt);
    if (adr_Reester_Func[32] != 0)
        assigningNewAddress(isd[32],(DWORD)&RegEnumKeyExAInt);
    if (adr_Reester_Func[33] != 0)
        assigningNewAddress(isd[33],(DWORD)&RegEnumKeyExWInt);
    if (adr_Reester_Func[34] != 0)
        assigningNewAddress(isd[34],(DWORD)&RegEnumValueAInt);
    if (adr_Reester_Func[35] != 0)
        assigningNewAddress(isd[35],(DWORD)&RegEnumValueWInt);
    if (adr_Reester_Func[36] != 0)
        assigningNewAddress(isd[36],(DWORD)&RegFlushKeyInt);
    if (adr_Reester_Func[37] != 0)
        assigningNewAddress(isd[37],(DWORD)&RegGetKeySecurityInt);
    if (adr_Reester_Func[38] != 0)
        assigningNewAddress(isd[38],(DWORD)&RegLoadKeyAInt);
    if (adr_Reester_Func[39] != 0)
        assigningNewAddress(isd[39],(DWORD)&RegLoadKeyWInt);
    if (adr_Reester_Func[40] != 0)
        assigningNewAddress(isd[40],(DWORD)&RegNotifyChangeKeyValueInt);
    if (adr_Reester_Func[41] != 0)
        assigningNewAddress(isd[41],(DWORD)&RegOpenKeyAInt);
    if (adr_Reester_Func[42] != 0)
        assigningNewAddress(isd[42],(DWORD)&RegOpenKeyWInt);
    if (adr_Reester_Func[43] != 0)
        assigningNewAddress(isd[43],(DWORD)&RegOpenKeyExAInt);
    if (adr_Reester_Func[44] != 0)
        assigningNewAddress(isd[44],(DWORD)&RegOpenKeyExWInt);
    if (adr_Reester_Func[45] != 0)
        assigningNewAddress(isd[45],(DWORD)&RegOpenKeyTransactedAInt);
    if (adr_Reester_Func[46] != 0)
        assigningNewAddress(isd[46],(DWORD)&RegOpenKeyTransactedWInt);
    if (adr_Reester_Func[47] != 0)
        assigningNewAddress(isd[47],(DWORD)&RegQueryInfoKeyAInt);
    if (adr_Reester_Func[48] != 0)
        assigningNewAddress(isd[48],(DWORD)&RegQueryInfoKeyWInt);
    if (adr_Reester_Func[49] != 0)
        assigningNewAddress(isd[49],(DWORD)&RegQueryValueAInt);
    if (adr_Reester_Func[50] != 0)
        assigningNewAddress(isd[50],(DWORD)&RegQueryValueWInt);
    if (adr_Reester_Func[51] != 0)
        assigningNewAddress(isd[51],(DWORD)&RegQueryMultipleValuesAInt);
    if (adr_Reester_Func[52] != 0)
        assigningNewAddress(isd[52],(DWORD)&RegQueryMultipleValuesWInt);
    if (adr_Reester_Func[53] != 0)
        assigningNewAddress(isd[53],(DWORD)&RegQueryValueExAInt);
    if (adr_Reester_Func[54] != 0)
        assigningNewAddress(isd[54],(DWORD)&RegQueryValueExWInt);
    if (adr_Reester_Func[55] != 0)
        assigningNewAddress(isd[55],(DWORD)&RegReplaceKeyAInt);
    if (adr_Reester_Func[56] != 0)
        assigningNewAddress(isd[56],(DWORD)&RegReplaceKeyWInt);
    if (adr_Reester_Func[57] != 0)
        assigningNewAddress(isd[57],(DWORD)&RegRestoreKeyAInt);
    if (adr_Reester_Func[58] != 0)
        assigningNewAddress(isd[58],(DWORD)&RegRestoreKeyWInt);
    if (adr_Reester_Func[59] != 0)
        assigningNewAddress(isd[59],(DWORD)&RegRenameKeyInt);
    if (adr_Reester_Func[60] != 0)
        assigningNewAddress(isd[60],(DWORD)&RegSaveKeyAInt);
    if (adr_Reester_Func[61] != 0)
        assigningNewAddress(isd[61],(DWORD)&RegSaveKeyWInt);
    if (adr_Reester_Func[62] != 0)
        assigningNewAddress(isd[62],(DWORD)&RegSetKeySecurityInt);
    if (adr_Reester_Func[63] != 0)
        assigningNewAddress(isd[63],(DWORD)&RegSetValueAInt);
    if (adr_Reester_Func[64] != 0)
        assigningNewAddress(isd[64],(DWORD)&RegSetValueWInt);
    if (adr_Reester_Func[65] != 0)
        assigningNewAddress(isd[65],(DWORD)&RegSetValueExAInt);
    if (adr_Reester_Func[66] != 0)
        assigningNewAddress(isd[66],(DWORD)&RegSetValueExWInt);
    if (adr_Reester_Func[67] != 0)
        assigningNewAddress(isd[67],(DWORD)&RegUnLoadKeyAInt);
    if (adr_Reester_Func[68] != 0)
        assigningNewAddress(isd[68],(DWORD)&RegUnLoadKeyWInt);
    if (adr_Reester_Func[69] != 0)
        assigningNewAddress(isd[69],(DWORD)&RegDeleteKeyValueAInt);
    if (adr_Reester_Func[70] != 0)
        assigningNewAddress(isd[70],(DWORD)&RegDeleteKeyValueWInt);
    if (adr_Reester_Func[71] != 0)
        assigningNewAddress(isd[71],(DWORD)&RegSetKeyValueAInt);
    if (adr_Reester_Func[72] != 0)
        assigningNewAddress(isd[72],(DWORD)&RegSetKeyValueWInt);
    if (adr_Reester_Func[73] != 0)
        assigningNewAddress(isd[73],(DWORD)&RegDeleteTreeAInt);
    if (adr_Reester_Func[74] != 0)
        assigningNewAddress(isd[74],(DWORD)&RegDeleteTreeWInt);
    if (adr_Reester_Func[75] != 0)
        assigningNewAddress(isd[75],(DWORD)&RegGetValueAInt);
    if (adr_Reester_Func[76] != 0)
        assigningNewAddress(isd[76],(DWORD)&RegGetValueWInt);
    if (adr_Reester_Func[77] != 0)
        assigningNewAddress(isd[77],(DWORD)&RegLoadMUIStringAInt);
    if (adr_Reester_Func[78] != 0)
        assigningNewAddress(isd[78],(DWORD)&RegLoadMUIStringWInt);
    if (adr_Reester_Func[79] != 0)
        assigningNewAddress(isd[79],(DWORD)&RegLoadAppKeyAInt);
    if (adr_Reester_Func[80] != 0)
        assigningNewAddress(isd[80],(DWORD)&RegLoadAppKeyWInt);
    if (adr_Reester_Func[81] != 0)
        assigningNewAddress(isd[81],(DWORD)&RegDisablePredefinedCacheInt);
    if (adr_Reester_Func[82] != 0)
        assigningNewAddress(isd[82],(DWORD)&RegDisablePredefinedCacheExInt);
    if (adr_Reester_Func[83] != 0)
        assigningNewAddress(isd[83],(DWORD)&RegOverridePredefKeyInt);
    if (adr_Reester_Func[84] != 0)
        assigningNewAddress(isd[84],(DWORD)&RegOpenUserClassesRootInt);
    if (adr_Reester_Func[85] != 0)
        assigningNewAddress(isd[85],(DWORD)&RegOpenCurrentUserInt);
    if (adr_Reester_Func[86] != 0)
        assigningNewAddress(isd[86],(DWORD)&RegConnectRegistryExAInt);
    if (adr_Reester_Func[87] != 0)
        assigningNewAddress(isd[87],(DWORD)&RegConnectRegistryExWInt);
    if (adr_Reester_Func[88] != 0)
        assigningNewAddress(isd[88],(DWORD)&CheckForHiberbootInt);
    if (adr_Reester_Func[89] != 0)
        assigningNewAddress(isd[89],(DWORD)&RegSaveKeyExAInt);
    if (adr_Reester_Func[90] != 0)
        assigningNewAddress(isd[90],(DWORD)&RegSaveKeyExWInt);
    return;
 
}

BOOL APIENTRY AbortSystemShutdownAInt(_In_opt_ LPSTR lpMachineName) {
    
    WriteInfoInFile("AbortSystemShutdownA", lpMachineName);
    auto res = ((BOOL(__stdcall*)(LPSTR))adr_Reester_Func[0])(lpMachineName);
    return res;
}

BOOL APIENTRY AbortSystemShutdownWInt(_In_opt_ LPWSTR lpMachineName){
    WriteInfoInFile("AbortSystemShutdownW", lpMachineName);

    auto res = ((BOOL(__stdcall*)(LPWSTR))adr_Reester_Func[1])(lpMachineName);
    return res;
}

DWORD APIENTRY InitiateShutdownAInt(_In_opt_ LPSTR lpMachineName, _In_opt_ LPSTR lpMessage, _In_ DWORD dwGracePeriod, _In_ DWORD dwShutdownFlags, _In_     DWORD dwReason) {
    WriteInfoInFile("InitiateShutdownA", lpMessage);
    auto res = ((DWORD(__stdcall*)( LPSTR , LPSTR , DWORD ,DWORD,DWORD))adr_Reester_Func[2])(lpMachineName,lpMessage,dwGracePeriod,dwShutdownFlags,dwReason);
    return res;
}

DWORD APIENTRY InitiateShutdownWInt(_In_opt_ LPWSTR lpMachineName, _In_opt_ LPWSTR lpMessage, _In_ DWORD dwGracePeriod, _In_ DWORD dwShutdownFlags, _In_     DWORD dwReason) {
    WriteInfoInFile("InitiateShutdownW: ", lpMessage);
    auto res = ((DWORD(__stdcall*)(LPWSTR, LPWSTR, DWORD, DWORD, DWORD))adr_Reester_Func[3])(lpMachineName, lpMessage, dwGracePeriod, dwShutdownFlags, dwReason);
    return res;
}

BOOL APIENTRY InitiateSystemShutdownAInt(_In_opt_ LPSTR lpMachineName, _In_opt_ LPSTR lpMessage, _In_ DWORD dwTimeout, _In_ BOOL bForceAppsClosed, _In_ BOOL bRebootAfterShutdown) {
    WriteInfoInFile("InitiateSystemShutdownA : ", lpMessage);
    auto res = ((BOOL(__stdcall*)(LPSTR, LPSTR, DWORD, BOOL, BOOL))adr_Reester_Func[4])(lpMachineName, lpMessage, dwTimeout, bForceAppsClosed, bRebootAfterShutdown);
    return res;
}

BOOL APIENTRY InitiateSystemShutdownExAInt(_In_opt_ LPSTR lpMachineName, _In_opt_ LPSTR lpMessage, _In_ DWORD dwTimeout, _In_ BOOL bForceAppsClosed, _In_ BOOL bRebootAfterShutdown, _In_ DWORD dwReason) {
    WriteInfoInFile("InitiateSystemShutdownW : ", lpMessage);
    auto res = ((BOOL(__stdcall*)(LPSTR, LPSTR, DWORD, BOOL, BOOL, DWORD))adr_Reester_Func[5])(lpMachineName, lpMessage, dwTimeout, bForceAppsClosed, bRebootAfterShutdown, dwReason);
    return res;
}

BOOL APIENTRY InitiateSystemShutdownExWInt(_In_opt_ LPWSTR lpMachineName, _In_opt_ LPWSTR lpMessage, _In_ DWORD dwTimeout, _In_ BOOL bForceAppsClosed, _In_ BOOL bRebootAfterShutdown, _In_ DWORD dwReason) {
    WriteInfoInFile("InitiateSystemShutdownW : ", lpMessage);
    auto res = ((BOOL(__stdcall*)(LPWSTR, LPWSTR, DWORD, BOOL, BOOL, DWORD))adr_Reester_Func[6])(lpMachineName, lpMessage, dwTimeout, bForceAppsClosed, bRebootAfterShutdown, dwReason);
    return res;
}

BOOL APIENTRY InitiateSystemShutdownWInt(_In_opt_ LPWSTR lpMachineName, _In_opt_ LPWSTR lpMessage, _In_ DWORD dwTimeout, _In_ BOOL bForceAppsClosed, _In_ BOOL bRebootAfterShutdown) {
    WriteInfoInFile("InitiateSystemShutdownW : ", lpMessage);
    auto res = ((BOOL(__stdcall*)(LPWSTR, LPWSTR, DWORD, BOOL, BOOL))adr_Reester_Func[7])(lpMachineName, lpMessage, dwTimeout, bForceAppsClosed, bRebootAfterShutdown);
    return res;
}

LSTATUS APIENTRY RegCloseKeyInt(_In_ HKEY hKey) {

    WriteInfoInFile("Close key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY ))adr_Reester_Func[8])(hKey);
    return res;
}

LSTATUS APIENTRY RegConnectRegistryAInt(_In_opt_ LPCSTR lpMachineName, _In_ HKEY hKey, _Out_ PHKEY phkResult) {
    WriteInfoInFile("Connect key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(LPCSTR, HKEY, PHKEY))adr_Reester_Func[9])(lpMachineName,hKey, phkResult);
    return res;
}

LSTATUS APIENTRY RegConnectRegistryWInt(_In_opt_ LPCWSTR lpMachineName, _In_ HKEY hKey, _Out_ PHKEY phkResult) {
    WriteInfoInFile("Connect key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(LPCWSTR, HKEY, PHKEY))adr_Reester_Func[10])(lpMachineName, hKey, phkResult);
    return res;
}

LSTATUS APIENTRY RegCopyTreeAInt(_In_  HKEY   hKeySrc, _In_opt_  LPCSTR  lpSubKey, _In_   HKEY   hKeyDest) {
    WriteInfoInFile("Copy key: ", hKeySrc);
    auto res = ((LSTATUS(__stdcall*)(HKEY, LPCSTR, HKEY))adr_Reester_Func[11])(hKeySrc, lpSubKey, hKeyDest);
    return res;
}

LSTATUS APIENTRY RegCopyTreeWInt(_In_  HKEY  hKeySrc, _In_opt_   LPCWSTR  lpSubKey, _In_    HKEY     hKeyDest) {
    WriteInfoInFile("Copy key: ", hKeySrc);
    auto res = ((LSTATUS(__stdcall*)(HKEY, LPCWSTR, HKEY))adr_Reester_Func[12])(hKeySrc, lpSubKey, hKeyDest);
    return res;
}

LSTATUS APIENTRY RegCreateKeyAInt(_In_ HKEY hKey, _In_opt_ LPCSTR lpSubKey, _Out_ PHKEY phkResult) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, LPCSTR, PHKEY))adr_Reester_Func[13])(hKey, lpSubKey, phkResult);
    return res;
}

LSTATUS APIENTRY RegCreateKeyExAInt(
    _In_ HKEY hKey,
    _In_ LPCSTR lpSubKey,
    _Reserved_ DWORD Reserved,
    _In_opt_ LPSTR lpClass,
    _In_ DWORD dwOptions,
    _In_ REGSAM samDesired,
    _In_opt_ CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _Out_ PHKEY phkResult,
    _Out_opt_ LPDWORD lpdwDisposition
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, LPCSTR, DWORD, LPSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES,  PHKEY, LPDWORD))adr_Reester_Func[14])(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition);
    return res;
}

LSTATUS APIENTRY RegCreateKeyExWInt(
    _In_ HKEY hKey,
    _In_ LPCWSTR lpSubKey,
    _Reserved_ DWORD Reserved,
    _In_opt_ LPWSTR lpClass,
    _In_ DWORD dwOptions,
    _In_ REGSAM samDesired,
    _In_opt_ CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _Out_ PHKEY phkResult,
    _Out_opt_ LPDWORD lpdwDisposition
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, LPCWSTR, DWORD, LPWSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD))adr_Reester_Func[15])(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition);
    return res;
}

LSTATUS
APIENTRY
RegCreateKeyTransactedAInt(
    _In_ HKEY hKey,
    _In_ LPCSTR lpSubKey,
    _Reserved_ DWORD Reserved,
    _In_opt_ LPSTR lpClass,
    _In_ DWORD dwOptions,
    _In_ REGSAM samDesired,
    _In_opt_ CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _Out_ PHKEY phkResult,
    _Out_opt_ LPDWORD lpdwDisposition,
    _In_        HANDLE hTransaction,
    _Reserved_ PVOID  pExtendedParemeter
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, LPCSTR, DWORD, LPSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD, HANDLE, PVOID))adr_Reester_Func[16])(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition, hTransaction, pExtendedParemeter);
    return res;
}

LSTATUS
APIENTRY
RegCreateKeyTransactedWInt(
    _In_ HKEY hKey,
    _In_ LPCWSTR lpSubKey,
    _Reserved_ DWORD Reserved,
    _In_opt_ LPWSTR lpClass,
    _In_ DWORD dwOptions,
    _In_ REGSAM samDesired,
    _In_opt_ CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _Out_ PHKEY phkResult,
    _Out_opt_ LPDWORD lpdwDisposition,
    _In_        HANDLE hTransaction,
    _Reserved_ PVOID  pExtendedParemeter
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, LPCWSTR, DWORD, LPWSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD, HANDLE, PVOID))adr_Reester_Func[17])(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition, hTransaction, pExtendedParemeter);
    return res;
}

LSTATUS APIENTRY RegCreateKeyWInt(_In_ HKEY hKey, _In_opt_ LPCWSTR lpSubKey, _Out_ PHKEY phkResult) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, LPCWSTR, PHKEY))adr_Reester_Func[18])(hKey, lpSubKey, phkResult);
    return res;
}

LSTATUS
APIENTRY
RegDeleteKeyAInt(
    _In_ HKEY hKey,
    _In_ LPCSTR lpSubKey
) {
WriteInfoInFile("Delete key: ", hKey);
auto res = ((LSTATUS(__stdcall*)(HKEY, LPCSTR))adr_Reester_Func[19])(hKey, lpSubKey);
return res;
}

LSTATUS
APIENTRY
RegDeleteKeyWInt(
    _In_ HKEY hKey,
    _In_ LPCWSTR lpSubKey
) {
WriteInfoInFile("Delete key: ", hKey);
auto res = ((LSTATUS(__stdcall*)(HKEY, LPCWSTR))adr_Reester_Func[20])(hKey, lpSubKey);
return res;
}

LSTATUS
APIENTRY
RegDeleteKeyExAInt(
    _In_ HKEY hKey,
    _In_ LPCSTR lpSubKey,
    _In_ REGSAM samDesired,
    _Reserved_ DWORD Reserved
){
    WriteInfoInFile("Delete key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, LPCSTR, REGSAM, DWORD))adr_Reester_Func[21])(hKey, lpSubKey, samDesired, Reserved);
    return res;
}

LSTATUS
APIENTRY
RegDeleteKeyExWInt(
    _In_ HKEY hKey,
    _In_ LPCWSTR lpSubKey,
    _In_ REGSAM samDesired,
    _Reserved_ DWORD Reserved
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, LPCWSTR, REGSAM, DWORD))adr_Reester_Func[22])(hKey, lpSubKey, samDesired, Reserved);
    return res;
}

LSTATUS
APIENTRY
RegDeleteKeyTransactedAInt(
    _In_ HKEY hKey,
    _In_ LPCSTR lpSubKey,
    _In_ REGSAM samDesired,
    _Reserved_ DWORD Reserved,
    _In_        HANDLE hTransaction,
    _Reserved_ PVOID  pExtendedParameter
) {
    WriteInfoInFile("Delete key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, LPCSTR, REGSAM, DWORD, HANDLE, PVOID))adr_Reester_Func[23])(hKey, lpSubKey, samDesired, Reserved, hTransaction, pExtendedParameter);
    return res;
}
LSTATUS
APIENTRY
RegDeleteKeyTransactedWInt(
    _In_ HKEY hKey,
    _In_ LPCWSTR lpSubKey,
    _In_ REGSAM samDesired,
    _Reserved_ DWORD Reserved,
    _In_        HANDLE hTransaction,
    _Reserved_ PVOID  pExtendedParameter
) {
    WriteInfoInFile("Delete key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, LPCWSTR, REGSAM, DWORD, HANDLE, PVOID))adr_Reester_Func[24])(hKey, lpSubKey, samDesired, Reserved, hTransaction, pExtendedParameter);
    return res;
}
LONG
APIENTRY
RegDisableReflectionKeyInt(
    _In_ HKEY hBase
) {
    WriteInfoInFile("Disable key: ", hBase);
    auto res = ((LONG(__stdcall*)(HKEY))adr_Reester_Func[25])(hBase);
    return res;
}
LONG
APIENTRY
RegEnableReflectionKeyInt(
    _In_ HKEY hBase
) {
    WriteInfoInFile("Create key: ", hBase);
    auto res = ((LONG(__stdcall*)(HKEY))adr_Reester_Func[26])(hBase);
    return res;
}
LONG
APIENTRY
RegQueryReflectionKeyInt(
    _In_ HKEY hBase,
    _Out_ BOOL* bIsReflectionDisabled
) {
    WriteInfoInFile("Create key: ", hBase);
    auto res = ((LONG(__stdcall*)(HKEY, BOOL*))adr_Reester_Func[27])(hBase, bIsReflectionDisabled);
    return res;
}
LSTATUS
APIENTRY
RegDeleteValueAInt(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpValueName
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, LPCSTR))adr_Reester_Func[28])(hKey, lpValueName);
    return res;
}
LSTATUS
APIENTRY
RegDeleteValueWInt(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpValueName
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, LPCWSTR))adr_Reester_Func[29])(hKey, lpValueName);
    return res;
}
LSTATUS
APIENTRY
RegEnumKeyAInt(
    _In_ HKEY hKey,
    _In_ DWORD dwIndex,
    _Out_writes_opt_(cchName) LPSTR lpName,
    _In_ DWORD cchName
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, DWORD, LPSTR, DWORD))adr_Reester_Func[30])(hKey, dwIndex, lpName, cchName);
    return res;
}
LSTATUS
APIENTRY
RegEnumKeyWInt(
    _In_ HKEY hKey,
    _In_ DWORD dwIndex,
    _Out_writes_opt_(cchName) LPWSTR lpName,
    _In_ DWORD cchName
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, DWORD, LPWSTR, DWORD))adr_Reester_Func[31])(hKey, dwIndex, lpName, cchName);
    return res;
}
LSTATUS
APIENTRY
RegEnumKeyExAInt(
    _In_ HKEY hKey,
    _In_ DWORD dwIndex,
    _Out_writes_to_opt_(*lpcchName, *lpcchName + 1) LPSTR lpName,
    _Inout_ LPDWORD lpcchName,
    _Reserved_ LPDWORD lpReserved,
    _Out_writes_to_opt_(*lpcchClass, *lpcchClass + 1) LPSTR lpClass,
    _Inout_opt_ LPDWORD lpcchClass,
    _Out_opt_ PFILETIME lpftLastWriteTime
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPSTR, LPDWORD, PFILETIME))adr_Reester_Func[32])(hKey, dwIndex, lpName, lpcchName, lpReserved, lpClass, lpcchClass, lpftLastWriteTime);
    return res;
}
LSTATUS
APIENTRY
RegEnumKeyExWInt(
    _In_ HKEY hKey,
    _In_ DWORD dwIndex,
    _Out_writes_to_opt_(*lpcchName, *lpcchName + 1) LPWSTR lpName,
    _Inout_ LPDWORD lpcchName,
    _Reserved_ LPDWORD lpReserved,
    _Out_writes_to_opt_(*lpcchClass, *lpcchClass + 1) LPWSTR lpClass,
    _Inout_opt_ LPDWORD lpcchClass,
    _Out_opt_ PFILETIME lpftLastWriteTime
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, DWORD, LPWSTR, LPDWORD, LPDWORD, LPWSTR, LPDWORD, PFILETIME))adr_Reester_Func[33])(hKey, dwIndex, lpName, lpcchName, lpReserved, lpClass, lpcchClass, lpftLastWriteTime);
    return res;
}
LSTATUS
APIENTRY
RegEnumValueAInt(
    _In_ HKEY hKey,
    _In_ DWORD dwIndex,
    _Out_writes_to_opt_(*lpcchValueName, *lpcchValueName + 1) LPSTR lpValueName,
    _Inout_ LPDWORD lpcchValueName,
    _Reserved_ LPDWORD lpReserved,
    _Out_opt_ LPDWORD lpType,
    _Out_writes_bytes_to_opt_(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPBYTE lpData,
    _Inout_opt_ LPDWORD lpcbData
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPDWORD, LPBYTE, LPDWORD))adr_Reester_Func[34])(hKey, dwIndex, lpValueName, lpcchValueName, lpReserved, lpType, lpData, lpcbData);
    return res;
}
LSTATUS
APIENTRY
RegEnumValueWInt(
    _In_ HKEY hKey,
    _In_ DWORD dwIndex,
    _Out_writes_to_opt_(*lpcchValueName, *lpcchValueName + 1) LPWSTR lpValueName,
    _Inout_ LPDWORD lpcchValueName,
    _Reserved_ LPDWORD lpReserved,
    _Out_opt_ LPDWORD lpType,
    _Out_writes_bytes_to_opt_(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPBYTE lpData,
    _Inout_opt_ LPDWORD lpcbData
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, DWORD, LPWSTR, LPDWORD, LPDWORD, LPDWORD, LPBYTE, LPDWORD))adr_Reester_Func[35])(hKey, dwIndex, lpValueName, lpcchValueName, lpReserved, lpType, lpData, lpcbData);
    return res;
}
LSTATUS
APIENTRY
RegFlushKeyInt(
    _In_ HKEY hKey
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY))adr_Reester_Func[36])(hKey);
    return res;
}
LSTATUS
APIENTRY
RegGetKeySecurityInt(
    _In_ HKEY hKey,
    _In_ SECURITY_INFORMATION SecurityInformation,
    _Out_writes_bytes_opt_(*lpcbSecurityDescriptor) PSECURITY_DESCRIPTOR pSecurityDescriptor,
    _Inout_ LPDWORD lpcbSecurityDescriptor
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, LPDWORD))adr_Reester_Func[37])(hKey, SecurityInformation, pSecurityDescriptor, lpcbSecurityDescriptor);
    return res;
}
LSTATUS
APIENTRY
RegLoadKeyAInt(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey,
    _In_ LPCSTR lpFile
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, LPCSTR, LPCSTR))adr_Reester_Func[38])(hKey, lpSubKey, lpFile);
    return res;
}
LSTATUS
APIENTRY
RegLoadKeyWInt(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey,
    _In_ LPCWSTR lpFile
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, LPCWSTR, LPCWSTR))adr_Reester_Func[39])(hKey, lpSubKey, lpFile);
    return res;
}
LSTATUS
APIENTRY
RegNotifyChangeKeyValueInt(
    _In_ HKEY hKey,
    _In_ BOOL bWatchSubtree,
    _In_ DWORD dwNotifyFilter,
    _In_opt_ HANDLE hEvent,
    _In_ BOOL fAsynchronous
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, BOOL, DWORD, HANDLE, BOOL))adr_Reester_Func[40])(hKey, bWatchSubtree, dwNotifyFilter, hEvent, fAsynchronous);
    return res;
}
LSTATUS
APIENTRY
RegOpenKeyAInt(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey,
    _Out_ PHKEY phkResult
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, LPCSTR, PHKEY))adr_Reester_Func[41])(hKey, lpSubKey, phkResult);
    return res;
}
LSTATUS
APIENTRY
RegOpenKeyWInt(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey,
    _Out_ PHKEY phkResult
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, LPCWSTR, PHKEY))adr_Reester_Func[42])(hKey, lpSubKey, phkResult);
    return res;
}
LSTATUS
APIENTRY
RegOpenKeyExAInt(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey,
    _In_opt_ DWORD ulOptions,
    _In_ REGSAM samDesired,
    _Out_ PHKEY phkResult
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY))adr_Reester_Func[43])(hKey, lpSubKey, ulOptions, samDesired, phkResult);
    return res;
}
LSTATUS
APIENTRY
RegOpenKeyExWInt(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey,
    _In_opt_ DWORD ulOptions,
    _In_ REGSAM samDesired,
    _Out_ PHKEY phkResult
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY))adr_Reester_Func[44])(hKey, lpSubKey, ulOptions, samDesired, phkResult);
    return res;
}
LSTATUS
APIENTRY
RegOpenKeyTransactedAInt(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey,
    _In_opt_ DWORD ulOptions,
    _In_ REGSAM samDesired,
    _Out_ PHKEY phkResult,
    _In_        HANDLE hTransaction,
    _Reserved_ PVOID  pExtendedParemeter
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY, HANDLE, PVOID))adr_Reester_Func[45])(hKey, lpSubKey, ulOptions, samDesired,phkResult, hTransaction, pExtendedParemeter);
    return res;
}
LSTATUS
APIENTRY
RegOpenKeyTransactedWInt(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey,
    _In_opt_ DWORD ulOptions,
    _In_ REGSAM samDesired,
    _Out_ PHKEY phkResult,
    _In_        HANDLE hTransaction,
    _Reserved_ PVOID  pExtendedParemeter
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY, HANDLE, PVOID))adr_Reester_Func[46])(hKey, lpSubKey, ulOptions, samDesired, phkResult, hTransaction, pExtendedParemeter);
    return res;
}
LSTATUS
APIENTRY
RegQueryInfoKeyAInt(
    _In_ HKEY hKey,
    _Out_writes_to_opt_(*lpcchClass, *lpcchClass + 1) LPSTR lpClass,
    _Inout_opt_ LPDWORD lpcchClass,
    _Reserved_ LPDWORD lpReserved,
    _Out_opt_ LPDWORD lpcSubKeys,
    _Out_opt_ LPDWORD lpcbMaxSubKeyLen,
    _Out_opt_ LPDWORD lpcbMaxClassLen,
    _Out_opt_ LPDWORD lpcValues,
    _Out_opt_ LPDWORD lpcbMaxValueNameLen,
    _Out_opt_ LPDWORD lpcbMaxValueLen,
    _Out_opt_ LPDWORD lpcbSecurityDescriptor,
    _Out_opt_ PFILETIME lpftLastWriteTime
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, LPSTR, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, PFILETIME))adr_Reester_Func[47])(hKey, lpClass, lpcchClass, lpReserved, lpcSubKeys, lpcbMaxSubKeyLen, lpcbMaxClassLen, lpcValues, lpcbMaxValueNameLen, lpcbMaxValueLen, lpcbSecurityDescriptor, lpftLastWriteTime);
    return res;
}
LSTATUS
APIENTRY
RegQueryInfoKeyWInt(
    _In_ HKEY hKey,
    _Out_writes_to_opt_(*lpcchClass, *lpcchClass + 1) LPWSTR lpClass,
    _Inout_opt_ LPDWORD lpcchClass,
    _Reserved_ LPDWORD lpReserved,
    _Out_opt_ LPDWORD lpcSubKeys,
    _Out_opt_ LPDWORD lpcbMaxSubKeyLen,
    _Out_opt_ LPDWORD lpcbMaxClassLen,
    _Out_opt_ LPDWORD lpcValues,
    _Out_opt_ LPDWORD lpcbMaxValueNameLen,
    _Out_opt_ LPDWORD lpcbMaxValueLen,
    _Out_opt_ LPDWORD lpcbSecurityDescriptor,
    _Out_opt_ PFILETIME lpftLastWriteTime
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, LPWSTR, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, PFILETIME))adr_Reester_Func[48])(hKey, lpClass, lpcchClass, lpReserved, lpcSubKeys, lpcbMaxSubKeyLen, lpcbMaxClassLen, lpcValues, lpcbMaxValueNameLen, lpcbMaxValueLen, lpcbSecurityDescriptor, lpftLastWriteTime);
    return res;
}
LSTATUS
APIENTRY
RegQueryValueAInt(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey,
    _Out_writes_bytes_to_opt_(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPSTR lpData,
    _Inout_opt_ PLONG lpcbData
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, LPCSTR, LPSTR, PLONG))adr_Reester_Func[49])(hKey, lpSubKey, lpData, lpcbData);
    return res;
}
LSTATUS
APIENTRY
RegQueryValueWInt(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey,
    _Out_writes_bytes_to_opt_(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPWSTR lpData,
    _Inout_opt_ PLONG lpcbData
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, LPCWSTR, LPWSTR, PLONG))adr_Reester_Func[50])(hKey, lpSubKey, lpData, lpcbData);
    return res;
}
LSTATUS
APIENTRY
RegQueryMultipleValuesAInt(
    _In_ HKEY hKey,
    _Out_writes_(num_vals) PVALENTA val_list,
    _In_ DWORD num_vals,
    _Out_writes_bytes_to_opt_(*ldwTotsize, *ldwTotsize) __out_data_source(REGISTRY) LPSTR lpValueBuf,
    _Inout_opt_ LPDWORD ldwTotsize
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, PVALENTA, DWORD, LPSTR, LPDWORD))adr_Reester_Func[51])(hKey, val_list,num_vals, lpValueBuf, ldwTotsize);
    return res;
}
LSTATUS
APIENTRY
RegQueryMultipleValuesWInt(
    _In_ HKEY hKey,
    _Out_writes_(num_vals) PVALENTW val_list,
    _In_ DWORD num_vals,
    _Out_writes_bytes_to_opt_(*ldwTotsize, *ldwTotsize) __out_data_source(REGISTRY) LPWSTR lpValueBuf,
    _Inout_opt_ LPDWORD ldwTotsize
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, PVALENTW, DWORD, LPWSTR, LPDWORD))adr_Reester_Func[52])(hKey, val_list, num_vals, lpValueBuf, ldwTotsize);
    return res;
}
LSTATUS
APIENTRY
RegQueryValueExAInt(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpValueName,
    _Reserved_ LPDWORD lpReserved,
    _Out_opt_ LPDWORD lpType,
    _Out_writes_bytes_to_opt_(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPBYTE lpData,
    _When_(lpData == NULL, _Out_opt_) _When_(lpData != NULL, _Inout_opt_) LPDWORD lpcbData
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD))adr_Reester_Func[53])(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
    return res;
}
LSTATUS
APIENTRY
RegQueryValueExWInt(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpValueName,
    _Reserved_ LPDWORD lpReserved,
    _Out_opt_ LPDWORD lpType,
    _Out_writes_bytes_to_opt_(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPBYTE lpData,
    _When_(lpData == NULL, _Out_opt_) _When_(lpData != NULL, _Inout_opt_) LPDWORD lpcbData
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD))adr_Reester_Func[54])(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
    return res;
}
LSTATUS
APIENTRY
RegReplaceKeyAInt(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey,
    _In_ LPCSTR lpNewFile,
    _In_ LPCSTR lpOldFile
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, LPCSTR, LPCSTR, LPCSTR))adr_Reester_Func[55])(hKey, lpSubKey, lpNewFile, lpOldFile);
    return res;
}
LSTATUS
APIENTRY
RegReplaceKeyWInt(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey,
    _In_ LPCWSTR lpNewFile,
    _In_ LPCWSTR lpOldFile
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, LPCWSTR, LPCWSTR, LPCWSTR))adr_Reester_Func[56])(hKey, lpSubKey, lpNewFile, lpOldFile);
    return res;
}
LSTATUS
APIENTRY
RegRestoreKeyAInt(
    _In_ HKEY hKey,
    _In_ LPCSTR lpFile,
    _In_ DWORD dwFlags
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, LPCSTR, DWORD))adr_Reester_Func[57])(hKey, lpFile, dwFlags);
    return res;
}
LSTATUS
APIENTRY
RegRestoreKeyWInt(
    _In_ HKEY hKey,
    _In_ LPCWSTR lpFile,
    _In_ DWORD dwFlags
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, LPCWSTR, DWORD))adr_Reester_Func[58])(hKey, lpFile, dwFlags);
    return res;
}
LSTATUS
APIENTRY
RegRenameKeyInt(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKeyName,
    _In_ LPCWSTR lpNewKeyName
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, LPCWSTR, LPCWSTR))adr_Reester_Func[59])(hKey, lpSubKeyName, lpNewKeyName);
    return res;
}
LSTATUS
APIENTRY
RegSaveKeyAInt(
    _In_ HKEY hKey,
    _In_ LPCSTR lpFile,
    _In_opt_ CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, LPCSTR, LPSECURITY_ATTRIBUTES))adr_Reester_Func[60])(hKey, lpFile, lpSecurityAttributes);
    return res;
}
LSTATUS
APIENTRY
RegSaveKeyWInt(
    _In_ HKEY hKey,
    _In_ LPCWSTR lpFile,
    _In_opt_ CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, LPCWSTR, LPSECURITY_ATTRIBUTES))adr_Reester_Func[61])(hKey, lpFile, lpSecurityAttributes);
    return res;
}
LSTATUS
APIENTRY
RegSetKeySecurityInt(
    _In_ HKEY hKey,
    _In_ SECURITY_INFORMATION SecurityInformation,
    _In_ PSECURITY_DESCRIPTOR pSecurityDescriptor
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR))adr_Reester_Func[62])(hKey, SecurityInformation, pSecurityDescriptor);
    return res;
}
LSTATUS
APIENTRY
RegSetValueAInt(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey,
    _In_ DWORD dwType,
    _In_reads_bytes_opt_(cbData) LPCSTR lpData,
    _In_ DWORD cbData
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, LPCSTR, DWORD, LPCSTR, DWORD))adr_Reester_Func[63])(hKey, lpSubKey, dwType, lpData, cbData);
    return res;
}
LSTATUS
APIENTRY
RegSetValueWInt(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey,
    _In_ DWORD dwType,
    _In_reads_bytes_opt_(cbData) LPCWSTR lpData,
    _In_ DWORD cbData
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, LPCWSTR, DWORD, LPCWSTR, DWORD))adr_Reester_Func[64])(hKey, lpSubKey, dwType, lpData, cbData);
    return res;
}
LSTATUS
APIENTRY
RegSetValueExAInt(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpValueName,
    _Reserved_ DWORD Reserved,
    _In_ DWORD dwType,
    _In_reads_bytes_opt_(cbData) CONST BYTE* lpData,
    _In_ DWORD cbData
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)( HKEY, LPCSTR, DWORD, DWORD,const BYTE*, DWORD))adr_Reester_Func[65])(hKey, lpValueName, Reserved, dwType, lpData, cbData);
    return res;
}
LSTATUS
APIENTRY
RegSetValueExWInt(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpValueName,
    _Reserved_ DWORD Reserved,
    _In_ DWORD dwType,
    _In_reads_bytes_opt_(cbData) CONST BYTE* lpData,
    _In_ DWORD cbData
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, LPCWSTR, DWORD, DWORD, const BYTE*, DWORD))adr_Reester_Func[66])(hKey, lpValueName, Reserved, dwType, lpData, cbData);
    return res;
}
LSTATUS
APIENTRY
RegUnLoadKeyAInt(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, LPCSTR))adr_Reester_Func[67])(hKey, lpSubKey);
    return res;
}
LSTATUS
APIENTRY
RegUnLoadKeyWInt(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, LPCWSTR))adr_Reester_Func[68])(hKey, lpSubKey);
    return res;
}
LSTATUS
APIENTRY
RegDeleteKeyValueAInt(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey,
    _In_opt_ LPCSTR lpValueName
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, LPCSTR, LPCSTR))adr_Reester_Func[69])(hKey, lpSubKey, lpValueName);
    return res;
}
LSTATUS
APIENTRY
RegDeleteKeyValueWInt(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey,
    _In_opt_ LPCWSTR lpValueName
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, LPCWSTR, LPCWSTR))adr_Reester_Func[70])(hKey, lpSubKey, lpValueName);
    return res;
}
LSTATUS
APIENTRY
RegSetKeyValueAInt(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey,
    _In_opt_ LPCSTR lpValueName,
    _In_ DWORD dwType,
    _In_reads_bytes_opt_(cbData) LPCVOID lpData,
    _In_ DWORD cbData
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, LPCSTR, LPCSTR, DWORD, LPCVOID, DWORD))adr_Reester_Func[71])(hKey, lpSubKey, lpValueName, dwType, lpData, cbData);
    return res;
}
LSTATUS
APIENTRY
RegSetKeyValueWInt(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey,
    _In_opt_ LPCWSTR lpValueName,
    _In_ DWORD dwType,
    _In_reads_bytes_opt_(cbData) LPCVOID lpData,
    _In_ DWORD cbData
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, LPCWSTR, LPCWSTR, DWORD, LPCVOID, DWORD))adr_Reester_Func[72])(hKey, lpSubKey, lpValueName, dwType, lpData, cbData);
    return res;
}
LSTATUS
APIENTRY
RegDeleteTreeAInt(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, LPCSTR))adr_Reester_Func[73])(hKey, lpSubKey);
    return res;
}
LSTATUS
APIENTRY
RegDeleteTreeWInt(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, LPCWSTR))adr_Reester_Func[74])(hKey, lpSubKey);
    return res;
}
LSTATUS
APIENTRY
RegGetValueAInt(
    _In_ HKEY hkey,
    _In_opt_ LPCSTR lpSubKey,
    _In_opt_ LPCSTR lpValue,
    _In_ DWORD dwFlags,
    _Out_opt_ LPDWORD pdwType,
    _When_((dwFlags & 0x7F) == RRF_RT_REG_SZ ||
        (dwFlags & 0x7F) == RRF_RT_REG_EXPAND_SZ ||
        (dwFlags & 0x7F) == (RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ) ||
        *pdwType == REG_SZ ||
        *pdwType == REG_EXPAND_SZ, _Post_z_)
    _When_((dwFlags & 0x7F) == RRF_RT_REG_MULTI_SZ ||
        *pdwType == REG_MULTI_SZ, _Post_ _NullNull_terminated_)
    _Out_writes_bytes_to_opt_(*pcbData, *pcbData) PVOID pvData,
    _Inout_opt_ LPDWORD pcbData
) {
    WriteInfoInFile("Create key: ", hkey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, LPCSTR, LPCSTR, DWORD, LPDWORD, PVOID, LPDWORD))adr_Reester_Func[75])(hkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData);
    return res;
}
LSTATUS
APIENTRY
RegGetValueWInt(
    _In_ HKEY hkey,
    _In_opt_ LPCWSTR lpSubKey,
    _In_opt_ LPCWSTR lpValue,
    _In_ DWORD dwFlags,
    _Out_opt_ LPDWORD pdwType,
    _When_((dwFlags & 0x7F) == RRF_RT_REG_SZ ||
        (dwFlags & 0x7F) == RRF_RT_REG_EXPAND_SZ ||
        (dwFlags & 0x7F) == (RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ) ||
        *pdwType == REG_SZ ||
        *pdwType == REG_EXPAND_SZ, _Post_z_)
    _When_((dwFlags & 0x7F) == RRF_RT_REG_MULTI_SZ ||
        *pdwType == REG_MULTI_SZ, _Post_ _NullNull_terminated_)
    _Out_writes_bytes_to_opt_(*pcbData, *pcbData) PVOID pvData,
    _Inout_opt_ LPDWORD pcbData
) {
    WriteInfoInFile("Create key: ", hkey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, LPCWSTR, LPCWSTR, DWORD, LPDWORD, PVOID, LPDWORD))adr_Reester_Func[76])(hkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData);
    return res;
}

LSTATUS
APIENTRY
RegLoadMUIStringAInt(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR pszValue,
    _Out_writes_bytes_opt_(cbOutBuf) LPSTR pszOutBuf,
    _In_ DWORD cbOutBuf,
    _Out_opt_ LPDWORD pcbData,
    _In_ DWORD Flags,
    _In_opt_ LPCSTR pszDirectory
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, LPCSTR, LPSTR, DWORD, LPDWORD, DWORD, LPCSTR))adr_Reester_Func[77])(hKey, pszValue, pszOutBuf, cbOutBuf, pcbData, Flags, pszDirectory);
    return res;
}
LSTATUS
APIENTRY
RegLoadMUIStringWInt(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR pszValue,
    _Out_writes_bytes_opt_(cbOutBuf) LPWSTR pszOutBuf,
    _In_ DWORD cbOutBuf,
    _Out_opt_ LPDWORD pcbData,
    _In_ DWORD Flags,
    _In_opt_ LPCWSTR pszDirectory
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, LPCWSTR, LPCWSTR, DWORD, LPDWORD, DWORD, LPCWSTR))adr_Reester_Func[78])(hKey, pszValue, pszOutBuf, cbOutBuf, pcbData, Flags, pszDirectory);
    return res;
}
LSTATUS
APIENTRY
RegLoadAppKeyAInt(
    _In_ LPCSTR lpFile,
    _Out_ PHKEY phkResult,
    _In_ REGSAM samDesired,
    _In_ DWORD dwOptions,
    _Reserved_ DWORD Reserved
) {
    WriteInfoInFile("Create key: ", lpFile);
    auto res = ((LSTATUS(__stdcall*)(LPCSTR, PHKEY, REGSAM, DWORD, DWORD))adr_Reester_Func[79])(lpFile, phkResult, samDesired, dwOptions, Reserved);
    return res;
}
LSTATUS
APIENTRY
RegLoadAppKeyWInt(
    _In_ LPCWSTR lpFile,
    _Out_ PHKEY phkResult,
    _In_ REGSAM samDesired,
    _In_ DWORD dwOptions,
    _Reserved_ DWORD Reserved
) {
    WriteInfoInFile("Create key: ", lpFile);
    auto res = ((LSTATUS(__stdcall*)(LPCWSTR, PHKEY, REGSAM, DWORD, DWORD))adr_Reester_Func[80])(lpFile, phkResult, samDesired, dwOptions, Reserved);
    return res;
}


LSTATUS
APIENTRY
RegDisablePredefinedCacheExInt(
    VOID
){
    WriteInfoInFile("Create key: ", "fdsfd");
    auto res = ((LONG(__stdcall*)(VOID))adr_Reester_Func[81])();
    return res;
}



LSTATUS
APIENTRY
RegDisablePredefinedCacheInt(
    VOID
) {
    WriteInfoInFile("Create key: ", "fsdfd");
    auto res = ((LSTATUS(__stdcall*)(VOID))adr_Reester_Func[82])();
    return res;
}

LSTATUS
APIENTRY
RegOverridePredefKeyInt(
    _In_ HKEY hKey,
    _In_opt_ HKEY hNewHKey
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(HKEY, HKEY))adr_Reester_Func[83])(hKey, hNewHKey);
    return res;
}




LSTATUS
APIENTRY
RegOpenUserClassesRootInt(
    _In_ HANDLE hToken,
    _Reserved_ DWORD dwOptions,
    _In_ REGSAM samDesired,
    _Out_ PHKEY phkResult
) {
    WriteInfoInFile("Create key: ", "fsdf");
    auto res = ((LSTATUS(__stdcall*)(HANDLE, DWORD, REGSAM, PHKEY))adr_Reester_Func[84])(hToken, dwOptions, samDesired, phkResult);
    return res;
}



LSTATUS
APIENTRY
RegOpenCurrentUserInt(
    _In_ REGSAM samDesired,
    _Out_ PHKEY phkResult
) {
    WriteInfoInFile("Create key: ", "sda");
    auto res = ((LSTATUS(__stdcall*)(REGSAM, PHKEY))adr_Reester_Func[85])(samDesired, phkResult);
    return res;
}


LSTATUS
APIENTRY
RegConnectRegistryExAInt(
    _In_opt_ LPCSTR lpMachineName,
    _In_ HKEY hKey,
    _In_ ULONG Flags,
    _Out_ PHKEY phkResult
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(LPCSTR, HKEY, ULONG, PHKEY))adr_Reester_Func[86])(lpMachineName, hKey, Flags, phkResult);
    return res;
}

LSTATUS
APIENTRY
RegConnectRegistryExWInt(
    _In_opt_ LPCWSTR lpMachineName,
    _In_ HKEY hKey,
    _In_ ULONG Flags,
    _Out_ PHKEY phkResult
) {
    WriteInfoInFile("Create key: ", hKey);
    auto res = ((LSTATUS(__stdcall*)(LPCWSTR, HKEY, ULONG, PHKEY))adr_Reester_Func[87])(lpMachineName, hKey, Flags, phkResult);
    return res;
}


DWORD
APIENTRY
CheckForHiberbootInt(
    _Inout_ PBOOLEAN pHiberboot,
    _In_ BOOLEAN bClearFlag
) {
    WriteInfoInFile("Create key: ", "asd");
    auto res = ((LSTATUS(__stdcall*)(PBOOLEAN, BOOLEAN))adr_Reester_Func[88])(pHiberboot, bClearFlag);
    return res;
}


LSTATUS
APIENTRY
RegSaveKeyExAInt(
    _In_ HKEY hKey,
    _In_ LPCSTR lpFile,
    _In_opt_ CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _In_ DWORD Flags
) {
    WriteInfoInFile("Create key: ", "asd");
    auto res = ((LSTATUS(__stdcall*)(HKEY, LPCSTR, CONST LPSECURITY_ATTRIBUTES, DWORD))adr_Reester_Func[89])(hKey, lpFile, lpSecurityAttributes, Flags);
    return res;
}


LSTATUS
APIENTRY
RegSaveKeyExWInt(
    _In_ HKEY hKey,
    _In_ LPCWSTR lpFile,
    _In_opt_ CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _In_ DWORD Flags
) {
    WriteInfoInFile("Create key: ", "asd");
    auto res = ((LSTATUS(__stdcall*)(HKEY, LPCWSTR, CONST LPSECURITY_ATTRIBUTES, DWORD))adr_Reester_Func[90])(hKey, lpFile, lpSecurityAttributes, Flags);
    return res;
}

LPWSTR convertStr(LPCSTR pInStr)
{
	int length = strlen(pInStr);
	wchar_t* pwstr = new wchar_t[length];
	int result = MultiByteToWideChar(
		CP_ACP, MB_PRECOMPOSED, pInStr, length,
		pwstr, length
	);
	pwstr[length] = L'\0';
	return LPWSTR(pwstr);
}
void WriteInfoInFile(const char* firstParam, char* discription) {
    std::ofstream outFile(fileName, std::ios::app);
    if (outFile.is_open())
    {
        outFile << firstParam << discription << std::endl;
    }
    outFile.close();

}
void WriteInfoInFile(const char* firstParam, LPWSTR discription) {
    std::ofstream outFile(fileName, std::ios::app);
    if (outFile.is_open())
    {
        outFile << firstParam << discription << std::endl;
    }
    outFile.close();

}
void WriteInfoInFile(const char* firstParam, HKEY discription) {
    std::ofstream outFile(fileName, std::ios::app);
    if (outFile.is_open())
    {
        outFile << firstParam << discription << std::endl;
    }
    outFile.close();

}
void WriteInfoInFile(const char* firstParam, LPCSTR discription) {
    std::ofstream outFile(fileName, std::ios::app);
    if (outFile.is_open())
    {
        outFile << firstParam << discription << std::endl;
    }
    outFile.close();

}
void WriteInfoInFile(const char* firstParam, LPCWSTR discription) {
    std::ofstream outFile(fileName, std::ios::app);
    if (outFile.is_open())
    {
        outFile << firstParam << discription << std::endl;
    }
    outFile.close();

}