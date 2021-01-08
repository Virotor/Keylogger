#include "pch.h"




void InterceptFunctionsJmp(void) {
    HMODULE  op = GetModuleHandle(convertStr("Advapi32.dll"));
    //сначала получим абсолютный адрес функции для перехвата

    std::ofstream outFile(fileName, std::ios::out);
    if(outFile.is_open())
        outFile.close();

    for (int i = 0; i < adr_Reester_Func.size(); i++) {
        adr_Reester_Func[i] = (DWORD)GetProcAddress(op,
            name_of_func[i]);
        std::cout << name_of_func[i] << std::endl;
        if (adr_Reester_Func[i] == 0)
        {
            break;
        }
    }
        // Зададим машинный код инструкции перехода, который затем впишем 
        // в начало полученного адреса:
   
    if (adr_Reester_Func[0] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[0], (void*)ad[0], reinterpret_cast<void**>(&_Std_ASSA));
    if (adr_Reester_Func[1] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[1], (void*)ad[1], reinterpret_cast<void**>(&_Std_ASSW));
    if (adr_Reester_Func[2] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[2], (void*)ad[2], reinterpret_cast<void**>(&_Std_ISA));
    if (adr_Reester_Func[3] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[3], (void*)ad[3], reinterpret_cast<void**>(&_Std_ISW));
    if (adr_Reester_Func[4] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[4], (void*)ad[4], reinterpret_cast<void**>(&_Std_ISSA));
    if (adr_Reester_Func[5] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[5], (void*)ad[5], reinterpret_cast<void**>(&_Std_ISSEA));
    if (adr_Reester_Func[6] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[6], (void*)ad[6], reinterpret_cast<void**>(&_Std_ISSEW));
    if (adr_Reester_Func[7] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[7], (void*)ad[7], reinterpret_cast<void**>(&_Std_ISSW));
    if (adr_Reester_Func[8] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[8], (void*)ad[8], reinterpret_cast<void**>(&_Std_RCK));
    if (adr_Reester_Func[9] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[9], (void*)ad[9], reinterpret_cast<void**>(&_Std_RCRA));
    if (adr_Reester_Func[10] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[10], (void*)ad[10], reinterpret_cast<void**>(&_Std_RCRW));
    if (adr_Reester_Func[11] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[11], (void*)ad[11], reinterpret_cast<void**>(&_Std_RCTA));
    if (adr_Reester_Func[12] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[12], (void*)ad[12], reinterpret_cast<void**>(&_Std_RCTW));
    if (adr_Reester_Func[13] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[13], (void*)ad[13], reinterpret_cast<void**>(&_Std_RCKA));
    if (adr_Reester_Func[14] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[14], (void*)ad[14], reinterpret_cast<void**>(&_Std_RCKEA));
    if (adr_Reester_Func[15] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[15], (void*)ad[15], reinterpret_cast<void**>(&_Std_RCKEW));
    if (adr_Reester_Func[16] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[16], (void*)ad[16], reinterpret_cast<void**>(&_Std_RCKTA));
    if (adr_Reester_Func[17] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[17], (void*)ad[17], reinterpret_cast<void**>(&_Std_RCKTW));
    if (adr_Reester_Func[18] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[18], (void*)ad[18], reinterpret_cast<void**>(&_Std_RCKW));
    if (adr_Reester_Func[19] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[19], (void*)ad[19], reinterpret_cast<void**>(&_Std_RDKA));
    if (adr_Reester_Func[20] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[20], (void*)ad[20], reinterpret_cast<void**>(&_Std_RDKW));
    if (adr_Reester_Func[21] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[21], (void*)ad[21], reinterpret_cast<void**>(&_Std_RDKEA));
    if (adr_Reester_Func[22] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[22], (void*)ad[22], reinterpret_cast<void**>(&_Std_RDKEW));
    if (adr_Reester_Func[23] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[23], (void*)ad[23], reinterpret_cast<void**>(&_Std_RDKTA));
    if (adr_Reester_Func[24] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[24], (void*)ad[24], reinterpret_cast<void**>(&_Std_RDKTW));
    if (adr_Reester_Func[25] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[25], (void*)ad[25], reinterpret_cast<void**>(&_Std_RDRK));
    if (adr_Reester_Func[26] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[26], (void*)ad[26], reinterpret_cast<void**>(&_Std_RERK));
    if (adr_Reester_Func[27] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[27], (void*)ad[27], reinterpret_cast<void**>(&_Std_RQRK));
    if (adr_Reester_Func[28] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[28], (void*)ad[28], reinterpret_cast<void**>(&_Std_RDVA));
    if (adr_Reester_Func[29] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[29], (void*)ad[29], reinterpret_cast<void**>(&_Std_RDVW));
    if (adr_Reester_Func[30] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[30], (void*)ad[30], reinterpret_cast<void**>(&_Std_REKA));
    if (adr_Reester_Func[31] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[31], (void*)ad[31], reinterpret_cast<void**>(&_Std_REKW));
    if (adr_Reester_Func[32] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[32], (void*)ad[32], reinterpret_cast<void**>(&_Std_REKEA));
    if (adr_Reester_Func[33] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[33], (void*)ad[33], reinterpret_cast<void**>(&_Std_REKEW));
    if (adr_Reester_Func[34] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[34], (void*)ad[34], reinterpret_cast<void**>(&_Std_REVA));
    if (adr_Reester_Func[35] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[35], (void*)ad[35], reinterpret_cast<void**>(&_Std_REVW));
    if (adr_Reester_Func[36] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[36], (void*)ad[36], reinterpret_cast<void**>(&_Std_RFK));
    if (adr_Reester_Func[37] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[37], (void*)ad[37], reinterpret_cast<void**>(&_Std_RGKS));
    if (adr_Reester_Func[38] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[38], (void*)ad[38], reinterpret_cast<void**>(&_Std_RLKA));
    if (adr_Reester_Func[39] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[39], (void*)ad[39], reinterpret_cast<void**>(&_Std_RLKW));
    if (adr_Reester_Func[40] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[40], (void*)ad[40], reinterpret_cast<void**>(&_Std_RNCKV));
    if (adr_Reester_Func[41] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[41], (void*)ad[41], reinterpret_cast<void**>(&_Std_ROKA));
    if (adr_Reester_Func[42] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[42], (void*)ad[42], reinterpret_cast<void**>(&_Std_ROKW));
    if (adr_Reester_Func[43] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[43], (void*)ad[43], reinterpret_cast<void**>(&_Std_ROKEA));
    if (adr_Reester_Func[44] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[44], (void*)ad[44], reinterpret_cast<void**>(&_Std_ROKEW));
    if (adr_Reester_Func[45] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[45], (void*)ad[45], reinterpret_cast<void**>(&_Std_ROKTA));
    if (adr_Reester_Func[46] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[46], (void*)ad[46], reinterpret_cast<void**>(&_Std_ROKTW));
    if (adr_Reester_Func[47] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[47], (void*)ad[47], reinterpret_cast<void**>(&_Std_RQIKA));
    if (adr_Reester_Func[48] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[48], (void*)ad[48], reinterpret_cast<void**>(&_Std_RQIKW));
    if (adr_Reester_Func[49] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[49], (void*)ad[49], reinterpret_cast<void**>(&_Std_RQVA));
    if (adr_Reester_Func[50] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[50], (void*)ad[50], reinterpret_cast<void**>(&_Std_RQVW));
    if (adr_Reester_Func[51] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[51], (void*)ad[51], reinterpret_cast<void**>(&_Std_RQMVA));
    if (adr_Reester_Func[52] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[52], (void*)ad[52], reinterpret_cast<void**>(&_Std_RQMVW));
    if (adr_Reester_Func[53] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[53], (void*)ad[53], reinterpret_cast<void**>(&_Std_RQVEA));
    if (adr_Reester_Func[54] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[54], (void*)ad[54], reinterpret_cast<void**>(&_Std_RQVEW));
    if (adr_Reester_Func[55] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[55], (void*)ad[55], reinterpret_cast<void**>(&_Std_RRKA));
    if (adr_Reester_Func[56] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[56], (void*)ad[56], reinterpret_cast<void**>(&_Std_RRKW));
    if (adr_Reester_Func[57] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[57], (void*)ad[57], reinterpret_cast<void**>(&_Std_RRKAI));
    if (adr_Reester_Func[58] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[58], (void*)ad[58], reinterpret_cast<void**>(&_Std_RRKWI));
    if (adr_Reester_Func[59] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[59], (void*)ad[59], reinterpret_cast<void**>(&_Std_RRK));
    if (adr_Reester_Func[60] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[60], (void*)ad[60], reinterpret_cast<void**>(&_Std_RSKA));
    if (adr_Reester_Func[61] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[61], (void*)ad[61], reinterpret_cast<void**>(&_Std_RSKW));
    if (adr_Reester_Func[62] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[62], (void*)ad[62], reinterpret_cast<void**>(&_Std_RSKS));
    if (adr_Reester_Func[63] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[63], (void*)ad[63], reinterpret_cast<void**>(&_Std_RSVA));
    if (adr_Reester_Func[64] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[64], (void*)ad[64], reinterpret_cast<void**>(&_Std_RSVW));
    if (adr_Reester_Func[65] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[65], (void*)ad[65], reinterpret_cast<void**>(&_Std_RSVEA));
    if (adr_Reester_Func[66] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[66], (void*)ad[66], reinterpret_cast<void**>(&_Std_RSVEW));
    if (adr_Reester_Func[67] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[67], (void*)ad[67], reinterpret_cast<void**>(&_Std_RULKA));
    if (adr_Reester_Func[68] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[68], (void*)ad[68], reinterpret_cast<void**>(&_Std_RULKW));
    if (adr_Reester_Func[69] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[69], (void*)ad[69], reinterpret_cast<void**>(&_Std_RDKVA));
    if (adr_Reester_Func[70] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[70], (void*)ad[70], reinterpret_cast<void**>(&_Std_RDKVW));
    if (adr_Reester_Func[71] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[71], (void*)ad[71], reinterpret_cast<void**>(&_Std_RSKVA));
    if (adr_Reester_Func[72] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[72], (void*)ad[72], reinterpret_cast<void**>(&_Std_RSKVW));
    if (adr_Reester_Func[73] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[73], (void*)ad[73], reinterpret_cast<void**>(&_Std_RDTA));
    if (adr_Reester_Func[74] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[74], (void*)ad[74], reinterpret_cast<void**>(&_Std_RDTW));
    if (adr_Reester_Func[75] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[75], (void*)ad[75], reinterpret_cast<void**>(&_Std_RGVA));
    if (adr_Reester_Func[76] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[76], (void*)ad[76], reinterpret_cast<void**>(&_Std_RGVW));
    if (adr_Reester_Func[77] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[77], (void*)ad[77], reinterpret_cast<void**>(&_Std_RLMSA));
    if (adr_Reester_Func[78] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[78], (void*)ad[78], reinterpret_cast<void**>(&_Std_RLMSW));
    if (adr_Reester_Func[79] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[79], (void*)ad[79], reinterpret_cast<void**>(&_Std_RLAKA));
    if (adr_Reester_Func[80] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[80], (void*)ad[80], reinterpret_cast<void**>(&_Std_RLAKW));
    if (adr_Reester_Func[81] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[81], (void*)ad[81], reinterpret_cast<void**>(&_Std_RDPC));
    if (adr_Reester_Func[82] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[82], (void*)ad[82], reinterpret_cast<void**>(&_Std_RDPCE));
    if (adr_Reester_Func[83] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[83], (void*)ad[83], reinterpret_cast<void**>(&_Std_ROPK));
    if (adr_Reester_Func[84] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[84], (void*)ad[84], reinterpret_cast<void**>(&_Std_ROUCR));
    if (adr_Reester_Func[85] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[85], (void*)ad[85], reinterpret_cast<void**>(&_Std_ROCU));
    if (adr_Reester_Func[86] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[86], (void*)ad[86], reinterpret_cast<void**>(&_Std_RCREA));
    if (adr_Reester_Func[87] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[87], (void*)ad[87], reinterpret_cast<void**>(&_Std_RCREW));
    if (adr_Reester_Func[88] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[88], (void*)ad[88], reinterpret_cast<void**>(&_Std_CFH));
    if (adr_Reester_Func[89] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[89], (void*)ad[89], reinterpret_cast<void**>(&_Std_RSKEA));
    if (adr_Reester_Func[90] != 0)
        Detours::HookFunction((void*)adr_Reester_Func[90], (void*)ad[90], reinterpret_cast<void**>(&_Std_RSKEW));
}

BOOL APIENTRY AbortSystemShutdownAInt(_In_opt_ LPSTR lpMachineName) {
    
    WriteInfoInFile("AbortSystemShutdownA", lpMachineName);
    return _Std_ASSA(lpMachineName);
}

BOOL APIENTRY AbortSystemShutdownWInt(_In_opt_ LPWSTR lpMachineName){
    WriteInfoInFile("AbortSystemShutdownW", lpMachineName);
    return _Std_ASSW(lpMachineName);
}

DWORD APIENTRY InitiateShutdownAInt(_In_opt_ LPSTR lpMachineName, _In_opt_ LPSTR lpMessage, _In_ DWORD dwGracePeriod, _In_ DWORD dwShutdownFlags, _In_     DWORD dwReason) {
    WriteInfoInFile("InitiateShutdownA", lpMessage);
    return _Std_ISA(lpMachineName,lpMessage,dwGracePeriod,dwShutdownFlags,dwReason);
}

DWORD APIENTRY InitiateShutdownWInt(_In_opt_ LPWSTR lpMachineName, _In_opt_ LPWSTR lpMessage, _In_ DWORD dwGracePeriod, _In_ DWORD dwShutdownFlags, _In_     DWORD dwReason) {
    WriteInfoInFile("InitiateShutdownW: ", lpMessage);
    return _Std_ISW(lpMachineName, lpMessage, dwGracePeriod, dwShutdownFlags, dwReason);
}

BOOL APIENTRY InitiateSystemShutdownAInt(_In_opt_ LPSTR lpMachineName, _In_opt_ LPSTR lpMessage, _In_ DWORD dwTimeout, _In_ BOOL bForceAppsClosed, _In_ BOOL bRebootAfterShutdown) {
    WriteInfoInFile("InitiateSystemShutdownA : ", lpMessage);
    return _Std_ISSA(lpMachineName, lpMessage, dwTimeout, bForceAppsClosed, bRebootAfterShutdown);
}

BOOL APIENTRY InitiateSystemShutdownExAInt(_In_opt_ LPSTR lpMachineName, _In_opt_ LPSTR lpMessage, _In_ DWORD dwTimeout, _In_ BOOL bForceAppsClosed, _In_ BOOL bRebootAfterShutdown, _In_ DWORD dwReason) {
    WriteInfoInFile("InitiateSystemShutdownW : ", lpMessage);
    return _Std_ISSEA(lpMachineName, lpMessage, dwTimeout, bForceAppsClosed, bRebootAfterShutdown, dwReason);
 
}

BOOL APIENTRY InitiateSystemShutdownExWInt(_In_opt_ LPWSTR lpMachineName, _In_opt_ LPWSTR lpMessage, _In_ DWORD dwTimeout, _In_ BOOL bForceAppsClosed, _In_ BOOL bRebootAfterShutdown, _In_ DWORD dwReason) {
    WriteInfoInFile("InitiateSystemShutdownW : ", lpMessage);
    return _Std_ISSEW(lpMachineName, lpMessage, dwTimeout, bForceAppsClosed, bRebootAfterShutdown, dwReason);
}

BOOL APIENTRY InitiateSystemShutdownWInt(_In_opt_ LPWSTR lpMachineName, _In_opt_ LPWSTR lpMessage, _In_ DWORD dwTimeout, _In_ BOOL bForceAppsClosed, _In_ BOOL bRebootAfterShutdown) {
    WriteInfoInFile("InitiateSystemShutdownW : ", lpMessage);
    return _Std_ISSW(lpMachineName, lpMessage, dwTimeout, bForceAppsClosed, bRebootAfterShutdown);
}

LSTATUS APIENTRY RegCloseKeyInt(_In_ HKEY hKey) {

    WriteInfoInFile("Close key: ", hKey);
    return _Std_RCK(hKey);
}

LSTATUS APIENTRY RegConnectRegistryAInt(_In_opt_ LPCSTR lpMachineName, _In_ HKEY hKey, _Out_ PHKEY phkResult) {
    WriteInfoInFile("Connect key: ", hKey);
    return _Std_RCRA(lpMachineName,hKey, phkResult);
}

LSTATUS APIENTRY RegConnectRegistryWInt(_In_opt_ LPCWSTR lpMachineName, _In_ HKEY hKey, _Out_ PHKEY phkResult) {
    WriteInfoInFile("Connect key: ", hKey);
    return _Std_RCRW(lpMachineName, hKey, phkResult);
}

LSTATUS APIENTRY RegCopyTreeAInt(_In_  HKEY   hKeySrc, _In_opt_  LPCSTR  lpSubKey, _In_   HKEY   hKeyDest) {
    WriteInfoInFile("CopyTree key: ", hKeySrc);
    return _Std_RCTA(hKeySrc, lpSubKey, hKeyDest);
}

LSTATUS APIENTRY RegCopyTreeWInt(_In_  HKEY  hKeySrc, _In_opt_   LPCWSTR  lpSubKey, _In_    HKEY     hKeyDest) {
    WriteInfoInFile("CopyTree key: ", hKeySrc);
    return _Std_RCTW(hKeySrc, lpSubKey, hKeyDest);
}

LSTATUS APIENTRY RegCreateKeyAInt(_In_ HKEY hKey, _In_opt_ LPCSTR lpSubKey, _Out_ PHKEY phkResult) {
    WriteInfoInFile("Create key: ", hKey);
    return _Std_RCKA(hKey, lpSubKey, phkResult);

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
    WriteInfoInFile("Create ex key: ", hKey);
    return _Std_RCKEA(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition);
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
    WriteInfoInFile("Create ex key: ", hKey);
    return _Std_RCKEW(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition);
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
    WriteInfoInFile("Create transacted key: ", hKey);
    return _Std_RCKTA(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition, hTransaction, pExtendedParemeter);
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
    WriteInfoInFile("Create transacted key: ", hKey);
    return _Std_RCKTW(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition, hTransaction, pExtendedParemeter);
}

LSTATUS APIENTRY RegCreateKeyWInt(_In_ HKEY hKey, _In_opt_ LPCWSTR lpSubKey, _Out_ PHKEY phkResult) {
    WriteInfoInFile("Create key: ", hKey);
    return _Std_RCKW(hKey, lpSubKey, phkResult);
}

LSTATUS
APIENTRY
RegDeleteKeyAInt(
    _In_ HKEY hKey,
    _In_ LPCSTR lpSubKey
) {
WriteInfoInFile("Delete key: ", hKey);
return _Std_RDKA(hKey, lpSubKey);
}

LSTATUS
APIENTRY
RegDeleteKeyWInt(
    _In_ HKEY hKey,
    _In_ LPCWSTR lpSubKey
) {
WriteInfoInFile("Delete key: ", hKey);
return _Std_RDKW(hKey, lpSubKey);
}

LSTATUS
APIENTRY
RegDeleteKeyExAInt(
    _In_ HKEY hKey,
    _In_ LPCSTR lpSubKey,
    _In_ REGSAM samDesired,
    _Reserved_ DWORD Reserved
){
    WriteInfoInFile("Delete ex key: ", hKey);
    return _Std_RDKEA(hKey, lpSubKey, samDesired, Reserved);
}

LSTATUS
APIENTRY
RegDeleteKeyExWInt(
    _In_ HKEY hKey,
    _In_ LPCWSTR lpSubKey,
    _In_ REGSAM samDesired,
    _Reserved_ DWORD Reserved
) {
    WriteInfoInFile("Delete ex key: ", hKey);
    return _Std_RDKEW(hKey, lpSubKey, samDesired, Reserved);
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
    WriteInfoInFile("Delete transacted key: ", hKey);
    return _Std_RDKTA(hKey, lpSubKey, samDesired, Reserved, hTransaction, pExtendedParameter);
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
    WriteInfoInFile("Delete transacted key: ", hKey);
    return _Std_RDKTW(hKey, lpSubKey, samDesired, Reserved, hTransaction, pExtendedParameter);
}
LONG
APIENTRY
RegDisableReflectionKeyInt(
    _In_ HKEY hBase
) {
    WriteInfoInFile("Disable reflection key: ", hBase);
    return _Std_RDRK(hBase);
}
LONG
APIENTRY
RegEnableReflectionKeyInt(
    _In_ HKEY hBase
) {
    WriteInfoInFile("Enable reflection key: ", hBase);
     return _Std_RERK(hBase);
}
LONG
APIENTRY
RegQueryReflectionKeyInt(
    _In_ HKEY hBase,
    _Out_ BOOL* bIsReflectionDisabled
) {
    WriteInfoInFile("Quary reflection key: ", hBase);
    return _Std_RQRK(hBase, bIsReflectionDisabled);

}
LSTATUS
APIENTRY
RegDeleteValueAInt(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpValueName
) {
    WriteInfoInFile("Delete value: ", hKey);
    return _Std_RDVA(hKey, lpValueName);
}
LSTATUS
APIENTRY
RegDeleteValueWInt(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpValueName
) {
    WriteInfoInFile("Delete value: ", hKey);
    return _Std_RDVW(hKey, lpValueName);
}
LSTATUS
APIENTRY
RegEnumKeyAInt(
    _In_ HKEY hKey,
    _In_ DWORD dwIndex,
    _Out_writes_opt_(cchName) LPSTR lpName,
    _In_ DWORD cchName
) {
    WriteInfoInFile("Enum key: ", hKey);
    return _Std_REKA(hKey, dwIndex, lpName, cchName);
}
LSTATUS
APIENTRY
RegEnumKeyWInt(
    _In_ HKEY hKey,
    _In_ DWORD dwIndex,
    _Out_writes_opt_(cchName) LPWSTR lpName,
    _In_ DWORD cchName
) {
    WriteInfoInFile("Enum key: ", hKey);
    return _Std_REKW(hKey, dwIndex, lpName, cchName);
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
    WriteInfoInFile("Enum ex key: ", hKey);
    return _Std_REKEA(hKey, dwIndex, lpName, lpcchName, lpReserved, lpClass, lpcchClass, lpftLastWriteTime);
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
    WriteInfoInFile("Enum ex key: ", hKey);
    return _Std_REKEW(hKey, dwIndex, lpName, lpcchName, lpReserved, lpClass, lpcchClass, lpftLastWriteTime);
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
    WriteInfoInFile("Enum value: ", hKey);
   return _Std_REVA(hKey, dwIndex, lpValueName, lpcchValueName, lpReserved, lpType, lpData, lpcbData);

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
    WriteInfoInFile("Enum value: ", hKey);
    return _Std_REVW(hKey, dwIndex, lpValueName, lpcchValueName, lpReserved, lpType, lpData, lpcbData);
}
LSTATUS
APIENTRY
RegFlushKeyInt(
    _In_ HKEY hKey
) {
    WriteInfoInFile("Flush key: ", hKey);
    return _Std_RFK(hKey);
}
LSTATUS
APIENTRY
RegGetKeySecurityInt(
    _In_ HKEY hKey,
    _In_ SECURITY_INFORMATION SecurityInformation,
    _Out_writes_bytes_opt_(*lpcbSecurityDescriptor) PSECURITY_DESCRIPTOR pSecurityDescriptor,
    _Inout_ LPDWORD lpcbSecurityDescriptor
) {
    WriteInfoInFile("Get key security: ", hKey);
    return _Std_RGKS(hKey, SecurityInformation, pSecurityDescriptor, lpcbSecurityDescriptor);
  
}
LSTATUS
APIENTRY
RegLoadKeyAInt(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey,
    _In_ LPCSTR lpFile
) {
    WriteInfoInFile("Load key: ", hKey);
    return _Std_RLKA(hKey, lpSubKey, lpFile);
}
LSTATUS
APIENTRY
RegLoadKeyWInt(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey,
    _In_ LPCWSTR lpFile
) {
    WriteInfoInFile("Load key: ", hKey);
    return _Std_RLKW(hKey, lpSubKey, lpFile);

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
    WriteInfoInFile("Notify change key value: ", hKey);
    return _Std_RNCKV(hKey, bWatchSubtree, dwNotifyFilter, hEvent, fAsynchronous);
}
LSTATUS
APIENTRY
RegOpenKeyAInt(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey,
    _Out_ PHKEY phkResult
) {
    WriteInfoInFile("Open key: ", hKey);
    return _Std_ROKA(hKey, lpSubKey, phkResult);
}
LSTATUS
APIENTRY
RegOpenKeyWInt(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey,
    _Out_ PHKEY phkResult
) {
    WriteInfoInFile("Open key: ", hKey);
    return _Std_ROKW(hKey, lpSubKey, phkResult);
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

    WriteInfoInFile("Open ex key: ", hKey);
    return _Std_ROKEA(hKey, lpSubKey, ulOptions, samDesired, phkResult);
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
    WriteInfoInFile("Open ex key: ", hKey);
    return _Std_ROKEW(hKey, lpSubKey, ulOptions, samDesired, phkResult);
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
    WriteInfoInFile("Open transacted key: ", hKey);
    return _Std_ROKTA(hKey, lpSubKey, ulOptions, samDesired,phkResult, hTransaction, pExtendedParemeter);
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
    WriteInfoInFile("Open transacted key: ", hKey);
    return _Std_ROKTW(hKey, lpSubKey, ulOptions, samDesired, phkResult, hTransaction, pExtendedParemeter);
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
    WriteInfoInFile("Query info key: ", hKey);
    return _Std_RQIKA(hKey, lpClass, lpcchClass, lpReserved, lpcSubKeys, lpcbMaxSubKeyLen, lpcbMaxClassLen, lpcValues, lpcbMaxValueNameLen, lpcbMaxValueLen, lpcbSecurityDescriptor, lpftLastWriteTime);
   
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
    WriteInfoInFile("Query info key: ", hKey);
    return _Std_RQIKW(hKey, lpClass, lpcchClass, lpReserved, lpcSubKeys, lpcbMaxSubKeyLen, lpcbMaxClassLen, lpcValues, lpcbMaxValueNameLen, lpcbMaxValueLen, lpcbSecurityDescriptor, lpftLastWriteTime);
}
LSTATUS
APIENTRY
RegQueryValueAInt(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey,
    _Out_writes_bytes_to_opt_(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPSTR lpData,
    _Inout_opt_ PLONG lpcbData
) {
    WriteInfoInFile("Query value: ", hKey);
    return _Std_RQVA(hKey, lpSubKey, lpData, lpcbData);
}
LSTATUS
APIENTRY
RegQueryValueWInt(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey,
    _Out_writes_bytes_to_opt_(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPWSTR lpData,
    _Inout_opt_ PLONG lpcbData
) {
    WriteInfoInFile("Query value: ", hKey);
    return _Std_RQVW(hKey, lpSubKey, lpData, lpcbData);
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
    WriteInfoInFile("Query multi values: ", hKey);
    return _Std_RQMVA(hKey, val_list,num_vals, lpValueBuf, ldwTotsize);
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
    WriteInfoInFile("Query multi values: ", hKey);
    return _Std_RQMVW(hKey, val_list, num_vals, lpValueBuf, ldwTotsize);
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
    WriteInfoInFile("Query ex value: ", hKey);
    return _Std_RQVEA(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
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
    WriteInfoInFile("Query ex value: ", hKey);
    return _Std_RQVEW(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
}
LSTATUS
APIENTRY
RegReplaceKeyAInt(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey,
    _In_ LPCSTR lpNewFile,
    _In_ LPCSTR lpOldFile
) {
    WriteInfoInFile("replace key ", hKey);
    return _Std_RRKA(hKey, lpSubKey, lpNewFile, lpOldFile);
}
LSTATUS
APIENTRY
RegReplaceKeyWInt(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey,
    _In_ LPCWSTR lpNewFile,
    _In_ LPCWSTR lpOldFile
) {
    WriteInfoInFile("Replace key: ", hKey);
    return _Std_RRKW(hKey, lpSubKey, lpNewFile, lpOldFile);
}
LSTATUS
APIENTRY
RegRestoreKeyAInt(
    _In_ HKEY hKey,
    _In_ LPCSTR lpFile,
    _In_ DWORD dwFlags
) {
    WriteInfoInFile("Restore key: ", hKey);
    return _Std_RRKAI(hKey, lpFile, dwFlags);
}
LSTATUS
APIENTRY
RegRestoreKeyWInt(
    _In_ HKEY hKey,
    _In_ LPCWSTR lpFile,
    _In_ DWORD dwFlags
) {
    WriteInfoInFile("Restore key: ", hKey);
    return _Std_RRKWI(hKey, lpFile, dwFlags);
}
LSTATUS
APIENTRY
RegRenameKeyInt(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKeyName,
    _In_ LPCWSTR lpNewKeyName
) {
    WriteInfoInFile("Rename key: ", hKey);
    return _Std_RRK(hKey, lpSubKeyName, lpNewKeyName);
}
LSTATUS
APIENTRY
RegSaveKeyAInt(
    _In_ HKEY hKey,
    _In_ LPCSTR lpFile,
    _In_opt_ CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes
) {
    WriteInfoInFile("Save key: ", hKey);
    return _Std_RSKA(hKey, lpFile, lpSecurityAttributes);
}
LSTATUS
APIENTRY
RegSaveKeyWInt(
    _In_ HKEY hKey,
    _In_ LPCWSTR lpFile,
    _In_opt_ CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes
) {
    WriteInfoInFile("Save key: ", hKey);
    return _Std_RSKW(hKey, lpFile, lpSecurityAttributes);
}
LSTATUS
APIENTRY
RegSetKeySecurityInt(
    _In_ HKEY hKey,
    _In_ SECURITY_INFORMATION SecurityInformation,
    _In_ PSECURITY_DESCRIPTOR pSecurityDescriptor
) {
    WriteInfoInFile("Set key security: ", hKey);
    return _Std_RSKS(hKey, SecurityInformation, pSecurityDescriptor);
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
    WriteInfoInFile("Set value: ", hKey);
    return _Std_RSVA(hKey, lpSubKey, dwType, lpData, cbData);
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
    WriteInfoInFile("Set value: ", hKey);
    return _Std_RSVW(hKey, lpSubKey, dwType, lpData, cbData);
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
    WriteInfoInFile("Set value ex: ", hKey);
    return _Std_RSVEA(hKey, lpValueName, Reserved, dwType, lpData, cbData);
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
    WriteInfoInFile("Set value ex: ", hKey);
    return _Std_RSVEW(hKey, lpValueName, Reserved, dwType, lpData, cbData);
}
LSTATUS
APIENTRY
RegUnLoadKeyAInt(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey
) {
    WriteInfoInFile("Unload Key: ", hKey);
    return _Std_RULKA(hKey, lpSubKey);
}
LSTATUS
APIENTRY
RegUnLoadKeyWInt(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey
) {
    WriteInfoInFile("Unload Key: ", hKey);
    return _Std_RULKW(hKey, lpSubKey);
}
LSTATUS
APIENTRY
RegDeleteKeyValueAInt(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey,
    _In_opt_ LPCSTR lpValueName
) {
    WriteInfoInFile("Delete key value: ", hKey);
    return _Std_RDKVA(hKey, lpSubKey, lpValueName);
}
LSTATUS
APIENTRY
RegDeleteKeyValueWInt(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey,
    _In_opt_ LPCWSTR lpValueName
) {
    WriteInfoInFile("Delete key value: ", hKey);
    return _Std_RDKVW(hKey, lpSubKey, lpValueName);
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
    WriteInfoInFile("Set key value: ", hKey);
    return _Std_RSKVA(hKey, lpSubKey, lpValueName, dwType, lpData, cbData);
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
    WriteInfoInFile("Set key value: ", hKey);
    return _Std_RSKVW(hKey, lpSubKey, lpValueName, dwType, lpData, cbData);
}
LSTATUS
APIENTRY
RegDeleteTreeAInt(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey
) {
    WriteInfoInFile("Delete tree: ", hKey);
    return _Std_RDTA(hKey, lpSubKey);
}
LSTATUS
APIENTRY
RegDeleteTreeWInt(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey
) {
    WriteInfoInFile("Delete tree: ", hKey);
    return _Std_RDTW(hKey, lpSubKey);
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
    WriteInfoInFile("Get value: ", hkey);
    return _Std_RGVA(hkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData);
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
    WriteInfoInFile("Get value: ", hkey);
    return _Std_RGVW(hkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData);
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
    WriteInfoInFile("Load MUI string: ", hKey);
    return _Std_RLMSA(hKey, pszValue, pszOutBuf, cbOutBuf, pcbData, Flags, pszDirectory);
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
    WriteInfoInFile("Load MUI string: ", hKey);
    return _Std_RLMSW(hKey, pszValue, pszOutBuf, cbOutBuf, pcbData, Flags, pszDirectory);
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
    WriteInfoInFile("Load app key: ", lpFile);
    return _Std_RLAKA(lpFile, phkResult, samDesired, dwOptions, Reserved);
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
    WriteInfoInFile("Load app key: ", lpFile);
    return _Std_RLAKW(lpFile, phkResult, samDesired, dwOptions, Reserved);
}


LSTATUS
APIENTRY
RegDisablePredefinedCacheExInt(
    VOID
){
    WriteInfoInFile("Disable Predefined cache ex", " ");
    return _Std_RDPCE();
}



LSTATUS
APIENTRY
RegDisablePredefinedCacheInt(
    VOID
) {
    WriteInfoInFile("Disable predefined cache", " ");
    return _Std_RDPC();
}

LSTATUS
APIENTRY
RegOverridePredefKeyInt(
    _In_ HKEY hKey,
    _In_opt_ HKEY hNewHKey
) {
    WriteInfoInFile("Override predef key: ", hKey);
    return _Std_ROPK(hKey, hNewHKey);
}




LSTATUS
APIENTRY
RegOpenUserClassesRootInt(
    _In_ HANDLE hToken,
    _Reserved_ DWORD dwOptions,
    _In_ REGSAM samDesired,
    _Out_ PHKEY phkResult
) {
    WriteInfoInFile("Open user classes root", " ");
    return _Std_ROUCR(hToken, dwOptions, samDesired, phkResult);
}



LSTATUS
APIENTRY
RegOpenCurrentUserInt(
    _In_ REGSAM samDesired,
    _Out_ PHKEY phkResult
) {
    WriteInfoInFile("Open current user", " ");
    return _Std_ROCU(samDesired, phkResult);
}


LSTATUS
APIENTRY
RegConnectRegistryExAInt(
    _In_opt_ LPCSTR lpMachineName,
    _In_ HKEY hKey,
    _In_ ULONG Flags,
    _Out_ PHKEY phkResult
) {
    WriteInfoInFile("Connect registory ex: ", hKey);
    return _Std_RCREA(lpMachineName, hKey, Flags, phkResult);
}

LSTATUS
APIENTRY
RegConnectRegistryExWInt(
    _In_opt_ LPCWSTR lpMachineName,
    _In_ HKEY hKey,
    _In_ ULONG Flags,
    _Out_ PHKEY phkResult
) {
    WriteInfoInFile("Connect registory ex: ", hKey);
    return _Std_RCREW(lpMachineName, hKey, Flags, phkResult);
}


DWORD
APIENTRY
CheckForHiberbootInt(
    _Inout_ PBOOLEAN pHiberboot,
    _In_ BOOLEAN bClearFlag
) {
    WriteInfoInFile("Check for hiberboot ", " ");
    return _Std_CFH(pHiberboot, bClearFlag);
}


LSTATUS
APIENTRY
RegSaveKeyExAInt(
    _In_ HKEY hKey,
    _In_ LPCSTR lpFile,
    _In_opt_ CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _In_ DWORD Flags
) {
    WriteInfoInFile("Save key ex: ", hKey);
    return _Std_RSKEA(hKey, lpFile, lpSecurityAttributes, Flags);
}


LSTATUS
APIENTRY
RegSaveKeyExWInt(
    _In_ HKEY hKey,
    _In_ LPCWSTR lpFile,
    _In_opt_ CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _In_ DWORD Flags
) {
    WriteInfoInFile("Save key ex: ", hKey);
    return _Std_RSKEW(hKey, lpFile, lpSecurityAttributes, Flags);    
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
    char* buf = new char[40];
    auto t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    ctime_s(buf, 40, &t);
    if (outFile.is_open())
    {
        outFile << buf << ": " << firstParam << " " << discription << std::endl;
    }
    else {
        std::cout << "Don't" << std::endl;
    }
    outFile.close();

}
void WriteInfoInFile(const char* firstParam, LPWSTR discription) {
    std::ofstream outFile(fileName, std::ios::app);
    char* buf = new char[40];
    auto t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    ctime_s(buf, 40, &t);
    if (outFile.is_open())
    {
        outFile << buf << ": " << firstParam << " " << discription << std::endl;
    }
    else {
        std::cout << "Don't" << std::endl;
    }
    outFile.close();

}
void WriteInfoInFile(const char* firstParam, HKEY discription) {
    std::ofstream outFile(fileName, std::ios::app);
    char* buf = new char[40];
    auto t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    ctime_s(buf, 40, &t);
    if (outFile.is_open())
    {
        outFile << buf << ": " << firstParam << " " << discription << std::endl;
    }
    else {
        std::cout << "Don't" << std::endl;
    }
    outFile.close();

}
void WriteInfoInFile(const char* firstParam, LPCSTR discription) {
    std::ofstream outFile(fileName, std::ios::app);
    char* buf = new char[40];
    auto t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    ctime_s(buf, 40, &t);
    if (outFile.is_open())
    {
        outFile << buf << ": " << firstParam << " " << discription << std::endl;
    }
    else {
        std::cout << "Don't" << std::endl;
    }
    outFile.close();

}
void WriteInfoInFile(const char* firstParam, LPCWSTR discription) {
    std::ofstream outFile(fileName, std::ios::app);
    char* buf = new char[40];
    auto t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    ctime_s(buf, 40, &t);
    if (outFile.is_open())
    {
        outFile  << buf << ": " <<  firstParam << " "<< discription << std::endl;
    }
    else {
        std::cout << "Don't" << std::endl;
    }
    outFile.close();

}