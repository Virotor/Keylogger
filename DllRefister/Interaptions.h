#pragma once

#include <iostream>
#include <stdarg.h>
#include <windows.h>
#include <vector>
#include <fstream>
#include <chrono>
#include <ctime> 


std::vector <DWORD> adr_Reester_Func(91,0);

char* fileName = new char[] {"result.txt"};

LPWSTR convertStr(LPCSTR pInStr);

void InterceptFunctionsJmp(void);
void WriteInfoInFile(const char* firstParam, char* discription);
void WriteInfoInFile(const char* firstParam, LPWSTR discription);
void WriteInfoInFile(const char* firstParam, HKEY discription);
void WriteInfoInFile(const char* firstParam, LPCSTR discription);
void WriteInfoInFile(const char* firstParam, LPCWSTR discription);
#pragma region functions
WINADVAPI
LSTATUS
APIENTRY
RegCloseKeyInt(
    _In_ HKEY hKey
);


WINADVAPI
LSTATUS
APIENTRY
RegOverridePredefKeyInt(
    _In_ HKEY hKey,
    _In_opt_ HKEY hNewHKey
);

WINADVAPI
LSTATUS
APIENTRY
RegOpenUserClassesRootInt(
    _In_ HANDLE hToken,
    _Reserved_ DWORD dwOptions,
    _In_ REGSAM samDesired,
    _Out_ PHKEY phkResult
);


WINADVAPI
LSTATUS
APIENTRY
RegOpenCurrentUserInt(
    _In_ REGSAM samDesired,
    _Out_ PHKEY phkResult
);


WINADVAPI
LSTATUS
APIENTRY
RegDisablePredefinedCacheInt(
    VOID
);

WINADVAPI
LSTATUS
APIENTRY
RegDisablePredefinedCacheExInt(
    VOID
);


WINADVAPI
LSTATUS
APIENTRY
RegConnectRegistryAInt(
    _In_opt_ LPCSTR lpMachineName,
    _In_ HKEY hKey,
    _Out_ PHKEY phkResult
);
WINADVAPI
LSTATUS
APIENTRY
RegConnectRegistryWInt(
    _In_opt_ LPCWSTR lpMachineName,
    _In_ HKEY hKey,
    _Out_ PHKEY phkResult
);
#ifdef UNICODE
#define RegConnectRegistry  RegConnectRegistryWInt
#else
#define RegConnectRegistry  RegConnectRegistryAInt
#endif // !UNICODE

WINADVAPI
LSTATUS
APIENTRY
RegConnectRegistryExAInt(
    _In_opt_ LPCSTR lpMachineName,
    _In_ HKEY hKey,
    _In_ ULONG Flags,
    _Out_ PHKEY phkResult
);
WINADVAPI
LSTATUS
APIENTRY
RegConnectRegistryExWInt(
    _In_opt_ LPCWSTR lpMachineName,
    _In_ HKEY hKey,
    _In_ ULONG Flags,
    _Out_ PHKEY phkResult
);
#ifdef UNICODE
#define RegConnectRegistryEx  RegConnectRegistryExWInt
#else
#define RegConnectRegistryEx RegConnectRegistryExAInt
#endif // !UNICODE

WINADVAPI
LSTATUS
APIENTRY
RegCreateKeyAInt(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey,
    _Out_ PHKEY phkResult
);
WINADVAPI
LSTATUS
APIENTRY
RegCreateKeyWInt(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey,
    _Out_ PHKEY phkResult
);
#ifdef UNICODE
#define RegCreateKey  RegCreateKeyWInt
#else
#define RegCreateKey  RegCreateKeyAInt
#endif // !UNICODE

WINADVAPI
LSTATUS
APIENTRY
RegCreateKeyExAInt(
    _In_ HKEY hKey,
    _In_ LPCSTR lpSubKey,
    _Reserved_ DWORD Reserved,
    _In_opt_ LPSTR lpClass,
    _In_ DWORD dwOptions,
    _In_ REGSAM samDesired,
    _In_opt_ CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _Out_ PHKEY phkResult,
    _Out_opt_ LPDWORD lpdwDisposition
);

WINADVAPI
LSTATUS
APIENTRY
RegCreateKeyExWInt(
    _In_ HKEY hKey,
    _In_ LPCWSTR lpSubKey,
    _Reserved_ DWORD Reserved,
    _In_opt_ LPWSTR lpClass,
    _In_ DWORD dwOptions,
    _In_ REGSAM samDesired,
    _In_opt_ CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _Out_ PHKEY phkResult,
    _Out_opt_ LPDWORD lpdwDisposition
);

#ifdef UNICODE
#define RegCreateKeyEx  RegCreateKeyExWInt
#else
#define RegCreateKeyEx  RegCreateKeyExAInt
#endif // !UNICODE

WINADVAPI
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
);
WINADVAPI
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
);
#ifdef UNICODE
#define RegCreateKeyTransacted  RegCreateKeyTransactedWInt
#else
#define RegCreateKeyTransacted  RegCreateKeyTransactedAInt
#endif // !UNICODE

WINADVAPI
LSTATUS
APIENTRY
RegDeleteKeyAInt(
    _In_ HKEY hKey,
    _In_ LPCSTR lpSubKey
);
WINADVAPI
LSTATUS
APIENTRY
RegDeleteKeyWInt(
    _In_ HKEY hKey,
    _In_ LPCWSTR lpSubKey
);
#ifdef UNICODE
#define RegDeleteKey  RegDeleteKeyWInt
#else
#define RegDeleteKey  RegDeleteKeyAInt
#endif // !UNICODE

WINADVAPI
LSTATUS
APIENTRY
RegDeleteKeyExAInt(
    _In_ HKEY hKey,
    _In_ LPCSTR lpSubKey,
    _In_ REGSAM samDesired,
    _Reserved_ DWORD Reserved
);

WINADVAPI
LSTATUS
APIENTRY
RegDeleteKeyExWInt(
    _In_ HKEY hKey,
    _In_ LPCWSTR lpSubKey,
    _In_ REGSAM samDesired,
    _Reserved_ DWORD Reserved
);

#ifdef UNICODE
#define RegDeleteKeyEx RegDeleteKeyExWInt
#else
#define RegDeleteKeyEx  RegDeleteKeyExAInt
#endif // !UNICODE

WINADVAPI
LSTATUS
APIENTRY
RegDeleteKeyTransactedAInt(
    _In_ HKEY hKey,
    _In_ LPCSTR lpSubKey,
    _In_ REGSAM samDesired,
    _Reserved_ DWORD Reserved,
    _In_        HANDLE hTransaction,
    _Reserved_ PVOID  pExtendedParameter
);
WINADVAPI
LSTATUS
APIENTRY
RegDeleteKeyTransactedWInt(
    _In_ HKEY hKey,
    _In_ LPCWSTR lpSubKey,
    _In_ REGSAM samDesired,
    _Reserved_ DWORD Reserved,
    _In_        HANDLE hTransaction,
    _Reserved_ PVOID  pExtendedParameter
);
#ifdef UNICODE
#define RegDeleteKeyTransacted RegDeleteKeyTransactedWInt
#else
#define RegDeleteKeyTransacted  RegDeleteKeyTransactedAInt
#endif // !UNICODE

WINADVAPI
LONG
APIENTRY
RegDisableReflectionKeyInt(
    _In_ HKEY hBase
);

WINADVAPI
LONG
APIENTRY
RegEnableReflectionKeyInt(
    _In_ HKEY hBase
);

WINADVAPI
LONG
APIENTRY
RegQueryReflectionKeyInt(
    _In_ HKEY hBase,
    _Out_ BOOL* bIsReflectionDisabled
);

WINADVAPI
LSTATUS
APIENTRY
RegDeleteValueAInt(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpValueName
);

WINADVAPI
LSTATUS
APIENTRY
RegDeleteValueWInt(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpValueName
);

WINADVAPI
LSTATUS
APIENTRY
RegEnumKeyAInt(
    _In_ HKEY hKey,
    _In_ DWORD dwIndex,
    _Out_writes_opt_(cchName) LPSTR lpName,
    _In_ DWORD cchName
);
WINADVAPI
LSTATUS
APIENTRY
RegEnumKeyWInt(
    _In_ HKEY hKey,
    _In_ DWORD dwIndex,
    _Out_writes_opt_(cchName) LPWSTR lpName,
    _In_ DWORD cchName
);

WINADVAPI
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
);

WINADVAPI
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
);

WINADVAPI
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
);

WINADVAPI
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

);

#ifdef UNICODE
#define RegEnumValue  RegEnumValueWInt
#else
#define RegEnumValue RegEnumValueAInt
#endif // !UNICODE

WINADVAPI
LSTATUS
APIENTRY
RegFlushKeyInt(
    _In_ HKEY hKey
);


WINADVAPI
LSTATUS
APIENTRY
RegGetKeySecurityInt(
    _In_ HKEY hKey,
    _In_ SECURITY_INFORMATION SecurityInformation,
    _Out_writes_bytes_opt_(*lpcbSecurityDescriptor) PSECURITY_DESCRIPTOR pSecurityDescriptor,
    _Inout_ LPDWORD lpcbSecurityDescriptor
);


WINADVAPI
LSTATUS
APIENTRY
RegLoadKeyAInt(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey,
    _In_ LPCSTR lpFile
);

WINADVAPI
LSTATUS
APIENTRY
RegLoadKeyWInt(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey,
    _In_ LPCWSTR lpFile
);

#ifdef UNICODE
#define RegLoadKey RegLoadKeyWInt
#else
#define RegLoadKey  RegLoadKeyAInt
#endif // !UNICODE

WINADVAPI
LSTATUS
APIENTRY
RegNotifyChangeKeyValueInt(
    _In_ HKEY hKey,
    _In_ BOOL bWatchSubtree,
    _In_ DWORD dwNotifyFilter,
    _In_opt_ HANDLE hEvent,
    _In_ BOOL fAsynchronous
);


WINADVAPI
LSTATUS
APIENTRY
RegOpenKeyAInt(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey,
    _Out_ PHKEY phkResult
);
WINADVAPI
LSTATUS
APIENTRY
RegOpenKeyWInt(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey,
    _Out_ PHKEY phkResult
);
#ifdef UNICODE
#define RegOpenKey RegOpenKeyWInt
#else
#define RegOpenKey RegOpenKeyAInt
#endif // !UNICODE

WINADVAPI
LSTATUS
APIENTRY
RegOpenKeyExAInt(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey,
    _In_opt_ DWORD ulOptions,
    _In_ REGSAM samDesired,
    _Out_ PHKEY phkResult
);

WINADVAPI
LSTATUS
APIENTRY
RegOpenKeyExWInt(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey,
    _In_opt_ DWORD ulOptions,
    _In_ REGSAM samDesired,
    _Out_ PHKEY phkResult
);

#ifdef UNICODE
#define RegOpenKeyEx  RegOpenKeyExWInt
#else
#define RegOpenKeyEx  RegOpenKeyExAInt
#endif // !UNICODE

WINADVAPI
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
);
WINADVAPI
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
);
#ifdef UNICODE
#define RegOpenKeyTransacted  RegOpenKeyTransactedWInt
#else
#define RegOpenKeyTransacted  RegOpenKeyTransactedAInt
#endif // !UNICODE

WINADVAPI
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
);

WINADVAPI
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
);

#ifdef UNICODE
#define RegQueryInfoKey  RegQueryInfoKeyWInt
#else
#define RegQueryInfoKey  RegQueryInfoKeyAInt
#endif // !UNICODE

WINADVAPI
LSTATUS
APIENTRY
RegQueryValueAInt(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey,
    _Out_writes_bytes_to_opt_(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPSTR lpData,
    _Inout_opt_ PLONG lpcbData
);
WINADVAPI
LSTATUS
APIENTRY
RegQueryValueWInt(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey,
    _Out_writes_bytes_to_opt_(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPWSTR lpData,
    _Inout_opt_ PLONG lpcbData
);
#ifdef UNICODE
#define RegQueryValue  RegQueryValueWInt
#else
#define RegQueryValue  RegQueryValueAInt
#endif // !UNICODE

#if (WINVER >= 0x0400)

WINADVAPI
LSTATUS
APIENTRY
RegQueryMultipleValuesAInt(
    _In_ HKEY hKey,
    _Out_writes_(num_vals) PVALENTA val_list,
    _In_ DWORD num_vals,
    _Out_writes_bytes_to_opt_(*ldwTotsize, *ldwTotsize) __out_data_source(REGISTRY) LPSTR lpValueBuf,
    _Inout_opt_ LPDWORD ldwTotsize
);

WINADVAPI
LSTATUS
APIENTRY
RegQueryMultipleValuesWInt(
    _In_ HKEY hKey,
    _Out_writes_(num_vals) PVALENTW val_list,
    _In_ DWORD num_vals,
    _Out_writes_bytes_to_opt_(*ldwTotsize, *ldwTotsize) __out_data_source(REGISTRY) LPWSTR lpValueBuf,
    _Inout_opt_ LPDWORD ldwTotsize
);

#ifdef UNICODE
#define RegQueryMultipleValues  RegQueryMultipleValuesWInt
#else
#define RegQueryMultipleValues  RegQueryMultipleValuesAInt
#endif // !UNICODE

#endif /* WINVER >= 0x0400 */

WINADVAPI
LSTATUS
APIENTRY
RegQueryValueExAInt(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpValueName,
    _Reserved_ LPDWORD lpReserved,
    _Out_opt_ LPDWORD lpType,
    _Out_writes_bytes_to_opt_(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPBYTE lpData,
    _When_(lpData == NULL, _Out_opt_) _When_(lpData != NULL, _Inout_opt_) LPDWORD lpcbData
);

WINADVAPI
LSTATUS
APIENTRY
RegQueryValueExWInt(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpValueName,
    _Reserved_ LPDWORD lpReserved,
    _Out_opt_ LPDWORD lpType,
    _Out_writes_bytes_to_opt_(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPBYTE lpData,
    _When_(lpData == NULL, _Out_opt_) _When_(lpData != NULL, _Inout_opt_) LPDWORD lpcbData
);

#ifdef UNICODE
#define RegQueryValueEx  RegQueryValueExWInt
#else
#define RegQueryValueEx  RegQueryValueExAInt
#endif // !UNICODE

WINADVAPI
LSTATUS
APIENTRY
RegReplaceKeyAInt(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey,
    _In_ LPCSTR lpNewFile,
    _In_ LPCSTR lpOldFile
);
WINADVAPI
LSTATUS
APIENTRY
RegReplaceKeyWInt(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey,
    _In_ LPCWSTR lpNewFile,
    _In_ LPCWSTR lpOldFile
);
#ifdef UNICODE
#define RegReplaceKey  RegReplaceKeyWInt
#else
#define RegReplaceKey  RegReplaceKeyAInt
#endif // !UNICODE

WINADVAPI
LSTATUS
APIENTRY
RegRestoreKeyAInt(
    _In_ HKEY hKey,
    _In_ LPCSTR lpFile,
    _In_ DWORD dwFlags
);

WINADVAPI
LSTATUS
APIENTRY
RegRestoreKeyWInt(
    _In_ HKEY hKey,
    _In_ LPCWSTR lpFile,
    _In_ DWORD dwFlags
);

#ifdef UNICODE
#define RegRestoreKey  RegRestoreKeyWInt
#else
#define RegRestoreKey  RegRestoreKeyAInt
#endif // !UNICODE

#if (WINVER >= 0x0600)

WINADVAPI
LSTATUS
APIENTRY
RegRenameKeyInt(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKeyName,
    _In_ LPCWSTR lpNewKeyName
);

#endif /* WINVER >= 0x0600 */

WINADVAPI
LSTATUS
APIENTRY
RegSaveKeyAInt(
    _In_ HKEY hKey,
    _In_ LPCSTR lpFile,
    _In_opt_ CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes
);
WINADVAPI
LSTATUS
APIENTRY
RegSaveKeyWInt(
    _In_ HKEY hKey,
    _In_ LPCWSTR lpFile,
    _In_opt_ CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes
);
#ifdef UNICODE
#define RegSaveKey  RegSaveKeyWInt
#else
#define RegSaveKey  RegSaveKeyAInt
#endif // !UNICODE

WINADVAPI
LSTATUS
APIENTRY
RegSetKeySecurityInt(
    _In_ HKEY hKey,
    _In_ SECURITY_INFORMATION SecurityInformation,
    _In_ PSECURITY_DESCRIPTOR pSecurityDescriptor
);


WINADVAPI
LSTATUS
APIENTRY
RegSetValueAInt(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey,
    _In_ DWORD dwType,
    _In_reads_bytes_opt_(cbData) LPCSTR lpData,
    _In_ DWORD cbData
);
WINADVAPI
LSTATUS
APIENTRY
RegSetValueWInt(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey,
    _In_ DWORD dwType,
    _In_reads_bytes_opt_(cbData) LPCWSTR lpData,
    _In_ DWORD cbData
);
#ifdef UNICODE
#define RegSetValue RegSetValueWInt
#else
#define RegSetValue RegSetValueAInt
#endif // !UNICODE

WINADVAPI
LSTATUS
APIENTRY
RegSetValueExAInt(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpValueName,
    _Reserved_ DWORD Reserved,
    _In_ DWORD dwType,
    _In_reads_bytes_opt_(cbData) CONST BYTE* lpData,
    _In_ DWORD cbData
);

WINADVAPI
LSTATUS
APIENTRY
RegSetValueExWInt(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpValueName,
    _Reserved_ DWORD Reserved,
    _In_ DWORD dwType,
    _In_reads_bytes_opt_(cbData) CONST BYTE* lpData,
    _In_ DWORD cbData
);

#ifdef UNICODE
#define RegSetValueEx RegSetValueExWInt
#else
#define RegSetValueEx RegSetValueExAInt
#endif // !UNICODE

WINADVAPI
LSTATUS
APIENTRY
RegUnLoadKeyAInt(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey
);

WINADVAPI
LSTATUS
APIENTRY
RegUnLoadKeyWInt(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey
);

#ifdef UNICODE
#define RegUnLoadKey  RegUnLoadKeyWInt
#else
#define RegUnLoadKey  RegUnLoadKeyAInt
#endif // !UNICODE

//
// Utils wrappers
//
#if _WIN32_WINNT >= 0x0600

WINADVAPI
LSTATUS
APIENTRY
RegDeleteKeyValueAInt(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey,
    _In_opt_ LPCSTR lpValueName
);

WINADVAPI
LSTATUS
APIENTRY
RegDeleteKeyValueWInt(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey,
    _In_opt_ LPCWSTR lpValueName
);

#ifdef UNICODE
#define RegDeleteKeyValue  RegDeleteKeyValueWInt
#else
#define RegDeleteKeyValue  RegDeleteKeyValueAInt
#endif // !UNICODE

WINADVAPI
LSTATUS
APIENTRY
RegSetKeyValueAInt(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey,
    _In_opt_ LPCSTR lpValueName,
    _In_ DWORD dwType,
    _In_reads_bytes_opt_(cbData) LPCVOID lpData,
    _In_ DWORD cbData
);

WINADVAPI
LSTATUS
APIENTRY
RegSetKeyValueWInt(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey,
    _In_opt_ LPCWSTR lpValueName,
    _In_ DWORD dwType,
    _In_reads_bytes_opt_(cbData) LPCVOID lpData,
    _In_ DWORD cbData
);

#ifdef UNICODE
#define RegSetKeyValue  RegSetKeyValueWInt
#else
#define RegSetKeyValue  RegSetKeyValueAInt
#endif // !UNICODE

WINADVAPI
LSTATUS
APIENTRY
RegDeleteTreeAInt(
    _In_ HKEY hKey,
    _In_opt_ LPCSTR lpSubKey
);

WINADVAPI
LSTATUS
APIENTRY
RegDeleteTreeWInt(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKey
);

#ifdef UNICODE
#define RegDeleteTree  RegDeleteTreeWInt
#else
#define RegDeleteTree  RegDeleteTreeAInt
#endif // !UNICODE

WINADVAPI
LSTATUS
APIENTRY
RegCopyTreeAInt(
    _In_        HKEY     hKeySrc,
    _In_opt_    LPCSTR  lpSubKey,
    _In_        HKEY     hKeyDest
);
#ifndef UNICODE
#define RegCopyTreeInt  RegCopyTreeAInt
#endif // !UNICODE

#endif // _WIN32_WINNT >= 0x0600

#if (_WIN32_WINNT >= 0x0502)

WINADVAPI
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
);

WINADVAPI
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
);

#ifdef UNICODE
#define RegGetValue  RegGetValueWInt
#else
#define RegGetValue  RegGetValueAInt
#endif // !UNICODE

#endif // (_WIN32_WINNT >= 0x0502)

#if (_WIN32_WINNT >= 0x0600)

WINADVAPI
LSTATUS
APIENTRY
RegCopyTreeWInt(
    _In_ HKEY hKeySrc,
    _In_opt_ LPCWSTR lpSubKey,
    _In_ HKEY hKeyDest
);

#ifdef UNICODE
#define RegCopyTreeInt  RegCopyTreeWInt
#endif

WINADVAPI
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
);

WINADVAPI
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
);

#ifdef UNICODE
#define RegLoadMUIString  RegLoadMUIStringWInt
#else
#define RegLoadMUIString  RegLoadMUIStringAInt
#endif // !UNICODE

WINADVAPI
LSTATUS
APIENTRY
RegLoadAppKeyAInt(
    _In_ LPCSTR lpFile,
    _Out_ PHKEY phkResult,
    _In_ REGSAM samDesired,
    _In_ DWORD dwOptions,
    _Reserved_ DWORD Reserved
);

WINADVAPI
LSTATUS
APIENTRY
RegLoadAppKeyWInt(
    _In_ LPCWSTR lpFile,
    _Out_ PHKEY phkResult,
    _In_ REGSAM samDesired,
    _In_ DWORD dwOptions,
    _Reserved_ DWORD Reserved
);

#ifdef UNICODE
#define RegLoadAppKey  RegLoadAppKeyWInt
#else
#define RegLoadAppKey  RegLoadAppKeyAInt
#endif // !UNICODE

#endif // _WIN32_WINNT >= 0x0600

//
// Remoteable System Shutdown APIs
//

__drv_preferredFunction("InitiateSystemShutdownEx", "Legacy API. Rearchitect to avoid Reboot")
WINADVAPI
BOOL
APIENTRY
InitiateSystemShutdownAInt(
    _In_opt_ LPSTR lpMachineName,
    _In_opt_ LPSTR lpMessage,
    _In_ DWORD dwTimeout,
    _In_ BOOL bForceAppsClosed,
    _In_ BOOL bRebootAfterShutdown
);
__drv_preferredFunction("InitiateSystemShutdownEx", "Legacy API. Rearchitect to avoid Reboot")
WINADVAPI
BOOL
APIENTRY
InitiateSystemShutdownWInt(
    _In_opt_ LPWSTR lpMachineName,
    _In_opt_ LPWSTR lpMessage,
    _In_ DWORD dwTimeout,
    _In_ BOOL bForceAppsClosed,
    _In_ BOOL bRebootAfterShutdown
);
#ifdef UNICODE
#define InitiateSystemShutdown  InitiateSystemShutdownWInt
#else
#define InitiateSystemShutdown  InitiateSystemShutdownAInt
#endif // !UNICODE

WINADVAPI
BOOL
APIENTRY
AbortSystemShutdownAInt(
    _In_opt_ LPSTR lpMachineName
);
WINADVAPI
BOOL
APIENTRY
AbortSystemShutdownWInt(
    _In_opt_ LPWSTR lpMachineName
);

WINADVAPI
DWORD
APIENTRY
InitiateShutdownAInt(
    _In_opt_ LPSTR lpMachineName,
    _In_opt_ LPSTR lpMessage,
    _In_     DWORD dwGracePeriod,
    _In_     DWORD dwShutdownFlags,
    _In_     DWORD dwReason
);
WINADVAPI
DWORD
APIENTRY
InitiateShutdownWInt(
    _In_opt_ LPWSTR lpMachineName,
    _In_opt_ LPWSTR lpMessage,
    _In_     DWORD dwGracePeriod,
    _In_     DWORD dwShutdownFlags,
    _In_     DWORD dwReason
);
#ifdef UNICODE
#define InitiateShutdown  InitiateShutdownWInt
#else
#define InitiateShutdown  InitiateShutdownAInt
#endif // !UNICODE

WINADVAPI
DWORD
APIENTRY
CheckForHiberbootInt(
    _Inout_ PBOOLEAN pHiberboot,
    _In_ BOOLEAN bClearFlag
);

WINADVAPI
LSTATUS
APIENTRY
RegSaveKeyExAInt(
    _In_ HKEY hKey,
    _In_ LPCSTR lpFile,
    _In_opt_ CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _In_ DWORD Flags
);

WINADVAPI
LSTATUS
APIENTRY
RegSaveKeyExWInt(
    _In_ HKEY hKey,
    _In_ LPCWSTR lpFile,
    _In_opt_ CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _In_ DWORD Flags
);

#ifdef UNICODE
#define RegSaveKeyEx  RegSaveKeyExWInt
#else
#define RegSaveKeyEx  RegSaveKeyExAInt
#endif // !UNICODE

WINADVAPI
BOOL
APIENTRY
InitiateSystemShutdownExAInt(
    _In_opt_ LPSTR lpMachineName,
    _In_opt_ LPSTR lpMessage,
    _In_ DWORD dwTimeout,
    _In_ BOOL bForceAppsClosed,
    _In_ BOOL bRebootAfterShutdown,
    _In_ DWORD dwReason
);

WINADVAPI
BOOL
APIENTRY
InitiateSystemShutdownExWInt(
    _In_opt_ LPWSTR lpMachineName,
    _In_opt_ LPWSTR lpMessage,
    _In_ DWORD dwTimeout,
    _In_ BOOL bForceAppsClosed,
    _In_ BOOL bRebootAfterShutdown,
    _In_ DWORD dwReason
);
#ifdef UNICODE
#define InitiateSystemShutdownEx  InitiateSystemShutdownExWInt
#else
#define InitiateSystemShutdownEx  InitiateSystemShutdownExAInt
#endif // !UNICODE



#pragma endregion
#pragma region names 
char** name_of_func = new char* [91]{
new char[40] {"AbortSystemShutdownA"},
new char[40] {"AbortSystemShutdownW"},
new char[40] {"InitiateShutdownA"},
new char[40] {"InitiateShutdownW"},
new char[40] {"InitiateSystemShutdownA"},
new char[40] {"InitiateSystemShutdownExA"},
new char[40] {"InitiateSystemShutdownExW"},
new char[40] {"InitiateSystemShutdownW"},
new char[40] {"RegCloseKey"},
new char[40] {"RegConnectRegistryA"},
new char[40] {"RegConnectRegistryW"},
new char[40] {"RegCopyTreeA"},
new char[40] {"RegCopyTreeW"},
new char[40] {"RegCreateKeyA"},
new char[40] {"RegCreateKeyExA"},
new char[40] {"RegCreateKeyExW"},
new char[40] {"RegCreateKeyTransactedA"},
new char[40] {"RegCreateKeyTransactedW"},
new char[40] {"RegCreateKeyW"},
new char[40] {"RegDeleteKeyA"},
new char[40] {"RegDeleteKeyW"},
new char[40] {"RegDeleteKeyExA"},
new char[40] {"RegDeleteKeyExW"},
new char[40] {"RegDeleteKeyTransactedA"},
new char[40] {"RegDeleteKeyTransactedW"},
new char[40] {"RegDisableReflectionKey"},
new char[40] {"RegEnableReflectionKey"},
new char[40] {"RegQueryReflectionKey"},
new char[40] {"RegDeleteValueA"},
new char[40] {"RegDeleteValueW"},
new char[40] {"RegEnumKeyA"},
new char[40] {"RegEnumKeyW"},
new char[40] {"RegEnumKeyExA"},
new char[40] {"RegEnumKeyExW"},
new char[40] {"RegEnumValueA"},
new char[40] {"RegEnumValueW"},
new char[40] {"RegFlushKey"},
new char[40] {"RegGetKeySecurity"},
new char[40] {"RegLoadKeyA"},
new char[40] {"RegLoadKeyW"},
new char[40] {"RegNotifyChangeKeyValue"},
new char[40] {"RegOpenKeyA"},
new char[40] {"RegOpenKeyW"},
new char[40] {"RegOpenKeyExA"},
new char[40] {"RegOpenKeyExW"},
new char[40] {"RegOpenKeyTransactedA"},
new char[40] {"RegOpenKeyTransactedW"},
new char[40] {"RegQueryInfoKeyA"},
new char[40] {"RegQueryInfoKeyW"},
new char[40] {"RegQueryValueA"},
new char[40] {"RegQueryValueW"},
new char[40] {"RegQueryMultipleValuesA"},
new char[40] {"RegQueryMultipleValuesW"},
new char[40] {"RegQueryValueExA"},
new char[40] {"RegQueryValueExW"},
new char[40] {"RegReplaceKeyA"},
new char[40] {"RegReplaceKeyW"},
new char[40] {"RegRestoreKeyA"},
new char[40] {"RegRestoreKeyW"},
new char[40] {"RegRenameKey"},
new char[40] {"RegSaveKeyA"},
new char[40] {"RegSaveKeyW"},
new char[40] {"RegSetKeySecurity"},
new char[40] {"RegSetValueA"},
new char[40] {"RegSetValueW"},
new char[40] {"RegSetValueExA"},
new char[40] {"RegSetValueExW"},
new char[40] {"RegUnLoadKeyA"},
new char[40] {"RegUnLoadKeyW"},
new char[40] {"RegDeleteKeyValueA"},
new char[40] {"RegDeleteKeyValueW"},
new char[40] {"RegSetKeyValueA"},
new char[40] {"RegSetKeyValueW"},
new char[40] {"RegDeleteTreeA"},
new char[40] {"RegDeleteTreeW"},
new char[40] {"RegGetValueA"},
new char[40] {"RegGetValueW"},
new char[40]{ "RegLoadMUIStringA" },
new char[40]{ "RegLoadMUIStringW" },
new char[40] {"RegLoadAppKeyA"},
new char[40] {"RegLoadAppKeyW"},

new char[40] {"RegDisablePredefinedCache"},
new char[40] {"RegDisablePredefinedCacheEx"},

new char[40] {"RegOverridePredefKey"},
new char[40] {"RegOpenUserClassesRoot"},
new char[40] {"RegOpenCurrentUser"},
new char[40] {"RegConnectRegistryExA"},
new char[40] {"RegConnectRegistryExW"},
new char[40]{ "CheckForHiberbootInt" },
new char[40] {"RegSaveKeyExA"},
new char[40] {"RegSaveKeyExW"}
};
#pragma endregion
#pragma region addrFunc
DWORD* ad = new DWORD[91]{(DWORD)&AbortSystemShutdownAInt,
                          (DWORD)&AbortSystemShutdownWInt,

                          (DWORD)&InitiateShutdownAInt,

                          (DWORD)&InitiateShutdownWInt,

                          (DWORD)&InitiateSystemShutdownAInt,

                          (DWORD)&InitiateSystemShutdownExAInt,

                          (DWORD)&InitiateSystemShutdownExWInt,

                          (DWORD)&InitiateSystemShutdownWInt,

                          (DWORD)&RegCloseKeyInt,

                          (DWORD)&RegConnectRegistryAInt,

                          (DWORD)&RegConnectRegistryWInt,

                          (DWORD)&RegCopyTreeAInt,

                          (DWORD)&RegCopyTreeWInt,

                          (DWORD)&RegCreateKeyAInt,

                          (DWORD)&RegCreateKeyExAInt,

                          (DWORD)&RegCreateKeyExWInt,

                          (DWORD)&RegCreateKeyTransactedAInt,

                          (DWORD)&RegCreateKeyTransactedWInt,

                          (DWORD)&RegCreateKeyWInt,

                          (DWORD)&RegDeleteKeyAInt,

                          (DWORD)&RegDeleteKeyWInt,

                          (DWORD)&RegDeleteKeyExAInt,

                          (DWORD)&RegDeleteKeyExWInt,

                          (DWORD)&RegDeleteKeyTransactedAInt,

                          (DWORD)&RegDeleteKeyTransactedWInt,

                          (DWORD)&RegDisableReflectionKeyInt,

                          (DWORD)&RegEnableReflectionKeyInt,

                          (DWORD)&RegQueryReflectionKeyInt,

                          (DWORD)&RegDeleteValueAInt,

                          (DWORD)&RegDeleteValueWInt,

                          (DWORD)&RegEnumKeyAInt,

                          (DWORD)&RegEnumKeyWInt,

                          (DWORD)&RegEnumKeyExAInt,

                          (DWORD)&RegEnumKeyExWInt,

                          (DWORD)&RegEnumValueAInt,

                          (DWORD)&RegEnumValueWInt,

                          (DWORD)&RegFlushKeyInt,

                          (DWORD)&RegGetKeySecurityInt,

                          (DWORD)&RegLoadKeyAInt,

                          (DWORD)&RegLoadKeyWInt,

                          (DWORD)&RegNotifyChangeKeyValueInt,

                          (DWORD)&RegOpenKeyAInt,

                          (DWORD)&RegOpenKeyWInt,

                          (DWORD)&RegOpenKeyExAInt,

                          (DWORD)&RegOpenKeyExWInt,

                          (DWORD)&RegOpenKeyTransactedAInt,

                          (DWORD)&RegOpenKeyTransactedWInt,

                          (DWORD)&RegQueryInfoKeyAInt,

                          (DWORD)&RegQueryInfoKeyWInt,

                          (DWORD)&RegQueryValueAInt,

                          (DWORD)&RegQueryValueWInt,

                          (DWORD)&RegQueryMultipleValuesAInt,

                          (DWORD)&RegQueryMultipleValuesWInt,

                          (DWORD)&RegQueryValueExAInt,

                          (DWORD)&RegQueryValueExWInt,

                          (DWORD)&RegReplaceKeyAInt,

                          (DWORD)&RegReplaceKeyWInt,

                          (DWORD)&RegRestoreKeyAInt,

                          (DWORD)&RegRestoreKeyWInt,

                          (DWORD)&RegRenameKeyInt,

                          (DWORD)&RegSaveKeyAInt,

                          (DWORD)&RegSaveKeyWInt,

                          (DWORD)&RegSetKeySecurityInt,

                          (DWORD)&RegSetValueAInt,

                          (DWORD)&RegSetValueWInt,

                          (DWORD)&RegSetValueExAInt,

                          (DWORD)&RegSetValueExWInt,

                          (DWORD)&RegUnLoadKeyAInt,

                          (DWORD)&RegUnLoadKeyWInt,

                          (DWORD)&RegDeleteKeyValueAInt,

                          (DWORD)&RegDeleteKeyValueWInt,

                          (DWORD)&RegSetKeyValueAInt,

                          (DWORD)&RegSetKeyValueWInt,

                          (DWORD)&RegDeleteTreeAInt,

                          (DWORD)&RegDeleteTreeWInt,

                          (DWORD)&RegGetValueAInt,

                          (DWORD)&RegGetValueWInt,

                          (DWORD)&RegLoadMUIStringAInt,

                          (DWORD)&RegLoadMUIStringWInt,

                          (DWORD)&RegLoadAppKeyAInt,

                          (DWORD)&RegLoadAppKeyWInt,

                          (DWORD)&RegDisablePredefinedCacheInt,

                          (DWORD)&RegDisablePredefinedCacheExInt,

                          (DWORD)&RegOverridePredefKeyInt,

                          (DWORD)&RegOpenUserClassesRootInt,

                          (DWORD)&RegOpenCurrentUserInt,

                          (DWORD)&RegConnectRegistryExAInt,

                          (DWORD)&RegConnectRegistryExWInt,

                          (DWORD)&CheckForHiberbootInt,

                          (DWORD)&RegSaveKeyExAInt,

                          (DWORD)&RegSaveKeyExWInt };
#pragma endregion
#pragma region func_trapline                         
typedef BOOL(WINAPI *ASSA)(LPSTR);
typedef BOOL(WINAPI *ASSW)(LPWSTR);
typedef DWORD(WINAPI *ISA)(LPSTR, LPSTR, DWORD, DWORD, DWORD);
typedef DWORD(WINAPI *ISW)(LPWSTR, LPWSTR, DWORD, DWORD, DWORD);
typedef BOOL(WINAPI* ISSA)(LPSTR, LPSTR, DWORD, BOOL, BOOL);
typedef BOOL(WINAPI* ISSEA)(LPSTR, LPSTR, DWORD, BOOL, BOOL, DWORD);
typedef BOOL(WINAPI* ISSEW)(LPWSTR, LPWSTR, DWORD, BOOL, BOOL, DWORD);
typedef BOOL(WINAPI* ISSW)(LPWSTR, LPWSTR, DWORD, BOOL, BOOL);
typedef LSTATUS(WINAPI* RCK)(HKEY);
typedef LSTATUS(WINAPI* RCRA)(LPCSTR, HKEY, PHKEY);
typedef LSTATUS(WINAPI* RCRW)(LPCWSTR, HKEY, PHKEY);
typedef LSTATUS(WINAPI* RCTA)(HKEY, LPCSTR, HKEY);
typedef LSTATUS(WINAPI* RCTW)(HKEY, LPCWSTR, HKEY);
typedef LSTATUS(WINAPI* RCKA)(HKEY, LPCSTR, PHKEY);
typedef LSTATUS(WINAPI* RCKEA)(HKEY, LPCSTR, DWORD, LPSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
typedef LSTATUS(WINAPI* RCKEW)(HKEY, LPCWSTR, DWORD, LPWSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
typedef LSTATUS(WINAPI* RCKTA)(HKEY, LPCSTR, DWORD, LPSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD, HANDLE, PVOID);
typedef LSTATUS(WINAPI* RCKTW)(HKEY, LPCWSTR, DWORD, LPWSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD, HANDLE, PVOID);
typedef LSTATUS(WINAPI* RCKW)(HKEY, LPCWSTR, PHKEY);
typedef LSTATUS(WINAPI* RDKA)(HKEY, LPCSTR);
typedef LSTATUS(WINAPI* RDKW)(HKEY, LPCWSTR);
typedef LSTATUS(WINAPI* RDKEA)(HKEY, LPCSTR, REGSAM, DWORD);
typedef LSTATUS(WINAPI* RDKEW)(HKEY, LPCWSTR, REGSAM, DWORD);
typedef LSTATUS(WINAPI* RDKTA)(HKEY, LPCSTR, REGSAM, DWORD, HANDLE, PVOID);
typedef LSTATUS(WINAPI* RDKTW)(HKEY, LPCWSTR, REGSAM, DWORD, HANDLE, PVOID);
typedef LONG(WINAPI* RDRK)(HKEY);
typedef LONG(WINAPI* RERK)(HKEY);
typedef LONG(WINAPI* RQRK)(HKEY, BOOL*);
typedef LSTATUS(WINAPI* RDVA)(HKEY, LPCSTR);
typedef LSTATUS(WINAPI* RDVW)(HKEY, LPCWSTR);
typedef LSTATUS(WINAPI* REKA)(HKEY, DWORD, LPSTR, DWORD);
typedef LSTATUS(WINAPI* REKW)(HKEY, DWORD, LPWSTR, DWORD);
typedef LSTATUS(WINAPI* REKEA)(HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPSTR, LPDWORD, PFILETIME);
typedef LSTATUS(WINAPI* REKEW)(HKEY, DWORD, LPWSTR, LPDWORD, LPDWORD, LPWSTR, LPDWORD, PFILETIME);
typedef LSTATUS(WINAPI* REVA)(HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
typedef LSTATUS(WINAPI* REVW)(HKEY, DWORD, LPWSTR, LPDWORD, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
typedef LSTATUS(WINAPI* RGKS)(HKEY, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, LPDWORD);
typedef LSTATUS(WINAPI* RFK)(HKEY);
typedef LSTATUS(WINAPI* RLKA)(HKEY, LPCSTR, LPCSTR);
typedef LSTATUS(WINAPI* RLKW)(HKEY, LPCWSTR, LPCWSTR);
typedef LSTATUS(WINAPI* RNCKV)(HKEY, BOOL, DWORD, HANDLE, BOOL);
typedef LSTATUS(WINAPI* ROKA)(HKEY, LPCSTR, PHKEY);
typedef LSTATUS(WINAPI* ROKW)(HKEY, LPCWSTR, PHKEY);
typedef LSTATUS(WINAPI* ROKEA)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
typedef LSTATUS(WINAPI* ROKEW)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
typedef LSTATUS(WINAPI* ROKTA)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY, HANDLE, PVOID);
typedef LSTATUS(WINAPI* ROKTW)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY, HANDLE, PVOID);
typedef LSTATUS(WINAPI* RQIKA)(HKEY, LPSTR, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, PFILETIME);
typedef LSTATUS(WINAPI* RQIKW)(HKEY, LPWSTR, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, PFILETIME);
typedef LSTATUS(WINAPI* RQVW)(HKEY, LPCWSTR, LPWSTR, PLONG);
typedef LSTATUS(WINAPI* RQVA)(HKEY, LPCSTR, LPSTR, PLONG);
typedef LSTATUS(WINAPI* RQMVA)(HKEY, PVALENTA, DWORD, LPSTR, LPDWORD);
typedef LSTATUS(WINAPI* RQMVW)(HKEY, PVALENTW, DWORD, LPWSTR, LPDWORD);
typedef LSTATUS(WINAPI* RQVEA)(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
typedef LSTATUS(WINAPI* RQVEW)(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
typedef LSTATUS(WINAPI* RRKA)(HKEY, LPCSTR, LPCSTR, LPCSTR);
typedef LSTATUS(WINAPI* RRKW)(HKEY, LPCWSTR, LPCWSTR, LPCWSTR);
typedef LSTATUS(WINAPI* RRKAI)(HKEY, LPCSTR, DWORD);
typedef LSTATUS(WINAPI* RRKWI)(HKEY, LPCWSTR, DWORD);
typedef LSTATUS(WINAPI* RRK)(HKEY, LPCWSTR, LPCWSTR);
typedef LSTATUS(WINAPI* RSKA)(HKEY, LPCSTR, LPSECURITY_ATTRIBUTES);
typedef LSTATUS(WINAPI* RSKW)(HKEY, LPCWSTR, LPSECURITY_ATTRIBUTES);
typedef LSTATUS(WINAPI* RSKS)(HKEY, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR);
typedef LSTATUS(WINAPI* RSVA)(HKEY, LPCSTR, DWORD, LPCSTR, DWORD);
typedef LSTATUS(WINAPI* RSVW)(HKEY, LPCWSTR, DWORD, LPCWSTR, DWORD);
typedef LSTATUS(WINAPI* RSVEA)(HKEY, LPCSTR, DWORD, DWORD, const BYTE*, DWORD);
typedef LSTATUS(WINAPI* RSVEW)(HKEY, LPCWSTR, DWORD, DWORD, const BYTE*, DWORD);
typedef LSTATUS(WINAPI* RULKA)(HKEY, LPCSTR);
typedef LSTATUS(WINAPI* RULKW)(HKEY, LPCWSTR);
typedef LSTATUS(WINAPI* RDKVA)(HKEY, LPCSTR, LPCSTR);
typedef LSTATUS(WINAPI* RDKVW)(HKEY, LPCWSTR, LPCWSTR);
typedef LSTATUS(WINAPI* RSKVA)(HKEY, LPCSTR, LPCSTR, DWORD, LPCVOID, DWORD);
typedef LSTATUS(WINAPI* RSKVW)(HKEY, LPCWSTR, LPCWSTR, DWORD, LPCVOID, DWORD);
typedef LSTATUS(WINAPI* RDTA)(HKEY, LPCSTR);
typedef LSTATUS(WINAPI* RDTW)(HKEY, LPCWSTR);
typedef LSTATUS(WINAPI* RGVA)(HKEY, LPCSTR, LPCSTR, DWORD, LPDWORD, PVOID, LPDWORD);
typedef LSTATUS(WINAPI* RGVW)(HKEY, LPCWSTR, LPCWSTR, DWORD, LPDWORD, PVOID, LPDWORD);
typedef LSTATUS(WINAPI* RLMSA)(HKEY, LPCSTR, LPSTR, DWORD, LPDWORD, DWORD, LPCSTR);
typedef LSTATUS(WINAPI* RLMSW)(HKEY, LPCWSTR, LPCWSTR, DWORD, LPDWORD, DWORD, LPCWSTR);
typedef LSTATUS(WINAPI* RLAKA)(LPCSTR, PHKEY, REGSAM, DWORD, DWORD);
typedef LSTATUS(WINAPI* RLAKW)(LPCWSTR, PHKEY, REGSAM, DWORD, DWORD);
typedef LSTATUS(WINAPI* RDPCE)(VOID);
typedef LSTATUS(WINAPI* RDPC)(VOID);
typedef LSTATUS(WINAPI* ROPK)(HKEY, HKEY);
typedef LSTATUS(WINAPI* ROUCR)(HANDLE, DWORD, REGSAM, PHKEY);
typedef LSTATUS(WINAPI* ROCU)(REGSAM, PHKEY);
typedef LSTATUS(WINAPI* RCREA)(LPCSTR, HKEY, ULONG, PHKEY);
typedef LSTATUS(WINAPI* RCREW)(LPCWSTR, HKEY, ULONG, PHKEY);
typedef LSTATUS(WINAPI* CFH)(PBOOLEAN, BOOLEAN);
typedef LSTATUS(WINAPI* RSKEA)(HKEY, LPCSTR, CONST LPSECURITY_ATTRIBUTES, DWORD);
typedef LSTATUS(WINAPI* RSKEW)(HKEY, LPCWSTR, CONST LPSECURITY_ATTRIBUTES, DWORD);
CFH   _Std_CFH;
RSKEA _Std_RSKEA;
RSKEW _Std_RSKEW;
RCREA  _Std_RCREA;
RCREW  _Std_RCREW;
ROUCR  _Std_ROUCR;
ROCU  _Std_ROCU;
ROPK   _Std_ROPK;
RDPCE  _Std_RDPCE;
RDPC _Std_RDPC;
RLAKA  _Std_RLAKA;
RLAKW  _Std_RLAKW;
RLMSA _Std_RLMSA;
RLMSW _Std_RLMSW;
RGVA  _Std_RGVA;
RGVW  _Std_RGVW;
RDTW  _Std_RDTW;
RDTA  _Std_RDTA;
RSKVA _Std_RSKVA;
RSKVW _Std_RSKVW;
RDKVA _Std_RDKVA;
RDKVW _Std_RDKVW;
RULKA _Std_RULKA;
RULKW _Std_RULKW;
RSVEA _Std_RSVEA;
RSVEW _Std_RSVEW;
RSVA _Std_RSVA;
RSVW _Std_RSVW;
RSKS _Std_RSKS;
RSKA  _Std_RSKA;
RSKW  _Std_RSKW;
RRK    _Std_RRK;
RRKAI _Std_RRKAI;
RRKWI _Std_RRKWI;
RRKA  _Std_RRKA;
RRKW  _Std_RRKW;
RQVEA _Std_RQVEA;
RQVEW _Std_RQVEW;
RQMVA _Std_RQMVA;
RQMVW _Std_RQMVW;
RQVA _Std_RQVA;
RQVW _Std_RQVW;
RQIKA _Std_RQIKA;
RQIKW _Std_RQIKW;
ROKTA _Std_ROKTA;
ROKTW _Std_ROKTW;
RNCKV _Std_RNCKV;
RLKA _Std_RLKA;
RLKW _Std_RLKW;
RGKS _Std_RGKS;
RFK  _Std_RFK;
REVA _Std_REVA;
REVW _Std_REVW;
ASSA _Std_ASSA;
ASSW _Std_ASSW;
ISA _Std_ISA;
ISSA _Std_ISSA;
ISSEA _Std_ISSEA;
ISSEW _Std_ISSEW;
ISSW _Std_ISSW;
ISW _Std_ISW;
RCK _Std_RCK;
RCRA _Std_RCRA;
RCRW _Std_RCRW;
RCTA _Std_RCTA;
RCTW _Std_RCTW;
RCKA _Std_RCKA;
RCKEA _Std_RCKEA;
RCKEW _Std_RCKEW;
RCKTA _Std_RCKTA;
RCKTW _Std_RCKTW;
RCKW  _Std_RCKW;
RDKA  _Std_RDKA;
RDKW  _Std_RDKW;
RDKEA  _Std_RDKEA;
RDKEW  _Std_RDKEW;
RDKTA  _Std_RDKTA;
RDKTW  _Std_RDKTW;
RDRK  _Std_RDRK;
RERK  _Std_RERK;
RQRK  _Std_RQRK;
RDVA  _Std_RDVA;
RDVW  _Std_RDVW;
REKA  _Std_REKA;
REKW  _Std_REKW;
REKEA  _Std_REKEA;
REKEW  _Std_REKEW;
ROKA _Std_ROKA;
ROKW _Std_ROKW;
ROKEW _Std_ROKEW;
ROKEA _Std_ROKEA;
#pragma endregion