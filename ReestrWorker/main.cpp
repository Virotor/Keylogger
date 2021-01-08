
#include <string.h>
#include <stdio.h>
#include <windows.h>
#include <iostream>

using namespace std;

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
#pragma pack(push,1)
struct INJECTORCODE
{
	BYTE  instr_push_loadlibrary_arg; //инструкция push
	DWORD loadlibrary_arg;            //аргумент push  

	WORD  instr_call_loadlibrary;     //инструкция call []  
	DWORD adr_from_call_loadlibrary;

	BYTE  instr_push_exitthread_arg;
	DWORD exitthread_arg;

	WORD  instr_call_exitthread;
	DWORD adr_from_call_exitthread;

	DWORD addr_loadlibrary;
	DWORD addr_exitthread;     //адрес функции ExitTHread
	BYTE  libraryname[100]{ "DllReester" };    //имя и путь к загружаемой библиотеке  
};
#pragma pack(pop)

BOOL InjectDll(DWORD pid)
{
	HANDLE hProcess;
	BYTE* p_code;
	INJECTORCODE cmds;
	DWORD  id;
	SIZE_T wr;

	//открыть процесс с нужным доступом
	hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_WRITE |
		PROCESS_VM_OPERATION, FALSE, pid);
	if (hProcess == NULL)
	{
		MessageBoxA(NULL, "You have not enough rights to attach dlls",
			"Error!", 0);
		return FALSE;
	}

	//зарезервировать память в процессе
	p_code = (BYTE*)VirtualAllocEx(hProcess, 0, sizeof(INJECTORCODE),
		MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (p_code == NULL)
	{
		std::cout << "Unable to alloc memory in remote process" << std::endl;
		return FALSE;
	}

	//инициализировать  машинный код
	cmds.instr_push_loadlibrary_arg = 0x68; //машинный код инструкции push
	cmds.loadlibrary_arg = (DWORD)((BYTE*)p_code
		+ offsetof(INJECTORCODE, libraryname));

	cmds.instr_call_loadlibrary = 0x15ff; //машинный код инструкции call
	cmds.adr_from_call_loadlibrary =
		(DWORD)(p_code + offsetof(INJECTORCODE, addr_loadlibrary));

	cmds.instr_push_exitthread_arg = 0x68;
	cmds.exitthread_arg = 0;

	cmds.instr_call_exitthread = 0x15ff;
	cmds.adr_from_call_exitthread =
		(DWORD)(p_code + offsetof(INJECTORCODE, addr_exitthread));

	cmds.addr_loadlibrary =
		(DWORD)GetProcAddress(GetModuleHandle(convertStr("kernel32.dll")), "LoadLibraryA");

	cmds.addr_exitthread =
		(DWORD)GetProcAddress(GetModuleHandle(convertStr("kernel32.dll")), "ExitThread");

	//strcpy_s((char*)cmds.libraryname,strlen((char*)cmds.libraryname), );

	/*После инициализации cmds в мнемонике ассемблера выглядит следующим
	  образом:
		push  adr_library_name               ;аргумент ф-ции loadlibrary
		call dword ptr [loadlibrary_adr]     ; вызвать LoadLibrary
		push exit_thread_arg                 ;аргумент для ExitThread
		call dword ptr [exit_thread_adr]     ;вызвать ExitThread
	*/

	//записать машинный код по зарезервированному адресу
	WriteProcessMemory(hProcess, p_code, &cmds, sizeof(cmds), &wr);

	//выполнить машинный код
	HANDLE z = CreateRemoteThread(hProcess, NULL, 0,
		(unsigned long(__stdcall*)(void*))p_code, 0, 0, &id);

	//ожидать завершения удаленного потока
	WaitForSingleObject(z, INFINITE);
	//освободить память
	VirtualFreeEx(hProcess, (void*)p_code, sizeof(cmds), MEM_RELEASE);

	return TRUE;
}




int main()
{
	HKEY hKey;
	DWORD dwDisposition;
	unsigned char szStr[2];
	szStr[0] = '1'; szStr[1] = '\0';
	int i;
	Sleep(1000);
	cout << "start" << endl;
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("Software\\VR_Online\\Test"), 0, KEY_ALL_ACCESS, &hKey) != ERROR_SUCCESS)
		cout << "\nError opening the desired subkey (doesn't exist?).\n";
	else
	{
		if (RegSetValueEx(hKey, TEXT("String Value"), NULL, REG_SZ, szStr, sizeof(szStr)) == ERROR_SUCCESS)
			cout << "\nThe value of the key was set successfully.\n";
		else
			cout << "\nError setting the value of the key.\n";
	}
	Sleep(1000);
	RegCloseKey(hKey);
	Sleep(1000);
	RegCreateKeyEx(HKEY_LOCAL_MACHINE, TEXT("Software\\VR_Online\\Test\\Another SubKey"), 0, NULL, 0, 0, NULL, &hKey, &dwDisposition);
	if (dwDisposition != REG_CREATED_NEW_KEY && dwDisposition != REG_OPENED_EXISTING_KEY)
		cout << "\nError creating the desired subkey (permissions?).\n";
	else
		cout << "\nThe subkey was successfully created.\n";
	Sleep(1000);
	RegCloseKey(hKey);
	Sleep(1000);
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("Software\\VR_Online\\Test"), 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS)
	{
		if (RegDeleteValue(hKey, TEXT("String Value")) == ERROR_SUCCESS)
			cout << "\nString Value value successfully removed.\n";
		else
			cout << "\nError removing the specified value (permissions?).\n";
	}
	else
		cout << "\nError opening the specified subkey path (doesn't exist?).\n";
	Sleep(1000);
	RegCloseKey(hKey);

	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("Software\\VR_Online\\Test"), 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS)
	{
		if (RegDeleteKey(hKey, TEXT("Another SubKey")) == ERROR_SUCCESS)
			cout << "\nAnother SubKey key successfully removed.\n";
		else
			cout << "\nError removing the specified key (permissions?).\n";
	}
	else
		cout << "\nError opening the specified subkey path (doesn't exist?).\n";
	Sleep(1000);
	RegCloseKey(hKey);
	Sleep(1000);
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("Software\\VR_Online"), 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS)
	{
		if (RegDeleteKey(hKey, TEXT("Test")) == ERROR_SUCCESS)
			cout << "\nTest key successfully removed.\n";
		else
			cout << "\nError removing the specified key (permissions?).\n";
	}
	else
		cout << "\nError opening the specified subkey path (doesn't exist?).\n";
	Sleep(1000);
	RegCloseKey(hKey);
	Sleep(1000);
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("Software"), 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS)
	{
		if (RegDeleteKey(hKey, TEXT("VR_Online")) == ERROR_SUCCESS)
			cout << "\nVR_Online key successfully removed.\n";
		else
			cout << "\nError removing the specified key (permissions?).\n";
	}
	else
		cout << "\nError opening the specified subkey path (doesn't exist?).\n";
	Sleep(1000);
	RegCloseKey(hKey);
	system("pause");
}