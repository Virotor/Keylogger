#include "structureDiscription.h"
#define _CRT_SECURE_NO_WARNINGS
//структура описывает поля, в которых содержится код внедрения
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



void main(int argc, char* argv[]) {

	if(argc != 1 ){
		STARTUPINFO cif;
		ZeroMemory(&cif, sizeof(STARTUPINFO));
		PROCESS_INFORMATION pi;
		INJECTORCODE cmds;
		BYTE* p_code;
		char* lpszDllName;
		DWORD wr, id;
		if (CreateProcessW(NULL, convertStr(argv[1]), NULL, NULL, FALSE, NULL, NULL, NULL, &cif, &pi)) {
			

			if (InjectDll(pi.dwProcessId)) {
				std::cout << "Tracking" << std::endl;
				WaitForSingleObject(pi.hProcess, INFINITE);
				bool isWorking = true;
				while (isWorking)
				{
					DWORD dw = WaitForSingleObject(pi.hProcess, 2000);
					switch (dw)
					{
					case WAIT_OBJECT_0:
						std::cout << "Program is finish" << std::endl;
						isWorking = false;
						break;
					}
				}
			}
			else {
				std::cout << "Proccess cannot tracking" << std::endl;
			}
      
		}
		else {
			std::cout << "Process cannot be lauch" << std::endl;
		}

	}
	else {
		std::cout << "Incorrect commandline arguments" <<std:: endl;
	}
	
	
}