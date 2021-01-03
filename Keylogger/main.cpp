#include "structureDiscription.h"

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
	BYTE  libraryname[100];    //имя и путь к загружаемой библиотеке  
};


void main(int argc, char* argv[]) {

	if(argc != 1 ){
		STARTUPINFO cif;
		ZeroMemory(&cif, sizeof(STARTUPINFO));
		PROCESS_INFORMATION pi;
		INJECTORCODE cmds;
		BYTE* p_code;
		char* lpszDllName;
		DWORD wr, id;

		if (CreateProcessW(NULL, convertStr(argv[1]), NULL, NULL, FALSE, DETACHED_PROCESS, NULL, NULL, &cif, &pi)) {
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
			std::cout << "Process cannot be lauch" << std::endl;
		}

	}
	else {
		std::cout << "Incorrect commandline arguments" <<std:: endl;
	}
	
	
}