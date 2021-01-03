#include "structureDiscription.h"

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