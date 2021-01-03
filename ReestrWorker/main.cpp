
#include <string.h>
#include <stdio.h>
#include <windows.h>
#include <iostream>

using namespace std;

int main()
{
	HKEY hKey;
	DWORD dwDisposition;
	unsigned char szStr[2];
	szStr[0] = '1'; szStr[1] = '\0';
	int i;
	//cin >> i;
	Sleep(40000);

	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("Software\\VR_Online\\Test"), 0, KEY_ALL_ACCESS, &hKey) != ERROR_SUCCESS)
		cout << "\nError opening the desired subkey (doesn't exist?).\n";
	else
	{
		if (RegSetValueEx(hKey, TEXT("String Value"), NULL, REG_SZ, szStr, sizeof(szStr)) == ERROR_SUCCESS)
			cout << "\nThe value of the key was set successfully.\n";
		else
			cout << "\nError setting the value of the key.\n";
	}
	RegCloseKey(hKey);

	RegCreateKeyEx(HKEY_LOCAL_MACHINE, TEXT("Software\\VR_Online\\Test\\Another SubKey"), 0, NULL, 0, 0, NULL, &hKey, &dwDisposition);
	if (dwDisposition != REG_CREATED_NEW_KEY && dwDisposition != REG_OPENED_EXISTING_KEY)
		cout << "\nError creating the desired subkey (permissions?).\n";
	else
		cout << "\nThe subkey was successfully created.\n";
	RegCloseKey(hKey);

	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("Software\\VR_Online\\Test"), 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS)
	{
		if (RegDeleteValue(hKey, TEXT("String Value")) == ERROR_SUCCESS)
			cout << "\nString Value value successfully removed.\n";
		else
			cout << "\nError removing the specified value (permissions?).\n";
	}
	else
		cout << "\nError opening the specified subkey path (doesn't exist?).\n";

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

	RegCloseKey(hKey);

	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("Software\\VR_Online"), 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS)
	{
		if (RegDeleteKey(hKey, TEXT("Test")) == ERROR_SUCCESS)
			cout << "\nTest key successfully removed.\n";
		else
			cout << "\nError removing the specified key (permissions?).\n";
	}
	else
		cout << "\nError opening the specified subkey path (doesn't exist?).\n";

	RegCloseKey(hKey);

	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("Software"), 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS)
	{
		if (RegDeleteKey(hKey, TEXT("VR_Online")) == ERROR_SUCCESS)
			cout << "\nVR_Online key successfully removed.\n";
		else
			cout << "\nError removing the specified key (permissions?).\n";
	}
	else
		cout << "\nError opening the specified subkey path (doesn't exist?).\n";

	RegCloseKey(hKey);

	system("pause");
}