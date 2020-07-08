#include "util.h"

DWORD get_process_id(char* name)
{
	DWORD pid = 0;
	PROCESSENTRY32 pe32;
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap != INVALID_HANDLE_VALUE)
	{
		pe32.dwSize = sizeof(PROCESSENTRY32);
		do
		{
			if (lstrcmpA(pe32.szExeFile, name) == 0)
				pid = pe32.th32ProcessID;

		} while (Process32Next(hProcessSnap, &pe32));

		CloseHandle(hProcessSnap);
	}
	return pid;
}