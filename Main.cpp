#define _CRT_SECURE_NO_WARNINGS
#include "SDK/includes.h"
#include "SDK/Main/Main.h"
#include "SDK/Main/raw.h"
#include "SDK/Main/ErasePE.h"
#include "SDK/ject.h"
#include "SDK/VAC Bypass/vac-bypass.h"

#include "Main.h"
#include "calibri.h"
#include <iostream>

#include <string>
globals g_globals;

#define cheatversion xorstr_("0.0.1")

typedef INT(__stdcall* dllmain)(HMODULE, DWORD, LPVOID);

std::string decrresp = "";
	
struct ManualMap
{
	LPVOID ImageBase;

	PIMAGE_NT_HEADERS NtHeaders;
	PIMAGE_BASE_RELOCATION BaseReloc;
	PIMAGE_IMPORT_DESCRIPTOR ImportDirectory;


};

DWORD FindProcessId(std::string processName)
{
	PROCESSENTRY32 processInfo;
	processInfo.dwSize = sizeof(processInfo);

	HANDLE processSnapshot = li(CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, NULL);
	if (processSnapshot == INVALID_HANDLE_VALUE)
		return 0;

	li(Process32First)(processSnapshot, &processInfo);
	if (!processName.compare(processInfo.szExeFile))
	{
		li(CloseHandle)(processSnapshot);
		return processInfo.th32ProcessID;
	}

	while (li(Process32Next)(processSnapshot, &processInfo))
	{
		if (!processName.compare(processInfo.szExeFile))
		{
			li(CloseHandle)(processSnapshot);
			return processInfo.th32ProcessID;
		}
	}

	li(CloseHandle)(processSnapshot);
	return 0;
}

DWORD __stdcall LibraryLoader(LPVOID Memory)
{

	ManualMap* MMap = (ManualMap*)Memory;

	PIMAGE_BASE_RELOCATION pIBR = MMap->BaseReloc;

	DWORD delta = (DWORD)((LPBYTE)MMap->ImageBase - MMap->NtHeaders->OptionalHeader.ImageBase); // Calculate the delta

	while (pIBR->VirtualAddress)
	{
		if (pIBR->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
		{
			int count = (pIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			PWORD list = (PWORD)(pIBR + 1);

			for (int i = 0; i < count; i++)
			{
				if (list[i])
				{
					PDWORD ptr = (PDWORD)((LPBYTE)MMap->ImageBase + (pIBR->VirtualAddress + (list[i] & 0xFFF)));
					*ptr += delta;
				}
			}
		}

		pIBR = (PIMAGE_BASE_RELOCATION)((LPBYTE)pIBR + pIBR->SizeOfBlock);
	}

	PIMAGE_IMPORT_DESCRIPTOR pIID = MMap->ImportDirectory;

	// Resolve DLL imports
	while (pIID->Characteristics)
	{
		PIMAGE_THUNK_DATA OrigFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)MMap->ImageBase + pIID->OriginalFirstThunk);
		PIMAGE_THUNK_DATA FirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)MMap->ImageBase + pIID->FirstThunk);

		HMODULE hModule = li(LoadLibraryA)((LPCSTR)MMap->ImageBase + pIID->Name);

		if (!hModule)
			return FALSE;

		while (OrigFirstThunk->u1.AddressOfData)
		{
			if (OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				// Import by ordinal
				DWORD Function = (DWORD)li(GetProcAddress)(hModule,
					(LPCSTR)(OrigFirstThunk->u1.Ordinal & 0xFFFF));

				if (!Function)
					return FALSE;

				FirstThunk->u1.Function = Function;
			}
			else
			{
				// Import by name
				PIMAGE_IMPORT_BY_NAME pIBN = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)MMap->ImageBase + OrigFirstThunk->u1.AddressOfData);
				DWORD Function = (DWORD)li(GetProcAddress)(hModule, (LPCSTR)pIBN->Name);
				if (!Function)
					return FALSE;

				FirstThunk->u1.Function = Function;
			}
			OrigFirstThunk++;
			FirstThunk++;
		}
		pIID++;
	}

	if (MMap->NtHeaders->OptionalHeader.AddressOfEntryPoint)
	{
		dllmain EntryPoint = (dllmain)((LPBYTE)MMap->ImageBase + MMap->NtHeaders->OptionalHeader.AddressOfEntryPoint);

		return EntryPoint((HMODULE)MMap->ImageBase, DLL_PROCESS_ATTACH, NULL); // Call the entry point
	}
	return TRUE;
}


int Log::Send(const char* msg, ...)
{
	if (msg == nullptr)
		return 0;

	char* buffer;
	va_list list;
	va_start(list, msg);
	int	len = _vscprintf(msg, list) + 1;
	buffer = (char*)malloc(len * sizeof(char));
	if (NULL != buffer)
	{
		vsprintf_s(buffer, len, msg, list);
		puts(buffer);
		free(buffer);
	}
	va_end(list);
	return 1;
}


std::string SDK::GetHWID()
{
	HW_PROFILE_INFO hwProfileInfo;

	li(GetCurrentHwProfile)(&hwProfileInfo);

	std::string myhwid(hwProfileInfo.szHwProfileGuid);

	return myhwid;
}


std::string SDK::Registry::GetRegValue(HKEY where, LPCSTR reg, LPCSTR value)
{
	HKEY rKey;
	char Reget[1024];
	DWORD RegetPath = 1024;
	li(RegOpenKeyExA)(HKEY_CURRENT_USER, reg, 0, KEY_QUERY_VALUE, &rKey);
	li(RegQueryValueExA)(rKey, (LPCSTR)value, NULL, NULL, (LPBYTE)Reget, &RegetPath);
	li(RegCloseKey)(rKey);
	return Reget;
}

void SDK::Registry::SetRegValue(HKEY keyg, LPCSTR reg, LPCSTR key, std::string regval) {
	HKEY hKey;
	if (li(RegCreateKeyExA)(keyg, reg, 0, 0, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, NULL));
	li(RegOpenKeyExA)(keyg, reg, 0,
		KEY_ALL_ACCESS, &hKey);
	li(RegSetValueExA)(hKey, key, 0, REG_SZ, (LPBYTE)regval.c_str(), regval.length());
}


void SDK::Files::Append(const char* name, const char* content) {
	std::ofstream outfile;
	outfile.open(name, std::ios_base::app);
	outfile << content;
}

void SDK::Files::Write(const char* name, const char* content)
{
	std::ofstream outfile;
	outfile.open(name, std::ios_base::app);
	outfile << content;
	outfile.close();
}

void uncharToChar(unsigned char ar1[], char ar2[], int hm)
{
	for (int i = 0; i < hm; i++)
	{
		ar2[i] = static_cast<char>(ar1[i]);
	}
}

std::string SDK::GetMAC()
{
	PIP_ADAPTER_INFO AdapterInfo;
	DWORD dwBufLen = sizeof(IP_ADAPTER_INFO);
	char* mac_addr = (char*)malloc(18);

	AdapterInfo = (IP_ADAPTER_INFO*)malloc(sizeof(IP_ADAPTER_INFO));
	if (AdapterInfo == NULL) {
		free(mac_addr);
		return NULL; // it is safe to call free(NULL)
	}

	// Make an initial call to GetAdaptersInfo to get the necessary size into the dwBufLen variable
	if (li(GetAdaptersInfo)(AdapterInfo, &dwBufLen) == ERROR_BUFFER_OVERFLOW) {
		free(AdapterInfo);
		AdapterInfo = (IP_ADAPTER_INFO*)malloc(dwBufLen);
		if (AdapterInfo == NULL) {
			free(mac_addr);
			return NULL;
		}
	}

	if (li(GetAdaptersInfo)(AdapterInfo, &dwBufLen) == NO_ERROR) {
		// Contains pointer to current adapter info
		PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
		// technically should look at pAdapterInfo->AddressLength
		//   and not assume it is 6.
		sprintf(mac_addr, xorstr_("%02X:%02X:%02X:%02X:%02X:%02X"),
			pAdapterInfo->Address[0], pAdapterInfo->Address[1],
			pAdapterInfo->Address[2], pAdapterInfo->Address[3],
			pAdapterInfo->Address[4], pAdapterInfo->Address[5]);
	}
	free(AdapterInfo);
	return mac_addr; // caller must free.
}

std::string SDK::GetGPU()
{
	DISPLAY_DEVICEA dd;
	dd.cb = sizeof(DISPLAY_DEVICEA);
	EnumDisplayDevicesA(NULL, 0, &dd, EDD_GET_DEVICE_INTERFACE_NAME);
	return std::string(dd.DeviceString);
}

std::string SDK::GetCPU()
{
	int CPUInfo[4] = { -1 };
	__cpuid(CPUInfo, 0x80000000);
	unsigned int nExIds = CPUInfo[0];

	char CPUBrandString[0x40] = { 0 };
	for (unsigned int i = 0x80000000; i <= nExIds; ++i)
	{
		__cpuid(CPUInfo, i);
		if (i == 0x80000002)
		{
			memcpy(CPUBrandString,
				CPUInfo,
				sizeof(CPUInfo));
		}
		else if (i == 0x80000003)
		{
			memcpy(CPUBrandString + 16,
				CPUInfo,
				sizeof(CPUInfo));
		}
		else if (i == 0x80000004)
		{
			memcpy(CPUBrandString + 32, CPUInfo, sizeof(CPUInfo));
		}
	}

	return CPUBrandString;
}


int cinme;
int waitinjtime = SessionTime;

char user_name[255] = "";
char pass_word[255] = "";

std::string accstatus = xorstr_("ERROR");

std::string subtime = xorstr_("ERROR");

int textcol = 2;
bool loggedin = false;

int cooldownlogin = 0;

std::string timeStampToHReadble(const time_t rawtime)
{
	struct tm* dt;
	char buffer[30];
	dt = li(localtime)(&rawtime);
	li(strftime)(buffer, sizeof(buffer), "%m%d%H%M%y", dt);
	return std::string(buffer);
}

std::string SDK::GetRandomString(size_t val)
{
	std::string str(xorstr_("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890"));
	std::random_device rd;
	std::mt19937 generator(rd());
	std::shuffle(str.begin(), str.end(), generator);
	return str.substr(0, val);
}

void DeleteBinary()
{
	CHAR szExeFileName[MAX_PATH];
	li(GetModuleFileName)(NULL, szExeFileName, MAX_PATH);
	std::string newname = SDK::GetRandomString(16).c_str();
	newname.append(xorstr_(".exe"));

	std::string cmdline = xorstr_("cmd.exe /c ping localhost -n 3 > nul & del /f /q  ");
	cmdline.append(newname);

	li(rename)(szExeFileName, newname.c_str());
	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };

	LPSTR szCmd = const_cast<char*>(cmdline.c_str());

	li(CreateProcessA)(NULL, szCmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
	li(CloseHandle)(pi.hProcess);
	li(CloseHandle)(pi.hThread);

	li(raise)(11);
}


DWORD WINAPI SDK::StartSession(LPVOID)
{
	std::this_thread::sleep_for(std::chrono::seconds(SessionTime));
	DeleteBinary();
	return 1;
}


std::vector<std::string> split_string(const std::string& str, const std::string& symbol)
{
	std::vector<std::string> tokens;
	size_t prev = 0, pos = 0;
	do
	{
		pos = str.find(symbol, prev);
		if (pos == std::string::npos) pos = str.length();
		std::string token = str.substr(prev, pos - prev);
		if (!token.empty()) tokens.push_back(token);
		prev = pos + symbol.length();

	} while (pos < str.length() && prev < str.length());

	return tokens;
}

std::string loaderdescription = xorstr_("ERROR");

std::string aes_key, aes_iv;

DWORD WINAPI Login(LPVOID)
{
	li(Sleep)(1000);

	SDK::Registry::SetRegValue(HKEY_CURRENT_USER, REGPATH, LOGIN, user_name);
	SDK::Registry::SetRegValue(HKEY_CURRENT_USER, REGPATH, PASSWORD, pass_word);

	std::string initial = Encrypt::DecryptAES256(HTTP::HttpPrivateSend(xorstr_("login"), user_name, pass_word, SDK::GetHWID()), CipherKey, Cipher_IV_Key);

	if (json::parse(initial)[xorstr_("data")] == xorstr_("ok")) {
		subtime = json::parse(initial)["subtime"];
		subtime = subtime + xorstr_(" days");
		loaderdescription = json::parse(initial)[xorstr_("description")];
		accstatus = xorstr_("Online");
		textcol = 1;
		loggedin = true;
	}
	else if (json::parse(initial)[xorstr_("error")] == xorstr_("Banned")) {
		accstatus = xorstr_("You are banned. ");
		textcol = 2;
		return 0;
	}
	else if (json::parse(initial)[xorstr_("error")] == xorstr_("No Subscription")) {
		accstatus = xorstr_("No Subscription.");
		textcol = 2;
		return 0;
	}
	else {
		accstatus = xorstr_("Invalid Username or Password");
		textcol = 2;
		return 0;
	}
	ErasePEHeaderFromMemory();
	return 0x228;

}


std::string loader_brand_name = SDK::GetRandomString(32);

// Main code
int APIENTRY WinMain(HINSTANCE, HINSTANCE, LPSTR, int)
{

	std::string siteconnect = xorstr_("https://");
	siteconnect.append(WebsiteApi);
bool checkinternet = InternetCheckConnection(siteconnect.c_str(), FLAG_ICC_FORCE_CONNECTION, 0);
if (!checkinternet) {
	accstatus = xorstr_("Offline");
	textcol = 2;
}
else
{
	accstatus = xorstr_("Online");
	textcol = 1;
}

	std::srand(time(NULL));

	VACBypass::KillSteamProcesses();

	li(CreateThread)(0, 0, &SDK::StartSession, 0, 0, 0);

	int someint1 = 54893;
	int someint2 = 58994350;

	std::string login = SDK::Registry::GetRegValue(HKEY_CURRENT_USER, REGPATH, LOGIN);
	std::string passwerd = SDK::Registry::GetRegValue(HKEY_CURRENT_USER, REGPATH, PASSWORD);

	const char* cock1 = login.c_str();
	const char* cock2 = passwerd.c_str();

	li(strcat)(user_name, cock1);
	li(strcat)(pass_word, cock2);

	// Create application window
	
	WNDCLASSEX wc = { sizeof(WNDCLASSEX), CS_CLASSDC, WndProc, 0L, 0L, li(GetModuleHandle)(NULL), NULL, NULL, NULL, NULL, loader_brand_name.c_str(), NULL };
	RegisterClassEx(&wc);
	
	main_hwnd = CreateWindow(wc.lpszClassName, loader_brand_name.c_str(), WS_POPUP, 0, 0, 5, 5, NULL, NULL, wc.hInstance, NULL);

	// Initialize Direct3D
	if (!CreateDeviceD3D(main_hwnd)) {
		CleanupDeviceD3D();
		UnregisterClass(wc.lpszClassName, wc.hInstance);
		return 1;
	}

	// Show the window
	ShowWindow(main_hwnd, SW_HIDE);
	UpdateWindow(main_hwnd);

	// Setup Dear ImGui context
	ImGui::CreateContext();

	ImGuiIO& io = ImGui::GetIO();
	io.IniFilename = nullptr; //crutial for not leaving the imgui.ini file
	io.ConfigFlags |= ImGuiWindowFlags_NoTitleBar | ImGuiConfigFlags_ViewportsEnable; // Enable Multi-Viewport / Platform Windows

	// Setup Dear ImGui style
	ImGui::StyleColorsDark();
	//ImGui::StyleColorsClassic();

	// When viewports are enabled we tweak WindowRounding/WindowBg so platform windows can look identical to regular ones.
	ImGuiStyle* style = &ImGui::GetStyle();
	style->FramePadding = ImVec2(4, 2);
	style->ItemSpacing = ImVec2(10, 2);
	style->IndentSpacing = 12;
	style->ScrollbarSize = 10;

	style->WindowRounding = 4;
	style->FrameRounding = 4;
	style->PopupRounding = 4;
	style->ScrollbarRounding = 6;
	style->GrabRounding = 4;
	style->TabRounding = 4;

	style->WindowTitleAlign = ImVec2(0.5f, 0.5f);
	style->WindowMenuButtonPosition = ImGuiDir_Right;

	style->DisplaySafeAreaPadding = ImVec2(4, 4);	

	// Setup Platform/Renderer backends
	ImGui_ImplWin32_Init(main_hwnd);
	ImGui_ImplDX9_Init(g_pd3dDevice);

	// Load Fonts
	// - If no fonts are loaded, dear imgui will use the default font. You can also load multiple fonts and use ImGui::PushFont()/PopFont() to select them.
	// - AddFontFromFileTTF() will return the ImFont* so you can store it if you need to select the font among multiple.
	// - If the file cannot be loaded, the function will return NULL. Please handle those errors in your application (e.g. use an assertion, or display an error and quit).
	// - The fonts will be rasterized at a given size (w/ oversampling) and stored into a texture when calling ImFontAtlas::Build()/GetTexDataAsXXXX(), which ImGui_ImplXXXX_NewFrame below will call.
	// - Read 'docs/FONTS.md' for more instructions and details.
	// - Remember that in C/C++ if you want to include a backslash \ in a string literal you need to write a double backslash \\ !
	//io.Fonts->AddFontDefault();
	io.Fonts->AddFontFromMemoryTTF(calibri, sizeof(calibri), 16);
	//io.Fonts->AddFontFromFileTTF("../../misc/fonts/Cousine-Regular.ttf", 15.0f);
	//io.Fonts->AddFontFromFileTTF("../../misc/fonts/DroidSans.ttf", 16.0f);
	//io.Fonts->AddFontFromFileTTF("../../misc/fonts/ProggyTiny.ttf", 10.0f);
	//ImFont* font = io.Fonts->AddFontFromFileTTF("c:\\Windows\\Fonts\\ArialUni.ttf", 18.0f, NULL, io.Fonts->GetGlyphRangesJapanese());
	//IM_ASSERT(font != NULL);

	DWORD window_flags = ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoTitleBar;

	RECT screen_rect;
	GetWindowRect(GetDesktopWindow(), &screen_rect);
	auto x = float(screen_rect.right - WINDOW_WIDTH) / 2.f;
	auto y = float(screen_rect.bottom - WINDOW_HEIGHT) / 2.f;

	// Main loop
	MSG msg;
	ZeroMemory(&msg, sizeof(msg));

	std::thread first(Security::Init);
	first.detach();

	std::string menutitle = LOADER_BRAND;

	while (msg.message != WM_QUIT)
	{
		if (PeekMessage(&msg, NULL, 0U, 0U, PM_REMOVE))
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
			continue;
		}

		// Start the Dear ImGui frame
		ImGui_ImplDX9_NewFrame();
		ImGui_ImplWin32_NewFrame();
		ImGui::NewFrame();
		{
			ImGui::SetNextWindowPos(ImVec2(x, y), ImGuiCond_Once);
			ImGui::SetNextWindowSize(ImVec2(WINDOW_WIDTH, WINDOW_HEIGHT));
			ImGui::SetNextWindowBgAlpha(1.0f);

			ImGui::Begin(loader_brand_name.c_str(), &loader_active, window_flags);
			{
				ImDrawList* draw = ImGui::GetWindowDrawList();
				const ImVec2 pos(ImGui::GetWindowPos().x + 6, ImGui::GetWindowPos().y + 6);


				draw->AddRectFilled(pos, ImVec2(pos.x + 385, pos.y + 20), ImColor(35, 39, 42), 5);
				draw->AddRectFilled(ImVec2(pos.x + 270, pos.y + 270), ImVec2(pos.x + 385, pos.y + 290), ImColor(35, 39, 42), 5);
				
				float font_size = ImGui::GetFontSize() * menutitle.size() / 2;
				ImGui::SameLine(
					ImGui::GetWindowSize().x / 2 -
					font_size + (font_size / 2)
				);

				ImGui::TextColored(ImVec4(0.61f, 0.66f, 0.76f, 1.0f), menutitle.c_str());

				//	ImGui::SetCursorPosX((ImGui::GetWindowWidth() - 180) / 2);


				if (loggedin) {

					ImGui::Text(xorstr_(""));
					ImGui::Text(xorstr_("Welcome,"));
					ImGui::SameLine();
					ImGui::SetCursorPosX((ImGui::GetWindowWidth() - 240) / 2);
					ImGui::TextColored(ImVec4(0.26f, 0.49f, 0.83f, 1.0f), user_name);
					ImGui::Text(xorstr_("Subscription for:"));
					ImGui::SameLine();
					ImGui::TextColored(ImVec4(0.26f, 0.84f, 0.67f, 1.0f), subtime.c_str());
					ImGui::Text(loaderdescription.c_str());
					//ImGui::SetCursorPosX((ImGui::GetWindowWidth() - 240) / 2);
					ImGui::Text(xorstr_(""));
					if (ImGui::Button(xorstr_("Inject CS:GO"), ImVec2(384, 25))) {

						VACBypass::Init();

						while (1)
						{
							if (FindProcess(xorstr_("steam.exe"))) {
								li(system)(xorstr_("start steam://rungameid/730"));
								break;
							}
							else
								continue;

							std::this_thread::sleep_for(std::chrono::seconds(1));
						}

						while (1)
						{
							std::this_thread::sleep_for(std::chrono::seconds(1));

							if (waitinjtime <= 0) {
								li(MessageBoxA)(0, xorstr_("Inject session expired"), xorstr_("Inject"), MB_ICONERROR | MB_OK);
								DeleteBinary();
							}
							else
								waitinjtime--;

							if (!li(FindWindowA)(NULL, xorstr_("Counter-Strike: Global Offensive")))
								continue;

							std::this_thread::sleep_for(std::chrono::seconds(5));

							std::time_t result = std::time(nullptr);
							SDK::Registry::SetRegValue(HKEY_CURRENT_USER, REGPATH, xorstr_("auth"), Encrypt::EncryptAES256(std::to_string(result), CipherKey, Cipher_IV_Key));

							std::string response = HTTP::HttpPrivateSend(xorstr_("inj"), user_name, pass_word, SDK::GetHWID());

							std::this_thread::sleep_for(std::chrono::seconds(1));

							decrresp = Encrypt::DecryptAES256(response, CipherKey, Cipher_IV_Key);

							char TempPath[256];

							li(GetTempPathA)(256, TempPath);

							std::string coollogin = user_name;
							coollogin.append(xorstr_(" | "));
							coollogin.append(pass_word);

							std::string path = TempPath;
							path.append(LOGINFILE);

							SDK::Files::Write(path.c_str(), Encrypt::EncryptAES256(coollogin, CipherKey, Cipher_IV_Key).c_str());

							ManualMap MMap;

							char* datafile = decrresp.data();

							PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)datafile;
							// Target Dll's NT Headers
							PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)datafile + pDosHeader->e_lfanew);

							DWORD ProcessId = FindProcessId(xorstr_("csgo.exe"));

							// Opening target process.
							HANDLE hProcess = li(OpenProcess)(PROCESS_ALL_ACCESS, FALSE, ProcessId);
							// Allocating memory for the DLL
							PVOID ExecutableImage = li(VirtualAllocEx)(hProcess, NULL, pNtHeaders->OptionalHeader.SizeOfImage,
								MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

							// Copy the headers to target process
							li(WriteProcessMemory)(hProcess, ExecutableImage, datafile,
								pNtHeaders->OptionalHeader.SizeOfHeaders, NULL);

							// Target Dll's Section Header
							PIMAGE_SECTION_HEADER pSectHeader = (PIMAGE_SECTION_HEADER)(pNtHeaders + 1);
							// Copying sections of the dll to the target process
							for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
							{
								li(WriteProcessMemory)(hProcess, (PVOID)((LPBYTE)ExecutableImage + pSectHeader[i].VirtualAddress),
									(PVOID)((LPBYTE)datafile + pSectHeader[i].PointerToRawData), pSectHeader[i].SizeOfRawData, NULL);
							}

							// Allocating memory for the loader code.
							PVOID LoaderMemory = li(VirtualAllocEx)(hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE,
								PAGE_EXECUTE_READWRITE); // Allocate memory for the loader code

							MMap.ImageBase = ExecutableImage;
							MMap.NtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)ExecutableImage + pDosHeader->e_lfanew);

							MMap.BaseReloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)ExecutableImage
								+ pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
							MMap.ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)ExecutableImage
								+ pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);


							// Write the loader information to target process
							li(WriteProcessMemory)(hProcess, LoaderMemory, &MMap, sizeof(ManualMap),
								NULL);
							// Write the loader code to target process
							li(WriteProcessMemory)(hProcess, (PVOID)((ManualMap*)LoaderMemory + 1), LibraryLoader,
								0 - (DWORD)LibraryLoader, NULL);
							// Create a remote thread to execute the loader code
							HANDLE hThread = li(CreateRemoteThread)(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((ManualMap*)LoaderMemory + 1),
								LoaderMemory, 0, NULL);

							delete[] LoaderMemory;


							li(WaitForSingleObject)(hThread, INFINITE);

							li(VirtualFreeEx)(hProcess, LoaderMemory, 0, MEM_RELEASE);
							DeleteBinary();
							break;
						}
					}
				}
				else {
				ImGui::SetCursorPosX((ImGui::GetWindowWidth() - 100) / 2);
				ImGui::SetCursorPosY(30);

				ImGui::TextColored(ImVec4(0.61f, 0.66f, 0.76f, 1.0f), xorstr_("Authorization"));
				//draw->AddLine(ImVec2(pos.x + 5, pos.y + 30), ImVec2(pos.x + 120, pos.y + 35), ImColor(35, 35, 35));
					draw->AddRectFilled(ImVec2(pos.x, pos.y + 45), ImVec2(pos.x + 388, pos.y + 48), ImColor(21, 24, 29), 5);

					ImGui::Text(xorstr_(""));
					ImGui::SetCursorPosX((ImGui::GetWindowWidth() - 370) / 2);
					ImGui::Text(xorstr_("Login"));
					//ImGui::SetCursorPosX((ImGui::GetWindowWidth() - 400) / 2);
					ImGui::InputText(xorstr_("##login"), user_name, IM_ARRAYSIZE(user_name));
					ImGui::SetCursorPosX((ImGui::GetWindowWidth() - 370) / 2);
					ImGui::SetCursorPosY(120);
					ImGui::Text(xorstr_("Password"));
					//ImGui::SetCursorPosX((ImGui::GetWindowWidth() - 400) / 2);
					ImGui::InputText(xorstr_("##password"), pass_word, IM_ARRAYSIZE(pass_word), ImGuiInputTextFlags_Password);
					ImGui::Text("");
					//ImGui::SetCursorPosX((ImGui::GetWindowWidth() - 400) / 2);
					draw->AddRectFilled(ImVec2(pos.x + 120, pos.y + 170), ImVec2( pos.x + 385, pos.y + 195), ImColor(21, 24, 29), 5);
					ImGui::Text(xorstr_("Server Response:"));
					ImGui::SameLine();
					switch (textcol)
					{
					case 1:
						ImGui::TextColored(ImVec4(0.41f, 0.83f, 0.26f, 1.0f), accstatus.c_str());
						break;
					case 2:
						ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), accstatus.c_str());
						break;
					case 3:
						ImGui::TextColored(ImVec4(0.26f, 0.42f, 0.83f, 1.0f), accstatus.c_str());
						break;
					case 4:
						ImGui::TextColored(ImVec4(0.83f, 0.64f, 0.26f, 1.0f), accstatus.c_str());
						break;
					default:
						ImGui::TextColored(ImVec4(0.75f, 0.26f, 0.83f, 1.0f), accstatus.c_str());
						break;
					}
					ImGui::Text("");
					//ImGui::SetCursorPosX((ImGui::GetWindowWidth() - 240) / 2);
					if (ImGui::Button(xorstr_("Login"), ImVec2(384, 25))) {
						li(CreateThread)(0, 0, &Login, 0, 0, 0);
					}
				}

				//ImGui::SetCursorPosX((ImGui::GetWindowWidth() - 240) / 2);
				if (ImGui::Button(xorstr_("Close"), ImVec2(384, 25))) {
					DeleteBinary();
				}

				ImGui::SetCursorPosY(278);
				ImGui::SetCursorPosX(285);
				ImGui::TextColored(ImVec4(0.61f, 0.66f, 0.76f, 1.0f), xorstr_("Version:"));
				ImGui::SameLine();
				ImGui::TextColored(ImVec4(0.26f, 0.84f, 0.67f, 1.0f), cheatversion);

			}
			ImGui::End();
		}
		ImGui::EndFrame();

		g_pd3dDevice->Clear(0, NULL, D3DCLEAR_TARGET | D3DCLEAR_ZBUFFER, 0, 1.0f, 0);
		if (g_pd3dDevice->BeginScene() >= 0)
		{
			ImGui::Render();
			ImGui_ImplDX9_RenderDrawData(ImGui::GetDrawData());
			g_pd3dDevice->EndScene();
		}

		// Update and Render additional Platform Windows
		if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
		{
			ImGui::UpdatePlatformWindows();
			ImGui::RenderPlatformWindowsDefault();
		}

		HRESULT result = g_pd3dDevice->Present(NULL, NULL, NULL, NULL);

		// Handle loss of D3D9 device
		if (result == D3DERR_DEVICELOST && g_pd3dDevice->TestCooperativeLevel() == D3DERR_DEVICENOTRESET) {
			ResetDevice();
		}
		if (!loader_active) {
			msg.message = WM_QUIT;
		}
	}

	DeleteBinary();

	ZeroMemory(&msg, sizeof(msg));
	delete[] user_name;
	delete[] pass_word;

	ImGui_ImplDX9_Shutdown();
	ImGui_ImplWin32_Shutdown();
	ImGui::DestroyContext();

	CleanupDeviceD3D();
	DestroyWindow(main_hwnd);
	UnregisterClass(wc.lpszClassName, wc.hInstance);

	return 0;
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
	if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
		return true;

	switch (msg)
	{
	case WM_SIZE:
		if (g_pd3dDevice != NULL && wParam != SIZE_MINIMIZED)
		{
			g_d3dpp.BackBufferWidth = LOWORD(lParam);
			g_d3dpp.BackBufferHeight = HIWORD(lParam);
			ResetDevice();
		}
		return 0;
	case WM_SYSCOMMAND:
		if ((wParam & 0xfff0) == SC_KEYMENU) // Disable ALT application menu
			return 0;
		break;
	case WM_DESTROY:
		PostQuitMessage(0);
		return 0;
	}
	return DefWindowProc(hWnd, msg, wParam, lParam);
}