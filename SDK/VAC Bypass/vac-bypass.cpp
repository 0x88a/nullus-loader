#include "../includes.h"
#include "raw.h"
#include "vac-bypass.h"

#pragma comment(lib, "Shlwapi.lib")

#define ERASE_ENTRY_POINT    TRUE


typedef HMODULE(__stdcall* pLoadLibraryA)(LPCSTR);
typedef FARPROC(__stdcall* pGetProcAddress)(HMODULE, LPCSTR);

typedef INT(__stdcall* dllmain)(HMODULE, DWORD, LPVOID);


typedef struct {
    LPVOID ImageBase;

    PIMAGE_NT_HEADERS NtHeaders;
    PIMAGE_BASE_RELOCATION BaseReloc;
    PIMAGE_IMPORT_DESCRIPTOR ImportDirectory;

    pLoadLibraryA fnLoadLibraryA;
    pGetProcAddress fnGetProcAddress;
} LoaderData;



DWORD GetProcessId(std::string processName)
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

DWORD __stdcall LoaderLibrary(LPVOID Memory)
{

    LoaderData* LoaderParams = (LoaderData*)Memory;

    PIMAGE_BASE_RELOCATION pIBR = LoaderParams->BaseReloc;

    DWORD delta = (DWORD)((LPBYTE)LoaderParams->ImageBase - LoaderParams->NtHeaders->OptionalHeader.ImageBase); // Calculate the delta

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
                    PDWORD ptr = (PDWORD)((LPBYTE)LoaderParams->ImageBase + (pIBR->VirtualAddress + (list[i] & 0xFFF)));
                    *ptr += delta;
                }
            }
        }

        pIBR = (PIMAGE_BASE_RELOCATION)((LPBYTE)pIBR + pIBR->SizeOfBlock);
    }

    PIMAGE_IMPORT_DESCRIPTOR pIID = LoaderParams->ImportDirectory;

    // Resolve DLL imports
    while (pIID->Characteristics)
    {
        PIMAGE_THUNK_DATA OrigFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)LoaderParams->ImageBase + pIID->OriginalFirstThunk);
        PIMAGE_THUNK_DATA FirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)LoaderParams->ImageBase + pIID->FirstThunk);

        HMODULE hModule = LoaderParams->fnLoadLibraryA((LPCSTR)LoaderParams->ImageBase + pIID->Name);

        if (!hModule)
            return FALSE;

        while (OrigFirstThunk->u1.AddressOfData)
        {
            if (OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
            {
                // Import by ordinal
                DWORD Function = (DWORD)LoaderParams->fnGetProcAddress(hModule,
                    (LPCSTR)(OrigFirstThunk->u1.Ordinal & 0xFFFF));

                if (!Function)
                    return FALSE;

                FirstThunk->u1.Function = Function;
            }
            else
            {
                // Import by name
                PIMAGE_IMPORT_BY_NAME pIBN = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)LoaderParams->ImageBase + OrigFirstThunk->u1.AddressOfData);
                DWORD Function = (DWORD)LoaderParams->fnGetProcAddress(hModule, (LPCSTR)pIBN->Name);
                if (!Function)
                    return FALSE;

                FirstThunk->u1.Function = Function;
            }
            OrigFirstThunk++;
            FirstThunk++;
        }
        pIID++;
    }

    if (LoaderParams->NtHeaders->OptionalHeader.AddressOfEntryPoint)
    {
        dllmain EntryPoint = (dllmain)((LPBYTE)LoaderParams->ImageBase + LoaderParams->NtHeaders->OptionalHeader.AddressOfEntryPoint);

        return EntryPoint((HMODULE)LoaderParams->ImageBase, DLL_PROCESS_ATTACH, NULL); // Call the entry point
    }
    return TRUE;
}


VOID stub(VOID) { }

VOID VACBypass::WaitOnModule(DWORD processId, PCWSTR moduleName)
{
    BOOL foundModule = FALSE;

    while (!foundModule) {
        HANDLE moduleSnapshot = INVALID_HANDLE_VALUE;

        while (moduleSnapshot == INVALID_HANDLE_VALUE)
            moduleSnapshot = li(CreateToolhelp32Snapshot)(TH32CS_SNAPMODULE, processId);

        MODULEENTRY32W moduleEntry;
        moduleEntry.dwSize = sizeof(moduleEntry);

        if (li(Module32FirstW)(moduleSnapshot, &moduleEntry)) {
            do {
                if (!li(lstrcmpiW)(moduleEntry.szModule, moduleName)) {
                    foundModule = TRUE;
                    break;
                }
            } while (li(Module32NextW)(moduleSnapshot, &moduleEntry));
        }
        li(CloseHandle)(moduleSnapshot);
    }
}

VOID VACBypass::KillSteamProcesses()
{
    HANDLE processSnapshot = li(CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, 0);

    PROCESSENTRY32W processEntry;
    processEntry.dwSize = sizeof(processEntry);

    if (li(Process32FirstW)(processSnapshot, &processEntry)) {
        PCWSTR steamProcesses[] = { xorstr_(L"Steam.exe"), xorstr_(L"SteamService.exe"), xorstr_(L"steamwebhelper.exe"), xorstr_(L"csgo.exe") };
        do {
            for (INT i = 0; i < _countof(steamProcesses); i++) {
                if (!lstrcmpiW(processEntry.szExeFile, steamProcesses[i])) {
                    HANDLE processHandle = li(OpenProcess)(PROCESS_TERMINATE, FALSE, processEntry.th32ProcessID);
                    if (processHandle) {
                        li(TerminateProcess)(processHandle, 0);
                        li(CloseHandle)(processHandle);
                    }
                }
            }
        } while (li(Process32NextW)(processSnapshot, &processEntry));
    }
    li(CloseHandle)(processSnapshot);
}


int VACBypass::Init()
{
    HKEY key = NULL;
    if (!li(RegOpenKeyExW)(HKEY_CURRENT_USER, xorstr_(L"Software\\Valve\\Steam"), 0, KEY_QUERY_VALUE, &key)) {
        std::string SteamPath = SDK::Registry::GetRegValue(HKEY_CURRENT_USER, xorstr_("SOFTWARE\\Valve\\Steam"), xorstr_("SteamPath")) + xorstr_("\\steam.exe");

            VACBypass::KillSteamProcesses();

            STARTUPINFO si1 = { sizeof(si1) };
            PROCESS_INFORMATION pi1;;

            LPSTR autorun = const_cast<char*>(SteamPath.c_str());
            if (li(CreateProcessA)(NULL, autorun, NULL, NULL, FALSE, 0, NULL, NULL, &si1, &pi1)) {
                VACBypass::WaitOnModule(pi1.dwProcessId, xorstr_(L"Steam.exe"));

                li(SuspendThread)(pi1.hThread);
                LoaderData LoaderParams;

                char* datafile = reinterpret_cast<char*>(binary);

                PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)datafile;
                // Target Dll's NT Headers
                PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)datafile + pDosHeader->e_lfanew);
                // Allocating memory for the DLL
                PVOID ExecutableImage = li(VirtualAllocEx)(pi1.hProcess, NULL, pNtHeaders->OptionalHeader.SizeOfImage,
                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

                // Copy the headers to target process
                li(WriteProcessMemory)(pi1.hProcess, ExecutableImage, datafile,
                    pNtHeaders->OptionalHeader.SizeOfHeaders, NULL);

                // Target Dll's Section Header
                PIMAGE_SECTION_HEADER pSectHeader = (PIMAGE_SECTION_HEADER)(pNtHeaders + 1);
                // Copying sections of the dll to the target process
                for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
                {
                    li(WriteProcessMemory)(pi1.hProcess, (PVOID)((LPBYTE)ExecutableImage + pSectHeader[i].VirtualAddress),
                        (PVOID)((LPBYTE)datafile + pSectHeader[i].PointerToRawData), pSectHeader[i].SizeOfRawData, NULL);
                }

                // Allocating memory for the loader code.
                PVOID LoaderMemory = li(VirtualAllocEx)(pi1.hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE); // Allocate memory for the loader code

                LoaderParams.ImageBase = ExecutableImage;
                LoaderParams.NtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)ExecutableImage + pDosHeader->e_lfanew);

                LoaderParams.BaseReloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)ExecutableImage
                    + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
                LoaderParams.ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)ExecutableImage
                    + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

                LoaderParams.fnLoadLibraryA = li(LoadLibraryA);
                LoaderParams.fnGetProcAddress = li(GetProcAddress);

                // Write the loader information to target process
                li(WriteProcessMemory)(pi1.hProcess, LoaderMemory, &LoaderParams, sizeof(LoaderData),
                    NULL);
                // Write the loader code to target process
                li(WriteProcessMemory)(pi1.hProcess, (PVOID)((LoaderData*)LoaderMemory + 1), LoaderLibrary,
                    0 - (DWORD)LoaderLibrary, NULL);
                // Create a remote thread to execute the loader code
                HANDLE hThread = li(CreateRemoteThread)(pi1.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((LoaderData*)LoaderMemory + 1),
                    LoaderMemory, 0, NULL);


                li(ResumeThread)(pi1.hThread);
                li(WaitForSingleObject)(hThread, INFINITE);
                li(VirtualFreeEx)(pi1.hProcess, LoaderMemory, 0, MEM_RELEASE);

                li(CloseHandle)(pi1.hProcess);
                li(CloseHandle)(pi1.hThread);

        }
        li(RegCloseKey)(key);
    }
    return 0;
}