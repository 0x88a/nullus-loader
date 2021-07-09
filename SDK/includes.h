#include <windows.h>
#include <iostream>
#include <chrono>
#include <thread>
#include <vector>
#include <fstream>
#include <TlHelp32.h>
#include <Psapi.h>
#include <Shlwapi.h>
#include <csignal>
#include <iomanip>
#include <winternl.h>
#include <cctype>
#include <wininet.h>
#include <shobjidl_core.h>
#include <iphlpapi.h>
#include <random>

#include "include/config.h"

#include <aes.h>
#include <cryptlib.h>
#include <filters.h>
#include <osrng.h>
#include <base64.h>
#include <hex.h>
#include <modes.h>
#include <iphlpapi.h>
#include <pem.h>
#include <rsa.h>
#include <sha.h>


#include "Crypter/Xor.h"
#include "Main/Main.h"
#include "Crypter/Crypter.h"
#include "Security/Security.h"
#include "HTTP/HTTP.h"
#include "lazy.h"
#include "json.hpp"

#pragma comment (lib, "wininet.lib")
#pragma comment (lib, "urlmon.lib")
#pragma comment(lib,"ImageHlp.lib")
#pragma comment(lib,"wintrust.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Mpr.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "Winmm.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "powrprof.lib")
#pragma comment(lib, "Lib/cryptlib.lib")
#pragma comment(lib,"ws2_32.lib")

using json = nlohmann::json;

struct globals
{
	struct
	{
		struct
		{
			std::string cipher;
			std::string iv;
		} key;
	} server_side;
};

extern globals g_globals;

#define FirstMSG /*ZeroX Loader | lolz.guru*/XoredStr<0xD9,25,0xACF328B4>("\x83\xBF\xA9\xB3\x85\xFE\x93\x8F\x80\x86\x86\x96\xC5\xE6\xC7\x84\x86\x86\x91\xC2\x8A\x9B\x9D\x85"+0xACF328B4).s
#define SessionDisabled /*[ZeroX] Session Disabled*/XoredStr<0x87,25,0x73FCA918>("\xDC\xD2\xEC\xF8\xE4\xD4\xD0\xAE\xDC\xF5\xE2\xE1\xFA\xFB\xFB\xB6\xD3\xF1\xEA\xFB\xF9\xF0\xF8\xFA"+0x73FCA918).s

#define KERNEL_DLL /*kernel32.dll*/XoredStr<0x31,13,0x7D7DC681>("\x5A\x57\x41\x5A\x50\x5A\x04\x0A\x17\x5E\x57\x50"+0x7D7DC681).s
#define VCRUNTIME /*VCRUNTIME140.dll*/XoredStr<0x56,17,0x978A142B>("\x00\x14\x0A\x0C\x14\x0F\x15\x10\x1B\x6E\x54\x51\x4C\x07\x08\x09"+0x978A142B).s
#define EMEMSET /*memset*/XoredStr<0x88,7,0x3D0750B0>("\xE5\xEC\xE7\xF8\xE9\xF9"+0x3D0750B0).s
#define PROCCOCK /*csgo.exe*/XoredStr<0xA1,9,0x07F8416A>("\xC2\xD1\xC4\xCB\x8B\xC3\xDF\xCD"+0x07F8416A).s
#define USER_DLL /*user32.dll*/XoredStr<0x43,11,0xCDF2CCE4>("\x36\x37\x20\x34\x74\x7A\x67\x2E\x27\x20"+0xCDF2CCE4).s
#define GETPROCADDRESS /*GetProcAddress*/XoredStr<0xA8,15,0x70F94AAD>("\xEF\xCC\xDE\xFB\xDE\xC2\xCD\xEE\xD4\xD5\xC0\xD6\xC7\xC6"+0x70F94AAD).s
#define LOADLIBRARY /*LoadLibraryA*/XoredStr<0x02,13,0x4C871906>("\x4E\x6C\x65\x61\x4A\x6E\x6A\x7B\x6B\x79\x75\x4C"+0x4C871906).s
#define FINDWINDOW /*FindWindowA*/XoredStr<0x64,12,0x3F5B99F6>("\x22\x0C\x08\x03\x3F\x00\x04\x0F\x03\x1A\x2F"+0x3F5B99F6).s
#define CREATETHREAD /*CreateThread*/XoredStr<0xDB,13,0x78313E83>("\x98\xAE\xB8\xBF\xAB\x85\xB5\x8A\x91\x81\x84\x82"+0x78313E83).s
#define CLOSEHANDLE /*CloseHandle*/XoredStr<0x9F,12,0xF5D2C01C>("\xDC\xCC\xCE\xD1\xC6\xEC\xC4\xC8\xC3\xC4\xCC"+0xF5D2C01C).s
#define SETCONSOLETITLEA /*SetConsoleTitleA*/XoredStr<0x8B,17,0xA3A0549B>("\xD8\xE9\xF9\xCD\xE0\xFE\xE2\xFD\xFF\xF1\xC1\xFF\xE3\xF4\xFC\xDB"+0xA3A0549B).s
#define GETSTDHANDLE /*GetStdHandle*/XoredStr<0x99,13,0x64423165>("\xDE\xFF\xEF\xCF\xE9\xFA\xD7\xC1\xCF\xC6\xCF\xC1"+0x64423165).s
#define GETCONSOLESCREENBUFFERINFO /*GetConsoleScreenBufferInfo*/XoredStr<0x73,27,0x2C5512CA>("\x34\x11\x01\x35\x18\x16\x0A\x15\x17\x19\x2E\x1D\x0D\xE5\xE4\xEC\xC1\xF1\xE3\xE0\xE2\xFA\xC0\xE4\xED\xE3"+0x2C5512CA).s
#define SETCONSOLETEXTATTRIBUTE /*SetConsoleTextAttribute*/XoredStr<0x39,24,0x51350230>("\x6A\x5F\x4F\x7F\x52\x50\x4C\x2F\x2D\x27\x17\x21\x3D\x32\x06\x3C\x3D\x38\x22\x2E\x38\x3A\x2A"+0x51350230).s
#define GETTEMPPATHA /*GetTempPathA*/XoredStr<0xA3,13,0x3A49FF00>("\xE4\xC1\xD1\xF2\xC2\xC5\xD9\xFA\xCA\xD8\xC5\xEF"+0x3A49FF00).s
#define CREATEMUTEXA /*CreateMutexA*/XoredStr<0x81,13,0x8E6E2AA7>("\xC2\xF0\xE6\xE5\xF1\xE3\xCA\xFD\xFD\xEF\xF3\xCD"+0x8E6E2AA7).s
#define LOADRESOURCE /*LoadResource*/XoredStr<0xCF,13,0xEC5F7C2A>("\x83\xBF\xB0\xB6\x81\xB1\xA6\xB9\xA2\xAA\xBA\xBF"+0xEC5F7C2A).s
#define LOCKRESOURCE /*LockResource*/XoredStr<0xB3,13,0xDAA9915B>("\xFF\xDB\xD6\xDD\xE5\xDD\xCA\xD5\xCE\xCE\xDE\xDB"+0xDAA9915B).s
#define SIZEOFRESOURCE /*SizeofResource*/XoredStr<0x1C,15,0xDD629CB0>("\x4F\x74\x64\x7A\x4F\x47\x70\x46\x57\x4A\x53\x55\x4B\x4C"+0xDD629CB0).s
#define OPENPROCESS /*OpenProcess*/XoredStr<0x8F,12,0x6536A977>("\xC0\xE0\xF4\xFC\xC3\xE6\xFA\xF5\xF2\xEB\xEA"+0x6536A977).s
#define SLEEP /*Sleep*/XoredStr<0x5B,6,0xC85A94CB>("\x08\x30\x38\x3B\x2F"+0xC85A94CB).s
#define WRITEFILE /*WriteFile*/XoredStr<0x94,10,0x80A62806>("\xC3\xE7\xFF\xE3\xFD\xDF\xF3\xF7\xF9"+0x80A62806).s
#define CREATEFILEA /*CreateFileA*/XoredStr<0x83,12,0x611AC886>("\xC0\xF6\xE0\xE7\xF3\xED\xCF\xE3\xE7\xE9\xCC"+0x611AC886).s
#define FINDRESOURCEA /*FindResourceA*/XoredStr<0x7B,14,0xE1C3458C>("\x3D\x15\x13\x1A\x2D\xE5\xF2\xED\xF6\xF6\xE6\xE3\xC6"+0xE1C3458C).s
#define VIRTUALALLOCEX /*VirtualAllocEx*/XoredStr<0x84,15,0x28787BAA>("\xD2\xEC\xF4\xF3\xFD\xE8\xE6\xCA\xE0\xE1\xE1\xEC\xD5\xE9"+0x28787BAA).s
#define WRITEPROCESSMEMORY /*WriteProcessMemory*/XoredStr<0x92,19,0x19F595AA>("\xC5\xE1\xFD\xE1\xF3\xC7\xEA\xF6\xF9\xFE\xEF\xEE\xD3\xFA\xCD\xCE\xD0\xDA"+0x19F595AA).s
#define CREATEREMOTETHREAD /*CreateRemoteThread*/XoredStr<0x05,19,0x31C11955>("\x46\x74\x62\x69\x7D\x6F\x59\x69\x60\x61\x7B\x75\x45\x7A\x61\x71\x74\x72"+0x31C11955).s
#define GETWINDOWTHREADPROCESSID /*GetWindowThreadProcessId*/XoredStr<0x8D,25,0x6FA70A68>("\xCA\xEB\xFB\xC7\xF8\xFC\xF7\xFB\xE2\xC2\xFF\xEA\xFC\xFB\xFF\xCC\xEF\xF1\xFC\xC5\xD2\xD1\xEA\xC0"+0x6FA70A68).s
#define NT_DLL /*ntdll.dll*/XoredStr<0xAF,10,0xDCC17ED6>("\xC1\xC4\xD5\xDE\xDF\x9A\xD1\xDA\xDB"+0xDCC17ED6).s
#define NTSETSTATEINFORMATIONTHREAD /*NtSetInformationThread*/XoredStr<0x21,23,0x8C476206>("\x6F\x56\x70\x41\x51\x6F\x49\x4E\x46\x58\x46\x4D\x59\x47\x40\x5E\x65\x5A\x41\x51\x54\x52"+0x8C476206).s
#define WAITFORSINGLEOBJECT /*WaitForSingleObject*/XoredStr<0x80,20,0x3253106C>("\xD7\xE0\xEB\xF7\xC2\xEA\xF4\xD4\xE1\xE7\xED\xE7\xE9\xC2\xEC\xE5\xF5\xF2\xE6"+0x3253106C).s
#define MESSAGEBOXA /*MessageBoxA*/XoredStr<0x88,12,0x90E2570E>("\xC5\xEC\xF9\xF8\xED\xEA\xEB\xCD\xFF\xE9\xD3"+0x90E2570E).s
#define REGCREATEKETEXA /*RegCreateKeyExA*/XoredStr<0xB0,16,0xF53516E3>("\xE2\xD4\xD5\xF0\xC6\xD0\xD7\xC3\xDD\xF2\xDF\xC2\xF9\xC5\xFF"+0xF53516E3).s
#define REGOPENKEYEXA /*RegOpenKeyExA*/XoredStr<0x62,14,0xA5D069D3>("\x30\x06\x03\x2A\x16\x02\x06\x22\x0F\x12\x29\x15\x2F"+0xA5D069D3).s
#define REGSETVALUEEXA /*RegSetValueExA*/XoredStr<0xEC,15,0xD720618B>("\xBE\x88\x89\xBC\x95\x85\xA4\x92\x98\x80\x93\xB2\x80\xB8"+0xD720618B).s
#define REGOPENKEYEXA /*RegOpenKeyExA*/XoredStr<0xC8,14,0xC5F2145B>("\x9A\xAC\xAD\x84\xBC\xA8\xA0\x84\xB5\xA8\x97\xAB\x95"+0xC5F2145B).s
#define REGQUERYVALUEXA /*RegQueryValueExA*/XoredStr<0x73,17,0xFBA17407>("\x21\x11\x12\x27\x02\x1D\x0B\x03\x2D\x1D\x11\x0B\x1A\xC5\xF9\xC3"+0xFBA17407).s
#define REGCLOSEKEY /*RegCloseKey*/XoredStr<0xDE,12,0xB6EF6E90>("\x8C\xBA\x87\xA2\x8E\x8C\x97\x80\xAD\x82\x91"+0xB6EF6E90).s

#define REGPATH xorstr_("SOFTWARE\\Sakura\\auth")
#define logintext /*Login: */XoredStr<0x34,8,0xBC8584DB>("\x78\x5A\x51\x5E\x56\x03\x1A"+0xBC8584DB).s
#define passwordtext /*Password: */XoredStr<0xE7,11,0xC9105349>("\xB7\x89\x9A\x99\x9C\x83\x9F\x8A\xD5\xD0"+0xC9105349).s
#define LOGIN /*login*/XoredStr<0x8A,6,0x28723192>("\xE6\xE4\xEB\xE4\xE0"+0x28723192).s
#define PASSWORD /*pass*/XoredStr<0x47,5,0xBB3FDB35>("\x37\x29\x3A\x39"+0xBB3FDB35).s
#define TOKEN /*token*/XoredStr<0x90,6,0x6B31712F>("\xE4\xFE\xF9\xF6\xFA"+0x6B31712F).s
#define PASSWORDBAD /*[ERROR] Login or password is incorrect*/XoredStr<0x99,39,0xDB00E0C4>("\xC2\xDF\xC9\xCE\xD2\xCC\xC2\x80\xED\xCD\xC4\xCD\xCB\x86\xC8\xDA\x89\xDA\xCA\xDF\xDE\xD9\xC0\xC2\xD5\x92\xDA\xC7\x95\xDF\xD9\xDB\xD6\xC8\xC9\xD9\xDE\xCA"+0xDB00E0C4).s
#define BANNED /*[ERROR] You are banned*/XoredStr<0x92,23,0x84765F21>("\xC9\xD6\xC6\xC7\xD9\xC5\xC5\xB9\xC3\xF4\xE9\xBD\xFF\xED\xC5\x81\xC0\xC2\xCA\xCB\xC3\xC3"+0x84765F21).s

#define DONTHAVESUB /*[ERROR] You dont have a sub*/XoredStr<0xE9,28,0xF02E0F85>("\xB2\xAF\xB9\xBE\xA2\xBC\xB2\xD0\xA8\x9D\x86\xD4\x91\x99\x99\x8C\xD9\x92\x9A\x8A\x98\xDE\x9E\x20\x72\x77\x61"+0xF02E0F85).s
#define CONNECTIONERROR /*[ERROR] Connection error*/XoredStr<0xD1,25,0xE4D380DD>("\x8A\x97\x81\x86\x9A\x84\x8A\xF8\x9A\xB5\xB5\xB2\xB8\xBD\xAB\x89\x8E\x8C\xC3\x81\x97\x94\x88\x9A"+0xE4D380DD).s

#define INAUTH /*in*/XoredStr<0xBD,3,0x6271F941>("\xD4\xD0"+0x6271F941).s
#define LOGINFILE /*/mrdrldr.dat*/XoredStr<0x40,13,0xDD106645>("\x6F\x2C\x30\x27\x36\x29\x22\x35\x66\x2D\x2B\x3F"+0xDD106645).s

#define BADPASSWORDTEXT /*error5*/XoredStr<0xB8,7,0x3C6A97A8>("\xDD\xCB\xC8\xD4\xCE\x88"+0x3C6A97A8).s
#define BANNEDTEXT /*error4*/XoredStr<0x49,7,0xEDA0B017>("\x2C\x38\x39\x23\x3F\x7A"+0xEDA0B017).s
#define AUTHORIZED /*error3*/XoredStr<0x4B,7,0x69CF5AA5>("\x2E\x3E\x3F\x21\x3D\x63"+0x69CF5AA5).s
#define SUBTEXT /*error2*/XoredStr<0x91,7,0x2BA57F6F>("\xF4\xE0\xE1\xFB\xE7\xA4"+0x2BA57F6F).s
#define HWIDERROR /*error1*/XoredStr<0x67,7,0x012C928C>("\x02\x1A\x1B\x05\x19\x5D"+0x012C928C).s
#define INJECTTEXT /*error6*/XoredStr<0x08,7,0xF733C2D9>("\x6D\x7B\x78\x64\x7E\x3B"+0xF733C2D9).s
