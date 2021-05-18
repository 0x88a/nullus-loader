#pragma once
#define WIN32_LEAN_AND_MEAN
#define SECURITY_WIN32
#include <windows.h>
#include <winsock2.h>
#include <security.h>
#include <iphlpapi.h>
#include <iostream>
#include <thread>
#include "xorstr.h"
#include <assert.h>
#include <tlhelp32.h>
#include <iostream>
#include <excpt.h>
#include <signal.h>
#include <string>
#include <shlwapi.h>
#include <iostream>
#include <ostream>
#include <vector>
#include "curl lib/include/curl/curl.h"
#include "Inject/ManualMap.h"
#include <Urlmon.h>
#include "sartaprotect.h"

#pragma comment(lib,"dxguid.lib")
#pragma comment(lib, "urlmon.lib")

using namespace std;

static char errorBuffer[CURL_ERROR_SIZE];
static string buffers;
BOOL IsAdministrator(VOID);
static int writer(char* data, size_t size, size_t nmemb, string* buffer)
{
	int result = 0;
	if (buffer != NULL)
	{
		buffer->append(data, size * nmemb);
		result = size * nmemb;
	}
	return result;
}
