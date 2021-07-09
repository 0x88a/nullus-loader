#pragma once


class SDK {
public:
	static int InitLoader();
	static DWORD WINAPI StartSession(LPVOID);
	static std::string GetHWID();
	static std::string GetCPU();
	static std::string GetGPU();
	static std::string GetMAC();
	static std::string GetRandomString(size_t val);
	class Registry {
	public:
		static std::string GetRegValue(HKEY where, const char* reg, const char* value);
		static void SetRegValue(HKEY keyg, LPCSTR reg, LPCSTR key, std::string regval);
	};

	class Files {
	public:
		static void Append(const char* name, const char* content);
		static void Write(const char* name, const char* content);
	};
	
};

class Log {
public:
	static int Send(const char* msg, ...);

};