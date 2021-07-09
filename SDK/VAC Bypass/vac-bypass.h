#pragma once


class VACBypass {
public: 
	static int Init();
	static void KillSteamProcesses();
	static void WaitOnModule(DWORD processId, PCWSTR moduleName);
};