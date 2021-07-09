#pragma once

class Server
{

public:

	Server(const char*, unsigned int);
	~Server();

	char* HandleData(char*, int* = nullptr, int = 512);
	void ReceiveData(char*&, int&);
	int SendData(char*);

	bool Connect();
	bool Disconnect();

private:

	int m_iPort;
	const char* m_pszAddress;
};