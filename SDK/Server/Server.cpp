#include "Server.h"

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <TlHelp32.h>
#include <string>
#include <algorithm>

#pragma comment (lib, "Ws2_32.lib")

namespace ServerVars
{
	SOCKET m_pSocket;
	WSADATA m_WSAData;
}

Server::Server( const char* m_pszAddress, unsigned int m_iPort )
{
	this->m_iPort = m_iPort;
	this->m_pszAddress = m_pszAddress;
}

Server::~Server( )
{
	Disconnect( );
}

char* Server::HandleData( char* m_pszQuery, int* m_pLength, int m_iSize )
{
	char* m_pszResult = new char[ m_iSize + 1 ];
	int m_iLength = 0;

	if ( m_pLength == nullptr )
		m_pLength = &m_iLength;

	send( ServerVars::m_pSocket, m_pszQuery, strlen( m_pszQuery ), 0 );
	*m_pLength = recv( ServerVars::m_pSocket, m_pszResult, m_iSize, 0 );
	if ( *m_pLength > 0 )
		m_pszResult[ *m_pLength ] = '\0';

	return m_pszResult;
}

void Server::ReceiveData( char*& m_pBuffer, int& m_pLength )
{
	ZeroMemory( m_pBuffer, BUFSIZ );
	m_pLength = recv( ServerVars::m_pSocket, m_pBuffer, BUFSIZ, 0 );
}

int Server::SendData( char* m_pszBuffer )
{
	return send( ServerVars::m_pSocket, m_pszBuffer, strlen( m_pszBuffer ), 0 );
}

bool Server::Connect( )
{
	ServerVars::m_pSocket = INVALID_SOCKET;

	struct addrinfo* m_pResult	= NULL;
	struct addrinfo* m_pUnk		= NULL;
	struct addrinfo m_Hints		= { 0 };

	int m_iResult = WSAStartup( MAKEWORD( 2, 2 ), &ServerVars::m_WSAData );
	if ( m_iResult != 0 )
		return false;

	m_Hints.ai_family	= AF_UNSPEC;
	m_Hints.ai_socktype = SOCK_STREAM;
	m_Hints.ai_protocol = IPPROTO_TCP;

	m_iResult = getaddrinfo( m_pszAddress, std::to_string( m_iPort ).c_str( ), &m_Hints, &m_pResult );
	if ( m_iResult != 0 )
		return false;

	for ( m_pUnk = m_pResult; m_pUnk != NULL; m_pUnk = m_pUnk->ai_next )
	{
		ServerVars::m_pSocket = socket( m_pUnk->ai_family, m_pUnk->ai_socktype, m_pUnk->ai_protocol );

		if ( ServerVars::m_pSocket == INVALID_SOCKET )
		{
			WSACleanup( );

			return false;
		}

		m_iResult = connect( ServerVars::m_pSocket, m_pUnk->ai_addr, m_pUnk->ai_addrlen );
		if ( m_iResult == SOCKET_ERROR )
		{
			closesocket( ServerVars::m_pSocket );
			ServerVars::m_pSocket = INVALID_SOCKET;

			return false;
		}
	}

	freeaddrinfo( m_pResult );

	if ( ServerVars::m_pSocket == INVALID_SOCKET )
	{
		WSACleanup( );
		ServerVars::m_pSocket = NULL;

		return false;
	}

	DWORD m_dwMode = 0;

	m_iResult = ioctlsocket( ServerVars::m_pSocket, FIONBIO, &m_dwMode );
	if ( m_iResult == SOCKET_ERROR )
	{
		closesocket( ServerVars::m_pSocket );
		WSACleanup( );
		ServerVars::m_pSocket = NULL;

		return false;
	}

	char m_szValue = 1;
	setsockopt( ServerVars::m_pSocket, IPPROTO_TCP, TCP_NODELAY, &m_szValue, sizeof( m_szValue ) );
	printf("Started\n");
	return true;
}

bool Server::Disconnect( )
{
	closesocket( ServerVars::m_pSocket );
	WSACleanup( );
	ServerVars::m_pSocket = NULL;

	return true;
}