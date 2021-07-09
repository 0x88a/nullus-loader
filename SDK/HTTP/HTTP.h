#pragma once

class HTTP {
public:
	static std::string HttpRequest(std::string site, std::string param);
	static std::string GetPage(std::string url);
	static std::string HttpPrivateSend(std::string logf, std::string login, std::string pass, std::string hwid);
};