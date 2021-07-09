#define _CRT_SECURE_NO_WARNINGS

#include "../includes.h"

#include "HTTP.h"


bool replace(std::string& str,
    const std::string& from,
    const std::string& to) {
    size_t start_pos = str.find(from);
    if (start_pos == std::string::npos)
        return false;
    str.replace(start_pos, from.length(), to);
    return true;
}

std::string replaceAll(std::string subject, const std::string& search, const std::string& replace) {
    size_t pos = 0;
    while ((pos = subject.find(search, pos)) != std::string::npos) {
        subject.replace(pos, search.length(), replace);
        pos += replace.length();
    }
    return subject;
}

std::string HTTP::GetPage(std::string URL) {
    HINTERNET interwebs = li(InternetOpenA)(xorstr_("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.128 Safari/537.36"), INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, NULL);
    HINTERNET urlFile;
    std::string rtn;
    if (interwebs) {
        std::string url_ = xorstr_("https://"); url_.append(WebsiteApi); url_.append(URL);
        urlFile = li(InternetOpenUrlA)(interwebs, url_.c_str(), NULL, NULL, NULL, NULL);
        if (urlFile) {
            char buffer[2000];
            DWORD bytesRead;
            do {
                li(InternetReadFile)(urlFile, buffer, 2000, &bytesRead);
                rtn.append(buffer, bytesRead);
                li(memset)(buffer, 0, 2000);
            } while (bytesRead);
            li(InternetCloseHandle)(interwebs);
            li(InternetCloseHandle)(urlFile);
            std::string p = replaceAll(rtn, "|n", "\r\n");
            return p;
        }
    }
    li(InternetCloseHandle)(interwebs);
    std::string p = replaceAll(rtn, "|n", "\r\n");
    return p;
}

__forceinline std::string HTTP::HttpRequest(std::string site, std::string param) {
    HINTERNET hInternet =
        li(InternetOpen)(
            xorstr_("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.128 Safari/537.36"),
            INTERNET_OPEN_TYPE_PRECONFIG,
            NULL, NULL,
            0);

    if (hInternet != NULL) {
        HINTERNET hConnect =
            li(InternetConnectA)(
                hInternet,
                site.c_str(),
                INTERNET_DEFAULT_HTTPS_PORT,
                NULL, NULL,
                INTERNET_SERVICE_HTTP,
                0,
                1u);

        if (hConnect != NULL) {

            HINTERNET hRequest =
                li(HttpOpenRequestA)(
                    hConnect,
                    xorstr_("POST"),
                    xorstr_("v3/api/loader/login.php"),
                    NULL,
                    NULL,
                    0,
                    INTERNET_FLAG_SECURE,
                    1);

            if (hRequest != NULL) {

                std::string hdrs = xorstr_("Content-Type: application/json");

                for (int i = 0; i < 6; i++) {
                    replace(param, xorstr_("+"), xorstr_("PLUS"));
                }

                BOOL bRequestSent = li(HttpSendRequestA)(hRequest, hdrs.c_str(), hdrs.length(), &param[0], param.length());
                //BOOL bSend = li(HttpSendRequestA)(hRequest, hdrs.c_str(), hdrs.length(), &param[0], param.length());
                if (!bRequestSent) {
                
                    li(raise)(11);
                }
                else {
                    std::string strResponse;
                    const int nBuffSize = 1024;
                    char buff[nBuffSize];

                    BOOL bKeepReading = true;
                    DWORD dwBytesRead = -1;

                    while (bKeepReading && dwBytesRead != 0) {
                        bKeepReading = li(InternetReadFile)(hRequest, buff, nBuffSize, &dwBytesRead);
                        strResponse.append(buff, dwBytesRead);
                    }

                    return strResponse;
                }
                // çàêðûâàåì çàïðîñ
                li(InternetCloseHandle)(hRequest);
            }
            // çàêðûâàåì ñåññèþ
            li(InternetCloseHandle)(hConnect);
        }
        // çàêðûâàåì WinInet
        li(InternetCloseHandle)(hInternet);
    }

}

std::string HTTP::HttpPrivateSend(std::string logf, std::string user, std::string pass, std::string hwid) {

    MEMORYSTATUSEX statex;

    statex.dwLength = sizeof(statex); // I misunderstand that

    GlobalMemoryStatusEx(&statex);

    std::string query;

    query += "{\"action\":\"" +logf+ "\",\"username\":\"" +user+ "\",  \"password\":\"" +pass+ "\", \"hwid\":\"" + hwid + "\", \"mac\":\"" + SDK::GetMAC().c_str() + "\"\}";
    query = Encrypt::EncryptAES256(query, CipherKey, Cipher_IV_Key);

    std::string response = HTTP::HttpRequest(WebsiteApi, query);

    //auto fixedresponse = explode(response, '|');
    //return fixedresponse[1];

    return response;

}