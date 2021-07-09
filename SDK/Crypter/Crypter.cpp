#define _CRT_SECURE_NO_WARNINGS
#include "../includes.h"
#include "Crypter.h"

#define CRC32C(c,d) (c=(c>>8)^crc_c[(c^(d))&0xFF])


#include <modes.h>
#include <osrng.h>
#include <rsa.h>
#include <sha.h>

std::string Encrypt::EncryptAES256(const std::string& str, const std::string& cipher_key, const std::string& iv_key)
{

    std::string str_out;

    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryption((CryptoPP::byte*)cipher_key.c_str(), 32, (CryptoPP::byte*)iv_key.c_str());

    CryptoPP::StringSource encryptor(str, true,
        new CryptoPP::StreamTransformationFilter(encryption,
            new CryptoPP::Base64Encoder(
                new CryptoPP::StringSink(str_out),
                false
            )
        )
    );
    return str_out;
}

std::string Encrypt::DecryptAES256(const std::string& str, const std::string& cipher_key, const std::string& iv_key)
{

    std::string str_out;

    CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryption((CryptoPP::byte*)cipher_key.c_str(), 32, (CryptoPP::byte*)iv_key.c_str());
    CryptoPP::StringSource decryptor(str, true,
        new CryptoPP::Base64Decoder(
            new CryptoPP::StreamTransformationFilter(decryption,
                new CryptoPP::StringSink(str_out)
            )
        )
    );
    return str_out;
}