#pragma once

class Encrypt {
	public:
		static std::string EncryptAES256(const std::string& str, const std::string& cipher_key, const std::string& iv_key);
		static std::string DecryptAES256(const std::string& str, const std::string& cipher_key, const std::string& iv_key);
};

