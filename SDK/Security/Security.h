#pragma once


class Security {
public:
	static std::string Scramble(std::string target);
	static std::string DeScramble(std::string target);
	static void Init();


};