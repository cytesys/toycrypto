#pragma once
#ifndef TOYCRYPTO_HPP
#define TOYCRYPTO_HPP

#include <string>

namespace SHA {
	auto sha0(const std::string &input) -> std::string;
	auto sha0_file(const std::string &filename) -> std::string;
	
	auto sha1(const std::string &input) -> std::string;
	auto sha1_file(const std::string &filename) -> std::string;
	
	auto sha224(const std::string &input) -> std::string;
	auto sha224_file(const std::string &filename) -> std::string;
	
	auto sha256(const std::string &input) -> std::string;
	auto sha256_file(const std::string &filename) -> std::string;
	
	auto sha384(const std::string &input) -> std::string;
	auto sha384_file(const std::string &filename) -> std::string;
	
	auto sha512(const std::string &input) -> std::string;
	auto sha512_file(const std::string &filename) -> std::string;
	
	auto sha512_224(const std::string &input) -> std::string;
	auto sha512_224_file(const std::string &filename) -> std::string;
	
	auto sha512_256(const std::string &input) -> std::string;
	auto sha512_256_file(const std::string &filename) -> std::string;
	
	auto shake128(std::string input, unsigned int output_length) -> std::string;
	auto shake256(std::string input, unsigned int output_length) -> std::string;
	auto sha3_224(std::string input) -> std::string;
	auto sha3_256(std::string input) -> std::string;
	auto sha3_384(std::string input) -> std::string;
	auto sha3_512(std::string input) -> std::string;
}

namespace MD {
	auto md2(const std::string& input)->std::string;
	auto md2_file(const std::string& filename)->std::string;

	auto md4(const std::string& input)->std::string;
	auto md4_file(const std::string& filename)->std::string;

	auto md5(const std::string& input)->std::string;
	auto md5_file(const std::string& filename)->std::string;
}

#endif
