#pragma once

#ifndef SHA_HPP
#define SHA_HPP

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
	
	std::string shake128(std::string input, unsigned int output_length);
	std::string shake256(std::string input, unsigned int output_length);
	std::string sha3_224(std::string input);
	std::string sha3_256(std::string input);
	std::string sha3_384(std::string input);
	std::string sha3_512(std::string input);
}

#endif