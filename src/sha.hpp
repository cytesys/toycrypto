#pragma once

#ifndef SHA_HPP
#define SHA_HPP

#include "common.hpp"

namespace SHA {
	auto sha1(const str &input)->str;
	auto sha1_file(const str &filename)->str;

	auto sha224(const str &input)->str;
	auto sha224_file(const str &filename)->str;

	auto sha256(const str &input)->str;
	auto sha256_file(const str &filename)->str;

	auto sha384(const str &input)->str;
	auto sha384_file(const str &filename)->str;

	auto sha512(const str &input)->str;
	auto sha512_file(const str& filename)->str;

	auto sha512_224(const str& input)->str;
	auto sha512_224_file(const str& filename)->str;

	auto sha512_256(const str& input)->str;
	auto sha512_256_file(const str& filename)->str;

	auto shake128(str input, unsigned int output_length)->str;
	auto shake256(str input, unsigned int output_length)->str;
	auto sha3_224(str input)->str;
	auto sha3_256(str input)->str;
	auto sha3_384(str input)->str;
	auto sha3_512(str input)->str;
}

#endif