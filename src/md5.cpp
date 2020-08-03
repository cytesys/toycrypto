#include <cstdint>
#include <string>
#include <array>
#include <cmath>
#include <stdexcept>
#include <fstream>
#include "common.hpp"

constexpr std::array<uint32_t, 64> K = {
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

constexpr std::array<unsigned int, 64> S = {
	7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
	5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
	4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
	6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
};

class MD5 {
private:
	std::array<uint32_t, 16> _X{ {} };
	uint64_t _ml;
	uint64_t _offset;
	uint32_t _A = 0x67452301;
	uint32_t _B = 0xefcdab89;
	uint32_t _C = 0x98badcfe;
	uint32_t _D = 0x10325476;

	void _handle();
	//void _debug();
public:
	MD5() {};
	void load_string(const std::string& input);
	void load_file(const std::string& filename);
	auto output()->std::string;
};

//void MD5::_debug() {
//	for (int i = 0; i < _X.size(); i++) {
//		printf("%08lx ", _X.at(i));
//	}
//	printf("\n");
//}

void MD5::load_string(const std::string& input) {
	_ml = input.length() * 8;
	_offset = 0;
	unsigned int index;

	while (input.length() - _offset >= 64) {
		// Load bytes from input into the chunk buffer
		// Store data in 32-bit words, reverse endian.
		for (int i = 0; i < 16; i++) {
			_X.at(i) = chars_to_uint32_t(
				input[(i * 4) + _offset + 3],
				input[(i * 4) + _offset + 2],
				input[(i * 4) + _offset + 1],
				input[(i * 4) + _offset]
			);
		}

		// Handle
		_handle();

		// Increase offset
		_offset += 64;
	}

	index = 0;

	// Load the remaining whole 32-bit words from input
	if ((input.length() - _offset) >= 4) {
		int rem_whole = std::floor((input.length() - _offset) / 4);
		int new_offset = _offset;

		for (int i = 0; i < (rem_whole * 4); i += 4) {
			_X.at(index++) = chars_to_uint32_t(
				input[i + _offset + 3],
				input[i + _offset + 2],
				input[i + _offset + 1],
				input[i + _offset]
			);

			new_offset += 4;
		}
		_offset = new_offset;
	}

	// Load the remaining bytes from input
	switch ((input.length() - _offset)) {
	case 0:
		_X.at(index++) = chars_to_uint32_t(
			0x00,
			0x00,
			0x00,
			0x80
		);
		break;
	case 1:
		_X.at(index++) = chars_to_uint32_t(
			0x00,
			0x00,
			0x80,
			input[_offset]
		);
		break;
	case 2:
		_X.at(index++) = chars_to_uint32_t(
			0x00,
			0x80,
			input[_offset + 1],
			input[_offset]
		);
		break;
	case 3:
		_X.at(index++) = chars_to_uint32_t(
			0x80,
			input[_offset + 2],
			input[_offset + 1],
			input[_offset]
		);
		break;
	default:
		throw std::runtime_error("This should not happen. Error in the switch in funtion MD2::load_string()!");
		break;
	}

	if (index + 2 > 16) {
		while (index < 16) {
			_X.at(index++) = chars_to_uint32_t(0x00, 0x00, 0x00, 0x00);
		}

		_handle();
		index = 0;
	}

	// Pad with zeroes
	while (index + 2 < 16) {
		_X.at(index++) = chars_to_uint32_t(0x00, 0x00, 0x00, 0x00);
	}

	// Append the message length
	_X.at(index++) = _ml & 0xffffffff;
	_X.at(index++) = leftrotate(_ml, 32) & 0xffffffff;

	_handle();
}

void MD5::load_file(const std::string &filename) {
	_offset = 0;
	char* buffer = new char[64];
	unsigned int index;
	unsigned int buffer_index;

	std::ifstream infile(filename, std::ifstream::binary);

	if (!infile.good()) {
		throw std::ios_base::failure("Could not open file!");
	}

	infile.seekg(0, infile.end);
	std::streamoff filelen = infile.tellg();
	infile.seekg(0, infile.beg);

	_ml = filelen * 8;

	while ((filelen - _offset) >= 64) {
		// Load 16 bytes into the chunk
		if (!infile.good()) {
			throw std::ios_base::failure("Could not open file!");
		}

		infile.read(buffer, 64);

		for (unsigned int i = 0; i < 16; i++) {
			_X.at(i) = chars_to_uint32_t(
				buffer[(i * 4) + 3],
				buffer[(i * 4) + 2],
				buffer[(i * 4) + 1],
				buffer[(i * 4)]
			);
		}

		_handle();

		_offset += 64;
	}

	index = 0;
	buffer_index = 0;

	// Load the remaining whole 32-bit words from input
	if ((filelen - _offset) > 0) {
		if (!infile.good()) {
			throw std::ios_base::failure("Could not open file!");
		}

		infile.read(buffer, (filelen - _offset));

		if ((filelen - _offset) >= 4) {
			int rem_whole = std::floor((filelen - _offset) / 4);
			int new_offset = _offset;

			for (int i = 0; i < (rem_whole * 4); i += 4) {
				_X.at(index++) = chars_to_uint32_t(
					buffer[i + 3],
					buffer[i + 2],
					buffer[i + 1],
					buffer[i]
				);

				new_offset += 4;
				buffer_index += 4;
			}
			_offset = new_offset;
		}
	}

	switch ((filelen - _offset)) {
	case 0:
		_X.at(index++) = chars_to_uint32_t(
			0x00,
			0x00,
			0x00,
			0x80
		);
		break;
	case 1:
		_X.at(index++) = chars_to_uint32_t(
			0x00,
			0x00,
			0x80,
			buffer[buffer_index]
		);
		break;
	case 2:
		_X.at(index++) = chars_to_uint32_t(
			0x00,
			0x80,
			buffer[buffer_index + 1],
			buffer[buffer_index]
		);
		break;
	case 3:
		_X.at(index++) = chars_to_uint32_t(
			0x80,
			buffer[buffer_index + 2],
			buffer[buffer_index + 1],
			buffer[buffer_index]
		);
		break;
	default:
		throw std::runtime_error("This should not happen. Error in the switch in funtion MD2::load_string()!");
		break;
	}

	// Pad with zeroes
	while (index + 2 < 16) {
		_X.at(index++) = chars_to_uint32_t(0x00, 0x00, 0x00, 0x00);
	}

	// Append the message length
	_X.at(index++) = _ml & 0xffffffff;
	_X.at(index++) = leftrotate(_ml, 32) & 0xffffffff;

	_handle();
}

void MD5::_handle() {
	//_debug();

	uint32_t AA = _A;
	uint32_t BB = _B;
	uint32_t CC = _C;
	uint32_t DD = _D;

	for (int i = 0; i < 64; i++) {
		uint32_t F, g;
		if (i >=0 && i <=15) {
			F = (BB & CC) | ((~BB) & DD);
			g = i;
		} else if (i >= 16 && i <= 31) {
			F = (DD & BB) | ((~DD) & CC);
			g = ((5 * i) + 1) % 16;
		} else if (i >= 32 && i <= 47) {
			F = BB ^ CC ^ DD;
			g = ((3 * i) + 5) % 16;
		} else {
			F = CC ^ (BB | (~DD));
			g = (7 * i) % 16;
		}

		F = F + AA + K[i] + _X[g];
		AA = DD;
		DD = CC;
		CC = BB;
		BB = BB + leftrotate(F, S[i]);
	}

	_A += AA;
	_B += BB;
	_C += CC;
	_D += DD;
}

auto MD5::output() -> std::string {
	std::string result = "";
	result += uint_to_hex(reverse_endianness(_A));
	result += uint_to_hex(reverse_endianness(_B));
	result += uint_to_hex(reverse_endianness(_C));
	result += uint_to_hex(reverse_endianness(_D));
	return result;
}

namespace MD {
	auto md5(const std::string& input) {
		MD5 instance = MD5();
		instance.load_string(input);
		return instance.output();
	}

	auto md5_file(const std::string& filename) {
		MD5 instance = MD5();
		instance.load_file(filename);
		return instance.output();
	}
}