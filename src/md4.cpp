#include <cstdint>
#include <string>
#include <array>
#include <cmath>
#include <exception>
#include "common.hpp"

static uint32_t F(uint32_t x, uint32_t y, uint32_t z) {
	return ((x & y) | ((~x) & z));
}

static uint32_t G(uint32_t x, uint32_t y, uint32_t z) {
	return ((x & y) | (x & z) | (y & z));
}

static uint32_t H(uint32_t x, uint32_t y, uint32_t z) {
	return (x ^ y ^ z);
}

static uint32_t FF(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, unsigned int s) {
	return leftrotate(a + F(b, c, d) + x, s);
}

static uint32_t GG(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, unsigned int s) {
	return leftrotate(a + G(b, c, d) + x + (uint32_t)0x5a827999, s);
}

static uint32_t HH(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, unsigned int s) {
	return leftrotate(a + H(b, c, d) + x + (uint32_t)0x6ed9eba1, s);
}

class MD4 {
private:
	std::array<uint32_t, 16> _X{ {} };
	uint64_t _ml;
	uint64_t _offset;
	uint32_t _A = 0x67452301;
	uint32_t _B = 0xefcdab89;
	uint32_t _C = 0x98badcfe;
	uint32_t _D = 0x10325476;

	void _handle();
	void _debug();
public:
	MD4() {};
	void load_string(const std::string& input);
	auto output()->std::string;
};

//void MD4::_debug() {
//	for (int i = 0; i < _X.size(); i++) {
//		printf("%08lx ", _X.at(i));
//	}
//	printf("\n");
//}

void MD4::load_string(const std::string& input) {
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
		throw std::exception("This should not happen. Error in the switch in funtion MD2::load_string()!");
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

void MD4::_handle() {
	//_debug();

	uint32_t AA = _A;
	uint32_t BB = _B;
	uint32_t CC = _C;
	uint32_t DD = _D;

	// Round 1
	AA = FF(AA, BB, CC, DD, _X[0], 3);
	DD = FF(DD, AA, BB, CC, _X[1], 7);
	CC = FF(CC, DD, AA, BB, _X[2], 11);
	BB = FF(BB, CC, DD, AA, _X[3], 19);
	AA = FF(AA, BB, CC, DD, _X[4], 3);
	DD = FF(DD, AA, BB, CC, _X[5], 7);
	CC = FF(CC, DD, AA, BB, _X[6], 11);
	BB = FF(BB, CC, DD, AA, _X[7], 19);
	AA = FF(AA, BB, CC, DD, _X[8], 3);
	DD = FF(DD, AA, BB, CC, _X[9], 7);
	CC = FF(CC, DD, AA, BB, _X[10], 11);
	BB = FF(BB, CC, DD, AA, _X[11], 19);
	AA = FF(AA, BB, CC, DD, _X[12], 3);
	DD = FF(DD, AA, BB, CC, _X[13], 7);
	CC = FF(CC, DD, AA, BB, _X[14], 11);
	BB = FF(BB, CC, DD, AA, _X[15], 19);

	// Round 2
	AA = GG(AA, BB, CC, DD, _X[0], 3);
	DD = GG(DD, AA, BB, CC, _X[4], 5);
	CC = GG(CC, DD, AA, BB, _X[8], 9);
	BB = GG(BB, CC, DD, AA, _X[12], 13);
	AA = GG(AA, BB, CC, DD, _X[1], 3);
	DD = GG(DD, AA, BB, CC, _X[5], 5);
	CC = GG(CC, DD, AA, BB, _X[9], 9);
	BB = GG(BB, CC, DD, AA, _X[13], 13);
	AA = GG(AA, BB, CC, DD, _X[2], 3);
	DD = GG(DD, AA, BB, CC, _X[6], 5);
	CC = GG(CC, DD, AA, BB, _X[10], 9);
	BB = GG(BB, CC, DD, AA, _X[14], 13);
	AA = GG(AA, BB, CC, DD, _X[3], 3);
	DD = GG(DD, AA, BB, CC, _X[7], 5);
	CC = GG(CC, DD, AA, BB, _X[11], 9);
	BB = GG(BB, CC, DD, AA, _X[15], 13);

	// Round 3
	AA = HH(AA, BB, CC, DD, _X[0], 3);
	DD = HH(DD, AA, BB, CC, _X[8], 9);
	CC = HH(CC, DD, AA, BB, _X[4], 11);
	BB = HH(BB, CC, DD, AA, _X[12], 15);
	AA = HH(AA, BB, CC, DD, _X[2], 3);
	DD = HH(DD, AA, BB, CC, _X[10], 9);
	CC = HH(CC, DD, AA, BB, _X[6], 11);
	BB = HH(BB, CC, DD, AA, _X[14], 15);
	AA = HH(AA, BB, CC, DD, _X[1], 3);
	DD = HH(DD, AA, BB, CC, _X[9], 9);
	CC = HH(CC, DD, AA, BB, _X[5], 11);
	BB = HH(BB, CC, DD, AA, _X[13], 15);
	AA = HH(AA, BB, CC, DD, _X[3], 3);
	DD = HH(DD, AA, BB, CC, _X[11], 9);
	CC = HH(CC, DD, AA, BB, _X[7], 11);
	BB = HH(BB, CC, DD, AA, _X[15], 15);

	_A += AA;
	_B += BB;
	_C += CC;
	_D += DD;
}

auto MD4::output() -> std::string {
	std::string result = "";
	result += uint_to_hex(reverse_endianness(_A));
	result += uint_to_hex(reverse_endianness(_B));
	result += uint_to_hex(reverse_endianness(_C));
	result += uint_to_hex(reverse_endianness(_D));
	return result;
}

namespace MD {
	auto md4(const std::string& input) {
		MD4 instance = MD4();
		instance.load_string(input);
		return instance.output();
	}
}