#include <array>
#include <iostream>

#include "common.hpp"
#include "toycrypto.hpp"

constexpr unsigned int BLOCK_SIZE = 16;
constexpr unsigned int BLOCK_BYTES = BLOCK_SIZE * 4;

constexpr unsigned int H_SIZE = 5;
constexpr std::array<u32, H_SIZE> H_INIT = {
	0x67452301,
	0xefcdab89,
	0x98badcfe,
	0x10325476,
	0xc3d2e1f0
};

constexpr std::array<u32, 4> K = {
	0x5a827999,
	0x6ed9eba1,
	0x8f1bbcdc,
	0xca62c1d6
};

class SHA1 {
public:
	auto hexdigest(std::istream* const input) -> std::string* const;

private:
	std::array<u32, H_SIZE> m_h = H_INIT;
	std::array<u32, BLOCK_SIZE> m_block = {};

	void load(std::istream* const input);
	void comp();

	// For debugging purposes
	void print_block();
};

// For debugging purposes
void SHA1::print_block() {
	unsigned int i;
	std::cout << "-- BLOCK --" << std::endl;
	for (i = 0; i < BLOCK_SIZE; i++) {
		std::cout << to_hex<u32>(m_block.at(i)) << " ";
		if ((i + 1) % 4 == 0) {
			std::cout << std::endl;
		}
		else {
			std::cout << "- ";
		}
	}
	std::cout << "---" << std::endl << std::endl;;
}

auto SHA1::hexdigest(std::istream* const input) -> std::string* const {
	// Load input
	load(input);

	// Generate output
	static std::string result = "";
	for (u32 i : m_h) {
		result += to_hex<u32>(i);
	}
	return &result;
}

void SHA1::load(std::istream* const input) {
	char* buffer = new char[BLOCK_BYTES]; 
	u64 length = 0;
	u64 read = 0;
	unsigned int i;

	// Read the entire file
	while (input->peek() != EOF) {
		if (!input->good()) {
			throw TC::exceptions::TCException("SHA1: Could not read the input!");
		}

		input->read(buffer, BLOCK_BYTES);
		read = input->gcount();
		length += read * 8;

		// Read in whole dwords
		for (i = 0; i < (read / 4); i++) {
			m_block.at(i) = load_be<u32>(buffer, BLOCK_BYTES, i * 4);
		}

		// Read in the rest
		if ((read % 4) > 0) {
			m_block.at(i) = load_be<u32>(buffer, BLOCK_BYTES, i * 4, read % 4);
		}

		if (read == BLOCK_BYTES) {
			comp();
			read = 0;
		}
	}

	delete[] buffer;

	// Append padding
	m_block.at(read / 4) ^= xor_mask_be<u32>(0x80, read % 4);

	// In case the message length does not fit
	if (read + 8 >= BLOCK_BYTES) {
		comp();
	}

	// Append message length
	m_block.at(BLOCK_SIZE - 2) = (length >> 32) & U32MAX;
	m_block.at(BLOCK_SIZE - 1) = length & U32MAX;
	comp();
}

void SHA1::comp()
{
	//print_block();
	std::array<u32, 80> words = {};
	size_t j;

	// Load words from the chunk into the words-array
	for (j = 0; j < BLOCK_SIZE; j++) {
		words.at(j) = m_block.at(j);
	}

	// Clear m_block
	m_block.fill(0);

	// Extend the words-array to 80 words
	for (j = BLOCK_SIZE; j < 80; j++) {
		words.at(j) = rotateleft<u32>(
			words.at(j-3) ^ words.at(j-8) ^ words.at(j-14) ^ words.at(j-16),
			1
		);
	}

	u32 a = m_h.at(0);
	u32 b = m_h.at(1);
	u32 c = m_h.at(2);
	u32 d = m_h.at(3);
	u32 e = m_h.at(4);

	u32 f, k;

	// Main loop
	for (j = 0; j < 80; j++) {
		if (j >= 0 && j <= 19) {
			f = (b & c) | ((~b) & d);
			k = K.at(0);
		} else if (j >= 20 && j <=39) {
			f = b ^ c ^ d;
			k = K.at(1);
		}
		else if (j >= 40 && j <= 59) {
			f = (b & c) | (b & d) | (c & d);
			k = K.at(2);
		} else {
			f = b ^ c ^ d;
			k = K.at(3);
		}

		u32 temp = rotateleft<u32>(a, 5) + f + e + k + words.at(j);
		e = d;
		d = c;
		c = rotateleft<u32>(b, 30);
		b = a;
		a = temp;
	}

	m_h.at(0) += a;
	m_h.at(1) += b;
	m_h.at(2) += c;
	m_h.at(3) += d;
	m_h.at(4) += e;
}

auto TC::SHA::sha1(std::istream* const input) -> std::string* const {
	SHA1 instance;
	return instance.hexdigest(input);
}
