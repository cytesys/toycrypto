#include <array>
#include <cmath>
#include <algorithm>
#include <iostream>

#include "common.hpp"
#include "toycrypto.hpp"

constexpr unsigned int BLOCK_SIZE = 200;
#define LANE(x, y) (((y) * 5) + (x))

constexpr std::array<u8, 25> RO = {
	 0,  1, 62, 28, 27,
	36, 44,  6, 55, 20,
	 3, 10, 43, 25, 39,
	41, 45, 15, 21,  8,
	18,  2, 61, 56, 14
};

u64 rc(size_t t) {
	u64 result = 0x1;
	unsigned int i;

	for (i = 1; i <= t; i++)
	{
		result <<= 1;
		if (result & 0x100)
			result ^= 0x71;
	}

	return result & 0x1;
}

class Keccak1600 {
public:
	Keccak1600(unsigned int rate, unsigned int capacity);
	void sponge(std::istream* const input, u8 dsuf);
	auto squeeze(size_t length)->std::string* const;

private:
	unsigned int m_rate;
	unsigned int m_cap;
	std::array<u64, 25> m_state = {};

	void keccakf();

	// For debugging purposes
	void print_state() const;
};

// For debugging purposes
void Keccak1600::print_state() const {
	unsigned int i;
	char sep;

	std::cout << "-- STATE --" << std::endl;
	for (i = 0; i < m_state.size(); i++) {
		if ((i + 1) == (m_rate / 64)) {
			sep = '|';
		} else {
			sep = ' ';
		}
		std::cout << to_hex<u64>(m_state.at(i)) << sep;
		if ((i + 1) % 2 == 0) {
			std::cout << std::endl;
		} else {
			std::cout << "- ";
		}
	}
	std::cout << std::endl << "---" << std::endl << std::endl;;
}

Keccak1600::Keccak1600(unsigned int rate, unsigned int capacity) : m_rate(rate), m_cap(capacity) {
	if ((rate + capacity) != 1600) {
		throw TC::exceptions::TCException("The permutation width is invalid!");
	}

	if ((rate % 8) > 0) {
		throw TC::exceptions::NotImplementedError("The supplied rate is not implemented!");
	}
}

void Keccak1600::keccakf() {
	//print_state();

	size_t i;
	size_t x;
	size_t y;

	for (i = 0; i < 24; i++) {
		std::array<u64, 5> c = {};
		u64 d;

		for (x = 0; x < 5; x++) {
			c.at(x) = m_state.at(LANE(x, 0)) ^ m_state.at(LANE(x, 1)) ^ m_state.at(LANE(x, 2)) ^ m_state.at(LANE(x, 3)) ^ m_state.at(LANE(x, 4));
		}

		for (x = 0; x < 5; x++) {
			d = c.at((x + 4) % 5) ^ rotateleft<u64>(c.at((x + 1) % 5), 1);
			for (y = 0; y < 5; y++) {
				m_state.at(LANE(x, y)) ^= d;
			}
		}

		std::array<u64, 25> b = {};
		for (y = 0; y < 5; y++) {
			for (x = 0; x < 5; x++) {
				b.at(LANE(y, ((2 * x) + (3 * y)) % 5)) = rotateleft<u64>(m_state.at(LANE(x, y)), RO.at(LANE(x, y)));
			}
		}

		for (y = 0; y < 5; y++) {
			for (x = 0; x < 5; x++) {
				m_state.at(LANE(x, y)) = b.at(LANE(x, y)) ^ ((~b.at(LANE((x + 1) % 5, y))) & b.at(LANE((x + 2) % 5, y)));
			}
		}

		u64 result = 0x0;
		unsigned int shift = 1;
		for (x = 0; x < 7; x++)
		{
			u64 value = rc(7 * i + x);
			result |= value << (shift - 1);
			shift *= 2;
		}
		m_state.at(0) ^= result;
	}

	// Debug
	//m_state.fill(0);
	// ---
}

void Keccak1600::sponge(std::istream* const input, u8 dsuf) {
	char* buffer = new char[BLOCK_SIZE];
	u64 blocksize = 0;
	const u64 rate = m_rate / 8;
	unsigned int i;

	while (input->peek() != EOF) {
		if (!input->good()) {
			throw TC::exceptions::TCException("Cannot read file/input");
		}

		// Try to read in a full block
		input->read(buffer, rate);
		blocksize = input->gcount();

		for (i = 0; i < (blocksize / 8); i++) {
			m_state.at(i) ^= load_le<u64>(buffer, BLOCK_SIZE, i * 8);
		}

		if ((blocksize % 8) > 0){
			// Read in the rest
			m_state.at(blocksize / 8) ^= load_le<u64>(buffer, BLOCK_SIZE, i * 8, blocksize % 8);
		}

		if (blocksize == rate) {
			keccakf();
			blocksize = 0;
		}
	}

	delete[] buffer;

	// Apply padding
	m_state.at(blocksize / 8) ^= xor_mask_le<u64>(dsuf, blocksize % 8);

	if (((dsuf & 0x80) != 0) && (blocksize + 1 == rate)) {
		keccakf();
	}

	m_state.at((rate / 8) - 1) ^= (u64)(0x1) << 63;
	keccakf();
}

auto Keccak1600::squeeze(size_t length) -> std::string* const {
	static std::string result = "";
	size_t rate = m_rate / 8;
	unsigned int i;
	size_t blocksize = 0;

	while (length > 0) {
		//std::cout << "- output -" << std::endl;
		blocksize = std::min(rate, length);
		for (i = 0; i < (blocksize / 8); i++) {
			result += to_hex<u64>(m_state.at(i), true);
		}

		// Squeeze out the rest
		result += to_hex<u64>(m_state.at(i), true).substr(0, (blocksize % 8) * 2);

		length -= blocksize;

		keccakf();
	}

	return &result;
}

auto TC::SHA::shake128(std::istream* const input, unsigned int bitlength) -> std::string* const {
	if ((bitlength % 8) != 0) {
		throw TC::exceptions::TCException("The bitlength must be divisible by 8!");
	}
	Keccak1600 inst(1344, 256);
	inst.sponge(input, 0x1f);
	return inst.squeeze(bitlength / 8);
}

auto TC::SHA::shake256(std::istream* const input, unsigned int bitlength) -> std::string* const {
	if ((bitlength % 8) != 0) {
		throw TC::exceptions::TCException("The bitlength must be divisible by 8!");
	}
		
	Keccak1600 inst(1088, 512);
	inst.sponge(input, 0x1f);
	return inst.squeeze(bitlength / 8);
}

auto TC::SHA::sha3_224(std::istream* const input) -> std::string* const {
	Keccak1600 inst(1152, 448);
	inst.sponge(input, 0x06);
	return inst.squeeze(28);
}

auto TC::SHA::sha3_256(std::istream* const input) -> std::string* const {
	Keccak1600 inst(1088, 512);
	inst.sponge(input, 0x06);
	return inst.squeeze(32);
}

auto TC::SHA::sha3_384(std::istream* const input) -> std::string* const {
	Keccak1600 inst(832, 768);
	inst.sponge(input, 0x06);
	return inst.squeeze(48);
}

auto TC::SHA::sha3_512(std::istream* const input) -> std::string* const {
	Keccak1600 inst(576, 1024);
	inst.sponge(input, 0x06);
	return inst.squeeze(64);
}
