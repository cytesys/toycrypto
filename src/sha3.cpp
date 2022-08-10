#include <array>
#include <cmath>
#include <algorithm>
#include <iostream>

#include "common.hpp"
#include "toycrypto.hpp"

#define CHUNK_SIZE 200
#define LANE(x, y) (((y) * 5) + (x))

static const u8 RO[25] = {
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

//u64 load_u64(char* buf, int offset, int num = 8) {
//	u64 temp = 0;
//	int j = num - 1;
//	//std::cout << "Offset: " << offset << std::endl;
//	//std::cout << "Num: " << num << std::endl;
//	for (int i = 7; i >= (8 - num); i--) {
//		temp <<= 8;
//		temp |= buf[offset + j--];
//		//std::cout << "Temp: " << u64_to_hex(temp) << std::endl;
//	}
//	return temp;
//}

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

	for (i = 0; i < m_state.size(); i++) {
		if ((i + 1) == (m_rate / 64)) {
			sep = '|';
		} else {
			sep = ' ';
		}
		std::cout << to_hex<u64>(m_state[i]) << sep;
		if ((i + 1) % 2 == 0) {
			std::cout << std::endl;
		} else {
			std::cout << "- ";
		}
	}
	std::cout << std::endl;
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
	//std::cout << "Step 2kf" << std::endl;
	//print_state();

	size_t i;
	size_t x;
	size_t y;

	for (i = 0; i < 24; i++) {
		//std::cout << "Step 2kf - " << i << std::endl;
		/*
		C[x] = A[x,0] xor A[x,1] xor A[x,2] xor A[x,3] xor A[x,4],   for x in 0…4
		D[x] = C[x-1] xor rot(C[x+1],1),                             for x in 0…4
		A[x,y] = A[x,y] xor D[x],                           for (x,y) in (0…4,0…4)
		*/
		std::array<u64, 5> c = {};
		u64 d;

		for (x = 0; x < 5; x++) {
			//std::cout << "Step 2kf2 - " << x << std::endl;
			c.at(x) = m_state.at(LANE(x, 0)) ^ m_state.at(LANE(x, 1)) ^ m_state.at(LANE(x, 2)) ^ m_state.at(LANE(x, 3)) ^ m_state.at(LANE(x, 4));
		}

		for (x = 0; x < 5; x++) {
			//std::cout << "Step 2kf3 - " << x << std::endl;
			d = c.at((x + 4) % 5) ^ rotateleft<u64>(c.at((x + 1) % 5), 1);
			for (y = 0; y < 5; y++) {
				m_state.at(LANE(x, y)) ^= d;
			}
		}

		/*
		B[y,2*x+3*y] = rot(A[x,y], r[x,y]),                 for (x,y) in (0…4,0…4)
		*/

		std::array<u64, 25> b = {};
		//std::cout << "Step 2kf5" << std::endl;
		for (y = 0; y < 5; y++) {
			//std::cout << "Step 2kf5 - " << y << std::endl;
			for (x = 0; x < 5; x++) {
				//std::cout << "r(" << x << ", " << y << ") [" << LANE(x, y) << "] = " << (int)(RO[LANE(x, y)]) << std::endl;
				b.at(LANE(y, ((2 * x) + (3 * y)) % 5)) = rotateleft<u64>(m_state.at(LANE(x, y)), RO[LANE(x, y)]);
			}
		}

		/*
		A[x,y] = B[x,y] xor ((not B[x+1,y]) and B[x+2,y]),  for (x,y) in (0…4,0…4)
		*/
		for (y = 0; y < 5; y++) {
			//std::cout << "Step 2kf6 - " << y << std::endl;
			for (x = 0; x < 5; x++) {
				m_state.at(LANE(x, y)) = b.at(LANE(x, y)) ^ ((~b.at(LANE((x + 1) % 5, y))) & b.at(LANE((x + 2) % 5, y)));
			}
		}

		/*
		A[0,0] = A[0,0] xor RC
		*/

		u64 result = 0x0;
		unsigned int shift = 1;
		for (x = 0; x < 7; x++)
		{
			u64 value = rc(7 * i + x);
			result |= value << (shift - 1);
			shift *= 2;
		}
		//std::cout << "RC[" << i << "]: " << u64_to_hex(result) << std::endl;
		m_state.at(0) ^= result;
	}

	// Debug
	//m_state.fill(0);
	// ---
}

void Keccak1600::sponge(std::istream* const input, u8 dsuf) {
	char* buffer = new char[CHUNK_SIZE];
	size_t blocksize = 0;
	unsigned int rate = m_rate / 8;
	unsigned int i;

	while (input->peek() != EOF) {
		//std::cout << "Step 2a" << std::endl;
		if (!input->good()) {
			throw TC::exceptions::TCException("Cannot read file/input");
		}
		//std::cout << "Step 2b" << std::endl;
		//std::cout << "Rate: " << rate / 8 << std::endl;

		// Try to read in a full block
		blocksize = input->readsome(buffer, rate);

		for (i = 0; i < (blocksize / 8); i++) {
			//std::cout << "Step 2c - " << i << std::endl;
			m_state.at(i) ^= load_le<u64>(buffer, CHUNK_SIZE, i * 8);
		}

		if ((blocksize % 8) > 0){
			// Read in the rest
			//std::cout << "Step 2rest - i: " << i << ", rest: " << read % 8 << std::endl;
			m_state.at(i) ^= load_le<u64>(buffer, CHUNK_SIZE, i * 8, blocksize % 8);
		}

		//std::cout << "Step 2d" << std::endl;
		if (blocksize == rate) {
			keccakf();
			blocksize = 0;
		}

	}

	delete[] buffer;

	// Apply padding
	//std::cout << "Step 2e" << std::endl;
	//m_state.at((blocksize++) / 8) ^= (u64)dsuf << ((read % 8) * 8);
	m_state.at(blocksize / 8) ^= xor_mask_le<u64>(dsuf, blocksize);

	if (((dsuf & 0x80) != 0) && (blocksize + 1 == rate)) {
		keccakf();
	}

	m_state.at((rate / 8) - 1) ^= 0x8000000000000000;
	//std::cout << "Step 2f" << std::endl;
	keccakf();
}

auto Keccak1600::squeeze(size_t length) -> std::string* const {
	static std::string result = "";
	size_t rate = m_rate / 8;
	unsigned int i;
	size_t blocksize = 0;

	while (length > 0) {
		//std::cout << "Step 3a - length: " << length << std::endl;
		blocksize = std::min(rate, length);
		for (i = 0; i < (blocksize / 8); i++) {
			//std::cout << "Step 3b - " << i << std::endl;
			//result += u64_to_hex(m_state.at(i));
			/*for (int j = 7; j >= 0; j--) {
				result += to_hex<u8>((m_state[i] >> ((7 - j) * 8)) & 0xff);
			}*/
			result += to_hex<u64>(m_state[i], true);
		}

		// Squeeze out the rest
		result += to_hex<u64>(m_state.at(i), true).substr(0, (blocksize % 8) * 2);
		/*if ((blocksize % 8) > 0) {
			for (int j = 7; j >= (8 - (blocksize % 8)); j--) {
				result += to_hex<u8>((m_state[i] >> ((7 - j) * 8)) & 0xff);
			}
		}*/

		length -= blocksize;

		keccakf();
	}

	return &result;
}

auto TC::SHA::shake128(std::istream* const input, unsigned int bitlength) -> std::string* const {
	if ((bitlength % 8) != 0) {
		throw TC::exceptions::TCException("The bitlength must be divisible by 8!");
	}
	//std::cout << "Step 1" << std::endl;
	Keccak1600 inst(1344, 256);
	//std::cout << "Step 2" << std::endl;
	inst.sponge(input, 0x1f);
	//std::cout << "Step 3" << std::endl;
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
