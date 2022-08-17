#include <array>
#include <iostream>

#include "common.hpp"
#include "toycrypto.hpp"


#define T_BYTES sizeof(T)
#define T_BITS (T_BYTES * 8)

constexpr unsigned int BLOCK_SIZE = 16;
#define BLOCK_BYTES (BLOCK_SIZE * T_BYTES)

constexpr unsigned int SALT_SIZE = 4;
#define SALT_BYTES (SALT_SIZE * T_BYTES)

// Initial values
constexpr unsigned int H_SIZE = 8;
constexpr std::array<u32, H_SIZE> IV24 = {
	0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
	0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
};
constexpr std::array<u32, H_SIZE> IV32 = {
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};
constexpr std::array<u64, H_SIZE> IV64 = {
	0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
	0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
	0x510e527fade682d1, 0x9b05688c2b3e6c1f,
	0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
};
constexpr std::array<u64, H_SIZE> IV38 = {
	0xcbbb9d5dc1059ed8, 0x629a292a367cd507,
	0x9159015a3070dd17, 0x152fecd8f70e5939,
	0x67332667ffc00b31, 0x8eb44a8768581511,
	0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4
};

// Constants
constexpr unsigned int C_SIZE = 16;
const std::array<u32, C_SIZE> C32 = {
	0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
	0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
	0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
	0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917
};

const std::array<u64, C_SIZE> C64 = {
	0x243f6a8885a308d3, 0x13198a2e03707344,
	0xa4093822299f31d0, 0x082efa98ec4e6c89,
	0x452821e638d01377, 0xbe5466cf34e90c6c,
	0xc0ac29b7c97c50dd, 0x3f84d5b5b5470917,
	0x9216d5d98979fb1b, 0xd1310ba698dfb5ac,
	0x2ffd72dbd01adfb7, 0xb8e1afed6a267e96,
	0xba7c9045f12c7f99, 0x24a19947b3916cf7,
	0x0801f2e2858efc16, 0x636920d871574e69
};

constexpr std::array<std::array<unsigned int, 16>, 10> SIGMA = { {
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
	{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
	{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
	{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
	{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
	{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
	{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
	{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
	{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0}
} };

template<class T>
class Blake {
public:
	Blake(unsigned int bitlength);
	void load_salt(std::istream* const salt);
	auto hexdigest(std::istream* const input)->std::string* const;

private:
	std::array<T, H_SIZE> m_h = {};
	std::array<T, SALT_SIZE> m_salt = {};
	std::array<T, BLOCK_SIZE> m_block = {};
	std::array<T, BLOCK_SIZE> m_v = {};
	const std::array<T, C_SIZE>* m_C = NULL;
	std::array<unsigned int, 4> m_rc = {};

	unsigned int m_out_length;

	void load(std::istream* const input);
	void comp(u64 length);
	void G(unsigned int r, unsigned int a, unsigned int b, unsigned int c, unsigned int d, unsigned int i);

	// For debugging purposes
	void print_block() const;
};

// For debugging purposes
template<class T>
void Blake<T>::print_block() const {
	unsigned int i;
	unsigned int perline = 4;

	if constexpr (std::is_same<T, u64>::value) {
		perline = 2;
	}

	std::cout << "-- BLOCK --" << std::endl;
	for (i = 0; i < BLOCK_SIZE; i++) {
		std::cout << to_hex<T>(m_block.at(i)) << " ";
		if ((i + 1) % perline == 0) {
			std::cout << std::endl;
		} else {
			std::cout << "- ";
		}
	}
	std::cout << "---" << std::endl << std::endl;
}

template<class T>
Blake<T>::Blake(unsigned int bitlength) : m_out_length(bitlength / 8) {
	if constexpr (std::is_same<T, u32>::value) {
		if (bitlength == 256) {
			m_h = IV32;
		} else if (bitlength == 224) {
			m_h = IV24;
		} else {
			throw TC::exceptions::NotImplementedError("Blake: The supplied bitlength is supported!");
		}

		m_C = &C32;
		m_rc = {16, 12, 8, 7};
	} else if constexpr (std::is_same<T, u64>::value) {
		if (bitlength == 512) {
			m_h = IV64;
		} else if (bitlength == 384) {
			m_h = IV38;
		} else {
			throw TC::exceptions::NotImplementedError("Blake: The supplied bitlength is not supported!");
		}

		m_C = &C64;
		m_rc = {32, 25, 16, 11};
	} else {
		throw TC::exceptions::TCException("Blake: The template type is not implemented!");
	}
}

template<class T>
auto Blake<T>::hexdigest(std::istream* const input) -> std::string* const {
	// Load input
	load(input);

	// Generate output
	static std::string result = "";
	unsigned int i;

	for (i = 0; i < (m_out_length / T_BYTES); i++) {
		result += to_hex<T>(m_h.at(i));
	}

	return &result;
}

template<class T>
void Blake<T>::load_salt(std::istream* const salt) {
	char* buffer = new char[SALT_BYTES];
	u64 read = 0;
	unsigned int i;

	// Load salt
	if (salt->peek() == EOF) {
		delete[] buffer;
		return;
	}

	if (!salt->good()) {
		throw TC::exceptions::TCException("Blake: Could not read the salt!");
	}

	salt->read(buffer, SALT_BYTES);
	read = salt->gcount();

	for (i = 0; i < (read / T_BYTES); i++) {
		m_salt.at((T_BYTES - 1) - i) = load_be<T>(buffer, SALT_BYTES, i * T_BYTES);
	}

	// Load the rest of the bytes
	if ((read % T_BYTES) > 0) {
		m_salt.at((T_BYTES - 1) - i) = load_be<T>(buffer, SALT_BYTES, i * T_BYTES, read % T_BYTES);
	}

	delete[] buffer;

	// For debugging
	/*std::cout << "Salt: " << std::endl;
	for (i = 0; i < 4; i++) {
		std::cout << to_hex<u32>(m_salt.at(i));
		if (i < 3) {
			std::cout << " - ";
		}
	}
	std::cout << std::endl << std::endl;*/
}

template<class T>
void Blake<T>::load(std::istream* const input) {
	char* buffer = new char[BLOCK_BYTES];
	u64 length = 0;
	u64 read = 0;
	unsigned int i;
	
	// Load input
	while (input->peek() != EOF) {
		if (!input->good()) {
			throw TC::exceptions::TCException("Blake: Could not read the input!");
		}

		input->read(buffer, BLOCK_BYTES);
		read = input->gcount();
		length += read * 8;

		for (i = 0; i < (read / T_BYTES); i++) {
			m_block.at(i) = load_be<T>(buffer, BLOCK_BYTES, i * T_BYTES);
		}

		// Load the rest of the bytes
		if ((read % T_BYTES) > 0) {
			m_block.at(i) = load_be<T>(buffer, BLOCK_BYTES, i * T_BYTES, read % T_BYTES);
		}

		// Process the block if it's big enough
		if (read == BLOCK_BYTES) {
			comp(length);
			read = 0;
		}
	}

	delete[] buffer;

	// Append padding
	m_block.at(read / T_BYTES) ^= xor_mask_be<T>(0x80, read % T_BYTES);

	// Process the block if the message length don't fit
	if (read + 8 >= BLOCK_BYTES) {
		comp(length);
	}

	if (m_out_length == 32 || m_out_length == 64)
		m_block.at(BLOCK_SIZE - 3) ^= (T)0x01;

	// Append message length
	if constexpr (std::is_same<T, u32>::value) {
		m_block.at(BLOCK_SIZE - 1) = length & U32MAX;
		m_block.at(BLOCK_SIZE - 2) = (length >> 32) & U32MAX;
	} else {
		m_block.at(BLOCK_SIZE - 1) = length;
	}

	comp(length);
}

template<class T>
void Blake<T>::G(unsigned int r, unsigned int a, unsigned int b, unsigned int c, unsigned int d, unsigned int i)
{
	T va = m_v.at(a);
	T vb = m_v.at(b);
	T vc = m_v.at(c);
	T vd = m_v.at(d);

	unsigned int sri = SIGMA.at(r % 10).at(i);
	unsigned int sri1 = SIGMA.at(r % 10).at(i + 1);

	va += vb + (m_block.at(sri) ^ m_C->at(sri1));
	vd = rotateright<T>(vd ^ va, m_rc.at(0));
	vc += vd;
	vb = rotateright<T>(vb ^ vc, m_rc.at(1));
	va += vb + (m_block.at(sri1) ^ m_C->at(sri));
	vd = rotateright<T>(vd ^ va, m_rc.at(2));
	vc += vd;
	vb = rotateright<T>(vb ^ vc, m_rc.at(3));

	m_v.at(a) = va;
	m_v.at(b) = vb;
	m_v.at(c) = vc;
	m_v.at(d) = vd;
}

template<class T>
void Blake<T>::comp(u64 length) {
	// Debugging
	//print_block();

	unsigned int i;
	unsigned int rounds;

	// Load m_h into m_v
	for (i = 0; i < H_SIZE; i++) {
		m_v.at(i) = m_h.at(i);
		if (i < 4) {
			m_v.at(i + 8) = m_salt.at(i) ^ m_C->at(i);
		}
	}

	// Load length into m_v
	if constexpr (std::is_same<T, u32>::value) {
		// 32-bit
		m_v.at(12) = (length & U32MAX) ^ m_C->at(4);
		m_v.at(13) = (length & U32MAX) ^ m_C->at(5);
		m_v.at(14) = (u32)(length >> 32) ^ m_C->at(6);
		m_v.at(15) = (u32)(length >> 32) ^ m_C->at(7);

		rounds = 14;
	} else {
		// 64-bit
		m_v.at(12) = length ^ m_C->at(4);
		m_v.at(13) = length ^ m_C->at(5);
		m_v.at(14) = m_C->at(6);
		m_v.at(15) = m_C->at(7);

		rounds = 16;
	}

	// The round function
	for (i = 0; i < rounds; i++) {
		G(i, 0, 4, 8, 12, 0);
		G(i, 1, 5, 9, 13, 2);
		G(i, 2, 6, 10, 14, 4);
		G(i, 3, 7, 11, 15, 6);
		G(i, 0, 5, 10, 15, 8);
		G(i, 1, 6, 11, 12, 10);
		G(i, 2, 7, 8, 13, 12);
		G(i, 3, 4, 9, 14, 14);
	}

	// Store the results in m_h
	for (i = 0; i < H_SIZE; i++) {
		m_h.at(i) = m_h.at(i) ^ m_salt.at(i % 4) ^ m_v.at(i) ^ m_v.at(i + 8);
	}

	// Clear m_block
	m_block.fill(0);
}

auto TC::BLAKE::blake256(std::istream* const input, std::istream* const salt) -> std::string* const {
	Blake<u32> inst(256);
	inst.load_salt(salt);
	return inst.hexdigest(input);
}

auto TC::BLAKE::blake256(std::istream* const input) -> std::string* const {
	Blake<u32> inst(256);
	return inst.hexdigest(input);
}

auto TC::BLAKE::blake224(std::istream* const input, std::istream* const salt) -> std::string* const {
	Blake<u32> inst(224);
	inst.load_salt(salt);
	return inst.hexdigest(input);
}

auto TC::BLAKE::blake224(std::istream* const input) -> std::string* const {
	Blake<u32> inst(224);
	return inst.hexdigest(input);
}

auto TC::BLAKE::blake384(std::istream* const input, std::istream* const salt) -> std::string* const {
	Blake<u64> inst(384);
	inst.load_salt(salt);
	return inst.hexdigest(input);
}

auto TC::BLAKE::blake384(std::istream* const input) -> std::string* const {
	Blake<u64> inst(384);
	return inst.hexdigest(input);
}

auto TC::BLAKE::blake512(std::istream* const input, std::istream* const salt) -> std::string* const {
	Blake<u64> inst(512);
	inst.load_salt(salt);
	return inst.hexdigest(input);
}

auto TC::BLAKE::blake512(std::istream* const input) -> std::string* const {
	Blake<u64> inst(512);
	return inst.hexdigest(input);
}