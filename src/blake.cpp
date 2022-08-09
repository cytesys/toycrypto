#include <array>
#include <iostream>

#include "common.hpp"
#include "toycrypto.hpp"


#define T_BYTES sizeof(T)
#define T_BITS (T_BYTES * 8)

#define BLOCK_SIZE 16
#define BLOCK_BYTES (BLOCK_SIZE * T_BYTES)

#define BLOCK32_BYTES 64  // 16 * 4 bytes
#define BLOCK64_BYTES 128 // 16 * 8 bytes

#define SALT_SIZE 4
#define SALT_BYTES (SALT_SIZE * T_BYTES)

#define SALT32_BYTES 16 // 4 * 4 bytes
#define SALT64_BYTES 32 // 4 * 8 bytes

// Initial values
#define H_SIZE 8
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
#define C_SIZE 16
constexpr std::array<u32, C_SIZE> C32 = {
	0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
	0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
	0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
	0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917
};

constexpr std::array<u64, C_SIZE> C64 = {
	0x243f6a8885a308d3, 0x13198a2e03707344,
	0xa4093822299f31d0, 0x082efa98ec4e6c89,
	0x452821e638d01377, 0xbe5466cf34e90c6c,
	0xc0ac29b7c97c50dd, 0x3f84d5b5b5470917,
	0x9216d5d98979fb1b, 0xd1310ba698dfb5ac,
	0x2ffd72dbd01adfb7, 0xb8e1afed6a267e96,
	0xba7c9045f12c7f99, 0x24a19947b3916cf7,
	0x0801f2e2858efc16, 0x636920d871574e69
};

// Permutations
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
	Blake(unsigned int type);
	void load_salt(std::istream* const salt);
	auto hexdigest(std::istream* const input)->std::string* const;

private:
	std::array<T, H_SIZE> m_h = {};
	std::array<T, SALT_SIZE> m_salt = {};
	std::array<T, BLOCK_SIZE> m_block = {};
	std::array<T, BLOCK_SIZE> m_v = {};

	u64 m_counter = 0;
	unsigned int m_type;

	void load(std::istream* const input);
	void handle();
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

	for (i = 0; i < BLOCK_SIZE; i++) {
		std::cout << to_hex<T>(m_block.at(i)) << " ";
		if ((i + 1) % perline == 0) {
			std::cout << std::endl;
		} else {
			std::cout << "- ";
		}
	}
	std::cout << std::endl;
}

template<class T>
Blake<T>::Blake(unsigned int type) : m_type(type) {
	if constexpr (std::is_same<T, u32>::value) {
		if (type == 256) {
			m_h = IV32;
		} else if (type == 224) {
			m_h = IV24;
		} else {
			throw TC::exceptions::NotImplementedError("Blake: The type is not implemented!");
		}
	} else if constexpr (std::is_same<T, u64>::value) {
		if (type == 512) {
			m_h = IV64;
		} else if (type == 384) {
			m_h = IV38;
		} else {
			throw TC::exceptions::NotImplementedError("Blake: The type is not implemented!");
		}
	} else {
		throw TC::exceptions::NotImplementedError("Blake: The template type is not implemented!");
	}
}

template<class T>
auto Blake<T>::hexdigest(std::istream* const input) -> std::string* const {
	load(input);

	static std::string result = "";
	for (unsigned int i = 0; i < (m_type / T_BITS); i++) {
		result += to_hex<T>(m_h[i]);
	}
	return &result;
}

template<class T>
void Blake<T>::load_salt(std::istream* const salt) {
	char* buffer = new char[SALT_BYTES];
	size_t read = 0;
	unsigned int i;

	// Load salt
	while (salt->peek() != EOF) {
		if (!salt->good()) {
			throw TC::exceptions::TCException("Blake: Could not read the salt!");
		}

		read = salt->readsome(buffer, SALT_BYTES);

		// Read whole dwords
		for (i = 0; i < (read / T_BYTES); i++) {
			m_salt.at((T_BYTES - 1) - i) = load_be<T>(buffer, SALT_BYTES, i * T_BYTES);
		}

		// Read in the rest
		if ((read % T_BYTES) > 0) {
			m_salt.at((T_BYTES - 1) - i) = load_be<T>(buffer, SALT_BYTES, i * T_BYTES, read % T_BYTES);
		}
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
	size_t read = 0;
	unsigned int i;
	
	// Load input
	while (input->peek() != EOF) {
		if (!input->good()) {
			throw TC::exceptions::TCException("Blake: Could not read the input!");
		}

		read = input->readsome(buffer, BLOCK_BYTES);
		m_counter += read * 8;

		// Read whole dwords
		for (i = 0; i < (read / T_BYTES); i++) {
			m_block.at(i) = load_be<T>(buffer, BLOCK_BYTES, i * T_BYTES);
		}

		// Read in the rest
		if ((read % T_BYTES) > 0) {
			m_block.at(i) = load_be<T>(buffer, BLOCK_BYTES, i * T_BYTES, read % T_BYTES);
		}

		// Process the block if it's big enough
		if (read == BLOCK_BYTES) {
			handle();
			read = 0;
		}
	}

	delete[] buffer;

	// Apply padding
	m_block.at(read / T_BYTES) ^= xor_mask_be<T>(0x80, read % T_BYTES);

	if (read + 8 >= BLOCK_BYTES) {
		handle();
	}

	if (m_type == 256 || m_type == 512)
		m_block.at(BLOCK_SIZE - 3) ^= (T)0x01;

	// Append message length
	if constexpr (std::is_same<T, u32>::value) {
		m_block.at(BLOCK_SIZE - 1) = m_counter & U32MAX;
		m_block.at(BLOCK_SIZE - 2) = (m_counter >> 32) & U32MAX;
	} else if constexpr (std::is_same<T, u64>::value) {
		m_block.at(BLOCK_SIZE - 1) = m_counter;
	} else {
		throw TC::exceptions::NotImplementedError("Blake: The template type is not supported!");
	}

	handle();
}

template<class T>
void Blake<T>::G(unsigned int r, unsigned int a, unsigned int b, unsigned int c, unsigned int d, unsigned int i)
{
	T va = m_v[a];
	T vb = m_v[b];
	T vc = m_v[c];
	T vd = m_v[d];

	unsigned int sri = SIGMA.at((size_t)(r) % 10).at(i);
	unsigned int sri1 = SIGMA.at((size_t)(r) % 10).at((size_t)(i) + 1);

	if constexpr (std::is_same<T, u32>::value) {
		va = va + vb + (m_block[sri] ^ C32[sri1]);
		vd = rotateright<T>((vd ^ va), 16);
		vc = vc + vd;
		vb = rotateright<T>((vb ^ vc), 12);
		va = va + vb + (m_block[sri1] ^ C32[sri]);
		vd = rotateright<T>((vd ^ va), 8);
		vc = vc + vd;
		vb = rotateright<T>((vb ^ vc), 7);
	} else if constexpr (std::is_same<T, u64>::value) {
		va = va + vb + (m_block[sri] ^ C64[sri1]);
		vd = rotateright<u64>((vd ^ va), 32);
		vc = vc + vd;
		vb = rotateright<u64>((vb ^ vc), 25);
		va = va + vb + (m_block[sri1] ^ C64[sri]);
		vd = rotateright<u64>((vd ^ va), 16);
		vc = vc + vd;
		vb = rotateright<u64>((vb ^ vc), 11);
	} else {
		throw TC::exceptions::NotImplementedError("Blake: The template type is not implemented!");
	}

	m_v[a] = va;
	m_v[b] = vb;
	m_v[c] = vc;
	m_v[d] = vd;
}

template<class T>
void Blake<T>::handle() {
	// Debugging
	//print_block();

	size_t i;

	// INITIALIZE V
	m_v.fill(0);

	// Load m_h into m_v
	for (i = 0; i < H_SIZE; i++)
		m_v[i] = m_h[i];

	if constexpr (std::is_same<T, u32>::value) {
		// Load m_salt into m_v
		for (i = 0; i < SALT_SIZE; i++)
			m_v[i + 8] = m_salt[i] ^ C32[i];

		// Load m_counter into m_v
		m_v[12] = (m_counter & U32MAX) ^ C32[4];
		m_v[13] = (m_counter & U32MAX) ^ C32[5];
		m_v[14] = (rotateleft<u64>(m_counter, 32) & U32MAX) ^ C32[6];
		m_v[15] = (rotateleft<u64>(m_counter, 32) & U32MAX) ^ C32[7];

		// ROUND FUNCTION
		for (unsigned int round = 0; round < 14; round++) {
			G(round, 0, 4, 8, 12, 0);
			G(round, 1, 5, 9, 13, 2);
			G(round, 2, 6, 10, 14, 4);
			G(round, 3, 7, 11, 15, 6);
			G(round, 0, 5, 10, 15, 8);
			G(round, 1, 6, 11, 12, 10);
			G(round, 2, 7, 8, 13, 12);
			G(round, 3, 4, 9, 14, 14);
		}
	} else if constexpr (std::is_same<T, u64>::value) {
		// Load m_salt into m_v
		for (i = 0; i < SALT_SIZE; i++)
			m_v[i + 8] = m_salt[i] ^ C64[i];

		// Load m_counter into m_v
		m_v[12] = m_counter ^ C64[4];
		m_v[13] = m_counter ^ C64[5];
		m_v[14] = C64[6];
		m_v[15] = C64[7];

		// ROUND FUNCTION
		for (unsigned int round = 0; round < 16; round++) {
			G(round, 0, 4, 8, 12, 0);
			G(round, 1, 5, 9, 13, 2);
			G(round, 2, 6, 10, 14, 4);
			G(round, 3, 7, 11, 15, 6);
			G(round, 0, 5, 10, 15, 8);
			G(round, 1, 6, 11, 12, 10);
			G(round, 2, 7, 8, 13, 12);
			G(round, 3, 4, 9, 14, 14);
		}
	} else {
		throw TC::exceptions::NotImplementedError("Blake: The template type is not implemented!");
	}

	// STORE RESULTS in m_h
	for (i = 0; i < H_SIZE; i++) {
		m_h[i] = m_h[i] ^ m_salt[i % 4] ^ m_v[i] ^ m_v[i + 8];
	}

	// Clear m_block
	m_block.fill(0);
}

/*class Blake64 {
public:
	Blake64(unsigned int type);
	void load(std::istream* const input, std::istream* const salt);
	auto output() const->str;
private:
	std::array<u64, H_SIZE> m_h = {};
	std::array<u64, SALT_SIZE> m_salt = {};
	std::array<u64, BLOCK_SIZE> m_block = {};
	std::array<u64, BLOCK_SIZE> m_v = {};
	u64 m_counter = 0;
	unsigned int m_type;

	void handle();
	void G(int r, int a, int b, int c, int d, int i);

	// For debugging purposes
	void print_block();
};

// For debugging purposes
void Blake64::print_block() {
	for (unsigned int i = 0; i < BLOCK_SIZE; i++) {
		std::cout << to_hex<u64>(m_block.at(i)) << " ";
		if ((i + 1) % 2 == 0) {
			std::cout << std::endl;
		} else {
			std::cout << "- ";
		}
	}
	std::cout << std::endl;
}

Blake64::Blake64(unsigned int type) : m_type(type) {
	if (type == 512) {
		m_h = IV64;
	} else if (type == 384) {
		m_h = IV38;
	} else {
		throw TC::exceptions::NotImplementedError("Blake64: The type is not implemented!");
	}
}

void Blake64::load(std::istream* input, std::istream* salt) {
	char* buffer = new char[BLOCK64_BYTES];
	u64 read;
	unsigned int i;

	// Load salt
	while (salt->peek() != EOF) {
		if (!salt->good()) {
			throw TC::exceptions::TCException("Blake64: Could not read the salt!");
		}

		read = salt->readsome(buffer, SALT64_BYTES);

		// Read whole dwords
		for (i = 0; i < (read / 8); i++) {
			m_salt.at(3 - i) = load_be<u64>(buffer, SALT64_BYTES, i * 8);
		}

		// Read in the rest
		if ((read % 8) > 0) {
			m_salt.at(3 - i) = load_be<u64>(buffer, SALT64_BYTES, i * 8, read % 8);
		}
	}

	// Debugging
	std::cout << "Salt: " << std::endl;
	for (i = 0; i < SALT_SIZE; i++) {
		std::cout << to_hex<u64>(m_salt.at(i));
		if ((i + 1) % 2 == 0) {
			std::cout << std::endl;
		} else {
			std::cout << " - ";
		}
	}
	std::cout << std::endl << std::endl;

	// Clear the buffer
	for (i = 0; i < BLOCK64_BYTES; i++) {
		buffer[i] = 0x00;
	}

	// Load input
	while (input->peek() != EOF) {
		if (!input->good()) {
			throw TC::exceptions::TCException("Blake64: Could not read the input!");
		}

		read = input->readsome(buffer, BLOCK64_BYTES);
		m_counter += read * 8;

		// Read whole dwords
		for (i = 0; i < (read / 8); i++) {
			m_block.at(i) = load_be<u64>(buffer, BLOCK64_BYTES, i * 8);
		}

		// Read in the rest
		if ((read % 8) > 0) {
			m_block.at(i) = load_be<u64>(buffer, BLOCK64_BYTES, i * 8, read % 8);
		}

		// Process the block if it's big enough
		if (read == BLOCK64_BYTES) {
			handle();
			read = 0;
		}
	}

	// Apply padding
	m_block.at(read / 8) ^= xor_mask_be<u64>(0x80, read % 8);

	if (read + 17 > BLOCK64_BYTES) {
		handle();
	}

	if (m_type == 512)
		m_block.at(BLOCK_SIZE - 3) ^= (u64)0x01;

	// Append message length
	m_block.at(BLOCK_SIZE - 1) = m_counter;

	handle();
}

void Blake64::G(int r, int a, int b, int c, int d, int i)
{
	u64 va = m_v[a];
	u64 vb = m_v[b];
	u64 vc = m_v[c];
	u64 vd = m_v[d];

	int sri = SIGMA[r % 10][i];
	int sri1 = SIGMA[r % 10][i + 1];

	va = va + vb + (m_block[sri] ^ C64[sri1]);
	vd = rotateright<u64>((vd ^ va), 32);
	vc = vc + vd;
	vb = rotateright<u64>((vb ^ vc), 25);
	va = va + vb + (m_block[sri1] ^ C64[sri]);
	vd = rotateright<u64>((vd ^ va), 16);
	vc = vc + vd;
	vb = rotateright<u64>((vb ^ vc), 11);

	m_v[a] = va;
	m_v[b] = vb;
	m_v[c] = vc;
	m_v[d] = vd;
}

void Blake64::handle()
{
	// Debugging
	//print_block();

	// INITIALIZE V
	m_v.fill(0);

	// Load m_h into m_v
	for (int i = 0; i < H_SIZE; i++)
		m_v[i] = m_h[i];

	// Load m_salt into m_v
	for (int i = 0; i < SALT_SIZE; i++)
		m_v[i + 8] = m_salt[i] ^ C64[i];

	// Load m_counter into m_v
	m_v[12] = m_counter ^ C64[4];
	m_v[13] = m_counter ^ C64[5];
	m_v[14] = 0x00 ^ C64[6];
	m_v[15] = 0x00 ^ C64[7];

	// ROUND FUNCTION
	for (int round = 0; round < 16; round++) {
		G(round, 0, 4, 8, 12, 0);
		G(round, 1, 5, 9, 13, 2);
		G(round, 2, 6, 10, 14, 4);
		G(round, 3, 7, 11, 15, 6);
		G(round, 0, 5, 10, 15, 8);
		G(round, 1, 6, 11, 12, 10);
		G(round, 2, 7, 8, 13, 12);
		G(round, 3, 4, 9, 14, 14);
	}

	// STORE RESULTS in m_h
	for (int i = 0; i < H_SIZE; i++) {
		m_h[i] = m_h[i] ^ m_salt[i % 4] ^ m_v[i] ^ m_v[i + 8];
	}

	// Clear m_block
	m_block.fill(0);
}

auto Blake64::output() const -> str
{
	str result = "";
	for (unsigned int i = 0; i < (m_type / 64); i++) {
		result += to_hex<u64>(m_h[i]);
	}
	return result;
}*/

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