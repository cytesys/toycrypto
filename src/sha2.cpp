#include <array>
#include <exception>
#include <fstream>
#include "common.hpp"

// Constants
constexpr unsigned int CHUNK32_SIZE = 64;
constexpr unsigned int CHUNK64_SIZE = 128;
constexpr u8 PADDING_BYTE = 0x80;

// Constant values for H
constexpr unsigned int H_SIZE = 8;
constexpr std::array<u32, H_SIZE> H_SHA224 = {
	0xc1059ed8, 0x367cd507,
	0x3070dd17, 0xf70e5939,
	0xffc00b31, 0x68581511,
	0x64f98fa7, 0xbefa4fa4
};
constexpr std::array<u32, H_SIZE> H_SHA256 = {
	0x6a09e667, 0xbb67ae85,
	0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c,
	0x1f83d9ab, 0x5be0cd19
};
constexpr std::array<u64, H_SIZE> H_SHA384 = {
	0xcbbb9d5dc1059ed8, 0x629a292a367cd507,
	0x9159015a3070dd17, 0x152fecd8f70e5939,
	0x67332667ffc00b31, 0x8eb44a8768581511,
	0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4
};
constexpr std::array<u64, H_SIZE> H_SHA512 = {
	0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
	0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
	0x510e527fade682d1, 0x9b05688c2b3e6c1f,
	0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
};

// TODO: Generate these tables automatically for different subtypes
constexpr std::array<u64, H_SIZE> H_SHA512_224 = {
	0x8c3d37c819544da2, 0x73e1996689dcd4d6,
	0x1dfab7ae32ff9c82, 0x679dd514582f9fcf,
	0x0f6d2b697bd44da8, 0x77e36f7304c48942,
	0x3f9d85a86a1d36c8, 0x1112e6ad91d692a1
};
constexpr std::array<u64, H_SIZE> H_SHA512_256 = {
	0x22312194fc2bf72c, 0x9f555fa3c84c64c2,
	0x2393b86b6f53b151, 0x963877195940eabd,
	0x96283ee2a88effe3, 0xbe5e1e2553863992,
	0x2b0199fc2c85b8aa, 0x0eb72ddc81c52ca2
};

// Constants for K
constexpr unsigned int K32_SIZE = 64;
constexpr unsigned int K64_SIZE = 80;
constexpr std::array<u32, K32_SIZE> K32 = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe,	0x9bdc06a7,	0xc19bf174,
	0xe49b69c1,	0xefbe4786,	0x0fc19dc6,	0x240ca1cc,
	0x2de92c6f,	0x4a7484aa,	0x5cb0a9dc,	0x76f988da,
	0x983e5152,	0xa831c66d,	0xb00327c8,	0xbf597fc7,
	0xc6e00bf3,	0xd5a79147,	0x06ca6351,	0x14292967,
	0x27b70a85,	0x2e1b2138,	0x4d2c6dfc,	0x53380d13,
	0x650a7354,	0x766a0abb,	0x81c2c92e,	0x92722c85,
	0xa2bfe8a1,	0xa81a664b,	0xc24b8b70,	0xc76c51a3,
	0xd192e819,	0xd6990624,	0xf40e3585,	0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};
constexpr std::array<u64, K64_SIZE> K64 = {
	0x428a2f98d728ae22, 0x7137449123ef65cd,
	0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
	0x3956c25bf348b538, 0x59f111f1b605d019,
	0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
	0xd807aa98a3030242, 0x12835b0145706fbe,
	0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
	0x72be5d74f27b896f, 0x80deb1fe3b1696b1,
	0x9bdc06a725c71235, 0xc19bf174cf692694,
	0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
	0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
	0x2de92c6f592b0275, 0x4a7484aa6ea6e483,
	0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
	0x983e5152ee66dfab, 0xa831c66d2db43210,
	0xb00327c898fb213f, 0xbf597fc7beef0ee4,
	0xc6e00bf33da88fc2, 0xd5a79147930aa725,
	0x06ca6351e003826f, 0x142929670a0e6e70,
	0x27b70a8546d22ffc, 0x2e1b21385c26c926,
	0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
	0x650a73548baf63de, 0x766a0abb3c77b2a8,
	0x81c2c92e47edaee6, 0x92722c851482353b,
	0xa2bfe8a14cf10364, 0xa81a664bbc423001,
	0xc24b8b70d0f89791, 0xc76c51a30654be30,
	0xd192e819d6ef5218, 0xd69906245565a910,
	0xf40e35855771202a, 0x106aa07032bbd1b8,
	0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
	0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
	0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
	0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
	0x748f82ee5defb2fc, 0x78a5636f43172f60,
	0x84c87814a1f0ab72, 0x8cc702081a6439ec,
	0x90befffa23631e28, 0xa4506cebde82bde9,
	0xbef9a3f7b2c67915, 0xc67178f2e372532b,
	0xca273eceea26619c, 0xd186b8c721c0c207,
	0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
	0x06f067aa72176fba, 0x0a637dc5a2c898a6,
	0x113f9804bef90dae, 0x1b710b35131c471b,
	0x28db77f523047d84, 0x32caab7b40c72493,
	0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
	0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
	0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

// A class for the "32-bit" version of SHA2
class SHA2_32 {
public:
	explicit SHA2_32(int type);
	void load_string(const str &input);
	void load_file(const str &filename);
	auto output() const -> str;

private:
	std::array<u32, H_SIZE> m_h{ {} };
	std::array<u32, K32_SIZE> m_k = K32;
	std::array<u8, CHUNK32_SIZE> m_chunk{ {} };
	int m_type;

	void handle();
};

SHA2_32::SHA2_32(int type)
{
	switch(type) {
		case 224:
			m_h = H_SHA224;
			break;
		case 256:
			m_h = H_SHA256;
			break;
		default:
			throw std::invalid_argument("The SHA2 type supplied is invalid or not implemented.");
			break;
	}
	
	m_type = type;
}

void SHA2_32::load_file(const str &filename)
{
	size_t offset = 0;
	size_t length = 0;
	size_t index = 0;
	size_t filelen = 0;
	
	// Open file
	char* buffer = new char[CHUNK32_SIZE] {};
	std::ifstream infile(filename, std::ifstream::binary);
	
	if (!infile.good())
		throw std::ios_base::failure("Could not open file!");

	// Get infile length
	infile.seekg (0, infile.end);
    filelen = infile.tellg();
	length = filelen * 8;
    infile.seekg (0, infile.beg);
	
	// Handle each chunk of the input
	while ((filelen - offset) >= CHUNK32_SIZE) {
		infile.read(buffer, CHUNK32_SIZE);
		for (int i = 0; i < CHUNK32_SIZE; i++) {
			m_chunk.at(i) = buffer[i];
		}
		
		handle();
		offset += CHUNK32_SIZE;
	}
	
	// Load the rest of the input into buffer
	index = filelen % CHUNK32_SIZE;
	infile.read(buffer, index);
	for (int i = 0; i < index; i++) {
		m_chunk.at(i) = buffer[i];
	}
	
	// Apply padding
	m_chunk.at(index++) = PADDING_BYTE;
	if ((index + 8) > CHUNK32_SIZE) {
		/*
		If there isn't enough space for the message length
		then fill the rest of the chunk with zeroes, handle
		the chunk and continue.
		*/
		while (index < CHUNK32_SIZE) {
			m_chunk.at(index++) = 0x00;
		}
		handle();
		index = 0;
	}
	
	// Pad with zeroes
	while ((index + 8) < CHUNK32_SIZE)
		m_chunk.at(index++) = 0x00;
	
	// Append message length
	for (int i = 56; i >= 0; i-=8) {
		m_chunk.at(index++) = (length >> i) & 0xff;
	}
	
	// Handle the chunk
	handle();
}

void SHA2_32::load_string(const str &input)
{
	size_t length = input.length() * 8;
	size_t offset = 0;
	size_t index = 0;
	
	// Handle each chunk of the input
	while (input.length() - offset >= CHUNK32_SIZE) {
		for (int i = 0; i < CHUNK32_SIZE; i++) {
			m_chunk.at(i) = input[i + offset];
		}
		
		handle();
		offset += CHUNK32_SIZE;
	}
	
	// Load the rest of the input into chunk
	index = 0;
	for (int i = 0; i < (input.length() - offset); i++) {
		m_chunk.at(i) = input[i + offset];
		index++;
	}
	
	// Apply padding
	m_chunk.at(index++) = PADDING_BYTE;
	if ((index + 8) > CHUNK32_SIZE) {
		/*
		If there isn't enough space for the message length
		then fill the rest of the chunk with zeroes, handle
		the chunk and continue.
		*/
		while (index < CHUNK32_SIZE)
			m_chunk.at(index++) = 0x00;
		handle();
		index = 0;
	}
	
	// Pad with zeroes
	while ((index + sizeof(length)) < CHUNK32_SIZE)
		m_chunk.at(index++) = 0x00;
	
	// Append message length
	for (int i = 56; i >= 0; i-=8) {
		m_chunk.at(index++) = (length >> i) & 0xff;
	}
	
	// Handle the chunk
	handle();
}

void SHA2_32::handle()
{
	std::array<u32, K32_SIZE> words{{}};

	// Copy chunk into the 16 first words
	for (u64 j = 0; j < CHUNK32_SIZE / 4; j++) {
		words.at(j) = u8_to_u32(
			m_chunk.at((j * 4)),
			m_chunk.at((j * 4) + 1),
			m_chunk.at((j * 4) + 2),
			m_chunk.at((j * 4) + 3)
		);
	}

	// Extend the first 16 words to the remaining 48
	for (u64 j = CHUNK32_SIZE / 4; j < K32_SIZE; j++) {
		u32 s0 = rightrotate(words.at(j - 15), 7) ^ rightrotate(words.at(j - 15), 18) ^ (words.at(j - 15) >> 3);
		u32 s1 = rightrotate(words.at(j - 2), 17) ^ rightrotate(words.at(j - 2), 19) ^ (words.at(j - 2) >> 10);
		words.at(j) = words.at(j - 16) + s0 + words.at(j - 7) + s1;
	}

	u32 a = m_h.at(0);
	u32 b = m_h.at(1);
	u32 c = m_h.at(2);
	u32 d = m_h.at(3);
	u32 e = m_h.at(4);
	u32 f = m_h.at(5);
	u32 g = m_h.at(6);
	u32 h = m_h.at(7);

	// Main compression loop
	for (int j = 0; j < K32_SIZE; j++) {
		u32 s1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
		u32 ch = (e & f) ^ (~e & g);
		u32 temp1 = h + s1 + ch + m_k.at(j) + words.at(j);
		u32 s0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
		u32 maj = (a & b) ^ (a & c) ^ (b & c);
		u32 temp2 = s0 + maj;

		h = g;
		g = f;
		f = e;
		e = d + temp1;
		d = c;
		c = b;
		b = a;
		a = temp1 + temp2;

	}

	// Add the compressed chunk to the current hash value
	m_h.at(0) += a;
	m_h.at(1) += b;
	m_h.at(2) += c;
	m_h.at(3) += d;
	m_h.at(4) += e;
	m_h.at(5) += f;
	m_h.at(6) += g;
	m_h.at(7) += h;
}

auto SHA2_32::output() const -> str
{
	str result = "";

	for (int i = 0; i < (m_type / 32); i++) {
		result += u32_to_hex(m_h.at(i));
	}

	return result;
}

// A class for the "64-bit" version of SHA2
class SHA2_64 {
public:
	explicit SHA2_64(int type, int subtype);
	void load_string(const str &input);
	void load_file(const str &filename);
	auto output() const -> str;

private:
	std::array<u64, H_SIZE> m_h{ {} };
	std::array<u64, K64_SIZE> m_k = K64;
	std::array<u8, CHUNK64_SIZE> m_chunk{ {} };
	int m_type;
	int m_subtype;

	void handle();
};

SHA2_64::SHA2_64(int type, int subtype)
{
	switch(type) {
		case 384:
			m_h = H_SHA384;
			break;
		case 512:
			switch(subtype) {
				case 0:
					m_h = H_SHA512;
					break;
				case 224:
					m_h = H_SHA512_224;
					break;
				case 256:
					m_h = H_SHA512_256;
					break;
				default:
					throw std::invalid_argument("The SHA2 subtype supplied is invalid or not implemented");
			}
			break;
		default:
			throw std::invalid_argument("The SHA2 type supplied is invalid or not implemented");
			break;
	}
	
	m_type = type;
	m_subtype = subtype;
}

void SHA2_64::load_file(const str &filename)
{
	size_t offset = 0;
	size_t filelen = 0;
	size_t index = 0;
	size_t length = 0;
	
	// Open file
	char* buffer = new char[CHUNK64_SIZE] {};
	std::ifstream infile(filename, std::ifstream::binary);
	if (!infile.good())
		throw std::ios_base::failure("Could not open file!");
	
	// Get infile length
	infile.seekg (0, infile.end);
    filelen = infile.tellg();
	length = filelen * 8;
    infile.seekg (0, infile.beg);
	
	// Handle each chunk of the input
	while ((filelen - offset) >= CHUNK64_SIZE) {
		infile.read(buffer, CHUNK64_SIZE);
		for (int i = 0; i < CHUNK64_SIZE; i++)
			m_chunk.at(i) = buffer[i];
		
		handle();
		offset += CHUNK64_SIZE;
	}
	
	// Load the rest of the input into buffer
	index = filelen % CHUNK64_SIZE;
	infile.read(buffer, index);
	for (int i = 0; i < index; i++)
		m_chunk.at(i) = buffer[i];
	
	// Apply padding
	m_chunk.at(index++) = PADDING_BYTE;
	if ((index + 8) > CHUNK64_SIZE) {
		/*
		If there isn't enough space for the message length
		then fill the rest of the chunk with zeroes, handle
		the chunk and continue.
		*/
		while (index < CHUNK64_SIZE)
			m_chunk.at(index++) = 0x00;
		handle();
		index = 0;
	}
	
	// Pad with zeroes
	while ((index + 8) < CHUNK64_SIZE)
		m_chunk.at(index++) = 0x00;
	
	// Append message length
	for (int i = 56; i >= 0; i-=8)
		m_chunk.at(index++) = (length >> i) & 0xff;
	
	// Handle the chunk
	handle();
}

void SHA2_64::load_string(const str &input)
{
	// Initialize message length
	size_t length = input.length() * 8;
	size_t offset = 0;
	size_t index;
	
	// Handle each chunk of the input
	while (input.length() - offset >= CHUNK64_SIZE) {
		for (int i = 0; i < CHUNK64_SIZE; i++)
			m_chunk.at(i) = input[i + offset];
		
		handle();
		offset += CHUNK64_SIZE;
	}
	
	// Load the rest of the input into chunk
	index = 0;
	for (int i = 0; i < (input.length() - offset); i++) {
		m_chunk.at(i) = input[i + offset];
		index++;
	}
	
	// Apply padding
	m_chunk.at(index++) = PADDING_BYTE;
	if ((index + 8) > CHUNK64_SIZE) {
		/*
		If there isn't enough space for the message length
		then fill the rest of the chunk with zeroes, handle
		the chunk and continue.
		*/
		while (index < CHUNK64_SIZE)
			m_chunk.at(index++) = 0x00;
		handle();
		index = 0;
	}
	
	// Pad with zeroes
	while ((index + 8) < CHUNK64_SIZE)
		m_chunk.at(index++) = 0x00;
	
	// Append message length
	for (int i = 56; i >= 0; i-=8)
		m_chunk.at(index++) = (length >> i) & 0xff;
	
	// Handle the chunk
	handle();
}

void SHA2_64::handle()
{
	//_print_chunk();
	std::array<u64, K64_SIZE> words{{}};

	// Copy chunk into the 16 first words
	for (int j = 0; j < 16; j++) {
		words.at(j) = u8_to_u64(
			m_chunk.at((j * 8)),
			m_chunk.at((j * 8) + 1),
			m_chunk.at((j * 8) + 2),
			m_chunk.at((j * 8) + 3),
			m_chunk.at((j * 8) + 4),
			m_chunk.at((j * 8) + 5),
			m_chunk.at((j * 8) + 6),
			m_chunk.at((j * 8) + 7)
		);
	}

	// Extend the first 16 words to 80
	for (int j = 16; j < K64_SIZE; j++) {
		u64 s0 = rightrotate(words.at(j - 15), 1) ^ rightrotate(words.at(j - 15), 8) ^ (words.at(j - 15) >> 7);
		u64 s1 = rightrotate(words.at(j - 2), 19) ^ rightrotate(words.at(j - 2), 61) ^ (words.at(j - 2) >> 6);
		words.at(j) = words.at(j - 16) + s0 + words.at(j - 7) + s1;
	}

	u64 a = m_h.at(0);
	u64 b = m_h.at(1);
	u64 c = m_h.at(2);
	u64 d = m_h.at(3);
	u64 e = m_h.at(4);
	u64 f = m_h.at(5);
	u64 g = m_h.at(6);
	u64 h = m_h.at(7);

	// Main compression loop
	for (int j = 0; j < K64_SIZE; j++) {
		u64 s1 = rightrotate(e, 14) ^ rightrotate(e, 18) ^ rightrotate(e, 41);
		u64 ch = (e & f) ^ (~e & g);
		u64 temp1 = h + s1 + ch + m_k.at(j) + words.at(j);
		u64 s0 = rightrotate(a, 28) ^ rightrotate(a, 34) ^ rightrotate(a, 39);
		u64 maj = (a & b) ^ (a & c) ^ (b & c);
		u64 temp2 = s0 + maj;

		h = g;
		g = f;
		f = e;
		e = d + temp1;
		d = c;
		c = b;
		b = a;
		a = temp1 + temp2;

	}

	// Add the compressed chunk to the current hash value
	m_h.at(0) += a;
	m_h.at(1) += b;
	m_h.at(2) += c;
	m_h.at(3) += d;
	m_h.at(4) += e;
	m_h.at(5) += f;
	m_h.at(6) += g;
	m_h.at(7) += h;
}

auto SHA2_64::output() const -> str
{
	str result = "";
	int index;

	if (m_type == 512 && m_subtype != 0) {
		for (int i = 0; i < (m_subtype / 32); i++) {
			if (i % 2 == 0) {
				index = i / 2;
				result += u32_to_hex((m_h.at(index) & 0xffffffff00000000) >> 32);
			} else {
				result += u32_to_hex(m_h.at(index) & 0xffffffff);
			}
		}
	} else {
		for (int i = 0; i < (m_type / 32); i++) {
			if (i % 2 == 0) {
				index = i / 2;
				result += u32_to_hex((m_h.at(index) & 0xffffffff00000000) >> 32);
			} else {
				result += u32_to_hex(m_h.at(index) & 0xffffffff);
			}
		}
	}

	return result;
}

namespace SHA {
	auto sha224(const str &input) -> str
	{
		SHA2_32 inst(224);
		inst.load_string(input);
		return inst.output();
	}
	
	auto sha224_file(const str &filename) -> str
	{
		SHA2_32 inst(224);
		inst.load_file(filename);
		return inst.output();
	}
	
	auto sha256(const str &input) -> str
	{
		SHA2_32 inst(256);
		inst.load_string(input);
		return inst.output();
	}
	
	auto sha256_file(const str &filename) -> str
	{
		SHA2_32 inst(256);
		inst.load_file(filename);
		return inst.output();
	}
	
	auto sha384(const str &input) -> str
	{
		SHA2_64 inst(384, 0);
		inst.load_string(input);
		return inst.output();
	}
	
	auto sha384_file(const str &filename) -> str
	{
		SHA2_64 inst(384, 0);
		inst.load_file(filename);
		return inst.output();
	}
	
	auto sha512(const str &input) -> str
	{
		SHA2_64 inst(512, 0);
		inst.load_string(input);
		return inst.output();
	}
	
	auto sha512_file(const str &filename) -> str
	{
		SHA2_64 inst(512, 0);
		inst.load_file(filename);
		return inst.output();
	}
	
	auto sha512_224(const str &input) -> str
	{
		SHA2_64 inst(512, 224);
		inst.load_string(input);
		return inst.output();
	}
	
	auto sha512_224_file(const str &filename) -> str
	{
		SHA2_64 inst(512, 224);
		inst.load_file(filename);
		return inst.output();
	}
	
	auto sha512_256(const str &input) -> str
	{
		SHA2_64 inst(512, 256);
		inst.load_string(input);
		return inst.output();
	}
	
	auto sha512_256_file(const str &filename) -> str
	{
		SHA2_64 inst(512, 256);
		inst.load_file(filename);
		return inst.output();
	}
}