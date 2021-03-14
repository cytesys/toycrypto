#include <array>
#include "common.hpp"


// Initial values
constexpr std::array<u32, 8> IV24 = {
	0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
	0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
};
constexpr std::array<u32, 8> IV32 = {
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};
constexpr std::array<u64, 8> IV64 = {
	0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
	0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
	0x510e527fade682d1, 0x9b05688c2b3e6c1f,
	0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
};
constexpr std::array<u64, 8> IV38 = {
	0xcbbb9d5dc1059ed8, 0x629a292a367cd507,
	0x9159015a3070dd17, 0x152fecd8f70e5939,
	0x67332667ffc00b31, 0x8eb44a8768581511,
	0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4
};

// Constants
constexpr std::array<u32, 16> C32 = {
	0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
	0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
	0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
	0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917
};

constexpr std::array<u64, 16> C64 = {
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
constexpr std::array<std::array<int, 16>, 10> SIGMA = { {
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

class Blake32 {
public:
	explicit Blake32(int type);
	void load_salt(const str& salt);
	void load_string(const str& input);
	auto output() const->str;
private:
	std::array<u32, 8> m_h{ {} };
	std::array<u32, 4> m_salt{ {0, 0, 0, 0} };
	std::array<u32, 16> m_block{ {} };
	std::array<u32, 16> m_v{ {} };
	u64 m_counter = 0;
	int m_type;

	void handle();
	void G(int r, int a, int b, int c, int d, int i);
};

Blake32::Blake32(int type) : m_type(type)
{
	if (type == 256) {
		m_h = IV32;
	}
	else if (type == 224) {
		m_h = IV24;
	}
	else {
		// We should technically never end up here
		throw "Not implemented!";
	}
}

void Blake32::load_salt(const str& salt) {
	if (salt.length() == 0)
		return;

	if (salt.length() > 16)
		throw "The salt can only be 16 bytes or less!";

	// Make an array named c_salt and fill it with zeroes
	std::array<u8, 16> c_salt{ {} };
	for (int i = 0; i < c_salt.size(); i++) {
		c_salt[i] = 0x00;
	}

	// Copy the 16 bytes of salt into c_salt.
	// If salt is shorter than 16 bytes, copy
	// all the bytes into c_salt.
	int salt_index = salt.length() - 1;
	for (int i = 15; i >= 0; i--) {
		c_salt.at(i) = salt[salt_index--];
		if (salt_index < 0) {
			break;
		}
	}

	// Copy c_salt into m_salt
	for (int i = 0; i < 4; i++) {
		m_salt.at(i) = u8_to_u32(
			c_salt.at((i * 4)),
			c_salt.at((i * 4) + 1),
			c_salt.at((i * 4) + 2),
			c_salt.at((i * 4) + 3)
		);
	}
}

void Blake32::load_string(const str& input)
{
	u64 length = input.length() * 8;
	size_t offset = 0;
	size_t index = 0;

	// Debugging
	/*printf("Salt: ");
	for (int i = 0; i < m_salt.size(); i++)
		printf("0x%lx, ", m_salt[i]);
	printf("\n");*/

	while (input.length() - offset >= 64) {
		// Load bytes from input into m_block
		for (int i = 0; i < 16; i++) {
			m_block.at(i) = u8_to_u32(
				input[(i * 4) + offset + 0],
				input[(i * 4) + offset + 1],
				input[(i * 4) + offset + 2],
				input[(i * 4) + offset + 3]
			);
		}

		m_counter += 512;
		handle();
		offset += 64;
	}

	// Load the remaining whole 32-bit words from input
	if ((input.length() - offset) >= 4) {
		int rem_bytes = (input.length() - offset) % 4;
		int rem_whole = (input.length() - offset - rem_bytes) / 4;
		size_t new_offset = offset;

		for (int i = 0; i < (rem_whole * 4); i += 4) {
			m_block.at(index++) = u8_to_u32(
				input[i + offset + 0],
				input[i + offset + 1],
				input[i + offset + 2],
				input[i + offset + 3]
			);

			new_offset += 4;
		}

		m_counter += (rem_whole * 32) + (rem_bytes * 8);
		offset = new_offset;
	}

	// Load the remaining bytes from input
	switch ((input.length() - offset)) {
	case 0:
		m_block.at(index++) = u8_to_u32(
			0x80,
			0x00,
			0x00,
			0x00
		);
		break;
	case 1:
		m_block.at(index++) = u8_to_u32(
			input[offset],
			0x80,
			0x00,
			0x00
		);
		break;
	case 2:
		m_block.at(index++) = u8_to_u32(
			input[offset],
			input[offset + 1],
			0x80,
			0x00
		);
		break;
	case 3:
		m_block.at(index++) = u8_to_u32(
			input[offset],
			input[offset + 1],
			input[offset + 2],
			0x80
		);
		break;
	default:
		break;
	}

	if (index + 2 > 16) {
		while (index < 16)
			m_block.at(index++) = 0x00;

		handle();
		index = 0;
	}

	// Pad with zeroes
	while (index + 2 < 16)
		m_block.at(index++) = 0x00;

	// A hacky way to add the last padding bit
	if (m_type == 256)
		m_block.at(index - 1) |= 1;

	// Append the message length
	m_block.at(index++) = leftrotate_u64(length, 32) & 0xffffffff;
	m_block.at(index++) = length & 0xffffffff;

	handle();
}

void Blake32::G(int r, int a, int b, int c, int d, int i)
{
	u32 va = m_v[a];
	u32 vb = m_v[b];
	u32 vc = m_v[c];
	u32 vd = m_v[d];

	int sri = SIGMA[r % 10][i];
	int sri1 = SIGMA[r % 10][i + 1];

	va = va + vb + (m_block[sri] ^ C32[sri1]);
	vd = rightrotate_u32((vd ^ va), 16);
	vc = vc + vd;
	vb = rightrotate_u32((vb ^ vc), 12);
	va = va + vb + (m_block[sri1] ^ C32[sri]);
	vd = rightrotate_u32((vd ^ va), 8);
	vc = vc + vd;
	vb = rightrotate_u32((vb ^ vc), 7);

	m_v[a] = va;
	m_v[b] = vb;
	m_v[c] = vc;
	m_v[d] = vd;
}

void Blake32::handle()
{
	// Debugging
	/*printf("Block:\n");
	for (int i = 0; i < m_block.size(); i++)
		printf("0x%lx,\n", m_block[i]);
	printf("\n");

	printf("Counter: 0x%llx\n", m_counter);

	printf("H:\n");
	for (int i = 0; i < m_h.size(); i++)
		printf("0x%lx,\n", m_h[i]);
	printf("\n");*/

	// INITIALIZE V
	for (int i = 0; i < m_v.size(); i++)
		m_v[i] = 0;

	// Load m_h into m_v
	for (int i = 0; i < m_h.size(); i++)
		m_v[i] = m_h[i];

	// Load m_salt into m_v
	for (int i = 0; i < m_salt.size(); i++)
		m_v[i + 8] = m_salt[i] ^ C32[i];

	// Load m_counter into m_v
	m_v[12] = (m_counter & 0xffffffff) ^ C32[4];
	m_v[13] = (m_counter & 0xffffffff) ^ C32[5];
	m_v[14] = (leftrotate_u64(m_counter, 32) & 0xffffffff) ^ C32[6];
	m_v[15] = (leftrotate_u64(m_counter, 32) & 0xffffffff) ^ C32[7];

	// Debugging
	/*printf("V:\n");
	for (int i = 0; i < m_v.size(); i++)
		printf("0x%lx,\n", m_v[i]);
	printf("\n");*/

	// ROUND FUNCTION
	for (int round = 0; round < 14; round++) {
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
	for (int i = 0; i < 8; i++) {
		m_h[i] = m_h[i] ^ m_salt[i % 4] ^ m_v[i] ^ m_v[i + 8];
	}
}

auto Blake32::output() const -> str
{
	str result = "";
	for (int i = 0; i < static_cast<int>(m_type / 32); i++) {
		result += u32_to_hex(m_h[i]);
	}
	return result;
}

class Blake64 {
public:
	explicit Blake64(int type);
	void load_salt(const str& salt);
	void load_string(const str& input);
	auto output() const->str;
private:
	std::array<u64, 8> m_h{ {} };
	std::array<u64, 4> m_salt{ {0, 0, 0, 0} };
	std::array<u64, 16> m_block{ {} };
	std::array<u64, 16> m_v{ {} };
	u64 m_counter = 0;
	int m_type;

	void handle();
	void G(int r, int a, int b, int c, int d, int i);
};

Blake64::Blake64(int type) : m_type(type)
{
	if (type == 512) {
		m_h = IV64;
	}
	else if (type == 384) {
		m_h = IV38;
	}
	else {
		// We should technically never end up here
		throw "Not implemented!";
	}
}

void Blake64::load_salt(const str& salt) {
	if (salt.length() == 0)
		return;

	if (salt.length() > 32)
		throw "The salt can only be 32 bytes or less!";

	// Make an array named c_salt and fill it with zeroes
	std::array<u8, 32> c_salt{ {} };
	for (int i = 0; i < c_salt.size(); i++) {
		c_salt[i] = 0x00;
	}

	// Copy the 32 bytes of salt into c_salt.
	// If salt is shorter than 32 bytes, copy
	// all the bytes into c_salt.
	int salt_index = salt.length() - 1;
	for (int i = 31; i >= 0; i--) {
		c_salt.at(i) = salt[salt_index--];
		if (salt_index < 0) {
			break;
		}
	}

	// Copy c_salt into m_salt
	for (int i = 0; i < 4; i++) {
		m_salt.at(i) = u8_to_u64(
			c_salt.at((i * 8)),
			c_salt.at((i * 8) + 1),
			c_salt.at((i * 8) + 2),
			c_salt.at((i * 8) + 3),
			c_salt.at((i * 8) + 4),
			c_salt.at((i * 8) + 5),
			c_salt.at((i * 8) + 6),
			c_salt.at((i * 8) + 7)
		);
	}
}

void Blake64::load_string(const str& input)
{
	u64 length = input.length() * 8;
	size_t offset = 0;
	size_t index = 0;

	// Debugging
	/*printf("Salt: ");
	for (int i = 0; i < m_salt.size(); i++)
		printf("0x%llx, ", m_salt[i]);
	printf("\n");*/

	while (input.length() - offset >= 128) {
		// Load bytes from input into m_block
		for (int i = 0; i < 16; i ++) {
			m_block.at(i) = u8_to_u64(
				input[(i * 8) + offset],
				input[(i * 8) + offset + 1],
				input[(i * 8) + offset + 2],
				input[(i * 8) + offset + 3],
				input[(i * 8) + offset + 4],
				input[(i * 8) + offset + 5],
				input[(i * 8) + offset + 6],
				input[(i * 8) + offset + 7]
			);
		}

		m_counter += 1024;
		handle();
		offset += 128;
	}

	// Load the remaining whole 64-bit words from input
	if ((input.length() - offset) >= 8) {
		int rem_bytes = (input.length() - offset) % 8;
		int rem_whole = (input.length() - offset - rem_bytes) / 8;
		size_t new_offset = offset;

		for (int i = 0; i < (rem_whole * 8); i += 8) {
			m_block.at(index++) = u8_to_u64(
				input[i + offset],
				input[i + offset + 1],
				input[i + offset + 2],
				input[i + offset + 3],
				input[i + offset + 4],
				input[i + offset + 5],
				input[i + offset + 6],
				input[i + offset + 7]
			);

			new_offset += 8;
		}

		m_counter += (rem_whole * 64) + (rem_bytes * 8);
		offset = new_offset;
	}

	// Load the remaining bytes from input
	switch ((input.length() - offset)) {
	case 0:
		m_block.at(index++) = u8_to_u64(
			0x80,
			0x00,
			0x00,
			0x00,
			0x00,
			0x00,
			0x00,
			0x00
		);
		break;
	case 1:
		m_block.at(index++) = u8_to_u64(
			input[offset],
			0x80,
			0x00,
			0x00,
			0x00,
			0x00,
			0x00,
			0x00
		);
		break;
	case 2:
		m_block.at(index++) = u8_to_u64(
			input[offset],
			input[offset + 1],
			0x80,
			0x00,
			0x00,
			0x00,
			0x00,
			0x00
		);
		break;
	case 3:
		m_block.at(index++) = u8_to_u64(
			input[offset],
			input[offset + 1],
			input[offset + 2],
			0x80,
			0x00,
			0x00,
			0x00,
			0x00
		);
		break;
	case 4:
		m_block.at(index++) = u8_to_u64(
			input[offset],
			input[offset + 1],
			input[offset + 2],
			input[offset + 3],
			0x80,
			0x00,
			0x00,
			0x00
		);
		break;
	case 5:
		m_block.at(index++) = u8_to_u64(
			input[offset],
			input[offset + 1],
			input[offset + 2],
			input[offset + 3],
			input[offset + 4],
			0x80,
			0x00,
			0x00
		);
		break;
	case 6:
		m_block.at(index++) = u8_to_u64(
			input[offset],
			input[offset + 1],
			input[offset + 2],
			input[offset + 3],
			input[offset + 4],
			input[offset + 5],
			0x80,
			0x00
		);
		break;
	case 7:
		m_block.at(index++) = u8_to_u64(
			input[offset],
			input[offset + 1],
			input[offset + 2],
			input[offset + 3],
			input[offset + 4],
			input[offset + 5],
			input[offset + 6],
			0x80
		);
		break;
	default:
		break;
	}

	if (index + 2 > 16) {
		while (index < 16)
			m_block.at(index++) = 0x00;

		handle();
		index = 0;
	}

	// Pad with zeroes
	while (index + 2 < 16)
		m_block.at(index++) = 0x00;

	// A hacky way to add the last padding bit
	if (m_type == 512)
		m_block.at(index - 1) |= 1;

	// Append the message length
	m_block.at(index++) = 0x00;
	m_block.at(index++) = length;

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
	vd = rightrotate_u64((vd ^ va), 32);
	vc = vc + vd;
	vb = rightrotate_u64((vb ^ vc), 25);
	va = va + vb + (m_block[sri1] ^ C64[sri]);
	vd = rightrotate_u64((vd ^ va), 16);
	vc = vc + vd;
	vb = rightrotate_u64((vb ^ vc), 11);

	m_v[a] = va;
	m_v[b] = vb;
	m_v[c] = vc;
	m_v[d] = vd;
}

void Blake64::handle()
{
	// Debugging
	/*printf("Block: \n");
	for (int i = 0; i < m_block.size(); i++)
		printf("0x%llx,\n", m_block[i]);
	printf("\n");

	printf("Counter: 0x%llx\n", m_counter);

	printf("H: \n");
	for (int i = 0; i < m_h.size(); i++)
		printf("0x%llx,\n", m_h[i]);
	printf("\n");*/

	// INITIALIZE V
	for (int i = 0; i < m_v.size(); i++)
		m_v[i] = 0;

	// Load m_h into m_v
	for (int i = 0; i < m_h.size(); i++)
		m_v[i] = m_h[i];

	// Load m_salt into m_v
	for (int i = 0; i < m_salt.size(); i++)
		m_v[i + 8] = m_salt[i] ^ C64[i];

	// Load m_counter into m_v
	m_v[12] = m_counter ^ C64[4];
	m_v[13] = m_counter ^ C64[5];
	m_v[14] = 0x00 ^ C64[6];
	m_v[15] = 0x00 ^ C64[7];

	// Debugging
	/*printf("V:\n");
	for (int i = 0; i < m_v.size(); i++)
		printf("0x%llx,\n", m_v[i]);
	printf("\n");*/

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
	for (int i = 0; i < 8; i++) {
		m_h[i] = m_h[i] ^ m_salt[i % 4] ^ m_v[i] ^ m_v[i + 8];
	}
}

auto Blake64::output() const -> str
{
	str result = "";
	for (int i = 0; i < static_cast<int>(m_type / 64); i++) {
		result += u32_to_hex(leftrotate_u64(m_h[i], 32) & 0xffffffff);
		result += u32_to_hex(m_h[i] & 0xffffffff);
	}
	return result;
}

namespace BLAKE {
	auto blake256(const str& input, const str& salt) -> str
	{
		Blake32 inst = Blake32(256);
		inst.load_salt(salt);
		inst.load_string(input);
		return inst.output();
	}

	auto blake224(const str& input, const str& salt) -> str
	{
		Blake32 inst = Blake32(224);
		inst.load_salt(salt);
		inst.load_string(input);
		return inst.output();
	}

	auto blake384(const str& input, const str& salt) -> str
	{
		Blake64 inst = Blake64(384);
		inst.load_salt(salt);
		inst.load_string(input);
		return inst.output();
	}

	auto blake512(const str& input, const str& salt) -> str
	{
		Blake64 inst = Blake64(512);
		inst.load_salt(salt);
		inst.load_string(input);
		return inst.output();
	}
}