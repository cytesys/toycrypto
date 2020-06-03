#include <cstdint>
#include <stdio.h>
#include <vector>
#include <inttypes.h>
#include <string>
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

namespace MD {
	std::string md4(std::string input) {
		std::vector<uint8_t> temp_buffer;
		std::vector<uint32_t> buffer;
		uint64_t ml = input.length() * 8;
		uint32_t X[16];
		
		// Initialize MD buffer
		uint32_t A = 0x67452301;
		uint32_t B = 0xefcdab89;
		uint32_t C = 0x98badcfe;
		uint32_t D = 0x10325476;
		
		for (uint8_t c : input) {
			temp_buffer.push_back(c);
		}
		
		// Append padding
		temp_buffer.push_back(0x80);
		
		if (input.length() < 8) {
			for (int i = 0; i < 8; i++) {
				temp_buffer.push_back(0x00);
			}
		}
		
		while (((temp_buffer.size() + 8) % 64) != 0) {
			temp_buffer.push_back(0x00);
		}
		
		// Append the message length
		ml = reverse_endianness(ml);
		for (int i = 1; i < 9; i++) {
			temp_buffer.push_back(leftrotate(ml, (i * 8)) & 0xff);
		}
		
		// Load words from temp_buffer to buffer
		for (int i = 0; i < temp_buffer.size(); i += 4) {
			buffer.push_back(
				chars_to_uint32_t(
					temp_buffer[i],
					temp_buffer[i + 1],
					temp_buffer[i + 2],
					temp_buffer[i + 3]
				)
			);
		}
		
		// Process message in 16-word blocks
		for (int i = 0; i < (buffer.size() / 16); i++) {
			for (int j = 0; j < 16; j++) {
				X[j] = reverse_endianness(buffer[(i * 16) + j]);
			}
			
			uint32_t AA = A;
			uint32_t BB = B;
			uint32_t CC = C;
			uint32_t DD = D;
			
			// Round 1
			AA = FF(AA, BB, CC, DD, X[0], 3);
			DD = FF(DD, AA, BB, CC, X[1], 7);
			CC = FF(CC, DD, AA, BB, X[2], 11);
			BB = FF(BB, CC, DD, AA, X[3], 19);
			AA = FF(AA, BB, CC, DD, X[4], 3);
			DD = FF(DD, AA, BB, CC, X[5], 7);
			CC = FF(CC, DD, AA, BB, X[6], 11);
			BB = FF(BB, CC, DD, AA, X[7], 19);
			AA = FF(AA, BB, CC, DD, X[8], 3);
			DD = FF(DD, AA, BB, CC, X[9], 7);
			CC = FF(CC, DD, AA, BB, X[10], 11);
			BB = FF(BB, CC, DD, AA, X[11], 19);
			AA = FF(AA, BB, CC, DD, X[12], 3);
			DD = FF(DD, AA, BB, CC, X[13], 7);
			CC = FF(CC, DD, AA, BB, X[14], 11);
			BB = FF(BB, CC, DD, AA, X[15], 19);
			
			// Round 2
			AA = GG(AA, BB, CC, DD, X[0], 3);
			DD = GG(DD, AA, BB, CC, X[4], 5);
			CC = GG(CC, DD, AA, BB, X[8], 9);
			BB = GG(BB, CC, DD, AA, X[12], 13);
			AA = GG(AA, BB, CC, DD, X[1], 3);
			DD = GG(DD, AA, BB, CC, X[5], 5);
			CC = GG(CC, DD, AA, BB, X[9], 9);
			BB = GG(BB, CC, DD, AA, X[13], 13);
			AA = GG(AA, BB, CC, DD, X[2], 3);
			DD = GG(DD, AA, BB, CC, X[6], 5);
			CC = GG(CC, DD, AA, BB, X[10], 9);
			BB = GG(BB, CC, DD, AA, X[14], 13);
			AA = GG(AA, BB, CC, DD, X[3], 3);
			DD = GG(DD, AA, BB, CC, X[7], 5);
			CC = GG(CC, DD, AA, BB, X[11], 9);
			BB = GG(BB, CC, DD, AA, X[15], 13);
			
			// Round 3
			AA = HH(AA, BB, CC, DD, X[0], 3);
			DD = HH(DD, AA, BB, CC, X[8], 9);
			CC = HH(CC, DD, AA, BB, X[4], 11);
			BB = HH(BB, CC, DD, AA, X[12], 15);
			AA = HH(AA, BB, CC, DD, X[2], 3);
			DD = HH(DD, AA, BB, CC, X[10], 9);
			CC = HH(CC, DD, AA, BB, X[6], 11);
			BB = HH(BB, CC, DD, AA, X[14], 15);
			AA = HH(AA, BB, CC, DD, X[1], 3);
			DD = HH(DD, AA, BB, CC, X[9], 9);
			CC = HH(CC, DD, AA, BB, X[5], 11);
			BB = HH(BB, CC, DD, AA, X[13], 15);
			AA = HH(AA, BB, CC, DD, X[3], 3);
			DD = HH(DD, AA, BB, CC, X[11], 9);
			CC = HH(CC, DD, AA, BB, X[7], 11);
			BB = HH(BB, CC, DD, AA, X[15], 15);
			
			A += AA;
			B += BB;
			C += CC;
			D += DD;
		}
		
		// Output
		char hash [33];
		sprintf(
			hash,
			"%08" PRIx32
			"%08" PRIx32
			"%08" PRIx32
			"%08" PRIx32,
			reverse_endianness(A),
			reverse_endianness(B),
			reverse_endianness(C),
			reverse_endianness(D)
		);
		
		return std::string(hash);
	}
}