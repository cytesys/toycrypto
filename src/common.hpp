#ifndef COMMON_HPP
#define COMMON_HPP

#include <cstdint>
#include <string>

using u8 = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;
using str = std::string;

constexpr unsigned int UIMAX = -1;
constexpr u8 U8MAX = -1;
constexpr u16 U16MAX = -1;
constexpr u32 U32MAX = -1;
constexpr u64 U64MAX = -1;

// Modulus operator
int modu(int, int);

// Returns a hex character for the selected nibble.
char lookup_nibble(u8);

// Generates a XOR mask big endian; Puts a specified byte value at the specified byte offset, big endian.
template<typename T>
T xor_mask_be(u8 byte, size_t place) {
	return (T)(byte) << (((sizeof(T) - 1) - (place % sizeof(T))) * 8);
}

// Generates a XOR mask little endian; Puts a specified byte value at the specified byte offset, little endian.
template<typename T>
T xor_mask_le(u8 byte, size_t place) {
	return (T)(byte) << ((place % sizeof(T)) * 8);
}

// Loads bytes from a buffer into a type T (u32 for example) big endian.
template<typename T>
T load_be(const char* buffer, unsigned int bufsize, unsigned int offset, unsigned int num = sizeof(T)) {
	T temp = 0;
	if (num > sizeof(T))
		num = sizeof(T);

	if (offset >= bufsize) {
		throw "Error in load_be: Offset is too large!";
	}

	if ((offset + num) > bufsize)
		throw "Error in load_be: Buffer overflow";

	for (unsigned int i = 0; i < num; i++) {
		temp <<= 8;
		temp |= buffer[offset + i];
	}
	temp <<= (sizeof(T) - num) * 8;
	return temp;
}

// Loads bytes from a buffer into a type T (u32 for example) little endian.
template<typename T>
T load_le(const char* buffer, unsigned int bufsize, unsigned int offset, unsigned int num = sizeof(T)) {
	T temp = 0;
	if (num > sizeof(T))
		num = sizeof(T);

	if (num == 0)
		return temp;

	if (offset >= bufsize) {
		throw "Error in load_le: Offset is too large!";
	}

	if ((offset + num) > bufsize)
		throw "Error in load_le: Buffer overflow";

	unsigned int j = num - 1;
	for (unsigned int i = 0; i < num; i++) {
		temp <<= 8;
		temp |= buffer[offset + (j--)];
	}
	return temp;
}

// Rotates a type T (u32 for example) to the left.
template<typename T>
T rotateleft(T a, unsigned int num) {
	return ((a << (num % (sizeof(T) * 8))) | (a >> ((sizeof(T) * 8) - (num % (sizeof(T) * 8)))));
}

// Rotates a type T (u32 for example) to the right.
template<typename T>
T rotateright(T a, unsigned int num) {
	return rotateleft<T>(a, (sizeof(T) * 8) - (num % (sizeof(T) * 8)));
}

// Generates a hex string for the selected value. Default is big endian.
template<typename T>
auto to_hex(T a, bool from_le = false) -> str {
	str result = "";
	if (from_le) {
		for (int i = (sizeof(T) - 1); i >= 0; i--) {
			u8 temp = (rotateleft<T>(a, (i + 1) * 8) & 0xff);
			result += lookup_nibble((temp >> 4) & 0xf);
			result += lookup_nibble(temp & 0xf);
		}
	} else {
		for (int i = 4; i <= (sizeof(T) * 8); i += 4) {
			result += lookup_nibble(rotateleft<T>(a, i) & 0xf);
		}
	}
	return result;
}

#endif
