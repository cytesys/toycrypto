#ifndef COMMON_HPP
#define COMMON_HPP

#include <cstdint>
#include <string>

using u8 = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;

constexpr u8 U8MAX = -1;
constexpr u16 U16MAX = -1;
constexpr u32 U32MAX = -1;
constexpr u64 U64MAX = -1;

// Modulus operator
int modu(int a, int b);

// Returns a hex character representing the lower nibble of the supplied byte.
char lookup_nibble(u8 byte);

// Generates a XOR mask as big endian (puts a specified byte value at the supplied byte offset).
template<typename T>
T xor_mask_be(u8 byte, size_t place) {
	return (T)(byte) << (((sizeof(T) - 1) - (place % sizeof(T))) * 8);
}

// Generates a XOR mask as little endian (puts a specified byte value at the supplied byte offset).
template<typename T>
T xor_mask_le(u8 byte, size_t place) {
	return (T)(byte) << ((place % sizeof(T)) * 8);
}

// Loads bytes from a buffer into a numeric type T as big endian.
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
		temp |= (u8)(buffer[offset + i]);
	}
	temp <<= (sizeof(T) - num) * 8;
	return temp;
}

// Loads bytes from a buffer into a numeric type T as little endian.
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
		temp |= (u8)(buffer[offset + (j--)]);
	}

	return temp;
}

// Rotates a numeric type T to the left.
template<typename T>
T rotateleft(T a, unsigned int num) {
	return ((a << (num % (sizeof(T) * 8))) | (a >> ((sizeof(T) * 8) - (num % (sizeof(T) * 8)))));
}

// Rotates a numeric type T to the right.
template<typename T>
T rotateright(T a, unsigned int num) {
	return rotateleft<T>(a, (sizeof(T) * 8) - (num % (sizeof(T) * 8)));
}

// Generates a hex string for the numeric type T.
template<typename T>
auto to_hex(T a, bool from_le = false) -> std::string {
	unsigned int i;
	std::string result = "";
	if (from_le) {
		for (i = (sizeof(T)); i > 0; i--) {
			u8 temp = (rotateleft<T>(a, i * 8) & 0xff);
			result += lookup_nibble((temp >> 4) & 0xf);
			result += lookup_nibble(temp & 0xf);
		}
	} else {
		for (i = 4; i <= (sizeof(T) * 8); i += 4) {
			result += lookup_nibble(rotateleft<T>(a, i) & 0xf);
		}
	}
	return result;
}

#endif
