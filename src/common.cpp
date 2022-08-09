#include "common.hpp"

constexpr char NIBBLES[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

int modu(int a, int b) {
	return (a % b + b) % b;
}

char lookup_nibble(u8 a) {
	return NIBBLES[a & 0xf];
}