#include <cstdio>
#include <cstdint>
#include <common.hpp>

int main(int argc, char** argv) {
	if (chars_to_uint32_t(0xab, 0xcd, 0x12, 0x34) != (uint32_t)0xabcd1234) {
		printf("Test failed!\n");
		return 1;
	}
	
	if (chars_to_uint32_t(0x22, 0x67, 0xaa, 0xbc) != (uint32_t)0x2267aabc) {
		printf("Test failed!\n");
		return 1;
	}
	
	if (chars_to_uint32_t(0x00, 0xff, 0xff, 0x00) != (uint32_t)0x00ffff00) {
		printf("Test failed!\n");
		return 1;
	}
	
	printf("Test passed!\n");
	
	return 0;
}