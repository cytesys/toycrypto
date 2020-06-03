#include <cstdio>
#include <cstdint>
#include <common.hpp>

int main(int argc, char** argv) {
	if (chars_to_uint64_t(0xab, 0xcd, 0x12, 0x34, 0x00, 0xaa, 0xbb, 0xcc) != (uint64_t)0xabcd123400aabbcc) {
		printf("Test failed!\n");
		return 1;
	}
	
	if (chars_to_uint64_t(0x22, 0x67, 0xaa, 0xbc, 0x44, 0x66, 0x88, 0xdd) != (uint64_t)0x2267aabc446688dd) {
		printf("Test failed!\n");
		return 1;
	}
	
	if (chars_to_uint64_t(0x00, 0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0x00) != (uint64_t)0x00ffff0000ffff00) {
		printf("Test failed!\n");
		return 1;
	}
	
	printf("Test passed!\n");
	
	return 0;
}