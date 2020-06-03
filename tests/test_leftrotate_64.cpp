#include <cstdio>
#include <cstdint>
#include <common.hpp>

int main(int argc, char** argv) {
	if (leftrotate((uint64_t)0x1234567890abcedf, 10) != (uint64_t)0xd159e242af3b7c48) {
		printf("Test failed!\n");
		return 1;
	}
	
	if (leftrotate((uint64_t)0x8000000000000000, 4) != (uint64_t)0x8) {
		printf("Test failed!\n");
		return 1;
	}
	
	if (leftrotate((uint64_t)0x8888888888888888, 6) != (uint64_t)0x2222222222222222) {
		printf("Test failed!\n");
		return 1;
	}
	
	if (leftrotate((uint64_t)0x1, 65) != (uint64_t)0x2) {
		printf("Test failed!\n");
		return 1;
	}
	
	printf("Test passed!\n");
	
	return 0;
}