#include <cstdio>
#include <cstdint>
#include <common.hpp>

int main(int argc, char** argv) {
	if (rightrotate((uint64_t)0x1234567890abcedf, 10) != (uint64_t)0xb7c48d159e242af3) {
		printf("Test failed!\n");
		return 1;
	}
	
	if (rightrotate((uint64_t)0x8, 4) != (uint64_t)0x8000000000000000) {
		printf("Test failed!\n");
		return 1;
	}
	
	if (rightrotate((uint64_t)0x8888888888888888, 6) != (uint64_t)0x2222222222222222) {
		printf("Test failed!\n");
		return 1;
	}
	
	if (rightrotate((uint64_t)0x4, 65) != (uint64_t)0x2) {
		printf("Test failed!\n");
		return 1;
	}
	
	printf("Test passed!\n");
	
	return 0;
}