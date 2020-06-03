#include <cstdio>
#include <cstdint>
#include <common.hpp>

int main(int argc, char** argv) {
	if (rightrotate((uint32_t)0x12345678, 10) != (uint32_t)0x9e048d15) {
		printf("Test failed!\n");
		return 1;
	}
	
	if (rightrotate((uint32_t)0x1, 4) != (uint32_t)0x10000000) {
		printf("Test failed!\n");
		return 1;
	}
	
	if (rightrotate((uint32_t)0x88888888, 6) != (uint32_t)0x22222222) {
		printf("Test failed!\n");
		return 1;
	}
	
	if (rightrotate((uint32_t)0x8, 34) != (uint32_t)0x2) {
		printf("Test failed!\n");
		return 1;
	}
	
	printf("Test passed!\n");
	
	return 0;
}