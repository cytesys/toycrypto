#include <cstdio>
#include <string>
#include <sha.hpp>
//#include "common_test.hpp"

int main(int argc, char** argv) {
	//generate_test_file();
	std::string filename = argv[1];
	std::string expected = "550a415d19f913bc3b95039d91b3d827fce9de39e4fbda2e7787ef8a";
	
	if (SHA::sha512_224_file(filename).compare(expected) != 0) {
		printf("Testing this file:\n%s\n\n", filename.c_str());
		printf("Got:\n%s\n\n", SHA::sha512_224_file(filename).c_str());
		printf("Expected:\n%s\n\n", expected.c_str());
		printf("Test failed\n");
		return 1;
	}

	printf("Test passed\n");

	return 0;
}