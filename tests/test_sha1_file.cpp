#include <cstdio>
#include <string>
#include <sha.hpp>
//#include "common_test.hpp"

int main(int argc, char** argv) {
	//generate_test_file();
	std::string filename = argv[1];
	std::string expected = "6fb253a833d7963b28f44d82e28cc3bdf3e6bf4b";
	
	if (SHA::sha1_file(filename).compare(expected) != 0) {
		printf("Testing this file:\n%s\n\n", filename.c_str());
		printf("Got:\n%s\n\n", SHA::sha1_file(filename).c_str());
		printf("Expected:\n%s\n\n", expected.c_str());
		printf("Test failed\n");

		return 1;
	}

	printf("Test passed\n");

	return 0;
}