#include <cstdio>
#include <string>
#include <sha.hpp>
//#include "common_test.hpp"

int main(int argc, char** argv) {
	//generate_test_file();
	std::string filename = argv[1];
	std::string expected = "a8580a61ddca2d14aa264a5651aa17ce3723470efe300c138a8cbd0abc5ccdf6";
	
	if (SHA::sha512_256_file(filename).compare(expected) != 0) {
		printf("Testing this file:\n%s\n\n", filename.c_str());
		printf("Got:\n%s\n\n", SHA::sha512_256_file(filename).c_str());
		printf("Expected:\n%s\n\n", expected.c_str());
		printf("Test failed\n");
		return 1;
	}

	printf("Test passed\n");

	return 0;
}