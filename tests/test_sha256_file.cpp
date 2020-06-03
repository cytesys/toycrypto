#include <cstdio>
#include <string>
#include <sha.hpp>
#include "common_test.hpp"

int main(int argc, char** argv) {
	generate_test_file();
	std::string filename = "testfile.txt";
	std::string expected = "53279bf49b1cc685ff246f7ca548f84945d82f8c70df26a84eac0a513aac79bb";
	
	if (SHA::sha256_file(filename).compare(expected) != 0) {
		printf("Testing this file:\n%s\n\n", filename.c_str());
		printf("Got:\n%s\n\n", SHA::sha256_file(filename).c_str());
		printf("Expected:\n%s\n\n", expected.c_str());
		printf("Test failed\n");
		return 1;
	}

	printf("Test passed\n");

	return 0;
}