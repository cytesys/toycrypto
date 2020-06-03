#include <cstdio>
#include <string>
#include <sha.hpp>
//#include "common_test.hpp"

int main(int argc, char** argv) {
	//generate_test_file();
	std::string filename = argv[1];
	std::string expected = "cc3a7f842a35056dfdfb165827fa8694382da28564ba69634ea60afa0a17d4feed670cd55444ae2ca72c4002767b01df5868f8ebf54de3fd2b78b66a26ea41de";
	
	if (SHA::sha512_file(filename).compare(expected) != 0) {
		printf("Testing this file:\n%s\n\n", filename.c_str());
		printf("Got:\n%s\n\n", SHA::sha512_file(filename).c_str());
		printf("Expected:\n%s\n\n", expected.c_str());
		printf("Test failed\n");
		return 1;
	}

	printf("Test passed\n");

	return 0;
}