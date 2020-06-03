#include <cstdio>
#include <string>
#include <sha.hpp>
//#include "common_test.hpp"

int main(int argc, char** argv) {
	//generate_test_file();
	std::string filename = argv[1];
	std::string expected = "7b097c746e512b04bae8a5d46329475646346c9ea6682b49b481fbae788cd11e4b763c8dd2d03173b71efa2dcac563bf";
	
	if (SHA::sha384_file(filename).compare(expected) != 0) {
		printf("Testing this file:\n%s\n\n", filename.c_str());
		printf("Got:\n%s\n\n", SHA::sha384_file(filename).c_str());
		printf("Expected:\n%s\n\n", expected.c_str());
		printf("Test failed\n");
		return 1;
	}

	printf("Test passed\n");

	return 0;
}