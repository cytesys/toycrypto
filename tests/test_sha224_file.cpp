#include <cstdio>
#include <string>
#include <sha.hpp>
#include "common_test.hpp"

int main(int argc, char** argv) {
	generate_test_file();
	std::string filename = "testfile.txt";
	std::string expected = "85e21930780474a8feef56f5bea9ab664eaf5cab967430c144a69636";
	
	if (SHA::sha224_file(filename).compare(expected) != 0) {
		printf("Testing this file:\n%s\n\n", filename.c_str());
		printf("Got:\n%s\n\n", SHA::sha224_file(filename).c_str());
		printf("Expected:\n%s\n\n", expected.c_str());
		printf("Test failed\n");
		return 1;
	}

	printf("Test passed\n");

	return 0;
}