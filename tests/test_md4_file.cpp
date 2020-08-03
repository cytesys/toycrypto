#include <cstdio>
#include <string>
#include <md.hpp>

int main(int argc, char** argv) {
	std::string filename = argv[1];
	std::string expected = "3a9acba60badd438a54f6c9b9e4ebfb4";
	
	if (MD::md4_file(filename).compare(expected) != 0) {
		printf("Testing this file:\n%s\n\n", filename.c_str());
		printf("Got:\n%s\n\n", MD::md4_file(filename).c_str());
		printf("Expected:\n%s\n\n", expected.c_str());
		printf("Test failed\n");

		return 1;
	}

	printf("Test passed\n");

	return 0;
}