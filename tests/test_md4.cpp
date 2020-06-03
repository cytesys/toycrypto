#include <cstdio>
#include <string>
#include <md.hpp>

int main(int argc, char** argv) {
	// Tests preparation
	const unsigned int test_num = 5;

	std::string test_strings[test_num] = {
		"",
		"The quick brown fox jumps over the lazy dog",
		"The quick brown fox jumps over the lazy cog",
		"p4ssword!abc[*f?)",
		"However they were incorrectly rounded to the nearest integer instead of being rounded to the nearest odd integer, with equilibrated proportions of zero and one bits."
	};

	std::string expected_hashes[test_num] = {
		"31d6cfe0d16ae931b73c59d7e0c089c0",
		"1bee69a46ba811185c194762abaeae90",
		"b86e130ce7028da59e672d56ad0113df",
		"d5c75c63e0957bd975c58a750a16519e",
		"999e0b4b552614faf1fa6a5e58d8b97b"
	};

	//Running the tests
	for (unsigned int i = 0; i < test_num; i++) {
		if (MD::md4(test_strings[i]).compare(expected_hashes[i]) != 0) {
			printf("Testing this:\n%s\n\n", test_strings[i].c_str());
            printf("Got:\n%s\n\n", MD::md4(test_strings[i]).c_str());
            printf("Expected:\n%s\n\n", expected_hashes[i].c_str());
            printf("Test failed\n");
            return 1;
		}
	}

	printf("Test passed\n");

	return 0;
}
