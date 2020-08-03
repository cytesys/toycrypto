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
		"d41d8cd98f00b204e9800998ecf8427e",
		"9e107d9d372bb6826bd81d3542a419d6",
		"1055d3e698d289f2af8663725127bd4b",
		"48fb4f659161c4a13a53d023a3d4ebf4",
		"d3bf3ebaeb624f7528e1fabc760e82d5"
	};

	//Running the tests
	for (unsigned int i = 0; i < test_num; i++) {
		if (MD::md5(test_strings[i]).compare(expected_hashes[i]) != 0) {
			printf("Testing this:\n%s\n\n", test_strings[i].c_str());
            printf("Got:\n%s\n\n", MD::md5(test_strings[i]).c_str());
            printf("Expected:\n%s\n\n", expected_hashes[i].c_str());
            printf("Test failed\n");
            return 1;
		}
	}

	printf("Test passed\n");

	return 0;
}
