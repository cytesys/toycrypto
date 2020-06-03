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
		"8350e5a3e24c153df2275c9f80692773",
		"03d85a0d629d2c442e987525319fc471",
		"6b890c9292668cdbbfda00a4ebf31f05",
		"2cb4b44d017d40ae90be8c4612434bc2",
		"d107d6485c9106eddd331c61078ed3c4"
	};

	//Running the tests
	for (unsigned int i = 0; i < test_num; i++) {
		if (MD::md2(test_strings[i]).compare(expected_hashes[i]) != 0) {
			printf("Testing this:\n%s\n\n", test_strings[i].c_str());
            printf("Got:\n%s\n\n", MD::md2(test_strings[i]).c_str());
            printf("Expected:\n%s\n\n", expected_hashes[i].c_str());
            printf("Test failed\n");
            return 1;
		}
	}

	printf("Test passed\n");

	return 0;
}
