#include <cstring>
#include <sha.hpp>
#include <md.hpp>

int main(int argc, char** argv) {
	if (argc > 2) {
		if (strcmp(argv[1], "sha0") == 0) {
			printf("%s\n", SHA::sha0(argv[2]).c_str());
		} else if (strcmp(argv[1], "sha0_file") == 0) {
			printf("%s\n", SHA::sha0_file(argv[2]).c_str());
		} else if (strcmp(argv[1], "sha1") == 0) {
			printf("%s\n", SHA::sha1(argv[2]).c_str());
		} else if (strcmp(argv[1], "sha1_file") == 0) {
			printf("%s\n", SHA::sha1_file(argv[2]).c_str());
		} else if (strcmp(argv[1], "sha224") == 0) {
			printf("%s\n", SHA::sha224(argv[2]).c_str());
		} else if (strcmp(argv[1], "sha224_file") == 0) {
			printf("%s\n", SHA::sha224_file(argv[2]).c_str());
		} else if (strcmp(argv[1], "sha256") == 0) {
			printf("%s\n", SHA::sha256(argv[2]).c_str());
		} else if (strcmp(argv[1], "sha256_file") == 0) {
			printf("%s\n", SHA::sha256_file(argv[2]).c_str());
		} else if (strcmp(argv[1], "sha384") == 0) {
			printf("%s\n", SHA::sha384(argv[2]).c_str());
		} else if (strcmp(argv[1], "sha384_file") == 0) {
			printf("%s\n", SHA::sha384_file(argv[2]).c_str());
		} else if (strcmp(argv[1], "sha512") == 0) {
			printf("%s\n", SHA::sha512(argv[2]).c_str());
		} else if (strcmp(argv[1], "sha512_file") == 0) {
			printf("%s\n", SHA::sha512_file(argv[2]).c_str());
		} else if (strcmp(argv[1], "sha512/224") == 0) {
			printf("%s\n", SHA::sha512_224(argv[2]).c_str());
		} else if (strcmp(argv[1], "sha512/224_file") == 0) {
			printf("%s\n", SHA::sha512_224_file(argv[2]).c_str());
		} else if (strcmp(argv[1], "sha512/256") == 0) {
			printf("%s\n", SHA::sha512_256(argv[2]).c_str());
		} else if (strcmp(argv[1], "sha512/256_file") == 0) {
			printf("%s\n", SHA::sha512_256_file(argv[2]).c_str());
		} else if (strcmp(argv[1], "shake128") == 0) {
			if (argc > 3) {
				printf("%s\n", SHA::shake128(argv[2], atoi(argv[3])).c_str());
			} else {
				printf("Error: You must provide an output length for shake128!\n");
				return 1;
			}
		} else if (strcmp(argv[1], "shake256") == 0) {
			if (argc > 3) {
				printf("%s\n", SHA::shake256(argv[2], atoi(argv[3])).c_str());
			} else {
				printf("Error: You must provide an output length for shake256!\n");
				return 1;
			}
		} else if (strcmp(argv[1], "sha3-224") == 0) {
			printf("%s\n", SHA::sha3_224(argv[2]).c_str());
		} else if (strcmp(argv[1], "sha3-256") == 0) {
			printf("%s\n", SHA::sha3_256(argv[2]).c_str());
		} else if (strcmp(argv[1], "sha3-384") == 0) {
			printf("%s\n", SHA::sha3_384(argv[2]).c_str());
		} else if (strcmp(argv[1], "sha3-512") == 0) {
			printf("%s\n", SHA::sha3_512(argv[2]).c_str());
		} else if (strcmp(argv[1], "md2") == 0) {
			printf("%s\n", MD::md2(argv[2]).c_str());
		} else if (strcmp(argv[1], "md4") == 0) {
			printf("%s\n", MD::md4(argv[2]).c_str());
		} else {
			printf("Error: The method \"%s\" is not implemented!\n", argv[1]);
			return 1;
		}
	} else {
		printf("Usage: <hash_method> <string_to_be_hashed> [output_length]\n");
	}

	return 0;
}
