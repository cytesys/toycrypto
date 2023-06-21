#include <iostream>

#include <toycrypto/hash/sha1.h>

int main(int argc, char** argv) {
    SHA1 test{};

    test.update("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 69);
    test.finalize();
    std::cout << test.hexdigest() << std::endl;

	return EXIT_SUCCESS;
}
