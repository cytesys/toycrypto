#include <iostream>

#include <toycrypto/hash/md5.h>

int main(int argc, char** argv) {
    MD5 test{};

    test.update("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 69);
    test.finalize();
    std::cout << test.hexdigest() << std::endl;

	return EXIT_SUCCESS;
}
