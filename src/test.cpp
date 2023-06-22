#include <iostream>

#include <toycrypto/hash/md2.h>

int main(int argc, char** argv) {
    MD2 test{};

    test.update("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 69);
    test.finalize();
    std::cout << test.hexdigest() << std::endl;

	return EXIT_SUCCESS;
}
