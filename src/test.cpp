#include <iostream>
#include <cstring>
#include <toycrypto/hash/sha1.h>

int main(int argc, char** argv) {
    typedef SHA1 algo;
    algo hfunc{};

    try {
        hfunc.update("Hello", 5);
        hfunc.finalize();
        std::string dgst = hfunc.hexdigest();
        printf("%s\n", dgst.data());
    } catch (std::exception err) {
        printf("Error: %s\n", err.what());
        return EXIT_FAILURE;
    }

	return EXIT_SUCCESS;
}
