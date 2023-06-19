#include <iostream>
#include <cstring>
#include <toycrypto/hash/sha3.h>

int main(int argc, char** argv) {
    typedef SHAKE128 algo;
    algo dgst(2048);

    const unsigned rbuflen = 256;
    const unsigned buflen = rbuflen * 2 + 1;

    char buffer[buflen];
//    unsigned char buf[rbuflen];

    char exp[buflen] = "f4202e3c5852f9182a0430fd8144f0a74b95e7417ecae17db0f8cfeed0e3e66eb5585ec6f86021cacf272c798bcf97d368b886b18fec3a571f096086a523717a3732d50db2b0b7998b4117ae66a761ccf1847a1616f4c07d5178d0d965f9feba351420f8bfb6f5ab9a0cb102568eabf3dfa4e22279f8082dce8143eb78235a1a54914ab71abb07f2f3648468370b9fbb071e074f1c030a4030225f40c39480339f3dc71d0f04f71326de1381674cc89e259e219927fae8ea2799a03da862a55afafe670957a2af3318d919d0a3358f3b891236d6a8e8d19999d1076b529968faefbd880d77bb300829dca87e9c8e4c28e0800ff37490a5bd8c36c0b0bdb2701a";

    try {
        for (unsigned i = 0; i < 1; i++) {
            dgst.update("The quick brown fox ", 20);
            dgst.update("jumps ", 6);
            dgst.update("over the lazy dog", 17);
            dgst.finalize();

            printf("Exp: %s\n", exp);

            dgst.hexdigest(buffer, buflen);
            printf("Got: %s\n", buffer);

            if (strcmp(buffer, exp) != 0) {
                fprintf(stderr, "Failed\n");
                return EXIT_FAILURE;
            }

//            dgst.digest(buf, rbuflen);
//            for (int i = 0; i < rbuflen; i++) {
//                fprintf(stdout, "%.02x", buf[i]);
//            }
//            fprintf(stdout, "\n");
            dgst.reset();
        }
    } catch (std::exception err) {
        fprintf(stderr, "Error: %s\n", err.what());
        return EXIT_FAILURE;
    }

	return EXIT_SUCCESS;
}
