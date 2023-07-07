#include <toycrypto/hash/md2.h>

constexpr std::string_view foo = "Hello now brown cow";

int main(int argc, char** argv) {
    MD2 h{};

    for (int i = 0; i < 100; i++)
        h.update("A", 1);
    h.finalize();

    std::cout << h.hexdigest() << std::endl;

    return EXIT_SUCCESS;
}
