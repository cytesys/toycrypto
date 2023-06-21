#include <toycrypto/common/util.h>

#include <array>
#include <span>

constexpr std::array<char, 16> hd = {
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
};

std::string TC::hexdigest(const unsigned char* const buffer, const size_t buflen) {
    std::string result{};
    auto sp = std::span(buffer, buflen);

    result.reserve(buflen * 2 + 1);

    for (const unsigned char c : sp) {
        result.push_back(hd.at((c & 0xf0) >> 4));
        result.push_back(hd.at(c & 0xf));
    }

    return result;
}
