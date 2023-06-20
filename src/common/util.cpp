#include <toycrypto/common/util.h>

#include <span>
#include <format>

std::string TC::hexdigest(const unsigned char* const buffer, const size_t buflen) {
    std::string result{};
    auto sp = std::span(buffer, buflen);

    result.reserve(buflen * 2 + 1);

    for (const unsigned char c : sp)
        result.append(std::format("{:02x}", c));

    return result;
}
