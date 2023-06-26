#pragma once

#ifndef TC_HASH_COMMON_H
#define TC_HASH_COMMON_H

#include <memory>
#include <concepts>
#include <string>
#include <toycrypto/internal/headerstuff.h>

extern "C++" {

template<typename T>
concept UTYPE = std::is_integral<T>::value && std::is_unsigned<T>::value;

enum HashEnum {
    HASH_NOT_READY,
    HASH_INIT,
    HASH_UPDATE,
    HASH_FINAL,
    HASH_DIGEST
};

class HashAPI {
public:
    TC_API virtual ~HashAPI() = 0;

    TC_API virtual void reset() = 0;

    TC_API virtual void update(const char* input, size_t input_len) = 0;

    TC_API virtual void finalize() = 0;

    TC_API virtual void digest(unsigned char* outbuf, size_t outbuf_len = 0) = 0;

    TC_API virtual std::string hexdigest(size_t length = 0) = 0;
};

}

#endif
