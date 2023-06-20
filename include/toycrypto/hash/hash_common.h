#pragma once

#ifndef TC_HASH_COMMON_H
#define TC_HASH_COMMON_H

#include <memory>
#include <concepts>
#include <string>
#include <toycrypto/internal/headerstuff.h>

extern "C++" {
    enum HashState {
        HASH_INIT,
        HASH_UPDATE,
        HASH_FINAL,
        HASH_DIGEST
    };

    template<typename T>
    concept x32or64 = std::is_integral<T>::value && (sizeof(T) == 4 || sizeof(T) == 8);

    class HashBase {
    public:
        TC_API virtual ~HashBase() = 0;

        TC_API virtual void reset() = 0;
        TC_API virtual void update(const char* buffer, size_t buflen) = 0;
        TC_API virtual void finalize() = 0;
        TC_API virtual void digest(unsigned char* output, size_t outlen) = 0;
    };

    class HashImpl : public HashBase {};

    class HashClass : public HashBase {
    public:
        TC_API virtual std::string hexdigest() = 0;
    };

}

#endif