#pragma once

#ifndef TC_COMMON_UTIL_H
#define TC_COMMON_UTIL_H

#include <string>
#include <toycrypto/internal/headerstuff.h>

namespace TC {

TC_API std::string hexdigest(const unsigned char* digest_buffer, size_t digest_len);

}

#endif
