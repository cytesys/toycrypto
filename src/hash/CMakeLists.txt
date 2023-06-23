set(TC_HASH_SOURCES
    hash_common.cpp
    blake.cpp
    blake2.cpp
    md2.cpp
    md4.cpp
    md5.cpp
    sha1.cpp
    sha2.cpp
    sha3.cpp
)

set(TC_HASH_HEADERS
    hash_common.h
    blake.h
    blake2.h
    md2.h
    md4.h
    md5.h
    sha1.h
    sha2.h
    sha3.h
)

list(TRANSFORM TC_HASH_SOURCES PREPEND "${CMAKE_CURRENT_SOURCE_DIR}/")
list(TRANSFORM TC_HASH_HEADERS PREPEND "${TC_HDR_DIR}/hash/")

set(TC_HASH_SOURCES ${TC_HASH_SOURCES} PARENT_SCOPE)
set(TC_HASH_HEADERS ${TC_HASH_HEADERS} PARENT_SCOPE)
