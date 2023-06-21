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
    hash/hash_common.h
    internal/hashbase.h
    hash/blake.h
    hash/blake2.h
    hash/md2.h
    hash/md4.h
    hash/md5.h
    hash/sha1.h
    hash/sha2.h
    hash/sha3.h
)

list(TRANSFORM TC_HASH_SOURCES PREPEND "${CMAKE_CURRENT_SOURCE_DIR}/")
list(TRANSFORM TC_HASH_HEADERS PREPEND "${TC_HDR_DIR}/")

set(TC_HASH_SOURCES ${TC_HASH_SOURCES} PARENT_SCOPE)
set(TC_HASH_HEADERS ${TC_HASH_HEADERS} PARENT_SCOPE)
