set(TC_INTERNAL_SOURCES
    hashbase.cpp
)

set(TC_INTERNAL_HEADERS
    common.h
    hashbase.h
    headerstuff.h
)

list(TRANSFORM TC_INTERNAL_SOURCES PREPEND "${CMAKE_CURRENT_SOURCE_DIR}/")
list(TRANSFORM TC_INTERNAL_HEADERS PREPEND "${TC_HDR_DIR}/internal/")

set(TC_INTERNAL_SOURCES ${TC_INTERNAL_SOURCES} PARENT_SCOPE)
set(TC_INTERNAL_HEADERS ${TC_INTERNAL_HEADERS} PARENT_SCOPE)
