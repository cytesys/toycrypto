add_subdirectory(common)
add_subdirectory(internal)
add_subdirectory(hash)

set(TC_SOURCES
    ${TC_COMMON_SOURCES}
    ${TC_INTERNAL_SOURCES}
    ${TC_HASH_SOURCES}

    PARENT_SCOPE
)

set(TC_HEADERS
    ${TC_COMMON_HEADERS}
    ${TC_INTERNAL_HEADERS}
    ${TC_HASH_HEADERS}

    PARENT_SCOPE
)
