cmake_minimum_required(VERSION 3.16)

# This is far from finished, so I don't want to set a version number yet.
project(toycrypto
    VERSION 0.0.1
    DESCRIPTION "Experimental crypto library"
    HOMEPAGE_URL "https://github.com/cytesys/toycrypto"
    LANGUAGES CXX
)

option(BUILD_SHARED_LIBS "Build shared libraries instead of static libraries" ON)

set(TC_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(TC_INC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(TC_HDR_DIR ${TC_INC_DIR}/toycrypto)

add_library(toycrypto_compiler_flags INTERFACE)
target_compile_features(toycrypto_compiler_flags INTERFACE cxx_std_20)
add_compile_definitions(toycrypto_compiler_flags INTERFACE "DEBUG=$<CONFIG:Debug>")
add_compile_definitions(toycrypto_compiler_flags INTERFACE "SHAREDBUILD=$<BOOL:${BUILD_SHARED_LIBS}>")

add_subdirectory(${TC_SRC_DIR})

# Build the toycrypto library
add_library(toycrypto ${TC_SOURCES} ${TC_HEADERS})
target_include_directories(toycrypto PUBLIC ${TC_INC_DIR})
target_link_libraries(toycrypto PUBLIC toycrypto_compiler_flags)
set_target_properties(toycrypto PROPERTIES VERSION ${PROJECT_VERSION})

install(TARGETS toycrypto toycrypto_compiler_flags
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib)
install(DIRECTORY ${TC_HDR_DIR} DESTINATION include)

# The executable try.exe is only used for testing
add_executable(try ./src/test.cpp)
target_link_libraries(try PUBLIC toycrypto toycrypto_compiler_flags)
install(TARGETS try
        RUNTIME DESTINATION bin)

# Enable testing
enable_testing()
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tests)
