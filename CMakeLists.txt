cmake_minimum_required(VERSION 3.16)

# This is far from finished, so I don't want to set a version number yet.
project(toycrypto VERSION 0.0.1)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(BUILD_SHARED_LIBS "Build shared libraries instead of static libraries" ON)

set(TC_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(TC_INC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(TC_HDR_DIR ${TC_INC_DIR}/toycrypto)

add_compile_definitions("DEBUG=$<CONFIG:Debug>")

add_subdirectory(${TC_SRC_DIR})

# Build the toycrypto library
add_library(toycrypto SHARED ${TC_SOURCES} ${TC_HEADERS})
add_library(toycrypto::toycrypto ALIAS toycrypto)
target_include_directories(toycrypto PUBLIC ${TC_INC_DIR})
set_target_properties(toycrypto PROPERTIES VERSION ${PROJECT_VERSION})

# The executable try.exe is only used for testing
add_executable(try ./src/test.cpp ./src/common/util.cpp)
target_include_directories(try PUBLIC ${TC_INC_DIR})
target_link_libraries(try PRIVATE toycrypto::toycrypto)

# Enable testing
enable_testing()
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tests)
