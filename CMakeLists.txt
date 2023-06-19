cmake_minimum_required(VERSION 3.16)

# This is far from finished, so I don't want to set a version number yet.
project(toycrypto VERSION 0.0.1)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(BUILD_SHARED_LIBS ON)

# Put everything in the same place for now
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})

set(TC_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(TC_INC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(TC_HDR_DIR ${TC_INC_DIR}/toycrypto)

add_compile_definitions("DEBUG=$<CONFIG:Debug>")

add_subdirectory(${TC_SRC_DIR})

# Build the toycrypto library
add_library(toycrypto SHARED ${TC_SOURCES} ${TC_HEADERS})
set_target_properties(toycrypto PROPERTIES VERSION ${PROJECT_VERSION})
target_include_directories(toycrypto PRIVATE ${TC_INC_DIR})

# The executable try.exe is only used for testing
add_executable(try ./src/test.cpp)
target_link_libraries(try PRIVATE toycrypto)
target_include_directories(try PRIVATE ${TC_INC_DIR})

# Enable testing
enable_testing()
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tests)
