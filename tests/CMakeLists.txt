# Fetch and build GTest
include(FetchContent)

FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG        release-1.12.1
)
FetchContent_MakeAvailable(googletest)
add_library(GTest::GTest INTERFACE IMPORTED)
target_link_libraries(GTest::GTest INTERFACE gtest_main)

# Add test sources
add_subdirectory(hash)
set(TC_TESTS
    ${TC_HASH_TESTS}
)

# Make all the tests
add_executable(unittests ${CMAKE_CURRENT_SOURCE_DIR}/unittests.cpp ${TC_TESTS})
target_include_directories(unittests PUBLIC ${TC_HDR_DIR})
target_link_libraries(unittests PRIVATE GTest::GTest toycrypto::toycrypto)

if (WIN32)
    add_custom_command(
        TARGET unittests POST_BUILD
        COMMAND ${CMAKE_COMMAND}
            -E copy_if_different
            $<TARGET_RUNTIME_DLLS:unittests>
            $<TARGET_FILE_DIR:unittests>
        COMMAND_EXPAND_LISTS
    )
endif ()

add_test(unittests_gtests unittests)
