include(FetchContent)

FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG        release-1.12.1
)
FetchContent_MakeAvailable(googletest)
add_library(GTest::GTest INTERFACE IMPORTED)
target_link_libraries(GTest::GTest INTERFACE gtest_main)

add_executable(foo_test ${CMAKE_CURRENT_SOURCE_DIR}/foo_test.cpp)

target_link_libraries(foo_test PRIVATE GTest::GTest)

if (WIN32)
    add_custom_command(
        TARGET foo_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_RUNTIME_DLLS:foo_test> $<TARGET_FILE_DIR:foo_test>
        COMMAND_EXPAND_LISTS
    )
endif ()

add_test(foo_gtests foo_test)
