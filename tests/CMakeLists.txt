set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/tests)
set(CTEST_BINARY_DIRECTORY ${PROJECT_BINARY_DIR}/tests)

file(GLOB files "test_*.cpp")

foreach(file ${files})
	string(REGEX REPLACE "(^.*/|\\.[^.]*$)" "" file_without_ext ${file})
	add_executable(${file_without_ext} ${file} common_test.hpp common_test.cpp)
	target_link_libraries(${file_without_ext} cryptotest)
	
	if(${file_without_ext} MATCHES "_file$")
		add_test(${file_without_ext} ${file_without_ext} ${PROJECT_SOURCE_DIR}/tests/testfile.txt)
	else()
		add_test(${file_without_ext} ${file_without_ext})
	endif()
	
	set_tests_properties(${file_without_ext}
		PROPERTIES
		PASS_REGULAR_EXPRESSION "Test passed")
	set_tests_properties(${file_without_ext}
		PROPERTIES
		FAIL_REGULAR_EXPRESSION "(Exception|Test failed)")
	set_tests_properties(${file_without_ext}
		PROPERTIES
		TIMEOUT 120)
	
	add_custom_command(
		TARGET ${file_without_ext}
		COMMENT "Run tests"
		POST_BUILD 
		WORKING_DIRECTORY ${PROJECT_BINARY_DIR}/tests
		COMMAND ${CMAKE_CTEST_COMMAND} -R "\^${file_without_ext}\$" --output-on-failures
	)
endforeach()
