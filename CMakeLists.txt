cmake_minimum_required(VERSION 3.1 FATAL_ERROR)
project(ece VERSION 0.0.1 LANGUAGES C)

set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_EXTENSIONS OFF)
set(C_STANDARD_REQUIRED ON)

include(GNUInstallDirs)

find_package(OpenSSL 1.1.0 REQUIRED)

include_directories(include)
enable_testing()

set(ECE_SOURCES
  src/aesgcm-header.c
  src/base64url.c
  src/buffer.c
  src/decrypt.c)
add_library(ece ${ECE_SOURCES})
set_target_properties(ece PROPERTIES
  OUTPUT_NAME ece
  VERSION "${ECE_VERSION}")
target_include_directories(ece PUBLIC ${OPENSSL_INCLUDE_DIR})
target_link_libraries(ece PRIVATE ${OPENSSL_LIBRARIES})
if(DEFINED ENV{COVERAGE})
  target_compile_options(ece PUBLIC "-fprofile-arcs;-ftest-coverage")
  target_link_libraries(ece PUBLIC --coverage)
endif()

set(ECE_DECRYPT_SOURCES
  tools/ece-decrypt/ece-decrypt.c)
add_executable(ece-decrypt ${ECE_DECRYPT_SOURCES})
set_target_properties(ece-decrypt PROPERTIES EXCLUDE_FROM_ALL 1)
target_include_directories(ece-decrypt PUBLIC tools/ece-decrypt)
target_link_libraries(ece-decrypt ece)

set(ECE_TEST_SOURCES
  test/aes128gcm.c
  test/aesgcm.c
  test/base64url.c
  test/test.c)
add_executable(ece-test ${ECE_TEST_SOURCES})
set_target_properties(ece-test PROPERTIES EXCLUDE_FROM_ALL 1)
target_include_directories(ece-test PUBLIC test)
target_link_libraries(ece-test PUBLIC ece)
add_test(NAME ece-test COMMAND ece-test)
add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND})
add_dependencies(check ece-test)

if(MSVC)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /W4 /WX")
  target_compile_definitions(ece PUBLIC "_CRT_SECURE_NO_WARNINGS")
else()
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -pedantic -Werror")
endif()
