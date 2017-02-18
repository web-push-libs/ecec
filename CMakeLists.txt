cmake_minimum_required(VERSION 3.1 FATAL_ERROR)
project(ece VERSION 0.0.1 LANGUAGES C)

set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_EXTENSIONS OFF)
set(C_STANDARD_REQUIRED ON)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -pedantic -Werror")

include(GNUInstallDirs)

find_package(OpenSSL 1.1.0 REQUIRED)

include_directories(include)

set(ECE_SOURCES
  src/aesgcm-header.c
  src/base64url.c
  src/ece.c)
add_library(ece ${ECE_SOURCES})
set_target_properties(ece PROPERTIES
  OUTPUT_NAME ece
  VERSION "${ECE_VERSION}")
target_include_directories(ece PUBLIC
  ${OPENSSL_INCLUDE_DIR})
target_link_libraries(ece ${OPENSSL_LIBRARIES})

set(ECE_DECRYPT_SOURCES
  tools/ece-decrypt/ece-decrypt.c)
add_executable(ece-decrypt ${ECE_DECRYPT_SOURCES})
set_target_properties(ece-decrypt PROPERTIES
  EXCLUDE_FROM_ALL 1)
target_include_directories(ece-decrypt PUBLIC
  tools/ece-decrypt)
target_link_libraries(ece-decrypt ece)
