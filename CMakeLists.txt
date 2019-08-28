CMAKE_MINIMUM_REQUIRED(VERSION 2.7)

set (PROJECT_NAME auditutils-project)
PROJECT(${PROJECT_NAME})

set(CMAKE_SUPPRESS_REGENERATION true)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_EXTENSIONS OFF) # want c++11 not gnu++11

set(CMAKE_CXX_RELEASE_FLAGS "-DNDEBUG=1")

set(DEPDIR $ENV{DEPDIR})

if(WINDOWS)
  set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT /NODEFAULTLIB")
  set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MTd")
endif()

add_subdirectory(bench_hexparse)
add_subdirectory(bench_records)

# find dependencies
FIND_LIBRARY(GTEST_LIB gtest HINT ${DEPDIR}/lib )

if ("${GTEST_LIB}" STREQUAL "GTEST_LIB-NOTFOUND")
else()
  add_subdirectory(tests)
endif()

install(DIRECTORY include DESTINATION . FILES_MATCHING PATTERN "*.h" )
