CMAKE_MINIMUM_REQUIRED(VERSION 2.7)

set (PROJECT_NAME bench_records)
PROJECT(${PROJECT_NAME})

file(GLOB HDRS "../include/*.h*" "*.h*")
file(GLOB SRCS "*.cpp")

include_directories(../include )
include_directories(.. $ENV{DEPDIR}/include )

set(CMAKE_EXE_LINKER_FLAGS "-L$ENV{DEPDIR}/lib")

add_executable (${PROJECT_NAME} ${SRCS} ${HDRS})
