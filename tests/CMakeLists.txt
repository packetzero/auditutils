CMAKE_MINIMUM_REQUIRED(VERSION 2.7)

set (PROJECT_NAME auditutils-tests)
PROJECT(${PROJECT_NAME})

file(GLOB HDRS "../include/auditutils/*.h*" "*.h*")
file(GLOB SRCS "*.cpp")

include_directories(../include )
include_directories(.. $ENV{DEPDIR}/include )
include_directories(.. $ENV{GTESTDIR}/include )

set(CMAKE_EXE_LINKER_FLAGS "-L$ENV{DEPDIR}/lib")

add_executable (${PROJECT_NAME} ${SRCS} ${HDRS})

#TARGET_LINK_LIBRARIES(${PROJECT_NAME} auditutils )

target_link_libraries (${PROJECT_NAME} gtest)
