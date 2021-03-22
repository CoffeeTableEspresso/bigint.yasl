cmake_minimum_required(VERSION 3.5.0)
project(bigint)

set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_C_STANDARD 99)

include_directories(.)

add_library(bigint SHARED
        bigint.c)

set_property(TARGET bigint PROPERTY POSITION_INDEPENDENT_CODE ON)

target_link_libraries(bigint yaslapi)
target_link_libraries(bigint tommath)
