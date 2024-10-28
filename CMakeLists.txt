cmake_minimum_required(VERSION 2.39)
project(streams C)

set(CMAKE_C_STANDARD 23)

add_executable(streams main.c)
target_link_libraries(streams libSDL2.so)
