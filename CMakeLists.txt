cmake_minimum_required(VERSION 3.16)
project(novek C)

set(CMAKE_C_STANDARD 11)


add_executable(novek main.c)
target_link_libraries(novek z)
