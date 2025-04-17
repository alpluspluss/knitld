cmake_minimum_required(VERSION 3.30)
project(knit)

set(CMAKE_CXX_STANDARD 20)

add_executable(knit
        src/macho/parser.cpp
        src/macho/reader.cpp
        src/macho/typeconv.cpp
        src/main.cpp
)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
