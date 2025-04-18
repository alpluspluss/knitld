cmake_minimum_required(VERSION 3.30)
project(knit)

set(CMAKE_CXX_STANDARD 20)

add_executable(knit
        src/dwarf.cpp
        src/dyld.cpp
        src/linker.cpp
        src/main.cpp
        src/parser.cpp
        src/reader.cpp
        src/typeconv.cpp
)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
