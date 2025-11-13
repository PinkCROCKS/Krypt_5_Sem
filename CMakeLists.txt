cmake_minimum_required(VERSION 3.28.3)
project(1_Lab)

set(CMAKE_CXX_STANDARD 23)

add_compile_options(-O3)
add_executable(1_Lab main.cpp
        Byte.h
        SymmetricContext.h
        Feystel.h
        Byte.cpp
        Feystel.cpp
        DES.h
        DES.cpp
        DEAL.h
        DEAL.cpp)

add_executable(tests test.cpp TestSymmetricContext.cpp TestSymmetricContext.h
        Byte.h SymmetricContext.h
        Byte.cpp)

add_executable(testSymmetric SymmetricContext.h TestSymmetricContext.cpp
        TestSymmetricContext.h test.cpp Byte.cpp Byte.h)