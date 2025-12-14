cmake_minimum_required(VERSION 3.22.1)
project(Crypt)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_SCAN_FOR_MODULES OFF)


# find_package(Boost REQUIRED COMPONENTS filesystem random system)

add_compile_options(-O3)

add_subdirectory(libs/BIT_FUNCTIONS)
add_subdirectory(libs/SymmetricContext)
add_subdirectory(libs/FEYSTEL)
add_subdirectory(libs/DES)
add_subdirectory(libs/DEAL)
add_subdirectory(libs/NUM_FUNCTIONS)
add_subdirectory(libs/PRIMARY_TEST)
add_subdirectory(libs/RSA)
add_subdirectory(libs/RIJNDEL)
add_subdirectory(libs/GALUA_FUNCTIONS)

add_executable(1lab "labs/main.cpp"
        libs/NUM_FUNCTIONS/src/num_functions.cpp
        libs/PRIMARY_TEST/src/primary_tests.cpp
        libs/RSA/src/RSA.cpp
        libs/RSA/include/RSA.h
        libs/RIJNDEL/include/RIJNDAEL.h
        libs/RIJNDEL/src/RIJNDAEL.cpp
        libs/GALUA_FUNCTIONS/src/Galua.cpp
        libs/GALUA_FUNCTIONS/include/Galua.h)
add_executable(2lab labs/2lab.cpp libs/NUM_FUNCTIONS/src/num_functions.cpp
        libs/PRIMARY_TEST/src/primary_tests.cpp)

add_executable(3lab libs/RIJNDEL/src/RIJNDAEL.cpp labs/3lab.cpp)

target_link_libraries(1lab deal bits_functions)
target_link_libraries(2lab number_functions primary_tests rsa bits_functions)
target_link_libraries(3lab rijndel bits_functions galua)