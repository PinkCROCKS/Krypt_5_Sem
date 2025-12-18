cmake_minimum_required(VERSION 3.22.1)
project(Crypt)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_SCAN_FOR_MODULES OFF)


find_package(Boost REQUIRED COMPONENTS filesystem random system)

add_compile_options(-O3)

add_subdirectory(libs/BIT_FUNCTIONS)
add_subdirectory(libs/SymmetricContext)
add_subdirectory(libs/FEYSTEL)
add_subdirectory(libs/DES)
add_subdirectory(libs/DEAL)
add_subdirectory(libs/NUM_FUNCTIONS)
add_subdirectory(libs/PRIMARY_TEST)
add_subdirectory(libs/RSA)
add_subdirectory(libs/RIJNDAEL)
add_subdirectory(libs/GALUA_FUNCTIONS)
add_subdirectory(libs/DIFFIE–HELLMAN)
add_subdirectory(libs/RC4)
add_subdirectory(libs/RC6)

add_executable(1lab "labs/main.cpp"
        libs/NUM_FUNCTIONS/src/num_functions.cpp
        libs/PRIMARY_TEST/src/primary_tests.cpp
        libs/RSA/src/RSA.cpp
        libs/RSA/include/RSA.h
        libs/RIJNDAEL/include/RIJNDAEL.h
        libs/RIJNDAEL/src/RIJNDAEL.cpp
        libs/GALUA_FUNCTIONS/src/Galua.cpp
        libs/GALUA_FUNCTIONS/include/Galua.h
        libs/DIFFIE–HELLMAN/include/DIFFIE_HELLMAN.h)
add_executable(2lab labs/2lab.cpp libs/NUM_FUNCTIONS/src/num_functions.cpp
        libs/PRIMARY_TEST/src/primary_tests.cpp)

add_executable(3lab libs/RIJNDAEL/src/RIJNDAEL.cpp labs/3lab.cpp)
add_executable(4lab libs/DIFFIE–HELLMAN/src/DIFFIE_HELLMAN.cpp labs/4lab.cpp)
add_executable(5lab libs/RC4/src/RC4.cpp labs/5lab.cpp)
add_executable(6lab libs/RC6/src/RC6.cpp labs/6lab.cpp)

target_link_libraries(1lab deal bits_functions)
target_link_libraries(2lab number_functions primary_tests rsa bits_functions)
target_link_libraries(3lab rijndel bits_functions galua)
target_link_libraries(4lab diffie_helman number_functions)
target_link_libraries(5lab rc4)
target_link_libraries(6lab rc6 bits_functions feistel_network number_functions)