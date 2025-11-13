cmake_minimum_required(VERSION 3.22.1)
project(Crypt)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_SCAN_FOR_MODULES OFF)


# find_package(Boost REQUIRED COMPONENTS filesystem random system)

#add_compile_options(-O3)

add_subdirectory(libs/BIT_FUNCTIONS)
add_subdirectory(libs/SymmetricContext)
add_subdirectory(libs/FEYSTEL)
add_subdirectory(libs/DES)
add_subdirectory(libs/DEAL)
add_subdirectory(libs/NUM_FUNCTIONS)
add_subdirectory(libs/PRIMARY_TEST)

add_executable(1lab "labs/main.cpp"
        libs/NUM_FUNCTIONS/src/num_functions.cpp
        libs/PRIMARY_TEST/src/primary_tests.cpp)
add_executable(2lab labs/2lab.cpp libs/NUM_FUNCTIONS/src/num_functions.cpp
        libs/PRIMARY_TEST/src/primary_tests.cpp)

target_link_libraries(1lab deal bits_functions)
target_link_libraries(2lab number_functions primary_tests)