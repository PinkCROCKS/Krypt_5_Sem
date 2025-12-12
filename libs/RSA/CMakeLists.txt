add_library(rsa src/RSA.cpp)
target_link_libraries(rsa PUBLIC number_functions primary_tests)
target_include_directories(rsa PUBLIC include)