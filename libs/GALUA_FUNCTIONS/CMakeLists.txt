add_library(galua SHARED src/Galua.cpp)
target_link_libraries(galua PUBLIC bits_functions)
target_include_directories(galua PUBLIC include)