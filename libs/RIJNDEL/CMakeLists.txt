add_library(rijndel SHARED src/RIJNDEL.cpp)
target_link_libraries(rijndel PUBLIC bits_functions symmetric_context galua)
target_include_directories(rijndel PUBLIC include)