add_library(des SHARED src/DES.cpp)
target_link_libraries(des PUBLIC bits_functions symmetric_context feistel_network)
target_include_directories(des PUBLIC include)