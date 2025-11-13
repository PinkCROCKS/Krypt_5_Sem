add_library(deal src/DEAL.cpp)
target_link_libraries(deal PUBLIC bits_functions symmetric_context feistel_network des)
target_include_directories(deal PUBLIC include)