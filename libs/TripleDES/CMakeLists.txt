add_library(tripledes SHARED src/TRIPLEDES.cpp)
target_link_libraries(tripledes PUBLIC symmetric_context feistel_network des)
target_include_directories(tripledes PUBLIC include)