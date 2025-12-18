add_library(rc6 SHARED src/RC6.cpp
        src/RC6_from_igorek.cpp
        include/RC6_from_igorek.h)
target_link_libraries(rc6 PUBLIC bits_functions feistel_network Boost::random Boost::system)
target_include_directories(rc6 PUBLIC include)