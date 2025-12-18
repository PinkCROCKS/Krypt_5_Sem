add_library(diffie_helman SHARED src/DIFFIE_HELLMAN.cpp)
target_link_libraries(diffie_helman PUBLIC number_functions primary_tests Boost::random Boost::system)
target_include_directories(diffie_helman PUBLIC include)