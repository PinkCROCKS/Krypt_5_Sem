#ifndef CRYPT_DIFFIE_HELLMAN_H
#define CRYPT_DIFFIE_HELLMAN_H
#include "num_functions.h"
#include "primary_tests.h"
#include "boost/random/random_device.hpp"
#include "boost/random.hpp"

namespace Deffie_Helman{
    std::vector<BOOSTED_INT> generate_base(size_t p_size= 2048);
    BOOSTED_INT generate_my_secret_number(const std::vector<BOOSTED_INT>& data);
    BOOSTED_INT send(BOOSTED_INT secret_number, const std::vector<BOOSTED_INT>& key);
    BOOSTED_INT generate_key(BOOSTED_INT parsel, BOOSTED_INT secret_number, const std::vector<BOOSTED_INT> &key);
}



#endif //CRYPT_DIFFIE_HELLMAN_H
