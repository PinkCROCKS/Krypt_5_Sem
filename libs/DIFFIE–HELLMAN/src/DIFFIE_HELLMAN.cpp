//
// Created by Ярослав on 18.12.2025.
//
#include "../include/DIFFIE_HELLMAN.h"

std::vector<BOOSTED_INT> Deffie_Helman::generate_base(size_t p_size) {
    MillerRabinaTest test;
    BOOSTED_INT g = 2;
    boost::random::random_device rand_device;
    boost::random::uniform_int_distribution<boost::multiprecision::cpp_int> dist(boost::multiprecision::cpp_int{1} << (p_size - 2), boost::multiprecision::cpp_int{1} << (p_size - 1));
    BOOSTED_INT q = dist(rand_device);
    BOOSTED_INT p_temp = 0;
    while(true) {
        p_temp = 2 * q + 1;;
        if(!test.is_prime(p_temp, 0.99)) {
            q = dist(rand_device);
        } else {
            return {g, p_temp};
        }
    }
}

BOOSTED_INT Deffie_Helman::generate_my_secret_number(const std::vector<BOOSTED_INT>& key) {
    auto g = key[0];
    auto p = key[1];
    boost::random::random_device rand_device;
    boost::random::uniform_int_distribution<boost::multiprecision::cpp_int> dist_a(2, p / 2 - 1);
    return fast_pow_mod(g, dist_a(rand_device), p);
}

BOOSTED_INT Deffie_Helman::send(BOOSTED_INT secret_number, const std::vector<BOOSTED_INT>& key) {
    auto g = key[0];
    auto p = key[1];
    return fast_pow_mod(g, secret_number, p);
}

BOOSTED_INT Deffie_Helman::generate_key(BOOSTED_INT parsel, BOOSTED_INT secret_number, const std::vector<BOOSTED_INT> &key) {
    auto g = key[0];
    auto p = key[1];
    return fast_pow_mod(parsel, secret_number, p);
}
