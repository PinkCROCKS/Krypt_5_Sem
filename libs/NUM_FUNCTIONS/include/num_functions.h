#ifndef CRYPT_NUM_FUNCTIONS_H
#define CRYPT_NUM_FUNCTIONS_H

#include <vector>
#include <boost/multiprecision/cpp_int.hpp>

using BOOSTED_INT = boost::multiprecision::cpp_int;

std::vector<BOOSTED_INT> extensioned_Evklid_Algorithm(const BOOSTED_INT& a,const BOOSTED_INT& b);
BOOSTED_INT gcd(const BOOSTED_INT& a,const BOOSTED_INT& b);
BOOSTED_INT fast_pow_mod(const BOOSTED_INT& a, const BOOSTED_INT& deg, const BOOSTED_INT& mod);
BOOSTED_INT jakobi_symbol(const BOOSTED_INT& a, const BOOSTED_INT& p);
BOOSTED_INT jacobi_symbol_by_artemiy(const boost::multiprecision::cpp_int &a,
                                     const boost::multiprecision::cpp_int &n);

#endif //CRYPT_NUM_FUNCTIONS_H
