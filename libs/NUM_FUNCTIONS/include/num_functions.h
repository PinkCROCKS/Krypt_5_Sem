#ifndef CRYPT_NUM_FUNCTIONS_H
#define CRYPT_NUM_FUNCTIONS_H

#include <vector>
#include <boost/multiprecision/cpp_int.hpp>

using BOOSTED_INT = boost::multiprecision::cpp_int;

std::vector<BOOSTED_INT> extensioned_Evklid_Algorithm(const BOOSTED_INT& a,const BOOSTED_INT& b);
BOOSTED_INT gcd(const BOOSTED_INT& a,const BOOSTED_INT& b);
BOOSTED_INT fast_pow_mod(const BOOSTED_INT& a, const BOOSTED_INT& deg, const BOOSTED_INT& mod);
BOOSTED_INT jakobi_symbol(const BOOSTED_INT& a, const BOOSTED_INT& p);
static std::vector<BOOSTED_INT> finding_continued_simple_fractions(const BOOSTED_INT & u, const BOOSTED_INT & v);
static std::vector<std::pair<BOOSTED_INT, BOOSTED_INT>>
finding_convergent_series_from_continuous_simple_fraction(const std::vector<BOOSTED_INT> & factors);
static std::pair<BOOSTED_INT, BOOSTED_INT> solving_quadratic_equation(const BOOSTED_INT & a, const BOOSTED_INT & b,
                                                                      const BOOSTED_INT & c);

#endif //CRYPT_NUM_FUNCTIONS_H
