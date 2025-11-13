#ifndef CRYPT_PRIMARY_TESTS_H
#define CRYPT_PRIMARY_TESTS_H

#include "boost/random.hpp"
#include <unordered_set>
#include "random"
#include "../../NUM_FUNCTIONS/include/num_functions.h"

typedef enum primeState{
    Prime,
    Composite,
    Continue
};

class PrimeTestMethod{
public:
    virtual double is_prime(const BOOSTED_INT& number, double probability) = 0;
};

class PrimeTest : public PrimeTestMethod {
public:
    double is_prime(const BOOSTED_INT& number, double probability) override;
protected:
    std::unordered_set<BOOSTED_INT> checked_numbers;
    virtual bool probability_complited(size_t amount_of_operations, double needed_probability) = 0;
    virtual primeState iteration(const BOOSTED_INT& a) = 0;
    virtual double probability(size_t amount_of_operations) = 0;
    virtual BOOSTED_INT generate_number_to_iteration(const BOOSTED_INT& a) = 0;
};

class FermaTest : public PrimeTest{
private:
    boost::random::mt19937 gen;
public:
    FermaTest() {
        std::random_device rd;
        gen.seed(rd());
    }
    primeState iteration(const BOOSTED_INT &a) override;
    double probability(size_t amount_of_operations) override;
    virtual BOOSTED_INT generate_number_to_iteration(const BOOSTED_INT& a) override;
    virtual bool probability_complited(size_t amount_of_operations, double needed_probability) override;
};

#endif //CRYPT_PRIMARY_TESTS_H
