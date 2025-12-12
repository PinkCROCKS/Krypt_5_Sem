#include "../include/primary_tests.h"

double PrimeTest::is_prime(const BOOSTED_INT &number, double needed_probability) {
    size_t amount_of_operations = 0;
    while(!probability_complited(amount_of_operations, needed_probability)) {
        amount_of_operations++;
        auto u = to_string(number);
        auto iteration_result = iteration(number);
        if (iteration_result == Continue){
            continue;
        } else {
            return 0;
        }
    }
    return probability(amount_of_operations);
}

bool PrimeTest::probability_complited(size_t amount_of_operations, double needed_probability) {
    return probability(amount_of_operations) > needed_probability;
}

primeState FermaTest::iteration(const BOOSTED_INT &n) {
    auto a = generate_number_to_iteration(n);
    if (gcd(n, a) != 1) {
        return Composite;
    }
    if (fast_pow_mod(a, n - 1, n) != 1){
        return Composite;
    }
    return Continue;
}

BOOSTED_INT FermaTest::generate_number_to_iteration(const BOOSTED_INT &a) {
    boost::random::uniform_int_distribution<BOOSTED_INT> dist(2, a - 1);
    BOOSTED_INT result = dist(gen);
    while (checked_numbers.find(result) != checked_numbers.end()){
        result = dist(gen);
    }
    checked_numbers.insert(result);
    return result;
}

double FermaTest::probability(size_t amount_of_operations) {
    return 1.0 - 1.0 / pow(2, amount_of_operations);
}

FermaTest::FermaTest() {
    std::random_device rd;
    gen.seed(rd());
}

double SoloveiShtrassenaTest::probability(size_t amount_of_operations) {
    return 1.0 - 1.0 / pow(2, amount_of_operations);
}

BOOSTED_INT SoloveiShtrassenaTest::generate_number_to_iteration(const BOOSTED_INT &a) {
    boost::random::uniform_int_distribution<BOOSTED_INT> dist(2, a - 1);
    BOOSTED_INT result = dist(gen);
    while (checked_numbers.find(result) != checked_numbers.end()){
        result = dist(gen);
    }
    checked_numbers.insert(result);
    return result;
}

primeState SoloveiShtrassenaTest::iteration(const BOOSTED_INT &n) {
    auto a = generate_number_to_iteration(n);
    if (gcd(n, a) != 1) {
        return Composite;
    }
    auto temp= fast_pow_mod(a, (n - 1) / 2, n);
    auto jacobi = jakobi_symbol(a, n);
    if (jacobi == 1 && temp != 1){
        return Composite;
    }
    if (jacobi == -1 && temp != n - 1){
        return Composite;
    }
    if (jacobi == 0) {
        return Composite;
    }

    return Continue;
}

SoloveiShtrassenaTest::SoloveiShtrassenaTest() {
    std::random_device rd;
    gen.seed(rd());
}

MillerRabinaTest::MillerRabinaTest() {
    std::random_device rd;
    gen.seed(rd());
}

primeState MillerRabinaTest::iteration(const BOOSTED_INT &n) {
    BOOSTED_INT  t = n - 1;
    BOOSTED_INT s = 0;
    while(t % 2 == 0) {
        s++;
        t /= 2;
    }
    auto u = to_string(s);
    auto y = to_string(t);
    auto a = generate_number_to_iteration(n);
    auto x = fast_pow_mod(a, t, n);
    bool finish = false;
    if (x == 1 || x == n - 1) {
        return Continue;
    }
    for (size_t j = 1; j < (s - 1); j++){
        x = fast_pow_mod(x, 2, n);
        if (x == 1) {
            return Composite;
        }
        if ( x == (n - 1)) {
            return Continue;
        }
    }
    return Composite;
}

double MillerRabinaTest::probability(size_t amount_of_operations) {
    return 1.0 - 1.0 / pow(4, amount_of_operations);
}

BOOSTED_INT MillerRabinaTest::generate_number_to_iteration(const BOOSTED_INT &a) {
    boost::random::uniform_int_distribution<BOOSTED_INT> dist(2, a - 2);
    BOOSTED_INT result = dist(gen);
    while (checked_numbers.find(result) != checked_numbers.end()){
        result = dist(gen);
    }
    checked_numbers.insert(result);
    return result;
}
