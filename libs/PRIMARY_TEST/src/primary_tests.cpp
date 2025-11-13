#include "../include/primary_tests.h"

double PrimeTest::is_prime(const BOOSTED_INT &number, double needed_probability) {
    size_t amount_of_operations = 0;
    while(!probability_complited(amount_of_operations, needed_probability)) {
        amount_of_operations++;
        auto iteration_result = iteration(number);
        if (iteration_result == Continue){
            continue;
        } else {
            return 0;
        }
    }
    return probability(amount_of_operations);
}

primeState FermaTest::iteration(const BOOSTED_INT &a) {
    auto n = generate_number_to_iteration(a);
    if (gcd(a, n) != 1) {
        return Composite;
    }
    if (fast_pow_mod(n, a - 1, a) != 1){
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

bool FermaTest::probability_complited(size_t amount_of_operations, double needed_probability) {
    return probability(amount_of_operations) > needed_probability;
}
