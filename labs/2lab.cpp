#include "primary_tests.h"

int main() {
    FermaTest ferma;
    std::cout << ferma.is_prime(3571, 0.99999999);
    return 0;
};