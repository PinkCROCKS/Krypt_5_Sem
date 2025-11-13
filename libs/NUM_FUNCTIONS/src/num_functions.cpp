#include "../include/num_functions.h"

BOOSTED_INT fast_pow_mod(const BOOSTED_INT &a, const BOOSTED_INT &deg, const BOOSTED_INT &mod) {
    // Проверка особых случаев
    if (mod == 0) {
        throw std::invalid_argument("Modulus cannot be zero");
    }
    if (mod == 1) {
        return 0;
    }
    if (deg == 0) {
        return 1;
    }
    if (a == 0) {
        return 0;
    }
    if (deg < 0) {
        throw std::invalid_argument("Negative exponent not supported");
    }

    BOOSTED_INT result = 1;
    BOOSTED_INT base = a % mod;
    BOOSTED_INT exponent = deg;

    while (exponent > 0) {
        if (exponent & 1) {
            result = (result * base) % mod;
        }
        base = (base * base) % mod;
        exponent >>= 1;
    }

    return result;
}

BOOSTED_INT gcd(const BOOSTED_INT &a, const BOOSTED_INT &b) {
    BOOSTED_INT x = a, y = b;
    while (y != 0) {
        BOOSTED_INT temp = y;
        y = x % y;
        x = temp;
    }
    return x;
}

std::vector<BOOSTED_INT> extensioned_Evklid_Algorithm(const BOOSTED_INT &a, const BOOSTED_INT &b) {
    BOOSTED_INT r0 = a, r1 = b;
    BOOSTED_INT x0 = 1, x1 = 0;
    BOOSTED_INT y0 = 0, y1 = 1;

    if (r0 < 0) {
        r0 = -r0;
        x0 = -x0;
        y0 = -y0;
    }
    while (true) {
        BOOSTED_INT q = r0 / r1;
        BOOSTED_INT r2 = r0 % r1;
        BOOSTED_INT x2 = x0 - q * x1;
        BOOSTED_INT y2 = y0 - q * y1;
        r0 = r1; r1 = r2;
        x0 = x1; x1 = x2;
        y0 = y1;
        y1 = y2;
        if (r1 == 0) {
            return {r0, x0, y0};
        }
    }
}

BOOSTED_INT legandr_symbol(const BOOSTED_INT& a, const BOOSTED_INT& p){
    if (p % 2 == 0) {
        throw std::invalid_argument("Incorrect p for legandr symbol");
    }
    if (a % p == 0){
        return 0;
    }
    return (fast_pow_mod(a, (p - 1) / 2, p) == 1) ? 1 : -1;
}

BOOSTED_INT jakobi_symbol(const BOOSTED_INT& a, const BOOSTED_INT& p){
    if (p % 2 == 0) {
        throw std::invalid_argument("Incorrect p for Jakobi symbol");
    }
    if (a == 1){
        return 1;
    }
    if (a < 0) {
        return jakobi_symbol(-a, p) * fast_pow_mod(-1, (p - 1) / 2, 0);
    }
    if (a % 2 == 0) {
        return jakobi_symbol(a / 2, p) * fast_pow_mod(-1, (p * p - 1) / 8, 0);
    }
    if (a < p){
        return jakobi_symbol(p, a) * fast_pow_mod(-1, (a - 1) * (p - 1) / 4, 0);
    } else {
        return jakobi_symbol(a % p, p);
    }
}

BOOSTED_INT jacobi_symbol_by_artemiy(const boost::multiprecision::cpp_int &a,
                                                                    const boost::multiprecision::cpp_int &n) {
    if (n <= 0 || n % 2 == 0) {
        throw std::invalid_argument("Jacobi symbol is defined only for positive odd n");
    }

    boost::multiprecision::cpp_int x = a % n;
    boost::multiprecision::cpp_int y = n;
    int j = 1;

    while (x != 0) {
        while (x % 2 == 0) {
            x /= 2;
            boost::multiprecision::cpp_int r = y % 8;
            if (r == 3 || r == 5) {
                j = -j;
            }
        }

        std::swap(x, y);

        if (x % 4 == 3 && y % 4 == 3) {
            j = -j;
        }

        x %= y;
    }

    return (y == 1) ? j : 0;
}
