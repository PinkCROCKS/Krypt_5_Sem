//
// Created by Ярослав on 18.12.2025.
//
#include "../libs/DIFFIE–HELLMAN/include/DIFFIE_HELLMAN.h"

using namespace Deffie_Helman;

int main() {
    auto base = generate_base(2048);
    auto a = generate_my_secret_number(base);
    auto b = generate_my_secret_number(base);
    auto parcel_from_a = send(a, base);
    auto parcel_from_b = send(b, base);
    auto key_a = generate_key(parcel_from_b, a, base);
    auto key_b = generate_key(parcel_from_a, b, base);
    std::cout << key_a << std::endl;
    std::cout << key_b << std::endl;
}