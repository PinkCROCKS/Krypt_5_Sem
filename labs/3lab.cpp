//
// Created by Ярослав on 29.11.2025.
//

#include "../libs/RIJNDEL/include/RIJNDEL.h"
#include "../libs/GALUA_FUNCTIONS/include/Galua.h"

int main(){
    INFO data{std::byte{0x32}, std::byte{0x43}, std::byte{0xf6}, std::byte{0xa8},
              std::byte{0x88}, std::byte{0x5a}, std::byte{0x30}, std::byte{0x8d},
              std::byte{0x31}, std::byte{0x31}, std::byte{0x98}, std::byte{0xa2},
              std::byte{0xe0},std::byte{0x37}, std::byte{0x07}, std::byte{0x34}};
    INFO key = {
            std::byte{0x2B}, std::byte{0x7E}, std::byte{0x15}, std::byte{0x16},
            std::byte{0x28}, std::byte{0xAE}, std::byte{0xD2}, std::byte{0xA6},
            std::byte{0xAB}, std::byte{0xF7}, std::byte{0x15}, std::byte{0x88},
            std::byte{0x09}, std::byte{0xCF}, std::byte{0x4F}, std::byte{0x3C},
    };
//    RIJNDAELKeysGenerator generator;
//    auto o = generator.make_round_keys(key, 12);
//    print_numeric_key(o[0]);
//    INFO test1{std::byte{0x04}, std::byte{0xe0}, std::byte{8}, std::byte{12}, std::byte{0}, std::byte{4}, std::byte{8}, std::byte{12}};
//    INFO test2{std::byte{1}, std::byte{5}, std::byte{9}, std::byte{13}, std::byte{1}, std::byte{5}, std::byte{9}, std::byte{13}};
//    INFO test3{std::byte{2}, std::byte{6}, std::byte{10}, std::byte{14}, std::byte{2}, std::byte{6}, std::byte{10}, std::byte{14}};
//    INFO test4{std::byte{3}, std::byte{7}, std::byte{11}, std::byte{15}, std::byte{3}, std::byte{7}, std::byte{11}, std::byte{15}};
//    STATE state{test1, test2, test3, test4};

    GaloisFieldService galua;
//    galua.print_irreducible_polynoms();
    std::byte AESmod{0x1b};
//    INFO row0{std::byte{0xd4}, std::byte{0xe0}, std::byte{0xb8}, std::byte{0x1e}};
//    INFO row1{std::byte{0xbf}, std::byte{0xb4}, std::byte{0x41}, std::byte{0x27}};
//    INFO row2{std::byte{0x5d}, std::byte{0x52}, std::byte{0x11}, std::byte{0x98}};
//    INFO row3{std::byte{0x30}, std::byte{0xae}, std::byte{0xf1}, std::byte{0xe5}};
//    STATE state{row0, row1, row2, row3};
//    INFO key_row0{std::byte{0xa0}, std::byte{0x88}, std::byte{0x23}, std::byte{0x2a}};
//    INFO key_row1{std::byte{0xfa}, std::byte{0x54}, std::byte{0xa3}, std::byte{0x6c}};
//    INFO key_row2{std::byte{0xfe}, std::byte{0x2c}, std::byte{0x39}, std::byte{0x76}};
//    INFO key_row3{std::byte{0x17}, std::byte{0xb1}, std::byte{0x39}, std::byte{0x05}};
//    STATE key{key_row0, key_row1, key_row2, key_row3};
//    auto r = GaloisFieldService::mixColumns(state, AESmod);
//    print_state(r);
//    print_state(GaloisFieldService::addRoundKey(r, key));
//    SboxGenerator s(AESmod);
//    RconGenerator r(AESmod);
//    RIJNDAELKeysGenerator generator(std::make_shared<SboxGenerator>(s), std::make_shared<RconGenerator>(r));
//    generator.print_all_round_keys(generator.make_round_keys(key, 10, 16), 128);
    Rijndael r{16, AESmod, key};
    r.encrypt(data);
    return 0;
}