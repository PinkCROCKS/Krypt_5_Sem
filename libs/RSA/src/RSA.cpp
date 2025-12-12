#include <optional>
#include <fstream>
#include "../include/RSA.h"

RSAKeyGenerator::RSAKeyGenerator(Ptests prime_test, double needed_probability, size_t bit_length) : min_probability(needed_probability), length(bit_length) {
    if (prime_test == fermaTest) {
        test = std::make_shared<FermaTest>();
    } else if (prime_test == soloveyShyrassenaTest){
        test = std::make_shared<SoloveiShtrassenaTest>();
    } else {
        test = std::make_shared<MillerRabinaTest>();
    }
}

BOOSTED_INT RSAKeyGenerator::generate_random() {
    boost::random::uniform_int_distribution<BOOSTED_INT> dist(BOOSTED_INT(1) << (length - 1), (BOOSTED_INT(1) << length) - 1);
    BOOSTED_INT result = dist(gen);
    while (checked_numbers.find(result) != checked_numbers.end()){
        result = dist(gen);
    }
    checked_numbers.insert(result);
    return result;
}

std::pair<std::pair<BOOSTED_INT, BOOSTED_INT>, std::pair<BOOSTED_INT, BOOSTED_INT>> RSAKeyGenerator::generate_keys(){
    while(true){
        BOOSTED_INT p;
        do {
            p = generate_random();
        } while(test->is_prime(p, min_probability) < min_probability);
        BOOSTED_INT q;
        do {
            q = generate_random();
        } while(test->is_prime(q, min_probability) < min_probability);
        if (gcd((p - 1) * (q - 1), e) != 1) {
            continue;
        }
        auto u = extensioned_Evklid_Algorithm(e, (p - 1) * (q - 1));
        BOOSTED_INT d = u[1] % ((p-1) * (q - 1));
        if (d < 0) {d += (p - 1) * (q - 1);}

        if (check_vinner(d, p, q) && check_ferma(p, q)) {
            return std::make_pair(std::make_pair(e, p * q), std::make_pair(d, p * q));
        }
    }

}

bool RSAKeyGenerator::check_ferma(const BOOSTED_INT &p, const BOOSTED_INT &q) {
    return boost::multiprecision::abs(p - q) > (BOOSTED_INT {1} << (length / 2 - 1));
}

bool RSAKeyGenerator::check_vinner(const BOOSTED_INT& d, const BOOSTED_INT &p, const BOOSTED_INT &q) {
    return fast_pow_mod(d, 4, 0) >= ((p * q) / 81);
}

RSA::RSA(Ptests test_type, double needed_probability, size_t length) : length(length){
    generator = std::make_shared<RSAKeyGenerator>(test_type, needed_probability, length);
    auto i = generator->generate_keys();
    public_key = i.first;
    private_key = i.second;
}

BOOSTED_INT RSA::convert_to_int(const INFO & block) {
    BOOSTED_INT res;
    for(size_t i = 0; i < block.size(); ++i) {
        res |= block[i];
        if(i != block.size() - 1) {
            res <<= 8;
        }
    }
    return res;
}

INFO RSA::convert_to_bytes_vector(const BOOSTED_INT & block) {
    INFO res;
    BOOSTED_INT copy_block(block);
    while(copy_block > 0) {
        res.push_back(std::byte{(copy_block & 0xFF).convert_to<std::byte>()});
        copy_block >>= 8;
    }
    std::reverse(res.begin(), res.end());
    return res;
}

INFO RSA::encrypt(const INFO &data) {
    size_t plain_size = (2 * length - 1) / 8 - 11;
    size_t encrypted_size = (2 * length) / 8;
    size_t blocks = (data.size() + plain_size - 1) / plain_size; // Округление вверх
    INFO result(blocks * encrypted_size);

    for (size_t i = 0; i < blocks; ++i) {
        size_t start = i * plain_size;
        size_t end = std::min(start + plain_size, data.size());

        INFO block(data.begin() + start, data.begin() + end);
        INFO encrypted = encrypt_single_block(block, plain_size);

        std::copy(encrypted.begin(), encrypted.end(),
                  result.begin() + i * encrypted_size);
    }

    return result;
}

INFO RSA::decrypt(const INFO& data) {
    size_t block_size = (2 * length) / 8;
    if (data.size() % block_size != 0) {
        throw std::invalid_argument("Data size is not multiple of encrypted block size");
    }
    size_t amount_of_operations = data.size() / block_size;
    INFO result;
    for (size_t j = 0; j < amount_of_operations; j++) {
        INFO block(block_size);
        std::copy(data.begin() + j * block_size, data.begin() + (j + 1) * block_size, block.begin());
        block = decrypt_single_block(block);
        result.insert(result.end(), block.begin(), block.end());
    }
    return result;
}

std::future<void> RSA::encrypt(const std::filesystem::path &input_file) {
    return std::async(std::launch::async, [this, input_file]() {
        std::ifstream input(input_file, std::ios::binary);
        auto output_file = input_file.parent_path() /
                           (input_file.stem().string() + "_encrypted" +
                            input_file.extension().string());
        std::ofstream output(output_file, std::ios::binary);

        if (!input.is_open()) {
            throw std::invalid_argument("Cannot open input file: " +
                                        input_file.string());
        }
        if (!output.is_open()) {
            throw std::invalid_argument("Cannot open output file: " +
                                        output_file.string());
        }

        size_t plain_block_size = (2 * length - 1) / 8 - 11;
        size_t encrypted_block_size = (2 * length) / 8;
        if (plain_block_size == 0) {
            throw std::runtime_error("Block size is too small for current key length");
        }
        std::vector<std::byte> buffer(plain_block_size);
        while (input.read(reinterpret_cast<char*>(buffer.data()),
                          plain_block_size) || input.gcount() > 0) {

            size_t bytes_read = input.gcount();
            INFO data_block(buffer.begin(), buffer.begin() + bytes_read);
            INFO encrypted_block = encrypt_single_block(data_block, plain_block_size);
            output.write(reinterpret_cast<const char*>(encrypted_block.data()),
                         encrypted_block.size());
        }
        input.close();
        output.close();
    });
}

std::future<void> RSA::decrypt(const std::filesystem::path &input_file) {
    return std::async(std::launch::async, [this, input_file]() {
        std::ifstream input(input_file, std::ios::binary);
        auto output_file = input_file.parent_path() /
                           (input_file.stem().string() + "_decrypted" +
                            input_file.extension().string());
        std::ofstream output(output_file, std::ios::binary);

        if (!input.is_open()) {
            throw std::invalid_argument("Cannot open input file: " +
                                        input_file.string());
        }
        if (!output.is_open()) {
            throw std::runtime_error("Cannot open output file: " +
                                     output_file.string());
        }
        size_t encrypted_block_size = (2 * length) / 8;
        std::vector<std::byte> buffer(encrypted_block_size);

        while (input.read(reinterpret_cast<char*>(buffer.data()),
                          encrypted_block_size) || input.gcount() > 0) {
            size_t bytes_read = input.gcount();
            if (bytes_read < encrypted_block_size) {
                buffer.resize(encrypted_block_size, std::byte{0});
            }

            try {
                INFO decrypted_block = decrypt_single_block(buffer);
                for (const auto& byte : decrypted_block) {
                    output.put(std::to_integer<char>(byte));
                }
            } catch (const std::exception& e) {
                throw std::runtime_error("Decryption failed: " +
                                         std::string(e.what()));
            }
        }
        input.close();
        output.close();
    });
}

INFO RSA::encrypt_single_block(const INFO &data, size_t block_size) {
    INFO padded_block = make_padding(data, block_size + 11 - data.size());
    BOOSTED_INT encrypted = convert_to_int(padded_block);
    encrypted = fast_pow_mod(encrypted, public_key.first, public_key.second);
    INFO result = convert_to_bytes_vector(encrypted);
    size_t encrypted_block_size = (2 * length) / 8;
    if (result.size() < encrypted_block_size) {
        INFO padded_result(encrypted_block_size - result.size(), std::byte{0});
        padded_result.insert(padded_result.end(), result.begin(), result.end());
        return padded_result;
    }
    return result;
}

INFO RSA::decrypt_single_block(const INFO &encrypted_block) {
    BOOSTED_INT decrypted = convert_to_int(encrypted_block);
    decrypted = fast_pow_mod(decrypted, private_key.first, private_key.second);
    INFO result = convert_to_bytes_vector(decrypted);
    return remove_padding(result);
}

INFO RSA::make_padding(const INFO &data, size_t padding_size) {
    if (padding_size < 11) {
        throw std::runtime_error("Padding size too small");
    }

    INFO result;
    result.reserve(data.size() + padding_size);

    // Add padding header
    result.push_back(std::byte{0});
    result.push_back(std::byte{2});

    // Add random padding
    std::mt19937 gen(std::random_device{}());
    std::uniform_int_distribution<> dist(1, 255);

    for (size_t i = 0; i < padding_size - 2 - 1; i++) {
        result.push_back(std::byte(static_cast<uint8_t>(dist(gen))));
    }

    // Add separator
    result.push_back(std::byte{0});

    // Add data
    result.insert(result.end(), data.begin(), data.end());

    return result;
}

INFO RSA::remove_padding(const INFO &padded_data) {
    if (padded_data.size() < 3) {
        return padded_data; // No padding to remove
    }

    // Find the zero separator after the random padding
    size_t data_start = 2; // Skip 0x00, 0x02
    while (data_start < padded_data.size() && padded_data[data_start] != std::byte{0}) {
        data_start++;
    }

    if (data_start >= padded_data.size() - 1) {
        return INFO(); // No data found
    }

    // Skip the zero separator
    data_start++;

    // Extract the actual data
    INFO result(padded_data.begin() + data_start, padded_data.end());
    return result;
}


