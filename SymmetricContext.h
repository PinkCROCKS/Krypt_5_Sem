//
// Created by Ярослав on 22.10.2025.
//

#ifndef INC_1_LAB_SYMMETRICCONTEXT_H
#define INC_1_LAB_SYMMETRICCONTEXT_H

#include <vector>
#include <memory>
#include <filesystem>
#include <random>
#include <algorithm>
#include <future>
#include <any>
#include "Byte.h"
#include "fstream"

typedef enum encryptionMethods{
    ECB,
    CBC,
    PCBC,
    CFB,
    OFB,
    CTR,
    Random_Delta
};

typedef enum paddingMethods{
    Zeros,
    ANSI_X_923,
    PKCS7,
    ISO_10126
};

class RoundKeysGenerator {
public:
    virtual std::vector<INFO> make_round_keys(const INFO& key, size_t amount_of_rounds) = 0;
};

class EncryptRound {
public:
    virtual INFO encryption_conversion(const INFO& data, const INFO& round_key) = 0;
};

class SymmetricAlgorithm {
protected:
    size_t block_size = 8;
public:
    virtual INFO encrypt(const INFO& data) = 0;
    virtual INFO decrypt(const INFO& data) = 0;
    size_t get_block_size() {
        return block_size;
    }

    void set_block_size(size_t size) {
        block_size = size;
    }
};

class KeyOnlyAlgorithm : public SymmetricAlgorithm {
private:
    INFO key;
public:
    KeyOnlyAlgorithm(const INFO& key)
            : key(key) {};
    INFO encrypt(const INFO& data) override {
        INFO encrypted = data;
        for (size_t i = 0; i < encrypted.size(); ++i) {
            encrypted[i] ^= key[i % key.size()];
        }

        return encrypted;
    }
    INFO decrypt(const INFO& data) override {
        return encrypt(data);
    }
};

class EncryptionMethod{
protected:
    std::shared_ptr<SymmetricAlgorithm> encryption_algorithm;
    bool padding;

    bool correct_data_for_encryption(const INFO& data, size_t block_size){
        return !(data.empty() || block_size == 0);
    }
public:
    virtual INFO encrypt(const INFO& data) = 0;
    virtual INFO decrypt(const INFO& data) = 0;
    bool padding_needed(){ return padding;}
};

class ECBMethod : public EncryptionMethod{
public:
    ECBMethod(std::shared_ptr<SymmetricAlgorithm> algorythm, bool pad=true){
        encryption_algorithm = algorythm;
        padding = pad;
    }
    INFO encrypt(const INFO& data) override {
        size_t block_size = encryption_algorithm->get_block_size();
        INFO encrypted_data = data;
        if (!correct_data_for_encryption(data, block_size)) {
            return encrypted_data;
        }

        std::vector<std::future<INFO>> futures;
        for (size_t i = 0; i < data.size(); i += block_size) {
            size_t end = std::min(i + block_size, data.size());
            INFO current_block(data.begin() + i, data.begin() + end);

            futures.push_back(std::async(
                    std::launch::async,
                    [this, block = std::move(current_block)]() mutable {
                        return encryption_algorithm->encrypt(block);
                    }
            ));
        }
        for (size_t i = 0; i < futures.size(); ++i) {
            INFO encrypted_block = futures[i].get();
            size_t start_index = i * block_size;
            std::copy(encrypted_block.begin(), encrypted_block.end(),
                      encrypted_data.begin() + start_index);
        }
        return encrypted_data;
    }

    INFO decrypt(const INFO& data) override {
        size_t block_size = encryption_algorithm->get_block_size();
        INFO decrypted_data = data;
        if (!correct_data_for_encryption(data, block_size)) {
            return decrypted_data;
        }

        std::vector<std::future<INFO>> futures;
        for (size_t i = 0; i < data.size(); i += block_size) {
            size_t end = std::min(i + block_size, data.size());
            INFO current_block(data.begin() + i, data.begin() + end);

            futures.push_back(std::async(
                    std::launch::async,
                    [this, block = std::move(current_block)]() mutable {
                        return encryption_algorithm->decrypt(block);
                    }
            ));
        }
        for (size_t i = 0; i < futures.size(); ++i) {
            INFO decrypted_block = futures[i].get();
            size_t start_index = i * block_size;
            std::copy(decrypted_block.begin(), decrypted_block.end(),
                      decrypted_data.begin() + start_index);
        }
        return decrypted_data;
    }
};

class CBCMethod : public EncryptionMethod{
private:
    INFO initial_vector;
public:
    CBCMethod(std::shared_ptr<SymmetricAlgorithm> algorythm, INFO vector, bool pad=true) {
        encryption_algorithm = algorythm;
        initial_vector = vector;
        padding = pad;
    }

    INFO encrypt(const INFO& data) override{
        size_t block_size = encryption_algorithm->get_block_size();
        INFO encrypted_data = data;
        if (initial_vector.size() < block_size){
            initial_vector.resize(block_size);
        }

        if (!correct_data_for_encryption(data, block_size)) {
            return encrypted_data;
        }

        INFO previous_block = initial_vector;
        for (size_t i = 0; i < data.size(); i += block_size) {
            INFO block(encrypted_data.begin() + i, encrypted_data.begin() + i + block_size);
            auto XOR_block = bit_op::xor_vectors(block, previous_block, block.size());
            auto encrypted_block = encryption_algorithm->encrypt(XOR_block);
            std::copy(encrypted_block.begin(), encrypted_block.end(), encrypted_data.begin() + i);
            previous_block = encrypted_block;
        }

        return encrypted_data;
    }

    INFO decrypt(const INFO& data) override {
        size_t block_size = encryption_algorithm->get_block_size();
        INFO decrypted_data = data;
        if (!correct_data_for_encryption(data, block_size)) {
            return decrypted_data;
        }

        std::vector<std::future<INFO>> futures;
        for (size_t i = 0; i < data.size(); i += block_size) {
            size_t end = std::min(i + block_size, data.size());
            INFO current_block(data.begin() + i, data.begin() + end);

            futures.push_back(std::async(
                    std::launch::async,
                    [this, block = std::move(current_block)]() mutable {
                        return encryption_algorithm->decrypt(block);
                    }
            ));
        }

        INFO previous_block = initial_vector;
        for (size_t i = 0; i < futures.size(); ++i) {
            INFO decrypted_block = futures[i].get();
            INFO result_block = bit_op::xor_vectors(decrypted_block, previous_block, block_size);
            size_t start_index = i * block_size;
            previous_block = INFO(data.begin() + start_index, data.begin() + start_index + block_size);
            std::copy(result_block.begin(), result_block.end(), decrypted_data.begin() + start_index);
        }

        return decrypted_data;
    }
};

class PCBCMethod : public EncryptionMethod {
private:
    INFO initial_vector;
public:
    PCBCMethod(std::shared_ptr<SymmetricAlgorithm> algorythm, INFO vector, bool pad=true) {
        encryption_algorithm = algorythm;
        initial_vector = vector;
        padding = pad;
    }

    INFO encrypt(const INFO& data) override {
        size_t block_size = encryption_algorithm->get_block_size();
        INFO encrypted_data = data;
        if (initial_vector.size() < block_size){
            initial_vector.resize(block_size);
        }
        if (!correct_data_for_encryption(data, block_size)) {
            return encrypted_data;
        }
        INFO processed = initial_vector;
        for (size_t i = 0; i < data.size(); i += block_size) {
            INFO block(data.begin() + i, data.begin() + i + block_size);
            INFO xor_block = bit_op::xor_vectors(processed, block, block.size());
            INFO encrypted_block = encryption_algorithm->encrypt(xor_block);
            std::copy(encrypted_block.begin(), encrypted_block.end(), encrypted_data.begin() + i);
            processed = bit_op::xor_vectors(block, encrypted_block, block.size());
        }
        return encrypted_data;
    }

    INFO decrypt(const INFO& data) override {
        size_t block_size = encryption_algorithm->get_block_size();
        INFO decrypted_data = data;
        if (initial_vector.size() < block_size){
            initial_vector.resize(block_size);
        }
        if (!correct_data_for_encryption(data, block_size)) {
            return decrypted_data;
        }
        INFO processed = initial_vector;
        for (size_t i = 0; i < data.size(); i += block_size) {
            INFO block(data.begin() + i, data.begin() + i + block_size);
            INFO decrypted_block = encryption_algorithm->decrypt(block);
            INFO xor_block = bit_op::xor_vectors(decrypted_block, processed, block.size());
            std::copy(xor_block.begin(), xor_block.end(), decrypted_data.begin() + i);
            processed = bit_op::xor_vectors(block, xor_block, block.size());
        }
        return decrypted_data;
    }
};

class CFBMethod : public EncryptionMethod {
private:
    INFO initial_vector;
public:
    CFBMethod(std::shared_ptr<SymmetricAlgorithm> algorythm, INFO vector, bool pad=true) {
        encryption_algorithm = algorythm;
        initial_vector = vector;
        padding = pad;
    }
    INFO encrypt(const INFO& data) override {
        size_t block_size = encryption_algorithm->get_block_size();
        if (data.size() % block_size != 0) {
            throw std::runtime_error("input block size incorrect");
        }
        size_t count_blocks = data.size() / block_size;

        INFO result(count_blocks * block_size);
        INFO c_prev{initial_vector};
        for(size_t i = 0; i < count_blocks; ++i) {
            INFO block(block_size);
            std::copy(data.begin() + i * block_size, data.begin() + (i + 1) * block_size, block.begin());
            INFO new_block = bit_op::xor_vectors(encryption_algorithm->encrypt(c_prev), block, block.size());
            std::copy(new_block.begin(), new_block.end(), result.begin() + i * block_size);
            c_prev = new_block;
        }
        return result;
    }
    INFO decrypt(const INFO& data) override {
        size_t block_size = encryption_algorithm->get_block_size();
        if (data.size() % block_size != 0) {
            throw std::runtime_error("input block size incorrect");
        }
        size_t count_blocks = data.size() / block_size;

        INFO result(count_blocks * block_size);
        INFO prev_c{initial_vector};

        for (size_t i = 0; i < count_blocks; ++i) {
            INFO block(block_size);
            std::copy(data.begin() + i * block_size, data.begin() + (i + 1) * block_size, block.begin());
            INFO new_block = bit_op::xor_vectors(encryption_algorithm->encrypt(prev_c), block, block.size());
            std::copy(new_block.begin(), new_block.end(), result.begin() + i * block_size);
            prev_c = block;
        }

        return result;
    }
};

class OFBMethod : public EncryptionMethod {
private:
    INFO initial_vector;
public:
    OFBMethod(std::shared_ptr<SymmetricAlgorithm> algorythm, INFO vector, bool pad=true) {
        encryption_algorithm = algorythm;
        initial_vector = vector;
        padding = pad;
    }
    INFO encrypt(const INFO& data) override {
        size_t block_size = encryption_algorithm->get_block_size();
        INFO encrypted_data = data;
        if (initial_vector.size() < block_size){
            initial_vector.resize(block_size);
        }
        INFO processed = initial_vector;
        for (size_t i = 0; i < encrypted_data.size(); i += block_size) {
            processed = encryption_algorithm->encrypt(processed);
            size_t current_block_size = std::min(block_size, encrypted_data.size() - i);
            INFO block(encrypted_data.begin() + i, encrypted_data.begin() + i + current_block_size);
            INFO keystream_block(processed.begin(), processed.begin() + current_block_size);
            INFO processed_block = bit_op::xor_vectors(block, keystream_block, current_block_size);
            std::copy(processed_block.begin(), processed_block.end(), encrypted_data.begin() + i);
        }
        return encrypted_data;
    }
    INFO decrypt(const INFO& data) override {
        size_t block_size = encryption_algorithm->get_block_size();
        INFO decrypted_data = data;
        if (initial_vector.size() < block_size){
            initial_vector.resize(block_size);
        }
        if (!correct_data_for_encryption(data, block_size)) {
            return decrypted_data;
        }
        INFO processed = initial_vector;
        for (size_t i = 0; i < decrypted_data.size(); i += block_size) {
            processed = encryption_algorithm->encrypt(processed);
            size_t current_block_size = std::min(block_size, decrypted_data.size() - i);
            INFO block(decrypted_data.begin() + i, decrypted_data.begin() + i + current_block_size);
            INFO keystream_block(processed.begin(), processed.begin() + current_block_size);
            INFO processed_block = bit_op::xor_vectors(block, keystream_block, current_block_size);
            std::copy(processed_block.begin(), processed_block.end(), decrypted_data.begin() + i);
        }
        return decrypted_data;
    }
};

class CTRMethod : public EncryptionMethod {
private:
    INFO initial_vector;
    INFO counter;
public:
    CTRMethod(std::shared_ptr<SymmetricAlgorithm> algorithm, INFO vector, bool pad = true) {
        encryption_algorithm = algorithm;
        initial_vector = vector;
        padding = pad;
        counter = initial_vector;
    }

    INFO encrypt(const INFO& data) override {
        if (data.empty()) return data;
        auto block_size = encryption_algorithm->get_block_size();
        INFO result = data;
        auto iv = initial_vector;
        if (iv.size() < block_size) iv.resize(block_size);

        const size_t num_blocks = (data.size() + block_size - 1) / block_size;
        if (num_blocks == 0) return data;
        const size_t num_threads = std::min(
                static_cast<size_t>(std::thread::hardware_concurrency()),
                num_blocks
        );

        std::vector<std::future<void>> futures;
        const size_t blocks_per_thread = num_blocks / num_threads;
        const size_t extra_blocks = num_blocks % num_threads;

        size_t start_block = 0;
        for (size_t t = 0; t < num_threads; ++t) {
            size_t end_block = start_block + blocks_per_thread + (t < extra_blocks ? 1 : 0);
            futures.push_back(std::async(std::launch::async, [&, start_block, end_block, block_size]() {
                for (size_t block_idx = start_block; block_idx < end_block; ++block_idx) {
                    size_t i = block_idx * block_size;
                    size_t end_index = std::min(i + block_size, result.size());
                    size_t current_block_size = end_index - i;
                    uint64_t counter = block_idx;
                    auto counter_value = bit_op::add_number_to_bytes(iv, counter);
                    auto encrypted_counter = encryption_algorithm->encrypt(counter_value);

                    INFO keystream_block(encrypted_counter.begin(),
                                                           encrypted_counter.begin() + current_block_size);
                    for (size_t j = 0; j < current_block_size; ++j) {
                        result[i + j] = result[i + j] ^ keystream_block[j];
                    }
                }
            }));

            start_block = end_block;
        }
        for (auto& future : futures) {
            future.get();
        }

        return result;
    }

    INFO decrypt(const INFO& data) override {
        if (data.empty()) return data;
        auto block_size = encryption_algorithm->get_block_size();
        INFO result = data;
        auto iv = initial_vector;
        if (iv.size() < block_size) iv.resize(block_size);

        const size_t num_blocks = (data.size() + block_size - 1) / block_size;
        if (num_blocks == 0) return data;
        const size_t num_threads = std::min(
                static_cast<size_t>(std::thread::hardware_concurrency()),
                num_blocks
        );

        std::vector<std::future<void>> futures;
        const size_t blocks_per_thread = num_blocks / num_threads;
        const size_t extra_blocks = num_blocks % num_threads;

        size_t start_block = 0;
        for (size_t t = 0; t < num_threads; ++t) {
            size_t end_block = start_block + blocks_per_thread + (t < extra_blocks ? 1 : 0);
            futures.push_back(std::async(std::launch::async, [&, start_block, end_block, block_size]() {
                for (size_t block_idx = start_block; block_idx < end_block; ++block_idx) {
                    size_t i = block_idx * block_size;
                    size_t end_index = std::min(i + block_size, result.size());
                    size_t current_block_size = end_index - i;
                    uint64_t counter = block_idx;
                    auto counter_value = bit_op::add_number_to_bytes(iv, counter);
                    auto encrypted_counter = encryption_algorithm->encrypt(counter_value);

                    INFO keystream_block(encrypted_counter.begin(),
                                                           encrypted_counter.begin() + current_block_size);
                    for (size_t j = 0; j < current_block_size; ++j) {
                        result[i + j] = result[i + j] ^ keystream_block[j];
                    }
                }
            }));

            start_block = end_block;
        }
        for (auto& future : futures) {
            future.get();
        }
        return result;
    }

private:
    void increment_counter(INFO& counter) {
        for (size_t i = counter.size(); i > 0; --i) {
            auto& byte = counter[i - 1];
            uint8_t value = std::to_integer<uint8_t>(byte);
            value++;
            byte = std::byte(value);
            if (value != 0) {
                break;
            }
        }
    }
};

class RandomDeltaMethod : public EncryptionMethod {
private:
    INFO initial_vector;
    INFO delta;

public:
    RandomDeltaMethod(std::shared_ptr<SymmetricAlgorithm> algorithm, INFO vector, bool pad = true) {
        encryption_algorithm = algorithm;
        initial_vector = vector;
        padding = pad;
        initialize_delta();
    }

    INFO encrypt(const INFO& data) override {
        size_t block_size = encryption_algorithm->get_block_size();
        INFO encrypted_data = data;

        if (initial_vector.size() < block_size) {
            initial_vector.resize(block_size);
        }
        INFO current_state = initial_vector;

        for (size_t i = 0; i < encrypted_data.size(); i += block_size) {
            INFO encrypted_state = encryption_algorithm->encrypt(current_state);
            size_t current_block_size = std::min(block_size, encrypted_data.size() - i);
            INFO block(encrypted_data.begin() + i, encrypted_data.begin() + i + current_block_size);
            INFO keystream_block(encrypted_state.begin(), encrypted_state.begin() + current_block_size);
            INFO processed_block = bit_op::xor_vectors(block, keystream_block, current_block_size);
            std::copy(processed_block.begin(), processed_block.end(), encrypted_data.begin() + i);
            update_state(current_state);
        }

        return encrypted_data;
    }

    INFO decrypt(const INFO& data) override {
        size_t block_size = encryption_algorithm->get_block_size();
        INFO decrypted_data = data;

        if (initial_vector.size() < block_size) {
            initial_vector.resize(block_size);
        }
        INFO current_state = initial_vector;

        for (size_t i = 0; i < decrypted_data.size(); i += block_size) {
            INFO encrypted_state = encryption_algorithm->encrypt(current_state);
            size_t current_block_size = std::min(block_size, decrypted_data.size() - i);
            INFO block(decrypted_data.begin() + i, decrypted_data.begin() + i + current_block_size);
            INFO keystream_block(encrypted_state.begin(), encrypted_state.begin() + current_block_size);
            INFO processed_block = bit_op::xor_vectors(block, keystream_block, current_block_size);
            std::copy(processed_block.begin(), processed_block.end(), decrypted_data.begin() + i);
            update_state(current_state);
        }

        return decrypted_data;
    }
    void set_delta(const INFO& new_delta) {
        delta = new_delta;
        if (delta.size() != encryption_algorithm->get_block_size()) {
            delta.resize(encryption_algorithm->get_block_size());
        }
    }
    INFO get_delta() const {
        return delta;
    }

private:
    void initialize_delta() {
        size_t block_size = encryption_algorithm->get_block_size();
        delta.resize(block_size);
        std::fill(delta.begin(), delta.end(), std::byte(0));
        std::copy(initial_vector.begin() + block_size / 2, initial_vector.end(), delta.begin() + block_size / 2);
    }
    void update_state(INFO& state) {
        size_t block_size = encryption_algorithm->get_block_size();
        if (state.size() != block_size) {
            state.resize(block_size);
        }
        if (delta.size() != block_size) {
            delta.resize(block_size);
        }
        bool carry = false;
        for (size_t i = block_size; i > 0; --i) {
            uint16_t sum = std::to_integer<uint16_t>(state[i-1]) +
                           std::to_integer<uint16_t>(delta[i-1]) +
                           (carry ? 1 : 0);

            state[i-1] = std::byte(sum & 0xFF);
            carry = (sum > 0xFF);
        }
    }
};

class PaddingMethod{
protected:
    size_t block_size;
public:
    virtual void make_padding(INFO& data) = 0;
    virtual void remove_padding(INFO& data) = 0;
};

class ZerosPadding : public PaddingMethod {
public:
    ZerosPadding(size_t size) {block_size = size;}
    void make_padding(INFO& data) override {
        size_t padding_size = abs(block_size - data.size() % block_size) ;
        size_t start_size = data.size();
        data.resize(data.size() + padding_size);
    }
    void remove_padding(INFO& data) override {
        size_t padding_size = static_cast<size_t>(data.back());
        if (padding_size == 0) {
            return;
        }
        if (padding_size > block_size) {
            throw std::runtime_error("Invalid Padding size");
        }
    }
};

class ANSIX923Padding : public PaddingMethod{
public:
    ANSIX923Padding(size_t size) {block_size = size;}
    void make_padding(INFO& data) override {
        size_t padding_size = block_size - data.size() % block_size;
        size_t start_size = data.size();
        data.resize(data.size() + padding_size);
        data[data.size() - 1] = std::byte(padding_size);
    }
    void remove_padding(INFO& data) override {
        size_t padding_size = static_cast<size_t>(data.back());
        if (padding_size == 0 || data.size() < 1) {
            return;
        }
        if (padding_size > block_size) {
            throw std::runtime_error("Invalid Padding size");
        }
//        for (size_t i = data.size() - padding_size; i < data.size(); ++i) {
//            if (data[i] != std::byte{0}) {
//                throw std::runtime_error("Invalid ANSI_X_923 padding");
//            }
//        }
        data.resize(data.size() - padding_size);
    }
};

class PKCS7Padding : public PaddingMethod {
public:
    PKCS7Padding(size_t size) {block_size = size;}
    void make_padding(INFO& data) override {
        size_t padding_size = block_size - data.size() % block_size;
        size_t start_size = data.size();
        data.resize(data.size() + padding_size);
        std::fill(data.begin() + start_size, data.end(), std::byte(padding_size));
    }

    void remove_padding(INFO& data) override {
        size_t padding_size = static_cast<size_t>(data.back());
        if (padding_size == 0 || data.size() < 1) {
            return;
        }
        if (padding_size > block_size) {
            throw std::runtime_error("Invalid Padding size");
        }
        for (size_t i = data.size() - padding_size; i < data.size(); ++i) {
            if (data[i] != std::byte(padding_size)) {
                throw std::runtime_error("Invalid PKCS7 padding");
            }
        }
        data.resize(data.size() - padding_size);
    }
};

class ISO10126Padding : public PaddingMethod {
public:
    ISO10126Padding(size_t size) {block_size = size;}
    void make_padding(INFO& data) override {
        size_t padding_size = block_size - data.size() % block_size;
        size_t start_size = data.size();
        data.resize(data.size() + padding_size);
        std::random_device rd;
        std::uniform_int_distribution<uint8_t> dist(0, 255);
        for (size_t i = start_size; i < data.size() - 1; ++i) {
            data[i] = std::byte(dist(rd));
        }
        data[data.size() - 1] = std::byte(padding_size);
    }
    void remove_padding(INFO& data) override {
        if (data.size() < 1) return;
        size_t padding_size = static_cast<size_t>(data.back());
        if (padding_size == 0 || data.size() < 1) {
            return;
        }
        if (padding_size > block_size) {
            throw std::runtime_error("Invalid Padding size");
        }
        data.resize(data.size() - padding_size);
    }
};

class SymmetricEncryptingContext{
    std::unique_ptr<EncryptionMethod> encryption_mode;
    std::unique_ptr<PaddingMethod> padding_mode;
    size_t block_size;
public:
    SymmetricEncryptingContext(encryptionMethods encryption_mode_,
                                       paddingMethods padding_mode_,
                                       std::optional<INFO> init_vector_,
                                       std::shared_ptr<SymmetricAlgorithm> algorithm_) {

        block_size = algorithm_->get_block_size();

        switch (padding_mode_) {
            case Zeros:
                padding_mode = std::make_unique<ZerosPadding>(block_size);
                break;
            case ANSI_X_923:
                padding_mode = std::make_unique<ANSIX923Padding>(block_size);
                break;
            case PKCS7:
                padding_mode = std::make_unique<PKCS7Padding>(block_size);
                break;
            case ISO_10126:
                padding_mode = std::make_unique<ISO10126Padding>(block_size);
                break;
        }

        switch (encryption_mode_) {
            case ECB:
                encryption_mode = std::make_unique<ECBMethod>(std::move(algorithm_));
                break;
            case CBC:
                encryption_mode = std::make_unique<CBCMethod>(std::move(algorithm_),  std::move(init_vector_.value()));
                break;
            case PCBC:
                encryption_mode = std::make_unique<PCBCMethod>(std::move(algorithm_), std::move(init_vector_.value()));
                break;
            case CFB:
                encryption_mode = std::make_unique<CFBMethod>(std::move(algorithm_), std::move(init_vector_.value()));
                break;
            case OFB:
                encryption_mode = std::make_unique<OFBMethod>(std::move(algorithm_), std::move(init_vector_.value()));
                break;
            case CTR:
                encryption_mode = std::make_unique<CTRMethod>(std::move(algorithm_), std::move(init_vector_.value()));
                break;
            case Random_Delta:
                encryption_mode = std::make_unique<RandomDeltaMethod>(std::move(algorithm_), std::move(init_vector_.value()));
                break;
        }
    }

    INFO padding(const INFO& data){
        INFO padding_data = data;
        size_t required_size = ((data.size() + block_size - 1) / block_size) * block_size;
        padding_mode->make_padding(padding_data);
        return padding_data;
    }
    INFO remove_padding(const INFO & data){
        INFO clear_data = data;
        padding_mode->remove_padding(clear_data);
        return clear_data;
    }
    std::future<INFO> encrypt(const INFO& data){
        return std::async(std::launch::async, [this, data]() -> INFO {
            INFO padding_data = padding(data);
            return encryption_mode->encrypt(padding_data);
        });
    }
    std::future<INFO> decrypt(const INFO& data){
        return std::async(std::launch::async, [this, data]() -> INFO {
            INFO decrypted_data = encryption_mode->decrypt(data);
            return remove_padding(decrypted_data);
        });
    }
    std::future<void> encrypt(const std::filesystem::path& input_file, const std::filesystem::path & output_file) {
        return std::async(std::launch::async, [this, input_file, output_file]() {
            if (!std::filesystem::exists(input_file)) {
                throw std::runtime_error("NO such file or directory: " + input_file.string());
            }

            std::filesystem::path actual_output_path = output_file;

            std::ifstream in_file(input_file, std::ios::binary);
            std::ofstream out_file(actual_output_path, std::ios::binary);

            if (!in_file.is_open()) {
                throw std::runtime_error("Cannot open input file: " + input_file.string());
            }
            if (!out_file.is_open()) {
                throw std::runtime_error("Cannot open output file: " + actual_output_path.string());
            }

            in_file.seekg(0, std::ios::end);
            size_t file_size = in_file.tellg();
            in_file.seekg(0, std::ios::beg);

            INFO file_data(file_size);
            in_file.read(reinterpret_cast<char*>(file_data.data()), file_size);

            auto padded_data = padding(file_data);
            auto encrypted_data = encryption_mode->encrypt(padded_data);

            out_file.write(reinterpret_cast<const char*>(encrypted_data.data()), encrypted_data.size());
            std::cout << "File encrypted: " << input_file << " -> " << actual_output_path << std::endl;
        });
    }
    std::future<void> decrypt(const std::filesystem::path& input_file,
                                               const std::filesystem::path& output_file) {
        return std::async(std::launch::async, [this, input_file, output_file]() {
            if (!std::filesystem::exists(input_file)) {
                throw std::runtime_error("Input file does not exist: " + input_file.string());
            }

            std::string stem = input_file.stem().string();
            if (stem.length() > 10 && stem.substr(stem.length() - 10) == "_encrypted") {
                stem = stem.substr(0, stem.length() - 10);
            }

            std::filesystem::path actual_output_path = output_file;


            std::ifstream in_file(input_file, std::ios::binary);
            std::ofstream out_file(actual_output_path, std::ios::binary);

            if (!in_file.is_open() || !out_file.is_open()) {
                throw std::runtime_error("Cannot open input or output file");
            }

            in_file.seekg(0, std::ios::end);
            size_t file_size = in_file.tellg();
            in_file.seekg(0, std::ios::beg);

            INFO encrypted_data(file_size);
            in_file.read(reinterpret_cast<char*>(encrypted_data.data()), file_size);

            INFO decrypted_data = encryption_mode->decrypt(encrypted_data);
            INFO unpadded_data = remove_padding(decrypted_data);
            out_file.write(reinterpret_cast<const char*>(unpadded_data.data()), unpadded_data.size());

            std::cout << "File decrypted: " << input_file << " -> " << actual_output_path << std::endl;
        });
    }
};

#endif
