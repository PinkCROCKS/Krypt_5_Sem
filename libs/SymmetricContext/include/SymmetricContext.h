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
#include <optional>
#include "../../BIT_FUNCTIONS/include/Byte.h"
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
    size_t get_block_size();
    void set_block_size(size_t size);
};

class KeyOnlyAlgorithm : public SymmetricAlgorithm {
private:
    INFO key;
public:
    KeyOnlyAlgorithm(const INFO& key)
            : key(key) {};
    INFO encrypt(const INFO& data) override;
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
    ECBMethod(std::shared_ptr<SymmetricAlgorithm> algorythm, bool pad=true);
    INFO encrypt(const INFO& data) override;

    INFO decrypt(const INFO& data) override;
};

class CBCMethod : public EncryptionMethod{
private:
    INFO initial_vector;
public:
    CBCMethod(std::shared_ptr<SymmetricAlgorithm> algorythm, INFO vector, bool pad=true);

    INFO encrypt(const INFO& data) override;

    INFO decrypt(const INFO& data) override;
};

class PCBCMethod : public EncryptionMethod {
private:
    INFO initial_vector;
public:
    PCBCMethod(std::shared_ptr<SymmetricAlgorithm> algorythm, INFO vector, bool pad=true);

    INFO encrypt(const INFO& data) override;

    INFO decrypt(const INFO& data) override;
};

class CFBMethod : public EncryptionMethod {
private:
    INFO initial_vector;
public:
    CFBMethod(std::shared_ptr<SymmetricAlgorithm> algorythm, INFO vector, bool pad=true);
    INFO encrypt(const INFO& data) override;
    INFO decrypt(const INFO& data) override;
};

class OFBMethod : public EncryptionMethod {
private:
    INFO initial_vector;
public:
    OFBMethod(std::shared_ptr<SymmetricAlgorithm> algorythm, INFO vector, bool pad=true);
    INFO encrypt(const INFO& data) override;
    INFO decrypt(const INFO& data) override;
};

class CTRMethod : public EncryptionMethod {
private:
    INFO initial_vector;
    INFO counter;
public:
    CTRMethod(std::shared_ptr<SymmetricAlgorithm> algorithm, INFO vector, bool pad = true);

    INFO encrypt(const INFO& data) override;

    INFO decrypt(const INFO& data) override;

private:
    void increment_counter(INFO& counter);
};

class RandomDeltaMethod : public EncryptionMethod {
private:
    INFO initial_vector;
    INFO delta;

public:
    RandomDeltaMethod(std::shared_ptr<SymmetricAlgorithm> algorithm, INFO vector, bool pad = true);

    INFO encrypt(const INFO& data) override;

    INFO decrypt(const INFO& data) override;
    void set_delta(const INFO& new_delta);
    INFO get_delta() const;

private:
    void initialize_delta();
    void update_state(INFO& state);
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
    void make_padding(INFO& data) override;
    void remove_padding(INFO& data) override;
};

class ANSIX923Padding : public PaddingMethod{
public:
    ANSIX923Padding(size_t size) {block_size = size;}
    void make_padding(INFO& data) override;
    void remove_padding(INFO& data) override;
};

class PKCS7Padding : public PaddingMethod {
public:
    PKCS7Padding(size_t size) {block_size = size;}
    void make_padding(INFO& data) override;

    void remove_padding(INFO& data) override;
};

class ISO10126Padding : public PaddingMethod {
public:
    ISO10126Padding(size_t size) {block_size = size;}
    void make_padding(INFO& data) override;
    void remove_padding(INFO& data) override;
};

class SymmetricEncryptingContext{
    std::unique_ptr<EncryptionMethod> encryption_mode;
    std::unique_ptr<PaddingMethod> padding_mode;
    size_t block_size;
public:
    SymmetricEncryptingContext(encryptionMethods encryption_mode_,
                                       paddingMethods padding_mode_,
                                       std::optional<INFO> init_vector_,
                                       std::shared_ptr<SymmetricAlgorithm> algorithm_);

    INFO padding(const INFO& data);
    INFO remove_padding(const INFO & data);
    std::future<INFO> encrypt(const INFO& data);
    std::future<INFO> decrypt(const INFO& data);
    std::future<void> encrypt(const std::filesystem::path& input_file, const std::filesystem::path & output_file);
    std::future<void> decrypt(const std::filesystem::path& input_file,
                                               const std::filesystem::path& output_file);
};

#endif
