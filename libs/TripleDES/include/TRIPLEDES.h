#ifndef CRYPT_TRIPLEDES_H
#define CRYPT_TRIPLEDES_H

#include "SymmetricContext.h"

#include <cstddef>
#include <vector>
#include <memory>
#include <stdexcept>
#include "DES.h"

enum class AlgorithmType {
    EEE,
    EDE,
};

const size_t block_size = 8;

class TripleDes : public SymmetricAlgorithm{
private:
    AlgorithmType type;
    INFO key1, key2, key3;
    std::shared_ptr<DES> des1, des2, des3;

public:
    TripleDes(AlgorithmType type_, const INFO & key_);
    INFO encrypt(const INFO&block) override;
    INFO decrypt(const INFO&block) override;
    size_t get_block_size() const;
};

#endif //CRYPT_TRIPLEDES_H
