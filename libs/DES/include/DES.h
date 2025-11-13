#ifndef INC_1_LAB_DES_H
#define INC_1_LAB_DES_H

#include "../../FEYSTEL/include/Feystel.h"

class DES : public SymmetricAlgorithm {
private:
    std::shared_ptr<FeystelNet> function;
    INFO key;
public:
    DES(const INFO& encrypting_key) : key(encrypting_key){
        FeystelKeysGeneretion generator;
        FeystelFunction feystel_function;
        function = std::make_shared<FeystelNet>(FeystelNet(std::make_shared<FeystelKeysGeneretion>(generator), std::make_shared<FeystelFunction>(feystel_function),
                16, key));
    }
    INFO encrypt(const INFO& data) override;
    INFO decrypt(const INFO& data) override;
};

#endif //INC_1_LAB_DES_H
