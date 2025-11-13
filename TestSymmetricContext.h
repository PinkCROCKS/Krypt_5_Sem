#ifndef INC_1_LAB_TESTSYMMETRICCONTEXT_H
#define INC_1_LAB_TESTSYMMETRICCONTEXT_H

#include "SymmetricContext.h"
#include <cassert>
#include <iostream>
#include <string>

class TestSymmetricContext {
private:
    std::shared_ptr<SymmetricAlgorithm> testAlgorithm;
    std::vector<std::byte> testKey;
    std::vector<std::byte> testIV;

    void setupTestAlgorithm();
    bool compareVectors(const INFO& v1, const INFO& v2);
    void printTestResult(const std::string& testName, bool passed);

public:
    TestSymmetricContext();

    void testECBMode();
    void testCBCMode();
    void testPCBCMode();
    void testCFBMode();
    void testOFBMode();
    void testCTRMode();
    void testRandomDeltaMode();

    void testAllModes();
    void testAllPaddingModes();

    void testZerosPadding();
    void testANSIX923Padding();
    void testPKCS7Padding();
    void testISO10126Padding();

    void testFileEncryption(const std::string& testFileName );
};

#endif //INC_1_LAB_TESTSYMMETRICCONTEXT_H
