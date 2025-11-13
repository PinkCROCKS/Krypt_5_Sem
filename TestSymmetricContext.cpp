#include "TestSymmetricContext.h"
#include <fstream>
#include <random>

TestSymmetricContext::TestSymmetricContext() {
    setupTestAlgorithm();
}

void TestSymmetricContext::setupTestAlgorithm() {
    testKey = {std::byte(119), std::byte(99), std::byte(111), std::byte(30),
                          std::byte(241), std::byte(164), std::byte(43), std::byte(34)};
    testIV = {std::byte{165}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
              std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF}};;
    testAlgorithm = std::make_shared<KeyOnlyAlgorithm>(testKey);
}

bool TestSymmetricContext::compareVectors(const INFO& v1, const INFO& v2) {
    if (v1.size() != v2.size()) return false;
    for (size_t i = 0; i < v1.size(); ++i) {
        if (v1[i] != v2[i]) return false;
    }
    return true;
}

void TestSymmetricContext::printTestResult(const std::string& testName, bool passed) {
    std::cout << testName << ": " << (passed ? "PASSED" : "FAILED") << std::endl;
}

void TestSymmetricContext::testECBMode() {
    std::cout << "\n=== Testing ECB Mode ===" << std::endl;

    INFO testData = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
                     std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08}};

    SymmetricEncryptingContext context(ECB, PKCS7, std::nullopt, testAlgorithm);

    auto encryptedFuture = context.encrypt(testData);
    auto decryptedFuture = context.decrypt(encryptedFuture.get());

    INFO result = decryptedFuture.get();

    bool passed = compareVectors(testData, result);
    printTestResult("ECB Mode Test", passed);

    if (!passed) {
        std::cout << "Original size: " << testData.size() << ", Result size: " << result.size() << std::endl;
    }
}

void TestSymmetricContext::testCBCMode() {
    std::cout << "\n=== Testing CBC Mode ===" << std::endl;

    INFO testData = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
                     std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08}};

    SymmetricEncryptingContext context(CBC, PKCS7, testIV, testAlgorithm);

    auto encryptedFuture = context.encrypt(testData);
    auto decryptedFuture = context.decrypt(encryptedFuture.get());

    INFO result = decryptedFuture.get();

    bool passed = compareVectors(testData, result);
    printTestResult("CBC Mode Test", passed);
}

void TestSymmetricContext::testPCBCMode() {
    std::cout << "\n=== Testing PCBC Mode ===" << std::endl;

    INFO testData = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
                     std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08}};

    SymmetricEncryptingContext context(PCBC, PKCS7, testIV, testAlgorithm);

    auto encryptedFuture = context.encrypt(testData);
    auto decryptedFuture = context.decrypt(encryptedFuture.get());

    INFO result = decryptedFuture.get();

    bool passed = compareVectors(testData, result);
    printTestResult("PCBC Mode Test", passed);
}

void TestSymmetricContext::testCFBMode() {
    std::cout << "\n=== Testing CFB Mode ===" << std::endl;

    INFO testData = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
                     std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08}};

    SymmetricEncryptingContext context(CFB, PKCS7, testIV, testAlgorithm);

    auto encryptedFuture = context.encrypt(testData);
    auto decryptedFuture = context.decrypt(encryptedFuture.get());

    INFO result = decryptedFuture.get();

    bool passed = compareVectors(testData, result);
    printTestResult("CFB Mode Test", passed);
}

void TestSymmetricContext::testOFBMode() {
    std::cout << "\n=== Testing OFB Mode ===" << std::endl;

    INFO testData = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
                     std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08}};

    SymmetricEncryptingContext context(OFB, PKCS7, testIV, testAlgorithm);

    auto encryptedFuture = context.encrypt(testData);
    auto decryptedFuture = context.decrypt(encryptedFuture.get());

    INFO result = decryptedFuture.get();

    bool passed = compareVectors(testData, result);
    printTestResult("OFB Mode Test", passed);
}

void TestSymmetricContext::testCTRMode() {
    std::cout << "\n=== Testing CTR Mode ===" << std::endl;

    INFO testData = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
                     std::byte{0x05}, std::byte{0x06}, std::byte{0x01}};

    SymmetricEncryptingContext context(CTR, PKCS7, testIV, testAlgorithm);

    auto encryptedFuture = context.encrypt(testData);
    auto t = encryptedFuture.get();
    auto decryptedFuture = context.decrypt(t);

    INFO result = decryptedFuture.get();

    bool passed = compareVectors(testData, result);
    printTestResult("CTR Mode Test", passed);
}

void TestSymmetricContext::testRandomDeltaMode() {
    std::cout << "\n=== Testing Random Delta Mode ===" << std::endl;

    INFO testData = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
                     std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08}};

    SymmetricEncryptingContext context(Random_Delta, PKCS7, testIV, testAlgorithm);

    auto encryptedFuture = context.encrypt(testData);
    auto decryptedFuture = context.decrypt(encryptedFuture.get());

    INFO result = decryptedFuture.get();

    bool passed = compareVectors(testData, result);
    printTestResult("Random Delta Mode Test", passed);
}

void TestSymmetricContext::testZerosPadding() {
    std::cout << "\n=== Testing Zeros Padding ===" << std::endl;

    INFO testData = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}}; // 3 bytes, needs padding

    SymmetricEncryptingContext context(ECB, Zeros, std::nullopt, testAlgorithm);

    auto encryptedFuture = context.encrypt(testData);
    auto decryptedFuture = context.decrypt(encryptedFuture.get());

    INFO result = decryptedFuture.get();

    // For zeros padding, we expect the original data back
    bool passed = compareVectors(testData, result);
    printTestResult("Zeros Padding Test", passed);
}

void TestSymmetricContext::testANSIX923Padding() {
    std::cout << "\n=== Testing ANSI X.923 Padding ===" << std::endl;

    INFO testData = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}}; // 3 bytes, needs padding

    SymmetricEncryptingContext context(ECB, ANSI_X_923, std::nullopt, testAlgorithm);

    auto encryptedFuture = context.encrypt(testData);
    auto decryptedFuture = context.decrypt(encryptedFuture.get());

    INFO result = decryptedFuture.get();

    bool passed = compareVectors(testData, result);
    printTestResult("ANSI X.923 Padding Test", passed);
}

void TestSymmetricContext::testPKCS7Padding() {
    std::cout << "\n=== Testing PKCS7 Padding ===" << std::endl;

    INFO testData = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}}; // 3 bytes, needs padding

    SymmetricEncryptingContext context(ECB, PKCS7, std::nullopt, testAlgorithm);

    auto encryptedFuture = context.encrypt(testData);
    auto decryptedFuture = context.decrypt(encryptedFuture.get());

    INFO result = decryptedFuture.get();

    bool passed = compareVectors(testData, result);
    printTestResult("PKCS7 Padding Test", passed);
}

void TestSymmetricContext::testISO10126Padding() {
    std::cout << "\n=== Testing ISO 10126 Padding ===" << std::endl;

    INFO testData = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}}; // 3 bytes, needs padding

    SymmetricEncryptingContext context(ECB, ISO_10126, std::nullopt, testAlgorithm);

    auto encryptedFuture = context.encrypt(testData);
    auto decryptedFuture = context.decrypt(encryptedFuture.get());

    INFO result = decryptedFuture.get();

    bool passed = compareVectors(testData, result);
    printTestResult("ISO 10126 Padding Test", passed);
}

void TestSymmetricContext::testAllModes() {
    std::cout << "=== Testing All Encryption Modes ===" << std::endl;

    testECBMode();
    testCBCMode();
    testPCBCMode();
    testCFBMode();
    testOFBMode();
    testCTRMode();
    testRandomDeltaMode();
}

void TestSymmetricContext::testAllPaddingModes() {
    std::cout << "=== Testing All Padding Modes ===" << std::endl;

    testZerosPadding();
    testANSIX923Padding();
    testPKCS7Padding();
    testISO10126Padding();
}

void TestSymmetricContext::testFileEncryption(const std::string& testFileName) {
    std::cout << "\n=== Testing File Encryption ===" << std::endl;

    try {
        INFO init_vector{std::byte{165}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
                         std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF}};
        SymmetricEncryptingContext context(CTR, ANSI_X_923, init_vector, testAlgorithm);
        std::filesystem::path inputPath = testFileName;
        std::filesystem::path encryptedOutput = inputPath.stem().string() + "_encrypted.bin";
        std::filesystem::path decryptedOutput = inputPath.stem().string() + "_decrypted" + inputPath.extension().string();

        std::cout << "Input file: " << inputPath << std::endl;
        std::cout << "Encrypted file: " << encryptedOutput << std::endl;
        std::cout << "Decrypted file: " << decryptedOutput << std::endl;
        auto encryptFuture = context.encrypt(inputPath, encryptedOutput);
        encryptFuture.get();
        std::cout << "File encrypted successfully" << std::endl;
        auto decryptFuture = context.decrypt(encryptedOutput, decryptedOutput);
        decryptFuture.get();
        std::cout << "File decrypted successfully" << std::endl;

    } catch (const std::exception& e) {
        std::cout << "File Encryption Test: FAILED - " << e.what() << std::endl;

        // Clean up on failure
        std::filesystem::remove(testFileName);
        std::filesystem::remove("encrypted_test_file.bin");
        std::filesystem::remove("decrypted_test_file.txt");

        // Also clean up any files that might have been created with new names
        std::filesystem::path inputPath = testFileName;
        std::filesystem::remove(inputPath.stem().string() + "_encrypted.bin");
        std::filesystem::remove(inputPath.stem().string() + "_decrypted" + inputPath.extension().string());
    }
}