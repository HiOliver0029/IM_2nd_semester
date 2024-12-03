#include <openssl/aes.h>
#include <openssl/rand.h>
#include <fstream>
#include <iostream>
#include <vector>

// AES Key size
const int AES_KEY_SIZE = 32;  // 256-bit key

// Function to read file into a vector
std::vector<unsigned char> readFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    return std::vector<unsigned char>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

// Function to write a vector to a file
void writeFile(const std::string& filename, const std::vector<unsigned char>& data) {
    std::ofstream file(filename, std::ios::binary);
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
}

// Generate a random AES key
std::vector<unsigned char> generateRandomKey(int length) {
    std::vector<unsigned char> key(length);
    if (!RAND_bytes(key.data(), length)) {
        throw std::runtime_error("Random key generation failed");
    }
    return key;
}

// Encrypt data using AES CBC mode
std::vector<unsigned char> aesEncrypt(const std::vector<unsigned char>& data, const std::vector<unsigned char>& key) {
    std::vector<unsigned char> ciphertext(data.size() + AES_BLOCK_SIZE);

    AES_KEY encryptKey;
    AES_set_encrypt_key(key.data(), AES_KEY_SIZE * 8, &encryptKey);

    unsigned char iv[AES_BLOCK_SIZE] = {0};
    RAND_bytes(iv, AES_BLOCK_SIZE);

    int outLen = 0;
    AES_cbc_encrypt(data.data(), ciphertext.data(), data.size(), &encryptKey, iv, AES_ENCRYPT);

    return ciphertext;
}

// Decrypt data using AES CBC mode
std::vector<unsigned char> aesDecrypt(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& key) {
    std::vector<unsigned char> decrypted(ciphertext.size());

    AES_KEY decryptKey;
    AES_set_decrypt_key(key.data(), AES_KEY_SIZE * 8, &decryptKey);

    unsigned char iv[AES_BLOCK_SIZE] = {0};
    int outLen = 0;
    AES_cbc_encrypt(ciphertext.data(), decrypted.data(), ciphertext.size(), &decryptKey, iv, AES_DECRYPT);

    return decrypted;
}

int main() {
    try {
        // // Encrypt the file
        // std::vector<unsigned char> data = readFile("signBT.py");
        // std::vector<unsigned char> aesKey = generateRandomKey(AES_KEY_SIZE);
        
        // std::vector<unsigned char> encryptedData = aesEncrypt(data, aesKey);
        
        // // Write key+encrypted data to output
        // encryptedData.insert(encryptedData.begin(), aesKey.begin(), aesKey.end());  // Prepend key
        // writeFile("tw-100a-a00-e14d9.tmp", encryptedData);
        
        // Decrypt the file
        std::vector<unsigned char> encryptedFile = readFile("tw-100a-a00-e14d9.tmp");
        
        // Extract key and encrypted data
        std::vector<unsigned char> key(encryptedFile.begin(), encryptedFile.begin() + AES_KEY_SIZE);
        std::vector<unsigned char> encryptedContent(encryptedFile.begin() + AES_KEY_SIZE, encryptedFile.end());
        
        std::vector<unsigned char> decryptedData = aesDecrypt(encryptedContent, key);
        writeFile("decrypted_signBT.py", decryptedData);


        std::vector<unsigned char> encryptedFile2 = readFile("tw-100b-a00-e14d9.tmp");
        
        // Extract key and encrypted data
        std::vector<unsigned char> key2(encryptedFile2.begin(), encryptedFile2.begin() + AES_KEY_SIZE);
        std::vector<unsigned char> encryptedContent2(encryptedFile2.begin() + AES_KEY_SIZE, encryptedFile2.end());
        
        std::vector<unsigned char> decryptedData2 = aesDecrypt(encryptedContent2, key2);
        writeFile("decrypted_config.txt", decryptedData2);
        
        std::cout << "File decrypted successfully!" << std::endl;
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
    }
    
    return 0;
}
