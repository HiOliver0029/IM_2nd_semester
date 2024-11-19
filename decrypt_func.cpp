#include <iostream>
#include <fstream>
#include <vector>
#include <openssl/aes.h>
#include <openssl/rand.h>

// 解密函數
std::vector<unsigned char> decrypt_payload(const std::vector<unsigned char>& key, const std::vector<unsigned char>& encrypted_data) {
    if (encrypted_data.size() < AES_BLOCK_SIZE) {
        throw std::length_error("Encrypted data is too small to contain IV and ciphertext.");
    }

    // 初始化解密後的數據，大小為加密數據 - IV 大小 (AES_BLOCK_SIZE)
    std::vector<unsigned char> decrypted_data(encrypted_data.size() - AES_BLOCK_SIZE);
    
    AES_KEY aes_key;
    AES_set_decrypt_key(key.data(), 256, &aes_key);

    unsigned char iv[AES_BLOCK_SIZE];
    std::copy(encrypted_data.begin(), encrypted_data.begin() + AES_BLOCK_SIZE, iv);  // 取得 IV
    
    // AES CBC 解密，移除 IV 部分
    AES_cbc_encrypt(encrypted_data.data() + AES_BLOCK_SIZE, decrypted_data.data(), encrypted_data.size() - AES_BLOCK_SIZE, &aes_key, iv, AES_DECRYPT);

    // 確認填充是否合法，避免長度錯誤
    if (decrypted_data.empty()) {
        throw std::length_error("Decrypted data is empty after AES decryption.");
    }

    // 去除填充（PKCS7）
    size_t pad_len = decrypted_data.back();
    if (pad_len > AES_BLOCK_SIZE || pad_len > decrypted_data.size()) {
        throw std::length_error("Invalid padding length detected.");
    }
    decrypted_data.resize(decrypted_data.size() - pad_len);

    return decrypted_data;
}

// 從檔案中讀取並解密
void decrypt_file(const std::string& file_path) {
    std::ifstream file(file_path, std::ios::binary);
    if (!file) {
        std::cerr << "Cannot open file: " << file_path << std::endl;
        return;
    }

    std::vector<unsigned char> file_content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    if (file_content.size() < 32) {
        std::cerr << "File content too small to contain valid key and encrypted data." << std::endl;
        return;
    }

    // 取得前 32 bytes 作為 key
    std::vector<unsigned char> key(file_content.begin(), file_content.begin() + 32);

    // 剩下的作為加密的數據
    std::vector<unsigned char> encrypted_data(file_content.begin() + 32, file_content.end());

    try {
        // 解密
        std::vector<unsigned char> decrypted_data = decrypt_payload(key, encrypted_data);
        std::cout << "Decrypted data: " << std::string(decrypted_data.begin(), decrypted_data.end()) << std::endl;
    } catch (const std::exception& ex) {
        std::cerr << "Error during decryption: " << ex.what() << std::endl;
    }
}

int main() {
    // decrypt_file("tw-100a-a00-e14d9.tmp");
    decrypt_file("tw-100b-a00-e14d9.tmp");
    return 0;
}
