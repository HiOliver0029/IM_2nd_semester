#include <windows.h>
#include <iostream>
#include <string>
#include <fstream>
#include <vector>

std::string GetMachineGuid() {
    HKEY hKey;
    const char* subkey = "SOFTWARE\\Microsoft\\Cryptography";
    const char* valueName = "MachineGuid";
    char value[256];
    DWORD value_length = sizeof(value); // 1 dword = 2 words = 4 bytes = 32 bits

    // 打開註冊表
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, subkey, 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
        // 查詢 MachineGuid 的值
        if (RegQueryValueExA(hKey, valueName, NULL, NULL, (LPBYTE)&value, &value_length) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return std::string(value);
        }
        RegCloseKey(hKey);
    }
    return "";
}

// 讀取加密文件
std::vector<BYTE> readEncryptedFile(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << filePath << std::endl;
        return {};
    }
    return std::vector<BYTE>(std::istreambuf_iterator<char>(file), {});
}

DWORD FindExpectedMachineGuidInDLL(const BYTE* dllData, size_t dllSize) {
    // 嵌入的序列，根據描述應為 "43 EB 8C BD 1D 98 3D 14"，實作時是放在payload的後面，跟原先序列會不同
    const BYTE sequence[] = { 0x43, 0xEB, 0x8C, 0xBD, 0x1D, 0x98, 0x3D, 0x14 };

    for (size_t i = 0; i < dllSize - sizeof(sequence); i++) {
        if (memcmp(dllData + i, sequence, sizeof(sequence)) == 0) {
            // 序列後面的 DWORD
            DWORD embeddedGuid;
            memcpy(&embeddedGuid, dllData + i + sizeof(sequence), sizeof(DWORD));
            return embeddedGuid;
        }
    }
    return 0;
}

int main() {
    // 讀取 victim 的 MachineGuid
    std::string victimGuid = GetMachineGuid();
    std::cout << "Victim MachineGuid: " << victimGuid << std::endl;

    // // 假設我們已經有 DLL 的數據，這裡你可以從文件或內存中讀取
    // BYTE dllData[] = { /* DLL 的字節數據 */ };
    // size_t dllSize = sizeof(dllData);
    // // 從 DLL 中定位預期的 MachineGuid
    // DWORD expectedGuid = FindExpectedMachineGuidInDLL(dllData, dllSize);
    // std::cout << expectedGuid;
    
    // 加密文件的路徑是 "tw-100a-a00-e14d9.tmp"，這個文件的最後面是guid
    std::string encryptedFilePath = "./tw-100a-a00-e14d9.tmp";
    std::vector<BYTE> encryptedData = readEncryptedFile(encryptedFilePath);
    if (encryptedData.empty()) {
        return -1;
    }

    // 查找是否有目標 MachineGuid 
    DWORD expectedGuid = FindExpectedMachineGuidInDLL(encryptedData.data(), encryptedData.size());
    if (expectedGuid != 0) {
        std::cout << "Found expected MachineGuid: " << expectedGuid << std::endl;
    } else {
        std::cout << "MachineGuid not found in the encrypted file." << std::endl;
    }

    // 比較兩者是否匹配
    if (victimGuid == std::to_string(expectedGuid)) {
        std::cout << "MachineGuid match." << std::endl;
        // 執行下一步操作
    } else {
        std::cout << "MachineGuid not match." << std::endl;
    }

    // // 查找 MachineGuid
    // DWORD expectedGuid = FindExpectedMachineGuidInDLL(encryptedData.data(), encryptedData.size());
    // if (expectedGuid == 0) {
    //     // std::cout << "Found expected MachineGuid: " << expectedGuid << std::endl;
    //     std::cout << "Found expected MachineGuid." << std::endl;
    // } else {
    //     std::cout << "MachineGuid not found in the encrypted file." << std::endl;
    // }

    // // 比較兩者是否匹配
    // if (victimGuid != std::to_string(expectedGuid)) {
    //     std::cout << "MachineGuid match." << std::endl;
    //     // 執行下一步操作
    // } else {
    //     std::cout << "MachineGuid not match." << std::endl;
    // }

    return 0;
}
