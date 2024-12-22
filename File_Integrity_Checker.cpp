#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <filesystem>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <map>
#include <chrono>
#include <thread>

namespace fs = std::filesystem;

std::string ComputeSHA256(const std::string& filePath){
    std::ifstream file(filePath, std::ios::binary);
    if(!file) 
        throw std::runtime_error("Cannot open file!");

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if(!mdctx) 
        throw std::runtime_error("Failed to create EVP_MD_CTX!");

    const EVP_MD* md = EVP_sha256();
    if(EVP_DigestInit_ex(mdctx, md, nullptr) != 1){
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Failed to initialize digest!");
    }

    char buffer[4096];
    while(file.read(buffer, sizeof(buffer))){
        if(EVP_DigestUpdate(mdctx, buffer, file.gcount()) != 1){
            EVP_MD_CTX_free(mdctx);
            throw std::runtime_error("Failed to update digest!");
        }
    }

    if(EVP_DigestUpdate(mdctx, buffer, file.gcount()) != 1){
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Failed to update digest!");
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLength;
    if(EVP_DigestFinal_ex(mdctx, hash, &hashLength) != 1){
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Failed to finalize digest!");
    }

    EVP_MD_CTX_free(mdctx);

    std::ostringstream oss;
    for(unsigned int i = 0; i < hashLength; i++){
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }

    return oss.str();
}

std::map<std::string, std::string> ScanDirectory(const std::string& dirPath){
    std::map<std::string, std::string> fileHashes;

    for(const auto& entry : fs::recursive_directory_iterator(dirPath)){
        if(fs::is_regular_file(entry)){
            try{
                std::string hash = ComputeSHA256(entry.path().string());
                fileHashes[entry.path().string()] = hash;
            }
            catch(const std::exception& ex){
                std::cerr << "Error processing file: " << entry.path() << "\n" << ex.what() << "\n";
            }
        }
    }
    return fileHashes;
}

void MonitorDirectory(const std::string& dirPath, int intervalSeconds){
    std::map<std::string, std::string> initialHashes = ScanDirectory(dirPath);

    while(true){
        std::this_thread::sleep_for(std::chrono::seconds(intervalSeconds));
        std::map<std::string, std::string> currentHashes = ScanDirectory(dirPath);
        for(const auto& [filePath, hash] : currentHashes){
            if(initialHashes.find(filePath) == initialHashes.end()){
                std::cout << "[ADDED] " << filePath << "\n";
            }
            else if(initialHashes[filePath] != hash){
                std::cout << "[MODIFIED] " << filePath << "\n";
            }
        }
        for(const auto& [filePath, hash] : initialHashes){
            if(currentHashes.find(filePath) == currentHashes.end()){
                std::cout << "[DELETED] " << filePath << "\n";
            }
        }
        initialHashes = currentHashes;
    }
}

int main(){
    std::string directoryPath;
    int interval;

    std::cout << "Enter the directory path to monitor: ";
    std::cin >> directoryPath;

    std::cout << "Enbter the monitor interval in second: ";
    std::cin >> interval;

    try{
        MonitorDirectory(directoryPath, interval);
    }
    catch(const std::exception& ex){
        std::cerr << "Error: " << ex.what() << "\n";
    }

    return 0;
}