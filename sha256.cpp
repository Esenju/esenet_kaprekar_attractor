// Peter Mbua 
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <openssl/evp.h> 


std::string generate_sha256(const std::string& input) {
    // Create a context for the message digest 
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (context == nullptr) return "";

    const EVP_MD* md = EVP_sha256();
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;

    // Initialize, Update with data, and Finalize the hash
    if (EVP_DigestInit_ex(context, md, nullptr) &&
        EVP_DigestUpdate(context, input.c_str(), input.length()) &&
        EVP_DigestFinal_ex(context, hash, &lengthOfHash)) {
        
        EVP_MD_CTX_free(context);

        // Convert byte array to hex string
        std::stringstream ss;
        for (unsigned int i = 0; i < lengthOfHash; ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        }
        return ss.str();
    }

    EVP_MD_CTX_free(context);
    return "";
}

int main() {
    std::string userInput;
    std::cout << "Enter text to hash: ";
    std::getline(std::cin, userInput);

    std::string fingerprint = generate_sha256(userInput);

    if (!fingerprint.empty()) {
        std::cout << "SHA-256 Fingerprint: " << fingerprint << std::endl;
    } else {
        std::cerr << "Error generating hash." << std::endl;
    }

    return 0;
}