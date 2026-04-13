#pragma once

#include <string>
#include <vector>

namespace security {

class AesGcm {
public:
    AesGcm(const std::string& hex_key);

    std::string encrypt(const std::string& plaintext);
    std::string decrypt(const std::string& ciphertext);

private:
    std::vector<unsigned char> key;
    
    std::vector<unsigned char> hex_to_bytes(const std::string& hex);
};

} // namespace security
