#pragma once

#include "aes.h"
#include <string>
#include <memory>

namespace security {

class SecurityLayer {
public:
    SecurityLayer(bool aes_enabled = false, const std::string& hex_key = "");

    std::string encrypt_message(const std::string& raw_fix);
    std::string decrypt_message(const std::string& raw_fix);

private:
    bool aes_enabled;
    std::unique_ptr<AesGcm> aes;
};

} // namespace security
