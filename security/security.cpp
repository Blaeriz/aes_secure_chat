#include "security.h"
#include <iostream>
#include <iomanip>
#include <sstream>

namespace security {

SecurityLayer::SecurityLayer(bool aes_enabled, const std::string& hex_key) : aes_enabled(aes_enabled) {
    if (aes_enabled) {
        aes = std::make_unique<AesGcm>(hex_key);
    }
}

std::string SecurityLayer::encrypt_message(const std::string& raw_fix) {
    if (!aes_enabled) return raw_fix;

    // 8=FIX.4.2\x019=XXX\x01BODY...10=XXX\x01
    size_t tag9_pos = raw_fix.find("\x01" "9=");
    if (tag9_pos == std::string::npos) return raw_fix;
    
    size_t body_start = raw_fix.find('\x01', tag9_pos + 3);
    if (body_start == std::string::npos) return raw_fix;
    body_start++;

    size_t tag10_pos = raw_fix.find("\x01" "10=", body_start);
    if (tag10_pos == std::string::npos) return raw_fix;
    
    std::string body = raw_fix.substr(body_start, tag10_pos - body_start);
    std::string encrypted_body = aes->encrypt(body);
    
    std::string header_prefix = raw_fix.substr(0, tag9_pos + 3); // "8=FIX.4.2\x019="
    
    std::string new_msg_body = header_prefix + std::to_string(encrypted_body.length()) + "\x01" + encrypted_body;
    
    unsigned int sum = 0;
    for (char c : new_msg_body) sum += static_cast<unsigned char>(c);
    sum += 1; // SOH

    std::ostringstream oss;
    oss << "\x01" << "10=" << std::setfill('0') << std::setw(3) << (sum % 256) << "\x01";
    
    return new_msg_body + oss.str();
}

std::string SecurityLayer::decrypt_message(const std::string& raw_fix) {
    if (!aes_enabled) return raw_fix;

    size_t tag9_pos = raw_fix.find("\x01" "9=");
    if (tag9_pos == std::string::npos) {
        std::cerr << "decrypt_message: tag 9 not found in raw message of length " << raw_fix.length() << std::endl;
        return raw_fix;
    }
    
    size_t body_start = raw_fix.find('\x01', tag9_pos + 3);
    if (body_start == std::string::npos) return raw_fix;
    body_start++;

    size_t tag10_pos = raw_fix.find("\x01" "10=", body_start);
    if (tag10_pos == std::string::npos) return raw_fix;
    
    std::string encrypted_body = raw_fix.substr(body_start, tag10_pos - body_start);
    std::string decrypted_body = aes->decrypt(encrypted_body);
    
    std::string header_prefix = raw_fix.substr(0, tag9_pos + 3);
    std::string new_msg_body = header_prefix + std::to_string(decrypted_body.length()) + "\x01" + decrypted_body;
    
    unsigned int sum = 0;
    for (char c : new_msg_body) sum += static_cast<unsigned char>(c);
    sum += 1; // SOH

    std::ostringstream oss;
    oss << "\x01" << "10=" << std::setfill('0') << std::setw(3) << (sum % 256) << "\x01";
    
    return new_msg_body + oss.str();
}

} // namespace security
