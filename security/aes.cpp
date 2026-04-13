#include "aes.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <stdexcept>
#include <iomanip>
#include <sstream>
#include <cstring>

namespace security {

AesGcm::AesGcm(const std::string& hex_key) {
    key = hex_to_bytes(hex_key);
    if (key.size() != 32) {
        throw std::runtime_error("AES key must be 256 bits (64 hex chars)");
    }
}

std::string AesGcm::encrypt(const std::string& plaintext) {
    unsigned char nonce[12];
    RAND_bytes(nonce, sizeof(nonce));

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key.data(), nonce);

    std::vector<unsigned char> ciphertext(plaintext.length());
    int len;
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, (const unsigned char*)plaintext.data(), plaintext.length());
    
    int ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;

    unsigned char tag[16];
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(ctx);

    std::string result;
    result.append((char*)nonce, 12);
    result.append((char*)ciphertext.data(), ciphertext_len);
    result.append((char*)tag, 16);
    
    return result;
}

std::string AesGcm::decrypt(const std::string& ciphertext_raw) {
    if (ciphertext_raw.length() < 12 + 16) {
        throw std::runtime_error("Ciphertext too short");
    }

    const unsigned char* nonce = (const unsigned char*)ciphertext_raw.data();
    const unsigned char* ciphertext = (const unsigned char*)ciphertext_raw.data() + 12;
    int ciphertext_len = ciphertext_raw.length() - 12 - 16;
    const unsigned char* tag = (const unsigned char*)ciphertext_raw.data() + ciphertext_raw.length() - 16;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key.data(), nonce);

    std::vector<unsigned char> plaintext(ciphertext_len);
    int len;
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext, ciphertext_len);
    
    int plaintext_len = len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag);
    
    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        plaintext_len += len;
        return std::string((char*)plaintext.data(), plaintext_len);
    } else {
        throw std::runtime_error("AES decryption failed (auth tag mismatch)");
    }
}

std::vector<unsigned char> AesGcm::hex_to_bytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    for (unsigned int i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = (unsigned char)strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

} // namespace security
