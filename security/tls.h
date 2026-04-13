#pragma once

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string>

namespace security {

class TlsContext {
public:
    TlsContext(bool is_server, const std::string& cert_path = "", const std::string& key_path = "");
    ~TlsContext();

    SSL* wrap_socket(int fd);

private:
    SSL_CTX* ctx;
    bool is_server;

    void init_openssl();
    void cleanup_openssl();
    SSL_CTX* create_context();
    void configure_context(const std::string& cert_path, const std::string& key_path);
};

} // namespace security
