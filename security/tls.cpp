#include "tls.h"
#include <iostream>
#include <unistd.h>

namespace security {

TlsContext::TlsContext(bool is_server, const std::string& cert_path, const std::string& key_path) : is_server(is_server) {
    init_openssl();
    ctx = create_context();
    if (is_server) {
        configure_context(cert_path, key_path);
    }
}

TlsContext::~TlsContext() {
    SSL_CTX_free(ctx);
    cleanup_openssl();
}

void TlsContext::init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void TlsContext::cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX* TlsContext::create_context() {
    const SSL_METHOD* method;
    SSL_CTX* ctx;

    method = is_server ? TLS_server_method() : TLS_client_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void TlsContext::configure_context(const std::string& cert_path, const std::string& key_path) {
    if (SSL_CTX_use_certificate_file(ctx, cert_path.c_str(), SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key_path.c_str(), SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

SSL* TlsContext::wrap_socket(int fd) {
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);

    if (is_server) {
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            return nullptr;
        }
    } else {
        if (SSL_connect(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            return nullptr;
        }
    }

    return ssl;
}

} // namespace security
