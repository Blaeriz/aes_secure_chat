#pragma once

#include <string>
#include <memory>
#include <openssl/ssl.h>
#include "aes.h"

namespace transport {

class TcpServer {
public:
    TcpServer(int port, bool use_tls = false, const std::string& cert_path = "", const std::string& key_path = "");
    ~TcpServer();

    void enable_aes(const std::string& hex_key);

    void listen_and_accept();
    void send(const std::string& data);
    std::string receive_message();

private:
    int server_fd;
    int client_fd;
    int port;
    bool use_tls;
    
    SSL_CTX* ssl_ctx;
    SSL* ssl;

    std::unique_ptr<security::AesGcm> aes;

    std::string buffer;
    
    void init_ssl(const std::string& cert_path, const std::string& key_path);
};

} // namespace transport
