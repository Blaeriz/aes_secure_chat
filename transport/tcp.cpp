#include "tcp.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdexcept>
#include <cstring>
#include <iostream>
#include <openssl/err.h>

namespace transport {

TcpServer::TcpServer(int port, bool use_tls, const std::string& cert_path, const std::string& key_path) 
    : port(port), server_fd(-1), client_fd(-1), use_tls(use_tls), ssl_ctx(nullptr), ssl(nullptr) {
    if (use_tls) {
        init_ssl(cert_path, key_path);
    }
}

TcpServer::~TcpServer() {
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (ssl_ctx) {
        SSL_CTX_free(ssl_ctx);
    }
    if (client_fd != -1) close(client_fd);
    if (server_fd != -1) close(server_fd);
}

void TcpServer::init_ssl(const std::string& cert_path, const std::string& key_path) {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    
    ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!ssl_ctx) {
        throw std::runtime_error("Unable to create SSL context");
    }

    if (SSL_CTX_use_certificate_file(ssl_ctx, cert_path.c_str(), SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("Error loading certificate");
    }

    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, key_path.c_str(), SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("Error loading private key");
    }
}

void TcpServer::listen_and_accept() {
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        throw std::runtime_error("Could not create socket");
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));

    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        throw std::runtime_error("Bind failed");
    }

    if (listen(server_fd, 3) < 0) {
        throw std::runtime_error("Listen failed");
    }

    std::cout << "Waiting for connection on port " << port << " (TLS: " << (use_tls ? "on" : "off") << ")..." << std::endl;

    int addrlen = sizeof(address);
    client_fd = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
    if (client_fd < 0) {
        throw std::runtime_error("Accept failed");
    }

    if (use_tls) {
        ssl = SSL_new(ssl_ctx);
        SSL_set_fd(ssl, client_fd);
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            throw std::runtime_error("SSL accept failed");
        }
    }

    std::cout << "Connected!" << std::endl;
}

void TcpServer::send(const std::string& data) {
    if (client_fd == -1) throw std::runtime_error("Not connected");
    if (use_tls) {
        SSL_write(ssl, data.c_str(), data.length());
    } else {
        ::send(client_fd, data.c_str(), data.length(), 0);
    }
}

std::string TcpServer::receive_message() {
    if (client_fd == -1) throw std::runtime_error("Not connected");

    char chunk[4096];
    while (true) {
        size_t tag10_pos = buffer.find("\x01" "10=");
        if (tag10_pos != std::string::npos) {
            size_t soh_pos = buffer.find('\x01', tag10_pos + 4);
            if (soh_pos != std::string::npos) {
                std::string msg = buffer.substr(0, soh_pos + 1);
                buffer.erase(0, soh_pos + 1);
                return msg;
            }
        }

        int bytes_read;
        if (use_tls) {
            bytes_read = SSL_read(ssl, chunk, sizeof(chunk));
        } else {
            bytes_read = recv(client_fd, chunk, sizeof(chunk), 0);
        }

        if (bytes_read <= 0) {
            throw std::runtime_error("Connection closed or error");
        }
        buffer.append(chunk, bytes_read);
    }
}

} // namespace transport
