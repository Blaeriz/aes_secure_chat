#include "codec.h"
#include "session.h"
#include "tcp.h"
#include "exchange.h"
#include "security.h"
#include <iostream>

int main() {
    bool aes_enabled = true;
    std::string aes_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    try {
        transport::TcpServer server(9878, true, "certs/cert.pem", "certs/key.pem");
        fix::Session session("EXCHANGE", "CLIENT1");
        simulator::Exchange exchange;
        security::SecurityLayer security_layer(aes_enabled, aes_key);

        server.listen_and_accept();

        while (true) {
            std::string raw = server.receive_message();
            std::string decrypted = security_layer.decrypt_message(raw);
            
            fix::Message msg = fix::Message::parse(decrypted);
            std::cout << "Received: " << msg.to_string() << std::endl;

            session.on_message_received(msg);
            std::string msgType = msg.get_required(35);

            auto send_msg = [&](fix::Message& out_msg) {
                std::string serialized = out_msg.serialize();
                std::string encrypted = security_layer.encrypt_message(serialized);
                server.send(encrypted);
            };

            if (msgType == "A") { // Logon
                session.set_state(fix::SessionState::ACTIVE);
                fix::Message response = session.prepare_message("A");
                response.set(98, 0);
                response.set(108, 30);
                
                std::cout << "Sending Logon ACK" << std::endl;
                send_msg(response);
            } else if (msgType == "5") { // Logout
                fix::Message response = session.prepare_message("5");
                std::cout << "Sending Logout ACK" << std::endl;
                send_msg(response);
                break;
            } else if (msgType == "D") { // NewOrderSingle
                std::vector<fix::Message> reports = exchange.process_message(msg);
                for (const auto& report : reports) {
                    fix::Message out_msg = session.prepare_message("8");
                    for (auto const& [tag, val] : report.get_fields()) {
                        if (tag != 34 && tag != 8 && tag != 9 && tag != 10 && tag != 52 && tag != 49 && tag != 56) {
                            out_msg.set(tag, val);
                        }
                    }
                    std::cout << "Sending ExecReport: " << out_msg.to_string() << std::endl;
                    send_msg(out_msg);
                }
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return 0;
}
