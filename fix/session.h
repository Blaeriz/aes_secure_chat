#pragma once

#include "codec.h"
#include <string>

namespace fix {

enum class SessionState {
    DISCONNECTED,
    LOGON_SENT,
    ACTIVE,
    LOGOUT_SENT
};

class Session {
public:
    Session(const std::string& sender_id, const std::string& target_id);

    Message prepare_message(const std::string& msgType);
    void on_message_received(const Message& msg);
    
    SessionState get_state() const { return state; }
    void set_state(SessionState s) { state = s; }

    int get_out_seq_num() const { return out_seq_num; }
    int get_expected_in_seq_num() const { return expected_in_seq_num; }

private:
    std::string sender_comp_id;
    std::string target_comp_id;
    int out_seq_num;
    int expected_in_seq_num;
    SessionState state;
};

} // namespace fix
