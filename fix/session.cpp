#include "session.h"
#include <chrono>
#include <iomanip>
#include <sstream>

namespace fix {

Session::Session(const std::string& sender_id, const std::string& target_id)
    : sender_comp_id(sender_id), target_comp_id(target_id), 
      out_seq_num(1), expected_in_seq_num(1), state(SessionState::DISCONNECTED) {}

Message Session::prepare_message(const std::string& msgType) {
    Message msg(msgType);
    msg.set(8, "FIX.4.2");
    msg.set(49, sender_comp_id);
    msg.set(56, target_comp_id);
    msg.set(34, out_seq_num++);
    
    // Set SendingTime
    auto now = std::chrono::system_clock::now();
    auto tt = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
    
    std::tm tm = *std::gmtime(&tt);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y%m%d-%H:%M:%S") << "." << std::setfill('0') << std::setw(3) << ms.count();
    msg.set(52, oss.str());

    return msg;
}

void Session::on_message_received(const Message& msg) {
    int seq_num = std::stoi(msg.get_required(34));
    
    if (seq_num == expected_in_seq_num) {
        expected_in_seq_num++;
    } else if (seq_num > expected_in_seq_num) {
        // ResendRequest should be emitted here
        // For now, just advance
        expected_in_seq_num = seq_num + 1;
    } else {
        // Dupe detected
    }
}

} // namespace fix
