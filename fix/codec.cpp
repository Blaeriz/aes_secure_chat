#include "codec.h"
#include <sstream>
#include <iomanip>
#include <numeric>
#include <stdexcept>
#include <algorithm>
#include <iostream>

namespace fix {

Message::Message(const std::string& msgType) {
    set(35, msgType);
}

void Message::set(int tag, const std::string& value) {
    fields[tag] = value;
}

void Message::set(int tag, int value) {
    fields[tag] = std::to_string(value);
}

void Message::set(int tag, double value) {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2) << value;
    fields[tag] = oss.str();
}

std::optional<std::string> Message::get(int tag) const {
    auto it = fields.find(tag);
    if (it != fields.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::string Message::get_required(int tag) const {
    auto val = get(tag);
    if (!val) {
        throw std::runtime_error("Required tag " + std::to_string(tag) + " not found");
    }
    return *val;
}

std::string Message::serialize() const {
    // 8, 9, 35 must be first
    // 10 must be last
    
    std::string body;
    // Collect all fields except 8, 9, 10
    std::vector<int> tags;
    for (const auto& [tag, _] : fields) {
        if (tag != 8 && tag != 9 && tag != 10 && tag != 35) {
            tags.push_back(tag);
        }
    }

    auto append_field = [&](std::string& target, int tag, const std::string& value) {
        target += std::to_string(tag) + "=" + value + SOH;
    };

    std::string msg_body;
    append_field(msg_body, 35, get_required(35));
    for (int tag : tags) {
        append_field(msg_body, tag, fields.at(tag));
    }

    int body_len = msg_body.length();
    
    std::string header;
    append_field(header, 8, get_required(8));
    append_field(header, 9, std::to_string(body_len));
    
    std::string full_msg = header + msg_body;
    
    unsigned int sum = 0;
    for (char c : full_msg) {
        sum += static_cast<unsigned char>(c);
    }
    
    std::ostringstream oss;
    oss << std::setfill('0') << std::setw(3) << (sum % 256);
    std::string checksum = oss.str();
    
    append_field(full_msg, 10, checksum);
    
    return full_msg;
}

Message Message::parse(const std::string& raw) {
    // Basic validation
    if (raw.substr(0, 2) != "8=") {
        throw std::runtime_error("Invalid FIX message: doesn't start with 8=");
    }

    Message msg;
    size_t pos = 0;
    while (pos < raw.length()) {
        size_t eq_pos = raw.find('=', pos);
        if (eq_pos == std::string::npos) break;
        
        std::string tag_str = raw.substr(pos, eq_pos - pos);
        int tag;
        try {
            tag = std::stoi(tag_str);
        } catch (const std::exception& e) {
            std::cerr << "Error parsing tag: '" << tag_str << "' at pos " << pos << " in: " << raw << std::endl;
            throw;
        }
        
        size_t soh_pos = raw.find(SOH, eq_pos + 1);
        if (soh_pos == std::string::npos) break;
        
        std::string value = raw.substr(eq_pos + 1, soh_pos - (eq_pos + 1));
        msg.set(tag, value);
        pos = soh_pos + 1;
    }

    // Validate BodyLength (tag 9)
    if (msg.get(9)) {
        int expected_len = std::stoi(*msg.get(9));
        size_t tag9_idx = raw.find("\x01" "9=");
        size_t body_start = raw.find(SOH, tag9_idx + 3) + 1;
        size_t tag10_idx = raw.find("\x01" "10=");
        int actual_len = tag10_idx - body_start;
        if (actual_len != expected_len) {
             std::cerr << "Warning: BodyLength mismatch. Expected: " << expected_len << " Actual: " << actual_len << std::endl;
        }
    }

    // Validate CheckSum (tag 10)
    if (msg.get(10)) {
        std::string expected_checksum = *msg.get(10);
        size_t tag10_idx = raw.find("\x01" "10=");
        std::string raw_before_checksum = raw.substr(0, tag10_idx + 1);
        
        unsigned int sum = 0;
        for (char c : raw_before_checksum) {
            sum += static_cast<unsigned char>(c);
        }
        
        std::ostringstream oss;
        oss << std::setfill('0') << std::setw(3) << (sum % 256);
        std::string actual_checksum = oss.str();
        
        if (actual_checksum != expected_checksum) {
            std::cerr << "Warning: CheckSum mismatch. Expected: " << expected_checksum << " Actual: " << actual_checksum << std::endl;
        }
    }

    return msg;
}

std::string Message::to_string() const {
    std::string res;
    for (const auto& [tag, val] : fields) {
        res += std::to_string(tag) + "=" + val + "|";
    }
    return res;
}

} // namespace fix
