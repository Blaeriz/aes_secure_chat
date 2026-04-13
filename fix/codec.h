#pragma once

#include <string>
#include <map>
#include <vector>
#include <optional>

namespace fix {

class Message {
public:
    Message() = default;
    Message(const std::string& msgType);

    void set(int tag, const std::string& value);
    void set(int tag, int value);
    void set(int tag, double value);

    std::optional<std::string> get(int tag) const;
    std::string get_required(int tag) const;

    std::string serialize() const;
    static Message parse(const std::string& raw);

    // Helper for debugging
    std::string to_string() const;

    const std::map<int, std::string>& get_fields() const { return fields; }

private:
    std::map<int, std::string> fields;
    
    static const char SOH = '\x01';
    
    std::string calculate_checksum(const std::string& data) const;
    int calculate_body_length(const std::string& body) const;
};

} // namespace fix
