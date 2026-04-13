#pragma once

#include "codec.h"
#include <string>
#include <map>
#include <vector>

namespace simulator {

struct Order {
    std::string cl_ord_id;
    std::string order_id;
    std::string symbol;
    char side;
    double quantity;
    char type;
    double price;
    char status;
};

class Exchange {
public:
    std::vector<fix::Message> process_message(const fix::Message& msg);

private:
    std::map<std::string, Order> orders;
    int next_order_id = 1;
    int next_exec_id = 1;

    fix::Message create_execution_report(const Order& order, char exec_type, char ord_status);
};

} // namespace simulator
