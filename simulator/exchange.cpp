#include "exchange.h"
#include <iostream>

namespace simulator {

std::vector<fix::Message> Exchange::process_message(const fix::Message& msg) {
    std::vector<fix::Message> responses;
    std::string msgType = msg.get_required(35);

    if (msgType == "D") { // NewOrderSingle
        Order o;
        o.cl_ord_id = msg.get_required(11);
        o.order_id = std::to_string(next_order_id++);
        o.symbol = msg.get_required(55);
        o.side = msg.get_required(54)[0];
        o.quantity = std::stod(msg.get_required(38));
        o.type = msg.get_required(40)[0];
        
        if (o.type == '1') { // Market
            o.status = '2'; // Filled
            responses.push_back(create_execution_report(o, 'F', '2'));
        } else { // Limit
            o.price = std::stod(msg.get_required(44));
            o.status = '0'; // New
            responses.push_back(create_execution_report(o, '0', '0'));
            
            // For sim, let's fill it immediately too
            o.status = '2'; // Filled
            responses.push_back(create_execution_report(o, 'F', '2'));
        }
        orders[o.cl_ord_id] = o;
    } else if (msgType == "F") { // OrderCancelRequest
        std::string orig_cl_ord_id = msg.get_required(41);
        if (orders.count(orig_cl_ord_id)) {
            Order& o = orders[orig_cl_ord_id];
            o.status = '4'; // Canceled
            responses.push_back(create_execution_report(o, '4', '4'));
        } else {
            // Should send OrderCancelReject
        }
    }

    return responses;
}

fix::Message Exchange::create_execution_report(const Order& order, char exec_type, char ord_status) {
    fix::Message report("8");
    report.set(37, order.order_id);
    report.set(11, order.cl_ord_id);
    report.set(17, std::to_string(next_exec_id++));
    report.set(150, std::string(1, exec_type));
    report.set(39, std::string(1, ord_status));
    report.set(55, order.symbol);
    report.set(54, std::string(1, order.side));
    report.set(38, order.quantity);
    report.set(14, order.quantity); // CumQty
    report.set(151, 0.0); // LeavesQty
    return report;
}

} // namespace simulator
