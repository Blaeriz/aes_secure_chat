cmake_minimum_required(VERSION 3.10)
project(fix_stack CXX)

set(CMAKE_CXX_STANDARD 17)

find_package(OpenSSL REQUIRED)

add_library(fix_codec fix/codec.cpp)
target_include_directories(fix_codec PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/fix)

add_library(fix_session fix/session.cpp)
target_link_libraries(fix_session fix_codec)
target_include_directories(fix_session PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/fix)

add_library(security security/aes.cpp security/tls.cpp security/security.cpp)
target_link_libraries(security OpenSSL::SSL OpenSSL::Crypto)
target_include_directories(security PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/security)

add_library(transport transport/tcp.cpp)
target_include_directories(transport PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/transport ${CMAKE_CURRENT_SOURCE_DIR}/security)
target_link_libraries(transport OpenSSL::SSL security)

add_library(exchange simulator/exchange.cpp)
target_link_libraries(exchange fix_codec)
target_include_directories(exchange PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/simulator)

add_executable(main_server main_server.cpp)
target_link_libraries(main_server fix_codec fix_session transport security exchange OpenSSL::SSL OpenSSL::Crypto)
