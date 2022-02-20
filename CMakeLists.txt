cmake_minimum_required(VERSION 3.0.0)
project(enigma4 VERSION 4.0.0)


add_subdirectory(libcryptography)

add_library(util STATIC
util/cmd.cc 
util/system_time.cc 
util/util.cc 
util/error.cc
)

add_library(net STATIC
net/messages/message.cc
net/messages/message_builder.cc
net/messages/message_parser.cc
net/sockets/socket.cc
net/sockets/tls_socket.cc
net/session.cc
)

target_link_libraries(net util)

add_library(client STATIC client/client.cc)

target_link_libraries(client net)

add_executable(enigma4 
enigma4/server.cc
enigma4/onion_routing_app.cc
enigma4/main.cc
)

target_link_libraries(enigma4 client net cryptography6 ssl)

add_executable(eclient example/eclient.cc)

target_link_libraries(eclient client net cryptography6 ssl)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
