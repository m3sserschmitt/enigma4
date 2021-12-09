cmake_minimum_required(VERSION 3.0.0)
project(enigma4 VERSION 4.0.0)


add_subdirectory(libcryptography)


add_library(util STATIC util/cmd.cc util/system_time.cc util/util.cc util/error.cc)


add_library(netessentials STATIC
networking/socket.cc 
enigma4/server.cc
enigma4/tls_server.cc

networking/tls_socket.cc 
networking/network_bridge.cc

onion_routing/client.cc
onion_routing/tls_client.cc

protocol/message.cc 
protocol/message_builder.cc 
protocol/message_parser.cc 
)
target_link_libraries(netessentials util cryptography6 crypto ssl)


add_library(onionr STATIC 
onion_routing/onion_routing_app.cc
onion_routing/route.cc
onion_routing/session.cc
)
target_link_libraries(onionr netessentials pthread)


add_executable(enigma4 enigma4/main.cc)
target_link_libraries(enigma4 onionr)


add_executable(eclient example/eclient.cc)
target_link_libraries(eclient onionr)

add_executable(tls_server tests/tls_server.cc)
target_link_libraries(tls_server onionr)

add_executable(tls_client tests/tls_client.cc)
target_link_libraries(tls_client onionr)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
