cmake_minimum_required(VERSION 3.0.0)
project(enigma4 VERSION 4.0.0)

add_executable(enigma4 main.cc cmd.cc server.cc socket.cc onion_routing.cc message.cc message_parser.cc message_builder.cc util.cc)
add_executable(client eclient.cc cmd.cc client.cc socket.cc tls_socket.cc message.cc message_builder.cc message_parser.cc util.cc)
add_executable(test test.cc socket.cc tls_socket.cc)

target_link_libraries(enigma4 cryptography6)
target_link_libraries(enigma4 crypto)
target_link_libraries(enigma4 pthread)

target_link_libraries(client cryptography)
target_link_libraries(client pthread)
target_link_libraries(client ssl)

target_link_libraries(test ssl)
target_link_libraries(test crypto)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)