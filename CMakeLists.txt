cmake_minimum_required(VERSION 3.0.0)
project(enigma4 VERSION 0.1.0)

include(CTest)
enable_testing()

add_executable(enigma4 main.cc server.cc osocket.cc onion_routing.cc message.cc message_parser.cc message_builder.cc util.cc client.cc)
add_executable(client eclient.cc client.cc osocket.cc message.cc message_builder.cc message_parser.cc util.cc)
add_executable(tests test.cc message.cc message_builder.cc message_parser.cc util.cc)

target_link_libraries(enigma4 cryptography)
target_link_libraries(client cryptography)
target_link_libraries(tests cryptography)

target_link_libraries(enigma4 pthread)
target_link_libraries(client pthread)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
