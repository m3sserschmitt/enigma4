cmake_minimum_required(VERSION 3.0.0)
project(libnet VERSION 1.0.0)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../libcryptography/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../libutil/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

add_library(net SHARED
./message/message_builder.cc
./message/message_parser.cc
./message/message.cc
./session/session.cc
./socket/socket.cc
./socket/tls_socket.cc
)

set_target_properties(net PROPERTIES VERSION ${PROJECT_VERSION} SOVERSION 1)

add_library(net1 STATIC
./message/message_builder.cc
./message/message_parser.cc
./message/message.cc
./session/session.cc
./socket/socket.cc
./socket/tls_socket.cc
)

target_link_libraries(net cryptography)
target_link_libraries(net1 cryptography)
target_link_libraries(net util)
target_link_libraries(net1 util)
target_link_libraries(net ssl)
target_link_libraries(net1 ssl)
