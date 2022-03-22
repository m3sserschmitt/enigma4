cmake_minimum_required(VERSION 3.0.0)

project(libenigma4-client VERSION 1.0.0)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../libcryptography/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../libnet/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../libutil/include)

add_library(enigma4-client SHARED ./client.cc)
set_target_properties(enigma4-client PROPERTIES VERSION ${PROJECT_VERSION} SOVERSION 1)

add_library(enigma4-client1 STATIC ./client.cc)
