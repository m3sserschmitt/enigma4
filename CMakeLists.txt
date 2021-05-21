cmake_minimum_required(VERSION 3.0.0)
project(enigma4 VERSION 0.1.0)

include(CTest)
enable_testing()

add_executable(enigma4 main.cc server.cc onion_routing.cc message.cc util.cc)

add_library(cryptography-dev SHARED IMPORTED)
set_target_properties(cryptography-dev PROPERTIES
  IMPORTED_LOCATION "${CMAKE_SOURCE_DIR}/cryptography/build/libcryptography-dev.so"
  INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR}/cryptography/include"
)

target_link_libraries(enigma4 cryptography-dev)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
