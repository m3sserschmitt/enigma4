cmake_minimum_required(VERSION 3.0.0)
project(enigma4 VERSION 4.0.0)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/libcryptography/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/libenigma4-client/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/libnet/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/libutil/include)

add_subdirectory(libutil)
add_subdirectory(libnet)
add_subdirectory(libenigma4-client)
add_subdirectory(libcryptography)

add_executable(enigma4 
enigma4/server.cc
enigma4/onion_routing_app.cc
enigma4/main.cc
)

target_link_libraries(enigma4 enigma4-client net util cryptography ssl)

add_executable(eclient example/eclient.cc)

target_link_libraries(eclient enigma4-client net util cryptography ssl)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
