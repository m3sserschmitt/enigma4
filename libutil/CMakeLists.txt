cmake_minimum_required(VERSION 3.0.0)
project(libutil VERSION 1.0.0)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../libcryptography/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

add_library(util SHARED
./util/cmd.cc
./util/file_util.cc
./util/key_util.cc
./util/string_util.cc
./util/system_time.cc
)

set_target_properties(util PROPERTIES VERSION ${PROJECT_VERSION} SOVERSION 1)

add_library(util1 STATIC
./util/cmd.cc
./util/file_util.cc
./util/key_util.cc
./util/string_util.cc
./util/system_time.cc
)
