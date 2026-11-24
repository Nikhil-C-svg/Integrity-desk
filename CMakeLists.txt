cmake_minimum_required(VERSION 3.16)
project(IntegrityDesk LANGUAGES CXX)

if(NOT WIN32)
  message(FATAL_ERROR "Integrity Desk uses Windows CNG for SHA-256.")
endif()

add_executable(integrity-desk integrity-desk.cpp)
set_target_properties(integrity-desk PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES CXX_EXTENSIONS NO)
target_link_libraries(integrity-desk PRIVATE bcrypt)

if(MINGW)
  target_link_options(integrity-desk PRIVATE -municode)
endif()
                                                                                                                                                                          