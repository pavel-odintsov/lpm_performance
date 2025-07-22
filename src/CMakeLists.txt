cmake_minimum_required(VERSION 3.15...4.0)

project(
  PatriciaPerformanceTests
  VERSION 1.0
  LANGUAGES CXX)

find_package(Boost 1.81 COMPONENTS system REQUIRED)

add_executable(patricia_performance_tests patricia_performance_tests.cpp)

target_include_directories(patricia_performance_tests PRIVATE "/home/pavel/repos/liblpm/include")
target_link_libraries(patricia_performance_tests "/home/pavel/repos/liblpm/build/liblpm.so.1.2.0")
