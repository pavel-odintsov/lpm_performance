cmake_minimum_required(VERSION 3.15...4.0)

project(
  PatriciaPerformanceTests
  VERSION 1.0
  LANGUAGES CXX)

add_library(libpatricia libpatricia/patricia.cpp)
add_executable(patricia_performance_tests patricia_performance_tests.cpp)
target_link_libraries(patricia_performance_tests libpatricia)

