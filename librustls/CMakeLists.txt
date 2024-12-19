cmake_minimum_required(VERSION 3.15)

project(rustls-ffi)

# Use `cmake -LH $BUILD_DIR` to see all options/help.
# Use `cmake --build $BUILD_DIR --target help` to see all targets.

include(cmake/options.cmake)
include(cmake/rust.cmake)
include(cmake/format.cmake)

add_subdirectory(tests)
