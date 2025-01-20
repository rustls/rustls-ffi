# !!!!!! Important !!!!!!
#
# CMake is only used for building the **C client/server examples** and for other misc.
# developer tasks.
#
# If you want to build/install librustls, use `cargo capi install` instead.
# See the README[0] for more information.
#
# [0]: https://github.com/rustls/rustls-ffi?tab=readme-ov-file#build-rustls-ffi
#
# !!!!!! Important !!!!!!

cmake_minimum_required(VERSION 3.15)

project(rustls-ffi)

# Use `cmake -LH $BUILD_DIR` to see all options/help.
# Use `cmake --build $BUILD_DIR --target help` to see all targets.

include(cmake/options.cmake)
include(cmake/rust.cmake)
include(cmake/format.cmake)

add_subdirectory(tests)
