include(ExternalProject)
set_directory_properties(PROPERTIES EP_PREFIX ${CMAKE_BINARY_DIR}/rust)

ExternalProject_Add(
    rustls-ffi
    DOWNLOAD_COMMAND ""
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ""
    COMMAND
        cargo build --locked ${CARGO_FEATURES}
        "$<IF:$<CONFIG:Release>,--release,-->"
    # Rely on cargo checking timestamps, rather than tell CMake where every
    # output is.
    BUILD_ALWAYS true
    INSTALL_COMMAND ""
    # Run cargo test with --quiet because msbuild will treat the presence
    # of "error" in stdout as an error, and we have some test functions that
    # end in "_error". Quiet mode suppresses test names, so this is a
    # sufficient workaround.
    TEST_COMMAND
        cargo test --locked ${CARGO_FEATURES}
        "$<IF:$<CONFIG:Release>,--release,-->" --quiet
)

add_custom_target(
    cbindgen
    # TODO(@cpu): I suspect this won't work on Windows :P
    COMMAND cbindgen > "src/rustls.h"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
)
