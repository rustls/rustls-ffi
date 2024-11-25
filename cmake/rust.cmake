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

add_custom_target(
    connect-test
    DEPENDS client
    COMMAND
        ${CMAKE_COMMAND} -E env RUSTLS_PLATFORM_VERIFIER=1
        ${CMAKE_BINARY_DIR}/tests/client example.com 443 /
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
)

if(WIN32)
    set(CLIENT_BINARY "${CMAKE_BINARY_DIR}\\tests\\$<CONFIG>\\client.exe")
    set(SERVER_BINARY "${CMAKE_BINARY_DIR}\\tests\\$<CONFIG>\\server.exe")
else()
    set(CLIENT_BINARY "${CMAKE_BINARY_DIR}/tests/client")
    set(SERVER_BINARY "${CMAKE_BINARY_DIR}/tests/server")
endif()

add_custom_target(
    integration-test
    DEPENDS client server
    COMMAND
        ${CMAKE_COMMAND} -E env CLIENT_BINARY=${CLIENT_BINARY} ${CMAKE_COMMAND}
        -E env SERVER_BINARY=${SERVER_BINARY} cargo test --locked
        ${CARGO_FEATURES} "$<IF:$<CONFIG:Release>,--release,>" --test
        client_server client_server_integration -- --ignored --exact
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
)
