include(ExternalProject)
set_directory_properties(PROPERTIES EP_PREFIX ${CMAKE_BINARY_DIR}/rust)

ExternalProject_Add(
    rustls-ffi
    DOWNLOAD_COMMAND ""
    CONFIGURE_COMMAND ""
    BUILD_COMMAND
        cargo capi build --locked ${CARGO_FEATURES}
        "$<IF:$<CONFIG:Release>,--release,-->"
    # Rely on cargo checking timestamps, rather than tell CMake where every
    # output is.
    BUILD_ALWAYS true
    INSTALL_COMMAND
        cargo capi install --libdir=lib --prefix=${CMAKE_BINARY_DIR}/rust
        --locked ${CARGO_FEATURES} "$<IF:$<CONFIG:Release>,--release,--debug>"
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

add_custom_target(connect-test DEPENDS client)

# For WIN32 when using dynamic linking we need to put the .dll
# in the search path for the binaries.
if(WIN32 AND DYN_LINK)
    add_custom_command(
        TARGET connect-test
        PRE_BUILD
        COMMAND
            ${CMAKE_COMMAND} -E copy "${CMAKE_BINARY_DIR}/rust/bin/rustls.dll"
            "${CMAKE_BINARY_DIR}\\tests\\$<CONFIG>\\"
    )
endif()

add_custom_command(
    TARGET connect-test
    POST_BUILD
    COMMAND
        ${CMAKE_COMMAND} -E env RUSTLS_PLATFORM_VERIFIER=1
        "$<TARGET_FILE:client>" example.com 443 /
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
)

add_custom_target(integration-test DEPENDS client server)

if(WIN32 AND DYN_LINK)
    add_custom_command(
        TARGET integration-test
        PRE_BUILD
        COMMAND
            ${CMAKE_COMMAND} -E copy "${CMAKE_BINARY_DIR}/rust/bin/rustls.dll"
            "${CMAKE_BINARY_DIR}\\tests\\$<CONFIG>\\"
    )
endif()

add_custom_command(
    TARGET integration-test
    POST_BUILD
    COMMAND
        ${CMAKE_COMMAND} -E env CLIENT_BINARY="$<TARGET_FILE:client>"
        ${CMAKE_COMMAND} -E env SERVER_BINARY="$<TARGET_FILE:server>" cargo test
        --locked ${CARGO_FEATURES} "$<IF:$<CONFIG:Release>,--release,>" --test
        client_server client_server_integration -- --ignored --exact
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
)

add_custom_target(ech-test DEPENDS client)

if(WIN32 AND DYN_LINK)
    add_custom_command(
        TARGET ech-test
        PRE_BUILD
        COMMAND
            ${CMAKE_COMMAND} -E copy "${CMAKE_BINARY_DIR}/rust/bin/rustls.dll"
            "${CMAKE_BINARY_DIR}\\tests\\$<CONFIG>\\"
    )
endif()

add_custom_command(
    TARGET ech-test
    POST_BUILD
    COMMAND cargo run -p rustls-ffi-tools --bin ech_fetch
    COMMAND
        ${CMAKE_COMMAND} -E env RUSTLS_PLATFORM_VERIFIER=1 ${CMAKE_COMMAND} -E
        env ECH_CONFIG_LIST="research.cloudflare.com.ech.configs.bin"
        $<TARGET_FILE:client> cloudflare-ech.com 443 /cdn-cgi/trace
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
)

add_custom_target(prefer-pq-test DEPENDS client)

if(WIN32 AND DYN_LINK)
    add_custom_command(
        TARGET prefer-pq-test
        PRE_BUILD
        COMMAND
            ${CMAKE_COMMAND} -E copy "${CMAKE_BINARY_DIR}/rust/bin/rustls.dll"
            "${CMAKE_BINARY_DIR}\\tests\\$<CONFIG>\\"
    )
endif()

add_custom_command(
    TARGET prefer-pq-test
    POST_BUILD
    COMMAND
        ${CMAKE_COMMAND} -E env RUSTLS_PLATFORM_VERIFIER=1 $<TARGET_FILE:client>
        pq.cloudflareresearch.com 443 /cdn-cgi/trace
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
)
