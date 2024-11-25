if(WIN32)
    add_compile_definitions(
        _WIN32_WINNT=0x601
        _CRT_SECURE_NO_WARNINGS
        _CRT_NONSTDC_NO_WARNINGS
        ssize_t=int
    )
elseif(APPLE) # Check this before UNIX! We want to handle Apple specially, and it's also a UNIX.
    add_link_options(LINKER:-dead_strip)
elseif(UNIX)
    add_link_options(LINKER:--gc-sections)
endif()

if(UNIX) # Handled separately from link options to allow Apple/Unix to share the same compile options.
    add_compile_options(-Werror -Wall -Wextra -Wpedantic)
endif()

if(CRYPTO_PROVIDER STREQUAL "aws_lc_rs")
    add_compile_definitions(DEFINE_AWS_LC_RS)
elseif(CRYPTO_PROVIDER STREQUAL "ring")
    add_compile_definitions(DEFINE_RING)
endif()

# Set ASAN sanitizer flags conditionally for Debug builds
set(sanitizer_flags "$<$<CONFIG:Debug>:-fsanitize=address>")

function(test_binary target_name)
    add_executable(${target_name})
    target_sources(${target_name} PRIVATE ${target_name}.c common.c common.h)
    add_dependencies(${target_name} rustls-ffi)

    target_include_directories(${target_name} PRIVATE ${CMAKE_SOURCE_DIR}/src)

    if(WIN32)
        target_compile_options(${target_name} PRIVATE ${sanitizer_flags})
        target_link_libraries(
            ${target_name}
            debug
            "${CMAKE_SOURCE_DIR}/target/debug/rustls_ffi.lib"
            optimized
            "${CMAKE_SOURCE_DIR}/target/release/rustls_ffi.lib"
            advapi32.lib
            bcrypt.lib
            crypt32.lib
            cryptnet.lib
            kernel32.lib
            ncrypt.lib
            bcrypt.lib
            advapi32.lib
            legacy_stdio_definitions.lib
            kernel32.lib
            advapi32.lib
            kernel32.lib
            ntdll.lib
            userenv.lib
            ws2_32.lib
            synchronization.lib
            kernel32.lib
            ws2_32.lib
            kernel32.lib
            msvcrt.lib
        )
        set_property(
            TARGET ${target_name}
            PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreadedDLL"
        )
    elseif(UNIX)
        target_compile_options(${target_name} PRIVATE ${sanitizer_flags})
        target_link_options(${target_name} PRIVATE ${sanitizer_flags})
        target_link_libraries(
            ${target_name}
            debug
            "${CMAKE_SOURCE_DIR}/target/debug/librustls_ffi.a"
            optimized
            "${CMAKE_SOURCE_DIR}/target/release/librustls_ffi.a"
        )
        if(CERT_COMPRESSION)
            target_link_libraries(${target_name} m)
        endif()
        if(APPLE)
            target_link_libraries(
                ${target_name}
                "-framework Foundation"
                "-framework Security"
            )
        endif()
    endif()
endfunction()

# Add client and server test binary targets
test_binary(client)
test_binary(server)
