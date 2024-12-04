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
if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    # Clang supports some additional undefined behaviour sanitizers that are helpful.
    set(sanitizer_flags
        "$<$<CONFIG:Debug>:-fsanitize=address,undefined,unsigned-integer-overflow,local-bounds,implicit-conversion>"
    )
else()
    # For GCC and MSVC, stick to just ASAN.
    set(sanitizer_flags "$<$<CONFIG:Debug>:-fsanitize=address>")
endif()

set(lib_extension "a") # Static linking (default) for both MacOS and Linux
if(WIN32 AND DYN_LINK)
    set(lib_extension "dll.lib") # Dynamic linking for Windows
elseif(WIN32)
    set(lib_extension "lib") # Static linking (default) for Windows
elseif(APPLE AND DYN_LINK)
    set(lib_extension "dylib") # Dynamic linking for MacOS
elseif(UNIX AND DYN_LINK)
    set(lib_extension "so") # Dynamic linking for Linux
endif()

function(test_binary target_name)
    add_executable(${target_name})
    target_sources(${target_name} PRIVATE ${target_name}.c common.c common.h)
    add_dependencies(${target_name} rustls-ffi)

    target_include_directories(
        ${target_name}
        PRIVATE ${CMAKE_BINARY_DIR}/rust/include
    )

    if(WIN32)
        target_compile_options(${target_name} PRIVATE ${sanitizer_flags})
        target_link_libraries(
            ${target_name}
            "${CMAKE_BINARY_DIR}/rust/lib/rustls.${lib_extension}"
        )
        target_link_libraries(
            ${target_name}
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
            "${CMAKE_BINARY_DIR}/rust/lib/librustls.${lib_extension}"
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
