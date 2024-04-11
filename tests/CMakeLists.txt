IF(WIN32)
	add_compile_definitions(
		_WIN32_WINNT=0x601
		_CRT_SECURE_NO_WARNINGS
		_CRT_NONSTDC_NO_WARNINGS
		ssize_t=int
	)
ENDIF(WIN32)

add_executable(client client.c common.c)
add_dependencies(client rustls-ffi)
target_include_directories(client PUBLIC ${CMAKE_SOURCE_DIR}/src)
IF(WIN32)
    target_link_libraries(
        client
        debug "${CMAKE_SOURCE_DIR}/target/debug/rustls_ffi.lib"
        optimized "${CMAKE_SOURCE_DIR}/target/release/rustls_ffi.lib"
        advapi32.lib bcrypt.lib crypt32.lib cryptnet.lib kernel32.lib ncrypt.lib bcrypt.lib advapi32.lib legacy_stdio_definitions.lib kernel32.lib advapi32.lib kernel32.lib ntdll.lib userenv.lib ws2_32.lib synchronization.lib kernel32.lib  ws2_32.lib kernel32.lib msvcrt.lib
    )
    set_property(TARGET client PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreadedDLL")
ENDIF(WIN32)
IF(UNIX)
    # TODO
ENDIF(UNIX)
IF(APPLE)
    # TODO
ENDIF(APPLE)

add_executable(server server.c common.c)
add_dependencies(server rustls-ffi)
target_include_directories(server PUBLIC ${CMAKE_SOURCE_DIR}/src)
IF(WIN32)
    target_link_libraries(
        server
        debug "${CMAKE_SOURCE_DIR}/target/debug/rustls_ffi.lib"
        optimized "${CMAKE_SOURCE_DIR}/target/release/rustls_ffi.lib"
        advapi32.lib bcrypt.lib crypt32.lib cryptnet.lib kernel32.lib ncrypt.lib bcrypt.lib advapi32.lib legacy_stdio_definitions.lib kernel32.lib advapi32.lib kernel32.lib ntdll.lib userenv.lib ws2_32.lib synchronization.lib kernel32.lib  ws2_32.lib kernel32.lib msvcrt.lib
    )
    set_property(TARGET server PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreadedDLL")
ENDIF(WIN32)
IF(UNIX)
    # TODO
ENDIF(UNIX)
IF(APPLE)
    # TODO
ENDIF(APPLE)
