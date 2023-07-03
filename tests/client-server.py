#!/usr/bin/env python3
import atexit
import os
import socket
import subprocess
import sys
import time

MAX_TRIES = 24
HOST = "localhost"
PORT = 8443


def port_is_open(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    errno = s.connect_ex((host, port))
    if errno == 0:
        s.close()
        return True
    else:
        return False


def wait_tcp_port(host, port):
    for _ in range(MAX_TRIES):
        if port_is_open(host, port):
            break
        else:
            print("{} - still trying to connect to {}:{}"
                  .format(time.strftime("%c"), host, port))
            time.sleep(0.5)
    else:
        print("unable to connect")
        sys.exit(1)
    print("Connected to {}:{}".format(host, port))


def run_with_maybe_valgrind(args, env, valgrind, expect_error=False):
    if valgrind is not None:
        args = [valgrind] + args
    process_env = os.environ.copy()
    process_env.update(env)
    try:
        subprocess.check_call(args, env=process_env, stdout=subprocess.DEVNULL)
    except subprocess.CalledProcessError as e:
        if not expect_error:
            raise e


def run_client_tests(client, valgrind):
    run_with_maybe_valgrind(
        [
            client,
            HOST,
            str(PORT),
            "/"
        ],
        {
            "CA_FILE": "testdata/minica.pem"
        },
        valgrind
    )
    run_with_maybe_valgrind(
        [
            client,
            HOST,
            str(PORT),
            "/"
        ],
        {
            "NO_CHECK_CERTIFICATE": ""
        },
        valgrind
    )
    run_with_maybe_valgrind(
        [
            client,
            HOST,
            str(PORT),
            "/"
        ],
        {
            "CA_FILE": "testdata/minica.pem",
            "VECTORED_IO": ""
        },
        valgrind
    )
    run_with_maybe_valgrind(
        [
            client,
            HOST,
            str(PORT),
            "/"
        ],
        {
            "CA_FILE": "testdata/minica.pem",
            "AUTH_CERT": "testdata/localhost/cert.pem",
            "AUTH_KEY": "testdata/localhost/key.pem",
        },
        valgrind
    )


def run_mtls_client_tests(client, valgrind):
    run_with_maybe_valgrind(
        [
            client,
            HOST,
            str(PORT),
            "/"
        ],
        {
            "CA_FILE": "testdata/minica.pem",
        },
        valgrind,
        expect_error=True  # Client connecting w/o AUTH_CERT/AUTH_KEY should err.
    )
    run_with_maybe_valgrind(
        [
            client,
            HOST,
            str(PORT),
            "/"
        ],
        {
            "CA_FILE": "testdata/minica.pem",
            "AUTH_CERT": "testdata/localhost/cert.pem",
            "AUTH_KEY": "testdata/localhost/key.pem",
        },
        valgrind
    )


def run_mtls_client_crl_tests(client, valgrind):
    run_with_maybe_valgrind(
        [
            client,
            HOST,
            str(PORT),
            "/"
        ],
        {
            "CA_FILE": "testdata/minica.pem",
            "AUTH_CERT": "testdata/example.com/cert.pem",
            "AUTH_KEY": "testdata/example.com/key.pem",
        },
        valgrind
    )
    run_with_maybe_valgrind(
        [
            client,
            HOST,
            str(PORT),
            "/"
        ],
        {
            "CA_FILE": "testdata/minica.pem",
            "AUTH_CERT": "testdata/localhost/cert.pem",
            "AUTH_KEY": "testdata/localhost/key.pem",
        },
        valgrind,
        expect_error=True  # Client connecting w/ revoked cert should err.
    )


def run_server(server, valgrind, env):
    args = [
        server,
        "testdata/localhost/cert.pem",
        "testdata/localhost/key.pem"
    ]
    if valgrind is not None:
        args = [valgrind] + args
    process_env = os.environ.copy()
    process_env.update(env)
    server = subprocess.Popen(args, env=process_env)

    atexit.register(server.kill)

    return server


def main():
    valgrind = os.getenv("VALGRIND")
    if len(sys.argv) != 3:
        if sys.platform.startswith("win32"):
            print("Usage: client-server.py client.exe server.exe")
        else:
            print("Usage: python3 client-server.py ./client ./server")
        sys.exit(1)
    client = sys.argv[1]
    server = sys.argv[2]

    if port_is_open(HOST, PORT):
        print("Cannot run tests; something is already listening on port {}"
              .format(PORT))
        sys.exit(1)

    # Standard client/server tests.
    server_popen = run_server(server, valgrind, {})
    wait_tcp_port(HOST, PORT)
    run_client_tests(client, valgrind)
    server_popen.kill()
    server_popen.wait()

    # Client/server tests w/ vectored I/O.
    server_popen = run_server(server, valgrind, {
        "VECTORED_IO": ""
    })
    wait_tcp_port(HOST, PORT)
    run_client_tests(client, valgrind)
    server_popen.kill()
    server_popen.wait()

    # Client/server tests w/ mandatory client authentication.
    server_popen = run_server(server, valgrind, {
        "AUTH_CERT": "testdata/minica.pem",
    })
    run_mtls_client_tests(client, valgrind)
    server_popen.kill()
    server_popen.wait()

    # Client/server tests w/ mandatory client authentication & CRL.
    run_server(server, valgrind, {
        "AUTH_CERT": "testdata/minica.pem",
        "AUTH_CRL": "testdata/test.crl.pem",
    })
    run_mtls_client_crl_tests(client, valgrind)


if __name__ == "__main__":
    main()
