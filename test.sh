#!/bin/bash
set -eu

port_is_open() {
  local host="$1" port="$2"
  if { exec 6<>/dev/tcp/"${host}"/"${port}" ; } 2>/dev/null ; then
    exec 6>&-
    return 0
  fi
  return 1
}

wait_tcp_port() {
    local host="$1" port="$2"

    # see https://tldp.org/LDP/abs/html/devref1.html for description of this syntax.
    local max_tries="24"
    for n in `seq 1 $max_tries` ; do
      if port_is_open "${host}" "${port}"; then
        break
      else
        echo "$(date) - still trying to connect to $host:$port"
        sleep .5
      fi
      if [ "$n" -eq "$max_tries" ]; then
        echo "unable to connect"
        exit 1
      fi
    done
    echo "Connected to $host:$port"
}

kill_server() {
  kill $SERVER_PID
}

run_client_tests() {
  CA_FILE=minica.pem ./target/client localhost 8443 /
  NO_CHECK_CERTIFICATE= ./target/client localhost 8443 /
  CA_FILE=minica.pem VECTORED_IO= ./target/client localhost 8443 /
}

if port_is_open localhost 8443 ; then
  echo "Cannot run tests; something is already listening on port 8443"
  exit 1
fi

# Start server in default config.
./target/server localhost/cert.pem localhost/key.pem &
SERVER_PID=$!
trap kill_server EXIT

wait_tcp_port localhost 8443
run_client_tests

kill_server
sleep 1

# Start server with vectored I/O
VECTORED_IO= ./target/server localhost/cert.pem localhost/key.pem &
SERVER_PID=$!
wait_tcp_port localhost 8443

run_client_tests
