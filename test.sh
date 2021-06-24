#!/bin/bash
./target/server localhost/cert.pem localhost/key.pem &
SERVER_PID=$!
trap "kill '${SERVER_PID}'" EXIT

wait_tcp_port() {
    local host="$1" port="$2"

    # see https://tldp.org/LDP/abs/html/devref1.html for description of this syntax.
    local max_tries="120"
    for n in `seq 1 $max_tries` ; do
      if exec 6<>/dev/tcp/$host/$port; then
        break
      else
        echo "$(date) - still trying to connect to $host:$port"
        sleep .1
      fi
      if [ "$n" -eq "$max_tries" ]; then
        echo "unable to connect"
        exit 1
      fi
    done
    exec 6>&-
    echo "Connected to $host:$port"
}

wait_tcp_port localhost 8443

CA_FILE=minica.pem ./target/client localhost 8443 /
NO_CHECK_CERTIFICATE= ./target/client localhost 8443 /
