#!/usr/bin/env bash

set -euo pipefail

main() {
    local -r uname=$(uname)
    local want;
    # If you need to change the values here, be sure to update the values in the
    # README. Alternatively, it is possible that adding new libraries to link
    # against was a mistake that should be reverted or worked around.
    if [[ "${uname}" == 'Darwin' ]]; then
        want='-framework Security -liconv -lSystem -lresolv -lc -lm -liconv'
    elif [[ "${uname}" == 'Linux' ]]; then
        want='-lgcc_s -lutil -lrt -lpthread -lm -ldl -lc'
    else
        # TODO
        want=''
    fi
    # unfortunately --print native-static-libs does not yield the
    # information in a machine consumable format, so we need to pull it
    # out of stderr.
    # https://users.rust-lang.org/t/print-native-static-libs/14102/14
    if ! RUSTFLAGS="--print native-static-libs" cargo build 2>&1 >/dev/null | grep -q -F -x "note: native-static-libs: ${want}"; then
        echo "got unexpected list of static libraries, fix or update README: ${want}"
        exit 1
    fi
}

main "$@"
