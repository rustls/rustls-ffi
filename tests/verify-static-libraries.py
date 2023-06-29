#!/usr/bin/env python3
import os
import re
import subprocess
import sys

STATIC_LIBS_RE = re.compile(
    b"note: native-static-libs: ([^\\n]+)\\n"
)


def main():
    # If you need to change the values here, be sure to update the values in
    # the README. Alternatively, it is possible that adding new libraries to
    # link against was a mistake that should be reverted or worked around.
    if sys.platform.startswith("darwin"):
        want = "-framework Security -liconv -lSystem -lc -lm"
    elif sys.platform.startswith("linux"):
        want = "-lgcc_s -lutil -lrt -lpthread -lm -ldl -lc"
    elif sys.platform.startswith("win32"):
        want = (
            "advapi32.lib credui.lib kernel32.lib secur32.lib "
            "legacy_stdio_definitions.lib "
            "kernel32.lib advapi32.lib userenv.lib "
            "kernel32.lib kernel32.lib ws2_32.lib bcrypt.lib ntdll.lib msvcrt.lib "
            "legacy_stdio_definitions.lib"
        )
    else:
        want = ""

    build = subprocess.run(
        ["cargo", "build"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        env=dict(os.environ, RUSTFLAGS="--print native-static-libs")
    )
    match = STATIC_LIBS_RE.search(build.stderr)
    if match is None:
        print("could not find list of native static libraries, check for "
              "compilation errors")
        sys.exit(1)
    got = match.group(1).decode("ascii")
    if want != got:
        print(
            "got unexpected list of native static libraries, "
            "fix or update README. Got:\n {}\nInstead of:\n {}"
            .format(got, want)
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
