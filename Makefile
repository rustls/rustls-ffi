# This Makefile exists exclusively as a convenience for users previously relying on the
# rustls-ffi Makefile for Linux/MacOS builds.
#
# GNU make is **not** required to build librustls and in most circumstances you are better off
# using cargo-c directly. See the README.md for more information.

CARGO ?= cargo
DESTDIR ?= /usr/local

all: install

check-cargo-c:
	@if ! ${CARGO} capi --version >/dev/null 2>&1; then \
		printf "%s" "Error: cargo-c is not installed. Install it with 'cargo install cargo-c' " && \
		printf "%s\n" "or download a binary release from https://github.com/lu-zero/cargo-c/releases/"; \
		exit 1; \
	fi

# NOTE: If you wish to customize library features, or build in debug mode, you should use cargo-c directly.
install: check-cargo-c
	${CARGO} capi install --release --libdir lib --prefix=${DESTDIR}

.PHONY: all install check-cargo-c
