ifeq ($(shell uname),Darwin)
    LDFLAGS := -Wl,-dead_strip -framework Security -framework Foundation
else
    LDFLAGS := -Wl,--gc-sections -lpthread -ldl
endif

CARGO ?= cargo
CARGOFLAGS += --locked

CFLAGS := -Werror -Wall -Wextra -Wpedantic -g -I src/
PROFILE := release
CRYPTO_PROVIDER := aws-lc-rs
DESTDIR=/usr/local

ifeq ($(PROFILE), debug)
	CFLAGS += -fsanitize=address -fsanitize=undefined
	LDFLAGS += -fsanitize=address -fsanitize=undefined
endif

ifeq ($(PROFILE), release)
	CFLAGS += -O3
	CARGOFLAGS += --release
endif

ifneq (,$(TARGET))
	PROFILE := $(TARGET)/$(PROFILE)
	CARGOFLAGS += --target $(TARGET)
endif

ifeq ($(CRYPTO_PROVIDER), aws-lc-rs)
	CFLAGS += -D DEFINE_AWS_LC_RS
	CARGOFLAGS += --no-default-features --features aws-lc-rs
else ifeq ($(CRYPTO_PROVIDER), ring)
	CFLAGS += -D DEFINE_RING
	CARGOFLAGS += --no-default-features --features ring
endif

all: target/client target/server

test: all
	${CARGO} test ${CARGOFLAGS}

integration: all
	${CARGO} test ${CARGOFLAGS} -- --ignored

connect-test: target/client
	RUSTLS_PLATFORM_VERIFIER=1 target/client example.com 443 /

target:
	mkdir -p $@

src/rustls.h: src/*.rs cbindgen.toml
	cbindgen > $@

target/$(PROFILE)/librustls_ffi.a: src/*.rs Cargo.toml
	RUSTFLAGS="-C metadata=rustls-ffi" ${CARGO} build $(CARGOFLAGS)

target/%.o: tests/%.c tests/common.h | target
	$(CC) -o $@ -c $< $(CFLAGS)

target/client: target/client.o target/common.o target/$(PROFILE)/librustls_ffi.a
	$(CC) -o $@ $^ $(LDFLAGS)

target/server: target/server.o target/common.o target/$(PROFILE)/librustls_ffi.a
	$(CC) -o $@ $^ $(LDFLAGS)

install: target/$(PROFILE)/librustls_ffi.a
	mkdir -p $(DESTDIR)/lib
	install target/$(PROFILE)/librustls_ffi.a $(DESTDIR)/lib/librustls.a
	mkdir -p $(DESTDIR)/include
	install src/rustls.h $(DESTDIR)/include/

clean:
	rm -rf target

format:
	find src tests \
		-name '*.[c|h]' \
		! -wholename 'src/rustls.h' | \
			xargs clang-format -i
	sed -i -e 's/ffi_panic_boundary! {/if true {/g' src/*.rs
	cargo fmt
	sed -i -e 's/if true {/ffi_panic_boundary! {/g' src/*.rs

format-check:
	find src tests \
		-name '*.[c|h]' \
		! -wholename 'src/rustls.h' | \
			xargs clang-format --dry-run -Werror -i
	sed -i -e 's/ffi_panic_boundary! {/if true {/g' src/*.rs
	cargo fmt --check
	sed -i -e 's/if true {/ffi_panic_boundary! {/g' src/*.rs

.PHONY: all clean test integration format format-check
