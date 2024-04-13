ifeq ($(shell uname),Darwin)
    LDFLAGS := -Wl,-dead_strip -framework Security -framework Foundation
else
    LDFLAGS := -Wl,--gc-sections -lpthread -ldl
endif

CARGO ?= cargo
CARGOFLAGS += --locked

CFLAGS := -Werror -Wall -Wextra -Wpedantic -g -I src/
PROFILE := release
DESTDIR=/usr/local

ifeq ($(CC), clang)
	CFLAGS += -fsanitize=address -fsanitize=undefined
	LDFLAGS += -fsanitize=address
endif

ifeq ($(PROFILE), release)
	CFLAGS += -O3
	CARGOFLAGS += --release
endif

ifneq (,$(TARGET))
	PROFILE := $(TARGET)/$(PROFILE)
	CARGOFLAGS += --target $(TARGET)
endif

all: target/client target/server

test: all
	${CARGO} test --locked

integration: all
	${CARGO} test --locked -- --ignored

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

format-check:
	find src tests \
		-name '*.[c|h]' \
		! -wholename 'src/rustls.h' | \
			xargs clang-format --dry-run -Werror -i

.PHONY: all clean test integration format format-check
