ifeq ($(shell uname),Darwin)
    LDFLAGS := -Wl,-dead_strip -framework Security -framework Foundation
else
    LDFLAGS := -Wl,--gc-sections -lpthread -ldl

endif

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

all: target/client target/server

test: all
	cargo test
	./test.sh

target:
	mkdir -p $@

src/rustls.h: src/*.rs cbindgen.toml
	cargo check
	cbindgen --lang C > $@

target/$(PROFILE)/librustls.a: src/*.rs Cargo.toml
	RUSTFLAGS="-C metadata=rustls-ffi" cargo build $(CARGOFLAGS)

target/%.o: tests/%.c src/rustls.h tests/common.h | target
	$(CC) -o $@ -c $< $(CFLAGS)

target/client: target/client.o target/common.o target/$(PROFILE)/librustls_ffi.a
	$(CC) -o $@ $^ $(LDFLAGS)

target/server: target/server.o target/common.o target/$(PROFILE)/librustls_ffi.a
	$(CC) -o $@ $^ $(LDFLAGS)

install: target/$(PROFILE)/librustls.a src/rustls.h
	mkdir -p $(DESTDIR)/lib
	install target/$(PROFILE)/librustls.a $(DESTDIR)/lib/
	mkdir -p $(DESTDIR)/include
	install src/rustls.h $(DESTDIR)/include/

clean:
	rm -rf target
