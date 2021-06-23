ifeq ($(shell uname),Darwin)
    LDFLAGS := -Wl,-dead_strip -framework Security -framework Foundation
else
    LDFLAGS := -Wl,--gc-sections -lpthread -ldl

endif

CFLAGS := -Werror -Wall -Wextra -Wpedantic -g

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

all: target/crustls-demo

test: all
	cargo test
	target/crustls-demo httpbin.org /headers

target:
	mkdir -p $@

src/crustls.h: src/*.rs cbindgen.toml
	cargo check
	cbindgen --lang C > $@

target/crustls-demo: target/main.o target/$(PROFILE)/libcrustls.a
	$(CC) -o $@ $^ $(LDFLAGS)

target/$(PROFILE)/libcrustls.a: src/*.rs Cargo.toml
	RUSTFLAGS="-C metadata=rustls-ffi" cargo build $(CARGOFLAGS)

target/main.o: src/main.c src/crustls.h | target
	$(CC) -o $@ -c $< $(CFLAGS)

install: target/$(PROFILE)/libcrustls.a src/crustls.h
	mkdir -p $(DESTDIR)/lib
	install target/$(PROFILE)/libcrustls.a $(DESTDIR)/lib/
	mkdir -p $(DESTDIR)/include
	install src/crustls.h $(DESTDIR)/include/crustls.h

clean:
	rm -rf target
