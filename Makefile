CFLAGS := -Werror -Wall -Wextra -Wpedantic -g
LDFLAGS := -Wl,--gc-sections -lpthread -ldl

PROFILE := debug

ifeq ($(PROFILE), release)
	CFLAGS += -O3
endif

all: target/crustls-demo

test: all
	target/crustls-demo httpbin.org /headers

target:
	mkdir -p $@

src/lib.h: src/lib.rs
	cbindgen --lang C --output src/lib.h

target/crustls-demo: target/main.o target/$(PROFILE)/libcrustls.a
	$(CC) -o $@ $^ $(LDFLAGS)

target/$(PROFILE)/libcrustls.a: src/lib.rs Cargo.toml
	cargo build --$(PROFILE)

target/main.o: src/main.c src/lib.h | target
	$(CC) -o $@ -c $< $(CFLAGS)

install: target/debug/libcrustls.a src/lib.h
	sudo install target/debug/libcrustls.a /usr/local/lib/
	sudo install src/lib.h /usr/local/include/crustls.h

clean:
	rm -rf target
