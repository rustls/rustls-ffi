CFLAGS := -Werror -Wall -Wextra -Wpedantic
LDFLAGS := -Wl,--gc-sections -lpthread -ldl

all: target/crustls-demo
	target/crustls-demo httpbin.org /headers

target:
	mkdir -p $@

src/lib.h: src/lib.rs
	cbindgen --lang C --output src/lib.h

target/crustls-demo: target/main.o target/debug/libcrustls.a
	$(CC) -o $@ $^ $(LDFLAGS)

target/debug/libcrustls.a: src/lib.rs Cargo.toml
	cargo build

target/main.o: src/main.c src/lib.h | target
	$(CC) -o $@ -c $< $(CFLAGS)

clean:
	rm -rf target
