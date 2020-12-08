ifeq ($(shell uname),Darwin)
    LDFLAGS := -Wl,-dead_strip
else
    LDFLAGS := -Wl,--gc-sections -lpthread -ldl
endif

all: target/crustls-demo
	target/crustls-demo

target:
	mkdir -p $@

src/lib.h:
	cbindgen --lang C --output src/lib.h

target/crustls-demo: target/main.o target/debug/libcrustls.a
	$(CC) -o $@ $^ $(LDFLAGS)

target/debug/libcrustls.a: src/lib.rs Cargo.toml
	cargo build

target/main.o: src/main.c | target
	$(CC) -o $@ -c $<

clean:
	rm -rf target
