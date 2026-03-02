# jpegfs

## Fuzzing

`cargo fuzz` needs a nightly toolchain and the `x86_64-unknown-linux-musl` target.

Setup (one-time):

```bash
rustup target add x86_64-unknown-linux-musl --toolchain nightly
```

Run:

```bash
cargo fuzz run --target x86_64-unknown-linux-gnu block_read_write
```

Quick smoke run (60 seconds):

```bash
cargo fuzz run --target x86_64-unknown-linux-gnu block_read_write -- -max_total_time=60
```
