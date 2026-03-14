# jpegfs

Run with `cargo run <jpeg_directory>`

## Fuzzing

`cargo fuzz` needs a nightly toolchain. Use `x86_64-unknown-linux-gnu` as the fuzz target.

Setup (one-time):

```bash
rustup toolchain install nightly
```

Run:

```bash
cargo fuzz run --target x86_64-unknown-linux-gnu filesystem_state_machine
```

Quick smoke run (60 seconds):

```bash
cargo fuzz run --target x86_64-unknown-linux-gnu filesystem_state_machine -- -max_total_time=60
```

Available modules:

- filesystem_state_maschine
- inode_roundtrip
- owned_jpeg_read_write
- pager_state_maschine
- store_block_persistence