# jpegfs

Run with `cargo run <jpeg_directory> <mount_directory>`

If the mount directory does not exist, jpegfs creates it and removes it again on shutdown.
Pre-existing mount directories are left in place.

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
- inode_raw_roundtrip
- inode_structured_roundtrip
- owned_jpeg_read_write
- pager_state_maschine
- store_block_persistence

Minimize all copora:

```bash
./fuzz/cmin-all.sh --target x86_64-unknown-linux-gnu
```
