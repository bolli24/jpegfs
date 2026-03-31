# jpegfs - a steganographic file system

Mount a file system from a folder of JPEGs:

```bash
cargo run -- mount <jpeg_directory> <mount_directory>
```

If the mount directory does not exist, jpegfs creates it and removes it again on shutdown.
Pre-existing mount directories are left in place.

Print info about a file system:

```bash
cargo run -- stat <jpeg_directory>
```

## Config

By default jpegfs uses all available hardware threads to decode and encode jpeg files in parallel.
Use `JPEGFS_JPEG_THREADS` environment variable to override.

## Fuzzing

`cargo fuzz` needs a nightly rust toolchain. Use `x86_64-unknown-linux-gnu` as the fuzz target.

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

Available fuzz targets:

- `encrypted_read_no_panic`: writes arbitrary bytes into a JPEG's LSB payload and verifies that
  `read_encrypted_with_key` never panics
- `encrypted_store_roundtrip`: fuzzes encrypted write/read round-trips and asserts the recovered plaintext matches the
  original.
- `filesystem_state_machine`: fuzzes filesystem operations and checks the resulting state for consistency.
- `inode_raw_roundtrip`: decodes arbitrary raw inode bytes and checks that valid inodes re-encode and decode stably.
- `inode_structured_roundtrip`: fuzzes structured inode values and checks round-trips.
- `owned_jpeg_lsb_roundtrip`: fuzzes in-memory `OwnedJpeg` LSB embedding and extraction without running the JPEG codec.
- `owned_jpeg_read_write`: fuzzes end-to-end JPEG read/write round-trips
- `pager_state_machine`: fuzzes pager inode, directory, and byte-page operations against a model and persistence checks.
- `store_block_persistence`: fuzzes `StoreBlock<String, 512>` inserts and validates persisted slot metadata and
  round-trips.

Everything but the `owned_jpeg` and `encrypted` targets may be run without the address sanitizer for 3-5 times faster
iteration:

```bash
cargo fuzz run --target x86_64-unknown-linux-gnu filesystem_state_machine --sanitizer none
```

Minimize all copora:

```bash
./fuzz/cmin-all.sh --target x86_64-unknown-linux-gnu
```
