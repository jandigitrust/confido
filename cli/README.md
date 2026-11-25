# Confido CLI

`confido-cli` adapts the [native client](../client/README.md) to process I/O.
It reads caller-selected policy and archives, prints JSON results, and creates
private archive files. The client library does not parse CLI arguments or exit
the process.

Build from the repository root:

```sh
cargo build --locked --manifest-path cli/Cargo.toml
```

The [command guide](../README.md#cli) lists commands and arguments.
[`src/commands.rs`](src/commands.rs) owns command parsing and archive files;
[`specs/confido-cli.spec`](specs/confido-cli.spec) owns RPM packaging.
