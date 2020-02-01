Release build 

`cargo build --release`

Strip symbols from binary (make sure the MinGW's *bin* folder is in *Path*)

`strip target/release/ioc-checker-probe.exe`

### Über binary size reduction (didn't worked for me)

This may greatly reduce size of the binary executable at the cost of compilation times.

[Source](https://github.com/johnthagen/min-sized-rust)

Install *Xargo* and nightly compiler

```$bash
$ rustup toolchain install nightly
$ rustup default nightly
$ rustup component add rust-src
$ cargo install xargo
```

Run `rustc -vV` and copy value of *host* key.
In my case the value is **x86_64-pc-windows-gnu** 

Build using this command
```bash
xargo build --target x86_64-pc-windows-gnu --release
```
Make sure to replace the `--target` parameter with your *host* value.
