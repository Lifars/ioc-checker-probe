IOC Checker Probe
=================

Build
------

Release build 

`cargo build --release`

You can also strip symbols from binary to reduce the size to approx. one half (make sure the GCC/MinGW's *bin* folder is in *Path*)

`strip target/release/ioc-checker-probe.exe`

### Über binary size reduction (didn't worked for me)

This may greatly reduce size of the binary executable at the cost of compilation times.

The steps below are taken from [source](https://github.com/johnthagen/min-sized-rust), but I was unable to reproduce them yet.

Install *Xargo* and nightly compiler

```$bash
$ rustup toolchain install nightly
$ rustup default nightly
$ rustup component add rust-src
$ cargo install xargo
```

Run `rustc -vV` and copy the value of the *host* key.
In my case the value is **x86_64-pc-windows-gnu** 

Build using this command
```bash
xargo build --target x86_64-pc-windows-gnu --release
```
Be sure to replace the value of `--target` parameter with your *host* value.

Running
-------

#### Online mode

IocChecker needs to be configured first.

Create the file `settings.toml` in the same directory as the executable with following content
```toml
server = "[IOC-SERVER URL]"
auth_probe_name = "[PROBE NAME]"
auth_key = "[API KEY]"
deep_search = false
max_iocs = 500
```
If you run the app without `settings.toml` it will create one automatically, but you still need to 
configure the `settings.toml`.

Options to configure are:
* `server` place here the URL of the IOC server.
* `auth_probe_name` is the login name of this probe instance
* `auth_key` is an API authentication key 
* `deep_search` with value `true` will initiate a deep scan of all filesystems and registries. It will also enable IOCs with **regular expressions**. Very slow.  
* `max_iocs` indicates how many of the latest IOCs from server will be downloaded. Set to `-1` to download all IOCs. 
 
#### Offline mode

Run the IocChecker as
```bash
ioc-checker-probe.exe --local [LIST-OF-IOC-FILES]
```
where `[LIST-OF-IOC-FILES]` denotes local IOC files in JSON format separated by whitespace.

#### Selectively disable some checks

Run the IocChecker with one or more options:
* `--dis-cert` disables *certificate* checking
* `--dis-conn` disables *open network connections* checking
* `--dis-dns` disables *DNS* checking
* `--dis-file` disables *file* checking
* `--dis-mutex` disables *mutex* checking
* `--dis-proc` disables *process* checking
* `--dis-reg` disables *registry* checking
