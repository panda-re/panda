# Rust Skeleton

This is a basic example of how to build a PANDA plugin with Rust.

## Building

To check if the plugin will build:

```
cargo check
```

To actually build the plugin:

```
cargo build --release
```

(remove `--release` if you want to build in debug mode)

The resulting plugin will be located in `target/release/librust_skeleton.so`.

## Structure

```
├── Cargo.toml
├── Makefile
├── README.md
└── src
   └── lib.rs
```

* Cargo.toml - The core plugin info. This informs `cargo` how to actually go about building the plugin. It includes the name, dependencies, and features of plugins.
* Makefile - Instructions for how the PANDA build system will build the plugin.
* lib.rs - The main source file of your plugin. Additional source files can be referenced from here.

## Cargo.toml

The dependencies section:

```toml
[dependencies]
panda-re = { version = "0.5", default-features = false }
```

To add a new dependency, add a new line in the form `name = "version"`.

For example to add [`libc`](https://docs.rs/libc), simply add the following line:

```toml
libc = "0.2"
```

## Targetting Multiple Architectures

In PANDA, a plugin is recompiled once per target architecture (that is to say, the architecture of the guest). To enable this behavior in Rust plugins, we use ["features"](https://doc.rust-lang.org/cargo/reference/features.html) in order to specify which architecture we are building for.

This is controlled by this section of Cargo.toml:

```toml
[features]
default = ["x86_64"]

x86_64 = ["panda-re/x86_64"]
i386 = ["panda-re/i386"]
arm = ["panda-re/arm"]
ppc = ["panda-re/ppc"]
mips = ["panda-re/mips"]
mipsel = ["panda-re/mipsel"]
```

by default `x86_64` is the only feature enabled (which is why we don't need to specify any features to build), this is primarily so that IDE support (rust-analyzer for VSCode/vim/etc, IntelliJ/CLion integration) works out of the box, as IDEs typically do type checking with the default feature set.

To build for, say, `arm` you can use the following command:

```
cargo build --release --no-default-features --features=arm
```

And if you wish to prevent certain code from compiling on certain platforms you can use the following:

```rust
#[cfg(not(feature = "arm"))]
fn breaks_arm() {
    // ...
}
```

## Other Resources

* [panda-rs documentation](https://docs.rs/panda-re) 
* [panda-rs announcement blog post](https://panda.re/blog/panda-rs)
* [panda-sys documentation](https://docs.rs/panda-re-sys)
* [The Rust Programming Language](https://doc.rust-lang.org/book/)
* [Some example Rust plugins](https://github.com/panda-re/panda-rs-plugins/)
