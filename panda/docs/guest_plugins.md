# PANDA Guest Plugins

### Overview

PANDA guest plugins are a feature of PANDA that allows you to run non-cooperative guest agents. This means without any control of the guest, you can run programs that can communicate with code running on the host system. This gives the ability to gain a semantic understanding of the guest through stable interfaces, with the drawback of not being usable in replays.

Some quick links to resources regarding guest plugins:

* [`rust_example`](/panda/guest_plugins/rust_example) - An example guest plugin written in Rust
* [`guest_plugin_example`](/panda/plugins/guest_plugin_example) - The PANDA (host) plugin that loads and interacts with the guest plugin example
* [`guest_plugin_manager` Rust Documentation](https://docs.rs/panda-re/latest/panda/plugins/guest_plugin_manager/index.html)
* [`guest_plugin_manager`](/panda/plugins/guest_plugin_manager) - Source for the guest plugin manager (the PANDA host plugin which handles loading/unloading guest plugins)

### Structure of Typical Usage

PANDA guest plugins are a bit more involved than normal PANDA plugins, due to needing to facilitate communication across the hypervisor:

* Host-side plugin 
    * A standard PANDA plugin (a shared object built from `panda/plugins`). 
    * Responsible for loading the code into the guest using the `guest_plugin_manager` plugin
    * Handles communication with the guest plugin 
        * Sending - queuing up messages for the guest 
        * Recieving - Provides a callback for messages sent by the guest
* Guest-side plugin 
    * A standard statically-linked executable cross-compiled for the guest (built from `panda/guest_plugins`)
    * Additional guest plugins will be built from `$EXTRA_GUEST_PLUGINS_PATH`
        * Requires a `$EXTRA_GUEST_PLUGINS_PATH/config.panda` file containing newline-separated plugin names. Each plugin is built from `$EXTRA_GUEST_PLUGINS_PATH/$plugin_name/`.
    * Communicates to the host using hypervisor calls via the [`panda-channels`](https://github.com/panda-re/panda-channels) library.

### Getting Started

For starters let's try developing an out-of-tree guest plugin. This process won't be any different than in-tree, so if down the road you wish to upstream your plugin it'll only require a bit of copy/pasting.

#### Creating a New Plugin

First up, create a folder to use as your "out-of-tree" plugins folder and set `EXTRA_GUEST_PLUGINS_PATH` accordingly:

```bash
mkdir guest_plugins
export EXTRA_GUEST_PLUGINS_PATH=`realpath guest_plugins`
```

Now let's create a guest plugin using the example plugin as a template:

1. Copy `panda/guest_plugins/guest_plugins/rust_example` to `$EXTRA_GUEST_PLUGINS_PATH/your_plugin_name`
2. Edit the `Cargo.toml` to change the name to match your folder name:

```toml
[package]
name = "your_plugin_name"
```

3. Create a `config.panda` file in your out-of-tree `guest_plugins` folder. The only thing this needs to contain is your plugin's name:

```
your_plugin_name
```

Later, if you make more plugins you can add each one on a new line:

```
your_plugin_name
your_other_plugin
```

#### Adding Some Guest Logic

For our example, we'll make a guest plugin which informs the host of how many files/directories are in `/etc`.

First up some imports we'll need:

```rust
use panda_channels::Channel;
use std::io::Write;
use std::fs;

fn main() {
}
```

We'll need `Channel` and `Write` for communicating with the host, and we'll need `fs` for actually interacting with the filesystem.

Then in our `main` function we'll read `/etc` using [`read_dir`](https://doc.rust-lang.org/std/fs/fn.read_dir.html) and use [`Iterator::count`](https://doc.rust-lang.org/std/iter/trait.Iterator.html#method.count):

```rust
let file_count = fs::read_dir("/etc").unwrap().count();
```

Now let's create a channel to send this information to the host:

```rust
let mut channel = Channel::main("your_plugin_name").unwrap();
```

We pass the name of our plugin to `Channel::main` to get the main channel for our plugin. This channel is automatically allocated by the `guest_plugin_manager` when we load our plugin and for most usecases it's all we'll need.

We've marked it as mutable so we can write to it. `Channel` implements Rust's [`Write`](https://doc.rust-lang.org/std/io/trait.Write.html) trait, so all we need to do is serialize our file count to bytes and use [`write_all`](https://doc.rust-lang.org/std/io/trait.Write.html#method.write_all) to send the bytes to the host:

```rust
channel.write_all(&(file_count as u32).to_le_bytes()).unwrap();
```

We convert `file_count` from `usize` (arch-width integer) to a 32-bit integer to serialize to a fixed number of bytes (that way our host code doesn't need to care about whether our guest is 32 or 64 bit) and then use `to_le_bytes` to convert to little endian bytes for us to write.

Putting that all together we get our complete guest plugin:

```rust
use panda_channels::Channel;
use std::io::Write;
use std::fs;

fn main() {
    let file_count = fs::read_dir("/etc").unwrap().count();
    let mut channel = Channel::main("your_plugin_name").unwrap();
    channel.write_all(&(file_count as u32).to_le_bytes()).unwrap();
}
```

If we want to check if it built properly, we can run:

```
cargo check
```

This will print out any errors that need to be resolved, if there's no issues we'll get:

```
   Finished dev [unoptimized + debuginfo] target(s) in 0.11s
```

This doesn't actually build or link our executable, so it saves a lot of time over doing a full PANDA build any time we want to check for compiler errors. Some other options are [`clippy`](https://github.com/rust-lang/rust-clippy) (A full Rust linter to help write idiomatic Rust) and [`bacon`](https://github.com/Canop/bacon) (Watches your project for changes and keeps a live-updating set of errors/warnings). Also helpful while developing is [`rust-analyzer`](https://rust-analyzer.github.io/), a Language Server implementation for VS Code, Emacs, Vim, etc.

#### Writing a Host Plugin

In order for our guest plugin to do anything, we'll need a host PANDA plugin in order to facilitate loading/message passing.

First up, let's create a new Rust plugin. Similarly to with our guest plugin, we can use an example plugin as a template and just find/replace the names.

I'd recommend using `panda/plugins/guest_plugin_example` as a base. Change the name in `Cargo.toml` to match the folder name, add the folder name to `panda/plugins/config.panda`, and you should be good to go.

If you use another plugin as your base, make sure you have a somewhat recent version of `panda-re`, as you'll need at least `0.26` for this:

```toml
[dependencies]
panda-re = { version = "0.26", default-features = false }
```

| Tip |
|:----|
| Install [`cargo-edit`](https://github.com/killercup/cargo-edit) and you can add the latest version of a dependency with `cargo add dep-name` |

Now onto actually writing the host plugin. First off we'll want to pull the guest plugin management utilities we'll need into scope:

```rust
use panda::plugins::guest_plugin_manager::{load_guest_plugin, channel_recv};
use panda::prelude::*;
```

We'll need a callback function for handling incoming messages from the guest. The `panda-re` package provides an (`#[channel_recv]`) attribute for this to do most of the work for us, so for the most part we just need to define a function which takes a `u32` (an ID representing the channel we're recieving messages from) and either bytes (`&[u8]`) or a string (`&str`). In this case, since we're dealing with binary data, let's go with a byte slice:

```rust
#[channel_recv]
fn message_recv(_: u32, data: &[u8]) {
}
```

And inside of that, let's just include a bit of code for converting back to an integer and printing it out to our terminal:

```rust
// convert &[u8] to [u8; 4]
let count_bytes: [u8; 4] = data[..4].try_into().unwrap();

// convert [u8; 4] to u32
let file_count = u32::from_le_bytes(count_bytes);

// print the file count to the terminal
println!("Guest `/etc` file count: {}", file_count);
```

Next up, let's define our `init` function. Since all we need to do when our plugin is load the guest plugin:

```rust
#[panda::init]
fn init(_: &mut PluginHandle) {
    let mut channel = load_guest_plugin("your_guest_plugin_name", message_recv);

    // if we needed to write to the channel at all we could do so here using
    // std::io::Write, just like the guest plugin.
}
```

Now we have everything we need for a fully-functional host plugin:

```rust
use panda::plugins::guest_plugin_manager::{load_guest_plugin, channel_recv};
use panda::prelude::*;

#[channel_recv]
fn message_recv(_: u32, data: &[u8]) {
    // convert &[u8] to [u8; 4]
    let count_bytes: [u8; 4] = data[..4].try_into().unwrap();

    // convert [u8; 4] to u32
    let file_count = u32::from_le_bytes(count_bytes);

    // print the file count to the terminal
    println!("Guest `/etc` file count: {}", file_count);
}

#[panda::init]
fn init(_: &mut PluginHandle) {
    load_guest_plugin("your_guest_plugin_name", message_recv);
}
```

If your plugin uses Rust 2018 edition then you'll also need to import `std::convert::TryInto`. If you forget this, no worries though, as rustc will remind you and tell you how to fix it:

```
help: the following trait is implemented but not in scope; perhaps add a `use` for it:
    |
1   | use std::convert::TryInto;
    |
```

#### Building

To build, we go through the standard PANDA build process:

1. Create a `build` folder in the root of your clone of PANDA if you haven't already
2. From within the build folder run `../build.sh`. In our case, we are only going to be testing on x86_64 while developing, so we can save ourselves some build time by only building a single architecture: `../build.sh x86_64-softmmu`

#### Testing Our Guest Plugin

The easiest way to test our plugin will be with a pypanda script. An example script can be found in [`panda/plugins/guest_plugin_example/try_it.py`](/panda/panda/plugins/guest_plugin_example/try_it.py).

```python
from pandare import Panda

panda = Panda(generic="x86_64")
panda.load_plugin("guest_plugin_example")

@panda.queue_blocking
def run_cmd():
    panda.revert_sync("root")
    panda.run_serial_cmd("cat", no_timeout=True)
    panda.run_serial_cmd("cat", no_timeout=True)

    panda.end_analysis()

panda.run()
```

Just replace `"guest_plugin_example"` with the name of your host PANDA plugin, then run the script. You should see roughly the following output:

```
$ python3 try_it.py

[...]
Guest `/etc` file count: 170
```

If you're getting this message, congrats! You've made your first PANDA guest plugin. If you're having trouble, a list of potential problems and solutions has been included below.

### Troubleshooting

If you issue is not listed here, ask for help in the PANDA/MIT Rehosting Slack, and we'll try to add it here.

##### "No guest plugin path was provided but plugin could not be found"

```
thread '<unnamed>' panicked at 'No guest plugin path was provided but plugin "your_guest_plugin_name" could not be found, ensure "your_guest_plugin_name" has been built.', src/interface/api.rs:23:21
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
fatal runtime error: failed to initiate panic, error 5
Aborted (core dumped)
```

Fix steps:

1. Ensure your guest plugin is listed in guest_plugins/config.panda
2. Make sure you properly updated the guest plugin name in $host_plugin/src/lib.rs
3. Double check for typos

#### "Fatal error: could not find path for plugin"

```
PANDA[core]:Fatal error: could not find path for plugin your_plugin_name
python3: {...}/panda/src/callbacks.c:166: _panda_load_plugin: Assertion `file name != NULL' failed.
Aborted (core dumped)`
```

Fix steps:

1. Ensure your host plugin is listed in panda/plugins/config.panda
2. Ensure you didn't miss any build errors happening when building your host plugin


#### "Failed to find channel number"

```
failed to find channel number
```

Fix steps:

1. Ensure the name you include in $guest_plugin/src/main.rs is correct when you call `Channel::main`
2. Ensure the name of the guest plugin itself is correct and contains no typos
