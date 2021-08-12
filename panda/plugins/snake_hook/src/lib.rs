use inline_python::python;
use once_cell::sync::OnceCell;
use panda::prelude::*;
use pyo3::prelude::*;

use std::ffi::{CStr, CString};
use std::path::PathBuf;
use std::sync::Mutex;

mod loader;
mod plugin_path;
mod panda_plugin;
mod py_unix_socket;
use panda_plugin::PandaPlugin;
use plugin_path::plugin_path;

#[derive(PandaArgs, Debug)]
#[name = "snake_hook"]
struct Args {
    #[arg(required, about = "colon-separated list of python plugins to run")]
    files: String,

    #[arg(about = "path for unix socket to redirect stdout to")]
    stdout: String,
}

/// Return the directory of the panda-system-* executable
fn executable_dir() -> PathBuf {
    std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .to_owned()
}

#[panda::init]
fn init(_: &mut PluginHandle) -> bool {
    let args = Args::from_panda_args();
    let plugin_self_path = plugin_path("snake_hook");

    if !plugin_self_path.exists() {
        panic!(
            "[snake_hook] snake_hook not found at '{}'",
            plugin_self_path.display()
        );
    }

    // 'Reload' self in order to ensure this plugin is set as RTLD_GLOBAL, as this is necessary
    // in order to ensure Python can load native python libraries
    let plugin_self_path = CString::new(plugin_self_path.to_str().unwrap()).unwrap();
    unsafe {
        let handle = libc::dlopen(
            plugin_self_path.as_ptr(),
            libc::RTLD_NOLOAD | libc::RTLD_GLOBAL | libc::RTLD_NOW,
        );

        if handle.is_null() {
            let err = CStr::from_ptr(libc::dlerror());
            println!(
                "[snake_hook] Error making snake_hook global dylib: {:?}",
                err
            );
        }
    }

    println!("[snake_hook] Initialized");
    loader::initialize_pyplugins(args);

    true
}

lazy_static::lazy_static! {
    /// References to all the loaded plugins so they can be uninitialized
    static ref PLUGINS: Mutex<Vec<Py<PyAny>>> = Mutex::new(Vec::new());
}

/// The global `Panda` object shared between plugins
static PANDA_OBJ: OnceCell<PyObject> = OnceCell::new();

#[panda::uninit]
fn uninit(_: &mut panda::PluginHandle) {
    let panda_obj = PANDA_OBJ.get().unwrap();
    let plugins = PLUGINS.lock().unwrap();

    // Run destructors for all plugins and clear all callbacks
    let plugins = &*plugins;
    python! {
        for plugin in 'plugins:
            if callable(getattr(plugin, "__del__", None)):
                plugin.__del__()
        'panda_obj.delete_callbacks()
    }
}
