use panda::prelude::*;
use inline_python::{python, Context};
use inline_python::pyo3::prelude::*;
use once_cell::sync::OnceCell;

use std::ffi::{CStr, CString};
use std::path::Path;

#[derive(PandaArgs, Debug)]
#[name = "snake_hook"]
struct Args {
    #[arg(required, about = "colon-separated list of python plugins to run")]
    files: String,
}

#[panda::init]
fn init(_: &mut PluginHandle) -> bool {
    let args = Args::from_panda_args();
    let plugin_self_path = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .join("panda/plugins/panda_snake_hook.so");

    let libpanda_path = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .join(format!("libpanda-{}.so", ARCH));

    if !plugin_self_path.exists() {
        panic!("Plugin not found at '{}'", plugin_self_path.display());
    }

    // 'Reload' self in order to ensure this plugin is set as RTLD_GLOBAL, as this is necessary
    // in order to ensure Python can load native python libraries
    let plugin_self_path = CString::new(plugin_self_path.to_str().unwrap()).unwrap();
    unsafe {
        let handle = libc::dlopen(
            plugin_self_path.as_ptr(),
            libc::RTLD_NOLOAD | libc::RTLD_GLOBAL | libc::RTLD_NOW
        );

        if handle.is_null() {
            let err = CStr::from_ptr(libc::dlerror());
            println!("[snake_hook] Error making snake_hook global dylib: {:?}", err);
        }
    }

    println!("[snake_hook] Initialized");

    let context: Context = python! {
        from pandare import Panda

        panda = Panda(arch='ARCH, libpanda_path='libpanda_path)
    };

    let panda_obj: PyObject = context.get("panda");
    let files = args.files.split(':').collect::<Vec<_>>();

    if let Err(python_err) = Python::with_gil(|py| -> PyResult<()> {
        for file in files {
            let path = Path::new(file);
            if path.exists() {
                let file_path = std::fs::canonicalize(path).unwrap().to_string_lossy().into_owned();
                let script = match std::fs::read_to_string(path) {
                    Ok(script) => script,
                    Err(_) => {
                        println!("[snake_hook] Error reading script '{}'", file);
                        continue
                    }
                };

                let module = PyModule::from_code(py, &script, &file_path, "snake_hook")?;

                if module.getattr("init").is_err() {
                    println!("[snake_hook] script '{}' is missing `init` function", file);
                    continue
                };

                let panda_obj = panda_obj.clone();
                context.run(python! {
                    'module.init('panda_obj)
                });

            } else {
                println!("[snake_hook] Script '{}' does not exist", file);
            }
        }

        Ok(())
    }) {
        // python error
        Python::with_gil(|py| -> PyResult<()> {
            Ok(python_err.print(py))
        }).unwrap();
    };

    PANDA_OBJ.set(panda_obj).unwrap();

    true
}

static PANDA_OBJ: OnceCell<PyObject> = OnceCell::new();

#[panda::uninit]
fn uninit(_: &mut panda::PluginHandle) {
    let panda_obj = PANDA_OBJ.get().unwrap();
    python! {
        'panda_obj.delete_callbacks()
    }
}

#[cfg(feature = "x86_64")]
const ARCH: &str = "x86_64";

#[cfg(feature = "i386")]
const ARCH: &str = "i386";

#[cfg(feature = "arm")]
const ARCH: &str = "arm";

#[cfg(feature = "ppc")]
const ARCH: &str = "ppc";

#[cfg(feature = "mips")]
const ARCH: &str = "mips";

#[cfg(feature = "mipsel")]
const ARCH: &str = "mipsel";

#[cfg(feature = "aarch64")]
const ARCH: &str = "aarch64";
