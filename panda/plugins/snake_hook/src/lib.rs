use panda::prelude::*;
use inline_python::Context;
use inline_python::pyo3::prelude::*;

use std::ffi::{CStr, CString};
//use std::sync::Mutex;
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
        .join("libpanda-x86_64.so");

    if !plugin_self_path.exists() {
        panic!("Plugin not found at '{}'", plugin_self_path.display());
    }

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

    let context: Context = inline_python::python! {
        from pandare import Panda

        panda = Panda(libpanda_path='libpanda_path)
    };

    let panda_obj = context.get::<PyObject>("panda");

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
                context.run(inline_python::python! {
                    'module.init('panda_obj)
                });

                //MODULES
                //    .lock()
                //    .unwrap()
                //    .push(module.into_py(py));
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

    //PANDA_OBJ
    //    .lock()
    //    .unwrap()
    //    .replace(panda_obj);

    true
}

//lazy_static::lazy_static! {
//    static ref MODULES: Mutex<Vec<Py<PyModule>>> = Mutex::new(Vec::new());
//    static ref PANDA_OBJ: Mutex<Option<PyObject>> = Mutex::new(None);
//}
