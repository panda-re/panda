use crate::{executable_dir, Args, PandaPlugin, PANDA_OBJ, PLUGINS, py_unix_socket::PyUnixSocket};
use inline_python::{python, Context};
use pyo3::{prelude::*, types::PyType};
use std::path::Path;

use panda::ARCH_NAME as ARCH;

/// Checks if the type `ty` is a subclass of `PandaPlugin` but is *not* `PandaPlugin` itself
fn is_plugin_type<'py>(py: Python<'py>, ty: &'py PyType) -> bool {
    ty.is_subclass::<PandaPlugin>().unwrap_or(false) && ty != py.get_type::<PandaPlugin>()
}

/// Load and initalize all the plugins
pub(crate) fn initialize_pyplugins(args: Args) {
    let load_all_classes = args.classes == "";
    let class_names = args.classes.split(":").collect::<Vec<_>>();
    let should_load = move |class: &PyType| {
        class.name().map(|name| class_names.contains(&name)).unwrap_or(false)
    };
    let libpanda_path = executable_dir().join(format!("libpanda-{}.so", ARCH));
    let context: Context = python! {
        from pandare import Panda

        panda = Panda(arch='ARCH, libpanda_path='libpanda_path)
    };

    let panda_obj: PyObject = context.get("panda");
    let files = args.files.split(':').collect::<Vec<_>>();

    if let Err(python_err) = Python::with_gil(|py| -> PyResult<()> {
        if !args.stdout.is_empty() {
            println!("[snake_hook] connecting python stdout to '{}'", args.stdout);
            let socket = Py::new(py, PyUnixSocket::new(&args.stdout)?)?;

            context.run(python! {
                import sys

                sys.stdout = 'socket;
            });
        }

        for file in files {
            let path = Path::new(file);
            if path.exists() {
                let file_path = std::fs::canonicalize(path)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                let panda_obj = panda_obj.clone();

                let panda_plugin = py.get_type::<PandaPlugin>();
                context.run(python! {
                    import importlib.util

                    // use importlib to import from 'file_path
                    spec = importlib.util.spec_from_file_location("panda_plugin", 'file_path)
                    plugin = importlib.util.module_from_spec(spec)

                    // inject the 'PandaPlugin' type into execution before running the module
                    plugin.PandaPlugin = 'panda_plugin

                    // run the module so any types can be declared
                    spec.loader.exec_module(plugin)
                });

                let plugin_module = context.get::<Py<PyModule>>("plugin");
                for (_name, item) in plugin_module.as_ref(py).dict().iter() {
                    // if the object is a type and the type is a subclass of PandaPlugin
                    // treat it as a plugin
                    if let Ok(class) = item.downcast::<PyType>() {
                        if !is_plugin_type(py, class) {
                            continue;
                        }

                        if !load_all_classes && !should_load(&class) {
                            continue;
                        }

                        if class.hasattr("__init__").unwrap_or(false) {
                            let panda_obj = &panda_obj;
                            context.run(python! {
                                // create an instance of the plugin class
                                plugin_obj = 'class('panda_obj)
                            });

                            // store the plugin object so we can de-initialize it later
                            let plugin_obj = context.get::<Py<PyAny>>("plugin_obj");
                            PLUGINS.lock().unwrap().push(plugin_obj);
                        } else {
                            println!(
                                "[snake_hook] Plugin class '{}' in '{}' requires a constructor",
                                class.name().unwrap_or("[unnamed]"),
                                file,
                            )
                        }
                    }
                }
            } else {
                println!("[snake_hook] Script '{}' does not exist", file);
            }
        }

        Ok(())
    }) {
        // On python exception print out the python stack trace
        Python::with_gil(|py| -> PyResult<()> {
            python_err.print(py);
            Ok(())
        })
        .unwrap();
    };

    // hold onto the Panda object to allow for deleting callbacks on uninit
    PANDA_OBJ.set(panda_obj).unwrap();
}
