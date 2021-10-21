use crate::{executable_dir, py_unix_socket::PyUnixSocket, Args, PANDA_OBJ};
use crate::{ArgMap, ArgValue};
use inline_python::{python, Context};
use pyo3::{prelude::*, types::IntoPyDict};
use std::path::Path;

use panda::ARCH_NAME as ARCH;

struct PluginFile {
    path: String,
    args: ArgMap,
}

fn parse_files(files: &str) -> Vec<PluginFile> {
    files
        .split(':')
        .map(|file| {
            let mut iter = file.split('|');
            let path = iter.next().unwrap().to_owned();

            let args = iter
                .map(|arg| {
                    arg.split_once("=")
                        .map(|(key, value)| (key.to_owned(), ArgValue::Value(value.to_string())))
                        .unwrap_or_else(|| (arg.to_owned(), ArgValue::NoValue))
                })
                .collect();

            PluginFile { path, args }
        })
        .collect()
}

/// Use PyPANDA's pyplugin - load the requested plugins with the provided arguments
pub(crate) fn initialize_pyplugins(args: Args) {
    let use_flask = args.flask;
    let libpanda_path = executable_dir().join(format!("libpanda-{}.so", ARCH));

    // Initialize PyPANDA
    let context: Context = python! {
        from pandare import Panda
        panda = Panda(arch='ARCH, libpanda_path='libpanda_path, catch_exceptions=False)
    };

    let panda_obj: PyObject = context.get("panda");
    let files = parse_files(&args.files);
    let load_all_classes = args.classes.is_empty();
    let class_names = args.classes.split(':').collect::<Vec<_>>();

    if let Err(python_err) = Python::with_gil(|py| -> PyResult<()> {
        if !args.stdout.is_empty() {
            println!("[snake_hook] connecting python stdout to '{}'", args.stdout);
            let socket = Py::new(py, PyUnixSocket::new(&args.stdout)?)?;

            context.run(python! {
                import sys
                sys.stdout = 'socket;
            });
        }

        if use_flask {
            // Enable flask, if user requested it
            // TODO: add support for specifying host
            let portno = args.port;
            context.run(python! {
                panda.pyplugins.enable_flask(port='portno)
            });
        }

        // For each file specified in the snake_hook args, resolve all
        // PyPlugin subclasses contained in that file, then load with
        // panda.pyplugins.load. Give each the specified arguments.
        for file in files {
            let PluginFile {
                path: ref file,
                args,
            } = file;

            let path = Path::new(file);
            if path.exists() {
                let file_path = std::fs::canonicalize(path).unwrap();
                let file_path = file_path.to_string_lossy().into_owned();
                let py_arg_list = args.into_py_dict(py);

                if load_all_classes {
                    // Load all the pyplugins in file_path
                    context.run(python! {
                        panda.pyplugins.load_all('file_path, args='py_arg_list)
                    });
                } else {
                    // For each file, try to load each class_name - swallow
                    // value errors raised if classes aren't present
                    let py_class_names = class_names.to_object(py);
                    context.run(python! {
                        panda.pyplugins.load(('file_path, 'py_class_names), args='py_arg_list)
                    })
                }
            } else {
                println!("[snake_hook] Script '{}' does not exist", file);
            }
        }

        if !load_all_classes {
            for class_name in class_names {
                context.run(python! {
                    if not panda.pyplugins.is_loaded('class_name):
                        raise ValueError("Failed to load plugin class " + 'class_name)
                })
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
