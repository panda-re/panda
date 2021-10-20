use crate::panda_plugin::{ArgMap, ArgValue, PandaPlugin, NEXT_PLUGIN_ARGS};
use crate::{executable_dir, py_unix_socket::PyUnixSocket, Args, PANDA_OBJ, PLUGINS};
use inline_python::{python, Context};
use pyo3::{prelude::*, types::PyType};
use std::path::Path;

use panda::ARCH_NAME as ARCH;

/// Checks if the type `ty` is a subclass of `PandaPlugin` but is *not* `PandaPlugin` itself
fn is_plugin_type<'py>(py: Python<'py>, ty: &'py PyType) -> bool {
    ty.is_subclass::<PandaPlugin>().unwrap_or(false) && ty != py.get_type::<PandaPlugin>()
}

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

/// Load and initalize all the plugins
pub(crate) fn initialize_pyplugins(args: Args) {
    let use_flask = args.flask;
    let load_all_classes = args.classes.is_empty();
    let class_names = args.classes.split(':').collect::<Vec<_>>();
    let should_load = move |class: &PyType| {
        class
            .name()
            .map(|name| class_names.contains(&name))
            .unwrap_or(false)
    };
    let libpanda_path = executable_dir().join(format!("libpanda-{}.so", ARCH));
    let context: Context = python! {
        from pandare import Panda

        panda = Panda(arch='ARCH, libpanda_path='libpanda_path, catch_exceptions=False)

        if 'use_flask:
            from flask import Flask, Blueprint
            app = Flask(__name__)
    };

    let (flask_app, blueprint) = Python::with_gil(|py| {
        (
            context
                .globals(py)
                .get_item("app")
                .map(|item| item.to_object(py)),
            context
                .globals(py)
                .get_item("Blueprint")
                .map(|item| item.to_object(py))
        )
    });

    let panda_obj: PyObject = context.get("panda");
    let files = parse_files(&args.files);

    let mut plugin_names = Vec::new();
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
            let PluginFile {
                path: ref file,
                args,
            } = file;

            *NEXT_PLUGIN_ARGS.lock().unwrap() = Some(args);

            let path = Path::new(file);
            if path.exists() {
                let file_path = std::fs::canonicalize(path)
                    .unwrap();
                let parent_dir = file_path.parent().unwrap();
                let file_path = file_path
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

                    // A script may import the normal PandaPlugin class from pandare
                    // but we need to overwrite that with the rust PandaPlugin class in order
                    // for all our snake_hook stuff to work.
                    import pandare
                    pandare.PandaPlugin = 'panda_plugin

                    // run the module so any types can be declared
                    spec.loader.exec_module(plugin)
                });

                let plugin_module = context.get::<Py<PyModule>>("plugin");
                for (name, item) in plugin_module.as_ref(py).dict().iter() {
                    // if the object is a type and the type is a subclass of PandaPlugin
                    // treat it as a plugin
                    if let Ok(class) = item.downcast::<PyType>() {
                        if !is_plugin_type(py, class) {
                            continue;
                        }

                        if !load_all_classes && !should_load(class) {
                            continue;
                        }

                        if class.hasattr("__init__").unwrap_or(false) {
                            let panda_obj = &panda_obj;

                            let name = name.to_string();
                            let display_name = class.getattr("name").ok().map(ToString::to_string);
                            plugin_names.push((name.clone(), display_name));

                            let flask_app = flask_app.as_ref().map(|app| app.clone_ref(py));
                            let blueprint = &blueprint;

                            let url_prefix = format!("/{}", name);
                            let template_dir = parent_dir.join("templates");
                            let template_dir = if template_dir.exists() {
                                Some(template_dir)
                            } else {
                                None
                            };

                            context.run(python! {
                                // create an instance of the plugin class
                                plugin_obj = 'class('panda_obj)

                                if 'use_flask:
                                    bp = 'blueprint('name, __name__, template_folder = 'template_dir)
                                    plugin_obj.flask = 'flask_app
                                    plugin_obj.webserver_init(bp)
                                    'flask_app.register_blueprint(bp, url_prefix='url_prefix)
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

    if use_flask {
        // professional html templating
        let html = format!(
            "<html><body><p><b>PANDA Plugin Webserver</b></p><p>Plugins:</p><ul>{}</ul></body></html>",
            plugin_names
                .into_iter()
                .map(|(name, display_name)| {
                    format!(
                        "<li><a href=\"./{}/\">{}</a></li>",
                        &name,
                        display_name.as_ref().unwrap_or_else(|| &name)
                    )
                })
                .collect::<String>()
        );

        let port = args.port;
        std::thread::spawn(move || {
            context.run(python! {
                app = 'flask_app

                @app.route("/")
                def index():
                    return 'html

                app.run(port='port)
            });

            println!("[snake_hook] flask server has started up.");
        });
    }

    // hold onto the Panda object to allow for deleting callbacks on uninit
    PANDA_OBJ.set(panda_obj).unwrap();
}
