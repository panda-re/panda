use lazy_static::lazy_static;
use pyo3::prelude::*;

use std::collections::HashMap;
use std::sync::Mutex;

#[pyclass(subclass, module = "snake_hook")]
pub struct PandaPlugin {
    args: ArgMap,
    pub flask: Option<PyObject>,
}

#[pymethods]
impl PandaPlugin {
    #[new]
    fn new() -> PyResult<Self> {
        let args = NEXT_PLUGIN_ARGS.lock().unwrap().take().unwrap();

        Ok(Self { args, flask: None })
    }

    fn get_arg(&self, name: &str) -> Option<String> {
        self.args
            .get(name)
            .map(|value| match &value {
                ArgValue::Value(value) => Some(value.clone()),
                ArgValue::NoValue => None,
            })
            .flatten()
    }

    fn get_arg_bool(&self, name: &str) -> bool {
        match self.args.get(name) {
            Some(ArgValue::Value(val)) => {
                matches!(&*val.to_lowercase(), "yes" | "true" | "1" | "y")
            }
            Some(ArgValue::NoValue) => true,
            None => false,
        }
    }

    fn webserver_init(&self, _flask: &PyAny) {}
}

lazy_static! {
    pub(crate) static ref NEXT_PLUGIN_ARGS: Mutex<Option<ArgMap>> = Mutex::new(None);
}

pub(crate) type ArgMap = HashMap<String, ArgValue>;

pub(crate) enum ArgValue {
    Value(String),
    NoValue,
}
