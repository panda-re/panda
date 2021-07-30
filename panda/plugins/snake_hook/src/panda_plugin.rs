use pyo3::prelude::*;

#[pyclass(subclass, module = "snake_hook")]
pub struct PandaPlugin {}

#[pymethods]
impl PandaPlugin {
    #[new]
    fn new() -> PyResult<Self> {
        Ok(Self {})
    }
}
