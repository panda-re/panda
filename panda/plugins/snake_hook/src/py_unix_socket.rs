use std::io::Write;
use std::os::unix::net::UnixStream;

use pyo3::prelude::*;

#[pyclass(module = "snake_hook")]
pub struct PyUnixSocket {
    stream: UnixStream,
}

#[pymethods]
impl PyUnixSocket {
    #[new]
    pub fn new(path: &str) -> PyResult<Self> {
        Ok(Self {
            stream: UnixStream::connect(path)?,
        })
    }

    pub fn write(&mut self, data: &str) -> PyResult<usize> {
        self.stream.write_all(data.as_bytes())?;

        Ok(data.len())
    }
}
