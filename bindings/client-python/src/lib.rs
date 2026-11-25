//! Python adapter for the shared Rust client library.
use confido_client::{ClientConfig, LiveAttempt, PeerCheckedClient};
use pyo3::{prelude::*, types::PyBytes};

fn error(value: impl ToString) -> PyErr {
    pyo3::exceptions::PyRuntimeError::new_err(value.to_string())
}

fn json_value(py: Python<'_>, value: &impl serde::Serialize) -> PyResult<PyObject> {
    let encoded = serde_json::to_string(value).map_err(error)?;
    Ok(py
        .import_bound("json")?
        .call_method1("loads", (encoded,))?
        .unbind())
}

/// A live attempt cannot be reconstructed from a serialized archive.
#[pyclass]
struct Attempt {
    runtime: Option<tokio::runtime::Runtime>,
    inner: Option<LiveAttempt>,
}

#[pymethods]
impl Attempt {
    #[getter]
    fn result(&self, py: Python<'_>) -> PyResult<PyObject> {
        json_value(
            py,
            self.inner
                .as_ref()
                .ok_or_else(|| error("Attempt already consumed"))?
                .result(),
        )
    }

    #[getter]
    fn archive(&self, py: Python<'_>) -> PyResult<PyObject> {
        json_value(
            py,
            self.inner
                .as_ref()
                .ok_or_else(|| error("Attempt already consumed"))?
                .archive(),
        )
    }

    /// Check the live HTTPS peer and consume this attempt exactly once.
    fn authenticate_peer(&mut self, py: Python<'_>) -> PyResult<Session> {
        let attempt = self
            .inner
            .take()
            .ok_or_else(|| error("Attempt already consumed"))?;
        let runtime = self
            .runtime
            .take()
            .ok_or_else(|| error("Runtime missing"))?;
        let client = py
            .allow_threads(|| {
                runtime
                    .block_on(attempt.authenticate_peer())
                    .map_err(|failure| failure.to_string())
            })
            .map_err(error)?;
        Ok(Session { runtime, client })
    }
}

#[pyclass]
struct Session {
    runtime: tokio::runtime::Runtime,
    client: PeerCheckedClient,
}

#[pymethods]
impl Session {
    /// Only requests to the peer-checked origin are permitted.
    fn request(
        &self,
        py: Python<'_>,
        method: &str,
        url: &str,
        headers: Vec<(String, String)>,
        body: &[u8],
    ) -> PyResult<(u16, Vec<(String, String)>, Py<PyBytes>)> {
        let body = body.to_vec();
        let (status, headers, bytes) = py
            .allow_threads(|| {
                self.runtime
                    .block_on(self.client.request(method, url, &headers, body))
                    .map_err(|failure| failure.to_string())
            })
            .map_err(error)?;
        Ok((status, headers, PyBytes::new_bound(py, &bytes).unbind()))
    }
}

#[pyfunction]
#[pyo3(signature = (origin, verifier_policy, allow_untrusted_bootstrap = false))]
fn appraise(
    py: Python<'_>,
    origin: &str,
    verifier_policy: &[u8],
    allow_untrusted_bootstrap: bool,
) -> PyResult<Attempt> {
    let config = ClientConfig::new(origin, verifier_policy.to_vec(), allow_untrusted_bootstrap)
        .map_err(error)?;
    let runtime = tokio::runtime::Runtime::new().map_err(error)?;
    let attempt = py
        .allow_threads(|| {
            runtime
                .block_on(confido_client::appraise(&config))
                .map_err(|failure| failure.to_string())
        })
        .map_err(error)?;
    Ok(Attempt {
        runtime: Some(runtime),
        inner: Some(attempt),
    })
}

#[pyfunction]
fn build_info(py: Python<'_>) -> PyResult<PyObject> {
    let info = serde_json::json!({
        "client": confido_client::build_info(),
        "wrapper": {
            "version": env!("CARGO_PKG_VERSION"),
            "source_sha256": env!("CONFIDO_SOURCE_SHA256"),
            "target": env!("CONFIDO_TARGET"),
            "rustc": env!("CONFIDO_RUSTC"),
            "build_profile": env!("CONFIDO_BUILD_PROFILE")
        }
    });
    json_value(py, &info)
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_function(wrap_pyfunction!(appraise, m)?)?;
    m.add_function(wrap_pyfunction!(build_info, m)?)?;
    m.add_class::<Attempt>()?;
    m.add_class::<Session>()?;
    Ok(())
}
