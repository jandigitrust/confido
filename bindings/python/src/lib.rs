use pyo3::prelude::*;
fn error(e: impl ToString) -> PyErr {
    pyo3::exceptions::PyValueError::new_err(e.to_string())
}
#[pyfunction]
#[pyo3(signature=(report,amd_chain,vcek,reference,policy,expected_nonce,evaluation_time))]
// Preserve the stable Python call signature for verifier inputs and context.
#[allow(clippy::too_many_arguments)]
fn verify(
    py: Python<'_>,
    report: &[u8],
    amd_chain: &[u8],
    vcek: &[u8],
    reference: &[u8],
    policy: &[u8],
    expected_nonce: &[u8],
    evaluation_time: i64,
) -> PyResult<PyObject> {
    let nonce: [u8; 32] = expected_nonce
        .try_into()
        .map_err(|_| error("Expected 32-byte nonce"))?;
    let r = py
        .allow_threads(|| {
            confido::verify(
                confido::VerificationInput {
                    report_json: report,
                    amd_chain_pem: amd_chain,
                    vcek_der: vcek,
                    reference_json: reference,
                },
                policy,
                &confido::VerificationContext {
                    expected_nonce: nonce,
                    evaluation_unix_seconds: evaluation_time,
                },
            )
        })
        .map_err(error)?;
    let s = serde_json::to_string(&r).map_err(error)?;
    Ok(py
        .import_bound("json")?
        .call_method1("loads", (s,))?
        .unbind())
}
#[pyfunction]
fn inspect_requirements(py: Python<'_>, report: &[u8]) -> PyResult<PyObject> {
    let r = confido::inspect_requirements(report).map_err(error)?;
    Ok(py
        .import_bound("json")?
        .call_method1("loads", (serde_json::to_string(&r).map_err(error)?,))?
        .unbind())
}
#[pyfunction]
fn build_info(py: Python<'_>) -> PyResult<PyObject> {
    let info = serde_json::json!({
        "core": confido::build_info(),
        "wrapper": {
            "version": env!("CARGO_PKG_VERSION"),
            "source_sha256": env!("CONFIDO_SOURCE_SHA256"),
            "target": env!("CONFIDO_TARGET"),
            "rustc": env!("CONFIDO_RUSTC"),
            "flags": env!("CONFIDO_BUILD_FLAGS"),
            "features": env!("CONFIDO_BUILD_FEATURES"),
            "build_profile": env!("CONFIDO_BUILD_PROFILE"),
        },
    });
    Ok(py
        .import_bound("json")?
        .call_method1("loads", (info.to_string(),))?
        .unbind())
}
#[pymodule]
fn confido_verifier(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_function(wrap_pyfunction!(verify, m)?)?;
    m.add_function(wrap_pyfunction!(build_info, m)?)?;
    m.add_function(wrap_pyfunction!(inspect_requirements, m)?)?;
    Ok(())
}
