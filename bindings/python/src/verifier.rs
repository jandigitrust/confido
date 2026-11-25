//! Offline verification API exposed by the unified Python SDK.
use pyo3::prelude::*;
fn error(e: impl ToString) -> PyErr {
    pyo3::exceptions::PyValueError::new_err(e.to_string())
}
#[pyfunction]
#[pyo3(signature=(report,amd_chain,vcek,reference,policy,expected_nonce,evaluation_time))]
// Preserve the stable Python call signature for verifier inputs and context.
#[allow(clippy::too_many_arguments)]
pub fn verify(
    py: Python<'_>,
    report: &[u8],
    amd_chain: &[u8],
    vcek: &[u8],
    reference: &[u8],
    policy: &[u8],
    expected_nonce: &[u8],
    evaluation_time: i64,
) -> PyResult<Py<PyAny>> {
    let nonce: [u8; 32] = expected_nonce
        .try_into()
        .map_err(|_| error("Expected 32-byte nonce"))?;
    let r = py
        .detach(|| {
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
    Ok(py.import("json")?.call_method1("loads", (s,))?.unbind())
}
#[pyfunction]
pub fn inspect_requirements(py: Python<'_>, report: &[u8]) -> PyResult<Py<PyAny>> {
    let r = confido::inspect_requirements(report).map_err(error)?;
    Ok(py
        .import("json")?
        .call_method1("loads", (serde_json::to_string(&r).map_err(error)?,))?
        .unbind())
}
