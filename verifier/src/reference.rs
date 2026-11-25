use crate::pcr::Pcr;
use evidence_protocol as vtpm;
use evidence_protocol::{IMALogEntry, ModuleLoadOrder};

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct ReferenceValues {
    pub ima_measurements: Vec<IMALogEntry>,
    #[serde(default)]
    pub pcr10_sha256: Option<String>,
}

#[cfg(test)]
mod tests;

impl ReferenceValues {
    /// Compare every received entry with the reference at the same position.
    ///
    /// Extra received entries are mismatches. Missing entries are reported by
    /// `compare_measurements`, so all returned values being true is not enough
    /// to establish that the complete measurement list matches.
    pub fn measurement_matches(&self, actual: &[IMALogEntry]) -> Vec<bool> {
        actual
            .iter()
            .enumerate()
            .map(|(index, observed)| self.ima_measurements.get(index) == Some(observed))
            .collect()
    }

    pub fn compare_measurements(&self, actual: &[IMALogEntry]) -> Vec<String> {
        let mut mismatches = Vec::new();
        if self.ima_measurements.len() != actual.len() {
            mismatches.push(format!(
                "count trusted={} actual={}",
                self.ima_measurements.len(),
                actual.len()
            ));
        }
        for (index, (trusted, observed)) in
            self.ima_measurements.iter().zip(actual.iter()).enumerate()
        {
            if trusted != observed {
                let expected = serde_json::to_value(trusted).expect("IMA entries serialize");
                let actual = serde_json::to_value(observed).expect("IMA entries serialize");
                let field = [
                    "name",
                    "PCR",
                    "ima_template",
                    "filedata_alg",
                    "filedata_hash",
                    "template_hash",
                    "filename_hint",
                ]
                .into_iter()
                .find(|field| expected[field] != actual[field])
                .unwrap_or("entry");
                let short = |value: &serde_json::Value| {
                    value.to_string().chars().take(120).collect::<String>()
                };
                mismatches.push(format!(
                    "index {index} ({}) {field}: expected={} observed={}",
                    observed.name.chars().take(80).collect::<String>(),
                    short(&expected[field]),
                    short(&actual[field])
                ));
            }
        }
        mismatches
    }

    pub fn get_boot_aggregate_hash(&self) -> Result<String, &'static str> {
        let entry = self
            .ima_measurements
            .iter()
            .find(|&measurement| measurement.filename_hint == "boot_aggregate");
        match entry {
            Some(measurement) => Ok(measurement.filedata_hash.clone()),
            None => Err("No entry found with filename_hint = 'boot_aggregate'"),
        }
    }

    pub fn boot_aggregate_algorithm(&self) -> Result<vtpm::Algorithm, &'static str> {
        let entry = self
            .ima_measurements
            .iter()
            .find(|measurement| measurement.filename_hint == "boot_aggregate")
            .ok_or("No boot aggregate in trusted measurements")?;
        let algo = match entry.filedata_alg.as_str() {
            "sha1" => vtpm::Algorithm::Sha1,
            "sha256" => vtpm::Algorithm::Sha256,
            _ => return Err("Unsupported boot aggregate algorithm"),
        };
        let digest =
            hex::decode(&entry.filedata_hash).map_err(|_| "Invalid boot aggregate hash")?;
        if digest.len() != algo.length() {
            return Err("Invalid boot aggregate hash length");
        }
        Ok(algo)
    }

    fn validate_order(&self, module_load_order: &ModuleLoadOrder) -> Result<(), &'static str> {
        if self.ima_measurements.is_empty() {
            return Err("No IMA records found");
        }
        if self.ima_measurements.len() != module_load_order.order.len() {
            return Err("TRS measurement count does not match the server IMA order");
        }
        for (name, measurement) in module_load_order.order.iter().zip(&self.ima_measurements) {
            if name != &measurement.name {
                return Err("TRS measurement order does not match the server IMA order");
            }
            if measurement.pcr != 10 {
                return Err("TRS measurement does not target PCR 10");
            }
        }
        Ok(())
    }

    pub fn ima_calculate(
        &self,
        module_load_order: &ModuleLoadOrder,
        algo: vtpm::Algorithm,
    ) -> Result<(vtpm::Algorithm, Vec<u8>), &'static str> {
        self.validate_order(module_load_order)?;
        let template = &self.ima_measurements[0].ima_template;
        if template != "ima-ng" && template != "ima-sig" {
            return Err("No known IMA template found in records");
        }
        if self
            .ima_measurements
            .iter()
            .any(|measurement| measurement.ima_template != *template)
        {
            return Err("Mixed templates found in records");
        }

        // Replay the trusted template digests in the selected PCR bank. In
        // particular, ima-sig cannot be reconstructed from a file digest and
        // path alone: its signature field is part of the template digest.
        let mut pcr = Pcr::new(algo.digest());
        for measurement in &self.ima_measurements {
            let digest =
                hex::decode(&measurement.template_hash).map_err(|_| "Invalid IMA template hash")?;
            pcr.extend_digest(&digest)?;
        }
        Ok((algo, pcr.value))
    }

    pub fn verify_boot_aggregate(&self, quote: &vtpm::Quote) -> Result<vtpm::Algorithm, String> {
        let algo = self.boot_aggregate_algorithm()?;
        let bank = quote.get_pcr_bank(algo).ok_or("Missing trusted PCR bank")?;
        let max = if algo == vtpm::Algorithm::Sha1 { 8 } else { 10 };
        let mut d = ring::digest::Context::new(algo.digest());
        for j in 0..max {
            let value = bank.pcr_values.get(j).ok_or("Missing boot aggregate PCR")?;
            if value.len() != algo.length() {
                return Err("Invalid PCR length".into());
            }
            d.update(value);
        }
        if hex::encode(d.finish().as_ref()) != self.get_boot_aggregate_hash()?.to_ascii_lowercase()
        {
            return Err("Boot aggregate mismatch".into());
        }
        Ok(algo)
    }

    pub fn verify_pcr10(
        &self,
        module_load_order: &ModuleLoadOrder,
        algo: vtpm::Algorithm,
        actual: &[u8],
    ) -> Result<(), &'static str> {
        self.validate_order(module_load_order)?;
        if actual.len() != algo.length() {
            return Err("Quoted PCR 10 has an invalid length");
        }
        let expected = if let Some(expected) = &self.pcr10_sha256 {
            if algo != vtpm::Algorithm::Sha256 {
                return Err("TRS contains SHA-256 PCR 10 but quote uses another PCR bank");
            }
            let digest =
                hex::decode(expected).map_err(|_| "TRS SHA-256 PCR 10 has an invalid format")?;
            if digest.len() != algo.length() {
                return Err("TRS SHA-256 PCR 10 has an invalid length");
            }
            digest
        } else {
            self.ima_calculate(module_load_order, algo)?.1
        };
        if expected != actual {
            return Err("PCR 10 mismatch");
        }
        Ok(())
    }
}
