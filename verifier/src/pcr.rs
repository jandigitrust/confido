use ring::digest::{Algorithm, Context};

pub struct Pcr {
    algo: &'static Algorithm,
    pub value: Vec<u8>,
}

impl Pcr {
    pub fn new(algo: &'static Algorithm) -> Self {
        Self {
            algo,
            value: vec![0; algo.output_len()],
        }
    }

    pub fn extend_digest(&mut self, template_hash: &[u8]) -> Result<(), &'static str> {
        if template_hash.len() != self.algo.output_len() {
            return Err("TRS template hashes do not match the selected PCR bank");
        }
        let mut hasher = Context::new(self.algo);
        hasher.update(&self.value);
        hasher.update(template_hash);
        self.value = hasher.finish().as_ref().to_vec();
        Ok(())
    }
}
