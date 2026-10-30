pub mod admission;
pub mod algorithms;
pub mod engine;
pub mod features;
pub mod fleet;
pub mod packet;

use sha2::{Digest, Sha256};
pub fn sha256(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}
