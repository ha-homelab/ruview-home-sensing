use ring::signature::{
    UnparsedPublicKey, RSA_PKCS1_2048_8192_SHA256, RSA_PSS_2048_8192_SHA256,
};
use std::path::Path;

fn main() {
    let original = std::env::args().any(|arg| arg == "--original");
    let root = Path::new(env!("RUVIEW_RING_FIXTURES"));
    let message = std::fs::read(root.join("message.bin")).unwrap();
    for bits in [2040, 2041, 2047, 2048] {
        let public = std::fs::read(root.join(format!("public-{bits}.der"))).unwrap();
        for (label, algorithm) in [
            ("signature", &RSA_PKCS1_2048_8192_SHA256),
            ("pss", &RSA_PSS_2048_8192_SHA256),
        ] {
            let signature = std::fs::read(root.join(format!("{label}-{bits}.bin"))).unwrap();
            let key = UnparsedPublicKey::new(algorithm, &public);
            let accepted = key.verify(&message, &signature).is_ok();
            let expected = if original { bits > 2040 } else { bits >= 2048 };
            assert_eq!(accepted, expected, "actual modulus length: {bits}");
            assert!(key.verify(b"tampered calibration message", &signature).is_err());
            println!("RSA {label} {bits}: accepted={accepted}; tampering rejected");
        }
    }
}
