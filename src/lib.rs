use rand::Rng;
use rsa_4096::{PrivKey, PubKey};

pub use rsa_4096::CryptErr;

pub use rsa_4096::rand_rsa_suite;

pub const MAX_BYTES: usize = 512;
pub use oaep_sha256::HASH_LEN;

pub fn encrypt(label: &[u8], message: &[u8], pub_key: &PubKey) -> Result<Vec<u8>, CryptErr> {
    let mut rand = rand::rng();
    let mut seed = [0u8; HASH_LEN];
    rand.fill_bytes(&mut seed);
    let oaep_encoded =
        oaep_sha256::encode(MAX_BYTES, &seed, label, message).map_err(|_| CryptErr)?;
    rsa_4096::encrypt_slice(&oaep_encoded, pub_key)
}

pub fn decrypt(
    label: &[u8],
    encrypted_message: &[u8],
    priv_key: &PrivKey,
) -> Result<Vec<u8>, CryptErr> {
    let decrypted_oaep_padded = rsa_4096::decrypt_slice(encrypted_message, priv_key)?;
    oaep_sha256::decode(MAX_BYTES, label, &decrypted_oaep_padded).map_err(|_| CryptErr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_test() {
        let (pub_key, priv_key) = rand_rsa_suite();
        let label = "Hello, world".as_bytes();
        let message = "a secret message for test".as_bytes();
        let encrypted_message = encrypt(&label, &message, &pub_key).expect("encrypt failure");
        let decrypted_message =
            decrypt(&label, &encrypted_message, &priv_key).expect("decrypt failure");
        assert_eq!(message, decrypted_message);
    }

    #[test]
    fn empty_roundtrip_test() {
        let (pub_key, priv_key) = rand_rsa_suite();
        let label = "".as_bytes();
        let message = "".as_bytes();
        let encrypted_message = encrypt(&label, &message, &pub_key).expect("encrypt failure");
        let decrypted_message =
            decrypt(&label, &encrypted_message, &priv_key).expect("decrypt failure");
        assert_eq!(message, decrypted_message);
    }
}
