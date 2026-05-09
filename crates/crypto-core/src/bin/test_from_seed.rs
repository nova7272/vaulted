use xrpl_vault_crypto_core::pre::{ProxyReEncryption, PreKeyPair};

fn main() {
    // Используем 32-байтный seed
    let seed: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];
    
    // Создаём keypair из seed дважды
    let kp1 = PreKeyPair::from_seed(&seed).unwrap();
    let kp2 = PreKeyPair::from_seed(&seed).unwrap();
    
    // Проверяем что публичные ключи одинаковые
    assert_eq!(kp1.export_public_key_bytes(), kp2.export_public_key_bytes());
    println!("from_seed deterministic: OK");
    println!("Public key: {}", kp1.public_key().to_hex());
    
    // Проверяем что шифрование работает
    let pre = ProxyReEncryption::new();
    let data = b"secret message";
    let encrypted = pre.encrypt(&kp1.public_key(), data).unwrap();
    let decrypted = pre.decrypt(&kp1, &encrypted).unwrap();
    assert_eq!(data.as_slice(), decrypted.as_slice());
    println!("Encrypt/decrypt: OK");
}
