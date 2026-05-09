use xrpl_vault_crypto_core::pre::ProxyReEncryption;

fn main() {
    let pre = ProxyReEncryption::new();
    let keypair = pre.generate_keypair();
    let pk_bytes = keypair.export_public_key_bytes();
    let pk_hex = hex::encode(&pk_bytes);
    println!("PRE Public Key ({} bytes): {}", pk_bytes.len(), pk_hex);
}
