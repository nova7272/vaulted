//! Утилиты хеширования для верификации данных
//!
//! Использует SHA-256 для совместимости и BLAKE3 для производительности.

use sha2::{Digest, Sha256};

/// Вычисляет SHA-256 хеш данных
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Вычисляет SHA-256 хеш и возвращает как hex-строку
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(sha256(data))
}

/// Вычисляет SHA-256 хеш с префиксом "sha256:"
pub fn sha256_prefixed(data: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(data))
}

/// Вычисляет BLAKE3 хеш данных (быстрее SHA-256)
pub fn blake3(data: &[u8]) -> [u8; 32] {
    blake3::hash(data).into()
}

/// Вычисляет BLAKE3 хеш и возвращает как hex-строку
pub fn blake3_hex(data: &[u8]) -> String {
    hex::encode(blake3(data))
}

/// Вычисляет BLAKE3 хеш с префиксом "blake3:"
pub fn blake3_prefixed(data: &[u8]) -> String {
    format!("blake3:{}", blake3_hex(data))
}

/// Инкрементальный hasher для больших файлов
pub struct StreamingHasher {
    sha256: Sha256,
    blake3: blake3::Hasher,
    bytes_processed: u64,
}

impl StreamingHasher {
    /// Создаёт новый streaming hasher
    pub fn new() -> Self {
        Self {
            sha256: Sha256::new(),
            blake3: blake3::Hasher::new(),
            bytes_processed: 0,
        }
    }

    /// Добавляет данные в hasher
    pub fn update(&mut self, data: &[u8]) {
        self.sha256.update(data);
        self.blake3.update(data);
        self.bytes_processed += data.len() as u64;
    }

    /// Возвращает количество обработанных байт
    pub fn bytes_processed(&self) -> u64 {
        self.bytes_processed
    }

    /// Финализирует и возвращает оба хеша
    pub fn finalize(self) -> HashResult {
        HashResult {
            sha256: self.sha256.finalize().into(),
            blake3: self.blake3.finalize().into(),
            bytes_processed: self.bytes_processed,
        }
    }
}

impl Default for StreamingHasher {
    fn default() -> Self {
        Self::new()
    }
}

/// Результат хеширования
#[derive(Debug, Clone)]
pub struct HashResult {
    /// SHA-256 хеш
    pub sha256: [u8; 32],
    /// BLAKE3 хеш
    pub blake3: [u8; 32],
    /// Количество обработанных байт
    pub bytes_processed: u64,
}

impl HashResult {
    /// SHA-256 как hex-строка
    pub fn sha256_hex(&self) -> String {
        hex::encode(self.sha256)
    }

    /// BLAKE3 как hex-строка
    pub fn blake3_hex(&self) -> String {
        hex::encode(self.blake3)
    }

    /// SHA-256 с префиксом
    pub fn sha256_prefixed(&self) -> String {
        format!("sha256:{}", self.sha256_hex())
    }

    /// BLAKE3 с префиксом
    pub fn blake3_prefixed(&self) -> String {
        format!("blake3:{}", self.blake3_hex())
    }
}

/// Проверяет соответствие хеша
pub fn verify_hash(data: &[u8], expected: &str) -> bool {
    if let Some(hex_hash) = expected.strip_prefix("sha256:") {
        sha256_hex(data) == hex_hash
    } else if let Some(hex_hash) = expected.strip_prefix("blake3:") {
        blake3_hex(data) == hex_hash
    } else {
        // Пробуем как SHA-256 без префикса
        sha256_hex(data) == expected
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let data = b"Hello, XRPL!";
        let hash = sha256(data);

        assert_eq!(hash.len(), 32);

        // Тот же вход = тот же хеш
        assert_eq!(sha256(data), hash);

        // Другой вход = другой хеш
        assert_ne!(sha256(b"Hello, World!"), hash);
    }

    #[test]
    fn test_sha256_hex() {
        let hash = sha256_hex(b"test");
        assert_eq!(hash.len(), 64); // 32 bytes * 2 hex chars
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_sha256_prefixed() {
        let hash = sha256_prefixed(b"test");
        assert!(hash.starts_with("sha256:"));
        assert_eq!(hash.len(), 7 + 64);
    }

    #[test]
    fn test_blake3() {
        let data = b"Hello, XRPL!";
        let hash = blake3(data);

        assert_eq!(hash.len(), 32);
        assert_eq!(blake3(data), hash);
    }

    #[test]
    fn test_streaming_hasher() {
        let data = b"Hello, XRPL Vault!";

        // Streaming
        let mut hasher = StreamingHasher::new();
        hasher.update(&data[..6]); // "Hello,"
        hasher.update(&data[6..]); // " XRPL Vault!"
        let result = hasher.finalize();

        // One-shot
        let sha256_direct = sha256(data);
        let blake3_direct = blake3(data);

        assert_eq!(result.sha256, sha256_direct);
        assert_eq!(result.blake3, blake3_direct);
        assert_eq!(result.bytes_processed, data.len() as u64);
    }

    #[test]
    fn test_verify_hash() {
        let data = b"test data";
        let sha256_hash = sha256_prefixed(data);
        let blake3_hash = blake3_prefixed(data);

        assert!(verify_hash(data, &sha256_hash));
        assert!(verify_hash(data, &blake3_hash));
        assert!(!verify_hash(b"wrong data", &sha256_hash));
    }

    #[test]
    fn test_verify_hash_without_prefix() {
        let data = b"test data";
        let hash = sha256_hex(data);

        assert!(verify_hash(data, &hash));
    }
}
