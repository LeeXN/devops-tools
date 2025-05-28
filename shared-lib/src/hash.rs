use anyhow::{Context, Result};
use blake3::Hasher as Blake3Hasher;
use sha2::{Sha256, Digest};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

/// BLAKE3哈希计算器，兼容b3sum格式
pub struct Blake3Calculator {
    buffer_size: usize,
}

impl Default for Blake3Calculator {
    fn default() -> Self {
        Self {
            buffer_size: 64 * 1024, // 64KB buffer for optimal performance
        }
    }
}

impl Blake3Calculator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_buffer_size(mut self, size: usize) -> Self {
        self.buffer_size = size;
        self
    }

    /// 计算文件的BLAKE3哈希值，输出格式兼容b3sum
    pub fn hash_file<P: AsRef<Path>>(&self, path: P) -> Result<String> {
        let path = path.as_ref();
        
        // 检查文件是否存在
        if !path.exists() {
            return Err(anyhow::anyhow!("文件不存在: {}", path.display()));
        }
        
        // 检查是否是文件
        if !path.is_file() {
            return Err(anyhow::anyhow!("路径不是文件: {}", path.display()));
        }
        
        let file = File::open(path)
            .with_context(|| format!("无法打开文件: {} (检查文件权限)", path.display()))?;
        
        let mut reader = BufReader::with_capacity(self.buffer_size, file);
        self.hash_reader(&mut reader)
            .with_context(|| format!("读取文件内容失败: {}", path.display()))
    }

    /// 从Reader计算BLAKE3哈希值
    pub fn hash_reader<R: Read>(&self, reader: &mut R) -> Result<String> {
        let mut hasher = Blake3Hasher::new();
        let mut buffer = vec![0u8; self.buffer_size];
        let mut total_bytes = 0u64;

        loop {
            let bytes_read = reader.read(&mut buffer)
                .with_context(|| format!("读取数据失败 (已读取 {} 字节, 缓冲区大小: {} 字节) - 可能是权限问题或文件损坏", total_bytes, self.buffer_size))?;
            
            if bytes_read == 0 {
                break;
            }
            
            total_bytes += bytes_read as u64;
            hasher.update(&buffer[..bytes_read]);
        }

        let hash = hasher.finalize();
        Ok(hash.to_hex().to_string())
    }

    /// 计算字节数据的BLAKE3哈希值
    pub fn hash_bytes(&self, data: &[u8]) -> String {
        let hash = blake3::hash(data);
        hash.to_hex().to_string()
    }

    /// 生成与b3sum兼容的输出格式
    pub fn format_b3sum_output(&self, hash: &str, filename: &str) -> String {
        format!("{}  {}", hash, filename)
    }
}

/// SHA256哈希计算器，兼容sha256sum格式
pub struct Sha256Calculator {
    buffer_size: usize,
}

impl Default for Sha256Calculator {
    fn default() -> Self {
        Self {
            buffer_size: 64 * 1024,
        }
    }
}

impl Sha256Calculator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_buffer_size(mut self, size: usize) -> Self {
        self.buffer_size = size;
        self
    }

    /// 计算文件的SHA256哈希值，输出格式兼容sha256sum
    pub fn hash_file<P: AsRef<Path>>(&self, path: P) -> Result<String> {
        let path = path.as_ref();
        
        // 检查文件是否存在
        if !path.exists() {
            return Err(anyhow::anyhow!("文件不存在: {}", path.display()));
        }
        
        // 检查是否是文件
        if !path.is_file() {
            return Err(anyhow::anyhow!("路径不是文件: {}", path.display()));
        }
        
        let file = File::open(path)
            .with_context(|| format!("无法打开文件: {} (检查文件权限)", path.display()))?;
        
        let mut reader = BufReader::with_capacity(self.buffer_size, file);
        self.hash_reader(&mut reader)
            .with_context(|| format!("读取文件内容失败: {}", path.display()))
    }

    /// 从Reader计算SHA256哈希值
    pub fn hash_reader<R: Read>(&self, reader: &mut R) -> Result<String> {
        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; self.buffer_size];
        let mut total_bytes = 0u64;

        loop {
            let bytes_read = reader.read(&mut buffer)
                .with_context(|| format!("读取数据失败 (已读取 {} 字节, 缓冲区大小: {} 字节) - 可能是权限问题或文件损坏", total_bytes, self.buffer_size))?;
            
            if bytes_read == 0 {
                break;
            }
            
            total_bytes += bytes_read as u64;
            hasher.update(&buffer[..bytes_read]);
        }

        let result = hasher.finalize();
        Ok(hex::encode(result))
    }

    /// 计算字节数据的SHA256哈希值
    pub fn hash_bytes(&self, data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        hex::encode(result)
    }

    /// 生成与sha256sum兼容的输出格式
    pub fn format_sha256sum_output(&self, hash: &str, filename: &str) -> String {
        format!("{}  {}", hash, filename)
    }
}

/// 混合哈希计算器，同时计算BLAKE3和SHA256
pub struct HybridHasher {
    blake3: Blake3Calculator,
    sha256: Sha256Calculator,
}

impl Default for HybridHasher {
    fn default() -> Self {
        Self {
            blake3: Blake3Calculator::default(),
            sha256: Sha256Calculator::default(),
        }
    }
}

impl HybridHasher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_buffer_size(mut self, size: usize) -> Self {
        self.blake3 = self.blake3.with_buffer_size(size);
        self.sha256 = self.sha256.with_buffer_size(size);
        self
    }

    /// 同时计算文件的BLAKE3和SHA256哈希值
    pub fn hash_file<P: AsRef<Path>>(&self, path: P) -> Result<(String, String)> {
        let path = path.as_ref();
        
        // 为了性能，我们需要读取文件两次
        let blake3_hash = self.blake3.hash_file(path)?;
        let sha256_hash = self.sha256.hash_file(path)?;
        
        Ok((blake3_hash, sha256_hash))
    }

    /// 从字节数据同时计算两种哈希值
    pub fn hash_bytes(&self, data: &[u8]) -> (String, String) {
        let blake3_hash = self.blake3.hash_bytes(data);
        let sha256_hash = self.sha256.hash_bytes(data);
        (blake3_hash, sha256_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_blake3_hash_bytes() {
        let calculator = Blake3Calculator::new();
        let data = b"hello world";
        let hash = calculator.hash_bytes(data);
        
        // BLAKE3 hash of "hello world"
        assert_eq!(hash, "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24");
    }

    #[test]
    fn test_sha256_hash_bytes() {
        let calculator = Sha256Calculator::new();
        let data = b"hello world";
        let hash = calculator.hash_bytes(data);
        
        // SHA256 hash of "hello world"
        assert_eq!(hash, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
    }

    #[test]
    fn test_blake3_hash_reader() {
        let calculator = Blake3Calculator::new();
        let data = b"hello world";
        let mut cursor = Cursor::new(data);
        let hash = calculator.hash_reader(&mut cursor).unwrap();
        
        assert_eq!(hash, "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24");
    }

    #[test]
    fn test_hybrid_hasher() {
        let hasher = HybridHasher::new();
        let data = b"hello world";
        let (blake3_hash, sha256_hash) = hasher.hash_bytes(data);
        
        assert_eq!(blake3_hash, "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24");
        assert_eq!(sha256_hash, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
    }
} 