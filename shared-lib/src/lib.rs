use anyhow::{Context, Result};
use blake3::Hasher;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

pub mod hash;
pub mod signature;
pub mod utils;

pub use hash::*;
pub use signature::*;
pub use utils::*;

/// 文件哈希信息结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileHashInfo {
    pub filename: String,
    pub blake3_hash: String,
    pub sha256_hash: String,
    pub file_size: u64,
    pub signature: Option<String>,
}

/// 哈希算法类型
#[derive(Debug, Clone, Copy)]
pub enum HashAlgorithm {
    Blake3,
    Sha256,
    Both,
}

/// 高性能文件哈希计算器
pub struct FileHasher {
    algorithm: HashAlgorithm,
    buffer_size: usize,
}

impl Default for FileHasher {
    fn default() -> Self {
        Self {
            algorithm: HashAlgorithm::Both,
            buffer_size: 64 * 1024, // 64KB buffer
        }
    }
}

impl FileHasher {
    pub fn new(algorithm: HashAlgorithm) -> Self {
        Self {
            algorithm,
            buffer_size: 64 * 1024,
        }
    }

    pub fn with_buffer_size(mut self, size: usize) -> Self {
        self.buffer_size = size;
        self
    }

    /// 计算文件哈希值
    pub fn hash_file<P: AsRef<Path>>(&self, path: P) -> Result<FileHashInfo> {
        let path = path.as_ref();
        let filename = path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();

        let file = File::open(path)
            .with_context(|| format!("Failed to open file: {}", path.display()))?;
        
        let metadata = file.metadata()
            .with_context(|| format!("Failed to get file metadata: {}", path.display()))?;
        
        let file_size = metadata.len();
        let mut reader = BufReader::with_capacity(self.buffer_size, file);

        let (blake3_hash, sha256_hash) = match self.algorithm {
            HashAlgorithm::Blake3 => {
                let hash = self.compute_blake3(&mut reader)?;
                (hash, String::new())
            }
            HashAlgorithm::Sha256 => {
                let hash = self.compute_sha256(&mut reader)?;
                (String::new(), hash)
            }
            HashAlgorithm::Both => {
                // 重新打开文件进行第二次哈希计算
                let file2 = File::open(path)?;
                let mut reader2 = BufReader::with_capacity(self.buffer_size, file2);
                
                let blake3_hash = self.compute_blake3(&mut reader)?;
                let sha256_hash = self.compute_sha256(&mut reader2)?;
                (blake3_hash, sha256_hash)
            }
        };

        Ok(FileHashInfo {
            filename,
            blake3_hash,
            sha256_hash,
            file_size,
            signature: None,
        })
    }

    /// 计算BLAKE3哈希
    fn compute_blake3<R: Read>(&self, reader: &mut R) -> Result<String> {
        let mut hasher = Hasher::new();
        let mut buffer = vec![0u8; self.buffer_size];

        loop {
            let bytes_read = reader.read(&mut buffer)
                .context("Failed to read file for BLAKE3 hashing")?;
            
            if bytes_read == 0 {
                break;
            }
            
            hasher.update(&buffer[..bytes_read]);
        }

        let hash = hasher.finalize();
        Ok(hash.to_hex().to_string())
    }

    /// 计算SHA256哈希
    fn compute_sha256<R: Read>(&self, reader: &mut R) -> Result<String> {
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; self.buffer_size];

        loop {
            let bytes_read = reader.read(&mut buffer)
                .context("Failed to read file for SHA256 hashing")?;
            
            if bytes_read == 0 {
                break;
            }
            
            hasher.update(&buffer[..bytes_read]);
        }

        let result = hasher.finalize();
        Ok(hex::encode(result))
    }

    /// 并行计算多个文件的哈希值
    pub fn hash_files_parallel<P: AsRef<Path> + Send + Sync>(
        &self,
        paths: &[P],
    ) -> Vec<Result<FileHashInfo>> {
        paths
            .par_iter()
            .map(|path| self.hash_file(path))
            .collect()
    }
} 