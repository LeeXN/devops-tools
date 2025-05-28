use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// 文件扫描器，用于查找指定模式的文件
pub struct FileScanner {
    extensions: Vec<String>,
    recursive: bool,
}

impl Default for FileScanner {
    fn default() -> Self {
        Self {
            extensions: vec!["tar.gz".to_string()],
            recursive: false,
        }
    }
}

impl FileScanner {
    pub fn new() -> Self {
        Self::default()
    }

    /// 设置要扫描的文件扩展名
    pub fn with_extensions(mut self, extensions: Vec<String>) -> Self {
        self.extensions = extensions;
        self
    }

    /// 设置是否递归扫描子目录
    pub fn with_recursive(mut self, recursive: bool) -> Self {
        self.recursive = recursive;
        self
    }

    /// 扫描目录中的文件
    pub fn scan_directory<P: AsRef<Path>>(&self, dir_path: P) -> Result<Vec<PathBuf>> {
        let dir_path = dir_path.as_ref();
        
        if !dir_path.exists() {
            return Err(anyhow::anyhow!("Directory does not exist: {}", dir_path.display()));
        }

        if !dir_path.is_dir() {
            return Err(anyhow::anyhow!("Path is not a directory: {}", dir_path.display()));
        }

        let mut files = Vec::new();

        if self.recursive {
            for entry in WalkDir::new(dir_path)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                if entry.file_type().is_file() {
                    if self.matches_extension(entry.path()) {
                        files.push(entry.path().to_path_buf());
                    }
                }
            }
        } else {
            let entries = fs::read_dir(dir_path)
                .with_context(|| format!("Failed to read directory: {}", dir_path.display()))?;

            for entry in entries {
                let entry = entry.context("Failed to read directory entry")?;
                let path = entry.path();
                
                if path.is_file() && self.matches_extension(&path) {
                    files.push(path);
                }
            }
        }

        files.sort();
        Ok(files)
    }

    /// 检查文件是否匹配指定的扩展名
    fn matches_extension(&self, path: &Path) -> bool {
        if self.extensions.is_empty() {
            return true;
        }

        let filename = match path.file_name().and_then(|n| n.to_str()) {
            Some(name) => name,
            None => return false,
        };

        self.extensions.iter().any(|ext| filename.ends_with(ext))
    }
}

/// 目录管理器，用于创建和管理签名目录
pub struct DirectoryManager;

impl DirectoryManager {
    /// 创建签名目录
    pub fn create_signatures_dir<P: AsRef<Path>>(base_path: P) -> Result<PathBuf> {
        let signatures_dir = base_path.as_ref().join("signatures");
        
        if !signatures_dir.exists() {
            fs::create_dir_all(&signatures_dir)
                .with_context(|| format!("Failed to create signatures directory: {}", signatures_dir.display()))?;
        }
        
        Ok(signatures_dir)
    }

    /// 获取哈希文件路径
    pub fn get_hash_file_path<P: AsRef<Path>>(signatures_dir: P, filename: &str) -> PathBuf {
        signatures_dir.as_ref().join(format!("{}.hash", filename))
    }

    /// 获取签名文件路径
    pub fn get_signature_file_path<P: AsRef<Path>>(signatures_dir: P, filename: &str) -> PathBuf {
        signatures_dir.as_ref().join(format!("{}.sig", filename))
    }

    /// 获取BLAKE3哈希文件路径
    pub fn get_blake3_file_path<P: AsRef<Path>>(signatures_dir: P, filename: &str) -> PathBuf {
        signatures_dir.as_ref().join(format!("{}.b3", filename))
    }

    /// 检查签名文件是否存在
    pub fn signature_exists<P: AsRef<Path>>(signatures_dir: P, filename: &str) -> bool {
        let sig_path = Self::get_signature_file_path(signatures_dir, filename);
        sig_path.exists()
    }

    /// 检查哈希文件是否存在
    pub fn hash_exists<P: AsRef<Path>>(signatures_dir: P, filename: &str) -> bool {
        let hash_path = Self::get_hash_file_path(signatures_dir, filename);
        hash_path.exists()
    }
}

/// 格式化工具
pub struct Formatter;

impl Formatter {
    /// 格式化文件大小为人类可读的格式
    pub fn format_file_size(size: u64) -> String {
        const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
        let mut size = size as f64;
        let mut unit_index = 0;

        while size >= 1024.0 && unit_index < UNITS.len() - 1 {
            size /= 1024.0;
            unit_index += 1;
        }

        if unit_index == 0 {
            format!("{} {}", size as u64, UNITS[unit_index])
        } else {
            format!("{:.2} {}", size, UNITS[unit_index])
        }
    }

    /// 格式化哈希输出，兼容标准工具格式
    pub fn format_hash_output(hash: &str, filename: &str, algorithm: &str) -> String {
        match algorithm.to_lowercase().as_str() {
            "blake3" | "b3" => format!("{}  {}", hash, filename),
            "sha256" => format!("{}  {}", hash, filename),
            _ => format!("{} ({}) = {}", filename, algorithm, hash),
        }
    }

    /// 格式化验证结果
    pub fn format_verification_result(filename: &str, is_valid: bool, algorithm: &str) -> String {
        let status = if is_valid { "OK" } else { "FAILED" };
        format!("{}: {} ({})", filename, status, algorithm)
    }

    /// 格式化进度信息
    pub fn format_progress(current: usize, total: usize, filename: &str) -> String {
        let percentage = if total > 0 {
            ((current as f64 / total as f64) * 100.0).round() as u32
        } else {
            0
        };
        format!("[{}/{}] ({}%) {}", current, total, percentage, filename)
    }

    /// 格式化简单的处理信息（不显示百分比）
    pub fn format_processing(filename: &str) -> String {
        format!("处理: {}", filename)
    }
}

/// 配置管理器
#[derive(Debug, Clone)]
pub struct Config {
    pub private_key_path: Option<PathBuf>,
    pub public_key_path: Option<PathBuf>,
    pub signatures_dir: PathBuf,
    pub algorithm: String,
    pub buffer_size: usize,
    pub parallel: bool,
    pub verbose: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            private_key_path: None,
            public_key_path: None,
            signatures_dir: PathBuf::from("signatures"),
            algorithm: "blake3".to_string(),
            buffer_size: 64 * 1024,
            parallel: true,
            verbose: false,
        }
    }
}

impl Config {
    pub fn new() -> Self {
        Self::default()
    }

    /// 从环境变量加载配置
    pub fn from_env() -> Self {
        let mut config = Self::default();

        if let Ok(private_key) = std::env::var("PRIVATE_KEY_PATH") {
            config.private_key_path = Some(PathBuf::from(private_key));
        }

        if let Ok(public_key) = std::env::var("PUBLIC_KEY_PATH") {
            config.public_key_path = Some(PathBuf::from(public_key));
        }

        if let Ok(signatures_dir) = std::env::var("SIGNATURES_DIR") {
            config.signatures_dir = PathBuf::from(signatures_dir);
        }

        if let Ok(algorithm) = std::env::var("HASH_ALGORITHM") {
            config.algorithm = algorithm;
        }

        if let Ok(buffer_size) = std::env::var("BUFFER_SIZE") {
            if let Ok(size) = buffer_size.parse::<usize>() {
                config.buffer_size = size;
            }
        }

        if let Ok(parallel) = std::env::var("PARALLEL") {
            config.parallel = parallel.to_lowercase() == "true";
        }

        if let Ok(verbose) = std::env::var("VERBOSE") {
            config.verbose = verbose.to_lowercase() == "true";
        }

        config
    }

    /// 验证配置
    pub fn validate(&self) -> Result<()> {
        if let Some(private_key_path) = &self.private_key_path {
            if !private_key_path.exists() {
                return Err(anyhow::anyhow!("Private key file does not exist: {}", private_key_path.display()));
            }
        }

        if let Some(public_key_path) = &self.public_key_path {
            if !public_key_path.exists() {
                return Err(anyhow::anyhow!("Public key file does not exist: {}", public_key_path.display()));
            }
        }

        if self.buffer_size == 0 {
            return Err(anyhow::anyhow!("Buffer size must be greater than 0"));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;

    #[test]
    fn test_file_scanner() {
        let temp_dir = std::env::temp_dir().join("test_scanner");
        std::fs::create_dir_all(&temp_dir).unwrap();

        // Create test files
        File::create(temp_dir.join("test1.tar.gz")).unwrap();
        File::create(temp_dir.join("test2.tar.gz")).unwrap();
        File::create(temp_dir.join("test3.txt")).unwrap();

        let scanner = FileScanner::new()
            .with_extensions(vec!["tar.gz".to_string()]);

        let files = scanner.scan_directory(&temp_dir).unwrap();
        assert_eq!(files.len(), 2);

        // Cleanup
        std::fs::remove_dir_all(temp_dir).ok();
    }

    #[test]
    fn test_formatter() {
        assert_eq!(Formatter::format_file_size(1024), "1.00 KB");
        assert_eq!(Formatter::format_file_size(1048576), "1.00 MB");
        assert_eq!(Formatter::format_file_size(512), "512 B");

        let hash_output = Formatter::format_hash_output(
            "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24",
            "test.txt",
            "blake3"
        );
        assert_eq!(hash_output, "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24  test.txt");
    }

    #[test]
    fn test_directory_manager() {
        let temp_dir = std::env::temp_dir().join("test_dir_manager");
        
        let signatures_dir = DirectoryManager::create_signatures_dir(&temp_dir).unwrap();
        assert!(signatures_dir.exists());

        let hash_path = DirectoryManager::get_hash_file_path(&signatures_dir, "test.tar.gz");
        assert_eq!(hash_path.file_name().unwrap(), "test.tar.gz.hash");

        let sig_path = DirectoryManager::get_signature_file_path(&signatures_dir, "test.tar.gz");
        assert_eq!(sig_path.file_name().unwrap(), "test.tar.gz.sig");

        // Cleanup
        std::fs::remove_dir_all(temp_dir).ok();
    }
} 